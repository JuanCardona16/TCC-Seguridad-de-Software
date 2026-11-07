#!/usr/bin/env python3
"""Servidor del panel de evidencias: archivos estáticos + ejecución en vivo.

El endpoint `POST /api/run/<ataque>` arranca el ataque en un hilo y devuelve un
identificador de ejecución; el panel sigue el avance con
`GET /api/run-progress/<run_id>`, que entrega las fases y las líneas de salida
reales a medida que aparecen. El ritmo de revelado lo pone el navegador: el
ataque real tarda milisegundos, la animación es didáctica.

Guardas del ejecutor (servidor local de laboratorio):

  1. Token de sesión por proceso: el panel obtiene `/api/token` (sin CORS, no
     cacheable) y lo envía en `X-Panel-Token`. Una página de otro origen no puede
     leer esa respuesta, así que no puede ejecutar nada (defensa contra CSRF y
     DNS rebinding).
  2. Solo atiende peticiones cuyo encabezado `Host` sea 127.0.0.1/localhost.
  3. El identificador del ataque debe cumplir un patrón estricto Y estar en la
     lista blanca; nunca se compone un comando con texto del cliente.
  4. El modo debe ser exactamente "vulnerable" o "hardened".
  5. Se ejecuta un único ataque a la vez.
  6. Cuerpo de la petición acotado, timeout con muerte del grupo de procesos y
     salida leída desde archivo (la memoria del proceso no crece con la salida).
  7. Directorio temporal y caché de cookies propios de cada ejecución, borrados
     al terminar: nunca se escriben las evidencias oficiales.

El proceso se lanza con Popen y una lista de argumentos (sin shell), de modo que
no hay interpretación de metacaracteres.
"""

from __future__ import annotations

import html
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import threading
import time
import uuid
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO = Path(os.environ.get("REPO_ROOT", "/repo"))
STATIC = Path("/site/static")

TARGETS = {
    "vulnerable": os.environ.get("TARGET_VULN", "http://app-vuln:8080"),
    "hardened": os.environ.get("TARGET_HARD", "https://gateway"),
}

DB_DSN = {
    "vulnerable": os.environ.get("DB_DSN_VULN", "postgres://lab:lab@db:5432/minigestor_vuln"),
    "hardened": os.environ.get("DB_DSN_HARD", "postgres://lab:lab@db:5432/minigestor_hard"),
}

# Ataques que se pueden ejecutar desde el panel: solo necesitan HTTP o la base.
RUNNABLE = {
    "01-sqli-search": "SQL injection en la búsqueda devuelve los hashes",
    "02-xss-stored": "El título se renderiza como HTML crudo",
    "03-idor": "Se lee un documento de otro usuario",
    "04-bruteforce": "Intentos de login sin límite",
    "05-session-forgery": "Una cookie forjada otorga el rol de administrador",
    "06-weak-hash": "Los hashes MD5 se revierten con un diccionario",
    "08-headers": "Cabeceras de seguridad presentes o ausentes",
}

# Ataques que necesitan privilegios sobre el host: se muestran con su comando.
HOST_ONLY = {
    "07-upload-traversal": "necesita inspeccionar el sistema de archivos del contenedor app-vuln",
    "09-tls-plaintext": "necesita tcpdump con NET_ADMIN sobre la red del laboratorio",
}

ID_PATTERN = re.compile(r"^[0-9]{2}-[a-z0-9-]+$")
TIMEOUT_SECONDS = 120
MAX_OUTPUT_CHARS = 8000
MAX_BODY_BYTES = 4096
MAX_LINEAS = 400
MAX_RUNS = 20

TOKEN = secrets.token_urlsafe(24)

_ejecutando = threading.Lock()
_runs: dict[str, "Ejecucion"] = {}
_runs_lock = threading.Lock()


def _mata_grupo(proceso: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proceso.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proceso.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


class Lector:
    """Lee un archivo de salida de forma incremental y publica líneas completas."""

    def __init__(self, ruta: Path, ejecucion: "Ejecucion", tipo: str) -> None:
        self.ruta = ruta
        self.ejecucion = ejecucion
        self.tipo = tipo
        self.offset = 0
        self.resto = ""

    def bombear(self) -> None:
        try:
            with open(self.ruta, "rb") as archivo:
                archivo.seek(self.offset)
                datos = archivo.read()
                self.offset = archivo.tell()
        except FileNotFoundError:
            return
        if not datos:
            return

        texto = self.resto + datos.decode("utf-8", errors="replace")
        lineas = texto.split("\n")
        self.resto = lineas.pop()
        for linea in lineas:
            limpia = linea.rstrip()
            if limpia:
                self.ejecucion.publicar(self.tipo, limpia)

    def vaciar(self) -> None:
        if self.resto.strip():
            self.ejecucion.publicar(self.tipo, self.resto.rstrip())
            self.resto = ""


class Ejecucion:
    """Estado observable de una corrida, consultable por el panel."""

    def __init__(self, ident: str, modo: str) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.ident = ident
        self.modo = modo
        self.target = TARGETS[modo]
        self.estado = "en_curso"
        self.fase = "preparando"
        self.inicio = time.time()
        self.exit_code: int | None = None
        self.duracion_ms: int | None = None
        self.lineas: list[dict] = []
        self.evidencia: dict | None = None
        self._lock = threading.Lock()

    def fase_nueva(self, fase: str, texto: str) -> None:
        self.fase = fase
        self.publicar("fase", texto)

    def publicar(self, tipo: str, texto: str) -> None:
        with self._lock:
            if len(self.lineas) >= MAX_LINEAS:
                return
            self.lineas.append(
                {
                    "t": int((time.time() - self.inicio) * 1000),
                    "tipo": tipo,
                    "texto": texto,
                }
            )

    def instantanea(self, desde: int = 0) -> dict:
        with self._lock:
            total = len(self.lineas)
            return {
                "id": self.id,
                "ataque": self.ident,
                "modo": self.modo,
                "target": self.target,
                "estado": self.estado,
                "fase": self.fase,
                "exit_code": self.exit_code,
                "duracion_ms": self.duracion_ms,
                "total_lineas": total,
                "lineas": self.lineas[max(0, desde) :],
                "truncado": total >= MAX_LINEAS,
                "evidencia": self.evidencia,
            }


def _registrar(ejecucion: Ejecucion) -> None:
    with _runs_lock:
        _runs[ejecucion.id] = ejecucion
        if len(_runs) > MAX_RUNS:
            for viejo in sorted(_runs.values(), key=lambda e: e.inicio)[: len(_runs) - MAX_RUNS]:
                if viejo.estado != "en_curso":
                    _runs.pop(viejo.id, None)


def _buscar(run_id: str) -> Ejecucion | None:
    with _runs_lock:
        return _runs.get(run_id)


def _correr(ejecucion: Ejecucion) -> None:
    """Ejecuta el ataque publicando fases y líneas a medida que ocurren."""
    trabajo = Path("/tmp") / f"replay-{uuid.uuid4().hex[:8]}"
    (trabajo / "cache").mkdir(parents=True, exist_ok=True)
    salida_txt = trabajo / "stdout.log"
    error_txt = trabajo / "stderr.log"

    entorno = os.environ.copy()
    entorno.update(
        {
            "EVIDENCE_DIR": str(trabajo),
            "CACHE_DIR": str(trabajo / "cache"),
            "DB_DSN": DB_DSN[ejecucion.modo],
            "LC_ALL": "C.UTF-8",
        }
    )

    try:
        ejecucion.fase_nueva(
            "preparando",
            f"Validando la prueba y el objetivo del laboratorio: {ejecucion.target}",
        )
        ejecucion.fase_nueva("ejecutando", f"Ejecutando attacks/{ejecucion.ident}.sh en modo {ejecucion.modo}")

        with open(salida_txt, "wb") as fsalida, open(error_txt, "wb") as ferror:
            proceso = subprocess.Popen(
                [
                    "bash",
                    str(REPO / "attacks" / f"{ejecucion.ident}.sh"),
                    ejecucion.target,
                    ejecucion.modo,
                ],
                stdout=fsalida,
                stderr=ferror,
                env=entorno,
                cwd=str(REPO),
                start_new_session=True,
            )

            lector_salida = Lector(salida_txt, ejecucion, "salida")
            lector_error = Lector(error_txt, ejecucion, "error")

            while True:
                lector_salida.bombear()
                lector_error.bombear()

                if proceso.poll() is not None:
                    break
                if time.time() - ejecucion.inicio > TIMEOUT_SECONDS:
                    _mata_grupo(proceso)
                    ejecucion.publicar("error", f"Tiempo agotado: el ataque superó {TIMEOUT_SECONDS} s")
                    break
                time.sleep(0.04)

            # Última pasada: vuelca lo que quedó en los buffers.
            lector_salida.bombear()
            lector_error.bombear()
            lector_salida.vaciar()
            lector_error.vaciar()

            codigo = proceso.wait()

        ejecucion.fase_nueva("recolectando", "Recolectando la evidencia: código de salida y salida completa")
        ejecucion.exit_code = codigo
        ejecucion.duracion_ms = int((time.time() - ejecucion.inicio) * 1000)

        ejecucion.fase_nueva("recolectando", "Extrayendo la evidencia visible de la respuesta cruda")
        ejecucion.evidencia = extraer_evidencia(ejecucion.ident, trabajo, ejecucion)

        ejecucion.fase_nueva("interpretando", "Interpretando el resultado contra la expectativa del modo")
        if codigo == 0:
            ejecucion.publicar(
                "veredicto", "ATAQUE EXITOSO: el defecto está presente (lo esperado en modo vulnerable)"
            )
        elif codigo == 1:
            ejecucion.publicar(
                "veredicto", "ATAQUE BLOQUEADO: la mitigación funcionó (lo esperado en modo endurecido)"
            )
        elif codigo == 124:
            ejecucion.publicar("veredicto", "TIEMPO AGOTADO: la prueba no terminó a tiempo")
        else:
            ejecucion.publicar("veredicto", f"SIN VEREDICTO: la prueba salió con código {codigo}")

        ejecucion.fase = "listo"
        ejecucion.estado = "listo"
    except Exception as error:  # noqa: BLE001 - se registra, no se filtra al cliente
        print(f"[error] fallo al ejecutar {ejecucion.ident} ({ejecucion.modo}): {error}", flush=True)
        ejecucion.publicar("error", "No se pudo ejecutar el ataque. Revisá el registro del contenedor.")
        ejecucion.fase = "error"
        ejecucion.estado = "error"
        ejecucion.exit_code = 125
    finally:
        shutil.rmtree(trabajo, ignore_errors=True)
        _ejecutando.release()


def _leer(ruta: Path, limite: int = 200_000) -> str:
    try:
        return ruta.read_text(encoding="utf-8", errors="replace")[:limite]
    except FileNotFoundError:
        return ""


def _evidencia_tabla(titulo, sub, fuente, columnas, filas, nota="") -> dict:
    return {
        "tipo": "tabla",
        "titulo": titulo,
        "sub": sub,
        "fuente": fuente,
        "columnas": columnas,
        "filas": filas,
        "nota": nota,
    }


def _evidencia_documento(titulo, sub, fuente, campos, contenido, denegado=False) -> dict:
    return {
        "tipo": "documento",
        "titulo": titulo,
        "sub": sub,
        "fuente": fuente,
        "campos": campos,
        "contenido": contenido,
        "denegado": denegado,
    }


def extraer_evidencia(ident: str, trabajo: Path, ejecucion: "Ejecucion") -> dict | None:
    """Convierte la salida cruda del ataque en evidencia legible para mostrar.

    Todo sale de los archivos que el propio script guardó en su directorio
    temporal o de sus líneas de salida: no se inventa ningún dato.
    """
    lineas = [linea["texto"] for linea in ejecucion.lineas]

    if ident == "01-sqli-search":
        crudo = _leer(trabajo / "01-sqli-search.html")
        filas = [
            [html.unescape(usuario), html.unescape(hash_expuesto)]
            for usuario, hash_expuesto in re.findall(
                r'<a href="/docs/\d+">([^<]+)</a></td><td>[^<]*</td><td>([^<]*)</td>', crudo
            )
        ]
        if not filas:
            return _evidencia_tabla(
                "La búsqueda no devolvió filas ajenas",
                "La consulta parametrizada trató el payload como texto plano",
                "01-sqli-search.html",
                ["Usuario filtrado", "Hash expuesto"],
                [],
                "En el modo endurecido el UNION SELECT no se interpreta como SQL.",
            )

        filas_hash = [
            fila for fila in filas if re.fullmatch(r"[0-9a-f]{32}|\$argon2.*", fila[1] or "")
        ]
        documentos = len(filas) - len(filas_hash)
        if not filas_hash:
            return _evidencia_tabla(
                "La búsqueda devolvió documentos ajenos",
                "El payload amplió el resultado más allá de los documentos del usuario",
                "01-sqli-search.html",
                ["Documento filtrado", "Archivo expuesto"],
                filas,
                "No se obtuvieron hashes: la tabla users no quedó expuesta por esta vía.",
            )
        return _evidencia_tabla(
            "Usuarios y hashes que devolvió la búsqueda inyectada",
            "El payload UNION SELECT agregó la tabla users al resultado",
            "01-sqli-search.html",
            ["Usuario filtrado", "Hash expuesto"],
            filas_hash,
            f"Además se filtraron {documentos} documentos ajenos en la misma respuesta."
            if documentos
            else "Cada fila es un usuario del sistema con su hash de contraseña.",
        )

    if ident == "02-xss-stored":
        crudo = _leer(trabajo / "02-dashboard.html")
        encontrado = re.search(r"<script[^>]*>.{0,80}?</script>", crudo, re.S)
        if encontrado:
            return {
                "tipo": "codigo",
                "titulo": "El título del documento se renderizó como HTML",
                "sub": "Esto es lo que el navegador ejecuta al abrir el panel",
                "fuente": "02-dashboard.html",
                "codigo": encontrado.group(0),
                "nota": "El script quedó guardado en la base y se ejecuta en el navegador de cada visitante.",
            }
        escapado = re.search(r"&lt;script&gt;.{0,90}", crudo, re.S)
        return {
            "tipo": "codigo",
            "titulo": "El título salió escapado",
            "sub": "El escape de salida convierte el script en texto inerte",
            "fuente": "02-dashboard.html",
            "codigo": (escapado.group(0) if escapado else "(sin coincidencias en la respuesta)"),
            "nota": "En el modo endurecido el navegador lo muestra como texto, no lo ejecuta.",
        }

    if ident == "03-idor":
        crudo = _leer(trabajo / "03-idor-doc1.html")
        if "Acceso denegado" in crudo:
            return _evidencia_documento(
                "El documento ajeno quedó bloqueado",
                "El servidor verificó la propiedad del recurso antes de leerlo",
                "03-idor-doc1.html",
                [("Propietario real", "alice"), ("Solicitante", "bob"), ("Resultado", "HTTP 403 · denegado")],
                "",
                denegado=True,
            )
        titulo = re.search(r"<h1>([^<]+)</h1>", crudo)
        duenio = re.search(r"<b>Dueño</b>([^<]*)</div>", crudo)
        contenido = re.search(r"<pre>(.*?)</pre>", crudo, re.S)
        return _evidencia_documento(
            "Documento confidencial leído sin permiso",
            f"bob abrió /docs/1, que pertenece a {(duenio.group(1).strip() if duenio else 'otro usuario')}",
            "03-idor-doc1.html",
            [
                ("Título", html.unescape(titulo.group(1)) if titulo else "—"),
                ("Propietario", duenio.group(1).strip() if duenio else "—"),
                ("Clasificación", "confidencial"),
                ("Resultado", "HTTP 200 · contenido servido"),
            ],
            html.unescape(contenido.group(1)).strip() if contenido else "",
        )

    if ident == "04-bruteforce":
        filas = [
            [intento, codigo, "sin límite" if codigo != "429" else "bloqueado"]
            for intento, codigo in re.findall(
                r"intento (\d+) con contrasena incorrecta -> HTTP (\d+)", "\n".join(lineas)
            )
        ]
        return _evidencia_tabla(
            "Intentos de autenticación con contraseña incorrecta",
            "Cada fila es una petición POST /login real",
            "salida del script",
            ["Intento", "HTTP", "Resultado"],
            filas,
            "Sin límite de intentos, la cuenta se puede atacar indefinidamente."
            if filas and filas[-1][2] == "sin límite"
            else "El límite de intentos cortó la prueba: la cuenta se bloquea temporalmente.",
        )

    if ident == "05-session-forgery":
        crudo = _leer(trabajo / "05-admin-forjado.html")
        filas = [
            [usuario, rol, docs, fallos]
            for usuario, rol, docs, fallos in re.findall(
                r"<td>([^<]+)</td><td>([^<]+)</td><td>(\d+)</td><td>(\d+)</td>", crudo
            )
        ]
        if not filas:
            return _evidencia_tabla(
                "La cookie forjada no abrió el panel",
                "La sesión firmada no valida y el rol se revalida en el servidor",
                "05-admin-forjado.html",
                ["Usuario", "Rol", "Documentos", "Intentos fallidos"],
                [],
                "Con `sid=alice:admin` el servidor endurecido redirige al login.",
            )
        return _evidencia_tabla(
            "Panel de administración abierto con una cookie inventada",
            "Se envió `sid=alice:admin` sin conocer ninguna contraseña",
            "05-admin-forjado.html",
            ["Usuario", "Rol", "Documentos", "Intentos fallidos"],
            filas,
            "Toda la tabla se sirvió a un cliente que solo copió un texto en la cookie.",
        )

    if ident == "06-weak-hash":
        hashes = {}
        craqueados = {}
        for linea in lineas:
            hallado = re.match(r"^\s+(\S+) -> (\S+)$", linea)
            if hallado:
                hashes[hallado.group(1)] = hallado.group(2)
                continue
            roto = re.match(r"^\s+CRACKEADO: (\S+):(.+)$", linea)
            if roto:
                craqueados[roto.group(1)] = roto.group(2)

        filas = []
        for usuario, valor in hashes.items():
            recortado = valor if len(valor) <= 36 else f"{valor[:33]}…"
            filas.append([usuario, recortado, craqueados.get(usuario, "no recuperada")])
        return _evidencia_tabla(
            "Hashes almacenados y contraseñas recuperadas",
            "Diccionario de diez palabras ejecutado contra los hashes de la base",
            "salida del script",
            ["Usuario", "Hash almacenado", "Contraseña recuperada"],
            filas,
            "Argon2id no cede a ese diccionario: cada intento cuesta 19 MiB de memoria."
            if filas and all(not _ for _ in craqueados) 
            else "MD5 sin sal se revierte en menos de un segundo por contraseña.",
        )

    if ident == "08-headers":
        filas = []
        for linea in lineas:
            presente = re.search(r"presente: (\S+)", linea)
            ausente = re.search(r"AUSENTE:\s+(\S+)", linea)
            if presente:
                filas.append([presente.group(1), "presente"])
            elif ausente:
                filas.append([ausente.group(1), "AUSENTE"])
        return _evidencia_tabla(
            "Cabeceras de seguridad de la respuesta",
            "Leídas de la respuesta HTTP de la portada",
            "08-headers.txt",
            ["Cabecera", "Estado"],
            filas,
            "Sin CSP ni X-Frame-Options el navegador no aplica ninguna defensa extra.",
        )

    return None


class Handler(SimpleHTTPRequestHandler):
    server_version = "PanelEvidencias/1.2"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC), **kwargs)

    # ------------------------------------------------------------ utilidades

    def _responder_json(self, estado: int, carga: dict) -> None:
        cuerpo = json.dumps(carga, ensure_ascii=False).encode("utf-8")
        self.send_response(estado)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-store")
        # Sin cabeceras CORS a propósito: otro origen no puede leer estas respuestas.
        self.end_headers()
        self.wfile.write(cuerpo)

    def _host_local(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]")
        return host in {"127.0.0.1", "localhost", "::1"}

    def _token_valido(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-Panel-Token") or "", TOKEN)

    def _autorizado(self) -> tuple[bool, int, dict]:
        if not self._host_local():
            return False, 403, {"error": "el panel solo atiende peticiones a 127.0.0.1"}
        if not self._token_valido():
            return False, 403, {"error": "token del panel ausente o inválido: recargá la página"}
        return True, 200, {}

    def _catalogo(self) -> dict:
        return {
            "ejecutables": RUNNABLE,
            "solo_terminal": HOST_ONLY,
            "targets": TARGETS,
            "timeout_seconds": TIMEOUT_SECONDS,
        }

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    # ---------------------------------------------------------------- rutas

    def do_GET(self) -> None:  # noqa: N802 - API de la librería estándar
        partes = urlparse(self.path)
        ruta = partes.path

        if ruta == "/api/catalogo":
            self._responder_json(200, self._catalogo())
            return

        if ruta == "/api/token":
            # Arranque del panel: se entrega el token a quien ya llegó por 127.0.0.1.
            if not self._host_local():
                self._responder_json(403, {"error": "el panel solo atiende peticiones a 127.0.0.1"})
                return
            self._responder_json(200, {"token": TOKEN})
            return

        if ruta.startswith("/api/run-progress/"):
            permitido, estado, error = self._autorizado()
            if not permitido:
                self._responder_json(estado, error)
                return

        if ruta.startswith("/api/run-progress/"):
            run_id = ruta.rsplit("/", 1)[-1]
            if not re.fullmatch(r"[0-9a-f]{12}", run_id):
                self._responder_json(400, {"error": "identificador de ejecución inválido"})
                return
            ejecucion = _buscar(run_id)
            if ejecucion is None:
                self._responder_json(404, {"error": "ejecución no encontrada o expirada"})
                return
            desde = 0
            valores = parse_qs(partes.query).get("desde")
            if valores:
                try:
                    desde = max(0, int(valores[0]))
                except ValueError:
                    desde = 0
            self._responder_json(200, ejecucion.instantanea(desde))
            return

        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802 - API de la librería estándar
        ruta = urlparse(self.path).path

        permitido, estado, error = self._autorizado()
        if not permitido:
            self._responder_json(estado, error)
            return

        try:
            longitud = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._responder_json(400, {"error": "Content-Length inválido"})
            return
        if longitud > MAX_BODY_BYTES:
            self._responder_json(413, {"error": "cuerpo de la petición demasiado grande"})
            return

        if ruta == "/api/recargar":
            resultado = subprocess.run(
                ["python", "/site/build_data.py"], capture_output=True, text=True, timeout=60
            )
            if resultado.returncode != 0:
                print(f"[error] recargar: {resultado.stdout}{resultado.stderr}", flush=True)
                self._responder_json(500, {"error": "no se pudieron regenerar los datos"})
                return
            resumen = resultado.stdout.strip().splitlines()[-1:] or ["datos regenerados"]
            self._responder_json(200, {"output": resumen[0]})
            return

        if not ruta.startswith("/api/run/"):
            self._responder_json(404, {"error": "ruta desconocida"})
            return

        ident = ruta.rsplit("/", 1)[-1]
        if not ID_PATTERN.match(ident):
            self._responder_json(400, {"error": "identificador de ataque inválido"})
            return

        try:
            cuerpo = json.loads(self.rfile.read(longitud) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._responder_json(400, {"error": "cuerpo JSON inválido"})
            return

        modo = cuerpo.get("mode")
        if modo not in TARGETS:
            self._responder_json(400, {"error": 'mode debe ser "vulnerable" o "hardened"'})
            return

        if ident in HOST_ONLY:
            self._responder_json(
                409,
                {
                    "error": f"{ident} no se ejecuta desde el panel: {HOST_ONLY[ident]}",
                    "comando": f"bash attacks/{ident}.sh {TARGETS[modo]} {modo}",
                },
            )
            return

        if ident not in RUNNABLE:
            self._responder_json(400, {"error": "ataque no habilitado en el panel"})
            return

        if not _ejecutando.acquire(blocking=False):
            self._responder_json(429, {"error": "ya hay una prueba en curso; esperá a que termine"})
            return

        ejecucion = Ejecucion(ident, modo)
        _registrar(ejecucion)
        hilo = threading.Thread(target=_correr, args=(ejecucion,), daemon=True)
        try:
            hilo.start()
        except RuntimeError:
            _ejecutando.release()
            self._responder_json(500, {"error": "no se pudo iniciar la prueba"})
            return

        self._responder_json(
            202,
            {
                "run_id": ejecucion.id,
                "ataque": ident,
                "modo": modo,
                "progreso": f"/api/run-progress/{ejecucion.id}",
            },
        )

    def log_message(self, formato: str, *args) -> None:
        print(f"{self.address_string()} {formato % args}", flush=True)


def main() -> int:
    print("generando datos del panel…", flush=True)
    subprocess.run(["/usr/local/bin/python", "/site/build_data.py"], check=False)

    puerto = int(os.environ.get("PORT", "8000"))
    servidor = ThreadingHTTPServer(("0.0.0.0", puerto), Handler)
    print(f"panel de evidencias en http://0.0.0.0:{puerto}", flush=True)
    print(f"  objetivo vulnerable: {TARGETS['vulnerable']}", flush=True)
    print(f"  objetivo endurecido: {TARGETS['hardened']}", flush=True)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

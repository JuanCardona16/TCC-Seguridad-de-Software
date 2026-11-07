#!/usr/bin/env python3
"""Servidor del panel de evidencias: archivos estáticos + ejecución en vivo.

Además de servir el panel, expone `POST /api/run/<ataque>` para que el docente
pueda ejecutar un ataque delante del grupo y ver la salida real.

Guardas del ejecutor (servidor local de laboratorio):

  1. Token de sesión por proceso: el panel obtiene `/api/token` (sin CORS, no
     cacheable) y lo envía en `X-Panel-Token`. Una página de otro origen no puede
     leer la respuesta de `/api/token`, así que no puede ejecutar nada (defensa
     contra CSRF y DNS rebinding).
  2. Solo atiende peticiones cuyo encabezado `Host` sea 127.0.0.1/localhost.
  3. El identificador del ataque debe cumplir un patrón estricto Y estar en la
     lista blanca; nunca se compone un comando con texto del cliente.
  4. El modo debe ser exactamente "vulnerable" o "hardened".
  5. Se ejecuta un único ataque a la vez (evita carreras y estados a medias).
  6. Cuerpo de la petición acotado, timeout con muerte del grupo de procesos y
     salida leída desde archivo (la memoria del proceso no crece con la salida).
  7. Directorio temporal y caché de cookies propios de cada ejecución, borrados
     al terminar: nunca se escriben las evidencias oficiales.

El proceso se lanza con Popen y una lista de argumentos (sin shell), de modo que
no hay interpretación de metacaracteres.
"""

from __future__ import annotations

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
from urllib.parse import urlparse

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

TOKEN = secrets.token_urlsafe(24)

_ejecutando = threading.Lock()


def _tail(ruta: Path, limite: int) -> str:
    """Devuelve los últimos `limite` bytes de un archivo, sin cargarlo entero."""
    try:
        with open(ruta, "rb") as archivo:
            archivo.seek(0, os.SEEK_END)
            tamano = archivo.tell()
            archivo.seek(max(0, tamano - limite))
            datos = archivo.read()
    except FileNotFoundError:
        return ""

    texto = datos.decode("utf-8", errors="replace")
    if tamano > limite:
        texto = f"[… {tamano - limite} bytes omitidos …]\n{texto}"
    return texto


def ejecutar_ataque(ident: str, modo: str) -> dict:
    """Ejecuta un ataque y devuelve salida, código y veredicto."""
    trabajo = Path("/tmp") / f"replay-{uuid.uuid4().hex[:8]}"
    (trabajo / "cache").mkdir(parents=True, exist_ok=True)
    salida_txt = trabajo / "stdout.log"
    error_txt = trabajo / "stderr.log"

    entorno = os.environ.copy()
    entorno.update(
        {
            "EVIDENCE_DIR": str(trabajo),
            # Caché de cookies propia de esta ejecución: se borra con el resto.
            "CACHE_DIR": str(trabajo / "cache"),
            "DB_DSN": DB_DSN[modo],
            "LC_ALL": "C.UTF-8",
        }
    )

    inicio = time.time()
    codigo = 125
    try:
        with open(salida_txt, "wb") as fsalida, open(error_txt, "wb") as ferror:
            proceso = subprocess.Popen(
                ["bash", str(REPO / "attacks" / f"{ident}.sh"), TARGETS[modo], modo],
                stdout=fsalida,
                stderr=ferror,
                env=entorno,
                cwd=str(REPO),
                start_new_session=True,  # grupo de procesos propio
            )
            try:
                codigo = proceso.wait(timeout=TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                # Mata también a los descendientes (curl, psql, etc.).
                try:
                    os.killpg(os.getpgid(proceso.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proceso.wait()
                codigo = 124

        salida = _tail(salida_txt, MAX_OUTPUT_CHARS)
        error = _tail(error_txt, 2000)
        if error.strip():
            salida += f"\n[stderr]\n{error}"
        if codigo == 124:
            salida = f"Tiempo agotado: el ataque superó los {TIMEOUT_SECONDS} s.\n{salida}"
    except Exception as error:  # noqa: BLE001 - se registra, no se filtra al cliente
        print(f"[error] fallo al ejecutar {ident} ({modo}): {error}", flush=True)
        codigo = 125
        salida = "No se pudo ejecutar el ataque. Revisá el registro del contenedor."
    finally:
        shutil.rmtree(trabajo, ignore_errors=True)

    return {
        "id": ident,
        "mode": modo,
        "target": TARGETS[modo],
        "exit_code": codigo,
        "ataque_exitoso": codigo == 0,
        "bloqueado": codigo == 1,
        "output": salida,
        "duration_ms": int((time.time() - inicio) * 1000),
    }


class Handler(SimpleHTTPRequestHandler):
    server_version = "PanelEvidencias/1.1"

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
        recibido = self.headers.get("X-Panel-Token") or ""
        return secrets.compare_digest(recibido, TOKEN)

    def _autorizado(self) -> tuple[bool, int, dict]:
        if not self._host_local():
            return False, 403, {"error": "el panel solo atiende peticiones a 127.0.0.1"}
        if not self._token_valido():
            return (
                False,
                403,
                {"error": "token del panel ausente o inválido: recargá la página"},
            )
        return True, 200, {}

    def _catalogo(self) -> dict:
        return {
            "ejecutables": RUNNABLE,
            "solo_terminal": HOST_ONLY,
            "targets": TARGETS,
            "timeout_seconds": TIMEOUT_SECONDS,
        }

    # ---------------------------------------------------------------- rutas

    def end_headers(self) -> None:
        # El panel es de un laboratorio local: nada se cachea ni se comparte.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def do_GET(self) -> None:  # noqa: N802 - API de la librería estándar
        ruta = urlparse(self.path).path
        if ruta == "/api/catalogo":
            self._responder_json(200, self._catalogo())
            return
        if ruta == "/api/token":
            if not self._host_local():
                self._responder_json(403, {"error": "solo disponible en 127.0.0.1"})
                return
            self._responder_json(200, {"token": TOKEN})
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
            # Solo se devuelve la última línea del resumen, sin rutas internas.
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
            self._responder_json(
                429, {"error": "ya hay una prueba en curso; esperá a que termine"}
            )
            return
        try:
            resultado = ejecutar_ataque(ident, modo)
        finally:
            _ejecutando.release()

        self._responder_json(200, resultado)

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

#!/usr/bin/env python3
"""Genera los diagramas SVG del TCC con layout calculado (sin coordenadas a mano).

Uso:  python3 docs/diagramas/generar_diagramas.py

Produce:
  docs/diagramas/arquitectura.svg   — arquitectura del laboratorio
  docs/diagramas/dfd-stride.svg     — flujo de datos con amenazas STRIDE

Las posiciones se calculan por grilla: cada caja sabe su fila y columna, las
flechas se enrutan por los canales libres entre columnas y las etiquetas se
anclan en esos canales, así no se superponen con el texto de las cajas.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path

SALIDA = Path(__file__).resolve().parent

FUENTE = "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, monospace"

FONDO = "#0d1117"
PANEL = "#161b22"
PANEL2 = "#1c2330"
LINEA = "#30363d"
TEXTO = "#e6edf3"
TENUE = "#8b949e"
ACENTO = "#58a6ff"
ROJO = "#f85149"
VERDE = "#3fb950"
AMBAR = "#d29922"

VULN_FONDO = "#1f1215"
HARD_FONDO = "#0f2117"
DATA_FONDO = "#101b2b"
STORE_FONDO = "#241a08"

TIPOS = {
    "vulnerable": (VULN_FONDO, ROJO, "#ffb3ae"),
    "endurecido": (HARD_FONDO, VERDE, "#9ae6b4"),
    "datos": (DATA_FONDO, ACENTO, "#a3c9f7"),
    "almacen": (STORE_FONDO, AMBAR, "#f5d78e"),
    "neutro": (PANEL2, TENUE, TEXTO),
}


def esc(texto: str) -> str:
    return (
        texto.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


@dataclass
class Caja:
    x: float
    y: float
    ancho: float
    alto: float
    titulo: str
    lineas: list[str] = field(default_factory=list)
    tipo: str = "neutro"
    subtitulo: str = ""

    @property
    def centro(self) -> tuple[float, float]:
        return (self.x + self.ancho / 2, self.y + self.alto / 2)

    def svg(self) -> str:
        fondo, borde, color_titulo = TIPOS[self.tipo]
        partes = [
            f'<rect x="{self.x}" y="{self.y}" width="{self.ancho}" height="{self.alto}" '
            f'rx="10" fill="{fondo}" stroke="{borde}" stroke-width="2"/>',
            f'<text x="{self.x + 18}" y="{self.y + 26}" fill="{color_titulo}" '
            f'font-family="{FUENTE}" font-size="15" font-weight="700">{esc(self.titulo)}</text>',
        ]
        if self.subtitulo:
            partes.append(
                f'<text x="{self.x + 18}" y="{self.y + 46}" fill="{TENUE}" '
                f'font-family="{MONO}" font-size="12">{esc(self.subtitulo)}</text>'
            )
        y_texto = self.y + (68 if self.subtitulo else 50)
        for linea in self.lineas:
            partes.append(
                f'<text x="{self.x + 18}" y="{y_texto}" fill="#c9d1d9" '
                f'font-family="{FUENTE}" font-size="12.5">{esc(linea)}</text>'
            )
            y_texto += 20
        return "\n    ".join(partes)


def caja(x, y, ancho, alto, titulo, lineas=None, tipo="neutro", subtitulo="") -> Caja:
    return Caja(x, y, ancho, alto, titulo, lineas or [], tipo, subtitulo)


def flecha(
    puntos: list[tuple[float, float]],
    color: str = TENUE,
    etiqueta: str = "",
    etiqueta_en: tuple[float, float] | None = None,
    tamano: int = 11,
    punteada: bool = False,
) -> str:
    """Polilínea con punta de flecha y etiqueta opcional."""
    trazo = " ".join(f"{x},{y}" for x, y in puntos)
    guion = ' stroke-dasharray="6 5"' if punteada else ""
    salida = [
        f'<polyline points="{trazo}" fill="none" stroke="{color}" stroke-width="2" '
        f'stroke-linejoin="round"{guion} marker-end="url(#punta-{_id_color(color)})"/>'
    ]
    if etiqueta and etiqueta_en:
        ex, ey = etiqueta_en
        salida.append(
            f'<text x="{ex}" y="{ey}" fill="{color}" font-family="{MONO}" font-size="{tamano}" '
            f'text-anchor="middle">{esc(etiqueta)}</text>'
        )
    return "\n    ".join(salida)


def _id_color(color: str) -> str:
    return {
        TENUE: "gris",
        ACENTO: "azul",
        ROJO: "rojo",
        VERDE: "verde",
        AMBAR: "ambar",
    }.get(color, "gris")


DEFS = f"""<defs>
    {''.join(
        f'<marker id="punta-{nombre}" markerWidth="9" markerHeight="7" refX="8" refY="3.5" orient="auto">'
        f'<path d="M0,0 L9,3.5 L0,7 z" fill="{color}"/></marker>'
        for nombre, color in [
            ("gris", TENUE),
            ("azul", ACENTO),
            ("rojo", ROJO),
            ("verde", VERDE),
            ("ambar", AMBAR),
        ]
    )}
  </defs>"""


def contenedor(x, y, ancho, alto, etiqueta: str = "", etiqueta_en: tuple[float, float] | None = None) -> str:
    """Caja de agrupación: el verificador la ignora al buscar cruces de flechas."""
    salida = (
        f'<rect x="{x}" y="{y}" width="{ancho}" height="{alto}" rx="14" '
        f'fill="#11161d" stroke="{LINEA}" stroke-dasharray="7 6" data-contenedor="1"/>'
    )
    if etiqueta:
        ex, ey = etiqueta_en or (x + 20, y + 26)
        salida += (
            f'\n    <text x="{ex}" y="{ey}" fill="{TENUE}" font-family="{MONO}" '
            f'font-size="12.5">{esc(etiqueta)}</text>'
        )
    return salida


def documento(ancho: int, alto: int, titulo: str, subtitulo: str, cuerpo: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{ancho}" height="{alto}" viewBox="0 0 {ancho} {alto}" role="img" aria-labelledby="titulo">
  <title id="titulo">{esc(titulo)}</title>
  {DEFS}

  <rect width="{ancho}" height="{alto}" fill="{FONDO}" data-contenedor="1"/>

  <text x="40" y="44" fill="{TEXTO}" font-family="{FUENTE}" font-size="23" font-weight="700">{esc(titulo)}</text>
  <text x="40" y="68" fill="{TENUE}" font-family="{FUENTE}" font-size="13.5">{esc(subtitulo)}</text>

  {cuerpo}
</svg>
"""


# ---------------------------------------------------------------------------
# Diagrama 1: arquitectura
# ---------------------------------------------------------------------------

def arquitectura() -> str:
    """Layout en bandas con corredores reservados: ninguna flecha cruza una caja."""
    ancho, alto = 1280, 860

    # -- banda del host (contenedor) -----------------------------------------
    host = contenedor(40, 90, 230, 520, "Host Linux · 127.0.0.1", (58, 114))
    navegador = caja(58, 132, 194, 92, "Navegador / auditor",
                     ["interacción manual", "Burp · ZAP (proxy)"], "neutro")
    suite = caja(58, 236, 194, 84, "Suite de ataques",
                 ["curl · sqlmap · hydra", "attacks/*.sh"], "neutro")
    panel = caja(58, 332, 194, 92, "Panel de evidencias",
                 ["ejecuta ataques", "en vivo desde 18090"], "neutro")
    nota_host = (
        f'<text x="58" y="474" fill="{TENUE}" font-family="{FUENTE}" font-size="12">'
        "Sin herramientas de seguridad</text>\n    "
        f'<text x="58" y="494" fill="{TENUE}" font-family="{FUENTE}" font-size="12">'
        "instaladas en el host: todo</text>\n    "
        f'<text x="58" y="514" fill="{TENUE}" font-family="{FUENTE}" font-size="12">'
        "vive en contenedores</text>"
    )

    # -- red del laboratorio (contenedor) ------------------------------------
    red = contenedor(310, 90, 620, 570, "lab_net · bridge 172.28.60.0/24 · red aislada", (330, 112))
    vuln = caja(334, 250, 270, 220, "app-vuln · :18080",
                ["MD5 sin sal", "cookie usuario:rol", "SQL concatenado",
                 "salida sin escapar", "sin verificar dueño", "/debug/config expuesto"],
                "vulnerable", "MODE=vulnerable")
    attacker = caja(334, 500, 270, 130, "attacker · netshoot",
                    ["tcpdump sobre el bridge", "NET_ADMIN / NET_RAW", "perfil: tools"],
                    "neutro", "captura de tráfico")
    gateway = caja(650, 130, 250, 120, "gateway nginx · :18443",
                   ["TLS 1.2 / 1.3 · AEAD", "HSTS · 301 desde :18083"],
                   "endurecido", "terminación TLS")
    hard = caja(650, 280, 250, 240, "app-hard · :8080",
                ["Argon2id (19 MiB, t=2)", "AES-256-GCM en reposo",
                 "sesión + HMAC-SHA256", "RBAC revalidado · TOTP",
                 "CSP · auditoría", "consultas parametrizadas"],
                "endurecido", "MODE=hardened")

    # -- almacenes -----------------------------------------------------------
    db = caja(980, 130, 290, 200, "db · PostgreSQL 16",
              ["sin puerto publicado", "minigestor_vuln", "minigestor_hard",
               "users · documents", "sessions · audit_log"],
              "datos", "solo en lab_net")
    docs = caja(980, 370, 290, 150, "volúmenes /data/docs",
                ["v1: nombre del cliente", "v1: contenido en claro",
                 "v2: nombre opaco (uuid)", "v2: AES-256-GCM + tag"],
                "almacen")

    firewall = caja(334, 686, 590, 86, "firewall · nftables (perfil tools)",
                    ["política drop por defecto · solo 443 desde lab_net",
                     "registro de intentos rechazados"],
                    "neutro")

    leyenda = [
        f'<rect x="40" y="630" width="230" height="150" rx="10" fill="{PANEL}" stroke="{LINEA}"/>',
        f'<text x="58" y="654" fill="{TEXTO}" font-family="{FUENTE}" font-size="12.5" font-weight="700">Leyenda</text>',
        f'<rect x="58" y="668" width="13" height="13" fill="{VULN_FONDO}" stroke="{ROJO}" stroke-width="2"/>',
        f'<text x="82" y="679" fill="#c9d1d9" font-family="{FUENTE}" font-size="12">superficie vulnerable (v1)</text>',
        f'<rect x="58" y="692" width="13" height="13" fill="{HARD_FONDO}" stroke="{VERDE}" stroke-width="2"/>',
        f'<text x="82" y="703" fill="#c9d1d9" font-family="{FUENTE}" font-size="12">superficie endurecida (v2)</text>',
        f'<rect x="58" y="716" width="13" height="13" fill="{DATA_FONDO}" stroke="{ACENTO}" stroke-width="2"/>',
        f'<text x="82" y="727" fill="#c9d1d9" font-family="{FUENTE}" font-size="12">datos estructurados</text>',
        f'<rect x="58" y="740" width="13" height="13" fill="{STORE_FONDO}" stroke="{AMBAR}" stroke-width="2"/>',
        f'<text x="82" y="751" fill="#c9d1d9" font-family="{FUENTE}" font-size="12">almacenamiento de archivos</text>',
    ]

    flechas = [
        # panel del host -> app vulnerable (corredor corto)
        flecha([(252, 378), (334, 378)], ROJO, "HTTP", (293, 366)),
        # navegador -> gateway TLS (corre por encima de la app vulnerable)
        flecha([(252, 178), (650, 178)], VERDE, "HTTPS", (451, 166)),
        # gateway -> app endurecida
        flecha([(775, 250), (775, 280)], VERDE, "proxy_pass", (790, 268), 10.5),
        # app vulnerable -> base de datos (baja por el corredor y entra por la izquierda)
        flecha([(604, 430), (620, 430), (620, 655), (950, 655), (950, 310), (980, 310)],
               ACENTO, "SQL", (700, 645)),
        # app endurecida -> volúmenes
        flecha([(900, 400), (980, 400)], AMBAR, "escritura", (940, 388), 10.5),
        # captura de tráfico
        flecha([(470, 500), (470, 470)], TENUE, "captura .pcap", (470, 490), 10.5, punteada=True),
    ]

    notas = (
        f'<text x="334" y="800" fill="{TENUE}" font-family="{FUENTE}" font-size="12.5">'
        "Las dos versiones comparten esquema de datos pero no instancia: las evidencias antes/después no se contaminan.</text>\n    "
        f'<text x="334" y="822" fill="{TENUE}" font-family="{FUENTE}" font-size="12.5">'
        "Ningún puerto se publica fuera de 127.0.0.1; la base de datos no publica puerto alguno.</text>"
    )

    cuerpo = "\n  ".join(
        [
            host, red,
            navegador.svg(), suite.svg(), panel.svg(), nota_host,
            vuln.svg(), attacker.svg(), gateway.svg(), hard.svg(),
            db.svg(), docs.svg(), firewall.svg(),
            *leyenda, *flechas, notas,
        ]
    )

    return documento(
        ancho, alto,
        "MiniGestor Documental — arquitectura del laboratorio",
        "Un binario, dos políticas de seguridad · todo publicado sobre 127.0.0.1 · datos simulados",
        cuerpo,
    )


# ---------------------------------------------------------------------------
# Diagrama 2: flujo de datos + STRIDE
# ---------------------------------------------------------------------------

def dfd() -> str:
    ancho, alto = 1280, 940
    y0 = 110

    entidad_x, entidad_ancho = 40, 210
    proceso_x, proceso_ancho = 380, 300
    almacen_x, almacen_ancho = 830, 300

    canal_ep = (entidad_x + entidad_ancho + proceso_x) / 2
    canal_pa = (proceso_x + proceso_ancho + almacen_x) / 2

    entidad = caja(
        entidad_x, y0 + 120, entidad_ancho, 330, "Usuario",
        ["navegador / auditor", "· ingresa credenciales", "· busca y lee documentos",
         "· sube archivos", "· administra usuarios"],
        "neutro", "entidad externa",
    )

    p1 = caja(proceso_x, y0, proceso_ancho, 104, "1 · Autenticación",
              ["verifica contraseña · TOTP", "v1: MD5 · cookie usuario:rol"],
              "datos", "proceso")
    p2 = caja(proceso_x, y0 + 124, proceso_ancho, 104, "2 · Consulta de documentos",
              ["búsqueda y render HTML", "v1: SQL concatenado, sin escape"],
              "datos", "proceso")
    p3 = caja(proceso_x, y0 + 248, proceso_ancho, 104, "3 · Carga de documentos",
              ["valida, nombra y persiste", "v1: nombre del cliente = ruta"],
              "datos", "proceso")
    p4 = caja(proceso_x, y0 + 372, proceso_ancho, 104, "4 · Descarga y auditoría",
              ["autoriza y registra el evento", "v1: sin autorización ni log"],
              "datos", "proceso")

    d1 = caja(almacen_x, y0, almacen_ancho, 104, "D1 · users",
              ["credenciales, rol, secreto TOTP", "contadores de intentos"],
              "almacen", "almacén de datos")
    d2 = caja(almacen_x, y0 + 124, almacen_ancho, 104, "D2 · documents + archivos",
              ["metadatos y contenido", "volumen /data/docs"],
              "almacen", "almacén de datos")
    d3 = caja(almacen_x, y0 + 372, almacen_ancho, 104, "D3 · audit_log",
              ["actor, acción, objetivo, resultado", "solo se usa en v2"],
              "almacen", "almacén de datos")

    # (origen_y, destino_y, destino_x, color, etiqueta, amenaza, y_de_la_etiqueta)
    flujos = [
        (y0 + 40, y0 + 40, proceso_x, ROJO, "F1 credenciales", "S · fuerza bruta", y0 + 30),
        (y0 + 40, y0 + 40, almacen_x, ROJO, "F2 hash", "I · MD5 sin sal", y0 + 30),
        (y0 + 176, y0 + 176, proceso_x, ROJO, "F3 búsqueda", "T · SQL injection", y0 + 166),
        (y0 + 176, y0 + 176, almacen_x, ROJO, "F4 SQL", "E · sin dueño", y0 + 166),
        (y0 + 300, y0 + 300, proceso_x, ROJO, "F5 archivo", "T · traversal", y0 + 290),
        (y0 + 300, y0 + 176, almacen_x, ROJO, "F6 escritura", "I · texto claro", y0 + 262),
        (y0 + 424, y0 + 424, proceso_x, ROJO, "F7 descarga", "I · IDOR", y0 + 414),
        (y0 + 424, y0 + 424, almacen_x, VERDE, "F8 evento (v2)", "R · repudio", y0 + 414),
    ]

    cuerpo = []
    for origen_y, destino_y, destino_x, color, etiqueta, amenaza, y_etiqueta in flujos:
        inicio_x = entidad_x + entidad_ancho if destino_x == proceso_x else proceso_x + proceso_ancho
        canal = canal_ep if destino_x == proceso_x else canal_pa
        cuerpo.append(
            flecha([(inicio_x, origen_y), (destino_x, destino_y)], color, etiqueta, (canal, y_etiqueta))
        )
        cuerpo.append(
            f'<text x="{canal}" y="{y_etiqueta + 16}" fill="{AMBAR}" font-family="{MONO}" '
            f'font-size="10.5" text-anchor="middle">{esc(amenaza)}</text>'
        )

    tabla_y = y0 + 520
    filas = [
        ("F1", "Spoofing", "Suplantación de usuario y fuerza bruta", "sin límite ni bloqueo", "04-bruteforce"),
        ("F2", "Information disclosure", "Hashes expuestos en una brecha", "MD5 sin sal", "06-weak-hash"),
        ("F3", "Tampering", "Inyección SQL en la búsqueda", "SQL concatenado", "01-sqli-search"),
        ("F4", "Elevation of privilege", "Lectura de documentos ajenos", "sin verificar dueño", "03-idor"),
        ("F5", "Tampering", "Escritura fuera del almacén", "nombre del cliente como ruta", "07-upload-traversal"),
        ("F6", "Information disclosure", "Contenido en claro en disco", "sin cifrado en reposo", "07-upload-traversal"),
        ("F7", "Elevation of privilege", "XSS en el navegador de la víctima", "salida sin escapar", "02-xss-stored"),
        ("F8", "Repudiation", "No se puede reconstruir quién hizo qué", "sin audit_log", "08-headers"),
    ]

    columnas = [
        (60, "FLUJO"), (140, "STRIDE"), (330, "AMENAZA"),
        (700, "DEFECTO EN V1"), (1000, "ATAQUE QUE LO DEMUESTRA"),
    ]
    cabecera = "".join(
        f'<text x="{x}" y="{tabla_y}" fill="{TENUE}" font-family="{MONO}" font-size="10.5">{esc(titulo)}</text>'
        for x, titulo in columnas
    )

    cuerpo_tabla = [cabecera]
    y_fila = tabla_y + 24
    for flujo, stride, amenaza, defecto, ataque in filas:
        cuerpo_tabla.append(
            f'<line x1="50" y1="{y_fila - 16}" x2="1230" y2="{y_fila - 16}" stroke="{LINEA}" stroke-width="1"/>'
        )
        cuerpo_tabla.append(f'<text x="60" y="{y_fila}" fill="#c9d1d9" font-family="{FUENTE}" font-size="12.5">{esc(flujo)}</text>')
        cuerpo_tabla.append(f'<text x="140" y="{y_fila}" fill="{AMBAR}" font-family="{FUENTE}" font-size="12.5">{esc(stride)}</text>')
        cuerpo_tabla.append(f'<text x="330" y="{y_fila}" fill="#c9d1d9" font-family="{FUENTE}" font-size="12.5">{esc(amenaza)}</text>')
        cuerpo_tabla.append(f'<text x="700" y="{y_fila}" fill="{TENUE}" font-family="{FUENTE}" font-size="12.5">{esc(defecto)}</text>')
        cuerpo_tabla.append(f'<text x="1000" y="{y_fila}" fill="{ACENTO}" font-family="{MONO}" font-size="11.5">{esc(ataque)}</text>')
        y_fila += 30

    cuerpo.extend(
        [
            entidad.svg(), p1.svg(), p2.svg(), p3.svg(), p4.svg(),
            d1.svg(), d2.svg(), d3.svg(),
            f'<text x="40" y="{y0 + 490}" fill="{TEXTO}" font-family="{FUENTE}" font-size="15" font-weight="700">'
            "Amenazas identificadas por flujo (STRIDE)</text>",
            f'<text x="40" y="{y0 + 508}" fill="{TENUE}" font-family="{FUENTE}" font-size="12">'
            "Cada flujo marcado en rojo es el que la suite de ataques explota en el modo vulnerable.</text>",
            *cuerpo_tabla,
        ]
    )

    return documento(
        ancho, alto,
        "MiniGestor Documental — flujo de datos y amenazas (STRIDE)",
        "Ocho flujos entre el usuario, los procesos y los almacenes · cada amenaza tiene su ataque",
        "\n  ".join(cuerpo),
    )


def main() -> int:
    (SALIDA / "arquitectura.svg").write_text(arquitectura(), encoding="utf-8")
    (SALIDA / "dfd-stride.svg").write_text(dfd(), encoding="utf-8")
    for nombre in ("arquitectura.svg", "dfd-stride.svg"):
        ruta = SALIDA / nombre
        print(f"  {nombre}: {ruta.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

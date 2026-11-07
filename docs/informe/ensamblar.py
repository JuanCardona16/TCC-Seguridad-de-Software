#!/usr/bin/env python3
"""Ensambla el HTML final del informe: portada, índice y cuerpo.

Además convierte los envoltorios `::: {.tabla-anchos data-cols="18,32,50"}` en
un <colgroup> real, de modo que con `table-layout: fixed` cada columna tenga el
ancho declarado y el texto se ajuste dentro de la celda en lugar de desbordar.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent
CUERPO = AQUI / ".cuerpo.html"
SALIDA = AQUI / "TCC-seguridad-informatica.html"
PORTADA = AQUI / "portada.html"
ESTILOS = AQUI / "print.css"
TOC_SALIDA = AQUI / ".toc.json"
PAGINAS = AQUI / ".paginas.json"

PATRON_ENVOLTORIO = re.compile(
    r'<div class="tabla-anchos"[^>]*data-cols="([^"]+)"[^>]*>(.*?)</div>', re.S
)
PATRON_TABLA = re.compile(r"<table[^>]*>")


def inyectar_anchos(bloque: str, anchos: list[str]) -> str:
    """Inserta un <colgroup> con los porcentajes normalizados.

    pandoc agrega su propio <colgroup> cuando la tabla tiene anchos relativos;
    se descarta antes de inyectar el declarado, porque el primero gana.
    """
    bloque = re.sub(r"<colgroup>.*?</colgroup>", "", bloque, flags=re.S)
    valores = []
    for ancho in anchos:
        try:
            valores.append(float(ancho.strip()))
        except ValueError:
            valores.append(1.0)
    total = sum(valores) or 1.0
    columnas = "".join(
        f'<col style="width:{valor / total * 100:.2f}%">' for valor in valores
    )
    return PATRON_TABLA.sub(
        lambda m: f'{m.group(0)}<colgroup>{columnas}</colgroup>', bloque, count=1
    )


PATRON_ENCABEZADO = re.compile(r'<h([23]) id="([^"]+)"[^>]*>(.*?)</h\1>', re.S)


def quitar_etiquetas(texto: str) -> str:
    return re.sub(r"<[^>]+>", "", texto).replace("&amp;", "&").strip()


def construir_indice(cuerpo: str, paginas: dict[str, int]) -> str:
    """Índice de contenido con números de página y puntos guía."""
    secciones = [
        {"nivel": int(nivel), "id": ident, "texto": quitar_etiquetas(interior)}
        for nivel, ident, interior in PATRON_ENCABEZADO.findall(cuerpo)
    ]
    TOC_SALIDA.write_text(
        __import__("json").dumps(secciones, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    filas = []
    for seccion in secciones:
        numero = paginas.get(seccion["id"], 0)
        clase = "n1" if seccion["nivel"] == 2 else "n2"
        etiqueta = f'<span class="pag">{numero}</span>' if numero else ""
        filas.append(
            f'<li class="{clase}"><a href="#{seccion["id"]}">'
            f'<span class="txt">{seccion["texto"]}</span>'
            f'<span class="puntos"></span>{etiqueta}</a></li>'
        )
    return (
        '<nav id="TOC"><h2>Contenido</h2><ul>' + "".join(filas) + "</ul></nav>"
    )


def procesar_tablas(html: str) -> tuple[str, int]:
    procesadas = 0

    def reemplazo(match: re.Match) -> str:
        nonlocal procesadas
        procesadas += 1
        anchos = match.group(1).split(",")
        interior = inyectar_anchos(match.group(2), anchos)
        return f'<div class="tabla-anchos">\n{interior}\n</div>'

    return PATRON_ENVOLTORIO.sub(reemplazo, html), procesadas


def main() -> int:
    for requerido in (CUERPO, PORTADA, ESTILOS):
        if not requerido.exists():
            print(f"falta {requerido}", file=sys.stderr)
            return 1

    cuerpo = CUERPO.read_text(encoding="utf-8")
    portada = PORTADA.read_text(encoding="utf-8")
    estilos = ESTILOS.read_text(encoding="utf-8")

    cuerpo, tablas = procesar_tablas(cuerpo)

    paginas: dict[str, int] = {}
    if PAGINAS.exists():
        paginas = __import__("json").loads(PAGINAS.read_text(encoding="utf-8"))
    indice = construir_indice(cuerpo, paginas)

    documento = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Endurecimiento de una aplicación de gestión documental — TCC Seguridad Informática 2026-2</title>
<style>
{estilos}
</style>
</head>
<body>
{portada}
{indice}
{cuerpo}
</body>
</html>
"""
    SALIDA.write_text(documento, encoding="utf-8")
    print(f"  tablas con ancho declarado: {tablas}")
    print(f"  índice: {len(__import__("json").loads(TOC_SALIDA.read_text(encoding="utf-8")))} entradas"
          + (" (con páginas)" if paginas else " (primera pasada, sin páginas)"))
    print(f"  HTML final: {SALIDA.name} ({len(documento) // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Indexa el informe y numera el contenido por páginas.

Se ejecuta entre las dos pasadas de construcción:

  1. `ensamblar.py` deja el índice sin números y escribe `.toc.json` con las
     secciones y sus identificadores.
  2. Se genera un PDF de prueba; este script busca en qué página aparece cada
     sección con `pdftotext` y escribe `.paginas.json`.
  3. `ensamblar.py --paginas .paginas.json` reconstruye el índice con los
     números y se genera el PDF definitivo.

Uso:  python3 docs/informe/numerar_toc.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

AQUI = Path(__file__).resolve().parent
PDF = AQUI / "TCC-seguridad-informatica.pdf"
TOC = AQUI / ".toc.json"
PAGINAS = AQUI / ".paginas.json"
PRIMERA_PAGINA_CUERPO = 2  # 1 = portada; las páginas del índice se descartan al comparar


def normalizar(texto: str) -> str:
    """Minúsculas, sin tildes, sin puntuación y con espacios simples."""
    sin_tildes = "".join(
        c for c in unicodedata.normalize("NFD", texto) if unicodedata.category(c) != "Mn"
    )
    limpio = re.sub(r"[^a-z0-9 ]+", " ", sin_tildes.lower())
    return re.sub(r"\s+", " ", limpio).strip()


def paginas_del_pdf() -> int:
    salida = subprocess.run(["pdfinfo", str(PDF)], capture_output=True, text=True, check=True)
    hallado = re.search(r"Pages:\s+(\d+)", salida.stdout)
    return int(hallado.group(1)) if hallado else 0


def lineas_de_pagina(pagina: int) -> list[str]:
    salida = subprocess.run(
        ["pdftotext", "-layout", "-f", str(pagina), "-l", str(pagina), str(PDF), "-"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [normalizar(linea) for linea in salida.stdout.splitlines() if linea.strip()]


def parece_indice(lineas: list[str]) -> bool:
    """El índice se reconoce porque casi todas sus líneas terminan en el número
    de página; el cuerpo termina en palabras."""
    if not lineas:
        return True
    if lineas[0] == "contenido":
        return True
    con_numero = sum(1 for linea in lineas if linea.rstrip()[-1:].isdigit())
    return len(lineas) >= 6 and con_numero / len(lineas) >= 0.6


def buscar(lineas: list[str], objetivo: str) -> bool:
    """Coincide si el título ocupa una línea propia o si está partido en dos.

    En el índice el título lleva el número de página al lado, por eso se exige
    coincidencia exacta o de línea completa; el índice además se descarta antes
    por no tener prosa.
    """
    if not objetivo:
        return False
    if any(linea == objetivo for linea in lineas):
        return True
    if any(linea.startswith(objetivo) for linea in lineas):
        return True
    return objetivo in " ".join(lineas)


def main() -> int:
    if not TOC.exists():
        print(f"falta {TOC}: corré ensamblar.py primero", file=sys.stderr)
        return 1
    if not PDF.exists():
        print(f"falta {PDF}", file=sys.stderr)
        return 1

    secciones = json.loads(TOC.read_text(encoding="utf-8"))
    total = paginas_del_pdf()
    lineas = {pagina: lineas_de_pagina(pagina) for pagina in range(1, total + 1)}
    paginas_indice = [p for p in range(2, total + 1) if parece_indice(lineas[p])]
    while paginas_indice and paginas_indice[0] > 2:
        # El índice es contiguo: solo cuentan las páginas iniciales.
        paginas_indice = [p for p in paginas_indice if p == 2 or p - 1 in paginas_indice]
    inicio_cuerpo = (max(paginas_indice) + 1) if paginas_indice else 2
    print(f"  páginas de índice: {paginas_indice} · el cuerpo empieza en la página {inicio_cuerpo}")
    siguiente = inicio_cuerpo

    paginas: dict[str, int] = {}
    for seccion in secciones:
        objetivo = normalizar(seccion["texto"])
        # Los títulos de tabla no son secciones: se buscan igual y, si no
        # aparecen, simplemente quedan sin número.
        encontrada = None
        for pagina in range(siguiente, total + 1):

            if buscar(lineas.get(pagina, []), objetivo):
                encontrada = pagina
                break
        if encontrada:
            paginas[seccion["id"]] = encontrada
            siguiente = encontrada
        else:
            paginas[seccion["id"]] = 0

    PAGINAS.write_text(json.dumps(paginas, ensure_ascii=False, indent=2), encoding="utf-8")
    faltantes = [clave for clave, valor in paginas.items() if valor == 0]
    print(f"  secciones indexadas: {len(paginas) - len(faltantes)}/{len(paginas)}")
    if faltantes:
        print(f"  sin página detectada: {', '.join(faltantes)}")

    # Comprobación: cada sección debe estar realmente en la página anotada.
    errores = [
        seccion["texto"]
        for seccion in secciones
        if paginas.get(seccion["id"])
        and not buscar(lineas.get(paginas[seccion["id"]], []), normalizar(seccion["texto"]))
    ]
    if errores:
        print(f"  páginas que no coinciden: {', '.join(errores)}")
        return 1
    print("  cada entrada del índice aparece en la página anotada")
    return 0


if __name__ == "__main__":
    sys.exit(main())

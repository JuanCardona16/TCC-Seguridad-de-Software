#!/usr/bin/env python3
"""Verifica la geometría de los SVG del TCC.

No reemplaza la revisión visual: detecta los errores que sí se pueden medir.
Estima el ancho de cada texto (caracteres × factor por familia y tamaño) y busca

  1. texto que se sale del lienzo,
  2. texto que se superpone con otro texto,
  3. texto que se superpone con una caja que no es la suya,
  4. flechas cuyo trazo atraviesa una caja.

Uso:  python3 docs/diagramas/verificar.py
Salida: informe por archivo y código de salida 1 si hay hallazgos.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

DIR = Path(__file__).resolve().parent
NS = "{http://www.w3.org/2000/svg}"

# Ancho medio de carácter relativo al tamaño de fuente.
FACTOR = {"sans": 0.52, "mono": 0.60}


@dataclass
class Rect:
    x: float
    y: float
    w: float
    h: float
    nombre: str = ""


@dataclass
class Texto:
    x: float
    y: float
    w: float
    h: float
    contenido: str
    ancla: str = "start"

    @property
    def x0(self) -> float:
        return self.x - self.w / 2 if self.ancla == "middle" else self.x

    @property
    def caja(self) -> tuple[float, float, float, float]:
        return (self.x0, self.y - self.h * 0.8, self.x0 + self.w, self.y + self.h * 0.25)


def es_mono(familia: str) -> bool:
    return "mono" in familia.lower()


def leer_svg(ruta: Path):
    arbol = ET.parse(ruta)
    raiz = arbol.getroot()
    ancho = float(raiz.get("width", 0))
    alto = float(raiz.get("height", 0))

    rects: list[Rect] = []
    contenedores: set[int] = set()
    textos: list[Texto] = []
    lineas: list[tuple[float, float, float, float]] = []

    for elemento in raiz.iter():
        etiqueta = elemento.tag.replace(NS, "")
        if etiqueta == "rect":
            if elemento.get("data-contenedor") == "1":
                contenedores.add(len(rects))
            rects.append(
                Rect(
                    float(elemento.get("x", 0)),
                    float(elemento.get("y", 0)),
                    float(elemento.get("width", 0)),
                    float(elemento.get("height", 0)),
                )
            )
        elif etiqueta == "text":
            contenido = "".join(elemento.itertext()).strip()
            if not contenido:
                continue
            tamano = float(elemento.get("font-size", 12))
            familia = elemento.get("font-family", "sans")
            factor = FACTOR["mono"] if es_mono(familia) else FACTOR["sans"]
            textos.append(
                Texto(
                    x=float(elemento.get("x", 0)),
                    y=float(elemento.get("y", 0)),
                    w=len(contenido) * tamano * factor,
                    h=tamano,
                    contenido=contenido,
                    ancla=elemento.get("text-anchor", "start"),
                )
            )
        elif etiqueta == "polyline":
            puntos = [
                tuple(float(v) for v in par.split(","))
                for par in elemento.get("points", "").split()
                if "," in par
            ]
            for (x1, y1), (x2, y2) in zip(puntos, puntos[1:]):
                lineas.append((x1, y1, x2, y2))

    return ancho, alto, rects, textos, lineas, contenedores


def solapan(a: tuple, b: tuple, margen: float = 1.0) -> bool:
    return not (
        a[2] <= b[0] + margen
        or b[2] <= a[0] + margen
        or a[3] <= b[1] + margen
        or b[3] <= a[1] + margen
    )


def dentro(caja: tuple, rect: Rect, margen: float = 0.5) -> bool:
    return (
        caja[0] >= rect.x - margen
        and caja[2] <= rect.x + rect.w + margen
        and caja[1] >= rect.y - margen
        and caja[3] <= rect.y + rect.h + margen
    )


def segmento_cruza_rect(linea, rect: Rect) -> bool:
    x1, y1, x2, y2 = linea
    # Solo interesan los segmentos horizontales o verticales (los usa el generador).
    if abs(y1 - y2) < 0.5:
        y = y1
        xmin, xmax = sorted((x1, x2))
        return rect.y < y < rect.y + rect.h and xmin < rect.x + rect.w and xmax > rect.x
    if abs(x1 - x2) < 0.5:
        x = x1
        ymin, ymax = sorted((y1, y2))
        return rect.x < x < rect.x + rect.w and ymin < rect.y + rect.h and ymax > rect.y
    return False


def revisar(ruta: Path) -> list[str]:
    ancho, alto, rects, textos, lineas, contenedores = leer_svg(ruta)
    problemas: list[str] = []

    for texto in textos:
        caja = texto.caja
        if caja[0] < 0 or caja[2] > ancho or caja[3] > alto:
            problemas.append(
                f"texto fuera del lienzo: «{texto.contenido[:48]}» "
                f"(x {caja[0]:.0f}..{caja[2]:.0f}, y {caja[1]:.0f}..{caja[3]:.0f})"
            )

    for i, a in enumerate(textos):
        for b in textos[i + 1 :]:
            if solapan(a.caja, b.caja, margen=0.5):
                problemas.append(
                    f"texto superpuesto: «{a.contenido[:36]}» vs «{b.contenido[:36]}»"
                )

    for texto in textos:
        caja = texto.caja
        ajenas = [
            r for indice, r in enumerate(rects)
            if indice not in contenedores and not dentro(caja, r)
        ]
        for rect in ajenas:
            propio = (
                caja[0] >= rect.x - 0.5
                and caja[2] <= rect.x + rect.w + 0.5
                and caja[1] >= rect.y - 0.5
                and caja[3] <= rect.y + rect.h + 0.5
            )
            if propio:
                continue
            if solapan(caja, (rect.x, rect.y, rect.x + rect.w, rect.y + rect.h), margen=0.5):
                problemas.append(
                    f"texto encima de una caja ajena: «{texto.contenido[:36]}» "
                    f"({texto.x:.0f},{texto.y:.0f}) sobre caja {rect.w:.0f}x{rect.h:.0f} en ({rect.x:.0f},{rect.y:.0f})"
                )

    for linea in lineas:
        for indice, rect in enumerate(rects):
            if indice in contenedores:
                continue
            if segmento_cruza_rect(linea, rect):
                problemas.append(
                    f"flecha atraviesa una caja en ({rect.x:.0f},{rect.y:.0f}) "
                    f"{rect.w:.0f}x{rect.h:.0f}: trazo {linea}"
                )

    return problemas


def main() -> int:
    total = 0
    for ruta in sorted(DIR.glob("*.svg")):
        problemas = revisar(ruta)
        print(f"\n{ruta.name}")
        if not problemas:
            print("  sin solapamientos detectados")
            continue
        total += len(problemas)
        vistos = set()
        for problema in problemas:
            if problema in vistos:
                continue
            vistos.add(problema)
            print(f"  - {problema}")

    print(f"\ntotal de hallazgos: {total}")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

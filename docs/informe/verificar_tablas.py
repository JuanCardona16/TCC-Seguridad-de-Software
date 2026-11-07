#!/usr/bin/env python3
"""Comprueba que ninguna celda de tabla desborde su columna en el HTML del informe.

Chromium carga el documento, mide `scrollWidth` contra `clientWidth` en cada
celda (y en cada bloque de código) y deja el resultado en un atributo del body.
El script lo lee con --dump-dom y falla si encuentra desbordes.

Uso:  python3 docs/informe/verificar_tablas.py
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

AQUI = Path(__file__).resolve().parent
HTML = AQUI / "TCC-seguridad-informatica.html"

SONDEO = """
<script>
(function () {
  function medir() {
    var desbordes = [];
    var medidor = document.createElement("canvas").getContext("2d");
    function anchoTexto(texto, fuente) {
      medidor.font = fuente;
      return medidor.measureText(texto).width;
    }

    document.querySelectorAll("td, th, pre").forEach(function (nodo) {
      var estilo = window.getComputedStyle(nodo);
      var disponible = nodo.clientWidth
        - parseFloat(estilo.paddingLeft || 0)
        - parseFloat(estilo.paddingRight || 0);
      if (nodo.tagName === "PRE") {
        disponible = nodo.clientWidth;
      }

      if (nodo.scrollWidth > nodo.clientWidth + 2) {
        desbordes.push({
          tipo: "desborde",
          etiqueta: nodo.tagName.toLowerCase(),
          texto: (nodo.textContent || "").trim().slice(0, 70),
          exceso: Math.round(nodo.scrollWidth - nodo.clientWidth)
        });
      }

      if (nodo.tagName !== "PRE" && disponible > 0) {
        var fuente = estilo.fontStyle + " " + estilo.fontWeight + " " + estilo.fontSize + " " + estilo.fontFamily;
        var palabras = (nodo.textContent || "").trim().split(/[^A-Za-z0-9_]+/).filter(Boolean);
        var masLarga = 0;
        var culpable = "";
        palabras.forEach(function (palabra) {
          var ancho = anchoTexto(palabra, fuente);
          if (ancho > masLarga) { masLarga = ancho; culpable = palabra; }
        });
        if (masLarga > disponible + 1) {
          desbordes.push({
            tipo: "palabra partida",
            etiqueta: nodo.tagName.toLowerCase(),
            palabra: culpable,
            texto: (nodo.textContent || "").trim().slice(0, 60),
            exceso: Math.round(masLarga - disponible)
          });
        }
      }
    });
    var tablas = Array.prototype.map.call(document.querySelectorAll("table"), function (t, i) {
      return { indice: i, ancho: t.scrollWidth, caja: t.clientWidth };
    });
    var anchas = tablas.filter(function (t) { return t.ancho > t.caja + 2; });
    document.body.setAttribute("data-desbordes", JSON.stringify(desbordes));
    document.body.setAttribute("data-tablas", JSON.stringify({ total: tablas.length, anchas: anchas }));
    document.body.setAttribute("data-listo", "1");
  }
  if (document.readyState === "complete") { medir(); } else { window.addEventListener("load", medir); }
})();
</script>
"""


def main() -> int:
    if not HTML.exists():
        print(f"no existe {HTML}: corré build-pdf.sh primero", file=sys.stderr)
        return 1

    original = HTML.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory() as temporal:
        copia = Path(temporal) / "verificacion.html"
        copia.write_text(original.replace("</body>", SONDEO + "</body>"), encoding="utf-8")

        resultado = subprocess.run(
            [
                "chromium",
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--virtual-time-budget=6000",
                "--dump-dom",
                f"file://{copia}",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

    dom = resultado.stdout
    if 'data-listo="1"' not in dom:
        print("no se pudo medir el documento (¿chromium falló?)", file=sys.stderr)
        return 1

    def atributo(nombre: str) -> str:
        hallado = re.search(rf'{nombre}="([^"]*)"', dom)
        return (
            hallado.group(1).replace("&quot;", '"') if hallado else ""
        )

    tablas = atributo("data-tablas")
    desbordes = atributo("data-desbordes")

    print(f"  tablas: {tablas}")
    if desbordes.strip() in ("", "[]"):
        print("  desbordes de celda: ninguno")
        return 0

    print(f"  DESBORDES: {desbordes}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

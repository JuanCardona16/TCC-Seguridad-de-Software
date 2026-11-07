#!/usr/bin/env python3
"""Genera los datos que consume el panel de evidencias.

Se ejecuta al arrancar el contenedor `evidence` (ver site/Dockerfile) a partir de
los archivos que produce el propio laboratorio:

  /repo/evidence/results.json      -> /site/static/data/results.json
  /repo/docs/riesgos/magerit.yml   -> /site/static/data/magerit.json
  /repo/evidence/http/*/*.log      -> /site/static/data/logs/<modo>/
  /repo/docs/diagramas/*.svg       -> /site/static/data/diagramas/

Nada de esto se escribe a mano: si la suite de ataques se vuelve a ejecutar,
basta reiniciar el contenedor para refrescar el panel.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import yaml

REPO = Path("/repo")
OUT = Path("/site/static/data")

NIVELES = ((16, "Crítico"), (9, "Alto"), (4, "Medio"), (0, "Bajo"))


def nivel(riesgo: int) -> str:
    for piso, nombre in NIVELES:
        if riesgo >= piso:
            return nombre
    return "Bajo"


def cargar_resultados() -> dict:
    origen = REPO / "evidence" / "results.json"
    if not origen.exists():
        print(f"[aviso] no existe {origen}: el panel arranca vacío", file=sys.stderr)
        return {
            "generated_at": None,
            "attacks": [],
            "summary": {"total": 0, "pass": 0, "fail": 0, "skip": 0},
        }
    return json.loads(origen.read_text(encoding="utf-8"))


def cargar_riesgos() -> dict:
    origen = REPO / "docs" / "riesgos" / "magerit.yml"
    if not origen.exists():
        print(f"[aviso] no existe {origen}: sin mapa de calor", file=sys.stderr)
        return {"metodo": None, "activos": [], "riesgos": []}

    datos = yaml.safe_load(origen.read_text(encoding="utf-8")) or {}
    for riesgo in datos.get("riesgos", []):
        valor = int(riesgo.get("frecuencia", 0)) * int(riesgo.get("degradacion", 0))
        riesgo["riesgo"] = valor
        riesgo["nivel"] = nivel(valor)
    return datos


def copiar_logs() -> int:
    copiados = 0
    for modo in ("vulnerable", "hardened"):
        origen = REPO / "evidence" / "http" / modo
        destino = OUT / "logs" / modo
        destino.mkdir(parents=True, exist_ok=True)
        if not origen.exists():
            continue
        for archivo in origen.glob("*.log"):
            shutil.copyfile(archivo, destino / archivo.name)
            copiados += 1
    return copiados


def copiar_diagramas() -> int:
    destino = OUT / "diagramas"
    destino.mkdir(parents=True, exist_ok=True)
    copiados = 0
    for nombre in ("arquitectura.svg", "dfd-stride.svg"):
        origen = REPO / "docs" / "diagramas" / nombre
        if origen.exists():
            shutil.copyfile(origen, destino / nombre)
            copiados += 1
    return copiados


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    resultados = cargar_resultados()
    (OUT / "results.json").write_text(
        json.dumps(resultados, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    riesgos = cargar_riesgos()
    (OUT / "magerit.json").write_text(
        json.dumps(riesgos, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )

    logs = copiar_logs()
    diagramas = copiar_diagramas()

    total = resultados.get("summary", {}).get("total", 0)
    print(
        f"panel listo: {total} ejecuciones de ataque, "
        f"{len(riesgos.get('riesgos', []))} riesgos, {logs} logs, {diagramas} diagramas"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

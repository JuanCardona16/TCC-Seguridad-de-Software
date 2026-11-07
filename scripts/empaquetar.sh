#!/usr/bin/env bash
# Empaqueta el entregable del TCC en un único archivo listo para subir.
#
#   bash scripts/empaquetar.sh
#   -> dist/TCC-seguridad-informatica-2026-2.zip
#
# Incluye: informe (PDF y Markdown), sustentación, evidencias de la suite,
# capturas de tráfico y el código completo del laboratorio.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DESTINO="$REPO/dist"
NOMBRE="TCC-seguridad-informatica-2026-2"
STAGE="$DESTINO/$NOMBRE"

command -v zip >/dev/null || { echo "falta zip en el sistema"; exit 1; }

echo "[1/4] Verificando evidencias"
if [ ! -f "$REPO/evidence/results.json" ]; then
    echo "  no existe evidence/results.json: ejecutá primero 'bash attacks/run-all.sh'"
    exit 1
fi
resumen="$(jq -r '"PASS=\(.summary.pass) FAIL=\(.summary.fail) SKIP=\(.summary.skip)"' "$REPO/evidence/results.json")"
echo "  $resumen"
if ! jq -e '.summary.fail == 0' "$REPO/evidence/results.json" >/dev/null; then
    echo "  hay expectativas fallidas: el entregable no se genera"
    exit 1
fi

echo "[2/4] Preparando carpeta de entrega"
rm -rf "$STAGE"
mkdir -p "$STAGE"

copiar() {
    local origen="$1" destino="$2"
    if [ -e "$REPO/$origen" ]; then
        mkdir -p "$STAGE/$destino"
        cp -r "$REPO/$origen" "$STAGE/$destino/"
    fi
}

copiar "README.md" "."
copiar "docker-compose.yml" "."
copiar "env.example" "."
copiar "app" "."
copiar "attacks" "."
copiar "site" "."
copiar "lab" "."
copiar "docs/informe" "docs"
copiar "docs/sustentacion" "docs"
copiar "docs/diagramas" "docs"
copiar "docs/riesgos" "docs"
copiar "evidence" "."

# Elementos volátiles que no deben viajar en la entrega.
rm -rf "$STAGE/app/target" "$STAGE/site/static/data" "$STAGE/evidence/.cache" \
       "$STAGE/lab/gateway/tls"
find "$STAGE" -name '*.pid' -delete

echo "[3/4] Comprimiendo"
( cd "$DESTINO" && zip -qr "$NOMBRE.zip" "$NOMBRE" -x '*.DS_Store' )
rm -rf "$STAGE"

echo "[4/4] Listo"
ls -lh "$DESTINO/$NOMBRE.zip" | awk '{print "  " $5 "  " $9}'
echo "  informe:    docs/informe/TCC-seguridad-informatica.pdf"
echo "  evidencias: evidence/results.json ($resumen)"

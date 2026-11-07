#!/usr/bin/env bash
# Genera el PDF del informe a partir del Markdown, sin instalar nada en el host.
#
#   1. pandoc (imagen oficial) convierte Markdown -> HTML autocontenido.
#   2. Chromium del sistema imprime ese HTML a PDF (A4).
#
# Uso:  bash docs/informe/build-pdf.sh
set -euo pipefail

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$AQUI/../.." && pwd)"
MD="$AQUI/TCC-seguridad-informatica.md"
HTML="$AQUI/TCC-seguridad-informatica.html"
PDF="$AQUI/TCC-seguridad-informatica.pdf"

command -v chromium >/dev/null || { echo "falta chromium en el host"; exit 1; }

echo "[1/3] Markdown -> HTML (pandoc en contenedor)"
docker run --rm -v "$REPO":/src -w /src pandoc/core:latest \
    --from=gfm+pipe_tables+task_lists \
    --to=html5 --standalone \
    --metadata title="TCC Seguridad Informática 2026-2" \
    --css="docs/informe/print.css" \
    -o "docs/informe/TCC-seguridad-informatica.html" \
    "docs/informe/TCC-seguridad-informatica.md"

echo "[2/3] HTML -> PDF (chromium headless)"
chromium --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
    --print-to-pdf="$PDF" "file://$HTML" 2>/dev/null || \
  chromium --headless=new --disable-gpu --no-sandbox --print-to-pdf="$PDF" "file://$HTML"

echo "[3/3] Listo"
ls -lh "$PDF" "$HTML" | awk '{print "  " $5 "  " $9}'

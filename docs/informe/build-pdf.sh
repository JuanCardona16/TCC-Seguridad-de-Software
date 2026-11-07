#!/usr/bin/env bash
# Genera el PDF del informe sin instalar nada en el host.
#
#   1. pandoc (contenedor oficial) convierte el Markdown en un fragmento HTML
#      con su índice.
#   2. Un ensamblador arma el documento final: portada institucional, índice y
#      cuerpo, aplicando el ancho de columna declarado en cada tabla
#      (::: {.tabla-anchos data-cols="18,32,50"}).
#   3. Chromium imprime ese HTML a PDF en A4.
#
# Uso:  bash docs/informe/build-pdf.sh
set -euo pipefail

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$AQUI/../.." && pwd)"
MD="docs/informe/TCC-seguridad-informatica.md"
CUERPO="docs/informe/.cuerpo.html"
HTML="docs/informe/TCC-seguridad-informatica.html"
PDF="docs/informe/TCC-seguridad-informatica.pdf"

command -v chromium >/dev/null || { echo "falta chromium en el host"; exit 1; }

echo "[1/4] Markdown -> HTML con índice (pandoc en contenedor)"
docker run --rm --user "$(id -u):$(id -g)" -v "$REPO":/src -w /src pandoc/core:latest \
    --from=markdown+fenced_divs+pipe_tables+raw_html+footnotes+definition_lists \
    --to=html5 \
    --toc --toc-depth=2 \
    --metadata title="Endurecimiento de una aplicación de gestión documental" \
    --metadata lang=es \
    -o "docs/informe/.cuerpo.html" \
    "$MD"

imprimir_pdf() {
    chromium --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
        --print-to-pdf="$REPO/$PDF" "file://$REPO/$HTML" 2>/dev/null || \
      chromium --headless=new --disable-gpu --no-sandbox --no-pdf-header-footer \
        --print-to-pdf="$REPO/$PDF" "file://$REPO/$HTML"
}

echo "[2/5] Ensamblado + índice con páginas (itera hasta estabilizar)"
rm -f docs/informe/.paginas.json
estable=0
for intento in 1 2 3 4; do
    cp -f docs/informe/.paginas.json /tmp/paginas.antes.json 2>/dev/null || echo '{}' > /tmp/paginas.antes.json
    python3 "$AQUI/ensamblar.py" | sed 's/^/  /'
    imprimir_pdf
    if python3 "$AQUI/numerar_toc.py" | sed 's/^/  /'; then
        if cmp -s /tmp/paginas.antes.json docs/informe/.paginas.json; then
            echo "  índice estable en la pasada $intento"
            estable=1
            break
        fi
        echo "  las páginas cambiaron: se recompone el índice (pasada $intento)"
    else
        echo "  la autocomprobación falló: se recompone el índice (pasada $intento)"
    fi
done
if [ "$estable" = "0" ]; then
    echo "  ATENCIÓN: el índice no estabilizó en cuatro pasadas" >&2
fi

echo "[3/5] PDF definitivo con el índice numerado"
python3 "$AQUI/ensamblar.py" | sed 's/^/  /'
imprimir_pdf
python3 "$AQUI/numerar_toc.py" | sed 's/^/  /'

echo "[4/5] Tamaño del archivo"
ls -lh "$REPO/$PDF" | awk '{print "  PDF: " $5}'

echo "[5/5] Verificación de desbordes de tabla"
python3 "$AQUI/verificar_tablas.py" || true

rm -f "$REPO/$CUERPO"
ls -lh "$REPO/$PDF" | awk '{print "  PDF: " $5}'

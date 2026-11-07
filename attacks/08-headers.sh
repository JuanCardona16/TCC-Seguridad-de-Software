#!/usr/bin/env bash
# OWASP A05:2021 Security Misconfiguration - cabeceras de seguridad
source "$(dirname "$0")/lib.sh" "$@"

out="$EVIDENCE_DIR/08-headers.txt"
curl_ -D "$out" -o /dev/null "$target/"

missing=""
for header in content-security-policy x-frame-options x-content-type-options referrer-policy; do
    if grep -qi "^$header:" "$out"; then
        say "  presente: $header"
    else
        say "  AUSENTE:  $header"
        missing="$missing $header"
    fi
done

if [ -n "$missing" ]; then
    say "ATAQUE EXITOSO: faltan controles de endurecimiento del navegador:$missing"
    say "evidence=$out"
    exit 0
fi
say "BLOQUEADO: todas las cabeceras de seguridad estan presentes"
say "evidence=$out"
exit 1

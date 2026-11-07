#!/usr/bin/env bash
# OWASP A02:2021 Cryptographic Failures - hashes de contrasena debiles
source "$(dirname "$0")/lib.sh" "$@"

if [ "$mode" = "vulnerable" ]; then db=minigestor_vuln; else db=minigestor_hard; fi
out="$EVIDENCE_DIR/06-hashes.txt"
consulta="SELECT username, password_hash FROM users ORDER BY id"

# Dos caminos para leer la base, la misma prueba:
#   - desde el host: `docker compose exec` contra el contenedor de PostgreSQL
#   - desde el panel de evidencias: `psql` directo con DB_DSN (esquema de laboratorio)
if [ -n "${DB_DSN:-}" ] && command -v psql >/dev/null 2>&1; then
    if ! psql "$DB_DSN" -At -F'|' -c "$consulta" > "$out" 2>/dev/null; then
        say "No se pudo leer la base con DB_DSN"
        exit 2
    fi
elif ! compose exec -T db psql -U lab -d "$db" -At -F'|' -c "$consulta" > "$out" 2>/dev/null; then
    say "No se pudo leer la base (¿esta levantado el laboratorio?)"
    exit 2
fi

wordlist=(alice123 bob123 admin123 123456 password admin alice bob password123 qwerty)
cracked=0
argon=0

while IFS='|' read -r user hash; do
    [ -z "${user:-}" ] && continue
    case "$hash" in
        \$argon2*)
            argon=$((argon + 1))
            say "  $user -> $hash"
            say "  formato Argon2id: cada intento cuesta 19 MiB de RAM y 2 iteraciones"
            continue
            ;;
    esac
    say "  $user -> $hash"
    for word in "${wordlist[@]}"; do
        candidate="$(printf '%s' "$word" | md5sum | cut -d' ' -f1)"
        if [ "$candidate" = "$hash" ]; then
            say "  CRACKEADO: $user:$word"
            cracked=1
        fi
    done
done < "$out"

if [ "$argon" -gt 0 ] && [ "$cracked" = "0" ]; then
    say "BLOQUEADO: Argon2id con sal por usuario no cede al diccionario"
    exit 1
fi
if [ "$cracked" = "1" ]; then
    say "ATAQUE EXITOSO: hashes MD5 sin sal recuperados con un diccionario minimo"
    exit 0
fi
say "Sin resultados concluyentes"
exit 2

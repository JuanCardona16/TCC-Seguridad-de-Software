#!/usr/bin/env bash
# Ejecuta la suite completa contra los dos modos y escribe evidence/results.json.
#
# Es una especificación ejecutable: cada ataque DEBE tener éxito en el modo
# vulnerable (defecto presente) y DEBE quedar bloqueado en el modo endurecido.
# Si alguna expectativa no se cumple, el informe no está verificando lo que dice.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$PWD"

VULN_URL="${VULN_URL:-http://127.0.0.1:18080}"
HARD_URL="${HARD_URL:-https://127.0.0.1:18443}"

IDS=(01-sqli-search 02-xss-stored 03-idor 04-bruteforce 05-session-forgery 06-weak-hash 07-upload-traversal 08-headers 09-tls-plaintext)
declare -A NAME=(
  [01-sqli-search]="SQL injection en la busqueda (UNION SELECT)"
  [02-xss-stored]="XSS almacenado en el titulo del documento"
  [03-idor]="IDOR: lectura de documentos ajenos"
  [04-bruteforce]="Fuerza bruta sin limite de intentos"
  [05-session-forgery]="Falsificacion de cookie de sesion (escalada)"
  [06-weak-hash]="Hashes de contrasena debiles (MD5)"
  [07-upload-traversal]="Path traversal en la carga de archivos"
  [08-headers]="Cabeceras de seguridad ausentes"
  [09-tls-plaintext]="Credenciales en claro sobre HTTP"
)
declare -A OWASP=(
  [01-sqli-search]="A03:2021 Injection"
  [02-xss-stored]="A03:2021 Injection"
  [03-idor]="A01:2021 Broken Access Control"
  [04-bruteforce]="A07:2021 Auth Failures"
  [05-session-forgery]="A01:2021 Broken Access Control"
  [06-weak-hash]="A02:2021 Cryptographic Failures"
  [07-upload-traversal]="A04:2021 Insecure Design"
  [08-headers]="A05:2021 Security Misconfiguration"
  [09-tls-plaintext]="A02:2021 Cryptographic Failures"
)

mkdir -p evidence/http/vulnerable evidence/http/hardened
rm -rf evidence/.cache
: > evidence/results.jsonl

verde=$'\033[32m'; rojo=$'\033[31m'; amar=$'\033[33m'; gris=$'\033[90m'; fin=$'\033[0m'
pass=0; fail=0; skip=0

printf '%-22s %-11s %-9s %s\n' "ATAQUE" "MODO" "VEREDICTO" "DETALLE"
printf '%s\n' "-------------------------------------------------------------------------------"

for id in "${IDS[@]}"; do
    for mode in vulnerable hardened; do
        if [ "$mode" = "vulnerable" ]; then url="$VULN_URL"; expect=0; else url="$HARD_URL"; expect=1; fi
        out="$(EVIDENCE_DIR="$REPO_ROOT/evidence/http/$mode" bash "attacks/$id.sh" "$url" "$mode" 2>&1)"
        rc=$?
        printf '%s\n' "$out" > "evidence/http/$mode/$id.log"

        case "$rc" in
            0) succeeded=true ;;
            1) succeeded=false ;;
            *) succeeded=null ;;
        esac

        if [ "$rc" = "2" ]; then
            verdict="SKIP"; skip=$((skip + 1)); color="$amar"
        elif [ "$rc" = "$expect" ]; then
            verdict="PASS"; pass=$((pass + 1)); color="$verde"
        else
            verdict="FAIL"; fail=$((fail + 1)); color="$rojo"
        fi

        detail="$(printf '%s' "$out" | grep -vE '^$' | tail -n 1)"
        printf '%-22s %-11s %s%-9s%s %s\n' "$id" "$mode" "$color" "$verdict" "$fin" "${detail:0:70}"

        jq -nc \
            --arg id "$id" \
            --arg name "${NAME[$id]}" \
            --arg owasp "${OWASP[$id]}" \
            --arg mode "$mode" \
            --arg target "$url" \
            --argjson succeeded "$succeeded" \
            --arg expected "$([ "$expect" = "0" ] && echo succeeded || echo blocked)" \
            --arg verdict "$verdict" \
            --arg detail "$detail" \
            '{id:$id,name:$name,owasp:$owasp,mode:$mode,target:$target,attack_succeeded:$succeeded,expected:$expected,verdict:$verdict,detail:$detail}' \
            >> evidence/results.jsonl
    done
done

jq -s --arg generated "$(date -Iseconds)" \
    '{generated_at:$generated, attacks:., summary:{total:length,
      pass:(map(select(.verdict=="PASS"))|length),
      fail:(map(select(.verdict=="FAIL"))|length),
      skip:(map(select(.verdict=="SKIP"))|length)}}' \
    evidence/results.jsonl > evidence/results.json

printf '%s\n' "-------------------------------------------------------------------------------"
printf 'PASS: %s  FAIL: %s  SKIP: %s  ->  evidence/results.json\n' "$pass" "$fail" "$skip"

[ "$fail" -eq 0 ] || exit 1

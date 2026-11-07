#!/usr/bin/env bash
# Utilidades compartidas por la suite de ataques.
# Cada script se invoca así:  attacks/NN-nombre.sh <url_objetivo> <vulnerable|hardened>
# Contrato de salida:
#   exit 0  -> el ataque tuvo éxito (el defecto ESTÁ PRESENTE)
#   exit 1  -> el ataque fue bloqueado (la mitigación FUNCIONA)
#   exit 2  -> no se pudo ejecutar la prueba (entorno incompleto)
set -uo pipefail

target="${1:?falta la URL objetivo}"
mode="${2:?falta el modo: vulnerable|hardened}"
export target mode

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_DIR="${CACHE_DIR:-$REPO_ROOT/evidence/.cache}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$REPO_ROOT/evidence/http/$mode}"
mkdir -p "$CACHE_DIR" "$EVIDENCE_DIR"
export REPO_ROOT CACHE_DIR EVIDENCE_DIR

# -k porque el certificado del laboratorio es autofirmado.
curl_() { curl -sk --max-time 20 "$@"; }

say() { printf '%s\n' "$*"; }

# Inicia sesión una sola vez por modo+usuario y cachea el cookie jar.
login() {
    local user="$1" pass="$2" jar
    jar="$CACHE_DIR/jar-$mode-$user.txt"
    if [ ! -s "$jar" ]; then
        curl_ -c "$jar" -o /dev/null -X POST "$target/login" \
            --data-urlencode "username=$user" \
            --data-urlencode "password=$pass"
    fi
    printf '%s' "$jar"
}

compose() { docker compose --project-directory "$REPO_ROOT" "$@"; }

#!/usr/bin/env bash
# Detiene el laboratorio. Los datos y las evidencias se conservan.
#
#   ./parar.sh           apaga los contenedores y conserva los volúmenes
#   ./parar.sh --todo    apaga y borra volúmenes (la próxima vez arranca de cero)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

BORRAR=0
[ "${1:-}" = "--todo" ] && BORRAR=1

if [ "$BORRAR" = "1" ]; then
    docker compose --profile tools down -v --remove-orphans
    echo "laboratorio detenido y volúmenes eliminados"
else
    docker compose --profile tools down --remove-orphans
    echo "laboratorio detenido (los volúmenes se conservan)"
fi

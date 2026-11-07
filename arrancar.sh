#!/usr/bin/env bash
# Arranca el laboratorio completo del TCC con un solo comando.
#
#   ./arrancar.sh                 arranque normal (compila, levanta, corre la suite, abre el panel)
#   ./arrancar.sh --sin-pruebas   no corre la suite de ataques (arranque en ~20 s)
#   ./arrancar.sh --sin-navegador no abre el navegador
#   ./arrancar.sh --limpiar       borra datos y volúmenes antes de arrancar (laboratorio de cero)
#
# Al terminar deja: aplicación vulnerable, aplicación endurecida, gateway TLS,
# panel de evidencias y contenedores de herramientas, con la suite verificada.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
RAIZ="$PWD"

CORRER_PRUEBAS=1
ABRIR_NAVEGADOR=1
LIMPIAR=0

for argumento in "$@"; do
    case "$argumento" in
        --sin-pruebas) CORRER_PRUEBAS=0 ;;
        --sin-navegador) ABRIR_NAVEGADOR=0 ;;
        --limpiar) LIMPIAR=1 ;;
        -h|--ayuda|--help)
            cat <<'AYUDA'
Arranca el laboratorio completo del TCC con un solo comando.

  ./arrancar.sh                  arranque normal: compila, levanta, corre la suite y abre el panel
  ./arrancar.sh --sin-pruebas    no corre la suite de ataques (arranque en ~20 s)
  ./arrancar.sh --sin-navegador  no abre el navegador
  ./arrancar.sh --limpiar        borra contenedores y volúmenes antes de arrancar (laboratorio de cero)

Al terminar quedan arriba: aplicación vulnerable, aplicación endurecida, gateway
TLS, panel de evidencias y herramientas de red, con la suite verificada.
AYUDA
            exit 0
            ;;
        *)
            echo "opción desconocida: $argumento (usá --ayuda)" >&2
            exit 2
            ;;
    esac
done

AZUL=$'\033[36m'; VERDE=$'\033[32m'; ROJO=$'\033[31m'; AMBAR=$'\033[33m'; GRIS=$'\033[90m'; FIN=$'\033[0m'

paso() { printf '%s▸%s %s\n' "$AZUL" "$FIN" "$1"; }
bien() { printf '  %s✓%s %s\n' "$VERDE" "$FIN" "$1"; }
aviso() { printf '  %s!%s %s\n' "$AMBAR" "$FIN" "$1"; }
mal() { printf '  %s✗%s %s\n' "$ROJO" "$FIN" "$1"; }
detalle() { printf '    %s%s%s\n' "$GRIS" "$1" "$FIN"; }

PUERTOS=(18080 18083 18090 18091 18443)
URL_PANEL="http://127.0.0.1:18090"
URL_VULN="http://127.0.0.1:18080"
URL_HARD="https://127.0.0.1:18443"

# --------------------------------------------------------------- comprobaciones
paso "Comprobando el entorno"
if ! command -v docker >/dev/null 2>&1; then
    mal "no está instalado Docker"; exit 1
fi
if ! docker info >/dev/null 2>&1; then
    mal "el motor de Docker no responde"
    detalle "probá: sudo systemctl start docker"
    exit 1
fi
bien "Docker $(docker version --format '{{.Server.Version}}') disponible"

if docker compose version >/dev/null 2>&1; then
    bien "Docker Compose $(docker compose version --short 2>/dev/null || docker compose version)"
else
    mal "falta el plugin 'docker compose'"; exit 1
fi

if [ "$LIMPIAR" = "1" ]; then
    paso "Borrando contenedores y volúmenes (laboratorio de cero)"
    docker compose --profile tools down -v --remove-orphans >/dev/null 2>&1
    bien "estado anterior eliminado"
fi

ocupados=""
for puerto in "${PUERTOS[@]}"; do
    if ss -ltn 2>/dev/null | grep -q ":$puerto "; then
        if ! docker ps --format '{{.Ports}}' | grep -q "127.0.0.1:$puerto->"; then
            ocupados="$ocupados $puerto"
        fi
    fi
done
if [ -n "$ocupados" ]; then
    mal "estos puertos están ocupados por otro programa:$ocupados"
    detalle "cerralos o cambiá los puertos en docker-compose.yml"
    exit 1
fi
bien "puertos 18080, 18083, 18090, 18091 y 18443 libres"

# ------------------------------------------------------------------- arranque
paso "Compilando la aplicación (usa caché; la primera vez tarda unos minutos)"
if docker compose build 2>&1 | tail -2 | sed 's/^/    /'; then
    bien "imagen tcc-seguridad/minigestor lista"
else
    mal "falló la compilación"; exit 1
fi

paso "Levantando los servicios"
docker compose --profile tools up -d --remove-orphans 2>&1 | grep -Ei "error|warn" | sed 's/^/    /' || true
bien "contenedores creados"

esperar_http() {
    local url="$1" nombre="$2" intentos="${3:-60}"
    while [ "$intentos" -gt 0 ]; do
        if curl -skf -o /dev/null --max-time 3 "$url"; then
            bien "$nombre responde"
            return 0
        fi
        sleep 1
        intentos=$((intentos - 1))
    done
    mal "$nombre no respondió"
    detalle "mirá el registro con: docker compose logs --tail 30"
    return 1
}

paso "Esperando a que los servicios estén sanos"
esperar_http "$URL_VULN/healthz" "aplicación vulnerable" || exit 1
esperar_http "$URL_HARD/healthz" "aplicación endurecida (TLS)" || exit 1
esperar_http "$URL_PANEL/healthz.txt" "panel de evidencias" || exit 1

# ---------------------------------------------------------------------- suite
RESUMEN_SUITE="sin ejecutar"
if [ "$CORRER_PRUEBAS" = "1" ]; then
    paso "Ejecutando la suite de ataques (unos 45 segundos)"
    salida="$(bash attacks/run-all.sh 2>&1)"
    linea="$(printf '%s\n' "$salida" | grep -E '^PASS:' | tail -1)"
    if [ -n "$linea" ]; then
        RESUMEN_SUITE="$linea"
        printf '  %s\n' "$linea" | sed 's/  PASS/  ✓ PASS/'
        if printf '%s' "$linea" | grep -q 'FAIL: 0'; then
            bien "las 18 expectativas se cumplieron"
        else
            aviso "hay expectativas sin cumplir: revisá evidence/results.json"
        fi
    else
        aviso "no se pudo leer el resumen de la suite"
        detalle "corré a mano: bash attacks/run-all.sh"
        RESUMEN_SUITE="revisar"
    fi
fi

paso "Refrescando el panel con las evidencias actuales"
docker compose restart evidence >/dev/null 2>&1
esperar_http "$URL_PANEL/healthz.txt" "panel de evidencias" 30 >/dev/null
bien "panel listo en $URL_PANEL"

# -------------------------------------------------------------------- resumen
echo
printf '%s┌──────────────────────────────────────────────────────────────────────┐%s\n' "$VERDE" "$FIN"
printf '%s│%s  LABORATORIO LISTO                                                  %s│%s\n' "$VERDE" "$FIN" "$VERDE" "$FIN"
printf '%s└──────────────────────────────────────────────────────────────────────┘%s\n' "$VERDE" "$FIN"
cat <<EOF

  Panel de evidencias   $URL_PANEL      ← empezá por acá
  App vulnerable        $URL_VULN
  App endurecida (TLS)  $URL_HARD
  Redirección a TLS     http://127.0.0.1:18083

  Usuarios demo         admin / admin123   ·   alice / alice123   ·   bob / bob123

  Suite de ataques      $RESUMEN_SUITE

  En el panel:  sección 1 = presentación del proyecto (para mostrar al docente)
                sección 2 = demostración en vivo con botón ▶ por ataque
                sección 3 = matriz antes/después
                sección 4 = mapa de calor MAGERIT
                sección 5 = diagramas con zoom

  Para apagar todo:     ./parar.sh

EOF

if [ "$ABRIR_NAVEGADOR" = "1" ] && command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL_PANEL" >/dev/null 2>&1 &
    bien "abriendo el panel en el navegador"
fi

docker compose ps --format '  {{.Name}}  {{.Status}}'

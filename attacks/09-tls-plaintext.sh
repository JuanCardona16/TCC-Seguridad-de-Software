#!/usr/bin/env bash
# OWASP A02 - credenciales en claro sobre HTTP frente a TLS
source "$(dirname "$0")/lib.sh" "$@"

if [ "$(docker inspect -f '{{.State.Running}}' tcc-attacker 2>/dev/null)" != "true" ]; then
    say "OMITIDO: requiere el perfil de herramientas (docker compose --profile tools up -d)"
    exit 2
fi

net_dir="$REPO_ROOT/evidence/network"
mkdir -p "$net_dir"

capture() { # $1=archivo $2=filtro $3=url $4=comando de login
    local file="$1" filter="$2" url="$3"
    compose exec -T attacker sh -c "nohup tcpdump -i any -s0 -w /ev/$file '$filter' >/dev/null 2>&1 & echo \$! > /ev/$file.pid; sleep 1" >/dev/null
    compose exec -T attacker curl -sk -o /dev/null -X POST "$url/login" \
        --data-urlencode 'username=alice' --data-urlencode 'password=alice123' >/dev/null 2>&1
    sleep 2
    compose exec -T attacker sh -c "kill \$(cat /ev/$file.pid)" >/dev/null 2>&1
    sleep 1
}

if [ "$mode" = "vulnerable" ]; then
    capture 09-http.pcap "tcp port 8080" "http://app-vuln:8080"
    pcap="$net_dir/09-http.pcap"
    if grep -qa 'alice123' "$pcap"; then
        say "ATAQUE EXITOSO: la contrasena viaja en claro y se lee en la captura"
        say "evidence=$pcap"
        exit 0
    fi
    say "No se encontro la contrasena en la captura HTTP"
    exit 2
fi

capture 09-tls.pcap "tcp port 443" "https://gateway"
pcap="$net_dir/09-tls.pcap"
if grep -qa 'alice123' "$pcap"; then
    say "La contrasena aparece en claro pese a TLS"
    exit 0
fi
say "BLOQUEADO: la captura TLS solo contiene texto cifrado"
say "evidence=$pcap"
exit 1

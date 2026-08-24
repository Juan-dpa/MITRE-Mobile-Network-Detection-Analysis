#!/usr/bin/env bash
set -Eeuo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$LAB_DIR/../../tools/runlib.sh"
LAB_PYTHON_MODULES=(cryptography)
TLS_KEYLOG=$KEY_DIR/skygofree-sslkeys.log
LAB_KEY_DYNAMIC_FILES=(
    "skygofree-sslkeys.log|Secretos TLS de InstanceID, la API GCM y el canal mtalk"
)
LAB_KEY_NOTE="El panel HTTP, DHCP y el acceso bancario sintético viajan en claro. El key log permite recuperar las dos órdenes transportadas por los canales TLS emulados de Google."

sky_args=(
    --victim-ip 10.32.7.10
    --dns-ip 8.8.8.8
    --c2-ip 217.194.13.133
    --iid-ip 172.217.117.4
    --gcm-ip 172.217.115.4
    --mtalk-ip 172.253.157.188
    --gateway-ip 10.32.7.1
    --bank-ip 18.154.48.19
    --keylog-file "$TLS_KEYLOG"
)

start_servers() {
    local src=$LAB_DIR/source program=$LAB_DIR/source/skygofree_lab.py
    : >"$TLS_KEYLOG"
    runner_info "secretos TLS locales: $TLS_KEYLOG"
    start_process dns dns "$PROJECT_ROOT" -- python3 "$LABDNS" --bind 8.8.8.8 \
        --record iid.googleapis.com=172.217.117.4 \
        --record android.googleapis.com=172.217.115.4 \
        --record mtalk.google.com=172.253.157.188 \
        --record www.bancosantander.es=18.154.48.19
    wait_udp dns 8.8.8.8 53
    start_process google google "$src" -- python3 "$program" google "${sky_args[@]}"
    wait_tcp google 172.217.117.4 443
    wait_tcp google 172.217.115.4 443
    wait_tcp google 172.253.157.188 5228
    start_process panel skygofree-c2 "$src" -- python3 "$program" panel "${sky_args[@]}"
    wait_tcp skygofree-c2 217.194.13.133 80
    start_process gateway rogue-ap "$src" -- python3 "$program" gateway "${sky_args[@]}"
    wait_udp rogue-ap 10.32.7.1 67
    start_process bank bank "$src" -- python3 "$program" bank "${sky_args[@]}"
    wait_tcp bank 18.154.48.19 80
}

run_client() {
    local src=$LAB_DIR/source victim_pid
    start_process victim victim "$src" -- python3 skygofree_lab.py victim "${sky_args[@]}"
    sleep 1
    "$LABNET" "$MANIFEST" exec skygofree-c2 --cwd "$src" -- \
        python3 skygofree_lab.py operator "${sky_args[@]}" --operator-delay 0.5
    victim_pid=$(awk -F'|' '$1 == "victim" { print $2 }' "$PROCESS_FILE")
    [[ $victim_pid =~ ^[0-9]+$ ]] || runner_die "no se pudo recuperar el PID de la víctima"
    wait "$victim_pid"
}

dispatch_runner "$@"

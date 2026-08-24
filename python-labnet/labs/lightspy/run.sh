#!/usr/bin/env bash
set -Eeuo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$LAB_DIR/../../tools/runlib.sh"
TLS_KEYLOG=$KEY_DIR/lightspy-sslkeys.log
LAB_KEY_DYNAMIC_FILES=(
    "lightspy-sslkeys.log|Secretos TLS en formato NSS para HTTPS y WSS del C2"
)
LAB_KEY_NOTE="El staging inicial usa HTTP en claro. El key log descifra tanto las solicitudes HTTPS como el WebSocket seguro del puerto 50000."

start_servers() {
    local src=$LAB_DIR/source
    : >"$TLS_KEYLOG"
    start_process dns dns "$PROJECT_ROOT" -- python3 "$LABDNS" --bind 8.8.8.8 \
        --record www.baidu.com=103.235.46.115
    wait_udp dns 8.8.8.8 53
    start_process c2 lightspy-c2 "$src" -- python3 run_lab.py serve
    wait_tcp lightspy-c2 45.83.237.13 8088
    wait_tcp lightspy-c2 45.134.1.180 50000
}

run_client() {
    "$LABNET" "$MANIFEST" exec victim --cwd "$LAB_DIR/source" -- \
        env LABNET_TLS_KEYLOG="$TLS_KEYLOG" python3 run_lab.py client
}

dispatch_runner "$@"

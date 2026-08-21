#!/usr/bin/env bash
set -Eeuo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$LAB_DIR/../../tools/runlib.sh"
LAB_PYTHON_MODULES=(cryptography)
TLS_KEYLOG=$KEY_DIR/drinik-sslkeys.log
LAB_KEY_DYNAMIC_FILES=(
    "drinik-sslkeys.log|Secretos TLS en formato NSS para Firebase y el canal FCM"
)
LAB_KEY_NOTE="Las consultas DNS, el C2 HTTP y la descarga viajan en claro; el mensaje aes() del registro reproduce una llamada de la muestra, no una capa criptográfica adicional en este flujo."

drinik_args=(
    --dns-ip 8.8.8.8 --dns-port 53
    --c2-ip 198.12.107.13 --c2-host gia.3utilities.com
    --firebase-ip 172.217.114.4 --mtalk-ip 108.177.15.188
    --download-ip 192.3.124.14 --download-host 192.3.124.14
)

start_servers() {
    local src=$LAB_DIR/source
    : >"$TLS_KEYLOG"
    start_process dns dns "$PROJECT_ROOT" -- python3 "$LABDNS" --bind 8.8.8.8 \
        --record firebaseinstallations.googleapis.com=172.217.114.4 \
        --record android.apis.google.com=172.217.114.4 \
        --record fcm.googleapis.com=172.217.114.4 \
        --record mtalk.google.com=108.177.15.188 \
        --record gia.3utilities.com=198.12.107.13
    wait_udp dns 8.8.8.8 53
    start_process firebase firebase "$src" -- python3 role_runner.py firebase \
        "${drinik_args[@]}" --ssl-keylog "$TLS_KEYLOG"
    wait_tcp firebase 172.217.114.4 443
    wait_tcp firebase 108.177.15.188 5228
    start_process download download-server "$src" -- python3 role_runner.py download "${drinik_args[@]}"
    wait_tcp download-server 192.3.124.14 80
    start_process c2 drinik-c2 "$src" -- python3 role_runner.py c2 \
        "${drinik_args[@]}" --ssl-keylog "$TLS_KEYLOG"
    wait_tcp drinik-c2 198.12.107.13 80
}

run_client() {
    "$LABNET" "$MANIFEST" exec victim --cwd "$LAB_DIR/source" -- python3 role_runner.py victim \
        "${drinik_args[@]}" --ssl-keylog "$TLS_KEYLOG"
}

dispatch_runner "$@"

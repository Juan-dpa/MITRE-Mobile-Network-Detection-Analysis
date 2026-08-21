#!/usr/bin/env bash
set -Eeuo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=../../tools/runlib.sh
source "$LAB_DIR/../../tools/runlib.sh"
LAB_PYTHON_MODULES=(cryptography)
TLS_KEYLOG=$KEY_DIR/keyraider-sslkeys.log
LAB_KEY_DYNAMIC_FILES=(
    "keyraider-sslkeys.log|Secretos TLS en formato NSS para descifrar la conexión con el servicio Apple"
)
LAB_KEY_NOTE="El canal C2 HTTP y las consultas DNS viajan en claro; la clave privada del certificado no sustituye al key log porque TLS negocia ECDHE."

start_servers() {
    local src=$LAB_DIR/source
    : >"$TLS_KEYLOG"
    start_process dns dns "$PROJECT_ROOT" -- python3 "$LABDNS" \
        --bind 8.8.8.8 \
        --record p12-buy.itunes.apple.com=17.8.136.178 \
        --record www.wushidou.cn=113.10.174.167
    wait_udp dns 8.8.8.8 53
    start_process apple apple "$src" -- python3 lab_server.py --role apple \
        --bind-host 17.8.136.178 --tls-port 443 --cert-dir "$src/certs"
    wait_tcp apple 17.8.136.178 443
    start_process c2 keyraider-c2 "$src" -- python3 lab_server.py --role c2 \
        --bind-host 113.10.174.167 --c2-port 80
    wait_tcp keyraider-c2 113.10.174.167 80
}

run_client() {
    "$LABNET" "$MANIFEST" exec victim --cwd "$LAB_DIR/source" -- python3 lab_client.py \
        --dns-server 8.8.8.8 --dns-port 53 --tls-port 443 --c2-port 80 \
        --keylog-file "$TLS_KEYLOG"
}

dispatch_runner "$@"

#!/usr/bin/env bash
set -Eeuo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$LAB_DIR/../../tools/runlib.sh"
LAB_PYTHON_MODULES=(cryptography)
TLS_KEYLOG=$KEY_DIR/monokle-sslkeys.log
LAB_KEY_DYNAMIC_FILES=(
    "monokle-sslkeys.log|Secretos TLS en formato NSS para las tres sesiones TLS"
)
LAB_KEY_VALUES=(
    "monokle-transport-aes-gcm.hex|2bd83e10e88ecf922314bac8ff1ce7bf603ae511de7aab8744e727ef48a3adfe|Clave AES-256-GCM del protocolo C2 interno"
)
LAB_KEY_NOTE="El key log abre las capas TLS; la clave AES-GCM permite interpretar ServerCommand y AgentResponse. AgentRegistration no lleva la envoltura AES propia."

start_servers() {
    local src=$LAB_DIR/source program=$LAB_DIR/source/monokle_emulator.py
    : >"$TLS_KEYLOG"
    runner_info "secretos TLS locales: $TLS_KEYLOG"
    start_process origin oracle-origin "$src" -- python3 "$program" origin \
        --origin-bind 23.208.220.69 --origin-port 443 --cert-dir "$src/certs" \
        --oracle-host www.oracle.com
    wait_tcp oracle-origin 23.208.220.69 443
    start_process proxy monokle-c2 "$src" -- python3 "$program" proxy \
        --proxy-bind 185.117.89.238 --proxy-port 443 \
        --origin-connect-host 23.208.220.69 --origin-port 443 --cert-dir "$src/certs" \
        --oracle-host www.oracle.com \
        --keylog-file "$TLS_KEYLOG"
    wait_tcp monokle-c2 185.117.89.238 443
    start_process c2 monokle-c2 "$src" -- python3 "$program" c2 \
        --c2-bind 185.117.89.238 --c2-port 17185 --cert-dir "$src/certs"
    wait_tcp monokle-c2 185.117.89.238 17185
}

run_client() {
    local src=$LAB_DIR/source
    "$LABNET" "$MANIFEST" exec victim --cwd "$src" -- python3 monokle_emulator.py client \
        --c2-connect-host 185.117.89.238 --c2-port 17185 \
        --proxy-connect-host 185.117.89.238 --proxy-port 443 \
        --origin-connect-host 23.208.220.69 --origin-port 443 --cert-dir "$src/certs" \
        --oracle-host www.oracle.com \
        --keylog-file "$TLS_KEYLOG"
}

dispatch_runner "$@"

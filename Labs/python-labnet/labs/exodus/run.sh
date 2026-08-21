#!/usr/bin/env bash
set -Eeuo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$LAB_DIR/../../tools/runlib.sh"
TLS_KEYLOG=$KEY_DIR/exodus-sslkeys.log
LAB_KEY_DYNAMIC_FILES=(
    "exodus-sslkeys.log|Secretos TLS en formato NSS para descifrar la sesión HTTPS"
)
LAB_KEY_NOTE="El key log descifra TLS. Los cuerpos de 256 bytes conservan el cifrado RSA/PKCS#1 v1.5 de staging y no existe una clave privada original en este laboratorio."

start_servers() {
    local src=$LAB_DIR/source
    start_process c2 exodus-c2 "$src" -- python3 server.py \
        --bind 54.71.249.137 --port 443 \
        --cert "$src/certs/exodus_sim.crt" --key "$src/certs/exodus_sim.key"
    wait_tcp exodus-c2 54.71.249.137 443
}

run_client() {
    : >"$TLS_KEYLOG"
    runner_info "secretos TLS locales: $TLS_KEYLOG"
    "$LABNET" "$MANIFEST" exec victim --cwd "$LAB_DIR/source" -- python3 client.py \
        --connect-host 54.71.249.137 --connect-port 443 --host-header 54.71.249.137 \
        --keylog-file "$TLS_KEYLOG" \
        --out-zip "$LAB_DIR/downloaded_exodus_two_sim.zip"
}

dispatch_runner "$@"

#!/usr/bin/env bash
set -Eeuo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$LAB_DIR/../../tools/runlib.sh"
LAB_PYTHON_MODULES=(Crypto)
LOCAL_PRIVATE=$KEY_DIR/notcompatible-rsalocal-private.pem
LAB_KEY_FILES=(
    "notcompatible-rsaglobal-public.pem|$LAB_DIR/source/keys/global_public.pem|Clave pública RSAGlobal para verificar las configuraciones SET firmadas"
)
LAB_KEY_DYNAMIC_FILES=(
    "notcompatible-rsalocal-private.pem|Clave privada RSALocal efímera para recuperar las claves RC4 de ambas sesiones"
)
LAB_KEY_NOTE="La RSALocal se genera una vez por ejecución y sirve para los enlaces con la pasarela y el C2; la RSAGlobal solo verifica firmas y no descifra esas sesiones."

start_servers() {
    local src=$LAB_DIR/source
    start_process ftp ftp-target "$src" -- python3 -m ftp_target.ftp_target \
        --listen-host 10.29.9.20 --ftp-port 21 --shell-port 6200
    wait_tcp ftp-target 10.29.9.20 21
    start_process c2 operational-c2 "$src" -- python3 -m c2.c2_server \
        --listen-host 5.45.65.100 --listen-port 80 \
        --advertise-host 5.45.65.100 --gw-host 173.242.124.163 --gw-port 443 \
        --target-host 10.29.9.20 --ftp-port 21 --shell-port 6200
    wait_tcp operational-c2 5.45.65.100 80
    start_process gateway gateway "$src" -- python3 -m gateway.gateway \
        --listen-host 173.242.124.163 --listen-port 443 \
        --advertise-host 173.242.124.163 --c2-host 5.45.65.100 --c2-port 80
    wait_tcp gateway 173.242.124.163 443
}

run_client() {
    "$LABNET" "$MANIFEST" exec victim --cwd "$LAB_DIR/source" -- \
        python3 -m victim.victim_proxy --gw-host 173.242.124.163 --gw-port 443 \
        --local-private-out "$LOCAL_PRIVATE"
}

dispatch_runner "$@"

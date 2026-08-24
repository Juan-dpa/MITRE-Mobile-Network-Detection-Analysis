#!/usr/bin/env bash
set -Eeuo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$LAB_DIR/../../tools/runlib.sh"
LAB_PYTHON_MODULES=(Crypto)
FLUBOT_PRIVATE=$KEY_DIR/flubot-rsa-private.pem
LAB_KEY_DYNAMIC_FILES=(
    "flubot-rsa-private.pem|Clave RSA privada del laboratorio para recuperar la clave XOR efímera de cada petición"
)
LAB_KEY_NOTE="Cada cuerpo HTTP contiene la identidad y la clave de sesión cifradas con RSA; tras recuperarla, esa clave permite revertir la transformación XOR de solicitud y respuesta."

start_servers() {
    local src=$LAB_DIR/source
    start_process dns dns "$PROJECT_ROOT" -- python3 "$LABDNS" --bind 8.8.8.8 \
        --record gurbngbcxheshsj.ru=189.165.94.67
    wait_udp dns 8.8.8.8 53
    start_process ftp ftp-target "$src" -- python3 ftp_vulnerable.py \
        --bind-host 10.106.7.20 --port 21
    wait_tcp ftp-target 10.106.7.20 21
    start_process c2 flubot-c2 "$src" -- python3 c2_server.py \
        --bind-host 189.165.94.67 --advertise-host gurbngbcxheshsj.ru \
        --http-port 80 --control-port 9000 --data-port 4444 \
        --target-host 10.106.7.20 --target-port 21 \
        --private-key-out "$FLUBOT_PRIVATE"
    wait_tcp flubot-c2 189.165.94.67 80
    wait_tcp flubot-c2 189.165.94.67 9000
}

run_client() {
    "$LABNET" "$MANIFEST" exec victim --cwd "$LAB_DIR/source" -- python3 bot_emulator.py \
        --c2-host gurbngbcxheshsj.ru --http-port 80 --dns-server 8.8.8.8:53
}

dispatch_runner "$@"

#!/usr/bin/env bash
set -Eeuo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$LAB_DIR/../../tools/runlib.sh"
LAB_KEY_NOTE="El laboratorio usa HTTP sin TLS; sus transformaciones de aplicación son reversibles y no requieren material criptográfico externo."

start_servers() {
    local src=$LAB_DIR/source
    start_process c2 gplayed-c2 "$src" -- python3 gplayed_c2.py --host 5.9.33.226 --port 5416
    wait_tcp gplayed-c2 5.9.33.226 5416
}

run_client() {
    "$LABNET" "$MANIFEST" exec victim --cwd "$LAB_DIR/source" -- python3 gplayed_client.py \
        --connect-url http://5.9.33.226:5416/ --host-header 5.9.33.226:5416 --pings 4
}

dispatch_runner "$@"

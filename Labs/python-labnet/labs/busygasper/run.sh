#!/usr/bin/env bash
set -Eeuo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
source "$LAB_DIR/../../tools/runlib.sh"
LAB_KEY_NOTE="DNS, IRC y FTP viajan en claro; no falta ningún fichero de claves para analizar la captura."

busy_args=(
    --irc-bind-host 149.28.246.185 --irc-connect-host 149.28.246.185
    --dns-server 8.8.8.8 --dns-port 53
    --ftp-bind-host 213.174.157.151 --ftp-connect-host 213.174.157.151
    --ftp-data-host 213.174.157.151 --ftp-data-port 20200
)

start_servers() {
    local src=$LAB_DIR/source
    start_process dns dns "$PROJECT_ROOT" -- python3 "$LABDNS" --bind 8.8.8.8 \
        --record irc.freenode.net=149.28.246.185
    wait_udp dns 8.8.8.8 53
    start_process irc irc "$src" -- python3 role_runner.py irc "${busy_args[@]}"
    wait_tcp irc 149.28.246.185 6667
    start_process ftp update-server "$src" -- python3 role_runner.py ftp "${busy_args[@]}"
    wait_tcp update-server 213.174.157.151 21
}

run_client() {
    start_process operator operator "$LAB_DIR/source" -- python3 role_runner.py operator \
        "${busy_args[@]}" --operator-delay 1.2
    "$LABNET" "$MANIFEST" exec victim --cwd "$LAB_DIR/source" -- python3 role_runner.py victim \
        "${busy_args[@]}" --irc-connect-host irc.freenode.net \
        --output-dir "$LAB_DIR/downloads"
}

dispatch_runner "$@"

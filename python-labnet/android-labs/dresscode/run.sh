#!/usr/bin/env bash
set -Eeuo pipefail

LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=../../tools/android-runlib.sh
source "$LAB_DIR/../../tools/android-runlib.sh"

start_servers() {
    local source_dir=$LAB_DIR/source
    start_process dns dns "$PROJECT_ROOT" -- python3 "$LABDNS" \
        --bind 10.230.30.53 --record dfm.nicsm.net=138.201.195.77
    wait_udp dns 10.230.30.53 53
    wait_tcp dns 10.230.30.53 53

    start_process smtp smtp-target "$source_dir" -- python3 smtp_emulator.py \
        --bind 10.230.30.25 --port 25
    wait_tcp smtp-target 10.230.30.25 25

    start_process operator operator "$source_dir" -- python3 attacker_socks4_client.py \
        --bind 10.230.30.20 --port 9002 \
        --target-ip 10.230.30.25 --target-port 25
    wait_tcp operator 10.230.30.20 9002

    start_process c2 c2 "$source_dir" -- python3 c2_emulator.py \
        --bind 138.201.195.77 --port 9001 \
        --attacker-host 10.230.30.20 --attacker-port 9002
    wait_tcp c2 138.201.195.77 9001
}

dispatch_android_runner "$@"

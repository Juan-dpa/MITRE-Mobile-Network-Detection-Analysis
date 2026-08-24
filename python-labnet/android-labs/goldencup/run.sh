#!/usr/bin/env bash
set -Eeuo pipefail

LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=../../tools/android-runlib.sh
source "$LAB_DIR/../../tools/android-runlib.sh"

LAB_PYTHON_MODULES=(Crypto)

wait_for_file() {
    local path=$1 attempts=${2:-80}
    while ((attempts > 0)); do
        [[ -s $path ]] && return 0
        sleep 0.1
        attempts=$((attempts - 1))
    done
    runner_die "no se generó el metadato esperado: $path"
}

android_after_emulator_command() {
    cat <<'EOF'

Cuando el AVD haya terminado de arrancar, limpia el estado de GoldenCup antes
de abrir la aplicación. Ejecuta en otra terminal de PowerShell:

& "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" -s emulator-5554 shell pm clear anew.football.cup.world.com.worldcup

La salida debe ser "Success". Este paso elimina el out.dex de una ejecución
anterior; si se conserva, la muestra omite deliberadamente el canal MQTT inicial.
EOF
}

start_servers() {
    local source_dir=$LAB_DIR/source
    local artifact_url_file=$SESSION_DIR/goldencup-artifact.url

    start_process dns dns "$PROJECT_ROOT" -- python3 "$LABDNS" \
        --bind 10.230.35.53 \
        --record www.goldncup.com=107.175.144.26 \
        --record goldncup.com=107.175.144.26
    wait_udp dns 10.230.35.53 53
    wait_tcp dns 10.230.35.53 53

    start_process mqtt c2 "$source_dir" -- mosquitto -c mqtt-server.conf -v
    wait_tcp c2 107.175.144.26 1883

    start_process http c2 "$source_dir" -- python3 http_server.py \
        --host 107.175.144.26 --port 80 \
        --domain www.goldncup.com \
        --metadata-file "$artifact_url_file"
    # La primera importación de PyCryptodome y la generación/cifrado del ZIP
    # pueden superar los ocho segundos del margen común sobre WSL. El proceso
    # ya está supervisado por start_process; aquí solo se amplía la espera de
    # disponibilidad del servicio específico.
    wait_tcp c2 107.175.144.26 80 300
    wait_for_file "$artifact_url_file" 300

    start_process operator operator "$source_dir" -- bash mqtt_operator.sh \
        107.175.144.26 "$artifact_url_file"
}

dispatch_android_runner "$@"

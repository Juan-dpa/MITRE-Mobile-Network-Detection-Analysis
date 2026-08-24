#!/usr/bin/env bash
set -Eeuo pipefail

LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=../../tools/android-runlib.sh
source "$LAB_DIR/../../tools/android-runlib.sh"

android_after_emulator_command() {
    cat <<'EOF'

El AVD API 21 debe conservar instalada la CA "TeleRAT Lab CA" utilizada por el
laboratorio original. Si no aparece en Seguridad > Credenciales de confianza >
Usuario, retira el laboratorio con down e instálala fuera de una captura desde:
C:\TFG-LAB\TFG\Workspace\TFG-LAB\Muestras\NID-TeleRAT\NID-TeleRAT-Lab\certs\telerat-lab-ca.cer

TeleRAT contiene dos ficheros DEX y no funciona en el AVD API 19: Android 4.4
intenta crear DefaultProvider antes de cargar classes2.dex. Utiliza el AVD API
21 mostrado por este pipeline.

Cuando Android haya arrancado, instala la APK, elimina los marcadores locales
de ejecuciones anteriores y abre la actividad desde otra terminal PowerShell:

$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
& $adb -s emulator-5554 install -r "C:\TFG-LAB\TFG\Workspace\TFG-LAB\Muestras\NID-TeleRAT\Muestra\_01fef43c059d6b37be7faf47a08eccbf76cf7f050a7340ac2cae11942f27eb1d.apk"
& $adb -s emulator-5554 shell am force-stop b4a.examplf
& $adb -s emulator-5554 shell pm clear b4a.examplf
& $adb -s emulator-5554 shell pm enable b4a.examplf/.main
& $adb -s emulator-5554 shell am start -n b4a.examplf/.main

Pulsa en la interfaz de TeleRAT el botón que oculta la actividad e inicia los
servicios. El operador emulado añadirá automáticamente la orden de estado.
EOF
}

start_servers() {
    local source_dir=$LAB_DIR/source

    start_process dns dns "$PROJECT_ROOT" -- python3 -u "$LABDNS" \
        --bind 10.230.70.53 \
        --record api.telegram.org=149.154.167.220
    wait_udp dns 10.230.70.53 53
    wait_tcp dns 10.230.70.53 53

    start_process operator operator "$source_dir" -- python3 -u operator_server.py \
        --bind 10.230.70.20 --port 9000
    wait_tcp operator 10.230.70.20 9000 300

    start_process telegram telegram "$source_dir" -- python3 -u bot_api_server.py \
        --bind 149.154.167.220 \
        --http-port 80 --https-port 443 \
        --operator-url http://10.230.70.20:9000 \
        --cert-dir certs \
        --log-file "$LOG_DIR/bot-api.jsonl"
    wait_tcp telegram 149.154.167.220 80 300
    wait_tcp telegram 149.154.167.220 443 300
}

dispatch_android_runner "$@"

#!/usr/bin/env bash
set -Eeuo pipefail

LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=../../tools/android-runlib.sh
source "$LAB_DIR/../../tools/android-runlib.sh"

LAB_KEY_DYNAMIC_FILES=(
  "xloader-sslkeys.log|Secretos TLS de las consultas HTTPS a twitter.com"
)

android_after_emulator_command() {
    cat <<'EOF'

Este laboratorio requiere que el AVD ya tenga región ko_KR y permita instalar
aplicaciones de orígenes desconocidos. La región se configura una sola vez,
fuera de una captura, y permanece en los datos del AVD.

Cuando Android haya arrancado, limpia la ejecución anterior e instala la APK
original desde otra terminal de PowerShell:

$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
& $adb -s emulator-5554 uninstall ufD.wykyx.vlhvh
& $adb -s emulator-5554 uninstall lab.xloader.secondary
& $adb -s emulator-5554 shell rm -f /sdcard/.update2/lab.xloader.secondary.apk
& $adb -s emulator-5554 install "C:\TFG-LAB\TFG\Workspace\TFG-LAB\Muestras\S0318-XLoaderForAndroid\Muestra\332e68d865009d627343b89a5744843e3fde4ae870193f36b82980363439a425.apk"
& $adb -s emulator-5554 shell am start -n ufD.wykyx.vlhvh/ufD.zxYxw.itxkRujzmzjP

Los mensajes "Unknown package" durante la limpieza solo indican que el paquete
ya estaba ausente.
EOF
}

start_servers() {
    local source_dir=$LAB_DIR/source
    local keylog=$KEY_DIR/xloader-sslkeys.log

    start_process dns dns "$PROJECT_ROOT" -- python3 -u "$LABDNS" \
        --bind 10.230.31.53 \
        --record twitter.com=10.230.31.11 \
        --record webview.lab=10.230.31.20 \
        --record vuln.lab=10.230.31.30
    wait_udp dns 10.230.31.53 53
    wait_tcp dns 10.230.31.53 53

    start_process twitter twitter "$source_dir" -- env \
        XLOADER_LOG_DIR="$LOG_DIR" XLOADER_TLS_KEYLOG="$keylog" \
        python3 -u -m servers.twitter.server
    wait_tcp twitter 10.230.31.11 443 300

    start_process webview webview "$source_dir" -- env XLOADER_LOG_DIR="$LOG_DIR" \
        python3 -u -m servers.http_lab.server --role webview
    wait_tcp webview 10.230.31.20 80 300

    start_process vulnerable vulnerable-target "$source_dir" -- env XLOADER_LOG_DIR="$LOG_DIR" \
        python3 -u -m servers.http_lab.server --role vulnerable-target
    wait_tcp vulnerable-target 10.230.31.30 80 300

    start_process c2 c2 "$source_dir" -- env XLOADER_LOG_DIR="$LOG_DIR" \
        python3 -u -m servers.c2.server --auto-continue
    wait_tcp c2 1.162.98.240 28833 300
}

dispatch_android_runner "$@"

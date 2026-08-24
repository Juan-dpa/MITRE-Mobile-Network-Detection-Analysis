#!/usr/bin/env bash
set -Eeuo pipefail

LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=../../tools/android-runlib.sh
source "$LAB_DIR/../../tools/android-runlib.sh"

LAB_KEY_DYNAMIC_FILES=(
  "redalert-sslkeys.log|Secretos TLS de la sesión HTTPS con twitter.com"
)

android_after_emulator_command() {
    cat <<'EOF'

Cuando el AVD haya arrancado, instala o abre manualmente la APK parcheada:
C:\TFG-LAB\TFG\Workspace\TFG-LAB\Muestras\S0539-RedAlert2.0\Muestra\Parche\RedAlert2.0-patched-entities.apk

Antes de abrir la aplicación, acota en este AVD el tiempo de espera del intento
primario silencioso. El cambio solo afecta a la instancia en ejecución y se
restablece al cerrar el emulador:

$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
& $adb -s emulator-5554 shell "echo 4 > /proc/sys/net/ipv4/tcp_syn_retries"

Antes de repetir una captura, borra los datos de com.kmc.prod o reinstala la
APK. La base SQLite conserva el C2 alternativo y el estado de registro, por lo
que una ejecución sin limpiar omitiría el resolver de respaldo.
EOF
}

start_servers() {
    local source_dir=$LAB_DIR/source
    local keylog=$KEY_DIR/redalert-sslkeys.log

    start_process dns dns "$PROJECT_ROOT" -- python3 "$LABDNS" \
        --bind 10.230.39.53 \
        --record www.timeapi.org=10.230.39.10 \
        --record twitter.com=10.230.39.11
    wait_udp dns 10.230.39.53 53
    wait_tcp dns 10.230.39.53 53

    start_process timeapi timeapi "$source_dir" -- python3 redalert_server.py \
        --role timeapi --host 10.230.39.10 --port 80
    # El laboratorio original crea los tres HTTPServer en un único proceso y no
    # aplica un timeout de ocho segundos. En WSL, el arranque en frío de Python
    # y sus módulos TLS puede superar ese margen sin que el proceso haya fallado.
    wait_tcp timeapi 10.230.39.10 80 300

    start_process twitter twitter "$source_dir" -- python3 redalert_server.py \
        --role twitter --host 10.230.39.11 --port 443 \
        --certificate certs/twitter.crt --private-key certs/twitter.key \
        --keylog-file "$keylog"
    wait_tcp twitter 10.230.39.11 443 300

    # La dirección primaria codificada debe producir un timeout, no un RST. El
    # C2 alternativo es una entidad distinta, publicada mediante Twitter.
    "$LABNET" "$MANIFEST" exec primary -- \
        iptables -I INPUT 1 -p tcp --dport 7878 -j DROP

    start_process c2 c2 "$source_dir" -- python3 redalert_server.py \
        --role c2 --host 192.168.56.20 --port 8060
    wait_tcp c2 192.168.56.20 8060 300
}

dispatch_android_runner "$@"

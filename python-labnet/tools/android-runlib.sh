#!/usr/bin/env bash

# Ciclo de vida semiautomático para muestras ejecutadas en Android Emulator
# sobre Windows. La topología y los servicios permanecen en Kali WSL; la GUI
# de la aplicación queda siempre bajo control del operador.

[[ -n ${LAB_DIR:-} ]] || { printf 'android-runlib.sh: falta LAB_DIR\n' >&2; exit 1; }

PROJECT_ROOT=$(cd "$LAB_DIR/../.." && pwd -P)
ANDROID_CONF=$LAB_DIR/android.conf
[[ -f $ANDROID_CONF ]] || { printf 'android-runlib.sh: no existe %s\n' "$ANDROID_CONF" >&2; exit 1; }

# runlib aporta la gestión probada de procesos, claves y namespaces. El
# lanzador Android sustituye únicamente el cliente automático y el flujo de
# captura de una sola pasada.
# shellcheck source=runlib.sh
source "$PROJECT_ROOT/tools/runlib.sh"
# shellcheck source=/dev/null
source "$ANDROID_CONF"

WINDOWS_HELPER=$PROJECT_ROOT/tools/android-windows.ps1
ANDROID_STATE_FILE=$RUN_STATE_DIR/android-session.env
ANDROID_CAPTURE_FILE=$RUN_STATE_DIR/android-capture.path
ANDROID_LOG_WINDOWS_FILE=$RUN_STATE_DIR/android-log-windows.pids
ANDROID_OUTPUT_ROOT=${ANDROID_OUTPUT_ROOT:-$PROJECT_ROOT/android-smoke}
ANDROID_GRACE_SECONDS=${ANDROID_GRACE_SECONDS:-10}
ANDROID_WSL_INTERFACE=${ANDROID_WSL_INTERFACE:-eth0}
ANDROID_WSL_DISTRIBUTION=${ANDROID_WSL_DISTRIBUTION:-kali-linux}
ANDROID_WINDOWS_STATE=${ANDROID_WINDOWS_STATE:-C:\\ProgramData\\TFG-Labnet\\$LAB_ID.json}
ANDROID_POWERSHELL_PATH_WSL=${ANDROID_POWERSHELL_PATH_WSL:-/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe}

declare -p ANDROID_ROUTE_IPS >/dev/null 2>&1 || ANDROID_ROUTE_IPS=()
declare -p ANDROID_KEY_FILES >/dev/null 2>&1 || ANDROID_KEY_FILES=()
declare -p ANDROID_ADDRESS_PROVENANCE >/dev/null 2>&1 || ANDROID_ADDRESS_PROVENANCE=()
declare -p ANDROID_REQUIRED_COMMANDS >/dev/null 2>&1 || ANDROID_REQUIRED_COMMANDS=()

SESSION_DIR=
EVENT_FILE=
WINDOWS_NETWORK_ACTIVE=0

android_die() {
    printf '[%s/android] ERROR: %s\n' "$LAB_ID" "$*" >&2
    exit 1
}

android_info() {
    printf '[%s/android] %s\n' "$LAB_ID" "$*"
}

android_require_command() {
    command -v "$1" >/dev/null 2>&1 || android_die "no se encuentra la orden requerida: $1"
}

android_validate_ipv4() {
    local ip=$1 octet
    local -a octets
    IFS=. read -r -a octets <<<"$ip"
    ((${#octets[@]} == 4)) || return 1
    for octet in "${octets[@]}"; do
        [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
}

android_validate_config() {
    local ip joined_ips="" entry filename source purpose provenance_ip description
    local provenance_ips=""
    local command
    for command in ip awk find sort sha256sum sed tail tr; do
        android_require_command "$command"
    done
    for command in "${ANDROID_REQUIRED_COMMANDS[@]}"; do
        android_require_command "$command"
    done
    [[ -f $PROJECT_ROOT/tools/labnet.sh ]] ||
        android_die "no se encuentra labnet.sh"
    [[ -f $WINDOWS_HELPER ]] || android_die "falta el controlador de Windows: $WINDOWS_HELPER"
    : "${ANDROID_DNS_IP:?falta ANDROID_DNS_IP en android.conf}"
    : "${ANDROID_AVD_NAME:?falta ANDROID_AVD_NAME en android.conf}"
    : "${ANDROID_EMULATOR_PORT:?falta ANDROID_EMULATOR_PORT en android.conf}"
    : "${ANDROID_EMULATOR_PATH_WIN:?falta ANDROID_EMULATOR_PATH_WIN en android.conf}"
    [[ -x $ANDROID_POWERSHELL_PATH_WSL ]] ||
        android_die "no se encuentra powershell.exe: $ANDROID_POWERSHELL_PATH_WSL"
    [[ $ANDROID_AVD_NAME =~ ^[A-Za-z0-9._-]+$ ]] ||
        android_die "nombre de AVD no válido: $ANDROID_AVD_NAME"
    [[ $ANDROID_EMULATOR_PORT =~ ^[0-9]+$ ]] &&
        ((ANDROID_EMULATOR_PORT >= 5554 && ANDROID_EMULATOR_PORT <= 5682 && ANDROID_EMULATOR_PORT % 2 == 0)) ||
        android_die "ANDROID_EMULATOR_PORT debe ser un puerto par entre 5554 y 5682"
    ((${#ANDROID_ROUTE_IPS[@]} > 0)) ||
        android_die "ANDROID_ROUTE_IPS no puede estar vacío"
    for ip in "${ANDROID_ROUTE_IPS[@]}"; do
        android_validate_ipv4 "$ip" || android_die "dirección de ruta no válida: $ip"
        [[ ,$joined_ips, != *,$ip,* ]] || android_die "dirección de ruta duplicada: $ip"
        joined_ips=${joined_ips:+$joined_ips,}$ip
    done
    [[ ,$joined_ips, == *,"$ANDROID_DNS_IP",* ]] ||
        android_die "ANDROID_DNS_IP debe aparecer en ANDROID_ROUTE_IPS"
    for entry in "${ANDROID_KEY_FILES[@]}"; do
        IFS='|' read -r filename source purpose <<<"$entry"
        [[ -n $filename && -n $source && -n $purpose ]] ||
            android_die "entrada mal formada en ANDROID_KEY_FILES: $entry"
        [[ -f $source ]] || android_die "no existe el material estático: $source"
    done
    for entry in "${ANDROID_ADDRESS_PROVENANCE[@]}"; do
        IFS='|' read -r provenance_ip description <<<"$entry"
        android_validate_ipv4 "$provenance_ip" ||
            android_die "IP no válida en ANDROID_ADDRESS_PROVENANCE: $entry"
        [[ -n $description ]] || android_die "falta la procedencia de $provenance_ip"
        [[ ,$provenance_ips, != *,$provenance_ip,* ]] ||
            android_die "procedencia duplicada para $provenance_ip"
        provenance_ips=${provenance_ips:+$provenance_ips,}$provenance_ip
    done
    for ip in "${ANDROID_ROUTE_IPS[@]}"; do
        [[ ,$provenance_ips, == *,$ip,* ]] ||
            android_die "falta documentar la procedencia de $ip"
    done
    bash "$LABNET_SCRIPT" "$MANIFEST" check >/dev/null
    android_windows_check
}

android_load_session() {
    [[ -f $ANDROID_STATE_FILE ]] || android_die "no existe una sesión activa para $LAB_ID"
    # El fichero se genera exclusivamente con printf %q y se considera estado
    # confiable del laboratorio.
    # shellcheck source=/dev/null
    source "$ANDROID_STATE_FILE"
    [[ -n $SESSION_DIR && $SESSION_DIR == "$ANDROID_OUTPUT_ROOT"/* ]] ||
        android_die "directorio de sesión no válido en el estado"
    LOG_DIR=$SESSION_DIR/logs
    KEY_DIR=$SESSION_DIR/keys
    EVENT_FILE=$SESSION_DIR/events.log
}

android_save_session() {
    mkdir -p -- "$RUN_STATE_DIR"
    {
        printf 'SESSION_DIR=%q\n' "$SESSION_DIR"
        printf 'WINDOWS_NETWORK_ACTIVE=%q\n' "$WINDOWS_NETWORK_ACTIVE"
    } >"$ANDROID_STATE_FILE"
}

android_mark_event() {
    local label=$1
    [[ -n $EVENT_FILE ]] || android_load_session
    printf '%s | %s\n' "$(date --iso-8601=seconds)" "$label" >>"$EVENT_FILE"
    android_info "marca temporal registrada: $label"
}

android_windows_path() {
    android_require_command wslpath
    wslpath -w "$1"
}

android_powershell() {
    local helper_win
    helper_win=$(android_windows_path "$WINDOWS_HELPER")
    "$ANDROID_POWERSHELL_PATH_WSL" -NoLogo -NoProfile -ExecutionPolicy Bypass \
        -File "$helper_win" "$@"
}

android_wsl_address() {
    local address
    address=$(ip -4 -o addr show dev "$ANDROID_WSL_INTERFACE" scope global 2>/dev/null |
        awk 'NR == 1 { sub(/\/.*/, "", $4); print $4 }')
    [[ -n $address ]] ||
        android_die "no se encontró una IPv4 global en $ANDROID_WSL_INTERFACE"
    printf '%s\n' "$address"
}

android_routes_csv() {
    local IFS=,
    printf '%s' "${ANDROID_ROUTE_IPS[*]}"
}

android_windows_network_up() {
    local wsl_ip destinations
    wsl_ip=$(android_wsl_address)
    destinations=$(android_routes_csv)
    android_info "solicitando a Windows las rutas aisladas hacia Kali WSL"
    android_powershell -Action NetworkUp -LabId "$LAB_ID" \
        -WslAddress "$wsl_ip" -DestinationCsv "$destinations" \
        -StateFile "$ANDROID_WINDOWS_STATE" \
        -EmulatorPath "$ANDROID_EMULATOR_PATH_WIN" || return 1
    WINDOWS_NETWORK_ACTIVE=1
    android_save_session
}

android_windows_check() {
    local wsl_ip destinations
    wsl_ip=$(android_wsl_address)
    destinations=$(android_routes_csv)
    android_powershell -Action Check -LabId "$LAB_ID" \
        -WslAddress "$wsl_ip" -DestinationCsv "$destinations" \
        -EmulatorPath "$ANDROID_EMULATOR_PATH_WIN"
}

android_windows_network_down() {
    android_powershell -Action NetworkDown -LabId "$LAB_ID" \
        -StateFile "$ANDROID_WINDOWS_STATE" || return 1
    WINDOWS_NETWORK_ACTIVE=0
    android_save_session
}

android_emulator_command() {
    printf '& "%s" "@%s" -port %s -dns-server %s -no-snapshot-load\n' \
        "$ANDROID_EMULATOR_PATH_WIN" "$ANDROID_AVD_NAME" \
        "$ANDROID_EMULATOR_PORT" "$ANDROID_DNS_IP"
}

android_export_keys() {
    local entry filename source purpose
    LAB_KEY_FILES=()
    for entry in "${ANDROID_KEY_FILES[@]}"; do
        IFS='|' read -r filename source purpose <<<"$entry"
        LAB_KEY_FILES+=("$filename|$source|$purpose")
    done
    export_key_material
}

android_entity_for_ip() {
    local wanted=$1 record name role ip_list ip
    local -a ips
    for record in "${ENTITIES[@]}"; do
        IFS='|' read -r name role ip_list <<<"$record"
        IFS=',' read -r -a ips <<<"$ip_list"
        for ip in "${ips[@]}"; do
            if [[ $ip == "$wanted" ]]; then
                printf '%s|%s\n' "$name" "$role"
                return 0
            fi
        done
    done
    return 1
}

android_write_session_files() {
    local setup=$SESSION_DIR/android-setup.txt summary=$SESSION_DIR/session.md
    local checksums=$SESSION_DIR/checksums.txt entry ip description entity role
    local -a checksum_paths=(
        "$LAB_DIR/run.sh"
        "$LAB_DIR/topology.conf"
        "$LAB_DIR/android.conf"
        "$PROJECT_ROOT/tools/labnet.sh"
        "$PROJECT_ROOT/tools/runlib.sh"
        "$PROJECT_ROOT/tools/android-runlib.sh"
        "$PROJECT_ROOT/tools/android-windows.ps1"
    )
    while IFS= read -r -d '' entry; do
        checksum_paths+=("$entry")
    done < <(find "$LAB_DIR/source" -maxdepth 2 -type f -print0 | sort -z)

    {
        printf 'AVD: %s\n' "$ANDROID_AVD_NAME"
        printf 'DNS del laboratorio: %s\n' "$ANDROID_DNS_IP"
        printf 'Comando de PowerShell para el arranque manual:\n'
        android_emulator_command
        printf 'Rutas de Windows hacia Kali WSL:\n'
        printf '  %s/32\n' "${ANDROID_ROUTE_IPS[@]}"
    } >"$setup"

    {
        printf '# Sesión Android: %s\n\n' "$LAB_ID"
        printf -- '- Fecha: `%s`\n' "$(date --iso-8601=seconds)"
        printf -- '- AVD de arranque manual: `%s`\n' "$ANDROID_AVD_NAME"
        printf -- '- DNS configurado al arrancar: `%s`\n\n' "$ANDROID_DNS_IP"
        printf '| Entidad | Rol | IP encaminada desde Windows | Procedencia |\n'
        printf '|---|---|---|---|\n'
        for entry in "${ANDROID_ADDRESS_PROVENANCE[@]}"; do
            IFS='|' read -r ip description <<<"$entry"
            IFS='|' read -r entity role < <(android_entity_for_ip "$ip")
            printf '| `%s` | `%s` | `%s` | %s |\n' "$entity" "$role" "$ip" "$description"
        done
        printf '\nLa dirección de origen del emulador no se traduce. La captura conserva las direcciones de destino anteriores.\n'
    } >"$summary"

    sha256sum "${checksum_paths[@]}" >"$checksums"
}

android_next_capture_path() {
    local candidate=$SESSION_DIR/$LAB_ID.pcap attempt=2
    while [[ -e $candidate ]]; do
        candidate=$SESSION_DIR/$LAB_ID-attempt-$attempt.pcap
        ((attempt += 1))
    done
    printf '%s\n' "$candidate"
}

android_log_windows_spec() {
    local row name process_pid logfile first=1
    [[ -f $PROCESS_FILE ]] || return 1
    while IFS= read -r row; do
        IFS='|' read -r name process_pid logfile <<<"$row"
        [[ -n $name && -f $logfile ]] || continue
        ((first == 1)) || printf ','
        printf '%s|%s' "$name" "$logfile"
        first=0
    done <"$PROCESS_FILE"
    ((first == 0))
}

android_log_windows_open() {
    local spec output pids recovery_tokens
    [[ ! -e $ANDROID_LOG_WINDOWS_FILE ]] || {
        android_info "las terminales de entidades ya están abiertas"
        return 1
    }
    spec=$(android_log_windows_spec) || {
        android_info "no hay logs de servicios para abrir"
        return 1
    }
    output=$(android_powershell -Action OpenLogWindows -LabId "$LAB_ID" \
        -LogSpec "$spec" -WslDistribution "$ANDROID_WSL_DISTRIBUTION") || return 1
    output=${output//$'\r'/}
    printf '%s\n' "$output"
    pids=$(sed -n 's/^TFG_LOG_PIDS=//p' <<<"$output" | tail -n 1)
    [[ $pids =~ ^[0-9]+@[0-9]+(,[0-9]+@[0-9]+)*$ ]] || {
        android_info "Windows abrió las terminales pero no devolvió un inventario de PID válido"
        recovery_tokens=$(grep -Eo '[0-9]+@[0-9]+(,[0-9]+@[0-9]+)*' <<<"$output" | tail -n 1 || true)
        if [[ $recovery_tokens =~ ^[0-9]+@[0-9]+(,[0-9]+@[0-9]+)*$ ]]; then
            android_powershell -Action CloseLogWindows -LabId "$LAB_ID" \
                -ProcessCsv "$recovery_tokens" || true
        fi
        return 1
    }
    printf '%s\n' "$pids" >"$ANDROID_LOG_WINDOWS_FILE"
}

android_log_windows_close() {
    local pids
    [[ -f $ANDROID_LOG_WINDOWS_FILE ]] || return 0
    pids=$(<"$ANDROID_LOG_WINDOWS_FILE")
    if [[ $pids =~ ^[0-9]+@[0-9]+(,[0-9]+@[0-9]+)*$ ]]; then
        android_powershell -Action CloseLogWindows -LabId "$LAB_ID" \
            -ProcessCsv "$pids" || return 1
    fi
    rm -f -- "$ANDROID_LOG_WINDOWS_FILE"
}

android_capture_start() {
    local output
    android_load_session
    [[ ! -f $ANDROID_CAPTURE_FILE ]] || android_die "ya existe una captura activa"
    output=$(android_next_capture_path)
    "$LABNET" "$MANIFEST" capture-start "$output"
    printf '%s\n' "$output" >"$ANDROID_CAPTURE_FILE"
    android_mark_event "captura iniciada: ${output##*/}"
    if ! android_log_windows_open; then
        "$LABNET" "$MANIFEST" capture-stop || true
        rm -f -- "$ANDROID_CAPTURE_FILE"
        return 1
    fi
    android_info "captura activa; las terminales visibles muestran cada entidad en tiempo real"
}

android_capture_stop() {
    local output= capture_status=0
    android_load_session
    if [[ ! -f $ANDROID_CAPTURE_FILE ]]; then
        android_info "no hay una captura activa"
        return 0
    fi
    output=$(<"$ANDROID_CAPTURE_FILE")
    android_mark_event "fin de la interacción manual"
    android_info "la captura continúa $ANDROID_GRACE_SECONDS segundos con los servidores activos"
    sleep "$ANDROID_GRACE_SECONDS"
    "$LABNET" "$MANIFEST" capture-stop || capture_status=$?
    ((capture_status == 0)) || return "$capture_status"
    rm -f -- "$ANDROID_CAPTURE_FILE"
    android_export_keys
    android_mark_event "captura finalizada: ${output##*/}"
}

android_prepare_cleanup() {
    local status=$?
    trap - EXIT ERR INT TERM
    android_info "falló la preparación; retirando únicamente el estado creado por esta sesión"
    android_log_windows_close || true
    stop_processes || true
    if ((WINDOWS_NETWORK_ACTIVE == 1)); then
        if ! android_windows_network_down; then
            android_info "Windows no retiró sus reglas; se conserva la topología para reintentar down"
            exit "$status"
        fi
    fi
    "$LABNET" "$MANIFEST" destroy || true
    rm -f -- "$ANDROID_STATE_FILE" "$ANDROID_CAPTURE_FILE" "$ANDROID_LOG_WINDOWS_FILE"
    rmdir -- "$RUN_STATE_DIR" 2>/dev/null || true
    exit "$status"
}

android_prepare() {
    local run_id
    runner_require_root
    android_validate_config
    [[ ! -e $RUN_STATE_DIR ]] || android_die "ya existe estado para $LAB_ID; ejecuta down"
    run_id=$(date +%Y%m%d-%H%M%S)
    SESSION_DIR=$ANDROID_OUTPUT_ROOT/$run_id/$LAB_ID
    LOG_DIR=$SESSION_DIR/logs
    KEY_DIR=$SESSION_DIR/keys
    EVENT_FILE=$SESSION_DIR/events.log
    mkdir -p -- "$LOG_DIR" "$KEY_DIR"
    : >"$EVENT_FILE"

    topology_create
    android_save_session
    trap android_prepare_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    android_windows_network_up
    start_servers
    android_write_session_files
    android_mark_event "topología y servicios preparados; el AVD queda bajo control del operador"
    trap - EXIT INT TERM
    android_info "entorno listo en $SESSION_DIR"
}

android_down() {
    runner_require_root
    if [[ -f $ANDROID_STATE_FILE ]]; then
        android_load_session
    fi
    if [[ -f $ANDROID_CAPTURE_FILE ]]; then
        android_capture_stop
    fi
    stop_processes || true
    android_log_windows_close || true
    if ((WINDOWS_NETWORK_ACTIVE == 1)) || [[ -f $ANDROID_STATE_FILE ]]; then
        android_windows_network_down
    fi
    "$LABNET" "$MANIFEST" destroy
    rm -f -- "$ANDROID_STATE_FILE" "$ANDROID_CAPTURE_FILE" "$ANDROID_LOG_WINDOWS_FILE"
    rmdir -- "$RUN_STATE_DIR" 2>/dev/null || true
    android_info "topología y aislamiento retirados"
}

android_status() {
    "$LABNET" "$MANIFEST" status
    if [[ -f $ANDROID_STATE_FILE ]]; then
        android_load_session
        printf 'Sesión:      %s\n' "$SESSION_DIR"
        printf 'AVD manual:  %s\n' "$ANDROID_AVD_NAME"
        if [[ -f $ANDROID_CAPTURE_FILE ]]; then
            printf 'PCAP:        activo -> %s\n' "$(<"$ANDROID_CAPTURE_FILE")"
        fi
    fi
}

android_run_failure_cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -f $ANDROID_CAPTURE_FILE ]]; then
        "$LABNET" "$MANIFEST" capture-stop || true
        rm -f -- "$ANDROID_CAPTURE_FILE"
    fi
    android_log_windows_close || true
    android_info "el flujo se interrumpió; los servicios y el aislamiento permanecen activos"
    android_info "revisa los logs y utiliza down para completar la retirada"
    exit "$status"
}

android_run_interactive() {
    (($# == 0)) || android_die "run no acepta argumentos"
    android_prepare
    trap android_run_failure_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    android_capture_start
    android_mark_event "comando de arranque manual entregado al operador"
    printf '\nLa topología, la captura y todas las entidades están activas.\n'
    printf 'Ejecuta este comando en una terminal de PowerShell independiente:\n\n'
    android_emulator_command
    if declare -F android_after_emulator_command >/dev/null; then
        android_after_emulator_command
    fi
    if declare -F android_during_interaction >/dev/null; then
        android_during_interaction
    fi
    printf '\n[%s/android] La captura permanece activa mientras interactúas con la muestra.\n' "$LAB_ID"
    printf '[%s/android] Cuando hayas terminado, cierra el AVD y pulsa INTRO para finalizar el PCAP y retirar el laboratorio...' "$LAB_ID"
    IFS= read -r _
    android_capture_stop
    android_down
    trap - EXIT INT TERM
}

android_usage() {
    cat <<'EOF'
Uso: sudo ./run.sh <orden> [opciones]

  check
      Valida manifiestos, activos y herramientas sin modificar el sistema.

  prepare
      Crea la topología e inicia los servicios; no controla el AVD.

  run
      Monta red y servicios, inicia la captura y muestra el comando de
      PowerShell con el que el operador puede arrancar el AVD manualmente.
      Abre una terminal visible por entidad y las cierra durante la retirada.

  capture-start
  capture-stop
  mark TEXTO
  status
  down
      Cierra la captura activa y retira servicios, terminales y red.
      Nunca detiene ni modifica el AVD.
EOF
}

dispatch_android_runner() {
    local command=${1:-}
    shift || true
    case "$command" in
        check)
            (($# == 0)) || android_die "check no acepta argumentos"
            runner_check_python_modules
            android_validate_config
            "$LABNET" "$MANIFEST" check
            android_info "configuración Android válida"
            ;;
        prepare)
            (($# == 0)) || android_die "prepare no acepta argumentos"
            android_prepare
            ;;
        run)
            android_run_interactive "$@"
            ;;
        capture-start)
            (($# == 0)) || android_die "capture-start no acepta argumentos"
            runner_require_root
            android_capture_start
            ;;
        capture-stop)
            (($# == 0)) || android_die "capture-stop no acepta argumentos"
            runner_require_root
            android_capture_stop
            ;;
        mark)
            (($# > 0)) || android_die "mark requiere un texto"
            android_load_session
            android_mark_event "$*"
            ;;
        status)
            (($# == 0)) || android_die "status no acepta argumentos"
            android_status
            ;;
        down)
            (($# == 0)) || android_die "down no acepta argumentos"
            android_down
            ;;
        -h|--help|help|'')
            android_usage
            ;;
        *)
            android_usage >&2
            android_die "orden desconocida: $command"
            ;;
    esac
}

#!/usr/bin/env bash

# Biblioteca para los lanzadores de cada muestra. El script que la incluya debe
# definir LAB_DIR antes de source y proporcionar start_servers/run_client.

[[ -n ${LAB_DIR:-} ]] || { printf 'runlib.sh: falta LAB_DIR\n' >&2; exit 1; }

PROJECT_ROOT=$(cd "$LAB_DIR/../.." && pwd -P)
PROJECT_VENV_BIN=$PROJECT_ROOT/.venv/bin
if [[ -x $PROJECT_VENV_BIN/python3 ]]; then
    export PATH="$PROJECT_VENV_BIN:$PATH"
fi
LABNET_SCRIPT=$PROJECT_ROOT/tools/labnet.sh
LABNET=labnet
LABDNS=$PROJECT_ROOT/tools/labdns.py
MANIFEST=$LAB_DIR/topology.conf

labnet() {
    bash "$LABNET_SCRIPT" "$@"
}

# shellcheck source=/dev/null
source "$MANIFEST"

RUN_STATE_ROOT=${LABNET_STATE_ROOT:-/run/tfg-labnet}
RUN_STATE_DIR=$RUN_STATE_ROOT/$LAB_ID
PROCESS_FILE=$RUN_STATE_DIR/processes.map
LOG_DIR=$LAB_DIR/logs
KEY_DIR=${LABNET_KEY_DIR:-$LOG_DIR/keys}

# Cada laboratorio puede declarar material estático, dinámico o literal. El
# pipeline lo reúne en KEY_DIR y deja un inventario que explica para qué sirve.
declare -a LAB_KEY_FILES=()
declare -a LAB_KEY_DYNAMIC_FILES=()
declare -a LAB_KEY_VALUES=()
declare -a LAB_PYTHON_MODULES=()
LAB_KEY_NOTE=

runner_die() {
    printf '[%s] ERROR: %s\n' "$LAB_ID" "$*" >&2
    exit 1
}

runner_info() {
    printf '[%s] %s\n' "$LAB_ID" "$*"
}

runner_require_root() {
    (( EUID == 0 )) || runner_die "ejecuta el lanzador con sudo dentro de Kali WSL"
}

runner_check_python_modules() {
    local module
    command -v python3 >/dev/null 2>&1 || runner_die "no se encuentra Python 3"
    for module in "${LAB_PYTHON_MODULES[@]}"; do
        if ! python3 -c "import $module" >/dev/null 2>&1; then
            runner_die "falta el módulo Python $module; crea $PROJECT_ROOT/.venv e instala $PROJECT_ROOT/requirements.txt"
        fi
    done
}

topology_create() {
    "$LABNET" "$MANIFEST" create
    mkdir -p -- "$LOG_DIR" "$KEY_DIR"
    : >"$PROCESS_FILE"
}

validate_key_filename() {
    local filename=$1
    if [[ ! $filename =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$ ]]; then
        printf '[%s] ERROR: nombre de fichero de claves no válido: %s\n' \
            "$LAB_ID" "$filename" >&2
        return 1
    fi
}

export_key_material() {
    local manifest=$KEY_DIR/key-material.txt
    local entry filename source purpose value
    local -a inventory=()

    mkdir -p -- "$KEY_DIR" || return 1

    for entry in "${LAB_KEY_FILES[@]}"; do
        IFS='|' read -r filename source purpose <<<"$entry"
        validate_key_filename "$filename" || return 1
        if [[ ! -f $source ]]; then
            printf '[%s] ERROR: no existe el material de claves requerido: %s\n' \
                "$LAB_ID" "$source" >&2
            return 1
        fi
        cp -f -- "$source" "$KEY_DIR/$filename" || return 1
        chmod 644 "$KEY_DIR/$filename" || return 1
        inventory+=("$filename|$purpose")
    done

    for entry in "${LAB_KEY_VALUES[@]}"; do
        IFS='|' read -r filename value purpose <<<"$entry"
        validate_key_filename "$filename" || return 1
        printf '%s\n' "$value" >"$KEY_DIR/$filename" || return 1
        chmod 644 "$KEY_DIR/$filename" || return 1
        inventory+=("$filename|$purpose")
    done

    for entry in "${LAB_KEY_DYNAMIC_FILES[@]}"; do
        IFS='|' read -r filename purpose <<<"$entry"
        validate_key_filename "$filename" || return 1
        if [[ ! -s $KEY_DIR/$filename ]]; then
            printf '[%s] ERROR: no se generó el material de claves requerido: %s\n' \
                "$LAB_ID" "$KEY_DIR/$filename" >&2
            return 1
        fi
        chmod 644 "$KEY_DIR/$filename" || return 1
        inventory+=("$filename|$purpose")
    done

    {
        printf 'Laboratorio: %s\n' "$LAB_ID"
        printf 'Directorio: %s\n' "$KEY_DIR"
        if ((${#inventory[@]} == 0)); then
            printf 'Material: ninguno\n'
        else
            printf 'Material:\n'
            for entry in "${inventory[@]}"; do
                IFS='|' read -r filename purpose <<<"$entry"
                printf '  - %s: %s\n' "$filename" "$purpose"
            done
        fi
        if [[ -n $LAB_KEY_NOTE ]]; then
            printf 'Nota: %s\n' "$LAB_KEY_NOTE"
        fi
    } >"$manifest" || return 1
    chmod 644 "$manifest" || return 1
    runner_info "material criptográfico inventariado en $KEY_DIR"
}

start_process() {
    local name=$1 entity=$2 cwd=$3
    shift 3
    [[ ${1:-} == -- ]] || runner_die "start_process requiere -- antes de la orden"
    shift
    (($# > 0)) || runner_die "start_process no recibió una orden"
    [[ $name =~ ^[a-z][a-z0-9_-]{0,39}$ ]] || runner_die "nombre de proceso no válido: $name"
    [[ -f $PROCESS_FILE ]] || runner_die "la topología no está preparada"
    if grep -q "^${name}|" "$PROCESS_FILE"; then
        runner_die "el proceso $name ya figura en el estado"
    fi
    local logfile=$LOG_DIR/$name.log pid
    setsid bash "$LABNET_SCRIPT" "$MANIFEST" exec "$entity" --cwd "$cwd" -- "$@" \
        >"$logfile" 2>&1 &
    pid=$!
    printf '%s|%s|%s\n' "$name" "$pid" "$logfile" >>"$PROCESS_FILE"
    sleep 0.15
    if ! kill -0 "$pid" 2>/dev/null; then
        tail -n 40 "$logfile" >&2 || true
        runner_die "el proceso $name terminó durante el arranque"
    fi
    runner_info "$name iniciado en $entity (PID $pid)"
}

wait_tcp() {
    local entity=$1 ip=$2 port=$3 attempts=${4:-80} output
    while ((attempts > 0)); do
        output=$("$LABNET" "$MANIFEST" exec "$entity" -- ss -H -ltn "sport = :$port" 2>/dev/null || true)
        if grep -Fq "$ip:$port" <<<"$output"; then
            return 0
        fi
        sleep 0.1
        attempts=$((attempts - 1))
    done
    runner_die "no apareció la escucha $ip:$port en $entity"
}

wait_udp() {
    local entity=$1 ip=$2 port=$3 attempts=${4:-80} output
    while ((attempts > 0)); do
        output=$("$LABNET" "$MANIFEST" exec "$entity" -- ss -H -lun "sport = :$port" 2>/dev/null || true)
        if grep -Fq "$ip:$port" <<<"$output"; then
            return 0
        fi
        sleep 0.1
        attempts=$((attempts - 1))
    done
    runner_die "no apareció la escucha UDP $ip:$port en $entity"
}

stop_processes() {
    local -a rows=()
    local row name pid logfile count
    [[ -f $PROCESS_FILE ]] || return 0
    mapfile -t rows <"$PROCESS_FILE"
    for ((count=${#rows[@]} - 1; count >= 0; count--)); do
        row=${rows[$count]}
        IFS='|' read -r name pid logfile <<<"$row"
        [[ $pid =~ ^[0-9]+$ ]] || continue
        if kill -0 "$pid" 2>/dev/null; then
            kill -INT -- "-$pid" 2>/dev/null || true
        fi
    done
    for _ in {1..40}; do
        local any=0
        for row in "${rows[@]}"; do
            IFS='|' read -r name pid logfile <<<"$row"
            [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null && any=1
        done
        ((any == 0)) && break
        sleep 0.1
    done
    for row in "${rows[@]}"; do
        IFS='|' read -r name pid logfile <<<"$row"
        [[ $pid =~ ^[0-9]+$ ]] || continue
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM -- "-$pid" 2>/dev/null || true
        fi
    done
    rm -f -- "$PROCESS_FILE"
}

topology_down() {
    "$LABNET" "$MANIFEST" capture-stop || true
    stop_processes
    "$LABNET" "$MANIFEST" destroy
}

capture_cleanup() {
    local status=$?
    trap - EXIT INT TERM

    if ! "$LABNET" "$MANIFEST" capture-stop; then
        if ((status == 0)); then status=1; fi
    fi
    if ! stop_processes; then
        if ((status == 0)); then status=1; fi
    fi
    if ! export_key_material; then
        if ((status == 0)); then status=1; fi
    fi
    if ! "$LABNET" "$MANIFEST" destroy; then
        if ((status == 0)); then status=1; fi
    fi
    exit "$status"
}

capture_workflow() {
    local output=${1:-}
    local result=0
    runner_require_root
    runner_check_python_modules
    topology_create
    trap capture_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ -n $output ]]; then
        "$LABNET" "$MANIFEST" capture-start "$output"
    else
        "$LABNET" "$MANIFEST" capture-start
    fi
    start_servers
    run_client || result=$?
    runner_info "cliente finalizado; la captura continúa 10 segundos con los servidores activos"
    sleep 10
    return "$result"
}

runner_usage() {
    cat <<EOF
Uso: sudo ./run.sh <orden> [argumentos]

  check                 valida el manifiesto
  up                    crea la topología e inicia servicios
  client                ejecuta solo el cliente en una topología activa
  capture [fichero]     ejecuta el flujo completo y genera la captura
  status                muestra el estado de red
  down                  detiene procesos y retira la topología
EOF
}

dispatch_runner() {
    local command=${1:-}
    shift || true
    case "$command" in
        check)
            (($# == 0)) || runner_die "check no acepta argumentos"
            runner_check_python_modules
            "$LABNET" "$MANIFEST" check
            ;;
        up)
            (($# == 0)) || runner_die "up no acepta argumentos"
            runner_require_root
            runner_check_python_modules
            topology_create
            start_servers
            ;;
        client)
            (($# == 0)) || runner_die "client no acepta argumentos"
            runner_require_root
            runner_check_python_modules
            run_client
            ;;
        capture)
            (($# <= 1)) || runner_die "capture acepta como máximo un fichero"
            capture_workflow "${1:-}"
            ;;
        status)
            (($# == 0)) || runner_die "status no acepta argumentos"
            "$LABNET" "$MANIFEST" status
            ;;
        down)
            (($# == 0)) || runner_die "down no acepta argumentos"
            runner_require_root
            topology_down
            ;;
        -h|--help|help|'')
            runner_usage
            ;;
        *)
            runner_usage >&2
            runner_die "orden desconocida: $command"
            ;;
    esac
}

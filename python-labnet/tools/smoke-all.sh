#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
(( EUID == 0 )) || { printf 'Ejecuta esta prueba con sudo dentro de Kali WSL.\n' >&2; exit 1; }
command -v timeout >/dev/null 2>&1 || { printf 'Falta timeout (coreutils).\n' >&2; exit 1; }
command -v capinfos >/dev/null 2>&1 || { printf 'Falta capinfos (wireshark-common).\n' >&2; exit 1; }

all_labs=(keyraider notcompatible skygofree exodus monokle gplayed busygasper drinik flubot lightspy)
labs=("$@")
if (($# == 0)); then
    labs=("${all_labs[@]}")
fi

run_id=$(date +%Y%m%d-%H%M%S)
output_dir=$ROOT/smoke/$run_id
mkdir -p -- "$output_dir"

for lab in "${labs[@]}"; do
    [[ $lab =~ ^[a-z][a-z0-9-]+$ && -f $ROOT/labs/$lab/run.sh ]] || {
        printf 'Laboratorio desconocido: %s\n' "$lab" >&2
        exit 1
    }
    lab_output_dir=$output_dir/$lab
    key_dir=$lab_output_dir/keys
    mkdir -p -- "$key_dir"
    output=$lab_output_dir/$lab.pcap
    printf '\n[smoke] %s -> %s\n' "$lab" "$output"
    LABNET_KEY_DIR=$key_dir timeout --foreground 180 \
        bash "$ROOT/labs/$lab/run.sh" capture "$output"
    capinfos -c -s "$output"
done

printf '\nPrueba dinámica completada: %s\n' "$output_dir"

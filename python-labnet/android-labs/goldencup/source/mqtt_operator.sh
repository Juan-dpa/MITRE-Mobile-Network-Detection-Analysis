#!/usr/bin/env bash
set -Eeuo pipefail

(($# == 2)) || {
    printf 'Uso: %s BROKER_IP FICHERO_URL\n' "${0##*/}" >&2
    exit 2
}

broker_ip=$1
url_file=$2
artifact_url=$(<"$url_file")

printf '[operator] esperando RT/AP/<client-id>/I/A = ON en %s:1883\n' "$broker_ip"

while true; do
    status=$(mosquitto_sub -h "$broker_ip" -p 1883 -V mqttv311 -q 2 \
        -t 'RT/AP/+/I/A' -C 1 -W 600 -F '%t|%p') || {
        printf '[operator] no se recibió el anuncio; reintentando la suscripción\n' >&2
        continue
    }
    topic=${status%%|*}
    payload=${status#*|}
    [[ $payload == ON ]] || {
        printf '[operator] ignorado %s = %s\n' "$topic" "$payload"
        continue
    }
    IFS=/ read -r root side client_id level code <<<"$topic"
    [[ $root == RT && $side == AP && -n $client_id && $level == I && $code == A ]] || {
        printf '[operator] tema de estado inesperado: %s\n' "$topic" >&2
        continue
    }
    break
done

command_topic="RT/SV/$client_id/C/a"
ack_topic="RT/AP/$client_id/I/B"
ack_file=$(mktemp)
ack_pid=
cleanup() {
    [[ -z $ack_pid ]] || kill "$ack_pid" 2>/dev/null || true
    rm -f -- "$ack_file"
}
trap cleanup EXIT INT TERM

printf '[operator] dispositivo %s disponible; esperando el acuse %s\n' \
    "$client_id" "$ack_topic"
mosquitto_sub -h "$broker_ip" -p 1883 -V mqttv311 -q 2 \
    -t "$ack_topic" -C 1 -W 600 -F '%t|%p' >"$ack_file" &
ack_pid=$!

# connectComplete y la suscripción de la APK son callbacks independientes.
# Esta pausa deja que el SUBSCRIBE QoS 2 llegue al broker antes de la orden.
sleep 1
mosquitto_pub -h "$broker_ip" -p 1883 -V mqttv311 -q 2 \
    -t "$command_topic" -m "$artifact_url"
printf '[operator] publicado %s = %s\n' "$command_topic" "$artifact_url"

if wait "$ack_pid"; then
    ack_pid=
    printf '[operator] acuse recibido: %s\n' "$(<"$ack_file")"
else
    ack_pid=
    printf '[operator] no se recibió el acuse de instalación antes del límite\n' >&2
    exit 1
fi

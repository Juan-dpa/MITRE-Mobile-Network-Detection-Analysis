#!/usr/bin/env bash
set -Eeuo pipefail

PROGRAM=${0##*/}

usage() {
    cat <<'EOF'
Uso: labnet.sh <manifiesto> <orden> [argumentos]

Órdenes:
  check                         valida el manifiesto sin cambiar la red
  create                        crea namespaces, veth, rutas y cortafuegos
  status                        muestra entidades, interfaces y captura
  exec <entidad> [--cwd DIR] -- ORDEN [ARG...]
  capture-start [FICHERO]       captura en el enlace de CAPTURE_ENTITY
  capture-stop                  finaliza la captura activa
  destroy                       elimina únicamente la topología del manifiesto
EOF
}

die() {
    printf '%s: %s\n' "$PROGRAM" "$*" >&2
    exit 1
}

info() {
    printf '[labnet] %s\n' "$*"
}

require_root() {
    (( EUID == 0 )) || die "esta orden requiere privilegios de root"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "no se encuentra la orden requerida: $1"
}

valid_ipv4() {
    local ip=$1 octet
    local -a octets
    IFS=. read -r -a octets <<<"$ip"
    ((${#octets[@]} == 4)) || return 1
    for octet in "${octets[@]}"; do
        [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
}

valid_visible_ipv4() {
    local ip=$1 first
    valid_ipv4 "$ip" || return 1
    first=${ip%%.*}
    ((10#$first != 0 && 10#$first != 127 && 10#$first < 224)) || return 1
    [[ $ip != 255.255.255.255 ]] || return 1
    [[ $ip != 192.0.2.* && $ip != 198.51.100.* && $ip != 203.0.113.* ]]
}

valid_port_spec() {
    local spec=$1 first last
    if [[ $spec =~ ^([0-9]{1,5})$ ]]; then
        first=${BASH_REMATCH[1]}
        ((10#$first >= 1 && 10#$first <= 65535))
    elif [[ $spec =~ ^([0-9]{1,5})-([0-9]{1,5})$ ]]; then
        first=${BASH_REMATCH[1]}
        last=${BASH_REMATCH[2]}
        ((10#$first >= 1 && 10#$last <= 65535 && 10#$first <= 10#$last))
    else
        return 1
    fi
}

declare -a ENTITY_ORDER=()
declare -A ENTITY_ROLE=()
declare -A ENTITY_IPS=()
declare -A ENTITY_PRIMARY=()
declare -A ENTITY_INDEX=()
declare -A ENTITY_EXTERNAL=()
declare -A IP_OWNER=()
declare -A SERVICE_KEYS=()

load_manifest() {
    local supplied=$1
    [[ -f $supplied ]] || die "no existe el manifiesto: $supplied"
    MANIFEST=$(cd "$(dirname "$supplied")" && pwd -P)/$(basename "$supplied")
    MANIFEST_DIR=${MANIFEST%/*}

    # El manifiesto forma parte del laboratorio y se considera código confiable.
    # shellcheck source=/dev/null
    source "$MANIFEST"

    : "${LAB_ID:?falta LAB_ID}"
    : "${TRANSIT_PREFIX:?falta TRANSIT_PREFIX}"
    : "${CAPTURE_ENTITY:?falta CAPTURE_ENTITY}"
    declare -p ENTITIES >/dev/null 2>&1 || die "falta el array ENTITIES"
    declare -p SERVICES >/dev/null 2>&1 || die "falta el array SERVICES"
    declare -p FLOWS >/dev/null 2>&1 || die "falta el array FLOWS"

    STATE_ROOT=${LABNET_STATE_ROOT:-/run/tfg-labnet}
    STATE_DIR=$STATE_ROOT/$LAB_ID
    MAP_FILE=$STATE_DIR/entities.map
    ROUTER_FILE=$STATE_DIR/router
    CAPTURE_MAP_FILE=$STATE_DIR/captures.map
    CAPTURE_PATH_FILE=$STATE_DIR/capture.path
    HOST_LINK_FILE=$STATE_DIR/host-link.map

    if ! declare -p CAPTURE_POINTS >/dev/null 2>&1; then
        CAPTURE_POINTS=("$CAPTURE_ENTITY|${CAPTURE_FILTER:-ip}")
    fi
    if ! declare -p EXTERNAL_ENTITIES >/dev/null 2>&1; then
        EXTERNAL_ENTITIES=()
    fi
}

validate_manifest() {
    local record name role ip_list extra ip index=0 key external
    local service_entity service_ip proto port label
    local src dst dst_ip flow_proto flow_port capture_name capture_filter
    local -A capture_names=()
    local -a ips

    [[ $LAB_ID =~ ^[a-z0-9][a-z0-9-]{0,23}$ ]] ||
        die "LAB_ID debe usar minúsculas, números o guiones y no superar 24 caracteres"
    [[ $TRANSIT_PREFIX =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] ||
        die "TRANSIT_PREFIX debe contener tres octetos IPv4"
    valid_ipv4 "$TRANSIT_PREFIX.1" || die "TRANSIT_PREFIX no es válido: $TRANSIT_PREFIX"

    ENTITY_ORDER=()
    ENTITY_ROLE=()
    ENTITY_IPS=()
    ENTITY_PRIMARY=()
    ENTITY_INDEX=()
    ENTITY_EXTERNAL=()
    IP_OWNER=()
    SERVICE_KEYS=()

    ((${#ENTITIES[@]} > 0)) || die "ENTITIES está vacío"
    ((${#ENTITIES[@]} <= 62)) || die "la topología admite como máximo 62 entidades"

    for record in "${ENTITIES[@]}"; do
        [[ $record =~ ^[^|]+\|[^|]+\|[^|]+$ ]] ||
            die "entidad mal formada (nombre|rol|ip[,ip...]): $record"
        IFS='|' read -r name role ip_list extra <<<"$record"
        [[ $name =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || die "nombre de entidad no válido: $name"
        [[ $role =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || die "rol no válido para $name: $role"
        [[ -z ${ENTITY_ROLE[$name]+x} ]] || die "nombre de entidad duplicado: $name"
        IFS=',' read -r -a ips <<<"$ip_list"
        ((${#ips[@]} > 0)) || die "la entidad $name no tiene direcciones visibles"
        for ip in "${ips[@]}"; do
            valid_visible_ipv4 "$ip" ||
                die "dirección visible no válida, de loopback o reservada para documentación en $name: $ip"
            [[ -z ${IP_OWNER[$ip]+x} ]] || die "la IP $ip pertenece a más de una entidad"
            IP_OWNER[$ip]=$name
        done
        ENTITY_ORDER+=("$name")
        ENTITY_ROLE[$name]=$role
        ENTITY_IPS[$name]=$ip_list
        ENTITY_PRIMARY[$name]=${ips[0]}
        ENTITY_INDEX[$name]=$index
        ((index += 1))
    done

    ((${#EXTERNAL_ENTITIES[@]} <= 1)) ||
        die "solo se admite una entidad externa por topología"
    for external in "${EXTERNAL_ENTITIES[@]}"; do
        [[ -n ${ENTITY_ROLE[$external]+x} ]] ||
            die "entidad inexistente en EXTERNAL_ENTITIES: $external"
        [[ -z ${ENTITY_EXTERNAL[$external]+x} ]] ||
            die "entidad externa duplicada: $external"
        ENTITY_EXTERNAL[$external]=1
    done
    if ((${#EXTERNAL_ENTITIES[@]} > 0)); then
        : "${HOST_LINK_PREFIX:?falta HOST_LINK_PREFIX para la entidad externa}"
        [[ $HOST_LINK_PREFIX =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] ||
            die "HOST_LINK_PREFIX debe contener tres octetos IPv4"
        valid_ipv4 "$HOST_LINK_PREFIX.1" ||
            die "HOST_LINK_PREFIX no es válido: $HOST_LINK_PREFIX"
        [[ $HOST_LINK_PREFIX != "$TRANSIT_PREFIX" ]] ||
            die "HOST_LINK_PREFIX y TRANSIT_PREFIX deben ser diferentes"
    fi

    [[ -n ${ENTITY_ROLE[$CAPTURE_ENTITY]+x} ]] ||
        die "CAPTURE_ENTITY no existe: $CAPTURE_ENTITY"
    ((${#CAPTURE_POINTS[@]} > 0)) || die "CAPTURE_POINTS está vacío"
    for record in "${CAPTURE_POINTS[@]}"; do
        [[ $record =~ ^[^|]+\|[^|]+$ ]] ||
            die "punto de captura mal formado (entidad|filtro BPF): $record"
        IFS='|' read -r capture_name capture_filter extra <<<"$record"
        [[ -n ${ENTITY_ROLE[$capture_name]+x} ]] ||
            die "entidad inexistente en CAPTURE_POINTS: $capture_name"
        [[ -z ${capture_names[$capture_name]+x} ]] ||
            die "entidad de captura duplicada: $capture_name"
        capture_names[$capture_name]=1
    done

    for record in "${SERVICES[@]}"; do
        [[ $record =~ ^[^|]+\|[^|]+\|[^|]+\|[^|]+\|[^|]+$ ]] ||
            die "servicio mal formado (entidad|ip|protocolo|puerto|nombre): $record"
        IFS='|' read -r service_entity service_ip proto port label extra <<<"$record"
        [[ -n ${ENTITY_ROLE[$service_entity]+x} ]] || die "servicio de entidad inexistente: $record"
        [[ ${IP_OWNER[$service_ip]:-} == "$service_entity" ]] ||
            die "el servicio $label usa una IP que no pertenece a $service_entity"
        [[ $proto == tcp || $proto == udp ]] || die "protocolo no válido en $label: $proto"
        valid_port_spec "$port" || die "puerto no válido en $label: $port"
        [[ $label =~ ^[a-z][a-z0-9_-]{0,39}$ ]] || die "nombre de servicio no válido: $label"
        [[ -z ${SERVICE_KEYS[$label]+x} ]] || die "nombre de servicio duplicado: $label"
        key=$service_entity'|'$service_ip'|'$proto'|'$port
        [[ -z ${SERVICE_KEYS[$key]+x} ]] || die "servicio duplicado: $record"
        SERVICE_KEYS[$label]=$key
        SERVICE_KEYS[$key]=$label
    done

    for record in "${FLOWS[@]}"; do
        [[ $record =~ ^[^|]+\|[^|]+\|[^|]+\|[^|]+\|[^|]+$ ]] ||
            die "flujo mal formado (origen|destino|ip|protocolo|puerto): $record"
        IFS='|' read -r src dst dst_ip flow_proto flow_port extra <<<"$record"
        [[ -n ${ENTITY_ROLE[$src]+x} ]] || die "origen inexistente en flujo: $record"
        [[ -n ${ENTITY_ROLE[$dst]+x} ]] || die "destino inexistente en flujo: $record"
        [[ ${IP_OWNER[$dst_ip]:-} == "$dst" ]] || die "IP de destino incoherente en flujo: $record"
        key=$dst'|'$dst_ip'|'$flow_proto'|'$flow_port
        [[ -n ${SERVICE_KEYS[$key]+x} ]] || die "el flujo no termina en un servicio declarado: $record"
    done
}

lab_token() {
    local sum
    sum=$(printf '%s' "$LAB_ID" | cksum | awk '{print $1}')
    printf '%05x' "$((sum % 1048576))"
}

router_namespace() {
    local token
    token=$(lab_token)
    printf 'tfg-%s-r' "$token"
}

entity_namespace() {
    local token=$1 index=$2
    printf 'tfg-%s-e%d' "$token" "$index"
}

router_interface() {
    local token=$1 index=$2
    printf 'lr%s%02d' "$token" "$index"
}

entity_temp_interface() {
    local token=$1 index=$2
    printf 'le%s%02d' "$token" "$index"
}

read_router_namespace() {
    [[ -f $ROUTER_FILE ]] || die "la topología $LAB_ID no está creada"
    ROUTER_NS=$(<"$ROUTER_FILE")
    [[ $ROUTER_NS == tfg-*-r ]] || die "estado de router no válido"
}

map_row_for() {
    local wanted=$1 row_name
    [[ -f $MAP_FILE ]] || die "la topología $LAB_ID no está creada"
    while IFS='|' read -r row_name MAP_ROLE MAP_NS MAP_RIF MAP_ROUTER_IP MAP_ENTITY_IP MAP_PRIMARY MAP_IPS MAP_KIND; do
        if [[ $row_name == "$wanted" ]]; then
            MAP_NAME=$row_name
            MAP_KIND=${MAP_KIND:-internal}
            return 0
        fi
    done <"$MAP_FILE"
    die "la entidad no existe en el estado activo: $wanted"
}

destroy_internal() {
    local name role ns rest router_ns host_if router_if host_ip router_ip previous_forward host_chain
    if [[ -f $CAPTURE_MAP_FILE ]]; then
        capture_stop_internal || true
    fi
    if [[ -f $MAP_FILE ]]; then
        while IFS='|' read -r name role ns rest; do
            [[ $ns == tfg-*-e+([0-9]) ]] || continue
            ip netns del "$ns" 2>/dev/null || true
        done <"$MAP_FILE"
    fi
    if [[ -f $ROUTER_FILE ]]; then
        router_ns=$(<"$ROUTER_FILE")
        [[ $router_ns == tfg-*-r ]] && ip netns del "$router_ns" 2>/dev/null || true
    fi
    if [[ -f $HOST_LINK_FILE ]]; then
        IFS='|' read -r host_if router_if host_ip router_ip previous_forward host_chain <"$HOST_LINK_FILE"
        if [[ $host_chain =~ ^TFGA[0-9a-f]{5}$ ]]; then
            iptables -D FORWARD -j "$host_chain" 2>/dev/null || true
            iptables -F "$host_chain" 2>/dev/null || true
            iptables -X "$host_chain" 2>/dev/null || true
        fi
        [[ $host_if == lha+([0-9a-f]) ]] && ip link del "$host_if" 2>/dev/null || true
        if [[ $previous_forward == 0 || $previous_forward == 1 ]]; then
            sysctl -q -w net.ipv4.ip_forward="$previous_forward" >/dev/null 2>&1 || true
        fi
    fi
    rm -f -- "$MAP_FILE" "$ROUTER_FILE" "$CAPTURE_MAP_FILE" "$CAPTURE_PATH_FILE" \
        "$HOST_LINK_FILE"
    rm -f -- "$STATE_DIR"/capture-*.pcap "$STATE_DIR"/tcpdump-*.log
    rmdir -- "$STATE_DIR" 2>/dev/null || true
}

create_topology() {
    local token router_ns name index ns rif eif host_octet router_ip entity_ip
    local primary ip other other_ip port_spec external_name= external_host_if=
    local external_router_if= external_host_ip= external_router_ip= previous_forward= external_host_chain=
    local record src dst dst_ip proto port
    local -a ips other_ips source_ips

    require_root
    for cmd in ip sysctl iptables; do require_command "$cmd"; done
    [[ ! -e $STATE_DIR ]] || die "ya existe estado para $LAB_ID; ejecuta destroy antes de recrearlo"
    if ((${#EXTERNAL_ENTITIES[@]} == 1)); then
        local active_host_link
        for active_host_link in "$STATE_ROOT"/*/host-link.map; do
            [[ -e $active_host_link ]] || continue
            die "ya existe otra topología con entrada externa: $active_host_link"
        done
    fi

    mkdir -p -- "$STATE_DIR"
    : >"$MAP_FILE"
    token=$(lab_token)
    router_ns=$(router_namespace)
    printf '%s\n' "$router_ns" >"$ROUTER_FILE"

    trap 'info "falló la creación; retirando la topología parcial"; destroy_internal' ERR INT TERM
    ip netns add "$router_ns"
    ip -n "$router_ns" link set lo up
    ip netns exec "$router_ns" sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
    ip netns exec "$router_ns" sysctl -q -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    ip netns exec "$router_ns" sysctl -q -w net.ipv4.conf.default.rp_filter=0 >/dev/null

    if ((${#EXTERNAL_ENTITIES[@]} == 1)); then
        external_name=${EXTERNAL_ENTITIES[0]}
        external_host_if=lha$token
        external_router_if=lra$token
        external_host_chain=TFGA$token
        external_host_ip=$HOST_LINK_PREFIX.1
        external_router_ip=$HOST_LINK_PREFIX.2
        previous_forward=$(sysctl -n net.ipv4.ip_forward)
        [[ $previous_forward == 0 || $previous_forward == 1 ]] ||
            die "no se pudo determinar net.ipv4.ip_forward"
        printf '%s|%s|%s|%s|%s|%s\n' \
            "$external_host_if" "$external_router_if" "$external_host_ip" \
            "$external_router_ip" "$previous_forward" "$external_host_chain" >"$HOST_LINK_FILE"
        sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
        iptables -N "$external_host_chain"
        iptables -I FORWARD 1 -j "$external_host_chain"
        ip link add "$external_host_if" type veth peer name "$external_router_if"
        ip link set "$external_router_if" netns "$router_ns"
        ip addr add "$external_host_ip/30" dev "$external_host_if"
        ip link set "$external_host_if" up
        ip -n "$router_ns" addr add "$external_router_ip/30" dev "$external_router_if"
        ip -n "$router_ns" link set "$external_router_if" up
        ip -n "$router_ns" route replace default via "$external_host_ip" dev "$external_router_if"
    fi

    for name in "${ENTITY_ORDER[@]}"; do
        index=${ENTITY_INDEX[$name]}
        if [[ -n ${ENTITY_EXTERNAL[$name]+x} ]]; then
            printf '%s|%s|external|%s|%s|%s|%s|%s|external\n' \
                "$name" "${ENTITY_ROLE[$name]}" "$external_router_if" \
                "$external_router_ip" "$external_host_ip" \
                "${ENTITY_PRIMARY[$name]}" "${ENTITY_IPS[$name]}" >>"$MAP_FILE"
            continue
        fi
        host_octet=$((index * 4 + 1))
        router_ip=$TRANSIT_PREFIX.$host_octet
        entity_ip=$TRANSIT_PREFIX.$((host_octet + 1))
        ns=$(entity_namespace "$token" "$index")
        rif=$(router_interface "$token" "$index")
        eif=$(entity_temp_interface "$token" "$index")
        primary=${ENTITY_PRIMARY[$name]}

        ip netns add "$ns"
        ip link add "$rif" type veth peer name "$eif"
        ip link set "$rif" netns "$router_ns"
        ip link set "$eif" netns "$ns"
        ip -n "$ns" link set "$eif" name eth0
        ip -n "$router_ns" addr add "$router_ip/30" dev "$rif"
        ip -n "$ns" addr add "$entity_ip/30" dev eth0
        ip -n "$router_ns" link set "$rif" up
        ip -n "$ns" link set lo up
        ip -n "$ns" link set eth0 up
        ip -n "$ns" link add dummy0 type dummy
        ip -n "$ns" link set dummy0 up
        IFS=',' read -r -a ips <<<"${ENTITY_IPS[$name]}"
        for ip in "${ips[@]}"; do
            ip -n "$ns" addr add "$ip/32" dev dummy0
            ip -n "$router_ns" route replace "$ip/32" via "$entity_ip" dev "$rif"
        done
        ip netns exec "$ns" sysctl -q -w net.ipv4.conf.all.rp_filter=0 >/dev/null
        ip netns exec "$ns" sysctl -q -w net.ipv4.conf.default.rp_filter=0 >/dev/null
        printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
            "$name" "${ENTITY_ROLE[$name]}" "$ns" "$rif" "$router_ip" "$entity_ip" \
            "$primary" "${ENTITY_IPS[$name]}" "internal" >>"$MAP_FILE"
    done

    if [[ -n $external_name ]]; then
        for name in "${ENTITY_ORDER[@]}"; do
            [[ -n ${ENTITY_EXTERNAL[$name]+x} ]] && continue
            IFS=',' read -r -a ips <<<"${ENTITY_IPS[$name]}"
            for ip in "${ips[@]}"; do
                ip route replace "$ip/32" via "$external_router_ip" dev "$external_host_if"
            done
        done
    fi

    for name in "${ENTITY_ORDER[@]}"; do
        [[ -n ${ENTITY_EXTERNAL[$name]+x} ]] && continue
        map_row_for "$name"
        ns=$MAP_NS
        router_ip=$MAP_ROUTER_IP
        primary=$MAP_PRIMARY
        for other in "${ENTITY_ORDER[@]}"; do
            [[ $other == "$name" ]] && continue
            [[ -n ${ENTITY_EXTERNAL[$other]+x} ]] && continue
            IFS=',' read -r -a other_ips <<<"${ENTITY_IPS[$other]}"
            for other_ip in "${other_ips[@]}"; do
                ip -n "$ns" route replace "$other_ip/32" via "$router_ip" dev eth0 src "$primary"
            done
        done
        if [[ -n $external_name ]]; then
            ip -n "$ns" route replace default via "$router_ip" dev eth0 src "$primary"
        fi
    done

    ip netns exec "$router_ns" iptables -P FORWARD DROP
    ip netns exec "$router_ns" iptables -A FORWARD \
        -m conntrack --ctstate ESTABLISHED -j ACCEPT
    for record in "${FLOWS[@]}"; do
        IFS='|' read -r src dst dst_ip proto port <<<"$record"
        port_spec=${port/-/:}
        if [[ -n ${ENTITY_EXTERNAL[$src]+x} ]]; then
            ip netns exec "$router_ns" iptables -A FORWARD \
                -i "$external_router_if" -d "$dst_ip/32" -p "$proto" --dport "$port_spec" \
                -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
            iptables -A "$external_host_chain" \
                -o "$external_host_if" -d "$dst_ip/32" -p "$proto" --dport "$port_spec" \
                -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        else
            IFS=',' read -r -a source_ips <<<"${ENTITY_IPS[$src]}"
            for ip in "${source_ips[@]}"; do
                ip netns exec "$router_ns" iptables -A FORWARD \
                    -s "$ip/32" -d "$dst_ip/32" -p "$proto" --dport "$port_spec" \
                    -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
            done
        fi
    done
    if [[ -n $external_name ]]; then
        iptables -A "$external_host_chain" -i "$external_host_if" \
            -m conntrack --ctstate ESTABLISHED -j ACCEPT
        iptables -A "$external_host_chain" -j RETURN
    fi
    trap - ERR INT TERM
    info "topología $LAB_ID creada con ${#ENTITY_ORDER[@]} entidades"
}

capture_stop_internal() {
    local pid part entity count output
    local -a parts=()
    [[ -f $CAPTURE_MAP_FILE ]] || return 0
    while IFS='|' read -r pid part entity; do
        [[ $pid =~ ^[0-9]+$ ]] || die "PID de captura no válido"
        if kill -0 "$pid" 2>/dev/null; then
            kill -INT "$pid" 2>/dev/null || true
        fi
    done <"$CAPTURE_MAP_FILE"
    count=0
    while ((count < 50)); do
        local any=0
        while IFS='|' read -r pid part entity; do
            kill -0 "$pid" 2>/dev/null && any=1
        done <"$CAPTURE_MAP_FILE"
        ((any == 0)) && break
        sleep 0.1
        ((count += 1))
    done
    while IFS='|' read -r pid part entity; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
        [[ -s $part ]] && parts+=("$part")
    done <"$CAPTURE_MAP_FILE"

    [[ -f $CAPTURE_PATH_FILE ]] || die "falta el destino de la captura"
    output=$(<"$CAPTURE_PATH_FILE")
    if ((${#parts[@]} == 1)); then
        mv -- "${parts[0]}" "$output"
    elif ((${#parts[@]} > 1)); then
        mergecap -F pcap -w "$output" "${parts[@]}"
        rm -f -- "${parts[@]}"
    else
        die "ningún proceso de captura produjo datos"
    fi
    rm -f -- "$CAPTURE_MAP_FILE" "$STATE_DIR"/tcpdump-*.log
    info "captura finalizada: $output"
}

capture_start() {
    local output=${1:-} parent pid capture_name capture_filter index=0 part record
    local -a filter_parts
    require_root
    require_command tcpdump
    read_router_namespace
    [[ ! -f $CAPTURE_MAP_FILE ]] || die "ya existe una captura activa para $LAB_ID"
    ((${#CAPTURE_POINTS[@]} == 1)) || require_command mergecap

    if [[ -z $output ]]; then
        output=${CAPTURE_DIR:-captures}/$LAB_ID-$(date +%Y%m%d-%H%M%S).pcap
    fi
    if [[ $output != /* ]]; then
        output=$MANIFEST_DIR/$output
    fi
    parent=${output%/*}
    mkdir -p -- "$parent"
    [[ ! -e $output ]] || die "el fichero de captura ya existe: $output"
    : >"$CAPTURE_MAP_FILE"
    printf '%s\n' "$output" >"$CAPTURE_PATH_FILE"
    for record in "${CAPTURE_POINTS[@]}"; do
        IFS='|' read -r capture_name capture_filter <<<"$record"
        map_row_for "$capture_name"
        read -r -a filter_parts <<<"$capture_filter"
        part=$STATE_DIR/capture-$index.pcap
        ip netns exec "$ROUTER_NS" tcpdump --immediate-mode -B 4096 -i "$MAP_RIF" \
            -s 0 -nn -U -w "$part" "${filter_parts[@]}" \
            >"$STATE_DIR/tcpdump-$index.log" 2>&1 &
        pid=$!
        printf '%s|%s|%s\n' "$pid" "$part" "$capture_name" >>"$CAPTURE_MAP_FILE"
        ((index += 1))
    done
    sleep 0.25
    while IFS='|' read -r pid part capture_name; do
        kill -0 "$pid" 2>/dev/null || {
            cat "$STATE_DIR"/tcpdump-*.log >&2 || true
            capture_stop_internal || true
            die "tcpdump no pudo iniciar en el enlace de $capture_name"
        }
    done <"$CAPTURE_MAP_FILE"
    info "capturando ${#CAPTURE_POINTS[@]} punto(s) de red; destino final: $output"
}

show_status() {
    local name role ns rif router_ip entity_ip primary ips kind
    if [[ ! -f $ROUTER_FILE ]]; then
        printf 'Laboratorio %s: no creado\n' "$LAB_ID"
        return 0
    fi
    read_router_namespace
    printf 'Laboratorio: %s\nRouter:      %s\n' "$LAB_ID" "$ROUTER_NS"
    printf '%-18s %-16s %-18s %-15s %-9s %s\n' ENTIDAD ROL NAMESPACE VETH TIPO IPS
    while IFS='|' read -r name role ns rif router_ip entity_ip primary ips kind; do
        printf '%-18s %-16s %-18s %-15s %-9s %s\n' \
            "$name" "$role" "$ns" "$rif" "${kind:-internal}" "$ips"
    done <"$MAP_FILE"
    if [[ -f $CAPTURE_MAP_FILE ]]; then
        printf 'Captura:    %s punto(s) -> %s\n' "$(wc -l <"$CAPTURE_MAP_FILE")" "$(<"$CAPTURE_PATH_FILE")"
    else
        printf 'Captura:    inactiva\n'
    fi
}

exec_in_entity() {
    local entity=$1 cwd=
    shift
    require_root
    map_row_for "$entity"
    [[ $MAP_KIND != external ]] ||
        die "no se pueden ejecutar órdenes dentro de la entidad externa $entity"
    if [[ ${1:-} == --cwd ]]; then
        (($# >= 3)) || die "--cwd requiere un directorio y una orden"
        cwd=$2
        shift 2
    fi
    [[ ${1:-} == -- ]] || die "falta -- antes de la orden"
    shift
    (($# > 0)) || die "no se indicó ninguna orden"
    if [[ -n $cwd ]]; then
        exec ip netns exec "$MAP_NS" bash -c 'cd -- "$1"; shift; exec "$@"' _ "$cwd" "$@"
    else
        exec ip netns exec "$MAP_NS" "$@"
    fi
}

main() {
    (($# >= 2)) || { usage >&2; exit 2; }
    local manifest=$1 command=$2
    shift 2
    load_manifest "$manifest"
    validate_manifest

    case "$command" in
        check)
            (($# == 0)) || die "check no acepta argumentos"
            info "manifiesto válido: $LAB_ID (${#ENTITY_ORDER[@]} entidades, ${#SERVICES[@]} servicios)"
            ;;
        create)
            (($# == 0)) || die "create no acepta argumentos"
            create_topology
            ;;
        status)
            (($# == 0)) || die "status no acepta argumentos"
            show_status
            ;;
        exec)
            (($# >= 3)) || die "uso: exec <entidad> [--cwd DIR] -- ORDEN"
            exec_in_entity "$@"
            ;;
        capture-start)
            (($# <= 1)) || die "capture-start acepta como máximo un fichero"
            capture_start "${1:-}"
            ;;
        capture-stop)
            (($# == 0)) || die "capture-stop no acepta argumentos"
            require_root
            capture_stop_internal
            ;;
        destroy)
            (($# == 0)) || die "destroy no acepta argumentos"
            require_root
            require_command ip
            destroy_internal
            info "topología $LAB_ID retirada"
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            usage >&2
            die "orden desconocida: $command"
            ;;
    esac
}

shopt -s extglob
main "$@"

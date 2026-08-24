#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
LABNET=$ROOT/tools/labnet.sh
MANIFEST=$ROOT/android-labs/dresscode/topology.conf
TEST_STATE_ROOT=$(mktemp -d /run/tfg-labnet-test.XXXXXX)
TEST_PCAP=$(mktemp /tmp/tfg-labnet-external.XXXXXX.pcap)
rm -f -- "$TEST_PCAP"
export LABNET_STATE_ROOT=$TEST_STATE_ROOT
server_pid=
sim_namespace=tfg-win-sim-$$
sim_host_if=tw$$
sim_peer_if=te$$

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ ${server_pid:-} =~ ^[0-9]+$ ]] && kill -0 "$server_pid" 2>/dev/null; then
        kill -TERM "$server_pid" 2>/dev/null || true
    fi
    if [[ $sim_namespace == tfg-win-sim-* ]]; then
        ip netns del "$sim_namespace" 2>/dev/null || true
    fi
    if [[ $sim_host_if =~ ^tw[0-9]+$ ]]; then
        ip link del "$sim_host_if" 2>/dev/null || true
    fi
    bash "$LABNET" "$MANIFEST" destroy >/dev/null 2>&1 || true
    if [[ $TEST_PCAP == /tmp/tfg-labnet-external.*.pcap ]]; then
        rm -f -- "$TEST_PCAP"
    fi
    if [[ $TEST_STATE_ROOT == /run/tfg-labnet-test.* ]]; then
        rmdir -- "$TEST_STATE_ROOT" 2>/dev/null || true
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

((EUID == 0)) || { printf 'test_external_topology.sh requiere root.\n' >&2; exit 1; }
for command in ip iptables python3 tcpdump; do
    command -v "$command" >/dev/null 2>&1 || { printf 'Falta %s.\n' "$command" >&2; exit 1; }
done

bash "$LABNET" "$MANIFEST" create
ip netns add "$sim_namespace"
ip link add "$sim_host_if" type veth peer name "$sim_peer_if"
ip link set "$sim_peer_if" netns "$sim_namespace"
ip addr add 10.253.30.1/30 dev "$sim_host_if"
ip link set "$sim_host_if" up
ip -n "$sim_namespace" addr add 10.253.30.2/30 dev "$sim_peer_if"
ip -n "$sim_namespace" link set lo up
ip -n "$sim_namespace" link set "$sim_peer_if" up
ip -n "$sim_namespace" route add 138.201.195.77/32 via 10.253.30.1 dev "$sim_peer_if"

bash "$LABNET" "$MANIFEST" exec c2 -- python3 -c '
import socket

with socket.socket() as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("138.201.195.77", 9001))
    server.listen(1)
    connection, _ = server.accept()
    with connection:
        connection.sendall(b"OK:" + connection.recv(32))
' &
server_pid=$!

for _ in {1..50}; do
    if bash "$LABNET" "$MANIFEST" exec c2 -- ss -H -ltn 'sport = :9001' |
        grep -Fq '138.201.195.77:9001'; then
        break
    fi
    sleep 0.1
done
kill -0 "$server_pid"

bash "$LABNET" "$MANIFEST" capture-start "$TEST_PCAP"
response=$(ip netns exec "$sim_namespace" python3 -c '
import socket

with socket.create_connection(("138.201.195.77", 9001), timeout=3) as client:
    client.sendall(b"external-path")
    print(client.recv(32).decode("ascii"))
')
[[ $response == OK:external-path ]]
wait "$server_pid"
server_pid=
bash "$LABNET" "$MANIFEST" capture-stop
tcpdump -nn -r "$TEST_PCAP" 2>/dev/null | grep -Fq '138.201.195.77.9001'

printf 'Topología externa y captura verificadas.\n'

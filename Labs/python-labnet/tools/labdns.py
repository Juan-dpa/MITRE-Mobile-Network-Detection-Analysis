#!/usr/bin/env python3
"""Servidor DNS autoritativo mínimo para los laboratorios aislados.

Solo responde registros A declarados de forma explícita. Implementa UDP y TCP
sin recurrir a resolutores del sistema ni reenviar consultas a Internet.
"""

from __future__ import annotations

import argparse
import ipaddress
import signal
import socket
import socketserver
import struct
import threading
from dataclasses import dataclass


def decode_name(packet: bytes, offset: int = 12) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("nombre DNS truncado")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("la consulta no puede comprimir QNAME")
        if length > 63 or offset + length > len(packet):
            raise ValueError("etiqueta DNS no válida")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length
    return ".".join(labels).lower().rstrip("."), offset


def build_response(packet: bytes, records: dict[str, str], ttl: int) -> bytes:
    if len(packet) < 12:
        raise ValueError("cabecera DNS truncada")
    transaction, flags, qdcount, _, _, _ = struct.unpack(">HHHHHH", packet[:12])
    if qdcount != 1 or flags & 0x8000:
        raise ValueError("se esperaba una consulta DNS con una pregunta")
    name, end = decode_name(packet)
    if end + 4 > len(packet):
        raise ValueError("pregunta DNS truncada")
    qtype, qclass = struct.unpack(">HH", packet[end : end + 4])
    question = packet[12 : end + 4]
    ip = records.get(name) if qtype == 1 and qclass == 1 else None
    rcode = 0 if ip else 3
    response_flags = 0x8000 | 0x0400 | (flags & 0x0100) | rcode
    answer_count = 1 if ip else 0
    header = struct.pack(">HHHHHH", transaction, response_flags, 1, answer_count, 0, 0)
    if not ip:
        return header + question
    answer = (
        b"\xc0\x0c"
        + struct.pack(">HHIH", 1, 1, ttl, 4)
        + ipaddress.IPv4Address(ip).packed
    )
    return header + question + answer


@dataclass(frozen=True)
class DnsState:
    records: dict[str, str]
    ttl: int


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet, sock = self.request
        try:
            response = build_response(packet, self.server.state.records, self.server.state.ttl)
        except (ValueError, UnicodeError):
            return
        sock.sendto(response, self.client_address)


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        header = self.request.recv(2)
        if len(header) != 2:
            return
        length = struct.unpack(">H", header)[0]
        packet = b""
        while len(packet) < length:
            chunk = self.request.recv(length - len(packet))
            if not chunk:
                return
            packet += chunk
        try:
            response = build_response(packet, self.server.state.records, self.server.state.ttl)
        except (ValueError, UnicodeError):
            return
        self.request.sendall(struct.pack(">H", len(response)) + response)


class ThreadingUdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadingTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_record(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("el registro debe usar nombre=IPv4")
    name, raw_ip = value.split("=", 1)
    name = name.lower().rstrip(".")
    if not name or any(not label for label in name.split(".")):
        raise argparse.ArgumentTypeError("nombre DNS no válido")
    try:
        ip = str(ipaddress.IPv4Address(raw_ip))
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if ipaddress.IPv4Address(ip).is_loopback:
        raise argparse.ArgumentTypeError("no se admiten respuestas de loopback")
    return name, ip


def main() -> int:
    parser = argparse.ArgumentParser(description="DNS A autoritativo para TFG-LAB")
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--ttl", type=int, default=60)
    parser.add_argument("--record", action="append", type=parse_record, required=True)
    args = parser.parse_args()
    records = dict(args.record)
    state = DnsState(records=records, ttl=args.ttl)
    udp = ThreadingUdpServer((args.bind, args.port), UdpHandler)
    tcp = ThreadingTcpServer((args.bind, args.port), TcpHandler)
    udp.state = state
    tcp.state = state
    threads = [
        threading.Thread(target=udp.serve_forever, name="dns-udp", daemon=True),
        threading.Thread(target=tcp.serve_forever, name="dns-tcp", daemon=True),
    ]
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    for thread in threads:
        thread.start()
    print(f"[DNS] {args.bind}:{args.port} UDP/TCP; {len(records)} registros", flush=True)
    for name, ip in sorted(records.items()):
        print(f"[DNS] A {name} -> {ip}", flush=True)
    try:
        stop.wait()
    finally:
        udp.shutdown()
        tcp.shutdown()
        udp.server_close()
        tcp.server_close()
        for thread in threads:
            thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

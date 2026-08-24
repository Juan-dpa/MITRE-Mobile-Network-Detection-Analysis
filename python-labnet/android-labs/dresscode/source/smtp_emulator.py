#!/usr/bin/env python3
"""Small SMTP service emulator for the proxy-through-victim lab.

The vulnerable mode emulates the known CVE-2020-7247 condition documented for
OpenSMTPD: shell metacharacters reaching MAIL FROM address handling. It records
a benign marker only; it never executes operating-system commands.
"""

from __future__ import annotations

import argparse
import socket
import threading
from datetime import datetime


CVE_2020_7247_QUALYS_LOCAL_POC = "MAIL FROM:<;sleep 66;>"
SHELL_METACHARS = {";", "|", "&", "`"}


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(msg: str) -> None:
    print(f"[{ts()}] [SMTP] {msg}", flush=True)


def send_line(conn: socket.socket, line: str) -> None:
    payload = line.encode("ascii") + b"\r\n"
    conn.sendall(payload)
    log(f"TX {payload!r}")


def recv_line(conn: socket.socket) -> bytes | None:
    data = bytearray()
    while True:
        b = conn.recv(1)
        if not b:
            return bytes(data) if data else None
        data += b
        if data.endswith(b"\n"):
            return bytes(data)


def has_opensmtpd_cve_2020_7247_shape(command: str) -> bool:
    upper = command.upper()
    if not upper.startswith("MAIL FROM:"):
        return False
    if command == CVE_2020_7247_QUALYS_LOCAL_POC:
        return True
    return any(char in command for char in SHELL_METACHARS) or "$(" in command


def handle_client(conn: socket.socket, peer: tuple[str, int], banner_name: str) -> None:
    log(f"connection from {peer[0]}:{peer[1]}")
    cve_2020_7247_seen = False
    in_data = False
    data_lines: list[str] = []
    with conn:
        send_line(conn, f"220 {banner_name} ESMTP LabSMTP-1.0")
        while True:
            line = recv_line(conn)
            if line is None:
                log("client closed connection")
                return
            log(f"RX {line!r}")
            command = line.decode("ascii", errors="replace").strip()
            if in_data:
                if command == ".":
                    in_data = False
                    log(f"DATA body received with {len(data_lines)} line(s)")
                    data_lines.clear()
                    if cve_2020_7247_seen:
                        send_line(conn, "250 CVE-2020-7247 simulated exploitation recorded")
                    else:
                        send_line(conn, "250 Message accepted for lab delivery")
                else:
                    data_lines.append(command)
                continue

            verb = command.split(" ", 1)[0].upper()
            if verb in {"EHLO", "HELO"}:
                send_line(conn, f"250-{banner_name}")
                send_line(conn, "250-VRFY")
                send_line(conn, "250 HELP")
            elif verb == "VRFY":
                target = command.split(" ", 1)[1] if " " in command else "unknown"
                send_line(conn, f"252 Cannot VRFY user, but will accept message for {target}")
            elif verb == "MAIL":
                if has_opensmtpd_cve_2020_7247_shape(command):
                    cve_2020_7247_seen = True
                    if command == CVE_2020_7247_QUALYS_LOCAL_POC:
                        log("[CVE-2020-7247] Qualys/Openwall PoC signature reached: MAIL FROM:<;sleep 66;>")
                    else:
                        log("[CVE-2020-7247] OpenSMTPD MAIL FROM shell metacharacter condition reached")
                    log("[EXPLOIT-SIMULATED] Remote service exploitation reached through victim proxy")
                    send_line(conn, "250 CVE-2020-7247 lab marker accepted")
                    continue
                send_line(conn, "250 OK")
            elif verb == "RCPT":
                send_line(conn, "250 OK")
            elif verb == "DATA":
                in_data = True
                data_lines.clear()
                send_line(conn, "354 End data with <CR><LF>.<CR><LF>")
            elif verb == "QUIT":
                send_line(conn, "221 Bye")
                return
            elif verb == "HELP":
                send_line(conn, "214 Lab SMTP emulator")
            else:
                send_line(conn, "500 Command not recognized in lab emulator")


def main() -> None:
    parser = argparse.ArgumentParser(description="SMTP service emulator")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--banner-name", default="vulnerable-smtp.lab")
    parser.add_argument("--accept-timeout", type=float, default=0.5, help="listener timeout for Ctrl+C handling")
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.bind, args.port))
        srv.listen(20)
        srv.settimeout(args.accept_timeout)
        log(f"listening on {args.bind}:{args.port}")
        try:
            while True:
                try:
                    conn, peer = srv.accept()
                except socket.timeout:
                    continue
                thread = threading.Thread(target=handle_client, args=(conn, peer, args.banner_name), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            log("Ctrl+C received; shutting down")


if __name__ == "__main__":
    main()


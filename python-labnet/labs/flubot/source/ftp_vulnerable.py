from __future__ import annotations

import argparse
import socket
import threading


def log(message: str) -> None:
    print(f"[ftp] {message}", flush=True)


def send_line(conn: socket.socket, line: str) -> None:
    conn.sendall(line.encode("ascii") + b"\r\n")


def recv_line(conn: socket.socket) -> str:
    data = bytearray()
    while not data.endswith(b"\r\n"):
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("ascii", errors="replace").strip()


def send_multiline(conn: socket.socket, lines: list[str]) -> None:
    conn.sendall("\r\n".join(lines).encode("ascii") + b"\r\n")


def handle_site_command(conn: socket.socket, args: str, pending_copy_from: str | None) -> str | None:
    parts = args.split(" ", 1)
    subcommand = parts[0].upper() if parts and parts[0] else ""
    value = parts[1] if len(parts) > 1 else ""

    if subcommand == "HELP":
        send_multiline(
            conn,
            [
                "214-The following SITE commands are recognized:",
                " CPFR <source-path>",
                " CPTO <destination-path>",
                "214 Help OK",
            ],
        )
        return pending_copy_from

    if subcommand == "CPFR":
        if not value:
            send_line(conn, "501 Missing source pathname")
            return pending_copy_from
        log(f"vulnerable SITE CPFR accepted source outside FTP root: {value!r}")
        send_line(conn, "350 File or directory exists, ready for destination name")
        return value

    if subcommand == "CPTO":
        if not value:
            send_line(conn, "501 Missing destination pathname")
            return pending_copy_from
        if pending_copy_from is None:
            send_line(conn, "503 Bad sequence of commands: send SITE CPFR first")
            return pending_copy_from
        log(f"vulnerable SITE CPTO copied {pending_copy_from!r} to {value!r}")
        send_line(conn, f"250 Copy successful: {pending_copy_from} -> {value}")
        return None

    send_line(conn, "502 SITE command not implemented")
    return pending_copy_from


def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    with conn:
        log(f"connection from {addr[0]}:{addr[1]}")
        send_line(conn, "220 vulnerable-python-ftp ready")
        authed = False
        pending_copy_from: str | None = None
        while True:
            line = recv_line(conn)
            if not line:
                return
            log(f"{addr[0]}:{addr[1]} -> {line!r}")
            verb, _, args = line.partition(" ")
            verb = verb.upper()
            if verb == "USER":
                send_line(conn, "331 Anonymous login ok, send password")
            elif verb == "PASS":
                authed = True
                send_line(conn, "230 Login successful")
            elif verb == "SYST":
                send_line(conn, "215 UNIX Type: L8")
            elif verb == "PWD":
                send_line(conn, '257 "/" is the current directory')
            elif verb == "NOOP":
                send_line(conn, "200 NOOP ok")
            elif verb == "FEAT":
                conn.sendall(b"211-Features\r\n UTF8\r\n211 End\r\n")
            elif verb == "QUIT":
                send_line(conn, "221 Goodbye")
                return
            elif not authed:
                send_line(conn, "530 Please login with USER and PASS")
            elif verb == "SITE":
                pending_copy_from = handle_site_command(conn, args, pending_copy_from)
            else:
                send_line(conn, "502 Command not implemented in lab FTP")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tiny vulnerable-style FTP service for SOCKS relay captures")
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2121)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.bind_host, args.port))
        listener.listen(5)
        log(f"listening on {args.bind_host}:{args.port}")
        while True:
            conn, addr = listener.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()

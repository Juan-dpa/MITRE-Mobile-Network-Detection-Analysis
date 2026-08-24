#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import io
import socketserver
import ssl
import subprocess
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

CHECKIN_PATH = "/eddd0317-2bdc-4140-86cb-0e8d7047b874"
DOWNLOAD_PATH = "/56e087c9-fc56-49bb-bbd0-4fafc4acd6e1"
CHECKIN_TOKEN = b"358fde5fe8f91b132636a6d5a7148070"
CERTIFICATE_IP = "54.71.249.137"


def args() -> argparse.Namespace:
    base = Path(__file__).resolve().parent
    p = argparse.ArgumentParser()
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--cert", default=str(base / "certs" / "exodus_sim.crt"))
    p.add_argument("--key", default=str(base / "certs" / "exodus_sim.key"))
    return p.parse_args()


def certificate_is_current(cert: Path, key: Path) -> bool:
    if not cert.is_file() or not key.is_file():
        return False
    try:
        probe = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
            check=True,
            capture_output=True,
            text=True,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
    except (FileNotFoundError, OSError, ssl.SSLError, subprocess.CalledProcessError):
        return False
    identities = [line.strip() for line in probe.stdout.splitlines() if "IP Address:" in line or "DNS:" in line]
    return identities == [f"IP Address:{CERTIFICATE_IP}"]


def ensure_cert(cert: Path, key: Path) -> None:
    if certificate_is_current(cert, key):
        return
    cert.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "3650",
        "-keyout", str(key), "-out", str(cert),
        "-subj", f"/CN={CERTIFICATE_IP}/O=nginx/OU=Exodus Traffic Simulation",
        "-addext", f"subjectAltName=IP:{CERTIFICATE_IP}",
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not certificate_is_current(cert, key):
        raise RuntimeError("El certificado Exodus generado no coincide con la identidad esperada")


def zinfo(name: str, dt: tuple[int, int, int, int, int, int]) -> ZipInfo:
    info = ZipInfo(name, date_time=dt)
    info.compress_type = ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    return info


def nested_zip(label: str) -> bytes:
    buf = io.BytesIO()
    with ZipFile(buf, "w", ZIP_DEFLATED) as zf:
        zf.writestr(zinfo("SIMULATION.txt", (2018, 12, 6, 5, 50, 0)), f"Benign placeholder for {label}\n")
    return buf.getvalue()


def exodus_two_zip() -> bytes:
    entries = [
        ("null_arm", (2018, 2, 27, 6, 44, 0), b"benign null_arm\n"),
        ("null_i686", (2018, 2, 27, 6, 44, 0), b"benign null_i686\n"),
        ("null_arm64", (2018, 2, 27, 6, 43, 0), b"benign null_arm64\n"),
        ("sepolicy-inject_arm", (2019, 1, 8, 4, 55, 0), b"benign sepolicy-inject_arm\n"),
        ("sepolicy-inject_arm64", (2019, 1, 8, 4, 55, 0), b"benign sepolicy-inject_arm64\n"),
        ("sepolicy-inject_i686", (2019, 1, 8, 4, 55, 0), b"benign sepolicy-inject_i686\n"),
        ("rootdaemon_arm", (2019, 1, 8, 4, 55, 0), b"benign rootdaemon_arm\n"),
        ("rootdaemon_arm64", (2019, 1, 8, 4, 55, 0), b"benign rootdaemon_arm64\n"),
        ("mike.jar", (2018, 12, 6, 5, 50, 0), nested_zip("mike.jar")),
        ("rootdaemon_i686", (2019, 1, 8, 4, 55, 0), b"benign rootdaemon_i686\n"),
        ("zygote daemon arm", (2019, 1, 8, 4, 55, 0), b"benign zygote daemon arm\n"),
        ("zygote daemon arm64", (2019, 1, 8, 4, 55, 0), b"benign zygote daemon arm64\n"),
        ("zygote daemon i686", (2019, 1, 8, 4, 55, 0), b"benign zygote daemon i686\n"),
        ("sapp.apk", (2019, 1, 8, 4, 53, 0), nested_zip("sapp.apk")),
        ("placeholder", (2018, 3, 29, 16, 31, 0), b""),
    ]
    buf = io.BytesIO()
    with ZipFile(buf, "w") as zf:
        for name, dt, data in entries:
            zf.writestr(zinfo(name, dt), data)
    return buf.getvalue()


def chunked(data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 96):
        chunk = data[i : i + 96]
        out += f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n"
    return bytes(out) + b"0\r\n\r\n"


def response(body: bytes) -> bytes:
    gz = gzip.compress(body)
    date = format_datetime(datetime.now(timezone.utc), usegmt=True)
    return (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.4.6 (Ubuntu)\r\n"
        f"Date: {date}\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "Content-Encoding: gzip\r\n"
        "\r\n"
    ).encode("ascii") + chunked(gz)


def read_request(rfile) -> tuple[str, dict[str, str], bytes] | None:
    line = rfile.readline(65536)
    if not line:
        return None
    request_line = line.decode("iso-8859-1").strip()
    headers: dict[str, str] = {}
    while True:
        h = rfile.readline(65536)
        if h in (b"\r\n", b"\n", b""):
            break
        text = h.decode("iso-8859-1")
        if ":" in text:
            k, v = text.split(":", 1)
            headers[k.lower()] = v.strip()
    body = rfile.read(int(headers.get("content-length", "0")))
    return request_line, headers, body


class Handler(socketserver.BaseRequestHandler):
    zip_body = exodus_two_zip()

    def handle(self) -> None:
        rfile = self.request.makefile("rb")
        while True:
            parsed = read_request(rfile)
            if parsed is None:
                return
            request_line, headers, body = parsed
            parts = request_line.split()
            method = parts[0] if len(parts) > 0 else ""
            path = parts[1] if len(parts) > 1 else ""
            print(f"[server] {method} {path} ua={headers.get('user-agent', '')!r} len={len(body)}")
            if method == "POST" and path == CHECKIN_PATH:
                self.request.sendall(response(CHECKIN_TOKEN))
            elif method == "POST" and path == DOWNLOAD_PATH:
                self.request.sendall(response(self.zip_body))
            else:
                self.request.sendall(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                return


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def main() -> int:
    a = args()
    cert = Path(a.cert)
    key = Path(a.key)
    ensure_cert(cert, key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    with Server((a.bind, a.port), Handler) as srv:
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        print(f"[server] listening on https://{a.bind}:{a.port}")
        srv.serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())

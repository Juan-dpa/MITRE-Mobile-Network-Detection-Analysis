#!/usr/bin/env python3
"""
Laboratorio de tráfico KeyRaider / MPPlugin.

Este servidor expone dos servicios:
  1. TLS 1.2 para p12-buy.itunes.apple.com, usado como flujo Apple/iTunes histórico.
  2. HTTP claro para www.wushidou.cn, usado como C2 de exfiltración /aid.php.

El objetivo es generar una firma de red reproducible con datos falsos de laboratorio.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import os
import signal
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Dict, Tuple


APPLE_HOST = "p12-buy.itunes.apple.com"
C2_HOST = "www.wushidou.cn"


def log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def generate_self_signed_cert(hostname: str, cert_dir: Path) -> Tuple[Path, Path]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / f"{hostname}.crt.pem"
    key_path = cert_dir / f"{hostname}.key.pem"

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise SystemExit(
            "Falta el módulo 'cryptography'. Instálalo o genera manualmente "
            f"{cert_path} y {key_path}."
        ) from exc

    if cert_path.exists() and key_path.exists():
        try:
            existing_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            existing_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            san = existing_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if (
                set(san.get_values_for_type(x509.DNSName)) == {hostname}
                and existing_cert.public_key().public_numbers()
                == existing_key.public_key().public_numbers()
            ):
                return cert_path, key_path
        except (OSError, ValueError, TypeError, x509.ExtensionNotFound):
            pass

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KeyRaider Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2015, 1, 1, tzinfo=dt.timezone.utc))
        .not_valid_after(dt.datetime(2036, 1, 1, tzinfo=dt.timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log(f"Generado certificado TLS de laboratorio para {hostname}: {cert_path}")
    return cert_path, key_path


def recv_http_message(conn: socket.socket, max_bytes: int = 256_000) -> bytes:
    conn.settimeout(3.0)
    data = b""

    while b"\r\n\r\n" not in data and len(data) < max_bytes:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk

    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return data

    headers_blob = data[:header_end].decode("iso-8859-1", errors="replace")
    content_length = 0
    for line in headers_blob.split("\r\n")[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() == "content-length":
            try:
                content_length = int(value.strip())
            except ValueError:
                content_length = 0
            break

    expected = header_end + 4 + content_length
    while len(data) < expected and len(data) < max_bytes:
        chunk = conn.recv(min(4096, expected - len(data)))
        if not chunk:
            break
        data += chunk

    return data


def parse_http_request(data: bytes) -> Tuple[str, Dict[str, str], bytes]:
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return "", {}, b""

    header_text = data[:header_end].decode("iso-8859-1", errors="replace")
    lines = header_text.split("\r\n")
    request_line = lines[0] if lines else ""
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return request_line, headers, data[header_end + 4 :]


def build_c2_response(mode: str) -> bytes:
    body = b"OK"

    if mode == "chunked":
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"2\r\n"
            b"OK\r\n"
            b"0\r\n"
            b"\r\n"
        )

    if mode == "gzip":
        gz_body = gzip.compress(body)
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Encoding: gzip\r\n"
            + f"Content-Length: {len(gz_body)}\r\n".encode("ascii")
            + b"\r\n"
            + gz_body
        )

    return (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )


def build_apple_response_body() -> bytes:
    return (
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        b"<plist version=\"1.0\"><dict>"
        b"<key>status</key><string>ok</string>"
        b"<key>dsPersonId</key><string>225000001</string>"
        b"</dict></plist>\n"
    )


def close_tls_gracefully(tls: ssl.SSLSocket, timeout: float = 2.0) -> bool:
    """Intercambia close_notify antes de cerrar el socket TCP subyacente."""
    try:
        tls.settimeout(timeout)
        raw = tls.unwrap()
    except (OSError, ssl.SSLError):
        tls.close()
        return False
    raw.close()
    return True


def handle_apple_tls(conn: socket.socket, addr, context: ssl.SSLContext, expected_host: str) -> None:
    tls: ssl.SSLSocket | None = None
    try:
        tls = context.wrap_socket(conn, server_side=True)
        log(f"TLS Apple aceptado desde {addr[0]}:{addr[1]} version={tls.version()} cipher={tls.cipher()}")
        data = recv_http_message(tls, max_bytes=64_000)
        request_line, headers, body = parse_http_request(data)
        log(f"TLS Apple app-data: {request_line!r} host={headers.get('host')!r} body_len={len(body)}")
        if headers.get("host") != expected_host:
            log(f"AVISO: Host interno TLS distinto al esperado: {headers.get('host')!r}")
        required_fields = (b"<key>appleId</key>", b"<key>password</key>", b"<key>guid</key>")
        if not body.startswith(b"<?xml") or not all(field in body for field in required_fields):
            log("AVISO: la autenticación Apple no contiene la plist XML esperada")

        response_body = build_apple_response_body()
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/xml\r\n"
            + f"Content-Length: {len(response_body)}\r\n".encode("ascii")
            + b"\r\n"
            + response_body
        )
        tls.sendall(response)
    except ssl.SSLError as exc:
        log(f"TLS Apple error SSL desde {addr}: {exc}")
    except OSError as exc:
        log(f"TLS Apple error socket desde {addr}: {exc}")
    finally:
        if tls is not None:
            if not close_tls_gracefully(tls):
                log(f"AVISO: cierre TLS Apple incompleto desde {addr}")
        else:
            conn.close()


def serve_apple_tls(args, stop_event: threading.Event) -> None:
    cert_path, key_path = generate_self_signed_cert(args.apple_host, Path(args.cert_dir))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    try:
        context.set_ciphers(
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "AES128-SHA:"
            "AES256-SHA"
        )
    except ssl.SSLError as exc:
        log(f"No se pudieron fijar todos los ciphers TLS 1.2 solicitados: {exc}")

    def sni_cb(ssl_sock: ssl.SSLSocket, server_name: str | None, _ctx: ssl.SSLContext) -> None:
        log(f"TLS ClientHello SNI={server_name!r}")
        if server_name != args.apple_host:
            log(f"AVISO: SNI distinto al esperado ({args.apple_host})")

    context.set_servername_callback(sni_cb)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.bind_host, args.tls_port))
        srv.listen(16)
        srv.settimeout(0.5)
        log(f"Servidor TLS Apple escuchando en {args.bind_host}:{args.tls_port} para {args.apple_host}")

        while not stop_event.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(
                target=handle_apple_tls,
                args=(conn, addr, context, args.apple_host),
                daemon=True,
            )
            thread.start()


def handle_c2_http(conn: socket.socket, addr, args) -> None:
    try:
        with conn:
            data = recv_http_message(conn)
            request_line, headers, body = parse_http_request(data)
            log(f"C2 HTTP desde {addr[0]}:{addr[1]}: {request_line!r}")
            log(f"C2 Host={headers.get('host')!r} Content-Type={headers.get('content-type')!r} body={body.decode('utf-8', errors='replace')!r}")

            if request_line != "POST /aid.php HTTP/1.1":
                log("AVISO: request-line C2 no coincide con MPPlugin")
            if headers.get("host") != args.c2_host:
                log(f"AVISO: Host C2 distinto al esperado: {headers.get('host')!r}")
            if headers.get("content-type") != "application/x-www-form-urlencoded":
                log(f"AVISO: Content-Type C2 distinto al esperado: {headers.get('content-type')!r}")

            conn.sendall(build_c2_response(args.c2_response))
    except OSError as exc:
        log(f"C2 HTTP error desde {addr}: {exc}")


def serve_c2_http(args, stop_event: threading.Event) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.bind_host, args.c2_port))
        srv.listen(16)
        srv.settimeout(0.5)
        log(f"Servidor C2 HTTP escuchando en {args.bind_host}:{args.c2_port} para {args.c2_host}")

        while not stop_event.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(target=handle_c2_http, args=(conn, addr, args), daemon=True)
            thread.start()


def parse_args():
    parser = argparse.ArgumentParser(description="Servidor de laboratorio KeyRaider/MPPlugin")
    parser.add_argument(
        "--role",
        choices=("apple", "c2", "both"),
        default="both",
        help="Servicio que debe ejecutar este proceso",
    )
    parser.add_argument("--bind-host", default="0.0.0.0", help="IP local de escucha")
    parser.add_argument("--apple-host", default=APPLE_HOST)
    parser.add_argument("--c2-host", default=C2_HOST)
    parser.add_argument("--tls-port", type=int, default=443, help="Puerto TLS Apple histórico")
    parser.add_argument("--c2-port", type=int, default=80, help="Puerto HTTP C2")
    parser.add_argument("--cert-dir", default=str(Path(__file__).with_name("certs")))
    parser.add_argument(
        "--c2-response",
        choices=("content-length", "chunked", "gzip"),
        default="content-length",
        help="Formato de respuesta C2 aceptado por Http::send()",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    stop_event = threading.Event()

    def request_stop(_signum=None, _frame=None):
        log("Parada solicitada, cerrando servidores...")
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    threads = []
    if args.role in ("apple", "both"):
        threads.append(
            threading.Thread(target=serve_apple_tls, args=(args, stop_event), daemon=True)
        )
    if args.role in ("c2", "both"):
        threads.append(
            threading.Thread(target=serve_c2_http, args=(args, stop_event), daemon=True)
        )

    for thread in threads:
        thread.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.2)
    except KeyboardInterrupt:
        request_stop()

    for thread in threads:
        thread.join(timeout=1.5)

    log("Servidor detenido.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

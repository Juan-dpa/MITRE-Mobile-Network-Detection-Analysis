#!/usr/bin/env python3
"""Sumidero HTTP de Golden Cup y generador de un contenedor .data inerte."""

from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import zlib
import zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from Crypto.Cipher import AES


ENC_MOD = 573


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def build_zip(out_dex: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("out.dex", out_dex)
    return buffer.getvalue()


def encrypt_zip_to_data(zip_bytes: bytes) -> bytes:
    key = os.urandom(32)
    encrypted = AES.new(key, AES.MODE_ECB).encrypt(pkcs7_pad(zip_bytes))
    insert_at = len(encrypted) % ENC_MOD
    return encrypted[:insert_at] + key + encrypted[insert_at:]


def load_dex(path: str | None) -> bytes:
    if path:
        return Path(path).read_bytes()
    return (
        b"inert GoldenCup lab placeholder named out.dex\n"
        b"This is not a functional Android dex.\n"
    )


def write_metadata(path: str, artifact_url: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(artifact_url + "\n", encoding="utf-8")
    temporary.replace(destination)


class GoldenCupHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.54"

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length else b""

    def _log(self, body: bytes) -> None:
        print("\n" + "=" * 72)
        print(datetime.now().isoformat(timespec="seconds"))
        print(f"{self.client_address[0]}:{self.client_address[1]}")
        print(f"{self.command} {self.path} {self.request_version}")
        for key, value in self.headers.items():
            print(f"{key}: {value}")
        print(body.decode("utf-8", errors="replace") if body else "<empty>")
        print("=" * 72, flush=True)

    def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle_op_php(self, body: bytes) -> None:
        form = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        operation = (form.get("op") or [""])[0]
        if operation in {"A", "B", "F"}:
            response = b"true"
        elif operation == "D":
            response = b"0"
        elif operation in {"E", "CCC"}:
            response = b"OK"
        else:
            response = b"OK"
        print(f"[op.php] op={operation!r} response={response!r}", flush=True)
        self._send_bytes(200, response, "text/plain; charset=utf-8")

    def _handle_artifact(self) -> None:
        if not self.path.split("?", 1)[0].endswith("/" + self.server.artifact_name):
            self._send_bytes(404, b"artifact not found\n", "text/plain; charset=utf-8")
            return
        data = self.server.artifact_data
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header(
            "Content-Disposition", f'attachment; filename="{self.server.artifact_name}"'
        )
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        print(
            f"[artifact] served {self.server.artifact_name} ({len(data)} bytes)",
            flush=True,
        )

    def do_GET(self) -> None:  # noqa: N802 - API de BaseHTTPRequestHandler
        body = self._read_body()
        self._log(body)
        if self.path.split("?", 1)[0].startswith("/payloads/"):
            self._handle_artifact()
        else:
            self._send_bytes(200, b"OK", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802 - API de BaseHTTPRequestHandler
        body = self._read_body()
        self._log(body)
        if self.path.split("?", 1)[0] == "/apps/d/p/op.php":
            self._handle_op_php(body)
        else:
            self._send_bytes(200, b"OK", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802 - API de BaseHTTPRequestHandler
        self.do_GET()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--domain", default="www.goldncup.com")
    parser.add_argument("--dex")
    parser.add_argument("--data")
    parser.add_argument("--metadata-file", required=True)
    args = parser.parse_args()

    if args.data:
        artifact_data = Path(args.data).read_bytes()
        artifact_name = Path(args.data).name
        if not artifact_name.endswith(".data"):
            raise SystemExit("--data filename must end in .data")
    else:
        zip_bytes = build_zip(load_dex(args.dex))
        checksum = zlib.adler32(zip_bytes) & 0xFFFFFFFF
        artifact_name = f"stage_{checksum}.data"
        artifact_data = encrypt_zip_to_data(zip_bytes)

    artifact_url = f"http://{args.domain}/payloads/{artifact_name}"
    server = ThreadingHTTPServer((args.host, args.port), GoldenCupHandler)
    server.artifact_name = artifact_name
    server.artifact_data = artifact_data
    write_metadata(args.metadata_file, artifact_url)

    print(f"GoldenCup HTTP sinkhole listening on {args.host}:{args.port}")
    print(f"Artifact URL: {artifact_url}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

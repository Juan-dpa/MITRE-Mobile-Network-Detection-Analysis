#!/usr/bin/env python3
"""Servicios controlados para el flujo de red de Red Alert 2.0."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
from urllib.parse import urlsplit


ANDROID_HASH = "jfkbl6fm02mfk0rcuva0i4vgoxyej2z8tvlr01jq"
TIME_TEXT = "2024-01-02T03:04:05+00:00"
TWITTER_ID = hashlib.md5((TIME_TEXT + ANDROID_HASH).encode()).hexdigest()[:15]
TWEET_TEXT = "192.168 56.20"
BOT_ID = "BOT_ID_LAB"
TARGET_PACKAGE = "com.android.smoketest"
MAIN_SELECTOR = "SELECTOR_PRINCIPAL_LAB"
TECH_SELECTOR = "SELECTOR_TECNICO_LAB"


def read_body(handler: BaseHTTPRequestHandler) -> bytes:
    length = int(handler.headers.get("Content-Length", "0") or 0)
    return handler.rfile.read(length) if length else b""


def decode_json(body: bytes) -> dict[str, object] | None:
    try:
        value = json.loads(base64.b64decode(body, validate=False).decode("utf-8"))
        return value if isinstance(value, dict) else None
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RedAlertLab/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(
            f"[{self.server.role}] {self.client_address[0]} "
            f"{fmt % args}",
            flush=True,
        )

    def send_payload(
        self,
        status: int,
        payload: str | bytes,
        content_type: str = "text/plain; charset=utf-8",
    ) -> None:
        body = payload.encode("utf-8") if isinstance(payload, str) else payload
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        print(
            f"[{self.server.role}] GET {self.path} Host={self.headers.get('Host')}",
            flush=True,
        )
        if self.server.role == "timeapi":
            if self.path != "/utc/now?%5CD":
                self.send_payload(404, "Not Found")
                return
            self.send_payload(
                200,
                f"<html><body>{html.escape(TIME_TEXT)}</body></html>",
                "text/html; charset=utf-8",
            )
            return
        if self.server.role == "twitter":
            if urlsplit(self.path).path != f"/{TWITTER_ID}":
                self.send_payload(404, "Not Found")
                return
            self.send_payload(
                200,
                f'<html><body><p class="tweet-text">{TWEET_TEXT}</p></body></html>',
                "text/html; charset=utf-8",
            )
            return
        self.send_payload(405, "Method Not Allowed")

    def do_POST(self) -> None:  # noqa: N802
        body = read_body(self)
        route = urlsplit(self.path).path
        print(
            f"[{self.server.role}] POST {route} Host={self.headers.get('Host')} "
            f"bytes={len(body)} body={body.decode('ascii', errors='replace')}",
            flush=True,
        )
        if self.server.role != "c2":
            self.send_payload(405, "Method Not Allowed")
            return
        if route == "/ping":
            self.send_payload(200, "OK")
            return
        if route == "/gt":
            selector = body.decode("ascii", errors="replace")
            if selector == MAIN_SELECTOR:
                template = Path(__file__).with_name("templates") / "principal.html"
            elif selector == TECH_SELECTOR:
                template = Path(__file__).with_name("templates") / "technical.html"
            else:
                self.send_payload(404, "Unknown selector")
                return
            payload = "".join(template.read_text(encoding="utf-8").splitlines())
            self.send_payload(200, payload, "text/html; charset=utf-8")
            return

        decoded = decode_json(body)
        if decoded is not None:
            print(
                f"[c2] decoded {route}: "
                f"{json.dumps(decoded, ensure_ascii=False, separators=(',', ':'))}",
                flush=True,
            )
        if route == "/stbi":
            self.send_payload(200, BOT_ID)
        elif route == "/sban":
            catalog = {
                TARGET_PACKAGE: MAIN_SELECTOR,
                TARGET_PACKAGE + "2": TECH_SELECTOR,
            }
            self.send_payload(
                200,
                json.dumps(catalog, separators=(",", ":")),
                "application/json; charset=utf-8",
            )
        elif route in {"/sy", "/ssl", "/ucs", "/std", "/ss", "/scal", "/scol"}:
            self.send_payload(200, "OK")
        else:
            self.send_payload(404, "Not Found")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("timeapi", "twitter", "c2"))
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--certificate")
    parser.add_argument("--private-key")
    parser.add_argument("--keylog-file")
    args = parser.parse_args()

    server = Server((args.host, args.port), Handler)
    server.role = args.role
    if args.role == "twitter":
        if not args.certificate or not args.private_key:
            parser.error("twitter requiere --certificate y --private-key")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            context.set_ciphers("DEFAULT")
        context.load_cert_chain(args.certificate, args.private_key)
        if args.keylog_file:
            keylog = Path(args.keylog_file)
            keylog.parent.mkdir(parents=True, exist_ok=True)
            context.keylog_filename = str(keylog)
        server.socket = context.wrap_socket(server.socket, server_side=True)

    print(
        f"[{args.role}] escucha en {args.host}:{args.port}; "
        f"twitter-id={TWITTER_ID}; c2=http://192.168.56.20:8060",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

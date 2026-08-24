from __future__ import annotations

import argparse
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from servers.common.config import ensure_runtime_directories, lab_path, load_config, runtime_log_path
from servers.common.events import EventLog
from servers.twitter.cjk_codec import encode


class TwitterLabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: dict[str, Any], event_log: EventLog):
        super().__init__(address, TwitterHandler)
        self.config = config
        self.event_log = event_log


class TwitterHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def lab_server(self) -> TwitterLabServer:
        return self.server  # type: ignore[return-value]

    def do_GET(self) -> None:
        account = self.path.split("?", 1)[0].strip("/")
        twitter = self.lab_server.config["twitter"]
        values = {
            twitter["c2_account"]: twitter["c2_value"],
            twitter["webview_account"]: twitter["webview_value"],
        }
        if account not in values:
            self.lab_server.event_log.emit(
                "unknown_account",
                client=self.client_address,
                path=self.path,
                host=self.headers.get("Host"),
            )
            self._respond(404, b"not found", "text/plain; charset=utf-8")
            return
        clear_value = values[account]
        encoded_value = encode(clear_value, low_bits=0)
        html = (
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            f"<title>abcd{encoded_value} </title>"
            "</head><body></body></html>"
        ).encode("utf-8")
        self.lab_server.event_log.emit(
            "resolver_response",
            client=self.client_address,
            account=account,
            decoded_value=clear_value,
            encoded_codepoints=[f"U+{ord(item):04X}" for item in encoded_value],
            user_agent=self.headers.get("User-Agent"),
        )
        self._respond(200, html, "text/html; charset=utf-8")

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response_only(status)
        self.send_header("Date", self.date_time_string())
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        return


def make_tls_context(config: dict[str, Any], *, reset_keylog: bool = True) -> ssl.SSLContext:
    twitter = config["twitter"]
    certificate = lab_path(twitter["certificate"])
    private_key = lab_path(twitter["private_key"])
    keylog = Path(os.environ.get("XLOADER_TLS_KEYLOG", str(lab_path(twitter["tls_keylog"]))))
    keylog.parent.mkdir(parents=True, exist_ok=True)
    if reset_keylog:
        keylog.write_text("", encoding="ascii")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA:@SECLEVEL=1"
    )
    context.load_cert_chain(certificate, private_key)
    context.keylog_filename = str(keylog)
    return context


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Servidor HTTPS que emula las cuentas de Twitter usadas por XLoader")
    parser.add_argument("--keep-keylog", action="store_true", help="No vaciar captures/tls-keys.log al arrancar")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config()
    ensure_runtime_directories(config)
    host = config["network"]["twitter_host"]
    port = int(config["network"]["twitter_https_port"])
    event_log = EventLog(runtime_log_path("twitter.jsonl"), "twitter")
    server = TwitterLabServer((host, port), config, event_log)
    server.socket = make_tls_context(config, reset_keylog=not args.keep_keylog).wrap_socket(
        server.socket,
        server_side=True,
    )
    event_log.emit(
        "listening",
        host=host,
        port=port,
        certificate=config["twitter"]["certificate"],
        tls="TLSv1.2",
        keylog=config["twitter"]["tls_keylog"],
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        event_log.emit("stopping")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

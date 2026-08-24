from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from servers.common.config import ensure_runtime_directories, load_config, runtime_log_path
from servers.common.events import EventLog


WEBVIEW_BODY = b"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Contenido controlado del laboratorio</title>
</head>
<body>
  <h1>Contenido controlado del laboratorio</h1>
  <p>Esta pagina no representa ninguna entidad bancaria y no carga recursos externos.</p>
</body>
</html>
"""


class LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: dict[str, Any], event_log: EventLog, role: str):
        super().__init__(address, LabHTTPHandler)
        self.config = config
        self.event_log = event_log
        self.role = role


class LabHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Apache/2.4.7"
    sys_version = "(Ubuntu)"

    @property
    def lab_server(self) -> LabHTTPServer:
        return self.server  # type: ignore[return-value]

    def do_GET(self) -> None:
        host_header = self.headers.get("Host", "")
        host = host_header.partition(":")[0].lower()
        headers = {key: value for key, value in self.headers.items()}
        if self.lab_server.role == "webview" and host == "webview.lab":
            self._handle_webview(headers)
            return
        if self.lab_server.role == "vulnerable-target" and host == "vuln.lab":
            self._handle_vulnerable_target(headers)
            return
        self.lab_server.event_log.emit(
            "unknown_virtual_host",
            client=self.client_address,
            host=host_header,
            path=self.path,
            headers=headers,
        )
        self._respond(421, b"unknown virtual host", "text/plain; charset=utf-8")

    def _handle_webview(self, headers: dict[str, str]) -> None:
        if self.path.split("?", 1)[0] == "/favicon.ico":
            self.lab_server.event_log.emit("webview_favicon", client=self.client_address)
            self._respond(204, b"", "image/x-icon")
            return
        self.lab_server.event_log.emit(
            "webview_request",
            client=self.client_address,
            method="GET",
            path=self.path,
            headers=headers,
        )
        self._respond(
            200,
            WEBVIEW_BODY,
            "text/html; charset=utf-8",
            extra_headers={
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
                "X-Content-Type-Options": "nosniff",
            },
        )

    def _handle_vulnerable_target(self, headers: dict[str, str]) -> None:
        scenario = self.lab_server.config["scenario"]
        expected_path = scenario["shellshock_url"].split("vuln.lab", 1)[1]
        actual_path = self.path.split("?", 1)[0]
        actual_user_agent = self.headers.get("User-Agent", "")
        recognized = actual_path == expected_path and actual_user_agent == scenario["shellshock_user_agent"]
        self.lab_server.event_log.emit(
            "shellshock_request",
            client=self.client_address,
            method="GET",
            path=self.path,
            headers=headers,
            recognized=recognized,
            command_executed=False,
        )
        if not recognized:
            self._respond(400, b"signature not recognized", "text/plain; charset=utf-8")
            return
        body = scenario["shellshock_body"].encode("ascii")
        self._respond(200, body, "text/plain; charset=us-ascii")

    def _respond(
        self,
        status: int,
        body: bytes,
        content_type: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Servicio HTTP controlado para XLoader")
    parser.add_argument("--role", required=True, choices=("webview", "vulnerable-target"))
    args = parser.parse_args()
    config = load_config()
    ensure_runtime_directories(config)
    host_key = "webview_host" if args.role == "webview" else "vulnerable_target_host"
    host = config["network"][host_key]
    port = int(config["network"]["http_port"])
    event_log = EventLog(runtime_log_path(f"{args.role}.jsonl"), args.role)
    server = LabHTTPServer((host, port), config, event_log, args.role)
    event_log.emit(
        "listening",
        host=host,
        port=port,
        virtual_hosts=["webview.lab"] if args.role == "webview" else ["vuln.lab"],
        command_execution=False,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        event_log.emit("stopping")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

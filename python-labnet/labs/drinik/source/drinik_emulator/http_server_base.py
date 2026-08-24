from __future__ import annotations

import ssl
import threading
from http.server import ThreadingHTTPServer
from typing import Type

from .logging_utils import log
from .tls_material import close_tls_gracefully


class GracefulTlsThreadingHTTPServer(ThreadingHTTPServer):
    def shutdown_request(self, request) -> None:
        if isinstance(request, ssl.SSLSocket):
            close_tls_gracefully(request)
            return
        super().shutdown_request(request)


class ManagedHttpServer:
    def __init__(
        self,
        *,
        name: str,
        ip: str,
        port: int,
        handler_cls: Type,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        self.name = name
        self.ip = ip
        self.port = port
        self.httpd = GracefulTlsThreadingHTTPServer((ip, port), handler_cls)
        self.httpd.daemon_threads = True
        if tls_context is not None:
            self.httpd.socket = tls_context.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, name=name, daemon=True)

    def start(self) -> None:
        log(self.name, f"listening on {self.ip}:{self.port}")
        self.thread.start()

    def stop(self) -> None:
        log(self.name, "stopping")
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2.0)

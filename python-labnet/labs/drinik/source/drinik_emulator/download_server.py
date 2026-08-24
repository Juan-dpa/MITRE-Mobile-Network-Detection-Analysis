from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler

from .config import LabConfig
from .http_server_base import ManagedHttpServer
from .logging_utils import log


APK_BYTES = (
    b"PK\x03\x04"
    b"DRINIK-LAB-AApk.apk"
    + b"\x00" * 512
    + b"AndroidManifest.xml"
    + b"\x00" * 512
)


@dataclass
class DownloadState:
    config: LabConfig


class DownloadHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.22.1"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        state: DownloadState = self.server.state
        log("download", f"GET {self.path} host={self.headers.get('Host', '')}")
        if self.path != state.config.download_path:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.android.package-archive")
        self.send_header("Content-Length", str(len(APK_BYTES)))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()
        self.wfile.write(APK_BYTES)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class DownloadServer:
    def __init__(self, config: LabConfig) -> None:
        self.server = ManagedHttpServer(
            name="download",
            ip=config.download.ip,
            port=config.download.port,
            handler_cls=DownloadHandler,
        )
        self.server.httpd.state = DownloadState(config=config)

    def start(self) -> None:
        self.server.start()

    def stop(self) -> None:
        self.server.stop()

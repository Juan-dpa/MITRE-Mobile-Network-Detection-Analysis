from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Mapping

from .tls_material import close_tls_gracefully


@dataclass
class HttpResponse:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def send_http_request(
    *,
    ip: str,
    port: int,
    host: str,
    method: str,
    path: str,
    headers: Mapping[str, str] | None = None,
    body: bytes = b"",
    timeout: float = 8.0,
    tls: bool = False,
    tls_context: ssl.SSLContext | None = None,
) -> HttpResponse:
    request_headers = {
        "Host": host,
        "Content-Length": str(len(body)),
        "Connection": "close",
    }
    if headers:
        request_headers.update(headers)

    head = [f"{method} {path} HTTP/1.1"]
    head.extend(f"{key}: {value}" for key, value in request_headers.items())
    raw = ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body

    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        conn: socket.socket | ssl.SSLSocket
        if tls:
            if tls_context is None:
                raise ValueError("tls_context is required when tls=True")
            conn = tls_context.wrap_socket(sock, server_hostname=host)
        else:
            conn = sock
        try:
            conn.sendall(raw)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = conn.recv(65536)
                except TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            if isinstance(conn, ssl.SSLSocket):
                close_tls_gracefully(conn)
            else:
                conn.close()

    response = b"".join(chunks)
    header_blob, _, body_blob = response.partition(b"\r\n\r\n")
    header_lines = header_blob.decode("iso-8859-1", errors="replace").split("\r\n")
    status_line = header_lines[0] if header_lines else "HTTP/1.1 0"
    parts = status_line.split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    reason = parts[2] if len(parts) > 2 else ""
    parsed_headers: dict[str, str] = {}
    for line in header_lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            parsed_headers[key.strip().lower()] = value.strip()
    return HttpResponse(status=status, reason=reason, headers=parsed_headers, body=body_blob)

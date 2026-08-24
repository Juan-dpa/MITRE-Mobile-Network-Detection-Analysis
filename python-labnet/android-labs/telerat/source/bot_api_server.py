#!/usr/bin/env python3
"""Emulación determinista de la API de bots consumida por TeleRAT.

Expone HTTP en el puerto 80 y HTTPS/TLS 1.0 en el 443. Solo implementa las
peticiones necesarias para la secuencia documentada de T1481.002.
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CERT_DIR = ROOT / "certs"
DEFAULT_LOG_FILE = ROOT / "logs" / "bot-api.jsonl"

INSTALL_MESSAGE_ID = 5001
KEYBOARD_MESSAGE_ID = 5002
RESULT_MESSAGE_ID = 5003


def compact_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class RequestJournal:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, entry: dict[str, Any]) -> None:
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self.lock:
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line)


class TeleRATHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        transport: str,
        operator_url: str,
        journal: RequestJournal,
    ) -> None:
        super().__init__(address, TeleRATHandler)
        self.transport = transport
        self.operator_url = operator_url.rstrip("/")
        self.journal = journal


class TeleRATHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: TeleRATHTTPServer

    def log_message(self, format_string: str, *args: Any) -> None:
        print(
            f"[api-{self.server.transport}] {self.client_address[0]} "
            f"{format_string % args}",
            flush=True,
        )

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def _record_request(self, body: bytes) -> None:
        tls_details: dict[str, Any] | None = None
        if isinstance(self.connection, ssl.SSLSocket):
            negotiated_cipher = self.connection.cipher()
            tls_details = {
                "version": self.connection.version(),
                "cipher": negotiated_cipher[0] if negotiated_cipher else None,
                "session_reused": self.connection.session_reused,
            }
        self.server.journal.append(
            {
                "time": time.time(),
                "peer": {"ip": self.client_address[0], "port": self.client_address[1]},
                "transport": self.server.transport,
                "method": self.command,
                "target": self.path,
                "request_version": self.request_version,
                "headers": list(self.headers.items()),
                "body_utf8": body.decode("utf-8", errors="replace"),
                "body_hex": body.hex(),
                "tls": tls_details,
            }
        )

    def _send_json(
        self,
        value: Any,
        status: HTTPStatus = HTTPStatus.OK,
        close: bool = False,
    ) -> None:
        payload = compact_json(value)
        self.send_response_only(status.value, status.phrase)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close" if close else "keep-alive")
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()
        if close:
            self.close_connection = True

    def _reject(self, reason: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
        print(f"[api-{self.server.transport}] Rechazo: {reason}", flush=True)
        self._send_json({"ok": False, "error": reason}, status=status, close=True)

    def _operator_request(
        self, method: str, endpoint: str, value: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        data = compact_json(value) if value is not None else None
        request = Request(
            self.server.operator_url + endpoint,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if data is not None else {},
        )
        try:
            with urlopen(request, timeout=2.0) as response:
                decoded = json.loads(response.read().decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise ValueError("Respuesta del operador no válida")
                return decoded
        except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(f"Operador no disponible: {exc}") from exc

    def _notify_operator(self, kind: str, query: dict[str, list[str]]) -> None:
        event = {
            "kind": kind,
            "transport": self.server.transport,
            "method": self.command,
            "request_target": self.path,
            "chat_id": query.get("chat_id", [None])[0],
            "text": query.get("text", [None])[0],
            "has_reply_markup": "reply_markup" in query,
        }
        try:
            self._operator_request("POST", "/event", event)
        except RuntimeError as exc:
            print(f"[api-{self.server.transport}] Aviso: {exc}", flush=True)

    def _validate_form_headers(self) -> str | None:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            return f"Content-Type inesperado: {content_type!r}"
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        if host != "api.telegram.org":
            return f"Host inesperado: {host!r}"
        return None

    def do_POST(self) -> None:  # noqa: N802 - nombre definido por http.server
        body = self._read_body()
        self._record_request(body)
        parsed = urlsplit(self.path)
        route = parsed.path.lower()
        query = parse_qs(parsed.query, keep_blank_values=True, encoding="utf-8")

        header_error = self._validate_form_headers()
        if header_error:
            self._reject(header_error)
            return

        if route.endswith("/getupdates"):
            if self.server.transport != "https":
                self._reject("getUpdates debe recibirse mediante HTTPS")
                return
            if body != b"amir":
                self._reject(f"Cuerpo de getUpdates inesperado: {body!r}")
                return
            try:
                updates = self._operator_request("GET", "/updates")
            except RuntimeError as exc:
                self._reject(str(exc), HTTPStatus.BAD_GATEWAY)
                return
            self._send_json(updates, close=False)
            return

        if route.endswith("/sendmessage") and self.server.transport == "http":
            if body != b"":
                self._reject(f"El informe de instalación debe tener cuerpo vacío: {body!r}")
                return
            if "chat_id" not in query or "text" not in query or "reply_markup" in query:
                self._reject("Consulta del informe de instalación inesperada")
                return
            response = {"ok": True, "result": {"message_id": INSTALL_MESSAGE_ID}}
            self._send_json(response, close=True)
            self._notify_operator("install_report", query)
            return

        if route.endswith("/sendmessage") and self.server.transport == "https":
            if body != b"amir":
                self._reject(f"Cuerpo del teclado inesperado: {body!r}")
                return
            required = {"chat_id", "text", "reply_markup"}
            if not required.issubset(query):
                self._reject("Faltan parámetros del mensaje con teclado")
                return
            response = {"ok": True, "result": {"message_id": KEYBOARD_MESSAGE_ID}}
            self._send_json(response, close=False)
            self._notify_operator("keyboard", query)
            return

        self._reject("Ruta POST no implementada", HTTPStatus.NOT_FOUND)

    def do_GET(self) -> None:  # noqa: N802 - nombre definido por http.server
        body = b""
        self._record_request(body)
        parsed = urlsplit(self.path)
        route = parsed.path.lower()
        query = parse_qs(parsed.query, keep_blank_values=True, encoding="utf-8")

        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        if host != "api.telegram.org":
            self._reject(f"Host inesperado: {host!r}")
            return
        if self.server.transport != "http" or not route.endswith("/sendmessage"):
            self._reject("El resultado debe ser un GET mediante HTTP", HTTPStatus.NOT_FOUND)
            return
        if "chat_id" not in query or "text" not in query:
            self._reject("Faltan chat_id o text en el resultado")
            return

        status_text = query["text"][0]
        response = {
            "ok": True,
            "result": {"message_id": RESULT_MESSAGE_ID, "text": status_text},
        }
        self._send_json(response, close=True)
        self._notify_operator("result", query)


def tls_context(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Android API 19 soporta TLS 1.2, pero el SSLSocket cliente no lo habilita
    # de forma predeterminada. Se fuerza el perfil que realmente negociará la
    # muestra en ese sistema: TLS 1.0 con RSA y AES-128-CBC/SHA-1.
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.maximum_version = ssl.TLSVersion.TLSv1
    context.set_ciphers("AES128-SHA:@SECLEVEL=0")
    context.options |= ssl.OP_NO_COMPRESSION
    if hasattr(ssl, "OP_NO_TICKET"):
        context.options |= ssl.OP_NO_TICKET
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    return context


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--https-port", type=int, default=443)
    parser.add_argument("--operator-url", default="http://127.0.0.1:9000")
    parser.add_argument("--cert-dir", type=Path, default=DEFAULT_CERT_DIR)
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    return parser.parse_args()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    args = parse_args()
    cert_file = args.cert_dir / "api.telegram.org.cert.pem"
    key_file = args.cert_dir / "api.telegram.org.key.pem"
    if not cert_file.exists() or not key_file.exists():
        raise SystemExit(
            "No se encuentran el certificado y la clave incluidos en el laboratorio."
        )

    journal = RequestJournal(args.log_file)
    http_server = TeleRATHTTPServer(
        (args.bind, args.http_port), "http", args.operator_url, journal
    )
    https_server = TeleRATHTTPServer(
        (args.bind, args.https_port), "https", args.operator_url, journal
    )
    https_server.socket = tls_context(cert_file, key_file).wrap_socket(
        https_server.socket, server_side=True
    )

    servers = [http_server, https_server]
    threads = [
        threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.25},
            name=f"telerat-{server.transport}",
            daemon=True,
        )
        for server in servers
    ]
    for thread in threads:
        thread.start()

    print(
        f"[api] HTTP en {args.bind}:{args.http_port}; "
        f"HTTPS/TLS 1.0 en {args.bind}:{args.https_port}",
        flush=True,
    )
    print(f"[api] Operador: {args.operator_url}", flush=True)
    print(f"[api] Registro: {args.log_file}", flush=True)
    try:
        while all(thread.is_alive() for thread in threads):
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\n[api] Ctrl+C recibido; cerrando ambos servidores...", flush=True)
    finally:
        for server in servers:
            server.shutdown()
        for server in servers:
            server.server_close()
        for thread in threads:
            thread.join(timeout=2.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


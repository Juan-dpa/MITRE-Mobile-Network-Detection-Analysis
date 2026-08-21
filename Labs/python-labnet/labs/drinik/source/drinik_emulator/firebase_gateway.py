from __future__ import annotations

import json
import queue
import socketserver
import ssl
import threading
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler

from .config import LabConfig
from .http_server_base import ManagedHttpServer
from .logging_utils import log


@dataclass
class PushClient:
    token: str
    messages: "queue.Queue[str]" = field(default_factory=queue.Queue)


class PushHub:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: list[PushClient] = []

    def register(self, token: str) -> PushClient:
        client = PushClient(token=token)
        with self._lock:
            self._clients.append(client)
        log("mtalk", f"registered TLS push client token={token}")
        return client

    def unregister(self, client: PushClient) -> None:
        with self._lock:
            if client in self._clients:
                self._clients.remove(client)
        log("mtalk", f"unregistered TLS push client token={client.token}")

    def publish(self, token: str, cmd: str) -> int:
        delivered = 0
        payload = json.dumps({"data": {"CMD": cmd}}, separators=(",", ":"))
        with self._lock:
            clients = list(self._clients)
        for client in clients:
            if client.token == token:
                client.messages.put(payload)
                delivered += 1
        return delivered


@dataclass
class FirebaseState:
    config: LabConfig
    push_hub: PushHub
    token: str = "fcm-token-drinik-lab-001"
    fid: str = "f.drnk-lab-fid-001"
    refresh_token: str = "refresh-token-drinik-lab"
    auth_token: str = "fis-auth-token-drinik-lab"


class FirebaseApiHandler(BaseHTTPRequestHandler):
    server_version = "Google Frontend"
    sys_version = ""

    def do_POST(self) -> None:  # noqa: N802
        state: FirebaseState = self.server.state
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length)
        host = self.headers.get("Host", "")
        log("firebase", f"POST host={host} path={self.path} len={length}")

        if self.path == state.config.fcm_installations_path:
            self._send_json(
                200,
                {
                    "name": f"projects/{state.config.project_id}/installations/{state.fid}",
                    "fid": state.fid,
                    "refreshToken": state.refresh_token,
                    "authToken": {
                        "token": state.auth_token,
                        "expiresIn": "604800s",
                    },
                },
            )
            return

        if self.path == state.config.fcm_register_path:
            fields = urllib.parse.parse_qs(raw_body.decode("utf-8", errors="replace"))
            log(
                "firebase",
                "register3 "
                f"scope={_first(fields, 'scope')} sender={_first(fields, 'sender')} appid={_first(fields, 'appid')}",
            )
            self._send_text(200, f"registration_id={state.token}")
            return

        if self.path == state.config.fcm_send_path:
            try:
                request = json.loads(raw_body.decode("utf-8"))
                message = request.get("message", {})
                token = message.get("token", "")
                cmd = message.get("data", {}).get("CMD", "")
            except Exception:
                token = ""
                cmd = ""
            delivered = state.push_hub.publish(token, cmd)
            log("firebase", f"messages:send token={token} delivered={delivered} CMD={cmd}")
            self._send_json(
                200,
                {
                    "name": f"projects/{state.config.project_id}/messages/drinik-lab-message-001",
                },
            )
            return

        self._send_text(404, "not found")

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send_json(self, status: int, obj: dict) -> None:
        payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class MtalkHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: MtalkServer = self.server
        conn = server.ssl_context.wrap_socket(self.request, server_side=True)
        conn.settimeout(0.5)
        client: PushClient | None = None
        try:
            hello = _recv_line(conn).decode("utf-8", errors="replace").strip()
            token = "unknown"
            if hello.startswith("FCM_CONNECT "):
                parts = dict(item.split("=", 1) for item in hello[len("FCM_CONNECT ") :].split(" ") if "=" in item)
                token = parts.get("token", token)
            client = server.push_hub.register(token)
            conn.sendall(b"FCM_CONNECTED\n")
            while not server.stop_event.is_set():
                try:
                    payload = client.messages.get(timeout=0.2)
                except queue.Empty:
                    continue
                log("mtalk", f"TLS push data.CMD to victim: {payload}")
                conn.sendall(payload.encode("utf-8") + b"\n")
        except Exception as exc:
            log("mtalk", f"client closed: {exc}")
        finally:
            if client is not None:
                server.push_hub.unregister(client)
            try:
                conn.close()
            except Exception:
                pass


class ThreadingMtalkServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class MtalkServer(ThreadingMtalkServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        ssl_context: ssl.SSLContext,
        push_hub: PushHub,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(server_address, MtalkHandler)
        self.ssl_context = ssl_context
        self.push_hub = push_hub
        self.stop_event = stop_event


class FirebaseGateway:
    def __init__(
        self,
        config: LabConfig,
        server_tls_context: ssl.SSLContext,
        stop_event: threading.Event,
    ) -> None:
        self.config = config
        self.push_hub = PushHub()
        self.state = FirebaseState(config=config, push_hub=self.push_hub)
        self.api_server = ManagedHttpServer(
            name="firebase",
            ip=config.firebase_api.ip,
            port=config.firebase_api.port,
            handler_cls=FirebaseApiHandler,
            tls_context=server_tls_context,
        )
        self.api_server.httpd.state = self.state
        self.mtalk_server = MtalkServer(
            (config.mtalk.ip, config.mtalk.port),
            server_tls_context,
            self.push_hub,
            stop_event,
        )
        self.mtalk_thread = threading.Thread(
            target=self.mtalk_server.serve_forever,
            name="mtalk",
            daemon=True,
        )

    def start(self) -> None:
        self.api_server.start()
        log("mtalk", f"listening on {self.config.mtalk.ip}:{self.config.mtalk.port}")
        self.mtalk_thread.start()

    def stop(self) -> None:
        self.api_server.stop()
        log("mtalk", "stopping")
        self.mtalk_server.shutdown()
        self.mtalk_server.server_close()
        self.mtalk_thread.join(timeout=2.0)


def _first(fields: dict[str, list[str]], key: str) -> str:
    values = fields.get(key, [""])
    return values[0] if values else ""


def _recv_line(conn: ssl.SSLSocket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = conn.recv(1)
        if not chunk:
            break
        chunks.append(chunk)
        if chunk == b"\n":
            break
    return b"".join(chunks)


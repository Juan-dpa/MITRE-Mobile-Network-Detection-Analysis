import io
import ipaddress
import socket
import struct
import zipfile
from typing import Callable, Optional


CRLF = b"\r\n"


def send_line(sock: socket.socket, line: str, trace: Optional[Callable[[str], None]] = None) -> None:
    if trace:
        trace(line)
    sock.sendall(line.encode("utf-8") + CRLF)


def recv_line(sock: socket.socket) -> str:
    data = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            if not data:
                return ""
            break
        data.extend(chunk)
        if chunk == b"\n":
            break
    return data.rstrip(b"\r\n").decode("utf-8", errors="replace")


def recv_until_closed(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def parse_ftp_code(line: str) -> int:
    if len(line) < 3 or not line[:3].isdigit():
        raise ValueError(f"Invalid FTP response: {line!r}")
    return int(line[:3])


def expect_ftp_range(line: str, low: int, high: int) -> None:
    code = parse_ftp_code(line)
    if not (low <= code < high):
        raise RuntimeError(f"Unexpected FTP response {line!r}; expected {low}xx")


def parse_pasv_response(line: str) -> tuple[str, int]:
    start = line.index("(") + 1
    end = line.index(")", start)
    parts = line[start:end].split(",")
    if len(parts) != 6:
        raise ValueError(f"Invalid PASV tuple: {line!r}")
    host = ".".join(parts[:4])
    port = (int(parts[4]) << 8) + int(parts[5])
    return host, port


def make_update_apk_bytes(package_name: str) -> bytes:
    buf = io.BytesIO()
    fixed_time = (2020, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        manifest = zipfile.ZipInfo("AndroidManifest.xml", fixed_time)
        manifest.external_attr = 0o644 << 16
        zf.writestr(manifest, f'<manifest package="{package_name}" />\n'.encode("utf-8"))

        dex = zipfile.ZipInfo("classes.dex", fixed_time)
        dex.external_attr = 0o644 << 16
        zf.writestr(dex, b"dex\n035\x00BusyGasper lab update payload\n")
    return buf.getvalue()


def is_zip_payload(payload: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
            return bool(zf.namelist())
    except zipfile.BadZipFile:
        return False


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def resolve_a_record(
    name: str,
    dns_server: str,
    dns_port: int,
    timeout: float,
    trace: Optional[Callable[[str], None]] = None,
) -> str:
    txid = 0xB655
    query = _build_dns_query(name, txid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        if trace:
            trace(f"[V -> DNS] A {name}")
        sock.sendto(query, (dns_server, dns_port))
        response, addr = sock.recvfrom(4096)
        ip = _parse_dns_a_response(response, txid)
        if trace:
            trace(f"[DNS -> V] {name} A {ip} from {addr[0]}:{addr[1]}")
        return ip


def _build_dns_query(name: str, txid: int) -> bytes:
    labels = name.rstrip(".").split(".")
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack("!HH", 1, 1)
    return header + question


def _parse_dns_a_response(data: bytes, txid: int) -> str:
    if len(data) < 12:
        raise ValueError("DNS response too short")
    rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rid != txid:
        raise ValueError("DNS transaction id mismatch")
    if flags & 0x000F:
        raise ValueError(f"DNS returned rcode {flags & 0x000F}")
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(data, offset)
        offset += 4
    for _ in range(ancount):
        offset = _skip_dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("Truncated DNS answer")
        rtype, rclass, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and rclass == 1 and rdlength == 4:
            return socket.inet_ntoa(rdata)
    raise ValueError("DNS response did not contain an A record")


def _skip_dns_name(data: bytes, offset: int) -> int:
    while True:
        if offset >= len(data):
            raise ValueError("Truncated DNS name")
        length = data[offset]
        offset += 1
        if length == 0:
            return offset
        if length & 0xC0 == 0xC0:
            if offset >= len(data):
                raise ValueError("Truncated DNS compression pointer")
            return offset + 1
        offset += length

from __future__ import annotations

import hashlib
import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Iterable


class ProtocolError(ValueError):
    pass


@dataclass
class Packet:
    tag: str
    data: bytes = b""
    children: list["Packet"] = field(default_factory=list)

    def pack(self) -> bytes:
        tag_bytes = self.tag.encode("ascii")
        if len(tag_bytes) > 0x7F:
            raise ProtocolError("Packet tags are limited to 127 bytes")
        if self.children and self.data:
            raise ProtocolError("A packet cannot contain children and raw data")

        tag_info = len(tag_bytes) | (0x80 if self.children else 0)
        body = b"".join(child.pack() for child in self.children) if self.children else self.data
        total_size = 5 + len(tag_bytes) + len(body)
        return struct.pack("<I", total_size) + bytes([tag_info]) + tag_bytes + body

    def get(self, tag: str) -> "Packet | None":
        return next((child for child in self.children if child.tag == tag), None)

    def require(self, tag: str) -> "Packet":
        result = self.get(tag)
        if result is None:
            raise ProtocolError(f"{self.tag} is missing child {tag}")
        return result

    def as_byte(self) -> int:
        if len(self.data) != 1:
            raise ProtocolError(f"{self.tag} is not a byte")
        return self.data[0]

    def as_word(self) -> int:
        if len(self.data) != 2:
            raise ProtocolError(f"{self.tag} is not a little-endian word")
        return struct.unpack("<H", self.data)[0]

    def as_dword(self) -> int:
        if len(self.data) != 4:
            raise ProtocolError(f"{self.tag} is not a little-endian dword")
        return struct.unpack("<I", self.data)[0]

    def as_int64(self) -> int:
        if len(self.data) != 8:
            raise ProtocolError(f"{self.tag} is not a little-endian int64")
        return struct.unpack("<Q", self.data)[0]

    def as_port(self) -> int:
        if len(self.data) != 2:
            raise ProtocolError(f"{self.tag} is not a network-order port")
        return struct.unpack(">H", self.data)[0]

    def as_ip(self) -> str:
        if len(self.data) != 4:
            raise ProtocolError(f"{self.tag} is not an IPv4 address")
        return str(ipaddress.IPv4Address(self.data))

    def as_string(self) -> str:
        return self.data.decode("utf-8")

    def digest(self) -> bytes:
        return hashlib.sha1(self.pack()).digest()

    def pretty(self, indent: int = 0) -> str:
        prefix = "  " * indent
        if self.children:
            lines = [f"{prefix}{self.tag}"]
            lines.extend(child.pretty(indent + 1) for child in self.children)
            return "\n".join(lines)
        rendered = self.data.hex(" ")
        if self.data and all(32 <= value < 127 for value in self.data):
            rendered += f" ({self.data.decode('ascii')!r})"
        return f"{prefix}{self.tag}: {rendered}"


def container(tag: str, *children: Packet) -> Packet:
    return Packet(tag=tag, children=list(children))


def raw(tag: str, data: bytes = b"") -> Packet:
    return Packet(tag=tag, data=data)


def word(tag: str, value: int) -> Packet:
    return raw(tag, struct.pack("<H", value))


def dword(tag: str, value: int) -> Packet:
    return raw(tag, struct.pack("<I", value))


def int64(tag: str, value: int) -> Packet:
    return raw(tag, struct.pack("<Q", value))


def port(tag: str, value: int) -> Packet:
    return raw(tag, struct.pack(">H", value))


def ipv4(tag: str, value: str) -> Packet:
    return raw(tag, ipaddress.IPv4Address(value).packed)


def text(tag: str, value: str) -> Packet:
    return raw(tag, value.encode("utf-8"))


def _parse_one(view: memoryview, offset: int = 0) -> tuple[Packet, int]:
    if len(view) - offset < 5:
        raise ProtocolError("Incomplete packet header")

    total_size = struct.unpack_from("<I", view, offset)[0]
    if total_size < 5 or offset + total_size > len(view):
        raise ProtocolError("Incomplete or invalid packet length")

    tag_info = view[offset + 4]
    tag_size = tag_info & 0x7F
    has_children = bool(tag_info & 0x80)
    body_start = offset + 5 + tag_size
    end = offset + total_size
    if body_start > end:
        raise ProtocolError("Tag extends beyond packet boundary")

    tag = bytes(view[offset + 5 : body_start]).decode("ascii")
    if not has_children:
        return Packet(tag=tag, data=bytes(view[body_start:end])), total_size

    children: list[Packet] = []
    cursor = body_start
    while cursor < end:
        child, consumed = _parse_one(view[cursor:end], 0)
        children.append(child)
        cursor += consumed
    if cursor != end:
        raise ProtocolError("Child packet boundaries do not match container length")
    return Packet(tag=tag, children=children), total_size


class PacketStream:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[Packet]:
        self.buffer.extend(data)
        packets: list[Packet] = []
        while True:
            if len(self.buffer) < 5:
                break
            total_size = struct.unpack_from("<I", self.buffer, 0)[0]
            if total_size < 5:
                raise ProtocolError(f"Invalid packet length {total_size}")
            if len(self.buffer) < total_size:
                break
            # Parse an immutable snapshot so resizing self.buffer below never
            # conflicts with a live memoryview.
            packet, consumed = _parse_one(memoryview(bytes(self.buffer[:total_size])))
            packets.append(packet)
            del self.buffer[:consumed]
        return packets


def first_matching(packets: Iterable[Packet], tag: str) -> Packet | None:
    return next((packet for packet in packets if packet.tag == tag), None)

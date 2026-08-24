"""Tramas RFC 6455 usadas por XLoader directamente sobre TCP, sin handshake HTTP."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass


OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA
MAX_FRAME_SIZE = 64 * 1024 * 1024


class FrameError(ConnectionError):
    pass


@dataclass(frozen=True)
class Frame:
    fin: bool
    opcode: int
    masked: bool
    payload: bytes


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        block = sock.recv(length - len(chunks))
        if not block:
            raise EOFError("El extremo cerró la conexión")
        chunks.extend(block)
    return bytes(chunks)


def read_frame(sock: socket.socket, *, require_mask: bool = True) -> Frame:
    first, second = _recv_exact(sock, 2)
    fin = bool(first & 0x80)
    rsv = first & 0x70
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if rsv:
        raise FrameError("La muestra envió bits RSV sin extensión negociada")
    if require_mask and not masked:
        raise FrameError("Una trama de cliente RFC 6455 debe estar enmascarada")
    if length == 126:
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _recv_exact(sock, 8))[0]
        if length & (1 << 63):
            raise FrameError("Longitud RFC 6455 inválida")
    if length > MAX_FRAME_SIZE:
        raise FrameError(f"Trama mayor que el límite del laboratorio: {length}")
    if opcode >= 0x8 and (not fin or length > 125):
        raise FrameError("Trama de control RFC 6455 inválida")
    mask = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length)
    if masked:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return Frame(fin=fin, opcode=opcode, masked=masked, payload=payload)


def build_frame(payload: bytes, *, opcode: int = OP_BINARY, fin: bool = True, mask: bytes | None = None) -> bytes:
    if opcode >= 0x8 and (not fin or len(payload) > 125):
        raise FrameError("Trama de control RFC 6455 inválida")
    first = (0x80 if fin else 0) | opcode
    masked = mask is not None
    if masked and len(mask) != 4:
        raise ValueError("La máscara RFC 6455 debe tener cuatro bytes")
    length = len(payload)
    mask_bit = 0x80 if masked else 0
    if length <= 125:
        header = bytes((first, mask_bit | length))
    elif length <= 0xFFFF:
        header = bytes((first, mask_bit | 126)) + struct.pack(">H", length)
    else:
        header = bytes((first, mask_bit | 127)) + struct.pack(">Q", length)
    if not masked:
        return header + payload
    encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return header + mask + encoded


def send_frame(sock: socket.socket, payload: bytes, *, opcode: int = OP_BINARY, fin: bool = True) -> None:
    sock.sendall(build_frame(payload, opcode=opcode, fin=fin))


class MessageAssembler:
    def __init__(self) -> None:
        self._opcode: int | None = None
        self._parts: list[bytes] = []

    def accept(self, frame: Frame) -> tuple[int, bytes] | None:
        if frame.opcode >= 0x8:
            return frame.opcode, frame.payload
        if frame.opcode in (OP_TEXT, OP_BINARY):
            if self._opcode is not None:
                raise FrameError("Comenzó un mensaje antes de terminar el fragmentado anterior")
            if frame.fin:
                return frame.opcode, frame.payload
            self._opcode = frame.opcode
            self._parts = [frame.payload]
            return None
        if frame.opcode == OP_CONTINUATION:
            if self._opcode is None:
                raise FrameError("Continuación RFC 6455 sin mensaje previo")
            self._parts.append(frame.payload)
            if not frame.fin:
                return None
            opcode = self._opcode
            payload = b"".join(self._parts)
            self._opcode = None
            self._parts = []
            return opcode, payload
        raise FrameError(f"Opcode RFC 6455 desconocido: {frame.opcode}")

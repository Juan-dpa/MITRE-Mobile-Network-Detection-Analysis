"""Subconjunto completo de MessagePack necesario para el RPC de XLoader.

Se implementa localmente para que el laboratorio no dependa de paquetes de PyPI.
Admite nil, booleanos, enteros, flotantes, UTF-8, binarios, arrays y mapas.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any


class MessagePackError(ValueError):
    pass


def pack(value: Any) -> bytes:
    if value is None:
        return b"\xc0"
    if value is False:
        return b"\xc2"
    if value is True:
        return b"\xc3"
    if isinstance(value, int):
        return _pack_int(value)
    if isinstance(value, float):
        return b"\xcb" + struct.pack(">d", value)
    if isinstance(value, str):
        return _pack_text(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _pack_binary(bytes(value))
    if isinstance(value, (list, tuple)):
        return _pack_array(value)
    if isinstance(value, dict):
        return _pack_map(value)
    raise TypeError(f"Tipo no representable en MessagePack: {type(value)!r}")


def _pack_int(value: int) -> bytes:
    if 0 <= value <= 0x7F:
        return bytes((value,))
    if -32 <= value < 0:
        return struct.pack("b", value)
    if 0 <= value <= 0xFF:
        return b"\xcc" + struct.pack(">B", value)
    if 0 <= value <= 0xFFFF:
        return b"\xcd" + struct.pack(">H", value)
    if 0 <= value <= 0xFFFFFFFF:
        return b"\xce" + struct.pack(">I", value)
    if 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xcf" + struct.pack(">Q", value)
    if -0x80 <= value < 0:
        return b"\xd0" + struct.pack(">b", value)
    if -0x8000 <= value < -0x80:
        return b"\xd1" + struct.pack(">h", value)
    if -0x80000000 <= value < -0x8000:
        return b"\xd2" + struct.pack(">i", value)
    if -0x8000000000000000 <= value < -0x80000000:
        return b"\xd3" + struct.pack(">q", value)
    raise OverflowError("El entero no cabe en MessagePack")


def _pack_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    length = len(encoded)
    if length <= 31:
        return bytes((0xA0 | length,)) + encoded
    if length <= 0xFF:
        return b"\xd9" + struct.pack(">B", length) + encoded
    if length <= 0xFFFF:
        return b"\xda" + struct.pack(">H", length) + encoded
    if length <= 0xFFFFFFFF:
        return b"\xdb" + struct.pack(">I", length) + encoded
    raise OverflowError("Cadena demasiado larga para MessagePack")


def _pack_binary(value: bytes) -> bytes:
    length = len(value)
    if length <= 0xFF:
        return b"\xc4" + struct.pack(">B", length) + value
    if length <= 0xFFFF:
        return b"\xc5" + struct.pack(">H", length) + value
    if length <= 0xFFFFFFFF:
        return b"\xc6" + struct.pack(">I", length) + value
    raise OverflowError("Binario demasiado largo para MessagePack")


def _pack_array(value: list[Any] | tuple[Any, ...]) -> bytes:
    length = len(value)
    if length <= 15:
        header = bytes((0x90 | length,))
    elif length <= 0xFFFF:
        header = b"\xdc" + struct.pack(">H", length)
    elif length <= 0xFFFFFFFF:
        header = b"\xdd" + struct.pack(">I", length)
    else:
        raise OverflowError("Array demasiado largo para MessagePack")
    return header + b"".join(pack(item) for item in value)


def _pack_map(value: dict[Any, Any]) -> bytes:
    length = len(value)
    if length <= 15:
        header = bytes((0x80 | length,))
    elif length <= 0xFFFF:
        header = b"\xde" + struct.pack(">H", length)
    elif length <= 0xFFFFFFFF:
        header = b"\xdf" + struct.pack(">I", length)
    else:
        raise OverflowError("Mapa demasiado largo para MessagePack")
    return header + b"".join(pack(key) + pack(item) for key, item in value.items())


@dataclass
class _Reader:
    data: memoryview
    offset: int = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if size < 0 or end > len(self.data):
            raise MessagePackError("Documento MessagePack truncado")
        value = self.data[self.offset:end].tobytes()
        self.offset = end
        return value

    def byte(self) -> int:
        return self.take(1)[0]


def unpack(data: bytes | bytearray | memoryview) -> Any:
    reader = _Reader(memoryview(data))
    value = _unpack_one(reader)
    if reader.offset != len(reader.data):
        raise MessagePackError("Hay bytes adicionales tras el documento MessagePack")
    return value


def _number(reader: _Reader, fmt: str) -> int | float:
    return struct.unpack(fmt, reader.take(struct.calcsize(fmt)))[0]


def _unpack_one(reader: _Reader) -> Any:
    marker = reader.byte()
    if marker <= 0x7F:
        return marker
    if marker >= 0xE0:
        return marker - 0x100
    if 0xA0 <= marker <= 0xBF:
        return reader.take(marker & 0x1F).decode("utf-8")
    if 0x90 <= marker <= 0x9F:
        return [_unpack_one(reader) for _ in range(marker & 0x0F)]
    if 0x80 <= marker <= 0x8F:
        return _unpack_map(reader, marker & 0x0F)
    if marker == 0xC0:
        return None
    if marker == 0xC2:
        return False
    if marker == 0xC3:
        return True
    if marker == 0xC4:
        return reader.take(int(_number(reader, ">B")))
    if marker == 0xC5:
        return reader.take(int(_number(reader, ">H")))
    if marker == 0xC6:
        return reader.take(int(_number(reader, ">I")))
    if marker == 0xCA:
        return _number(reader, ">f")
    if marker == 0xCB:
        return _number(reader, ">d")
    if marker == 0xCC:
        return _number(reader, ">B")
    if marker == 0xCD:
        return _number(reader, ">H")
    if marker == 0xCE:
        return _number(reader, ">I")
    if marker == 0xCF:
        return _number(reader, ">Q")
    if marker == 0xD0:
        return _number(reader, ">b")
    if marker == 0xD1:
        return _number(reader, ">h")
    if marker == 0xD2:
        return _number(reader, ">i")
    if marker == 0xD3:
        return _number(reader, ">q")
    if marker == 0xD9:
        return reader.take(int(_number(reader, ">B"))).decode("utf-8")
    if marker == 0xDA:
        return reader.take(int(_number(reader, ">H"))).decode("utf-8")
    if marker == 0xDB:
        return reader.take(int(_number(reader, ">I"))).decode("utf-8")
    if marker == 0xDC:
        return [_unpack_one(reader) for _ in range(int(_number(reader, ">H")))]
    if marker == 0xDD:
        return [_unpack_one(reader) for _ in range(int(_number(reader, ">I")))]
    if marker == 0xDE:
        return _unpack_map(reader, int(_number(reader, ">H")))
    if marker == 0xDF:
        return _unpack_map(reader, int(_number(reader, ">I")))
    raise MessagePackError(f"Marcador MessagePack no admitido: 0x{marker:02x}")


def _unpack_map(reader: _Reader, length: int) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for _ in range(length):
        # En una asignación con subíndice Python evalúa antes el lado derecho.
        # Se extraen por separado para conservar el orden clave/valor del flujo.
        key = _unpack_one(reader)
        value = _unpack_one(reader)
        result[key] = value
    return result

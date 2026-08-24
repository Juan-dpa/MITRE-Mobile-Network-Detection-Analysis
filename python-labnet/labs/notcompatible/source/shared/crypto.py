from __future__ import annotations

import os
import struct
from pathlib import Path

from Crypto.PublicKey import RSA


class CryptoError(ValueError):
    pass


class RC4:
    """Stateful RC4 matching com.security.patch.RC4."""

    def __init__(self, key: bytes) -> None:
        if not key:
            raise CryptoError("RC4 key cannot be empty")
        self.state = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.state[i] + key[i % len(key)]) & 0xFF
            self.state[i], self.state[j] = self.state[j], self.state[i]
        self.x = 0
        self.y = 0

    def crypt(self, data: bytes) -> bytes:
        result = bytearray(len(data))
        for index, value in enumerate(data):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.y + self.state[self.x]) & 0xFF
            self.state[self.x], self.state[self.y] = (
                self.state[self.y],
                self.state[self.x],
            )
            xor_index = (self.state[self.x] + self.state[self.y]) & 0xFF
            result[index] = value ^ self.state[xor_index]
        return bytes(result)


def modulus_size(key: RSA.RsaKey) -> int:
    return (key.n.bit_length() + 7) // 8


def modulus_bytes(key: RSA.RsaKey) -> bytes:
    return key.n.to_bytes(modulus_size(key), "big")


def raw_public_operation(message: bytes, public_key: RSA.RsaKey) -> bytes:
    size = modulus_size(public_key)
    value = int.from_bytes(message, "big")
    if value >= public_key.n:
        raise CryptoError("Raw RSA message is not smaller than the modulus")
    return pow(value, public_key.e, public_key.n).to_bytes(size, "big")


def raw_private_operation(message: bytes, private_key: RSA.RsaKey) -> bytes:
    if not private_key.has_private():
        raise CryptoError("A private RSA key is required")
    size = modulus_size(private_key)
    value = int.from_bytes(message, "big")
    if value >= private_key.n:
        raise CryptoError("Raw RSA message is not smaller than the modulus")
    return pow(value, private_key.d, private_key.n).to_bytes(size, "big")


def encrypt_session_key(public_key: RSA.RsaKey, rc4_key: bytes) -> bytes:
    if len(rc4_key) != 100:
        raise CryptoError("NotCompatible uses a 100-byte RC4 key")
    # A non-zero marker preserves the 101-byte plaintext after leading-zero stripping.
    return raw_public_operation(b"\x07" + rc4_key, public_key)


def decrypt_session_key(private_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    plaintext = raw_private_operation(ciphertext, private_key).lstrip(b"\x00")
    if len(plaintext) != 101:
        raise CryptoError(f"Expected a 101-byte RSA plaintext, got {len(plaintext)}")
    return plaintext[1:101]


def sign_digest_raw(private_key: RSA.RsaKey, digest: bytes) -> bytes:
    size = modulus_size(private_key)
    if len(digest) >= size:
        raise CryptoError("Digest is too large for the RSA modulus")
    # The malware only checks the trailing digest bytes after a raw public operation.
    block = b"\x01" + b"\x00" * (size - len(digest) - 1) + digest
    return raw_private_operation(block, private_key)


def verify_digest_raw(public_key: RSA.RsaKey, digest: bytes, signature: bytes) -> bool:
    recovered = raw_public_operation(signature, public_key)
    return recovered[-len(digest) :] == digest


def generate_global_keys(private_path: Path, public_path: Path, modulus_path: Path) -> None:
    key = RSA.generate(1024)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(key.export_key("PEM"))
    public_path.write_bytes(key.public_key().export_key("PEM"))
    modulus_path.write_bytes(modulus_bytes(key.public_key()))


def load_key(path: str | Path) -> RSA.RsaKey:
    return RSA.import_key(Path(path).read_bytes())


def new_session_key() -> bytes:
    return os.urandom(100)


def u32le(value: int) -> bytes:
    return struct.pack("<I", value)

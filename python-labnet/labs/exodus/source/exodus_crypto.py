#!/usr/bin/env python3
from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass

XOR_KEY = b"Kjk1MmphFG"

STAGING_KEY_OBFUSCATED = """
BiMicwQHMSYEICAbA1okKkkfdgUKOy53DCw/KwcWcysmeAQvMw8NBAo7LnB1BjcfcyInDANSJyEG
Mh8DZCMZU3opEzgqBT89Cl09LzsfIBR/DgFiL1koEQoPc18cVBwGATIuHjEiU3M8AQgBJS0aHihV
GyQqARQJIyAzSRUEJyoXMWQSH1UjLD5aMXcHMw5JOAAhC3M/e1wAdTc+PAcpCiEGMQQfGQkdCQlg
XxwDZiYdOS8GYC5bQgE4MSxwJQ8BGAB4GVswCh14LS9fLj0xHXQLEiZbWn1UQhAUMS8cO2sANyoq
cD04GwJICz9APX50LDpfcgYgBzkeIBxBXQAUFDoGaXM+EgQeJTglCig2DSsFUCAIMh4uNQkGChoV
DEMACDIuHzhfORgJJCt/JCQ7axhdFQt/KCAwDwIeJiAaNgoyXg4IFSpFCwM0eiQGUxoMKT4hFSME
PFc0RgcKFjZ6BjF3fwEAEi8kBwwoBi4qFRlybBoZBH46QgYuLWwfICFwKTw5LAcWCig=
"""


@dataclass(frozen=True)
class RsaPublicKey:
    modulus: int
    exponent: int

    @property
    def size_bytes(self) -> int:
        return (self.modulus.bit_length() + 7) // 8


def compact(text: str) -> str:
    return "".join(text.split())


def decode_xor_base64(text: str) -> str:
    raw = base64.b64decode(compact(text))
    return bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(raw)).decode("ascii")


class DerReader:
    def __init__(self, data: bytes):
        self.data = data
        self.off = 0

    def tlv(self) -> tuple[int, bytes]:
        tag = self.data[self.off]
        self.off += 1
        first = self.data[self.off]
        self.off += 1
        if first < 0x80:
            ln = first
        else:
            n = first & 0x7F
            ln = int.from_bytes(self.data[self.off : self.off + n], "big")
            self.off += n
        val = self.data[self.off : self.off + ln]
        self.off += ln
        return tag, val


def one_tlv(data: bytes, tag: int) -> bytes:
    r = DerReader(data)
    got, val = r.tlv()
    if got != tag or r.off != len(data):
        raise ValueError("Unexpected DER structure")
    return val


def parse_spki_rsa_public_key(der: bytes) -> RsaPublicKey:
    spki = one_tlv(der, 0x30)
    r = DerReader(spki)
    alg_tag, _alg = r.tlv()
    bit_tag, bitstr = r.tlv()
    if alg_tag != 0x30 or bit_tag != 0x03 or bitstr[0] != 0:
        raise ValueError("Not an RSA SubjectPublicKeyInfo")
    rsa_seq = one_tlv(bitstr[1:], 0x30)
    rr = DerReader(rsa_seq)
    mod_tag, mod = rr.tlv()
    exp_tag, exp = rr.tlv()
    if mod_tag != 0x02 or exp_tag != 0x02:
        raise ValueError("Bad RSA public key")
    if mod.startswith(b"\x00"):
        mod = mod[1:]
    return RsaPublicKey(int.from_bytes(mod, "big"), int.from_bytes(exp, "big"))


def load_staging_public_key() -> tuple[str, bytes, RsaPublicKey]:
    key_b64 = decode_xor_base64(STAGING_KEY_OBFUSCATED)
    der = base64.b64decode(compact(key_b64))
    return key_b64, der, parse_spki_rsa_public_key(der)


def rsa_pkcs1_v1_5_encrypt(message: bytes, key: RsaPublicKey) -> bytes:
    k = key.size_bytes
    if len(message) > k - 11:
        raise ValueError("Message too long for RSA/PKCS1")
    ps_len = k - len(message) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        ps.extend(b for b in secrets.token_bytes(ps_len - len(ps)) if b != 0)
    em = b"\x00\x02" + bytes(ps[:ps_len]) + b"\x00" + message
    return pow(int.from_bytes(em, "big"), key.exponent, key.modulus).to_bytes(k, "big")


def build_plaintext(device_id: str, release: str, line: str, subscriber: str, operator: str, network_type: str, sim_state: str) -> str:
    return f" #{device_id}#{release}#{line}##{subscriber}#{operator}#{network_type}#{sim_state}"

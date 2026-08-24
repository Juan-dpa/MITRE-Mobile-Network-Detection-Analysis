from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass

from .config import LabConfig
from .logging_utils import log


class DnsResolutionError(RuntimeError):
    pass


@dataclass
class DnsResolver:
    config: LabConfig
    allow_fallback: bool = False

    def resolve_a(self, hostname: str) -> str:
        try:
            socket.inet_aton(hostname)
            return hostname
        except OSError:
            pass
        fallback = self._fallback_ip(hostname)
        if self.allow_fallback and fallback:
            log("dns", f"{hostname} -> {fallback} (static fallback)")
            return fallback
        try:
            ip = self._query_a(hostname)
            log("dns", f"{hostname} -> {ip}")
            return ip
        except Exception as exc:
            if self.allow_fallback and fallback:
                log("dns", f"{hostname} DNS failed ({exc}); using fallback {fallback}")
                return fallback
            raise DnsResolutionError(
                f"Could not resolve {hostname} through CoreDNS at "
                f"{self.config.dns_ip}:{self.config.dns_port}: {exc}"
            ) from exc

    def _query_a(self, hostname: str) -> str:
        query_id = random.randint(0, 0xFFFF)
        qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in hostname.split(".")) + b"\x00"
        packet = (
            struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
            + qname
            + struct.pack("!HH", 1, 1)
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.config.timeout_seconds)
            sock.sendto(packet, (self.config.dns_ip, self.config.dns_port))
            data, _ = sock.recvfrom(4096)

        if len(data) < 12:
            raise ValueError("short DNS response")
        rid, _flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])
        if rid != query_id:
            raise ValueError("DNS transaction id mismatch")
        offset = 12
        for _ in range(qdcount):
            offset = _skip_name(data, offset)
            offset += 4
        for _ in range(ancount):
            offset = _skip_name(data, offset)
            rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            rdata = data[offset : offset + rdlen]
            offset += rdlen
            if rtype == 1 and rclass == 1 and rdlen == 4:
                return socket.inet_ntoa(rdata)
        raise ValueError("no A answer")

    def _fallback_ip(self, hostname: str) -> str | None:
        mapping = {
            self.config.c2.host: self.config.c2.ip,
            self.config.firebase_api.host: self.config.firebase_api.ip,
            self.config.android_api_host: self.config.firebase_api.ip,
            self.config.fcm_api_host: self.config.firebase_api.ip,
            self.config.mtalk.host: self.config.mtalk.ip,
            "mtalk4.google.com": self.config.mtalk.ip,
            "alt1-mtalk.google.com": self.config.mtalk.ip,
            self.config.download.host: self.config.download.ip,
        }
        return mapping.get(hostname)


def _skip_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length

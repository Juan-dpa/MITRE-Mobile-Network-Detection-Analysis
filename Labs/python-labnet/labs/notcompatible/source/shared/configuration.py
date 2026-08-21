from __future__ import annotations

from Crypto.PublicKey import RSA

from .crypto import sign_digest_raw
from .protocol import Packet, container, int64, ipv4, port, raw, word


def build_group(group_id: int, host: str, service_port: int) -> Packet:
    return container(
        "GROUP",
        word("ID", group_id),
        container("SERV", ipv4("IP", host), port("PORT", service_port)),
    )


def build_signed_set(
    global_private: RSA.RsaKey,
    gateway_host: str,
    gateway_port: int,
    c2_host: str,
    c2_port: int,
    lid: int,
) -> Packet:
    data = container(
        "DATA",
        build_group(0, gateway_host, gateway_port),
        build_group(1, c2_host, c2_port),
        int64("LID", lid),
    )
    signature = sign_digest_raw(global_private, data.digest())
    return container("SET", data, raw("Sign", signature))

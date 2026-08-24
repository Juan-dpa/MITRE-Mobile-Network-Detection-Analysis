from __future__ import annotations

import socket
import struct
import time
from collections import deque
from typing import Callable

from Crypto.PublicKey import RSA

from .crypto import (
    RC4,
    decrypt_session_key,
    encrypt_session_key,
    modulus_bytes,
    new_session_key,
)
from .protocol import Packet, PacketStream


class SessionClosed(ConnectionError):
    pass


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise SessionClosed("Peer closed the TCP connection")
        data.extend(chunk)
    return bytes(data)


class EncryptedPacketSession:
    def __init__(self, sock: socket.socket, rc4_key: bytes, peer_name: str) -> None:
        self.sock = sock
        self.peer_name = peer_name
        self.rx = RC4(rc4_key)
        self.tx = RC4(rc4_key)
        self.stream = PacketStream()
        self.pending: deque[Packet] = deque()

    def send_packet(self, packet: Packet) -> None:
        self.sock.sendall(self.tx.crypt(packet.pack()))

    def receive_available(self, timeout: float | None = None) -> list[Packet]:
        previous_timeout = self.sock.gettimeout()
        try:
            self.sock.settimeout(timeout)
            encrypted = self.sock.recv(8192)
        except socket.timeout:
            return []
        finally:
            self.sock.settimeout(previous_timeout)
        if not encrypted:
            raise SessionClosed(f"{self.peer_name} closed the encrypted session")
        return self.stream.feed(self.rx.crypt(encrypted))

    def recv_one(self, timeout: float | None = None) -> Packet:
        if self.pending:
            return self.pending.popleft()
        packets = self.receive_available(timeout)
        if not packets:
            raise TimeoutError(f"Timed out waiting for a packet from {self.peer_name}")
        self.pending.extend(packets[1:])
        return packets[0]

    def wait_for(
        self,
        predicate: Callable[[Packet], bool],
        timeout: float,
    ) -> Packet:
        deadline = time.monotonic() + timeout
        deferred: deque[Packet] = deque()
        try:
            while True:
                while self.pending:
                    packet = self.pending.popleft()
                    if predicate(packet):
                        return packet
                    deferred.append(packet)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"Timed out waiting for packet from {self.peer_name}")
                packets = self.receive_available(min(remaining, 0.5))
                for index, packet in enumerate(packets):
                    if predicate(packet):
                        self.pending.extend(packets[index + 1 :])
                        return packet
                    deferred.append(packet)
        finally:
            # Preserve every unrelated packet exactly once and in arrival order.
            self.pending.extendleft(reversed(deferred))

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def client_handshake(
    sock: socket.socket,
    local_private_key: RSA.RsaKey,
    peer_name: str,
) -> EncryptedPacketSession:
    modulus = modulus_bytes(local_private_key.public_key())
    sock.sendall(struct.pack("<I", len(modulus)) + modulus)

    encrypted_length = struct.unpack("<I", recv_exact(sock, 4))[0]
    if encrypted_length < 64 or encrypted_length > 1024:
        raise ValueError(f"Invalid RSA response length {encrypted_length}")
    encrypted_key = recv_exact(sock, encrypted_length)
    rc4_key = decrypt_session_key(local_private_key, encrypted_key)
    return EncryptedPacketSession(sock, rc4_key, peer_name)


def server_handshake(
    sock: socket.socket,
    peer_name: str,
) -> tuple[EncryptedPacketSession, RSA.RsaKey]:
    modulus_length = struct.unpack("<I", recv_exact(sock, 4))[0]
    if modulus_length < 64 or modulus_length > 1024:
        raise ValueError(f"Invalid client modulus length {modulus_length}")
    modulus = int.from_bytes(recv_exact(sock, modulus_length), "big")
    client_public = RSA.construct((modulus, 65537))

    rc4_key = new_session_key()
    encrypted_key = encrypt_session_key(client_public, rc4_key)
    sock.sendall(struct.pack("<I", len(encrypted_key)) + encrypted_key)
    return EncryptedPacketSession(sock, rc4_key, peer_name), client_public

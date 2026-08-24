from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from pathlib import Path

from drinik_emulator.c2_server import C2Server
from drinik_emulator.config import LabConfig, RuntimePaths
from drinik_emulator.dns_client import DnsResolver
from drinik_emulator.download_server import DownloadServer
from drinik_emulator.firebase_gateway import FirebaseGateway
from drinik_emulator.logging_utils import log
from drinik_emulator.tls_material import client_context, ensure_self_signed_cert, server_context
from drinik_emulator.victim import VictimClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Drinik FCM/HTTP/download traffic on loopback.")
    parser.add_argument(
        "--allow-dns-fallback",
        action="store_true",
        help="Continue with static 127/8 mappings if CoreDNS is not reachable.",
    )
    parser.add_argument(
        "--ssl-keylog",
        default=None,
        help="Path for TLS key log. Defaults to runtime/sslkeys.log.",
    )
    parser.add_argument(
        "--keep-alive",
        action="store_true",
        help="Keep servers running after the sequence until Ctrl+C.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_dir = Path(__file__).resolve().parent
    paths = RuntimePaths.under(base_dir)
    keylog_path = Path(args.ssl_keylog) if args.ssl_keylog else paths.ssl_keylog
    config = LabConfig()
    stop_event = threading.Event()

    def handle_stop(_signum: int, _frame: object) -> None:
        log("main", "Ctrl+C received, stopping")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)

    cert_path, key_path = ensure_self_signed_cert(
        paths.cert_dir,
        config.firebase_api.ip,
        config.mtalk.ip,
    )
    server_tls = server_context(cert_path, key_path, keylog_path)
    client_tls = client_context(keylog_path)
    resolver = DnsResolver(config=config, allow_fallback=args.allow_dns_fallback)

    servers = [
        FirebaseGateway(config, server_tls, stop_event),
        C2Server(config, resolver, client_tls, stop_event),
        DownloadServer(config),
    ]

    try:
        for server in servers:
            server.start()
        time.sleep(config.start_delay_seconds)

        victim = VictimClient(config, resolver, client_tls, stop_event)
        victim.run_sequence()
        log("main", "sequence complete")

        if args.keep_alive:
            log("main", "servers kept alive; press Ctrl+C to stop")
            while not stop_event.is_set():
                time.sleep(0.2)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        stop_event.set()
        for server in reversed(servers):
            try:
                server.stop()
            except Exception as exc:
                log("main", f"error stopping server: {exc}")
        log("main", f"TLS key log: {keylog_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

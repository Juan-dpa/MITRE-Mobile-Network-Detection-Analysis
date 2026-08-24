#!/usr/bin/env python3
from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from pathlib import Path

from drinik_emulator.c2_server import C2Server
from drinik_emulator.config import Endpoint, LabConfig, RuntimePaths
from drinik_emulator.dns_client import DnsResolver
from drinik_emulator.download_server import DownloadServer
from drinik_emulator.firebase_gateway import FirebaseGateway
from drinik_emulator.logging_utils import log
from drinik_emulator.tls_material import client_context, ensure_self_signed_cert, server_context
from drinik_emulator.victim import VictimClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ejecuta una entidad aislada del laboratorio Drinik")
    parser.add_argument("role", choices=("firebase", "c2", "download", "victim"))
    parser.add_argument("--dns-ip", default="8.8.8.8")
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--c2-ip", default="198.12.107.13")
    parser.add_argument("--c2-host", default="gia.3utilities.com")
    parser.add_argument("--firebase-ip", default="172.217.114.4")
    parser.add_argument("--mtalk-ip", default="108.177.15.188")
    parser.add_argument("--download-ip", default="192.3.124.14")
    parser.add_argument("--download-host", default="192.3.124.14")
    parser.add_argument("--ssl-keylog", default=None)
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> LabConfig:
    return LabConfig(
        c2=Endpoint(args.c2_host, args.c2_ip, 80),
        firebase_api=Endpoint("firebaseinstallations.googleapis.com", args.firebase_ip, 443),
        mtalk=Endpoint("mtalk.google.com", args.mtalk_ip, 5228),
        download=Endpoint(args.download_host, args.download_ip, 80),
        dns_ip=args.dns_ip,
        dns_port=args.dns_port,
    )


def wait_for_stop(stop: threading.Event) -> None:
    while not stop.wait(0.2):
        pass


def main() -> int:
    args = parse_args()
    config = build_config(args)
    base_dir = Path(__file__).resolve().parent
    paths = RuntimePaths.under(base_dir)
    keylog = Path(args.ssl_keylog) if args.ssl_keylog else paths.root / f"sslkeys-{args.role}.log"
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    cert_path, key_path = ensure_self_signed_cert(
        paths.cert_dir,
        config.firebase_api.ip,
        config.mtalk.ip,
    )
    resolver = DnsResolver(config=config, allow_fallback=False)
    component = None

    try:
        if args.role == "firebase":
            component = FirebaseGateway(config, server_context(cert_path, key_path, keylog), stop)
            component.start()
            wait_for_stop(stop)
        elif args.role == "c2":
            component = C2Server(config, resolver, client_context(keylog), stop)
            component.start()
            wait_for_stop(stop)
        elif args.role == "download":
            component = DownloadServer(config)
            component.start()
            wait_for_stop(stop)
        else:
            victim = VictimClient(config, resolver, client_context(keylog), stop)
            victim.run_sequence()
            log("victim", "secuencia completa")
        return 0
    except KeyboardInterrupt:
        stop.set()
        return 130
    except BaseException as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        stop.set()
        return 1
    finally:
        stop.set()
        if component is not None:
            try:
                component.stop()
            except Exception as exc:
                log("runner", f"error al detener {args.role}: {exc}")
        time.sleep(0.1)


if __name__ == "__main__":
    sys.exit(main())

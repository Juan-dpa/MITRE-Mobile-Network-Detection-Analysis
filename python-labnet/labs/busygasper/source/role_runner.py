#!/usr/bin/env python3
from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from pathlib import Path

from config import EmulationConfig
from entities.busygasper_victim import BusyGasperVictim
from entities.ftp_server import FtpServer
from entities.irc_operator import IrcOperator
from entities.irc_server import IrcServer
from protocol import make_update_apk_bytes


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Ejecuta una entidad aislada del laboratorio BusyGasper")
    result.add_argument("role", choices=("irc", "ftp", "operator", "victim"))
    result.add_argument("--irc-bind-host", default="149.28.246.185")
    result.add_argument("--irc-connect-host", default="149.28.246.185")
    result.add_argument("--irc-port", type=int, default=6667)
    result.add_argument("--dns-server", default="8.8.8.8")
    result.add_argument("--dns-port", type=int, default=53)
    result.add_argument("--ftp-bind-host", default="213.174.157.151")
    result.add_argument("--ftp-connect-host", default="213.174.157.151")
    result.add_argument("--ftp-port", type=int, default=21)
    result.add_argument("--ftp-data-host", default="213.174.157.151")
    result.add_argument("--ftp-data-port", type=int, default=20200)
    result.add_argument("--operator-delay", type=float, default=1.0)
    result.add_argument("--victim-id", default="12345")
    result.add_argument("--update-name", default="update.apk")
    result.add_argument("--output-dir", default=str(Path(__file__).with_name("downloads")))
    result.add_argument("--timeout", type=float, default=15.0)
    return result


def build_config(args: argparse.Namespace) -> EmulationConfig:
    return EmulationConfig(
        irc_bind_host=args.irc_bind_host,
        irc_connect_host=args.irc_connect_host,
        irc_port=args.irc_port,
        dns_server=args.dns_server,
        dns_port=args.dns_port,
        ftp_bind_host=args.ftp_bind_host,
        ftp_connect_host=args.ftp_connect_host,
        ftp_port=args.ftp_port,
        ftp_data_host=args.ftp_data_host,
        ftp_data_port=args.ftp_data_port,
        victim_id=args.victim_id,
        update_name=args.update_name,
        socket_timeout=args.timeout,
    )


def wait_ready(name: str, thread: threading.Thread, event: threading.Event, timeout: float) -> None:
    if not event.wait(timeout):
        raise TimeoutError(f"{name} no quedó listo")
    error = getattr(thread, "error", None)
    if error:
        raise RuntimeError(f"falló {name}") from error


def serve(thread: threading.Thread, ready: threading.Event, stop: threading.Event, timeout: float) -> None:
    thread.start()
    wait_ready(thread.name, thread, ready, timeout)
    while not stop.wait(0.2):
        error = getattr(thread, "error", None)
        if error:
            raise RuntimeError(f"falló {thread.name}") from error


def main() -> int:
    args = parser().parse_args()
    config = build_config(args)
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    try:
        if args.role == "irc":
            component = IrcServer(config, stop)
            serve(component, component.ready, stop, args.timeout)
        elif args.role == "ftp":
            payload = make_update_apk_bytes(config.package_name)
            component = FtpServer(config, payload, stop)
            serve(component, component.ready, stop, args.timeout)
        elif args.role == "operator":
            # La sincronización entre procesos se realiza por orden de arranque:
            # la víctima dispone de este margen para registrarse en el IRC.
            time.sleep(args.operator_delay)
            victim_registered = threading.Event()
            victim_registered.set()
            component = IrcOperator(config, victim_registered, stop)
            component.start()
            wait_ready("operador IRC", component, component.ready, args.timeout)
            if not component.done.wait(args.timeout):
                raise TimeoutError("el operador no recibió la confirmación de actualización")
            if component.error:
                raise RuntimeError("falló el operador IRC") from component.error
        else:
            component = BusyGasperVictim(config, stop)
            component.start()
            if not component.done.wait(args.timeout):
                raise TimeoutError("la secuencia de la víctima no terminó")
            if component.error:
                raise RuntimeError("falló la víctima BusyGasper") from component.error
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            output = output_dir / config.update_name
            output.write_bytes(component.downloaded_payload)
            print(f"[VICTIM] carga inerte guardada en {output}")
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
        if "component" in locals() and component.is_alive():
            component.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())

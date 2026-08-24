from __future__ import annotations

import argparse
import logging
import socket
import threading


LOG = logging.getLogger("ftp")


class LabBackdoor:
    def __init__(self, host: str, port: int, stop: threading.Event) -> None:
        self.host = host
        self.port = port
        self.stop = stop
        self.started = False
        self.listener: socket.socket | None = None
        self.lock = threading.Lock()

    def start(self) -> None:
        with self.lock:
            if self.started:
                return
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((self.host, self.port))
            self.listener.listen()
            self.listener.settimeout(0.5)
            self.started = True
            threading.Thread(target=self.run, daemon=True).start()
            LOG.warning(
                "CVE-2011-2523 lab trigger activated: simulated shell on %s:%d",
                self.host,
                self.port,
            )

    def run(self) -> None:
        assert self.listener is not None
        while not self.stop.is_set():
            try:
                client, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self.handle_shell,
                args=(client, address),
                daemon=True,
            ).start()

    def handle_shell(self, client: socket.socket, address) -> None:
        peer = f"{address[0]}:{address[1]}"
        LOG.info("Simulated bind shell connection from %s", peer)
        buffer = bytearray()
        try:
            while not self.stop.is_set():
                data = client.recv(4096)
                if not data:
                    break
                buffer.extend(data)
                while b"\n" in buffer:
                    line, _, remainder = buffer.partition(b"\n")
                    buffer[:] = remainder
                    command = line.rstrip(b"\r")
                    LOG.info("Shell received %r", command)
                    if command == b"id":
                        client.sendall(b"uid=0(root) gid=0(root) groups=0(root)\n")
                    elif command == b"exit":
                        return
                    else:
                        # Deliberately avoid offering arbitrary command execution.
                        client.sendall(b"lab-shell: command disabled\n")
        except OSError:
            pass
        finally:
            client.close()
            LOG.info("Simulated bind shell disconnected: %s", peer)

    def close(self) -> None:
        if self.listener is not None:
            self.listener.close()


def handle_ftp(
    client: socket.socket,
    address,
    backdoor: LabBackdoor,
    stop: threading.Event,
) -> None:
    peer = f"{address[0]}:{address[1]}"
    LOG.info("FTP connection from %s", peer)
    trigger_seen = False
    buffer = bytearray()
    try:
        client.sendall(b"220 (vsFTPd 2.3.4)\r\n")
        while not stop.is_set():
            data = client.recv(4096)
            if not data:
                break
            buffer.extend(data)
            while b"\n" in buffer:
                line, _, remainder = buffer.partition(b"\n")
                buffer[:] = remainder
                line = line.rstrip(b"\r")
                LOG.info("FTP received %r [%s]", line, line.hex(" "))
                upper = line.upper()
                if upper.startswith(b"USER "):
                    username = line[5:]
                    trigger_seen = b":)" in username
                    client.sendall(b"331 Please specify the password.\r\n")
                elif upper.startswith(b"PASS "):
                    if trigger_seen:
                        backdoor.start()
                    client.sendall(b"530 Login incorrect.\r\n")
                elif upper == b"QUIT":
                    client.sendall(b"221 Goodbye.\r\n")
                    return
                else:
                    client.sendall(b"500 Unknown command.\r\n")
    except OSError:
        pass
    finally:
        client.close()
        LOG.info("FTP disconnected: %s", peer)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safe lab emulation of the CVE-2011-2523 network behavior"
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--ftp-port", type=int, default=2121)
    parser.add_argument("--shell-port", type=int, default=6200)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [FTP] %(message)s",
        datefmt="%H:%M:%S",
    )
    stop = threading.Event()
    backdoor = LabBackdoor(args.listen_host, args.shell_port, stop)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen_host, args.ftp_port))
    listener.listen()
    listener.settimeout(0.5)
    LOG.info(
        "FTP target listening on %s:%d; shell will appear on %d after trigger",
        args.listen_host,
        args.ftp_port,
        args.shell_port,
    )
    LOG.info("Only the harmless command 'id' is implemented (Ctrl+C to stop)")

    try:
        while not stop.is_set():
            try:
                client, address = listener.accept()
            except socket.timeout:
                continue
            threading.Thread(
                target=handle_ftp,
                args=(client, address, backdoor, stop),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        LOG.info("Ctrl+C received, shutting down")
    finally:
        stop.set()
        listener.close()
        backdoor.close()


if __name__ == "__main__":
    main()

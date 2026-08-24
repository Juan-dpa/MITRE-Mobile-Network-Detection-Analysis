#!/usr/bin/env python3
"""Operador determinista para el laboratorio de TeleRAT.

El servidor mantiene la cola que la API emulada entregará mediante getUpdates.
De forma predeterminada, cuando recibe el evento que representa la publicación
del teclado de órdenes, añade automáticamente la orden «دریافت وضعیت».
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit


DEFAULT_COMMAND = "دریافت وضعیت"


def compact_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def numeric_id(value: str | int | None, fallback: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return fallback


@dataclass(frozen=True)
class OperatorConfig:
    command: str
    delay: float
    auto_command: bool
    operator_id: int
    first_name: str
    username: str
    first_update_id: int
    first_message_id: int


class OperatorState:
    def __init__(self, config: OperatorConfig) -> None:
        self.config = config
        self.lock = threading.RLock()
        self.updates: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.command_scheduled = False
        self.command_queued = False
        self.scenario_complete = False
        self.chat_id: str | None = None

    def record_event(self, event: dict[str, Any]) -> None:
        kind = str(event.get("kind", "unknown"))
        with self.lock:
            self.events.append({"received_at": int(time.time()), **event})
            if event.get("chat_id") not in (None, ""):
                self.chat_id = str(event["chat_id"])
            if kind == "result":
                self.scenario_complete = True

            should_schedule = (
                kind == "keyboard"
                and self.config.auto_command
                and not self.command_scheduled
                and not self.command_queued
            )
            if should_schedule:
                self.command_scheduled = True

        print(f"[operador] Evento recibido: {kind}", flush=True)
        if should_schedule:
            timer = threading.Timer(
                self.config.delay,
                self.queue_command,
                kwargs={"text": self.config.command, "chat_id": self.chat_id},
            )
            timer.daemon = True
            timer.start()

    def queue_command(self, text: str, chat_id: str | None = None) -> dict[str, Any]:
        with self.lock:
            selected_chat = str(chat_id or self.chat_id or self.config.operator_id)
            chat_numeric = numeric_id(selected_chat, self.config.operator_id)
            operator_numeric = (
                chat_numeric if chat_numeric > 0 else self.config.operator_id
            )
            update = {
                "update_id": self.config.first_update_id + len(self.updates),
                "message": {
                    "message_id": self.config.first_message_id + len(self.updates),
                    "from": {
                        "id": operator_numeric,
                        "is_bot": False,
                        "first_name": self.config.first_name,
                        "username": self.config.username,
                    },
                    "chat": {"id": chat_numeric, "type": "private"},
                    "date": int(time.time()),
                    "text": text,
                },
            }
            self.updates.append(update)
            self.chat_id = selected_chat
            self.command_queued = True
            self.command_scheduled = False

        print(
            f"[operador] Orden añadida: {text!r} "
            f"(update_id={update['update_id']}, chat_id={selected_chat})",
            flush=True,
        )
        return update

    def telegram_updates(self) -> dict[str, Any]:
        with self.lock:
            # TeleRAT no envía offset. Se conserva la lista completa para que
            # el aumento de su longitud señale una actualización nueva.
            return {"ok": True, "result": list(self.updates)}

    def status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "ok": True,
                "chat_id": self.chat_id,
                "updates": list(self.updates),
                "events": list(self.events),
                "command_scheduled": self.command_scheduled,
                "command_queued": self.command_queued,
                "scenario_complete": self.scenario_complete,
            }


class OperatorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: OperatorState) -> None:
        super().__init__(address, OperatorHandler)
        self.state = state


class OperatorHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: OperatorHTTPServer

    def log_message(self, format_string: str, *args: Any) -> None:
        print(f"[operador-http] {format_string % args}", flush=True)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length) if length else b"{}"
        value = json.loads(data.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("El cuerpo JSON debe ser un objeto")
        return value

    def _send_json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = compact_json(value)
        self.send_response_only(status.value, status.phrase)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()

    def do_GET(self) -> None:  # noqa: N802 - nombre definido por http.server
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._send_json({"ok": True})
            return
        if parsed.path == "/updates":
            self._send_json(self.server.state.telegram_updates())
            return
        if parsed.path == "/status":
            self._send_json(self.server.state.status())
            return
        self._send_json({"ok": False, "error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802 - nombre definido por http.server
        parsed = urlsplit(self.path)
        try:
            body = self._read_json()
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._send_json(
                {"ok": False, "error": f"invalid_json: {exc}"},
                HTTPStatus.BAD_REQUEST,
            )
            return

        if parsed.path == "/event":
            self.server.state.record_event(body)
            self._send_json({"ok": True})
            return

        if parsed.path == "/command":
            query = parse_qs(parsed.query, keep_blank_values=True)
            text = str(body.get("text") or query.get("text", [DEFAULT_COMMAND])[0])
            chat_id = body.get("chat_id") or query.get("chat_id", [None])[0]
            update = self.server.state.queue_command(text=text, chat_id=chat_id)
            self._send_json({"ok": True, "update": update})
            return

        self._send_json({"ok": False, "error": "not_found"}, HTTPStatus.NOT_FOUND)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--command", default=DEFAULT_COMMAND)
    parser.add_argument("--command-delay", type=float, default=1.0)
    parser.add_argument("--no-auto-command", action="store_true")
    parser.add_argument("--operator-id", type=int, default=471078355)
    parser.add_argument("--first-name", default="Operator")
    parser.add_argument("--username", default="operator")
    parser.add_argument("--first-update-id", type=int, default=800000001)
    parser.add_argument("--first-message-id", type=int, default=7001)
    return parser.parse_args()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    args = parse_args()
    config = OperatorConfig(
        command=args.command,
        delay=args.command_delay,
        auto_command=not args.no_auto_command,
        operator_id=args.operator_id,
        first_name=args.first_name,
        username=args.username,
        first_update_id=args.first_update_id,
        first_message_id=args.first_message_id,
    )
    server = OperatorHTTPServer((args.bind, args.port), OperatorState(config))
    print(
        f"[operador] Escuchando en http://{args.bind}:{args.port} "
        f"(orden automática: {config.auto_command}, texto: {config.command!r})",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\n[operador] Ctrl+C recibido; cerrando...", flush=True)
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())



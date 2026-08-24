from __future__ import annotations

import sys
import socket
import ssl
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
KEYRAIDER_SOURCE = ROOT / "labs" / "keyraider" / "source"
sys.path.insert(0, str(KEYRAIDER_SOURCE))

import lab_client  # noqa: E402
import lab_server  # noqa: E402


class KeyRaiderFlowTests(unittest.TestCase):
    def test_apple_authentication_uses_xml_plist(self) -> None:
        body = lab_client.build_apple_authentication_plist(
            "victim@example.com",
            "Password&123",
            "00000000-1111-2222-3333-444444444444",
        )

        self.assertTrue(body.startswith(b'<?xml version="1.0"'))
        self.assertIn(b"<key>appleId</key>\n\t<string>victim@example.com</string>", body)
        self.assertIn(b"<key>password</key>\n\t<string>Password&amp;123</string>", body)
        self.assertIn(b"<key>guid</key>", body)
        self.assertNotIn(b"appleId=victim", body)

    def test_apple_response_contains_required_person_id(self) -> None:
        body = lab_server.build_apple_response_body()
        response = (
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"\r\n"
            + body
        )

        lab_client.validate_apple_authentication_response(response)
        self.assertIn(b"<key>dsPersonId</key><string>225000001</string>", body)

    def test_exfiltration_is_rejected_without_person_id(self) -> None:
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
        with self.assertRaisesRegex(RuntimeError, "dsPersonId"):
            lab_client.validate_apple_authentication_response(response)

    def test_apple_tls_exchange_closes_cleanly(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=KEYRAIDER_SOURCE / "certs/p12-buy.itunes.apple.com.crt.pem",
            keyfile=KEYRAIDER_SOURCE / "certs/p12-buy.itunes.apple.com.key.pem",
        )
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        server_shutdowns: list[bool] = []
        actual_close = lab_server.close_tls_gracefully

        def record_close(sock: ssl.SSLSocket) -> bool:
            result = actual_close(sock)
            server_shutdowns.append(result)
            return result

        def serve_once() -> None:
            conn, addr = listener.accept()
            lab_server.handle_apple_tls(
                conn,
                addr,
                context,
                lab_server.APPLE_HOST,
            )

        thread = threading.Thread(target=serve_once, daemon=True)
        thread.start()
        try:
            with patch.object(
                lab_server,
                "close_tls_gracefully",
                side_effect=record_close,
            ):
                lab_client.apple_tls_flow(
                    "127.0.0.1",
                    port,
                    lab_server.APPLE_HOST,
                    "victim@example.com",
                    "Password123",
                    "00000000-1111-2222-3333-444444444444",
                    None,
                )
        finally:
            listener.close()
            thread.join(timeout=3)

        self.assertFalse(thread.is_alive())
        self.assertEqual(server_shutdowns, [True])


if __name__ == "__main__":
    unittest.main()

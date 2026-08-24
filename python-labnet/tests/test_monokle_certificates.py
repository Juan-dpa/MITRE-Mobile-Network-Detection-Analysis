from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MONOKLE_SOURCE = ROOT / "labs" / "monokle" / "source"
sys.path.insert(0, str(MONOKLE_SOURCE))

import monokle_emulator as monokle  # noqa: E402


class MonokleCertificateTests(unittest.TestCase):
    def test_certificates_are_regenerated_when_oracle_hostname_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            old_paths = monokle.ensure_cert_material(cert_dir, "login.oraclecloud.com")
            old_proxy = old_paths["proxy_cert"].read_bytes()

            paths = monokle.ensure_cert_material(cert_dir, "www.oracle.com")

            self.assertTrue(monokle.cert_material_is_current(paths, "www.oracle.com"))
            self.assertFalse(monokle.cert_material_is_current(paths, "login.oraclecloud.com"))
            self.assertNotEqual(old_proxy, paths["proxy_cert"].read_bytes())

    def test_certificates_are_regenerated_when_key_does_not_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_dir = Path(temp_dir)
            paths = monokle.ensure_cert_material(cert_dir, "www.oracle.com")
            paths["proxy_key"].write_bytes(paths["origin_key"].read_bytes())

            repaired = monokle.ensure_cert_material(cert_dir, "www.oracle.com")

            self.assertTrue(monokle.cert_material_is_current(repaired, "www.oracle.com"))


if __name__ == "__main__":
    unittest.main()

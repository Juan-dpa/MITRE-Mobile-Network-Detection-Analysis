from __future__ import annotations

import importlib.util
import io
import ipaddress
import struct
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "labdns.py"
SPEC = importlib.util.spec_from_file_location("labdns", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
labdns = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = labdns
SPEC.loader.exec_module(labdns)


def query(name: str, transaction: int = 0x1234) -> bytes:
    qname = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)


class DnsTests(unittest.TestCase):
    def test_known_a_record(self) -> None:
        response = labdns.build_response(query("c2.example"), {"c2.example": "10.200.0.20"}, 60)
        transaction, flags, questions, answers, _, _ = struct.unpack(">HHHHHH", response[:12])
        self.assertEqual(transaction, 0x1234)
        self.assertEqual(flags & 0x000F, 0)
        self.assertEqual((questions, answers), (1, 1))
        self.assertEqual(response[-4:], ipaddress.IPv4Address("10.200.0.20").packed)

    def test_unknown_name_is_nxdomain(self) -> None:
        response = labdns.build_response(query("missing.example"), {}, 60)
        _, flags, _, answers, _, _ = struct.unpack(">HHHHHH", response[:12])
        self.assertEqual(flags & 0x000F, 3)
        self.assertEqual(answers, 0)

    def test_loopback_answer_is_rejected(self) -> None:
        with self.assertRaises(Exception):
            labdns.parse_record("bad.example=127.0.0.1")

    def test_query_log_reports_transport_client_and_result(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            labdns.log_query(
                query("c2.example"),
                {"c2.example": "10.200.0.20"},
                "UDP",
                ("10.0.2.15", 53000),
            )
        line = output.getvalue()
        self.assertIn("UDP 10.0.2.15:53000", line)
        self.assertIn("A c2.example -> 10.200.0.20", line)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FluBotFlowTests(unittest.TestCase):
    def test_injection_list_worker_starts_before_ping(self) -> None:
        source = (ROOT / "labs/flubot/source/bot_emulator.py").read_text(encoding="utf-8")
        submit = source.index("injects_future = executor.submit(")
        ping = source.index("command = panel_send(", submit)
        wait = source.index("injects_future.result(timeout=10)", ping)
        self.assertLess(submit, ping)
        self.assertLess(ping, wait)
        self.assertIn("GET_INJECTS_LIST,com.android.chrome,com.google.android.gm", source)

    def test_panel_has_a_controlled_injection_list_response(self) -> None:
        source = (ROOT / "labs/flubot/source/c2_server.py").read_text(encoding="utf-8")
        self.assertIn('payload.startswith("GET_INJECTS_LIST,")', source)
        self.assertIn('return "com.android.chrome"', source)


if __name__ == "__main__":
    unittest.main()

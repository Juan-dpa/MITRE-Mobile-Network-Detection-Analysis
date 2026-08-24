from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
ANDROID_LABS = ROOT / "android-labs"


class AndroidPipelineTests(unittest.TestCase):
    def test_every_android_lab_has_required_files(self) -> None:
        labs = [path for path in ANDROID_LABS.iterdir() if path.is_dir()]
        self.assertTrue(labs)
        for lab in labs:
            with self.subTest(lab=lab.name):
                for filename in ("run.sh", "topology.conf", "android.conf"):
                    self.assertTrue((lab / filename).is_file())

    def test_routes_are_real_or_private_ipv4(self) -> None:
        forbidden = (
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        )
        for config in ANDROID_LABS.glob("*/android.conf"):
            text = config.read_text(encoding="utf-8")
            block = re.search(r"ANDROID_ROUTE_IPS=\((.*?)\)", text, re.DOTALL)
            self.assertIsNotNone(block, config)
            addresses = re.findall(r'"(\d+(?:\.\d+){3})"', block.group(1))
            self.assertTrue(addresses, config)
            for value in addresses:
                address = ipaddress.ip_address(value)
                self.assertFalse(any(address in network for network in forbidden), value)

    def test_dresscode_uses_historical_c2_and_no_emulator_alias(self) -> None:
        lab = ANDROID_LABS / "dresscode"
        effective = "\n".join(
            (lab / name).read_text(encoding="utf-8")
            for name in ("topology.conf", "android.conf", "run.sh")
        )
        self.assertIn("138.201.195.77", effective)
        self.assertNotIn("10.0.2.2", effective)
        self.assertIn("dfm.nicsm.net=138.201.195.77", effective)

    def test_dresscode_does_not_inject_a_synthetic_service_start(self) -> None:
        dresscode = (ANDROID_LABS / "dresscode" / "run.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("android_after_capture_start", dresscode)
        self.assertNotIn("shell am startservice", dresscode)
        self.assertNotIn("adb root", dresscode)

    def test_goldencup_preserves_mqtt_and_uses_campaign_ioc(self) -> None:
        lab = ANDROID_LABS / "goldencup"
        launcher = (lab / "run.sh").read_text(encoding="utf-8")
        topology = (lab / "topology.conf").read_text(encoding="utf-8")
        config = (lab / "android.conf").read_text(encoding="utf-8")
        broker = (lab / "source" / "mqtt-server.conf").read_text(encoding="utf-8")
        operator = (lab / "source" / "mqtt_operator.sh").read_text(encoding="utf-8")

        self.assertIn("www.goldncup.com=107.175.144.26", launcher)
        self.assertIn("107.175.144.26|tcp|1883", topology)
        self.assertIn("107.175.144.26|tcp|80", topology)
        self.assertIn("golden_api21_aosp", config)
        self.assertIn("mosquitto mosquitto_pub mosquitto_sub", config)
        self.assertIn("listener 1883 107.175.144.26", broker)
        self.assertIn("RT/AP/+/I/A", operator)
        self.assertIn("RT/SV/$client_id/C/a", operator)
        self.assertIn("RT/AP/$client_id/I/B", operator)
        self.assertIn("shell pm clear anew.football.cup.world.com.worldcup", launcher)
        self.assertNotIn("jonalbertwebsite.000webhostapp.com=", launcher)

    def test_redalert_preserves_dead_drop_and_template_flow(self) -> None:
        lab = ANDROID_LABS / "redalert"
        launcher = (lab / "run.sh").read_text(encoding="utf-8")
        topology = (lab / "topology.conf").read_text(encoding="utf-8")
        config = (lab / "android.conf").read_text(encoding="utf-8")
        server = (lab / "source" / "redalert_server.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("www.timeapi.org=10.230.39.10", launcher)
        self.assertIn("twitter.com=10.230.39.11", launcher)
        self.assertIn("--dport 7878 -j DROP", launcher)
        self.assertIn("primary|146.0.72.85|tcp|7878|primary-blackhole", topology)
        self.assertIn("c2|192.168.56.20|tcp|8060", topology)
        self.assertIn("android|primary|146.0.72.85|tcp|7878", topology)
        self.assertIn("android|c2|192.168.56.20|tcp|8060", topology)
        self.assertIn("TFG_TeleRAT_API19", config)
        self.assertIn("redalert-sslkeys.log", launcher)
        self.assertIn("wait_tcp timeapi 10.230.39.10 80 300", launcher)
        self.assertIn("wait_tcp twitter 10.230.39.11 443 300", launcher)
        self.assertIn("wait_tcp c2 192.168.56.20 8060 300", launcher)
        self.assertIn("tcp_syn_retries", launcher)
        self.assertIn("echo 4", launcher)
        self.assertIn('TWEET_TEXT = "192.168 56.20"', server)
        for route in ("/ping", "/stbi", "/sban", "/gt", "/sy", "/ssl", "/ucs"):
            self.assertIn(route, server)

    def test_xloader_preserves_resolver_binary_c2_and_http_relay(self) -> None:
        lab = ANDROID_LABS / "xloader"
        launcher = (lab / "run.sh").read_text(encoding="utf-8")
        topology = (lab / "topology.conf").read_text(encoding="utf-8")
        config = (lab / "android.conf").read_text(encoding="utf-8")
        scenario = (lab / "source" / "config" / "lab.toml").read_text(
            encoding="utf-8"
        )
        c2 = (lab / "source" / "servers" / "c2" / "server.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("twitter.com=10.230.31.11", launcher)
        self.assertIn("webview.lab=10.230.31.20", launcher)
        self.assertIn("vuln.lab=10.230.31.30", launcher)
        self.assertIn("c2|1.162.98.240|tcp|28833", topology)
        self.assertIn('c2_value = "1.162.98.240:28833"', scenario)
        self.assertIn("GPlayed_API22_AOSP", config)
        self.assertIn("xloader-sslkeys.log", launcher)
        self.assertIn("--auto-continue", launcher)
        self.assertNotIn("--continue-file", launcher)
        self.assertNotIn("android_during_interaction", launcher)
        self.assertIn("getPkgMap", c2)
        self.assertIn("getPkgData", c2)
        self.assertIn('session.send_request("http", params)', c2)
        self.assertIn("shellshock_user_agent", scenario)
        secondary_apk = (
            lab
            / "source"
            / "android"
            / "secondary_apk"
            / "dist"
            / "lab-xloader-secondary.apk"
        )
        self.assertEqual(
            hashlib.sha256(secondary_apk.read_bytes()).hexdigest(),
            "4896291f416fbbce50775c258d3f72c7d5c0c48a770084e6cb0ec73878dfb7ee",
        )

    def test_android_run_captures_before_showing_manual_avd_command(self) -> None:
        runlib = (ROOT / "tools" / "android-runlib.sh").read_text(
            encoding="utf-8"
        )
        start = runlib.index("android_run_interactive()")
        end = runlib.index("android_usage()", start)
        workflow = runlib[start:end]
        self.assertLess(workflow.index("android_prepare"), workflow.index("android_capture_start"))
        self.assertLess(workflow.index("android_capture_start"), workflow.index("android_emulator_command"))
        self.assertIn("android_prepare\n", workflow)
        self.assertIn("android_after_emulator_command", workflow)

    def test_pipeline_never_controls_or_inspects_the_avd(self) -> None:
        runlib = (ROOT / "tools" / "android-runlib.sh").read_text(
            encoding="utf-8"
        )
        forbidden = (
            "android_adb",
            "android_start_avd",
            "android_kill_avd",
            "android_wait_boot",
            "android_verify_device",
            "force-stop",
            "emu kill",
            "--attach",
            "--kill-avd",
        )
        for value in forbidden:
            self.assertNotIn(value, runlib)
        self.assertIn("android_emulator_command()", runlib)
        self.assertIn("-dns-server %s -no-snapshot-load", runlib)

    def test_android_entities_use_visible_windows_with_tracked_cleanup(self) -> None:
        runlib = (ROOT / "tools" / "android-runlib.sh").read_text(
            encoding="utf-8"
        )
        controller = (ROOT / "tools" / "android-windows.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("android_log_windows_open()", runlib)
        self.assertIn("android_log_windows_close()", runlib)
        self.assertIn("output=${output//$'\\r'/}", runlib)
        self.assertIn("recovery_tokens", runlib)
        self.assertIn("OpenLogWindows", controller)
        self.assertIn("CloseLogWindows", controller)
        self.assertIn("TFG_LOG_PIDS=", controller)
        self.assertIn("Get-Command 'wsl.exe'", controller)
        self.assertIn("Start-Process -FilePath $wsl -WindowStyle Normal", controller)
        self.assertIn("$process.ProcessName -ne 'wsl'", controller)
        self.assertNotIn("StartAvd", controller)
        self.assertNotIn("StopAvd", controller)
        self.assertNotIn("Invoke-StartAvd", controller)
        self.assertNotIn("Invoke-StopAvd", controller)

    def test_android_event_timestamp_uses_supported_coreutils_precision(self) -> None:
        runlib = (ROOT / "tools" / "android-runlib.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("date --iso-8601=seconds", runlib)
        self.assertNotIn("date --iso-8601=milliseconds", runlib)

    def test_windows_controller_is_session_scoped(self) -> None:
        controller = (ROOT / "tools" / "android-windows.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("-PolicyStore ActiveStore", controller)
        self.assertIn("CreatedRoutes", controller)
        self.assertIn("FirewallRules", controller)
        self.assertIn("Remove-LabState", controller)
        self.assertIn("Get-IPv4BlockPrefixes", controller)
        self.assertNotIn("Get-IPv4BlockRanges", controller)
        self.assertIn("$prefixLength -eq 31", controller)
        self.assertIn("$prefixLength -eq 32", controller)
        self.assertIn("ResultFile", controller)

    def test_powershell_path_does_not_depend_on_sudo_secure_path(self) -> None:
        runlib = (ROOT / "tools" / "android-runlib.sh").read_text(
            encoding="utf-8"
        )
        expected = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        self.assertIn(expected, runlib)
        self.assertNotIn("android_require_command powershell.exe", runlib)


if __name__ == "__main__":
    unittest.main()

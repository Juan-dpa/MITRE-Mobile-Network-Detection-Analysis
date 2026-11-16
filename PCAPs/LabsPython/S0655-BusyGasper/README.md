# BusyGasper: Bidirectional y Download separados

Preparación y verificación: 26 de octubre de 2026. Derivados del [PCAP original](../../../PCAPs/LabsPython/S0655-BusyGasper/S0655-BusyGasper.pcap), que permanece intacto. No se ha vuelto a ejecutar el laboratorio. Las referencias a tramas y streams siguientes corresponden al original salvo indicación contraria.

| Archivo | Técnica objetivo | Contenido | Paquetes | Trama máxima |
|---|---|---|---:|---:|
| [Bidirectional](S0655-BusyGasper-T1481.002-bidirectional.pcap) | T1481.002 | DNS y sesión IRC completa, sin FTP | 23 | 133 B |
| [Download](S0655-BusyGasper-T1407-download.pcap) | T1407 | Control y datos FTP completos, sin IRC | 32 | 386 B |

No se asignan técnicas acompañantes a estas dos vistas. La separación se realiza por conexiones completas: las selecciones no se solapan y, juntas, conservan los 55 paquetes originales. Todos mantienen sus tiempos originales.

## 1. Bidirectional: DNS e IRC

Selección: **tramas 1–19 y 52–55**. Incluye DNS de `irc.freenode.net` y el stream TCP original **0**, conectado a `149.28.246.185:6667`.

- Tramas 1–2: resolución DNS.
- Tramas 3–5: handshake TCP original.
- Tramas 6–17: registro `NICK`/`USER` y respuestas de bienvenida hasta `004`.
- Tramas 18–19: orden `#Uupdate.apk` y su ACK TCP.
- Tramas 52–55: respuesta funcional `PRIVMSG IRCBoss :com.android.system.bdata updated` y cierre TCP completo. En la copia ocupan las posiciones 20–23.

Se retiran únicamente las conexiones FTP, que usan otros espacios de secuencia. El IRC no pierde bytes y no necesita reajustes de SEQ/ACK para unir sus partes anteriores y posteriores a la transferencia.

**Es una vista del canal C&C de la ejecución original.** Conserva la orden de actualización y su resultado, pero no contiene la transferencia ni los bytes del fichero. No se ha sustituido esa orden por otra ni se presenta el archivo como una ejecución nueva en la que no ocurrió la descarga. Una regla que reconozca el texto de la orden puede seguir alertando sobre él; la separación de conexiones no determina cómo nombrará el producto su alerta.

## 2. Download: control y datos FTP

Selección: **tramas 20–51**, streams TCP originales **1 y 2**. No contiene IRC, consultas DNS ni mensajes de retorno por el C&C.

| Parte | Extremo servidor | Tramas originales | Handshake en la copia |
|---|---|---|---|
| Control FTP | `213.174.157.151:21` | 20–31, 35–38 y 44–51 | 1–3 |
| Datos FTP | `213.174.157.151:20200` | 32–34 y 39–43 | 13–15 |

El control conserva saludo, autenticación, `pasv`, `type i`, `retr update.apk`, respuestas `150`/`226` y `quit`. La respuesta `227` anuncia `(213,174,157,151,78,232)`: `78 × 256 + 232 = 20200`, que coincide con la conexión de datos conservada. Ambos flujos incluyen sus cierres FIN/ACK completos.

**No se añade T1509 por TCP/20200:** es el puerto de datos negociado mediante FTP pasivo, una función normal de ese protocolo. No representa un C&C trasladado arbitrariamente a un puerto no estándar.

La transferencia contiene los **320 bytes originales** de `update.apk`, con SHA-256 `16b13fcd0d9817e781ee9f45011791671a4c7a3151bae63fe4a7b55e89c1aa63`. Coinciden exactamente con el [artefacto recibido por el laboratorio](../../../python-labnet/labs/busygasper/downloads/update.apk).

El fichero es el ZIP/APK inerte de la emulación: contiene `AndroidManifest.xml` y un `classes.dex` con un marcador del laboratorio, no un DEX ejecutable verificado. Se preserva sin alteraciones; la captura acredita la transferencia emulada, no una instalación o ejecución exitosa. El contexto de la orden que la inició permanece en el original y en la vista IRC.

## 3. Transformaciones y verificación

No se trasplantan handshakes ni se añaden paquetes. Tampoco se resegmenta, se cambia el contenido o se alteran SEQ/ACK, direcciones, puertos, opciones TCP, longitudes o timestamps.

Los 55 paquetes originales presentan checksums de transporte parciales de offloading. Se comprueba que cada valor coincide con la suma de su pseudocabecera y se completa en la copia: **23 checksums en Bidirectional** —21 TCP y dos UDP— y **32 TCP en Download**. Estos campos de dos bytes son las únicas modificaciones de los paquetes seleccionados.

Los `.procedencia.json` contienen el mapeo entre tramas originales y de salida, hashes y cambios exactos. La [verificación](verificacion.json) confirma reconstrucción byte a byte desde esos registros, handshakes y cierres completos, continuidad de secuencias, ACK coherentes, checksums IPv4/TCP/UDP válidos, separación de canales, igualdad de los datos de aplicación y hash del fichero transferido. No aparecen tramas mayores de 4000 B, paquetes malformados ni avisos `tcp.analysis.flags`.

El MCP de Wireshark confirma la orden y respuesta IRC, la negociación FTP y su transferencia de 320 bytes. El análisis experto del derivado FTP no muestra errores ni advertencias. No se han reproducido las copias en NGFW ni Snort en esta fase.

SHA-256 del original, comprobado antes y después: `9d64d93ec36067e67846a7ee5c50b338643bee3898bd8bddffabffcbde108adf`.

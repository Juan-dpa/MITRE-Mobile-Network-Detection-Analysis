# DressCode: proxy y explotación separados

Preparación y verificación: 25 de octubre de 2026. Original: [S0300-DressCode.pcap](../../../PCAPs/LabsAndroidStudio/S0300-DressCode/S0300-DressCode.pcap), sin modificar. Los números de trama y stream se refieren al original salvo indicación contraria.

| Archivo | Contenido | Paquetes | Máximo de trama |
|---|---|---:|---:|
| [Proxy T1604](S0300-DressCode-T1604-proxy.pcap) | Resolución del C2, apertura de SOCKS y SMTP, saludo y EHLO sin ataque | 43 | 97 B |
| [Explotación T1428](S0300-DressCode-T1428-explotacion.pcap) | Conexión SMTP completa de la víctima al objetivo | 26 | 105 B |

Son derivados del PCAP existente, no capturas de una nueva ejecución. El origen observado `172.22.0.1` corresponde al extremo del emulador visible tras la traducción de red del laboratorio.

## Corte del proxy

La orden `CREATE` está en la trama 46. Las tramas 49–51 establecen el TCP del túnel y la 52 contiene SOCKS4 CONNECT a `10.230.30.25:25`. El TCP hacia SMTP se establece en 55–57; la respuesta SOCKS4 concedida aparece en 58. El saludo SMTP se recibe en 60 y se retransmite al operador en 61.

Antes de cortar se conserva también una operación normal: `EHLO attacker.lab`, transmitida por el túnel en 63 y por la conexión SMTP en 64. La respuesta completa termina en 70 y llega al operador en 71, que la confirma en 72. Esto conserva evidencia de retransmisión en ambos sentidos.

El primer contenido malicioso es `MAIL FROM:<;sleep 66;>`: trama 73 del túnel y 74 de SMTP. Ninguna de las dos cargas se conserva en el PCAP del proxy. Tampoco se incluyen las respuestas ni los textos posteriores que mencionan la explotación.

La selección incluye los cuatro paquetes DNS iniciales de `dfm.nicsm.net` —15–18— y los streams TCP 0, 1 y 2 hasta la trama 72. Se excluyen las demás conversaciones DNS/mDNS y el segundo intento de control/proxy posterior a la explotación.

## ACK separado del ataque

Al terminar la trama 72, la última parte de la respuesta EHLO ya ha llegado al operador, pero su confirmación TCP en el tramo víctima–SMTP aparece junto al ataque en la trama 74.

La última trama del PCAP del proxy, número 43, es un **ACK sintetizado a partir de la trama original 74**. Conserva direcciones, puertos, SEQ, ACK, ventana y timestamp. Se retiran los 24 bytes del `MAIL FROM` y el flag PSH; se ajustan las longitudes y los checksums IPv4/TCP. No contiene datos de aplicación ni cierra la conexión.

El ACK final tiene SEQ relativo 20 y ACK 89: confirma los 88 bytes enviados hasta ese punto por SMTP, contando el SYN aparte. No se confirman bytes de la explotación ni se modifican secuencias de paquetes anteriores.

Al terminar la copia, los streams SOCKS y SMTP quedan abiertos y todos sus datos están confirmados. El stream 0 de control C2 conserva su cierre original, completado en las tramas 53–54: ya había ordenado abrir el túnel y no transporta el tráfico SMTP posterior. No se reabre artificialmente ni se añaden FIN/RST.

## SOCKS en TCP/1080

Se aplica la elección previa de TCP/1080 para SOCKS mediante una transformación documentada de la copia:

- Se cambia `CREATE,10.230.30.20,9002` por `CREATE,10.230.30.20,1080` en la trama 46, conservando el salto de línea.
- Se cambia el puerto del operador de 9002 a 1080 en los 13 paquetes del stream 1 seleccionados, en ambos sentidos, incluidos los handshakes.
- Se recalculan los checksums afectados. Ambos números tienen cuatro dígitos, por lo que el mensaje conserva su longitud y no es necesario ajustar SEQ/ACK.

La petición SOCKS sigue solicitando el objetivo SMTP/25. Se conserva el carácter inverso del proxy: la víctima inicia TCP hacia el operador, y este envía la petición SOCKS. El control C2/9001 conserva el puerto de la muestra. La modificación a 1080 no se presenta como tráfico obtenido en una nueva ejecución del APK.

## Explotación aislada

Se conserva íntegramente `tcp.stream == 2`, con 26 paquetes. En la copia pasa a ser el stream 0. No se incluyen el C2 ni el túnel que transporta otra copia del ataque.

El handshake original 55–57 aparece como tramas 1–3 de la salida. Las nueve tramas originales 55, 56, 57, 60, 64, 65, 66, 69 y 70 aportan el establecimiento, saludo y EHLO anteriores al ataque; se conservan aunque también formen parte de la preparación del proxy. La trama original 74 aparece como trama 10, con el `MAIL FROM` intacto. El resto de la transacción SMTP y los cierres originales 97, 98, 104 y 105 también se conservan.

En este archivo solo se completan 13 checksums TCP parciales de offloading. El contenido SMTP, las secuencias, las opciones TCP y los tiempos no cambian. No se trasplantan ni inventan handshakes. Las respuestas describen la explotación controlada del servicio emulado; no acreditan un compromiso real.

## Verificación y procedencia

Se verificaron los tres requisitos: separación del ataque respecto a la preparación del proxy, handshake inicial completo en cada flujo relevante y ninguna trama superior a 4000 B. No hizo falta resegmentar.

Además se comprobaron continuidad de secuencias y ACK, checksums IPv4/TCP/UDP, correspondencia de los bytes retransmitidos entre SOCKS y SMTP y estados finales. TShark 4.6.5 no mostró avisos de análisis TCP ni paquetes malformados. El MCP de Wireshark confirmó la orden CREATE con 1080, el intercambio SOCKS sin ataque, los handshakes y el contenido de la explotación.

Los archivos `.procedencia.json` contienen hashes, el mapa completo de tramas/streams y los cambios de bytes con offsets. Aplicando estos cambios por orden a los registros originales seleccionados, y ajustando las longitudes del registro del ACK derivado, se reproducen las copias. La inversión de cada cambio reconstruyó exactamente la trama original. No se alteraron timestamps.

[verificacion.json](verificacion.json) recoge las comprobaciones independientes. El SHA-256 del original permanece en `960160ec184db42e9083ed5d9ae541f6820a8b8945a07cd1f071e8d4c2860d81`. La reproducción en NGFW/Snort corresponde a la fase experimental posterior.

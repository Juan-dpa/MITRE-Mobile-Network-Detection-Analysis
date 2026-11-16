# NotCompatible: proxy y explotación separados

Preparación y verificación: 25 de octubre de 2026. Original: [S0299-NotCompatible.pcap](../../../PCAPs/LabsPython/S0299-NotCompatible/S0299-NotCompatible.pcap), sin modificar. Los números de trama siguientes corresponden al original salvo indicación contraria.

| Archivo | Selección del original | Paquetes | Máximo de trama |
|---|---|---:|---:|
| [Proxy T1604](S0299-NotCompatible-T1604-proxy.pcap) | Tramas 1–38 | 38 | 336 B |
| [Explotación T1428](S0299-NotCompatible-T1428-explotacion.pcap) | Streams TCP 2 y 3 completos | 25 | 105 B |

## Punto de separación

En la trama 29, el C2 solicita abrir la conexión al FTP. Las tramas 30–32 establecen esa conexión TCP. El servidor envía su saludo en la 34, la víctima lo retransmite al C2 en la 37 y este lo confirma en la 38. Ahí termina el primer PCAP. La trama 39 contiene el primer mensaje de ataque por el canal C2; la 40 lleva ese mismo contenido al FTP.

El PCAP del proxy conserva los canales operativos C2 y FTP abiertos, sin FIN/RST y con todos los bytes enviados confirmados. El stream 0, correspondiente al gateway inicial, tiene su cierre original: su función de entregar el C2 operativo ya había terminado. No es uno de los canales que deban permanecer abiertos al llegar al corte. No hay órdenes FTP de explotación ni conexión a 6200 en este archivo.

## Explotación y handshakes

Según la opción acordada, el segundo PCAP conserva únicamente las conexiones de salida de la víctima al objetivo: FTP/21 y el servicio emulado/6200. El canal C2 queda fuera. Retenerlo habría exigido repetir también su negociación RSA/RC4 y el contexto anterior del proxy; copiar únicamente sus tres paquetes del handshake TCP no bastaba.

Se incluyen las 15 tramas del FTP y las 10 del servicio 6200, en su orden y con sus tiempos originales. Los streams originales 2 y 3 pasan a ser 0 y 1 en la copia.

- Las tramas originales 30, 31 y 32 son el handshake FTP; aparecen como tramas 1, 2 y 3 del segundo PCAP.
- Las originales 34 y 35 son el saludo FTP y su ACK; aparecen como 4 y 5. Son contexto necesario anterior al ataque.
- La original 40, primer envío de ataque al FTP, aparece como trama 6.
- Las originales 55, 56 y 57 forman el handshake del servicio 6200; aparecen como 13, 14 y 15. Esta conexión se establece durante la explotación.

Las cinco tramas FTP anteriores al corte se incluyen en ambos PCAPs. No se sintetizan handshakes, no se renumeran secuencias TCP y no se cambian tiempos. Los cierres reales de los dos flujos de explotación se conservan. El original representa una explotación controlada sobre un servicio emulado.

## Cambios y comprobaciones

La única modificación de bytes dentro de las tramas seleccionadas consiste en completar sus checksums TCP parciales de offloading: 38 en el proxy y 25 en la explotación. Antes de corregir cada uno se comprobó que coincidía con la suma parcial de la pseudocabecera IP. No hay resegmentación ni cierres añadidos.

Se comprobaron los handshakes de todas las conexiones, continuidad de secuencias, ACK, estado al final, checksums IPv4/TCP y ausencia de tramas superiores a 4000 B. El descifrado local del C2 permitió confirmar el corte antes del primer comando de ataque y la retransmisión del saludo FTP; no se publican las claves en los informes. TShark y el MCP de Wireshark contrastaron las capturas resultantes y las conversaciones extraídas.

La comparación binaria confirmó que, al revertir los dos bytes de checksum TCP, cada registro vuelve a ser idéntico al registro original, incluidos cabeceras y tiempos. No aparecieron avisos de análisis TCP ni paquetes malformados en las copias. El SHA-256 del original sigue siendo `e2fcbc7b4c852f108589a7a7dac0d79523bef23c7d3ac48bc4e87002471fd5ee`.

Cada archivo `.procedencia.json` contiene el hash de la copia, el mapa de tramas y streams, y los valores anterior y posterior de cada checksum. Esa información permite reproducir la transformación seleccionando los registros indicados y aplicando únicamente los cambios de checksum registrados. [verificacion.json](verificacion.json) recoge las comprobaciones independientes. La reproducción en NGFW/Snort corresponde a la fase experimental posterior.

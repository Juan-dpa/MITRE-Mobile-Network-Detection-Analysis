# FluBot: proxy y explotación separados

Preparación y verificación: 10 de noviembre de 2026. Derivados del [PCAP original](../../../PCAPs/LabsPython/S1067-FluBot/S1067-FluBot.pcap), sin modificarlo ni volver a ejecutar el laboratorio. Las referencias a tramas y streams corresponden al original salvo indicación contraria.

| Archivo | Técnica objetivo | Selección | Paquetes | Trama máxima |
|---|---|---|---:|---:|
| [Proxy](S1067-FluBot-T1604-proxy.pcap) | T1604 | Tramas 1–78 | 78 | 488 B |
| [Explotación](S1067-FluBot-T1428-explotacion.pcap) | T1428 | Stream TCP 5 completo | 31 | 127 B |

## 1. Proxy establecido y funcional

El primer archivo conserva la resolución del C2, las tres conversaciones HTTP iniciales y la apertura del relé inverso. Las peticiones del panel son `PREPING`, `GET_INJECTS_LIST` y `PING`; sus respuestas son `NONE,`, un nombre de paquete y la orden `SOCKS,gurbngbcxheshsj.ru:9000`. No se descarga código en esas transacciones. Se conserva íntegra su protección RSA/XOR, sin sustituir el contenido por texto en claro.

El corte se realiza después del ACK de la trama 78:

| Tramas | Operación conservada |
|---|---|
| 52–54 | Handshake del canal de control, víctima → C2/9000 |
| 55–62 | Saludo de control y anuncio del puerto del subcanal |
| 65–67 | Handshake del subcanal SOCKS, víctima → C2 |
| 68–69 | Petición SOCKS4 CONNECT a `10.106.7.20:21` y ACK |
| 70–72 | Handshake de la conexión víctima → FTP |
| 73–74 | Respuesta SOCKS4 positiva `00 5a 00 00 00 00 00 00` y ACK |
| 75–76 | Saludo del FTP y ACK de la víctima |
| 77–78 | Retransmisión del mismo saludo por SOCKS y ACK del C2 |

Al terminar, los streams 3, 4 y 5 permanecen abiertos y todos los bytes enviados en ambos sentidos están confirmados. No se añaden cierres. Los tres streams HTTP anteriores conservan sus cierres originales, ya que sus transacciones han terminado.

La trama 79 comienza la autenticación FTP a través del túnel y queda fuera de este primer archivo. La explotación aparece más tarde: `SITE CPFR` en 104 por el túnel y en 105 hacia FTP; `SITE CPTO` en 110 y 111, respectivamente. Ninguno de esos comandos ni sus respuestas se incluye en el PCAP del proxy.

## 2. SOCKS en TCP/1080

El laboratorio eligió 4444 para el subcanal SOCKS; la muestra admite el puerto recibido por el canal de control. Se aplica en la copia la misma elección de 1080 utilizada para DressCode:

- En los nueve paquetes seleccionados del stream 4 se cambia el puerto del C2 de 4444 a 1080, en ambos sentidos y desde el handshake.
- En la trama 61 se cambia el anuncio binario del puerto: `11 5c` pasa a `04 38`, ambos enteros de dos bytes en big-endian.
- Se recalculan los checksums de transporte afectados.

La longitud del mensaje no cambia y no hace falta reajustar SEQ/ACK. La petición SOCKS sigue indicando el destino FTP/21. El canal de control conserva TCP/9000 y su protocolo propio, distinto de la negociación SOCKS4 del subcanal. Tampoco cambia la orden cifrada del panel que apunta a ese canal de control.

No se asignan técnicas acompañantes a las entregas. Se elimina el uso de SOCKS/4444 que sustentaba T1509 en este escenario; el número de puerto del control propietario no se etiqueta automáticamente como otra manifestación de esa técnica. La transformación se documenta como modificación del PCAP original, no como una captura nueva ni como un puerto histórico fijo de FluBot.

## 3. Explotación aislada

Se conserva únicamente `tcp.stream == 5`: la conversación entre `10.106.7.10:33762` y `10.106.7.20:21`. En la copia pasa a ser el stream 0. Sus 31 paquetes están intercalados con los del túnel en el original; no se toma indiscriminadamente el intervalo temporal 70–130.

| Contenido | Tramas originales | Posición en la copia |
|---|---|---|
| Handshake TCP | 70–72 | 1–3 |
| Saludo FTP y ACK | 75–76 | 4–5 |
| Autenticación, SYST y PWD con sus respuestas | Paquetes del stream 5 entre 80 y 101 | 6–18 |
| `SITE CPFR`, respuesta y ACK | 105–107 | 19–21 |
| `SITE CPTO`, respuesta y ACK | 111–113 | 22–24 |
| QUIT, respuesta y ACK | 117–119 | 25–27 |
| FIN del servidor, ACK, FIN de la víctima y ACK final | 120, 125, 128, 130 | 28–31 |

Se preservan los 113 bytes enviados por la víctima y los 279 del servidor. El archivo no incluye el panel ni el túnel que transportaba otra copia del ataque. Tampoco necesita copiar handshakes de esos canales: el FTP ya tiene el suyo y se conserva desde el inicio.

Las cinco tramas 70, 71, 72, 75 y 76 aparecen en ambos PCAPs como contexto compartido de establecimiento y saludo FTP. Esa coincidencia no incorpora explotación al archivo del proxy. No se sintetizan paquetes ni se cambian los tiempos.

El objetivo es el servicio Python emulado del laboratorio. Se mantiene la conversación de explotación controlada existente; sus respuestas no se presentan como evidencia de compromiso de un servidor real.

## 4. Transformaciones, procedencia y verificación

Además de los cambios de puerto anteriores, se completan los checksums parciales de offloading: 78 en el proxy y 30 en la explotación. El paquete restante de la explotación ya tiene un checksum completo válido y se conserva. Antes de corregirlos se comprueba que los valores parciales coinciden con la suma de su pseudocabecera.

Se preservan las cabeceras global y de registro del PCAP, timestamps, longitudes, direcciones, opciones TCP, SEQ/ACK, flags y contenido, con la única excepción de los dos bytes del puerto anunciado en la trama 61. No hay resegmentación, trasplante de handshakes ni cierres añadidos.

Cada `.procedencia.json` contiene hashes, selección, mapa de tramas y cambios exactos con offsets. Aplicar esos cambios a los registros originales reproduce las copias; invertirlos reconstruye cada trama original. La [verificación](verificacion.json) recoge:

- Handshakes completos en todos los flujos, sin huecos ni solapamientos de secuencia ni ACK adelantados.
- Todos los datos y FIN conservados confirmados; los tres canales operativos del proxy abiertos y el FTP de explotación cerrado.
- Checksums IPv4/TCP/UDP matemáticamente válidos y ninguna trama superior a 4000 B.
- Coincidencia del puerto anunciado con las cabeceras SOCKS, respuesta de conexión concedida y saludo FTP retransmitido íntegro.
- Contenido cifrado del panel conservado y comprobado mediante el material de análisis local, sin publicar claves.
- Confirmación de flujos, secuencias y puertos por TShark; ausencia de avisos de análisis TCP, paquetes malformados y checksums incorrectos.
- Inspección mediante el MCP de Wireshark del control, SOCKS y FTP; sin errores ni advertencias en Expert Info.

El SHA-256 del original, comprobado antes y después, permanece en `17167c7a3edf389b9ae817ecf3881f7563761b36fcf256ef3a78693d49803326`. No se ha reproducido el tráfico en NGFW/Snort en esta fase.

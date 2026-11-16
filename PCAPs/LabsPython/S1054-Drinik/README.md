# Drinik: One-Way y descarga separados

Preparación y verificación: 26 de octubre de 2026. Derivados del [PCAP original](../../../PCAPs/LabsPython/S1054-Drinik/S1054-Drinik.pcap), sin modificarlo ni volver a ejecutar el laboratorio. Las referencias a tramas y streams corresponden al original salvo indicación contraria.

| Archivo | Técnica objetivo | Contenido | Paquetes | Trama máxima |
|---|---|---|---:|---:|
| [One-Way](S1054-Drinik-T1481.003-one-way.pcap) | T1481.003 | Registro, FCM y confirmaciones HTTP al panel; sin transferencia de la APK | 136 | 2719 B |
| [Download](S1054-Drinik-T1407-download.pcap) | T1407 | Conexión HTTP completa entre víctima y servidor de descarga | 12 | 1132 B |

No se asignan técnicas acompañantes. Las selecciones son disjuntas y conservan, entre ambas, los 148 paquetes originales. Se separan conexiones completas; no se trasplantan handshakes ni se reajustan SEQ/ACK.

## 1. One-Way: tramas 1–100 y 113–148

Se mantienen los streams originales **0, 1, 2, 3, 4, 5, 7 y 8**, además de sus 16 paquetes DNS. Los streams originales 7 y 8 pasan a numerarse 6 y 7 en la copia.

| Función | Streams originales | Evidencia conservada |
|---|---|---|
| Registro Firebase y obtención del token | 0–1 | Conexiones HTTPS completas y DNS |
| Entrega de la orden por FCM | 2 | Canal TLS `mtalk` en 5228, desde su handshake y establecimiento hasta el estado final capturado |
| Comunicación del token al panel | 3 | POST `CMD=Token` a `/iaserver.php` |
| Publicación de la orden por el operador | 4 | Petición HTTPS a la API FCM `messages:send` y su respuesta |
| Confirmación de la orden | 5 | POST `insertServerCMD` con el resultado de `DOWNLOADAPK` |
| Confirmaciones posteriores | 7–8 | `firstDownloadCompleted!` y confirmación de `SendMessage` al panel HTTP |

La orden `DOWNLOADAPK:::http://192.3.124.14/AApk.apk` llega por FCM. Los resultados funcionales vuelven al panel propio `198.12.107.13:80`, por `/iaserver.php`. Esa distribución conserva One-Way Communication; los ACK o respuestas técnicas de FCM no convierten el retorno funcional en bidireccional por ese servicio.

La copia conserva las referencias a la descarga en la orden y en sus confirmaciones, pero no contiene ninguna conexión al servidor `192.3.124.14` ni los bytes de la APK. Es una vista del C&C del escenario original, no una nueva ejecución sin descarga. La clasificación de las alertas que produzcan esas referencias dependerá de las reglas del detector.

La captura original también observa la publicación operador–FCM, además del tráfico de la víctima. Se conserva ese punto de observación; no se atribuye a la APK la petición que publica el operador.

El stream 2 conserva su **semicierre original**: FIN de la víctima en 86 y ACK del servidor en 144, que pasa a la posición 132 en la copia. No aparece FIN del servidor y no se añade uno. Los otros siete streams conservan sus cierres de ambos extremos. La negociación, los registros TLS y los mensajes de aplicación se mantienen íntegros. El descifrado de verificación con el [registro de claves original](../../../PCAPs/LabsPython/S1054-Drinik/keys/drinik-sslkeys.log) coincide con el original en las cuatro conversaciones TLS; los secretos no se copian a los informes.

No se añade T1509 por el puerto 5228, propio del servicio de entrega de Google utilizado en este escenario.

## 2. Download: tramas 101–112

Se extrae íntegro el **stream TCP original 6**, entre `10.105.4.10:33284` y `192.3.124.14:80`. En la copia es el único stream TCP, con índice 0.

| Tramas originales | Operación | Posición en la copia |
|---|---|---|
| 101–103 | Handshake TCP original | 1–3 |
| 104–105 | `GET /AApk.apk` y ACK | 4–5 |
| 106–109 | Respuesta HTTP 200, cuerpo y ACK | 6–9 |
| 110–112 | FIN/ACK de ambos extremos y ACK final | 10–12 |

La copia no contiene FCM, tráfico del panel ni DNS. La URL utiliza una IP literal y no hay una resolución DNS de ese servidor en el original.

El cuerpo de la respuesta conserva **1066 bytes**, con SHA-256 `4009bcb0c979225863e210dc1710a5751f4fee01be31a305434e68f1ca76d028`. Coincide byte a byte con el original y con la constante `APK_BYTES` del [servidor del laboratorio](../../../python-labnet/labs/drinik/source/drinik_emulator/download_server.py).

Ese contenido es un sustituto sintético de APK: incluye la firma inicial `PK`, marcadores del laboratorio y relleno, pero no forma un ZIP/APK válido e instalable. Se conserva tal como fue generado; esta separación no cambia la naturaleza del artefacto ni acredita instalación o ejecución.

## 3. Transformaciones y verificación

Los únicos bytes modificados son los checksums de transporte. Los 148 paquetes originales contienen sumas parciales de offloading; se verifica su coincidencia con la suma de la pseudocabecera antes de completarlas. Se corrigen **136 checksums en One-Way** —120 TCP y 16 UDP— y **12 TCP en Download**.

Se preservan cabeceras IP, direcciones, puertos, opciones TCP, SEQ/ACK, flags, longitudes, datos de aplicación, timestamps y cabeceras de registro PCAP. No se generan paquetes ni se resegmenta: todas las tramas cumplen el límite de 4000 B.

Wireshark conserva ocho notas de longitud superior al MSS negociado en el archivo One-Way, heredadas de los paquetes originales; el máximo de trama es 2719 B. No se han modificado esos tamaños en esta separación. Esta comprobación del límite de 4000 B no equivale a validar una MTU concreta de reproducción.

Los `.procedencia.json` recogen selección, posiciones de salida, hashes y cambios exactos. La [verificación](verificacion.json) confirma reconstrucción byte a byte desde esos registros, checksums IPv4/TCP/UDP completos, handshakes, ausencia de huecos de secuencia y ACK adelantados, integridad de los datos, descifrado TLS equivalente y separación de conexiones. No aparecen paquetes malformados ni avisos `tcp.analysis.flags`.

El MCP de Wireshark confirma las conexiones de One-Way, el ACK tardío de `mtalk` y la transacción HTTP de descarga. No se han reproducido las copias en NGFW ni Snort en esta fase.

SHA-256 del original, comprobado antes y después: `ad497812d993135804f0441ee56d366f4f8392518c5cdc0375bbd5b4c8cee9e2`.

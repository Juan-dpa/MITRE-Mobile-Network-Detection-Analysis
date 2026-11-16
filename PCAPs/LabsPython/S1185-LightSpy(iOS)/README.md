# LightSpy: descarga y C&C separados

Preparación y verificación: 10 de noviembre de 2026. Derivados del [PCAP original](../../../PCAPs/LabsPython/S1185-LightSpy(iOS)/S1185-LightSpy(iOS).pcap), sin modificarlo ni volver a ejecutar el laboratorio. Las referencias a tramas y streams corresponden al original salvo indicación contraria.

| Archivo | Técnica objetivo y acompañante | Selección original | Paquetes originales → tratados | Trama máxima final |
|---|---|---|---:|---:|
| [Descarga](S1185-LightSpy-T1407-descarga-T1509.pcap) | T1407 + T1509 | Tramas 1–203; streams TCP 0–16 | 203 → 267 | 1514 B |
| [C&C](S1185-LightSpy-T1509-c2.pcap) | T1509 dentro de las técnicas seleccionadas para el estudio | Tramas 204–458; streams TCP 17–27 y dos paquetes DNS | 255 → 652 | 1514 B |

Las selecciones son disjuntas y, entre ambas, conservan los 458 paquetes originales, representando cada trama resegmentada mediante sus nuevos segmentos. No se elimina tráfico, se sintetizan cierres ni se trasplantan handshakes. Se mantienen los puertos 8088 y 50000 documentados en la muestra.

## 1. Descarga: T1407 con T1509

El primer archivo contiene las diecisiete conexiones HTTP completas entre la víctima `10.118.5.10` y `45.83.237.13:8088`. Las primeras dieciséis transfieren los cuerpos que representan los componentes del laboratorio; la última transfiere el fichero auxiliar `ircbin.plist`.

Las descargas conservadas son `browser`, `EnvironmentalRecording`, `FileManage`, `ios_qq`, `ios_telegram`, `ios_wechat`, `KeyChain`, `light`, `Screenaaa`, `ShellCommandaaa`, `SoftInfoaaa`, `WifiList`, `locationaaa.dylib`, `baseinfoaaa.dylib`, `irc_loader`, `launchctl` e `ircbin.plist`. El plist acompaña al despliegue; no se presenta por sí solo como descarga de código.

Todas las respuestas son HTTP 200 y conservan sus longitudes y cuerpos. Los dieciséis componentes tienen 8192 bytes cada uno y el plist capturado tiene 179 bytes. Los hashes de los diecisiete cuerpos coinciden con el original y con el registro del cliente de esa ejecución. El laboratorio utiliza sustitutos sintéticos e inertes de los componentes; la separación no modifica su naturaleza ni acredita ejecución de los Mach-O originales.

Los streams conservan sus índices 0–16. Cada uno mantiene su handshake y cierre TCP originales. La última conexión termina en la trama original 203, antes del comienzo de las conexiones del C&C. No se divide cada transferencia en un ensayo distinto, porque todas representan la misma técnica objetivo.

El puerto 8088 procede de la URL integrada en `095`, según el [análisis local](../../../Documentos/Markdowns/S1185-LightSpy(iOS).md). Se conserva T1509 como acompañante del canal HTTP de descarga.

## 2. C&C: T1509 sin la transferencia de código

El segundo archivo conserva las once conexiones TCP/TLS a `45.134.1.180:50000`. Los streams originales 17–27 pasan a numerarse 0–10 en la copia.

| Streams originales | Función |
|---|---|
| 17, 18, 20, 21, 22, 24 y 25 | Peticiones HTTPS de registros a `/api/log/` |
| 19 | Canal WSS persistente: actualización HTTP 101, configuración, manifiesto, órdenes y resultados |
| 23 | Petición HTTPS con información del dispositivo a `/api/phone/` |
| 26 y 27 | Dos subidas HTTPS a `/api/phone_shard_file` |

Se mantienen también la consulta y respuesta DNS de `www.baidu.com`, tramas originales 204 y 211, como parte de la comprobación de conectividad del escenario. No resuelven el C2 ni representan un Dead Drop Resolver; los servidores de descarga y C&C se contactan por IP literal.

El manifiesto recibido por WSS contiene una URL de `ios_wechat`, pero no se produce una nueva descarga en esta fase. La comprobación del contenido TLS confirma que el GET de WSS corresponde a su actualización de protocolo y que el resto son POST a las API del C2. Por tanto, esta vista conserva el canal de control y sus acciones posteriores sin incorporar la transferencia T1407 del primer archivo. No se describe como un canal sin actividad: incluye información del dispositivo, órdenes y resultados del laboratorio.

Las dos subidas transportan 409600 y 190400 bytes, respectivamente, desde la víctima hacia el C2. Se conservan sus offsets 0 y 409600, las respuestas que indican 409600 y 0, y los 600000 bytes del resultado inerte. Su SHA-256 es `23eef78b0e27ad4d2060207b9b1a269740ce3110eff51efadec672b8edd1ebee`, idéntico al original y al fichero del laboratorio.

El puerto 50000 procede de la configuración de `irc_loader` entregada al núcleo `light`; no se sustituye por 443. Todas las conexiones conservan su establecimiento TCP/TLS y su cierre. El canal WSS se mantiene íntegro, sin cortar registros TLS ni reconstruir su estado criptográfico.

## 3. Resegmentación TCP

El original contiene 37 tramas mayores de 4000 B: dieciséis en los streams HTTP 0–15 y veintiuna en los streams TLS 26–27. Su máximo es 65226 B. Se resegmentan únicamente esas tramas; las restantes conservan sus límites originales.

Se utiliza una longitud máxima de paquete IPv4 de 1500 B. Las cabeceras de las tramas afectadas ocupan 20 B de IPv4 y 32 B de TCP, por lo que cada nuevo segmento lleva como máximo 1448 bytes de datos TCP. Esto respeta el MSS 1460 negociado y produce tramas Ethernet de hasta 1514 B, sin FCS capturado.

Para cada trama grande:

- Se divide su carga TCP en intervalos consecutivos, sin eliminar ni sustituir bytes.
- El SEQ de cada segmento es el SEQ original más el desplazamiento de su carga. Se preservan ACK, ventana y opciones TCP.
- El flag PSH se conserva únicamente en el último segmento derivado; ACK permanece en todos.
- Se ajustan las longitudes IPv4 y del registro PCAP, y se recalculan los checksums IPv4 y TCP.
- Los segmentos se insertan consecutivamente con el mismo timestamp de la trama original, antes del siguiente registro original.

Se preservan direcciones MAC/IP, puertos, TTL, identificador IPv4 y flag DF. Todas las tramas resegmentadas tenían DF activo, que se mantiene; no se introduce fragmentación IP. Ninguna trama SYN, FIN o RST se divide ni se añade. El orden de bytes de HTTP y de los registros TLS permanece intacto.

Además, se completan los checksums parciales de transporte de los paquetes seleccionados, comprobando antes su coincidencia con la suma de la pseudocabecera. En la salida de descarga cambian 267 checksums de transporte y en la del C&C 651; el paquete restante del C&C ya tenía un checksum válido y se conserva.

## 4. Verificación y anomalía original conservada

La [verificación](verificacion.json) confirma:

- Handshakes completos en las 28 conexiones TCP y cierres de ambos extremos confirmados.
- Ausencia de huecos de datos, solapamientos contradictorios y ACK que confirmen bytes no observados.
- Igualdad de los bytes reconstruidos de cada trama original y de cada sentido de cada stream.
- Checksums IPv4/TCP/UDP matemáticamente válidos, tamaños IPv4 ≤1500 B y cero tramas superiores a 4000 B.
- Coincidencia de los diecisiete cuerpos HTTP con la captura original y los hashes registrados por el cliente.
- Descifrado idéntico, en ambos sentidos, de las once conversaciones TLS mediante el [registro de claves original](../../../PCAPs/LabsPython/S1185-LightSpy(iOS)/keys/lightspy-sslkeys.log), sin copiar claves a los informes.
- Conservación exacta de los dos fragmentos de subida y de su contenido conjunto de 600000 bytes.
- Concordancia de TShark con los streams, SEQ/ACK y longitudes; ninguna trama malformada ni checksum incorrecto.
- Inspección mediante el MCP de Wireshark de las peticiones HTTP, handshakes y Expert Info de ambas copias.

El C&C conserva la retransmisión de FIN de la trama original 359 y su D-SACK/ACK ambiguo en 360, que aparecen como 156 y 157 en la copia. El primer FIN estaba en 354, que pasa a 151. Se trata del mismo cierre retransmitido, sin pérdida de datos; el cierre termina correctamente. No se elimina esta evidencia del original ni se interpreta como un defecto introducido por la resegmentación. Las notas de tamaño superior al MSS desaparecen y no aparecen nuevas anomalías de análisis TCP.

El plist actual del directorio de payloads tiene saltos de línea CRLF, mientras que el capturado tiene LF. Sus diferencias se limitan a esos saltos; se conservan los 179 bytes capturados, que coinciden con el hash del registro original. No se sustituye el cuerpo del PCAP por la versión actual del fichero.

## 5. Procedencia y límites

Cada `.procedencia.json` recoge hashes, selección, correspondencia entre tramas originales y segmentos de salida, intervalos de carga y cambios de cabecera con offsets. Aplicar esas instrucciones a los registros originales reproduce exactamente las copias. La verificación comprueba también la inversión de los cambios y la reconstrucción de la carga de cada trama original a partir de sus segmentos.

Se conserva la cabecera global PCAP y todos los timestamps originales. El SHA-256 del original, comprobado antes y después, permanece en `bc0b1f6aaca8bff170d20e70d3a8aeda628bccf7220f930fccdda4c09879d724`.

Estas comprobaciones validan las transformaciones de los PCAPs. No se ha reproducido tráfico en NGFW/Snort ni se ha ejecutado la muestra o el laboratorio en esta fase.

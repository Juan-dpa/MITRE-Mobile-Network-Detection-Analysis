# XLoader: resolver, descarga, proxy y explotación

Preparación y verificación: 25 de octubre de 2026. Se trabaja sobre derivados del [PCAP original](../../../PCAPs/LabsAndroidStudio/S0318-XLoaderForAndroid/S0318-XLoaderForAndroid.pcap), que no se modifica. No se ha vuelto a ejecutar la muestra. Las referencias a tramas y streams siguientes corresponden al original salvo indicación contraria.

| Archivo | Contenido | Paquetes | Trama máxima |
|---|---|---:|---:|
| [Dead Drop Resolver — T1481.001](S0318-XLoader-T1481.001-resolver.pcap) | DNS de Twitter y conexión HTTPS que devuelve el extremo C2 | 18 | 1345 B |
| [Descarga — T1407 + T1509](S0318-XLoader-T1407-descarga-T1509.pcap) | `getPkgMap`, `getPkgData` y sus respuestas, incluida la APK | 21 | 1514 B |
| [Proxy — T1604 + T1509](S0318-XLoader-T1604-proxy-T1509.pcap) | Orden `http` y su resultado, únicamente entre C2 y víctima | 11 | 419 B |
| [Explotación — T1428](S0318-XLoader-T1428-explotacion.pcap) | Conexión HTTP completa entre víctima y objetivo | 10 | 224 B |

T1509 permanece como acompañante en las dos copias que contienen el C2 en TCP/28833. Ningún archivo contiene tramas superiores a 4000 B.

## 1. Dead Drop Resolver

Se seleccionan las tramas **2–19**: DNS AAAA/A de `twitter.com` en 2–5 y TCP stream 0 completo en 6–19. El handshake TCP 6–8 y la negociación TLS se conservan antes del tráfico cifrado.

La comprobación con el registro de claves TLS original confirma `GET /sdfghuio342`, HTTP 200 y un cuerpo de 150 bytes. La decodificación CJK del título devuelve `1.162.98.240:28833`. Se excluye el stream 2, cuya consulta `/fdgoer343` proporciona la URL del WebView, y se excluye la conexión posterior al C2.

Se conservan el FIN del servidor en 16, su ACK en 17, el `close_notify` del cliente en 18 y el RST terminal en 19. No se añade otro cierre. Solo se completan los ocho checksums de transporte parciales de offloading detectados; el contenido TLS no cambia. El [registro de claves TLS](../../../PCAPs/LabsAndroidStudio/S0318-XLoaderForAndroid/keys/xloader-sslkeys.log) permanece con los originales; no se copian sus secretos a los informes.

## 2. Descarga de código

Selección antes de resegmentar: **20–22, 84–89 y 107–111**. Los tres primeros paquetes son el handshake original del canal C2. Se retiran los mensajes iniciales de registro/estado y toda la operación `http` posterior.

| Tramas originales | Mensaje conservado |
|---|---|
| 84 / 85 | `getPkgMap`, ID 11, y respuesta con el mapa de paquetes |
| 86 / 87–88 | `getPkgData`, ID 12, y respuesta con la APK |
| 89 | ACK de los datos recibidos |
| 107–111 | Terminación del C2, reutilizada y ajustada a esta selección |

Las tramas 87 y 88 contienen conjuntamente **una única trama de aplicación RFC 6455** de 12 787 bytes. Se dividen únicamente sus segmentos TCP: 87 genera cinco segmentos y 88 genera cuatro, con un máximo de 1460 bytes de carga TCP, conforme al MSS negociado. El resultado tiene 21 paquetes y un máximo de 1514 bytes de trama Ethernet.

No se recodifica MessagePack ni se altera la APK: conserva **12 755 bytes**, con SHA-256 `4896291f416fbbce50775c258d3f72c7d5c0c48a770084e6cb0ec73878dfb7ee`. Tampoco se infiere una instalación exitosa a partir de su transferencia.

El cierre original ocurrió después del proxy. En esta copia se reutiliza después de la descarga, remapeando SEQ/ACK y conservando sus tiempos originales. Por tanto, es una selección con cirugía TCP y cierre trasladado de contexto; no se presenta como una nueva ejecución que hubiera terminado por sí sola inmediatamente después de descargar.

## 3. Proxy: únicamente el tramo C2–víctima

Selección: **20–22, 90–91 y 106–111**. Las tramas 20–22 aportan el handshake TCP; 90 contiene la orden `http` con ID 9001, 91 su ACK y 106 la respuesta con el mismo ID. Se conservan también los mensajes de terminación. Se excluyen la descarga y todas las conexiones de la víctima al servidor objetivo.

La respuesta RPC contiene estado 200 y un cuerpo de 44 bytes. Ese cuerpo coincide exactamente con el recibido por HTTP en el PCAP de explotación: SHA-256 `c13976b17e68254dd68842679c80db0adacfa2497feee7244012adb3b3daa581`.

**La separación acordada es por tramos de comunicación.** La orden original `http` conserva el vector Shellshock dentro de sus parámetros; no se ha convertido en una petición inocua. Aunque la conexión al objetivo esté excluida, una firma que inspeccione ese contenido encapsulado podría detectarlo. El archivo no debe describirse como libre de bytes de explotación ni como garantía de atribución exclusiva de una alerta a T1604.

## 4. Explotación: únicamente el tramo víctima–objetivo

Se extrae completo **TCP stream 5, tramas 96–105**. Su handshake original 96–98 queda en las posiciones 1–3 de la copia. La petición a `/cgi-bin/status` con el `User-Agent` original está en 99, la respuesta en 101–102 y la terminación en 102–105. Se conservan ambos sentidos y todos los bytes HTTP.

Solo se completan cuatro checksums TCP parciales de offloading. No se cambian secuencias, tiempos ni contenido, ni se incorporan el C2, el túnel lógico o DNS. La dirección de la víctima visible en la captura es `172.22.0.1`, correspondiente al extremo observado del emulador tras su traducción de red. La respuesta corresponde al servicio controlado del laboratorio, no a un compromiso real acreditado.

## 5. Cómo se mantiene la integridad al cortar el C2

Los dos PCAPs del C2 conservan los SYN, SYN/ACK y ACK originales, incluidos sus números iniciales y opciones TCP. No basta con anteponer esos tres paquetes: también se ajustan SEQ/ACK para eliminar los huecos que dejarían los mensajes retirados.

Para cada sentido se identifican los intervalos de datos retenidos. La nueva posición relativa es la cantidad de bytes retenidos anterior a la posición original; SYN y FIN consumen una posición adicional. Este mismo mapeo se aplica a los ACK del sentido contrario. El campo ACK inactivo del RST se conserva como estaba.

Por ejemplo, en la copia del proxy la orden `http` comienza en SEQ relativo 1 y lleva ACK 1; la respuesta comienza en SEQ 1 y confirma ACK 120. Ambas partes quedan contiguas al handshake, aunque sus posiciones originales fueran posteriores al registro y a la descarga.

El protocolo de esta muestra lleva tramas RFC 6455 directamente sobre TCP, sin negociación HTTP Upgrade. Se mantiene esa particularidad. Cada trama conserva su máscara y bytes originales; los mensajes MessagePack y los identificadores RPC 11, 12 y 9001 no se reescriben. La validación del código local confirma que no hay un estado criptográfico continuo que obligue a conservar los mensajes descartados.

En la resegmentación se recalculan longitudes y checksums; el IP ID avanza por segmento y PSH queda en la última parte de cada trama original. Las partes mantienen el timestamp de su trama de origen. Las demás tramas mantienen sus tiempos originales.

## 6. Cierres y verificación

Resolver, descarga y proxy mantienen una terminación mediante FIN del servidor y RST final, coherente con el original. El cliente envía su mensaje de cierre después del FIN del servidor; el RST final termina la sesión sin que esos últimos bytes tengan un ACK normal. No se interpreta como un hueco de datos ni se inventan FIN adicionales. En la explotación se conserva el cierre mediante FIN/ACK en ambos sentidos.

Se comprobaron de manera independiente los handshakes, las secuencias y los ACK, los checksums completos mediante suma de verificación, los límites de tamaño, el contenido de los mensajes y los hashes de la APK y de la respuesta. La reconstrucción a partir de las tramas seleccionadas y los cambios documentados coincidió exactamente con cada salida. No aparecieron paquetes malformados ni avisos `tcp.analysis.flags` en las copias.

El MCP de Wireshark contrastó los flujos. Su análisis experto de la descarga conserva el aviso de conexión terminada por RST; es el cierre elegido del original, no un defecto nuevo de secuencias. Se distingue este aviso de los errores de reensamblado.

Cada `.procedencia.json` registra la selección, los hashes, el mapeo a tramas de salida, los intervalos TCP retenidos, las porciones de carga y las modificaciones de cabecera. [verificacion.json](verificacion.json) recoge la auditoría. No se han reproducido estas capturas en NGFW/Snort todavía.

SHA-256 del original, comprobado antes y después: `3bf4c00db8b3eb0721f55f6b7b0a68ae741fee10482ba159d378307d562fac64`.

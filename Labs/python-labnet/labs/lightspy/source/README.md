# Laboratorio de red de LightSpy para iOS

Este laboratorio reproduce mediante Python el flujo de red recuperado de `095`, `irc_loader`, `light` e `ios_wechat`. Los artefactos descargados y el fichero transferido por la orden `12005` son cuerpos sintéticos e inertes. Ningún Mach-O se ejecuta.

## Requisitos

La ejecución está prevista dentro de WSL con Python 3.10 o posterior, OpenSSL, CoreDNS, `iproute2` y tcpdump. CoreDNS se ejecuta como un proceso independiente desde la raíz del laboratorio. El cliente y los servidores Python comparten la interfaz `lo`.

## Componentes

`run_lab.py capture` añade temporalmente a `lo` las dos direcciones históricas, inicia los servidores Python y tcpdump, ejecuta el cliente emulado, cierra esos servicios y retira únicamente las direcciones que haya añadido. No inicia ni detiene CoreDNS: el servidor DNS debe permanecer abierto en otra terminal durante la ejecución. El PCAP queda en `captures/`, los registros y los secretos TLS de esa misma ejecución en `logs/`.

Los modos `serve` y `client` permiten ejecutar por separado los dos extremos durante una depuración. `serve` inicia el servidor HTTP de `45.83.237.13:8088` y un solo servidor TLS en `45.134.1.180:50000`; el segundo distingue las peticiones HTTPS de la actualización WebSocket después de establecer TLS. `client` ejecuta las diecisiete descargas, la consulta DNS, el arranque concurrente del C2, la sincronización WSS, la orden `12005`, la carga fragmentada y la finalización.

El `Corefile` responde únicamente a la consulta A de `www.baidu.com`. El certificado autofirmado se genera en el primer arranque con SAN para `45.134.1.180`; el cliente desactiva la validación de cadena y nombre, como el código analizado. Cada ejecución del cliente crea un registro de claves TLS independiente dentro de `logs/`.

La ejecución concreta selecciona una respuesta DNS no almacenada en caché, versiones remotas distintas y un manifiesto nuevo que contiene `ios_wechat`. El resultado inerte de 600000 bytes obliga a realizar dos peticiones de subida: 409600 y 190400 bytes. La respuesta a cada fragmento conserva el prefijo de cuatro bytes y el campo `offset`; la finalización `12005` solo se transmite por WSS tras recibir el valor cero.

Los registros de instrumentación son locales y no añaden cabeceras, campos ni valores identificativos a las comunicaciones. TLS 1.2 y los valores sintéticos del dispositivo son elecciones controladas porque el análisis estático no fija una huella TLS histórica ni los datos del terminal comprometido. El PCAP representa la firma de red derivada del código y no constituye una ejecución de la IPA original ni demuestra el contenido histórico de los servidores.

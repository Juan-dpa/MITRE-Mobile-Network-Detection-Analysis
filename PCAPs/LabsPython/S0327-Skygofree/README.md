# Skygofree: orden Wi-Fi y tráfico externo separados

Preparación: 25 de octubre de 2026. Derivados del [PCAP original](../../../PCAPs/LabsPython/S0327-Skygofree/S0327-Skygofree.pcap), sin modificarlo ni volver a ejecutar el laboratorio. Las referencias a tramas y streams corresponden al original salvo indicación contraria.

| Archivo | Contenido | Paquetes | Trama máxima |
|---|---|---:|---:|
| [Orden Wi-Fi — T1481.003](S0327-Skygofree-T1481.003-orden-wifi.pcap) | Preparación del C&C, orden Wi-Fi por GCM y confirmación por HTTP | 144 | 1316 B |
| [Tráfico externo — T1638](S0327-Skygofree-T1638-trafico-wifi.pcap) | DHCP, DNS y HTTP bancario posteriores a la orden | 18 | 389 B |

## 1. Corte entre C&C y tráfico externo

El primer archivo selecciona **1–143 y 162**. El segundo selecciona **144–161**. Las selecciones no se solapan y, juntas, contienen los 162 paquetes originales. Se conservan sus timestamps y su orden relativo.

La trama **162** pertenece al C&C: confirma el FIN de la víctima en 143 dentro del canal GCM. Aunque llega después del tráfico bancario, se incluye como último paquete del primer archivo —posición 144—. No se corta únicamente por tiempo.

Cada conexión TCP queda íntegra en uno de los dos archivos. Por ello se conservan sus handshakes originales y no es necesario trasplantarlos, inventar paquetes ni reajustar SEQ/ACK. Tampoco se necesita resegmentación: todas las tramas son inferiores a 4000 B.

## 2. Orden Wi-Fi y respuesta: T1481.003

Se conservan los streams TCP originales **0–8**, junto con sus consultas DNS. El archivo incluye la obtención del token, el registro, la activación `attiva`, la orden `wifi_enable` y su confirmación `wifiYES`.

El registro y la activación son contexto de la ejecución original. El canal persistente TLS de `mtalk` contiene login, heartbeat, `attiva` y después la orden Wi-Fi. Eliminar registros cifrados intermedios conservando únicamente un handshake TCP rompería la continuidad del transporte y del estado TLS. Se mantiene esa conversación completa, sin cambiar sus registros cifrados ni sus mensajes.

| Tramas originales | Operación |
|---|---|
| 98–100 | Handshake TCP del C&C con la API GCM para enviar la orden Wi-Fi |
| 101–108 | Negociación TLS y petición `/gcm/send` con la orden; respuesta de la API |
| 109 | Entrega de `PUSH comando=wifi_enable_SantanderFreeWiFi_RogueLab2026!_WPA2_AES` por el canal GCM ya establecido |
| 110–111 | ACK de aplicación de la entrega y su confirmación TCP |
| 112–123 | Conexión completa a `ser.php` para obtener el panel de retorno |
| 124–133 | Conexión completa a `control.php`: POST con `wifiYES` en 127 y HTTP 200 en 130 |
| 134–143 y 162 | Terminaciones de los canales restantes; 162 pertenece al canal GCM |

La orden es recibida mediante el servicio GCM; el resultado funcional `wifiYES` vuelve por el panel HTTP propio. Los ACK de transporte y de entrega de GCM no cambian esa clasificación funcional como **One-Way Communication**. No se incorpora T1509 por el puerto habitual 5228 de ese servicio.

La verificación local con el [registro de claves TLS original](../../../PCAPs/LabsPython/S0327-Skygofree/keys/skygofree-sslkeys.log) permite comprobar la orden dentro de TLS; los secretos no se copian al informe. El cifrado del PCAP se conserva.

## 3. Tráfico externo a C&C: vista del escenario T1638

| Original | Posición en la copia | Contenido |
|---|---|---|
| 144–147 | 1–4 | DHCP Discover, Offer, Request y ACK entre víctima y servidor DHCP del laboratorio |
| 148–149 | 5–6 | Consulta DNS de `www.bancosantander.es` y respuesta `18.154.48.19` |
| 150–152 | 7–9 | Handshake TCP entre víctima y servidor bancario emulado, puerto 80 |
| 153–161 | 10–18 | POST HTTP, respuesta 302 y cierre TCP |

El POST a `/particulares/acceso-clientes/` contiene un NIF y una contraseña ficticios del laboratorio, en claro. El servidor devuelve una redirección a `/particulares/area-clientes/posicion-global/` y un cuerpo que confirma la recepción de credenciales sintéticas. La captura no contiene una petición posterior que siga esa redirección.

Este archivo conserva el tráfico expuesto en la topología controlada del escenario AiTM. El laboratorio emula DHCP y HTTP mediante procesos Python e interfaces `veth`; no captura una asociación 802.11 real. La atribución a T1638 depende del escenario y de la topología documentados en el [análisis de Skygofree](../../../Documentos/Markdowns/S0327-Skygofree.md). El HTTP aislado no demuestra por sí solo que el adversario controla el punto de acceso. Tampoco se interpreta `wifiYES` como prueba independiente de asociación Wi-Fi exitosa.

## 4. Modificaciones y cierres

Los 162 paquetes originales contienen checksums TCP o UDP parciales de offloading. Se comprobó que cada valor coincide con la suma de su pseudocabecera y se completó el checksum de transporte en las copias. Es la única modificación de bytes de paquete: 144 checksums en C&C y 18 en el tráfico externo. Se preservan direcciones, puertos, longitudes, opciones, SEQ/ACK, payloads y cabeceras IP.

Se conservan todos los cierres existentes. El canal GCM original, stream 1, tiene FIN del cliente y ACK del servidor, pero no FIN del servidor: permanece **semicerrado**, como en el original. No se añade un cierre sintético. Los restantes ocho streams del C&C y el stream HTTP externo conservan FIN de ambos extremos y sus confirmaciones.

## 5. Procedencia y verificación

Cada `.procedencia.json` registra las tramas seleccionadas, sus posiciones de salida, hashes y los dos bytes del campo checksum antes y después de completar la suma. Esto permite reconstruir exactamente los derivados a partir del original.

La [verificación](verificacion.json) comprueba los handshakes, secuencias y ACK, la igualdad de datos de aplicación, los checksums completos mediante cálculo independiente, el descifrado de las conversaciones TLS seleccionadas y el límite de 4000 B. El MCP de Wireshark contrasta la separación y los intercambios HTTP. No se han reproducido las capturas en NGFW ni Snort en esta fase.

SHA-256 del original: `2260793ad6a5fda170ba05e94ceafc047ebea5832a058d65c87f67fc47a1e2fe`.

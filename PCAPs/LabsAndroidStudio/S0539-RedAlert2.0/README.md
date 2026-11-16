# Red Alert 2.0: resolver y descarga de plantillas

Preparación y verificación: 26 de octubre de 2026. Derivados del [PCAP original](../../../PCAPs/LabsAndroidStudio/S0539-RedAlert2.0/S0539-RedAlert2.0.pcap), sin modificarlo ni volver a ejecutar la APK. Las referencias a tramas y streams siguientes corresponden al original salvo indicación contraria.

| Archivo | Técnica objetivo | Acompañante | Paquetes | Trama máxima |
|---|---|---|---:|---:|
| [Dead Drop Resolver](S0539-RedAlert2.0-T1481.001-resolver.pcap) | T1481.001 | Ninguna de las técnicas adicionales estudiadas | 32 | 1294 B |
| [Descarga de plantillas](S0539-RedAlert2.0-T1407-descarga-T1509.pcap) | T1407 | T1509: HTTP/8060 | 30 | 860 B |

## 1. Resolver: tramas 7–38

Se conservan las consultas DNS y las conexiones completas de TimeAPI y Twitter. La selección contiene ocho paquetes DNS y 24 paquetes TCP, distribuidos en los streams originales 1 y 2.

| Tramas originales | Operación | Posiciones en la copia |
|---|---|---|
| 7–10 | DNS AAAA/A de `www.timeapi.org`, incluidas sus respuestas | 1–4 |
| 11–20 | HTTP/80 de TimeAPI: handshake, consulta, respuesta y cierre | 5–14 |
| 21–24 | DNS AAAA/A de `twitter.com`, incluidas sus respuestas | 15–18 |
| 25–38 | HTTPS/443 de Twitter: handshake TCP/TLS, consulta, respuesta y terminación | 19–32 |

TimeAPI devuelve `2024-01-02T03:04:05+00:00` dentro de HTML. Se ha comprobado que, junto con el valor constante de la muestra, produce el identificador `86d08d31c9d4733` consultado después en Twitter. La respuesta de Twitter contiene `tweet-text` con `192.168 56.20`, del que la muestra reconstruye la IP `192.168.56.20`.

La copia termina tras obtener esa dirección. Se excluyen los intentos fallidos hacia el C2 primario en 7878, el tráfico mDNS ajeno al escenario, la validación posterior `/ping` en 8060 y las operaciones siguientes del C2. El archivo representa la obtención de la dirección de respaldo; no se presenta como la cadena completa de validación y uso de ese C2.

**No se etiqueta T1509 en este archivo:** los servicios conservados usan DNS/53, HTTP/80 y TLS/443. El puerto 8060 que la muestra añade localmente a la dirección obtenida no aparece como conexión de transporte en este derivado.

Se preserva el FIN del servidor de Twitter y el RST terminal original. El aviso experto de Wireshark por RST corresponde a la trama original 38, posición 32 en la copia. El cliente envía antes una alerta TLS de cierre de 37 bytes que no recibe un ACK normal antes del RST; no se inventan paquetes para sustituir esa terminación.

El descifrado de verificación utiliza el [registro de claves TLS original](../../../PCAPs/LabsAndroidStudio/S0539-RedAlert2.0/keys/redalert-sslkeys.log), sin copiar sus secretos a los informes. La conversación descifrada coincide con la del original; los registros cifrados no se alteran.

## 2. T1407 con T1509: tramas 59–88

Se extraen íntegros los streams originales **5, 6 y 7**. Cada uno tiene diez paquetes, incluidos su handshake TCP y su cierre mediante FIN/ACK de ambos extremos.

| Tramas originales | Operación | Posiciones en la copia |
|---|---|---|
| 59–68 | `POST /sban` y catálogo de plantillas | 1–10 |
| 69–78 | `POST /gt` con `SELECTOR_PRINCIPAL_LAB` y plantilla principal | 11–20 |
| 79–88 | `POST /gt` con `SELECTOR_TECNICO_LAB` y plantilla técnica | 21–30 |

El catálogo relaciona `com.android.smoketest` y su variante terminada en `2` con los dos selectores solicitados después. Las tres respuestas son HTTP 200. No se incluyen resolver, `/ping`, registro `/stbi` ni otras consultas u operaciones del C2.

**T1509 se conserva como acompañante:** todas estas conexiones usan HTTP sobre TCP/8060. El puerto procede de la concatenación `":8060"` implementada por la muestra para el C2 alternativo; el laboratorio eligió la IP de respaldo. No se cambian direcciones, puertos ni cabeceras Host.

Los cuerpos descargados mantienen exactamente los bytes del original y coinciden con las plantillas del laboratorio después de aplicar la eliminación de saltos de línea que realiza el servidor:

| Plantilla | Bytes | SHA-256 |
|---|---:|---|
| Principal | 462 | `addd3308b1a9032efdcc20645d5e91f288bd66adfffdae0a7368fe5ce07d74c6` |
| Técnica | 280 | `b6397ea41506d416b81b2dae2c8093f9ed65f4f2907f835f8402bda84f29ca62` |

Se conserva el caso de descarga de plantillas asociado a T1407 en el [análisis local](../../../Documentos/Markdowns/S0539-RedAlert2.0.md). Son los HTML controlados del laboratorio; no se añade código a sus cuerpos ni se infiere una ejecución o superposición exitosa a partir de la transferencia.

## 3. Transformaciones y verificación

La separación utiliza conexiones completas con sus handshakes originales. No requiere trasplantar handshakes, reajustar SEQ/ACK, resegmentar ni añadir cierres. Se conservan los timestamps, las longitudes, las opciones TCP, los flags y todos los datos de aplicación.

Se completan **14 checksums parciales de offloading en el resolver** —diez TCP y cuatro UDP— y **12 TCP en la descarga**. Antes de cambiarlos se comprueba que su valor coincide con la suma de la pseudocabecera correspondiente. Los demás checksums ya eran válidos y permanecen intactos. Estos campos de dos bytes son las únicas modificaciones de los paquetes seleccionados.

Cada `.procedencia.json` identifica las tramas originales, su posición en la copia, los hashes y los bytes exactos modificados. La [verificación](verificacion.json) confirma la reconstrucción de las salidas desde esos registros, checksums IPv4/TCP/UDP completos, handshakes, continuidad de SEQ/ACK, equivalencia del TLS descifrado, correspondencia entre catálogo y selectores, hashes de las plantillas y ausencia de tramas mayores de 4000 B. El MCP de Wireshark confirma la selección y los servicios conservados.

Las selecciones son disjuntas y contienen 62 paquetes del original. El resto permanece disponible en el original. No se han reproducido las copias en NGFW ni Snort en esta fase.

SHA-256 del original, comprobado antes y después: `cdc776ceb1d10240cd82f080345c71e8e6f7c9b1e6eb6102261a1fa2a21c941e`.

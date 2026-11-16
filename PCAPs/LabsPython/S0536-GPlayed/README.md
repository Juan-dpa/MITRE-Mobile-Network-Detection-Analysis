# GPlayed: reparación de tamaño

Preparación y verificación: 10 de noviembre de 2026. [Captura preparada](S0536-GPlayed-T1407-T1509-preparado.pcap), con T1407 y T1509 conservadas. El [original](../../../PCAPs/LabsPython/S0536-GPlayed/S0536-GPlayed.pcap) permanece intacto.

La trama original 44, de 5609 B, contiene 5543 bytes TCP de la respuesta LoadPlugin. Se representa mediante cuatro segmentos consecutivos: 1448, 1448, 1448 y 1199 bytes de carga TCP. El archivo pasa de 60 a 63 paquetes, con un máximo de trama de 1514 B y paquetes IPv4 de hasta 1500 B.

Se ajustan longitudes, SEQ de cada segmento y checksums. PSH permanece únicamente en el último segmento. Se mantienen ACK, ventana, opciones TCP, direcciones, puerto 5416 y timestamps originales. No se fragmenta IP ni se añaden cierres o handshakes. También se completan los checksums parciales de transporte para la reproducción.

Las cinco conversaciones conservan sus handshakes, cierres y contenido de aplicación. Se ha comprobado la reconstrucción exacta de todas las cargas originales, los cambios registrados en el manifiesto, los checksums y la ausencia de tramas mayores de 4000 B. TShark y el MCP de Wireshark no muestran nuevas anomalías ni avisos de análisis TCP.

La [procedencia](S0536-GPlayed-T1407-T1509-preparado.procedencia.json) registra cada transformación y permite reproducir la copia. La [verificación](verificacion.json) detalla las comprobaciones de los flujos y las transacciones HTTP. No se ha realizado reproducción en NGFW/Snort.

SHA-256 del original: `99882b84c5a318433a053bd09cdb8ad517cffc130422c8c2dce448d2f51bdde0`.

SHA-256 de la copia: `9be877de4773795382f133c20cc9ac9277bfe3c95c1648932886ad3f7d18618d`.

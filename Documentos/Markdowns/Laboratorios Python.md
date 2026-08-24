# Laboratorios Python para la generación de PCAP

Esta guía centraliza la ejecución de los laboratorios cuyo tráfico se reproduce íntegramente mediante clientes y servidores Python. Los documentos de cada muestra conservan la justificación técnica, las entidades, el direccionamiento y la evidencia que debe aparecer en la captura; aquí se concentra la operativa común, que puede cambiar a medida que evoluciona la automatización.

Los escenarios se ejecutan dentro de Kali WSL sobre topologías aisladas construidas con *network namespaces* e interfaces `veth`. Cada entidad tiene un único nombre lógico, aunque puede disponer de varias combinaciones de dirección, protocolo y puerto. El enrutamiento solo permite los flujos declarados por cada escenario y no proporciona salida a Internet.

## Criterio de direccionamiento

La topología definitiva no utiliza los bloques reservados por la [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737.html). Aunque resultan adecuados para documentación, su presencia en una captura destinada a evaluar IDS, IPS o NGFW puede activar políticas de espacio reservado o no enrutable antes de que el motor aplique la inspección ordinaria. Mantenerlos introduciría una variable ajena al comportamiento del malware.

Las víctimas, operadores y objetivos internos usan direcciones privadas de la [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918.html). La infraestructura maliciosa utiliza direcciones observadas en el código o publicadas en referencias técnicas. Los servicios legítimos se representan mediante una dirección real del proveedor obtenida por DNS entre el 20 y el 21 de agosto de 2026; el resolutor común adopta `8.8.8.8`, dirección publicada por [Google Public DNS](https://developers.google.com/speed/public-dns/docs/using). Ninguna de esas direcciones abandona el laboratorio: los *network namespaces* carecen de salida a Internet y la ruta solo existe dentro de la topología aislada.

Esta diferencia permite interpretar el PCAP sin ambigüedad:

| Tipo de dirección | Significado dentro del laboratorio |
|---|---|
| IP pública maliciosa | IOC extraído del código o de una referencia; el documento indica su procedencia y si el servicio concreto es observado o una reutilización controlada. |
| IP pública legítima | Dirección del proveedor resuelta para el nombre emulado; no se clasifica como IOC y puede cambiar fuera del laboratorio. |
| Dirección privada RFC 1918 | Víctima, operador u objetivo controlado cuya selección no procede del malware. |

## Escenarios incluidos

| Identificador | Documento | Extremos principales | Material auxiliar para Wireshark |
|---|---|---|---|
| `keyraider` | [KeyRaider](S0288-KeyRaider.md) | DNS en `8.8.8.8:53`, Apple en `17.8.136.178:443` y C2 en `113.10.174.167:80` | `keyraider-sslkeys.log` |
| `notcompatible` | [NotCompatible](S0299-NotCompatible.md) | Pasarela en `173.242.124.163:443`, C2 en `5.45.65.100:80` y objetivo en `10.29.9.20:21/6200` | Claves RSA global y local del laboratorio |
| `skygofree` | [Skygofree](S0327-Skygofree.md) | Panel en `217.194.13.133:80`; Google en `172.217.117.4:443`, `172.217.115.4:443` y `172.253.157.188:5228`; AP controlado en `10.32.7.1:67`; banco simulado en `18.154.48.19:80` | `skygofree-sslkeys.log` |
| `exodus` | [Exodus](S0405-Exodus.md) | C2 en `54.71.249.137:443` | `exodus-sslkeys.log` |
| `monokle` | [Monokle](S0407-Monokle.md) | C2 y proxy en `185.117.89.238:17185/443`; origen `www.oracle.com` en `23.208.220.69:443` | `monokle-sslkeys.log` y clave AES-GCM del transporte |
| `gplayed` | [GPlayed](S0536-GPlayed.md) | C2 en `5.9.33.226:5416` | No requiere claves; el tráfico usa HTTP |
| `busygasper` | [BusyGasper](S0655-BusyGasper.md) | DNS en `8.8.8.8:53`, IRC en `149.28.246.185:6667` y FTP en `213.174.157.151:21/20200` | No requiere claves; DNS, IRC y FTP viajan en claro |
| `drinik` | [Drinik](S1054-Drinik.md) | Firebase en `172.217.114.4:443` y `108.177.15.188:5228`, panel en `198.12.107.13:80` y descarga en `192.3.124.14:80` | `drinik-sslkeys.log` |
| `flubot` | [FluBot](S1067-FluBot.md) | C2 `gurbngbcxheshsj.ru` en `189.165.94.67:80/9000/4444` y objetivo FTP en `10.106.7.20:21` | `flubot-rsa-private.pem` |
| `lightspy` | [LightSpy](S1185-LightSpy%28iOS%29.md) | DNS en `8.8.8.8:53`, Baidu en `103.235.46.115`, *staging* en `45.83.237.13:8088` y C2 en `45.134.1.180:50000` | `lightspy-sslkeys.log` |

## Comprobación previa

La orden `check` valida el manifiesto de red y las dependencias Python sin crear la topología. Desde la raíz del proyecto puede aplicarse a un escenario concreto:

```bash
cd ~/python-labnet
bash labs/<identificador>/run.sh check
```

Los lanzadores utilizan automáticamente `~/python-labnet/.venv/bin/python3` cuando existe. NotCompatible y FluBot requieren `pycryptodome`; KeyRaider, Skygofree, Monokle y Drinik requieren `cryptography`. Los demás escenarios solo dependen de la biblioteca estándar de Python. También deben estar disponibles `ip`, `iptables`, `tcpdump`, `capinfos`, `timeout` y, para las capturas con varios puntos, `mergecap`.

## Ejecución automatizada

El siguiente comando ejecuta secuencialmente los diez escenarios:

```bash
cd ~/python-labnet
sudo bash tools/smoke-all.sh
```

Se puede ejecutar un único escenario o una selección indicando sus identificadores:

```bash
sudo bash tools/smoke-all.sh exodus
sudo bash tools/smoke-all.sh keyraider notcompatible monokle
```

Por cada ejecución se crea un directorio con marca temporal. Dentro aparece un subdirectorio por muestra que agrupa la captura y todo el material necesario para interpretarla:

```text
smoke/AAAAMMDD-HHMMSS/
└── <identificador>/
    ├── <identificador>.pcap
    └── keys/
        ├── key-material.txt
        └── <claves o secretos de sesión>
```

`key-material.txt` explica el propósito de cada fichero. También se genera cuando el protocolo viaja en claro, para dejar constancia de que la captura no depende de claves externas.

El flujo automatizado crea la topología, inicia la captura, levanta los servidores y ejecuta el cliente en primer plano. Cuando el cliente termina, los servidores permanecen activos durante diez segundos. Después se detiene la captura, se cierran los servicios, se recopila el material de claves y se retira la topología. Este orden evita que el cierre artificial del laboratorio interrumpa las últimas conexiones del cliente.

## Ejecución individual para desarrollo

Cada escenario ofrece la misma interfaz:

```bash
cd ~/python-labnet
sudo bash labs/<identificador>/run.sh capture
```

Puede indicarse una ruta de salida explícita como segundo argumento. Para investigar un laboratorio por etapas se dispone además de las órdenes siguientes:

```bash
sudo bash labs/<identificador>/run.sh up
sudo bash labs/<identificador>/run.sh client
sudo bash labs/<identificador>/run.sh status
sudo bash labs/<identificador>/run.sh down
```

`up` crea la topología e inicia los servicios; `client` ejecuta únicamente el cliente sobre una topología activa; `status` muestra el estado; y `down` detiene los procesos y retira los elementos de red pertenecientes al escenario.

## Validación de las capturas

La validación no se limita a comprobar que el PCAP contiene paquetes. Para cada muestra se debe contrastar:

- el orden de los intercambios con su diagrama de secuencia comunicativa;
- los protocolos, puertos, direcciones, rutas, cabeceras y estructuras de mensaje descritos en el documento;
- la causalidad entre canales cuando intervienen varias entidades;
- el cierre completo de las conexiones, distinguiendo los reinicios propios del protocolo de los provocados por el laboratorio;
- el descifrado o la reconstrucción de la capa de aplicación mediante los ficheros reunidos en `keys/`.

En NotCompatible, el tráfico de TCP/443 emplea un protocolo propietario protegido con RSA y RC4, no TLS. Un analizador puede clasificarlo heurísticamente como SSL por el puerto, pero la interpretación correcta se obtiene con el material RSA incluido por el laboratorio.

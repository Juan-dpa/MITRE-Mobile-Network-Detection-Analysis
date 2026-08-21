# Laboratorios Python sobre topologías veth

Este directorio contiene una copia de trabajo independiente de los diez laboratorios íntegramente emulados con Python. No modifica el repositorio original ni el *vault* de Obsidian.

El motor `tools/labnet.sh` crea una topología en estrella mediante *network namespaces*. Cada entidad dispone de un único nombre lógico, una interfaz de tránsito y una o varias IP visibles sobre `dummy0`. Los servicios se declaran por separado como `entidad|IP|protocolo|puerto|nombre`, de modo que una misma entidad puede publicar tantas combinaciones IP:puerto como requiera el protocolo. LightSpy y Firebase/Drinik ejercitan expresamente el caso de varias IP bajo un solo nombre.

No se crea una ruta por defecto ni se aplica NAT. El router acepta únicamente los flujos enumerados en el manifiesto y descarta el resto. Las IP históricas quedan asignadas dentro de espacios de nombres aislados: el laboratorio no necesita ni puede encaminar esos destinos hacia Internet.

## Requisitos en Kali WSL

```bash
sudo apt install iproute2 iptables tcpdump wireshark-common util-linux openssl python3 python3-venv
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Los lanzadores detectan `.venv/bin/python3` y lo anteponen a `PATH` después de
entrar mediante `sudo`. De este modo, los procesos de los espacios de nombres
utilizan el entorno del proyecto sin depender del `secure_path` de `sudo`.
Antes de crear la topología, cada laboratorio comprueba sus módulos específicos
y falla con un diagnóstico explícito si falta alguno.

Las dependencias Python externas se concentran en dos paquetes: `pycryptodome`
para NotCompatible y FluBot, y `cryptography` para KeyRaider, Skygofree, Monokle y Drinik.
Exodus, GPlayed, BusyGasper y LightSpy solo requieren la biblioteca estándar.
La validación estática comprueba que cualquier importación externa quede
declarada en el preflight de su lanzador y cubierta por `requirements.txt`.

`mergecap`, incluido en `wireshark-common`, solo se emplea cuando una secuencia necesita capturar más de un enlace sin duplicar paquetes. Es el caso de Monokle —tráfico de la víctima y salida del proxy hacia el origen— y Drinik —tráfico de la víctima y publicación del panel hacia Firebase—. Los filtros de cada punto evitan volver a incorporar el mismo flujo por su interfaz de destino.

## Uso

Cada muestra ofrece la misma interfaz. Por ejemplo:

```bash
cd labs/drinik
./run.sh check
sudo ./run.sh capture
```

La orden `check` valida tanto el manifiesto como las dependencias Python del
laboratorio. La orden `capture` crea la red, inicia DNS y servidores y ejecuta
el cliente. Cuando este termina, mantiene la captura y los servidores activos
durante diez segundos; después cierra primero la captura, detiene los servicios
y retira la topología. Este mismo orden se respeta aunque falle la secuencia.
También se puede trabajar de forma interactiva:

```bash
sudo ./run.sh up
sudo ./run.sh client
sudo ./run.sh status
sudo ./run.sh down
```

`down` solo elimina namespaces cuyo nombre determinista consta en `/run/tfg-labnet/<laboratorio>`; nunca opera sobre el espacio de nombres de WSL ni sobre interfaces ajenas.

## Formato del manifiesto

```bash
ENTITIES=(
  "victim|victim|10.105.4.10"
  "firebase|legitimate|172.217.114.4,108.177.15.188"
)

SERVICES=(
  "firebase|172.217.114.4|tcp|443|firebase-api"
  "firebase|108.177.15.188|tcp|5228|mtalk"
)

FLOWS=(
  "victim|firebase|172.217.114.4|tcp|443"
  "victim|firebase|108.177.15.188|tcp|5228"
)
```

El validador rechaza nombres repetidos, IP compartidas entre entidades, servicios en IP ajenas, flujos sin servicio de destino, cualquier IP visible dentro de `127.0.0.0/8` y los tres bloques reservados por la RFC 5737.

## Criterio de direccionamiento

| Laboratorio | Infraestructura maliciosa representada | Extremos legítimos o controlados |
|---|---|---|
| KeyRaider | `113.10.174.167:80` para `www.wushidou.cn` | Apple `17.8.136.178:443`; DNS `8.8.8.8:53` |
| NotCompatible | *Gateway* `173.242.124.163:443`; C2 operativo `5.45.65.100:80` | Objetivo FTP privado `10.29.9.20:21/6200` |
| Skygofree | Panel `217.194.13.133:80` | Google `172.217.117.4:443`, `172.217.115.4:443` y `172.253.157.188:5228`; AP privado `10.32.7.1:67`; sitio legítimo `18.154.48.19:80` |
| Exodus | `54.71.249.137:443` | Víctima privada `10.40.5.10` |
| Monokle | `185.117.89.238:17185/443` para C2 y proxy de intercepción | `www.oracle.com` en `23.208.220.69:443` |
| GPlayed | `5.9.33.226:5416` | Víctima privada `10.53.6.10` |
| BusyGasper | `213.174.157.151:21/20200` como servidor de actualización | IRC `149.28.246.185:6667`; DNS `8.8.8.8:53`; operador `10.65.5.20` |
| Drinik | C2 `198.12.107.13:80`; descarga `192.3.124.14:80` | Firebase `172.217.114.4:443`; mtalk `108.177.15.188:5228`; DNS `8.8.8.8:53` |
| FluBot | `gurbngbcxheshsj.ru` en `189.165.94.67:80/9000/4444` | Objetivo FTP privado `10.106.7.20:21`; DNS `8.8.8.8:53` |
| LightSpy | `45.83.237.13:8088` y `45.134.1.180:50000` | DNS `8.8.8.8:53`; respuesta de Baidu `103.235.46.115` |

La topología final excluye los bloques reservados para documentación porque algunos productos de seguridad pueden tratarlos como espacio no enrutable antes de aplicar la inspección ordinaria. Las direcciones públicas se reutilizan únicamente dentro de *namespaces* aislados: el laboratorio no establece conexiones con sus titulares reales. Los IOC maliciosos proceden del código o de referencias técnicas; las direcciones de proveedores legítimos se obtuvieron mediante DNS entre el 20 y el 21 de agosto de 2026, y los objetivos elegidos por el operador se mantienen en las subredes privadas de las víctimas para evitar atribuciones falsas.

## Validación

```bash
./tools/validate.sh
```

La validación comprueba sintaxis Bash, los diez manifiestos, ausencia de loopback en las órdenes efectivas, compilación de todo el Python y las respuestas A/NXDOMAIN del DNS autoritativo. La prueba dinámica de namespaces requiere ejecutarse dentro de Kali WSL con `sudo`; no debe intentarse desde PowerShell.

Para ejecutar secuencialmente los diez flujos y comprobar que cada captura contiene paquetes:

```bash
sudo ./tools/smoke-all.sh
```

También admite una selección, por ejemplo `sudo ./tools/smoke-all.sh exodus drinik`. Cada laboratorio dispone de 180 segundos y siempre ejecuta su limpieza antes de continuar. Los resultados quedan agrupados por ejecución y por muestra:

```text
smoke/AAAAMMDD-HHMMSS/
├── exodus/
│   ├── exodus.pcap
│   └── keys/
│       ├── exodus-sslkeys.log
│       └── key-material.txt
└── flubot/
    ├── flubot.pcap
    └── keys/
        ├── flubot-rsa-private.pem
        └── key-material.txt
```

`key-material.txt` identifica el uso de cada fichero. También se genera en los laboratorios cuyos protocolos viajan en claro, donde confirma expresamente que el análisis no requiere llaves externas.

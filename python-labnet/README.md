# Laboratorios sobre topolog??as veth

Este directorio contiene una copia de trabajo independiente de los diez laboratorios ??ntegramente emulados con Python y del pipeline semiautom??tico para muestras ejecutadas en Android Emulator. No modifica el repositorio original ni el *vault* de Obsidian.

El motor `tools/labnet.sh` crea una topolog??a en estrella mediante *network namespaces*. Cada entidad dispone de un ??nico nombre l??gico, una interfaz de tr??nsito y una o varias IP visibles sobre `dummy0`. Los servicios se declaran por separado como `entidad|IP|protocolo|puerto|nombre`, de modo que una misma entidad puede publicar tantas combinaciones IP:puerto como requiera el protocolo. LightSpy y Firebase/Drinik ejercitan expresamente el caso de varias IP bajo un solo nombre.

No se crea una ruta por defecto ni se aplica NAT. El router acepta ??nicamente los flujos enumerados en el manifiesto y descarta el resto. Las IP hist??ricas quedan asignadas dentro de espacios de nombres aislados: el laboratorio no necesita ni puede encaminar esos destinos hacia Internet.

Los laboratorios situados en `android-labs/` reutilizan el mismo router, pero reciben el cliente desde Windows mediante una veth de entrada. Windows encamina exclusivamente las IP declaradas hacia Kali WSL y restringe los ejecutables del emulador a esos destinos. La direcci??n de origen del emulador no se traduce; las direcciones de los servidores se conservan en la captura.

El pipeline no controla el ciclo de vida del AVD ni utiliza ADB. Una vez preparada la red y activa la captura, muestra el comando exacto que el operador debe ejecutar en una terminal de PowerShell independiente.

## Requisitos en Kali WSL

```bash
sudo apt install iproute2 iptables tcpdump wireshark-common util-linux openssl python3 python3-venv mosquitto mosquitto-clients
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Los lanzadores detectan `.venv/bin/python3` y lo anteponen a `PATH` despu??s de
entrar mediante `sudo`. De este modo, los procesos de los espacios de nombres
utilizan el entorno del proyecto sin depender del `secure_path` de `sudo`.
Antes de crear la topolog??a, cada laboratorio comprueba sus m??dulos espec??ficos
y falla con un diagn??stico expl??cito si falta alguno.

Las dependencias Python externas se concentran en dos paquetes: `pycryptodome`
para NotCompatible, FluBot y el generador `.data` de Golden Cup, y `cryptography` para KeyRaider, Skygofree, Monokle y Drinik.
Exodus, GPlayed, BusyGasper y LightSpy solo requieren la biblioteca est??ndar.
La validaci??n est??tica comprueba que cualquier importaci??n externa quede
declarada en el preflight de su lanzador y cubierta por `requirements.txt`.

`mergecap`, incluido en `wireshark-common`, solo se emplea cuando una secuencia necesita capturar m??s de un enlace sin duplicar paquetes. Es el caso de Monokle ???tr??fico de la v??ctima y salida del proxy hacia el origen??? y Drinik ???tr??fico de la v??ctima y publicaci??n del panel hacia Firebase???. Los filtros de cada punto evitan volver a incorporar el mismo flujo por su interfaz de destino.

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
durante diez segundos; despu??s cierra primero la captura, detiene los servicios
y retira la topolog??a. Este mismo orden se respeta aunque falle la secuencia.
Tambi??n se puede trabajar de forma interactiva:

```bash
sudo ./run.sh up
sudo ./run.sh client
sudo ./run.sh status
sudo ./run.sh down
```

`down` solo elimina namespaces cuyo nombre determinista consta en `/run/tfg-labnet/<laboratorio>`; nunca opera sobre el espacio de nombres de WSL ni sobre interfaces ajenas.

Las muestras Android utilizan un flujo distinto porque la GUI queda bajo control del operador:

```bash
sudo bash android-labs/dresscode/run.sh check
sudo bash android-labs/dresscode/run.sh run
sudo bash android-labs/goldencup/run.sh check
sudo bash android-labs/goldencup/run.sh run
sudo bash android-labs/redalert/run.sh check
sudo bash android-labs/redalert/run.sh run

sudo bash android-labs/xloader/run.sh check
sudo bash android-labs/xloader/run.sh run
```

La orden `run` crea primero la topolog??a y los servicios de Kali e inicia despu??s la captura. A continuaci??n muestra el comando de PowerShell para arrancar manualmente el AVD con el DNS del laboratorio; nunca lo inicia, inspecciona ni detiene. Cada proceso dispone de una terminal WSL visible que sigue su log en tiempo real. En Golden Cup, Mosquitto conserva el protocolo original y el operador publica la URL solo despu??s de observar `RT/AP/<client-id>/I/A = ON`. En RedAlert 2.0, TCP/7878 permanece silencioso para activar el resolver, mientras TCP/8060 sirve el flujo alternativo; la sesi??n TLS de Twitter genera un fichero de secretos junto al PCAP. En XLoader, la terminal principal espera la entrega de la APK secundaria, solicita confirmaci??n tras su instalaci??n manual y solo entonces libera la orden `http` que reproduce Shellshock. Antes de la confirmaci??n final, el operador debe cerrar el AVD por su cuenta; el pipeline mantiene entonces diez segundos de gracia, cierra la captura, detiene los servicios y retira las terminales auxiliares. Los subcomandos `prepare`, `capture-start`, `capture-stop`, `mark`, `status` y `down` permiten recuperar una sesi??n interrumpida. El controlador de Windows puede mostrar una solicitud UAC al instalar o retirar las rutas y reglas temporales. Los resultados se guardan en `android-smoke/` y estos laboratorios no se incorporan a `smoke-all.sh`.

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

| Laboratorio | Infraestructura maliciosa representada | Extremos leg??timos o controlados |
|---|---|---|
| KeyRaider | `113.10.174.167:80` para `www.wushidou.cn` | Apple `17.8.136.178:443`; DNS `8.8.8.8:53` |
| NotCompatible | *Gateway* `173.242.124.163:443`; C2 operativo `5.45.65.100:80` | Objetivo FTP privado `10.29.9.20:21/6200` |
| Skygofree | Panel `217.194.13.133:80` | Google `172.217.117.4:443`, `172.217.115.4:443` y `172.253.157.188:5228`; AP privado `10.32.7.1:67`; sitio leg??timo `18.154.48.19:80` |
| Exodus | `54.71.249.137:443` | V??ctima privada `10.40.5.10` |
| Monokle | `185.117.89.238:17185/443` para C2 y proxy de intercepci??n | `www.oracle.com` en `23.208.220.69:443` |
| GPlayed | `5.9.33.226:5416` | V??ctima privada `10.53.6.10` |
| BusyGasper | `213.174.157.151:21/20200` como servidor de actualizaci??n | IRC `149.28.246.185:6667`; DNS `8.8.8.8:53`; operador `10.65.5.20` |
| Drinik | C2 `198.12.107.13:80`; descarga `192.3.124.14:80` | Firebase `172.217.114.4:443`; mtalk `108.177.15.188:5228`; DNS `8.8.8.8:53` |
| FluBot | `gurbngbcxheshsj.ru` en `189.165.94.67:80/9000/4444` | Objetivo FTP privado `10.106.7.20:21`; DNS `8.8.8.8:53` |
| LightSpy | `45.83.237.13:8088` y `45.134.1.180:50000` | DNS `8.8.8.8:53`; respuesta de Baidu `103.235.46.115` |
| Golden Cup | `107.175.144.26:1883/80` para `goldncup.com`, IOC de la campa??a publicado por Symantec | DNS controlado `10.230.35.53:53`; operador MQTT `10.230.35.20` |

La topolog??a final excluye los bloques reservados para documentaci??n porque algunos productos de seguridad pueden tratarlos como espacio no enrutable antes de aplicar la inspecci??n ordinaria. Las direcciones p??blicas se reutilizan ??nicamente dentro de *namespaces* aislados: el laboratorio no establece conexiones con sus titulares reales. Los IOC maliciosos proceden del c??digo o de referencias t??cnicas; las direcciones de proveedores leg??timos se obtuvieron mediante DNS entre el 20 y el 21 de agosto de 2026, y los objetivos elegidos por el operador se mantienen en las subredes privadas de las v??ctimas para evitar atribuciones falsas.

## Validaci??n

```bash
./tools/validate.sh
```

La validaci??n comprueba sintaxis Bash, los diez manifiestos, ausencia de loopback en las ??rdenes efectivas, compilaci??n de todo el Python y las respuestas A/NXDOMAIN del DNS autoritativo. La prueba din??mica de namespaces requiere ejecutarse dentro de Kali WSL con `sudo`; no debe intentarse desde PowerShell.

Para ejecutar secuencialmente los diez flujos y comprobar que cada captura contiene paquetes:

```bash
sudo ./tools/smoke-all.sh
```

Tambi??n admite una selecci??n, por ejemplo `sudo ./tools/smoke-all.sh exodus drinik`. Cada laboratorio dispone de 180 segundos y siempre ejecuta su limpieza antes de continuar. Los resultados quedan agrupados por ejecuci??n y por muestra:

```text
smoke/AAAAMMDD-HHMMSS/
????????? exodus/
???   ????????? exodus.pcap
???   ????????? keys/
???       ????????? exodus-sslkeys.log
???       ????????? key-material.txt
????????? flubot/
    ????????? flubot.pcap
    ????????? keys/
        ????????? flubot-rsa-private.pem
        ????????? key-material.txt
```

`key-material.txt` identifica el uso de cada fichero. T
# Laboratorios Android sobre topologías veth

Los laboratorios Android mantienen la muestra original dentro de Android Emulator sobre Windows y trasladan a Kali WSL el DNS, el C2 y los demás participantes controlados. El motor comparte con los laboratorios Python la creación de *network namespaces*, interfaces veth, rutas, reglas de flujo y capturas, pero sustituye el cliente automático por una sesión interactiva.

La dirección de origen producida por el NAT del emulador se conserva sin traducción. Windows instala rutas `/32` hacia Kali para cada servidor declarado, por lo que el PCAP mantiene las direcciones asignadas al C2, al DNS, al operador y a los objetivos. Un conjunto temporal de reglas de Windows Firewall limita los ejecutables del emulador a esas direcciones: el complemento IPv4 se expresa mediante prefijos CIDR y direcciones individuales compatibles con el proveedor de Windows. IPv6 queda fuera de la política porque no interviene en estos laboratorios. Las rutas se crean en `ActiveStore` y no sobreviven a un reinicio.

El pipeline no controla ni inspecciona el AVD y tampoco utiliza ADB. El acceso directo «Puente ADB-TFG» puede seguir utilizándose para tareas manuales, pero no forma parte del camino de captura.

### Criterio de direccionamiento

Las direcciones públicas atribuidas a infraestructura maliciosa proceden del código de la muestra, de los IOC publicados por la referencia técnica o de un registro histórico de DNS pasivo. Los servicios legítimos abusados por el malware pueden conservar una dirección pública del proveedor, como ocurre con Telegram, o representarse mediante direcciones privadas cuando el contenido debe quedar bajo control del laboratorio. Las direcciones privadas asignadas al DNS, al operador y a los objetivos auxiliares son decisiones del escenario y no se presentan como IOC.

Esta distinción se mantiene en cada documento individual. En particular, una IP privada suministrada por un servicio emulado, como el C2 alternativo de RedAlert 2.0, solo representa el valor controlado de esa ejecución; no se atribuye a la campaña histórica.

### Uso interactivo

Desde Kali WSL se inicia un laboratorio mediante una sola orden:

```bash
cd ~/python-labnet
sudo bash android-labs/dresscode/run.sh run
```

El flujo realiza estas operaciones:

1. Valida el manifiesto, los servidores y las herramientas.
2. Crea la topología y solicita a Windows, mediante una elevación UAC, las rutas y reglas temporales de aislamiento.
3. Inicia en Kali los servicios y la captura.
4. Abre una terminal WSL visible para el log de cada proceso.
5. Muestra el comando exacto con el que el operador debe arrancar el AVD desde una terminal de PowerShell independiente.
6. Mantiene la captura mientras el operador maneja la aplicación y cierra el AVD por su cuenta.
7. Al recibir `INTRO`, conserva los servidores y la captura durante diez segundos y después cierra el PCAP.
8. Detiene los servicios y retira las terminales, las rutas, el aislamiento y la topología.

DressCode muestra el arranque de `DressCode_API22_AOSP`; Golden Cup y TeleRAT emplean `golden_api21_aosp`; RedAlert 2.0 reutiliza `TFG_TeleRAT_API19`; y XLoader utiliza `GPlayed_API22_AOSP`. TeleRAT requiere API 21 o posterior porque una clase necesaria durante el arranque se encuentra en `classes2.dex`. El parámetro `-dns-server` forma parte del comando generado, por lo que el AVD debe iniciarse después de preparar el laboratorio. El pipeline nunca ejecuta ese comando en nombre del operador.

### Recuperación y diagnóstico

La topología, los servidores y el aislamiento no se destruyen por cerrar accidentalmente la terminal. La sesión se recupera con órdenes independientes:

```bash
sudo bash android-labs/dresscode/run.sh status
sudo bash android-labs/dresscode/run.sh capture-start
sudo bash android-labs/dresscode/run.sh mark "aplicación activada"
sudo bash android-labs/dresscode/run.sh capture-stop
sudo bash android-labs/dresscode/run.sh down
```

`down` cierra una captura activa, detiene los servicios y retira las rutas, el cortafuegos y los *namespaces*. No detiene aplicaciones ni apaga el emulador; el operador debe cerrar el AVD manualmente.

### Resultados

Cada intento queda bajo un directorio propio:

```text
android-smoke/AAAAMMDD-HHMMSS/dresscode/
├── dresscode.pcap
├── android-setup.txt
├── checksums.txt
├── events.log
├── session.md
├── keys/
│   └── key-material.txt
└── logs/
```

`session.md` identifica el AVD y documenta la función y procedencia de cada dirección. `android-setup.txt` conserva los parámetros de arranque. Si se repite la captura sin retirar la topología, el pipeline crea `dresscode-attempt-2.pcap` y sucesivos ficheros sin sobrescribir el intento anterior.

### Laboratorios incorporados

| Identificador | Cliente                           | Entidades en Kali                                        | Direccionamiento                                                                                                                                                               |
| ------------- | --------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `dresscode`   | APK original en Android Emulator  | DNS, C2, operador SOCKS4 y SMTP                          | `dfm.nicsm.net` responde con la IP histórica `138.201.195.77`; operador `10.230.30.20`; SMTP `10.230.30.25`; DNS `10.230.30.53`                                                |
| `goldencup`   | APK original en Android Emulator  | DNS, broker Mosquitto, servidor HTTP y operador MQTT     | `goldncup.com` responde con el IOC `107.175.144.26`; MQTT/1883 y HTTP/80 comparten el C2; operador `10.230.35.20`; DNS `10.230.35.53`                                          |
| `redalert`    | APK parcheada en Android Emulator | DNS, TimeAPI, Twitter HTTPS y C2 HTTP                    | TimeAPI `10.230.39.10`; Twitter `10.230.39.11`; el IOC `146.0.72.85:7878` permanece silencioso y el C2 alternativo controlado utiliza `192.168.56.20:8060`; DNS `10.230.39.53` |
| `xloader`     | APK original en Android Emulator  | DNS, Twitter HTTPS, C2 TCP, WebView HTTP y objetivo HTTP | Twitter controlado `10.230.31.11`; IOC `1.162.98.240:28833`; WebView `10.230.31.20`; objetivo `10.230.31.30`; DNS `10.230.31.53`                                               |
| `telerat`     | APK original en Android Emulator  | DNS, API de Telegram HTTP/HTTPS y operador               | `api.telegram.org` responde con la dirección legítima `149.154.167.220`; operador interno `10.230.70.20`; DNS `10.230.70.53`                                                   |

La incorporación de cada muestra requiere investigar sus IOC y declarar únicamente las rutas necesarias. Los laboratorios Android no forman parte de `smoke-all.sh`, porque la interacción con la GUI es deliberadamente manual.

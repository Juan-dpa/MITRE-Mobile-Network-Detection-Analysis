# Sesión Android: xloader

- Fecha: `2026-08-24T12:26:53+02:00`
- AVD de arranque manual: `GPlayed_API22_AOSP`
- DNS configurado al arrancar: `10.230.31.53`

| Entidad | Rol | IP encaminada desde Windows | Procedencia |
|---|---|---|---|
| `dns` | `infrastructure` | `10.230.31.53` | DNS controlado del laboratorio |
| `twitter` | `legitimate-service` | `10.230.31.11` | Representación controlada de Twitter elegida para el laboratorio |
| `c2` | `malicious` | `1.162.98.240` | C2 de XLoader en TCP/28833 publicado por Trend Micro |
| `webview` | `lab-content` | `10.230.31.20` | Contenido WebView controlado elegido para el laboratorio |
| `vulnerable-target` | `lab-target` | `10.230.31.30` | Servicio CGI vulnerable controlado elegido para el laboratorio |

La dirección de origen del emulador no se traduce. La captura conserva las direcciones de destino anteriores.

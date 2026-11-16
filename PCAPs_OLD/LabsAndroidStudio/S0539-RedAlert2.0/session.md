# Sesión Android: redalert

- Fecha: `2026-08-23T22:10:09+02:00`
- AVD de arranque manual: `TFG_TeleRAT_API19`
- DNS configurado al arrancar: `10.230.39.53`

| Entidad | Rol | IP encaminada desde Windows | Procedencia |
|---|---|---|---|
| `dns` | `infrastructure` | `10.230.39.53` | DNS controlado del laboratorio |
| `timeapi` | `legitimate-service` | `10.230.39.10` | TimeAPI controlada elegida para el laboratorio |
| `twitter` | `legitimate-service` | `10.230.39.11` | Representación controlada de Twitter elegida para el laboratorio |
| `primary` | `malicious` | `146.0.72.85` | C2 primario codificado en la APK; permanece silencioso en TCP/7878 |
| `c2` | `malicious` | `192.168.56.20` | C2 alternativo controlado publicado mediante el tweet-text del laboratorio |

La dirección de origen del emulador no se traduce. La captura conserva las direcciones de destino anteriores.

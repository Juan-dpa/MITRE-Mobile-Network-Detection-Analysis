# Análisis de rendimiento de NGFW/IDS/IPS en MITRE ATT&CK Mobile

Este repositorio reúne la documentación, los laboratorios y las capturas de tráfico de un Trabajo Fin de Grado que continúa la línea de investigación del departamento de Ingeniería Telemática - Universidad de Sevilla sobre las capacidades de detección de Snort, FortiGate y Palo Alto. El marco de referencia utilizado es **MITRE ATT&CK Mobile, versión 18**, centrado en el entorno móvil Android/iOS.

El objetivo es comparar el rendimiento detectivo de un sistema Open Source y sistemas NGFW (Cortafuegos de próxima generación), atendiendo tanto a las detecciones de tráfico malicioso como a los falsos positivos generados con tráfico benigno. El alcance se limita a las técnicas y subtécnicas que dejan evidencias observables a nivel de red.

## Procedimiento

El estudio se puede descomponer en las siguientes fases:

1. **Seleccionar las técnicas y muestras.** Identificar los comportamientos observables en red y las familias de malware que permiten estudiarlos.
2. **Analizar las muestras.** Revisar su código y las referencias técnicas para determinar los protocolos, mensajes y secuencias de comunicación asociados a cada técnica.
3. **Obtener las capturas.** Investigar PCAPs disponibles en datasets y generar tráfico en laboratorios controlados, mediante muestras ejecutadas en Android Emulator o reproducciones de sus comunicaciones con clientes y servidores Python.
4. **Validar el tráfico.** Comprobar en Wireshark que las capturas contienen las comunicaciones descritas, utilizando las claves o secretos de sesión del laboratorio cuando sea necesario.
5. **Evaluar los sistemas.** Suministrar las capturas a Snort, con los conjuntos de reglas seleccionados, y a FortiGate y Palo Alto. Repetir la evaluación con tráfico benigno para recoger los falsos positivos.
6. **Comparar los resultados.** Recopilar las alertas, relacionarlas con las técnicas estudiadas y discutir las diferencias de detección y las limitaciones de cada sistema.



## Contenido del repositorio

- [Documentos/Markdowns](Documentos/Markdowns/): objetivos, marco teórico, análisis de las muestras y procedimientos de laboratorio.
- [Documentos/Memoria-Quarto](Documentos/Memoria-Quarto/): fuentes de la memoria del TFG.
- [python-labnet](python-labnet/): código y herramientas para preparar los escenarios y capturar sus comunicaciones.
- [PCAPs](PCAPs/): capturas organizadas por laboratorios Python, Android, SS7, phishing y tráfico benigno.
- [Excel](Excel/): tablas de trabajo para clasificar las técnicas y recoger los resultados de la comparación.
- [JSON-MITRE](JSON-MITRE/): datos de MITRE ATT&CK Mobile utilizados como referencia.

Por su tamaño, los datasets de tráfico benigno quedan fuera de Git. Su procedencia se conserva en [PCAPs/Benigno/Fuente.md](PCAPs/Benigno/Fuente.md).

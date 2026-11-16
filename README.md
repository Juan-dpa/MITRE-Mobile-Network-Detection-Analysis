# Análisis de rendimiento de NGFW/IDS/IPS en MITRE ATT&CK Mobile

Continuando con la línea de investigación del departamento de Ingeniería Telemática de la Universidad de Sevilla, este Trabajo Fin de Grado estudia las capacidades de detección de Snort, FortiGate y Palo Alto en el entorno móvil (Android/iOS). El marco de referencia utilizado es **MITRE ATT&CK Mobile, versión 18**.

El objetivo es comparar el rendimiento detectivo de Snort como sistema Open Source frente a los NGFW (Cortafuegos de próxima generación) de Fortinet y Palo Alto, utilizando tráfico malicioso y benigno para evaluar las detecciones y los falsos positivos. El estudio se centra en las técnicas y subtécnicas observables a nivel de red.

## Procedimiento

El estudio se puede descomponer en las siguientes fases:

1. Seleccionar las técnicas de MITRE ATT&CK Mobile observables en red y las familias de malware que permitan estudiarlas.
2. Analizar el código de las muestras y las referencias técnicas para identificar los protocolos, mensajes y secuencias de comunicación asociados a cada técnica.
3. Obtener capturas de tráfico (PCAPs) de datasets o generarlas en laboratorios controlados, ejecutando muestras en Android Emulator o reproduciendo sus comunicaciones mediante clientes y servidores Python. Recopilar también tráfico benigno de aplicaciones legítimas.
4. Comprobar en Wireshark que las capturas contienen los comportamientos descritos, utilizando las claves o secretos de sesión del laboratorio cuando sea necesario.
5. Suministrar las capturas a Snort, con los conjuntos de reglas seleccionados, y a FortiGate y Palo Alto. Analizar los logs generados tanto con tráfico malicioso como con tráfico benigno.
6. Crear tablas de detecciones que relacionen las alertas con las técnicas estudiadas y comparar la cobertura, los falsos positivos y las limitaciones de cada sistema.

## Contenido del repositorio

- [Documentos/Markdowns](Documentos/Markdowns/): objetivos, marco teórico, análisis de las muestras y procedimientos de laboratorio.
- [Documentos/Memoria-Quarto](Documentos/Memoria-Quarto/): fuentes de la memoria del TFG.
- [python-labnet](python-labnet/): código y herramientas para preparar los escenarios y capturar sus comunicaciones.
- [PCAPs](PCAPs/): capturas organizadas por laboratorios Python, Android, SS7, phishing y tráfico benigno.
- [Excel](Excel/): tablas de trabajo para clasificar las técnicas y recoger los resultados de la comparación.
- [JSON-MITRE](JSON-MITRE/): datos de MITRE ATT&CK Mobile utilizados como referencia.

Por su tamaño, los datasets de tráfico benigno quedan fuera de Git. Su procedencia se conserva en [PCAPs/Benigno/Fuente.md](PCAPs/Benigno/Fuente.md).

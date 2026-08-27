# Memoria TFG con Quarto

Los ficheros `.qmd` son las fuentes editables. `Memoria_TFG.tex`, `_book/` y los
recursos generados por Quarto son productos de compilación y no deben editarse a
mano.

La salida PDF utiliza la clase oficial `etsibook` de la ETSI. Los datos de la
cubierta y la portada se centralizan bajo la clave `etsi` de `_quarto.yml`.
Todos los campos marcados como `PENDIENTE` deben completarse antes de entregar
la memoria. La lista `etsi.directors` admite varios tutores y también el tutor
ponente requerido cuando el tutor principal no pertenece a la ETSI.

Durante la redacción se usa una maquetación a una cara, sin corrección de
encuadernación, para que todas las páginas tengan el mismo margen. Si la copia
final se imprime y encuaderna a doble cara, se debe cambiar `sides=oneside` por
`sides=twoside` y retirar las dos instrucciones de `latex/etsi-layout.tex` para
recuperar la configuración oficial de impresión.

## Previsualización y PDF

Desde la raíz del proyecto:

```powershell
quarto preview
quarto render
quarto render --to pdf
```

También se pueden ejecutar desde los botones **Preview** y **Render** de la
extensión de Quarto para Visual Studio Code.

`quarto preview` genera la vista HTML. `quarto render` construye HTML y PDF en
una misma ejecución. Para regenerar únicamente el entregable PDF, se puede usar
`quarto render --to pdf`.

## Incorporación de una muestra

1. Copiar el Markdown original a `repositorio/<identificador>-<nombre>.qmd`.
2. Añadir como primer encabezado `### <identificador> -- <nombre>`.
3. Bajar un nivel los encabezados internos de la muestra.
4. Cambiar la etiqueta de cada bloque Mermaid de `mermaid` a `{mermaid}` y
   añadir `label`, `fig-cap` y un `fig-width` compatible con A4.
5. Incluir el fichero en `04-repositorio.qmd` mediante el shortcode `include`.
6. Ejecutar primero el render HTML y después el PDF.

El Markdown original situado fuera de este proyecto se conserva sin cambios.

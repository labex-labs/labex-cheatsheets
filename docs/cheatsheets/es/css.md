---
title: 'Hoja de Trucos CSS | LabEx'
description: 'Aprenda CSS3 con esta hoja de trucos completa. Referencia rápida para selectores CSS, flexbox, grid, animaciones, diseño responsivo y técnicas modernas de estilo para desarrolladores web.'
pdfUrl: '/cheatsheets/pdf/css-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de CSS
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/css">Aprende CSS con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende el estilo web con CSS a través de laboratorios prácticos y escenarios del mundo real. LabEx proporciona cursos completos de CSS que cubren propiedades esenciales, selectores, técnicas de diseño, diseño responsivo y características modernas. Domina el estilo web eficiente y el diseño de maquetación para flujos de trabajo de desarrollo web modernos.
</base-disclaimer-content>
</base-disclaimer>

## Sintaxis CSS y Selectores

### Sintaxis Básica

CSS consiste en selectores y declaraciones. El selector apunta a elementos HTML, y las declaraciones establecen valores de propiedad.

```css
/* Sintaxis básica */
selector {
  property: value;
  property: value;
}

/* Ejemplo */
p {
  color: red;
  font-size: 16px;
}
```

### Selectores de Elementos

Apuntan a elementos HTML por su nombre de etiqueta.

```css
/* Seleccionar todos los párrafos */
p {
  color: blue;
}

/* Seleccionar todos los encabezados */
h1 {
  font-size: 2em;
}

/* Seleccionar todos los enlaces */
a {
  text-decoration: none;
}
```

### Selectores de Clase

Apuntan a elementos con atributos de clase específicos.

```css
/* Seleccionar elementos con class="highlight" */
.highlight {
  background-color: yellow;
}

/* Seleccionar párrafos con class="intro" */
p.intro {
  font-weight: bold;
}

/* Clases múltiples */
.large.bold {
  font-size: 20px;
  font-weight: bold;
}
```

<BaseQuiz id="css-class-1" correct="B">
  <template #question>
    ¿Cómo seleccionas un elemento con class="highlight" en CSS?
  </template>
  
  <BaseQuizOption value="A">highlight { }</BaseQuizOption>
  <BaseQuizOption value="B" correct>.highlight { }</BaseQuizOption>
  <BaseQuizOption value="C">#highlight { }</BaseQuizOption>
  <BaseQuizOption value="D">class="highlight" { }</BaseQuizOption>
  
  <BaseQuizAnswer>
    Los selectores de clase usan un prefijo de punto (<code>.</code>). <code>.highlight</code> selecciona todos los elementos con <code>class="highlight"</code>. Los selectores de ID usan <code>#</code>, y los selectores de elemento no usan prefijo.
  </BaseQuizAnswer>
</BaseQuiz>

### Selectores de ID

Apuntan a elementos con atributos de ID específicos.

```css
/* Seleccionar elemento con id="header" */
#header {
  background-color: #333;
}

/* Los IDs deben ser únicos por página */
#navigation {
  position: fixed;
}
```

### Selectores de Atributo

Apuntan a elementos con ciertos atributos usando selectores de atributo.

```css
/* Elementos con atributo title */
[title] {
  cursor: help;
}

/* Enlaces a sitios externos */
a[href^='http'] {
  color: red;
}

/* Elementos de entrada de tipo texto */
input[type='text'] {
  border: 1px solid #ccc;
}
```

### Pseudo-clases

Las pseudo-clases aplican CSS basándose en cambios de estado e interacciones del usuario.

```css
/* Estados de enlace */
a:hover {
  color: red;
}
a:visited {
  color: purple;
}
a:active {
  color: orange;
}

/* Estados de formulario */
input:focus {
  border-color: blue;
}
input:invalid {
  border-color: red;
}

/* Pseudo-clases estructurales */
li:first-child {
  font-weight: bold;
}
li:nth-child(odd) {
  background-color: #f0f0f0;
}
```

## Modelo de Caja y Diseño

### Contenido: `width` / `height`

El área de contenido real del elemento.

```css
/* Establecer dimensiones */
div {
  width: 300px;
  height: 200px;
}

/* Dimensionamiento responsivo */
.container {
  width: 100%;
  max-width: 1200px;
}

/* Restricciones mínimas/máximas */
.box {
  min-height: 100px;
  max-width: 500px;
}
```

### Relleno (Padding): `padding`

Espacio entre el contenido y el borde, dentro del elemento.

```css
/* Todos los lados */
div {
  padding: 20px;
}

/* Lados individuales */
div {
  padding-top: 10px;
  padding-right: 15px;
}

/* Abreviatura: arriba derecha abajo izquierda */
div {
  padding: 10px 15px 20px 5px;
}
```

<BaseQuiz id="css-padding-1" correct="C">
  <template #question>
    ¿Qué establece <code>padding: 10px 20px</code>?
  </template>
  
  <BaseQuizOption value="A">10px arriba/abajo, 20px izquierda/derecha</BaseQuizOption>
  <BaseQuizOption value="B">10px en todos los lados</BaseQuizOption>
  <BaseQuizOption value="C" correct>10px arriba/abajo, 20px izquierda/derecha</BaseQuizOption>
  <BaseQuizOption value="D">10px arriba, 20px abajo</BaseQuizOption>
  
  <BaseQuizAnswer>
    Cuando se proporcionan dos valores, el primero se aplica a arriba y abajo, y el segundo a izquierda y derecha. Por lo tanto, <code>padding: 10px 20px</code> significa 10px de relleno vertical y 20px de relleno horizontal.
  </BaseQuizAnswer>
</BaseQuiz>
```

### Borde (Border): `border`

Los bordes proporcionan un marco para los elementos con tamaño, estilo y color personalizables.

```css
/* Abreviatura de borde */
div {
  border: 2px solid #333;
}

/* Propiedades individuales */
div {
  border-width: 1px;
  border-style: dashed;
  border-color: red;
}

/* Lados individuales */
div {
  border-bottom: 3px solid blue;
}
```

### Margen (Margin): `margin`

Espacio fuera del borde, entre elementos.

```css
/* Todos los lados */
div {
  margin: 20px;
}

/* Centrar horizontalmente */
div {
  margin: 0 auto;
}

/* Lados individuales */
div {
  margin-top: 30px;
  margin-bottom: 10px;
}

/* Márgenes negativos */
div {
  margin-left: -20px;
}
```

<BaseQuiz id="css-margin-1" correct="C">
  <template #question>
    ¿Qué hace <code>margin: 0 auto</code>?
  </template>
  
  <BaseQuizOption value="A">Elimina todos los márgenes</BaseQuizOption>
  <BaseQuizOption value="B">Añade márgenes iguales en todos los lados</BaseQuizOption>
  <BaseQuizOption value="C" correct>Centra un elemento de bloque horizontalmente</BaseQuizOption>
  <BaseQuizOption value="D">Centra un elemento de bloque verticalmente</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>margin: 0 auto</code> establece los márgenes superior e inferior en 0 y los márgenes izquierdo/derecho en auto, lo que centra un elemento de nivel de bloque horizontalmente dentro de su contenedor.
  </BaseQuizAnswer>
</BaseQuiz>

## Texto y Tipografía

### Propiedades de Fuente

Controlan la familia, el tamaño, el grosor y el estilo de la fuente.

```css
/* Familia de fuentes */
body {
  font-family: Arial, sans-serif;
}

/* Google Fonts */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
body {
  font-family: 'Roboto', sans-serif;
}

/* Tamaño de fuente */
h1 {
  font-size: 2rem;
}
p {
  font-size: 16px;
}

/* Grosor de fuente */
h2 {
  font-weight: bold;
}
span {
  font-weight: 300;
}
```

### Alineación de Texto

Controlan la posición y el espaciado del texto.

```css
/* Alineación horizontal */
h1 {
  text-align: center;
}
p {
  text-align: justify;
}

/* Altura de línea */
p {
  line-height: 1.6;
}

/* Espaciado de letras y palabras */
h1 {
  letter-spacing: 2px;
}
p {
  word-spacing: 4px;
}
```

### Estilo de Texto

Añaden decoraciones y transformaciones al texto.

```css
/* Decoración de texto */
a {
  text-decoration: underline;
}
.strike {
  text-decoration: line-through;
}

/* Transformación de texto */
.uppercase {
  text-transform: uppercase;
}
.capitalize {
  text-transform: capitalize;
}

/* Sombra de texto */
h1 {
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}
```

### Colores

CSS proporciona varias formas diferentes de especificar colores para diversas necesidades de estilo.

```css
/* Formatos de color */
p {
  color: red;
}
div {
  background-color: #ff5733;
}
```

<BaseQuiz id="css-colors-1" correct="D">
  <template #question>
    ¿Qué formato de color CSS se utiliza más comúnmente para el diseño web?
  </template>
  
  <BaseQuizOption value="A">Solo RGB</BaseQuizOption>
  <BaseQuizOption value="B">Solo colores con nombre</BaseQuizOption>
  <BaseQuizOption value="C">Solo HSL</BaseQuizOption>
  <BaseQuizOption value="D" correct>Los códigos Hex (#RRGGBB) son muy comunes, junto con colores con nombre y RGB</BaseQuizOption>
  
  <BaseQuizAnswer>
    Los códigos de color Hex (#RRGGBB) se utilizan ampliamente porque son concisos y fáciles de copiar desde las herramientas de diseño. Los colores con nombre y RGB/rgba también son comunes. La elección depende del caso de uso específico y la preferencia.
  </BaseQuizAnswer>
</BaseQuiz>
span {
  color: rgb(255, 87, 51);
}
section {
  background-color: rgba(255, 87, 51, 0.8);
}

/_ Colores HSL _/
header {
background-color: hsl(200, 100%, 50%);
}

/_ Variables CSS para colores _/
:root {
--primary-color: #3498db;
}
.button {
background-color: var(--primary-color);
}

````

## Diseño Flexbox

### Propiedades del Contenedor Flex

Propiedades aplicadas al contenedor padre.

```css
/* Habilitar flexbox */
.container {
  display: flex;
}

/* Dirección del flex */
.container {
  flex-direction: row; /* por defecto */
  flex-direction: column;
  flex-direction: row-reverse;
}

/* Justificar contenido (eje principal) */
.container {
  justify-content: flex-start; /* por defecto */
  justify-content: center;
  justify-content: space-between;
  justify-content: space-around;
}

/* Alinear elementos (eje transversal) */
.container {
  align-items: stretch; /* por defecto */
  align-items: center;
  align-items: flex-start;
}
````

### Propiedades del Elemento Flex

Propiedades aplicadas a los elementos hijos.

```css
/* Flex grow/shrink */
.item {
  flex-grow: 1; /* crecer para llenar el espacio */
  flex-shrink: 1; /* encoger si es necesario */
  flex-basis: auto; /* tamaño inicial */
}

/* Abreviatura */
.item {
  flex: 1; /* flex: 1 1 0% */
  flex: 0 0 200px; /* ancho fijo */
}

/* Alineación individual */
.item {
  align-self: center;
  align-self: flex-end;
}

/* Orden */
.item {
  order: 2; /* cambiar el orden visual */
}
```

## Diseño CSS Grid

### Contenedor Grid

Define la estructura y las propiedades de la cuadrícula.

```css
/* Habilitar grid */
.grid-container {
  display: grid;
}

/* Definir columnas y filas */
.grid-container {
  grid-template-columns: 1fr 2fr 1fr;
  grid-template-rows: 100px auto 50px;
}

/* Espacios de la cuadrícula */
.grid-container {
  gap: 20px;
  column-gap: 30px;
  row-gap: 10px;
}

/* Áreas de cuadrícula con nombre */
.grid-container {
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}
```

### Elementos Grid

Posicionan y dimensionan los elementos de la cuadrícula.

```css
/* Posicionamiento de la cuadrícula */
.grid-item {
  grid-column: 1 / 3; /* abarcar columnas 1-2 */
  grid-row: 2 / 4; /* abarcar filas 2-3 */
}

/* Abreviatura */
.grid-item {
  grid-area: 2 / 1 / 4 / 3; /* inicio-fila / inicio-col / fin-fila / fin-col */
}

/* Áreas con nombre */
.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}

/* Colocación automática */
.grid-item {
  grid-column: span 2; /* abarcar 2 columnas */
  grid-row: span 3; /* abarcar 3 filas */
}
```

## Posicionamiento

### Propiedad Position

Controla el comportamiento de posicionamiento de los elementos.

```css
/* Estático (por defecto) */
.element {
  position: static;
}

/* Posicionamiento relativo */
.element {
  position: relative;
  top: 20px;
  left: 10px;
}

/* Posicionamiento absoluto */
.element {
  position: absolute;
  top: 0;
  right: 0;
}

/* Posicionamiento fijo */
.navbar {
  position: fixed;
  top: 0;
  width: 100%;
}

/* Posicionamiento pegajoso (sticky) */
.sidebar {
  position: sticky;
  top: 20px;
}
```

### Z-Index y Contexto de Apilamiento

Controla el orden en que los elementos se superponen usando z-index y contexto de apilamiento.

```css
/* Orden de apilamiento */
.modal {
  position: fixed;
  z-index: 1000;
}
.overlay {
  position: absolute;
  z-index: 999;
}

/* Creación de contexto de apilamiento */
.container {
  position: relative;
  z-index: 0;
}

/* Valores comunes de z-index */
.dropdown {
  z-index: 100;
}
.modal {
  z-index: 1000;
}
.tooltip {
  z-index: 10000;
}
```

## Diseño Responsivo

### Media Queries

Aplican estilos basados en las características del dispositivo.

```css
/* Enfoque "mobile first" */
.container {
  width: 100%;
}

/* Estilos para tabletas */
@media (min-width: 768px) {
  .container {
    width: 750px;
  }
}

/* Estilos para escritorio */
@media (min-width: 1024px) {
  .container {
    width: 960px;
  }
}

/* Estilos de impresión */
@media print {
  body {
    font-size: 12pt;
  }
  .no-print {
    display: none;
  }
}

/* Orientación */
@media (orientation: landscape) {
  .sidebar {
    display: block;
  }
}
```

### Unidades Responsivas

Usan unidades relativas para diseños flexibles.

```css
/* Unidades de viewport */
.hero {
  height: 100vh;
} /* altura completa del viewport */
.sidebar {
  width: 25vw;
} /* 25% del ancho del viewport */

/* Unidades relativas */
p {
  font-size: 1.2em;
} /* 1.2x el tamaño de fuente del padre */
h1 {
  font-size: 2rem;
} /* 2x el tamaño de fuente raíz */

/* Unidades porcentuales */
.container {
  width: 80%;
}
.column {
  width: 50%;
}

/* Grid responsivo */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

/* Flexbox responsivo */
.flex-container {
  display: flex;
  flex-wrap: wrap;
}
```

## Animaciones y Transiciones

### Transiciones CSS

Cambios suaves entre valores de propiedad.

```css
/* Transición básica */
.button {
  background-color: blue;
  transition: background-color 0.3s ease;
}
.button:hover {
  background-color: red;
}

/* Múltiples propiedades */
.card {
  transform: scale(1);
  opacity: 1;
  transition: all 0.3s ease-in-out;
}
.card:hover {
  transform: scale(1.05);
  opacity: 0.8;
}

/* Transiciones individuales */
.element {
  transition-property: width, height;
  transition-duration: 0.5s, 1s;
  transition-timing-function: ease, linear;
}
```

### Animaciones CSS

Crear animaciones complejas con keyframes.

```css
/* Definir keyframes */
@keyframes slideIn {
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(0);
  }
}

@keyframes pulse {
  0%,
  100% {
    transform: scale(1);
  }
  50% {
    transform: scale(1.1);
  }
}

/* Aplicar animaciones */
.slide-in {
  animation: slideIn 0.5s ease-out;
}
.pulse {
  animation: pulse 2s infinite;
}

/* Abreviatura de animación */
.spinner {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}
```

## Variables CSS y Funciones

### Variables CSS

Definir y usar propiedades personalizadas para una tematización consistente.

```css
/* Definir variables */
:root {
  --primary-color: #3498db;
  --secondary-color: #2ecc71;
  --font-size-large: 24px;
  --border-radius: 8px;
}

/* Usar variables */
.button {
  background-color: var(--primary-color);
  border-radius: var(--border-radius);
}

/* Valores de reserva */
.text {
  color: var(--text-color, #333);
}

/* Variables locales */
.card {
  --card-padding: 20px;
  padding: var(--card-padding);
}
```

### Funciones CSS

CSS tiene una gama de funciones integradas para cálculos y valores dinámicos.

```css
/* Función Calc */
.container {
  width: calc(100% - 40px);
  height: calc(100vh - 60px);
}

/* Funciones Min/Max */
.responsive {
  width: min(90%, 1200px);
  font-size: max(16px, 1.2vw);
  height: clamp(200px, 50vh, 400px);
}

/* Funciones de color */
.element {
  background-color: hsl(200, 50%, 50%);
  color: rgb(255, 87, 51);
}

/* Funciones de transformación */
.rotate {
  transform: rotate(45deg);
}
.scale {
  transform: scale(1.5);
}
.translate {
  transform: translate(20px, 30px);
}
```

## Mejores Prácticas y Organización

### Organización CSS

Estructura tu CSS para el mantenimiento.

```css
/* Usar nombres de clase significativos */
.hero-section {
}
.primary-button {
}
.navigation-menu {
}

/* Metodología BEM */
.block {
}
.block__element {
}
.block--modifier {
}

/* Ejemplo */
.card {
}
.card__header {
}
.card__body {
}
.card--featured {
}

/* Agrupar estilos relacionados */
/* ===== DISEÑO (LAYOUT) ===== */
.container {
}
.grid {
}

/* ===== COMPONENTES ===== */
.button {
}
.card {
}
```

### Rendimiento y Optimización

Escribir CSS eficiente para un mejor rendimiento.

```css
/* Evitar anidamiento profundo */
/* Malo */
.header .nav ul li a {
}

/* Bueno */
.nav-link {
}

/* Usar selectores eficientes */
/* Malo */
body div.container > p {
}

/* Bueno */
.content-text {
}

/* Minimizar repintados */
/* Usar transform en lugar de cambiar position */
.element {
  transform: translateX(100px);
  /* en lugar de left: 100px; */
}

/* Agrupar prefijos de proveedor */
.element {
  -webkit-border-radius: 5px;
  -moz-border-radius: 5px;
  border-radius: 5px;
}
```

## Depuración CSS

### Herramientas de Desarrollo del Navegador

Inspeccionar y modificar CSS en tiempo real.

```css
/* Pasos comunes de depuración */
/* 1. Clic derecho → Inspeccionar Elemento */
/* 2. Revisar estilos Calculados */
/* 3. Buscar propiedades anuladas */
/* 4. Probar cambios en tiempo real */
/* 5. Copiar el CSS modificado de vuelta a tu archivo */
```

### Problemas Comunes de CSS

Solucionar problemas encontrados frecuentemente.

```css
/* Problemas del modelo de caja */
* {
  box-sizing: border-box;
}

/* Limpiar floats */
.clearfix::after {
  content: '';
  display: table;
  clear: both;
}

/* Problemas de z-index */
/* Asegurar elementos posicionados para que z-index funcione */
.element {
  position: relative;
  z-index: 1;
}
```

### Validación CSS

Asegurarse de que tu CSS sigue los estándares y las mejores prácticas.

```css
/* Usar validadores CSS */
/* Validador CSS W3C */
/* Herramientas de compatibilidad del navegador */

/* Comentar tu código */
/* ===== ESTILOS DEL ENCABEZADO ===== */
.header {
}

/* TODO: Añadir estilos móviles */
/* FIXME: Arreglar compatibilidad con IE */

/* Usar formato consistente */
.element {
  property: value;
  property: value;
}
```

## Frameworks y Herramientas CSS

### Preprocesadores CSS

Extienden CSS con variables, anidamiento y funciones.

```scss
/* Ejemplo SCSS/Sass */
$primary-color: #3498db;
$border-radius: 8px;

.button {
  background-color: $primary-color;
  border-radius: $border-radius;

  &:hover {
    background-color: darken($primary-color, 10%);
  }
}
```

```less
/* Ejemplo Less */
@primary-color: #3498db;

.button {
  background-color: @primary-color;

  &:hover {
    background-color: lighten(@primary-color, 10%);
  }
}
```

### CSS-in-JS y Herramientas Modernas

Enfoques modernos para el estilo en aplicaciones web.

```css
/* Plugins PostCSS */
/* Autoprefixer - añade prefijos de proveedor */
/* PurgeCSS - elimina el CSS no utilizado */

/* Módulos CSS */
.button {
  composes: base-button;
  background-color: blue;
}
```

```javascript
/* CSS de utilidad primero (Tailwind) */
;<div class="flex items-center justify-center p-4 bg-blue-500">
  <span class="text-white font-bold">Button</span>
</div>

/* CSS-in-JS (Styled Components) */
const Button = styled.button`
  background: ${(props) => (props.primary ? 'blue' : 'white')};
  padding: 1rem 2rem;
`
```

## Enlaces Relevantes

- <router-link to="/html">Hoja de Trucos de HTML</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/react">Hoja de Trucos de React</router-link>
- <router-link to="/web-development">Hoja de Trucos de Desarrollo Web</router-link>

---
title: 'Hoja de Trucos de HTML | LabEx'
description: 'Aprenda HTML5 con esta hoja de trucos completa. Referencia rápida de etiquetas HTML, elementos semánticos, formularios, accesibilidad y estándares modernos de desarrollo web para desarrolladores frontend.'
pdfUrl: '/cheatsheets/pdf/html-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de HTML
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/html">Aprende HTML con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende la estructura web de HTML a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de HTML que cubren elementos esenciales, marcado semántico, formularios, integración de medios y características modernas de HTML5. Domina la estructura eficiente de páginas web y la organización de contenido para flujos de trabajo de desarrollo web modernos.
</base-disclaimer-content>
</base-disclaimer>

## Estructura del Documento HTML

### Documento HTML Básico: `<!DOCTYPE html>`

Cada documento HTML comienza con una declaración de tipo de documento y sigue una estructura estándar.

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Page Title</title>
  </head>
  <body>
    <!-- El contenido de la página va aquí -->
  </body>
</html>
```

<BaseQuiz id="html-doctype-1" correct="A">
  <template #question>
    ¿Cuál es el propósito de <code><!DOCTYPE html></code>?
  </template>
  
  <BaseQuizOption value="A" correct>Declara el tipo de documento y la versión de HTML</BaseQuizOption>
  <BaseQuizOption value="B">Crea un nuevo elemento HTML</BaseQuizOption>
  <BaseQuizOption value="C">Vincula a una hoja de estilo externa</BaseQuizOption>
  <BaseQuizOption value="D">Establece el título de la página</BaseQuizOption>
  
  <BaseQuizAnswer>
    La declaración <code><!DOCTYPE html></code> le dice al navegador qué versión de HTML está utilizando el documento. Para HTML5, esta simple declaración es suficiente y debe ser la primera línea de cada documento HTML.
  </BaseQuizAnswer>
</BaseQuiz>

### Elementos Head: `<head>`

La sección head contiene metadatos sobre el documento.

```html
<!-- Codificación de caracteres -->
<meta charset="UTF-8" />
<!-- Viewport para diseño responsivo -->
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<!-- Descripción de la página -->
<meta name="description" content="Page description" />
<!-- Enlace a CSS -->
<link rel="stylesheet" href="styles.css" />
<!-- Enlace a favicon -->
<link rel="icon" href="favicon.ico" />
```

### Comentarios HTML: `<!-- -->`

Los comentarios no se muestran, pero ayudan a documentar tu código.

```html
<!-- Este es un comentario -->
<!-- 
  Comentario multilínea
  para explicaciones más largas
-->
```

### Anatomía de los Elementos HTML

Los elementos HTML consisten en etiquetas de apertura, contenido y etiquetas de cierre.

```html
<!-- Elemento con contenido -->
<p>This is a paragraph</p>
<!-- Elementos auto-cerrados -->
<img src="image.jpg" alt="Description" />
<br />
<hr />
<!-- Elementos con atributos -->
<a href="https://example.com" target="_blank">Link</a>
<!-- Elementos anidados -->
<div>
  <p>Nested paragraph</p>
</div>
```

## Elementos de Contenido de Texto

### Encabezados: `h1` a `h6`

Definen la jerarquía e importancia de las secciones de contenido.

```html
<h1>Main Title</h1>
<h2>Section Title</h2>
<h3>Subsection Title</h3>
<h4>Sub-subsection Title</h4>
<h5>Minor Heading</h5>
<h6>Smallest Heading</h6>
```

<BaseQuiz id="html-headings-1" correct="B">
  <template #question>
    ¿Cuál es la jerarquía correcta de encabezados?
  </template>
  
  <BaseQuizOption value="A">h1 debe usarse varias veces en una página</BaseQuizOption>
  <BaseQuizOption value="B" correct>h1 debe usarse una vez como título principal, seguido de h2, h3, etc.</BaseQuizOption>
  <BaseQuizOption value="C">Todos los encabezados tienen la misma importancia</BaseQuizOption>
  <BaseQuizOption value="D">h6 es el encabezado más importante</BaseQuizOption>
  
  <BaseQuizAnswer>
    Los encabezados HTML deben seguir una jerarquía lógica: usa un <code>h1</code> para el título principal de la página, luego <code>h2</code> para las secciones principales, <code>h3</code> para las subsecciones, y así sucesivamente. Esto ayuda con la accesibilidad y el SEO.
  </BaseQuizAnswer>
</BaseQuiz>

### Párrafos: `p`

El elemento más común para bloques de contenido de texto.

```html
<p>
  This is a paragraph of text. It can contain multiple sentences and will wrap
  automatically.
</p>
<p>This is another paragraph. Paragraphs are separated by margin space.</p>
```

### Formato de Texto: `<strong>`, `<em>`, `<b>`, `<i>`

Elementos para enfatizar y dar estilo al texto en línea.

```html
<strong>Strong importance (bold)</strong>
<em>Emphasis (italic)</em>
<b>Bold text</b>
<i>Italic text</i>
<u>Underlined text</u>
<mark>Highlighted text</mark>
<small>Small text</small>
<del>Deleted text</del>
<ins>Inserted text</ins>
```

### Saltos de Línea y Espacio: `<br>`, `<hr>`, `<pre>`

Controlan el flujo de texto y el espaciado dentro del contenido.

```html
<!-- Salto de línea -->
Line 1<br />
Line 2
<!-- Regla horizontal -->
<hr />
<!-- Texto preformateado -->
<pre>
  Text with
    preserved    spacing
      and line breaks
</pre>
<!-- Formato de código -->
<code>console.log('Hello');</code>
```

## Listas y Navegación

### Listas Desordenadas: `<ul>`

Crea listas con viñetas para elementos no secuenciales.

```html
<ul>
  <li>First item</li>
  <li>Second item</li>
  <li>Third item</li>
</ul>
<!-- Listas anidadas -->
<ul>
  <li>
    Main item
    <ul>
      <li>Sub item 1</li>
      <li>Sub item 2</li>
    </ul>
  </li>
</ul>
```

### Listas Ordenadas: `<ol>`

Crea listas numeradas para elementos secuenciales.

```html
<ol>
  <li>First step</li>
  <li>Second step</li>
  <li>Third step</li>
</ol>
<!-- Numeración personalizada -->
<ol start="5">
  <li>Item 5</li>
  <li>Item 6</li>
</ol>
<!-- Tipos de numeración diferentes -->
<ol type="A">
  <li>Item A</li>
  <li>Item B</li>
</ol>
```

### Listas de Descripción: `<dl>`

Crea listas de términos y sus descripciones.

```html
<dl>
  <dt>HTML</dt>
  <dd>HyperText Markup Language</dd>

  <dt>CSS</dt>
  <dd>Cascading Style Sheets</dd>

  <dt>JavaScript</dt>
  <dd>Programming language for web</dd>
</dl>
```

### Enlaces y Navegación: `<a>`

Crea hipervínculos y estructuras de navegación.

```html
<!-- Enlace básico -->
<a href="https://example.com">Visit Example</a>
<!-- Enlace en nueva pestaña -->
<a href="https://example.com" target="_blank">New Tab</a>
<!-- Enlace de correo electrónico -->
<a href="mailto:email@example.com">Send Email</a>
<!-- Enlace telefónico -->
<a href="tel:+1234567890">Call Us</a>
<!-- Anclas de página internas -->
<a href="#section1">Go to Section 1</a>
<h2 id="section1">Section 1</h2>
```

<BaseQuiz id="html-links-1" correct="B">
  <template #question>
    ¿Qué hace <code>target="_blank"</code> en una etiqueta de anclaje?
  </template>
  
  <BaseQuizOption value="A">Abre el enlace en la misma ventana</BaseQuizOption>
  <BaseQuizOption value="B" correct>Abre el enlace en una nueva pestaña o ventana</BaseQuizOption>
  <BaseQuizOption value="C">Cierra la ventana actual</BaseQuizOption>
  <BaseQuizOption value="D">Descarga el enlace</BaseQuizOption>
  
  <BaseQuizAnswer>
    El atributo <code>target="_blank"</code> abre la página enlazada en una nueva pestaña o ventana del navegador, permitiendo a los usuarios mantener abierta la página original.
  </BaseQuizAnswer>
</BaseQuiz>

## Formularios y Elementos de Entrada

### Estructura Básica del Formulario: `<form>`

La base para la recopilación de entradas del usuario.

```html
<form action="/submit" method="POST">
  <label for="username">Username:</label>
  <input type="text" id="username" name="username" required />

  <label for="email">Email:</label>
  <input type="email" id="email" name="email" required />

  <input type="submit" value="Submit" />
</form>
```

### Tipos de Entrada: `<input>`

Varios tipos de entrada para diferentes necesidades de recopilación de datos.

```html
<!-- Entradas de texto -->
<input type="text" placeholder="Enter text" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="Password" />
<input type="url" placeholder="https://example.com" />
<input type="tel" placeholder="+1234567890" />
<!-- Entradas numéricas -->
<input type="number" min="1" max="100" step="1" />
<input type="range" min="0" max="100" value="50" />
<!-- Fecha y hora -->
<input type="date" />
<input type="time" />
<input type="datetime-local" />
```

### Controles de Formulario: `<checkbox>`, `<radio>`, `<select>`, `<textarea>`

Elementos de formulario adicionales para la interacción del usuario.

```html
<!-- Checkboxes -->
<input type="checkbox" id="agree" name="agree" />
<label for="agree">I agree to terms</label>
<!-- Botones de radio -->
<input type="radio" id="option1" name="choice" value="1" />
<label for="option1">Option 1</label>
<input type="radio" id="option2" name="choice" value="2" />
<label for="option2">Option 2</label>
<!-- Menú desplegable Select -->
<select name="country">
  <option value="us">United States</option>
  <option value="uk">United Kingdom</option>
  <option value="ca">Canada</option>
</select>
<!-- Textarea -->
<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="Enter your message"
></textarea>
```

### Validación de Formularios: `required`, `min`, `max`, `pattern`

Atributos de validación de formularios integrados en HTML.

```html
<input type="text" required />
<input type="email" required />
<input type="text" minlength="3" maxlength="20" />
<input type="number" min="1" max="100" />
<input type="text" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}" />
```

<BaseQuiz id="html-validation-1" correct="A">
  <template #question>
    ¿Qué hace el atributo <code>required</code> en una entrada HTML?
  </template>
  
  <BaseQuizOption value="A" correct>Evita el envío del formulario si el campo está vacío</BaseQuizOption>
  <BaseQuizOption value="B">Hace que el campo solo de lectura</BaseQuizOption>
  <BaseQuizOption value="C">Oculta el campo</BaseQuizOption>
  <BaseQuizOption value="D">Establece un valor predeterminado</BaseQuizOption>
  
  <BaseQuizAnswer>
    El atributo <code>required</code> hace que un campo de entrada sea obligatorio. Si el campo está vacío al enviar el formulario, el navegador evitará el envío y mostrará un mensaje de validación.
  </BaseQuizAnswer>
</BaseQuiz>

## Elementos Multimedia

### Imágenes: `<img>`, `<picture>`

Muestra imágenes con varios atributos y opciones.

```html
<!-- Imagen básica -->
<img src="image.jpg" alt="Description" />
<!-- Imagen responsiva -->
<img src="image.jpg" alt="Description" width="100%" height="auto" />
<!-- Imagen con tamaño -->
<img src="image.jpg" alt="Description" width="300" height="200" />
<!-- Elemento Picture para imágenes responsivas -->
<picture>
  <source media="(min-width: 800px)" srcset="large.jpg" />
  <source media="(min-width: 400px)" srcset="medium.jpg" />
  <img src="small.jpg" alt="Description" />
</picture>
```

### Audio: `<audio>`

Incorpora contenido de audio con controles de reproducción.

```html
<!-- Audio básico -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
  <source src="audio.ogg" type="audio/ogg" />
  Your browser does not support audio.
</audio>
<!-- Audio con reproducción automática -->
<audio controls autoplay loop>
  <source src="background.mp3" type="audio/mpeg" />
</audio>
```

### Video: `<video>`

Incorpora contenido de video con opciones completas.

```html
<!-- Video básico -->
<video controls width="400" height="300">
  <source src="video.mp4" type="video/mp4" />
  <source src="video.webm" type="video/webm" />
  Your browser does not support video.
</video>
<!-- Video con póster y atributos -->
<video controls poster="thumbnail.jpg" width="100%" height="auto">
  <source src="video.mp4" type="video/mp4" />
  <track src="captions.vtt" kind="captions" srclang="en" label="English" />
</video>
```

### Contenido Incrustado: `<iframe>`

Incrusta contenido y aplicaciones externas.

```html
<!-- iFrame para contenido externo -->
<iframe src="https://example.com" width="100%" height="400"></iframe>
<!-- Incrustación de video de YouTube -->
<iframe
  width="560"
  height="315"
  src="https://www.youtube.com/embed/VIDEO_ID"
></iframe>
<!-- Incrustación de Google Maps -->
<iframe src="https://maps.google.com/..."></iframe>
```

## Tablas

### Estructura Básica de Tabla: `<table>`

Crea visualizaciones de datos estructurados con tablas.

```html
<table>
  <thead>
    <tr>
      <th>Name</th>
      <th>Age</th>
      <th>City</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>John</td>
      <td>25</td>
      <td>New York</td>
    </tr>
    <tr>
      <td>Jane</td>
      <td>30</td>
      <td>London</td>
    </tr>
  </tbody>
</table>
```

### Características Avanzadas de Tabla: `rowspan`, `colspan`, `<caption>`

Funcionalidad de tabla mejorada con expansión y agrupación.

```html
<table>
  <caption>
    Sales Report
  </caption>
  <colgroup>
    <col style="width: 50%" />
    <col style="width: 25%" />
    <col style="width: 25%" />
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">Product</th>
      <th colspan="2">Sales</th>
    </tr>
    <tr>
      <th>Q1</th>
      <th>Q2</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Product A</td>
      <td>$1000</td>
      <td>$1200</td>
    </tr>
  </tbody>
</table>
```

## Elementos Semánticos HTML5

### Elementos de Estructura de Página: `<header>`, `<nav>`, `<main>`, `<footer>`

Definen las secciones principales del diseño de tu página.

```html
<!-- Encabezado de página -->
<header>
  <nav>
    <ul>
      <li><a href="#home">Home</a></li>
      <li><a href="#about">About</a></li>
    </ul>
  </nav>
</header>
<!-- Contenido principal -->
<main>
  <article>
    <h1>Article Title</h1>
    <p>Article content...</p>
  </article>
</main>
<!-- Barra lateral -->
<aside>
  <h2>Related Links</h2>
  <ul>
    <li><a href="#">Link 1</a></li>
  </ul>
</aside>
<!-- Pie de página de la página -->
<footer>
  <p>© 2024 Company Name</p>
</footer>
```

### Elementos de Agrupación de Contenido: `<section>`, `<article>`, `<div>`, `<figure>`

Organizan y agrupan secciones de contenido relacionado.

```html
<!-- Sección genérica -->
<section>
  <h2>Section Title</h2>
  <p>Section content...</p>
</section>
<!-- Artículo independiente -->
<article>
  <header>
    <h1>Article Title</h1>
    <time datetime="2024-01-01">January 1, 2024</time>
  </header>
  <p>Article content...</p>
</article>
<!-- Contenedor genérico -->
<div class="container">
  <p>Generic content grouping</p>
</div>
<!-- Figura con pie de foto -->
<figure>
  <img src="chart.jpg" alt="Sales Chart" />
  <figcaption>Sales data for Q1 2024</figcaption>
</figure>
```

## Atributos HTML

### Atributos Globales: `id`, `class`, `title`, `data-*`

Atributos que se pueden usar en cualquier elemento HTML.

```html
<!-- ID para identificación única -->
<div id="unique-element">Content</div>
<!-- Clase para estilo y selección -->
<p class="highlight important">Text</p>
<!-- Título para tooltips -->
<span title="This is a tooltip">Hover me</span>
<!-- Atributos de datos -->
<div data-user-id="123" data-role="admin">User</div>
<!-- Idioma -->
<p lang="es">Hola mundo</p>
<!-- Dirección del contenido -->
<p dir="rtl">Right to left text</p>
<!-- Elementos ocultos -->
<div hidden>This won't be displayed</div>
```

### Atributos de Accesibilidad: `alt`, `aria-*`, `tabindex`, `role`

Atributos que mejoran la accesibilidad y la experiencia del usuario.

```html
<!-- Texto alternativo para imágenes -->
<img src="photo.jpg" alt="A sunset over mountains" />
<!-- Etiquetas ARIA -->
<button aria-label="Close dialog">×</button>
<div aria-hidden="true">Decorative content</div>
<!-- Accesibilidad del formulario -->
<label for="email">Email Address:</label>
<input type="email" id="email" aria-describedby="email-help" />
<small id="email-help">We'll never share your email</small>
<!-- Índice de tabulación -->
<div tabindex="0">Focusable div</div>
<div tabindex="-1">Programmatically focusable</div>
<!-- Atributo de rol -->
<div role="button" tabindex="0">Custom button</div>
```

## Características Modernas de HTML5

### Nuevas Características de Entrada: `color`, `search`, `file`, `datalist`

HTML5 introdujo nuevos tipos de entrada y atributos.

```html
<!-- Nuevos tipos de entrada -->
<input type="color" value="#ff0000" />
<input type="search" placeholder="Search..." />
<input type="file" accept="image/*" multiple />
<!-- Datalist para autocompletado -->
<input list="browsers" name="browser" />
<datalist id="browsers">
  <option value="Chrome"></option>
  <option value="Firefox"></option>
  <option value="Safari"></option>
</datalist>
<!-- Progreso y medidor -->
<progress value="70" max="100">70%</progress>
<meter value="0.6">60%</meter>
```

### Canvas y SVG: `<canvas>`, `<svg>`

Capacidades de gráficos y dibujo en HTML5.

```html
<!-- Canvas para gráficos dinámicos -->
<canvas id="myCanvas" width="400" height="200">
  Your browser does not support canvas.
</canvas>
<!-- SVG en línea -->
<svg width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue" stroke="black" stroke-width="2" />
</svg>
```

### Detalles y Resumen: `<details>`, `<summary>`

Crea secciones de contenido colapsables sin JavaScript.

```html
<details>
  <summary>Click to expand</summary>
  <p>
    This content is hidden by default and revealed when clicking the summary.
  </p>
  <ul>
    <li>Item 1</li>
    <li>Item 2</li>
  </ul>
</details>
<details open>
  <summary>This starts expanded</summary>
  <p>Content visible by default.</p>
</details>
```

### Elemento Dialog: `<dialog>`

Funcionalidad nativa de diálogo y modal.

```html
<!-- Elemento Dialog -->
<dialog id="myDialog">
  <h2>Dialog Title</h2>
  <p>Dialog content goes here.</p>
  <button onclick="closeDialog()">Close</button>
</dialog>
<button onclick="openDialog()">Open Dialog</button>
<script>
  function openDialog() {
    document.getElementById('myDialog').showModal()
  }
</script>
```

## Mejores Prácticas y Validación

### Mejores Prácticas de HTML

Escribe HTML limpio, mantenible y accesible.

```html
<!-- Siempre declara el doctype -->
<!DOCTYPE html>
<!-- Usa elementos semánticos -->
<header>...</header>
<main>...</main>
<footer>...</footer>
<!-- Anidación correcta -->
<div>
  <p>Properly nested content</p>
</div>
<!-- Usa minúsculas para elementos y atributos -->
<img src="image.jpg" alt="description" />
<!-- Cierra todas las etiquetas -->
<p>Always close your tags</p>
<!-- Usa texto alt significativo -->
<img src="chart.png" alt="Sales increased 25% in Q4" />
```

### Validación y Depuración de HTML

Asegúrate de que tu HTML sea válido y accesible.

```html
<!-- Usa el Validador HTML de W3C -->
<!-- https://validator.w3.org/ -->
<!-- Errores comunes de validación -->
<!-- Faltan atributos alt -->
<img src="image.jpg" alt="" />
<!-- Proporciona texto alt -->
<!-- Etiquetas sin cerrar -->
<p>Text content</p>
<!-- Siempre cierra las etiquetas -->
<!-- Anidación inválida -->
<p>
  Valid paragraph content
  <!-- No coloques elementos de bloque dentro de párrafos -->
</p>
<!-- Usa herramientas de desarrollador -->
<!-- Clic derecho → Inspeccionar elemento -->
<!-- Revisa la consola en busca de errores -->
<!-- Valida la accesibilidad con WAVE o axe -->
```

## Motores de Plantillas y Frameworks HTML

### Motores de Plantillas: Handlebars, Mustache

Generación dinámica de HTML con lenguajes de plantillas.

```html
<!-- Plantilla de Handlebars -->
<div>
  <h1>{{title}}</h1>
  {{#each items}}
  <p>{{this}}</p>
  {{/each}}
</div>
<!-- Plantilla de Mustache -->
<div>
  <h1>{{title}}</h1>
  {{#items}}
  <p>{{.}}</p>
  {{/items}}
</div>
```

### Componentes Web: `<template>`, Elementos Personalizados

Elementos HTML personalizados reutilizables.

```html
<!-- Definición de elemento personalizado -->
<template id="my-component">
  <style>
    p {
      color: blue;
    }
  </style>
  <p><slot></slot></p>
</template>
<!-- Uso -->
<my-component>Hello World</my-component>
<script>
  class MyComponent extends HTMLElement {
    // Lógica del componente
  }
  customElements.define('my-component', MyComponent)
</script>
```

### Integración de Frameworks: React JSX, Plantillas Vue

HTML dentro de frameworks de JavaScript modernos.

```html
<!-- React JSX -->
function Component() { return (
<div className="container">
  <h1>{title}</h1>
  <p>Content here</p>
</div>
); }
<!-- Plantilla de Vue -->
<template>
  <div class="container">
    <h1>{{ title }}</h1>
    <p v-if="showContent">Content here</p>
  </div>
</template>
```

## Enlaces Relevantes

- <router-link to="/css">Hoja de Trucos de CSS</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/web-development">Hoja de Trucos de Desarrollo Web</router-link>
- <router-link to="/react">Hoja de Trucos de React</router-link>
- <router-link to="/git">Hoja de Trucos de Git</router-link>
- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>

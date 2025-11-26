---
title: 'Hoja de Trucos de HTML'
description: 'Aprenda HTML con nuestra hoja de trucos completa que cubre comandos esenciales, conceptos y mejores prácticas.'
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
<p>Este es un párrafo</p>
<!-- Elementos de autocierre -->
<img src="image.jpg" alt="Description" />
<br />
<hr />
<!-- Elementos con atributos -->
<a href="https://example.com" target="_blank">Enlace</a>
<!-- Elementos anidados -->
<div>
  <p>Párrafo anidado</p>
</div>
```

## Elementos de Contenido de Texto

### Encabezados: `h1` a `h6`

Definen la jerarquía e importancia de las secciones de contenido.

```html
<h1>Título Principal</h1>
<h2>Título de Sección</h2>
<h3>Título de Subsección</h3>
<h4>Título de Sub-subsección</h4>
<h5>Encabezado Menor</h5>
<h6>Encabezado Más Pequeño</h6>
```

### Párrafos: `p`

El elemento más común para bloques de contenido de texto.

```html
<p>
  Este es un párrafo de texto. Puede contener múltiples oraciones y se ajustará
  automáticamente.
</p>
<p>Este es otro párrafo. Los párrafos están separados por espacio de margen.</p>
```

### Formato de Texto: `<strong>`, `<em>`, `<b>`, `<i>`

Elementos para enfatizar y dar estilo al texto en línea.

```html
<strong>Importancia fuerte (negrita)</strong>
<em>Énfasis (cursiva)</em>
<b>Texto en negrita</b>
<i>Texto en cursiva</i>
<u>Texto subrayado</u>
<mark>Texto resaltado</mark>
<small>Texto pequeño</small>
<del>Texto eliminado</del>
<ins>Texto insertado</ins>
```

### Saltos de Línea y Espacio: `<br>`, `<hr>`, `<pre>`

Controlan el flujo de texto y el espaciado dentro del contenido.

```html
<!-- Salto de línea -->
Línea 1<br />
Línea 2
<!-- Regla horizontal -->
<hr />
<!-- Texto preformateado -->
<pre>
  Texto con
    espaciado    preservado
      y saltos de línea
</pre>
<!-- Formato de código -->
<code>console.log('Hello');</code>
```

## Listas y Navegación

### Listas Desordenadas: `<ul>`

Crea listas con viñetas para elementos no secuenciales.

```html
<ul>
  <li>Primer elemento</li>
  <li>Segundo elemento</li>
  <li>Tercer elemento</li>
</ul>
<!-- Listas anidadas -->
<ul>
  <li>
    Elemento principal
    <ul>
      <li>Sub elemento 1</li>
      <li>Sub elemento 2</li>
    </ul>
  </li>
</ul>
```

### Listas Ordenadas: `<ol>`

Crea listas numeradas para elementos secuenciales.

```html
<ol>
  <li>Primer paso</li>
  <li>Segundo paso</li>
  <li>Tercer paso</li>
</ol>
<!-- Numeración personalizada -->
<ol start="5">
  <li>Elemento 5</li>
  <li>Elemento 6</li>
</ol>
<!-- Tipos de numeración diferentes -->
<ol type="A">
  <li>Elemento A</li>
  <li>Elemento B</li>
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
  <dd>Lenguaje de programación para la web</dd>
</dl>
```

### Enlaces y Navegación: `<a>`

Crea hipervínculos y estructuras de navegación.

```html
<!-- Enlace básico -->
<a href="https://example.com">Visitar Ejemplo</a>
<!-- Enlace en nueva pestaña -->
<a href="https://example.com" target="_blank">Nueva Pestaña</a>
<!-- Enlace de correo electrónico -->
<a href="mailto:email@example.com">Enviar Correo</a>
<!-- Enlace telefónico -->
<a href="tel:+1234567890">Llámanos</a>
<!-- Anclas de página internas -->
<a href="#section1">Ir a Sección 1</a>
<h2 id="section1">Sección 1</h2>
```

## Formularios y Elementos de Entrada

### Estructura Básica del Formulario: `<form>`

La base para la recopilación de entradas del usuario.

```html
<form action="/submit" method="POST">
  <label for="username">Nombre de usuario:</label>
  <input type="text" id="username" name="username" required />

  <label for="email">Correo electrónico:</label>
  <input type="email" id="email" name="email" required />

  <input type="submit" value="Enviar" />
</form>
```

### Tipos de Entrada: `<input>`

Varios tipos de entrada para diferentes necesidades de recopilación de datos.

```html
<!-- Entradas de texto -->
<input type="text" placeholder="Ingresar texto" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="Contraseña" />
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
<label for="agree">Acepto los términos</label>
<!-- Botones de radio -->
<input type="radio" id="option1" name="choice" value="1" />
<label for="option1">Opción 1</label>
<input type="radio" id="option2" name="choice" value="2" />
<label for="option2">Opción 2</label>
<!-- Menú desplegable (Select) -->
<select name="country">
  <option value="us">Estados Unidos</option>
  <option value="uk">Reino Unido</option>
  <option value="ca">Canadá</option>
</select>
<!-- Textarea -->
<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="Escriba su mensaje"
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

## Elementos Multimedia

### Imágenes: `<img>`, `<picture>`

Muestra imágenes con varios atributos y opciones.

```html
<!-- Imagen básica -->
<img src="image.jpg" alt="Descripción" />
<!-- Imagen responsiva -->
<img src="image.jpg" alt="Description" width="100%" height="auto" />
<!-- Imagen con tamaño -->
<img src="image.jpg" alt="Description" width="300" height="200" />
<!-- Elemento picture para imágenes responsivas -->
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
  Tu navegador no soporta audio.
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
  Tu navegador no soporta video.
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
      <th>Nombre</th>
      <th>Edad</th>
      <th>Ciudad</th>
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

Funcionalidad mejorada de tablas con expansión y agrupación.

```html
<table>
  <caption>
    Informe de Ventas
  </caption>
  <colgroup>
    <col style="width: 50%" />
    <col style="width: 25%" />
    <col style="width: 25%" />
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">Producto</th>
      <th colspan="2">Ventas</th>
    </tr>
    <tr>
      <th>T1</th>
      <th>T2</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Producto A</td>
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
      <li><a href="#home">Inicio</a></li>
      <li><a href="#about">Acerca de</a></li>
    </ul>
  </nav>
</header>
<!-- Contenido principal -->
<main>
  <article>
    <h1>Título del Artículo</h1>
    <p>Contenido del artículo...</p>
  </article>
</main>
<!-- Barra lateral -->
<aside>
  <h2>Enlaces Relacionados</h2>
  <ul>
    <li><a href="#">Enlace 1</a></li>
  </ul>
</aside>
<!-- Pie de página de la página -->
<footer>
  <p>© 2024 Nombre de la Compañía</p>
</footer>
```

### Elementos de Agrupación de Contenido: `<section>`, `<article>`, `<div>`, `<figure>`

Organizan y agrupan secciones de contenido relacionado.

```html
<!-- Sección genérica -->
<section>
  <h2>Título de Sección</h2>
  <p>Contenido de la sección...</p>
</section>
<!-- Artículo independiente -->
<article>
  <header>
    <h1>Título del Artículo</h1>
    <time datetime="2024-01-01">1 de Enero, 2024</time>
  </header>
  <p>Contenido del artículo...</p>
</article>
<!-- Contenedor genérico -->
<div class="container">
  <p>Agrupación de contenido genérico</p>
</div>
<!-- Figura con pie de foto -->
<figure>
  <img src="chart.jpg" alt="Gráfico de Ventas" />
  <figcaption>Datos de ventas para el T1 2024</figcaption>
</figure>
```

## Atributos HTML

### Atributos Globales: `id`, `class`, `title`, `data-*`

Atributos que se pueden usar en cualquier elemento HTML.

```html
<!-- ID para identificación única -->
<div id="unique-element">Contenido</div>
<!-- Clase para estilo y selección -->
<p class="highlight important">Texto</p>
<!-- Título para tooltips -->
<span title="Este es un tooltip">Pasa el ratón sobre mí</span>
<!-- Atributos de datos -->
<div data-user-id="123" data-role="admin">Usuario</div>
<!-- Idioma -->
<p lang="es">Hola mundo</p>
<!-- Dirección del contenido -->
<p dir="rtl">Texto de derecha a izquierda</p>
<!-- Elementos ocultos -->
<div hidden>Esto no se mostrará</div>
```

### Atributos de Accesibilidad: `alt`, `aria-*`, `tabindex`, `role`

Atributos que mejoran la accesibilidad y la experiencia del usuario.

```html
<!-- Texto alternativo para imágenes -->
<img src="photo.jpg" alt="Un atardecer sobre montañas" />
<!-- Etiquetas ARIA -->
<button aria-label="Cerrar diálogo">×</button>
<div aria-hidden="true">Contenido decorativo</div>
<!-- Accesibilidad del formulario -->
<label for="email">Dirección de Correo Electrónico:</label>
<input type="email" id="email" aria-describedby="email-help" />
<small id="email-help">Nunca compartiremos tu correo</small>
<!-- Índice de tabulación -->
<div tabindex="0">Div enfocable</div>
<div tabindex="-1">Div enfocable programáticamente</div>
<!-- Atributo de rol -->
<div role="button" tabindex="0">Botón personalizado</div>
```

## Características Modernas de HTML5

### Nuevas Características de Entrada: `color`, `search`, `file`, `datalist`

HTML5 introdujo nuevos tipos de entrada y atributos.

```html
<!-- Nuevos tipos de entrada -->
<input type="color" value="#ff0000" />
<input type="search" placeholder="Buscar..." />
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

Capacidades gráficas y de dibujo en HTML5.

```html
<!-- Canvas para gráficos dinámicos -->
<canvas id="myCanvas" width="400" height="200">
  Tu navegador no soporta canvas.
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
  <summary>Haz clic para expandir</summary>
  <p>
    Este contenido está oculto por defecto y se revela al hacer clic en el
    resumen.
  </p>
  <ul>
    <li>Elemento 1</li>
    <li>Elemento 2</li>
  </ul>
</details>
<details open>
  <summary>Esto comienza expandido</summary>
  <p>Contenido visible por defecto.</p>
</details>
```

### Elemento Dialog: `<dialog>`

Funcionalidad nativa de diálogo y modal en HTML.

```html
<!-- Elemento de diálogo -->
<dialog id="myDialog">
  <h2>Título del Diálogo</h2>
  <p>El contenido del diálogo va aquí.</p>
  <button onclick="closeDialog()">Cerrar</button>
</dialog>
<button onclick="openDialog()">Abrir Diálogo</button>
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
  <p>Contenido anidado correctamente</p>
</div>
<!-- Usa minúsculas para elementos y atributos -->
<img src="image.jpg" alt="description" />
<!-- Cierra todas las etiquetas -->
<p>Siempre cierra tus etiquetas</p>
<!-- Usa texto alt significativo -->
<img src="chart.png" alt="Las ventas aumentaron un 25% en el T4" />
```

### Validación y Depuración de HTML

Asegúrate de que tu HTML sea válido y accesible.

```html
<!-- Usa el Validador HTML de W3C -->
<!-- https://validator.w3.org/ -->
<!-- Errores comunes de validación -->
<!-- Faltan atributos alt -->
<img src="image.jpg" alt="" />
<!-- Proporcionar texto alt -->
<!-- Etiquetas sin cerrar -->
<p>Contenido de texto</p>
<!-- Siempre cierra las etiquetas -->
<!-- Anidación inválida -->
<p>
  Contenido de párrafo válido
  <!-- No coloques elementos de bloque dentro de párrafos -->
</p>
<!-- Usa herramientas de desarrollador -->
<!-- Clic derecho → Inspeccionar elemento -->
<!-- Revisa la consola en busca de errores -->
<!-- Valida la accesibilidad con WAVE o axe -->
```

## Plantillas y Frameworks HTML

### Motores de Plantillas: Handlebars, Mustache

Generación dinámica de HTML con lenguajes de plantillas.

```html
<!-- Plantilla Handlebars -->
<div>
  <h1>{{title}}</h1>
  {{#each items}}
  <p>{{this}}</p>
  {{/each}}
</div>
<!-- Plantilla Mustache -->
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
<my-component>Hola Mundo</my-component>
<script>
  class MyComponent extends HTMLElement {
    // Lógica del componente
  }
  customElements.define('my-component', MyComponent)
</script>
```

### Integración de Frameworks: React JSX, Plantillas Vue

HTML dentro de frameworks JavaScript modernos.

```html
<!-- React JSX -->
function Component() { return (
<div className="container">
  <h1>{title}</h1>
  <p>Contenido aquí</p>
</div>
); }
<!-- Plantilla Vue -->
<template>
  <div class="container">
    <h1>{{ title }}</h1>
    <p v-if="showContent">Contenido aquí</p>
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

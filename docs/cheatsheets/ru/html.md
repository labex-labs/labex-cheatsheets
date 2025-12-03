---
title: 'Шпаргалка по HTML | LabEx'
description: 'Изучите HTML5 с помощью этой исчерпывающей шпаргалки. Быстрый справочник по тегам HTML, семантическим элементам, формам, доступности и современным стандартам веб-разработки для фронтенд-разработчиков.'
pdfUrl: '/cheatsheets/pdf/html-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по HTML
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/html">Изучайте HTML с практическими лабораторными работами</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите структуру веб-страниц HTML с помощью практических лабораторных работ и сценариев из реального мира. LabEx предлагает комплексные курсы по HTML, охватывающие основные элементы, семантическую разметку, формы, интеграцию мультимедиа и современные функции HTML5. Освойте эффективную структуру веб-страниц и организацию контента для современных рабочих процессов веб-разработки.
</base-disclaimer-content>
</base-disclaimer>

## Структура документа HTML

### Базовый документ HTML: `<!DOCTYPE html>`

Каждый документ HTML начинается с объявления типа документа и следует стандартной структуре.

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Page Title</title>
  </head>
  <body>
    <!-- Page content goes here -->
  </body>
</html>
```

<BaseQuiz id="html-doctype-1" correct="A">
  <template #question>
    What is the purpose of <code><!DOCTYPE html></code>?
  </template>
  
  <BaseQuizOption value="A" correct>It declares the document type and HTML version</BaseQuizOption>
  <BaseQuizOption value="B">It creates a new HTML element</BaseQuizOption>
  <BaseQuizOption value="C">It links to an external stylesheet</BaseQuizOption>
  <BaseQuizOption value="D">It sets the page title</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code><!DOCTYPE html></code> declaration tells the browser which version of HTML the document is using. For HTML5, this simple declaration is sufficient and should be the first line of every HTML document.
  </BaseQuizAnswer>
</BaseQuiz>

### Элементы Head: `<head>`

Секция head содержит метаданные о документе.

```html
<!-- Character encoding -->
<meta charset="UTF-8" />
<!-- Viewport for responsive design -->
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<!-- Page description -->
<meta name="description" content="Page description" />
<!-- Link to CSS -->
<link rel="stylesheet" href="styles.css" />
<!-- Link to favicon -->
<link rel="icon" href="favicon.ico" />
```

### Комментарии HTML: `<!-- -->`

Комментарии не отображаются, но помогают документировать ваш код.

```html
<!-- This is a comment -->
<!-- 
  Multi-line comment
  for longer explanations
-->
```

### Анатомия элемента HTML

Элементы HTML состоят из открывающих тегов, содержимого и закрывающих тегов.

```html
<!-- Element with content -->
<p>This is a paragraph</p>
<!-- Self-closing elements -->
<img src="image.jpg" alt="Description" />
<br />
<hr />
<!-- Elements with attributes -->
<a href="https://example.com" target="_blank">Link</a>
<!-- Nested elements -->
<div>
  <p>Nested paragraph</p>
</div>
```

## Элементы текстового контента

### Заголовки: `h1` до `h6`

Определяют иерархию и важность разделов контента.

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
    What is the correct heading hierarchy?
  </template>
  
  <BaseQuizOption value="A">h1 should be used multiple times on a page</BaseQuizOption>
  <BaseQuizOption value="B" correct>h1 should be used once as the main title, followed by h2, h3, etc.</BaseQuizOption>
  <BaseQuizOption value="C">All headings have the same importance</BaseQuizOption>
  <BaseQuizOption value="D">h6 is the most important heading</BaseQuizOption>
  
  <BaseQuizAnswer>
    HTML headings should follow a logical hierarchy: use one <code>h1</code> for the main page title, then <code>h2</code> for major sections, <code>h3</code> for subsections, and so on. This helps with accessibility and SEO.
  </BaseQuizAnswer>
</BaseQuiz>

### Абзацы: `p`

Наиболее распространенный элемент для блоков текстового контента.

```html
<p>
  This is a paragraph of text. It can contain multiple sentences and will wrap
  automatically.
</p>
<p>This is another paragraph. Paragraphs are separated by margin space.</p>
```

### Форматирование текста: `<strong>`, `<em>`, `<b>`, `<i>`

Элементы для выделения и стилизации текста в строке.

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

### Разрывы строк и пробелы: `<br>`, `<hr>`, `<pre>`

Управление потоком текста и интервалами внутри контента.

```html
<!-- Line break -->
Line 1<br />
Line 2
<!-- Horizontal rule -->
<hr />
<!-- Preformatted text -->
<pre>
  Text with
    preserved    spacing
      and line breaks
</pre>
<!-- Code formatting -->
<code>console.log('Hello');</code>
```

## Списки и навигация

### Ненумерованные списки: `<ul>`

Создание списков с маркерами для не последовательных элементов.

```html
<ul>
  <li>First item</li>
  <li>Second item</li>
  <li>Third item</li>
</ul>
<!-- Nested lists -->
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

### Нумерованные списки: `<ol>`

Создание пронумерованных списков для последовательных элементов.

```html
<ol>
  <li>First step</li>
  <li>Second step</li>
  <li>Third step</li>
</ol>
<!-- Custom numbering -->
<ol start="5">
  <li>Item 5</li>
  <li>Item 6</li>
</ol>
<!-- Different numbering types -->
<ol type="A">
  <li>Item A</li>
  <li>Item B</li>
</ol>
```

### Списки определений: `<dl>`

Создание списков терминов и их описаний.

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

### Ссылки и навигация: `<a>`

Создание гиперссылок и навигационных структур.

```html
<!-- Basic link -->
<a href="https://example.com">Visit Example</a>
<!-- Link in new tab -->
<a href="https://example.com" target="_blank">New Tab</a>
<!-- Email link -->
<a href="mailto:email@example.com">Send Email</a>
<!-- Phone link -->
<a href="tel:+1234567890">Call Us</a>
<!-- Internal page anchors -->
<a href="#section1">Go to Section 1</a>
<h2 id="section1">Section 1</h2>
```

<BaseQuiz id="html-links-1" correct="B">
  <template #question>
    What does <code>target="_blank"</code> do in an anchor tag?
  </template>
  
  <BaseQuizOption value="A">Opens the link in the same window</BaseQuizOption>
  <BaseQuizOption value="B" correct>Opens the link in a new tab or window</BaseQuizOption>
  <BaseQuizOption value="C">Closes the current window</BaseQuizOption>
  <BaseQuizOption value="D">Downloads the link</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code>target="_blank"</code> attribute opens the linked page in a new browser tab or window, allowing users to keep the original page open.
  </BaseQuizAnswer>
</BaseQuiz>

## Формы и элементы ввода

### Базовая структура формы: `<form>`

Основа для сбора пользовательского ввода.

```html
<form action="/submit" method="POST">
  <label for="username">Username:</label>
  <input type="text" id="username" name="username" required />

  <label for="email">Email:</label>
  <input type="email" id="email" name="email" required />

  <input type="submit" value="Submit" />
</form>
```

### Типы ввода: `<input>`

Различные типы ввода для различных потребностей сбора данных.

```html
<!-- Text inputs -->
<input type="text" placeholder="Enter text" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="Password" />
<input type="url" placeholder="https://example.com" />
<input type="tel" placeholder="+1234567890" />
<!-- Number inputs -->
<input type="number" min="1" max="100" step="1" />
<input type="range" min="0" max="100" value="50" />
<!-- Date and time -->
<input type="date" />
<input type="time" />
<input type="datetime-local" />
```

### Элементы управления формой: `<checkbox>`, `<radio>`, `<select>`, `<textarea>`

Дополнительные элементы формы для взаимодействия с пользователем.

```html
<!-- Checkboxes -->
<input type="checkbox" id="agree" name="agree" />
<label for="agree">I agree to terms</label>
<!-- Radio buttons -->
<input type="radio" id="option1" name="choice" value="1" />
<label for="option1">Option 1</label>
<input type="radio" id="option2" name="choice" value="2" />
<label for="option2">Option 2</label>
<!-- Select dropdown -->
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

### Проверка формы: `required`, `min`, `max`, `pattern`

Встроенные атрибуты проверки форм HTML.

```html
<input type="text" required />
<input type="email" required />
<input type="text" minlength="3" maxlength="20" />
<input type="number" min="1" max="100" />
<input type="text" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}" />
```

<BaseQuiz id="html-validation-1" correct="A">
  <template #question>
    What does the <code>required</code> attribute do in an HTML input?
  </template>
  
  <BaseQuizOption value="A" correct>Prevents form submission if the field is empty</BaseQuizOption>
  <BaseQuizOption value="B">Makes the field read-only</BaseQuizOption>
  <BaseQuizOption value="C">Hides the field</BaseQuizOption>
  <BaseQuizOption value="D">Sets a default value</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code>required</code> attribute makes an input field mandatory. If the field is empty when the form is submitted, the browser will prevent submission and show a validation message.
  </BaseQuizAnswer>
</BaseQuiz>

## Мультимедиа

### Изображения: `<img>`, `<picture>`

Отображение изображений с различными атрибутами и опциями.

```html
<!-- Basic image -->
<img src="image.jpg" alt="Description" />
<!-- Responsive image -->
<img src="image.jpg" alt="Description" width="100%" height="auto" />
<!-- Image with size -->
<img src="image.jpg" alt="Description" width="300" height="200" />
<!-- Picture element for responsive images -->
<picture>
  <source media="(min-width: 800px)" srcset="large.jpg" />
  <source media="(min-width: 400px)" srcset="medium.jpg" />
  <img src="small.jpg" alt="Description" />
</picture>
```

### Аудио: `<audio>`

Встраивание аудиоконтента с элементами управления воспроизведением.

```html
<!-- Basic audio -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
  <source src="audio.ogg" type="audio/ogg" />
  Your browser does not support audio.
</audio>
<!-- Audio with autoplay -->
<audio controls autoplay loop>
  <source src="background.mp3" type="audio/mpeg" />
</audio>
```

### Видео: `<video>`

Встраивание видеоконтента с исчерпывающими опциями.

```html
<!-- Basic video -->
<video controls width="400" height="300">
  <source src="video.mp4" type="video/mp4" />
  <source src="video.webm" type="video/webm" />
  Your browser does not support video.
</video>
<!-- Video with poster and attributes -->
<video controls poster="thumbnail.jpg" width="100%" height="auto">
  <source src="video.mp4" type="video/mp4" />
  <track src="captions.vtt" kind="captions" srclang="en" label="English" />
</video>
```

### Встраиваемый контент: `<iframe>`

Встраивание внешнего контента и приложений.

```html
<!-- iFrame for external content -->
<iframe src="https://example.com" width="100%" height="400"></iframe>
<!-- YouTube video embed -->
<iframe
  width="560"
  height="315"
  src="https://www.youtube.com/embed/VIDEO_ID"
></iframe>
<!-- Google Maps embed -->
<iframe src="https://maps.google.com/..."></iframe>
```

## Таблицы

### Базовая структура таблицы: `<table>`

Создание структурированных отображений данных с помощью таблиц.

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

### Расширенные функции таблицы: `rowspan`, `colspan`, `<caption>`

Улучшенная функциональность таблицы с объединением и группировкой.

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

## Семантические элементы HTML5

### Элементы структуры страницы: `<header>`, `<nav>`, `<main>`, `<footer>`

Определяют основные разделы макета вашей страницы.

```html
<!-- Page header -->
<header>
  <nav>
    <ul>
      <li><a href="#home">Home</a></li>
      <li><a href="#about">About</a></li>
    </ul>
  </nav>
</header>
<!-- Main content -->
<main>
  <article>
    <h1>Article Title</h1>
    <p>Article content...</p>
  </article>
</main>
<!-- Sidebar -->
<aside>
  <h2>Related Links</h2>
  <ul>
    <li><a href="#">Link 1</a></li>
  </ul>
</aside>
<!-- Page footer -->
<footer>
  <p>© 2024 Company Name</p>
</footer>
```

### Элементы группировки контента: `<section>`, `<article>`, `<div>`, `<figure>`

Организация и группировка связанных разделов контента.

```html
<!-- Generic section -->
<section>
  <h2>Section Title</h2>
  <p>Section content...</p>
</section>
<!-- Standalone article -->
<article>
  <header>
    <h1>Article Title</h1>
    <time datetime="2024-01-01">January 1, 2024</time>
  </header>
  <p>Article content...</p>
</article>
<!-- Generic container -->
<div class="container">
  <p>Generic content grouping</p>
</div>
<!-- Figure with caption -->
<figure>
  <img src="chart.jpg" alt="Sales Chart" />
  <figcaption>Sales data for Q1 2024</figcaption>
</figure>
```

## Атрибуты HTML

### Глобальные атрибуты: `id`, `class`, `title`, `data-*`

Атрибуты, которые могут использоваться на любом элементе HTML.

```html
<!-- ID for unique identification -->
<div id="unique-element">Content</div>
<!-- Class for styling and selection -->
<p class="highlight important">Text</p>
<!-- Title for tooltips -->
<span title="This is a tooltip">Hover me</span>
<!-- Data attributes -->
<div data-user-id="123" data-role="admin">User</div>
<!-- Language -->
<p lang="es">Hola mundo</p>
<!-- Content direction -->
<p dir="rtl">Right to left text</p>
<!-- Hidden elements -->
<div hidden>This won't be displayed</div>
```

### Атрибуты доступности: `alt`, `aria-*`, `tabindex`, `role`

Атрибуты, которые улучшают доступность и пользовательский опыт.

```html
<!-- Alternative text for images -->
<img src="photo.jpg" alt="A sunset over mountains" />
<!-- ARIA labels -->
<button aria-label="Close dialog">×</button>
<div aria-hidden="true">Decorative content</div>
<!-- Form accessibility -->
<label for="email">Email Address:</label>
<input type="email" id="email" aria-describedby="email-help" />
<small id="email-help">We'll never share your email</small>
<!-- Tab index -->
<div tabindex="0">Focusable div</div>
<div tabindex="-1">Programmatically focusable</div>
<!-- Role attribute -->
<div role="button" tabindex="0">Custom button</div>
```

## Современные функции HTML5

### Новые функции ввода: `color`, `search`, `file`, `datalist`

HTML5 представил новые типы ввода и атрибуты.

```html
<!-- New input types -->
<input type="color" value="#ff0000" />
<input type="search" placeholder="Search..." />
<input type="file" accept="image/*" multiple />
<!-- Datalist for autocomplete -->
<input list="browsers" name="browser" />
<datalist id="browsers">
  <option value="Chrome"></option>
  <option value="Firefox"></option>
  <option value="Safari"></option>
</datalist>
<!-- Progress and meter -->
<progress value="70" max="100">70%</progress>
<meter value="0.6">60%</meter>
```

### Canvas и SVG: `<canvas>`, `<svg>`

Возможности графики и рисования в HTML5.

```html
<!-- Canvas for dynamic graphics -->
<canvas id="myCanvas" width="400" height="200">
  Your browser does not support canvas.
</canvas>
<!-- Inline SVG -->
<svg width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue" stroke="black" stroke-width="2" />
</svg>
```

### Детали и резюме: `<details>`, `<summary>`

Создание сворачиваемых разделов контента без JavaScript.

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

### Элемент Диалог: `<dialog>`

Нативная функциональность диалоговых окон и модальных окон.

```html
<!-- Dialog element -->
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

## Лучшие практики и проверка

### Лучшие практики HTML

Пишите чистый, поддерживаемый и доступный HTML.

```html
<!-- Always declare doctype -->
<!DOCTYPE html>
<!-- Use semantic elements -->
<header>...</header>
<main>...</main>
<footer>...</footer>
<!-- Proper nesting -->
<div>
  <p>Properly nested content</p>
</div>
<!-- Use lowercase for elements and attributes -->
<img src="image.jpg" alt="description" />
<!-- Close all tags -->
<p>Always close your tags</p>
<!-- Use meaningful alt text -->
<img src="chart.png" alt="Sales increased 25% in Q4" />
```

### Проверка и отладка HTML

Убедитесь, что ваш HTML является допустимым и доступным.

```html
<!-- Use W3C HTML Validator -->
<!-- https://validator.w3.org/ -->
<!-- Common validation errors -->
<!-- Missing alt attributes -->
<img src="image.jpg" alt="" />
<!-- Provide alt text -->
<!-- Unclosed tags -->
<p>Text content</p>
<!-- Always close tags -->
<!-- Invalid nesting -->
<p>
  Valid paragraph content
  <!-- Don't put block elements inside paragraphs -->
</p>
<!-- Use developer tools -->
<!-- Right-click → Inspect Element -->
<!-- Check console for errors -->
<!-- Validate accessibility with WAVE or axe -->
```

## Шаблоны и фреймворки HTML

### Шаблонные движки: Handlebars, Mustache

Динамическая генерация HTML с помощью языков шаблонов.

```html
<!-- Handlebars template -->
<div>
  <h1>{{title}}</h1>
  {{#each items}}
  <p>{{this}}</p>
  {{/each}}
</div>
<!-- Mustache template -->
<div>
  <h1>{{title}}</h1>
  {{#items}}
  <p>{{.}}</p>
  {{/items}}
</div>
```

### Веб-компоненты: `<template>`, Пользовательские элементы

Повторно используемые пользовательские элементы HTML.

```html
<!-- Custom element definition -->
<template id="my-component">
  <style>
    p {
      color: blue;
    }
  </style>
  <p><slot></slot></p>
</template>
<!-- Usage -->
<my-component>Hello World</my-component>
<script>
  class MyComponent extends HTMLElement {
    // Component logic
  }
  customElements.define('my-component', MyComponent)
</script>
```

### Интеграция с фреймворками: React JSX, Vue Templates

HTML внутри современных JavaScript-фреймворков.

```html
<!-- React JSX -->
function Component() { return (
<div className="container">
  <h1>{title}</h1>
  <p>Content here</p>
</div>
); }
<!-- Vue template -->
<template>
  <div class="container">
    <h1>{{ title }}</h1>
    <p v-if="showContent">Content here</p>
  </div>
</template>
```

## Соответствующие ссылки

- <router-link to="/css">Шпаргалка по CSS</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/web-development">Шпаргалка по веб-разработке</router-link>
- <router-link to="/react">Шпаргалка по React</router-link>
- <router-link to="/git">Шпаргалка по Git</router-link>
- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>

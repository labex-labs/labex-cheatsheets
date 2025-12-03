---
title: 'Шпаргалка по веб-разработке | LabEx'
description: 'Изучите веб-разработку с помощью этой комплексной шпаргалки. Краткий справочник по HTML, CSS, JavaScript, API, адаптивному дизайну, оптимизации производительности и основам full-stack разработки.'
pdfUrl: '/cheatsheets/pdf/web-development-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по веб-разработке
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/web-development">Изучайте веб-разработку с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучайте веб-разработку с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по веб-разработке, охватывающие основные сведения о HTML, CSS, JavaScript, манипулировании DOM и адаптивном дизайне. Освойте создание интерактивных и адаптивных веб-сайтов для современных рабочих процессов веб-разработки.
</base-disclaimer-content>
</base-disclaimer>

## Основы HTML и структура документа

### Базовая структура HTML: `<!DOCTYPE html>`

Создайте основу каждой веб-страницы.

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>My Web Page</title>
    <link rel="stylesheet" href="style.css" />
  </head>
  <body>
    <h1>Hello World!</h1>
    <script src="script.js"></script>
  </body>
</html>
```

### Семантические элементы: `<header>` / `<main>` / `<footer>`

Используйте значимые семантические элементы HTML5 для лучшей структуры.

```html
<header>
  <nav>
    <ul>
      <li><a href="#home">Home</a></li>
      <li><a href="#about">About</a></li>
    </ul>
  </nav>
</header>
<main>
  <section>
    <h1>Welcome</h1>
    <p>Main content here</p>
  </section>
</main>
<footer>
  <p>© 2024 My Website</p>
</footer>
```

<BaseQuiz id="webdev-semantic-1" correct="B">
  <template #question>
    Каково основное преимущество использования семантических элементов HTML, таких как `header`, `main` и `footer`?
  </template>
  
  <BaseQuizOption value="A">Они заставляют страницу загружаться быстрее</BaseQuizOption>
  <BaseQuizOption value="B" correct>Они улучшают доступность (accessibility) и SEO, предоставляя смысл структуре</BaseQuizOption>
  <BaseQuizOption value="C">Они автоматически стилизуют страницу</BaseQuizOption>
  <BaseQuizOption value="D">Они необходимы для работы JavaScript</BaseQuizOption>
  
  <BaseQuizAnswer>
    Семантические элементы HTML придают смысл структуре документа, что облегчает понимание организации контента для программ чтения с экрана, поисковых систем и разработчиков. Это улучшает доступность и SEO.
  </BaseQuizAnswer>
</BaseQuiz>

### Текстовые элементы: `<h1>` до `<h6>` / `<p>`

Структурируйте контент с правильной иерархией заголовков и абзацами.

```html
<h1>Main Title</h1>
<h2>Section Heading</h2>
<h3>Subsection</h3>
<p>
  This is a paragraph with <strong>bold text</strong> and <em>italic text</em>.
</p>
<p>Another paragraph with a <a href="https://example.com">link</a>.</p>
```

### Списки: `<ul>` / `<ol>` / `<li>`

Создавайте организованные списки информации.

```html
<!-- Unordered list -->
<ul>
  <li>First item</li>
  <li>Second item</li>
  <li>Third item</li>
</ul>

<!-- Ordered list -->
<ol>
  <li>Step 1</li>
  <li>Step 2</li>
  <li>Step 3</li>
</ol>
```

### Изображения и медиа: `<img>` / `<video>` / `<audio>`

Встраивайте мультимедийный контент с правильными атрибутами.

```html
<!-- Image with alt text -->
<img src="image.jpg" alt="Description of image" width="300" />

<!-- Video element -->
<video controls width="400">
  <source src="video.mp4" type="video/mp4" />
  Your browser doesn't support video.
</video>

<!-- Audio element -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
</audio>
```

### Таблицы: `<table>` / `<tr>` / `<td>`

Отображайте табличные данные с правильной структурой.

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
  </tbody>
</table>
```

## Формы и ввод данных пользователем

### Структура формы: `<form>`

Создайте контейнер для пользовательских вводов и элементов управления.

```html
<form action="/submit" method="POST">
  <label for="name">Name:</label>
  <input type="text" id="name" name="name" required />

  <label for="email">Email:</label>
  <input type="email" id="email" name="email" required />

  <button type="submit">Submit</button>
</form>
```

### Типы ввода: `type="text"` / `type="email"`

Используйте соответствующие типы ввода для различных данных.

```html
<input type="text" placeholder="Enter your name" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="Password" />
<input type="number" min="1" max="100" />
<input type="date" />
<input type="checkbox" id="agree" />
<input type="radio" name="gender" value="male" />
<input type="file" accept=".jpg,.png" />
```

### Элементы управления формой: `<select>` / `<textarea>`

Предоставьте пользователям различные способы ввода информации.

```html
<select name="country" id="country">
  <option value="">Select a country</option>
  <option value="us">United States</option>
  <option value="ca">Canada</option>
</select>

<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="Enter your message"
></textarea>
```

## Основы CSS и стилизация

### Селекторы CSS: `element` / `.class` / `#id`

Выбирайте элементы HTML для стилизации с помощью различных типов селекторов.

```css
/* Element selector */
h1 {
  color: blue;
  font-size: 2rem;
}

/* Class selector */
.highlight {
  background-color: yellow;
  padding: 10px;
}

/* ID selector */
#header {
  background-color: navy;
  color: white;
}

/* Descendant selector */
.container p {
  line-height: 1.6;
}
```

### Блочная модель: `margin` / `padding` / `border`

Управляйте отступами и макетом с помощью блочной модели CSS.

```css
.box {
  width: 300px;
  height: 200px;
  margin: 20px; /* Outside spacing */
  padding: 15px; /* Inside spacing */
  border: 2px solid black; /* Border properties */
}

/* Shorthand properties */
.element {
  margin: 10px 20px; /* top/bottom left/right */
  padding: 10px 15px 20px 25px; /* top right bottom left */
  border-radius: 5px; /* Rounded corners */
}
```

<BaseQuiz id="webdev-boxmodel-1" correct="B">
  <template #question>
    В чем разница между `margin` и `padding` в CSS?
  </template>
  
  <BaseQuizOption value="A">Разницы нет</BaseQuizOption>
  <BaseQuizOption value="B" correct>Margin — это пространство снаружи элемента, padding — это пространство внутри элемента</BaseQuizOption>
  <BaseQuizOption value="C">Margin используется для горизонтального расстояния, padding — для вертикального</BaseQuizOption>
  <BaseQuizOption value="D">Margin используется для границ, padding — для контента</BaseQuizOption>
  
  <BaseQuizAnswer>
    Margin создает пространство за пределами границы элемента (между элементами), в то время как padding создает пространство внутри элемента между контентом и границей. Оба влияют на расстояние, но в разных областях.
  </BaseQuizAnswer>
</BaseQuiz>

### Flexbox: `display: flex`

Легко создавайте гибкие и адаптивные макеты.

```css
.container {
  display: flex;
  justify-content: center; /* Horizontal alignment */
  align-items: center; /* Vertical alignment */
  gap: 20px; /* Space between items */
}

.flex-item {
  flex: 1; /* Equal width items */
}

/* Flexbox direction */
.column-layout {
  display: flex;
  flex-direction: column;
}
```

<BaseQuiz id="webdev-flexbox-1" correct="A">
  <template #question>
    Что делает `justify-content: center` во Flexbox?
  </template>
  
  <BaseQuizOption value="A" correct>Центрирует flex-элементы вдоль главной оси (по умолчанию по горизонтали)</BaseQuizOption>
  <BaseQuizOption value="B">Центрирует элементы по вертикали</BaseQuizOption>
  <BaseQuizOption value="C">Равномерно распределяет элементы</BaseQuizOption>
  <BaseQuizOption value="D">Растягивает элементы, чтобы заполнить пространство</BaseQuizOption>
  
  <BaseQuizAnswer>
    `justify-content` управляет выравниванием вдоль главной оси (по умолчанию горизонтальной). `center` центрирует все flex-элементы в контейнере. Используйте `align-items` для управления выравниванием по поперечной оси (вертикальной).
  </BaseQuizAnswer>
</BaseQuiz>

### Сетка (Grid Layout): `display: grid`

Создавайте сложные двумерные макеты.

```css
.grid-container {
  display: grid;
  grid-template-columns: repeat(3, 1fr); /* 3 equal columns */
  grid-gap: 20px;
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}

.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}
```

## Основы JavaScript и фундаментальные принципы программирования

### Переменные: `let` / `const` / `var`

Храните и манипулируйте данными с помощью различных объявлений переменных.

```javascript
// Modern variable declarations
let name = 'John' // Can be reassigned
const age = 25 // Cannot be reassigned
const colors = ['red', 'blue'] // Array (contents can change)

// Variable types
let message = 'Hello World' // String
let count = 42 // Number
let isActive = true // Boolean
let data = null // Null
let user = {
  // Object
  name: 'Alice',
  email: 'alice@example.com',
}
```

### Функции: `function` / Стрелочные функции

Создавайте многократно используемые блоки кода с различным синтаксисом функций.

```javascript
// Function declaration
function greet(name) {
  return `Hello, ${name}!`
}

// Arrow function
const add = (a, b) => a + b

// Arrow function with block
const calculateArea = (width, height) => {
  const area = width * height
  return area
}

// Function with default parameters
function createUser(name, age = 18) {
  return { name, age }
}
```

### Условная логика: `if` / `else` / `switch`

Управляйте потоком программы с помощью условных операторов.

```javascript
// If/else statement
if (age >= 18) {
  console.log('Adult')
} else if (age >= 13) {
  console.log('Teenager')
} else {
  console.log('Child')
}

// Ternary operator
const status = age >= 18 ? 'adult' : 'minor'

// Switch statement
switch (day) {
  case 'Monday':
    console.log('Start of work week')
    break
  case 'Friday':
    console.log('TGIF!')
    break
  default:
    console.log('Regular day')
}
```

### Циклы: `for` / `while` / Методы массивов

Итерируйте по данным и повторяйте операции.

```javascript
// For loop
for (let i = 0; i < 5; i++) {
  console.log(i)
}

// For...of loop
for (const item of items) {
  console.log(item)
}

// Array methods
const numbers = [1, 2, 3, 4, 5]
numbers.forEach((num) => console.log(num))
const doubled = numbers.map((num) => num * 2)
const evens = numbers.filter((num) => num % 2 === 0)
const sum = numbers.reduce((total, num) => total + num, 0)
```

## Манипуляции с DOM и события

### Выбор элементов: `querySelector` / `getElementById`

Находите и получайте доступ к элементам HTML в JavaScript.

```javascript
// Select single elements
const title = document.getElementById('title')
const button = document.querySelector('.btn')
const firstParagraph = document.querySelector('p')

// Select multiple elements
const allButtons = document.querySelectorAll('.btn')
const allParagraphs = document.getElementsByTagName('p')

// Check if element exists
if (button) {
  button.style.color = 'blue'
}
```

### Изменение контента: `innerHTML` / `textContent`

Изменяйте содержимое и атрибуты HTML-элементов.

```javascript
// Change text content
title.textContent = 'New Title'
title.innerHTML = '<strong>Bold Title</strong>'

// Modify attributes
button.setAttribute('disabled', 'true')
const src = image.getAttribute('src')

// Add/remove classes
button.classList.add('active')
button.classList.remove('hidden')
button.classList.toggle('highlighted')
```

### Обработка событий: `addEventListener`

Реагируйте на взаимодействие пользователя и события браузера.

```javascript
// Click event
button.addEventListener('click', function () {
  alert('Button clicked!')
})

// Form submit event
form.addEventListener('submit', function (e) {
  e.preventDefault() // Prevent form submission
  const formData = new FormData(form)
  console.log(formData.get('username'))
})

// Keyboard events
document.addEventListener('keydown', function (e) {
  if (e.key === 'Enter') {
    console.log('Enter key pressed')
  }
})
```

### Создание элементов: `createElement` / `appendChild`

Динамически создавайте и добавляйте новые HTML-элементы.

```javascript
// Create new element
const newDiv = document.createElement('div')
newDiv.textContent = 'New content'
newDiv.className = 'highlight'
// Add to page
document.body.appendChild(newDiv)

// Create list item
const li = document.createElement('li')
li.innerHTML = "<a href='#'>New Link</a>"
document.querySelector('ul').appendChild(li)

// Remove element
const oldElement = document.querySelector('.remove-me')
oldElement.remove()
```

## Адаптивный дизайн и медиа-запросы CSS

### Мета-тег Viewport: `viewport`

Настройте правильный viewport для адаптивного дизайна.

```html
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
```

```css
/* CSS for responsive images */
img {
  max-width: 100%;
  height: auto;
}

/* Responsive container */
.container {
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 20px;
}
```

### Медиа-запросы: `@media`

Применяйте разные стили в зависимости от размера экрана и возможностей устройства.

```css
/* Mobile first approach */
.grid {
  display: grid;
  grid-template-columns: 1fr; /* Single column on mobile */
  gap: 20px;
}

/* Tablet and up */
@media (min-width: 768px) {
  .grid {
    grid-template-columns: repeat(2, 1fr); /* 2 columns */
  }
}

/* Desktop and up */
@media (min-width: 1024px) {
  .grid {
    grid-template-columns: repeat(3, 1fr); /* 3 columns */
  }
}
```

### Гибкие единицы: `rem` / `em` / `%` / `vw` / `vh`

Используйте относительные единицы для масштабируемого и адаптивного дизайна.

```css
/* Relative to root font-size */
h1 {
  font-size: 2rem;
} /* 32px if root is 16px */

/* Relative to parent font-size */
p {
  font-size: 1.2em;
} /* 1.2 times parent size */

/* Percentage based */
.sidebar {
  width: 30%;
} /* 30% of parent width */

/* Viewport units */
.hero {
  height: 100vh; /* Full viewport height */
  width: 100vw; /* Full viewport width */
}
```

### Адаптивная типографика: `clamp()`

Создавайте плавную типографику, которая масштабируется в зависимости от размера экрана.

```css
/* Fluid typography */
h1 {
  font-size: clamp(1.5rem, 4vw, 3rem);
  /* Min: 1.5rem, Preferred: 4vw, Max: 3rem */
}

/* Responsive spacing */
.section {
  padding: clamp(2rem, 5vw, 6rem) clamp(1rem, 3vw, 3rem);
}

/* Container queries (newer browsers) */
@container (min-width: 400px) {
  .card {
    display: flex;
  }
}
```

## Отладка и инструменты разработчика браузера

### Методы Console: `console.log()` / `console.error()`

Отлаживайте и отслеживайте свой код с помощью вывода в консоль.

```javascript
// Basic logging
console.log('Hello, world!')
console.log('User data:', userData)

// Different log levels
console.info('Information message')
console.warn('Warning message')
console.error('Error message')

// Grouping logs
console.group('User Details')
console.log('Name:', user.name)
console.log('Email:', user.email)
console.groupEnd()
```

### Методы отладки: `debugger` / Точки останова (Breakpoints)

Приостановите выполнение кода для проверки переменных и состояния программы.

```javascript
function calculateTotal(items) {
  let total = 0
  debugger // Code will pause here when dev tools open

  for (let item of items) {
    total += item.price
    console.log('Current total:', total)
  }
  return total
}

// Error handling
try {
  const result = riskyFunction()
} catch (error) {
  console.error('Error occurred:', error.message)
}
```

### Инструменты разработчика браузера: Elements / Console / Network

Используйте инструменты браузера для проверки HTML, отладки JavaScript и мониторинга сетевых запросов.

```javascript
// Inspect elements in console
$0 // Currently selected element in Elements tab
$1 // Previously selected element

// Query elements from console
$('selector') // Same as document.querySelector
$$('selector') // Same as document.querySelectorAll

// Monitor functions
monitor(functionName) // Log when function is called

// Performance timing
console.time('operation')
// ... some code ...
console.timeEnd('operation')

// Common errors and solutions
// ReferenceError: Variable not defined
// console.log(undefinedVariable); //
```

### Типы ошибок: `TypeError` / `ReferenceError`

Поймите распространенные ошибки JavaScript и способы их исправления.

## Соответствующие ссылки

- <router-link to="/html">Шпаргалка по HTML</router-link>
- <router-link to="/css">Шпаргалка по CSS</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/react">Шпаргалка по React</router-link>

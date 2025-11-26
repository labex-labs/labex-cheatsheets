---
title: 'Шпаргалка по CSS'
description: 'Изучите CSS с нашей подробной шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/css-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по CSS
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/css">Изучайте CSS с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучайте веб-стилизацию CSS с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по CSS, охватывающие основные свойства, селекторы, методы макетирования, адаптивный дизайн и современные функции. Освойте эффективную веб-стилизацию и разработку макетов для современных рабочих процессов веб-разработки.
</base-disclaimer-content>
</base-disclaimer>

## Синтаксис CSS и Селекторы

### Базовый Синтаксис

CSS состоит из селекторов и деклараций. Селектор нацелен на HTML-элементы, а декларации устанавливают значения свойств.

```css
/* Базовый синтаксис */
selector {
  property: value;
  property: value;
}

/* Пример */
p {
  color: red;
  font-size: 16px;
}
```

### Селекторы Элементов

Нацеливание на HTML-элементы по их тегу.

```css
/* Выбрать все абзацы */
p {
  color: blue;
}

/* Выбрать все заголовки */
h1 {
  font-size: 2em;
}

/* Выбрать все ссылки */
a {
  text-decoration: none;
}
```

### Селекторы Классов

Нацеливание на элементы с определенным атрибутом `class`.

```css
/* Выбрать элементы с class="highlight" */
.highlight {
  background-color: yellow;
}

/* Выбрать абзацы с class="intro" */
p.intro {
  font-weight: bold;
}

/* Несколько классов */
.large.bold {
  font-size: 20px;
  font-weight: bold;
}
```

### Селекторы ID

Нацеливание на элементы с определенным атрибутом `id`.

```css
/* Выбрать элемент с id="header" */
#header {
  background-color: #333;
}

/* ID должны быть уникальными на странице */
#navigation {
  position: fixed;
}
```

### Селекторы Атрибутов

Нацеливание на элементы с определенными атрибутами с использованием селекторов атрибутов.

```css
/* Элементы с атрибутом title */
[title] {
  cursor: help;
}

/* Ссылки на внешние сайты */
a[href^='http'] {
  color: red;
}

/* Элементы ввода типа text */
input[type='text'] {
  border: 1px solid #ccc;
}
```

### Псевдоклассы

Псевдоклассы применяют CSS на основе изменений состояния и взаимодействия с пользователем.

```css
/* Состояния ссылок */
a:hover {
  color: red;
}
a:visited {
  color: purple;
}
a:active {
  color: orange;
}

/* Состояния форм */
input:focus {
  border-color: blue;
}
input:invalid {
  border-color: red;
}

/* Структурные псевдоклассы */
li:first-child {
  font-weight: bold;
}
li:nth-child(odd) {
  background-color: #f0f0f0;
}
```

## Модель Блока и Макет

### Контент: `width` / `height`

Фактическая область контента элемента.

```css
/* Установка размеров */
div {
  width: 300px;
  height: 200px;
}

/* Адаптивное изменение размера */
.container {
  width: 100%;
  max-width: 1200px;
}

/* Ограничения мин/макс */
.box {
  min-height: 100px;
  max-width: 500px;
}
```

### Отступ (Padding): `padding`

Пространство между контентом и границей, внутри элемента.

```css
/* Все стороны */
div {
  padding: 20px;
}

/* Отдельные стороны */
div {
  padding-top: 10px;
  padding-right: 15px;
}

/* Сокращенная запись: верх, право, низ, лево */
div {
  padding: 10px 15px 20px 5px;
}
```

### Граница (Border): `border`

Границы обеспечивают рамку для элементов с настраиваемыми размером, стилем и цветом.

```css
/* Сокращенная запись границы */
div {
  border: 2px solid #333;
}

/* Отдельные свойства */
div {
  border-width: 1px;
  border-style: dashed;
  border-color: red;
}

/* Отдельные стороны */
div {
  border-bottom: 3px solid blue;
}
```

### Поле (Margin): `margin`

Пространство вне границы, между элементами.

```css
/* Все стороны */
div {
  margin: 20px;
}

/* Центрирование по горизонтали */
div {
  margin: 0 auto;
}

/* Отдельные стороны */
div {
  margin-top: 30px;
  margin-bottom: 10px;
}

/* Отрицательные отступы */
div {
  margin-left: -20px;
}
```

## Текст и Типографика

### Свойства Шрифта

Управление семейством шрифтов, размером, начертанием и стилем.

```css
/* Семейство шрифтов */
body {
  font-family: Arial, sans-serif;
}

/* Google Fonts */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
body {
  font-family: 'Roboto', sans-serif;
}

/* Размер шрифта */
h1 {
  font-size: 2rem;
}
p {
  font-size: 16px;
}

/* Начертание шрифта */
h2 {
  font-weight: bold;
}
span {
  font-weight: 300;
}
```

### Выравнивание Текста

Управление позиционированием и интервалами текста.

```css
/* Горизонтальное выравнивание */
h1 {
  text-align: center;
}
p {
  text-align: justify;
}

/* Высота строки */
p {
  line-height: 1.6;
}

/* Интервал между буквами и словами */
h1 {
  letter-spacing: 2px;
}
p {
  word-spacing: 4px;
}
```

### Стилизация Текста

Добавление декораций и преобразований к тексту.

```css
/* Декорация текста */
a {
  text-decoration: underline;
}
.strike {
  text-decoration: line-through;
}

/* Преобразование текста */
.uppercase {
  text-transform: uppercase;
}
.capitalize {
  text-transform: capitalize;
}

/* Тень текста */
h1 {
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}
```

### Цвета

CSS предоставляет несколько различных способов указания цветов для различных потребностей стилизации.

```css
/* Форматы цветов */
p {
  color: red;
}
div {
  background-color: #ff5733;
}
span {
  color: rgb(255, 87, 51);
}
section {
  background-color: rgba(255, 87, 51, 0.8);
}

/* HSL цвета */
header {
  background-color: hsl(200, 100%, 50%);
}

/* CSS Переменные для цветов */
:root {
  --primary-color: #3498db;
}
.button {
  background-color: var(--primary-color);
}
```

## Макет Flexbox

### Свойства Flex-Контейнера

Свойства, применяемые к родительскому контейнеру.

```css
/* Включить flexbox */
.container {
  display: flex;
}

/* Направление flex (основная ось) */
.container {
  flex-direction: row; /* по умолчанию */
  flex-direction: column;
  flex-direction: row-reverse;
}

/* Выравнивание содержимого (основная ось) */
.container {
  justify-content: flex-start; /* по умолчанию */
  justify-content: center;
  justify-content: space-between;
  justify-content: space-around;
}

/* Выравнивание элементов (поперечная ось) */
.container {
  align-items: stretch; /* по умолчанию */
  align-items: center;
  align-items: flex-start;
}
```

### Свойства Flex-Элементов

Свойства, применяемые к дочерним элементам.

```css
/* Рост/сжатие flex */
.item {
  flex-grow: 1; /* расти, чтобы заполнить пространство */
  flex-shrink: 1; /* сжиматься при необходимости */
  flex-basis: auto; /* начальный размер */
}

/* Сокращенная запись */
.item {
  flex: 1; /* flex: 1 1 0% */
  flex: 0 0 200px; /* фиксированная ширина */
}

/* Индивидуальное выравнивание */
.item {
  align-self: center;
  align-self: flex-end;
}

/* Порядок */
.item {
  order: 2; /* изменить визуальный порядок */
}
```

## Макет CSS Grid

### Grid-Контейнер

Определение структуры и свойств сетки.

```css
/* Включить grid */
.grid-container {
  display: grid;
}

/* Определение колонок и строк */
.grid-container {
  grid-template-columns: 1fr 2fr 1fr;
  grid-template-rows: 100px auto 50px;
}

/* Промежутки сетки (gaps) */
.grid-container {
  gap: 20px;
  column-gap: 30px;
  row-gap: 10px;
}

/* Именованные области сетки */
.grid-container {
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}
```

### Grid-Элементы

Позиционирование и размеры элементов сетки.

```css
/* Позиционирование в сетке */
.grid-item {
  grid-column: 1 / 3; /* охватывает колонки 1-2 */
  grid-row: 2 / 4; /* охватывает строки 2-3 */
}

/* Сокращенная запись */
.grid-item {
  grid-area: 2 / 1 / 4 / 3; /* row-start / col-start / row-end / col-end */
}

/* Именованные области */
.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}

/* Автоматическое размещение */
.grid-item {
  grid-column: span 2; /* охватывает 2 колонки */
  grid-row: span 3; /* охватывает 3 строки */
}
```

## Позиционирование

### Свойство Position

Управление поведением позиционирования элементов.

```css
/* Static (по умолчанию) */
.element {
  position: static;
}

/* Relative позиционирование */
.element {
  position: relative;
  top: 20px;
  left: 10px;
}

/* Absolute позиционирование */
.element {
  position: absolute;
  top: 0;
  right: 0;
}

/* Fixed позиционирование */
.navbar {
  position: fixed;
  top: 0;
  width: 100%;
}

/* Sticky позиционирование */
.sidebar {
  position: sticky;
  top: 20px;
}
```

### Z-Index и Стек Слоев

Управление порядком наложения элементов друг на друга с помощью `z-index` и контекста стекирования.

```css
/* Порядок наложения */
.modal {
  position: fixed;
  z-index: 1000;
}
.overlay {
  position: absolute;
  z-index: 999;
}

/* Создание контекста стекирования */
.container {
  position: relative;
  z-index: 0;
}

/* Общие значения z-index */
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

## Адаптивный Дизайн

### Медиа-Запросы

Применение стилей на основе характеристик устройства.

```css
/* Подход Mobile first */
.container {
  width: 100%;
}

/* Стили для планшетов */
@media (min-width: 768px) {
  .container {
    width: 750px;
  }
}

/* Стили для настольных ПК */
@media (min-width: 1024px) {
  .container {
    width: 960px;
  }
}

/* Стили для печати */
@media print {
  body {
    font-size: 12pt;
  }
  .no-print {
    display: none;
  }
}

/* Ориентация */
@media (orientation: landscape) {
  .sidebar {
    display: block;
  }
}
```

### Адаптивные Единицы Измерения

Использование относительных единиц для гибких макетов.

```css
/* Единицы области просмотра (Viewport) */
.hero {
  height: 100vh;
} /* полная высота области просмотра */
.sidebar {
  width: 25vw;
} /* 25% ширины области просмотра */

/* Относительные единицы */
p {
  font-size: 1.2em;
} /* 1.2x размер шрифта родителя */
h1 {
  font-size: 2rem;
} /* 2x размер шрифта корня */

/* Процентные единицы */
.container {
  width: 80%;
}
.column {
  width: 50%;
}

/* Адаптивный CSS Grid */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

/* Адаптивный Flexbox */
.flex-container {
  display: flex;
  flex-wrap: wrap;
}
```

## Анимации и Переходы

### CSS Переходы (Transitions)

Плавное изменение значений свойств.

```css
/* Базовый переход */
.button {
  background-color: blue;
  transition: background-color 0.3s ease;
}
.button:hover {
  background-color: red;
}

/* Несколько свойств */
.card {
  transform: scale(1);
  opacity: 1;
  transition: all 0.3s ease-in-out;
}
.card:hover {
  transform: scale(1.05);
  opacity: 0.8;
}

/* Индивидуальные переходы */
.element {
  transition-property: width, height;
  transition-duration: 0.5s, 1s;
  transition-timing-function: ease, linear;
}
```

### CSS Анимации

Создание сложных анимаций с помощью `@keyframes`.

```css
/* Определение ключевых кадров */
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

/* Применение анимаций */
.slide-in {
  animation: slideIn 0.5s ease-out;
}
.pulse {
  animation: pulse 2s infinite;
}

/* Сокращенная запись анимации */
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

## CSS Переменные и Функции

### CSS Переменные

Определение и использование пользовательских свойств для согласованной тематизации.

```css
/* Определение переменных */
:root {
  --primary-color: #3498db;
  --secondary-color: #2ecc71;
  --font-size-large: 24px;
  --border-radius: 8px;
}

/* Использование переменных */
.button {
  background-color: var(--primary-color);
  border-radius: var(--border-radius);
}

/* Значения по умолчанию */
.text {
  color: var(--text-color, #333);
}

/* Локальные переменные */
.card {
  --card-padding: 20px;
  padding: var(--card-padding);
}
```

### CSS Функции

CSS имеет ряд встроенных функций для вычислений и динамических значений.

```css
/* Функция Calc */
.container {
  width: calc(100% - 40px);
  height: calc(100vh - 60px);
}

/* Функции Min/Max */
.responsive {
  width: min(90%, 1200px);
  font-size: max(16px, 1.2vw);
  height: clamp(200px, 50vh, 400px);
}

/* Цветовые функции */
.element {
  background-color: hsl(200, 50%, 50%);
  color: rgb(255, 87, 51);
}

/* Функции Transform */
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

## Лучшие Практики и Организация

### Организация CSS

Структурирование вашего CSS для удобства сопровождения.

```css
/* Использование осмысленных имен классов */
.hero-section {
}
.primary-button {
}
.navigation-menu {
}

/* Методология BEM */
.block {
}
.block__element {
}
.block--modifier {
}

/* Пример */
.card {
}
.card__header {
}
.card__body {
}
.card--featured {
}

/* Группировка связанных стилей */
/* ===== МАКЕТ ===== */
.container {
}
.grid {
}

/* ===== КОМПОНЕНТЫ ===== */
.button {
}
.card {
}
```

### Производительность и Оптимизация

Написание эффективного CSS для лучшей производительности.

```css
/* Избегайте глубокой вложенности */
/* Плохо */
.header .nav ul li a {
}

/* Хорошо */
.nav-link {
}

/* Использование эффективных селекторов */
/* Плохо */
body div.container > p {
}

/* Хорошо */
.content-text {
}

/* Минимизация перерисовок */
/* Используйте transform вместо изменения position */
.element {
  transform: translateX(100px);
  /* вместо left: 100px; */
}

/* Группировка префиксов вендоров */
.element {
  -webkit-border-radius: 5px;
  -moz-border-radius: 5px;
  border-radius: 5px;
}
```

## Отладка CSS

### Инструменты Разработчика Браузера

Просмотр и изменение CSS в реальном времени.

```css
/* Общие шаги отладки */
/* 1. Щелкните правой кнопкой мыши → Inspect Element */
/* 2. Проверьте вычисленные стили (Computed styles) */
/* 3. Ищите переопределенные свойства */
/* 4. Тестируйте изменения в реальном времени */
/* 5. Скопируйте измененный CSS обратно в ваш файл */
```

### Распространенные Проблемы CSS

Устранение часто встречающихся проблем.

```css
/* Проблемы модели блока */
* {
  box-sizing: border-box;
}

/* Очистка float'ов */
.clearfix::after {
  content: '';
  display: table;
  clear: both;
}

/* Проблемы z-index */
/* Убедитесь, что элементы имеют позиционирование для работы z-index */
.element {
  position: relative;
  z-index: 1;
}
```

### Валидация CSS

Убедитесь, что ваш CSS соответствует стандартам и лучшим практикам.

```css
/* Использование валидаторов CSS */
/* W3C CSS Validator */
/* Инструменты совместимости с браузерами */

/* Комментируйте свой код */
/* ===== СТИЛИ ЗАГОЛОВКА ===== */
.header {
}

/* TODO: Добавить мобильные стили */
/* FIXME: Исправить совместимость с IE */

/* Используйте согласованное форматирование */
.element {
  property: value;
  property: value;
}
```

## Связанные Ссылки

- <router-link to="/html">Шпаргалка по HTML</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/react">Шпаргалка по React</router-link>
- <router-link to="/web-development">Шпаргалка по Веб-Разработке</router-link>

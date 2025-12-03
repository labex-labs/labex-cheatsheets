---
title: 'Шпаргалка по JavaScript | LabEx'
description: 'Изучите программирование на JavaScript с помощью этой исчерпывающей шпаргалки. Быстрый справочник по синтаксису JS, ES6+, манипуляциям с DOM, async/await, Node.js и современной веб-разработке.'
pdfUrl: '/cheatsheets/pdf/javascript-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по JavaScript
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/javascript">Изучайте JavaScript с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучайте программирование на JavaScript с помощью практических лабораторий и реальных сценариев. LabEx предлагает комплексные курсы по JavaScript, охватывающие основные синтаксис, функции, манипуляции с DOM, асинхронное программирование и современные функции ES6+. Освойте JavaScript для эффективной веб-разработки и рабочих процессов программирования.
</base-disclaimer-content>
</base-disclaimer>

## Переменные и Типы Данных

### Объявления Переменных: `let`, `const`, `var`

Объявляйте переменные с разной областью видимости и изменяемостью.

```javascript
// Ограниченная блоком, изменяемая
let name = 'John'
let age = 25
age = 26 // Можно переназначать

// Ограниченная блоком, неизменяемая
const PI = 3.14159
const user = { name: 'Alice' }
user.age = 30 // Свойства объекта можно изменять

// Ограниченная функцией (избегать в современном JS)
var oldVariable = 'legacy'
```

<BaseQuiz id="javascript-let-const-1" correct="B">
  <template #question>
    Какова основная разница между <code>let</code> и <code>const</code>?
  </template>
  
  <BaseQuizOption value="A">let имеет область видимости функции, const имеет область видимости блока</BaseQuizOption>
  <BaseQuizOption value="B" correct>let разрешает переназначение, const не разрешает переназначение</BaseQuizOption>
  <BaseQuizOption value="C">const можно использовать только для чисел, let можно использовать для любого типа</BaseQuizOption>
  <BaseQuizOption value="D">Разницы нет</BaseQuizOption>
  
  <BaseQuizAnswer>
    И <code>let</code>, и <code>const</code> имеют блочную область видимости, но <code>let</code> позволяет вам переназначать переменную, в то время как <code>const</code> предотвращает переназначение. Однако свойства объектов <code>const</code> все еще могут быть изменены.
  </BaseQuizAnswer>
</BaseQuiz>

### Примитивные Типы

Основные типы данных в JavaScript.

```javascript
// String
let message = 'Hello World'
let template = `Welcome ${name}`

// Number
let integer = 42
let float = 3.14
let scientific = 2e5 // 200000

// Boolean
let isActive = true
let isComplete = false

// Other primitives
let nothing = null
let notDefined = undefined
let unique = Symbol('id')
```

### Проверка Типов: `typeof`, `instanceof`

Определите тип переменных и значений.

```javascript
// Проверка примитивных типов
typeof 42 // 'number'
typeof 'hello' // 'string'
typeof true // 'boolean'
typeof undefined // 'undefined'

// Проверка типов объектов
let arr = [1, 2, 3]
typeof arr // 'object'
arr instanceof Array // true

let date = new Date()
date instanceof Date // true
```

### Преобразование Типов

Преобразование между различными типами данных.

```javascript
// Преобразование в строку
String(42) // '42'
;(42).toString() // '42'

// Преобразование в число
Number('42') // 42
parseInt('42px') // 42
parseFloat('3.14') // 3.14

// Преобразование в булево значение
Boolean(0) // false
Boolean('hello') // true
!!'text' // true (двойное отрицание)
```

## Функции

### Объявления Функций

Традиционный способ определения функций с поднятием (hoisting).

```javascript
// Объявление функции (hoisted)
function greet(name) {
  return `Hello, ${name}!`
}

// Функция с параметрами по умолчанию
function multiply(a, b = 1) {
  return a * b
}

// Остаточные параметры (Rest parameters)
function sum(...numbers) {
  return numbers.reduce((a, b) => a + b, 0)
}
```

### Функциональные Выражения и Стрелочные Функции

Современный синтаксис функций и анонимные функции.

```javascript
// Функциональное выражение
const add = function (a, b) {
  return a + b
}

// Стрелочная функция (краткая)
const subtract = (a, b) => a - b

// Стрелочная функция с блочным телом
const processData = (data) => {
  const processed = data.filter((x) => x > 0)
  return processed.map((x) => x * 2)
}
```

<BaseQuiz id="javascript-arrow-1" correct="C">
  <template #question>
    Какая ключевая характеристика стрелочных функций?
  </template>
  
  <BaseQuizOption value="A">Они поднимаются (hoisted) как объявления функций</BaseQuizOption>
  <BaseQuizOption value="B">У них есть собственное связывание <code>this</code></BaseQuizOption>
  <BaseQuizOption value="C" correct>Они наследуют <code>this</code> из окружающей области видимости</BaseQuizOption>
  <BaseQuizOption value="D">Они не могут возвращать значения</BaseQuizOption>
  
  <BaseQuizAnswer>
    Стрелочные функции не имеют собственного связывания <code>this</code>. Вместо этого они наследуют <code>this</code> из лексической (окружающей) области видимости, что делает их полезными для колбэков и обработчиков событий, когда вы хотите сохранить контекст.
  </BaseQuizAnswer>
</BaseQuiz>

### Функции Высшего Порядка

Функции, которые принимают или возвращают другие функции.

```javascript
// Функция, возвращающая функцию
function createMultiplier(factor) {
  return function (number) {
    return number * factor
  }
}
const double = createMultiplier(2)

// Функция как параметр
function applyOperation(arr, operation) {
  return arr.map(operation)
}
```

## Массивы и Объекты

### Методы Массивов: `map()`, `filter()`, `reduce()`

Функциональное преобразование и манипулирование массивами.

```javascript
const numbers = [1, 2, 3, 4, 5]

// Преобразование каждого элемента
const doubled = numbers.map((x) => x * 2)
// [2, 4, 6, 8, 10]

// Фильтрация элементов
const evens = numbers.filter((x) => x % 2 === 0)
// [2, 4]

// Свертка до одного значения
const sum = numbers.reduce((acc, curr) => acc + curr, 0)
// 15

// Цепочка методов
const result = numbers
  .filter((x) => x > 2)
  .map((x) => x * 3)
  .reduce((a, b) => a + b, 0)
```

<BaseQuiz id="javascript-array-1" correct="A">
  <template #question>
    Что возвращает <code>filter()</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Новый массив с элементами, прошедшими тест</BaseQuizOption>
  <BaseQuizOption value="B">Первый элемент, прошедший тест</BaseQuizOption>
  <BaseQuizOption value="C">Единственное значение, полученное путем свертки массива</BaseQuizOption>
  <BaseQuizOption value="D">Исходный массив, измененный на месте</BaseQuizOption>
  
  <BaseQuizAnswer>
    Метод <code>filter()</code> создает новый массив, содержащий все элементы, прошедшие тест, реализованный предоставленной функцией. Он не изменяет исходный массив.
  </BaseQuizAnswer>
</BaseQuiz>

### Утилиты Массивов: `find()`, `includes()`, `sort()`

Поиск, проверка и упорядочивание элементов массива.

```javascript
const users = [
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 30 },
  { name: 'Charlie', age: 35 },
]

// Поиск элемента
const user = users.find((u) => u.age > 30)

// Проверка, содержит ли массив значение
;[1, 2, 3].includes(2) // true

// Сортировка массива
const sorted = users.sort((a, b) => a.age - b.age)
```

### Создание и Манипуляции с Объектами

Работа с объектами и их свойствами.

```javascript
// Литерал объекта
const person = {
  name: 'John',
  age: 30,
  greet() {
    return `Hi, I'm ${this.name}`
  },
}

// Object.keys, values, entries
Object.keys(person) // ['name', 'age', 'greet']
Object.values(person) // ['John', 30, function]
Object.entries(person) // [['name', 'John'], ...]

// Присвоение объекта
const newPerson = Object.assign({}, person, { age: 31 })
```

### Деструктурирующее Присваивание

Извлечение значений из массивов и объектов.

```javascript
// Деструктуризация массива
const [first, second, ...rest] = [1, 2, 3, 4, 5]
// first: 1, second: 2, rest: [3, 4, 5]

// Деструктуризация объекта
const { name, age } = person
const { name: userName, age: userAge = 18 } = person

// Деструктуризация параметров функции
function displayUser({ name, age }) {
  console.log(`${name} is ${age} years old`)
}
```

## Манипуляции с DOM

### Выбор Элементов: `querySelector()`, `getElementById()`

Поиск и выбор элементов HTML.

```javascript
// Выбор по ID
const header = document.getElementById('main-header')

// Выбор по CSS-селектору (первое совпадение)
const button = document.querySelector('.btn-primary')
const input = document.querySelector('input[type="email"]')

// Выбор нескольких элементов
const allButtons = document.querySelectorAll('.btn')
const listItems = document.querySelectorAll('li')

// Преобразование NodeList в Array
const buttonsArray = Array.from(allButtons)
```

<BaseQuiz id="javascript-dom-1" correct="C">
  <template #question>
    Какова разница между <code>querySelector()</code> и <code>querySelectorAll()</code>?
  </template>
  
  <BaseQuizOption value="A">Разницы нет</BaseQuizOption>
  <BaseQuizOption value="B">querySelector быстрее</BaseQuizOption>
  <BaseQuizOption value="C" correct>querySelector возвращает первый совпадающий элемент, querySelectorAll возвращает все совпадающие элементы</BaseQuizOption>
  <BaseQuizOption value="D">querySelector работает с ID, querySelectorAll работает с классами</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>querySelector()</code> возвращает первый элемент, соответствующий CSS-селектору, в то время как <code>querySelectorAll()</code> возвращает NodeList, содержащий все совпадающие элементы. Используйте <code>querySelector()</code>, когда нужен один элемент, и <code>querySelectorAll()</code>, когда нужно несколько.
  </BaseQuizAnswer>
</BaseQuiz>

### Модификация Элементов

Изменение содержимого, атрибутов и стилей.

```javascript
// Изменение текстового содержимого
element.textContent = 'New text'
element.innerHTML = 'Bold text'

// Модификация атрибутов
element.setAttribute('data-id', '123')
element.removeAttribute('disabled')
const value = element.getAttribute('data-id')

// Изменение классов
element.classList.add('active')
element.classList.remove('hidden')
element.classList.toggle('highlight')
```

### Создание и Вставка Элементов

Динамическое создание и добавление HTML-элементов.

```javascript
// Создание нового элемента
const div = document.createElement('div')
div.textContent = 'Hello World'
div.className = 'container'

// Вставка элементов
const parent = document.querySelector('#container')
parent.appendChild(div)
parent.insertBefore(div, parent.firstChild)

// Современные методы вставки
parent.prepend(div) // Вставить в начало
parent.append(div) // Вставить в конец
div.before(newElement) // Вставить перед div
div.after(newElement) // Вставить после div
```

### Стилизация Элементов

Применение CSS-стилей программно.

```javascript
// Прямая модификация стиля
element.style.color = 'red'
element.style.backgroundColor = 'blue'
element.style.fontSize = '16px'

// Установка нескольких стилей
Object.assign(element.style, {
  width: '100px',
  height: '50px',
  border: '1px solid black',
})

// Получение вычисленных стилей
const styles = window.getComputedStyle(element)
const color = styles.getPropertyValue('color')
```

## Обработка Событий

### Добавление Обработчиков Событий

Реагирование на действия пользователя и события браузера.

```javascript
// Базовый обработчик событий
button.addEventListener('click', function (event) {
  console.log('Button clicked!')
})

// Обработчик событий со стрелочной функцией
button.addEventListener('click', (e) => {
  e.preventDefault() // Предотвратить поведение по умолчанию
  console.log('Clicked:', e.target)
})

// Обработчик событий с опциями
element.addEventListener('scroll', handler, {
  passive: true,
  once: true,
})
```

### Типы Событий и Свойства

Общие события и свойства объекта события.

```javascript
// События мыши
element.addEventListener('click', handleClick)
element.addEventListener('mouseover', handleMouseOver)
element.addEventListener('mouseout', handleMouseOut)

// События клавиатуры
input.addEventListener('keydown', (e) => {
  console.log('Key pressed:', e.key)
  if (e.key === 'Enter') {
    // Обработать клавишу Enter
  }
})

// События формы
form.addEventListener('submit', handleSubmit)
```

### Делегирование Событий

Эффективная обработка событий для нескольких элементов.

```javascript
// Делегирование событий на родительском элементе
document.querySelector('#list').addEventListener('click', (e) => {
  if (e.target.matches('.list-item')) {
    console.log('List item clicked:', e.target.textContent)
  }
})

// Удаление обработчиков событий
function handleClick(e) {
  console.log('Clicked')
}
button.addEventListener('click', handleClick)
button.removeEventListener('click', handleClick)
```

### Пользовательские События

Создание и отправка пользовательских событий.

```javascript
// Создание пользовательского события
const customEvent = new CustomEvent('userLogin', {
  detail: { username: 'john', timestamp: Date.now() },
})

// Отправка события
element.dispatchEvent(customEvent)

// Прослушивание пользовательского события
element.addEventListener('userLogin', (e) => {
  console.log('User logged in:', e.detail.username)
})
```

## Асинхронное Программирование

### Промисы: `Promise`, `then()`, `catch()`

Работа с асинхронными операциями с использованием промисов.

```javascript
// Создание промиса
const fetchData = new Promise((resolve, reject) => {
  setTimeout(() => {
    const success = true
    if (success) {
      resolve({ data: 'Hello World' })
    } else {
      reject(new Error('Failed to fetch'))
    }
  }, 1000)
})

// Использование промисов
fetchData
  .then((result) => console.log(result.data))
  .catch((error) => console.error(error))
  .finally(() => console.log('Done'))
```

### Async/Await: `async`, `await`

Современный синтаксис для обработки асинхронного кода.

```javascript
// Асинхронная функция
async function getData() {
  try {
    const response = await fetch('/api/data')
    const data = await response.json()
    return data
  } catch (error) {
    console.error('Error:', error)
    throw error
  }
}

// Использование асинхронной функции
getData()
  .then((data) => console.log(data))
  .catch((error) => console.error(error))
```

### API Fetch: `fetch()`

Выполнение HTTP-запросов к серверам.

```javascript
// GET запрос
fetch('/api/users')
  .then((response) => response.json())
  .then((users) => console.log(users))

// POST запрос
fetch('/api/users', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ name: 'John', age: 30 }),
})
  .then((response) => response.json())
  .then((data) => console.log(data))
```

### Утилиты Промисов: `Promise.all()`, `Promise.race()`

Одновременная работа с несколькими промисами.

```javascript
// Ожидание разрешения всех промисов
const promises = [fetch('/api/users'), fetch('/api/posts')]
Promise.all(promises)
  .then((responses) => Promise.all(responses.map((r) => r.json())))
  .then(([users, posts]) => {
    console.log('Users:', users)
    console.log('Posts:', posts)
  })

// Race - побеждает первый разрешившийся промис
Promise.race(promises).then((firstResponse) => console.log('First response'))
```

## Современные Функции ES6+

### Шаблонные Литералы и Оператор Распространения (Spread Operator)

Интерполяция строк и распространение массивов/объектов.

```javascript
// Шаблонные литералы
const name = 'Alice'
const age = 25
const message = `Hello, ${name}! You are ${age} years old.`

// Многострочные строки
const html = `
    <div>
        ${name}
        Age: ${age}
    </div>
`

// Оператор распространения
const arr1 = [1, 2, 3]
const arr2 = [4, 5, 6]
const combined = [...arr1, ...arr2] // [1,2,3,4,5,6]

const obj1 = { a: 1, b: 2 }
const obj2 = { ...obj1, c: 3 } // { a: 1, b: 2, c: 3 }
```

### Классы и Модули

Объектно-ориентированное программирование и система модулей.

```javascript
// ES6 Классы
class Person {
  constructor(name, age) {
    this.name = name
    this.age = age
  }

  greet() {
    return `Hi, I'm ${this.name}`
  }

  static createAnonymous() {
    return new Person('Anonymous', 0)
  }
}

// Наследование
class Student extends Person {
  constructor(name, age, grade) {
    super(name, age)
    this.grade = grade
  }
}

// Экспорт/импорт модулей
export const helper = () => 'helper function'
export default Person

import Person, { helper } from './person.js'
```

## Обработка Ошибок

### Try/Catch/Finally

Обработка синхронных и асинхронных ошибок.

```javascript
// Базовая обработка ошибок
try {
  const result = riskyOperation()
  console.log(result)
} catch (error) {
  console.error('Error occurred:', error.message)
} finally {
  console.log('Cleanup code runs here')
}

// Асинхронная обработка ошибок
async function asyncOperation() {
  try {
    const data = await fetch('/api/data')
    const json = await data.json()
    return json
  } catch (error) {
    console.error('Async error:', error)
    throw error // Повторный выброс, если необходимо
  }
}
```

### Пользовательские Ошибки и Отладка

Создание пользовательских типов ошибок и эффективная отладка.

```javascript
// Пользовательский класс ошибки
class ValidationError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'ValidationError'
    this.field = field
  }
}

// Выброс пользовательской ошибки
function validateEmail(email) {
  if (!email.includes('@')) {
    throw new ValidationError('Invalid email format', 'email')
  }
}

// Методы отладки в консоли
console.log('Basic log')
console.warn('Warning message')
console.error('Error message')
console.table([{ name: 'John', age: 30 }])
console.time('operation')
// ... some code
console.timeEnd('operation')
```

## Локальное Хранилище и JSON

### API LocalStorage

Постоянное хранение данных в браузере.

```javascript
// Сохранение данных
localStorage.setItem('username', 'john_doe')
localStorage.setItem(
  'settings',
  JSON.stringify({
    theme: 'dark',
    notifications: true,
  }),
)

// Получение данных
const username = localStorage.getItem('username')
const settings = JSON.parse(localStorage.getItem('settings'))

// Удаление данных
localStorage.removeItem('username')
localStorage.clear() // Удалить все элементы

// Проверка существования ключа
if (localStorage.getItem('username') !== null) {
  // Ключ существует
}
```

### Операции с JSON

Разбор и сериализация данных JSON.

```javascript
// JavaScript объект в строку JSON
const user = { name: 'Alice', age: 25, active: true }
const jsonString = JSON.stringify(user)
// '{"name":"Alice","age":25,"active":true}'

// Строка JSON в объект JavaScript
const jsonData = '{"name":"Bob","age":30}'
const userObj = JSON.parse(jsonData)

// Обработка ошибок разбора JSON
try {
  const data = JSON.parse(invalidJson)
} catch (error) {
  console.error('Invalid JSON:', error.message)
}

// JSON с пользовательским replacer/reviver
const filtered = JSON.stringify(user, ['name', 'age'])
const parsed = JSON.parse(jsonString, (key, value) => {
  return key === 'age' ? value + 1 : value
})
```

## Регулярные Выражения

### Создание и Тестирование Шаблонов

Создание шаблонов regex и тестирование строк.

```javascript
// Литерал Regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Конструктор RegExp
const phoneRegex = new RegExp(r'\d{3}-\d{3}-\d{4}');

// Метод test
const isValidEmail = emailRegex.test('user@example.com'); // true

// Метод match
const text = 'Call me at 123-456-7890';
const phoneMatch = text.match(/\d{3}-\d{3}-\d{4}/);
console.log(phoneMatch[0]); // '123-456-7890'

// Глобальный поиск
const allNumbers = text.match(/\d+/g); // ['123', '456', '7890']
```

### Методы Строк с Regex

Использование regex с методами манипуляции строками.

```javascript
// Замена с помощью regex
const text = 'Hello World 123'
const cleaned = text.replace(/\d+/g, '') // 'Hello World '

// Разделение с помощью regex
const parts = 'apple,banana;orange:grape'.split(/[,:;]/)
// ['apple', 'banana', 'orange', 'grape']

// Метод search
const position = text.search(/\d+/) // 12 (позиция первой цифры)

// Общие шаблоны
const patterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  phone: /^\d{3}-\d{3}-\d{4}$/,
  url: /^https?:\/\/.+/,
  digits: /\d+/g,
  whitespace: /\s+/g,
}
```

## Настройка JavaScript и Среда

### Консоль Браузера

Встроенная среда JavaScript в веб-браузерах.

```javascript
// Открыть инструменты разработчика браузера (F12)
// Перейти на вкладку Console
console.log('Hello JavaScript!')

// Проверить код напрямую
let x = 5
let y = 10
console.log(x + y) // 15

// Включить скрипты в HTML
```

### Среда Node.js

Среда выполнения JavaScript для серверной разработки.

```bash
# Установить Node.js с nodejs.org
# Проверить установку
node --version
npm --version

# Запустить JavaScript файл
node script.js

# Инициализировать npm проект
npm init -y

# Установить пакеты
npm install lodash
npm install --save-dev jest
```

### Современные Инструменты Разработки

Основные инструменты для разработки на JavaScript.

```json
// Скрипт Package.json
{
  "scripts": {
    "start": "node index.js",
    "test": "jest",
    "build": "webpack"
  }
}
```

```bash
# Модули ES6 в браузере
# Babel для поддержки старых браузеров
npm install --save-dev @babel/core @babel/preset-env
```

## Лучшие Практики и Производительность

### Оптимизация Производительности

Техники для улучшения производительности JavaScript.

```javascript
// Дебаунсинг (Debouncing) для частых событий
function debounce(func, delay) {
  let timeoutId
  return function (...args) {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func.apply(this, args), delay)
  }
}

// Использование дебаунсированной функции
const debouncedSearch = debounce(searchFunction, 300)
input.addEventListener('input', debouncedSearch)

// Эффективные запросы к DOM
const elements = document.querySelectorAll('.item')
// Кэшировать длину, чтобы избежать пересчета
for (let i = 0, len = elements.length; i < len; i++) {
  // Обработать elements[i]
}
```

### Организация Кода и Стандарты

Структурирование кода для удобства сопровождения и читаемости.

```javascript
// Использовать строгий режим
'use strict'

// Соглашения об именовании
const userName = 'john' // camelCase для переменных
const API_URL = 'https://api.example.com' // CAPS для констант

// Документация функций
/**
 * Вычисляет площадь прямоугольника
 * @param {number} width - Ширина прямоугольника
 * @param {number} height - Высота прямоугольника
 * @returns {number} Площадь прямоугольника
 */
function calculateArea(width, height) {
  return width * height
}

// Использовать const по умолчанию, let при необходимости переназначения
const config = { theme: 'dark' }
let counter = 0
```

## Тестирование JavaScript Кода

### Модульное Тестирование с Jest

Написание и запуск тестов для функций JavaScript.

```javascript
// Установка Jest: npm install --save-dev jest

// math.js
export function add(a, b) {
  return a + b
}

export function multiply(a, b) {
  return a * b
}

// math.test.js
import { add, multiply } from './math.js'

test('adds 1 + 2 to equal 3', () => {
  expect(add(1, 2)).toBe(3)
})

test('multiplies 3 * 4 to equal 12', () => {
  expect(multiply(3, 4)).toBe(12)
})

// Запуск тестов: npm test
```

### Тестирование в Браузере и Отладка

Отладка JavaScript в инструментах разработчика браузера.

```javascript
// Установка точек останова
debugger // Приостанавливает выполнение в инструментах разработчика

// Методы консоли для отладки
console.log('Variable value:', variable)
console.assert(x > 0, 'x should be positive')
console.trace('Function call stack')

// Измерение производительности
performance.mark('start')
// ... код для измерения
performance.mark('end')
performance.measure('operation', 'start', 'end')

// Просмотр записей производительности
const measurements = performance.getEntriesByType('measure')
```

## Соответствующие Ссылки

- <router-link to="/html">Шпаргалка по HTML</router-link>
- <router-link to="/css">Шпаргалка по CSS</router-link>
- <router-link to="/react">Шпаргалка по React</router-link>
- <router-link to="/web-development">Шпаргалка по Веб-Разработке</router-link>

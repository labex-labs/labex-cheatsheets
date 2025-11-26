---
title: 'Hoja de Trucos de JavaScript'
description: 'Aprenda JavaScript con nuestra hoja de trucos completa que cubre comandos esenciales, conceptos y mejores prácticas.'
pdfUrl: '/cheatsheets/pdf/javascript-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de JavaScript
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/javascript">Aprende JavaScript con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende programación JavaScript a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de JavaScript que cubren sintaxis esencial, funciones, manipulación del DOM, programación asíncrona y características modernas de ES6+. Domina JavaScript para flujos de trabajo eficientes de desarrollo web y programación.
</base-disclaimer-content>
</base-disclaimer>

## Variables y Tipos de Datos

### Declaraciones de Variables: `let`, `const`, `var`

Declara variables con diferentes alcances y mutabilidad.

```javascript
// Con alcance de bloque, mutable
let name = 'John'
let age = 25
age = 26 // Se puede reasignar

// Con alcance de bloque, inmutable
const PI = 3.14159
const user = { name: 'Alice' }
user.age = 30 // Las propiedades del objeto se pueden modificar

// Con alcance de función (evitar en JS moderno)
var oldVariable = 'legacy'
```

### Tipos Primitivos

Tipos de datos básicos en JavaScript.

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

// Otros primitivos
let nothing = null
let notDefined = undefined
let unique = Symbol('id')
```

### Verificación de Tipo: `typeof`, `instanceof`

Determina el tipo de variables y valores.

```javascript
// Comprobar tipos primitivos
typeof 42 // 'number'
typeof 'hello' // 'string'
typeof true // 'boolean'
typeof undefined // 'undefined'

// Comprobar tipos de objeto
let arr = [1, 2, 3]
typeof arr // 'object'
arr instanceof Array // true

let date = new Date()
date instanceof Date // true
```

### Conversión de Tipo

Convierte entre diferentes tipos de datos.

```javascript
// Conversión a String
String(42) // '42'
;(42).toString() // '42'

// Conversión a Number
Number('42') // 42
parseInt('42px') // 42
parseFloat('3.14') // 3.14

// Conversión a Boolean
Boolean(0) // false
Boolean('hello') // true
!!'text' // true (doble negación)
```

## Funciones

### Declaraciones de Funciones

Forma tradicional de definir funciones con elevación (hoisting).

```javascript
// Declaración de función (con hoisting)
function greet(name) {
  return `Hello, ${name}!`
}

// Función con parámetros por defecto
function multiply(a, b = 1) {
  return a * b
}

// Parámetros restantes (rest parameters)
function sum(...numbers) {
  return numbers.reduce((a, b) => a + b, 0)
}
```

### Expresiones de Función y Funciones de Flecha

Sintaxis de función moderna y funciones anónimas.

```javascript
// Expresión de función
const add = function (a, b) {
  return a + b
}

// Función de flecha (concisa)
const subtract = (a, b) => a - b

// Función de flecha con cuerpo de bloque
const processData = (data) => {
  const processed = data.filter((x) => x > 0)
  return processed.map((x) => x * 2)
}
```

### Funciones de Orden Superior

Funciones que toman o devuelven otras funciones.

```javascript
// Función que devuelve una función
function createMultiplier(factor) {
  return function (number) {
    return number * factor
  }
}
const double = createMultiplier(2)

// Función como parámetro
function applyOperation(arr, operation) {
  return arr.map(operation)
}
```

## Arrays y Objetos

### Métodos de Array: `map()`, `filter()`, `reduce()`

Transforma y manipula arrays funcionalmente.

```javascript
const numbers = [1, 2, 3, 4, 5]

// Transforma cada elemento
const doubled = numbers.map((x) => x * 2)
// [2, 4, 6, 8, 10]

// Filtra elementos
const evens = numbers.filter((x) => x % 2 === 0)
// [2, 4]

// Reduce a un solo valor
const sum = numbers.reduce((acc, curr) => acc + curr, 0)
// 15

// Encadenamiento de métodos
const result = numbers
  .filter((x) => x > 2)
  .map((x) => x * 3)
  .reduce((a, b) => a + b, 0)
```

### Utilidades de Array: `find()`, `includes()`, `sort()`

Busca, comprueba y organiza elementos de array.

```javascript
const users = [
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 30 },
  { name: 'Charlie', age: 35 },
]

// Encuentra elemento
const user = users.find((u) => u.age > 30)

// Comprueba si el array incluye un valor
;[1, 2, 3].includes(2) // true

// Ordena array
const sorted = users.sort((a, b) => a.age - b.age)
```

### Creación y Manipulación de Objetos

Trabaja con objetos y sus propiedades.

```javascript
// Literal de objeto
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

// Asignación de objeto
const newPerson = Object.assign({}, person, { age: 31 })
```

### Asignación por Desestructuración

Extrae valores de arrays y objetos.

```javascript
// Desestructuración de array
const [first, second, ...rest] = [1, 2, 3, 4, 5]
// first: 1, second: 2, rest: [3, 4, 5]

// Desestructuración de objeto
const { name, age } = person
const { name: userName, age: userAge = 18 } = person

// Desestructuración de parámetros de función
function displayUser({ name, age }) {
  console.log(`${name} is ${age} years old`)
}
```

## Manipulación del DOM

### Selección de Elementos: `querySelector()`, `getElementById()`

Encuentra y selecciona elementos HTML.

```javascript
// Seleccionar por ID
const header = document.getElementById('main-header')

// Seleccionar por selector CSS (primera coincidencia)
const button = document.querySelector('.btn-primary')
const input = document.querySelector('input[type="email"]')

// Seleccionar múltiples elementos
const allButtons = document.querySelectorAll('.btn')
const listItems = document.querySelectorAll('li')

// Convertir NodeList a Array
const buttonsArray = Array.from(allButtons)
```

### Modificación de Elementos

Cambia contenido, atributos y estilos.

```javascript
// Cambiar contenido de texto
element.textContent = 'New text'
element.innerHTML = 'Bold text'

// Modificar atributos
element.setAttribute('data-id', '123')
element.removeAttribute('disabled')
const value = element.getAttribute('data-id')

// Cambiar clases
element.classList.add('active')
element.classList.remove('hidden')
element.classList.toggle('highlight')
```

### Creación e Inserción de Elementos

Crea y añade dinámicamente elementos HTML.

```javascript
// Crear nuevo elemento
const div = document.createElement('div')
div.textContent = 'Hello World'
div.className = 'container'

// Insertar elementos
const parent = document.querySelector('#container')
parent.appendChild(div)
parent.insertBefore(div, parent.firstChild)

// Métodos de inserción modernos
parent.prepend(div) // Insertar al principio
parent.append(div) // Insertar al final
div.before(newElement) // Insertar antes de div
div.after(newElement) // Insertar después de div
```

### Estilismo de Elementos

Aplica estilos CSS programáticamente.

```javascript
// Modificación directa de estilo
element.style.color = 'red'
element.style.backgroundColor = 'blue'
element.style.fontSize = '16px'

// Establecer múltiples estilos
Object.assign(element.style, {
  width: '100px',
  height: '50px',
  border: '1px solid black',
})

// Obtener estilos calculados
const styles = window.getComputedStyle(element)
const color = styles.getPropertyValue('color')
```

## Manejo de Eventos

### Añadir Escuchadores de Eventos

Responde a interacciones del usuario y eventos del navegador.

```javascript
// Escuchador de eventos básico
button.addEventListener('click', function (event) {
  console.log('Button clicked!')
})

// Controlador de eventos de función de flecha
button.addEventListener('click', (e) => {
  e.preventDefault() // Prevenir comportamiento por defecto
  console.log('Clicked:', e.target)
})

// Escuchador de eventos con opciones
element.addEventListener('scroll', handler, {
  passive: true,
  once: true,
})
```

### Tipos de Eventos y Propiedades

Eventos comunes y propiedades del objeto de evento.

```javascript
// Eventos del ratón
element.addEventListener('click', handleClick)
element.addEventListener('mouseover', handleMouseOver)
element.addEventListener('mouseout', handleMouseOut)

// Eventos del teclado
input.addEventListener('keydown', (e) => {
  console.log('Key pressed:', e.key)
  if (e.key === 'Enter') {
    // Manejar tecla Enter
  }
})

// Eventos de formulario
form.addEventListener('submit', handleSubmit)
```

### Delegación de Eventos

Maneja eventos en múltiples elementos de manera eficiente.

```javascript
// Delegación de eventos en el elemento padre
document.querySelector('#list').addEventListener('click', (e) => {
  if (e.target.matches('.list-item')) {
    console.log('List item clicked:', e.target.textContent)
  }
})

// Eliminación de escuchadores de eventos
function handleClick(e) {
  console.log('Clicked')
}
button.addEventListener('click', handleClick)
button.removeEventListener('click', handleClick)
```

### Eventos Personalizados

Crea y dispara eventos personalizados.

```javascript
// Crear evento personalizado
const customEvent = new CustomEvent('userLogin', {
  detail: { username: 'john', timestamp: Date.now() },
})

// Disparar evento
element.dispatchEvent(customEvent)

// Escuchar evento personalizado
element.addEventListener('userLogin', (e) => {
  console.log('User logged in:', e.detail.username)
})
```

## Programación Asíncrona

### Promesas: `Promise`, `then()`, `catch()`

Trabaja con operaciones asíncronas usando promesas.

```javascript
// Creando una promesa
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

// Usando promesas
fetchData
  .then((result) => console.log(result.data))
  .catch((error) => console.error(error))
  .finally(() => console.log('Done'))
```

### Async/Await: `async`, `await`

Sintaxis moderna para manejar código asíncrono.

```javascript
// Función async
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

// Usando función async
getData()
  .then((data) => console.log(data))
  .catch((error) => console.error(error))
```

### API Fetch: `fetch()`

Realiza peticiones HTTP a servidores.

```javascript
// Petición GET
fetch('/api/users')
  .then((response) => response.json())
  .then((users) => console.log(users))

// Petición POST
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

### Utilidades de Promesa: `Promise.all()`, `Promise.race()`

Trabaja con múltiples promesas simultáneamente.

```javascript
// Esperar a que todas las promesas se resuelvan
const promises = [fetch('/api/users'), fetch('/api/posts')]
Promise.all(promises)
  .then((responses) => Promise.all(responses.map((r) => r.json())))
  .then(([users, posts]) => {
    console.log('Users:', users)
    console.log('Posts:', posts)
  })

// Race - la primera promesa que se resuelve gana
Promise.race(promises).then((firstResponse) => console.log('First response'))
```

## Características Modernas ES6+

### Literales de Plantilla y Operador Spread

Interpolación de cadenas y propagación de arrays/objetos.

```javascript
// Literales de plantilla
const name = 'Alice'
const age = 25
const message = `Hello, ${name}! You are ${age} years old.`

// Cadenas multilínea
const html = `
    <div>
        ${name}
        Age: ${age}
    </div>
`

// Operador spread
const arr1 = [1, 2, 3]
const arr2 = [4, 5, 6]
const combined = [...arr1, ...arr2] // [1,2,3,4,5,6]

const obj1 = { a: 1, b: 2 }
const obj2 = { ...obj1, c: 3 } // { a: 1, b: 2, c: 3 }
```

### Clases y Módulos

Programación orientada a objetos y sistema de módulos.

```javascript
// Clases ES6
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

// Herencia
class Student extends Person {
  constructor(name, age, grade) {
    super(name, age)
    this.grade = grade
  }
}

// Exportaciones/importaciones de módulo
export const helper = () => 'helper function'
export default Person

import Person, { helper } from './person.js'
```

## Manejo de Errores

### Try/Catch/Finally

Maneja errores síncronos y asíncronos.

```javascript
// Manejo básico de errores
try {
  const result = riskyOperation()
  console.log(result)
} catch (error) {
  console.error('Error occurred:', error.message)
} finally {
  console.log('Cleanup code runs here')
}

// Manejo de errores asíncronos
async function asyncOperation() {
  try {
    const data = await fetch('/api/data')
    const json = await data.json()
    return json
  } catch (error) {
    console.error('Async error:', error)
    throw error // Re-lanzar si es necesario
  }
}
```

### Errores Personalizados y Depuración

Crea tipos de error personalizados y depura eficazmente.

```javascript
// Clase de error personalizada
class ValidationError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'ValidationError'
    this.field = field
  }
}

// Lanzar error personalizado
function validateEmail(email) {
  if (!email.includes('@')) {
    throw new ValidationError('Invalid email format', 'email')
  }
}

// Métodos de depuración de consola
console.log('Basic log')
console.warn('Warning message')
console.error('Error message')
console.table([{ name: 'John', age: 30 }])
console.time('operation')
// ... some code
console.timeEnd('operation')
```

## Local Storage y JSON

### API LocalStorage

Almacena datos persistentemente en el navegador.

```javascript
// Almacenar datos
localStorage.setItem('username', 'john_doe')
localStorage.setItem(
  'settings',
  JSON.stringify({
    theme: 'dark',
    notifications: true,
  }),
)

// Recuperar datos
const username = localStorage.getItem('username')
const settings = JSON.parse(localStorage.getItem('settings'))

// Eliminar datos
localStorage.removeItem('username')
localStorage.clear() // Eliminar todos los elementos

// Comprobar si la clave existe
if (localStorage.getItem('username') !== null) {
  // La clave existe
}
```

### Operaciones JSON

Analiza y serializa datos JSON.

```javascript
// Objeto JavaScript a cadena JSON
const user = { name: 'Alice', age: 25, active: true }
const jsonString = JSON.stringify(user)
// '{"name":"Alice","age":25,"active":true}'

// Cadena JSON a objeto JavaScript
const jsonData = '{"name":"Bob","age":30}'
const userObj = JSON.parse(jsonData)

// Manejar errores de análisis JSON
try {
  const data = JSON.parse(invalidJson)
} catch (error) {
  console.error('Invalid JSON:', error.message)
}

// JSON con reemplazador/reviver personalizado
const filtered = JSON.stringify(user, ['name', 'age'])
const parsed = JSON.parse(jsonString, (key, value) => {
  return key === 'age' ? value + 1 : value
})
```

## Expresiones Regulares

### Creación y Prueba de Patrones

Crea patrones regex y prueba contra cadenas.

```javascript
// Literal de Regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Constructor RegExp
const phoneRegex = new RegExp(r'\d{3}-\d{3}-\d{4}');

// Método test
const isValidEmail = emailRegex.test('user@example.com'); // true

// Método match
const text = 'Call me at 123-456-7890';
const phoneMatch = text.match(/\d{3}-\d{3}-\d{4}/);
console.log(phoneMatch[0]); // '123-456-7890'

// Búsqueda global
const allNumbers = text.match(/\d+/g); // ['123', '456', '7890']
```

### Métodos de Cadena con Regex

Usa regex con métodos de manipulación de cadenas.

```javascript
// Reemplazar con regex
const text = 'Hello World 123'
const cleaned = text.replace(/\d+/g, '') // 'Hello World '

// Dividir con regex
const parts = 'apple,banana;orange:grape'.split(/[,:;]/)
// ['apple', 'banana', 'orange', 'grape']

// Método search
const position = text.search(/\d+/) // 12 (posición del primer dígito)

// Patrones comunes
const patterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  phone: /^\d{3}-\d{3}-\d{4}$/,
  url: /^https?:\/\/.+/,
  digits: /\d+/g,
  whitespace: /\s+/g,
}
```

## Configuración y Entorno de JavaScript

### Consola del Navegador

Entorno JavaScript incorporado en navegadores web.

```javascript
// Abrir herramientas de desarrollador del navegador (F12)
// Ir a la pestaña Console
console.log('Hello JavaScript!')

// Probar código directamente
let x = 5
let y = 10
console.log(x + y) // 15

// Incluir scripts en HTML
```

### Entorno Node.js

Runtime de JavaScript para desarrollo del lado del servidor.

```bash
# Instalar Node.js desde nodejs.org
# Comprobar instalación
node --version
npm --version

# Ejecutar archivo JavaScript
node script.js

# Inicializar proyecto npm
npm init -y

# Instalar paquetes
npm install lodash
npm install --save-dev jest
```

### Herramientas de Desarrollo Modernas

Herramientas esenciales para el desarrollo de JavaScript.

```json
// Script package.json
{
  "scripts": {
    "start": "node index.js",
    "test": "jest",
    "build": "webpack"
  }
}
```

```bash
# Módulos ES6 en el navegador
# Babel para soporte de navegadores antiguos
npm install --save-dev @babel/core @babel/preset-env
```

## Mejores Prácticas y Rendimiento

### Optimización del Rendimiento

Técnicas para mejorar el rendimiento de JavaScript.

```javascript
// Debouncing para eventos frecuentes
function debounce(func, delay) {
  let timeoutId
  return function (...args) {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func.apply(this, args), delay)
  }
}

// Usar función con debounce
const debouncedSearch = debounce(searchFunction, 300)
input.addEventListener('input', debouncedSearch)

// Consultas DOM eficientes
const elements = document.querySelectorAll('.item')
// Almacenar la longitud para evitar recálculos
for (let i = 0, len = elements.length; i < len; i++) {
  // Procesar elements[i]
}
```

### Organización y Estándares del Código

Estructura el código para mantenibilidad y legibilidad.

```javascript
// Usar modo estricto
'use strict'

// Convenciones de nomenclatura consistentes
const userName = 'john' // camelCase para variables
const API_URL = 'https://api.example.com' // MAYÚSCULAS para constantes

// Documentación de funciones
/**
 * Calcula el área de un rectángulo
 * @param {number} width - El ancho del rectángulo
 * @param {number} height - La altura del rectángulo
 * @returns {number} El área del rectángulo
 */
function calculateArea(width, height) {
  return width * height
}

// Usar const por defecto, let cuando se necesite reasignación
const config = { theme: 'dark' }
let counter = 0
```

## Pruebas de Código JavaScript

### Pruebas Unitarias con Jest

Escribe y ejecuta pruebas para funciones de JavaScript.

```javascript
// Instalar Jest: npm install --save-dev jest

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

// Ejecutar pruebas: npm test
```

### Pruebas en el Navegador y Depuración

Depura JavaScript en las herramientas de desarrollador del navegador.

```javascript
// Establecer puntos de interrupción (breakpoints)
debugger // Pausa la ejecución en las herramientas de desarrollo

// Métodos de consola para depuración
console.log('Variable value:', variable)
console.assert(x > 0, 'x should be positive')
console.trace('Function call stack')

// Medición de rendimiento
performance.mark('start')
// ... código a medir
performance.mark('end')
performance.measure('operation', 'start', 'end')

// Comprobar entradas de rendimiento
const measurements = performance.getEntriesByType('measure')
```

## Enlaces Relevantes

- <router-link to="/html">Hoja de Trucos de HTML</router-link>
- <router-link to="/css">Hoja de Trucos de CSS</router-link>
- <router-link to="/react">Hoja de Trucos de React</router-link>
- <router-link to="/web-development">Hoja de Trucos de Desarrollo Web</router-link>

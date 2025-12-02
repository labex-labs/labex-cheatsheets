---
title: 'JavaScript Cheatsheet | LabEx'
description: 'Learn JavaScript programming with this comprehensive cheatsheet. Quick reference for JS syntax, ES6+, DOM manipulation, async/await, Node.js, and modern web development.'
pdfUrl: '/cheatsheets/pdf/javascript-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
JavaScript Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/javascript">Learn JavaScript with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn JavaScript programming through hands-on labs and real-world scenarios. LabEx provides comprehensive JavaScript courses covering essential syntax, functions, DOM manipulation, asynchronous programming, and modern ES6+ features. Master JavaScript for efficient web development and programming workflows.
</base-disclaimer-content>
</base-disclaimer>

## Variables & Data Types

### Variable Declarations: `let`, `const`, `var`

Declare variables with different scopes and mutability.

```javascript
// Block-scoped, mutable
let name = 'John'
let age = 25
age = 26 // Can be reassigned

// Block-scoped, immutable
const PI = 3.14159
const user = { name: 'Alice' }
user.age = 30 // Object properties can be modified

// Function-scoped (avoid in modern JS)
var oldVariable = 'legacy'
```

<BaseQuiz id="javascript-let-const-1" correct="B">
  <template #question>
    What is the main difference between `let` and `const`?
  </template>
  
  <BaseQuizOption value="A">let is function-scoped, const is block-scoped</BaseQuizOption>
  <BaseQuizOption value="B" correct>let allows reassignment, const does not allow reassignment</BaseQuizOption>
  <BaseQuizOption value="C">const can only be used for numbers, let can be used for any type</BaseQuizOption>
  <BaseQuizOption value="D">There is no difference</BaseQuizOption>
  
  <BaseQuizAnswer>
    Both `let` and `const` are block-scoped, but `let` allows you to reassign the variable, while `const` prevents reassignment. However, `const` objects can still have their properties modified.
  </BaseQuizAnswer>
</BaseQuiz>

### Primitive Types

Basic data types in JavaScript.

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

### Type Checking: `typeof`, `instanceof`

Determine the type of variables and values.

```javascript
// Check primitive types
typeof 42 // 'number'
typeof 'hello' // 'string'
typeof true // 'boolean'
typeof undefined // 'undefined'

// Check object types
let arr = [1, 2, 3]
typeof arr // 'object'
arr instanceof Array // true

let date = new Date()
date instanceof Date // true
```

### Type Conversion

Convert between different data types.

```javascript
// String conversion
String(42) // '42'
;(42).toString() // '42'

// Number conversion
Number('42') // 42
parseInt('42px') // 42
parseFloat('3.14') // 3.14

// Boolean conversion
Boolean(0) // false
Boolean('hello') // true
!!'text' // true (double negation)
```

## Functions

### Function Declarations

Traditional way to define functions with hoisting.

```javascript
// Function declaration (hoisted)
function greet(name) {
  return `Hello, ${name}!`
}

// Function with default parameters
function multiply(a, b = 1) {
  return a * b
}

// Rest parameters
function sum(...numbers) {
  return numbers.reduce((a, b) => a + b, 0)
}
```

### Function Expressions & Arrow Functions

Modern function syntax and anonymous functions.

```javascript
// Function expression
const add = function (a, b) {
  return a + b
}

// Arrow function (concise)
const subtract = (a, b) => a - b

// Arrow function with block body
const processData = (data) => {
  const processed = data.filter((x) => x > 0)
  return processed.map((x) => x * 2)
}
```

<BaseQuiz id="javascript-arrow-1" correct="C">
  <template #question>
    What is a key characteristic of arrow functions?
  </template>
  
  <BaseQuizOption value="A">They are hoisted like function declarations</BaseQuizOption>
  <BaseQuizOption value="B">They have their own `this` binding</BaseQuizOption>
  <BaseQuizOption value="C" correct>They inherit `this` from the enclosing scope</BaseQuizOption>
  <BaseQuizOption value="D">They cannot return values</BaseQuizOption>
  
  <BaseQuizAnswer>
    Arrow functions do not have their own `this` binding. Instead, they inherit `this` from the lexical (enclosing) scope, which makes them useful for callbacks and event handlers where you want to preserve the context.
  </BaseQuizAnswer>
</BaseQuiz>

### Higher-Order Functions

Functions that take or return other functions.

```javascript
// Function that returns a function
function createMultiplier(factor) {
  return function (number) {
    return number * factor
  }
}
const double = createMultiplier(2)

// Function as parameter
function applyOperation(arr, operation) {
  return arr.map(operation)
}
```

## Arrays & Objects

### Array Methods: `map()`, `filter()`, `reduce()`

Transform and manipulate arrays functionally.

```javascript
const numbers = [1, 2, 3, 4, 5]

// Transform each element
const doubled = numbers.map((x) => x * 2)
// [2, 4, 6, 8, 10]

// Filter elements
const evens = numbers.filter((x) => x % 2 === 0)
// [2, 4]

// Reduce to single value
const sum = numbers.reduce((acc, curr) => acc + curr, 0)
// 15

// Chain methods
const result = numbers
  .filter((x) => x > 2)
  .map((x) => x * 3)
  .reduce((a, b) => a + b, 0)
```

<BaseQuiz id="javascript-array-1" correct="A">
  <template #question>
    What does `filter()` return?
  </template>
  
  <BaseQuizOption value="A" correct>A new array with elements that pass the test</BaseQuizOption>
  <BaseQuizOption value="B">The first element that passes the test</BaseQuizOption>
  <BaseQuizOption value="C">A single value reduced from the array</BaseQuizOption>
  <BaseQuizOption value="D">The original array modified in place</BaseQuizOption>
  
  <BaseQuizAnswer>
    The `filter()` method creates a new array containing all elements that pass the test implemented by the provided function. It does not modify the original array.
  </BaseQuizAnswer>
</BaseQuiz>

### Array Utilities: `find()`, `includes()`, `sort()`

Search, check, and organize array elements.

```javascript
const users = [
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 30 },
  { name: 'Charlie', age: 35 },
]

// Find element
const user = users.find((u) => u.age > 30)

// Check if array includes value
;[1, 2, 3].includes(2) // true

// Sort array
const sorted = users.sort((a, b) => a.age - b.age)
```

### Object Creation & Manipulation

Work with objects and their properties.

```javascript
// Object literal
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

// Object assignment
const newPerson = Object.assign({}, person, { age: 31 })
```

### Destructuring Assignment

Extract values from arrays and objects.

```javascript
// Array destructuring
const [first, second, ...rest] = [1, 2, 3, 4, 5]
// first: 1, second: 2, rest: [3, 4, 5]

// Object destructuring
const { name, age } = person
const { name: userName, age: userAge = 18 } = person

// Function parameter destructuring
function displayUser({ name, age }) {
  console.log(`${name} is ${age} years old`)
}
```

## DOM Manipulation

### Element Selection: `querySelector()`, `getElementById()`

Find and select HTML elements.

```javascript
// Select by ID
const header = document.getElementById('main-header')

// Select by CSS selector (first match)
const button = document.querySelector('.btn-primary')
const input = document.querySelector('input[type="email"]')

// Select multiple elements
const allButtons = document.querySelectorAll('.btn')
const listItems = document.querySelectorAll('li')

// Convert NodeList to Array
const buttonsArray = Array.from(allButtons)
```

<BaseQuiz id="javascript-dom-1" correct="C">
  <template #question>
    What is the difference between `querySelector()` and `querySelectorAll()`?
  </template>
  
  <BaseQuizOption value="A">There is no difference</BaseQuizOption>
  <BaseQuizOption value="B">querySelector is faster</BaseQuizOption>
  <BaseQuizOption value="C" correct>querySelector returns the first matching element, querySelectorAll returns all matching elements</BaseQuizOption>
  <BaseQuizOption value="D">querySelector works with IDs, querySelectorAll works with classes</BaseQuizOption>
  
  <BaseQuizAnswer>
    `querySelector()` returns the first element that matches the CSS selector, while `querySelectorAll()` returns a NodeList containing all matching elements. Use `querySelector()` when you need one element, and `querySelectorAll()` when you need multiple.
  </BaseQuizAnswer>
</BaseQuiz>

### Element Modification

Change content, attributes, and styles.

```javascript
// Change text content
element.textContent = 'New text'
element.innerHTML = 'Bold text'

// Modify attributes
element.setAttribute('data-id', '123')
element.removeAttribute('disabled')
const value = element.getAttribute('data-id')

// Change classes
element.classList.add('active')
element.classList.remove('hidden')
element.classList.toggle('highlight')
```

### Creating & Inserting Elements

Dynamically create and add HTML elements.

```javascript
// Create new element
const div = document.createElement('div')
div.textContent = 'Hello World'
div.className = 'container'

// Insert elements
const parent = document.querySelector('#container')
parent.appendChild(div)
parent.insertBefore(div, parent.firstChild)

// Modern insertion methods
parent.prepend(div) // Insert at beginning
parent.append(div) // Insert at end
div.before(newElement) // Insert before div
div.after(newElement) // Insert after div
```

### Styling Elements

Apply CSS styles programmatically.

```javascript
// Direct style modification
element.style.color = 'red'
element.style.backgroundColor = 'blue'
element.style.fontSize = '16px'

// Set multiple styles
Object.assign(element.style, {
  width: '100px',
  height: '50px',
  border: '1px solid black',
})

// Get computed styles
const styles = window.getComputedStyle(element)
const color = styles.getPropertyValue('color')
```

## Event Handling

### Adding Event Listeners

Respond to user interactions and browser events.

```javascript
// Basic event listener
button.addEventListener('click', function (event) {
  console.log('Button clicked!')
})

// Arrow function event handler
button.addEventListener('click', (e) => {
  e.preventDefault() // Prevent default behavior
  console.log('Clicked:', e.target)
})

// Event listener with options
element.addEventListener('scroll', handler, {
  passive: true,
  once: true,
})
```

### Event Types & Properties

Common events and event object properties.

```javascript
// Mouse events
element.addEventListener('click', handleClick)
element.addEventListener('mouseover', handleMouseOver)
element.addEventListener('mouseout', handleMouseOut)

// Keyboard events
input.addEventListener('keydown', (e) => {
  console.log('Key pressed:', e.key)
  if (e.key === 'Enter') {
    // Handle enter key
  }
})

// Form events
form.addEventListener('submit', handleSubmit)
```

### Event Delegation

Handle events on multiple elements efficiently.

```javascript
// Event delegation on parent element
document.querySelector('#list').addEventListener('click', (e) => {
  if (e.target.matches('.list-item')) {
    console.log('List item clicked:', e.target.textContent)
  }
})

// Removing event listeners
function handleClick(e) {
  console.log('Clicked')
}
button.addEventListener('click', handleClick)
button.removeEventListener('click', handleClick)
```

### Custom Events

Create and dispatch custom events.

```javascript
// Create custom event
const customEvent = new CustomEvent('userLogin', {
  detail: { username: 'john', timestamp: Date.now() },
})

// Dispatch event
element.dispatchEvent(customEvent)

// Listen for custom event
element.addEventListener('userLogin', (e) => {
  console.log('User logged in:', e.detail.username)
})
```

## Asynchronous Programming

### Promises: `Promise`, `then()`, `catch()`

Work with asynchronous operations using promises.

```javascript
// Creating a promise
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

// Using promises
fetchData
  .then((result) => console.log(result.data))
  .catch((error) => console.error(error))
  .finally(() => console.log('Done'))
```

### Async/Await: `async`, `await`

Modern syntax for handling asynchronous code.

```javascript
// Async function
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

// Using async function
getData()
  .then((data) => console.log(data))
  .catch((error) => console.error(error))
```

### Fetch API: `fetch()`

Make HTTP requests to servers.

```javascript
// GET request
fetch('/api/users')
  .then((response) => response.json())
  .then((users) => console.log(users))

// POST request
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

### Promise Utilities: `Promise.all()`, `Promise.race()`

Work with multiple promises simultaneously.

```javascript
// Wait for all promises to resolve
const promises = [fetch('/api/users'), fetch('/api/posts')]
Promise.all(promises)
  .then((responses) => Promise.all(responses.map((r) => r.json())))
  .then(([users, posts]) => {
    console.log('Users:', users)
    console.log('Posts:', posts)
  })

// Race - first promise to resolve wins
Promise.race(promises).then((firstResponse) => console.log('First response'))
```

## ES6+ Modern Features

### Template Literals & Spread Operator

String interpolation and array/object spreading.

```javascript
// Template literals
const name = 'Alice'
const age = 25
const message = `Hello, ${name}! You are ${age} years old.`

// Multi-line strings
const html = `
    <div>
        ${name}
        Age: ${age}
    </div>
`

// Spread operator
const arr1 = [1, 2, 3]
const arr2 = [4, 5, 6]
const combined = [...arr1, ...arr2] // [1,2,3,4,5,6]

const obj1 = { a: 1, b: 2 }
const obj2 = { ...obj1, c: 3 } // { a: 1, b: 2, c: 3 }
```

### Classes & Modules

Object-oriented programming and module system.

```javascript
// ES6 Classes
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

// Inheritance
class Student extends Person {
  constructor(name, age, grade) {
    super(name, age)
    this.grade = grade
  }
}

// Module exports/imports
export const helper = () => 'helper function'
export default Person

import Person, { helper } from './person.js'
```

## Error Handling

### Try/Catch/Finally

Handle synchronous and asynchronous errors.

```javascript
// Basic error handling
try {
  const result = riskyOperation()
  console.log(result)
} catch (error) {
  console.error('Error occurred:', error.message)
} finally {
  console.log('Cleanup code runs here')
}

// Async error handling
async function asyncOperation() {
  try {
    const data = await fetch('/api/data')
    const json = await data.json()
    return json
  } catch (error) {
    console.error('Async error:', error)
    throw error // Re-throw if needed
  }
}
```

### Custom Errors & Debugging

Create custom error types and debug effectively.

```javascript
// Custom error class
class ValidationError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'ValidationError'
    this.field = field
  }
}

// Throw custom error
function validateEmail(email) {
  if (!email.includes('@')) {
    throw new ValidationError('Invalid email format', 'email')
  }
}

// Console debugging methods
console.log('Basic log')
console.warn('Warning message')
console.error('Error message')
console.table([{ name: 'John', age: 30 }])
console.time('operation')
// ... some code
console.timeEnd('operation')
```

## Local Storage & JSON

### LocalStorage API

Store data persistently in the browser.

```javascript
// Store data
localStorage.setItem('username', 'john_doe')
localStorage.setItem(
  'settings',
  JSON.stringify({
    theme: 'dark',
    notifications: true,
  }),
)

// Retrieve data
const username = localStorage.getItem('username')
const settings = JSON.parse(localStorage.getItem('settings'))

// Remove data
localStorage.removeItem('username')
localStorage.clear() // Remove all items

// Check if key exists
if (localStorage.getItem('username') !== null) {
  // Key exists
}
```

### JSON Operations

Parse and stringify JSON data.

```javascript
// JavaScript object to JSON string
const user = { name: 'Alice', age: 25, active: true }
const jsonString = JSON.stringify(user)
// '{"name":"Alice","age":25,"active":true}'

// JSON string to JavaScript object
const jsonData = '{"name":"Bob","age":30}'
const userObj = JSON.parse(jsonData)

// Handle JSON parsing errors
try {
  const data = JSON.parse(invalidJson)
} catch (error) {
  console.error('Invalid JSON:', error.message)
}

// JSON with custom replacer/reviver
const filtered = JSON.stringify(user, ['name', 'age'])
const parsed = JSON.parse(jsonString, (key, value) => {
  return key === 'age' ? value + 1 : value
})
```

## Regular Expressions

### Creating & Testing Patterns

Create regex patterns and test against strings.

```javascript
// Regex literal
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// RegExp constructor
const phoneRegex = new RegExp(r'\d{3}-\d{3}-\d{4}');

// Test method
const isValidEmail = emailRegex.test('user@example.com'); // true

// Match method
const text = 'Call me at 123-456-7890';
const phoneMatch = text.match(/\d{3}-\d{3}-\d{4}/);
console.log(phoneMatch[0]); // '123-456-7890'

// Global search
const allNumbers = text.match(/\d+/g); // ['123', '456', '7890']
```

### String Methods with Regex

Use regex with string manipulation methods.

```javascript
// Replace with regex
const text = 'Hello World 123'
const cleaned = text.replace(/\d+/g, '') // 'Hello World '

// Split with regex
const parts = 'apple,banana;orange:grape'.split(/[,:;]/)
// ['apple', 'banana', 'orange', 'grape']

// Search method
const position = text.search(/\d+/) // 12 (position of first digit)

// Common patterns
const patterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  phone: /^\d{3}-\d{3}-\d{4}$/,
  url: /^https?:\/\/.+/,
  digits: /\d+/g,
  whitespace: /\s+/g,
}
```

## JavaScript Setup & Environment

### Browser Console

Built-in JavaScript environment in web browsers.

```javascript
// Open browser developer tools (F12)
// Go to Console tab
console.log('Hello JavaScript!')

// Test code directly
let x = 5
let y = 10
console.log(x + y) // 15

// Include scripts in HTML
```

### Node.js Environment

JavaScript runtime for server-side development.

```bash
# Install Node.js from nodejs.org
# Check installation
node --version
npm --version

# Run JavaScript file
node script.js

# Initialize npm project
npm init -y

# Install packages
npm install lodash
npm install --save-dev jest
```

### Modern Development Tools

Essential tools for JavaScript development.

```json
// Package.json script
{
  "scripts": {
    "start": "node index.js",
    "test": "jest",
    "build": "webpack"
  }
}
```

```bash
# ES6 modules in browser
# Babel for older browser support
npm install --save-dev @babel/core @babel/preset-env
```

## Best Practices & Performance

### Performance Optimization

Techniques to improve JavaScript performance.

```javascript
// Debouncing for frequent events
function debounce(func, delay) {
  let timeoutId
  return function (...args) {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func.apply(this, args), delay)
  }
}

// Use debounced function
const debouncedSearch = debounce(searchFunction, 300)
input.addEventListener('input', debouncedSearch)

// Efficient DOM queries
const elements = document.querySelectorAll('.item')
// Cache length to avoid recalculation
for (let i = 0, len = elements.length; i < len; i++) {
  // Process elements[i]
}
```

### Code Organization & Standards

Structure code for maintainability and readability.

```javascript
// Use strict mode
'use strict'

// Consistent naming conventions
const userName = 'john' // camelCase for variables
const API_URL = 'https://api.example.com' // CAPS for constants

// Function documentation
/**
 * Calculates the area of a rectangle
 * @param {number} width - The width of the rectangle
 * @param {number} height - The height of the rectangle
 * @returns {number} The area of the rectangle
 */
function calculateArea(width, height) {
  return width * height
}

// Use const by default, let when reassignment needed
const config = { theme: 'dark' }
let counter = 0
```

## Testing JavaScript Code

### Unit Testing with Jest

Write and run tests for JavaScript functions.

```javascript
// Install Jest: npm install --save-dev jest

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

// Run tests: npm test
```

### Browser Testing & Debugging

Debug JavaScript in browser developer tools.

```javascript
// Set breakpoints
debugger // Pauses execution in dev tools

// Console methods for debugging
console.log('Variable value:', variable)
console.assert(x > 0, 'x should be positive')
console.trace('Function call stack')

// Performance timing
performance.mark('start')
// ... code to measure
performance.mark('end')
performance.measure('operation', 'start', 'end')

// Check performance entries
const measurements = performance.getEntriesByType('measure')
```

## Relevant Links

- <router-link to="/html">HTML Cheatsheet</router-link>
- <router-link to="/css">CSS Cheatsheet</router-link>
- <router-link to="/react">React Cheatsheet</router-link>
- <router-link to="/web-development">Web Development Cheatsheet</router-link>

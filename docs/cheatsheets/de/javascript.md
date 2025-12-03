---
title: 'JavaScript Spickzettel | LabEx'
description: 'Lernen Sie JavaScript-Programmierung mit diesem umfassenden Spickzettel. Schnelle Referenz für JS-Syntax, ES6+, DOM-Manipulation, Async/Await, Node.js und moderne Webentwicklung.'
pdfUrl: '/cheatsheets/pdf/javascript-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
JavaScript Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/javascript">Lernen Sie JavaScript mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie die JavaScript-Programmierung durch praktische Labs und reale Szenarien. LabEx bietet umfassende JavaScript-Kurse, die wesentliche Syntax, Funktionen, DOM-Manipulation, asynchrone Programmierung und moderne ES6+-Funktionen abdecken. Meistern Sie JavaScript für effiziente Webentwicklung und Programmier-Workflows.
</base-disclaimer-content>
</base-disclaimer>

## Variablen & Datentypen

### Variablendeklarationen: `let`, `const`, `var`

Deklarieren Sie Variablen mit unterschiedlichem Geltungsbereich und unterschiedlicher Änderbarkeit.

```javascript
// Block-scoped, veränderbar
let name = 'John'
let age = 25
age = 26 // Kann neu zugewiesen werden

// Block-scoped, unveränderbar
const PI = 3.14159
const user = { name: 'Alice' }
user.age = 30 // Objekteigenschaften können geändert werden

// Funktions-scoped (in modernem JS vermeiden)
var oldVariable = 'legacy'
```

<BaseQuiz id="javascript-let-const-1" correct="B">
  <template #question>
    Was ist der Hauptunterschied zwischen <code>let</code> und <code>const</code>?
  </template>
  
  <BaseQuizOption value="A">let ist funktions-scoped, const ist block-scoped</BaseQuizOption>
  <BaseQuizOption value="B" correct>let erlaubt Neuzuweisung, const erlaubt keine Neuzuweisung</BaseQuizOption>
  <BaseQuizOption value="C">const kann nur für Zahlen verwendet werden, let kann für jeden Typ verwendet werden</BaseQuizOption>
  <BaseQuizOption value="D">Es gibt keinen Unterschied</BaseQuizOption>
  
  <BaseQuizAnswer>
    Sowohl <code>let</code> als auch <code>const</code> sind block-scoped, aber <code>let</code> erlaubt es Ihnen, die Variable neu zuzuweisen, während <code>const</code> die Neuzuweisung verhindert. Objekte, die mit <code>const</code> deklariert wurden, können jedoch immer noch ihre Eigenschaften ändern.
  </BaseQuizAnswer>
</BaseQuiz>

### Primitive Typen

Grundlegende Datentypen in JavaScript.

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

// Andere Primitiven
let nothing = null
let notDefined = undefined
let unique = Symbol('id')
```

### Typüberprüfung: `typeof`, `instanceof`

Bestimmen Sie den Typ von Variablen und Werten.

```javascript
// Primitive Typen prüfen
typeof 42 // 'number'
typeof 'hello' // 'string'
typeof true // 'boolean'
typeof undefined // 'undefined'

// Objekttypen prüfen
let arr = [1, 2, 3]
typeof arr // 'object'
arr instanceof Array // true

let date = new Date()
date instanceof Date // true
```

### Typkonvertierung

Konvertieren Sie zwischen verschiedenen Datentypen.

```javascript
// String-Konvertierung
String(42) // '42'
;(42).toString() // '42'

// Number-Konvertierung
Number('42') // 42
parseInt('42px') // 42
parseFloat('3.14') // 3.14

// Boolean-Konvertierung
Boolean(0) // false
Boolean('hello') // true
!!'text' // true (doppelte Negation)
```

## Funktionen

### Funktionsdeklarationen

Traditionelle Methode zur Definition von Funktionen mit Hoisting.

```javascript
// Funktionsdeklaration (gehoisted)
function greet(name) {
  return `Hello, ${name}!`
}

// Funktion mit Standardparametern
function multiply(a, b = 1) {
  return a * b
}

// Rest-Parameter
function sum(...numbers) {
  return numbers.reduce((a, b) => a + b, 0)
}
```

### Funktionsausdrücke & Pfeilfunktionen

Moderne Funktionssyntax und anonyme Funktionen.

```javascript
// Funktionsausdruck
const add = function (a, b) {
  return a + b
}

// Pfeilfunktion (prägnant)
const subtract = (a, b) => a - b

// Pfeilfunktion mit Block-Body
const processData = (data) => {
  const processed = data.filter((x) => x > 0)
  return processed.map((x) => x * 2)
}
```

<BaseQuiz id="javascript-arrow-1" correct="C">
  <template #question>
    Was ist ein Schlüsselmerkmal von Pfeilfunktionen?
  </template>
  
  <BaseQuizOption value="A">Sie werden wie Funktionsdeklarationen gehoisted</BaseQuizOption>
  <BaseQuizOption value="B">Sie haben ihre eigene <code>this</code>-Bindung</BaseQuizOption>
  <BaseQuizOption value="C" correct>Sie erben <code>this</code> aus dem umgebenden Gültigkeitsbereich</BaseQuizOption>
  <BaseQuizOption value="D">Sie können keine Werte zurückgeben</BaseQuizOption>
  
  <BaseQuizAnswer>
    Pfeilfunktionen haben keine eigene <code>this</code>-Bindung. Stattdessen erben sie <code>this</code> aus dem lexikalischen (umgebenden) Gültigkeitsbereich, was sie nützlich für Callbacks und Event-Handler macht, bei denen der Kontext beibehalten werden soll.
  </BaseQuizAnswer>
</BaseQuiz>

### Funktionen höherer Ordnung

Funktionen, die andere Funktionen als Argumente entgegennehmen oder zurückgeben.

```javascript
// Funktion, die eine Funktion zurückgibt
function createMultiplier(factor) {
  return function (number) {
    return number * factor
  }
}
const double = createMultiplier(2)

// Funktion als Parameter
function applyOperation(arr, operation) {
  return arr.map(operation)
}
```

## Arrays & Objekte

### Array-Methoden: `map()`, `filter()`, `reduce()`

Arrays funktional transformieren und manipulieren.

```javascript
const numbers = [1, 2, 3, 4, 5]

// Jedes Element transformieren
const doubled = numbers.map((x) => x * 2)
// [2, 4, 6, 8, 10]

// Elemente filtern
const evens = numbers.filter((x) => x % 2 === 0)
// [2, 4]

// Zu einem einzelnen Wert reduzieren
const sum = numbers.reduce((acc, curr) => acc + curr, 0)
// 15

// Methoden verketten
const result = numbers
  .filter((x) => x > 2)
  .map((x) => x * 3)
  .reduce((a, b) => a + b, 0)
```

<BaseQuiz id="javascript-array-1" correct="A">
  <template #question>
    Was gibt <code>filter()</code> zurück?
  </template>
  
  <BaseQuizOption value="A" correct>Ein neues Array mit Elementen, die den Test bestehen</BaseQuizOption>
  <BaseQuizOption value="B">Das erste Element, das den Test besteht</BaseQuizOption>
  <BaseQuizOption value="C">Ein einzelner Wert, der aus dem Array reduziert wurde</BaseQuizOption>
  <BaseQuizOption value="D">Das ursprüngliche Array, das an Ort und Stelle geändert wurde</BaseQuizOption>
  
  <BaseQuizAnswer>
    Die Methode <code>filter()</code> erstellt ein neues Array, das alle Elemente enthält, die den durch die bereitgestellte Funktion implementierten Test bestehen. Sie modifiziert nicht das ursprüngliche Array.
  </BaseQuizAnswer>
</BaseQuiz>

### Array-Dienstprogramme: `find()`, `includes()`, `sort()`

Array-Elemente suchen, überprüfen und organisieren.

```javascript
const users = [
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 30 },
  { name: 'Charlie', age: 35 },
]

// Element finden
const user = users.find((u) => u.age > 30)

// Prüfen, ob Array Wert enthält
;[1, 2, 3].includes(2) // true

// Array sortieren
const sorted = users.sort((a, b) => a.age - b.age)
```

### Objekterstellung & -manipulation

Mit Objekten und ihren Eigenschaften arbeiten.

```javascript
// Objektliteral
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

// Objektzuweisung
const newPerson = Object.assign({}, person, { age: 31 })
```

### Destrukturierungszuweisung

Werte aus Arrays und Objekten extrahieren.

```javascript
// Array-Destrukturierung
const [first, second, ...rest] = [1, 2, 3, 4, 5]
// first: 1, second: 2, rest: [3, 4, 5]

// Objekt-Destrukturierung
const { name, age } = person
const { name: userName, age: userAge = 18 } = person

// Funktionsparameter-Destrukturierung
function displayUser({ name, age }) {
  console.log(`${name} is ${age} years old`)
}
```

## DOM-Manipulation

### Elementauswahl: `querySelector()`, `getElementById()`

HTML-Elemente finden und auswählen.

```javascript
// Nach ID auswählen
const header = document.getElementById('main-header')

// Nach CSS-Selektor auswählen (erste Übereinstimmung)
const button = document.querySelector('.btn-primary')
const input = document.querySelector('input[type="email"]')

// Mehrere Elemente auswählen
const allButtons = document.querySelectorAll('.btn')
const listItems = document.querySelectorAll('li')

// NodeList in Array umwandeln
const buttonsArray = Array.from(allButtons)
```

<BaseQuiz id="javascript-dom-1" correct="C">
  <template #question>
    Was ist der Unterschied zwischen <code>querySelector()</code> und <code>querySelectorAll()</code>?
  </template>
  
  <BaseQuizOption value="A">Es gibt keinen Unterschied</BaseQuizOption>
  <BaseQuizOption value="B">querySelector ist schneller</BaseQuizOption>
  <BaseQuizOption value="C" correct>querySelector gibt das erste passende Element zurück, querySelectorAll gibt alle passenden Elemente zurück</BaseQuizOption>
  <BaseQuizOption value="D">querySelector funktioniert mit IDs, querySelectorAll funktioniert mit Klassen</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>querySelector()</code> gibt das erste Element zurück, das mit dem CSS-Selektor übereinstimmt, während <code>querySelectorAll()</code> eine NodeList zurückgibt, die alle übereinstimmenden Elemente enthält. Verwenden Sie <code>querySelector()</code>, wenn Sie ein Element benötigen, und <code>querySelectorAll()</code>, wenn Sie mehrere benötigen.
  </BaseQuizAnswer>
</BaseQuiz>

### Elementmodifikation

Textinhalt, Attribute und Stile ändern.

```javascript
// Textinhalt ändern
element.textContent = 'Neuer Text'
element.innerHTML = 'Fetter Text'

// Attribute ändern
element.setAttribute('data-id', '123')
element.removeAttribute('disabled')
const value = element.getAttribute('data-id')

// Klassen ändern
element.classList.add('active')
element.classList.remove('hidden')
element.classList.toggle('highlight')
```

### Elemente erstellen & einfügen

HTML-Elemente dynamisch erstellen und hinzufügen.

```javascript
// Neues Element erstellen
const div = document.createElement('div')
div.textContent = 'Hello World'
div.className = 'container'

// Elemente einfügen
const parent = document.querySelector('#container')
parent.appendChild(div)
parent.insertBefore(div, parent.firstChild)

// Moderne Einfügemethoden
parent.prepend(div) // Am Anfang einfügen
parent.append(div) // Am Ende einfügen
div.before(newElement) // Vor div einfügen
div.after(newElement) // Nach div einfügen
```

### Elemente stylen

CSS-Stile programmatisch anwenden.

```javascript
// Direkte Stiländerung
element.style.color = 'red'
element.style.backgroundColor = 'blue'
element.style.fontSize = '16px'

// Mehrere Stile festlegen
Object.assign(element.style, {
  width: '100px',
  height: '50px',
  border: '1px solid black',
})

// Berechnete Stile abrufen
const styles = window.getComputedStyle(element)
const color = styles.getPropertyValue('color')
```

## Ereignisbehandlung

### Hinzufügen von Event-Listenern

Auf Benutzerinteraktionen und Browserereignisse reagieren.

```javascript
// Basis-Event-Listener
button.addEventListener('click', function (event) {
  console.log('Button geklickt!')
})

// Event-Handler als Pfeilfunktion
button.addEventListener('click', (e) => {
  e.preventDefault() // Standardverhalten verhindern
  console.log('Geklickt:', e.target)
})

// Event-Listener mit Optionen
element.addEventListener('scroll', handler, {
  passive: true,
  once: true,
})
```

### Ereignistypen & -eigenschaften

Häufige Ereignisse und Eigenschaften des Ereignisobjekts.

```javascript
// Mausereignisse
element.addEventListener('click', handleClick)
element.addEventListener('mouseover', handleMouseOver)
element.addEventListener('mouseout', handleMouseOut)

// Tastaturereignisse
input.addEventListener('keydown', (e) => {
  console.log('Taste gedrückt:', e.key)
  if (e.key === 'Enter') {
    // Enter-Taste behandeln
  }
})

// Formularereignisse
form.addEventListener('submit', handleSubmit)
```

### Ereignisdelegation

Ereignisse für mehrere Elemente effizient behandeln.

```javascript
// Ereignisdelegation am Elternelement
document.querySelector('#list').addEventListener('click', (e) => {
  if (e.target.matches('.list-item')) {
    console.log('Listenpunkt geklickt:', e.target.textContent)
  }
})

// Event-Listener entfernen
function handleClick(e) {
  console.log('Geklickt')
}
button.addEventListener('click', handleClick)
button.removeEventListener('click', handleClick)
```

### Benutzerdefinierte Ereignisse

Benutzerdefinierte Ereignisse erstellen und auslösen.

```javascript
// Benutzerdefiniertes Ereignis erstellen
const customEvent = new CustomEvent('userLogin', {
  detail: { username: 'john', timestamp: Date.now() },
})

// Ereignis auslösen
element.dispatchEvent(customEvent)

// Auf benutzerdefiniertes Ereignis hören
element.addEventListener('userLogin', (e) => {
  console.log('Benutzer angemeldet:', e.detail.username)
})
```

## Asynchrone Programmierung

### Promises: `Promise`, `then()`, `catch()`

Mit asynchronen Operationen mithilfe von Promises arbeiten.

```javascript
// Ein Promise erstellen
const fetchData = new Promise((resolve, reject) => {
  setTimeout(() => {
    const success = true
    if (success) {
      resolve({ data: 'Hello World' })
    } else {
      reject(new Error('Fehler beim Abrufen'))
    }
  }, 1000)
})

// Promises verwenden
fetchData
  .then((result) => console.log(result.data))
  .catch((error) => console.error(error))
  .finally(() => console.log('Fertig'))
```

### Async/Await: `async`, `await`

Moderne Syntax zur Behandlung asynchronen Codes.

```javascript
// Async-Funktion
async function getData() {
  try {
    const response = await fetch('/api/data')
    const data = await response.json()
    return data
  } catch (error) {
    console.error('Fehler:', error)
    throw error
  }
}

// Async-Funktion verwenden
getData()
  .then((data) => console.log(data))
  .catch((error) => console.error(error))
```

### Fetch API: `fetch()`

HTTP-Anfragen an Server senden.

```javascript
// GET-Anfrage
fetch('/api/users')
  .then((response) => response.json())
  .then((users) => console.log(users))

// POST-Anfrage
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

### Promise-Dienstprogramme: `Promise.all()`, `Promise.race()`

Mehrere Promises gleichzeitig bearbeiten.

```javascript
// Warten, bis alle Promises aufgelöst sind
const promises = [fetch('/api/users'), fetch('/api/posts')]
Promise.all(promises)
  .then((responses) => Promise.all(responses.map((r) => r.json())))
  .then(([users, posts]) => {
    console.log('Benutzer:', users)
    console.log('Beiträge:', posts)
  })

// Race - das erste Promise, das aufgelöst wird, gewinnt
Promise.race(promises).then((firstResponse) => console.log('Erste Antwort'))
```

## ES6+ Moderne Funktionen

### Template-Literale & Spread-Operator

String-Interpolation und Array-/Objekt-Spreading.

```javascript
// Template-Literale
const name = 'Alice'
const age = 25
const message = `Hello, ${name}! You are ${age} years old.`

// Mehrzeilige Strings
const html = `
    <div>
        ${name}
        Age: ${age}
    </div>
`

// Spread-Operator
const arr1 = [1, 2, 3]
const arr2 = [4, 5, 6]
const combined = [...arr1, ...arr2] // [1,2,3,4,5,6]

const obj1 = { a: 1, b: 2 }
const obj2 = { ...obj1, c: 3 } // { a: 1, b: 2, c: 3 }
```

### Klassen & Module

Objektorientierte Programmierung und Modulsystem.

```javascript
// ES6 Klassen
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

// Vererbung
class Student extends Person {
  constructor(name, age, grade) {
    super(name, age)
    this.grade = grade
  }
}

// Modul-Exporte/Importe
export const helper = () => 'helper function'
export default Person

import Person, { helper } from './person.js'
```

## Fehlerbehandlung

### Try/Catch/Finally

Synchrone und asynchrone Fehler behandeln.

```javascript
// Grundlegende Fehlerbehandlung
try {
  const result = riskyOperation()
  console.log(result)
} catch (error) {
  console.error('Fehler aufgetreten:', error.message)
} finally {
  console.log('Aufräumcode läuft hier')
}

// Asynchrone Fehlerbehandlung
async function asyncOperation() {
  try {
    const data = await fetch('/api/data')
    const json = await data.json()
    return json
  } catch (error) {
    console.error('Asynchroner Fehler:', error)
    throw error // Erneut werfen, falls nötig
  }
}
```

### Benutzerdefinierte Fehler & Debugging

Benutzerdefinierte Fehlertypen erstellen und effektiv debuggen.

```javascript
// Benutzerdefinierte Fehlerklasse
class ValidationError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'ValidationError'
    this.field = field
  }
}

// Benutzerdefinierten Fehler auslösen
function validateEmail(email) {
  if (!email.includes('@')) {
    throw new ValidationError('Ungültiges E-Mail-Format', 'email')
  }
}

// Konsolen-Debugging-Methoden
console.log('Einfacher Log')
console.warn('Warnmeldung')
console.error('Fehlermeldung')
console.table([{ name: 'John', age: 30 }])
console.time('operation')
// ... etwas Code
console.timeEnd('operation')
```

## Local Storage & JSON

### LocalStorage API

Daten dauerhaft im Browser speichern.

```javascript
// Daten speichern
localStorage.setItem('username', 'john_doe')
localStorage.setItem(
  'settings',
  JSON.stringify({
    theme: 'dark',
    notifications: true,
  }),
)

// Daten abrufen
const username = localStorage.getItem('username')
const settings = JSON.parse(localStorage.getItem('settings'))

// Daten entfernen
localStorage.removeItem('username')
localStorage.clear() // Alle Elemente entfernen

// Prüfen, ob Schlüssel existiert
if (localStorage.getItem('username') !== null) {
  // Schlüssel existiert
}
```

### JSON-Operationen

JSON-Daten parsen und stringifizieren.

```javascript
// JavaScript-Objekt zu JSON-String
const user = { name: 'Alice', age: 25, active: true }
const jsonString = JSON.stringify(user)
// '{"name":"Alice","age":25,"active":true}'

// JSON-String zu JavaScript-Objekt
const jsonData = '{"name":"Bob","age":30}'
const userObj = JSON.parse(jsonData)

// JSON-Parsing-Fehler behandeln
try {
  const data = JSON.parse(invalidJson)
} catch (error) {
  console.error('Ungültiges JSON:', error.message)
}

// JSON mit benutzerdefiniertem Replacer/Reviver
const filtered = JSON.stringify(user, ['name', 'age'])
const parsed = JSON.parse(jsonString, (key, value) => {
  return key === 'age' ? value + 1 : value
})
```

## Reguläre Ausdrücke

### Muster erstellen & testen

Regex-Muster erstellen und gegen Zeichenketten testen.

```javascript
// Regex-Literal
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// RegExp-Konstruktor
const phoneRegex = new RegExp(r'\d{3}-\d{3}-\d{4}');

// Test-Methode
const isValidEmail = emailRegex.test('user@example.com'); // true

// Match-Methode
const text = 'Call me at 123-456-7890';
const phoneMatch = text.match(/\d{3}-\d{3}-\d{4}/);
console.log(phoneMatch[0]); // '123-456-7890'

// Globale Suche
const allNumbers = text.match(/\d+/g); // ['123', '456', '7890']
```

### String-Methoden mit Regex

Regex mit Methoden zur Zeichenkettenmanipulation verwenden.

```javascript
// Ersetzen mit Regex
const text = 'Hello World 123'
const cleaned = text.replace(/\d+/g, '') // 'Hello World '

// Aufteilen mit Regex
const parts = 'apple,banana;orange:grape'.split(/[,:;]/)
// ['apple', 'banana', 'orange', 'grape']

// Search-Methode
const position = text.search(/\d+/) // 12 (Position der ersten Ziffer)

// Häufige Muster
const patterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  phone: /^\d{3}-\d{3}-\d{4}$/,
  url: /^https?:\/\/.+/,
  digits: /\d+/g,
  whitespace: /\s+/g,
}
```

## JavaScript-Setup & Umgebung

### Browser-Konsole

Integrierte JavaScript-Umgebung in Webbrowsern.

```javascript
// Browser-Entwicklertools öffnen (F12)
// Zum Konsolen-Tab wechseln
console.log('Hello JavaScript!')

// Code direkt testen
let x = 5
let y = 10
console.log(x + y) // 15

// Skripte in HTML einbinden
```

### Node.js-Umgebung

JavaScript-Laufzeitumgebung für die serverseitige Entwicklung.

```bash
# Node.js von nodejs.org installieren
# Installation prüfen
node --version
npm --version

# JavaScript-Datei ausführen
node script.js

# npm-Projekt initialisieren
npm init -y

# Pakete installieren
npm install lodash
npm install --save-dev jest
```

### Moderne Entwicklungswerkzeuge

Wesentliche Werkzeuge für die JavaScript-Entwicklung.

```json
// Package.json Skript
{
  "scripts": {
    "start": "node index.js",
    "test": "jest",
    "build": "webpack"
  }
}
```

```bash
# ES6-Module im Browser
# Babel für Unterstützung älterer Browser
npm install --save-dev @babel/core @babel/preset-env
```

## Best Practices & Performance

### Performance-Optimierung

Techniken zur Verbesserung der JavaScript-Performance.

```javascript
// Debouncing für häufige Ereignisse
function debounce(func, delay) {
  let timeoutId
  return function (...args) {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func.apply(this, args), delay)
  }
}

// Debounced Funktion verwenden
const debouncedSearch = debounce(searchFunction, 300)
input.addEventListener('input', debouncedSearch)

// Effiziente DOM-Abfragen
const elements = document.querySelectorAll('.item')
// Länge cachen, um Neuberechnung zu vermeiden
for (let i = 0, len = elements.length; i < len; i++) {
  // elements[i] verarbeiten
}
```

### Code-Organisation & Standards

Code für Wartbarkeit und Lesbarkeit strukturieren.

```javascript
// Strikten Modus verwenden
'use strict'

// Einheitliche Namenskonventionen
const userName = 'john' // camelCase für Variablen
const API_URL = 'https://api.example.com' // GROSSBUCHSTABEN für Konstanten

// Funktionsdokumentation
/**
 * Berechnet die Fläche eines Rechtecks
 * @param {number} width - Die Breite des Rechtecks
 * @param {number} height - Die Höhe des Rechtecks
 * @returns {number} Die Fläche des Rechtecks
 */
function calculateArea(width, height) {
  return width * height
}

// Standardmäßig const verwenden, let bei Neuzuweisung
const config = { theme: 'dark' }
let counter = 0
```

## Testen von JavaScript-Code

### Unit-Tests mit Jest

Tests für JavaScript-Funktionen schreiben und ausführen.

```javascript
// Jest installieren: npm install --save-dev jest

// math.js
export function add(a, b) {
  return a + b
}

export function multiply(a, b) {
  return a * b
}

// math.test.js
import { add, multiply } from './math.js'

test('addiert 1 + 2 zu 3', () => {
  expect(add(1, 2)).toBe(3)
})

test('multipliziert 3 * 4 zu 12', () => {
  expect(multiply(3, 4)).toBe(12)
})

// Tests ausführen: npm test
```

### Browser-Tests & Debugging

JavaScript in den Entwicklertools des Browsers debuggen.

```javascript
// Breakpoints setzen
debugger // Pausiert die Ausführung in den Entwicklertools

// Konsolenmethoden zum Debuggen
console.log('Wert der Variablen:', variable)
console.assert(x > 0, 'x sollte positiv sein')
console.trace('Funktionsaufrufstapel')

// Performance-Messung
performance.mark('start')
// ... zu messender Code
performance.mark('end')
performance.measure('operation', 'start', 'end')

// Performance-Einträge prüfen
const measurements = performance.getEntriesByType('measure')
```

## Relevante Links

- <router-link to="/html">HTML Spickzettel</router-link>
- <router-link to="/css">CSS Spickzettel</router-link>
- <router-link to="/react">React Spickzettel</router-link>
- <router-link to="/web-development">Webentwicklung Spickzettel</router-link>

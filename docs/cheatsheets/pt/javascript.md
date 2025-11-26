---
title: 'Folha de Referência JavaScript'
description: 'Aprenda JavaScript com nossa folha de referência abrangente cobrindo comandos essenciais, conceitos e melhores práticas.'
pdfUrl: '/cheatsheets/pdf/javascript-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas de JavaScript
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/javascript">Aprenda JavaScript com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda programação JavaScript através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de JavaScript que cobrem sintaxe essencial, funções, manipulação de DOM, programação assíncrona e recursos modernos do ES6+. Domine JavaScript para fluxos de trabalho eficientes de desenvolvimento web e programação.
</base-disclaimer-content>
</base-disclaimer>

## Variáveis e Tipos de Dados

### Declarações de Variáveis: `let`, `const`, `var`

Declare variáveis com diferentes escopos e mutabilidade.

```javascript
// Escopo de bloco, mutável
let name = 'John'
let age = 25
age = 26 // Pode ser reatribuído

// Escopo de bloco, imutável
const PI = 3.14159
const user = { name: 'Alice' }
user.age = 30 // Propriedades do objeto podem ser modificadas

// Escopo de função (evitar em JS moderno)
var oldVariable = 'legacy'
```

### Tipos Primitivos

Tipos de dados básicos em JavaScript.

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

// Outros primitivos
let nothing = null
let notDefined = undefined
let unique = Symbol('id')
```

### Verificação de Tipo: `typeof`, `instanceof`

Determine o tipo de variáveis e valores.

```javascript
// Verificar tipos primitivos
typeof 42 // 'number'
typeof 'hello' // 'string'
typeof true // 'boolean'
typeof undefined // 'undefined'

// Verificar tipos de objeto
let arr = [1, 2, 3]
typeof arr // 'object'
arr instanceof Array // true

let date = new Date()
date instanceof Date // true
```

### Conversão de Tipo

Converter entre diferentes tipos de dados.

```javascript
// Conversão para String
String(42) // '42'
;(42).toString() // '42'

// Conversão para Number
Number('42') // 42
parseInt('42px') // 42
parseFloat('3.14') // 3.14

// Conversão para Boolean
Boolean(0) // false
Boolean('hello') // true
!!'text' // true (negação dupla)
```

## Funções

### Declarações de Função

Maneira tradicional de definir funções com _hoisting_.

```javascript
// Declaração de função (hoisted)
function greet(name) {
  return `Hello, ${name}!`
}

// Função com parâmetros padrão
function multiply(a, b = 1) {
  return a * b
}

// Parâmetros restantes (rest parameters)
function sum(...numbers) {
  return numbers.reduce((a, b) => a + b, 0)
}
```

### Expressões de Função e Funções de Seta (Arrow Functions)

Sintaxe de função moderna e funções anônimas.

```javascript
// Expressão de função
const add = function (a, b) {
  return a + b
}

// Função de seta (concisa)
const subtract = (a, b) => a - b

// Função de seta com corpo de bloco
const processData = (data) => {
  const processed = data.filter((x) => x > 0)
  return processed.map((x) => x * 2)
}
```

### Funções de Ordem Superior (Higher-Order Functions)

Funções que recebem ou retornam outras funções.

```javascript
// Função que retorna uma função
function createMultiplier(factor) {
  return function (number) {
    return number * factor
  }
}
const double = createMultiplier(2)

// Função como parâmetro
function applyOperation(arr, operation) {
  return arr.map(operation)
}
```

## Arrays e Objetos

### Métodos de Array: `map()`, `filter()`, `reduce()`

Transformar e manipular arrays funcionalmente.

```javascript
const numbers = [1, 2, 3, 4, 5]

// Transformar cada elemento
const doubled = numbers.map((x) => x * 2)
// [2, 4, 6, 8, 10]

// Filtrar elementos
const evens = numbers.filter((x) => x % 2 === 0)
// [2, 4]

// Reduzir para um único valor
const sum = numbers.reduce((acc, curr) => acc + curr, 0)
// 15

// Encadear métodos
const result = numbers
  .filter((x) => x > 2)
  .map((x) => x * 3)
  .reduce((a, b) => a + b, 0)
```

### Utilitários de Array: `find()`, `includes()`, `sort()`

Pesquisar, verificar e organizar elementos de array.

```javascript
const users = [
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 30 },
  { name: 'Charlie', age: 35 },
]

// Encontrar elemento
const user = users.find((u) => u.age > 30)

// Verificar se o array inclui valor
;[1, 2, 3].includes(2) // true

// Ordenar array
const sorted = users.sort((a, b) => a.age - b.age)
```

### Criação e Manipulação de Objetos

Trabalhar com objetos e suas propriedades.

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

// Atribuição de objeto
const newPerson = Object.assign({}, person, { age: 31 })
```

### Atribuição de Desestruturação (Destructuring Assignment)

Extrair valores de arrays e objetos.

```javascript
// Desestruturação de array
const [first, second, ...rest] = [1, 2, 3, 4, 5]
// first: 1, second: 2, rest: [3, 4, 5]

// Desestruturação de objeto
const { name, age } = person
const { name: userName, age: userAge = 18 } = person

// Desestruturação de parâmetro de função
function displayUser({ name, age }) {
  console.log(`${name} is ${age} years old`)
}
```

## Manipulação do DOM

### Seleção de Elementos: `querySelector()`, `getElementById()`

Encontrar e selecionar elementos HTML.

```javascript
// Selecionar por ID
const header = document.getElementById('main-header')

// Selecionar por seletor CSS (primeira correspondência)
const button = document.querySelector('.btn-primary')
const input = document.querySelector('input[type="email"]')

// Selecionar múltiplos elementos
const allButtons = document.querySelectorAll('.btn')
const listItems = document.querySelectorAll('li')

// Converter NodeList para Array
const buttonsArray = Array.from(allButtons)
```

### Modificação de Elementos

Alterar conteúdo, atributos e estilos.

```javascript
// Mudar conteúdo de texto
element.textContent = 'Novo texto'
element.innerHTML = 'Texto em negrito'

// Modificar atributos
element.setAttribute('data-id', '123')
element.removeAttribute('disabled')
const value = element.getAttribute('data-id')

// Mudar classes
element.classList.add('active')
element.classList.remove('hidden')
element.classList.toggle('highlight')
```

### Criação e Inserção de Elementos

Criar dinamicamente e adicionar elementos HTML.

```javascript
// Criar novo elemento
const div = document.createElement('div')
div.textContent = 'Hello World'
div.className = 'container'

// Inserir elementos
const parent = document.querySelector('#container')
parent.appendChild(div)
parent.insertBefore(div, parent.firstChild)

// Métodos de inserção modernos
parent.prepend(div) // Inserir no início
parent.append(div) // Inserir no final
div.before(newElement) // Inserir antes de div
div.after(newElement) // Inserir depois de div
```

### Estilização de Elementos

Aplicar estilos CSS programaticamente.

```javascript
// Modificação de estilo direta
element.style.color = 'red'
element.style.backgroundColor = 'blue'
element.style.fontSize = '16px'

// Definir múltiplos estilos
Object.assign(element.style, {
  width: '100px',
  height: '50px',
  border: '1px solid black',
})

// Obter estilos computados
const styles = window.getComputedStyle(element)
const color = styles.getPropertyValue('color')
```

## Manipulação de Eventos

### Adicionar Ouvintes de Eventos (Event Listeners)

Responder a interações do usuário e eventos do navegador.

```javascript
// Ouvinte de evento básico
button.addEventListener('click', function (event) {
  console.log('Botão clicado!')
})

// Manipulador de evento de função de seta
button.addEventListener('click', (e) => {
  e.preventDefault() // Prevenir comportamento padrão
  console.log('Clicado:', e.target)
})

// Ouvinte de evento com opções
element.addEventListener('scroll', handler, {
  passive: true,
  once: true,
})
```

### Tipos de Eventos e Propriedades

Eventos comuns e propriedades do objeto de evento.

```javascript
// Eventos de mouse
element.addEventListener('click', handleClick)
element.addEventListener('mouseover', handleMouseOver)
element.addEventListener('mouseout', handleMouseOut)

// Eventos de teclado
input.addEventListener('keydown', (e) => {
  console.log('Tecla pressionada:', e.key)
  if (e.key === 'Enter') {
    // Lidar com a tecla Enter
  }
})

// Eventos de formulário
form.addEventListener('submit', handleSubmit)
```

### Delegação de Eventos

Lidar com eventos em múltiplos elementos de forma eficiente.

```javascript
// Delegação de eventos no elemento pai
document.querySelector('#list').addEventListener('click', (e) => {
  if (e.target.matches('.list-item')) {
    console.log('Item da lista clicado:', e.target.textContent)
  }
})

// Removendo ouvintes de eventos
function handleClick(e) {
  console.log('Clicado')
}
button.addEventListener('click', handleClick)
button.removeEventListener('click', handleClick)
```

### Eventos Personalizados

Criar e despachar eventos personalizados.

```javascript
// Criar evento personalizado
const customEvent = new CustomEvent('userLogin', {
  detail: { username: 'john', timestamp: Date.now() },
})

// Despachar evento
element.dispatchEvent(customEvent)

// Escutar evento personalizado
element.addEventListener('userLogin', (e) => {
  console.log('Usuário logado:', e.detail.username)
})
```

## Programação Assíncrona

### Promises: `Promise`, `then()`, `catch()`

Trabalhar com operações assíncronas usando promises.

```javascript
// Criando uma promise
const fetchData = new Promise((resolve, reject) => {
  setTimeout(() => {
    const success = true
    if (success) {
      resolve({ data: 'Hello World' })
    } else {
      reject(new Error('Falha ao buscar'))
    }
  }, 1000)
})

// Usando promises
fetchData
  .then((result) => console.log(result.data))
  .catch((error) => console.error(error))
  .finally(() => console.log('Concluído'))
```

### Async/Await: `async`, `await`

Sintaxe moderna para lidar com código assíncrono.

```javascript
// Função async
async function getData() {
  try {
    const response = await fetch('/api/data')
    const data = await response.json()
    return data
  } catch (error) {
    console.error('Erro:', error)
    throw error
  }
}

// Usando função async
getData()
  .then((data) => console.log(data))
  .catch((error) => console.error(error))
```

### API Fetch: `fetch()`

Fazer requisições HTTP para servidores.

```javascript
// Requisição GET
fetch('/api/users')
  .then((response) => response.json())
  .then((users) => console.log(users))

// Requisição POST
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

### Utilitários de Promise: `Promise.all()`, `Promise.race()`

Trabalhar com múltiplas promises simultaneamente.

```javascript
// Esperar todas as promises resolverem
const promises = [fetch('/api/users'), fetch('/api/posts')]
Promise.all(promises)
  .then((responses) => Promise.all(responses.map((r) => r.json())))
  .then(([users, posts]) => {
    console.log('Usuários:', users)
    console.log('Posts:', posts)
  })

// Race - a primeira promise a resolver vence
Promise.race(promises).then((firstResponse) => console.log('Primeira resposta'))
```

## Recursos Modernos ES6+

### Template Literals e Spread Operator

Interpolação de strings e espalhamento de array/objeto.

```javascript
// Template literals
const name = 'Alice'
const age = 25
const message = `Hello, ${name}! You are ${age} years old.`

// Strings de múltiplas linhas
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

### Classes e Módulos

Programação orientada a objetos e sistema de módulos.

```javascript
// Classes ES6
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

// Herança
class Student extends Person {
  constructor(name, age, grade) {
    super(name, age)
    this.grade = grade
  }
}

// Exportações/Importações de Módulo
export const helper = () => 'helper function'
export default Person

import Person, { helper } from './person.js'
```

## Tratamento de Erros

### Try/Catch/Finally

Lidar com erros síncronos e assíncronos.

```javascript
// Tratamento básico de erro
try {
  const result = riskyOperation()
  console.log(result)
} catch (error) {
  console.error('Ocorreu um erro:', error.message)
} finally {
  console.log('O código de limpeza é executado aqui')
}

// Tratamento de erro assíncrono
async function asyncOperation() {
  try {
    const data = await fetch('/api/data')
    const json = await data.json()
    return json
  } catch (error) {
    console.error('Erro assíncrono:', error)
    throw error // Re-lançar se necessário
  }
}
```

### Erros Personalizados e Depuração

Criar tipos de erro personalizados e depurar de forma eficaz.

```javascript
// Classe de erro personalizada
class ValidationError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'ValidationError'
    this.field = field
  }
}

// Lançar erro personalizado
function validateEmail(email) {
  if (!email.includes('@')) {
    throw new ValidationError('Formato de e-mail inválido', 'email')
  }
}

// Métodos de depuração do console
console.log('Log básico')
console.warn('Mensagem de aviso')
console.error('Mensagem de erro')
console.table([{ name: 'John', age: 30 }])
console.time('operation')
// ... algum código
console.timeEnd('operation')
```

## Local Storage e JSON

### API LocalStorage

Armazenar dados persistentemente no navegador.

```javascript
// Armazenar dados
localStorage.setItem('username', 'john_doe')
localStorage.setItem(
  'settings',
  JSON.stringify({
    theme: 'dark',
    notifications: true,
  }),
)

// Recuperar dados
const username = localStorage.getItem('username')
const settings = JSON.parse(localStorage.getItem('settings'))

// Remover dados
localStorage.removeItem('username')
localStorage.clear() // Remover todos os itens

// Verificar se a chave existe
if (localStorage.getItem('username') !== null) {
  // A chave existe
}
```

### Operações JSON

Analisar (parse) e serializar (stringify) dados JSON.

```javascript
// Objeto JavaScript para string JSON
const user = { name: 'Alice', age: 25, active: true }
const jsonString = JSON.stringify(user)
// '{"name":"Alice","age":25,"active":true}'

// String JSON para objeto JavaScript
const jsonData = '{"name":"Bob","age":30}'
const userObj = JSON.parse(jsonData)

// Lidar com erros de análise JSON
try {
  const data = JSON.parse(invalidJson)
} catch (error) {
  console.error('JSON Inválido:', error.message)
}

// JSON com replacer/reviver personalizado
const filtered = JSON.stringify(user, ['name', 'age'])
const parsed = JSON.parse(jsonString, (key, value) => {
  return key === 'age' ? value + 1 : value
})
```

## Expressões Regulares

### Criação e Teste de Padrões

Criar padrões regex e testá-los contra strings.

```javascript
// Literal de Regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Construtor RegExp
const phoneRegex = new RegExp(r'\d{3}-\d{3}-\d{4}');

// Método test
const isValidEmail = emailRegex.test('user@example.com'); // true

// Método match
const text = 'Call me at 123-456-7890';
const phoneMatch = text.match(/\d{3}-\d{3}-\d{4}/);
console.log(phoneMatch[0]); // '123-456-7890'

// Busca global
const allNumbers = text.match(/\d+/g); // ['123', '456', '7890']
```

### Métodos de String com Regex

Usar regex com métodos de manipulação de string.

```javascript
// Substituir com regex
const text = 'Hello World 123'
const cleaned = text.replace(/\d+/g, '') // 'Hello World '

// Dividir com regex
const parts = 'apple,banana;orange:grape'.split(/[,:;]/)
// ['apple', 'banana', 'orange', 'grape']

// Método search
const position = text.search(/\d+/) // 12 (posição do primeiro dígito)

// Padrões comuns
const patterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  phone: /^\d{3}-\d{3}-\d{4}$/,
  url: /^https?:\/\/.+/,
  digits: /\d+/g,
  whitespace: /\s+/g,
}
```

## Configuração e Ambiente JavaScript

### Console do Navegador

Ambiente JavaScript embutido em navegadores web.

```javascript
// Abrir ferramentas de desenvolvedor do navegador (F12)
// Ir para a aba Console
console.log('Hello JavaScript!')

// Testar código diretamente
let x = 5
let y = 10
console.log(x + y) // 15

// Incluir scripts no HTML
```

### Ambiente Node.js

Runtime JavaScript para desenvolvimento server-side.

```bash
# Instalar Node.js em nodejs.org
# Verificar instalação
node --version
npm --version

# Executar arquivo JavaScript
node script.js

# Inicializar projeto npm
npm init -y

# Instalar pacotes
npm install lodash
npm install --save-dev jest
```

### Ferramentas de Desenvolvimento Modernas

Ferramentas essenciais para desenvolvimento JavaScript.

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
# Módulos ES6 no navegador
# Babel para suporte a navegadores mais antigos
npm install --save-dev @babel/core @babel/preset-env
```

## Melhores Práticas e Desempenho

### Otimização de Desempenho

Técnicas para melhorar o desempenho do JavaScript.

```javascript
// Debouncing para eventos frequentes
function debounce(func, delay) {
  let timeoutId
  return function (...args) {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func.apply(this, args), delay)
  }
}

// Usar função debounced
const debouncedSearch = debounce(searchFunction, 300)
input.addEventListener('input', debouncedSearch)

// Consultas DOM eficientes
const elements = document.querySelectorAll('.item')
// Armazenar o comprimento para evitar recálculo
for (let i = 0, len = elements.length; i < len; i++) {
  // Processar elements[i]
}
```

### Organização e Padrões de Código

Estruturar o código para manutenibilidade e legibilidade.

```javascript
// Usar modo estrito
'use strict'

// Convenções de nomenclatura consistentes
const userName = 'john' // camelCase para variáveis
const API_URL = 'https://api.example.com' // CAPS para constantes

// Documentação de função
/**
 * Calcula a área de um retângulo
 * @param {number} width - A largura do retângulo
 * @param {number} height - A altura do retângulo
 * @returns {number} A área do retângulo
 */
function calculateArea(width, height) {
  return width * height
}

// Usar const por padrão, let quando a reatribuição for necessária
const config = { theme: 'dark' }
let counter = 0
```

## Testando Código JavaScript

### Teste Unitário com Jest

Escrever e executar testes para funções JavaScript.

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

// Executar testes: npm test
```

### Teste de Navegador e Depuração

Depurar JavaScript nas ferramentas de desenvolvedor do navegador.

```javascript
// Definir breakpoints
debugger // Pausa a execução nas ferramentas de desenvolvimento

// Métodos de console para depuração
console.log('Valor da variável:', variable)
console.assert(x > 0, 'x deve ser positivo')
console.trace('Pilha de chamadas de função')

// Cronometragem de desempenho
performance.mark('start')
// ... código para medir
performance.mark('end')
performance.measure('operation', 'start', 'end')

// Verificar entradas de desempenho
const measurements = performance.getEntriesByType('measure')
```

## Links Relevantes

- <router-link to="/html">Folha de Dicas de HTML</router-link>
- <router-link to="/css">Folha de Dicas de CSS</router-link>
- <router-link to="/react">Folha de Dicas de React</router-link>
- <router-link to="/web-development">Folha de Dicas de Desenvolvimento Web</router-link>

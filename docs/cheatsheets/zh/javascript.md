---
title: 'JavaScript 速查表'
description: '使用我们涵盖核心命令、概念和最佳实践的综合速查表，快速掌握 JavaScript。'
pdfUrl: '/cheatsheets/pdf/javascript-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
JavaScript 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/javascript">通过实践实验室学习 JavaScript</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 JavaScript 编程。LabEx 提供全面的 JavaScript 课程，涵盖基本语法、函数、DOM 操作、异步编程和现代 ES6+ 特性。掌握 JavaScript，实现高效的 Web 开发和编程工作流程。
</base-disclaimer-content>
</base-disclaimer>

## 变量和数据类型

### 变量声明：`let`, `const`, `var`

使用不同作用域和可变性的方式声明变量。

```javascript
// 块级作用域，可变
let name = 'John'
let age = 25
age = 26 // 可以重新赋值

// 块级作用域，不可变
const PI = 3.14159
const user = { name: 'Alice' }
user.age = 30 // 对象属性可以修改

// 函数作用域（现代 JavaScript 中应避免使用）
var oldVariable = 'legacy'
```

### 原始类型 (Primitive Types)

JavaScript 中的基本数据类型。

```javascript
// 字符串 (String)
let message = 'Hello World'
let template = `Welcome ${name}`

// 数字 (Number)
let integer = 42
let float = 3.14
let scientific = 2e5 // 200000

// 布尔值 (Boolean)
let isActive = true
let isComplete = false

// 其他原始类型
let nothing = null
let notDefined = undefined
let unique = Symbol('id')
```

### 类型检查：`typeof`, `instanceof`

确定变量和值的数据类型。

```javascript
// 检查原始类型
typeof 42 // 'number'
typeof 'hello' // 'string'
typeof true // 'boolean'
typeof undefined // 'undefined'

// 检查对象类型
let arr = [1, 2, 3]
typeof arr // 'object'
arr instanceof Array // true

let date = new Date()
date instanceof Date // true
```

### 类型转换 (Type Conversion)

在不同数据类型之间进行转换。

```javascript
// 字符串转换
String(42) // '42'
;(42).toString() // '42'

// 数字转换
Number('42') // 42
parseInt('42px') // 42
parseFloat('3.14') // 3.14

// 布尔值转换
Boolean(0) // false
Boolean('hello') // true
!!'text' // true (双重否定)
```

## 函数 (Functions)

### 函数声明 (Function Declarations)

定义函数的方式，具有变量提升 (hoisting) 特性。

```javascript
// 函数声明（已提升）
function greet(name) {
  return `Hello, ${name}!`
}

// 带有默认参数的函数
function multiply(a, b = 1) {
  return a * b
}

// 剩余参数 (Rest parameters)
function sum(...numbers) {
  return numbers.reduce((a, b) => a + b, 0)
}
```

### 函数表达式和箭头函数 (Function Expressions & Arrow Functions)

现代函数语法和匿名函数。

```javascript
// 函数表达式
const add = function (a, b) {
  return a + b
}

// 箭头函数（简洁）
const subtract = (a, b) => a - b

// 箭头函数带块体
const processData = (data) => {
  const processed = data.filter((x) => x > 0)
  return processed.map((x) => x * 2)
}
```

### 高阶函数 (Higher-Order Functions)

接受其他函数作为参数或返回其他函数的函数。

```javascript
// 返回一个函数的函数
function createMultiplier(factor) {
  return function (number) {
    return number * factor
  }
}
const double = createMultiplier(2)

// 作为参数的函数
function applyOperation(arr, operation) {
  return arr.map(operation)
}
```

## 数组和对象 (Arrays & Objects)

### 数组方法：`map()`, `filter()`, `reduce()`

函数式地转换和操作数组。

```javascript
const numbers = [1, 2, 3, 4, 5]

// 转换每个元素
const doubled = numbers.map((x) => x * 2)
// [2, 4, 6, 8, 10]

// 过滤元素
const evens = numbers.filter((x) => x % 2 === 0)
// [2, 4]

// 归约为单个值
const sum = numbers.reduce((acc, curr) => acc + curr, 0)
// 15

// 方法链式调用
const result = numbers
  .filter((x) => x > 2)
  .map((x) => x * 3)
  .reduce((a, b) => a + b, 0)
```

### 数组工具：`find()`, `includes()`, `sort()`

搜索、检查和组织数组元素。

```javascript
const users = [
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 30 },
  { name: 'Charlie', age: 35 },
]

// 查找元素
const user = users.find((u) => u.age > 30)

// 检查数组是否包含某个值
;[1, 2, 3].includes(2) // true

// 排序数组
const sorted = users.sort((a, b) => a.age - b.age)
```

### 对象创建和操作 (Object Creation & Manipulation)

处理对象及其属性。

```javascript
// 对象字面量
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

// 对象赋值
const newPerson = Object.assign({}, person, { age: 31 })
```

### 解构赋值 (Destructuring Assignment)

从数组和对象中提取值。

```javascript
// 数组解构
const [first, second, ...rest] = [1, 2, 3, 4, 5]
// first: 1, second: 2, rest: [3, 4, 5]

// 对象解构
const { name, age } = person
const { name: userName, age: userAge = 18 } = person

// 函数参数解构
function displayUser({ name, age }) {
  console.log(`${name} is ${age} years old`)
}
```

## DOM 操作 (DOM Manipulation)

### 元素选择：`querySelector()`, `getElementById()`

查找和选择 HTML 元素。

```javascript
// 按 ID 选择
const header = document.getElementById('main-header')

// 按 CSS 选择器选择（第一个匹配项）
const button = document.querySelector('.btn-primary')
const input = document.querySelector('input[type="email"]')

// 选择多个元素
const allButtons = document.querySelectorAll('.btn')
const listItems = document.querySelectorAll('li')

// 将 NodeList 转换为 Array
const buttonsArray = Array.from(allButtons)
```

### 元素修改 (Element Modification)

更改内容、属性和样式。

```javascript
// 更改文本内容
element.textContent = '新文本'
element.innerHTML = '粗体文本'

// 修改属性
element.setAttribute('data-id', '123')
element.removeAttribute('disabled')
const value = element.getAttribute('data-id')

// 更改类名
element.classList.add('active')
element.classList.remove('hidden')
element.classList.toggle('highlight')
```

### 创建和插入元素 (Creating & Inserting Elements)

动态创建和添加 HTML 元素。

```javascript
// 创建新元素
const div = document.createElement('div')
div.textContent = 'Hello World'
div.className = 'container'

// 插入元素
const parent = document.querySelector('#container')
parent.appendChild(div)
parent.insertBefore(div, parent.firstChild)

// 现代插入方法
parent.prepend(div) // 在开头插入
parent.append(div) // 在末尾插入
div.before(newElement) // 在 div 之前插入
div.after(newElement) // 在 div 之后插入
```

### 样式化元素 (Styling Elements)

以编程方式应用 CSS 样式。

```javascript
// 直接修改样式
element.style.color = 'red'
element.style.backgroundColor = 'blue'
element.style.fontSize = '16px'

// 设置多个样式
Object.assign(element.style, {
  width: '100px',
  height: '50px',
  border: '1px solid black',
})

// 获取计算后的样式
const styles = window.getComputedStyle(element)
const color = styles.getPropertyValue('color')
```

## 事件处理 (Event Handling)

### 添加事件监听器 (Adding Event Listeners)

响应用户交互和浏览器事件。

```javascript
// 基本事件监听器
button.addEventListener('click', function (event) {
  console.log('按钮被点击了！')
})

// 箭头函数事件处理程序
button.addEventListener('click', (e) => {
  e.preventDefault() // 阻止默认行为
  console.log('点击：', e.target)
})

// 带选项的事件监听器
element.addEventListener('scroll', handler, {
  passive: true,
  once: true,
})
```

### 事件类型和属性 (Event Types & Properties)

常见事件和事件对象属性。

```javascript
// 鼠标事件
element.addEventListener('click', handleClick)
element.addEventListener('mouseover', handleMouseOver)
element.addEventListener('mouseout', handleMouseOut)

// 键盘事件
input.addEventListener('keydown', (e) => {
  console.log('按下的键：', e.key)
  if (e.key === 'Enter') {
    // 处理回车键
  }
})

// 表单事件
form.addEventListener('submit', handleSubmit)
```

### 事件委托 (Event Delegation)

高效地处理多个元素的事件。

```javascript
// 在父元素上进行事件委托
document.querySelector('#list').addEventListener('click', (e) => {
  if (e.target.matches('.list-item')) {
    console.log('列表项被点击：', e.target.textContent)
  }
})

// 移除事件监听器
function handleClick(e) {
  console.log('被点击')
}
button.addEventListener('click', handleClick)
button.removeEventListener('click', handleClick)
```

### 自定义事件 (Custom Events)

创建和派发自定义事件。

```javascript
// 创建自定义事件
const customEvent = new CustomEvent('userLogin', {
  detail: { username: 'john', timestamp: Date.now() },
})

// 派发事件
element.dispatchEvent(customEvent)

// 监听自定义事件
element.addEventListener('userLogin', (e) => {
  console.log('用户登录：', e.detail.username)
})
```

## 异步编程 (Asynchronous Programming)

### Promises: `Promise`, `then()`, `catch()`

使用 Promise 处理异步操作。

```javascript
// 创建一个 Promise
const fetchData = new Promise((resolve, reject) => {
  setTimeout(() => {
    const success = true
    if (success) {
      resolve({ data: 'Hello World' })
    } else {
      reject(new Error('获取失败'))
    }
  }, 1000)
})

// 使用 Promise
fetchData
  .then((result) => console.log(result.data))
  .catch((error) => console.error(error))
  .finally(() => console.log('完成'))
```

### Async/Await: `async`, `await`

处理异步代码的现代语法。

```javascript
// Async 函数
async function getData() {
  try {
    const response = await fetch('/api/data')
    const data = await response.json()
    return data
  } catch (error) {
    console.error('错误：', error)
    throw error
  }
}

// 使用 async 函数
getData()
  .then((data) => console.log(data))
  .catch((error) => console.error(error))
```

### Fetch API: `fetch()`

向服务器发起 HTTP 请求。

```javascript
// GET 请求
fetch('/api/users')
  .then((response) => response.json())
  .then((users) => console.log(users))

// POST 请求
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

### Promise 工具：`Promise.all()`, `Promise.race()`

同时处理多个 Promise。

```javascript
// 等待所有 Promise 解析完成
const promises = [fetch('/api/users'), fetch('/api/posts')]
Promise.all(promises)
  .then((responses) => Promise.all(responses.map((r) => r.json())))
  .then(([users, posts]) => {
    console.log('用户：', users)
    console.log('帖子：', posts)
  })

// Race - 第一个解析的 Promise 获胜
Promise.race(promises).then((firstResponse) => console.log('第一个响应'))
```

## ES6+ 现代特性 (Modern Features)

### 模板字面量和展开运算符 (Template Literals & Spread Operator)

字符串插值和数组/对象的展开。

```javascript
// 模板字面量
const name = 'Alice'
const age = 25
const message = `Hello, ${name}! You are ${age} years old.`

// 多行字符串
const html = `
    <div>
        ${name}
        Age: ${age}
    </div>
`

// 展开运算符
const arr1 = [1, 2, 3]
const arr2 = [4, 5, 6]
const combined = [...arr1, ...arr2] // [1,2,3,4,5,6]

const obj1 = { a: 1, b: 2 }
const obj2 = { ...obj1, c: 3 } // { a: 1, b: 2, c: 3 }
```

### 类和模块 (Classes & Modules)

面向对象编程和模块系统。

```javascript
// ES6 类
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

// 继承
class Student extends Person {
  constructor(name, age, grade) {
    super(name, age)
    this.grade = grade
  }
}

// 模块导出/导入
export const helper = () => 'helper function'
export default Person

import Person, { helper } from './person.js'
```

## 错误处理 (Error Handling)

### Try/Catch/Finally

处理同步和异步错误。

```javascript
// 基本错误处理
try {
  const result = riskyOperation()
  console.log(result)
} catch (error) {
  console.error('发生错误：', error.message)
} finally {
  console.log('清理代码在此处运行')
}

// 异步错误处理
async function asyncOperation() {
  try {
    const data = await fetch('/api/data')
    const json = await data.json()
    return json
  } catch (error) {
    console.error('异步错误：', error)
    throw error // 如果需要，重新抛出
  }
}
```

### 自定义错误和调试 (Custom Errors & Debugging)

创建自定义错误类型并有效调试。

```javascript
// 自定义错误类
class ValidationError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'ValidationError'
    this.field = field
  }
}

// 抛出自定义错误
function validateEmail(email) {
  if (!email.includes('@')) {
    throw new ValidationError('无效的电子邮件格式', 'email')
  }
}

// Console 调试方法
console.log('基本日志')
console.warn('警告信息')
console.error('错误信息')
console.table([{ name: 'John', age: 30 }])
console.time('operation')
// ... 一些代码
console.timeEnd('operation')
```

## 本地存储和 JSON (Local Storage & JSON)

### LocalStorage API

在浏览器中持久存储数据。

```javascript
// 存储数据
localStorage.setItem('username', 'john_doe')
localStorage.setItem(
  'settings',
  JSON.stringify({
    theme: 'dark',
    notifications: true,
  }),
)

// 检索数据
const username = localStorage.getItem('username')
const settings = JSON.parse(localStorage.getItem('settings'))

// 移除数据
localStorage.removeItem('username')
localStorage.clear() // 移除所有项

// 检查键是否存在
if (localStorage.getItem('username') !== null) {
  // 键存在
}
```

### JSON 操作 (JSON Operations)

解析和字符串化 JSON 数据。

```javascript
// JavaScript 对象转 JSON 字符串
const user = { name: 'Alice', age: 25, active: true }
const jsonString = JSON.stringify(user)
// '{"name":"Alice","age":25,"active":true}'

// JSON 字符串转 JavaScript 对象
const jsonData = '{"name":"Bob","age":30}'
const userObj = JSON.parse(jsonData)

// 处理 JSON 解析错误
try {
  const data = JSON.parse(invalidJson)
} catch (error) {
  console.error('无效的 JSON:', error.message)
}

// 使用自定义 replacer/reviver 的 JSON
const filtered = JSON.stringify(user, ['name', 'age'])
const parsed = JSON.parse(jsonString, (key, value) => {
  return key === 'age' ? value + 1 : value
})
```

## 正则表达式 (Regular Expressions)

### 创建和测试模式 (Creating & Testing Patterns)

创建正则表达式模式并测试字符串。

```javascript
// Regex 字面量
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// RegExp 构造函数
const phoneRegex = new RegExp(r'\d{3}-\d{3}-\d{4}');

// Test 方法
const isValidEmail = emailRegex.test('user@example.com'); // true

// Match 方法
const text = 'Call me at 123-456-7890';
const phoneMatch = text.match(/\d{3}-\d{3}-\d{4}/);
console.log(phoneMatch[0]); // '123-456-7890'

// 全局搜索
const allNumbers = text.match(/\d+/g); // ['123', '456', '7890']
```

### 带正则表达式的字符串方法 (String Methods with Regex)

将正则表达式与字符串操作方法结合使用。

```javascript
// 用正则表达式替换
const text = 'Hello World 123'
const cleaned = text.replace(/\d+/g, '') // 'Hello World '

// 用正则表达式分割
const parts = 'apple,banana;orange:grape'.split(/[,:;]/)
// ['apple', 'banana', 'orange', 'grape']

// Search 方法
const position = text.search(/\d+/) // 12 (第一个数字的位置)

// 常见模式
const patterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  phone: /^\d{3}-\d{3}-\d{4}$/,
  url: /^https?:\/\/.+/,
  digits: /\d+/g,
  whitespace: /\s+/g,
}
```

## JavaScript 设置和环境 (Setup & Environment)

### 浏览器控制台 (Browser Console)

Web 浏览器中内置的 JavaScript 环境。

```javascript
// 打开浏览器开发者工具 (F12)
// 转到 Console 标签页
console.log('Hello JavaScript!')

// 直接测试代码
let x = 5
let y = 10
console.log(x + y) // 15

// 在 HTML 中包含脚本
```

### Node.js 环境 (Node.js Environment)

用于服务器端开发的 JavaScript 运行时。

```bash
# 从 nodejs.org 安装 Node.js
# 检查安装情况
node --version
npm --version

# 运行 JavaScript 文件
node script.js

# 初始化 npm 项目
npm init -y

# 安装包
npm install lodash
npm install --save-dev jest
```

### 现代开发工具 (Modern Development Tools)

JavaScript 开发的基本工具。

```json
// package.json 脚本
{
  "scripts": {
    "start": "node index.js",
    "test": "jest",
    "build": "webpack"
  }
}
```

```bash
# 浏览器中的 ES6 模块
# Babel 用于旧版浏览器支持
npm install --save-dev @babel/core @babel/preset-env
```

## 最佳实践和性能 (Best Practices & Performance)

### 性能优化 (Performance Optimization)

提高 JavaScript 性能的技术。

```javascript
// 节流 (Debouncing) 适用于频繁事件
function debounce(func, delay) {
  let timeoutId
  return function (...args) {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func.apply(this, args), delay)
  }
}

// 使用节流函数
const debouncedSearch = debounce(searchFunction, 300)
input.addEventListener('input', debouncedSearch)

// 高效的 DOM 查询
const elements = document.querySelectorAll('.item')
// 缓存长度以避免重复计算
for (let i = 0, len = elements.length; i < len; i++) {
  // 处理 elements[i]
}
```

### 代码组织和标准 (Code Organization & Standards)

为可维护性和可读性组织代码。

```javascript
// 使用严格模式
'use strict'

// 一致的命名约定
const userName = 'john' // 变量使用 camelCase
const API_URL = 'https://api.example.com' // 常量使用 CAPS

// 函数文档
/**
 * 计算矩形的面积
 * @param {number} width - 矩形的宽度
 * @param {number} height - 矩形的高度
 * @returns {number} 矩形的面积
 */
function calculateArea(width, height) {
  return width * height
}

// 默认使用 const，需要重新赋值时使用 let
const config = { theme: 'dark' }
let counter = 0
```

## 测试 JavaScript 代码 (Testing JavaScript Code)

### 使用 Jest 进行单元测试 (Unit Testing with Jest)

编写和运行 JavaScript 函数的测试。

```javascript
// 安装 Jest: npm install --save-dev jest

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

// 运行测试：npm test
```

### 浏览器测试和调试 (Browser Testing & Debugging)

在浏览器开发者工具中调试 JavaScript。

```javascript
// 设置断点
debugger // 在开发者工具中暂停执行

// Console 调试方法
console.log('变量值：', variable)
console.assert(x > 0, 'x 应该是正数')
console.trace('函数调用堆栈')

// 性能计时
performance.mark('start')
// ... 要测量的代码
performance.mark('end')
performance.measure('operation', 'start', 'end')

// 检查性能条目
const measurements = performance.getEntriesByType('measure')
```

## 相关链接 (Relevant Links)

- <router-link to="/html">HTML 速查表</router-link>
- <router-link to="/css">CSS 速查表</router-link>
- <router-link to="/react">React 速查表</router-link>
- <router-link to="/web-development">Web 开发速查表</router-link>

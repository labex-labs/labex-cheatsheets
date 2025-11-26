---
title: 'Web 開発チートシート'
description: '必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートで Web 開発を習得しましょう。'
pdfUrl: '/cheatsheets/pdf/web-development-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Web 開発チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/web-development">Learn Web Development with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと現実世界のシナリオを通じてウェブ開発を学びましょう。LabEx は、不可欠な HTML、CSS、JavaScript、DOM 操作、レスポンシブデザインを網羅した包括的なウェブ開発コースを提供します。最新のウェブ開発ワークフローのために、インタラクティブでレスポンシブなウェブサイトの構築を習得します。
</base-disclaimer-content>
</base-disclaimer>

## HTML の基礎とドキュメント構造

### 基本的な HTML 構造：`<!DOCTYPE html>`

すべての Web ページの基盤を作成します。

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

### セマンティック要素：`<header>` / `<main>` / `<footer>`

より良い構造のために、意味のある HTML5 セマンティック要素を使用します。

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

### テキスト要素：`<h1>` から `<h6>` / `<p>`

適切な見出し階層と段落でコンテンツを構成します。

```html
<h1>Main Title</h1>
<h2>Section Heading</h2>
<h3>Subsection</h3>
<p>
  This is a paragraph with <strong>bold text</strong> and <em>italic text</em>.
</p>
<p>Another paragraph with a <a href="https://example.com">link</a>.</p>
```

### リスト：`<ul>` / `<ol>` / `<li>`

情報の整理されたリストを作成します。

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

### 画像とメディア：`<img>` / `<video>` / `<audio>`

適切な属性を使用してマルチメディアコンテンツを埋め込みます。

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

### テーブル：`<table>` / `<tr>` / `<td>`

適切な構造で表形式のデータを表示します。

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

## フォームとユーザー入力

### フォームの構造：`<form>`

ユーザー入力コントロールのコンテナを作成します。

```html
<form action="/submit" method="POST">
  <label for="name">Name:</label>
  <input type="text" id="name" name="name" required />

  <label for="email">Email:</label>
  <input type="email" id="email" name="email" required />

  <button type="submit">Submit</button>
</form>
```

### 入力タイプ：`type="text"` / `type="email"`

さまざまなデータに対して適切な入力タイプを使用します。

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

### フォームコントロール：`<select>` / `<textarea>`

ユーザーが情報を入力するためのさまざまな方法を提供します。

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

## CSS の基礎とスタイリング

### CSS セレクタ：`element` / `.class` / `#id`

異なるセレクタタイプを使用して HTML 要素をターゲットにします。

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

### ボックスモデル：`margin` / `padding` / `border`

CSS ボックスモデルを使用して、間隔とレイアウトを制御します。

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

### Flexbox: `display: flex`

簡単に柔軟でレスポンシブなレイアウトを作成します。

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

### Grid レイアウト：`display: grid`

複雑な 2 次元レイアウトを作成します。

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

## JavaScript の基本とプログラミングの基礎

### 変数：`let` / `const` / `var`

異なる変数宣言を使用してデータを格納および操作します。

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

### 関数：`function` / Arrow Functions

さまざまな関数構文を使用して、再利用可能なコードブロックを作成します。

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

### 条件ロジック：`if` / `else` / `switch`

条件文を使用してプログラムフローを制御します。

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

### ループ：`for` / `while` / Array Methods

データを反復処理し、操作を繰り返します。

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

## DOM 操作とイベント

### 要素の選択：`querySelector` / `getElementById`

JavaScript で HTML 要素を見つけてアクセスします。

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

### コンテンツの変更：`innerHTML` / `textContent`

HTML 要素の内容と属性を変更します。

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

### イベント処理：`addEventListener`

ユーザーの操作やブラウザイベントに応答します。

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

### 要素の作成：`createElement` / `appendChild`

新しい HTML 要素を動的に作成し、追加します。

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

## レスポンシブデザインと CSS メディアクエリ

### ビューポートメタタグ：`viewport`

レスポンシブデザインのために適切なビューポートを設定します。

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

### メディアクエリ：`@media`

画面サイズやデバイス機能に基づいて異なるスタイルを適用します。

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

### 柔軟な単位：`rem` / `em` / `%` / `vw` / `vh`

スケーラブルでレスポンシブなデザインのために相対的な単位を使用します。

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

### レスポンシブタイポグラフィ：`clamp()`

画面サイズに合わせてスケーリングする流動的なタイポグラフィを作成します。

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

## デバッグとブラウザ開発者ツール

### コンソールメソッド：`console.log()` / `console.error()`

コンソール出力でコードをデバッグおよび監視します。

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

### デバッグ技術：`debugger` / Breakpoints

コードの実行を一時停止して、変数やプログラムの状態を検査します。

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

### ブラウザ DevTools: Elements / Console / Network

ブラウザツールを使用して、HTML を検査し、JavaScript をデバッグし、ネットワークリクエストを監視します。

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

### エラータイプ：`TypeError` / `ReferenceError`

一般的な JavaScript エラーを理解し、修正方法を学びます。

## 関連リンク

- <router-link to="/html">HTML チートシート</router-link>
- <router-link to="/css">CSS チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/react">React チートシート</router-link>

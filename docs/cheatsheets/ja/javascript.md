---
title: 'JavaScript チートシート | LabEx'
description: 'この包括的なチートシートで JavaScript プログラミングを学習。JS 構文、ES6+、DOM 操作、async/await、Node.js、最新 Web 開発のクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/javascript-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
JavaScript チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/javascript">ハンズオンラボで JavaScript を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて JavaScript プログラミングを学びましょう。LabEx は、必須の構文、関数、DOM 操作、非同期プログラミング、最新の ES6+ 機能などを網羅した包括的な JavaScript コースを提供します。効率的な Web 開発とプログラミングワークフローのために JavaScript を習得しましょう。
</base-disclaimer-content>
</base-disclaimer>

## 変数とデータ型

### 変数宣言：`let`, `const`, `var`

異なるスコープと変更可能性を持つ変数を宣言します。

```javascript
// ブロック スコープ、変更可能
let name = 'John'
let age = 25
age = 26 // 再代入可能

// ブロック スコープ、変更不可能
const PI = 3.14159
const user = { name: 'Alice' }
user.age = 30 // オブジェクトのプロパティは変更可能

// 関数 スコープ（モダン JS では非推奨）
var oldVariable = 'legacy'
```

<BaseQuiz id="javascript-let-const-1" correct="B">
  <template #question>
    <code>let</code>と <code>const</code> の主な違いは何ですか？
  </template>
  
  <BaseQuizOption value="A">let は関数スコープ、const はブロック スコープである</BaseQuizOption>
  <BaseQuizOption value="B" correct>let は再代入を許可し、const は再代入を許可しない</BaseQuizOption>
  <BaseQuizOption value="C">const は数値にのみ使用でき、let は任意の型に使用できる</BaseQuizOption>
  <BaseQuizOption value="D">違いはない</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>let</code>も <code>const</code> もブロック スコープですが、<code>let</code>は変数の再代入を許可し、<code>const</code>は再代入を防ぎます。ただし、<code>const</code> オブジェクトのプロパティは変更可能です。
  </BaseQuizAnswer>
</BaseQuiz>

### プリミティブ型

JavaScript の基本的なデータ型。

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

// その他のプリミティブ
let nothing = null
let notDefined = undefined
let unique = Symbol('id')
```

### 型チェック：`typeof`, `instanceof`

変数と値の型を特定します。

```javascript
// プリミティブ型のチェック
typeof 42 // 'number'
typeof 'hello' // 'string'
typeof true // 'boolean'
typeof undefined // 'undefined'

// オブジェクト型のチェック
let arr = [1, 2, 3]
typeof arr // 'object'
arr instanceof Array // true

let date = new Date()
date instanceof Date // true
```

### 型変換

異なるデータ型間の変換。

```javascript
// 文字列への変換
String(42) // '42'
;(42).toString() // '42'

// 数値への変換
Number('42') // 42
parseInt('42px') // 42
parseFloat('3.14') // 3.14

// 真偽値への変換
Boolean(0) // false
Boolean('hello') // true
!!'text' // true (二重否定)
```

## 関数

### 関数宣言

巻き上げ（hoisting）を伴う関数の従来の定義方法。

```javascript
// 関数宣言（巻き上げられる）
function greet(name) {
  return `Hello, ${name}!`
}

// デフォルトパラメータを持つ関数
function multiply(a, b = 1) {
  return a * b
}

// Rest パラメータ
function sum(...numbers) {
  return numbers.reduce((a, b) => a + b, 0)
}
```

### 関数式とアロー関数

モダンな関数構文と無名関数。

```javascript
// 関数式
const add = function (a, b) {
  return a + b
}

// アロー関数（簡潔）
const subtract = (a, b) => a - b

// ブロック本体を持つアロー関数
const processData = (data) => {
  const processed = data.filter((x) => x > 0)
  return processed.map((x) => x * 2)
}
```

<BaseQuiz id="javascript-arrow-1" correct="C">
  <template #question>
    アロー関数の主な特徴は何ですか？
  </template>
  
  <BaseQuizOption value="A">関数宣言のように巻き上げられる</BaseQuizOption>
  <BaseQuizOption value="B">独自の <code>this</code> バインディングを持つ</BaseQuizOption>
  <BaseQuizOption value="C" correct>囲むスコープから <code>this</code> を継承する</BaseQuizOption>
  <BaseQuizOption value="D">値を返すことができない</BaseQuizOption>
  
  <BaseQuizAnswer>
    アロー関数は独自の <code>this</code>バインディングを持ちません。代わりに、レキシカル（囲む）スコープから<code>this</code> を継承するため、コンテキストを保持したいコールバックやイベントハンドラで役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

### 高階関数

他の関数を受け取ったり返したりする関数。

```javascript
// 関数を返す関数
function createMultiplier(factor) {
  return function (number) {
    return number * factor
  }
}
const double = createMultiplier(2)

// パラメータとしての関数
function applyOperation(arr, operation) {
  return arr.map(operation)
}
```

## 配列とオブジェクト

### 配列メソッド：`map()`, `filter()`, `reduce()`

配列を関数的に変換・操作します。

```javascript
const numbers = [1, 2, 3, 4, 5]

// 各要素を変換
const doubled = numbers.map((x) => x * 2)
// [2, 4, 6, 8, 10]

// 要素をフィルタリング
const evens = numbers.filter((x) => x % 2 === 0)
// [2, 4]

// 単一の値に集約
const sum = numbers.reduce((acc, curr) => acc + curr, 0)
// 15

// メソッドの連鎖
const result = numbers
  .filter((x) => x > 2)
  .map((x) => x * 3)
  .reduce((a, b) => a + b, 0)
```

<BaseQuiz id="javascript-array-1" correct="A">
  <template #question>
    <code>filter()</code> は何を返しますか？
  </template>
  
  <BaseQuizOption value="A" correct>テストに合格した要素を持つ新しい配列</BaseQuizOption>
  <BaseQuizOption value="B">テストに合格した最初の要素</BaseQuizOption>
  <BaseQuizOption value="C">配列から集約された単一の値</BaseQuizOption>
  <BaseQuizOption value="D">インプレースで変更された元の配列</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>filter()</code> メソッドは、提供された関数によって実装されたテストに合格したすべての要素を含む新しい配列を作成します。元の配列は変更されません。
  </BaseQuizAnswer>
</BaseQuiz>

### 配列ユーティリティ：`find()`, `includes()`, `sort()`

配列要素の検索、確認、整理。

```javascript
const users = [
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 30 },
  { name: 'Charlie', age: 35 },
]

// 要素の検索
const user = users.find((u) => u.age > 30)

// 配列が値を含むかどうかの確認
;[1, 2, 3].includes(2) // true

// 配列のソート
const sorted = users.sort((a, b) => a.age - b.age)
```

### オブジェクトの作成と操作

オブジェクトとそのプロパティの操作。

```javascript
// オブジェクトリテラル
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

// オブジェクトの割り当て
const newPerson = Object.assign({}, person, { age: 31 })
```

### 分割代入 (Destructuring Assignment)

配列とオブジェクトから値を抽出します。

```javascript
// 配列の分割代入
const [first, second, ...rest] = [1, 2, 3, 4, 5]
// first: 1, second: 2, rest: [3, 4, 5]

// オブジェクトの分割代入
const { name, age } = person
const { name: userName, age: userAge = 18 } = person

// 関数パラメータの分割代入
function displayUser({ name, age }) {
  console.log(`${name} is ${age} years old`)
}
```

## DOM 操作

### 要素の選択：`querySelector()`, `getElementById()`

HTML 要素を見つけて選択します。

```javascript
// ID による選択
const header = document.getElementById('main-header')

// CSS セレクタによる選択（最初のマッチ）
const button = document.querySelector('.btn-primary')
const input = document.querySelector('input[type="email"]')

// 複数の要素の選択
const allButtons = document.querySelectorAll('.btn')
const listItems = document.querySelectorAll('li')

// NodeList を Array に変換
const buttonsArray = Array.from(allButtons)
```

<BaseQuiz id="javascript-dom-1" correct="C">
  <template #question>
    <code>querySelector()</code>と <code>querySelectorAll()</code> の違いは何ですか？
  </template>
  
  <BaseQuizOption value="A">違いはない</BaseQuizOption>
  <BaseQuizOption value="B">querySelector の方が速い</BaseQuizOption>
  <BaseQuizOption value="C" correct>querySelector は最初に一致した要素を返し、querySelectorAll は一致したすべての要素を返す</BaseQuizOption>
  <BaseQuizOption value="D">querySelector は ID に使用され、querySelectorAll はクラスに使用される</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>querySelector()</code>は CSS セレクタに一致する最初の要素を返し、<code>querySelectorAll()</code>は一致するすべての要素を含む NodeList を返します。1 つの要素が必要な場合は <code>querySelector()</code>を、複数の要素が必要な場合は<code>querySelectorAll()</code> を使用します。
  </BaseQuizAnswer>
</BaseQuiz>

### 要素の変更

コンテンツ、属性、スタイルの変更。

```javascript
// テキストコンテンツの変更
element.textContent = 'New text'
element.innerHTML = 'Bold text'

// 属性の変更
element.setAttribute('data-id', '123')
element.removeAttribute('disabled')
const value = element.getAttribute('data-id')

// クラスの変更
element.classList.add('active')
element.classList.remove('hidden')
element.classList.toggle('highlight')
```

### 要素の作成と挿入

HTML 要素を動的に作成し、追加します。

```javascript
// 新しい要素の作成
const div = document.createElement('div')
div.textContent = 'Hello World'
div.className = 'container'

// 要素の挿入
const parent = document.querySelector('#container')
parent.appendChild(div)
parent.insertBefore(div, parent.firstChild)

// モダンな挿入メソッド
parent.prepend(div) // 最初に挿入
parent.append(div) // 最後に挿入
div.before(newElement) // div の前に挿入
div.after(newElement) // div の後に挿入
```

### 要素のスタイリング

CSS スタイルをプログラムで適用します。

```javascript
// 直接的なスタイルの変更
element.style.color = 'red'
element.style.backgroundColor = 'blue'
element.style.fontSize = '16px'

// 複数のスタイルの設定
Object.assign(element.style, {
  width: '100px',
  height: '50px',
  border: '1px solid black',
})

// 計算されたスタイルの取得
const styles = window.getComputedStyle(element)
const color = styles.getPropertyValue('color')
```

## イベント処理

### イベントリスナーの追加

ユーザー操作やブラウザイベントに応答します。

```javascript
// 基本的なイベントリスナー
button.addEventListener('click', function (event) {
  console.log('Button clicked!')
})

// アロー関数によるイベントハンドラ
button.addEventListener('click', (e) => {
  e.preventDefault() // デフォルトの動作を防止
  console.log('Clicked:', e.target)
})

// オプション付きのイベントリスナー
element.addEventListener('scroll', handler, {
  passive: true,
  once: true,
})
```

### イベントの種類とプロパティ

一般的なイベントとイベントオブジェクトのプロパティ。

```javascript
// マウスイベント
element.addEventListener('click', handleClick)
element.addEventListener('mouseover', handleMouseOver)
element.addEventListener('mouseout', handleMouseOut)

// キーボードイベント
input.addEventListener('keydown', (e) => {
  console.log('Key pressed:', e.key)
  if (e.key === 'Enter') {
    // Enter キーの処理
  }
})

// フォームイベント
form.addEventListener('submit', handleSubmit)
```

### イベント委任 (Event Delegation)

複数の要素に対して効率的にイベントを処理します。

```javascript
// 親要素でのイベント委任
document.querySelector('#list').addEventListener('click', (e) => {
  if (e.target.matches('.list-item')) {
    console.log('List item clicked:', e.target.textContent)
  }
})

// イベントリスナーの削除
function handleClick(e) {
  console.log('Clicked')
}
button.addEventListener('click', handleClick)
button.removeEventListener('click', handleClick)
```

### カスタムイベント

カスタムイベントの作成とディスパッチ。

```javascript
// カスタムイベントの作成
const customEvent = new CustomEvent('userLogin', {
  detail: { username: 'john', timestamp: Date.now() },
})

// イベントのディスパッチ
element.dispatchEvent(customEvent)

// カスタムイベントのリスニング
element.addEventListener('userLogin', (e) => {
  console.log('User logged in:', e.detail.username)
})
```

## 非同期プログラミング

### Promise: `Promise`, `then()`, `catch()`

Promise を使用して非同期操作を扱います。

```javascript
// Promise の作成
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

// Promise の使用
fetchData
  .then((result) => console.log(result.data))
  .catch((error) => console.error(error))
  .finally(() => console.log('Done'))
```

### Async/Await: `async`, `await`

非同期コードを扱うためのモダンな構文。

```javascript
// Async 関数
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

// async 関数の使用
getData()
  .then((data) => console.log(data))
  .catch((error) => console.error(error))
```

### Fetch API: `fetch()`

サーバーへの HTTP リクエストの実行。

```javascript
// GET リクエスト
fetch('/api/users')
  .then((response) => response.json())
  .then((users) => console.log(users))

// POST リクエスト
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

### Promise ユーティリティ：`Promise.all()`, `Promise.race()`

複数の Promise を同時に扱う。

```javascript
// すべての Promise が解決されるのを待つ
const promises = [fetch('/api/users'), fetch('/api/posts')]
Promise.all(promises)
  .then((responses) => Promise.all(responses.map((r) => r.json())))
  .then(([users, posts]) => {
    console.log('Users:', users)
    console.log('Posts:', posts)
  })

// Race - 最初に解決した Promise が勝つ
Promise.race(promises).then((firstResponse) => console.log('First response'))
```

## ES6+ モダン機能

### テンプレートリテラルとスプレッド演算子

文字列補間と配列/オブジェクトのスプレッド。

```javascript
// テンプレートリテラル
const name = 'Alice'
const age = 25
const message = `Hello, ${name}! You are ${age} years old.`

// 複数行文字列
const html = `
    <div>
        ${name}
        Age: ${age}
    </div>
`

// スプレッド演算子
const arr1 = [1, 2, 3]
const arr2 = [4, 5, 6]
const combined = [...arr1, ...arr2] // [1,2,3,4,5,6]

const obj1 = { a: 1, b: 2 }
const obj2 = { ...obj1, c: 3 } // { a: 1, b: 2, c: 3 }
```

### クラスとモジュール

オブジェクト指向プログラミングとモジュールシステム。

```javascript
// ES6 クラス
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

// 継承
class Student extends Person {
  constructor(name, age, grade) {
    super(name, age)
    this.grade = grade
  }
}

// モジュールのエクスポート/インポート
export const helper = () => 'helper function'
export default Person

import Person, { helper } from './person.js'
```

## エラー処理

### Try/Catch/Finally

同期および非同期のエラーを処理します。

```javascript
// 基本的なエラー処理
try {
  const result = riskyOperation()
  console.log(result)
} catch (error) {
  console.error('Error occurred:', error.message)
} finally {
  console.log('Cleanup code runs here')
}

// 非同期エラー処理
async function asyncOperation() {
  try {
    const data = await fetch('/api/data')
    const json = await data.json()
    return json
  } catch (error) {
    console.error('Async error:', error)
    throw error // 必要に応じて再スロー
  }
}
```

### カスタムエラーとデバッグ

カスタムエラー型を作成し、効果的にデバッグします。

```javascript
// カスタムエラークラス
class ValidationError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'ValidationError'
    this.field = field
  }
}

// カスタムエラーのスロー
function validateEmail(email) {
  if (!email.includes('@')) {
    throw new ValidationError('Invalid email format', 'email')
  }
}

// コンソールデバッグメソッド
console.log('Basic log')
console.warn('Warning message')
console.error('Error message')
console.table([{ name: 'John', age: 30 }])
console.time('operation')
// ... some code
console.timeEnd('operation')
```

## ローカルストレージと JSON

### LocalStorage API

ブラウザに永続的にデータを保存します。

```javascript
// データの保存
localStorage.setItem('username', 'john_doe')
localStorage.setItem(
  'settings',
  JSON.stringify({
    theme: 'dark',
    notifications: true,
  }),
)

// データの取得
const username = localStorage.getItem('username')
const settings = JSON.parse(localStorage.getItem('settings'))

// データの削除
localStorage.removeItem('username')
localStorage.clear() // すべてのアイテムを削除

// キーの存在確認
if (localStorage.getItem('username') !== null) {
  // キーは存在する
}
```

### JSON 操作

JSON データの解析と文字列化。

```javascript
// JavaScript オブジェクトから JSON 文字列へ
const user = { name: 'Alice', age: 25, active: true }
const jsonString = JSON.stringify(user)
// '{"name":"Alice","age":25,"active":true}'

// JSON 文字列から JavaScript オブジェクトへ
const jsonData = '{"name":"Bob","age":30}'
const userObj = JSON.parse(jsonData)

// JSON 解析エラーの処理
try {
  const data = JSON.parse(invalidJson)
} catch (error) {
  console.error('Invalid JSON:', error.message)
}

// カスタムの replacer/reviver を使用した JSON
const filtered = JSON.stringify(user, ['name', 'age'])
const parsed = JSON.parse(jsonString, (key, value) => {
  return key === 'age' ? value + 1 : value
})
```

## 正規表現

### パターンの作成とテスト

正規表現パターンを作成し、文字列に対してテストします。

```javascript
// 正規表現リテラル
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// RegExp コンストラクタ
const phoneRegex = new RegExp(r'\d{3}-\d{3}-\d{4}');

// test メソッド
const isValidEmail = emailRegex.test('user@example.com'); // true

// match メソッド
const text = 'Call me at 123-456-7890';
const phoneMatch = text.match(/\d{3}-\d{3}-\d{4}/);
console.log(phoneMatch[0]); // '123-456-7890'

// グローバル検索
const allNumbers = text.match(/\d+/g); // ['123', '456', '7890']
```

### 正規表現を使用した文字列メソッド

文字列操作メソッドでの正規表現の使用。

```javascript
// 正規表現による置換
const text = 'Hello World 123'
const cleaned = text.replace(/\d+/g, '') // 'Hello World '

// 正規表現による分割
const parts = 'apple,banana;orange:grape'.split(/[,:;]/)
// ['apple', 'banana', 'orange', 'grape']

// search メソッド
const position = text.search(/\d+/) // 12 (最初の数字の位置)

// 一般的なパターン
const patterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  phone: /^\d{3}-\d{3}-\d{4}$/,
  url: /^https?:\/\/.+/,
  digits: /\d+/g,
  whitespace: /\s+/g,
}
```

## JavaScript のセットアップと環境

### ブラウザコンソール

Web ブラウザに組み込まれた JavaScript 実行環境。

```javascript
// ブラウザの開発者ツールを開く (F12)
// コンソールタブに移動
console.log('Hello JavaScript!')

// 直接コードをテスト
let x = 5
let y = 10
console.log(x + y) // 15

// HTML へのスクリプトの組み込み
```

### Node.js 環境

サーバーサイド開発のための JavaScript ランタイム。

```bash
# nodejs.orgからNode.jsをインストール
# インストールの確認
node --version
npm --version

# JavaScriptファイルの実行
node script.js

# npmプロジェクトの初期化
npm init -y

# パッケージのインストール
npm install lodash
npm install --save-dev jest
```

### モダン開発ツール

JavaScript 開発に不可欠なツール。

```json
// Package.json スクリプト
{
  "scripts": {
    "start": "node index.js",
    "test": "jest",
    "build": "webpack"
  }
}
```

```bash
# ブラウザでのES6モジュール
# 古いブラウザサポートのためのBabel
npm install --save-dev @babel/core @babel/preset-env
```

## ベストプラクティスとパフォーマンス

### パフォーマンス最適化

JavaScript のパフォーマンスを向上させるためのテクニック。

```javascript
// 頻繁なイベントのためのデバウンス
function debounce(func, delay) {
  let timeoutId
  return function (...args) {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func.apply(this, args), delay)
  }
}

// デバウンスされた関数の使用
const debouncedSearch = debounce(searchFunction, 300)
input.addEventListener('input', debouncedSearch)

// 効率的な DOM クエリ
const elements = document.querySelectorAll('.item')
// 長さをキャッシュして再計算を回避
for (let i = 0, len = elements.length; i < len; i++) {
  // elements[i] を処理
}
```

### コードの整理と標準

保守性と可読性のためにコードを構造化します。

```javascript
// 厳格モードの使用
'use strict'

// 一貫した命名規則
const userName = 'john' // 変数はキャメルケース
const API_URL = 'https://api.example.com' // 定数は大文字

// 関数ドキュメント
/**
 * 長方形の面積を計算します
 * @param {number} width - 長方形の幅
 * @param {number} height - 長方形の高さ
 * @returns {number} 長方形の面積
 */
function calculateArea(width, height) {
  return width * height
}

// デフォルトで const を使用し、再代入が必要な場合は let を使用
const config = { theme: 'dark' }
let counter = 0
```

## JavaScript コードのテスト

### Jest による単体テスト

JavaScript 関数のテストを作成・実行します。

```javascript
// Jest のインストール：npm install --save-dev jest

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

// テストの実行：npm test
```

### ブラウザテストとデバッグ

ブラウザの開発者ツールでの JavaScript のデバッグ。

```javascript
// ブレークポイントの設定
debugger // 開発者ツールで実行を一時停止

// デバッグのためのコンソールメソッド
console.log('Variable value:', variable)
console.assert(x > 0, 'x は正であるべき')
console.trace('関数呼び出しスタック')

// パフォーマンス測定
performance.mark('start')
// ... 測定するコード
performance.mark('end')
performance.measure('operation', 'start', 'end')

// パフォーマンスエントリの確認
const measurements = performance.getEntriesByType('measure')
```

## 関連リンク

- <router-link to="/html">HTML チートシート</router-link>
- <router-link to="/css">CSS チートシート</router-link>
- <router-link to="/react">React チートシート</router-link>
- <router-link to="/web-development">Web 開発チートシート</router-link>

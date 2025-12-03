---
title: 'JavaScript 치트 시트 | LabEx'
description: '이 포괄적인 치트 시트로 JavaScript 프로그래밍을 배우세요. JS 구문, ES6+, DOM 조작, async/await, Node.js 및 최신 웹 개발을 위한 빠른 참조.'
pdfUrl: '/cheatsheets/pdf/javascript-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
JavaScript 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/javascript">Hands-On Labs 로 JavaScript 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 JavaScript 프로그래밍을 학습하세요. LabEx 는 필수 구문, 함수, DOM 조작, 비동기 프로그래밍 및 최신 ES6+ 기능을 다루는 포괄적인 JavaScript 과정을 제공합니다. 효율적인 웹 개발 및 프로그래밍 워크플로우를 위해 JavaScript 를 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 변수 및 데이터 타입

### 변수 선언: `let`, `const`, `var`

다양한 범위와 변경 가능성을 가진 변수를 선언합니다.

```javascript
// 블록 범위, 변경 가능
let name = 'John'
let age = 25
age = 26 // 재할당 가능

// 블록 범위, 변경 불가능
const PI = 3.14159
const user = { name: 'Alice' }
user.age = 30 // 객체 속성은 수정 가능

// 함수 범위 (최신 JS 에서는 사용 지양)
var oldVariable = 'legacy'
```

<BaseQuiz id="javascript-let-const-1" correct="B">
  <template #question>
    `let` 과 `const` 의 주요 차이점은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">let 은 함수 범위이고, const 는 블록 범위입니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>let 은 재할당을 허용하고, const 는 재할당을 허용하지 않습니다</BaseQuizOption>
  <BaseQuizOption value="C">const 는 숫자에서만 사용할 수 있고, let 은 모든 타입에 사용할 수 있습니다</BaseQuizOption>
  <BaseQuizOption value="D">차이점이 없습니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `let` 과 `const` 는 모두 블록 범위이지만, `let` 은 변수 재할당을 허용하는 반면 `const` 는 재할당을 방지합니다. 하지만 `const` 객체의 속성은 여전히 수정될 수 있습니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 기본 타입 (Primitive Types)

JavaScript 의 기본 데이터 타입입니다.

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

// 기타 기본 타입
let nothing = null
let notDefined = undefined
let unique = Symbol('id')
```

### 타입 확인: `typeof`, `instanceof`

변수와 값의 타입을 확인합니다.

```javascript
// 기본 타입 확인
typeof 42 // 'number'
typeof 'hello' // 'string'
typeof true // 'boolean'
typeof undefined // 'undefined'

// 객체 타입 확인
let arr = [1, 2, 3]
typeof arr // 'object'
arr instanceof Array // true

let date = new Date()
date instanceof Date // true
```

### 타입 변환 (Type Conversion)

다른 데이터 타입 간에 변환합니다.

```javascript
// 문자열 변환
String(42) // '42'
;(42).toString() // '42'

// 숫자 변환
Number('42') // 42
parseInt('42px') // 42
parseFloat('3.14') // 3.14

// 불리언 변환
Boolean(0) // false
Boolean('hello') // true
!!'text' // true (이중 부정)
```

## 함수 (Functions)

### 함수 선언 (Function Declarations)

호이스팅 (hoisting) 을 사용하는 전통적인 함수 정의 방식입니다.

```javascript
// 함수 선언 (호이스팅됨)
function greet(name) {
  return `Hello, ${name}!`
}

// 기본 매개변수가 있는 함수
function multiply(a, b = 1) {
  return a * b
}

// 나머지 매개변수 (Rest parameters)
function sum(...numbers) {
  return numbers.reduce((a, b) => a + b, 0)
}
```

### 함수 표현식 및 화살표 함수 (Function Expressions & Arrow Functions)

현대적인 함수 구문 및 익명 함수입니다.

```javascript
// 함수 표현식
const add = function (a, b) {
  return a + b
}

// 화살표 함수 (간결함)
const subtract = (a, b) => a - b

// 블록 본문을 가진 화살표 함수
const processData = (data) => {
  const processed = data.filter((x) => x > 0)
  return processed.map((x) => x * 2)
}
```

<BaseQuiz id="javascript-arrow-1" correct="C">
  <template #question>
    화살표 함수의 주요 특징은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">함수 선언처럼 호이스팅됩니다</BaseQuizOption>
  <BaseQuizOption value="B">자체적인 `this` 바인딩을 가집니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>자신을 둘러싼 범위로부터 `this` 를 상속받습니다</BaseQuizOption>
  <BaseQuizOption value="D">값을 반환할 수 없습니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    화살표 함수는 자체적인 `this` 바인딩을 가지지 않습니다. 대신, 렉시컬 (둘러싼) 범위로부터 `this` 를 상속받으므로 콜백 및 이벤트 핸들러에서 컨텍스트를 유지하고 싶을 때 유용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 고차 함수 (Higher-Order Functions)

다른 함수를 인수로 받거나 반환하는 함수입니다.

```javascript
// 함수를 반환하는 함수
function createMultiplier(factor) {
  return function (number) {
    return number * factor
  }
}
const double = createMultiplier(2)

// 매개변수로 함수 사용
function applyOperation(arr, operation) {
  return arr.map(operation)
}
```

## 배열 및 객체 (Arrays & Objects)

### 배열 메서드: `map()`, `filter()`, `reduce()`

배열을 함수형으로 변환하고 조작합니다.

```javascript
const numbers = [1, 2, 3, 4, 5]

// 각 요소 변환
const doubled = numbers.map((x) => x * 2)
// [2, 4, 6, 8, 10]

// 요소 필터링
const evens = numbers.filter((x) => x % 2 === 0)
// [2, 4]

// 단일 값으로 축소
const sum = numbers.reduce((acc, curr) => acc + curr, 0)
// 15

// 메서드 체이닝
const result = numbers
  .filter((x) => x > 2)
  .map((x) => x * 3)
  .reduce((a, b) => a + b, 0)
```

<BaseQuiz id="javascript-array-1" correct="A">
  <template #question>
    `filter()` 는 무엇을 반환합니까?
  </template>
  
  <BaseQuizOption value="A" correct>테스트를 통과하는 요소들로 이루어진 새 배열</BaseQuizOption>
  <BaseQuizOption value="B">테스트를 통과하는 첫 번째 요소</BaseQuizOption>
  <BaseQuizOption value="C">배열에서 축소된 단일 값</BaseQuizOption>
  <BaseQuizOption value="D">제자리에서 수정된 원본 배열</BaseQuizOption>
  
  <BaseQuizAnswer>
    `filter()` 메서드는 제공된 함수로 구현된 테스트를 통과하는 모든 요소를 포함하는 새 배열을 생성합니다. 원본 배열은 수정하지 않습니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 배열 유틸리티: `find()`, `includes()`, `sort()`

배열 요소를 검색하고, 확인하고, 정렬합니다.

```javascript
const users = [
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 30 },
  { name: 'Charlie', age: 35 },
]

// 요소 찾기
const user = users.find((u) => u.age > 30)

// 배열에 값이 포함되어 있는지 확인
;[1, 2, 3].includes(2) // true

// 배열 정렬
const sorted = users.sort((a, b) => a.age - b.age)
```

### 객체 생성 및 조작

객체와 그 속성을 다룹니다.

```javascript
// 객체 리터럴
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

// 객체 할당
const newPerson = Object.assign({}, person, { age: 31 })
```

### 구조 분해 할당 (Destructuring Assignment)

배열과 객체에서 값을 추출합니다.

```javascript
// 배열 구조 분해
const [first, second, ...rest] = [1, 2, 3, 4, 5]
// first: 1, second: 2, rest: [3, 4, 5]

// 객체 구조 분해
const { name, age } = person
const { name: userName, age: userAge = 18 } = person

// 함수 매개변수 구조 분해
function displayUser({ name, age }) {
  console.log(`${name} is ${age} years old`)
}
```

## DOM 조작 (DOM Manipulation)

### 요소 선택: `querySelector()`, `getElementById()`

HTML 요소를 찾고 선택합니다.

```javascript
// ID 로 선택
const header = document.getElementById('main-header')

// CSS 선택자로 선택 (첫 번째 일치 항목)
const button = document.querySelector('.btn-primary')
const input = document.querySelector('input[type="email"]')

// 여러 요소 선택
const allButtons = document.querySelectorAll('.btn')
const listItems = document.querySelectorAll('li')

// NodeList 를 배열로 변환
const buttonsArray = Array.from(allButtons)
```

<BaseQuiz id="javascript-dom-1" correct="C">
  <template #question>
    `querySelector()` 와 `querySelectorAll()` 의 차이점은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">차이점이 없습니다</BaseQuizOption>
  <BaseQuizOption value="B">querySelector 가 더 빠릅니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>querySelector 는 일치하는 첫 번째 요소를 반환하고, querySelectorAll 은 일치하는 모든 요소를 반환합니다</BaseQuizOption>
  <BaseQuizOption value="D">querySelector 는 ID 에 사용되고, querySelectorAll 은 클래스에 사용됩니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `querySelector()` 는 CSS 선택자와 일치하는 첫 번째 요소를 반환하는 반면, `querySelectorAll()` 는 일치하는 모든 요소를 포함하는 NodeList 를 반환합니다. 하나의 요소가 필요할 때는 `querySelector()` 를, 여러 요소가 필요할 때는 `querySelectorAll()` 를 사용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 요소 수정 (Element Modification)

콘텐츠, 속성 및 스타일을 변경합니다.

```javascript
// 텍스트 콘텐츠 변경
element.textContent = '새 텍스트'
element.innerHTML = '굵은 텍스트'

// 속성 수정
element.setAttribute('data-id', '123')
element.removeAttribute('disabled')
const value = element.getAttribute('data-id')

// 클래스 변경
element.classList.add('active')
element.classList.remove('hidden')
element.classList.toggle('highlight')
```

### 요소 생성 및 삽입

HTML 요소를 동적으로 생성하고 추가합니다.

```javascript
// 새 요소 생성
const div = document.createElement('div')
div.textContent = 'Hello World'
div.className = 'container'

// 요소 삽입
const parent = document.querySelector('#container')
parent.appendChild(div)
parent.insertBefore(div, parent.firstChild)

// 최신 삽입 메서드
parent.prepend(div) // 시작 부분에 삽입
parent.append(div) // 끝 부분에 삽입
div.before(newElement) // div 앞에 삽입
div.after(newElement) // div 뒤에 삽입
```

### 요소 스타일링

CSS 스타일을 프로그래밍 방식으로 적용합니다.

```javascript
// 직접 스타일 수정
element.style.color = 'red'
element.style.backgroundColor = 'blue'
element.style.fontSize = '16px'

// 여러 스타일 설정
Object.assign(element.style, {
  width: '100px',
  height: '50px',
  border: '1px solid black',
})

// 계산된 스타일 가져오기
const styles = window.getComputedStyle(element)
const color = styles.getPropertyValue('color')
```

## 이벤트 처리 (Event Handling)

### 이벤트 리스너 추가

사용자 상호 작용 및 브라우저 이벤트에 응답합니다.

```javascript
// 기본 이벤트 리스너
button.addEventListener('click', function (event) {
  console.log('버튼 클릭됨!')
})

// 화살표 함수 이벤트 핸들러
button.addEventListener('click', (e) => {
  e.preventDefault() // 기본 동작 방지
  console.log('클릭 대상:', e.target)
})

// 옵션이 있는 이벤트 리스너
element.addEventListener('scroll', handler, {
  passive: true,
  once: true,
})
```

### 이벤트 유형 및 속성

일반적인 이벤트 및 이벤트 객체 속성입니다.

```javascript
// 마우스 이벤트
element.addEventListener('click', handleClick)
element.addEventListener('mouseover', handleMouseOver)
element.addEventListener('mouseout', handleMouseOut)

// 키보드 이벤트
input.addEventListener('keydown', (e) => {
  console.log('눌린 키:', e.key)
  if (e.key === 'Enter') {
    // Enter 키 처리
  }
})

// 폼 이벤트
form.addEventListener('submit', handleSubmit)
```

### 이벤트 위임 (Event Delegation)

여러 요소에 대해 이벤트를 효율적으로 처리합니다.

```javascript
// 부모 요소에 대한 이벤트 위임
document.querySelector('#list').addEventListener('click', (e) => {
  if (e.target.matches('.list-item')) {
    console.log('목록 항목 클릭됨:', e.target.textContent)
  }
})

// 이벤트 리스너 제거
function handleClick(e) {
  console.log('클릭됨')
}
button.addEventListener('click', handleClick)
button.removeEventListener('click', handleClick)
```

### 사용자 정의 이벤트 (Custom Events)

사용자 정의 이벤트를 생성하고 디스패치합니다.

```javascript
// 사용자 정의 이벤트 생성
const customEvent = new CustomEvent('userLogin', {
  detail: { username: 'john', timestamp: Date.now() },
})

// 이벤트 디스패치
element.dispatchEvent(customEvent)

// 사용자 정의 이벤트 수신
element.addEventListener('userLogin', (e) => {
  console.log('사용자 로그인:', e.detail.username)
})
```

## 비동기 프로그래밍 (Asynchronous Programming)

### Promise: `Promise`, `then()`, `catch()`

Promise 를 사용하여 비동기 작업을 처리합니다.

```javascript
// Promise 생성
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

// Promise 사용
fetchData
  .then((result) => console.log(result.data))
  .catch((error) => console.error(error))
  .finally(() => console.log('완료'))
```

### Async/Await: `async`, `await`

비동기 코드를 처리하기 위한 최신 구문입니다.

```javascript
// Async 함수
async function getData() {
  try {
    const response = await fetch('/api/data')
    const data = await response.json()
    return data
  } catch (error) {
    console.error('오류:', error)
    throw error
  }
}

// async 함수 사용
getData()
  .then((data) => console.log(data))
  .catch((error) => console.error(error))
```

### Fetch API: `fetch()`

서버에 HTTP 요청을 보냅니다.

```javascript
// GET 요청
fetch('/api/users')
  .then((response) => response.json())
  .then((users) => console.log(users))

// POST 요청
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

### Promise 유틸리티: `Promise.all()`, `Promise.race()`

여러 Promise 를 동시에 처리합니다.

```javascript
// 모든 Promise 가 해결될 때까지 대기
const promises = [fetch('/api/users'), fetch('/api/posts')]
Promise.all(promises)
  .then((responses) => Promise.all(responses.map((r) => r.json())))
  .then(([users, posts]) => {
    console.log('사용자:', users)
    console.log('게시물:', posts)
  })

// Race - 가장 먼저 해결되는 Promise 가 승리
Promise.race(promises).then((firstResponse) => console.log('첫 번째 응답'))
```

## ES6+ 최신 기능 (ES6+ Modern Features)

### 템플릿 리터럴 및 스프레드 연산자 (Template Literals & Spread Operator)

문자열 보간 및 배열/객체 확산.

```javascript
// 템플릿 리터럴
const name = 'Alice'
const age = 25
const message = `Hello, ${name}! You are ${age} years old.`

// 여러 줄 문자열
const html = `
    <div>
        ${name}
        Age: ${age}
    </div>
`

// 스프레드 연산자
const arr1 = [1, 2, 3]
const arr2 = [4, 5, 6]
const combined = [...arr1, ...arr2] // [1,2,3,4,5,6]

const obj1 = { a: 1, b: 2 }
const obj2 = { ...obj1, c: 3 } // { a: 1, b: 2, c: 3 }
```

### 클래스 및 모듈 (Classes & Modules)

객체 지향 프로그래밍 및 모듈 시스템.

```javascript
// ES6 클래스
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

// 상속
class Student extends Person {
  constructor(name, age, grade) {
    super(name, age)
    this.grade = grade
  }
}

// 모듈 내보내기/가져오기
export const helper = () => 'helper function'
export default Person

import Person, { helper } from './person.js'
```

## 오류 처리 (Error Handling)

### Try/Catch/Finally

동기 및 비동기 오류를 처리합니다.

```javascript
// 기본 오류 처리
try {
  const result = riskyOperation()
  console.log(result)
} catch (error) {
  console.error('오류 발생:', error.message)
} finally {
  console.log('정리 코드가 여기에 실행됩니다')
}

// 비동기 오류 처리
async function asyncOperation() {
  try {
    const data = await fetch('/api/data')
    const json = await data.json()
    return json
  } catch (error) {
    console.error('비동기 오류:', error)
    throw error // 필요한 경우 다시 throw
  }
}
```

### 사용자 정의 오류 및 디버깅

사용자 정의 오류 유형을 생성하고 효과적으로 디버깅합니다.

```javascript
// 사용자 정의 오류 클래스
class ValidationError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'ValidationError'
    this.field = field
  }
}

// 사용자 정의 오류 throw
function validateEmail(email) {
  if (!email.includes('@')) {
    throw new ValidationError('유효하지 않은 이메일 형식', 'email')
  }
}

// 콘솔 디버깅 메서드
console.log('기본 로그')
console.warn('경고 메시지')
console.error('오류 메시지')
console.table([{ name: 'John', age: 30 }])
console.time('operation')
// ... 측정할 코드
console.timeEnd('operation')
```

## 로컬 스토리지 및 JSON (Local Storage & JSON)

### LocalStorage API

브라우저에 영구적으로 데이터를 저장합니다.

```javascript
// 데이터 저장
localStorage.setItem('username', 'john_doe')
localStorage.setItem(
  'settings',
  JSON.stringify({
    theme: 'dark',
    notifications: true,
  }),
)

// 데이터 검색
const username = localStorage.getItem('username')
const settings = JSON.parse(localStorage.getItem('settings'))

// 데이터 제거
localStorage.removeItem('username')
localStorage.clear() // 모든 항목 제거

// 키 존재 여부 확인
if (localStorage.getItem('username') !== null) {
  // 키가 존재함
}
```

### JSON 작업

JSON 데이터를 구문 분석하고 문자열로 변환합니다.

```javascript
// JavaScript 객체를 JSON 문자열로
const user = { name: 'Alice', age: 25, active: true }
const jsonString = JSON.stringify(user)
// '{"name":"Alice","age":25,"active":true}'

// JSON 문자열을 JavaScript 객체로
const jsonData = '{"name":"Bob","age":30}'
const userObj = JSON.parse(jsonData)

// JSON 구문 분석 오류 처리
try {
  const data = JSON.parse(invalidJson)
} catch (error) {
  console.error('유효하지 않은 JSON:', error.message)
}

// 사용자 정의 replacer/reviver를 사용한 JSON
const filtered = JSON.stringify(user, ['name', 'age'])
const parsed = JSON.parse(jsonString, (key, value) => {
  return key === 'age' ? value + 1 : value
})
```

## 정규 표현식 (Regular Expressions)

### 패턴 생성 및 테스트

정규식 패턴을 생성하고 문자열에 대해 테스트합니다.

```javascript
// 정규식 리터럴
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// RegExp 생성자
const phoneRegex = new RegExp(r'\d{3}-\d{3}-\d{4}');

// test 메서드
const isValidEmail = emailRegex.test('user@example.com'); // true

// match 메서드
const text = 'Call me at 123-456-7890';
const phoneMatch = text.match(/\d{3}-\d{3}-\d{4}/);
console.log(phoneMatch[0]); // '123-456-7890'

// 전역 검색
const allNumbers = text.match(/\d+/g); // ['123', '456', '7890']
```

### 정규식을 사용한 문자열 메서드

문자열 조작 메서드에서 정규식을 사용합니다.

```javascript
// 정규식으로 대체
const text = 'Hello World 123'
const cleaned = text.replace(/\d+/g, '') // 'Hello World '

// 정규식으로 분할
const parts = 'apple,banana;orange:grape'.split(/[,:;]/)
// ['apple', 'banana', 'orange', 'grape']

// search 메서드
const position = text.search(/\d+/) // 12 (첫 번째 숫자의 위치)

// 일반적인 패턴
const patterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  phone: /^\d{3}-\d{3}-\d{4}$/,
  url: /^https?:\/\/.+/,
  digits: /\d+/g,
  whitespace: /\s+/g,
}
```

## JavaScript 설정 및 환경 (JavaScript Setup & Environment)

### 브라우저 콘솔 (Browser Console)

웹 브라우저의 내장 JavaScript 환경입니다.

```javascript
// 웹 브라우저 개발자 도구 열기 (F12)
// Console 탭으로 이동
console.log('Hello JavaScript!')

// 코드를 직접 테스트
let x = 5
let y = 10
console.log(x + y) // 15

// HTML 에 스크립트 포함
```

### Node.js 환경

서버 측 개발을 위한 JavaScript 런타임입니다.

```bash
# nodejs.org에서 Node.js 설치
# 설치 확인
node --version
npm --version

# JavaScript 파일 실행
node script.js

# npm 프로젝트 초기화
npm init -y

# 패키지 설치
npm install lodash
npm install --save-dev jest
```

### 최신 개발 도구

JavaScript 개발에 필수적인 도구입니다.

```json
// package.json 스크립트
{
  "scripts": {
    "start": "node index.js",
    "test": "jest",
    "build": "webpack"
  }
}
```

```bash
# 브라우저의 ES6 모듈
# 이전 브라우저 지원을 위한 Babel
npm install --save-dev @babel/core @babel/preset-env
```

## 모범 사례 및 성능 (Best Practices & Performance)

### 성능 최적화

JavaScript 성능을 개선하기 위한 기술입니다.

```javascript
// 빈번한 이벤트에 대한 디바운싱 (Debouncing)
function debounce(func, delay) {
  let timeoutId
  return function (...args) {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func.apply(this, args), delay)
  }
}

// 디바운스된 함수 사용
const debouncedSearch = debounce(searchFunction, 300)
input.addEventListener('input', debouncedSearch)

// 효율적인 DOM 쿼리
const elements = document.querySelectorAll('.item')
// 길이 계산을 피하기 위해 길이 캐시
for (let i = 0, len = elements.length; i < len; i++) {
  // elements[i] 처리
}
```

### 코드 구성 및 표준

유지 관리 및 가독성을 위해 코드를 구조화합니다.

```javascript
// 엄격 모드 사용
'use strict'

// 일관된 명명 규칙
const userName = 'john' // 변수는 camelCase
const API_URL = 'https://api.example.com' // 상수는 대문자

// 함수 문서화
/**
 * 직사각형의 넓이를 계산합니다
 * @param {number} width - 직사각형의 너비
 * @param {number} height - 직사각형의 높이
 * @returns {number} 직사각형의 넓이
 */
function calculateArea(width, height) {
  return width * height
}

// 기본적으로 const 사용, 재할당이 필요할 때만 let 사용
const config = { theme: 'dark' }
let counter = 0
```

## JavaScript 코드 테스트 (Testing JavaScript Code)

### Jest 를 사용한 단위 테스트

JavaScript 함수에 대한 테스트를 작성하고 실행합니다.

```javascript
// Jest 설치: npm install --save-dev jest

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

// 테스트 실행: npm test
```

### 브라우저 테스트 및 디버깅

브라우저 개발자 도구에서 JavaScript 디버깅.

```javascript
// 중단점 설정
debugger // 개발자 도구에서 실행 일시 중지

// 디버깅을 위한 콘솔 메서드
console.log('변수 값:', variable)
console.assert(x > 0, 'x 는 양수여야 합니다')
console.trace('함수 호출 스택')

// 성능 타이밍
performance.mark('start')
// ... 측정할 코드
performance.mark('end')
performance.measure('operation', 'start', 'end')

// 성능 항목 확인
const measurements = performance.getEntriesByType('measure')
```

## 관련 링크 (Relevant Links)

- <router-link to="/html">HTML 치트 시트</router-link>
- <router-link to="/css">CSS 치트 시트</router-link>
- <router-link to="/react">React 치트 시트</router-link>
- <router-link to="/web-development">웹 개발 치트 시트</router-link>

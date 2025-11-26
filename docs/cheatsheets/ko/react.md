---
title: 'React 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 포괄적인 치트 시트로 React 를 학습하세요.'
pdfUrl: '/cheatsheets/pdf/react-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
React 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/react">실습 랩을 통해 React 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 React 프론트엔드 개발을 학습하세요. LabEx 는 필수적인 컴포넌트 생성, 상태 관리, 훅, 이벤트 처리 및 성능 최적화를 다루는 포괄적인 React 강좌를 제공합니다. 현대적인 웹 애플리케이션을 위한 효율적이고 유지보수 가능한 사용자 인터페이스 구축을 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 컴포넌트 생성 및 JSX

### 함수형 컴포넌트: `function` / `=>`

함수 구문을 사용하여 컴포넌트를 생성합니다.

```javascript
import React from 'react'

// 함수 선언
function Welcome(props) {
  return <h1>Hello, {props.name}!</h1>
}

// 화살표 함수
const Welcome = (props) => {
  return <h1>Hello, {props.name}!</h1>
}

// 간단한 컴포넌트를 위한 암시적 반환
const Greeting = ({ name }) => <h1>Hello, {name}!</h1>
```

### 클래스 컴포넌트: `class extends React.Component`

ES6 클래스 구문을 사용하여 컴포넌트를 생성합니다.

```javascript
import React, { Component } from 'react'

class Welcome extends Component {
  render() {
    return <h1>Hello, {this.props.name}!</h1>
  }
}

// 생성자 포함
class Counter extends Component {
  constructor(props) {
    super(props)
    this.state = { count: 0 }
  }
  render() {
    return <div>Count: {this.state.count}</div>
  }
}
```

### JSX 요소: `<element>`

JavaScript 내에서 HTML 과 유사한 구문을 작성합니다.

```javascript
// JSX 요소
const element = <h1>Hello, world!</h1>

// 표현식이 포함된 JSX
const name = 'John'
const greeting = <h1>Hello, {name}!</h1>

// 여러 줄 JSX
const element = (
  <div>
    <h1>Welcome!</h1>
    <p>Good to see you here.</p>
  </div>
)
```

### 컴포넌트 내보내기: `export default` / `export`

다른 파일에서 사용하기 위해 컴포넌트를 내보냅니다.

```javascript
// 기본 내보내기
export default function App() {
  return <div>My App</div>
}

// 이름 있는 내보내기
export const Button = () => <button>Click me</button>
```

### 컴포넌트 가져오기: `import`

다른 파일에서 컴포넌트를 가져옵니다.

```javascript
// 기본 컴포넌트 가져오기
import App from './App'

// 이름 있는 컴포넌트 가져오기
import { Button } from './Button'

// 여러 컴포넌트 가져오기
import React, { useState, useEffect } from 'react'

// 별칭을 사용하여 가져오기
import { Button as MyButton } from './Button'
```

### 프래그먼트: `<React.Fragment>` / `<>`

추가적인 DOM 노드 없이 요소를 그룹화합니다.

```javascript
// React.Fragment 사용
return (
  <React.Fragment>
    <h1>Title</h1>
    <p>Description</p>
  </React.Fragment>
)

// 짧은 구문 사용
return (
  <>
    <h1>Title</h1>
    <p>Description</p>
  </>
)
```

## Props 및 컴포넌트 구조

### Props: `props.name`

데이터를 부모에서 자식 컴포넌트로 전달합니다.

```javascript
// props 수신
function Welcome(props) {
  return <h1>Hello, {props.name}!</h1>
}

// props 구조 분해
function Welcome({ name, age }) {
  return (
    <h1>
      Hello, {name}! You are {age} years old.
    </h1>
  )
}

// 기본 props
function Welcome({ name = 'Guest' }) {
  return <h1>Hello, {name}!</h1>
}
```

### PropTypes: `Component.propTypes`

컴포넌트에 전달된 props 를 검증합니다 (prop-types 패키지 필요).

```javascript
import PropTypes from 'prop-types'

function Welcome({ name, age }) {
  return (
    <h1>
      Hello, {name}! Age: {age}
    </h1>
  )
}

Welcome.propTypes = {
  name: PropTypes.string.isRequired,
  age: PropTypes.number,
}

Welcome.defaultProps = {
  age: 18,
}
```

### Children: `props.children`

컴포넌트 열기/닫기 태그 사이에 전달된 콘텐츠에 접근합니다.

```javascript
// children 을 사용하는 컴포넌트
function Card({ children }) {
  return <div className="card">{children}</div>
}

// 사용법
;<Card>
  <h2>Title</h2>
  <p>Content here</p>
</Card>
```

## 상태 관리 및 훅

### useState 훅: `useState()`

함수형 컴포넌트에 상태를 추가합니다.

```javascript
import React, { useState } from 'react'

function Counter() {
  const [count, setCount] = useState(0)
  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={() => setCount(count + 1)}>Increment</button>
    </div>
  )
}

// 여러 상태 변수
function Form() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
}
```

### useEffect 훅: `useEffect()`

함수형 컴포넌트에서 부수 효과 (side effects) 를 수행합니다.

```javascript
import React, { useState, useEffect } from 'react'

function Timer() {
  const [count, setCount] = useState(0)

  // 렌더링 후마다 실행되는 효과
  useEffect(() => {
    document.title = `Count: ${count}`
  })

  // 정리 (cleanup) 가 있는 효과
  useEffect(() => {
    const timer = setInterval(() => setCount((c) => c + 1), 1000)
    return () => clearInterval(timer)
  }, [])
}
```

### 클래스 상태: `this.state` / `setState()`

클래스 컴포넌트에서 상태를 관리합니다.

```javascript
class Counter extends React.Component {
  constructor(props) {
    super(props)
    this.state = { count: 0 }
  }
  increment = () => {
    this.setState({ count: this.state.count + 1 })
  }
  render() {
    return (
      <div>
        <p>Count: {this.state.count}</p>
        <button onClick={this.increment}>Increment</button>
      </div>
    )
  }
}
```

### 사용자 정의 훅: `use...`

재사용 가능한 상태 기반 로직을 생성합니다.

```javascript
// 사용자 정의 훅
function useCounter(initialValue = 0) {
  const [count, setCount] = useState(initialValue)
  const increment = () => setCount(count + 1)
  const decrement = () => setCount(count - 1)
  const reset = () => setCount(initialValue)
  return { count, increment, decrement, reset }
}

// 사용법
function Counter() {
  const { count, increment, decrement, reset } = useCounter(0)
  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={increment}>+</button>
      <button onClick={decrement}>-</button>
      <button onClick={reset}>Reset</button>
    </div>
  )
}
```

## 이벤트 처리

### 클릭 이벤트: `onClick`

버튼 클릭 및 요소 상호 작용을 처리합니다.

```javascript
function Button() {
  const handleClick = () => {
    alert('Button clicked!')
  }
  return <button onClick={handleClick}>Click me</button>
}

// 인라인 이벤트 핸들러
function Button() {
  return <button onClick={() => alert('Clicked!')}>Click me</button>
}

// 매개변수 전달
function Button() {
  const handleClick = (message) => {
    alert(message)
  }
  return <button onClick={() => handleClick('Hello!')}>Click me</button>
}
```

### 폼 이벤트: `onChange` / `onSubmit`

폼 입력 및 제출을 처리합니다.

```javascript
function Form() {
  const [value, setValue] = useState('')
  const handleChange = (e) => {
    setValue(e.target.value)
  }
  const handleSubmit = (e) => {
    e.preventDefault()
    console.log('Submitted:', value)
  }
  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={value}
        onChange={handleChange}
        placeholder="Enter text"
      />
      <button type="submit">Submit</button>
    </form>
  )
}
```

### 이벤트 객체: `event.target` / `event.preventDefault()`

이벤트 속성에 접근하고 기본 동작을 제어합니다.

```javascript
function handleInput(event) {
  console.log('Input value:', event.target.value)
  console.log('Input name:', event.target.name)
}

function handleFormSubmit(event) {
  event.preventDefault() // 폼 제출 방지
  console.log('Form submitted')
}

// 이벤트 위임
function List() {
  const handleClick = (event) => {
    if (event.target.tagName === 'BUTTON') {
      console.log('Button clicked:', event.target.textContent)
    }
  }
  return (
    <div onClick={handleClick}>
      <button>Button 1</button>
      <button>Button 2</button>
    </div>
  )
}
```

### 키보드 이벤트: `onKeyDown` / `onKeyUp`

키보드 상호 작용에 응답합니다.

```javascript
function KeyboardHandler() {
  const handleKeyDown = (event) => {
    if (event.key === 'Enter') {
      console.log('Enter key pressed')
    }
    if (event.ctrlKey && event.key === 's') {
      event.preventDefault()
      console.log('Ctrl+S pressed')
    }
  }
  return <input onKeyDown={handleKeyDown} placeholder="Type here..." />
}
```

## 조건부 렌더링

### 조건부 연산자: `&&` / `?:`

조건에 따라 요소를 표시/숨깁니다.

```javascript
function Greeting({ user }) {
  return (
    <div>
      {user && <h1>Welcome, {user.name}!</h1>}
      {!user && <h1>Please log in</h1>}
    </div>
  )
}

// 삼항 연산자
function Status({ isOnline }) {
  return <div>User is {isOnline ? 'online' : 'offline'}</div>
}
```

### If/Else 로직: `if` 문

복잡한 조건 처리를 위해 전통적인 JavaScript 로직을 사용합니다.

```javascript
function UserProfile({ user, isAdmin }) {
  if (!user) {
    return <div>Loading...</div>
  }
  if (isAdmin) {
    return <AdminPanel user={user} />
  }
  return <UserPanel user={user} />
}

// 조기 반환 패턴
function Component({ data }) {
  if (!data) return null
  if (data.error) return <ErrorMessage />
  return <DataDisplay data={data} />
}
```

### Switch 문: `switch`

여러 조건을 효율적으로 처리합니다.

```javascript
function StatusIcon({ status }) {
  switch (status) {
    case 'loading':
      return <Spinner />
    case 'success':
      return <CheckIcon />
    case 'error':
      return <ErrorIcon />
    default:
      return null
  }
}
```

### 동적 스타일: 조건부 CSS

컴포넌트 상태 또는 props 에 따라 스타일을 적용합니다.

```javascript
function Button({ variant, disabled }) {
  const className = `btn ${variant} ${disabled ? 'disabled' : ''}`
  return (
    <button
      className={className}
      style={{
        backgroundColor: variant === 'primary' ? 'blue' : 'gray',
        opacity: disabled ? 0.5 : 1,
      }}
      disabled={disabled}
    >
      Click me
    </button>
  )
}
```

## 목록 렌더링 및 키

### Map 함수: `array.map()`

배열 데이터로부터 컴포넌트 목록을 렌더링합니다.

```javascript
function TodoList({ todos }) {
  return (
    <ul>
      {todos.map((todo) => (
        <li key={todo.id}>{todo.text}</li>
      ))}
    </ul>
  )
}

// 인덱스 포함 (가능하면 피해야 함)
function ItemList({ items }) {
  return (
    <ul>
      {items.map((item, index) => (
        <li key={index}>{item}</li>
      ))}
    </ul>
  )
}
```

### 키: `key` prop

목록 항목을 최적화하기 위해 고유 식별자를 제공합니다.

```javascript
// 좋음: 고유 ID 사용
function UserList({ users }) {
  return (
    <ul>
      {users.map((user) => (
        <li key={user.id}>
          <UserCard user={user} />
        </li>
      ))}
    </ul>
  )
}

// 복합 키 생성
function CommentList({ comments }) {
  return (
    <div>
      {comments.map((comment) => (
        <Comment key={`${comment.postId}-${comment.id}`} comment={comment} />
      ))}
    </div>
  )
}
```

### 필터 및 Map: 배열 메서드

목록을 렌더링하기 전에 배열을 처리합니다.

```javascript
function TaskList({ tasks, showCompleted }) {
  const filteredTasks = showCompleted
    ? tasks
    : tasks.filter((task) => !task.completed)
  return (
    <ul>
      {filteredTasks.map((task) => (
        <li key={task.id} className={task.completed ? 'completed' : ''}>
          {task.title}
        </li>
      ))}
    </ul>
  )
}
```

### 빈 상태: 빈 배열 처리

목록이 비어 있을 때 적절한 콘텐츠를 표시합니다.

```javascript
function ProductList({ products }) {
  if (products.length === 0) {
    return <div>No products found.</div>
  }
  return (
    <div>
      {products.map((product) => (
        <ProductCard key={product.id} product={product} />
      ))}
    </div>
  )
}
```

## 성능 최적화

### React.memo: `React.memo()`

함수형 컴포넌트의 불필요한 리렌더링을 방지합니다.

```javascript
const ExpensiveComponent = React.memo(function ExpensiveComponent({ data }) {
  return <div>{/* Complex rendering logic */}</div>
})

// 사용자 정의 비교 사용
const MyComponent = React.memo(
  function MyComponent({ user }) {
    return <div>{user.name}</div>
  },
  (prevProps, nextProps) => {
    return prevProps.user.id === nextProps.user.id
  },
)
```

### useMemo 훅: `useMemo()`

비용이 많이 드는 계산을 메모이제이션합니다.

```javascript
function ExpensiveList({ items, searchTerm }) {
  const filteredItems = useMemo(() => {
    return items.filter((item) =>
      item.name.toLowerCase().includes(searchTerm.toLowerCase()),
    )
  }, [items, searchTerm])
  return (
    <ul>
      {filteredItems.map((item) => (
        <li key={item.id}>{item.name}</li>
      ))}
    </ul>
  )
}
```

### useCallback 훅: `useCallback()`

불필요한 리렌더링을 방지하기 위해 함수 참조를 메모이제이션합니다.

```javascript
function Parent({ items }) {
  const [count, setCount] = useState(0)
  const handleItemClick = useCallback((itemId) => {
    console.log('Item clicked:', itemId)
  }, []) // 빈 의존성 배열
  return (
    <div>
      <button onClick={() => setCount(count + 1)}>Count: {count}</button>
      <ItemList items={items} onItemClick={handleItemClick} />
    </div>
  )
}
```

### 지연 로딩: `React.lazy()` / `Suspense`

번들 크기를 줄이기 위해 필요할 때만 컴포넌트를 로드합니다.

```javascript
const LazyComponent = React.lazy(() => import('./LazyComponent'))

function App() {
  return (
    <div>
      <Suspense fallback={<div>Loading...</div>}>
        <LazyComponent />
      </Suspense>
    </div>
  )
}
```

## 컴포넌트 통신

### Props Down: 부모에서 자식으로

부모 컴포넌트에서 자식 컴포넌트로 데이터를 전달합니다.

```javascript
function Parent() {
  const [user, setUser] = useState({ name: 'John', age: 30 })
  return (
    <div>
      <ChildComponent user={user} />
      <AnotherChild userName={user.name} />
    </div>
  )
}

function ChildComponent({ user }) {
  return <div>Hello, {user.name}!</div>
}
```

### Callbacks Up: 자식에서 부모로

자식 컴포넌트에서 부모 컴포넌트로 데이터를 다시 보냅니다.

```javascript
function Parent() {
  const [message, setMessage] = useState('')
  const handleChildMessage = (msg) => {
    setMessage(msg)
  }
  return (
    <div>
      <p>Message: {message}</p>
      <Child onMessage={handleChildMessage} />
    </div>
  )
}

function Child({ onMessage }) {
  return (
    <button onClick={() => onMessage('Hello from child!')}>Send Message</button>
  )
}
```

### Context API: `createContext` / `useContext`

prop 드릴링 없이 여러 컴포넌트에 걸쳐 상태를 공유합니다.

```javascript
const UserContext = React.createContext()

function App() {
  const [user, setUser] = useState({ name: 'John' })
  return (
    <UserContext.Provider value={{ user, setUser }}>
      <Header />
      <Main />
    </UserContext.Provider>
  )
}

function Header() {
  const { user } = useContext(UserContext)
  return <h1>Welcome, {user.name}!</h1>
}
```

### Refs: `useRef` / `forwardRef`

DOM 요소에 접근하거나 가변 값을 저장합니다.

```javascript
function TextInput() {
  const inputRef = useRef(null)
  const focusInput = () => {
    inputRef.current.focus()
  }
  return (
    <div>
      <input ref={inputRef} type="text" />
      <button onClick={focusInput}>Focus Input</button>
    </div>
  )
}

// Ref 전달
const FancyInput = forwardRef((props, ref) => (
  <input className="fancy" ref={ref} {...props} />
))
```

## 개발 도구 및 디버깅

### React DevTools: 브라우저 확장 프로그램

React 컴포넌트를 디버깅하고 컴포넌트 트리를 검사합니다.

```javascript
// React DevTools 브라우저 확장 프로그램 설치
// Components 탭: 컴포넌트 계층 구조 검사
// Profiler 탭: 성능 측정

// 콘솔 디버깅
function MyComponent(props) {
  console.log('MyComponent props:', props)
  console.log('MyComponent rendered')
  return <div>{props.children}</div>
}
```

### 에러 경계: `componentDidCatch`

컴포넌트 트리에서 JavaScript 오류를 잡아 대체 UI 를 표시합니다.

```javascript
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false }
  }
  static getDerivedStateFromError(error) {
    return { hasError: true }
  }
  componentDidCatch(error, errorInfo) {
    console.log('Error caught:', error, errorInfo)
  }
  render() {
    if (this.state.hasError) {
      return <h1>Something went wrong.</h1>
    }
    return this.props.children
  }
}
```

### Strict Mode: `React.StrictMode`

개발 중 추가적인 검사 및 경고를 활성화합니다.

```javascript
import React from 'react'
import ReactDOM from 'react-dom'

ReactDOM.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
  document.getElementById('root'),
)
```

### 프로파일링: 성능 측정

컴포넌트 성능을 측정하고 병목 현상을 식별합니다.

```javascript
// React DevTools Profiler 사용
// 프로파일링할 컴포넌트 래핑
import { Profiler } from 'react'

function onRenderCallback(id, phase, actualDuration) {
  console.log('Component', id, 'took', actualDuration, 'ms')
}

;<Profiler id="App" onRender={onRenderCallback}>
  <App />
</Profiler>
```

## React 설치 및 설정

### Create React App: `npx create-react-app`

새로운 React 프로젝트를 빠르게 부트스트랩합니다.

```bash
# 새 React 앱 생성
npx create-react-app my-app
cd my-app

# 개발 서버 시작
npm start

# 프로덕션 빌드
npm run build

# 테스트 실행
npm test
```

### Vite: `npm create vite@latest`

React 프로젝트를 위한 빠른 빌드 도구 및 개발 서버.

```bash
# 새 Vite React 앱 생성
npm create vite@latest my-react-app -- --template react
cd my-react-app
npm install

# 개발 서버 시작
npm run dev

# 프로덕션 빌드
npm run build
```

### 수동 설정 / 가져오기

기존 프로젝트에 React 를 추가하거나 CDN 을 사용합니다.

```bash
# React 및 ReactDOM 설치
npm install react react-dom

# 개발용
npm install --save-dev @vitejs/plugin-react
```

```javascript
// 기본 React 가져오기
import React from 'react'
import ReactDOM from 'react-dom/client'

// DOM 에 렌더링
const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(<App />)
```

## 고급 패턴 및 기능

### 고차 컴포넌트 (HOC)

컴포넌트를 래핑하여 컴포넌트 로직을 재사용합니다.

```javascript
function withLoading(WrappedComponent) {
  return function WithLoadingComponent(props) {
    if (props.isLoading) {
      return <div>Loading...</div>
    }
    return <WrappedComponent {...props} />
  }
}

// 사용법
const UserListWithLoading = withLoading(UserList)
;<UserListWithLoading users={users} isLoading={loading} />
```

### 렌더 프롭 패턴

값을 함수로 전달하는 prop 을 사용하여 컴포넌트 간에 코드를 공유합니다.

```javascript
function DataFetcher({ render, url }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    fetch(url)
      .then((res) => res.json())
      .then((data) => {
        setData(data)
        setLoading(false)
      })
  }, [url])
  return render({ data, loading })
}

// 사용법
;<DataFetcher
  url="/api/users"
  render={({ data, loading }) =>
    loading ? <Spinner /> : <UserList users={data} />
  }
/>
```

### 복합 컴포넌트

응집력 있는 단위로 함께 작동하는 컴포넌트를 생성합니다.

```javascript
function Tabs({ children, activeTab }) {
  return (
    <div className="tabs">
      {React.Children.map(children, (child, index) =>
        React.cloneElement(child, { isActive: index === activeTab }),
      )}
    </div>
  )
}

function Tab({ children, isActive }) {
  return <div className={`tab ${isActive ? 'active' : ''}`}>{children}</div>
}

// 사용법
;<Tabs activeTab={0}>
  <Tab>Tab 1 Content</Tab>
  <Tab>Tab 2 Content</Tab>
</Tabs>
```

### Portal: `ReactDOM.createPortal()`

자식 요소를 부모 컴포넌트 계층 구조 외부의 DOM 노드에 렌더링합니다.

```javascript
import ReactDOM from 'react-dom'

function Modal({ children, isOpen }) {
  if (!isOpen) return null
  return ReactDOM.createPortal(
    <div className="modal-overlay">
      <div className="modal">{children}</div>
    </div>,
    document.getElementById('modal-root'),
  )
}
```

### 상속보다 합성

클래스 상속 대신 합성 패턴을 사용합니다.

```javascript
// 좋음: 합성
function Button({ variant, children, ...props }) {
  return (
    <button className={`btn btn-${variant}`} {...props}>
      {children}
    </button>
  )
}

function IconButton({ icon, children, ...props }) {
  return (
    <Button {...props}>
      <Icon name={icon} />
      {children}
    </Button>
  )
}
```

### 컴포넌트 패턴: 유연한 API

사용하기 쉽고 유연한 컴포넌트 API 를 설계합니다.

```javascript
// 유연한 Card 컴포넌트
function Card({ header, children, footer, variant = 'default' }) {
  return (
    <div className={`card card-${variant}`}>
      {header && <div className="card-header">{header}</div>}
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
    </div>
  )
}

// 사용법
;<Card header={<h3>Title</h3>} footer={<Button>Action</Button>}>
  Card content here
</Card>
```

## 관련 링크

- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/html">HTML 치트 시트</router-link>
- <router-link to="/css">CSS 치트 시트</router-link>
- <router-link to="/web-development">웹 개발 치트 시트</router-link>

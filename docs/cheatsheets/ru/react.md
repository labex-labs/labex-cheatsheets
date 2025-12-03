---
title: 'Шпаргалка по React | LabEx'
description: 'Изучите разработку на React с помощью этой исчерпывающей шпаргалки. Быстрый справочник по хукам React, компонентам, JSX, управлению состоянием, пропсам и современным паттернам фронтенд-разработки.'
pdfUrl: '/cheatsheets/pdf/react-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по React
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/react">Изучите React с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите разработку фронтенда на React с помощью практических лабораторий и сценариев реального мира. LabEx предлагает комплексные курсы по React, охватывающие создание основных компонентов, управление состоянием, хуки, обработку событий и оптимизацию производительности. Освойте создание эффективных и поддерживаемых пользовательских интерфейсов для современных веб-приложений.
</base-disclaimer-content>
</base-disclaimer>

## Создание компонентов и JSX

### Функциональные компоненты: `function` / `=>`

Создавайте компоненты с использованием синтаксиса функций.

```javascript
import React from 'react'

// Объявление функции
function Welcome(props) {
  return <h1>Hello, {props.name}!</h1>
}

// Стрелочная функция
const Welcome = (props) => {
  return <h1>Hello, {props.name}!</h1>
}

// Неявный возврат для простых компонентов
const Greeting = ({ name }) => <h1>Hello, {name}!</h1>
```

### Классовые компоненты: `class extends React.Component`

Создавайте компоненты с использованием синтаксиса классов ES6.

```javascript
import React, { Component } from 'react'

class Welcome extends Component {
  render() {
    return <h1>Hello, {this.props.name}!</h1>
  }
}

// С конструктором
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

### Элементы JSX: `<element>`

Пишите синтаксис, похожий на HTML, внутри JavaScript.

```javascript
// Элемент JSX
const element = <h1>Hello, world!</h1>

// JSX с выражениями
const name = 'John'
const greeting = <h1>Hello, {name}!</h1>

// Многострочный JSX
const element = (
  <div>
    <h1>Welcome!</h1>
    <p>Good to see you here.</p>
  </div>
)
```

### Экспорт компонента: `export default` / `export`

Экспортируйте компоненты для использования в других файлах.

```javascript
// Экспорт по умолчанию
export default function App() {
  return <div>My App</div>
}

// Именованный экспорт
export const Button = () => <button>Click me</button>
```

### Импорт компонента: `import`

Импортируйте компоненты из других файлов.

```javascript
// Импорт компонента по умолчанию
import App from './App'

// Импорт именованного компонента
import { Button } from './Button'

// Импорт нескольких компонентов
import React, { useState, useEffect } from 'react'

// Импорт с псевдонимом
import { Button as MyButton } from './Button'
```

### Фрагмент: `<React.Fragment>` / `<>`

Группируйте элементы без добавления лишних узлов DOM.

```javascript
// Использование React.Fragment
return (
  <React.Fragment>
    <h1>Title</h1>
    <p>Description</p>
  </React.Fragment>
)

// Использование короткого синтаксиса
return (
  <>
    <h1>Title</h1>
    <p>Description</p>
  </>
)
```

## Props и структура компонентов

### Props: `props.name`

Передача данных от родительских компонентов к дочерним.

```javascript
// Получение props
function Welcome(props) {
  return <h1>Hello, {props.name}!</h1>
}

// Деструктуризация props
function Welcome({ name, age }) {
  return (
    <h1>
      Hello, {name}! You are {age} years old.
    </h1>
  )
}

// Значения по умолчанию для props
function Welcome({ name = 'Guest' }) {
  return <h1>Hello, {name}!</h1>
}
```

<BaseQuiz id="react-props-1" correct="B">
  <template #question>
    How do you pass data from a parent component to a child component in React?
  </template>
  
  <BaseQuizOption value="A">Using state variables</BaseQuizOption>
  <BaseQuizOption value="B" correct>Using props</BaseQuizOption>
  <BaseQuizOption value="C">Using refs</BaseQuizOption>
  <BaseQuizOption value="D">Using context API</BaseQuizOption>
  
  <BaseQuizAnswer>
    Props (short for properties) are the primary way to pass data from parent to child components in React. You pass props as attributes when rendering the child component.
  </BaseQuizAnswer>
</BaseQuiz>

### PropTypes: `Component.propTypes`

Проверка типов передаваемых props компонентам (требуется пакет prop-types).

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

Доступ к содержимому, переданному между открывающим и закрывающим тегами компонента.

```javascript
// Компонент, использующий children
function Card({ children }) {
  return <div className="card">{children}</div>
}

// Использование
;<Card>
  <h2>Title</h2>
  <p>Content here</p>
</Card>
```

## Управление состоянием и хуки

### Хук useState: `useState()`

Добавление состояния в функциональные компоненты.

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

// Несколько переменных состояния
function Form() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
}
```

<BaseQuiz id="react-usestate-1" correct="A">
  <template #question>
    What does `useState(0)` return?
  </template>
  
  <BaseQuizOption value="A" correct>An array with the state value and a function to update it</BaseQuizOption>
  <BaseQuizOption value="B">Just the state value</BaseQuizOption>
  <BaseQuizOption value="C">A function to update the state</BaseQuizOption>
  <BaseQuizOption value="D">Nothing, it just sets the state</BaseQuizOption>
  
  <BaseQuizAnswer>
    `useState` returns an array with two elements: the current state value and a function to update it. The initial value (0) is passed as an argument.
  </BaseQuizAnswer>
</BaseQuiz>

### Хук useEffect: `useEffect()`

Выполнение побочных эффектов в функциональных компонентах.

```javascript
import React, { useState, useEffect } from 'react'

function Timer() {
  const [count, setCount] = useState(0)

  // Эффект запускается после каждого рендеринга
  useEffect(() => {
    document.title = `Count: ${count}`
  })

  // Эффект с очисткой
  useEffect(() => {
    const timer = setInterval(() => setCount((c) => c + 1), 1000)
    return () => clearInterval(timer)
  }, [])
}
```

<BaseQuiz id="react-useeffect-1" correct="D">
  <template #question>
    What does the empty dependency array `[]` in `useEffect(() => {...}, [])` mean?
  </template>
  
  <BaseQuizOption value="A">The effect runs on every render</BaseQuizOption>
  <BaseQuizOption value="B">The effect never runs</BaseQuizOption>
  <BaseQuizOption value="C">The effect runs twice</BaseQuizOption>
  <BaseQuizOption value="D" correct>The effect runs only once after the initial render</BaseQuizOption>
  
  <BaseQuizAnswer>
    An empty dependency array means the effect has no dependencies, so it will only run once after the component mounts. This is useful for setup code that should only run once.
  </BaseQuizAnswer>
</BaseQuiz>

### Состояние класса: `this.state` / `setState()`

Управление состоянием в классовых компонентах.

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

### Пользовательские хуки: `use...`

Создание многократно используемой логики состояния.

```javascript
// Пользовательский хук
function useCounter(initialValue = 0) {
  const [count, setCount] = useState(initialValue)
  const increment = () => setCount(count + 1)
  const decrement = () => setCount(count - 1)
  const reset = () => setCount(initialValue)
  return { count, increment, decrement, reset }
}

// Использование
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

## Обработка событий

<BaseQuiz id="react-props-2" correct="A">
  <template #question>
    What is the purpose of PropTypes in React?
  </template>
  
  <BaseQuizOption value="A" correct>To validate the types of props passed to components</BaseQuizOption>
  <BaseQuizOption value="B">To improve component performance</BaseQuizOption>
  <BaseQuizOption value="C">To automatically style components</BaseQuizOption>
  <BaseQuizOption value="D">To make components faster</BaseQuizOption>
  
  <BaseQuizAnswer>
    PropTypes help catch bugs by validating that components receive props of the correct type. They provide runtime type checking and are especially useful during development.
  </BaseQuizAnswer>
</BaseQuiz>

### События клика: `onClick`

Обработка кликов по кнопкам и взаимодействий с элементами.

```javascript
function Button() {
  const handleClick = () => {
    alert('Button clicked!')
  }
  return <button onClick={handleClick}>Click me</button>
}

// Встроенный обработчик событий
function Button() {
  return <button onClick={() => alert('Clicked!')}>Click me</button>
}

// Передача параметров
function Button() {
  const handleClick = (message) => {
    alert(message)
  }
  return <button onClick={() => handleClick('Hello!')}>Click me</button>
}
```

### События формы: `onChange` / `onSubmit`

Обработка ввода данных в формах и их отправки.

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

### Объект события: `event.target` / `event.preventDefault()`

Доступ к свойствам события и управление поведением по умолчанию.

```javascript
function handleInput(event) {
  console.log('Input value:', event.target.value)
  console.log('Input name:', event.target.name)
}

function handleFormSubmit(event) {
  event.preventDefault() // Предотвратить отправку формы
  console.log('Form submitted')
}

// Делегирование событий
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

### События клавиатуры: `onKeyDown` / `onKeyUp`

Реагирование на нажатия клавиш.

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

## Условный рендеринг

### Условные операторы: `&&` / `?:`

Показать/скрыть элементы на основе условий.

```javascript
function Greeting({ user }) {
  return (
    <div>
      {user && <h1>Welcome, {user.name}!</h1>}
      {!user && <h1>Please log in</h1>}
    </div>
  )
}

// Тернарный оператор
function Status({ isOnline }) {
  return <div>User is {isOnline ? 'online' : 'offline'}</div>
}
```

### Логика If/Else: операторы `if`

Использование традиционной логики JavaScript для сложных условий.

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

// Шаблон раннего возврата
function Component({ data }) {
  if (!data) return null
  if (data.error) return <ErrorMessage />
  return <DataDisplay data={data} />
}
```

### Операторы Switch: `switch`

Эффективная обработка множества условий.

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

### Динамические стили: Условный CSS

Применение стилей на основе состояния или props компонента.

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

## Рендеринг списков и ключи

### Функция Map: `array.map()`

Рендеринг списков компонентов из данных массива.

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

// С индексом (избегать, когда это возможно)
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

### Ключи: prop `key`

Предоставление уникальных идентификаторов для элементов списка для оптимизации рендеринга.

```javascript
// Хорошо: использование уникального ID
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

// Создание составных ключей
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

### Filter и Map: Методы массива

Обработка массивов перед их рендерингом.

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

### Состояния пустого списка: Обработка пустых массивов

Отображение соответствующего содержимого, когда списки пусты.

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

## Оптимизация производительности

### React.memo: `React.memo()`

Предотвращение ненужных повторных рендерингов функциональных компонентов.

```javascript
const ExpensiveComponent = React.memo(function ExpensiveComponent({ data }) {
  return <div>{/* Complex rendering logic */}</div>
})

// С пользовательским сравнением
const MyComponent = React.memo(
  function MyComponent({ user }) {
    return <div>{user.name}</div>
  },
  (prevProps, nextProps) => {
    return prevProps.user.id === nextProps.user.id
  },
)
```

### Хук useMemo: `useMemo()`

Мемоизация дорогостоящих вычислений.

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

### Хук useCallback: `useCallback()`

Мемоизация ссылок на функции для предотвращения ненужных повторных рендерингов.

```javascript
function Parent({ items }) {
  const [count, setCount] = useState(0)
  const handleItemClick = useCallback((itemId) => {
    console.log('Item clicked:', itemId)
  }, []) // Пустой массив зависимостей
  return (
    <div>
      <button onClick={() => setCount(count + 1)}>Count: {count}</button>
      <ItemList items={items} onItemClick={handleItemClick} />
    </div>
  )
}
```

### Ленивая загрузка: `React.lazy()` / `Suspense`

Загрузка компонентов только при необходимости для уменьшения размера бандла.

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

## Взаимодействие компонентов

### Props Down: Родитель к Дочернему

Передача данных от родительских компонентов к дочерним.

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

### Callbacks Up: Дочерний к Родительскому

Отправка данных от дочерних компонентов обратно родительским.

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

Совместное использование состояния между несколькими компонентами без "проброса пропсов" (prop drilling).

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

Доступ к элементам DOM или хранение изменяемых значений.

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

// Пересылка refs
const FancyInput = forwardRef((props, ref) => (
  <input className="fancy" ref={ref} {...props} />
))
```

## Инструменты разработки и отладка

### React DevTools: Расширение браузера

Отладка компонентов React и инспекция дерева компонентов.

```javascript
// Установите расширение React DevTools для браузера
// Вкладка Components: Инспекция иерархии компонентов
// Вкладка Profiler: Измерение производительности

// Отладка в консоли
function MyComponent(props) {
  console.log('MyComponent props:', props)
  console.log('MyComponent rendered')
  return <div>{props.children}</div>
}
```

### Границы ошибок: `componentDidCatch`

Перехват ошибок JavaScript в дереве компонентов и отображение резервного UI.

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

Включение дополнительных проверок и предупреждений для режима разработки.

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

### Профилирование: Измерение производительности

Измерение производительности компонентов и выявление узких мест.

```javascript
// Использование React DevTools Profiler
// Обертывание компонентов для профилирования
import { Profiler } from 'react'

function onRenderCallback(id, phase, actualDuration) {
  console.log('Component', id, 'took', actualDuration, 'ms')
}

;<Profiler id="App" onRender={onRenderCallback}>
  <App />
</Profiler>
```

## Установка и настройка React

### Create React App: `npx create-react-app`

Быстрый старт нового проекта React.

```bash
# Создать новое приложение React
npx create-react-app my-app
cd my-app

# Запустить сервер разработки
npm start

# Сборка для продакшена
npm run build

# Запустить тесты
npm test
```

### Vite: `npm create vite@latest`

Быстрый инструмент сборки и сервер разработки для проектов React.

```bash
# Создать новое приложение Vite React
npm create vite@latest my-react-app -- --template react
cd my-react-app
npm install

# Запустить сервер разработки
npm run dev

# Сборка для продакшена
npm run build
```

### Ручная настройка / Импорт

Добавление React в существующий проект или использование CDN.

```bash
# Установить React и ReactDOM
npm install react react-dom

# Для разработки
npm install --save-dev @vitejs/plugin-react
```

```javascript
// Базовый импорт React
import React from 'react'
import ReactDOM from 'react-dom/client'

// Рендеринг в DOM
const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(<App />)
```

## Расширенные шаблоны и функции

### Компонент высшего порядка (HOC)

Повторное использование логики компонентов путем оборачивания компонентов.

```javascript
function withLoading(WrappedComponent) {
  return function WithLoadingComponent(props) {
    if (props.isLoading) {
      return <div>Loading...</div>
    }
    return <WrappedComponent {...props} />
  }
}

// Использование
const UserListWithLoading = withLoading(UserList)
;<UserListWithLoading users={users} isLoading={loading} />
```

### Шаблон Render Props

Совместное использование кода между компонентами с помощью prop, значением которого является функция.

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

// Использование
;<DataFetcher
  url="/api/users"
  render={({ data, loading }) =>
    loading ? <Spinner /> : <UserList users={data} />
  }
/>
```

### Составные компоненты

Создание компонентов, которые работают вместе как единое целое.

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

// Использование
;<Tabs activeTab={0}>
  <Tab>Tab 1 Content</Tab>
  <Tab>Tab 2 Content</Tab>
</Tabs>
```

### Портал: `ReactDOM.createPortal()`

Рендеринг дочерних элементов в узел DOM за пределами иерархии родительского компонента.

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

### Композиция вместо наследования

Использование шаблонов композиции вместо расширения классов.

```javascript
// Хорошо: Композиция
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

### Шаблоны компонентов: Гибкие API

Проектирование API компонентов, которые являются гибкими и простыми в использовании.

```javascript
// Гибкий компонент Card
function Card({ header, children, footer, variant = 'default' }) {
  return (
    <div className={`card card-${variant}`}>
      {header && <div className="card-header">{header}</div>}
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
    </div>
  )
}

// Использование
;<Card header={<h3>Title</h3>} footer={<Button>Action</Button>}>
  Card content here
</Card>
```

## Соответствующие ссылки

- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/html">Шпаргалка по HTML</router-link>
- <router-link to="/css">Шпаргалка по CSS</router-link>
- <router-link to="/web-development">Шпаргалка по веб-разработке</router-link>

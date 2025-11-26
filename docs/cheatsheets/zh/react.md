---
title: 'React 速查表'
description: '使用我们涵盖核心命令、概念和最佳实践的综合 React 速查表，快速掌握 React。'
pdfUrl: '/cheatsheets/pdf/react-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
React 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/react">通过实践实验室学习 React</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 React 前端开发。LabEx 提供全面的 React 课程，涵盖基本的组件创建、状态管理、Hooks、事件处理和性能优化。掌握为现代 Web 应用程序构建高效且可维护的用户界面的技能。
</base-disclaimer-content>
</base-disclaimer>

## 组件创建与 JSX

### 函数式组件：`function` / `=>`

使用函数语法创建组件。

```javascript
import React from 'react'

// 函数声明
function Welcome(props) {
  return <h1>Hello, {props.name}!</h1>
}

// 箭头函数
const Welcome = (props) => {
  return <h1>Hello, {props.name}!</h1>
}

// 简单组件的隐式返回
const Greeting = ({ name }) => <h1>Hello, {name}!</h1>
```

### 类组件：`class extends React.Component`

使用 ES6 类语法创建组件。

```javascript
import React, { Component } from 'react'

class Welcome extends Component {
  render() {
    return <h1>Hello, {this.props.name}!</h1>
  }
}

// 带有构造函数的组件
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

### JSX 元素：`<element>`

在 JavaScript 中编写类似 HTML 的语法。

```javascript
// JSX 元素
const element = <h1>Hello, world!</h1>

// 带有表达式的 JSX
const name = 'John'
const greeting = <h1>Hello, {name}!</h1>

// 多行 JSX
const element = (
  <div>
    <h1>Welcome!</h1>
    <p>Good to see you here.</p>
  </div>
)
```

### 组件导出：`export default` / `export`

导出组件以便在其他文件中使用。

```javascript
// 默认导出
export default function App() {
  return <div>My App</div>
}

// 命名导出
export const Button = () => <button>Click me</button>
```

### 组件导入：`import`

从其他文件中导入组件。

```javascript
// 导入默认组件
import App from './App'

// 导入命名组件
import { Button } from './Button'

// 导入多个组件
import React, { useState, useEffect } from 'react'

// 导入并使用别名
import { Button as MyButton } from './Button'
```

### 片段 (Fragment): `<React.Fragment>` / `<>`

在不添加额外 DOM 节点的情况下对元素进行分组。

```javascript
// 使用 React.Fragment
return (
  <React.Fragment>
    <h1>Title</h1>
    <p>Description</p>
  </React.Fragment>
)

// 使用简写语法
return (
  <>
    <h1>Title</h1>
    <p>Description</p>
  </>
)
```

## Props 与组件结构

### Props: `props.name`

将数据从父组件传递给子组件。

```javascript
// 接收 props
function Welcome(props) {
  return <h1>Hello, {props.name}!</h1>
}

// 解构 props
function Welcome({ name, age }) {
  return (
    <h1>
      Hello, {name}! You are {age} years old.
    </h1>
  )
}

// 默认 props
function Welcome({ name = 'Guest' }) {
  return <h1>Hello, {name}!</h1>
}
```

### PropTypes: `Component.propTypes`

验证传递给组件的 props（需要 prop-types 包）。

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

访问在组件开始和结束标签之间传递的内容。

```javascript
// 使用 children 的组件
function Card({ children }) {
  return <div className="card">{children}</div>
}

// 用法
;<Card>
  <h2>Title</h2>
  <p>Content here</p>
</Card>
```

## 状态管理与 Hooks

### useState Hook: `useState()`

向函数式组件添加状态。

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

// 多个状态变量
function Form() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
}
```

### useEffect Hook: `useEffect()`

在函数式组件中执行副作用操作。

```javascript
import React, { useState, useEffect } from 'react'

function Timer() {
  const [count, setCount] = useState(0)

  // 每次渲染后执行的 Effect
  useEffect(() => {
    document.title = `Count: ${count}`
  })

  // 带有清理函数的 Effect
  useEffect(() => {
    const timer = setInterval(() => setCount((c) => c + 1), 1000)
    return () => clearInterval(timer)
  }, [])
}
```

### 类状态：`this.state` / `setState()`

在类组件中管理状态。

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

### 自定义 Hooks: `use...`

创建可重用的有状态逻辑。

```javascript
// 自定义 Hook
function useCounter(initialValue = 0) {
  const [count, setCount] = useState(initialValue)
  const increment = () => setCount(count + 1)
  const decrement = () => setCount(count - 1)
  const reset = () => setCount(initialValue)
  return { count, increment, decrement, reset }
}

// 用法
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

## 事件处理

### 点击事件：`onClick`

处理按钮点击和元素交互。

```javascript
function Button() {
  const handleClick = () => {
    alert('Button clicked!')
  }
  return <button onClick={handleClick}>Click me</button>
}

// 内联事件处理函数
function Button() {
  return <button onClick={() => alert('Clicked!')}>Click me</button>
}

// 传递参数
function Button() {
  const handleClick = (message) => {
    alert(message)
  }
  return <button onClick={() => handleClick('Hello!')}>Click me</button>
}
```

### 表单事件：`onChange` / `onSubmit`

处理表单输入和提交。

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

### 事件对象：`event.target` / `event.preventDefault()`

访问事件属性并控制默认行为。

```javascript
function handleInput(event) {
  console.log('Input value:', event.target.value)
  console.log('Input name:', event.target.name)
}

function handleFormSubmit(event) {
  event.preventDefault() // 阻止表单提交
  console.log('Form submitted')
}

// 事件委托
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

### 键盘事件：`onKeyDown` / `onKeyUp`

响应键盘交互。

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

## 条件渲染

### 条件运算符：`&&` / `?:`

根据条件显示/隐藏元素。

```javascript
function Greeting({ user }) {
  return (
    <div>
      {user && <h1>Welcome, {user.name}!</h1>}
      {!user && <h1>Please log in</h1>}
    </div>
  )
}

// 三元运算符
function Status({ isOnline }) {
  return <div>User is {isOnline ? 'online' : 'offline'}</div>
}
```

### If/Else 逻辑：`if` 语句

使用传统的 JavaScript 逻辑处理复杂条件。

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

// 提前返回模式
function Component({ data }) {
  if (!data) return null
  if (data.error) return <ErrorMessage />
  return <DataDisplay data={data} />
}
```

### Switch 语句：`switch`

高效处理多个条件。

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

### 动态样式：条件 CSS

根据组件状态或 props 应用样式。

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

## 列表渲染与 Keys

### Map 函数：`array.map()`

从数组数据渲染组件列表。

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

// 使用索引（应尽量避免）
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

### Keys: `key` 属性

为列表项提供唯一的标识符以优化渲染。

```javascript
// 好：使用唯一 ID
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

// 创建复合 Key
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

### Filter 与 Map: 数组方法

在渲染前处理数组。

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

### 空状态：处理空数组

在列表为空时显示适当的内容。

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

## 性能优化

### React.memo: `React.memo()`

防止函数式组件不必要的重新渲染。

```javascript
const ExpensiveComponent = React.memo(function ExpensiveComponent({ data }) {
  return <div>{/* 复杂的渲染逻辑 */}</div>
})

// 使用自定义比较函数
const MyComponent = React.memo(
  function MyComponent({ user }) {
    return <div>{user.name}</div>
  },
  (prevProps, nextProps) => {
    return prevProps.user.id === nextProps.user.id
  },
)
```

### useMemo Hook: `useMemo()`

记忆化昂贵的计算。

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

### useCallback Hook: `useCallback()`

记忆化函数引用，以防止不必要的重新渲染。

```javascript
function Parent({ items }) {
  const [count, setCount] = useState(0)
  const handleItemClick = useCallback((itemId) => {
    console.log('Item clicked:', itemId)
  }, []) // 空依赖数组
  return (
    <div>
      <button onClick={() => setCount(count + 1)}>Count: {count}</button>
      <ItemList items={items} onItemClick={handleItemClick} />
    </div>
  )
}
```

### 懒加载：`React.lazy()` / `Suspense`

仅在需要时加载组件，以减小包大小。

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

## 组件通信

### Props 向下传递：父组件到子组件

将数据从父组件传递给子组件。

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

### 回调向上：子组件到父组件

将数据从子组件发送回父组件。

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

在不进行 Prop 逐层传递的情况下共享跨多个组件的状态。

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

访问 DOM 元素或存储可变值。

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

// 转发 Ref
const FancyInput = forwardRef((props, ref) => (
  <input className="fancy" ref={ref} {...props} />
))
```

## 开发工具与调试

### React DevTools: 浏览器扩展

调试 React 组件并检查组件树。

```javascript
// 安装 React DevTools 浏览器扩展
// Components 选项卡：检查组件层级结构
// Profiler 选项卡：测量性能

// 控制台调试
function MyComponent(props) {
  console.log('MyComponent props:', props)
  console.log('MyComponent rendered')
  return <div>{props.children}</div>
}
```

### 错误边界 (Error Boundaries): `componentDidCatch`

捕获组件树中的 JavaScript 错误并显示回退 UI。

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

### 严格模式：`React.StrictMode`

为开发启用额外的检查和警告。

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

### 分析 (Profiling): 性能测量

测量组件性能并识别瓶颈。

```javascript
// 使用 React DevTools Profiler
// 包裹需要分析的组件
import { Profiler } from 'react'

function onRenderCallback(id, phase, actualDuration) {
  console.log('Component', id, 'took', actualDuration, 'ms')
}

;<Profiler id="App" onRender={onRenderCallback}>
  <App />
</Profiler>
```

## React 安装与设置

### Create React App: `npx create-react-app`

快速启动一个新的 React 项目。

```bash
# 创建新的 React 应用
npx create-react-app my-app
cd my-app

# 启动开发服务器
npm start

# 构建生产版本
npm run build

# 运行测试
npm test
```

### Vite: `npm create vite@latest`

用于 React 项目的快速构建工具和开发服务器。

```bash
# 创建新的 Vite React 应用
npm create vite@latest my-react-app -- --template react
cd my-react-app
npm install

# 启动开发服务器
npm run dev

# 构建生产版本
npm run build
```

### 手动设置 / 导入

将 React 添加到现有项目或使用 CDN。

```bash
# 安装 React 和 ReactDOM
npm install react react-dom

# 用于开发
npm install --save-dev @vitejs/plugin-react
```

```javascript
// 基础 React 导入
import React from 'react'
import ReactDOM from 'react-dom/client'

// 渲染到 DOM
const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(<App />)
```

## 高级模式与特性

### 高阶组件 (HOC)

通过包装组件来重用组件逻辑。

```javascript
function withLoading(WrappedComponent) {
  return function WithLoadingComponent(props) {
    if (props.isLoading) {
      return <div>Loading...</div>
    }
    return <WrappedComponent {...props} />
  }
}

// 用法
const UserListWithLoading = withLoading(UserList)
;<UserListWithLoading users={users} isLoading={loading} />
```

### Render Props 模式

通过将函数作为 prop 值来在组件之间共享代码。

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

// 用法
;<DataFetcher
  url="/api/users"
  render={({ data, loading }) =>
    loading ? <Spinner /> : <UserList users={data} />
  }
/>
```

### 复合组件 (Compound Components)

创建协同工作的组件单元。

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

// 用法
;<Tabs activeTab={0}>
  <Tab>Tab 1 Content</Tab>
  <Tab>Tab 2 Content</Tab>
</Tabs>
```

### Portal: `ReactDOM.createPortal()`

将子组件渲染到父组件层次结构之外的 DOM 节点中。

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

### 组合优于继承

使用组合模式而不是继承类。

```javascript
// 好：组合
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

### 组件模式：灵活的 API

设计灵活且易于使用的组件 API。

```javascript
// 灵活的 Card 组件
function Card({ header, children, footer, variant = 'default' }) {
  return (
    <div className={`card card-${variant}`}>
      {header && <div className="card-header">{header}</div>}
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
    </div>
  )
}

// 用法
;<Card header={<h3>Title</h3>} footer={<Button>Action</Button>}>
  Card content here
</Card>
```

## 相关链接

- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/html">HTML 速查表</router-link>
- <router-link to="/css">CSS 速查表</router-link>
- <router-link to="/web-development">Web 开发速查表</router-link>

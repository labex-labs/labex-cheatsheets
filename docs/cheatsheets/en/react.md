---
title: 'React Cheatsheet | LabEx'
description: 'Learn React development with this comprehensive cheatsheet. Quick reference for React hooks, components, JSX, state management, props, and modern frontend development patterns.'
pdfUrl: '/cheatsheets/pdf/react-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
React Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/react">Learn React with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn React frontend development through hands-on labs and real-world scenarios. LabEx provides comprehensive React courses covering essential component creation, state management, hooks, event handling, and performance optimization. Master building efficient and maintainable user interfaces for modern web applications.
</base-disclaimer-content>
</base-disclaimer>

## Component Creation & JSX

### Functional Components: `function` / `=>`

Create components using function syntax.

```javascript
import React from 'react'

// Function declaration
function Welcome(props) {
  return <h1>Hello, {props.name}!</h1>
}

// Arrow function
const Welcome = (props) => {
  return <h1>Hello, {props.name}!</h1>
}

// Implicit return for simple components
const Greeting = ({ name }) => <h1>Hello, {name}!</h1>
```

### Class Components: `class extends React.Component`

Create components using ES6 class syntax.

```javascript
import React, { Component } from 'react'

class Welcome extends Component {
  render() {
    return <h1>Hello, {this.props.name}!</h1>
  }
}

// With constructor
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

### JSX Elements: `<element>`

Write HTML-like syntax within JavaScript.

```javascript
// JSX element
const element = <h1>Hello, world!</h1>

// JSX with expressions
const name = 'John'
const greeting = <h1>Hello, {name}!</h1>

// Multi-line JSX
const element = (
  <div>
    <h1>Welcome!</h1>
    <p>Good to see you here.</p>
  </div>
)
```

### Component Export: `export default` / `export`

Export components for use in other files.

```javascript
// Default export
export default function App() {
  return <div>My App</div>
}

// Named export
export const Button = () => <button>Click me</button>
```

### Component Import: `import`

Import components from other files.

```javascript
// Import default component
import App from './App'

// Import named component
import { Button } from './Button'

// Import multiple components
import React, { useState, useEffect } from 'react'

// Import with alias
import { Button as MyButton } from './Button'
```

### Fragment: `<React.Fragment>` / `<>`

Group elements without adding extra DOM nodes.

```javascript
// Using React.Fragment
return (
  <React.Fragment>
    <h1>Title</h1>
    <p>Description</p>
  </React.Fragment>
)

// Using short syntax
return (
  <>
    <h1>Title</h1>
    <p>Description</p>
  </>
)
```

## Props & Component Structure

### Props: `props.name`

Pass data from parent to child components.

```javascript
// Receiving props
function Welcome(props) {
  return <h1>Hello, {props.name}!</h1>
}

// Destructuring props
function Welcome({ name, age }) {
  return (
    <h1>
      Hello, {name}! You are {age} years old.
    </h1>
  )
}

// Default props
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

Validate props passed to components (requires prop-types package).

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

Access content passed between component opening/closing tags.

```javascript
// Component that uses children
function Card({ children }) {
  return <div className="card">{children}</div>
}

// Usage
;<Card>
  <h2>Title</h2>
  <p>Content here</p>
</Card>
```

## State Management & Hooks

### useState Hook: `useState()`

Add state to functional components.

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

// Multiple state variables
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

### useEffect Hook: `useEffect()`

Perform side effects in functional components.

```javascript
import React, { useState, useEffect } from 'react'

function Timer() {
  const [count, setCount] = useState(0)

  // Effect runs after every render
  useEffect(() => {
    document.title = `Count: ${count}`
  })

  // Effect with cleanup
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

### Class State: `this.state` / `setState()`

Manage state in class components.

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

### Custom Hooks: `use...`

Create reusable stateful logic.

```javascript
// Custom hook
function useCounter(initialValue = 0) {
  const [count, setCount] = useState(initialValue)
  const increment = () => setCount(count + 1)
  const decrement = () => setCount(count - 1)
  const reset = () => setCount(initialValue)
  return { count, increment, decrement, reset }
}

// Usage
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

## Event Handling

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

### Click Events: `onClick`

Handle button clicks and element interactions.

```javascript
function Button() {
  const handleClick = () => {
    alert('Button clicked!')
  }
  return <button onClick={handleClick}>Click me</button>
}

// Inline event handler
function Button() {
  return <button onClick={() => alert('Clicked!')}>Click me</button>
}

// Passing parameters
function Button() {
  const handleClick = (message) => {
    alert(message)
  }
  return <button onClick={() => handleClick('Hello!')}>Click me</button>
}
```

### Form Events: `onChange` / `onSubmit`

Handle form inputs and submissions.

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

### Event Object: `event.target` / `event.preventDefault()`

Access event properties and control default behavior.

```javascript
function handleInput(event) {
  console.log('Input value:', event.target.value)
  console.log('Input name:', event.target.name)
}

function handleFormSubmit(event) {
  event.preventDefault() // Prevent form submission
  console.log('Form submitted')
}

// Event delegation
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

### Keyboard Events: `onKeyDown` / `onKeyUp`

Respond to keyboard interactions.

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

## Conditional Rendering

### Conditional Operators: `&&` / `?:`

Show/hide elements based on conditions.

```javascript
function Greeting({ user }) {
  return (
    <div>
      {user && <h1>Welcome, {user.name}!</h1>}
      {!user && <h1>Please log in</h1>}
    </div>
  )
}

// Ternary operator
function Status({ isOnline }) {
  return <div>User is {isOnline ? 'online' : 'offline'}</div>
}
```

### If/Else Logic: `if` statements

Use traditional JavaScript logic for complex conditions.

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

// Early return pattern
function Component({ data }) {
  if (!data) return null
  if (data.error) return <ErrorMessage />
  return <DataDisplay data={data} />
}
```

### Switch Statements: `switch`

Handle multiple conditions efficiently.

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

### Dynamic Styles: Conditional CSS

Apply styles based on component state or props.

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

## List Rendering & Keys

### Map Function: `array.map()`

Render lists of components from array data.

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

// With index (avoid when possible)
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

### Keys: `key` prop

Provide unique identifiers for list items to optimize rendering.

```javascript
// Good: using unique ID
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

// Creating compound keys
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

### Filter & Map: Array methods

Process arrays before rendering them.

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

### Empty States: Handling empty arrays

Display appropriate content when lists are empty.

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

## Performance Optimization

### React.memo: `React.memo()`

Prevent unnecessary re-renders of functional components.

```javascript
const ExpensiveComponent = React.memo(function ExpensiveComponent({ data }) {
  return <div>{/* Complex rendering logic */}</div>
})

// With custom comparison
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

Memoize expensive calculations.

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

Memoize function references to prevent unnecessary re-renders.

```javascript
function Parent({ items }) {
  const [count, setCount] = useState(0)
  const handleItemClick = useCallback((itemId) => {
    console.log('Item clicked:', itemId)
  }, []) // Empty dependency array
  return (
    <div>
      <button onClick={() => setCount(count + 1)}>Count: {count}</button>
      <ItemList items={items} onItemClick={handleItemClick} />
    </div>
  )
}
```

### Lazy Loading: `React.lazy()` / `Suspense`

Load components only when needed to reduce bundle size.

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

## Component Communication

### Props Down: Parent to Child

Pass data from parent components to child components.

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

### Callbacks Up: Child to Parent

Send data from child components back to parent components.

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

Share state across multiple components without prop drilling.

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

Access DOM elements or store mutable values.

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

// Forward refs
const FancyInput = forwardRef((props, ref) => (
  <input className="fancy" ref={ref} {...props} />
))
```

## Development Tools & Debugging

### React DevTools: Browser Extension

Debug React components and inspect component tree.

```javascript
// Install React DevTools browser extension
// Components tab: Inspect component hierarchy
// Profiler tab: Measure performance

// Console debugging
function MyComponent(props) {
  console.log('MyComponent props:', props)
  console.log('MyComponent rendered')
  return <div>{props.children}</div>
}
```

### Error Boundaries: `componentDidCatch`

Catch JavaScript errors in component tree and display fallback UI.

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

Enable additional checks and warnings for development.

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

### Profiling: Performance measurement

Measure component performance and identify bottlenecks.

```javascript
// Using React DevTools Profiler
// Wrap components to profile
import { Profiler } from 'react'

function onRenderCallback(id, phase, actualDuration) {
  console.log('Component', id, 'took', actualDuration, 'ms')
}

;<Profiler id="App" onRender={onRenderCallback}>
  <App />
</Profiler>
```

## React Installation & Setup

### Create React App: `npx create-react-app`

Quickly bootstrap a new React project.

```bash
# Create new React app
npx create-react-app my-app
cd my-app

# Start development server
npm start

# Build for production
npm run build

# Run tests
npm test
```

### Vite: `npm create vite@latest`

Fast build tool and dev server for React projects.

```bash
# Create new Vite React app
npm create vite@latest my-react-app -- --template react
cd my-react-app
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

### Manual Setup / Import

Add React to existing project or use CDN.

```bash
# Install React and ReactDOM
npm install react react-dom

# For development
npm install --save-dev @vitejs/plugin-react
```

```javascript
// Basic React import
import React from 'react'
import ReactDOM from 'react-dom/client'

// Render to DOM
const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(<App />)
```

## Advanced Patterns & Features

### Higher-Order Components (HOC)

Reuse component logic by wrapping components.

```javascript
function withLoading(WrappedComponent) {
  return function WithLoadingComponent(props) {
    if (props.isLoading) {
      return <div>Loading...</div>
    }
    return <WrappedComponent {...props} />
  }
}

// Usage
const UserListWithLoading = withLoading(UserList)
;<UserListWithLoading users={users} isLoading={loading} />
```

### Render Props Pattern

Share code between components using a prop whose value is a function.

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

// Usage
;<DataFetcher
  url="/api/users"
  render={({ data, loading }) =>
    loading ? <Spinner /> : <UserList users={data} />
  }
/>
```

### Compound Components

Create components that work together as a cohesive unit.

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

// Usage
;<Tabs activeTab={0}>
  <Tab>Tab 1 Content</Tab>
  <Tab>Tab 2 Content</Tab>
</Tabs>
```

### Portal: `ReactDOM.createPortal()`

Render children into a DOM node outside the parent component's hierarchy.

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

### Composition over Inheritance

Use composition patterns instead of extending classes.

```javascript
// Good: Composition
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

### Component Patterns: Flexible APIs

Design component APIs that are flexible and easy to use.

```javascript
// Flexible Card component
function Card({ header, children, footer, variant = 'default' }) {
  return (
    <div className={`card card-${variant}`}>
      {header && <div className="card-header">{header}</div>}
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
    </div>
  )
}

// Usage
;<Card header={<h3>Title</h3>} footer={<Button>Action</Button>}>
  Card content here
</Card>
```

## Relevant Links

- <router-link to="/javascript">JavaScript Cheatsheet</router-link>
- <router-link to="/html">HTML Cheatsheet</router-link>
- <router-link to="/css">CSS Cheatsheet</router-link>
- <router-link to="/web-development">Web Development Cheatsheet</router-link>

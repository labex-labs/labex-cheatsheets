---
title: 'Hoja de Trucos de React'
description: 'Aprenda React con nuestra hoja de trucos completa que cubre comandos esenciales, conceptos y mejores prácticas.'
pdfUrl: '/cheatsheets/pdf/react-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de React
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/react">Aprende Desarrollo Frontend con React y Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda desarrollo frontend con React a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de React que cubren la creación esencial de componentes, gestión de estado, hooks, manejo de eventos y optimización del rendimiento. Domine la construcción de interfaces de usuario eficientes y mantenibles para aplicaciones web modernas.
</base-disclaimer-content>
</base-disclaimer>

## Creación de Componentes y JSX

### Componentes Funcionales: `function` / `=>`

Cree componentes usando sintaxis de función.

```javascript
import React from 'react'

// Declaración de función
function Welcome(props) {
  return <h1>Hola, {props.name}!</h1>
}

// Función de flecha
const Welcome = (props) => {
  return <h1>Hola, {props.name}!</h1>
}

// Retorno implícito para componentes simples
const Greeting = ({ name }) => <h1>Hola, {name}!</h1>
```

### Componentes de Clase: `class extends React.Component`

Cree componentes usando sintaxis de clase ES6.

```javascript
import React, { Component } from 'react'

class Welcome extends Component {
  render() {
    return <h1>Hola, {this.props.name}!</h1>
  }
}

// Con constructor
class Counter extends Component {
  constructor(props) {
    super(props)
    this.state = { count: 0 }
  }
  render() {
    return <div>Cuenta: {this.state.count}</div>
  }
}
```

### Elementos JSX: `<element>`

Escriba sintaxis similar a HTML dentro de JavaScript.

```javascript
// Elemento JSX
const element = <h1>Hola, mundo!</h1>

// JSX con expresiones
const name = 'John'
const greeting = <h1>Hola, {name}!</h1>

// JSX de varias líneas
const element = (
  <div>
    <h1>¡Bienvenido!</h1>
    <p>Me alegra verte aquí.</p>
  </div>
)
```

### Exportación de Componentes: `export default` / `export`

Exporte componentes para su uso en otros archivos.

```javascript
// Exportación por defecto
export default function App() {
  return <div>Mi App</div>
}

// Exportación nombrada
export const Button = () => <button>Haz clic</button>
```

### Importación de Componentes: `import`

Importe componentes desde otros archivos.

```javascript
// Importar componente por defecto
import App from './App'

// Importar componente nombrado
import { Button } from './Button'

// Importar múltiples componentes
import React, { useState, useEffect } from 'react'

// Importar con alias
import { Button as MyButton } from './Button'
```

### Fragmento: `<React.Fragment>` / `<>`

Agrupe elementos sin añadir nodos DOM adicionales.

```javascript
// Usando React.Fragment
return (
  <React.Fragment>
    <h1>Título</h1>
    <p>Descripción</p>
  </React.Fragment>
)

// Usando sintaxis corta
return (
  <>
    <h1>Título</h1>
    <p>Descripción</p>
  </>
)
```

## Props y Estructura de Componentes

### Props: `props.name`

Pase datos de componentes padre a hijo.

```javascript
// Recibiendo props
function Welcome(props) {
  return <h1>Hola, {props.name}!</h1>
}

// Desestructuración de props
function Welcome({ name, age }) {
  return (
    <h1>
      Hola, {name}! Tienes {age} años.
    </h1>
  )
}

// Props por defecto
function Welcome({ name = 'Invitado' }) {
  return <h1>Hola, {name}!</h1>
}
```

### PropTypes: `Component.propTypes`

Valide las props pasadas a los componentes (requiere el paquete prop-types).

```javascript
import PropTypes from 'prop-types'

function Welcome({ name, age }) {
  return (
    <h1>
      Hola, {name}! Edad: {age}
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

Acceda al contenido pasado entre las etiquetas de apertura/cierre del componente.

```javascript
// Componente que usa children
function Card({ children }) {
  return <div className="card">{children}</div>
}

// Uso
;<Card>
  <h2>Título</h2>
  <p>Contenido aquí</p>
</Card>
```

## Gestión de Estado y Hooks

### Hook useState: `useState()`

Añada estado a componentes funcionales.

```javascript
import React, { useState } from 'react'

function Counter() {
  const [count, setCount] = useState(0)
  return (
    <div>
      <p>Cuenta: {count}</p>
      <button onClick={() => setCount(count + 1)}>Incrementar</button>
    </div>
  )
}

// Múltiples variables de estado
function Form() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
}
```

### Hook useEffect: `useEffect()`

Realice efectos secundarios en componentes funcionales.

```javascript
import React, { useState, useEffect } from 'react'

function Timer() {
  const [count, setCount] = useState(0)

  // El efecto se ejecuta después de cada renderizado
  useEffect(() => {
    document.title = `Cuenta: ${count}`
  })

  // Efecto con limpieza
  useEffect(() => {
    const timer = setInterval(() => setCount((c) => c + 1), 1000)
    return () => clearInterval(timer)
  }, [])
}
```

### Estado de Clase: `this.state` / `setState()`

Administre el estado en componentes de clase.

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
        <p>Cuenta: {this.state.count}</p>
        <button onClick={this.increment}>Incrementar</button>
      </div>
    )
  }
}
```

### Hooks Personalizados: `use...`

Cree lógica de estado reutilizable.

```javascript
// Hook personalizado
function useCounter(initialValue = 0) {
  const [count, setCount] = useState(initialValue)
  const increment = () => setCount(count + 1)
  const decrement = () => setCount(count - 1)
  const reset = () => setCount(initialValue)
  return { count, increment, decrement, reset }
}

// Uso
function Counter() {
  const { count, increment, decrement, reset } = useCounter(0)
  return (
    <div>
      <p>Cuenta: {count}</p>
      <button onClick={increment}>+</button>
      <button onClick={decrement}>-</button>
      <button onClick={reset}>Reiniciar</button>
    </div>
  )
}
```

## Manejo de Eventos

### Eventos de Clic: `onClick`

Maneje clics de botones e interacciones de elementos.

```javascript
function Button() {
  const handleClick = () => {
    alert('¡Botón presionado!')
  }
  return <button onClick={handleClick}>Haz clic</button>
}

// Manejador de eventos en línea
function Button() {
  return <button onClick={() => alert('¡Presionado!')}>Haz clic</button>
}

// Pasando parámetros
function Button() {
  const handleClick = (message) => {
    alert(message)
  }
  return <button onClick={() => handleClick('¡Hola!')}>Haz clic</button>
}
```

### Eventos de Formulario: `onChange` / `onSubmit`

Maneje las entradas y envíos de formularios.

```javascript
function Form() {
  const [value, setValue] = useState('')
  const handleChange = (e) => {
    setValue(e.target.value)
  }
  const handleSubmit = (e) => {
    e.preventDefault()
    console.log('Enviado:', value)
  }
  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={value}
        onChange={handleChange}
        placeholder="Introduce texto"
      />
      <button type="submit">Enviar</button>
    </form>
  )
}
```

### Objeto de Evento: `event.target` / `event.preventDefault()`

Acceda a las propiedades del evento y controle el comportamiento predeterminado.

```javascript
function handleInput(event) {
  console.log('Valor de entrada:', event.target.value)
  console.log('Nombre de entrada:', event.target.name)
}

function handleFormSubmit(event) {
  event.preventDefault() // Previene el envío del formulario
  console.log('Formulario enviado')
}

// Delegación de eventos
function List() {
  const handleClick = (event) => {
    if (event.target.tagName === 'BUTTON') {
      console.log('Botón presionado:', event.target.textContent)
    }
  }
  return (
    <div onClick={handleClick}>
      <button>Botón 1</button>
      <button>Botón 2</button>
    </div>
  )
}
```

### Eventos de Teclado: `onKeyDown` / `onKeyUp`

Responda a las interacciones del teclado.

```javascript
function KeyboardHandler() {
  const handleKeyDown = (event) => {
    if (event.key === 'Enter') {
      console.log('Tecla Enter presionada')
    }
    if (event.ctrlKey && event.key === 's') {
      event.preventDefault()
      console.log('Ctrl+S presionado')
    }
  }
  return <input onKeyDown={handleKeyDown} placeholder="Escribe aquí..." />
}
```

## Renderizado Condicional

### Operadores Condicionales: `&&` / `?:`

Mostrar/ocultar elementos basados en condiciones.

```javascript
function Greeting({ user }) {
  return (
    <div>
      {user && <h1>Bienvenido, {user.name}!</h1>}
      {!user && <h1>Por favor, inicie sesión</h1>}
    </div>
  )
}

// Operador ternario
function Status({ isOnline }) {
  return <div>El usuario está {isOnline ? 'en línea' : 'desconectado'}</div>
}
```

### Lógica If/Else: Declaraciones `if`

Use lógica tradicional de JavaScript para condiciones complejas.

```javascript
function UserProfile({ user, isAdmin }) {
  if (!user) {
    return <div>Cargando...</div>
  }
  if (isAdmin) {
    return <AdminPanel user={user} />
  }
  return <UserPanel user={user} />
}

// Patrón de retorno temprano
function Component({ data }) {
  if (!data) return null
  if (data.error) return <ErrorMessage />
  return <DataDisplay data={data} />
}
```

### Sentencias Switch: `switch`

Maneje múltiples condiciones de manera eficiente.

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

### Estilos Dinámicos: CSS Condicional

Aplique estilos basados en el estado o las props del componente.

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
      Haz clic
    </button>
  )
}
```

## Renderizado de Listas y Claves

### Función Map: `array.map()`

Renderice listas de componentes a partir de datos de array.

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

// Con índice (evitar cuando sea posible)
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

### Claves: Prop `key`

Proporcione identificadores únicos para los elementos de la lista para optimizar el renderizado.

```javascript
// Bueno: usando ID único
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

// Creando claves compuestas
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

### Filtrar y Mapear: Métodos de Array

Procese arrays antes de renderizarlos.

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

### Estados Vacíos: Manejo de arrays vacíos

Muestre contenido apropiado cuando las listas estén vacías.

```javascript
function ProductList({ products }) {
  if (products.length === 0) {
    return <div>No se encontraron productos.</div>
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

## Optimización del Rendimiento

### React.memo: `React.memo()`

Evite renderizados innecesarios de componentes funcionales.

```javascript
const ExpensiveComponent = React.memo(function ExpensiveComponent({ data }) {
  return <div>{/* Lógica de renderizado compleja */}</div>
})

// Con comparación personalizada
const MyComponent = React.memo(
  function MyComponent({ user }) {
    return <div>{user.name}</div>
  },
  (prevProps, nextProps) => {
    return prevProps.user.id === nextProps.user.id
  },
)
```

### Hook useMemo: `useMemo()`

Memorice cálculos costosos.

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

### Hook useCallback: `useCallback()`

Memorice referencias de funciones para evitar renderizados innecesarios.

```javascript
function Parent({ items }) {
  const [count, setCount] = useState(0)
  const handleItemClick = useCallback((itemId) => {
    console.log('Elemento presionado:', itemId)
  }, []) // Array de dependencias vacío
  return (
    <div>
      <button onClick={() => setCount(count + 1)}>Cuenta: {count}</button>
      <ItemList items={items} onItemClick={handleItemClick} />
    </div>
  )
}
```

### Carga Diferida: `React.lazy()` / `Suspense`

Cargue componentes solo cuando sea necesario para reducir el tamaño del paquete.

```javascript
const LazyComponent = React.lazy(() => import('./LazyComponent'))

function App() {
  return (
    <div>
      <Suspense fallback={<div>Cargando...</div>}>
        <LazyComponent />
      </Suspense>
    </div>
  )
}
```

## Comunicación entre Componentes

### Props Hacia Abajo: Padre a Hijo

Pase datos de componentes padre a componentes hijo.

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
  return <div>Hola, {user.name}!</div>
}
```

### Callbacks Hacia Arriba: Hijo a Padre

Envíe datos de componentes hijo de vuelta a componentes padre.

```javascript
function Parent() {
  const [message, setMessage] = useState('')
  const handleChildMessage = (msg) => {
    setMessage(msg)
  }
  return (
    <div>
      <p>Mensaje: {message}</p>
      <Child onMessage={handleChildMessage} />
    </div>
  )
}

function Child({ onMessage }) {
  return (
    <button onClick={() => onMessage('¡Hola desde el hijo!')}>
      Enviar Mensaje
    </button>
  )
}
```

### Context API: `createContext` / `useContext`

Comparta estado a través de múltiples componentes sin "prop drilling".

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
  return <h1>Bienvenido, {user.name}!</h1>
}
```

### Refs: `useRef` / `forwardRef`

Acceda a elementos DOM o almacene valores mutables.

```javascript
function TextInput() {
  const inputRef = useRef(null)
  const focusInput = () => {
    inputRef.current.focus()
  }
  return (
    <div>
      <input ref={inputRef} type="text" />
      <button onClick={focusInput}>Enfocar Entrada</button>
    </div>
  )
}

// Reenvío de refs
const FancyInput = forwardRef((props, ref) => (
  <input className="fancy" ref={ref} {...props} />
))
```

## Herramientas de Desarrollo y Depuración

### React DevTools: Extensión del Navegador

Depure componentes de React e inspeccione el árbol de componentes.

```javascript
// Instalar la extensión del navegador React DevTools
// Pestaña Components: Inspeccionar jerarquía de componentes
// Pestaña Profiler: Medir el rendimiento

// Depuración en consola
function MyComponent(props) {
  console.log('Props de MyComponent:', props)
  console.log('MyComponent renderizado')
  return <div>{props.children}</div>
}
```

### Límites de Error: `componentDidCatch`

Capture errores de JavaScript en el árbol de componentes y muestre una UI de reserva.

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
    console.log('Error capturado:', error, errorInfo)
  }
  render() {
    if (this.state.hasError) {
      return <h1>Algo salió mal.</h1>
    }
    return this.props.children
  }
}
```

### Modo Estricto: `React.StrictMode`

Habilite verificaciones y advertencias adicionales para el desarrollo.

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

### Perfilado: Medición de rendimiento

Mida el rendimiento del componente e identifique cuellos de botella.

```javascript
// Usando el Profiler de React DevTools
// Envuelva componentes para perfilar
import { Profiler } from 'react'

function onRenderCallback(id, phase, actualDuration) {
  console.log('Componente', id, 'tomó', actualDuration, 'ms')
}

;<Profiler id="App" onRender={onRenderCallback}>
  <App />
</Profiler>
```

## Instalación y Configuración de React

### Create React App: `npx create-react-app`

Inicie rápidamente un nuevo proyecto de React.

```bash
# Crear nueva app de React
npx create-react-app mi-app
cd mi-app

# Iniciar servidor de desarrollo
npm start

# Construir para producción
npm run build

# Ejecutar pruebas
npm test
```

### Vite: `npm create vite@latest`

Herramienta de compilación rápida y servidor de desarrollo para proyectos de React.

```bash
# Crear nueva app de Vite React
npm create vite@latest mi-app-react -- --template react
cd mi-app-react
npm install

# Iniciar servidor de desarrollo
npm run dev

# Construir para producción
npm run build
```

### Configuración Manual / Importación

Añada React a un proyecto existente o use CDN.

```bash
# Instalar React y ReactDOM
npm install react react-dom

# Para desarrollo
npm install --save-dev @vitejs/plugin-react
```

```javascript
// Importación básica de React
import React from 'react'
import ReactDOM from 'react-dom/client'

// Renderizar a DOM
const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(<App />)
```

## Patrones y Características Avanzadas

### Componentes de Orden Superior (HOC)

Reutilice la lógica de componentes envolviendo componentes.

```javascript
function withLoading(WrappedComponent) {
  return function WithLoadingComponent(props) {
    if (props.isLoading) {
      return <div>Cargando...</div>
    }
    return <WrappedComponent {...props} />
  }
}

// Uso
const UserListWithLoading = withLoading(UserList)
;<UserListWithLoading users={users} isLoading={loading} />
```

### Patrón Render Props

Comparta código entre componentes usando una prop cuyo valor es una función.

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

// Uso
;<DataFetcher
  url="/api/users"
  render={({ data, loading }) =>
    loading ? <Spinner /> : <UserList users={data} />
  }
/>
```

### Componentes Compuestos

Cree componentes que trabajan juntos como una unidad cohesiva.

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

// Uso
;<Tabs activeTab={0}>
  <Tab>Contenido de la Pestaña 1</Tab>
  <Tab>Contenido de la Pestaña 2</Tab>
</Tabs>
```

### Portal: `ReactDOM.createPortal()`

Renderice hijos en un nodo DOM fuera de la jerarquía del componente padre.

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

### Composición sobre Herencia

Use patrones de composición en lugar de extender clases.

```javascript
// Bueno: Composición
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

### Patrones de Componentes: APIs Flexibles

Diseñe APIs de componentes que sean flexibles y fáciles de usar.

```javascript
// Componente Card Flexible
function Card({ header, children, footer, variant = 'default' }) {
  return (
    <div className={`card card-${variant}`}>
      {header && <div className="card-header">{header}</div>}
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
    </div>
  )
}

// Uso
;<Card header={<h3>Título</h3>} footer={<Button>Acción</Button>}>
  Contenido de la tarjeta aquí
</Card>
```

## Enlaces Relevantes

- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/html">Hoja de Trucos de HTML</router-link>
- <router-link to="/css">Hoja de Trucos de CSS</router-link>
- <router-link to="/web-development">Hoja de Trucos de Desarrollo Web</router-link>

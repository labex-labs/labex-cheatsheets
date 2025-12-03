---
title: 'React Spickzettel | LabEx'
description: 'Lernen Sie die React-Entwicklung mit diesem umfassenden Spickzettel. Schnelle Referenz für React Hooks, Komponenten, JSX, Zustandsverwaltung, Props und moderne Frontend-Entwicklungsmuster.'
pdfUrl: '/cheatsheets/pdf/react-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
React Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/react">Lernen Sie React mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Erlernen Sie die Frontend-Entwicklung mit React durch praktische Labs und reale Szenarien. LabEx bietet umfassende React-Kurse, die die wesentliche Komponentenerstellung, Zustandsverwaltung, Hooks, Ereignisbehandlung und Leistungsoptimierung abdecken. Meistern Sie den Aufbau effizienter und wartbarer Benutzeroberflächen für moderne Webanwendungen.
</base-disclaimer-content>
</base-disclaimer>

## Komponentenerstellung & JSX

### Funktionale Komponenten: `function` / `=>`

Erstellen Sie Komponenten mit Funktionssyntax.

```javascript
import React from 'react'

// Funktionsdeklaration
function Welcome(props) {
  return <h1>Hallo, {props.name}!</h1>
}

// Pfeilfunktion
const Welcome = (props) => {
  return <h1>Hallo, {props.name}!</h1>
}

// Implizite Rückgabe für einfache Komponenten
const Greeting = ({ name }) => <h1>Hallo, {name}!</h1>
```

### Klassenkomponenten: `class extends React.Component`

Erstellen Sie Komponenten mit ES6-Klassensyntax.

```javascript
import React, { Component } from 'react'

class Welcome extends Component {
  render() {
    return <h1>Hallo, {this.props.name}!</h1>
  }
}

// Mit Konstruktor
class Counter extends Component {
  constructor(props) {
    super(props)
    this.state = { count: 0 }
  }
  render() {
    return <div>Zähler: {this.state.count}</div>
  }
}
```

### JSX-Elemente: `<element>`

Schreiben Sie HTML-ähnliche Syntax innerhalb von JavaScript.

```javascript
// JSX-Element
const element = <h1>Hallo, Welt!</h1>

// JSX mit Ausdrücken
const name = 'John'
const greeting = <h1>Hallo, {name}!</h1>

// Mehrzeiliges JSX
const element = (
  <div>
    <h1>Willkommen!</h1>
    <p>Schön, Sie hier zu sehen.</p>
  </div>
)
```

### Komponenten-Export: `export default` / `export`

Exportieren Sie Komponenten zur Verwendung in anderen Dateien.

```javascript
// Standardexport
export default function App() {
  return <div>Meine App</div>
}

// Benannter Export
export const Button = () => <button>Klick mich</button>
```

### Komponenten-Import: `import`

Importieren Sie Komponenten aus anderen Dateien.

```javascript
// Standardkomponente importieren
import App from './App'

// Benannte Komponente importieren
import { Button } from './Button'

// Mehrere Komponenten importieren
import React, { useState, useEffect } from 'react'

// Import mit Alias
import { Button as MyButton } from './Button'
```

### Fragment: `<React.Fragment>` / `<>`

Gruppieren Sie Elemente, ohne zusätzliche DOM-Knoten hinzuzufügen.

```javascript
// Verwendung von React.Fragment
return (
  <React.Fragment>
    <h1>Titel</h1>
    <p>Beschreibung</p>
  </React.Fragment>
)

// Verwendung der Kurzschreibweise
return (
  <>
    <h1>Titel</h1>
    <p>Beschreibung</p>
  </>
)
```

## Props & Komponentenstruktur

### Props: `props.name`

Übergeben Sie Daten von Eltern- an Kindkomponenten.

```javascript
// Props empfangen
function Welcome(props) {
  return <h1>Hallo, {props.name}!</h1>
}

// Props destrukturieren
function Welcome({ name, age }) {
  return (
    <h1>
      Hallo, {name}! Sie sind {age} Jahre alt.
    </h1>
  )
}

// Standard-Props
function Welcome({ name = 'Gast' }) {
  return <h1>Hallo, {name}!</h1>
}
```

<BaseQuiz id="react-props-1" correct="B">
  <template #question>
    Wie übergeben Sie Daten von einer Elternkomponente an eine Kindkomponente in React?
  </template>
  
  <BaseQuizOption value="A">Verwendung von Zustandsvariablen</BaseQuizOption>
  <BaseQuizOption value="B" correct>Verwendung von Props</BaseQuizOption>
  <BaseQuizOption value="C">Verwendung von Refs</BaseQuizOption>
  <BaseQuizOption value="D">Verwendung der Context API</BaseQuizOption>
  
  <BaseQuizAnswer>
    Props (Kurzform für Eigenschaften) sind der primäre Weg, um Daten von Eltern- an Kindkomponenten in React zu übergeben. Sie übergeben Props als Attribute, wenn Sie die Kindkomponente rendern.
  </BaseQuizAnswer>
</BaseQuiz>

### PropTypes: `Component.propTypes`

Validieren Sie Props, die an Komponenten übergeben werden (erfordert das prop-types-Paket).

```javascript
import PropTypes from 'prop-types'

function Welcome({ name, age }) {
  return (
    <h1>
      Hallo, {name}! Alter: {age}
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

Greifen Sie auf Inhalte zu, die zwischen den öffnenden/schließenden Tags einer Komponente übergeben werden.

```javascript
// Komponente, die Children verwendet
function Card({ children }) {
  return <div className="card">{children}</div>
}

// Verwendung
;<Card>
  <h2>Titel</h2>
  <p>Inhalt hier</p>
</Card>
```

## Zustandsverwaltung & Hooks

### useState Hook: `useState()`

Fügen Sie funktionalen Komponenten einen Zustand hinzu.

```javascript
import React, { useState } from 'react'

function Counter() {
  const [count, setCount] = useState(0)
  return (
    <div>
      <p>Zähler: {count}</p>
      <button onClick={() => setCount(count + 1)}>Inkrementieren</button>
    </div>
  )
}

// Mehrere Zustandsvariablen
function Form() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
}
```

<BaseQuiz id="react-usestate-1" correct="A">
  <template #question>
    Was gibt `useState(0)` zurück?
  </template>
  
  <BaseQuizOption value="A" correct>Ein Array mit dem Zustandswert und einer Funktion, um ihn zu aktualisieren</BaseQuizOption>
  <BaseQuizOption value="B">Nur den Zustandswert</BaseQuizOption>
  <BaseQuizOption value="C">Eine Funktion, um den Zustand zu aktualisieren</BaseQuizOption>
  <BaseQuizOption value="D">Nichts, es setzt nur den Zustand</BaseQuizOption>
  
  <BaseQuizAnswer>
    `useState` gibt ein Array mit zwei Elementen zurück: dem aktuellen Zustandswert und einer Funktion, um ihn zu aktualisieren. Der Anfangswert (0) wird als Argument übergeben.
  </BaseQuizAnswer>
</BaseQuiz>

### useEffect Hook: `useEffect()`

Führen Sie Seiteneffekte in funktionalen Komponenten aus.

```javascript
import React, { useState, useEffect } from 'react'

function Timer() {
  const [count, setCount] = useState(0)

  // Effekt läuft nach jedem Rendern
  useEffect(() => {
    document.title = `Zähler: ${count}`
  })

  // Effekt mit Bereinigung
  useEffect(() => {
    const timer = setInterval(() => setCount((c) => c + 1), 1000)
    return () => clearInterval(timer)
  }, [])
}
```

<BaseQuiz id="react-useeffect-1" correct="D">
  <template #question>
    Was bedeutet das leere Abhängigkeitsarray `[]` in `useEffect(() => {...}, [])`?
  </template>
  
  <BaseQuizOption value="A">Der Effekt läuft bei jedem Rendern</BaseQuizOption>
  <BaseQuizOption value="B">Der Effekt läuft nie</BaseQuizOption>
  <BaseQuizOption value="C">Der Effekt läuft zweimal</BaseQuizOption>
  <BaseQuizOption value="D" correct>Der Effekt läuft nur einmal nach dem anfänglichen Rendern</BaseQuizOption>
  
  <BaseQuizAnswer>
    Ein leeres Abhängigkeitsarray bedeutet, dass der Effekt keine Abhängigkeiten hat und daher nur einmal ausgeführt wird, nachdem die Komponente eingebunden wurde. Dies ist nützlich für einmalige Einrichtungscodes.
  </BaseQuizAnswer>
</BaseQuiz>

### Klassenstatus: `this.state` / `setState()`

Verwalten Sie den Zustand in Klassenkomponenten.

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
        <p>Zähler: {this.state.count}</p>
        <button onClick={this.increment}>Inkrementieren</button>
      </div>
    )
  }
}
```

### Benutzerdefinierte Hooks: `use...`

Erstellen Sie wiederverwendbare zustandsbehaftete Logik.

```javascript
// Benutzerdefinierter Hook
function useCounter(initialValue = 0) {
  const [count, setCount] = useState(initialValue)
  const increment = () => setCount(count + 1)
  const decrement = () => setCount(count - 1)
  const reset = () => setCount(initialValue)
  return { count, increment, decrement, reset }
}

// Verwendung
function Counter() {
  const { count, increment, decrement, reset } = useCounter(0)
  return (
    <div>
      <p>Zähler: {count}</p>
      <button onClick={increment}>+</button>
      <button onClick={decrement}>-</button>
      <button onClick={reset}>Zurücksetzen</button>
    </div>
  )
}
```

## Ereignisbehandlung

<BaseQuiz id="react-props-2" correct="A">
  <template #question>
    Was ist der Zweck von PropTypes in React?
  </template>
  
  <BaseQuizOption value="A" correct>Zur Validierung der Typen von Props, die an Komponenten übergeben werden</BaseQuizOption>
  <BaseQuizOption value="B">Zur Verbesserung der Komponentenleistung</BaseQuizOption>
  <BaseQuizOption value="C">Zur automatischen Gestaltung von Komponenten</BaseQuizOption>
  <BaseQuizOption value="D">Um Komponenten schneller zu machen</BaseQuizOption>
  
  <BaseQuizAnswer>
    PropTypes helfen, Fehler abzufangen, indem sie validieren, dass Komponenten Props vom richtigen Typ erhalten. Sie bieten Laufzeit-Typprüfung und sind besonders nützlich während der Entwicklung.
  </BaseQuizAnswer>
</BaseQuiz>

### Klick-Ereignisse: `onClick`

Behandeln Sie Klicks auf Schaltflächen und Interaktionen mit Elementen.

```javascript
function Button() {
  const handleClick = () => {
    alert('Schaltfläche geklickt!')
  }
  return <button onClick={handleClick}>Klick mich</button>
}

// Inline-Ereignisbehandlung
function Button() {
  return <button onClick={() => alert('Geklickt!')}>Klick mich</button>
}

// Parameter übergeben
function Button() {
  const handleClick = (message) => {
    alert(message)
  }
  return <button onClick={() => handleClick('Hallo!')}>Klick mich</button>
}
```

### Formularereignisse: `onChange` / `onSubmit`

Behandeln Sie Formulareingaben und -übermittlungen.

```javascript
function Form() {
  const [value, setValue] = useState('')
  const handleChange = (e) => {
    setValue(e.target.value)
  }
  const handleSubmit = (e) => {
    e.preventDefault()
    console.log('Übermittelt:', value)
  }
  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={value}
        onChange={handleChange}
        placeholder="Text eingeben"
      />
      <button type="submit">Senden</button>
    </form>
  )
}
```

### Ereignisobjekt: `event.target` / `event.preventDefault()`

Greifen Sie auf Ereigniseigenschaften zu und steuern Sie das Standardverhalten.

```javascript
function handleInput(event) {
  console.log('Eingabewert:', event.target.value)
  console.log('Eingabename:', event.target.name)
}

function handleFormSubmit(event) {
  event.preventDefault() // Formularübermittlung verhindern
  console.log('Formular übermittelt')
}

// Ereignisdelegation
function List() {
  const handleClick = (event) => {
    if (event.target.tagName === 'BUTTON') {
      console.log('Schaltfläche geklickt:', event.target.textContent)
    }
  }
  return (
    <div onClick={handleClick}>
      <button>Schaltfläche 1</button>
      <button>Schaltfläche 2</button>
    </div>
  )
}
```

### Tastaturereignisse: `onKeyDown` / `onKeyUp`

Reagieren Sie auf Tastaturinteraktionen.

```javascript
function KeyboardHandler() {
  const handleKeyDown = (event) => {
    if (event.key === 'Enter') {
      console.log('Enter-Taste gedrückt')
    }
    if (event.ctrlKey && event.key === 's') {
      event.preventDefault()
      console.log('Strg+S gedrückt')
    }
  }
  return <input onKeyDown={handleKeyDown} placeholder="Hier tippen..." />
}
```

## Bedingtes Rendern

### Bedingte Operatoren: `&&` / `?:`

Elemente basierend auf Bedingungen anzeigen/ausblenden.

```javascript
function Greeting({ user }) {
  return (
    <div>
      {user && <h1>Willkommen, {user.name}!</h1>}
      {!user && <h1>Bitte melden Sie sich an</h1>}
    </div>
  )
}

// Ternärer Operator
function Status({ isOnline }) {
  return <div>Benutzer ist {isOnline ? 'online' : 'offline'}</div>
}
```

### If/Else-Logik: `if`-Anweisungen

Verwenden Sie traditionelle JavaScript-Logik für komplexe Bedingungen.

```javascript
function UserProfile({ user, isAdmin }) {
  if (!user) {
    return <div>Wird geladen...</div>
  }
  if (isAdmin) {
    return <AdminPanel user={user} />
  }
  return <UserPanel user={user} />
}

// Frühe Rückgabe-Muster
function Component({ data }) {
  if (!data) return null
  if (data.error) return <ErrorMessage />
  return <DataDisplay data={data} />
}
```

### Switch-Anweisungen: `switch`

Behandeln Sie mehrere Bedingungen effizient.

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

### Dynamische Stile: Bedingtes CSS

Wenden Sie Stile basierend auf dem Zustand oder den Props der Komponente an.

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
      Klick mich
    </button>
  )
}
```

## Listen-Rendering & Schlüssel

### Map-Funktion: `array.map()`

Rendern Sie Listen von Komponenten aus Array-Daten.

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

// Mit Index (nach Möglichkeit vermeiden)
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

### Schlüssel: `key`-Prop

Stellen Sie eindeutige Identifikatoren für Listenelemente bereit, um das Rendern zu optimieren.

```javascript
// Gut: Verwendung einer eindeutigen ID
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

// Erstellen zusammengesetzter Schlüssel
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

### Filtern & Mappen: Array-Methoden

Verarbeiten Sie Arrays, bevor Sie sie rendern.

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

### Leere Zustände: Umgang mit leeren Arrays

Zeigen Sie geeignete Inhalte an, wenn Listen leer sind.

```javascript
function ProductList({ products }) {
  if (products.length === 0) {
    return <div>Keine Produkte gefunden.</div>
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

## Leistungsoptimierung

### React.memo: `React.memo()`

Verhindern Sie unnötige Neurenderns funktionaler Komponenten.

```javascript
const ExpensiveComponent = React.memo(function ExpensiveComponent({ data }) {
  return <div>{/* Komplexe Rendering-Logik */}</div>
})

// Mit benutzerdefinierter Vergleichsfunktion
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

Memoize aufwendige Berechnungen.

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

Memoize Funktionsreferenzen, um unnötige Neurenderns zu verhindern.

```javascript
function Parent({ items }) {
  const [count, setCount] = useState(0)
  const handleItemClick = useCallback((itemId) => {
    console.log('Element geklickt:', itemId)
  }, []) // Leeres Abhängigkeitsarray
  return (
    <div>
      <button onClick={() => setCount(count + 1)}>Zähler: {count}</button>
      <ItemList items={items} onItemClick={handleItemClick} />
    </div>
  )
}
```

### Lazy Loading: `React.lazy()` / `Suspense`

Laden Sie Komponenten nur bei Bedarf, um die Bundle-Größe zu reduzieren.

```javascript
const LazyComponent = React.lazy(() => import('./LazyComponent'))

function App() {
  return (
    <div>
      <Suspense fallback={<div>Wird geladen...</div>}>
        <LazyComponent />
      </Suspense>
    </div>
  )
}
```

## Komponentenkommunikation

### Props Down: Eltern zu Kind

Übergeben Sie Daten von Elternkomponenten an Kindkomponenten.

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
  return <div>Hallo, {user.name}!</div>
}
```

### Callbacks Up: Kind zu Eltern

Senden Sie Daten von Kindkomponenten zurück an Elternkomponenten.

```javascript
function Parent() {
  const [message, setMessage] = useState('')
  const handleChildMessage = (msg) => {
    setMessage(msg)
  }
  return (
    <div>
      <p>Nachricht: {message}</p>
      <Child onMessage={handleChildMessage} />
    </div>
  )
}

function Child({ onMessage }) {
  return (
    <button onClick={() => onMessage('Hallo von Kind!')}>
      Nachricht senden
    </button>
  )
}
```

### Context API: `createContext` / `useContext`

Teilen Sie den Zustand über mehrere Komponenten hinweg, ohne Prop Drilling.

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
  return <h1>Willkommen, {user.name}!</h1>
}
```

### Refs: `useRef` / `forwardRef`

Greifen Sie auf DOM-Elemente zu oder speichern Sie veränderliche Werte.

```javascript
function TextInput() {
  const inputRef = useRef(null)
  const focusInput = () => {
    inputRef.current.focus()
  }
  return (
    <div>
      <input ref={inputRef} type="text" />
      <button onClick={focusInput}>Eingabe fokussieren</button>
    </div>
  )
}

// Refs weiterleiten
const FancyInput = forwardRef((props, ref) => (
  <input className="fancy" ref={ref} {...props} />
))
```

## Entwicklungs-Tools & Debugging

### React DevTools: Browser-Erweiterung

Debuggen Sie React-Komponenten und untersuchen Sie die Komponentenstruktur.

```javascript
// Installieren Sie die React DevTools Browser-Erweiterung
// Komponenten-Tab: Komponentenhierarchie untersuchen
// Profiler-Tab: Leistung messen

// Konsolen-Debugging
function MyComponent(props) {
  console.log('MyComponent Props:', props)
  console.log('MyComponent gerendert')
  return <div>{props.children}</div>
}
```

### Error Boundaries: `componentDidCatch`

Fangen Sie JavaScript-Fehler im Komponentenbaum ab und zeigen Sie eine Fallback-UI an.

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
    console.log('Fehler abgefangen:', error, errorInfo)
  }
  render() {
    if (this.state.hasError) {
      return <h1>Etwas ist schiefgelaufen.</h1>
    }
    return this.props.children
  }
}
```

### Strict Mode: `React.StrictMode`

Aktivieren Sie zusätzliche Prüfungen und Warnungen für die Entwicklung.

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

### Profiling: Leistungsmessung

Messen Sie die Komponentenleistung und identifizieren Sie Engpässe.

```javascript
// Verwendung des React DevTools Profilers
// Komponenten zum Profilen umwickeln
import { Profiler } from 'react'

function onRenderCallback(id, phase, actualDuration) {
  console.log('Komponente', id, 'benötigte', actualDuration, 'ms')
}

;<Profiler id="App" onRender={onRenderCallback}>
  <App />
</Profiler>
```

## React Installation & Einrichtung

### Create React App: `npx create-react-app`

Erstellen Sie schnell eine neue React-Anwendung.

```bash
# Neue React-App erstellen
npx create-react-app my-app
cd my-app

# Entwicklungsserver starten
npm start

# Für die Produktion erstellen
npm run build

# Tests ausführen
npm test
```

### Vite: `npm create vite@latest`

Schnelles Build-Tool und Entwicklungsserver für React-Projekte.

```bash
# Neue Vite React-App erstellen
npm create vite@latest my-react-app -- --template react
cd my-react-app
npm install

# Entwicklungsserver starten
npm run dev

# Für die Produktion erstellen
npm run build
```

### Manuelle Einrichtung / Import

Fügen Sie React einem bestehenden Projekt hinzu oder verwenden Sie CDN.

```bash
# React und ReactDOM installieren
npm install react react-dom

# Für die Entwicklung
npm install --save-dev @vitejs/plugin-react
```

```javascript
// Grundlegender React-Import
import React from 'react'
import ReactDOM from 'react-dom/client'

// In DOM rendern
const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(<App />)
```

## Erweiterte Muster & Funktionen

### Higher-Order Components (HOC)

Wiederverwenden von Komponentenlogik durch Umwickeln von Komponenten.

```javascript
function withLoading(WrappedComponent) {
  return function WithLoadingComponent(props) {
    if (props.isLoading) {
      return <div>Wird geladen...</div>
    }
    return <WrappedComponent {...props} />
  }
}

// Verwendung
const UserListWithLoading = withLoading(UserList)
;<UserListWithLoading users={users} isLoading={loading} />
```

### Render Props Muster

Teilen Sie Code zwischen Komponenten, indem Sie eine Prop verwenden, deren Wert eine Funktion ist.

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

// Verwendung
;<DataFetcher
  url="/api/users"
  render={({ data, loading }) =>
    loading ? <Spinner /> : <UserList users={data} />
  }
/>
```

### Verbundene Komponenten

Erstellen Sie Komponenten, die als zusammenhängende Einheit zusammenarbeiten.

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

// Verwendung
;<Tabs activeTab={0}>
  <Tab>Tab 1 Inhalt</Tab>
  <Tab>Tab 2 Inhalt</Tab>
</Tabs>
```

### Portal: `ReactDOM.createPortal()`

Rendern Sie Kinder in einen DOM-Knoten außerhalb der Hierarchie der Elternkomponente.

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

### Komposition vor Vererbung

Verwenden Sie Kompositionsmuster anstelle der Erweiterung von Klassen.

```javascript
// Gut: Komposition
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

### Komponentenmuster: Flexible APIs

Entwerfen Sie Komponenten-APIs, die flexibel und einfach zu bedienen sind.

```javascript
// Flexible Card-Komponente
function Card({ header, children, footer, variant = 'default' }) {
  return (
    <div className={`card card-${variant}`}>
      {header && <div className="card-header">{header}</div>}
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
    </div>
  )
}

// Verwendung
;<Card header={<h3>Titel</h3>} footer={<Button>Aktion</Button>}>
  Karteninhalt hier
</Card>
```

## Relevante Links

- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/html">HTML Spickzettel</router-link>
- <router-link to="/css">CSS Spickzettel</router-link>
- <router-link to="/web-development">Webentwicklung Spickzettel</router-link>

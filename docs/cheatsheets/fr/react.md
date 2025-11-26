---
title: 'Anti-sèche React'
description: 'Maîtrisez React avec notre anti-sèche complète couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/react-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche React
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/react">Apprenez le développement frontend React avec des laboratoires pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez le développement frontend React grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours React complets couvrant la création de composants essentiels, la gestion d'état, les hooks, la gestion des événements et l'optimisation des performances. Maîtrisez la construction d'interfaces utilisateur efficaces et maintenables pour les applications web modernes.
</base-disclaimer-content>
</base-disclaimer>

## Création de Composants & JSX

### Composants Fonctionnels : `function` / `=>`

Créez des composants en utilisant la syntaxe de fonction.

```javascript
import React from 'react'

// Déclaration de fonction
function Welcome(props) {
  return <h1>Bonjour, {props.name} !</h1>
}

// Fonction fléchée
const Welcome = (props) => {
  return <h1>Bonjour, {props.name} !</h1>
}

// Retour implicite pour les composants simples
const Greeting = ({ name }) => <h1>Bonjour, {name} !</h1>
```

### Composants de Classe : `class extends React.Component`

Créez des composants en utilisant la syntaxe de classe ES6.

```javascript
import React, { Component } from 'react'

class Welcome extends Component {
  render() {
    return <h1>Bonjour, {this.props.name} !</h1>
  }
}

// Avec constructeur
class Counter extends Component {
  constructor(props) {
    super(props)
    this.state = { count: 0 }
  }
  render() {
    return <div>Compteur : {this.state.count}</div>
  }
}
```

### Éléments JSX : `<element>`

Écrivez une syntaxe de type HTML dans JavaScript.

```javascript
// Élément JSX
const element = <h1>Bonjour, le monde !</h1>

// JSX avec expressions
const name = 'John'
const greeting = <h1>Bonjour, {name} !</h1>

// JSX multiligne
const element = (
  <div>
    <h1>Bienvenue !</h1>
    <p>Ravi de vous voir ici.</p>
  </div>
)
```

### Exportation de Composants : `export default` / `export`

Exportez des composants pour les utiliser dans d'autres fichiers.

```javascript
// Exportation par défaut
export default function App() {
  return <div>Mon App</div>
}

// Exportation nommée
export const Button = () => <button>Cliquez-moi</button>
```

### Importation de Composants : `import`

Importez des composants depuis d'autres fichiers.

```javascript
// Importation du composant par défaut
import App from './App'

// Importation du composant nommé
import { Button } from './Button'

// Importation de plusieurs composants
import React, { useState, useEffect } from 'react'

// Importation avec alias
import { Button as MyButton } from './Button'
```

### Fragment : `<React.Fragment>` / `<>`

Regroupez des éléments sans ajouter de nœuds DOM supplémentaires.

```javascript
// Utilisation de React.Fragment
return (
  <React.Fragment>
    <h1>Titre</h1>
    <p>Description</p>
  </React.Fragment>
)

// Utilisation de la syntaxe courte
return (
  <>
    <h1>Titre</h1>
    <p>Description</p>
  </>
)
```

## Props & Structure des Composants

### Props : `props.name`

Passez des données du composant parent au composant enfant.

```javascript
// Réception des props
function Welcome(props) {
  return <h1>Bonjour, {props.name} !</h1>
}

// Déstructuration des props
function Welcome({ name, age }) {
  return (
    <h1>
      Bonjour, {name} ! Vous avez {age} ans.
    </h1>
  )
}

// Props par défaut
function Welcome({ name = 'Invité' }) {
  return <h1>Bonjour, {name} !</h1>
}
```

### PropTypes : `Component.propTypes`

Validez les props passées aux composants (nécessite le paquet prop-types).

```javascript
import PropTypes from 'prop-types'

function Welcome({ name, age }) {
  return (
    <h1>
      Bonjour, {name} ! Âge : {age}
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

### Children : `props.children`

Accédez au contenu passé entre les balises d'ouverture/fermeture du composant.

```javascript
// Composant qui utilise children
function Card({ children }) {
  return <div className="card">{children}</div>
}

// Utilisation
;<Card>
  <h2>Titre</h2>
  <p>Contenu ici</p>
</Card>
```

## Gestion d'État & Hooks

### Hook useState : `useState()`

Ajoutez un état aux composants fonctionnels.

```javascript
import React, { useState } from 'react'

function Counter() {
  const [count, setCount] = useState(0)
  return (
    <div>
      <p>Compteur : {count}</p>
      <button onClick={() => setCount(count + 1)}>Incrémenter</button>
    </div>
  )
}

// Variables d'état multiples
function Form() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
}
```

### Hook useEffect : `useEffect()`

Effectuez des effets secondaires dans les composants fonctionnels.

```javascript
import React, { useState, useEffect } from 'react'

function Timer() {
  const [count, setCount] = useState(0)

  // L'effet s'exécute après chaque rendu
  useEffect(() => {
    document.title = `Compteur : ${count}`
  })

  // Effet avec nettoyage
  useEffect(() => {
    const timer = setInterval(() => setCount((c) => c + 1), 1000)
    return () => clearInterval(timer)
  }, [])
}
```

### État de Classe : `this.state` / `setState()`

Gérez l'état dans les composants de classe.

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
        <p>Compteur : {this.state.count}</p>
        <button onClick={this.increment}>Incrémenter</button>
      </div>
    )
  }
}
```

### Hooks Personnalisés : `use...`

Créez une logique d'état réutilisable.

```javascript
// Hook personnalisé
function useCounter(initialValue = 0) {
  const [count, setCount] = useState(initialValue)
  const increment = () => setCount(count + 1)
  const decrement = () => setCount(count - 1)
  const reset = () => setCount(initialValue)
  return { count, increment, decrement, reset }
}

// Utilisation
function Counter() {
  const { count, increment, decrement, reset } = useCounter(0)
  return (
    <div>
      <p>Compteur : {count}</p>
      <button onClick={increment}>+</button>
      <button onClick={decrement}>-</button>
      <button onClick={reset}>Réinitialiser</button>
    </div>
  )
}
```

## Gestion des Événements

### Événements Clic : `onClick`

Gérez les clics de bouton et les interactions d'éléments.

```javascript
function Button() {
  const handleClick = () => {
    alert('Bouton cliqué !')
  }
  return <button onClick={handleClick}>Cliquez-moi</button>
}

// Gestionnaire d'événement en ligne
function Button() {
  return <button onClick={() => alert('Clic !')}>Cliquez-moi</button>
}

// Passage de paramètres
function Button() {
  const handleClick = (message) => {
    alert(message)
  }
  return <button onClick={() => handleClick('Bonjour !')}>Cliquez-moi</button>
}
```

### Événements de Formulaire : `onChange` / `onSubmit`

Gérez les saisies et les soumissions de formulaire.

```javascript
function Form() {
  const [value, setValue] = useState('')
  const handleChange = (e) => {
    setValue(e.target.value)
  }
  const handleSubmit = (e) => {
    e.preventDefault()
    console.log('Soumis :', value)
  }
  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={value}
        onChange={handleChange}
        placeholder="Entrez du texte"
      />
      <button type="submit">Soumettre</button>
    </form>
  )
}
```

### Objet d'Événement : `event.target` / `event.preventDefault()`

Accédez aux propriétés de l'événement et contrôlez le comportement par défaut.

```javascript
function handleInput(event) {
  console.log('Valeur de saisie :', event.target.value)
  console.log('Nom de la saisie :', event.target.name)
}

function handleFormSubmit(event) {
  event.preventDefault() // Empêche la soumission du formulaire
  console.log('Formulaire soumis')
}

// Délégation d'événement
function List() {
  const handleClick = (event) => {
    if (event.target.tagName === 'BUTTON') {
      console.log('Bouton cliqué :', event.target.textContent)
    }
  }
  return (
    <div onClick={handleClick}>
      <button>Bouton 1</button>
      <button>Bouton 2</button>
    </div>
  )
}
```

### Événements Clavier : `onKeyDown` / `onKeyUp`

Répondez aux interactions du clavier.

```javascript
function KeyboardHandler() {
  const handleKeyDown = (event) => {
    if (event.key === 'Enter') {
      console.log('Touche Entrée pressée')
    }
    if (event.ctrlKey && event.key === 's') {
      event.preventDefault()
      console.log('Ctrl+S pressé')
    }
  }
  return <input onKeyDown={handleKeyDown} placeholder="Tapez ici..." />
}
```

## Rendu Conditionnel

### Opérateurs Conditionnels : `&&` / `?:`

Afficher/masquer des éléments en fonction de conditions.

```javascript
function Greeting({ user }) {
  return (
    <div>
      {user && <h1>Bienvenue, {user.name} !</h1>}
      {!user && <h1>Veuillez vous connecter</h1>}
    </div>
  )
}

// Opérateur ternaire
function Status({ isOnline }) {
  return <div>L'utilisateur est {isOnline ? 'en ligne' : 'hors ligne'}</div>
}
```

### Logique If/Else : Instructions `if`

Utilisez la logique JavaScript traditionnelle pour des conditions complexes.

```javascript
function UserProfile({ user, isAdmin }) {
  if (!user) {
    return <div>Chargement...</div>
  }
  if (isAdmin) {
    return <AdminPanel user={user} />
  }
  return <UserPanel user={user} />
}

// Modèle de retour anticipé
function Component({ data }) {
  if (!data) return null
  if (data.error) return <ErrorMessage />
  return <DataDisplay data={data} />
}
```

### Instructions Switch : `switch`

Gérez plusieurs conditions efficacement.

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

### Styles Dynamiques : CSS Conditionnel

Appliquez des styles basés sur l'état ou les props du composant.

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
      Cliquez-moi
    </button>
  )
}
```

## Rendu de Listes & Clés

### Fonction Map : `array.map()`

Rendez des listes de composants à partir de données de tableau.

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

// Avec index (à éviter si possible)
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

### Clés : prop `key`

Fournissez des identifiants uniques pour les éléments de liste afin d'optimiser le rendu.

```javascript
// Bon : utilisation d'un ID unique
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

// Création de clés composées
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

### Filtrer & Mapper : Méthodes de tableau

Traitez les tableaux avant de les rendre.

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

### États Vides : Gestion des tableaux vides

Affichez le contenu approprié lorsque les listes sont vides.

```javascript
function ProductList({ products }) {
  if (products.length === 0) {
    return <div>Aucun produit trouvé.</div>
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

## Optimisation des Performances

### React.memo : `React.memo()`

Empêchez les rendus inutiles des composants fonctionnels.

```javascript
const ExpensiveComponent = React.memo(function ExpensiveComponent({ data }) {
  return <div>{/* Logique de rendu complexe */}</div>
})

// Avec comparaison personnalisée
const MyComponent = React.memo(
  function MyComponent({ user }) {
    return <div>{user.name}</div>
  },
  (prevProps, nextProps) => {
    return prevProps.user.id === nextProps.user.id
  },
)
```

### Hook useMemo : `useMemo()`

Mémorisez les calculs coûteux.

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

### Hook useCallback : `useCallback()`

Mémorisez les références de fonction pour éviter les rendus inutiles.

```javascript
function Parent({ items }) {
  const [count, setCount] = useState(0)
  const handleItemClick = useCallback((itemId) => {
    console.log('Élément cliqué :', itemId)
  }, []) // Tableau de dépendances vide
  return (
    <div>
      <button onClick={() => setCount(count + 1)}>Compteur : {count}</button>
      <ItemList items={items} onItemClick={handleItemClick} />
    </div>
  )
}
```

### Chargement Paresseux : `React.lazy()` / `Suspense`

Chargez les composants uniquement lorsque nécessaire pour réduire la taille du bundle.

```javascript
const LazyComponent = React.lazy(() => import('./LazyComponent'))

function App() {
  return (
    <div>
      <Suspense fallback={<div>Chargement...</div>}>
        <LazyComponent />
      </Suspense>
    </div>
  )
}
```

## Communication entre Composants

### Props Down : Parent vers Enfant

Passez des données des composants parents aux composants enfants.

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
  return <div>Bonjour, {user.name} !</div>
}
```

### Callbacks Up : Enfant vers Parent

Envoyez des données des composants enfants aux composants parents.

```javascript
function Parent() {
  const [message, setMessage] = useState('')
  const handleChildMessage = (msg) => {
    setMessage(msg)
  }
  return (
    <div>
      <p>Message : {message}</p>
      <Child onMessage={handleChildMessage} />
    </div>
  )
}

function Child({ onMessage }) {
  return (
    <button onClick={() => onMessage("Bonjour depuis l'enfant !")}>
      Envoyer Message
    </button>
  )
}
```

### Context API : `createContext` / `useContext`

Partagez l'état à travers plusieurs composants sans "prop drilling".

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
  return <h1>Bienvenue, {user.name} !</h1>
}
```

### Refs : `useRef` / `forwardRef`

Accédez aux éléments DOM ou stockez des valeurs mutables.

```javascript
function TextInput() {
  const inputRef = useRef(null)
  const focusInput = () => {
    inputRef.current.focus()
  }
  return (
    <div>
      <input ref={inputRef} type="text" />
      <button onClick={focusInput}>Focaliser l'entrée</button>
    </div>
  )
}

// Réacheminement des refs
const FancyInput = forwardRef((props, ref) => (
  <input className="fancy" ref={ref} {...props} />
))
```

## Outils de Développement & Débogage

### React DevTools : Extension de Navigateur

Déboguez les composants React et inspectez l'arborescence des composants.

```javascript
// Installer l'extension de navigateur React DevTools
// Onglet Components : Inspecter la hiérarchie des composants
// Onglet Profiler : Mesurer les performances

// Débogage dans la console
function MyComponent(props) {
  console.log('Props de MyComponent :', props)
  console.log('MyComponent rendu')
  return <div>{props.children}</div>
}
```

### Limites d'Erreur : `componentDidCatch`

Capturez les erreurs JavaScript dans l'arborescence des composants et affichez une UI de secours.

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
    console.log('Erreur capturée :', error, errorInfo)
  }
  render() {
    if (this.state.hasError) {
      return <h1>Quelque chose s'est mal passé.</h1>
    }
    return this.props.children
  }
}
```

### Strict Mode : `React.StrictMode`

Activez des vérifications et des avertissements supplémentaires pour le développement.

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

### Profilage : Mesure des performances

Mesurez les performances des composants et identifiez les goulots d'étranglement.

```javascript
// Utilisation du profileur React DevTools
// Encapsuler les composants à profiler
import { Profiler } from 'react'

function onRenderCallback(id, phase, actualDuration) {
  console.log('Composant', id, 'a pris', actualDuration, 'ms')
}

;<Profiler id="App" onRender={onRenderCallback}>
  <App />
</Profiler>
```

## Installation & Configuration React

### Create React App : `npx create-react-app`

Initialisez rapidement un nouveau projet React.

```bash
# Créer une nouvelle application React
npx create-react-app mon-app
cd mon-app

# Démarrer le serveur de développement
npm start

# Construire pour la production
npm run build

# Exécuter les tests
npm test
```

### Vite : `npm create vite@latest`

Outil de build rapide et serveur de développement pour les projets React.

```bash
# Créer une nouvelle application Vite React
npm create vite@latest mon-app-react -- --template react
cd mon-app-react
npm install

# Démarrer le serveur de développement
npm run dev

# Construire pour la production
npm run build
```

### Configuration Manuelle / Importation

Ajoutez React à un projet existant ou utilisez le CDN.

```bash
# Installer React et ReactDOM
npm install react react-dom

# Pour le développement
npm install --save-dev @vitejs/plugin-react
```

```javascript
// Importation React de base
import React from 'react'
import ReactDOM from 'react-dom/client'

// Rendu dans le DOM
const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(<App />)
```

## Patterns & Fonctionnalités Avancés

### Higher-Order Components (HOC)

Réutilisez la logique de composant en enveloppant des composants.

```javascript
function withLoading(WrappedComponent) {
  return function WithLoadingComponent(props) {
    if (props.isLoading) {
      return <div>Chargement...</div>
    }
    return <WrappedComponent {...props} />
  }
}

// Utilisation
const UserListWithLoading = withLoading(UserList)
;<UserListWithLoading users={users} isLoading={loading} />
```

### Pattern Render Props

Partagez du code entre les composants en utilisant une prop dont la valeur est une fonction.

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

// Utilisation
;<DataFetcher
  url="/api/users"
  render={({ data, loading }) =>
    loading ? <Spinner /> : <UserList users={data} />
  }
/>
```

### Composants Composés

Créez des composants qui fonctionnent ensemble comme une unité cohérente.

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

// Utilisation
;<Tabs activeTab={0}>
  <Tab>Contenu de l'Onglet 1</Tab>
  <Tab>Contenu de l'Onglet 2</Tab>
</Tabs>
```

### Portail : `ReactDOM.createPortal()`

Rendez les enfants dans un nœud DOM situé en dehors de la hiérarchie du composant parent.

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

### Composition plutôt qu'Héritage

Utilisez des modèles de composition au lieu d'étendre des classes.

```javascript
// Bon : Composition
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

### Modèles de Composants : APIs Flexibles

Concevez des APIs de composants qui sont flexibles et faciles à utiliser.

```javascript
// Composant Card flexible
function Card({ header, children, footer, variant = 'default' }) {
  return (
    <div className={`card card-${variant}`}>
      {header && <div className="card-header">{header}</div>}
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
    </div>
  )
}

// Utilisation
;<Card header={<h3>Titre</h3>} footer={<Button>Action</Button>}>
  Contenu de la carte ici
</Card>
```

## Liens Pertinents

- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/html">Feuille de triche HTML</router-link>
- <router-link to="/css">Feuille de triche CSS</router-link>
- <router-link to="/web-development">Feuille de triche Développement Web</router-link>

---
title: 'Folha de Cola React | LabEx'
description: 'Aprenda desenvolvimento React com esta folha de cola abrangente. Referência rápida para hooks, componentes, JSX, gerenciamento de estado, props e padrões modernos de desenvolvimento frontend em React.'
pdfUrl: '/cheatsheets/pdf/react-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas de React
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/react">Aprenda React com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda desenvolvimento frontend React através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de React que cobrem a criação essencial de componentes, gerenciamento de estado, hooks, manipulação de eventos e otimização de desempenho. Domine a construção de interfaces de usuário eficientes e de fácil manutenção para aplicações web modernas.
</base-disclaimer-content>
</base-disclaimer>

## Criação de Componentes e JSX

### Componentes Funcionais: `function` / `=>`

Crie componentes usando sintaxe de função.

```javascript
import React from 'react'

// Declaração de função
function Welcome(props) {
  return <h1>Olá, {props.name}!</h1>
}

// Função de seta (Arrow function)
const Welcome = (props) => {
  return <h1>Olá, {props.name}!</h1>
}

// Retorno implícito para componentes simples
const Greeting = ({ name }) => <h1>Olá, {name}!</h1>
```

### Componentes de Classe: `class extends React.Component`

Crie componentes usando a sintaxe de classe ES6.

```javascript
import React, { Component } from 'react'

class Welcome extends Component {
  render() {
    return <h1>Olá, {this.props.name}!</h1>
  }
}

// Com construtor
class Counter extends Component {
  constructor(props) {
    super(props)
    this.state = { count: 0 }
  }
  render() {
    return <div>Contagem: {this.state.count}</div>
  }
}
```

### Elementos JSX: `<element>`

Escreva sintaxe semelhante a HTML dentro do JavaScript.

```javascript
// Elemento JSX
const element = <h1>Olá, mundo!</h1>

// JSX com expressões
const name = 'John'
const greeting = <h1>Olá, {name}!</h1>

// JSX de múltiplas linhas
const element = (
  <div>
    <h1>Bem-vindo!</h1>
    <p>Bom vê-lo por aqui.</p>
  </div>
)
```

### Exportação de Componentes: `export default` / `export`

Exporte componentes para uso em outros arquivos.

```javascript
// Exportação padrão
export default function App() {
  return <div>Meu App</div>
}

// Exportação nomeada
export const Button = () => <button>Clique em mim</button>
```

### Importação de Componentes: `import`

Importe componentes de outros arquivos.

```javascript
// Importar componente padrão
import App from './App'

// Importar componente nomeado
import { Button } from './Button'

// Importar múltiplos componentes
import React, { useState, useEffect } from 'react'

// Importar com alias
import { Button as MyButton } from './Button'
```

### Fragmento: `<React.Fragment>` / `<>`

Agrupe elementos sem adicionar nós DOM extras.

```javascript
// Usando React.Fragment
return (
  <React.Fragment>
    <h1>Título</h1>
    <p>Descrição</p>
  </React.Fragment>
)

// Usando sintaxe curta
return (
  <>
    <h1>Título</h1>
    <p>Descrição</p>
  </>
)
```

## Props e Estrutura de Componentes

### Props: `props.name`

Passe dados de componentes pai para componentes filho.

```javascript
// Recebendo props
function Welcome(props) {
  return <h1>Olá, {props.name}!</h1>
}

// Desestruturação de props
function Welcome({ name, age }) {
  return (
    <h1>
      Olá, {name}! Você tem {age} anos.
    </h1>
  )
}

// Props padrão
function Welcome({ name = 'Convidado' }) {
  return <h1>Olá, {name}!</h1>
}
```

<BaseQuiz id="react-props-1" correct="B">
  <template #question>
    Como você passa dados de um componente pai para um componente filho no React?
  </template>
  
  <BaseQuizOption value="A">Usando variáveis de estado</BaseQuizOption>
  <BaseQuizOption value="B" correct>Usando props</BaseQuizOption>
  <BaseQuizOption value="C">Usando refs</BaseQuizOption>
  <BaseQuizOption value="D">Usando a API de contexto</BaseQuizOption>
  
  <BaseQuizAnswer>
    Props (abreviação de propriedades) são a principal forma de passar dados de componentes pai para componentes filho no React. Você passa props como atributos ao renderizar o componente filho.
  </BaseQuizAnswer>
</BaseQuiz>

### PropTypes: `Component.propTypes`

Valide as props passadas para os componentes (requer o pacote prop-types).

```javascript
import PropTypes from 'prop-types'

function Welcome({ name, age }) {
  return (
    <h1>
      Olá, {name}! Idade: {age}
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

Acesse o conteúdo passado entre as tags de abertura/fechamento do componente.

```javascript
// Componente que usa children
function Card({ children }) {
  return <div className="card">{children}</div>
}

// Uso
;<Card>
  <h2>Título</h2>
  <p>Conteúdo aqui</p>
</Card>
```

## Gerenciamento de Estado e Hooks

### Hook useState: `useState()`

Adicione estado a componentes funcionais.

```javascript
import React, { useState } from 'react'

function Counter() {
  const [count, setCount] = useState(0)
  return (
    <div>
      <p>Contagem: {count}</p>
      <button onClick={() => setCount(count + 1)}>Incrementar</button>
    </div>
  )
}

// Múltiplas variáveis de estado
function Form() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
}
```

<BaseQuiz id="react-usestate-1" correct="A">
  <template #question>
    O que <code>useState(0)</code> retorna?
  </template>
  
  <BaseQuizOption value="A" correct>Um array com o valor do estado e uma função para atualizá-lo</BaseQuizOption>
  <BaseQuizOption value="B">Apenas o valor do estado</BaseQuizOption>
  <BaseQuizOption value="C">Uma função para atualizar o estado</BaseQuizOption>
  <BaseQuizOption value="D">Nada, apenas define o estado</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>useState</code> retorna um array com dois elementos: o valor de estado atual e uma função para atualizá-lo. O valor inicial (0) é passado como argumento.
  </BaseQuizAnswer>
</BaseQuiz>

### Hook useEffect: `useEffect()`

Execute efeitos colaterais em componentes funcionais.

```javascript
import React, { useState, useEffect } from 'react'

function Timer() {
  const [count, setCount] = useState(0)

  // O efeito é executado após cada renderização
  useEffect(() => {
    document.title = `Contagem: ${count}`
  })

  // Efeito com limpeza
  useEffect(() => {
    const timer = setInterval(() => setCount((c) => c + 1), 1000)
    return () => clearInterval(timer)
  }, [])
}
```

<BaseQuiz id="react-useeffect-1" correct="D">
  <template #question>
    O que o array de dependências vazio <code>[]</code> em <code>useEffect(() => {...}, [])</code> significa?
  </template>
  
  <BaseQuizOption value="A">O efeito é executado em cada renderização</BaseQuizOption>
  <BaseQuizOption value="B">O efeito nunca é executado</BaseQuizOption>
  <BaseQuizOption value="C">O efeito é executado duas vezes</BaseQuizOption>
  <BaseQuizOption value="D" correct>O efeito é executado apenas uma vez após a renderização inicial</BaseQuizOption>
  
  <BaseQuizAnswer>
    Um array de dependências vazio significa que o efeito não tem dependências, então ele será executado apenas uma vez após o componente ser montado. Isso é útil para código de configuração que deve ser executado apenas uma vez.
  </BaseQuizAnswer>
</BaseQuiz>

### Estado de Classe: `this.state` / `setState()`

Gerencie o estado em componentes de classe.

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
        <p>Contagem: {this.state.count}</p>
        <button onClick={this.increment}>Incrementar</button>
      </div>
    )
  }
}
```

### Hooks Personalizados: `use...`

Crie lógica de estado reutilizável.

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
      <p>Contagem: {count}</p>
      <button onClick={increment}>+</button>
      <button onClick={decrement}>-</button>
      <button onClick={reset}>Resetar</button>
    </div>
  )
}
```

## Manipulação de Eventos

<BaseQuiz id="react-props-2" correct="A">
  <template #question>
    Qual é o propósito do PropTypes no React?
  </template>
  
  <BaseQuizOption value="A" correct>Validar os tipos de props passadas para os componentes</BaseQuizOption>
  <BaseQuizOption value="B">Melhorar o desempenho do componente</BaseQuizOption>
  <BaseQuizOption value="C">Estilizar componentes automaticamente</BaseQuizOption>
  <BaseQuizOption value="D">Tornar os componentes mais rápidos</BaseQuizOption>
  
  <BaseQuizAnswer>
    PropTypes ajuda a capturar erros validando se os componentes recebem props do tipo correto. Eles fornecem verificação de tipo em tempo de execução e são especialmente úteis durante o desenvolvimento.
  </BaseQuizAnswer>
</BaseQuiz>

### Eventos de Clique: `onClick`

Manipule cliques de botão e interações de elementos.

```javascript
function Button() {
  const handleClick = () => {
    alert('Botão clicado!')
  }
  return <button onClick={handleClick}>Clique em mim</button>
}

// Manipulador de evento em linha
function Button() {
  return <button onClick={() => alert('Clicado!')}>Clique em mim</button>
}

// Passando parâmetros
function Button() {
  const handleClick = (message) => {
    alert(message)
  }
  return <button onClick={() => handleClick('Olá!')}>Clique em mim</button>
}
```

### Eventos de Formulário: `onChange` / `onSubmit`

Manipule entradas e envios de formulário.

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
        placeholder="Digite o texto"
      />
      <button type="submit">Enviar</button>
    </form>
  )
}
```

### Objeto de Evento: `event.target` / `event.preventDefault()`

Acesse propriedades de evento e controle o comportamento padrão.

```javascript
function handleInput(event) {
  console.log('Valor da entrada:', event.target.value)
  console.log('Nome da entrada:', event.target.name)
}

function handleFormSubmit(event) {
  event.preventDefault() // Previne o envio do formulário
  console.log('Formulário enviado')
}

// Delegação de eventos
function List() {
  const handleClick = (event) => {
    if (event.target.tagName === 'BUTTON') {
      console.log('Botão clicado:', event.target.textContent)
    }
  }
  return (
    <div onClick={handleClick}>
      <button>Botão 1</button>
      <button>Botão 2</button>
    </div>
  )
}
```

### Eventos de Teclado: `onKeyDown` / `onKeyUp`

Responda a interações do teclado.

```javascript
function KeyboardHandler() {
  const handleKeyDown = (event) => {
    if (event.key === 'Enter') {
      console.log('Tecla Enter pressionada')
    }
    if (event.ctrlKey && event.key === 's') {
      event.preventDefault()
      console.log('Ctrl+S pressionado')
    }
  }
  return <input onKeyDown={handleKeyDown} placeholder="Digite aqui..." />
}
```

## Renderização Condicional

### Operadores Condicionais: `&&` / `?:`

Mostrar/ocultar elementos com base em condições.

```javascript
function Greeting({ user }) {
  return (
    <div>
      {user && <h1>Bem-vindo, {user.name}!</h1>}
      {!user && <h1>Por favor, faça login</h1>}
    </div>
  )
}

// Operador ternário
function Status({ isOnline }) {
  return <div>Usuário está {isOnline ? 'online' : 'offline'}</div>
}
```

### Lógica If/Else: Declarações `if`

Use a lógica tradicional do JavaScript para condições complexas.

```javascript
function UserProfile({ user, isAdmin }) {
  if (!user) {
    return <div>Carregando...</div>
  }
  if (isAdmin) {
    return <AdminPanel user={user} />
  }
  return <UserPanel user={user} />
}

// Padrão de retorno antecipado
function Component({ data }) {
  if (!data) return null
  if (data.error) return <ErrorMessage />
  return <DataDisplay data={data} />
}
```

### Declarações Switch: `switch`

Lide com múltiplas condições de forma eficiente.

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

### Estilos Dinâmicos: CSS Condicional

Aplique estilos com base no estado ou nas props do componente.

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
      Clique em mim
    </button>
  )
}
```

## Renderização de Listas e Chaves

### Função Map: `array.map()`

Renderize listas de componentes a partir de dados de array.

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

// Com índice (evitar quando possível)
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

### Chaves: Prop `key`

Forneça identificadores exclusivos para itens de lista para otimizar a renderização.

```javascript
// Bom: usando ID exclusivo
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

// Criando chaves compostas
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

### Filtrar e Mapear: Métodos de Array

Processe arrays antes de renderizá-los.

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

### Estados Vazios: Lidando com arrays vazios

Exiba o conteúdo apropriado quando as listas estiverem vazias.

```javascript
function ProductList({ products }) {
  if (products.length === 0) {
    return <div>Nenhum produto encontrado.</div>
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

## Otimização de Desempenho

### React.memo: `React.memo()`

Evite renderizações desnecessárias de componentes funcionais.

```javascript
const ExpensiveComponent = React.memo(function ExpensiveComponent({ data }) {
  return <div>{/* Lógica de renderização complexa */}</div>
})

// Com comparação personalizada
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

Memoize cálculos caros.

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

Memoize referências de função para evitar renderizações desnecessárias.

```javascript
function Parent({ items }) {
  const [count, setCount] = useState(0)
  const handleItemClick = useCallback((itemId) => {
    console.log('Item clicado:', itemId)
  }, []) // Array de dependências vazio
  return (
    <div>
      <button onClick={() => setCount(count + 1)}>Contagem: {count}</button>
      <ItemList items={items} onItemClick={handleItemClick} />
    </div>
  )
}
```

### Carregamento Lento (Lazy Loading): `React.lazy()` / `Suspense`

Carregue componentes apenas quando necessário para reduzir o tamanho do pacote.

```javascript
const LazyComponent = React.lazy(() => import('./LazyComponent'))

function App() {
  return (
    <div>
      <Suspense fallback={<div>Carregando...</div>}>
        <LazyComponent />
      </Suspense>
    </div>
  )
}
```

## Comunicação entre Componentes

### Props Down: Pai para Filho

Passe dados de componentes pai para componentes filho.

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
  return <div>Olá, {user.name}!</div>
}
```

### Callbacks Up: Filho para Pai

Envie dados de componentes filho de volta para componentes pai.

```javascript
function Parent() {
  const [message, setMessage] = useState('')
  const handleChildMessage = (msg) => {
    setMessage(msg)
  }
  return (
    <div>
      <p>Mensagem: {message}</p>
      <Child onMessage={handleChildMessage} />
    </div>
  )
}

function Child({ onMessage }) {
  return (
    <button onClick={() => onMessage('Olá do filho!')}>Enviar Mensagem</button>
  )
}
```

### API de Contexto: `createContext` / `useContext`

Compartilhe estado entre vários componentes sem "prop drilling".

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
  return <h1>Bem-vindo, {user.name}!</h1>
}
```

### Refs: `useRef` / `forwardRef`

Acesse elementos DOM ou armazene valores mutáveis.

```javascript
function TextInput() {
  const inputRef = useRef(null)
  const focusInput = () => {
    inputRef.current.focus()
  }
  return (
    <div>
      <input ref={inputRef} type="text" />
      <button onClick={focusInput}>Focar Entrada</button>
    </div>
  )
}

// Encaminhamento de refs
const FancyInput = forwardRef((props, ref) => (
  <input className="fancy" ref={ref} {...props} />
))
```

## Ferramentas de Desenvolvimento e Depuração

### React DevTools: Extensão do Navegador

Depure componentes React e inspecione a árvore de componentes.

```javascript
// Instale a extensão do navegador React DevTools
// Aba Components: Inspecione a hierarquia de componentes
// Aba Profiler: Meça o desempenho

// Depuração no console
function MyComponent(props) {
  console.log('Props de MyComponent:', props)
  console.log('MyComponent renderizado')
  return <div>{props.children}</div>
}
```

### Boundaries de Erro: `componentDidCatch`

Capture erros de JavaScript na árvore de componentes e exiba uma UI de fallback.

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
    console.log('Erro capturado:', error, errorInfo)
  }
  render() {
    if (this.state.hasError) {
      return <h1>Algo deu errado.</h1>
    }
    return this.props.children
  }
}
```

### Strict Mode: `React.StrictMode`

Ative verificações e avisos adicionais para o desenvolvimento.

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

### Perfilamento: Medição de Desempenho

Meça o desempenho do componente e identifique gargalos.

```javascript
// Usando o Profiler do React DevTools
// Envolva componentes para perfilamento
import { Profiler } from 'react'

function onRenderCallback(id, phase, actualDuration) {
  console.log('Componente', id, 'levou', actualDuration, 'ms')
}

;<Profiler id="App" onRender={onRenderCallback}>
  <App />
</Profiler>
```

## Instalação e Configuração do React

### Create React App: `npx create-react-app`

Inicie rapidamente um novo projeto React.

```bash
# Crie um novo aplicativo React
npx create-react-app meu-app
cd meu-app

# Inicie o servidor de desenvolvimento
npm start

# Construa para produção
npm run build

# Execute testes
npm test
```

### Vite: `npm create vite@latest`

Ferramenta de compilação rápida e servidor de desenvolvimento para projetos React.

```bash
# Crie um novo aplicativo Vite React
npm create vite@latest meu-app-react -- --template react
cd meu-app-react
npm install

# Inicie o servidor de desenvolvimento
npm run dev

# Construa para produção
npm run build
```

### Configuração Manual / Importação

Adicione React a um projeto existente ou use CDN.

```bash
# Instale React e ReactDOM
npm install react react-dom

# Para desenvolvimento
npm install --save-dev @vitejs/plugin-react
```

```javascript
// Importação básica do React
import React from 'react'
import ReactDOM from 'react-dom/client'

// Renderizar no DOM
const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(<App />)
```

## Padrões e Recursos Avançados

### Componentes de Ordem Superior (HOC)

Reutilize a lógica do componente envolvendo componentes.

```javascript
function withLoading(WrappedComponent) {
  return function WithLoadingComponent(props) {
    if (props.isLoading) {
      return <div>Carregando...</div>
    }
    return <WrappedComponent {...props} />
  }
}

// Uso
const UserListWithLoading = withLoading(UserList)
;<UserListWithLoading users={users} isLoading={loading} />
```

### Padrão Render Props

Compartilhe código entre componentes usando uma prop cujo valor é uma função.

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

### Componentes Compostos

Crie componentes que trabalham juntos como uma unidade coesa.

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
  <Tab>Conteúdo da Aba 1</Tab>
  <Tab>Conteúdo da Aba 2</Tab>
</Tabs>
```

### Portal: `ReactDOM.createPortal()`

Renderize filhos em um nó DOM fora da hierarquia do componente pai.

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

### Composição sobre Herança

Use padrões de composição em vez de estender classes.

```javascript
// Bom: Composição
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

### Padrões de Componentes: APIs Flexíveis

Projete APIs de componentes que sejam flexíveis e fáceis de usar.

```javascript
// Componente Card flexível
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
;<Card header={<h3>Título</h3>} footer={<Button>Ação</Button>}>
  Conteúdo do Card aqui
</Card>
```

## Links Relevantes

- <router-link to="/javascript">Folha de Dicas de JavaScript</router-link>
- <router-link to="/html">Folha de Dicas de HTML</router-link>
- <router-link to="/css">Folha de Dicas de CSS</router-link>
- <router-link to="/web-development">Folha de Dicas de Desenvolvimento Web</router-link>

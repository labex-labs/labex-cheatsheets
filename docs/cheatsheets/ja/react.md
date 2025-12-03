---
title: 'React チートシート | LabEx'
description: 'この包括的なチートシートで React 開発を学習しましょう。React フック、コンポーネント、JSX、状態管理、プロパティ、最新のフロントエンド開発パターンのクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/react-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
React チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/react">ハンズオンラボで React を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと現実世界のシナリオを通じて、React フロントエンド開発を学びましょう。LabEx は、必須のコンポーネント作成、状態管理、フック、イベント処理、パフォーマンス最適化を網羅した包括的な React コースを提供します。最新の Web アプリケーション向けに効率的で保守性の高いユーザーインターフェースを構築するスキルを習得します。
</base-disclaimer-content>
</base-disclaimer>

## コンポーネントの作成と JSX

### 関数コンポーネント：`function` / `=>`

関数構文を使用してコンポーネントを作成します。

```javascript
import React from 'react'

// 関数宣言
function Welcome(props) {
  return <h1>Hello, {props.name}!</h1>
}

// アロー関数
const Welcome = (props) => {
  return <h1>Hello, {props.name}!</h1>
}

// シンプルなコンポーネントの暗黙的な返却
const Greeting = ({ name }) => <h1>Hello, {name}!</h1>
```

### クラスコンポーネント：`class extends React.Component`

ES6 クラス構文を使用してコンポーネントを作成します。

```javascript
import React, { Component } from 'react'

class Welcome extends Component {
  render() {
    return <h1>Hello, {this.props.name}!</h1>
  }
}

// constructor 付き
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

### JSX 要素：`<element>`

JavaScript 内で HTML のような構文を記述します。

```javascript
// JSX 要素
const element = <h1>Hello, world!</h1>

// 式を含む JSX
const name = 'John'
const greeting = <h1>Hello, {name}!</h1>

// 複数行の JSX
const element = (
  <div>
    <h1>Welcome!</h1>
    <p>Good to see you here.</p>
  </div>
)
```

### コンポーネントのエクスポート：`export default` / `export`

コンポーネントをエクスポートして、他のファイルで使用できるようにします。

```javascript
// デフォルトエクスポート
export default function App() {
  return <div>My App</div>
}

// 名前付きエクスポート
export const Button = () => <button>Click me</button>
```

### コンポーネントのインポート：`import`

他のファイルからコンポーネントをインポートします。

```javascript
// デフォルトコンポーネントのインポート
import App from './App'

// 名前付きコンポーネントのインポート
import { Button } from './Button'

// 複数のコンポーネントのインポート
import React, { useState, useEffect } from 'react'

// エイリアス付きのインポート
import { Button as MyButton } from './Button'
```

### フラグメント：`<React.Fragment>` / `<>`

余分な DOM ノードを追加せずに要素をグループ化します。

```javascript
// React.Fragment を使用
return (
  <React.Fragment>
    <h1>Title</h1>
    <p>Description</p>
  </React.Fragment>
)

// 短縮構文を使用
return (
  <>
    <h1>Title</h1>
    <p>Description</p>
  </>
)
```

## Props とコンポーネントの構造

### Props: `props.name`

親から子コンポーネントへデータを渡します。

```javascript
// props の受信
function Welcome(props) {
  return <h1>Hello, {props.name}!</h1>
}

// props の分割代入
function Welcome({ name, age }) {
  return (
    <h1>
      Hello, {name}! You are {age} years old.
    </h1>
  )
}

// デフォルト props
function Welcome({ name = 'Guest' }) {
  return <h1>Hello, {name}!</h1>
}
```

<BaseQuiz id="react-props-1" correct="B">
  <template #question>
    React で親コンポーネントから子コンポーネントにデータを渡すにはどうすればよいですか？
  </template>
  
  <BaseQuizOption value="A">state 変数を使用する</BaseQuizOption>
  <BaseQuizOption value="B" correct>props を使用する</BaseQuizOption>
  <BaseQuizOption value="C">ref を使用する</BaseQuizOption>
  <BaseQuizOption value="D">context API を使用する</BaseQuizOption>
  
  <BaseQuizAnswer>
    Props（プロパティの略）は、React で親から子コンポーネントへデータを渡す主要な方法です。子コンポーネントをレンダリングする際に、属性として props を渡します。
  </BaseQuizAnswer>
</BaseQuiz>

### PropTypes: `Component.propTypes`

コンポーネントに渡された props を検証します（prop-types パッケージが必要）。

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

コンポーネントの開始タグと終了タグの間で渡されたコンテンツにアクセスします。

```javascript
// children を使用するコンポーネント
function Card({ children }) {
  return <div className="card">{children}</div>
}

// 使用例
;<Card>
  <h2>Title</h2>
  <p>Content here</p>
</Card>
```

## 状態管理とフック

### useState フック：`useState()`

関数コンポーネントに状態を追加します。

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

// 複数の状態変数
function Form() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
}
```

<BaseQuiz id="react-usestate-1" correct="A">
  <template #question>
    `useState(0)` は何を返しますか？
  </template>
  
  <BaseQuizOption value="A" correct>状態値とそれを更新する関数の配列</BaseQuizOption>
  <BaseQuizOption value="B">状態値のみ</BaseQuizOption>
  <BaseQuizOption value="C">状態を更新するための関数</BaseQuizOption>
  <BaseQuizOption value="D">状態を設定するだけで何も返さない</BaseQuizOption>
  
  <BaseQuizAnswer>
    `useState` は、現在の状態値とそれを更新する関数の 2 つの要素を持つ配列を返します。引数として初期値（0）が渡されます。
  </BaseQuizAnswer>
</BaseQuiz>

### useEffect フック：`useEffect()`

関数コンポーネントで副作用を実行します。

```javascript
import React, { useState, useEffect } from 'react'

function Timer() {
  const [count, setCount] = useState(0)

  // すべてのレンダリング後に実行されるエフェクト
  useEffect(() => {
    document.title = `Count: ${count}`
  })

  // クリーンアップ付きのエフェクト
  useEffect(() => {
    const timer = setInterval(() => setCount((c) => c + 1), 1000)
    return () => clearInterval(timer)
  }, [])
}
```

<BaseQuiz id="react-useeffect-1" correct="D">
  <template #question>
    `useEffect(() => {...}, [])`の空の依存関係配列は何を意味しますか？
  </template>
  
  <BaseQuizOption value="A">エフェクトはすべてのレンダリングで実行される</BaseQuizOption>
  <BaseQuizOption value="B">エフェクトは実行されない</BaseQuizOption>
  <BaseQuizOption value="C">エフェクトは 2 回実行される</BaseQuizOption>
  <BaseQuizOption value="D" correct>エフェクトは最初のレンダリング後に一度だけ実行される</BaseQuizOption>
  
  <BaseQuizAnswer>
    空の依存関係配列は、エフェクトに依存関係がないことを意味するため、コンポーネントのマウント後に一度だけ実行されます。これは一度だけ実行されるべきセットアップコードに役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

### クラスの状態：`this.state` / `setState()`

クラスコンポーネントで状態を管理します。

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

### カスタムフック：`use...`

再利用可能な状態ロジックを作成します。

```javascript
// カスタムフック
function useCounter(initialValue = 0) {
  const [count, setCount] = useState(initialValue)
  const increment = () => setCount(count + 1)
  const decrement = () => setCount(count - 1)
  const reset = () => setCount(initialValue)
  return { count, increment, decrement, reset }
}

// 使用例
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

## イベント処理

<BaseQuiz id="react-props-2" correct="A">
  <template #question>
    React における PropTypes の目的は何ですか？
  </template>
  
  <BaseQuizOption value="A" correct>コンポーネントに渡される props の型を検証すること</BaseQuizOption>
  <BaseQuizOption value="B">コンポーネントのパフォーマンスを向上させること</BaseQuizOption>
  <BaseQuizOption value="C">コンポーネントを自動的にスタイリングすること</BaseQuizOption>
  <BaseQuizOption value="D">コンポーネントを高速化すること</BaseQuizOption>
  
  <BaseQuizAnswer>
    PropTypes は、コンポーネントが正しい型の props を受け取ることを検証することでバグの発見に役立ちます。これらはランタイムの型チェックを提供し、特に開発中に役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

### クリックイベント：`onClick`

ボタンのクリックや要素の操作を処理します。

```javascript
function Button() {
  const handleClick = () => {
    alert('Button clicked!')
  }
  return <button onClick={handleClick}>Click me</button>
}

// インラインイベントハンドラ
function Button() {
  return <button onClick={() => alert('Clicked!')}>Click me</button>
}

// パラメータを渡す
function Button() {
  const handleClick = (message) => {
    alert(message)
  }
  return <button onClick={() => handleClick('Hello!')}>Click me</button>
}
```

### フォームイベント：`onChange` / `onSubmit`

フォームの入力と送信を処理します。

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

### イベントオブジェクト：`event.target` / `event.preventDefault()`

イベントプロパティにアクセスし、デフォルトの動作を制御します。

```javascript
function handleInput(event) {
  console.log('Input value:', event.target.value)
  console.log('Input name:', event.target.name)
}

function handleFormSubmit(event) {
  event.preventDefault() // フォームの送信を防止
  console.log('Form submitted')
}

// イベントの委譲
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

### キーボードイベント：`onKeyDown` / `onKeyUp`

キーボード操作に応答します。

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

## 条件付きレンダリング

### 条件演算子：`&&` / `?:`

条件に基づいて要素を表示/非表示にします。

```javascript
function Greeting({ user }) {
  return (
    <div>
      {user && <h1>Welcome, {user.name}!</h1>}
      {!user && <h1>Please log in</h1>}
    </div>
  )
}

// 三項演算子
function Status({ isOnline }) {
  return <div>User is {isOnline ? 'online' : 'offline'}</div>
}
```

### If/Elseロジック: `if`文

複雑な条件のために従来の JavaScript ロジックを使用します。

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

// 早期リターンパターン
function Component({ data }) {
  if (!data) return null
  if (data.error) return <ErrorMessage />
  return <DataDisplay data={data} />
}
```

### Switch 文：`switch`

複数の条件を効率的に処理します。

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

### 動的スタイル：条件付き CSS

コンポーネントの状態や props に基づいてスタイルを適用します。

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

## リストのレンダリングとキー

### Map 関数：`array.map()`

配列データからコンポーネントのリストをレンダリングします。

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

// インデックス付き（可能な限り避ける）
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

### キー: `key` prop

レンダリングを最適化するために、リスト項目に一意の識別子を提供します。

```javascript
// 良い例：一意の ID を使用
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

// 複合キーの作成
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

### Filter と Map: 配列メソッド

リストをレンダリングする前に配列を処理します。

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

### 空の状態：空の配列の処理

リストが空の場合に適切なコンテンツを表示します。

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

## パフォーマンスの最適化

### React.memo: `React.memo()`

関数コンポーネントの不要な再レンダリングを防ぎます。

```javascript
const ExpensiveComponent = React.memo(function ExpensiveComponent({ data }) {
  return <div>{/* 複雑なレンダリングロジック */}</div>
})

// カスタム比較付き
const MyComponent = React.memo(
  function MyComponent({ user }) {
    return <div>{user.name}</div>
  },
  (prevProps, nextProps) => {
    return prevProps.user.id === nextProps.user.id
  },
)
```

### useMemo フック：`useMemo()`

高負荷な計算をメモ化します。

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

### useCallback フック：`useCallback()`

関数参照をメモ化して、不要な再レンダリングを防ぎます。

```javascript
function Parent({ items }) {
  const [count, setCount] = useState(0)
  const handleItemClick = useCallback((itemId) => {
    console.log('Item clicked:', itemId)
  }, []) // 空の依存関係配列
  return (
    <div>
      <button onClick={() => setCount(count + 1)}>Count: {count}</button>
      <ItemList items={items} onItemClick={handleItemClick} />
    </div>
  )
}
```

### 遅延ロード：`React.lazy()` / `Suspense`

バンドルサイズを削減するために、必要なときにのみコンポーネントをロードします。

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

## コンポーネント間の通信

### Props Down: 親から子へ

親コンポーネントから子コンポーネントへデータを渡します。

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

### Callbacks Up: 子から親へ

子コンポーネントから親コンポーネントへデータを送り返します。

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

プロップドリリングなしで複数のコンポーネント間で状態を共有します。

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

DOM 要素にアクセスしたり、変更可能な値を格納したりします。

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

// Ref の転送
const FancyInput = forwardRef((props, ref) => (
  <input className="fancy" ref={ref} {...props} />
))
```

## 開発ツールとデバッグ

### React DevTools: ブラウザ拡張機能

React コンポーネントをデバッグし、コンポーネントツリーを検査します。

```javascript
// React DevTools ブラウザ拡張機能をインストール
// Components タブ：コンポーネント階層の検査
// Profiler タブ：パフォーマンスの測定

// コンソールデバッグ
function MyComponent(props) {
  console.log('MyComponent props:', props)
  console.log('MyComponent rendered')
  return <div>{props.children}</div>
}
```

### エラー境界線：`componentDidCatch`

コンポーネントツリー内の JavaScript エラーをキャッチし、フォールバック UI を表示します。

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

開発中に、追加のチェックと警告を有効にします。

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

### プロファイリング：パフォーマンス測定

コンポーネントのパフォーマンスを測定し、ボトルネックを特定します。

```javascript
// React DevTools Profiler の使用
// プロファイル対象のコンポーネントをラップ
import { Profiler } from 'react'

function onRenderCallback(id, phase, actualDuration) {
  console.log('Component', id, 'took', actualDuration, 'ms')
}

;<Profiler id="App" onRender={onRenderCallback}>
  <App />
</Profiler>
```

## React のインストールとセットアップ

### Create React App: `npx create-react-app`

新しい React プロジェクトを迅速にブートストラップします。

```bash
# 新しいReactアプリの作成
npx create-react-app my-app
cd my-app

# 開発サーバーの起動
npm start

# 本番環境向けビルド
npm run build

# テストの実行
npm test
```

### Vite: `npm create vite@latest`

React プロジェクト向けの高速なビルドツールと開発サーバー。

```bash
# 新しいVite Reactアプリの作成
npm create vite@latest my-react-app -- --template react
cd my-react-app
npm install

# 開発サーバーの起動
npm run dev

# 本番環境向けビルド
npm run build
```

### 手動セットアップ/インポート

既存のプロジェクトに React を追加するか、CDN を使用します。

```bash
# ReactとReactDOMのインストール
npm install react react-dom

# 開発用
npm install --save-dev @vitejs/plugin-react
```

```javascript
// 基本的な React インポート
import React from 'react'
import ReactDOM from 'react-dom/client'

// DOM へのレンダリング
const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(<App />)
```

## 高度なパターンと機能

### 高階コンポーネント (HOC)

コンポーネントをラップすることで、コンポーネントロジックを再利用します。

```javascript
function withLoading(WrappedComponent) {
  return function WithLoadingComponent(props) {
    if (props.isLoading) {
      return <div>Loading...</div>
    }
    return <WrappedComponent {...props} />
  }
}

// 使用例
const UserListWithLoading = withLoading(UserList)
;<UserListWithLoading users={users} isLoading={loading} />
```

### Render Props パターン

props の値として関数を使用することで、コンポーネント間でコードを共有します。

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

// 使用例
;<DataFetcher
  url="/api/users"
  render={({ data, loading }) =>
    loading ? <Spinner /> : <UserList users={data} />
  }
/>
```

### 複合コンポーネント

協調して機能する一貫したユニットとしてコンポーネントを作成します。

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

// 使用例
;<Tabs activeTab={0}>
  <Tab>Tab 1 Content</Tab>
  <Tab>Tab 2 Content</Tab>
</Tabs>
```

### Portal: `ReactDOM.createPortal()`

子要素を親コンポーネントの階層外の DOM ノードにレンダリングします。

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

### 継承よりもコンポジション

クラスを拡張する代わりに、コンポジションパターンを使用します。

```javascript
// 良い例：コンポジション
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

### コンポーネントパターン：柔軟な API

柔軟で使いやすいコンポーネント API を設計します。

```javascript
// 柔軟な Card コンポーネント
function Card({ header, children, footer, variant = 'default' }) {
  return (
    <div className={`card card-${variant}`}>
      {header && <div className="card-header">{header}</div>}
      <div className="card-body">{children}</div>
      {footer && <div className="card-footer">{footer}</div>}
    </div>
  )
}

// 使用例
;<Card header={<h3>Title</h3>} footer={<Button>Action</Button>}>
  Card content here
</Card>
```

## 関連リンク

- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/html">HTML チートシート</router-link>
- <router-link to="/css">CSS チートシート</router-link>
- <router-link to="/web-development">Web 開発チートシート</router-link>

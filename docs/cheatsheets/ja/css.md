---
title: 'CSS チートシート'
description: '必須のコマンド、概念、ベストプラクティスを網羅した包括的なチートシートで CSS を学習しましょう。'
pdfUrl: '/cheatsheets/pdf/css-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
CSS チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/css">ハンズオンラボで CSS を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて CSS ウェブスタイリングを学びましょう。LabEx は、必須プロパティ、セレクタ、レイアウト技術、レスポンシブデザイン、および最新機能を網羅した包括的な CSS コースを提供します。最新のウェブ開発ワークフローのために、効率的なウェブスタイリングとレイアウトデザインを習得します。
</base-disclaimer-content>
</base-disclaimer>

## CSS 構文とセレクタ

### 基本構文

CSS は、セレクタと宣言で構成されます。セレクタは HTML 要素をターゲットにし、宣言はプロパティ値の設定を行います。

```css
/* 基本構文 */
selector {
  property: value;
  property: value;
}

/* 例 */
p {
  color: red;
  font-size: 16px;
}
```

### 要素セレクタ

タグ名で HTML 要素をターゲットにします。

```css
/* すべての段落を選択 */
p {
  color: blue;
}

/* すべての見出しを選択 */
h1 {
  font-size: 2em;
}

/* すべてのリンクを選択 */
a {
  text-decoration: none;
}
```

### クラスセレクタ

特定の`class`属性を持つ要素をターゲットにします。

```css
/* class="highlight" を持つ要素を選択 */
.highlight {
  background-color: yellow;
}

/* class="intro" を持つ段落を選択 */
p.intro {
  font-weight: bold;
}

/* 複数のクラス */
.large.bold {
  font-size: 20px;
  font-weight: bold;
}
```

### ID セレクタ

特定の`ID`属性を持つ要素をターゲットにします。

```css
/* id="header" を持つ要素を選択 */
#header {
  background-color: #333;
}

/* ID はページごとに一意であるべき */
#navigation {
  position: fixed;
}
```

### 属性セレクタ

属性セレクタを使用して、特定の属性を持つ要素をターゲットにします。

```css
/* title 属性を持つ要素 */
[title] {
  cursor: help;
}

/* 外部リンク (http で始まる href) */
a[href^='http'] {
  color: red;
}

/* type が text の入力要素 */
input[type='text'] {
  border: 1px solid #ccc;
}
```

### 擬似クラス

擬似クラスは、状態の変化やユーザー操作に基づいて CSS を適用します。

```css
/* リンクの状態 */
a:hover {
  color: red;
}
a:visited {
  color: purple;
}
a:active {
  color: orange;
}

/* フォームの状態 */
input:focus {
  border-color: blue;
}
input:invalid {
  border-color: red;
}

/* 構造的擬似クラス */
li:first-child {
  font-weight: bold;
}
li:nth-child(odd) {
  background-color: #f0f0f0;
}
```

## ボックスモデルとレイアウト

### コンテンツ：`width` / `height`

要素の実際のコンテンツ領域。

```css
/* 寸法の設定 */
div {
  width: 300px;
  height: 200px;
}

/* レスポンシブなサイズ設定 */
.container {
  width: 100%;
  max-width: 1200px;
}

/* 最小/最大制約 */
.box {
  min-height: 100px;
  max-width: 500px;
}
```

### パディング：`padding`

コンテンツと境界線の間のスペース。要素の内部にあります。

```css
/* 全方向 */
div {
  padding: 20px;
}

/* 個別の辺 */
div {
  padding-top: 10px;
  padding-right: 15px;
}

/* ショートハンド：上 右 下 左 */
div {
  padding: 10px 15px 20px 5px;
}
```

### ボーダー: `border`

要素のフレームを提供し、サイズ、スタイル、色をカスタマイズできます。

```css
/* ボーダーのショートハンド */
div {
  border: 2px solid #333;
}

/* 個別のプロパティ */
div {
  border-width: 1px;
  border-style: dashed;
  border-color: red;
}

/* 個別の辺 */
div {
  border-bottom: 3px solid blue;
}
```

### マージン：`margin`

境界線の外側のスペース。要素間に適用されます。

```css
/* 全方向 */
div {
  margin: 20px;
}

/* 水平方向の中央揃え */
div {
  margin: 0 auto;
}

/* 個別の辺 */
div {
  margin-top: 30px;
  margin-bottom: 10px;
}

/* 負のマージン */
div {
  margin-left: -20px;
}
```

## テキストとタイポグラフィ

### フォントプロパティ

フォントファミリー、サイズ、太さ、スタイルを制御します。

```css
/* フォントファミリー */
body {
  font-family: Arial, sans-serif;
}

/* Google Fonts */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
body {
  font-family: 'Roboto', sans-serif;
}

/* フォントサイズ */
h1 {
  font-size: 2rem;
}
p {
  font-size: 16px;
}

/* フォントの太さ */
h2 {
  font-weight: bold;
}
span {
  font-weight: 300;
}
```

### テキストの配置

テキストの位置と間隔を制御します。

```css
/* 水平方向の配置 */
h1 {
  text-align: center;
}
p {
  text-align: justify;
}

/* 行の高さ */
p {
  line-height: 1.6;
}

/* 文字間隔と単語間隔 */
h1 {
  letter-spacing: 2px;
}
p {
  word-spacing: 4px;
}
```

### テキストのスタイリング

テキストに装飾や変換を追加します。

```css
/* テキスト装飾 */
a {
  text-decoration: underline;
}
.strike {
  text-decoration: line-through;
}

/* テキスト変換 */
.uppercase {
  text-transform: uppercase;
}
.capitalize {
  text-transform: capitalize;
}

/* テキストシャドウ */
h1 {
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}
```

### 色

CSS には、さまざまなスタイリングニーズに対応するためにいくつかの異なる色の指定方法があります。

```css
/* 色の形式 */
p {
  color: red;
}
div {
  background-color: #ff5733;
}
span {
  color: rgb(255, 87, 51);
}
section {
  background-color: rgba(255, 87, 51, 0.8);
}

/* HSL 色 */
header {
  background-color: hsl(200, 100%, 50%);
}

/* CSS 変数による色 */
:root {
  --primary-color: #3498db;
}
.button {
  background-color: var(--primary-color);
}
```

## Flexbox レイアウト

### Flex コンテナのプロパティ

親コンテナに適用されるプロパティ。

```css
/* Flexbox を有効にする */
.container {
  display: flex;
}

/* flex-direction */
.container {
  flex-direction: row; /* デフォルト */
  flex-direction: column;
  flex-direction: row-reverse;
}

/* justify-content (主軸) */
.container {
  justify-content: flex-start; /* デフォルト */
  justify-content: center;
  justify-content: space-between;
  justify-content: space-around;
}

/* align-items (交差軸) */
.container {
  align-items: stretch; /* デフォルト */
  align-items: center;
  align-items: flex-start;
}
```

### Flex アイテムのプロパティ

子要素に適用されるプロパティ。

```css
/* flex grow/shrink */
.item {
  flex-grow: 1; /* スペースを埋めるために拡大 */
  flex-shrink: 1; /* 必要に応じて縮小 */
  flex-basis: auto; /* 初期サイズ */
}

/* ショートハンド */
.item {
  flex: 1; /* flex: 1 1 0% */
  flex: 0 0 200px; /* 固定幅 */
}

/* 個別の配置 */
.item {
  align-self: center;
  align-self: flex-end;
}

/* order */
.item {
  order: 2; /* 視覚的な順序を変更 */
}
```

## CSS Grid レイアウト

### Grid コンテナ

グリッド構造とプロパティを定義します。

```css
/* グリッドを有効にする */
.grid-container {
  display: grid;
}

/* 列と行の定義 */
.grid-container {
  grid-template-columns: 1fr 2fr 1fr;
  grid-template-rows: 100px auto 50px;
}

/* グリッドの間隔 */
.grid-container {
  gap: 20px;
  column-gap: 30px;
  row-gap: 10px;
}

/* 名前付きグリッドエリア */
.grid-container {
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}
```

### Grid アイテム

グリッドアイテムの位置とサイズを設定します。

```css
/* グリッドの位置指定 */
.grid-item {
  grid-column: 1 / 3; /* 列 1 から 2 までをまたぐ */
  grid-row: 2 / 4; /* 行 2 から 3 までをまたぐ */
}

/* ショートハンド */
.grid-item {
  grid-area: 2 / 1 / 4 / 3; /* row-start / col-start / row-end / col-end */
}

/* 名前付きエリア */
.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}

/* 自動配置 */
.grid-item {
  grid-column: span 2; /* 2 列分をまたぐ */
  grid-row: span 3; /* 3 行分をまたぐ */
}
```

## ポジショニング

### position プロパティ

要素のポジショニング動作を制御します。

```css
/* static (デフォルト) */
.element {
  position: static;
}

/* relative ポジショニング */
.element {
  position: relative;
  top: 20px;
  left: 10px;
}

/* absolute ポジショニング */
.element {
  position: absolute;
  top: 0;
  right: 0;
}

/* fixed ポジショニング */
.navbar {
  position: fixed;
  top: 0;
  width: 100%;
}

/* sticky ポジショニング */
.sidebar {
  position: sticky;
  top: 20px;
}
```

### Z-Index とスタッキング

`z-index`を使用して、要素が互いに重なり合う順序を制御します。

```css
/* スタッキング順序 */
.modal {
  position: fixed;
  z-index: 1000;
}
.overlay {
  position: absolute;
  z-index: 999;
}

/* スタッキングコンテキストの作成 */
.container {
  position: relative;
  z-index: 0;
}

/* 一般的な z-index の値 */
.dropdown {
  z-index: 100;
}
.modal {
  z-index: 1000;
}
.tooltip {
  z-index: 10000;
}
```

## レスポンシブデザイン

### メディアクエリ

デバイスの特性に基づいてスタイルを適用します。

```css
/* モバイルファーストのアプローチ */
.container {
  width: 100%;
}

/* タブレットスタイル */
@media (min-width: 768px) {
  .container {
    width: 750px;
  }
}

/* デスクトップスタイル */
@media (min-width: 1024px) {
  .container {
    width: 960px;
  }
}

/* 印刷スタイル */
@media print {
  body {
    font-size: 12pt;
  }
  .no-print {
    display: none;
  }
}

/* 向き */
@media (orientation: landscape) {
  .sidebar {
    display: block;
  }
}
```

### レスポンシブ単位

柔軟なレイアウトのために相対的な単位を使用します。

```css
/* ビューポート単位 */
.hero {
  height: 100vh;
} /* ビューポートの高さ全体 */
.sidebar {
  width: 25vw;
} /* ビューポート幅の 25% */

/* 相対単位 */
p {
  font-size: 1.2em;
} /* 親のフォントサイズの 1.2 倍 */
h1 {
  font-size: 2rem;
} /* ルートフォントサイズの 2 倍 */

/* パーセンテージ単位 */
.container {
  width: 80%;
}
.column {
  width: 50%;
}

/* CSS Grid レスポンシブ */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

/* Flexbox レスポンシブ */
.flex-container {
  display: flex;
  flex-wrap: wrap;
}
```

## アニメーションとトランジション

### CSS トランジション

プロパティ値間のスムーズな変化。

```css
/* 基本的なトランジション */
.button {
  background-color: blue;
  transition: background-color 0.3s ease;
}
.button:hover {
  background-color: red;
}

/* 複数のプロパティ */
.card {
  transform: scale(1);
  opacity: 1;
  transition: all 0.3s ease-in-out;
}
.card:hover {
  transform: scale(1.05);
  opacity: 0.8;
}

/* 個別のトランジション */
.element {
  transition-property: width, height;
  transition-duration: 0.5s, 1s;
  transition-timing-function: ease, linear;
}
```

### CSS アニメーション

キーフレームを使用して複雑なアニメーションを作成します。

```css
/* キーフレームの定義 */
@keyframes slideIn {
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(0);
  }
}

@keyframes pulse {
  0%,
  100% {
    transform: scale(1);
  }
  50% {
    transform: scale(1.1);
  }
}

/* アニメーションの適用 */
.slide-in {
  animation: slideIn 0.5s ease-out;
}
.pulse {
  animation: pulse 2s infinite;
}

/* アニメーションのショートハンド */
.spinner {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}
```

## CSS 変数と関数

### CSS 変数

一貫したテーマ設定のためにカスタムプロパティを定義します。

```css
/* 変数の定義 */
:root {
  --primary-color: #3498db;
  --secondary-color: #2ecc71;
  --font-size-large: 24px;
  --border-radius: 8px;
}

/* 変数の使用 */
.button {
  background-color: var(--primary-color);
  border-radius: var(--border-radius);
}

/* フォールバック値 */
.text {
  color: var(--text-color, #333);
}

/* ローカル変数 */
.card {
  --card-padding: 20px;
  padding: var(--card-padding);
}
```

### CSS 関数

計算や動的な値のために、CSS には一連の組み込み関数があります。

```css
/* calc 関数 */
.container {
  width: calc(100% - 40px);
  height: calc(100vh - 60px);
}

/* min/max 関数 */
.responsive {
  width: min(90%, 1200px);
  font-size: max(16px, 1.2vw);
  height: clamp(200px, 50vh, 400px);
}

/* 色の関数 */
.element {
  background-color: hsl(200, 50%, 50%);
  color: rgb(255, 87, 51);
}

/* transform 関数 */
.rotate {
  transform: rotate(45deg);
}
.scale {
  transform: scale(1.5);
}
.translate {
  transform: translate(20px, 30px);
}
```

## ベストプラクティスと構成

### CSS の構成

保守性のために CSS を構造化します。

```css
/* 意味のあるクラス名を使用 */
.hero-section {
}
.primary-button {
}
.navigation-menu {
}

/* BEM メソドロジー */
.block {
}
.block__element {
}
.block--modifier {
}

/* 例 */
.card {
}
.card__header {
}
.card__body {
}
.card--featured {
}

/* 関連するスタイルをグループ化 */
/* ===== レイアウト ===== */
.container {
}
.grid {
}

/* ===== コンポーネント ===== */
.button {
}
.card {
}
```

### パフォーマンスと最適化

パフォーマンス向上のために効率的な CSS を記述します。

```css
/* 深いネストを避ける */
/* 悪い例 */
.header .nav ul li a {
}

/* 良い例 */
.nav-link {
}

/* 効率的なセレクタの使用 */
/* 悪い例 */
body div.container > p {
}

/* 良い例 */
.content-text {
}

/* 再描画の最小化 */
/* position の変更の代わりに transform を使用 */
.element {
  transform: translateX(100px);
  /* left: 100px; の代わりに */
}

/* ベンダープレフィックスのグループ化 */
.element {
  -webkit-border-radius: 5px;
  -moz-border-radius: 5px;
  border-radius: 5px;
}
```

## CSS デバッグ

### ブラウザ開発者ツール

リアルタイムで CSS を検査および変更します。

```css
/* 一般的なデバッグ手順 */
/* 1. 右クリック → 要素を検証 */
/* 2. 計算済みスタイルを確認 */
/* 3. 上書きされているプロパティを確認 */
/* 4. リアルタイムで変更をテスト */
/* 5. 変更した CSS をファイルにコピーバック */
```

### 一般的な CSS の問題

頻繁に発生する問題のトラブルシューティング。

```css
/* ボックスモデルの問題 */
* {
  box-sizing: border-box;
}

/* float のクリア */
.clearfix::after {
  content: '';
  display: table;
  clear: both;
}

/* Z-index の問題 */
/* z-index を機能させるには、要素が配置されていること */
.element {
  position: relative;
  z-index: 1;
}
```

### CSS 検証

標準とベストプラクティスに従っていることを確認します。

```css
/* CSS バリデーターの使用 */
/* W3C CSS Validator */
/* ブラウザ互換性ツール */

/* コードにコメントする */
/* ===== ヘッダースタイル ===== */
.header {
}

/* TODO: モバイルスタイルを追加 */
/* FIXME: IE 互換性を修正 */

/* 一貫したフォーマットを使用 */
.element {
  property: value;
  property: value;
}
```

## CSS フレームワークとツール

### CSS プリプロセッサ

変数、ネスト、関数などで CSS を拡張します。

```scss
/* SCSS/Sassの例 */
$primary-color: #3498db;
$border-radius: 8px;

.button {
  background-color: $primary-color;
  border-radius: $border-radius;

  &:hover {
    background-color: darken($primary-color, 10%);
  }
}
```

```less
/* Less の例 */
@primary-color: #3498db;

.button {
  background-color: @primary-color;

  &:hover {
    background-color: lighten(@primary-color, 10%);
  }
}
```

### CSS-in-JS と最新ツール

Web アプリケーションにおけるスタイリングの最新のアプローチ。

```css
/* PostCSS プラグイン */
/* Autoprefixer - ベンダープレフィックスを追加 */
/* PurgeCSS - 未使用の CSS を削除 */

/* CSS Modules */
.button {
  composes: base-button;
  background-color: blue;
}
```

```javascript
/* ユーティリティファースト CSS (Tailwind) */
;<div class="flex items-center justify-center p-4 bg-blue-500">
  <span class="text-white font-bold">Button</span>
</div>

/* CSS-in-JS (Styled Components) */
const Button = styled.button`
  background: ${(props) => (props.primary ? 'blue' : 'white')};
  padding: 1rem 2rem;
`
```

## 関連リンク

- <router-link to="/html">HTML チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/react">React チートシート</router-link>
- <router-link to="/web-development">Web 開発 チートシート</router-link>

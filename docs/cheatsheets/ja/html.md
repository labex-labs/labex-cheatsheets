---
title: 'HTML チートシート | LabEx'
description: 'この包括的なチートシートで HTML5 を学習しましょう。フロントエンド開発者向けに、HTML タグ、セマンティック要素、フォーム、アクセシビリティ、最新の Web 開発標準のクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/html-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
HTML チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/html">ハンズオンラボで HTML を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて HTML のウェブ構造を学びます。LabEx は、必須要素、セマンティックマークアップ、フォーム、メディア統合、最新の HTML5 機能までを網羅した包括的な HTML コースを提供します。最新の Web 開発ワークフローのために、効率的なウェブページ構造とコンテンツ編成を習得しましょう。
</base-disclaimer-content>
</base-disclaimer>

## HTML ドキュメント構造

### 基本的な HTML ドキュメント：`<!DOCTYPE html>`

すべての HTML ドキュメントは、ドキュメントタイプ宣言から始まり、標準的な構造に従います。

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Page Title</title>
  </head>
  <body>
    <!-- ページコンテンツはここに入ります -->
  </body>
</html>
```

<BaseQuiz id="html-doctype-1" correct="A">
  <template #question>
    <code><!DOCTYPE html></code>の目的は何ですか？
  </template>
  
  <BaseQuizOption value="A" correct>ドキュメントタイプと HTML バージョンを宣言する</BaseQuizOption>
  <BaseQuizOption value="B">新しい HTML 要素を作成する</BaseQuizOption>
  <BaseQuizOption value="C">外部スタイルシートにリンクする</BaseQuizOption>
  <BaseQuizOption value="D">ページのタイトルを設定する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code><!DOCTYPE html></code>宣言は、ブラウザにドキュメントが使用している HTML のバージョンを伝えます。HTML5 の場合、この単純な宣言で十分であり、すべての HTML ドキュメントの最初の行である必要があります。
  </BaseQuizAnswer>
</BaseQuiz>

### Head 要素：`<head>`

head セクションには、ドキュメントに関するメタデータが含まれます。

```html
<!-- 文字エンコーディング -->
<meta charset="UTF-8" />
<!-- レスポンシブデザインのためのビューポート -->
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<!-- ページの説明 -->
<meta name="description" content="Page description" />
<!-- CSS へのリンク -->
<link rel="stylesheet" href="styles.css" />
<!-- ファビコンへのリンク -->
<link rel="icon" href="favicon.ico" />
```

### HTML コメント：`<!-- -->`

コメントは表示されませんが、コードの文書化に役立ちます。

```html
<!-- これはコメントです -->
<!-- 
  より長い説明のための
  複数行コメント
-->
```

### HTML 要素の構造

HTML 要素は、開始タグ、コンテンツ、終了タグで構成されます。

```html
<!-- コンテンツを持つ要素 -->
<p>これは段落です</p>
<!-- 自己終了要素 -->
<img src="image.jpg" alt="Description" />
<br />
<hr />
<!-- 属性を持つ要素 -->
<a href="https://example.com" target="_blank">リンク</a>
<!-- ネストされた要素 -->
<div>
  <p>ネストされた段落</p>
</div>
```

## テキストコンテンツ要素

### 見出し：`h1`から`h6`

コンテンツセクションの階層と重要度を定義します。

```html
<h1>メインタイトル</h1>
<h2>セクションタイトル</h2>
<h3>サブセクションタイトル</h3>
<h4>サブサブセクションタイトル</h4>
<h5>マイナー見出し</h5>
<h6>最小の見出し</h6>
```

<BaseQuiz id="html-headings-1" correct="B">
  <template #question>
    正しい見出しの階層構造は何ですか？
  </template>
  
  <BaseQuizOption value="A">h1 はページ上で複数回使用されるべきである</BaseQuizOption>
  <BaseQuizOption value="B" correct>h1 はメインタイトルとして一度だけ使用され、その後 h2、h3 と続くべきである</BaseQuizOption>
  <BaseQuizOption value="C">すべて見出しは同じ重要度を持つ</BaseQuizOption>
  <BaseQuizOption value="D">h6 が最も重要な見出しである</BaseQuizOption>
  
  <BaseQuizAnswer>
    HTML の見出しは論理的な階層に従うべきです。メインページタイトルには <code>h1</code>を一度使用し、主要セクションには<code>h2</code>、サブセクションには<code>h3</code> を使用するなど、順序立てて使用します。これはアクセシビリティと SEO に役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

### 段落：`p`

テキストコンテンツブロックの最も一般的な要素です。

```html
<p>
  これはテキストの段落です。複数の文を含めることができ、自動的に折り返されます。
</p>
<p>これは別の段落です。段落間にはマージン（余白）が設定されます。</p>
```

### テキストの書式設定：`<strong>`, `<em>`, `<b>`, `<i>`

インラインテキストの強調表示とスタイリングのための要素。

```html
<strong>強い重要性（太字）</strong>
<em>強調（斜体）</em>
<b>太字テキスト</b>
<i>斜体テキスト</i>
<u>下線付きテキスト</u>
<mark>ハイライトされたテキスト</mark>
<small>小さなテキスト</small>
<del>削除されたテキスト</del>
<ins>挿入されたテキスト</ins>
```

### 改行とスペース：`<br>`, `<hr>`, `<pre>`

コンテンツ内のテキストの流れと間隔を制御します。

```html
<!-- 改行 -->
Line 1<br />
Line 2
<!-- 水平線 -->
<hr />
<!-- 事前整形されたテキスト -->
<pre>
  スペースが
    保持される    間隔
      と改行
</pre>
<!-- コードの書式設定 -->
<code>console.log('Hello');</code>
```

## リストとナビゲーション

### 順序なしリスト：`<ul>`

順序のない項目（箇条書き）のリストを作成します。

```html
<ul>
  <li>最初の項目</li>
  <li>2 番目の項目</li>
  <li>3 番目の項目</li>
</ul>
<!-- ネストされたリスト -->
<ul>
  <li>
    メイン項目
    <ul>
      <li>サブ項目 1</li>
      <li>サブ項目 2</li>
    </ul>
  </li>
</ul>
```

### 順序付きリスト：`<ol>`

順序のある項目（番号付き）のリストを作成します。

```html
<ol>
  <li>最初のステップ</li>
  <li>2 番目のステップ</li>
  <li>3 番目のステップ</li>
</ol>
<!-- カスタム番号付け -->
<ol start="5">
  <li>項目 5</li>
  <li>項目 6</li>
</ol>
<!-- 異なる番号付けタイプ -->
<ol type="A">
  <li>項目 A</li>
  <li>項目 B</li>
</ol>
```

### 説明リスト：`<dl>`

用語とその説明のリストを作成します。

```html
<dl>
  <dt>HTML</dt>
  <dd>HyperText Markup Language</dd>

  <dt>CSS</dt>
  <dd>Cascading Style Sheets</dd>

  <dt>JavaScript</dt>
  <dd>プログラミング言語（ウェブ用）</dd>
</dl>
```

### リンクとナビゲーション：`<a>`

ハイパーリンクとナビゲーション構造を作成します。

```html
<!-- 基本的なリンク -->
<a href="https://example.com">Example を訪問</a>
<!-- 新しいタブで開くリンク -->
<a href="https://example.com" target="_blank">新しいタブ</a>
<!-- E メールリンク -->
<a href="mailto:email@example.com">E メールを送信</a>
<!-- 電話リンク -->
<a href="tel:+1234567890">電話する</a>
<!-- ページ内アンカーリンク -->
<a href="#section1">セクション 1 へ移動</a>
<h2 id="section1">セクション 1</h2>
```

<BaseQuiz id="html-links-1" correct="B">
  <template #question>
    アンカータグの <code>target="_blank"</code> は何をしますか？
  </template>
  
  <BaseQuizOption value="A">同じウィンドウでリンクを開く</BaseQuizOption>
  <BaseQuizOption value="B" correct>新しいタブまたはウィンドウでリンクを開く</BaseQuizOption>
  <BaseQuizOption value="C">現在のウィンドウを閉じる</BaseQuizOption>
  <BaseQuizOption value="D">リンクをダウンロードする</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>target="_blank"</code> 属性は、リンクされたページを新しいブラウザタブまたはウィンドウで開きます。これにより、ユーザーは元のページを開いたままにできます。
  </BaseQuizAnswer>
</BaseQuiz>

## フォームと入力要素

### 基本的なフォーム構造：`<form>`

ユーザー入力収集の基盤です。

```html
<form action="/submit" method="POST">
  <label for="username">ユーザー名：</label>
  <input type="text" id="username" name="username" required />

  <label for="email">E メール：</label>
  <input type="email" id="email" name="email" required />

  <input type="submit" value="送信" />
</form>
```

### 入力タイプ：`<input>`

さまざまなデータ収集ニーズに対応する多様な入力タイプ。

```html
<!-- テキスト入力 -->
<input type="text" placeholder="テキストを入力" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="パスワード" />
<input type="url" placeholder="https://example.com" />
<input type="tel" placeholder="+1234567890" />
<!-- 数値入力 -->
<input type="number" min="1" max="100" step="1" />
<input type="range" min="0" max="100" value="50" />
<!-- 日付と時刻 -->
<input type="date" />
<input type="time" />
<input type="datetime-local" />
```

### フォームコントロール：`<checkbox>`, `<radio>`, `<select>`, `<textarea>`

ユーザーインタラクションのための追加のフォーム要素。

```html
<!-- チェックボックス -->
<input type="checkbox" id="agree" name="agree" />
<label for="agree">規約に同意する</label>
<!-- ラジオボタン -->
<input type="radio" id="option1" name="choice" value="1" />
<label for="option1">オプション 1</label>
<input type="radio" id="option2" name="choice" value="2" />
<label for="option2">オプション 2</label>
<!-- 選択ドロップダウン -->
<select name="country">
  <option value="us">United States</option>
  <option value="uk">United Kingdom</option>
  <option value="ca">Canada</option>
</select>
<!-- テキストエリア -->
<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="メッセージを入力"
></textarea>
```

### フォームの検証：`required`, `min`, `max`, `pattern`

組み込みの HTML フォーム検証属性。

```html
<input type="text" required />
<input type="email" required />
<input type="text" minlength="3" maxlength="20" />
<input type="number" min="1" max="100" />
<input type="text" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}" />
```

<BaseQuiz id="html-validation-1" correct="A">
  <template #question>
    HTML 入力の <code>required</code> 属性は何をしますか？
  </template>
  
  <BaseQuizOption value="A" correct>フィールドが空の場合、フォームの送信を防ぐ</BaseQuizOption>
  <BaseQuizOption value="B">フィールドを読み取り専用にする</BaseQuizOption>
  <BaseQuizOption value="C">フィールドを非表示にする</BaseQuizOption>
  <BaseQuizOption value="D">デフォルト値を設定する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>required</code> 属性は入力フィールドを必須にします。フォーム送信時にフィールドが空の場合、ブラウザは送信を防止し、検証メッセージを表示します。
  </BaseQuizAnswer>
</BaseQuiz>

## メディア要素

### 画像：`<img>`, `<picture>`

さまざまな属性とオプションで画像を表示します。

```html
<!-- 基本的な画像 -->
<img src="image.jpg" alt="説明" />
<!-- レスポンシブ画像 -->
<img src="image.jpg" alt="説明" width="100%" height="auto" />
<!-- サイズ指定のある画像 -->
<img src="image.jpg" alt="説明" width="300" height="200" />
<!-- レスポンシブ画像のための picture 要素 -->
<picture>
  <source media="(min-width: 800px)" srcset="large.jpg" />
  <source media="(min-width: 400px)" srcset="medium.jpg" />
  <img src="small.jpg" alt="説明" />
</picture>
```

### オーディオ：`<audio>`

再生コントロール付きでオーディオコンテンツを埋め込みます。

```html
<!-- 基本的なオーディオ -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
  <source src="audio.ogg" type="audio/ogg" />
  お使いのブラウザはオーディオをサポートしていません。
</audio>
<!-- autoplay 付きオーディオ -->
<audio controls autoplay loop>
  <source src="background.mp3" type="audio/mpeg" />
</audio>
```

### ビデオ：`<video>`

包括的なオプションでビデオコンテンツを埋め込みます。

```html
<!-- 基本的なビデオ -->
<video controls width="400" height="300">
  <source src="video.mp4" type="video/mp4" />
  <source src="video.webm" type="video/webm" />
  お使いのブラウザはビデオをサポートしていません。
</video>
<!-- ポスターと属性付きビデオ -->
<video controls poster="thumbnail.jpg" width="100%" height="auto">
  <source src="video.mp4" type="video/mp4" />
  <track src="captions.vtt" kind="captions" srclang="en" label="English" />
</video>
```

### 埋め込みコンテンツ：`<iframe>`

外部コンテンツやアプリケーションを埋め込みます。

```html
<!-- 外部コンテンツのための iFrame -->
<iframe src="https://example.com" width="100%" height="400"></iframe>
<!-- YouTube ビデオの埋め込み -->
<iframe
  width="560"
  height="315"
  src="https://www.youtube.com/embed/VIDEO_ID"
></iframe>
<!-- Google マップの埋め込み -->
<iframe src="https://maps.google.com/..."></iframe>
```

## テーブル

### 基本的なテーブル構造：`<table>`

テーブルを使用して構造化されたデータ表示を作成します。

```html
<table>
  <thead>
    <tr>
      <th>名前</th>
      <th>年齢</th>
      <th>都市</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>John</td>
      <td>25</td>
      <td>New York</td>
    </tr>
    <tr>
      <td>Jane</td>
      <td>30</td>
      <td>London</td>
    </tr>
  </tbody>
</table>
```

### 高度なテーブル機能：`rowspan`, `colspan`, `<caption>`

セル結合とグループ化によるテーブル機能の強化。

```html
<table>
  <caption>
    売上レポート
  </caption>
  <colgroup>
    <col style="width: 50%" />
    <col style="width: 25%" />
    <col style="width: 25%" />
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">製品</th>
      <th colspan="2">売上</th>
    </tr>
    <tr>
      <th>第 1 四半期</th>
      <th>第 2 四半期</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>製品 A</td>
      <td>$1000</td>
      <td>$1200</td>
    </tr>
  </tbody>
</table>
```

## セマンティック HTML5 要素

### ページ構造要素：`<header>`, `<nav>`, `<main>`, `<footer>`

ページの主要なレイアウトセクションを定義します。

```html
<!-- ページヘッダー -->
<header>
  <nav>
    <ul>
      <li><a href="#home">ホーム</a></li>
      <li><a href="#about">アバウト</a></li>
    </ul>
  </nav>
</header>
<!-- メインコンテンツ -->
<main>
  <article>
    <h1>記事のタイトル</h1>
    <p>記事のコンテンツ...</p>
  </article>
</main>
<!-- サイドバー -->
<aside>
  <h2>関連リンク</h2>
  <ul>
    <li><a href="#">リンク 1</a></li>
  </ul>
</aside>
<!-- ページフッター -->
<footer>
  <p>© 2024 会社名</p>
</footer>
```

### コンテンツグループ化要素：`<section>`, `<article>`, `<div>`, `<figure>`

関連するコンテンツセクションを整理およびグループ化します。

```html
<!-- 一般的なセクション -->
<section>
  <h2>セクションタイトル</h2>
  <p>セクションコンテンツ...</p>
</section>
<!-- 独立した記事 -->
<article>
  <header>
    <h1>記事のタイトル</h1>
    <time datetime="2024-01-01">2024 年 1 月 1 日</time>
  </header>
  <p>記事のコンテンツ...</p>
</article>
<!-- 一般的なコンテナ -->
<div class="container">
  <p>一般的なコンテンツのグループ化</p>
</div>
<!-- キャプション付きの図 -->
<figure>
  <img src="chart.jpg" alt="売上チャート" />
  <figcaption>2024 年第 1 四半期の売上データ</figcaption>
</figure>
```

## HTML 属性

### グローバル属性：`id`, `class`, `title`, `data-*`

任意の HTML 要素に使用できる属性。

```html
<!-- 一意の識別子としての ID -->
<div id="unique-element">コンテンツ</div>
<!-- スタイリングと選択のためのクラス -->
<p class="highlight important">テキスト</p>
<!-- ツールチップのためのタイトル -->
<span title="これはツールチップです">ホバーしてください</span>
<!-- データ属性 -->
<div data-user-id="123" data-role="admin">ユーザー</div>
<!-- 言語 -->
<p lang="es">Hola mundo</p>
<!-- コンテンツの方向 -->
<p dir="rtl">右から左へのテキスト</p>
<!-- 非表示の要素 -->
<div hidden>これは表示されません</div>
```

### アクセシビリティ属性：`alt`, `aria-*`, `tabindex`, `role`

アクセシビリティとユーザーエクスペリエンスを向上させる属性。

```html
<!-- 画像の代替テキスト -->
<img src="photo.jpg" alt="山の上にある夕日" />
<!-- ARIA ラベル -->
<button aria-label="ダイアログを閉じる">×</button>
<div aria-hidden="true">装飾的なコンテンツ</div>
<!-- フォームのアクセシビリティ -->
<label for="email">E メールアドレス：</label>
<input type="email" id="email" aria-describedby="email-help" />
<small id="email-help">E メールを共有することはありません</small>
<!-- タブインデックス -->
<div tabindex="0">フォーカス可能な div</div>
<div tabindex="-1">プログラムでフォーカス可能な div</div>
<!-- ロール属性 -->
<div role="button" tabindex="0">カスタムボタン</div>
```

## HTML5 の最新機能

### 新しい入力機能：`color`, `search`, `file`, `datalist`

HTML5 で導入された新しい入力タイプと属性。

```html
<!-- 新しい入力タイプ -->
<input type="color" value="#ff0000" />
<input type="search" placeholder="検索..." />
<input type="file" accept="image/*" multiple />
<!-- オートコンプリートのための datalist -->
<input list="browsers" name="browser" />
<datalist id="browsers">
  <option value="Chrome"></option>
  <option value="Firefox"></option>
  <option value="Safari"></option>
</datalist>
<!-- Progress と meter -->
<progress value="70" max="100">70%</progress>
<meter value="0.6">60%</meter>
```

### Canvas と SVG: `<canvas>`, `<svg>`

HTML5 におけるグラフィックスと描画機能。

```html
<!-- 動的グラフィックスのための Canvas -->
<canvas id="myCanvas" width="400" height="200">
  お使いのブラウザは canvas をサポートしていません。
</canvas>
<!-- インライン SVG -->
<svg width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue" stroke="black" stroke-width="2" />
</svg>
```

### 詳細と要約：`<details>`, `<summary>`

JavaScript なしで折りたたみ可能なコンテンツセクションを作成します。

```html
<details>
  <summary>展開するにはクリック</summary>
  <p>
    このコンテンツはデフォルトで非表示になっており、summary
    をクリックすると表示されます。
  </p>
  <ul>
    <li>項目 1</li>
    <li>項目 2</li>
  </ul>
</details>
<details open>
  <summary>これはデフォルトで展開されます</summary>
  <p>コンテンツはデフォルトで表示されます。</p>
</details>
```

### ダイアログ要素：`<dialog>`

ネイティブのダイアログおよびモーダル機能。

```html
<!-- ダイアログ要素 -->
<dialog id="myDialog">
  <h2>ダイアログタイトル</h2>
  <p>ダイアログコンテンツはここに配置されます。</p>
  <button onclick="closeDialog()">閉じる</button>
</dialog>
<button onclick="openDialog()">ダイアログを開く</button>
<script>
  function openDialog() {
    document.getElementById('myDialog').showModal()
  }
</script>
```

## ベストプラクティスと検証

### HTML のベストプラクティス

クリーンで保守しやすく、アクセシブルな HTML を作成します。

```html
<!-- 常に doctype を宣言する -->
<!DOCTYPE html>
<!-- セマンティック要素を使用する -->
<header>...</header>
<main>...</main>
<footer>...</footer>
<!-- 適切なネスト -->
<div>
  <p>適切にネストされたコンテンツ</p>
</div>
<!-- 要素と属性には小文字を使用する -->
<img src="image.jpg" alt="description" />
<!-- すべてのタグを閉じる -->
<p>常にタグを閉じる</p>
<!-- 意味のある alt テキストを使用する -->
<img src="chart.png" alt="第4四半期に売上が25%増加" />
```

### HTML の検証とデバッグ

HTML が有効であり、アクセシブルであることを確認します。

```html
<!-- W3C HTML バリデーターを使用 -->
<!-- https://validator.w3.org/ -->
<!-- 一般的な検証エラー -->
<!-- alt 属性の欠落 -->
<img src="image.jpg" alt="" />
<!-- alt テキストを提供する -->
<!-- タグが閉じられていない -->
<p>テキストコンテンツ</p>
<!-- 常にタグを閉じる -->
<!-- 無効なネスト -->
<p>
  有効な段落コンテンツ
  <!-- 段落内にブロック要素を入れない -->
</p>
<!-- 開発者ツールを使用 -->
<!-- 右クリック → 要素を検証 -->
<!-- コンソールでエラーを確認 -->
<!-- WAVE または axe でアクセシビリティを検証 -->
```

## HTML テンプレートとフレームワーク

### テンプレートエンジン：Handlebars, Mustache

テンプレート言語を使用した動的な HTML 生成。

```html
<!-- Handlebars テンプレート -->
<div>
  <h1>{{title}}</h1>
  {{#each items}}
  <p>{{this}}</p>
  {{/each}}
</div>
<!-- Mustache テンプレート -->
<div>
  <h1>{{title}}</h1>
  {{#items}}
  <p>{{.}}</p>
  {{/items}}
</div>
```

### Web Components: `<template>`, カスタム要素

再利用可能なカスタム HTML 要素。

```html
<!-- カスタム要素の定義 -->
<template id="my-component">
  <style>
    p {
      color: blue;
    }
  </style>
  <p><slot></slot></p>
</template>
<!-- 使用法 -->
<my-component>Hello World</my-component>
<script>
  class MyComponent extends HTMLElement {
    // コンポーネントのロジック
  }
  customElements.define('my-component', MyComponent)
</script>
```

### フレームワークの統合：React JSX, Vue テンプレート

モダンな JavaScript フレームワーク内の HTML。

```html
<!-- React JSX -->
function Component() { return (
<div className="container">
  <h1>{title}</h1>
  <p>ここにコンテンツ</p>
</div>
); }
<!-- Vue テンプレート -->
<template>
  <div class="container">
    <h1>{{ title }}</h1>
    <p v-if="showContent">ここにコンテンツ</p>
  </div>
</template>
```

## 関連リンク

- <router-link to="/css">CSS チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/web-development">Web 開発チートシート</router-link>
- <router-link to="/react">React チートシート</router-link>
- <router-link to="/git">Git チートシート</router-link>
- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>

---
title: 'Folha de Referência HTML | LabEx'
description: 'Aprenda HTML5 com esta folha de referência abrangente. Referência rápida para tags HTML, elementos semânticos, formulários, acessibilidade e padrões modernos de desenvolvimento web para desenvolvedores frontend.'
pdfUrl: '/cheatsheets/pdf/html-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas de HTML
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/html">Aprenda HTML com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda a estrutura da web em HTML através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de HTML que cobrem elementos essenciais, marcação semântica, formulários, integração de mídia e recursos modernos do HTML5. Domine a estrutura eficiente de páginas web e a organização de conteúdo para fluxos de trabalho de desenvolvimento web modernos.
</base-disclaimer-content>
</base-disclaimer>

## Estrutura do Documento HTML

### Documento HTML Básico: `<!DOCTYPE html>`

Todo documento HTML começa com uma declaração de tipo de documento e segue uma estrutura padrão.

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Page Title</title>
  </head>
  <body>
    <!-- O conteúdo da página vai aqui -->
  </body>
</html>
```

<BaseQuiz id="html-doctype-1" correct="A">
  <template #question>
    Qual é o propósito de `<!DOCTYPE html>`?
  </template>
  
  <BaseQuizOption value="A" correct>Ele declara o tipo de documento e a versão HTML</BaseQuizOption>
  <BaseQuizOption value="B">Ele cria um novo elemento HTML</BaseQuizOption>
  <BaseQuizOption value="C">Ele vincula a uma folha de estilo externa</BaseQuizOption>
  <BaseQuizOption value="D">Ele define o título da página</BaseQuizOption>
  
  <BaseQuizAnswer>
    A declaração `<!DOCTYPE html>` informa ao navegador qual versão do HTML o documento está usando. Para HTML5, esta declaração simples é suficiente e deve ser a primeira linha de todo documento HTML.
  </BaseQuizAnswer>
</BaseQuiz>

### Elementos Head: `<head>`

A seção head contém metadados sobre o documento.

```html
<!-- Codificação de caracteres -->
<meta charset="UTF-8" />
<!-- Viewport para design responsivo -->
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<!-- Descrição da página -->
<meta name="description" content="Page description" />
<!-- Link para CSS -->
<link rel="stylesheet" href="styles.css" />
<!-- Link para favicon -->
<link rel="icon" href="favicon.ico" />
```

### Comentários HTML: `<!-- -->`

Comentários não são exibidos, mas ajudam a documentar seu código.

```html
<!-- Este é um comentário -->
<!-- 
  Comentário de múltiplas linhas
  para explicações mais longas
-->
```

### Anatomia de Elementos HTML

Elementos HTML consistem em tags de abertura, conteúdo e tags de fechamento.

```html
<!-- Elemento com conteúdo -->
<p>This is a paragraph</p>
<!-- Elementos de auto-fechamento -->
<img src="image.jpg" alt="Description" />
<br />
<hr />
<!-- Elementos com atributos -->
<a href="https://example.com" target="_blank">Link</a>
<!-- Elementos aninhados -->
<div>
  <p>Nested paragraph</p>
</div>
```

## Elementos de Conteúdo de Texto

### Títulos: `h1` a `h6`

Definem a hierarquia e a importância das seções de conteúdo.

```html
<h1>Main Title</h1>
<h2>Section Title</h2>
<h3>Subsection Title</h3>
<h4>Sub-subsection Title</h4>
<h5>Minor Heading</h5>
<h6>Smallest Heading</h6>
```

<BaseQuiz id="html-headings-1" correct="B">
  <template #question>
    Qual é a hierarquia correta de títulos?
  </template>
  
  <BaseQuizOption value="A">h1 deve ser usado várias vezes em uma página</BaseQuizOption>
  <BaseQuizOption value="B" correct>h1 deve ser usado uma vez como título principal, seguido por h2, h3, etc.</BaseQuizOption>
  <BaseQuizOption value="C">Todos os títulos têm a mesma importância</BaseQuizOption>
  <BaseQuizOption value="D">h6 é o título mais importante</BaseQuizOption>
  
  <BaseQuizAnswer>
    Os títulos HTML devem seguir uma hierarquia lógica: use um `h1` para o título principal da página, depois `h2` para seções principais, `h3` para subseções e assim por diante. Isso ajuda na acessibilidade e SEO.
  </BaseQuizAnswer>
</BaseQuiz>

### Parágrafos: `p`

O elemento mais comum para blocos de conteúdo de texto.

```html
<p>
  This is a paragraph of text. It can contain multiple sentences and will wrap
  automatically.
</p>
<p>This is another paragraph. Paragraphs are separated by margin space.</p>
```

### Formatação de Texto: `<strong>`, `<em>`, `<b>`, `<i>`

Elementos para enfatizar e estilizar texto em linha.

```html
<strong>Strong importance (bold)</strong>
<em>Emphasis (italic)</em>
<b>Bold text</b>
<i>Italic text</i>
<u>Underlined text</u>
<mark>Highlighted text</mark>
<small>Small text</small>
<del>Deleted text</del>
<ins>Inserted text</ins>
```

### Quebras de Linha e Espaçamento: `<br>`, `<hr>`, `<pre>`

Controlam o fluxo de texto e o espaçamento dentro do conteúdo.

```html
<!-- Quebra de linha -->
Line 1<br />
Line 2
<!-- Regra horizontal -->
<hr />
<!-- Texto pré-formatado -->
<pre>
  Text with
    preserved    spacing
      and line breaks
</pre>
<!-- Formatação de código -->
<code>console.log('Hello');</code>
```

## Listas e Navegação

### Listas Não Ordenadas: `<ul>`

Cria listas com marcadores para itens não sequenciais.

```html
<ul>
  <li>First item</li>
  <li>Second item</li>
  <li>Third item</li>
</ul>
<!-- Listas aninhadas -->
<ul>
  <li>
    Main item
    <ul>
      <li>Sub item 1</li>
      <li>Sub item 2</li>
    </ul>
  </li>
</ul>
```

### Listas Ordenadas: `<ol>`

Cria listas numeradas para itens sequenciais.

```html
<ol>
  <li>First step</li>
  <li>Second step</li>
  <li>Third step</li>
</ol>
<!-- Numeração personalizada -->
<ol start="5">
  <li>Item 5</li>
  <li>Item 6</li>
</ol>
<!-- Tipos de numeração diferentes -->
<ol type="A">
  <li>Item A</li>
  <li>Item B</li>
</ol>
```

### Listas de Descrição: `<dl>`

Cria listas de termos e suas descrições.

```html
<dl>
  <dt>HTML</dt>
  <dd>HyperText Markup Language</dd>

  <dt>CSS</dt>
  <dd>Cascading Style Sheets</dd>

  <dt>JavaScript</dt>
  <dd>Programming language for web</dd>
</dl>
```

### Links e Navegação: `<a>`

Cria hiperlinks e estruturas de navegação.

```html
<!-- Link básico -->
<a href="https://example.com">Visit Example</a>
<!-- Link em nova aba -->
<a href="https://example.com" target="_blank">New Tab</a>
<!-- Link de e-mail -->
<a href="mailto:email@example.com">Send Email</a>
<!-- Link de telefone -->
<a href="tel:+1234567890">Call Us</a>
<!-- Âncoras de página internas -->
<a href="#section1">Go to Section 1</a>
<h2 id="section1">Section 1</h2>
```

<BaseQuiz id="html-links-1" correct="B">
  <template #question>
    O que `target="_blank"` faz em uma tag de âncora?
  </template>
  
  <BaseQuizOption value="A">Abre o link na mesma janela</BaseQuizOption>
  <BaseQuizOption value="B" correct>Abre o link em uma nova aba ou janela</BaseQuizOption>
  <BaseQuizOption value="C">Fecha a janela atual</BaseQuizOption>
  <BaseQuizOption value="D">Baixa o link</BaseQuizOption>
  
  <BaseQuizAnswer>
    O atributo `target="_blank"` abre a página vinculada em uma nova aba ou janela do navegador, permitindo que os usuários mantenham a página original aberta.
  </BaseQuizAnswer>
</BaseQuiz>

## Formulários e Elementos de Entrada

### Estrutura Básica do Formulário: `<form>`

A base para a coleta de entrada do usuário.

```html
<form action="/submit" method="POST">
  <label for="username">Username:</label>
  <input type="text" id="username" name="username" required />

  <label for="email">Email:</label>
  <input type="email" id="email" name="email" required />

  <input type="submit" value="Submit" />
</form>
```

### Tipos de Entrada: `<input>`

Vários tipos de entrada para diferentes necessidades de coleta de dados.

```html
<!-- Entradas de texto -->
<input type="text" placeholder="Enter text" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="Password" />
<input type="url" placeholder="https://example.com" />
<input type="tel" placeholder="+1234567890" />
<!-- Entradas numéricas -->
<input type="number" min="1" max="100" step="1" />
<input type="range" min="0" max="100" value="50" />
<!-- Data e hora -->
<input type="date" />
<input type="time" />
<input type="datetime-local" />
```

### Controles de Formulário: `<checkbox>`, `<radio>`, `<select>`, `<textarea>`

Elementos de formulário adicionais para interação do usuário.

```html
<!-- Checkboxes -->
<input type="checkbox" id="agree" name="agree" />
<label for="agree">I agree to terms</label>
<!-- Botões de rádio -->
<input type="radio" id="option1" name="choice" value="1" />
<label for="option1">Option 1</label>
<input type="radio" id="option2" name="choice" value="2" />
<label for="option2">Option 2</label>
<!-- Dropdown select -->
<select name="country">
  <option value="us">United States</option>
  <option value="uk">United Kingdom</option>
  <option value="ca">Canada</option>
</select>
<!-- Textarea -->
<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="Enter your message"
></textarea>
```

### Validação de Formulário: `required`, `min`, `max`, `pattern`

Atributos de validação de formulário HTML integrados.

```html
<input type="text" required />
<input type="email" required />
<input type="text" minlength="3" maxlength="20" />
<input type="number" min="1" max="100" />
<input type="text" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}" />
```

<BaseQuiz id="html-validation-1" correct="A">
  <template #question>
    O que o atributo `required` faz em uma entrada HTML?
  </template>
  
  <BaseQuizOption value="A" correct>Impede o envio do formulário se o campo estiver vazio</BaseQuizOption>
  <BaseQuizOption value="B">Torna o campo somente leitura</BaseQuizOption>
  <BaseQuizOption value="C">Oculta o campo</BaseQuizOption>
  <BaseQuizOption value="D">Define um valor padrão</BaseQuizOption>
  
  <BaseQuizAnswer>
    O atributo `required` torna um campo de entrada obrigatório. Se o campo estiver vazio ao enviar o formulário, o navegador impedirá o envio e exibirá uma mensagem de validação.
  </BaseQuizAnswer>
</BaseQuiz>

## Elementos de Mídia

### Imagens: `<img>`, `<picture>`

Exibe imagens com vários atributos e opções.

```html
<!-- Imagem básica -->
<img src="image.jpg" alt="Description" />
<!-- Imagem responsiva -->
<img src="image.jpg" alt="Description" width="100%" height="auto" />
<!-- Imagem com tamanho -->
<img src="image.jpg" alt="Description" width="300" height="200" />
<!-- Elemento picture para imagens responsivas -->
<picture>
  <source media="(min-width: 800px)" srcset="large.jpg" />
  <source media="(min-width: 400px)" srcset="medium.jpg" />
  <img src="small.jpg" alt="Description" />
</picture>
```

### Áudio: `<audio>`

Incorpora conteúdo de áudio com controles de reprodução.

```html
<!-- Áudio básico -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
  <source src="audio.ogg" type="audio/ogg" />
  Seu navegador não suporta áudio.
</audio>
<!-- Áudio com autoplay -->
<audio controls autoplay loop>
  <source src="background.mp3" type="audio/mpeg" />
</audio>
```

### Vídeo: `<video>`

Incorpora conteúdo de vídeo com opções abrangentes.

```html
<!-- Vídeo básico -->
<video controls width="400" height="300">
  <source src="video.mp4" type="video/mp4" />
  <source src="video.webm" type="video/webm" />
  Seu navegador não suporta vídeo.
</video>
<!-- Vídeo com pôster e atributos -->
<video controls poster="thumbnail.jpg" width="100%" height="auto">
  <source src="video.mp4" type="video/mp4" />
  <track src="captions.vtt" kind="captions" srclang="en" label="English" />
</video>
```

### Conteúdo Incorporado: `<iframe>`

Incorpora conteúdo e aplicativos externos.

```html
<!-- iFrame para conteúdo externo -->
<iframe src="https://example.com" width="100%" height="400"></iframe>
<!-- Incorporação de vídeo do YouTube -->
<iframe
  width="560"
  height="315"
  src="https://www.youtube.com/embed/VIDEO_ID"
></iframe>
<!-- Incorporação do Google Maps -->
<iframe src="https://maps.google.com/..."></iframe>
```

## Tabelas

### Estrutura Básica da Tabela: `<table>`

Cria exibições de dados estruturados com tabelas.

```html
<table>
  <thead>
    <tr>
      <th>Name</th>
      <th>Age</th>
      <th>City</th>
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

### Recursos Avançados de Tabela: `rowspan`, `colspan`, `<caption>`

Funcionalidade aprimorada da tabela com expansão e agrupamento.

```html
<table>
  <caption>
    Sales Report
  </caption>
  <colgroup>
    <col style="width: 50%" />
    <col style="width: 25%" />
    <col style="width: 25%" />
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">Product</th>
      <th colspan="2">Sales</th>
    </tr>
    <tr>
      <th>Q1</th>
      <th>Q2</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Product A</td>
      <td>$1000</td>
      <td>$1200</td>
    </tr>
  </tbody>
</table>
```

## Elementos Semânticos HTML5

### Elementos de Estrutura da Página: `<header>`, `<nav>`, `<main>`, `<footer>`

Definem as principais seções do layout da sua página.

```html
<!-- Cabeçalho da página -->
<header>
  <nav>
    <ul>
      <li><a href="#home">Home</a></li>
      <li><a href="#about">About</a></li>
    </ul>
  </nav>
</header>
<!-- Conteúdo principal -->
<main>
  <article>
    <h1>Article Title</h1>
    <p>Article content...</p>
  </article>
</main>
<!-- Barra lateral -->
<aside>
  <h2>Related Links</h2>
  <ul>
    <li><a href="#">Link 1</a></li>
  </ul>
</aside>
<!-- Rodapé da página -->
<footer>
  <p>© 2024 Company Name</p>
</footer>
```

### Elementos de Agrupamento de Conteúdo: `<section>`, `<article>`, `<div>`, `<figure>`

Organizam e agrupam seções de conteúdo relacionadas.

```html
<!-- Seção genérica -->
<section>
  <h2>Section Title</h2>
  <p>Section content...</p>
</section>
<!-- Artigo autônomo -->
<article>
  <header>
    <h1>Article Title</h1>
    <time datetime="2024-01-01">January 1, 2024</time>
  </header>
  <p>Article content...</p>
</article>
<!-- Contêiner genérico -->
<div class="container">
  <p>Generic content grouping</p>
</div>
<!-- Figura com legenda -->
<figure>
  <img src="chart.jpg" alt="Sales Chart" />
  <figcaption>Sales data for Q1 2024</figcaption>
</figure>
```

## Atributos HTML

### Atributos Globais: `id`, `class`, `title`, `data-*`

Atributos que podem ser usados em qualquer elemento HTML.

```html
<!-- ID para identificação única -->
<div id="unique-element">Content</div>
<!-- Class para estilização e seleção -->
<p class="highlight important">Text</p>
<!-- Title para tooltips -->
<span title="This is a tooltip">Hover me</span>
<!-- Atributos de dados -->
<div data-user-id="123" data-role="admin">User</div>
<!-- Idioma -->
<p lang="es">Hola mundo</p>
<!-- Direção do conteúdo -->
<p dir="rtl">Right to left text</p>
<!-- Elementos ocultos -->
<div hidden>This won't be displayed</div>
```

### Atributos de Acessibilidade: `alt`, `aria-*`, `tabindex`, `role`

Atributos que melhoram a acessibilidade e a experiência do usuário.

```html
<!-- Texto alternativo para imagens -->
<img src="photo.jpg" alt="A sunset over mountains" />
<!-- Rótulos ARIA -->
<button aria-label="Close dialog">×</button>
<div aria-hidden="true">Decorative content</div>
<!-- Acessibilidade do formulário -->
<label for="email">Email Address:</label>
<input type="email" id="email" aria-describedby="email-help" />
<small id="email-help">We'll never share your email</small>
<!-- Índice de tabulação -->
<div tabindex="0">Focusable div</div>
<div tabindex="-1">Programmatically focusable</div>
<!-- Atributo de função -->
<div role="button" tabindex="0">Custom button</div>
```

## Recursos Modernos do HTML5

### Novos Recursos de Entrada: `color`, `search`, `file`, `datalist`

O HTML5 introduziu novos tipos de entrada e atributos.

```html
<!-- Novos tipos de entrada -->
<input type="color" value="#ff0000" />
<input type="search" placeholder="Search..." />
<input type="file" accept="image/*" multiple />
<!-- Datalist para preenchimento automático -->
<input list="browsers" name="browser" />
<datalist id="browsers">
  <option value="Chrome"></option>
  <option value="Firefox"></option>
  <option value="Safari"></option>
</datalist>
<!-- Progresso e medidor -->
<progress value="70" max="100">70%</progress>
<meter value="0.6">60%</meter>
```

### Canvas e SVG: `<canvas>`, `<svg>`

Capacidades de gráficos e desenho no HTML5.

```html
<!-- Canvas para gráficos dinâmicos -->
<canvas id="myCanvas" width="400" height="200">
  Seu navegador não suporta canvas.
</canvas>
<!-- SVG em linha -->
<svg width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue" stroke="black" stroke-width="2" />
</svg>
```

### Detalhes e Resumo: `<details>`, `<summary>`

Cria seções de conteúdo recolhíveis sem JavaScript.

```html
<details>
  <summary>Click to expand</summary>
  <p>
    This content is hidden by default and revealed when clicking the summary.
  </p>
  <ul>
    <li>Item 1</li>
    <li>Item 2</li>
  </ul>
</details>
<details open>
  <summary>This starts expanded</summary>
  <p>Content visible by default.</p>
</details>
```

### Elemento Dialog: `<dialog>`

Funcionalidade nativa de diálogo e modal.

```html
<!-- Elemento dialog -->
<dialog id="myDialog">
  <h2>Dialog Title</h2>
  <p>Dialog content goes here.</p>
  <button onclick="closeDialog()">Close</button>
</dialog>
<button onclick="openDialog()">Open Dialog</button>
<script>
  function openDialog() {
    document.getElementById('myDialog').showModal()
  }
</script>
```

## Melhores Práticas e Validação

### Melhores Práticas de HTML

Escreva HTML limpo, de fácil manutenção e acessível.

```html
<!-- Sempre declare doctype -->
<!DOCTYPE html>
<!-- Use elementos semânticos -->
<header>...</header>
<main>...</main>
<footer>...</footer>
<!-- Aninhamento correto -->
<div>
  <p>Properly nested content</p>
</div>
<!-- Use letras minúsculas para elementos e atributos -->
<img src="image.jpg" alt="description" />
<!-- Feche todas as tags -->
<p>Always close your tags</p>
<!-- Use texto alt significativo -->
<img src="chart.png" alt="Sales increased 25% in Q4" />
```

### Validação e Depuração de HTML

Garanta que seu HTML seja válido e acessível.

```html
<!-- Use o Validador HTML W3C -->
<!-- https://validator.w3.org/ -->
<!-- Erros comuns de validação -->
<!-- Atributos alt ausentes -->
<img src="image.jpg" alt="" />
<!-- Forneça texto alt -->
<!-- Tags não fechadas -->
<p>Text content</p>
<!-- Sempre feche as tags -->
<!-- Aninhamento inválido -->
<p>
  Valid paragraph content
  <!-- Não coloque elementos de bloco dentro de parágrafos -->
</p>
<!-- Use ferramentas do desenvolvedor -->
<!-- Clique com o botão direito → Inspecionar Elemento -->
<!-- Verifique o console em busca de erros -->
<!-- Valide a acessibilidade com WAVE ou axe -->
```

## Modelos e Frameworks HTML

### Mecanismos de Modelo: Handlebars, Mustache

Geração de HTML dinâmico com linguagens de modelo.

```html
<!-- Modelo Handlebars -->
<div>
  <h1>{{title}}</h1>
  {{#each items}}
  <p>{{this}}</p>
  {{/each}}
</div>
<!-- Modelo Mustache -->
<div>
  <h1>{{title}}</h1>
  {{#items}}
  <p>{{.}}</p>
  {{/items}}
</div>
```

### Componentes Web: `<template>`, Elementos Personalizados

Elementos HTML personalizados reutilizáveis.

```html
<!-- Definição de elemento personalizado -->
<template id="my-component">
  <style>
    p {
      color: blue;
    }
  </style>
  <p><slot></slot></p>
</template>
<!-- Uso -->
<my-component>Hello World</my-component>
<script>
  class MyComponent extends HTMLElement {
    // Lógica do componente
  }
  customElements.define('my-component', MyComponent)
</script>
```

### Integração de Framework: React JSX, Modelos Vue

HTML dentro de frameworks JavaScript modernos.

```html
<!-- React JSX -->
function Component() { return (
<div className="container">
  <h1>{title}</h1>
  <p>Content here</p>
</div>
); }
<!-- Modelo Vue -->
<template>
  <div class="container">
    <h1>{{ title }}</h1>
    <p v-if="showContent">Content here</p>
  </div>
</template>
```

## Links Relevantes

- <router-link to="/css">Folha de Dicas de CSS</router-link>
- <router-link to="/javascript">Folha de Dicas de JavaScript</router-link>
- <router-link to="/web-development">Folha de Dicas de Desenvolvimento Web</router-link>
- <router-link to="/react">Folha de Dicas de React</router-link>
- <router-link to="/git">Folha de Dicas de Git</router-link>
- <router-link to="/linux">Folha de Dicas de Linux</router-link>
- <router-link to="/shell">Folha de Dicas de Shell</router-link>
- <router-link to="/docker">Folha de Dicas de Docker</router-link>

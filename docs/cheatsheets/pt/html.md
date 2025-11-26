---
title: 'Folha de Referência HTML'
description: 'Aprenda HTML com nossa folha de referência abrangente cobrindo comandos essenciais, conceitos e melhores práticas.'
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
Aprenda a estrutura da web HTML através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de HTML que cobrem elementos essenciais, marcação semântica, formulários, integração de mídia e recursos modernos do HTML5. Domine a estrutura eficiente de páginas web e a organização de conteúdo para fluxos de trabalho de desenvolvimento web modernos.
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
    <title>Título da Página</title>
  </head>
  <body>
    <!-- O conteúdo da página vai aqui -->
  </body>
</html>
```

### Elementos Head: `<head>`

A seção head contém metadados sobre o documento.

```html
<!-- Codificação de caracteres -->
<meta charset="UTF-8" />
<!-- Viewport para design responsivo -->
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<!-- Descrição da página -->
<meta name="description" content="Descrição da página" />
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

### Anatomia dos Elementos HTML

Elementos HTML consistem em tags de abertura, conteúdo e tags de fechamento.

```html
<!-- Elemento com conteúdo -->
<p>Este é um parágrafo</p>
<!-- Elementos de auto-fechamento -->
<img src="image.jpg" alt="Descrição" />
<br />
<hr />
<!-- Elementos com atributos -->
<a href="https://example.com" target="_blank">Link</a>
<!-- Elementos aninhados -->
<div>
  <p>Parágrafo aninhado</p>
</div>
```

## Elementos de Conteúdo de Texto

### Títulos: `h1` a `h6`

Definem a hierarquia e a importância das seções de conteúdo.

```html
<h1>Título Principal</h1>
<h2>Título da Seção</h2>
<h3>Título da Subseção</h3>
<h4>Título da Sub-subseção</h4>
<h5>Título Menor</h5>
<h6>Título Menor</h6>
```

### Parágrafos: `p`

O elemento mais comum para blocos de conteúdo de texto.

```html
<p>
  Este é um parágrafo de texto. Ele pode conter múltiplas frases e será quebrado
  automaticamente.
</p>
<p>Este é outro parágrafo. Parágrafos são separados por espaço de margem.</p>
```

### Formatação de Texto: `<strong>`, `<em>`, `<b>`, `<i>`

Elementos para enfatizar e estilizar texto em linha.

```html
<strong>Importância forte (negrito)</strong>
<em>Ênfase (itálico)</em>
<b>Texto em negrito</b>
<i>Texto em itálico</i>
<u>Texto sublinhado</u>
<mark>Texto destacado</mark>
<small>Texto pequeno</small>
<del>Texto excluído</del>
<ins>Texto inserido</ins>
```

### Quebras de Linha e Espaçamento: `<br>`, `<hr>`, `<pre>`

Controlam o fluxo de texto e o espaçamento dentro do conteúdo.

```html
<!-- Quebra de linha -->
Linha 1<br />
Linha 2
<!-- Regra horizontal -->
<hr />
<!-- Texto pré-formatado -->
<pre>
  Texto com
    espaçamento    preservado
      e quebras de linha
</pre>
<!-- Formatação de código -->
<code>console.log('Olá');</code>
```

## Listas e Navegação

### Listas Não Ordenadas: `<ul>`

Cria listas com marcadores para itens não sequenciais.

```html
<ul>
  <li>Primeiro item</li>
  <li>Segundo item</li>
  <li>Terceiro item</li>
</ul>
<!-- Listas aninhadas -->
<ul>
  <li>
    Item principal
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
  <li>Primeiro passo</li>
  <li>Segundo passo</li>
  <li>Terceiro passo</li>
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
  <dd>Linguagem de programação para web</dd>
</dl>
```

### Links e Navegação: `<a>`

Cria hiperlinks e estruturas de navegação.

```html
<!-- Link básico -->
<a href="https://example.com">Visitar Exemplo</a>
<!-- Link em nova aba -->
<a href="https://example.com" target="_blank">Nova Aba</a>
<!-- Link de e-mail -->
<a href="mailto:email@example.com">Enviar E-mail</a>
<!-- Link de telefone -->
<a href="tel:+1234567890">Ligue para Nós</a>
<!-- Âncoras de página interna -->
<a href="#section1">Ir para Seção 1</a>
<h2 id="section1">Seção 1</h2>
```

## Formulários e Elementos de Entrada

### Estrutura Básica do Formulário: `<form>`

A base para a coleta de entrada do usuário.

```html
<form action="/submit" method="POST">
  <label for="username">Nome de Usuário:</label>
  <input type="text" id="username" name="username" required />

  <label for="email">E-mail:</label>
  <input type="email" id="email" name="email" required />

  <input type="submit" value="Enviar" />
</form>
```

### Tipos de Entrada: `<input>`

Vários tipos de entrada para diferentes necessidades de coleta de dados.

```html
<!-- Entradas de texto -->
<input type="text" placeholder="Digite o texto" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="Senha" />
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
<label for="agree">Eu concordo com os termos</label>
<!-- Botões de rádio -->
<input type="radio" id="option1" name="choice" value="1" />
<label for="option1">Opção 1</label>
<input type="radio" id="option2" name="choice" value="2" />
<label for="option2">Opção 2</label>
<!-- Dropdown de seleção -->
<select name="country">
  <option value="us">Estados Unidos</option>
  <option value="uk">Reino Unido</option>
  <option value="ca">Canadá</option>
</select>
<!-- Área de texto -->
<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="Digite sua mensagem"
></textarea>
```

### Validação de Formulário: `required`, `min`, `max`, `pattern`

Atributos de validação de formulário integrados do HTML.

```html
<input type="text" required />
<input type="email" required />
<input type="text" minlength="3" maxlength="20" />
<input type="number" min="1" max="100" />
<input type="text" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}" />
```

## Elementos de Mídia

### Imagens: `<img>`, `<picture>`

Exibe imagens com vários atributos e opções.

```html
<!-- Imagem básica -->
<img src="image.jpg" alt="Descrição" />
<!-- Imagem responsiva -->
<img src="image.jpg" alt="Descrição" width="100%" height="auto" />
<!-- Imagem com tamanho -->
<img src="image.jpg" alt="Descrição" width="300" height="200" />
<!-- Elemento picture para imagens responsivas -->
<picture>
  <source media="(min-width: 800px)" srcset="large.jpg" />
  <source media="(min-width: 400px)" srcset="medium.jpg" />
  <img src="small.jpg" alt="Descrição" />
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

Incorpora conteúdo e aplicações externas.

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
      <th>Nome</th>
      <th>Idade</th>
      <th>Cidade</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>John</td>
      <td>25</td>
      <td>Nova York</td>
    </tr>
    <tr>
      <td>Jane</td>
      <td>30</td>
      <td>Londres</td>
    </tr>
  </tbody>
</table>
```

### Recursos Avançados de Tabela: `rowspan`, `colspan`, `<caption>`

Funcionalidade aprimorada da tabela com expansão e agrupamento.

```html
<table>
  <caption>
    Relatório de Vendas
  </caption>
  <colgroup>
    <col style="width: 50%" />
    <col style="width: 25%" />
    <col style="width: 25%" />
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">Produto</th>
      <th colspan="2">Vendas</th>
    </tr>
    <tr>
      <th>T1</th>
      <th>T2</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Produto A</td>
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
      <li><a href="#home">Início</a></li>
      <li><a href="#about">Sobre</a></li>
    </ul>
  </nav>
</header>
<!-- Conteúdo principal -->
<main>
  <article>
    <h1>Título do Artigo</h1>
    <p>Conteúdo do artigo...</p>
  </article>
</main>
<!-- Barra lateral -->
<aside>
  <h2>Links Relacionados</h2>
  <ul>
    <li><a href="#">Link 1</a></li>
  </ul>
</aside>
<!-- Rodapé da página -->
<footer>
  <p>© 2024 Nome da Empresa</p>
</footer>
```

### Elementos de Agrupamento de Conteúdo: `<section>`, `<article>`, `<div>`, `<figure>`

Organizam e agrupam seções de conteúdo relacionadas.

```html
<!-- Seção genérica -->
<section>
  <h2>Título da Seção</h2>
  <p>Conteúdo da seção...</p>
</section>
<!-- Artigo autônomo -->
<article>
  <header>
    <h1>Título do Artigo</h1>
    <time datetime="2024-01-01">1 de Janeiro de 2024</time>
  </header>
  <p>Conteúdo do artigo...</p>
</article>
<!-- Contêiner genérico -->
<div class="container">
  <p>Agrupamento de conteúdo genérico</p>
</div>
<!-- Figura com legenda -->
<figure>
  <img src="chart.jpg" alt="Gráfico de Vendas" />
  <figcaption>Dados de vendas para o T1 de 2024</figcaption>
</figure>
```

## Atributos HTML

### Atributos Globais: `id`, `class`, `title`, `data-*`

Atributos que podem ser usados em qualquer elemento HTML.

```html
<!-- ID para identificação única -->
<div id="unique-element">Conteúdo</div>
<!-- Classe para estilização e seleção -->
<p class="highlight important">Texto</p>
<!-- Título para tooltips -->
<span title="Este é um tooltip">Passe o mouse sobre mim</span>
<!-- Atributos de dados -->
<div data-user-id="123" data-role="admin">Usuário</div>
<!-- Idioma -->
<p lang="es">Hola mundo</p>
<!-- Direção do conteúdo -->
<p dir="rtl">Texto da direita para a esquerda</p>
<!-- Elementos ocultos -->
<div hidden>Isso não será exibido</div>
```

### Atributos de Acessibilidade: `alt`, `aria-*`, `tabindex`, `role`

Atributos que melhoram a acessibilidade e a experiência do usuário.

```html
<!-- Texto alternativo para imagens -->
<img src="photo.jpg" alt="Um pôr do sol sobre montanhas" />
<!-- Rótulos ARIA -->
<button aria-label="Fechar diálogo">×</button>
<div aria-hidden="true">Conteúdo decorativo</div>
<!-- Acessibilidade do formulário -->
<label for="email">Endereço de E-mail:</label>
<input type="email" id="email" aria-describedby="email-help" />
<small id="email-help">Nunca compartilharemos seu e-mail</small>
<!-- Índice de tabulação -->
<div tabindex="0">Div focável</div>
<div tabindex="-1">Div focável programaticamente</div>
<!-- Atributo de função -->
<div role="button" tabindex="0">Botão personalizado</div>
```

## Recursos Modernos do HTML5

### Novos Recursos de Entrada: `color`, `search`, `file`, `datalist`

O HTML5 introduziu novos tipos de entrada e atributos.

```html
<!-- Novos tipos de entrada -->
<input type="color" value="#ff0000" />
<input type="search" placeholder="Pesquisar..." />
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
  <summary>Clique para expandir</summary>
  <p>Este conteúdo está oculto por padrão e é revelado ao clicar no resumo.</p>
  <ul>
    <li>Item 1</li>
    <li>Item 2</li>
  </ul>
</details>
<details open>
  <summary>Isto começa expandido</summary>
  <p>Conteúdo visível por padrão.</p>
</details>
```

### Elemento Dialog: `<dialog>`

Funcionalidade nativa de diálogo e modal no HTML.

```html
<!-- Elemento de diálogo -->
<dialog id="myDialog">
  <h2>Título do Diálogo</h2>
  <p>O conteúdo do diálogo vai aqui.</p>
  <button onclick="closeDialog()">Fechar</button>
</dialog>
<button onclick="openDialog()">Abrir Diálogo</button>
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
<!-- Sempre declare o doctype -->
<!DOCTYPE html>
<!-- Use elementos semânticos -->
<header>...</header>
<main>...</main>
<footer>...</footer>
<!-- Aninhamento correto -->
<div>
  <p>Conteúdo aninhado corretamente</p>
</div>
<!-- Use letras minúsculas para elementos e atributos -->
<img src="image.jpg" alt="descrição" />
<!-- Feche todas as tags -->
<p>Sempre feche suas tags</p>
<!-- Use texto alt significativo -->
<img src="chart.png" alt="Vendas aumentaram 25% no T4" />
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
<p>Conteúdo de texto</p>
<!-- Sempre feche as tags -->
<!-- Aninhamento inválido -->
<p>
  Parágrafo válido
  <!-- Não coloque elementos de bloco dentro de parágrafos -->
</p>
<!-- Use ferramentas do desenvolvedor -->
<!-- Clique com o botão direito → Inspecionar Elemento -->
<!-- Verifique o console em busca de erros -->
<!-- Valide a acessibilidade com WAVE ou axe -->
```

## Motores de Template e Frameworks HTML

### Motores de Template: Handlebars, Mustache

Geração de HTML dinâmico com linguagens de template.

```html
<!-- Template Handlebars -->
<div>
  <h1>{{title}}</h1>
  {{#each items}}
  <p>{{this}}</p>
  {{/each}}
</div>
<!-- Template Mustache -->
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
<my-component>Olá Mundo</my-component>
<script>
  class MyComponent extends HTMLElement {
    // Lógica do componente
  }
  customElements.define('my-component', MyComponent)
</script>
```

### Integração com Frameworks: React JSX, Templates Vue

HTML dentro de frameworks JavaScript modernos.

```html
<!-- React JSX -->
function Component() { return (
<div className="container">
  <h1>{title}</h1>
  <p>Conteúdo aqui</p>
</div>
); }
<!-- Template Vue -->
<template>
  <div class="container">
    <h1>{{ title }}</h1>
    <p v-if="showContent">Conteúdo aqui</p>
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

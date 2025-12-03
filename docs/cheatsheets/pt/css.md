---
title: 'Folha de Referência CSS | LabEx'
description: 'Aprenda CSS3 com esta folha de referência abrangente. Referência rápida para seletores CSS, flexbox, grid, animações, design responsivo e técnicas modernas de estilização para desenvolvedores web.'
pdfUrl: '/cheatsheets/pdf/css-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas de CSS
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/css">Aprenda CSS com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda estilização web com CSS através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de CSS cobrindo propriedades essenciais, seletores, técnicas de layout, design responsivo e recursos modernos. Domine a estilização web eficiente e o design de layout para fluxos de trabalho de desenvolvimento web modernos.
</base-disclaimer-content>
</base-disclaimer>

## Sintaxe CSS e Seletores

### Sintaxe Básica

CSS consiste em seletores e declarações. O seletor visa elementos HTML, e as declarações definem valores de propriedade.

```css
/* Sintaxe básica */
selector {
  property: value;
  property: value;
}

/* Exemplo */
p {
  color: red;
  font-size: 16px;
}
```

### Seletores de Elementos

Visam elementos HTML pelo nome da tag.

```css
/* Selecionar todos os parágrafos */
p {
  color: blue;
}

/* Selecionar todos os cabeçalhos */
h1 {
  font-size: 2em;
}

/* Selecionar todos os links */
a {
  text-decoration: none;
}
```

### Seletores de Classe

Visam elementos com atributos de classe específicos.

```css
/* Selecionar elementos com class="highlight" */
.highlight {
  background-color: yellow;
}

/* Selecionar parágrafos com class="intro" */
p.intro {
  font-weight: bold;
}

/* Múltiplas classes */
.large.bold {
  font-size: 20px;
  font-weight: bold;
}
```

<BaseQuiz id="css-class-1" correct="B">
  <template #question>
    Como você seleciona um elemento com class="highlight" em CSS?
  </template>
  
  <BaseQuizOption value="A">highlight { }</BaseQuizOption>
  <BaseQuizOption value="B" correct>.highlight { }</BaseQuizOption>
  <BaseQuizOption value="C">#highlight { }</BaseQuizOption>
  <BaseQuizOption value="D">class="highlight" { }</BaseQuizOption>
  
  <BaseQuizAnswer>
    Seletores de classe usam um ponto (<code>.</code>) como prefixo. <code>.highlight</code> seleciona todos os elementos com <code>class="highlight"</code>. Seletores de ID usam <code>#</code>, e seletores de elemento não usam prefixo.
  </BaseQuizAnswer>
</BaseQuiz>

### Seletores de ID

Visam elementos com atributos de ID específicos.

```css
/* Selecionar elemento com id="header" */
#header {
  background-color: #333;
}

/* IDs devem ser únicos por página */
#navigation {
  position: fixed;
}
```

### Seletores de Atributo

Visam elementos com certos atributos usando seletores de atributo.

```css
/* Elementos com atributo title */
[title] {
  cursor: help;
}

/* Links para sites externos */
a[href^='http'] {
  color: red;
}

/* Elementos de input do tipo text */
input[type='text'] {
  border: 1px solid #ccc;
}
```

### Pseudo-classes

Pseudo-classes aplicam CSS com base em mudanças de estado e interações do usuário.

```css
/* Estados de link */
a:hover {
  color: red;
}
a:visited {
  color: purple;
}
a:active {
  color: orange;
}

/* Estados de formulário */
input:focus {
  border-color: blue;
}
input:invalid {
  border-color: red;
}

/* Pseudo-classes estruturais */
li:first-child {
  font-weight: bold;
}
li:nth-child(odd) {
  background-color: #f0f0f0;
}
```

## Modelo de Caixa e Layout

### Conteúdo: `width` / `height`

A área de conteúdo real do elemento.

```css
/* Definir dimensões */
div {
  width: 300px;
  height: 200px;
}

/* Dimensionamento responsivo */
.container {
  width: 100%;
  max-width: 1200px;
}

/* Restrições Mínimas/Máximas */
.box {
  min-height: 100px;
  max-width: 500px;
}
```

### Preenchimento (Padding): `padding`

Espaço entre o conteúdo e a borda, dentro do elemento.

```css
/* Todos os lados */
div {
  padding: 20px;
}

/* Lados individuais */
div {
  padding-top: 10px;
  padding-right: 15px;
}

/* Abreviação: topo direita inferior esquerda */
div {
  padding: 10px 15px 20px 5px;
}
```

<BaseQuiz id="css-padding-1" correct="C">
  <template #question>
    O que <code>padding: 10px 20px</code> define?
  </template>
  
  <BaseQuizOption value="A">10px topo/inferior, 20px esquerda/direita</BaseQuizOption>
  <BaseQuizOption value="B">10px em todos os lados</BaseQuizOption>
  <BaseQuizOption value="C" correct>10px topo/inferior, 20px esquerda/direita</BaseQuizOption>
  <BaseQuizOption value="D">10px topo, 20px inferior</BaseQuizOption>
  
  <BaseQuizAnswer>
    Quando dois valores são fornecidos, o primeiro aplica-se ao topo e inferior, e o segundo aplica-se à esquerda e direita. Portanto, <code>padding: 10px 20px</code> significa preenchimento vertical de 10px e preenchimento horizontal de 20px.
  </BaseQuizAnswer>
</BaseQuiz>
```

### Borda (Border): `border`

Bordas fornecem uma moldura para elementos com tamanho, estilo e cor personalizáveis.

```css
/* Abreviação de borda */
div {
  border: 2px solid #333;
}

/* Propriedades individuais */
div {
  border-width: 1px;
  border-style: dashed;
  border-color: red;
}

/* Lados individuais */
div {
  border-bottom: 3px solid blue;
}
```

### Margem (Margin): `margin`

Espaço fora da borda, entre os elementos.

```css
/* Todos os lados */
div {
  margin: 20px;
}

/* Centralizar horizontalmente */
div {
  margin: 0 auto;
}

/* Lados individuais */
div {
  margin-top: 30px;
  margin-bottom: 10px;
}

/* Margens negativas */
div {
  margin-left: -20px;
}
```

<BaseQuiz id="css-margin-1" correct="C">
  <template #question>
    O que <code>margin: 0 auto</code> faz?
  </template>
  
  <BaseQuizOption value="A">Remove todas as margens</BaseQuizOption>
  <BaseQuizOption value="B">Adiciona margens iguais em todos os lados</BaseQuizOption>
  <BaseQuizOption value="C" correct>Centraliza um elemento de bloco horizontalmente</BaseQuizOption>
  <BaseQuizOption value="D">Centraliza um elemento de bloco verticalmente</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>margin: 0 auto</code> define as margens superior e inferior como 0 e as margens esquerda/direita como auto, o que centraliza um elemento de bloco horizontalmente dentro de seu contêiner.
  </BaseQuizAnswer>
</BaseQuiz>

## Texto e Tipografia

### Propriedades de Fonte

Controlam a família da fonte, tamanho, peso e estilo.

```css
/* Família da fonte */
body {
  font-family: Arial, sans-serif;
}

/* Google Fonts */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
body {
  font-family: 'Roboto', sans-serif;
}

/* Tamanho da fonte */
h1 {
  font-size: 2rem;
}
p {
  font-size: 16px;
}

/* Peso da fonte */
h2 {
  font-weight: bold;
}
span {
  font-weight: 300;
}
```

### Alinhamento de Texto

Controla o posicionamento e espaçamento do texto.

```css
/* Alinhamento horizontal */
h1 {
  text-align: center;
}
p {
  text-align: justify;
}

/* Altura da linha */
p {
  line-height: 1.6;
}

/* Espaçamento entre letras e palavras */
h1 {
  letter-spacing: 2px;
}
p {
  word-spacing: 4px;
}
```

### Estilização de Texto

Adiciona decorações e transformações ao texto.

```css
/* Decoração de texto */
a {
  text-decoration: underline;
}
.strike {
  text-decoration: line-through;
}

/* Transformação de texto */
.uppercase {
  text-transform: uppercase;
}
.capitalize {
  text-transform: capitalize;
}

/* Sombra de texto */
h1 {
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}
```

### Cores

CSS fornece várias maneiras diferentes de especificar cores para diversas necessidades de estilização.

```css
/* Formatos de cor */
p {
  color: red;
}
div {
  background-color: #ff5733;
}
```

<BaseQuiz id="css-colors-1" correct="D">
  <template #question>
    Qual formato de cor CSS é mais comumente usado para design web?
  </template>
  
  <BaseQuizOption value="A">Apenas RGB</BaseQuizOption>
  <BaseQuizOption value="B">Apenas cores nomeadas</BaseQuizOption>
  <BaseQuizOption value="C">Apenas HSL</BaseQuizOption>
  <BaseQuizOption value="D" correct>Códigos Hexadecimais (#RRGGBB) são muito comuns, juntamente com cores nomeadas e RGB</BaseQuizOption>
  
  <BaseQuizAnswer>
    Os códigos de cor Hexadecimais (#RRGGBB) são amplamente utilizados porque são concisos e fáceis de copiar de ferramentas de design. Cores nomeadas e RGB/rgba também são comuns. A escolha depende do caso de uso específico e da preferência.
  </BaseQuizAnswer>
</BaseQuiz>
span {
  color: rgb(255, 87, 51);
}
section {
  background-color: rgba(255, 87, 51, 0.8);
}

/_ Cores HSL _/
header {
background-color: hsl(200, 100%, 50%);
}

/_ Variáveis CSS para cores _/
:root {
--primary-color: #3498db;
}
.button {
background-color: var(--primary-color);
}

````

## Layout Flexbox

### Propriedades do Contêiner Flex

Propriedades aplicadas ao contêiner pai.

```css
/* Habilitar flexbox */
.container {
  display: flex;
}

/* Direção flexível */
.container {
  flex-direction: row; /* padrão */
  flex-direction: column;
  flex-direction: row-reverse;
}

/* Justificar conteúdo (eixo principal) */
.container {
  justify-content: flex-start; /* padrão */
  justify-content: center;
  justify-content: space-between;
  justify-content: space-around;
}

/* Alinhar itens (eixo cruzado) */
.container {
  align-items: stretch; /* padrão */
  align-items: center;
  align-items: flex-start;
}
````

### Propriedades do Item Flex

Propriedades aplicadas aos elementos filhos.

```css
/* Crescimento/Encolhimento flexível */
.item {
  flex-grow: 1; /* crescer para preencher o espaço */
  flex-shrink: 1; /* encolher se necessário */
  flex-basis: auto; /* tamanho inicial */
}

/* Abreviação */
.item {
  flex: 1; /* flex: 1 1 0% */
  flex: 0 0 200px; /* largura fixa */
}

/* Alinhamento individual */
.item {
  align-self: center;
  align-self: flex-end;
}

/* Ordem */
.item {
  order: 2; /* alterar ordem visual */
}
```

## Layout CSS Grid

### Contêiner Grid

Definir estrutura e propriedades da grade.

```css
/* Habilitar grid */
.grid-container {
  display: grid;
}

/* Definir colunas e linhas */
.grid-container {
  grid-template-columns: 1fr 2fr 1fr;
  grid-template-rows: 100px auto 50px;
}

/* Espaços da grade (gaps) */
.grid-container {
  gap: 20px;
  column-gap: 30px;
  row-gap: 10px;
}

/* Áreas de grade nomeadas */
.grid-container {
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}
```

### Itens da Grade

Posicionar e dimensionar itens da grade.

```css
/* Posicionamento da grade */
.grid-item {
  grid-column: 1 / 3; /* abranger colunas 1-2 */
  grid-row: 2 / 4; /* abranger linhas 2-3 */
}

/* Abreviação */
.grid-item {
  grid-area: 2 / 1 / 4 / 3; /* linha-início / coluna-início / linha-fim / coluna-fim */
}

/* Áreas nomeadas */
.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}

/* Colocação automática */
.grid-item {
  grid-column: span 2; /* abranger 2 colunas */
  grid-row: span 3; /* abranger 3 linhas */
}
```

## Posicionamento

### Propriedade Position

Controla o comportamento de posicionamento do elemento.

```css
/* Estático (padrão) */
.element {
  position: static;
}

/* Posicionamento relativo */
.element {
  position: relative;
  top: 20px;
  left: 10px;
}

/* Posicionamento absoluto */
.element {
  position: absolute;
  top: 0;
  right: 0;
}

/* Posicionamento fixo */
.navbar {
  position: fixed;
  top: 0;
  width: 100%;
}

/* Posicionamento pegajoso (sticky) */
.sidebar {
  position: sticky;
  top: 20px;
}
```

### Z-Index e Empilhamento

Controla a ordem em que os elementos se sobrepõem usando z-index e contexto de empilhamento.

```css
/* Ordem de empilhamento */
.modal {
  position: fixed;
  z-index: 1000;
}
.overlay {
  position: absolute;
  z-index: 999;
}

/* Criando contexto de empilhamento */
.container {
  position: relative;
  z-index: 0;
}

/* Valores comuns de z-index */
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

## Design Responsivo

### Media Queries

Aplicam estilos com base nas características do dispositivo.

```css
/* Abordagem mobile first */
.container {
  width: 100%;
}

/* Estilos para Tablet */
@media (min-width: 768px) {
  .container {
    width: 750px;
  }
}

/* Estilos para Desktop */
@media (min-width: 1024px) {
  .container {
    width: 960px;
  }
}

/* Estilos de impressão */
@media print {
  body {
    font-size: 12pt;
  }
  .no-print {
    display: none;
  }
}

/* Orientação */
@media (orientation: landscape) {
  .sidebar {
    display: block;
  }
}
```

### Unidades Responsivas

Usam unidades relativas para layouts flexíveis.

```css
/* Unidades de Viewport */
.hero {
  height: 100vh;
} /* altura total da viewport */
.sidebar {
  width: 25vw;
} /* 25% da largura da viewport */

/* Unidades Relativas */
p {
  font-size: 1.2em;
} /* 1.2x o tamanho da fonte do pai */
h1 {
  font-size: 2rem;
} /* 2x o tamanho da fonte raiz */

/* Unidades de Porcentagem */
.container {
  width: 80%;
}
.column {
  width: 50%;
}

/* Grid CSS responsivo */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

/* Flexbox responsivo */
.flex-container {
  display: flex;
  flex-wrap: wrap;
}
```

## Animações e Transições

### Transições CSS

Mudanças suaves entre valores de propriedade.

```css
/* Transição básica */
.button {
  background-color: blue;
  transition: background-color 0.3s ease;
}
.button:hover {
  background-color: red;
}

/* Múltiplas propriedades */
.card {
  transform: scale(1);
  opacity: 1;
  transition: all 0.3s ease-in-out;
}
.card:hover {
  transform: scale(1.05);
  opacity: 0.8;
}

/* Transições individuais */
.element {
  transition-property: width, height;
  transition-duration: 0.5s, 1s;
  transition-timing-function: ease, linear;
}
```

### Animações CSS

Criam animações complexas com keyframes.

```css
/* Definir keyframes */
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

/* Aplicar animações */
.slide-in {
  animation: slideIn 0.5s ease-out;
}
.pulse {
  animation: pulse 2s infinite;
}

/* Abreviação de animação */
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

## Variáveis e Funções CSS

### Variáveis CSS

Definem e usam propriedades personalizadas para temas consistentes.

```css
/* Definir variáveis */
:root {
  --primary-color: #3498db;
  --secondary-color: #2ecc71;
  --font-size-large: 24px;
  --border-radius: 8px;
}

/* Usar variáveis */
.button {
  background-color: var(--primary-color);
  border-radius: var(--border-radius);
}

/* Valores de fallback */
.text {
  color: var(--text-color, #333);
}

/* Variáveis locais */
.card {
  --card-padding: 20px;
  padding: var(--card-padding);
}
```

### Funções CSS

CSS tem uma gama de funções integradas para cálculos e valores dinâmicos.

```css
/* Função Calc */
.container {
  width: calc(100% - 40px);
  height: calc(100vh - 60px);
}

/* Funções Min/Max */
.responsive {
  width: min(90%, 1200px);
  font-size: max(16px, 1.2vw);
  height: clamp(200px, 50vh, 400px);
}

/* Funções de Cor */
.element {
  background-color: hsl(200, 50%, 50%);
  color: rgb(255, 87, 51);
}

/* Funções de Transformação */
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

## Melhores Práticas e Organização

### Organização CSS

Estruturar seu CSS para manutenção.

```css
/* Usar nomes de classe significativos */
.hero-section {
}
.primary-button {
}
.navigation-menu {
}

/* Metodologia BEM */
.block {
}
.block__element {
}
.block--modifier {
}

/* Exemplo */
.card {
}
.card__header {
}
.card__body {
}
.card--featured {
}

/* Agrupar estilos relacionados */
/* ===== LAYOUT ===== */
.container {
}
.grid {
}

/* ===== COMPONENTES ===== */
.button {
}
.card {
}
```

### Desempenho e Otimização

Escrever CSS eficiente para melhor desempenho.

```css
/* Evitar aninhamento profundo */
/* Ruim */
.header .nav ul li a {
}

/* Bom */
.nav-link {
}

/* Usar seletores eficientes */
/* Ruim */
body div.container > p {
}

/* Bom */
.content-text {
}

/* Minimizar repaints */
/* Usar transform em vez de mudar position */
.element {
  transform: translateX(100px);
  /* em vez de left: 100px; */
}

/* Agrupar prefixos de fornecedor */
.element {
  -webkit-border-radius: 5px;
  -moz-border-radius: 5px;
  border-radius: 5px;
}
```

## Depuração CSS

### Ferramentas de Desenvolvedor do Navegador

Inspecionar e modificar CSS em tempo real.

```css
/* Passos comuns de depuração */
/* 1. Clique com o botão direito → Inspecionar Elemento */
/* 2. Verificar estilos Calculados */
/* 3. Procurar propriedades substituídas */
/* 4. Testar alterações em tempo real */
/* 5. Copiar CSS modificado de volta para o seu arquivo */
```

### Problemas Comuns de CSS

Solucionar problemas frequentemente encontrados.

```css
/* Problemas de modelo de caixa */
* {
  box-sizing: border-box;
}

/* Limpando floats */
.clearfix::after {
  content: '';
  display: table;
  clear: both;
}

/* Problemas de z-index */
/* Garantir elementos posicionados para z-index funcionar */
.element {
  position: relative;
  z-index: 1;
}
```

### Validação CSS

Garantir que seu CSS siga padrões e melhores práticas.

```css
/* Usar validadores CSS */
/* Validador CSS W3C */
/* Ferramentas de compatibilidade de navegador */

/* Comentar seu código */
/* ===== ESTILOS DO CABEÇALHO ===== */
.header {
}

/* TODO: Adicionar estilos móveis */
/* FIXME: Corrigir compatibilidade com IE */

/* Usar formatação consistente */
.element {
  property: value;
  property: value;
}
```

## Frameworks e Ferramentas CSS

### Pré-processadores CSS

Estender CSS com variáveis, aninhamento e funções.

```scss
/* Exemplo SCSS/Sass */
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
/* Exemplo Less */
@primary-color: #3498db;

.button {
  background-color: @primary-color;

  &:hover {
    background-color: lighten(@primary-color, 10%);
  }
}
```

### CSS-in-JS e Ferramentas Modernas

Abordagens modernas para estilização em aplicações web.

```css
/* Plugins PostCSS */
/* Autoprefixer - adiciona prefixos de fornecedor */
/* PurgeCSS - remove CSS não utilizado */

/* Módulos CSS */
.button {
  composes: base-button;
  background-color: blue;
}
```

```javascript
/* CSS utilitário-primeiro (Tailwind) */
;<div class="flex items-center justify-center p-4 bg-blue-500">
  <span class="text-white font-bold">Botão</span>
</div>

/* CSS-in-JS (Styled Components) */
const Button = styled.button`
  background: ${(props) => (props.primary ? 'blue' : 'white')};
  padding: 1rem 2rem;
`
```

## Links Relevantes

- <router-link to="/html">Folha de Dicas de HTML</router-link>
- <router-link to="/javascript">Folha de Dicas de JavaScript</router-link>
- <router-link to="/react">Folha de Dicas de React</router-link>
- <router-link to="/web-development">Folha de Dicas de Desenvolvimento Web</router-link>

---
title: 'Fiche de Référence Développement Web | LabEx'
description: 'Apprenez le développement web avec cette fiche complète. Référence rapide pour HTML, CSS, JavaScript, API, conception responsive, optimisation des performances et essentiels du développement full-stack.'
pdfUrl: '/cheatsheets/pdf/web-development-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche pour le développement Web
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/web-development">Apprenez le développement Web avec des laboratoires pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez le développement web grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets sur le développement web couvrant les bases essentielles de HTML, CSS, JavaScript, la manipulation du DOM et la conception réactive. Maîtrisez la création de sites Web interactifs et réactifs pour les flux de travail de développement Web modernes.
</base-disclaimer-content>
</base-disclaimer>

## Fondamentaux HTML et Structure de Document

### Structure HTML de Base : `<!DOCTYPE html>`

Créez la base de chaque page Web.

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>My Web Page</title>
    <link rel="stylesheet" href="style.css" />
  </head>
  <body>
    <h1>Hello World!</h1>
    <script src="script.js"></script>
  </body>
</html>
```

### Éléments Sémantiques : `<header>` / `<main>` / `<footer>`

Utilisez des éléments sémantiques HTML5 significatifs pour une meilleure structure.

```html
<header>
  <nav>
    <ul>
      <li><a href="#home">Home</a></li>
      <li><a href="#about">About</a></li>
    </ul>
  </nav>
</header>
<main>
  <section>
    <h1>Welcome</h1>
    <p>Main content here</p>
  </section>
</main>
<footer>
  <p>© 2024 My Website</p>
</footer>
```

<BaseQuiz id="webdev-semantic-1" correct="B">
  <template #question>
    Quel est l'avantage principal d'utiliser des éléments HTML sémantiques tels que <code>header</code>, <code>main</code> et <code>footer</code> ?
  </template>
  
  <BaseQuizOption value="A">Ils rendent le chargement de la page plus rapide</BaseQuizOption>
  <BaseQuizOption value="B" correct>Ils améliorent l'accessibilité et le SEO en donnant un sens à la structure</BaseQuizOption>
  <BaseQuizOption value="C">Ils stylisent automatiquement la page</BaseQuizOption>
  <BaseQuizOption value="D">Ils sont requis pour que JavaScript fonctionne</BaseQuizOption>
  
  <BaseQuizAnswer>
    Les éléments HTML sémantiques donnent un sens à la structure du document, ce qui facilite la compréhension de l'organisation du contenu par les lecteurs d'écran, les moteurs de recherche et les développeurs. Cela améliore l'accessibilité et le SEO.
  </BaseQuizAnswer>
</BaseQuiz>

### Éléments de Texte : `<h1>` à `<h6>` / `<p>`

Structurez le contenu avec une hiérarchie de titres appropriée et des paragraphes.

```html
<h1>Main Title</h1>
<h2>Section Heading</h2>
<h3>Subsection</h3>
<p>
  This is a paragraph with <strong>bold text</strong> and <em>italic text</em>.
</p>
<p>Another paragraph with a <a href="https://example.com">link</a>.</p>
```

### Listes : `<ul>` / `<ol>` / `<li>`

Créez des listes d'informations organisées.

```html
<!-- Unordered list -->
<ul>
  <li>First item</li>
  <li>Second item</li>
  <li>Third item</li>
</ul>

<!-- Ordered list -->
<ol>
  <li>Step 1</li>
  <li>Step 2</li>
  <li>Step 3</li>
</ol>
```

### Images et Médias : `<img>` / `<video>` / `<audio>`

Intégrez du contenu multimédia avec les attributs appropriés.

```html
<!-- Image with alt text -->
<img src="image.jpg" alt="Description of image" width="300" />

<!-- Video element -->
<video controls width="400">
  <source src="video.mp4" type="video/mp4" />
  Your browser doesn't support video.
</video>

<!-- Audio element -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
</audio>
```

### Tableaux : `<table>` / `<tr>` / `<td>`

Affichez des données tabulaires avec la structure appropriée.

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
  </tbody>
</table>
```

## Formulaires et Entrée Utilisateur

### Structure du Formulaire : `<form>`

Créez le conteneur pour les entrées et les contrôles de l'utilisateur.

```html
<form action="/submit" method="POST">
  <label for="name">Name:</label>
  <input type="text" id="name" name="name" required />

  <label for="email">Email:</label>
  <input type="email" id="email" name="email" required />

  <button type="submit">Submit</button>
</form>
```

### Types d'Entrée : `type="text"` / `type="email"`

Utilisez les types d'entrée appropriés pour différentes données.

```html
<input type="text" placeholder="Enter your name" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="Password" />
<input type="number" min="1" max="100" />
<input type="date" />
<input type="checkbox" id="agree" />
<input type="radio" name="gender" value="male" />
<input type="file" accept=".jpg,.png" />
```

### Contrôles de Formulaire : `<select>` / `<textarea>`

Fournissez diverses façons pour les utilisateurs de saisir des informations.

```html
<select name="country" id="country">
  <option value="">Select a country</option>
  <option value="us">United States</option>
  <option value="ca">Canada</option>
</select>

<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="Enter your message"
></textarea>
```

## Fondamentaux CSS et Stylisme

### Sélecteurs CSS : `element` / `.class` / `#id`

Ciblez les éléments HTML pour le stylisme avec différents types de sélecteurs.

```css
/* Element selector */
h1 {
  color: blue;
  font-size: 2rem;
}

/* Class selector */
.highlight {
  background-color: yellow;
  padding: 10px;
}

/* ID selector */
#header {
  background-color: navy;
  color: white;
}

/* Descendant selector */
.container p {
  line-height: 1.6;
}
```

### Modèle de Boîte (Box Model) : `margin` / `padding` / `border`

Contrôlez l'espacement et la mise en page avec le modèle de boîte CSS.

```css
.box {
  width: 300px;
  height: 200px;
  margin: 20px; /* Outside spacing */
  padding: 15px; /* Inside spacing */
  border: 2px solid black; /* Border properties */
}

/* Shorthand properties */
.element {
  margin: 10px 20px; /* top/bottom left/right */
  padding: 10px 15px 20px 25px; /* top right bottom left */
  border-radius: 5px; /* Rounded corners */
}
```

<BaseQuiz id="webdev-boxmodel-1" correct="B">
  <template #question>
    Quelle est la différence entre <code>margin</code> et <code>padding</code> en CSS ?
  </template>
  
  <BaseQuizOption value="A">Il n'y a pas de différence</BaseQuizOption>
  <BaseQuizOption value="B" correct>La marge est l'espace à l'extérieur de l'élément, le padding est l'espace à l'intérieur de l'élément</BaseQuizOption>
  <BaseQuizOption value="C">La marge est pour l'espacement horizontal, le padding est pour l'espacement vertical</BaseQuizOption>
  <BaseQuizOption value="D">La marge est pour les bordures, le padding est pour le contenu</BaseQuizOption>
  
  <BaseQuizAnswer>
    La marge crée de l'espace à l'extérieur de la bordure de l'élément (entre les éléments), tandis que le padding crée de l'espace à l'intérieur de l'élément entre le contenu et la bordure. Les deux affectent l'espacement mais dans des zones différentes.
  </BaseQuizAnswer>
</BaseQuiz>

### Flexbox : `display: flex`

Créez des mises en page flexibles et réactives facilement.

```css
.container {
  display: flex;
  justify-content: center; /* Horizontal alignment */
  align-items: center; /* Vertical alignment */
  gap: 20px; /* Space between items */
}

.flex-item {
  flex: 1; /* Equal width items */
}

/* Flexbox direction */
.column-layout {
  display: flex;
  flex-direction: column;
}
```

<BaseQuiz id="webdev-flexbox-1" correct="A">
  <template #question>
    Que fait <code>justify-content: center</code> en Flexbox ?
  </template>
  
  <BaseQuizOption value="A" correct>Centre les éléments flex le long de l'axe principal (horizontal par défaut)</BaseQuizOption>
  <BaseQuizOption value="B">Centre les éléments verticalement</BaseQuizOption>
  <BaseQuizOption value="C">Espace les éléments uniformément</BaseQuizOption>
  <BaseQuizOption value="D">Étire les éléments pour remplir l'espace</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>justify-content</code> contrôle l'alignement le long de l'axe principal (horizontal par défaut). <code>center</code> centre tous les éléments flex dans le conteneur. Utilisez <code>align-items</code> pour contrôler l'alignement sur l'axe transversal (vertical).
  </BaseQuizAnswer>
</BaseQuiz>

### Mise en Page en Grille (Grid Layout) : `display: grid`

Créez des mises en page bidimensionnelles complexes.

```css
.grid-container {
  display: grid;
  grid-template-columns: repeat(3, 1fr); /* 3 columns equal */
  grid-gap: 20px;
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}

.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}
```

## Bases JavaScript et Fondamentaux de Programmation

### Variables : `let` / `const` / `var`

Stockez et manipulez des données avec différentes déclarations de variables.

```javascript
// Modern variable declarations
let name = 'John' // Can be reassigned
const age = 25 // Cannot be reassigned
const colors = ['red', 'blue'] // Array (contents can change)

// Variable types
let message = 'Hello World' // String
let count = 42 // Number
let isActive = true // Boolean
let data = null // Null
let user = {
  // Object
  name: 'Alice',
  email: 'alice@example.com',
}
```

### Fonctions : `function` / Fonctions Fléchées (Arrow Functions)

Créez des blocs de code réutilisables avec différentes syntaxes de fonction.

```javascript
// Function declaration
function greet(name) {
  return `Hello, ${name}!`
}

// Arrow function
const add = (a, b) => a + b

// Arrow function with block
const calculateArea = (width, height) => {
  const area = width * height
  return area
}

// Function with default parameters
function createUser(name, age = 18) {
  return { name, age }
}
```

### Logique Conditionnelle : `if` / `else` / `switch`

Contrôlez le flux du programme avec des instructions conditionnelles.

```javascript
// If/else statement
if (age >= 18) {
  console.log('Adult')
} else if (age >= 13) {
  console.log('Teenager')
} else {
  console.log('Child')
}

// Ternary operator
const status = age >= 18 ? 'adult' : 'minor'

// Switch statement
switch (day) {
  case 'Monday':
    console.log('Start of work week')
    break
  case 'Friday':
    console.log('TGIF!')
    break
  default:
    console.log('Regular day')
}
```

### Boucles : `for` / `while` / Méthodes de Tableau (Array Methods)

Itérez sur les données et répétez les opérations.

```javascript
// For loop
for (let i = 0; i < 5; i++) {
  console.log(i)
}

// For...of loop
for (const item of items) {
  console.log(item)
}

// Array methods
const numbers = [1, 2, 3, 4, 5]
numbers.forEach((num) => console.log(num))
const doubled = numbers.map((num) => num * 2)
const evens = numbers.filter((num) => num % 2 === 0)
const sum = numbers.reduce((total, num) => total + num, 0)
```

## Manipulation du DOM et Événements

### Sélection d'Éléments : `querySelector` / `getElementById`

Trouvez et accédez aux éléments HTML en JavaScript.

```javascript
// Select single elements
const title = document.getElementById('title')
const button = document.querySelector('.btn')
const firstParagraph = document.querySelector('p')

// Select multiple elements
const allButtons = document.querySelectorAll('.btn')
const allParagraphs = document.getElementsByTagName('p')

// Check if element exists
if (button) {
  button.style.color = 'blue'
}
```

### Modification du Contenu : `innerHTML` / `textContent`

Changez le contenu et les attributs des éléments HTML.

```javascript
// Change text content
title.textContent = 'New Title'
title.innerHTML = '<strong>Bold Title</strong>'

// Modify attributes
button.setAttribute('disabled', 'true')
const src = image.getAttribute('src')

// Add/remove classes
button.classList.add('active')
button.classList.remove('hidden')
button.classList.toggle('highlighted')
```

### Gestion des Événements : `addEventListener`

Répondez aux interactions de l'utilisateur et aux événements du navigateur.

```javascript
// Click event
button.addEventListener('click', function () {
  alert('Button clicked!')
})

// Form submit event
form.addEventListener('submit', function (e) {
  e.preventDefault() // Prevent form submission
  const formData = new FormData(form)
  console.log(formData.get('username'))
})

// Keyboard events
document.addEventListener('keydown', function (e) {
  if (e.key === 'Enter') {
    console.log('Enter key pressed')
  }
})
```

### Création d'Éléments : `createElement` / `appendChild`

Créez et ajoutez dynamiquement de nouveaux éléments HTML.

```javascript
// Create new element
const newDiv = document.createElement('div')
newDiv.textContent = 'New content'
newDiv.className = 'highlight'
// Add to page
document.body.appendChild(newDiv)

// Create list item
const li = document.createElement('li')
li.innerHTML = "<a href='#'>New Link</a>"
document.querySelector('ul').appendChild(li)

// Remove element
const oldElement = document.querySelector('.remove-me')
oldElement.remove()
```

## Conception Réactive (Responsive Design) et Requêtes Média CSS

### Balise Meta Viewport : `viewport`

Configurez le viewport approprié pour la conception réactive.

```html
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
```

```css
/* CSS for responsive images */
img {
  max-width: 100%;
  height: auto;
}

/* Responsive container */
.container {
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 20px;
}
```

### Requêtes Média : `@media`

Appliquez différents styles en fonction de la taille de l'écran et des capacités de l'appareil.

```css
/* Mobile first approach */
.grid {
  display: grid;
  grid-template-columns: 1fr; /* Single column on mobile */
  gap: 20px;
}

/* Tablet and up */
@media (min-width: 768px) {
  .grid {
    grid-template-columns: repeat(2, 1fr); /* 2 columns */
  }
}

/* Desktop and up */
@media (min-width: 1024px) {
  .grid {
    grid-template-columns: repeat(3, 1fr); /* 3 columns */
  }
}
```

### Unités Flexibles : `rem` / `em` / `%` / `vw` / `vh`

Utilisez des unités relatives pour des conceptions évolutives et réactives.

```css
/* Relative to root font-size */
h1 {
  font-size: 2rem;
} /* 32px if root is 16px */

/* Relative to parent font-size */
p {
  font-size: 1.2em;
} /* 1.2 times parent size */

/* Percentage based */
.sidebar {
  width: 30%;
} /* 30% of parent width */

/* Viewport units */
.hero {
  height: 100vh; /* Full viewport height */
  width: 100vw; /* Full viewport width */
}
```

### Typographie Réactive : `clamp()`

Créez une typographie fluide qui s'adapte à la taille de l'écran.

```css
/* Fluid typography */
h1 {
  font-size: clamp(1.5rem, 4vw, 3rem);
  /* Min: 1.5rem, Preferred: 4vw, Max: 3rem */
}

/* Responsive spacing */
.section {
  padding: clamp(2rem, 5vw, 6rem) clamp(1rem, 3vw, 3rem);
}

/* Container queries (newer browsers) */
@container (min-width: 400px) {
  .card {
    display: flex;
  }
}
```

## Débogage et Outils de Développement du Navigateur

### Méthodes de Console : `console.log()` / `console.error()`

Déboguez et surveillez votre code avec la sortie de la console.

```javascript
// Basic logging
console.log('Hello, world!')
console.log('User data:', userData)

// Different log levels
console.info('Information message')
console.warn('Warning message')
console.error('Error message')

// Grouping logs
console.group('User Details')
console.log('Name:', user.name)
console.log('Email:', user.email)
console.groupEnd()
```

### Techniques de Débogage : `debugger` / Points d'Arrêt (Breakpoints)

Mettez en pause l'exécution du code pour inspecter les variables et l'état du programme.

```javascript
function calculateTotal(items) {
  let total = 0
  debugger // Code will pause here when dev tools open

  for (let item of items) {
    total += item.price
    console.log('Current total:', total)
  }
  return total
}

// Error handling
try {
  const result = riskyFunction()
} catch (error) {
  console.error('Error occurred:', error.message)
}
```

### Outils de Développement du Navigateur : Elements / Console / Network

Utilisez les outils du navigateur pour inspecter le HTML, déboguer le JavaScript et surveiller les requêtes réseau.

```javascript
// Inspect elements in console
$0 // Currently selected element in Elements tab
$1 // Previously selected element

// Query elements from console
$('selector') // Same as document.querySelector
$$('selector') // Same as document.querySelectorAll

// Monitor functions
monitor(functionName) // Log when function is called

// Performance timing
console.time('operation')
// ... some code ...
console.timeEnd('operation')

// Common errors and solutions
// ReferenceError: Variable not defined
// console.log(undefinedVariable); //
```

### Types d'Erreur : `TypeError` / `ReferenceError`

Comprenez les erreurs JavaScript courantes et comment les corriger.

## Liens Pertinents

- <router-link to="/html">Feuille de triche HTML</router-link>
- <router-link to="/css">Feuille de triche CSS</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/react">Feuille de triche React</router-link>

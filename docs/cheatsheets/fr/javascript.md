---
title: 'Fiche de Référence JavaScript | LabEx'
description: 'Apprenez la programmation JavaScript avec cette fiche complète. Référence rapide pour la syntaxe JS, ES6+, la manipulation du DOM, async/await, Node.js et le développement web moderne.'
pdfUrl: '/cheatsheets/pdf/javascript-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche JavaScript
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/javascript">Apprenez JavaScript avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la programmation JavaScript grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets sur JavaScript couvrant la syntaxe essentielle, les fonctions, la manipulation du DOM, la programmation asynchrone et les fonctionnalités modernes ES6+. Maîtrisez JavaScript pour un développement web et des flux de travail de programmation efficaces.
</base-disclaimer-content>
</base-disclaimer>

## Variables et Types de Données

### Déclarations de Variables : `let`, `const`, `var`

Déclarez des variables avec différentes portées et mutabilités.

```javascript
// Portée de bloc, mutable
let name = 'John'
let age = 25
age = 26 // Peut être réassigné

// Portée de bloc, immuable
const PI = 3.14159
const user = { name: 'Alice' }
user.age = 30 // Les propriétés d'objet peuvent être modifiées

// Portée de fonction (à éviter dans le JS moderne)
var oldVariable = 'legacy'
```

<BaseQuiz id="javascript-let-const-1" correct="B">
  <template #question>
    Quelle est la principale différence entre `let` et `const` ?
  </template>
  
  <BaseQuizOption value="A">let a une portée de fonction, const a une portée de bloc</BaseQuizOption>
  <BaseQuizOption value="B" correct>let permet la réassignation, const n'autorise pas la réassignation</BaseQuizOption>
  <BaseQuizOption value="C">const ne peut être utilisé que pour les nombres, let peut être utilisé pour n'importe quel type</BaseQuizOption>
  <BaseQuizOption value="D">Il n'y a aucune différence</BaseQuizOption>
  
  <BaseQuizAnswer>
    `let` et `const` ont tous deux une portée de bloc, mais `let` vous permet de réassigner la variable, tandis que `const` empêche la réassignation. Cependant, les propriétés des objets `const` peuvent toujours être modifiées.
  </BaseQuizAnswer>
</BaseQuiz>

### Types Primitifs

Types de données de base en JavaScript.

```javascript
// String
let message = 'Hello World'
let template = `Welcome ${name}`

// Number
let integer = 42
let float = 3.14
let scientific = 2e5 // 200000

// Boolean
let isActive = true
let isComplete = false

// Autres primitifs
let nothing = null
let notDefined = undefined
let unique = Symbol('id')
```

### Vérification de Type : `typeof`, `instanceof`

Déterminer le type des variables et des valeurs.

```javascript
// Vérifier les types primitifs
typeof 42 // 'number'
typeof 'hello' // 'string'
typeof true // 'boolean'
typeof undefined // 'undefined'

// Vérifier les types d'objet
let arr = [1, 2, 3]
typeof arr // 'object'
arr instanceof Array // true

let date = new Date()
date instanceof Date // true
```

### Conversion de Type

Convertir entre différents types de données.

```javascript
// Conversion en String
String(42) // '42'
;(42).toString() // '42'

// Conversion en Number
Number('42') // 42
parseInt('42px') // 42
parseFloat('3.14') // 3.14

// Conversion en Boolean
Boolean(0) // false
Boolean('hello') // true
!!'text' // true (double négation)
```

## Fonctions

### Déclarations de Fonction

Manière traditionnelle de définir des fonctions avec _hoisting_.

```javascript
// Déclaration de fonction (hoistée)
function greet(name) {
  return `Hello, ${name}!`
}

// Fonction avec paramètres par défaut
function multiply(a, b = 1) {
  return a * b
}

// Paramètres rest
function sum(...numbers) {
  return numbers.reduce((a, b) => a + b, 0)
}
```

### Expressions de Fonction et Fonctions Fléchées

Syntaxe de fonction moderne et fonctions anonymes.

```javascript
// Expression de fonction
const add = function (a, b) {
  return a + b
}

// Fonction fléchée (concise)
const subtract = (a, b) => a - b

// Fonction fléchée avec corps de bloc
const processData = (data) => {
  const processed = data.filter((x) => x > 0)
  return processed.map((x) => x * 2)
}
```

<BaseQuiz id="javascript-arrow-1" correct="C">
  <template #question>
    Quelle est une caractéristique clé des fonctions fléchées ?
  </template>
  
  <BaseQuizOption value="A">Elles sont hoistées comme les déclarations de fonction</BaseQuizOption>
  <BaseQuizOption value="B">Elles ont leur propre liaison `this`</BaseQuizOption>
  <BaseQuizOption value="C" correct>Elles héritent de `this` de la portée englobante</BaseQuizOption>
  <BaseQuizOption value="D">Elles ne peuvent pas retourner de valeurs</BaseQuizOption>
  
  <BaseQuizAnswer>
    Les fonctions fléchées n'ont pas leur propre liaison `this`. Au lieu de cela, elles héritent de `this` de la portée lexicale (englobante), ce qui les rend utiles pour les rappels (*callbacks*) et les gestionnaires d'événements où vous souhaitez préserver le contexte.
  </BaseQuizAnswer>
</BaseQuiz>

### Fonctions d'Ordre Supérieur

Fonctions qui prennent ou retournent d'autres fonctions.

```javascript
// Fonction qui retourne une fonction
function createMultiplier(factor) {
  return function (number) {
    return number * factor
  }
}
const double = createMultiplier(2)

// Fonction comme paramètre
function applyOperation(arr, operation) {
  return arr.map(operation)
}
```

## Tableaux et Objets

### Méthodes de Tableau : `map()`, `filter()`, `reduce()`

Transformer et manipuler des tableaux de manière fonctionnelle.

```javascript
const numbers = [1, 2, 3, 4, 5]

// Transformer chaque élément
const doubled = numbers.map((x) => x * 2)
// [2, 4, 6, 8, 10]

// Filtrer les éléments
const evens = numbers.filter((x) => x % 2 === 0)
// [2, 4]

// Réduire à une seule valeur
const sum = numbers.reduce((acc, curr) => acc + curr, 0)
// 15

// Chaîner les méthodes
const result = numbers
  .filter((x) => x > 2)
  .map((x) => x * 3)
  .reduce((a, b) => a + b, 0)
```

<BaseQuiz id="javascript-array-1" correct="A">
  <template #question>
    Que retourne `filter()` ?
  </template>
  
  <BaseQuizOption value="A" correct>Un nouveau tableau avec les éléments qui passent le test</BaseQuizOption>
  <BaseQuizOption value="B">Le premier élément qui passe le test</BaseQuizOption>
  <BaseQuizOption value="C">Une seule valeur réduite à partir du tableau</BaseQuizOption>
  <BaseQuizOption value="D">Le tableau original modifié sur place</BaseQuizOption>
  
  <BaseQuizAnswer>
    La méthode `filter()` crée un nouveau tableau contenant tous les éléments qui passent le test implémenté par la fonction fournie. Elle ne modifie pas le tableau original.
  </BaseQuizAnswer>
</BaseQuiz>

### Utilitaires de Tableau : `find()`, `includes()`, `sort()`

Rechercher, vérifier et organiser les éléments du tableau.

```javascript
const users = [
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 30 },
  { name: 'Charlie', age: 35 },
]

// Trouver un élément
const user = users.find((u) => u.age > 30)

// Vérifier si le tableau inclut une valeur
;[1, 2, 3].includes(2) // true

// Trier le tableau
const sorted = users.sort((a, b) => a.age - b.age)
```

### Création et Manipulation d'Objets

Travailler avec des objets et leurs propriétés.

```javascript
// Littéral d'objet
const person = {
  name: 'John',
  age: 30,
  greet() {
    return `Hi, I'm ${this.name}`
  },
}

// Object.keys, values, entries
Object.keys(person) // ['name', 'age', 'greet']
Object.values(person) // ['John', 30, function]
Object.entries(person) // [['name', 'John'], ...]

// Assignation d'objet
const newPerson = Object.assign({}, person, { age: 31 })
```

### Affectation par Décomposition (_Destructuring_)

Extraire des valeurs des tableaux et des objets.

```javascript
// Décomposition de tableau
const [first, second, ...rest] = [1, 2, 3, 4, 5]
// first: 1, second: 2, rest: [3, 4, 5]

// Décomposition d'objet
const { name, age } = person
const { name: userName, age: userAge = 18 } = person

// Décomposition de paramètre de fonction
function displayUser({ name, age }) {
  console.log(`${name} is ${age} years old`)
}
```

## Manipulation du DOM

### Sélection d'Éléments : `querySelector()`, `getElementById()`

Trouver et sélectionner des éléments HTML.

```javascript
// Sélectionner par ID
const header = document.getElementById('main-header')

// Sélectionner par sélecteur CSS (première correspondance)
const button = document.querySelector('.btn-primary')
const input = document.querySelector('input[type="email"]')

// Sélectionner plusieurs éléments
const allButtons = document.querySelectorAll('.btn')
const listItems = document.querySelectorAll('li')

// Convertir NodeList en Array
const buttonsArray = Array.from(allButtons)
```

<BaseQuiz id="javascript-dom-1" correct="C">
  <template #question>
    Quelle est la différence entre `querySelector()` et `querySelectorAll()` ?
  </template>
  
  <BaseQuizOption value="A">Il n'y a pas de différence</BaseQuizOption>
  <BaseQuizOption value="B">querySelector est plus rapide</BaseQuizOption>
  <BaseQuizOption value="C" correct>querySelector retourne le premier élément correspondant, querySelectorAll retourne tous les éléments correspondants</BaseQuizOption>
  <BaseQuizOption value="D">querySelector fonctionne avec les IDs, querySelectorAll fonctionne avec les classes</BaseQuizOption>
  
  <BaseQuizAnswer>
    `querySelector()` retourne le premier élément qui correspond au sélecteur CSS, tandis que `querySelectorAll()` retourne une `NodeList` contenant tous les éléments correspondants. Utilisez `querySelector()` lorsque vous avez besoin d'un seul élément, et `querySelectorAll()` lorsque vous en avez besoin de plusieurs.
  </BaseQuizAnswer>
</BaseQuiz>

### Modification d'Éléments

Changer le contenu, les attributs et les styles.

```javascript
// Changer le contenu texte
element.textContent = 'Nouveau texte'
element.innerHTML = 'Texte en gras'

// Modifier les attributs
element.setAttribute('data-id', '123')
element.removeAttribute('disabled')
const value = element.getAttribute('data-id')

// Changer les classes
element.classList.add('active')
element.classList.remove('hidden')
element.classList.toggle('highlight')
```

### Création et Insertion d'Éléments

Créer et ajouter dynamiquement des éléments HTML.

```javascript
// Créer un nouvel élément
const div = document.createElement('div')
div.textContent = 'Hello World'
div.className = 'container'

// Insérer des éléments
const parent = document.querySelector('#container')
parent.appendChild(div)
parent.insertBefore(div, parent.firstChild)

// Méthodes d'insertion modernes
parent.prepend(div) // Insérer au début
parent.append(div) // Insérer à la fin
div.before(newElement) // Insérer avant div
div.after(newElement) // Insérer après div
```

### Stylisation des Éléments

Appliquer des styles CSS par programmation.

```javascript
// Modification directe du style
element.style.color = 'red'
element.style.backgroundColor = 'blue'
element.style.fontSize = '16px'

// Définir plusieurs styles
Object.assign(element.style, {
  width: '100px',
  height: '50px',
  border: '1px solid black',
})

// Obtenir les styles calculés
const styles = window.getComputedStyle(element)
const color = styles.getPropertyValue('color')
```

## Gestion des Événements

### Ajout d'Écouteurs d'Événements

Répondre aux interactions utilisateur et aux événements du navigateur.

```javascript
// Écouteur d'événement de base
button.addEventListener('click', function (event) {
  console.log('Bouton cliqué !')
})

// Gestionnaire d'événement de fonction fléchée
button.addEventListener('click', (e) => {
  e.preventDefault() // Empêcher le comportement par défaut
  console.log('Clicqué :', e.target)
})

// Écouteur d'événement avec options
element.addEventListener('scroll', handler, {
  passive: true,
  once: true,
})
```

### Types d'Événements et Propriétés

Événements courants et propriétés de l'objet événement.

```javascript
// Événements de souris
element.addEventListener('click', handleClick)
element.addEventListener('mouseover', handleMouseOver)
element.addEventListener('mouseout', handleMouseOut)

// Événements de clavier
input.addEventListener('keydown', (e) => {
  console.log('Touche pressée :', e.key)
  if (e.key === 'Enter') {
    // Gérer la touche Entrée
  }
})

// Événements de formulaire
form.addEventListener('submit', handleSubmit)
```

### Délégation d'Événements

Gérer les événements sur plusieurs éléments efficacement.

```javascript
// Délégation d'événement sur l'élément parent
document.querySelector('#list').addEventListener('click', (e) => {
  if (e.target.matches('.list-item')) {
    console.log('Élément de liste cliqué :', e.target.textContent)
  }
})

// Suppression des écouteurs d'événements
function handleClick(e) {
  console.log('Clicqué')
}
button.addEventListener('click', handleClick)
button.removeEventListener('click', handleClick)
```

### Événements Personnalisés

Créer et déclencher des événements personnalisés.

```javascript
// Créer un événement personnalisé
const customEvent = new CustomEvent('userLogin', {
  detail: { username: 'john', timestamp: Date.now() },
})

// Déclencher l'événement
element.dispatchEvent(customEvent)

// Écouter l'événement personnalisé
element.addEventListener('userLogin', (e) => {
  console.log('Utilisateur connecté :', e.detail.username)
})
```

## Programmation Asynchrone

### Promesses : `Promise`, `then()`, `catch()`

Travailler avec des opérations asynchrones à l'aide de promesses.

```javascript
// Création d'une promesse
const fetchData = new Promise((resolve, reject) => {
  setTimeout(() => {
    const success = true
    if (success) {
      resolve({ data: 'Hello World' })
    } else {
      reject(new Error('Échec de la récupération'))
    }
  }, 1000)
})

// Utilisation des promesses
fetchData
  .then((result) => console.log(result.data))
  .catch((error) => console.error(error))
  .finally(() => console.log('Terminé'))
```

### Async/Await : `async`, `await`

Syntaxe moderne pour gérer le code asynchrone.

```javascript
// Fonction Async
async function getData() {
  try {
    const response = await fetch('/api/data')
    const data = await response.json()
    return data
  } catch (error) {
    console.error('Erreur :', error)
    throw error
  }
}

// Utilisation de la fonction async
getData()
  .then((data) => console.log(data))
  .catch((error) => console.error(error))
```

### API Fetch : `fetch()`

Effectuer des requêtes HTTP vers des serveurs.

```javascript
// Requête GET
fetch('/api/users')
  .then((response) => response.json())
  .then((users) => console.log(users))

// Requête POST
fetch('/api/users', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ name: 'John', age: 30 }),
})
  .then((response) => response.json())
  .then((data) => console.log(data))
```

### Utilitaires de Promesse : `Promise.all()`, `Promise.race()`

Travailler avec plusieurs promesses simultanément.

```javascript
// Attendre que toutes les promesses soient résolues
const promises = [fetch('/api/users'), fetch('/api/posts')]
Promise.all(promises)
  .then((responses) => Promise.all(responses.map((r) => r.json())))
  .then(([users, posts]) => {
    console.log('Utilisateurs :', users)
    console.log('Publications :', posts)
  })

// Race - la première promesse à se résoudre gagne
Promise.race(promises).then((firstResponse) => console.log('Première réponse'))
```

## Fonctionnalités Modernes ES6+

### Littéraux de Modèle et Opérateur de Propagation (_Spread Operator_)

Interpolation de chaînes et propagation de tableaux/objets.

```javascript
// Littéraux de modèle
const name = 'Alice'
const age = 25
const message = `Hello, ${name}! You are ${age} years old.`

// Chaînes multilignes
const html = `
    <div>
        ${name}
        Age: ${age}
    </div>
`

// Opérateur de propagation
const arr1 = [1, 2, 3]
const arr2 = [4, 5, 6]
const combined = [...arr1, ...arr2] // [1,2,3,4,5,6]

const obj1 = { a: 1, b: 2 }
const obj2 = { ...obj1, c: 3 } // { a: 1, b: 2, c: 3 }
```

### Classes et Modules

Programmation orientée objet et système de modules.

```javascript
// Classes ES6
class Person {
  constructor(name, age) {
    this.name = name
    this.age = age
  }

  greet() {
    return `Hi, I'm ${this.name}`
  }

  static createAnonymous() {
    return new Person('Anonymous', 0)
  }
}

// Héritage
class Student extends Person {
  constructor(name, age, grade) {
    super(name, age)
    this.grade = grade
  }
}

// Exportations/importations de module
export const helper = () => 'helper function'
export default Person

import Person, { helper } from './person.js'
```

## Gestion des Erreurs

### Try/Catch/Finally

Gérer les erreurs synchrones et asynchrones.

```javascript
// Gestion d'erreur de base
try {
  const result = riskyOperation()
  console.log(result)
} catch (error) {
  console.error('Erreur survenue :', error.message)
} finally {
  console.log("Le code de nettoyage s'exécute ici")
}

// Gestion des erreurs asynchrones
async function asyncOperation() {
  try {
    const data = await fetch('/api/data')
    const json = await data.json()
    return json
  } catch (error) {
    console.error('Erreur asynchrone :', error)
    throw error // Relancer si nécessaire
  }
}
```

### Erreurs Personnalisées et Débogage

Créer des types d'erreurs personnalisés et déboguer efficacement.

```javascript
// Classe d'erreur personnalisée
class ValidationError extends Error {
  constructor(message, field) {
    super(message)
    this.name = 'ValidationError'
    this.field = field
  }
}

// Lancer une erreur personnalisée
function validateEmail(email) {
  if (!email.includes('@')) {
    throw new ValidationError("Format d'email invalide", 'email')
  }
}

// Méthodes de débogage de console
console.log('Log de base')
console.warn("Message d'avertissement")
console.error("Message d'erreur")
console.table([{ name: 'John', age: 30 }])
console.time('operation')
// ... du code
console.timeEnd('operation')
```

## Stockage Local et JSON

### API LocalStorage

Stocker des données de manière persistante dans le navigateur.

```javascript
// Stocker des données
localStorage.setItem('username', 'john_doe')
localStorage.setItem(
  'settings',
  JSON.stringify({
    theme: 'dark',
    notifications: true,
  }),
)

// Récupérer des données
const username = localStorage.getItem('username')
const settings = JSON.parse(localStorage.getItem('settings'))

// Supprimer des données
localStorage.removeItem('username')
localStorage.clear() // Supprimer tous les éléments

// Vérifier si la clé existe
if (localStorage.getItem('username') !== null) {
  // La clé existe
}
```

### Opérations JSON

Analyser et sérialiser des données JSON.

```javascript
// Objet JavaScript vers chaîne JSON
const user = { name: 'Alice', age: 25, active: true }
const jsonString = JSON.stringify(user)
// '{"name":"Alice","age":25,"active":true}'

// Chaîne JSON vers objet JavaScript
const jsonData = '{"name":"Bob","age":30}'
const userObj = JSON.parse(jsonData)

// Gérer les erreurs d'analyse JSON
try {
  const data = JSON.parse(invalidJson)
} catch (error) {
  console.error('JSON invalide :', error.message)
}

// JSON avec replacer/reviver personnalisé
const filtered = JSON.stringify(user, ['name', 'age'])
const parsed = JSON.parse(jsonString, (key, value) => {
  return key === 'age' ? value + 1 : value
})
```

## Expressions Régulières

### Création et Test de Motifs

Créer des motifs regex et tester des chaînes.

```javascript
// Littéral Regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Constructeur RegExp
const phoneRegex = new RegExp(r'\d{3}-\d{3}-\d{4}');

// Méthode test
const isValidEmail = emailRegex.test('user@example.com'); // true

// Méthode match
const text = 'Call me at 123-456-7890';
const phoneMatch = text.match(/\d{3}-\d{3}-\d{4}/);
console.log(phoneMatch[0]); // '123-456-7890'

// Recherche globale
const allNumbers = text.match(/\d+/g); // ['123', '456', '7890']
```

### Méthodes de Chaîne avec Regex

Utiliser des regex avec des méthodes de manipulation de chaînes.

```javascript
// Remplacer avec regex
const text = 'Hello World 123'
const cleaned = text.replace(/\d+/g, '') // 'Hello World '

// Diviser avec regex
const parts = 'apple,banana;orange:grape'.split(/[,:;]/)
// ['apple', 'banana', 'orange', 'grape']

// Méthode search
const position = text.search(/\d+/) // 12 (position du premier chiffre)

// Motifs courants
const patterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  phone: /^\d{3}-\d{3}-\d{4}$/,
  url: /^https?:\/\/.+/,
  digits: /\d+/g,
  whitespace: /\s+/g,
}
```

## Configuration et Environnement JavaScript

### Console du Navigateur

Environnement JavaScript intégré dans les navigateurs web.

```javascript
// Ouvrir les outils de développement du navigateur (F12)
// Aller à l'onglet Console
console.log('Hello JavaScript!')

// Tester le code directement
let x = 5
let y = 10
console.log(x + y) // 15

// Inclure des scripts dans HTML
```

### Environnement Node.js

Runtime JavaScript pour le développement côté serveur.

```bash
# Installer Node.js depuis nodejs.org
# Vérifier l'installation
node --version
npm --version

# Exécuter un fichier JavaScript
node script.js

# Initialiser un projet npm
npm init -y

# Installer des paquets
npm install lodash
npm install --save-dev jest
```

### Outils de Développement Modernes

Outils essentiels pour le développement JavaScript.

```json
// Script package.json
{
  "scripts": {
    "start": "node index.js",
    "test": "jest",
    "build": "webpack"
  }
}
```

```bash
# Modules ES6 dans le navigateur
# Babel pour la prise en charge des anciens navigateurs
npm install --save-dev @babel/core @babel/preset-env
```

## Bonnes Pratiques et Performance

### Optimisation des Performances

Techniques pour améliorer les performances JavaScript.

```javascript
// Debouncing pour les événements fréquents
function debounce(func, delay) {
  let timeoutId
  return function (...args) {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func.apply(this, args), delay)
  }
}

// Utiliser la fonction debounced
const debouncedSearch = debounce(searchFunction, 300)
input.addEventListener('input', debouncedSearch)

// Requêtes DOM efficaces
const elements = document.querySelectorAll('.item')
// Mettre en cache la longueur pour éviter le recalcul
for (let i = 0, len = elements.length; i < len; i++) {
  // Traiter elements[i]
}
```

### Organisation du Code et Normes

Structurer le code pour la maintenabilité et la lisibilité.

```javascript
// Utiliser le mode strict
'use strict'

// Conventions de nommage cohérentes
const userName = 'john' // camelCase pour les variables
const API_URL = 'https://api.example.com' // CAPS pour les constantes

// Documentation de fonction
/**
 * Calcule l'aire d'un rectangle
 * @param {number} width - La largeur du rectangle
 * @param {number} height - La hauteur du rectangle
 * @returns {number} L'aire du rectangle
 */
function calculateArea(width, height) {
  return width * height
}

// Utiliser const par défaut, let lorsque la réassignation est nécessaire
const config = { theme: 'dark' }
let counter = 0
```

## Tester le Code JavaScript

### Tests Unitaires avec Jest

Écrire et exécuter des tests pour les fonctions JavaScript.

```javascript
// Installer Jest : npm install --save-dev jest

// math.js
export function add(a, b) {
  return a + b
}

export function multiply(a, b) {
  return a * b
}

// math.test.js
import { add, multiply } from './math.js'

test('adds 1 + 2 to equal 3', () => {
  expect(add(1, 2)).toBe(3)
})

test('multiplies 3 * 4 to equal 12', () => {
  expect(multiply(3, 4)).toBe(12)
})

// Exécuter les tests : npm test
```

### Tests et Débogage dans le Navigateur

Déboguer JavaScript dans les outils de développement du navigateur.

```javascript
// Définir des points d'arrêt
debugger // Met en pause l'exécution dans les outils de développement

// Méthodes de console pour le débogage
console.log('Valeur de la variable :', variable)
console.assert(x > 0, 'x devrait être positif')
console.trace("Pile d'appels de fonction")

// Chronométrage des performances
performance.mark('start')
// ... code à mesurer
performance.mark('end')
performance.measure('operation', 'start', 'end')

// Consulter les entrées de performance
const measurements = performance.getEntriesByType('measure')
```

## Liens Pertinents

- <router-link to="/html">Feuille de triche HTML</router-link>
- <router-link to="/css">Feuille de triche CSS</router-link>
- <router-link to="/react">Feuille de triche React</router-link>
- <router-link to="/web-development">Feuille de triche Développement Web</router-link>

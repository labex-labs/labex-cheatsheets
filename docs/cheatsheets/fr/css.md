---
title: 'Fiche de Référence CSS'
description: 'Apprenez le CSS avec notre fiche complète couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/css-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche CSS
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/css">Apprenez le CSS avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez le style web CSS grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours CSS complets couvrant les propriétés essentielles, les sélecteurs, les techniques de mise en page, la conception réactive et les fonctionnalités modernes. Maîtrisez le style web efficace et la conception de mise en page pour les flux de travail de développement web modernes.
</base-disclaimer-content>
</base-disclaimer>

## Syntaxe CSS et Sélecteurs

### Syntaxe de Base

Le CSS se compose de sélecteurs et de déclarations. Le sélecteur cible les éléments HTML, et les déclarations définissent les valeurs des propriétés.

```css
/* Syntaxe de base */
selector {
  property: value;
  property: value;
}

/* Exemple */
p {
  color: red;
  font-size: 16px;
}
```

### Sélecteurs d'Élément

Ciblez les éléments HTML par leur nom de balise.

```css
/* Sélectionner tous les paragraphes */
p {
  color: blue;
}

/* Sélectionner tous les titres */
h1 {
  font-size: 2em;
}

/* Sélectionner tous les liens */
a {
  text-decoration: none;
}
```

### Sélecteurs de Classe

Ciblez les éléments avec des attributs de classe spécifiques.

```css
/* Sélectionner les éléments avec class="highlight" */
.highlight {
  background-color: yellow;
}

/* Sélectionner les paragraphes avec class="intro" */
p.intro {
  font-weight: bold;
}

/* Classes multiples */
.large.bold {
  font-size: 20px;
  font-weight: bold;
}
```

### Sélecteurs d'ID

Ciblez les éléments avec des attributs d'ID spécifiques.

```css
/* Sélectionner l'élément avec id="header" */
#header {
  background-color: #333;
}

/* Les IDs doivent être uniques par page */
#navigation {
  position: fixed;
}
```

### Sélecteurs d'Attribut

Ciblez les éléments possédant certains attributs en utilisant des sélecteurs d'attribut.

```css
/* Éléments avec l'attribut title */
[title] {
  cursor: help;
}

/* Liens vers des sites externes */
a[href^='http'] {
  color: red;
}

/* Éléments d'entrée de type text */
input[type='text'] {
  border: 1px solid #ccc;
}
```

### Pseudo-classes

Les pseudo-classes appliquent du CSS en fonction des changements d'état et des interactions utilisateur.

```css
/* États des liens */
a:hover {
  color: red;
}
a:visited {
  color: purple;
}
a:active {
  color: orange;
}

/* États des formulaires */
input:focus {
  border-color: blue;
}
input:invalid {
  border-color: red;
}

/* Pseudo-classes structurelles */
li:first-child {
  font-weight: bold;
}
li:nth-child(odd) {
  background-color: #f0f0f0;
}
```

## Modèle de Boîte et Mise en Page

### Contenu : `width` / `height`

La zone de contenu réelle de l'élément.

```css
/* Définir les dimensions */
div {
  width: 300px;
  height: 200px;
}

/* Dimensionnement réactif */
.container {
  width: 100%;
  max-width: 1200px;
}

/* Contraintes min/max */
.box {
  min-height: 100px;
  max-width: 500px;
}
```

### Rembourrage : `padding`

Espace entre le contenu et la bordure, à l'intérieur de l'élément.

```css
/* Tous les côtés */
div {
  padding: 20px;
}

/* Côtés individuels */
div {
  padding-top: 10px;
  padding-right: 15px;
}

/* Raccourci : haut droite bas gauche */
div {
  padding: 10px 15px 20px 5px;
}
```

### Bordure : `border`

Les bordures fournissent un cadre pour les éléments avec une taille, un style et une couleur personnalisables.

```css
/* Raccourci de bordure */
div {
  border: 2px solid #333;
}

/* Propriétés individuelles */
div {
  border-width: 1px;
  border-style: dashed;
  border-color: red;
}

/* Côtés individuels */
div {
  border-bottom: 3px solid blue;
}
```

### Marge : `margin`

Espace à l'extérieur de la bordure, entre les éléments.

```css
/* Tous les côtés */
div {
  margin: 20px;
}

/* Centrer horizontalement */
div {
  margin: 0 auto;
}

/* Côtés individuels */
div {
  margin-top: 30px;
  margin-bottom: 10px;
}

/* Marges négatives */
div {
  margin-left: -20px;
}
```

## Texte et Typographie

### Propriétés de Police

Contrôlez la famille de police, la taille, l'épaisseur et le style.

```css
/* Famille de police */
body {
  font-family: Arial, sans-serif;
}

/* Google Fonts */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
body {
  font-family: 'Roboto', sans-serif;
}

/* Taille de police */
h1 {
  font-size: 2rem;
}
p {
  font-size: 16px;
}

/* Épaisseur de police */
h2 {
  font-weight: bold;
}
span {
  font-weight: 300;
}
```

### Alignement du Texte

Contrôlez le positionnement et l'espacement du texte.

```css
/* Alignement horizontal */
h1 {
  text-align: center;
}
p {
  text-align: justify;
}

/* Hauteur de ligne */
p {
  line-height: 1.6;
}

/* Espacement des lettres et des mots */
h1 {
  letter-spacing: 2px;
}
p {
  word-spacing: 4px;
}
```

### Style de Texte

Ajoutez des décorations et des transformations au texte.

```css
/* Décoration de texte */
a {
  text-decoration: underline;
}
.strike {
  text-decoration: line-through;
}

/* Transformation de texte */
.uppercase {
  text-transform: uppercase;
}
.capitalize {
  text-transform: capitalize;
}

/* Ombre de texte */
h1 {
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}
```

### Couleurs

Le CSS offre plusieurs façons de spécifier les couleurs pour divers besoins de style.

```css
/* Formats de couleur */
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

/* Couleurs HSL */
header {
  background-color: hsl(200, 100%, 50%);
}

/* Variables CSS pour les couleurs */
:root {
  --primary-color: #3498db;
}
.button {
  background-color: var(--primary-color);
}
```

## Mise en Page Flexbox

### Propriétés du Conteneur Flex

Propriétés appliquées au conteneur parent.

```css
/* Activer flexbox */
.container {
  display: flex;
}

/* Direction flex */
.container {
  flex-direction: row; /* défaut */
  flex-direction: column;
  flex-direction: row-reverse;
}

/* Justify content (axe principal) */
.container {
  justify-content: flex-start; /* défaut */
  justify-content: center;
  justify-content: space-between;
  justify-content: space-around;
}

/* Align items (axe transversal) */
.container {
  align-items: stretch; /* défaut */
  align-items: center;
  align-items: flex-start;
}
```

### Propriétés des Éléments Flex

Propriétés appliquées aux éléments enfants.

```css
/* Flex grow/shrink */
.item {
  flex-grow: 1; /* grandir pour remplir l'espace */
  flex-shrink: 1; /* rétrécir si nécessaire */
  flex-basis: auto; /* taille initiale */
}

/* Raccourci */
.item {
  flex: 1; /* flex: 1 1 0% */
  flex: 0 0 200px; /* largeur fixe */
}

/* Alignement individuel */
.item {
  align-self: center;
  align-self: flex-end;
}

/* Ordre */
.item {
  order: 2; /* changer l'ordre visuel */
}
```

## Mise en Page CSS Grid

### Conteneur Grid

Définir la structure et les propriétés de la grille.

```css
/* Activer la grille */
.grid-container {
  display: grid;
}

/* Définir les colonnes et les lignes */
.grid-container {
  grid-template-columns: 1fr 2fr 1fr;
  grid-template-rows: 100px auto 50px;
}

/* Espacement de la grille */
.grid-container {
  gap: 20px;
  column-gap: 30px;
  row-gap: 10px;
}

/* Zones de grille nommées */
.grid-container {
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}
```

### Éléments Grid

Positionner et dimensionner les éléments de la grille.

```css
/* Positionnement de la grille */
.grid-item {
  grid-column: 1 / 3; /* couvrir les colonnes 1-2 */
  grid-row: 2 / 4; /* couvrir les lignes 2-3 */
}

/* Raccourci */
.grid-item {
  grid-area: 2 / 1 / 4 / 3; /* row-start / col-start / row-end / col-end */
}

/* Zones nommées */
.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}

/* Placement automatique */
.grid-item {
  grid-column: span 2; /* couvrir 2 colonnes */
  grid-row: span 3; /* couvrir 3 lignes */
}
```

## Positionnement

### Propriété Position

Contrôler le comportement de positionnement des éléments.

```css
/* Statique (défaut) */
.element {
  position: static;
}

/* Positionnement relatif */
.element {
  position: relative;
  top: 20px;
  left: 10px;
}

/* Positionnement absolu */
.element {
  position: absolute;
  top: 0;
  right: 0;
}

/* Positionnement fixe */
.navbar {
  position: fixed;
  top: 0;
  width: 100%;
}

/* Positionnement collant (sticky) */
.sidebar {
  position: sticky;
  top: 20px;
}
```

### Z-Index et Empilement

Contrôlez l'ordre dans lequel les éléments se superposent en utilisant z-index et le contexte d'empilement.

```css
/* Ordre d'empilement */
.modal {
  position: fixed;
  z-index: 1000;
}
.overlay {
  position: absolute;
  z-index: 999;
}

/* Création d'un contexte d'empilement */
.container {
  position: relative;
  z-index: 0;
}

/* Valeurs z-index courantes */
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

## Conception Réactive

### Media Queries

Appliquer des styles basés sur les caractéristiques de l'appareil.

```css
/* Approche mobile d'abord */
.container {
  width: 100%;
}

/* Styles pour tablette */
@media (min-width: 768px) {
  .container {
    width: 750px;
  }
}

/* Styles pour ordinateur de bureau */
@media (min-width: 1024px) {
  .container {
    width: 960px;
  }
}

/* Styles d'impression */
@media print {
  body {
    font-size: 12pt;
  }
  .no-print {
    display: none;
  }
}

/* Orientation */
@media (orientation: landscape) {
  .sidebar {
    display: block;
  }
}
```

### Unités Réactives

Utilisez des unités relatives pour des mises en page flexibles.

```css
/* Unités de vue */
.hero {
  height: 100vh;
} /* hauteur complète de la vue */
.sidebar {
  width: 25vw;
} /* 25% de la largeur de la vue */

/* Unités relatives */
p {
  font-size: 1.2em;
} /* 1.2x la taille de police du parent */
h1 {
  font-size: 2rem;
} /* 2x la taille de police racine */

/* Unités en pourcentage */
.container {
  width: 80%;
}
.column {
  width: 50%;
}

/* Grid réactif */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

/* Flexbox réactif */
.flex-container {
  display: flex;
  flex-wrap: wrap;
}
```

## Animations et Transitions

### Transitions CSS

Changements fluides entre les valeurs des propriétés.

```css
/* Transition de base */
.button {
  background-color: blue;
  transition: background-color 0.3s ease;
}
.button:hover {
  background-color: red;
}

/* Propriétés multiples */
.card {
  transform: scale(1);
  opacity: 1;
  transition: all 0.3s ease-in-out;
}
.card:hover {
  transform: scale(1.05);
  opacity: 0.8;
}

/* Transitions individuelles */
.element {
  transition-property: width, height;
  transition-duration: 0.5s, 1s;
  transition-timing-function: ease, linear;
}
```

### Animations CSS

Créez des animations complexes avec des keyframes.

```css
/* Définir les keyframes */
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

/* Appliquer les animations */
.slide-in {
  animation: slideIn 0.5s ease-out;
}
.pulse {
  animation: pulse 2s infinite;
}

/* Raccourci d'animation */
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

## Variables CSS et Fonctions

### Variables CSS

Définissez et utilisez des propriétés personnalisées pour un thème cohérent.

```css
/* Définir les variables */
:root {
  --primary-color: #3498db;
  --secondary-color: #2ecc71;
  --font-size-large: 24px;
  --border-radius: 8px;
}

/* Utiliser les variables */
.button {
  background-color: var(--primary-color);
  border-radius: var(--border-radius);
}

/* Valeurs de secours */
.text {
  color: var(--text-color, #333);
}

/* Variables locales */
.card {
  --card-padding: 20px;
  padding: var(--card-padding);
}
```

### Fonctions CSS

Le CSS dispose d'une gamme de fonctions intégrées pour les calculs et les valeurs dynamiques.

```css
/* Fonction Calc */
.container {
  width: calc(100% - 40px);
  height: calc(100vh - 60px);
}

/* Fonctions Min/Max */
.responsive {
  width: min(90%, 1200px);
  font-size: max(16px, 1.2vw);
  height: clamp(200px, 50vh, 400px);
}

/* Fonctions de couleur */
.element {
  background-color: hsl(200, 50%, 50%);
  color: rgb(255, 87, 51);
}

/* Fonctions de transformation */
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

## Bonnes Pratiques et Organisation

### Organisation CSS

Structurez votre CSS pour la maintenabilité.

```css
/* Utiliser des noms de classes significatifs */
.hero-section {
}
.primary-button {
}
.navigation-menu {
}

/* Méthodologie BEM */
.block {
}
.block__element {
}
.block--modifier {
}

/* Exemple */
.card {
}
.card__header {
}
.card__body {
}
.card--featured {
}

/* Grouper les styles connexes */
/* ===== MISE EN PAGE ===== */
.container {
}
.grid {
}

/* ===== COMPOSANTS ===== */
.button {
}
.card {
}
```

### Performance et Optimisation

Écrire du CSS efficace pour de meilleures performances.

```css
/* Éviter l'imbrication profonde */
/* Mauvais */
.header .nav ul li a {
}

/* Bon */
.nav-link {
}

/* Utiliser des sélecteurs efficaces */
/* Mauvais */
body div.container > p {
}

/* Bon */
.content-text {
}

/* Minimiser les repeints */
/* Utiliser transform au lieu de changer position */
.element {
  transform: translateX(100px);
  /* au lieu de left: 100px; */
}

/* Grouper les préfixes vendeur */
.element {
  -webkit-border-radius: 5px;
  -moz-border-radius: 5px;
  border-radius: 5px;
}
```

## Débogage CSS

### Outils de Développement du Navigateur

Inspecter et modifier le CSS en temps réel.

```css
/* Étapes de débogage courantes */
/* 1. Clic droit → Inspecter l'élément */
/* 2. Vérifier les styles Calculés */
/* 3. Rechercher les propriétés remplacées */
/* 4. Tester les changements en temps réel */
/* 5. Copier le CSS modifié dans votre fichier */
```

### Problèmes CSS Courants

Dépanner les problèmes fréquemment rencontrés.

```css
/* Problèmes de modèle de boîte */
* {
  box-sizing: border-box;
}

/* Effacer les flottants */
.clearfix::after {
  content: '';
  display: table;
  clear: both;
}

/* Problèmes de z-index */
/* Assurez-vous que les éléments sont positionnés pour que z-index fonctionne */
.element {
  position: relative;
  z-index: 1;
}
```

### Validation CSS

Assurez-vous que votre CSS suit les normes et les bonnes pratiques.

```css
/* Utiliser des validateurs CSS */
/* Validateur CSS W3C */
/* Outils de compatibilité des navigateurs */

/* Commenter votre code */
/* ===== STYLES D'EN-TÊTE ===== */
.header {
}

/* TODO: Ajouter des styles mobiles */
/* FIXME: Corriger la compatibilité IE */

/* Utiliser un formatage cohérent */
.element {
  property: value;
  property: value;
}
```

## Frameworks et Outils CSS

### Préprocesseurs CSS

Étendez le CSS avec des variables, l'imbrication et des fonctions.

```scss
/* Exemple SCSS/Sass */
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
/* Exemple Less */
@primary-color: #3498db;

.button {
  background-color: @primary-color;

  &:hover {
    background-color: lighten(@primary-color, 10%);
  }
}
```

### CSS-in-JS et Outils Modernes

Approches modernes pour le style dans les applications web.

```css
/* Plugins PostCSS */
/* Autoprefixer - ajoute les préfixes vendeur */
/* PurgeCSS - supprime le CSS inutilisé */

/* Modules CSS */
.button {
  composes: base-button;
  background-color: blue;
}
```

```javascript
/* CSS utilitaire d'abord (Tailwind) */
;<div class="flex items-center justify-center p-4 bg-blue-500">
  <span class="text-white font-bold">Button</span>
</div>

/* CSS-in-JS (Styled Components) */
const Button = styled.button`
  background: ${(props) => (props.primary ? 'blue' : 'white')};
  padding: 1rem 2rem;
`
```

## Liens Pertinents

- <router-link to="/html">Feuille de triche HTML</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/react">Feuille de triche React</router-link>
- <router-link to="/web-development">Feuille de triche Développement Web</router-link>

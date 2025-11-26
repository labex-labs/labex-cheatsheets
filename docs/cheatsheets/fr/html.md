---
title: 'Fiche de Référence HTML'
description: 'Apprenez le HTML avec notre fiche complète couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/html-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche HTML
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/html">Apprenez le HTML avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la structure web HTML grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours HTML complets couvrant les éléments essentiels, le balisage sémantique, les formulaires, l'intégration multimédia et les fonctionnalités modernes de HTML5. Maîtrisez la structure de page web efficace et l'organisation du contenu pour les flux de travail de développement web modernes.
</base-disclaimer-content>
</base-disclaimer>

## Structure du Document HTML

### Document HTML de Base : `<!DOCTYPE html>`

Chaque document HTML commence par une déclaration de type de document et suit une structure standard.

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Page Title</title>
  </head>
  <body>
    <!-- Le contenu de la page va ici -->
  </body>
</html>
```

### Éléments de Tête : `<head>`

La section head contient les métadonnées sur le document.

```html
<!-- Encodage des caractères -->
<meta charset="UTF-8" />
<!-- Viewport pour la conception réactive -->
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<!-- Description de la page -->
<meta name="description" content="Page description" />
<!-- Lien vers le CSS -->
<link rel="stylesheet" href="styles.css" />
<!-- Lien vers le favicon -->
<link rel="icon" href="favicon.ico" />
```

### Commentaires HTML : `<!-- -->`

Les commentaires ne sont pas affichés mais aident à documenter votre code.

```html
<!-- Ceci est un commentaire -->
<!-- 
  Commentaire multi-lignes
  pour des explications plus longues
-->
```

### Anatomie des Éléments HTML

Les éléments HTML se composent de balises d'ouverture, de contenu et de balises de fermeture.

```html
<!-- Élément avec contenu -->
<p>Ceci est un paragraphe</p>
<!-- Éléments auto-fermants -->
<img src="image.jpg" alt="Description" />
<br />
<hr />
<!-- Éléments avec attributs -->
<a href="https://example.com" target="_blank">Lien</a>
<!-- Éléments imbriqués -->
<div>
  <p>Paragraphe imbriqué</p>
</div>
```

## Éléments de Contenu Textuel

### Titres : `h1` à `h6`

Définissent la hiérarchie et l'importance des sections de contenu.

```html
<h1>Titre Principal</h1>
<h2>Titre de Section</h2>
<h3>Titre de Sous-section</h3>
<h4>Titre de Sous-sous-section</h4>
<h5>Titre Mineur</h5>
<h6>Titre le Plus Petit</h6>
```

### Paragraphes : `p`

L'élément le plus courant pour les blocs de contenu textuel.

```html
<p>
  Ceci est un paragraphe de texte. Il peut contenir plusieurs phrases et
  s'enroulera automatiquement.
</p>
<p>
  Ceci est un autre paragraphe. Les paragraphes sont séparés par un espace de
  marge.
</p>
```

### Formatage de Texte : `<strong>`, `<em>`, `<b>`, `<i>`

Éléments pour mettre en évidence et styliser le texte en ligne.

```html
<strong>Importance forte (gras)</strong>
<em>Emphase (italique)</em>
<b>Texte en gras</b>
<i>Texte en italique</i>
<u>Texte souligné</u>
<mark>Texte surligné</mark>
<small>Petit texte</small>
<del>Texte supprimé</del>
<ins>Texte inséré</ins>
```

### Sauts de Ligne et Espacement : `<br>`, `<hr>`, `<pre>`

Contrôlent le flux de texte et l'espacement dans le contenu.

```html
<!-- Saut de ligne -->
Ligne 1<br />
Ligne 2
<!-- Règle horizontale -->
<hr />
<!-- Texte préformaté -->
<pre>
  Texte avec
    espacement    préservé
      et sauts de ligne
</pre>
<!-- Formatage de code -->
<code>console.log('Hello');</code>
```

## Listes et Navigation

### Listes Non Ordonnées : `<ul>`

Crée des listes à puces pour des éléments non séquentiels.

```html
<ul>
  <li>Premier élément</li>
  <li>Deuxième élément</li>
  <li>Troisième élément</li>
</ul>
<!-- Listes imbriquées -->
<ul>
  <li>
    Élément principal
    <ul>
      <li>Sous-élément 1</li>
      <li>Sous-élément 2</li>
    </ul>
  </li>
</ul>
```

### Listes Ordonnées : `<ol>`

Crée des listes numérotées pour des éléments séquentiels.

```html
<ol>
  <li>Première étape</li>
  <li>Deuxième étape</li>
  <li>Troisième étape</li>
</ol>
<!-- Numérotation personnalisée -->
<ol start="5">
  <li>Élément 5</li>
  <li>Élément 6</li>
</ol>
<!-- Types de numérotation différents -->
<ol type="A">
  <li>Élément A</li>
  <li>Élément B</li>
</ol>
```

### Listes de Description : `<dl>`

Crée des listes de termes et de leurs descriptions.

```html
<dl>
  <dt>HTML</dt>
  <dd>HyperText Markup Language</dd>

  <dt>CSS</dt>
  <dd>Cascading Style Sheets</dd>

  <dt>JavaScript</dt>
  <dd>Langage de programmation pour le web</dd>
</dl>
```

### Liens et Navigation : `<a>`

Crée des hyperliens et des structures de navigation.

```html
<!-- Lien de base -->
<a href="https://example.com">Visiter Example</a>
<!-- Lien dans un nouvel onglet -->
<a href="https://example.com" target="_blank">Nouvel Onglet</a>
<!-- Lien par e-mail -->
<a href="mailto:email@example.com">Envoyer un E-mail</a>
<!-- Lien téléphonique -->
<a href="tel:+1234567890">Nous Appeler</a>
<!-- Ancres de page internes -->
<a href="#section1">Aller à la Section 1</a>
<h2 id="section1">Section 1</h2>
```

## Formulaires et Éléments d'Entrée

### Structure de Formulaire de Base : `<form>`

La base de la collecte d'entrées utilisateur.

```html
<form action="/submit" method="POST">
  <label for="username">Nom d'utilisateur :</label>
  <input type="text" id="username" name="username" required />

  <label for="email">E-mail :</label>
  <input type="email" id="email" name="email" required />

  <input type="submit" value="Soumettre" />
</form>
```

### Types d'Entrée : `<input>`

Divers types d'entrée pour différents besoins de collecte de données.

```html
<!-- Entrées texte -->
<input type="text" placeholder="Entrez du texte" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="Mot de passe" />
<input type="url" placeholder="https://example.com" />
<input type="tel" placeholder="+1234567890" />
<!-- Entrées numériques -->
<input type="number" min="1" max="100" step="1" />
<input type="range" min="0" max="100" value="50" />
<!-- Date et heure -->
<input type="date" />
<input type="time" />
<input type="datetime-local" />
```

### Contrôles de Formulaire : `<checkbox>`, `<radio>`, `<select>`, `<textarea>`

Éléments de formulaire supplémentaires pour l'interaction utilisateur.

```html
<!-- Cases à cocher -->
<input type="checkbox" id="agree" name="agree" />
<label for="agree">J'accepte les conditions</label>
<!-- Boutons radio -->
<input type="radio" id="option1" name="choice" value="1" />
<label for="option1">Option 1</label>
<input type="radio" id="option2" name="choice" value="2" />
<label for="option2">Option 2</label>
<!-- Menu déroulant -->
<select name="country">
  <option value="us">États-Unis</option>
  <option value="uk">Royaume-Uni</option>
  <option value="ca">Canada</option>
</select>
<!-- Zone de texte -->
<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="Entrez votre message"
></textarea>
```

### Validation de Formulaire : `required`, `min`, `max`, `pattern`

Attributs de validation de formulaire HTML intégrés.

```html
<input type="text" required />
<input type="email" required />
<input type="text" minlength="3" maxlength="20" />
<input type="number" min="1" max="100" />
<input type="text" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}" />
```

## Éléments Multimédias

### Images : `<img>`, `<picture>`

Afficher des images avec divers attributs et options.

```html
<!-- Image de base -->
<img src="image.jpg" alt="Description" />
<!-- Image réactive -->
<img src="image.jpg" alt="Description" width="100%" height="auto" />
<!-- Image avec taille -->
<img src="image.jpg" alt="Description" width="300" height="200" />
<!-- Élément picture pour les images réactives -->
<picture>
  <source media="(min-width: 800px)" srcset="large.jpg" />
  <source media="(min-width: 400px)" srcset="medium.jpg" />
  <img src="small.jpg" alt="Description" />
</picture>
```

### Audio : `<audio>`

Intégrer du contenu audio avec des commandes de lecture.

```html
<!-- Audio de base -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
  <source src="audio.ogg" type="audio/ogg" />
  Votre navigateur ne prend pas en charge l'audio.
</audio>
<!-- Audio avec lecture automatique -->
<audio controls autoplay loop>
  <source src="background.mp3" type="audio/mpeg" />
</audio>
```

### Vidéo : `<video>`

Intégrer du contenu vidéo avec des options complètes.

```html
<!-- Vidéo de base -->
<video controls width="400" height="300">
  <source src="video.mp4" type="video/mp4" />
  <source src="video.webm" type="video/webm" />
  Votre navigateur ne prend pas en charge la vidéo.
</video>
<!-- Vidéo avec affiche et attributs -->
<video controls poster="thumbnail.jpg" width="100%" height="auto">
  <source src="video.mp4" type="video/mp4" />
  <track src="captions.vtt" kind="captions" srclang="en" label="English" />
</video>
```

### Contenu Intégré : `<iframe>`

Intégrer du contenu et des applications externes.

```html
<!-- iFrame pour contenu externe -->
<iframe src="https://example.com" width="100%" height="400"></iframe>
<!-- Intégration vidéo YouTube -->
<iframe
  width="560"
  height="315"
  src="https://www.youtube.com/embed/VIDEO_ID"
></iframe>
<!-- Intégration Google Maps -->
<iframe src="https://maps.google.com/..."></iframe>
```

## Tableaux

### Structure de Tableau de Base : `<table>`

Créer des affichages de données structurées avec des tableaux.

```html
<table>
  <thead>
    <tr>
      <th>Nom</th>
      <th>Âge</th>
      <th>Ville</th>
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
      <td>Londres</td>
    </tr>
  </tbody>
</table>
```

### Fonctionnalités Avancées de Tableau : `rowspan`, `colspan`, `<caption>`

Fonctionnalité de tableau améliorée avec fusion et regroupement.

```html
<table>
  <caption>
    Rapport de Ventes
  </caption>
  <colgroup>
    <col style="width: 50%" />
    <col style="width: 25%" />
    <col style="width: 25%" />
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">Produit</th>
      <th colspan="2">Ventes</th>
    </tr>
    <tr>
      <th>T1</th>
      <th>T2</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Produit A</td>
      <td>1000 $</td>
      <td>1200 $</td>
    </tr>
  </tbody>
</table>
```

## Éléments HTML5 Sémantiques

### Éléments de Structure de Page : `<header>`, `<nav>`, `<main>`, `<footer>`

Définissent les principales sections de la mise en page de votre page.

```html
<!-- En-tête de page -->
<header>
  <nav>
    <ul>
      <li><a href="#home">Accueil</a></li>
      <li><a href="#about">À Propos</a></li>
    </ul>
  </nav>
</header>
<!-- Contenu principal -->
<main>
  <article>
    <h1>Titre de l'Article</h1>
    <p>Contenu de l'article...</p>
  </article>
</main>
<!-- Barre latérale -->
<aside>
  <h2>Liens Connexes</h2>
  <ul>
    <li><a href="#">Lien 1</a></li>
  </ul>
</aside>
<!-- Pied de page de la page -->
<footer>
  <p>© 2024 Nom de l'Entreprise</p>
</footer>
```

### Éléments de Regroupement de Contenu : `<section>`, `<article>`, `<div>`, `<figure>`

Organisent et regroupent les sections de contenu liées.

```html
<!-- Section générique -->
<section>
  <h2>Titre de Section</h2>
  <p>Contenu de la section...</p>
</section>
<!-- Article autonome -->
<article>
  <header>
    <h1>Titre de l'Article</h1>
    <time datetime="2024-01-01">1er Janvier 2024</time>
  </header>
  <p>Contenu de l'article...</p>
</article>
<!-- Conteneur générique -->
<div class="container">
  <p>Regroupement de contenu générique</p>
</div>
<!-- Figure avec légende -->
<figure>
  <img src="chart.jpg" alt="Graphique des ventes" />
  <figcaption>Données de ventes pour le T1 2024</figcaption>
</figure>
```

## Attributs HTML

### Attributs Globaux : `id`, `class`, `title`, `data-*`

Attributs pouvant être utilisés sur n'importe quel élément HTML.

```html
<!-- ID pour identification unique -->
<div id="unique-element">Contenu</div>
<!-- Classe pour le style et la sélection -->
<p class="highlight important">Texte</p>
<!-- Titre pour les info-bulles -->
<span title="Ceci est une info-bulle">Survolez-moi</span>
<!-- Attributs de données -->
<div data-user-id="123" data-role="admin">Utilisateur</div>
<!-- Langue -->
<p lang="es">Hola mundo</p>
<!-- Direction du contenu -->
<p dir="rtl">Texte de droite à gauche</p>
<!-- Éléments masqués -->
<div hidden>Ceci ne sera pas affiché</div>
```

### Attributs d'Accessibilité : `alt`, `aria-*`, `tabindex`, `role`

Attributs qui améliorent l'accessibilité et l'expérience utilisateur.

```html
<!-- Texte alternatif pour les images -->
<img src="photo.jpg" alt="Un coucher de soleil sur les montagnes" />
<!-- Étiquettes ARIA -->
<button aria-label="Fermer la boîte de dialogue">×</button>
<div aria-hidden="true">Contenu décoratif</div>
<!-- Accessibilité du formulaire -->
<label for="email">Adresse E-mail :</label>
<input type="email" id="email" aria-describedby="email-help" />
<small id="email-help">Nous ne partagerons jamais votre e-mail</small>
<!-- Index de tabulation -->
<div tabindex="0">Div focalisable</div>
<div tabindex="-1">Div focalisable par programme</div>
<!-- Attribut de rôle -->
<div role="button" tabindex="0">Bouton personnalisé</div>
```

## Fonctionnalités Modernes HTML5

### Nouvelles Fonctionnalités d'Entrée : `color`, `search`, `file`, `datalist`

HTML5 a introduit de nouveaux types d'entrée et des attributs.

```html
<!-- Nouveaux types d'entrée -->
<input type="color" value="#ff0000" />
<input type="search" placeholder="Rechercher..." />
<input type="file" accept="image/*" multiple />
<!-- Datalist pour l'autocomplétion -->
<input list="browsers" name="browser" />
<datalist id="browsers">
  <option value="Chrome"></option>
  <option value="Firefox"></option>
  <option value="Safari"></option>
</datalist>
<!-- Progression et mesure -->
<progress value="70" max="100">70%</progress>
<meter value="0.6">60%</meter>
```

### Canvas et SVG : `<canvas>`, `<svg>`

Capacités graphiques et de dessin en HTML5.

```html
<!-- Canvas pour les graphiques dynamiques -->
<canvas id="myCanvas" width="400" height="200">
  Votre navigateur ne prend pas en charge le canvas.
</canvas>
<!-- SVG en ligne -->
<svg width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue" stroke="black" stroke-width="2" />
</svg>
```

### Détails et Résumé : `<details>`, `<summary>`

Crée des sections de contenu réductibles sans JavaScript.

```html
<details>
  <summary>Cliquez pour développer</summary>
  <p>Ce contenu est masqué par défaut et révélé en cliquant sur le résumé.</p>
  <ul>
    <li>Élément 1</li>
    <li>Élément 2</li>
  </ul>
</details>
<details open>
  <summary>Ceci commence développé</summary>
  <p>Contenu visible par défaut.</p>
</details>
```

### Élément Dialog : `<dialog>`

Fonctionnalité native de boîte de dialogue et de modale.

```html
<!-- Élément dialog -->
<dialog id="myDialog">
  <h2>Titre de la Boîte de Dialogue</h2>
  <p>Le contenu de la boîte de dialogue va ici.</p>
  <button onclick="closeDialog()">Fermer</button>
</dialog>
<button onclick="openDialog()">Ouvrir la Boîte de Dialogue</button>
<script>
  function openDialog() {
    document.getElementById('myDialog').showModal()
  }
</script>
```

## Bonnes Pratiques et Validation

### Bonnes Pratiques HTML

Écrivez un HTML propre, maintenable et accessible.

```html
<!-- Déclarer toujours le doctype -->
<!DOCTYPE html>
<!-- Utiliser des éléments sémantiques -->
<header>...</header>
<main>...</main>
<footer>...</footer>
<!-- Imbrication correcte -->
<div>
  <p>Contenu correctement imbriqué</p>
</div>
<!-- Utiliser des minuscules pour les éléments et attributs -->
<img src="image.jpg" alt="description" />
<!-- Fermer toutes les balises -->
<p>Fermez toujours vos balises</p>
<!-- Utiliser un texte alt significatif -->
<img src="chart.png" alt="Les ventes ont augmenté de 25% au T4" />
```

### Validation et Débogage HTML

Assurez-vous que votre HTML est valide et accessible.

```html
<!-- Utiliser le validateur HTML W3C -->
<!-- https://validator.w3.org/ -->
<!-- Erreurs de validation courantes -->
<!-- Attributs alt manquants -->
<img src="image.jpg" alt="" />
<!-- Fournir un texte alt -->
<!-- Balises non fermées -->
<p>Contenu texte</p>
<!-- Toujours fermer les balises -->
<!-- Imbrication invalide -->
<p>
  Contenu de paragraphe valide
  <!-- Ne pas placer d'éléments de bloc à l'intérieur des paragraphes -->
</p>
<!-- Utiliser les outils de développement -->
<!-- Clic droit → Inspecter l'élément -->
<!-- Vérifier la console pour les erreurs -->
<!-- Valider l'accessibilité avec WAVE ou axe -->
```

## Moteurs de Modèles et Frameworks HTML

### Moteurs de Modèles : Handlebars, Mustache

Génération HTML dynamique avec des langages de modèles.

```html
<!-- Modèle Handlebars -->
<div>
  <h1>{{title}}</h1>
  {{#each items}}
  <p>{{this}}</p>
  {{/each}}
</div>
<!-- Modèle Mustache -->
<div>
  <h1>{{title}}</h1>
  {{#items}}
  <p>{{.}}</p>
  {{/items}}
</div>
```

### Composants Web : `<template>`, Éléments Personnalisés

Éléments HTML personnalisés réutilisables.

```html
<!-- Définition d'un élément personnalisé -->
<template id="my-component">
  <style>
    p {
      color: blue;
    }
  </style>
  <p><slot></slot></p>
</template>
<!-- Utilisation -->
<my-component>Hello World</my-component>
<script>
  class MyComponent extends HTMLElement {
    // Logique du composant
  }
  customElements.define('my-component', MyComponent)
</script>
```

### Intégration de Framework : JSX React, Modèles Vue

HTML au sein des frameworks JavaScript modernes.

```html
<!-- React JSX -->
function Component() { return (
<div className="container">
  <h1>{title}</h1>
  <p>Contenu ici</p>
</div>
); }
<!-- Modèle Vue -->
<template>
  <div class="container">
    <h1>{{ title }}</h1>
    <p v-if="showContent">Contenu ici</p>
  </div>
</template>
```

## Liens Pertinents

- <router-link to="/css">Feuille de triche CSS</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/web-development">Feuille de triche Développement Web</router-link>
- <router-link to="/react">Feuille de triche React</router-link>
- <router-link to="/git">Feuille de triche Git</router-link>
- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/docker">Feuille de triche Docker</router-link>

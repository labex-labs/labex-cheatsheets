---
title: 'HTML Spickzettel'
description: 'Lernen Sie HTML mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/html-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
HTML Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/html">HTML mit praktischen Übungen lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie die Struktur des HTML-Webs durch praktische Übungen und reale Szenarien. LabEx bietet umfassende HTML-Kurse, die wesentliche Elemente, semantische Auszeichnung, Formulare, Medienintegration und moderne HTML5-Funktionen abdecken. Meistern Sie die effiziente Strukturierung von Webseiten und die Organisation von Inhalten für moderne Webentwicklungs-Workflows.
</base-disclaimer-content>
</base-disclaimer>

## HTML-Dokumentstruktur

### Basis-HTML-Dokument: `<!DOCTYPE html>`

Jedes HTML-Dokument beginnt mit einer Dokumenttypdeklaration und folgt einer Standardstruktur.

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Seitentitel</title>
  </head>
  <body>
    <!-- Seiteninhalt kommt hierher -->
  </body>
</html>
```

### Head-Elemente: `<head>`

Der Head-Bereich enthält Metadaten über das Dokument.

```html
<!-- Zeichenkodierung -->
<meta charset="UTF-8" />
<!-- Viewport für responsives Design -->
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<!-- Seitenbeschreibung -->
<meta name="description" content="Seitenbeschreibung" />
<!-- Link zu CSS -->
<link rel="stylesheet" href="styles.css" />
<!-- Link zu Favicon -->
<link rel="icon" href="favicon.ico" />
```

### HTML-Kommentare: `<!-- -->`

Kommentare werden nicht angezeigt, helfen aber bei der Dokumentation Ihres Codes.

```html
<!-- Dies ist ein Kommentar -->
<!-- 
  Mehrzeiliger Kommentar
  für längere Erklärungen
-->
```

### Anatomie von HTML-Elementen

HTML-Elemente bestehen aus öffnenden Tags, Inhalt und schließenden Tags.

```html
<!-- Element mit Inhalt -->
<p>Dies ist ein Absatz</p>
<!-- Selbstschließende Elemente -->
<img src="image.jpg" alt="Beschreibung" />
<br />
<hr />
<!-- Elemente mit Attributen -->
<a href="https://example.com" target="_blank">Link</a>
<!-- Geschachtelte Elemente -->
<div>
  <p>Geschachtelter Absatz</p>
</div>
```

## Textelementen

### Überschriften: `h1` bis `h6`

Definieren die Hierarchie und Wichtigkeit von Inhaltsabschnitten.

```html
<h1>Haupttitel</h1>
<h2>Abschnittstitel</h2>
<h3>Unterabschnittstitel</h3>
<h4>Sub-Unterabschnittstitel</h4>
<h5>Kleinere Überschrift</h5>
<h6>Kleinste Überschrift</h6>
```

### Absätze: `p`

Das gängigste Element für Textinhaltsblöcke.

```html
<p>
  Dies ist ein Textabsatz. Er kann mehrere Sätze enthalten und wird automatisch
  umgebrochen.
</p>
<p>Dies ist ein weiterer Absatz. Absätze sind durch Randabstand getrennt.</p>
```

### Textformatierung: `<strong>`, `<em>`, `<b>`, `<i>`

Elemente zur Hervorhebung und Formatierung von Text inline.

```html
<strong>Starke Wichtigkeit (fett)</strong>
<em>Hervorhebung (kursiv)</em>
<b>Fetter Text</b>
<i>Kursiver Text</i>
<u>Unterstrichener Text</u>
<mark>Markierter Text</mark>
<small>Kleiner Text</small>
<del>Gelöschter Text</del>
<ins>Eingefügter Text</ins>
```

### Zeilenumbrüche & Abstand: `<br>`, `<hr>`, `<pre>`

Steuern den Textfluss und den Abstand innerhalb des Inhalts.

```html
<!-- Zeilenumbruch -->
Zeile 1<br />
Zeile 2
<!-- Horizontale Linie -->
<hr />
<!-- Vorformatierter Text -->
<pre>
  Text mit
    erhaltenem    Abstand
      und Zeilenumbrüchen
</pre>
<!-- Code-Formatierung -->
<code>console.log('Hello');</code>
```

## Listen & Navigation

### Ungeordnete Listen: `<ul>`

Erstellen Sie Listen mit Aufzählungszeichen für nicht-sequentielle Elemente.

```html
<ul>
  <li>Erstes Element</li>
  <li>Zweites Element</li>
  <li>Drittes Element</li>
</ul>
<!-- Geschachtelte Listen -->
<ul>
  <li>
    Hauptelement
    <ul>
      <li>Unterelement 1</li>
      <li>Unterelement 2</li>
    </ul>
  </li>
</ul>
```

### Geordnete Listen: `<ol>`

Erstellen Sie nummerierte Listen für sequentielle Elemente.

```html
<ol>
  <li>Erster Schritt</li>
  <li>Zweiter Schritt</li>
  <li>Dritter Schritt</li>
</ol>
<!-- Benutzerdefinierte Nummerierung -->
<ol start="5">
  <li>Element 5</li>
  <li>Element 6</li>
</ol>
<!-- Verschiedene Nummerierungstypen -->
<ol type="A">
  <li>Element A</li>
  <li>Element B</li>
</ol>
```

### Beschreibungslisten: `<dl>`

Erstellen Sie Listen von Begriffen und deren Beschreibungen.

```html
<dl>
  <dt>HTML</dt>
  <dd>HyperText Markup Language</dd>

  <dt>CSS</dt>
  <dd>Cascading Style Sheets</dd>

  <dt>JavaScript</dt>
  <dd>Programmiersprache für das Web</dd>
</dl>
```

### Links & Navigation: `<a>`

Erstellen Sie Hyperlinks und Navigationsstrukturen.

```html
<!-- Basis-Link -->
<a href="https://example.com">Beispiel besuchen</a>
<!-- Link in neuem Tab -->
<a href="https://example.com" target="_blank">Neuer Tab</a>
<!-- E-Mail-Link -->
<a href="mailto:email@example.com">E-Mail senden</a>
<!-- Telefon-Link -->
<a href="tel:+1234567890">Rufen Sie uns an</a>
<!-- Interne Seitenanker -->
<a href="#section1">Gehe zu Abschnitt 1</a>
<h2 id="section1">Abschnitt 1</h2>
```

## Formulare & Eingabeelemente

### Basis-Formularstruktur: `<form>`

Die Grundlage für die Sammlung von Benutzereingaben.

```html
<form action="/submit" method="POST">
  <label for="username">Benutzername:</label>
  <input type="text" id="username" name="username" required />

  <label for="email">E-Mail:</label>
  <input type="email" id="email" name="email" required />

  <input type="submit" value="Senden" />
</form>
```

### Eingabetypen: `<input>`

Verschiedene Eingabetypen für unterschiedliche Datenerfassungsanforderungen.

```html
<!-- Texteingaben -->
<input type="text" placeholder="Text eingeben" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="Passwort" />
<input type="url" placeholder="https://example.com" />
<input type="tel" placeholder="+1234567890" />
<!-- Zahleneingaben -->
<input type="number" min="1" max="100" step="1" />
<input type="range" min="0" max="100" value="50" />
<!-- Datum und Uhrzeit -->
<input type="date" />
<input type="time" />
<input type="datetime-local" />
```

### Formularsteuerelemente: `<checkbox>`, `<radio>`, `<select>`, `<textarea>`

Zusätzliche Formularelemente für die Benutzerinteraktion.

```html
<!-- Checkboxen -->
<input type="checkbox" id="agree" name="agree" />
<label for="agree">Ich stimme den Bedingungen zu</label>
<!-- Radio-Buttons -->
<input type="radio" id="option1" name="choice" value="1" />
<label for="option1">Option 1</label>
<input type="radio" id="option2" name="choice" value="2" />
<label for="option2">Option 2</label>
<!-- Select-Dropdown -->
<select name="country">
  <option value="us">Vereinigte Staaten</option>
  <option value="uk">Vereinigtes Königreich</option>
  <option value="ca">Kanada</option>
</select>
<!-- Textbereich -->
<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="Ihre Nachricht eingeben"
></textarea>
```

### Formularvalidierung: `required`, `min`, `max`, `pattern`

Integrierte HTML-Formularvalidierungsattribute.

```html
<input type="text" required />
<input type="email" required />
<input type="text" minlength="3" maxlength="20" />
<input type="number" min="1" max="100" />
<input type="text" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}" />
```

## Medienelemente

### Bilder: `<img>`, `<picture>`

Bilder mit verschiedenen Attributen und Optionen anzeigen.

```html
<!-- Basisbild -->
<img src="image.jpg" alt="Beschreibung" />
<!-- Responsives Bild -->
<img src="image.jpg" alt="Beschreibung" width="100%" height="auto" />
<!-- Bild mit Größe -->
<img src="image.jpg" alt="Beschreibung" width="300" height="200" />
<!-- Picture-Element für responsive Bilder -->
<picture>
  <source media="(min-width: 800px)" srcset="large.jpg" />
  <source media="(min-width: 400px)" srcset="medium.jpg" />
  <img src="small.jpg" alt="Beschreibung" />
</picture>
```

### Audio: `<audio>`

Audiodaten mit Wiedergabesteuerungen einbetten.

```html
<!-- Basis-Audio -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
  <source src="audio.ogg" type="audio/ogg" />
  Ihr Browser unterstützt Audio nicht.
</audio>
<!-- Audio mit Autoplay -->
<audio controls autoplay loop>
  <source src="background.mp3" type="audio/mpeg" />
</audio>
```

### Video: `<video>`

Videodaten mit umfassenden Optionen einbetten.

```html
<!-- Basis-Video -->
<video controls width="400" height="300">
  <source src="video.mp4" type="video/mp4" />
  <source src="video.webm" type="video/webm" />
  Ihr Browser unterstützt Video nicht.
</video>
<!-- Video mit Poster und Attributen -->
<video controls poster="thumbnail.jpg" width="100%" height="auto">
  <source src="video.mp4" type="video/mp4" />
  <track src="captions.vtt" kind="captions" srclang="en" label="English" />
</video>
```

### Eingebettete Inhalte: `<iframe>`

Externe Inhalte und Anwendungen einbetten.

```html
<!-- iFrame für externe Inhalte -->
<iframe src="https://example.com" width="100%" height="400"></iframe>
<!-- YouTube-Video-Embed -->
<iframe
  width="560"
  height="315"
  src="https://www.youtube.com/embed/VIDEO_ID"
></iframe>
<!-- Google Maps Embed -->
<iframe src="https://maps.google.com/..."></iframe>
```

## Tabellen

### Basis-Tabellenstruktur: `<table>`

Strukturierte Datenanzeigen mit Tabellen erstellen.

```html
<table>
  <thead>
    <tr>
      <th>Name</th>
      <th>Alter</th>
      <th>Stadt</th>
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

### Erweiterte Tabellenfunktionen: `rowspan`, `colspan`, `<caption>`

Erweiterte Tabellenfunktionalität mit Spanning und Gruppierung.

```html
<table>
  <caption>
    Verkaufsbericht
  </caption>
  <colgroup>
    <col style="width: 50%" />
    <col style="width: 25%" />
    <col style="width: 25%" />
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">Produkt</th>
      <th colspan="2">Verkäufe</th>
    </tr>
    <tr>
      <th>Q1</th>
      <th>Q2</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Produkt A</td>
      <td>$1000</td>
      <td>$1200</td>
    </tr>
  </tbody>
</table>
```

## Semantische HTML5-Elemente

### Seitenstruktur-Elemente: `<header>`, `<nav>`, `<main>`, `<footer>`

Definieren Sie die Hauptabschnitte Ihres Seitenlayouts.

```html
<!-- Seitentitel -->
<header>
  <nav>
    <ul>
      <li><a href="#home">Home</a></li>
      <li><a href="#about">Über uns</a></li>
    </ul>
  </nav>
</header>
<!-- Hauptinhalt -->
<main>
  <article>
    <h1>Artikeltitel</h1>
    <p>Artikelinhalt...</p>
  </article>
</main>
<!-- Seitenleiste -->
<aside>
  <h2>Verwandte Links</h2>
  <ul>
    <li><a href="#">Link 1</a></li>
  </ul>
</aside>
<!-- Seitenfußzeile -->
<footer>
  <p>© 2024 Firmenname</p>
</footer>
```

### Inhaltsgruppierungselemente: `<section>`, `<article>`, `<div>`, `<figure>`

Organisieren und gruppieren Sie zusammengehörige Inhaltsabschnitte.

```html
<!-- Generischer Abschnitt -->
<section>
  <h2>Abschnittstitel</h2>
  <p>Abschnittsinhalt...</p>
</section>
<!-- Eigenständiger Artikel -->
<article>
  <header>
    <h1>Artikeltitel</h1>
    <time datetime="2024-01-01">1. Januar 2024</time>
  </header>
  <p>Artikelinhalt...</p>
</article>
<!-- Generischer Container -->
<div class="container">
  <p>Generische Inhaltsgruppierung</p>
</div>
<!-- Figur mit Bildunterschrift -->
<figure>
  <img src="chart.jpg" alt="Verkaufsdiagramm" />
  <figcaption>Verkaufsdaten für Q1 2024</figcaption>
</figure>
```

## HTML-Attribute

### Globale Attribute: `id`, `class`, `title`, `data-*`

Attribute, die auf jedem HTML-Element verwendet werden können.

```html
<!-- ID zur eindeutigen Identifizierung -->
<div id="unique-element">Inhalt</div>
<!-- Klasse für Styling und Auswahl -->
<p class="highlight important">Text</p>
<!-- Titel für Tooltips -->
<span title="Dies ist ein Tooltip">Hovern Sie über mich</span>
<!-- Datenattribute -->
<div data-user-id="123" data-role="admin">Benutzer</div>
<!-- Sprache -->
<p lang="es">Hola mundo</p>
<!-- Textrichtung -->
<p dir="rtl">Rechts nach links Text</p>
<!-- Ausgeblendete Elemente -->
<div hidden>Dies wird nicht angezeigt</div>
```

### Barrierefreiheitsattribute: `alt`, `aria-*`, `tabindex`, `role`

Attribute, die die Barrierefreiheit und Benutzererfahrung verbessern.

```html
<!-- Alternativtext für Bilder -->
<img src="photo.jpg" alt="Ein Sonnenuntergang über Bergen" />
<!-- ARIA-Labels -->
<button aria-label="Dialog schließen">×</button>
<div aria-hidden="true">Dekorativer Inhalt</div>
<!-- Formular-Barrierefreiheit -->
<label for="email">E-Mail-Adresse:</label>
<input type="email" id="email" aria-describedby="email-help" />
<small id="email-help">Wir werden Ihre E-Mail niemals weitergeben</small>
<!-- Tab-Index -->
<div tabindex="0">Fokusfähiges div</div>
<div tabindex="-1">Programmatisch fokussierbares div</div>
<!-- Rollenattribut -->
<div role="button" tabindex="0">Benutzerdefinierter Button</div>
```

## HTML5 Moderne Funktionen

### Neue Eingabefunktionen: `color`, `search`, `file`, `datalist`

HTML5 führte neue Eingabetypen und Attribute ein.

```html
<!-- Neue Eingabetypen -->
<input type="color" value="#ff0000" />
<input type="search" placeholder="Suchen..." />
<input type="file" accept="image/*" multiple />
<!-- Datalist für Autovervollständigung -->
<input list="browsers" name="browser" />
<datalist id="browsers">
  <option value="Chrome"></option>
  <option value="Firefox"></option>
  <option value="Safari"></option>
</datalist>
<!-- Fortschritt und Messwert -->
<progress value="70" max="100">70%</progress>
<meter value="0.6">60%</meter>
```

### Canvas & SVG: `<canvas>`, `<svg>`

Grafik- und Zeichenfunktionen in HTML5.

```html
<!-- Canvas für dynamische Grafiken -->
<canvas id="myCanvas" width="400" height="200">
  Ihr Browser unterstützt Canvas nicht.
</canvas>
<!-- Inline SVG -->
<svg width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue" stroke="black" stroke-width="2" />
</svg>
```

### Details & Zusammenfassung: `<details>`, `<summary>`

Erstellen Sie einklappbare Inhaltsabschnitte ohne JavaScript.

```html
<details>
  <summary>Klicken zum Erweitern</summary>
  <p>
    Dieser Inhalt ist standardmäßig ausgeblendet und wird beim Klicken auf die
    Zusammenfassung angezeigt.
  </p>
  <ul>
    <li>Element 1</li>
    <li>Element 2</li>
  </ul>
</details>
<details open>
  <summary>Dies beginnt erweitert</summary>
  <p>Inhalt standardmäßig sichtbar.</p>
</details>
```

### Dialog-Element: `<dialog>`

Native Dialog- und Modal-Funktionalität.

```html
<!-- Dialog-Element -->
<dialog id="myDialog">
  <h2>Dialogtitel</h2>
  <p>Dialoginhalt hier.</p>
  <button onclick="closeDialog()">Schließen</button>
</dialog>
<button onclick="openDialog()">Dialog öffnen</button>
<script>
  function openDialog() {
    document.getElementById('myDialog').showModal()
  }
</script>
```

## Best Practices & Validierung

### HTML Best Practices

Schreiben Sie sauberes, wartbares und zugängliches HTML.

```html
<!-- Immer Doctype deklarieren -->
<!DOCTYPE html>
<!-- Semantische Elemente verwenden -->
<header>...</header>
<main>...</main>
<footer>...</footer>
<!-- Korrekte Verschachtelung -->
<div>
  <p>Korrekter verschachtelter Inhalt</p>
</div>
<!-- Kleinbuchstaben für Elemente und Attribute verwenden -->
<img src="image.jpg" alt="beschreibung" />
<!-- Alle Tags schließen -->
<p>Schließen Sie immer Ihre Tags</p>
<!-- Sinnvolle Alt-Texte verwenden -->
<img src="chart.png" alt="Umsatz stieg im 4. Quartal um 25%" />
```

### HTML-Validierung & Debugging

Stellen Sie sicher, dass Ihr HTML gültig und zugänglich ist.

```html
<!-- W3C HTML Validator verwenden -->
<!-- https://validator.w3.org/ -->
<!-- Häufige Validierungsfehler -->
<!-- Fehlende Alt-Attribute -->
<img src="image.jpg" alt="" />
<!-- Alt-Text angeben -->
<!-- Nicht geschlossene Tags -->
<p>Textinhalt</p>
<!-- Tags immer schließen -->
<!-- Ungültige Verschachtelung -->
<p>
  Gültiger Absatzinhalt
  <!-- Blockelemente nicht in Absätze einfügen -->
</p>
<!-- Entwicklertools verwenden -->
<!-- Rechtsklick → Element untersuchen -->
<!-- Auf Fehler in der Konsole prüfen -->
<!-- Barrierefreiheit mit WAVE oder axe validieren -->
```

## HTML-Vorlagen & Frameworks

### Template-Engines: Handlebars, Mustache

Dynamische HTML-Generierung mit Template-Sprachen.

```html
<!-- Handlebars-Vorlage -->
<div>
  <h1>{{title}}</h1>
  {{#each items}}
  <p>{{this}}</p>
  {{/each}}
</div>
<!-- Mustache-Vorlage -->
<div>
  <h1>{{title}}</h1>
  {{#items}}
  <p>{{.}}</p>
  {{/items}}
</div>
```

### Web Components: `<template>`, Custom Elements

Wiederverwendbare benutzerdefinierte HTML-Elemente.

```html
<!-- Definition eines benutzerdefinierten Elements -->
<template id="my-component">
  <style>
    p {
      color: blue;
    }
  </style>
  <p><slot></slot></p>
</template>
<!-- Verwendung -->
<my-component>Hallo Welt</my-component>
<script>
  class MyComponent extends HTMLElement {
    // Komponentenlogik
  }
  customElements.define('my-component', MyComponent)
</script>
```

### Framework-Integration: React JSX, Vue Templates

HTML innerhalb moderner JavaScript-Frameworks.

```html
<!-- React JSX -->
function Component() { return (
<div className="container">
  <h1>{title}</h1>
  <p>Inhalt hier</p>
</div>
); }
<!-- Vue-Vorlage -->
<template>
  <div class="container">
    <h1>{{ title }}</h1>
    <p v-if="showContent">Inhalt hier</p>
  </div>
</template>
```

## Relevante Links

- <router-link to="/css">CSS Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/web-development">Webentwicklung Spickzettel</router-link>
- <router-link to="/react">React Spickzettel</router-link>
- <router-link to="/git">Git Spickzettel</router-link>
- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>

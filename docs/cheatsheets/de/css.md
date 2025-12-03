---
title: 'CSS Spickzettel | LabEx'
description: 'Lernen Sie CSS3 mit diesem umfassenden Spickzettel. Schnelle Referenz für CSS-Selektoren, Flexbox, Grid, Animationen, responsives Design und moderne Styling-Techniken für Webentwickler.'
pdfUrl: '/cheatsheets/pdf/css-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
CSS Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/css">CSS mit praktischen Übungen lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie CSS-Web-Styling durch praktische Übungen und reale Szenarien. LabEx bietet umfassende CSS-Kurse, die wesentliche Eigenschaften, Selektoren, Layout-Techniken, responsives Design und moderne Funktionen abdecken. Meistern Sie effizientes Web-Styling und Layout-Design für moderne Webentwicklungs-Workflows.
</base-disclaimer-content>
</base-disclaimer>

## CSS Syntax & Selektoren

### Grundlegende Syntax

CSS besteht aus Selektoren und Deklarationen. Der Selektor zielt auf HTML-Elemente ab, und Deklarationen legen Eigenschaftswerte fest.

```css
/* Grundlegende Syntax */
selector {
  property: value;
  property: value;
}

/* Beispiel */
p {
  color: red;
  font-size: 16px;
}
```

### Element-Selektoren

Zielen auf HTML-Elemente anhand ihres Tag-Namens ab.

```css
/* Alle Absätze auswählen */
p {
  color: blue;
}

/* Alle Überschriften auswählen */
h1 {
  font-size: 2em;
}

/* Alle Links auswählen */
a {
  text-decoration: none;
}
```

### Klassen-Selektoren

Zielen auf Elemente mit spezifischen Klassenattributen ab.

```css
/* Elemente mit class="highlight" auswählen */
.highlight {
  background-color: yellow;
}

/* Absätze mit class="intro" auswählen */
p.intro {
  font-weight: bold;
}

/* Mehrere Klassen */
.large.bold {
  font-size: 20px;
  font-weight: bold;
}
```

<BaseQuiz id="css-class-1" correct="B">
  <template #question>
    Wie wählen Sie in CSS ein Element mit class="highlight" aus?
  </template>
  
  <BaseQuizOption value="A">highlight { }</BaseQuizOption>
  <BaseQuizOption value="B" correct>.highlight { }</BaseQuizOption>
  <BaseQuizOption value="C">#highlight { }</BaseQuizOption>
  <BaseQuizOption value="D">class="highlight" { }</BaseQuizOption>
  
  <BaseQuizAnswer>
    Klassen-Selektoren verwenden einen Punkt (`.`) als Präfix. `.highlight` wählt alle Elemente mit `class="highlight"` aus. ID-Selektoren verwenden `#`, und Element-Selektoren verwenden kein Präfix.
  </BaseQuizAnswer>
</BaseQuiz>

### ID-Selektoren

Zielen auf Elemente mit spezifischen ID-Attributen ab.

```css
/* Element mit id="header" auswählen */
#header {
  background-color: #333;
}

/* IDs sollten pro Seite eindeutig sein */
#navigation {
  position: fixed;
}
```

### Attribut-Selektoren

Zielen auf Elemente mit bestimmten Attributen mithilfe von Attribut-Selektoren ab.

```css
/* Elemente mit title-Attribut */
[title] {
  cursor: help;
}

/* Links zu externen Seiten */
a[href^='http'] {
  color: red;
}

/* Eingabeelemente vom Typ text */
input[type='text'] {
  border: 1px solid #ccc;
}
```

### Pseudo-Klassen

Pseudo-Klassen wenden CSS basierend auf Zustandsänderungen und Benutzerinteraktionen an.

```css
/* Link-Zustände */
a:hover {
  color: red;
}
a:visited {
  color: purple;
}
a:active {
  color: orange;
}

/* Formularzustände */
input:focus {
  border-color: blue;
}
input:invalid {
  border-color: red;
}

/* Strukturelle Pseudo-Klassen */
li:first-child {
  font-weight: bold;
}
li:nth-child(odd) {
  background-color: #f0f0f0;
}
```

## Box-Modell & Layout

### Inhalt: `width` / `height`

Der tatsächliche Inhaltsbereich des Elements.

```css
/* Dimensionen festlegen */
div {
  width: 300px;
  height: 200px;
}

/* Responsive Größenanpassung */
.container {
  width: 100%;
  max-width: 1200px;
}

/* Min/Max-Beschränkungen */
.box {
  min-height: 100px;
  max-width: 500px;
}
```

### Padding: `padding`

Platz zwischen Inhalt und Rahmen, innerhalb des Elements.

```css
/* Alle Seiten */
div {
  padding: 20px;
}

/* Einzelne Seiten */
div {
  padding-top: 10px;
  padding-right: 15px;
}

/* Kurzschreibweise: oben rechts unten links */
div {
  padding: 10px 15px 20px 5px;
}
```

<BaseQuiz id="css-padding-1" correct="C">
  <template #question>
    Was bewirkt `padding: 10px 20px`?
  </template>
  
  <BaseQuizOption value="A">10px oben/unten, 20px links/rechts</BaseQuizOption>
  <BaseQuizOption value="B">10px alle Seiten</BaseQuizOption>
  <BaseQuizOption value="C" correct>10px oben/unten, 20px links/rechts</BaseQuizOption>
  <BaseQuizOption value="D">10px oben, 20px unten</BaseQuizOption>
  
  <BaseQuizAnswer>
    Wenn zwei Werte angegeben werden, gilt der erste für oben und unten, und der zweite für links und rechts. Also bedeutet `padding: 10px 20px` 10px vertikales Padding und 20px horizontales Padding.
  </BaseQuizAnswer>
</BaseQuiz>
```

### Border: `border`

Ränder bieten einen Rahmen für Elemente mit anpassbarer Größe, Stil und Farbe.

```css
/* Border Kurzschreibweise */
div {
  border: 2px solid #333;
}

/* Einzelne Eigenschaften */
div {
  border-width: 1px;
  border-style: dashed;
  border-color: red;
}

/* Einzelne Seiten */
div {
  border-bottom: 3px solid blue;
}
```

### Margin: `margin`

Platz außerhalb des Rahmens, zwischen Elementen.

```css
/* Alle Seiten */
div {
  margin: 20px;
}

/* Horizontal zentrieren */
div {
  margin: 0 auto;
}

/* Einzelne Seiten */
div {
  margin-top: 30px;
  margin-bottom: 10px;
}

/* Negative Margins */
div {
  margin-left: -20px;
}
```

<BaseQuiz id="css-margin-1" correct="C">
  <template #question>
    Was bewirkt `margin: 0 auto`?
  </template>
  
  <BaseQuizOption value="A">Entfernt alle Margins</BaseQuizOption>
  <BaseQuizOption value="B">Fügt gleiche Margins auf allen Seiten hinzu</BaseQuizOption>
  <BaseQuizOption value="C" correct>Zentriert ein Blockelement horizontal</BaseQuizOption>
  <BaseQuizOption value="D">Zentriert ein Blockelement vertikal</BaseQuizOption>
  
  <BaseQuizAnswer>
    `margin: 0 auto` setzt obere und untere Margins auf 0 und linke/rechte Margins auf auto, was ein Block-Level-Element horizontal innerhalb seines Containers zentriert.
  </BaseQuizAnswer>
</BaseQuiz>

## Text & Typografie

### Schriftarten-Eigenschaften

Steuern Sie Schriftfamilie, -größe, -stärke und -stil.

```css
/* Schriftfamilie */
body {
  font-family: Arial, sans-serif;
}

/* Google Fonts */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
body {
  font-family: 'Roboto', sans-serif;
}

/* Schriftgröße */
h1 {
  font-size: 2rem;
}
p {
  font-size: 16px;
}

/* Schriftstärke */
h2 {
  font-weight: bold;
}
span {
  font-weight: 300;
}
```

### Textausrichtung

Steuern Sie die Textpositionierung und den Abstand.

```css
/* Horizontale Ausrichtung */
h1 {
  text-align: center;
}
p {
  text-align: justify;
}

/* Zeilenhöhe */
p {
  line-height: 1.6;
}

/* Zeichen- und Wortabstand */
h1 {
  letter-spacing: 2px;
}
p {
  word-spacing: 4px;
}
```

### Text-Styling

Fügen Sie Textdekorationen und Transformationen hinzu.

```css
/* Textdekoration */
a {
  text-decoration: underline;
}
.strike {
  text-decoration: line-through;
}

/* Texttransformation */
.uppercase {
  text-transform: uppercase;
}
.capitalize {
  text-transform: capitalize;
}

/* Textschatten */
h1 {
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}
```

### Farben

CSS bietet verschiedene Möglichkeiten, Farben für unterschiedliche Styling-Anforderungen anzugeben.

```css
/* Farbformate */
p {
  color: red;
}
div {
  background-color: #ff5733;
}
```

<BaseQuiz id="css-colors-1" correct="D">
  <template #question>
    Welches CSS-Farbformat wird am häufigsten für Webdesign verwendet?
  </template>
  
  <BaseQuizOption value="A">Nur RGB</BaseQuizOption>
  <BaseQuizOption value="B">Nur benannte Farben</BaseQuizOption>
  <BaseQuizOption value="C">Nur HSL</BaseQuizOption>
  <BaseQuizOption value="D" correct>Hex-Codes (#RRGGBB) sind sehr verbreitet, zusammen mit benannten Farben und RGB</BaseQuizOption>
  
  <BaseQuizAnswer>
    Hex-Farb-Codes (#RRGGBB) sind weit verbreitet, da sie prägnant sind und leicht aus Designtools kopiert werden können. Benannte Farben sowie RGB/rgba sind ebenfalls üblich. Die Wahl hängt vom spezifischen Anwendungsfall und der Präferenz ab.
  </BaseQuizAnswer>
</BaseQuiz>
span {
  color: rgb(255, 87, 51);
}
section {
  background-color: rgba(255, 87, 51, 0.8);
}

/_ HSL Farben _/
header {
background-color: hsl(200, 100%, 50%);
}

/_ CSS Variablen für Farben _/
:root {
--primary-color: #3498db;
}
.button {
background-color: var(--primary-color);
}

````

## Flexbox Layout

### Flex Container Eigenschaften

Eigenschaften, die auf den übergeordneten Container angewendet werden.

```css
/* Flexbox aktivieren */
.container {
  display: flex;
}

/* Flex-Richtung */
.container {
  flex-direction: row; /* Standard */
  flex-direction: column;
  flex-direction: row-reverse;
}

/* Justify content (Hauptachse) */
.container {
  justify-content: flex-start; /* Standard */
  justify-content: center;
  justify-content: space-between;
  justify-content: space-around;
}

/* Align items (Querachse) */
.container {
  align-items: stretch; /* Standard */
  align-items: center;
  align-items: flex-start;
}
```

### Flex Item Eigenschaften

Eigenschaften, die auf die Kindelemente angewendet werden.

```css
/* Flex wachsen/schrumpfen */
.item {
  flex-grow: 1; /* Platz füllen, um zu wachsen */
  flex-shrink: 1; /* schrumpfen, falls nötig */
  flex-basis: auto; /* Anfangsgröße */
}

/* Kurzschreibweise */
.item {
  flex: 1; /* flex: 1 1 0% */
  flex: 0 0 200px; /* feste Breite */
}

/* Individuelle Ausrichtung */
.item {
  align-self: center;
  align-self: flex-end;
}

/* Reihenfolge */
.item {
  order: 2; /* visuelle Reihenfolge ändern */
}
```

## CSS Grid Layout

### Grid Container

Definieren Sie die Rasterstruktur und -eigenschaften.

```css
/* Grid aktivieren */
.grid-container {
  display: grid;
}

/* Spalten und Reihen definieren */
.grid-container {
  grid-template-columns: 1fr 2fr 1fr;
  grid-template-rows: 100px auto 50px;
}

/* Grid-Abstände */
.grid-container {
  gap: 20px;
  column-gap: 30px;
  row-gap: 10px;
}

/* Benannte Grid-Bereiche */
.grid-container {
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}
```

### Grid Items

Positionieren und dimensionieren Sie Grid-Elemente.

```css
/* Grid-Positionierung */
.grid-item {
  grid-column: 1 / 3; /* Spalten 1-2 überspannen */
  grid-row: 2 / 4; /* Reihen 2-3 überspannen */
}

/* Kurzschreibweise */
.grid-item {
  grid-area: 2 / 1 / 4 / 3; /* reihe-start / spalte-start / reihe-ende / spalte-ende */
}

/* Benannte Bereiche */
.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}

/* Automatische Platzierung */
.grid-item {
  grid-column: span 2; /* 2 Spalten überspannen */
  grid-row: span 3; /* 3 Reihen überspannen */
}
```

## Positionierung

### Position Eigenschaft

Steuern Sie das Positionierungsverhalten von Elementen.

```css
/* Statisch (Standard) */
.element {
  position: static;
}

/* Relative Positionierung */
.element {
  position: relative;
  top: 20px;
  left: 10px;
}

/* Absolute Positionierung */
.element {
  position: absolute;
  top: 0;
  right: 0;
}

/* Feste Positionierung */
.navbar {
  position: fixed;
  top: 0;
  width: 100%;
}

/* Sticky Positionierung */
.sidebar {
  position: sticky;
  top: 20px;
}
```

### Z-Index & Stapelreihenfolge

Steuern Sie die Reihenfolge, in der sich Elemente überlagern, mithilfe von z-index und Stapelkontext.

```css
/* Stapelreihenfolge */
.modal {
  position: fixed;
  z-index: 1000;
}
.overlay {
  position: absolute;
  z-index: 999;
}

/* Erstellen eines Stapelkontexts */
.container {
  position: relative;
  z-index: 0;
}

/* Übliche z-index Werte */
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

## Responsives Design

### Media Queries

Wenden Sie Stile basierend auf Geräte- oder Anzeigeeigenschaften an.

```css
/* Mobile first Ansatz */
.container {
  width: 100%;
}

/* Tablet-Stile */
@media (min-width: 768px) {
  .container {
    width: 750px;
  }
}

/* Desktop-Stile */
@media (min-width: 1024px) {
  .container {
    width: 960px;
  }
}

/* Druckstile */
@media print {
  body {
    font-size: 12pt;
  }
  .no-print {
    display: none;
  }
}

/* Ausrichtung */
@media (orientation: landscape) {
  .sidebar {
    display: block;
  }
}
```

### Responsive Einheiten

Verwenden Sie relative Einheiten für flexible Layouts.

```css
/* Viewport-Einheiten */
.hero {
  height: 100vh;
} /* volle Viewport-Höhe */
.sidebar {
  width: 25vw;
} /* 25% der Viewport-Breite */

/* Relative Einheiten */
p {
  font-size: 1.2em;
} /* 1.2x Schriftgröße des Elternelements */
h1 {
  font-size: 2rem;
} /* 2x Schriftgröße der Wurzel */

/* Prozentuale Einheiten */
.container {
  width: 80%;
}
.column {
  width: 50%;
}

/* CSS Grid responsiv */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

/* Flexbox responsiv */
.flex-container {
  display: flex;
  flex-wrap: wrap;
}
```

## Animationen & Übergänge

### CSS Übergänge (Transitions)

Sanfte Änderungen zwischen Eigenschaftswerten.

```css
/* Grundlegender Übergang */
.button {
  background-color: blue;
  transition: background-color 0.3s ease;
}
.button:hover {
  background-color: red;
}

/* Mehrere Eigenschaften */
.card {
  transform: scale(1);
  opacity: 1;
  transition: all 0.3s ease-in-out;
}
.card:hover {
  transform: scale(1.05);
  opacity: 0.8;
}

/* Einzelne Übergänge */
.element {
  transition-property: width, height;
  transition-duration: 0.5s, 1s;
  transition-timing-function: ease, linear;
}
```

### CSS Animationen

Erstellen Sie komplexe Animationen mit Keyframes.

```css
/* Keyframes definieren */
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

/* Animationen anwenden */
.slide-in {
  animation: slideIn 0.5s ease-out;
}
.pulse {
  animation: pulse 2s infinite;
}

/* Animations-Kurzschreibweise */
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

## CSS Variablen & Funktionen

### CSS Variablen

Definieren und verwenden Sie benutzerdefinierte Eigenschaften für konsistentes Theming.

```css
/* Variablen definieren */
:root {
  --primary-color: #3498db;
  --secondary-color: #2ecc71;
  --font-size-large: 24px;
  --border-radius: 8px;
}

/* Variablen verwenden */
.button {
  background-color: var(--primary-color);
  border-radius: var(--border-radius);
}

/* Fallback-Werte */
.text {
  color: var(--text-color, #333);
}

/* Lokale Variablen */
.card {
  --card-padding: 20px;
  padding: var(--card-padding);
}
```

### CSS Funktionen

CSS verfügt über eine Reihe integrierter Funktionen für Berechnungen und dynamische Werte.

```css
/* Calc Funktion */
.container {
  width: calc(100% - 40px);
  height: calc(100vh - 60px);
}

/* Min/Max Funktionen */
.responsive {
  width: min(90%, 1200px);
  font-size: max(16px, 1.2vw);
  height: clamp(200px, 50vh, 400px);
}

/* Farb-Funktionen */
.element {
  background-color: hsl(200, 50%, 50%);
  color: rgb(255, 87, 51);
}

/* Transform Funktionen */
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

## Best Practices & Organisation

### CSS Organisation

Strukturieren Sie Ihr CSS für Wartbarkeit.

```css
/* Sinnvolle Klassennamen verwenden */
.hero-section {
}
.primary-button {
}
.navigation-menu {
}

/* BEM Methodik */
.block {
}
.block__element {
}
.block--modifier {
}

/* Beispiel */
.card {
}
.card__header {
}
.card__body {
}
.card--featured {
}

/* Verwandte Stile gruppieren */
/* ===== LAYOUT ===== */
.container {
}
.grid {
}

/* ===== KOMPONENTEN ===== */
.button {
}
.card {
}
```

### Performance & Optimierung

Schreiben Sie effizientes CSS für bessere Leistung.

```css
/* Tiefes Nesting vermeiden */
/* Schlecht */
.header .nav ul li a {
}

/* Gut */
.nav-link {
}

/* Effiziente Selektoren verwenden */
/* Schlecht */
body div.container > p {
}

/* Gut */
.content-text {
}

/* Repaints minimieren */
/* transform anstelle von changing position verwenden */
.element {
  transform: translateX(100px);
  /* anstelle von left: 100px; */
}

/* Vendor-Präfixe gruppieren */
.element {
  -webkit-border-radius: 5px;
  -moz-border-radius: 5px;
  border-radius: 5px;
}
```

## CSS Debugging

### Browser DevTools

CSS in Echtzeit inspizieren und ändern.

```css
/* Häufige Debugging-Schritte */
/* 1. Rechtsklick → Element untersuchen */
/* 2. Berechnete Stile prüfen */
/* 3. Überschriebene Eigenschaften suchen */
/* 4. Änderungen in Echtzeit testen */
/* 5. Geändertes CSS zurück in Ihre Datei kopieren */
```

### Häufige CSS-Probleme

Häufig auftretende Probleme beheben.

```css
/* Box-Modell Probleme */
* {
  box-sizing: border-box;
}

/* Floats löschen */
.clearfix::after {
  content: '';
  display: table;
  clear: both;
}

/* Z-index Probleme */
/* Sicherstellen, dass Elemente für z-index positioniert sind */
.element {
  position: relative;
  z-index: 1;
}
```

### CSS Validierung

Stellen Sie sicher, dass Ihr CSS Standards und Best Practices entspricht.

```css
/* CSS-Validatoren verwenden */
/* W3C CSS Validator */
/* Browser-Kompatibilitätswerkzeuge */

/* Ihren Code kommentieren */
/* ===== HEADER STILE ===== */
.header {
}

/* TODO: Mobile Stile hinzufügen */
/* FIXME: IE-Kompatibilität beheben */

/* Konsistente Formatierung verwenden */
.element {
  property: value;
  property: value;
}
```

## CSS Frameworks & Tools

### CSS-Präprozessoren

Erweitern Sie CSS um Variablen, Verschachtelung und Funktionen.

```scss
/* SCSS/Sass Beispiel */
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
/* Less Beispiel */
@primary-color: #3498db;

.button {
  background-color: @primary-color;

  &:hover {
    background-color: lighten(@primary-color, 10%);
  }
}
```

### CSS-in-JS & Moderne Tools

Moderne Ansätze zum Styling in Webanwendungen.

```css
/* PostCSS Plugins */
/* Autoprefixer - fügt Vendor-Präfixe hinzu */
/* PurgeCSS - entfernt ungenutztes CSS */

/* CSS Modules */
.button {
  composes: base-button;
  background-color: blue;
}
```

```javascript
/* Utility-first CSS (Tailwind) */
;<div class="flex items-center justify-center p-4 bg-blue-500">
  <span class="text-white font-bold">Button</span>
</div>

/* CSS-in-JS (Styled Components) */
const Button = styled.button`
  background: ${(props) => (props.primary ? 'blue' : 'white')};
  padding: 1rem 2rem;
`
```

## Relevante Links

- <router-link to="/html">HTML Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/react">React Spickzettel</router-link>
- <router-link to="/web-development">Webentwicklung Spickzettel</router-link>
````

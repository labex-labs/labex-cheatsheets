---
title: 'CSS Cheatsheet | LabEx'
description: 'Learn CSS3 with this comprehensive cheatsheet. Quick reference for CSS selectors, flexbox, grid, animations, responsive design, and modern styling techniques for web developers.'
pdfUrl: '/cheatsheets/pdf/css-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
CSS Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/css">Learn CSS with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn CSS web styling through hands-on labs and real-world scenarios. LabEx provides comprehensive CSS courses covering essential properties, selectors, layout techniques, responsive design, and modern features. Master efficient web styling and layout design for modern web development workflows.
</base-disclaimer-content>
</base-disclaimer>

## CSS Syntax & Selectors

### Basic Syntax

CSS consists of selectors and declarations. The selector targets HTML elements, and declarations set property values.

```css
/* Basic syntax */
selector {
  property: value;
  property: value;
}

/* Example */
p {
  color: red;
  font-size: 16px;
}
```

### Element Selectors

Target HTML elements by their tag name.

```css
/* Select all paragraphs */
p {
  color: blue;
}

/* Select all headings */
h1 {
  font-size: 2em;
}

/* Select all links */
a {
  text-decoration: none;
}
```

### Class Selectors

Target elements with specific class attributes.

```css
/* Select elements with class="highlight" */
.highlight {
  background-color: yellow;
}

/* Select paragraphs with class="intro" */
p.intro {
  font-weight: bold;
}

/* Multiple classes */
.large.bold {
  font-size: 20px;
  font-weight: bold;
}
```

### ID Selectors

Target elements with specific ID attributes.

```css
/* Select element with id="header" */
#header {
  background-color: #333;
}

/* IDs should be unique per page */
#navigation {
  position: fixed;
}
```

### Attribute Selectors

Target elements with certain attributes using attribute selectors.

```css
/* Elements with title attribute */
[title] {
  cursor: help;
}

/* Links to external sites */
a[href^='http'] {
  color: red;
}

/* Input elements of type text */
input[type='text'] {
  border: 1px solid #ccc;
}
```

### Pseudo-classes

Pseudo-classes apply CSS based on state changes and user interactions.

```css
/* Link states */
a:hover {
  color: red;
}
a:visited {
  color: purple;
}
a:active {
  color: orange;
}

/* Form states */
input:focus {
  border-color: blue;
}
input:invalid {
  border-color: red;
}

/* Structural pseudo-classes */
li:first-child {
  font-weight: bold;
}
li:nth-child(odd) {
  background-color: #f0f0f0;
}
```

## Box Model & Layout

### Content: `width` / `height`

The actual content area of the element.

```css
/* Set dimensions */
div {
  width: 300px;
  height: 200px;
}

/* Responsive sizing */
.container {
  width: 100%;
  max-width: 1200px;
}

/* Min/max constraints */
.box {
  min-height: 100px;
  max-width: 500px;
}
```

### Padding: `padding`

Space between content and border, inside the element.

```css
/* All sides */
div {
  padding: 20px;
}

/* Individual sides */
div {
  padding-top: 10px;
  padding-right: 15px;
}

/* Shorthand: top right bottom left */
div {
  padding: 10px 15px 20px 5px;
}
```

### Border: `border`

Borders provide a frame for elements with customizable size, style and color.

```css
/* Border shorthand */
div {
  border: 2px solid #333;
}

/* Individual properties */
div {
  border-width: 1px;
  border-style: dashed;
  border-color: red;
}

/* Individual sides */
div {
  border-bottom: 3px solid blue;
}
```

### Margin: `margin`

Space outside the border, between elements.

```css
/* All sides */
div {
  margin: 20px;
}

/* Center horizontally */
div {
  margin: 0 auto;
}

/* Individual sides */
div {
  margin-top: 30px;
  margin-bottom: 10px;
}

/* Negative margins */
div {
  margin-left: -20px;
}
```

## Text & Typography

### Font Properties

Control font family, size, weight, and style.

```css
/* Font family */
body {
  font-family: Arial, sans-serif;
}

/* Google Fonts */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
body {
  font-family: 'Roboto', sans-serif;
}

/* Font size */
h1 {
  font-size: 2rem;
}
p {
  font-size: 16px;
}

/* Font weight */
h2 {
  font-weight: bold;
}
span {
  font-weight: 300;
}
```

### Text Alignment

Control text positioning and spacing.

```css
/* Horizontal alignment */
h1 {
  text-align: center;
}
p {
  text-align: justify;
}

/* Line height */
p {
  line-height: 1.6;
}

/* Letter and word spacing */
h1 {
  letter-spacing: 2px;
}
p {
  word-spacing: 4px;
}
```

### Text Styling

Add decorations and transformations to text.

```css
/* Text decoration */
a {
  text-decoration: underline;
}
.strike {
  text-decoration: line-through;
}

/* Text transformation */
.uppercase {
  text-transform: uppercase;
}
.capitalize {
  text-transform: capitalize;
}

/* Text shadow */
h1 {
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}
```

### Colors

CSS provides several different ways to specify colors for various styling needs.

```css
/* Color formats */
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

/* HSL colors */
header {
  background-color: hsl(200, 100%, 50%);
}

/* CSS Variables for colors */
:root {
  --primary-color: #3498db;
}
.button {
  background-color: var(--primary-color);
}
```

## Flexbox Layout

### Flex Container Properties

Properties applied to the parent container.

```css
/* Enable flexbox */
.container {
  display: flex;
}

/* Flex direction */
.container {
  flex-direction: row; /* default */
  flex-direction: column;
  flex-direction: row-reverse;
}

/* Justify content (main axis) */
.container {
  justify-content: flex-start; /* default */
  justify-content: center;
  justify-content: space-between;
  justify-content: space-around;
}

/* Align items (cross axis) */
.container {
  align-items: stretch; /* default */
  align-items: center;
  align-items: flex-start;
}
```

### Flex Item Properties

Properties applied to child elements.

```css
/* Flex grow/shrink */
.item {
  flex-grow: 1; /* grow to fill space */
  flex-shrink: 1; /* shrink if needed */
  flex-basis: auto; /* initial size */
}

/* Shorthand */
.item {
  flex: 1; /* flex: 1 1 0% */
  flex: 0 0 200px; /* fixed width */
}

/* Individual alignment */
.item {
  align-self: center;
  align-self: flex-end;
}

/* Order */
.item {
  order: 2; /* change visual order */
}
```

## CSS Grid Layout

### Grid Container

Define grid structure and properties.

```css
/* Enable grid */
.grid-container {
  display: grid;
}

/* Define columns and rows */
.grid-container {
  grid-template-columns: 1fr 2fr 1fr;
  grid-template-rows: 100px auto 50px;
}

/* Grid gaps */
.grid-container {
  gap: 20px;
  column-gap: 30px;
  row-gap: 10px;
}

/* Named grid areas */
.grid-container {
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}
```

### Grid Items

Position and size grid items.

```css
/* Grid positioning */
.grid-item {
  grid-column: 1 / 3; /* span columns 1-2 */
  grid-row: 2 / 4; /* span rows 2-3 */
}

/* Shorthand */
.grid-item {
  grid-area: 2 / 1 / 4 / 3; /* row-start / col-start / row-end / col-end */
}

/* Named areas */
.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}

/* Auto placement */
.grid-item {
  grid-column: span 2; /* span 2 columns */
  grid-row: span 3; /* span 3 rows */
}
```

## Positioning

### Position Property

Control element positioning behavior.

```css
/* Static (default) */
.element {
  position: static;
}

/* Relative positioning */
.element {
  position: relative;
  top: 20px;
  left: 10px;
}

/* Absolute positioning */
.element {
  position: absolute;
  top: 0;
  right: 0;
}

/* Fixed positioning */
.navbar {
  position: fixed;
  top: 0;
  width: 100%;
}

/* Sticky positioning */
.sidebar {
  position: sticky;
  top: 20px;
}
```

### Z-Index & Stacking

Control the order in which elements layer on top of each other using z-index and stacking context.

```css
/* Stacking order */
.modal {
  position: fixed;
  z-index: 1000;
}
.overlay {
  position: absolute;
  z-index: 999;
}

/* Creating stacking context */
.container {
  position: relative;
  z-index: 0;
}

/* Common z-index values */
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

## Responsive Design

### Media Queries

Apply styles based on device characteristics.

```css
/* Mobile first approach */
.container {
  width: 100%;
}

/* Tablet styles */
@media (min-width: 768px) {
  .container {
    width: 750px;
  }
}

/* Desktop styles */
@media (min-width: 1024px) {
  .container {
    width: 960px;
  }
}

/* Print styles */
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

### Responsive Units

Use relative units for flexible layouts.

```css
/* Viewport units */
.hero {
  height: 100vh;
} /* full viewport height */
.sidebar {
  width: 25vw;
} /* 25% of viewport width */

/* Relative units */
p {
  font-size: 1.2em;
} /* 1.2x parent font size */
h1 {
  font-size: 2rem;
} /* 2x root font size */

/* Percentage units */
.container {
  width: 80%;
}
.column {
  width: 50%;
}

/* CSS Grid responsive */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

/* Flexbox responsive */
.flex-container {
  display: flex;
  flex-wrap: wrap;
}
```

## Animations & Transitions

### CSS Transitions

Smooth changes between property values.

```css
/* Basic transition */
.button {
  background-color: blue;
  transition: background-color 0.3s ease;
}
.button:hover {
  background-color: red;
}

/* Multiple properties */
.card {
  transform: scale(1);
  opacity: 1;
  transition: all 0.3s ease-in-out;
}
.card:hover {
  transform: scale(1.05);
  opacity: 0.8;
}

/* Individual transitions */
.element {
  transition-property: width, height;
  transition-duration: 0.5s, 1s;
  transition-timing-function: ease, linear;
}
```

### CSS Animations

Create complex animations with keyframes.

```css
/* Define keyframes */
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

/* Apply animations */
.slide-in {
  animation: slideIn 0.5s ease-out;
}
.pulse {
  animation: pulse 2s infinite;
}

/* Animation shorthand */
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

## CSS Variables & Functions

### CSS Variables

Define and use custom properties for consistent theming.

```css
/* Define variables */
:root {
  --primary-color: #3498db;
  --secondary-color: #2ecc71;
  --font-size-large: 24px;
  --border-radius: 8px;
}

/* Use variables */
.button {
  background-color: var(--primary-color);
  border-radius: var(--border-radius);
}

/* Fallback values */
.text {
  color: var(--text-color, #333);
}

/* Local variables */
.card {
  --card-padding: 20px;
  padding: var(--card-padding);
}
```

### CSS Functions

CSS has a range of built-in functions for calculations and dynamic values.

```css
/* Calc function */
.container {
  width: calc(100% - 40px);
  height: calc(100vh - 60px);
}

/* Min/max functions */
.responsive {
  width: min(90%, 1200px);
  font-size: max(16px, 1.2vw);
  height: clamp(200px, 50vh, 400px);
}

/* Color functions */
.element {
  background-color: hsl(200, 50%, 50%);
  color: rgb(255, 87, 51);
}

/* Transform functions */
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

## Best Practices & Organization

### CSS Organization

Structure your CSS for maintainability.

```css
/* Use meaningful class names */
.hero-section {
}
.primary-button {
}
.navigation-menu {
}

/* BEM methodology */
.block {
}
.block__element {
}
.block--modifier {
}

/* Example */
.card {
}
.card__header {
}
.card__body {
}
.card--featured {
}

/* Group related styles */
/* ===== LAYOUT ===== */
.container {
}
.grid {
}

/* ===== COMPONENTS ===== */
.button {
}
.card {
}
```

### Performance & Optimization

Write efficient CSS for better performance.

```css
/* Avoid deep nesting */
/* Bad */
.header .nav ul li a {
}

/* Good */
.nav-link {
}

/* Use efficient selectors */
/* Bad */
body div.container > p {
}

/* Good */
.content-text {
}

/* Minimize repaints */
/* Use transform instead of changing position */
.element {
  transform: translateX(100px);
  /* instead of left: 100px; */
}

/* Group vendor prefixes */
.element {
  -webkit-border-radius: 5px;
  -moz-border-radius: 5px;
  border-radius: 5px;
}
```

## CSS Debugging

### Browser DevTools

Inspect and modify CSS in real-time.

```css
/* Common debugging steps */
/* 1. Right-click → Inspect Element */
/* 2. Check Computed styles */
/* 3. Look for overridden properties */
/* 4. Test changes in real-time */
/* 5. Copy modified CSS back to your file */
```

### Common CSS Issues

Troubleshoot frequently encountered problems.

```css
/* Box model issues */
* {
  box-sizing: border-box;
}

/* Clearing floats */
.clearfix::after {
  content: '';
  display: table;
  clear: both;
}

/* Z-index issues */
/* Ensure positioned elements for z-index to work */
.element {
  position: relative;
  z-index: 1;
}
```

### CSS Validation

Ensure your CSS follows standards and best practices.

```css
/* Use CSS validators */
/* W3C CSS Validator */
/* Browser compatibility tools */

/* Comment your code */
/* ===== HEADER STYLES ===== */
.header {
}

/* TODO: Add mobile styles */
/* FIXME: Fix IE compatibility */

/* Use consistent formatting */
.element {
  property: value;
  property: value;
}
```

## CSS Frameworks & Tools

### CSS Preprocessors

Extend CSS with variables, nesting, and functions.

```scss
/* SCSS/Sass example */
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
/* Less example */
@primary-color: #3498db;

.button {
  background-color: @primary-color;

  &:hover {
    background-color: lighten(@primary-color, 10%);
  }
}
```

### CSS-in-JS & Modern Tools

Modern approaches to styling in web applications.

```css
/* PostCSS plugins */
/* Autoprefixer - adds vendor prefixes */
/* PurgeCSS - removes unused CSS */

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

## Relevant Links

- <router-link to="/html">HTML Cheatsheet</router-link>
- <router-link to="/javascript">JavaScript Cheatsheet</router-link>
- <router-link to="/react">React Cheatsheet</router-link>
- <router-link to="/web-development">Web Development Cheatsheet</router-link>

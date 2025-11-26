---
title: 'CSS 速查表'
description: '使用我们涵盖基本命令、概念和最佳实践的综合 CSS 速查表进行学习。'
pdfUrl: '/cheatsheets/pdf/css-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
CSS 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/css">通过实践实验室学习 CSS</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 CSS 网页样式。LabEx 提供全面的 CSS 课程，涵盖基本属性、选择器、布局技术、响应式设计和现代特性。掌握高效的网页样式和布局设计，以适应现代 Web 开发工作流程。
</base-disclaimer-content>
</base-disclaimer>

## CSS 语法与选择器

### 基本语法

CSS 由选择器和声明组成。选择器定位 HTML 元素，声明设置属性值。

```css
/* 基本语法 */
selector {
  property: value;
  property: value;
}

/* 示例 */
p {
  color: red;
  font-size: 16px;
}
```

### 元素选择器

按标签名称选择 HTML 元素。

```css
/* 选择所有段落 */
p {
  color: blue;
}

/* 选择所有标题 */
h1 {
  font-size: 2em;
}

/* 选择所有链接 */
a {
  text-decoration: none;
}
```

### 类选择器

选择具有特定 class 属性的元素。

```css
/* 选择 class="highlight" 的元素 */
.highlight {
  background-color: yellow;
}

/* 选择 class="intro" 的段落 */
p.intro {
  font-weight: bold;
}

/* 多个类 */
.large.bold {
  font-size: 20px;
  font-weight: bold;
}
```

### ID 选择器

选择具有特定 ID 属性的元素。

```css
/* 选择 id="header" 的元素 */
#header {
  background-color: #333;
}

/* ID 在每页上应是唯一的 */
#navigation {
  position: fixed;
}
```

### 属性选择器

使用属性选择器选择具有特定属性的元素。

```css
/* 具有 title 属性的元素 */
[title] {
  cursor: help;
}

/* 指向外部站点的链接 */
a[href^='http'] {
  color: red;
}

/* 类型为 text 的 input 元素 */
input[type='text'] {
  border: 1px solid #ccc;
}
```

### 伪类

伪类根据状态变化和用户交互应用 CSS。

```css
/* 链接状态 */
a:hover {
  color: red;
}
a:visited {
  color: purple;
}
a:active {
  color: orange;
}

/* 表单状态 */
input:focus {
  border-color: blue;
}
input:invalid {
  border-color: red;
}

/* 结构化伪类 */
li:first-child {
  font-weight: bold;
}
li:nth-child(odd) {
  background-color: #f0f0f0;
}
```

## 盒模型与布局

### 内容：`width` / `height`

元素的实际内容区域。

```css
/* 设置尺寸 */
div {
  width: 300px;
  height: 200px;
}

/* 响应式尺寸 */
.container {
  width: 100%;
  max-width: 1200px;
}

/* 最小/最大约束 */
.box {
  min-height: 100px;
  max-width: 500px;
}
```

### 内边距：`padding`

内容与边框之间的空间，位于元素内部。

```css
/* 所有边 */
div {
  padding: 20px;
}

/* 单独的边 */
div {
  padding-top: 10px;
  padding-right: 15px;
}

/* 简写：上 右 下 左 */
div {
  padding: 10px 15px 20px 5px;
}
```

### 边框：`border`

边框为元素提供框架，具有可自定义的大小、样式和颜色。

```css
/* 边框简写 */
div {
  border: 2px solid #333;
}

/* 单独的属性 */
div {
  border-width: 1px;
  border-style: dashed;
  border-color: red;
}

/* 单独的边 */
div {
  border-bottom: 3px solid blue;
}
```

### 外边距：`margin`

位于边框外部的空间，用于元素之间的间隔。

```css
/* 所有边 */
div {
  margin: 20px;
}

/* 水平居中 */
div {
  margin: 0 auto;
}

/* 单独的边 */
div {
  margin-top: 30px;
  margin-bottom: 10px;
}

/* 负外边距 */
div {
  margin-left: -20px;
}
```

## 文本与排版

### 字体属性

控制字体族、大小、粗细和样式。

```css
/* 字体族 */
body {
  font-family: Arial, sans-serif;
}

/* Google 字体 */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
body {
  font-family: 'Roboto', sans-serif;
}

/* 字体大小 */
h1 {
  font-size: 2rem;
}
p {
  font-size: 16px;
}

/* 字体粗细 */
h2 {
  font-weight: bold;
}
span {
  font-weight: 300;
}
```

### 文本对齐

控制文本定位和间距。

```css
/* 水平对齐 */
h1 {
  text-align: center;
}
p {
  text-align: justify;
}

/* 行高 */
p {
  line-height: 1.6;
}

/* 字母和单词间距 */
h1 {
  letter-spacing: 2px;
}
p {
  word-spacing: 4px;
}
```

### 文本样式

向文本添加装饰和转换。

```css
/* 文本装饰 */
a {
  text-decoration: underline;
}
.strike {
  text-decoration: line-through;
}

/* 文本转换 */
.uppercase {
  text-transform: uppercase;
}
.capitalize {
  text-transform: capitalize;
}

/* 文本阴影 */
h1 {
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}
```

### 颜色

CSS 提供了多种指定颜色值的方式，以满足各种样式需求。

```css
/* 颜色格式 */
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

/* HSL 颜色 */
header {
  background-color: hsl(200, 100%, 50%);
}

/* CSS 变量用于颜色 */
:root {
  --primary-color: #3498db;
}
.button {
  background-color: var(--primary-color);
}
```

## Flexbox 布局

### 弹性容器属性

应用于父容器的属性。

```css
/* 启用 flexbox */
.container {
  display: flex;
}

/* 弹性方向 */
.container {
  flex-direction: row; /* 默认 */
  flex-direction: column;
  flex-direction: row-reverse;
}

/* 对齐内容 (主轴) */
.container {
  justify-content: flex-start; /* 默认 */
  justify-content: center;
  justify-content: space-between;
  justify-content: space-around;
}

/* 对齐项目 (交叉轴) */
.container {
  align-items: stretch; /* 默认 */
  align-items: center;
  align-items: flex-start;
}
```

### 弹性项目属性

应用于子元素的属性。

```css
/* 弹性增长/收缩 */
.item {
  flex-grow: 1; /* 增长以填充空间 */
  flex-shrink: 1; /* 需要时收缩 */
  flex-basis: auto; /* 初始大小 */
}

/* 简写 */
.item {
  flex: 1; /* flex: 1 1 0% */
  flex: 0 0 200px; /* 固定宽度 */
}

/* 单独对齐 */
.item {
  align-self: center;
  align-self: flex-end;
}

/* 顺序 */
.item {
  order: 2; /* 改变视觉顺序 */
}
```

## CSS Grid 布局

### Grid 容器

定义网格结构和属性。

```css
/* 启用 grid */
.grid-container {
  display: grid;
}

/* 定义列和行 */
.grid-container {
  grid-template-columns: 1fr 2fr 1fr;
  grid-template-rows: 100px auto 50px;
}

/* 网格间距 */
.grid-container {
  gap: 20px;
  column-gap: 30px;
  row-gap: 10px;
}

/* 命名网格区域 */
.grid-container {
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}
```

### Grid 项目

定位和调整网格项目的大小。

```css
/* 网格定位 */
.grid-item {
  grid-column: 1 / 3; /* 跨越第 1 到第 2 列 */
  grid-row: 2 / 4; /* 跨越第 2 到第 3 行 */
}

/* 简写 */
.grid-item {
  grid-area: 2 / 1 / 4 / 3; /* row-start / col-start / row-end / col-end */
}

/* 命名区域 */
.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}

/* 自动放置 */
.grid-item {
  grid-column: span 2; /* 跨越 2 列 */
  grid-row: span 3; /* 跨越 3 行 */
}
```

## 定位

### Position 属性

控制元素的定位行为。

```css
/* Static (默认) */
.element {
  position: static;
}

/* Relative 定位 */
.element {
  position: relative;
  top: 20px;
  left: 10px;
}

/* Absolute 定位 */
.element {
  position: absolute;
  top: 0;
  right: 0;
}

/* Fixed 定位 */
.navbar {
  position: fixed;
  top: 0;
  width: 100%;
}

/* Sticky 定位 */
.sidebar {
  position: sticky;
  top: 20px;
}
```

### Z-Index 与堆叠顺序

使用 z-index 和堆叠上下文控制元素在 Z 轴上的层叠顺序。

```css
/* 堆叠顺序 */
.modal {
  position: fixed;
  z-index: 1000;
}
.overlay {
  position: absolute;
  z-index: 999;
}

/* 创建堆叠上下文 */
.container {
  position: relative;
  z-index: 0;
}

/* 常见的 z-index 值 */
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

## 响应式设计

### 媒体查询

根据设备特性应用样式。

```css
/* 移动优先方法 */
.container {
  width: 100%;
}

/* 平板电脑样式 */
@media (min-width: 768px) {
  .container {
    width: 750px;
  }
}

/* 桌面样式 */
@media (min-width: 1024px) {
  .container {
    width: 960px;
  }
}

/* 打印样式 */
@media print {
  body {
    font-size: 12pt;
  }
  .no-print {
    display: none;
  }
}

/* 方向 */
@media (orientation: landscape) {
  .sidebar {
    display: block;
  }
}
```

### 响应式单位

使用相对单位实现灵活布局。

```css
/* 视口单位 */
.hero {
  height: 100vh;
} /* 100% 视口高度 */
.sidebar {
  width: 25vw;
} /* 25% 视口宽度 */

/* 相对单位 */
p {
  font-size: 1.2em;
} /* 父字体大小的 1.2 倍 */
h1 {
  font-size: 2rem;
} /* 根字体大小的 2 倍 */

/* 百分比单位 */
.container {
  width: 80%;
}
.column {
  width: 50%;
}

/* CSS Grid 响应式 */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

/* Flexbox 响应式 */
.flex-container {
  display: flex;
  flex-wrap: wrap;
}
```

## 动画与过渡

### CSS 过渡

属性值之间的平滑变化。

```css
/* 基本过渡 */
.button {
  background-color: blue;
  transition: background-color 0.3s ease;
}
.button:hover {
  background-color: red;
}

/* 多个属性 */
.card {
  transform: scale(1);
  opacity: 1;
  transition: all 0.3s ease-in-out;
}
.card:hover {
  transform: scale(1.05);
  opacity: 0.8;
}

/* 单独的过渡 */
.element {
  transition-property: width, height;
  transition-duration: 0.5s, 1s;
  transition-timing-function: ease, linear;
}
```

### CSS 动画

使用关键帧创建复杂的动画。

```css
/* 定义关键帧 */
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

/* 应用动画 */
.slide-in {
  animation: slideIn 0.5s ease-out;
}
.pulse {
  animation: pulse 2s infinite;
}

/* 动画简写 */
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

## CSS 变量与函数

### CSS 变量

定义和使用自定义属性以实现一致的主题化。

```css
/* 定义变量 */
:root {
  --primary-color: #3498db;
  --secondary-color: #2ecc71;
  --font-size-large: 24px;
  --border-radius: 8px;
}

/* 使用变量 */
.button {
  background-color: var(--primary-color);
  border-radius: var(--border-radius);
}

/* 备用值 */
.text {
  color: var(--text-color, #333);
}

/* 局部变量 */
.card {
  --card-padding: 20px;
  padding: var(--card-padding);
}
```

### CSS 函数

CSS 拥有一系列内置函数，用于计算和动态值。

```css
/* Calc 函数 */
.container {
  width: calc(100% - 40px);
  height: calc(100vh - 60px);
}

/* Min/max 函数 */
.responsive {
  width: min(90%, 1200px);
  font-size: max(16px, 1.2vw);
  height: clamp(200px, 50vh, 400px);
}

/* 颜色函数 */
.element {
  background-color: hsl(200, 50%, 50%);
  color: rgb(255, 87, 51);
}

/* 转换函数 */
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

## 最佳实践与组织

### CSS 组织

构建可维护的 CSS 结构。

```css
/* 使用有意义的类名 */
.hero-section {
}
.primary-button {
}
.navigation-menu {
}

/* BEM 方法论 */
.block {
}
.block__element {
}
.block--modifier {
}

/* 示例 */
.card {
}
.card__header {
}
.card__body {
}
.card--featured {
}

/* 组合相关样式 */
/* ===== 布局 ===== */
.container {
}
.grid {
}

/* ===== 组件 ===== */
.button {
}
.card {
}
```

### 性能与优化

编写高效的 CSS 以获得更好的性能。

```css
/* 避免深度嵌套 */
/* 差 */
.header .nav ul li a {
}

/* 好 */
.nav-link {
}

/* 使用高效的选择器 */
/* 差 */
body div.container > p {
}

/* 好 */
.content-text {
}

/* 最小化重绘 */
/* 使用 transform 代替改变 position */
.element {
  transform: translateX(100px);
  /* 代替 left: 100px; */
}

/* 组合供应商前缀 */
.element {
  -webkit-border-radius: 5px;
  -moz-border-radius: 5px;
  border-radius: 5px;
}
```

## CSS 调试

### 浏览器开发者工具

实时检查和修改 CSS。

```css
/* 常见调试步骤 */
/* 1. 右键点击 → 检查元素 */
/* 2. 检查计算出的样式 */
/* 3. 查看被覆盖的属性 */
/* 4. 实时测试更改 */
/* 5. 将修改后的 CSS 复制回文件 */
```

### 常见 CSS 问题

解决经常遇到的问题。

```css
/* 盒模型问题 */
* {
  box-sizing: border-box;
}

/* 清除浮动 */
.clearfix::after {
  content: '';
  display: table;
  clear: both;
}

/* Z-index 问题 */
/* 确保 z-index 生效的元素已定位 */
.element {
  position: relative;
  z-index: 1;
}
```

### CSS 验证

确保您的 CSS 符合标准和最佳实践。

```css
/* 使用 CSS 验证器 */
/* W3C CSS 验证器 */
/* 浏览器兼容性工具 */

/* 注释您的代码 */
/* ===== 头部样式 ===== */
.header {
}

/* TODO: 添加移动端样式 */
/* FIXME: 修复 IE 兼容性 */

/* 使用一致的格式 */
.element {
  property: value;
  property: value;
}
```

## CSS 框架与工具

### CSS 预处理器

使用变量、嵌套和函数扩展 CSS。

```scss
/* SCSS/Sass 示例 */
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
/* Less 示例 */
@primary-color: #3498db;

.button {
  background-color: @primary-color;

  &:hover {
    background-color: lighten(@primary-color, 10%);
  }
}
```

### CSS-in-JS 与现代工具

Web 应用程序中样式化的现代方法。

```css
/* PostCSS 插件 */
/* Autoprefixer - 添加供应商前缀 */
/* PurgeCSS - 移除未使用的 CSS */

/* CSS Modules */
.button {
  composes: base-button;
  background-color: blue;
}
```

```javascript
/* 实用工具优先的 CSS (Tailwind) */
;<div class="flex items-center justify-center p-4 bg-blue-500">
  <span class="text-white font-bold">Button</span>
</div>

/* CSS-in-JS (Styled Components) */
const Button = styled.button`
  background: ${(props) => (props.primary ? 'blue' : 'white')};
  padding: 1rem 2rem;
`
```

## 相关链接

- <router-link to="/html">HTML 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/react">React 速查表</router-link>
- <router-link to="/web-development">Web 开发速查表</router-link>

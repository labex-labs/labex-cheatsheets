---
title: 'Web 开发速查表'
description: '使用我们涵盖关键命令、概念和最佳实践的综合速查表，学习 Web 开发。'
pdfUrl: '/cheatsheets/pdf/web-development-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Web 开发速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/web-development">通过实践实验室学习 Web 开发</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Web 开发。LabEx 提供全面的 Web 开发课程，涵盖基本的 HTML、CSS、JavaScript、DOM 操作和响应式设计。掌握构建具有交互性和响应性的网站所需的现代 Web 开发工作流程。
</base-disclaimer-content>
</base-disclaimer>

## HTML 基础与文档结构

### 基本 HTML 结构：`<!DOCTYPE html>`

创建每个网页的基础。

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

### 语义化元素：`<header>` / `<main>` / `<footer>`

使用有意义的 HTML5 语义化元素以获得更好的结构。

```html
<header>
  <nav>
    <ul>
      <li><a href="#home">主页</a></li>
      <li><a href="#about">关于</a></li>
    </ul>
  </nav>
</header>
<main>
  <section>
    <h1>欢迎</h1>
    <p>主要内容在此</p>
  </section>
</main>
<footer>
  <p>© 2024 我的网站</p>
</footer>
```

### 文本元素：`<h1>` 到 `<h6>` / `<p>`

使用正确的标题层级和段落来构建内容结构。

```html
<h1>主标题</h1>
<h2>章节标题</h2>
<h3>子章节</h3>
<p>这是一个带有<strong>粗体文本</strong>和<em>斜体文本</em>的段落。</p>
<p>另一个带有<a href="https://example.com">链接</a>的段落。</p>
```

### 列表：`<ul>` / `<ol>` / `<li>`

创建有组织的、信息化的列表。

```html
<!-- 无序列表 -->
<ul>
  <li>第一项</li>
  <li>第二项</li>
  <li>第三项</li>
</ul>

<!-- 有序列表 -->
<ol>
  <li>步骤 1</li>
  <li>步骤 2</li>
  <li>步骤 3</li>
</ol>
```

### 图像与媒体：`<img>` / `<video>` / `<audio>`

使用正确的属性嵌入多媒体内容。

```html
<!-- 带有 alt 文本的图像 -->
<img src="image.jpg" alt="图像的描述" width="300" />

<!-- 视频元素 -->
<video controls width="400">
  <source src="video.mp4" type="video/mp4" />
  您的浏览器不支持视频。
</video>

<!-- 音频元素 -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
</audio>
```

### 表格：`<table>` / `<tr>` / `<td>`

使用正确的结构显示表格数据。

```html
<table>
  <thead>
    <tr>
      <th>姓名</th>
      <th>年龄</th>
      <th>城市</th>
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

## 表单与用户输入

### 表单结构：`<form>`

为用户输入和控件创建容器。

```html
<form action="/submit" method="POST">
  <label for="name">姓名：</label>
  <input type="text" id="name" name="name" required />

  <label for="email">电子邮件：</label>
  <input type="email" id="email" name="email" required />

  <button type="submit">提交</button>
</form>
```

### 输入类型：`type="text"` / `type="email"`

为不同数据使用适当的输入类型。

```html
<input type="text" placeholder="输入您的姓名" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="密码" />
<input type="number" min="1" max="100" />
<input type="date" />
<input type="checkbox" id="agree" />
<input type="radio" name="gender" value="male" />
<input type="file" accept=".jpg,.png" />
```

### 表单控件：`<select>` / `<textarea>`

为用户提供各种输入信息的方式。

```html
<select name="country" id="country">
  <option value="">选择一个国家</option>
  <option value="us">美国</option>
  <option value="ca">加拿大</option>
</select>

<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="输入您的消息"
></textarea>
```

## CSS 基础与样式

### CSS 选择器：`element` / `.class` / `#id`

使用不同类型的选择器定位 HTML 元素以进行样式设置。

```css
/* 元素选择器 */
h1 {
  color: blue;
  font-size: 2rem;
}

/* 类选择器 */
.highlight {
  background-color: yellow;
  padding: 10px;
}

/* ID 选择器 */
#header {
  background-color: navy;
  color: white;
}

/* 后代选择器 */
.container p {
  line-height: 1.6;
}
```

### 盒模型：`margin` / `padding` / `border`

使用 CSS 盒模型控制间距和布局。

```css
.box {
  width: 300px;
  height: 200px;
  margin: 20px; /* 外部间距 */
  padding: 15px; /* 内部间距 */
  border: 2px solid black; /* 边框属性 */
}

/* 简写属性 */
.element {
  margin: 10px 20px; /* 上/下 左/右 */
  padding: 10px 15px 20px 25px; /* 上 右下 左 */
  border-radius: 5px; /* 圆角 */
}
```

### Flexbox: `display: flex`

轻松创建灵活且响应式的布局。

```css
.container {
  display: flex;
  justify-content: center; /* 水平对齐 */
  align-items: center; /* 垂直对齐 */
  gap: 20px; /* 项目之间的间距 */
}

.flex-item {
  flex: 1; /* 等宽项目 */
}

/* Flexbox 方向 */
.column-layout {
  display: flex;
  flex-direction: column;
}
```

### Grid 布局：`display: grid`

创建复杂的二维布局。

```css
.grid-container {
  display: grid;
  grid-template-columns: repeat(3, 1fr); /* 3 个等宽的列 */
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

## JavaScript 基础与编程核心概念

### 变量：`let` / `const` / `var`

使用不同的变量声明来存储和操作数据。

```javascript
// 现代变量声明
let name = 'John' // 可以重新赋值
const age = 25 // 不能重新赋值
const colors = ['red', 'blue'] // 数组（内容可以更改）

// 变量类型
let message = 'Hello World' // 字符串 (String)
let count = 42 // 数字 (Number)
let isActive = true // 布尔值 (Boolean)
let data = null // 空值 (Null)
let user = {
  // 对象 (Object)
  name: 'Alice',
  email: 'alice@example.com',
}
```

### 函数：`function` / 箭头函数

使用不同的函数语法创建可重用的代码块。

```javascript
// 函数声明
function greet(name) {
  return `Hello, ${name}!`
}

// 箭头函数
const add = (a, b) => a + b

// 带代码块的箭头函数
const calculateArea = (width, height) => {
  const area = width * height
  return area
}

// 带默认参数的函数
function createUser(name, age = 18) {
  return { name, age }
}
```

### 条件逻辑：`if` / `else` / `switch`

使用条件语句控制程序流程。

```javascript
// If/else 语句
if (age >= 18) {
  console.log('成年人')
} else if (age >= 13) {
  console.log('青少年')
} else {
  console.log('儿童')
}

// 三元运算符
const status = age >= 18 ? 'adult' : 'minor'

// Switch 语句
switch (day) {
  case 'Monday':
    console.log('工作周开始')
    break
  case 'Friday':
    console.log('周五啦！')
    break
  default:
    console.log('普通的一天')
}
```

### 循环：`for` / `while` / 数组方法

迭代数据并重复操作。

```javascript
// For 循环
for (let i = 0; i < 5; i++) {
  console.log(i)
}

// For...of 循环
for (const item of items) {
  console.log(item)
}

// 数组方法
const numbers = [1, 2, 3, 4, 5]
numbers.forEach((num) => console.log(num))
const doubled = numbers.map((num) => num * 2)
const evens = numbers.filter((num) => num % 2 === 0)
const sum = numbers.reduce((total, num) => total + num, 0)
```

## DOM 操作与事件

### 选择元素：`querySelector` / `getElementById`

在 JavaScript 中查找和访问 HTML 元素。

```javascript
// 选择单个元素
const title = document.getElementById('title')
const button = document.querySelector('.btn')
const firstParagraph = document.querySelector('p')

// 选择多个元素
const allButtons = document.querySelectorAll('.btn')
const allParagraphs = document.getElementsByTagName('p')

// 检查元素是否存在
if (button) {
  button.style.color = 'blue'
}
```

### 修改内容：`innerHTML` / `textContent`

更改 HTML 元素的内容和属性。

```javascript
// 更改文本内容
title.textContent = '新标题'
title.innerHTML = '<strong>粗体标题</strong>'

// 修改属性
button.setAttribute('disabled', 'true')
const src = image.getAttribute('src')

// 添加/移除类
button.classList.add('active')
button.classList.remove('hidden')
button.classList.toggle('highlighted')
```

### 事件处理：`addEventListener`

响应用户交互和浏览器事件。

```javascript
// 点击事件
button.addEventListener('click', function () {
  alert('按钮被点击了！')
})

// 表单提交事件
form.addEventListener('submit', function (e) {
  e.preventDefault() // 阻止表单提交
  const formData = new FormData(form)
  console.log(formData.get('username'))
})

// 键盘事件
document.addEventListener('keydown', function (e) {
  if (e.key === 'Enter') {
    console.log('按下了 Enter 键')
  }
})
```

### 创建元素：`createElement` / `appendChild`

动态创建和添加新的 HTML 元素。

```javascript
// 创建新元素
const newDiv = document.createElement('div')
newDiv.textContent = '新内容'
newDiv.className = 'highlight'
// 添加到页面
document.body.appendChild(newDiv)

// 创建列表项
const li = document.createElement('li')
li.innerHTML = "<a href='#'>新链接</a>"
document.querySelector('ul').appendChild(li)

// 移除元素
const oldElement = document.querySelector('.remove-me')
oldElement.remove()
```

## 响应式设计与 CSS 媒体查询

### 视口 Meta 标签：`viewport`

为响应式设计设置正确的视口。

```html
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
```

```css
/* 响应式图像的 CSS */
img {
  max-width: 100%;
  height: auto;
}

/* 响应式容器 */
.container {
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 20px;
}
```

### 媒体查询：`@media`

根据屏幕大小和设备能力应用不同的样式。

```css
/* 移动优先方法 */
.grid {
  display: grid;
  grid-template-columns: 1fr; /* 移动端单列 */
  gap: 20px;
}

/* 平板电脑及以上 */
@media (min-width: 768px) {
  .grid {
    grid-template-columns: repeat(2, 1fr); /* 2 列 */
  }
}

/* 桌面端及以上 */
@media (min-width: 1024px) {
  .grid {
    grid-template-columns: repeat(3, 1fr); /* 3 列 */
  }
}
```

### 弹性单位：`rem` / `em` / `%` / `vw` / `vh`

使用相对单位创建可扩展和响应式的设计。

```css
/* 相对于根字体大小 */
h1 {
  font-size: 2rem;
} /* 如果根字体为 16px，则为 32px */

/* 相对于父级字体大小 */
p {
  font-size: 1.2em;
} /* 父级大小的 1.2 倍 */

/* 基于百分比 */
.sidebar {
  width: 30%;
} /* 父级宽度的 30% */

/* 视口单位 */
.hero {
  height: 100vh; /* 完整的视口高度 */
  width: 100vw; /* 完整的视口宽度 */
}
```

### 响应式排版：`clamp()`

创建随屏幕尺寸缩放的流式排版。

```css
/* 流式排版 */
h1 {
  font-size: clamp(1.5rem, 4vw, 3rem);
  /* 最小值：1.5rem, 首选值：4vw, 最大值：3rem */
}

/* 响应式间距 */
.section {
  padding: clamp(2rem, 5vw, 6rem) clamp(1rem, 3vw, 3rem);
}

/* 容器查询 (较新的浏览器) */
@container (min-width: 400px) {
  .card {
    display: flex;
  }
}
```

## 调试与浏览器开发者工具

### Console 方法：`console.log()` / `console.error()`

使用控制台输出调试和监控代码。

```javascript
// 基本日志记录
console.log('Hello, world!')
console.log('用户数据：', userData)

// 不同级别的日志
console.info('信息消息')
console.warn('警告消息')
console.error('错误消息')

// 分组日志
console.group('用户详情')
console.log('姓名：', user.name)
console.log('电子邮件：', user.email)
console.groupEnd()
```

### 调试技术：`debugger` / 断点

暂停代码执行以检查变量和程序状态。

```javascript
function calculateTotal(items) {
  let total = 0
  debugger // 如果打开了开发者工具，代码将在此处暂停

  for (let item of items) {
    total += item.price
    console.log('当前总计：', total)
  }
  return total
}

// 错误处理
try {
  const result = riskyFunction()
} catch (error) {
  console.error('发生错误：', error.message)
}
```

### 浏览器 DevTools: Elements / Console / Network

使用浏览器工具检查 HTML、调试 JavaScript 和监控网络请求。

```javascript
// 在控制台中检查元素
$0 // Elements 标签页中当前选中的元素
$1 // 上一个选中的元素

// 从控制台查询元素
$('selector') // 等同于 document.querySelector
$$('selector') // 等同于 document.querySelectorAll

// 监控函数
monitor(functionName) // 调用函数时记录日志

// 性能计时
console.time('operation')
// ... 一些代码 ...
console.timeEnd('operation')

// 常见错误及解决方案
// ReferenceError: 变量未定义
// console.log(undefinedVariable); //
```

### 错误类型：`TypeError` / `ReferenceError`

了解常见的 JavaScript 错误及其修复方法。

## 相关链接

- <router-link to="/html">HTML 速查表</router-link>
- <router-link to="/css">CSS 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/react">React 速查表</router-link>

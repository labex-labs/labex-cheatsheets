---
title: 'HTML 速查表 | LabEx'
description: '使用这份全面的速查表学习 HTML5。前端开发人员的 HTML 标签、语义化元素、表单、可访问性和现代 Web 开发标准的快速参考。'
pdfUrl: '/cheatsheets/pdf/html-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
HTML 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/html">通过实践实验学习 HTML</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验和真实场景学习 HTML 网页结构。LabEx 提供全面的 HTML 课程，涵盖基本元素、语义化标记、表单、媒体集成和现代 HTML5 特性。掌握高效的网页结构和内容组织，以适应现代 Web 开发工作流程。
</base-disclaimer-content>
</base-disclaimer>

## HTML 文档结构

### 基本 HTML 文档：`<!DOCTYPE html>`

每个 HTML 文档都以文档类型声明开始，并遵循标准结构。

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Page Title</title>
  </head>
  <body>
    <!-- 页面内容放在这里 -->
  </body>
</html>
```

<BaseQuiz id="html-doctype-1" correct="A">
  <template #question>
    <code><!DOCTYPE html></code> 的目的是什么？
  </template>
  
  <BaseQuizOption value="A" correct>它声明了文档类型和 HTML 版本</BaseQuizOption>
  <BaseQuizOption value="B">它创建了一个新的 HTML 元素</BaseQuizOption>
  <BaseQuizOption value="C">它链接到一个外部样式表</BaseQuizOption>
  <BaseQuizOption value="D">它设置了页面标题</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code><!DOCTYPE html></code> 声明告诉浏览器文档正在使用的 HTML 版本。对于 HTML5，这个简单的声明就足够了，并且应该是每个 HTML 文档的第一行。
  </BaseQuizAnswer>
</BaseQuiz>

### Head 元素：`<head>`

head 部分包含有关文档的元数据。

```html
<!-- 字符编码 -->
<meta charset="UTF-8" />
<!-- 用于响应式设计的视口 -->
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<!-- 页面描述 -->
<meta name="description" content="Page description" />
<!-- 链接到 CSS -->
<link rel="stylesheet" href="styles.css" />
<!-- 链接到 favicon -->
<link rel="icon" href="favicon.ico" />
```

### HTML 注释：`<!-- -->`

注释不会显示，但有助于记录代码。

```html
<!-- 这是一个注释 -->
<!-- 
  多行注释
  用于更长的解释
-->
```

### HTML 元素解剖

HTML 元素由开始标签、内容和结束标签组成。

```html
<!-- 带内容的元素 -->
<p>这是一个段落</p>
<!-- 自闭合元素 -->
<img src="image.jpg" alt="Description" />
<br />
<hr />
<!-- 带属性的元素 -->
<a href="https://example.com" target="_blank">链接</a>
<!-- 嵌套元素 -->
<div>
  <p>嵌套的段落</p>
</div>
```

## 文本内容元素

### 标题：`h1` 到 `h6`

定义内容层次结构和重要性。

```html
<h1>主标题</h1>
<h2>章节标题</h2>
<h3>子章节标题</h3>
<h4>次级子章节标题</h4>
<h5>小标题</h5>
<h6>最小标题</h6>
```

<BaseQuiz id="html-headings-1" correct="B">
  <template #question>
    正确的标题层级结构是怎样的？
  </template>
  
  <BaseQuizOption value="A">h1 应该在页面上多次使用</BaseQuizOption>
  <BaseQuizOption value="B" correct>h1 应作为主标题使用一次，然后是 h2、h3 等</BaseQuizOption>
  <BaseQuizOption value="C">所有标题的重要性都相同</BaseQuizOption>
  <BaseQuizOption value="D">h6 是最重要的标题</BaseQuizOption>
  
  <BaseQuizAnswer>
    HTML 标题应遵循逻辑层次结构：使用一个 <code>h1</code> 作为主页面标题，然后使用 <code>h2</code> 表示主要部分，<code>h3</code> 表示子部分，依此类推。这有助于可访问性和 SEO。
  </BaseQuizAnswer>
</BaseQuiz>

### 段落：`p`

最常见的文本内容块元素。

```html
<p>这是包含文本的段落。它可以包含多个句子，并且会自动换行。</p>
<p>这是另一个段落。段落之间有边距间隔。</p>
```

### 文本格式化：`<strong>`, `<em>`, `<b>`, `<i>`

用于行内文本强调和样式的元素。

```html
<strong>重要性强（粗体）</strong>
<em>强调（斜体）</em>
<b>粗体文本</b>
<i>斜体文本</i>
<u>带下划线的文本</u>
<mark>高亮文本</mark>
<small>小文本</small>
<del>已删除文本</del>
<ins>已插入文本</ins>
```

### 换行和间距：`<br>`, `<hr>`, `<pre>`

控制内容内的文本流和间距。

```html
<!-- 换行 -->
第 1 行<br />
第 2 行
<!-- 水平线 -->
<hr />
<!-- 预格式化文本 -->
<pre>
  带有
    保留的    间距
      和换行的文本
</pre>
<!-- 代码格式化 -->
<code>console.log('Hello');</code>
```

## 列表和导航

### 无序列表：`<ul>`

创建用于非顺序项目的项目符号列表。

```html
<ul>
  <li>第一项</li>
  <li>第二项</li>
  <li>第三项</li>
</ul>
<!-- 嵌套列表 -->
<ul>
  <li>
    主项目
    <ul>
      <li>子项目 1</li>
      <li>子项目 2</li>
    </ul>
  </li>
</ul>
```

### 有序列表：`<ol>`

创建用于顺序项目的编号列表。

```html
<ol>
  <li>第一步</li>
  <li>第二步</li>
  <li>第三步</li>
</ol>
<!-- 自定义编号 -->
<ol start="5">
  <li>第 5 项</li>
  <li>第 6 项</li>
</ol>
<!-- 不同编号类型 -->
<ol type="A">
  <li>A 项</li>
  <li>B 项</li>
</ol>
```

### 定义列表：`<dl>`

创建术语及其描述的列表。

```html
<dl>
  <dt>HTML</dt>
  <dd>超文本标记语言</dd>

  <dt>CSS</dt>
  <dd>层叠样式表</dd>

  <dt>JavaScript</dt>
  <dd>用于 Web 的编程语言</dd>
</dl>
```

### 链接和导航：`<a>`

创建超链接和导航结构。

```html
<!-- 基本链接 -->
<a href="https://example.com">访问 Example</a>
<!-- 在新标签页中打开链接 -->
<a href="https://example.com" target="_blank">新标签页</a>
<!-- 电子邮件链接 -->
<a href="mailto:email@example.com">发送邮件</a>
<!-- 电话链接 -->
<a href="tel:+1234567890">致电我们</a>
<!-- 内部页面锚点 -->
<a href="#section1">转到第 1 节</a>
<h2 id="section1">第 1 节</h2>
```

<BaseQuiz id="html-links-1" correct="B">
  <template #question>
    锚点标签中的 <code>target="_blank"</code> 有什么作用？
  </template>
  
  <BaseQuizOption value="A">在同一窗口中打开链接</BaseQuizOption>
  <BaseQuizOption value="B" correct>在新标签页或窗口中打开链接</BaseQuizOption>
  <BaseQuizOption value="C">关闭当前窗口</BaseQuizOption>
  <BaseQuizOption value="D">下载链接内容</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>target="_blank"</code> 属性会在新的浏览器标签页或窗口中打开链接的页面，使用户可以保持原始页面打开。
  </BaseQuizAnswer>
</BaseQuiz>

## 表单和输入元素

### 基本表单结构：`<form>`

用户输入收集的基础。

```html
<form action="/submit" method="POST">
  <label for="username">用户名：</label>
  <input type="text" id="username" name="username" required />

  <label for="email">电子邮件：</label>
  <input type="email" id="email" name="email" required />

  <input type="submit" value="提交" />
</form>
```

### 输入类型：`<input>`

用于不同数据收集需求的各种输入类型。

```html
<!-- 文本输入 -->
<input type="text" placeholder="输入文本" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="密码" />
<input type="url" placeholder="https://example.com" />
<input type="tel" placeholder="+1234567890" />
<!-- 数字输入 -->
<input type="number" min="1" max="100" step="1" />
<input type="range" min="0" max="100" value="50" />
<!-- 日期和时间 -->
<input type="date" />
<input type="time" />
<input type="datetime-local" />
```

### 表单控件：`<checkbox>`, `<radio>`, `<select>`, `<textarea>`

用于用户交互的其他表单元素。

```html
<!-- 复选框 -->
<input type="checkbox" id="agree" name="agree" />
<label for="agree">我同意条款</label>
<!-- 单选按钮 -->
<input type="radio" id="option1" name="choice" value="1" />
<label for="option1">选项 1</label>
<input type="radio" id="option2" name="choice" value="2" />
<label for="option2">选项 2</label>
<!-- 选择下拉列表 -->
<select name="country">
  <option value="us">美国</option>
  <option value="uk">英国</option>
  <option value="ca">加拿大</option>
</select>
<!-- 文本区域 -->
<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="输入您的消息"
></textarea>
```

### 表单验证：`required`, `min`, `max`, `pattern`

内置的 HTML 表单验证属性。

```html
<input type="text" required />
<input type="email" required />
<input type="text" minlength="3" maxlength="20" />
<input type="number" min="1" max="100" />
<input type="text" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}" />
```

<BaseQuiz id="html-validation-1" correct="A">
  <template #question>
    HTML 输入中的 <code>required</code> 属性有什么作用？
  </template>
  
  <BaseQuizOption value="A" correct>如果字段为空，则阻止表单提交</BaseQuizOption>
  <BaseQuizOption value="B">使字段只读</BaseQuizOption>
  <BaseQuizOption value="C">隐藏字段</BaseQuizOption>
  <BaseQuizOption value="D">设置默认值</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>required</code> 属性使输入字段成为必填项。如果提交表单时该字段为空，浏览器将阻止提交并显示验证消息。
  </BaseQuizAnswer>
</BaseQuiz>

## 媒体元素

### 图像：`<img>`, `<picture>`

显示具有各种属性和选项的图像。

```html
<!-- 基本图像 -->
<img src="image.jpg" alt="描述" />
<!-- 响应式图像 -->
<img src="image.jpg" alt="描述" width="100%" height="auto" />
<!-- 带尺寸的图像 -->
<img src="image.jpg" alt="描述" width="300" height="200" />
<!-- Picture 元素用于响应式图像 -->
<picture>
  <source media="(min-width: 800px)" srcset="large.jpg" />
  <source media="(min-width: 400px)" srcset="medium.jpg" />
  <img src="small.jpg" alt="描述" />
</picture>
```

### 音频：`<audio>`

嵌入带有播放控件的音频内容。

```html
<!-- 基本音频 -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
  <source src="audio.ogg" type="audio/ogg" />
  您的浏览器不支持音频。
</audio>
<!-- 带自动播放的音频 -->
<audio controls autoplay loop>
  <source src="background.mp3" type="audio/mpeg" />
</audio>
```

### 视频：`<video>`

嵌入带有全面选项的视频内容。

```html
<!-- 基本视频 -->
<video controls width="400" height="300">
  <source src="video.mp4" type="video/mp4" />
  <source src="video.webm" type="video/webm" />
  您的浏览器不支持视频。
</video>
<!-- 带海报和属性的视频 -->
<video controls poster="thumbnail.jpg" width="100%" height="auto">
  <source src="video.mp4" type="video/mp4" />
  <track src="captions.vtt" kind="captions" srclang="en" label="English" />
</video>
```

### 嵌入内容：`<iframe>`

嵌入外部内容和应用程序。

```html
<!-- 用于外部内容的 iFrame -->
<iframe src="https://example.com" width="100%" height="400"></iframe>
<!-- YouTube 视频嵌入 -->
<iframe
  width="560"
  height="315"
  src="https://www.youtube.com/embed/VIDEO_ID"
></iframe>
<!-- Google Maps 嵌入 -->
<iframe src="https://maps.google.com/..."></iframe>
```

## 表格

### 基本表格结构：`<table>`

使用表格创建结构化数据展示。

```html
<table>
  <thead>
    <tr>
      <th>名称</th>
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
    <tr>
      <td>Jane</td>
      <td>30</td>
      <td>London</td>
    </tr>
  </tbody>
</table>
```

### 高级表格特性：`rowspan`, `colspan`, `<caption>`

通过跨越和分组增强表格功能。

```html
<table>
  <caption>
    销售报告
  </caption>
  <colgroup>
    <col style="width: 50%" />
    <col style="width: 25%" />
    <col style="width: 25%" />
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">产品</th>
      <th colspan="2">销售额</th>
    </tr>
    <tr>
      <th>第一季度</th>
      <th>第二季度</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>A 产品</td>
      <td>$1000</td>
      <td>$1200</td>
    </tr>
  </tbody>
</table>
```

## HTML5 语义元素

### 页面结构元素：`<header>`, `<nav>`, `<main>`, `<footer>`

定义页面的主要布局部分。

```html
<!-- 页面头部 -->
<header>
  <nav>
    <ul>
      <li><a href="#home">主页</a></li>
      <li><a href="#about">关于</a></li>
    </ul>
  </nav>
</header>
<!-- 主要内容 -->
<main>
  <article>
    <h1>文章标题</h1>
    <p>文章内容...</p>
  </article>
</main>
<!-- 侧边栏 -->
<aside>
  <h2>相关链接</h2>
  <ul>
    <li><a href="#">链接 1</a></li>
  </ul>
</aside>
<!-- 页面页脚 -->
<footer>
  <p>© 2024 公司名称</p>
</footer>
```

### 内容分组元素：`<section>`, `<article>`, `<div>`, `<figure>`

组织和分组相关的内容部分。

```html
<!-- 通用部分 -->
<section>
  <h2>章节标题</h2>
  <p>章节内容...</p>
</section>
<!-- 独立文章 -->
<article>
  <header>
    <h1>文章标题</h1>
    <time datetime="2024-01-01">2024 年 1 月 1 日</time>
  </header>
  <p>文章内容...</p>
</article>
<!-- 通用容器 -->
<div class="container">
  <p>通用内容分组</p>
</div>
<!-- 带标题的图 -->
<figure>
  <img src="chart.jpg" alt="销售图表" />
  <figcaption>2024 年第一季度销售数据</figcaption>
</figure>
```

## HTML 属性

### 全局属性：`id`, `class`, `title`, `data-*`

可用于任何 HTML 元素的属性。

```html
<!-- 用于唯一标识的 ID -->
<div id="unique-element">内容</div>
<!-- 用于样式和选择的 Class -->
<p class="highlight important">文本</p>
<!-- 用于工具提示的 Title -->
<span title="这是一个工具提示">悬停我</span>
<!-- 数据属性 -->
<div data-user-id="123" data-role="admin">用户</div>
<!-- 语言 -->
<p lang="es">Hola mundo</p>
<!-- 内容方向 -->
<p dir="rtl">从右到左的文本</p>
<!-- 隐藏的元素 -->
<div hidden>这不会显示</div>
```

### 可访问性属性：`alt`, `aria-*`, `tabindex`, `role`

改善可访问性和用户体验的属性。

```html
<!-- 图像的替代文本 -->
<img src="photo.jpg" alt="一座山脉上的日落" />
<!-- ARIA 标签 -->
<button aria-label="关闭对话框">×</button>
<div aria-hidden="true">装饰性内容</div>
<!-- 表单可访问性 -->
<label for="email">电子邮件地址：</label>
<input type="email" id="email" aria-describedby="email-help" />
<small id="email-help">我们绝不会分享您的电子邮件</small>
<!-- Tab 索引 -->
<div tabindex="0">可聚焦的 div</div>
<div tabindex="-1">可编程聚焦的 div</div>
<!-- 角色属性 -->
<div role="button" tabindex="0">自定义按钮</div>
```

## HTML5 新特性

### 新的输入特性：`color`, `search`, `file`, `datalist`

HTML5 引入了新的输入类型和属性。

```html
<!-- 新的输入类型 -->
<input type="color" value="#ff0000" />
<input type="search" placeholder="搜索..." />
<input type="file" accept="image/*" multiple />
<!-- 用于自动完成的数据列表 -->
<input list="browsers" name="browser" />
<datalist id="browsers">
  <option value="Chrome"></option>
  <option value="Firefox"></option>
  <option value="Safari"></option>
</datalist>
<!-- 进度条和仪表 -->
<progress value="70" max="100">70%</progress>
<meter value="0.6">60%</meter>
```

### 画布和 SVG: `<canvas>`, `<svg>`

HTML5 中的图形和绘图功能。

```html
<!-- 用于动态图形的 Canvas -->
<canvas id="myCanvas" width="400" height="200">
  您的浏览器不支持 canvas。
</canvas>
<!-- 内联 SVG -->
<svg width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue" stroke="black" stroke-width="2" />
</svg>
```

### 详情和摘要：`<details>`, `<summary>`

在没有 JavaScript 的情况下创建可折叠的内容部分。

```html
<details>
  <summary>点击展开</summary>
  <p>此内容默认隐藏，点击摘要时显示。</p>
  <ul>
    <li>项目 1</li>
    <li>项目 2</li>
  </ul>
</details>
<details open>
  <summary>此项默认展开</summary>
  <p>默认可见的内容。</p>
</details>
```

### 对话框元素：`<dialog>`

原生的对话框和模态功能。

```html
<!-- 对话框元素 -->
<dialog id="myDialog">
  <h2>对话框标题</h2>
  <p>对话框内容放在这里。</p>
  <button onclick="closeDialog()">关闭</button>
</dialog>
<button onclick="openDialog()">打开对话框</button>
<script>
  function openDialog() {
    document.getElementById('myDialog').showModal()
  }
</script>
```

## 最佳实践和验证

### HTML 最佳实践

编写干净、可维护和可访问的 HTML。

```html
<!-- 始终声明 doctype -->
<!DOCTYPE html>
<!-- 使用语义化元素 -->
<header>...</header>
<main>...</main>
<footer>...</footer>
<!-- 正确的嵌套 -->
<div>
  <p>正确嵌套的内容</p>
</div>
<!-- 元素和属性使用小写 -->
<img src="image.jpg" alt="description" />
<!-- 关闭所有标签 -->
<p>始终关闭您的标签</p>
<!-- 使用有意义的 alt 文本 -->
<img src="chart.png" alt="第四季度销售额增长 25%" />
```

### HTML 验证和调试

确保您的 HTML 有效且可访问。

```html
<!-- 使用 W3C HTML 验证器 -->
<!-- https://validator.w3.org/ -->
<!-- 常见的验证错误 -->
<!-- 缺少 alt 属性 -->
<img src="image.jpg" alt="" />
<!-- 提供 alt 文本 -->
<!-- 未关闭的标签 -->
<p>文本内容</p>
<!-- 始终关闭标签 -->
<!-- 无效的嵌套 -->
<p>
  有效的段落内容
  <!-- 不要将块级元素放在段落内 -->
</p>
<!-- 使用开发者工具 -->
<!-- 右键单击 → 检查元素 -->
<!-- 检查控制台中的错误 -->
<!-- 使用 WAVE 或 axe 验证可访问性 -->
```

## HTML 模板和框架

### 模板引擎：Handlebars, Mustache

使用模板语言进行动态 HTML 生成。

```html
<!-- Handlebars 模板 -->
<div>
  <h1>{{title}}</h1>
  {{#each items}}
  <p>{{this}}</p>
  {{/each}}
</div>
<!-- Mustache 模板 -->
<div>
  <h1>{{title}}</h1>
  {{#items}}
  <p>{{.}}</p>
  {{/items}}
</div>
```

### Web Components: `<template>`, 自定义元素

可重用的自定义 HTML 元素。

```html
<!-- 自定义元素定义 -->
<template id="my-component">
  <style>
    p {
      color: blue;
    }
  </style>
  <p><slot></slot></p>
</template>
<!-- 用法 -->
<my-component>Hello World</my-component>
<script>
  class MyComponent extends HTMLElement {
    // 组件逻辑
  }
  customElements.define('my-component', MyComponent)
</script>
```

### 框架集成：React JSX, Vue 模板

现代 JavaScript 框架中的 HTML。

```html
<!-- React JSX -->
function Component() { return (
<div className="container">
  <h1>{title}</h1>
  <p>Content here</p>
</div>
); }
<!-- Vue 模板 -->
<template>
  <div class="container">
    <h1>{{ title }}</h1>
    <p v-if="showContent">Content here</p>
  </div>
</template>
```

## 相关链接

- <router-link to="/css">CSS 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/web-development">Web 开发速查表</router-link>
- <router-link to="/react">React 速查表</router-link>
- <router-link to="/git">Git 速查表</router-link>
- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>

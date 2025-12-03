---
title: 'CSS 치트 시트 | LabEx'
description: '포괄적인 CSS 치트 시트로 CSS3 를 학습하세요. 웹 개발자를 위한 CSS 선택자, 플렉스박스, 그리드, 애니메이션, 반응형 디자인 및 최신 스타일링 기술에 대한 빠른 참조 가이드입니다.'
pdfUrl: '/cheatsheets/pdf/css-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
CSS 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/css">Hands-On Labs 로 CSS 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 CSS 웹 스타일링을 학습하세요. LabEx 는 필수 속성, 선택자, 레이아웃 기술, 반응형 디자인 및 최신 기능을 다루는 포괄적인 CSS 강좌를 제공합니다. 현대적인 웹 개발 워크플로우를 위한 효율적인 웹 스타일링 및 레이아웃 디자인을 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## CSS 구문 및 선택자

### 기본 구문

CSS 는 선택자와 선언으로 구성됩니다. 선택자는 HTML 요소를 대상으로 지정하고, 선언은 속성 값을 설정합니다.

```css
/* 기본 구문 */
selector {
  property: value;
  property: value;
}

/* 예시 */
p {
  color: red;
  font-size: 16px;
}
```

### 요소 선택자

태그 이름을 사용하여 HTML 요소를 대상으로 지정합니다.

```css
/* 모든 단락 선택 */
p {
  color: blue;
}

/* 모든 제목 선택 */
h1 {
  font-size: 2em;
}

/* 모든 링크 선택 */
a {
  text-decoration: none;
}
```

### 클래스 선택자

특정 `class` 속성을 가진 요소를 대상으로 지정합니다.

```css
/* class="highlight"를 가진 요소 선택 */
.highlight {
  background-color: yellow;
}

/* class="intro"를 가진 단락 선택 */
p.intro {
  font-weight: bold;
}

/* 여러 클래스 */
.large.bold {
  font-size: 20px;
  font-weight: bold;
}
```

<BaseQuiz id="css-class-1" correct="B">
  <template #question>
    CSS 에서 class="highlight"를 가진 요소를 선택하는 방법은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">highlight { }</BaseQuizOption>
  <BaseQuizOption value="B" correct>.highlight { }</BaseQuizOption>
  <BaseQuizOption value="C">#highlight { }</BaseQuizOption>
  <BaseQuizOption value="D">class="highlight" { }</BaseQuizOption>
  
  <BaseQuizAnswer>
    클래스 선택자는 점 (`.`) 접두사를 사용합니다. `.highlight` 는 `class="highlight"` 를 가진 모든 요소를 선택합니다. ID 선택자는 `#` 을 사용하고, 요소 선택자는 접두사를 사용하지 않습니다.
  </BaseQuizAnswer>
</BaseQuiz>

### ID 선택자

특정 `id` 속성을 가진 요소를 대상으로 지정합니다.

```css
/* id="header"를 가진 요소 선택 */
#header {
  background-color: #333;
}

/* ID 는 페이지당 고유해야 합니다 */
#navigation {
  position: fixed;
}
```

### 속성 선택자

속성 선택자를 사용하여 특정 속성을 가진 요소를 대상으로 지정합니다.

```css
/* title 속성을 가진 요소 */
[title] {
  cursor: help;
}

/* 외부 사이트로 연결되는 링크 */
a[href^='http'] {
  color: red;
}

/* type 이 text 인 input 요소 */
input[type='text'] {
  border: 1px solid #ccc;
}
```

### 의사 클래스 (Pseudo-classes)

의사 클래스는 상태 변경 및 사용자 상호 작용을 기반으로 CSS 를 적용합니다.

```css
/* 링크 상태 */
a:hover {
  color: red;
}
a:visited {
  color: purple;
}
a:active {
  color: orange;
}

/* 폼 상태 */
input:focus {
  border-color: blue;
}
input:invalid {
  border-color: red;
}

/* 구조적 의사 클래스 */
li:first-child {
  font-weight: bold;
}
li:nth-child(odd) {
  background-color: #f0f0f0;
}
```

## 박스 모델 및 레이아웃

### 콘텐츠: `width` / `height`

요소의 실제 콘텐츠 영역입니다.

```css
/* 크기 설정 */
div {
  width: 300px;
  height: 200px;
}

/* 반응형 크기 조정 */
.container {
  width: 100%;
  max-width: 1200px;
}

/* 최소/최대 제약 조건 */
.box {
  min-height: 100px;
  max-width: 500px;
}
```

### 패딩 (Padding): `padding`

콘텐츠와 테두리 사이의 공간으로, 요소 내부에 있습니다.

```css
/* 모든 면 */
div {
  padding: 20px;
}

/* 개별 면 */
div {
  padding-top: 10px;
  padding-right: 15px;
}

/* 단축 구문: 위 오른쪽 아래 왼쪽 */
div {
  padding: 10px 15px 20px 5px;
}
```

<BaseQuiz id="css-padding-1" correct="C">
  <template #question>
    `padding: 10px 20px`는 무엇을 설정합니까?
  </template>
  
  <BaseQuizOption value="A">10px 위/아래, 20px 왼쪽/오른쪽</BaseQuizOption>
  <BaseQuizOption value="B">10px 모든 면</BaseQuizOption>
  <BaseQuizOption value="C" correct>10px 위/아래, 20px 왼쪽/오른쪽</BaseQuizOption>
  <BaseQuizOption value="D">10px 위, 20px 아래</BaseQuizOption>
  
  <BaseQuizAnswer>
    두 개의 값이 제공되면 첫 번째 값은 위쪽과 아래쪽에 적용되고 두 번째 값은 왼쪽과 오른쪽에 적용됩니다. 따라서 `padding: 10px 20px`는 10px 의 수직 패딩과 20px 의 수평 패딩을 의미합니다.
  </BaseQuizAnswer>
</BaseQuiz>
```

### 테두리 (Border): `border`

테두리는 사용자 정의 가능한 크기, 스타일 및 색상으로 요소에 프레임을 제공합니다.

```css
/* 테두리 단축 구문 */
div {
  border: 2px solid #333;
}

/* 개별 속성 */
div {
  border-width: 1px;
  border-style: dashed;
  border-color: red;
}

/* 개별 면 */
div {
  border-bottom: 3px solid blue;
}
```

### 마진 (Margin): `margin`

테두리 바깥쪽의 공간으로, 요소들 사이에 위치합니다.

```css
/* 모든 면 */
div {
  margin: 20px;
}

/* 수평으로 가운데 정렬 */
div {
  margin: 0 auto;
}

/* 개별 면 */
div {
  margin-top: 30px;
  margin-bottom: 10px;
}

/* 음수 마진 */
div {
  margin-left: -20px;
}
```

<BaseQuiz id="css-margin-1" correct="C">
  <template #question>
    `margin: 0 auto`는 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A">모든 마진 제거</BaseQuizOption>
  <BaseQuizOption value="B">모든 면에 동일한 마진 추가</BaseQuizOption>
  <BaseQuizOption value="C" correct>블록 요소를 수평으로 가운데 정렬</BaseQuizOption>
  <BaseQuizOption value="D">블록 요소를 수직으로 가운데 정렬</BaseQuizOption>
  
  <BaseQuizAnswer>
    `margin: 0 auto`는 위쪽과 아래쪽 마진을 0으로 설정하고 왼쪽/오른쪽 마진을 auto로 설정하여 블록 레벨 요소를 컨테이너 내에서 수평으로 가운데 정렬합니다.
  </BaseQuizAnswer>
</BaseQuiz>

## 텍스트 및 타이포그래피

### 글꼴 속성

글꼴 모음, 크기, 굵기 및 스타일을 제어합니다.

```css
/* 글꼴 모음 */
body {
  font-family: Arial, sans-serif;
}

/* Google Fonts */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
body {
  font-family: 'Roboto', sans-serif;
}

/* 글꼴 크기 */
h1 {
  font-size: 2rem;
}
p {
  font-size: 16px;
}

/* 글꼴 굵기 */
h2 {
  font-weight: bold;
}
span {
  font-weight: 300;
}
```

### 텍스트 정렬

텍스트 위치 및 간격을 제어합니다.

```css
/* 수평 정렬 */
h1 {
  text-align: center;
}
p {
  text-align: justify;
}

/* 줄 높이 */
p {
  line-height: 1.6;
}

/* 글자 및 단어 간격 */
h1 {
  letter-spacing: 2px;
}
p {
  word-spacing: 4px;
}
```

### 텍스트 스타일링

텍스트에 장식 및 변환을 추가합니다.

```css
/* 텍스트 장식 */
a {
  text-decoration: underline;
}
.strike {
  text-decoration: line-through;
}

/* 텍스트 변환 */
.uppercase {
  text-transform: uppercase;
}
.capitalize {
  text-transform: capitalize;
}

/* 텍스트 그림자 */
h1 {
  text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}
```

### 색상

CSS는 다양한 스타일링 요구 사항에 대해 여러 가지 색상 지정 방법을 제공합니다.

```css
/* 색상 형식 */
p {
  color: red;
}
div {
  background-color: #ff5733;
}
```

<BaseQuiz id="css-colors-1" correct="D">
  <template #question>
    웹 디자인에 가장 일반적으로 사용되는 CSS 색상 형식은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">RGB만</BaseQuizOption>
  <BaseQuizOption value="B">이름 있는 색상만</BaseQuizOption>
  <BaseQuizOption value="C">HSL만</BaseQuizOption>
  <BaseQuizOption value="D" correct>Hex 코드(#RRGGBB)는 이름 있는 색상과 함께 매우 일반적입니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    Hex 색상 코드(#RRGGBB)는 디자인 도구에서 복사하기 쉽고 간결하기 때문에 널리 사용됩니다. 이름 있는 색상 및 RGB/rgba도 일반적입니다. 선택은 특정 사용 사례와 선호도에 따라 달라집니다.
  </BaseQuizAnswer>
</BaseQuiz>
span {
  color: rgb(255, 87, 51);
}
section {
  background-color: rgba(255, 87, 51, 0.8);
}

/_ HSL 색상 _/
header {
background-color: hsl(200, 100%, 50%);
}

/_ CSS 변수를 사용한 색상 _/
:root {
--primary-color: #3498db;
}
.button {
background-color: var(--primary-color);
}

````

## Flexbox 레이아웃

### Flex 컨테이너 속성

부모 컨테이너에 적용되는 속성입니다.

```css
/* flexbox 활성화 */
.container {
  display: flex;
}

/* Flex 방향 */
.container {
  flex-direction: row; /* 기본값 */
  flex-direction: column;
  flex-direction: row-reverse;
}

/* Justify content (주축) */
.container {
  justify-content: flex-start; /* 기본값 */
  justify-content: center;
  justify-content: space-between;
  justify-content: space-around;
}

/* Align items (교차축) */
.container {
  align-items: stretch; /* 기본값 */
  align-items: center;
  align-items: flex-start;
}
````

### Flex 항목 속성

자식 요소에 적용되는 속성입니다.

```css
/* Flex grow/shrink */
.item {
  flex-grow: 1; /* 공간을 채우기 위해 성장 */
  flex-shrink: 1; /* 필요한 경우 축소 */
  flex-basis: auto; /* 초기 크기 */
}

/* 단축 구문 */
.item {
  flex: 1; /* flex: 1 1 0% */
  flex: 0 0 200px; /* 고정 너비 */
}

/* 개별 정렬 */
.item {
  align-self: center;
  align-self: flex-end;
}

/* 순서 (Order) */
.item {
  order: 2; /* 시각적 순서 변경 */
}
```

## CSS Grid 레이아웃

### Grid 컨테이너

그리드 구조와 속성을 정의합니다.

```css
/* 그리드 활성화 */
.grid-container {
  display: grid;
}

/* 열 및 행 정의 */
.grid-container {
  grid-template-columns: 1fr 2fr 1fr;
  grid-template-rows: 100px auto 50px;
}

/* 그리드 간격 */
.grid-container {
  gap: 20px;
  column-gap: 30px;
  row-gap: 10px;
}

/* 이름 붙여진 그리드 영역 */
.grid-container {
  grid-template-areas:
    'header header header'
    'sidebar main main'
    'footer footer footer';
}
```

### Grid 항목

그리드 항목의 위치와 크기를 지정합니다.

```css
/* 그리드 위치 지정 */
.grid-item {
  grid-column: 1 / 3; /* 열 1-2 걸침 */
  grid-row: 2 / 4; /* 행 2-3 걸침 */
}

/* 단축 구문 */
.grid-item {
  grid-area: 2 / 1 / 4 / 3; /* row-start / col-start / row-end / col-end */
}

/* 이름 붙여진 영역 */
.header {
  grid-area: header;
}
.sidebar {
  grid-area: sidebar;
}
.main {
  grid-area: main;
}

/* 자동 배치 */
.grid-item {
  grid-column: span 2; /* 2 개 열 걸침 */
  grid-row: span 3; /* 3 개 행 걸침 */
}
```

## 포지셔닝 (Positioning)

### Position 속성

요소의 위치 지정 동작을 제어합니다.

```css
/* Static (기본값) */
.element {
  position: static;
}

/* Relative 포지셔닝 */
.element {
  position: relative;
  top: 20px;
  left: 10px;
}

/* Absolute 포지셔닝 */
.element {
  position: absolute;
  top: 0;
  right: 0;
}

/* Fixed 포지셔닝 */
.navbar {
  position: fixed;
  top: 0;
  width: 100%;
}

/* Sticky 포지셔닝 */
.sidebar {
  position: sticky;
  top: 20px;
}
```

### Z-Index 및 스태킹

z-index 와 스태킹 컨텍스트를 사용하여 요소가 서로 위에 쌓이는 순서를 제어합니다.

```css
/* 스태킹 순서 */
.modal {
  position: fixed;
  z-index: 1000;
}
.overlay {
  position: absolute;
  z-index: 999;
}

/* 스태킹 컨텍스트 생성 */
.container {
  position: relative;
  z-index: 0;
}

/* 일반적인 z-index 값 */
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

## 반응형 디자인

### 미디어 쿼리 (Media Queries)

장치 특성을 기반으로 스타일을 적용합니다.

```css
/* 모바일 우선 접근 방식 */
.container {
  width: 100%;
}

/* 태블릿 스타일 */
@media (min-width: 768px) {
  .container {
    width: 750px;
  }
}

/* 데스크톱 스타일 */
@media (min-width: 1024px) {
  .container {
    width: 960px;
  }
}

/* 인쇄 스타일 */
@media print {
  body {
    font-size: 12pt;
  }
  .no-print {
    display: none;
  }
}

/* 방향 */
@media (orientation: landscape) {
  .sidebar {
    display: block;
  }
}
```

### 반응형 단위

유연한 레이아웃을 위해 상대 단위를 사용합니다.

```css
/* 뷰포트 단위 */
.hero {
  height: 100vh;
} /* 전체 뷰포트 높이 */
.sidebar {
  width: 25vw;
} /* 뷰포트 너비의 25% */

/* 상대 단위 */
p {
  font-size: 1.2em;
} /* 부모 글꼴 크기의 1.2 배 */
h1 {
  font-size: 2rem;
} /* 루트 글꼴 크기의 2 배 */

/* 백분율 단위 */
.container {
  width: 80%;
}
.column {
  width: 50%;
}

/* CSS Grid 반응형 */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}

/* Flexbox 반응형 */
.flex-container {
  display: flex;
  flex-wrap: wrap;
}
```

## 애니메이션 및 전환

### CSS 전환 (Transitions)

속성 값 간의 부드러운 변화입니다.

```css
/* 기본 전환 */
.button {
  background-color: blue;
  transition: background-color 0.3s ease;
}
.button:hover {
  background-color: red;
}

/* 여러 속성 */
.card {
  transform: scale(1);
  opacity: 1;
  transition: all 0.3s ease-in-out;
}
.card:hover {
  transform: scale(1.05);
  opacity: 0.8;
}

/* 개별 전환 */
.element {
  transition-property: width, height;
  transition-duration: 0.5s, 1s;
  transition-timing-function: ease, linear;
}
```

### CSS 애니메이션

키프레임을 사용하여 복잡한 애니메이션을 만듭니다.

```css
/* 키프레임 정의 */
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

/* 애니메이션 적용 */
.slide-in {
  animation: slideIn 0.5s ease-out;
}
.pulse {
  animation: pulse 2s infinite;
}

/* 애니메이션 단축 구문 */
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

## CSS 변수 및 함수

### CSS 변수

일관된 테마를 위해 사용자 정의 속성을 정의하고 사용합니다.

```css
/* 변수 정의 */
:root {
  --primary-color: #3498db;
  --secondary-color: #2ecc71;
  --font-size-large: 24px;
  --border-radius: 8px;
}

/* 변수 사용 */
.button {
  background-color: var(--primary-color);
  border-radius: var(--border-radius);
}

/* 대체 값 */
.text {
  color: var(--text-color, #333);
}

/* 로컬 변수 */
.card {
  --card-padding: 20px;
  padding: var(--card-padding);
}
```

### CSS 함수

계산 및 동적 값을 위해 내장된 다양한 함수를 사용합니다.

```css
/* Calc 함수 */
.container {
  width: calc(100% - 40px);
  height: calc(100vh - 60px);
}

/* Min/max 함수 */
.responsive {
  width: min(90%, 1200px);
  font-size: max(16px, 1.2vw);
  height: clamp(200px, 50vh, 400px);
}

/* 색상 함수 */
.element {
  background-color: hsl(200, 50%, 50%);
  color: rgb(255, 87, 51);
}

/* 변환 함수 */
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

## 모범 사례 및 구성

### CSS 구성

유지 관리를 위해 CSS 구조를 구성합니다.

```css
/* 의미 있는 클래스 이름 사용 */
.hero-section {
}
.primary-button {
}
.navigation-menu {
}

/* BEM 방법론 */
.block {
}
.block__element {
}
.block--modifier {
}

/* 예시 */
.card {
}
.card__header {
}
.card__body {
}
.card--featured {
}

/* 관련 스타일 그룹화 */
/* ===== 레이아웃 ===== */
.container {
}
.grid {
}

/* ===== 컴포넌트 ===== */
.button {
}
.card {
}
```

### 성능 및 최적화

더 나은 성능을 위해 효율적인 CSS 를 작성합니다.

```css
/* 깊은 중첩 피하기 */
/* 나쁨 */
.header .nav ul li a {
}

/* 좋음 */
.nav-link {
}

/* 효율적인 선택자 사용 */
/* 나쁨 */
body div.container > p {
}

/* 좋음 */
.content-text {
}

/* 리페인트 최소화 */
/* position 대신 transform 사용 */
.element {
  transform: translateX(100px);
  /* left: 100px; 대신 */
}

/* 공급업체 접두사 그룹화 */
.element {
  -webkit-border-radius: 5px;
  -moz-border-radius: 5px;
  border-radius: 5px;
}
```

## CSS 디버깅

### 브라우저 개발자 도구

실시간으로 CSS 를 검사하고 수정합니다.

```css
/* 일반적인 디버깅 단계 */
/* 1. 마우스 오른쪽 클릭 → 요소 검사 */
/* 2. 계산된 스타일 확인 */
/* 3. 재정의된 속성 확인 */
/* 4. 실시간으로 변경 사항 테스트 */
/* 5. 수정된 CSS 를 파일에 다시 복사 */
```

### 일반적인 CSS 문제

자주 발생하는 문제를 해결합니다.

```css
/* 박스 모델 문제 */
* {
  box-sizing: border-box;
}

/* float 정리 */
.clearfix::after {
  content: '';
  display: table;
  clear: both;
}

/* Z-index 문제 */
/* z-index 가 작동하려면 위치 지정된 요소가 필요합니다 */
.element {
  position: relative;
  z-index: 1;
}
```

### CSS 유효성 검사

표준 및 모범 사례를 따르는지 확인합니다.

```css
/* CSS 검사기 사용 */
/* W3C CSS 검사기 */
/* 브라우저 호환성 도구 */

/* 코드 주석 처리 */
/* ===== 헤더 스타일 ===== */
.header {
}

/* TODO: 모바일 스타일 추가 */
/* FIXME: IE 호환성 수정 */

/* 일관된 형식 사용 */
.element {
  property: value;
  property: value;
}
```

## CSS 프레임워크 및 도구

### CSS 전처리기

변수, 중첩 및 함수로 CSS 를 확장합니다.

```scss
/* SCSS/Sass 예시 */
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
/* Less 예시 */
@primary-color: #3498db;

.button {
  background-color: @primary-color;

  &:hover {
    background-color: lighten(@primary-color, 10%);
  }
}
```

### CSS-in-JS 및 최신 도구

웹 애플리케이션 스타일링을 위한 현대적인 접근 방식입니다.

```css
/* PostCSS 플러그인 */
/* Autoprefixer - 공급업체 접두사 추가 */
/* PurgeCSS - 사용하지 않는 CSS 제거 */

/* CSS 모듈 */
.button {
  composes: base-button;
  background-color: blue;
}
```

```javascript
/* 유틸리티 우선 CSS (Tailwind) */
;<div class="flex items-center justify-center p-4 bg-blue-500">
  <span class="text-white font-bold">Button</span>
</div>

/* CSS-in-JS (Styled Components) */
const Button = styled.button`
  background: ${(props) => (props.primary ? 'blue' : 'white')};
  padding: 1rem 2rem;
`
```

## 관련 링크

- <router-link to="/html">HTML 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/react">React 치트 시트</router-link>
- <router-link to="/web-development">웹 개발 치트 시트</router-link>

---
title: 'HTML 치트 시트 | LabEx'
description: '이 포괄적인 치트 시트로 HTML5 를 학습하세요. 프론트엔드 개발자를 위한 HTML 태그, 시맨틱 요소, 폼, 접근성 및 최신 웹 개발 표준에 대한 빠른 참조 자료입니다.'
pdfUrl: '/cheatsheets/pdf/html-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
HTML 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/html">실습 랩을 통해 HTML 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 HTML 웹 구조를 학습하세요. LabEx 는 필수 요소, 시맨틱 마크업, 폼, 미디어 통합 및 최신 HTML5 기능을 다루는 포괄적인 HTML 과정을 제공합니다. 현대 웹 개발 워크플로우를 위한 효율적인 웹 페이지 구조 및 콘텐츠 구성을 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## HTML 문서 구조

### 기본 HTML 문서: `<!DOCTYPE html>`

모든 HTML 문서는 문서 유형 선언으로 시작하며 표준 구조를 따릅니다.

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Page Title</title>
  </head>
  <body>
    <!-- 페이지 콘텐츠는 여기에 들어갑니다 -->
  </body>
</html>
```

<BaseQuiz id="html-doctype-1" correct="A">
  <template #question>
    <code><!DOCTYPE html></code>의 목적은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A" correct>문서 유형과 HTML 버전을 선언합니다</BaseQuizOption>
  <BaseQuizOption value="B">새로운 HTML 요소를 생성합니다</BaseQuizOption>
  <BaseQuizOption value="C">외부 스타일시트를 연결합니다</BaseQuizOption>
  <BaseQuizOption value="D">페이지 제목을 설정합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code><!DOCTYPE html></code> 선언은 브라우저에 문서가 사용하는 HTML 버전을 알려줍니다. HTML5 의 경우, 이 간단한 선언만으로 충분하며 모든 HTML 문서의 첫 번째 줄에 있어야 합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### Head 요소: `<head>`

head 섹션에는 문서에 대한 메타데이터가 포함됩니다.

```html
<!-- 문자 인코딩 -->
<meta charset="UTF-8" />
<!-- 반응형 디자인을 위한 뷰포트 -->
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<!-- 페이지 설명 -->
<meta name="description" content="Page description" />
<!-- CSS 연결 -->
<link rel="stylesheet" href="styles.css" />
<!-- 즐겨찾기 아이콘 연결 -->
<link rel="icon" href="favicon.ico" />
```

### HTML 주석: `<!-- -->`

주석은 표시되지 않지만 코드를 문서화하는 데 도움이 됩니다.

```html
<!-- 이것은 주석입니다 -->
<!-- 
  더 긴 설명을 위한
  여러 줄 주석
-->
```

### HTML 요소 해부학

HTML 요소는 시작 태그, 콘텐츠 및 닫는 태그로 구성됩니다.

```html
<!-- 콘텐츠가 있는 요소 -->
<p>이것은 단락입니다</p>
<!-- 자체 닫는 요소 -->
<img src="image.jpg" alt="Description" />
<br />
<hr />
<!-- 속성이 있는 요소 -->
<a href="https://example.com" target="_blank">링크</a>
<!-- 중첩된 요소 -->
<div>
  <p>중첩된 단락</p>
</div>
```

## 텍스트 콘텐츠 요소

### 제목: `h1` ~ `h6`

콘텐츠 섹션의 계층 구조와 중요도를 정의합니다.

```html
<h1>주요 제목</h1>
<h2>섹션 제목</h2>
<h3>하위 섹션 제목</h3>
<h4>소제목</h4>
<h5>작은 제목</h5>
<h6>가장 작은 제목</h6>
```

<BaseQuiz id="html-headings-1" correct="B">
  <template #question>
    올바른 제목 계층 구조는 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">h1 은 페이지에서 여러 번 사용되어야 합니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>h1 은 주요 제목으로 한 번 사용되어야 하며, 그 다음으로 h2, h3 등이 사용되어야 합니다</BaseQuizOption>
  <BaseQuizOption value="C">모든 제목은 동일한 중요도를 가집니다</BaseQuizOption>
  <BaseQuizOption value="D">h6 이 가장 중요한 제목입니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    HTML 제목은 논리적인 계층 구조를 따라야 합니다. 주요 페이지 제목에는 <code>h1</code> 을 한 번 사용하고, 주요 섹션에는 <code>h2</code> 를, 하위 섹션에는 <code>h3</code> 을 사용하는 식으로 진행해야 합니다. 이는 접근성과 SEO 에 도움이 됩니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 단락: `p`

텍스트 콘텐츠 블록에 가장 일반적으로 사용되는 요소입니다.

```html
<p>
  이것은 텍스트 단락입니다. 여러 문장을 포함할 수 있으며 자동으로 줄 바꿈됩니다.
</p>
<p>이것은 또 다른 단락입니다. 단락은 여백으로 구분됩니다.</p>
```

### 텍스트 서식: `<strong>`, `<em>`, `<b>`, `<i>`

인라인 텍스트 강조 및 스타일링을 위한 요소입니다.

```html
<strong>강한 중요도 (굵게)</strong>
<em>강조 (기울임꼴)</em>
<b>굵은 텍스트</b>
<i>기울임꼴 텍스트</i>
<u>밑줄 친 텍스트</u>
<mark>강조 표시된 텍스트</mark>
<small>작은 텍스트</small>
<del>삭제된 텍스트</del>
<ins>삽입된 텍스트</ins>
```

### 줄 바꿈 및 공백: `<br>`, `<hr>`, `<pre>`

콘텐츠 내에서 텍스트 흐름 및 간격을 제어합니다.

```html
<!-- 줄 바꿈 -->
첫 번째 줄<br />
두 번째 줄
<!-- 수평선 -->
<hr />
<!-- 사전 서식 지정 텍스트 -->
<pre>
  보존된    간격이 있는
      텍스트
      및 줄 바꿈
</pre>
<!-- 코드 서식 -->
<code>console.log('Hello');</code>
```

## 목록 및 탐색

### 비순서 목록: `<ul>`

순서가 없는 항목에 대해 글머리 기호 목록을 만듭니다.

```html
<ul>
  <li>첫 번째 항목</li>
  <li>두 번째 항목</li>
  <li>세 번째 항목</li>
</ul>
<!-- 중첩된 목록 -->
<ul>
  <li>
    주요 항목
    <ul>
      <li>하위 항목 1</li>
      <li>하위 항목 2</li>
    </ul>
  </li>
</ul>
```

### 순서 목록: `<ol>`

순서가 있는 항목에 대해 번호가 매겨진 목록을 만듭니다.

```html
<ol>
  <li>첫 번째 단계</li>
  <li>두 번째 단계</li>
  <li>세 번째 단계</li>
</ol>
<!-- 사용자 지정 번호 매기기 -->
<ol start="5">
  <li>5 번 항목</li>
  <li>6 번 항목</li>
</ol>
<!-- 다른 번호 매기기 유형 -->
<ol type="A">
  <li>A 항목</li>
  <li>B 항목</li>
</ol>
```

### 설명 목록: `<dl>`

용어와 해당 설명을 나열하는 목록을 만듭니다.

```html
<dl>
  <dt>HTML</dt>
  <dd>HyperText Markup Language</dd>

  <dt>CSS</dt>
  <dd>Cascading Style Sheets</dd>

  <dt>JavaScript</dt>
  <dd>웹을 위한 프로그래밍 언어</dd>
</dl>
```

### 링크 및 탐색: `<a>`

하이퍼링크 및 탐색 구조를 만듭니다.

```html
<!-- 기본 링크 -->
<a href="https://example.com">Example 방문</a>
<!-- 새 탭에서 링크 열기 -->
<a href="https://example.com" target="_blank">새 탭</a>
<!-- 이메일 링크 -->
<a href="mailto:email@example.com">이메일 보내기</a>
<!-- 전화 링크 -->
<a href="tel:+1234567890">전화 걸기</a>
<!-- 내부 페이지 앵커 -->
<a href="#section1">섹션 1 로 이동</a>
<h2 id="section1">섹션 1</h2>
```

<BaseQuiz id="html-links-1" correct="B">
  <template #question>
    앵커 태그에서 <code>target="_blank"</code> 는 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A">현재 창에서 링크를 엽니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>새 탭이나 창에서 링크를 엽니다</BaseQuizOption>
  <BaseQuizOption value="C">현재 창을 닫습니다</BaseQuizOption>
  <BaseQuizOption value="D">링크를 다운로드합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>target="_blank"</code> 속성은 연결된 페이지를 새 브라우저 탭이나 창에서 열어 사용자가 원래 페이지를 열어 둘 수 있도록 합니다.
  </BaseQuizAnswer>
</BaseQuiz>

## 폼 및 입력 요소

### 기본 폼 구조: `<form>`

사용자 입력 수집의 기반입니다.

```html
<form action="/submit" method="POST">
  <label for="username">사용자 이름:</label>
  <input type="text" id="username" name="username" required />

  <label for="email">이메일:</label>
  <input type="email" id="email" name="email" required />

  <input type="submit" value="제출" />
</form>
```

### 입력 유형: `<input>`

다양한 데이터 수집 요구 사항을 위한 다양한 입력 유형입니다.

```html
<!-- 텍스트 입력 -->
<input type="text" placeholder="텍스트 입력" />
<input type="email" placeholder="email@example.com" />
<input type="password" placeholder="비밀번호" />
<input type="url" placeholder="https://example.com" />
<input type="tel" placeholder="+1234567890" />
<!-- 숫자 입력 -->
<input type="number" min="1" max="100" step="1" />
<input type="range" min="0" max="100" value="50" />
<!-- 날짜 및 시간 -->
<input type="date" />
<input type="time" />
<input type="datetime-local" />
```

### 폼 컨트롤: `<checkbox>`, `<radio>`, `<select>`, `<textarea>`

사용자 상호 작용을 위한 추가 폼 요소입니다.

```html
<!-- 체크박스 -->
<input type="checkbox" id="agree" name="agree" />
<label for="agree">약관에 동의합니다</label>
<!-- 라디오 버튼 -->
<input type="radio" id="option1" name="choice" value="1" />
<label for="option1">옵션 1</label>
<input type="radio" id="option2" name="choice" value="2" />
<label for="option2">옵션 2</label>
<!-- 선택 드롭다운 -->
<select name="country">
  <option value="us">미국</option>
  <option value="uk">영국</option>
  <option value="ca">캐나다</option>
</select>
<!-- 텍스트 영역 -->
<textarea
  name="message"
  rows="4"
  cols="50"
  placeholder="메시지를 입력하세요"
></textarea>
```

### 폼 유효성 검사: `required`, `min`, `max`, `pattern`

내장된 HTML 폼 유효성 검사 속성입니다.

```html
<input type="text" required />
<input type="email" required />
<input type="text" minlength="3" maxlength="20" />
<input type="number" min="1" max="100" />
<input type="text" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}" />
```

<BaseQuiz id="html-validation-1" correct="A">
  <template #question>
    HTML 입력에서 <code>required</code> 속성은 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A" correct>필드가 비어 있으면 폼 제출을 방지합니다</BaseQuizOption>
  <BaseQuizOption value="B">필드를 읽기 전용으로 만듭니다</BaseQuizOption>
  <BaseQuizOption value="C">필드를 숨깁니다</BaseQuizOption>
  <BaseQuizOption value="D">기본값을 설정합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>required</code> 속성은 입력 필드를 필수 항목으로 만듭니다. 폼 제출 시 필드가 비어 있으면 브라우저는 제출을 방지하고 유효성 검사 메시지를 표시합니다.
  </BaseQuizAnswer>
</BaseQuiz>

## 미디어 요소

### 이미지: `<img>`, `<picture>`

다양한 속성과 옵션으로 이미지를 표시합니다.

```html
<!-- 기본 이미지 -->
<img src="image.jpg" alt="설명" />
<!-- 반응형 이미지 -->
<img src="image.jpg" alt="설명" width="100%" height="auto" />
<!-- 크기가 지정된 이미지 -->
<img src="image.jpg" alt="설명" width="300" height="200" />
<!-- 반응형 이미지를 위한 Picture 요소 -->
<picture>
  <source media="(min-width: 800px)" srcset="large.jpg" />
  <source media="(min-width: 400px)" srcset="medium.jpg" />
  <img src="small.jpg" alt="설명" />
</picture>
```

### 오디오: `<audio>`

재생 제어 기능을 갖춘 오디오 콘텐츠를 삽입합니다.

```html
<!-- 기본 오디오 -->
<audio controls>
  <source src="audio.mp3" type="audio/mpeg" />
  <source src="audio.ogg" type="audio/ogg" />
  브라우저가 오디오를 지원하지 않습니다.
</audio>
<!-- 자동 재생 오디오 -->
<audio controls autoplay loop>
  <source src="background.mp3" type="audio/mpeg" />
</audio>
```

### 비디오: `<video>`

포괄적인 옵션을 갖춘 비디오 콘텐츠를 삽입합니다.

```html
<!-- 기본 비디오 -->
<video controls width="400" height="300">
  <source src="video.mp4" type="video/mp4" />
  <source src="video.webm" type="video/webm" />
  브라우저가 비디오를 지원하지 않습니다.
</video>
<!-- 포스터 및 속성이 있는 비디오 -->
<video controls poster="thumbnail.jpg" width="100%" height="auto">
  <source src="video.mp4" type="video/mp4" />
  <track src="captions.vtt" kind="captions" srclang="en" label="English" />
</video>
```

### 임베드된 콘텐츠: `<iframe>`

외부 콘텐츠 및 애플리케이션을 삽입합니다.

```html
<!-- 외부 콘텐츠를 위한 iFrame -->
<iframe src="https://example.com" width="100%" height="400"></iframe>
<!-- YouTube 비디오 임베드 -->
<iframe
  width="560"
  height="315"
  src="https://www.youtube.com/embed/VIDEO_ID"
></iframe>
<!-- Google 지도 임베드 -->
<iframe src="https://maps.google.com/..."></iframe>
```

## 테이블

### 기본 테이블 구조: `<table>`

테이블을 사용하여 구조화된 데이터 표시를 만듭니다.

```html
<table>
  <thead>
    <tr>
      <th>이름</th>
      <th>나이</th>
      <th>도시</th>
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

### 고급 테이블 기능: `rowspan`, `colspan`, `<caption>`

스패닝 및 그룹화를 통한 향상된 테이블 기능입니다.

```html
<table>
  <caption>
    판매 보고서
  </caption>
  <colgroup>
    <col style="width: 50%" />
    <col style="width: 25%" />
    <col style="width: 25%" />
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">제품</th>
      <th colspan="2">판매</th>
    </tr>
    <tr>
      <th>1 분기</th>
      <th>2 분기</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>제품 A</td>
      <td>$1000</td>
      <td>$1200</td>
    </tr>
  </tbody>
</table>
```

## 시맨틱 HTML5 요소

### 페이지 구조 요소: `<header>`, `<nav>`, `<main>`, `<footer>`

페이지 레이아웃의 주요 섹션을 정의합니다.

```html
<!-- 페이지 헤더 -->
<header>
  <nav>
    <ul>
      <li><a href="#home">홈</a></li>
      <li><a href="#about">소개</a></li>
    </ul>
  </nav>
</header>
<!-- 주요 콘텐츠 -->
<main>
  <article>
    <h1>기사 제목</h1>
    <p>기사 내용...</p>
  </article>
</main>
<!-- 사이드바 -->
<aside>
  <h2>관련 링크</h2>
  <ul>
    <li><a href="#">링크 1</a></li>
  </ul>
</aside>
<!-- 페이지 푸터 -->
<footer>
  <p>© 2024 회사 이름</p>
</footer>
```

### 콘텐츠 그룹화 요소: `<section>`, `<article>`, `<div>`, `<figure>`

관련 콘텐츠 섹션을 구성하고 그룹화합니다.

```html
<!-- 일반 섹션 -->
<section>
  <h2>섹션 제목</h2>
  <p>섹션 내용...</p>
</section>
<!-- 독립형 기사 -->
<article>
  <header>
    <h1>기사 제목</h1>
    <time datetime="2024-01-01">2024 년 1 월 1 일</time>
  </header>
  <p>기사 내용...</p>
</article>
<!-- 일반 컨테이너 -->
<div class="container">
  <p>일반 콘텐츠 그룹화</p>
</div>
<!-- 캡션이 있는 그림 -->
<figure>
  <img src="chart.jpg" alt="판매 차트" />
  <figcaption>2024 년 1 분기 판매 데이터</figcaption>
</figure>
```

## HTML 속성

### 전역 속성: `id`, `class`, `title`, `data-*`

모든 HTML 요소에 사용할 수 있는 속성입니다.

```html
<!-- 고유 식별자를 위한 ID -->
<div id="unique-element">콘텐츠</div>
<!-- 스타일링 및 선택을 위한 클래스 -->
<p class="highlight important">텍스트</p>
<!-- 도구 설명 (툴팁) 을 위한 제목 -->
<span title="이것은 도구 설명입니다">나에게 마우스를 올려보세요</span>
<!-- 데이터 속성 -->
<div data-user-id="123" data-role="admin">사용자</div>
<!-- 언어 -->
<p lang="es">Hola mundo</p>
<!-- 콘텐츠 방향 -->
<p dir="rtl">오른쪽에서 왼쪽 텍스트</p>
<!-- 숨겨진 요소 -->
<div hidden>이것은 표시되지 않습니다</div>
```

### 접근성 속성: `alt`, `aria-*`, `tabindex`, `role`

접근성 및 사용자 경험을 개선하는 속성입니다.

```html
<!-- 이미지에 대한 대체 텍스트 -->
<img src="photo.jpg" alt="산 위의 일몰" />
<!-- ARIA 레이블 -->
<button aria-label="대화 상자 닫기">×</button>
<div aria-hidden="true">장식용 콘텐츠</div>
<!-- 폼 접근성 -->
<label for="email">이메일 주소:</label>
<input type="email" id="email" aria-describedby="email-help" />
<small id="email-help">이메일을 공유하지 않습니다</small>
<!-- 탭 인덱스 -->
<div tabindex="0">포커스 가능한 div</div>
<div tabindex="-1">프로그램적으로 포커스 가능한</div>
<!-- 역할 속성 -->
<div role="button" tabindex="0">사용자 지정 버튼</div>
```

## HTML5 최신 기능

### 새로운 입력 기능: `color`, `search`, `file`, `datalist`

HTML5 는 새로운 입력 유형과 속성을 도입했습니다.

```html
<!-- 새로운 입력 유형 -->
<input type="color" value="#ff0000" />
<input type="search" placeholder="검색..." />
<input type="file" accept="image/*" multiple />
<!-- 자동 완성을 위한 Datalist -->
<input list="browsers" name="browser" />
<datalist id="browsers">
  <option value="Chrome"></option>
  <option value="Firefox"></option>
  <option value="Safari"></option>
</datalist>
<!-- 진행률 및 미터 -->
<progress value="70" max="100">70%</progress>
<meter value="0.6">60%</meter>
```

### 캔버스 및 SVG: `<canvas>`, `<svg>`

HTML5 의 그래픽 및 그리기 기능입니다.

```html
<!-- 동적 그래픽을 위한 캔버스 -->
<canvas id="myCanvas" width="400" height="200">
  브라우저가 캔버스를 지원하지 않습니다.
</canvas>
<!-- 인라인 SVG -->
<svg width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue" stroke="black" stroke-width="2" />
</svg>
```

### 세부 정보 및 요약: `<details>`, `<summary>`

JavaScript 없이 접을 수 있는 콘텐츠 섹션을 만듭니다.

```html
<details>
  <summary>확장하려면 클릭하세요</summary>
  <p>이 콘텐츠는 기본적으로 숨겨져 있으며 요약을 클릭하면 표시됩니다.</p>
  <ul>
    <li>항목 1</li>
    <li>항목 2</li>
  </ul>
</details>
<details open>
  <summary>기본적으로 확장됨</summary>
  <p>기본적으로 보이는 콘텐츠입니다.</p>
</details>
```

### 대화 상자 요소: `<dialog>`

기본 대화 상자 및 모달 기능을 제공합니다.

```html
<!-- 대화 상자 요소 -->
<dialog id="myDialog">
  <h2>대화 상자 제목</h2>
  <p>대화 상자 콘텐츠는 여기에 들어갑니다.</p>
  <button onclick="closeDialog()">닫기</button>
</dialog>
<button onclick="openDialog()">대화 상자 열기</button>
<script>
  function openDialog() {
    document.getElementById('myDialog').showModal()
  }
</script>
```

## 모범 사례 및 유효성 검사

### HTML 모범 사례

깔끔하고 유지 관리하기 쉬우며 접근 가능한 HTML 을 작성합니다.

```html
<!-- 항상 doctype 을 선언하세요 -->
<!DOCTYPE html>
<!-- 시맨틱 요소를 사용하세요 -->
<header>...</header>
<main>...</main>
<footer>...</footer>
<!-- 올바른 중첩 -->
<div>
  <p>올바르게 중첩된 콘텐츠</p>
</div>
<!-- 요소와 속성에 소문자를 사용하세요 -->
<img src="image.jpg" alt="description" />
<!-- 모든 태그를 닫으세요 -->
<p>태그를 항상 닫으세요</p>
<!-- 의미 있는 alt 텍스트 사용 -->
<img src="chart.png" alt="4분기 판매량 25% 증가" />
```

### HTML 유효성 검사 및 디버깅

HTML 이 유효하고 접근 가능한지 확인합니다.

```html
<!-- W3C HTML 검사기 사용 -->
<!-- https://validator.w3.org/ -->
<!-- 일반적인 유효성 검사 오류 -->
<!-- 누락된 alt 속성 -->
<img src="image.jpg" alt="" />
<!-- alt 텍스트 제공 -->
<!-- 닫히지 않은 태그 -->
<p>텍스트 콘텐츠</p>
<!-- 항상 태그 닫기 -->
<!-- 잘못된 중첩 -->
<p>
  유효한 단락 콘텐츠
  <!-- 단락 안에 블록 요소를 넣지 마세요 -->
</p>
<!-- 개발자 도구 사용 -->
<!-- 마우스 오른쪽 버튼 클릭 → 요소 검사 -->
<!-- 콘솔에서 오류 확인 -->
<!-- WAVE 또는 axe 로 접근성 검사 -->
```

## HTML 템플릿 및 프레임워크

### 템플릿 엔진: Handlebars, Mustache

템플릿 언어를 사용한 동적 HTML 생성.

```html
<!-- Handlebars 템플릿 -->
<div>
  <h1>{{title}}</h1>
  {{#each items}}
  <p>{{this}}</p>
  {{/each}}
</div>
<!-- Mustache 템플릿 -->
<div>
  <h1>{{title}}</h1>
  {{#items}}
  <p>{{.}}</p>
  {{/items}}
</div>
```

### 웹 컴포넌트: `<template>`, 사용자 지정 요소

재사용 가능한 사용자 지정 HTML 요소.

```html
<!-- 사용자 지정 요소 정의 -->
<template id="my-component">
  <style>
    p {
      color: blue;
    }
  </style>
  <p><slot></slot></p>
</template>
<!-- 사용 -->
<my-component>Hello World</my-component>
<script>
  class MyComponent extends HTMLElement {
    // 컴포넌트 로직
  }
  customElements.define('my-component', MyComponent)
</script>
```

### 프레임워크 통합: React JSX, Vue 템플릿

최신 JavaScript 프레임워크 내의 HTML.

```html
<!-- React JSX -->
function Component() { return (
<div className="container">
  <h1>{title}</h1>
  <p>여기에 콘텐츠</p>
</div>
); }
<!-- Vue 템플릿 -->
<template>
  <div class="container">
    <h1>{{ title }}</h1>
    <p v-if="showContent">여기에 콘텐츠</p>
  </div>
</template>
```

## 관련 링크

- <router-link to="/css">CSS 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/web-development">웹 개발 치트 시트</router-link>
- <router-link to="/react">React 치트 시트</router-link>
- <router-link to="/git">Git 치트 시트</router-link>
- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>

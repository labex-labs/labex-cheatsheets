---
title: 'Matplotlib 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 포괄적인 치트 시트로 Matplotlib 을 배우세요.'
pdfUrl: '/cheatsheets/pdf/matplotlib-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Matplotlib 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/matplotlib">실습 랩을 통해 Matplotlib 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 Matplotlib 데이터 시각화를 학습하세요. LabEx 는 필수 플로팅 함수, 사용자 정의 기술, 서브플롯 레이아웃 및 고급 시각화 유형을 다루는 포괄적인 Matplotlib 강좌를 제공합니다. Python 데이터 과학 워크플로우를 위한 효과적인 데이터 시각화를 만드는 방법을 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 기본 플로팅 및 차트 유형

### 선 그래프: `plt.plot()`

연속 데이터 시각화를 위한 선 차트 생성.

```python
import matplotlib.pyplot as plt
import numpy as np

# 기본 선 그래프
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
plt.plot(x, y)
plt.show()

# 여러 선
plt.plot(x, y, label='Line 1')
plt.plot(x, [1, 3, 5, 7, 9], label='Line 2')
plt.legend()

# 선 스타일 및 색상
plt.plot(x, y, 'r--', linewidth=2, marker='o')
```

### 산점도: `plt.scatter()`

두 변수 간의 관계 표시.

```python
# 기본 산점도
plt.scatter(x, y)

# 다른 색상 및 크기 포함
colors = [1, 2, 3, 4, 5]
sizes = [20, 50, 100, 200, 500]
plt.scatter(x, y, c=colors, s=sizes, alpha=0.6)
plt.colorbar()  # 색상 막대 추가
```

### 막대 차트: `plt.bar()` / `plt.barh()`

수직 또는 수평 막대 차트 생성.

```python
# 수직 막대
categories = ['A', 'B', 'C', 'D']
values = [20, 35, 30, 25]
plt.bar(categories, values)

# 수평 막대
plt.barh(categories, values)

# 그룹화된 막대
x = np.arange(len(categories))
plt.bar(x - 0.2, values, 0.4, label='Group 1')
plt.bar(x + 0.2, [15, 25, 35, 20], 0.4, label='Group 2')
```

### 히스토그램: `plt.hist()`

연속 데이터의 분포 표시.

```python
# 기본 히스토그램
data = np.random.randn(1000)
plt.hist(data, bins=30)

# 사용자 정의 히스토그램
plt.hist(data, bins=50, alpha=0.7, color='skyblue', edgecolor='black')

# 여러 히스토그램
plt.hist([data1, data2], bins=30, alpha=0.7, label=['Data 1', 'Data 2'])
```

### 파이 차트: `plt.pie()`

비율 데이터를 원형 차트로 표시.

```python
# 기본 파이 차트
sizes = [25, 35, 20, 20]
labels = ['A', 'B', 'C', 'D']
plt.pie(sizes, labels=labels)

# 백분율이 포함된 분리된 파이 차트
explode = (0, 0.1, 0, 0)  # 두 번째 조각 분리
plt.pie(sizes, labels=labels, autopct='%1.1f%%',
        explode=explode, shadow=True, startangle=90)
```

### 상자 그림 (Box Plot): `plt.boxplot()`

데이터 분포 및 이상치 시각화.

```python
# 단일 상자 그림
data = [np.random.randn(100) for _ in range(4)]
plt.boxplot(data)

# 사용자 정의 상자 그림
plt.boxplot(data, labels=['Group 1', 'Group 2', 'Group 3', 'Group 4'],
           patch_artist=True, notch=True)
```

## 플롯 사용자 정의 및 스타일링

### 레이블 및 제목: `plt.xlabel()` / `plt.title()`

명확성과 맥락을 위해 플롯에 설명 텍스트 추가.

```python
# 기본 레이블 및 제목
plt.plot(x, y)
plt.xlabel('X 축 레이블')
plt.ylabel('Y 축 레이블')
plt.title('플롯 제목')

# 글꼴 속성을 사용한 서식 지정된 제목
plt.title('내 플롯', fontsize=16, fontweight='bold')
plt.xlabel('X 값', fontsize=12)

# 가독성을 위한 그리드
plt.grid(True, alpha=0.3)
```

### 색상 및 스타일: `color` / `linestyle` / `marker`

플롯 요소의 시각적 모양 사용자 정의.

```python
# 색상 옵션
plt.plot(x, y, color='red')  # 이름 지정된 색상
plt.plot(x, y, color='#FF5733')  # 16 진수 색상
plt.plot(x, y, color=(0.1, 0.2, 0.5))  # RGB 튜플

# 선 스타일
plt.plot(x, y, linestyle='--')  # 점선
plt.plot(x, y, linestyle=':')   # 점선
plt.plot(x, y, linestyle='-.')  # 대시 - 점선

# 마커
plt.plot(x, y, marker='o', markersize=8, markerfacecolor='red')
```

### 범례 및 주석: `plt.legend()` / `plt.annotate()`

범례와 주석을 추가하여 플롯 요소 설명.

```python
# 기본 범례
plt.plot(x, y1, label='데이터셋 1')
plt.plot(x, y2, label='데이터셋 2')
plt.legend()

# 범례 위치 사용자 정의
plt.legend(loc='upper right', fontsize=10, frameon=False)

# 주석
plt.annotate('중요 지점', xy=(2, 4), xytext=(3, 6),
            arrowprops=dict(arrowstyle='->', color='red'))
```

## 축 및 레이아웃 제어

### 축 범위: `plt.xlim()` / `plt.ylim()`

각 축에 표시되는 값의 범위를 제어합니다.

```python
# 축 범위 설정
plt.xlim(0, 10)
plt.ylim(-5, 15)

# 여백을 포함한 자동 범위 조정
plt.margins(x=0.1, y=0.1)

# 축 반전
plt.gca().invert_yaxis()  # y 축 반전
```

### 틱 및 레이블: `plt.xticks()` / `plt.yticks()`

축 틱 마크와 해당 레이블 사용자 정의.

```python
# 사용자 정의 틱 위치
plt.xticks([0, 2, 4, 6, 8, 10])
plt.yticks(np.arange(0, 101, 10))

# 사용자 정의 틱 레이블
plt.xticks([0, 1, 2, 3], ['1 월', '2 월', '3 월', '4 월'])

# 틱 레이블 회전
plt.xticks(rotation=45)

# 틱 제거
plt.xticks([])
plt.yticks([])
```

### 종횡비: `plt.axis()`

종횡비 및 축 모양 제어.

```python
# 동일한 종횡비
plt.axis('equal')
# 정사각형 플롯
plt.axis('square')
# 축 끄기
plt.axis('off')
# 사용자 정의 종횡비
plt.gca().set_aspect('equal', adjustable='box')
```

### 그림 크기: `plt.figure()`

전체 그림의 크기와 해상도 제어.

```python
# 그림 크기 설정 (너비, 높이 인치)
plt.figure(figsize=(10, 6))

# 더 나은 품질을 위한 높은 DPI
plt.figure(figsize=(8, 6), dpi=300)

# 여러 그림
fig1 = plt.figure(1)
plt.plot(x, y1)
fig2 = plt.figure(2)
plt.plot(x, y2)
```

### 깔끔한 레이아웃: `plt.tight_layout()`

서브플롯 간격을 자동으로 조정하여 모양 개선.

```python
# 겹치는 요소 방지
plt.tight_layout()

# 수동 간격 조정
plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)

# 서브플롯 주변 패딩
plt.tight_layout(pad=3.0)
```

### 스타일 시트: `plt.style.use()`

일관된 플롯 모양을 위해 사전 정의된 스타일 적용.

```python
# 사용 가능한 스타일
print(plt.style.available)

# 내장 스타일 사용
plt.style.use('seaborn-v0_8')
plt.style.use('ggplot')
plt.style.use('bmh')

# 기본값으로 재설정
plt.style.use('default')
```

## 서브플롯 및 여러 플롯

### 기본 서브플롯: `plt.subplot()` / `plt.subplots()`

단일 그림 내에 여러 플롯 생성.

```python
# 2x2 서브플롯 그리드 생성
fig, axes = plt.subplots(2, 2, figsize=(10, 8))

# 각 서브플롯에 플롯
axes[0, 0].plot(x, y)
axes[0, 1].scatter(x, y)
axes[1, 0].bar(x, y)
axes[1, 1].hist(y, bins=10)

# 대안 구문
plt.subplot(2, 2, 1)  # 2 행, 2 열, 첫 번째 서브플롯
plt.plot(x, y)
plt.subplot(2, 2, 2)  # 두 번째 서브플롯
plt.scatter(x, y)
```

### 공유 축: `sharex` / `sharey`

일관된 스케일링을 위해 서브플롯 간 축 연결.

```python
# 서브플롯 간 x 축 공유
fig, axes = plt.subplots(2, 1, sharex=True)
axes[0].plot(x, y1)
axes[1].plot(x, y2)

# 두 축 모두 공유
fig, axes = plt.subplots(2, 2, sharex=True, sharey=True)
```

### GridSpec: 고급 레이아웃

다양한 크기의 서브플롯을 가진 복잡한 서브플롯 배열 생성.

```python
import matplotlib.gridspec as gridspec

# 사용자 정의 그리드 생성
gs = gridspec.GridSpec(3, 3)
fig = plt.figure(figsize=(10, 8))

# 크기가 다른 서브플롯
ax1 = fig.add_subplot(gs[0, :])  # 맨 위 행, 모든 열
ax2 = fig.add_subplot(gs[1, :-1])  # 중간 행, 처음 2 개 열
ax3 = fig.add_subplot(gs[1:, -1])  # 마지막 열, 아래 2 개 행
ax4 = fig.add_subplot(gs[-1, 0])   # 왼쪽 아래
ax5 = fig.add_subplot(gs[-1, 1])   # 가운데 아래
```

### 서브플롯 간격: `hspace` / `wspace`

서브플롯 간의 간격 제어.

```python
# 서브플롯 생성 시 간격 조정
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
plt.subplots_adjust(hspace=0.4, wspace=0.3)

# 또는 자동 조정을 위해 tight_layout 사용
plt.tight_layout()
```

## 고급 시각화 유형

### 히트맵: `plt.imshow()` / `plt.pcolormesh()`

색상 코딩된 행렬로 2D 데이터 시각화.

```python
# 기본 히트맵
data = np.random.randn(10, 10)
plt.imshow(data, cmap='viridis')
plt.colorbar()

# 불규칙한 그리드에 대한 Pcolormesh
x = np.linspace(0, 10, 11)
y = np.linspace(0, 5, 6)
X, Y = np.meshgrid(x, y)
Z = np.sin(X) * np.cos(Y)
plt.pcolormesh(X, Y, Z, shading='auto')
plt.colorbar()
```

### 등고선 플롯: `plt.contour()` / `plt.contourf()`

레벨 곡선 및 채워진 등고선 영역 표시.

```python
# 등고선
x = np.linspace(-3, 3, 100)
y = np.linspace(-3, 3, 100)
X, Y = np.meshgrid(x, y)
Z = X**2 + Y**2
plt.contour(X, Y, Z, levels=10)
plt.clabel(plt.contour(X, Y, Z), inline=True, fontsize=8)

# 채워진 등고선
plt.contourf(X, Y, Z, levels=20, cmap='RdBu')
plt.colorbar()
```

### 3D 플롯: `mplot3d`

3 차원 시각화 생성.

```python
from mpl_toolkits.mplot3d import Axes3D

fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# 3D 산점도
ax.scatter(x, y, z)

# 3D 표면 플롯
ax.plot_surface(X, Y, Z, cmap='viridis')

# 3D 선 플롯
ax.plot(x, y, z)
```

### 오차 막대: `plt.errorbar()`

불확실성 측정값을 포함하여 데이터 표시.

```python
# 기본 오차 막대
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
yerr = [0.5, 0.8, 0.3, 0.7, 0.4]
plt.errorbar(x, y, yerr=yerr, fmt='o-', capsize=5)

# 비대칭 오차 막대
yerr_lower = [0.4, 0.6, 0.2, 0.5, 0.3]
yerr_upper = [0.6, 1.0, 0.4, 0.9, 0.5]
plt.errorbar(x, y, yerr=[yerr_lower, yerr_upper], fmt='s-')
```

### 두 영역 채우기: `plt.fill_between()`

곡선 사이 또는 선 주변 영역 음영 처리.

```python
# 두 곡선 사이 채우기
y1 = [2, 4, 6, 8, 10]
y2 = [1, 3, 5, 7, 9]
plt.fill_between(x, y1, y2, alpha=0.3, color='blue')

# 오차를 포함한 선 주변 채우기
plt.plot(x, y, 'k-', linewidth=2)
plt.fill_between(x, y-yerr, y+yerr, alpha=0.2, color='gray')
```

### 바이올린 플롯: 상자 그림의 대안

사분위수와 함께 분포 모양 표시.

```python
# pyplot 사용
parts = plt.violinplot([data1, data2, data3])

# 색상 사용자 정의
for pc in parts['bodies']:
    pc.set_facecolor('lightblue')
    pc.set_alpha(0.7)
```

## 대화형 및 애니메이션 기능

### 대화형 백엔드: `%matplotlib widget`

Jupyter 노트북에서 대화형 플롯 활성화.

```python
# Jupyter 노트북에서
%matplotlib widget

# 기본 상호 작용을 위해
%matplotlib notebook
```

### 이벤트 처리: 마우스 및 키보드

플롯에 대한 사용자 상호 작용에 응답.

```python
# 대화형 확대/축소, 이동 및 호버
def onclick(event):
    if event.inaxes:
        print(f'클릭 위치 x={event.xdata}, y={event.ydata}')

fig, ax = plt.subplots()
ax.plot(x, y)
fig.canvas.mpl_connect('button_press_event', onclick)
plt.show()
```

### 애니메이션: `matplotlib.animation`

시계열 또는 변경되는 데이터를 위한 애니메이션 플롯 생성.

```python
from matplotlib.animation import FuncAnimation

fig, ax = plt.subplots()
line, = ax.plot([], [], 'r-')
ax.set_xlim(0, 10)
ax.set_ylim(-2, 2)

def animate(frame):
    x = np.linspace(0, 10, 100)
    y = np.sin(x + frame * 0.1)
    line.set_data(x, y)
    return line,

ani = FuncAnimation(fig, animate, frames=200, blit=True, interval=50)
plt.show()

# 애니메이션 저장
# ani.save('animation.gif', writer='pillow')
```

## 플롯 저장 및 내보내기

### 그림 저장: `plt.savefig()`

다양한 옵션으로 플롯을 이미지 파일로 내보내기.

```python
# 기본 저장
plt.savefig('my_plot.png')

# 고품질 저장
plt.savefig('plot.png', dpi=300, bbox_inches='tight')

# 다른 형식
plt.savefig('plot.pdf')  # PDF
plt.savefig('plot.svg')  # SVG (벡터)
plt.savefig('plot.eps')  # EPS

# 투명한 배경
plt.savefig('plot.png', transparent=True)
```

### 그림 품질: DPI 및 크기

저장된 플롯의 해상도 및 치수 제어.

```python
# 출판물을 위한 고해상도 DPI
plt.savefig('plot.png', dpi=600)

# 사용자 정의 크기 (너비, 높이 인치)
plt.figure(figsize=(12, 8))
plt.savefig('plot.png', figsize=(12, 8))

# 공백 자르기
plt.savefig('plot.png', bbox_inches='tight', pad_inches=0.1)
```

### 일괄 내보내기 및 메모리 관리

여러 플롯을 처리하고 메모리 효율성 유지.

```python
# 메모리 확보를 위해 그림 닫기
plt.close()  # 현재 그림 닫기
plt.close('all')  # 모든 그림 닫기

# 자동 정리를 위한 컨텍스트 관리자
with plt.figure() as fig:
    plt.plot(x, y)
    plt.savefig('plot.png')

# 일괄 저장 여러 플롯
for i, data in enumerate(datasets):
    plt.figure()
    plt.plot(data)
    plt.savefig(f'plot_{i}.png')
    plt.close()
```

## 구성 및 모범 사례

### RC 매개변수: `plt.rcParams`

모든 플롯에 대한 기본 스타일 및 동작 설정.

```python
# 일반적인 rc 매개변수
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 12
plt.rcParams['lines.linewidth'] = 2
plt.rcParams['axes.grid'] = True

# 설정 저장 및 복원
original_params = plt.rcParams.copy()
# ... 변경 사항 적용 ...
plt.rcParams.update(original_params)  # 복원
```

### 색상 관리: 색상 맵 및 팔레트

색상 및 색상 맵을 효과적으로 사용.

```python
# 사용 가능한 색상 맵 나열
print(plt.colormaps())

# 여러 선에 색상 맵 사용
colors = plt.cm.viridis(np.linspace(0, 1, len(datasets)))
for i, (data, color) in enumerate(zip(datasets, colors)):
    plt.plot(data, color=color, label=f'데이터셋 {i+1}')

# 사용자 정의 색상 맵
from matplotlib.colors import LinearSegmentedColormap
custom_cmap = LinearSegmentedColormap.from_list('custom', ['red', 'yellow', 'blue'])
```

### 성능 최적화

대규모 데이터셋에 대한 플로팅 성능 향상.

```python
# 애니메이션을 위한 블리팅 사용
ani = FuncAnimation(fig, animate, blit=True)

# 복잡한 플롯 래스터화
plt.plot(x, y, rasterized=True)

# 대규모 데이터셋에 대한 데이터 포인트 감소
# 플로팅 전에 데이터 다운샘플링
indices = np.arange(0, len(large_data), step=10)
plt.plot(large_data[indices])
```

### 메모리 사용량: 효율적인 플로팅

많은 플롯 또는 대규모 시각화를 만들 때 메모리 관리.

```python
# 새 그림을 만드는 대신 축 지우기
fig, ax = plt.subplots()
for data in datasets:
    ax.clear()  # 이전 플롯 지우기
    ax.plot(data)
    plt.savefig(f'plot_{i}.png')

# 대규모 데이터셋에 대한 제너레이터 사용
def data_generator():
    for i in range(1000):
        yield np.random.randn(100)

for i, data in enumerate(data_generator()):
    if i > 10:  # 플롯 개수 제한
        break
```

## 데이터 라이브러리와의 통합

### Pandas 통합: 직접 플로팅

Pandas DataFrame 메서드를 통한 Matplotlib 사용.

```python
import pandas as pd

# DataFrame 플로팅 (matplotlib 백엔드 사용)
df.plot(kind='line', x='date', y='value')
df.plot.scatter(x='x_col', y='y_col')
df.plot.hist(bins=30)
df.plot.box()

# 기본 matplotlib 객체 액세스
ax = df.plot(kind='line')
ax.set_title('사용자 정의 제목')
plt.show()
```

### NumPy 통합: 배열 시각화

NumPy 배열 및 수학 함수 효율적으로 플로팅.

```python
# 2D 배열 시각화
arr = np.random.rand(10, 10)
plt.imshow(arr, cmap='hot', interpolation='nearest')

# 수학 함수
x = np.linspace(0, 4*np.pi, 1000)
y = np.sin(x) * np.exp(-x/10)
plt.plot(x, y)

# 통계 분포
data = np.random.normal(0, 1, 10000)
plt.hist(data, bins=50, density=True, alpha=0.7)
```

### Seaborn 통합: 향상된 스타일링

Seaborn 과 Matplotlib 을 결합하여 기본 미학 개선.

```python
import seaborn as sns

# matplotlib 와 함께 seaborn 스타일 사용
sns.set_style('whitegrid')
plt.plot(x, y)
plt.show()

# seaborn 및 matplotlib 혼합
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
sns.scatterplot(data=df, x='x', y='y', ax=axes[0,0])
plt.plot(x, y, ax=axes[0,1])  # 순수 matplotlib
```

### Jupyter 통합: 인라인 플로팅

Jupyter 노트북 환경에 맞게 Matplotlib 최적화.

```python
# Jupyter 매직 명령어
%matplotlib inline  # 정적 플롯
%matplotlib widget  # 대화형 플롯

# 고해상도 디스플레이
%config InlineBackend.figure_format = 'retina'

# 자동 그림 크기 조정
%matplotlib inline
plt.rcParams['figure.dpi'] = 100
```

## 설치 및 환경 설정

### Pip: `pip install matplotlib`

Matplotlib 용 표준 Python 패키지 설치 관리자.

```bash
# Matplotlib 설치
pip install matplotlib

# 최신 버전으로 업그레이드
pip install matplotlib --upgrade

# 추가 백엔드와 함께 설치
pip install matplotlib[qt5]

# 패키지 정보 표시
pip show matplotlib
```

### Conda: `conda install matplotlib`

Anaconda/Miniconda 환경용 패키지 관리자.

```bash
# 현재 환경에 설치
conda install matplotlib

# matplotlib 업데이트
conda update matplotlib

# matplotlib를 포함한 환경 생성
conda create -n dataviz matplotlib numpy pandas

# matplotlib 정보 나열
conda list matplotlib
```

### 백엔드 구성

다양한 환경에 대한 디스플레이 백엔드 설정.

```python
# 사용 가능한 백엔드 확인
import matplotlib
print(matplotlib.get_backend())

# 프로그래밍 방식으로 백엔드 설정
matplotlib.use('TkAgg')  # Tkinter 용
matplotlib.use('Qt5Agg')  # PyQt5 용

# 헤드리스 서버용
matplotlib.use('Agg')

# 백엔드 설정 후 가져오기
import matplotlib.pyplot as plt
```

## 관련 링크

- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/numpy">NumPy 치트 시트</router-link>
- <router-link to="/pandas">Pandas 치트 시트</router-link>
- <router-link to="/sklearn">scikit-learn 치트 시트</router-link>
- <router-link to="/datascience">데이터 과학 치트 시트</router-link>

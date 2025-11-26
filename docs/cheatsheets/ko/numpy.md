---
title: 'NumPy 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 종합 치트 시트로 NumPy 를 학습하세요.'
pdfUrl: '/cheatsheets/pdf/numpy-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
NumPy 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/numpy">실습 랩을 통한 NumPy 학습</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 NumPy 수치 계산을 학습하세요. LabEx 는 필수적인 배열 연산, 수학 함수, 선형 대수 및 성능 최적화를 다루는 포괄적인 NumPy 과정을 제공합니다. 데이터 과학 워크플로우를 위한 효율적인 수치 계산 및 배열 조작을 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 배열 생성 및 초기화

### 리스트로부터: `np.array()`

Python 리스트 또는 중첩 리스트로부터 배열을 생성합니다.

```python
import numpy as np

# 리스트로부터 1D 배열 생성
arr = np.array([1, 2, 3, 4])
# 중첩 리스트로부터 2D 배열 생성
arr2d = np.array([[1, 2], [3, 4]])
# 데이터 타입 지정
arr = np.array([1, 2, 3], dtype=float)
# 문자열 배열
arr_str = np.array(['a', 'b', 'c'])
```

### 0 또는 1 로 채우기: `np.zeros()` / `np.ones()`

0 또는 1 로 채워진 배열을 생성합니다.

```python
# 0 으로 채워진 배열
zeros = np.zeros(5)  # 1D
zeros2d = np.zeros((3, 4))  # 2D
# 1 로 채워진 배열
ones = np.ones((2, 3))
# 데이터 타입 지정
zeros_int = np.zeros(5, dtype=int)
```

### 단위 행렬: `np.eye()` / `np.identity()`

선형 대수 연산을 위한 단위 행렬을 생성합니다.

```python
# 3x3 단위 행렬
identity = np.eye(3)
# 대체 방법
identity2 = np.identity(4)
```

### 범위 배열: `np.arange()` / `np.linspace()`

균일한 간격의 값으로 배열을 생성합니다.

```python
# Python range 와 유사
arr = np.arange(10)  # 0 부터 9 까지
arr = np.arange(2, 10, 2)  # 2, 4, 6, 8
# 균일하게 간격이 지정된 값
arr = np.linspace(0, 1, 5)  # 0 부터 1 까지 5 개의 값
# 끝점 포함
arr = np.linspace(0, 10, 11)
```

### 랜덤 배열: `np.random`

랜덤 값으로 배열을 생성합니다.

```python
# 0 과 1 사이의 랜덤 값
rand = np.random.random((2, 3))
# 랜덤 정수
rand_int = np.random.randint(0, 10, size=(3, 3))
# 정규 분포
normal = np.random.normal(0, 1, size=5)
# 재현성을 위한 랜덤 시드 설정
np.random.seed(42)
```

### 특수 배열: `np.full()` / `np.empty()`

특정 값으로 채워진 배열 또는 초기화되지 않은 배열을 생성합니다.

```python
# 특정 값으로 채우기
full_arr = np.full((2, 3), 7)
# 빈 배열 (초기화되지 않음)
empty_arr = np.empty((2, 2))
# 기존 배열 모양과 같은 배열
like_arr = np.zeros_like(arr)
```

## 배열 속성 및 구조

### 기본 속성: `shape` / `size` / `ndim`

배열의 차원과 크기에 대한 기본 정보를 얻습니다.

```python
# 배열 차원 (튜플)
arr.shape
# 총 요소 수
arr.size
# 차원 수
arr.ndim
# 요소의 데이터 타입
arr.dtype
# 각 요소의 바이트 크기
arr.itemsize
```

### 배열 정보: 메모리 사용량

배열 메모리 사용량 및 구조에 대한 자세한 정보를 얻습니다.

```python
# 바이트 단위 메모리 사용량
arr.nbytes
# 배열 정보 (디버깅용)
arr.flags
# 배열이 데이터를 소유하는지 확인
arr.owndata
# (배열이 뷰인 경우) 기본 객체
arr.base
```

### 데이터 타입: `astype()`

다른 데이터 타입 간에 효율적으로 변환합니다.

```python
# 다른 타입으로 변환
arr.astype(float)
arr.astype(int)
arr.astype(str)
# 더 구체적인 타입
arr.astype(np.float32)
arr.astype(np.int16)
```

## 배열 인덱싱 및 슬라이싱

### 기본 인덱싱: `arr[index]`

개별 요소와 슬라이스에 접근합니다.

```python
# 단일 요소
arr[0]  # 첫 번째 요소
arr[-1]  # 마지막 요소
# 2D 배열 인덱싱
arr2d[0, 1]  # 0 행, 1 열
arr2d[1]  # 전체 1 행
# 슬라이싱
arr[1:4]  # 1 번째부터 3 번째 요소까지
arr[::2]  # 두 번째 요소마다
arr[::-1]  # 배열 역순
```

### 불리언 인덱싱: `arr[condition]`

조건을 기반으로 배열을 필터링합니다.

```python
# 간단한 조건
arr[arr > 5]
# 다중 조건
arr[(arr > 2) & (arr < 8)]
arr[(arr < 2) | (arr > 8)]
# 불리언 배열
mask = arr > 3
filtered = arr[mask]
```

### 고급 인덱싱: Fancy Indexing

인덱스 배열을 사용하여 여러 요소에 접근합니다.

```python
# 인덱스 배열로 인덱싱
indices = [0, 2, 4]
arr[indices]
# 2D 팬시 인덱싱
arr2d[[0, 1], [1, 2]]  # (0,1) 및 (1,2) 요소
# 슬라이싱과 결합
arr2d[1:, [0, 2]]
```

### Where 함수: `np.where()`

조건부 선택 및 요소 대체.

```python
# 조건이 참인 인덱스 찾기
indices = np.where(arr > 5)
# 조건부 대체
result = np.where(arr > 5, arr, 0)  # 5 보다 큰 값은 0 으로 대체
# 다중 조건
result = np.where(arr > 5, 'high', 'low')
```

## 배열 조작 및 재구성

### 재구성: `reshape()` / `resize()` / `flatten()`

데이터를 보존하면서 배열 차원을 변경합니다.

```python
# 재구성 (가능하면 뷰 생성)
arr.reshape(2, 3)
arr.reshape(-1, 1)  # -1 은 차원 추론
# 크기 조정 (원본 배열 수정)
arr.resize((2, 3))
# 1D 로 평탄화
arr.flatten()  # 복사본 반환
arr.ravel()  # 가능하면 뷰 반환
```

### 전치: `T` / `transpose()`

행렬 연산을 위해 배열 축을 교환합니다.

```python
# 간단한 전치
arr2d.T
# 축 지정 전치
arr.transpose()
np.transpose(arr)
# 고차원용 전치
arr3d.transpose(2, 0, 1)
```

### 요소 추가/제거

요소를 추가하거나 제거하여 배열 크기를 수정합니다.

```python
# 요소 추가
np.append(arr, [4, 5])
# 특정 위치에 삽입
np.insert(arr, 1, 99)
# 요소 삭제
np.delete(arr, [1, 3])
# 요소 반복
np.repeat(arr, 3)
np.tile(arr, 2)
```

### 배열 결합: `concatenate()` / `stack()`

여러 배열을 함께 연결합니다.

```python
# 기존 축을 따라 연결
np.concatenate([arr1, arr2])
np.concatenate([arr1, arr2], axis=1)
# 배열 스택 (새로운 축 생성)
np.vstack([arr1, arr2])  # 수직으로
np.hstack([arr1, arr2])  # 수평으로
np.dstack([arr1, arr2])  # 깊이 방향으로
```

## 수학 연산

### 기본 산술: `+`, `-`, `*`, `/`

배열에 대한 요소별 산술 연산입니다.

```python
# 요소별 연산
arr1 + arr2
arr1 - arr2
arr1 * arr2  # 요소별 곱셈
arr1 / arr2
arr1 ** 2  # 제곱
arr1 % 3  # 모듈로 연산
```

### 범용 함수 (ufuncs)

수학 함수를 요소별로 적용합니다.

```python
# 삼각 함수
np.sin(arr)
np.cos(arr)
np.tan(arr)
# 지수 및 로그
np.exp(arr)
np.log(arr)
np.log10(arr)
# 제곱근 및 거듭제곱
np.sqrt(arr)
np.power(arr, 3)
```

### 집계 함수

배열 차원에 걸쳐 요약 통계를 계산합니다.

```python
# 기본 통계
np.sum(arr)
np.mean(arr)
np.std(arr)  # 표준 편차
np.var(arr)  # 분산
np.min(arr)
np.max(arr)
# 특정 축을 따라
np.sum(arr2d, axis=0)  # 행을 따라 합계
np.mean(arr2d, axis=1)  # 열을 따라 평균
```

### 비교 연산

불리언 배열을 반환하는 요소별 비교 연산입니다.

```python
# 비교 연산자
arr > 5
arr == 3
arr != 0
# 배열 비교
np.array_equal(arr1, arr2)
np.allclose(arr1, arr2)  # 허용 오차 내에서
# Any/all 연산
np.any(arr > 5)
np.all(arr > 0)
```

## 선형 대수

### 행렬 연산: `np.dot()` / `@`

행렬 곱셈 및 내적을 수행합니다.

```python
# 행렬 곱셈
np.dot(A, B)
A @ B  # Python 3.5+ 연산자
# 요소별 곱셈
A * B
# 행렬 거듭제곱
np.linalg.matrix_power(A, 3)
```

### 분해: `np.linalg`

고급 계산을 위한 행렬 분해.

```python
# 고윳값 및 고유 벡터
eigenvals, eigenvecs = np.linalg.eig(A)
# 특이값 분해
U, s, Vt = np.linalg.svd(A)
# QR 분해
Q, R = np.linalg.qr(A)
```

### 행렬 속성

중요한 행렬 특성을 계산합니다.

```python
# 행렬식
np.linalg.det(A)
# 행렬 역행렬
np.linalg.inv(A)
# 유사 역행렬
np.linalg.pinv(A)
# 행렬 랭크
np.linalg.matrix_rank(A)
# 트레이스 (대각선 합)
np.trace(A)
```

### 선형 시스템 풀이: `np.linalg.solve()`

선형 방정식 시스템을 풉니다.

```python
# Ax = b 풀기
x = np.linalg.solve(A, b)
# 최소 제곱 해
x = np.linalg.lstsq(A, b, rcond=None)[0]
```

## 배열 입력/출력

### NumPy 바이너리: `np.save()` / `np.load()`

NumPy 배열을 위한 효율적인 바이너리 형식.

```python
# 단일 배열 저장
np.save('array.npy', arr)
# 배열 로드
loaded_arr = np.load('array.npy')
# 다중 배열 저장
np.savez('arrays.npz', a=arr1, b=arr2)
# 다중 배열 로드
data = np.load('arrays.npz')
arr1_loaded = data['a']
```

### 텍스트 파일: `np.loadtxt()` / `np.savetxt()`

배열을 텍스트 파일로 읽고 씁니다.

```python
# CSV/텍스트 파일에서 로드
arr = np.loadtxt('data.csv', delimiter=',')
# 헤더 행 건너뛰기
arr = np.loadtxt('data.csv', delimiter=',', skiprows=1)
# 텍스트 파일에 저장
np.savetxt('output.csv', arr, delimiter=',', fmt='%.2f')
```

### 구조화된 데이터용 CSV: `np.genfromtxt()`

누락된 데이터 처리를 위한 고급 텍스트 파일 읽기.

```python
# 누락된 값 처리
arr = np.genfromtxt('data.csv', delimiter=',',
                    missing_values='N/A', filling_values=0)
# 이름 붙여진 열
data = np.genfromtxt('data.csv', delimiter=',',
                     names=True, dtype=None)
```

### 메모리 매핑: `np.memmap()`

메모리에 맞지 않는 배열을 다룹니다.

```python
# 메모리 매핑된 배열 생성
mmap_arr = np.memmap('large_array.dat', dtype='float32',
                     mode='w+', shape=(1000000,))
# 디스크에 저장된 것처럼 일반 배열처럼 접근
mmap_arr[0:10] = np.random.random(10)
```

## 성능 및 브로드캐스팅

### 브로드캐스팅 규칙

서로 다른 모양의 배열을 NumPy 가 처리하는 방법을 이해합니다.

```python
# 브로드캐스팅 예시
arr1 = np.array([[1, 2, 3]])  # 모양 (1, 3)
arr2 = np.array([[1], [2]])   # 모양 (2, 1)
result = arr1 + arr2          # 모양 (2, 3)
# 스칼라 브로드캐스팅
arr + 5  # 모든 요소에 5 를 더함
arr * 2  # 모든 요소를 2 로 곱함
```

### 벡터화된 연산

Python 루프 대신 NumPy 의 내장 함수를 사용합니다.

```python
# 루프 대신 벡터화된 연산 사용
# 나쁨: for 루프
result = []
for x in arr:
    result.append(x ** 2)
# 좋음: 벡터화됨
result = arr ** 2
# 사용자 정의 벡터화 함수
def custom_func(x):
    return x ** 2 + 2 * x + 1
vec_func = np.vectorize(custom_func)
result = vec_func(arr)
```

### 메모리 최적화

대용량 배열에 대한 효율적인 메모리 사용 기술.

```python
# 적절한 데이터 타입 사용
arr_int8 = arr.astype(np.int8)  # 요소당 1 바이트
arr_float32 = arr.astype(np.float32)  # float64 에 비해 4 바이트
# 뷰 대 복사본
view = arr[::2]  # 뷰 생성 (메모리 공유)
copy = arr[::2].copy()  # 복사본 생성 (새 메모리)
# 배열이 뷰인지 복사본인지 확인
view.base is arr  # 뷰의 경우 True
```

### 성능 팁

빠른 NumPy 코드를 위한 모범 사례.

```python
# 가능한 경우 인플레이스 연산 사용
arr += 5  # arr = arr + 5 대신
np.add(arr, 5, out=arr)  # 명시적 인플레이스
# 배열 생성 최소화
# 나쁨: 중간 배열 생성
result = ((arr + 1) * 2) ** 2
# 좋음: 가능한 경우 복합 연산 사용
```

## 난수 생성

### 기본 랜덤: `np.random`

다양한 분포에서 난수를 생성합니다.

```python
# 랜덤 실수 [0, 1)
np.random.random(5)
# 랜덤 정수
np.random.randint(0, 10, size=5)
# 정규 분포
np.random.normal(mu=0, sigma=1, size=5)
# 균일 분포
np.random.uniform(-1, 1, size=5)
```

### 샘플링: `choice()` / `shuffle()`

기존 데이터에서 샘플링하거나 배열을 순열화합니다.

```python
# 배열에서 랜덤 선택
np.random.choice(arr, size=3)
# 비복원 추출
np.random.choice(arr, size=3, replace=False)
# 배열을 인플레이스로 섞기
np.random.shuffle(arr)
# 랜덤 순열
np.random.permutation(arr)
```

### 시드 및 생성기

재현성을 위해 난수 생성을 제어합니다.

```python
# 재현성을 위한 시드 설정
np.random.seed(42)
# 최신 접근 방식: 생성기
rng = np.random.default_rng(42)
rng.random(5)
rng.integers(0, 10, size=5)
rng.normal(0, 1, size=5)
```

## 통계 함수

### 기술 통계

중심 경향 및 분산에 대한 기본 통계 측정값.

```python
# 중심 경향
np.mean(arr)
np.median(arr)
# 분산 측정값
np.std(arr)  # 표준 편차
np.var(arr)  # 분산
np.ptp(arr)  # 범위 (max - min)
# 분위수
np.percentile(arr, [25, 50, 75])
np.quantile(arr, [0.25, 0.5, 0.75])
```

### 상관관계 및 공분산

변수 간의 관계를 측정합니다.

```python
# 상관 계수
np.corrcoef(x, y)
# 공분산
np.cov(x, y)
# 상호 상관관계
np.correlate(x, y, mode='full')
```

### 히스토그램 및 비닝

데이터 분포를 분석하고 빈을 생성합니다.

```python
# 히스토그램
counts, bins = np.histogram(arr, bins=10)
# 2D 히스토그램
H, xedges, yedges = np.histogram2d(x, y, bins=10)
# 이산화 (빈 인덱스 할당)
bin_indices = np.digitize(arr, bins)
```

### 특수 통계 함수

고급 통계 계산.

```python
# 가중 통계
np.average(arr, weights=weights)
# 고유 값 및 개수
unique_vals, counts = np.unique(arr, return_counts=True)
# Bincount (정수 배열용)
np.bincount(int_arr)
```

## NumPy 설치 및 설정

### Pip: `pip install numpy`

표준 Python 패키지 설치 관리자.

```bash
# NumPy 설치
pip install numpy
# 최신 버전으로 업그레이드
pip install numpy --upgrade
# 특정 버전 설치
pip install numpy==1.21.0
# 패키지 정보 보기
pip show numpy
```

### Conda: `conda install numpy`

Anaconda/Miniconda 환경용 패키지 관리자.

```bash
# 현재 환경에 NumPy 설치
conda install numpy
# NumPy 업데이트
conda update numpy
# conda-forge에서 설치
conda install -c conda-forge numpy
# NumPy가 포함된 환경 생성
conda create -n myenv numpy
```

### 설치 확인 및 가져오기

NumPy 설치를 확인하고 표준 가져오기를 수행합니다.

```python
# 표준 가져오기
import numpy as np
# 버전 확인
print(np.__version__)
# 빌드 정보 확인
np.show_config()
# 출력 옵션 설정
np.set_printoptions(precision=2, suppress=True)
```

## 고급 기능

### 구조화된 배열

복잡한 데이터 구조를 위한 이름 있는 필드를 가진 배열.

```python
# 구조화된 데이터 타입 정의
dt = np.dtype([('name', 'U10'), ('age', 'i4'), ('weight', 'f4')])
# 구조화된 배열 생성
people = np.array([('Alice', 25, 55.0), ('Bob', 30, 70.5)], dtype=dt)
# 필드 접근
people['name']
people['age']
```

### 마스크 배열: `np.ma`

누락되거나 유효하지 않은 데이터를 처리합니다.

```python
# 마스크 배열 생성
masked_arr = np.ma.array([1, 2, 3, 4, 5], mask=[0, 0, 1, 0, 0])
# 연산은 마스크된 값을 무시합니다
np.ma.mean(masked_arr)
# 마스크된 값 채우기
filled = masked_arr.filled(0)
```

### 다항식: `np.poly1d`

다항식 표현 및 연산을 다룹니다.

```python
# 다항식 생성 (내림차순 계수)
p = np.poly1d([1, -2, 1])  # x² - 2x + 1
# 다항식 평가
p(5)  # x=5 에서 평가
# 근 찾기
np.roots([1, -2, 1])
# 다항식 피팅
coeff = np.polyfit(x, y, degree=2)
```

### 고속 푸리에 변환: `np.fft`

주파수 영역 분석 및 신호 처리.

```python
# 1D FFT
fft_result = np.fft.fft(signal)
# 주파수
freqs = np.fft.fftfreq(len(signal))
# 역 FFT
reconstructed = np.fft.ifft(fft_result)
# 이미지용 2D FFT
fft2d = np.fft.fft2(image)
```

## 관련 링크

- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/pandas">Pandas 치트 시트</router-link>
- <router-link to="/matplotlib">Matplotlib 치트 시트</router-link>
- <router-link to="/sklearn">scikit-learn 치트 시트</router-link>
- <router-link to="/datascience">데이터 과학 치트 시트</router-link>

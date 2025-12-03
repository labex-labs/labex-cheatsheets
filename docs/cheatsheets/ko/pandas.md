---
title: 'Pandas 치트 시트 | LabEx'
description: '이 포괄적인 치트 시트로 Pandas 데이터 조작을 배우세요. DataFrame 작업, 데이터 정리, 필터링, 그룹화, 병합 및 Python 데이터 분석을 위한 빠른 참조.'
pdfUrl: '/cheatsheets/pdf/pandas-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Pandas 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/pandas">Hands-On 실습으로 Pandas 배우기</a>
</base-disclaimer-title>
<base-disclaimer-content>
Hands-On 실습과 실제 시나리오를 통해 Pandas 데이터 조작을 학습하세요. LabEx 는 필수 연산, 데이터 정리, 분석 및 시각화를 다루는 포괄적인 Pandas 과정을 제공합니다. DataFrame 작업, 누락된 데이터 처리, 집계 수행 및 Python 의 강력한 데이터 분석 라이브러리를 사용하여 데이터 세트를 효율적으로 분석하는 방법을 배우십시오.
</base-disclaimer-content>
</base-disclaimer>

## 데이터 로딩 및 저장

### CSV 읽기: `pd.read_csv()`

CSV 파일에서 DataFrame 으로 데이터를 로드합니다.

```python
import pandas as pd
# CSV 파일 읽기
df = pd.read_csv('data.csv')
# 첫 번째 열을 인덱스로 설정
df = pd.read_csv('data.csv', index_col=0)
# 다른 구분자 지정
df = pd.read_csv('data.csv', sep=';')
# 날짜 파싱
df = pd.read_csv('data.csv', parse_dates=['Date'])
```

<BaseQuiz id="pandas-read-csv-1" correct="B">
  <template #question>
    <code>pd.read_csv('data.csv')</code> 는 무엇을 반환합니까?
  </template>
  
  <BaseQuizOption value="A">딕셔너리 리스트</BaseQuizOption>
  <BaseQuizOption value="B" correct>pandas DataFrame</BaseQuizOption>
  <BaseQuizOption value="C">NumPy 배열</BaseQuizOption>
  <BaseQuizOption value="D">문자열</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>pd.read_csv()</code> 는 CSV 파일을 읽어 열과 행을 가진 2 차원 레이블 데이터 구조인 pandas DataFrame 을 반환합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### Excel 읽기: `pd.read_excel()`

Excel 파일에서 데이터를 로드합니다.

```python
# 첫 번째 시트 읽기
df = pd.read_excel('data.xlsx')
# 특정 시트 읽기
df = pd.read_excel('data.xlsx', sheet_name='Sheet2')
# 2 번째 행을 헤더로 설정 (0 부터 인덱싱)
df = pd.read_excel('data.xlsx', header=1)
```

### SQL 읽기: `pd.read_sql()`

SQL 쿼리 또는 테이블을 DataFrame 으로 읽습니다.

```python
from sqlalchemy import create_engine
engine = create_engine('sqlite:///my_database.db')
df = pd.read_sql('SELECT * FROM users', engine)
df = pd.read_sql_table('products', engine)
```

### CSV 저장: `df.to_csv()`

DataFrame 을 CSV 파일로 씁니다.

```python
# 인덱스 열 제외
df.to_csv('output.csv', index=False)
# 헤더 행 제외
df.to_csv('output.csv', header=False)
```

### Excel 저장: `df.to_excel()`

DataFrame 을 Excel 파일로 씁니다.

```python
# Excel 로 저장
df.to_excel('output.xlsx', sheet_name='Results')
writer = pd.ExcelWriter('output.xlsx')
df1.to_excel(writer, sheet_name='Sheet1')
df2.to_excel(writer, sheet_name='Sheet2')
writer.save()
```

### SQL 저장: `df.to_sql()`

DataFrame 을 SQL 데이터베이스 테이블로 씁니다.

```python
# 테이블 생성/대체
df.to_sql('new_table', engine, if_exists='replace', index=False)
# 기존 테이블에 추가
df.to_sql('existing_table', engine, if_exists='append')
```

## DataFrame 정보 및 구조

### 기본 정보: `df.info()`

DataFrame 의 간결한 요약 (데이터 유형 및 null 이 아닌 값 포함) 을 출력합니다.

```python
# DataFrame 요약 표시
df.info()
# 각 열의 데이터 유형 표시
df.dtypes
# 행 및 열의 수 가져오기 (튜플)
df.shape
# 열 이름 가져오기
df.columns
# 행 인덱스 가져오기
df.index
```

### 기술 통계: `df.describe()`

수치형 열의 기술 통계를 생성합니다.

```python
# 수치형 열에 대한 요약 통계
df.describe()
# 특정 열에 대한 요약
df['column'].describe()
# 모든 열 포함 (객체 유형 포함)
df.describe(include='all')
```

### 데이터 보기: `df.head()` / `df.tail()`

DataFrame 의 처음 또는 마지막 'n'개 행을 표시합니다.

```python
# 처음 5 개 행
df.head()
# 마지막 10 개 행
df.tail(10)
# 무작위 5 개 행
df.sample(5)
```

## 데이터 정리 및 변환

### 누락된 값: `isnull()` / `fillna()` / `dropna()`

누락된 (NaN) 값을 식별, 채우기 또는 삭제합니다.

```python
# 열별 누락 값 개수
df.isnull().sum()
# 모든 NaN 을 0 으로 채우기
df.fillna(0)
# 열 평균으로 채우기
df['col'].fillna(df['col'].mean())
# NaN 이 있는 행 삭제
df.dropna()
# NaN 이 있는 열 삭제
df.dropna(axis=1)
```

<BaseQuiz id="pandas-missing-1" correct="B">
  <template #question>
    <code>df.dropna(axis=1)</code> 는 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A">누락된 값이 있는 행을 삭제합니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>누락된 값이 있는 열을 삭제합니다</BaseQuizOption>
  <BaseQuizOption value="C">누락된 값을 0 으로 채웁니다</BaseQuizOption>
  <BaseQuizOption value="D">누락된 값을 계산합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>axis=1</code> 매개변수는 "열"을 의미하므로 <code>df.dropna(axis=1)</code> 은 누락된 값이 포함된 열을 제거합니다. 행을 삭제하려면 <code>axis=0</code>(기본값) 을 사용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 중복: `duplicated()` / `drop_duplicates()`

중복된 행을 식별하고 제거합니다.

```python
# 중복을 나타내는 부울 시리즈
df.duplicated()
# 모든 중복 행 제거
df.drop_duplicates()
# 특정 열을 기반으로 제거
df.drop_duplicates(subset=['col1', 'col2'])
```

<BaseQuiz id="pandas-duplicates-1" correct="A">
  <template #question>
    <code>df.drop_duplicates()</code> 는 기본적으로 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A" correct>중복된 행을 제거하고 첫 번째 발생 항목을 유지합니다</BaseQuizOption>
  <BaseQuizOption value="B">모든 행을 제거합니다</BaseQuizOption>
  <BaseQuizOption value="C">중복된 행만 유지합니다</BaseQuizOption>
  <BaseQuizOption value="D">중복의 첫 번째 발생 항목을 제거합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    기본적으로 <code>drop_duplicates()</code> 는 각 중복 행의 첫 번째 발생 항목을 유지하고 후속 중복 항목을 제거합니다. 대신 마지막 발생 항목을 유지하려면 <code>keep='last'</code> 를 사용할 수 있습니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 데이터 유형: `astype()`

열의 데이터 유형을 변경합니다.

```python
# 정수로 변경
df['col'].astype(int)
# 문자열로 변경
df['col'].astype(str)
# datetime 으로 변환
df['col'] = pd.to_datetime(df['col'])
```

### 함수 적용: `apply()` / `map()` / `replace()`

DataFrame/Series에 함수를 적용하거나 값을 대체합니다.

```python
# 열에 람다 함수 적용
df['col'].apply(lambda x: x*2)
# 딕셔너리를 사용하여 값 매핑
df['col'].map({'old': 'new'})
# 값 대체
df.replace('old_val', 'new_val')
# 여러 값 대체
df.replace(['A', 'B'], ['C', 'D'])
```

<BaseQuiz id="pandas-apply-1" correct="A">
  <template #question>
    <code>df['col'].apply(lambda x: x*2)</code>는 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A" correct>각 요소에 함수를 적용하여 각 값을 2 배로 만듭니다</BaseQuizOption>
  <BaseQuizOption value="B">전체 열에 한 번 2 를 곱합니다</BaseQuizOption>
  <BaseQuizOption value="C">열을 2 로 대체합니다</BaseQuizOption>
  <BaseQuizOption value="D">열의 요소를 계산합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>apply()</code> 메서드는 Series 의 각 요소에 함수를 적용합니다. 람다 함수 <code>lambda x: x*2</code>는 각 값을 2 배로 곱하여 변환된 값을 가진 새 Series 를 반환합니다.
  </BaseQuizAnswer>
</BaseQuiz>

## DataFrame 검사

### 고유 값: `unique()` / `value_counts()`

고유 값과 그 빈도를 탐색합니다.

```python
# 열의 고유 값 가져오기
df['col'].unique()
# 고유 값 개수 가져오기
df['col'].nunique()
# 각 고유 값의 발생 횟수 계산
df['col'].value_counts()
# 고유 값의 비율
df['col'].value_counts(normalize=True)
```

### 상관 관계: `corr()` / `cov()`

수치형 열 간의 상관 관계 및 공분산을 계산합니다.

```python
# 열의 쌍별 상관 관계
df.corr()
# 열의 쌍별 공분산
df.cov()
# 두 특정 열 간의 상관 관계
df['col1'].corr(df['col2'])
```

### 집계: `groupby()` / `agg()`

범주별로 데이터를 그룹화하고 집계 함수를 적용합니다.

```python
# 각 범주에 대한 평균
df.groupby('category_col').mean()
# 여러 열로 그룹화
df.groupby(['col1', 'col2']).sum()
# 여러 집계
df.groupby('category_col').agg({'num_col': ['min', 'max', 'mean']})
```

### 교차표: `pd.crosstab()`

두 개 이상의 요인의 빈도표를 계산합니다.

```python
df.pivot_table(values='sales', index='region', columns='product', aggfunc='sum')
# 단순 빈도표
pd.crosstab(df['col1'], df['col2'])
# 행/열 합계 포함
pd.crosstab(df['col1'], df['col2'], margins=True)
# 집계 값 포함
pd.crosstab(df['col1'], df['col2'], values=df['value_col'], aggfunc='mean')
```

## 메모리 관리

### 메모리 사용량: `df.memory_usage()`

각 열 또는 전체 DataFrame 의 메모리 사용량을 표시합니다.

```python
# 각 열의 메모리 사용량
df.memory_usage()
# 바이트 단위의 총 메모리 사용량
df.memory_usage(deep=True).sum()
# info() 출력에서 자세한 메모리 사용량
df.info(memory_usage='deep')
```

### Dtype 최적화: `astype()`

더 작고 적절한 데이터 유형으로 열을 변환하여 메모리를 줄입니다.

```python
# 정수 다운캐스팅
df['int_col'] = df['int_col'].astype('int16')
# 부동 소수점 다운캐스팅
df['float_col'] = df['float_col'].astype('float32')
# 범주형 유형 사용
df['category_col'] = df['category_col'].astype('category')
```

### 대용량 파일 청킹: `read_csv(chunksize=...)`

한 번에 모든 데이터를 메모리에 로드하는 것을 방지하기 위해 청크 단위로 대용량 파일을 처리합니다.

```python
chunk_iterator = pd.read_csv('large_data.csv', chunksize=10000)
for chunk in chunk_iterator:
    # 각 청크 처리
    print(chunk.shape)
# (필요한 경우) 처리된 청크 연결
# processed_chunks = []
# for chunk in chunk_iterator:
#    processed_chunks.append(process_chunk(chunk))
# final_df = pd.concat(processed_chunks)
```

## 데이터 가져오기/내보내기

### JSON 읽기: `pd.read_json()`

JSON 파일 또는 URL 에서 데이터를 로드합니다.

```python
# 로컬 JSON 에서 읽기
df = pd.read_json('data.json')
# URL 에서 읽기
df = pd.read_json('http://example.com/api/data')
# JSON 문자열에서 읽기
df = pd.read_json(json_string_data)
```

### HTML 읽기: `pd.read_html()`

URL, 문자열 또는 파일에서 HTML 테이블을 구문 분석합니다.

```python
tables = pd.read_html('http://www.w3.org/TR/html401/sgml/entities.html')
# 일반적으로 DataFrame 리스트를 반환
df = tables[0]
```

### JSON 으로 저장: `df.to_json()`

DataFrame 을 JSON 형식으로 씁니다.

```python
# JSON 파일로 저장
df.to_json('output.json', orient='records', indent=4)
# JSON 문자열로 저장
json_str = df.to_json(orient='split')
```

### HTML 로 저장: `df.to_html()`

DataFrame 을 HTML 테이블로 렌더링합니다.

```python
# HTML 문자열로 저장
html_table_str = df.to_html()
# HTML 파일로 저장
df.to_html('output.html', index=False)
```

### 클립보드 읽기: `pd.read_clipboard()`

클립보드의 텍스트를 DataFrame 으로 읽습니다.

```python
# 웹/스프레드시트에서 테이블 데이터를 복사하고 실행
df = pd.read_clipboard()
```

## 데이터 직렬화

### Pickle: `df.to_pickle()` / `pd.read_pickle()`

Pandas 객체를 디스크에 직렬화/역직렬화합니다.

```python
# DataFrame 을 pickle 파일로 저장
df.to_pickle('my_dataframe.pkl')
# DataFrame 로드
loaded_df = pd.read_pickle('my_dataframe.pkl')
```

### HDF5: `df.to_hdf()` / `pd.read_hdf()`

대용량 데이터 세트에 유용한 HDF5 형식을 사용하여 DataFrame 을 저장/로드합니다.

```python
# HDF5 로 저장
df.to_hdf('my_data.h5', key='df', mode='w')
# HDF5 에서 로드
loaded_df = pd.read_hdf('my_data.h5', key='df')
```

## 데이터 필터링 및 선택

### 레이블 기반: `df.loc[]` / `df.at[]`

인덱스/열의 명시적 레이블로 데이터를 선택합니다.

```python
# 인덱스 0 인 행 선택
df.loc[0]
# 'col1'에 대한 모든 행 선택
df.loc[:, 'col1']
# 행 슬라이싱 및 여러 열 선택
df.loc[0:5, ['col1', 'col2']]
# 행에 대한 부울 인덱싱
df.loc[df['col'] > 5]
# 레이블 기반 빠른 스칼라 접근
df.at[0, 'col1']
```

### 위치 기반: `df.iloc[]` / `df.iat[]`

인덱스/열의 정수 위치로 데이터를 선택합니다.

```python
# 위치로 첫 번째 행 선택
df.iloc[0]
# 위치로 첫 번째 열 선택
df.iloc[:, 0]
# 위치로 행 슬라이싱 및 여러 열 선택
df.iloc[0:5, [0, 1]]
# 위치 기반 빠른 스칼라 접근
df.iat[0, 0]
```

### 부울 인덱싱: `df[condition]`

하나 이상의 조건을 기반으로 행을 필터링합니다.

```python
# 'col1'이 10 보다 큰 행
df[df['col1'] > 10]
# 다중 조건
df[(df['col1'] > 10) & (df['col2'] == 'A')]
# 'col1'이 리스트에 없는 행
df[~df['col1'].isin([1, 2, 3])]
```

### 데이터 쿼리: `df.query()`

쿼리 문자열 표현식을 사용하여 행을 필터링합니다.

```python
# 부울 인덱싱과 동일
df.query('col1 > 10')
# 복잡한 쿼리
df.query('col1 > 10 and col2 == "A"')
# '@'를 사용하여 로컬 변수 사용
df.query('col1 in @my_list')
```

## 성능 모니터링

### 연산 타이밍: `%%timeit` / `time`

Python/Pandas 코드의 실행 시간을 측정합니다.

```python
# 한 줄/셀 타이밍을 위한 Jupyter/IPython 매직 명령어
%%timeit
df['col'].apply(lambda x: x*2) # 예시 연산

import time
start_time = time.time()
# 여기에 Pandas 코드 입력
end_time = time.time()
print(f"실행 시간: {end_time - start_time} 초")

```

### 최적화된 연산: `eval()` / `query()`

특히 대용량 DataFrame 에서 요소별 연산 및 필터링에 대해 더 빠른 성능을 활용합니다.

```python
# `df['col1'] + df['col2']`보다 빠름
df['new_col'] = df.eval('col1 + col2')
# 더 빠른 필터링
df_filtered = df.query('col1 > @threshold and col2 == "value"')
```

### 코드 프로파일링: `cProfile` / `line_profiler`

Python 함수에서 시간이 소요되는 부분을 분석합니다.

```python
import cProfile
def my_pandas_function(df):
    # Pandas 연산
    return df.groupby('col').mean()
cProfile.run('my_pandas_function(df)') # cProfile 로 함수 실행

# line_profiler 의 경우 (pip install line_profiler 로 설치):
# @profile
# def my_function(df):
#    ...
# %load_ext line_profiler
# %lprun -f my_function my_function(df)
```

## Pandas 설치 및 설정

### Pip: `pip install pandas`

표준 Python 패키지 설치 관리자입니다.

```python
# Pandas 설치
pip install pandas
# Pandas 를 최신 버전으로 업그레이드
pip install pandas --upgrade
# 설치된 Pandas 패키지 정보 표시
pip show pandas
```

### Conda: `conda install pandas`

Anaconda/Miniconda 환경용 패키지 관리자입니다.

```python
# 현재 conda 환경에 Pandas 설치
conda install pandas
# Pandas 업데이트
conda update pandas
# 설치된 Pandas 패키지 나열
conda list pandas
# Pandas 를 포함하여 새 환경 생성
conda create -n myenv pandas
```

### 버전 확인 / 가져오기

Pandas 설치를 확인하고 스크립트에서 가져옵니다.

```python
# 표준 가져오기 별칭
import pandas as pd
# 설치된 Pandas 버전 확인
print(pd.__version__)
# 모든 열 표시
pd.set_option('display.max_columns', None)
# 더 많은 행 표시
pd.set_option('display.max_rows', 100)
```

## 구성 및 설정

### 표시 옵션: `pd.set_option()`

콘솔/Jupyter 에서 DataFrame 이 표시되는 방식을 제어합니다.

```python
# 표시할 최대 행 수
pd.set_option('display.max_rows', 50)
# 모든 열 표시
pd.set_option('display.max_columns', None)
# 표시 너비
pd.set_option('display.width', 1000)
# 부동 소수점 값 형식 지정
pd.set_option('display.float_format', '{:.2f}'.format)
```

### 옵션 재설정: `pd.reset_option()`

특정 옵션을 재설정하거나 모든 옵션을 기본값으로 재설정합니다.

```python
# 특정 옵션 재설정
pd.reset_option('display.max_rows')
# 모든 옵션을 기본값으로 재설정
pd.reset_option('all')
```

### 옵션 가져오기: `pd.get_option()`

지정된 옵션의 현재 값을 검색합니다.

```python
# 현재 max_rows 설정 가져오기
print(pd.get_option('display.max_rows'))
```

### 컨텍스트 관리자: `pd.option_context()`

`with` 문 내에서 옵션을 일시적으로 설정합니다.

```python
with pd.option_context('display.max_rows', 10, 'display.max_columns', 5):
    print(df) # 임시 옵션으로 DataFrame 표시
print(df) # 블록 외부에서는 옵션이 이전 설정으로 되돌아갑니다
```

## 메서드 체이닝

### 연산 체이닝

일련의 변환을 DataFrame 에 적용합니다.

```python
(
    df.dropna(subset=['col1'])
    .assign(new_col = lambda x: x['col2'] * 2)
    .query('new_col > 10')
    .groupby('category_col')
    ['new_col']
    .mean()
    .reset_index()
)
```

### `.pipe()` 사용

DataFrame 을 첫 번째 인수로 받는 함수를 적용하여 체인 내에서 사용자 지정 단계를 활성화합니다.

```python
def custom_filter(df, threshold):
    return df[df['value'] > threshold]

(
    df.pipe(custom_filter, threshold=50)
    .groupby('group')
    .agg(total_value=('value', 'sum'))
)
```

## 관련 링크

- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/numpy">NumPy 치트 시트</router-link>
- <router-link to="/matplotlib">Matplotlib 치트 시트</router-link>
- <router-link to="/sklearn">scikit-learn 치트 시트</router-link>
- <router-link to="/datascience">데이터 과학 치트 시트</router-link>
- <router-link to="/mysql">MySQL 치트 시트</router-link>
- <router-link to="/postgresql">PostgreSQL 치트 시트</router-link>
- <router-link to="/sqlite">SQLite 치트 시트</router-link>

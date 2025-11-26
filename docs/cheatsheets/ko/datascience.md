---
title: '데이터 과학 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 포괄적인 치트 시트로 데이터 과학을 학습하세요.'
pdfUrl: '/cheatsheets/pdf/data-science-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
데이터 과학 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/datascience">Hands-On Labs 로 데이터 과학 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 기반 랩과 실제 시나리오를 통해 데이터 과학을 학습하세요. LabEx 는 필수 Python 라이브러리, 데이터 조작, 통계 분석, 머신러닝 및 데이터 시각화를 다루는 포괄적인 데이터 과학 과정을 제공합니다. 데이터 수집, 정리, 분석 및 모델 배포 기술을 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 필수 Python 라이브러리

### 핵심 데이터 과학 스택

NumPy, Pandas, Matplotlib, Seaborn, scikit-learn 과 같은 주요 라이브러리는 데이터 과학 워크플로우의 기반을 형성합니다.

```python
# 데이터 과학을 위한 필수 임포트
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.metrics import accuracy_score,
classification_report
```

### NumPy: `import numpy as np`

Python 을 사용한 수치 계산을 위한 기본 패키지입니다.

```python
# 배열 생성
arr = np.array([1, 2, 3, 4, 5])
matrix = np.array([[1, 2], [3, 4]])
# 기본 연산
np.mean(arr)       # 평균
np.std(arr)        # 표준 편차
np.reshape(arr, (5, 1))  # 배열 재구성
# 데이터 생성
np.random.normal(0, 1, 100)  # 난수 정규 분포
```

### Pandas: `import pandas as pd`

데이터 조작 및 분석 라이브러리입니다.

```python
# DataFrame 생성
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
# 데이터 읽기
df = pd.read_csv('data.csv')
# 기본 탐색
df.head()          # 처음 5 개 행
df.info()          # 데이터 유형 및 누락된 값
df.describe()      # 요약 통계
# 데이터 조작
df.groupby('column').mean()
df.fillna(df.mean())  # 누락된 값 처리
```

### Matplotlib & Seaborn: 시각화

통계적 시각화 및 플롯을 생성합니다.

```python
# Matplotlib 기본
plt.plot(x, y)
plt.hist(data, bins=20)
plt.scatter(x, y)
plt.show()
# 통계적 플롯을 위한 Seaborn
sns.boxplot(data=df, x='category', y='value')
sns.heatmap(df.corr(), annot=True)
sns.pairplot(df)
```

## 데이터 과학 워크플로우

### 1. 문제 정의

데이터 과학은 수학, 통계, 프로그래밍 및 비즈니스 인텔리전스를 결합한 다학제적 분야입니다. 목표와 성공 측정 기준을 정의합니다.

```python
# 비즈니스 문제 정의
# - 어떤 질문에 답하고 있는가?
# - 성공을 측정할 지표는 무엇인가?
# - 어떤 데이터가 필요한가?
```

### 2. 데이터 수집 및 가져오기

다양한 소스와 형식에서 데이터를 수집합니다.

```python
# 다중 데이터 소스
df_csv = pd.read_csv('data.csv')
df_json = pd.read_json('data.json')
df_sql = pd.read_sql('SELECT * FROM
table', connection)
# API 및 웹 스크래핑
import requests
response =
requests.get('https://api.example.co
m/data')
```

### 3. 데이터 탐색 (EDA)

데이터 구조, 패턴 및 품질을 이해합니다.

```python
# 탐색적 데이터 분석
df.shape              # 차원
df.dtypes             # 데이터 유형
df.isnull().sum()     # 누락된 값
df['column'].value_counts()  #
빈도수 계산
df.corr()             # 상관 관계 행렬
# EDA 를 위한 시각화
sns.histplot(df['numeric_column'])
sns.boxplot(data=df,
y='numeric_column')
plt.figure(figsize=(10, 8))
sns.heatmap(df.corr(), annot=True)
```

## 데이터 정리 및 전처리

### 누락된 데이터 처리

데이터를 분석하기 전에 정리하고 준비해야 합니다. 여기에는 누락된 데이터 처리, 중복 제거 및 변수 정규화가 포함됩니다. 데이터 정리는 종종 가장 시간이 많이 걸리지만 데이터 과학 프로세스에서 가장 중요한 측면입니다.

```python
# 누락된 값 식별
df.isnull().sum()
df.isnull().sum() / len(df) * 100  # 누락된 비율
# 누락된 값 처리
df.dropna()                    # NaN 이 있는 행 제거
df.fillna(df.mean())          # 평균으로 채우기
df.fillna(method='forward')   # 순방향 채우기
df.fillna(method='backward')  # 역방향 채우기
# 고급 대체
from sklearn.impute import SimpleImputer, KNNImputer
imputer = SimpleImputer(strategy='median')
df_filled = pd.DataFrame(imputer.fit_transform(df))
```

### 데이터 변환

데이터 정규화 (데이터를 [0, 1]과 같은 표준 범위로 스케일링) 는 특징 크기의 차이로 인한 편향을 방지하는 데 도움이 됩니다.

```python
# 스케일링 및 정규화
from sklearn.preprocessing import StandardScaler,
MinMaxScaler
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df[numeric_columns])
# [0,1] 로의 Min-Max 스케일링
minmax = MinMaxScaler()
df_normalized =
minmax.fit_transform(df[numeric_columns])
# 범주형 변수 인코딩
pd.get_dummies(df, columns=['category_column'])
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
df['encoded'] = le.fit_transform(df['category'])
```

### 이상치 탐지 및 처리

분석을 왜곡할 수 있는 극단적인 값을 식별하고 처리합니다.

```python
# 통계적 이상치 탐지
Q1 = df['column'].quantile(0.25)
Q3 = df['column'].quantile(0.75)
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR
# 이상치 제거
df_clean = df[(df['column'] >= lower_bound) &
              (df['column'] <= upper_bound)]
# Z-점수 방법
from scipy import stats
z_scores = np.abs(stats.zscore(df['column']))
df_no_outliers = df[z_scores < 3]
```

### 특성 공학 (Feature Engineering)

모델 성능을 향상시키기 위해 새로운 변수를 생성합니다.

```python
# 새 특성 생성
df['feature_ratio'] = df['feature1'] / df['feature2']
df['feature_sum'] = df['feature1'] + df['feature2']
# 날짜/시간 특성
df['date'] = pd.to_datetime(df['date'])
df['year'] = df['date'].dt.year
df['month'] = df['date'].dt.month
df['day_of_week'] = df['date'].dt.day_name()
# 연속 변수 구간화 (Binning)
df['age_group'] = pd.cut(df['age'], bins=[0, 18, 35, 50, 100],
                        labels=['Child', 'Young Adult', 'Adult',
'Senior'])
```

## 통계 분석

### 기술 통계량

이러한 중심 경향성 척도는 데이터를 요약하고 데이터 분포에 대한 통찰력을 제공합니다. 이는 모든 데이터 세트를 이해하는 기초입니다. 평균은 데이터 세트의 모든 값의 평균입니다. 이상치에 매우 민감합니다.

```python
# 중심 경향성
mean = df['column'].mean()
median = df['column'].median()
mode = df['column'].mode()[0]
# 변동성 측정
std_dev = df['column'].std()
variance = df['column'].var()
range_val = df['column'].max() - df['column'].min()
# 분포 모양
skewness = df['column'].skew()
kurtosis = df['column'].kurtosis()
# 분위수
percentiles = df['column'].quantile([0.25, 0.5, 0.75, 0.95])
```

### 가설 검정

통계적 가설을 테스트하고 가정을 검증합니다.

```python
# 평균 비교를 위한 T-검정
from scipy.stats import ttest_ind, ttest_1samp
# 단일 표본 t-검정
t_stat, p_value = ttest_1samp(data, population_mean)
# 이중 표본 t-검정
group1 = df[df['group'] == 'A']['value']
group2 = df[df['group'] == 'B']['value']
t_stat, p_value = ttest_ind(group1, group2)
# 독립성 검정을 위한 카이제곱 검정
from scipy.stats import chi2_contingency
chi2, p_value, dof, expected =
chi2_contingency(contingency_table)
```

### 상관 관계 분석

변수 간의 관계를 이해합니다.

```python
# 상관 관계 행렬
correlation_matrix = df.corr()
plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix, annot=True,
cmap='coolwarm')
# 특정 상관 관계
pearson_corr = df['var1'].corr(df['var2'])
spearman_corr = df['var1'].corr(df['var2'],
method='spearman')
# 상관 관계의 통계적 유의성
from scipy.stats import pearsonr
correlation, p_value = pearsonr(df['var1'], df['var2'])
```

### ANOVA 및 회귀 분석

분산 및 변수 간의 관계를 분석합니다.

```python
# 일원 분산 분석 (One-way ANOVA)
from scipy.stats import f_oneway
group_data = [df[df['group'] == g]['value'] for g in
df['group'].unique()]
f_stat, p_value = f_oneway(*group_data)
# 선형 회귀 분석
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score
X = df[['feature1', 'feature2']]
y = df['target']
model = LinearRegression().fit(X, y)
y_pred = model.predict(X)
r2 = r2_score(y, y_pred)
```

## 머신러닝 모델

### 지도 학습 - 분류

의사 결정 트리: 결정과 그 가능한 결과의 트리와 같은 모델입니다. 각 노드는 속성에 대한 테스트를 나타내며 각 분기는 결과를 나타냅니다. 분류 작업에 일반적으로 사용됩니다.

```python
# 훈련 - 테스트 분할
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y,
test_size=0.2, random_state=42)
# 로지스틱 회귀
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression()
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
# 의사 결정 트리
from sklearn.tree import DecisionTreeClassifier
dt = DecisionTreeClassifier(max_depth=5)
dt.fit(X_train, y_train)
# 랜덤 포레스트
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=100)
rf.fit(X_train, y_train)
```

### 지도 학습 - 회귀

연속적인 타겟 변수를 예측합니다.

```python
# 선형 회귀
from sklearn.linear_model import LinearRegression
lr = LinearRegression()
lr.fit(X_train, y_train)
y_pred = lr.predict(X_test)
# 다항 회귀
from sklearn.preprocessing import PolynomialFeatures
poly = PolynomialFeatures(degree=2)
X_poly = poly.fit_transform(X)
# 릿지 및 라쏘 회귀
from sklearn.linear_model import Ridge, Lasso
ridge = Ridge(alpha=1.0)
lasso = Lasso(alpha=0.1)
ridge.fit(X_train, y_train)
lasso.fit(X_train, y_train)
```

### 비지도 학습

레이블이 지정된 결과 없이 데이터에서 패턴을 발견합니다.

```python
# K-평균 군집화
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
clusters = kmeans.fit_predict(X)
df['cluster'] = clusters
# 주성분 분석 (PCA)
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)
# 계층적 군집화
from scipy.cluster.hierarchy import dendrogram, linkage
linkage_matrix = linkage(X_scaled, method='ward')
dendrogram(linkage_matrix)
```

### 모델 평가

적절한 메트릭을 사용하여 모델 성능을 평가합니다.

```python
# 분류 메트릭
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score, confusion_matrix
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# 혼동 행렬
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d')
# 회귀 메트릭
from sklearn.metrics import mean_squared_error,
mean_absolute_error
mse = mean_squared_error(y_test, y_pred)
mae = mean_absolute_error(y_test, y_pred)
rmse = np.sqrt(mse)
```

## 데이터 시각화

### 탐색적 시각화

데이터 분포 및 관계를 이해합니다.

```python
# 분포 플롯
plt.figure(figsize=(12, 4))
plt.subplot(1, 3, 1)
plt.hist(df['numeric_col'], bins=20, edgecolor='black')
plt.subplot(1, 3, 2)
sns.boxplot(y=df['numeric_col'])
plt.subplot(1, 3, 3)
sns.violinplot(y=df['numeric_col'])
# 관계 플롯
plt.figure(figsize=(10, 6))
sns.scatterplot(data=df, x='feature1', y='feature2',
hue='category')
sns.regplot(data=df, x='feature1', y='target')
# 범주형 데이터
sns.countplot(data=df, x='category')
sns.barplot(data=df, x='category', y='value')
```

### 고급 시각화

포괄적인 대시보드 및 보고서를 생성합니다.

```python
# 여러 뷰를 위한 서브플롯
fig, axes = plt.subplots(2, 2, figsize=(15, 10))
axes[0,0].hist(df['col1'])
axes[0,1].scatter(df['col1'], df['col2'])
axes[1,0].boxplot(df['col1'])
sns.heatmap(df.corr(), ax=axes[1,1])
# Plotly 를 사용한 대화형 플롯
import plotly.express as px
fig = px.scatter(df, x='feature1', y='feature2',
                color='category', size='value',
                hover_data=['additional_info'])
fig.show()
```

### 통계 플롯

통계적 관계 및 모델 결과를 시각화합니다.

```python
# 상관 관계를 위한 쌍 플롯
sns.pairplot(df, hue='target_category')
# 회귀 분석을 위한 잔차 플롯
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.scatter(y_pred, y_test - y_pred)
plt.xlabel('예측값')
plt.ylabel('잔차')
plt.subplot(1, 2, 2)
plt.scatter(y_test, y_pred)
plt.plot([y_test.min(), y_test.max()], [y_test.min(),
y_test.max()], 'r--')
# 분류를 위한 ROC 곡선
from sklearn.metrics import roc_curve, auc
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, label=f'ROC 곡선 (AUC = {roc_auc:.2f})')
```

### 사용자 정의 및 스타일링

전문적인 시각화 서식 지정.

```python
# 스타일 및 색상 설정
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
# 사용자 정의 그림 설정
plt.figure(figsize=(12, 8))
plt.title('전문 차트 제목', fontsize=16,
fontweight='bold')
plt.xlabel('X 축 레이블', fontsize=14)
plt.ylabel('Y 축 레이블', fontsize=14)
plt.legend(loc='best')
plt.grid(True, alpha=0.3)
plt.tight_layout()
# 고품질 플롯 저장
plt.savefig('analysis_plot.png', dpi=300,
bbox_inches='tight')
```

## 모델 배포 및 MLOps

### 모델 지속성

훈련된 모델을 저장하고 로드하여 프로덕션 환경에서 사용합니다.

```python
# pickle 을 사용한 모델 저장
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(trained_model, f)
# 저장된 모델 로드
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
# sklearn 모델에 joblib 사용
import joblib
joblib.dump(trained_model, 'model.joblib')
loaded_model = joblib.load('model.joblib')
# 타임스탬프를 사용한 모델 버전 관리
import datetime
timestamp =
datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
model_name = f'model_{timestamp}.pkl'
```

### 교차 검증 및 하이퍼파라미터 튜닝

모델 성능을 최적화하고 과적합을 방지합니다.

```python
# 교차 검증
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"CV 정확도: {cv_scores.mean():.3f} (+/-
{cv_scores.std() * 2:.3f})")
# 하이퍼파라미터 튜닝을 위한 그리드 검색
from sklearn.model_selection import GridSearchCV
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [3, 5, 7],
    'min_samples_split': [2, 5, 10]
}
grid_search = GridSearchCV(RandomForestClassifier(),
param_grid, cv=5)
grid_search.fit(X_train, y_train)
best_model = grid_search.best_estimator_
```

### 성능 모니터링

필수 개념에 대한 빠른 액세스를 갖는 것은 워크플로우에 큰 차이를 만듭니다. 초보자가 발판을 찾든 숙련된 실무자가 신뢰할 수 있는 참조를 찾든 치트 시트는 귀중한 동반자 역할을 합니다.

```python
# 모델 성능 추적
import time
start_time = time.time()
predictions = model.predict(X_test)
inference_time = time.time() - start_time
print(f"추론 시간: {inference_time:.4f} 초")
# 메모리 사용량 모니터링
import psutil
process = psutil.Process()
memory_usage = process.memory_info().rss / 1024 /
1024  # MB
print(f"메모리 사용량: {memory_usage:.2f} MB")
# 특성 중요도 분석
feature_importance = model.feature_importances_
importance_df = pd.DataFrame({
    'feature': X.columns,
    'importance': feature_importance
}).sort_values('importance', ascending=False)
```

### 모델 문서화

모델 가정, 성능 및 사용법을 문서화합니다.

```python
# 모델 보고서 생성
model_report = {
    'model_type': type(model).__name__,
    'training_data_shape': X_train.shape,
    'features_used': list(X.columns),
    'performance_metrics': {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred,
average='weighted'),
        'recall': recall_score(y_test, y_pred,
average='weighted')
    },
    'training_date': datetime.datetime.now().isoformat(),
    'model_version': '1.0'
}
# 모델 메타데이터 저장
import json
with open('model_metadata.json', 'w') as f:
    json.dump(model_report, f, indent=2)
```

## 모범 사례 및 팁

### 코드 구성

재현성과 협업을 위해 프로젝트를 구성합니다.

```python
# 프로젝트 구조
project/
├── data/
│   ├── raw/
│   └── processed/
├── notebooks/
├── src/
│   ├── data_processing.py
│   ├── modeling.py
│   └── visualization.py
├── models/
├── reports/
└── requirements.txt
# git 을 사용한 버전 관리
git init
git add .
git commit -m "Initial data
science project setup"
```

### 환경 관리

시스템 전반에 걸쳐 재현 가능한 환경을 보장합니다.

```bash
# 가상 환경 생성
python -m venv ds_env
source ds_env/bin/activate  #
Linux/Mac
# ds_env\Scripts\activate   #
Windows
# 요구 사항 파일
pip freeze > requirements.txt
# Conda 환경
conda create -n ds_project
python=3.9
conda activate ds_project
conda install pandas numpy
scikit-learn matplotlib seaborn
jupyter
```

### 데이터 품질 검사

파이프라인 전체에서 데이터 무결성을 확인합니다.

```python
# 데이터 검증 함수
def validate_data(df):
    checks = {
        'shape': df.shape,
        'missing_values':
df.isnull().sum().sum(),
        'duplicates':
df.duplicated().sum(),
        'data_types':
df.dtypes.to_dict()
    }
    return checks
# 자동 데이터 품질 보고서
def data_quality_report(df):
    print(f"데이터셋 모양:
{df.shape}")
    print(f"누락된 값:
{df.isnull().sum().sum()}")
    print(f"중복 행:
{df.duplicated().sum()}")
    print("\n열 데이터 유형:")
    print(df.dtypes)
```

## 관련 링크

- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/pandas">Pandas 치트 시트</router-link>
- <router-link to="/numpy">NumPy 치트 시트</router-link>
- <router-link to="/matplotlib">Matplotlib 치트 시트</router-link>
- <router-link to="/sklearn">Scikit-learn 치트 시트</router-link>
- <router-link to="/database">데이터베이스 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>

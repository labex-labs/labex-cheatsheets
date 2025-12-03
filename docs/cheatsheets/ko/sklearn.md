---
title: 'Scikit-learn 치트 시트 | LabEx'
description: '이 포괄적인 치트 시트로 scikit-learn 머신러닝을 학습하세요. ML 알고리즘, 모델 훈련, 전처리, 평가 및 Python 머신러닝 워크플로우에 대한 빠른 참조 자료입니다.'
pdfUrl: '/cheatsheets/pdf/sklearn-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
scikit-learn 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/sklearn">Hands-On Labs 로 scikit-learn 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 기반 랩과 실제 시나리오를 통해 scikit-learn 머신러닝을 학습하세요. LabEx 는 필수적인 데이터 전처리, 모델 선택, 훈련, 평가 및 특성 공학을 다루는 포괄적인 scikit-learn 과정을 제공합니다. Python 을 사용하여 머신러닝 알고리즘을 마스터하고 예측 모델을 구축하세요.
</base-disclaimer-content>
</base-disclaimer>

## 설치 및 가져오기 (Installation & Imports)

### 설치: `pip install scikit-learn`

scikit-learn 및 일반적인 종속성 설치.

```bash
# scikit-learn 설치
pip install scikit-learn
# 추가 패키지와 함께 설치
pip install scikit-learn pandas numpy matplotlib
# 최신 버전으로 업그레이드
pip install scikit-learn --upgrade
```

### 필수 가져오기 (Essential Imports)

scikit-learn 워크플로우를 위한 표준 가져오기.

```python
# 핵심 가져오기
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,
classification_report
# 일반적인 알고리즘
from sklearn.linear_model import LinearRegression,
LogisticRegression
from sklearn.ensemble import RandomForestClassifier,
GradientBoostingRegressor
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
```

### 버전 확인 (Check Version)

scikit-learn 설치 확인.

```python
import sklearn
print(sklearn.__version__)
# 빌드 구성 표시
sklearn.show_versions()
```

### 데이터셋 로드 (Dataset Loading)

연습을 위해 내장 데이터셋 로드.

```python
from sklearn.datasets import load_iris, load_boston,
make_classification
# 샘플 데이터셋 로드
iris = load_iris()
X, y = iris.data, iris.target
# 합성 데이터 생성
X_synth, y_synth = make_classification(n_samples=1000,
n_features=20, n_informative=10, random_state=42)
```

## 데이터 전처리 (Data Preprocessing)

### 훈련 - 테스트 분할: `train_test_split()`

데이터를 훈련 및 테스트 세트로 분할.

```python
# 기본 분할 (훈련 80%, 테스트 20%)
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
random_state=42)
# 분류를 위한 계층적 분할 (Stratified split)
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
stratify=y, random_state=42)
# 다중 분할
X_train, X_temp, y_train, y_temp =
train_test_split(X, y, test_size=0.4,
random_state=42)
X_val, X_test, y_val, y_test =
train_test_split(X_temp, y_temp,
test_size=0.5, random_state=42)
```

<BaseQuiz id="sklearn-split-1" correct="B">
  <template #question>
    데이터를 훈련 및 테스트 세트로 분할하는 것이 중요한 이유는 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">데이터셋 크기를 줄이기 위해</BaseQuizOption>
  <BaseQuizOption value="B" correct>보지 못한 데이터에 대한 모델 성능을 평가하고 과적합을 방지하기 위해</BaseQuizOption>
  <BaseQuizOption value="C">모델 훈련 속도를 높이기 위해</BaseQuizOption>
  <BaseQuizOption value="D">데이터셋 균형을 맞추기 위해</BaseQuizOption>
  
  <BaseQuizAnswer>
    데이터 분할을 통해 한 부분으로 모델을 훈련하고 다른 부분으로 테스트할 수 있습니다. 이는 모델이 새로운, 보지 못한 데이터에 얼마나 잘 일반화되는지 평가하고 훈련 데이터에 과적합되는 것을 방지하는 데 도움이 됩니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 특성 스케일링: `StandardScaler()` / `MinMaxScaler()`

특성을 유사한 규모로 정규화.

```python
# 표준화 (평균=0, 표준편차=1)
from sklearn.preprocessing import
StandardScaler, MinMaxScaler
scaler = StandardScaler()
X_scaled =
scaler.fit_transform(X_train)
X_test_scaled =
scaler.transform(X_test)
# Min-Max 스케일링 (0-1 범위)
minmax_scaler = MinMaxScaler()
X_minmax =
minmax_scaler.fit_transform(X_train)
X_test_minmax =
minmax_scaler.transform(X_test)
```

<BaseQuiz id="sklearn-scaling-1" correct="A">
  <template #question>
    머신러닝에서 특성 스케일링이 중요한 이유는 무엇입니까?
  </template>
  
  <BaseQuizOption value="A" correct>모든 특성이 유사한 규모를 갖도록 하여 일부 특성이 지배하는 것을 방지합니다</BaseQuizOption>
  <BaseQuizOption value="B">누락된 값을 제거합니다</BaseQuizOption>
  <BaseQuizOption value="C">특성의 수를 늘립니다</BaseQuizOption>
  <BaseQuizOption value="D">중복된 행을 제거합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    특성 스케일링은 SVM, KNN 및 신경망과 같은 알고리즘이 특성 규모에 민감하기 때문에 중요합니다. 스케일링 없이는 범위가 더 큰 특성이 모델 학습 과정에서 지배하게 될 수 있습니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 인코딩: `LabelEncoder()` / `OneHotEncoder()`

범주형 변수를 수치형 형식으로 변환.

```python
# 타겟 변수에 대한 레이블 인코딩
from sklearn.preprocessing import
LabelEncoder, OneHotEncoder
label_encoder = LabelEncoder()
y_encoded =
label_encoder.fit_transform(y)
# 범주형 특성에 대한 원 - 핫 인코딩
from sklearn.preprocessing import
OneHotEncoder
encoder =
OneHotEncoder(sparse=False,
drop='first')
X_encoded =
encoder.fit_transform(X_categorical)
# 특성 이름 가져오기
feature_names =
encoder.get_feature_names_out()
```

## 지도 학습 - 분류 (Supervised Learning - Classification)

### 로지스틱 회귀: `LogisticRegression()`

이진 및 다중 클래스 분류를 위한 선형 모델.

```python
# 기본 로지스틱 회귀
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression(random_state=42)
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
y_proba = log_reg.predict_proba(X_test)
# 정규화 포함
log_reg_l2 = LogisticRegression(C=0.1, penalty='l2')
log_reg_l1 = LogisticRegression(C=0.1, penalty='l1',
solver='liblinear')
```

### 결정 트리: `DecisionTreeClassifier()`

분류 작업을 위한 트리 기반 모델.

```python
# 결정 트리 분류기
from sklearn.tree import DecisionTreeClassifier
tree_clf = DecisionTreeClassifier(max_depth=5,
random_state=42)
tree_clf.fit(X_train, y_train)
y_pred = tree_clf.predict(X_test)
# 특성 중요도
importances = tree_clf.feature_importances_
# 트리 시각화
from sklearn.tree import plot_tree
plot_tree(tree_clf, max_depth=3, filled=True)
```

### 랜덤 포레스트: `RandomForestClassifier()`

여러 결정 트리를 결합하는 앙상블 방법.

```python
# 랜덤 포레스트 분류기
from sklearn.ensemble import RandomForestClassifier
rf_clf = RandomForestClassifier(n_estimators=100,
random_state=42)
rf_clf.fit(X_train, y_train)
y_pred = rf_clf.predict(X_test)
# 하이퍼파라미터 튜닝
rf_clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42
)
```

<BaseQuiz id="sklearn-randomforest-1" correct="A">
  <template #question>
    RandomForestClassifier 에서 <code>n_estimators</code> 는 무엇을 제어합니까?
  </template>
  
  <BaseQuizOption value="A" correct>포레스트 내의 결정 트리 개수</BaseQuizOption>
  <BaseQuizOption value="B">각 트리의 최대 깊이</BaseQuizOption>
  <BaseQuizOption value="C">고려할 특성의 개수</BaseQuizOption>
  <BaseQuizOption value="D">랜덤 시드</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>n_estimators</code> 는 랜덤 포레스트에 포함할 결정 트리의 수를 지정합니다. 트리가 많을수록 일반적으로 성능은 향상되지만 계산 시간은 증가합니다. 기본값은 보통 100 입니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 서포트 벡터 머신: `SVC()`

커널 방법을 사용하는 강력한 분류기.

```python
# SVM 분류기
from sklearn.svm import SVC
svm_clf = SVC(kernel='rbf', C=1.0, gamma='scale',
random_state=42)
svm_clf.fit(X_train, y_train)
y_pred = svm_clf.predict(X_test)
# 다른 커널
svm_linear = SVC(kernel='linear')
svm_poly = SVC(kernel='poly', degree=3)
svm_rbf = SVC(kernel='rbf', gamma=0.1)
```

## 지도 학습 - 회귀 (Supervised Learning - Regression)

### 선형 회귀: `LinearRegression()`

연속적인 타겟 변수를 위한 기본 선형 모델.

```python
# 단순 선형 회귀
from sklearn.linear_model import LinearRegression
lin_reg = LinearRegression()
lin_reg.fit(X_train, y_train)
y_pred = lin_reg.predict(X_test)
# 계수 및 절편 가져오기
coefficients = lin_reg.coef_
intercept = lin_reg.intercept_
print(f"R² 점수: {lin_reg.score(X_test, y_test)}")
```

### 릿지 회귀: `Ridge()`

L2 정규화를 사용한 선형 회귀.

```python
# 릿지 회귀 (L2 정규화)
from sklearn.linear_model import Ridge
ridge_reg = Ridge(alpha=1.0)
ridge_reg.fit(X_train, y_train)
y_pred = ridge_reg.predict(X_test)
# alpha 선택을 위한 교차 검증
from sklearn.linear_model import RidgeCV
ridge_cv = RidgeCV(alphas=[0.1, 1.0, 10.0])
ridge_cv.fit(X_train, y_train)
```

### 라쏘 회귀: `Lasso()`

특성 선택을 위한 L1 정규화를 사용한 선형 회귀.

```python
# 라쏘 회귀 (L1 정규화)
from sklearn.linear_model import Lasso
lasso_reg = Lasso(alpha=0.1)
lasso_reg.fit(X_train, y_train)
y_pred = lasso_reg.predict(X_test)
# 특성 선택 (0 이 아닌 계수)
selected_features = X.columns[lasso_reg.coef_ != 0]
print(f"선택된 특성: {len(selected_features)}")
```

### 랜덤 포레스트 회귀: `RandomForestRegressor()`

회귀 작업을 위한 앙상블 방법.

```python
# 랜덤 포레스트 회귀자
from sklearn.ensemble import RandomForestRegressor
rf_reg = RandomForestRegressor(n_estimators=100,
random_state=42)
rf_reg.fit(X_train, y_train)
y_pred = rf_reg.predict(X_test)
# 회귀를 위한 특성 중요도
feature_importance = rf_reg.feature_importances_
```

## 모델 평가 (Model Evaluation)

### 분류 지표 (Classification Metrics)

분류 모델 성능 평가.

```python
# 기본 정확도
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# 상세 분류 보고서
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred))
# 혼동 행렬
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
```

### ROC 곡선 및 AUC

ROC 곡선을 그리고 곡선 아래 면적을 계산.

```python
# 이진 분류를 위한 ROC 곡선
from sklearn.metrics import roc_curve, auc
fpr, tpr, thresholds = roc_curve(y_test, y_proba[:, 1])
roc_auc = auc(fpr, tpr)
# ROC 곡선 그리기
import matplotlib.pyplot as plt
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.legend()
```

### 회귀 지표 (Regression Metrics)

회귀 모델 성능 평가.

```python
# 회귀 지표
from sklearn.metrics import mean_squared_error,
mean_absolute_error, r2_score
mse = mean_squared_error(y_test, y_pred)
rmse = np.sqrt(mse)
mae = mean_absolute_error(y_test, y_pred)
r2 = r2_score(y_test, y_pred)
print(f"MSE: {mse:.4f}")
print(f"RMSE: {rmse:.4f}")
print(f"MAE: {mae:.4f}")
print(f"R²: {r2:.4f}")
```

### 교차 검증 (Cross-Validation)

교차 검증을 사용하여 강력한 모델 평가.

```python
# K-겹 교차 검증
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"CV 정확도: {cv_scores.mean():.4f} (+/-
{cv_scores.std() * 2:.4f})")
# 불균형 데이터셋을 위한 계층적 K-겹
skf = StratifiedKFold(n_splits=5, shuffle=True,
random_state=42)
cv_scores = cross_val_score(model, X, y, cv=skf,
scoring='f1_weighted')
```

## 비지도 학습 (Unsupervised Learning)

### K-평균 군집화: `KMeans()`

데이터를 k 개의 군집으로 분할.

```python
# K-평균 군집화
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
cluster_labels = kmeans.fit_predict(X)
centroids = kmeans.cluster_centers_
# 최적의 군집 수 결정 (엘보우 방법)
inertias = []
K_range = range(1, 11)
for k in K_range:
    kmeans = KMeans(n_clusters=k, random_state=42)
    kmeans.fit(X)
    inertias.append(kmeans.inertia_)
```

### 주성분 분석: `PCA()`

차원 축소 기법.

```python
# 차원 축소를 위한 PCA
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)
explained_variance = pca.explained_variance_ratio_
# 최적의 성분 수 찾기
pca_full = PCA()
pca_full.fit(X)
cumsum =
np.cumsum(pca_full.explained_variance_ratio_)
# 95% 분산을 위한 성분 수 찾기
n_components = np.argmax(cumsum >= 0.95) + 1
```

### DBSCAN 군집화: `DBSCAN()`

밀도 기반 군집화 알고리즘.

```python
# DBSCAN 군집화
from sklearn.cluster import DBSCAN
dbscan = DBSCAN(eps=0.5, min_samples=5)
cluster_labels = dbscan.fit_predict(X)
n_clusters = len(set(cluster_labels)) - (1 if -1 in
cluster_labels else 0)
n_noise = list(cluster_labels).count(-1)
print(f"군집 수: {n_clusters}")
print(f"노이즈 포인트 수: {n_noise}")
```

### 계층적 군집화: `AgglomerativeClustering()`

군집의 계층 구조 구축.

```python
# 계층적 군집화
from sklearn.cluster import AgglomerativeClustering
agg_clustering = AgglomerativeClustering(n_clusters=3,
linkage='ward')
cluster_labels = agg_clustering.fit_predict(X)
# 덴드로그램 시각화
from scipy.cluster.hierarchy import dendrogram, linkage
linked = linkage(X, 'ward')
plt.figure(figsize=(12, 8))
dendrogram(linked)
```

## 모델 선택 및 하이퍼파라미터 튜닝 (Model Selection & Hyperparameter Tuning)

### 그리드 검색: `GridSearchCV()`

파라미터 그리드에 대한 철저한 검색.

```python
# 하이퍼파라미터 튜닝을 위한 그리드 검색
from sklearn.model_selection import GridSearchCV
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [3, 5, 7, None],
    'min_samples_split': [2, 5, 10]
}
grid_search = GridSearchCV(
    RandomForestClassifier(random_state=42),
    param_grid, cv=5, scoring='accuracy', n_jobs=-1
)
grid_search.fit(X_train, y_train)
best_model = grid_search.best_estimator_
best_params = grid_search.best_params_
```

### 랜덤 검색: `RandomizedSearchCV()`

파라미터 분포에서 무작위 샘플링.

```python
# 랜덤 검색 (더 큰 파라미터 공간에 대해 더 빠름)
from sklearn.model_selection import
RandomizedSearchCV
from scipy.stats import randint
param_dist = {
    'n_estimators': randint(100, 500),
    'max_depth': [3, 5, 7, None],
    'min_samples_split': randint(2, 11)
}
random_search = RandomizedSearchCV(
    RandomForestClassifier(random_state=42),
    param_dist, n_iter=50, cv=5, scoring='accuracy',
n_jobs=-1, random_state=42
)
random_search.fit(X_train, y_train)
```

### 파이프라인: `Pipeline()`

전처리 및 모델링 단계를 연결.

```python
# 전처리 및 모델링 파이프라인 생성
from sklearn.pipeline import Pipeline
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier(random_state=42))
])
pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)
# 그리드 검색과 파이프라인
param_grid = {
    'classifier__n_estimators': [100, 200],
    'classifier__max_depth': [3, 5, None]
}
grid_search = GridSearchCV(pipeline, param_grid, cv=5)
grid_search.fit(X_train, y_train)
```

### 특성 선택: `SelectKBest()` / `RFE()`

가장 유익한 특성 선택.

```python
# 단변수 특성 선택
from sklearn.feature_selection import SelectKBest,
f_classif
selector = SelectKBest(score_func=f_classif, k=10)
X_selected = selector.fit_transform(X_train, y_train)
selected_features = X.columns[selector.get_support()]
# 재귀적 특성 제거
from sklearn.feature_selection import RFE
rfe = RFE(RandomForestClassifier(random_state=42),
n_features_to_select=10)
X_rfe = rfe.fit_transform(X_train, y_train)
```

## 고급 기술 (Advanced Techniques)

### 앙상블 방법: `VotingClassifier()` / `BaggingClassifier()`

더 나은 성능을 위해 여러 모델 결합.

```python
# 투표 분류기 (다양한 알고리즘의 앙상블)
from sklearn.ensemble import VotingClassifier
voting_clf = VotingClassifier(
    estimators=[
        ('lr', LogisticRegression(random_state=42)),
        ('rf', RandomForestClassifier(random_state=42)),
        ('svm', SVC(probability=True, random_state=42))
    ], voting='soft'
)
voting_clf.fit(X_train, y_train)
y_pred = voting_clf.predict(X_test)
# 배깅 분류기
from sklearn.ensemble import BaggingClassifier
bagging_clf = BaggingClassifier(DecisionTreeClassifier(),
n_estimators=100, random_state=42)
bagging_clf.fit(X_train, y_train)
```

### 그래디언트 부스팅: `GradientBoostingClassifier()`

오류 수정을 통한 순차적 앙상블 방법.

```python
# 그래디언트 부스팅 분류기
from sklearn.ensemble import
GradientBoostingClassifier
gb_clf = GradientBoostingClassifier(n_estimators=100,
learning_rate=0.1, random_state=42)
gb_clf.fit(X_train, y_train)
y_pred = gb_clf.predict(X_test)
# 특성 중요도
importances = gb_clf.feature_importances_
# 학습 곡선
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores =
learning_curve(gb_clf, X, y, cv=5)
```

### 불균형 데이터 처리: `SMOTE()` / 클래스 가중치

데이터셋의 클래스 불균형 처리.

```python
# imbalanced-learn 설치: pip install imbalanced-learn
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train,
y_train)
# 클래스 가중치 사용
rf_balanced =
RandomForestClassifier(class_weight='balanced',
random_state=42)
rf_balanced.fit(X_train, y_train)
# 수동 클래스 가중치
from sklearn.utils.class_weight import
compute_class_weight
class_weights = compute_class_weight('balanced',
classes=np.unique(y_train), y=y_train)
weight_dict = dict(zip(np.unique(y_train), class_weights))
```

### 모델 지속성: `joblib`

훈련된 모델 저장 및 로드.

```python
# 모델 저장
import joblib
joblib.dump(model, 'trained_model.pkl')
# 모델 로드
loaded_model = joblib.load('trained_model.pkl')
y_pred = loaded_model.predict(X_test)
# 전체 파이프라인 저장
joblib.dump(pipeline, 'preprocessing_pipeline.pkl')
loaded_pipeline =
joblib.load('preprocessing_pipeline.pkl')
# pickle 을 사용한 대안
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
```

## 성능 및 디버깅 (Performance & Debugging)

### 학습 곡선: `learning_curve()`

과적합 및 과소적합 진단.

```python
# 학습 곡선 그리기
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores = learning_curve(
    model, X, y, cv=5, train_sizes=np.linspace(0.1, 1.0, 10)
)
plt.figure(figsize=(10, 6))
plt.plot(train_sizes, np.mean(train_scores, axis=1), 'o-',
label='Training Score')
plt.plot(train_sizes, np.mean(val_scores, axis=1), 'o-',
label='Validation Score')
plt.xlabel('Training Set Size')
plt.ylabel('Score')
plt.legend()
```

### 검증 곡선: `validation_curve()`

하이퍼파라미터 효과 분석.

```python
# 단일 하이퍼파라미터에 대한 검증 곡선
from sklearn.model_selection import validation_curve
param_range = [10, 50, 100, 200, 500]
train_scores, val_scores = validation_curve(
    RandomForestClassifier(random_state=42), X, y,
    param_name='n_estimators',
param_range=param_range, cv=5
)
plt.figure(figsize=(10, 6))
plt.plot(param_range, np.mean(train_scores, axis=1), 'o-',
label='Training')
plt.plot(param_range, np.mean(val_scores, axis=1), 'o-',
label='Validation')
plt.xlabel('Number of Estimators')
plt.ylabel('Score')
```

### 특성 중요도 시각화

모델 예측을 주도하는 특성 이해.

```python
# 특성 중요도 그리기
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
plt.figure(figsize=(12, 8))
plt.title("Feature Importance")
plt.bar(range(X.shape[1]), importances[indices])
plt.xticks(range(X.shape[1]), [X.columns[i] for i in indices],
rotation=90)
# 모델 해석력을 위한 SHAP 값
# pip install shap
import shap
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_test)
shap.summary_plot(shap_values, X_test)
```

### 모델 비교 (Model Comparison)

여러 알고리즘을 체계적으로 비교.

```python
# 여러 모델 비교
from sklearn.model_selection import cross_val_score
models = {
    'Logistic Regression':
LogisticRegression(random_state=42),
    'Random Forest':
RandomForestClassifier(random_state=42),
    'SVM': SVC(random_state=42),
    'Gradient Boosting':
GradientBoostingClassifier(random_state=42)
}
results = {}
for name, model in models.items():
    scores = cross_val_score(model, X_train, y_train, cv=5,
scoring='accuracy')
    results[name] = scores.mean()
    print(f"{name}: {scores.mean():.4f} (+/- {scores.std() *
2:.4f})")
```

## 구성 및 모범 사례 (Configuration & Best Practices)

### 랜덤 상태 및 재현성 (Random State & Reproducibility)

실행 간 일관된 결과 보장.

```python
# 재현성을 위한 랜덤 상태 설정
import numpy as np
np.random.seed(42)
# 모든 sklearn 구성 요소에서 random_state 설정
model =
RandomForestClassifier(random
_state=42)
train_test_split(X, y,
random_state=42)
# 교차 검증의 경우
cv = StratifiedKFold(n_splits=5,
shuffle=True, random_state=42)
```

### 메모리 및 성능 (Memory & Performance)

대규모 데이터셋 및 계산 효율성을 위한 최적화.

```python
# 병렬 처리를 위해 n_jobs=-1 사용
model =
RandomForestClassifier(n_jobs=
-1)
grid_search =
GridSearchCV(model,
param_grid, n_jobs=-1)
# 대규모 데이터셋의 경우 사용 가능한 곳에서 partial_fit 사용
from sklearn.linear_model
import SGDClassifier
sgd = SGDClassifier()
# 청크 단위로 데이터 처리
for chunk in chunks:
    sgd.partial_fit(chunk_X,
chunk_y)
```

### 경고 및 디버깅 (Warnings & Debugging)

일반적인 문제 처리 및 모델 디버깅.

```python
# 경고 억제 (주의해서 사용)
import warnings
warnings.filterwarnings('ignore')
# Jupyter 에서 향상된 표시를 위해 sklearn 의 set_config 활성화
from sklearn import set_config
set_config(display='diagram')  #
향상된 표시
# 데이터 유출 확인
from sklearn.model_selection
import cross_val_score
# CV 루프 내에서 전처리 수행 확인
```

## 관련 링크 (Relevant Links)

- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/pandas">Pandas 치트 시트</router-link>
- <router-link to="/numpy">NumPy 치트 시트</router-link>
- <router-link to="/matplotlib">Matplotlib 치트 시트</router-link>
- <router-link to="/datascience">데이터 과학 치트 시트</router-link>
- <router-link to="/database">데이터베이스 치트 시트</router-link>

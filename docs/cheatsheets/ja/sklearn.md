---
title: 'scikit-learn チートシート'
description: '必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートで scikit-learn を習得しましょう。'
pdfUrl: '/cheatsheets/pdf/sklearn-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
scikit-learn チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/sklearn">ハンズオンラボで scikit-learn を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、scikit-learn 機械学習を学びましょう。LabEx は、必須のデータ前処理、モデル選択、トレーニング、評価、特徴量エンジニアリングを網羅した包括的な scikit-learn コースを提供します。機械学習アルゴリズムを習得し、Python で予測モデルを構築します。
</base-disclaimer-content>
</base-disclaimer>

## インストールとインポート

### インストール：`pip install scikit-learn`

scikit-learn と一般的な依存関係をインストールします。

```bash
# scikit-learnをインストール
pip install scikit-learn
# 追加パッケージと共にインストール
pip install scikit-learn pandas numpy matplotlib
# 最新バージョンにアップグレード
pip install scikit-learn --upgrade
```

### 必須インポート

scikit-learn のワークフローのための標準的なインポート。

```python
# コアインポート
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,
classification_report
# 一般的なアルゴリズム
from sklearn.linear_model import LinearRegression,
LogisticRegression
from sklearn.ensemble import RandomForestClassifier,
GradientBoostingRegressor
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
```

### バージョンの確認

scikit-learn のインストールを確認します。

```python
import sklearn
print(sklearn.__version__)
# ビルド設定を表示
sklearn.show_versions()
```

### データセットの読み込み

練習用に組み込みデータセットを読み込みます。

```python
from sklearn.datasets import load_iris, load_boston,
make_classification
# サンプルデータセットの読み込み
iris = load_iris()
X, y = iris.data, iris.target
# 合成データの生成
X_synth, y_synth = make_classification(n_samples=1000,
n_features=20, n_informative=10, random_state=42)
```

## データ前処理

### 訓練 - テスト分割：`train_test_split()`

データを訓練セットとテストセットに分割します。

```python
# 基本的な分割 (訓練 80%、テスト 20%)
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
random_state=42)
# 分類のための層化分割
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
stratify=y, random_state=42)
# 複数回の分割
X_train, X_temp, y_train, y_temp =
train_test_split(X, y, test_size=0.4,
random_state=42)
X_val, X_test, y_val, y_test =
train_test_split(X_temp, y_temp,
test_size=0.5, random_state=42)
```

### 特徴量スケーリング：`StandardScaler()` / `MinMaxScaler()`

特徴量を類似したスケールに正規化します。

```python
# 標準化 (平均=0, 標準偏差=1)
from sklearn.preprocessing import
StandardScaler, MinMaxScaler
scaler = StandardScaler()
X_scaled =
scaler.fit_transform(X_train)
X_test_scaled =
scaler.transform(X_test)
# Min-Max スケーリング (0-1 の範囲)
minmax_scaler = MinMaxScaler()
X_minmax =
minmax_scaler.fit_transform(X_train)
X_test_minmax =
minmax_scaler.transform(X_test)
```

### エンコーディング：`LabelEncoder()` / `OneHotEncoder()`

カテゴリ変数を数値形式に変換します。

```python
# 目的変数に対するラベルエンコーディング
from sklearn.preprocessing import
LabelEncoder, OneHotEncoder
label_encoder = LabelEncoder()
y_encoded =
label_encoder.fit_transform(y)
# カテゴリ特徴量に対するワンホットエンコーディング
from sklearn.preprocessing import
OneHotEncoder
encoder =
OneHotEncoder(sparse=False,
drop='first')
X_encoded =
encoder.fit_transform(X_categorical)
# 特徴量名を取得
feature_names =
encoder.get_feature_names_out()
```

## 教師あり学習 - 分類

### ロジスティック回帰：`LogisticRegression()`

二値分類および多クラス分類のための線形モデル。

```python
# 基本的なロジスティック回帰
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression(random_state=42)
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
y_proba = log_reg.predict_proba(X_test)
# 正則化あり
log_reg_l2 = LogisticRegression(C=0.1, penalty='l2')
log_reg_l1 = LogisticRegression(C=0.1, penalty='l1',
solver='liblinear')
```

### 決定木：`DecisionTreeClassifier()`

分類タスクのための木ベースのモデル。

```python
# 決定木分類器
from sklearn.tree import DecisionTreeClassifier
tree_clf = DecisionTreeClassifier(max_depth=5,
random_state=42)
tree_clf.fit(X_train, y_train)
y_pred = tree_clf.predict(X_test)
# 特徴量の重要度
importances = tree_clf.feature_importances_
# 木の可視化
from sklearn.tree import plot_tree
plot_tree(tree_clf, max_depth=3, filled=True)
```

### ランダムフォレスト：`RandomForestClassifier()`

複数の決定木を組み合わせるアンサンブル手法。

```python
# ランダムフォレスト分類器
from sklearn.ensemble import RandomForestClassifier
rf_clf = RandomForestClassifier(n_estimators=100,
random_state=42)
rf_clf.fit(X_train, y_train)
y_pred = rf_clf.predict(X_test)
# ハイパーパラメータチューニング
rf_clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42
)
```

### サポートベクターマシン：`SVC()`

カーネル法を用いた強力な分類器。

```python
# SVM 分類器
from sklearn.svm import SVC
svm_clf = SVC(kernel='rbf', C=1.0, gamma='scale',
random_state=42)
svm_clf.fit(X_train, y_train)
y_pred = svm_clf.predict(X_test)
# 異なるカーネル
svm_linear = SVC(kernel='linear')
svm_poly = SVC(kernel='poly', degree=3)
svm_rbf = SVC(kernel='rbf', gamma=0.1)
```

## 教師あり学習 - 回帰

### 線形回帰：`LinearRegression()`

連続的な目的変数に対する基本的な線形モデル。

```python
# 単純な線形回帰
from sklearn.linear_model import LinearRegression
lin_reg = LinearRegression()
lin_reg.fit(X_train, y_train)
y_pred = lin_reg.predict(X_test)
# 係数と切片の取得
coefficients = lin_reg.coef_
intercept = lin_reg.intercept_
print(f"R² スコア：{lin_reg.score(X_test, y_test)}")
```

### リッジ回帰：`Ridge()`

L2 正則化を伴う線形回帰。

```python
# リッジ回帰 (L2 正則化)
from sklearn.linear_model import Ridge
ridge_reg = Ridge(alpha=1.0)
ridge_reg.fit(X_train, y_train)
y_pred = ridge_reg.predict(X_test)
# alpha 選択のための交差検証
from sklearn.linear_model import RidgeCV
ridge_cv = RidgeCV(alphas=[0.1, 1.0, 10.0])
ridge_cv.fit(X_train, y_train)
```

### ラッソ回帰：`Lasso()`

特徴量選択のための L1 正則化を伴う線形回帰。

```python
# ラッソ回帰 (L1 正則化)
from sklearn.linear_model import Lasso
lasso_reg = Lasso(alpha=0.1)
lasso_reg.fit(X_train, y_train)
y_pred = lasso_reg.predict(X_test)
# 特徴量選択 (ゼロでない係数)
selected_features = X.columns[lasso_reg.coef_ != 0]
print(f"選択された特徴量：{len(selected_features)}")
```

### ランダムフォレスト回帰：`RandomForestRegressor()`

回帰タスクのためのアンサンブル手法。

```python
# ランダムフォレスト回帰器
from sklearn.ensemble import RandomForestRegressor
rf_reg = RandomForestRegressor(n_estimators=100,
random_state=42)
rf_reg.fit(X_train, y_train)
y_pred = rf_reg.predict(X_test)
# 回帰のための特徴量の重要度
feature_importance = rf_reg.feature_importances_
```

## モデル評価

### 分類メトリクス

分類モデルの性能を評価します。

```python
# 基本的な精度
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# 詳細な分類レポート
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred))
# 混同行列
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
```

### ROC 曲線と AUC

ROC 曲線をプロットし、曲線下面積を計算します。

```python
# 二値分類のための ROC 曲線
from sklearn.metrics import roc_curve, auc
fpr, tpr, thresholds = roc_curve(y_test, y_proba[:, 1])
roc_auc = auc(fpr, tpr)
# ROC 曲線のプロット
import matplotlib.pyplot as plt
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel('偽陽性率 (False Positive Rate)')
plt.ylabel('真陽性率 (True Positive Rate)')
plt.legend()
```

### 回帰メトリクス

回帰モデルの性能を評価します。

```python
# 回帰メトリクス
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

### 交差検証

交差検証を用いた堅牢なモデル評価。

```python
# K 分割交差検証
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"CV 精度: {cv_scores.mean():.4f} (+/-
{cv_scores.std() * 2:.4f})")
# 不均衡データセットのための層化 K 分割
skf = StratifiedKFold(n_splits=5, shuffle=True,
random_state=42)
cv_scores = cross_val_score(model, X, y, cv=skf,
scoring='f1_weighted')
```

## 教師なし学習

### K 平均法：`KMeans()`

データを k 個のクラスターに分割します。

```python
# K 平均法クラスタリング
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
cluster_labels = kmeans.fit_predict(X)
centroids = kmeans.cluster_centers_
# 最適なクラスター数の決定 (エルボー法)
inertias = []
K_range = range(1, 11)
for k in K_range:
    kmeans = KMeans(n_clusters=k, random_state=42)
    kmeans.fit(X)
    inertias.append(kmeans.inertia_)
```

### 主成分分析：`PCA()`

次元削減技術。

```python
# 次元削減のための PCA
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)
explained_variance = pca.explained_variance_ratio_
# 最適なコンポーネント数の検索
pca_full = PCA()
pca_full.fit(X)
cumsum =
np.cumsum(pca_full.explained_variance_ratio_)
# 95% の分散を保持するコンポーネント数の検索
n_components = np.argmax(cumsum >= 0.95) + 1
```

### DBSCAN クラスタリング：`DBSCAN()`

密度ベースのクラスタリングアルゴリズム。

```python
# DBSCAN クラスタリング
from sklearn.cluster import DBSCAN
dbscan = DBSCAN(eps=0.5, min_samples=5)
cluster_labels = dbscan.fit_predict(X)
n_clusters = len(set(cluster_labels)) - (1 if -1 in
cluster_labels else 0)
n_noise = list(cluster_labels).count(-1)
print(f"クラスター数：{n_clusters}")
print(f"ノイズ点の数：{n_noise}")
```

### 階層的クラスタリング：`AgglomerativeClustering()`

クラスターの階層を構築します。

```python
# 階層的クラスタリング
from sklearn.cluster import AgglomerativeClustering
agg_clustering = AgglomerativeClustering(n_clusters=3,
linkage='ward')
cluster_labels = agg_clustering.fit_predict(X)
# デンドログラムの可視化
from scipy.cluster.hierarchy import dendrogram, linkage
linked = linkage(X, 'ward')
plt.figure(figsize=(12, 8))
dendrogram(linked)
```

## モデル選択とハイパーパラメータチューニング

### グリッドサーチ：`GridSearchCV()`

パラメータグリッド全体での網羅的な探索。

```python
# ハイパーパラメータチューニングのためのグリッドサーチ
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

### ランダムサーチ：`RandomizedSearchCV()`

パラメータ分布からのランダムサンプリング。

```python
# ランダムサーチ (大規模なパラメータ空間では高速)
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

### パイプライン：`Pipeline()`

前処理とモデリングのステップを連鎖させます。

```python
# 前処理とモデリングのパイプラインを作成
from sklearn.pipeline import Pipeline
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier(random_state=42))
])
pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)
# グリッドサーチとパイプライン
param_grid = {
    'classifier__n_estimators': [100, 200],
    'classifier__max_depth': [3, 5, None]
}
grid_search = GridSearchCV(pipeline, param_grid, cv=5)
grid_search.fit(X_train, y_train)
```

### 特徴量選択：`SelectKBest()` / `RFE()`

最も情報量の多い特徴量を選択します。

```python
# 単変量特徴量選択
from sklearn.feature_selection import SelectKBest,
f_classif
selector = SelectKBest(score_func=f_classif, k=10)
X_selected = selector.fit_transform(X_train, y_train)
selected_features = X.columns[selector.get_support()]
# 再帰的特徴量除去
from sklearn.feature_selection import RFE
rfe = RFE(RandomForestClassifier(random_state=42),
n_features_to_select=10)
X_rfe = rfe.fit_transform(X_train, y_train)
```

## 高度なテクニック

### アンサンブル手法：`VotingClassifier()` / `BaggingClassifier()`

より良い性能のために複数のモデルを組み合わせます。

```python
# Voting classifier (異なるアルゴリズムのアンサンブル)
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
# Bagging classifier
from sklearn.ensemble import BaggingClassifier
bagging_clf = BaggingClassifier(DecisionTreeClassifier(),
n_estimators=100, random_state=42)
bagging_clf.fit(X_train, y_train)
```

### 勾配ブースティング：`GradientBoostingClassifier()`

誤差修正を伴う逐次的なアンサンブル手法。

```python
# 勾配ブースティング分類器
from sklearn.ensemble import
GradientBoostingClassifier
gb_clf = GradientBoostingClassifier(n_estimators=100,
learning_rate=0.1, random_state=42)
gb_clf.fit(X_train, y_train)
y_pred = gb_clf.predict(X_test)
# 特徴量の重要度
importances = gb_clf.feature_importances_
# 学習曲線
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores =
learning_curve(gb_clf, X, y, cv=5)
```

### 不均衡データの処理：`SMOTE()` / クラスウェイト

データセット内のクラス不均衡に対処します。

```python
# imbalanced-learn のインストール：pip install imbalanced-learn
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train,
y_train)
# クラスウェイトの使用
rf_balanced =
RandomForestClassifier(class_weight='balanced',
random_state=42)
rf_balanced.fit(X_train, y_train)
# 手動でのクラスウェイト計算
from sklearn.utils.class_weight import
compute_class_weight
class_weights = compute_class_weight('balanced',
classes=np.unique(y_train), y=y_train)
weight_dict = dict(zip(np.unique(y_train), class_weights))
```

### モデルの永続化：`joblib`

訓練済みモデルの保存と読み込み。

```python
# モデルの保存
import joblib
joblib.dump(model, 'trained_model.pkl')
# モデルの読み込み
loaded_model = joblib.load('trained_model.pkl')
y_pred = loaded_model.predict(X_test)
# パイプライン全体の保存
joblib.dump(pipeline, 'preprocessing_pipeline.pkl')
loaded_pipeline =
joblib.load('preprocessing_pipeline.pkl')
# pickle の使用 (代替手段)
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
```

## パフォーマンスとデバッグ

### 学習曲線：`learning_curve()`

過学習と未学習を診断します。

```python
# 学習曲線のプロット
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores = learning_curve(
    model, X, y, cv=5, train_sizes=np.linspace(0.1, 1.0, 10)
)
plt.figure(figsize=(10, 6))
plt.plot(train_sizes, np.mean(train_scores, axis=1), 'o-',
label='トレーニング スコア')
plt.plot(train_sizes, np.mean(val_scores, axis=1), 'o-',
label='検証スコア')
plt.xlabel('トレーニングセットサイズ')
plt.ylabel('スコア')
plt.legend()
```

### 検証曲線：`validation_curve()`

ハイパーパラメータの影響を分析します。

```python
# 単一ハイパーパラメータの検証曲線
from sklearn.model_selection import validation_curve
param_range = [10, 50, 100, 200, 500]
train_scores, val_scores = validation_curve(
    RandomForestClassifier(random_state=42), X, y,
    param_name='n_estimators',
param_range=param_range, cv=5
)
plt.figure(figsize=(10, 6))
plt.plot(param_range, np.mean(train_scores, axis=1), 'o-',
label='トレーニング')
plt.plot(param_range, np.mean(val_scores, axis=1), 'o-',
label='検証')
plt.xlabel('推定器の数')
plt.ylabel('スコア')
```

### 特徴量の重要度の可視化

モデルの予測にどの特徴量が寄与しているかを理解します。

```python
# 特徴量の重要度のプロット
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
plt.figure(figsize=(12, 8))
plt.title("特徴量の重要度")
plt.bar(range(X.shape[1]), importances[indices])
plt.xticks(range(X.shape[1]), [X.columns[i] for i in indices],
rotation=90)
# モデル解釈のための SHAP 値
# pip install shap
import shap
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_test)
shap.summary_plot(shap_values, X_test)
```

### モデルの比較

複数のアルゴリズムを体系的に比較します。

```python
# 複数のモデルの比較
from sklearn.model_selection import cross_val_score
models = {
    'ロジスティック回帰':
LogisticRegression(random_state=42),
    'ランダムフォレスト':
RandomForestClassifier(random_state=42),
    'SVM': SVC(random_state=42),
    '勾配ブースティング':
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

## 設定とベストプラクティス

### ランダムシードと再現性

実行間で結果の一貫性を保証します。

```python
# 再現性のためのランダムシードの設定
import numpy as np
np.random.seed(42)
# すべての sklearn コンポーネントで random_state を設定
model =
RandomForestClassifier(random
_state=42)
train_test_split(X, y,
random_state=42)
# 交差検証用
cv = StratifiedKFold(n_splits=5,
shuffle=True, random_state=42)
```

### メモリとパフォーマンス

大規模データセットと計算効率のための最適化。

```python
# 並列処理のために n_jobs=-1 を使用
model =
RandomForestClassifier(n_jobs=
-1)
grid_search =
GridSearchCV(model,
param_grid, n_jobs=-1)
# 大規模データセットの場合、利用可能な場合は partial_fit を使用
from sklearn.linear_model
import SGDClassifier
sgd = SGDClassifier()
# チャンクごとにデータを処理
for chunk in chunks:
    sgd.partial_fit(chunk_X,
chunk_y)
```

### 警告とデバッグ

一般的な問題の処理とモデルのデバッグ。

```python
# 警告を抑制 (注意して使用)
import warnings
warnings.filterwarnings('ignore')
# Jupyter でのデバッグ表示を強化するための sklearn の set_config
from sklearn import set_config
set_config(display='diagram')  #
Jupyterでの表示を強化
# データリークの確認
from sklearn.model_selection
import cross_val_score
# CV ループ内で前処理が実行されていることを確認
```

## 関連リンク

- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/pandas">Pandas チートシート</router-link>
- <router-link to="/numpy">NumPy チートシート</router-link>
- <router-link to="/matplotlib">Matplotlib チートシート</router-link>
- <router-link to="/datascience">データサイエンス チートシート</router-link>
- <router-link to="/database">データベース チートシート</router-link>

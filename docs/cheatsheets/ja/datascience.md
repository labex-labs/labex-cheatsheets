---
title: 'データサイエンス チートシート | LabEx'
description: 'この包括的なチートシートでデータサイエンスを学ぶ。データ分析、機械学習、統計、可視化、Python ライブラリ、データサイエンスワークフローのクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/data-science-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
データサイエンス チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/datascience">ハンズオンラボでデータサイエンスを学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと現実世界のシナリオを通じてデータサイエンスを学びましょう。LabEx は、必須の Python ライブラリ、データ操作、統計分析、機械学習、データ視覚化を網羅した包括的なデータサイエンスコースを提供します。データ収集、クリーニング、分析、モデルデプロイメントの技術を習得します。
</base-disclaimer-content>
</base-disclaimer>

## 必須の Python ライブラリ

### コアデータサイエンススタック

NumPy、Pandas、Matplotlib、Seaborn、scikit-learn などの主要なライブラリは、データサイエンスワークフローの基盤を形成します。

```python
# データサイエンスの必須インポート
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

Python による数値計算のための基本的なパッケージ。

```python
# 配列の作成
arr = np.array([1, 2, 3, 4, 5])
matrix = np.array([[1, 2], [3, 4]])
# 基本的な操作
np.mean(arr)       # 平均
np.std(arr)        # 標準偏差
np.reshape(arr, (5, 1))  # 配列の整形
# データの生成
np.random.normal(0, 1, 100)  # ランダムな正規分布
```

### Pandas: `import pandas as pd`

データ操作と分析のためのライブラリ。

```python
# DataFrame の作成
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
# データの読み込み
df = pd.read_csv('data.csv')
# 基本的な探索
df.head()          # 最初の 5 行
df.info()          # データ型と欠損値
df.describe()      # 要約統計量
# データ操作
df.groupby('column').mean()
df.fillna(df.mean())  # 欠損値の処理
```

<BaseQuiz id="datascience-pandas-1" correct="C">
  <template #question>
    Pandas で `df.head()` は何を返しますか？
  </template>
  
  <BaseQuizOption value="A">DataFrame の最後の 5 行</BaseQuizOption>
  <BaseQuizOption value="B">DataFrame の要約</BaseQuizOption>
  <BaseQuizOption value="C" correct>DataFrame の最初の 5 行</BaseQuizOption>
  <BaseQuizOption value="D">DataFrame のすべての行</BaseQuizOption>
  
  <BaseQuizAnswer>
    `df.head()`はデフォルトで DataFrame の最初の 5 行を表示します。`df.head(10)` のように異なる数値を指定して最初の 10 行を表示することもできます。データを素早く確認するのに役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

### Matplotlib & Seaborn: 視覚化

統計的な視覚化とプロットを作成します。

```python
# Matplotlib の基本
plt.plot(x, y)
plt.hist(data, bins=20)
plt.scatter(x, y)
plt.show()
# 統計プロットのための Seaborn
sns.boxplot(data=df, x='category', y='value')
sns.heatmap(df.corr(), annot=True)
sns.pairplot(df)
```

## データサイエンスのワークフロー

### 1. 問題の定義

データサイエンスは、数学、統計学、プログラミング、ビジネスインテリジェンスを組み合わせた学際的な分野です。目的と成功基準を定義します。

```python
# ビジネス上の問題の定義
# - どのような質問に答えるのか？
# - 成功を測る指標は何か？
# - どのようなデータが必要か？
```

### 2. データ収集とインポート

さまざまなソースと形式からデータを収集します。

```python
# 複数のデータソース
df_csv = pd.read_csv('data.csv')
df_json = pd.read_json('data.json')
df_sql = pd.read_sql('SELECT * FROM
table', connection)
# API と Web スクレイピング
import requests
response =
requests.get('https://api.example.co
m/data')
```

### 3. データ探索（EDA）

データの構造、パターン、品質を理解します。

```python
# 探索的データ分析 (EDA)
df.shape              # 次元
df.dtypes             # データ型
df.isnull().sum()     # 欠損値の数
df['column'].value_counts()  #
度数分布
df.corr()             # 相関行列
# EDA のための視覚化
sns.histplot(df['numeric_column'])
sns.boxplot(data=df,
y='numeric_column')
plt.figure(figsize=(10, 8))
sns.heatmap(df.corr(), annot=True)
```

## データクリーニングと前処理

### 欠損値の処理

データを分析する前に、クリーニングと準備が必要です。これには、欠損値の処理、重複の削除、変数の正規化が含まれます。データクリーニングは、データサイエンスプロセスの中で最も時間のかかる、しかし最も重要な側面であることがよくあります。

```python
# 欠損値の特定
df.isnull().sum()
df.isnull().sum() / len(df) * 100  # 欠損率 (%)
# 欠損値の処理
df.dropna()                    # NaN のある行を削除
df.fillna(df.mean())          # 平均値で埋める
df.fillna(method='forward')   # 前方補完
df.fillna(method='backward')  # 後方補完
# 高度な補完
from sklearn.impute import SimpleImputer, KNNImputer
imputer = SimpleImputer(strategy='median')
df_filled = pd.DataFrame(imputer.fit_transform(df))
```

<BaseQuiz id="datascience-missing-1" correct="B">
  <template #question>
    `method='forward'` による前方補完は何に使用されますか？
  </template>
  
  <BaseQuizOption value="A">欠損値を平均値で埋める</BaseQuizOption>
  <BaseQuizOption value="B" correct>欠損値を直前の非 null 値で埋める</BaseQuizOption>
  <BaseQuizOption value="C">欠損値をランダムな値で埋める</BaseQuizOption>
  <BaseQuizOption value="D">欠損値を削除する</BaseQuizOption>
  
  <BaseQuizAnswer>
    前方補完は、直前の有効な観測値を前方に伝播させて欠損値を埋めます。新しいデータが利用可能になるまで以前の値を維持したい時系列データに役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

### データ変換

データの正規化（データを[0, 1]などの標準範囲にスケーリングすること）は、特徴量の大きさの違いによるバイアスを避けるのに役立ちます。

```python
# スケーリングと正規化
from sklearn.preprocessing import StandardScaler,
MinMaxScaler
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df[numeric_columns])
# [0,1] への Min-Max スケーリング
minmax = MinMaxScaler()
df_normalized =
minmax.fit_transform(df[numeric_columns])
# カテゴリ変数のエンコーディング
pd.get_dummies(df, columns=['category_column'])
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
df['encoded'] = le.fit_transform(df['category'])
```

<BaseQuiz id="datascience-scaling-1" correct="C">
  <template #question>
    StandardScaler と MinMaxScaler の違いは何ですか？
  </template>
  
  <BaseQuizOption value="A">違いはない</BaseQuizOption>
  <BaseQuizOption value="B">StandardScaler は [0,1] にスケーリングし、MinMaxScaler は平均=0、標準偏差=1 にスケーリングする</BaseQuizOption>
  <BaseQuizOption value="C" correct>StandardScaler は平均=0、標準偏差=1 に正規化し、MinMaxScaler は [0,1] の範囲にスケーリングする</BaseQuizOption>
  <BaseQuizOption value="D">StandardScaler の方が速い</BaseQuizOption>
  
  <BaseQuizAnswer>
    StandardScaler はデータを平均 0、標準偏差 1 に変換します（z スコア正規化）。MinMaxScaler はデータを固定範囲、通常は [0, 1] にスケーリングします。どちらも有用ですが、シナリオが異なります。
  </BaseQuizAnswer>
</BaseQuiz>

### 外れ値の検出と処理

分析を歪める可能性のある極端な値を特定し、処理します。

```python
# 統計的外れ値の検出
Q1 = df['column'].quantile(0.25)
Q3 = df['column'].quantile(0.75)
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR
# 外れ値の削除
df_clean = df[(df['column'] >= lower_bound) &
              (df['column'] <= upper_bound)]
# Z スコア法
from scipy import stats
z_scores = np.abs(stats.zscore(df['column']))
df_no_outliers = df[z_scores < 3]
```

### 特徴量エンジニアリング

モデルのパフォーマンスを向上させるために新しい変数を生成します。

```python
# 新しい特徴量の作成
df['feature_ratio'] = df['feature1'] / df['feature2']
df['feature_sum'] = df['feature1'] + df['feature2']
# 日付/時刻の特徴量
df['date'] = pd.to_datetime(df['date'])
df['year'] = df['date'].dt.year
df['month'] = df['date'].dt.month
df['day_of_week'] = df['date'].dt.day_name()
# 連続変数のビニング
df['age_group'] = pd.cut(df['age'], bins=[0, 18, 35, 50, 100],
                        labels=['Child', 'Young Adult', 'Adult',
'Senior'])
```

## 統計分析

### 記述統計量

これらの中心傾向の尺度は、データを要約し、その分布に関する洞察を提供します。これらは、あらゆるデータセットを理解するための基礎となります。平均値は、データセット内のすべての値の平均です。外れ値に非常に敏感です。

```python
# 中心傾向
mean = df['column'].mean()
median = df['column'].median()
mode = df['column'].mode()[0]
# ばらつきの尺度
std_dev = df['column'].std()
variance = df['column'].var()
range_val = df['column'].max() - df['column'].min()
# 分布の形状
skewness = df['column'].skew()
kurtosis = df['column'].kurtosis()
# パーセンタイル
percentiles = df['column'].quantile([0.25, 0.5, 0.75, 0.95])
```

### 仮説検定

統計的仮説を検定し、仮定を検証します。

```python
# 平均を比較するための t 検定
from scipy.stats import ttest_ind, ttest_1samp
# 1 標本の t 検定
t_stat, p_value = ttest_1samp(data, population_mean)
# 2 標本の t 検定
group1 = df[df['group'] == 'A']['value']
group2 = df[df['group'] == 'B']['value']
t_stat, p_value = ttest_ind(group1, group2)
# 独立性のカイ二乗検定
from scipy.stats import chi2_contingency
chi2, p_value, dof, expected =
chi2_contingency(contingency_table)
```

### 相関分析

変数間の関係を理解します。

```python
# 相関行列
correlation_matrix = df.corr()
plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix, annot=True,
cmap='coolwarm')
# 特定の相関
pearson_corr = df['var1'].corr(df['var2'])
spearman_corr = df['var1'].corr(df['var2'],
method='spearman')
# 相関の統計的有意性
from scipy.stats import pearsonr
correlation, p_value = pearsonr(df['var1'], df['var2'])
```

### ANOVA と回帰

分散と変数間の関係を分析します。

```python
# 一元配置分散分析 (One-way ANOVA)
from scipy.stats import f_oneway
group_data = [df[df['group'] == g]['value'] for g in
df['group'].unique()]
f_stat, p_value = f_oneway(*group_data)
# 線形回帰分析
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score
X = df[['feature1', 'feature2']]
y = df['target']
model = LinearRegression().fit(X, y)
y_pred = model.predict(X)
r2 = r2_score(y, y_pred)
```

## 機械学習モデル

### 教師あり学習 - 分類

決定木：意思決定とそれらの可能な結果の木のようなモデル。各ノードは属性に対するテストを表し、各ブランチは結果を表します。分類タスクによく使用されます。

```python
# 訓練 - テスト分割
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y,
test_size=0.2, random_state=42)
# ロジスティック回帰
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression()
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
# 決定木
from sklearn.tree import DecisionTreeClassifier
dt = DecisionTreeClassifier(max_depth=5)
dt.fit(X_train, y_train)
# ランダムフォレスト
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=100)
rf.fit(X_train, y_train)
```

### 教師あり学習 - 回帰

連続する目的変数を予測します。

```python
# 線形回帰
from sklearn.linear_model import LinearRegression
lr = LinearRegression()
lr.fit(X_train, y_train)
y_pred = lr.predict(X_test)
# 多項式回帰
from sklearn.preprocessing import PolynomialFeatures
poly = PolynomialFeatures(degree=2)
X_poly = poly.fit_transform(X)
# Ridge および Lasso 回帰
from sklearn.linear_model import Ridge, Lasso
ridge = Ridge(alpha=1.0)
lasso = Lasso(alpha=0.1)
ridge.fit(X_train, y_train)
lasso.fit(X_train, y_train)
```

### 教師なし学習

ラベル付けされた結果なしでデータ内のパターンを発見します。

```python
# K 平均法クラスタリング
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
clusters = kmeans.fit_predict(X)
df['cluster'] = clusters
# 主成分分析 (PCA)
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)
# 階層的クラスタリング
from scipy.cluster.hierarchy import dendrogram, linkage
linkage_matrix = linkage(X_scaled, method='ward')
dendrogram(linkage_matrix)
```

### モデル評価

適切なメトリクスを使用してモデルのパフォーマンスを評価します。

```python
# 分類メトリクス
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score, confusion_matrix
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# 混同行列
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d')
# 回帰メトリクス
from sklearn.metrics import mean_squared_error,
mean_absolute_error
mse = mean_squared_error(y_test, y_pred)
mae = mean_absolute_error(y_test, y_pred)
rmse = np.sqrt(mse)
```

## データ視覚化

### 探索的視覚化

データの分布と関係性を理解します。

```python
# 分布プロット
plt.figure(figsize=(12, 4))
plt.subplot(1, 3, 1)
plt.hist(df['numeric_col'], bins=20, edgecolor='black')
plt.subplot(1, 3, 2)
sns.boxplot(y=df['numeric_col'])
plt.subplot(1, 3, 3)
sns.violinplot(y=df['numeric_col'])
# 関係性プロット
plt.figure(figsize=(10, 6))
sns.scatterplot(data=df, x='feature1', y='feature2',
hue='category')
sns.regplot(data=df, x='feature1', y='target')
# カテゴリデータ
sns.countplot(data=df, x='category')
sns.barplot(data=df, x='category', y='value')
```

### 高度な視覚化

包括的なダッシュボードとレポートを作成します。

```python
# 複数のビューのためのサブプロット
fig, axes = plt.subplots(2, 2, figsize=(15, 10))
axes[0,0].hist(df['col1'])
axes[0,1].scatter(df['col1'], df['col2'])
axes[1,0].boxplot(df['col1'])
sns.heatmap(df.corr(), ax=axes[1,1])
# Plotly によるインタラクティブプロット
import plotly.express as px
fig = px.scatter(df, x='feature1', y='feature2',
                color='category', size='value',
                hover_data=['additional_info'])
fig.show()
```

### 統計プロット

統計的な関係とモデルの結果を視覚化します。

```python
# 相関のためのペアプロット
sns.pairplot(df, hue='target_category')
# 回帰のための残差プロット
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.scatter(y_pred, y_test - y_pred)
plt.xlabel('予測値')
plt.ylabel('残差')
plt.subplot(1, 2, 2)
plt.scatter(y_test, y_pred)
plt.plot([y_test.min(), y_test.max()], [y_test.min(),
y_test.max()], 'r--')
# 分類のための ROC 曲線
from sklearn.metrics import roc_curve, auc
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, label=f'ROC 曲線 (AUC = {roc_auc:.2f})')
```

### カスタマイズとスタイリング

プロフェッショナルな視覚化のフォーマット設定。

```python
# スタイルと色の設定
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
# カスタム図の設定
plt.figure(figsize=(12, 8))
plt.title('プロフェッショナルなグラフタイトル', fontsize=16,
fontweight='bold')
plt.xlabel('X 軸ラベル', fontsize=14)
plt.ylabel('Y 軸ラベル', fontsize=14)
plt.legend(loc='best')
plt.grid(True, alpha=0.3)
plt.tight_layout()
# 高品質なプロットの保存
plt.savefig('analysis_plot.png', dpi=300,
bbox_inches='tight')
```

## モデルデプロイと MLOps

### モデルの永続化

学習済みモデルを保存し、本番環境での使用のためにロードします。

```python
# pickle を使用したモデルの保存
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(trained_model, f)
# 保存されたモデルのロード
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
# sklearn モデルのための joblib の使用
import joblib
joblib.dump(trained_model, 'model.joblib')
loaded_model = joblib.load('model.joblib')
# タイムスタンプによるモデルのバージョン管理
import datetime
timestamp =
datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
model_name = f'model_{timestamp}.pkl'
```

### 交差検証とハイパーパラメータチューニング

モデルのパフォーマンスを最適化し、過学習を防ぎます。

```python
# 交差検証
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"CV精度: {cv_scores.mean():.3f} (+/-
{cv_scores.std() * 2:.3f})")
# ハイパーパラメータチューニングのためのグリッドサーチ
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

### パフォーマンス監視

重要な概念やコマンドにすぐにアクセスできることは、ワークフローにおいて大きな違いを生みます。初心者で足場を固めている場合でも、経験豊富な実務家が信頼できるリファレンスを探している場合でも、チートシートは非常に貴重な仲間となります。

```python
# モデルパフォーマンスの追跡
import time
start_time = time.time()
predictions = model.predict(X_test)
inference_time = time.time() - start_time
print(f"推論時間：{inference_time:.4f}秒")
# メモリ使用量の監視
import psutil
process = psutil.Process()
memory_usage = process.memory_info().rss / 1024 /
1024  # MB
print(f"メモリ使用量：{memory_usage:.2f} MB")
# 特徴量の重要度分析
feature_importance = model.feature_importances_
importance_df = pd.DataFrame({
    'feature': X.columns,
    'importance': feature_importance
}).sort_values('importance', ascending=False)
```

### モデルのドキュメント化

モデルの仮定、パフォーマンス、使用方法を文書化します。

```python
# モデルレポートの作成
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
# モデルメタデータの保存
import json
with open('model_metadata.json', 'w') as f:
    json.dump(model_report, f, indent=2)
```

## ベストプラクティスとヒント

### コードの整理

再現性と共同作業のためにプロジェクトを構成します。

```python
# プロジェクト構造
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
# git によるバージョン管理
git init
git add .
git commit -m "Initial data
science project setup"
```

### 環境管理

システム間で再現可能な環境を保証します。

```bash
# 仮想環境の作成
python -m venv ds_env
source ds_env/bin/activate  #
Linux/Mac
# ds_env\Scripts\activate   #
Windows
# requirements.txtファイル
pip freeze > requirements.txt
# Conda環境
conda create -n ds_project
python=3.9
conda activate ds_project
conda install pandas numpy
scikit-learn matplotlib seaborn
jupyter
```

### データ品質チェック

パイプライン全体でデータの整合性を検証します。

```python
# データ検証関数
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
# 自動データ品質レポート
def data_quality_report(df):
    print(f"データセットの形状:
{df.shape}")
    print(f"欠損値の数:
{df.isnull().sum().sum()}")
    print(f"重複行数:
{df.duplicated().sum()}")
    print("\n列のデータ型：")
    print(df.dtypes)
```

## 関連リンク

- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/pandas">Pandas チートシート</router-link>
- <router-link to="/numpy">NumPy チートシート</router-link>
- <router-link to="/matplotlib">Matplotlib チートシート</router-link>
- <router-link to="/sklearn">Scikit-learn チートシート</router-link>
- <router-link to="/database">データベース チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>

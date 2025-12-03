---
title: '数据科学速查表 | LabEx'
description: '使用本综合速查表学习数据科学。数据分析、机器学习、统计学、可视化、Python 库和数据科学工作流程的快速参考。'
pdfUrl: '/cheatsheets/pdf/data-science-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
数据科学速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/datascience">通过实践实验室学习数据科学</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习数据科学。LabEx 提供全面的数据科学课程，涵盖基本的 Python 库、数据操作、统计分析、机器学习和数据可视化。掌握数据收集、清洗、分析和模型部署技术。
</base-disclaimer-content>
</base-disclaimer>

## 核心 Python 库

### 核心数据科学栈

NumPy、Pandas、Matplotlib、Seaborn 和 scikit-learn 等关键库构成了数据科学工作流程的基础。

```python
# Essential imports for data science
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

用于 Python 数值计算的基础包。

```python
# Create arrays
arr = np.array([1, 2, 3, 4, 5])
matrix = np.array([[1, 2], [3, 4]])
# Basic operations
np.mean(arr)       # 平均值
np.std(arr)        # 标准差
np.reshape(arr, (5, 1))  # 重塑数组
# Generate data
np.random.normal(0, 1, 100)  # 随机正态分布
distribution
```

### Pandas: `import pandas as pd`

数据操作和分析库。

```python
# Create DataFrame
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
# Read data
df = pd.read_csv('data.csv')
# Basic exploration
df.head()          # 前 5 行
df.info()          # 数据类型和缺失值
df.describe()      # 摘要统计信息
# Data manipulation
df.groupby('column').mean()
df.fillna(df.mean())  # 处理缺失值
```

<BaseQuiz id="datascience-pandas-1" correct="C">
  <template #question>
    Pandas 中的 <code>df.head()</code> 返回什么？
  </template>
  
  <BaseQuizOption value="A">DataFrame 的最后 5 行</BaseQuizOption>
  <BaseQuizOption value="B">DataFrame 的摘要</BaseQuizOption>
  <BaseQuizOption value="C" correct>DataFrame 的前 5 行</BaseQuizOption>
  <BaseQuizOption value="D">DataFrame 的所有行</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>df.head()</code> 默认显示 DataFrame 的前 5 行。您可以指定不同的数字，例如 <code>df.head(10)</code> 查看前 10 行。它对于快速检查数据很有用。
  </BaseQuizAnswer>
</BaseQuiz>

### Matplotlib & Seaborn: 可视化

创建统计可视化和图表。

```python
# Matplotlib basics
plt.plot(x, y)
plt.hist(data, bins=20)
plt.scatter(x, y)
plt.show()
# Seaborn for statistical plots
sns.boxplot(data=df, x='category', y='value')
sns.heatmap(df.corr(), annot=True)
sns.pairplot(df)
```

## 数据科学工作流程

### 1. 问题定义

数据科学是一个多学科领域，结合了数学、统计学、编程和商业智能。定义目标和成功指标。

```python
# Define business problem
# - What question are we answering?
# - What metrics will measure
success?
# - What data do we need?
```

### 2. 数据收集与导入

从各种来源和格式收集数据。

```python
# Multiple data sources
df_csv = pd.read_csv('data.csv')
df_json = pd.read_json('data.json')
df_sql = pd.read_sql('SELECT * FROM
table', connection)
# APIs and web scraping
import requests
response =
requests.get('https://api.example.co
m/data')
```

### 3. 数据探索 (EDA)

了解数据结构、模式和质量。

```python
# Exploratory Data Analysis
df.shape              # 维度
df.dtypes             # 数据类型
df.isnull().sum()     # 缺失值
df['column'].value_counts()  #
频率计数
df.corr()             # 相关性矩阵
# Visualizations for EDA
sns.histplot(df['numeric_column'])
sns.boxplot(data=df,
y='numeric_column')
plt.figure(figsize=(10, 8))
sns.heatmap(df.corr(), annot=True)
```

## 数据清洗与预处理

### 处理缺失数据

在分析数据之前，必须对其进行清洗和准备。这包括处理缺失数据、删除重复项和标准化变量。数据清洗通常是数据科学过程中最耗时但最关键的方面。

```python
# Identify missing values
df.isnull().sum()
df.isnull().sum() / len(df) * 100  # 缺失百分比
# Handle missing values
df.dropna()                    # 删除含 NaN 的行
df.fillna(df.mean())          # 用均值填充
df.fillna(method='forward')   # 前向填充
df.fillna(method='backward')  # 后向填充
# Advanced imputation
from sklearn.impute import SimpleImputer, KNNImputer
imputer = SimpleImputer(strategy='median')
df_filled = pd.DataFrame(imputer.fit_transform(df))
```

<BaseQuiz id="datascience-missing-1" correct="B">
  <template #question>
    前向填充（<code>method='forward'</code>）用于什么？
  </template>
  
  <BaseQuizOption value="A">用均值填充缺失值</BaseQuizOption>
  <BaseQuizOption value="B" correct>用前一个非空值填充缺失值</BaseQuizOption>
  <BaseQuizOption value="C">用随机值填充缺失值</BaseQuizOption>
  <BaseQuizOption value="D">删除缺失值</BaseQuizOption>
  
  <BaseQuizAnswer>
    前向填充将上一个有效观测值向前传播以填充缺失值。这对于时间序列数据很有用，因为您希望在有新数据可用之前保持前一个值。
  </BaseQuizAnswer>
</BaseQuiz>

### 数据转换

数据归一化（将数据缩放到标准范围如 [0, 1]）有助于避免因特征幅度不同而导致的偏差。

```python
# Scaling and normalization
from sklearn.preprocessing import StandardScaler,
MinMaxScaler
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df[numeric_columns])
# Min-Max scaling to [0,1]
minmax = MinMaxScaler()
df_normalized =
minmax.fit_transform(df[numeric_columns])
# Encoding categorical variables
pd.get_dummies(df, columns=['category_column'])
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
df['encoded'] = le.fit_transform(df['category'])
```

<BaseQuiz id="datascience-scaling-1" correct="C">
  <template #question>
    StandardScaler 和 MinMaxScaler 有什么区别？
  </template>
  
  <BaseQuizOption value="A">没有区别</BaseQuizOption>
  <BaseQuizOption value="B">StandardScaler 缩放到 [0,1]，MinMaxScaler 缩放到均值为 0、标准差为 1</BaseQuizOption>
  <BaseQuizOption value="C" correct>StandardScaler 归一化到均值为 0、标准差为 1，MinMaxScaler 缩放到 [0,1] 范围</BaseQuizOption>
  <BaseQuizOption value="D">StandardScaler 更快</BaseQuizOption>
  
  <BaseQuizAnswer>
    StandardScaler 将数据转换为均值为 0、标准差为 1（Z-分数归一化）。MinMaxScaler 将数据缩放到固定范围，通常是 [0, 1]。两者都很有用，但适用于不同的场景。
  </BaseQuizAnswer>
</BaseQuiz>

### 异常值检测与处理

识别并处理可能影响分析的极端值。

```python
# Statistical outlier detection
Q1 = df['column'].quantile(0.25)
Q3 = df['column'].quantile(0.75)
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR
# Remove outliers
df_clean = df[(df['column'] >= lower_bound) &
              (df['column'] <= upper_bound)]
# Z-score method
from scipy import stats
z_scores = np.abs(stats.zscore(df['column']))
df_no_outliers = df[z_scores < 3]
```

### 特征工程

创建新变量以提高模型性能。

```python
# Create new features
df['feature_ratio'] = df['feature1'] / df['feature2']
df['feature_sum'] = df['feature1'] + df['feature2']
# Date/time features
df['date'] = pd.to_datetime(df['date'])
df['year'] = df['date'].dt.year
df['month'] = df['date'].dt.month
df['day_of_week'] = df['date'].dt.day_name()
# Binning continuous variables
df['age_group'] = pd.cut(df['age'], bins=[0, 18, 35, 50, 100],
                        labels=['Child', 'Young Adult', 'Adult',
'Senior'])
```

## 统计分析

### 描述性统计

这些集中趋势的度量总结了数据并提供了对其分布的洞察。它们是理解任何数据集的基础。均值是数据集中所有值的平均值。它对异常值非常敏感。

```python
# Central tendency
mean = df['column'].mean()
median = df['column'].median()
mode = df['column'].mode()[0]
# Variability measures
std_dev = df['column'].std()
variance = df['column'].var()
range_val = df['column'].max() - df['column'].min()
# Distribution shape
skewness = df['column'].skew()
kurtosis = df['column'].kurtosis()
# Percentiles
percentiles = df['column'].quantile([0.25, 0.5, 0.75, 0.95])
```

### 假设检验

检验统计假设并验证前提。

```python
# T-test for comparing means
from scipy.stats import ttest_ind, ttest_1samp
# One-sample t-test
t_stat, p_value = ttest_1samp(data, population_mean)
# Two-sample t-test
group1 = df[df['group'] == 'A']['value']
group2 = df[df['group'] == 'B']['value']
t_stat, p_value = ttest_ind(group1, group2)
# Chi-square test for independence
from scipy.stats import chi2_contingency
chi2, p_value, dof, expected =
chi2_contingency(contingency_table)
```

### 相关性分析

了解变量之间的关系。

```python
# Correlation matrix
correlation_matrix = df.corr()
plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix, annot=True,
cmap='coolwarm')
# Specific correlations
pearson_corr = df['var1'].corr(df['var2'])
spearman_corr = df['var1'].corr(df['var2'],
method='spearman')
# Statistical significance of correlation
from scipy.stats import pearsonr
correlation, p_value = pearsonr(df['var1'], df['var2'])
```

### 方差分析 (ANOVA) 和回归

分析方差和变量之间的关系。

```python
# One-way ANOVA
from scipy.stats import f_oneway
group_data = [df[df['group'] == g]['value'] for g in
df['group'].unique()]
f_stat, p_value = f_oneway(*group_data)
# Linear regression analysis
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score
X = df[['feature1', 'feature2']]
y = df['target']
model = LinearRegression().fit(X, y)
y_pred = model.predict(X)
r2 = r2_score(y, y_pred)
```

## 机器学习模型

### 监督学习 - 分类

决策树：一个关于决策及其可能后果的树状模型。每个节点代表对一个属性的测试，每个分支代表一个结果。它通常用于分类任务。

```python
# Train-test split
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y,
test_size=0.2, random_state=42)
# Logistic Regression
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression()
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
# Decision Tree
from sklearn.tree import DecisionTreeClassifier
dt = DecisionTreeClassifier(max_depth=5)
dt.fit(X_train, y_train)
# Random Forest
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=100)
rf.fit(X_train, y_train)
```

### 监督学习 - 回归

预测连续的目标变量。

```python
# Linear Regression
from sklearn.linear_model import LinearRegression
lr = LinearRegression()
lr.fit(X_train, y_train)
y_pred = lr.predict(X_test)
# Polynomial Regression
from sklearn.preprocessing import PolynomialFeatures
poly = PolynomialFeatures(degree=2)
X_poly = poly.fit_transform(X)
# Ridge & Lasso Regression
from sklearn.linear_model import Ridge, Lasso
ridge = Ridge(alpha=1.0)
lasso = Lasso(alpha=0.1)
ridge.fit(X_train, y_train)
lasso.fit(X_train, y_train)
```

### 无监督学习

在没有标签结果的情况下发现数据中的模式。

```python
# K-Means Clustering
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
clusters = kmeans.fit_predict(X)
df['cluster'] = clusters
# Principal Component Analysis (PCA)
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)
# Hierarchical Clustering
from scipy.cluster.hierarchy import dendrogram, linkage
linkage_matrix = linkage(X_scaled, method='ward')
dendrogram(linkage_matrix)
```

### 模型评估

使用适当的指标评估模型性能。

```python
# Classification metrics
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score, confusion_matrix
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d')
# Regression metrics
from sklearn.metrics import mean_squared_error,
mean_absolute_error
mse = mean_squared_error(y_test, y_pred)
mae = mean_absolute_error(y_test, y_pred)
rmse = np.sqrt(mse)
```

## 数据可视化

### 探索性可视化

了解数据分布和关系。

```python
# Distribution plots
plt.figure(figsize=(12, 4))
plt.subplot(1, 3, 1)
plt.hist(df['numeric_col'], bins=20, edgecolor='black')
plt.subplot(1, 3, 2)
sns.boxplot(y=df['numeric_col'])
plt.subplot(1, 3, 3)
sns.violinplot(y=df['numeric_col'])
# Relationship plots
plt.figure(figsize=(10, 6))
sns.scatterplot(data=df, x='feature1', y='feature2',
hue='category')
sns.regplot(data=df, x='feature1', y='target')
# Categorical data
sns.countplot(data=df, x='category')
sns.barplot(data=df, x='category', y='value')
```

### 高级可视化

创建全面的仪表板和报告。

```python
# Subplots for multiple views
fig, axes = plt.subplots(2, 2, figsize=(15, 10))
axes[0,0].hist(df['col1'])
axes[0,1].scatter(df['col1'], df['col2'])
axes[1,0].boxplot(df['col1'])
sns.heatmap(df.corr(), ax=axes[1,1])
# Interactive plots with Plotly
import plotly.express as px
fig = px.scatter(df, x='feature1', y='feature2',
                color='category', size='value',
                hover_data=['additional_info'])
fig.show()
```

### 统计图表

可视化统计关系和模型结果。

```python
# Pair plots for correlation
sns.pairplot(df, hue='target_category')
# Residual plots for regression
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.scatter(y_pred, y_test - y_pred)
plt.xlabel('Predicted')
plt.ylabel('Residuals')
plt.subplot(1, 2, 2)
plt.scatter(y_test, y_pred)
plt.plot([y_test.min(), y_test.max()], [y_test.min(),
y_test.max()], 'r--')
# ROC Curve for classification
from sklearn.metrics import roc_curve, auc
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc:.2f})')
```

### 自定义与样式

专业的视觉格式化。

```python
# Set style and colors
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
# Custom figure settings
plt.figure(figsize=(12, 8))
plt.title('专业图表标题', fontsize=16,
fontweight='bold')
plt.xlabel('X 轴标签', fontsize=14)
plt.ylabel('Y 轴标签', fontsize=14)
plt.legend(loc='best')
plt.grid(True, alpha=0.3)
plt.tight_layout()
# Save high-quality plots
plt.savefig('analysis_plot.png', dpi=300,
bbox_inches='tight')
```

## 模型部署与 MLOps

### 模型持久化

保存和加载训练好的模型以供生产使用。

```python
# Save models with pickle
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(trained_model, f)
# Load saved model
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
# Using joblib for sklearn models
import joblib
joblib.dump(trained_model, 'model.joblib')
loaded_model = joblib.load('model.joblib')
# Model versioning with timestamps
import datetime
timestamp =
datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
model_name = f'model_{timestamp}.pkl'
```

### 交叉验证与超参数调优

优化模型性能并防止过拟合。

```python
# Cross-validation
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"CV Accuracy: {cv_scores.mean():.3f} (+/-
{cv_scores.std() * 2:.3f})")
# Grid Search for hyperparameter tuning
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

### 性能监控

快速访问基本概念和命令可以在工作流程中起到关键作用。无论您是初学者还是经验丰富的从业者，都在寻找可靠的参考，速查表都是无价的伴侣。

```python
# Model performance tracking
import time
start_time = time.time()
predictions = model.predict(X_test)
inference_time = time.time() - start_time
print(f"Inference time: {inference_time:.4f} seconds")
# Memory usage monitoring
import psutil
process = psutil.Process()
memory_usage = process.memory_info().rss / 1024 /
1024  # MB
print(f"Memory usage: {memory_usage:.2f} MB")
# Feature importance analysis
feature_importance = model.feature_importances_
importance_df = pd.DataFrame({
    'feature': X.columns,
    'importance': feature_importance
}).sort_values('importance', ascending=False)
```

### 模型文档

记录模型的假设、性能和用法。

```python
# Create model report
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
# Save model metadata
import json
with open('model_metadata.json', 'w') as f:
    json.dump(model_report, f, indent=2)
```

## 最佳实践与技巧

### 代码组织

为可重现性和协作组织项目。

```python
# Project structure
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
# Version control with git
git init
git add .
git commit -m "Initial data
science project setup"
```

### 环境管理

确保跨系统的环境可重现性。

```bash
# Create virtual environment
python -m venv ds_env
source ds_env/bin/activate  #
Linux/Mac
# ds_env\Scripts\activate   #
Windows
# Requirements file
pip freeze > requirements.txt
# Conda environment
conda create -n ds_project
python=3.9
conda activate ds_project
conda install pandas numpy
scikit-learn matplotlib seaborn
jupyter
```

### 数据质量检查

在整个管道中验证数据完整性。

```python
# Data validation functions
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
# Automated data quality report
def data_quality_report(df):
    print(f"数据集形状:
{df.shape}")
    print(f"缺失值数量:
{df.isnull().sum().sum()}")
    print(f"重复行数:
{df.duplicated().sum()}")
    print("\n列数据类型：")
    print(df.dtypes)
```

## 相关链接

- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/pandas">Pandas 速查表</router-link>
- <router-link to="/numpy">NumPy 速查表</router-link>
- <router-link to="/matplotlib">Matplotlib 速查表</router-link>
- <router-link to="/sklearn">Scikit-learn 速查表</router-link>
- <router-link to="/database">数据库速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>

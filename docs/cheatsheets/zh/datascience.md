---
title: '数据科学速查表'
description: '使用我们涵盖核心命令、概念和最佳实践的综合速查表，快速掌握数据科学。'
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
通过实践实验室和真实世界场景学习数据科学。LabEx 提供全面的数据科学课程，涵盖基本的 Python 库、数据操作、统计分析、机器学习和数据可视化。掌握数据收集、清洗、分析和模型部署技术。
</base-disclaimer-content>
</base-disclaimer>

## 核心 Python 库

### 核心数据科学栈

像 NumPy、Pandas、Matplotlib、Seaborn 和 scikit-learn 这样的关键库构成了数据科学工作流程的基础。

```python
# 数据科学的基本导入
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

用于 Python 数值计算的基本包。

```python
# 创建数组
arr = np.array([1, 2, 3, 4, 5])
matrix = np.array([[1, 2], [3, 4]])
# 基本操作
np.mean(arr)       # 平均值
np.std(arr)        # 标准差
np.reshape(arr, (5, 1))  # 重塑数组
# 生成数据
np.random.normal(0, 1, 100)  # 随机正态分布
```

### Pandas: `import pandas as pd`

数据操作和分析库。

```python
# 创建 DataFrame
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
# 读取数据
df = pd.read_csv('data.csv')
# 基本探索
df.head()          # 前 5 行
df.info()          # 数据类型和缺失值
df.describe()      # 汇总统计信息
# 数据操作
df.groupby('column').mean()
df.fillna(df.mean())  # 处理缺失值
```

### Matplotlib & Seaborn: 可视化

创建统计可视化和图表。

```python
# Matplotlib 基础
plt.plot(x, y)
plt.hist(data, bins=20)
plt.scatter(x, y)
plt.show()
# Seaborn 用于统计图表
sns.boxplot(data=df, x='category', y='value')
sns.heatmap(df.corr(), annot=True)
sns.pairplot(df)
```

## 数据科学工作流程

### 1. 问题定义

数据科学是一个多学科领域，结合了数学、统计学、编程和商业智能。定义目标和成功指标。

```python
# 定义业务问题
# - 我们在回答什么问题？
# - 哪些指标衡量成功？
# - 我们需要哪些数据？
```

### 2. 数据收集与导入

从各种来源和格式收集数据。

```python
# 多数据源
df_csv = pd.read_csv('data.csv')
df_json = pd.read_json('data.json')
df_sql = pd.read_sql('SELECT * FROM
table', connection)
# API 和网络抓取
import requests
response =
requests.get('https://api.example.co
m/data')
```

### 3. 数据探索 (EDA)

了解数据结构、模式和质量。

```python
# 探索性数据分析
df.shape              # 维度
df.dtypes             # 数据类型
df.isnull().sum()     # 缺失值
df['column'].value_counts()  #
频率计数
df.corr()             # 相关性矩阵
# EDA 可视化
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
# 识别缺失值
df.isnull().sum()
df.isnull().sum() / len(df) * 100  # 缺失百分比
# 处理缺失值
df.dropna()                    # 删除含 NaN 的行
df.fillna(df.mean())          # 用平均值填充
df.fillna(method='forward')   # 前向填充
df.fillna(method='backward')  # 后向填充
# 高级插补
from sklearn.impute import SimpleImputer, KNNImputer
imputer = SimpleImputer(strategy='median')
df_filled = pd.DataFrame(imputer.fit_transform(df))
```

### 数据转换

数据归一化（将数据缩放到标准范围如 [0, 1]）有助于避免因特征幅度差异造成的偏差。

```python
# 缩放和归一化
from sklearn.preprocessing import StandardScaler,
MinMaxScaler
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df[numeric_columns])
# Min-Max 缩放到 [0,1]
minmax = MinMaxScaler()
df_normalized =
minmax.fit_transform(df[numeric_columns])
# 编码分类变量
pd.get_dummies(df, columns=['category_column'])
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
df['encoded'] = le.fit_transform(df['category'])
```

### 异常值检测与处理

识别并处理可能影响分析的极端值。

```python
# 统计异常值检测
Q1 = df['column'].quantile(0.25)
Q3 = df['column'].quantile(0.75)
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR
# 删除异常值
df_clean = df[(df['column'] >= lower_bound) &
              (df['column'] <= upper_bound)]
# Z-score 方法
from scipy import stats
z_scores = np.abs(stats.zscore(df['column']))
df_no_outliers = df[z_scores < 3]
```

### 特征工程

创建新变量以提高模型性能。

```python
# 创建新特征
df['feature_ratio'] = df['feature1'] / df['feature2']
df['feature_sum'] = df['feature1'] + df['feature2']
# 日期/时间特征
df['date'] = pd.to_datetime(df['date'])
df['year'] = df['date'].dt.year
df['month'] = df['date'].dt.month
df['day_of_week'] = df['date'].dt.day_name()
# 分箱连续变量
df['age_group'] = pd.cut(df['age'], bins=[0, 18, 35, 50, 100],
                        labels=['Child', 'Young Adult', 'Adult',
'Senior'])
```

## 统计分析

### 描述性统计

这些集中趋势的度量总结了数据并提供了对其分布的洞察。它们是理解任何数据集的基础。平均值是数据集中所有值的平均数。它对异常值非常敏感。

```python
# 集中趋势
mean = df['column'].mean()
median = df['column'].median()
mode = df['column'].mode()[0]
# 变异性度量
std_dev = df['column'].std()
variance = df['column'].var()
range_val = df['column'].max() - df['column'].min()
# 分布形状
skewness = df['column'].skew()
kurtosis = df['column'].kurtosis()
# 分位数
percentiles = df['column'].quantile([0.25, 0.5, 0.75, 0.95])
```

### 假设检验

检验统计假设并验证假设。

```python
# T 检验用于比较均值
from scipy.stats import ttest_ind, ttest_1samp
# 单样本 t 检验
t_stat, p_value = ttest_1samp(data, population_mean)
# 双样本 t 检验
group1 = df[df['group'] == 'A']['value']
group2 = df[df['group'] == 'B']['value']
t_stat, p_value = ttest_ind(group1, group2)
# 卡方检验独立性
from scipy.stats import chi2_contingency
chi2, p_value, dof, expected =
chi2_contingency(contingency_table)
```

### 相关性分析

了解变量之间的关系。

```python
# 相关性矩阵
correlation_matrix = df.corr()
plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix, annot=True,
cmap='coolwarm')
# 特定相关性
pearson_corr = df['var1'].corr(df['var2'])
spearman_corr = df['var1'].corr(df['var2'],
method='spearman')
# 相关性的统计显著性
from scipy.stats import pearsonr
correlation, p_value = pearsonr(df['var1'], df['var2'])
```

### 方差分析 (ANOVA) 和回归

分析变量间的方差和关系。

```python
# 单因素方差分析
from scipy.stats import f_oneway
group_data = [df[df['group'] == g]['value'] for g in
df['group'].unique()]
f_stat, p_value = f_oneway(*group_data)
# 线性回归分析
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

决策树：一个关于决策及其可能结果的树状模型。每个节点代表对一个属性的测试，每个分支代表一个结果。它常用于分类任务。

```python
# 训练 - 测试分割
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y,
test_size=0.2, random_state=42)
# 逻辑回归
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression()
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
# 决策树
from sklearn.tree import DecisionTreeClassifier
dt = DecisionTreeClassifier(max_depth=5)
dt.fit(X_train, y_train)
# 随机森林
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=100)
rf.fit(X_train, y_train)
```

### 监督学习 - 回归

预测连续的目标变量。

```python
# 线性回归
from sklearn.linear_model import LinearRegression
lr = LinearRegression()
lr.fit(X_train, y_train)
y_pred = lr.predict(X_test)
# 多项式回归
from sklearn.preprocessing import PolynomialFeatures
poly = PolynomialFeatures(degree=2)
X_poly = poly.fit_transform(X)
# Ridge 和 Lasso 回归
from sklearn.linear_model import Ridge, Lasso
ridge = Ridge(alpha=1.0)
lasso = Lasso(alpha=0.1)
ridge.fit(X_train, y_train)
lasso.fit(X_train, y_train)
```

### 无监督学习

在没有标签结果的情况下发现数据中的模式。

```python
# K-均值聚类
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
clusters = kmeans.fit_predict(X)
df['cluster'] = clusters
# 主成分分析 (PCA)
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)
# 层次聚类
from scipy.cluster.hierarchy import dendrogram, linkage
linkage_matrix = linkage(X_scaled, method='ward')
dendrogram(linkage_matrix)
```

### 模型评估

使用适当的指标评估模型性能。

```python
# 分类指标
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score, confusion_matrix
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# 混淆矩阵
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d')
# 回归指标
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
# 分布图
plt.figure(figsize=(12, 4))
plt.subplot(1, 3, 1)
plt.hist(df['numeric_col'], bins=20, edgecolor='black')
plt.subplot(1, 3, 2)
sns.boxplot(y=df['numeric_col'])
plt.subplot(1, 3, 3)
sns.violinplot(y=df['numeric_col'])
# 关系图
plt.figure(figsize=(10, 6))
sns.scatterplot(data=df, x='feature1', y='feature2',
hue='category')
sns.regplot(data=df, x='feature1', y='target')
# 分类数据
sns.countplot(data=df, x='category')
sns.barplot(data=df, x='category', y='value')
```

### 高级可视化

创建综合仪表板和报告。

```python
# 子图用于多个视图
fig, axes = plt.subplots(2, 2, figsize=(15, 10))
axes[0,0].hist(df['col1'])
axes[0,1].scatter(df['col1'], df['col2'])
axes[1,0].boxplot(df['col1'])
sns.heatmap(df.corr(), ax=axes[1,1])
# 使用 Plotly 进行交互式绘图
import plotly.express as px
fig = px.scatter(df, x='feature1', y='feature2',
                color='category', size='value',
                hover_data=['additional_info'])
fig.show()
```

### 统计图表

可视化统计关系和模型结果。

```python
# 相关性配对图
sns.pairplot(df, hue='target_category')
# 回归残差图
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.scatter(y_pred, y_test - y_pred)
plt.xlabel('预测值')
plt.ylabel('残差')
plt.subplot(1, 2, 2)
plt.scatter(y_test, y_pred)
plt.plot([y_test.min(), y_test.max()], [y_test.min(),
y_test.max()], 'r--')
# 分类 ROC 曲线
from sklearn.metrics import roc_curve, auc
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, label=f'ROC 曲线 (AUC = {roc_auc:.2f})')
```

### 定制和样式设置

专业的视觉格式。

```python
# 设置样式和颜色
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
# 自定义图形设置
plt.figure(figsize=(12, 8))
plt.title('专业图表标题', fontsize=16,
fontweight='bold')
plt.xlabel('X 轴标签', fontsize=14)
plt.ylabel('Y 轴标签', fontsize=14)
plt.legend(loc='best')
plt.grid(True, alpha=0.3)
plt.tight_layout()
# 保存高质量图表
plt.savefig('analysis_plot.png', dpi=300,
bbox_inches='tight')
```

## 模型部署与 MLOps

### 模型持久化

保存和加载训练好的模型以供生产使用。

```python
# 使用 pickle 保存模型
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(trained_model, f)
# 加载已保存的模型
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
# 使用 joblib 处理 sklearn 模型
import joblib
joblib.dump(trained_model, 'model.joblib')
loaded_model = joblib.load('model.joblib')
# 使用时间戳进行模型版本控制
import datetime
timestamp =
datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
model_name = f'model_{timestamp}.pkl'
```

### 交叉验证与超参数调优

优化模型性能并防止过拟合。

```python
# 交叉验证
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"CV 准确率: {cv_scores.mean():.3f} (+/-
{cv_scores.std() * 2:.3f})")
# 超参数调优的网格搜索
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

快速访问基本概念和命令可以在您的工作流程中发挥重要作用。无论您是初学者还是经验丰富的从业者，寻求可靠的参考，备忘单都是宝贵的伴侣。

```python
# 模型性能跟踪
import time
start_time = time.time()
predictions = model.predict(X_test)
inference_time = time.time() - start_time
print(f"推理时间：{inference_time:.4f} 秒")
# 内存使用情况监控
import psutil
process = psutil.Process()
memory_usage = process.memory_info().rss / 1024 /
1024  # MB
print(f"内存使用：{memory_usage:.2f} MB")
# 特征重要性分析
feature_importance = model.feature_importances_
importance_df = pd.DataFrame({
    'feature': X.columns,
    'importance': feature_importance
}).sort_values('importance', ascending=False)
```

### 模型文档

记录模型的假设、性能和用法。

```python
# 创建模型报告
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
# 保存模型元数据
import json
with open('model_metadata.json', 'w') as f:
    json.dump(model_report, f, indent=2)
```

## 最佳实践与技巧

### 代码组织

为可重现性和协作组织项目。

```python
# 项目结构
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
# 使用 git 进行版本控制
git init
git add .
git commit -m "Initial data
science project setup"
```

### 环境管理

确保跨系统可重现的环境。

```bash
# 创建虚拟环境
python -m venv ds_env
source ds_env/bin/activate  #
Linux/Mac
# ds_env\Scripts\activate   #
Windows
# 需求文件
pip freeze > requirements.txt
# Conda 环境
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
# 数据验证函数
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
# 自动数据质量报告
def data_quality_report(df):
    print(f"数据集形状:
{df.shape}")
    print(f"缺失值:
{df.isnull().sum().sum()}")
    print(f"重复行:
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

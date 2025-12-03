---
title: 'scikit-learn 速查表 | LabEx'
description: '使用这份全面的速查表学习 scikit-learn 机器学习。快速参考 ML 算法、模型训练、预处理、评估和 Python 机器学习工作流程。'
pdfUrl: '/cheatsheets/pdf/sklearn-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
scikit-learn 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/sklearn">通过实践实验室学习 scikit-learn</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 scikit-learn 机器学习。LabEx 提供全面的 scikit-learn 课程，涵盖基本的数据预处理、模型选择、训练、评估和特征工程。使用 Python 掌握机器学习算法并构建预测模型。
</base-disclaimer-content>
</base-disclaimer>

## 安装与导入

### 安装：`pip install scikit-learn`

安装 scikit-learn 和常用依赖项。

```bash
# 安装 scikit-learn
pip install scikit-learn
# 安装附加包
pip install scikit-learn pandas numpy matplotlib
# 升级到最新版本
pip install scikit-learn --upgrade
```

### 核心导入

scikit-learn 工作流程的标准导入。

```python
# 核心导入
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,
classification_report
# 常用算法
from sklearn.linear_model import LinearRegression,
LogisticRegression
from sklearn.ensemble import RandomForestClassifier,
GradientBoostingRegressor
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
```

### 检查版本

验证您的 scikit-learn 安装。

```python
import sklearn
print(sklearn.__version__)
# 显示构建配置
sklearn.show_versions()
```

### 数据集加载

加载内置数据集以供练习。

```python
from sklearn.datasets import load_iris, load_boston,
make_classification
# 加载样本数据集
iris = load_iris()
X, y = iris.data, iris.target
# 生成合成数据
X_synth, y_synth = make_classification(n_samples=1000,
n_features=20, n_informative=10, random_state=42)
```

## 数据预处理

### 训练 - 测试集划分：`train_test_split()`

将数据划分为训练集和测试集。

```python
# 基本划分 (80% 训练，20% 测试)
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
random_state=42)
# 分类分层划分
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
stratify=y, random_state=42)
# 多次划分
X_train, X_temp, y_train, y_temp =
train_test_split(X, y, test_size=0.4,
random_state=42)
X_val, X_test, y_val, y_test =
train_test_split(X_temp, y_temp,
test_size=0.5, random_state=42)
```

<BaseQuiz id="sklearn-split-1" correct="B">
  <template #question>
    为什么将数据划分为训练集和测试集很重要？
  </template>
  
  <BaseQuizOption value="A">为了减小数据集大小</BaseQuizOption>
  <BaseQuizOption value="B" correct>为了在未见过的数据上评估模型性能并防止过拟合</BaseQuizOption>
  <BaseQuizOption value="C">为了加快模型训练速度</BaseQuizOption>
  <BaseQuizOption value="D">为了平衡数据集</BaseQuizOption>
  
  <BaseQuizAnswer>
    数据划分允许您在一部分数据上训练模型，在另一部分数据上进行测试。这有助于评估模型泛化到新、未见过数据的能力，并防止模型过拟合训练数据。
  </BaseQuizAnswer>
</BaseQuiz>

### 特征缩放：`StandardScaler()` / `MinMaxScaler()`

将特征归一化到相似的尺度。

```python
# 标准化 (均值=0, 标准差=1)
from sklearn.preprocessing import
StandardScaler, MinMaxScaler
scaler = StandardScaler()
X_scaled =
scaler.fit_transform(X_train)
X_test_scaled =
scaler.transform(X_test)
# Min-Max 缩放 (0-1 范围)
minmax_scaler = MinMaxScaler()
X_minmax =
minmax_scaler.fit_transform(X_train)
X_test_minmax =
minmax_scaler.transform(X_test)
```

<BaseQuiz id="sklearn-scaling-1" correct="A">
  <template #question>
    为什么特征缩放在机器学习中很重要？
  </template>
  
  <BaseQuizOption value="A" correct>它确保所有特征处于相似的尺度，防止某些特征占据主导地位</BaseQuizOption>
  <BaseQuizOption value="B">它会移除缺失值</BaseQuizOption>
  <BaseQuizOption value="C">它会增加特征的数量</BaseQuizOption>
  <BaseQuizOption value="D">它会移除重复的行</BaseQuizOption>
  
  <BaseQuizAnswer>
    特征缩放很重要，因为像 SVM、KNN 和神经网络这样的算法对特征尺度很敏感。如果没有缩放，范围较大的特征可能会主导模型的学习过程。
  </BaseQuizAnswer>
</BaseQuiz>

### 编码：`LabelEncoder()` / `OneHotEncoder()`

将分类变量转换为数值格式。

```python
# 目标变量的标签编码
from sklearn.preprocessing import
LabelEncoder, OneHotEncoder
label_encoder = LabelEncoder()
y_encoded =
label_encoder.fit_transform(y)
# 分类特征的独热编码
from sklearn.preprocessing import
OneHotEncoder
encoder =
OneHotEncoder(sparse=False,
drop='first')
X_encoded =
encoder.fit_transform(X_categorical)
# 获取特征名称
feature_names =
encoder.get_feature_names_out()
```

## 监督学习 - 分类

### 逻辑回归：`LogisticRegression()`

用于二元和多类别分类的线性模型。

```python
# 基本逻辑回归
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression(random_state=42)
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
y_proba = log_reg.predict_proba(X_test)
# 带正则化
log_reg_l2 = LogisticRegression(C=0.1, penalty='l2')
log_reg_l1 = LogisticRegression(C=0.1, penalty='l1',
solver='liblinear')
```

### 决策树：`DecisionTreeClassifier()`

用于分类任务的基于树的模型。

```python
# 决策树分类器
from sklearn.tree import DecisionTreeClassifier
tree_clf = DecisionTreeClassifier(max_depth=5,
random_state=42)
tree_clf.fit(X_train, y_train)
y_pred = tree_clf.predict(X_test)
# 特征重要性
importances = tree_clf.feature_importances_
# 可视化树
from sklearn.tree import plot_tree
plot_tree(tree_clf, max_depth=3, filled=True)
```

### 随机森林：`RandomForestClassifier()`

结合多个决策树的集成方法。

```python
# 随机森林分类器
from sklearn.ensemble import RandomForestClassifier
rf_clf = RandomForestClassifier(n_estimators=100,
random_state=42)
rf_clf.fit(X_train, y_train)
y_pred = rf_clf.predict(X_test)
# 超参数调优
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
    <code>RandomForestClassifier</code> 中的 <code>n_estimators</code> 控制什么？
  </template>
  
  <BaseQuizOption value="A" correct>森林中决策树的数量</BaseQuizOption>
  <BaseQuizOption value="B">每棵树的最大深度</BaseQuizOption>
  <BaseQuizOption value="C">要考虑的特征数量</BaseQuizOption>
  <BaseQuizOption value="D">随机种子</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>n_estimators</code> 指定随机森林中包含多少棵决策树。更多的树通常会提高性能，但会增加计算时间。默认值通常是 100。
  </BaseQuizAnswer>
</BaseQuiz>

### 支持向量机：`SVC()`

使用核方法的强大分类器。

```python
# SVM 分类器
from sklearn.svm import SVC
svm_clf = SVC(kernel='rbf', C=1.0, gamma='scale',
random_state=42)
svm_clf.fit(X_train, y_train)
y_pred = svm_clf.predict(X_test)
# 不同核函数
svm_linear = SVC(kernel='linear')
svm_poly = SVC(kernel='poly', degree=3)
svm_rbf = SVC(kernel='rbf', gamma=0.1)
```

## 监督学习 - 回归

### 线性回归：`LinearRegression()`

用于连续目标变量的基本线性模型。

```python
# 简单线性回归
from sklearn.linear_model import LinearRegression
lin_reg = LinearRegression()
lin_reg.fit(X_train, y_train)
y_pred = lin_reg.predict(X_test)
# 获取系数和截距
coefficients = lin_reg.coef_
intercept = lin_reg.intercept_
print(f"R² 分数：{lin_reg.score(X_test, y_test)}")
```

### 岭回归：`Ridge()`

带有 L2 正则化的线性回归。

```python
# 岭回归 (L2 正则化)
from sklearn.linear_model import Ridge
ridge_reg = Ridge(alpha=1.0)
ridge_reg.fit(X_train, y_train)
y_pred = ridge_reg.predict(X_test)
# 使用交叉验证选择 alpha
from sklearn.linear_model import RidgeCV
ridge_cv = RidgeCV(alphas=[0.1, 1.0, 10.0])
ridge_cv.fit(X_train, y_train)
```

### Lasso 回归：`Lasso()`

带有 L1 正则化的线性回归，用于特征选择。

```python
# Lasso 回归 (L1 正则化)
from sklearn.linear_model import Lasso
lasso_reg = Lasso(alpha=0.1)
lasso_reg.fit(X_train, y_train)
y_pred = lasso_reg.predict(X_test)
# 特征选择 (非零系数)
selected_features = X.columns[lasso_reg.coef_ != 0]
print(f"选择的特征数量：{len(selected_features)}")
```

### 随机森林回归：`RandomForestRegressor()`

用于回归任务的集成方法。

```python
# 随机森林回归器
from sklearn.ensemble import RandomForestRegressor
rf_reg = RandomForestRegressor(n_estimators=100,
random_state=42)
rf_reg.fit(X_train, y_train)
y_pred = rf_reg.predict(X_test)
# 回归的特征重要性
feature_importance = rf_reg.feature_importances_
```

## 模型评估

### 分类指标

评估分类模型的性能。

```python
# 基本准确率
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# 详细分类报告
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred))
# 混淆矩阵
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
```

### ROC 曲线与 AUC

绘制 ROC 曲线并计算曲线下面积。

```python
# 二分类的 ROC 曲线
from sklearn.metrics import roc_curve, auc
fpr, tpr, thresholds = roc_curve(y_test, y_proba[:, 1])
roc_auc = auc(fpr, tpr)
# 绘制 ROC 曲线
import matplotlib.pyplot as plt
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, label=f'ROC 曲线 (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel('假阳性率')
plt.ylabel('真阳性率')
plt.legend()
```

### 回归指标

评估回归模型的性能。

```python
# 回归指标
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

### 交叉验证

使用交叉验证进行稳健的模型评估。

```python
# K 折交叉验证
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"CV 准确率: {cv_scores.mean():.4f} (+/-
{cv_scores.std() * 2:.4f})")
# 分层 K 折用于不平衡数据集
skf = StratifiedKFold(n_splits=5, shuffle=True,
random_state=42)
cv_scores = cross_val_score(model, X, y, cv=skf,
scoring='f1_weighted')
```

## 无监督学习

### K-均值聚类：`KMeans()`

将数据划分为 k 个簇。

```python
# K-均值聚类
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
cluster_labels = kmeans.fit_predict(X)
centroids = kmeans.cluster_centers_
# 确定最佳簇数 (肘部法则)
inertias = []
K_range = range(1, 11)
for k in K_range:
    kmeans = KMeans(n_clusters=k, random_state=42)
    kmeans.fit(X)
    inertias.append(kmeans.inertia_)
```

### 主成分分析：`PCA()`

降维技术。

```python
# PCA 用于降维
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)
explained_variance = pca.explained_variance_ratio_
# 查找最佳分量数
pca_full = PCA()
pca_full.fit(X)
cumsum =
np.cumsum(pca_full.explained_variance_ratio_)
# 查找解释 95% 方差的分量数
n_components = np.argmax(cumsum >= 0.95) + 1
```

### DBSCAN 聚类：`DBSCAN()`

基于密度的聚类算法。

```python
# DBSCAN 聚类
from sklearn.cluster import DBSCAN
dbscan = DBSCAN(eps=0.5, min_samples=5)
cluster_labels = dbscan.fit_predict(X)
n_clusters = len(set(cluster_labels)) - (1 if -1 in
cluster_labels else 0)
n_noise = list(cluster_labels).count(-1)
print(f"簇的数量：{n_clusters}")
print(f"噪声点的数量：{n_noise}")
```

### 层次聚类：`AgglomerativeClustering()`

构建簇的层次结构。

```python
# 层次聚类
from sklearn.cluster import AgglomerativeClustering
agg_clustering = AgglomerativeClustering(n_clusters=3,
linkage='ward')
cluster_labels = agg_clustering.fit_predict(X)
# 树状图可视化
from scipy.cluster.hierarchy import dendrogram, linkage
linked = linkage(X, 'ward')
plt.figure(figsize=(12, 8))
dendrogram(linked)
```

## 模型选择与超参数调优

### 网格搜索：`GridSearchCV()`

对参数网格进行穷举搜索。

```python
# 用于超参数调优的网格搜索
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

### 随机搜索：`RandomizedSearchCV()`

从参数分布中随机采样。

```python
# 随机搜索 (对于大型参数空间更快)
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

### 管道：`Pipeline()`

将预处理和建模步骤链接起来。

```python
# 创建预处理和建模管道
from sklearn.pipeline import Pipeline
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier(random_state=42))
])
pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)
# 带网格搜索的管道
param_grid = {
    'classifier__n_estimators': [100, 200],
    'classifier__max_depth': [3, 5, None]
}
grid_search = GridSearchCV(pipeline, param_grid, cv=5)
grid_search.fit(X_train, y_train)
```

### 特征选择：`SelectKBest()` / `RFE()`

选择信息量最大的特征。

```python
# 单变量特征选择
from sklearn.feature_selection import SelectKBest,
f_classif
selector = SelectKBest(score_func=f_classif, k=10)
X_selected = selector.fit_transform(X_train, y_train)
selected_features = X.columns[selector.get_support()]
# 递归特征消除
from sklearn.feature_selection import RFE
rfe = RFE(RandomForestClassifier(random_state=42),
n_features_to_select=10)
X_rfe = rfe.fit_transform(X_train, y_train)
```

## 高级技术

### 集成方法：`VotingClassifier()` / `BaggingClassifier()`

组合多个模型以获得更好的性能。

```python
# 投票分类器 (不同算法的集成)
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
# Bagging 分类器
from sklearn.ensemble import BaggingClassifier
bagging_clf = BaggingClassifier(DecisionTreeClassifier(),
n_estimators=100, random_state=42)
bagging_clf.fit(X_train, y_train)
```

### 梯度提升：`GradientBoostingClassifier()`

带有误差修正的顺序集成方法。

```python
# 梯度提升分类器
from sklearn.ensemble import
GradientBoostingClassifier
gb_clf = GradientBoostingClassifier(n_estimators=100,
learning_rate=0.1, random_state=42)
gb_clf.fit(X_train, y_train)
y_pred = gb_clf.predict(X_test)
# 特征重要性
importances = gb_clf.feature_importances_
# 学习曲线
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores =
learning_curve(gb_clf, X, y, cv=5)
```

### 处理不平衡数据：`SMOTE()` / 类权重

解决数据集中类别不平衡问题。

```python
# 安装 imbalanced-learn: pip install imbalanced-learn
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train,
y_train)
# 使用类别权重
rf_balanced =
RandomForestClassifier(class_weight='balanced',
random_state=42)
rf_balanced.fit(X_train, y_train)
# 手动计算类别权重
from sklearn.utils.class_weight import
compute_class_weight
class_weights = compute_class_weight('balanced',
classes=np.unique(y_train), y=y_train)
weight_dict = dict(zip(np.unique(y_train), class_weights))
```

### 模型持久化：`joblib`

保存和加载训练好的模型。

```python
# 保存模型
import joblib
joblib.dump(model, 'trained_model.pkl')
# 加载模型
loaded_model = joblib.load('trained_model.pkl')
y_pred = loaded_model.predict(X_test)
# 保存整个管道
joblib.dump(pipeline, 'preprocessing_pipeline.pkl')
loaded_pipeline =
joblib.load('preprocessing_pipeline.pkl')
# 使用 pickle
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
```

## 性能与调试

### 学习曲线：`learning_curve()`

诊断过拟合和欠拟合。

```python
# 绘制学习曲线
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores = learning_curve(
    model, X, y, cv=5, train_sizes=np.linspace(0.1, 1.0, 10)
)
plt.figure(figsize=(10, 6))
plt.plot(train_sizes, np.mean(train_scores, axis=1), 'o-',
label='训练分数')
plt.plot(train_sizes, np.mean(val_scores, axis=1), 'o-',
label='验证分数')
plt.xlabel('训练集大小')
plt.ylabel('分数')
plt.legend()
```

### 验证曲线：`validation_curve()`

分析超参数对模型性能的影响。

```python
# 单个超参数的验证曲线
from sklearn.model_selection import validation_curve
param_range = [10, 50, 100, 200, 500]
train_scores, val_scores = validation_curve(
    RandomForestClassifier(random_state=42), X, y,
    param_name='n_estimators',
param_range=param_range, cv=5
)
plt.figure(figsize=(10, 6))
plt.plot(param_range, np.mean(train_scores, axis=1), 'o-',
label='训练')
plt.plot(param_range, np.mean(val_scores, axis=1), 'o-',
label='验证')
plt.xlabel('估计器数量')
plt.ylabel('分数')
```

### 特征重要性可视化

了解哪些特征驱动了模型预测。

```python
# 绘制特征重要性
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
plt.figure(figsize=(12, 8))
plt.title("特征重要性")
plt.bar(range(X.shape[1]), importances[indices])
plt.xticks(range(X.shape[1]), [X.columns[i] for i in indices],
rotation=90)
# SHAP 值用于模型可解释性
# pip install shap
import shap
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_test)
shap.summary_plot(shap_values, X_test)
```

### 模型比较

系统地比较多种算法。

```python
# 比较多个模型
from sklearn.model_selection import cross_val_score
models = {
    '逻辑回归':
LogisticRegression(random_state=42),
    '随机森林':
RandomForestClassifier(random_state=42),
    'SVM': SVC(random_state=42),
    '梯度提升':
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

## 配置与最佳实践

### 随机状态与可复现性

确保跨运行结果一致。

```python
# 设置随机状态以保证可复现性
import numpy as np
np.random.seed(42)
# 在所有 sklearn 组件中设置 random_state
model =
RandomForestClassifier(random
_state=42)
train_test_split(X, y,
random_state=42)
# 用于交叉验证
cv = StratifiedKFold(n_splits=5,
shuffle=True, random_state=42)
```

### 内存与性能

针对大型数据集和计算效率进行优化。

```python
# 使用 n_jobs=-1 进行并行处理
model =
RandomForestClassifier(n_jobs=
-1)
grid_search =
GridSearchCV(model,
param_grid, n_jobs=-1)
# 对于大型数据集，如果可用，使用
partial_fit
from sklearn.linear_model
import SGDClassifier
sgd = SGDClassifier()
# 分块处理数据
for chunk in chunks:
    sgd.partial_fit(chunk_X,
chunk_y)
```

### 警告与调试

处理常见问题并调试模型。

```python
# 抑制警告 (谨慎使用)
import warnings
warnings.filterwarnings('ignore')
# 启用 sklearn 的 set_config 以获得更好的调试效果
from sklearn import set_config
set_config(display='diagram')  #
在 Jupyter 中增强显示
# 检查数据泄露
from sklearn.model_selection
import cross_val_score
# 确保预处理在 CV 循环内部完成
```

## 相关链接

- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/pandas">Pandas 速查表</router-link>
- <router-link to="/numpy">NumPy 速查表</router-link>
- <router-link to="/matplotlib">Matplotlib 速查表</router-link>
- <router-link to="/datascience">数据科学速查表</router-link>
- <router-link to="/database">数据库速查表</router-link>

---
title: 'Шпаргалка по Data Science | LabEx'
description: 'Изучите науку о данных с помощью этой комплексной шпаргалки. Быстрый справочник по анализу данных, машинному обучению, статистике, визуализации, библиотекам Python и рабочим процессам Data Science.'
pdfUrl: '/cheatsheets/pdf/data-science-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Data Science
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/datascience">Изучайте Data Science с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучайте науку о данных с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по науке о данных, охватывающие основные библиотеки Python, манипулирование данными, статистический анализ, машинное обучение и визуализацию данных. Освойте методы сбора, очистки, анализа данных и развертывания моделей.
</base-disclaimer-content>
</base-disclaimer>

## Основные библиотеки Python

### Основной стек Data Science

Ключевые библиотеки, такие как NumPy, Pandas, Matplotlib, Seaborn и scikit-learn, составляют основу рабочих процессов науки о данных.

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

Основной пакет для численных вычислений с использованием Python.

```python
# Create arrays
arr = np.array([1, 2, 3, 4, 5])
matrix = np.array([[1, 2], [3, 4]])
# Basic operations
np.mean(arr)       # Среднее
np.std(arr)        # Стандартное отклонение
np.reshape(arr, (5, 1))  # Изменение формы массива
# Generate data
np.random.normal(0, 1, 100)  # Случайное нормальное
распределение
```

### Pandas: `import pandas as pd`

Библиотека для манипулирования данными и анализа.

```python
# Create DataFrame
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
# Read data
df = pd.read_csv('data.csv')
# Basic exploration
df.head()          # Первые 5 строк
df.info()          # Типы данных и пропущенные значения
df.describe()      # Сводная статистика
# Data manipulation
df.groupby('column').mean()
df.fillna(df.mean())  # Обработка пропущенных значений
```

<BaseQuiz id="datascience-pandas-1" correct="C">
  <template #question>
    Что возвращает <code>df.head()</code> в Pandas?
  </template>
  
  <BaseQuizOption value="A">Последние 5 строк DataFrame</BaseQuizOption>
  <BaseQuizOption value="B">Сводка DataFrame</BaseQuizOption>
  <BaseQuizOption value="C" correct>Первые 5 строк DataFrame</BaseQuizOption>
  <BaseQuizOption value="D">Все строки DataFrame</BaseQuizOption>
  
  <BaseQuizAnswer>
    По умолчанию <code>df.head()</code> отображает первые 5 строк DataFrame. Вы можете указать другое число, например <code>df.head(10)</code>, чтобы увидеть первые 10 строк. Это полезно для быстрого осмотра ваших данных.
  </BaseQuizAnswer>
</BaseQuiz>

### Matplotlib & Seaborn: Визуализация

Создание статистических визуализаций и графиков.

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

## Рабочий процесс Data Science

### 1. Определение проблемы

Наука о данных — это междисциплинарная область, сочетающая математику, статистику, программирование и бизнес-аналитику. Определите цели и метрики успеха.

```python
# Define business problem
# - What question are we answering?
# - What metrics will measure
success?
# - What data do we need?
```

### 2. Сбор и импорт данных

Сбор данных из различных источников и форматов.

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

### 3. Исследовательский анализ данных (EDA)

Понимание структуры данных, закономерностей и качества.

```python
# Exploratory Data Analysis
df.shape              # Размеры
df.dtypes             # Типы данных
df.isnull().sum()     # Пропущенные значения
df['column'].value_counts()  #
Частотные подсчеты
df.corr()             # Матрица корреляции
# Visualizations for EDA
sns.histplot(df['numeric_column'])
sns.boxplot(data=df,
y='numeric_column')
plt.figure(figsize=(10, 8))
sns.heatmap(df.corr(), annot=True)
```

## Очистка и предварительная обработка данных

### Обработка пропущенных данных

Прежде чем анализировать данные, их необходимо очистить и подготовить. Это включает обработку пропущенных данных, удаление дубликатов и нормализацию переменных. Очистка данных часто является самой трудоемкой, но критически важной частью процесса Data Science.

```python
# Identify missing values
df.isnull().sum()
df.isnull().sum() / len(df) * 100  # Процент пропущенных
# Handle missing values
df.dropna()                    # Удалить строки с NaN
df.fillna(df.mean())          # Заполнить средним
df.fillna(method='forward')   # Прямое заполнение
df.fillna(method='backward')  # Обратное заполнение
# Advanced imputation
from sklearn.impute import SimpleImputer, KNNImputer
imputer = SimpleImputer(strategy='median')
df_filled = pd.DataFrame(imputer.fit_transform(df))
```

<BaseQuiz id="datascience-missing-1" correct="B">
  <template #question>
    Для чего используется прямое заполнение (<code>method='forward'</code>)?
  </template>
  
  <BaseQuizOption value="A">Заполнение пропущенных значений средним</BaseQuizOption>
  <BaseQuizOption value="B" correct>Заполнение пропущенных значений предыдущим непустым значением</BaseQuizOption>
  <BaseQuizOption value="C">Заполнение пропущенных значений случайными значениями</BaseQuizOption>
  <BaseQuizOption value="D">Удаление пропущенных значений</BaseQuizOption>
  
  <BaseQuizAnswer>
    Прямое заполнение распространяет последнее действительное наблюдение вперед для заполнения пропущенных значений. Это полезно для временных рядов, где вы хотите сохранить предыдущее значение до появления новых данных.
  </BaseQuizAnswer>
</BaseQuiz>

### Преобразование данных

Нормализация данных (масштабирование данных до стандартного диапазона, например [0, 1]) помогает избежать смещений из-за различий в величинах признаков.

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
    В чем разница между StandardScaler и MinMaxScaler?
  </template>
  
  <BaseQuizOption value="A">Разницы нет</BaseQuizOption>
  <BaseQuizOption value="B">StandardScaler масштабирует до [0,1], MinMaxScaler масштабирует до среднее=0, стд=1</BaseQuizOption>
  <BaseQuizOption value="C" correct>StandardScaler нормализует до среднего=0 и стандартного отклонения=1, MinMaxScaler масштабирует до диапазона [0,1]</BaseQuizOption>
  <BaseQuizOption value="D">StandardScaler работает быстрее</BaseQuizOption>
  
  <BaseQuizAnswer>
    StandardScaler преобразует данные так, чтобы их среднее было равно 0, а стандартное отклонение — 1 (z-оценка нормализации). MinMaxScaler масштабирует данные до фиксированного диапазона, обычно [0, 1]. Оба полезны, но для разных сценариев.
  </BaseQuizAnswer>
</BaseQuiz>

### Обнаружение и обработка выбросов

Выявление и обработка экстремальных значений, которые могут исказить анализ.

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

### Конструирование признаков (Feature Engineering)

Создание новых переменных для улучшения производительности модели.

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

## Статистический анализ

### Описательная статистика

Эти меры центральной тенденции обобщают данные и дают представление об их распределении. Они являются основой для понимания любого набора данных. Среднее — это среднее всех значений в наборе данных. Оно очень чувствительно к выбросам.

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

### Проверка гипотез

Проверка статистических гипотез и подтверждение предположений.

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

### Корреляционный анализ

Понимание взаимосвязей между переменными.

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

### ANOVA и регрессия

Анализ дисперсии и взаимосвязей между переменными.

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

## Модели машинного обучения

### Обучение с учителем — Классификация

Деревья решений: Древовидная модель решений и их возможных последствий. Каждый узел представляет собой проверку атрибута, а каждая ветвь — результат. Обычно используется для задач классификации.

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

### Обучение с учителем — Регрессия

Прогнозирование непрерывных целевых переменных.

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

### Обучение без учителя

Обнаружение закономерностей в данных без размеченных результатов.

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

### Оценка модели

Оценка производительности модели с использованием соответствующих метрик.

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

## Визуализация данных

### Исследовательские визуализации

Понимание распределений и взаимосвязей данных.

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

### Расширенные визуализации

Создание комплексных информационных панелей и отчетов.

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

### Статистические графики

Визуализация статистических взаимосвязей и результатов модели.

```python
# Pair plots for correlation
sns.pairplot(df, hue='target_category')
# Residual plots for regression
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.scatter(y_pred, y_test - y_pred)
plt.xlabel('Предсказанное')
plt.ylabel('Остатки')
plt.subplot(1, 2, 2)
plt.scatter(y_test, y_pred)
plt.plot([y_test.min(), y_test.max()], [y_test.min(),
y_test.max()], 'r--')
# ROC Curve for classification
from sklearn.metrics import roc_curve, auc
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, label=f'ROC-кривая (AUC = {roc_auc:.2f})')
```

### Настройка и стилизация

Форматирование профессиональных визуализаций.

```python
# Set style and colors
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
# Custom figure settings
plt.figure(figsize=(12, 8))
plt.title('Профессиональное название графика', fontsize=16,
fontweight='bold')
plt.xlabel('Метка оси X', fontsize=14)
plt.ylabel('Метка оси Y', fontsize=14)
plt.legend(loc='best')
plt.grid(True, alpha=0.3)
plt.tight_layout()
# Save high-quality plots
plt.savefig('analysis_plot.png', dpi=300,
bbox_inches='tight')
```

## Развертывание модели и MLOps

### Сохранение модели (Persistence)

Сохранение и загрузка обученных моделей для использования в продакшене.

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

### Кросс-валидация и настройка гиперпараметров

Оптимизация производительности модели и предотвращение переобучения.

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

### Мониторинг производительности

Наличие быстрого доступа к основным концепциям и командам может иметь решающее значение в вашем рабочем процессе. Независимо от того, являетесь ли вы новичком, осваивающим основы, или опытным специалистом, ищущим надежный справочник, шпаргалки служат бесценными помощниками.

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

### Документация модели

Документирование предположений модели, производительности и использования.

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

## Рекомендации и советы

### Организация кода

Структурирование проектов для воспроизводимости и совместной работы.

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

### Управление средой

Обеспечение воспроизводимых сред в разных системах.

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

### Проверки качества данных

Проверка целостности данных на протяжении всего конвейера.

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
    print(f"Dataset shape:
{df.shape}")
    print(f"Missing values:
{df.isnull().sum().sum()}")
    print(f"Duplicate rows:
{df.duplicated().sum()}")
    print("\nColumn data types:")
    print(df.dtypes)
```

## Соответствующие ссылки

- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/pandas">Шпаргалка по Pandas</router-link>
- <router-link to="/numpy">Шпаргалка по NumPy</router-link>
- <router-link to="/matplotlib">Шпаргалка по Matplotlib</router-link>
- <router-link to="/sklearn">Шпаргалка по Scikit-learn</router-link>
- <router-link to="/database">Шпаргалка по Базам данных</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>

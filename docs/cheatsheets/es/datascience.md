---
title: 'Hoja de Trucos de Ciencia de Datos | LabEx'
description: 'Aprenda ciencia de datos con esta hoja de trucos completa. Referencia rápida para análisis de datos, aprendizaje automático, estadística, visualización, librerías de Python y flujos de trabajo de ciencia de datos.'
pdfUrl: '/cheatsheets/pdf/data-science-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Ciencia de Datos
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/datascience">Aprenda Ciencia de Datos con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda ciencia de datos a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de ciencia de datos que cubren bibliotecas esenciales de Python, manipulación de datos, análisis estadístico, aprendizaje automático y visualización de datos. Domine las técnicas de recopilación, limpieza, análisis de datos y despliegue de modelos.
</base-disclaimer-content>
</base-disclaimer>

## Bibliotecas Esenciales de Python

### Pila Central de Ciencia de Datos

Bibliotecas clave como NumPy, Pandas, Matplotlib, Seaborn y scikit-learn forman la base de los flujos de trabajo de ciencia de datos.

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

Paquete fundamental para la computación numérica con Python.

```python
# Create arrays
arr = np.array([1, 2, 3, 4, 5])
matrix = np.array([[1, 2], [3, 4]])
# Basic operations
np.mean(arr)       # Promedio
np.std(arr)        # Desviación estándar
np.reshape(arr, (5, 1))  # Remodelar arreglo
# Generate data
np.random.normal(0, 1, 100)  # Distribución
normal aleatoria
```

### Pandas: `import pandas as pd`

Biblioteca para manipulación y análisis de datos.

```python
# Create DataFrame
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
# Read data
df = pd.read_csv('data.csv')
# Basic exploration
df.head()          # Primeras 5 filas
df.info()          # Tipos de datos y valores faltantes
df.describe()      # Estadísticas resumidas
# Data manipulation
df.groupby('column').mean()
df.fillna(df.mean())  # Manejar valores faltantes
```

<BaseQuiz id="datascience-pandas-1" correct="C">
  <template #question>
    ¿Qué devuelve <code>df.head()</code> en Pandas?
  </template>
  
  <BaseQuizOption value="A">Las últimas 5 filas del DataFrame</BaseQuizOption>
  <BaseQuizOption value="B">Un resumen del DataFrame</BaseQuizOption>
  <BaseQuizOption value="C" correct>Las primeras 5 filas del DataFrame</BaseQuizOption>
  <BaseQuizOption value="D">Todas las filas del DataFrame</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>df.head()</code> muestra las primeras 5 filas del DataFrame por defecto. Puede especificar un número diferente, como <code>df.head(10)</code> para ver las primeras 10 filas. Es útil para inspeccionar rápidamente sus datos.
  </BaseQuizAnswer>
</BaseQuiz>

### Matplotlib & Seaborn: Visualización

Cree visualizaciones y gráficos estadísticos.

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

## Flujo de Trabajo de Ciencia de Datos

### 1. Definición del Problema

La ciencia de datos es un campo multidisciplinario que combina matemáticas, estadística, programación e inteligencia empresarial. Defina objetivos y métricas de éxito.

```python
# Define business problem
# - ¿Qué pregunta estamos respondiendo?
# - ¿Qué métricas medirán el
éxito?
# - ¿Qué datos necesitamos?
```

### 2. Recopilación e Importación de Datos

Reúna datos de varias fuentes y formatos.

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

### 3. Exploración de Datos (EDA)

Comprenda la estructura, los patrones y la calidad de los datos.

```python
# Exploratory Data Analysis
df.shape              # Dimensiones
df.dtypes             # Tipos de datos
df.isnull().sum()     # Valores faltantes
df['column'].value_counts()  #
Frecuencias de conteo
df.corr()             # Matriz de correlación
# Visualizations for EDA
sns.histplot(df['numeric_column'])
sns.boxplot(data=df,
y='numeric_column')
plt.figure(figsize=(10, 8))
sns.heatmap(df.corr(), annot=True)
```

## Limpieza y Preprocesamiento de Datos

### Manejo de Datos Faltantes

Antes de analizar los datos, deben limpiarse y prepararse. Esto incluye manejar datos faltantes, eliminar duplicados y normalizar variables. La limpieza de datos es a menudo el aspecto más lento pero crítico del proceso de ciencia de datos.

```python
# Identify missing values
df.isnull().sum()
df.isnull().sum() / len(df) * 100  # Porcentaje faltante
# Handle missing values
df.dropna()                    # Eliminar filas con NaN
df.fillna(df.mean())          # Rellenar con la media
df.fillna(method='forward')   # Relleno hacia adelante
df.fillna(method='backward')  # Relleno hacia atrás
# Advanced imputation
from sklearn.impute import SimpleImputer, KNNImputer
imputer = SimpleImputer(strategy='median')
df_filled = pd.DataFrame(imputer.fit_transform(df))
```

<BaseQuiz id="datascience-missing-1" correct="B">
  <template #question>
    ¿Para qué se utiliza el relleno hacia adelante (<code>method='forward'</code>)?
  </template>
  
  <BaseQuizOption value="A">Rellenar valores faltantes con la media</BaseQuizOption>
  <BaseQuizOption value="B" correct>Rellenar valores faltantes con el valor no nulo anterior</BaseQuizOption>
  <BaseQuizOption value="C">Rellenar valores faltantes con valores aleatorios</BaseQuizOption>
  <BaseQuizOption value="D">Eliminar valores faltantes</BaseQuizOption>
  
  <BaseQuizAnswer>
    El relleno hacia adelante propaga la última observación válida hacia adelante para rellenar los valores faltantes. Esto es útil para datos de series temporales donde desea mantener el valor anterior hasta que haya nuevos datos disponibles.
  </BaseQuizAnswer>
</BaseQuiz>

### Transformación de Datos

La normalización de datos (escalar datos a un rango estándar como [0, 1]) ayuda a evitar sesgos debido a diferencias en la magnitud de las características.

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
    ¿Cuál es la diferencia entre StandardScaler y MinMaxScaler?
  </template>
  
  <BaseQuizOption value="A">No hay diferencia</BaseQuizOption>
  <BaseQuizOption value="B">StandardScaler escala a [0,1], MinMaxScaler escala a media=0, std=1</BaseQuizOption>
  <BaseQuizOption value="C" correct>StandardScaler normaliza a media=0 y std=1, MinMaxScaler escala al rango [0,1]</BaseQuizOption>
  <BaseQuizOption value="D">StandardScaler es más rápido</BaseQuizOption>
  
  <BaseQuizAnswer>
    StandardScaler transforma los datos para tener una media de 0 y una desviación estándar de 1 (normalización de puntuación Z). MinMaxScaler escala los datos a un rango fijo, típicamente [0, 1]. Ambos son útiles pero para diferentes escenarios.
  </BaseQuizAnswer>
</BaseQuiz>

### Detección y Tratamiento de Valores Atípicos (Outliers)

Identifique y maneje valores extremos que puedan sesgar el análisis.

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

### Ingeniería de Características (Feature Engineering)

Cree nuevas variables para mejorar el rendimiento del modelo.

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

## Análisis Estadístico

### Estadísticas Descriptivas

Estas medidas de tendencia central resumen los datos y proporcionan información sobre su distribución. Son fundamentales para comprender cualquier conjunto de datos. La media es el promedio de todos los valores en un conjunto de datos. Es muy sensible a los valores atípicos.

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

### Pruebas de Hipótesis

Pruebe hipótesis estadísticas y valide suposiciones.

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

### Análisis de Correlación

Comprenda las relaciones entre variables.

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

### ANOVA y Regresión

Analice la varianza y las relaciones entre variables.

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

## Modelos de Aprendizaje Automático

### Aprendizaje Supervisado - Clasificación

Árboles de Decisión: Un modelo similar a un árbol de decisiones y consecuencias posibles. Cada nodo representa una prueba en un atributo, y cada rama representa el resultado. Se utiliza comúnmente para tareas de clasificación.

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

### Aprendizaje Supervisado - Regresión

Predicción de variables objetivo continuas.

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

### Aprendizaje No Supervisado

Descubra patrones en los datos sin resultados etiquetados.

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

### Evaluación del Modelo

Evalúe el rendimiento del modelo utilizando métricas apropiadas.

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

## Visualización de Datos

### Visualizaciones Exploratorias

Comprenda las distribuciones y relaciones de los datos.

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

### Visualizaciones Avanzadas

Cree paneles y reportes completos.

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

### Gráficos Estadísticos

Visualice relaciones estadísticas y resultados del modelo.

```python
# Pair plots for correlation
sns.pairplot(df, hue='target_category')
# Residual plots for regression
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.scatter(y_pred, y_test - y_pred)
plt.xlabel('Predicho')
plt.ylabel('Residuos')
plt.subplot(1, 2, 2)
plt.scatter(y_test, y_pred)
plt.plot([y_test.min(), y_test.max()], [y_test.min(),
y_test.max()], 'r--')
# ROC Curve for classification
from sklearn.metrics import roc_curve, auc
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, label=f'Curva ROC (AUC = {roc_auc:.2f})')
```

### Personalización y Estilo

Formato profesional de visualización.

```python
# Set style and colors
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
# Custom figure settings
plt.figure(figsize=(12, 8))
plt.title('Título de Gráfico Profesional', fontsize=16,
fontweight='bold')
plt.xlabel('Etiqueta del Eje X', fontsize=14)
plt.ylabel('Etiqueta del Eje Y', fontsize=14)
plt.legend(loc='best')
plt.grid(True, alpha=0.3)
plt.tight_layout()
# Save high-quality plots
plt.savefig('analysis_plot.png', dpi=300,
bbox_inches='tight')
```

## Despliegue de Modelos y MLOps

### Persistencia del Modelo

Guardar y cargar modelos entrenados para uso en producción.

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

### Validación Cruzada y Ajuste de Hiperparámetros

Optimice el rendimiento del modelo y prevenga el sobreajuste.

```python
# Cross-validation
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"Precisión CV: {cv_scores.mean():.3f} (+/-
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

### Monitoreo del Rendimiento

Tener acceso rápido a conceptos y comandos esenciales puede marcar la diferencia en su flujo de trabajo. Ya sea que sea un principiante que encuentra su lugar o un profesional experimentado que busca una referencia confiable, las hojas de trucos sirven como compañeros invaluables.

```python
# Model performance tracking
import time
start_time = time.time()
predictions = model.predict(X_test)
inference_time = time.time() - start_time
print(f"Tiempo de inferencia: {inference_time:.4f} segundos")
# Memory usage monitoring
import psutil
process = psutil.Process()
memory_usage = process.memory_info().rss / 1024 /
1024  # MB
print(f"Uso de memoria: {memory_usage:.2f} MB")
# Feature importance analysis
feature_importance = model.feature_importances_
importance_df = pd.DataFrame({
    'feature': X.columns,
    'importance': feature_importance
}).sort_values('importance', ascending=False)
```

### Documentación del Modelo

Documente las suposiciones, el rendimiento y el uso del modelo.

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

## Mejores Prácticas y Consejos

### Organización del Código

Estructure los proyectos para la reproducibilidad y la colaboración.

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

### Gestión de Entornos

Asegure entornos reproducibles en todos los sistemas.

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

### Verificación de Calidad de Datos

Valide la integridad de los datos a lo largo de todo el flujo de trabajo.

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

## Enlaces Relevantes

- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/pandas">Hoja de Trucos de Pandas</router-link>
- <router-link to="/numpy">Hoja de Trucos de NumPy</router-link>
- <router-link to="/matplotlib">Hoja de Trucos de Matplotlib</router-link>
- <router-link to="/sklearn">Hoja de Trucos de Scikit-learn</router-link>
- <router-link to="/database">Hoja de Trucos de Base de Datos</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>

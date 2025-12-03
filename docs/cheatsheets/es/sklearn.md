---
title: 'Hoja de Trucos de scikit-learn | LabEx'
description: 'Aprenda machine learning con scikit-learn con esta hoja de trucos completa. Referencia rápida para algoritmos de ML, entrenamiento de modelos, preprocesamiento, evaluación y flujos de trabajo de aprendizaje automático en Python.'
pdfUrl: '/cheatsheets/pdf/sklearn-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de scikit-learn
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/sklearn">Aprenda scikit-learn con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda aprendizaje automático con scikit-learn a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de scikit-learn que cubren el preprocesamiento de datos esencial, la selección de modelos, el entrenamiento, la evaluación y la ingeniería de características. Domine los algoritmos de aprendizaje automático y cree modelos predictivos con Python.
</base-disclaimer-content>
</base-disclaimer>

## Instalación e Importaciones

### Instalación: `pip install scikit-learn`

Instalar scikit-learn y dependencias comunes.

```bash
# Instalar scikit-learn
pip install scikit-learn
# Instalar con paquetes adicionales
pip install scikit-learn pandas numpy matplotlib
# Actualizar a la última versión
pip install scikit-learn --upgrade
```

### Importaciones Esenciales

Importaciones estándar para flujos de trabajo de scikit-learn.

```python
# Importaciones principales
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,
classification_report
# Algoritmos comunes
from sklearn.linear_model import LinearRegression,
LogisticRegression
from sklearn.ensemble import RandomForestClassifier,
GradientBoostingRegressor
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
```

### Comprobar Versión

Verificar su instalación de scikit-learn.

```python
import sklearn
print(sklearn.__version__)
# Mostrar configuración de compilación
sklearn.show_versions()
```

### Carga de Conjuntos de Datos

Cargar conjuntos de datos integrados para practicar.

```python
from sklearn.datasets import load_iris, load_boston,
make_classification
# Cargar conjuntos de datos de muestra
iris = load_iris()
X, y = iris.data, iris.target
# Generar datos sintéticos
X_synth, y_synth = make_classification(n_samples=1000,
n_features=20, n_informative=10, random_state=42)
```

## Preprocesamiento de Datos

### División Entrenamiento-Prueba: `train_test_split()`

Dividir los datos en conjuntos de entrenamiento y prueba.

```python
# División básica (80% entrenamiento, 20% prueba)
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
random_state=42)
# División estratificada para clasificación
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
stratify=y, random_state=42)
# Múltiples divisiones
X_train, X_temp, y_train, y_temp =
train_test_split(X, y, test_size=0.4,
random_state=42)
X_val, X_test, y_val, y_test =
train_test_split(X_temp, y_temp,
test_size=0.5, random_state=42)
```

<BaseQuiz id="sklearn-split-1" correct="B">
  <template #question>
    ¿Por qué es importante dividir los datos en conjuntos de entrenamiento y prueba?
  </template>
  
  <BaseQuizOption value="A">Para reducir el tamaño del conjunto de datos</BaseQuizOption>
  <BaseQuizOption value="B" correct>Para evaluar el rendimiento del modelo en datos no vistos y prevenir el sobreajuste</BaseQuizOption>
  <BaseQuizOption value="C">Para acelerar el entrenamiento del modelo</BaseQuizOption>
  <BaseQuizOption value="D">Para equilibrar el conjunto de datos</BaseQuizOption>
  
  <BaseQuizAnswer>
    Dividir los datos permite entrenar el modelo con una porción y probarlo con otra. Esto ayuda a evaluar qué tan bien se generaliza el modelo a datos nuevos y no vistos y previene el sobreajuste a los datos de entrenamiento.
  </BaseQuizAnswer>
</BaseQuiz>

### Escalado de Características: `StandardScaler()` / `MinMaxScaler()`

Normalizar las características a escalas similares.

```python
# Estandarización (media=0, desviación estándar=1)
from sklearn.preprocessing import
StandardScaler, MinMaxScaler
scaler = StandardScaler()
X_scaled =
scaler.fit_transform(X_train)
X_test_scaled =
scaler.transform(X_test)
# Escalado Min-Max (rango 0-1)
minmax_scaler = MinMaxScaler()
X_minmax =
minmax_scaler.fit_transform(X_train)
X_test_minmax =
minmax_scaler.transform(X_test)
```

<BaseQuiz id="sklearn-scaling-1" correct="A">
  <template #question>
    ¿Por qué es importante el escalado de características en el aprendizaje automático?
  </template>
  
  <BaseQuizOption value="A" correct>Asegura que todas las características estén en una escala similar, evitando que algunas características dominen</BaseQuizOption>
  <BaseQuizOption value="B">Elimina los valores faltantes</BaseQuizOption>
  <BaseQuizOption value="C">Aumenta el número de características</BaseQuizOption>
  <BaseQuizOption value="D">Elimina filas duplicadas</BaseQuizOption>
  
  <BaseQuizAnswer>
    El escalado de características es importante porque algoritmos como SVM, KNN y redes neuronales son sensibles a las escalas de las características. Sin escalado, las características con rangos más grandes pueden dominar el proceso de aprendizaje del modelo.
  </BaseQuizAnswer>
</BaseQuiz>

### Codificación: `LabelEncoder()` / `OneHotEncoder()`

Convertir variables categóricas a formato numérico.

```python
# Codificación de etiquetas para la variable objetivo
from sklearn.preprocessing import
LabelEncoder, OneHotEncoder
label_encoder = LabelEncoder()
y_encoded =
label_encoder.fit_transform(y)
# Codificación one-hot para características categóricas
from sklearn.preprocessing import
OneHotEncoder
encoder =
OneHotEncoder(sparse=False,
drop='first')
X_encoded =
encoder.fit_transform(X_categorical)
# Obtener nombres de características
feature_names =
encoder.get_feature_names_out()
```

## Aprendizaje Supervisado - Clasificación

### Regresión Logística: `LogisticRegression()`

Modelo lineal para clasificación binaria y multiclase.

```python
# Regresión logística básica
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression(random_state=42)
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
y_proba = log_reg.predict_proba(X_test)
# Con regularización
log_reg_l2 = LogisticRegression(C=0.1, penalty='l2')
log_reg_l1 = LogisticRegression(C=0.1, penalty='l1',
solver='liblinear')
```

### Árbol de Decisión: `DecisionTreeClassifier()`

Modelo basado en árboles para tareas de clasificación.

```python
# Clasificador de árbol de decisión
from sklearn.tree import DecisionTreeClassifier
tree_clf = DecisionTreeClassifier(max_depth=5,
random_state=42)
tree_clf.fit(X_train, y_train)
y_pred = tree_clf.predict(X_test)
# Importancia de las características
importances = tree_clf.feature_importances_
# Visualizar árbol
from sklearn.tree import plot_tree
plot_tree(tree_clf, max_depth=3, filled=True)
```

### Bosque Aleatorio: `RandomForestClassifier()`

Método de conjunto que combina múltiples árboles de decisión.

```python
# Clasificador de bosque aleatorio
from sklearn.ensemble import RandomForestClassifier
rf_clf = RandomForestClassifier(n_estimators=100,
random_state=42)
rf_clf.fit(X_train, y_train)
y_pred = rf_clf.predict(X_test)
# Ajuste de hiperparámetros
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
    ¿Qué controla `n_estimators` en RandomForestClassifier?
  </template>
  
  <BaseQuizOption value="A" correct>El número de árboles de decisión en el bosque</BaseQuizOption>
  <BaseQuizOption value="B">La profundidad máxima de cada árbol</BaseQuizOption>
  <BaseQuizOption value="C">El número de características a considerar</BaseQuizOption>
  <BaseQuizOption value="D">La semilla aleatoria</BaseQuizOption>
  
  <BaseQuizAnswer>
    `n_estimators` especifica cuántos árboles de decisión incluir en el bosque aleatorio. Más árboles generalmente mejoran el rendimiento pero aumentan el tiempo de cómputo. El valor predeterminado suele ser 100.
  </BaseQuizAnswer>
</BaseQuiz>

### Máquina de Vectores de Soporte: `SVC()`

Clasificador potente que utiliza métodos de kernel.

```python
# Clasificador SVM
from sklearn.svm import SVC
svm_clf = SVC(kernel='rbf', C=1.0, gamma='scale',
random_state=42)
svm_clf.fit(X_train, y_train)
y_pred = svm_clf.predict(X_test)
# Diferentes kernels
svm_linear = SVC(kernel='linear')
svm_poly = SVC(kernel='poly', degree=3)
svm_rbf = SVC(kernel='rbf', gamma=0.1)
```

## Aprendizaje Supervisado - Regresión

### Regresión Lineal: `LinearRegression()`

Modelo lineal básico para variables objetivo continuas.

```python
# Regresión lineal simple
from sklearn.linear_model import LinearRegression
lin_reg = LinearRegression()
lin_reg.fit(X_train, y_train)
y_pred = lin_reg.predict(X_test)
# Obtener coeficientes e intercepto
coefficients = lin_reg.coef_
intercept = lin_reg.intercept_
print(f"Puntuación R²: {lin_reg.score(X_test, y_test)}")
```

### Regresión Ridge: `Ridge()`

Regresión lineal con regularización L2.

```python
# Regresión Ridge (regularización L2)
from sklearn.linear_model import Ridge
ridge_reg = Ridge(alpha=1.0)
ridge_reg.fit(X_train, y_train)
y_pred = ridge_reg.predict(X_test)
# Validación cruzada para selección de alpha
from sklearn.linear_model import RidgeCV
ridge_cv = RidgeCV(alphas=[0.1, 1.0, 10.0])
ridge_cv.fit(X_train, y_train)
```

### Regresión Lasso: `Lasso()`

Regresión lineal con regularización L1 para selección de características.

```python
# Regresión Lasso (regularización L1)
from sklearn.linear_model import Lasso
lasso_reg = Lasso(alpha=0.1)
lasso_reg.fit(X_train, y_train)
y_pred = lasso_reg.predict(X_test)
# Selección de características (coeficientes distintos de cero)
selected_features = X.columns[lasso_reg.coef_ != 0]
print(f"Características seleccionadas: {len(selected_features)}")
```

### Regresión de Bosque Aleatorio: `RandomForestRegressor()`

Método de conjunto para tareas de regresión.

```python
# Regresor de bosque aleatorio
from sklearn.ensemble import RandomForestRegressor
rf_reg = RandomForestRegressor(n_estimators=100,
random_state=42)
rf_reg.fit(X_train, y_train)
y_pred = rf_reg.predict(X_test)
# Importancia de las características para regresión
feature_importance = rf_reg.feature_importances_
```

## Evaluación de Modelos

### Métricas de Clasificación

Evaluar el rendimiento del modelo de clasificación.

```python
# Precisión básica
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# Informe de clasificación detallado
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred))
# Matriz de confusión
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
```

### Curva ROC y AUC

Trazar la curva ROC y calcular el Área Bajo la Curva.

```python
# Curva ROC para clasificación binaria
from sklearn.metrics import roc_curve, auc
fpr, tpr, thresholds = roc_curve(y_test, y_proba[:, 1])
roc_auc = auc(fpr, tpr)
# Trazar curva ROC
import matplotlib.pyplot as plt
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, label=f'Curva ROC (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel('Tasa de Falsos Positivos')
plt.ylabel('Tasa de Verdaderos Positivos')
plt.legend()
```

### Métricas de Regresión

Evaluar el rendimiento del modelo de regresión.

```python
# Métricas de regresión
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

### Validación Cruzada

Evaluación robusta del modelo mediante validación cruzada.

```python
# Validación cruzada K-fold
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"Precisión CV: {cv_scores.mean():.4f} (+/-
{cv_scores.std() * 2:.4f})")
# K-fold estratificada para conjuntos de datos desequilibrados
skf = StratifiedKFold(n_splits=5, shuffle=True,
random_state=42)
cv_scores = cross_val_score(model, X, y, cv=skf,
scoring='f1_weighted')
```

## Aprendizaje No Supervisado

### Agrupamiento K-Means: `KMeans()`

Particionar datos en k grupos.

```python
# Agrupamiento K-means
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
cluster_labels = kmeans.fit_predict(X)
centroids = kmeans.cluster_centers_
# Determinar el número óptimo de grupos (método del codo)
inertias = []
K_range = range(1, 11)
for k in K_range:
    kmeans = KMeans(n_clusters=k, random_state=42)
    kmeans.fit(X)
    inertias.append(kmeans.inertia_)
```

### Análisis de Componentes Principales: `PCA()`

Técnica de reducción de dimensionalidad.

```python
# PCA para reducción de dimensionalidad
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)
explained_variance = pca.explained_variance_ratio_
# Encontrar el número óptimo de componentes
pca_full = PCA()
pca_full.fit(X)
cumsum =
np.cumsum(pca_full.explained_variance_ratio_)
# Encontrar componentes para el 95% de varianza
n_components = np.argmax(cumsum >= 0.95) + 1
```

### Agrupamiento DBSCAN: `DBSCAN()`

Algoritmo de agrupamiento basado en densidad.

```python
# Agrupamiento DBSCAN
from sklearn.cluster import DBSCAN
dbscan = DBSCAN(eps=0.5, min_samples=5)
cluster_labels = dbscan.fit_predict(X)
n_clusters = len(set(cluster_labels)) - (1 if -1 in
cluster_labels else 0)
n_noise = list(cluster_labels).count(-1)
print(f"Número de grupos: {n_clusters}")
print(f"Número de puntos de ruido: {n_noise}")
```

### Agrupamiento Jerárquico: `AgglomerativeClustering()`

Construir jerarquía de grupos.

```python
# Agrupamiento aglomerativo
from sklearn.cluster import AgglomerativeClustering
agg_clustering = AgglomerativeClustering(n_clusters=3,
linkage='ward')
cluster_labels = agg_clustering.fit_predict(X)
# Visualización del dendrograma
from scipy.cluster.hierarchy import dendrogram, linkage
linked = linkage(X, 'ward')
plt.figure(figsize=(12, 8))
dendrogram(linked)
```

## Selección de Modelos y Ajuste de Hiperparámetros

### Búsqueda en Cuadrícula: `GridSearchCV()`

Búsqueda exhaustiva sobre la cuadrícula de parámetros.

```python
# Búsqueda en cuadrícula para ajuste de hiperparámetros
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

### Búsqueda Aleatoria: `RandomizedSearchCV()`

Muestreo aleatorio de la distribución de parámetros.

```python
# Búsqueda aleatoria (más rápida para espacios de parámetros grandes)
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

### Pipeline: `Pipeline()`

Encadenar pasos de preprocesamiento y modelado.

```python
# Crear pipeline de preprocesamiento y modelado
from sklearn.pipeline import Pipeline
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier(random_state=42))
])
pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)
# Búsqueda en cuadrícula con pipeline
param_grid = {
    'classifier__n_estimators': [100, 200],
    'classifier__max_depth': [3, 5, None]
}
grid_search = GridSearchCV(pipeline, param_grid, cv=5)
grid_search.fit(X_train, y_train)
```

### Selección de Características: `SelectKBest()` / `RFE()`

Seleccionar las características más informativas.

```python
# Selección de características univariada
from sklearn.feature_selection import SelectKBest,
f_classif
selector = SelectKBest(score_func=f_classif, k=10)
X_selected = selector.fit_transform(X_train, y_train)
selected_features = X.columns[selector.get_support()]
# Eliminación Recursiva de Características
from sklearn.feature_selection import RFE
rfe = RFE(RandomForestClassifier(random_state=42),
n_features_to_select=10)
X_rfe = rfe.fit_transform(X_train, y_train)
```

## Técnicas Avanzadas

### Métodos de Conjunto: `VotingClassifier()` / `BaggingClassifier()`

Combinar múltiples modelos para un mejor rendimiento.

```python
# Clasificador de votación (conjunto de diferentes algoritmos)
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
# Clasificador de bagging
from sklearn.ensemble import BaggingClassifier
bagging_clf = BaggingClassifier(DecisionTreeClassifier(),
n_estimators=100, random_state=42)
bagging_clf.fit(X_train, y_train)
```

### Aumento de Gradiente: `GradientBoostingClassifier()`

Método de conjunto secuencial con corrección de errores.

```python
# Clasificador de aumento de gradiente
from sklearn.ensemble import
GradientBoostingClassifier
gb_clf = GradientBoostingClassifier(n_estimators=100,
learning_rate=0.1, random_state=42)
gb_clf.fit(X_train, y_train)
y_pred = gb_clf.predict(X_test)
# Importancia de las características
importances = gb_clf.feature_importances_
# Curva de aprendizaje
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores =
learning_curve(gb_clf, X, y, cv=5)
```

### Manejo de Datos Desequilibrados: `SMOTE()` / Pesos de Clase

Abordar el desequilibrio de clases en los conjuntos de datos.

```python
# Instalar imbalanced-learn: pip install imbalanced-learn
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train,
y_train)
# Usar pesos de clase
rf_balanced =
RandomForestClassifier(class_weight='balanced',
random_state=42)
rf_balanced.fit(X_train, y_train)
# Pesos de clase manuales
from sklearn.utils.class_weight import
compute_class_weight
class_weights = compute_class_weight('balanced',
classes=np.unique(y_train), y=y_train)
weight_dict = dict(zip(np.unique(y_train), class_weights))
```

### Persistencia del Modelo: `joblib`

Guardar y cargar modelos entrenados.

```python
# Guardar modelo
import joblib
joblib.dump(model, 'trained_model.pkl')
# Cargar modelo
loaded_model = joblib.load('trained_model.pkl')
y_pred = loaded_model.predict(X_test)
# Guardar pipeline completo
joblib.dump(pipeline, 'preprocessing_pipeline.pkl')
loaded_pipeline =
joblib.load('preprocessing_pipeline.pkl')
# Alternativa usando pickle
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
```

## Rendimiento y Depuración

### Curvas de Aprendizaje: `learning_curve()`

Diagnosticar sobreajuste y subajuste.

```python
# Trazar curvas de aprendizaje
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores = learning_curve(
    model, X, y, cv=5, train_sizes=np.linspace(0.1, 1.0, 10)
)
plt.figure(figsize=(10, 6))
plt.plot(train_sizes, np.mean(train_scores, axis=1), 'o-',
label='Puntuación de Entrenamiento')
plt.plot(train_sizes, np.mean(val_scores, axis=1), 'o-',
label='Puntuación de Validación')
plt.xlabel('Tamaño del Conjunto de Entrenamiento')
plt.ylabel('Puntuación')
plt.legend()
```

### Curvas de Validación: `validation_curve()`

Analizar el efecto de los hiperparámetros.

```python
# Curva de validación para un hiperparámetro único
from sklearn.model_selection import validation_curve
param_range = [10, 50, 100, 200, 500]
train_scores, val_scores = validation_curve(
    RandomForestClassifier(random_state=42), X, y,
    param_name='n_estimators',
param_range=param_range, cv=5
)
plt.figure(figsize=(10, 6))
plt.plot(param_range, np.mean(train_scores, axis=1), 'o-',
label='Entrenamiento')
plt.plot(param_range, np.mean(val_scores, axis=1), 'o-',
label='Validación')
plt.xlabel('Número de Estimadores')
plt.ylabel('Puntuación')
```

### Visualización de Importancia de Características

Comprender qué características impulsan las predicciones del modelo.

```python
# Trazar importancia de características
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
plt.figure(figsize=(12, 8))
plt.title("Importancia de Características")
plt.bar(range(X.shape[1]), importances[indices])
plt.xticks(range(X.shape[1]), [X.columns[i] for i in indices],
rotation=90)
# Valores SHAP para interpretabilidad del modelo
# pip install shap
import shap
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_test)
shap.summary_plot(shap_values, X_test)
```

### Comparación de Modelos

Comparar múltiples algoritmos sistemáticamente.

```python
# Comparar múltiples modelos
from sklearn.model_selection import cross_val_score
models = {
    'Regresión Logística':
LogisticRegression(random_state=42),
    'Bosque Aleatorio':
RandomForestClassifier(random_state=42),
    'SVM': SVC(random_state=42),
    'Aumento de Gradiente':
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

## Configuración y Mejores Prácticas

### Estado Aleatorio y Reproducibilidad

Asegurar resultados consistentes entre ejecuciones.

```python
# Establecer estado aleatorio para
reproducibilidad
import numpy as np
np.random.seed(42)
# Establecer random_state en todos los
componentes sklearn
model =
RandomForestClassifier(random
_state=42)
train_test_split(X, y,
random_state=42)
# Para validación cruzada
cv = StratifiedKFold(n_splits=5,
shuffle=True, random_state=42)
```

### Memoria y Rendimiento

Optimizar para grandes conjuntos de datos y eficiencia computacional.

```python
# Usar n_jobs=-1 para
procesamiento paralelo
model =
RandomForestClassifier(n_jobs=
-1)
grid_search =
GridSearchCV(model,
param_grid, n_jobs=-1)
# Para grandes conjuntos de datos, usar
partial_fit cuando esté disponible
from sklearn.linear_model
import SGDClassifier
sgd = SGDClassifier()
# Procesar datos en fragmentos
for chunk in chunks:
    sgd.partial_fit(chunk_X,
chunk_y)
```

### Advertencias y Depuración

Manejar problemas comunes y depurar modelos.

```python
# Suprimir advertencias (usar con
cuidado)
import warnings
warnings.filterwarnings('ignore')
# Habilitar set_config de sklearn para
mejor depuración
from sklearn import set_config
set_config(display='diagram')  #
Visualización mejorada en Jupyter
# Comprobar si hay fuga de datos
from sklearn.model_selection
import cross_val_score
# Asegurar que el preprocesamiento se
realice dentro del bucle CV
```

## Enlaces Relevantes

- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/pandas">Hoja de Trucos de Pandas</router-link>
- <router-link to="/numpy">Hoja de Trucos de NumPy</router-link>
- <router-link to="/matplotlib">Hoja de Trucos de Matplotlib</router-link>
- <router-link to="/datascience">Hoja de Trucos de Ciencia de Datos</router-link>
- <router-link to="/database">Hoja de Trucos de Base de Datos</router-link>

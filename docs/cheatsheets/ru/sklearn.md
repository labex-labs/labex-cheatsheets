---
title: 'Шпаргалка по scikit-learn'
description: 'Изучите scikit-learn с нашей подробной шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/sklearn-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
scikit-learn Шпаргалка
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/sklearn">Изучите scikit-learn с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите машинное обучение с помощью scikit-learn через практические лаборатории и сценарии реального мира. LabEx предлагает комплексные курсы по scikit-learn, охватывающие необходимое предварительное преобразование данных, выбор модели, обучение, оценку и инжиниринг признаков. Освойте алгоритмы машинного обучения и создавайте предиктивные модели с помощью Python.
</base-disclaimer-content>
</base-disclaimer>

## Установка и Импорты

### Установка: `pip install scikit-learn`

Установка scikit-learn и общих зависимостей.

```bash
# Установить scikit-learn
pip install scikit-learn
# Установить с дополнительными пакетами
pip install scikit-learn pandas numpy matplotlib
# Обновить до последней версии
pip install scikit-learn --upgrade
```

### Основные Импорты

Стандартные импорты для рабочих процессов scikit-learn.

```python
# Основные импорты
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,
classification_report
# Общие алгоритмы
from sklearn.linear_model import LinearRegression,
LogisticRegression
from sklearn.ensemble import RandomForestClassifier,
GradientBoostingRegressor
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
```

### Проверка Версии

Проверка вашей установки scikit-learn.

```python
import sklearn
print(sklearn.__version__)
# Показать конфигурацию сборки
sklearn.show_versions()
```

### Загрузка Наборов Данных

Загрузка встроенных наборов данных для практики.

```python
from sklearn.datasets import load_iris, load_boston,
make_classification
# Загрузить примеры наборов данных
iris = load_iris()
X, y = iris.data, iris.target
# Сгенерировать синтетические данные
X_synth, y_synth = make_classification(n_samples=1000,
n_features=20, n_informative=10, random_state=42)
```

## Предварительная Обработка Данных

### Разделение на Обучающую/Тестовую Выборки: `train_test_split()`

Разделение данных на обучающие и тестовые наборы.

```python
# Базовое разделение (80% обучение, 20% тест)
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
random_state=42)
# Стратифицированное разделение для классификации
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
stratify=y, random_state=42)
# Множественное разделение
X_train, X_temp, y_train, y_temp =
train_test_split(X, y, test_size=0.4,
random_state=42)
X_val, X_test, y_val, y_test =
train_test_split(X_temp, y_temp,
test_size=0.5, random_state=42)
```

### Масштабирование Признаков: `StandardScaler()` / `MinMaxScaler()`

Нормализация признаков до схожих масштабов.

```python
# Стандартизация (среднее=0, стд=1)
from sklearn.preprocessing import
StandardScaler, MinMaxScaler
scaler = StandardScaler()
X_scaled =
scaler.fit_transform(X_train)
X_test_scaled =
scaler.transform(X_test)
# Масштабирование Min-Max (диапазон 0-1)
minmax_scaler = MinMaxScaler()
X_minmax =
minmax_scaler.fit_transform(X_train)
X_test_minmax =
minmax_scaler.transform(X_test)
```

### Кодирование: `LabelEncoder()` / `OneHotEncoder()`

Преобразование категориальных переменных в числовой формат.

```python
# Кодирование меток для целевой переменной
from sklearn.preprocessing import
LabelEncoder, OneHotEncoder
label_encoder = LabelEncoder()
y_encoded =
label_encoder.fit_transform(y)
# One-hot кодирование для категориальных
признаков
from sklearn.preprocessing import
OneHotEncoder
encoder =
OneHotEncoder(sparse=False,
drop='first')
X_encoded =
encoder.fit_transform(X_categorical)
# Получить имена признаков
feature_names =
encoder.get_feature_names_out()
```

## Обучение с Учителем - Классификация

### Логистическая Регрессия: `LogisticRegression()`

Линейная модель для бинарной и многоклассовой классификации.

```python
# Базовая логистическая регрессия
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression(random_state=42)
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
y_proba = log_reg.predict_proba(X_test)
# С регуляризацией
log_reg_l2 = LogisticRegression(C=0.1, penalty='l2')
log_reg_l1 = LogisticRegression(C=0.1, penalty='l1',
solver='liblinear')
```

### Дерево Решений: `DecisionTreeClassifier()`

Модель на основе деревьев для задач классификации.

```python
# Классификатор дерева решений
from sklearn.tree import DecisionTreeClassifier
tree_clf = DecisionTreeClassifier(max_depth=5,
random_state=42)
tree_clf.fit(X_train, y_train)
y_pred = tree_clf.predict(X_test)
# Важность признаков
importances = tree_clf.feature_importances_
# Визуализация дерева
from sklearn.tree import plot_tree
plot_tree(tree_clf, max_depth=3, filled=True)
```

### Случайный Лес: `RandomForestClassifier()`

Ансамблевый метод, объединяющий несколько деревьев решений.

```python
# Классификатор случайного леса
from sklearn.ensemble import RandomForestClassifier
rf_clf = RandomForestClassifier(n_estimators=100,
random_state=42)
rf_clf.fit(X_train, y_train)
y_pred = rf_clf.predict(X_test)
# Настройка гиперпараметров
rf_clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42
)
```

### Метод Опорных Векторов: `SVC()`

Мощный классификатор, использующий ядерные методы.

```python
# Классификатор SVM
from sklearn.svm import SVC
svm_clf = SVC(kernel='rbf', C=1.0, gamma='scale',
random_state=42)
svm_clf.fit(X_train, y_train)
y_pred = svm_clf.predict(X_test)
# Различные ядра
svm_linear = SVC(kernel='linear')
svm_poly = SVC(kernel='poly', degree=3)
svm_rbf = SVC(kernel='rbf', gamma=0.1)
```

## Обучение с Учителем - Регрессия

### Линейная Регрессия: `LinearRegression()`

Базовая линейная модель для непрерывных целевых переменных.

```python
# Простая линейная регрессия
from sklearn.linear_model import LinearRegression
lin_reg = LinearRegression()
lin_reg.fit(X_train, y_train)
y_pred = lin_reg.predict(X_test)
# Получить коэффициенты и сдвиг
coefficients = lin_reg.coef_
intercept = lin_reg.intercept_
print(f"R² score: {lin_reg.score(X_test, y_test)}")
```

### Регрессия Ридж: `Ridge()`

Линейная регрессия с L2-регуляризацией.

```python
# Регрессия Ридж (L2-регуляризация)
from sklearn.linear_model import Ridge
ridge_reg = Ridge(alpha=1.0)
ridge_reg.fit(X_train, y_train)
y_pred = ridge_reg.predict(X_test)
# Кросс-валидация для выбора alpha
from sklearn.linear_model import RidgeCV
ridge_cv = RidgeCV(alphas=[0.1, 1.0, 10.0])
ridge_cv.fit(X_train, y_train)
```

### Регрессия Лассо: `Lasso()`

Линейная регрессия с L1-регуляризацией для отбора признаков.

```python
# Регрессия Лассо (L1-регуляризация)
from sklearn.linear_model import Lasso
lasso_reg = Lasso(alpha=0.1)
lasso_reg.fit(X_train, y_train)
y_pred = lasso_reg.predict(X_test)
# Отбор признаков (ненулевые коэффициенты)
selected_features = X.columns[lasso_reg.coef_ != 0]
print(f"Selected features: {len(selected_features)}")
```

### Регрессия Случайного Леса: `RandomForestRegressor()`

Ансамблевый метод для задач регрессии.

```python
# Регрессор случайного леса
from sklearn.ensemble import RandomForestRegressor
rf_reg = RandomForestRegressor(n_estimators=100,
random_state=42)
rf_reg.fit(X_train, y_train)
y_pred = rf_reg.predict(X_test)
# Важность признаков для регрессии
feature_importance = rf_reg.feature_importances_
```

## Оценка Модели

### Метрики Классификации

Оценка производительности модели классификации.

```python
# Базовая точность
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# Подробный отчет о классификации
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred))
# Матрица ошибок
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
```

### Кривая ROC и AUC

Построение кривой ROC и вычисление площади под кривой.

```python
# Кривая ROC для бинарной классификации
from sklearn.metrics import roc_curve, auc
fpr, tpr, thresholds = roc_curve(y_test, y_proba[:, 1])
roc_auc = auc(fpr, tpr)
# Построение кривой ROC
import matplotlib.pyplot as plt
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.legend()
```

### Метрики Регрессии

Оценка производительности модели регрессии.

```python
# Метрики регрессии
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

### Кросс-Валидация

Надежная оценка модели с использованием кросс-валидации.

```python
# K-блочная кросс-валидация
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"CV Accuracy: {cv_scores.mean():.4f} (+/-
{cv_scores.std() * 2:.4f})")
# Стратифицированная K-fold для несбалансированных наборов данных
skf = StratifiedKFold(n_splits=5, shuffle=True,
random_state=42)
cv_scores = cross_val_score(model, X, y, cv=skf,
scoring='f1_weighted')
```

## Обучение без Учителя

### Кластеризация K-Means: `KMeans()`

Разделение данных на k кластеров.

```python
# Кластеризация K-средних
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
cluster_labels = kmeans.fit_predict(X)
centroids = kmeans.cluster_centers_
# Определение оптимального числа кластеров (метод локтя)
inertias = []
K_range = range(1, 11)
for k in K_range:
    kmeans = KMeans(n_clusters=k, random_state=42)
    kmeans.fit(X)
    inertias.append(kmeans.inertia_)
```

### Метод Главных Компонент: `PCA()`

Техника снижения размерности.

```python
# PCA для снижения размерности
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)
explained_variance = pca.explained_variance_ratio_
# Найти оптимальное число компонент
pca_full = PCA()
pca_full.fit(X)
cumsum =
np.cumsum(pca_full.explained_variance_ratio_)
# Найти компоненты для 95% дисперсии
n_components = np.argmax(cumsum >= 0.95) + 1
```

### Кластеризация DBSCAN: `DBSCAN()`

Алгоритм кластеризации на основе плотности.

```python
# Кластеризация DBSCAN
from sklearn.cluster import DBSCAN
dbscan = DBSCAN(eps=0.5, min_samples=5)
cluster_labels = dbscan.fit_predict(X)
n_clusters = len(set(cluster_labels)) - (1 if -1 in
cluster_labels else 0)
n_noise = list(cluster_labels).count(-1)
print(f"Number of clusters: {n_clusters}")
print(f"Number of noise points: {n_noise}")
```

### Иерархическая Кластеризация: `AgglomerativeClustering()`

Построение иерархии кластеров.

```python
# Агломеративная кластеризация
from sklearn.cluster import AgglomerativeClustering
agg_clustering = AgglomerativeClustering(n_clusters=3,
linkage='ward')
cluster_labels = agg_clustering.fit_predict(X)
# Визуализация дендрограммы
from scipy.cluster.hierarchy import dendrogram, linkage
linked = linkage(X, 'ward')
plt.figure(figsize=(12, 8))
dendrogram(linked)
```

## Выбор Модели и Настройка Гиперпараметров

### Поиск по Сетке: `GridSearchCV()`

Исчерпывающий поиск по сетке параметров.

```python
# Поиск по сетке для настройки гиперпараметров
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

### Случайный Поиск: `RandomizedSearchCV()`

Случайная выборка из распределений параметров.

```python
# Случайный поиск (быстрее для больших пространств параметров)
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

### Конвейер: `Pipeline()`

Объединение шагов предварительной обработки и моделирования.

```python
# Создание конвейера предварительной обработки и моделирования
from sklearn.pipeline import Pipeline
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier(random_state=42))
])
pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)
# Конвейер с поиском по сетке
param_grid = {
    'classifier__n_estimators': [100, 200],
    'classifier__max_depth': [3, 5, None]
}
grid_search = GridSearchCV(pipeline, param_grid, cv=5)
grid_search.fit(X_train, y_train)
```

### Отбор Признаков: `SelectKBest()` / `RFE()`

Выбор наиболее информативных признаков.

```python
# Унивариантный отбор признаков
from sklearn.feature_selection import SelectKBest,
f_classif
selector = SelectKBest(score_func=f_classif, k=10)
X_selected = selector.fit_transform(X_train, y_train)
selected_features = X.columns[selector.get_support()]
# Рекурсивное исключение признаков
from sklearn.feature_selection import RFE
rfe = RFE(RandomForestClassifier(random_state=42),
n_features_to_select=10)
X_rfe = rfe.fit_transform(X_train, y_train)
```

## Продвинутые Методы

### Ансамблевые Методы: `VotingClassifier()` / `BaggingClassifier()`

Объединение нескольких моделей для лучшей производительности.

```python
# Классификатор голосования (ансамбль различных алгоритмов)
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
# Классификатор бэггинга
from sklearn.ensemble import BaggingClassifier
bagging_clf = BaggingClassifier(DecisionTreeClassifier(),
n_estimators=100, random_state=42)
bagging_clf.fit(X_train, y_train)
```

### Градиентный Бустинг: `GradientBoostingClassifier()`

Последовательный ансамблевый метод с коррекцией ошибок.

```python
# Классификатор градиентного бустинга
from sklearn.ensemble import
GradientBoostingClassifier
gb_clf = GradientBoostingClassifier(n_estimators=100,
learning_rate=0.1, random_state=42)
gb_clf.fit(X_train, y_train)
y_pred = gb_clf.predict(X_test)
# Важность признаков
importances = gb_clf.feature_importances_
# Кривая обучения
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores =
learning_curve(gb_clf, X, y, cv=5)
```

### Обработка Несбалансированных Данных: `SMOTE()` / Веса Классов

Устранение дисбаланса классов в наборах данных.

```python
# Установка imbalanced-learn: pip install imbalanced-learn
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train,
y_train)
# Использование весов классов
rf_balanced =
RandomForestClassifier(class_weight='balanced',
random_state=42)
rf_balanced.fit(X_train, y_train)
# Ручные веса классов
from sklearn.utils.class_weight import
compute_class_weight
class_weights = compute_class_weight('balanced',
classes=np.unique(y_train), y=y_train)
weight_dict = dict(zip(np.unique(y_train), class_weights))
```

### Сохранение Модели: `joblib`

Сохранение и загрузка обученных моделей.

```python
# Сохранить модель
import joblib
joblib.dump(model, 'trained_model.pkl')
# Загрузить модель
loaded_model = joblib.load('trained_model.pkl')
y_pred = loaded_model.predict(X_test)
# Сохранить весь конвейер
joblib.dump(pipeline, 'preprocessing_pipeline.pkl')
loaded_pipeline =
joblib.load('preprocessing_pipeline.pkl')
# Альтернатива с использованием pickle
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
```

## Производительность и Отладка

### Кривые Обучения: `learning_curve()`

Диагностика переобучения и недообучения.

```python
# Построение кривых обучения
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

### Кривые Валидации: `validation_curve()`

Анализ влияния гиперпараметров.

```python
# Кривая валидации для одного гиперпараметра
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

### Визуализация Важности Признаков

Понимание того, какие признаки определяют прогнозы модели.

```python
# Построение важности признаков
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
plt.figure(figsize=(12, 8))
plt.title("Feature Importance")
plt.bar(range(X.shape[1]), importances[indices])
plt.xticks(range(X.shape[1]), [X.columns[i] for i in indices],
rotation=90)
# Значения SHAP для интерпретируемости модели
# pip install shap
import shap
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_test)
shap.summary_plot(shap_values, X_test)
```

### Сравнение Моделей

Систематическое сравнение нескольких алгоритмов.

```python
# Сравнение нескольких моделей
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

## Конфигурация и Лучшие Практики

### Случайное Состояние и Воспроизводимость

Обеспечение согласованных результатов при каждом запуске.

```python
# Установка случайного состояния для
воспроизводимости
import numpy as np
np.random.seed(42)
# Установка random_state во всех
компонентах sklearn
model =
RandomForestClassifier(random
_state=42)
train_test_split(X, y,
random_state=42)
# Для кросс-валидации
cv = StratifiedKFold(n_splits=5,
shuffle=True, random_state=42)
```

### Память и Производительность

Оптимизация для больших наборов данных и вычислительной эффективности.

```python
# Использование n_jobs=-1 для параллельной
обработки
model =
RandomForestClassifier(n_jobs=
-1)
grid_search =
GridSearchCV(model,
param_grid, n_jobs=-1)
# Для больших наборов данных используйте
partial_fit, когда это возможно
from sklearn.linear_model
import SGDClassifier
sgd = SGDClassifier()
# Обработка данных по частям
for chunk in chunks:
    sgd.partial_fit(chunk_X,
chunk_y)
```

### Предупреждения и Отладка

Обработка распространенных проблем и отладка моделей.

```python
# Подавление предупреждений (использовать
осторожно)
import warnings
warnings.filterwarnings('ignore')
# Включение set_config sklearn для
улучшенной отладки
from sklearn import set_config
set_config(display='diagram')  #
Улучшенный дисплей в Jupyter
# Проверка на утечку данных
from sklearn.model_selection
import cross_val_score
# Убедитесь, что предварительная
обработка выполняется внутри цикла CV
```

## Соответствующие Ссылки

- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/pandas">Шпаргалка по Pandas</router-link>
- <router-link to="/numpy">Шпаргалка по NumPy</router-link>
- <router-link to="/matplotlib">Шпаргалка по Matplotlib</router-link>
- <router-link to="/datascience">Шпаргалка по Науке о Данных</router-link>
- <router-link to="/database">Шпаргалка по Базам Данных</router-link>

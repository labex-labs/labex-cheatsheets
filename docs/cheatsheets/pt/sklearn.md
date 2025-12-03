---
title: 'Folha de Cola scikit-learn | LabEx'
description: 'Aprenda machine learning com scikit-learn usando esta folha de cola abrangente. Referência rápida para algoritmos de ML, treinamento de modelos, pré-processamento, avaliação e fluxos de trabalho de aprendizado de máquina em Python.'
pdfUrl: '/cheatsheets/pdf/sklearn-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
scikit-learn Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/sklearn">Aprenda scikit-learn com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda machine learning com scikit-learn através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de scikit-learn que cobrem pré-processamento de dados essencial, seleção de modelos, treinamento, avaliação e engenharia de recursos. Domine algoritmos de machine learning e construa modelos preditivos com Python.
</base-disclaimer-content>
</base-disclaimer>

## Instalação e Importações

### Instalação: `pip install scikit-learn`

Instale scikit-learn e dependências comuns.

```bash
# Instalar scikit-learn
pip install scikit-learn
# Instalar com pacotes adicionais
pip install scikit-learn pandas numpy matplotlib
# Atualizar para a versão mais recente
pip install scikit-learn --upgrade
```

### Importações Essenciais

Importações padrão para fluxos de trabalho do scikit-learn.

```python
# Importações principais
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,
classification_report
# Algoritmos comuns
from sklearn.linear_model import LinearRegression,
LogisticRegression
from sklearn.ensemble import RandomForestClassifier,
GradientBoostingRegressor
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
```

### Verificar Versão

Verifique sua instalação do scikit-learn.

```python
import sklearn
print(sklearn.__version__)
# Mostrar configuração de compilação
sklearn.show_versions()
```

### Carregamento de Conjunto de Dados

Carregue conjuntos de dados internos para prática.

```python
from sklearn.datasets import load_iris, load_boston,
make_classification
# Carregar conjuntos de dados de amostra
iris = load_iris()
X, y = iris.data, iris.target
# Gerar dados sintéticos
X_synth, y_synth = make_classification(n_samples=1000,
n_features=20, n_informative=10, random_state=42)
```

## Pré-processamento de Dados

### Divisão Treino-Teste: `train_test_split()`

Divida os dados em conjuntos de treinamento e teste.

```python
# Divisão básica (80% treino, 20% teste)
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
random_state=42)
# Divisão estratificada para classificação
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
stratify=y, random_state=42)
# Múltiplas divisões
X_train, X_temp, y_train, y_temp =
train_test_split(X, y, test_size=0.4,
random_state=42)
X_val, X_test, y_val, y_test =
train_test_split(X_temp, y_temp,
test_size=0.5, random_state=42)
```

<BaseQuiz id="sklearn-split-1" correct="B">
  <template #question>
    Por que é importante dividir os dados em conjuntos de treinamento e teste?
  </template>
  
  <BaseQuizOption value="A">Para reduzir o tamanho do conjunto de dados</BaseQuizOption>
  <BaseQuizOption value="B" correct>Para avaliar o desempenho do modelo em dados não vistos e prevenir o overfitting</BaseQuizOption>
  <BaseQuizOption value="C">Para acelerar o treinamento do modelo</BaseQuizOption>
  <BaseQuizOption value="D">Para balancear o conjunto de dados</BaseQuizOption>
  
  <BaseQuizAnswer>
    Dividir os dados permite treinar o modelo em uma porção e testá-lo em outra. Isso ajuda a avaliar o quão bem o modelo generaliza para novos dados não vistos e previne o overfitting aos dados de treinamento.
  </BaseQuizAnswer>
</BaseQuiz>

### Escalonamento de Recursos: `StandardScaler()` / `MinMaxScaler()`

Normalizar recursos para escalas semelhantes.

```python
# Padronização (média=0, dp=1)
from sklearn.preprocessing import
StandardScaler, MinMaxScaler
scaler = StandardScaler()
X_scaled =
scaler.fit_transform(X_train)
X_test_scaled =
scaler.transform(X_test)
# Escalonamento Min-Max (intervalo 0-1)
minmax_scaler = MinMaxScaler()
X_minmax =
minmax_scaler.fit_transform(X_train)
X_test_minmax =
minmax_scaler.transform(X_test)
```

<BaseQuiz id="sklearn-scaling-1" correct="A">
  <template #question>
    Por que o escalonamento de recursos é importante em machine learning?
  </template>
  
  <BaseQuizOption value="A" correct>Garante que todos os recursos estejam em uma escala semelhante, impedindo que alguns recursos dominem</BaseQuizOption>
  <BaseQuizOption value="B">Remove valores ausentes</BaseQuizOption>
  <BaseQuizOption value="C">Aumenta o número de recursos</BaseQuizOption>
  <BaseQuizOption value="D">Remove linhas duplicadas</BaseQuizOption>
  
  <BaseQuizAnswer>
    O escalonamento de recursos é importante porque algoritmos como SVM, KNN e redes neurais são sensíveis às escalas dos recursos. Sem escalonamento, recursos com intervalos maiores podem dominar o processo de aprendizado do modelo.
  </BaseQuizAnswer>
</BaseQuiz>

### Codificação: `LabelEncoder()` / `OneHotEncoder()`

Converter variáveis categóricas em formato numérico.

```python
# Codificação de rótulos para a variável alvo
from sklearn.preprocessing import
LabelEncoder, OneHotEncoder
label_encoder = LabelEncoder()
y_encoded =
label_encoder.fit_transform(y)
# Codificação one-hot para recursos categóricos
from sklearn.preprocessing import
OneHotEncoder
encoder =
OneHotEncoder(sparse=False,
drop='first')
X_encoded =
encoder.fit_transform(X_categorical)
# Obter nomes dos recursos
feature_names =
encoder.get_feature_names_out()
```

## Aprendizado Supervisionado - Classificação

### Regressão Logística: `LogisticRegression()`

Modelo linear para classificação binária e multiclasse.

```python
# Regressão logística básica
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression(random_state=42)
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
y_proba = log_reg.predict_proba(X_test)
# Com regularização
log_reg_l2 = LogisticRegression(C=0.1, penalty='l2')
log_reg_l1 = LogisticRegression(C=0.1, penalty='l1',
solver='liblinear')
```

### Árvore de Decisão: `DecisionTreeClassifier()`

Modelo baseado em árvore para tarefas de classificação.

```python
# Classificador de árvore de decisão
from sklearn.tree import DecisionTreeClassifier
tree_clf = DecisionTreeClassifier(max_depth=5,
random_state=42)
tree_clf.fit(X_train, y_train)
y_pred = tree_clf.predict(X_test)
# Importância do recurso
importances = tree_clf.feature_importances_
# Visualizar árvore
from sklearn.tree import plot_tree
plot_tree(tree_clf, max_depth=3, filled=True)
```

### Floresta Aleatória: `RandomForestClassifier()`

Método de conjunto que combina múltiplas árvores de decisão.

```python
# Classificador de floresta aleatória
from sklearn.ensemble import RandomForestClassifier
rf_clf = RandomForestClassifier(n_estimators=100,
random_state=42)
rf_clf.fit(X_train, y_train)
y_pred = rf_clf.predict(X_test)
# Ajuste de hiperparâmetros
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
    O que <code>n_estimators</code> controla em RandomForestClassifier?
  </template>
  
  <BaseQuizOption value="A" correct>O número de árvores de decisão na floresta</BaseQuizOption>
  <BaseQuizOption value="B">A profundidade máxima de cada árvore</BaseQuizOption>
  <BaseQuizOption value="C">O número de recursos a serem considerados</BaseQuizOption>
  <BaseQuizOption value="D">A semente aleatória</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>n_estimators</code> especifica quantas árvores de decisão incluir na floresta aleatória. Mais árvores geralmente melhoram o desempenho, mas aumentam o tempo de computação. O padrão é geralmente 100.
  </BaseQuizAnswer>
</BaseQuiz>

### Máquina de Vetores de Suporte: `SVC()`

Classificador poderoso que usa métodos de kernel.

```python
# Classificador SVM
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

## Aprendizado Supervisionado - Regressão

### Regressão Linear: `LinearRegression()`

Modelo linear básico para variáveis alvo contínuas.

```python
# Regressão linear simples
from sklearn.linear_model import LinearRegression
lin_reg = LinearRegression()
lin_reg.fit(X_train, y_train)
y_pred = lin_reg.predict(X_test)
# Obter coeficientes e intercepto
coefficients = lin_reg.coef_
intercept = lin_reg.intercept_
print(f"Pontuação R²: {lin_reg.score(X_test, y_test)}")
```

### Regressão Ridge: `Ridge()`

Regressão linear com regularização L2.

```python
# Regressão Ridge (regularização L2)
from sklearn.linear_model import Ridge
ridge_reg = Ridge(alpha=1.0)
ridge_reg.fit(X_train, y_train)
y_pred = ridge_reg.predict(X_test)
# Validação cruzada para seleção de alpha
from sklearn.linear_model import RidgeCV
ridge_cv = RidgeCV(alphas=[0.1, 1.0, 10.0])
ridge_cv.fit(X_train, y_train)
```

### Regressão Lasso: `Lasso()`

Regressão linear com regularização L1 para seleção de recursos.

```python
# Regressão Lasso (regularização L1)
from sklearn.linear_model import Lasso
lasso_reg = Lasso(alpha=0.1)
lasso_reg.fit(X_train, y_train)
y_pred = lasso_reg.predict(X_test)
# Seleção de recursos (coeficientes diferentes de zero)
selected_features = X.columns[lasso_reg.coef_ != 0]
print(f"Recursos selecionados: {len(selected_features)}")
```

### Regressão Floresta Aleatória: `RandomForestRegressor()`

Método de conjunto para tarefas de regressão.

```python
# Regressor de floresta aleatória
from sklearn.ensemble import RandomForestRegressor
rf_reg = RandomForestRegressor(n_estimators=100,
random_state=42)
rf_reg.fit(X_train, y_train)
y_pred = rf_reg.predict(X_test)
# Importância do recurso para regressão
feature_importance = rf_reg.feature_importances_
```

## Avaliação de Modelo

### Métricas de Classificação

Avalie o desempenho do modelo de classificação.

```python
# Precisão básica
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# Relatório de classificação detalhado
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred))
# Matriz de confusão
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
```

### Curva ROC e AUC

Plote a curva ROC e calcule a Área Sob a Curva.

```python
# Curva ROC para classificação binária
from sklearn.metrics import roc_curve, auc
fpr, tpr, thresholds = roc_curve(y_test, y_proba[:, 1])
roc_auc = auc(fpr, tpr)
# Plotar curva ROC
import matplotlib.pyplot as plt
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, label=f'Curva ROC (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel('Taxa de Falso Positivo')
plt.ylabel('Taxa de Verdadeiro Positivo')
plt.legend()
```

### Métricas de Regressão

Avalie o desempenho do modelo de regressão.

```python
# Métricas de regressão
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

### Validação Cruzada

Avaliação robusta do modelo usando validação cruzada.

```python
# Validação cruzada K-fold
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"Precisão CV: {cv_scores.mean():.4f} (+/-
{cv_scores.std() * 2:.4f})")
# K-fold Estratificado para conjuntos de dados desbalanceados
skf = StratifiedKFold(n_splits=5, shuffle=True,
random_state=42)
cv_scores = cross_val_score(model, X, y, cv=skf,
scoring='f1_weighted')
```

## Aprendizado Não Supervisionado

### Agrupamento K-Means: `KMeans()`

Particionar dados em k clusters.

```python
# Agrupamento K-means
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
cluster_labels = kmeans.fit_predict(X)
centroids = kmeans.cluster_centers_
# Determinar o número ideal de clusters (método do cotovelo)
inertias = []
K_range = range(1, 11)
for k in K_range:
    kmeans = KMeans(n_clusters=k, random_state=42)
    kmeans.fit(X)
    inertias.append(kmeans.inertia_)
```

### Análise de Componentes Principais: `PCA()`

Técnica de redução de dimensionalidade.

```python
# PCA para redução de dimensionalidade
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)
explained_variance = pca.explained_variance_ratio_
# Encontrar o número ideal de componentes
pca_full = PCA()
pca_full.fit(X)
cumsum =
np.cumsum(pca_full.explained_variance_ratio_)
# Encontrar componentes para 95% de variância
n_components = np.argmax(cumsum >= 0.95) + 1
```

### Agrupamento DBSCAN: `DBSCAN()`

Algoritmo de agrupamento baseado em densidade.

```python
# Agrupamento DBSCAN
from sklearn.cluster import DBSCAN
dbscan = DBSCAN(eps=0.5, min_samples=5)
cluster_labels = dbscan.fit_predict(X)
n_clusters = len(set(cluster_labels)) - (1 if -1 in
cluster_labels else 0)
n_noise = list(cluster_labels).count(-1)
print(f"Número de clusters: {n_clusters}")
print(f"Número de pontos de ruído: {n_noise}")
```

### Agrupamento Hierárquico: `AgglomerativeClustering()`

Construir hierarquia de clusters.

```python
# Agrupamento aglomerativo
from sklearn.cluster import AgglomerativeClustering
agg_clustering = AgglomerativeClustering(n_clusters=3,
linkage='ward')
cluster_labels = agg_clustering.fit_predict(X)
# Visualização do dendrograma
from scipy.cluster.hierarchy import dendrogram, linkage
linked = linkage(X, 'ward')
plt.figure(figsize=(12, 8))
dendrogram(linked)
```

## Seleção de Modelo e Ajuste de Hiperparâmetros

### Busca em Grade: `GridSearchCV()`

Busca exaustiva na grade de parâmetros.

```python
# Busca em grade para ajuste de hiperparâmetros
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

### Busca Aleatória: `RandomizedSearchCV()`

Amostragem aleatória de distribuições de parâmetros.

```python
# Busca aleatória (mais rápida para grandes espaços de parâmetros)
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

Encadeamento de etapas de pré-processamento e modelagem.

```python
# Criar pipeline de pré-processamento e modelagem
from sklearn.pipeline import Pipeline
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier(random_state=42))
])
pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)
# Busca em grade com pipeline
param_grid = {
    'classifier__n_estimators': [100, 200],
    'classifier__max_depth': [3, 5, None]
}
grid_search = GridSearchCV(pipeline, param_grid, cv=5)
grid_search.fit(X_train, y_train)
```

### Seleção de Recursos: `SelectKBest()` / `RFE()`

Selecione os recursos mais informativos.

```python
# Seleção de recursos univariada
from sklearn.feature_selection import SelectKBest,
f_classif
selector = SelectKBest(score_func=f_classif, k=10)
X_selected = selector.fit_transform(X_train, y_train)
selected_features = X.columns[selector.get_support()]
# Eliminação Recursiva de Recursos
from sklearn.feature_selection import RFE
rfe = RFE(RandomForestClassifier(random_state=42),
n_features_to_select=10)
X_rfe = rfe.fit_transform(X_train, y_train)
```

## Técnicas Avançadas

### Métodos de Conjunto: `VotingClassifier()` / `BaggingClassifier()`

Combine múltiplos modelos para melhor desempenho.

```python
# Classificador de votação (conjunto de diferentes algoritmos)
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
# Classificador de Bagging
from sklearn.ensemble import BaggingClassifier
bagging_clf = BaggingClassifier(DecisionTreeClassifier(),
n_estimators=100, random_state=42)
bagging_clf.fit(X_train, y_train)
```

### Aumento de Gradiente: `GradientBoostingClassifier()`

Método de conjunto sequencial com correção de erro.

```python
# Classificador de aumento de gradiente
from sklearn.ensemble import
GradientBoostingClassifier
gb_clf = GradientBoostingClassifier(n_estimators=100,
learning_rate=0.1, random_state=42)
gb_clf.fit(X_train, y_train)
y_pred = gb_clf.predict(X_test)
# Importância do recurso
importances = gb_clf.feature_importances_
# Curva de aprendizado
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores =
learning_curve(gb_clf, X, y, cv=5)
```

### Lidar com Dados Desbalanceados: `SMOTE()` / Pesos de Classe

Aborde o desequilíbrio de classes em conjuntos de dados.

```python
# Instalar imbalanced-learn: pip install imbalanced-learn
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train,
y_train)
# Usando pesos de classe
rf_balanced =
RandomForestClassifier(class_weight='balanced',
random_state=42)
rf_balanced.fit(X_train, y_train)
# Pesos de classe manuais
from sklearn.utils.class_weight import
compute_class_weight
class_weights = compute_class_weight('balanced',
classes=np.unique(y_train), y=y_train)
weight_dict = dict(zip(np.unique(y_train), class_weights))
```

### Persistência de Modelo: `joblib`

Salvar e carregar modelos treinados.

```python
# Salvar modelo
import joblib
joblib.dump(model, 'trained_model.pkl')
# Carregar modelo
loaded_model = joblib.load('trained_model.pkl')
y_pred = loaded_model.predict(X_test)
# Salvar pipeline inteiro
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

## Desempenho e Depuração

### Curvas de Aprendizado: `learning_curve()`

Diagnosticar overfitting e underfitting.

```python
# Plotar curvas de aprendizado
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores = learning_curve(
    model, X, y, cv=5, train_sizes=np.linspace(0.1, 1.0, 10)
)
plt.figure(figsize=(10, 6))
plt.plot(train_sizes, np.mean(train_scores, axis=1), 'o-',
label='Pontuação de Treinamento')
plt.plot(train_sizes, np.mean(val_scores, axis=1), 'o-',
label='Pontuação de Validação')
plt.xlabel('Tamanho do Conjunto de Treinamento')
plt.ylabel('Pontuação')
plt.legend()
```

### Curvas de Validação: `validation_curve()`

Analisar o efeito dos hiperparâmetros.

```python
# Curva de validação para hiperparâmetro único
from sklearn.model_selection import validation_curve
param_range = [10, 50, 100, 200, 500]
train_scores, val_scores = validation_curve(
    RandomForestClassifier(random_state=42), X, y,
    param_name='n_estimators',
param_range=param_range, cv=5
)
plt.figure(figsize=(10, 6))
plt.plot(param_range, np.mean(train_scores, axis=1), 'o-',
label='Treinamento')
plt.plot(param_range, np.mean(val_scores, axis=1), 'o-',
label='Validação')
plt.xlabel('Número de Estimadores')
plt.ylabel('Pontuação')
```

### Visualização da Importância do Recurso

Entenda quais recursos impulsionam as previsões do modelo.

```python
# Plotar importância do recurso
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
plt.figure(figsize=(12, 8))
plt.title("Importância do Recurso")
plt.bar(range(X.shape[1]), importances[indices])
plt.xticks(range(X.shape[1]), [X.columns[i] for i in indices],
rotation=90)
# Valores SHAP para interpretabilidade do modelo
# pip install shap
import shap
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_test)
shap.summary_plot(shap_values, X_test)
```

### Comparação de Modelos

Compare algoritmos múltiplos sistematicamente.

```python
# Comparar múltiplos modelos
from sklearn.model_selection import cross_val_score
models = {
    'Regressão Logística':
LogisticRegression(random_state=42),
    'Floresta Aleatória':
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

## Configuração e Melhores Práticas

### Estado Aleatório e Reprodutibilidade

Garanta resultados consistentes entre execuções.

```python
# Definir estado aleatório para
reprodutibilidade
import numpy as np
np.random.seed(42)
# Definir random_state em todos os
componentes sklearn
model =
RandomForestClassifier(random
_state=42)
train_test_split(X, y,
random_state=42)
# Para validação cruzada
cv = StratifiedKFold(n_splits=5,
shuffle=True, random_state=42)
```

### Memória e Desempenho

Otimizar para grandes conjuntos de dados e eficiência computacional.

```python
# Usar n_jobs=-1 para
processamento paralelo
model =
RandomForestClassifier(n_jobs=
-1)
grid_search =
GridSearchCV(model,
param_grid, n_jobs=-1)
# Para grandes conjuntos de dados, usar
partial_fit quando disponível
from sklearn.linear_model
import SGDClassifier
sgd = SGDClassifier()
# Processar dados em blocos
for chunk in chunks:
    sgd.partial_fit(chunk_X,
chunk_y)
```

### Avisos e Depuração

Lidar com problemas comuns e depurar modelos.

```python
# Suprimir avisos (use com
cuidado)
import warnings
warnings.filterwarnings('ignore')
# Habilitar set_config do sklearn para
melhor depuração
from sklearn import set_config
set_config(display='diagram')  #
Exibição aprimorada no Jupyter
# Verificar vazamento de dados
from sklearn.model_selection
import cross_val_score
# Garantir que o pré-processamento seja
feito dentro do loop CV
```

## Links Relevantes

- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/pandas">Pandas Cheatsheet</router-link>
- <router-link to="/numpy">NumPy Cheatsheet</router-link>
- <router-link to="/matplotlib">Matplotlib Cheatsheet</router-link>
- <router-link to="/datascience">Data Science Cheatsheet</router-link>
- <router-link to="/database">Database Cheatsheet</router-link>

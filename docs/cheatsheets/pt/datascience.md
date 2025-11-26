---
title: 'Folha de Cola de Ciência de Dados'
description: 'Aprenda Ciência de Dados com nossa folha de cola abrangente cobrindo comandos essenciais, conceitos e melhores práticas.'
pdfUrl: '/cheatsheets/pdf/data-science-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas de Ciência de Dados
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/datascience">Aprenda Ciência de Dados com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda ciência de dados através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de ciência de dados cobrindo bibliotecas essenciais do Python, manipulação de dados, análise estatística, aprendizado de máquina e visualização de dados. Domine técnicas de coleta, limpeza, análise de dados e implantação de modelos.
</base-disclaimer-content>
</base-disclaimer>

## Bibliotecas Essenciais do Python

### Pilha Central de Ciência de Dados

Bibliotecas chave como NumPy, Pandas, Matplotlib, Seaborn e scikit-learn formam a base dos fluxos de trabalho de ciência de dados.

```python
# Importações essenciais para ciência de dados
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

Pacote fundamental para computação numérica com Python.

```python
# Criar arrays
arr = np.array([1, 2, 3, 4, 5])
matrix = np.array([[1, 2], [3, 4]])
# Operações básicas
np.mean(arr)       # Média
np.std(arr)        # Desvio padrão
np.reshape(arr, (5, 1))  # Remodelar array
# Gerar dados
np.random.normal(0, 1, 100)  # Distribuição
normal aleatória
```

### Pandas: `import pandas as pd`

Biblioteca para manipulação e análise de dados.

```python
# Criar DataFrame
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
# Ler dados
df = pd.read_csv('data.csv')
# Exploração básica
df.head()          # Primeiras 5 linhas
df.info()          # Tipos de dados e valores ausentes
df.describe()      # Estatísticas resumidas
# Manipulação de dados
df.groupby('column').mean()
df.fillna(df.mean())  # Lidar com valores ausentes
```

### Matplotlib & Seaborn: Visualização

Criação de visualizações estatísticas e gráficos.

```python
# Fundamentos do Matplotlib
plt.plot(x, y)
plt.hist(data, bins=20)
plt.scatter(x, y)
plt.show()
# Seaborn para gráficos estatísticos
sns.boxplot(data=df, x='category', y='value')
sns.heatmap(df.corr(), annot=True)
sns.pairplot(df)
```

## Fluxo de Trabalho de Ciência de Dados

### 1. Definição do Problema

A ciência de dados é um campo multidisciplinar, combinando matemática, estatística, programação e inteligência de negócios. Defina objetivos e métricas de sucesso.

```python
# Definir problema de negócio
# - Que pergunta estamos respondendo?
# - Que métricas medirão o
sucesso?
# - Que dados precisamos?
```

### 2. Coleta e Importação de Dados

Reúna dados de várias fontes e formatos.

```python
# Múltiplas fontes de dados
df_csv = pd.read_csv('data.csv')
df_json = pd.read_json('data.json')
df_sql = pd.read_sql('SELECT * FROM
table', connection)
# APIs e web scraping
import requests
response =
requests.get('https://api.example.co
m/data')
```

### 3. Exploração de Dados (EDA)

Entenda a estrutura, padrões e qualidade dos dados.

```python
# Análise Exploratória de Dados
df.shape              # Dimensões
df.dtypes             # Tipos de dados
df.isnull().sum()     # Valores ausentes
df['column'].value_counts()  #
Contagens de frequência
df.corr()             # Matriz de correlação
# Visualizações para EDA
sns.histplot(df['numeric_column'])
sns.boxplot(data=df,
y='numeric_column')
plt.figure(figsize=(10, 8))
sns.heatmap(df.corr(), annot=True)
```

## Limpeza e Pré-processamento de Dados

### Tratamento de Dados Ausentes

Antes de analisar os dados, eles devem ser limpos e preparados. Isso inclui lidar com dados ausentes, remover duplicatas e normalizar variáveis. A limpeza de dados é frequentemente o aspecto mais demorado, mas crucial, do processo de ciência de dados.

```python
# Identificar valores ausentes
df.isnull().sum()
df.isnull().sum() / len(df) * 100  # Porcentagem ausente
# Lidar com valores ausentes
df.dropna()                    # Remover linhas com NaN
df.fillna(df.mean())          # Preencher com a média
df.fillna(method='forward')   # Preenchimento para frente
df.fillna(method='backward')  # Preenchimento para trás
# Imputação avançada
from sklearn.impute import SimpleImputer, KNNImputer
imputer = SimpleImputer(strategy='median')
df_filled = pd.DataFrame(imputer.fit_transform(df))
```

### Transformação de Dados

A normalização de dados (escalonamento de dados para um intervalo padrão como [0, 1]) ajuda a evitar vieses devido a diferenças na magnitude das características.

```python
# Escalonamento e normalização
from sklearn.preprocessing import StandardScaler,
MinMaxScaler
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df[numeric_columns])
# Escalonamento Min-Max para [0,1]
minmax = MinMaxScaler()
df_normalized =
minmax.fit_transform(df[numeric_columns])
# Codificação de variáveis categóricas
pd.get_dummies(df, columns=['category_column'])
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
df['encoded'] = le.fit_transform(df['category'])
```

### Detecção e Tratamento de Outliers

Identifique e trate valores extremos que podem distorcer a análise.

```python
# Detecção estatística de outliers
Q1 = df['column'].quantile(0.25)
Q3 = df['column'].quantile(0.75)
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR
# Remover outliers
df_clean = df[(df['column'] >= lower_bound) &
              (df['column'] <= upper_bound)]
# Método Z-score
from scipy import stats
z_scores = np.abs(stats.zscore(df['column']))
df_no_outliers = df[z_scores < 3]
```

### Engenharia de Características (Feature Engineering)

Crie novas variáveis para melhorar o desempenho do modelo.

```python
# Criar novas características
df['feature_ratio'] = df['feature1'] / df['feature2']
df['feature_sum'] = df['feature1'] + df['feature2']
# Características de data/hora
df['date'] = pd.to_datetime(df['date'])
df['year'] = df['date'].dt.year
df['month'] = df['date'].dt.month
df['day_of_week'] = df['date'].dt.day_name()
# Agrupamento de variáveis contínuas
df['age_group'] = pd.cut(df['age'], bins=[0, 18, 35, 50, 100],
                        labels=['Child', 'Young Adult', 'Adult',
'Senior'])
```

## Análise Estatística

### Estatísticas Descritivas

Essas medidas de tendência central resumem os dados e fornecem insights sobre sua distribuição. Elas são fundamentais para entender qualquer conjunto de dados. A média é a média de todos os valores em um conjunto de dados. É altamente sensível a outliers.

```python
# Tendência central
mean = df['column'].mean()
median = df['column'].median()
mode = df['column'].mode()[0]
# Medidas de variabilidade
std_dev = df['column'].std()
variance = df['column'].var()
range_val = df['column'].max() - df['column'].min()
# Forma da distribuição
skewness = df['column'].skew()
kurtosis = df['column'].kurtosis()
# Percentis
percentiles = df['column'].quantile([0.25, 0.5, 0.75, 0.95])
```

### Teste de Hipóteses

Teste hipóteses estatísticas e valide suposições.

```python
# Teste t para comparar médias
from scipy.stats import ttest_ind, ttest_1samp
# Teste t de uma amostra
t_stat, p_value = ttest_1samp(data, population_mean)
# Teste t de duas amostras
group1 = df[df['group'] == 'A']['value']
group2 = df[df['group'] == 'B']['value']
t_stat, p_value = ttest_ind(group1, group2)
# Teste Qui-quadrado para independência
from scipy.stats import chi2_contingency
chi2, p_value, dof, expected =
chi2_contingency(contingency_table)
```

### Análise de Correlação

Entenda os relacionamentos entre variáveis.

```python
# Matriz de correlação
correlation_matrix = df.corr()
plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix, annot=True,
cmap='coolwarm')
# Correlações específicas
pearson_corr = df['var1'].corr(df['var2'])
spearman_corr = df['var1'].corr(df['var2'],
method='spearman')
# Significância estatística da correlação
from scipy.stats import pearsonr
correlation, p_value = pearsonr(df['var1'], df['var2'])
```

### ANOVA e Regressão

Analise a variância e os relacionamentos entre variáveis.

```python
# ANOVA de um fator
from scipy.stats import f_oneway
group_data = [df[df['group'] == g]['value'] for g in
df['group'].unique()]
f_stat, p_value = f_oneway(*group_data)
# Análise de regressão linear
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score
X = df[['feature1', 'feature2']]
y = df['target']
model = LinearRegression().fit(X, y)
y_pred = model.predict(X)
r2 = r2_score(y, y_pred)
```

## Modelos de Aprendizado de Máquina

### Aprendizado Supervisionado - Classificação

Árvores de Decisão: Um modelo em forma de árvore de decisões e suas possíveis consequências. Cada nó representa um teste em um atributo, e cada ramificação representa o resultado. É comumente usado para tarefas de classificação.

```python
# Divisão treino-teste
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y,
test_size=0.2, random_state=42)
# Regressão Logística
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression()
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
# Árvore de Decisão
from sklearn.tree import DecisionTreeClassifier
dt = DecisionTreeClassifier(max_depth=5)
dt.fit(X_train, y_train)
# Floresta Aleatória (Random Forest)
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=100)
rf.fit(X_train, y_train)
```

### Aprendizado Supervisionado - Regressão

Prever variáveis alvo contínuas.

```python
# Regressão Linear
from sklearn.linear_model import LinearRegression
lr = LinearRegression()
lr.fit(X_train, y_train)
y_pred = lr.predict(X_test)
# Regressão Polinomial
from sklearn.preprocessing import PolynomialFeatures
poly = PolynomialFeatures(degree=2)
X_poly = poly.fit_transform(X)
# Regressão Ridge & Lasso
from sklearn.linear_model import Ridge, Lasso
ridge = Ridge(alpha=1.0)
lasso = Lasso(alpha=0.1)
ridge.fit(X_train, y_train)
lasso.fit(X_train, y_train)
```

### Aprendizado Não Supervisionado

Descubra padrões em dados sem resultados rotulados.

```python
# Agrupamento K-Means
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
clusters = kmeans.fit_predict(X)
df['cluster'] = clusters
# Análise de Componentes Principais (PCA)
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)
# Agrupamento Hierárquico
from scipy.cluster.hierarchy import dendrogram, linkage
linkage_matrix = linkage(X_scaled, method='ward')
dendrogram(linkage_matrix)
```

### Avaliação de Modelo

Avalie o desempenho do modelo usando métricas apropriadas.

```python
# Métricas de classificação
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score, confusion_matrix
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# Matriz de Confusão
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d')
# Métricas de regressão
from sklearn.metrics import mean_squared_error,
mean_absolute_error
mse = mean_squared_error(y_test, y_pred)
mae = mean_absolute_error(y_test, y_pred)
rmse = np.sqrt(mse)
```

## Visualização de Dados

### Visualizações Exploratórias

Entenda as distribuições e relacionamentos dos dados.

```python
# Gráficos de distribuição
plt.figure(figsize=(12, 4))
plt.subplot(1, 3, 1)
plt.hist(df['numeric_col'], bins=20, edgecolor='black')
plt.subplot(1, 3, 2)
sns.boxplot(y=df['numeric_col'])
plt.subplot(1, 3, 3)
sns.violinplot(y=df['numeric_col'])
# Gráficos de relacionamento
plt.figure(figsize=(10, 6))
sns.scatterplot(data=df, x='feature1', y='feature2',
hue='category')
sns.regplot(data=df, x='feature1', y='target')
# Dados categóricos
sns.countplot(data=df, x='category')
sns.barplot(data=df, x='category', y='value')
```

### Visualizações Avançadas

Crie painéis e relatórios abrangentes.

```python
# Subplots para múltiplas visualizações
fig, axes = plt.subplots(2, 2, figsize=(15, 10))
axes[0,0].hist(df['col1'])
axes[0,1].scatter(df['col1'], df['col2'])
axes[1,0].boxplot(df['col1'])
sns.heatmap(df.corr(), ax=axes[1,1])
# Gráficos interativos com Plotly
import plotly.express as px
fig = px.scatter(df, x='feature1', y='feature2',
                color='category', size='value',
                hover_data=['additional_info'])
fig.show()
```

### Gráficos Estatísticos

Visualize relacionamentos estatísticos e resultados de modelos.

```python
# Pair plots para correlação
sns.pairplot(df, hue='target_category')
# Gráficos de resíduos para regressão
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.scatter(y_pred, y_test - y_pred)
plt.xlabel('Previsto')
plt.ylabel('Resíduos')
plt.subplot(1, 2, 2)
plt.scatter(y_test, y_pred)
plt.plot([y_test.min(), y_test.max()], [y_test.min(),
y_test.max()], 'r--')
# Curva ROC para classificação
from sklearn.metrics import roc_curve, auc
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, label=f'Curva ROC (AUC = {roc_auc:.2f})')
```

### Personalização e Estilização

Formatação profissional de visualização.

```python
# Definir estilo e cores
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
# Configurações personalizadas da figura
plt.figure(figsize=(12, 8))
plt.title('Título do Gráfico Profissional', fontsize=16,
fontweight='bold')
plt.xlabel('Rótulo do Eixo X', fontsize=14)
plt.ylabel('Rótulo do Eixo Y', fontsize=14)
plt.legend(loc='best')
plt.grid(True, alpha=0.3)
plt.tight_layout()
# Salvar gráficos de alta qualidade
plt.savefig('analysis_plot.png', dpi=300,
bbox_inches='tight')
```

## Implantação de Modelo e MLOps

### Persistência de Modelo

Salvar e carregar modelos treinados para uso em produção.

```python
# Salvar modelos com pickle
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(trained_model, f)
# Carregar modelo salvo
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
# Usando joblib para modelos sklearn
import joblib
joblib.dump(trained_model, 'model.joblib')
loaded_model = joblib.load('model.joblib')
# Versionamento de modelo com timestamps
import datetime
timestamp =
datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
model_name = f'model_{timestamp}.pkl'
```

### Validação Cruzada e Ajuste de Hiperparâmetros

Otimize o desempenho do modelo e evite o sobreajuste (overfitting).

```python
# Validação cruzada
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"Acurácia CV: {cv_scores.mean():.3f} (+/-
{cv_scores.std() * 2:.3f})")
# Grid Search para ajuste de hiperparâmetros
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

### Monitoramento de Desempenho

Ter acesso rápido a conceitos essenciais e comandos pode fazer toda a diferença em seu fluxo de trabalho. Seja você um iniciante se orientando ou um profissional experiente procurando uma referência confiável, as folhas de dicas servem como companheiros inestimáveis.

```python
# Rastreamento de desempenho do modelo
import time
start_time = time.time()
predictions = model.predict(X_test)
inference_time = time.time() - start_time
print(f"Tempo de inferência: {inference_time:.4f} segundos")
# Monitoramento de uso de memória
import psutil
process = psutil.Process()
memory_usage = process.memory_info().rss / 1024 /
1024  # MB
print(f"Uso de memória: {memory_usage:.2f} MB")
# Análise de importância de características
feature_importance = model.feature_importances_
importance_df = pd.DataFrame({
    'feature': X.columns,
    'importance': feature_importance
}).sort_values('importance', ascending=False)
```

### Documentação do Modelo

Documente suposições, desempenho e uso do modelo.

```python
# Criar relatório do modelo
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
# Salvar metadados do modelo
import json
with open('model_metadata.json', 'w') as f:
    json.dump(model_report, f, indent=2)
```

## Melhores Práticas e Dicas

### Organização do Código

Estruture projetos para reprodutibilidade e colaboração.

```python
# Estrutura do projeto
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
# Controle de versão com git
git init
git add .
git commit -m "Configuração inicial do
projeto de ciência de dados"
```

### Gerenciamento de Ambiente

Garanta ambientes reprodutíveis em diferentes sistemas.

```bash
# Criar ambiente virtual
python -m venv ds_env
source ds_env/bin/activate  #
Linux/Mac
# ds_env\Scripts\activate   #
Windows
# Arquivo de requisitos
pip freeze > requirements.txt
# Ambiente Conda
conda create -n ds_project
python=3.9
conda activate ds_project
conda install pandas numpy
scikit-learn matplotlib seaborn
jupyter
```

### Verificações de Qualidade de Dados

Valide a integridade dos dados em todo o pipeline.

```python
# Funções de validação de dados
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
# Relatório de qualidade de dados automatizado
def data_quality_report(df):
    print(f"Formato do conjunto de dados:
{df.shape}")
    print(f"Valores ausentes:
{df.isnull().sum().sum()}")
    print(f"Linhas duplicadas:
{df.duplicated().sum()}")
    print("\nTipos de dados das colunas:")
    print(df.dtypes)
```

## Links Relevantes

- <router-link to="/python">Folha de Dicas de Python</router-link>
- <router-link to="/pandas">Folha de Dicas de Pandas</router-link>
- <router-link to="/numpy">Folha de Dicas de NumPy</router-link>
- <router-link to="/matplotlib">Folha de Dicas de Matplotlib</router-link>
- <router-link to="/sklearn">Folha de Dicas de Scikit-learn</router-link>
- <router-link to="/database">Folha de Dicas de Banco de Dados</router-link>
- <router-link to="/javascript">Folha de Dicas de JavaScript</router-link>
- <router-link to="/devops">Folha de Dicas de DevOps</router-link>

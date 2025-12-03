---
title: 'Fiche de Référence Science des Données | LabEx'
description: "Apprenez la science des données avec cette fiche complète. Référence rapide pour l'analyse de données, l'apprentissage automatique, les statistiques, la visualisation, les bibliothèques Python et les flux de travail en science des données."
pdfUrl: '/cheatsheets/pdf/data-science-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche en science des données
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/datascience">Apprenez la science des données avec des laboratoires pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la science des données grâce à des laboratoires pratiques et à des scénarios réels. LabEx propose des cours complets en science des données couvrant les bibliothèques Python essentielles, la manipulation de données, l'analyse statistique, l'apprentissage automatique et la visualisation de données. Maîtrisez les techniques de collecte, de nettoyage, d'analyse de données et de déploiement de modèles.
</base-disclaimer-content>
</base-disclaimer>

## Bibliothèques Python Essentielles

### Pile de base pour la science des données

Les bibliothèques clés comme NumPy, Pandas, Matplotlib, Seaborn et scikit-learn constituent la base des flux de travail en science des données.

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

Package fondamental pour le calcul numérique avec Python.

```python
# Create arrays
arr = np.array([1, 2, 3, 4, 5])
matrix = np.array([[1, 2], [3, 4]])
# Basic operations
np.mean(arr)       # Moyenne
np.std(arr)        # Écart type
np.reshape(arr, (5, 1))  # Remodeler le tableau
# Generate data
np.random.normal(0, 1, 100)  # Distribution normale aléatoire
```

### Pandas: `import pandas as pd`

Bibliothèque de manipulation et d'analyse de données.

```python
# Create DataFrame
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
# Read data
df = pd.read_csv('data.csv')
# Basic exploration
df.head()          # Premières 5 lignes
df.info()          # Types de données et valeurs manquantes
df.describe()      # Statistiques récapitulatives
# Data manipulation
df.groupby('column').mean()
df.fillna(df.mean())  # Gérer les valeurs manquantes
```

<BaseQuiz id="datascience-pandas-1" correct="C">
  <template #question>
    Que retourne `df.head()` dans Pandas ?
  </template>
  
  <BaseQuizOption value="A">Les 5 dernières lignes du DataFrame</BaseQuizOption>
  <BaseQuizOption value="B">Un résumé du DataFrame</BaseQuizOption>
  <BaseQuizOption value="C" correct>Les 5 premières lignes du DataFrame</BaseQuizOption>
  <BaseQuizOption value="D">Toutes les lignes du DataFrame</BaseQuizOption>
  
  <BaseQuizAnswer>
    `df.head()` affiche les 5 premières lignes du DataFrame par défaut. Vous pouvez spécifier un nombre différent, comme `df.head(10)` pour voir les 10 premières lignes. C'est utile pour inspecter rapidement vos données.
  </BaseQuizAnswer>
</BaseQuiz>

### Matplotlib & Seaborn: Visualisation

Créer des visualisations statistiques et des graphiques.

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

## Flux de travail en science des données

### 1. Définition du problème

La science des données est un domaine multidisciplinaire, combinant mathématiques, statistiques, programmation et intelligence d'affaires. Définir les objectifs et les métriques de succès.

```python
# Define business problem
# - Quelle question répondons-nous ?
# - Quelles métriques mesureront le succès ?
# - De quelles données avons-nous besoin ?
```

### 2. Collecte et importation des données

Rassembler des données provenant de diverses sources et formats.

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

### 3. Exploration des données (EDA)

Comprendre la structure, les modèles et la qualité des données.

```python
# Exploratory Data Analysis
df.shape              # Dimensions
df.dtypes             # Types de données
df.isnull().sum()     # Valeurs manquantes
df['column'].value_counts()  # Fréquence des comptes
df.corr()             # Matrice de corrélation
# Visualizations for EDA
sns.histplot(df['numeric_column'])
sns.boxplot(data=df,
y='numeric_column')
plt.figure(figsize=(10, 8))
sns.heatmap(df.corr(), annot=True)
```

## Nettoyage et prétraitement des données

### Gestion des données manquantes

Avant d'analyser les données, elles doivent être nettoyées et préparées. Cela comprend la gestion des données manquantes, la suppression des doublons et la normalisation des variables. Le nettoyage des données est souvent l'aspect le plus chronophage mais le plus critique du processus de science des données.

```python
# Identify missing values
df.isnull().sum()
df.isnull().sum() / len(df) * 100  # Pourcentage manquant
# Handle missing values
df.dropna()                    # Supprimer les lignes avec NaN
df.fillna(df.mean())          # Remplir avec la moyenne
df.fillna(method='forward')   # Remplissage avant
df.fillna(method='backward')  # Remplissage arrière
# Advanced imputation
from sklearn.impute import SimpleImputer, KNNImputer
imputer = SimpleImputer(strategy='median')
df_filled = pd.DataFrame(imputer.fit_transform(df))
```

<BaseQuiz id="datascience-missing-1" correct="B">
  <template #question>
    À quoi sert le remplissage avant (`method='forward'`) ?
  </template>
  
  <BaseQuizOption value="A">Remplir les valeurs manquantes avec la moyenne</BaseQuizOption>
  <BaseQuizOption value="B" correct>Remplir les valeurs manquantes avec la valeur non nulle précédente</BaseQuizOption>
  <BaseQuizOption value="C">Remplir les valeurs manquantes avec des valeurs aléatoires</BaseQuizOption>
  <BaseQuizOption value="D">Supprimer les valeurs manquantes</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le remplissage avant propage la dernière observation valide vers l'avant pour combler les valeurs manquantes. Ceci est utile pour les données de séries chronologiques où vous souhaitez conserver la valeur précédente jusqu'à ce que de nouvelles données soient disponibles.
  </BaseQuizAnswer>
</BaseQuiz>

### Transformation des données

La normalisation des données (mise à l'échelle des données dans une plage standard comme [0, 1]) aide à éviter les biais dus aux différences d'ampleur des caractéristiques.

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
    Quelle est la différence entre StandardScaler et MinMaxScaler ?
  </template>
  
  <BaseQuizOption value="A">Il n'y a pas de différence</BaseQuizOption>
  <BaseQuizOption value="B">StandardScaler met à l'échelle à [0,1], MinMaxScaler met à l'échelle à moyenne=0, écart type=1</BaseQuizOption>
  <BaseQuizOption value="C" correct>StandardScaler normalise à moyenne=0 et écart type=1, MinMaxScaler met à l'échelle à la plage [0,1]</BaseQuizOption>
  <BaseQuizOption value="D">StandardScaler est plus rapide</BaseQuizOption>
  
  <BaseQuizAnswer>
    StandardScaler transforme les données pour avoir une moyenne de 0 et un écart type de 1 (normalisation du score Z). MinMaxScaler met à l'échelle les données dans une plage fixe, typiquement [0, 1]. Les deux sont utiles mais pour des scénarios différents.
  </BaseQuizAnswer>
</BaseQuiz>

### Détection et traitement des valeurs aberrantes

Identifier et traiter les valeurs extrêmes qui peuvent fausser l'analyse.

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

### Ingénierie des caractéristiques (Feature Engineering)

Créer de nouvelles variables pour améliorer les performances du modèle.

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

## Analyse statistique

### Statistiques descriptives

Ces mesures de tendance centrale résument les données et donnent un aperçu de leur distribution. Elles sont fondamentales pour comprendre n'importe quel ensemble de données. La moyenne est la moyenne de toutes les valeurs d'un ensemble de données. Elle est très sensible aux valeurs aberrantes.

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

### Tests d'hypothèses

Tester des hypothèses statistiques et valider des hypothèses.

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

### Analyse de corrélation

Comprendre les relations entre les variables.

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

### ANOVA et régression

Analyser la variance et les relations entre les variables.

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

## Modèles d'apprentissage automatique

### Apprentissage supervisé - Classification

Arbres de décision : un modèle arborescent de décisions et de leurs conséquences possibles. Chaque nœud représente un test sur un attribut, et chaque branche représente le résultat. Il est couramment utilisé pour les tâches de classification.

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

### Apprentissage supervisé - Régression

Prédire des variables cibles continues.

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

### Apprentissage non supervisé

Découvrir des modèles dans les données sans résultats étiquetés.

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

### Évaluation du modèle

Évaluer les performances du modèle à l'aide des métriques appropriées.

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

## Visualisation des données

### Visualisations exploratoires

Comprendre les distributions et les relations des données.

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

### Visualisations avancées

Créer des tableaux de bord et des rapports complets.

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

### Graphiques statistiques

Visualiser les relations statistiques et les résultats des modèles.

```python
# Pair plots for correlation
sns.pairplot(df, hue='target_category')
# Residual plots for regression
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.scatter(y_pred, y_test - y_pred)
plt.xlabel('Prédit')
plt.ylabel('Résidus')
plt.subplot(1, 2, 2)
plt.scatter(y_test, y_pred)
plt.plot([y_test.min(), y_test.max()], [y_test.min(),
y_test.max()], 'r--')
# ROC Curve for classification
from sklearn.metrics import roc_curve, auc
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, label=f'Courbe ROC (AUC = {roc_auc:.2f})')
```

### Personnalisation et style

Formatage professionnel des visualisations.

```python
# Set style and colors
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
# Custom figure settings
plt.figure(figsize=(12, 8))
plt.title('Titre de graphique professionnel', fontsize=16,
fontweight='bold')
plt.xlabel('Étiquette de l\'axe X', fontsize=14)
plt.ylabel('Étiquette de l\'axe Y', fontsize=14)
plt.legend(loc='best')
plt.grid(True, alpha=0.3)
plt.tight_layout()
# Save high-quality plots
plt.savefig('analysis_plot.png', dpi=300,
bbox_inches='tight')
```

## Déploiement de modèles et MLOps

### Persistance des modèles

Sauvegarder et charger les modèles entraînés pour une utilisation en production.

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

### Validation croisée et réglage des hyperparamètres

Optimiser les performances du modèle et prévenir le surapprentissage.

```python
# Cross-validation
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"Précision CV : {cv_scores.mean():.3f} (+/-
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

### Surveillance des performances

Avoir un accès rapide aux concepts essentiels et aux commandes peut faire toute la différence dans votre flux de travail. Que vous soyez débutant en train de trouver vos marques ou praticien expérimenté à la recherche d'une référence fiable, les feuilles de triche sont des compagnons inestimables.

```python
# Model performance tracking
import time
start_time = time.time()
predictions = model.predict(X_test)
inference_time = time.time() - start_time
print(f"Temps d'inférence : {inference_time:.4f} secondes")
# Memory usage monitoring
import psutil
process = psutil.Process()
memory_usage = process.memory_info().rss / 1024 /
1024  # MB
print(f"Utilisation de la mémoire : {memory_usage:.2f} Mo")
# Feature importance analysis
feature_importance = model.feature_importances_
importance_df = pd.DataFrame({
    'feature': X.columns,
    'importance': feature_importance
}).sort_values('importance', ascending=False)
```

### Documentation du modèle

Documenter les hypothèses, les performances et l'utilisation du modèle.

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

## Bonnes pratiques et conseils

### Organisation du code

Structurer les projets pour la reproductibilité et la collaboration.

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

### Gestion de l'environnement

Assurer des environnements reproductibles sur différents systèmes.

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

### Vérifications de la qualité des données

Valider l'intégrité des données tout au long du pipeline.

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
    print(f"Taille du jeu de données :
{df.shape}")
    print(f"Valeurs manquantes :
{df.isnull().sum().sum()}")
    print(f"Lignes dupliquées :
{df.duplicated().sum()}")
    print("\nTypes de données des colonnes :")
    print(df.dtypes)
```

## Liens pertinents

- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/pandas">Feuille de triche Pandas</router-link>
- <router-link to="/numpy">Feuille de triche NumPy</router-link>
- <router-link to="/matplotlib">Feuille de triche Matplotlib</router-link>
- <router-link to="/sklearn">Feuille de triche Scikit-learn</router-link>
- <router-link to="/database">Feuille de triche Base de données</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>

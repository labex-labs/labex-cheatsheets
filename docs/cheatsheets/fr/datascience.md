---
title: 'Fiche de Référence Science des Données'
description: 'Apprenez la science des données avec notre aide-mémoire complet couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/data-science-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Fiche Récapitulative de la Science des Données
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/datascience">Apprendre la Science des Données avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la science des données grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets en science des données couvrant les bibliothèques Python essentielles, la manipulation de données, l'analyse statistique, l'apprentissage automatique et la visualisation de données. Maîtrisez les techniques de collecte, de nettoyage, d'analyse de données et de déploiement de modèles.
</base-disclaimer-content>
</base-disclaimer>

## Bibliothèques Python Essentielles

### Pile Fondamentale de la Science des Données

Les bibliothèques clés comme NumPy, Pandas, Matplotlib, Seaborn et scikit-learn forment la base des flux de travail de la science des données.

```python
# Imports essentiels pour la science des données
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
# Créer des tableaux
arr = np.array([1, 2, 3, 4, 5])
matrix = np.array([[1, 2], [3, 4]])
# Opérations de base
np.mean(arr)       # Moyenne
np.std(arr)        # Écart-type
np.reshape(arr, (5, 1))  # Remodeler le tableau
# Générer des données
np.random.normal(0, 1, 100)  # Distribution normale
aléatoire
```

### Pandas: `import pandas as pd`

Bibliothèque de manipulation et d'analyse de données.

```python
# Créer un DataFrame
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
# Lire les données
df = pd.read_csv('data.csv')
# Exploration de base
df.head()          # Premières 5 lignes
df.info()          # Types de données et valeurs manquantes
df.describe()      # Statistiques descriptives
# Manipulation de données
df.groupby('column').mean()
df.fillna(df.mean())  # Gérer les valeurs manquantes
```

### Matplotlib & Seaborn: Visualisation

Créer des visualisations statistiques et des graphiques.

```python
# Bases de Matplotlib
plt.plot(x, y)
plt.hist(data, bins=20)
plt.scatter(x, y)
plt.show()
# Seaborn pour les graphiques statistiques
sns.boxplot(data=df, x='category', y='value')
sns.heatmap(df.corr(), annot=True)
sns.pairplot(df)
```

## Flux de Travail de la Science des Données

### 1. Définition du Problème

La science des données est un domaine multidisciplinaire, combinant mathématiques, statistiques, programmation et intelligence d'affaires. Définir les objectifs et les métriques de succès.

```python
# Définir le problème métier
# - Quelle question répondons-nous ?
# - Quelles métriques mesureront le
succès ?
# - De quelles données avons-nous
besoin ?
```

### 2. Collecte et Importation des Données

Rassembler des données provenant de diverses sources et formats.

```python
# Sources de données multiples
df_csv = pd.read_csv('data.csv')
df_json = pd.read_json('data.json')
df_sql = pd.read_sql('SELECT * FROM
table', connection)
# API et web scraping
import requests
response =
requests.get('https://api.example.co
m/data')
```

### 3. Exploration des Données (EDA)

Comprendre la structure, les modèles et la qualité des données.

```python
# Analyse Exploratoire des Données
df.shape              # Dimensions
df.dtypes             # Types de données
df.isnull().sum()     # Valeurs manquantes
df['column'].value_counts()  #
Comptages de fréquence
df.corr()             # Matrice de corrélation
# Visualisations pour l'EDA
sns.histplot(df['numeric_column'])
sns.boxplot(data=df,
y='numeric_column')
plt.figure(figsize=(10, 8))
sns.heatmap(df.corr(), annot=True)
```

## Nettoyage et Prétraitement des Données

### Gestion des Données Manquantes

Avant d'analyser les données, elles doivent être nettoyées et préparées. Cela inclut la gestion des données manquantes, la suppression des doublons et la normalisation des variables. Le nettoyage des données est souvent l'aspect le plus chronophage mais le plus critique du processus de science des données.

```python
# Identifier les valeurs manquantes
df.isnull().sum()
df.isnull().sum() / len(df) * 100  # Pourcentage manquant
# Gérer les valeurs manquantes
df.dropna()                    # Supprimer les lignes avec NaN
df.fillna(df.mean())          # Remplir avec la moyenne
df.fillna(method='forward')   # Remplissage avant
df.fillna(method='backward')  # Remplissage arrière
# Imputation avancée
from sklearn.impute import SimpleImputer, KNNImputer
imputer = SimpleImputer(strategy='median')
df_filled = pd.DataFrame(imputer.fit_transform(df))
```

### Transformation des Données

La normalisation des données (mise à l'échelle des données dans une plage standard comme [0, 1]) aide à éviter les biais dus aux différences d'ampleur des caractéristiques.

```python
# Mise à l'échelle et normalisation
from sklearn.preprocessing import StandardScaler,
MinMaxScaler
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df[numeric_columns])
# Mise à l'échelle Min-Max à [0,1]
minmax = MinMaxScaler()
df_normalized =
minmax.fit_transform(df[numeric_columns])
# Encodage des variables catégorielles
pd.get_dummies(df, columns=['category_column'])
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
df['encoded'] = le.fit_transform(df['category'])
```

### Détection et Traitement des Valeurs Aberrantes (Outliers)

Identifier et gérer les valeurs extrêmes qui pourraient fausser l'analyse.

```python
# Détection statistique des valeurs aberrantes
Q1 = df['column'].quantile(0.25)
Q3 = df['column'].quantile(0.75)
IQR = Q3 - Q1
lower_bound = Q1 - 1.5 * IQR
upper_bound = Q3 + 1.5 * IQR
# Supprimer les valeurs aberrantes
df_clean = df[(df['column'] >= lower_bound) &
              (df['column'] <= upper_bound)]
# Méthode du Z-score
from scipy import stats
z_scores = np.abs(stats.zscore(df['column']))
df_no_outliers = df[z_scores < 3]
```

### Ingénierie des Caractéristiques (Feature Engineering)

Créer de nouvelles variables pour améliorer les performances du modèle.

```python
# Créer de nouvelles caractéristiques
df['feature_ratio'] = df['feature1'] / df['feature2']
df['feature_sum'] = df['feature1'] + df['feature2']
# Caractéristiques Date/Heure
df['date'] = pd.to_datetime(df['date'])
df['year'] = df['date'].dt.year
df['month'] = df['date'].dt.month
df['day_of_week'] = df['date'].dt.day_name()
# Regroupement (Binning) de variables continues
df['age_group'] = pd.cut(df['age'], bins=[0, 18, 35, 50, 100],
                        labels=['Child', 'Young Adult', 'Adult',
'Senior'])
```

## Analyse Statistique

### Statistiques Descriptives

Ces mesures de tendance centrale résument les données et donnent un aperçu de leur distribution. Elles sont fondamentales pour comprendre n'importe quel ensemble de données. La moyenne est la moyenne de toutes les valeurs d'un ensemble de données. Elle est très sensible aux valeurs aberrantes.

```python
# Tendance centrale
mean = df['column'].mean()
median = df['column'].median()
mode = df['column'].mode()[0]
# Mesures de variabilité
std_dev = df['column'].std()
variance = df['column'].var()
range_val = df['column'].max() - df['column'].min()
# Forme de la distribution
skewness = df['column'].skew()
kurtosis = df['column'].kurtosis()
# Percentiles
percentiles = df['column'].quantile([0.25, 0.5, 0.75, 0.95])
```

### Tests d'Hypothèses

Tester des hypothèses statistiques et valider des suppositions.

```python
# Test t pour comparer les moyennes
from scipy.stats import ttest_ind, ttest_1samp
# Test t à un échantillon
t_stat, p_value = ttest_1samp(data, population_mean)
# Test t à deux échantillons
group1 = df[df['group'] == 'A']['value']
group2 = df[df['group'] == 'B']['value']
t_stat, p_value = ttest_ind(group1, group2)
# Test du Chi-carré pour l'indépendance
from scipy.stats import chi2_contingency
chi2, p_value, dof, expected =
chi2_contingency(contingency_table)
```

### Analyse de Corrélation

Comprendre les relations entre les variables.

```python
# Matrice de corrélation
correlation_matrix = df.corr()
plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix, annot=True,
cmap='coolwarm')
# Corrélations spécifiques
pearson_corr = df['var1'].corr(df['var2'])
spearman_corr = df['var1'].corr(df['var2'],
method='spearman')
# Signification statistique de la corrélation
from scipy.stats import pearsonr
correlation, p_value = pearsonr(df['var1'], df['var2'])
```

### ANOVA et Régression

Analyser la variance et les relations entre les variables.

```python
# ANOVA à un facteur
from scipy.stats import f_oneway
group_data = [df[df['group'] == g]['value'] for g in
df['group'].unique()]
f_stat, p_value = f_oneway(*group_data)
# Analyse de régression linéaire
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score
X = df[['feature1', 'feature2']]
y = df['target']
model = LinearRegression().fit(X, y)
y_pred = model.predict(X)
r2 = r2_score(y, y_pred)
```

## Modèles d'Apprentissage Automatique (Machine Learning)

### Apprentissage Supervisé - Classification

Arbres de Décision : Un modèle arborescent de décisions et de leurs conséquences possibles. Chaque nœud représente un test sur un attribut, et chaque branche représente le résultat. Il est couramment utilisé pour les tâches de classification.

```python
# Séparation entraînement-test
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y,
test_size=0.2, random_state=42)
# Régression Logistique
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression()
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
# Arbre de Décision
from sklearn.tree import DecisionTreeClassifier
dt = DecisionTreeClassifier(max_depth=5)
dt.fit(X_train, y_train)
# Forêt Aléatoire (Random Forest)
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=100)
rf.fit(X_train, y_train)
```

### Apprentissage Supervisé - Régression

Prédire des variables cibles continues.

```python
# Régression Linéaire
from sklearn.linear_model import LinearRegression
lr = LinearRegression()
lr.fit(X_train, y_train)
y_pred = lr.predict(X_test)
# Régression Polynomiale
from sklearn.preprocessing import PolynomialFeatures
poly = PolynomialFeatures(degree=2)
X_poly = poly.fit_transform(X)
# Régression Ridge & Lasso
from sklearn.linear_model import Ridge, Lasso
ridge = Ridge(alpha=1.0)
lasso = Lasso(alpha=0.1)
ridge.fit(X_train, y_train)
lasso.fit(X_train, y_train)
```

### Apprentissage Non Supervisé

Découvrir des modèles dans les données sans résultats étiquetés.

```python
# Clustering K-Means
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
clusters = kmeans.fit_predict(X)
df['cluster'] = clusters
# Analyse en Composantes Principales (PCA)
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)
# Clustering Hiérarchique
from scipy.cluster.hierarchy import dendrogram, linkage
linkage_matrix = linkage(X_scaled, method='ward')
dendrogram(linkage_matrix)
```

### Évaluation du Modèle

Évaluer les performances du modèle à l'aide des métriques appropriées.

```python
# Métriques de classification
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score, confusion_matrix
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# Matrice de Confusion
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d')
# Métriques de régression
from sklearn.metrics import mean_squared_error,
mean_absolute_error
mse = mean_squared_error(y_test, y_pred)
mae = mean_absolute_error(y_test, y_pred)
rmse = np.sqrt(mse)
```

## Visualisation des Données

### Visualisations Exploratoires

Comprendre les distributions et les relations des données.

```python
# Graphiques de distribution
plt.figure(figsize=(12, 4))
plt.subplot(1, 3, 1)
plt.hist(df['numeric_col'], bins=20, edgecolor='black')
plt.subplot(1, 3, 2)
sns.boxplot(y=df['numeric_col'])
plt.subplot(1, 3, 3)
sns.violinplot(y=df['numeric_col'])
# Graphiques de relation
plt.figure(figsize=(10, 6))
sns.scatterplot(data=df, x='feature1', y='feature2',
hue='category')
sns.regplot(data=df, x='feature1', y='target')
# Données catégorielles
sns.countplot(data=df, x='category')
sns.barplot(data=df, x='category', y='value')
```

### Visualisations Avancées

Créer des tableaux de bord et des rapports complets.

```python
# Sous-graphiques pour plusieurs vues
fig, axes = plt.subplots(2, 2, figsize=(15, 10))
axes[0,0].hist(df['col1'])
axes[0,1].scatter(df['col1'], df['col2'])
axes[1,0].boxplot(df['col1'])
sns.heatmap(df.corr(), ax=axes[1,1])
# Graphiques interactifs avec Plotly
import plotly.express as px
fig = px.scatter(df, x='feature1', y='feature2',
                color='category', size='value',
                hover_data=['additional_info'])
fig.show()
```

### Graphiques Statistiques

Visualiser les relations statistiques et les résultats des modèles.

```python
# Graphiques de paires pour la corrélation
sns.pairplot(df, hue='target_category')
# Graphiques de résidus pour la régression
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.scatter(y_pred, y_test - y_pred)
plt.xlabel('Prédit')
plt.ylabel('Résidus')
plt.subplot(1, 2, 2)
plt.scatter(y_test, y_pred)
plt.plot([y_test.min(), y_test.max()], [y_test.min(),
y_test.max()], 'r--')
# Courbe ROC pour la classification
from sklearn.metrics import roc_curve, auc
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, label=f'Courbe ROC (AUC = {roc_auc:.2f})')
```

### Personnalisation et Style

Formatage professionnel des visualisations.

```python
# Définir le style et les couleurs
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
# Paramètres de figure personnalisés
plt.figure(figsize=(12, 8))
plt.title('Titre de Graphique Professionnel', fontsize=16,
fontweight='bold')
plt.xlabel('Étiquette Axe X', fontsize=14)
plt.ylabel('Étiquette Axe Y', fontsize=14)
plt.legend(loc='best')
plt.grid(True, alpha=0.3)
plt.tight_layout()
# Sauvegarder des graphiques de haute qualité
plt.savefig('analysis_plot.png', dpi=300,
bbox_inches='tight')
```

## Déploiement de Modèles et MLOps

### Persistance des Modèles

Sauvegarder et charger les modèles entraînés pour une utilisation en production.

```python
# Sauvegarder les modèles avec pickle
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(trained_model, f)
# Charger le modèle sauvegardé
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
# Utilisation de joblib pour les modèles sklearn
import joblib
joblib.dump(trained_model, 'model.joblib')
loaded_model = joblib.load('model.joblib')
# Versionnage des modèles avec horodatages
import datetime
timestamp =
datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
model_name = f'model_{timestamp}.pkl'
```

### Validation Croisée et Réglage des Hyperparamètres

Optimiser les performances du modèle et prévenir le surapprentissage (overfitting).

```python
# Validation croisée
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"Précision CV: {cv_scores.mean():.3f} (+/-
{cv_scores.std() * 2:.3f})")
# Recherche par grille (Grid Search) pour le réglage des hyperparamètres
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

### Surveillance des Performances

Avoir un accès rapide aux concepts essentiels et aux commandes peut faire toute la différence dans votre flux de travail. Que vous soyez débutant en quête de repères ou praticien expérimenté à la recherche d'une référence fiable, les fiches récapitulatives sont des compagnons inestimables.

```python
# Suivi des performances du modèle
import time
start_time = time.time()
predictions = model.predict(X_test)
inference_time = time.time() - start_time
print(f"Temps d'inférence : {inference_time:.4f} secondes")
# Surveillance de l'utilisation de la mémoire
import psutil
process = psutil.Process()
memory_usage = process.memory_info().rss / 1024 /
1024  # MB
print(f"Utilisation mémoire : {memory_usage:.2f} MB")
# Analyse de l'importance des caractéristiques
feature_importance = model.feature_importances_
importance_df = pd.DataFrame({
    'feature': X.columns,
    'importance': feature_importance
}).sort_values('importance', ascending=False)
```

### Documentation du Modèle

Documenter les hypothèses, les performances et l'utilisation du modèle.

```python
# Créer un rapport de modèle
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
# Sauvegarder les métadonnées du modèle
import json
with open('model_metadata.json', 'w') as f:
    json.dump(model_report, f, indent=2)
```

## Bonnes Pratiques et Conseils

### Organisation du Code

Structurer les projets pour la reproductibilité et la collaboration.

```python
# Structure du projet
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
# Contrôle de version avec git
git init
git add .
git commit -m "Initial data
science project setup"
```

### Gestion de l'Environnement

Assurer des environnements reproductibles sur différents systèmes.

```bash
# Créer un environnement virtuel
python -m venv ds_env
source ds_env/bin/activate  #
Linux/Mac
# ds_env\Scripts\activate   #
Windows
# Fichier des exigences
pip freeze > requirements.txt
# Environnement Conda
conda create -n ds_project
python=3.9
conda activate ds_project
conda install pandas numpy
scikit-learn matplotlib seaborn
jupyter
```

### Vérifications de la Qualité des Données

Valider l'intégrité des données tout au long du pipeline.

```python
# Fonctions de validation des données
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
# Rapport automatisé sur la qualité des données
def data_quality_report(df):
    print(f"Forme du jeu de données :
{df.shape}")
    print(f"Valeurs manquantes :
{df.isnull().sum().sum()}")
    print(f"Lignes dupliquées :
{df.duplicated().sum()}")
    print("\nTypes de données des colonnes:")
    print(df.dtypes)
```

## Liens Pertinents

- <router-link to="/python">Fiche Récapitulative Python</router-link>
- <router-link to="/pandas">Fiche Récapitulative Pandas</router-link>
- <router-link to="/numpy">Fiche Récapitulative NumPy</router-link>
- <router-link to="/matplotlib">Fiche Récapitulative Matplotlib</router-link>
- <router-link to="/sklearn">Fiche Récapitulative Scikit-learn</router-link>
- <router-link to="/database">Fiche Récapitulative Base de Données</router-link>
- <router-link to="/javascript">Fiche Récapitulative JavaScript</router-link>
- <router-link to="/devops">Fiche Récapitulative DevOps</router-link>

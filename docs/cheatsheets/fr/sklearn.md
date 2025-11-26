---
title: 'Fiche Récapitulative scikit-learn'
description: 'Maîtrisez scikit-learn avec notre aide-mémoire complet couvrant les commandes essentielles, concepts et meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/sklearn-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche scikit-learn
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/sklearn">Apprenez scikit-learn avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez l'apprentissage automatique avec scikit-learn grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets sur scikit-learn couvrant le prétraitement des données essentiel, la sélection de modèles, l'entraînement, l'évaluation et l'ingénierie des fonctionnalités. Maîtrisez les algorithmes d'apprentissage automatique et construisez des modèles prédictifs avec Python.
</base-disclaimer-content>
</base-disclaimer>

## Installation et Imports

### Installation : `pip install scikit-learn`

Installez scikit-learn et les dépendances courantes.

```bash
# Installer scikit-learn
pip install scikit-learn
# Installer avec des paquets supplémentaires
pip install scikit-learn pandas numpy matplotlib
# Mettre à jour vers la dernière version
pip install scikit-learn --upgrade
```

### Imports Essentiels

Imports standards pour les flux de travail scikit-learn.

```python
# Imports principaux
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,
classification_report
# Algorithmes courants
from sklearn.linear_model import LinearRegression,
LogisticRegression
from sklearn.ensemble import RandomForestClassifier,
GradientBoostingRegressor
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
```

### Vérifier la Version

Vérifiez votre installation de scikit-learn.

```python
import sklearn
print(sklearn.__version__)
# Afficher la configuration de construction
sklearn.show_versions()
```

### Chargement de Jeu de Données

Chargez les jeux de données intégrés pour la pratique.

```python
from sklearn.datasets import load_iris, load_boston,
make_classification
# Charger des jeux de données d'exemple
iris = load_iris()
X, y = iris.data, iris.target
# Générer des données synthétiques
X_synth, y_synth = make_classification(n_samples=1000,
n_features=20, n_informative=10, random_state=42)
```

## Prétraitement des Données

### Division Entraînement-Test : `train_test_split()`

Divisez les données en ensembles d'entraînement et de test.

```python
# Division de base (80% entraînement, 20% test)
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
random_state=42)
# Division stratifiée pour la classification
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
stratify=y, random_state=42)
# Divisions multiples
X_train, X_temp, y_train, y_temp =
train_test_split(X, y, test_size=0.4,
random_state=42)
X_val, X_test, y_val, y_test =
train_test_split(X_temp, y_temp,
test_size=0.5, random_state=42)
```

### Mise à l'Échelle des Caractéristiques : `StandardScaler()` / `MinMaxScaler()`

Normalisez les caractéristiques à des échelles similaires.

```python
# Standardisation (moyenne=0, écart-type=1)
from sklearn.preprocessing import
StandardScaler, MinMaxScaler
scaler = StandardScaler()
X_scaled =
scaler.fit_transform(X_train)
X_test_scaled =
scaler.transform(X_test)
# Mise à l'échelle Min-Max (plage 0-1)
minmax_scaler = MinMaxScaler()
X_minmax =
minmax_scaler.fit_transform(X_train)
X_test_minmax =
minmax_scaler.transform(X_test)
```

### Encodage : `LabelEncoder()` / `OneHotEncoder()`

Convertissez les variables catégorielles en format numérique.

```python
# Encodage des étiquettes pour la variable cible
from sklearn.preprocessing import
LabelEncoder, OneHotEncoder
label_encoder = LabelEncoder()
y_encoded =
label_encoder.fit_transform(y)
# Encodage one-hot pour les caractéristiques catégorielles
from sklearn.preprocessing import
OneHotEncoder
encoder =
OneHotEncoder(sparse=False,
drop='first')
X_encoded =
encoder.fit_transform(X_categorical)
# Obtenir les noms des caractéristiques
feature_names =
encoder.get_feature_names_out()
```

## Apprentissage Supervisé - Classification

### Régression Logistique : `LogisticRegression()`

Modèle linéaire pour la classification binaire et multiclasse.

```python
# Régression logistique de base
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression(random_state=42)
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
y_proba = log_reg.predict_proba(X_test)
# Avec régularisation
log_reg_l2 = LogisticRegression(C=0.1, penalty='l2')
log_reg_l1 = LogisticRegression(C=0.1, penalty='l1',
solver='liblinear')
```

### Arbre de Décision : `DecisionTreeClassifier()`

Modèle basé sur des arbres pour les tâches de classification.

```python
# Classifieur par arbre de décision
from sklearn.tree import DecisionTreeClassifier
tree_clf = DecisionTreeClassifier(max_depth=5,
random_state=42)
tree_clf.fit(X_train, y_train)
y_pred = tree_clf.predict(X_test)
# Importance des caractéristiques
importances = tree_clf.feature_importances_
# Visualiser l'arbre
from sklearn.tree import plot_tree
plot_tree(tree_clf, max_depth=3, filled=True)
```

### Forêt Aléatoire : `RandomForestClassifier()`

Méthode d'ensemble combinant plusieurs arbres de décision.

```python
# Classifieur par forêt aléatoire
from sklearn.ensemble import RandomForestClassifier
rf_clf = RandomForestClassifier(n_estimators=100,
random_state=42)
rf_clf.fit(X_train, y_train)
y_pred = rf_clf.predict(X_test)
# Réglage des hyperparamètres
rf_clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42
)
```

### Machine à Vecteurs de Support : `SVC()`

Classifieur puissant utilisant des méthodes de noyau.

```python
# Classifieur SVM
from sklearn.svm import SVC
svm_clf = SVC(kernel='rbf', C=1.0, gamma='scale',
random_state=42)
svm_clf.fit(X_train, y_train)
y_pred = svm_clf.predict(X_test)
# Différents noyaux
svm_linear = SVC(kernel='linear')
svm_poly = SVC(kernel='poly', degree=3)
svm_rbf = SVC(kernel='rbf', gamma=0.1)
```

## Apprentissage Supervisé - Régression

### Régression Linéaire : `LinearRegression()`

Modèle linéaire de base pour les variables cibles continues.

```python
# Régression linéaire simple
from sklearn.linear_model import LinearRegression
lin_reg = LinearRegression()
lin_reg.fit(X_train, y_train)
y_pred = lin_reg.predict(X_test)
# Obtenir les coefficients et l'ordonnée à l'origine
coefficients = lin_reg.coef_
intercept = lin_reg.intercept_
print(f"Score R² : {lin_reg.score(X_test, y_test)}")
```

### Régression Ridge : `Ridge()`

Régression linéaire avec régularisation L2.

```python
# Régression Ridge (régularisation L2)
from sklearn.linear_model import Ridge
ridge_reg = Ridge(alpha=1.0)
ridge_reg.fit(X_train, y_train)
y_pred = ridge_reg.predict(X_test)
# Validation croisée pour la sélection d'alpha
from sklearn.linear_model import RidgeCV
ridge_cv = RidgeCV(alphas=[0.1, 1.0, 10.0])
ridge_cv.fit(X_train, y_train)
```

### Régression Lasso : `Lasso()`

Régression linéaire avec régularisation L1 pour la sélection de caractéristiques.

```python
# Régression Lasso (régularisation L1)
from sklearn.linear_model import Lasso
lasso_reg = Lasso(alpha=0.1)
lasso_reg.fit(X_train, y_train)
y_pred = lasso_reg.predict(X_test)
# Sélection de caractéristiques (coefficients non nuls)
selected_features = X.columns[lasso_reg.coef_ != 0]
print(f"Caractéristiques sélectionnées : {len(selected_features)}")
```

### Régression Forêt Aléatoire : `RandomForestRegressor()`

Méthode d'ensemble pour les tâches de régression.

```python
# Régresseur par forêt aléatoire
from sklearn.ensemble import RandomForestRegressor
rf_reg = RandomForestRegressor(n_estimators=100,
random_state=42)
rf_reg.fit(X_train, y_train)
y_pred = rf_reg.predict(X_test)
# Importance des caractéristiques pour la régression
feature_importance = rf_reg.feature_importances_
```

## Évaluation du Modèle

### Métriques de Classification

Évaluez la performance du modèle de classification.

```python
# Précision de base
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# Rapport de classification détaillé
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred))
# Matrice de confusion
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
```

### Courbe ROC et AUC

Tracez la courbe ROC et calculez l'Aire Sous la Courbe.

```python
# Courbe ROC pour la classification binaire
from sklearn.metrics import roc_curve, auc
fpr, tpr, thresholds = roc_curve(y_test, y_proba[:, 1])
roc_auc = auc(fpr, tpr)
# Tracer la courbe ROC
import matplotlib.pyplot as plt
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, label=f'Courbe ROC (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel('Taux de Faux Positifs')
plt.ylabel('Taux de Vrais Positifs')
plt.legend()
```

### Métriques de Régression

Évaluez la performance du modèle de régression.

```python
# Métriques de régression
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

### Validation Croisée

Évaluation robuste du modèle utilisant la validation croisée.

```python
# Validation croisée K-fold
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"Précision CV: {cv_scores.mean():.4f} (+/-
{cv_scores.std() * 2:.4f})")
# K-fold stratifiée pour les jeux de données déséquilibrés
skf = StratifiedKFold(n_splits=5, shuffle=True,
random_state=42)
cv_scores = cross_val_score(model, X, y, cv=skf,
scoring='f1_weighted')
```

## Apprentissage Non Supervisé

### Clustering K-Means : `KMeans()`

Partitionner les données en k clusters.

```python
# Clustering K-means
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
cluster_labels = kmeans.fit_predict(X)
centroids = kmeans.cluster_centers_
# Déterminer le nombre optimal de clusters (méthode du coude)
inertias = []
K_range = range(1, 11)
for k in K_range:
    kmeans = KMeans(n_clusters=k, random_state=42)
    kmeans.fit(X)
    inertias.append(kmeans.inertia_)
```

### Analyse en Composantes Principales : `PCA()`

Technique de réduction de dimensionnalité.

```python
# PCA pour la réduction de dimensionnalité
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)
explained_variance = pca.explained_variance_ratio_
# Trouver le nombre optimal de composantes
pca_full = PCA()
pca_full.fit(X)
cumsum =
np.cumsum(pca_full.explained_variance_ratio_)
# Trouver les composantes pour 95% de variance
n_components = np.argmax(cumsum >= 0.95) + 1
```

### Clustering DBSCAN : `DBSCAN()`

Algorithme de clustering basé sur la densité.

```python
# Clustering DBSCAN
from sklearn.cluster import DBSCAN
dbscan = DBSCAN(eps=0.5, min_samples=5)
cluster_labels = dbscan.fit_predict(X)
n_clusters = len(set(cluster_labels)) - (1 if -1 in
cluster_labels else 0)
n_noise = list(cluster_labels).count(-1)
print(f"Nombre de clusters: {n_clusters}")
print(f"Nombre de points de bruit: {n_noise}")
```

### Clustering Hiérarchique : `AgglomerativeClustering()`

Construire une hiérarchie de clusters.

```python
# Clustering agglomératif
from sklearn.cluster import AgglomerativeClustering
agg_clustering = AgglomerativeClustering(n_clusters=3,
linkage='ward')
cluster_labels = agg_clustering.fit_predict(X)
# Visualisation du dendrogramme
from scipy.cluster.hierarchy import dendrogram, linkage
linked = linkage(X, 'ward')
plt.figure(figsize=(12, 8))
dendrogram(linked)
```

## Sélection de Modèle et Réglage des Hyperparamètres

### Recherche par Grille : `GridSearchCV()`

Recherche exhaustive sur une grille de paramètres.

```python
# Recherche par grille pour le réglage des hyperparamètres
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

### Recherche Aléatoire : `RandomizedSearchCV()`

Échantillonnage aléatoire à partir de distributions de paramètres.

```python
# Recherche aléatoire (plus rapide pour les grands espaces de paramètres)
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

### Pipeline : `Pipeline()`

Chaîner les étapes de prétraitement et de modélisation.

```python
# Créer un pipeline de prétraitement et de modélisation
from sklearn.pipeline import Pipeline
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier(random_state=42))
])
pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)
# Pipeline avec recherche par grille
param_grid = {
    'classifier__n_estimators': [100, 200],
    'classifier__max_depth': [3, 5, None]
}
grid_search = GridSearchCV(pipeline, param_grid, cv=5)
grid_search.fit(X_train, y_train)
```

### Sélection de Caractéristiques : `SelectKBest()` / `RFE()`

Sélectionner les caractéristiques les plus informatives.

```python
# Sélection de caractéristiques univariée
from sklearn.feature_selection import SelectKBest,
f_classif
selector = SelectKBest(score_func=f_classif, k=10)
X_selected = selector.fit_transform(X_train, y_train)
selected_features = X.columns[selector.get_support()]
# Élimination Récursive de Caractéristiques
from sklearn.feature_selection import RFE
rfe = RFE(RandomForestClassifier(random_state=42),
n_features_to_select=10)
X_rfe = rfe.fit_transform(X_train, y_train)
```

## Techniques Avancées

### Méthodes d'Ensemble : `VotingClassifier()` / `BaggingClassifier()`

Combiner plusieurs modèles pour une meilleure performance.

```python
# Classifieur de vote (ensemble de différents algorithmes)
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
# Classifieur Bagging
from sklearn.ensemble import BaggingClassifier
bagging_clf = BaggingClassifier(DecisionTreeClassifier(),
n_estimators=100, random_state=42)
bagging_clf.fit(X_train, y_train)
```

### Gradient Boosting : `GradientBoostingClassifier()`

Méthode d'ensemble séquentielle avec correction d'erreur.

```python
# Classifieur de gradient boosting
from sklearn.ensemble import
GradientBoostingClassifier
gb_clf = GradientBoostingClassifier(n_estimators=100,
learning_rate=0.1, random_state=42)
gb_clf.fit(X_train, y_train)
y_pred = gb_clf.predict(X_test)
# Importance des caractéristiques
importances = gb_clf.feature_importances_
# Courbe d'apprentissage
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores =
learning_curve(gb_clf, X, y, cv=5)
```

### Gestion des Données Déséquilibrées : `SMOTE()` / Poids des Classes

Aborder le déséquilibre des classes dans les jeux de données.

```python
# Installer imbalanced-learn: pip install imbalanced-learn
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train,
y_train)
# Utilisation des poids de classe
rf_balanced =
RandomForestClassifier(class_weight='balanced',
random_state=42)
rf_balanced.fit(X_train, y_train)
# Poids de classe manuels
from sklearn.utils.class_weight import
compute_class_weight
class_weights = compute_class_weight('balanced',
classes=np.unique(y_train), y=y_train)
weight_dict = dict(zip(np.unique(y_train), class_weights))
```

### Persistance du Modèle : `joblib`

Sauvegarder et charger les modèles entraînés.

```python
# Sauvegarder le modèle
import joblib
joblib.dump(model, 'trained_model.pkl')
# Charger le modèle
loaded_model = joblib.load('trained_model.pkl')
y_pred = loaded_model.predict(X_test)
# Sauvegarder le pipeline entier
joblib.dump(pipeline, 'preprocessing_pipeline.pkl')
loaded_pipeline =
joblib.load('preprocessing_pipeline.pkl')
# Alternative utilisant pickle
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
```

## Performance et Débogage

### Courbes d'Apprentissage : `learning_curve()`

Diagnostiquer le surapprentissage et le sous-apprentissage.

```python
# Tracer les courbes d'apprentissage
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores = learning_curve(
    model, X, y, cv=5, train_sizes=np.linspace(0.1, 1.0, 10)
)
plt.figure(figsize=(10, 6))
plt.plot(train_sizes, np.mean(train_scores, axis=1), 'o-',
label='Score d\'Entraînement')
plt.plot(train_sizes, np.mean(val_scores, axis=1), 'o-',
label='Score de Validation')
plt.xlabel('Taille de l\'Ensemble d\'Entraînement')
plt.ylabel('Score')
plt.legend()
```

### Courbes de Validation : `validation_curve()`

Analyser l'effet des hyperparamètres.

```python
# Courbe de validation pour un seul hyperparamètre
from sklearn.model_selection import validation_curve
param_range = [10, 50, 100, 200, 500]
train_scores, val_scores = validation_curve(
    RandomForestClassifier(random_state=42), X, y,
    param_name='n_estimators',
param_range=param_range, cv=5
)
plt.figure(figsize=(10, 6))
plt.plot(param_range, np.mean(train_scores, axis=1), 'o-',
label='Entraînement')
plt.plot(param_range, np.mean(val_scores, axis=1), 'o-',
label='Validation')
plt.xlabel('Nombre d\'Estimateurs')
plt.ylabel('Score')
```

### Visualisation de l'Importance des Caractéristiques

Comprendre quelles caractéristiques pilotent les prédictions du modèle.

```python
# Tracer l'importance des caractéristiques
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
plt.figure(figsize=(12, 8))
plt.title("Importance des Caractéristiques")
plt.bar(range(X.shape[1]), importances[indices])
plt.xticks(range(X.shape[1]), [X.columns[i] for i in indices],
rotation=90)
# Valeurs SHAP pour l'interprétabilité du modèle
# pip install shap
import shap
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_test)
shap.summary_plot(shap_values, X_test)
```

### Comparaison de Modèles

Comparer plusieurs algorithmes de manière systématique.

```python
# Comparer plusieurs modèles
from sklearn.model_selection import cross_val_score
models = {
    'Régression Logistique':
LogisticRegression(random_state=42),
    'Forêt Aléatoire':
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

## Configuration et Bonnes Pratiques

### État Aléatoire et Reproductibilité

Assurer des résultats cohérents à travers les exécutions.

```python
# Définir l'état aléatoire pour la
reproductibilité
import numpy as np
np.random.seed(42)
# Définir random_state dans tous les
composants sklearn
model =
RandomForestClassifier(random
_state=42)
train_test_split(X, y,
random_state=42)
# Pour la validation croisée
cv = StratifiedKFold(n_splits=5,
shuffle=True, random_state=42)
```

### Mémoire et Performance

Optimiser pour les grands jeux de données et l'efficacité computationnelle.

```python
# Utiliser n_jobs=-1 pour le traitement
parallèle
model =
RandomForestClassifier(n_jobs=
-1)
grid_search =
GridSearchCV(model,
param_grid, n_jobs=-1)
# Pour les grands jeux de données, utiliser
partial_fit lorsqu'il est disponible
from sklearn.linear_model
import SGDClassifier
sgd = SGDClassifier()
# Traiter les données par lots
for chunk in chunks:
    sgd.partial_fit(chunk_X,
chunk_y)
```

### Avertissements et Débogage

Gérer les problèmes courants et déboguer les modèles.

```python
# Supprimer les avertissements (à utiliser avec
prudence)
import warnings
warnings.filterwarnings('ignore')
# Activer set_config de sklearn pour un meilleur
débogage
from sklearn import set_config
set_config(display='diagram')  # Affichage
amélioré dans Jupyter
# Vérifier la fuite de données
from sklearn.model_selection
import cross_val_score
# S'assurer que le prétraitement est fait
dans la boucle CV
```

## Liens Pertinents

- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/pandas">Feuille de triche Pandas</router-link>
- <router-link to="/numpy">Feuille de triche NumPy</router-link>
- <router-link to="/matplotlib">Feuille de triche Matplotlib</router-link>
- <router-link to="/datascience">Feuille de triche Science des Données</router-link>
- <router-link to="/database">Feuille de triche Base de Données</router-link>

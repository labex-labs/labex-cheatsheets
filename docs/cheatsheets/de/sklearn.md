---
title: 'scikit-learn Spickzettel | LabEx'
description: 'Lernen Sie scikit-learn Machine Learning mit diesem umfassenden Spickzettel. Schnelle Referenz für ML-Algorithmen, Modelltraining, Vorverarbeitung, Evaluierung und Python ML-Workflows.'
pdfUrl: '/cheatsheets/pdf/sklearn-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
scikit-learn Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/sklearn">Lernen Sie scikit-learn mit Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie maschinelles Lernen mit scikit-learn durch praktische Übungen und reale Szenarien. LabEx bietet umfassende scikit-learn Kurse, die wesentliche Datenvorverarbeitung, Modellauswahl, Training, Evaluierung und Feature Engineering abdecken. Meistern Sie Algorithmen des maschinellen Lernens und erstellen Sie prädiktive Modelle mit Python.
</base-disclaimer-content>
</base-disclaimer>

## Installation & Importe

### Installation: `pip install scikit-learn`

Installieren Sie scikit-learn und gängige Abhängigkeiten.

```bash
# Installieren Sie scikit-learn
pip install scikit-learn
# Installieren mit zusätzlichen Paketen
pip install scikit-learn pandas numpy matplotlib
# Auf die neueste Version aktualisieren
pip install scikit-learn --upgrade
```

### Wesentliche Importe

Standardimporte für scikit-learn Workflows.

```python
# Kernimporte
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,
classification_report
# Gängige Algorithmen
from sklearn.linear_model import LinearRegression,
LogisticRegression
from sklearn.ensemble import RandomForestClassifier,
GradientBoostingRegressor
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
```

### Version prüfen

Überprüfen Sie Ihre scikit-learn Installation.

```python
import sklearn
print(sklearn.__version__)
# Build-Konfiguration anzeigen
sklearn.show_versions()
```

### Datensatz laden

Laden Sie eingebaute Datensätze zum Üben.

```python
from sklearn.datasets import load_iris, load_boston,
make_classification
# Beispiel-Datensätze laden
iris = load_iris()
X, y = iris.data, iris.target
# Synthetische Daten generieren
X_synth, y_synth = make_classification(n_samples=1000,
n_features=20, n_informative=10, random_state=42)
```

## Datenvorverarbeitung

### Train-Test-Split: `train_test_split()`

Daten in Trainings- und Testsets aufteilen.

```python
# Grundlegende Aufteilung (80% Training, 20% Test)
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
random_state=42)
# Stratifizierte Aufteilung für Klassifikation
X_train, X_test, y_train, y_test =
train_test_split(X, y, test_size=0.2,
stratify=y, random_state=42)
# Mehrere Aufteilungen
X_train, X_temp, y_train, y_temp =
train_test_split(X, y, test_size=0.4,
random_state=42)
X_val, X_test, y_val, y_test =
train_test_split(X_temp, y_temp,
test_size=0.5, random_state=42)
```

<BaseQuiz id="sklearn-split-1" correct="B">
  <template #question>
    Warum ist es wichtig, Daten in Trainings- und Testsets aufzuteilen?
  </template>
  
  <BaseQuizOption value="A">Um die Datensatzgröße zu reduzieren</BaseQuizOption>
  <BaseQuizOption value="B" correct>Um die Modellleistung auf ungesehenen Daten zu bewerten und Überanpassung zu verhindern</BaseQuizOption>
  <BaseQuizOption value="C">Um das Modelltraining zu beschleunigen</BaseQuizOption>
  <BaseQuizOption value="D">Um den Datensatz auszugleichen</BaseQuizOption>
  
  <BaseQuizAnswer>
    Die Aufteilung der Daten ermöglicht es, das Modell auf einem Teil zu trainieren und es auf einem anderen zu testen. Dies hilft zu bewerten, wie gut das Modell auf neue, ungesehene Daten generalisiert, und verhindert eine Überanpassung an die Trainingsdaten.
  </BaseQuizAnswer>
</BaseQuiz>

### Feature-Skalierung: `StandardScaler()` / `MinMaxScaler()`

Merkmale auf ähnliche Skalen normalisieren.

```python
# Standardisierung (Mittelwert=0, Standardabweichung=1)
from sklearn.preprocessing import
StandardScaler, MinMaxScaler
scaler = StandardScaler()
X_scaled =
scaler.fit_transform(X_train)
X_test_scaled =
scaler.transform(X_test)
# Min-Max-Skalierung (Bereich 0-1)
minmax_scaler = MinMaxScaler()
X_minmax =
minmax_scaler.fit_transform(X_train)
X_test_minmax =
minmax_scaler.transform(X_test)
```

<BaseQuiz id="sklearn-scaling-1" correct="A">
  <template #question>
    Warum ist die Feature-Skalierung beim maschinellen Lernen wichtig?
  </template>
  
  <BaseQuizOption value="A" correct>Sie stellt sicher, dass alle Features auf einer ähnlichen Skala sind, wodurch verhindert wird, dass einige Features dominieren</BaseQuizOption>
  <BaseQuizOption value="B">Sie entfernt fehlende Werte</BaseQuizOption>
  <BaseQuizOption value="C">Sie erhöht die Anzahl der Features</BaseQuizOption>
  <BaseQuizOption value="D">Sie entfernt doppelte Zeilen</BaseQuizOption>
  
  <BaseQuizAnswer>
    Die Feature-Skalierung ist wichtig, da Algorithmen wie SVM, KNN und neuronale Netze empfindlich auf Feature-Skalen reagieren. Ohne Skalierung können Features mit größeren Bereichen den Lernprozess des Modells dominieren.
  </BaseQuizAnswer>
</BaseQuiz>

### Kodierung: `LabelEncoder()` / `OneHotEncoder()`

Kategorische Variablen in numerische Form umwandeln.

```python
# Label-Kodierung für die Zielvariable
from sklearn.preprocessing import
LabelEncoder, OneHotEncoder
label_encoder = LabelEncoder()
y_encoded =
label_encoder.fit_transform(y)
# One-Hot-Kodierung für kategorische
Features
from sklearn.preprocessing import
OneHotEncoder
encoder =
OneHotEncoder(sparse=False,
drop='first')
X_encoded =
encoder.fit_transform(X_categorical)
# Feature-Namen abrufen
feature_names =
encoder.get_feature_names_out()
```

## Überwachtes Lernen - Klassifikation

### Logistische Regression: `LogisticRegression()`

Lineares Modell für binäre und multiklassige Klassifikation.

```python
# Grundlegende logistische Regression
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression(random_state=42)
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
y_proba = log_reg.predict_proba(X_test)
# Mit Regularisierung
log_reg_l2 = LogisticRegression(C=0.1, penalty='l2')
log_reg_l1 = LogisticRegression(C=0.1, penalty='l1',
solver='liblinear')
```

### Entscheidungsbaum: `DecisionTreeClassifier()`

Baumbasiertes Modell für Klassifikationsaufgaben.

```python
# Entscheidungsbaum-Klassifikator
from sklearn.tree import DecisionTreeClassifier
tree_clf = DecisionTreeClassifier(max_depth=5,
random_state=42)
tree_clf.fit(X_train, y_train)
y_pred = tree_clf.predict(X_test)
# Feature-Wichtigkeit
importances = tree_clf.feature_importances_
# Baum visualisieren
from sklearn.tree import plot_tree
plot_tree(tree_clf, max_depth=3, filled=True)
```

### Random Forest: `RandomForestClassifier()`

Ensemble-Methode, die mehrere Entscheidungsbäume kombiniert.

```python
# Random Forest Klassifikator
from sklearn.ensemble import RandomForestClassifier
rf_clf = RandomForestClassifier(n_estimators=100,
random_state=42)
rf_clf.fit(X_train, y_train)
y_pred = rf_clf.predict(X_test)
# Hyperparameter-Tuning
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
    Was steuert <code>n_estimators</code> im RandomForestClassifier?
  </template>
  
  <BaseQuizOption value="A" correct>Die Anzahl der Entscheidungsbäume im Wald</BaseQuizOption>
  <BaseQuizOption value="B">Die maximale Tiefe jedes Baumes</BaseQuizOption>
  <BaseQuizOption value="C">Die Anzahl der Features, die berücksichtigt werden</BaseQuizOption>
  <BaseQuizOption value="D">Der Zufalls-Seed</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>n_estimators</code> gibt an, wie viele Entscheidungsbäume im Random Forest enthalten sein sollen. Mehr Bäume verbessern im Allgemeinen die Leistung, erhöhen aber die Rechenzeit. Der Standardwert ist normalerweise 100.
  </BaseQuizAnswer>
</BaseQuiz>

### Support Vector Machine: `SVC()`

Leistungsstarker Klassifikator, der Kernel-Methoden verwendet.

```python
# SVM Klassifikator
from sklearn.svm import SVC
svm_clf = SVC(kernel='rbf', C=1.0, gamma='scale',
random_state=42)
svm_clf.fit(X_train, y_train)
y_pred = svm_clf.predict(X_test)
# Verschiedene Kernel
svm_linear = SVC(kernel='linear')
svm_poly = SVC(kernel='poly', degree=3)
svm_rbf = SVC(kernel='rbf', gamma=0.1)
```

## Überwachtes Lernen - Regression

### Lineare Regression: `LinearRegression()`

Grundlegendes lineares Modell für kontinuierliche Zielvariablen.

```python
# Einfache lineare Regression
from sklearn.linear_model import LinearRegression
lin_reg = LinearRegression()
lin_reg.fit(X_train, y_train)
y_pred = lin_reg.predict(X_test)
# Koeffizienten und Achsenabschnitt abrufen
coefficients = lin_reg.coef_
intercept = lin_reg.intercept_
print(f"R²-Wert: {lin_reg.score(X_test, y_test)}")
```

### Ridge Regression: `Ridge()`

Lineare Regression mit L2-Regularisierung.

```python
# Ridge Regression (L2 Regularisierung)
from sklearn.linear_model import Ridge
ridge_reg = Ridge(alpha=1.0)
ridge_reg.fit(X_train, y_train)
y_pred = ridge_reg.predict(X_test)
# Kreuzvalidierung zur Auswahl von Alpha
from sklearn.linear_model import RidgeCV
ridge_cv = RidgeCV(alphas=[0.1, 1.0, 10.0])
ridge_cv.fit(X_train, y_train)
```

### Lasso Regression: `Lasso()`

Lineare Regression mit L1-Regularisierung zur Feature-Auswahl.

```python
# Lasso Regression (L1 Regularisierung)
from sklearn.linear_model import Lasso
lasso_reg = Lasso(alpha=0.1)
lasso_reg.fit(X_train, y_train)
y_pred = lasso_reg.predict(X_test)
# Feature-Auswahl (nicht-null Koeffizienten)
selected_features = X.columns[lasso_reg.coef_ != 0]
print(f"Ausgewählte Features: {len(selected_features)}")
```

### Random Forest Regression: `RandomForestRegressor()`

Ensemble-Methode für Regressionsaufgaben.

```python
# Random Forest Regressor
from sklearn.ensemble import RandomForestRegressor
rf_reg = RandomForestRegressor(n_estimators=100,
random_state=42)
rf_reg.fit(X_train, y_train)
y_pred = rf_reg.predict(X_test)
# Feature-Wichtigkeit für Regression
feature_importance = rf_reg.feature_importances_
```

## Modellbewertung

### Klassifikationsmetriken

Bewertung der Leistung von Klassifikationsmodellen.

```python
# Grundlegende Genauigkeit
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# Detaillierter Klassifikationsbericht
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred))
# Konfusionsmatrix
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
```

### ROC-Kurve & AUC

ROC-Kurve plotten und Fläche unter der Kurve berechnen.

```python
# ROC-Kurve für binäre Klassifikation
from sklearn.metrics import roc_curve, auc
fpr, tpr, thresholds = roc_curve(y_test, y_proba[:, 1])
roc_auc = auc(fpr, tpr)
# ROC-Kurve plotten
import matplotlib.pyplot as plt
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, label=f'ROC Kurve (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], 'k--')
plt.xlabel('Falsche Positivrate')
plt.ylabel('Wahre Positivrate')
plt.legend()
```

### Regressionsmetriken

Bewertung der Leistung von Regressionsmodellen.

```python
# Regressionsmetriken
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

### Kreuzvalidierung

Robuste Modellbewertung mittels Kreuzvalidierung.

```python
# K-Fold Kreuzvalidierung
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"KV Genauigkeit: {cv_scores.mean():.4f} (+/-
{cv_scores.std() * 2:.4f})")
# Stratified K-Fold für unausgewogene Datensätze
skf = StratifiedKFold(n_splits=5, shuffle=True,
random_state=42)
cv_scores = cross_val_score(model, X, y, cv=skf,
scoring='f1_weighted')
```

## Unüberwachtes Lernen

### K-Means-Clustering: `KMeans()`

Daten in k Cluster partitionieren.

```python
# K-Means Clustering
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
cluster_labels = kmeans.fit_predict(X)
centroids = kmeans.cluster_centers_
# Bestimmung der optimalen Clusteranzahl (Ellbogen-Methode)
inertias = []
K_range = range(1, 11)
for k in K_range:
    kmeans = KMeans(n_clusters=k, random_state=42)
    kmeans.fit(X)
    inertias.append(kmeans.inertia_)
```

### Hauptkomponentenanalyse: `PCA()`

Technik zur Dimensionsreduktion.

```python
# PCA zur Dimensionsreduktion
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)
explained_variance = pca.explained_variance_ratio_
# Optimale Anzahl von Komponenten finden
pca_full = PCA()
pca_full.fit(X)
cumsum =
np.cumsum(pca_full.explained_variance_ratio_)
# Komponenten für 95% Varianz finden
n_components = np.argmax(cumsum >= 0.95) + 1
```

### DBSCAN-Clustering: `DBSCAN()`

Dichtebasiertes Clustering-Verfahren.

```python
# DBSCAN Clustering
from sklearn.cluster import DBSCAN
dbscan = DBSCAN(eps=0.5, min_samples=5)
cluster_labels = dbscan.fit_predict(X)
n_clusters = len(set(cluster_labels)) - (1 if -1 in
cluster_labels else 0)
n_noise = list(cluster_labels).count(-1)
print(f"Anzahl der Cluster: {n_clusters}")
print(f"Anzahl der Rauschpunkte: {n_noise}")
```

### Hierarchisches Clustering: `AgglomerativeClustering()`

Hierarchie von Clustern aufbauen.

```python
# Agglomeratives Clustering
from sklearn.cluster import AgglomerativeClustering
agg_clustering = AgglomerativeClustering(n_clusters=3,
linkage='ward')
cluster_labels = agg_clustering.fit_predict(X)
# Dendrogramm-Visualisierung
from scipy.cluster.hierarchy import dendrogram, linkage
linked = linkage(X, 'ward')
plt.figure(figsize=(12, 8))
dendrogram(linked)
```

## Modellauswahl & Hyperparameter-Tuning

### Grid Search: `GridSearchCV()`

Umfassende Suche im Parameter-Grid.

```python
# Grid Search für Hyperparameter-Tuning
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

### Random Search: `RandomizedSearchCV()`

Zufällige Stichproben aus Parameterverteilungen.

```python
# Random Search (schneller für große Parameterbereiche)
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

Verkettung von Vorverarbeitungs- und Modellierungsschritten.

```python
# Pipeline für Vorverarbeitung und Modellierung erstellen
from sklearn.pipeline import Pipeline
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('classifier', RandomForestClassifier(random_state=42))
])
pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)
# Pipeline mit Grid Search
param_grid = {
    'classifier__n_estimators': [100, 200],
    'classifier__max_depth': [3, 5, None]
}
grid_search = GridSearchCV(pipeline, param_grid, cv=5)
grid_search.fit(X_train, y_train)
```

### Feature-Auswahl: `SelectKBest()` / `RFE()`

Auswahl der informativsten Features.

```python
# Univariate Feature-Auswahl
from sklearn.feature_selection import SelectKBest,
f_classif
selector = SelectKBest(score_func=f_classif, k=10)
X_selected = selector.fit_transform(X_train, y_train)
selected_features = X.columns[selector.get_support()]
# Rekursive Feature Elimination
from sklearn.feature_selection import RFE
rfe = RFE(RandomForestClassifier(random_state=42),
n_features_to_select=10)
X_rfe = rfe.fit_transform(X_train, y_train)
```

## Fortgeschrittene Techniken

### Ensemble-Methoden: `VotingClassifier()` / `BaggingClassifier()`

Kombinieren mehrerer Modelle für bessere Leistung.

```python
# Voting Classifier (Ensemble verschiedener Algorithmen)
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
# Bagging Classifier
from sklearn.ensemble import BaggingClassifier
bagging_clf = BaggingClassifier(DecisionTreeClassifier(),
n_estimators=100, random_state=42)
bagging_clf.fit(X_train, y_train)
```

### Gradient Boosting: `GradientBoostingClassifier()`

Sequentielle Ensemble-Methode mit Fehlerkorrektur.

```python
# Gradient Boosting Klassifikator
from sklearn.ensemble import
GradientBoostingClassifier
gb_clf = GradientBoostingClassifier(n_estimators=100,
learning_rate=0.1, random_state=42)
gb_clf.fit(X_train, y_train)
y_pred = gb_clf.predict(X_test)
# Feature-Wichtigkeit
importances = gb_clf.feature_importances_
# Lernkurve
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores =
learning_curve(gb_clf, X, y, cv=5)
```

### Umgang mit unausgewogenen Daten: `SMOTE()` / Klassen-Gewichte

Behandlung von Klassenungleichgewichten in Datensätzen.

```python
# Installieren Sie imbalanced-learn: pip install imbalanced-learn
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train,
y_train)
# Verwendung von Klassen-Gewichten
rf_balanced =
RandomForestClassifier(class_weight='balanced',
random_state=42)
rf_balanced.fit(X_train, y_train)
# Manuelle Klassen-Gewichte
from sklearn.utils.class_weight import
compute_class_weight
class_weights = compute_class_weight('balanced',
classes=np.unique(y_train), y=y_train)
weight_dict = dict(zip(np.unique(y_train), class_weights))
```

### Modellpersistenz: `joblib`

Trainierte Modelle speichern und laden.

```python
# Modell speichern
import joblib
joblib.dump(model, 'trained_model.pkl')
# Modell laden
loaded_model = joblib.load('trained_model.pkl')
y_pred = loaded_model.predict(X_test)
# Gesamte Pipeline speichern
joblib.dump(pipeline, 'preprocessing_pipeline.pkl')
loaded_pipeline =
joblib.load('preprocessing_pipeline.pkl')
# Alternative mit pickle
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
```

## Leistung & Debugging

### Lernkurven: `learning_curve()`

Diagnose von Überanpassung und Unteranpassung.

```python
# Lernkurven plotten
from sklearn.model_selection import learning_curve
train_sizes, train_scores, val_scores = learning_curve(
    model, X, y, cv=5, train_sizes=np.linspace(0.1, 1.0, 10)
)
plt.figure(figsize=(10, 6))
plt.plot(train_sizes, np.mean(train_scores, axis=1), 'o-',
label='Trainings-Score')
plt.plot(train_sizes, np.mean(val_scores, axis=1), 'o-',
label='Validierungs-Score')
plt.xlabel('Größe des Trainingsdatensatzes')
plt.ylabel('Score')
plt.legend()
```

### Validierungskurven: `validation_curve()`

Analyse des Einflusses von Hyperparametern.

```python
# Validierungskurve für einen einzelnen Hyperparameter
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
label='Validierung')
plt.xlabel('Anzahl der Schätzer')
plt.ylabel('Score')
```

### Visualisierung der Feature-Wichtigkeit

Verstehen, welche Features die Modellvorhersagen bestimmen.

```python
# Feature-Wichtigkeit plotten
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
plt.figure(figsize=(12, 8))
plt.title("Feature-Wichtigkeit")
plt.bar(range(X.shape[1]), importances[indices])
plt.xticks(range(X.shape[1]), [X.columns[i] for i in indices],
rotation=90)
# SHAP-Werte für Modellinterpretierbarkeit
# pip install shap
import shap
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_test)
shap.summary_plot(shap_values, X_test)
```

### Modellvergleich

Mehrere Algorithmen systematisch vergleichen.

```python
# Mehrere Modelle vergleichen
from sklearn.model_selection import cross_val_score
models = {
    'Logistische Regression':
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

## Konfiguration & Best Practices

### Random State & Reproduzierbarkeit

Konsistente Ergebnisse über Durchläufe hinweg sicherstellen.

```python
# Setzen des Random State für
Reproduzierbarkeit
import numpy as np
np.random.seed(42)
# Setzen des random_state in allen
sklearn Komponenten
model =
RandomForestClassifier(random
_state=42)
train_test_split(X, y,
random_state=42)
# Für Kreuzvalidierung
cv = StratifiedKFold(n_splits=5,
shuffle=True, random_state=42)
```

### Speicher & Leistung

Optimierung für große Datensätze und rechnerische Effizienz.

```python
# n_jobs=-1 für parallele
Verarbeitung verwenden
model =
RandomForestClassifier(n_jobs=
-1)
grid_search =
GridSearchCV(model,
param_grid, n_jobs=-1)
# Für große Datensätze, partial_fit verwenden, wenn verfügbar
from sklearn.linear_model
import SGDClassifier
sgd = SGDClassifier()
# Daten in Blöcken verarbeiten
for chunk in chunks:
    sgd.partial_fit(chunk_X,
chunk_y)
```

### Warnungen & Debugging

Umgang mit häufigen Problemen und Debugging von Modellen.

```python
# Warnungen unterdrücken (vorsichtig verwenden)
import warnings
warnings.filterwarnings('ignore')
# set_config von sklearn für besseres Debugging aktivieren
from sklearn import set_config
set_config(display='diagram')  #
Erweiterte Anzeige in Jupyter
# Auf Datenleckage prüfen
from sklearn.model_selection
import cross_val_score
# Sicherstellen, dass die Vorverarbeitung innerhalb der CV-Schleife erfolgt
```

## Relevante Links

- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/pandas">Pandas Spickzettel</router-link>
- <router-link to="/numpy">NumPy Spickzettel</router-link>
- <router-link to="/matplotlib">Matplotlib Spickzettel</router-link>
- <router-link to="/datascience">Data Science Spickzettel</router-link>
- <router-link to="/database">Datenbank Spickzettel</router-link>

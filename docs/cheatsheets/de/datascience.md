---
title: 'Data Science Spickzettel | LabEx'
description: 'Lernen Sie Data Science mit diesem umfassenden Spickzettel. Schnelle Referenz für Datenanalyse, maschinelles Lernen, Statistik, Visualisierung, Python-Bibliotheken und Data-Science-Workflows.'
pdfUrl: '/cheatsheets/pdf/data-science-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Data Science Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/datascience">Data Science mit praxisnahen Labs lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Data Science durch praxisnahe Labs und reale Szenarien. LabEx bietet umfassende Data-Science-Kurse, die wesentliche Python-Bibliotheken, Datenmanipulation, statistische Analyse, maschinelles Lernen und Datenvisualisierung abdecken. Meistern Sie Techniken zur Datenerfassung, -bereinigung, -analyse und Modellbereitstellung.
</base-disclaimer-content>
</base-disclaimer>

## Wesentliche Python-Bibliotheken

### Kern-Data-Science-Stack

Schlüsselbibliotheken wie NumPy, Pandas, Matplotlib, Seaborn und scikit-learn bilden die Grundlage für Data-Science-Workflows.

```python
# Wesentliche Importe für Data Science
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

Grundlegendes Paket für numerisches Rechnen mit Python.

```python
# Arrays erstellen
arr = np.array([1, 2, 3, 4, 5])
matrix = np.array([[1, 2], [3, 4]])
# Grundlegende Operationen
np.mean(arr)       # Durchschnitt
np.std(arr)        # Standardabweichung
np.reshape(arr, (5, 1))  # Array umformen
# Daten generieren
np.random.normal(0, 1, 100)  # Zufällige Normalverteilung
```

### Pandas: `import pandas as pd`

Bibliothek für Datenmanipulation und -analyse.

```python
# DataFrame erstellen
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
# Daten einlesen
df = pd.read_csv('data.csv')
# Grundlegende Erkundung
df.head()          # Erste 5 Zeilen
df.info()          # Datentypen und fehlende Werte
df.describe()      # Zusammenfassende Statistiken
# Datenmanipulation
df.groupby('column').mean()
df.fillna(df.mean())  # Fehlende Werte behandeln
```

<BaseQuiz id="datascience-pandas-1" correct="C">
  <template #question>
    Was gibt <code>df.head()</code> in Pandas zurück?
  </template>
  
  <BaseQuizOption value="A">Die letzten 5 Zeilen des DataFrames</BaseQuizOption>
  <BaseQuizOption value="B">Eine Zusammenfassung des DataFrames</BaseQuizOption>
  <BaseQuizOption value="C" correct>Die ersten 5 Zeilen des DataFrames</BaseQuizOption>
  <BaseQuizOption value="D">Alle Zeilen des DataFrames</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>df.head()</code> zeigt standardmäßig die ersten 5 Zeilen des DataFrames an. Sie können eine andere Zahl angeben, z. B. <code>df.head(10)</code>, um die ersten 10 Zeilen anzuzeigen. Es ist nützlich, um schnell einen Blick auf Ihre Daten zu werfen.
  </BaseQuizAnswer>
</BaseQuiz>

### Matplotlib & Seaborn: Visualisierung

Erstellen Sie statistische Visualisierungen und Diagramme.

```python
# Matplotlib Grundlagen
plt.plot(x, y)
plt.hist(data, bins=20)
plt.scatter(x, y)
plt.show()
# Seaborn für statistische Diagramme
sns.boxplot(data=df, x='category', y='value')
sns.heatmap(df.corr(), annot=True)
sns.pairplot(df)
```

## Data-Science-Workflow

### 1. Problemdefinition

Data Science ist ein multidisziplinäres Feld, das Mathematik, Statistik, Programmierung und Business Intelligence kombiniert. Definieren Sie Ziele und Erfolgskennzahlen.

```python
# Geschäftsproblem definieren
# - Welche Frage beantworten wir?
# - Welche Metriken messen den Erfolg?
# - Welche Daten benötigen wir?
```

### 2. Datenerfassung & Import

Sammeln Sie Daten aus verschiedenen Quellen und Formaten.

```python
# Mehrere Datenquellen
df_csv = pd.read_csv('data.csv')
df_json = pd.read_json('data.json')
df_sql = pd.read_sql('SELECT * FROM
table', connection)
# APIs und Web Scraping
import requests
response =
requests.get('https://api.example.co
m/data')
```

### 3. Datenexploration (EDA)

Verstehen Sie die Datenstruktur, Muster und Qualität.

```python
# Explorative Datenanalyse
df.shape              # Dimensionen
df.dtypes             # Datentypen
df.isnull().sum()     # Fehlende Werte
df['column'].value_counts()  #
Häufigkeitszählungen
df.corr()             # Korrelationsmatrix
# Visualisierungen für EDA
sns.histplot(df['numeric_column'])
sns.boxplot(data=df,
y='numeric_column')
plt.figure(figsize=(10, 8))
sns.heatmap(df.corr(), annot=True)
```

## Datenbereinigung & Vorverarbeitung

### Umgang mit fehlenden Daten

Bevor Daten analysiert werden, müssen sie bereinigt und vorbereitet werden. Dies umfasst den Umgang mit fehlenden Daten, das Entfernen von Duplikaten und die Normalisierung von Variablen. Die Datenbereinigung ist oft der zeitaufwändigste, aber kritischste Aspekt des Data-Science-Prozesses.

```python
# Fehlende Werte identifizieren
df.isnull().sum()
df.isnull().sum() / len(df) * 100  # Prozentsatz fehlend
# Fehlende Werte behandeln
df.dropna()                    # Zeilen mit NaN entfernen
df.fillna(df.mean())          # Mit Mittelwert auffüllen
df.fillna(method='forward')   # Vorwärts auffüllen
df.fillna(method='backward')  # Rückwärts auffüllen
# Erweiterte Imputation
from sklearn.impute import SimpleImputer, KNNImputer
imputer = SimpleImputer(strategy='median')
df_filled = pd.DataFrame(imputer.fit_transform(df))
```

<BaseQuiz id="datascience-missing-1" correct="B">
  <template #question>
    Wofür wird das Vorwärtsauffüllen (<code>method='forward'</code>) verwendet?
  </template>
  
  <BaseQuizOption value="A">Zum Auffüllen fehlender Werte mit dem Mittelwert</BaseQuizOption>
  <BaseQuizOption value="B" correct>Zum Auffüllen fehlender Werte mit dem vorherigen Nicht-Null-Wert</BaseQuizOption>
  <BaseQuizOption value="C">Zum Auffüllen fehlender Werte mit Zufallswerten</BaseQuizOption>
  <BaseQuizOption value="D">Zum Entfernen fehlender Werte</BaseQuizOption>
  
  <BaseQuizAnswer>
    Forward fill überträgt die letzte gültige Beobachtung nach vorne, um fehlende Werte aufzufüllen. Dies ist nützlich für Zeitreihendaten, bei denen der vorherige Wert beibehalten werden soll, bis neue Daten verfügbar sind.
  </BaseQuizAnswer>
</BaseQuiz>

### Datentransformation

Daten-Normalisierung (Skalierung von Daten in einen Standardbereich wie [0, 1]) hilft, Verzerrungen aufgrund von Unterschieden in der Merkmalsgröße zu vermeiden.

```python
# Skalierung und Normalisierung
from sklearn.preprocessing import StandardScaler,
MinMaxScaler
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df[numeric_columns])
# Min-Max-Skalierung auf [0,1]
minmax = MinMaxScaler()
df_normalized =
minmax.fit_transform(df[numeric_columns])
# Kategorische Variablen kodieren
pd.get_dummies(df, columns=['category_column'])
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
df['encoded'] = le.fit_transform(df['category'])
```

<BaseQuiz id="datascience-scaling-1" correct="C">
  <template #question>
    Was ist der Unterschied zwischen StandardScaler und MinMaxScaler?
  </template>
  
  <BaseQuizOption value="A">Es gibt keinen Unterschied</BaseQuizOption>
  <BaseQuizOption value="B">StandardScaler skaliert auf [0,1], MinMaxScaler skaliert auf Mittelwert=0, Standardabweichung=1</BaseQuizOption>
  <BaseQuizOption value="C" correct>StandardScaler normalisiert auf Mittelwert=0 und Standardabweichung=1, MinMaxScaler skaliert auf den Bereich [0,1]</BaseQuizOption>
  <BaseQuizOption value="D">StandardScaler ist schneller</BaseQuizOption>
  
  <BaseQuizAnswer>
    StandardScaler transformiert Daten so, dass sie einen Mittelwert von 0 und eine Standardabweichung von 1 haben (Z-Score-Normalisierung). MinMaxScaler skaliert Daten auf einen festen Bereich, typischerweise [0, 1]. Beide sind nützlich, aber für unterschiedliche Szenarien.
  </BaseQuizAnswer>
</BaseQuiz>

### Ausreißererkennung & -behandlung

Extremwerte identifizieren und behandeln, die die Analyse verzerren können.

```python
# Statistische Ausreißererkennung
Q1 = df['column'].quantile(0.25)
Q3 = df['column'].quantile(0.75)
IQR = Q3 - Q1
untere_grenze = Q1 - 1.5 * IQR
obere_grenze = Q3 + 1.5 * IQR
# Ausreißer entfernen
df_clean = df[(df['column'] >= untere_grenze) &
              (df['column'] <= obere_grenze)]
# Z-Score-Methode
from scipy import stats
z_scores = np.abs(stats.zscore(df['column']))
df_no_outliers = df[z_scores < 3]
```

### Feature Engineering

Erstellen Sie neue Variablen, um die Modellleistung zu verbessern.

```python
# Neue Features erstellen
df['feature_ratio'] = df['feature1'] / df['feature2']
df['feature_sum'] = df['feature1'] + df['feature2']
# Datums-/Zeit-Features
df['date'] = pd.to_datetime(df['date'])
df['year'] = df['date'].dt.year
df['month'] = df['date'].dt.month
df['day_of_week'] = df['date'].dt.day_name()
# Kontinuierliche Variablen bündeln (Binning)
df['age_group'] = pd.cut(df['age'], bins=[0, 18, 35, 50, 100],
                        labels=['Kind', 'Junger Erwachsener', 'Erwachsener',
'Senior'])
```

## Statistische Analyse

### Beschreibende Statistik

Diese Maße der zentralen Tendenz fassen Daten zusammen und geben Aufschluss über ihre Verteilung. Sie sind grundlegend für das Verständnis jedes Datensatzes. Der Mittelwert ist der Durchschnitt aller Werte in einem Datensatz. Er ist sehr empfindlich gegenüber Ausreißern.

```python
# Zentrale Tendenz
mean = df['column'].mean()
median = df['column'].median()
mode = df['column'].mode()[0]
# Variabilitätsmaße
std_dev = df['column'].std()
variance = df['column'].var()
range_val = df['column'].max() - df['column'].min()
# Verteilungsform
skewness = df['column'].skew()
kurtosis = df['column'].kurtosis()
# Perzentile
percentiles = df['column'].quantile([0.25, 0.5, 0.75, 0.95])
```

### Hypothesentests

Statistische Hypothesen testen und Annahmen validieren.

```python
# T-Test zum Vergleich von Mittelwerten
from scipy.stats import ttest_ind, ttest_1samp
# Ein-Stichproben-T-Test
t_stat, p_value = ttest_1samp(data, population_mean)
# Zwei-Stichproben-T-Test
group1 = df[df['group'] == 'A']['value']
group2 = df[df['group'] == 'B']['value']
t_stat, p_value = ttest_ind(group1, group2)
# Chi-Quadrat-Test auf Unabhängigkeit
from scipy.stats import chi2_contingency
chi2, p_value, dof, expected =
chi2_contingency(contingency_table)
```

### Korrelationsanalyse

Beziehungen zwischen Variablen verstehen.

```python
# Korrelationsmatrix
correlation_matrix = df.corr()
plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix, annot=True,
cmap='coolwarm')
# Spezifische Korrelationen
pearson_corr = df['var1'].corr(df['var2'])
spearman_corr = df['var1'].corr(df['var2'],
method='spearman')
# Statistische Signifikanz der Korrelation
from scipy.stats import pearsonr
correlation, p_value = pearsonr(df['var1'], df['var2'])
```

### ANOVA & Regression

Varianz und Beziehungen zwischen Variablen analysieren.

```python
# Einweg-ANOVA
from scipy.stats import f_oneway
group_data = [df[df['group'] == g]['value'] for g in
df['group'].unique()]
f_stat, p_value = f_oneway(*group_data)
# Lineare Regressionsanalyse
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score
X = df[['feature1', 'feature2']]
y = df['target']
model = LinearRegression().fit(X, y)
y_pred = model.predict(X)
r2 = r2_score(y, y_pred)
```

## Machine-Learning-Modelle

### Überwachtes Lernen – Klassifikation

Entscheidungsbäume: Ein baumartiges Modell von Entscheidungen und ihren möglichen Konsequenzen. Jeder Knoten stellt einen Test eines Attributs dar, und jeder Ast stellt das Ergebnis dar. Wird häufig für Klassifikationsaufgaben verwendet.

```python
# Train-Test-Split
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y,
test_size=0.2, random_state=42)
# Logistische Regression
from sklearn.linear_model import LogisticRegression
log_reg = LogisticRegression()
log_reg.fit(X_train, y_train)
y_pred = log_reg.predict(X_test)
# Entscheidungsbaum
from sklearn.tree import DecisionTreeClassifier
dt = DecisionTreeClassifier(max_depth=5)
dt.fit(X_train, y_train)
# Random Forest
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=100)
rf.fit(X_train, y_train)
```

### Überwachtes Lernen – Regression

Kontinuierliche Zielvariablen vorhersagen.

```python
# Lineare Regression
from sklearn.linear_model import LinearRegression
lr = LinearRegression()
lr.fit(X_train, y_train)
y_pred = lr.predict(X_test)
# Polynomielle Regression
from sklearn.preprocessing import PolynomialFeatures
poly = PolynomialFeatures(degree=2)
X_poly = poly.fit_transform(X)
# Ridge- & Lasso-Regression
from sklearn.linear_model import Ridge, Lasso
ridge = Ridge(alpha=1.0)
lasso = Lasso(alpha=0.1)
ridge.fit(X_train, y_train)
lasso.fit(X_train, y_train)
```

### Unüberwachtes Lernen

Muster in Daten ohne gekennzeichnete Ergebnisse entdecken.

```python
# K-Means-Clustering
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
clusters = kmeans.fit_predict(X)
df['cluster'] = clusters
# Hauptkomponentenanalyse (PCA)
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)
# Hierarchisches Clustering
from scipy.cluster.hierarchy import dendrogram, linkage
linkage_matrix = linkage(X_scaled, method='ward')
dendrogram(linkage_matrix)
```

### Modellevaluierung

Die Modellleistung anhand geeigneter Metriken bewerten.

```python
# Klassifikationsmetriken
from sklearn.metrics import accuracy_score,
precision_score, recall_score, f1_score, confusion_matrix
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred,
average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
# Konfusionsmatrix
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d')
# Regressionsmetriken
from sklearn.metrics import mean_squared_error,
mean_absolute_error
mse = mean_squared_error(y_test, y_pred)
mae = mean_absolute_error(y_test, y_pred)
rmse = np.sqrt(mse)
```

## Datenvisualisierung

### Explorative Visualisierungen

Verteilungen und Beziehungen der Daten verstehen.

```python
# Verteilungsdiagramme
plt.figure(figsize=(12, 4))
plt.subplot(1, 3, 1)
plt.hist(df['numeric_col'], bins=20, edgecolor='black')
plt.subplot(1, 3, 2)
sns.boxplot(y=df['numeric_col'])
plt.subplot(1, 3, 3)
sns.violinplot(y=df['numeric_col'])
# Beziehungsdiagramme
plt.figure(figsize=(10, 6))
sns.scatterplot(data=df, x='feature1', y='feature2',
hue='category')
sns.regplot(data=df, x='feature1', y='target')
# Kategorische Daten
sns.countplot(data=df, x='category')
sns.barplot(data=df, x='category', y='value')
```

### Erweiterte Visualisierungen

Umfassende Dashboards und Berichte erstellen.

```python
# Subplots für mehrere Ansichten
fig, axes = plt.subplots(2, 2, figsize=(15, 10))
axes[0,0].hist(df['col1'])
axes[0,1].scatter(df['col1'], df['col2'])
axes[1,0].boxplot(df['col1'])
sns.heatmap(df.corr(), ax=axes[1,1])
# Interaktive Diagramme mit Plotly
import plotly.express as px
fig = px.scatter(df, x='feature1', y='feature2',
                color='category', size='value',
                hover_data=['additional_info'])
fig.show()
```

### Statistische Diagramme

Statistische Beziehungen und Modellergebnisse visualisieren.

```python
# Streudiagramme für Korrelation
sns.pairplot(df, hue='target_category')
# Residuenplots für Regression
plt.figure(figsize=(12, 4))
plt.subplot(1, 2, 1)
plt.scatter(y_pred, y_test - y_pred)
plt.xlabel('Vorhergesagt')
plt.ylabel('Residuen')
plt.subplot(1, 2, 2)
plt.scatter(y_test, y_pred)
plt.plot([y_test.min(), y_test.max()], [y_test.min(),
y_test.max()], 'r--')
# ROC-Kurve für Klassifikation
from sklearn.metrics import roc_curve, auc
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, label=f'ROC-Kurve (AUC = {roc_auc:.2f})')
```

### Anpassung & Styling

Professionelle Formatierung von Visualisierungen.

```python
# Stil und Farben einstellen
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")
# Benutzerdefinierte Figureneinstellungen
plt.figure(figsize=(12, 8))
plt.title('Professioneller Diagrammtitel', fontsize=16,
fontweight='bold')
plt.xlabel('X-Achsen-Beschriftung', fontsize=14)
plt.ylabel('Y-Achsen-Beschriftung', fontsize=14)
plt.legend(loc='best')
plt.grid(True, alpha=0.3)
plt.tight_layout()
# Hochwertige Diagramme speichern
plt.savefig('analysis_plot.png', dpi=300,
bbox_inches='tight')
```

## Modellbereitstellung & MLOps

### Modellpersistenz

Trainierte Modelle für die Produktionsnutzung speichern und laden.

```python
# Modelle mit pickle speichern
import pickle
with open('model.pkl', 'wb') as f:
    pickle.dump(trained_model, f)
# Gespeichertes Modell laden
with open('model.pkl', 'rb') as f:
    loaded_model = pickle.load(f)
# Verwendung von joblib für sklearn-Modelle
import joblib
joblib.dump(trained_model, 'model.joblib')
loaded_model = joblib.load('model.joblib')
# Modellversionierung mit Zeitstempeln
import datetime
timestamp =
datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
model_name = f'model_{timestamp}.pkl'
```

### Kreuzvalidierung & Hyperparameter-Tuning

Modellleistung optimieren und Überanpassung verhindern.

```python
# Kreuzvalidierung
from sklearn.model_selection import cross_val_score,
StratifiedKFold
cv_scores = cross_val_score(model, X, y, cv=5,
scoring='accuracy')
print(f"CV Genauigkeit: {cv_scores.mean():.3f} (+/-
{cv_scores.std() * 2:.3f})")
# Grid Search für Hyperparameter-Tuning
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

### Leistungsüberwachung

Schneller Zugriff auf wesentliche Konzepte und Befehle kann den Unterschied in Ihrem Workflow ausmachen. Egal, ob Sie als Anfänger Fuß fassen oder als erfahrener Praktiker eine zuverlässige Referenz suchen, Spickzettel sind unschätzbare Begleiter.

```python
# Modellleistungsverfolgung
import time
start_time = time.time()
predictions = model.predict(X_test)
inference_time = time.time() - start_time
print(f"Inferenzzeit: {inference_time:.4f} Sekunden")
# Speicherüberwachung
import psutil
process = psutil.Process()
memory_usage = process.memory_info().rss / 1024 /
1024  # MB
print(f"Speichernutzung: {memory_usage:.2f} MB")
# Feature-Wichtigkeitsanalyse
feature_importance = model.feature_importances_
importance_df = pd.DataFrame({
    'feature': X.columns,
    'importance': feature_importance
}).sort_values('importance', ascending=False)
```

### Modelldokumentation

Annahmen, Leistung und Verwendung des Modells dokumentieren.

```python
# Modellbericht erstellen
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
# Modellmetadaten speichern
import json
with open('model_metadata.json', 'w') as f:
    json.dump(model_report, f, indent=2)
```

## Best Practices & Tipps

### Code-Organisation

Projekte für Reproduzierbarkeit und Zusammenarbeit strukturieren.

```python
# Projektstruktur
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
# Versionskontrolle mit git
git init
git add .
git commit -m "Initial data
science project setup"
```

### Umgebungsmanagement

Reproduzierbare Umgebungen auf verschiedenen Systemen gewährleisten.

```bash
# Virtuelle Umgebung erstellen
python -m venv ds_env
source ds_env/bin/activate  #
Linux/Mac
# ds_env\Scripts\activate   #
Windows
# Requirements-Datei
pip freeze > requirements.txt
# Conda-Umgebung
conda create -n ds_project
python=3.9
conda activate ds_project
conda install pandas numpy
scikit-learn matplotlib seaborn
jupyter
```

### Datenqualitätsprüfungen

Die Datenintegrität während des gesamten Prozesses validieren.

```python
# Datenvalidierungsfunktionen
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
# Automatisierter Datenqualitätsbericht
def data_quality_report(df):
    print(f"Dataset-Form:
{df.shape}")
    print(f"Fehlende Werte:
{df.isnull().sum().sum()}")
    print(f"Duplizierte Zeilen:
{df.duplicated().sum()}")
    print("\nDatentypen der Spalten:")
    print(df.dtypes)
```

## Relevante Links

- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/pandas">Pandas Spickzettel</router-link>
- <router-link to="/numpy">NumPy Spickzettel</router-link>
- <router-link to="/matplotlib">Matplotlib Spickzettel</router-link>
- <router-link to="/sklearn">Scikit-learn Spickzettel</router-link>
- <router-link to="/database">Datenbank Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>

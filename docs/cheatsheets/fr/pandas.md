---
title: 'Fiche Mémo Pandas | LabEx'
description: "Maîtrisez la manipulation de données Pandas avec cette fiche mémo complète. Référence rapide pour les opérations DataFrame, le nettoyage de données, le filtrage, le regroupement, la fusion et l'analyse de données Python."
pdfUrl: '/cheatsheets/pdf/pandas-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Pandas
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/pandas">Apprenez Pandas avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la manipulation de données Pandas grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours Pandas complets couvrant les opérations essentielles, le nettoyage des données, l'analyse et la visualisation. Apprenez à travailler avec des DataFrames, à gérer les données manquantes, à effectuer des agrégations et à analyser efficacement des ensembles de données en utilisant la puissante bibliothèque d'analyse de données de Python.
</base-disclaimer-content>
</base-disclaimer>

## Chargement et Sauvegarde des Données

### Lire un CSV : `pd.read_csv()`

Charger des données à partir d'un fichier CSV dans un DataFrame.

```python
import pandas as pd
# Lire un fichier CSV
df = pd.read_csv('data.csv')
# Définir la première colonne comme index
df = pd.read_csv('data.csv', index_col=0)
# Spécifier un séparateur différent
df = pd.read_csv('data.csv', sep=';')
# Analyser les dates
df = pd.read_csv('data.csv', parse_dates=['Date'])
```

<BaseQuiz id="pandas-read-csv-1" correct="B">
  <template #question>
    Que retourne <code>pd.read_csv('data.csv')</code> ?
  </template>
  
  <BaseQuizOption value="A">Une liste de dictionnaires</BaseQuizOption>
  <BaseQuizOption value="B" correct>Un DataFrame pandas</BaseQuizOption>
  <BaseQuizOption value="C">Un tableau NumPy</BaseQuizOption>
  <BaseQuizOption value="D">Une chaîne de caractères</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>pd.read_csv()</code> lit un fichier CSV et retourne un DataFrame pandas, qui est une structure de données bidimensionnelle étiquetée avec des colonnes et des lignes.
  </BaseQuizAnswer>
</BaseQuiz>

### Lire un Excel : `pd.read_excel()`

Charger des données à partir d'un fichier Excel.

```python
# Lire la première feuille
df = pd.read_excel('data.xlsx')
# Lire une feuille spécifique
df = pd.read_excel('data.xlsx', sheet_name='Sheet2')
# Définir la ligne 2 comme en-tête (indexé à partir de 0)
df = pd.read_excel('data.xlsx', header=1)
```

### Lire SQL : `pd.read_sql()`

Lire une requête SQL ou une table dans un DataFrame.

```python
from sqlalchemy import create_engine
engine = create_engine('sqlite:///my_database.db')
df = pd.read_sql('SELECT * FROM users', engine)
df = pd.read_sql_table('products', engine)
```

### Sauvegarder en CSV : `df.to_csv()`

Écrire le DataFrame dans un fichier CSV.

```python
# Exclure la colonne d'index
df.to_csv('output.csv', index=False)
# Exclure la ligne d'en-tête
df.to_csv('output.csv', header=False)
```

### Sauvegarder en Excel : `df.to_excel()`

Écrire le DataFrame dans un fichier Excel.

```python
# Sauvegarder en Excel
df.to_excel('output.xlsx', sheet_name='Résultats')
writer = pd.ExcelWriter('output.xlsx')
df1.to_excel(writer, sheet_name='Feuille1')
df2.to_excel(writer, sheet_name='Feuille2')
writer.save()
```

### Sauvegarder en SQL : `df.to_sql()`

Écrire le DataFrame dans une table de base de données SQL.

```python
# Créer/remplacer la table
df.to_sql('new_table', engine, if_exists='replace', index=False)
# Ajouter à la table existante
df.to_sql('existing_table', engine, if_exists='append')
```

## Informations et Structure du DataFrame

### Informations de Base : `df.info()`

Affiche un résumé concis d'un DataFrame, y compris les types de données et les valeurs non nulles.

```python
# Afficher le résumé du DataFrame
df.info()
# Afficher les types de données de chaque colonne
df.dtypes
# Obtenir le nombre de lignes et de colonnes (tuple)
df.shape
# Obtenir les noms des colonnes
df.columns
# Obtenir l'index des lignes
df.index
```

### Statistiques Descriptives : `df.describe()`

Génère des statistiques descriptives des colonnes numériques.

```python
# Statistiques récapitulatives pour les colonnes numériques
df.describe()
# Résumé pour une colonne spécifique
df['column'].describe()
# Inclure toutes les colonnes (y compris le type objet)
df.describe(include='all')
```

### Voir les Données : `df.head()` / `df.tail()`

Afficher les 'n' premières ou dernières lignes du DataFrame.

```python
# Premières 5 lignes
df.head()
# Dernières 10 lignes
df.tail(10)
# 5 lignes aléatoires
df.sample(5)
```

## Nettoyage et Transformation des Données

### Valeurs Manquantes : `isnull()` / `fillna()` / `dropna()`

Identifier, remplir ou supprimer les valeurs manquantes (NaN).

```python
# Compter les valeurs manquantes par colonne
df.isnull().sum()
# Remplir tous les NaN avec 0
df.fillna(0)
# Remplir avec la moyenne de la colonne
df['col'].fillna(df['col'].mean())
# Supprimer les lignes avec n'importe quel NaN
df.dropna()
# Supprimer les colonnes avec n'importe quel NaN
df.dropna(axis=1)
```

<BaseQuiz id="pandas-missing-1" correct="B">
  <template #question>
    Que fait <code>df.dropna(axis=1)</code> ?
  </template>
  
  <BaseQuizOption value="A">Supprime les lignes avec des valeurs manquantes</BaseQuizOption>
  <BaseQuizOption value="B" correct>Supprime les colonnes avec des valeurs manquantes</BaseQuizOption>
  <BaseQuizOption value="C">Remplit les valeurs manquantes avec 0</BaseQuizOption>
  <BaseQuizOption value="D">Compte les valeurs manquantes</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le paramètre <code>axis=1</code> signifie "colonnes", donc <code>df.dropna(axis=1)</code> supprime les colonnes qui contiennent des valeurs manquantes. Utilisez <code>axis=0</code> (par défaut) pour supprimer les lignes.
  </BaseQuizAnswer>
</BaseQuiz>

### Doublons : `duplicated()` / `drop_duplicates()`

Identifier et supprimer les lignes dupliquées.

```python
# Série booléenne indiquant les doublons
df.duplicated()
# Supprimer toutes les lignes dupliquées
df.drop_duplicates()
# Supprimer en se basant sur des colonnes spécifiques
df.drop_duplicates(subset=['col1', 'col2'])
```

<BaseQuiz id="pandas-duplicates-1" correct="A">
  <template #question>
    Que fait <code>df.drop_duplicates()</code> par défaut ?
  </template>
  
  <BaseQuizOption value="A" correct>Supprime les lignes dupliquées, en conservant la première occurrence</BaseQuizOption>
  <BaseQuizOption value="B">Supprime toutes les lignes</BaseQuizOption>
  <BaseQuizOption value="C">Ne conserve que les lignes dupliquées</BaseQuizOption>
  <BaseQuizOption value="D">Supprime la première occurrence des doublons</BaseQuizOption>
  
  <BaseQuizAnswer>
    Par défaut, <code>drop_duplicates()</code> conserve la première occurrence de chaque ligne dupliquée et supprime les doublons suivants. Vous pouvez utiliser <code>keep='last'</code> pour conserver la dernière occurrence à la place.
  </BaseQuizAnswer>
</BaseQuiz>

### Types de Données : `astype()`

Changer le type de données d'une colonne.

```python
# Changer en entier
df['col'].astype(int)
# Changer en chaîne de caractères
df['col'].astype(str)
# Convertir en datetime
df['col'] = pd.to_datetime(df['col'])
```

### Appliquer une Fonction : `apply()` / `map()` / `replace()`

Appliquer des fonctions ou remplacer des valeurs dans des DataFrames/Séries.

```python
# Appliquer une fonction lambda à une colonne
df['col'].apply(lambda x: x*2)
# Mapper des valeurs en utilisant un dictionnaire
df['col'].map({'old': 'new'})
# Remplacer des valeurs
df.replace('old_val', 'new_val')
# Remplacer plusieurs valeurs
df.replace(['A', 'B'], ['C', 'D'])
```

<BaseQuiz id="pandas-apply-1" correct="A">
  <template #question>
    Que fait <code>df['col'].apply(lambda x: x*2)</code> ?
  </template>
  
  <BaseQuizOption value="A" correct>Applique une fonction à chaque élément de la colonne, multipliant chacun par 2</BaseQuizOption>
  <BaseQuizOption value="B">Multiplie la colonne entière par 2 une seule fois</BaseQuizOption>
  <BaseQuizOption value="C">Remplace la colonne par 2</BaseQuizOption>
  <BaseQuizOption value="D">Compte les éléments dans la colonne</BaseQuizOption>
  
  <BaseQuizAnswer>
    La méthode <code>apply()</code> applique une fonction à chaque élément d'une Série. La fonction lambda <code>lambda x: x*2</code> multiplie chaque valeur par 2, retournant une nouvelle Série avec les valeurs transformées.
  </BaseQuizAnswer>
</BaseQuiz>

## Inspection du DataFrame

### Valeurs Uniques : `unique()` / `value_counts()`

Explorer les valeurs uniques et leurs fréquences.

```python
# Obtenir les valeurs uniques dans une colonne
df['col'].unique()
# Obtenir le nombre de valeurs uniques
df['col'].nunique()
# Compter les occurrences de chaque valeur unique
df['col'].value_counts()
# Proportions des valeurs uniques
df['col'].value_counts(normalize=True)
```

### Corrélation : `corr()` / `cov()`

Calculer la corrélation et la covariance entre les colonnes numériques.

```python
# Corrélation par paires des colonnes
df.corr()
# Covariance par paires des colonnes
df.cov()
# Corrélation entre deux colonnes spécifiques
df['col1'].corr(df['col2'])
```

### Agrégations : `groupby()` / `agg()`

Grouper les données par catégories et appliquer des fonctions d'agrégation.

```python
# Moyenne pour chaque catégorie
df.groupby('category_col').mean()
# Grouper par plusieurs colonnes
df.groupby(['col1', 'col2']).sum()
# Agrégations multiples
df.groupby('category_col').agg({'num_col': ['min', 'max', 'mean']})
```

### Tableaux Croisés : `pd.crosstab()`

Calculer une table de fréquences de deux facteurs ou plus.

```python
df.pivot_table(values='sales', index='region', columns='product', aggfunc='sum')
# Tableau de fréquences simple
pd.crosstab(df['col1'], df['col2'])
# Avec sommes de lignes/colonnes
pd.crosstab(df['col1'], df['col2'], margins=True)
# Avec valeurs agrégées
pd.crosstab(df['col1'], df['col2'], values=df['value_col'], aggfunc='mean')
```

## Gestion de la Mémoire

### Utilisation de la Mémoire : `df.memory_usage()`

Afficher l'utilisation de la mémoire de chaque colonne ou du DataFrame entier.

```python
# Utilisation de la mémoire de chaque colonne
df.memory_usage()
# Utilisation totale de la mémoire en octets
df.memory_usage(deep=True).sum()
# Utilisation détaillée de la mémoire dans la sortie de info()
df.info(memory_usage='deep')
```

### Optimiser les Types de Données : `astype()`

Réduire la mémoire en convertissant les colonnes en types de données plus petits et appropriés.

```python
# Réduire un entier
df['int_col'] = df['int_col'].astype('int16')
# Réduire un flottant
df['float_col'] = df['float_col'].astype('float32')
# Utiliser le type catégoriel
df['category_col'] = df['category_col'].astype('category')
```

### Fichiers Volumineux : `read_csv(chunksize=...)`

Traiter les fichiers volumineux par morceaux pour éviter de tout charger en mémoire à la fois.

```python
chunk_iterator = pd.read_csv('large_data.csv', chunksize=10000)
for chunk in chunk_iterator:
    # Traiter chaque morceau
    print(chunk.shape)
# Concaténer les morceaux traités (si nécessaire)
# processed_chunks = []
# for chunk in chunk_iterator:
#    processed_chunks.append(process_chunk(chunk))
# final_df = pd.concat(processed_chunks)
```

## Importation/Exportation de Données

### Lire JSON : `pd.read_json()`

Charger des données à partir d'un fichier JSON ou d'une URL.

```python
# Lire depuis un JSON local
df = pd.read_json('data.json')
# Lire depuis une URL
df = pd.read_json('http://example.com/api/data')
# Lire depuis une chaîne JSON
df = pd.read_json(json_string_data)
```

### Lire HTML : `pd.read_html()`

Analyser les tables HTML à partir d'une URL, d'une chaîne ou d'un fichier.

```python
tables = pd.read_html('http://www.w3.org/TR/html401/sgml/entities.html')
# Retourne généralement une liste de DataFrames
df = tables[0]
```

### Vers JSON : `df.to_json()`

Écrire le DataFrame au format JSON.

```python
# Vers un fichier JSON
df.to_json('output.json', orient='records', indent=4)
# Vers une chaîne JSON
json_str = df.to_json(orient='split')
```

### Vers HTML : `df.to_html()`

Rendre le DataFrame sous forme de tableau HTML.

```python
# Vers une chaîne HTML
html_table_str = df.to_html()
# Vers un fichier HTML
df.to_html('output.html', index=False)
```

### Lire le Presse-papiers : `pd.read_clipboard()`

Lire le texte du presse-papiers dans un DataFrame.

```python
# Copier les données du tableau depuis le web/tableur et exécuter
df = pd.read_clipboard()
```

## Sérialisation des Données

### Pickle : `df.to_pickle()` / `pd.read_pickle()`

Sérialiser/désérialiser des objets Pandas vers/depuis le disque.

```python
# Sauvegarder le DataFrame comme un fichier pickle
df.to_pickle('my_dataframe.pkl')
# Charger le DataFrame
loaded_df = pd.read_pickle('my_dataframe.pkl')
```

### HDF5 : `df.to_hdf()` / `pd.read_hdf()`

Stocker/charger des DataFrames en utilisant le format HDF5, idéal pour les grands ensembles de données.

```python
# Sauvegarder en HDF5
df.to_hdf('my_data.h5', key='df', mode='w')
# Charger depuis HDF5
loaded_df = pd.read_hdf('my_data.h5', key='df')
```

## Filtrage et Sélection des Données

### Basé sur les Étiquettes : `df.loc[]` / `df.at[]`

Sélectionner des données par étiquette explicite d'index/colonnes.

```python
# Sélectionner la ligne avec l'index 0
df.loc[0]
# Sélectionner toutes les lignes pour 'col1'
df.loc[:, 'col1']
# Trancher les lignes et sélectionner plusieurs colonnes
df.loc[0:5, ['col1', 'col2']]
# Indexation booléenne pour les lignes
df.loc[df['col'] > 5]
# Accès scalaire rapide par étiquette
df.at[0, 'col1']
```

### Basé sur la Position : `df.iloc[]` / `df.iat[]`

Sélectionner des données par position entière d'index/colonnes.

```python
# Sélectionner la première ligne par position
df.iloc[0]
# Sélectionner la première colonne par position
df.iloc[:, 0]
# Trancher les lignes et sélectionner plusieurs colonnes par position
df.iloc[0:5, [0, 1]]
# Accès scalaire rapide par position
df.iat[0, 0]
```

### Indexation Booléenne : `df[condition]`

Filtrer les lignes en fonction d'une ou plusieurs conditions.

```python
# Lignes où 'col1' est supérieur à 10
df[df['col1'] > 10]
# Conditions multiples
df[(df['col1'] > 10) & (df['col2'] == 'A')]
# Lignes où 'col1' N'EST PAS dans la liste
df[~df['col1'].isin([1, 2, 3])]
```

### Interroger les Données : `df.query()`

Filtrer les lignes en utilisant une expression de chaîne de requête.

```python
# Équivalent à l'indexation booléenne
df.query('col1 > 10')
# Requête complexe
df.query('col1 > 10 and col2 == "A"')
# Utiliser des variables locales avec '@'
df.query('col1 in @my_list')
```

## Surveillance des Performances

### Chronométrage des Opérations : `%%timeit` / `time`

Mesurer le temps d'exécution du code Python/Pandas.

```python
# Commande magique Jupyter/IPython pour chronométrer une ligne/cellule
%%timeit
df['col'].apply(lambda x: x*2) # Opération exemple

import time
start_time = time.time()
# Votre code Pandas ici
end_time = time.time()
print(f"Temps d'exécution : {end_time - start_time} secondes")
```

### Opérations Optimisées : `eval()` / `query()`

Utiliser ces méthodes pour des performances plus rapides sur de grands DataFrames, en particulier pour les opérations élément par élément et le filtrage.

```python
# Plus rapide que `df['col1'] + df['col2']`
df['new_col'] = df.eval('col1 + col2')
# Filtrage plus rapide
df_filtered = df.query('col1 > @threshold and col2 == "value"')
```

### Profilage du Code : `cProfile` / `line_profiler`

Analyser où le temps est passé dans vos fonctions Python.

```python
import cProfile
def my_pandas_function(df):
    # Opérations Pandas
    return df.groupby('col').mean()
cProfile.run('my_pandas_function(df)') # Exécuter la fonction avec cProfile

# Pour line_profiler (installer avec pip install line_profiler):
# @profile
# def my_function(df):
#    ...
# %load_ext line_profiler
# %lprun -f my_function my_function(df)
```

## Installation et Configuration de Pandas

### Pip : `pip install pandas`

Installateur de paquets Python standard.

```python
# Installer Pandas
pip install pandas
# Mettre à jour Pandas vers la dernière version
pip install pandas --upgrade
# Afficher les informations sur le paquet Pandas installé
pip show pandas
```

### Conda : `conda install pandas`

Gestionnaire de paquets pour les environnements Anaconda/Miniconda.

```python
# Installer Pandas dans l'environnement conda actuel
conda install pandas
# Mettre à jour Pandas
conda update pandas
# Lister le paquet Pandas installé
conda list pandas
# Créer un nouvel environnement avec Pandas
conda create -n myenv pandas
```

### Vérifier la Version / Importer

Vérifier votre installation Pandas et l'importer dans vos scripts.

```python
# Alias d'importation standard
import pandas as pd
# Vérifier la version de Pandas installée
print(pd.__version__)
# Afficher toutes les colonnes
pd.set_option('display.max_columns', None)
# Afficher plus de lignes
pd.set_option('display.max_rows', 100)
```

## Options et Paramètres

### Options d'Affichage : `pd.set_option()`

Contrôler comment les DataFrames sont affichés dans la console/Jupyter.

```python
# Nombre maximal de lignes à afficher
pd.set_option('display.max_rows', 50)
# Afficher toutes les colonnes
pd.set_option('display.max_columns', None)
# Largeur de l'affichage
pd.set_option('display.width', 1000)
# Formater les valeurs flottantes
pd.set_option('display.float_format', '{:.2f}'.format)
```

### Réinitialiser les Options : `pd.reset_option()`

Réinitialiser une option spécifique ou toutes les options à leurs valeurs par défaut.

```python
# Réinitialiser une option spécifique
pd.reset_option('display.max_rows')
# Réinitialiser toutes les options par défaut
pd.reset_option('all')
```

### Obtenir les Options : `pd.get_option()`

Récupérer la valeur actuelle d'une option spécifiée.

```python
# Obtenir le paramètre max_rows actuel
print(pd.get_option('display.max_rows'))
```

### Gestionnaire de Contexte : `pd.option_context()`

Définir temporairement des options dans une instruction `with`.

```python
with pd.option_context('display.max_rows', 10, 'display.max_columns', 5):
    print(df) # DataFrame affiché avec les options temporaires
print(df) # Les options reviennent aux paramètres précédents en dehors du bloc
```

## Enchaînement de Méthodes

### Opérations en Chaîne

Appliquer une séquence de transformations à un DataFrame.

```python
(
    df.dropna(subset=['col1'])
    .assign(new_col = lambda x: x['col2'] * 2)
    .query('new_col > 10')
    .groupby('category_col')
    ['new_col']
    .mean()
    .reset_index()
)
```

### Utilisation de `.pipe()`

Appliquer des fonctions qui prennent le DataFrame comme premier argument, permettant des étapes personnalisées dans une chaîne.

```python
def custom_filter(df, threshold):
    return df[df['value'] > threshold]

(
    df.pipe(custom_filter, threshold=50)
    .groupby('group')
    .agg(total_value=('value', 'sum'))
)
```

## Liens Pertinents

- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/numpy">Feuille de triche NumPy</router-link>
- <router-link to="/matplotlib">Feuille de triche Matplotlib</router-link>
- <router-link to="/sklearn">Feuille de triche scikit-learn</router-link>
- <router-link to="/datascience">Feuille de triche Science des Données</router-link>
- <router-link to="/mysql">Feuille de triche MySQL</router-link>
- <router-link to="/postgresql">Feuille de triche PostgreSQL</router-link>
- <router-link to="/sqlite">Feuille de triche SQLite</router-link>

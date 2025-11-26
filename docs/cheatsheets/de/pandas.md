---
title: 'Pandas Spickzettel'
description: 'Lernen Sie Pandas mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/pandas-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Pandas Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/pandas">Lernen Sie Pandas mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie die Datenmanipulation mit Pandas durch praktische Labs und reale Szenarien. LabEx bietet umfassende Pandas-Kurse, die wesentliche Operationen, Datenbereinigung, Analyse und Visualisierung abdecken. Lernen Sie, effizient mit DataFrames zu arbeiten, fehlende Daten zu behandeln, Aggregationen durchzuführen und Datensätze mithilfe der leistungsstarken Datenanalysebibliothek von Python zu analysieren.
</base-disclaimer-content>
</base-disclaimer>

## Datenladen & Speichern

### CSV lesen: `pd.read_csv()`

Daten aus einer CSV-Datei in einen DataFrame laden.

```python
import pandas as pd
# Eine CSV-Datei lesen
df = pd.read_csv('data.csv')
# Erste Spalte als Index festlegen
df = pd.read_csv('data.csv', index_col=0)
# Einen anderen Separator angeben
df = pd.read_csv('data.csv', sep=';')
# Daten parsen
df = pd.read_csv('data.csv', parse_dates=['Date'])
```

### Excel lesen: `pd.read_excel()`

Daten aus einer Excel-Datei laden.

```python
# Erstes Blatt lesen
df = pd.read_excel('data.xlsx')
# Spezifisches Blatt lesen
df = pd.read_excel('data.xlsx', sheet_name='Sheet2')
# Zeile 2 als Kopfzeile festlegen (0-indiziert)
df = pd.read_excel('data.xlsx', header=1)
```

### SQL lesen: `pd.read_sql()`

SQL-Abfrage oder Tabelle in einen DataFrame lesen.

```python
from sqlalchemy import create_engine
engine = create_engine('sqlite:///my_database.db')
df = pd.read_sql('SELECT * FROM users', engine)
df = pd.read_sql_table('products', engine)
```

### CSV speichern: `df.to_csv()`

DataFrame in eine CSV-Datei schreiben.

```python
# Indexspalte ausschließen
df.to_csv('output.csv', index=False)
# Kopfzeile ausschließen
df.to_csv('output.csv', header=False)
```

### Excel speichern: `df.to_excel()`

DataFrame in eine Excel-Datei schreiben.

```python
# In Excel speichern
df.to_excel('output.xlsx', sheet_name='Results')
writer = pd.ExcelWriter('output.xlsx')
df1.to_excel(writer, sheet_name='Sheet1')
df2.to_excel(writer, sheet_name='Sheet2')
writer.save()
```

### SQL speichern: `df.to_sql()`

DataFrame in eine SQL-Datenbanktabelle schreiben.

```python
# Tabelle erstellen/ersetzen
df.to_sql('new_table', engine, if_exists='replace', index=False)
# An bestehende Tabelle anhängen
df.to_sql('existing_table', engine, if_exists='append')
```

## DataFrame Info & Struktur

### Basisinformationen: `df.info()`

Gibt eine prägnante Zusammenfassung eines DataFrames aus, einschließlich Datentypen und nicht-null-Werten.

```python
# DataFrame-Zusammenfassung anzeigen
df.info()
# Datentypen jeder Spalte anzeigen
df.dtypes
# Anzahl der Zeilen und Spalten abrufen (Tupel)
df.shape
# Spaltennamen abrufen
df.columns
# Zeilenindex abrufen
df.index
```

### Beschreibende Statistiken: `df.describe()`

Erzeugt beschreibende Statistiken für numerische Spalten.

```python
# Zusammenfassende Statistiken für numerische Spalten
df.describe()
# Zusammenfassung für eine bestimmte Spalte
df['column'].describe()
# Alle Spalten einschließen (auch Objekttyp)
df.describe(include='all')
```

### Daten anzeigen: `df.head()` / `df.tail()`

Die ersten oder letzten 'n' Zeilen des DataFrames anzeigen.

```python
# Erste 5 Zeilen
df.head()
# Letzte 10 Zeilen
df.tail(10)
# Zufällige 5 Zeilen
df.sample(5)
```

## Datenbereinigung & Transformation

### Fehlende Werte: `isnull()` / `fillna()` / `dropna()`

Fehlende (NaN) Werte identifizieren, füllen oder entfernen.

```python
# Fehlende Werte pro Spalte zählen
df.isnull().sum()
# Alle NaN mit 0 füllen
df.fillna(0)
# Mit Spaltenmittelwert füllen
df['col'].fillna(df['col'].mean())
# Zeilen mit beliebigen NaN entfernen
df.dropna()
# Spalten mit beliebigen NaN entfernen
df.dropna(axis=1)
```

### Duplikate: `duplicated()` / `drop_duplicates()`

Doppelte Zeilen identifizieren und entfernen.

```python
# Boolesche Serie, die Duplikate anzeigt
df.duplicated()
# Alle doppelten Zeilen entfernen
df.drop_duplicates()
# Basierend auf bestimmten Spalten entfernen
df.drop_duplicates(subset=['col1', 'col2'])
```

### Datentypen: `astype()`

Den Datentyp einer Spalte ändern.

```python
# In Integer ändern
df['col'].astype(int)
# In String ändern
df['col'].astype(str)
# In Datum/Uhrzeit konvertieren
df['col'] = pd.to_datetime(df['col'])
```

### Funktion anwenden: `apply()` / `map()` / `replace()`

Funktionen anwenden oder Werte in DataFrames/Serien ersetzen.

```python
# Lambda-Funktion auf eine Spalte anwenden
df['col'].apply(lambda x: x*2)
# Werte mithilfe eines Wörterbuchs zuordnen
df['col'].map({'old': 'new'})
# Werte ersetzen
df.replace('old_val', 'new_val')
# Mehrere Werte ersetzen
df.replace(['A', 'B'], ['C', 'D'])
```

## DataFrame Inspektion

### Eindeutige Werte: `unique()` / `value_counts()`

Eindeutige Werte und deren Häufigkeiten untersuchen.

```python
# Eindeutige Werte in einer Spalte abrufen
df['col'].unique()
# Anzahl der eindeutigen Werte abrufen
df['col'].nunique()
# Vorkommen jedes eindeutigen Werts zählen
df['col'].value_counts()
# Anteile der eindeutigen Werte
df['col'].value_counts(normalize=True)
```

### Korrelation: `corr()` / `cov()`

Korrelation und Kovarianz zwischen numerischen Spalten berechnen.

```python
# Paarweise Korrelation der Spalten
df.corr()
# Paarweise Kovarianz der Spalten
df.cov()
# Korrelation zwischen zwei spezifischen Spalten
df['col1'].corr(df['col2'])
```

### Aggregationen: `groupby()` / `agg()`

Daten nach Kategorien gruppieren und Aggregatfunktionen anwenden.

```python
# Mittelwert für jede Kategorie
df.groupby('category_col').mean()
# Nach mehreren Spalten gruppieren
df.groupby(['col1', 'col2']).sum()
# Mehrere Aggregationen
df.groupby('category_col').agg({'num_col': ['min', 'max', 'mean']})
```

### Kreuztabellen: `pd.crosstab()`

Eine Häufigkeitstabelle von zwei oder mehr Faktoren berechnen.

```python
df.pivot_table(values='sales', index='region', columns='product', aggfunc='sum')
# Einfache Häufigkeitstabelle
pd.crosstab(df['col1'], df['col2'])
# Mit Zeilen-/Spaltensummen
pd.crosstab(df['col1'], df['col2'], margins=True)
# Mit aggregierten Werten
pd.crosstab(df['col1'], df['col2'], values=df['value_col'], aggfunc='mean')
```

## Speichermanagement

### Speichernutzung: `df.memory_usage()`

Die Speichernutzung jeder Spalte oder des gesamten DataFrames anzeigen.

```python
# Speichernutzung jeder Spalte
df.memory_usage()
# Gesamte Speichernutzung in Bytes
df.memory_usage(deep=True).sum()
# Detaillierte Speichernutzung in info()-Ausgabe
df.info(memory_usage='deep')
```

### Dtypes optimieren: `astype()`

Speicher reduzieren, indem Spalten in kleinere, geeignete Datentypen umgewandelt werden.

```python
# Integer herunterstufen
df['int_col'] = df['int_col'].astype('int16')
# Float herunterstufen
df['float_col'] = df['float_col'].astype('float32')
# Kategorietyp verwenden
df['category_col'] = df['category_col'].astype('category')
```

### Große Dateien in Chunks verarbeiten: `read_csv(chunksize=...)`

Große Dateien in Blöcken verarbeiten, um zu vermeiden, dass alles auf einmal in den Speicher geladen wird.

```python
chunk_iterator = pd.read_csv('large_data.csv', chunksize=10000)
for chunk in chunk_iterator:
    # Jeden Chunk verarbeiten
    print(chunk.shape)
# Verarbeitete Chunks zusammenfügen (falls erforderlich)
# processed_chunks = []
# for chunk in chunk_iterator:
#    processed_chunks.append(process_chunk(chunk))
# final_df = pd.concat(processed_chunks)
```

## Datenimport/Export

### JSON lesen: `pd.read_json()`

Daten aus einer JSON-Datei oder URL laden.

```python
# Aus lokaler JSON lesen
df = pd.read_json('data.json')
# Von URL lesen
df = pd.read_json('http://example.com/api/data')
# Aus JSON-String lesen
df = pd.read_json(json_string_data)
```

### HTML lesen: `pd.read_html()`

HTML-Tabellen aus einer URL, einem String oder einer Datei parsen.

```python
tables = pd.read_html('http://www.w3.org/TR/html401/sgml/entities.html')
# Gibt normalerweise eine Liste von DataFrames zurück
df = tables[0]
```

### Zu JSON: `df.to_json()`

DataFrame in das JSON-Format schreiben.

```python
# In JSON-Datei schreiben
df.to_json('output.json', orient='records', indent=4)
# In JSON-String schreiben
json_str = df.to_json(orient='split')
```

### Zu HTML: `df.to_html()`

DataFrame als HTML-Tabelle rendern.

```python
# In HTML-String
html_table_str = df.to_html()
# In HTML-Datei
df.to_html('output.html', index=False)
```

### Zwischenablage lesen: `pd.read_clipboard()`

Text aus der Zwischenablage in einen DataFrame lesen.

```python
# Tabellendaten aus dem Web/Tabellenkalkulation kopieren und ausführen
df = pd.read_clipboard()
```

## Daten Serialisierung

### Pickle: `df.to_pickle()` / `pd.read_pickle()`

Pandas-Objekte auf die Festplatte serialisieren/deserialisieren.

```python
# DataFrame als Pickle-Datei speichern
df.to_pickle('my_dataframe.pkl')
# DataFrame laden
loaded_df = pd.read_pickle('my_dataframe.pkl')
```

### HDF5: `df.to_hdf()` / `pd.read_hdf()`

DataFrames im HDF5-Format speichern/laden, gut für große Datensätze.

```python
# In HDF5 speichern
df.to_hdf('my_data.h5', key='df', mode='w')
# Aus HDF5 laden
loaded_df = pd.read_hdf('my_data.h5', key='df')
```

## Datenfilterung & Auswahl

### Label-basiert: `df.loc[]` / `df.at[]`

Daten anhand des expliziten Labels von Index/Spalten auswählen.

```python
# Zeile mit Index 0 auswählen
df.loc[0]
# Alle Zeilen für 'col1' auswählen
df.loc[:, 'col1']
# Zeilenbereich auswählen und mehrere Spalten auswählen
df.loc[0:5, ['col1', 'col2']]
# Boolesche Indizierung für Zeilen
df.loc[df['col'] > 5]
# Schneller Skalarzugriff nach Label
df.at[0, 'col1']
```

### Positionsbasiert: `df.iloc[]` / `df.iat[]`

Daten anhand der ganzzahligen Position von Index/Spalten auswählen.

```python
# Erste Zeile nach Position auswählen
df.iloc[0]
# Erste Spalte nach Position auswählen
df.iloc[:, 0]
# Zeilenbereich auswählen und mehrere Spalten nach Position auswählen
df.iloc[0:5, [0, 1]]
# Schneller Skalarzugriff nach Position
df.iat[0, 0]
```

### Boolesche Indizierung: `df[condition]`

Zeilen basierend auf einer oder mehreren Bedingungen filtern.

```python
# Zeilen, bei denen 'col1' größer als 10 ist
df[df['col1'] > 10]
# Mehrere Bedingungen
df[(df['col1'] > 10) & (df['col2'] == 'A')]
# Zeilen, bei denen 'col1' NICHT in der Liste ist
df[~df['col1'].isin([1, 2, 3])]
```

### Daten abfragen: `df.query()`

Zeilen mithilfe eines Abfragestring-Ausdrucks filtern.

```python
# Äquivalent zur booleschen Indizierung
df.query('col1 > 10')
# Komplexe Abfrage
df.query('col1 > 10 and col2 == "A"')
# Lokale Variablen mit '@' verwenden
df.query('col1 in @my_list')
```

## Leistungsüberwachung

### Operationen timen: `%%timeit` / `time`

Die Ausführungszeit von Python/Pandas-Code messen.

```python
# Jupyter/IPython Magic Command zum Timen einer Zeile/Zelle
%%timeit
df['col'].apply(lambda x: x*2) # Beispieloperation

import time
start_time = time.time()
# Ihr Pandas-Code hier
end_time = time.time()
print(f"Ausführungszeit: {end_time - start_time} Sekunden")
```

### Optimierte Operationen: `eval()` / `query()`

Diese Methoden nutzen, um eine schnellere Leistung bei großen DataFrames zu erzielen, insbesondere bei elementweisen Operationen und Filterungen.

```python
# Schneller als `df['col1'] + df['col2']`
df['new_col'] = df.eval('col1 + col2')
# Schnellere Filterung
df_filtered = df.query('col1 > @threshold and col2 == "value"')
```

### Code profilieren: `cProfile` / `line_profiler`

Analysieren, wo Zeit bei Ihren Python-Funktionen verbracht wird.

```python
import cProfile
def my_pandas_function(df):
    # Pandas-Operationen
    return df.groupby('col').mean()
cProfile.run('my_pandas_function(df)') # Funktion mit cProfile ausführen

# Für line_profiler (mit pip install line_profiler installieren):
# @profile
# def my_function(df):
#    ...
# %load_ext line_profiler
# %lprun -f my_function my_function(df)
```

## Pandas Installation & Setup

### Pip: `pip install pandas`

Standard Python Paketinstallationsprogramm.

```python
# Pandas installieren
pip install pandas
# Pandas auf die neueste Version aktualisieren
pip install pandas --upgrade
# Informationen zum installierten Pandas-Paket anzeigen
pip show pandas
```

### Conda: `conda install pandas`

Paketmanager für Anaconda/Miniconda-Umgebungen.

```python
# Pandas in der aktuellen conda-Umgebung installieren
conda install pandas
# Pandas aktualisieren
conda update pandas
# Installiertes Pandas-Paket auflisten
conda list pandas
# Neue Umgebung mit Pandas erstellen
conda create -n myenv pandas
```

### Version prüfen / Importieren

Die Pandas-Installation überprüfen und sie in Ihren Skripten importieren.

```python
# Standard-Importalias
import pandas as pd
# Installierte Pandas-Version prüfen
print(pd.__version__)
# Alle Spalten anzeigen
pd.set_option('display.max_columns', None)
# Mehr Zeilen anzeigen
pd.set_option('display.max_rows', 100)
```

## Konfiguration & Einstellungen

### Anzeigeoptionen: `pd.set_option()`

Steuern, wie DataFrames in der Konsole/Jupyter angezeigt werden.

```python
# Max. anzuzeigende Zeilen
pd.set_option('display.max_rows', 50)
# Alle Spalten anzeigen
pd.set_option('display.max_columns', None)
# Breite der Anzeige
pd.set_option('display.width', 1000)
# Gleitkommazahlen formatieren
pd.set_option('display.float_format', '{:.2f}'.format)
```

### Optionen zurücksetzen: `pd.reset_option()`

Eine bestimmte Option oder alle Optionen auf ihre Standardwerte zurücksetzen.

```python
# Spezifische Option zurücksetzen
pd.reset_option('display.max_rows')
# Alle Optionen auf Standard zurücksetzen
pd.reset_option('all')
```

### Optionen abrufen: `pd.get_option()`

Den aktuellen Wert einer angegebenen Option abrufen.

```python
# Aktuelle max_rows-Einstellung abrufen
print(pd.get_option('display.max_rows'))
```

### Kontextmanager: `pd.option_context()`

Optionen temporär innerhalb einer `with`-Anweisung festlegen.

```python
with pd.option_context('display.max_rows', 10, 'display.max_columns', 5):
    print(df) # DataFrame wird mit temporären Optionen angezeigt
print(df) # Optionen kehren außerhalb des Blocks zu den vorherigen Einstellungen zurück
```

## Method Chaining

### Operationen verketten

Eine Sequenz von Transformationen auf einen DataFrame anwenden.

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

### `.pipe()` verwenden

Funktionen anwenden, die den DataFrame als erstes Argument akzeptieren, um benutzerdefinierte Schritte in einer Kette zu ermöglichen.

```python
def custom_filter(df, threshold):
    return df[df['value'] > threshold]

(
    df.pipe(custom_filter, threshold=50)
    .groupby('group')
    .agg(total_value=('value', 'sum'))
)
```

## Relevante Links

- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/numpy">NumPy Spickzettel</router-link>
- <router-link to="/matplotlib">Matplotlib Spickzettel</router-link>
- <router-link to="/sklearn">scikit-learn Spickzettel</router-link>
- <router-link to="/datascience">Data Science Spickzettel</router-link>
- <router-link to="/mysql">MySQL Spickzettel</router-link>
- <router-link to="/postgresql">PostgreSQL Spickzettel</router-link>
- <router-link to="/sqlite">SQLite Spickzettel</router-link>

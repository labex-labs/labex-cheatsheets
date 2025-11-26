---
title: 'NumPy Spickzettel'
description: 'Lernen Sie NumPy mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/numpy-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
NumPy Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/numpy">NumPy mit praxisnahen Labs lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie numerisches Rechnen mit NumPy durch praxisnahe Labs und reale Szenarien. LabEx bietet umfassende NumPy-Kurse, die wesentliche Array-Operationen, mathematische Funktionen, lineare Algebra und Leistungsoptimierung abdecken. Meistern Sie effizientes numerisches Rechnen und Array-Manipulation für Data-Science-Workflows.
</base-disclaimer-content>
</base-disclaimer>

## Array-Erstellung & Initialisierung

### Aus Listen: `np.array()`

Erstellen Sie Arrays aus Python-Listen oder verschachtelten Listen.

```python
import numpy as np

# 1D-Array aus Liste
arr = np.array([1, 2, 3, 4])
# 2D-Array aus verschachtelten Listen
arr2d = np.array([[1, 2], [3, 4]])
# Datentyp angeben
arr = np.array([1, 2, 3], dtype=float)
# Array von Strings
arr_str = np.array(['a', 'b', 'c'])
```

### Nullen und Einsen: `np.zeros()` / `np.ones()`

Erstellen Sie Arrays, die mit Nullen oder Einsen gefüllt sind.

```python
# Array von Nullen
zeros = np.zeros(5)  # 1D
zeros2d = np.zeros((3, 4))  # 2D
# Array von Einsen
ones = np.ones((2, 3))
# Datentyp angeben
zeros_int = np.zeros(5, dtype=int)
```

### Einheitsmatrix: `np.eye()` / `np.identity()`

Erstellen Sie Einheitsmatrizen für Operationen der linearen Algebra.

```python
# 3x3 Einheitsmatrix
identity = np.eye(3)
# Alternative Methode
identity2 = np.identity(4)
```

### Bereichs-Arrays: `np.arange()` / `np.linspace()`

Erstellen Sie Arrays mit gleichmäßig verteilten Werten.

```python
# Ähnlich wie Python range
arr = np.arange(10)  # 0 bis 9
arr = np.arange(2, 10, 2)  # 2, 4, 6, 8
# Gleichmäßig verteilte Werte
arr = np.linspace(0, 1, 5)  # 5 Werte von 0 bis 1
# Endpunkt einschließen
arr = np.linspace(0, 10, 11)
```

### Zufalls-Arrays: `np.random`

Generieren Sie Arrays mit Zufallswerten.

```python
# Zufallswerte zwischen 0 und 1
rand = np.random.random((2, 3))
# Zufallsganzzahlen
rand_int = np.random.randint(0, 10, size=(3, 3))
# Normalverteilung
normal = np.random.normal(0, 1, size=5)
# Zufalls-Seed für Reproduzierbarkeit setzen
np.random.seed(42)
```

### Spezial-Arrays: `np.full()` / `np.empty()`

Erstellen Sie Arrays mit spezifischen Werten oder uninitialisiert.

```python
# Mit spezifischem Wert füllen
full_arr = np.full((2, 3), 7)
# Leeres Array (uninitialisiert)
empty_arr = np.empty((2, 2))
# Form wie vorhandenes Array
like_arr = np.zeros_like(arr)
```

## Array-Eigenschaften & Struktur

### Grundlegende Eigenschaften: `shape` / `size` / `ndim`

Rufen Sie grundlegende Informationen zu Array-Dimensionen und -Größe ab.

```python
# Array-Dimensionen (Tupel)
arr.shape
# Gesamtanzahl der Elemente
arr.size
# Anzahl der Dimensionen
arr.ndim
# Datentyp der Elemente
arr.dtype
# Größe jedes Elements in Bytes
arr.itemsize
```

### Array-Infos: Speicherbelegung

Rufen Sie detaillierte Informationen zur Speicherbelegung und Struktur des Arrays ab.

```python
# Speicherbelegung in Bytes
arr.nbytes
# Array-Infos (zur Fehlersuche)
arr.flags
# Prüfen, ob das Array seine Daten besitzt
arr.owndata
# Basisobjekt (falls das Array eine Ansicht ist)
arr.base
```

### Datentypen: `astype()`

Konvertieren Sie effizient zwischen verschiedenen Datentypen.

```python
# In anderen Typ konvertieren
arr.astype(float)
arr.astype(int)
arr.astype(str)
# Spezifischere Typen
arr.astype(np.float32)
arr.astype(np.int16)
```

## Array-Indizierung & Slicing

### Grundlegende Indizierung: `arr[index]`

Greifen Sie auf einzelne Elemente und Slices zu.

```python
# Einzelnes Element
arr[0]  # Erstes Element
arr[-1]  # Letztes Element
# 2D-Array-Indizierung
arr2d[0, 1]  # Zeile 0, Spalte 1
arr2d[1]  # Ganze Zeile 1
# Slicing
arr[1:4]  # Elemente 1 bis 3
arr[::2]  # Jedes zweite Element
arr[::-1]  # Array umkehren
```

### Boolesche Indizierung: `arr[condition]`

Filtern Sie Arrays basierend auf Bedingungen.

```python
# Einfache Bedingung
arr[arr > 5]
# Mehrere Bedingungen
arr[(arr > 2) & (arr < 8)]
arr[(arr < 2) | (arr > 8)]
# Boolesches Array
mask = arr > 3
filtered = arr[mask]
```

### Erweiterte Indizierung: Fancy Indexing

Verwenden Sie Arrays von Indizes, um auf mehrere Elemente zuzugreifen.

```python
# Indizierung mit Array von Indizes
indices = [0, 2, 4]
arr[indices]
# 2D Fancy Indexing
arr2d[[0, 1], [1, 2]]  # Elemente (0,1) und (1,2)
# Kombiniert mit Slicing
arr2d[1:, [0, 2]]
```

### Where-Funktion: `np.where()`

Bedingte Auswahl und Elementersetzung.

```python
# Indizes finden, bei denen die Bedingung wahr ist
indices = np.where(arr > 5)
# Bedingte Ersetzung
result = np.where(arr > 5, arr, 0)  # Werte >5 durch 0 ersetzen
# Mehrere Bedingungen
result = np.where(arr > 5, 'high', 'low')
```

## Array-Manipulation & Umformen

### Umformen: `reshape()` / `resize()` / `flatten()`

Ändern Sie die Array-Dimensionen unter Beibehaltung der Daten.

```python
# Umformen (erzeugt Ansicht, wenn möglich)
arr.reshape(2, 3)
arr.reshape(-1, 1)  # -1 bedeutet Dimension ableiten
# Größe ändern (modifiziert das ursprüngliche Array)
arr.resize((2, 3))
# Zu 1D abflachen
arr.flatten()  # Gibt Kopie zurück
arr.ravel()  # Gibt Ansicht zurück, wenn möglich
```

### Transponieren: `T` / `transpose()`

Tauschen Sie Array-Achsen für Operationen der linearen Algebra.

```python
# Einfaches Transponieren
arr2d.T
# Transponieren mit Achsenangabe
arr.transpose()
np.transpose(arr)
# Für höhere Dimensionen
arr3d.transpose(2, 0, 1)
```

### Hinzufügen/Entfernen von Elementen

Ändern Sie die Array-Größe durch Hinzufügen oder Entfernen von Elementen.

```python
# Elemente anhängen
np.append(arr, [4, 5])
# An spezifischer Position einfügen
np.insert(arr, 1, 99)
# Elemente löschen
np.delete(arr, [1, 3])
# Elemente wiederholen
np.repeat(arr, 3)
np.tile(arr, 2)
```

### Arrays kombinieren: `concatenate()` / `stack()`

Fügen Sie mehrere Arrays zusammen.

```python
# Entlang der vorhandenen Achse verketten
np.concatenate([arr1, arr2])
np.concatenate([arr1, arr2], axis=1)
# Arrays stapeln (erzeugt neue Achse)
np.vstack([arr1, arr2])  # Vertikal
np.hstack([arr1, arr2])  # Horizontal
np.dstack([arr1, arr2])  # Tiefenweise
```

## Mathematische Operationen

### Grundlegende Arithmetik: `+`, `-`, `*`, `/`

Elementweise arithmetische Operationen auf Arrays.

```python
# Elementweise Operationen
arr1 + arr2
arr1 - arr2
arr1 * arr2  # Elementweise Multiplikation
arr1 / arr2
arr1 ** 2  # Quadrieren
arr1 % 3  # Modulo-Operation
```

### Universal Functions (ufuncs)

Wenden Sie mathematische Funktionen elementweise an.

```python
# Trigonometrische Funktionen
np.sin(arr)
np.cos(arr)
np.tan(arr)
# Exponential- und logarithmisch
np.exp(arr)
np.log(arr)
np.log10(arr)
# Quadratwurzel und Potenz
np.sqrt(arr)
np.power(arr, 3)
```

### Aggregationsfunktionen

Berechnen Sie zusammenfassende Statistiken über Array-Dimensionen hinweg.

```python
# Grundlegende Statistiken
np.sum(arr)
np.mean(arr)
np.std(arr)  # Standardabweichung
np.var(arr)  # Varianz
np.min(arr)
np.max(arr)
# Entlang einer spezifischen Achse
np.sum(arr2d, axis=0)  # Summe entlang der Zeilen
np.mean(arr2d, axis=1)  # Mittelwert entlang der Spalten
```

### Vergleichsoperationen

Elementweise Vergleiche, die boolesche Arrays zurückgeben.

```python
# Vergleichsoperatoren
arr > 5
arr == 3
arr != 0
# Array-Vergleiche
np.array_equal(arr1, arr2)
np.allclose(arr1, arr2)  # Innerhalb der Toleranz
# Any/all Operationen
np.any(arr > 5)
np.all(arr > 0)
```

## Lineare Algebra

### Matrixoperationen: `np.dot()` / `@`

Führen Sie Matrixmultiplikationen und Skalarprodukte durch.

```python
# Matrixmultiplikation
np.dot(A, B)
A @ B  # Python 3.5+ Operator
# Elementweise Multiplikation
A * B
# Matrixpotenz
np.linalg.matrix_power(A, 3)
```

### Zerlegungen: `np.linalg`

Matrixzerlegungen für fortgeschrittene Berechnungen.

```python
# Eigenwerte und Eigenvektoren
eigenvals, eigenvecs = np.linalg.eig(A)
# Singulärwertzerlegung
U, s, Vt = np.linalg.svd(A)
# QR-Zerlegung
Q, R = np.linalg.qr(A)
```

### Matrixeigenschaften

Berechnen Sie wichtige Matrixmerkmale.

```python
# Determinante
np.linalg.det(A)
# Matrixinvers
np.linalg.inv(A)
# Pseudoinverse
np.linalg.pinv(A)
# Matrixrang
np.linalg.matrix_rank(A)
# Spur (Summe der Diagonale)
np.trace(A)
```

### Lösen linearer Systeme: `np.linalg.solve()`

Lösen Sie Systeme linearer Gleichungen.

```python
# Löse Ax = b
x = np.linalg.solve(A, b)
# Kleinste-Quadrate-Lösung
x = np.linalg.lstsq(A, b, rcond=None)[0]
```

## Array Ein-/Ausgabe

### NumPy Binär: `np.save()` / `np.load()`

Effizientes Binärformat für NumPy-Arrays.

```python
# Einzelnes Array speichern
np.save('array.npy', arr)
# Array laden
loaded_arr = np.load('array.npy')
# Mehrere Arrays speichern
np.savez('arrays.npz', a=arr1, b=arr2)
# Mehrere Arrays laden
data = np.load('arrays.npz')
arr1_loaded = data['a']
```

### Textdateien: `np.loadtxt()` / `np.savetxt()`

Lesen und schreiben Sie Arrays als Textdateien.

```python
# Aus CSV/Textdatei laden
arr = np.loadtxt('data.csv', delimiter=',')
# Kopfzeile überspringen
arr = np.loadtxt('data.csv', delimiter=',', skiprows=1)
# In Textdatei speichern
np.savetxt('output.csv', arr, delimiter=',', fmt='%.2f')
```

### CSV mit strukturierten Daten: `np.genfromtxt()`

Fortgeschrittenes Lesen von Textdateien mit Behandlung fehlender Daten.

```python
# Fehlende Werte behandeln
arr = np.genfromtxt('data.csv', delimiter=',',
                    missing_values='N/A', filling_values=0)
# Benannte Spalten
data = np.genfromtxt('data.csv', delimiter=',',
                     names=True, dtype=None)
```

### Speicherabbildung: `np.memmap()`

Arbeiten Sie mit Arrays, die zu groß sind, um in den Speicher zu passen.

```python
# Speicherabbild-Array erstellen
mmap_arr = np.memmap('large_array.dat', dtype='float32',
                     mode='w+', shape=(1000000,))
# Wie ein reguläres Array zugreifen, aber auf der Festplatte gespeichert
mmap_arr[0:10] = np.random.random(10)
```

## Performance & Broadcasting

### Broadcasting-Regeln

Verstehen Sie, wie NumPy Operationen auf Arrays unterschiedlicher Form behandelt.

```python
# Broadcasting-Beispiele
arr1 = np.array([[1, 2, 3]])  # Form (1, 3)
arr2 = np.array([[1], [2]])   # Form (2, 1)
result = arr1 + arr2          # Form (2, 3)
# Skalar-Broadcasting
arr + 5  # Addiert 5 zu allen Elementen
arr * 2  # Multipliziert alle Elemente mit 2
```

### Vektorisierte Operationen

Verwenden Sie die integrierten Funktionen von NumPy anstelle von Python-Schleifen.

```python
# Anstelle von Schleifen, vektorisierte Operationen verwenden
# Schlecht: for-Schleife
result = []
for x in arr:
    result.append(x ** 2)
# Gut: vektorisiert
result = arr ** 2
# Benutzerdefinierte vektorisierte Funktion
def custom_func(x):
    return x ** 2 + 2 * x + 1
vec_func = np.vectorize(custom_func)
result = vec_func(arr)
```

### Speicheroptimierung

Techniken für eine effiziente Speichernutzung mit großen Arrays.

```python
# Geeignete Datentypen verwenden
arr_int8 = arr.astype(np.int8)  # 1 Byte pro Element
arr_float32 = arr.astype(np.float32)  # 4 Bytes vs. 8 für float64
# Ansichten vs. Kopien
view = arr[::2]  # Erstellt Ansicht (teilt Speicher)
copy = arr[::2].copy()  # Erstellt Kopie (neuer Speicher)
# Prüfen, ob Array Ansicht oder Kopie ist
view.base is arr  # True für Ansicht
```

### Performance-Tipps

Best Practices für schnellen NumPy-Code.

```python
# In-place-Operationen verwenden, wenn möglich
arr += 5  # Anstelle von arr = arr + 5
np.add(arr, 5, out=arr)  # Explizit in-place
# Array-Erstellung minimieren
# Schlecht: erstellt Zwischen-Arrays
result = ((arr + 1) * 2) ** 2
# Besser: zusammengesetzte Operationen verwenden, wo möglich
```

## Zufallszahlengenerierung

### Grundlegendes Zufallsereignis: `np.random`

Generieren Sie Zufallszahlen aus verschiedenen Verteilungen.

```python
# Zufällige Gleitkommazahlen [0, 1)
np.random.random(5)
# Zufallsganzzahlen
np.random.randint(0, 10, size=5)
# Normalverteilung
np.random.normal(mu=0, sigma=1, size=5)
# Gleichverteilung
np.random.uniform(-1, 1, size=5)
```

### Stichprobenziehung: `choice()` / `shuffle()`

Ziehen Sie Stichproben aus vorhandenen Daten oder permutieren Sie Arrays.

```python
# Zufällige Auswahl aus Array
np.random.choice(arr, size=3)
# Ohne Zurücklegen
np.random.choice(arr, size=3, replace=False)
# Array in-place mischen
np.random.shuffle(arr)
# Zufällige Permutation
np.random.permutation(arr)
```

### Seeds & Generatoren

Steuern Sie die Zufälligkeit für reproduzierbare Ergebnisse.

```python
# Seed für Reproduzierbarkeit setzen
np.random.seed(42)
# Moderner Ansatz: Generator
rng = np.random.default_rng(42)
rng.random(5)
rng.integers(0, 10, size=5)
rng.normal(0, 1, size=5)
```

## Statistische Funktionen

### Beschreibende Statistiken

Grundlegende statistische Kennzahlen für Zentralität und Streuung.

```python
# Zentralität
np.mean(arr)
np.median(arr)
# Streuungsmaße
np.std(arr)  # Standardabweichung
np.var(arr)  # Varianz
np.ptp(arr)  # Peak to peak (max - min)
# Perzentile
np.percentile(arr, [25, 50, 75])
np.quantile(arr, [0.25, 0.5, 0.75])
```

### Korrelation & Kovarianz

Messen Sie Beziehungen zwischen Variablen.

```python
# Korrelationskoeffizient
np.corrcoef(x, y)
# Kovarianz
np.cov(x, y)
# Kreuzkorrelation
np.correlate(x, y, mode='full')
```

### Histogramm & Binning

Analysieren Sie die Datenverteilung und erstellen Sie Bins.

```python
# Histogramm
counts, bins = np.histogram(arr, bins=10)
# 2D-Histogramm
H, xedges, yedges = np.histogram2d(x, y, bins=10)
# Digitalisieren (Bin-Indizes zuweisen)
bin_indices = np.digitize(arr, bins)
```

### Spezielle statistische Funktionen

Fortgeschrittene statistische Berechnungen.

```python
# Gewichtete Statistiken
np.average(arr, weights=weights)
# Eindeutige Werte und Zählungen
unique_vals, counts = np.unique(arr, return_counts=True)
# Bincount (für Integer-Arrays)
np.bincount(int_arr)
```

## NumPy Installation & Einrichtung

### Pip: `pip install numpy`

Standard Python Paket-Installer.

```bash
# NumPy installieren
pip install numpy
# Auf neueste Version aktualisieren
pip install numpy --upgrade
# Spezifische Version installieren
pip install numpy==1.21.0
# Paketinformationen anzeigen
pip show numpy
```

### Conda: `conda install numpy`

Paketmanager für Anaconda/Miniconda-Umgebungen.

```bash
# NumPy in aktueller Umgebung installieren
conda install numpy
# NumPy aktualisieren
conda update numpy
# Aus conda-forge installieren
conda install -c conda-forge numpy
# Umgebung mit NumPy erstellen
conda create -n myenv numpy
```

### Installation prüfen & Importieren

Überprüfen Sie Ihre NumPy-Installation und den Standardimport.

```python
# Standardimport
import numpy as np
# Version prüfen
print(np.__version__)
# Build-Informationen prüfen
np.show_config()
# Druckoptionen einstellen
np.set_printoptions(precision=2, suppress=True)
```

## Erweiterte Funktionen

### Strukturierte Arrays

Arrays mit benannten Feldern für komplexe Datenstrukturen.

```python
# Strukturierte Datenart definieren
dt = np.dtype([('name', 'U10'), ('age', 'i4'), ('weight', 'f4')])
# Strukturiertes Array erstellen
people = np.array([('Alice', 25, 55.0), ('Bob', 30, 70.5)], dtype=dt)
# Felder zugreifen
people['name']
people['age']
```

### Maskierte Arrays: `np.ma`

Behandeln Sie Arrays mit fehlenden oder ungültigen Daten.

```python
# Maskiertes Array erstellen
masked_arr = np.ma.array([1, 2, 3, 4, 5], mask=[0, 0, 1, 0, 0])
# Operationen ignorieren maskierte Werte
np.ma.mean(masked_arr)
# Maskierte Werte auffüllen
filled = masked_arr.filled(0)
```

### Polynome: `np.poly1d`

Arbeiten Sie mit Polynomausdrücken und -operationen.

```python
# Polynom erstellen (Koeffizienten in absteigender Reihenfolge)
p = np.poly1d([1, -2, 1])  # x² - 2x + 1
# Polynom auswerten
p(5)  # Auswerten bei x=5
# Wurzeln finden
np.roots([1, -2, 1])
# Polynomanpassung
coeff = np.polyfit(x, y, degree=2)
```

### Schnelle Fourier-Transformation: `np.fft`

Frequenzbereichsanalyse und Signalverarbeitung.

```python
# 1D FFT
fft_result = np.fft.fft(signal)
# Frequenzen
freqs = np.fft.fftfreq(len(signal))
# Inverse FFT
reconstructed = np.fft.ifft(fft_result)
# 2D FFT für Bilder
fft2d = np.fft.fft2(image)
```

## Relevante Links

- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/pandas">Pandas Spickzettel</router-link>
- <router-link to="/matplotlib">Matplotlib Spickzettel</router-link>
- <router-link to="/sklearn">scikit-learn Spickzettel</router-link>
- <router-link to="/datascience">Data Science Spickzettel</router-link>

---
title: 'Matplotlib Spickzettel | LabEx'
description: 'Lernen Sie Matplotlib-Datenvisualisierung mit diesem umfassenden Spickzettel. Schnelle Referenz für Diagramme, Grafiken, Unterplots, Anpassung und Python-Datenvisualisierung.'
pdfUrl: '/cheatsheets/pdf/matplotlib-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Matplotlib Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/matplotlib">Lernen Sie Matplotlib mit praktischen Übungen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie die Matplotlib-Datenvisualisierung durch praktische Übungen und reale Szenarien. LabEx bietet umfassende Matplotlib-Kurse, die wesentliche Plot-Funktionen, Anpassungstechniken, Subplot-Layouts und erweiterte Visualisierungstypen abdecken. Meistern Sie die Erstellung effektiver Datenvisualisierungen für Python-Data-Science-Workflows.
</base-disclaimer-content>
</base-disclaimer>

## Grundlegendes Plotten & Diagrammtypen

### Liniendiagramm: `plt.plot()`

Erstellt Liniendiagramme zur Visualisierung kontinuierlicher Daten.

```python
import matplotlib.pyplot as plt
import numpy as np

# Einfaches Liniendiagramm
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
plt.plot(x, y)
plt.show()

# Mehrere Linien
plt.plot(x, y, label='Linie 1')
plt.plot(x, [1, 3, 5, 7, 9], label='Linie 2')
plt.legend()

# Linienstile und Farben
plt.plot(x, y, 'r--', linewidth=2, marker='o')
```

<BaseQuiz id="matplotlib-plot-1" correct="C">
  <template #question>
    Was bewirkt <code>plt.show()</code> in Matplotlib?
  </template>
  
  <BaseQuizOption value="A">Speichert das Diagramm in einer Datei</BaseQuizOption>
  <BaseQuizOption value="B">Schließt das Diagrammfenster</BaseQuizOption>
  <BaseQuizOption value="C" correct>Zeigt das Diagramm in einem Fenster an</BaseQuizOption>
  <BaseQuizOption value="D">Löscht das Diagramm</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>plt.show()</code> zeigt das Diagramm in einem interaktiven Fenster an. Diese Funktion muss aufgerufen werden, um die Visualisierung zu sehen. Ohne sie wird das Diagramm nicht angezeigt.
  </BaseQuizAnswer>
</BaseQuiz>

### Streudiagramm: `plt.scatter()`

Zeigt Beziehungen zwischen zwei Variablen an.

```python
# Einfaches Streudiagramm
plt.scatter(x, y)

# Mit unterschiedlichen Farben und Größen
colors = [1, 2, 3, 4, 5]
sizes = [20, 50, 100, 200, 500]
plt.scatter(x, y, c=colors, s=sizes, alpha=0.6)
plt.colorbar()  # Farbleiste hinzufügen
```

<BaseQuiz id="matplotlib-scatter-1" correct="D">
  <template #question>
    Was steuert der Parameter <code>alpha</code> in Matplotlib-Diagrammen?
  </template>
  
  <BaseQuizOption value="A">Die Farbe des Diagramms</BaseQuizOption>
  <BaseQuizOption value="B">Die Größe des Diagramms</BaseQuizOption>
  <BaseQuizOption value="C">Die Position des Diagramms</BaseQuizOption>
  <BaseQuizOption value="D" correct>Die Transparenz/Opazität der Diagrammelemente</BaseQuizOption>
  
  <BaseQuizAnswer>
    Der Parameter <code>alpha</code> steuert die Transparenz mit Werten von 0 (vollständig transparent) bis 1 (vollständig opak). Er ist nützlich für die Erstellung überlappender Visualisierungen, bei denen man durch Elemente hindurchsehen möchte.
  </BaseQuizAnswer>
</BaseQuiz>

### Balkendiagramm: `plt.bar()` / `plt.barh()`

Erstellt vertikale oder horizontale Balkendiagramme.

```python
# Vertikale Balken
categories = ['A', 'B', 'C', 'D']
values = [20, 35, 30, 25]
plt.bar(categories, values)

# Horizontale Balken
plt.barh(categories, values)

# Gruppierte Balken
x = np.arange(len(categories))
plt.bar(x - 0.2, values, 0.4, label='Gruppe 1')
plt.bar(x + 0.2, [15, 25, 35, 20], 0.4, label='Gruppe 2')
```

### Histogramm: `plt.hist()`

Zeigt die Verteilung kontinuierlicher Daten.

```python
# Einfaches Histogramm
data = np.random.randn(1000)
plt.hist(data, bins=30)

# Angepasstes Histogramm
plt.hist(data, bins=50, alpha=0.7, color='skyblue', edgecolor='black')

# Mehrere Histogramme
plt.hist([data1, data2], bins=30, alpha=0.7, label=['Daten 1', 'Daten 2'])
```

### Tortendiagramm: `plt.pie()`

Zeigt proportionale Daten als kreisförmiges Diagramm an.

```python
# Einfaches Tortendiagramm
sizes = [25, 35, 20, 20]
labels = ['A', 'B', 'C', 'D']
plt.pie(sizes, labels=labels)

# Explodiertes Tortendiagramm mit Prozentangaben
explode = (0, 0.1, 0, 0)  # 2. Segment herausziehen
plt.pie(sizes, labels=labels, autopct='%1.1f%%',
        explode=explode, shadow=True, startangle=90)
```

### Boxplot: `plt.boxplot()`

Visualisiert die Datenverteilung und Ausreißer.

```python
# Einzelner Boxplot
data = [np.random.randn(100) for _ in range(4)]
plt.boxplot(data)

# Angepasster Boxplot
plt.boxplot(data, labels=['Gruppe 1', 'Gruppe 2', 'Gruppe 3', 'Gruppe 4'],
           patch_artist=True, notch=True)
```

## Diagrammanpassung & Stil

### Beschriftungen & Titel: `plt.xlabel()` / `plt.title()`

Fügt beschreibenden Text zur besseren Übersicht und Kontext hinzu.

```python
# Einfache Beschriftungen und Titel
plt.plot(x, y)
plt.xlabel('X-Achsen-Beschriftung')
plt.ylabel('Y-Achsen-Beschriftung')
plt.title('Diagrammtitel')

# Formatierte Titel mit Schrifteigenschaften
plt.title('Mein Diagramm', fontsize=16, fontweight='bold')
plt.xlabel('X-Werte', fontsize=12)

# Gitter für bessere Lesbarkeit
plt.grid(True, alpha=0.3)
```

### Farben & Stile: `color` / `linestyle` / `marker`

Passen Sie das visuelle Erscheinungsbild von Diagrammelementen an.

```python
# Farboptionen
plt.plot(x, y, color='red')  # Benannte Farben
plt.plot(x, y, color='#FF5733')  # Hex-Farben
plt.plot(x, y, color=(0.1, 0.2, 0.5))  # RGB-Tupel

# Linienstile
plt.plot(x, y, linestyle='--')  # Gestrichelt
plt.plot(x, y, linestyle=':')   # Gepunktet
plt.plot(x, y, linestyle='-.')  # Strich-Punkt

# Marker
plt.plot(x, y, marker='o', markersize=8, markerfacecolor='red')
```

### Legenden & Anmerkungen: `plt.legend()` / `plt.annotate()`

Fügen Sie Legenden und Anmerkungen hinzu, um Diagrammelemente zu erklären.

```python
# Einfache Legende
plt.plot(x, y1, label='Datensatz 1')
plt.plot(x, y2, label='Datensatz 2')
plt.legend()

# Legendenposition anpassen
plt.legend(loc='upper right', fontsize=10, frameon=False)

# Anmerkungen
plt.annotate('Wichtiger Punkt', xy=(2, 4), xytext=(3, 6),
            arrowprops=dict(arrowstyle='->', color='red'))
```

<BaseQuiz id="matplotlib-legend-1" correct="B">
  <template #question>
    Was ist für <code>plt.legend()</code> erforderlich, um Beschriftungen anzuzeigen?
  </template>
  
  <BaseQuizOption value="A">Nichts, es funktioniert automatisch</BaseQuizOption>
  <BaseQuizOption value="B" correct>Jedes Diagramm muss einen <code>label</code>-Parameter gesetzt haben</BaseQuizOption>
  <BaseQuizOption value="C">Die Legende muss vor dem Plotten erstellt werden</BaseQuizOption>
  <BaseQuizOption value="D">Beschriftungen müssen manuell in der Legende festgelegt werden</BaseQuizOption>
  
  <BaseQuizAnswer>
    Um eine Legende anzuzeigen, müssen Sie den Parameter <code>label</code> beim Erstellen jedes Diagramms festlegen (z. B. <code>plt.plot(x, y, label='Datensatz 1')</code>). Dann zeigt ein Aufruf von <code>plt.legend()</code> alle Beschriftungen an.
  </BaseQuizAnswer>
</BaseQuiz>

## Achsen- & Layout-Steuerung

### Achsenbegrenzungen: `plt.xlim()` / `plt.ylim()`

Steuern Sie den Wertebereich, der auf jeder Achse angezeigt wird.

```python
# Achsenbegrenzungen festlegen
plt.xlim(0, 10)
plt.ylim(-5, 15)

# Automatische Anpassung der Begrenzungen mit Rand
plt.margins(x=0.1, y=0.1)

# Achse umkehren
plt.gca().invert_yaxis()  # Y-Achse umkehren
```

### Ticks & Beschriftungen: `plt.xticks()` / `plt.yticks()`

Passen Sie Achsenmarkierungen und deren Beschriftungen an.

```python
# Benutzerdefinierte Tick-Positionen
plt.xticks([0, 2, 4, 6, 8, 10])
plt.yticks(np.arange(0, 101, 10))

# Benutzerdefinierte Tick-Beschriftungen
plt.xticks([0, 1, 2, 3], ['Jan', 'Feb', 'Mär', 'Apr'])

# Tick-Beschriftungen drehen
plt.xticks(rotation=45)

# Ticks entfernen
plt.xticks([])
plt.yticks([])
```

### Seitenverhältnis: `plt.axis()`

Steuert das Seitenverhältnis und das Erscheinungsbild der Achsen.

```python
# Gleiches Seitenverhältnis
plt.axis('equal')
# Quadratisches Diagramm
plt.axis('square')
# Achse ausschalten
plt.axis('off')
# Benutzerdefiniertes Seitenverhältnis
plt.gca().set_aspect('equal', adjustable='box')
```

### Figurengröße: `plt.figure()`

Steuert die Gesamtgröße und Auflösung Ihrer Diagramme.

```python
# Figurengröße festlegen (Breite, Höhe in Zoll)
plt.figure(figsize=(10, 6))

# Hohe DPI für bessere Qualität
plt.figure(figsize=(8, 6), dpi=300)

# Mehrere Figuren
fig1 = plt.figure(1)
plt.plot(x, y1)
fig2 = plt.figure(2)
plt.plot(x, y2)
```

### Layout anpassen: `plt.tight_layout()`

Passt automatisch den Abstand der Subplots für ein besseres Erscheinungsbild an.

```python
# Überlappende Elemente verhindern
plt.tight_layout()

# Manuelle Abstandsanpassung
plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)

# Abstand um Subplots
plt.tight_layout(pad=3.0)
```

### Style Sheets: `plt.style.use()`

Wendet vordefinierte Stile für ein konsistentes Diagrammerscheinungsbild an.

```python
# Verfügbare Stile
print(plt.style.available)

# Eingebaute Stile verwenden
plt.style.use('seaborn-v0_8')
plt.style.use('ggplot')
plt.style.use('bmh')

# Auf Standard zurücksetzen
plt.style.use('default')
```

## Subplots & Mehrere Diagramme

### Einfache Subplots: `plt.subplot()` / `plt.subplots()`

Erstellt mehrere Diagramme in einer einzigen Figure.

```python
# 2x2 Subplot-Raster erstellen
fig, axes = plt.subplots(2, 2, figsize=(10, 8))

# In jedem Subplot zeichnen
axes[0, 0].plot(x, y)
axes[0, 1].scatter(x, y)
axes[1, 0].bar(x, y)
axes[1, 1].hist(y, bins=10)

# Alternative Syntax
plt.subplot(2, 2, 1)  # 2 Zeilen, 2 Spalten, 1. Subplot
plt.plot(x, y)
plt.subplot(2, 2, 2)  # 2. Subplot
plt.scatter(x, y)
```

### Gemeinsame Achsen: `sharex` / `sharey`

Verknüpft Achsen über Subplots hinweg für eine konsistente Skalierung.

```python
# X-Achse über Subplots teilen
fig, axes = plt.subplots(2, 1, sharex=True)
axes[0].plot(x, y1)
axes[1].plot(x, y2)

# Beide Achsen teilen
fig, axes = plt.subplots(2, 2, sharex=True, sharey=True)
```

### GridSpec: Erweiterte Layouts

Erstellt komplexe Subplot-Anordnungen mit unterschiedlichen Größen.

```python
import matplotlib.gridspec as gridspec

# Benutzerdefiniertes Raster erstellen
gs = gridspec.GridSpec(3, 3)
fig = plt.figure(figsize=(10, 8))

# Subplots unterschiedlicher Größe
ax1 = fig.add_subplot(gs[0, :])  # Obere Zeile, alle Spalten
ax2 = fig.add_subplot(gs[1, :-1])  # Mittlere Zeile, erste 2 Spalten
ax3 = fig.add_subplot(gs[1:, -1])  # Letzte Spalte, untere 2 Zeilen
ax4 = fig.add_subplot(gs[-1, 0])   # Unten links
ax5 = fig.add_subplot(gs[-1, 1])   # Unten Mitte
```

### Subplot-Abstand: `hspace` / `wspace`

Steuert den Abstand zwischen Subplots.

```python
# Abstand beim Erstellen von Subplots anpassen
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
plt.subplots_adjust(hspace=0.4, wspace=0.3)

# Oder tight_layout für automatische Anpassung verwenden
plt.tight_layout()
```

## Erweiterte Visualisierungstypen

### Heatmaps: `plt.imshow()` / `plt.pcolormesh()`

Visualisiert 2D-Daten als farbkodierte Matrizen.

```python
# Einfache Heatmap
data = np.random.randn(10, 10)
plt.imshow(data, cmap='viridis')
plt.colorbar()

# Pcolormesh für unregelmäßige Gitter
x = np.linspace(0, 10, 11)
y = np.linspace(0, 5, 6)
X, Y = np.meshgrid(x, y)
Z = np.sin(X) * np.cos(Y)
plt.pcolormesh(X, Y, Z, shading='auto')
plt.colorbar()
```

### Konturdiagramme: `plt.contour()` / `plt.contourf()`

Zeigt Höhenlinien und gefüllte Konturbereiche an.

```python
# Konturlinien
x = np.linspace(-3, 3, 100)
y = np.linspace(-3, 3, 100)
X, Y = np.meshgrid(x, y)
Z = X**2 + Y**2
plt.contour(X, Y, Z, levels=10)
plt.clabel(plt.contour(X, Y, Z), inline=True, fontsize=8)

# Gefüllte Konturen
plt.contourf(X, Y, Z, levels=20, cmap='RdBu')
plt.colorbar()
```

### 3D-Diagramme: `mplot3d`

Erstellt dreidimensionale Visualisierungen.

```python
from mpl_toolkits.mplot3d import Axes3D

fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# 3D-Streudiagramm
ax.scatter(x, y, z)

# 3D-Oberflächendiagramm
ax.plot_surface(X, Y, Z, cmap='viridis')

# 3D-Liniendiagramm
ax.plot(x, y, z)
```

### Fehlerbalken: `plt.errorbar()`

Zeigt Daten mit Unsicherheitsmessungen an.

```python
# Einfache Fehlerbalken
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
yerr = [0.5, 0.8, 0.3, 0.7, 0.4]
plt.errorbar(x, y, yerr=yerr, fmt='o-', capsize=5)

# Asymmetrische Fehlerbalken
yerr_lower = [0.4, 0.6, 0.2, 0.5, 0.3]
yerr_upper = [0.6, 1.0, 0.4, 0.9, 0.5]
plt.errorbar(x, y, yerr=[yerr_lower, yerr_upper], fmt='s-')
```

### Zwischen zwei füllen: `plt.fill_between()`

Schattiert Bereiche zwischen Kurven oder um Linien herum.

```python
# Füllen zwischen zwei Kurven
y1 = [2, 4, 6, 8, 10]
y2 = [1, 3, 5, 7, 9]
plt.fill_between(x, y1, y2, alpha=0.3, color='blue')

# Füllen um eine Linie mit Fehler
plt.plot(x, y, 'k-', linewidth=2)
plt.fill_between(x, y-yerr, y+yerr, alpha=0.2, color='gray')
```

### Violin-Diagramme: Alternative zu Boxplots

Zeigt die Verteilungsform zusammen mit Quartilen an.

```python
# Verwendung von pyplot
parts = plt.violinplot([data1, data2, data3])

# Farben anpassen
for pc in parts['bodies']:
    pc.set_facecolor('lightblue')
    pc.set_alpha(0.7)
```

## Interaktive & Animationsfunktionen

### Interaktives Backend: `%matplotlib widget`

Aktiviert interaktive Diagramme in Jupyter Notebooks.

```python
# In Jupyter Notebook
%matplotlib widget

# Oder für grundlegende Interaktivität
%matplotlib notebook
```

### Ereignisbehandlung: Maus & Tastatur

Reagiert auf Benutzerinteraktionen mit Diagrammen.

```python
# Interaktives Zoomen, Verschieben und Schweben
def onclick(event):
    if event.inaxes:
        print(f'Geklickt bei x={event.xdata}, y={event.ydata}')

fig, ax = plt.subplots()
ax.plot(x, y)
fig.canvas.mpl_connect('button_press_event', onclick)
plt.show()
```

### Animationen: `matplotlib.animation`

Erstellt animierte Diagramme für Zeitreihen oder sich ändernde Daten.

```python
from matplotlib.animation import FuncAnimation

fig, ax = plt.subplots()
line, = ax.plot([], [], 'r-')
ax.set_xlim(0, 10)
ax.set_ylim(-2, 2)

def animate(frame):
    x = np.linspace(0, 10, 100)
    y = np.sin(x + frame * 0.1)
    line.set_data(x, y)
    return line,

ani = FuncAnimation(fig, animate, frames=200, blit=True, interval=50)
plt.show()

# Animation speichern
# ani.save('animation.gif', writer='pillow')
```

## Speichern & Exportieren von Diagrammen

### Figur speichern: `plt.savefig()`

Exportiert Diagramme in Bilddateien mit verschiedenen Optionen.

```python
# Einfaches Speichern
plt.savefig('mein_diagramm.png')

# Hochauflösendes Speichern
plt.savefig('diagramm.png', dpi=300, bbox_inches='tight')

# Verschiedene Formate
plt.savefig('diagramm.pdf')  # PDF
plt.savefig('diagramm.svg')  # SVG (Vektor)
plt.savefig('diagramm.eps')  # EPS

# Transparenter Hintergrund
plt.savefig('diagramm.png', transparent=True)
```

### Figurengröße: DPI & Größe

Steuert die Auflösung und Abmessungen gespeicherter Diagramme.

```python
# Hohe DPI für Publikationen
plt.savefig('diagramm.png', dpi=600)

# Benutzerdefinierte Größe (Breite, Höhe in Zoll)
plt.figure(figsize=(12, 8))
plt.savefig('diagramm.png', figsize=(12, 8))

# Leerraum abschneiden
plt.savefig('diagramm.png', bbox_inches='tight', pad_inches=0.1)
```

### Stapel-Export & Speicherverwaltung

Behandelt mehrere Diagramme und verwaltet den Speicher effizient.

```python
# Figuren schließen, um Speicher freizugeben
plt.close()  # Aktuelle Figur schließen
plt.close('all')  # Alle Figuren schließen

# Kontextmanager für automatische Bereinigung
with plt.figure() as fig:
    plt.plot(x, y)
    plt.savefig('diagramm.png')

# Stapelweises Speichern mehrerer Diagramme
for i, data in enumerate(datasets):
    plt.figure()
    plt.plot(data)
    plt.savefig(f'diagramm_{i}.png')
    plt.close()
```

## Konfiguration & Best Practices

### RC-Parameter: `plt.rcParams`

Legt Standardstile und Verhalten für alle Diagramme fest.

```python
# Häufige rc-Parameter
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 12
plt.rcParams['lines.linewidth'] = 2
plt.rcParams['axes.grid'] = True

# Einstellungen speichern und wiederherstellen
original_params = plt.rcParams.copy()
# ... Änderungen vornehmen ...
plt.rcParams.update(original_params)  # Wiederherstellen
```

### Farbverwaltung: Colormaps & Paletten

Effektiver Umgang mit Farben und Colormaps.

```python
# Verfügbare Colormaps auflisten
print(plt.colormaps())

# Colormap für mehrere Linien verwenden
colors = plt.cm.viridis(np.linspace(0, 1, len(datasets)))
for i, (data, color) in enumerate(zip(datasets, colors)):
    plt.plot(data, color=color, label=f'Datensatz {i+1}')

# Benutzerdefinierte Colormap
from matplotlib.colors import LinearSegmentedColormap
custom_cmap = LinearSegmentedColormap.from_list('custom', ['red', 'yellow', 'blue'])
```

### Leistungsoptimierung

Verbessert die Plot-Leistung für große Datensätze.

```python
# Blitting für Animationen verwenden
ani = FuncAnimation(fig, animate, blit=True)

# Komplexe Diagramme rasterisieren
plt.plot(x, y, rasterized=True)

# Datenpunkte für große Datensätze reduzieren
# Daten vor dem Plotten herunterabtasten
indices = np.arange(0, len(large_data), step=10)
plt.plot(large_data[indices])
```

### Speichernutzung: Effizientes Plotten

Verwaltet den Speicher beim Erstellen vieler Diagramme oder großer Visualisierungen.

```python
# Achsen löschen anstatt neue Figuren zu erstellen
fig, ax = plt.subplots()
for data in datasets:
    ax.clear()  # Vorheriges Diagramm löschen
    ax.plot(data)
    plt.savefig(f'diagramm_{i}.png')

# Generatoren für große Datensätze verwenden
def data_generator():
    for i in range(1000):
        yield np.random.randn(100)

for i, data in enumerate(data_generator()):
    if i > 10:  # Anzahl der Diagramme begrenzen
        break
```

## Integration mit Datenbibliotheken

### Pandas-Integration: Direktes Plotten

Verwendet Matplotlib über Pandas DataFrame-Methoden.

```python
import pandas as pd

# DataFrame-Plotten (verwendet Matplotlib-Backend)
df.plot(kind='line', x='date', y='value')
df.plot.scatter(x='x_col', y='y_col')
df.plot.hist(bins=30)
df.plot.box()

# Zugriff auf zugrunde liegende Matplotlib-Objekte
ax = df.plot(kind='line')
ax.set_title('Benutzerdefinierter Titel')
plt.show()
```

### NumPy-Integration: Array-Visualisierung

Effizientes Plotten von NumPy-Arrays und mathematischen Funktionen.

```python
# 2D-Array-Visualisierung
arr = np.random.rand(10, 10)
plt.imshow(arr, cmap='hot', interpolation='nearest')

# Mathematische Funktionen
x = np.linspace(0, 4*np.pi, 1000)
y = np.sin(x) * np.exp(-x/10)
plt.plot(x, y)

# Statistische Verteilungen
data = np.random.normal(0, 1, 10000)
plt.hist(data, bins=50, density=True, alpha=0.7)
```

### Seaborn-Integration: Verbesserte Stile

Kombiniert Matplotlib mit Seaborn für bessere Standard-Ästhetik.

```python
import seaborn as sns

# Seaborn-Styling mit Matplotlib verwenden
sns.set_style('whitegrid')
plt.plot(x, y)
plt.show()

# Seaborn und Matplotlib mischen
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
sns.scatterplot(data=df, x='x', y='y', ax=axes[0,0])
plt.plot(x, y, ax=axes[0,1])  # Reines Matplotlib
```

### Jupyter-Integration: Inline-Plotten

Optimiert Matplotlib für Jupyter Notebook-Umgebungen.

```python
# Magic Commands für Jupyter
%matplotlib inline  # Statische Diagramme
%matplotlib widget  # Interaktive Diagramme

# Hochauflösende Anzeigen
%config InlineBackend.figure_format = 'retina'

# Automatische Figurengröße
%matplotlib inline
plt.rcParams['figure.dpi'] = 100
```

## Installation & Umgebungseinrichtung

### Pip: `pip install matplotlib`

Standard Python Paket-Installer für Matplotlib.

```bash
# Matplotlib installieren
pip install matplotlib

# Auf die neueste Version aktualisieren
pip install matplotlib --upgrade

# Mit zusätzlichen Backends installieren
pip install matplotlib[qt5]

# Paketinformationen anzeigen
pip show matplotlib
```

### Conda: `conda install matplotlib`

Paketmanager für Anaconda/Miniconda-Umgebungen.

```bash
# In der aktuellen Umgebung installieren
conda install matplotlib

# Matplotlib aktualisieren
conda update matplotlib

# Umgebung mit Matplotlib erstellen
conda create -n dataviz matplotlib numpy pandas

# Matplotlib-Informationen auflisten
conda list matplotlib
```

### Backend-Konfiguration

Einrichtung von Anzeigebackends für verschiedene Umgebungen.

```python
# Verfügbare Backends prüfen
import matplotlib
print(matplotlib.get_backend())

# Backend programmatisch festlegen
matplotlib.use('TkAgg')  # Für Tkinter
matplotlib.use('Qt5Agg')  # Für PyQt5

# Für Headless-Server
matplotlib.use('Agg')

# Nach dem Festlegen des Backends importieren
import matplotlib.pyplot as plt
```

## Relevante Links

- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/numpy">NumPy Spickzettel</router-link>
- <router-link to="/pandas">Pandas Spickzettel</router-link>
- <router-link to="/sklearn">scikit-learn Spickzettel</router-link>
- <router-link to="/datascience">Data Science Spickzettel</router-link>

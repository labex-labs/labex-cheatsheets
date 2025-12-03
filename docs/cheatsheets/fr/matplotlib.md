---
title: 'Fiche Mémo Matplotlib | LabEx'
description: 'Maîtrisez la visualisation de données Matplotlib avec cette fiche mémo complète. Référence rapide pour le traçage, les graphiques, les sous-graphiques, la personnalisation et la visualisation de données Python.'
pdfUrl: '/cheatsheets/pdf/matplotlib-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Matplotlib
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/matplotlib">Apprenez Matplotlib avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la visualisation de données Matplotlib grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours Matplotlib complets couvrant les fonctions de traçage essentielles, les techniques de personnalisation, les mises en page de sous-graphiques et les types de visualisation avancés. Maîtrisez la création de visualisations de données efficaces pour les flux de travail de science des données Python.
</base-disclaimer-content>
</base-disclaimer>

## Tracé de Base et Types de Graphiques

### Graphique Linéaire : `plt.plot()`

Crée des graphiques linéaires pour la visualisation de données continues.

```python
import matplotlib.pyplot as plt
import numpy as np

# Graphique linéaire de base
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
plt.plot(x, y)
plt.show()

# Lignes multiples
plt.plot(x, y, label='Ligne 1')
plt.plot(x, [1, 3, 5, 7, 9], label='Ligne 2')
plt.legend()

# Styles et couleurs de ligne
plt.plot(x, y, 'r--', linewidth=2, marker='o')
```

<BaseQuiz id="matplotlib-plot-1" correct="C">
  <template #question>
    Que fait `plt.show()` dans Matplotlib ?
  </template>
  
  <BaseQuizOption value="A">Sauvegarde le graphique dans un fichier</BaseQuizOption>
  <BaseQuizOption value="B">Ferme la fenêtre du graphique</BaseQuizOption>
  <BaseQuizOption value="C" correct>Affiche le graphique dans une fenêtre</BaseQuizOption>
  <BaseQuizOption value="D">Efface le graphique</BaseQuizOption>
  
  <BaseQuizAnswer>
    `plt.show()` affiche le graphique dans une fenêtre interactive. Il est nécessaire d'appeler cette fonction pour voir la visualisation. Sans elle, le graphique ne sera pas affiché.
  </BaseQuizAnswer>
</BaseQuiz>

### Nuage de Points : `plt.scatter()`

Affiche les relations entre deux variables.

```python
# Nuage de points de base
plt.scatter(x, y)

# Avec différentes couleurs et tailles
colors = [1, 2, 3, 4, 5]
sizes = [20, 50, 100, 200, 500]
plt.scatter(x, y, c=colors, s=sizes, alpha=0.6)
plt.colorbar()  # Ajoute une barre de couleur
```

<BaseQuiz id="matplotlib-scatter-1" correct="D">
  <template #question>
    Que contrôle le paramètre `alpha` dans les graphiques matplotlib ?
  </template>
  
  <BaseQuizOption value="A">La couleur du graphique</BaseQuizOption>
  <BaseQuizOption value="B">La taille du graphique</BaseQuizOption>
  <BaseQuizOption value="C">La position du graphique</BaseQuizOption>
  <BaseQuizOption value="D" correct>La transparence/opacité des éléments du graphique</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le paramètre `alpha` contrôle la transparence, avec des valeurs allant de 0 (complètement transparent) à 1 (complètement opaque). Il est utile pour créer des visualisations superposées où l'on souhaite voir à travers les éléments.
  </BaseQuizAnswer>
</BaseQuiz>

### Diagramme à Barres : `plt.bar()` / `plt.barh()`

Crée des diagrammes à barres verticales ou horizontales.

```python
# Barres verticales
categories = ['A', 'B', 'C', 'D']
values = [20, 35, 30, 25]
plt.bar(categories, values)

# Barres horizontales
plt.barh(categories, values)

# Barres groupées
x = np.arange(len(categories))
plt.bar(x - 0.2, values, 0.4, label='Groupe 1')
plt.bar(x + 0.2, [15, 25, 35, 20], 0.4, label='Groupe 2')
```

### Histogramme : `plt.hist()`

Montre la distribution des données continues.

```python
# Histogramme de base
data = np.random.randn(1000)
plt.hist(data, bins=30)

# Histogramme personnalisé
plt.hist(data, bins=50, alpha=0.7, color='skyblue', edgecolor='black')

# Histogrammes multiples
plt.hist([data1, data2], bins=30, alpha=0.7, label=['Données 1', 'Données 2'])
```

### Diagramme Circulaire : `plt.pie()`

Affiche les données proportionnelles sous forme de graphique circulaire.

```python
# Diagramme circulaire de base
sizes = [25, 35, 20, 20]
labels = ['A', 'B', 'C', 'D']
plt.pie(sizes, labels=labels)

# Diagramme circulaire explosé avec pourcentages
explode = (0, 0.1, 0, 0)  # Explose la 2ème tranche
plt.pie(sizes, labels=labels, autopct='%1.1f%%',
        explode=explode, shadow=True, startangle=90)
```

### Diagramme en Boîte : `plt.boxplot()`

Visualise la distribution des données et les valeurs aberrantes.

```python
# Diagramme en boîte unique
data = [np.random.randn(100) for _ in range(4)]
plt.boxplot(data)

# Diagramme en boîte personnalisé
plt.boxplot(data, labels=['Groupe 1', 'Groupe 2', 'Groupe 3', 'Groupe 4'],
           patch_artist=True, notch=True)
```

## Personnalisation et Style du Graphique

### Étiquettes et Titres : `plt.xlabel()` / `plt.title()`

Ajoute du texte descriptif à vos graphiques pour plus de clarté et de contexte.

```python
# Étiquettes et titre de base
plt.plot(x, y)
plt.xlabel('Étiquette de l\'axe X')
plt.ylabel('Étiquette de l\'axe Y')
plt.title('Titre du Graphique')

# Titres formatés avec propriétés de police
plt.title('Mon Graphique', fontsize=16, fontweight='bold')
plt.xlabel('Valeurs X', fontsize=12)

# Grille pour une meilleure lisibilité
plt.grid(True, alpha=0.3)
```

### Couleurs et Styles : `color` / `linestyle` / `marker`

Personnalise l'apparence visuelle des éléments du graphique.

```python
# Options de couleur
plt.plot(x, y, color='red')  # Couleurs nommées
plt.plot(x, y, color='#FF5733')  # Couleurs Hexadécimales
plt.plot(x, y, color=(0.1, 0.2, 0.5))  # Tuple RVB

# Styles de ligne
plt.plot(x, y, linestyle='--')  # Tirets
plt.plot(x, y, linestyle=':')   # Points
plt.plot(x, y, linestyle='-.')  # Tirets-points

# Marqueurs
plt.plot(x, y, marker='o', markersize=8, markerfacecolor='red')
```

### Légendes et Annotations : `plt.legend()` / `plt.annotate()`

Ajoute des légendes et des annotations pour expliquer les éléments du graphique.

```python
# Légende de base
plt.plot(x, y1, label='Ensemble de données 1')
plt.plot(x, y2, label='Ensemble de données 2')
plt.legend()

# Position de la légende personnalisée
plt.legend(loc='upper right', fontsize=10, frameon=False)

# Annotations
plt.annotate('Point Important', xy=(2, 4), xytext=(3, 6),
            arrowprops=dict(arrowstyle='->', color='red'))
```

<BaseQuiz id="matplotlib-legend-1" correct="B">
  <template #question>
    Qu'est-ce qui est requis pour que `plt.legend()` affiche des étiquettes ?
  </template>
  
  <BaseQuizOption value="A">Rien, cela fonctionne automatiquement</BaseQuizOption>
  <BaseQuizOption value="B" correct>Chaque tracé doit avoir un paramètre `label` défini</BaseQuizOption>
  <BaseQuizOption value="C">La légende doit être créée avant le traçage</BaseQuizOption>
  <BaseQuizOption value="D">Les étiquettes doivent être définies manuellement dans la légende</BaseQuizOption>
  
  <BaseQuizAnswer>
    Pour afficher une légende, vous devez définir le paramètre `label` lors de la création de chaque tracé (par exemple, `plt.plot(x, y, label='Ensemble de données 1')`). Ensuite, appeler `plt.legend()` affichera toutes les étiquettes.
  </BaseQuizAnswer>
</BaseQuiz>

## Contrôle des Axes et de la Mise en Page

### Limites des Axes : `plt.xlim()` / `plt.ylim()`

Contrôle la plage de valeurs affichées sur chaque axe.

```python
# Définir les limites des axes
plt.xlim(0, 10)
plt.ylim(-5, 15)

# Ajustement automatique des limites avec marge
plt.margins(x=0.1, y=0.1)

# Inverser l'axe
plt.gca().invert_yaxis()  # Inverse l'axe y
```

### Graduations et Étiquettes : `plt.xticks()` / `plt.yticks()`

Personnalise les marques de graduation des axes et leurs étiquettes.

```python
# Positions de graduation personnalisées
plt.xticks([0, 2, 4, 6, 8, 10])
plt.yticks(np.arange(0, 101, 10))

# Étiquettes de graduation personnalisées
plt.xticks([0, 1, 2, 3], ['Jan', 'Fév', 'Mar', 'Avr'])

# Rotation des étiquettes de graduation
plt.xticks(rotation=45)

# Suppression des graduations
plt.xticks([])
plt.yticks([])
```

### Rapport d'Aspect : `plt.axis()`

Contrôle le rapport d'aspect et l'apparence des axes.

```python
# Rapport d'aspect égal
plt.axis('equal')
# Graphique carré
plt.axis('square')
# Désactiver l'axe
plt.axis('off')
# Rapport d'aspect personnalisé
plt.gca().set_aspect('equal', adjustable='box')
```

### Taille de la Figure : `plt.figure()`

Contrôle la taille et la résolution globales de vos graphiques.

```python
# Définir la taille de la figure (largeur, hauteur en pouces)
plt.figure(figsize=(10, 6))

# DPI élevé pour une meilleure qualité
plt.figure(figsize=(8, 6), dpi=300)

# Figures multiples
fig1 = plt.figure(1)
plt.plot(x, y1)
fig2 = plt.figure(2)
plt.plot(x, y2)
```

### Mise en Page Ajustée : `plt.tight_layout()`

Ajuste automatiquement l'espacement des sous-graphiques pour une meilleure apparence.

```python
# Empêche les éléments qui se chevauchent
plt.tight_layout()

# Ajustement manuel de l'espacement
plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)

# Marge autour des sous-graphiques
plt.tight_layout(pad=3.0)
```

### Feuilles de Style : `plt.style.use()`

Applique des styles prédéfinis pour une apparence de graphique cohérente.

```python
# Styles disponibles
print(plt.style.available)

# Utiliser des styles intégrés
plt.style.use('seaborn-v0_8')
plt.style.use('ggplot')
plt.style.use('bmh')

# Réinitialiser à la valeur par défaut
plt.style.use('default')
```

## Sous-graphiques et Graphiques Multiples

### Sous-graphiques de Base : `plt.subplot()` / `plt.subplots()`

Crée plusieurs graphiques dans une seule figure.

```python
# Créer une grille de sous-graphiques 2x2
fig, axes = plt.subplots(2, 2, figsize=(10, 8))

# Tracer dans chaque sous-graphique
axes[0, 0].plot(x, y)
axes[0, 1].scatter(x, y)
axes[1, 0].bar(x, y)
axes[1, 1].hist(y, bins=10)

# Syntaxe alternative
plt.subplot(2, 2, 1)  # 2 lignes, 2 colonnes, 1er sous-graphique
plt.plot(x, y)
plt.subplot(2, 2, 2)  # 2ème sous-graphique
plt.scatter(x, y)
```

### Axes Partagés : `sharex` / `sharey`

Lie les axes à travers les sous-graphiques pour une mise à l'échelle cohérente.

```python
# Partager l'axe x à travers les sous-graphiques
fig, axes = plt.subplots(2, 1, sharex=True)
axes[0].plot(x, y1)
axes[1].plot(x, y2)

# Partager les deux axes
fig, axes = plt.subplots(2, 2, sharex=True, sharey=True)
```

### GridSpec : Mises en Page Avancées

Crée des arrangements de sous-graphiques complexes avec des tailles variables.

```python
import matplotlib.gridspec as gridspec

# Créer une grille personnalisée
gs = gridspec.GridSpec(3, 3)
fig = plt.figure(figsize=(10, 8))

# Sous-graphiques de tailles différentes
ax1 = fig.add_subplot(gs[0, :])  # Ligne du haut, toutes les colonnes
ax2 = fig.add_subplot(gs[1, :-1])  # Ligne du milieu, premières 2 colonnes
ax3 = fig.add_subplot(gs[1:, -1])  # Dernière colonne, 2 dernières lignes
ax4 = fig.add_subplot(gs[-1, 0])   # En bas à gauche
ax5 = fig.add_subplot(gs[-1, 1])   # En bas au milieu
```

### Espacement des Sous-graphiques : `hspace` / `wspace`

Contrôle l'espacement entre les sous-graphiques.

```python
# Ajuster l'espacement lors de la création des sous-graphiques
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
plt.subplots_adjust(hspace=0.4, wspace=0.3)

# Ou utiliser tight_layout pour un ajustement automatique
plt.tight_layout()
```

## Types de Visualisation Avancés

### Cartes de Chaleur : `plt.imshow()` / `plt.pcolormesh()`

Visualise les données 2D sous forme de matrices codées par couleur.

```python
# Carte de chaleur de base
data = np.random.randn(10, 10)
plt.imshow(data, cmap='viridis')
plt.colorbar()

# Pcolormesh pour les grilles irrégulières
x = np.linspace(0, 10, 11)
y = np.linspace(0, 5, 6)
X, Y = np.meshgrid(x, y)
Z = np.sin(X) * np.cos(Y)
plt.pcolormesh(X, Y, Z, shading='auto')
plt.colorbar()
```

### Graphiques de Contour : `plt.contour()` / `plt.contourf()`

Affiche les courbes de niveau et les régions de contour remplies.

```python
# Lignes de contour
x = np.linspace(-3, 3, 100)
y = np.linspace(-3, 3, 100)
X, Y = np.meshgrid(x, y)
Z = X**2 + Y**2
plt.contour(X, Y, Z, levels=10)
plt.clabel(plt.contour(X, Y, Z), inline=True, fontsize=8)

# Contours remplis
plt.contourf(X, Y, Z, levels=20, cmap='RdBu')
plt.colorbar()
```

### Graphiques 3D : `mplot3d`

Crée des visualisations tridimensionnelles.

```python
from mpl_toolkits.mplot3d import Axes3D

fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# Nuage de points 3D
ax.scatter(x, y, z)

# Graphique de surface 3D
ax.plot_surface(X, Y, Z, cmap='viridis')

# Graphique linéaire 3D
ax.plot(x, y, z)
```

### Barres d\'Erreur : `plt.errorbar()`

Affiche les données avec des mesures d'incertitude.

```python
# Barres d'erreur de base
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
yerr = [0.5, 0.8, 0.3, 0.7, 0.4]
plt.errorbar(x, y, yerr=yerr, fmt='o-', capsize=5)

# Barres d'erreur asymétriques
yerr_lower = [0.4, 0.6, 0.2, 0.5, 0.3]
yerr_upper = [0.6, 1.0, 0.4, 0.9, 0.5]
plt.errorbar(x, y, yerr=[yerr_lower, yerr_upper], fmt='s-')
```

### Remplissage Entre : `plt.fill_between()`

Ombre les zones entre les courbes ou autour des lignes.

```python
# Remplissage entre deux courbes
y1 = [2, 4, 6, 8, 10]
y2 = [1, 3, 5, 7, 9]
plt.fill_between(x, y1, y2, alpha=0.3, color='blue')

# Remplissage autour d'une ligne avec erreur
plt.plot(x, y, 'k-', linewidth=2)
plt.fill_between(x, y-yerr, y+yerr, alpha=0.2, color='gray')
```

### Graphiques en Violon : Alternative aux Diagrammes en Boîte

Montre la forme de la distribution ainsi que les quartiles.

```python
# Utilisation de pyplot
parts = plt.violinplot([data1, data2, data3])

# Personnaliser les couleurs
for pc in parts['bodies']:
    pc.set_facecolor('lightblue')
    pc.set_alpha(0.7)
```

## Fonctionnalités Interactives et d'Animation

### Backend Interactif : `%matplotlib widget`

Active les graphiques interactifs dans les notebooks Jupyter.

```python
# Dans un notebook Jupyter
%matplotlib widget

# Ou pour une interactivité de base
%matplotlib notebook
```

### Gestion des Événements : Souris et Clavier

Répond aux interactions de l'utilisateur avec les graphiques.

```python
# Zoom interactif, panoramique et survol
def onclick(event):
    if event.inaxes:
        print(f'Clic à x={event.xdata}, y={event.ydata}')

fig, ax = plt.subplots()
ax.plot(x, y)
fig.canvas.mpl_connect('button_press_event', onclick)
plt.show()
```

### Animations : `matplotlib.animation`

Crée des graphiques animés pour les séries temporelles ou les données changeantes.

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

# Sauvegarder l'animation
# ani.save('animation.gif', writer='pillow')
```

## Sauvegarde et Exportation de Graphiques

### Sauvegarder la Figure : `plt.savefig()`

Exporte les graphiques dans des fichiers image avec diverses options.

```python
# Sauvegarde de base
plt.savefig('mon_graphique.png')

# Sauvegarde de haute qualité
plt.savefig('graphique.png', dpi=300, bbox_inches='tight')

# Différents formats
plt.savefig('graphique.pdf')  # PDF
plt.savefig('graphique.svg')  # SVG (vecteur)
plt.savefig('graphique.eps')  # EPS

# Arrière-plan transparent
plt.savefig('graphique.png', transparent=True)
```

### Qualité de la Figure : DPI et Taille

Contrôle la résolution et les dimensions des graphiques enregistrés.

```python
# DPI élevé pour les publications
plt.savefig('graphique.png', dpi=600)

# Taille personnalisée (largeur, hauteur en pouces)
plt.figure(figsize=(12, 8))
plt.savefig('graphique.png', figsize=(12, 8))

# Rogner l'espace blanc
plt.savefig('graphique.png', bbox_inches='tight', pad_inches=0.1)
```

### Exportation par Lots et Gestion de la Mémoire

Gère plusieurs graphiques et l'efficacité de la mémoire.

```python
# Fermer les figures pour libérer la mémoire
plt.close()  # Ferme la figure actuelle
plt.close('all')  # Ferme toutes les figures

# Gestionnaire de contexte pour un nettoyage automatique
with plt.figure() as fig:
    plt.plot(x, y)
    plt.savefig('graphique.png')

# Sauvegarde par lots de plusieurs graphiques
for i, data in enumerate(datasets):
    plt.figure()
    plt.plot(data)
    plt.savefig(f'graphique_{i}.png')
    plt.close()
```

## Configuration et Bonnes Pratiques

### Paramètres RC : `plt.rcParams`

Définit le style et le comportement par défaut pour tous les graphiques.

```python
# Paramètres rc courants
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 12
plt.rcParams['lines.linewidth'] = 2
plt.rcParams['axes.grid'] = True

# Sauvegarder et restaurer les paramètres
original_params = plt.rcParams.copy()
# ... faire des changements ...
plt.rcParams.update(original_params)  # Restaurer
```

### Gestion des Couleurs : Cartes de Couleurs et Palettes

Travaille efficacement avec les couleurs et les cartes de couleurs.

```python
# Lister les cartes de couleurs disponibles
print(plt.colormaps())

# Utiliser une carte de couleurs pour plusieurs lignes
colors = plt.cm.viridis(np.linspace(0, 1, len(datasets)))
for i, (data, color) in enumerate(zip(datasets, colors)):
    plt.plot(data, color=color, label=f'Ensemble de données {i+1}')

# Carte de couleurs personnalisée
from matplotlib.colors import LinearSegmentedColormap
custom_cmap = LinearSegmentedColormap.from_list('custom', ['red', 'yellow', 'blue'])
```

### Optimisation des Performances

Améliore les performances de traçage pour les grands ensembles de données.

```python
# Utiliser le "blit" pour les animations
ani = FuncAnimation(fig, animate, blit=True)

# Rendu matriciel des graphiques complexes
plt.plot(x, y, rasterized=True)

# Réduire les points de données pour les grands ensembles de données
# Sous-échantillonner les données avant le traçage
indices = np.arange(0, len(large_data), step=10)
plt.plot(large_data[indices])
```

### Utilisation de la Mémoire : Traçage Efficace

Gère la mémoire lors de la création de nombreux graphiques ou de visualisations volumineuses.

```python
# Effacer les axes au lieu de créer de nouvelles figures
fig, ax = plt.subplots()
for data in datasets:
    ax.clear()  # Efface le tracé précédent
    ax.plot(data)
    plt.savefig(f'graphique_{i}.png')

# Utiliser des générateurs pour les grands ensembles de données
def data_generator():
    for i in range(1000):
        yield np.random.randn(100)

for i, data in enumerate(data_generator()):
    if i > 10:  # Limiter le nombre de graphiques
        break
```

## Intégration avec les Bibliothèques de Données

### Intégration Pandas : Traçage Direct

Utilise les méthodes de DataFrame de Pandas.

```python
import pandas as pd

# Traçage de DataFrame (utilise le backend matplotlib)
df.plot(kind='line', x='date', y='value')
df.plot.scatter(x='x_col', y='y_col')
df.plot.hist(bins=30)
df.plot.box()

# Accéder aux objets matplotlib sous-jacents
ax = df.plot(kind='line')
ax.set_title('Titre Personnalisé')
plt.show()
```

### Intégration NumPy : Visualisation de Tableaux

Trace efficacement les tableaux NumPy et les fonctions mathématiques.

```python
# Visualisation de tableau 2D
arr = np.random.rand(10, 10)
plt.imshow(arr, cmap='hot', interpolation='nearest')

# Fonctions mathématiques
x = np.linspace(0, 4*np.pi, 1000)
y = np.sin(x) * np.exp(-x/10)
plt.plot(x, y)

# Distributions statistiques
data = np.random.normal(0, 1, 10000)
plt.hist(data, bins=50, density=True, alpha=0.7)
```

### Intégration Seaborn : Style Amélioré

Combine Matplotlib avec Seaborn pour de meilleures esthétiques par défaut.

```python
import seaborn as sns

# Utiliser le style seaborn avec matplotlib
sns.set_style('whitegrid')
plt.plot(x, y)
plt.show()

# Mélanger seaborn et matplotlib
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
sns.scatterplot(data=df, x='x', y='y', ax=axes[0,0])
plt.plot(x, y, ax=axes[0,1])  # Matplotlib pur
```

### Intégration Jupyter : Traçage En Ligne

Optimise Matplotlib pour les environnements de notebooks Jupyter.

```python
# Commandes magiques pour Jupyter
%matplotlib inline  # Graphiques statiques
%matplotlib widget  # Graphiques interactifs

# Affichages DPI élevés
%config InlineBackend.figure_format = 'retina'

# Dimensionnement automatique des figures
%matplotlib inline
plt.rcParams['figure.dpi'] = 100
```

## Installation et Configuration de l'Environnement

### Pip : `pip install matplotlib`

Installateur de paquets Python standard pour Matplotlib.

```bash
# Installer Matplotlib
pip install matplotlib

# Mettre à jour vers la dernière version
pip install matplotlib --upgrade

# Installer avec des backends supplémentaires
pip install matplotlib[qt5]

# Afficher les informations sur le paquet
pip show matplotlib
```

### Conda : `conda install matplotlib`

Gestionnaire de paquets pour les environnements Anaconda/Miniconda.

```bash
# Installer dans l'environnement actuel
conda install matplotlib

# Mettre à jour matplotlib
conda update matplotlib

# Créer un environnement avec matplotlib
conda create -n dataviz matplotlib numpy pandas

# Lister les informations sur matplotlib
conda list matplotlib
```

### Configuration du Backend

Configurer les backends d'affichage pour différents environnements.

```python
# Vérifier les backends disponibles
import matplotlib
print(matplotlib.get_backend())

# Définir le backend par programmation
matplotlib.use('TkAgg')  # Pour Tkinter
matplotlib.use('Qt5Agg')  # Pour PyQt5

# Pour les serveurs sans tête (headless)
matplotlib.use('Agg')

# Importer après avoir défini le backend
import matplotlib.pyplot as plt
```

## Liens Pertinents

- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/numpy">Feuille de triche NumPy</router-link>
- <router-link to="/pandas">Feuille de triche Pandas</router-link>
- <router-link to="/sklearn">Feuille de triche scikit-learn</router-link>
- <router-link to="/datascience">Feuille de triche Science des Données</router-link>

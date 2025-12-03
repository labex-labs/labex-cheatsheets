---
title: 'Fiche Mémo NumPy | LabEx'
description: "Apprenez le calcul numérique avec NumPy grâce à cette fiche mémo complète. Référence rapide pour les tableaux, l'algèbre linéaire, les opérations mathématiques, le broadcasting et le calcul scientifique Python."
pdfUrl: '/cheatsheets/pdf/numpy-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche NumPy
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/numpy">Apprenez NumPy avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez le calcul numérique NumPy grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours NumPy complets couvrant les opérations de tableau essentielles, les fonctions mathématiques, l'algèbre linéaire et l'optimisation des performances. Maîtrisez le calcul numérique efficace et la manipulation de tableaux pour les flux de travail de science des données.
</base-disclaimer-content>
</base-disclaimer>

## Création et Initialisation de Tableaux

### À partir de Listes : `np.array()`

Crée des tableaux à partir de listes Python ou de listes imbriquées.

```python
import numpy as np

# Tableau 1D à partir d'une liste
arr = np.array([1, 2, 3, 4])
# Tableau 2D à partir de listes imbriquées
arr2d = np.array([[1, 2], [3, 4]])
# Spécifier le type de données
arr = np.array([1, 2, 3], dtype=float)
# Tableau de chaînes de caractères
arr_str = np.array(['a', 'b', 'c'])
```

<BaseQuiz id="numpy-array-1" correct="C">
  <template #question>
    Quel est l'avantage principal des tableaux NumPy par rapport aux listes Python ?
  </template>
  
  <BaseQuizOption value="A">Ils peuvent stocker des chaînes de caractères</BaseQuizOption>
  <BaseQuizOption value="B">Ils sont plus faciles à créer</BaseQuizOption>
  <BaseQuizOption value="C" correct>Ils sont plus rapides et plus efficaces en mémoire pour les opérations numériques</BaseQuizOption>
  <BaseQuizOption value="D">Ils peuvent stocker des types de données mixtes</BaseQuizOption>
  
  <BaseQuizAnswer>
    Les tableaux NumPy sont optimisés pour les calculs numériques, offrant des opérations plus rapides et une utilisation de la mémoire plus efficace par rapport aux listes Python, en particulier pour les grands ensembles de données et les opérations mathématiques.
  </BaseQuizAnswer>
</BaseQuiz>

### Zéros et Uns : `np.zeros()` / `np.ones()`

Crée des tableaux remplis de zéros ou d'uns.

```python
# Tableau de zéros
zeros = np.zeros(5)  # 1D
zeros2d = np.zeros((3, 4))  # 2D
# Tableau d'uns
ones = np.ones((2, 3))
# Spécifier le type de données
zeros_int = np.zeros(5, dtype=int)
```

### Matrice Identité : `np.eye()` / `np.identity()`

Crée des matrices identité pour les opérations d'algèbre linéaire.

```python
# Matrice identité 3x3
identity = np.eye(3)
# Méthode alternative
identity2 = np.identity(4)
```

### Tableaux de Plage : `np.arange()` / `np.linspace()`

Crée des tableaux avec des valeurs espacées uniformément.

```python
# Similaire à la portée Python
arr = np.arange(10)  # 0 à 9
arr = np.arange(2, 10, 2)  # 2, 4, 6, 8
# Valeurs espacées uniformément
arr = np.linspace(0, 1, 5)  # 5 valeurs de 0 à 1
# Incluant le point final
arr = np.linspace(0, 10, 11)
```

### Tableaux Aléatoires : `np.random`

Génère des tableaux avec des valeurs aléatoires.

```python
# Valeurs aléatoires entre 0 et 1
rand = np.random.random((2, 3))
# Entiers aléatoires
rand_int = np.random.randint(0, 10, size=(3, 3))
# Distribution normale
normal = np.random.normal(0, 1, size=5)
# Définir la graine aléatoire pour la reproductibilité
np.random.seed(42)
```

### Tableaux Spéciaux : `np.full()` / `np.empty()`

Crée des tableaux avec des valeurs spécifiques ou non initialisés.

```python
# Remplir avec une valeur spécifique
full_arr = np.full((2, 3), 7)
# Tableau vide (non initialisé)
empty_arr = np.empty((2, 2))
# Comme la forme du tableau existant
like_arr = np.zeros_like(arr)
```

## Propriétés et Structure du Tableau

### Propriétés de Base : `shape` / `size` / `ndim`

Obtenir des informations fondamentales sur les dimensions et la taille du tableau.

```python
# Dimensions du tableau (tuple)
arr.shape
# Nombre total d'éléments
arr.size
# Nombre de dimensions
arr.ndim
# Type de données des éléments
arr.dtype
# Taille de chaque élément en octets
arr.itemsize
```

### Informations sur le Tableau : Utilisation de la Mémoire

Obtenir des informations détaillées sur l'utilisation de la mémoire et la structure du tableau.

```python
# Utilisation de la mémoire en octets
arr.nbytes
# Informations sur le tableau (pour le débogage)
arr.flags
# Vérifier si le tableau possède ses données
arr.owndata
# Objet de base (si le tableau est une vue)
arr.base
```

### Types de Données : `astype()`

Convertir efficacement entre différents types de données.

```python
# Convertir en un type différent
arr.astype(float)
arr.astype(int)
arr.astype(str)
# Types plus spécifiques
arr.astype(np.float32)
arr.astype(np.int16)
```

## Indexation et Tranchage de Tableaux

### Indexation de Base : `arr[index]`

Accéder aux éléments individuels et aux tranches.

```python
# Élément unique
arr[0]  # Premier élément
arr[-1]  # Dernier élément
# Indexation de tableau 2D
arr2d[0, 1]  # Ligne 0, Colonne 1
arr2d[1]  # Ligne entière 1
# Tranchage
arr[1:4]  # Éléments 1 à 3
arr[::2]  # Tous les deux éléments
arr[::-1]  # Inverser le tableau
```

### Indexation Booléenne : `arr[condition]`

Filtrer les tableaux en fonction de conditions.

```python
# Condition simple
arr[arr > 5]
# Conditions multiples
arr[(arr > 2) & (arr < 8)]
arr[(arr < 2) | (arr > 8)]
# Tableau booléen
mask = arr > 3
filtered = arr[mask]
```

<BaseQuiz id="numpy-boolean-1" correct="C">
  <template #question>
    Que retourne l'indexation booléenne <code>arr[arr > 5]</code> ?
  </template>
  
  <BaseQuizOption value="A">Un tableau booléen</BaseQuizOption>
  <BaseQuizOption value="B">Le tableau original</BaseQuizOption>
  <BaseQuizOption value="C" correct>Un tableau contenant uniquement les éléments supérieurs à 5</BaseQuizOption>
  <BaseQuizOption value="D">Une erreur</BaseQuizOption>
  
  <BaseQuizAnswer>
    L'indexation booléenne filtre le tableau, ne retournant que les éléments pour lesquels la condition est vraie. <code>arr[arr > 5]</code> retourne un nouveau tableau contenant uniquement les valeurs supérieures à 5.
  </BaseQuizAnswer>
</BaseQuiz>

### Indexation Avancée : Indexation Fantaisie (Fancy Indexing)

Utiliser des tableaux d'indices pour accéder à plusieurs éléments.

```python
# Indexation avec un tableau d'indices
indices = [0, 2, 4]
arr[indices]
# Indexation fantaisie 2D
arr2d[[0, 1], [1, 2]]  # Éléments (0,1) et (1,2)
# Combiné avec le tranchage
arr2d[1:, [0, 2]]
```

### Fonction Where : `np.where()`

Sélection conditionnelle et remplacement d'éléments.

```python
# Trouver les indices où la condition est vraie
indices = np.where(arr > 5)
# Remplacement conditionnel
result = np.where(arr > 5, arr, 0)  # Remplacer les valeurs >5 par 0
# Conditions multiples
result = np.where(arr > 5, 'high', 'low')
```

## Manipulation et Remodelage de Tableaux

### Remodelage : `reshape()` / `resize()` / `flatten()`

Modifier les dimensions du tableau tout en préservant les données.

```python
# Remodeler (crée une vue si possible)
arr.reshape(2, 3)
arr.reshape(-1, 1)  # -1 signifie inférer la dimension
# Redimensionner (modifie le tableau original)
arr.resize((2, 3))
# Aplatir en 1D
arr.flatten()  # Retourne une copie
arr.ravel()  # Retourne une vue si possible
```

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    Que signifie <code>-1</code> dans <code>arr.reshape(-1, 1)</code> ?
  </template>
  
  <BaseQuizOption value="A">Cela crée une erreur</BaseQuizOption>
  <BaseQuizOption value="B" correct>NumPy infère automatiquement la dimension</BaseQuizOption>
  <BaseQuizOption value="C">Cela crée un tableau 1D</BaseQuizOption>
  <BaseQuizOption value="D">Cela inverse le tableau</BaseQuizOption>
  
  <BaseQuizAnswer>
    Utiliser <code>-1</code> dans reshape indique à NumPy de calculer automatiquement cette dimension en fonction de la taille totale du tableau et des autres dimensions spécifiées. Ceci est utile lorsque vous connaissez une dimension mais souhaitez que NumPy trouve l'autre.
  </BaseQuizAnswer>
</BaseQuiz>

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    Que signifie <code>-1</code> dans <code>arr.reshape(-1, 1)</code> ?
  </template>
  
  <BaseQuizOption value="A">Cela crée une erreur</BaseQuizOption>
  <BaseQuizOption value="B" correct>NumPy infère automatiquement la dimension</BaseQuizOption>
  <BaseQuizOption value="C">Cela supprime cette dimension</BaseQuizOption>
  <BaseQuizOption value="D">Cela définit la dimension à 1</BaseQuizOption>
  
  <BaseQuizAnswer>
    Utiliser <code>-1</code> dans reshape indique à NumPy de calculer automatiquement cette dimension en fonction de la taille totale du tableau et des autres dimensions spécifiées. Ceci est utile lorsque vous connaissez une dimension mais souhaitez que NumPy trouve l'autre.
  </BaseQuizAnswer>
</BaseQuiz>

### Transposition : `T` / `transpose()`

Échanger les axes du tableau pour les opérations matricielles.

```python
# Transposition simple
arr2d.T
# Transposition avec spécification des axes
arr.transpose()
np.transpose(arr)
# Pour les dimensions supérieures
arr3d.transpose(2, 0, 1)
```

### Ajout/Suppression d'Éléments

Modifier la taille du tableau en ajoutant ou supprimant des éléments.

```python
# Ajouter des éléments
np.append(arr, [4, 5])
# Insérer à une position spécifique
np.insert(arr, 1, 99)
# Supprimer des éléments
np.delete(arr, [1, 3])
# Répéter des éléments
np.repeat(arr, 3)
np.tile(arr, 2)
```

### Combinaison de Tableaux : `concatenate()` / `stack()`

Joindre plusieurs tableaux ensemble.

```python
# Concaténer le long d'un axe existant
np.concatenate([arr1, arr2])
np.concatenate([arr1, arr2], axis=1)
# Empiler les tableaux (crée un nouvel axe)
np.vstack([arr1, arr2])  # Verticalement
np.hstack([arr1, arr2])  # Horizontalement
np.dstack([arr1, arr2])  # En profondeur
```

## Opérations Mathématiques

### Arithmétique de Base : `+`, `-`, `*`, `/`

Opérations arithmétiques élément par élément sur les tableaux.

```python
# Opérations élément par élément
arr1 + arr2
arr1 - arr2
arr1 * arr2  # Multiplication élément par élément
arr1 / arr2
arr1 ** 2  # Mise au carré
arr1 % 3  # Opération modulo
```

### Fonctions Universelles (ufuncs)

Appliquer des fonctions mathématiques élément par élément.

```python
# Fonctions trigonométriques
np.sin(arr)
np.cos(arr)
np.tan(arr)
# Exponentielle et logarithmique
np.exp(arr)
np.log(arr)
np.log10(arr)
# Racine carrée et puissance
np.sqrt(arr)
np.power(arr, 3)
```

### Fonctions d'Agrégation

Calculer des statistiques récapitulatives sur les dimensions du tableau.

```python
# Statistiques de base
np.sum(arr)
np.mean(arr)
np.std(arr)  # Écart type
np.var(arr)  # Variance
np.min(arr)
np.max(arr)
# Le long d'un axe spécifique
np.sum(arr2d, axis=0)  # Somme le long des lignes
np.mean(arr2d, axis=1)  # Moyenne le long des colonnes
```

### Opérations de Comparaison

Comparaisons élément par élément retournant des tableaux booléens.

```python
# Opérateurs de comparaison
arr > 5
arr == 3
arr != 0
# Comparaisons de tableaux
np.array_equal(arr1, arr2)
np.allclose(arr1, arr2)  # Dans la tolérance
# Opérations any/all
np.any(arr > 5)
np.all(arr > 0)
```

## Algèbre Linéaire

### Opérations Matricielles : `np.dot()` / `@`

Effectuer la multiplication matricielle et le produit scalaire.

```python
# Multiplication matricielle
np.dot(A, B)
A @ B  # Opérateur Python 3.5+
# Multiplication élément par élément
A * B
# Puissance matricielle
np.linalg.matrix_power(A, 3)
```

### Décompositions : `np.linalg`

Décompositions matricielles pour les calculs avancés.

```python
# Valeurs propres et vecteurs propres
eigenvals, eigenvecs = np.linalg.eig(A)
# Décomposition en valeurs singulières
U, s, Vt = np.linalg.svd(A)
# Décomposition QR
Q, R = np.linalg.qr(A)
```

### Propriétés Matricielles

Calculer des caractéristiques matricielles importantes.

```python
# Déterminant
np.linalg.det(A)
# Inverse de la matrice
np.linalg.inv(A)
# Pseudo-inverse
np.linalg.pinv(A)
# Rang de la matrice
np.linalg.matrix_rank(A)
# Trace (somme de la diagonale)
np.trace(A)
```

### Résolution de Systèmes Linéaires : `np.linalg.solve()`

Résoudre des systèmes d'équations linéaires.

```python
# Résoudre Ax = b
x = np.linalg.solve(A, b)
# Solution des moindres carrés
x = np.linalg.lstsq(A, b, rcond=None)[0]
```

## Entrée/Sortie de Tableaux

### Binaire NumPy : `np.save()` / `np.load()`

Format binaire efficace pour les tableaux NumPy.

```python
# Sauvegarder un tableau unique
np.save('array.npy', arr)
# Charger un tableau
loaded_arr = np.load('array.npy')
# Sauvegarder plusieurs tableaux
np.savez('arrays.npz', a=arr1, b=arr2)
# Charger plusieurs tableaux
data = np.load('arrays.npz')
arr1_loaded = data['a']
```

### Fichiers Texte : `np.loadtxt()` / `np.savetxt()`

Lire et écrire des tableaux sous forme de fichiers texte.

```python
# Charger à partir d'un fichier CSV/texte
arr = np.loadtxt('data.csv', delimiter=',')
# Sauter la ligne d'en-tête
arr = np.loadtxt('data.csv', delimiter=',', skiprows=1)
# Sauvegarder dans un fichier texte
np.savetxt('output.csv', arr, delimiter=',', fmt='%.2f')
```

### CSV avec Données Structurées : `np.genfromtxt()`

Lecture avancée de fichiers texte avec gestion des données manquantes.

```python
# Gérer les valeurs manquantes
arr = np.genfromtxt('data.csv', delimiter=',',
                    missing_values='N/A', filling_values=0)
# Colonnes nommées
data = np.genfromtxt('data.csv', delimiter=',',
                     names=True, dtype=None)
```

### Mappage Mémoire : `np.memmap()`

Travailler avec des tableaux trop volumineux pour tenir en mémoire.

```python
# Créer un tableau mappé en mémoire
mmap_arr = np.memmap('large_array.dat', dtype='float32',
                     mode='w+', shape=(1000000,))
# Accéder comme un tableau régulier mais stocké sur disque
mmap_arr[0:10] = np.random.random(10)
```

## Performances et Diffusion (Broadcasting)

### Règles de Diffusion (Broadcasting)

Comprendre comment NumPy gère les opérations sur des tableaux de formes différentes.

```python
# Exemples de diffusion
arr1 = np.array([[1, 2, 3]])  # Forme (1, 3)
arr2 = np.array([[1], [2]])   # Forme (2, 1)
result = arr1 + arr2          # Forme (2, 3)
# Diffusion scalaire
arr + 5  # Ajoute 5 à tous les éléments
arr * 2  # Multiplie tous les éléments par 2
```

### Opérations Vectorisées

Utiliser les fonctions intégrées de NumPy au lieu des boucles Python.

```python
# Au lieu de boucles, utiliser des opérations vectorisées
# Mauvais : boucle for
result = []
for x in arr:
    result.append(x ** 2)
# Bon : vectorisé
result = arr ** 2
# Fonction vectorisée personnalisée
def custom_func(x):
    return x ** 2 + 2 * x + 1
vec_func = np.vectorize(custom_func)
result = vec_func(arr)
```

### Optimisation de la Mémoire

Techniques pour une utilisation efficace de la mémoire avec les grands tableaux.

```python
# Utiliser des types de données appropriés
arr_int8 = arr.astype(np.int8)  # 1 octet par élément
arr_float32 = arr.astype(np.float32)  # 4 octets contre 8 pour float64
# Vues vs Copies
view = arr[::2]  # Crée une vue (partage la mémoire)
copy = arr[::2].copy()  # Crée une copie (nouvelle mémoire)
# Vérifier si le tableau est une vue ou une copie
view.base is arr  # True pour la vue
```

### Conseils de Performance

Meilleures pratiques pour un code NumPy rapide.

```python
# Utiliser des opérations en place lorsque c'est possible
arr += 5  # Au lieu de arr = arr + 5
np.add(arr, 5, out=arr)  # Explicite en place
# Minimiser la création de tableaux
# Mauvais : crée des tableaux intermédiaires
result = ((arr + 1) * 2) ** 2
# Mieux : utiliser des opérations composées lorsque possible
```

## Génération de Nombres Aléatoires

### Aléatoire de Base : `np.random`

Générer des nombres aléatoires à partir de diverses distributions.

```python
# Flottants aléatoires [0, 1)
np.random.random(5)
# Entiers aléatoires
np.random.randint(0, 10, size=5)
# Distribution normale
np.random.normal(mu=0, sigma=1, size=5)
# Distribution uniforme
np.random.uniform(-1, 1, size=5)
```

### Échantillonnage : `choice()` / `shuffle()`

Échantillonner à partir de données existantes ou permuter des tableaux.

```python
# Choix aléatoire dans le tableau
np.random.choice(arr, size=3)
# Sans remplacement
np.random.choice(arr, size=3, replace=False)
# Mélanger le tableau en place
np.random.shuffle(arr)
# Permutation aléatoire
np.random.permutation(arr)
```

### Graines et Générateurs

Contrôler l'aléatoire pour des résultats reproductibles.

```python
# Définir la graine pour la reproductibilité
np.random.seed(42)
# Approche moderne : Générateur
rng = np.random.default_rng(42)
rng.random(5)
rng.integers(0, 10, size=5)
rng.normal(0, 1, size=5)
```

## Fonctions Statistiques

### Statistiques Descriptives

Mesures statistiques de base de la tendance centrale et de la dispersion.

```python
# Tendance centrale
np.mean(arr)
np.median(arr)
# Mesures de dispersion
np.std(arr)  # Écart type
np.var(arr)  # Variance
np.ptp(arr)  # Amplitude (max - min)
# Percentiles
np.percentile(arr, [25, 50, 75])
np.quantile(arr, [0.25, 0.5, 0.75])
```

### Corrélation et Covariance

Mesurer les relations entre les variables.

```python
# Coefficient de corrélation
np.corrcoef(x, y)
# Covariance
np.cov(x, y)
# Corrélation croisée
np.correlate(x, y, mode='full')
```

### Histogramme et Binning

Analyser la distribution des données et créer des bacs (bins).

```python
# Histogramme
counts, bins = np.histogram(arr, bins=10)
# Histogramme 2D
H, xedges, yedges = np.histogram2d(x, y, bins=10)
# Numériser (assigner des indices de bac)
bin_indices = np.digitize(arr, bins)
```

### Fonctions Statistiques Spéciales

Calculs statistiques avancés.

```python
# Statistiques pondérées
np.average(arr, weights=weights)
# Valeurs uniques et comptes
unique_vals, counts = np.unique(arr, return_counts=True)
# Bincount (pour les tableaux d'entiers)
np.bincount(int_arr)
```

## Installation et Configuration de NumPy

### Pip : `pip install numpy`

Installateur de paquets Python standard.

```bash
# Installer NumPy
pip install numpy
# Mettre à jour vers la dernière version
pip install numpy --upgrade
# Installer une version spécifique
pip install numpy==1.21.0
# Afficher les informations sur le paquet
pip show numpy
```

### Conda : `conda install numpy`

Gestionnaire de paquets pour les environnements Anaconda/Miniconda.

```bash
# Installer NumPy dans l'environnement actuel
conda install numpy
# Mettre à jour NumPy
conda update numpy
# Installer depuis conda-forge
conda install -c conda-forge numpy
# Créer un environnement avec NumPy
conda create -n myenv numpy
```

### Vérifier l'Installation et Importer

Vérifier votre installation NumPy et l'importation standard.

```python
# Importation standard
import numpy as np
# Vérifier la version
print(np.__version__)
# Vérifier les informations de construction
np.show_config()
# Définir les options d'impression
np.set_printoptions(precision=2, suppress=True)
```

## Fonctionnalités Avancées

### Tableaux Structurés

Tableaux avec des champs nommés pour des structures de données complexes.

```python
# Définir le type de données structuré
dt = np.dtype([('name', 'U10'), ('age', 'i4'), ('weight', 'f4')])
# Créer un tableau structuré
people = np.array([('Alice', 25, 55.0), ('Bob', 30, 70.5)], dtype=dt)
# Accéder aux champs
people['name']
people['age']
```

### Tableaux Masqués : `np.ma`

Gérer les tableaux avec des données manquantes ou invalides.

```python
# Créer un tableau masqué
masked_arr = np.ma.array([1, 2, 3, 4, 5], mask=[0, 0, 1, 0, 0])
# Les opérations ignorent les valeurs masquées
np.ma.mean(masked_arr)
# Remplir les valeurs masquées
filled = masked_arr.filled(0)
```

### Polynômes : `np.poly1d`

Travailler avec des expressions polynomiales et des opérations.

```python
# Créer un polynôme (coefficients par ordre décroissant)
p = np.poly1d([1, -2, 1])  # x² - 2x + 1
# Évaluer le polynôme
p(5)  # Évaluer à x=5
# Trouver les racines
np.roots([1, -2, 1])
# Ajustement polynomial
coeff = np.polyfit(x, y, degree=2)
```

### Transformée de Fourier Rapide : `np.fft`

Analyse du domaine fréquentiel et traitement du signal.

```python
# FFT 1D
fft_result = np.fft.fft(signal)
# Fréquences
freqs = np.fft.fftfreq(len(signal))
# FFT inverse
reconstructed = np.fft.ifft(fft_result)
# FFT 2D pour les images
fft2d = np.fft.fft2(image)
```

## Liens Pertinents

- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/pandas">Feuille de triche Pandas</router-link>
- <router-link to="/matplotlib">Feuille de triche Matplotlib</router-link>
- <router-link to="/sklearn">Feuille de triche scikit-learn</router-link>
- <router-link to="/datascience">Feuille de triche Science des Données</router-link>

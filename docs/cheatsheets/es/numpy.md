---
title: 'Hoja de Trucos de NumPy | LabEx'
description: 'Aprenda computación numérica con NumPy con esta hoja de trucos completa. Referencia rápida para arrays, álgebra lineal, operaciones matemáticas, broadcasting y computación científica en Python.'
pdfUrl: '/cheatsheets/pdf/numpy-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de NumPy
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/numpy">Aprende NumPy con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende computación numérica con NumPy a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de NumPy que cubren operaciones esenciales de arrays, funciones matemáticas, álgebra lineal y optimización de rendimiento. Domina la computación numérica eficiente y la manipulación de arrays para flujos de trabajo de ciencia de datos.
</base-disclaimer-content>
</base-disclaimer>

## Creación e Inicialización de Arrays

### A partir de Listas: `np.array()`

Crea arrays a partir de listas de Python o listas anidadas.

```python
import numpy as np

# Array 1D a partir de lista
arr = np.array([1, 2, 3, 4])
# Array 2D a partir de listas anidadas
arr2d = np.array([[1, 2], [3, 4]])
# Especificar tipo de dato
arr = np.array([1, 2, 3], dtype=float)
# Array de cadenas (strings)
arr_str = np.array(['a', 'b', 'c'])
```

<BaseQuiz id="numpy-array-1" correct="C">
  <template #question>
    ¿Cuál es la principal ventaja de los arrays de NumPy sobre las listas de Python?
  </template>
  
  <BaseQuizOption value="A">Pueden almacenar cadenas</BaseQuizOption>
  <BaseQuizOption value="B">Son más fáciles de crear</BaseQuizOption>
  <BaseQuizOption value="C" correct>Son más rápidos y eficientes en memoria para operaciones numéricas</BaseQuizOption>
  <BaseQuizOption value="D">Pueden almacenar tipos de datos mixtos</BaseQuizOption>
  
  <BaseQuizAnswer>
    Los arrays de NumPy están optimizados para cálculos numéricos, proporcionando operaciones más rápidas y un uso de memoria más eficiente en comparación con las listas de Python, especialmente para grandes conjuntos de datos y operaciones matemáticas.
  </BaseQuizAnswer>
</BaseQuiz>

### Ceros y Unos: `np.zeros()` / `np.ones()`

Crea arrays llenos de ceros o unos.

```python
# Array de ceros
zeros = np.zeros(5)  # 1D
zeros2d = np.zeros((3, 4))  # 2D
# Array de unos
ones = np.ones((2, 3))
# Especificar tipo de dato
zeros_int = np.zeros(5, dtype=int)
```

### Matriz Identidad: `np.eye()` / `np.identity()`

Crea matrices identidad para operaciones de álgebra lineal.

```python
# Matriz identidad de 3x3
identity = np.eye(3)
# Método alternativo
identity2 = np.identity(4)
```

### Arrays de Rango: `np.arange()` / `np.linspace()`

Crea arrays con valores espaciados uniformemente.

```python
# Similar al rango de Python
arr = np.arange(10)  # 0 a 9
arr = np.arange(2, 10, 2)  # 2, 4, 6, 8
# Valores espaciados uniformemente
arr = np.linspace(0, 1, 5)  # 5 valores de 0 a 1
# Incluyendo el punto final
arr = np.linspace(0, 10, 11)
```

### Arrays Aleatorios: `np.random`

Genera arrays con valores aleatorios.

```python
# Valores aleatorios entre 0 y 1
rand = np.random.random((2, 3))
# Enteros aleatorios
rand_int = np.random.randint(0, 10, size=(3, 3))
# Distribución normal
normal = np.random.normal(0, 1, size=5)
# Establecer semilla aleatoria para reproducibilidad
np.random.seed(42)
```

### Arrays Especiales: `np.full()` / `np.empty()`

Crea arrays con valores específicos o sin inicializar.

```python
# Rellenar con valor específico
full_arr = np.full((2, 3), 7)
# Array vacío (sin inicializar)
empty_arr = np.empty((2, 2))
# Forma como array existente
like_arr = np.zeros_like(arr)
```

## Propiedades y Estructura del Array

### Propiedades Básicas: `shape` / `size` / `ndim`

Obtén información fundamental sobre las dimensiones y el tamaño del array.

```python
# Dimensiones del array (tupla)
arr.shape
# Número total de elementos
arr.size
# Número de dimensiones
arr.ndim
# Tipo de dato de los elementos
arr.dtype
# Tamaño de cada elemento en bytes
arr.itemsize
```

### Información del Array: Uso de Memoria

Obtén información detallada sobre el uso de memoria y la estructura del array.

```python
# Uso de memoria en bytes
arr.nbytes
# Información del array (para depuración)
arr.flags
# Comprobar si el array posee sus datos
arr.owndata
# Objeto base (si el array es una vista)
arr.base
```

### Tipos de Datos: `astype()`

Convierte eficientemente entre diferentes tipos de datos.

```python
# Convertir a diferente tipo
arr.astype(float)
arr.astype(int)
arr.astype(str)
# Tipos más específicos
arr.astype(np.float32)
arr.astype(np.int16)
```

## Indexación y Segmentación de Arrays

### Indexación Básica: `arr[index]`

Accede a elementos individuales y segmentos (slices).

```python
# Elemento único
arr[0]  # Primer elemento
arr[-1]  # Último elemento
# Indexación 2D
arr2d[0, 1]  # Fila 0, Columna 1
arr2d[1]  # Fila completa 1
# Segmentación (Slicing)
arr[1:4]  # Elementos del 1 al 3
arr[::2]  # Cada segundo elemento
arr[::-1]  # Array invertido
```

### Indexación Booleana: `arr[condition]`

Filtra arrays basados en condiciones.

```python
# Condición simple
arr[arr > 5]
# Múltiples condiciones
arr[(arr > 2) & (arr < 8)]
arr[(arr < 2) | (arr > 8)]
# Array booleano
mask = arr > 3
filtered = arr[mask]
```

<BaseQuiz id="numpy-boolean-1" correct="C">
  <template #question>
    ¿Qué devuelve la indexación booleana `arr[arr > 5]`?
  </template>
  
  <BaseQuizOption value="A">Un array booleano</BaseQuizOption>
  <BaseQuizOption value="B">El array original</BaseQuizOption>
  <BaseQuizOption value="C" correct>Un array solo con elementos mayores que 5</BaseQuizOption>
  <BaseQuizOption value="D">Un error</BaseQuizOption>
  
  <BaseQuizAnswer>
    La indexación booleana filtra el array, devolviendo solo los elementos donde la condición es verdadera. `arr[arr > 5]` devuelve un nuevo array que contiene solo valores mayores que 5.
  </BaseQuizAnswer>
</BaseQuiz>

### Indexación Avanzada: Indexación Fantasma (Fancy Indexing)

Usa arrays de índices para acceder a múltiples elementos.

```python
# Indexar con array de índices
indices = [0, 2, 4]
arr[indices]
# Indexación fantasma 2D
arr2d[[0, 1], [1, 2]]  # Elementos (0,1) y (1,2)
# Combinado con segmentación
arr2d[1:, [0, 2]]
```

### Función Where: `np.where()`

Selección condicional y reemplazo de elementos.

```python
# Encontrar índices donde la condición es verdadera
indices = np.where(arr > 5)
# Reemplazo condicional
result = np.where(arr > 5, arr, 0)  # Reemplaza valores >5 con 0
# Múltiples condiciones
result = np.where(arr > 5, 'high', 'low')
```

## Manipulación y Remodelación de Arrays

### Remodelación: `reshape()` / `resize()` / `flatten()`

Cambia las dimensiones del array preservando los datos.

```python
# Remodelar (crea vista si es posible)
arr.reshape(2, 3)
arr.reshape(-1, 1)  # -1 significa inferir la dimensión
# Redimensionar (modifica el array original)
arr.resize((2, 3))
# Aplanar a 1D
arr.flatten()  # Devuelve copia
arr.ravel()  # Devuelve vista si es posible
```

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    ¿Qué significa `-1` en `arr.reshape(-1, 1)`?
  </template>
  
  <BaseQuizOption value="A">Crea un error</BaseQuizOption>
  <BaseQuizOption value="B" correct>NumPy infiere la dimensión automáticamente</BaseQuizOption>
  <BaseQuizOption value="C">Crea un array 1D</BaseQuizOption>
  <BaseQuizOption value="D">Invierte el array</BaseQuizOption>
  
  <BaseQuizAnswer>
    Usar `-1` en reshape le dice a NumPy que calcule automáticamente esa dimensión basándose en el tamaño total del array y las otras dimensiones especificadas. Esto es útil cuando conoces una dimensión pero quieres que NumPy calcule la otra.
  </BaseQuizAnswer>
</BaseQuiz>

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    ¿Qué significa `-1` en `arr.reshape(-1, 1)`?
  </template>
  
  <BaseQuizOption value="A">Crea un error</BaseQuizOption>
  <BaseQuizOption value="B" correct>NumPy infiere la dimensión automáticamente</BaseQuizOption>
  <BaseQuizOption value="C">Elimina esa dimensión</BaseQuizOption>
  <BaseQuizOption value="D">Establece la dimensión a 1</BaseQuizOption>
  
  <BaseQuizAnswer>
    Usar `-1` en reshape le dice a NumPy que calcule automáticamente esa dimensión basándose en el tamaño total del array y las otras dimensiones especificadas. Esto es útil cuando conoces una dimensión pero quieres que NumPy calcule la otra.
  </BaseQuizAnswer>
</BaseQuiz>

### Transposición: `T` / `transpose()`

Intercambia los ejes del array para operaciones matriciales.

```python
# Transposición simple
arr2d.T
# Transposición con especificación de ejes
arr.transpose()
np.transpose(arr)
# Para dimensiones superiores
arr3d.transpose(2, 0, 1)
```

### Añadir/Eliminar Elementos

Modifica el tamaño del array añadiendo o eliminando elementos.

```python
# Añadir elementos
np.append(arr, [4, 5])
# Insertar en posición específica
np.insert(arr, 1, 99)
# Eliminar elementos
np.delete(arr, [1, 3])
# Repetir elementos
np.repeat(arr, 3)
np.tile(arr, 2)
```

### Combinar Arrays: `concatenate()` / `stack()`

Une múltiples arrays.

```python
# Concatenar a lo largo del eje existente
np.concatenate([arr1, arr2])
np.concatenate([arr1, arr2], axis=1)
# Apilar arrays (crea un nuevo eje)
np.vstack([arr1, arr2])  # Verticalmente
np.hstack([arr1, arr2])  # Horizontalmente
np.dstack([arr1, arr2])  # Profundidad
```

## Operaciones Matemáticas

### Aritmética Básica: `+`, `-`, `*`, `/`

Operaciones aritméticas elemento a elemento en arrays.

```python
# Operaciones elemento a elemento
arr1 + arr2
arr1 - arr2
arr1 * arr2  # Multiplicación elemento a elemento
arr1 / arr2
arr1 ** 2  # Elevar al cuadrado
arr1 % 3  # Operación módulo
```

### Funciones Universales (ufuncs)

Aplica funciones matemáticas elemento a elemento.

```python
# Funciones trigonométricas
np.sin(arr)
np.cos(arr)
np.tan(arr)
# Exponencial y logarítmica
np.exp(arr)
np.log(arr)
np.log10(arr)
# Raíz cuadrada y potencia
np.sqrt(arr)
np.power(arr, 3)
```

### Funciones de Agregación

Calcula estadísticas resumidas a través de las dimensiones del array.

```python
# Estadísticas básicas
np.sum(arr)
np.mean(arr)
np.std(arr)  # Desviación estándar
np.var(arr)  # Varianza
np.min(arr)
np.max(arr)
# A lo largo de un eje específico
np.sum(arr2d, axis=0)  # Suma a lo largo de las filas
np.mean(arr2d, axis=1)  # Media a lo largo de las columnas
```

### Operaciones de Comparación

Comparaciones elemento a elemento que devuelven arrays booleanos.

```python
# Operadores de comparación
arr > 5
arr == 3
arr != 0
# Comparaciones de arrays
np.array_equal(arr1, arr2)
np.allclose(arr1, arr2)  # Dentro de la tolerancia
# Operaciones any/all
np.any(arr > 5)
np.all(arr > 0)
```

## Álgebra Lineal

### Operaciones de Matriz: `np.dot()` / `@`

Realiza multiplicación de matrices y productos punto.

```python
# Multiplicación de matrices
np.dot(A, B)
A @ B  # Operador Python 3.5+
# Multiplicación elemento a elemento
A * B
# Potencia de matriz
np.linalg.matrix_power(A, 3)
```

### Descomposiciones: `np.linalg`

Descomposiciones de matrices para cálculos avanzados.

```python
# Valores y vectores propios
eigenvals, eigenvecs = np.linalg.eig(A)
# Descomposición de Valores Singulares
U, s, Vt = np.linalg.svd(A)
# Descomposición QR
Q, R = np.linalg.qr(A)
```

### Propiedades de la Matriz

Calcula características importantes de la matriz.

```python
# Determinante
np.linalg.det(A)
# Inversa de la matriz
np.linalg.inv(A)
# Pseudo-inversa
np.linalg.pinv(A)
# Rango de la matriz
np.linalg.matrix_rank(A)
# Traza (suma de la diagonal)
np.trace(A)
```

### Resolver Sistemas Lineales: `np.linalg.solve()`

Resuelve sistemas de ecuaciones lineales.

```python
# Resolver Ax = b
x = np.linalg.solve(A, b)
# Solución de mínimos cuadrados
x = np.linalg.lstsq(A, b, rcond=None)[0]
```

## Entrada/Salida de Arrays

### Binario de NumPy: `np.save()` / `np.load()`

Formato binario eficiente para arrays de NumPy.

```python
# Guardar array único
np.save('array.npy', arr)
# Cargar array
loaded_arr = np.load('array.npy')
# Guardar múltiples arrays
np.savez('arrays.npz', a=arr1, b=arr2)
# Cargar múltiples arrays
data = np.load('arrays.npz')
arr1_loaded = data['a']
```

### Archivos de Texto: `np.loadtxt()` / `np.savetxt()`

Lee y escribe arrays como archivos de texto.

```python
# Cargar desde archivo CSV/texto
arr = np.loadtxt('data.csv', delimiter=',')
# Omitir fila de encabezado
arr = np.loadtxt('data.csv', delimiter=',', skiprows=1)
# Guardar en archivo de texto
np.savetxt('output.csv', arr, delimiter=',', fmt='%.2f')
```

### Datos Estructurados CSV: `np.genfromtxt()`

Lectura avanzada de archivos de texto con manejo de datos faltantes.

```python
# Manejar valores faltantes
arr = np.genfromtxt('data.csv', delimiter=',',
                    missing_values='N/A', filling_values=0)
# Columnas con nombre
data = np.genfromtxt('data.csv', delimiter=',',
                     names=True, dtype=None)
```

### Mapeo de Memoria: `np.memmap()`

Trabaja con arrays demasiado grandes para caber en la memoria.

```python
# Crear array mapeado en memoria
mmap_arr = np.memmap('large_array.dat', dtype='float32',
                     mode='w+', shape=(1000000,))
# Acceder como array regular pero almacenado en disco
mmap_arr[0:10] = np.random.random(10)
```

## Rendimiento y Difusión (Broadcasting)

### Reglas de Difusión (Broadcasting)

Comprende cómo NumPy maneja operaciones en arrays de diferentes formas.

```python
# Ejemplos de broadcasting
arr1 = np.array([[1, 2, 3]])  # Forma (1, 3)
arr2 = np.array([[1], [2]])   # Forma (2, 1)
result = arr1 + arr2          # Forma (2, 3)
# Difusión escalar
arr + 5  # Suma 5 a todos los elementos
arr * 2  # Multiplica todos los elementos por 2
```

### Operaciones Vectorizadas

Usa las funciones integradas de NumPy en lugar de bucles de Python.

```python
# En lugar de bucles, usa operaciones vectorizadas
# Malo: bucle for
result = []
for x in arr:
    result.append(x ** 2)
# Bueno: vectorizado
result = arr ** 2
# Función vectorizada personalizada
def custom_func(x):
    return x ** 2 + 2 * x + 1
vec_func = np.vectorize(custom_func)
result = vec_func(arr)
```

### Optimización de Memoria

Técnicas para un uso eficiente de la memoria con arrays grandes.

```python
# Usar tipos de datos apropiados
arr_int8 = arr.astype(np.int8)  # 1 byte por elemento
arr_float32 = arr.astype(np.float32)  # 4 bytes vs 8 para float64
# Vistas vs copias
view = arr[::2]  # Crea vista (comparte memoria)
copy = arr[::2].copy()  # Crea copia (nueva memoria)
# Comprobar si el array es vista o copia
view.base is arr  # True para vista
```

### Consejos de Rendimiento

Mejores prácticas para código NumPy rápido.

```python
# Usar operaciones in-place cuando sea posible
arr += 5  # En lugar de arr = arr + 5
np.add(arr, 5, out=arr)  # In-place explícito
# Minimizar la creación de arrays
# Malo: crea arrays intermedios
result = ((arr + 1) * 2) ** 2
# Mejor: usar operaciones compuestas cuando sea posible
```

## Generación de Números Aleatorios

### Aleatorio Básico: `np.random`

Genera números aleatorios a partir de varias distribuciones.

```python
# Flotantes aleatorios [0, 1)
np.random.random(5)
# Enteros aleatorios
np.random.randint(0, 10, size=5)
# Distribución normal
np.random.normal(mu=0, sigma=1, size=5)
# Distribución uniforme
np.random.uniform(-1, 1, size=5)
```

### Muestreo: `choice()` / `shuffle()`

Muestra de datos existentes o permutación de arrays.

```python
# Elección aleatoria del array
np.random.choice(arr, size=3)
# Sin reemplazo
np.random.choice(arr, size=3, replace=False)
# Barajar array in-place
np.random.shuffle(arr)
# Permutación aleatoria
np.random.permutation(arr)
```

### Semillas y Generadores

Controla la aleatoriedad para resultados reproducibles.

```python
# Establecer semilla para reproducibilidad
np.random.seed(42)
# Enfoque moderno: Generador
rng = np.random.default_rng(42)
rng.random(5)
rng.integers(0, 10, size=5)
rng.normal(0, 1, size=5)
```

## Funciones Estadísticas

### Estadísticas Descriptivas

Medidas básicas de tendencia central y dispersión.

```python
# Tendencia central
np.mean(arr)
np.median(arr)
# Medidas de dispersión
np.std(arr)  # Desviación estándar
np.var(arr)  # Varianza
np.ptp(arr)  # Pico a pico (máx - mín)
# Percentiles
np.percentile(arr, [25, 50, 75])
np.quantile(arr, [0.25, 0.5, 0.75])
```

### Correlación y Covarianza

Mide las relaciones entre variables.

```python
# Coeficiente de correlación
np.corrcoef(x, y)
# Covarianza
np.cov(x, y)
# Correlación cruzada
np.correlate(x, y, mode='full')
```

### Histograma y Agrupación (Binning)

Analiza la distribución de datos y crea contenedores.

```python
# Histograma
counts, bins = np.histogram(arr, bins=10)
# Histograma 2D
H, xedges, yedges = np.histogram2d(x, y, bins=10)
# Digitalizar (asignar índices de contenedor)
bin_indices = np.digitize(arr, bins)
```

### Funciones Estadísticas Especiales

Cálculos estadísticos avanzados.

```python
# Estadísticas ponderadas
np.average(arr, weights=weights)
# Valores únicos y conteos
unique_vals, counts = np.unique(arr, return_counts=True)
# Conteo de contenedores (para arrays de enteros)
np.bincount(int_arr)
```

## Instalación y Configuración de NumPy

### Pip: `pip install numpy`

Instalador estándar de paquetes de Python.

```bash
# Instalar NumPy
pip install numpy
# Actualizar a la última versión
pip install numpy --upgrade
# Instalar versión específica
pip install numpy==1.21.0
# Mostrar información del paquete
pip show numpy
```

### Conda: `conda install numpy`

Gestor de paquetes para entornos Anaconda/Miniconda.

```bash
# Instalar NumPy en el entorno actual
conda install numpy
# Actualizar NumPy
conda update numpy
# Instalar desde conda-forge
conda install -c conda-forge numpy
# Crear entorno con NumPy
conda create -n myenv numpy
```

### Comprobar Instalación e Importación

Verifica tu instalación de NumPy y la importación estándar.

```python
# Importación estándar
import numpy as np
# Comprobar versión
print(np.__version__)
# Comprobar información de compilación
np.show_config()
# Opciones de impresión
np.set_printoptions(precision=2, suppress=True)
```

## Características Avanzadas

### Arrays Estructurados

Arrays con campos nombrados para estructuras de datos complejas.

```python
# Definir tipo de dato estructurado
dt = np.dtype([('name', 'U10'), ('age', 'i4'), ('weight', 'f4')])
# Crear array estructurado
people = np.array([('Alice', 25, 55.0), ('Bob', 30, 70.5)], dtype=dt)
# Acceder a campos
people['name']
people['age']
```

### Arrays Enmascarados: `np.ma`

Maneja arrays con datos faltantes o inválidos.

```python
# Crear array enmascarado
masked_arr = np.ma.array([1, 2, 3, 4, 5], mask=[0, 0, 1, 0, 0])
# Las operaciones ignoran los valores enmascarados
np.ma.mean(masked_arr)
# Rellenar valores enmascarados
filled = masked_arr.filled(0)
```

### Polinomios: `np.poly1d`

Trabaja con expresiones polinómicas y operaciones.

```python
# Crear polinomio (coeficientes en orden descendente)
p = np.poly1d([1, -2, 1])  # x² - 2x + 1
# Evaluar polinomio
p(5)  # Evaluar en x=5
# Encontrar raíces
np.roots([1, -2, 1])
# Ajuste polinómico
coeff = np.polyfit(x, y, degree=2)
```

### Transformada Rápida de Fourier: `np.fft`

Análisis de dominio de frecuencia y procesamiento de señales.

```python
# FFT 1D
fft_result = np.fft.fft(signal)
# Frecuencias
freqs = np.fft.fftfreq(len(signal))
# FFT inversa
reconstructed = np.fft.ifft(fft_result)
# FFT 2D para imágenes
fft2d = np.fft.fft2(image)
```

## Enlaces Relevantes

- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/pandas">Hoja de Trucos de Pandas</router-link>
- <router-link to="/matplotlib">Hoja de Trucos de Matplotlib</router-link>
- <router-link to="/sklearn">Hoja de Trucos de scikit-learn</router-link>
- <router-link to="/datascience">Hoja de Trucos de Ciencia de Datos</router-link>

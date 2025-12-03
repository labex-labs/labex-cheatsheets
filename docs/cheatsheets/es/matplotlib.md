---
title: 'Hoja de Trucos de Matplotlib | LabEx'
description: 'Aprenda visualización de datos con Matplotlib con esta hoja de trucos completa. Referencia rápida para trazado, gráficos, diagramas, subgráficos, personalización y visualización de datos en Python.'
pdfUrl: '/cheatsheets/pdf/matplotlib-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Matplotlib
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/matplotlib">Aprenda Matplotlib con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda visualización de datos con Matplotlib a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Matplotlib que cubren funciones esenciales de trazado, técnicas de personalización, diseños de subgráficos y tipos de visualización avanzados. Domine la creación de visualizaciones de datos efectivas para flujos de trabajo de ciencia de datos en Python.
</base-disclaimer-content>
</base-disclaimer>

## Trazado Básico y Tipos de Gráficos

### Gráfico de Líneas: `plt.plot()`

Cree gráficos de líneas para la visualización de datos continuos.

```python
import matplotlib.pyplot as plt
import numpy as np

# Gráfico de líneas básico
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
plt.plot(x, y)
plt.show()

# Múltiples líneas
plt.plot(x, y, label='Línea 1')
plt.plot(x, [1, 3, 5, 7, 9], label='Línea 2')
plt.legend()

# Estilos y colores de línea
plt.plot(x, y, 'r--', linewidth=2, marker='o')
```

<BaseQuiz id="matplotlib-plot-1" correct="C">
  <template #question>
    ¿Qué hace `plt.show()` en Matplotlib?
  </template>
  
  <BaseQuizOption value="A">Guarda el gráfico en un archivo</BaseQuizOption>
  <BaseQuizOption value="B">Cierra la ventana del gráfico</BaseQuizOption>
  <BaseQuizOption value="C" correct>Muestra el gráfico en una ventana</BaseQuizOption>
  <BaseQuizOption value="D">Limpia el gráfico</BaseQuizOption>
  
  <BaseQuizAnswer>
    `plt.show()` muestra el gráfico en una ventana interactiva. Es necesario llamar a esta función para ver la visualización. Sin ella, el gráfico no se mostrará.
  </BaseQuizAnswer>
</BaseQuiz>

### Gráfico de Dispersión: `plt.scatter()`

Muestra la relación entre dos variables.

```python
# Gráfico de dispersión básico
plt.scatter(x, y)

# Con diferentes colores y tamaños
colors = [1, 2, 3, 4, 5]
sizes = [20, 50, 100, 200, 500]
plt.scatter(x, y, c=colors, s=sizes, alpha=0.6)
plt.colorbar()  # Añadir barra de color
```

<BaseQuiz id="matplotlib-scatter-1" correct="D">
  <template #question>
    ¿Qué controla el parámetro `alpha` en los gráficos de matplotlib?
  </template>
  
  <BaseQuizOption value="A">El color del gráfico</BaseQuizOption>
  <BaseQuizOption value="B">El tamaño del gráfico</BaseQuizOption>
  <BaseQuizOption value="C">La posición del gráfico</BaseQuizOption>
  <BaseQuizOption value="D" correct>La transparencia/opacidad de los elementos del gráfico</BaseQuizOption>
  
  <BaseQuizAnswer>
    El parámetro `alpha` controla la transparencia, con valores de 0 (completamente transparente) a 1 (completamente opaco). Es útil para crear visualizaciones superpuestas donde se desea ver a través de los elementos.
  </BaseQuizAnswer>
</BaseQuiz>

### Gráfico de Barras: `plt.bar()` / `plt.barh()`

Cree gráficos de barras verticales u horizontales.

```python
# Barras verticales
categories = ['A', 'B', 'C', 'D']
values = [20, 35, 30, 25]
plt.bar(categories, values)

# Barras horizontales
plt.barh(categories, values)

# Barras agrupadas
x = np.arange(len(categories))
plt.bar(x - 0.2, values, 0.4, label='Grupo 1')
plt.bar(x + 0.2, [15, 25, 35, 20], 0.4, label='Grupo 2')
```

### Histograma: `plt.hist()`

Muestra la distribución de datos continuos.

```python
# Histograma básico
data = np.random.randn(1000)
plt.hist(data, bins=30)

# Histograma personalizado
plt.hist(data, bins=50, alpha=0.7, color='skyblue', edgecolor='black')

# Múltiples histogramas
plt.hist([data1, data2], bins=30, alpha=0.7, label=['Datos 1', 'Datos 2'])
```

### Gráfico Circular (Tarta): `plt.pie()`

Muestra datos proporcionales como un gráfico circular.

```python
# Gráfico circular básico
sizes = [25, 35, 20, 20]
labels = ['A', 'B', 'C', 'D']
plt.pie(sizes, labels=labels)

# Gráfico circular explotado con porcentajes
explode = (0, 0.1, 0, 0)  # explotar la segunda porción
plt.pie(sizes, labels=labels, autopct='%1.1f%%',
        explode=explode, shadow=True, startangle=90)
```

### Diagrama de Caja (Box Plot): `plt.boxplot()`

Visualiza la distribución de datos y los valores atípicos (outliers).

```python
# Diagrama de caja único
data = [np.random.randn(100) for _ in range(4)]
plt.boxplot(data)

# Diagrama de caja personalizado
plt.boxplot(data, labels=['Grupo 1', 'Grupo 2', 'Grupo 3', 'Grupo 4'],
           patch_artist=True, notch=True)
```

## Personalización y Estilo de Gráficos

### Etiquetas y Títulos: `plt.xlabel()` / `plt.title()`

Añada texto descriptivo a sus gráficos para mayor claridad y contexto.

```python
# Etiquetas y título básicos
plt.plot(x, y)
plt.xlabel('Etiqueta del Eje X')
plt.ylabel('Etiqueta del Eje Y')
plt.title('Título del Gráfico')

# Títulos formateados con propiedades de fuente
plt.title('Mi Gráfico', fontsize=16, fontweight='bold')
plt.xlabel('Valores X', fontsize=12)

# Rejilla para mejor legibilidad
plt.grid(True, alpha=0.3)
```

### Colores y Estilos: `color` / `linestyle` / `marker`

Personalice la apariencia visual de los elementos del gráfico.

```python
# Opciones de color
plt.plot(x, y, color='red')  # Colores nombrados
plt.plot(x, y, color='#FF5733')  # Colores Hex
plt.plot(x, y, color=(0.1, 0.2, 0.5))  # Tupla RGB

# Estilos de línea
plt.plot(x, y, linestyle='--')  # Discontinua
plt.plot(x, y, linestyle=':')   # Punteada
plt.plot(x, y, linestyle='-.')  # Rayas y puntos

# Marcadores
plt.plot(x, y, marker='o', markersize=8, markerfacecolor='red')
```

### Leyendas y Anotaciones: `plt.legend()` / `plt.annotate()`

Añada leyendas y anotaciones para explicar los elementos del gráfico.

```python
# Leyenda básica
plt.plot(x, y1, label='Conjunto de Datos 1')
plt.plot(x, y2, label='Conjunto de Datos 2')
plt.legend()

# Posición de la leyenda personalizada
plt.legend(loc='upper right', fontsize=10, frameon=False)

# Anotaciones
plt.annotate('Punto Importante', xy=(2, 4), xytext=(3, 6),
            arrowprops=dict(arrowstyle='->', color='red'))
```

<BaseQuiz id="matplotlib-legend-1" correct="B">
  <template #question>
    ¿Qué se requiere para que `plt.legend()` muestre etiquetas?
  </template>
  
  <BaseQuizOption value="A">Nada, funciona automáticamente</BaseQuizOption>
  <BaseQuizOption value="B" correct>Cada gráfico debe tener un parámetro `label` establecido</BaseQuizOption>
  <BaseQuizOption value="C">La leyenda debe crearse antes de trazar</BaseQuizOption>
  <BaseQuizOption value="D">Las etiquetas deben establecerse manualmente en la leyenda</BaseQuizOption>
  
  <BaseQuizAnswer>
    Para mostrar una leyenda, debe establecer el parámetro `label` al crear cada gráfico (ej: `plt.plot(x, y, label='Conjunto de Datos 1')`). Luego, llamar a `plt.legend()` mostrará todas las etiquetas.
  </BaseQuizAnswer>
</BaseQuiz>

## Control de Ejes y Diseño

### Límites del Eje: `plt.xlim()` / `plt.ylim()`

Controle el rango de valores mostrados en cada eje.

```python
# Establecer límites del eje
plt.xlim(0, 10)
plt.ylim(-5, 15)

# Ajuste automático de límites con margen
plt.margins(x=0.1, y=0.1)

# Invertir eje
plt.gca().invert_yaxis()  # Invertir eje y
```

### Marcas y Etiquetas de Eje: `plt.xticks()` / `plt.yticks()`

Personalice las marcas de graduación del eje y sus etiquetas.

```python
# Posiciones de marcas personalizadas
plt.xticks([0, 2, 4, 6, 8, 10])
plt.yticks(np.arange(0, 101, 10))

# Etiquetas de marcas personalizadas
plt.xticks([0, 1, 2, 3], ['Ene', 'Feb', 'Mar', 'Abr'])

# Rotar etiquetas de marcas
plt.xticks(rotation=45)

# Eliminar marcas
plt.xticks([])
plt.yticks([])
```

### Relación de Aspecto: `plt.axis()`

Controle la relación de aspecto y la apariencia de los ejes.

```python
# Relación de aspecto igual
plt.axis('equal')
# Gráfico cuadrado
plt.axis('square')
# Desactivar eje
plt.axis('off')
# Relación de aspecto personalizada
plt.gca().set_aspect('equal', adjustable='box')
```

### Tamaño de Figura: `plt.figure()`

Controle el tamaño y la resolución general de sus gráficos.

```python
# Establecer tamaño de figura (ancho, alto en pulgadas)
plt.figure(figsize=(10, 6))

# DPI alto para mejor calidad
plt.figure(figsize=(8, 6), dpi=300)

# Múltiples figuras
fig1 = plt.figure(1)
plt.plot(x, y1)
fig2 = plt.figure(2)
plt.plot(x, y2)
```

### Diseño Ajustado: `plt.tight_layout()`

Ajuste automáticamente el espaciado de los subgráficos para una mejor apariencia.

```python
# Evitar elementos superpuestos
plt.tight_layout()

# Ajuste manual del espaciado
plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)

# Relleno alrededor de los subgráficos
plt.tight_layout(pad=3.0)
```

### Hojas de Estilo: `plt.style.use()`

Aplique estilos predefinidos para una apariencia de gráfico consistente.

```python
# Estilos disponibles
print(plt.style.available)

# Usar estilos integrados
plt.style.use('seaborn-v0_8')
plt.style.use('ggplot')
plt.style.use('bmh')

# Restablecer al predeterminado
plt.style.use('default')
```

## Subgráficos y Múltiples Gráficos

### Subgráficos Básicos: `plt.subplot()` / `plt.subplots()`

Cree múltiples gráficos en una sola figura.

```python
# Crear cuadrícula de subgráficos de 2x2
fig, axes = plt.subplots(2, 2, figsize=(10, 8))

# Trazar en cada subgráfico
axes[0, 0].plot(x, y)
axes[0, 1].scatter(x, y)
axes[1, 0].bar(x, y)
axes[1, 1].hist(y, bins=10)

# Sintaxis alternativa
plt.subplot(2, 2, 1)  # 2 filas, 2 columnas, 1er subgráfico
plt.plot(x, y)
plt.subplot(2, 2, 2)  # 2do subgráfico
plt.scatter(x, y)
```

### Ejes Compartidos: `sharex` / `sharey`

Vincule los ejes a través de los subgráficos para una escala consistente.

```python
# Compartir eje x a través de subgráficos
fig, axes = plt.subplots(2, 1, sharex=True)
axes[0].plot(x, y1)
axes[1].plot(x, y2)

# Compartir ambos ejes
fig, axes = plt.subplots(2, 2, sharex=True, sharey=True)
```

### GridSpec: Diseños Avanzados

Cree arreglos complejos de subgráficos con tamaños variables.

```python
import matplotlib.gridspec as gridspec

# Crear cuadrícula personalizada
gs = gridspec.GridSpec(3, 3)
fig = plt.figure(figsize=(10, 8))

# Subgráficos de diferentes tamaños
ax1 = fig.add_subplot(gs[0, :])  # Fila superior, todas las columnas
ax2 = fig.add_subplot(gs[1, :-1])  # Fila media, primeras 2 columnas
ax3 = fig.add_subplot(gs[1:, -1])  # Última columna, últimas 2 filas
ax4 = fig.add_subplot(gs[-1, 0])   # Esquina inferior izquierda
ax5 = fig.add_subplot(gs[-1, 1])   # Centro inferior
```

### Espaciado de Subgráficos: `hspace` / `wspace`

Controle el espaciado entre subgráficos.

```python
# Ajustar espaciado al crear subgráficos
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
plt.subplots_adjust(hspace=0.4, wspace=0.3)

# O usar tight_layout para ajuste automático
plt.tight_layout()
```

## Tipos de Visualización Avanzados

### Mapas de Calor (Heatmaps): `plt.imshow()` / `plt.pcolormesh()`

Visualice datos 2D como matrices codificadas por color.

```python
# Mapa de calor básico
data = np.random.randn(10, 10)
plt.imshow(data, cmap='viridis')
plt.colorbar()

# Pcolormesh para cuadrículas irregulares
x = np.linspace(0, 10, 11)
y = np.linspace(0, 5, 6)
X, Y = np.meshgrid(x, y)
Z = np.sin(X) * np.cos(Y)
plt.pcolormesh(X, Y, Z, shading='auto')
plt.colorbar()
```

### Gráficos de Contorno: `plt.contour()` / `plt.contourf()`

Muestre curvas de nivel y regiones de contorno rellenas.

```python
# Líneas de contorno
x = np.linspace(-3, 3, 100)
y = np.linspace(-3, 3, 100)
X, Y = np.meshgrid(x, y)
Z = X**2 + Y**2
plt.contour(X, Y, Z, levels=10)
plt.clabel(plt.contour(X, Y, Z), inline=True, fontsize=8)

# Contornos rellenos
plt.contourf(X, Y, Z, levels=20, cmap='RdBu')
plt.colorbar()
```

### Gráficos 3D: `mplot3d`

Cree visualizaciones tridimensionales.

```python
from mpl_toolkits.mplot3d import Axes3D

fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# Dispersión 3D
ax.scatter(x, y, z)

# Gráfico de superficie 3D
ax.plot_surface(X, Y, Z, cmap='viridis')

# Gráfico de línea 3D
ax.plot(x, y, z)
```

### Barras de Error: `plt.errorbar()`

Muestre datos con mediciones de incertidumbre.

```python
# Barras de error básicas
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
yerr = [0.5, 0.8, 0.3, 0.7, 0.4]
plt.errorbar(x, y, yerr=yerr, fmt='o-', capsize=5)

# Barras de error asimétricas
yerr_lower = [0.4, 0.6, 0.2, 0.5, 0.3]
yerr_upper = [0.6, 1.0, 0.4, 0.9, 0.5]
plt.errorbar(x, y, yerr=[yerr_lower, yerr_upper], fmt='s-')
```

### Rellenar Entre: `plt.fill_between()`

Sombrear áreas entre curvas o alrededor de líneas.

```python
# Rellenar entre dos curvas
y1 = [2, 4, 6, 8, 10]
y2 = [1, 3, 5, 7, 9]
plt.fill_between(x, y1, y2, alpha=0.3, color='blue')

# Rellenar alrededor de una línea con error
plt.plot(x, y, 'k-', linewidth=2)
plt.fill_between(x, y-yerr, y+yerr, alpha=0.2, color='gray')
```

### Gráficos de Violín: Alternativa a los Box Plots

Muestran la forma de la distribución junto con los cuartiles.

```python
# Usando pyplot
parts = plt.violinplot([data1, data2, data3])

# Personalizar colores
for pc in parts['bodies']:
    pc.set_facecolor('lightblue')
    pc.set_alpha(0.7)
```

## Funciones Interactivas y de Animación

### Backend Interactivo: `%matplotlib widget`

Habilita gráficos interactivos en cuadernos Jupyter.

```python
# En cuaderno Jupyter
%matplotlib widget

# O para interactividad básica
%matplotlib notebook
```

### Manejo de Eventos: Ratón y Teclado

Responda a las interacciones del usuario con los gráficos.

```python
# Zoom interactivo, paneo y pasar el ratón por encima
def onclick(event):
    if event.inaxes:
        print(f'Haga clic en x={event.xdata}, y={event.ydata}')

fig, ax = plt.subplots()
ax.plot(x, y)
fig.canvas.mpl_connect('button_press_event', onclick)
plt.show()
```

### Animaciones: `matplotlib.animation`

Cree gráficos animados para series temporales o datos cambiantes.

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

# Guardar animación
# ani.save('animation.gif', writer='pillow')
```

## Guardar y Exportar Gráficos

### Guardar Figura: `plt.savefig()`

Exporte gráficos a archivos de imagen con varias opciones.

```python
# Guardar básico
plt.savefig('mi_grafico.png')

# Guardar de alta calidad
plt.savefig('grafico.png', dpi=300, bbox_inches='tight')

# Diferentes formatos
plt.savefig('grafico.pdf')  # PDF
plt.savefig('grafico.svg')  # SVG (vectorial)
plt.savefig('grafico.eps')  # EPS

# Fondo transparente
plt.savefig('grafico.png', transparent=True)
```

### Calidad de la Figura: DPI y Tamaño

Controle la resolución y las dimensiones de los gráficos guardados.

```python
# DPI alto para publicaciones
plt.savefig('grafico.png', dpi=600)

# Tamaño personalizado (ancho, alto en pulgadas)
plt.figure(figsize=(12, 8))
plt.savefig('grafico.png', figsize=(12, 8))

# Recortar espacio en blanco
plt.savefig('grafico.png', bbox_inches='tight', pad_inches=0.1)
```

### Exportación por Lotes y Gestión de Memoria

Maneje múltiples gráficos y la eficiencia de la memoria.

```python
# Cerrar figuras para liberar memoria
plt.close()  # Cerrar figura actual
plt.close('all')  # Cerrar todas las figuras

# Administrador de contexto para limpieza automática
with plt.figure() as fig:
    plt.plot(x, y)
    plt.savefig('grafico.png')

# Guardar por lotes múltiples gráficos
for i, data in enumerate(datasets):
    plt.figure()
    plt.plot(data)
    plt.savefig(f'grafico_{i}.png')
    plt.close()
```

## Configuración y Mejores Prácticas

### Parámetros RC: `plt.rcParams`

Establezca el estilo y el comportamiento predeterminados para todos los gráficos.

```python
# Parámetros rc comunes
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 12
plt.rcParams['lines.linewidth'] = 2
plt.rcParams['axes.grid'] = True

# Guardar y restaurar configuración
original_params = plt.rcParams.copy()
# ... hacer cambios ...
plt.rcParams.update(original_params)  # Restaurar
```

### Gestión de Color: Mapas de Color y Paletas

Trabaje eficazmente con colores y mapas de color.

```python
# Listar mapas de color disponibles
print(plt.colormaps())

# Usar mapa de color para múltiples líneas
colors = plt.cm.viridis(np.linspace(0, 1, len(datasets)))
for i, (data, color) in enumerate(zip(datasets, colors)):
    plt.plot(data, color=color, label=f'Conjunto de Datos {i+1}')

# Mapa de color personalizado
from matplotlib.colors import LinearSegmentedColormap
custom_cmap = LinearSegmentedColormap.from_list('custom', ['red', 'yellow', 'blue'])
```

### Optimización del Rendimiento

Mejore el rendimiento del trazado para conjuntos de datos grandes.

```python
# Usar blitting para animaciones
ani = FuncAnimation(fig, animate, blit=True)

# Rasterizar gráficos complejos
plt.plot(x, y, rasterized=True)

# Reducir puntos de datos para conjuntos de datos grandes
# Submuestrear datos antes de trazar
indices = np.arange(0, len(large_data), step=10)
plt.plot(large_data[indices])
```

### Uso de Memoria: Trazado Eficiente

Administre la memoria al crear muchos gráficos o visualizaciones grandes.

```python
# Limpiar ejes en lugar de crear nuevas figuras
fig, ax = plt.subplots()
for data in datasets:
    ax.clear()  # Limpiar gráfico anterior
    ax.plot(data)
    plt.savefig(f'grafico_{i}.png')

# Usar generadores para conjuntos de datos grandes
def data_generator():
    for i in range(1000):
        yield np.random.randn(100)

for i, data in enumerate(data_generator()):
    if i > 10:  # Limitar el número de gráficos
        break
```

## Integración con Librerías de Datos

### Integración con Pandas: Trazado Directo

Use métodos de DataFrame de Pandas para trazar.

```python
import pandas as pd

# Trazado de DataFrame (usa el backend de matplotlib)
df.plot(kind='line', x='date', y='value')
df.plot.scatter(x='x_col', y='y_col')
df.plot.hist(bins=30)
df.plot.box()

# Acceder a los objetos matplotlib subyacentes
ax = df.plot(kind='line')
ax.set_title('Título Personalizado')
plt.show()
```

### Integración con NumPy: Visualización de Arreglos

Trace eficientemente arreglos de NumPy y funciones matemáticas.

```python
# Visualización de arreglo 2D
arr = np.random.rand(10, 10)
plt.imshow(arr, cmap='hot', interpolation='nearest')

# Funciones matemáticas
x = np.linspace(0, 4*np.pi, 1000)
y = np.sin(x) * np.exp(-x/10)
plt.plot(x, y)

# Distribuciones estadísticas
data = np.random.normal(0, 1, 10000)
plt.hist(data, bins=50, density=True, alpha=0.7)
```

### Integración con Seaborn: Estilo Mejorado

Combine Matplotlib con Seaborn para mejores estéticas predeterminadas.

```python
import seaborn as sns

# Usar estilo seaborn con matplotlib
sns.set_style('whitegrid')
plt.plot(x, y)
plt.show()

# Mezclar seaborn y matplotlib
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
sns.scatterplot(data=df, x='x', y='y', ax=axes[0,0])
plt.plot(x, y, ax=axes[0,1])  # Matplotlib puro
```

### Integración con Jupyter: Trazado en Línea

Optimice Matplotlib para entornos de cuadernos Jupyter.

```python
# Comandos mágicos para Jupyter
%matplotlib inline  # Gráficos estáticos
%matplotlib widget  # Gráficos interactivos

# Pantallas de alta resolución (DPI)
%config InlineBackend.figure_format = 'retina'

# Tamaño de figura automático
%matplotlib inline
plt.rcParams['figure.dpi'] = 100
```

## Instalación y Configuración del Entorno

### Pip: `pip install matplotlib`

Instalador de paquetes estándar de Python para Matplotlib.

```bash
# Instalar Matplotlib
pip install matplotlib

# Actualizar a la última versión
pip install matplotlib --upgrade

# Instalar con backends adicionales
pip install matplotlib[qt5]

# Mostrar información del paquete
pip show matplotlib
```

### Conda: `conda install matplotlib`

Gestor de paquetes para entornos Anaconda/Miniconda.

```bash
# Instalar en el entorno actual
conda install matplotlib

# Actualizar matplotlib
conda update matplotlib

# Crear entorno con matplotlib
conda create -n dataviz matplotlib numpy pandas

# Listar información de matplotlib
conda list matplotlib
```

### Configuración del Backend

Configure los backends de visualización para diferentes entornos.

```python
# Verificar backends disponibles
import matplotlib
print(matplotlib.get_backend())

# Establecer backend programáticamente
matplotlib.use('TkAgg')  # Para Tkinter
matplotlib.use('Qt5Agg')  # Para PyQt5

# Para servidores sin cabeza (headless)
matplotlib.use('Agg')

# Importar después de establecer el backend
import matplotlib.pyplot as plt
```

## Enlaces Relevantes

- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/numpy">Hoja de Trucos de NumPy</router-link>
- <router-link to="/pandas">Hoja de Trucos de Pandas</router-link>
- <router-link to="/sklearn">Hoja de Trucos de scikit-learn</router-link>
- <router-link to="/datascience">Hoja de Trucos de Ciencia de Datos</router-link>

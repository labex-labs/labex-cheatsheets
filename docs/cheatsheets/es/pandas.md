---
title: 'Hoja de Trucos de Pandas | LabEx'
description: 'Aprenda manipulación de datos con Pandas con esta hoja de trucos completa. Referencia rápida para operaciones de DataFrame, limpieza de datos, filtrado, agrupación, fusión y análisis de datos en Python.'
pdfUrl: '/cheatsheets/pdf/pandas-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Pandas
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/pandas">Aprende Pandas con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda manipulación de datos con Pandas a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Pandas que cubren operaciones esenciales, limpieza de datos, análisis y visualización. Aprenda a trabajar con DataFrames, manejar datos faltantes, realizar agregaciones y analizar conjuntos de datos de manera eficiente utilizando la potente biblioteca de análisis de datos de Python.
</base-disclaimer-content>
</base-disclaimer>

## Carga y Guardado de Datos

### Leer CSV: `pd.read_csv()`

Cargar datos desde un archivo CSV a un DataFrame.

```python
import pandas as pd
# Leer un archivo CSV
df = pd.read_csv('data.csv')
# Establecer la primera columna como índice
df = pd.read_csv('data.csv', index_col=0)
# Especificar un separador diferente
df = pd.read_csv('data.csv', sep=';')
# Analizar fechas
df = pd.read_csv('data.csv', parse_dates=['Date'])
```

<BaseQuiz id="pandas-read-csv-1" correct="B">
  <template #question>
    ¿Qué devuelve <code>pd.read_csv('data.csv')</code>?
  </template>
  
  <BaseQuizOption value="A">Una lista de diccionarios</BaseQuizOption>
  <BaseQuizOption value="B" correct>Un DataFrame de pandas</BaseQuizOption>
  <BaseQuizOption value="C">Un array de NumPy</BaseQuizOption>
  <BaseQuizOption value="D">Una cadena de texto</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>pd.read_csv()</code> lee un archivo CSV y devuelve un DataFrame de pandas, que es una estructura de datos bidimensional etiquetada con columnas y filas.
  </BaseQuizAnswer>
</BaseQuiz>

### Leer Excel: `pd.read_excel()`

Cargar datos desde un archivo de Excel.

```python
# Leer la primera hoja
df = pd.read_excel('data.xlsx')
# Leer hoja específica
df = pd.read_excel('data.xlsx', sheet_name='Sheet2')
# Establecer la fila 2 como encabezado (índice 0)
df = pd.read_excel('data.xlsx', header=1)
```

### Leer SQL: `pd.read_sql()`

Leer una consulta SQL o tabla en un DataFrame.

```python
from sqlalchemy import create_engine
engine = create_engine('sqlite:///my_database.db')
df = pd.read_sql('SELECT * FROM users', engine)
df = pd.read_sql_table('products', engine)
```

### Guardar CSV: `df.to_csv()`

Escribir DataFrame a un archivo CSV.

```python
# Excluir la columna de índice
df.to_csv('output.csv', index=False)
# Excluir la fila de encabezado
df.to_csv('output.csv', header=False)
```

### Guardar Excel: `df.to_excel()`

Escribir DataFrame a un archivo de Excel.

```python
# Guardar en Excel
df.to_excel('output.xlsx', sheet_name='Results')
writer = pd.ExcelWriter('output.xlsx')
df1.to_excel(writer, sheet_name='Sheet1')
df2.to_excel(writer, sheet_name='Sheet2')
writer.save()
```

### Guardar SQL: `df.to_sql()`

Escribir DataFrame a una tabla de base de datos SQL.

```python
# Crear/reemplazar tabla
df.to_sql('new_table', engine, if_exists='replace', index=False)
# Añadir a tabla existente
df.to_sql('existing_table', engine, if_exists='append')
```

## Información y Estructura del DataFrame

### Información Básica: `df.info()`

Imprime un resumen conciso de un DataFrame, incluyendo tipos de datos y valores no nulos.

```python
# Mostrar resumen del DataFrame
df.info()
# Mostrar tipos de datos de cada columna
df.dtypes
# Obtener el número de filas y columnas (tupla)
df.shape
# Obtener nombres de columnas
df.columns
# Obtener índice de filas
df.index
```

### Estadísticas Descriptivas: `df.describe()`

Genera estadísticas descriptivas de las columnas numéricas.

```python
# Estadísticas resumidas para columnas numéricas
df.describe()
# Resumen para una columna específica
df['column'].describe()
# Incluir todas las columnas (también tipo objeto)
df.describe(include='all')
```

### Ver Datos: `df.head()` / `df.tail()`

Mostrar las primeras o últimas 'n' filas del DataFrame.

```python
# Primeras 5 filas
df.head()
# Últimas 10 filas
df.tail(10)
# 5 filas aleatorias
df.sample(5)
```

## Limpieza y Transformación de Datos

### Valores Faltantes: `isnull()` / `fillna()` / `dropna()`

Identificar, rellenar o eliminar valores faltantes (NaN).

```python
# Contar valores faltantes por columna
df.isnull().sum()
# Rellenar todos los NaN con 0
df.fillna(0)
# Rellenar con la media de la columna
df['col'].fillna(df['col'].mean())
# Eliminar filas con cualquier NaN
df.dropna()
# Eliminar columnas con cualquier NaN
df.dropna(axis=1)
```

<BaseQuiz id="pandas-missing-1" correct="B">
  <template #question>
    ¿Qué hace <code>df.dropna(axis=1)</code>?
  </template>
  
  <BaseQuizOption value="A">Elimina filas con valores faltantes</BaseQuizOption>
  <BaseQuizOption value="B" correct>Elimina columnas con valores faltantes</BaseQuizOption>
  <BaseQuizOption value="C">Rellena valores faltantes con 0</BaseQuizOption>
  <BaseQuizOption value="D">Cuenta valores faltantes</BaseQuizOption>
  
  <BaseQuizAnswer>
    El parámetro <code>axis=1</code> significa "columnas", por lo que <code>df.dropna(axis=1)</code> elimina las columnas que contienen cualquier valor faltante. Use <code>axis=0</code> (predeterminado) para eliminar filas.
  </BaseQuizAnswer>
</BaseQuiz>

### Duplicados: `duplicated()` / `drop_duplicates()`

Identificar y eliminar filas duplicadas.

```python
# Serie booleana que indica duplicados
df.duplicated()
# Eliminar todas las filas duplicadas
df.drop_duplicates()
# Eliminar basado en columnas específicas
df.drop_duplicates(subset=['col1', 'col2'])
```

<BaseQuiz id="pandas-duplicates-1" correct="A">
  <template #question>
    ¿Qué hace <code>df.drop_duplicates()</code> por defecto?
  </template>
  
  <BaseQuizOption value="A" correct>Elimina filas duplicadas, conservando la primera ocurrencia</BaseQuizOption>
  <BaseQuizOption value="B">Elimina todas las filas</BaseQuizOption>
  <BaseQuizOption value="C">Conserva solo las filas duplicadas</BaseQuizOption>
  <BaseQuizOption value="D">Elimina la primera ocurrencia de duplicados</BaseQuizOption>
  
  <BaseQuizAnswer>
    Por defecto, <code>drop_duplicates()</code> conserva la primera ocurrencia de cada fila duplicada y elimina las subsiguientes. Puede usar <code>keep='last'</code> para conservar la última ocurrencia en su lugar.
  </BaseQuizAnswer>
</BaseQuiz>

### Tipos de Datos: `astype()`

Cambiar el tipo de dato de una columna.

```python
# Cambiar a entero
df['col'].astype(int)
# Cambiar a cadena de texto
df['col'].astype(str)
# Convertir a fecha y hora
df['col'] = pd.to_datetime(df['col'])
```

### Aplicar Función: `apply()` / `map()` / `replace()`

Aplicar funciones o reemplazar valores en DataFrames/Series.

```python
# Aplicar función lambda a una columna
df['col'].apply(lambda x: x*2)
# Mapear valores usando un diccionario
df['col'].map({'old': 'new'})
# Reemplazar valores
df.replace('old_val', 'new_val')
# Reemplazar múltiples valores
df.replace(['A', 'B'], ['C', 'D'])
```

<BaseQuiz id="pandas-apply-1" correct="A">
  <template #question>
    ¿Qué hace <code>df['col'].apply(lambda x: x*2)</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Aplica una función a cada elemento de la columna, multiplicando cada uno por 2</BaseQuizOption>
  <BaseQuizOption value="B">Multiplica toda la columna por 2 una vez</BaseQuizOption>
  <BaseQuizOption value="C">Reemplaza la columna con 2</BaseQuizOption>
  <BaseQuizOption value="D">Cuenta elementos en la columna</BaseQuizOption>
  
  <BaseQuizAnswer>
    El método <code>apply()</code> aplica una función a cada elemento de una Serie. La función lambda <code>lambda x: x*2</code> multiplica cada valor por 2, devolviendo una nueva Serie con los valores transformados.
  </BaseQuizAnswer>
</BaseQuiz>

## Inspección del DataFrame

### Valores Únicos: `unique()` / `value_counts()`

Explorar valores únicos y sus frecuencias.

```python
# Obtener valores únicos en una columna
df['col'].unique()
# Obtener número de valores únicos
df['col'].nunique()
# Contar ocurrencias de cada valor único
df['col'].value_counts()
# Proporciones de valores únicos
df['col'].value_counts(normalize=True)
```

### Correlación: `corr()` / `cov()`

Calcular correlación y covarianza entre columnas numéricas.

```python
# Correlación por pares de columnas
df.corr()
# Covarianza por pares de columnas
df.cov()
# Correlación entre dos columnas específicas
df['col1'].corr(df['col2'])
```

### Agregaciones: `groupby()` / `agg()`

Agrupar datos por categorías y aplicar funciones de agregación.

```python
# Media para cada categoría
df.groupby('category_col').mean()
# Agrupar por múltiples columnas
df.groupby(['col1', 'col2']).sum()
# Múltiples agregaciones
df.groupby('category_col').agg({'num_col': ['min', 'max', 'mean']})
```

### Tablas de Contingencia: `pd.crosstab()`

Calcular una tabla de frecuencia de dos o más factores.

```python
df.pivot_table(values='sales', index='region', columns='product', aggfunc='sum')
# Tabla de frecuencia simple
pd.crosstab(df['col1'], df['col2'])
# Con sumas de filas/columnas
pd.crosstab(df['col1'], df['col2'], margins=True)
# Con valores agregados
pd.crosstab(df['col1'], df['col2'], values=df['value_col'], aggfunc='mean')
```

## Gestión de Memoria

### Uso de Memoria: `df.memory_usage()`

Mostrar el uso de memoria de cada columna o del DataFrame completo.

```python
# Uso de memoria de cada columna
df.memory_usage()
# Uso total de memoria en bytes
df.memory_usage(deep=True).sum()
# Uso de memoria detallado en la salida de info()
df.info(memory_usage='deep')
```

### Optimizar Tipos de Datos: `astype()`

Reducir la memoria convirtiendo columnas a tipos de datos más pequeños y apropiados.

```python
# Reducir entero
df['int_col'] = df['int_col'].astype('int16')
# Reducir flotante
df['float_col'] = df['float_col'].astype('float32')
# Usar tipo categórico
df['category_col'] = df['category_col'].astype('category')
```

### Archivos Grandes en Fragmentos: `read_csv(chunksize=...)`

Procesar archivos grandes en fragmentos para evitar cargar todo en memoria a la vez.

```python
chunk_iterator = pd.read_csv('large_data.csv', chunksize=10000)
for chunk in chunk_iterator:
    # Procesar cada fragmento
    print(chunk.shape)
# Concatenar fragmentos procesados (si es necesario)
# processed_chunks = []
# for chunk in chunk_iterator:
#    processed_chunks.append(process_chunk(chunk))
# final_df = pd.concat(processed_chunks)
```

## Importación/Exportación de Datos

### Leer JSON: `pd.read_json()`

Cargar datos desde un archivo JSON o URL.

```python
# Leer desde JSON local
df = pd.read_json('data.json')
# Leer desde URL
df = pd.read_json('http://example.com/api/data')
# Leer desde cadena JSON
df = pd.read_json(json_string_data)
```

### Leer HTML: `pd.read_html()`

Analizar tablas HTML desde una URL, cadena o archivo.

```python
tables = pd.read_html('http://www.w3.org/TR/html401/sgml/entities.html')
# Usualmente devuelve una lista de DataFrames
df = tables[0]
```

### A JSON: `df.to_json()`

Escribir DataFrame a formato JSON.

```python
# A archivo JSON
df.to_json('output.json', orient='records', indent=4)
# A cadena JSON
json_str = df.to_json(orient='split')
```

### A HTML: `df.to_html()`

Renderizar DataFrame como una tabla HTML.

```python
# A cadena HTML
html_table_str = df.to_html()
# A archivo HTML
df.to_html('output.html', index=False)
```

### Leer Portapapeles: `pd.read_clipboard()`

Leer texto del portapapeles en un DataFrame.

```python
# Copiar datos de tabla desde web/hoja de cálculo y ejecutar
df = pd.read_clipboard()
```

## Serialización de Datos

### Pickle: `df.to_pickle()` / `pd.read_pickle()`

Serializar/deserializar objetos de Pandas hacia/desde disco.

```python
# Guardar DataFrame como archivo pickle
df.to_pickle('my_dataframe.pkl')
# Cargar DataFrame
loaded_df = pd.read_pickle('my_dataframe.pkl')
```

### HDF5: `df.to_hdf()` / `pd.read_hdf()`

Almacenar/cargar DataFrames usando el formato HDF5, bueno para conjuntos de datos grandes.

```python
# Guardar en HDF5
df.to_hdf('my_data.h5', key='df', mode='w')
# Cargar desde HDF5
loaded_df = pd.read_hdf('my_data.h5', key='df')
```

## Filtrado y Selección de Datos

### Basado en Etiqueta: `df.loc[]` / `df.at[]`

Seleccionar datos por la etiqueta explícita del índice/columnas.

```python
# Seleccionar fila con índice 0
df.loc[0]
# Seleccionar todas las filas para 'col1'
df.loc[:, 'col1']
# Rebanar filas y seleccionar múltiples columnas
df.loc[0:5, ['col1', 'col2']]
# Indexación booleana para filas
df.loc[df['col'] > 5]
# Acceso rápido a escalar por etiqueta
df.at[0, 'col1']
```

### Basado en Posición: `df.iloc[]` / `df.iat[]`

Seleccionar datos por la posición entera del índice/columnas.

```python
# Seleccionar la primera fila por posición
df.iloc[0]
# Seleccionar la primera columna por posición
df.iloc[:, 0]
# Rebanar filas y seleccionar múltiples columnas por posición
df.iloc[0:5, [0, 1]]
# Acceso rápido a escalar por posición
df.iat[0, 0]
```

### Indexación Booleana: `df[condition]`

Filtrar filas basadas en una o más condiciones.

```python
# Filas donde 'col1' es mayor que 10
df[df['col1'] > 10]
# Múltiples condiciones
df[(df['col1'] > 10) & (df['col2'] == 'A')]
# Filas donde 'col1' NO está en la lista
df[~df['col1'].isin([1, 2, 3])]
```

### Consultar Datos: `df.query()`

Filtrar filas usando una expresión de cadena de consulta.

```python
# Equivalente a la indexación booleana
df.query('col1 > 10')
# Consulta compleja
df.query('col1 > 10 and col2 == "A"')
# Usar variables locales con '@'
df.query('col1 in @my_list')
```

## Monitoreo de Rendimiento

### Cronometrar Operaciones: `%%timeit` / `time`

Medir el tiempo de ejecución de código Python/Pandas.

```python
# Comando mágico de Jupyter/IPython para cronometrar una línea/celda
%%timeit
df['col'].apply(lambda x: x*2) # Operación de ejemplo

import time
start_time = time.time()
# Su código Pandas aquí
end_time = time.time()
print(f"Tiempo de ejecución: {end_time - start_time} segundos")
```

### Operaciones Optimizadas: `eval()` / `query()`

Utilice estos métodos para un rendimiento más rápido en DataFrames grandes, especialmente para operaciones elemento a elemento y filtrado.

```python
# Más rápido que `df['col1'] + df['col2']`
df['new_col'] = df.eval('col1 + col2')
# Filtrado más rápido
df_filtered = df.query('col1 > @threshold and col2 == "value"')
```

### Perfilado de Código: `cProfile` / `line_profiler`

Analizar dónde se invierte el tiempo en sus funciones de Python.

```python
import cProfile
def my_pandas_function(df):
    # Operaciones de Pandas
    return df.groupby('col').mean()
cProfile.run('my_pandas_function(df)') # Ejecutar función con cProfile

# Para line_profiler (instalar con pip install line_profiler):
# @profile
# def my_function(df):
#    ...
# %load_ext line_profiler
# %lprun -f my_function my_function(df)
```

## Instalación y Configuración de Pandas

### Pip: `pip install pandas`

Instalador de paquetes estándar de Python.

```python
# Instalar Pandas
pip install pandas
# Actualizar Pandas a la última versión
pip install pandas --upgrade
# Mostrar información del paquete Pandas instalado
pip show pandas
```

### Conda: `conda install pandas`

Administrador de paquetes para entornos Anaconda/Miniconda.

```python
# Instalar Pandas en el entorno conda actual
conda install pandas
# Actualizar Pandas
conda update pandas
# Listar paquete Pandas instalado
conda list pandas
# Crear nuevo entorno con Pandas
conda create -n myenv pandas
```

### Verificar Versión / Importar

Verifique su instalación de Pandas e impórtelo en sus scripts.

```python
# Alias de importación estándar
import pandas as pd
# Comprobar la versión de Pandas instalada
print(pd.__version__)
# Mostrar todas las columnas
pd.set_option('display.max_columns', None)
# Mostrar más filas
pd.set_option('display.max_rows', 100)
```

## Configuración y Ajustes

### Opciones de Visualización: `pd.set_option()`

Controlar cómo se muestran los DataFrames en la consola/Jupyter.

```python
# Máximo de filas a mostrar
pd.set_option('display.max_rows', 50)
# Mostrar todas las columnas
pd.set_option('display.max_columns', None)
# Ancho de la visualización
pd.set_option('display.width', 1000)
# Formatear valores flotantes
pd.set_option('display.float_format', '{:.2f}'.format)
```

### Restablecer Opciones: `pd.reset_option()`

Restablecer una opción específica o todas las opciones a sus valores predeterminados.

```python
# Restablecer opción específica
pd.reset_option('display.max_rows')
# Restablecer todas las opciones al valor predeterminado
pd.reset_option('all')
```

### Obtener Opciones: `pd.get_option()`

Recuperar el valor actual de una opción especificada.

```python
# Obtener la configuración actual de max_rows
print(pd.get_option('display.max_rows'))
```

### Administrador de Contexto: `pd.option_context()`

Establecer opciones temporalmente dentro de una declaración `with`.

```python
with pd.option_context('display.max_rows', 10, 'display.max_columns', 5):
    print(df) # DataFrame mostrado con opciones temporales
print(df) # Las opciones vuelven a sus configuraciones anteriores fuera del bloque
```

## Encadenamiento de Métodos

### Encadenamiento de Operaciones

Aplicar una secuencia de transformaciones a un DataFrame.

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

### Uso de `.pipe()`

Aplicar funciones que toman el DataFrame como su primer argumento, permitiendo pasos personalizados en una cadena.

```python
def custom_filter(df, threshold):
    return df[df['value'] > threshold]

(
    df.pipe(custom_filter, threshold=50)
    .groupby('group')
    .agg(total_value=('value', 'sum'))
)
```

## Enlaces Relevantes

- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/numpy">Hoja de Trucos de NumPy</router-link>
- <router-link to="/matplotlib">Hoja de Trucos de Matplotlib</router-link>
- <router-link to="/sklearn">Hoja de Trucos de scikit-learn</router-link>
- <router-link to="/datascience">Hoja de Trucos de Ciencia de Datos</router-link>
- <router-link to="/mysql">Hoja de Trucos de MySQL</router-link>
- <router-link to="/postgresql">Hoja de Trucos de PostgreSQL</router-link>
- <router-link to="/sqlite">Hoja de Trucos de SQLite</router-link>

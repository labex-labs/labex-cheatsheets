---
title: 'Folha de Cola Pandas'
description: 'Aprenda Pandas com nossa folha de cola abrangente cobrindo comandos essenciais, conceitos e melhores práticas.'
pdfUrl: '/cheatsheets/pdf/pandas-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Pandas Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/pandas">Aprenda Pandas com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda manipulação de dados com Pandas através de laboratórios práticos e cenários do mundo real. LabEx oferece cursos abrangentes de Pandas cobrindo operações essenciais, limpeza de dados, análise e visualização. Aprenda a trabalhar com DataFrames, lidar com dados ausentes, realizar agregações e analisar conjuntos de dados de forma eficiente usando a poderosa biblioteca de análise de dados do Python.
</base-disclaimer-content>
</base-disclaimer>

## Carregamento e Salvamento de Dados

### Ler CSV: `pd.read_csv()`

Carrega dados de um arquivo CSV para um DataFrame.

```python
import pandas as pd
# Ler um arquivo CSV
df = pd.read_csv('data.csv')
# Definir a primeira coluna como índice
df = pd.read_csv('data.csv', index_col=0)
# Especificar um separador diferente
df = pd.read_csv('data.csv', sep=';')
# Analisar datas
df = pd.read_csv('data.csv', parse_dates=['Date'])
```

### Ler Excel: `pd.read_excel()`

Carrega dados de um arquivo Excel.

```python
# Ler a primeira planilha
df = pd.read_excel('data.xlsx')
# Ler planilha específica
df = pd.read_excel('data.xlsx', sheet_name='Sheet2')
# Definir a linha 2 como cabeçalho (indexado em 0)
df = pd.read_excel('data.xlsx', header=1)
```

### Ler SQL: `pd.read_sql()`

Lê uma consulta SQL ou tabela em um DataFrame.

```python
from sqlalchemy import create_engine
engine = create_engine('sqlite:///my_database.db')
df = pd.read_sql('SELECT * FROM users', engine)
df = pd.read_sql_table('products', engine)
```

### Salvar CSV: `df.to_csv()`

Escreve o DataFrame em um arquivo CSV.

```python
# Excluir a coluna de índice
df.to_csv('output.csv', index=False)
# Excluir a linha de cabeçalho
df.to_csv('output.csv', header=False)
```

### Salvar Excel: `df.to_excel()`

Escreve o DataFrame em um arquivo Excel.

```python
# Salvar no Excel
df.to_excel('output.xlsx', sheet_name='Results')
writer = pd.ExcelWriter('output.xlsx')
df1.to_excel(writer, sheet_name='Sheet1')
df2.to_excel(writer, sheet_name='Sheet2')
writer.save()
```

### Salvar SQL: `df.to_sql()`

Escreve o DataFrame em uma tabela de banco de dados SQL.

```python
# Criar/substituir tabela
df.to_sql('new_table', engine, if_exists='replace', index=False)
# Anexar à tabela existente
df.to_sql('existing_table', engine, if_exists='append')
```

## Informações e Estrutura do DataFrame

### Informações Básicas: `df.info()`

Imprime um resumo conciso de um DataFrame, incluindo tipos de dados e valores não nulos.

```python
# Exibir resumo do DataFrame
df.info()
# Mostrar tipos de dados de cada coluna
df.dtypes
# Obter o número de linhas e colunas (tupla)
df.shape
# Obter nomes das colunas
df.columns
# Obter índice das linhas
df.index
```

### Estatísticas Descritivas: `df.describe()`

Gera estatísticas descritivas das colunas numéricas.

```python
# Estatísticas resumidas para colunas numéricas
df.describe()
# Resumo para uma coluna específica
df['column'].describe()
# Incluir todas as colunas (também tipo objeto)
df.describe(include='all')
```

### Visualizar Dados: `df.head()` / `df.tail()`

Exibe as primeiras ou últimas 'n' linhas do DataFrame.

```python
# Primeiras 5 linhas
df.head()
# Últimas 10 linhas
df.tail(10)
# 5 linhas aleatórias
df.sample(5)
```

## Limpeza e Transformação de Dados

### Valores Ausentes: `isnull()` / `fillna()` / `dropna()`

Identifica, preenche ou remove valores ausentes (NaN).

```python
# Contar valores ausentes por coluna
df.isnull().sum()
# Preencher todos os NaN com 0
df.fillna(0)
# Preencher com a média da coluna
df['col'].fillna(df['col'].mean())
# Remover linhas com qualquer NaN
df.dropna()
# Remover colunas com qualquer NaN
df.dropna(axis=1)
```

### Duplicatas: `duplicated()` / `drop_duplicates()`

Identifica e remove linhas duplicadas.

```python
# Série booleana indicando duplicatas
df.duplicated()
# Remover todas as linhas duplicadas
df.drop_duplicates()
# Remover com base em colunas específicas
df.drop_duplicates(subset=['col1', 'col2'])
```

### Tipos de Dados: `astype()`

Altera o tipo de dado de uma coluna.

```python
# Mudar para inteiro
df['col'].astype(int)
# Mudar para string
df['col'].astype(str)
# Converter para datetime
df['col'] = pd.to_datetime(df['col'])
```

### Aplicar Função: `apply()` / `map()` / `replace()`

Aplica funções ou substitui valores em DataFrames/Séries.

```python
# Aplicar função lambda a uma coluna
df['col'].apply(lambda x: x*2)
# Mapear valores usando um dicionário
df['col'].map({'old': 'new'})
# Substituir valores
df.replace('old_val', 'new_val')
# Substituir múltiplos valores
df.replace(['A', 'B'], ['C', 'D'])
```

## Inspeção do DataFrame

### Valores Únicos: `unique()` / `value_counts()`

Explora valores únicos e suas frequências.

```python
# Obter valores únicos em uma coluna
df['col'].unique()
# Obter número de valores únicos
df['col'].nunique()
# Contar ocorrências de cada valor único
df['col'].value_counts()
# Proporções de valores únicos
df['col'].value_counts(normalize=True)
```

### Correlação: `corr()` / `cov()`

Calcula a correlação e covariância entre colunas numéricas.

```python
# Correlação par a par das colunas
df.corr()
# Covariância par a par das colunas
df.cov()
# Correlação entre duas colunas específicas
df['col1'].corr(df['col2'])
```

### Agregações: `groupby()` / `agg()`

Agrupa dados por categorias e aplica funções de agregação.

```python
# Média para cada categoria
df.groupby('category_col').mean()
# Agrupar por múltiplas colunas
df.groupby(['col1', 'col2']).sum()
# Múltiplas agregações
df.groupby('category_col').agg({'num_col': ['min', 'max', 'mean']})
```

### Tabelas de Contingência: `pd.crosstab()`

Calcula uma tabela de frequência de dois ou mais fatores.

```python
df.pivot_table(values='sales', index='region', columns='product', aggfunc='sum')
# Tabela de frequência simples
pd.crosstab(df['col1'], df['col2'])
# Com somas de linha/coluna
pd.crosstab(df['col1'], df['col2'], margins=True)
# Com valores agregados
pd.crosstab(df['col1'], df['col2'], values=df['value_col'], aggfunc='mean')
```

## Gerenciamento de Memória

### Uso de Memória: `df.memory_usage()`

Exibe o uso de memória de cada coluna ou do DataFrame inteiro.

```python
# Uso de memória de cada coluna
df.memory_usage()
# Uso total de memória em bytes
df.memory_usage(deep=True).sum()
# Uso de memória detalhado na saída do info()
df.info(memory_usage='deep')
```

### Otimizar Dtypes: `astype()`

Reduz a memória convertendo colunas para tipos de dados menores e apropriados.

```python
# Downcast de inteiro
df['int_col'] = df['int_col'].astype('int16')
# Downcast de float
df['float_col'] = df['float_col'].astype('float32')
# Usar tipo categórico
df['category_col'] = df['category_col'].astype('category')
```

### Arquivos Grandes em Blocos: `read_csv(chunksize=...)`

Processa arquivos grandes em blocos para evitar carregar tudo na memória de uma vez.

```python
chunk_iterator = pd.read_csv('large_data.csv', chunksize=10000)
for chunk in chunk_iterator:
    # Processar cada bloco
    print(chunk.shape)
# Concatenar blocos processados (se necessário)
# processed_chunks = []
# for chunk in chunk_iterator:
#    processed_chunks.append(process_chunk(chunk))
# final_df = pd.concat(processed_chunks)
```

## Importação/Exportação de Dados

### Ler JSON: `pd.read_json()`

Carrega dados de um arquivo JSON ou URL.

```python
# Ler JSON local
df = pd.read_json('data.json')
# Ler de uma URL
df = pd.read_json('http://example.com/api/data')
# Ler de uma string JSON
df = pd.read_json(json_string_data)
```

### Ler HTML: `pd.read_html()`

Analisa tabelas HTML de uma URL, string ou arquivo.

```python
tables = pd.read_html('http://www.w3.org/TR/html401/sgml/entities.html')
# Geralmente retorna uma lista de DataFrames
df = tables[0]
```

### Para JSON: `df.to_json()`

Escreve o DataFrame no formato JSON.

```python
# Para arquivo JSON
df.to_json('output.json', orient='records', indent=4)
# Para string JSON
json_str = df.to_json(orient='split')
```

### Para HTML: `df.to_html()`

Renderiza o DataFrame como uma tabela HTML.

```python
# Para string HTML
html_table_str = df.to_html()
# Para arquivo HTML
df.to_html('output.html', index=False)
```

### Ler Área de Transferência: `pd.read_clipboard()`

Lê texto da área de transferência para um DataFrame.

```python
# Copie dados de tabela da web/planilha e execute
df = pd.read_clipboard()
```

## Serialização de Dados

### Pickle: `df.to_pickle()` / `pd.read_pickle()`

Serializa/desserializa objetos Pandas para/do disco.

```python
# Salvar DataFrame como um arquivo pickle
df.to_pickle('my_dataframe.pkl')
# Carregar DataFrame
loaded_df = pd.read_pickle('my_dataframe.pkl')
```

### HDF5: `df.to_hdf()` / `pd.read_hdf()`

Armazena/carrega DataFrames usando o formato HDF5, bom para grandes conjuntos de dados.

```python
# Salvar em HDF5
df.to_hdf('my_data.h5', key='df', mode='w')
# Carregar de HDF5
loaded_df = pd.read_hdf('my_data.h5', key='df')
```

## Filtragem e Seleção de Dados

### Baseado em Rótulo: `df.loc[]` / `df.at[]`

Seleciona dados pelo rótulo explícito do índice/colunas.

```python
# Selecionar linha com índice 0
df.loc[0]
# Selecionar todas as linhas para 'col1'
df.loc[:, 'col1']
# Fatiar linhas e selecionar múltiplas colunas
df.loc[0:5, ['col1', 'col2']]
# Indexação booleana para linhas
df.loc[df['col'] > 5]
# Acesso escalar rápido por rótulo
df.at[0, 'col1']
```

### Baseado em Posição: `df.iloc[]` / `df.iat[]`

Seleciona dados pela posição inteira do índice/colunas.

```python
# Selecionar a primeira linha por posição
df.iloc[0]
# Selecionar a primeira coluna por posição
df.iloc[:, 0]
# Fatiar linhas e selecionar múltiplas colunas por posição
df.iloc[0:5, [0, 1]]
# Acesso escalar rápido por posição
df.iat[0, 0]
```

### Indexação Booleana: `df[condition]`

Filtra linhas com base em uma ou mais condições.

```python
# Linhas onde 'col1' é maior que 10
df[df['col1'] > 10]
# Múltiplas condições
df[(df['col1'] > 10) & (df['col2'] == 'A')]
# Linhas onde 'col1' NÃO está na lista
df[~df['col1'].isin([1, 2, 3])]
```

### Consultar Dados: `df.query()`

Filtra linhas usando uma expressão de string de consulta.

```python
# Equivalente à indexação booleana
df.query('col1 > 10')
# Consulta complexa
df.query('col1 > 10 and col2 == "A"')
# Usar variáveis locais com '@'
df.query('col1 in @my_list')
```

## Monitoramento de Desempenho

### Cronometrar Operações: `%%timeit` / `time`

Mede o tempo de execução de código Python/Pandas.

```python
# Comando mágico do Jupyter/IPython para cronometrar uma linha/célula
%%timeit
df['col'].apply(lambda x: x*2) # Operação de exemplo

import time
start_time = time.time()
# Seu código Pandas aqui
end_time = time.time()
print(f"Execution time: {end_time - start_time} seconds")
```

### Operações Otimizadas: `eval()` / `query()`

Utiliza esses métodos para um desempenho mais rápido em DataFrames grandes, especialmente para operações elemento a elemento e filtragem.

```python
# Mais rápido que `df['col1'] + df['col2']`
df['new_col'] = df.eval('col1 + col2')
# Filtragem mais rápida
df_filtered = df.query('col1 > @threshold and col2 == "value"')
```

### Perfilamento de Código: `cProfile` / `line_profiler`

Analisa onde o tempo é gasto nas suas funções Python.

```python
import cProfile
def my_pandas_function(df):
    # Operações Pandas
    return df.groupby('col').mean()
cProfile.run('my_pandas_function(df)') # Executar função com cProfile

# Para line_profiler (instalar com pip install line_profiler):
# @profile
# def my_function(df):
#    ...
# %load_ext line_profiler
# %lprun -f my_function my_function(df)
```

## Instalação e Configuração do Pandas

### Pip: `pip install pandas`

Instalador de pacotes Python padrão.

```python
# Instalar Pandas
pip install pandas
# Atualizar Pandas para a versão mais recente
pip install pandas --upgrade
# Mostrar informações do pacote Pandas instalado
pip show pandas
```

### Conda: `conda install pandas`

Gerenciador de pacotes para ambientes Anaconda/Miniconda.

```python
# Instalar Pandas no ambiente conda atual
conda install pandas
# Atualizar Pandas
conda update pandas
# Listar pacote Pandas instalado
conda list pandas
# Criar novo ambiente com Pandas
conda create -n myenv pandas
```

### Verificar Versão / Importar

Verifique sua instalação do Pandas e importe-o em seus scripts.

```python
# Alias de importação padrão
import pandas as pd
# Verificar a versão do Pandas instalada
print(pd.__version__)
# Exibir todas as colunas
pd.set_option('display.max_columns', None)
# Exibir mais linhas
pd.set_option('display.max_rows', 100)
```

## Opções de Configuração

### Opções de Exibição: `pd.set_option()`

Controla como os DataFrames são exibidos no console/Jupyter.

```python
# Máximo de linhas a serem exibidas
pd.set_option('display.max_rows', 50)
# Exibir todas as colunas
pd.set_option('display.max_columns', None)
# Largura da exibição
pd.set_option('display.width', 1000)
# Formatar valores float
pd.set_option('display.float_format', '{:.2f}'.format)
```

### Redefinir Opções: `pd.reset_option()`

Redefine uma opção específica ou todas as opções para seus valores padrão.

```python
# Redefinir opção específica
pd.reset_option('display.max_rows')
# Redefinir todas as opções para o padrão
pd.reset_option('all')
```

### Obter Opções: `pd.get_option()`

Recupera o valor atual de uma opção especificada.

```python
# Obter a configuração atual de max_rows
print(pd.get_option('display.max_rows'))
```

### Gerenciador de Contexto: `pd.option_context()`

Define temporariamente opções dentro de uma instrução `with`.

```python
with pd.option_context('display.max_rows', 10, 'display.max_columns', 5):
    print(df) # DataFrame exibido com opções temporárias
print(df) # As opções retornam às configurações anteriores fora do bloco
```

## Encademanento de Métodos

### Encadear Operações

Aplica uma sequência de transformações a um DataFrame.

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

### Usando `.pipe()`

Aplica funções que recebem o DataFrame como seu primeiro argumento, permitindo etapas personalizadas em uma cadeia.

```python
def custom_filter(df, threshold):
    return df[df['value'] > threshold]

(
    df.pipe(custom_filter, threshold=50)
    .groupby('group')
    .agg(total_value=('value', 'sum'))
)
```

## Links Relevantes

- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/numpy">NumPy Cheatsheet</router-link>
- <router-link to="/matplotlib">Matplotlib Cheatsheet</router-link>
- <router-link to="/sklearn">scikit-learn Cheatsheet</router-link>
- <router-link to="/datascience">Data Science Cheatsheet</router-link>
- <router-link to="/mysql">MySQL Cheatsheet</router-link>
- <router-link to="/postgresql">PostgreSQL Cheatsheet</router-link>
- <router-link to="/sqlite">SQLite Cheatsheet</router-link>

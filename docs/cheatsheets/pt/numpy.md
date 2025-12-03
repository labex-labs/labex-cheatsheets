---
title: 'Folha de Dicas NumPy | LabEx'
description: 'Aprenda computação numérica com NumPy usando esta folha de dicas abrangente. Referência rápida para arrays, álgebra linear, operações matemáticas, broadcasting e computação científica em Python.'
pdfUrl: '/cheatsheets/pdf/numpy-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
NumPy Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/numpy">Aprenda NumPy com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda computação numérica com NumPy através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de NumPy cobrindo operações essenciais de array, funções matemáticas, álgebra linear e otimização de desempenho. Domine a computação numérica eficiente e a manipulação de arrays para fluxos de trabalho de ciência de dados.
</base-disclaimer-content>
</base-disclaimer>

## Criação e Inicialização de Arrays

### A Partir de Listas: `np.array()`

Cria arrays a partir de listas Python ou listas aninhadas.

```python
import numpy as np

# Array 1D a partir de lista
arr = np.array([1, 2, 3, 4])
# Array 2D a partir de listas aninhadas
arr2d = np.array([[1, 2], [3, 4]])
# Especificar tipo de dado
arr = np.array([1, 2, 3], dtype=float)
# Array de strings
arr_str = np.array(['a', 'b', 'c'])
```

<BaseQuiz id="numpy-array-1" correct="C">
  <template #question>
    Qual é a principal vantagem dos arrays NumPy sobre as listas Python?
  </template>
  
  <BaseQuizOption value="A">Eles podem armazenar strings</BaseQuizOption>
  <BaseQuizOption value="B">Eles são mais fáceis de criar</BaseQuizOption>
  <BaseQuizOption value="C" correct>Eles são mais rápidos e eficientes em termos de memória para operações numéricas</BaseQuizOption>
  <BaseQuizOption value="D">Eles podem armazenar tipos de dados mistos</BaseQuizOption>
  
  <BaseQuizAnswer>
    Os arrays NumPy são otimizados para computações numéricas, fornecendo operações mais rápidas e uso de memória mais eficiente em comparação com as listas Python, especialmente para grandes conjuntos de dados e operações matemáticas.
  </BaseQuizAnswer>
</BaseQuiz>

### Zeros e Uns: `np.zeros()` / `np.ones()`

Cria arrays preenchidos com zeros ou uns.

```python
# Array de zeros
zeros = np.zeros(5)  # 1D
zeros2d = np.zeros((3, 4))  # 2D
# Array de uns
ones = np.ones((2, 3))
# Especificar tipo de dado
zeros_int = np.zeros(5, dtype=int)
```

### Matriz Identidade: `np.eye()` / `np.identity()`

Cria matrizes identidade para operações de álgebra linear.

```python
# Matriz identidade 3x3
identity = np.eye(3)
# Método alternativo
identity2 = np.identity(4)
```

### Arrays de Intervalo: `np.arange()` / `np.linspace()`

Cria arrays com valores espaçados uniformemente.

```python
# Semelhante ao range do Python
arr = np.arange(10)  # 0 a 9
arr = np.arange(2, 10, 2)  # 2, 4, 6, 8
# Valores igualmente espaçados
arr = np.linspace(0, 1, 5)  # 5 valores de 0 a 1
# Incluindo o ponto final
arr = np.linspace(0, 10, 11)
```

### Arrays Aleatórios: `np.random`

Gera arrays com valores aleatórios.

```python
# Valores aleatórios entre 0 e 1
rand = np.random.random((2, 3))
# Inteiros aleatórios
rand_int = np.random.randint(0, 10, size=(3, 3))
# Distribuição normal
normal = np.random.normal(0, 1, size=5)
# Definir semente aleatória para reprodutibilidade
np.random.seed(42)
```

### Arrays Especiais: `np.full()` / `np.empty()`

Cria arrays com valores específicos ou não inicializados.

```python
# Preencher com valor específico
full_arr = np.full((2, 3), 7)
# Array vazio (não inicializado)
empty_arr = np.empty((2, 2))
# Semelhante ao formato de array existente
like_arr = np.zeros_like(arr)
```

## Propriedades e Estrutura do Array

### Propriedades Básicas: `shape` / `size` / `ndim`

Obtém informações fundamentais sobre as dimensões e o tamanho do array.

```python
# Dimensões do array (tupla)
arr.shape
# Número total de elementos
arr.size
# Número de dimensões
arr.ndim
# Tipo de dado dos elementos
arr.dtype
# Tamanho de cada elemento em bytes
arr.itemsize
```

### Informações do Array: Uso de Memória

Obtém informações detalhadas sobre o uso de memória e a estrutura do array.

```python
# Uso de memória em bytes
arr.nbytes
# Informações do array (para depuração)
arr.flags
# Verificar se o array possui seus dados
arr.owndata
# Objeto base (se o array for uma visualização)
arr.base
```

### Tipos de Dados: `astype()`

Converte entre diferentes tipos de dados de forma eficiente.

```python
# Converter para tipo diferente
arr.astype(float)
arr.astype(int)
arr.astype(str)
# Tipos mais específicos
arr.astype(np.float32)
arr.astype(np.int16)
```

## Indexação e Fatiamento de Arrays

### Indexação Básica: `arr[index]`

Acessa elementos individuais e fatias.

```python
# Elemento único
arr[0]  # Primeiro elemento
arr[-1]  # Último elemento
# Indexação de array 2D
arr2d[0, 1]  # Linha 0, Coluna 1
arr2d[1]  # Linha 1 inteira
# Fatiamento (Slicing)
arr[1:4]  # Elementos 1 a 3
arr[::2]  # Cada segundo elemento
arr[::-1]  # Array invertido
```

### Indexação Booleana: `arr[condition]`

Filtra arrays com base em condições.

```python
# Condição simples
arr[arr > 5]
# Múltiplas condições
arr[(arr > 2) & (arr < 8)]
arr[(arr < 2) | (arr > 8)]
# Array booleano
mask = arr > 3
filtered = arr[mask]
```

<BaseQuiz id="numpy-boolean-1" correct="C">
  <template #question>
    O que retorna a indexação booleana `arr[arr > 5]`?
  </template>
  
  <BaseQuizOption value="A">Um array booleano</BaseQuizOption>
  <BaseQuizOption value="B">O array original</BaseQuizOption>
  <BaseQuizOption value="C" correct>Um array contendo apenas elementos maiores que 5</BaseQuizOption>
  <BaseQuizOption value="D">Um erro</BaseQuizOption>
  
  <BaseQuizAnswer>
    A indexação booleana filtra o array, retornando apenas os elementos onde a condição é verdadeira. `arr[arr > 5]` retorna um novo array contendo apenas valores maiores que 5.
  </BaseQuizAnswer>
</BaseQuiz>

### Indexação Avançada: Indexação "Fancy"

Usa arrays de índices para acessar múltiplos elementos.

```python
# Índice com array de índices
indices = [0, 2, 4]
arr[indices]
# Indexação "fancy" 2D
arr2d[[0, 1], [1, 2]]  # Elementos (0,1) e (1,2)
# Combinado com fatiamento
arr2d[1:, [0, 2]]
```

### Função Where: `np.where()`

Seleção condicional e substituição de elementos.

```python
# Encontrar índices onde a condição é verdadeira
indices = np.where(arr > 5)
# Substituição condicional
result = np.where(arr > 5, arr, 0)  # Substitui valores >5 por 0
# Múltiplas condições
result = np.where(arr > 5, 'high', 'low')
```

## Manipulação e Remodelagem de Arrays

### Remodelagem: `reshape()` / `resize()` / `flatten()`

Altera as dimensões do array preservando os dados.

```python
# Remodelar (cria visualização se possível)
arr.reshape(2, 3)
arr.reshape(-1, 1)  # -1 significa inferir a dimensão
# Redimensionar (modifica o array original)
arr.resize((2, 3))
# Achatar para 1D
arr.flatten()  # Retorna cópia
arr.ravel()  # Retorna visualização se possível
```

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    O que significa `-1` em `arr.reshape(-1, 1)`?
  </template>
  
  <BaseQuizOption value="A">Cria um erro</BaseQuizOption>
  <BaseQuizOption value="B" correct>O NumPy infere a dimensão automaticamente</BaseQuizOption>
  <BaseQuizOption value="C">Cria um array 1D</BaseQuizOption>
  <BaseQuizOption value="D">Inverte o array</BaseQuizOption>
  
  <BaseQuizAnswer>
    Usar `-1` em reshape diz ao NumPy para calcular automaticamente essa dimensão com base no tamanho total do array e nas outras dimensões especificadas. Isso é útil quando você conhece uma dimensão, mas quer que o NumPy descubra a outra.
  </BaseQuizAnswer>
</BaseQuiz>

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    O que significa `-1` em `arr.reshape(-1, 1)`?
  </template>
  
  <BaseQuizOption value="A">Cria um erro</BaseQuizOption>
  <BaseQuizOption value="B" correct>O NumPy infere a dimensão automaticamente</BaseQuizOption>
  <BaseQuizOption value="C">Remove essa dimensão</BaseQuizOption>
  <BaseQuizOption value="D">Define a dimensão como 1</BaseQuizOption>
  
  <BaseQuizAnswer>
    Usar `-1` em reshape diz ao NumPy para calcular automaticamente essa dimensão com base no tamanho total do array e nas outras dimensões especificadas. Isso é útil quando você conhece uma dimensão, mas quer que o NumPy descubra a outra.
  </BaseQuizAnswer>
</BaseQuiz>

### Transposição: `T` / `transpose()`

Troca os eixos do array para operações de matriz.

```python
# Transposição simples
arr2d.T
# Transposição com especificação de eixos
arr.transpose()
np.transpose(arr)
# Para dimensões maiores
arr3d.transpose(2, 0, 1)
```

### Adicionar/Remover Elementos

Modifica o tamanho do array adicionando ou removendo elementos.

```python
# Anexar elementos
np.append(arr, [4, 5])
# Inserir na posição específica
np.insert(arr, 1, 99)
# Deletar elementos
np.delete(arr, [1, 3])
# Repetir elementos
np.repeat(arr, 3)
np.tile(arr, 2)
```

### Combinando Arrays: `concatenate()` / `stack()`

Junta múltiplos arrays.

```python
# Concatenar ao longo do eixo existente
np.concatenate([arr1, arr2])
np.concatenate([arr1, arr2], axis=1)
# Empilhar arrays (cria novo eixo)
np.vstack([arr1, arr2])  # Verticalmente
np.hstack([arr1, arr2])  # Horizontalmente
np.dstack([arr1, arr2])  # Profundidade
```

## Operações Matemáticas

### Aritmética Básica: `+`, `-`, `*`, `/`

Operações aritméticas elemento a elemento em arrays.

```python
# Operações elemento a elemento
arr1 + arr2
arr1 - arr2
arr1 * arr2  # Multiplicação elemento a elemento
arr1 / arr2
arr1 ** 2  # Elevar ao quadrado
arr1 % 3  # Operação de módulo
```

### Funções Universais (ufuncs)

Aplica funções matemáticas elemento a elemento.

```python
# Funções trigonométricas
np.sin(arr)
np.cos(arr)
np.tan(arr)
# Exponencial e logarítmica
np.exp(arr)
np.log(arr)
np.log10(arr)
# Raiz quadrada e potência
np.sqrt(arr)
np.power(arr, 3)
```

### Funções de Agregação

Calcula estatísticas resumidas ao longo das dimensões do array.

```python
# Estatísticas básicas
np.sum(arr)
np.mean(arr)
np.std(arr)  # Desvio padrão
np.var(arr)  # Variância
np.min(arr)
np.max(arr)
# Ao longo de um eixo específico
np.sum(arr2d, axis=0)  # Soma ao longo das linhas
np.mean(arr2d, axis=1)  # Média ao longo das colunas
```

### Operações de Comparação

Comparações elemento a elemento que retornam arrays booleanos.

```python
# Operadores de comparação
arr > 5
arr == 3
arr != 0
# Comparações de array
np.array_equal(arr1, arr2)
np.allclose(arr1, arr2)  # Dentro da tolerância
# Operações any/all
np.any(arr > 5)
np.all(arr > 0)
```

## Álgebra Linear

### Operações de Matriz: `np.dot()` / `@`

Executa multiplicação de matrizes e produtos escalares.

```python
# Multiplicação de matrizes
np.dot(A, B)
A @ B  # Operador Python 3.5+
# Multiplicação elemento a elemento
A * B
# Potência da matriz
np.linalg.matrix_power(A, 3)
```

### Decomposições: `np.linalg`

Decomposições de matrizes para cálculos avançados.

```python
# Autovalores e autovetores
eigenvals, eigenvecs = np.linalg.eig(A)
# Decomposição de Valor Singular
U, s, Vt = np.linalg.svd(A)
# Decomposição QR
Q, R = np.linalg.qr(A)
```

### Propriedades da Matriz

Calcula características importantes da matriz.

```python
# Determinante
np.linalg.det(A)
# Inversa da matriz
np.linalg.inv(A)
# Pseudo-inversa
np.linalg.pinv(A)
# Posto da matriz
np.linalg.matrix_rank(A)
# Traço (soma da diagonal)
np.trace(A)
```

### Solução de Sistemas Lineares: `np.linalg.solve()`

Resolve sistemas de equações lineares.

```python
# Resolver Ax = b
x = np.linalg.solve(A, b)
# Solução de mínimos quadrados
x = np.linalg.lstsq(A, b, rcond=None)[0]
```

## Entrada/Saída de Array

### Binário NumPy: `np.save()` / `np.load()`

Formato binário eficiente para arrays NumPy.

```python
# Salvar array único
np.save('array.npy', arr)
# Carregar array
loaded_arr = np.load('array.npy')
# Salvar múltiplos arrays
np.savez('arrays.npz', a=arr1, b=arr2)
# Carregar múltiplos arrays
data = np.load('arrays.npz')
arr1_loaded = data['a']
```

### Arquivos de Texto: `np.loadtxt()` / `np.savetxt()`

Lê e escreve arrays como arquivos de texto.

```python
# Carregar de arquivo CSV/texto
arr = np.loadtxt('data.csv', delimiter=',')
# Pular linha de cabeçalho
arr = np.loadtxt('data.csv', delimiter=',', skiprows=1)
# Salvar em arquivo de texto
np.savetxt('output.csv', arr, delimiter=',', fmt='%.2f')
```

### Dados Estruturados CSV: `np.genfromtxt()`

Leitura avançada de arquivos de texto com tratamento de dados ausentes.

```python
# Lidar com valores ausentes
arr = np.genfromtxt('data.csv', delimiter=',',
                    missing_values='N/A', filling_values=0)
# Colunas nomeadas
data = np.genfromtxt('data.csv', delimiter=',',
                     names=True, dtype=None)
```

### Mapeamento de Memória: `np.memmap()`

Trabalha com arrays grandes demais para caber na memória.

```python
# Criar array mapeado em memória
mmap_arr = np.memmap('large_array.dat', dtype='float32',
                     mode='w+', shape=(1000000,))
# Acessar como array regular, mas armazenado em disco
mmap_arr[0:10] = np.random.random(10)
```

## Desempenho e Broadcasting

### Regras de Broadcasting

Entender como o NumPy lida com operações em arrays de formas diferentes.

```python
# Exemplos de Broadcasting
arr1 = np.array([[1, 2, 3]])  # Forma (1, 3)
arr2 = np.array([[1], [2]])   # Forma (2, 1)
result = arr1 + arr2          # Forma (2, 3)
# Broadcasting escalar
arr + 5  # Adiciona 5 a todos os elementos
arr * 2  # Multiplica todos os elementos por 2
```

### Operações Vetorizadas

Use funções internas do NumPy em vez de loops Python.

```python
# Em vez de loops, use operações vetorizadas
# Ruim: loop for
result = []
for x in arr:
    result.append(x ** 2)
# Bom: vetorizado
result = arr ** 2
# Função vetorizada personalizada
def custom_func(x):
    return x ** 2 + 2 * x + 1
vec_func = np.vectorize(custom_func)
result = vec_func(arr)
```

### Otimização de Memória

Técnicas para uso eficiente da memória com arrays grandes.

```python
# Usar tipos de dados apropriados
arr_int8 = arr.astype(np.int8)  # 1 byte por elemento
arr_float32 = arr.astype(np.float32)  # 4 bytes vs 8 para float64
# Visualizações vs Cópias
view = arr[::2]  # Cria visualização (compartilha memória)
copy = arr[::2].copy()  # Cria cópia (nova memória)
# Verificar se o array é visualização ou cópia
view.base is arr  # Verdadeiro para visualização
```

### Dicas de Desempenho

Melhores práticas para código NumPy rápido.

```python
# Usar operações in-place quando possível
arr += 5  # Em vez de arr = arr + 5
np.add(arr, 5, out=arr)  # Explícito in-place
# Minimizar a criação de arrays
# Ruim: cria arrays intermediários
result = ((arr + 1) * 2) ** 2
# Melhor: usar operações compostas quando possível
```

## Geração de Números Aleatórios

### Aleatório Básico: `np.random`

Gera números aleatórios de várias distribuições.

```python
# Floats aleatórios [0, 1)
np.random.random(5)
# Inteiros aleatórios
np.random.randint(0, 10, size=5)
# Distribuição normal
np.random.normal(mu=0, sigma=1, size=5)
# Distribuição uniforme
np.random.uniform(-1, 1, size=5)
```

### Amostragem: `choice()` / `shuffle()`

Amostra de dados existentes ou permuta arrays.

```python
# Escolha aleatória do array
np.random.choice(arr, size=3)
# Sem reposição
np.random.choice(arr, size=3, replace=False)
# Embaralha o array in-place
np.random.shuffle(arr)
# Permutação aleatória
np.random.permutation(arr)
```

### Sementes e Geradores

Controla a aleatoriedade para resultados reprodutíveis.

```python
# Definir semente para reprodutibilidade
np.random.seed(42)
# Abordagem moderna: Gerador
rng = np.random.default_rng(42)
rng.random(5)
rng.integers(0, 10, size=5)
rng.normal(0, 1, size=5)
```

## Funções Estatísticas

### Estatísticas Descritivas

Medidas básicas de tendência central e dispersão.

```python
# Tendência central
np.mean(arr)
np.median(arr)
# Medidas de dispersão
np.std(arr)  # Desvio padrão
np.var(arr)  # Variância
np.ptp(arr)  # Pico a pico (máx - mín)
# Percentis
np.percentile(arr, [25, 50, 75])
np.quantile(arr, [0.25, 0.5, 0.75])
```

### Correlação e Covariância

Mede as relações entre variáveis.

```python
# Coeficiente de correlação
np.corrcoef(x, y)
# Covariância
np.cov(x, y)
# Correlação cruzada
np.correlate(x, y, mode='full')
```

### Histograma e Agrupamento (Binning)

Analisa a distribuição de dados e cria grupos.

```python
# Histograma
counts, bins = np.histogram(arr, bins=10)
# Histograma 2D
H, xedges, yedges = np.histogram2d(x, y, bins=10)
# Digitalizar (atribuir índices de grupo)
bin_indices = np.digitize(arr, bins)
```

### Funções Estatísticas Especiais

Cálculos estatísticos avançados.

```python
# Estatísticas ponderadas
np.average(arr, weights=weights)
# Valores únicos e contagens
unique_vals, counts = np.unique(arr, return_counts=True)
# Bincount (para arrays de inteiros)
np.bincount(int_arr)
```

## Instalação e Configuração do NumPy

### Pip: `pip install numpy`

Instalador de pacotes Python padrão.

```bash
# Instalar NumPy
pip install numpy
# Atualizar para a versão mais recente
pip install numpy --upgrade
# Instalar versão específica
pip install numpy==1.21.0
# Mostrar informações do pacote
pip show numpy
```

### Conda: `conda install numpy`

Gerenciador de pacotes para ambientes Anaconda/Miniconda.

```bash
# Instalar NumPy no ambiente atual
conda install numpy
# Atualizar NumPy
conda update numpy
# Instalar do conda-forge
conda install -c conda-forge numpy
# Criar ambiente com NumPy
conda create -n myenv numpy
```

### Verificar Instalação e Importação

Verifica sua instalação do NumPy e a importação padrão.

```python
# Importação padrão
import numpy as np
# Verificar versão
print(np.__version__)
# Verificar informações de compilação
np.show_config()
# Definir opções de impressão
np.set_printoptions(precision=2, suppress=True)
```

## Recursos Avançados

### Arrays Estruturados

Arrays com campos nomeados para estruturas de dados complexas.

```python
# Definir tipo de dado estruturado
dt = np.dtype([('name', 'U10'), ('age', 'i4'), ('weight', 'f4')])
# Criar array estruturado
people = np.array([('Alice', 25, 55.0), ('Bob', 30, 70.5)], dtype=dt)
# Acessar campos
people['name']
people['age']
```

### Arrays Mascarados: `np.ma`

Lida com arrays com dados ausentes ou inválidos.

```python
# Criar array mascarado
masked_arr = np.ma.array([1, 2, 3, 4, 5], mask=[0, 0, 1, 0, 0])
# Operações ignoram valores mascarados
np.ma.mean(masked_arr)
# Preencher valores mascarados
filled = masked_arr.filled(0)
```

### Polinômios: `np.poly1d`

Trabalha com expressões e operações de polinômios.

```python
# Criar polinômio (coeficientes em ordem decrescente)
p = np.poly1d([1, -2, 1])  # x² - 2x + 1
# Avaliar polinômio
p(5)  # Avaliar em x=5
# Encontrar raízes
np.roots([1, -2, 1])
# Ajuste de polinômio
coeff = np.polyfit(x, y, degree=2)
```

### Transformada Rápida de Fourier: `np.fft`

Análise de domínio de frequência e processamento de sinais.

```python
# FFT 1D
fft_result = np.fft.fft(signal)
# Frequências
freqs = np.fft.fftfreq(len(signal))
# IFFT
reconstructed = np.fft.ifft(fft_result)
# FFT 2D para imagens
fft2d = np.fft.fft2(image)
```

## Links Relevantes

- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/pandas">Pandas Cheatsheet</router-link>
- <router-link to="/matplotlib">Matplotlib Cheatsheet</router-link>
- <router-link to="/sklearn">scikit-learn Cheatsheet</router-link>
- <router-link to="/datascience">Data Science Cheatsheet</router-link>

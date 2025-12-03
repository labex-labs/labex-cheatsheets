---
title: 'Matplotlib Guia Rápido | LabEx'
description: 'Aprenda visualização de dados com Matplotlib usando este guia rápido abrangente. Referência rápida para plotagem, gráficos, subplots, personalização e visualização de dados em Python.'
pdfUrl: '/cheatsheets/pdf/matplotlib-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas Matplotlib
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/matplotlib">Aprenda Matplotlib com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda visualização de dados com Matplotlib através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Matplotlib cobrindo funções essenciais de plotagem, técnicas de personalização, layouts de subplots e tipos de visualização avançados. Domine a criação de visualizações de dados eficazes para fluxos de trabalho de ciência de dados em Python.
</base-disclaimer-content>
</base-disclaimer>

## Plotagem Básica e Tipos de Gráfico

### Gráfico de Linha: `plt.plot()`

Cria gráficos de linha para visualização de dados contínuos.

```python
import matplotlib.pyplot as plt
import numpy as np

# Gráfico de linha básico
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
plt.plot(x, y)
plt.show()

# Múltiplas linhas
plt.plot(x, y, label='Linha 1')
plt.plot(x, [1, 3, 5, 7, 9], label='Linha 2')
plt.legend()

# Estilos de linha e cores
plt.plot(x, y, 'r--', linewidth=2, marker='o')
```

<BaseQuiz id="matplotlib-plot-1" correct="C">
  <template #question>
    O que faz `plt.show()` em Matplotlib?
  </template>
  
  <BaseQuizOption value="A">Salva o gráfico em um arquivo</BaseQuizOption>
  <BaseQuizOption value="B">Fecha a janela do gráfico</BaseQuizOption>
  <BaseQuizOption value="C" correct>Exibe o gráfico em uma janela</BaseQuizOption>
  <BaseQuizOption value="D">Limpa o gráfico</BaseQuizOption>
  
  <BaseQuizAnswer>
    `plt.show()` exibe o gráfico em uma janela interativa. É necessário chamar esta função para ver a visualização. Sem ela, o gráfico não será exibido.
  </BaseQuizAnswer>
</BaseQuiz>

### Gráfico de Dispersão: `plt.scatter()`

Exibe a relação entre duas variáveis.

```python
# Gráfico de dispersão básico
plt.scatter(x, y)

# Com cores e tamanhos diferentes
colors = [1, 2, 3, 4, 5]
sizes = [20, 50, 100, 200, 500]
plt.scatter(x, y, c=colors, s=sizes, alpha=0.6)
plt.colorbar()  # Adiciona barra de cores
```

<BaseQuiz id="matplotlib-scatter-1" correct="D">
  <template #question>
    O que o parâmetro `alpha` controla em gráficos matplotlib?
  </template>
  
  <BaseQuizOption value="A">A cor do gráfico</BaseQuizOption>
  <BaseQuizOption value="B">O tamanho do gráfico</BaseQuizOption>
  <BaseQuizOption value="C">A posição do gráfico</BaseQuizOption>
  <BaseQuizOption value="D" correct>A transparência/opacidade dos elementos do gráfico</BaseQuizOption>
  
  <BaseQuizAnswer>
    O parâmetro `alpha` controla a transparência, com valores de 0 (completamente transparente) a 1 (completamente opaco). É útil para criar visualizações sobrepostas onde se deseja ver através dos elementos.
  </BaseQuizAnswer>
</BaseQuiz>

### Gráfico de Barras: `plt.bar()` / `plt.barh()`

Cria gráficos de barras verticais ou horizontais.

```python
# Barras verticais
categories = ['A', 'B', 'C', 'D']
values = [20, 35, 30, 25]
plt.bar(categories, values)

# Barras horizontais
plt.barh(categories, values)

# Barras agrupadas
x = np.arange(len(categories))
plt.bar(x - 0.2, values, 0.4, label='Grupo 1')
plt.bar(x + 0.2, [15, 25, 35, 20], 0.4, label='Grupo 2')
```

### Histograma: `plt.hist()`

Mostra a distribuição de dados contínuos.

```python
# Histograma básico
data = np.random.randn(1000)
plt.hist(data, bins=30)

# Histograma personalizado
plt.hist(data, bins=50, alpha=0.7, color='skyblue', edgecolor='black')

# Múltiplos histogramas
plt.hist([data1, data2], bins=30, alpha=0.7, label=['Dados 1', 'Dados 2'])
```

### Gráfico de Pizza: `plt.pie()`

Exibe dados proporcionais como um gráfico circular.

```python
# Gráfico de pizza básico
sizes = [25, 35, 20, 20]
labels = ['A', 'B', 'C', 'D']
plt.pie(sizes, labels=labels)

# Gráfico de pizza destacado com porcentagens
explode = (0, 0.1, 0, 0)  # destaca a 2ª fatia
plt.pie(sizes, labels=labels, autopct='%1.1f%%',
        explode=explode, shadow=True, startangle=90)
```

### Gráfico de Caixa: `plt.boxplot()`

Visualiza a distribuição de dados e valores atípicos (outliers).

```python
# Gráfico de caixa único
data = [np.random.randn(100) for _ in range(4)]
plt.boxplot(data)

# Gráfico de caixa personalizado
plt.boxplot(data, labels=['Grupo 1', 'Grupo 2', 'Grupo 3', 'Grupo 4'],
           patch_artist=True, notch=True)
```

## Personalização e Estilo de Plotagem

### Rótulos e Títulos: `plt.xlabel()` / `plt.title()`

Adiciona texto descritivo aos seus gráficos para clareza e contexto.

```python
# Rótulos e título básicos
plt.plot(x, y)
plt.xlabel('Rótulo do Eixo X')
plt.ylabel('Rótulo do Eixo Y')
plt.title('Título do Gráfico')

# Títulos formatados com propriedades de fonte
plt.title('Meu Gráfico', fontsize=16, fontweight='bold')
plt.xlabel('Valores X', fontsize=12)

# Grade para melhor legibilidade
plt.grid(True, alpha=0.3)
```

### Cores e Estilos: `color` / `linestyle` / `marker`

Personaliza a aparência visual dos elementos do gráfico.

```python
# Opções de cor
plt.plot(x, y, color='red')  # Cores nomeadas
plt.plot(x, y, color='#FF5733')  # Cores Hex
plt.plot(x, y, color=(0.1, 0.2, 0.5))  # Tupla RGB

# Estilos de linha
plt.plot(x, y, linestyle='--')  # Tracejado
plt.plot(x, y, linestyle=':')   # Pontilhado
plt.plot(x, y, linestyle='-.')  # Traço-ponto

# Marcadores
plt.plot(x, y, marker='o', markersize=8, markerfacecolor='red')
```

### Legendas e Anotações: `plt.legend()` / `plt.annotate()`

Adiciona legendas e anotações para explicar os elementos do gráfico.

```python
# Legenda básica
plt.plot(x, y1, label='Conjunto de Dados 1')
plt.plot(x, y2, label='Conjunto de Dados 2')
plt.legend()

# Posição da legenda personalizada
plt.legend(loc='upper right', fontsize=10, frameon=False)

# Anotações
plt.annotate('Ponto Importante', xy=(2, 4), xytext=(3, 6),
            arrowprops=dict(arrowstyle='->', color='red'))
```

<BaseQuiz id="matplotlib-legend-1" correct="B">
  <template #question>
    O que é necessário para que `plt.legend()` exiba rótulos?
  </template>
  
  <BaseQuizOption value="A">Nada, funciona automaticamente</BaseQuizOption>
  <BaseQuizOption value="B" correct>Cada plotagem deve ter um parâmetro `label` definido</BaseQuizOption>
  <BaseQuizOption value="C">A legenda deve ser criada antes da plotagem</BaseQuizOption>
  <BaseQuizOption value="D">Os rótulos devem ser definidos manualmente na legenda</BaseQuizOption>
  
  <BaseQuizAnswer>
    Para exibir uma legenda, você precisa definir o parâmetro `label` ao criar cada plotagem (ex: `plt.plot(x, y, label='Conjunto de Dados 1')`). Em seguida, chamar `plt.legend()` exibirá todos os rótulos.
  </BaseQuizAnswer>
</BaseQuiz>

## Controle de Eixos e Layout

### Limites do Eixo: `plt.xlim()` / `plt.ylim()`

Controla o intervalo de valores exibidos em cada eixo.

```python
# Define os limites do eixo
plt.xlim(0, 10)
plt.ylim(-5, 15)

# Ajusta automaticamente os limites com margem
plt.margins(x=0.1, y=0.1)

# Inverte o eixo
plt.gca().invert_yaxis()  # Inverte o eixo y
```

### Marcas e Rótulos dos Eixos: `plt.xticks()` / `plt.yticks()`

Personaliza as marcas de marcação dos eixos e seus rótulos.

```python
# Posições personalizadas das marcas
plt.xticks([0, 2, 4, 6, 8, 10])
plt.yticks(np.arange(0, 101, 10))

# Rótulos personalizados das marcas
plt.xticks([0, 1, 2, 3], ['Jan', 'Fev', 'Mar', 'Abr'])

# Rotaciona os rótulos das marcas
plt.xticks(rotation=45)

# Remove as marcas
plt.xticks([])
plt.yticks([])
```

### Proporção do Eixo: `plt.axis()`

Controla a proporção do eixo e a aparência dos eixos.

```python
# Proporção de aspecto igual
plt.axis('equal')
# Gráfico quadrado
plt.axis('square')
# Desliga o eixo
plt.axis('off')
# Proporção de aspecto personalizada
plt.gca().set_aspect('equal', adjustable='box')
```

### Tamanho da Figura: `plt.figure()`

Controla o tamanho geral e a resolução dos seus gráficos.

```python
# Define o tamanho da figura (largura, altura em polegadas)
plt.figure(figsize=(10, 6))

# DPI alto para melhor qualidade
plt.figure(figsize=(8, 6), dpi=300)

# Múltiplas figuras
fig1 = plt.figure(1)
plt.plot(x, y1)
fig2 = plt.figure(2)
plt.plot(x, y2)
```

### Layout Ajustado: `plt.tight_layout()`

Ajusta automaticamente o espaçamento dos subplots para uma melhor aparência.

```python
# Previne elementos sobrepostos
plt.tight_layout()

# Ajuste manual do espaçamento
plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)

# Preenchimento ao redor dos subplots
plt.tight_layout(pad=3.0)
```

### Folhas de Estilo: `plt.style.use()`

Aplica estilos predefinidos para uma aparência de gráfico consistente.

```python
# Estilos disponíveis
print(plt.style.available)

# Usa estilos internos
plt.style.use('seaborn-v0_8')
plt.style.use('ggplot')
plt.style.use('bmh')

# Restaura para o padrão
plt.style.use('default')
```

## Subplots e Múltiplos Gráficos

### Subplots Básicos: `plt.subplot()` / `plt.subplots()`

Cria múltiplos gráficos em uma única figura.

```python
# Cria uma grade de subplot 2x2
fig, axes = plt.subplots(2, 2, figsize=(10, 8))

# Plota em cada subplot
axes[0, 0].plot(x, y)
axes[0, 1].scatter(x, y)
axes[1, 0].bar(x, y)
axes[1, 1].hist(y, bins=10)

# Sintaxe alternativa
plt.subplot(2, 2, 1)  # 2 linhas, 2 colunas, 1º subplot
plt.plot(x, y)
plt.subplot(2, 2, 2)  # 2º subplot
plt.scatter(x, y)
```

### Eixos Compartilhados: `sharex` / `sharey`

Vincula eixos entre subplots para dimensionamento consistente.

```python
# Compartilha o eixo x entre os subplots
fig, axes = plt.subplots(2, 1, sharex=True)
axes[0].plot(x, y1)
axes[1].plot(x, y2)

# Compartilha ambos os eixos
fig, axes = plt.subplots(2, 2, sharex=True, sharey=True)
```

### GridSpec: Layouts Avançados

Cria arranjos complexos de subplots com tamanhos variados.

```python
import matplotlib.gridspec as gridspec

# Cria grade personalizada
gs = gridspec.GridSpec(3, 3)
fig = plt.figure(figsize=(10, 8))

# Subplots de tamanhos diferentes
ax1 = fig.add_subplot(gs[0, :])  # Linha superior, todas as colunas
ax2 = fig.add_subplot(gs[1, :-1])  # Linha do meio, primeiras 2 colunas
ax3 = fig.add_subplot(gs[1:, -1])  # Última coluna, últimas 2 linhas
ax4 = fig.add_subplot(gs[-1, 0])   # Canto inferior esquerdo
ax5 = fig.add_subplot(gs[-1, 1])   # Meio inferior
```

### Espaçamento de Subplot: `hspace` / `wspace`

Controla o espaçamento entre subplots.

```python
# Ajusta o espaçamento ao criar subplots
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
plt.subplots_adjust(hspace=0.4, wspace=0.3)

# Ou use tight_layout para ajuste automático
plt.tight_layout()
```

## Tipos de Visualização Avançados

### Mapas de Calor: `plt.imshow()` / `plt.pcolormesh()`

Visualiza dados 2D como matrizes codificadas por cores.

```python
# Mapa de calor básico
data = np.random.randn(10, 10)
plt.imshow(data, cmap='viridis')
plt.colorbar()

# Pcolormesh para grades irregulares
x = np.linspace(0, 10, 11)
y = np.linspace(0, 5, 6)
X, Y = np.meshgrid(x, y)
Z = np.sin(X) * np.cos(Y)
plt.pcolormesh(X, Y, Z, shading='auto')
plt.colorbar()
```

### Gráficos de Contorno: `plt.contour()` / `plt.contourf()`

Mostra curvas de nível e regiões de contorno preenchidas.

```python
# Linhas de contorno
x = np.linspace(-3, 3, 100)
y = np.linspace(-3, 3, 100)
X, Y = np.meshgrid(x, y)
Z = X**2 + Y**2
plt.contour(X, Y, Z, levels=10)
plt.clabel(plt.contour(X, Y, Z), inline=True, fontsize=8)

# Contornos preenchidos
plt.contourf(X, Y, Z, levels=20, cmap='RdBu')
plt.colorbar()
```

### Gráficos 3D: `mplot3d`

Cria visualizações tridimensionais.

```python
from mpl_toolkits.mplot3d import Axes3D

fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# Dispersão 3D
ax.scatter(x, y, z)

# Gráfico de superfície 3D
ax.plot_surface(X, Y, Z, cmap='viridis')

# Gráfico de linha 3D
ax.plot(x, y, z)
```

### Barras de Erro: `plt.errorbar()`

Exibe dados com medições de incerteza.

```python
# Barras de erro básicas
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
yerr = [0.5, 0.8, 0.3, 0.7, 0.4]
plt.errorbar(x, y, yerr=yerr, fmt='o-', capsize=5)

# Barras de erro assimétricas
yerr_lower = [0.4, 0.6, 0.2, 0.5, 0.3]
yerr_upper = [0.6, 1.0, 0.4, 0.9, 0.5]
plt.errorbar(x, y, yerr=[yerr_lower, yerr_upper], fmt='s-')
```

### Preencher Entre: `plt.fill_between()`

Sombreia áreas entre curvas ou ao redor de linhas.

```python
# Preenche entre duas curvas
y1 = [2, 4, 6, 8, 10]
y2 = [1, 3, 5, 7, 9]
plt.fill_between(x, y1, y2, alpha=0.3, color='blue')

# Preenche ao redor de uma linha com erro
plt.plot(x, y, 'k-', linewidth=2)
plt.fill_between(x, y-yerr, y+yerr, alpha=0.2, color='gray')
```

### Gráficos de Violino: Alternativa aos Box Plots

Mostra a forma da distribuição juntamente com os quartis.

```python
# Usando pyplot
parts = plt.violinplot([data1, data2, data3])

# Personaliza as cores
for pc in parts['bodies']:
    pc.set_facecolor('lightblue')
    pc.set_alpha(0.7)
```

## Recursos Interativos e de Animação

### Backend Interativo: `%matplotlib widget`

Habilita gráficos interativos em notebooks Jupyter.

```python
# No notebook Jupyter
%matplotlib widget

# Ou para interatividade básica
%matplotlib notebook
```

### Manipulação de Eventos: Mouse e Teclado

Responde às interações do usuário com os gráficos.

```python
# Zoom interativo, pan e hover
def onclick(event):
    if event.inaxes:
        print(f'Clicado em x={event.xdata}, y={event.ydata}')

fig, ax = plt.subplots()
ax.plot(x, y)
fig.canvas.mpl_connect('button_press_event', onclick)
plt.show()
```

### Animações: `matplotlib.animation`

Cria gráficos animados para séries temporais ou dados em mudança.

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

# Salvar animação
# ani.save('animation.gif', writer='pillow')
```

## Salvando e Exportando Gráficos

### Salvar Figura: `plt.savefig()`

Exporta gráficos para arquivos de imagem com várias opções.

```python
# Salvar básico
plt.savefig('meu_grafico.png')

# Salvar em alta qualidade
plt.savefig('grafico.png', dpi=300, bbox_inches='tight')

# Diferentes formatos
plt.savefig('grafico.pdf')  # PDF
plt.savefig('grafico.svg')  # SVG (vetorial)
plt.savefig('grafico.eps')  # EPS

# Fundo transparente
plt.savefig('grafico.png', transparent=True)
```

### Qualidade da Figura: DPI e Tamanho

Controla a resolução e as dimensões dos gráficos salvos.

```python
# DPI alto para publicações
plt.savefig('grafico.png', dpi=600)

# Tamanho personalizado (largura, altura em polegadas)
plt.figure(figsize=(12, 8))
plt.savefig('grafico.png', figsize=(12, 8))

# Cortar espaço em branco
plt.savefig('grafico.png', bbox_inches='tight', pad_inches=0.1)
```

### Exportação em Lote e Gerenciamento de Memória

Lida com múltiplos gráficos e gerencia a memória de forma eficiente.

```python
# Fecha figuras para liberar memória
plt.close()  # Fecha a figura atual
plt.close('all')  # Fecha todas as figuras

# Gerenciador de contexto para limpeza automática
with plt.figure() as fig:
    plt.plot(x, y)
    plt.savefig('grafico.png')

# Salvar em lote múltiplos gráficos
for i, data in enumerate(datasets):
    plt.figure()
    plt.plot(data)
    plt.savefig(f'grafico_{i}.png')
    plt.close()
```

## Integração com Bibliotecas de Dados

### Integração Pandas: Plotagem Direta

Usa métodos de DataFrame do Pandas.

```python
import pandas as pd

# Plotagem de DataFrame (usa backend matplotlib)
df.plot(kind='line', x='data', y='valor')
df.plot.scatter(x='coluna_x', y='coluna_y')
df.plot.hist(bins=30)
df.plot.box()

# Acessa objetos matplotlib subjacentes
ax = df.plot(kind='line')
ax.set_title('Título Personalizado')
plt.show()
```

### Integração NumPy: Visualização de Array

Plota eficientemente arrays NumPy e funções matemáticas.

```python
# Visualização de array 2D
arr = np.random.rand(10, 10)
plt.imshow(arr, cmap='hot', interpolation='nearest')

# Funções matemáticas
x = np.linspace(0, 4*np.pi, 1000)
y = np.sin(x) * np.exp(-x/10)
plt.plot(x, y)

# Distribuições estatísticas
data = np.random.normal(0, 1, 10000)
plt.hist(data, bins=50, density=True, alpha=0.7)
```

### Integração Seaborn: Estilo Aprimorado

Combina Matplotlib com Seaborn para melhores estéticas padrão.

```python
import seaborn as sns

# Usa estilo seaborn com matplotlib
sns.set_style('whitegrid')
plt.plot(x, y)
plt.show()

# Mistura seaborn e matplotlib
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
sns.scatterplot(data=df, x='x', y='y', ax=axes[0,0])
plt.plot(x, y, ax=axes[0,1])  # Matplotlib puro
```

### Integração Jupyter: Plotagem em Linha

Otimiza Matplotlib para ambientes de notebook Jupyter.

```python
# Comandos mágicos para Jupyter
%matplotlib inline  # Gráficos estáticos
%matplotlib widget  # Gráficos interativos

# Exibições de alta DPI
%config InlineBackend.figure_format = 'retina'

# Dimensionamento automático de figura
%matplotlib inline
plt.rcParams['figure.dpi'] = 100
```

## Instalação e Configuração do Ambiente

### Pip: `pip install matplotlib`

Instalador de pacotes Python padrão para Matplotlib.

```bash
# Instala Matplotlib
pip install matplotlib

# Atualiza para a versão mais recente
pip install matplotlib --upgrade

# Instala com backends adicionais
pip install matplotlib[qt5]

# Mostra informações do pacote
pip show matplotlib
```

### Conda: `conda install matplotlib`

Gerenciador de pacotes para ambientes Anaconda/Miniconda.

```bash
# Instala no ambiente atual
conda install matplotlib

# Atualiza matplotlib
conda update matplotlib

# Cria ambiente com matplotlib
conda create -n dataviz matplotlib numpy pandas

# Lista informações do matplotlib
conda list matplotlib
```

### Configuração do Backend

Configura backends de exibição para diferentes ambientes.

```python
# Verifica backends disponíveis
import matplotlib
print(matplotlib.get_backend())

# Define o backend programaticamente
matplotlib.use('TkAgg')  # Para Tkinter
matplotlib.use('Qt5Agg')  # Para PyQt5

# Para servidores headless
matplotlib.use('Agg')

# Importa após definir o backend
import matplotlib.pyplot as plt
```

## Links Relevantes

- <router-link to="/python">Folha de Dicas Python</router-link>
- <router-link to="/numpy">Folha de Dicas NumPy</router-link>
- <router-link to="/pandas">Folha de Dicas Pandas</router-link>
- <router-link to="/sklearn">Folha de Dicas scikit-learn</router-link>
- <router-link to="/datascience">Folha de Dicas Ciência de Dados</router-link>

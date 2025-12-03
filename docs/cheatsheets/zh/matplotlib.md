---
title: 'Matplotlib 速查表 | LabEx'
description: '使用此综合速查表学习 Matplotlib 数据可视化。绘图、图表、图形、子图、自定义和 Python 数据可视化的快速参考。'
pdfUrl: '/cheatsheets/pdf/matplotlib-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Matplotlib 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/matplotlib">使用实践实验室学习 Matplotlib</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Matplotlib 数据可视化。LabEx 提供全面的 Matplotlib 课程，涵盖基本绘图函数、自定义技术、子图布局和高级可视化类型。掌握为 Python 数据科学工作流程创建有效数据可视化的技能。
</base-disclaimer-content>
</base-disclaimer>

## 基本绘图和图表类型

### 折线图：`plt.plot()`

创建用于连续数据可视化的折线图。

```python
import matplotlib.pyplot as plt
import numpy as np

# 基本折线图
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
plt.plot(x, y)
plt.show()

# 多条线
plt.plot(x, y, label='Line 1')
plt.plot(x, [1, 3, 5, 7, 9], label='Line 2')
plt.legend()

# 线型和颜色
plt.plot(x, y, 'r--', linewidth=2, marker='o')
```

<BaseQuiz id="matplotlib-plot-1" correct="C">
  <template #question>
    <code>plt.show()</code> 在 Matplotlib 中做什么？
  </template>
  
  <BaseQuizOption value="A">将图表保存到文件</BaseQuizOption>
  <BaseQuizOption value="B">关闭图表窗口</BaseQuizOption>
  <BaseQuizOption value="C" correct>在窗口中显示图表</BaseQuizOption>
  <BaseQuizOption value="D">清除图表</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>plt.show()</code> 在交互式窗口中显示图表。调用此函数才能看到可视化效果。没有它，图表将不会显示。
  </BaseQuizAnswer>
</BaseQuiz>

### 散点图：`plt.scatter()`

显示两个变量之间的关系。

```python
# 基本散点图
plt.scatter(x, y)

# 带有不同颜色和大小
colors = [1, 2, 3, 4, 5]
sizes = [20, 50, 100, 200, 500]
plt.scatter(x, y, c=colors, s=sizes, alpha=0.6)
plt.colorbar()  # 添加颜色条
```

<BaseQuiz id="matplotlib-scatter-1" correct="D">
  <template #question>
    Matplotlib 图表中的 <code>alpha</code> 参数控制什么？
  </template>
  
  <BaseQuizOption value="A">图表的颜色</BaseQuizOption>
  <BaseQuizOption value="B">图表的大小</BaseQuizOption>
  <BaseQuizOption value="C">图表的位置</BaseQuizOption>
  <BaseQuizOption value="D" correct>图表元素的透明度/不透明度</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>alpha</code> 参数控制透明度，取值范围从 0（完全透明）到 1（完全不透明）。当需要看到重叠的可视化元素时，它非常有用。
  </BaseQuizAnswer>
</BaseQuiz>

### 条形图：`plt.bar()` / `plt.barh()`

创建垂直或水平条形图。

```python
# 垂直条形图
categories = ['A', 'B', 'C', 'D']
values = [20, 35, 30, 25]
plt.bar(categories, values)

# 水平条形图
plt.barh(categories, values)

# 分组条形图
x = np.arange(len(categories))
plt.bar(x - 0.2, values, 0.4, label='Group 1')
plt.bar(x + 0.2, [15, 25, 35, 20], 0.4, label='Group 2')
```

### 直方图：`plt.hist()`

显示连续数据的分布。

```python
# 基本直方图
data = np.random.randn(1000)
plt.hist(data, bins=30)

# 自定义直方图
plt.hist(data, bins=50, alpha=0.7, color='skyblue', edgecolor='black')

# 多个直方图
plt.hist([data1, data2], bins=30, alpha=0.7, label=['Data 1', 'Data 2'])
```

### 饼图：`plt.pie()`

将比例数据显示为圆形图表。

```python
# 基本饼图
sizes = [25, 35, 20, 20]
labels = ['A', 'B', 'C', 'D']
plt.pie(sizes, labels=labels)

# 带百分比的爆炸饼图
explode = (0, 0.1, 0, 0)  # 爆炸第二个切片
plt.pie(sizes, labels=labels, autopct='%1.1f%%',
        explode=explode, shadow=True, startangle=90)
```

### 箱线图：`plt.boxplot()`

可视化数据分布和异常值。

```python
# 单个箱线图
data = [np.random.randn(100) for _ in range(4)]
plt.boxplot(data)

# 自定义箱线图
plt.boxplot(data, labels=['Group 1', 'Group 2', 'Group 3', 'Group 4'],
           patch_artist=True, notch=True)
```

## 图表自定义和样式

### 标签和标题：`plt.xlabel()` / `plt.title()`

为图表添加描述性文本，以提高清晰度和上下文。

```python
# 基本标签和标题
plt.plot(x, y)
plt.xlabel('X 轴标签')
plt.ylabel('Y 轴标签')
plt.title('图表标题')

# 带有字体属性的格式化标题
plt.title('我的图表', fontsize=16, fontweight='bold')
plt.xlabel('X 值', fontsize=12)

# 网格线，提高可读性
plt.grid(True, alpha=0.3)
```

### 颜色和样式：`color` / `linestyle` / `marker`

自定义绘图元素的视觉外观。

```python
# 颜色选项
plt.plot(x, y, color='red')  # 命名颜色
plt.plot(x, y, color='#FF5733')  # Hex 颜色
plt.plot(x, y, color=(0.1, 0.2, 0.5))  # RGB 元组

# 线型
plt.plot(x, y, linestyle='--')  # 虚线
plt.plot(x, y, linestyle=':')   # 点线
plt.plot(x, y, linestyle='-.')  # 虚点线

# 标记
plt.plot(x, y, marker='o', markersize=8, markerfacecolor='red')
```

### 图例和注释：`plt.legend()` / `plt.annotate()`

添加图例和注释以解释图表元素。

```python
# 基本图例
plt.plot(x, y1, label='数据集 1')
plt.plot(x, y2, label='数据集 2')
plt.legend()

# 自定义图例位置
plt.legend(loc='upper right', fontsize=10, frameon=False)

# 注释
plt.annotate('重要点', xy=(2, 4), xytext=(3, 6),
            arrowprops=dict(arrowstyle='->', color='red'))
```

<BaseQuiz id="matplotlib-legend-1" correct="B">
  <template #question>
    <code>plt.legend()</code> 需要什么才能显示标签？
  </template>
  
  <BaseQuizOption value="A">不需要，它会自动工作</BaseQuizOption>
  <BaseQuizOption value="B" correct>每个图表都必须设置 <code>label</code> 参数</BaseQuizOption>
  <BaseQuizOption value="C">必须先创建图例，然后才能绘图</BaseQuizOption>
  <BaseQuizOption value="D">必须在图例中手动设置标签</BaseQuizOption>
  
  <BaseQuizAnswer>
    要显示图例，您需要在创建每个图表时设置 <code>label</code> 参数（例如 <code>plt.plot(x, y, label='数据集 1')</code>）。然后调用 <code>plt.legend()</code> 就会显示所有标签。
  </BaseQuizAnswer>
</BaseQuiz>

## 坐标轴和布局控制

### 坐标轴限制：`plt.xlim()` / `plt.ylim()`

控制每个坐标轴上显示的数值范围。

```python
# 设置坐标轴限制
plt.xlim(0, 10)
plt.ylim(-5, 15)

# 自动调整限制并留出边距
plt.margins(x=0.1, y=0.1)

# 反转坐标轴
plt.gca().invert_yaxis()  # 反转 y 轴
```

### 刻度线和标签：`plt.xticks()` / `plt.yticks()`

自定义坐标轴刻度标记及其标签。

```python
# 自定义刻度位置
plt.xticks([0, 2, 4, 6, 8, 10])
plt.yticks(np.arange(0, 101, 10))

# 自定义刻度标签
plt.xticks([0, 1, 2, 3], ['一月', '二月', '三月', '四月'])

# 旋转刻度标签
plt.xticks(rotation=45)

# 移除刻度线
plt.xticks([])
plt.yticks([])
```

### 纵横比：`plt.axis()`

控制纵横比和坐标轴外观。

```python
# 相等纵横比
plt.axis('equal')
# 方形图表
plt.axis('square')
# 关闭坐标轴
plt.axis('off')
# 自定义纵横比
plt.gca().set_aspect('equal', adjustable='box')
```

### 图形大小：`plt.figure()`

控制图表的整体大小和分辨率。

```python
# 设置图形大小（宽度、高度，单位：英寸）
plt.figure(figsize=(10, 6))

# 高 DPI 以获得更好的质量
plt.figure(figsize=(8, 6), dpi=300)

# 多个图形
fig1 = plt.figure(1)
plt.plot(x, y1)
fig2 = plt.figure(2)
plt.plot(x, y2)
```

### 紧凑布局：`plt.tight_layout()`

自动调整子图间距，以获得更好的外观。

```python
# 防止元素重叠
plt.tight_layout()

# 手动调整间距
plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)

# 子图周围的填充
plt.tight_layout(pad=3.0)
```

### 样式表：`plt.style.use()`

应用预定义样式以获得一致的图表外观。

```python
# 可用样式
print(plt.style.available)

# 使用内置样式
plt.style.use('seaborn-v0_8')
plt.style.use('ggplot')
plt.style.use('bmh')

# 重置为默认
plt.style.use('default')
```

## 子图和多图

### 基本子图：`plt.subplot()` / `plt.subplots()`

在一个图形中创建多个图表。

```python
# 创建 2x2 子图网格
fig, axes = plt.subplots(2, 2, figsize=(10, 8))

# 在每个子图中绘图
axes[0, 0].plot(x, y)
axes[0, 1].scatter(x, y)
axes[1, 0].bar(x, y)
axes[1, 1].hist(y, bins=10)

# 替代语法
plt.subplot(2, 2, 1)  # 2 行，2 列，第 1 个子图
plt.plot(x, y)
plt.subplot(2, 2, 2)  # 第 2 个子图
plt.scatter(x, y)
```

### 共享坐标轴：`sharex` / `sharey`

跨子图链接坐标轴以实现一致的缩放。

```python
# 在子图间共享 x 轴
fig, axes = plt.subplots(2, 1, sharex=True)
axes[0].plot(x, y1)
axes[1].plot(x, y2)

# 共享两个坐标轴
fig, axes = plt.subplots(2, 2, sharex=True, sharey=True)
```

### GridSpec: 高级布局

创建具有不同大小的复杂子图排列。

```python
import matplotlib.gridspec as gridspec

# 创建自定义网格
gs = gridspec.GridSpec(3, 3)
fig = plt.figure(figsize=(10, 8))

# 不同大小的子图
ax1 = fig.add_subplot(gs[0, :])  # 顶行，所有列
ax2 = fig.add_subplot(gs[1, :-1])  # 中间行，前 2 列
ax3 = fig.add_subplot(gs[1:, -1])  # 最后一列，下 2 行
ax4 = fig.add_subplot(gs[-1, 0])   # 左下角
ax5 = fig.add_subplot(gs[-1, 1])   # 中下部
```

### 子图间距：`hspace` / `wspace`

控制子图之间的间距。

```python
# 创建子图时调整间距
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
plt.subplots_adjust(hspace=0.4, wspace=0.3)

# 或使用 tight_layout 进行自动调整
plt.tight_layout()
```

## 高级可视化类型

### 热力图：`plt.imshow()` / `plt.pcolormesh()`

将 2D 数据可视化为彩色编码矩阵。

```python
# 基本热力图
data = np.random.randn(10, 10)
plt.imshow(data, cmap='viridis')
plt.colorbar()

# Pcolormesh 用于不规则网格
x = np.linspace(0, 10, 11)
y = np.linspace(0, 5, 6)
X, Y = np.meshgrid(x, y)
Z = np.sin(X) * np.cos(Y)
plt.pcolormesh(X, Y, Z, shading='auto')
plt.colorbar()
```

### 等高线图：`plt.contour()` / `plt.contourf()`

显示水平曲线和填充的等高线区域。

```python
# 等高线
x = np.linspace(-3, 3, 100)
y = np.linspace(-3, 3, 100)
X, Y = np.meshgrid(x, y)
Z = X**2 + Y**2
plt.contour(X, Y, Z, levels=10)
plt.clabel(plt.contour(X, Y, Z), inline=True, fontsize=8)

# 填充等高线
plt.contourf(X, Y, Z, levels=20, cmap='RdBu')
plt.colorbar()
```

### 3D 图表：`mplot3d`

创建三维可视化。

```python
from mpl_toolkits.mplot3d import Axes3D

fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# 3D 散点图
ax.scatter(x, y, z)

# 3D 曲面图
ax.plot_surface(X, Y, Z, cmap='viridis')

# 3D 折线图
ax.plot(x, y, z)
```

### 误差棒：`plt.errorbar()`

显示带有不确定性测量的图表数据。

```python
# 基本误差棒
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
yerr = [0.5, 0.8, 0.3, 0.7, 0.4]
plt.errorbar(x, y, yerr=yerr, fmt='o-', capsize=5)

# 非对称误差棒
yerr_lower = [0.4, 0.6, 0.2, 0.5, 0.3]
yerr_upper = [0.6, 1.0, 0.4, 0.9, 0.5]
plt.errorbar(x, y, yerr=[yerr_lower, yerr_upper], fmt='s-')
```

### 填充区域：`plt.fill_between()`

在曲线之间或线条周围的区域着色。

```python
# 在两条曲线之间填充
y1 = [2, 4, 6, 8, 10]
y2 = [1, 3, 5, 7, 9]
plt.fill_between(x, y1, y2, alpha=0.3, color='blue')

# 围绕误差线填充
plt.plot(x, y, 'k-', linewidth=2)
plt.fill_between(x, y-yerr, y+yerr, alpha=0.2, color='gray')
```

### 小提琴图：Box Plots 的替代方案

显示分布形状以及四分位数。

```python
# 使用 pyplot
parts = plt.violinplot([data1, data2, data3])

# 自定义颜色
for pc in parts['bodies']:
    pc.set_facecolor('lightblue')
    pc.set_alpha(0.7)
```

## 交互和动画功能

### 交互式后端：`%matplotlib widget`

在 Jupyter notebook 中启用交互式图表。

```python
# 在 Jupyter notebook 中
%matplotlib widget

# 或用于基本交互性
%matplotlib notebook
```

### 事件处理：鼠标和键盘

响应用户与图表的交互。

```python
# 交互式缩放、平移和悬停
def onclick(event):
    if event.inaxes:
        print(f'点击位置 x={event.xdata}, y={event.ydata}')

fig, ax = plt.subplots()
ax.plot(x, y)
fig.canvas.mpl_connect('button_press_event', onclick)
plt.show()
```

### 动画：`matplotlib.animation`

创建动画以显示时间序列或变化数据。

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

# 保存动画
# ani.save('animation.gif', writer='pillow')
```

## 保存和导出图表

### 保存图形：`plt.savefig()`

将图表导出为各种选项的图像文件。

```python
# 基本保存
plt.savefig('my_plot.png')

# 高质量保存
plt.savefig('plot.png', dpi=300, bbox_inches='tight')

# 不同格式
plt.savefig('plot.pdf')  # PDF
plt.savefig('plot.svg')  # SVG (矢量)
plt.savefig('plot.eps')  # EPS

# 透明背景
plt.savefig('plot.png', transparent=True)
```

### 图形质量：DPI 和大小

控制保存图表的分辨率和尺寸。

```python
# 用于出版物的高 DPI
plt.savefig('plot.png', dpi=600)

# 自定义大小（宽度、高度，单位：英寸）
plt.figure(figsize=(12, 8))
plt.savefig('plot.png', figsize=(12, 8))

# 裁剪空白
plt.savefig('plot.png', bbox_inches='tight', pad_inches=0.1)
```

### 批量导出和内存管理

处理多个图表和内存效率。

```python
# 关闭图形以释放内存
plt.close()  # 关闭当前图形
plt.close('all')  # 关闭所有图形

# 用于自动清理的上下文管理器
with plt.figure() as fig:
    plt.plot(x, y)
    plt.savefig('plot.png')

# 批量保存多个图表
for i, data in enumerate(datasets):
    plt.figure()
    plt.plot(data)
    plt.savefig(f'plot_{i}.png')
    plt.close()
```

## 配置和最佳实践

### RC 参数：`plt.rcParams`

设置所有图表的默认样式和行为。

```python
# 常用 rc 参数
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 12
plt.rcParams['lines.linewidth'] = 2
plt.rcParams['axes.grid'] = True

# 保存和恢复设置
original_params = plt.rcParams.copy()
# ... 进行更改 ...
plt.rcParams.update(original_params)  # 恢复
```

### 颜色管理：颜色映射和调色板

有效地处理颜色和颜色映射。

```python
# 列出可用颜色映射
print(plt.colormaps())

# 对多条线使用颜色映射
colors = plt.cm.viridis(np.linspace(0, 1, len(datasets)))
for i, (data, color) in enumerate(zip(datasets, colors)):
    plt.plot(data, color=color, label=f'数据集 {i+1}')

# 自定义颜色映射
from matplotlib.colors import LinearSegmentedColormap
custom_cmap = LinearSegmentedColormap.from_list('custom', ['red', 'yellow', 'blue'])
```

### 性能优化

提高大型数据集的绘图性能。

```python
# 动画中使用位图绘制 (blit)
ani = FuncAnimation(fig, animate, blit=True)

# 复杂图表栅格化
plt.plot(x, y, rasterized=True)

# 减少数据集数据点
# 绘图前对数据进行降采样
indices = np.arange(0, len(large_data), step=10)
plt.plot(large_data[indices])
```

### 内存使用：高效绘图

在创建多个图表或大型可视化时管理内存。

```python
# 清除坐标轴而不是创建新图形
fig, ax = plt.subplots()
for data in datasets:
    ax.clear()  # 清除上一个图表
    ax.plot(data)
    plt.savefig(f'plot_{i}.png')

# 对大型数据集使用生成器
def data_generator():
    for i in range(1000):
        yield np.random.randn(100)

for i, data in enumerate(data_generator()):
    if i > 10:  # 限制图表数量
        break
```

## 与数据库集成

### Pandas 集成：直接绘图

通过 Pandas DataFrame 方法使用 Matplotlib。

```python
import pandas as pd

# DataFrame 绘图（使用 matplotlib 后端）
df.plot(kind='line', x='date', y='value')
df.plot.scatter(x='x_col', y='y_col')
df.plot.hist(bins=30)
df.plot.box()

# 访问底层 matplotlib 对象
ax = df.plot(kind='line')
ax.set_title('自定义标题')
plt.show()
```

### NumPy 集成：数组可视化

有效地绘制 NumPy 数组和数学函数。

```python
# 2D 数组可视化
arr = np.random.rand(10, 10)
plt.imshow(arr, cmap='hot', interpolation='nearest')

# 数学函数
x = np.linspace(0, 4*np.pi, 1000)
y = np.sin(x) * np.exp(-x/10)
plt.plot(x, y)

# 统计分布
data = np.random.normal(0, 1, 10000)
plt.hist(data, bins=50, density=True, alpha=0.7)
```

### Seaborn 集成：增强的样式

结合 Matplotlib 和 Seaborn 以获得更好的默认美学效果。

```python
import seaborn as sns

# 使用 seaborn 样式和 matplotlib
sns.set_style('whitegrid')
plt.plot(x, y)
plt.show()

# 混合 seaborn 和 matplotlib
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
sns.scatterplot(data=df, x='x', y='y', ax=axes[0,0])
plt.plot(x, y, ax=axes[0,1])  # 纯 Matplotlib
```

### Jupyter 集成：内联绘图

优化 Matplotlib 以用于 Jupyter notebook 环境。

```python
# Jupyter 的魔术命令
%matplotlib inline  # 静态图表
%matplotlib widget  # 交互式图表

# 高 DPI 显示
%config InlineBackend.figure_format = 'retina'

# 自动图形大小
%matplotlib inline
plt.rcParams['figure.dpi'] = 100
```

## 安装和环境设置

### Pip: `pip install matplotlib`

用于 Matplotlib 的标准 Python 包安装程序。

```bash
# 安装 Matplotlib
pip install matplotlib

# 升级到最新版本
pip install matplotlib --upgrade

# 安装附加后端
pip install matplotlib[qt5]

# 显示包信息
pip show matplotlib
```

### Conda: `conda install matplotlib`

用于 Anaconda/Miniconda 环境的包管理器。

```bash
# 在当前环境中安装
conda install matplotlib

# 更新 matplotlib
conda update matplotlib

# 创建包含 matplotlib 的环境
conda create -n dataviz matplotlib numpy pandas

# 列出 matplotlib 信息
conda list matplotlib
```

### 后端配置

为不同环境设置显示后端。

```python
# 检查可用后端
import matplotlib
print(matplotlib.get_backend())

# 以编程方式设置后端
matplotlib.use('TkAgg')  # 用于 Tkinter
matplotlib.use('Qt5Agg')  # 用于 PyQt5

# 用于无头服务器
matplotlib.use('Agg')

# 设置后端后导入
import matplotlib.pyplot as plt
```

## 相关链接

- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/numpy">NumPy 速查表</router-link>
- <router-link to="/pandas">Pandas 速查表</router-link>
- <router-link to="/sklearn">scikit-learn 速查表</router-link>
- <router-link to="/datascience">数据科学速查表</router-link>

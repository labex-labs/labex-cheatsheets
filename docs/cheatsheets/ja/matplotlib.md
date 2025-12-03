---
title: 'Matplotlib チートシート | LabEx'
description: 'この包括的なチートシートで Matplotlib のデータ可視化を学ぶ。プロット、チャート、グラフ、サブプロット、カスタマイズ、Python データ可視化のクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/matplotlib-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Matplotlib チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/matplotlib">Matplotlib をハンズオンラボで学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、Matplotlib データ視覚化を学習します。LabEx は、必須のプロット関数、カスタマイズ技術、サブプロットレイアウト、高度な視覚化タイプを網羅した包括的な Matplotlib コースを提供します。Python データサイエンスワークフローで効果的なデータ視覚化を作成するスキルを習得します。
</base-disclaimer-content>
</base-disclaimer>

## 基本的なプロットとチャートタイプ

### 折れ線グラフ：`plt.plot()`

連続データの視覚化のために折れ線グラフを作成します。

```python
import matplotlib.pyplot as plt
import numpy as np

# 基本的な折れ線グラフ
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
plt.plot(x, y)
plt.show()

# 複数線
plt.plot(x, y, label='Line 1')
plt.plot(x, [1, 3, 5, 7, 9], label='Line 2')
plt.legend()

# 線種と色
plt.plot(x, y, 'r--', linewidth=2, marker='o')
```

<BaseQuiz id="matplotlib-plot-1" correct="C">
  <template #question>
    Matplotlib における <code>plt.show()</code> の役割は何ですか？
  </template>
  
  <BaseQuizOption value="A">プロットをファイルに保存する</BaseQuizOption>
  <BaseQuizOption value="B">プロットウィンドウを閉じる</BaseQuizOption>
  <BaseQuizOption value="C" correct>プロットをウィンドウに表示する</BaseQuizOption>
  <BaseQuizOption value="D">プロットをクリアする</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>plt.show()</code> はプロットをインタラクティブなウィンドウに表示します。視覚化を見るためにはこの関数を呼び出す必要があります。これがないと、プロットは表示されません。
  </BaseQuizAnswer>
</BaseQuiz>

### 散布図：`plt.scatter()`

2 つの変数の間の関係を表示します。

```python
# 基本的な散布図
plt.scatter(x, y)

# 異なる色とサイズで
colors = [1, 2, 3, 4, 5]
sizes = [20, 50, 100, 200, 500]
plt.scatter(x, y, c=colors, s=sizes, alpha=0.6)
plt.colorbar()  # カラーバーを追加
```

<BaseQuiz id="matplotlib-scatter-1" correct="D">
  <template #question>
    matplotlib プロットにおける <code>alpha</code> パラメータは何を制御しますか？
  </template>
  
  <BaseQuizOption value="A">プロットの色</BaseQuizOption>
  <BaseQuizOption value="B">プロットのサイズ</BaseQuizOption>
  <BaseQuizOption value="C">プロットの位置</BaseQuizOption>
  <BaseQuizOption value="D" correct>プロット要素の透明度/不透明度</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>alpha</code> パラメータは透明度を制御し、値は 0（完全な透明）から 1（完全な不透明）までです。重なり合う視覚化を作成し、要素を通して見たい場合に便利です。
  </BaseQuizAnswer>
</BaseQuiz>

### 棒グラフ：`plt.bar()` / `plt.barh()`

垂直または水平の棒グラフを作成します。

```python
# 垂直棒グラフ
categories = ['A', 'B', 'C', 'D']
values = [20, 35, 30, 25]
plt.bar(categories, values)

# 水平棒グラフ
plt.barh(categories, values)

# グループ化された棒グラフ
x = np.arange(len(categories))
plt.bar(x - 0.2, values, 0.4, label='Group 1')
plt.bar(x + 0.2, [15, 25, 35, 20], 0.4, label='Group 2')
```

### ヒストグラム：`plt.hist()`

連続データの分布を表示します。

```python
# 基本的なヒストグラム
data = np.random.randn(1000)
plt.hist(data, bins=30)

# カスタマイズされたヒストグラム
plt.hist(data, bins=50, alpha=0.7, color='skyblue', edgecolor='black')

# 複数ヒストグラム
plt.hist([data1, data2], bins=30, alpha=0.7, label=['Data 1', 'Data 2'])
```

### 円グラフ：`plt.pie()`

比例データを円グラフとして表示します。

```python
# 基本的な円グラフ
sizes = [25, 35, 20, 20]
labels = ['A', 'B', 'C', 'D']
plt.pie(sizes, labels=labels)

# パーセンテージ付きの切り出し円グラフ
explode = (0, 0.1, 0, 0)  # 2 番目のスライスを切り出す
plt.pie(sizes, labels=labels, autopct='%1.1f%%',
        explode=explode, shadow=True, startangle=90)
```

### 箱ひげ図：`plt.boxplot()`

データの分布と外れ値を視覚化します。

```python
# 単一の箱ひげ図
data = [np.random.randn(100) for _ in range(4)]
plt.boxplot(data)

# カスタマイズされた箱ひげ図
plt.boxplot(data, labels=['Group 1', 'Group 2', 'Group 3', 'Group 4'],
           patch_artist=True, notch=True)
```

## プロットのカスタマイズとスタイリング

### ラベルとタイトル：`plt.xlabel()` / `plt.title()`

プロットに説明的なテキストを追加し、明確さと文脈を提供します。

```python
# 基本的なラベルとタイトル
plt.plot(x, y)
plt.xlabel('X 軸ラベル')
plt.ylabel('Y 軸ラベル')
plt.title('プロットのタイトル')

# フォントプロパティ付きの整形されたタイトル
plt.title('マイプロット', fontsize=16, fontweight='bold')
plt.xlabel('X 値', fontsize=12)

# 読みやすさのためのグリッド
plt.grid(True, alpha=0.3)
```

### 色とスタイル：`color` / `linestyle` / `marker`

プロット要素の視覚的な外観をカスタマイズします。

```python
# 色のオプション
plt.plot(x, y, color='red')  # 名前付きの色
plt.plot(x, y, color='#FF5733')  # 16 進数の色
plt.plot(x, y, color=(0.1, 0.2, 0.5))  # RGB タプル

# 線種
plt.plot(x, y, linestyle='--')  # 破線
plt.plot(x, y, linestyle=':')   # 点線
plt.plot(x, y, linestyle='-.')  # 破線と点線

# マーカー
plt.plot(x, y, marker='o', markersize=8, markerfacecolor='red')
```

### 凡例と注釈：`plt.legend()` / `plt.annotate()`

凡例と注釈を追加して、プロット要素を説明します。

```python
# 基本的な凡例
plt.plot(x, y1, label='Dataset 1')
plt.plot(x, y2, label='Dataset 2')
plt.legend()

# 凡例の位置のカスタマイズ
plt.legend(loc='upper right', fontsize=10, frameon=False)

# 注釈
plt.annotate('重要な点', xy=(2, 4), xytext=(3, 6),
            arrowprops=dict(arrowstyle='->', color='red'))
```

<BaseQuiz id="matplotlib-legend-1" correct="B">
  <template #question>
    <code>plt.legend()</code> がラベルを表示するために必要なものは何ですか？
  </template>
  
  <BaseQuizOption value="A">何もしない、自動的に機能する</BaseQuizOption>
  <BaseQuizOption value="B" correct>各プロットに <code>label</code> パラメータを設定する必要がある</BaseQuizOption>
  <BaseQuizOption value="C">プロットを作成する前に凡例を作成する必要がある</BaseQuizOption>
  <BaseQuizOption value="D">凡例内でラベルを手動で設定する必要がある</BaseQuizOption>
  
  <BaseQuizAnswer>
    凡例を表示するには、各プロットを作成する際に <code>label</code> パラメータを設定する必要があります（例：<code>plt.plot(x, y, label='Dataset 1')</code>）。その後、<code>plt.legend()</code> を呼び出すと、すべてのラベルが表示されます。
  </BaseQuizAnswer>
</BaseQuiz>

## 軸とレイアウトの制御

### 軸の範囲：`plt.xlim()` / `plt.ylim()`

各軸に表示する値の範囲を制御します。

```python
# 軸の範囲を設定
plt.xlim(0, 10)
plt.ylim(-5, 15)

# マージン付きの自動調整された範囲
plt.margins(x=0.1, y=0.1)

# 軸の反転
plt.gca().invert_yaxis()  # Y 軸を反転
```

### 目盛りとラベル：`plt.xticks()` / `plt.yticks()`

軸の目盛りマークとそのラベルをカスタマイズします。

```python
# カスタムの目盛り位置
plt.xticks([0, 2, 4, 6, 8, 10])
plt.yticks(np.arange(0, 101, 10))

# カスタムの目盛りラベル
plt.xticks([0, 1, 2, 3], ['Jan', 'Feb', 'Mar', 'Apr'])

# 目盛りラベルの回転
plt.xticks(rotation=45)

# 目盛りの削除
plt.xticks([])
plt.yticks([])
```

### アスペクト比：`plt.axis()`

アスペクト比と軸の外観を制御します。

```python
# 等しいアスペクト比
plt.axis('equal')
# 正方形のプロット
plt.axis('square')
# 軸のオフ
plt.axis('off')
# カスタムアスペクト比
plt.gca().set_aspect('equal', adjustable='box')
```

### 図のサイズ：`plt.figure()`

プロット全体のサイズと解像度を制御します。

```python
# 図のサイズを設定（幅、高さはインチ単位）
plt.figure(figsize=(10, 6))

# より高品質のための高 DPI
plt.figure(figsize=(8, 6), dpi=300)

# 複数の図
fig1 = plt.figure(1)
plt.plot(x, y1)
fig2 = plt.figure(2)
plt.plot(x, y2)
```

### タイトレイアウト：`plt.tight_layout()`

サブプロット間の間隔を自動的に調整し、外観を改善します。

```python
# 重なり合う要素を防ぐ
plt.tight_layout()

# 手動の間隔調整
plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)

# サブプロットの周囲のパディング
plt.tight_layout(pad=3.0)
```

### スタイルシート：`plt.style.use()`

定義済みのスタイルを適用して、プロットの外観を統一します。

```python
# 利用可能なスタイル
print(plt.style.available)

# 内蔵スタイルの使用
plt.style.use('seaborn-v0_8')
plt.style.use('ggplot')
plt.style.use('bmh')

# デフォルトに戻す
plt.style.use('default')
```

## サブプロットと複数のプロット

### 基本的なサブプロット：`plt.subplot()` / `plt.subplots()`

単一の図内に複数のプロットを作成します。

```python
# 2x2 のサブプロットグリッドを作成
fig, axes = plt.subplots(2, 2, figsize=(10, 8))

# 各サブプロットへのプロット
axes[0, 0].plot(x, y)
axes[0, 1].scatter(x, y)
axes[1, 0].bar(x, y)
axes[1, 1].hist(y, bins=10)

# 代替構文
plt.subplot(2, 2, 1)  # 2 行、2 列、1 番目のサブプロット
plt.plot(x, y)
plt.subplot(2, 2, 2)  # 2 番目のサブプロット
plt.scatter(x, y)
```

### 共有軸：`sharex` / `sharey`

一貫したスケーリングのために、サブプロット間で軸をリンクします。

```python
# サブプロット間で X 軸を共有
fig, axes = plt.subplots(2, 1, sharex=True)
axes[0].plot(x, y1)
axes[1].plot(x, y2)

# 両方の軸を共有
fig, axes = plt.subplots(2, 2, sharex=True, sharey=True)
```

### GridSpec: 高度なレイアウト

異なるサイズのサブプロットを持つ複雑なサブプロット配置を作成します。

```python
import matplotlib.gridspec as gridspec

# カスタムグリッドの作成
gs = gridspec.GridSpec(3, 3)
fig = plt.figure(figsize=(10, 8))

# サイズの異なるサブプロット
ax1 = fig.add_subplot(gs[0, :])  # 上の行、すべての列
ax2 = fig.add_subplot(gs[1, :-1])  # 中間の行、最初の 2 列
ax3 = fig.add_subplot(gs[1:, -1])  # 最後の列、下の 2 行
ax4 = fig.add_subplot(gs[-1, 0])   # 左下
ax5 = fig.add_subplot(gs[-1, 1])   # 中央下
```

### サブプロットの間隔：`hspace` / `wspace`

サブプロット間の間隔を制御します。

```python
# サブプロット作成時の間隔調整
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
plt.subplots_adjust(hspace=0.4, wspace=0.3)

# または、自動調整のために tight_layout を使用
plt.tight_layout()
```

## 高度な視覚化タイプ

### ヒートマップ：`plt.imshow()` / `plt.pcolormesh()`

2D データを色分けされた行列として視覚化します。

```python
# 基本的なヒートマップ
data = np.random.randn(10, 10)
plt.imshow(data, cmap='viridis')
plt.colorbar()

# 不規則なグリッドのための Pcolormesh
x = np.linspace(0, 10, 11)
y = np.linspace(0, 5, 6)
X, Y = np.meshgrid(x, y)
Z = np.sin(X) * np.cos(Y)
plt.pcolormesh(X, Y, Z, shading='auto')
plt.colorbar()
```

### 等高線図：`plt.contour()` / `plt.contourf()`

レベル曲線と塗りつぶされた等高線領域を表示します。

```python
# 等高線
x = np.linspace(-3, 3, 100)
y = np.linspace(-3, 3, 100)
X, Y = np.meshgrid(x, y)
Z = X**2 + Y**2
plt.contour(X, Y, Z, levels=10)
plt.clabel(plt.contour(X, Y, Z), inline=True, fontsize=8)

# 塗りつぶされた等高線
plt.contourf(X, Y, Z, levels=20, cmap='RdBu')
plt.colorbar()
```

### 3D プロット：`mplot3d`

3 次元の視覚化を作成します。

```python
from mpl_toolkits.mplot3d import Axes3D

fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# 3D 散布図
ax.scatter(x, y, z)

# 3D 表面プロット
ax.plot_surface(X, Y, Z, cmap='viridis')

# 3D 折れ線グラフ
ax.plot(x, y, z)
```

### 誤差棒：`plt.errorbar()`

不確実性の測定値を伴うデータを表示します。

```python
# 基本的な誤差棒
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
yerr = [0.5, 0.8, 0.3, 0.7, 0.4]
plt.errorbar(x, y, yerr=yerr, fmt='o-', capsize=5)

# 非対称な誤差棒
yerr_lower = [0.4, 0.6, 0.2, 0.5, 0.3]
yerr_upper = [0.6, 1.0, 0.4, 0.9, 0.5]
plt.errorbar(x, y, yerr=[yerr_lower, yerr_upper], fmt='s-')
```

### 間の塗りつぶし：`plt.fill_between()`

曲線間、または線周辺の領域をシェーディングします。

```python
# 2 つの曲線の間の塗りつぶし
y1 = [2, 4, 6, 8, 10]
y2 = [1, 3, 5, 7, 9]
plt.fill_between(x, y1, y2, alpha=0.3, color='blue')

# 誤差を伴う線周辺の塗りつぶし
plt.plot(x, y, 'k-', linewidth=2)
plt.fill_between(x, y-yerr, y+yerr, alpha=0.2, color='gray')
```

### バイオリンプロット：箱ひげ図の代替

四分位範囲とともに分布の形状を示す。

```python
# pyplot を使用
parts = plt.violinplot([data1, data2, data3])

# 色のカスタマイズ
for pc in parts['bodies']:
    pc.set_facecolor('lightblue')
    pc.set_alpha(0.7)
```

## インタラクティブ機能とアニメーション

### インタラクティブバックエンド：`%matplotlib widget`

Jupyter ノートブックでインタラクティブなプロットを有効にします。

```python
# Jupyter ノートブック内
%matplotlib widget

# または基本的なインタラクティブ性のため
%matplotlib notebook
```

### イベント処理：マウスとキーボード

プロットに対するユーザーの操作に応答します。

```python
# マウスのクリックとキーボードの応答
def onclick(event):
    if event.inaxes:
        print(f'クリック位置 x={event.xdata}, y={event.ydata}')

fig, ax = plt.subplots()
ax.plot(x, y)
fig.canvas.mpl_connect('button_press_event', onclick)
plt.show()
```

### アニメーション：`matplotlib.animation`

時系列データや変化するデータのためのアニメーションプロットを作成します。

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

# アニメーションの保存
# ani.save('animation.gif', writer='pillow')
```

## プロットの保存とエクスポート

### 図の保存：`plt.savefig()`

様々なオプションを使用してプロットを図ファイルにエクスポートします。

```python
# 基本的な保存
plt.savefig('my_plot.png')

# 高品質な保存
plt.savefig('plot.png', dpi=300, bbox_inches='tight')

# 異なる形式
plt.savefig('plot.pdf')  # PDF
plt.savefig('plot.svg')  # SVG (ベクトル)
plt.savefig('plot.eps')  # EPS

# 透明な背景
plt.savefig('plot.png', transparent=True)
```

### 図の品質：DPI とサイズ

保存されるプロットの解像度と寸法を制御します。

```python
# 出版物用の高 DPI
plt.savefig('plot.png', dpi=600)

# カスタムサイズ（幅、高さはインチ単位）
plt.figure(figsize=(12, 8))
plt.savefig('plot.png', figsize=(12, 8))

# 余白の切り取り
plt.savefig('plot.png', bbox_inches='tight', pad_inches=0.1)
```

### バッチエクスポートとメモリ管理

複数のプロットを処理し、メモリを効率的に管理します。

```python
# メモリを解放するために図を閉じる
plt.close()  # 現在の図を閉じる
plt.close('all')  # すべての図を閉じる

# 自動クリーンアップのためのコンテキストマネージャ
with plt.figure() as fig:
    plt.plot(x, y)
    plt.savefig('plot.png')

# 複数のプロットのバッチ保存
for i, data in enumerate(datasets):
    plt.figure()
    plt.plot(data)
    plt.savefig(f'plot_{i}.png')
    plt.close()
```

## 設定とベストプラクティス

### RC パラメータ：`plt.rcParams`

すべてのプロットのデフォルトのスタイリングと動作を設定します。

```python
# 一般的な rc パラメータ
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 12
plt.rcParams['lines.linewidth'] = 2
plt.rcParams['axes.grid'] = True

# 設定の保存と復元
original_params = plt.rcParams.copy()
# ... 変更を行う ...
plt.rcParams.update(original_params)  # 復元
```

### 色の管理：カラーマップとパレット

色とカラーマップを効果的に扱います。

```python
# 利用可能なカラーマップのリスト
print(plt.colormaps())

# 複数線に対するカラーマップの使用
colors = plt.cm.viridis(np.linspace(0, 1, len(datasets)))
for i, (data, color) in enumerate(zip(datasets, colors)):
    plt.plot(data, color=color, label=f'Dataset {i+1}')

# カスタムカラーマップ
from matplotlib.colors import LinearSegmentedColormap
custom_cmap = LinearSegmentedColormap.from_list('custom', ['red', 'yellow', 'blue'])
```

### パフォーマンスの最適化

大規模なデータセットのプロットパフォーマンスを向上させます。

```python
# アニメーションのためのブライティングの使用
ani = FuncAnimation(fig, animate, blit=True)

# 複雑なプロットのラスタライズ
plt.plot(x, y, rasterized=True)

# 大規模データセットのためのデータポイントの削減
# プロット前にデータをダウンサンプリング
indices = np.arange(0, len(large_data), step=10)
plt.plot(large_data[indices])
```

### メモリ使用量：効率的なプロット

多数のプロットや大規模な視覚化を作成する際のメモリ管理。

```python
# 新しい図を作成する代わりに軸をクリアする
fig, ax = plt.subplots()
for data in datasets:
    ax.clear()  # 前のプロットをクリア
    ax.plot(data)
    plt.savefig(f'plot_{i}.png')

# 大規模データセットのためのジェネレータの使用
def data_generator():
    for i in range(1000):
        yield np.random.randn(100)

for i, data in enumerate(data_generator()):
    if i > 10:  # プロット数を制限
        break
```

## データライブラリとの統合

### Pandas との統合：直接プロット

Pandas DataFrame メソッドを介した Matplotlib の使用。

```python
import pandas as pd

# DataFrame のプロット（matplotlib バックエンドを使用）
df.plot(kind='line', x='date', y='value')
df.plot.scatter(x='x_col', y='y_col')
df.plot.hist(bins=30)
df.plot.box()

# 基になる matplotlib オブジェクトへのアクセス
ax = df.plot(kind='line')
ax.set_title('カスタムタイトル')
plt.show()
```

### NumPy との統合：配列の視覚化

NumPy 配列と数学関数の効率的なプロット。

```python
# 2D 配列の視覚化
arr = np.random.rand(10, 10)
plt.imshow(arr, cmap='hot', interpolation='nearest')

# 数学関数
x = np.linspace(0, 4*np.pi, 1000)
y = np.sin(x) * np.exp(-x/10)
plt.plot(x, y)

# 統計分布
data = np.random.normal(0, 1, 10000)
plt.hist(data, bins=50, density=True, alpha=0.7)
```

### Seaborn との統合：スタイリングの強化

より良いデフォルトの美学のために Matplotlib と Seaborn を組み合わせます。

```python
import seaborn as sns

# matplotlib での seaborn スタイリングの使用
sns.set_style('whitegrid')
plt.plot(x, y)
plt.show()

# seaborn と matplotlib の混合
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
sns.scatterplot(data=df, x='x', y='y', ax=axes[0,0])
plt.plot(x, y, ax=axes[0,1])  # 純粋な matplotlib
```

### Jupyter との統合：インラインプロット

Jupyter ノートブック環境向けに Matplotlib を最適化します。

```python
# Jupyter のマジックコマンド
%matplotlib inline  # 静的プロット
%matplotlib widget  # インタラクティブプロット

# 高 DPI 表示
%config InlineBackend.figure_format = 'retina'

# 自動図サイズ設定
%matplotlib inline
plt.rcParams['figure.dpi'] = 100
```

## インストールと環境設定

### Pip: `pip install matplotlib`

Matplotlib の標準的な Python パッケージインストーラ。

```bash
# Matplotlib のインストール
pip install matplotlib

# 最新バージョンへのアップグレード
pip install matplotlib --upgrade

# 追加のバックエンドをインストール
pip install matplotlib[qt5]

# パッケージ情報の表示
pip show matplotlib
```

### Conda: `conda install matplotlib`

Anaconda/Miniconda 環境用のパッケージマネージャ。

```bash
# 現在の環境にインストール
conda install matplotlib

# matplotlib の更新
conda update matplotlib

# matplotlib を含む環境の作成
conda create -n dataviz matplotlib numpy pandas

# matplotlib の情報のリスト表示
conda list matplotlib
```

### バックエンドの設定

異なる環境での表示バックエンドの設定。

```python
# 利用可能なバックエンドの確認
import matplotlib
print(matplotlib.get_backend())

# プログラムによるバックエンドの設定
matplotlib.use('TkAgg')  # Tkinter 用
matplotlib.use('Qt5Agg')  # PyQt5 用

# ヘッドレスサーバー用
matplotlib.use('Agg')

# バックエンド設定後にインポート
import matplotlib.pyplot as plt
```

## 関連リンク

- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/numpy">NumPy チートシート</router-link>
- <router-link to="/pandas">Pandas チートシート</router-link>
- <router-link to="/sklearn">scikit-learn チートシート</router-link>
- <router-link to="/datascience">データサイエンス チートシート</router-link>

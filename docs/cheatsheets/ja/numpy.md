---
title: 'NumPy チートシート | LabEx'
description: 'この包括的なチートシートで NumPy 数値計算を学ぶ。配列、線形代数、数学的演算、ブロードキャスト、Python 科学計算のクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/numpy-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
NumPy チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/numpy">Learn NumPy with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
LabEx では、ハンズオンラボと現実世界のシナリオを通じて NumPy 数値計算を学習できます。LabEx は、必須の配列操作、数学関数、線形代数、パフォーマンス最適化を網羅した包括的な NumPy コースを提供しています。データサイエンスのワークフローのために、効率的な数値計算と配列操作を習得しましょう。
</base-disclaimer-content>
</base-disclaimer>

## 配列の作成と初期化

### リストから：`np.array()`

Python のリストまたはネストされたリストから配列を作成します。

```python
import numpy as np

# リストからの 1D 配列
arr = np.array([1, 2, 3, 4])
# ネストされたリストからの 2D 配列
arr2d = np.array([[1, 2], [3, 4]])
# データ型を指定
arr = np.array([1, 2, 3], dtype=float)
# 文字列の配列
arr_str = np.array(['a', 'b', 'c'])
```

<BaseQuiz id="numpy-array-1" correct="C">
  <template #question>
    NumPy 配列が Python リストよりも優れている主な利点は何ですか？
  </template>
  
  <BaseQuizOption value="A">文字列を格納できること</BaseQuizOption>
  <BaseQuizOption value="B">作成が容易であること</BaseQuizOption>
  <BaseQuizOption value="C" correct>数値演算において高速でメモリ効率が良いこと</BaseQuizOption>
  <BaseQuizOption value="D">混合データ型を格納できること</BaseQuizOption>
  
  <BaseQuizAnswer>
    NumPy 配列は数値計算用に最適化されており、特に大規模データセットや数学的演算において、Python リストよりも高速な操作と効率的なメモリ使用量を提供します。
  </BaseQuizAnswer>
</BaseQuiz>

### ゼロとイチ：`np.zeros()` / `np.ones()`

ゼロまたはイチで埋められた配列を作成します。

```python
# ゼロの配列
zeros = np.zeros(5)  # 1D
zeros2d = np.zeros((3, 4))  # 2D
# イチの配列
ones = np.ones((2, 3))
# データ型を指定
zeros_int = np.zeros(5, dtype=int)
```

### 単位行列：`np.eye()` / `np.identity()`

線形代数演算のための単位行列を作成します。

```python
# 3x3 の単位行列
identity = np.eye(3)
# 代替メソッド
identity2 = np.identity(4)
```

### 範囲配列：`np.arange()` / `np.linspace()`

等間隔の値を持つ配列を作成します。

```python
# Python の range に似ている
arr = np.arange(10)  # 0 から 9 まで
arr = np.arange(2, 10, 2)  # 2, 4, 6, 8
# 等間隔の値
arr = np.linspace(0, 1, 5)  # 0 から 1 までの 5 つの値
# 終点を含む
arr = np.linspace(0, 10, 11)
```

### ランダム配列：`np.random`

ランダムな値を持つ配列を生成します。

```python
# 0 から 1 の間のランダムな値
rand = np.random.random((2, 3))
# ランダムな整数
rand_int = np.random.randint(0, 10, size=(3, 3))
# 正規分布
normal = np.random.normal(0, 1, size=5)
# 再現性のためのランダムシード設定
np.random.seed(42)
```

### 特殊な配列：`np.full()` / `np.empty()`

特定の値で埋める配列、または未初期化の配列を作成します。

```python
# 特定の値で埋める
full_arr = np.full((2, 3), 7)
# 空の配列（未初期化）
empty_arr = np.empty((2, 2))
# 既存の配列の形状に合わせる
like_arr = np.zeros_like(arr)
```

## 配列のプロパティと構造

### 基本プロパティ：`shape` / `size` / `ndim`

配列の次元とサイズに関する基本的な情報を取得します。

```python
# 配列の次元 (タプル)
arr.shape
# 要素の総数
arr.size
# 次元数
arr.ndim
# 要素のデータ型
arr.dtype
# 各要素のバイトサイズ
arr.itemsize
```

### 配列情報：メモリ使用量

配列のメモリ使用量と構造に関する詳細情報を取得します。

```python
# メモリ使用量 (バイト単位)
arr.nbytes
# 配列情報 (デバッグ用)
arr.flags
# 配列がデータを所有しているか確認
arr.owndata
# ベースオブジェクト (配列がビューの場合)
arr.base
```

### データ型：`astype()`

異なるデータ型間で効率的に変換します。

```python
# 異なる型への変換
arr.astype(float)
arr.astype(int)
arr.astype(str)
# より具体的な型
arr.astype(np.float32)
arr.astype(np.int16)
```

## 配列のインデックス指定とスライス

### 基本インデックス指定：`arr[index]`

個々の要素とスライスにアクセスします。

```python
# 単一要素
arr[0]  # 最初の要素
arr[-1]  # 最後の要素
# 2D 配列のインデックス指定
arr2d[0, 1]  # 0 行目、1 列目
arr2d[1]  # 1 行目全体
# スライス
arr[1:4]  # 1 番目から 3 番目の要素まで
arr[::2]  # 2 つおきの要素
arr[::-1]  # 配列を反転
```

### ブールインデックス指定：`arr[condition]`

条件に基づいて配列をフィルタリングします。

```python
# 単純な条件
arr[arr > 5]
# 複数の条件
arr[(arr > 2) & (arr < 8)]
arr[(arr < 2) | (arr > 8)]
# ブール配列
mask = arr > 3
filtered = arr[mask]
```

<BaseQuiz id="numpy-boolean-1" correct="C">
  <template #question>
    ブールインデックス指定 <code>arr[arr > 5]</code> は何を返しますか？
  </template>
  
  <BaseQuizOption value="A">ブール配列</BaseQuizOption>
  <BaseQuizOption value="B">元の配列</BaseQuizOption>
  <BaseQuizOption value="C" correct>5 より大きい要素のみを含む配列</BaseQuizOption>
  <BaseQuizOption value="D">エラー</BaseQuizOption>
  
  <BaseQuizAnswer>
    ブールインデックス指定は配列をフィルタリングし、条件が真である要素のみを返します。<code>arr[arr > 5]</code> は 5 より大きい値のみを含む新しい配列を返します。
  </BaseQuizAnswer>
</BaseQuiz>

### 高度なインデックス指定：Fancy Indexing

インデックスの配列を使用して複数の要素にアクセスします。

```python
# インデックス配列によるインデックス指定
indices = [0, 2, 4]
arr[indices]
# 2D ファンシーインデックス指定
arr2d[[0, 1], [1, 2]]  # 要素 (0,1) と (1,2)
# スライスとの組み合わせ
arr2d[1:, [0, 2]]
```

### Where 関数：`np.where()`

条件付きの選択と要素の置換を行います。

```python
# 条件が真であるインデックスを見つける
indices = np.where(arr > 5)
# 条件付き置換
result = np.where(arr > 5, arr, 0)  # 5 より大きい値を 0 に置換
# 複数の条件
result = np.where(arr > 5, 'high', 'low')
```

## 配列の操作とリシェイプ

### リシェイプ：`reshape()` / `resize()` / `flatten()`

データを保持したまま配列の次元を変更します。

```python
# リシェイプ (可能な場合はビューを作成)
arr.reshape(2, 3)
arr.reshape(-1, 1)  # -1 は次元を推測
# リサイズ (元の配列を変更)
arr.resize((2, 3))
# 1D にフラット化
arr.flatten()  # コピーを返す
arr.ravel()  # 可能な場合はビューを返す
```

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    <code>arr.reshape(-1, 1)</code> における <code>-1</code> は何を意味しますか？
  </template>
  
  <BaseQuizOption value="A">エラーを作成する</BaseQuizOption>
  <BaseQuizOption value="B" correct>配列サイズに基づいて次元を自動的に推測する</BaseQuizOption>
  <BaseQuizOption value="C">1D 配列を作成する</BaseQuizOption>
  <BaseQuizOption value="D">配列を反転する</BaseQuizOption>
  
  <BaseQuizAnswer>
    リシェイプで <code>-1</code> を使用すると、NumPy に配列の総サイズと指定された他の次元に基づいてその次元を自動的に計算するように指示します。これは、1 つの次元はわかっているが、もう一方の次元を NumPy に計算させたい場合に便利です。
  </BaseQuizAnswer>
</BaseQuiz>

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    <code>arr.reshape(-1, 1)</code> における <code>-1</code> は何を意味しますか？
  </template>
  
  <BaseQuizOption value="A">エラーを作成する</BaseQuizOption>
  <BaseQuizOption value="B" correct>NumPy が次元を自動的に推測する</BaseQuizOption>
  <BaseQuizOption value="C">その次元を削除する</BaseQuizOption>
  <BaseQuizOption value="D">次元を 1 に設定する</BaseQuizOption>
  
  <BaseQuizAnswer>
    リシェイプで <code>-1</code> を使用すると、NumPy に配列の総サイズと指定された他の次元に基づいてその次元を自動的に計算するように指示します。これは、1 つの次元はわかっているが、もう一方の次元を NumPy に計算させたい場合に便利です。
  </BaseQuizAnswer>
</BaseQuiz>

### 転置：`T` / `transpose()`

行列演算のために配列の軸を交換します。

```python
# 単純な転置
arr2d.T
# 軸指定による転置
arr.transpose()
np.transpose(arr)
# より高次元の場合
arr3d.transpose(2, 0, 1)
```

### 要素の追加/削除

要素の追加または削除による配列サイズの変更。

```python
# 要素の追加
np.append(arr, [4, 5])
# 特定の位置に挿入
np.insert(arr, 1, 99)
# 要素の削除
np.delete(arr, [1, 3])
# 要素の繰り返し
np.repeat(arr, 3)
np.tile(arr, 2)
```

### 配列の結合：`concatenate()` / `stack()`

複数の配列を結合します。

```python
# 既存の軸に沿った結合
np.concatenate([arr1, arr2])
np.concatenate([arr1, arr2], axis=1)
# 配列をスタック (新しい軸を作成)
np.vstack([arr1, arr2])  # 垂直方向
np.hstack([arr1, arr2])  # 水平方向
np.dstack([arr1, arr2])  # 奥行き方向
```

## 数学的な操作

### 基本的な算術：`+`, `-`, `*`, `/`

配列に対する要素ごとの算術演算。

```python
# 要素ごとの演算
arr1 + arr2
arr1 - arr2
arr1 * arr2  # 要素ごとの乗算
arr1 / arr2
arr1 ** 2  # 2 乗
arr1 % 3  # モジュロ演算
```

### ユニバーサル関数 (ufuncs)

数学関数を要素ごとに適用します。

```python
# 三角関数
np.sin(arr)
np.cos(arr)
np.tan(arr)
# 指数関数と対数関数
np.exp(arr)
np.log(arr)
np.log10(arr)
# 平方根とべき乗
np.sqrt(arr)
np.power(arr, 3)
```

### 集計関数

配列の次元にわたる要約統計量を計算します。

```python
# 基本的な統計
np.sum(arr)
np.mean(arr)
np.std(arr)  # 標準偏差
np.var(arr)  # 分散
np.min(arr)
np.max(arr)
# 特定の軸に沿って
np.sum(arr2d, axis=0)  # 行に沿った合計
np.mean(arr2d, axis=1)  # 列に沿った平均
```

### 比較演算

ブール配列を返す要素ごとの比較演算。

```python
# 比較演算子
arr > 5
arr == 3
arr != 0
# 配列比較
np.array_equal(arr1, arr2)
np.allclose(arr1, arr2)  # 許容誤差内
# Any/all 演算
np.any(arr > 5)
np.all(arr > 0)
```

## 線形代数

### 行列演算：`np.dot()` / `@`

行列乗算とドット積を実行します。

```python
# 行列乗算
np.dot(A, B)
A @ B  # Python 3.5 以降の演算子
# 要素ごとの乗算
A * B
# 行列べき乗
np.linalg.matrix_power(A, 3)
```

### 分解：`np.linalg`

高度な計算のための行列分解。

```python
# 固有値と固有ベクトル
eigenvals, eigenvecs = np.linalg.eig(A)
# 特異値分解
U, s, Vt = np.linalg.svd(A)
# QR 分解
Q, R = np.linalg.qr(A)
```

### 行列のプロパティ

重要な行列特性を計算します。

```python
# 行列式
np.linalg.det(A)
# 行列の逆
np.linalg.inv(A)
# 擬似逆行列
np.linalg.pinv(A)
# 行列のランク
np.linalg.matrix_rank(A)
# トレース (対角要素の合計)
np.trace(A)
```

### 線形システムの解法：`np.linalg.solve()`

連立一次方程式を解きます。

```python
# Ax = b を解く
x = np.linalg.solve(A, b)
# 最小二乗解
x = np.linalg.lstsq(A, b, rcond=None)[0]
```

## 配列の入出力

### NumPy バイナリ：`np.save()` / `np.load()`

NumPy 配列のための効率的なバイナリ形式。

```python
# 単一配列の保存
np.save('array.npy', arr)
# 配列の読み込み
loaded_arr = np.load('array.npy')
# 複数配列の保存
np.savez('arrays.npz', a=arr1, b=arr2)
# 複数配列の読み込み
data = np.load('arrays.npz')
arr1_loaded = data['a']
```

### テキストファイル：`np.loadtxt()` / `np.savetxt()`

配列をテキストファイルとして読み書きします。

```python
# CSV/テキストファイルからの読み込み
arr = np.loadtxt('data.csv', delimiter=',')
# ヘッダー行をスキップ
arr = np.loadtxt('data.csv', delimiter=',', skiprows=1)
# テキストファイルへの保存
np.savetxt('output.csv', arr, delimiter=',', fmt='%.2f')
```

### 構造化データを持つ CSV: `np.genfromtxt()`

欠損値処理を備えた高度なテキストファイル読み込み。

```python
# 欠損値の処理
arr = np.genfromtxt('data.csv', delimiter=',',
                    missing_values='N/A', filling_values=0)
# 名前付き列
data = np.genfromtxt('data.csv', delimiter=',',
                     names=True, dtype=None)
```

### メモリマップ：`np.memmap()`

メモリに収まらない配列を扱うために使用します。

```python
# メモリマップ配列の作成
mmap_arr = np.memmap('large_array.dat', dtype='float32',
                     mode='w+', shape=(1000000,))
# 通常の配列のようにアクセスするが、ディスクに保存されている
mmap_arr[0:10] = np.random.random(10)
```

## パフォーマンスとブロードキャスト

### ブロードキャストのルール

異なる形状の配列に対する演算の処理方法を理解します。

```python
# ブロードキャストの例
arr1 = np.array([[1, 2, 3]])  # 形状 (1, 3)
arr2 = np.array([[1], [2]])   # 形状 (2, 1)
result = arr1 + arr2          # 形状 (2, 3)
# スカラーのブロードキャスト
arr + 5  # 全要素に 5 を加算
arr * 2  # 全要素を 2 倍
```

### ベクトル化された演算

Python ループの代わりに NumPy の組み込み関数を使用します。

```python
# ループの代わりにベクトル化された演算を使用
# 悪い例：for ループ
result = []
for x in arr:
    result.append(x ** 2)
# 良い例：ベクトル化
result = arr ** 2
# カスタムベクトル化関数
def custom_func(x):
    return x ** 2 + 2 * x + 1
vec_func = np.vectorize(custom_func)
result = vec_func(arr)
```

### メモリ最適化

大規模配列のメモリ使用効率を高めるためのテクニック。

```python
# 適切なデータ型を使用
arr_int8 = arr.astype(np.int8)  # 要素あたり 1 バイト
arr_float32 = arr.astype(np.float32)  # float64 の代わりに 4 バイト
# ビューとコピー
view = arr[::2]  # ビューを作成 (メモリを共有)
copy = arr[::2].copy()  # コピーを作成 (新しいメモリ)
# 配列がビューかコピーかを確認
view.base is arr  # ビューの場合は True
```

### パフォーマンスのヒント

高速な NumPy コードのためのベストプラクティス。

```python
# 可能な場合はインプレース操作を使用
arr += 5  # arr = arr + 5 の代わりに
np.add(arr, 5, out=arr)  # 明示的なインプレース
# 中間配列の作成を最小限に抑える
# 悪い例：中間配列を作成
result = ((arr + 1) * 2) ** 2
# より良い例：可能な場合は複合演算を使用
```

## 乱数生成

### 基本的な乱数：`np.random`

様々な分布から乱数を生成します。

```python
# ランダムな浮動小数点数 [0, 1)
np.random.random(5)
# ランダムな整数
np.random.randint(0, 10, size=5)
# 正規分布
np.random.normal(mu=0, sigma=1, size=5)
# 一様分布
np.random.uniform(-1, 1, size=5)
```

### サンプリング：`choice()` / `shuffle()`

既存のデータからサンプリングしたり、配列を並べ替えたりします。

```python
# 配列からのランダムな選択
np.random.choice(arr, size=3)
# 非復元抽出
np.random.choice(arr, size=3, replace=False)
# 配列をインプレースでシャッフル
np.random.shuffle(arr)
# ランダムな順列
np.random.permutation(arr)
```

### シードとジェネレータ

再現性のために乱数を制御します。

```python
# 再現性のためのシード設定
np.random.seed(42)
# 最新のアプローチ：Generator
rng = np.random.default_rng(42)
rng.random(5)
rng.integers(0, 10, size=5)
rng.normal(0, 1, size=5)
```

## 統計関数

### 記述統計

中心傾向とばらつきの基本的な統計量。

```python
# 中心傾向
np.mean(arr)
np.median(arr)
# ばらつきの尺度
np.std(arr)  # 標準偏差
np.var(arr)  # 分散
np.ptp(arr)  # ピークからピーク (max - min)
# パーセンタイル
np.percentile(arr, [25, 50, 75])
np.quantile(arr, [0.25, 0.5, 0.75])
```

### 相関と共分散

変数間の関係性を測定します。

```python
# 相関係数
np.corrcoef(x, y)
# 共分散
np.cov(x, y)
# クロス相関
np.correlate(x, y, mode='full')
```

### ヒストグラムとビニング

データの分布を分析し、ビンを作成します。

```python
# ヒストグラム
counts, bins = np.histogram(arr, bins=10)
# 2D ヒストグラム
H, xedges, yedges = np.histogram2d(x, y, bins=10)
# デジタル化 (ビンインデックスの割り当て)
bin_indices = np.digitize(arr, bins)
```

### 特殊な統計関数

高度な統計計算。

```python
# 加重統計
np.average(arr, weights=weights)
# 一意な値とカウント
unique_vals, counts = np.unique(arr, return_counts=True)
# ビンカウント (整数配列用)
np.bincount(int_arr)
```

## NumPy のインストールとセットアップ

### Pip: `pip install numpy`

標準的な Python パッケージインストーラ。

```bash
# NumPyをインストール
pip install numpy
# 最新バージョンにアップグレード
pip install numpy --upgrade
# 特定のバージョンをインストール
pip install numpy==1.21.0
# パッケージ情報を表示
pip show numpy
```

### Conda: `conda install numpy`

Anaconda/Miniconda環境用のパッケージマネージャ。

```bash
# 現在の環境にNumPyをインストール
conda install numpy
# NumPyを更新
conda update numpy
# conda-forgeからインストール
conda install -c conda-forge numpy
# 環境を作成してNumPyをインストール
conda create -n myenv numpy
```

### インストールの確認とインポート

NumPy のインストールを確認し、標準的なインポートを行います。

```python
# 標準的なインポート
import numpy as np
# バージョンの確認
print(np.__version__)
# ビルド情報の表示
np.show_config()
# 印刷オプションの設定
np.set_printoptions(precision=2, suppress=True)
```

## 高度な機能

### 構造化配列

複雑なデータ構造のための名前付きフィールドを持つ配列。

```python
# 構造化データ型の定義
dt = np.dtype([('name', 'U10'), ('age', 'i4'), ('weight', 'f4')])
# 構造化配列の作成
people = np.array([('Alice', 25, 55.0), ('Bob', 30, 70.5)], dtype=dt)
# フィールドへのアクセス
people['name']
people['age']
```

### マスク配列：`np.ma`

欠損データや無効なデータを持つ配列を扱います。

```python
# マスク配列の作成
masked_arr = np.ma.array([1, 2, 3, 4, 5], mask=[0, 0, 1, 0, 0])
# マスクされた値は演算で無視される
np.ma.mean(masked_arr)
# マスクされた値を埋める
filled = masked_arr.filled(0)
```

### 多項式：`np.poly1d`

多項式表現とその操作を扱います。

```python
# 多項式の作成 (係数は降順)
p = np.poly1d([1, -2, 1])  # x² - 2x + 1
# 多項式の評価
p(5)  # x=5 で評価
# 根の検索
np.roots([1, -2, 1])
# 多項式フィッティング
coeff = np.polyfit(x, y, degree=2)
```

### 高速フーリエ変換：`np.fft`

周波数領域解析と信号処理。

```python
# 1D FFT
fft_result = np.fft.fft(signal)
# 周波数
freqs = np.fft.fftfreq(len(signal))
# 逆 FFT
reconstructed = np.fft.ifft(fft_result)
# 画像の 2D FFT
fft2d = np.fft.fft2(image)
```

## 関連リンク

- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/pandas">Pandas チートシート</router-link>
- <router-link to="/matplotlib">Matplotlib チートシート</router-link>
- <router-link to="/sklearn">scikit-learn チートシート</router-link>
- <router-link to="/datascience">データサイエンス チートシート</router-link>

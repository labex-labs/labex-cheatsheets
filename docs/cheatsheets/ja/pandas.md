---
title: 'Pandas チートシート'
description: '必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートで Pandas を習得しましょう。'
pdfUrl: '/cheatsheets/pdf/pandas-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Pandas チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/pandas">ハンズオンラボで Pandas を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、Pandas データ操作を学びましょう。LabEx は、必須操作、データクレンジング、分析、視覚化を網羅した包括的な Pandas コースを提供しています。DataFrame の操作、欠損データの処理、集計の実行、Python の強力なデータ分析ライブラリを使用したデータセットの効率的な分析方法を学びます。
</base-disclaimer-content>
</base-disclaimer>

## データの読み込みと保存

### CSV の読み込み：`pd.read_csv()`

CSV ファイルから DataFrame にデータをロードします。

```python
import pandas as pd
# CSV ファイルを読み込む
df = pd.read_csv('data.csv')
# 最初の列をインデックスとして設定
df = pd.read_csv('data.csv', index_col=0)
# 異なる区切り文字を指定
df = pd.read_csv('data.csv', sep=';')
# 日付をパース
df = pd.read_csv('data.csv', parse_dates=['Date'])
```

### Excel の読み込み：`pd.read_excel()`

Excel ファイルからデータをロードします。

```python
# 最初のシートを読み込む
df = pd.read_excel('data.xlsx')
# 特定のシートを読み込む
df = pd.read_excel('data.xlsx', sheet_name='Sheet2')
# 2 行目（0 から数えて）をヘッダーとして設定
df = pd.read_excel('data.xlsx', header=1)
```

### SQL の読み込み：`pd.read_sql()`

SQL クエリまたはテーブルを DataFrame に読み込みます。

```python
from sqlalchemy import create_engine
engine = create_engine('sqlite:///my_database.db')
df = pd.read_sql('SELECT * FROM users', engine)
df = pd.read_sql_table('products', engine)
```

### CSV への保存：`df.to_csv()`

DataFrame を CSV ファイルに書き出します。

```python
# インデックス列を除外
df.to_csv('output.csv', index=False)
# ヘッダー行を除外
df.to_csv('output.csv', header=False)
```

### Excel への保存：`df.to_excel()`

DataFrame を Excel ファイルに書き出します。

```python
# Excel に保存
df.to_excel('output.xlsx', sheet_name='Results')
writer = pd.ExcelWriter('output.xlsx')
df1.to_excel(writer, sheet_name='Sheet1')
df2.to_excel(writer, sheet_name='Sheet2')
writer.save()
```

### SQL への保存：`df.to_sql()`

DataFrame を SQL データベースのテーブルに書き込みます。

```python
# テーブルを作成/置き換え
df.to_sql('new_table', engine, if_exists='replace', index=False)
# 既存のテーブルに追加
df.to_sql('existing_table', engine, if_exists='append')
```

## DataFrame のインフォメーションと構造

### 基本情報：`df.info()`

DataFrame の簡潔な概要（データ型や非 Null 値を含む）を出力します。

```python
# DataFrame の概要を表示
df.info()
# 各列のデータ型を表示
df.dtypes
# 行数と列数（タプル）を取得
df.shape
# 列名を取得
df.columns
# 行インデックスを取得
df.index
```

### 記述統計：`df.describe()`

数値列の記述統計量を生成します。

```python
# 数値列の要約統計量
df.describe()
# 特定の列の要約
df['column'].describe()
# すべての列を含める（object 型も）
df.describe(include='all')
```

### データの表示：`df.head()` / `df.tail()`

DataFrame の先頭または末尾の 'n' 行を表示します。

```python
# 最初の 5 行
df.head()
# 最後の 10 行
df.tail(10)
# ランダムな 5 行
df.sample(5)
```

## データクレンジングと変換

### 欠損値：`isnull()` / `fillna()` / `dropna()`

欠損値 (NaN) を特定、補完、または削除します。

```python
# 列ごとの欠損値の数をカウント
df.isnull().sum()
# すべての NaN を 0 で埋める
df.fillna(0)
# 列の平均値で埋める
df['col'].fillna(df['col'].mean())
# 任意の NaN を含む行を削除
df.dropna()
# 任意の NaN を含む列を削除
df.dropna(axis=1)
```

### 複製：`duplicated()` / `drop_duplicates()`

重複する行を特定し、削除します。

```python
# 重複を示すブール値の Series
df.duplicated()
# すべての重複行を削除
df.drop_duplicates()
# 特定の列に基づいて削除
df.drop_duplicates(subset=['col1', 'col2'])
```

### データ型：`astype()`

列のデータ型を変更します。

```python
# 整数型に変更
df['col'].astype(int)
# 文字列型に変更
df['col'].astype(str)
# datetime 型に変換
df['col'] = pd.to_datetime(df['col'])
```

### 関数の適用：`apply()` / `map()` / `replace()`

DataFrame/Seriesに関数を適用したり、値を置換したりします。

```python
# 列に関数を適用 (lambda)
df['col'].apply(lambda x: x*2)
# 辞書を使用して値をマッピング
df['col'].map({'old': 'new'})
# 値を置換
df.replace('old_val', 'new_val')
# 複数の値を置換
df.replace(['A', 'B'], ['C', 'D'])
```

## DataFrame の検査

### 一意な値：`unique()` / `value_counts()`

一意な値とその頻度を調べます。

```python
# 列の一意な値を取得
df['col'].unique()
# 一意な値の数を取得
df['col'].nunique()
# 各一意な値の出現回数をカウント
df['col'].value_counts()
# 一意な値の割合
df['col'].value_counts(normalize=True)
```

### 相関：`corr()` / `cov()`

数値列間の相関と共分散を計算します。

```python
# 列間のペアワイズ相関
df.corr()
# 列間のペアワイズ共分散
df.cov()
# 2 つの特定の列間の相関
df['col1'].corr(df['col2'])
```

### 集計：`groupby()` / `agg()`

カテゴリ別にデータをグループ化し、集計関数を適用します。

```python
# カテゴリごとの平均値
df.groupby('category_col').mean()
# 複数の列でグループ化
df.groupby(['col1', 'col2']).sum()
# 複数の集計
df.groupby('category_col').agg({'num_col': ['min', 'max', 'mean']})
```

### クロス集計：`pd.crosstab()`

2 つ以上の要因の頻度表を計算します。

```python
df.pivot_table(values='sales', index='region', columns='product', aggfunc='sum')
# 単純な頻度表
pd.crosstab(df['col1'], df['col2'])
# 行/列の合計付き
pd.crosstab(df['col1'], df['col2'], margins=True)
# 集計値付き
pd.crosstab(df['col1'], df['col2'], values=df['value_col'], aggfunc='mean')
```

## メモリ管理

### メモリ使用量：`df.memory_usage()`

各列または DataFrame 全体のメモリ使用量を表示します。

```python
# 各列のメモリ使用量
df.memory_usage()
# 合計メモリ使用量（バイト単位）
df.memory_usage(deep=True).sum()
# info() 出力の詳細なメモリ使用量
df.info(memory_usage='deep')
```

### Dtype の最適化：`astype()`

より小さく適切なデータ型に列を変換することでメモリを削減します。

```python
# 整数をダウンキャスト
df['int_col'] = df['int_col'].astype('int16')
# 浮動小数点数をダウンキャスト
df['float_col'] = df['float_col'].astype('float32')
# カテゴリ型を使用
df['category_col'] = df['category_col'].astype('category')
```

### 大容量ファイルのチャンク処理：`read_csv(chunksize=...)`

一度にすべてをメモリにロードするのを避けるため、大きなファイルをチャンク単位で処理します。

```python
chunk_iterator = pd.read_csv('large_data.csv', chunksize=10000)
for chunk in chunk_iterator:
    # 各チャンクを処理
    print(chunk.shape)
# 処理されたチャンクを結合（必要な場合）
# processed_chunks = []
# for chunk in chunk_iterator:
#    processed_chunks.append(process_chunk(chunk))
# final_df = pd.concat(processed_chunks)
```

## データインポート/エクスポート

### JSON の読み込み：`pd.read_json()`

JSON ファイルまたは URL からデータをロードします。

```python
# ローカル JSON から読み込み
df = pd.read_json('data.json')
# URL から読み込み
df = pd.read_json('http://example.com/api/data')
# JSON 文字列から読み込み
df = pd.read_json(json_string_data)
```

### HTML の読み込み：`pd.read_html()`

URL、文字列、またはファイルから HTML テーブルを解析します。

```python
tables = pd.read_html('http://www.w3.org/TR/html401/sgml/entities.html')
# 通常、DataFrame のリストが返される
df = tables[0]
```

### JSON への書き出し：`df.to_json()`

DataFrame を JSON 形式に書き出します。

```python
# JSON ファイルへ
df.to_json('output.json', orient='records', indent=4)
# JSON 文字列へ
json_str = df.to_json(orient='split')
```

### HTML への書き出し：`df.to_html()`

DataFrame を HTML テーブルとしてレンダリングします。

```python
# HTML 文字列へ
html_table_str = df.to_html()
# HTML ファイルへ
df.to_html('output.html', index=False)
```

### クリップボードからの読み込み：`pd.read_clipboard()`

クリップボードからテキストを DataFrame に読み込みます。

```python
# Web やスプレッドシートから表データをコピーして実行
df = pd.read_clipboard()
```

## データシリアライゼーション

### Pickle: `df.to_pickle()` / `pd.read_pickle()`

Pandas オブジェクトをディスクにシリアライズ/デシリアライズします。

```python
# DataFrame を pickle ファイルとして保存
df.to_pickle('my_dataframe.pkl')
# DataFrame をロード
loaded_df = pd.read_pickle('my_dataframe.pkl')
```

### HDF5: `df.to_hdf()` / `pd.read_hdf()`

HDF5 形式を使用して DataFrame を保存/ロードします。大規模データセットに適しています。

```python
# HDF5 に保存
df.to_hdf('my_data.h5', key='df', mode='w')
# HDF5 からロード
loaded_df = pd.read_hdf('my_data.h5', key='df')
```

## データのフィルタリングと選択

### ラベルベース：`df.loc[]` / `df.at[]`

インデックス/列の明示的なラベルでデータを選択します。

```python
# インデックス 0 の行を選択
df.loc[0]
# 'col1'のすべての行を選択
df.loc[:, 'col1']
# 行のスライスと複数の列の選択
df.loc[0:5, ['col1', 'col2']]
# 行のブールインデックス指定
df.loc[df['col'] > 5]
# ラベルによる高速なスカラーアクセス
df.at[0, 'col1']
```

### 位置ベース：`df.iloc[]` / `df.iat[]`

インデックス/列の整数位置でデータを選択します。

```python
# 位置で最初の行を選択
df.iloc[0]
# 位置で最初の列を選択
df.iloc[:, 0]
# 行のスライスと複数の列の位置による選択
df.iloc[0:5, [0, 1]]
# 位置による高速なスカラーアクセス
df.iat[0, 0]
```

### ブールインデックス指定：`df[condition]`

1 つ以上の条件に基づいて行をフィルタリングします。

```python
# 'col1'が 10 より大きい行
df[df['col1'] > 10]
# 複数の条件
df[(df['col1'] > 10) & (df['col2'] == 'A')]
# 'col1'がリスト [1, 2, 3] に含まれていない行
df[~df['col1'].isin([1, 2, 3])]
```

### クエリによるデータ検索：`df.query()`

クエリ文字列式を使用して行をフィルタリングします。

```python
# ブールインデックス指定と同等
df.query('col1 > 10')
# 複雑なクエリ
df.query('col1 > 10 and col2 == "A"')
# '@'を使用してローカル変数を参照
df.query('col1 in @my_list')
```

## パフォーマンス監視

### 操作のタイミング測定：`%%timeit` / `time`

Python/Pandasコードの実行時間を測定します。

```python
# 1 行/セルのタイミング測定のための Jupyter/IPython マジックコマンド
%%timeit
df['col'].apply(lambda x: x*2) # 例の操作

import time
start_time = time.time()
# ここに Pandas コードを記述
end_time = time.time()
print(f"実行時間：{end_time - start_time} 秒")
```

### 最適化された操作：`eval()` / `query()`

特に大規模な DataFrame での要素ごとの操作やフィルタリングにおいて、これらのメソッドを利用して高速なパフォーマンスを実現します。

```python
# `df['col1'] + df['col2']` よりも高速
df['new_col'] = df.eval('col1 + col2')
# 高速なフィルタリング
df_filtered = df.query('col1 > @threshold and col2 == "value"')
```

### コードのプロファイリング：`cProfile` / `line_profiler`

Python 関数のどこに時間が費やされているかを分析します。

```python
import cProfile
def my_pandas_function(df):
    # Pandas 操作
    return df.groupby('col').mean()
cProfile.run('my_pandas_function(df)') # cProfile で関数を実行

# line_profiler の場合 (pip install line_profiler でインストール):
# @profile
# def my_function(df):
#    ...
# %load_ext line_profiler
# %lprun -f my_function my_function(df)
```

## Pandas のインストールとセットアップ

### Pip: `pip install pandas`

標準的な Python パッケージインストーラです。

```python
# Pandas をインストール
pip install pandas
# Pandas を最新バージョンにアップグレード
pip install pandas --upgrade
# インストールされている Pandas パッケージの情報を表示
pip show pandas
```

### Conda: `conda install pandas`

Anaconda/Miniconda環境用のパッケージマネージャです。

```python
# 現在の conda 環境に Pandas をインストール
conda install pandas
# Pandas を更新
conda update pandas
# インストールされている Pandas パッケージをリスト表示
conda list pandas
# Pandas を含む新しい環境を作成
conda create -n myenv pandas
```

### バージョンの確認 / インポート

Pandas のインストールを確認し、スクリプトでインポートします。

```python
# 標準的なインポートエイリアス
import pandas as pd
# インストールされている Pandas のバージョンを確認
print(pd.__version__)
# すべての列を表示
pd.set_option('display.max_columns', None)
# より多くの行を表示
pd.set_option('display.max_rows', 100)
```

## 設定とオプション

### 表示オプション：`pd.set_option()`

コンソール/Jupyter での DataFrame の表示方法を制御します。

```python
# 表示する最大行数
pd.set_option('display.max_rows', 50)
# すべての列を表示
pd.set_option('display.max_columns', None)
# 表示幅
pd.set_option('display.width', 1000)
# 浮動小数点数の書式設定
pd.set_option('display.float_format', '{:.2f}'.format)
```

### オプションのリセット：`pd.reset_option()`

特定のオプションまたはすべてのオプションをデフォルト値にリセットします。

```python
# 特定のオプションをリセット
pd.reset_option('display.max_rows')
# すべてのオプションをデフォルトにリセット
pd.reset_option('all')
```

### オプションの取得：`pd.get_option()`

指定されたオプションの現在の値を取得します。

```python
# 現在の max_rows 設定を取得
print(pd.get_option('display.max_rows'))
```

### コンテキストマネージャ：`pd.option_context()`

`with` ステートメント内でオプションを一時的に設定します。

```python
with pd.option_context('display.max_rows', 10, 'display.max_columns', 5):
    print(df) # 一時的なオプションで DataFrame が表示される
print(df) # ブロックの外ではオプションは以前の設定に戻る
```

## メソッドチェーン

### チェーン操作

一連の変換を DataFrame に適用します。

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

### `.pipe()` の使用

DataFrame を最初の引数として受け取る関数を適用できるようにし、チェーン内のカスタムステップを可能にします。

```python
def custom_filter(df, threshold):
    return df[df['value'] > threshold]

(
    df.pipe(custom_filter, threshold=50)
    .groupby('group')
    .agg(total_value=('value', 'sum'))
)
```

## 関連リンク

- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/numpy">NumPy チートシート</router-link>
- <router-link to="/matplotlib">Matplotlib チートシート</router-link>
- <router-link to="/sklearn">scikit-learn チートシート</router-link>
- <router-link to="/datascience">データサイエンス チートシート</router-link>
- <router-link to="/mysql">MySQL チートシート</router-link>
- <router-link to="/postgresql">PostgreSQL チートシート</router-link>
- <router-link to="/sqlite">SQLite チートシート</router-link>

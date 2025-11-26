---
title: 'Pandas 速查表'
description: '使用我们涵盖基本命令、概念和最佳实践的 Pandas 全面速查表进行学习。'
pdfUrl: '/cheatsheets/pdf/pandas-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Pandas 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/pandas">通过实践实验室学习 Pandas</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Pandas 数据操作。LabEx 提供全面的 Pandas 课程，涵盖基本操作、数据清洗、分析和可视化。学习如何使用 Python 强大的数据分析库来处理 DataFrame、处理缺失数据、执行聚合和高效分析数据集。
</base-disclaimer-content>
</base-disclaimer>

## 数据加载与保存

### 读取 CSV: `pd.read_csv()`

将数据从 CSV 文件加载到 DataFrame。

```python
import pandas as pd
# 读取一个 CSV 文件
df = pd.read_csv('data.csv')
# 将第一列设为索引
df = pd.read_csv('data.csv', index_col=0)
# 指定不同的分隔符
df = pd.read_csv('data.csv', sep=';')
# 解析日期
df = pd.read_csv('data.csv', parse_dates=['Date'])
```

### 读取 Excel: `pd.read_excel()`

从 Excel 文件加载数据。

```python
# 读取第一个工作表
df = pd.read_excel('data.xlsx')
# 读取指定工作表
df = pd.read_excel('data.xlsx', sheet_name='Sheet2')
# 将第 2 行设为标题行 (0 索引)
df = pd.read_excel('data.xlsx', header=1)
```

### 读取 SQL: `pd.read_sql()`

将 SQL 查询或表读入 DataFrame。

```python
from sqlalchemy import create_engine
engine = create_engine('sqlite:///my_database.db')
df = pd.read_sql('SELECT * FROM users', engine)
df = pd.read_sql_table('products', engine)
```

### 保存 CSV: `df.to_csv()`

将 DataFrame 写入 CSV 文件。

```python
# 排除索引列
df.to_csv('output.csv', index=False)
# 排除标题行
df.to_csv('output.csv', header=False)
```

### 保存 Excel: `df.to_excel()`

将 DataFrame 写入 Excel 文件。

```python
# 保存到 Excel
df.to_excel('output.xlsx', sheet_name='Results')
writer = pd.ExcelWriter('output.xlsx')
df1.to_excel(writer, sheet_name='Sheet1')
df2.to_excel(writer, sheet_name='Sheet2')
writer.save()
```

### 保存 SQL: `df.to_sql()`

将 DataFrame 写入 SQL 数据库表。

```python
# 创建/替换表
df.to_sql('new_table', engine, if_exists='replace', index=False)
# 追加到现有表
df.to_sql('existing_table', engine, if_exists='append')
```

## DataFrame 信息与结构

### 基本信息：`df.info()`

打印 DataFrame 的简洁摘要，包括数据类型和非空值。

```python
# 显示 DataFrame 摘要
df.info()
# 显示每列的数据类型
df.dtypes
# 获取行数和列数 (元组)
df.shape
# 获取列名
df.columns
# 获取行索引
df.index
```

### 描述性统计：`df.describe()`

生成数值列的描述性统计信息。

```python
# 数值列的摘要统计
df.describe()
# 特定列的摘要
df['column'].describe()
# 包含所有列 (也包括 object 类型)
df.describe(include='all')
```

### 查看数据：`df.head()` / `df.tail()`

显示 DataFrame 的前 'n' 行或后 'n' 行。

```python
# 前 5 行
df.head()
# 后 10 行
df.tail(10)
# 随机 5 行
df.sample(5)
```

## 数据清洗与转换

### 缺失值：`isnull()` / `fillna()` / `dropna()`

识别、填充或删除缺失 (NaN) 值。

```python
# 统计每列的缺失值数量
df.isnull().sum()
# 用 0 填充所有 NaN
df.fillna(0)
# 用列均值填充
df['col'].fillna(df['col'].mean())
# 删除任何包含 NaN 的行
df.dropna()
# 删除任何包含 NaN 的列
df.dropna(axis=1)
```

### 重复项：`duplicated()` / `drop_duplicates()`

识别并删除重复的行。

```python
# 指示重复项的布尔序列
df.duplicated()
# 删除所有重复行
df.drop_duplicates()
# 基于特定列删除重复项
df.drop_duplicates(subset=['col1', 'col2'])
```

### 数据类型：`astype()`

更改列的数据类型。

```python
# 更改为整数
df['col'].astype(int)
# 更改为字符串
df['col'].astype(str)
# 转换为 datetime
df['col'] = pd.to_datetime(df['col'])
```

### 应用函数：`apply()` / `map()` / `replace()`

在 DataFrame/Series 上应用函数或替换值。

```python
# 对列应用 lambda 函数
df['col'].apply(lambda x: x*2)
# 使用字典映射值
df['col'].map({'old': 'new'})
# 替换值
df.replace('old_val', 'new_val')
# 替换多个值
df.replace(['A', 'B'], ['C', 'D'])
```

## DataFrame 检查

### 唯一值：`unique()` / `value_counts()`

探索唯一值及其频率。

```python
# 获取列中的唯一值
df['col'].unique()
# 获取唯一值的数量
df['col'].nunique()
# 计算每个唯一值的出现次数
df['col'].value_counts()
# 唯一值的比例
df['col'].value_counts(normalize=True)
```

### 相关性：`corr()` / `cov()`

计算数值列之间的相关性和协方差。

```python
# 列的成对相关性
df.corr()
# 列的成对协方差
df.cov()
# 两个特定列之间的相关性
df['col1'].corr(df['col2'])
```

### 聚合：`groupby()` / `agg()`

按类别对数据进行分组并应用聚合函数。

```python
# 每个类别的均值
df.groupby('category_col').mean()
# 按多列分组
df.groupby(['col1', 'col2']).sum()
# 多重聚合
df.groupby('category_col').agg({'num_col': ['min', 'max', 'mean']})
```

### 交叉表：`pd.crosstab()`

计算两个或多个因子的频率表。

```python
df.pivot_table(values='sales', index='region', columns='product', aggfunc='sum')
# 简单的频率表
pd.crosstab(df['col1'], df['col2'])
# 带行列总计
pd.crosstab(df['col1'], df['col2'], margins=True)
# 带聚合值
pd.crosstab(df['col1'], df['col2'], values=df['value_col'], aggfunc='mean')
```

## 内存管理

### 内存使用：`df.memory_usage()`

显示每列或整个 DataFrame 的内存使用情况。

```python
# 每列的内存使用情况
df.memory_usage()
# 总内存使用量 (字节)
df.memory_usage(deep=True).sum()
# info() 输出中的详细内存使用情况
df.info(memory_usage='deep')
```

### 优化 Dtypes: `astype()`

通过转换为更小、更合适的 Dtype 来减少内存占用。

```python
# 降级整数类型
df['int_col'] = df['int_col'].astype('int16')
# 降级浮点数类型
df['float_col'] = df['float_col'].astype('float32')
# 使用分类类型
df['category_col'] = df['category_col'].astype('category')
```

### 分块处理大文件：`read_csv(chunksize=...)`

分块处理大文件，避免一次性将所有内容加载到内存中。

```python
chunk_iterator = pd.read_csv('large_data.csv', chunksize=10000)
for chunk in chunk_iterator:
    # 处理每个分块
    print(chunk.shape)
# 如果需要，连接处理后的分块
# processed_chunks = []
# for chunk in chunk_iterator:
#    processed_chunks.append(process_chunk(chunk))
# final_df = pd.concat(processed_chunks)
```

## 数据导入/导出

### 读取 JSON: `pd.read_json()`

从 JSON 文件或 URL 加载数据。

```python
# 从本地 JSON 读取
df = pd.read_json('data.json')
# 从 URL 读取
df = pd.read_json('http://example.com/api/data')
# 从 JSON 字符串读取
df = pd.read_json(json_string_data)
```

### 读取 HTML: `pd.read_html()`

解析来自 URL、字符串或文件的 HTML 表格。

```python
tables = pd.read_html('http://www.w3.org/TR/html401/sgml/entities.html')
# 通常返回一个 DataFrame 列表
df = tables[0]
```

### 转 JSON: `df.to_json()`

将 DataFrame 写入 JSON 格式。

```python
# 写入 JSON 文件
df.to_json('output.json', orient='records', indent=4)
# 写入 JSON 字符串
json_str = df.to_json(orient='split')
```

### 转 HTML: `df.to_html()`

将 DataFrame 渲染为 HTML 表格。

```python
# 写入 HTML 字符串
html_table_str = df.to_html()
# 写入 HTML 文件
df.to_html('output.html', index=False)
```

### 读取剪贴板：`pd.read_clipboard()`

将剪贴板中的文本读入 DataFrame。

```python
# 从网页/电子表格复制表格数据并运行
df = pd.read_clipboard()
```

## 数据序列化

### Pickle: `df.to_pickle()` / `pd.read_pickle()`

将 Pandas 对象序列化/反序列化到磁盘。

```python
# 将 DataFrame 保存为 pickle 文件
df.to_pickle('my_dataframe.pkl')
# 加载 DataFrame
loaded_df = pd.read_pickle('my_dataframe.pkl')
```

### HDF5: `df.to_hdf()` / `pd.read_hdf()`

使用 HDF5 格式存储/加载 DataFrame，适用于大型数据集。

```python
# 保存到 HDF5
df.to_hdf('my_data.h5', key='df', mode='w')
# 从 HDF5 加载
loaded_df = pd.read_hdf('my_data.h5', key='df')
```

## 数据过滤与选择

### 基于标签：`df.loc[]` / `df.at[]`

按索引/列的显式标签选择数据。

```python
# 选择索引为 0 的行
df.loc[0]
# 选择 'col1' 的所有行
df.loc[:, 'col1']
# 切片行并选择多列
df.loc[0:5, ['col1', 'col2']]
# 布尔索引选择行
df.loc[df['col'] > 5]
# 按标签快速访问标量值
df.at[0, 'col1']
```

### 基于位置：`df.iloc[]` / `df.iat[]`

按索引/列的整数位置选择数据。

```python
# 按位置选择第一行
df.iloc[0]
# 按位置选择第一列
df.iloc[:, 0]
# 切片行并按位置选择多列
df.iloc[0:5, [0, 1]]
# 按位置快速访问标量值
df.iat[0, 0]
```

### 布尔索引：`df[condition]`

根据一个或多个条件过滤行。

```python
# 'col1' 大于 10 的行
df[df['col1'] > 10]
# 多条件
df[(df['col1'] > 10) & (df['col2'] == 'A')]
# 'col1' 不在列表中的行
df[~df['col1'].isin([1, 2, 3])]
```

### 查询数据：`df.query()`

使用查询字符串表达式过滤行。

```python
# 等同于布尔索引
df.query('col1 > 10')
# 复杂查询
df.query('col1 > 10 and col2 == "A"')
# 使用 '@' 引用局部变量
df.query('col1 in @my_list')
```

## 性能监控

### 计时操作：`%%timeit` / `time`

测量 Python/Pandas 代码的执行时间。

```python
# 用于计时单行/单元格的 Jupyter/IPython 魔术命令
%%timeit
df['col'].apply(lambda x: x*2) # 示例操作

import time
start_time = time.time()
# 您的 Pandas 代码放在这里
end_time = time.time()
print(f"Execution time: {end_time - start_time} seconds")
```

### 优化操作：`eval()` / `query()`

在大型 DataFrame 上利用这些方法以获得更快的性能，尤其适用于逐元素操作和过滤。

```python
# 比 `df['col1'] + df['col2']` 更快
df['new_col'] = df.eval('col1 + col2')
# 更快的过滤
df_filtered = df.query('col1 > @threshold and col2 == "value"')
```

### 代码分析：`cProfile` / `line_profiler`

分析代码中时间花费最多的部分。

```python
import cProfile
def my_pandas_function(df):
    # Pandas 操作
    return df.groupby('col').mean()
cProfile.run('my_pandas_function(df)') # 使用 cProfile 运行函数

# 对于 line_profiler (使用 pip install line_profiler 安装):
# @profile
# def my_function(df):
#    ...
# %load_ext line_profiler
# %lprun -f my_function my_function(df)
```

## Pandas 安装与设置

### Pip: `pip install pandas`

标准的 Python 包安装程序。

```python
# 安装 Pandas
pip install pandas
# 将 Pandas 升级到最新版本
pip install pandas --upgrade
# 显示已安装的 Pandas 包信息
pip show pandas
```

### Conda: `conda install pandas`

Anaconda/Miniconda 环境的包管理器。

```python
# 在当前 conda 环境中安装 Pandas
conda install pandas
# 更新 Pandas
conda update pandas
# 列出已安装的 Pandas 包
conda list pandas
# 创建包含 Pandas 的新环境
conda create -n myenv pandas
```

### 检查版本 / 导入

在脚本中验证您的 Pandas 安装并导入它。

```python
# 标准导入别名
import pandas as pd
# 检查已安装的 Pandas 版本
print(pd.__version__)
# 显示所有列
pd.set_option('display.max_columns', None)
# 显示更多行
pd.set_option('display.max_rows', 100)
```

## 配置与设置

### 显示选项：`pd.set_option()`

控制 DataFrame 在控制台/Jupyter 中的显示方式。

```python
# 最大显示行数
pd.set_option('display.max_rows', 50)
# 显示所有列
pd.set_option('display.max_columns', None)
# 显示宽度
pd.set_option('display.width', 1000)
# 格式化浮点数值
pd.set_option('display.float_format', '{:.2f}'.format)
```

### 重置选项：`pd.reset_option()`

将特定选项或所有选项重置为其默认值。

```python
# 重置特定选项
pd.reset_option('display.max_rows')
# 重置所有选项为默认值
pd.reset_option('all')
```

### 获取选项：`pd.get_option()`

检索指定选项的当前值。

```python
# 获取当前的 max_rows 设置
print(pd.get_option('display.max_rows'))
```

### 上下文管理器：`pd.option_context()`

在 `with` 语句中临时设置选项。

```python
with pd.option_context('display.max_rows', 10, 'display.max_columns', 5):
    print(df) # DataFrame 以临时选项显示
print(df) # 选项在块外恢复到先前设置
```

## 方法链式调用

### 链式操作

对 DataFrame 应用一系列转换。

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

### 使用 `.pipe()`

应用将 DataFrame 作为其第一个参数的函数，从而可以在链中实现自定义步骤。

```python
def custom_filter(df, threshold):
    return df[df['value'] > threshold]

(
    df.pipe(custom_filter, threshold=50)
    .groupby('group')
    .agg(total_value=('value', 'sum'))
)
```

## 相关链接

- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/numpy">NumPy 速查表</router-link>
- <router-link to="/matplotlib">Matplotlib 速查表</router-link>
- <router-link to="/sklearn">scikit-learn 速查表</router-link>
- <router-link to="/datascience">数据科学速查表</router-link>
- <router-link to="/mysql">MySQL 速查表</router-link>
- <router-link to="/postgresql">PostgreSQL 速查表</router-link>
- <router-link to="/sqlite">SQLite 速查表</router-link>

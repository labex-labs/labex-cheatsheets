---
title: 'NumPy 速查表 | LabEx'
description: '使用这份全面的速查表学习 NumPy 数值计算。快速参考数组、线性代数、数学运算、广播和 Python 科研计算。'
pdfUrl: '/cheatsheets/pdf/numpy-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
NumPy 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/numpy">通过实践实验室学习 NumPy</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 NumPy 数值计算。LabEx 提供全面的 NumPy 课程，涵盖基本的数组操作、数学函数、线性代数和性能优化。掌握高效的数值计算和数组操作，以用于数据科学工作流程。
</base-disclaimer-content>
</base-disclaimer>

## 数组创建与初始化

### 从列表创建：`np.array()`

从 Python 列表或嵌套列表中创建数组。

```python
import numpy as np

# 从列表创建一维数组
arr = np.array([1, 2, 3, 4])
# 从嵌套列表创建二维数组
arr2d = np.array([[1, 2], [3, 4]])
# 指定数据类型
arr = np.array([1, 2, 3], dtype=float)
# 字符串数组
arr_str = np.array(['a', 'b', 'c'])
```

<BaseQuiz id="numpy-array-1" correct="C">
  <template #question>
    NumPy 数组相较于 Python 列表的主要优势是什么？
  </template>
  
  <BaseQuizOption value="A">它们可以存储字符串</BaseQuizOption>
  <BaseQuizOption value="B">它们更容易创建</BaseQuizOption>
  <BaseQuizOption value="C" correct>它们在数值运算上更快、内存效率更高</BaseQuizOption>
  <BaseQuizOption value="D">它们可以存储混合数据类型</BaseQuizOption>
  
  <BaseQuizAnswer>
    NumPy 数组针对数值计算进行了优化，与 Python 列表相比，在大型数据集和数学运算中提供了更快的操作和更高效的内存使用。
  </BaseQuizAnswer>
</BaseQuiz>

### 零和一：`np.zeros()` / `np.ones()`

创建填充了零或一的数组。

```python
# 零数组
zeros = np.zeros(5)  # 一维
zeros2d = np.zeros((3, 4))  # 二维
# 一数组
ones = np.ones((2, 3))
# 指定数据类型
zeros_int = np.zeros(5, dtype=int)
```

### 单位矩阵：`np.eye()` / `np.identity()`

为线性代数运算创建单位矩阵。

```python
# 3x3 单位矩阵
identity = np.eye(3)
# 替代方法
identity2 = np.identity(4)
```

### 范围数组：`np.arange()` / `np.linspace()`

创建具有等距值的数组。

```python
# 类似于 Python 的 range
arr = np.arange(10)  # 0 到 9
arr = np.arange(2, 10, 2)  # 2, 4, 6, 8
# 等距值
arr = np.linspace(0, 1, 5)  # 从 0 到 1 的 5 个值
# 包含端点
arr = np.linspace(0, 10, 11)
```

### 随机数组：`np.random`

生成具有随机值的数组。

```python
# 0 到 1 之间的随机值
rand = np.random.random((2, 3))
# 随机整数
rand_int = np.random.randint(0, 10, size=(3, 3))
# 正态分布
normal = np.random.normal(0, 1, size=5)
# 设置随机种子以保证可复现性
np.random.seed(42)
```

### 特殊数组：`np.full()` / `np.empty()`

创建填充特定值或未初始化的数组。

```python
# 填充特定值
full_arr = np.full((2, 3), 7)
# 空数组（未初始化）
empty_arr = np.empty((2, 2))
# 形状与现有数组相同
like_arr = np.zeros_like(arr)
```

## 数组属性与结构

### 基本属性：`shape` / `size` / `ndim`

获取有关数组维度和大小的基本信息。

```python
# 数组维度（元组）
arr.shape
# 元素总数
arr.size
# 维度数量
arr.ndim
# 元素数据类型
arr.dtype
# 每个元素的大小（字节）
arr.itemsize
```

### 数组信息：内存使用

获取有关数组内存使用和结构的详细信息。

```python
# 内存使用（字节）
arr.nbytes
# 数组信息（用于调试）
arr.flags
# 检查数组是否拥有其数据
arr.owndata
# 基对象（如果数组是视图）
arr.base
```

### 数据类型：`astype()`

高效地在不同数据类型之间转换。

```python
# 转换为不同类型
arr.astype(float)
arr.astype(int)
arr.astype(str)
# 更具体的类型
arr.astype(np.float32)
arr.astype(np.int16)
```

## 数组索引与切片

### 基本索引：`arr[index]`

访问单个元素和切片。

```python
# 单个元素
arr[0]  # 第一个元素
arr[-1]  # 最后一个元素
# 二维数组索引
arr2d[0, 1]  # 第 0 行，第 1 列
arr2d[1]  # 整个第 1 行
# 切片
arr[1:4]  # 元素 1 到 3
arr[::2]  # 每隔一个元素
arr[::-1]  # 反转数组
```

### 布尔索引：`arr[condition]`

根据条件过滤数组。

```python
# 简单条件
arr[arr > 5]
# 多个条件
arr[(arr > 2) & (arr < 8)]
arr[(arr < 2) | (arr > 8)]
# 布尔数组
mask = arr > 3
filtered = arr[mask]
```

<BaseQuiz id="numpy-boolean-1" correct="C">
  <template #question>
    布尔索引 `arr[arr > 5]` 返回什么？
  </template>
  
  <BaseQuizOption value="A">一个布尔数组</BaseQuizOption>
  <BaseQuizOption value="B">原始数组</BaseQuizOption>
  <BaseQuizOption value="C" correct>一个只包含大于 5 的元素的数组</BaseQuizOption>
  <BaseQuizOption value="D">一个错误</BaseQuizOption>
  
  <BaseQuizAnswer>
    布尔索引会过滤数组，只返回条件为真的元素。`arr[arr > 5]` 返回一个包含所有大于 5 的值的新数组。
  </BaseQuizAnswer>
</BaseQuiz>

### 高级索引：范型索引 (Fancy Indexing)

使用索引数组来访问多个元素。

```python
# 使用索引数组
indices = [0, 2, 4]
arr[indices]
# 二维范型索引
arr2d[[0, 1], [1, 2]]  # 元素 (0,1) 和 (1,2)
# 与切片结合
arr2d[1:, [0, 2]]
```

### Where 函数：`np.where()`

条件选择和元素替换。

```python
# 查找条件为真的索引
indices = np.where(arr > 5)
# 条件替换
result = np.where(arr > 5, arr, 0)  # 将大于 5 的值替换为 0
# 多个条件
result = np.where(arr > 5, 'high', 'low')
```

## 数组操作与重塑

### 重塑：`reshape()` / `resize()` / `flatten()`

在保留数据的情况下更改数组维度。

```python
# 重塑（如果可能，创建视图）
arr.reshape(2, 3)
arr.reshape(-1, 1)  # -1 表示自动推断维度
# 调整大小（修改原始数组）
arr.resize((2, 3))
# 展平为一维
arr.flatten()  # 返回副本
arr.ravel()  # 尽可能返回视图
```

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    在 `arr.reshape(-1, 1)` 中，`-1` 代表什么？
  </template>
  
  <BaseQuizOption value="A">它会产生一个错误</BaseQuizOption>
  <BaseQuizOption value="B" correct>它会自动根据数组大小推断维度</BaseQuizOption>
  <BaseQuizOption value="C">它会创建一个一维数组</BaseQuizOption>
  <BaseQuizOption value="D">它会反转数组</BaseQuizOption>
  
  <BaseQuizAnswer>
    在重塑中使用 `-1` 告诉 NumPy 根据数组的总大小和其他指定的维度自动计算该维度。当你只知道一个维度而希望 NumPy 找出另一个维度时，这很有用。
  </BaseQuizAnswer>
</BaseQuiz>

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    在 `arr.reshape(-1, 1)` 中，`-1` 代表什么？
  </template>
  
  <BaseQuizOption value="A">它会产生一个错误</BaseQuizOption>
  <BaseQuizOption value="B" correct>NumPy 会自动推断维度</BaseQuizOption>
  <BaseQuizOption value="C">它会移除该维度</BaseQuizOption>
  <BaseQuizOption value="D">它将维度设置为 1</BaseQuizOption>
  
  <BaseQuizAnswer>
    在重塑中使用 `-1` 告诉 NumPy 根据数组的总大小和其他指定的维度自动计算该维度。当你只知道一个维度而希望 NumPy 找出另一个维度时，这很有用。
  </BaseQuizAnswer>
</BaseQuiz>

### 转置：`T` / `transpose()`

交换数组轴以进行矩阵运算。

```python
# 简单转置
arr2d.T
# 带轴规范的转置
arr.transpose()
np.transpose(arr)
# 对于更高维度
arr3d.transpose(2, 0, 1)
```

### 添加/删除元素

通过添加或删除元素来修改数组大小。

```python
# 追加元素
np.append(arr, [4, 5])
# 在特定位置插入
np.insert(arr, 1, 99)
# 删除元素
np.delete(arr, [1, 3])
# 重复元素
np.repeat(arr, 3)
np.tile(arr, 2)
```

### 组合数组：`concatenate()` / `stack()`

将多个数组连接在一起。

```python
# 沿现有轴连接
np.concatenate([arr1, arr2])
np.concatenate([arr1, arr2], axis=1)
# 堆叠数组（创建新轴）
np.vstack([arr1, arr2])  # 垂直堆叠
np.hstack([arr1, arr2])  # 水平堆叠
np.dstack([arr1, arr2])  # 深度堆叠
```

## 数学运算

### 基本算术：`+`, `-`, `*`, `/`

对数组进行元素级的算术运算。

```python
# 元素级运算
arr1 + arr2
arr1 - arr2
arr1 * arr2  # 元素级乘法
arr1 / arr2
arr1 ** 2  # 平方
arr1 % 3  # 模运算
```

### 通用函数 (ufuncs)

对元素级应用数学函数。

```python
# 三角函数
np.sin(arr)
np.cos(arr)
np.tan(arr)
# 指数和对数
np.exp(arr)
np.log(arr)
np.log10(arr)
# 平方根和幂
np.sqrt(arr)
np.power(arr, 3)
```

### 聚合函数

计算跨数组维度的摘要统计信息。

```python
# 基本统计
np.sum(arr)
np.mean(arr)
np.std(arr)  # 标准差
np.var(arr)  # 方差
np.min(arr)
np.max(arr)
# 沿特定轴
np.sum(arr2d, axis=0)  # 沿行求和
np.mean(arr2d, axis=1)  # 沿列求平均值
```

### 比较运算

返回布尔数组的元素级比较。

```python
# 比较运算符
arr > 5
arr == 3
arr != 0
# 数组比较
np.array_equal(arr1, arr2)
np.allclose(arr1, arr2)  # 在容差范围内
# 任何/所有操作
np.any(arr > 5)
np.all(arr > 0)
```

## 线性代数

### 矩阵运算：`np.dot()` / `@`

执行矩阵乘法和点积。

```python
# 矩阵乘法
np.dot(A, B)
A @ B  # Python 3.5+ 运算符
# 元素级乘法
A * B
# 矩阵幂
np.linalg.matrix_power(A, 3)
```

### 分解：`np.linalg`

用于高级计算的矩阵分解。

```python
# 特征值和特征向量
eigenvals, eigenvecs = np.linalg.eig(A)
# 奇异值分解
U, s, Vt = np.linalg.svd(A)
# QR 分解
Q, R = np.linalg.qr(A)
```

### 矩阵属性

计算重要的矩阵特征。

```python
# 行列式
np.linalg.det(A)
# 矩阵逆
np.linalg.inv(A)
# 伪逆
np.linalg.pinv(A)
# 矩阵秩
np.linalg.matrix_rank(A)
# 迹（对角线元素之和）
np.trace(A)
```

### 求解线性系统：`np.linalg.solve()`

求解线性方程组。

```python
# 求解 Ax = b
x = np.linalg.solve(A, b)
# 最小二乘解
x = np.linalg.lstsq(A, b, rcond=None)[0]
```

## 数组输入/输出

### NumPy 二进制：`np.save()` / `np.load()`

NumPy 数组的高效二进制格式。

```python
# 保存单个数组
np.save('array.npy', arr)
# 加载数组
loaded_arr = np.load('array.npy')
# 保存多个数组
np.savez('arrays.npz', a=arr1, b=arr2)
# 加载多个数组
data = np.load('arrays.npz')
arr1_loaded = data['a']
```

### 文本文件：`np.loadtxt()` / `np.savetxt()`

以文本文件形式读写数组。

```python
# 从 CSV/文本文件加载
arr = np.loadtxt('data.csv', delimiter=',')
# 跳过标题行
arr = np.loadtxt('data.csv', delimiter=',', skiprows=1)
# 保存到文本文件
np.savetxt('output.csv', arr, delimiter=',', fmt='%.2f')
```

### 结构化数据 CSV: `np.genfromtxt()`

处理缺失数据的文本文件的高级读取。

```python
# 处理缺失值
arr = np.genfromtxt('data.csv', delimiter=',',
                    missing_values='N/A', filling_values=0)
# 命名列
data = np.genfromtxt('data.csv', delimiter=',',
                     names=True, dtype=None)
```

### 内存映射：`np.memmap()`

处理无法完全放入内存的数组。

```python
# 创建内存映射数组
mmap_arr = np.memmap('large_array.dat', dtype='float32',
                     mode='w+', shape=(1000000,))
# 像常规数组一样访问，但存储在磁盘上
mmap_arr[0:10] = np.random.random(10)
```

## 性能与广播

### 广播规则

理解 NumPy 如何处理不同形状数组上的运算。

```python
# 广播示例
arr1 = np.array([[1, 2, 3]])  # 形状 (1, 3)
arr2 = np.array([[1], [2]])   # 形状 (2, 1)
result = arr1 + arr2          # 形状 (2, 3)
# 标量广播
arr + 5  # 所有元素加 5
arr * 2  # 所有元素乘以 2
```

### 向量化操作

使用 NumPy 内置函数代替 Python 循环。

```python
# 代替循环，使用向量化操作
# 差：for 循环
result = []
for x in arr:
    result.append(x ** 2)
# 好：向量化
result = arr ** 2
# 自定义向量化函数
def custom_func(x):
    return x ** 2 + 2 * x + 1
vec_func = np.vectorize(custom_func)
result = vec_func(arr)
```

### 内存优化

用于大型数组高效内存使用的技术。

```python
# 使用适当的数据类型
arr_int8 = arr.astype(np.int8)  # 每个元素 1 字节
arr_float32 = arr.astype(np.float32)  # 4 字节 vs float64 的 8 字节
# 视图与副本
view = arr[::2]  # 创建视图（共享内存）
copy = arr[::2].copy()  # 创建副本（新内存）
# 检查数组是视图还是副本
view.base is arr  # True 表示视图
```

### 性能提示

快速 NumPy 代码的最佳实践。

```python
# 尽可能使用原地操作
arr += 5  # 代替 arr = arr + 5
np.add(arr, 5, out=arr)  # 明确的原地操作
# 最小化数组创建
# 差：创建中间数组
result = ((arr + 1) * 2) ** 2
# 更好：尽可能使用复合操作
```

## 随机数生成

### 基本随机：`np.random`

从各种分布生成随机数。

```python
# 随机浮点数 [0, 1)
np.random.random(5)
# 随机整数
np.random.randint(0, 10, size=5)
# 正态分布
np.random.normal(mu=0, sigma=1, size=5)
# 均匀分布
np.random.uniform(-1, 1, size=5)
```

### 采样：`choice()` / `shuffle()`

从现有数据中采样或排列数组。

```python
# 从数组中随机选择
np.random.choice(arr, size=3)
# 不重复抽样
np.random.choice(arr, size=3, replace=False)
# 原地打乱数组
np.random.shuffle(arr)
# 随机排列
np.random.permutation(arr)
```

### 种子与生成器

控制随机性以获得可复现的结果。

```python
# 设置种子以保证可复现性
np.random.seed(42)
# 现代方法：生成器
rng = np.random.default_rng(42)
rng.random(5)
rng.integers(0, 10, size=5)
rng.normal(0, 1, size=5)
```

## 统计函数

### 描述性统计

集中趋势和离散度的基本统计度量。

```python
# 集中趋势
np.mean(arr)
np.median(arr)
# 离散度度量
np.std(arr)  # 标准差
np.var(arr)  # 方差
np.ptp(arr)  # 峰峰值 (max - min)
# 百分位数
np.percentile(arr, [25, 50, 75])
np.quantile(arr, [0.25, 0.5, 0.75])
```

### 相关与协方差

衡量变量之间的关系。

```python
# 相关系数
np.corrcoef(x, y)
# 协方差
np.cov(x, y)
# 互相关
np.correlate(x, y, mode='full')
```

### 直方图与分箱

分析数据分布并创建分箱。

```python
# 直方图
counts, bins = np.histogram(arr, bins=10)
# 二维直方图
H, xedges, yedges = np.histogram2d(x, y, bins=10)
# 分箱（分配箱索引）
bin_indices = np.digitize(arr, bins)
```

### 特殊统计函数

高级统计计算。

```python
# 加权统计
np.average(arr, weights=weights)
# 唯一值和计数
unique_vals, counts = np.unique(arr, return_counts=True)
# 计数（用于整数数组）
np.bincount(int_arr)
```

## NumPy 安装与设置

### Pip: `pip install numpy`

标准的 Python 包安装程序。

```bash
# 安装 NumPy
pip install numpy
# 升级到最新版本
pip install numpy --upgrade
# 安装特定版本
pip install numpy==1.21.0
# 显示包信息
pip show numpy
```

### Conda: `conda install numpy`

Anaconda/Miniconda 环境的包管理器。

```bash
# 在当前环境中安装 NumPy
conda install numpy
# 更新 NumPy
conda update numpy
# 从 conda-forge 安装
conda install -c conda-forge numpy
# 创建包含 NumPy 的环境
conda create -n myenv numpy
```

### 检查安装与导入

验证您的 NumPy 安装并进行标准导入。

```python
# 标准导入
import numpy as np
# 检查版本
print(np.__version__)
# 检查构建信息
np.show_config()
# 设置打印选项
np.set_printoptions(precision=2, suppress=True)
```

## 高级特性

### 结构化数组

具有命名字段的数组，用于复杂数据结构。

```python
# 定义结构化数据类型
dt = np.dtype([('name', 'U10'), ('age', 'i4'), ('weight', 'f4')])
# 创建结构化数组
people = np.array([('Alice', 25, 55.0), ('Bob', 30, 70.5)], dtype=dt)
# 访问字段
people['name']
people['age']
```

### 掩码数组：`np.ma`

处理具有缺失或无效数据的数组。

```python
# 创建掩码数组
masked_arr = np.ma.array([1, 2, 3, 4, 5], mask=[0, 0, 1, 0, 0])
# 运算会忽略掩码值
np.ma.mean(masked_arr)
# 填充掩码值
filled = masked_arr.filled(0)
```

### 多项式：`np.poly1d`

处理多项式表达式和运算。

```python
# 创建多项式（系数按降幂排列）
p = np.poly1d([1, -2, 1])  # x² - 2x + 1
# 评估多项式
p(5)  # 在 x=5 处评估
# 寻找根
np.roots([1, -2, 1])
# 多项式拟合
coeff = np.polyfit(x, y, degree=2)
```

### 快速傅里叶变换：`np.fft`

频域分析和信号处理。

```python
# 一维 FFT
fft_result = np.fft.fft(signal)
# 频率
freqs = np.fft.fftfreq(len(signal))
# 逆 FFT
reconstructed = np.fft.ifft(fft_result)
# 二维 FFT 用于图像
fft2d = np.fft.fft2(image)
```

## 相关链接

- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/pandas">Pandas 速查表</router-link>
- <router-link to="/matplotlib">Matplotlib 速查表</router-link>
- <router-link to="/sklearn">scikit-learn 速查表</router-link>
- <router-link to="/datascience">数据科学速查表</router-link>

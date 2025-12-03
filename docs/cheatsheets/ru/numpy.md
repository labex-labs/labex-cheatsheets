---
title: 'Шпаргалка по NumPy | LabEx'
description: 'Изучите численные вычисления NumPy с помощью этой исчерпывающей шпаргалки. Краткий справочник по массивам, линейной алгебре, математическим операциям, широковещанию (broadcasting) и научным вычислениям на Python.'
pdfUrl: '/cheatsheets/pdf/numpy-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по NumPy
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/numpy">Изучите NumPy с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите числовые вычисления NumPy с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по NumPy, охватывающие основные операции с массивами, математические функции, линейную алгебру и оптимизацию производительности. Освойте эффективные числовые вычисления и манипуляции с массивами для рабочих процессов науки о данных.
</base-disclaimer-content>
</base-disclaimer>

## Создание и инициализация массивов

### Из списков: `np.array()`

Создание массивов из списков Python или вложенных списков.

```python
import numpy as np

# 1D массив из списка
arr = np.array([1, 2, 3, 4])
# 2D массив из вложенных списков
arr2d = np.array([[1, 2], [3, 4]])
# Указание типа данных
arr = np.array([1, 2, 3], dtype=float)
# Массив строк
arr_str = np.array(['a', 'b', 'c'])
```

<BaseQuiz id="numpy-array-1" correct="C">
  <template #question>
    What is the main advantage of NumPy arrays over Python lists?
  </template>
  
  <BaseQuizOption value="A">They can store strings</BaseQuizOption>
  <BaseQuizOption value="B">They are easier to create</BaseQuizOption>
  <BaseQuizOption value="C" correct>They are faster and more memory-efficient for numerical operations</BaseQuizOption>
  <BaseQuizOption value="D">They can store mixed data types</BaseQuizOption>
  
  <BaseQuizAnswer>
    NumPy arrays are optimized for numerical computations, providing faster operations and more efficient memory usage compared to Python lists, especially for large datasets and mathematical operations.
  </BaseQuizAnswer>
</BaseQuiz>

### Нули и единицы: `np.zeros()` / `np.ones()`

Создание массивов, заполненных нулями или единицами.

```python
# Массив нулей
zeros = np.zeros(5)  # 1D
zeros2d = np.zeros((3, 4))  # 2D
# Массив единиц
ones = np.ones((2, 3))
# Указание типа данных
zeros_int = np.zeros(5, dtype=int)
```

### Единичная матрица: `np.eye()` / `np.identity()`

Создание единичных матриц для операций линейной алгебры.

```python
# Единичная матрица 3x3
identity = np.eye(3)
# Альтернативный метод
identity2 = np.identity(4)
```

### Массивы диапазона: `np.arange()` / `np.linspace()`

Создание массивов с равномерно расположенными значениями.

```python
# Похоже на Python range
arr = np.arange(10)  # От 0 до 9
arr = np.arange(2, 10, 2)  # 2, 4, 6, 8
# Равномерно расположенные значения
arr = np.linspace(0, 1, 5)  # 5 значений от 0 до 1
# Включая конечную точку
arr = np.linspace(0, 10, 11)
```

### Случайные массивы: `np.random`

Генерация массивов со случайными значениями.

```python
# Случайные значения от 0 до 1
rand = np.random.random((2, 3))
# Случайные целые числа
rand_int = np.random.randint(0, 10, size=(3, 3))
# Нормальное распределение
normal = np.random.normal(0, 1, size=5)
# Установка начального числа (seed) для воспроизводимости
np.random.seed(42)
```

### Специальные массивы: `np.full()` / `np.empty()`

Создание массивов с определенными значениями или неинициализированных.

```python
# Заполнение определенным значением
full_arr = np.full((2, 3), 7)
# Пустой массив (неинициализированный)
empty_arr = np.empty((2, 2))
# По форме существующего массива
like_arr = np.zeros_like(arr)
```

## Свойства и структура массива

### Основные свойства: `shape` / `size` / `ndim`

Получение фундаментальной информации о размерностях и размере массива.

```python
# Размерности массива (кортеж)
arr.shape
# Общее количество элементов
arr.size
# Количество измерений
arr.ndim
# Тип данных элементов
arr.dtype
# Размер каждого элемента в байтах
arr.itemsize
```

### Информация о массиве: Использование памяти

Получение подробной информации об использовании памяти и структуре массива.

```python
# Использование памяти в байтах
arr.nbytes
# Информация о массиве (для отладки)
arr.flags
# Проверка, владеет ли массив своими данными
arr.owndata
# Базовый объект (если массив является представлением/view)
arr.base
```

### Типы данных: `astype()`

Эффективное преобразование между различными типами данных.

```python
# Преобразование в другой тип
arr.astype(float)
arr.astype(int)
arr.astype(str)
# Более специфичные типы
arr.astype(np.float32)
arr.astype(np.int16)
```

## Индексирование и нарезка массивов

### Базовое индексирование: `arr[index]`

Доступ к отдельным элементам и срезам.

```python
# Отдельный элемент
arr[0]  # Первый элемент
arr[-1]  # Последний элемент
# Индексирование 2D массива
arr2d[0, 1]  # Строка 0, Столбец 1
arr2d[1]  # Вся строка 1
# Нарезка (Slicing)
arr[1:4]  # Элементы с 1 по 3
arr[::2]  # Каждый второй элемент
arr[::-1]  # Обратный массив
```

### Булево индексирование: `arr[condition]`

Фильтрация массивов на основе условий.

```python
# Простое условие
arr[arr > 5]
# Множественные условия
arr[(arr > 2) & (arr < 8)]
arr[(arr < 2) | (arr > 8)]
# Булев массив
mask = arr > 3
filtered = arr[mask]
```

<BaseQuiz id="numpy-boolean-1" correct="C">
  <template #question>
    What does boolean indexing <code>arr[arr > 5]</code> return?
  </template>
  
  <BaseQuizOption value="A">A boolean array</BaseQuizOption>
  <BaseQuizOption value="B">The original array</BaseQuizOption>
  <BaseQuizOption value="C" correct>An array with only elements greater than 5</BaseQuizOption>
  <BaseQuizOption value="D">An error</BaseQuizOption>
  
  <BaseQuizAnswer>
    Boolean indexing filters the array, returning only elements where the condition is true. <code>arr[arr > 5]</code> returns a new array containing only values greater than 5.
  </BaseQuizAnswer>
</BaseQuiz>

### Расширенное индексирование: Fancy Indexing

Использование массивов индексов для доступа к нескольким элементам.

```python
# Индексирование с массивом индексов
indices = [0, 2, 4]
arr[indices]
# 2D индексирование
arr2d[[0, 1], [1, 2]]  # Элементы (0,1) и (1,2)
# Комбинация с нарезкой
arr2d[1:, [0, 2]]
```

### Функция Where: `np.where()`

Условный выбор и замена элементов.

```python
# Найти индексы, где условие истинно
indices = np.where(arr > 5)
# Условная замена
result = np.where(arr > 5, arr, 0)  # Заменить значения >5 на 0
# Множественные условия
result = np.where(arr > 5, 'high', 'low')
```

## Манипуляции и изменение формы массива

### Изменение формы: `reshape()` / `resize()` / `flatten()`

Изменение размерностей массива с сохранением данных.

```python
# Изменение формы (создает представление, если возможно)
arr.reshape(2, 3)
arr.reshape(-1, 1)  # -1 означает автоматический вывод размерности
# Изменение размера (изменяет исходный массив)
arr.resize((2, 3))
# Сплющивание в 1D
arr.flatten()  # Возвращает копию
arr.ravel()  # Возвращает представление, если возможно
```

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    What does <code>-1</code> mean in <code>arr.reshape(-1, 1)</code>?
  </template>
  
  <BaseQuizOption value="A">It creates an error</BaseQuizOption>
  <BaseQuizOption value="B" correct>It infers the dimension automatically based on array size</BaseQuizOption>
  <BaseQuizOption value="C">It creates a 1D array</BaseQuizOption>
  <BaseQuizOption value="D">It reverses the array</BaseQuizOption>
  
  <BaseQuizAnswer>
    Using <code>-1</code> in reshape tells NumPy to automatically calculate that dimension based on the array's total size and the other specified dimensions. This is useful when you know one dimension but want NumPy to figure out the other.
  </BaseQuizAnswer>
</BaseQuiz>

<BaseQuiz id="numpy-reshape-1" correct="B">
  <template #question>
    What does <code>-1</code> mean in <code>arr.reshape(-1, 1)</code>?
  </template>
  
  <BaseQuizOption value="A">It creates an error</BaseQuizOption>
  <BaseQuizOption value="B" correct>NumPy infers the dimension automatically</BaseQuizOption>
  <BaseQuizOption value="C">It removes that dimension</BaseQuizOption>
  <BaseQuizOption value="D">It sets the dimension to 1</BaseQuizOption>
  
  <BaseQuizAnswer>
    Using <code>-1</code> in reshape tells NumPy to automatically calculate that dimension based on the array's total size and the other specified dimensions. This is useful when you know one dimension but want NumPy to figure out the other.
  </BaseQuizAnswer>
</BaseQuiz>

### Транспонирование: `T` / `transpose()`

Обмен осями массива для операций линейной алгебры.

```python
# Простое транспонирование
arr2d.T
# Транспонирование с указанием осей
arr.transpose()
np.transpose(arr)
# Для более высоких размерностей
arr3d.transpose(2, 0, 1)
```

### Добавление/удаление элементов

Изменение размера массива путем добавления или удаления элементов.

```python
# Добавить элементы
np.append(arr, [4, 5])
# Вставить на определенную позицию
np.insert(arr, 1, 99)
# Удалить элементы
np.delete(arr, [1, 3])
# Повторить элементы
np.repeat(arr, 3)
np.tile(arr, 2)
```

### Объединение массивов: `concatenate()` / `stack()`

Соединение нескольких массивов вместе.

```python
# Объединение вдоль существующей оси
np.concatenate([arr1, arr2])
np.concatenate([arr1, arr2], axis=1)
# Стек массивов (создает новую ось)
np.vstack([arr1, arr2])  # Вертикально
np.hstack([arr1, arr2])  # Горизонтально
np.dstack([arr1, arr2])  # По глубине
```

## Математические операции

### Основная арифметика: `+`, `-`, `*`, `/`

Поэлементные арифметические операции над массивами.

```python
# Поэлементные операции
arr1 + arr2
arr1 - arr2
arr1 * arr2  # Поэлементное умножение
arr1 / arr2
arr1 ** 2  # Возведение в квадрат
arr1 % 3  # Операция по модулю
```

### Универсальные функции (ufuncs)

Применение математических функций к элементам.

```python
# Тригонометрические функции
np.sin(arr)
np.cos(arr)
np.tan(arr)
# Экспоненциальная и логарифмическая
np.exp(arr)
np.log(arr)
np.log10(arr)
# Квадратный корень и степень
np.sqrt(arr)
np.power(arr, 3)
```

### Функции агрегации

Вычисление сводной статистики по размерностям массива.

```python
# Основная статистика
np.sum(arr)
np.mean(arr)
np.std(arr)  # Стандартное отклонение
np.var(arr)  # Дисперсия
np.min(arr)
np.max(arr)
# Вдоль определенной оси
np.sum(arr2d, axis=0)  # Сумма по строкам
np.mean(arr2d, axis=1)  # Среднее по столбцам
```

### Операции сравнения

Поэлементные сравнения, возвращающие булевы массивы.

```python
# Операторы сравнения
arr > 5
arr == 3
arr != 0
# Сравнение массивов
np.array_equal(arr1, arr2)
np.allclose(arr1, arr2)  # В пределах допуска
# Операции any/all
np.any(arr > 5)
np.all(arr > 0)
```

## Линейная алгебра

### Матричные операции: `np.dot()` / `@`

Выполнение матричного умножения и скалярных произведений.

```python
# Матричное умножение
np.dot(A, B)
A @ B  # Оператор Python 3.5+
# Поэлементное умножение
A * B
# Матричная степень
np.linalg.matrix_power(A, 3)
```

### Разложения: `np.linalg`

Разложения матриц для расширенных вычислений.

```python
# Собственные значения и собственные векторы
eigenvals, eigenvecs = np.linalg.eig(A)
# Сингулярное разложение (SVD)
U, s, Vt = np.linalg.svd(A)
# QR-разложение
Q, R = np.linalg.qr(A)
```

### Свойства матрицы

Вычисление важных характеристик матрицы.

```python
# Определитель
np.linalg.det(A)
# Обратная матрица
np.linalg.inv(A)
# Псевдообратная матрица
np.linalg.pinv(A)
# Ранг матрицы
np.linalg.matrix_rank(A)
# След (сумма диагонали)
np.trace(A)
```

### Решение линейных систем: `np.linalg.solve()`

Решение систем линейных уравнений.

```python
# Решить Ax = b
x = np.linalg.solve(A, b)
# Решение методом наименьших квадратов
x = np.linalg.lstsq(A, b, rcond=None)[0]
```

## Ввод/вывод массивов

### Бинарный формат NumPy: `np.save()` / `np.load()`

Эффективный бинарный формат для массивов NumPy.

```python
# Сохранить один массив
np.save('array.npy', arr)
# Загрузить массив
loaded_arr = np.load('array.npy')
# Сохранить несколько массивов
np.savez('arrays.npz', a=arr1, b=arr2)
# Загрузить несколько массивов
data = np.load('arrays.npz')
arr1_loaded = data['a']
```

### Текстовые файлы: `np.loadtxt()` / `np.savetxt()`

Чтение и запись массивов в виде текстовых файлов.

```python
# Загрузить из CSV/текстового файла
arr = np.loadtxt('data.csv', delimiter=',')
# Пропустить строку заголовка
arr = np.loadtxt('data.csv', delimiter=',', skiprows=1)
# Сохранить в текстовый файл
np.savetxt('output.csv', arr, delimiter=',', fmt='%.2f')
```

### CSV со структурированными данными: `np.genfromtxt()`

Расширенное чтение текстовых файлов с обработкой пропущенных данных.

```python
# Обработка пропущенных значений
arr = np.genfromtxt('data.csv', delimiter=',',
                    missing_values='N/A', filling_values=0)
# Именованные столбцы
data = np.genfromtxt('data.csv', delimiter=',',
                     names=True, dtype=None)
```

### Отображение памяти: `np.memmap()`

Работа с массивами, слишком большими для размещения в памяти.

```python
# Создание массива с отображением памяти
mmap_arr = np.memmap('large_array.dat', dtype='float32',
                     mode='w+', shape=(1000000,))
# Доступ как к обычному массиву, но хранится на диске
mmap_arr[0:10] = np.random.random(10)
```

## Производительность и вещание (Broadcasting)

### Правила вещания (Broadcasting)

Понимание того, как NumPy обрабатывает операции над массивами разной формы.

```python
# Примеры вещания
arr1 = np.array([[1, 2, 3]])  # Форма (1, 3)
arr2 = np.array([[1], [2]])   # Форма (2, 1)
result = arr1 + arr2          # Форма (2, 3)
# Вещание скаляра
arr + 5  # Добавляет 5 ко всем элементам
arr * 2  # Умножает все элементы на 2
```

### Векторизованные операции

Использование встроенных функций NumPy вместо циклов Python.

```python
# Вместо циклов используйте векторизованные операции
# Плохо: цикл for
result = []
for x in arr:
    result.append(x ** 2)
# Хорошо: векторизовано
result = arr ** 2
# Пользовательская векторизованная функция
def custom_func(x):
    return x ** 2 + 2 * x + 1
vec_func = np.vectorize(custom_func)
result = vec_func(arr)
```

### Оптимизация памяти

Методы для эффективного использования памяти с большими массивами.

```python
# Использование подходящих типов данных
arr_int8 = arr.astype(np.int8)  # 1 байт на элемент
arr_float32 = arr.astype(np.float32)  # 4 байта вместо 8 для float64
# Представления (Views) против копий (Copies)
view = arr[::2]  # Создает представление (разделяет память)
copy = arr[::2].copy()  # Создает копию (новая память)
# Проверка, является ли массив представлением или копией
view.base is arr  # True для представления
```

### Советы по производительности

Лучшие практики для быстрого кода NumPy.

```python
# Используйте операции на месте, когда это возможно
arr += 5  # Вместо arr = arr + 5
np.add(arr, 5, out=arr)  # Явное выполнение на месте
# Минимизируйте создание массивов
# Плохо: создает промежуточные массивы
result = ((arr + 1) * 2) ** 2
# Лучше: используйте составные операции, где это возможно
```

## Генерация случайных чисел

### Базовые случайные числа: `np.random`

Генерация случайных чисел из различных распределений.

```python
# Случайные числа с плавающей точкой [0, 1)
np.random.random(5)
# Случайные целые числа
np.random.randint(0, 10, size=5)
# Нормальное распределение
np.random.normal(mu=0, sigma=1, size=5)
# Равномерное распределение
np.random.uniform(-1, 1, size=5)
```

### Выборка: `choice()` / `shuffle()`

Выборка из существующих данных или перестановка массивов.

```python
# Случайный выбор из массива
np.random.choice(arr, size=3)
# Без замены
np.random.choice(arr, size=3, replace=False)
# Перемешать массив на месте
np.random.shuffle(arr)
# Случайная перестановка
np.random.permutation(arr)
```

### Начальные числа (Seeds) и Генераторы

Управление случайностью для воспроизводимых результатов.

```python
# Установка начального числа для воспроизводимости
np.random.seed(42)
# Современный подход: Генератор
rng = np.random.default_rng(42)
rng.random(5)
rng.integers(0, 10, size=5)
rng.normal(0, 1, size=5)
```

## Статистические функции

### Описательная статистика

Основные статистические меры центральной тенденции и разброса.

```python
# Центральная тенденция
np.mean(arr)
np.median(arr)
# Меры разброса
np.std(arr)  # Стандартное отклонение
np.var(arr)  # Дисперсия
np.ptp(arr)  # Разница между максимумом и минимумом
# Квантили
np.percentile(arr, [25, 50, 75])
np.quantile(arr, [0.25, 0.5, 0.75])
```

### Корреляция и ковариация

Измерение взаимосвязей между переменными.

```python
# Коэффициент корреляции
np.corrcoef(x, y)
# Ковариация
np.cov(x, y)
# Кросс-корреляция
np.correlate(x, y, mode='full')
```

### Гистограмма и биннинг

Анализ распределения данных и создание интервалов (бинов).

```python
# Гистограмма
counts, bins = np.histogram(arr, bins=10)
# 2D гистограмма
H, xedges, yedges = np.histogram2d(x, y, bins=10)
# Дигитализация (присвоение индексов интервалов)
bin_indices = np.digitize(arr, bins)
```

### Специальные статистические функции

Расширенные статистические вычисления.

```python
# Взвешенная статистика
np.average(arr, weights=weights)
# Уникальные значения и их количество
unique_vals, counts = np.unique(arr, return_counts=True)
# Bincount (для целочисленных массивов)
np.bincount(int_arr)
```

## Установка и настройка NumPy

### Pip: `pip install numpy`

Стандартный установщик пакетов Python.

```bash
# Установить NumPy
pip install numpy
# Обновить до последней версии
pip install numpy --upgrade
# Установить конкретную версию
pip install numpy==1.21.0
# Показать информацию о пакете
pip show numpy
```

### Conda: `conda install numpy`

Менеджер пакетов для сред Anaconda/Miniconda.

```bash
# Установить NumPy в текущей среде
conda install numpy
# Обновить NumPy
conda update numpy
# Установить из conda-forge
conda install -c conda-forge numpy
# Создать среду с NumPy
conda create -n myenv numpy
```

### Проверка установки и импорт

Проверка установки NumPy и стандартный импорт.

```python
# Стандартный импорт
import numpy as np
# Проверить версию
print(np.__version__)
# Проверить информацию о сборке
np.show_config()
# Настроить параметры вывода
np.set_printoptions(precision=2, suppress=True)
```

## Расширенные возможности

### Структурированные массивы

Массивы с именованными полями для сложных структур данных.

```python
# Определить структурированный тип данных
dt = np.dtype([('name', 'U10'), ('age', 'i4'), ('weight', 'f4')])
# Создать структурированный массив
people = np.array([('Alice', 25, 55.0), ('Bob', 30, 70.5)], dtype=dt)
# Доступ к полям
people['name']
people['age']
```

### Маскированные массивы: `np.ma`

Обработка массивов с отсутствующими или недействительными данными.

```python
# Создать маскированный массив
masked_arr = np.ma.array([1, 2, 3, 4, 5], mask=[0, 0, 1, 0, 0])
# Операции игнорируют маскированные значения
np.ma.mean(masked_arr)
# Заполнить маскированные значения
filled = masked_arr.filled(0)
```

### Полиномы: `np.poly1d`

Работа с полиномиальными выражениями и операциями.

```python
# Создать полином (коэффициенты в порядке убывания степени)
p = np.poly1d([1, -2, 1])  # x² - 2x + 1
# Оценить полином
p(5)  # Оценить при x=5
# Найти корни
np.roots([1, -2, 1])
# Полиномиальная подгонка
coeff = np.polyfit(x, y, degree=2)
```

### Быстрое преобразование Фурье: `np.fft`

Анализ частотной области и обработка сигналов.

```python
# 1D БПФ
fft_result = np.fft.fft(signal)
# Частоты
freqs = np.fft.fftfreq(len(signal))
# Обратное БПФ
reconstructed = np.fft.ifft(fft_result)
# 2D БПФ для изображений
fft2d = np.fft.fft2(image)
```

## Связанные ссылки

- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/pandas">Шпаргалка по Pandas</router-link>
- <router-link to="/matplotlib">Шпаргалка по Matplotlib</router-link>
- <router-link to="/sklearn">Шпаргалка по scikit-learn</router-link>
- <router-link to="/datascience">Шпаргалка по науке о данных</router-link>

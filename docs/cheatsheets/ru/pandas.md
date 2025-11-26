---
title: 'Шпаргалка по Pandas'
description: 'Изучите Pandas с нашей подробной шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/pandas-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Pandas
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/pandas">Изучите Pandas с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите манипулирование данными Pandas с помощью практических лабораторий и сценариев реального мира. LabEx предлагает комплексные курсы по Pandas, охватывающие основные операции, очистку данных, анализ и визуализацию. Научитесь эффективно работать с DataFrames, обрабатывать отсутствующие данные, выполнять агрегации и анализировать наборы данных с помощью мощной библиотеки анализа данных Python.
</base-disclaimer-content>
</base-disclaimer>

## Загрузка и сохранение данных

### Чтение CSV: `pd.read_csv()`

Загрузка данных из CSV-файла в DataFrame.

```python
import pandas as pd
# Чтение CSV-файла
df = pd.read_csv('data.csv')
# Установка первого столбца в качестве индекса
df = pd.read_csv('data.csv', index_col=0)
# Указание другого разделителя
df = pd.read_csv('data.csv', sep=';')
# Разбор дат
df = pd.read_csv('data.csv', parse_dates=['Date'])
```

### Чтение Excel: `pd.read_excel()`

Загрузка данных из файла Excel.

```python
# Чтение первого листа
df = pd.read_excel('data.xlsx')
# Чтение определенного листа
df = pd.read_excel('data.xlsx', sheet_name='Sheet2')
# Установка строки 2 в качестве заголовка (индексация с 0)
df = pd.read_excel('data.xlsx', header=1)
```

### Чтение SQL: `pd.read_sql()`

Чтение SQL-запроса или таблицы в DataFrame.

```python
from sqlalchemy import create_engine
engine = create_engine('sqlite:///my_database.db')
df = pd.read_sql('SELECT * FROM users', engine)
df = pd.read_sql_table('products', engine)
```

### Сохранение CSV: `df.to_csv()`

Запись DataFrame в CSV-файл.

```python
# Исключить столбец индекса
df.to_csv('output.csv', index=False)
# Исключить строку заголовка
df.to_csv('output.csv', header=False)
```

### Сохранение Excel: `df.to_excel()`

Запись DataFrame в файл Excel.

```python
# Сохранить в Excel
df.to_excel('output.xlsx', sheet_name='Results')
writer = pd.ExcelWriter('output.xlsx')
df1.to_excel(writer, sheet_name='Sheet1')
df2.to_excel(writer, sheet_name='Sheet2')
writer.save()
```

### Сохранение SQL: `df.to_sql()`

Запись DataFrame в таблицу базы данных SQL.

```python
# Создать/заменить таблицу
df.to_sql('new_table', engine, if_exists='replace', index=False)
# Добавить в существующую таблицу
df.to_sql('existing_table', engine, if_exists='append')
```

## Информация и структура DataFrame

### Основная информация: `df.info()`

Выводит краткую сводку DataFrame, включая типы данных и непустые значения.

```python
# Отобразить сводку DataFrame
df.info()
# Показать типы данных каждого столбца
df.dtypes
# Получить количество строк и столбцов (кортеж)
df.shape
# Получить имена столбцов
df.columns
# Получить индекс строк
df.index
```

### Описательная статистика: `df.describe()`

Генерирует описательную статистику числовых столбцов.

```python
# Сводная статистика для числовых столбцов
df.describe()
# Сводка для определенного столбца
df['column'].describe()
# Включить все столбцы (включая тип object)
df.describe(include='all')
```

### Просмотр данных: `df.head()` / `df.tail()`

Отображает первые или последние 'n' строк DataFrame.

```python
# Первые 5 строк
df.head()
# Последние 10 строк
df.tail(10)
# Случайные 5 строк
df.sample(5)
```

## Очистка и преобразование данных

### Отсутствующие значения: `isnull()` / `fillna()` / `dropna()`

Идентификация, заполнение или удаление отсутствующих (NaN) значений.

```python
# Подсчет отсутствующих значений по столбцам
df.isnull().sum()
# Заполнить все NaN нулем
df.fillna(0)
# Заполнить средним значением столбца
df['col'].fillna(df['col'].mean())
# Удалить строки с любым NaN
df.dropna()
# Удалить столбцы с любым NaN
df.dropna(axis=1)
```

### Дубликаты: `duplicated()` / `drop_duplicates()`

Идентификация и удаление дублирующихся строк.

```python
# Булевый ряд, указывающий на дубликаты
df.duplicated()
# Удалить все дублирующиеся строки
df.drop_duplicates()
# Удалить на основе определенных столбцов
df.drop_duplicates(subset=['col1', 'col2'])
```

### Типы данных: `astype()`

Изменение типа данных столбца.

```python
# Изменить на целое число
df['col'].astype(int)
# Изменить на строку
df['col'].astype(str)
# Преобразовать в datetime
df['col'] = pd.to_datetime(df['col'])
```

### Применение функций: `apply()` / `map()` / `replace()`

Применение функций или замена значений в DataFrames/Series.

```python
# Применить лямбда-функцию к столбцу
df['col'].apply(lambda x: x*2)
# Сопоставить значения с помощью словаря
df['col'].map({'old': 'new'})
# Заменить значения
df.replace('old_val', 'new_val')
# Заменить несколько значений
df.replace(['A', 'B'], ['C', 'D'])
```

## Инспекция DataFrame

### Уникальные значения: `unique()` / `value_counts()`

Исследование уникальных значений и их частоты.

```python
# Получить уникальные значения в столбце
df['col'].unique()
# Получить количество уникальных значений
df['col'].nunique()
# Подсчет вхождений каждого уникального значения
df['col'].value_counts()
# Доли уникальных значений
df['col'].value_counts(normalize=True)
```

### Корреляция: `corr()` / `cov()`

Вычисление корреляции и ковариации между числовыми столбцами.

```python
# Попарная корреляция столбцов
df.corr()
# Попарная ковариация столбцов
df.cov()
# Корреляция между двумя конкретными столбцами
df['col1'].corr(df['col2'])
```

### Агрегации: `groupby()` / `agg()`

Группировка данных по категориям и применение агрегирующих функций.

```python
# Среднее для каждой категории
df.groupby('category_col').mean()
# Группировка по нескольким столбцам
df.groupby(['col1', 'col2']).sum()
# Несколько агрегаций
df.groupby('category_col').agg({'num_col': ['min', 'max', 'mean']})
```

### Перекрестные таблицы: `pd.crosstab()`

Вычисление таблицы частот двух или более факторов.

```python
df.pivot_table(values='sales', index='region', columns='product', aggfunc='sum')
# Простая таблица частот
pd.crosstab(df['col1'], df['col2'])
# С суммами по строкам/столбцам
pd.crosstab(df['col1'], df['col2'], margins=True)
# С агрегированными значениями
pd.crosstab(df['col1'], df['col2'], values=df['value_col'], aggfunc='mean')
```

## Управление памятью

### Использование памяти: `df.memory_usage()`

Отображение использования памяти каждым столбцом или всем DataFrame.

```python
# Использование памяти каждым столбцом
df.memory_usage()
# Общее использование памяти в байтах
df.memory_usage(deep=True).sum()
# Подробное использование памяти в выводе info()
df.info(memory_usage='deep')
```

### Оптимизация типов данных: `astype()`

Уменьшение памяти путем преобразования столбцов в меньшие, подходящие типы данных.

```python
# Понижение разрядности целого числа
df['int_col'] = df['int_col'].astype('int16')
# Понижение разрядности числа с плавающей точкой
df['float_col'] = df['float_col'].astype('float32')
# Использование типа categorical
df['category_col'] = df['category_col'].astype('category')
```

### Чтение больших файлов по частям: `read_csv(chunksize=...)`

Обработка больших файлов частями, чтобы избежать загрузки всего в память одновременно.

```python
chunk_iterator = pd.read_csv('large_data.csv', chunksize=10000)
for chunk in chunk_iterator:
    # Обработка каждого чанка
    print(chunk.shape)
# Объединение обработанных чанков (если необходимо)
# processed_chunks = []
# for chunk in chunk_iterator:
#    processed_chunks.append(process_chunk(chunk))
# final_df = pd.concat(processed_chunks)
```

## Импорт/Экспорт данных

### Чтение JSON: `pd.read_json()`

Загрузка данных из JSON-файла или URL.

```python
# Чтение из локального JSON
df = pd.read_json('data.json')
# Чтение из URL
df = pd.read_json('http://example.com/api/data')
# Чтение из строки JSON
df = pd.read_json(json_string_data)
```

### Чтение HTML: `pd.read_html()`

Разбор HTML-таблиц из URL, строки или файла.

```python
tables = pd.read_html('http://www.w3.org/TR/html401/sgml/entities.html')
# Обычно возвращает список DataFrame
df = tables[0]
```

### В JSON: `df.to_json()`

Запись DataFrame в формате JSON.

```python
# В JSON-файл
df.to_json('output.json', orient='records', indent=4)
# В строку JSON
json_str = df.to_json(orient='split')
```

### В HTML: `df.to_html()`

Отрисовка DataFrame в виде HTML-таблицы.

```python
# В строку HTML
html_table_str = df.to_html()
# В HTML-файл
df.to_html('output.html', index=False)
```

### Чтение буфера обмена: `pd.read_clipboard()`

Чтение текста из буфера обмена в DataFrame.

```python
# Скопируйте табличные данные из веба/таблицы и выполните
df = pd.read_clipboard()
```

## Сериализация данных

### Pickle: `df.to_pickle()` / `pd.read_pickle()`

Сериализация/десериализация объектов Pandas на диск и с диска.

```python
# Сохранить DataFrame как файл pickle
df.to_pickle('my_dataframe.pkl')
# Загрузить DataFrame
loaded_df = pd.read_pickle('my_dataframe.pkl')
```

### HDF5: `df.to_hdf()` / `pd.read_hdf()`

Хранение/загрузка DataFrames с использованием формата HDF5, подходит для больших наборов данных.

```python
# Сохранить в HDF5
df.to_hdf('my_data.h5', key='df', mode='w')
# Загрузить из HDF5
loaded_df = pd.read_hdf('my_data.h5', key='df')
```

## Фильтрация и выбор данных

### По меткам: `df.loc[]` / `df.at[]`

Выбор данных по явному имени метки индекса/столбцов.

```python
# Выбрать строку с индексом 0
df.loc[0]
# Выбрать все строки для 'col1'
df.loc[:, 'col1']
# Срез строк и выбор нескольких столбцов
df.loc[0:5, ['col1', 'col2']]
# Булева индексация для строк
df.loc[df['col'] > 5]
# Быстрый доступ к скаляру по метке
df.at[0, 'col1']
```

### По позиции: `df.iloc[]` / `df.iat[]`

Выбор данных по целочисленной позиции индекса/столбцов.

```python
# Выбрать первую строку по позиции
df.iloc[0]
# Выбрать первый столбец по позиции
df.iloc[:, 0]
# Срез строк и выбор нескольких столбцов по позиции
df.iloc[0:5, [0, 1]]
# Быстрый доступ к скаляру по позиции
df.iat[0, 0]
```

### Булева индексация: `df[condition]`

Фильтрация строк на основе одного или нескольких условий.

```python
# Строки, где 'col1' больше 10
df[df['col1'] > 10]
# Несколько условий
df[(df['col1'] > 10) & (df['col2'] == 'A')]
# Строки, где 'col1' НЕ находится в списке
df[~df['col1'].isin([1, 2, 3])]
```

### Запрос данных: `df.query()`

Фильтрация строк с использованием строкового выражения запроса.

```python
# Эквивалентно булевой индексации
df.query('col1 > 10')
# Сложный запрос
df.query('col1 > 10 and col2 == "A"')
# Использование локальных переменных с '@'
df.query('col1 in @my_list')
```

## Мониторинг производительности

### Измерение времени: `%%timeit` / `time`

Измерение времени выполнения кода Python/Pandas.

```python
# Магическая команда Jupyter/IPython для измерения времени строки/ячейки
%%timeit
df['col'].apply(lambda x: x*2) # Пример операции

import time
start_time = time.time()
# Ваш код Pandas здесь
end_time = time.time()
print(f"Execution time: {end_time - start_time} seconds")
```

### Оптимизированные операции: `eval()` / `query()`

Использование этих методов для более быстрой работы с большими DataFrame, особенно для поэлементных операций и фильтрации.

```python
# Быстрее, чем `df['col1'] + df['col2']`
df['new_col'] = df.eval('col1 + col2')
# Более быстрая фильтрация
df_filtered = df.query('col1 > @threshold and col2 == "value"')
```

### Профилирование кода: `cProfile` / `line_profiler`

Анализ того, на что тратится время в ваших функциях Python.

```python
import cProfile
def my_pandas_function(df):
    # Операции Pandas
    return df.groupby('col').mean()
cProfile.run('my_pandas_function(df)') # Запуск функции с cProfile

# Для line_profiler (установить через pip install line_profiler):
# @profile
# def my_function(df):
#    ...
# %load_ext line_profiler
# %lprun -f my_function my_function(df)
```

## Установка и настройка Pandas

### Pip: `pip install pandas`

Стандартный установщик пакетов Python.

```python
# Установить Pandas
pip install pandas
# Обновить Pandas до последней версии
pip install pandas --upgrade
# Показать информацию об установленном пакете Pandas
pip show pandas
```

### Conda: `conda install pandas`

Менеджер пакетов для сред Anaconda/Miniconda.

```python
# Установить Pandas в текущей среде conda
conda install pandas
# Обновить Pandas
conda update pandas
# Показать установленный пакет Pandas
conda list pandas
# Создать новую среду с Pandas
conda create -n myenv pandas
```

### Проверка версии / Импорт

Проверка установки Pandas и импорт ее в ваших скриптах.

```python
# Стандартный псевдоним импорта
import pandas as pd
# Проверить установленную версию Pandas
print(pd.__version__)
# Отобразить все столбцы
pd.set_option('display.max_columns', None)
# Отобразить больше строк
pd.set_option('display.max_rows', 100)
```

## Конфигурация и настройки

### Параметры отображения: `pd.set_option()`

Управление тем, как DataFrame отображаются в консоли/Jupyter.

```python
# Максимальное количество отображаемых строк
pd.set_option('display.max_rows', 50)
# Отображать все столбцы
pd.set_option('display.max_columns', None)
# Ширина отображения
pd.set_option('display.width', 1000)
# Форматирование чисел с плавающей точкой
pd.set_option('display.float_format', '{:.2f}'.format)
```

### Сброс параметров: `pd.reset_option()`

Сброс определенного параметра или всех параметров к значениям по умолчанию.

```python
# Сбросить определенный параметр
pd.reset_option('display.max_rows')
# Сбросить все параметры по умолчанию
pd.reset_option('all')
```

### Получение параметров: `pd.get_option()`

Получение текущего значения указанного параметра.

```python
# Получить текущую настройку max_rows
print(pd.get_option('display.max_rows'))
```

### Менеджер контекста: `pd.option_context()`

Временная установка параметров внутри блока `with`.

```python
with pd.option_context('display.max_rows', 10, 'display.max_columns', 5):
    print(df) # DataFrame отображается с временными параметрами
print(df) # Параметры возвращаются к предыдущим настройкам за пределами блока
```

## Цепочки методов

### Цепочки операций

Применение последовательности преобразований к DataFrame.

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

### Использование `.pipe()`

Применение функций, которые принимают DataFrame в качестве первого аргумента, что позволяет использовать настраиваемые шаги в цепочке.

```python
def custom_filter(df, threshold):
    return df[df['value'] > threshold]

(
    df.pipe(custom_filter, threshold=50)
    .groupby('group')
    .agg(total_value=('value', 'sum'))
)
```

## Соответствующие ссылки

- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/numpy">Шпаргалка по NumPy</router-link>
- <router-link to="/matplotlib">Шпаргалка по Matplotlib</router-link>
- <router-link to="/sklearn">Шпаргалка по scikit-learn</router-link>
- <router-link to="/datascience">Шпаргалка по науке о данных</router-link>
- <router-link to="/mysql">Шпаргалка по MySQL</router-link>
- <router-link to="/postgresql">Шпаргалка по PostgreSQL</router-link>
- <router-link to="/sqlite">Шпаргалка по SQLite</router-link>

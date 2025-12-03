---
title: 'Шпаргалка Matplotlib | LabEx'
description: 'Изучите визуализацию данных Matplotlib с помощью этой исчерпывающей шпаргалки. Краткий справочник по построению графиков, диаграмм, подграфиков, настройке и визуализации данных на Python.'
pdfUrl: '/cheatsheets/pdf/matplotlib-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Matplotlib Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/matplotlib">Изучить Matplotlib с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите визуализацию данных Matplotlib с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по Matplotlib, охватывающие основные функции построения графиков, методы настройки, макеты подграфиков и расширенные типы визуализации. Освойте создание эффективных визуализаций данных для рабочих процессов науки о данных на Python.
</base-disclaimer-content>
</base-disclaimer>

## Базовое построение графиков и типы диаграмм

### Линейный график: `plt.plot()`

Создание линейных диаграмм для визуализации непрерывных данных.

```python
import matplotlib.pyplot as plt
import numpy as np

# Базовый линейный график
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
plt.plot(x, y)
plt.show()

# Несколько линий
plt.plot(x, y, label='Линия 1')
plt.plot(x, [1, 3, 5, 7, 9], label='Линия 2')
plt.legend()

# Стили линий и цвета
plt.plot(x, y, 'r--', linewidth=2, marker='o')
```

<BaseQuiz id="matplotlib-plot-1" correct="C">
  <template #question>
    Что делает `plt.show()` в Matplotlib?
  </template>
  
  <BaseQuizOption value="A">Сохраняет график в файл</BaseQuizOption>
  <BaseQuizOption value="B">Закрывает окно графика</BaseQuizOption>
  <BaseQuizOption value="C" correct>Отображает график в окне</BaseQuizOption>
  <BaseQuizOption value="D">Очищает график</BaseQuizOption>
  
  <BaseQuizAnswer>
    `plt.show()` отображает график в интерактивном окне. Необходимо вызвать эту функцию, чтобы увидеть визуализацию. Без нее график не будет отображен.
  </BaseQuizAnswer>
</BaseQuiz>

### Точечная диаграмма: `plt.scatter()`

Отображение взаимосвязей между двумя переменными.

```python
# Базовая точечная диаграмма
plt.scatter(x, y)

# С разными цветами и размерами
colors = [1, 2, 3, 4, 5]
sizes = [20, 50, 100, 200, 500]
plt.scatter(x, y, c=colors, s=sizes, alpha=0.6)
plt.colorbar()  # Добавить цветовую шкалу
```

<BaseQuiz id="matplotlib-scatter-1" correct="D">
  <template #question>
    Что контролирует параметр `alpha` в графиках matplotlib?
  </template>
  
  <BaseQuizOption value="A">Цвет графика</BaseQuizOption>
  <BaseQuizOption value="B">Размер графика</BaseQuizOption>
  <BaseQuizOption value="C">Положение графика</BaseQuizOption>
  <BaseQuizOption value="D" correct>Прозрачность/непрозрачность элементов графика</BaseQuizOption>
  
  <BaseQuizAnswer>
    Параметр `alpha` контролирует прозрачность, со значениями от 0 (полностью прозрачный) до 1 (полностью непрозрачный). Он полезен для создания перекрывающихся визуализаций, где вы хотите видеть сквозь элементы.
  </BaseQuizAnswer>
</BaseQuiz>

### Столбчатая диаграмма: `plt.bar()` / `plt.barh()`

Создание вертикальных или горизонтальных столбчатых диаграмм.

```python
# Вертикальные столбцы
categories = ['A', 'B', 'C', 'D']
values = [20, 35, 30, 25]
plt.bar(categories, values)

# Горизонтальные столбцы
plt.barh(categories, values)

# Группированные столбцы
x = np.arange(len(categories))
plt.bar(x - 0.2, values, 0.4, label='Группа 1')
plt.bar(x + 0.2, [15, 25, 35, 20], 0.4, label='Группа 2')
```

### Гистограмма: `plt.hist()`

Отображение распределения непрерывных данных.

```python
# Базовая гистограмма
data = np.random.randn(1000)
plt.hist(data, bins=30)

# Настроенная гистограмма
plt.hist(data, bins=50, alpha=0.7, color='skyblue', edgecolor='black')

# Несколько гистограмм
plt.hist([data1, data2], bins=30, alpha=0.7, label=['Данные 1', 'Данные 2'])
```

### Круговая диаграмма: `plt.pie()`

Отображение пропорциональных данных в виде круговой диаграммы.

```python
# Базовая круговая диаграмма
sizes = [25, 35, 20, 20]
labels = ['A', 'B', 'C', 'D']
plt.pie(sizes, labels=labels)

# Выделенный круг с процентами
explode = (0, 0.1, 0, 0)  # Выделить 2-й сектор
plt.pie(sizes, labels=labels, autopct='%1.1f%%',
        explode=explode, shadow=True, startangle=90)
```

### Ящичковая диаграмма: `plt.boxplot()`

Визуализация распределения данных и выбросов.

```python
# Одна ящичковая диаграмма
data = [np.random.randn(100) for _ in range(4)]
plt.boxplot(data)

# Настроенная ящичковая диаграмма
plt.boxplot(data, labels=['Группа 1', 'Группа 2', 'Группа 3', 'Группа 4'],
           patch_artist=True, notch=True)
```

## Настройка и стилизация графика

### Метки и заголовки: `plt.xlabel()` / `plt.title()`

Добавление описательного текста для ясности и контекста ваших графиков.

```python
# Базовые метки и заголовок
plt.plot(x, y)
plt.xlabel('Метка оси X')
plt.ylabel('Метка оси Y')
plt.title('Заголовок графика')

# Форматированные заголовки со свойствами шрифта
plt.title('Мой график', fontsize=16, fontweight='bold')
plt.xlabel('Значения X', fontsize=12)

# Сетка для лучшей читаемости
plt.grid(True, alpha=0.3)
```

### Цвета и стили: `color` / `linestyle` / `marker`

Настройка визуального оформления элементов графика.

```python
# Варианты цвета
plt.plot(x, y, color='red')  # Именованные цвета
plt.plot(x, y, color='#FF5733')  # Hex-коды
plt.plot(x, y, color=(0.1, 0.2, 0.5))  # RGB кортеж

# Стили линий
plt.plot(x, y, linestyle='--')  # Пунктирная
plt.plot(x, y, linestyle=':')   # Точечная
plt.plot(x, y, linestyle='-.')  # Штрих-пунктирная

# Маркеры
plt.plot(x, y, marker='o', markersize=8, markerfacecolor='red')
```

### Легенды и аннотации: `plt.legend()` / `plt.annotate()`

Добавление легенд и аннотаций для объяснения элементов графика.

```python
# Базовая легенда
plt.plot(x, y1, label='Набор данных 1')
plt.plot(x, y2, label='Набор данных 2')
plt.legend()

# Настройка положения легенды
plt.legend(loc='upper right', fontsize=10, frameon=False)

# Аннотации
plt.annotate('Важная точка', xy=(2, 4), xytext=(3, 6),
            arrowprops=dict(arrowstyle='->', color='red'))
```

<BaseQuiz id="matplotlib-legend-1" correct="B">
  <template #question>
    Что требуется для отображения меток с помощью `plt.legend()`?
  </template>
  
  <BaseQuizOption value="A">Ничего, она работает автоматически</BaseQuizOption>
  <BaseQuizOption value="B" correct>Каждому графику должен быть задан параметр `label`</BaseQuizOption>
  <BaseQuizOption value="C">Легенда должна быть создана до построения графика</BaseQuizOption>
  <BaseQuizOption value="D">Метки должны быть заданы вручную в легенде</BaseQuizOption>
  
  <BaseQuizAnswer>
    Чтобы отобразить легенду, необходимо установить параметр `label` при создании каждого графика (например, `plt.plot(x, y, label='Набор данных 1')`). Затем вызов `plt.legend()` отобразит все метки.
  </BaseQuizAnswer>
</BaseQuiz>

## Управление осями и макетом

### Пределы осей: `plt.xlim()` / `plt.ylim()`

Управление диапазоном значений, отображаемых на каждой оси.

```python
# Установка пределов осей
plt.xlim(0, 10)
plt.ylim(-5, 15)

# Автоматическая настройка пределов с запасом
plt.margins(x=0.1, y=0.1)

# Инвертировать ось
plt.gca().invert_yaxis()  # Инвертировать ось Y
```

### Тики и метки: `plt.xticks()` / `plt.yticks()`

Настройка отметок тиков на осях и их меток.

```python
# Пользовательские позиции тиков
plt.xticks([0, 2, 4, 6, 8, 10])
plt.yticks(np.arange(0, 101, 10))

# Пользовательские метки тиков
plt.xticks([0, 1, 2, 3], ['Янв', 'Фев', 'Мар', 'Апр'])

# Поворот меток тиков
plt.xticks(rotation=45)

# Удалить тики
plt.xticks([])
plt.yticks([])
```

### Соотношение сторон: `plt.axis()`

Управление соотношением сторон и внешним видом осей.

```python
# Равное соотношение сторон
plt.axis('equal')
# Квадратный график
plt.axis('square')
# Отключить ось
plt.axis('off')
# Пользовательское соотношение сторон
plt.gca().set_aspect('equal', adjustable='box')
```

### Размер фигуры: `plt.figure()`

Управление общим размером и разрешением ваших графиков.

```python
# Установка размера фигуры (ширина, высота в дюймах)
plt.figure(figsize=(10, 6))

# Высокое DPI для лучшего качества
plt.figure(figsize=(8, 6), dpi=300)

# Несколько фигур
fig1 = plt.figure(1)
plt.plot(x, y1)
fig2 = plt.figure(2)
plt.plot(x, y2)
```

### Плотное расположение: `plt.tight_layout()`

Автоматическая настройка интервалов подграфиков для лучшего внешнего вида.

```python
# Предотвращение перекрытия элементов
plt.tight_layout()

# Ручная настройка интервалов
plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)

# Отступы вокруг подграфиков
plt.tight_layout(pad=3.0)
```

### Таблицы стилей: `plt.style.use()`

Применение предопределенных стилей для согласованного внешнего вида графиков.

```python
# Доступные стили
print(plt.style.available)

# Использование встроенных стилей
plt.style.use('seaborn-v0_8')
plt.style.use('ggplot')
plt.style.use('bmh')

# Сброс к значению по умолчанию
plt.style.use('default')
```

## Подграфики и несколько графиков

### Базовые подграфики: `plt.subplot()` / `plt.subplots()`

Создание нескольких графиков на одной фигуре.

```python
# Создание сетки подграфиков 2x2
fig, axes = plt.subplots(2, 2, figsize=(10, 8))

# Построение графика в каждом подграфике
axes[0, 0].plot(x, y)
axes[0, 1].scatter(x, y)
axes[1, 0].bar(x, y)
axes[1, 1].hist(y, bins=10)

# Альтернативный синтаксис
plt.subplot(2, 2, 1)  # 2 строки, 2 столбца, 1-й подграфик
plt.plot(x, y)
plt.subplot(2, 2, 2)  # 2-й подграфик
plt.scatter(x, y)
```

### Общие оси: `sharex` / `sharey`

Связывание осей между подграфиками для согласованного масштабирования.

```python
# Общая ось X для подграфиков
fig, axes = plt.subplots(2, 1, sharex=True)
axes[0].plot(x, y1)
axes[1].plot(x, y2)

# Общие обе оси
fig, axes = plt.subplots(2, 2, sharex=True, sharey=True)
```

### GridSpec: Расширенные макеты

Создание сложных расположений подграфиков с изменяющимся размером.

```python
import matplotlib.gridspec as gridspec

# Создание пользовательской сетки
gs = gridspec.GridSpec(3, 3)
fig = plt.figure(figsize=(10, 8))

# Подграфики разного размера
ax1 = fig.add_subplot(gs[0, :])  # Верхний ряд, все столбцы
ax2 = fig.add_subplot(gs[1, :-1])  # Средний ряд, первые 2 столбца
ax3 = fig.add_subplot(gs[1:, -1])  # Последний столбец, нижние 2 ряда
ax4 = fig.add_subplot(gs[-1, 0])   # Нижний левый
ax5 = fig.add_subplot(gs[-1, 1])   # Нижний средний
```

### Интервал подграфиков: `hspace` / `wspace`

Управление интервалом между подграфиками.

```python
# Настройка интервала при создании подграфиков
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
plt.subplots_adjust(hspace=0.4, wspace=0.3)

# Или используйте tight_layout для автоматической настройки
plt.tight_layout()
```

## Расширенные типы визуализации

### Тепловые карты: `plt.imshow()` / `plt.pcolormesh()`

Визуализация 2D-данных в виде матриц, закодированных цветом.

```python
# Базовая тепловая карта
data = np.random.randn(10, 10)
plt.imshow(data, cmap='viridis')
plt.colorbar()

# Pcolormesh для нерегулярных сеток
x = np.linspace(0, 10, 11)
y = np.linspace(0, 5, 6)
X, Y = np.meshgrid(x, y)
Z = np.sin(X) * np.cos(Y)
plt.pcolormesh(X, Y, Z, shading='auto')
plt.colorbar()
```

### Контурные графики: `plt.contour()` / `plt.contourf()`

Отображение кривых уровня и заполненных контурных областей.

```python
# Линии контура
x = np.linspace(-3, 3, 100)
y = np.linspace(-3, 3, 100)
X, Y = np.meshgrid(x, y)
Z = X**2 + Y**2
plt.contour(X, Y, Z, levels=10)
plt.clabel(plt.contour(X, Y, Z), inline=True, fontsize=8)

# Заполненные контуры
plt.contourf(X, Y, Z, levels=20, cmap='RdBu')
plt.colorbar()
```

### 3D Графики: `mplot3d`

Создание трехмерных визуализаций.

```python
from mpl_toolkits.mplot3d import Axes3D

fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

# 3D точечная диаграмма
ax.scatter(x, y, z)

# 3D поверхностный график
ax.plot_surface(X, Y, Z, cmap='viridis')

# 3D линейный график
ax.plot(x, y, z)
```

### Полосы погрешностей: `plt.errorbar()`

Отображение данных с измерениями неопределенности.

```python
# Базовые полосы погрешностей
x = [1, 2, 3, 4, 5]
y = [2, 4, 6, 8, 10]
yerr = [0.5, 0.8, 0.3, 0.7, 0.4]
plt.errorbar(x, y, yerr=yerr, fmt='o-', capsize=5)

# Асимметричные полосы погрешностей
yerr_lower = [0.4, 0.6, 0.2, 0.5, 0.3]
yerr_upper = [0.6, 1.0, 0.4, 0.9, 0.5]
plt.errorbar(x, y, yerr=[yerr_lower, yerr_upper], fmt='s-')
```

### Заполнение между: `plt.fill_between()`

Затенение областей между кривыми или вокруг линий.

```python
# Заполнение между двумя кривыми
y1 = [2, 4, 6, 8, 10]
y2 = [1, 3, 5, 7, 9]
plt.fill_between(x, y1, y2, alpha=0.3, color='blue')

# Заполнение вокруг линии с погрешностью
plt.plot(x, y, 'k-', linewidth=2)
plt.fill_between(x, y-yerr, y+yerr, alpha=0.2, color='gray')
```

### Скрипичные диаграммы: Альтернатива ящичковым диаграммам

Отображение формы распределения вместе с квартилями.

```python
# Использование pyplot
parts = plt.violinplot([data1, data2, data3])

# Настройка цветов
for pc in parts['bodies']:
    pc.set_facecolor('lightblue')
    pc.set_alpha(0.7)
```

## Интерактивные функции и анимация

### Интерактивный бэкенд: `%matplotlib widget`

Включение интерактивных графиков в Jupyter notebook.

```python
# В Jupyter notebook
%matplotlib widget

# Или для базовой интерактивности
%matplotlib notebook
```

### Обработка событий: Мышь и клавиатура

Реагирование на взаимодействие пользователя с графиками.

```python
# Интерактивное масштабирование, панорамирование и наведение
def onclick(event):
    if event.inaxes:
        print(f'Нажато по x={event.xdata}, y={event.ydata}')

fig, ax = plt.subplots()
ax.plot(x, y)
fig.canvas.mpl_connect('button_press_event', onclick)
plt.show()
```

### Анимации: `matplotlib.animation`

Создание анимированных графиков для временных рядов или изменяющихся данных.

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

# Сохранить анимацию
# ani.save('animation.gif', writer='pillow')
```

## Сохранение и экспорт графиков

### Сохранить фигуру: `plt.savefig()`

Экспорт графиков в файлы изображений с различными опциями.

```python
# Базовое сохранение
plt.savefig('my_plot.png')

# Сохранение высокого качества
plt.savefig('plot.png', dpi=300, bbox_inches='tight')

# Различные форматы
plt.savefig('plot.pdf')  # PDF
plt.savefig('plot.svg')  # SVG (векторный)
plt.savefig('plot.eps')  # EPS

# Прозрачный фон
plt.savefig('plot.png', transparent=True)
```

### Качество фигуры: DPI и размер

Управление разрешением и размерами сохраненных графиков.

```python
# Высокий DPI для публикаций
plt.savefig('plot.png', dpi=600)

# Пользовательский размер (ширина, высота в дюймах)
plt.figure(figsize=(12, 8))
plt.savefig('plot.png', figsize=(12, 8))

# Обрезка пустого пространства
plt.savefig('plot.png', bbox_inches='tight', pad_inches=0.1)
```

### Пакетный экспорт и управление памятью

Обработка нескольких графиков и эффективное использование памяти.

```python
# Закрыть фигуры для освобождения памяти
plt.close()  # Закрыть текущую фигуру
plt.close('all')  # Закрыть все фигуры

# Менеджер контекста для автоматической очистки
with plt.figure() as fig:
    plt.plot(x, y)
    plt.savefig('plot.png')

# Пакетное сохранение нескольких графиков
for i, data in enumerate(datasets):
    plt.figure()
    plt.plot(data)
    plt.savefig(f'plot_{i}.png')
    plt.close()
```

## Конфигурация и лучшие практики

### RC Параметры: `plt.rcParams`

Установка стилей по умолчанию и поведения для всех графиков.

```python
# Общие rc параметры
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 12
plt.rcParams['lines.linewidth'] = 2
plt.rcParams['axes.grid'] = True

# Сохранение и восстановление настроек
original_params = plt.rcParams.copy()
# ... внести изменения ...
plt.rcParams.update(original_params)  # Восстановить
```

### Управление цветом: Цветовые карты и палитры

Эффективная работа с цветами и цветовыми картами.

```python
# Список доступных цветовых карт
print(plt.colormaps())

# Использование цветовой карты для нескольких линий
colors = plt.cm.viridis(np.linspace(0, 1, len(datasets)))
for i, (data, color) in enumerate(zip(datasets, colors)):
    plt.plot(data, color=color, label=f'Набор данных {i+1}')

# Пользовательская цветовая карта
from matplotlib.colors import LinearSegmentedColormap
custom_cmap = LinearSegmentedColormap.from_list('custom', ['red', 'yellow', 'blue'])
```

### Оптимизация производительности

Улучшение построения графиков для больших наборов данных.

```python
# Использование blitting для анимаций
ani = FuncAnimation(fig, animate, blit=True)

# Растеризация сложных графиков
plt.plot(x, y, rasterized=True)

# Уменьшение количества точек данных для больших наборов данных
# Даунсэмплинг данных перед построением графика
indices = np.arange(0, len(large_data), step=10)
plt.plot(large_data[indices])
```

### Использование памяти: Эффективное построение графиков

Управление памятью при создании множества графиков или больших визуализаций.

```python
# Очистка осей вместо создания новых фигур
fig, ax = plt.subplots()
for data in datasets:
    ax.clear()  # Очистить предыдущий график
    ax.plot(data)
    plt.savefig(f'plot_{i}.png')

# Использование генераторов для больших наборов данных
def data_generator():
    for i in range(1000):
        yield np.random.randn(100)

for i, data in enumerate(data_generator()):
    if i > 10:  # Ограничить количество графиков
        break
```

## Интеграция с библиотеками данных

### Интеграция с Pandas: Прямое построение графиков

Использование методов DataFrame для построения графиков.

```python
import pandas as pd

# Построение графика DataFrame (использует бэкенд matplotlib)
df.plot(kind='line', x='date', y='value')
df.plot.scatter(x='x_col', y='y_col')
df.plot.hist(bins=30)
df.plot.box()

# Доступ к базовым объектам matplotlib
ax = df.plot(kind='line')
ax.set_title('Пользовательский заголовок')
plt.show()
```

### Интеграция с NumPy: Визуализация массивов

Эффективное построение графиков массивов NumPy и математических функций.

```python
# Визуализация 2D массива
arr = np.random.rand(10, 10)
plt.imshow(arr, cmap='hot', interpolation='nearest')

# Математические функции
x = np.linspace(0, 4*np.pi, 1000)
y = np.sin(x) * np.exp(-x/10)
plt.plot(x, y)

# Статистические распределения
data = np.random.normal(0, 1, 10000)
plt.hist(data, bins=50, density=True, alpha=0.7)
```

### Интеграция с Seaborn: Улучшенная стилизация

Объединение Matplotlib с Seaborn для лучшей эстетики по умолчанию.

```python
import seaborn as sns

# Использование стиля seaborn с matplotlib
sns.set_style('whitegrid')
plt.plot(x, y)
plt.show()

# Смешивание seaborn и matplotlib
fig, axes = plt.subplots(2, 2, figsize=(10, 8))
sns.scatterplot(data=df, x='x', y='y', ax=axes[0,0])
plt.plot(x, y, ax=axes[0,1])  # Чистый matplotlib
```

### Интеграция с Jupyter: Встроенное построение графиков

Оптимизация Matplotlib для сред Jupyter notebook.

```python
# Магические команды для Jupyter
%matplotlib inline  # Статические графики
%matplotlib widget  # Интерактивные графики

# Дисплеи с высоким DPI
%config InlineBackend.figure_format = 'retina'

# Автоматическое определение размера фигуры
%matplotlib inline
plt.rcParams['figure.dpi'] = 100
```

## Установка и настройка среды

### Pip: `pip install matplotlib`

Стандартный установщик пакетов Python для Matplotlib.

```bash
# Установка Matplotlib
pip install matplotlib

# Обновление до последней версии
pip install matplotlib --upgrade

# Установка с дополнительными бэкендами
pip install matplotlib[qt5]

# Показать информацию о пакете
pip show matplotlib
```

### Conda: `conda install matplotlib`

Менеджер пакетов для сред Anaconda/Miniconda.

```bash
# Установка в текущей среде
conda install matplotlib

# Обновление matplotlib
conda update matplotlib

# Создание среды с matplotlib
conda create -n dataviz matplotlib numpy pandas

# Показать информацию о matplotlib
conda list matplotlib
```

### Конфигурация бэкенда

Настройка бэкендов отображения для различных сред.

```python
# Проверить доступные бэкенды
import matplotlib
print(matplotlib.get_backend())

# Установить бэкенд программно
matplotlib.use('TkAgg')  # Для Tkinter
matplotlib.use('Qt5Agg')  # Для PyQt5

# Для безголовых серверов
matplotlib.use('Agg')

# Импортировать после установки бэкенда
import matplotlib.pyplot as plt
```

## Связанные ссылки

- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/numpy">NumPy Cheatsheet</router-link>
- <router-link to="/pandas">Pandas Cheatsheet</router-link>
- <router-link to="/sklearn">scikit-learn Cheatsheet</router-link>
- <router-link to="/datascience">Data Science Cheatsheet</router-link>

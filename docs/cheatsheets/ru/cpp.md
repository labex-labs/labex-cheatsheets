---
title: 'Шпаргалка по C++ | LabEx'
description: 'Изучите программирование на C++ с помощью этой исчерпывающей шпаргалки. Быстрый справочник по синтаксису C++, ООП, STL, шаблонам, управлению памятью и функциям современного C++ для разработчиков ПО.'
pdfUrl: '/cheatsheets/pdf/cpp-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по C++
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/cpp">Изучите C++ с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучайте программирование на C++ с помощью практических лабораторных работ и сценариев из реального мира. LabEx предлагает комплексные курсы по C++, охватывающие основной синтаксис, объектно-ориентированное программирование, контейнеры STL, управление памятью и продвинутые методы. Освойте мощные возможности C++ для создания высокопроизводительных приложений и системного программного обеспечения.
</base-disclaimer-content>
</base-disclaimer>

## Базовый синтаксис и структура

### Программа "Hello World"

Базовая структура программы на C++.

```cpp
#include <iostream>
using namespace std;
int main() {
    cout << "Hello, World!" << endl;
    return 0;
}
```

### Заголовки и пространства имен

Подключение библиотек и управление пространствами имен.

```cpp
#include <iostream>  // Поток ввода/вывода
#include <vector>    // Динамические массивы
#include <string>    // Класс строки
#include <algorithm> // Алгоритмы STL
using namespace std;
// Или указывать индивидуально:
// using std::cout;
// using std::cin;
```

### Комментарии

Однострочные и многострочные комментарии.

```cpp
// Однострочный комментарий
/*
Многострочный комментарий
охватывает несколько строк
*/
// TODO: Реализовать функцию
/* FIXME: Ошибка в этом разделе */
```

### Функция Main

Точка входа программы с возвращаемыми значениями.

```cpp
int main() {
    // Код программы здесь
    return 0;  // Успех
}
int main(int argc, char* argv[]) {
    // argc: количество аргументов
    // argv: значения аргументов (командная строка)
    return 0;
}
```

<BaseQuiz id="cpp-main-1" correct="B">
  <template #question>
    В чем разница между операторами вывода в C и C++?
  </template>
  
  <BaseQuizOption value="A">Разницы нет</BaseQuizOption>
  <BaseQuizOption value="B" correct>C использует printf(), C++ использует cout с оператором <<</BaseQuizOption>
  <BaseQuizOption value="C">C++ не поддерживает вывод</BaseQuizOption>
  <BaseQuizOption value="D">C использует cout, C++ использует printf</BaseQuizOption>
  
  <BaseQuizAnswer>
    C использует `printf()` из stdio.h, в то время как C++ использует `cout` из iostream с оператором вставки потока `<<`. C++ также поддерживает printf для совместимости.
  </BaseQuizAnswer>
</BaseQuiz>

### Базовый вывод

Отображение текста и переменных в консоли.

```cpp
cout << "Hello" << endl;
cout << "Value: " << 42 << endl;
// Несколько значений в одной строке
cout << "Name: " << name << ", Age: " << age << endl;
```

### Базовый ввод

Чтение ввода пользователя из консоли.

```cpp
int age;
string name;
cin >> age;
cin >> name;
// Чтение всей строки с пробелами
getline(cin, name);
```

## Типы данных и переменные

### Примитивные типы

Основные типы данных для хранения различных видов значений.

```cpp
// Целочисленные типы
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// Типы с плавающей точкой
float price = 19.99f;
double precise = 3.14159265359;
// Символ и булево значение
char grade = 'A';
bool is_valid = true;
```

### Строки и массивы

Типы данных для текста и коллекций.

```cpp
// Строки
string name = "John Doe";
string empty_str;
// Массивы
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// Динамические массивы (векторы)
vector<int> dynamic_array = {10, 20, 30};
vector<string> names(5); // Размер 5, пустые строки
```

<BaseQuiz id="cpp-vector-1" correct="B">
  <template #question>
    В чем основное преимущество `vector` перед обычными массивами в C++?
  </template>
  
  <BaseQuizOption value="A">Векторы работают быстрее</BaseQuizOption>
  <BaseQuizOption value="B" correct>Векторы могут динамически изменять размер, в то время как массивы имеют фиксированный размер</BaseQuizOption>
  <BaseQuizOption value="C">Векторы используют меньше памяти</BaseQuizOption>
  <BaseQuizOption value="D">Преимуществ нет</BaseQuizOption>
  
  <BaseQuizAnswer>
    `vector` — это динамический массив, который может расти или уменьшаться во время выполнения, в отличие от обычных массивов, размер которых фиксируется на этапе компиляции. Это делает векторы более гибкими для многих сценариев использования.
  </BaseQuizAnswer>
</BaseQuiz>

### Константы и Auto

Неизменяемые значения и автоматическое определение типа.

```cpp
// Константы
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Ключевое слово Auto (C++11+)
auto x = 42;        // int
auto y = 3.14;      // double
auto name = "John"; // const char*
// Псевдонимы типов
typedef unsigned int uint;
using real = double;
```

## Структуры управления потоком

### Условные операторы

Принятие решений на основе условий.

```cpp
// Оператор If-else
if (age >= 18) {
    cout << "Adult" << endl;
} else if (age >= 13) {
    cout << "Teenager" << endl;
} else {
    cout << "Child" << endl;
}
// Тернарный оператор
string status = (age >= 18) ? "Adult" : "Minor";
// Оператор Switch
switch (grade) {
    case 'A':
        cout << "Excellent!" << endl;
        break;
    case 'B':
        cout << "Good job!" << endl;
        break;
    default:
        cout << "Keep trying!" << endl;
}
```

### Циклы For

Итерация с циклами, основанными на счетчике.

```cpp
// Традиционный цикл for
for (int i = 0; i < 10; i++) {
    cout << i << " ";
}
// Цикл for на основе диапазона (C++11+)
vector<int> numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    cout << num << " ";
}
// Auto с циклом на основе диапазона
for (auto& item : container) {
    // Обработка элемента
}
```

<BaseQuiz id="cpp-range-for-1" correct="B">
  <template #question>
    Что такое цикл for на основе диапазона в C++?
  </template>
  
  <BaseQuizOption value="A">Цикл, который работает только с массивами</BaseQuizOption>
  <BaseQuizOption value="B" correct>Цикл, который автоматически перебирает все элементы в контейнере</BaseQuizOption>
  <BaseQuizOption value="C">Цикл, который работает бесконечно</BaseQuizOption>
  <BaseQuizOption value="D">Цикл, который требует ручного управления индексами</BaseQuizOption>
  
  <BaseQuizAnswer>
    Циклы for на основе диапазона (введенные в C++11) автоматически перебирают все элементы в контейнере (например, векторах, массивах, строках) без необходимости вручную управлять индексами. Синтаксис: `for (auto item : container)`.
  </BaseQuizAnswer>
</BaseQuiz>

### Циклы While

Итерация на основе условия.

```cpp
// Цикл While
int count = 0;
while (count < 5) {
    cout << count << endl;
    count++;
}
// Цикл Do-while (выполняется как минимум один раз)
int input;
do {
    cout << "Enter a number (0 to quit): ";
    cin >> input;
} while (input != 0);
```

### Управление циклами

Операторы `break` и `continue`.

```cpp
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // Пропустить итерацию
    }
    if (i == 7) {
        break;    // Выйти из цикла
    }
    cout << i << " ";
}
// Вложенные циклы с именованным break
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // Прерывается только внутренний цикл
        cout << i << "," << j << " ";
    }
}
```

## Функции

### Объявление и определение функции

Создание многократно используемых блоков кода.

```cpp
// Объявление функции (прототип)
int add(int a, int b);
void printMessage(string msg);
// Определение функции
int add(int a, int b) {
    return a + b;
}
void printMessage(string msg) {
    cout << msg << endl;
}
// Вызов функции
int result = add(5, 3);
printMessage("Hello, functions!");
```

### Перегрузка функций

Несколько функций с одинаковым именем.

```cpp
// Разные типы параметров
int multiply(int a, int b) {
    return a * b;
}
double multiply(double a, double b) {
    return a * b;
}
// Разное количество параметров
int multiply(int a, int b, int c) {
    return a * b * c;
}
```

### Параметры по умолчанию

Предоставление значений по умолчанию для параметров функции.

```cpp
void greet(string name, string greeting = "Hello") {
    cout << greeting << ", " << name << "!" << endl;
}
// Вызовы функций
greet("Alice");              // Используется значение по умолчанию "Hello"
greet("Bob", "Good morning"); // Используется настраиваемое приветствие
```

### Передача по ссылке

Изменение переменных через параметры функции.

```cpp
// Передача по значению (копия)
void changeValue(int x) {
    x = 100; // Оригинальная переменная не изменится
}
// Передача по ссылке
void changeReference(int& x) {
    x = 100; // Оригинальная переменная изменится
}
// Константная ссылка (только для чтения, эффективно)
void processLargeData(const vector<int>& data) {
    // Можно читать данные, но не изменять
}
```

## Объектно-ориентированное программирование

### Определение класса

Определение пользовательских типов данных с атрибутами и методами.

```cpp
class Rectangle {
private:
    double width, height;
public:
    // Конструктор
    Rectangle(double w, double h) : width(w), height(h) {}

    // Конструктор по умолчанию
    Rectangle() : width(0), height(0) {}

    // Функции-члены
    double area() const {
        return width * height;
    }

    void setDimensions(double w, double h) {
        width = w;
        height = h;
    }

    // Функции-получатели (геттеры)
    double getWidth() const { return width; }
    double getHeight() const { return height; }
};
```

### Создание и использование объектов

Создание экземпляров и использование объектов класса.

```cpp
// Создание объектов
Rectangle rect1(5.0, 3.0);
Rectangle rect2; // Конструктор по умолчанию
// Использование функций-членов
cout << "Area: " << rect1.area() << endl;
rect2.setDimensions(4.0, 2.0);
// Динамическое выделение
Rectangle* rect3 = new Rectangle(6.0, 4.0);
cout << rect3->area() << endl;
delete rect3; // Освобождение памяти
```

### Наследование

Создание специализированных классов на основе базовых классов.

```cpp
class Shape {
protected:
    string color;

public:
    Shape(string c) : color(c) {}
    virtual double area() const = 0; // Чисто виртуальная функция
    string getColor() const { return color; }
};
class Circle : public Shape {
private:
    double radius;

public:
    Circle(double r, string c) : Shape(c), radius(r) {}

    double area() const override {
        return 3.14159 * radius * radius;
    }
};
```

### Полиморфизм

Использование указателей базового класса для доступа к объектам производного класса.

```cpp
// Виртуальные функции и полиморфизм
vector<Shape*> shapes;
shapes.push_back(new Circle(5.0, "red"));
shapes.push_back(new Rectangle(4.0, 6.0));
for (Shape* shape : shapes) {
    cout << "Area: " << shape->area() << endl;
    // Вызывается соответствующий метод производного класса
}
```

## Управление памятью

### Динамическое выделение памяти

Выделение и освобождение памяти во время выполнения.

```cpp
// Один объект
int* ptr = new int(42);
cout << *ptr << endl;
delete ptr;
ptr = nullptr;
// Выделение массива
int* arr = new int[10];
for (int i = 0; i < 10; i++) {
    arr[i] = i * i;
}
delete[] arr;
// Проверка на сбой выделения
int* large_array = new(nothrow) int[1000000];
if (large_array == nullptr) {
    cout << "Allocation failed!" << endl;
}
```

### Умные указатели (C++11+)

Автоматическое управление памятью с помощью RAII.

```cpp
#include <memory>
// unique_ptr (эксклюзивное владение)
unique_ptr<int> ptr1 = make_unique<int>(42);
unique_ptr<int> ptr2 = move(ptr1); // Передача владения
// shared_ptr (совместное владение)
shared_ptr<int> sptr1 = make_shared<int>(100);
shared_ptr<int> sptr2 = sptr1; // Совместное владение
cout << sptr1.use_count() << endl; // Счетчик ссылок
```

### Ссылки против указателей

Два способа косвенного доступа к объектам.

```cpp
int x = 10;
// Ссылка (псевдоним)
int& ref = x;  // Должна быть инициализирована
ref = 20;      // Изменяет x на 20
// Указатель
int* ptr = &x; // Указывает на адрес x
*ptr = 30;     // Разыменование и изменение x
ptr = nullptr; // Может указывать на ничто
// Вариации с const
const int* ptr1 = &x;    // Нельзя изменять значение
int* const ptr2 = &x;    // Нельзя изменять адрес
const int* const ptr3 = &x; // Нельзя изменять ни то, ни другое
```

### Стек против Кучи

Стратегии выделения памяти.

```cpp
// Выделение в стеке (автоматическое)
int stack_var = 42;
int stack_array[100];
// Выделение в куче (динамическое)
int* heap_var = new int(42);
int* heap_array = new int[100];
// Объекты в стеке очищаются автоматически
// Объекты в куче должны быть удалены вручную
delete heap_var;
delete[] heap_array;
```

## Стандартная библиотека шаблонов (STL)

### Контейнеры: Vector и String

Динамические массивы и манипуляции со строками.

```cpp
#include <vector>
#include <string>
// Операции с вектором
vector<int> nums = {1, 2, 3};
nums.push_back(4);        // Добавить элемент
nums.pop_back();          // Удалить последний
nums.insert(nums.begin() + 1, 10); // Вставить по позиции
nums.erase(nums.begin()); // Удалить первый
// Операции со строками
string text = "Hello";
text += " World";         // Конкатенация
text.append("!");         // Добавить в конец
cout << text.substr(0, 5) << endl; // Подстрока
text.replace(6, 5, "C++"); // Заменить "World" на "C++"
```

### Контейнеры: Map и Set

Ассоциативные контейнеры для пар ключ-значение и уникальных элементов.

```cpp
#include <map>
#include <set>
// Map (пары ключ-значение)
map<string, int> ages;
ages["Alice"] = 25;
ages["Bob"] = 30;
ages.insert({"Charlie", 35});
// Set (уникальные элементы)
set<int> unique_nums = {3, 1, 4, 1, 5, 9};
unique_nums.insert(2);
unique_nums.erase(1);
// Автоматически отсортировано: {2, 3, 4, 5, 9}
```

### Алгоритмы

Алгоритмы STL для общих операций.

```cpp
#include <algorithm>
vector<int> nums = {64, 34, 25, 12, 22, 11, 90};
// Сортировка
sort(nums.begin(), nums.end());
sort(nums.rbegin(), nums.rend()); // Обратная сортировка
// Поиск
auto it = find(nums.begin(), nums.end(), 25);
if (it != nums.end()) {
    cout << "Found at position: " << it - nums.begin();
}
// Другие полезные алгоритмы
reverse(nums.begin(), nums.end());
int max_val = *max_element(nums.begin(), nums.end());
int count = count_if(nums.begin(), nums.end(),
                    [](int x) { return x > 50; });
```

### Итераторы

Навигация по контейнерам эффективно.

```cpp
vector<string> words = {"hello", "world", "cpp"};
// Типы итераторов
vector<string>::iterator it;
auto it2 = words.begin(); // Auto в C++11
// Итерация по контейнеру
for (it = words.begin(); it != words.end(); ++it) {
    cout << *it << " ";
}
// Цикл на основе диапазона (предпочтительнее)
for (const auto& word : words) {
    cout << word << " ";
}
```

## Операции ввода/вывода

### Файловый ввод: Чтение файлов

Чтение данных из текстовых файлов.

```cpp
#include <fstream>
#include <sstream>
// Чтение всего файла
ifstream file("data.txt");
if (file.is_open()) {
    string line;
    while (getline(file, line)) {
        cout << line << endl;
    }
    file.close();
}
// Чтение по словам
ifstream file2("numbers.txt");
int number;
while (file2 >> number) {
    cout << number << " ";
}
// Чтение с проверкой ошибок
if (!file.good()) {
    cerr << "Error reading file!" << endl;
}
```

### Обработка строковых потоков

Разбор и манипулирование строками как потоками.

```cpp
#include <sstream>
// Разбор значений, разделенных запятыми
string data = "apple,banana,cherry";
stringstream ss(data);
string item;
vector<string> fruits;
while (getline(ss, item, ',')) {
    fruits.push_back(item);
}
// Преобразование строк в числа
string num_str = "123";
int num = stoi(num_str);
double d = stod("3.14159");
string back_to_str = to_string(num);
```

### Файловый вывод: Запись в файлы

Запись данных в текстовые файлы.

```cpp
// Запись в файл
ofstream outfile("output.txt");
if (outfile.is_open()) {
    outfile << "Hello, file!" << endl;
    outfile << "Number: " << 42 << endl;
    outfile.close();
}
// Добавление в существующий файл
ofstream appendfile("log.txt", ios::app);
appendfile << "New log entry" << endl;
// Запись вектора в файл
vector<int> numbers = {1, 2, 3, 4, 5};
ofstream numfile("numbers.txt");
for (int num : numbers) {
    numfile << num << " ";
}
```

### Форматирование потока

Управление форматом и точностью вывода.

```cpp
#include <iomanip>
double pi = 3.14159265;
cout << fixed << setprecision(2) << pi << endl; // 3.14
cout << setw(10) << "Right" << endl;          // Выравнивание по правому краю
cout << left << setw(10) << "Left" << endl;     // Выравнивание по левому краю
cout << hex << 255 << endl;                    // Шестнадцатеричный формат: ff
```

## Обработка ошибок

### Блоки Try-Catch

Обработка исключений, которые могут возникнуть во время выполнения.

```cpp
try {
    int result = 10 / 0; // Это может вызвать исключение
    vector<int> vec(5);
    vec.at(10) = 100;    // Доступ за пределами диапазона

} catch (const exception& e) {
    cout << "Exception caught: " << e.what() << endl;
} catch (...) {
    cout << "Unknown exception caught!" << endl;
}
// Конкретные типы исключений
try {
    string str = "abc";
    int num = stoi(str); // Вызывает invalid_argument
} catch (const invalid_argument& e) {
    cout << "Invalid argument: " << e.what() << endl;
} catch (const out_of_range& e) {
    cout << "Out of range: " << e.what() << endl;
}
```

### Генерация пользовательских исключений

Создание и генерация собственных исключений.

```cpp
// Класс пользовательского исключения
class CustomException : public exception {
    string message;
public:
    CustomException(const string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};
// Функция, которая генерирует исключение
void validateAge(int age) {
    if (age < 0 || age > 150) {
        throw CustomException("Invalid age range!");
    }
}
// Использование
try {
    validateAge(-5);
} catch (const CustomException& e) {
    cout << e.what() << endl;
}
```

### Паттерн RAII

Инициализация ресурсов при приобретении для безопасного управления ресурсами.

```cpp
// RAII с умными указателями
{
    unique_ptr<int[]> arr = make_unique<int[]>(1000);
    // Массив будет автоматически удален при выходе из области видимости
}
// RAII с файловым вводом/выводом
{
    ifstream file("data.txt");
    // Файл будет автоматически закрыт при выходе из области видимости
    if (file.is_open()) {
        // Обработка файла
    }
}
// Пользовательский класс RAII
class FileHandler {
    FILE* file;
public:
    FileHandler(const char* filename) {
        file = fopen(filename, "r");
    }
    ~FileHandler() {
        if (file) fclose(file);
    }
    FILE* get() { return file; }
};
```

### Утверждения и отладка

Отладка и проверка предположений программы.

```cpp
#include <cassert>
#include <iostream>
void processArray(int* arr, int size) {
    assert(arr != nullptr);  // Утверждение отладчика
    assert(size > 0);        // Проверка предположения

    // Обработка массива...
}
// Условная компиляция для отладочного вывода
#ifdef DEBUG
    #define DBG_PRINT(x) cout << "DEBUG: " << x << endl
#else
    #define DBG_PRINT(x)
#endif
// Использование
DBG_PRINT("Starting function");
```

## Компиляция и сборка

### Компиляция GCC/G++

GNU Compiler Collection для C++.

```bash
# Базовая компиляция
g++ -o program main.cpp
# С отладочной информацией
g++ -g -o program main.cpp
# Уровни оптимизации
g++ -O2 -o program main.cpp
# Несколько исходных файлов
g++ -o program main.cpp utils.cpp math.cpp
# Включение дополнительных каталогов
g++ -I/usr/local/include -o program main.cpp
# Линковка библиотек
g++ -o program main.cpp -lm -lpthread
```

### Стандарты современного C++

Компиляция с использованием определенных версий стандарта C++.

```bash
# Стандарт C++11
g++ -std=c++11 -o program main.cpp
# Стандарт C++14
g++ -std=c++14 -o program main.cpp
# Стандарт C++17 (рекомендуется)
g++ -std=c++17 -o program main.cpp
# Стандарт C++20 (последний)
g++ -std=c++20 -o program main.cpp
# Включить все предупреждения
g++ -Wall -Wextra -std=c++17 -o program main.cpp
```

### Основы Makefile

Автоматизация компиляции с помощью утилиты make.

```makefile
# Простой Makefile
CXX = g++
CXXFLAGS = -std=c++17 -Wall -g
TARGET = program
SOURCES = main.cpp utils.cpp
$(TARGET): $(SOURCES)
$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES)
clean:
rm -f $(TARGET)
.PHONY: clean
```

## Рекомендации и советы

### Соглашения об именовании

Последовательное именование делает код более читаемым.

```cpp
// Переменные и функции: snake_case или camelCase
int student_count;
int studentCount;
void calculateAverage();
// Константы: UPPER_CASE
const int MAX_BUFFER_SIZE = 1024;
const double PI = 3.14159;
// Классы: PascalCase
class StudentRecord {
    // Переменные-члены: префикс m_ или суффикс _
    string m_name;
    int age_;

public:
    // Публичный интерфейс
    void setName(const string& name);
    string getName() const;
};
```

### Безопасность памяти

Предотвращение распространенных ошибок, связанных с памятью.

```cpp
// Используйте умные указатели вместо сырых указателей
auto ptr = make_unique<int>(42);
auto shared = make_shared<vector<int>>(10);
// Инициализируйте переменные
int count = 0;        // Хорошо
int count;            // Опасно - неинициализировано
// Циклы на основе диапазона более безопасны
for (const auto& item : container) {
    // Безопасная обработка элемента
}
// Проверка допустимости указателя
if (ptr != nullptr) {
    // Безопасно разыменовывать
}
```

### Советы по производительности

Пишите эффективный код на C++.

```cpp
// Передавайте большие объекты по const-ссылке
void processData(const vector<int>& data) {
    // Избегайте копирования больших объектов
}
// Используйте префиксный инкремент для итераторов
for (auto it = vec.begin(); it != vec.end(); ++it) {
    // ++it часто быстрее, чем it++
}
// Резервируйте емкость вектора, когда размер известен
vector<int> numbers;
numbers.reserve(1000); // Избегайте повторного выделения
// Используйте emplace вместо push для объектов
vector<string> words;
words.emplace_back("Hello"); // Конструирование на месте
words.push_back(string("World")); // Конструирование, затем копирование
```

### Организация кода

Структурируйте код для удобства сопровождения.

```cpp
// Заголовочный файл (utils.h)
#ifndef UTILS_H
#define UTILS_H
class MathUtils {
public:
    static double calculateArea(double radius);
    static int fibonacci(int n);
};
#endif // UTILS_H
// Файл реализации (utils.cpp)
#include "utils.h"
#include <cmath>
double MathUtils::calculateArea(double radius) {
    return M_PI * radius * radius;
}
// Используйте const-функции-члены, когда это возможно
double getRadius() const { return radius; }
```

## Соответствующие ссылки

- <router-link to="/c-programming">Шпаргалка по программированию на C</router-link>
- <router-link to="/java">Шпаргалка по Java</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/golang">Шпаргалка по Golang</router-link>
- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>

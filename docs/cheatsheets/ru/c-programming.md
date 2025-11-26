---
title: 'Шпаргалка по программированию на C'
description: 'Изучите программирование на C с нашей исчерпывающей шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/c-programming-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по языку программирования C
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/c">Изучите программирование на C с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите программирование на C с помощью практических лабораторных работ и сценариев из реального мира. LabEx предлагает комплексные курсы по C, охватывающие основной синтаксис, управление памятью, указатели, структуры данных и продвинутые методы. Освойте мощные возможности C для создания эффективных системных приложений и понимания концепций низкоуровневого программирования.
</base-disclaimer-content>
</base-disclaimer>

## Базовый синтаксис и структура

### Программа "Hello World"

Базовая структура программы на C.

```c
#include <stdio.h>
int main() {
    printf("Hello, World!\n");
    return 0;
}
```

### Заголовочные файлы и препроцессор

Подключение библиотек и использование директив препроцессора.

```c
#include <stdio.h>    // Стандартный ввод/вывод
#include <stdlib.h>   // Стандартная библиотека
#include <string.h>   // Функции для строк
#include <math.h>     // Математические функции
#define PI 3.14159
#define MAX_SIZE 100
```

### Комментарии

Однострочные и многострочные комментарии.

```c
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

```c
int main() {
    // Код программы здесь
    return 0;  // Успех
}
int main(int argc, char *argv[]) {
    // argc: количество аргументов
    // argv: значения аргументов (командная строка)
    return 0;
}
```

### Базовый вывод

Отображение текста и переменных в консоли.

```c
printf("Hello\n");
printf("Value: %d\n", 42);
// Несколько значений в одной строке
printf("Name: %s, Age: %d\n", name, age);
```

### Базовый ввод

Чтение ввода пользователя из консоли.

```c
int age;
char name[50];
scanf("%d", &age);
scanf("%s", name);
// Чтение всей строки с пробелами
fgets(name, sizeof(name), stdin);
```

## Типы данных и переменные

### Примитивные типы

Основные типы данных для хранения различных видов значений.

```c
// Целочисленные типы
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// Типы с плавающей точкой
float price = 19.99f;
double precise = 3.14159265359;
// Символьный и булев (используя int)
char grade = 'A';
int is_valid = 1;  // 1 для true, 0 для false
```

### Массивы и строки

Массивы и работа со строками в C.

```c
// Массивы
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// Строки (массивы символов)
char name[50] = "John Doe";
char greeting[] = "Hello";
char buffer[100];  // Не инициализирован
// Длина и размер строки
int len = strlen(name);
int size = sizeof(buffer);
```

### Константы и модификаторы

Неизменяемые значения и модификаторы хранения.

```c
// Константы
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Константы препроцессора
#define BUFFER_SIZE 512
#define TRUE 1
#define FALSE 0
// Модификаторы хранения
static int count = 0;     // Статическая переменная
extern int global_var;    // Внешняя переменная
register int fast_var;    // Подсказка для регистра
```

## Структуры управления потоком

### Условные операторы

Принятие решений на основе условий.

```c
// Оператор If-else
if (age >= 18) {
    printf("Adult\n");
} else if (age >= 13) {
    printf("Teenager\n");
} else {
    printf("Child\n");
}
// Тернарный оператор
char* status = (age >= 18) ? "Adult" : "Minor";
// Оператор Switch
switch (grade) {
    case 'A':
        printf("Excellent!\n");
        break;
    case 'B':
        printf("Good job!\n");
        break;
    default:
        printf("Keep trying!\n");
}
```

### Циклы For

Итерация с циклами, основанными на счетчике.

```c
// Традиционный цикл for
for (int i = 0; i < 10; i++) {
    printf("%d ", i);
}
// Итерация по массиву
int numbers[] = {1, 2, 3, 4, 5};
int size = sizeof(numbers) / sizeof(numbers[0]);
for (int i = 0; i < size; i++) {
    printf("%d ", numbers[i]);
}
// Вложенные циклы
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        printf("%d,%d ", i, j);
    }
}
```

### Циклы While

Итерация, основанная на условии.

```c
// Цикл While
int count = 0;
while (count < 5) {
    printf("%d\n", count);
    count++;
}
// Цикл Do-while (выполняется как минимум один раз)
int input;
do {
    printf("Enter a number (0 to quit): ");
    scanf("%d", &input);
} while (input != 0);
```

### Управление циклами

Операторы break и continue.

```c
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // Пропустить итерацию
    }
    if (i == 7) {
        break;    // Выход из цикла
    }
    printf("%d ", i);
}
// Вложенные циклы с break
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // Прервать только внутренний цикл
        printf("%d,%d ", i, j);
    }
}
```

## Функции

### Объявление и определение функции

Создание многократно используемых блоков кода.

```c
// Объявление функции (прототип)
int add(int a, int b);
void printMessage(char* msg);
// Определение функции
int add(int a, int b) {
    return a + b;
}
void printMessage(char* msg) {
    printf("%s\n", msg);
}
// Вызов функции
int result = add(5, 3);
printMessage("Hello, functions!");
```

### Передача массивов в функции

Функции, работающие с массивами.

```c
// Массив как параметр (указатель)
void printArray(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}
// Изменение элементов массива
void doubleValues(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;
    }
}
```

### Рекурсивные функции

Функции, вызывающие сами себя.

```c
// Вычисление факториала
int factorial(int n) {
    if (n <= 1) {
        return 1;  // Базовый случай
    }
    return n * factorial(n - 1);
}
// Последовательность Фибоначчи
int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }
    return fibonacci(n-1) + fibonacci(n-2);
}
```

### Указатели на функции

Указатели на функции для динамического поведения.

```c
// Объявление указателя на функцию
int (*operation)(int, int);
// Присвоение функции указателю
operation = add;
int result = operation(5, 3);
// Массив указателей на функции
int (*operations[])(int, int) = {add, subtract, multiply};
result = operations[0](10, 5);
```

## Указатели и управление памятью

### Основы указателей

Объявление и использование указателей для доступа к адресам памяти.

```c
int x = 10;
int *ptr = &x;  // Указатель на x
printf("Value of x: %d\n", x);
printf("Address of x: %p\n", &x);
printf("Value of ptr: %p\n", ptr);
printf("Value pointed by ptr: %d\n", *ptr);
// Изменение значения через указатель
*ptr = 20;
printf("New value of x: %d\n", x);
// Нулевой указатель
int *null_ptr = NULL;
```

### Массивы и указатели

Связь между массивами и указателями.

```c
int arr[5] = {1, 2, 3, 4, 5};
int *p = arr;  // Указывает на первый элемент
// Нотация массива против арифметики указателей
printf("%d\n", arr[2]);   // Нотация массива
printf("%d\n", *(p + 2)); // Арифметика указателей
printf("%d\n", p[2]);     // Указатель как массив
// Итерация с использованием указателя
for (int i = 0; i < 5; i++) {
    printf("%d ", *(p + i));
}
```

### Динамическое выделение памяти

Выделение и освобождение памяти во время выполнения.

```c
#include <stdlib.h>
// Выделение памяти для одного целого числа
int *ptr = (int*)malloc(sizeof(int));
if (ptr != NULL) {
    *ptr = 42;
    printf("Value: %d\n", *ptr);
    free(ptr);  // Всегда освобождайте выделенную память
}
// Динамическое выделение массива
int *arr = (int*)malloc(10 * sizeof(int));
if (arr != NULL) {
    for (int i = 0; i < 10; i++) {
        arr[i] = i * i;
    }
    free(arr);
}
```

### Указатели на строки

Работа со строками и указателями на символы.

```c
// Литералы строк и указатели
char *str1 = "Hello";           // Литерал строки
char str2[] = "World";          // Массив символов
char *str3 = (char*)malloc(20); // Динамическая строка
// Функции для строк
strcpy(str3, "Dynamic");
printf("Length: %lu\n", strlen(str1));
printf("Compare: %d\n", strcmp(str1, str2));
strcat(str2, "!");
// Всегда освобождайте динамические строки
free(str3);
```

## Структуры и типы, определяемые пользователем

### Определение структуры

Определение пользовательских типов данных с несколькими полями.

```c
// Определение структуры
struct Rectangle {
    double width;
    double height;
};
// Структура с typedef
typedef struct {
    char name[50];
    int age;
    double gpa;
} Student;
// Создание и инициализация структур
struct Rectangle rect1 = {5.0, 3.0};
Student student1 = {"Alice", 20, 3.75};
// Доступ к членам структуры
printf("Area: %.2f\n", rect1.width * rect1.height);
printf("Student: %s, Age: %d\n", student1.name, student1.age);
```

### Вложенные структуры

Структуры, содержащие другие структуры.

```c
typedef struct {
    int day, month, year;
} Date;
typedef struct {
    char name[50];
    Date birthdate;
    double salary;
} Employee;
Employee emp = {
    "John Smith",
    {15, 6, 1985},
    50000.0
};
printf("Born: %d/%d/%d\n",
       emp.birthdate.day,
       emp.birthdate.month,
       emp.birthdate.year);
```

### Указатели на структуры

Использование указателей для доступа и изменения структур.

```c
Student *student_ptr = &student1;
// Доступ с использованием указателя (два способа)
printf("Name: %s\n", (*student_ptr).name);
printf("Age: %d\n", student_ptr->age);
// Изменение через указатель
student_ptr->age = 21;
strcpy(student_ptr->name, "Alice Johnson");
// Динамическое выделение структуры
Student *new_student = (Student*)malloc(sizeof(Student));
if (new_student != NULL) {
    strcpy(new_student->name, "Bob");
    new_student->age = 19;
    new_student->gpa = 3.2;
    free(new_student);
}
```

### Объединения и перечисления

Альтернативные методы организации данных.

```c
// Union - общее пространство памяти
union Data {
    int integer;
    float floating;
    char character;
};
union Data data;
data.integer = 42;
printf("Integer: %d\n", data.integer);
// Перечисление
enum Weekday {
    MONDAY, TUESDAY, WEDNESDAY,
    THURSDAY, FRIDAY, SATURDAY, SUNDAY
};
enum Weekday today = FRIDAY;
printf("Today is day %d\n", today);
```

## Операции ввода/вывода файлов

### Чтение файлов

Чтение данных из текстовых файлов.

```c
#include <stdio.h>
// Чтение файла посимвольно
FILE *file = fopen("data.txt", "r");
if (file != NULL) {
    int ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}
// Чтение построчно
FILE *file2 = fopen("lines.txt", "r");
char buffer[256];
while (fgets(buffer, sizeof(buffer), file2) != NULL) {
    printf("Line: %s", buffer);
}
fclose(file2);
// Чтение форматированных данных
FILE *numbers = fopen("numbers.txt", "r");
int num;
while (fscanf(numbers, "%d", &num) == 1) {
    printf("Number: %d\n", num);
}
fclose(numbers);
```

### Проверка ошибок

Безопасная обработка файловых операций.

```c
FILE *file = fopen("data.txt", "r");
if (file == NULL) {
    printf("Error opening file!\n");
    perror("fopen");  // Вывод системного сообщения об ошибке
    return 1;
}
// Проверка ошибок чтения
if (ferror(file)) {
    printf("Error reading file!\n");
}
// Проверка конца файла
if (feof(file)) {
    printf("Reached end of file\n");
}
fclose(file);
```

### Запись в файлы

Запись данных в текстовые файлы.

```c
// Запись в файл
FILE *outfile = fopen("output.txt", "w");
if (outfile != NULL) {
    fprintf(outfile, "Hello, file!\n");
    fprintf(outfile, "Number: %d\n", 42);
    fclose(outfile);
}
// Добавление в существующий файл
FILE *appendfile = fopen("log.txt", "a");
if (appendfile != NULL) {
    fprintf(appendfile, "New log entry\n");
    fclose(appendfile);
}
// Запись массива в файл
int numbers[] = {1, 2, 3, 4, 5};
FILE *numfile = fopen("numbers.txt", "w");
for (int i = 0; i < 5; i++) {
    fprintf(numfile, "%d ", numbers[i]);
}
fclose(numfile);
```

### Двоичные файловые операции

Эффективное чтение и запись двоичных данных.

```c
// Запись двоичных данных
Student students[3] = {
    {"Alice", 20, 3.75},
    {"Bob", 21, 3.2},
    {"Charlie", 19, 3.9}
};
FILE *binfile = fopen("students.bin", "wb");
fwrite(students, sizeof(Student), 3, binfile);
fclose(binfile);
// Чтение двоичных данных
Student loaded_students[3];
FILE *readbin = fopen("students.bin", "rb");
fread(loaded_students, sizeof(Student), 3, readbin);
fclose(readbin);
```

## Манипуляции со строками

### Функции для строк

Общие операции со строками из библиотеки string.h.

```c
#include <string.h>
char str1[50] = "Hello";
char str2[] = "World";
char dest[100];
// Длина строки
int len = strlen(str1);
printf("Length: %d\n", len);
// Копирование строки
strcpy(dest, str1);
strncpy(dest, str1, 10); // Копировать первые 10 символов
// Конкатенация строк
strcat(dest, " ");
strcat(dest, str2);
strncat(dest, "!", 1);   // Добавить 1 символ
// Сравнение строк
int result = strcmp(str1, str2);
if (result == 0) {
    printf("Strings are equal\n");
}
```

### Поиск по строкам

Поиск подстрок и символов в строках.

```c
char text[] = "The quick brown fox";
char *ptr;
// Поиск первого вхождения символа
ptr = strchr(text, 'q');
if (ptr != NULL) {
    printf("Found 'q' at position: %ld\n", ptr - text);
}
// Поиск последнего вхождения
ptr = strrchr(text, 'o');
printf("Last 'o' at position: %ld\n", ptr - text);
// Поиск подстроки
ptr = strstr(text, "brown");
if (ptr != NULL) {
    printf("Found 'brown' at: %s\n", ptr);
}
```

### Преобразование строк

Преобразование строк в числа и наоборот.

```c
#include <stdlib.h>
// Преобразование строки в число
char num_str[] = "12345";
char float_str[] = "3.14159";
int num = atoi(num_str);
long long_num = atol(num_str);
double float_num = atof(float_str);
printf("Integer: %d\n", num);
printf("Long: %ld\n", long_num);
printf("Double: %.2f\n", float_num);
// Число в строку (используя sprintf)
char buffer[50];
sprintf(buffer, "%d", 42);
sprintf(buffer, "%.2f", 3.14159);
printf("String: %s\n", buffer);
```

### Пользовательская обработка строк

Ручные методы манипуляции строками.

```c
// Подсчет символов в строке
int countChar(char *str, char target) {
    int count = 0;
    while (*str) {
        if (*str == target) count++;
        str++;
    }
    return count;
}
// Реверс строки на месте
void reverseString(char *str) {
    int len = strlen(str);
    for (int i = 0; i < len/2; i++) {
        char temp = str[i];
        str[i] = str[len-1-i];
        str[len-1-i] = temp;
    }
}
```

## Компиляция и процесс сборки

### Компиляция GCC

GNU Compiler Collection для C.

```bash
# Базовая компиляция
gcc -o program main.c
# С информацией для отладки
gcc -g -o program main.c
# Уровни оптимизации
gcc -O2 -o program main.c
# Несколько исходных файлов
gcc -o program main.c utils.c math.c
# Включение дополнительных каталогов
gcc -I/usr/local/include -o program main.c
# Линковка библиотек
gcc -o program main.c -lm -lpthread
```

### Стандарты C

Компиляция с использованием конкретных версий стандарта C.

```bash
# Стандарт C90/C89 (ANSI C)
gcc -std=c89 -o program main.c
# Стандарт C99
gcc -std=c99 -o program main.c
# Стандарт C11 (рекомендуется)
gcc -std=c11 -o program main.c
# Стандарт C18 (последний)
gcc -std=c18 -o program main.c
# Включить все предупреждения
gcc -Wall -Wextra -std=c11 -o program main.c
```

### Основы Makefile

Автоматизация компиляции с помощью утилиты make.

```makefile
# Простой Makefile
CC = gcc
CFLAGS = -std=c11 -Wall -g
TARGET = program
SOURCES = main.c utils.c
$(TARGET): $(SOURCES)
$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)
clean:
rm -f $(TARGET)
.PHONY: clean
```

## Рекомендации и советы

### Соглашения об именовании

Последовательное именование делает код более читаемым.

```c
// Переменные и функции: snake_case
int student_count;
double calculate_average(int scores[], int size);
// Константы: UPPER_CASE
#define MAX_BUFFER_SIZE 1024
#define PI 3.14159
// Структуры: PascalCase или snake_case
typedef struct {
    char name[50];
    int age;
} Student;
// Глобальные переменные: префикс g_
int g_total_count = 0;
// Параметры функции: понятные имена
void process_data(int *input_array, int array_size);
```

### Безопасность памяти

Предотвращение распространенных ошибок, связанных с памятью.

```c
// Всегда инициализируйте переменные
int count = 0;        // Хорошо
int count;            // Опасно - неинициализированная
// Проверка возвращаемого значения malloc
int *ptr = malloc(sizeof(int) * 10);
if (ptr == NULL) {
    printf("Memory allocation failed!\n");
    return -1;
}
// Всегда освобождайте выделенную память
free(ptr);
ptr = NULL;  // Предотвращение случайного повторного использования
// Проверка границ массива
for (int i = 0; i < array_size; i++) {
    // Безопасный доступ к массиву
    array[i] = i;
}
```

### Советы по производительности

Написание эффективного кода на C.

```c
// Использование подходящих типов данных
char small_num = 10;   // Для небольших значений
int normal_num = 1000; // Для типичных целых чисел
// Минимизация вызовов функций в циклах
int len = strlen(str); // Вычислить один раз
for (int i = 0; i < len; i++) {
    // Обработка строки
}
// Использование register для часто используемых переменных
register int counter;
// Предпочитать массивы, а не динамическое выделение, когда размер известен
int fixed_array[100];  // Выделение в стеке
// Против
int *dynamic_array = malloc(100 * sizeof(int));
```

### Организация кода

Структурирование кода для удобства сопровождения.

```c
// Заголовочный файл (utils.h)
#ifndef UTILS_H
#define UTILS_H
// Прототипы функций
double calculate_area(double radius);
int fibonacci(int n);
// Определения структур
typedef struct {
    int x, y;
} Point;
#endif // UTILS_H
// Файл реализации (utils.c)
#include "utils.h"
#include <math.h>
double calculate_area(double radius) {
    return M_PI * radius * radius;
}
```

## Соответствующие ссылки

- <router-link to="/cpp">Шпаргалка по C++</router-link>
- <router-link to="/java">Шпаргалка по Java</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/golang">Шпаргалка по Golang</router-link>
- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>

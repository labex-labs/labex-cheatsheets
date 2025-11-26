---
title: 'Шпаргалка по Java'
description: 'Изучите Java с нашей полной шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/java-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Java
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/java">Изучайте Java с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучайте программирование на Java с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по Java, охватывающие основной синтаксис, объектно-ориентированное программирование, коллекции, обработку исключений и лучшие практики. Освойте основы разработки на Java и создавайте надежные приложения.
</base-disclaimer-content>
</base-disclaimer>

## Структура Программы и Базовый Синтаксис

### Hello World: Базовая Программа

Простейшая программа на Java, которая выводит "Hello, World!" на экран.

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### Объявление Класса: `public class`

Класс — это шаблон/проект, описывающий поведение/состояние, которое поддерживают объекты.

```java
public class MyClass {
    // Содержимое класса здесь
    int myVariable;

    public void myMethod() {
        System.out.println("Hello from method!");
    }
}
```

### Метод Main: Точка Входа Программы

Метод `main` — это место, где начинается выполнение программы на Java.

```java
public static void main(String[] args) {
    // Код программы здесь
    System.out.println("Program starts here");
}
```

### Комментарии: Документирование Кода

Используйте однострочные (`//`) и многострочные (`/* */`) комментарии, чтобы сделать код более понятным и удобным для сопровождения.

```java
// Однострочный комментарий
System.out.println("Hello");

/* Многострочный комментарий
   Может занимать несколько строк
   Используется для подробных объяснений */
```

### Инструкции и Точки с Запятой

Каждая инструкция в Java должна заканчиваться точкой с запятой.

```java
int number = 10;
String name = "Java";
System.out.println(name);
```

### Блоки Кода: Фигурные Скобки

Блоки кода заключаются в фигурные скобки `{}`, обозначая начало и конец секций кода.

```java
public class Example {
    public void method() {
        if (true) {
            System.out.println("Inside if block");
        }
    }
}
```

## Типы Данных и Переменные

### Примитивные Типы Данных

Базовые типы данных, встроенные в язык Java.

```java
// Целочисленные типы
byte smallNum = 127;        // -128 до 127
short shortNum = 32000;     // -32,768 до 32,767
int number = 100;           // -2^31 до 2^31-1
long bigNum = 10000L;       // -2^63 до 2^63-1

// Типы с плавающей точкой
float decimal = 3.14f;      // Одинарная точность
double precision = 3.14159; // Двойная точность

// Другие типы
char letter = 'A';          // Один символ
boolean flag = true;        // true или false
```

### Объявление и Инициализация Переменных

Создание и присвоение значений переменным.

```java
// Только объявление
int age;
String name;

// Объявление с инициализацией
int age = 25;
String name = "John";

// Множественное объявление
int x = 10, y = 20, z = 30;

// Финальные переменные (константы)
final double PI = 3.14159;
```

### Операции со Строками

Строки представляют собой последовательности символов и являются неизменяемыми (immutable), то есть после создания их значение изменить нельзя.

```java
String greeting = "Hello";
String name = "World";

// Конкатенация строк
String message = greeting + " " + name;
System.out.println(message); // "Hello World"

// Методы строк
int length = message.length();
boolean isEmpty = message.isEmpty();
String uppercase = message.toUpperCase();
```

## Операторы Управления Потоком

### Условные Операторы: `if`, `else if`, `else`

Выполняют различные блоки кода в зависимости от условий.

```java
int score = 85;
if (score >= 90) {
    System.out.println("Grade A");
} else if (score >= 80) {
    System.out.println("Grade B");
} else if (score >= 70) {
    System.out.println("Grade C");
} else {
    System.out.println("Grade F");
}
```

### Оператор Switch

Многопутевая ветвь, основанная на значениях переменных.

```java
int day = 3;
switch (day) {
    case 1:
        System.out.println("Monday");
        break;
    case 2:
        System.out.println("Tuesday");
        break;
    case 3:
        System.out.println("Wednesday");
        break;
    default:
        System.out.println("Other day");
}
```

### Цикл For: Повторение с Подсчетом

Повторяет код определенное количество раз.

```java
// Стандартный цикл for
for (int i = 0; i < 5; i++) {
    System.out.println("Count: " + i);
}

// Улучшенный цикл for (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println("Number: " + num);
}
```

### Циклы While и Do-While

Повторяют код, пока условие истинно.

```java
// Цикл While
int i = 0;
while (i < 3) {
    System.out.println("While: " + i);
    i++;
}

// Цикл Do-while (выполняется как минимум один раз)
int j = 0;
do {
    System.out.println("Do-while: " + j);
    j++;
} while (j < 3);
```

## Объектно-Ориентированное Программирование

### Классы и Объекты

Объекты имеют состояние и поведение. Объект — это экземпляр класса.

```java
public class Car {
    // Переменные экземпляра (состояние)
    String color;
    String model;
    int year;

    // Конструктор
    public Car(String color, String model, int year) {
        this.color = color;
        this.model = model;
        this.year = year;
    }

    // Метод (поведение)
    public void start() {
        System.out.println("Car is starting...");
    }
}

// Создание объектов
Car myCar = new Car("Red", "Toyota", 2022);
myCar.start();
```

### Конструкторы

Специальные методы, используемые для инициализации объектов.

```java
public class Person {
    String name;
    int age;

    // Конструктор по умолчанию
    public Person() {
        name = "Unknown";
        age = 0;
    }

    // Конструктор с параметрами
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
```

### Наследование: `extends`

Наследование позволяет повторно использовать код и создает иерархические отношения между классами.

```java
public class Animal {
    protected String name;

    public void eat() {
        System.out.println(name + " is eating");
    }
}

public class Dog extends Animal {
    public Dog(String name) {
        this.name = name;
    }

    public void bark() {
        System.out.println(name + " is barking");
    }
}

Dog myDog = new Dog("Buddy");
myDog.eat();  // Наследуемый метод
myDog.bark(); // Собственный метод
```

### Модификаторы Доступа

Модификаторы контролируют доступ к классам, методам и переменным.

```java
public class Example {
    public int publicVar;      // Доступно везде
    private int privateVar;    // Только внутри этого класса
    protected int protectedVar; // Внутри пакета + подклассы
    int defaultVar;            // Только внутри пакета

    private void privateMethod() {
        // Доступно только внутри этого класса
    }
}
```

## Методы и Функции

### Объявление Метода

Метод — это, по сути, поведение, в котором пишется логика, манипулируются данные и выполняются действия.

```java
public class Calculator {
    // Метод с параметрами и возвращаемым значением
    public int add(int a, int b) {
        return a + b;
    }

    // Метод без возвращаемого значения
    public void printSum(int a, int b) {
        int result = add(a, b);
        System.out.println("Sum: " + result);
    }

    // Статический метод (принадлежит классу)
    public static int multiply(int a, int b) {
        return a * b;
    }
}
```

### Перегрузка Методов (Method Overloading)

Несколько методов с одинаковым именем, но разными параметрами.

```java
public class MathUtils {
    public int add(int a, int b) {
        return a + b;
    }

    public double add(double a, double b) {
        return a + b;
    }

    public int add(int a, int b, int c) {
        return a + b + c;
    }
}
```

### Параметры Методов и Возвращаемые Типы

Передача данных в методы и возврат результатов.

```java
public class StringHelper {
    // Метод с параметром String и возвращаемым значением
    public String formatName(String firstName, String lastName) {
        return firstName + " " + lastName;
    }

    // Метод с параметром-массивом
    public int findMax(int[] numbers) {
        int max = numbers[0];
        for (int num : numbers) {
            if (num > max) {
                max = num;
            }
        }
        return max;
    }
}
```

### Рекурсивные Методы

Методы, которые вызывают сами себя для решения задач.

```java
public class RecursiveExamples {
    // Вычисление факториала
    public int factorial(int n) {
        if (n <= 1) {
            return 1;
        }
        return n * factorial(n - 1);
    }

    // Последовательность Фибоначчи
    public int fibonacci(int n) {
        if (n <= 1) {
            return n;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

## Массивы и Коллекции

### Объявление и Инициализация Массива

Создание и инициализация массивов разных типов.

```java
// Объявление и инициализация массива
int[] numbers = {1, 2, 3, 4, 5};
String[] names = {"Alice", "Bob", "Charlie"};

// Массив с заданным размером
int[] scores = new int[10];
scores[0] = 95;
scores[1] = 87;

// Получение длины массива
int length = numbers.length;
System.out.println("Length: " + length);

// Перебор массива
for (int i = 0; i < numbers.length; i++) {
    System.out.println("Element " + i + ": " + numbers[i]);
}
```

### Многомерные Массивы

Массивы массивов для структур данных, похожих на матрицы.

```java
// Объявление 2D массива
int[][] matrix = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

// Доступ к элементам
int element = matrix[1][2]; // Получает 6

// Перебор 2D массива
for (int i = 0; i < matrix.length; i++) {
    for (int j = 0; j < matrix[i].length; j++) {
        System.out.print(matrix[i][j] + " ");
    }
    System.out.println();
}
```

### ArrayList: Динамические Массивы

Массивы с изменяемым размером, которые могут динамически расти и сжиматься.

```java
import java.util.ArrayList;

// Создание ArrayList
ArrayList<String> list = new ArrayList<>();

// Добавление элементов
list.add("Apple");
list.add("Banana");
list.add("Orange");

// Получение элемента
String fruit = list.get(0); // Получает "Apple"

// Удаление элемента
list.remove(1); // Удаляет "Banana"

// Размер и итерация
System.out.println("Size: " + list.size());
for (String item : list) {
    System.out.println(item);
}
```

### HashMap: Пары Ключ-Значение

Хранение данных в виде пар ключ-значение для быстрого поиска.

```java
import java.util.HashMap;

// Создание HashMap
HashMap<String, Integer> ages = new HashMap<>();

// Добавление пар ключ-значение
ages.put("Alice", 25);
ages.put("Bob", 30);
ages.put("Charlie", 35);

// Получение значения по ключу
int aliceAge = ages.get("Alice");

// Проверка наличия ключа
if (ages.containsKey("Bob")) {
    System.out.println("Bob's age: " + ages.get("Bob"));
}
```

## Обработка Исключений

### Блоки Try-Catch

Обработка исключений для предотвращения сбоев программы.

```java
public class ExceptionExample {
    public static void main(String[] args) {
        try {
            int result = 10 / 0; // Это вызовет ArithmeticException
            System.out.println("Result: " + result);
        } catch (ArithmeticException e) {
            System.out.println("Cannot divide by zero!");
            System.out.println("Error: " + e.getMessage());
        } finally {
            System.out.println("This always executes");
        }
    }
}
```

### Несколько Блоков Catch

Отдельная обработка различных типов исключений.

```java
public void processArray(String[] arr, int index) {
    try {
        int number = Integer.parseInt(arr[index]);
        int result = 100 / number;
        System.out.println("Result: " + result);
    } catch (ArrayIndexOutOfBoundsException e) {
        System.out.println("Invalid array index");
    } catch (NumberFormatException e) {
        System.out.println("Invalid number format");
    } catch (ArithmeticException e) {
        System.out.println("Cannot divide by zero");
    }
}
```

### Выброс Пользовательских Исключений

Создание и выбрасывание собственных исключений.

```java
public class AgeValidator {
    public void validateAge(int age) throws IllegalArgumentException {
        if (age < 0) {
            throw new IllegalArgumentException("Age cannot be negative");
        }
        if (age > 150) {
            throw new IllegalArgumentException("Age seems unrealistic");
        }
        System.out.println("Valid age: " + age);
    }

    public static void main(String[] args) {
        AgeValidator validator = new AgeValidator();
        try {
            validator.validateAge(-5);
        } catch (IllegalArgumentException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
```

### Распространенные Типы Исключений

Часто встречающиеся исключения в программах на Java.

```java
// NullPointerException
String str = null;
// str.length(); // Вызывает NullPointerException

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
// int val = arr[5]; // Вызывает ArrayIndexOutOfBoundsException

// NumberFormatException
// int num = Integer.parseInt("abc"); // Вызывает NumberFormatException

// FileNotFoundException (при работе с файлами)
// IOException (общие операции ввода/вывода)
```

## Операции Ввода/Вывода

### Ввод с Консоли: Класс Scanner

Чтение ввода с клавиатуры с использованием `Scanner`.

```java
import java.util.Scanner;

public class InputExample {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter your name: ");
        String name = scanner.nextLine();

        System.out.print("Enter your age: ");
        int age = scanner.nextInt();

        System.out.print("Enter your height: ");
        double height = scanner.nextDouble();

        System.out.println("Name: " + name);
        System.out.println("Age: " + age);
        System.out.println("Height: " + height);

        scanner.close();
    }
}
```

### Вывод на Консоль: System.out

Отображение вывода на консоли в различных форматах.

```java
public class OutputExample {
    public static void main(String[] args) {
        // Базовый вывод
        System.out.println("Hello, World!");
        System.out.print("No newline");
        System.out.print(" continues here\n");

        // Форматированный вывод
        String name = "Java";
        int version = 17;
        System.out.printf("Welcome to %s %d!%n", name, version);

        // Вывод переменных
        int x = 10, y = 20;
        System.out.println("x = " + x + ", y = " + y);
        System.out.println("Sum = " + (x + y));
    }
}
```

### Чтение Файлов: BufferedReader

Эффективное чтение текстовых файлов построчно.

```java
import java.io.*;

public class FileReadExample {
    public static void readFile(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            int lineNumber = 1;

            while ((line = reader.readLine()) != null) {
                System.out.println(lineNumber + ": " + line);
                lineNumber++;
            }
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
        }
    }
}
```

### Запись Файлов: PrintWriter

Запись текстовых данных в файлы с надлежащей обработкой исключений.

```java
import java.io.*;

public class FileWriteExample {
    public static void writeFile(String filename, String[] data) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("# Data File");
            writer.println("Generated on: " + new java.util.Date());
            writer.println();

            for (int i = 0; i < data.length; i++) {
                writer.println("Line " + (i + 1) + ": " + data[i]);
            }

            System.out.println("File written successfully!");
        } catch (IOException e) {
            System.out.println("Error writing file: " + e.getMessage());
        }
    }
}
```

## Среда Разработки Java

### Установка JDK

JDK (Java Development Kit) = JRE + Инструменты Разработки. Необходим для разработки Java-приложений.

```bash
# Скачать JDK с Oracle или OpenJDK
# Установить JDK в вашей системе
# Установить переменную окружения JAVA_HOME
export JAVA_HOME=/path/to/jdk
export PATH=$JAVA_HOME/bin:$PATH

# Проверить установку
java -version
javac -version
```

### Компиляция и Запуск Программ на Java

Используйте `javac` для компиляции исходного кода Java и `java` для запуска скомпилированной программы.

```bash
# Скомпилировать исходный файл Java
javac MyProgram.java

# Запустить скомпилированную программу на Java
java MyProgram

# Компиляция с classpath
javac -cp .:mylib.jar MyProgram.java

# Запуск с classpath
java -cp .:mylib.jar MyProgram
```

### Настройка IDE и Разработка

Популярные интегрированные среды разработки (IDE) для Java.

```bash
# Популярные IDE для Java:
# - IntelliJ IDEA (JetBrains)
# - Eclipse IDE
# - Visual Studio Code с расширениями Java
# - NetBeans

# Компиляция через командную строку
javac -d bin src/*.java
java -cp bin MainClass

# Создание JAR-файла
jar cf myapp.jar -C bin .
```

## Лучшие Практики и Общие Шаблоны

### Соглашения об Именовании

Следуйте стандартам именования Java для лучшей читаемости кода.

```java
// Классы: PascalCase
public class StudentManager { }
public class BankAccount { }

// Методы и переменные: camelCase
int studentAge;
String firstName;
public void calculateGrade() { }
public boolean isValidEmail() { }

// Константы: UPPER_CASE
public static final int MAX_SIZE = 100;
public static final String DEFAULT_NAME = "Unknown";

// Пакеты: lowercase
package com.company.project;
package utils.database;
package com.example.myapp;
```

### Организация Кода

Структурируйте ваши Java-программы для удобства сопровождения.

```java
import java.util.ArrayList;
import java.util.Scanner;

/**
 * Этот класс демонстрирует хорошую организацию кода на Java
 * @author Your Name
 * @version 1.0
 */
public class WellOrganizedClass {
    // Константы в первую очередь
    private static final int MAX_ATTEMPTS = 3;

    // Переменные экземпляра
    private String name;
    private int value;

    // Конструктор
    public WellOrganizedClass(String name) {
        this.name = name;
        this.value = 0;
    }

    // Публичные методы
    public void doSomething() {
        // Реализация
    }

    // Приватные вспомогательные методы
    private boolean isValid() {
        return value > 0;
    }
}
```

### Предотвращение Ошибок

Общие практики для избежания ошибок и улучшения качества кода.

```java
public class BestPractices {
    public void safeDivision(int a, int b) {
        // Проверка деления на ноль
        if (b == 0) {
            throw new IllegalArgumentException("Cannot divide by zero");
        }
        int result = a / b;
        System.out.println("Result: " + result);
    }

    public void safeStringOperations(String input) {
        // Проверка на null перед использованием строк
        if (input != null && !input.isEmpty()) {
            System.out.println("Length: " + input.length());
            System.out.println("Uppercase: " + input.toUpperCase());
        } else {
            System.out.println("Invalid input string");
        }
    }

    public void safeArrayAccess(int[] array, int index) {
        // Проверка границ
        if (array != null && index >= 0 && index < array.length) {
            System.out.println("Value: " + array[index]);
        } else {
            System.out.println("Invalid array access");
        }
    }
}
```

### Управление Ресурсами

Правильная обработка ресурсов для предотвращения утечек памяти.

```java
import java.io.*;

public class ResourceManagement {
    // Try-with-resources (автоматическая очистка)
    public void readFileProper(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine();
            System.out.println(line);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        // Reader автоматически закрывается
    }

    // Ручная очистка ресурсов (не рекомендуется)
    public void readFileManual(String filename) {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(filename));
            String line = reader.readLine();
            System.out.println(line);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    System.out.println("Error closing reader");
                }
            }
        }
    }
}
```

## Соответствующие Ссылки

- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/cpp">Шпаргалка по C++</router-link>
- <router-link to="/golang">Шпаргалка по Go</router-link>
- <router-link to="/web-development">Шпаргалка по Веб-разработке</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>
- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>

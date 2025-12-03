---
title: 'Шпаргалка по Java | LabEx'
description: 'Изучайте программирование на Java с помощью этой исчерпывающей шпаргалки. Быстрый справочник по синтаксису Java, ООП, коллекциям, потокам, фреймворку Spring и основам корпоративной разработки.'
pdfUrl: '/cheatsheets/pdf/java-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Java
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/java">Изучите Java с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите программирование на Java с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по Java, охватывающие основной синтаксис, объектно-ориентированное программирование, коллекции, обработку исключений и лучшие практики. Освойте основы разработки на Java и создавайте надежные приложения.
</base-disclaimer-content>
</base-disclaimer>

## Структура программы и базовый синтаксис

### Hello World: Базовая программа

Простейшая программа на Java, которая выводит "Hello, World!" на экран.

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### Объявление класса: `public class`

Класс — это шаблон/проект, описывающий поведение/состояние, которое поддерживают объекты.

```java
public class MyClass {
    // Здесь находится содержимое класса
    int myVariable;

    public void myMethod() {
        System.out.println("Hello from method!");
    }
}
```

### Метод Main: Точка входа программы

Метод `main` — это место, где начинается выполнение программы на Java.

```java
public static void main(String[] args) {
    // Код программы здесь
    System.out.println("Program starts here");
}
```

<BaseQuiz id="java-main-1" correct="C">
  <template #question>
    Какова правильная сигнатура метода main в Java?
  </template>
  
  <BaseQuizOption value="A">public void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="B">static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="C" correct>public static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="D">public static int main(String[] args)</BaseQuizOption>
  
  <BaseQuizAnswer>
    Метод main должен быть <code>public static void main(String[] args)</code>. <code>public</code> позволяет JVM получить к нему доступ, <code>static</code> означает, что он принадлежит классу, <code>void</code> означает, что он ничего не возвращает, а <code>String[] args</code> принимает аргументы командной строки.
  </BaseQuizAnswer>
</BaseQuiz>

### Комментарии: Документация кода

Используйте однострочные (`//`) и многострочные (`/* */`) комментарии, чтобы сделать код более понятным и удобным для сопровождения.

```java
// Однострочный комментарий
System.out.println("Hello");

/* Многострочный комментарий
   Может занимать несколько строк
   Используется для подробных объяснений */
```

### Инструкции и точки с запятой

Каждая инструкция в Java должна заканчиваться точкой с запятой.

```java
int number = 10;
String name = "Java";
System.out.println(name);
```

### Блоки кода: Фигурные скобки

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

## Типы данных и переменные

### Примитивные типы данных

Основные типы данных, встроенные в язык Java.

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

### Объявление и инициализация переменных

Создание переменных и присвоение им значений.

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

### Операции со строками

Строки представляют собой последовательности символов и являются неизменяемыми (immutable), что означает, что после создания их значение изменить нельзя.

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

<BaseQuiz id="java-string-1" correct="A">
  <template #question>
    Что означает, что строки в Java являются неизменяемыми (immutable)?
  </template>
  
  <BaseQuizOption value="A" correct>После создания значение строки изменить нельзя</BaseQuizOption>
  <BaseQuizOption value="B">Строки не могут быть созданы</BaseQuizOption>
  <BaseQuizOption value="C">Строки могут хранить только числа</BaseQuizOption>
  <BaseQuizOption value="D">Строки удаляются автоматически</BaseQuizOption>
  
  <BaseQuizAnswer>
    Неизменяемость означает, что после создания объекта String его значение не может быть изменено. Операции вроде <code>toUpperCase()</code> возвращают новый объект String, а не изменяют исходный.
  </BaseQuizAnswer>
</BaseQuiz>

## Операторы управления потоком

### Условные операторы: `if`, `else if`, `else`

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

Многопутевое ветвление на основе значений переменных.

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

### Цикл For: Повторение по счетчику

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

<BaseQuiz id="java-for-loop-1" correct="C">
  <template #question>
    Для чего используется улучшенный цикл for (for-each)?
  </template>
  
  <BaseQuizOption value="A">Для итерации с переменной-счетчиком</BaseQuizOption>
  <BaseQuizOption value="B">Для бесконечных циклов</BaseQuizOption>
  <BaseQuizOption value="C" correct>Для итерации по массивам и коллекциям без индекса</BaseQuizOption>
  <BaseQuizOption value="D">Только для вложенных циклов</BaseQuizOption>
  
  <BaseQuizAnswer>
    Улучшенный цикл for (for-each) упрощает итерацию по массивам и коллекциям, автоматически управляя индексом, что делает код более читаемым и менее подверженным ошибкам.
  </BaseQuizAnswer>
</BaseQuiz>

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

<BaseQuiz id="java-while-1" correct="B">
  <template #question>
    Каково ключевое различие между циклами <code>while</code> и <code>do-while</code>?
  </template>
  
  <BaseQuizOption value="A">Различий нет</BaseQuizOption>
  <BaseQuizOption value="B" correct>do-while выполняется как минимум один раз, в то время как while может не выполниться ни разу</BaseQuizOption>
  <BaseQuizOption value="C">while работает быстрее</BaseQuizOption>
  <BaseQuizOption value="D">do-while работает только с массивами</BaseQuizOption>
  
  <BaseQuizAnswer>
    Цикл <code>do-while</code> проверяет условие после выполнения тела цикла, поэтому он всегда выполняется как минимум один раз. Цикл <code>while</code> проверяет условие сначала, поэтому он может не выполниться, если условие изначально ложно.
  </BaseQuizAnswer>
</BaseQuiz>

## Объектно-ориентированное программирование

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
myDog.eat();  // Унаследованный метод
myDog.bark(); // Собственный метод
```

### Модификаторы доступа

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

## Методы и функции

### Объявление метода

Метод — это, по сути, поведение, в котором пишется логика, обрабатываются данные и выполняются действия.

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

### Перегрузка методов (Method Overloading)

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

### Параметры метода и возвращаемые типы

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

### Рекурсивные методы

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

## Массивы и коллекции

### Объявление и инициализация массива

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

### Многомерные массивы

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

### ArrayList: Динамические массивы

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

### HashMap: Пары ключ-значение

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

## Обработка исключений

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

### Несколько блоков Catch

Обработка различных типов исключений по отдельности.

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

### Генерация пользовательских исключений

Создание и генерация собственных исключений.

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

### Общие типы исключений

Часто встречающиеся исключения в программах на Java.

```java
// NullPointerException
String str = null;
// str.length(); // Вызовет NullPointerException

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
// int val = arr[5]; // Вызовет ArrayIndexOutOfBoundsException

// NumberFormatException
// int num = Integer.parseInt("abc"); // Вызовет NumberFormatException

// FileNotFoundException (при работе с файлами)
// IOException (общие операции ввода/вывода)
```

## Операции ввода/вывода

### Ввод с консоли: Класс Scanner

Чтение ввода с клавиатуры с помощью `Scanner`.

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

### Вывод на консоль: System.out

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

### Чтение файла: BufferedReader

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

### Запись в файл: PrintWriter

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

## Среда разработки Java

### Установка JDK

JDK (Java Development Kit) = JRE + Инструменты разработки. Необходим для разработки Java-приложений.

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

### Компиляция и запуск программ на Java

Используйте `javac` для компиляции исходного кода Java и `java` для запуска скомпилированной программы.

```bash
# Скомпилировать исходный файл Java
javac MyProgram.java

# Запустить скомпилированную программу Java
java MyProgram

# Компиляция с указанием classpath
javac -cp .:mylib.jar MyProgram.java

# Запуск с указанием classpath
java -cp .:mylib.jar MyProgram
```

### Настройка и разработка в IDE

Популярные интегрированные среды разработки (IDE) для разработки на Java.

```bash
# Популярные IDE для Java:
# - IntelliJ IDEA (JetBrains)
# - Eclipse IDE
# - Visual Studio Code с расширениями Java
# - NetBeans

# Компиляция из командной строки
javac -d bin src/*.java
java -cp bin MainClass

# Создание JAR-файла
jar cf myapp.jar -C bin .
```

## Лучшие практики и общие шаблоны

### Соглашения об именовании

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

### Организация кода

Структурирование программ на Java для удобства сопровождения.

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

### Предотвращение ошибок

Общие практики для избежания ошибок и повышения качества кода.

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
        // Проверка границ массива
        if (array != null && index >= 0 && index < array.length) {
            System.out.println("Value: " + array[index]);
        } else {
            System.out.println("Invalid array access");
        }
    }
}
```

### Управление ресурсами

Надлежащая обработка ресурсов для предотвращения утечек памяти.

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

## Соответствующие ссылки

- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/cpp">Шпаргалка по C++</router-link>
- <router-link to="/golang">Шпаргалка по Go</router-link>
- <router-link to="/web-development">Шпаргалка по веб-разработке</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>
- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>

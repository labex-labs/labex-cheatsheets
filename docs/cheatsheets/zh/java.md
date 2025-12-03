---
title: 'Java 速查表 | LabEx'
description: '使用这份全面的 Java 速查表学习 Java 编程。快速参考 Java 语法、OOP、集合、流、Spring 框架和企业开发要点。'
pdfUrl: '/cheatsheets/pdf/java-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Java 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/java">使用实践实验室学习 Java</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Java 编程。LabEx 提供全面的 Java 课程，涵盖基本语法、面向对象编程、集合、异常处理和最佳实践。掌握 Java 开发基础知识并构建健壮的应用程序。
</base-disclaimer-content>
</base-disclaimer>

## 程序结构与基本语法

### Hello World：基本程序

在屏幕上显示“Hello, World!”的最简单的 Java 程序。

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### 类声明：`public class`

类是描述对象所支持的行为/状态的模板/蓝图。

```java
public class MyClass {
    // 类的内容放在这里
    int myVariable;

    public void myMethod() {
        System.out.println("Hello from method!");
    }
}
```

### Main 方法：程序入口点

main 方法是 Java 程序执行开始的地方。

```java
public static void main(String[] args) {
    // 程序代码在这里
    System.out.println("Program starts here");
}
```

<BaseQuiz id="java-main-1" correct="C">
  <template #question>
    Java 中 main 方法的正确签名是什么？
  </template>
  
  <BaseQuizOption value="A">public void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="B">static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="C" correct>public static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="D">public static int main(String[] args)</BaseQuizOption>
  
  <BaseQuizAnswer>
    main 方法必须是 `public static void main(String[] args)`。`public` 允许 JVM 访问它，`static` 表示它属于类，`void` 表示它不返回任何内容，`String[] args` 接收命令行参数。
  </BaseQuizAnswer>
</BaseQuiz>

### 注释：代码文档

使用单行 (`//`) 和多行 (`/* */`) 注释使代码更易于理解和维护。

```java
// 单行注释
System.out.println("Hello");

/* 多行注释
   可以跨越多行
   用于详细解释 */
```

### 语句与分号

Java 中的每条语句都必须以分号结束。

```java
int number = 10;
String name = "Java";
System.out.println(name);
```

### 代码块：花括号

代码块用花括号 `{}` 括起来，标记代码部分的开始和结束。

```java
public class Example {
    public void method() {
        if (true) {
            System.out.println("Inside if block");
        }
    }
}
```

## 数据类型与变量

### 基本数据类型

Java 语言内置的基本数据类型。

```java
// 整数类型
byte smallNum = 127;        // -128 到 127
short shortNum = 32000;     // -32,768 到 32,767
int number = 100;           // -2^31 到 2^31-1
long bigNum = 10000L;       // -2^63 到 2^63-1

// 浮点类型
float decimal = 3.14f;      // 单精度
double precision = 3.14159; // 双精度

// 其他类型
char letter = 'A';          // 单个字符
boolean flag = true;        // true 或 false
```

### 变量声明与初始化

创建和给变量赋值。

```java
// 仅声明
int age;
String name;

// 声明并初始化
int age = 25;
String name = "John";

// 多重声明
int x = 10, y = 20, z = 30;

// Final 变量（常量）
final double PI = 3.14159;
```

### 字符串操作

字符串表示字符序列，并且是不可变的，意味着一旦创建，其值就不能更改。

```java
String greeting = "Hello";
String name = "World";

// 字符串连接
String message = greeting + " " + name;
System.out.println(message); // "Hello World"

// 字符串方法
int length = message.length();
boolean isEmpty = message.isEmpty();
String uppercase = message.toUpperCase();
```

<BaseQuiz id="java-string-1" correct="A">
  <template #question>
    Java 字符串不可变性意味着什么？
  </template>
  
  <BaseQuizOption value="A" correct>一旦创建，字符串的值就不能更改</BaseQuizOption>
  <BaseQuizOption value="B">字符串不能被创建</BaseQuizOption>
  <BaseQuizOption value="C">字符串只能存储数字</BaseQuizOption>
  <BaseQuizOption value="D">字符串会自动删除</BaseQuizOption>
  
  <BaseQuizAnswer>
    不可变性意味着一旦创建了 String 对象，其值就不能被修改。像 `toUpperCase()` 这样的操作会返回一个新的 String 对象，而不是修改原始对象。
  </BaseQuizAnswer>
</BaseQuiz>

## 控制流语句

### 条件语句：`if`, `else if`, `else`

根据条件执行不同的代码块。

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

### Switch 语句

基于变量值进行多路分支。

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

### For 循环：计数重复

重复执行代码特定的次数。

```java
// 标准 for 循环
for (int i = 0; i < 5; i++) {
    System.out.println("Count: " + i);
}

// 增强型 for 循环 (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println("Number: " + num);
}
```

<BaseQuiz id="java-for-loop-1" correct="C">
  <template #question>
    增强型 for 循环（for-each）用于什么？
  </template>
  
  <BaseQuizOption value="A">使用计数器变量进行迭代</BaseQuizOption>
  <BaseQuizOption value="B">无限循环</BaseQuizOption>
  <BaseQuizOption value="C" correct>在没有索引的情况下迭代数组和集合</BaseQuizOption>
  <BaseQuizOption value="D">仅用于嵌套循环</BaseQuizOption>
  
  <BaseQuizAnswer>
    增强型 for 循环（for-each）通过自动处理索引来简化对数组和集合的迭代，使代码更具可读性，并减少出错的可能性。
  </BaseQuizAnswer>
</BaseQuiz>

### While 和 Do-While 循环

只要条件为真就重复执行代码。

```java
// While 循环
int i = 0;
while (i < 3) {
    System.out.println("While: " + i);
    i++;
}

// Do-while 循环（至少执行一次）
int j = 0;
do {
    System.out.println("Do-while: " + j);
    j++;
} while (j < 3);
```

<BaseQuiz id="java-while-1" correct="B">
  <template #question>
    `while` 和 `do-while` 循环之间的主要区别是什么？
  </template>
  
  <BaseQuizOption value="A">没有区别</BaseQuizOption>
  <BaseQuizOption value="B" correct>do-while 至少执行一次，而 while 可能一次都不执行</BaseQuizOption>
  <BaseQuizOption value="C">while 速度更快</BaseQuizOption>
  <BaseQuizOption value="D">do-while 只适用于数组</BaseQuizOption>
  
  <BaseQuizAnswer>
    `do-while` 循环在执行循环体后检查条件，因此至少会运行一次。`while` 循环首先检查条件，如果条件一开始就为 false，则可能不会执行。
  </BaseQuizAnswer>
</BaseQuiz>

## 面向对象编程

### 类与对象

对象具有状态和行为。对象是类的实例。

```java
public class Car {
    // 实例变量（状态）
    String color;
    String model;
    int year;

    // 构造函数
    public Car(String color, String model, int year) {
        this.color = color;
        this.model = model;
        this.year = year;
    }

    // 方法（行为）
    public void start() {
        System.out.println("Car is starting...");
    }
}

// 创建对象
Car myCar = new Car("Red", "Toyota", 2022);
myCar.start();
```

### 构造函数

用于初始化对象的特殊方法。

```java
public class Person {
    String name;
    int age;

    // 默认构造函数
    public Person() {
        name = "Unknown";
        age = 0;
    }

    // 带参数的构造函数
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
```

### 继承：`extends`

继承支持代码重用，并在类之间创建层次结构关系。

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
myDog.eat();  // 继承的方法
myDog.bark(); // 自己的方法
```

### 访问修饰符

修饰符控制对类、方法和变量的访问。

```java
public class Example {
    public int publicVar;      // 可以在任何地方访问
    private int privateVar;    // 仅在当前类中访问
    protected int protectedVar; // 在包内和子类中访问
    int defaultVar;            // 仅在包内访问

    private void privateMethod() {
        // 仅在此类中可访问
    }
}
```

## 方法与函数

### 方法声明

方法基本上是编写逻辑、操作数据和执行操作的地方。

```java
public class Calculator {
    // 带参数和返回值的方
    public int add(int a, int b) {
        return a + b;
    }

    // 无返回值的方法
    public void printSum(int a, int b) {
        int result = add(a, b);
        System.out.println("Sum: " + result);
    }

    // 静态方法（属于类）
    public static int multiply(int a, int b) {
        return a * b;
    }
}
```

### 方法重载

多个同名但参数不同的方法。

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

### 方法参数与返回类型

将数据传递给方法并返回结果。

```java
public class StringHelper {
    // 带 String 参数和返回值的方
    public String formatName(String firstName, String lastName) {
        return firstName + " " + lastName;
    }

    // 带数组参数的方法
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

### 递归方法

调用自身来解决问题的方法。

```java
public class RecursiveExamples {
    // 计算阶乘
    public int factorial(int n) {
        if (n <= 1) {
            return 1;
        }
        return n * factorial(n - 1);
    }

    // 斐波那契数列
    public int fibonacci(int n) {
        if (n <= 1) {
            return n;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

## 数组与集合

### 数组声明与初始化

创建和初始化不同类型的数组。

```java
// 数组声明和初始化
int[] numbers = {1, 2, 3, 4, 5};
String[] names = {"Alice", "Bob", "Charlie"};

// 指定大小的数组
int[] scores = new int[10];
scores[0] = 95;
scores[1] = 87;

// 获取数组长度
int length = numbers.length;
System.out.println("Length: " + length);

// 遍历数组
for (int i = 0; i < numbers.length; i++) {
    System.out.println("Element " + i + ": " + numbers[i]);
}
```

### 多维数组

用于矩阵等数据结构的数组的数组。

```java
// 二维数组声明
int[][] matrix = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

// 访问元素
int element = matrix[1][2]; // 获取 6

// 遍历二维数组
for (int i = 0; i < matrix.length; i++) {
    for (int j = 0; j < matrix[i].length; j++) {
        System.out.print(matrix[i][j] + " ");
    }
    System.out.println();
}
```

### ArrayList：动态数组

可动态增长和缩小的可调整大小的数组。

```java
import java.util.ArrayList;

// 创建 ArrayList
ArrayList<String> list = new ArrayList<>();

// 添加元素
list.add("Apple");
list.add("Banana");
list.add("Orange");

// 获取元素
String fruit = list.get(0); // 获取 "Apple"

// 移除元素
list.remove(1); // 移除 "Banana"

// 大小和迭代
System.out.println("Size: " + list.size());
for (String item : list) {
    System.out.println(item);
}
```

### HashMap：键值对

以键值对形式存储数据，以便快速查找。

```java
import java.util.HashMap;

// 创建 HashMap
HashMap<String, Integer> ages = new HashMap<>();

// 添加键值对
ages.put("Alice", 25);
ages.put("Bob", 30);
ages.put("Charlie", 35);

// 通过键获取值
int aliceAge = ages.get("Alice");

// 检查键是否存在
if (ages.containsKey("Bob")) {
    System.out.println("Bob's age: " + ages.get("Bob"));
}
```

## 异常处理

### Try-Catch 块

处理异常以防止程序崩溃。

```java
public class ExceptionExample {
    public static void main(String[] args) {
        try {
            int result = 10 / 0; // 这将抛出 ArithmeticException
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

### 多个 Catch 块

分别处理不同类型的异常。

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

### 抛出自定义异常

创建并抛出自己的异常。

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

### 常见异常类型

Java 程序中经常遇到的异常类型。

```java
// NullPointerException
String str = null;
// str.length(); // 抛出 NullPointerException

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
// int val = arr[5]; // 抛出 ArrayIndexOutOfBoundsException

// NumberFormatException
// int num = Integer.parseInt("abc"); // 抛出 NumberFormatException

// FileNotFoundException (处理文件时)
// IOException (一般 I/O 操作)
```

## 输入/输出操作

### 控制台输入：Scanner 类

使用 Scanner 从键盘读取输入。

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

### 控制台输出：System.out

以各种格式将输出显示到控制台。

```java
public class OutputExample {
    public static void main(String[] args) {
        // 基本输出
        System.out.println("Hello, World!");
        System.out.print("No newline");
        System.out.print(" continues here\n");

        // 格式化输出
        String name = "Java";
        int version = 17;
        System.out.printf("Welcome to %s %d!%n", name, version);

        // 输出变量
        int x = 10, y = 20;
        System.out.println("x = " + x + ", y = " + y);
        System.out.println("Sum = " + (x + y));
    }
}
```

### 文件读取：BufferedReader

高效地逐行读取文本文件。

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

### 文件写入：PrintWriter

带有适当异常处理的将文本数据写入文件。

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

## Java 开发环境

### JDK 安装

JDK (Java Development Kit) = JRE + 开发工具。开发 Java 应用程序所需。

```bash
# 从 Oracle 或 OpenJDK 下载 JDK
# 在系统上安装 JDK
# 设置 JAVA_HOME 环境变量
export JAVA_HOME=/path/to/jdk
export PATH=$JAVA_HOME/bin:$PATH

# 验证安装
java -version
javac -version
```

### 编译与运行 Java 程序

使用 `javac` 编译 Java 源代码，使用 `java` 运行编译后的程序。

```bash
# 编译 Java 源文件
javac MyProgram.java

# 运行编译后的 Java 程序
java MyProgram

# 带类路径编译
javac -cp .:mylib.jar MyProgram.java

# 带类路径运行
java -cp .:mylib.jar MyProgram
```

### IDE 设置与开发

用于 Java 开发的流行集成开发环境。

```bash
# 流行的 Java IDE：
# - IntelliJ IDEA (JetBrains)
# - Eclipse IDE
# - Visual Studio Code with Java extensions
# - NetBeans

# 命令行编译
javac -d bin src/*.java
java -cp bin MainClass

# 创建 JAR 文件
jar cf myapp.jar -C bin .
```

## 最佳实践与常见模式

### 命名约定

遵循 Java 命名标准以提高代码可读性。

```java
// 类：PascalCase (帕斯卡命名法)
public class StudentManager { }
public class BankAccount { }

// 方法和变量：camelCase (驼峰命名法)
int studentAge;
String firstName;
public void calculateGrade() { }
public boolean isValidEmail() { }

// 常量：大写字母加下划线
public static final int MAX_SIZE = 100;
public static final String DEFAULT_NAME = "Unknown";

// 包：小写
package com.company.project;
package utils.database;
package com.example.myapp;
```

### 代码组织

构建结构化的 Java 程序以方便维护。

```java
import java.util.ArrayList;
import java.util.Scanner;

/**
 * 此类演示了良好的 Java 代码组织
 * @author 你的名字
 * @version 1.0
 */
public class WellOrganizedClass {
    // 常量优先
    private static final int MAX_ATTEMPTS = 3;

    // 实例变量
    private String name;
    private int value;

    // 构造函数
    public WellOrganizedClass(String name) {
        this.name = name;
        this.value = 0;
    }

    // 公共方法
    public void doSomething() {
        // 实现
    }

    // 私有辅助方法
    private boolean isValid() {
        return value > 0;
    }
}
```

### 错误预防

避免错误的常见做法，提高代码质量。

```java
public class BestPractices {
    public void safeDivision(int a, int b) {
        // 检查除零错误
        if (b == 0) {
            throw new IllegalArgumentException("Cannot divide by zero");
        }
        int result = a / b;
        System.out.println("Result: " + result);
    }

    public void safeStringOperations(String input) {
        // 在使用字符串之前进行空值检查
        if (input != null && !input.isEmpty()) {
            System.out.println("Length: " + input.length());
            System.out.println("Uppercase: " + input.toUpperCase());
        } else {
            System.out.println("Invalid input string");
        }
    }

    public void safeArrayAccess(int[] array, int index) {
        // 边界检查
        if (array != null && index >= 0 && index < array.length) {
            System.out.println("Value: " + array[index]);
        } else {
            System.out.println("Invalid array access");
        }
    }
}
```

### 资源管理

妥善处理资源以防止内存泄漏。

```java
import java.io.*;

public class ResourceManagement {
    // Try-with-resources（自动清理）
    public void readFileProper(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine();
            System.out.println(line);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        // Reader 会自动关闭
    }

    // 手动资源清理（不推荐）
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

## 相关链接

- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/cpp">C++ 速查表</router-link>
- <router-link to="/golang">Go 速查表</router-link>
- <router-link to="/web-development">Web 开发速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/kubernetes">Kubernetes 速查表</router-link>

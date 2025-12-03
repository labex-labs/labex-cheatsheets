---
title: 'Java Cheatsheet | LabEx'
description: 'Learn Java programming with this comprehensive cheatsheet. Quick reference for Java syntax, OOP, collections, streams, Spring framework, and enterprise development essentials.'
pdfUrl: '/cheatsheets/pdf/java-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Java Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/java">Learn Java with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn Java programming through hands-on labs and real-world scenarios. LabEx provides comprehensive Java courses covering essential syntax, object-oriented programming, collections, exception handling, and best practices. Master Java development fundamentals and build robust applications.
</base-disclaimer-content>
</base-disclaimer>

## Program Structure & Basic Syntax

### Hello World: Basic Program

The simplest Java program that displays "Hello, World!" on the screen.

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### Class Declaration: `public class`

A class is a template/blueprint that describes the behavior/state that objects support.

```java
public class MyClass {
    // Class content goes here
    int myVariable;

    public void myMethod() {
        System.out.println("Hello from method!");
    }
}
```

### Main Method: Program Entry Point

The main method is where Java program execution begins.

```java
public static void main(String[] args) {
    // Program code here
    System.out.println("Program starts here");
}
```

<BaseQuiz id="java-main-1" correct="C">
  <template #question>
    What is the correct signature for the main method in Java?
  </template>
  
  <BaseQuizOption value="A">public void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="B">static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="C" correct>public static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="D">public static int main(String[] args)</BaseQuizOption>
  
  <BaseQuizAnswer>
    The main method must be <code>public static void main(String[] args)</code>. <code>public</code> allows JVM to access it, <code>static</code> means it belongs to the class, <code>void</code> means it returns nothing, and <code>String[] args</code> receives command-line arguments.
  </BaseQuizAnswer>
</BaseQuiz>

### Comments: Code Documentation

Use single-line (`//`) and multi-line (`/* */`) comments to make code more understandable and maintainable.

```java
// Single-line comment
System.out.println("Hello");

/* Multi-line comment
   Can span multiple lines
   Used for detailed explanations */
```

### Statements & Semicolons

Each statement in Java must end with a semicolon.

```java
int number = 10;
String name = "Java";
System.out.println(name);
```

### Code Blocks: Curly Braces

Blocks of code are enclosed in curly braces `{}`, marking the beginning and end of code sections.

```java
public class Example {
    public void method() {
        if (true) {
            System.out.println("Inside if block");
        }
    }
}
```

## Data Types & Variables

### Primitive Data Types

Basic data types built into Java language.

```java
// Integer types
byte smallNum = 127;        // -128 to 127
short shortNum = 32000;     // -32,768 to 32,767
int number = 100;           // -2^31 to 2^31-1
long bigNum = 10000L;       // -2^63 to 2^63-1

// Floating point types
float decimal = 3.14f;      // Single precision
double precision = 3.14159; // Double precision

// Other types
char letter = 'A';          // Single character
boolean flag = true;        // true or false
```

### Variable Declaration & Initialization

Creating and assigning values to variables.

```java
// Declaration only
int age;
String name;

// Declaration with initialization
int age = 25;
String name = "John";

// Multiple declarations
int x = 10, y = 20, z = 30;

// Final variables (constants)
final double PI = 3.14159;
```

### String Operations

Strings represent sequences of characters and are immutable, meaning once created, their values cannot be changed.

```java
String greeting = "Hello";
String name = "World";

// String concatenation
String message = greeting + " " + name;
System.out.println(message); // "Hello World"

// String methods
int length = message.length();
boolean isEmpty = message.isEmpty();
String uppercase = message.toUpperCase();
```

<BaseQuiz id="java-string-1" correct="A">
  <template #question>
    What does it mean that Java strings are immutable?
  </template>
  
  <BaseQuizOption value="A" correct>Once created, a string's value cannot be changed</BaseQuizOption>
  <BaseQuizOption value="B">Strings cannot be created</BaseQuizOption>
  <BaseQuizOption value="C">Strings can only store numbers</BaseQuizOption>
  <BaseQuizOption value="D">Strings are automatically deleted</BaseQuizOption>
  
  <BaseQuizAnswer>
    Immutability means that once a String object is created, its value cannot be modified. Operations like <code>toUpperCase()</code> return a new String object rather than modifying the original.
  </BaseQuizAnswer>
</BaseQuiz>

## Control Flow Statements

### Conditional Statements: `if`, `else if`, `else`

Execute different code blocks based on conditions.

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

### Switch Statement

Multi-way branching based on variable values.

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

### For Loop: Counted Repetition

Repeat code a specific number of times.

```java
// Standard for loop
for (int i = 0; i < 5; i++) {
    System.out.println("Count: " + i);
}

// Enhanced for loop (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println("Number: " + num);
}
```

<BaseQuiz id="java-for-loop-1" correct="C">
  <template #question>
    What is the enhanced for loop (for-each) used for?
  </template>
  
  <BaseQuizOption value="A">Iterating with a counter variable</BaseQuizOption>
  <BaseQuizOption value="B">Infinite loops</BaseQuizOption>
  <BaseQuizOption value="C" correct>Iterating through arrays and collections without an index</BaseQuizOption>
  <BaseQuizOption value="D">Nested loops only</BaseQuizOption>
  
  <BaseQuizAnswer>
    The enhanced for loop (for-each) simplifies iteration through arrays and collections by automatically handling the index, making code more readable and less error-prone.
  </BaseQuizAnswer>
</BaseQuiz>

### While & Do-While Loops

Repeat code while a condition is true.

```java
// While loop
int i = 0;
while (i < 3) {
    System.out.println("While: " + i);
    i++;
}

// Do-while loop (executes at least once)
int j = 0;
do {
    System.out.println("Do-while: " + j);
    j++;
} while (j < 3);
```

<BaseQuiz id="java-while-1" correct="B">
  <template #question>
    What is the key difference between <code>while</code> and <code>do-while</code> loops?
  </template>
  
  <BaseQuizOption value="A">There is no difference</BaseQuizOption>
  <BaseQuizOption value="B" correct>do-while executes at least once, while may not execute at all</BaseQuizOption>
  <BaseQuizOption value="C">while is faster</BaseQuizOption>
  <BaseQuizOption value="D">do-while only works with arrays</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code>do-while</code> loop checks the condition after executing the loop body, so it always runs at least once. The <code>while</code> loop checks the condition first, so it may not execute if the condition is false initially.
  </BaseQuizAnswer>
</BaseQuiz>

## Object-Oriented Programming

### Classes & Objects

Objects have states and behaviors. An object is an instance of a class.

```java
public class Car {
    // Instance variables (state)
    String color;
    String model;
    int year;

    // Constructor
    public Car(String color, String model, int year) {
        this.color = color;
        this.model = model;
        this.year = year;
    }

    // Method (behavior)
    public void start() {
        System.out.println("Car is starting...");
    }
}

// Creating objects
Car myCar = new Car("Red", "Toyota", 2022);
myCar.start();
```

### Constructors

Special methods used to initialize objects.

```java
public class Person {
    String name;
    int age;

    // Default constructor
    public Person() {
        name = "Unknown";
        age = 0;
    }

    // Parameterized constructor
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
```

### Inheritance: `extends`

Inheritance enables code reuse and creates hierarchical relationships between classes.

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
myDog.eat();  // Inherited method
myDog.bark(); // Own method
```

### Access Modifiers

Modifiers control access to classes, methods, and variables.

```java
public class Example {
    public int publicVar;      // Accessible everywhere
    private int privateVar;    // Only within this class
    protected int protectedVar; // Within package + subclasses
    int defaultVar;            // Within package only

    private void privateMethod() {
        // Only accessible within this class
    }
}
```

## Methods & Functions

### Method Declaration

A method is basically a behavior where logics are written, data is manipulated and actions are executed.

```java
public class Calculator {
    // Method with parameters and return value
    public int add(int a, int b) {
        return a + b;
    }

    // Method with no return value
    public void printSum(int a, int b) {
        int result = add(a, b);
        System.out.println("Sum: " + result);
    }

    // Static method (belongs to class)
    public static int multiply(int a, int b) {
        return a * b;
    }
}
```

### Method Overloading

Multiple methods with same name but different parameters.

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

### Method Parameters & Return Types

Pass data to methods and return results.

```java
public class StringHelper {
    // Method with String parameter and return
    public String formatName(String firstName, String lastName) {
        return firstName + " " + lastName;
    }

    // Method with array parameter
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

### Recursive Methods

Methods that call themselves to solve problems.

```java
public class RecursiveExamples {
    // Calculate factorial
    public int factorial(int n) {
        if (n <= 1) {
            return 1;
        }
        return n * factorial(n - 1);
    }

    // Fibonacci sequence
    public int fibonacci(int n) {
        if (n <= 1) {
            return n;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

## Arrays & Collections

### Array Declaration & Initialization

Create and initialize arrays of different types.

```java
// Array declaration and initialization
int[] numbers = {1, 2, 3, 4, 5};
String[] names = {"Alice", "Bob", "Charlie"};

// Array with specified size
int[] scores = new int[10];
scores[0] = 95;
scores[1] = 87;

// Getting array length
int length = numbers.length;
System.out.println("Length: " + length);

// Loop through array
for (int i = 0; i < numbers.length; i++) {
    System.out.println("Element " + i + ": " + numbers[i]);
}
```

### Multi-dimensional Arrays

Arrays of arrays for matrix-like data structures.

```java
// 2D array declaration
int[][] matrix = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

// Access elements
int element = matrix[1][2]; // Gets 6

// Loop through 2D array
for (int i = 0; i < matrix.length; i++) {
    for (int j = 0; j < matrix[i].length; j++) {
        System.out.print(matrix[i][j] + " ");
    }
    System.out.println();
}
```

### ArrayList: Dynamic Arrays

Resizable arrays that can grow and shrink dynamically.

```java
import java.util.ArrayList;

// Create ArrayList
ArrayList<String> list = new ArrayList<>();

// Add elements
list.add("Apple");
list.add("Banana");
list.add("Orange");

// Get element
String fruit = list.get(0); // Gets "Apple"

// Remove element
list.remove(1); // Removes "Banana"

// Size and iteration
System.out.println("Size: " + list.size());
for (String item : list) {
    System.out.println(item);
}
```

### HashMap: Key-Value Pairs

Store data as key-value pairs for fast lookup.

```java
import java.util.HashMap;

// Create HashMap
HashMap<String, Integer> ages = new HashMap<>();

// Add key-value pairs
ages.put("Alice", 25);
ages.put("Bob", 30);
ages.put("Charlie", 35);

// Get value by key
int aliceAge = ages.get("Alice");

// Check if key exists
if (ages.containsKey("Bob")) {
    System.out.println("Bob's age: " + ages.get("Bob"));
}
```

## Exception Handling

### Try-Catch Blocks

Handle exceptions to prevent program crashes.

```java
public class ExceptionExample {
    public static void main(String[] args) {
        try {
            int result = 10 / 0; // This will throw ArithmeticException
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

### Multiple Catch Blocks

Handle different types of exceptions separately.

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

### Throwing Custom Exceptions

Create and throw your own exceptions.

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

### Common Exception Types

Frequently encountered exceptions in Java programs.

```java
// NullPointerException
String str = null;
// str.length(); // Throws NullPointerException

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
// int val = arr[5]; // Throws ArrayIndexOutOfBoundsException

// NumberFormatException
// int num = Integer.parseInt("abc"); // Throws NumberFormatException

// FileNotFoundException (when working with files)
// IOException (general I/O operations)
```

## Input/Output Operations

### Console Input: Scanner Class

Read input from the keyboard using Scanner.

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

### Console Output: System.out

Display output to the console in various formats.

```java
public class OutputExample {
    public static void main(String[] args) {
        // Basic output
        System.out.println("Hello, World!");
        System.out.print("No newline");
        System.out.print(" continues here\n");

        // Formatted output
        String name = "Java";
        int version = 17;
        System.out.printf("Welcome to %s %d!%n", name, version);

        // Output variables
        int x = 10, y = 20;
        System.out.println("x = " + x + ", y = " + y);
        System.out.println("Sum = " + (x + y));
    }
}
```

### File Reading: BufferedReader

Read text files line by line efficiently.

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

### File Writing: PrintWriter

Write text data to files with proper exception handling.

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

## Java Development Environment

### JDK Installation

JDK (Java Development Kit) = JRE + Development Tools. Required for developing Java applications.

```bash
# Download JDK from Oracle or OpenJDK
# Install JDK on your system
# Set JAVA_HOME environment variable
export JAVA_HOME=/path/to/jdk
export PATH=$JAVA_HOME/bin:$PATH

# Verify installation
java -version
javac -version
```

### Compile & Run Java Programs

Use `javac` to compile Java source code and `java` to run the compiled program.

```bash
# Compile Java source file
javac MyProgram.java

# Run compiled Java program
java MyProgram

# Compile with classpath
javac -cp .:mylib.jar MyProgram.java

# Run with classpath
java -cp .:mylib.jar MyProgram
```

### IDE Setup & Development

Popular Integrated Development Environments for Java development.

```bash
# Popular Java IDEs:
# - IntelliJ IDEA (JetBrains)
# - Eclipse IDE
# - Visual Studio Code with Java extensions
# - NetBeans

# Command line compilation
javac -d bin src/*.java
java -cp bin MainClass

# JAR file creation
jar cf myapp.jar -C bin .
```

## Best Practices & Common Patterns

### Naming Conventions

Follow Java naming standards for better code readability.

```java
// Classes: PascalCase
public class StudentManager { }
public class BankAccount { }

// Methods and variables: camelCase
int studentAge;
String firstName;
public void calculateGrade() { }
public boolean isValidEmail() { }

// Constants: UPPER_CASE
public static final int MAX_SIZE = 100;
public static final String DEFAULT_NAME = "Unknown";

// Packages: lowercase
package com.company.project;
package utils.database;
package com.example.myapp;
```

### Code Organization

Structure your Java programs for maintainability.

```java
import java.util.ArrayList;
import java.util.Scanner;

/**
 * This class demonstrates good Java code organization
 * @author Your Name
 * @version 1.0
 */
public class WellOrganizedClass {
    // Constants first
    private static final int MAX_ATTEMPTS = 3;

    // Instance variables
    private String name;
    private int value;

    // Constructor
    public WellOrganizedClass(String name) {
        this.name = name;
        this.value = 0;
    }

    // Public methods
    public void doSomething() {
        // Implementation
    }

    // Private helper methods
    private boolean isValid() {
        return value > 0;
    }
}
```

### Error Prevention

Common practices to avoid bugs and improve code quality.

```java
public class BestPractices {
    public void safeDivision(int a, int b) {
        // Check for division by zero
        if (b == 0) {
            throw new IllegalArgumentException("Cannot divide by zero");
        }
        int result = a / b;
        System.out.println("Result: " + result);
    }

    public void safeStringOperations(String input) {
        // Null check before using strings
        if (input != null && !input.isEmpty()) {
            System.out.println("Length: " + input.length());
            System.out.println("Uppercase: " + input.toUpperCase());
        } else {
            System.out.println("Invalid input string");
        }
    }

    public void safeArrayAccess(int[] array, int index) {
        // Bounds checking
        if (array != null && index >= 0 && index < array.length) {
            System.out.println("Value: " + array[index]);
        } else {
            System.out.println("Invalid array access");
        }
    }
}
```

### Resource Management

Properly handle resources to prevent memory leaks.

```java
import java.io.*;

public class ResourceManagement {
    // Try-with-resources (automatic cleanup)
    public void readFileProper(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine();
            System.out.println(line);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        // Reader is automatically closed
    }

    // Manual resource cleanup (not recommended)
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

## Relevant Links

- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/javascript">JavaScript Cheatsheet</router-link>
- <router-link to="/cpp">C++ Cheatsheet</router-link>
- <router-link to="/golang">Go Cheatsheet</router-link>
- <router-link to="/web-development">Web Development Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/kubernetes">Kubernetes Cheatsheet</router-link>

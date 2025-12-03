---
title: 'Hoja de Trucos de Java | LabEx'
description: 'Aprenda programación Java con esta hoja de trucos completa. Referencia rápida de sintaxis Java, OOP, colecciones, streams, framework Spring y elementos esenciales del desarrollo empresarial.'
pdfUrl: '/cheatsheets/pdf/java-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Java
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/java">Aprende Java con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende programación Java a través de laboratorios prácticos y escenarios del mundo real. LabEx proporciona cursos completos de Java que cubren sintaxis esencial, programación orientada a objetos, colecciones, manejo de excepciones y mejores prácticas. Domina los fundamentos del desarrollo en Java y construye aplicaciones robustas.
</base-disclaimer-content>
</base-disclaimer>

## Estructura del Programa y Sintaxis Básica

### Hola Mundo: Programa Básico

El programa Java más simple que muestra "Hello, World!" en la pantalla.

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### Declaración de Clase: `public class`

Una clase es una plantilla/plano que describe el comportamiento/estado que soportan los objetos.

```java
public class MyClass {
    // El contenido de la clase va aquí
    int myVariable;

    public void myMethod() {
        System.out.println("Hello from method!");
    }
}
```

### Método Main: Punto de Entrada del Programa

El método principal es donde comienza la ejecución del programa Java.

```java
public static void main(String[] args) {
    // Código del programa aquí
    System.out.println("Program starts here");
}
```

<BaseQuiz id="java-main-1" correct="C">
  <template #question>
    ¿Cuál es la firma correcta para el método main en Java?
  </template>
  
  <BaseQuizOption value="A">public void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="B">static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="C" correct>public static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="D">public static int main(String[] args)</BaseQuizOption>
  
  <BaseQuizAnswer>
    El método main debe ser <code>public static void main(String[] args)</code>. <code>public</code> permite que la JVM acceda a él, <code>static</code> significa que pertenece a la clase, <code>void</code> significa que no devuelve nada, y <code>String[] args</code> recibe argumentos de línea de comandos.
  </BaseQuizAnswer>
</BaseQuiz>

### Comentarios: Documentación del Código

Usa comentarios de una sola línea (`//`) y de varias líneas (`/* */`) para hacer el código más comprensible y mantenible.

```java
// Comentario de una sola línea
System.out.println("Hello");

/* Comentario de varias líneas
   Puede abarcar varias líneas
   Usado para explicaciones detalladas */
```

### Sentencias y Punto y Coma

Cada sentencia en Java debe terminar con un punto y coma.

```java
int number = 10;
String name = "Java";
System.out.println(name);
```

### Bloques de Código: Llaves

Los bloques de código están encerrados entre llaves `{}`, marcando el inicio y el final de las secciones de código.

```java
public class Example {
    public void method() {
        if (true) {
            System.out.println("Inside if block");
        }
    }
}
```

## Tipos de Datos y Variables

### Tipos de Datos Primitivos

Tipos de datos básicos integrados en el lenguaje Java.

```java
// Tipos enteros
byte smallNum = 127;        // -128 a 127
short shortNum = 32000;     // -32,768 a 32,767
int number = 100;           // -2^31 a 2^31-1
long bigNum = 10000L;       // -2^63 a 2^63-1

// Tipos de punto flotante
float decimal = 3.14f;      // Precisión simple
double precision = 3.14159; // Doble precisión

// Otros tipos
char letter = 'A';          // Carácter único
boolean flag = true;        // true o false
```

### Declaración e Inicialización de Variables

Crear y asignar valores a variables.

```java
// Declaración solamente
int age;
String name;

// Declaración con inicialización
int age = 25;
String name = "John";

// Declaraciones múltiples
int x = 10, y = 20, z = 30;

// Variables finales (constantes)
final double PI = 3.14159;
```

### Operaciones con Cadenas (String)

Las cadenas representan secuencias de caracteres y son inmutables, lo que significa que una vez creados, sus valores no se pueden cambiar.

```java
String greeting = "Hello";
String name = "World";

// Concatenación de cadenas
String message = greeting + " " + name;
System.out.println(message); // "Hello World"

// Métodos de cadena
int length = message.length();
boolean isEmpty = message.isEmpty();
String uppercase = message.toUpperCase();
```

<BaseQuiz id="java-string-1" correct="A">
  <template #question>
    ¿Qué significa que las cadenas de Java sean inmutables?
  </template>
  
  <BaseQuizOption value="A" correct>Una vez creados, el valor de una cadena no se puede cambiar</BaseQuizOption>
  <BaseQuizOption value="B">Las cadenas no se pueden crear</BaseQuizOption>
  <BaseQuizOption value="C">Las cadenas solo pueden almacenar números</BaseQuizOption>
  <BaseQuizOption value="D">Las cadenas se eliminan automáticamente</BaseQuizOption>
  
  <BaseQuizAnswer>
    La inmutabilidad significa que una vez que se crea un objeto String, su valor no se puede modificar. Operaciones como <code>toUpperCase()</code> devuelven un nuevo objeto String en lugar de modificar el original.
  </BaseQuizAnswer>
</BaseQuiz>

## Sentencias de Flujo de Control

### Sentencias Condicionales: `if`, `else if`, `else`

Ejecutan diferentes bloques de código basados en condiciones.

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

### Sentencia Switch

Ramificación de múltiples vías basada en los valores de las variables.

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

### Bucle For: Repetición Contada

Repetir código un número específico de veces.

```java
// Bucle for estándar
for (int i = 0; i < 5; i++) {
    System.out.println("Count: " + i);
}

// Bucle for mejorado (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println("Number: " + num);
}
```

<BaseQuiz id="java-for-loop-1" correct="C">
  <template #question>
    ¿Para qué se utiliza el bucle for mejorado (for-each)?
  </template>
  
  <BaseQuizOption value="A">Iterar con una variable contadora</BaseQuizOption>
  <BaseQuizOption value="B">Bucles infinitos</BaseQuizOption>
  <BaseQuizOption value="C" correct>Iterar a través de arrays y colecciones sin un índice</BaseQuizOption>
  <BaseQuizOption value="D">Solo bucles anidados</BaseQuizOption>
  
  <BaseQuizAnswer>
    El bucle for mejorado (for-each) simplifica la iteración a través de arrays y colecciones al manejar automáticamente el índice, haciendo el código más legible y menos propenso a errores.
  </BaseQuizAnswer>
</BaseQuiz>

### Bucles While y Do-While

Repetir código mientras una condición sea verdadera.

```java
// Bucle While
int i = 0;
while (i < 3) {
    System.out.println("While: " + i);
    i++;
}

// Bucle Do-while (ejecuta al menos una vez)
int j = 0;
do {
    System.out.println("Do-while: " + j);
    j++;
} while (j < 3);
```

<BaseQuiz id="java-while-1" correct="B">
  <template #question>
    ¿Cuál es la diferencia clave entre los bucles <code>while</code> y <code>do-while</code>?
  </template>
  
  <BaseQuizOption value="A">No hay diferencia</BaseQuizOption>
  <BaseQuizOption value="B" correct>do-while se ejecuta al menos una vez, mientras que while puede no ejecutarse nunca</BaseQuizOption>
  <BaseQuizOption value="C">while es más rápido</BaseQuizOption>
  <BaseQuizOption value="D">do-while solo funciona con arrays</BaseQuizOption>
  
  <BaseQuizAnswer>
    El bucle <code>do-while</code> comprueba la condición después de ejecutar el cuerpo del bucle, por lo que siempre se ejecuta al menos una vez. El bucle <code>while</code> comprueba la condición primero, por lo que puede no ejecutarse si la condición es falsa inicialmente.
  </BaseQuizAnswer>
</BaseQuiz>

## Programación Orientada a Objetos

### Clases y Objetos

Los objetos tienen estados y comportamientos. Un objeto es una instancia de una clase.

```java
public class Car {
    // Variables de instancia (estado)
    String color;
    String model;
    int year;

    // Constructor
    public Car(String color, String model, int year) {
        this.color = color;
        this.model = model;
        this.year = year;
    }

    // Método (comportamiento)
    public void start() {
        System.out.println("Car is starting...");
    }
}

// Creación de objetos
Car myCar = new Car("Red", "Toyota", 2022);
myCar.start();
```

### Constructores

Métodos especiales utilizados para inicializar objetos.

```java
public class Person {
    String name;
    int age;

    // Constructor por defecto
    public Person() {
        name = "Unknown";
        age = 0;
    }

    // Constructor parametrizado
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
```

### Herencia: `extends`

La herencia permite la reutilización de código y crea relaciones jerárquicas entre clases.

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
myDog.eat();  // Método heredado
myDog.bark(); // Método propio
```

### Modificadores de Acceso

Los modificadores controlan el acceso a clases, métodos y variables.

```java
public class Example {
    public int publicVar;      // Accesible en todas partes
    private int privateVar;    // Solo dentro de esta clase
    protected int protectedVar; // Dentro del paquete + subclases
    int defaultVar;            // Solo dentro del paquete

    private void privateMethod() {
        // Solo accesible dentro de esta clase
    }
}
```

## Métodos y Funciones

### Declaración de Método

Un método es básicamente un comportamiento donde se escribe la lógica, se manipulan los datos y se ejecutan las acciones.

```java
public class Calculator {
    // Método con parámetros y valor de retorno
    public int add(int a, int b) {
        return a + b;
    }

    // Método sin valor de retorno
    public void printSum(int a, int b) {
        int result = add(a, b);
        System.out.println("Sum: " + result);
    }

    // Método estático (pertenece a la clase)
    public static int multiply(int a, int b) {
        return a * b;
    }
}
```

### Sobrecarga de Métodos (Method Overloading)

Múltiples métodos con el mismo nombre pero diferentes parámetros.

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

### Parámetros de Método y Tipos de Retorno

Pasar datos a métodos y devolver resultados.

```java
public class StringHelper {
    // Método con parámetro String y retorno
    public String formatName(String firstName, String lastName) {
        return firstName + " " + lastName;
    }

    // Método con parámetro de array
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

### Métodos Recursivos

Métodos que se llaman a sí mismos para resolver problemas.

```java
public class RecursiveExamples {
    // Calcular factorial
    public int factorial(int n) {
        if (n <= 1) {
            return 1;
        }
        return n * factorial(n - 1);
    }

    // Secuencia de Fibonacci
    public int fibonacci(int n) {
        if (n <= 1) {
            return n;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

## Arrays y Colecciones

### Declaración e Inicialización de Arrays

Crear e inicializar arrays de diferentes tipos.

```java
// Declaración e inicialización de array
int[] numbers = {1, 2, 3, 4, 5};
String[] names = {"Alice", "Bob", "Charlie"};

// Array con tamaño especificado
int[] scores = new int[10];
scores[0] = 95;
scores[1] = 87;

// Obtener la longitud del array
int length = numbers.length;
System.out.println("Length: " + length);

// Recorrer el array
for (int i = 0; i < numbers.length; i++) {
    System.out.println("Element " + i + ": " + numbers[i]);
}
```

### Arrays Multidimensionales

Arrays de arrays para estructuras de datos tipo matriz.

```java
// Declaración de array 2D
int[][] matrix = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

// Acceder a elementos
int element = matrix[1][2]; // Obtiene 6

// Recorrer array 2D
for (int i = 0; i < matrix.length; i++) {
    for (int j = 0; j < matrix[i].length; j++) {
        System.out.print(matrix[i][j] + " ");
    }
    System.out.println();
}
```

### ArrayList: Arrays Dinámicos

Arrays redimensionables que pueden crecer y encogerse dinámicamente.

```java
import java.util.ArrayList;

// Crear ArrayList
ArrayList<String> list = new ArrayList<>();

// Añadir elementos
list.add("Apple");
list.add("Banana");
list.add("Orange");

// Obtener elemento
String fruit = list.get(0); // Obtiene "Apple"

// Eliminar elemento
list.remove(1); // Elimina "Banana"

// Tamaño e iteración
System.out.println("Size: " + list.size());
for (String item : list) {
    System.out.println(item);
}
```

### HashMap: Pares Clave-Valor

Almacenar datos como pares clave-valor para una búsqueda rápida.

```java
import java.util.HashMap;

// Crear HashMap
HashMap<String, Integer> ages = new HashMap<>();

// Añadir pares clave-valor
ages.put("Alice", 25);
ages.put("Bob", 30);
ages.put("Charlie", 35);

// Obtener valor por clave
int aliceAge = ages.get("Alice");

// Comprobar si la clave existe
if (ages.containsKey("Bob")) {
    System.out.println("Bob's age: " + ages.get("Bob"));
}
```

## Manejo de Excepciones

### Bloques Try-Catch

Manejar excepciones para evitar que el programa se bloquee.

```java
public class ExceptionExample {
    public static void main(String[] args) {
        try {
            int result = 10 / 0; // Esto lanzará ArithmeticException
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

### Múltiples Bloques Catch

Manejar diferentes tipos de excepciones por separado.

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

### Lanzamiento de Excepciones Personalizadas

Crear y lanzar tus propias excepciones.

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

### Tipos de Excepciones Comunes

Excepciones frecuentemente encontradas en programas Java.

```java
// NullPointerException
String str = null;
// str.length(); // Lanza NullPointerException

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
// int val = arr[5]; // Lanza ArrayIndexOutOfBoundsException

// NumberFormatException
// int num = Integer.parseInt("abc"); // Lanza NumberFormatException

// FileNotFoundException (al trabajar con archivos)
// IOException (operaciones I/O generales)
```

## Operaciones de Entrada/Salida

### Entrada de Consola: Clase Scanner

Leer la entrada desde el teclado usando Scanner.

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

### Salida de Consola: System.out

Mostrar la salida en la consola en varios formatos.

```java
public class OutputExample {
    public static void main(String[] args) {
        // Salida básica
        System.out.println("Hello, World!");
        System.out.print("No newline");
        System.out.print(" continues here\n");

        // Salida formateada
        String name = "Java";
        int version = 17;
        System.out.printf("Welcome to %s %d!%n", name, version);

        // Salida de variables
        int x = 10, y = 20;
        System.out.println("x = " + x + ", y = " + y);
        System.out.println("Sum = " + (x + y));
    }
}
```

### Lectura de Archivos: BufferedReader

Leer archivos de texto línea por línea de manera eficiente.

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

### Escritura de Archivos: PrintWriter

Escribir datos de texto en archivos con manejo adecuado de excepciones.

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

## Entorno de Desarrollo Java

### Instalación de JDK

JDK (Java Development Kit) = JRE + Herramientas de Desarrollo. Requerido para desarrollar aplicaciones Java.

```bash
# Descargar JDK desde Oracle u OpenJDK
# Instalar JDK en su sistema
# Establecer la variable de entorno JAVA_HOME
export JAVA_HOME=/path/to/jdk
export PATH=$JAVA_HOME/bin:$PATH

# Verificar instalación
java -version
javac -version
```

### Compilar y Ejecutar Programas Java

Usar `javac` para compilar código fuente Java y `java` para ejecutar el programa compilado.

```bash
# Compilar archivo fuente Java
javac MyProgram.java

# Ejecutar programa Java compilado
java MyProgram

# Compilar con classpath
javac -cp .:mylib.jar MyProgram.java

# Ejecutar con classpath
java -cp .:mylib.jar MyProgram
```

### Configuración de IDE y Desarrollo

Entornos de Desarrollo Integrados populares para el desarrollo en Java.

```bash
# IDEs populares para Java:
# - IntelliJ IDEA (JetBrains)
# - Eclipse IDE
# - Visual Studio Code con extensiones de Java
# - NetBeans

# Compilación desde la línea de comandos
javac -d bin src/*.java
java -cp bin MainClass

# Creación de archivo JAR
jar cf myapp.jar -C bin .
```

## Mejores Prácticas y Patrones Comunes

### Convenciones de Nomenclatura

Sigue los estándares de nomenclatura de Java para una mejor legibilidad del código.

```java
// Clases: PascalCase
public class StudentManager { }
public class BankAccount { }

// Métodos y variables: camelCase
int studentAge;
String firstName;
public void calculateGrade() { }
public boolean isValidEmail() { }

// Constantes: UPPER_CASE
public static final int MAX_SIZE = 100;
public static final String DEFAULT_NAME = "Unknown";

// Paquetes: minúsculas
package com.company.project;
package utils.database;
package com.example.myapp;
```

### Organización del Código

Estructurar tus programas Java para su mantenibilidad.

```java
import java.util.ArrayList;
import java.util.Scanner;

/**
 * Esta clase demuestra una buena organización del código Java
 * @author Your Name
 * @version 1.0
 */
public class WellOrganizedClass {
    // Constantes primero
    private static final int MAX_ATTEMPTS = 3;

    // Variables de instancia
    private String name;
    private int value;

    // Constructor
    public WellOrganizedClass(String name) {
        this.name = name;
        this.value = 0;
    }

    // Métodos públicos
    public void doSomething() {
        // Implementación
    }

    // Métodos de ayuda privados
    private boolean isValid() {
        return value > 0;
    }
}
```

### Prevención de Errores

Prácticas comunes para evitar errores y mejorar la calidad del código.

```java
public class BestPractices {
    public void safeDivision(int a, int b) {
        // Comprobar división por cero
        if (b == 0) {
            throw new IllegalArgumentException("Cannot divide by zero");
        }
        int result = a / b;
        System.out.println("Result: " + result);
    }

    public void safeStringOperations(String input) {
        // Comprobación de nulos antes de usar cadenas
        if (input != null && !input.isEmpty()) {
            System.out.println("Length: " + input.length());
            System.out.println("Uppercase: " + input.toUpperCase());
        } else {
            System.out.println("Invalid input string");
        }
    }

    public void safeArrayAccess(int[] array, int index) {
        // Comprobación de límites
        if (array != null && index >= 0 && index < array.length) {
            System.out.println("Value: " + array[index]);
        } else {
            System.out.println("Invalid array access");
        }
    }
}
```

### Gestión de Recursos

Manejar correctamente los recursos para prevenir fugas de memoria.

```java
import java.io.*;

public class ResourceManagement {
    // Try-with-resources (limpieza automática)
    public void readFileProper(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine();
            System.out.println(line);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        // El Reader se cierra automáticamente
    }

    // Limpieza manual de recursos (no recomendado)
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

## Enlaces Relevantes

- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/cpp">Hoja de Trucos de C++</router-link>
- <router-link to="/golang">Hoja de Trucos de Go</router-link>
- <router-link to="/web-development">Hoja de Trucos de Desarrollo Web</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>
- <router-link to="/kubernetes">Hoja de Trucos de Kubernetes</router-link>

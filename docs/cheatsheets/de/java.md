---
title: 'Java Spickzettel'
description: 'Lernen Sie Java mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/java-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Java Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/java">Java mit praktischen Übungen lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie die Java-Programmierung durch praktische Übungen und reale Szenarien. LabEx bietet umfassende Java-Kurse, die grundlegende Syntax, objektorientierte Programmierung, Collections, Ausnahmebehandlung und Best Practices abdecken. Meistern Sie die Grundlagen der Java-Entwicklung und erstellen Sie robuste Anwendungen.
</base-disclaimer-content>
</base-disclaimer>

## Programmstruktur & Grundlegende Syntax

### Hallo Welt: Einfaches Programm

Das einfachste Java-Programm, das "Hello, World!" auf dem Bildschirm ausgibt.

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### Klassendeklaration: `public class`

Eine Klasse ist eine Vorlage/Blaupause, die das Verhalten/den Zustand beschreibt, den Objekte unterstützen.

```java
public class MyClass {
    // Klasseninhalt kommt hierher
    int myVariable;

    public void myMethod() {
        System.out.println("Hello from method!");
    }
}
```

### Main-Methode: Programm-Einstiegspunkt

Die Main-Methode ist der Beginn der Java-Programmausführung.

```java
public static void main(String[] args) {
    // Programmcode hier
    System.out.println("Program starts here");
}
```

### Kommentare: Code-Dokumentation

Verwenden Sie einzeilige (`//`) und mehrzeilige (`/* */`) Kommentare, um Code verständlicher und wartbarer zu machen.

```java
// Einzeiliger Kommentar
System.out.println("Hello");

/* Mehrzeiliger Kommentar
   Kann sich über mehrere Zeilen erstrecken
   Wird für detaillierte Erklärungen verwendet */
```

### Anweisungen & Semikolons

Jede Anweisung in Java muss mit einem Semikolon enden.

```java
int number = 10;
String name = "Java";
System.out.println(name);
```

### Codeblöcke: Geschweifte Klammern

Codeblöcke werden in geschweifte Klammern `{}` eingeschlossen und markieren den Anfang und das Ende von Codeabschnitten.

```java
public class Example {
    public void method() {
        if (true) {
            System.out.println("Inside if block");
        }
    }
}
```

## Datentypen & Variablen

### Primitive Datentypen

Grundlegende, in die Java-Sprache eingebaute Datentypen.

```java
// Integer-Typen
byte smallNum = 127;        // -128 bis 127
short shortNum = 32000;     // -32.768 bis 32.767
int number = 100;           // -2^31 bis 2^31-1
long bigNum = 10000L;       // -2^63 bis 2^63-1

// Gleitkommatypen
float decimal = 3.14f;      // Einfache Genauigkeit
double precision = 3.14159; // Doppelte Genauigkeit

// Andere Typen
char letter = 'A';          // Einzelnes Zeichen
boolean flag = true;        // true oder false
```

### Variablendeklaration & Initialisierung

Erstellen und Zuweisen von Werten zu Variablen.

```java
// Nur Deklaration
int age;
String name;

// Deklaration mit Initialisierung
int age = 25;
String name = "John";

// Mehrere Deklarationen
int x = 10, y = 20, z = 30;

// Final-Variablen (Konstanten)
final double PI = 3.14159;
```

### String-Operationen

Strings stellen Zeichenfolgen dar und sind unveränderlich (immutable), d.h. ihr Wert kann nach der Erstellung nicht mehr geändert werden.

```java
String greeting = "Hello";
String name = "World";

// String-Verkettung
String message = greeting + " " + name;
System.out.println(message); // "Hello World"

// String-Methoden
int length = message.length();
boolean isEmpty = message.isEmpty();
String uppercase = message.toUpperCase();
```

## Kontrollflussanweisungen

### Bedingte Anweisungen: `if`, `else if`, `else`

Führen unterschiedliche Codeblöcke basierend auf Bedingungen aus.

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

### Switch-Anweisung

Mehrfache Verzweigung basierend auf Variablenwerten.

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

### For-Schleife: Gezählte Wiederholung

Code wiederholen, eine bestimmte Anzahl von Malen.

```java
// Standard for-Schleife
for (int i = 0; i < 5; i++) {
    System.out.println("Count: " + i);
}

// Erweiterte for-Schleife (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println("Number: " + num);
}
```

### While- & Do-While-Schleifen

Code wiederholen, solange eine Bedingung wahr ist.

```java
// While-Schleife
int i = 0;
while (i < 3) {
    System.out.println("While: " + i);
    i++;
}

// Do-while-Schleife (wird mindestens einmal ausgeführt)
int j = 0;
do {
    System.out.println("Do-while: " + j);
    j++;
} while (j < 3);
```

## Objektorientierte Programmierung

### Klassen & Objekte

Objekte haben Zustände und Verhaltensweisen. Ein Objekt ist eine Instanz einer Klasse.

```java
public class Car {
    // Instanzvariablen (Zustand)
    String color;
    String model;
    int year;

    // Konstruktor
    public Car(String color, String model, int year) {
        this.color = color;
        this.model = model;
        this.year = year;
    }

    // Methode (Verhalten)
    public void start() {
        System.out.println("Car is starting...");
    }
}

// Objekte erstellen
Car myCar = new Car("Red", "Toyota", 2022);
myCar.start();
```

### Konstruktoren

Spezielle Methoden, die zur Initialisierung von Objekten verwendet werden.

```java
public class Person {
    String name;
    int age;

    // Standardkonstruktor
    public Person() {
        name = "Unknown";
        age = 0;
    }

    // Parametrisierter Konstruktor
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
```

### Vererbung: `extends`

Vererbung ermöglicht Code-Wiederverwendung und schafft hierarchische Beziehungen zwischen Klassen.

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
myDog.eat();  // Geerbte Methode
myDog.bark(); // Eigene Methode
```

### Zugriffsmodifikatoren

Modifikatoren steuern den Zugriff auf Klassen, Methoden und Variablen.

```java
public class Example {
    public int publicVar;      // Überall zugänglich
    private int privateVar;    // Nur innerhalb dieser Klasse
    protected int protectedVar; // Innerhalb des Pakets + Unterklassen
    int defaultVar;            // Nur innerhalb des Pakets

    private void privateMethod() {
        // Nur innerhalb dieser Klasse zugänglich
    }
}
```

## Methoden & Funktionen

### Methodendeklaration

Eine Methode ist im Grunde ein Verhalten, in dem Logik geschrieben, Daten manipuliert und Aktionen ausgeführt werden.

```java
public class Calculator {
    // Methode mit Parametern und Rückgabewert
    public int add(int a, int b) {
        return a + b;
    }

    // Methode ohne Rückgabewert
    public void printSum(int a, int b) {
        int result = add(a, b);
        System.out.println("Sum: " + result);
    }

    // Statische Methode (gehört zur Klasse)
    public static int multiply(int a, int b) {
        return a * b;
    }
}
```

### Methodenüberladung (Method Overloading)

Mehrere Methoden mit gleichem Namen, aber unterschiedlichen Parametern.

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

### Methodenparameter & Rückgabetypen

Daten an Methoden übergeben und Ergebnisse zurückgeben.

```java
public class StringHelper {
    // Methode mit String-Parameter und Rückgabe
    public String formatName(String firstName, String lastName) {
        return firstName + " " + lastName;
    }

    // Methode mit Array-Parameter
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

### Rekursive Methoden

Methoden, die sich selbst aufrufen, um Probleme zu lösen.

```java
public class RecursiveExamples {
    // Fakultät berechnen
    public int factorial(int n) {
        if (n <= 1) {
            return 1;
        }
        return n * factorial(n - 1);
    }

    // Fibonacci-Folge
    public int fibonacci(int n) {
        if (n <= 1) {
            return n;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

## Arrays & Collections

### Array-Deklaration & Initialisierung

Arrays verschiedener Typen erstellen und initialisieren.

```java
// Array-Deklaration und Initialisierung
int[] numbers = {1, 2, 3, 4, 5};
String[] names = {"Alice", "Bob", "Charlie"};

// Array mit angegebener Größe
int[] scores = new int[10];
scores[0] = 95;
scores[1] = 87;

// Array-Länge abrufen
int length = numbers.length;
System.out.println("Length: " + length);

// Durch Array iterieren
for (int i = 0; i < numbers.length; i++) {
    System.out.println("Element " + i + ": " + numbers[i]);
}
```

### Mehrdimensionale Arrays

Arrays von Arrays für matrixähnliche Datenstrukturen.

```java
// 2D-Array-Deklaration
int[][] matrix = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

// Elemente abrufen
int element = matrix[1][2]; // Holt 6

// Durch 2D-Array iterieren
for (int i = 0; i < matrix.length; i++) {
    for (int j = 0; j < matrix[i].length; j++) {
        System.out.print(matrix[i][j] + " ");
    }
    System.out.println();
}
```

### ArrayList: Dynamische Arrays

Größenveränderbare Arrays, die dynamisch wachsen und schrumpfen können.

```java
import java.util.ArrayList;

// ArrayList erstellen
ArrayList<String> list = new ArrayList<>();

// Elemente hinzufügen
list.add("Apple");
list.add("Banana");
list.add("Orange");

// Element abrufen
String fruit = list.get(0); // Holt "Apple"

// Element entfernen
list.remove(1); // Entfernt "Banana"

// Größe und Iteration
System.out.println("Size: " + list.size());
for (String item : list) {
    System.out.println(item);
}
```

### HashMap: Schlüssel-Wert-Paare

Daten als Schlüssel-Wert-Paare speichern für schnellen Abruf.

```java
import java.util.HashMap;

// HashMap erstellen
HashMap<String, Integer> ages = new HashMap<>();

// Schlüssel-Wert-Paare hinzufügen
ages.put("Alice", 25);
ages.put("Bob", 30);
ages.put("Charlie", 35);

// Wert anhand des Schlüssels abrufen
int aliceAge = ages.get("Alice");

// Prüfen, ob Schlüssel existiert
if (ages.containsKey("Bob")) {
    System.out.println("Bob's age: " + ages.get("Bob"));
}
```

## Ausnahmebehandlung (Exception Handling)

### Try-Catch-Blöcke

Ausnahmen behandeln, um Programmabstürze zu verhindern.

```java
public class ExceptionExample {
    public static void main(String[] args) {
        try {
            int result = 10 / 0; // Löst ArithmeticException aus
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

### Mehrere Catch-Blöcke

Verschiedene Arten von Ausnahmen separat behandeln.

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

### Auslösen benutzerdefinierter Ausnahmen (Throwing Custom Exceptions)

Eigene Ausnahmen erstellen und auslösen.

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

### Häufige Ausnahmetypen

Häufig auftretende Ausnahmen in Java-Programmen.

```java
// NullPointerException
String str = null;
// str.length(); // Löst NullPointerException aus

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
// int val = arr[5]; // Löst ArrayIndexOutOfBoundsException aus

// NumberFormatException
// int num = Integer.parseInt("abc"); // Löst NumberFormatException aus

// FileNotFoundException (bei der Arbeit mit Dateien)
// IOException (allgemeine I/O-Operationen)
```

## Eingabe-/Ausgabeoperationen (Input/Output)

### Konsoleneingabe: Scanner-Klasse

Eingaben von der Tastatur mithilfe von Scanner lesen.

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

### Konsolenausgabe: System.out

Ausgabe in verschiedenen Formaten auf der Konsole anzeigen.

```java
public class OutputExample {
    public static void main(String[] args) {
        // Grundlegende Ausgabe
        System.out.println("Hello, World!");
        System.out.print("No newline");
        System.out.print(" continues here\n");

        // Formatierte Ausgabe
        String name = "Java";
        int version = 17;
        System.out.printf("Welcome to %s %d!%n", name, version);

        // Variablen ausgeben
        int x = 10, y = 20;
        System.out.println("x = " + x + ", y = " + y);
        System.out.println("Sum = " + (x + y));
    }
}
```

### Dateilesen: BufferedReader

Textdateien zeilenweise effizient lesen.

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

### Dateischreiben: PrintWriter

Textdaten mit ordnungsgemäßer Ausnahmebehandlung in Dateien schreiben.

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

## Java Entwicklungsumgebung

### JDK-Installation

JDK (Java Development Kit) = JRE + Entwicklungswerkzeuge. Erforderlich für die Entwicklung von Java-Anwendungen.

```bash
# JDK von Oracle oder OpenJDK herunterladen
# JDK auf Ihrem System installieren
# JAVA_HOME Umgebungsvariable setzen
export JAVA_HOME=/path/to/jdk
export PATH=$JAVA_HOME/bin:$PATH

# Installation überprüfen
java -version
javac -version
```

### Java-Programme kompilieren & ausführen

Verwenden Sie `javac`, um Java-Quelldateien zu kompilieren, und `java`, um das kompilierte Programm auszuführen.

```bash
# Java-Quelldatei kompilieren
javac MyProgram.java

# Kompiliertes Java-Programm ausführen
java MyProgram

# Kompilieren mit Classpath
javac -cp .:mylib.jar MyProgram.java

# Ausführen mit Classpath
java -cp .:mylib.jar MyProgram
```

### IDE-Setup & Entwicklung

Beliebte Integrierte Entwicklungsumgebungen (IDEs) für die Java-Entwicklung.

```bash
# Beliebte Java-IDEs:
# - IntelliJ IDEA (JetBrains)
# - Eclipse IDE
# - Visual Studio Code mit Java-Erweiterungen
# - NetBeans

# Kompilierung über die Kommandozeile
javac -d bin src/*.java
java -cp bin MainClass

# JAR-Datei erstellen
jar cf myapp.jar -C bin .
```

## Best Practices & Häufige Muster

### Benennungskonventionen

Java-Namensstandards für bessere Lesbarkeit des Codes befolgen.

```java
// Klassen: PascalCase
public class StudentManager { }
public class BankAccount { }

// Methoden und Variablen: camelCase
int studentAge;
String firstName;
public void calculateGrade() { }
public boolean isValidEmail() { }

// Konstanten: UPPER_CASE
public static final int MAX_SIZE = 100;
public static final String DEFAULT_NAME = "Unknown";

// Pakete: kleinbuchstaben
package com.company.project;
package utils.database;
package com.example.myapp;
```

### Code-Organisation

Java-Programme für Wartbarkeit strukturieren.

```java
import java.util.ArrayList;
import java.util.Scanner;

/**
 * Diese Klasse demonstriert gute Java-Code-Organisation
 * @author Your Name
 * @version 1.0
 */
public class WellOrganizedClass {
    // Konstanten zuerst
    private static final int MAX_ATTEMPTS = 3;

    // Instanzvariablen
    private String name;
    private int value;

    // Konstruktor
    public WellOrganizedClass(String name) {
        this.name = name;
        this.value = 0;
    }

    // Öffentliche Methoden
    public void doSomething() {
        // Implementierung
    }

    // Private Hilfsmethoden
    private boolean isValid() {
        return value > 0;
    }
}
```

### Fehlervermeidung

Gängige Praktiken, um Fehler zu vermeiden und die Codequalität zu verbessern.

```java
public class BestPractices {
    public void safeDivision(int a, int b) {
        // Prüfung auf Division durch Null
        if (b == 0) {
            throw new IllegalArgumentException("Cannot divide by zero");
        }
        int result = a / b;
        System.out.println("Result: " + result);
    }

    public void safeStringOperations(String input) {
        // Null-Prüfung vor der Verwendung von Strings
        if (input != null && !input.isEmpty()) {
            System.out.println("Length: " + input.length());
            System.out.println("Uppercase: " + input.toUpperCase());
        } else {
            System.out.println("Invalid input string");
        }
    }

    public void safeArrayAccess(int[] array, int index) {
        // Bereichsprüfung
        if (array != null && index >= 0 && index < array.length) {
            System.out.println("Value: " + array[index]);
        } else {
            System.out.println("Invalid array access");
        }
    }
}
```

### Ressourcenverwaltung

Ressourcen ordnungsgemäß verwalten, um Speicherlecks zu verhindern.

```java
import java.io.*;

public class ResourceManagement {
    // Try-with-resources (automatische Bereinigung)
    public void readFileProper(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine();
            System.out.println(line);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        // Reader wird automatisch geschlossen
    }

    // Manuelle Ressourcenbereinigung (nicht empfohlen)
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

## Relevante Links

- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/cpp">C++ Spickzettel</router-link>
- <router-link to="/golang">Go Spickzettel</router-link>
- <router-link to="/web-development">Webentwicklung Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>

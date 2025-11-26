---
title: 'Fiche de Référence Java'
description: 'Apprenez Java avec notre aide-mémoire complet couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/java-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Java Aide-mémoire
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/java">Apprenez Java avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la programmation Java grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours Java complets couvrant la syntaxe essentielle, la programmation orientée objet, les collections, la gestion des exceptions et les meilleures pratiques. Maîtrisez les fondamentaux du développement Java et construisez des applications robustes.
</base-disclaimer-content>
</base-disclaimer>

## Structure du Programme et Syntaxe de Base

### Hello World : Programme de Base

Le programme Java le plus simple qui affiche "Hello, World!" à l'écran.

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### Déclaration de Classe : `public class`

Une classe est un modèle/plan qui décrit le comportement/l'état que les objets supportent.

```java
public class MyClass {
    // Le contenu de la classe va ici
    int myVariable;

    public void myMethod() {
        System.out.println("Hello from method!");
    }
}
```

### Méthode Main : Point d'Entrée du Programme

La méthode main est l'endroit où l'exécution du programme Java commence.

```java
public static void main(String[] args) {
    // Code du programme ici
    System.out.println("Program starts here");
}
```

### Commentaires : Documentation du Code

Utilisez des commentaires sur une seule ligne (`//`) et sur plusieurs lignes (`/* */`) pour rendre le code plus compréhensible et maintenable.

```java
// Commentaire sur une seule ligne
System.out.println("Hello");

/* Commentaire sur plusieurs lignes
   Peut s'étendre sur plusieurs lignes
   Utilisé pour des explications détaillées */
```

### Instructions et Points-Virgules

Chaque instruction en Java doit se terminer par un point-virgule.

```java
int number = 10;
String name = "Java";
System.out.println(name);
```

### Blocs de Code : Accolades

Les blocs de code sont entourés d'accolades `{}`, marquant le début et la fin des sections de code.

```java
public class Example {
    public void method() {
        if (true) {
            System.out.println("Inside if block");
        }
    }
}
```

## Types de Données et Variables

### Types de Données Primitifs

Types de données de base intégrés au langage Java.

```java
// Types entiers
byte smallNum = 127;        // -128 à 127
short shortNum = 32000;     // -32,768 à 32,767
int number = 100;           // -2^31 à 2^31-1
long bigNum = 10000L;       // -2^63 à 2^63-1

// Types à virgule flottante
float decimal = 3.14f;      // Précision simple
double precision = 3.14159; // Double précision

// Autres types
char letter = 'A';          // Caractère unique
boolean flag = true;        // vrai ou faux
```

### Déclaration et Initialisation de Variables

Créer et assigner des valeurs aux variables.

```java
// Déclaration seule
int age;
String name;

// Déclaration avec initialisation
int age = 25;
String name = "John";

// Déclarations multiples
int x = 10, y = 20, z = 30;

// Variables finales (constantes)
final double PI = 3.14159;
```

### Opérations sur les Chaînes de Caractères (String)

Les chaînes représentent des séquences de caractères et sont immuables, ce qui signifie qu'une fois créées, leurs valeurs ne peuvent pas être modifiées.

```java
String greeting = "Hello";
String name = "World";

// Concaténation de chaînes
String message = greeting + " " + name;
System.out.println(message); // "Hello World"

// Méthodes de chaîne
int length = message.length();
boolean isEmpty = message.isEmpty();
String uppercase = message.toUpperCase();
```

## Instructions de Flux de Contrôle

### Instructions Conditionnelles : `if`, `else if`, `else`

Exécutent différents blocs de code en fonction des conditions.

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

### Instruction Switch

Branchement multi-voies basé sur les valeurs des variables.

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

### Boucle For : Répétition Comptée

Répéter du code un nombre spécifique de fois.

```java
// Boucle for standard
for (int i = 0; i < 5; i++) {
    System.out.println("Count: " + i);
}

// Boucle for améliorée (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println("Number: " + num);
}
```

### Boucles While et Do-While

Répéter du code tant qu'une condition est vraie.

```java
// Boucle While
int i = 0;
while (i < 3) {
    System.out.println("While: " + i);
    i++;
}

// Boucle Do-while (s'exécute au moins une fois)
int j = 0;
do {
    System.out.println("Do-while: " + j);
    j++;
} while (j < 3);
```

## Programmation Orientée Objet

### Classes et Objets

Les objets ont des états et des comportements. Un objet est une instance d'une classe.

```java
public class Car {
    // Variables d'instance (état)
    String color;
    String model;
    int year;

    // Constructeur
    public Car(String color, String model, int year) {
        this.color = color;
        this.model = model;
        this.year = year;
    }

    // Méthode (comportement)
    public void start() {
        System.out.println("Car is starting...");
    }
}

// Création d'objets
Car myCar = new Car("Red", "Toyota", 2022);
myCar.start();
```

### Constructeurs

Méthodes spéciales utilisées pour initialiser des objets.

```java
public class Person {
    String name;
    int age;

    // Constructeur par défaut
    public Person() {
        name = "Unknown";
        age = 0;
    }

    // Constructeur paramétré
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
```

### Héritage : `extends`

L'héritage permet la réutilisation du code et crée des relations hiérarchiques entre les classes.

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
myDog.eat();  // Méthode héritée
myDog.bark(); // Méthode propre
```

### Modificateurs d'Accès

Les modificateurs contrôlent l'accès aux classes, méthodes et variables.

```java
public class Example {
    public int publicVar;      // Accessible partout
    private int privateVar;    // Seulement dans cette classe
    protected int protectedVar; // Dans le package + sous-classes
    int defaultVar;            // Seulement dans le package

    private void privateMethod() {
        // Seulement accessible dans cette classe
    }
}
```

## Méthodes et Fonctions

### Déclaration de Méthode

Une méthode est essentiellement un comportement où la logique est écrite, les données sont manipulées et les actions sont exécutées.

```java
public class Calculator {
    // Méthode avec paramètres et valeur de retour
    public int add(int a, int b) {
        return a + b;
    }

    // Méthode sans valeur de retour
    public void printSum(int a, int b) {
        int result = add(a, b);
        System.out.println("Sum: " + result);
    }

    // Méthode statique (appartient à la classe)
    public static int multiply(int a, int b) {
        return a * b;
    }
}
```

### Surcharge de Méthode (Method Overloading)

Plusieurs méthodes avec le même nom mais des paramètres différents.

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

### Paramètres de Méthode et Types de Retour

Passer des données aux méthodes et retourner des résultats.

```java
public class StringHelper {
    // Méthode avec paramètre String et retour
    public String formatName(String firstName, String lastName) {
        return firstName + " " + lastName;
    }

    // Méthode avec paramètre tableau
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

### Méthodes Récursives

Méthodes qui s'appellent elles-mêmes pour résoudre des problèmes.

```java
public class RecursiveExamples {
    // Calculer la factorielle
    public int factorial(int n) {
        if (n <= 1) {
            return 1;
        }
        return n * factorial(n - 1);
    }

    // Suite de Fibonacci
    public int fibonacci(int n) {
        if (n <= 1) {
            return n;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

## Tableaux et Collections

### Déclaration et Initialisation de Tableau

Créer et initialiser des tableaux de différents types.

```java
// Déclaration et initialisation de tableau
int[] numbers = {1, 2, 3, 4, 5};
String[] names = {"Alice", "Bob", "Charlie"};

// Tableau avec taille spécifiée
int[] scores = new int[10];
scores[0] = 95;
scores[1] = 87;

// Obtenir la longueur du tableau
int length = numbers.length;
System.out.println("Length: " + length);

// Parcourir le tableau
for (int i = 0; i < numbers.length; i++) {
    System.out.println("Element " + i + ": " + numbers[i]);
}
```

### Tableaux Multi-dimensionnels

Tableaux de tableaux pour des structures de données de type matrice.

```java
// Déclaration de tableau 2D
int[][] matrix = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

// Accéder aux éléments
int element = matrix[1][2]; // Obtient 6

// Parcourir le tableau 2D
for (int i = 0; i < matrix.length; i++) {
    for (int j = 0; j < matrix[i].length; j++) {
        System.out.print(matrix[i][j] + " ");
    }
    System.out.println();
}
```

### ArrayList : Tableaux Dynamiques

Tableaux redimensionnables qui peuvent croître et rétrécir dynamiquement.

```java
import java.util.ArrayList;

// Créer ArrayList
ArrayList<String> list = new ArrayList<>();

// Ajouter des éléments
list.add("Apple");
list.add("Banana");
list.add("Orange");

// Obtenir un élément
String fruit = list.get(0); // Obtient "Apple"

// Supprimer un élément
list.remove(1); // Supprime "Banana"

// Taille et itération
System.out.println("Size: " + list.size());
for (String item : list) {
    System.out.println(item);
}
```

### HashMap : Paires Clé-Valeur

Stocker des données sous forme de paires clé-valeur pour une recherche rapide.

```java
import java.util.HashMap;

// Créer HashMap
HashMap<String, Integer> ages = new HashMap<>();

// Ajouter des paires clé-valeur
ages.put("Alice", 25);
ages.put("Bob", 30);
ages.put("Charlie", 35);

// Obtenir la valeur par clé
int aliceAge = ages.get("Alice");

// Vérifier si la clé existe
if (ages.containsKey("Bob")) {
    System.out.println("Bob's age: " + ages.get("Bob"));
}
```

## Gestion des Exceptions

### Blocs Try-Catch

Gérer les exceptions pour éviter les plantages du programme.

```java
public class ExceptionExample {
    public static void main(String[] args) {
        try {
            int result = 10 / 0; // Ceci lancera ArithmeticException
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

### Blocs Catch Multiples

Gérer différents types d'exceptions séparément.

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

### Lancer des Exceptions Personnalisées

Créer et lancer vos propres exceptions.

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

### Types d'Exceptions Courantes

Exceptions fréquemment rencontrées dans les programmes Java.

```java
// NullPointerException
String str = null;
// str.length(); // Lance NullPointerException

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
// int val = arr[5]; // Lance ArrayIndexOutOfBoundsException

// NumberFormatException
// int num = Integer.parseInt("abc"); // Lance NumberFormatException

// FileNotFoundException (lors du travail avec des fichiers)
// IOException (opérations d'E/S générales)
```

## Opérations d'Entrée/Sortie

### Entrée Console : Classe Scanner

Lire l'entrée depuis le clavier en utilisant Scanner.

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

### Sortie Console : System.out

Afficher la sortie sur la console dans divers formats.

```java
public class OutputExample {
    public static void main(String[] args) {
        // Sortie de base
        System.out.println("Hello, World!");
        System.out.print("No newline");
        System.out.print(" continues here\n");

        // Sortie formatée
        String name = "Java";
        int version = 17;
        System.out.printf("Welcome to %s %d!%n", name, version);

        // Afficher les variables
        int x = 10, y = 20;
        System.out.println("x = " + x + ", y = " + y);
        System.out.println("Sum = " + (x + y));
    }
}
```

### Lecture de Fichier : BufferedReader

Lire les fichiers texte ligne par ligne efficacement.

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

### Écriture de Fichier : PrintWriter

Écrire des données textuelles dans des fichiers avec une gestion appropriée des exceptions.

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

## Environnement de Développement Java

### Installation du JDK

JDK (Java Development Kit) = JRE + Outils de Développement. Requis pour développer des applications Java.

```bash
# Télécharger JDK depuis Oracle ou OpenJDK
# Installer le JDK sur votre système
# Définir la variable d'environnement JAVA_HOME
export JAVA_HOME=/path/to/jdk
export PATH=$JAVA_HOME/bin:$PATH

# Vérifier l'installation
java -version
javac -version
```

### Compiler et Exécuter des Programmes Java

Utilisez `javac` pour compiler le code source Java et `java` pour exécuter le programme compilé.

```bash
# Compiler le fichier source Java
javac MyProgram.java

# Exécuter le programme Java compilé
java MyProgram

# Compiler avec classpath
javac -cp .:mylib.jar MyProgram.java

# Exécuter avec classpath
java -cp .:mylib.jar MyProgram
```

### Configuration et Développement d'IDE

Environnements de Développement Intégrés populaires pour le développement Java.

```bash
# IDE Java populaires :
# - IntelliJ IDEA (JetBrains)
# - Eclipse IDE
# - Visual Studio Code avec extensions Java
# - NetBeans

# Compilation en ligne de commande
javac -d bin src/*.java
java -cp bin MainClass

# Création de fichier JAR
jar cf myapp.jar -C bin .
```

## Bonnes Pratiques et Modèles Courants

### Conventions de Nommage

Suivez les normes de nommage Java pour une meilleure lisibilité du code.

```java
// Classes : PascalCase
public class StudentManager { }
public class BankAccount { }

// Méthodes et variables : camelCase
int studentAge;
String firstName;
public void calculateGrade() { }
public boolean isValidEmail() { }

// Constantes : UPPER_CASE
public static final int MAX_SIZE = 100;
public static final String DEFAULT_NAME = "Unknown";

// Packages : minuscules
package com.company.project;
package utils.database;
package com.example.myapp;
```

### Organisation du Code

Structurez vos programmes Java pour la maintenabilité.

```java
import java.util.ArrayList;
import java.util.Scanner;

/**
 * Cette classe démontre une bonne organisation du code Java
 * @author Your Name
 * @version 1.0
 */
public class WellOrganizedClass {
    // Constantes d'abord
    private static final int MAX_ATTEMPTS = 3;

    // Variables d'instance
    private String name;
    private int value;

    // Constructeur
    public WellOrganizedClass(String name) {
        this.name = name;
        this.value = 0;
    }

    // Méthodes publiques
    public void doSomething() {
        // Implémentation
    }

    // Méthodes d'aide privées
    private boolean isValid() {
        return value > 0;
    }
}
```

### Prévention des Erreurs

Pratiques courantes pour éviter les bugs et améliorer la qualité du code.

```java
public class BestPractices {
    public void safeDivision(int a, int b) {
        // Vérifier la division par zéro
        if (b == 0) {
            throw new IllegalArgumentException("Cannot divide by zero");
        }
        int result = a / b;
        System.out.println("Result: " + result);
    }

    public void safeStringOperations(String input) {
        // Vérification Null avant d'utiliser les chaînes
        if (input != null && !input.isEmpty()) {
            System.out.println("Length: " + input.length());
            System.out.println("Uppercase: " + input.toUpperCase());
        } else {
            System.out.println("Invalid input string");
        }
    }

    public void safeArrayAccess(int[] array, int index) {
        // Vérification des limites
        if (array != null && index >= 0 && index < array.length) {
            System.out.println("Value: " + array[index]);
        } else {
            System.out.println("Invalid array access");
        }
    }
}
```

### Gestion des Ressources

Gérer correctement les ressources pour éviter les fuites de mémoire.

```java
import java.io.*;

public class ResourceManagement {
    // Try-with-resources (nettoyage automatique)
    public void readFileProper(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine();
            System.out.println(line);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        // Le Reader est automatiquement fermé
    }

    // Nettoyage manuel des ressources (non recommandé)
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

## Liens Pertinents

- <router-link to="/python">Aide-mémoire Python</router-link>
- <router-link to="/javascript">Aide-mémoire JavaScript</router-link>
- <router-link to="/cpp">Aide-mémoire C++</router-link>
- <router-link to="/golang">Aide-mémoire Go</router-link>
- <router-link to="/web-development">Aide-mémoire Développement Web</router-link>
- <router-link to="/devops">Aide-mémoire DevOps</router-link>
- <router-link to="/docker">Aide-mémoire Docker</router-link>
- <router-link to="/kubernetes">Aide-mémoire Kubernetes</router-link>

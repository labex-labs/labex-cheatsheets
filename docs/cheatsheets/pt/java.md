---
title: 'Cheatsheet Java | LabEx'
description: 'Aprenda programação Java com este cheatsheet abrangente. Referência rápida para sintaxe Java, OOP, coleções, streams, framework Spring e essenciais de desenvolvimento empresarial.'
pdfUrl: '/cheatsheets/pdf/java-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Java Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/java">Aprenda Java com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda programação Java através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Java que cobrem sintaxe essencial, programação orientada a objetos, coleções, tratamento de exceções e melhores práticas. Domine os fundamentos do desenvolvimento Java e construa aplicações robustas.
</base-disclaimer-content>
</base-disclaimer>

## Estrutura do Programa e Sintaxe Básica

### Olá Mundo: Programa Básico

O programa Java mais simples que exibe "Hello, World!" na tela.

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### Declaração de Classe: `public class`

Uma classe é um modelo/planta que descreve o comportamento/estado que os objetos suportam.

```java
public class MyClass {
    // O conteúdo da classe vai aqui
    int myVariable;

    public void myMethod() {
        System.out.println("Hello from method!");
    }
}
```

### Método Main: Ponto de Entrada do Programa

O método main é onde a execução do programa Java começa.

```java
public static void main(String[] args) {
    // Código do programa aqui
    System.out.println("Program starts here");
}
```

<BaseQuiz id="java-main-1" correct="C">
  <template #question>
    Qual é a assinatura correta para o método main em Java?
  </template>
  
  <BaseQuizOption value="A">public void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="B">static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="C" correct>public static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="D">public static int main(String[] args)</BaseQuizOption>
  
  <BaseQuizAnswer>
    O método main deve ser <code>public static void main(String[] args)</code>. <code>public</code> permite que a JVM o acesse, <code>static</code> significa que pertence à classe, <code>void</code> significa que não retorna nada, e <code>String[] args</code> recebe argumentos de linha de comando.
  </BaseQuizAnswer>
</BaseQuiz>

### Comentários: Documentação do Código

Use comentários de linha única (`//`) e de múltiplas linhas (`/* */`) para tornar o código mais compreensível e fácil de manter.

```java
// Comentário de linha única
System.out.println("Hello");

/* Comentário de múltiplas linhas
   Pode abranger várias linhas
   Usado para explicações detalhadas */
```

### Declarações e Ponto e Vírgula

Cada declaração em Java deve terminar com um ponto e vírgula.

```java
int number = 10;
String name = "Java";
System.out.println(name);
```

### Blocos de Código: Chaves

Blocos de código são envolvidos por chaves `{}`, marcando o início e o fim das seções de código.

```java
public class Example {
    public void method() {
        if (true) {
            System.out.println("Inside if block");
        }
    }
}
```

## Tipos de Dados e Variáveis

### Tipos de Dados Primitivos

Tipos de dados básicos incorporados à linguagem Java.

```java
// Tipos inteiros
byte smallNum = 127;        // -128 a 127
short shortNum = 32000;     // -32,768 a 32,767
int number = 100;           // -2^31 a 2^31-1
long bigNum = 10000L;       // -2^63 a 2^63-1

// Tipos de ponto flutuante
float decimal = 3.14f;      // Precisão simples
double precision = 3.14159; // Precisão dupla

// Outros tipos
char letter = 'A';          // Caractere único
boolean flag = true;        // verdadeiro ou falso
```

### Declaração e Inicialização de Variáveis

Criando e atribuindo valores a variáveis.

```java
// Apenas declaração
int age;
String name;

// Declaração com inicialização
int age = 25;
String name = "John";

// Múltiplas declarações
int x = 10, y = 20, z = 30;

// Variáveis finais (constantes)
final double PI = 3.14159;
```

### Operações com String

Strings representam sequências de caracteres e são imutáveis, o que significa que uma vez criados, seus valores não podem ser alterados.

```java
String greeting = "Hello";
String name = "World";

// Concatenação de String
String message = greeting + " " + name;
System.out.println(message); // "Hello World"

// Métodos de String
int length = message.length();
boolean isEmpty = message.isEmpty();
String uppercase = message.toUpperCase();
```

<BaseQuiz id="java-string-1" correct="A">
  <template #question>
    O que significa que as strings Java são imutáveis?
  </template>
  
  <BaseQuizOption value="A" correct>Uma vez criadas, o valor de uma string não pode ser alterado</BaseQuizOption>
  <BaseQuizOption value="B">Strings não podem ser criadas</BaseQuizOption>
  <BaseQuizOption value="C">Strings só podem armazenar números</BaseQuizOption>
  <BaseQuizOption value="D">Strings são excluídas automaticamente</BaseQuizOption>
  
  <BaseQuizAnswer>
    Imutabilidade significa que, uma vez que um objeto String é criado, seu valor não pode ser modificado. Operações como <code>toUpperCase()</code> retornam um novo objeto String em vez de modificar o original.
  </BaseQuizAnswer>
</BaseQuiz>

## Declarações de Fluxo de Controle

### Declarações Condicionais: `if`, `else if`, `else`

Executam diferentes blocos de código com base em condições.

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

### Declaração Switch

Ramificação de múltiplas vias baseada nos valores das variáveis.

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

### Loop For: Repetição Contada

Repete o código um número específico de vezes.

```java
// Loop for padrão
for (int i = 0; i < 5; i++) {
    System.out.println("Count: " + i);
}

// Loop for aprimorado (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println("Number: " + num);
}
```

<BaseQuiz id="java-for-loop-1" correct="C">
  <template #question>
    Para que serve o loop for aprimorado (for-each)?
  </template>
  
  <BaseQuizOption value="A">Iterar com uma variável de contador</BaseQuizOption>
  <BaseQuizOption value="B">Loops infinitos</BaseQuizOption>
  <BaseQuizOption value="C" correct>Iterar por arrays e coleções sem um índice</BaseQuizOption>
  <BaseQuizOption value="D">Apenas loops aninhados</BaseQuizOption>
  
  <BaseQuizAnswer>
    O loop for aprimorado (for-each) simplifica a iteração por arrays e coleções, lidando automaticamente com o índice, tornando o código mais legível e menos propenso a erros.
  </BaseQuizAnswer>
</BaseQuiz>

### Loops While & Do-While

Repete o código enquanto uma condição for verdadeira.

```java
// Loop While
int i = 0;
while (i < 3) {
    System.out.println("While: " + i);
    i++;
}

// Loop Do-while (executa pelo menos uma vez)
int j = 0;
do {
    System.out.println("Do-while: " + j);
    j++;
} while (j < 3);
```

<BaseQuiz id="java-while-1" correct="B">
  <template #question>
    Qual é a principal diferença entre os loops <code>while</code> e <code>do-while</code>?
  </template>
  
  <BaseQuizOption value="A">Não há diferença</BaseQuizOption>
  <BaseQuizOption value="B" correct>do-while executa pelo menos uma vez, enquanto while pode não executar</BaseQuizOption>
  <BaseQuizOption value="C">while é mais rápido</BaseQuizOption>
  <BaseQuizOption value="D">do-while só funciona com arrays</BaseQuizOption>
  
  <BaseQuizAnswer>
    O loop <code>do-while</code> verifica a condição após executar o corpo do loop, portanto, ele sempre é executado pelo menos uma vez. O loop <code>while</code> verifica a condição primeiro, então pode não ser executado se a condição for falsa inicialmente.
  </BaseQuizAnswer>
</BaseQuiz>

## Programação Orientada a Objetos

### Classes e Objetos

Objetos têm estados e comportamentos. Um objeto é uma instância de uma classe.

```java
public class Car {
    // Variáveis de instância (estado)
    String color;
    String model;
    int year;

    // Construtor
    public Car(String color, String model, int year) {
        this.color = color;
        this.model = model;
        this.year = year;
    }

    // Método (comportamento)
    public void start() {
        System.out.println("Car is starting...");
    }
}

// Criação de objetos
Car myCar = new Car("Red", "Toyota", 2022);
myCar.start();
```

### Construtores

Métodos especiais usados para inicializar objetos.

```java
public class Person {
    String name;
    int age;

    // Construtor padrão
    public Person() {
        name = "Unknown";
        age = 0;
    }

    // Construtor parametrizado
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
```

### Herança: `extends`

A herança permite a reutilização de código e cria relações hierárquicas entre classes.

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
myDog.eat();  // Método herdado
myDog.bark(); // Método próprio
```

### Modificadores de Acesso

Modificadores controlam o acesso a classes, métodos e variáveis.

```java
public class Example {
    public int publicVar;      // Acessível em todos os lugares
    private int privateVar;    // Apenas dentro desta classe
    protected int protectedVar; // Dentro do pacote + subclasses
    int defaultVar;            // Apenas dentro do pacote

    private void privateMethod() {
        // Acessível apenas dentro desta classe
    }
}
```

## Métodos e Funções

### Declaração de Método

Um método é basicamente um comportamento onde a lógica é escrita, os dados são manipulados e as ações são executadas.

```java
public class Calculator {
    // Método com parâmetros e valor de retorno
    public int add(int a, int b) {
        return a + b;
    }

    // Método sem valor de retorno
    public void printSum(int a, int b) {
        int result = add(a, b);
        System.out.println("Sum: " + result);
    }

    // Método estático (pertence à classe)
    public static int multiply(int a, int b) {
        return a * b;
    }
}
```

### Sobrecarga de Método (Method Overloading)

Múltiplos métodos com o mesmo nome, mas parâmetros diferentes.

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

### Parâmetros de Método e Tipos de Retorno

Passar dados para métodos e retornar resultados.

```java
public class StringHelper {
    // Método com parâmetro String e retorno
    public String formatName(String firstName, String lastName) {
        return firstName + " " + lastName;
    }

    // Método com parâmetro de array
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

Métodos que chamam a si mesmos para resolver problemas.

```java
public class RecursiveExamples {
    // Calcular fatorial
    public int factorial(int n) {
        if (n <= 1) {
            return 1;
        }
        return n * factorial(n - 1);
    }

    // Sequência de Fibonacci
    public int fibonacci(int n) {
        if (n <= 1) {
            return n;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

## Arrays e Coleções

### Declaração e Inicialização de Array

Criar e inicializar arrays de diferentes tipos.

```java
// Declaração e inicialização de array
int[] numbers = {1, 2, 3, 4, 5};
String[] names = {"Alice", "Bob", "Charlie"};

// Array com tamanho especificado
int[] scores = new int[10];
scores[0] = 95;
scores[1] = 87;

// Obtendo o comprimento do array
int length = numbers.length;
System.out.println("Length: " + length);

// Percorrer o array
for (int i = 0; i < numbers.length; i++) {
    System.out.println("Element " + i + ": " + numbers[i]);
}
```

### Arrays Multidimensionais

Arrays de arrays para estruturas de dados semelhantes a matrizes.

```java
// Declaração de array 2D
int[][] matrix = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

// Acessar elementos
int element = matrix[1][2]; // Obtém 6

// Percorrer array 2D
for (int i = 0; i < matrix.length; i++) {
    for (int j = 0; j < matrix[i].length; j++) {
        System.out.print(matrix[i][j] + " ");
    }
    System.out.println();
}
```

### ArrayList: Arrays Dinâmicos

Arrays redimensionáveis que podem crescer e encolher dinamicamente.

```java
import java.util.ArrayList;

// Criar ArrayList
ArrayList<String> list = new ArrayList<>();

// Adicionar elementos
list.add("Apple");
list.add("Banana");
list.add("Orange");

// Obter elemento
String fruit = list.get(0); // Obtém "Apple"

// Remover elemento
list.remove(1); // Remove "Banana"

// Tamanho e iteração
System.out.println("Size: " + list.size());
for (String item : list) {
    System.out.println(item);
}
```

### HashMap: Pares Chave-Valor

Armazena dados como pares chave-valor para pesquisa rápida.

```java
import java.util.HashMap;

// Criar HashMap
HashMap<String, Integer> ages = new HashMap<>();

// Adicionar pares chave-valor
ages.put("Alice", 25);
ages.put("Bob", 30);
ages.put("Charlie", 35);

// Obter valor pela chave
int aliceAge = ages.get("Alice");

// Verificar se a chave existe
if (ages.containsKey("Bob")) {
    System.out.println("Bob's age: " + ages.get("Bob"));
}
```

## Tratamento de Exceções

### Blocos Try-Catch

Lidar com exceções para evitar falhas no programa.

```java
public class ExceptionExample {
    public static void main(String[] args) {
        try {
            int result = 10 / 0; // Isso lançará ArithmeticException
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

### Múltiplos Blocos Catch

Lidar com diferentes tipos de exceções separadamente.

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

### Lançando Exceções Personalizadas

Criar e lançar suas próprias exceções.

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

### Tipos de Exceção Comuns

Exceções frequentemente encontradas em programas Java.

```java
// NullPointerException
String str = null;
// str.length(); // Lança NullPointerException

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
// int val = arr[5]; // Lança ArrayIndexOutOfBoundsException

// NumberFormatException
// int num = Integer.parseInt("abc"); // Lança NumberFormatException

// FileNotFoundException (ao trabalhar com arquivos)
// IOException (operações gerais de E/S)
```

## Operações de Entrada/Saída

### Entrada do Console: Classe Scanner

Ler a entrada do teclado usando Scanner.

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

### Saída do Console: System.out

Exibir saída no console em vários formatos.

```java
public class OutputExample {
    public static void main(String[] args) {
        // Saída básica
        System.out.println("Hello, World!");
        System.out.print("No newline");
        System.out.print(" continues here\n");

        // Saída formatada
        String name = "Java";
        int version = 17;
        System.out.printf("Welcome to %s %d!%n", name, version);

        // Saída de variáveis
        int x = 10, y = 20;
        System.out.println("x = " + x + ", y = " + y);
        System.out.println("Sum = " + (x + y));
    }
}
```

### Leitura de Arquivo: BufferedReader

Ler arquivos de texto linha por linha de forma eficiente.

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

### Escrita de Arquivo: PrintWriter

Escrever dados de texto em arquivos com tratamento de exceção adequado.

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

## Ambiente de Desenvolvimento Java

### Instalação do JDK

JDK (Java Development Kit) = JRE + Ferramentas de Desenvolvimento. Necessário para desenvolver aplicações Java.

```bash
# Baixar JDK da Oracle ou OpenJDK
# Instalar JDK no seu sistema
# Definir a variável de ambiente JAVA_HOME
export JAVA_HOME=/path/to/jdk
export PATH=$JAVA_HOME/bin:$PATH

# Verificar instalação
java -version
javac -version
```

### Compilar e Executar Programas Java

Use `javac` para compilar o código-fonte Java e `java` para executar o programa compilado.

```bash
# Compilar arquivo fonte Java
javac MyProgram.java

# Executar programa Java compilado
java MyProgram

# Compilar com classpath
javac -cp .:mylib.jar MyProgram.java

# Executar com classpath
java -cp .:mylib.jar MyProgram
```

### Configuração e Desenvolvimento de IDE

Ambientes de Desenvolvimento Integrado populares para desenvolvimento Java.

```bash
# IDEs Java Populares:
# - IntelliJ IDEA (JetBrains)
# - Eclipse IDE
# - Visual Studio Code com extensões Java
# - NetBeans

# Compilação via linha de comando
javac -d bin src/*.java
java -cp bin MainClass

# Criação de arquivo JAR
jar cf myapp.jar -C bin .
```

## Melhores Práticas e Padrões Comuns

### Convenções de Nomenclatura

Siga os padrões de nomenclatura Java para melhor legibilidade do código.

```java
// Classes: PascalCase
public class StudentManager { }
public class BankAccount { }

// Métodos e variáveis: camelCase
int studentAge;
String firstName;
public void calculateGrade() { }
public boolean isValidEmail() { }

// Constantes: UPPER_CASE
public static final int MAX_SIZE = 100;
public static final String DEFAULT_NAME = "Unknown";

// Pacotes: minúsculo
package com.company.project;
package utils.database;
package com.example.myapp;
```

### Organização do Código

Estruturar seus programas Java para manutenção.

```java
import java.util.ArrayList;
import java.util.Scanner;

/**
 * Esta classe demonstra boa organização de código Java
 * @author Your Name
 * @version 1.0
 */
public class WellOrganizedClass {
    // Constantes primeiro
    private static final int MAX_ATTEMPTS = 3;

    // Variáveis de instância
    private String name;
    private int value;

    // Construtor
    public WellOrganizedClass(String name) {
        this.name = name;
        this.value = 0;
    }

    // Métodos públicos
    public void doSomething() {
        // Implementação
    }

    // Métodos auxiliares privados
    private boolean isValid() {
        return value > 0;
    }
}
```

### Prevenção de Erros

Práticas comuns para evitar bugs e melhorar a qualidade do código.

```java
public class BestPractices {
    public void safeDivision(int a, int b) {
        // Verificar divisão por zero
        if (b == 0) {
            throw new IllegalArgumentException("Cannot divide by zero");
        }
        int result = a / b;
        System.out.println("Result: " + result);
    }

    public void safeStringOperations(String input) {
        // Verificação de nulo antes de usar strings
        if (input != null && !input.isEmpty()) {
            System.out.println("Length: " + input.length());
            System.out.println("Uppercase: " + input.toUpperCase());
        } else {
            System.out.println("Invalid input string");
        }
    }

    public void safeArrayAccess(int[] array, int index) {
        // Verificação de limites
        if (array != null && index >= 0 && index < array.length) {
            System.out.println("Value: " + array[index]);
        } else {
            System.out.println("Invalid array access");
        }
    }
}
```

### Gerenciamento de Recursos

Lidar adequadamente com recursos para evitar vazamentos de memória.

```java
import java.io.*;

public class ResourceManagement {
    // Try-with-resources (limpeza automática)
    public void readFileProper(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine();
            System.out.println(line);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        // Reader é fechado automaticamente
    }

    // Limpeza manual de recursos (não recomendado)
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

## Links Relevantes

- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/javascript">JavaScript Cheatsheet</router-link>
- <router-link to="/cpp">C++ Cheatsheet</router-link>
- <router-link to="/golang">Go Cheatsheet</router-link>
- <router-link to="/web-development">Web Development Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/kubernetes">Kubernetes Cheatsheet</router-link>

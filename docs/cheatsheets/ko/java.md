---
title: 'Java 치트 시트 | LabEx'
description: '포괄적인 치트 시트로 Java 프로그래밍을 학습하세요. Java 구문, OOP, 컬렉션, 스트림, Spring 프레임워크 및 엔터프라이즈 개발 필수 사항에 대한 빠른 참조.'
pdfUrl: '/cheatsheets/pdf/java-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Java 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/java">Hands-On Labs 로 Java 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 기반 랩과 실제 시나리오를 통해 Java 프로그래밍을 학습하세요. LabEx 는 필수 구문, 객체 지향 프로그래밍, 컬렉션, 예외 처리 및 모범 사례를 다루는 포괄적인 Java 과정을 제공합니다. Java 개발 기본 사항을 마스터하고 강력한 애플리케이션을 구축하세요.
</base-disclaimer-content>
</base-disclaimer>

## 프로그램 구조 및 기본 구문

### Hello World: 기본 프로그램

화면에 "Hello, World!"를 표시하는 가장 간단한 Java 프로그램입니다.

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### 클래스 선언: `public class`

클래스는 객체가 지원하는 동작/상태를 설명하는 템플릿/청사진입니다.

```java
public class MyClass {
    // 클래스 내용은 여기에 들어갑니다
    int myVariable;

    public void myMethod() {
        System.out.println("Hello from method!");
    }
}
```

### 메인 메서드: 프로그램 진입점

메인 메서드는 Java 프로그램 실행이 시작되는 곳입니다.

```java
public static void main(String[] args) {
    // 프로그램 코드는 여기에
    System.out.println("Program starts here");
}
```

<BaseQuiz id="java-main-1" correct="C">
  <template #question>
    Java 에서 메인 메서드의 올바른 시그니처는 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">public void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="B">static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="C" correct>public static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="D">public static int main(String[] args)</BaseQuizOption>
  
  <BaseQuizAnswer>
    메인 메서드는 `public static void main(String[] args)`여야 합니다. `public` 은 JVM 이 접근할 수 있게 하고, `static` 은 클래스에 속함을 의미하며, `void` 는 반환 값이 없음을 의미하고, `String[] args`는 명령줄 인수를 받습니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 주석: 코드 문서화

코드 이해도와 유지보수성을 높이기 위해 단일 행 (`//`) 및 다중 행 (`/* */`) 주석을 사용합니다.

```java
// 단일 행 주석
System.out.println("Hello");

/* 다중 행 주석
   여러 줄에 걸쳐 있을 수 있습니다
   자세한 설명을 위해 사용됩니다 */
```

### 문장 및 세미콜론

Java 의 각 문장은 세미콜론으로 끝나야 합니다.

```java
int number = 10;
String name = "Java";
System.out.println(name);
```

### 코드 블록: 중괄호

코드 블록은 중괄호 `{}`로 묶여 코드 섹션의 시작과 끝을 표시합니다.

```java
public class Example {
    public void method() {
        if (true) {
            System.out.println("Inside if block");
        }
    }
}
```

## 데이터 타입 및 변수

### 기본 데이터 타입

Java 언어에 내장된 기본 데이터 타입입니다.

```java
// 정수 타입
byte smallNum = 127;        // -128 to 127
short shortNum = 32000;     // -32,768 to 32,767
int number = 100;           // -2^31 to 2^31-1
long bigNum = 10000L;       // -2^63 to 2^63-1

// 부동 소수점 타입
float decimal = 3.14f;      // 단정밀도
double precision = 3.14159; // 배정밀도

// 기타 타입
char letter = 'A';          // 단일 문자
boolean flag = true;        // true 또는 false
```

### 변수 선언 및 초기화

변수를 생성하고 값 할당하기.

```java
// 선언만
int age;
String name;

// 초기화와 함께 선언
int age = 25;
String name = "John";

// 다중 선언
int x = 10, y = 20, z = 30;

// final 변수 (상수)
final double PI = 3.14159;
```

### 문자열 연산

문자열은 문자 시퀀스를 나타내며 불변 (immutable) 입니다. 즉, 일단 생성되면 값을 변경할 수 없습니다.

```java
String greeting = "Hello";
String name = "World";

// 문자열 연결
String message = greeting + " " + name;
System.out.println(message); // "Hello World"

// 문자열 메서드
int length = message.length();
boolean isEmpty = message.isEmpty();
String uppercase = message.toUpperCase();
```

<BaseQuiz id="java-string-1" correct="A">
  <template #question>
    Java 문자열이 불변 (immutable) 이라는 것은 무엇을 의미합니까?
  </template>
  
  <BaseQuizOption value="A" correct>일단 생성되면 문자열의 값을 변경할 수 없습니다</BaseQuizOption>
  <BaseQuizOption value="B">문자열을 생성할 수 없습니다</BaseQuizOption>
  <BaseQuizOption value="C">문자열은 숫자만 저장할 수 있습니다</BaseQuizOption>
  <BaseQuizOption value="D">문자열은 자동으로 삭제됩니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    불변성은 String 객체가 생성되면 그 값을 수정할 수 없음을 의미합니다. `toUpperCase()` 와 같은 연산은 원본을 수정하는 대신 새 String 객체를 반환합니다.
  </BaseQuizAnswer>
</BaseQuiz>

## 제어 흐름문

### 조건문: `if`, `else if`, `else`

조건에 따라 다른 코드 블록을 실행합니다.

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

### Switch 문

변수 값을 기반으로 다중 분기 처리를 수행합니다.

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

### For 루프: 횟수 반복

특정 횟수만큼 코드를 반복합니다.

```java
// 표준 for 루프
for (int i = 0; i < 5; i++) {
    System.out.println("Count: " + i);
}

// 향상된 for 루프 (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println("Number: " + num);
}
```

<BaseQuiz id="java-for-loop-1" correct="C">
  <template #question>
    향상된 for 루프 (for-each) 는 무엇에 사용됩니까?
  </template>
  
  <BaseQuizOption value="A">카운터 변수를 사용하여 반복</BaseQuizOption>
  <BaseQuizOption value="B">무한 루프</BaseQuizOption>
  <BaseQuizOption value="C" correct>인덱스 없이 배열 및 컬렉션을 반복</BaseQuizOption>
  <BaseQuizOption value="D">중첩 루프에서만 사용</BaseQuizOption>
  
  <BaseQuizAnswer>
    향상된 for 루프 (for-each) 는 인덱스를 자동으로 처리하여 배열 및 컬렉션 반복을 단순화하여 코드를 더 읽기 쉽고 오류 발생 가능성을 줄입니다.
  </BaseQuizAnswer>
</BaseQuiz>

### While 및 Do-While 루프

조건이 참인 동안 코드를 반복합니다.

```java
// While 루프
int i = 0;
while (i < 3) {
    System.out.println("While: " + i);
    i++;
}

// Do-while 루프 (최소 한 번 실행)
int j = 0;
do {
    System.out.println("Do-while: " + j);
    j++;
} while (j < 3);
```

<BaseQuiz id="java-while-1" correct="B">
  <template #question>
    `while` 루프와 `do-while` 루프의 주요 차이점은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">차이점이 없습니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>do-while 은 최소 한 번 실행되지만, while 은 전혀 실행되지 않을 수 있습니다</BaseQuizOption>
  <BaseQuizOption value="C">while 이 더 빠릅니다</BaseQuizOption>
  <BaseQuizOption value="D">do-while 은 배열에서만 작동합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `do-while` 루프는 루프 본문을 실행한 후 조건을 확인하므로 항상 최소 한 번 실행됩니다. `while` 루프는 조건을 먼저 확인하므로 조건이 처음부터 거짓이면 실행되지 않을 수 있습니다.
  </BaseQuizAnswer>
</BaseQuiz>

## 객체 지향 프로그래밍

### 클래스 및 객체

객체는 상태와 동작을 가집니다. 객체는 클래스의 인스턴스입니다.

```java
public class Car {
    // 인스턴스 변수 (상태)
    String color;
    String model;
    int year;

    // 생성자
    public Car(String color, String model, int year) {
        this.color = color;
        this.model = model;
        this.year = year;
    }

    // 메서드 (동작)
    public void start() {
        System.out.println("Car is starting...");
    }
}

// 객체 생성
Car myCar = new Car("Red", "Toyota", 2022);
myCar.start();
```

### 생성자

객체를 초기화하는 데 사용되는 특수 메서드입니다.

```java
public class Person {
    String name;
    int age;

    // 기본 생성자
    public Person() {
        name = "Unknown";
        age = 0;
    }

    // 매개변수화된 생성자
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
```

### 상속: `extends`

상속은 코드 재사용을 가능하게 하고 클래스 간의 계층적 관계를 만듭니다.

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
myDog.eat();  // 상속받은 메서드
myDog.bark(); // 자신의 메서드
```

### 접근 한정자

한정자는 클래스, 메서드 및 변수에 대한 접근을 제어합니다.

```java
public class Example {
    public int publicVar;      // 어디서든 접근 가능
    private int privateVar;    // 이 클래스 내에서만 접근 가능
    protected int protectedVar; // 패키지 + 서브클래스 내에서 접근 가능
    int defaultVar;            // 패키지 내에서만 접근 가능

    private void privateMethod() {
        // 이 클래스 내에서만 접근 가능
    }
}
```

## 메서드 및 함수

### 메서드 선언

메서드는 로직이 작성되고, 데이터가 조작되며, 동작이 실행되는 기본 동작입니다.

```java
public class Calculator {
    // 매개변수와 반환 값이 있는 메서드
    public int add(int a, int b) {
        return a + b;
    }

    // 반환 값이 없는 메서드
    public void printSum(int a, int b) {
        int result = add(a, b);
        System.out.println("Sum: " + result);
    }

    // 정적 메서드 (클래스에 속함)
    public static int multiply(int a, int b) {
        return a * b;
    }
}
```

### 메서드 오버로딩

매개변수가 다른 동일한 이름의 여러 메서드입니다.

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

### 메서드 매개변수 및 반환 타입

메서드에 데이터를 전달하고 결과를 반환합니다.

```java
public class StringHelper {
    // String 매개변수와 반환 값이 있는 메서드
    public String formatName(String firstName, String lastName) {
        return firstName + " " + lastName;
    }

    // 배열 매개변수가 있는 메서드
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

### 재귀 메서드

문제를 해결하기 위해 자신을 호출하는 메서드입니다.

```java
public class RecursiveExamples {
    // 팩토리얼 계산
    public int factorial(int n) {
        if (n <= 1) {
            return 1;
        }
        return n * factorial(n - 1);
    }

    // 피보나치 수열
    public int fibonacci(int n) {
        if (n <= 1) {
            return n;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

## 배열 및 컬렉션

### 배열 선언 및 초기화

다양한 유형의 배열을 생성하고 초기화합니다.

```java
// 배열 선언 및 초기화
int[] numbers = {1, 2, 3, 4, 5};
String[] names = {"Alice", "Bob", "Charlie"};

// 지정된 크기로 배열 생성
int[] scores = new int[10];
scores[0] = 95;
scores[1] = 87;

// 배열 길이 가져오기
int length = numbers.length;
System.out.println("Length: " + length);

// 배열 순회
for (int i = 0; i < numbers.length; i++) {
    System.out.println("Element " + i + ": " + numbers[i]);
}
```

### 다차원 배열

행렬과 같은 데이터 구조를 위한 배열의 배열입니다.

```java
// 2 차원 배열 선언
int[][] matrix = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

// 요소 접근
int element = matrix[1][2]; // 6 을 가져옴

// 2 차원 배열 순회
for (int i = 0; i < matrix.length; i++) {
    for (int j = 0; j < matrix[i].length; j++) {
        System.out.print(matrix[i][j] + " ");
    }
    System.out.println();
}
```

### ArrayList: 동적 배열

동적으로 크기가 조정되고 축소될 수 있는 가변 크기 배열입니다.

```java
import java.util.ArrayList;

// ArrayList 생성
ArrayList<String> list = new ArrayList<>();

// 요소 추가
list.add("Apple");
list.add("Banana");
list.add("Orange");

// 요소 가져오기
String fruit = list.get(0); // "Apple"을 가져옴

// 요소 제거
list.remove(1); // "Banana" 제거

// 크기 및 반복
System.out.println("Size: " + list.size());
for (String item : list) {
    System.out.println(item);
}
```

### HashMap: 키 - 값 쌍

빠른 조회를 위해 키 - 값 쌍으로 데이터를 저장합니다.

```java
import java.util.HashMap;

// HashMap 생성
HashMap<String, Integer> ages = new HashMap<>();

// 키 - 값 쌍 추가
ages.put("Alice", 25);
ages.put("Bob", 30);
ages.put("Charlie", 35);

// 키로 값 가져오기
int aliceAge = ages.get("Alice");

// 키 존재 여부 확인
if (ages.containsKey("Bob")) {
    System.out.println("Bob's age: " + ages.get("Bob"));
}
```

## 예외 처리

### Try-Catch 블록

프로그램 충돌을 방지하기 위해 예외를 처리합니다.

```java
public class ExceptionExample {
    public static void main(String[] args) {
        try {
            int result = 10 / 0; // ArithmeticException 발생
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

### 다중 Catch 블록

서로 다른 유형의 예외를 별도로 처리합니다.

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

### 사용자 정의 예외 던지기

자체 예외를 생성하고 던집니다.

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

### 일반적인 예외 유형

Java 프로그램에서 자주 발생하는 예외입니다.

```java
// NullPointerException
String str = null;
// str.length(); // NullPointerException 발생

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
// int val = arr[5]; // ArrayIndexOutOfBoundsException 발생

// NumberFormatException
// int num = Integer.parseInt("abc"); // NumberFormatException 발생

// FileNotFoundException (파일 작업 시)
// IOException (일반적인 I/O 작업)
```

## 입력/출력 작업

### 콘솔 입력: Scanner 클래스

Scanner 를 사용하여 키보드 입력을 읽습니다.

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

### 콘솔 출력: System.out

다양한 형식으로 콘솔에 출력을 표시합니다.

```java
public class OutputExample {
    public static void main(String[] args) {
        // 기본 출력
        System.out.println("Hello, World!");
        System.out.print("No newline");
        System.out.print(" continues here\n");

        // 형식화된 출력
        String name = "Java";
        int version = 17;
        System.out.printf("Welcome to %s %d!%n", name, version);

        // 변수 출력
        int x = 10, y = 20;
        System.out.println("x = " + x + ", y = " + y);
        System.out.println("Sum = " + (x + y));
    }
}
```

### 파일 읽기: BufferedReader

효율적으로 파일을 한 줄씩 읽습니다.

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

### 파일 쓰기: PrintWriter

적절한 예외 처리를 통해 텍스트 데이터를 파일에 씁니다.

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

## Java 개발 환경

### JDK 설치

JDK (Java Development Kit) = JRE + 개발 도구. Java 애플리케이션 개발에 필요합니다.

```bash
# Oracle 또는 OpenJDK에서 JDK 다운로드
# 시스템에 JDK 설치
# JAVA_HOME 환경 변수 설정
export JAVA_HOME=/path/to/jdk
export PATH=$JAVA_HOME/bin:$PATH

# 설치 확인
java -version
javac -version
```

### Java 프로그램 컴파일 및 실행

`javac`를 사용하여 Java 소스 코드를 컴파일하고 `java`를 사용하여 컴파일된 프로그램을 실행합니다.

```bash
# Java 소스 파일 컴파일
javac MyProgram.java

# 컴파일된 Java 프로그램 실행
java MyProgram

# 클래스 경로를 사용하여 컴파일
javac -cp .:mylib.jar MyProgram.java

# 클래스 경로를 사용하여 실행
java -cp .:mylib.jar MyProgram
```

### IDE 설정 및 개발

Java 개발을 위한 인기 있는 통합 개발 환경입니다.

```bash
# 인기 있는 Java IDE:
# - IntelliJ IDEA (JetBrains)
# - Eclipse IDE
# - Java 확장이 포함된 Visual Studio Code
# - NetBeans

# 명령줄 컴파일
javac -d bin src/*.java
java -cp bin MainClass

# JAR 파일 생성
jar cf myapp.jar -C bin .
```

## 모범 사례 및 일반적인 패턴

### 명명 규칙

코드 가독성을 높이기 위해 Java 명명 표준을 따릅니다.

```java
// 클래스: PascalCase
public class StudentManager { }
public class BankAccount { }

// 메서드 및 변수: camelCase
int studentAge;
String firstName;
public void calculateGrade() { }
public boolean isValidEmail() { }

// 상수: UPPER_CASE
public static final int MAX_SIZE = 100;
public static final String DEFAULT_NAME = "Unknown";

// 패키지: lowercase
package com.company.project;
package utils.database;
package com.example.myapp;
```

### 코드 구성

유지보수를 위해 Java 프로그램을 구조화합니다.

```java
import java.util.ArrayList;
import java.util.Scanner;

/**
 * 이 클래스는 좋은 Java 코드 구성을 보여줍니다
 * @author Your Name
 * @version 1.0
 */
public class WellOrganizedClass {
    // 상수를 먼저
    private static final int MAX_ATTEMPTS = 3;

    // 인스턴스 변수
    private String name;
    private int value;

    // 생성자
    public WellOrganizedClass(String name) {
        this.name = name;
        this.value = 0;
    }

    // 공개 메서드
    public void doSomething() {
        // 구현
    }

    // 비공개 헬퍼 메서드
    private boolean isValid() {
        return value > 0;
    }
}
```

### 오류 방지

버그를 피하고 코드 품질을 개선하기 위한 일반적인 관행입니다.

```java
public class BestPractices {
    public void safeDivision(int a, int b) {
        // 0 으로 나누는 것 확인
        if (b == 0) {
            throw new IllegalArgumentException("Cannot divide by zero");
        }
        int result = a / b;
        System.out.println("Result: " + result);
    }

    public void safeStringOperations(String input) {
        // 문자열 사용 전 Null 확인
        if (input != null && !input.isEmpty()) {
            System.out.println("Length: " + input.length());
            System.out.println("Uppercase: " + input.toUpperCase());
        } else {
            System.out.println("Invalid input string");
        }
    }

    public void safeArrayAccess(int[] array, int index) {
        // 경계 확인
        if (array != null && index >= 0 && index < array.length) {
            System.out.println("Value: " + array[index]);
        } else {
            System.out.println("Invalid array access");
        }
    }
}
```

### 리소스 관리

메모리 누수를 방지하기 위해 리소스를 적절하게 처리합니다.

```java
import java.io.*;

public class ResourceManagement {
    // Try-with-resources (자동 정리)
    public void readFileProper(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine();
            System.out.println(line);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        // Reader 는 자동으로 닫힙니다
    }

    // 수동 리소스 정리 (권장되지 않음)
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

## 관련 링크

- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/cpp">C++ 치트 시트</router-link>
- <router-link to="/golang">Go 치트 시트</router-link>
- <router-link to="/web-development">웹 개발 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>

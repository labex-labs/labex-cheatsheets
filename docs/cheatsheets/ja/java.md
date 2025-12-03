---
title: 'Java チートシート | LabEx'
description: 'この包括的なチートシートで Java プログラミングを学習。Java 構文、OOP、コレクション、ストリーム、Spring フレームワーク、エンタープライズ開発の必須事項を素早く参照できます。'
pdfUrl: '/cheatsheets/pdf/java-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Java チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/java">ハンズオンラボで Java を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて Java プログラミングを学びましょう。LabEx は、必須の構文、オブジェクト指向プログラミング、コレクション、例外処理、ベストプラクティスを網羅した包括的な Java コースを提供します。Java 開発の基礎を習得し、堅牢なアプリケーションを構築します。
</base-disclaimer-content>
</base-disclaimer>

## プログラム構造と基本構文

### Hello World: 基本的なプログラム

画面に "Hello, World!" を表示する最もシンプルな Java プログラム。

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### クラス宣言：`public class`

クラスは、オブジェクトがサポートする動作/状態を記述するテンプレート/ブループリントです。

```java
public class MyClass {
    // クラスの内容をここに記述
    int myVariable;

    public void myMethod() {
        System.out.println("Hello from method!");
    }
}
```

### main メソッド：プログラムのエントリーポイント

main メソッドは、Java プログラムの実行が開始される場所です。

```java
public static void main(String[] args) {
    // プログラムコードをここに記述
    System.out.println("Program starts here");
}
```

<BaseQuiz id="java-main-1" correct="C">
  <template #question>
    Java における main メソッドの正しいシグネチャは何ですか？
  </template>
  
  <BaseQuizOption value="A">public void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="B">static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="C" correct>public static void main(String[] args)</BaseQuizOption>
  <BaseQuizOption value="D">public static int main(String[] args)</BaseQuizOption>
  
  <BaseQuizAnswer>
    main メソッドは <code>public static void main(String[] args)</code> である必要があります。<code>public</code> は JVM がアクセスできるようにし、<code>static</code> はクラスに属することを意味し、<code>void</code> は何も返さないことを意味し、<code>String[] args</code> はコマンドライン引数を受け取ります。
  </BaseQuizAnswer>
</BaseQuiz>

### コメント：コードのドキュメント化

コードをより理解しやすく、保守しやすくするために、単一行 (`//`) および複数行 (`/* */`) のコメントを使用します。

```java
// 単一行コメント
System.out.println("Hello");

/* 複数行コメント
   複数行にまたがることができます
   詳細な説明に使用されます */
```

### ステートメントとセミコロン

Java では、各ステートメントはセミコロンで終了する必要があります。

```java
int number = 10;
String name = "Java";
System.out.println(name);
```

### コードブロック：波括弧

コードブロックは波括弧 `{}` で囲まれ、コードセクションの開始と終了を示します。

```java
public class Example {
    public void method() {
        if (true) {
            System.out.println("Inside if block");
        }
    }
}
```

## データ型と変数

### プリミティブデータ型

Java 言語に組み込まれている基本的なデータ型。

```java
// 整数型
byte smallNum = 127;        // -128 から 127
short shortNum = 32000;     // -32,768 から 32,767
int number = 100;           // -2^31 から 2^31-1
long bigNum = 10000L;       // -2^63 から 2^63-1

// 浮動小数点型
float decimal = 3.14f;      // 単精度
double precision = 3.14159; // 倍精度

// その他の型
char letter = 'A';          // 単一文字
boolean flag = true;        // true または false
```

### 変数の宣言と初期化

変数の作成と値の代入。

```java
// 宣言のみ
int age;
String name;

// 初期化を伴う宣言
int age = 25;
String name = "John";

// 複数宣言
int x = 10, y = 20, z = 30;

// final 変数 (定数)
final double PI = 3.14159;
```

### 文字列操作

文字列は文字のシーケンスを表し、不変（immutable）です。つまり、一度作成されると、その値を変更することはできません。

```java
String greeting = "Hello";
String name = "World";

// 文字列の連結
String message = greeting + " " + name;
System.out.println(message); // "Hello World"

// 文字列メソッド
int length = message.length();
boolean isEmpty = message.isEmpty();
String uppercase = message.toUpperCase();
```

<BaseQuiz id="java-string-1" correct="A">
  <template #question>
    Java の文字列が不変（immutable）であるとはどういう意味ですか？
  </template>
  
  <BaseQuizOption value="A" correct>作成された後、文字列の値を変更することはできない</BaseQuizOption>
  <BaseQuizOption value="B">文字列を作成できない</BaseQuizOption>
  <BaseQuizOption value="C">文字列は数値のみを格納できる</BaseQuizOption>
  <BaseQuizOption value="D">文字列は自動的に削除される</BaseQuizOption>
  
  <BaseQuizAnswer>
    不変性とは、一度 String オブジェクトが作成されると、その値を変更できないことを意味します。<code>toUpperCase()</code> のような操作は、元のオブジェクトを変更するのではなく、新しい String オブジェクトを返します。
  </BaseQuizAnswer>
</BaseQuiz>

## 制御フロー文

### 条件分岐：`if`, `else if`, `else`

条件に基づいて異なるコードブロックを実行します。

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

### Switch 文

変数の値に基づいて多方向分岐を行います。

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

### For ループ：回数指定の繰り返し

特定の回数だけコードを繰り返します。

```java
// 標準の for ループ
for (int i = 0; i < 5; i++) {
    System.out.println("Count: " + i);
}

// 拡張 for ループ (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println("Number: " + num);
}
```

<BaseQuiz id="java-for-loop-1" correct="C">
  <template #question>
    拡張 for ループ (for-each) は何に使用されますか？
  </template>
  
  <BaseQuizOption value="A">カウンター変数を使用して反復処理を行う</BaseQuizOption>
  <BaseQuizOption value="B">無限ループ</BaseQuizOption>
  <BaseQuizOption value="C" correct>インデックスなしで配列やコレクションを反復処理する</BaseQuizOption>
  <BaseQuizOption value="D">ネストされたループのみ</BaseQuizOption>
  
  <BaseQuizAnswer>
    拡張 for ループ (for-each) は、配列やコレクションの反復処理を簡素化し、インデックスを自動的に処理するため、コードの可読性が向上し、エラーが発生しにくくなります。
  </BaseQuizAnswer>
</BaseQuiz>

### While および Do-While ループ

条件が真である限りコードを繰り返します。

```java
// While ループ
int i = 0;
while (i < 3) {
    System.out.println("While: " + i);
    i++;
}

// Do-while ループ (少なくとも 1 回実行される)
int j = 0;
do {
    System.out.println("Do-while: " + j);
    j++;
} while (j < 3);
```

<BaseQuiz id="java-while-1" correct="B">
  <template #question>
    <code>while</code> ループと <code>do-while</code> ループの主な違いは何ですか？
  </template>
  
  <BaseQuizOption value="A">違いはない</BaseQuizOption>
  <BaseQuizOption value="B" correct>do-while は少なくとも 1 回実行されるが、while はまったく実行されない場合がある</BaseQuizOption>
  <BaseQuizOption value="C">while の方が高速である</BaseQuizOption>
  <BaseQuizOption value="D">do-while は配列でのみ機能する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>do-while</code> ループはループ本体の実行後に条件をチェックするため、常に少なくとも 1 回実行されます。<code>while</code> ループは最初に条件をチェックするため、条件が最初に偽であれば実行されません。
  </BaseQuizAnswer>
</BaseQuiz>

## オブジェクト指向プログラミング

### クラスとオブジェクト

オブジェクトには状態と動作があります。オブジェクトはクラスのインスタンスです。

```java
public class Car {
    // インスタンス変数 (状態)
    String color;
    String model;
    int year;

    // コンストラクタ
    public Car(String color, String model, int year) {
        this.color = color;
        this.model = model;
        this.year = year;
    }

    // メソッド (動作)
    public void start() {
        System.out.println("Car is starting...");
    }
}

// オブジェクトの作成
Car myCar = new Car("Red", "Toyota", 2022);
myCar.start();
```

### コンストラクタ

オブジェクトを初期化するために使用される特別なメソッド。

```java
public class Person {
    String name;
    int age;

    // デフォルトコンストラクタ
    public Person() {
        name = "Unknown";
        age = 0;
    }

    // パラメータ化されたコンストラクタ
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
```

### 継承：`extends`

継承はコードの再利用を可能にし、クラス間に階層的な関係を作成します。

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
myDog.eat();  // 継承されたメソッド
myDog.bark(); // 独自のメソッド
```

### アクセス修飾子

クラス、メソッド、変数へのアクセスを制御する修飾子。

```java
public class Example {
    public int publicVar;      // どこからでもアクセス可能
    private int privateVar;    // このクラス内でのみアクセス可能
    protected int protectedVar; // パッケージ内およびサブクラスからアクセス可能
    int defaultVar;            // パッケージ内でのみアクセス可能

    private void privateMethod() {
        // このクラス内でのみアクセス可能
    }
}
```

## メソッドと関数

### メソッドの宣言

メソッドは、ロジックが記述され、データが操作され、アクションが実行される動作の基本です。

```java
public class Calculator {
    // パラメータと戻り値を持つメソッド
    public int add(int a, int b) {
        return a + b;
    }

    // 戻り値のないメソッド
    public void printSum(int a, int b) {
        int result = add(a, b);
        System.out.println("Sum: " + result);
    }

    // static メソッド (クラスに属する)
    public static int multiply(int a, int b) {
        return a * b;
    }
}
```

### メソッドのオーバーロード

同じ名前でパラメータが異なる複数のメソッド。

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

### メソッドパラメータと戻り値の型

メソッドにデータを渡し、結果を返す。

```java
public class StringHelper {
    // String パラメータと戻り値を持つメソッド
    public String formatName(String firstName, String lastName) {
        return firstName + " " + lastName;
    }

    // 配列パラメータを持つメソッド
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

### 再帰メソッド

問題を解決するために自身を呼び出すメソッド。

```java
public class RecursiveExamples {
    // 階乗の計算
    public int factorial(int n) {
        if (n <= 1) {
            return 1;
        }
        return n * factorial(n - 1);
    }

    // フィボナッチ数列
    public int fibonacci(int n) {
        if (n <= 1) {
            return n;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

## 配列とコレクション

### 配列の宣言と初期化

さまざまな型の配列を作成し、初期化します。

```java
// 配列の宣言と初期化
int[] numbers = {1, 2, 3, 4, 5};
String[] names = {"Alice", "Bob", "Charlie"};

// 指定されたサイズの配列
int[] scores = new int[10];
scores[0] = 95;
scores[1] = 87;

// 配列の長さの取得
int length = numbers.length;
System.out.println("Length: " + length);

// 配列のループ処理
for (int i = 0; i < numbers.length; i++) {
    System.out.println("Element " + i + ": " + numbers[i]);
}
```

### 多次元配列

行列のようなデータ構造のための配列の配列。

```java
// 2 次元配列の宣言
int[][] matrix = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

// 要素へのアクセス
int element = matrix[1][2]; // 6 を取得

// 2 次元配列のループ処理
for (int i = 0; i < matrix.length; i++) {
    for (int j = 0; j < matrix[i].length; j++) {
        System.out.print(matrix[i][j] + " ");
    }
    System.out.println();
}
```

### ArrayList: 動的配列

動的に増減できるサイズ変更可能な配列。

```java
import java.util.ArrayList;

// ArrayList の作成
ArrayList<String> list = new ArrayList<>();

// 要素の追加
list.add("Apple");
list.add("Banana");
list.add("Orange");

// 要素の取得
String fruit = list.get(0); // "Apple" を取得

// 要素の削除
list.remove(1); // "Banana" を削除

// サイズと反復処理
System.out.println("Size: " + list.size());
for (String item : list) {
    System.out.println(item);
}
```

### HashMap: キーと値のペア

高速なルックアップのためにキーと値のペアとしてデータを格納します。

```java
import java.util.HashMap;

// HashMap の作成
HashMap<String, Integer> ages = new HashMap<>();

// キーと値のペアの追加
ages.put("Alice", 25);
ages.put("Bob", 30);
ages.put("Charlie", 35);

// キーによる値の取得
int aliceAge = ages.get("Alice");

// キーの存在確認
if (ages.containsKey("Bob")) {
    System.out.println("Bob's age: " + ages.get("Bob"));
}
```

## 例外処理

### Try-Catch ブロック

プログラムのクラッシュを防ぐために例外を処理します。

```java
public class ExceptionExample {
    public static void main(String[] args) {
        try {
            int result = 10 / 0; // これは ArithmeticException をスローします
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

### 複数の Catch ブロック

異なる種類の例外を個別に処理します。

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

### カスタム例外のスロー

独自の例外を作成してスローします。

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

### 一般的な例外タイプ

Java プログラムで頻繁に発生する例外。

```java
// NullPointerException
String str = null;
// str.length(); // NullPointerException をスローします

// ArrayIndexOutOfBoundsException
int[] arr = {1, 2, 3};
// int val = arr[5]; // ArrayIndexOutOfBoundsException をスローします

// NumberFormatException
// int num = Integer.parseInt("abc"); // NumberFormatException をスローします

// FileNotFoundException (ファイル操作時)
// IOException (一般的な I/O 操作)
```

## 入出力操作

### コンソール入力：Scanner クラス

Scanner を使用してキーボードから入力を読み取ります。

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

### コンソール出力：System.out

さまざまな形式でコンソールに出力を表示します。

```java
public class OutputExample {
    public static void main(String[] args) {
        // 基本的な出力
        System.out.println("Hello, World!");
        System.out.print("No newline");
        System.out.print(" continues here\n");

        // フォーマットされた出力
        String name = "Java";
        int version = 17;
        System.out.printf("Welcome to %s %d!%n", name, version);

        // 変数の出力
        int x = 10, y = 20;
        System.out.println("x = " + x + ", y = " + y);
        System.out.println("Sum = " + (x + y));
    }
}
```

### ファイル読み取り：BufferedReader

テキストファイルを一行ずつ効率的に読み取ります。

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

### ファイル書き込み：PrintWriter

適切な例外処理でテキストデータをファイルに書き込みます。

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

## Java 開発環境

### JDK のインストール

JDK (Java Development Kit) = JRE + 開発ツール。Java アプリケーションの開発に必要です。

```bash
# Oracle または OpenJDK から JDK をダウンロード
# システムに JDK をインストール
# JAVA_HOME 環境変数を設定
export JAVA_HOME=/path/to/jdk
export PATH=$JAVA_HOME/bin:$PATH

# インストールの確認
java -version
javac -version
```

### Java プログラムのコンパイルと実行

`javac` を使用して Java ソースコードをコンパイルし、`java` を使用してコンパイルされたプログラムを実行します。

```bash
# Java ソースファイルのコンパイル
javac MyProgram.java

# コンパイルされた Java プログラムの実行
java MyProgram

# クラスパスを指定してコンパイル
javac -cp .:mylib.jar MyProgram.java

# クラスパスを指定して実行
java -cp .:mylib.jar MyProgram
```

### IDE のセットアップと開発

Java 開発のための人気のある統合開発環境。

```bash
# 人気の Java IDE:
# - IntelliJ IDEA (JetBrains)
# - Eclipse IDE
# - Visual Studio Code (Java 拡張機能付き)
# - NetBeans

# コマンドラインコンパイル
javac -d bin src/*.java
java -cp bin MainClass

# JAR ファイルの作成
jar cf myapp.jar -C bin .
```

## ベストプラクティスと一般的なパターン

### 命名規則

コードの可読性を高めるために、Java の命名標準に従います。

```java
// クラス：PascalCase
public class StudentManager { }
public class BankAccount { }

// メソッドと変数：camelCase
int studentAge;
String firstName;
public void calculateGrade() { }
public boolean isValidEmail() { }

// 定数：UPPER_CASE
public static final int MAX_SIZE = 100;
public static final String DEFAULT_NAME = "Unknown";

// パッケージ：lowercase
package com.company.project;
package utils.database;
package com.example.myapp;
```

### コードの整理

保守性のために Java プログラムを構造化します。

```java
import java.util.ArrayList;
import java.util.Scanner;

/**
 * 優れた Java コードの整理方法を示します
 * @author Your Name
 * @version 1.0
 */
public class WellOrganizedClass {
    // 定数を最初
    private static final int MAX_ATTEMPTS = 3;

    // インスタンス変数
    private String name;
    private int value;

    // コンストラクタ
    public WellOrganizedClass(String name) {
        this.name = name;
        this.value = 0;
    }

    // public メソッド
    public void doSomething() {
        // 実装
    }

    // private ヘルパーメソッド
    private boolean isValid() {
        return value > 0;
    }
}
```

### エラー防止

バグを回避し、コード品質を向上させるための一般的なプラクティス。

```java
public class BestPractices {
    public void safeDivision(int a, int b) {
        // ゼロ除算のチェック
        if (b == 0) {
            throw new IllegalArgumentException("Cannot divide by zero");
        }
        int result = a / b;
        System.out.println("Result: " + result);
    }

    public void safeStringOperations(String input) {
        // 文字列を使用する前の null チェック
        if (input != null && !input.isEmpty()) {
            System.out.println("Length: " + input.length());
            System.out.println("Uppercase: " + input.toUpperCase());
        } else {
            System.out.println("Invalid input string");
        }
    }

    public void safeArrayAccess(int[] array, int index) {
        // 境界チェック
        if (array != null && index >= 0 && index < array.length) {
            System.out.println("Value: " + array[index]);
        } else {
            System.out.println("Invalid array access");
        }
    }
}
```

### リソース管理

メモリリークを防ぐためにリソースを適切に処理します。

```java
import java.io.*;

public class ResourceManagement {
    // Try-with-resources (自動クリーンアップ)
    public void readFileProper(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line = reader.readLine();
            System.out.println(line);
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
        // Reader は自動的に閉じられます
    }

    // 手動リソースクリーンアップ (非推奨)
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

## 関連リンク

- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/cpp">C++ チートシート</router-link>
- <router-link to="/golang">Go チートシート</router-link>
- <router-link to="/web-development">Web 開発チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/kubernetes">Kubernetes チートシート</router-link>

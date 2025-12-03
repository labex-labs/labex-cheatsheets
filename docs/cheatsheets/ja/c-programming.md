---
title: 'C 言語チートシート | LabEx'
description: 'この包括的なチートシートで C 言語を習得。C の構文、ポインタ、メモリ管理、データ構造、システムプログラミングの要点を開発者向けに素早く参照できます。'
pdfUrl: '/cheatsheets/pdf/c-programming-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
C 言語チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/c">ハンズオンラボで C プログラミングを学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて C プログラミングを学びましょう。LabEx は、必須の構文、メモリ管理、ポインタ、データ構造、高度なテクニックを網羅した包括的な C コースを提供します。C の強力な機能を習得し、効率的なシステムレベルのアプリケーションを構築し、低レベルのプログラミング概念を理解してください。
</base-disclaimer-content>
</base-disclaimer>

## 基本構文と構造

### Hello World プログラム

C プログラムの基本構造。

```c
#include <stdio.h>
int main() {
    printf("Hello, World!\n");
    return 0;
}
```

### ヘッダーとプリプロセッサ

ライブラリのインクルードとプリプロセッサディレクティブの使用。

```c
#include <stdio.h>    // 標準入出力
#include <stdlib.h>   // 標準ライブラリ
#include <string.h>   // 文字列関数
#include <math.h>     // 数学関数
#define PI 3.14159
#define MAX_SIZE 100
```

### コメント

一行コメントと複数行コメント。

```c
// 一行コメント
/*
複数行コメント
複数行にまたがる
*/
// TODO: 機能実装
/* FIXME: このセクションのバグ */
```

### main 関数

戻り値を持つプログラムのエントリーポイント。

```c
int main() {
    // プログラムコードをここに
    return 0;  // 成功
}
int main(int argc, char *argv[]) {
    // argc: 引数の数
    // argv: 引数の値（コマンドライン）
    return 0;
}
```

<BaseQuiz id="c-main-1" correct="C">
  <template #question>
    main 関数内の`return 0`は何を示しますか？
  </template>
  
  <BaseQuizOption value="A">プログラムは失敗した</BaseQuizOption>
  <BaseQuizOption value="B">プログラムはまだ実行中である</BaseQuizOption>
  <BaseQuizOption value="C" correct>プログラムは正常に実行された</BaseQuizOption>
  <BaseQuizOption value="D">プログラムは値を返さなかった</BaseQuizOption>
  
  <BaseQuizAnswer>
    C では、main 関数からの`return 0`はプログラムが正常に実行されたことを示します。ゼロ以外の戻り値は通常、エラーまたは異常終了を示します。
  </BaseQuizAnswer>
</BaseQuiz>

### 基本的な出力

コンソールへのテキストと変数の表示。

```c
printf("Hello\n");
printf("Value: %d\n", 42);
// 1 行に複数の値
printf("Name: %s, Age: %d\n", name, age);
```

### 基本的な入力

コンソールからのユーザー入力の読み取り。

```c
int age;
char name[50];
scanf("%d", &age);
scanf("%s", name);
// スペースを含む行全体を読み取る
fgets(name, sizeof(name), stdin);
```

## データ型と変数

### プリミティブ型

さまざまな種類の値を格納するための基本的なデータ型。

```c
// 整数型
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// 浮動小数点型
float price = 19.99f;
double precise = 3.14159265359;
// 文字とブール値（int を使用）
char grade = 'A';
int is_valid = 1;  // 1 は true、0 は false
```

### 配列と文字列

C における配列と文字列の取り扱い。

```c
// 配列
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// 文字列（文字配列）
char name[50] = "John Doe";
char greeting[] = "Hello";
char buffer[100];  // 未初期化
// 文字列の長さとサイズ
int len = strlen(name);
int size = sizeof(buffer);
```

<BaseQuiz id="c-arrays-1" correct="C">
  <template #question>
    C では文字列は何として表現されますか？
  </template>
  
  <BaseQuizOption value="A">特別な文字列型として</BaseQuizOption>
  <BaseQuizOption value="B">整数として</BaseQuizOption>
  <BaseQuizOption value="C" correct>文字の配列として</BaseQuizOption>
  <BaseQuizOption value="D">ポインタのみとして</BaseQuizOption>
  
  <BaseQuizAnswer>
    C では、文字列は文字の配列（`char`）として表現されます。文字列はヌル文字（`\0`）で終端され、これが文字列の終わりを示します。
  </BaseQuizAnswer>
</BaseQuiz>

### 定数と修飾子

不変の値とストレージ修飾子。

```c
// 定数
const int MAX_SIZE = 100;
const double PI = 3.14159;
// プリプロセッサ定数
#define BUFFER_SIZE 512
#define TRUE 1
#define FALSE 0
// ストレージ修飾子
static int count = 0;     // 静的変数
extern int global_var;    // 外部変数
register int fast_var;    // レジスタヒント
```

## 制御フロー構造

### 条件分岐文

条件に基づいた意思決定。

```c
// If-else 文
if (age >= 18) {
    printf("Adult\n");
} else if (age >= 13) {
    printf("Teenager\n");
} else {
    printf("Child\n");
}
// 三項演算子
char* status = (age >= 18) ? "Adult" : "Minor";
// Switch 文
switch (grade) {
    case 'A':
        printf("Excellent!\n");
        break;
    case 'B':
        printf("Good job!\n");
        break;
    default:
        printf("Keep trying!\n");
}
```

### For ループ

カウンターベースのループによる反復処理。

```c
// 従来の for ループ
for (int i = 0; i < 10; i++) {
    printf("%d ", i);
}
// 配列の反復処理
int numbers[] = {1, 2, 3, 4, 5};
int size = sizeof(numbers) / sizeof(numbers[0]);
for (int i = 0; i < size; i++) {
    printf("%d ", numbers[i]);
}
// ネストされたループ
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        printf("%d,%d ", i, j);
    }
}
```

<BaseQuiz id="c-for-loop-1" correct="A">
  <template #question>
    `sizeof(numbers) / sizeof(numbers[0])`は何を計算しますか？
  </template>
  
  <BaseQuizOption value="A" correct>配列の要素数</BaseQuizOption>
  <BaseQuizOption value="B">配列の総メモリサイズ</BaseQuizOption>
  <BaseQuizOption value="C">最後の要素のインデックス</BaseQuizOption>
  <BaseQuizOption value="D">1 つの要素のサイズ</BaseQuizOption>
  
  <BaseQuizAnswer>
    この式は、配列の総サイズを 1 つの要素のサイズで割ることにより、配列の長さを計算します。これは、配列が長さを格納しないため、C で一般的なイディオムです。
  </BaseQuizAnswer>
</BaseQuiz>

### While ループ

条件ベースの反復処理。

```c
// While ループ
int count = 0;
while (count < 5) {
    printf("%d\n", count);
    count++;
}
// Do-while ループ（少なくとも 1 回実行される）
int input;
do {
    printf("Enter a number (0 to quit): ");
    scanf("%d", &input);
} while (input != 0);
```

### ループ制御

`break`と`continue`ステートメント。

```c
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // このイテレーションをスキップ
    }
    if (i == 7) {
        break;    // ループを終了
    }
    printf("%d ", i);
}
// ネストされたループと break
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // 内側のループのみを抜ける
        printf("%d,%d ", i, j);
    }
}
```

## 関数

### 関数宣言と定義

再利用可能なコードブロックの作成。

```c
// 関数宣言（プロトタイプ）
int add(int a, int b);
void printMessage(char* msg);
// 関数定義
int add(int a, int b) {
    return a + b;
}
void printMessage(char* msg) {
    printf("%s\n", msg);
}
// 関数呼び出し
int result = add(5, 3);
printMessage("Hello, functions!");
```

### 配列を関数に渡す

配列を扱う関数。

```c
// パラメータとしての配列（ポインタ）
void printArray(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}
// 配列要素の変更
void doubleValues(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;
    }
}
```

### 再帰関数

自分自身を呼び出す関数。

```c
// 階乗の計算
int factorial(int n) {
    if (n <= 1) {
        return 1;  // ベースケース
    }
    return n * factorial(n - 1);
}
// フィボナッチ数列
int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }
    return fibonacci(n-1) + fibonacci(n-2);
}
```

### 関数ポインタ

動的な動作のための関数へのポインタ。

```c
// 関数ポインタの宣言
int (*operation)(int, int);
// ポインタに関数を割り当て
operation = add;
int result = operation(5, 3);
// 関数ポインタの配列
int (*operations[])(int, int) = {add, subtract, multiply};
result = operations[0](10, 5);
```

## ポインタとメモリ管理

### ポインタの基本

メモリのアドレスを参照し、アクセスするためのポインタの宣言と使用。

```c
int x = 10;
int *ptr = &x;  // x へのポインタ
printf("Value of x: %d\n", x);
printf("Address of x: %p\n", &x);
printf("Value of ptr: %p\n", ptr);
printf("Value pointed by ptr: %d\n", *ptr);
// ポインタ経由での値の変更
*ptr = 20;
printf("New value of x: %d\n", x);
// NULL ポインタ
int *null_ptr = NULL;
```

### 配列とポインタ

配列とポインタの関係。

```c
int arr[5] = {1, 2, 3, 4, 5};
int *p = arr;  // 最初の要素を指す
// 配列表記 vs ポインタ演算
printf("%d\n", arr[2]);   // 配列表記
printf("%d\n", *(p + 2)); // ポインタ演算
printf("%d\n", p[2]);     // 配列としてのポインタ
// ポインタを使用した反復処理
for (int i = 0; i < 5; i++) {
    printf("%d ", *(p + i));
}
```

### 動的メモリ割り当て

実行時にメモリを割り当ておよび解放する。

```c
#include <stdlib.h>
// 単一の整数のためのメモリ割り当て
int *ptr = (int*)malloc(sizeof(int));
if (ptr != NULL) {
    *ptr = 42;
    printf("Value: %d\n", *ptr);
    free(ptr);  // 割り当てられたメモリは必ず解放する
}
// 配列の動的割り当て
int *arr = (int*)malloc(10 * sizeof(int));
if (arr != NULL) {
    for (int i = 0; i < 10; i++) {
        arr[i] = i * i;
    }
    free(arr);
}
```

### 文字列ポインタ

文字列と文字ポインタの操作。

```c
// 文字列リテラルとポインタ
char *str1 = "Hello";           // 文字列リテラル
char str2[] = "World";          // 文字配列
char *str3 = (char*)malloc(20); // 動的文字列
// 文字列関数
strcpy(str3, "Dynamic");
printf("Length: %lu\n", strlen(str1));
printf("Compare: %d\n", strcmp(str1, str2));
strcat(str2, "!");
// 動的文字列は必ず解放する
free(str3);
```

## 構造体とユーザー定義型

### 構造体の定義

複数のフィールドを持つカスタムデータ型の定義。

```c
// 構造体の定義
struct Rectangle {
    double width;
    double height;
};
// typedef 付きの構造体
typedef struct {
    char name[50];
    int age;
    double gpa;
} Student;
// 構造体の作成と初期化
struct Rectangle rect1 = {5.0, 3.0};
Student student1 = {"Alice", 20, 3.75};
// 構造体メンバーへのアクセス
printf("Area: %.2f\n", rect1.width * rect1.height);
printf("Student: %s, Age: %d\n", student1.name, student1.age);
```

### 構造体のネスト

他の構造体を含む構造体。

```c
typedef struct {
    int day, month, year;
} Date;
typedef struct {
    char name[50];
    Date birthdate;
    double salary;
} Employee;
Employee emp = {
    "John Smith",
    {15, 6, 1985},
    50000.0
};
printf("Born: %d/%d/%d\n",
       emp.birthdate.day,
       emp.birthdate.month,
       emp.birthdate.year);
```

### 構造体へのポインタ

構造体へのポインタを使用してアクセスおよび変更する。

```c
Student *student_ptr = &student1;
// ポインタを使用したアクセス（2 つの方法）
printf("Name: %s\n", (*student_ptr).name);
printf("Age: %d\n", student_ptr->age);
// ポインタ経由での変更
student_ptr->age = 21;
strcpy(student_ptr->name, "Alice Johnson");
// 動的構造体割り当て
Student *new_student = (Student*)malloc(sizeof(Student));
if (new_student != NULL) {
    strcpy(new_student->name, "Bob");
    new_student->age = 19;
    new_student->gpa = 3.2;
    free(new_student);
}
```

### 共用体と列挙型

代替のデータ編成方法。

```c
// 共用体 - メモリ空間を共有
union Data {
    int integer;
    float floating;
    char character;
};
union Data data;
data.integer = 42;
printf("Integer: %d\n", data.integer);
// 列挙型
enum Weekday {
    MONDAY, TUESDAY, WEDNESDAY,
    THURSDAY, FRIDAY, SATURDAY, SUNDAY
};
enum Weekday today = FRIDAY;
printf("Today is day %d\n", today);
```

## ファイル入出力操作

### ファイル読み取り

テキストファイルからのデータ読み取り。

```c
#include <stdio.h>
// ファイル全体を文字ごとに読み取る
FILE *file = fopen("data.txt", "r");
if (file != NULL) {
    int ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}
// 1 行ずつ読み取る
FILE *file2 = fopen("lines.txt", "r");
char buffer[256];
while (fgets(buffer, sizeof(buffer), file2) != NULL) {
    printf("Line: %s", buffer);
}
fclose(file2);
// 書式付きデータを読み取る
FILE *numbers = fopen("numbers.txt", "r");
int num;
while (fscanf(numbers, "%d", &num) == 1) {
    printf("Number: %d\n", num);
}
fclose(numbers);
```

### エラーチェック

ファイル操作を安全に処理する。

```c
FILE *file = fopen("data.txt", "r");
if (file == NULL) {
    printf("Error opening file!\n");
    perror("fopen");  // システムエラーメッセージを表示
    return 1;
}
// 読み取りエラーのチェック
if (ferror(file)) {
    printf("Error reading file!\n");
}
// ファイル終端のチェック
if (feof(file)) {
    printf("Reached end of file\n");
}
fclose(file);
```

### ファイル書き込み

テキストファイルへのデータ書き込み。

```c
// ファイルへの書き込み
FILE *outfile = fopen("output.txt", "w");
if (outfile != NULL) {
    fprintf(outfile, "Hello, file!\n");
    fprintf(outfile, "Number: %d\n", 42);
    fclose(outfile);
}
// 既存のファイルへの追記
FILE *appendfile = fopen("log.txt", "a");
if (appendfile != NULL) {
    fprintf(appendfile, "New log entry\n");
    fclose(appendfile);
}
// 配列をファイルに書き込む
int numbers[] = {1, 2, 3, 4, 5};
FILE *numfile = fopen("numbers.txt", "w");
for (int i = 0; i < 5; i++) {
    fprintf(numfile, "%d ", numbers[i]);
}
fclose(numfile);
```

### バイナリファイル操作

バイナリデータの効率的な読み書き。

```c
// バイナリデータの書き込み
Student students[3] = {
    {"Alice", 20, 3.75},
    {"Bob", 21, 3.2},
    {"Charlie", 19, 3.9}
};
FILE *binfile = fopen("students.bin", "wb");
fwrite(students, sizeof(Student), 3, binfile);
fclose(binfile);
// バイナリデータの読み取り
Student loaded_students[3];
FILE *readbin = fopen("students.bin", "rb");
fread(loaded_students, sizeof(Student), 3, readbin);
fclose(readbin);
```

## 文字列操作

### 文字列関数

string.h ライブラリからの一般的な文字列操作。

```c
#include <string.h>
char str1[50] = "Hello";
char str2[] = "World";
char dest[100];
// 文字列長
int len = strlen(str1);
printf("Length: %d\n", len);
// 文字列コピー
strcpy(dest, str1);
strncpy(dest, str1, 10); // 最初の 10 文字をコピー
// 文字列連結
strcat(dest, " ");
strcat(dest, str2);
strncat(dest, "!", 1);   // 1 文字追記
// 文字列比較
int result = strcmp(str1, str2);
if (result == 0) {
    printf("Strings are equal\n");
}
```

### 文字列検索

文字列内での部分文字列や文字の検索。

```c
char text[] = "The quick brown fox";
char *ptr;
// 文字の最初の出現を見つける
ptr = strchr(text, 'q');
if (ptr != NULL) {
    printf("Found 'q' at position: %ld\n", ptr - text);
}
// 最後の出現を見つける
ptr = strrchr(text, 'o');
printf("Last 'o' at position: %ld\n", ptr - text);
// 部分文字列を見つける
ptr = strstr(text, "brown");
if (ptr != NULL) {
    printf("Found 'brown' at: %s\n", ptr);
}
```

### 文字列変換

文字列を数値に、数値を文字列に変換する。

```c
#include <stdlib.h>
// 文字列から数値への変換
char num_str[] = "12345";
char float_str[] = "3.14159";
int num = atoi(num_str);
long long_num = atol(num_str);
double float_num = atof(float_str);
printf("Integer: %d\n", num);
printf("Long: %ld\n", long_num);
printf("Double: %.2f\n", float_num);
// 数値から文字列へ (sprintf を使用)
char buffer[50];
sprintf(buffer, "%d", 42);
sprintf(buffer, "%.2f", 3.14159);
printf("String: %s\n", buffer);
```

### カスタム文字列処理

手動での文字列操作テクニック。

```c
// 文字列内の文字をカウント
int countChar(char *str, char target) {
    int count = 0;
    while (*str) {
        if (*str == target) count++;
        str++;
    }
    return count;
}
// 文字列をインプレースで反転
void reverseString(char *str) {
    int len = strlen(str);
    for (int i = 0; i < len/2; i++) {
        char temp = str[i];
        str[i] = str[len-1-i];
        str[len-1-i] = temp;
    }
}
```

## コンパイルとビルドプロセス

### GCC コンパイル

C 言語用の GNU コンパイラコレクション。

```bash
# 基本的なコンパイル
gcc -o program main.c
# デバッグ情報付き
gcc -g -o program main.c
# 最適化レベル
gcc -O2 -o program main.c
# 複数のソースファイル
gcc -o program main.c utils.c math.c
# 追加のディレクトリを含める
gcc -I/usr/local/include -o program main.c
# ライブラリをリンク
gcc -o program main.c -lm -lpthread
```

### C 標準

特定の C 標準バージョンでコンパイルする。

```bash
# C90/C89標準 (ANSI C)
gcc -std=c89 -o program main.c
# C99標準
gcc -std=c99 -o program main.c
# C11標準（推奨）
gcc -std=c11 -o program main.c
# C18標準（最新）
gcc -std=c18 -o program main.c
# すべての警告を有効にする
gcc -Wall -Wextra -std=c11 -o program main.c
```

### Makefile の基本

make ユーティリティを使用したコンパイルの自動化。

```makefile
# シンプルなMakefile
CC = gcc
CFLAGS = -std=c11 -Wall -g
TARGET = program
SOURCES = main.c utils.c
$(TARGET): $(SOURCES)
$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)
clean:
rm -f $(TARGET)
.PHONY: clean
```

## ベストプラクティスとヒント

### 名前付け規則

一貫した名前付けはコードの可読性を高めます。

```c
// 変数と関数：snake_case
int student_count;
double calculate_average(int scores[], int size);
// 定数：UPPER_CASE
#define MAX_BUFFER_SIZE 1024
#define PI 3.14159
// 構造体：PascalCase または snake_case
typedef struct {
    char name[50];
    int age;
} Student;
// グローバル変数：g_ を接頭辞として付ける
int g_total_count = 0;
// 関数パラメータ：明確な名前
void process_data(int *input_array, int array_size);
```

### メモリ安全性

一般的なメモリ関連のバグを防ぐ。

```c
// 変数は常に初期化する
int count = 0;        // 良い
int count;            // 危険 - 未初期化
// malloc の戻り値をチェックする
int *ptr = malloc(sizeof(int) * 10);
if (ptr == NULL) {
    printf("Memory allocation failed!\n");
    return -1;
}
// 割り当てられたメモリは常に解放する
free(ptr);
ptr = NULL;  // 意図しない再利用を防ぐ
// 配列の境界チェック
for (int i = 0; i < array_size; i++) {
    // 安全な配列アクセス
    array[i] = i;
}
```

### パフォーマンスのヒント

効率的な C コードを書く。

```c
// 適切なデータ型を使用する
char small_num = 10;   // 小さい値用
int normal_num = 1000; // 通常の整数用
// ループ内の関数呼び出しを最小限に抑える
int len = strlen(str); // 一度計算する
for (int i = 0; i < len; i++) {
    // 文字列を処理
}
// 頻繁にアクセスされる変数には register を使用する
register int counter;
// サイズが既知の場合は動的割り当てよりも配列を優先する
int fixed_array[100];  // スタック割り当て
// vs
int *dynamic_array = malloc(100 * sizeof(int));
```

### コードの構成

保守性のためにコードを構造化する。

```c
// ヘッダーファイル (utils.h)
#ifndef UTILS_H
#define UTILS_H
// 関数プロトタイプ
double calculate_area(double radius);
int fibonacci(int n);
// 構造体の定義
typedef struct {
    int x, y;
} Point;
#endif // UTILS_H
// 実装ファイル (utils.c)
#include "utils.h"
#include <math.h>
double calculate_area(double radius) {
    return M_PI * radius * radius;
}
```

## 関連リンク

- <router-link to="/cpp">C++ チートシート</router-link>
- <router-link to="/java">Java チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/golang">Golang チートシート</router-link>
- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>

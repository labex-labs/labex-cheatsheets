---
title: 'C++ チートシート'
description: 'C++ の必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートで学習しましょう。'
pdfUrl: '/cheatsheets/pdf/cpp-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
C++ チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/cpp">Learn C++ with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて C++ プログラミングを学びましょう。LabEx は、必須の構文、オブジェクト指向プログラミング、STL コンテナ、メモリ管理、高度なテクニックを網羅した包括的な C++ コースを提供します。C++ の強力な機能を習得し、高性能なアプリケーションやシステムソフトウェアを構築しましょう。
</base-disclaimer-content>
</base-disclaimer>

## 基本的な構文と構造

### Hello World プログラム

C++ プログラムの基本構造。

```cpp
#include <iostream>
using namespace std;
int main() {
    cout << "Hello, World!" << endl;
    return 0;
}
```

### ヘッダーと名前空間

ライブラリのインクルードと名前空間の管理。

```cpp
#include <iostream>  // 入出力ストリーム
#include <vector>    // 動的配列
#include <string>    // 文字列クラス
#include <algorithm> // STL アルゴリズム
using namespace std;
// 個別に指定することも可能：
// using std::cout;
// using std::cin;
```

### コメント

一行コメントと複数行コメント。

```cpp
// 一行コメント
/*
複数行コメント
複数行にまたがる
*/
// TODO: 機能の実装
/* FIXME: このセクションのバグ */
```

### main 関数

戻り値を持つプログラムのエントリーポイント。

```cpp
int main() {
    // プログラムコードをここに記述
    return 0;  // 成功
}
int main(int argc, char* argv[]) {
    // argc: 引数の数
    // argv: 引数の値 (コマンドライン)
    return 0;
}
```

### 基本的な出力

コンソールへのテキストと変数の表示。

```cpp
cout << "Hello" << endl;
cout << "Value: " << 42 << endl;
// 一行に複数の値
cout << "Name: " << name << ", Age: " << age << endl;
```

### 基本的な入力

コンソールからのユーザー入力の読み取り。

```cpp
int age;
string name;
cin >> age;
cin >> name;
// スペースを含む行全体を読み取る
getline(cin, name);
```

## データ型と変数

### プリミティブ型

さまざまな種類の値を格納するための基本的なデータ型。

```cpp
// 整数型
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// 浮動小数点型
float price = 19.99f;
double precise = 3.14159265359;
// 文字とブール値
char grade = 'A';
bool is_valid = true;
```

### 文字列と配列

テキストとコレクションのデータ型。

```cpp
// 文字列
string name = "John Doe";
string empty_str;
// 配列
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// 動的配列 (ベクター)
vector<int> dynamic_array = {10, 20, 30};
vector<string> names(5); // サイズ 5、空の文字列
```

### 定数と Auto

不変の値と自動的な型推論。

```cpp
// 定数
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Auto キーワード (C++11 以降)
auto x = 42;        // int
auto y = 3.14;      // double
auto name = "John"; // const char*
// 型エイリアス
typedef unsigned int uint;
using real = double;
```

## 制御フロー構造

### 条件文

条件に基づいた意思決定。

```cpp
// If-else 文
if (age >= 18) {
    cout << "Adult" << endl;
} else if (age >= 13) {
    cout << "Teenager" << endl;
} else {
    cout << "Child" << endl;
}
// 三項演算子
string status = (age >= 18) ? "Adult" : "Minor";
// Switch 文
switch (grade) {
    case 'A':
        cout << "Excellent!" << endl;
        break;
    case 'B':
        cout << "Good job!" << endl;
        break;
    default:
        cout << "Keep trying!" << endl;
}
```

### For ループ

カウンターベースのループによる反復処理。

```cpp
// 従来の for ループ
for (int i = 0; i < 10; i++) {
    cout << i << " ";
}
// Range-based for ループ (C++11 以降)
vector<int> numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    cout << num << " ";
}
// Range-based ループでの Auto
for (auto& item : container) {
    // item を処理
}
```

### While ループ

条件ベースの反復処理。

```cpp
// While ループ
int count = 0;
while (count < 5) {
    cout << count << endl;
    count++;
}
// Do-while ループ (少なくとも 1 回実行される)
int input;
do {
    cout << "Enter a number (0 to quit): ";
    cin >> input;
} while (input != 0);
```

### ループ制御

Break と Continue ステートメント。

```cpp
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // イテレーションをスキップ
    }
    if (i == 7) {
        break;    // ループを終了
    }
    cout << i << " ";
}
// ラベル付き break によるネストされたループ
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // 内側のループのみを終了
        cout << i << "," << j << " ";
    }
}
```

## 関数

### 関数宣言と定義

再利用可能なコードブロックの作成。

```cpp
// 関数宣言 (プロトタイプ)
int add(int a, int b);
void printMessage(string msg);
// 関数定義
int add(int a, int b) {
    return a + b;
}
void printMessage(string msg) {
    cout << msg << endl;
}
// 関数呼び出し
int result = add(5, 3);
printMessage("Hello, functions!");
```

### 関数オーバーロード

同じ名前を持つ複数の関数。

```cpp
// パラメータの型が異なる
int multiply(int a, int b) {
    return a * b;
}
double multiply(double a, double b) {
    return a * b;
}
// パラメータの数が異なる
int multiply(int a, int b, int c) {
    return a * b * c;
}
```

### デフォルト引数

関数パラメータのデフォルト値の設定。

```cpp
void greet(string name, string greeting = "Hello") {
    cout << greeting << ", " << name << "!" << endl;
}
// 関数呼び出し
greet("Alice");              // デフォルトの "Hello" を使用
greet("Bob", "Good morning"); // カスタム挨拶を使用
```

### 参照渡し

関数パラメータを介した変数の変更。

```cpp
// 値渡し (コピー)
void changeValue(int x) {
    x = 100; // 元の変数は変更されない
}
// 参照渡し
void changeReference(int& x) {
    x = 100; // 元の変数が変更される
}
// const 参照 (読み取り専用、効率的)
void processLargeData(const vector<int>& data) {
    // データを読み取ることはできるが、変更はできない
}
```

## オブジェクト指向プログラミング

### クラス定義

属性とメソッドを持つカスタムデータ型の定義。

```cpp
class Rectangle {
private:
    double width, height;
public:
    // コンストラクタ
    Rectangle(double w, double h) : width(w), height(h) {}

    // デフォルトコンストラクタ
    Rectangle() : width(0), height(0) {}

    // メンバ関数
    double area() const {
        return width * height;
    }

    void setDimensions(double w, double h) {
        width = w;
        height = h;
    }

    // ゲッター関数
    double getWidth() const { return width; }
    double getHeight() const { return height; }
};
```

### オブジェクトの作成と使用

クラスオブジェクトのインスタンス化と使用。

```cpp
// オブジェクトの作成
Rectangle rect1(5.0, 3.0);
Rectangle rect2; // デフォルトコンストラクタ
// メンバ関数の使用
cout << "Area: " << rect1.area() << endl;
rect2.setDimensions(4.0, 2.0);
// 動的割り当て
Rectangle* rect3 = new Rectangle(6.0, 4.0);
cout << rect3->area() << endl;
delete rect3; // メモリの解放
```

### 継承

基底クラスから派生クラスを作成する。

```cpp
class Shape {
protected:
    string color;

public:
    Shape(string c) : color(c) {}
    virtual double area() const = 0; // 純粋仮想関数
    string getColor() const { return color; }
};
class Circle : public Shape {
private:
    double radius;

public:
    Circle(double r, string c) : Shape(c), radius(r) {}

    double area() const override {
        return 3.14159 * radius * radius;
    }
};
```

### ポリモーフィズム

派生オブジェクトにアクセスするための基底クラスポインタの使用。

```cpp
// 仮想関数とポリモーフィズム
vector<Shape*> shapes;
shapes.push_back(new Circle(5.0, "red"));
shapes.push_back(new Rectangle(4.0, 6.0));
for (Shape* shape : shapes) {
    cout << "Area: " << shape->area() << endl;
    // 適切な派生クラスのメソッドが呼び出される
}
```

## メモリ管理

### 動的メモリ割り当て

実行時におけるメモリの割り当てと解放。

```cpp
// 単一オブジェクト
int* ptr = new int(42);
cout << *ptr << endl;
delete ptr;
ptr = nullptr;
// 配列の割り当て
int* arr = new int[10];
for (int i = 0; i < 10; i++) {
    arr[i] = i * i;
}
delete[] arr;
// 割り当て失敗のチェック
int* large_array = new(nothrow) int[1000000];
if (large_array == nullptr) {
    cout << "Allocation failed!" << endl;
}
```

### スマートポインタ (C++11 以降)

RAII による自動メモリ管理。

```cpp
#include <memory>
// unique_ptr (排他的所有権)
unique_ptr<int> ptr1 = make_unique<int>(42);
unique_ptr<int> ptr2 = move(ptr1); // 所有権を移動
// shared_ptr (共有所有権)
shared_ptr<int> sptr1 = make_shared<int>(100);
shared_ptr<int> sptr2 = sptr1; // 所有権を共有
cout << sptr1.use_count() << endl; // 参照カウント
```

### 参照とポインタ

オブジェクトに間接的にアクセスする 2 つの方法。

```cpp
int x = 10;
// 参照 (エイリアス)
int& ref = x;  // 初期化が必要
ref = 20;      // x を 20 に変更
// ポインタ
int* ptr = &x; // x のアドレスを指す
*ptr = 30;     // 間接参照して x を変更
ptr = nullptr; // 何も指さないようにできる
// const バリエーション
const int* ptr1 = &x;    // 値を変更不可
int* const ptr2 = &x;    // アドレスを変更不可
const int* const ptr3 = &x; // 両方変更不可
```

### スタックとヒープ

メモリ割り当て戦略。

```cpp
// スタック割り当て (自動)
int stack_var = 42;
int stack_array[100];
// ヒープ割り当て (動的)
int* heap_var = new int(42);
int* heap_array = new int[100];
// スタックオブジェクトは自動的にクリーンアップされる
// ヒープオブジェクトは手動で delete する必要がある
delete heap_var;
delete[] heap_array;
```

## 標準テンプレートライブラリ (STL)

### コンテナ：Vector と String

動的配列と文字列操作。

```cpp
#include <vector>
#include <string>
// Vector の操作
vector<int> nums = {1, 2, 3};
nums.push_back(4);        // 要素の追加
nums.pop_back();          // 最後の要素の削除
nums.insert(nums.begin() + 1, 10); // 位置を指定して挿入
nums.erase(nums.begin()); // 最初の要素の削除
// String の操作
string text = "Hello";
text += " World";         // 連結
text.append("!");         // 追加
cout << text.substr(0, 5) << endl; // 部分文字列
text.replace(6, 5, "C++"); // "World" を "C++" に置換
```

### コンテナ：Map と Set

キーと値のペア、および一意な要素のための連想コンテナ。

```cpp
#include <map>
#include <set>
// Map (キーと値のペア)
map<string, int> ages;
ages["Alice"] = 25;
ages["Bob"] = 30;
ages.insert({"Charlie", 35});
// Set (一意な要素)
set<int> unique_nums = {3, 1, 4, 1, 5, 9};
unique_nums.insert(2);
unique_nums.erase(1);
// 自動的にソートされる：{2, 3, 4, 5, 9}
```

### アルゴリズム

一般的な操作のための STL アルゴリズム。

```cpp
#include <algorithm>
vector<int> nums = {64, 34, 25, 12, 22, 11, 90};
// ソート
sort(nums.begin(), nums.end());
sort(nums.rbegin(), nums.rend()); // 降順ソート
// 検索
auto it = find(nums.begin(), nums.end(), 25);
if (it != nums.end()) {
    cout << "Found at position: " << it - nums.begin();
}
// その他の便利なアルゴリズム
reverse(nums.begin(), nums.end());
int max_val = *max_element(nums.begin(), nums.end());
int count = count_if(nums.begin(), nums.end(),
                    [](int x) { return x > 50; });
```

### イテレータ

コンテナ内を効率的に移動するための手段。

```cpp
vector<string> words = {"hello", "world", "cpp"};
// イテレータの型
vector<string>::iterator it;
auto it2 = words.begin(); // C++11 auto
// コンテナの反復処理
for (it = words.begin(); it != words.end(); ++it) {
    cout << *it << " ";
}
// Range-based ループ (推奨)
for (const auto& word : words) {
    cout << word << " ";
}
```

## 入出力操作

### ファイル入力：ファイルの読み取り

テキストファイルからのデータ読み取り。

```cpp
#include <fstream>
#include <sstream>
// ファイル全体を読み取る
ifstream file("data.txt");
if (file.is_open()) {
    string line;
    while (getline(file, line)) {
        cout << line << endl;
    }
    file.close();
}
// 単語ごとに読み取る
ifstream file2("numbers.txt");
int number;
while (file2 >> number) {
    cout << number << " ";
}
// エラーチェック付きの読み取り
if (!file.good()) {
    cerr << "Error reading file!" << endl;
}
```

### 文字列ストリーム処理

文字列をストリームとして解析および操作する。

```cpp
#include <sstream>
// カンマ区切りの値を解析
string data = "apple,banana,cherry";
stringstream ss(data);
string item;
vector<string> fruits;
while (getline(ss, item, ',')) {
    fruits.push_back(item);
}
// 文字列から数値への変換
string num_str = "123";
int num = stoi(num_str);
double d = stod("3.14159");
string back_to_str = to_string(num);
```

### ファイル出力：ファイルへの書き込み

テキストファイルへのデータ書き込み。

```cpp
// ファイルへの書き込み
ofstream outfile("output.txt");
if (outfile.is_open()) {
    outfile << "Hello, file!" << endl;
    outfile << "Number: " << 42 << endl;
    outfile.close();
}
// 既存のファイルへの追記
ofstream appendfile("log.txt", ios::app);
appendfile << "New log entry" << endl;
// ベクターをファイルに書き込む
vector<int> numbers = {1, 2, 3, 4, 5};
ofstream numfile("numbers.txt");
for (int num : numbers) {
    numfile << num << " ";
}
```

### ストリームの書式設定

出力形式と精度を制御する。

```cpp
#include <iomanip>
double pi = 3.14159265;
cout << fixed << setprecision(2) << pi << endl; // 3.14
cout << setw(10) << "Right" << endl;          // 右寄せ
cout << left << setw(10) << "Left" << endl;     // 左寄せ
cout << hex << 255 << endl;                    // 16 進数：ff
```

## エラー処理

### Try-Catch ブロック

実行中に発生する可能性のある例外の処理。

```cpp
try {
    int result = 10 / 0; // 例外をスローする可能性がある
    vector<int> vec(5);
    vec.at(10) = 100;    // 範囲外アクセス

} catch (const exception& e) {
    cout << "Exception caught: " << e.what() << endl;
} catch (...) {
    cout << "Unknown exception caught!" << endl;
}
// 特定の例外型
try {
    string str = "abc";
    int num = stoi(str); // invalid_argument をスロー
} catch (const invalid_argument& e) {
    cout << "Invalid argument: " << e.what() << endl;
} catch (const out_of_range& e) {
    cout << "Out of range: " << e.what() << endl;
}
```

### カスタム例外のスロー

独自の例外を作成してスローする。

```cpp
// カスタム例外クラス
class CustomException : public exception {
    string message;
public:
    CustomException(const string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};
// 例外をスローする関数
void validateAge(int age) {
    if (age < 0 || age > 150) {
        throw CustomException("Invalid age range!");
    }
}
// 使用例
try {
    validateAge(-5);
} catch (const CustomException& e) {
    cout << e.what() << endl;
}
```

### RAII パターン

安全なリソース管理のためのリソース取得は初期化 (RAII)。

```cpp
// スマートポインタによる RAII
{
    unique_ptr<int[]> arr = make_unique<int[]>(1000);
    // スコープを抜けると配列は自動的に削除される
}
// ファイルハンドリングによる RAII
{
    ifstream file("data.txt");
    // スコープを抜けるとファイルは自動的に閉じられる
    if (file.is_open()) {
        // ファイルを処理
    }
}
// カスタム RAII クラス
class FileHandler {
    FILE* file;
public:
    FileHandler(const char* filename) {
        file = fopen(filename, "r");
    }
    ~FileHandler() {
        if (file) fclose(file);
    }
    FILE* get() { return file; }
};
```

### アサーションとデバッグ

プログラムの前提条件の検証とデバッグ。

```cpp
#include <cassert>
#include <iostream>
void processArray(int* arr, int size) {
    assert(arr != nullptr);  // デバッグアサーション
    assert(size > 0);        // 前提条件の検証

    // 配列を処理...
}
// 条件付きコンパイルによるデバッグ出力
#ifdef DEBUG
    #define DBG_PRINT(x) cout << "DEBUG: " << x << endl
#else
    #define DBG_PRINT(x)
#endif
// 使用例
DBG_PRINT("Starting function");
```

## コンパイルとビルドプロセス

### GCC/G++ コンパイル

C++ 用の GNU コンパイラコレクション。

```bash
# 基本的なコンパイル
g++ -o program main.cpp
# デバッグ情報付き
g++ -g -o program main.cpp
# 最適化レベル
g++ -O2 -o program main.cpp
# 複数のソースファイル
g++ -o program main.cpp utils.cpp math.cpp
# 追加のディレクトリを含める
g++ -I/usr/local/include -o program main.cpp
# ライブラリのリンク
g++ -o program main.cpp -lm -lpthread
```

### モダン C++ 標準

特定の C++ 標準バージョンでのコンパイル。

```bash
# C++11標準
g++ -std=c++11 -o program main.cpp
# C++14標準
g++ -std=c++14 -o program main.cpp
# C++17標準 (推奨)
g++ -std=c++17 -o program main.cpp
# C++20標準 (最新)
g++ -std=c++20 -o program main.cpp
# すべての警告を有効にする
g++ -Wall -Wextra -std=c++17 -o program main.cpp
```

### Makefile の基本

make ユーティリティを使用したコンパイルの自動化。

```makefile
# シンプルなMakefile
CXX = g++
CXXFLAGS = -std=c++17 -Wall -g
TARGET = program
SOURCES = main.cpp utils.cpp
$(TARGET): $(SOURCES)
$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES)
clean:
rm -f $(TARGET)
.PHONY: clean
```

## ベストプラクティスとヒント

### 名前付け規則

一貫した名前付けはコードの可読性を高めます。

```cpp
// 変数と関数：snake_case または camelCase
int student_count;
int studentCount;
void calculateAverage();
// 定数：UPPER_CASE
const int MAX_BUFFER_SIZE = 1024;
const double PI = 3.14159;
// クラス：PascalCase
class StudentRecord {
    // メンバ変数：m_ または末尾の _ をプレフィックスとして使用
    string m_name;
    int age_;

public:
    // 公開インターフェース
    void setName(const string& name);
    string getName() const;
};
```

### メモリ安全性

一般的なメモリ関連のバグを防ぐ。

```cpp
// raw pointer の代わりにスマートポインタを使用
auto ptr = make_unique<int>(42);
auto shared = make_shared<vector<int>>(10);
// 変数を初期化する
int count = 0;        // 良い
int count;            // 危険 - 未初期化
// Range-based ループの方が安全
for (const auto& item : container) {
    // item を安全に処理
}
// ポインタの有効性をチェック
if (ptr != nullptr) {
    // 間接参照しても安全
}
```

### パフォーマンスのヒント

効率的な C++ コードの記述。

```cpp
// 大きなオブジェクトは const 参照で渡す
void processData(const vector<int>& data) {
    // 大きなオブジェクトのコピーを避ける
}
// イテレータにはプリインクリメントを使用する
for (auto it = vec.begin(); it != vec.end(); ++it) {
    // ++it は it++ よりも高速な場合がある
}
// サイズがわかっている場合はベクターの容量を予約する
vector<int> numbers;
numbers.reserve(1000); // 再割り当てを回避
// オブジェクトには push よりも emplace を使用する
vector<string> words;
words.emplace_back("Hello"); // インプレースで構築
words.push_back(string("World")); // 構築してからコピー
```

### コードの構成

保守性のためにコードを構造化する。

```cpp
// ヘッダーファイル (utils.h)
#ifndef UTILS_H
#define UTILS_H
class MathUtils {
public:
    static double calculateArea(double radius);
    static int fibonacci(int n);
};
#endif // UTILS_H
// 実装ファイル (utils.cpp)
#include "utils.h"
#include <cmath>
double MathUtils::calculateArea(double radius) {
    return M_PI * radius * radius;
}
// 可能な場合は const メンバ関数を使用する
double getRadius() const { return radius; }
```

## 関連リンク

- <router-link to="/c-programming">C 言語 チートシート</router-link>
- <router-link to="/java">Java チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/golang">Golang チートシート</router-link>
- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>

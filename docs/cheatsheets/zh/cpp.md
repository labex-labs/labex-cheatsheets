---
title: 'C++ 速查表'
description: '使用我们涵盖基本命令、概念和最佳实践的综合 C++ 速查表，快速学习 C++。'
pdfUrl: '/cheatsheets/pdf/cpp-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
C++ 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/cpp">使用实践实验室学习 C++</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 C++ 编程。LabEx 提供全面的 C++ 课程，涵盖基本语法、面向对象编程、STL 容器、内存管理和高级技术。掌握 C++ 的强大功能，构建高性能应用程序和系统软件。
</base-disclaimer-content>
</base-disclaimer>

## 基本语法与结构

### Hello World 程序

C++ 程序的结构基础。

```cpp
#include <iostream>
using namespace std;
int main() {
    cout << "Hello, World!" << endl;
    return 0;
}
```

### 头文件与命名空间

包含库并管理命名空间。

```cpp
#include <iostream>  // 输入/输出流
#include <vector>    // 动态数组
#include <string>    // 字符串类
#include <algorithm> // STL 算法
using namespace std;
// 或单独指定：
// using std::cout;
// using std::cin;
```

### 注释

单行和多行注释。

```cpp
// 单行注释
/*
多行注释
跨越多行
*/
// TODO: 实现功能
/* FIXME: 此处有 Bug */
```

### Main 函数

程序的入口点及返回值。

```cpp
int main() {
    // 程序代码在此处
    return 0;  // 成功
}
int main(int argc, char* argv[]) {
    // argc: 参数数量
    // argv: 参数值 (命令行)
    return 0;
}
```

### 基本输出

向控制台显示文本和变量。

```cpp
cout << "Hello" << endl;
cout << "值：" << 42 << endl;
// 一行中的多个值
cout << "姓名：" << name << ", 年龄：" << age << endl;
```

### 基本输入

从控制台读取用户输入。

```cpp
int age;
string name;
cin >> age;
cin >> name;
// 读取包含空格的整行
getline(cin, name);
```

## 数据类型与变量

### 原始类型

用于存储不同种类值的基本数据类型。

```cpp
// 整数类型
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// 浮点类型
float price = 19.99f;
double precise = 3.14159265359;
// 字符和布尔值
char grade = 'A';
bool is_valid = true;
```

### 字符串与数组

文本和集合数据类型。

```cpp
// 字符串
string name = "John Doe";
string empty_str;
// 数组
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// 动态数组 (向量)
vector<int> dynamic_array = {10, 20, 30};
vector<string> names(5); // 大小为 5，空字符串
```

### 常量与 Auto

不可变值和自动类型推导。

```cpp
// 常量
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Auto 关键字 (C++11+)
auto x = 42;        // int
auto y = 3.14;      // double
auto name = "John"; // const char*
// 类型别名
typedef unsigned int uint;
using real = double;
```

## 控制流结构

### 条件语句

基于条件做出决策。

```cpp
// If-else 语句
if (age >= 18) {
    cout << "成年人" << endl;
} else if (age >= 13) {
    cout << "青少年" << endl;
} else {
    cout << "儿童" << endl;
}
// 三元运算符
string status = (age >= 18) ? "成年人" : "未成年人";
// Switch 语句
switch (grade) {
    case 'A':
        cout << "优秀！" << endl;
        break;
    case 'B':
        cout << "干得好！" << endl;
        break;
    default:
        cout << "继续努力！" << endl;
}
```

### For 循环

使用基于计数器的循环进行迭代。

```cpp
// 传统 for 循环
for (int i = 0; i < 10; i++) {
    cout << i << " ";
}
// 基于范围的 for 循环 (C++11+)
vector<int> numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    cout << num << " ";
}
// 带有 auto 的基于范围的循环
for (auto& item : container) {
    // 处理 item
}
```

### While 循环

基于条件的迭代。

```cpp
// While 循环
int count = 0;
while (count < 5) {
    cout << count << endl;
    count++;
}
// Do-while 循环 (至少执行一次)
int input;
do {
    cout << "输入一个数字 (0 退出): ";
    cin >> input;
} while (input != 0);
```

### 循环控制

Break 和 continue 语句。

```cpp
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // 跳过本次迭代
    }
    if (i == 7) {
        break;    // 退出循环
    }
    cout << i << " ";
}
// 带有标签的嵌套循环的 break
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // 只跳出内层循环
        cout << i << "," << j << " ";
    }
}
```

## 函数

### 函数声明与定义

创建可重用代码块。

```cpp
// 函数声明 (原型)
int add(int a, int b);
void printMessage(string msg);
// 函数定义
int add(int a, int b) {
    return a + b;
}
void printMessage(string msg) {
    cout << msg << endl;
}
// 函数调用
int result = add(5, 3);
printMessage("Hello, functions!");
```

### 函数重载

多个同名函数。

```cpp
// 不同参数类型
int multiply(int a, int b) {
    return a * b;
}
double multiply(double a, double b) {
    return a * b;
}
// 不同参数数量
int multiply(int a, int b, int c) {
    return a * b * c;
}
```

### 默认参数

为函数参数提供默认值。

```cpp
void greet(string name, string greeting = "Hello") {
    cout << greeting << ", " << name << "!" << endl;
}
// 函数调用
greet("Alice");              // 使用默认的 "Hello"
greet("Bob", "Good morning"); // 使用自定义的问候语
```

### 按引用传递

通过函数参数修改变量。

```cpp
// 按值传递 (复制)
void changeValue(int x) {
    x = 100; // 原始变量未改变
}
// 按引用传递
void changeReference(int& x) {
    x = 100; // 原始变量被修改
}
// Const 引用 (只读，高效)
void processLargeData(const vector<int>& data) {
    // 可以读取数据但不能修改
}
```

## 面向对象编程

### 类定义

定义具有属性和方法的自定义数据类型。

```cpp
class Rectangle {
private:
    double width, height;
public:
    // 构造函数
    Rectangle(double w, double h) : width(w), height(h) {}

    // 默认构造函数
    Rectangle() : width(0), height(0) {}

    // 成员函数
    double area() const {
        return width * height;
    }

    void setDimensions(double w, double h) {
        width = w;
        height = h;
    }

    // Getter 函数
    double getWidth() const { return width; }
    double getHeight() const { return height; }
};
```

### 对象创建与使用

实例化和使用类对象。

```cpp
// 创建对象
Rectangle rect1(5.0, 3.0);
Rectangle rect2; // 默认构造函数
// 使用成员函数
cout << "面积：" << rect1.area() << endl;
rect2.setDimensions(4.0, 2.0);
// 动态分配
Rectangle* rect3 = new Rectangle(6.0, 4.0);
cout << rect3->area() << endl;
delete rect3; // 清理内存
```

### 继承

从基类创建派生类。

```cpp
class Shape {
protected:
    string color;

public:
    Shape(string c) : color(c) {}
    virtual double area() const = 0; // 纯虚函数
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

### 多态性

使用基类指针访问派生对象。

```cpp
// 虚函数和多态性
vector<Shape*> shapes;
shapes.push_back(new Circle(5.0, "red"));
shapes.push_back(new Rectangle(4.0, 6.0));
for (Shape* shape : shapes) {
    cout << "面积：" << shape->area() << endl;
    // 调用相应的派生类方法
}
```

## 内存管理

### 动态内存分配

在运行时分配和释放内存。

```cpp
// 单个对象
int* ptr = new int(42);
cout << *ptr << endl;
delete ptr;
ptr = nullptr;
// 数组分配
int* arr = new int[10];
for (int i = 0; i < 10; i++) {
    arr[i] = i * i;
}
delete[] arr;
// 检查分配失败
int* large_array = new(nothrow) int[1000000];
if (large_array == nullptr) {
    cout << "分配失败！" << endl;
}
```

### 智能指针 (C++11+)

使用 RAII 进行自动内存管理。

```cpp
#include <memory>
// unique_ptr (独占所有权)
unique_ptr<int> ptr1 = make_unique<int>(42);
unique_ptr<int> ptr2 = move(ptr1); // 转移所有权
// shared_ptr (共享所有权)
shared_ptr<int> sptr1 = make_shared<int>(100);
shared_ptr<int> sptr2 = sptr1; // 共享所有权
cout << sptr1.use_count() << endl; // 引用计数
```

### 引用与指针

间接访问对象的两种方式。

```cpp
int x = 10;
// 引用 (别名)
int& ref = x;  // 必须初始化
ref = 20;      // 改变 x 为 20
// 指针
int* ptr = &x; // 指向 x 的地址
*ptr = 30;     // 解引用并改变 x
ptr = nullptr; // 可以指向空
// Const 变体
const int* ptr1 = &x;    // 不能改变值
int* const ptr2 = &x;    // 不能改变地址
const int* const ptr3 = &x; // 两者都不能改变
```

### 栈与堆

内存分配策略。

```cpp
// 栈分配 (自动)
int stack_var = 42;
int stack_array[100];
// 堆分配 (动态)
int* heap_var = new int(42);
int* heap_array = new int[100];
// 栈对象自动清理
// 堆对象必须手动删除
delete heap_var;
delete[] heap_array;
```

## 标准模板库 (STL)

### 容器：Vector 与 String

动态数组和字符串操作。

```cpp
#include <vector>
#include <string>
// Vector 操作
vector<int> nums = {1, 2, 3};
nums.push_back(4);        // 添加元素
nums.pop_back();          // 移除最后一个
nums.insert(nums.begin() + 1, 10); // 在位置 1 插入 10
nums.erase(nums.begin()); // 移除第一个
// String 操作
string text = "Hello";
text += " World";         // 拼接
text.append("!");         // 追加
cout << text.substr(0, 5) << endl; // 子字符串
text.replace(6, 5, "C++"); // 将 "World" 替换为 "C++"
```

### 容器：Map 与 Set

用于键值对和唯一元素的关联容器。

```cpp
#include <map>
#include <set>
// Map (键值对)
map<string, int> ages;
ages["Alice"] = 25;
ages["Bob"] = 30;
ages.insert({"Charlie", 35});
// Set (唯一元素)
set<int> unique_nums = {3, 1, 4, 1, 5, 9};
unique_nums.insert(2);
unique_nums.erase(1);
// 自动排序：{2, 3, 4, 5, 9}
```

### 算法

用于常见操作的 STL 算法。

```cpp
#include <algorithm>
vector<int> nums = {64, 34, 25, 12, 22, 11, 90};
// 排序
sort(nums.begin(), nums.end());
sort(nums.rbegin(), nums.rend()); // 降序排序
// 查找
auto it = find(nums.begin(), nums.end(), 25);
if (it != nums.end()) {
    cout << "找到位置：" << it - nums.begin();
}
// 其他有用算法
reverse(nums.begin(), nums.end());
int max_val = *max_element(nums.begin(), nums.end());
int count = count_if(nums.begin(), nums.end(),
                    [](int x) { return x > 50; });
```

### 迭代器

高效地遍历容器。

```cpp
vector<string> words = {"hello", "world", "cpp"};
// 迭代器类型
vector<string>::iterator it;
auto it2 = words.begin(); // C++11 auto
// 遍历容器
for (it = words.begin(); it != words.end(); ++it) {
    cout << *it << " ";
}
// 基于范围的循环 (首选)
for (const auto& word : words) {
    cout << word << " ";
}
```

## 输入/输出操作

### 文件输入：读取文件

从文本文件读取数据。

```cpp
#include <fstream>
#include <sstream>
// 读取整个文件
ifstream file("data.txt");
if (file.is_open()) {
    string line;
    while (getline(file, line)) {
        cout << line << endl;
    }
    file.close();
}
// 按单词读取
ifstream file2("numbers.txt");
int number;
while (file2 >> number) {
    cout << number << " ";
}
// 带错误检查
if (!file.good()) {
    cerr << "读取文件错误！" << endl;
}
```

### 字符串流处理

将字符串作为流进行解析和操作。

```cpp
#include <sstream>
// 解析逗号分隔值
string data = "apple,banana,cherry";
stringstream ss(data);
string item;
vector<string> fruits;
while (getline(ss, item, ',')) {
    fruits.push_back(item);
}
// 字符串转数字
string num_str = "123";
int num = stoi(num_str);
double d = stod("3.14159");
string back_to_str = to_string(num);
```

### 文件输出：写入文件

将数据写入文本文件。

```cpp
// 写入文件
ofstream outfile("output.txt");
if (outfile.is_open()) {
    outfile << "Hello, file!" << endl;
    outfile << "数字：" << 42 << endl;
    outfile.close();
}
// 追加到现有文件
ofstream appendfile("log.txt", ios::app);
appendfile << "新的日志条目" << endl;
// 将 vector 写入文件
vector<int> numbers = {1, 2, 3, 4, 5};
ofstream numfile("numbers.txt");
for (int num : numbers) {
    numfile << num << " ";
}
```

### 流格式化

控制输出格式和精度。

```cpp
#include <iomanip>
double pi = 3.14159265;
cout << fixed << setprecision(2) << pi << endl; // 3.14
cout << setw(10) << "右对齐" << endl;          // 右对齐
cout << left << setw(10) << "左对齐" << endl;     // 左对齐
cout << hex << 255 << endl;                    // 十六进制：ff
```

## 错误处理

### Try-Catch 块

处理执行期间可能发生的异常。

```cpp
try {
    int result = 10 / 0; // 这可能会抛出异常
    vector<int> vec(5);
    vec.at(10) = 100;    // 越界访问

} catch (const exception& e) {
    cout << "捕获到异常：" << e.what() << endl;
} catch (...) {
    cout << "捕获到未知异常！" << endl;
}
// 特定异常类型
try {
    string str = "abc";
    int num = stoi(str); // 抛出 invalid_argument
} catch (const invalid_argument& e) {
    cout << "无效参数：" << e.what() << endl;
} catch (const out_of_range& e) {
    cout << "超出范围：" << e.what() << endl;
}
```

### 抛出自定义异常

创建并抛出自己的异常。

```cpp
// 自定义异常类
class CustomException : public exception {
    string message;
public:
    CustomException(const string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};
// 抛出异常的函数
void validateAge(int age) {
    if (age < 0 || age > 150) {
        throw CustomException("无效的年龄范围！");
    }
}
// 用法
try {
    validateAge(-5);
} catch (const CustomException& e) {
    cout << e.what() << endl;
}
```

### RAII 模式

用于安全资源管理的初始化资源获取。

```cpp
// 智能指针的 RAII
{
    unique_ptr<int[]> arr = make_unique<int[]>(1000);
    // 数组在超出作用域时自动删除
}
// 文件处理的 RAII
{
    ifstream file("data.txt");
    // 文件在超出作用域时自动关闭
    if (file.is_open()) {
        // 处理文件
    }
}
// 自定义 RAII 类
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

### 断言与调试

调试和验证程序假设。

```cpp
#include <cassert>
#include <iostream>
void processArray(int* arr, int size) {
    assert(arr != nullptr);  // 调试断言
    assert(size > 0);        // 验证假设

    // 处理数组...
}
// 条件编译用于调试输出
#ifdef DEBUG
    #define DBG_PRINT(x) cout << "DEBUG: " << x << endl
#else
    #define DBG_PRINT(x)
#endif
// 用法
DBG_PRINT("开始函数");
```

## 编译与构建过程

### GCC/G++ 编译

用于 C++ 的 GNU 编译器集合。

```bash
# 基本编译
g++ -o program main.cpp
# 包含调试信息
g++ -g -o program main.cpp
# 优化级别
g++ -O2 -o program main.cpp
# 多个源文件
g++ -o program main.cpp utils.cpp math.cpp
# 包含附加目录
g++ -I/usr/local/include -o program main.cpp
# 链接库
g++ -o program main.cpp -lm -lpthread
```

### 现代 C++ 标准

使用特定 C++ 标准版本进行编译。

```bash
# C++11 标准
g++ -std=c++11 -o program main.cpp
# C++14 标准
g++ -std=c++14 -o program main.cpp
# C++17 标准 (推荐)
g++ -std=c++17 -o program main.cpp
# C++20 标准 (最新)
g++ -std=c++20 -o program main.cpp
# 启用所有警告
g++ -Wall -Wextra -std=c++17 -o program main.cpp
```

### Makefile 基础

使用 make 工具自动化编译。

```makefile
# 简单的 Makefile
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

## 最佳实践与技巧

### 命名约定

一致的命名使代码更具可读性。

```cpp
// 变量和函数：snake_case 或 camelCase
int student_count;
int studentCount;
void calculateAverage();
// 常量：UPPER_CASE
const int MAX_BUFFER_SIZE = 1024;
const double PI = 3.14159;
// 类：PascalCase
class StudentRecord {
    // 成员变量：前缀 m_ 或后缀 _
    string m_name;
    int age_;

public:
    // 公共接口
    void setName(const string& name);
    string getName() const;
};
```

### 内存安全

防止常见的内存相关错误。

```cpp
// 使用智能指针代替原始指针
auto ptr = make_unique<int>(42);
auto shared = make_shared<vector<int>>(10);
// 初始化变量
int count = 0;        // 好
int count;            // 危险 - 未初始化
// 基于范围的循环更安全
for (const auto& item : container) {
    // 安全地处理 item
}
// 检查指针有效性
if (ptr != nullptr) {
    // 可以安全地解引用
}
```

### 性能提示

编写高效的 C++ 代码。

```cpp
// 传递大对象时使用 const 引用
void processData(const vector<int>& data) {
    // 避免复制大对象
}
// 对迭代器使用前缀自增
for (auto it = vec.begin(); it != vec.end(); ++it) {
    // ++it 通常比 it++ 更快
}
// 在已知大小时预留 vector 容量
vector<int> numbers;
numbers.reserve(1000); // 避免重新分配
// 对对象使用 emplace 而不是 push
vector<string> words;
words.emplace_back("Hello"); // 原位构造
words.push_back(string("World")); // 构造后复制
```

### 代码组织

构建可维护的代码结构。

```cpp
// 头文件 (utils.h)
#ifndef UTILS_H
#define UTILS_H
class MathUtils {
public:
    static double calculateArea(double radius);
    static int fibonacci(int n);
};
#endif // UTILS_H
// 实现文件 (utils.cpp)
#include "utils.h"
#include <cmath>
double MathUtils::calculateArea(double radius) {
    return M_PI * radius * radius;
}
// 尽可能使用 const 成员函数
double getRadius() const { return radius; }
```

## 相关链接

- <router-link to="/c-programming">C 编程速查表</router-link>
- <router-link to="/java">Java 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/golang">Golang 速查表</router-link>
- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>

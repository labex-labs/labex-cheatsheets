---
title: 'C 语言速查表 | LabEx'
description: '使用本综合 C 语言速查表快速学习 C 编程。包含 C 语法、指针、内存管理、数据结构和系统编程要点的快速参考，专为开发者设计。'
pdfUrl: '/cheatsheets/pdf/c-programming-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
C 编程速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/c">通过实践实验室学习 C 编程</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 C 编程。LabEx 提供全面的 C 课程，涵盖基本语法、内存管理、指针、数据结构和高级技术。掌握 C 的强大功能，以构建高效的系统级应用程序并理解底层编程概念。
</base-disclaimer-content>
</base-disclaimer>

## 基本语法与结构

### Hello World 程序

C 程序的结构基础。

```c
#include <stdio.h>
int main() {
    printf("Hello, World!\n");
    return 0;
}
```

### 头文件与预处理器

包含库和使用预处理器指令。

```c
#include <stdio.h>    // 标准输入/输出
#include <stdlib.h>   // 标准库
#include <string.h>   // 字符串函数
#include <math.h>     // 数学函数
#define PI 3.14159
#define MAX_SIZE 100
```

### 注释

单行和多行注释。

```c
// 单行注释
/*
多行注释
跨越多行
*/
// TODO: 实现功能
/* FIXME: 此处有错误 */
```

### Main 函数

程序的入口点及返回值。

```c
int main() {
    // 程序的代码放在这里
    return 0;  // 成功
}
int main(int argc, char *argv[]) {
    // argc: 参数数量
    // argv: 参数值 (命令行)
    return 0;
}
```

<BaseQuiz id="c-main-1" correct="C">
  <template #question>
    在 main 函数中 `return 0` 表示什么？
  </template>
  
  <BaseQuizOption value="A">程序失败</BaseQuizOption>
  <BaseQuizOption value="B">程序仍在运行</BaseQuizOption>
  <BaseQuizOption value="C" correct>程序成功执行</BaseQuizOption>
  <BaseQuizOption value="D">程序未返回值</BaseQuizOption>
  
  <BaseQuizAnswer>
    在 C 语言中，从 main 函数 `return 0` 表示程序成功执行。非零返回值通常表示错误或异常终止。
  </BaseQuizAnswer>
</BaseQuiz>

### 基本输出

向控制台显示文本和变量。

```c
printf("Hello\n");
printf("Value: %d\n", 42);
// 一行中的多个值
printf("Name: %s, Age: %d\n", name, age);
```

### 基本输入

从控制台读取用户输入。

```c
int age;
char name[50];
scanf("%d", &age);
scanf("%s", name);
// 使用 fgets 读取包含空格的整行
fgets(name, sizeof(name), stdin);
```

## 数据类型与变量

### 基本类型

用于存储不同类型值的基本数据类型。

```c
// 整数类型
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// 浮点类型
float price = 19.99f;
double precise = 3.14159265359;
// 字符和布尔值 (使用 int)
char grade = 'A';
int is_valid = 1;  // 1 表示 true, 0 表示 false
```

### 数组与字符串

C 中的数组和字符串处理。

```c
// 数组
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// 字符串 (字符数组)
char name[50] = "John Doe";
char greeting[] = "Hello";
char buffer[100];  // 未初始化
// 字符串长度和大小
int len = strlen(name);
int size = sizeof(buffer);
```

<BaseQuiz id="c-arrays-1" correct="C">
  <template #question>
    C 语言中字符串是如何表示的？
  </template>
  
  <BaseQuizOption value="A">作为特殊的字符串类型</BaseQuizOption>
  <BaseQuizOption value="B">作为整数</BaseQuizOption>
  <BaseQuizOption value="C" correct>作为字符数组</BaseQuizOption>
  <BaseQuizOption value="D">仅作为指针</BaseQuizOption>
  
  <BaseQuizAnswer>
    在 C 语言中，字符串表示为字符数组 (`char`)。字符串以空字符 (`\0`) 结尾，该字符标记了字符串的末尾。
  </BaseQuizAnswer>
</BaseQuiz>

### 常量与修饰符

不可变值和存储修饰符。

```c
// 常量
const int MAX_SIZE = 100;
const double PI = 3.14159;
// 预处理器常量
#define BUFFER_SIZE 512
#define TRUE 1
#define FALSE 0
// 存储修饰符
static int count = 0;     // 静态变量
extern int global_var;    // 外部变量
register int fast_var;    // 寄存器提示
```

## 控制流结构

### 条件语句

基于条件做出决策。

```c
// If-else 语句
if (age >= 18) {
    printf("Adult\n");
} else if (age >= 13) {
    printf("Teenager\n");
} else {
    printf("Child\n");
}
// 三元运算符
char* status = (age >= 18) ? "Adult" : "Minor";
// Switch 语句
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

### For 循环

基于计数器的循环迭代。

```c
// 传统的 for 循环
for (int i = 0; i < 10; i++) {
    printf("%d ", i);
}
// 数组迭代
int numbers[] = {1, 2, 3, 4, 5};
int size = sizeof(numbers) / sizeof(numbers[0]);
for (int i = 0; i < size; i++) {
    printf("%d ", numbers[i]);
}
// 嵌套循环
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        printf("%d,%d ", i, j);
    }
}
```

<BaseQuiz id="c-for-loop-1" correct="A">
  <template #question>
    `sizeof(numbers) / sizeof(numbers[0])` 计算的是什么？
  </template>
  
  <BaseQuizOption value="A" correct>数组中的元素数量</BaseQuizOption>
  <BaseQuizOption value="B">数组的总内存大小</BaseQuizOption>
  <BaseQuizOption value="C">最后一个元素的索引</BaseQuizOption>
  <BaseQuizOption value="D">一个元素的大小</BaseQuizOption>
  
  <BaseQuizAnswer>
    该表达式通过将数组的总大小除以一个元素的大小来计算数组的长度。这是 C 语言中的常见惯用法，因为数组本身不存储其长度。
  </BaseQuizAnswer>
</BaseQuiz>

### While 循环

基于条件的迭代。

```c
// While 循环
int count = 0;
while (count < 5) {
    printf("%d\n", count);
    count++;
}
// Do-while 循环 (至少执行一次)
int input;
do {
    printf("Enter a number (0 to quit): ");
    scanf("%d", &input);
} while (input != 0);
```

### 循环控制

Break 和 continue 语句。

```c
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // 跳过本次迭代
    }
    if (i == 7) {
        break;    // 退出循环
    }
    printf("%d ", i);
}
// 嵌套循环与 break
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // 只跳出内层循环
        printf("%d,%d ", i, j);
    }
}
```

## 函数

### 函数声明与定义

创建可重用的代码块。

```c
// 函数声明 (原型)
int add(int a, int b);
void printMessage(char* msg);
// 函数定义
int add(int a, int b) {
    return a + b;
}
void printMessage(char* msg) {
    printf("%s\n", msg);
}
// 函数调用
int result = add(5, 3);
printMessage("Hello, functions!");
```

### 向函数传递数组

处理数组的函数。

```c
// 数组作为参数 (指针)
void printArray(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}
// 修改数组元素
void doubleValues(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;
    }
}
```

### 递归函数

调用自身的函数。

```c
// 阶乘计算
int factorial(int n) {
    if (n <= 1) {
        return 1;  // 基准情况
    }
    return n * factorial(n - 1);
}
// 斐波那契数列
int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }
    return fibonacci(n-1) + fibonacci(n-2);
}
```

### 函数指针

用于动态行为的函数指针。

```c
// 函数指针声明
int (*operation)(int, int);
// 将函数赋值给指针
operation = add;
int result = operation(5, 3);
// 函数指针数组
int (*operations[])(int, int) = {add, subtract, multiply};
result = operations[0](10, 5);
```

## 指针与内存管理

### 指针基础

声明和使用指针来访问内存地址。

```c
int x = 10;
int *ptr = &x;  // x 的指针
printf("Value of x: %d\n", x);
printf("Address of x: %p\n", &x);
printf("Value of ptr: %p\n", ptr);
printf("Value pointed by ptr: %d\n", *ptr);
// 通过指针修改值
*ptr = 20;
printf("New value of x: %d\n", x);
// 空指针
int *null_ptr = NULL;
```

### 数组与指针

数组和指针之间的关系。

```c
int arr[5] = {1, 2, 3, 4, 5};
int *p = arr;  // 指向第一个元素
// 数组表示法 vs 指针算术
printf("%d\n", arr[2]);   // 数组表示法
printf("%d\n", *(p + 2)); // 指针算术
printf("%d\n", p[2]);     // 将指针当作数组使用
// 使用指针迭代
for (int i = 0; i < 5; i++) {
    printf("%d ", *(p + i));
}
```

### 动态内存分配

在运行时分配和释放内存。

```c
#include <stdlib.h>
// 为单个整数分配内存
int *ptr = (int*)malloc(sizeof(int));
if (ptr != NULL) {
    *ptr = 42;
    printf("Value: %d\n", *ptr);
    free(ptr);  // 始终释放分配的内存
}
// 动态分配数组
int *arr = (int*)malloc(10 * sizeof(int));
if (arr != NULL) {
    for (int i = 0; i < 10; i++) {
        arr[i] = i * i;
    }
    free(arr);
}
```

### 字符串指针

处理字符串和字符指针。

```c
// 字符串字面量和指针
char *str1 = "Hello";           // 字符串字面量
char str2[] = "World";          // 字符数组
char *str3 = (char*)malloc(20); // 动态字符串
// 字符串函数
strcpy(str3, "Dynamic");
printf("Length: %lu\n", strlen(str1));
printf("Compare: %d\n", strcmp(str1, str2));
strcat(str2, "!");
// 始终释放动态字符串
free(str3);
```

## 结构体与用户定义类型

### 结构体定义

定义具有多个字段的自定义数据类型。

```c
// 结构体定义
struct Rectangle {
    double width;
    double height;
};
// 带 typedef 的结构体
typedef struct {
    char name[50];
    int age;
    double gpa;
} Student;
// 创建和初始化结构体
struct Rectangle rect1 = {5.0, 3.0};
Student student1 = {"Alice", 20, 3.75};
// 访问结构体成员
printf("Area: %.2f\n", rect1.width * rect1.height);
printf("Student: %s, Age: %d\n", student1.name, student1.age);
```

### 嵌套结构体

包含其他结构的结构体。

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

### 结构体指针

使用指针访问和修改结构体。

```c
Student *student_ptr = &student1;
// 通过指针访问 (两种方法)
printf("Name: %s\n", (*student_ptr).name);
printf("Age: %d\n", student_ptr->age);
// 通过指针修改
student_ptr->age = 21;
strcpy(student_ptr->name, "Alice Johnson");
// 动态结构体分配
Student *new_student = (Student*)malloc(sizeof(Student));
if (new_student != NULL) {
    strcpy(new_student->name, "Bob");
    new_student->age = 19;
    new_student->gpa = 3.2;
    free(new_student);
}
```

### 联合体和枚举

替代的数据组织方法。

```c
// 联合体 - 共享内存空间
union Data {
    int integer;
    float floating;
    char character;
};
union Data data;
data.integer = 42;
printf("Integer: %d\n", data.integer);
// 枚举
enum Weekday {
    MONDAY, TUESDAY, WEDNESDAY,
    THURSDAY, FRIDAY, SATURDAY, SUNDAY
};
enum Weekday today = FRIDAY;
printf("Today is day %d\n", today);
```

## 文件输入/输出操作

### 文件读取

从文本文件读取数据。

```c
#include <stdio.h>
// 按字符读取整个文件
FILE *file = fopen("data.txt", "r");
if (file != NULL) {
    int ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}
// 按行读取
FILE *file2 = fopen("lines.txt", "r");
char buffer[256];
while (fgets(buffer, sizeof(buffer), file2) != NULL) {
    printf("Line: %s", buffer);
}
fclose(file2);
// 读取格式化数据
FILE *numbers = fopen("numbers.txt", "r");
int num;
while (fscanf(numbers, "%d", &num) == 1) {
    printf("Number: %d\n", num);
}
fclose(numbers);
```

### 错误检查

安全处理文件操作。

```c
FILE *file = fopen("data.txt", "r");
if (file == NULL) {
    printf("Error opening file!\n");
    perror("fopen");  // 打印系统错误信息
    return 1;
}
// 检查读取错误
if (ferror(file)) {
    printf("Error reading file!\n");
}
// 检查文件结束
if (feof(file)) {
    printf("Reached end of file\n");
}
fclose(file);
```

### 文件写入

向文本文件写入数据。

```c
// 写入文件
FILE *outfile = fopen("output.txt", "w");
if (outfile != NULL) {
    fprintf(outfile, "Hello, file!\n");
    fprintf(outfile, "Number: %d\n", 42);
    fclose(outfile);
}
// 追加到现有文件
FILE *appendfile = fopen("log.txt", "a");
if (appendfile != NULL) {
    fprintf(appendfile, "New log entry\n");
    fclose(appendfile);
}
// 写入数组到文件
int numbers[] = {1, 2, 3, 4, 5};
FILE *numfile = fopen("numbers.txt", "w");
for (int i = 0; i < 5; i++) {
    fprintf(numfile, "%d ", numbers[i]);
}
fclose(numfile);
```

### 二进制文件操作

高效地读写二进制数据。

```c
// 写入二进制数据
Student students[3] = {
    {"Alice", 20, 3.75},
    {"Bob", 21, 3.2},
    {"Charlie", 19, 3.9}
};
FILE *binfile = fopen("students.bin", "wb");
fwrite(students, sizeof(Student), 3, binfile);
fclose(binfile);
// 读取二进制数据
Student loaded_students[3];
FILE *readbin = fopen("students.bin", "rb");
fread(loaded_students, sizeof(Student), 3, readbin);
fclose(readbin);
```

## 字符串操作

### 字符串函数

来自 string.h 库的常见字符串操作。

```c
#include <string.h>
char str1[50] = "Hello";
char str2[] = "World";
char dest[100];
// 字符串长度
int len = strlen(str1);
printf("Length: %d\n", len);
// 字符串复制
strcpy(dest, str1);
strncpy(dest, str1, 10); // 复制前 10 个字符
// 字符串连接
strcat(dest, " ");
strcat(dest, str2);
strncat(dest, "!", 1);   // 追加 1 个字符
// 字符串比较
int result = strcmp(str1, str2);
if (result == 0) {
    printf("Strings are equal\n");
}
```

### 字符串搜索

在字符串中查找子串和字符。

```c
char text[] = "The quick brown fox";
char *ptr;
// 查找字符的第一次出现
ptr = strchr(text, 'q');
if (ptr != NULL) {
    printf("Found 'q' at position: %ld\n", ptr - text);
}
// 查找最后一次出现
ptr = strrchr(text, 'o');
printf("Last 'o' at position: %ld\n", ptr - text);
// 查找子串
ptr = strstr(text, "brown");
if (ptr != NULL) {
    printf("Found 'brown' at: %s\n", ptr);
}
```

### 字符串转换

将字符串转换为数字，反之亦然。

```c
#include <stdlib.h>
// 字符串转数字转换
char num_str[] = "12345";
char float_str[] = "3.14159";
int num = atoi(num_str);
long long_num = atol(num_str);
double float_num = atof(float_str);
printf("Integer: %d\n", num);
printf("Long: %ld\n", long_num);
printf("Double: %.2f\n", float_num);
// 数字转字符串 (使用 sprintf)
char buffer[50];
sprintf(buffer, "%d", 42);
sprintf(buffer, "%.2f", 3.14159);
printf("String: %s\n", buffer);
```

### 自定义字符串处理

手动字符串操作技术。

```c
// 计算字符串中特定字符的个数
int countChar(char *str, char target) {
    int count = 0;
    while (*str) {
        if (*str == target) count++;
        str++;
    }
    return count;
}
// 就地反转字符串
void reverseString(char *str) {
    int len = strlen(str);
    for (int i = 0; i < len/2; i++) {
        char temp = str[i];
        str[i] = str[len-1-i];
        str[len-1-i] = temp;
    }
}
```

## 编译与构建过程

### GCC 编译

用于 C 语言的 GNU 编译器集合。

```bash
# 基本编译
gcc -o program main.c
# 包含调试信息
gcc -g -o program main.c
# 优化级别
gcc -O2 -o program main.c
# 多个源文件
gcc -o program main.c utils.c math.c
# 包含附加目录
gcc -I/usr/local/include -o program main.c
# 链接库
gcc -o program main.c -lm -lpthread
```

### C 标准

使用特定 C 标准版本进行编译。

```bash
# C90/C89 标准 (ANSI C)
gcc -std=c89 -o program main.c
# C99 标准
gcc -std=c99 -o program main.c
# C11 标准 (推荐)
gcc -std=c11 -o program main.c
# C18 标准 (最新)
gcc -std=c18 -o program main.c
# 启用所有警告
gcc -Wall -Wextra -std=c11 -o program main.c
```

### Makefile 基础

使用 make 工具自动化编译过程。

```makefile
# 简单的 Makefile
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

## 最佳实践与技巧

### 命名约定

一致的命名使代码更具可读性。

```c
// 变量和函数：snake_case (蛇形命名法)
int student_count;
double calculate_average(int scores[], int size);
// 常量：UPPER_CASE (大写)
#define MAX_BUFFER_SIZE 1024
#define PI 3.14159
// 结构体：PascalCase 或 snake_case
typedef struct {
    char name[50];
    int age;
} Student;
// 全局变量：以 g_ 为前缀
int g_total_count = 0;
// 函数参数：清晰的名称
void process_data(int *input_array, int array_size);
```

### 内存安全

防止常见的内存相关错误。

```c
// 始终初始化变量
int count = 0;        // 好
int count;            // 危险 - 未初始化
// 检查 malloc 的返回值
int *ptr = malloc(sizeof(int) * 10);
if (ptr == NULL) {
    printf("Memory allocation failed!\n");
    return -1;
}
// 始终释放分配的内存
free(ptr);
ptr = NULL;  // 防止意外重用
// 数组边界检查
for (int i = 0; i < array_size; i++) {
    // 安全的数组访问
    array[i] = i;
}
```

### 性能提示

编写高效的 C 代码。

```c
// 使用适当的数据类型
char small_num = 10;   // 用于小数值
int normal_num = 1000; // 用于典型整数
// 在循环中最小化函数调用
int len = strlen(str); // 只计算一次
for (int i = 0; i < len; i++) {
    // 处理字符串
}
// 对频繁访问的变量使用 register
register int counter;
// 尺寸已知时，优先使用数组而不是动态分配
int fixed_array[100];  // 栈分配
// vs
int *dynamic_array = malloc(100 * sizeof(int));
```

### 代码组织

为可维护性组织代码。

```c
// 头文件 (utils.h)
#ifndef UTILS_H
#define UTILS_H
// 函数原型
double calculate_area(double radius);
int fibonacci(int n);
// 结构体定义
typedef struct {
    int x, y;
} Point;
#endif // UTILS_H
// 实现文件 (utils.c)
#include "utils.h"
#include <math.h>
double calculate_area(double radius) {
    return M_PI * radius * radius;
}
```

## 相关链接

- <router-link to="/cpp">C++ 速查表</router-link>
- <router-link to="/java">Java 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/golang">Golang 速查表</router-link>
- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>

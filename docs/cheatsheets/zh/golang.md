---
title: 'Golang 速查表 | LabEx'
description: '使用本综合速查表学习 Go 编程。Go 语法、goroutine、通道、接口、错误处理和后端开发并发编程的快速参考。'
pdfUrl: '/cheatsheets/pdf/golang-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Golang 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/golang">使用实践实验室学习 Golang</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Go 编程。LabEx 提供全面的 Go 课程，涵盖基本语法、并发模式、错误处理和高级技术。掌握 Go 的独特特性，如 goroutines、channels 和 interfaces，以构建高效的并发应用程序。
</base-disclaimer-content>
</base-disclaimer>

## 安装与设置

### 安装 Go: 下载与解压

从官方网站下载并安装 Go。

```bash
# 从 https://golang.org/dl/ 下载
# Linux/macOS - 解压到 /usr/local
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
# 在 ~/.bashrc 或 ~/.zshrc 中添加到 PATH
export PATH=$PATH:/usr/local/go/bin
# 验证安装
go version
```

### 包管理器：使用 Homebrew (macOS)

在 macOS 上使用 Homebrew 安装 Go。

```bash
# 使用 Homebrew 安装 Go
brew install go
# 验证安装
go version
go env GOPATH
```

### Windows 安装

在 Windows 系统上安装 Go。

```bash
# 从 https://golang.org/dl/ 下载 .msi 安装程序
# 运行安装程序并遵循提示
# 在命令提示符中验证
go version
echo %GOPATH%
```

### 工作区设置：`go mod init`

初始化一个新的 Go 模块和工作区。

```bash
# 创建新目录并初始化模块
mkdir my-go-project
cd my-go-project
go mod init my-go-project
# 创建 main.go
echo 'package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}' > main.go
# 运行程序
go run main.go
```

### 环境变量

重要的 Go 环境变量。

```bash
# 查看所有 Go 环境变量
go env
# 关键变量
go env GOROOT    # Go 安装目录
go env GOPATH    # 工作区目录
go env GOOS      # 操作系统
go env GOARCH    # 架构
```

### IDE 设置：VS Code

为 Go 开发配置 VS Code。

```bash
# 在 VS Code 中安装 Go 扩展
# Ctrl+Shift+P -> Go: Install/Update Tools
# 启用的关键功能：
# - 语法高亮
# - IntelliSense
# - 调试
# - 测试集成
```

## 基本语法与类型

### 包与导入

每个 Go 文件都以包声明和导入开始。

```go
package main
import (
    "fmt"
    "strings"
    "time"
)
// 单个导入
import "os"
```

### 变量与常量

声明和初始化变量和常量。

```go
// 变量声明
var name string = "Go"
var age int = 15
var isOpen bool
// 短声明
name := "Golang"
count := 42
// 常量
const Pi = 3.14159
const Message = "Hello, Go!"
```

<BaseQuiz id="golang-variables-1" correct="B">
  <template #question>
    <code>var name string = "Go"</code> 和 <code>name := "Go"</code> 有什么区别？
  </template>
  
  <BaseQuizOption value="A">没有区别</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>:=</code> 是推断类型的简短声明，<code>var</code> 显式声明类型</BaseQuizOption>
  <BaseQuizOption value="C"><code>:=</code> 只能用于常量</BaseQuizOption>
  <BaseQuizOption value="D"><code>var</code> 只能在函数内部使用</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>:=</code> 运算符是变量声明和初始化的简写形式，Go 会自动推断类型。<code>var</code> 显式声明变量类型，可用于包级别或函数级别。
  </BaseQuizAnswer>
</BaseQuiz>

### 基本数据类型

Go 中可用的基本类型。

```go
// 数值类型
var i int = 42
var f float64 = 3.14
var c complex64 = 1 + 2i
// 文本类型
var s string = "Hello"
var r rune = 'A'
// 布尔值
var b bool = true
```

## 控制流

### 条件语句：`if` / `else` / `switch`

使用条件语句控制程序流程。

```go
// If 语句
if age >= 18 {
    fmt.Println("Adult")
} else if age >= 13 {
    fmt.Println("Teenager")
} else {
    fmt.Println("Child")
}
// Switch 语句
switch day {
case "Monday":
    fmt.Println("Start of work week")
case "Friday":
    fmt.Println("TGIF")
default:
    fmt.Println("Regular day")
}
```

### 循环：`for` / `range`

使用各种循环结构进行迭代。

```go
// 传统 for 循环
for i := 0; i < 10; i++ {
    fmt.Println(i)
}
// While 风格循环
for condition {
    // 循环体
}
// 无限循环
for {
    // 需要时 break
}
```

### 范围迭代

迭代切片、数组、映射和字符串。

```go
// 迭代切片
numbers := []int{1, 2, 3, 4, 5}
for index, value := range numbers {
    fmt.Printf("Index: %d, Value: %d\n", index, value)
}
// 迭代映射
colors := map[string]string{"red": "#FF0000", "green": "#00FF00"}
for key, value := range colors {
    fmt.Printf("%s: %s\n", key, value)
}
// 迭代字符串
for i, char := range "Hello" {
    fmt.Printf("%d: %c\n", i, char)
}
```

<BaseQuiz id="golang-range-1" correct="B">
  <template #question>
    在 Go 中迭代切片时，<code>range</code> 返回什么？
  </template>
  
  <BaseQuizOption value="A">仅值</BaseQuizOption>
  <BaseQuizOption value="B" correct>索引和值</BaseQuizOption>
  <BaseQuizOption value="C">仅索引</BaseQuizOption>
  <BaseQuizOption value="D">切片的长度</BaseQuizOption>
  
  <BaseQuizAnswer>
    当使用 <code>range</code> 遍历切片时，它返回两个值：索引（位置）和该索引处的值。如果不需要其中一个值，可以使用 <code>_</code> 忽略它。
  </BaseQuizAnswer>
</BaseQuiz>

### 控制语句：`break` / `continue`

控制循环的执行流程。

```go
// 跳出循环
for i := 0; i < 10; i++ {
    if i == 5 {
        break
    }
    fmt.Println(i)
}
// 跳过当前迭代
for i := 0; i < 5; i++ {
    if i == 2 {
        continue
    }
    fmt.Println(i)
}
```

<BaseQuiz id="golang-control-1" correct="C">
  <template #question>
    Go 循环中的 <code>break</code> 和 <code>continue</code> 有什么区别？
  </template>
  
  <BaseQuizOption value="A">没有区别</BaseQuizOption>
  <BaseQuizOption value="B">break 跳过当前迭代，continue 退出循环</BaseQuizOption>
  <BaseQuizOption value="C" correct>break 完全退出循环，continue 跳到下一次迭代</BaseQuizOption>
  <BaseQuizOption value="D">两者都退出循环</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>break</code> 立即退出循环，并在循环后继续执行。<code>continue</code> 跳过当前迭代的其余部分，进入循环的下一次迭代。
  </BaseQuizAnswer>
</BaseQuiz>

## 函数

### 函数声明：`func`

定义带有参数和返回值的函数。

```go
// 基本函数
func greet(name string) {
    fmt.Printf("Hello, %s!\n", name)
}
// 带返回值的函数
func add(a, b int) int {
    return a + b
}
// 多返回值
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
```

### 命名返回和可变参数函数

高级函数特性和模式。

```go
// 命名返回
func split(sum int) (x, y int) {
    x = sum * 4 / 9
    y = sum - x
    return // 裸返回
}
// 可变参数函数
func sum(nums ...int) int {
    total := 0
    for _, num := range nums {
        total += num
    }
    return total
}
// 用法
result := sum(1, 2, 3, 4, 5)
```

### 函数类型与闭包

函数作为 Go 中的一等公民。

```go
// 函数作为变量
var multiply func(int, int) int
multiply = func(a, b int) int {
    return a * b
}
// 匿名函数
square := func(x int) int {
    return x * x
}
// 闭包
func counter() func() int {
    count := 0
    return func() int {
        count++
        return count
    }
}
// 用法
c := counter()
fmt.Println(c()) // 1
fmt.Println(c()) // 2
```

### Defer 语句

延迟函数执行直到其包围的函数返回。

```go
func processFile(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close() // 函数返回时执行

    // 处理文件内容
    // file.Close() 将自动调用
}
```

## 数据结构

### 数组与切片

固定和动态的元素序列。

```go
// 数组（固定大小）
var arr [5]int = [5]int{1, 2, 3, 4, 5}
shortArr := [3]string{"a", "b", "c"}
// 切片（动态）
var slice []int
slice = append(slice, 1, 2, 3)
// 创建带容量的切片
numbers := make([]int, 5, 10) // 长度 5，容量 10
// 切片操作
slice2 := slice[1:3]  // [2, 3]
copy(slice2, slice)   // 复制元素
```

### 映射 (Maps)

用于高效查找的键值对。

```go
// 映射声明和初始化
var m map[string]int
m = make(map[string]int)
// 短声明
ages := map[string]int{
    "Alice": 30,
    "Bob":   25,
    "Carol": 35,
}
// 映射操作
ages["David"] = 40        // 添加/更新
delete(ages, "Bob")       // 删除
age, exists := ages["Alice"] // 检查存在性
```

### 结构体 (Structs)

使用自定义类型将相关数据组合在一起。

```go
// 结构体定义
type Person struct {
    Name    string
    Age     int
    Email   string
}
// 创建结构体实例
p1 := Person{
    Name:  "Alice",
    Age:   30,
    Email: "alice@example.com",
}
p2 := Person{"Bob", 25, "bob@example.com"}
// 访问字段
fmt.Println(p1.Name)
p1.Age = 31
```

### 指针 (Pointers)

引用变量的内存地址。

```go
// 指针声明
var p *int
num := 42
p = &num  // num 的地址
// 解引用
fmt.Println(*p) // 地址处的值 (42)
*p = 100        // 通过指针改变值
// 结构体指针
person := &Person{Name: "Alice", Age: 30}
person.Age = 31  // 自动解引用
```

## 方法与接口

### 方法 (Methods)

将功能附加到自定义类型上。

```go
type Rectangle struct {
    Width, Height float64
}
// 带接收者的值方法
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}
// 指针接收者（可以修改）
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor
    r.Height *= factor
}
// 用法
rect := Rectangle{Width: 10, Height: 5}
fmt.Println(rect.Area()) // 50
rect.Scale(2)            // 修改 rect
```

### 接口 (Interfaces)

定义类型必须满足的契约。

```go
// 接口定义
type Shape interface {
    Area() float64
    Perimeter() float64
}
// 为 Rectangle 实现接口
func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}
// Rectangle 现在实现了 Shape 接口
func printShapeInfo(s Shape) {
    fmt.Printf("Area: %.2f, Perimeter: %.2f\n",
               s.Area(), s.Perimeter())
}
```

### 空接口与类型断言

处理未知类型的数值。

```go
// 空接口可以容纳任何值
var i interface{}
i = 42
i = "hello"
i = []int{1, 2, 3}
// 类型断言
str, ok := i.(string)
if ok {
    fmt.Printf("String value: %s\n", str)
}
// 类型开关
switch v := i.(type) {
case int:
    fmt.Printf("Integer: %d\n", v)
case string:
    fmt.Printf("String: %s\n", v)
default:
    fmt.Printf("Unknown type: %T\n", v)
}
```

### 嵌入 (Embedding)

通过嵌入其他类型来组合类型。

```go
type Person struct {
    Name string
    Age  int
}
type Employee struct {
    Person    // 嵌入的结构体
    Company   string
    Salary    float64
}
// 用法
emp := Employee{
    Person:  Person{Name: "Alice", Age: 30},
    Company: "TechCorp",
    Salary:  75000,
}
// 直接访问嵌入的字段
fmt.Println(emp.Name) // "Alice"
```

## 错误处理

### 基本错误处理

使用内置的 error 接口进行错误处理。

```go
import "errors"
// 返回错误的函数
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
// 错误检查
result, err := divide(10, 2)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Result: %.2f\n", result)
```

### 自定义错误

为特定错误情况创建自定义错误类型。

```go
// 自定义错误类型
type ValidationError struct {
    Field   string
    Message string
}
func (e ValidationError) Error() string {
    return fmt.Sprintf("validation error in %s: %s",
                       e.Field, e.Message)
}
// 使用自定义错误的函数
func validateAge(age int) error {
    if age < 0 {
        return ValidationError{
            Field:   "age",
            Message: "must be non-negative",
        }
    }
    return nil
}
```

### 错误包装 (Error Wrapping)

在保留原始错误的同时为错误添加额外上下文。

```go
import "fmt"
// 使用额外上下文包装错误
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("failed to open file %s: %w",
                          filename, err)
    }
    defer file.Close()

    // 处理文件...
    return nil
}
// 错误解包
err := processFile("missing.txt")
if err != nil {
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        fmt.Println("Path error:", pathErr)
    }
}
```

### Panic 与恢复 (Recovery)

使用 panic 和 recover 处理异常情况。

```go
// 可能导致 panic 的函数
func riskyOperation() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from panic:", r)
        }
    }()

    // 这将导致 panic
    panic("something went wrong!")
}
// 用法
riskyOperation() // panic 后程序继续执行
```

## 并发

### Goroutines

由 Go 运行时管理的轻量级线程。

```go
import "time"
// 简单 goroutine
func sayHello() {
    fmt.Println("Hello from goroutine!")
}
func main() {
    // 启动 goroutine
    go sayHello()

    // 匿名 goroutine
    go func() {
        fmt.Println("Anonymous goroutine")
    }()

    // 等待 goroutines 完成
    time.Sleep(time.Second)
}
```

### 通道 (Channels)

使用通道在 goroutines 之间进行通信。

```go
// 创建通道
ch := make(chan int)
// 带缓冲的通道
buffered := make(chan string, 3)
// 发送和接收
go func() {
    ch <- 42  // 发送值
}()
value := <-ch  // 接收值
// 关闭通道
close(ch)
```

### 通道模式

通道通信的常见模式。

```go
// 工作者模式
func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Worker %d processing job %d\n", id, job)
        results <- job * 2
    }
}
// 扇出模式 (Fan-out)
jobs := make(chan int, 100)
results := make(chan int, 100)
// 启动工作者
for w := 1; w <= 3; w++ {
    go worker(w, jobs, results)
}
// 发送工作
for j := 1; j <= 5; j++ {
    jobs <- j
}
close(jobs)
```

### Select 语句

同时处理多个通道操作。

```go
func main() {
    ch1 := make(chan string)
    ch2 := make(chan string)

    go func() {
        time.Sleep(time.Second)
        ch1 <- "from ch1"
    }()

    go func() {
        time.Sleep(2 * time.Second)
        ch2 <- "from ch2"
    }()

    // 选择第一个可用的通道
    select {
    case msg1 := <-ch1:
        fmt.Println(msg1)
    case msg2 := <-ch2:
        fmt.Println(msg2)
    case <-time.After(3 * time.Second):
        fmt.Println("timeout")
    }
}
```

## 文件 I/O 与 JSON

### 文件操作

使用各种方法读取和写入文件。

```go
import (
    "io/ioutil"
    "os"
)
// 读取整个文件
data, err := ioutil.ReadFile("file.txt")
if err != nil {
    log.Fatal(err)
}
content := string(data)
// 写入文件
text := "Hello, World!"
err = ioutil.WriteFile("output.txt", []byte(text), 0644)
// 带更多控制的文件打开
file, err := os.Open("data.txt")
if err != nil {
    log.Fatal(err)
}
defer file.Close()
```

### CSV 处理

读写 CSV 文件。

```go
import (
    "encoding/csv"
    "os"
)
// 读取 CSV
file, _ := os.Open("data.csv")
defer file.Close()
reader := csv.NewReader(file)
records, _ := reader.ReadAll()
// 写入 CSV
file, _ = os.Create("output.csv")
defer file.Close()
writer := csv.NewWriter(file)
defer writer.Flush()
writer.Write([]string{"Name", "Age", "City"})
writer.Write([]string{"Alice", "30", "NYC"})
```

### JSON 处理

编码和解码 JSON 数据。

```go
import "encoding/json"
// 用于 JSON 映射的结构体
type Person struct {
    Name  string `json:"name"`
    Age   int    `json:"age"`
    Email string `json:"email,omitempty"`
}
// 编码 (Go 到 JSON)
person := Person{Name: "Alice", Age: 30}
jsonData, err := json.Marshal(person)
if err != nil {
    log.Fatal(err)
}
// 解码 (JSON 到 Go)
var p Person
err = json.Unmarshal(jsonData, &p)
```

### HTTP 请求

发起 HTTP 请求并处理响应。

```go
import "net/http"
// GET 请求
resp, err := http.Get("https://api.github.com/users/octocat")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
body, _ := ioutil.ReadAll(resp.Body)
// POST 请求（带 JSON）
jsonData := []byte(`{"name":"Alice","age":30}`)
resp, err = http.Post("https://api.example.com/users",
                      "application/json",
                      bytes.NewBuffer(jsonData))
```

## 测试

### 单元测试：`go test`

使用 Go 的测试框架编写和运行测试。

```go
// math.go
package main
func Add(a, b int) int {
    return a + b
}
// math_test.go
package main
import "testing"
func TestAdd(t *testing.T) {
    result := Add(2, 3)
    expected := 5

    if result != expected {
        t.Errorf("Add(2, 3) = %d; want %d", result, expected)
    }
}
// 运行测试
// go test
// go test -v (详细模式)
```

### 表驱动测试 (Table-Driven Tests)

高效地测试多个用例。

```go
func TestAddMultiple(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {"positive numbers", 2, 3, 5},
        {"with zero", 0, 5, 5},
        {"negative numbers", -1, -2, -3},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Add(tt.a, tt.b)
            if result != tt.expected {
                t.Errorf("got %d, want %d", result, tt.expected)
            }
        })
    }
}
```

### 基准测试 (Benchmarking)

衡量函数性能。

```go
func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(2, 3)
    }
}
// 运行基准测试
// go test -bench=.
// go test -bench=BenchmarkAdd -benchmem
```

### 示例测试 (Example Tests)

创建作为文档的可执行示例。

```go
import "fmt"
func ExampleAdd() {
    result := Add(2, 3)
    fmt.Printf("2 + 3 = %d", result)
    // Output: 2 + 3 = 5
}
func ExampleAdd_negative() {
    result := Add(-1, -2)
    fmt.Printf("(-1) + (-2) = %d", result)
    // Output: (-1) + (-2) = -3
}
// 运行示例
// go test -run Example
```

## Go 模块与包

### 模块管理

初始化和管理 Go 模块以进行依赖项管理。

```bash
# 初始化新模块
go mod init github.com/username/project
# 添加依赖项
go get github.com/gorilla/mux
go get -u github.com/gin-gonic/gin  # 更新到最新版本
# 移除未使用的依赖项
go mod tidy
# 下载依赖项
go mod download
# 本地化依赖项
go mod vendor
```

### go.mod 文件

理解模块定义文件。

```go
module github.com/username/myproject
go 1.21
require (
    github.com/gorilla/mux v1.8.0
    github.com/stretchr/testify v1.8.4
)
require (
    github.com/davecgh/go-spew v1.1.1 // indirect
    github.com/pmezard/go-difflib v1.0.0 // indirect
)
```

### 创建包

将代码结构化为可重用的包。

```go
// 包结构
// myproject/
//   ├── go.mod
//   ├── main.go
//   └── utils/
//       ├── math.go
//       └── string.go
// utils/math.go
package utils
// 导出函数（首字母大写）
func Add(a, b int) int {
    return a + b
}
// 私有函数（首字母小写）
func multiply(a, b int) int {
    return a * b
}
// main.go
package main
import (
    "fmt"
    "github.com/username/myproject/utils"
)
func main() {
    result := utils.Add(5, 3)
    fmt.Println(result)
}
```

### 常用 Go 命令

Go 开发的基本命令。

```bash
# 运行 Go 程序
go run main.go
# 构建可执行文件
go build
go build -o myapp  # 自定义名称
# 将二进制文件安装到 GOPATH/bin
go install
# 格式化代码
go fmt ./...
# 检查代码是否存在问题
go vet ./...
# 清理构建缓存
go clean -cache
```

## 相关链接

- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/kubernetes">Kubernetes 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/java">Java 速查表</router-link>

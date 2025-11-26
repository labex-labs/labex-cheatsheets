---
title: 'Golang 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 포괄적인 치트 시트로 Golang 을 학습하세요.'
pdfUrl: '/cheatsheets/pdf/golang-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Golang 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/golang">Hands-On Labs 로 Golang 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 기반 랩과 실제 시나리오를 통해 Go 프로그래밍을 학습하세요. LabEx 는 필수 구문, 동시성 패턴, 오류 처리 및 고급 기술을 다루는 포괄적인 Go 과정을 제공합니다. 고루틴, 채널, 인터페이스와 같은 Go 의 고유한 기능을 마스터하여 효율적이고 동시적인 애플리케이션을 구축하세요.
</base-disclaimer-content>
</base-disclaimer>

## 설치 및 설정 (Installation & Setup)

### Go 설치: 다운로드 및 압축 해제

공식 웹사이트에서 Go 를 다운로드하여 설치합니다.

```bash
# https://golang.org/dl/ 에서 다운로드
# Linux/macOS - /usr/local 에 압축 해제
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
# ~/.bashrc 또는 ~/.zshrc 에 PATH 추가
export PATH=$PATH:/usr/local/go/bin
# 설치 확인
go version
```

### 패키지 관리자: Homebrew 사용 (macOS)

macOS 에서 Homebrew 를 사용하여 Go 를 설치합니다.

```bash
# Homebrew로 Go 설치
brew install go
# 설치 확인
go version
go env GOPATH
```

### Windows 설치

Windows 시스템에 Go 를 설치합니다.

```bash
# https://golang.org/dl/ 에서 .msi 설치 프로그램 다운로드
# 설치 프로그램을 실행하고 안내에 따름
# 명령 프롬프트에서 확인
go version
echo %GOPATH%
```

### 작업 공간 설정: `go mod init`

새로운 Go 모듈 및 작업 공간을 초기화합니다.

```bash
# 새 디렉토리 생성 및 모듈 초기화
mkdir my-go-project
cd my-go-project
go mod init my-go-project
# main.go 생성
echo 'package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}' > main.go
# 프로그램 실행
go run main.go
```

### 환경 변수

주요 Go 환경 변수.

```bash
# 모든 Go 환경 변수 보기
go env
# 주요 변수
go env GOROOT    # Go 설치 디렉토리
go env GOPATH    # 작업 공간 디렉토리
go env GOOS      # 운영 체제
go env GOARCH    # 아키텍처
```

### IDE 설정: VS Code

Go 개발을 위해 VS Code 구성.

```bash
# VS Code에서 Go 확장 프로그램 설치
# Ctrl+Shift+P -> Go: Install/Update Tools
# 활성화되는 주요 기능:
# - 구문 강조 (Syntax highlighting)
# - IntelliSense
# - 디버깅 (Debugging)
# - 테스트 통합 (Testing integration)
```

## 기본 구문 및 타입 (Basic Syntax & Types)

### 패키지 및 임포트 (Package & Imports)

모든 Go 파일은 패키지 선언과 임포트로 시작합니다.

```go
package main
import (
    "fmt"
    "strings"
    "time"
)
// 단일 임포트
import "os"
```

### 변수 및 상수 (Variables & Constants)

변수와 상수를 선언하고 초기화합니다.

```go
// 변수 선언
var name string = "Go"
var age int = 15
var isOpen bool
// 짧은 선언
name := "Golang"
count := 42
// 상수
const Pi = 3.14159
const Message = "Hello, Go!"
```

### 기본 데이터 타입 (Basic Data Types)

Go 에서 사용 가능한 기본 타입.

```go
// 숫자 타입
var i int = 42
var f float64 = 3.14
var c complex64 = 1 + 2i
// 텍스트 타입
var s string = "Hello"
var r rune = 'A'
// 불리언
var b bool = true
```

## 제어 흐름 (Control Flow)

### 조건문: `if` / `else` / `switch`

조건문을 사용하여 프로그램 흐름을 제어합니다.

```go
// If 문
if age >= 18 {
    fmt.Println("Adult")
} else if age >= 13 {
    fmt.Println("Teenager")
} else {
    fmt.Println("Child")
}
// Switch 문
switch day {
case "Monday":
    fmt.Println("Start of work week")
case "Friday":
    fmt.Println("TGIF")
default:
    fmt.Println("Regular day")
}
```

### 반복문: `for` / `range`

다양한 반복 구조를 사용하여 반복합니다.

```go
// 전통적인 for 루프
for i := 0; i < 10; i++ {
    fmt.Println(i)
}
// While 스타일 루프
for condition {
    // 루프 본문
}
// 무한 루프
for {
    // 필요할 때 break
}
```

### Range 반복

슬라이스, 배열, 맵 및 문자열을 반복합니다.

```go
// 슬라이스 반복
numbers := []int{1, 2, 3, 4, 5}
for index, value := range numbers {
    fmt.Printf("Index: %d, Value: %d\n", index, value)
}
// 맵 반복
colors := map[string]string{"red": "#FF0000", "green": "#00FF00"}
for key, value := range colors {
    fmt.Printf("%s: %s\n", key, value)
}
// 문자열 반복
for i, char := range "Hello" {
    fmt.Printf("%d: %c\n", i, char)
}
```

### 제어문: `break` / `continue`

루프 실행 흐름을 제어합니다.

```go
// 루프 탈출
for i := 0; i < 10; i++ {
    if i == 5 {
        break
    }
    fmt.Println(i)
}
// 현재 반복 건너뛰기
for i := 0; i < 5; i++ {
    if i == 2 {
        continue
    }
    fmt.Println(i)
}
```

## 함수 (Functions)

### 함수 선언: `func`

매개변수와 반환 값을 가진 함수를 정의합니다.

```go
// 기본 함수
func greet(name string) {
    fmt.Printf("Hello, %s!\n", name)
}
// 반환 값이 있는 함수
func add(a, b int) int {
    return a + b
}
// 다중 반환 값
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
```

### 명명된 반환 및 가변 함수 (Named Returns & Variadic Functions)

고급 함수 기능 및 패턴.

```go
// 명명된 반환 값
func split(sum int) (x, y int) {
    x = sum * 4 / 9
    y = sum - x
    return // 네이키드 반환
}
// 가변 함수 (Variadic function)
func sum(nums ...int) int {
    total := 0
    for _, num := range nums {
        total += num
    }
    return total
}
// 사용법
result := sum(1, 2, 3, 4, 5)
```

### 함수 타입 및 클로저 (Function Types & Closures)

함수는 Go 에서 일급 시민입니다.

```go
// 변수로서의 함수
var multiply func(int, int) int
multiply = func(a, b int) int {
    return a * b
}
// 익명 함수
square := func(x int) int {
    return x * x
}
// 클로저
func counter() func() int {
    count := 0
    return func() int {
        count++
        return count
    }
}
// 사용법
c := counter()
fmt.Println(c()) // 1
fmt.Println(c()) // 2
```

### Defer 문

주변 함수가 반환될 때까지 함수의 실행을 연기합니다.

```go
func processFile(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close() // 함수 반환 시 실행됨

    // 파일 내용 처리
    // file.Close() 가 자동으로 호출됨
}
```

## 데이터 구조 (Data Structures)

### 배열 및 슬라이스 (Arrays & Slices)

고정 및 동적 요소 시퀀스.

```go
// 배열 (고정 크기)
var arr [5]int = [5]int{1, 2, 3, 4, 5}
shortArr := [3]string{"a", "b", "c"}
// 슬라이스 (동적)
var slice []int
slice = append(slice, 1, 2, 3)
// 용량을 가진 슬라이스 생성
numbers := make([]int, 5, 10) // 길이 5, 용량 10
// 슬라이스 연산
slice2 := slice[1:3]  // [2, 3]
copy(slice2, slice)   // 요소 복사
```

### 맵 (Maps)

효율적인 조회를 위한 키 - 값 쌍.

```go
// 맵 선언 및 초기화
var m map[string]int
m = make(map[string]int)
// 짧은 선언
ages := map[string]int{
    "Alice": 30,
    "Bob":   25,
    "Carol": 35,
}
// 맵 연산
ages["David"] = 40        // 추가/업데이트
delete(ages, "Bob")       // 삭제
age, exists := ages["Alice"] // 존재 여부 확인
```

### 구조체 (Structs)

관련 데이터를 사용자 정의 타입으로 그룹화합니다.

```go
// 구조체 정의
type Person struct {
    Name    string
    Age     int
    Email   string
}
// 구조체 인스턴스 생성
p1 := Person{
    Name:  "Alice",
    Age:   30,
    Email: "alice@example.com",
}
p2 := Person{"Bob", 25, "bob@example.com"}
// 필드 접근
fmt.Println(p1.Name)
p1.Age = 31
```

### 포인터 (Pointers)

변수의 메모리 주소를 참조합니다.

```go
// 포인터 선언
var p *int
num := 42
p = &num  // num 의 주소
// 역참조 (Dereferencing)
fmt.Println(*p) // 주소의 값 (42)
*p = 100        // 포인터를 통해 값 변경
// 구조체 포인터
person := &Person{Name: "Alice", Age: 30}
person.Age = 31  // 자동 역참조
```

## 메서드 및 인터페이스 (Methods & Interfaces)

### 메서드 (Methods)

사용자 정의 타입에 기능을 연결합니다.

```go
type Rectangle struct {
    Width, Height float64
}
// 수신자 (receiver) 가 있는 메서드
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}
// 포인터 수신자 (수정 가능)
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor
    r.Height *= factor
}
// 사용법
rect := Rectangle{Width: 10, Height: 5}
fmt.Println(rect.Area()) // 50
rect.Scale(2)            // rect 수정
```

### 인터페이스 (Interfaces)

타입이 만족해야 하는 계약을 정의합니다.

```go
// 인터페이스 정의
type Shape interface {
    Area() float64
    Perimeter() float64
}
// Rectangle 에 대한 인터페이스 구현
func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}
// Rectangle 은 이제 Shape 인터페이스를 구현함
func printShapeInfo(s Shape) {
    fmt.Printf("Area: %.2f, Perimeter: %.2f\n",
               s.Area(), s.Perimeter())
}
```

### 빈 인터페이스 및 타입 단언 (Empty Interface & Type Assertions)

알 수 없는 타입의 값 처리.

```go
// 빈 인터페이스는 모든 값을 가질 수 있음
var i interface{}
i = 42
i = "hello"
i = []int{1, 2, 3}
// 타입 단언
str, ok := i.(string)
if ok {
    fmt.Printf("String value: %s\n", str)
}
// 타입 스위치
switch v := i.(type) {
case int:
    fmt.Printf("Integer: %d\n", v)
case string:
    fmt.Printf("String: %s\n", v)
default:
    fmt.Printf("Unknown type: %T\n", v)
}
```

### 임베딩 (Embedding)

다른 타입을 임베드하여 타입을 구성합니다.

```go
type Person struct {
    Name string
    Age  int
}
type Employee struct {
    Person    // 임베드된 구조체
    Company   string
    Salary    float64
}
// 사용법
emp := Employee{
    Person:  Person{Name: "Alice", Age: 30},
    Company: "TechCorp",
    Salary:  75000,
}
// 임베드된 필드에 직접 접근
fmt.Println(emp.Name) // "Alice"
```

## 오류 처리 (Error Handling)

### 기본 오류 처리

내장된 error 인터페이스를 사용하여 오류를 처리합니다.

```go
import "errors"
// 오류를 반환하는 함수
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
// 오류 확인
result, err := divide(10, 2)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Result: %.2f\n", result)
```

### 사용자 정의 오류 (Custom Errors)

특정 오류 조건에 대해 사용자 정의 오류 타입을 생성합니다.

```go
// 사용자 정의 오류 타입
type ValidationError struct {
    Field   string
    Message string
}
func (e ValidationError) Error() string {
    return fmt.Sprintf("validation error in %s: %s",
                       e.Field, e.Message)
}
// 사용자 정의 오류를 사용하는 함수
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

### 오류 래핑 (Error Wrapping)

원래 오류를 보존하면서 오류에 컨텍스트를 추가합니다.

```go
import "fmt"
// 추가 컨텍스트로 오류 래핑
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("failed to open file %s: %w",
                          filename, err)
    }
    defer file.Close()

    // 파일 처리...
    return nil
}
// 오류 풀기 (Unwrap errors)
err := processFile("missing.txt")
if err != nil {
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        fmt.Println("Path error:", pathErr)
    }
}
```

### Panic 및 복구 (Panic & Recovery)

panic 과 recover 를 사용하여 예외적인 상황을 처리합니다.

```go
// panic 을 유발할 수 있는 함수
func riskyOperation() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from panic:", r)
        }
    }()

    // 이것은 panic 을 유발함
    panic("something went wrong!")
}
// 사용법
riskyOperation() // panic 후 프로그램 계속 실행됨
```

## 동시성 (Concurrency)

### 고루틴 (Goroutines)

Go 런타임이 관리하는 경량 스레드.

```go
import "time"
// 간단한 고루틴
func sayHello() {
    fmt.Println("Hello from goroutine!")
}
func main() {
    // 고루틴 시작
    go sayHello()

    // 익명 고루틴
    go func() {
        fmt.Println("Anonymous goroutine")
    }()

    // 고루틴이 완료될 때까지 대기
    time.Sleep(time.Second)
}
```

### 채널 (Channels)

채널을 사용하여 고루틴 간의 통신.

```go
// 채널 생성
ch := make(chan int)
// 버퍼링된 채널
buffered := make(chan string, 3)
// 송신 및 수신
go func() {
    ch <- 42  // 값 송신
}()
value := <-ch  // 값 수신
// 채널 닫기
close(ch)
```

### 채널 패턴 (Channel Patterns)

채널 통신의 일반적인 패턴.

```go
// 작업자 패턴
func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Worker %d processing job %d\n", id, job)
        results <- job * 2
    }
}
// 팬아웃 패턴 (Fan-out pattern)
jobs := make(chan int, 100)
results := make(chan int, 100)
// 작업자 시작
for w := 1; w <= 3; w++ {
    go worker(w, jobs, results)
}
// 작업 전송
for j := 1; j <= 5; j++ {
    jobs <- j
}
close(jobs)
```

### Select 문

여러 채널 작업을 동시에 처리합니다.

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

    // 사용 가능한 첫 번째 채널 처리
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

## 파일 I/O 및 JSON (File I/O & JSON)

### 파일 작업 (File Operations)

다양한 방법을 사용하여 파일을 읽고 씁니다.

```go
import (
    "io/ioutil"
    "os"
)
// 파일 전체 읽기
data, err := ioutil.ReadFile("file.txt")
if err != nil {
    log.Fatal(err)
}
content := string(data)
// 파일에 쓰기
text := "Hello, World!"
err = ioutil.WriteFile("output.txt", []byte(text), 0644)
// 더 많은 제어로 파일 열기
file, err := os.Open("data.txt")
if err != nil {
    log.Fatal(err)
}
defer file.Close()
```

### CSV 처리 (CSV Handling)

CSV 파일을 읽고 씁니다.

```go
import (
    "encoding/csv"
    "os"
)
// CSV 읽기
file, _ := os.Open("data.csv")
defer file.Close()
reader := csv.NewReader(file)
records, _ := reader.ReadAll()
// CSV 쓰기
file, _ = os.Create("output.csv")
defer file.Close()
writer := csv.NewWriter(file)
defer writer.Flush()
writer.Write([]string{"Name", "Age", "City"})
writer.Write([]string{"Alice", "30", "NYC"})
```

### JSON 처리 (JSON Processing)

JSON 데이터를 인코딩하고 디코딩합니다.

```go
import "encoding/json"
// JSON 매핑을 위한 구조체
type Person struct {
    Name  string `json:"name"`
    Age   int    `json:"age"`
    Email string `json:"email,omitempty"`
}
// 마샬링 (Go -> JSON)
person := Person{Name: "Alice", Age: 30}
jsonData, err := json.Marshal(person)
if err != nil {
    log.Fatal(err)
}
// 언마샬링 (JSON -> Go)
var p Person
err = json.Unmarshal(jsonData, &p)
```

### HTTP 요청 (HTTP Requests)

HTTP 요청을 보내고 응답을 처리합니다.

```go
import "net/http"
// GET 요청
resp, err := http.Get("https://api.github.com/users/octocat")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
body, _ := ioutil.ReadAll(resp.Body)
// POST 요청 (JSON 포함)
jsonData := []byte(`{"name":"Alice","age":30}`)
resp, err = http.Post("https://api.example.com/users",
                      "application/json",
                      bytes.NewBuffer(jsonData))
```

## 테스트 (Testing)

### 단위 테스트: `go test`

Go 의 테스트 프레임워크를 사용하여 테스트를 작성하고 실행합니다.

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
// 테스트 실행
// go test
// go test -v (상세 모드)
```

### 테이블 기반 테스트 (Table-Driven Tests)

여러 케이스를 효율적으로 테스트합니다.

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

### 벤치마킹 (Benchmarking)

함수의 성능을 측정합니다.

func BenchmarkAdd(b \*testing.B) {
for i := 0; i < b.N; i++ {
Add(2, 3)
}
}
// 벤치마크 실행
// go test -bench=.
// go test -bench=BenchmarkAdd -benchmem

````

### 예제 테스트 (Example Tests)

문서 역할을 하는 실행 가능한 예제를 생성합니다.

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
// 예제 실행
// go test -run Example
````

## Go 모듈 및 패키지 (Go Modules & Packages)

### 모듈 관리 (Module Management)

의존성 관리를 위해 Go 모듈을 초기화하고 관리합니다.

```bash
# 새 모듈 초기화
go mod init github.com/username/project
# 의존성 추가
go get github.com/gorilla/mux
go get -u github.com/gin-gonic/gin  # 최신 버전으로 업데이트
# 사용하지 않는 의존성 제거
go mod tidy
# 의존성 다운로드
go mod download
# 로컬에 의존성 벤더링
go mod vendor
```

### go.mod 파일

모듈 정의 파일 이해하기.

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

### 패키지 생성 (Creating Packages)

코드를 재사용 가능한 패키지로 구성합니다.

```go
// 패키지 구조
// myproject/
//   ├── go.mod
//   ├── main.go
//   └── utils/
//       ├── math.go
//       └── string.go
// utils/math.go
package utils
// 내보내진 함수 (대문자로 시작)
func Add(a, b int) int {
    return a + b
}
// 비공개 함수 (소문자로 시작)
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

### 일반적인 Go 명령어 (Common Go Commands)

Go 개발을 위한 필수 명령어.

```bash
# Go 프로그램 실행
go run main.go
# 실행 파일 빌드
go build
go build -o myapp  # 사용자 지정 이름
# 바이너리를 GOPATH/bin 에 설치
go install
# 코드 포맷팅
go fmt ./...
# 문제 확인을 위해 코드 검사
go vet ./...
# 빌드 캐시 정리
go clean -cache
```

## 관련 링크 (Relevant Links)

- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/java">Java 치트 시트</router-link>

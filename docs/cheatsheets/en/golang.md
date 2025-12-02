---
title: 'Golang Cheatsheet | LabEx'
description: 'Learn Go programming with this comprehensive cheatsheet. Quick reference for Go syntax, goroutines, channels, interfaces, error handling, and concurrent programming for backend developers.'
pdfUrl: '/cheatsheets/pdf/golang-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Golang Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/golang">Learn Golang with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn Go programming through hands-on labs and real-world scenarios. LabEx provides comprehensive Go courses covering essential syntax, concurrency patterns, error handling, and advanced techniques. Master Go's unique features like goroutines, channels, and interfaces to build efficient, concurrent applications.
</base-disclaimer-content>
</base-disclaimer>

## Installation & Setup

### Install Go: Download & Extract

Download and install Go from the official website.

```bash
# Download from https://golang.org/dl/
# Linux/macOS - extract to /usr/local
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
# Add to PATH in ~/.bashrc or ~/.zshrc
export PATH=$PATH:/usr/local/go/bin
# Verify installation
go version
```

### Package Manager: Using Homebrew (macOS)

Install Go using Homebrew on macOS.

```bash
# Install Go with Homebrew
brew install go
# Verify installation
go version
go env GOPATH
```

### Windows Installation

Install Go on Windows systems.

```bash
# Download .msi installer from https://golang.org/dl/
# Run installer and follow prompts
# Verify in Command Prompt
go version
echo %GOPATH%
```

### Workspace Setup: `go mod init`

Initialize a new Go module and workspace.

```bash
# Create new directory and initialize module
mkdir my-go-project
cd my-go-project
go mod init my-go-project
# Create main.go
echo 'package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}' > main.go
# Run the program
go run main.go
```

### Environment Variables

Important Go environment variables.

```bash
# View all Go environment variables
go env
# Key variables
go env GOROOT    # Go installation directory
go env GOPATH    # Workspace directory
go env GOOS      # Operating system
go env GOARCH    # Architecture
```

### IDE Setup: VS Code

Configure VS Code for Go development.

```bash
# Install Go extension in VS Code
# Ctrl+Shift+P -> Go: Install/Update Tools
# Key features enabled:
# - Syntax highlighting
# - IntelliSense
# - Debugging
# - Testing integration
```

## Basic Syntax & Types

### Package & Imports

Every Go file begins with a package declaration and imports.

```go
package main
import (
    "fmt"
    "strings"
    "time"
)
// Single import
import "os"
```

### Variables & Constants

Declare and initialize variables and constants.

```go
// Variable declarations
var name string = "Go"
var age int = 15
var isOpen bool
// Short declaration
name := "Golang"
count := 42
// Constants
const Pi = 3.14159
const Message = "Hello, Go!"
```

<BaseQuiz id="golang-variables-1" correct="B">
  <template #question>
    What is the difference between `var name string = "Go"` and `name := "Go"`?
  </template>
  
  <BaseQuizOption value="A">There is no difference</BaseQuizOption>
  <BaseQuizOption value="B" correct>`:=` is short declaration that infers the type, `var` explicitly declares the type</BaseQuizOption>
  <BaseQuizOption value="C">`:=` can only be used for constants</BaseQuizOption>
  <BaseQuizOption value="D">`var` can only be used inside functions</BaseQuizOption>
  
  <BaseQuizAnswer>
    The `:=` operator is shorthand for variable declaration and initialization, and Go infers the type automatically. `var` explicitly declares the variable type and can be used at package level or function level.
  </BaseQuizAnswer>
</BaseQuiz>

### Basic Data Types

Fundamental types available in Go.

```go
// Numeric types
var i int = 42
var f float64 = 3.14
var c complex64 = 1 + 2i
// Text types
var s string = "Hello"
var r rune = 'A'
// Boolean
var b bool = true
```

## Control Flow

### Conditionals: `if` / `else` / `switch`

Control program flow with conditional statements.

```go
// If statements
if age >= 18 {
    fmt.Println("Adult")
} else if age >= 13 {
    fmt.Println("Teenager")
} else {
    fmt.Println("Child")
}
// Switch statements
switch day {
case "Monday":
    fmt.Println("Start of work week")
case "Friday":
    fmt.Println("TGIF")
default:
    fmt.Println("Regular day")
}
```

### Loops: `for` / `range`

Iterate using various loop constructs.

```go
// Traditional for loop
for i := 0; i < 10; i++ {
    fmt.Println(i)
}
// While-style loop
for condition {
    // loop body
}
// Infinite loop
for {
    // break when needed
}
```

### Range Iteration

Iterate over slices, arrays, maps, and strings.

```go
// Iterate over slice
numbers := []int{1, 2, 3, 4, 5}
for index, value := range numbers {
    fmt.Printf("Index: %d, Value: %d\n", index, value)
}
// Iterate over map
colors := map[string]string{"red": "#FF0000", "green": "#00FF00"}
for key, value := range colors {
    fmt.Printf("%s: %s\n", key, value)
}
// Iterate over string
for i, char := range "Hello" {
    fmt.Printf("%d: %c\n", i, char)
}
```

<BaseQuiz id="golang-range-1" correct="B">
  <template #question>
    What does `range` return when iterating over a slice in Go?
  </template>
  
  <BaseQuizOption value="A">Only the value</BaseQuizOption>
  <BaseQuizOption value="B" correct>Both the index and the value</BaseQuizOption>
  <BaseQuizOption value="C">Only the index</BaseQuizOption>
  <BaseQuizOption value="D">The length of the slice</BaseQuizOption>
  
  <BaseQuizAnswer>
    When using `range` with a slice, it returns two values: the index (position) and the value at that index. You can use `_` to ignore either value if you don't need it.
  </BaseQuizAnswer>
</BaseQuiz>

### Control Statements: `break` / `continue`

Control loop execution flow.

```go
// Break out of loop
for i := 0; i < 10; i++ {
    if i == 5 {
        break
    }
    fmt.Println(i)
}
// Skip current iteration
for i := 0; i < 5; i++ {
    if i == 2 {
        continue
    }
    fmt.Println(i)
}
```

<BaseQuiz id="golang-control-1" correct="C">
  <template #question>
    What is the difference between `break` and `continue` in Go loops?
  </template>
  
  <BaseQuizOption value="A">There is no difference</BaseQuizOption>
  <BaseQuizOption value="B">break skips the current iteration, continue exits the loop</BaseQuizOption>
  <BaseQuizOption value="C" correct>break exits the loop completely, continue skips to the next iteration</BaseQuizOption>
  <BaseQuizOption value="D">Both exit the loop</BaseQuizOption>
  
  <BaseQuizAnswer>
    `break` immediately exits the loop and continues execution after the loop. `continue` skips the rest of the current iteration and moves to the next iteration of the loop.
  </BaseQuizAnswer>
</BaseQuiz>

## Functions

### Function Declaration: `func`

Define functions with parameters and return values.

```go
// Basic function
func greet(name string) {
    fmt.Printf("Hello, %s!\n", name)
}
// Function with return value
func add(a, b int) int {
    return a + b
}
// Multiple return values
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
```

### Named Returns & Variadic Functions

Advanced function features and patterns.

```go
// Named return values
func split(sum int) (x, y int) {
    x = sum * 4 / 9
    y = sum - x
    return // naked return
}
// Variadic function
func sum(nums ...int) int {
    total := 0
    for _, num := range nums {
        total += num
    }
    return total
}
// Usage
result := sum(1, 2, 3, 4, 5)
```

### Function Types & Closures

Functions as first-class citizens in Go.

```go
// Function as variable
var multiply func(int, int) int
multiply = func(a, b int) int {
    return a * b
}
// Anonymous function
square := func(x int) int {
    return x * x
}
// Closure
func counter() func() int {
    count := 0
    return func() int {
        count++
        return count
    }
}
// Usage
c := counter()
fmt.Println(c()) // 1
fmt.Println(c()) // 2
```

### Defer Statement

Defer execution of functions until surrounding function returns.

```go
func processFile(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close() // Executed when function returns

    // Process file contents
    // file.Close() will be called automatically
}
```

## Data Structures

### Arrays & Slices

Fixed and dynamic sequences of elements.

```go
// Arrays (fixed size)
var arr [5]int = [5]int{1, 2, 3, 4, 5}
shortArr := [3]string{"a", "b", "c"}
// Slices (dynamic)
var slice []int
slice = append(slice, 1, 2, 3)
// Make slice with capacity
numbers := make([]int, 5, 10) // length 5, capacity 10
// Slice operations
slice2 := slice[1:3]  // [2, 3]
copy(slice2, slice)   // Copy elements
```

### Maps

Key-value pairs for efficient lookups.

```go
// Map declaration and initialization
var m map[string]int
m = make(map[string]int)
// Short declaration
ages := map[string]int{
    "Alice": 30,
    "Bob":   25,
    "Carol": 35,
}
// Map operations
ages["David"] = 40        // Add/update
delete(ages, "Bob")       // Delete
age, exists := ages["Alice"] // Check existence
```

### Structs

Group related data together with custom types.

```go
// Struct definition
type Person struct {
    Name    string
    Age     int
    Email   string
}
// Create struct instances
p1 := Person{
    Name:  "Alice",
    Age:   30,
    Email: "alice@example.com",
}
p2 := Person{"Bob", 25, "bob@example.com"}
// Access fields
fmt.Println(p1.Name)
p1.Age = 31
```

### Pointers

Reference memory addresses of variables.

```go
// Pointer declaration
var p *int
num := 42
p = &num  // Address of num
// Dereferencing
fmt.Println(*p) // Value at address (42)
*p = 100        // Change value through pointer
// Pointers with structs
person := &Person{Name: "Alice", Age: 30}
person.Age = 31  // Automatic dereferencing
```

## Methods & Interfaces

### Methods

Attach functionality to custom types.

```go
type Rectangle struct {
    Width, Height float64
}
// Method with receiver
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}
// Pointer receiver (can modify)
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor
    r.Height *= factor
}
// Usage
rect := Rectangle{Width: 10, Height: 5}
fmt.Println(rect.Area()) // 50
rect.Scale(2)            // Modifies rect
```

### Interfaces

Define contracts that types must satisfy.

```go
// Interface definition
type Shape interface {
    Area() float64
    Perimeter() float64
}
// Implement interface for Rectangle
func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}
// Rectangle now implements Shape interface
func printShapeInfo(s Shape) {
    fmt.Printf("Area: %.2f, Perimeter: %.2f\n",
               s.Area(), s.Perimeter())
}
```

### Empty Interface & Type Assertions

Work with values of unknown types.

```go
// Empty interface can hold any value
var i interface{}
i = 42
i = "hello"
i = []int{1, 2, 3}
// Type assertion
str, ok := i.(string)
if ok {
    fmt.Printf("String value: %s\n", str)
}
// Type switch
switch v := i.(type) {
case int:
    fmt.Printf("Integer: %d\n", v)
case string:
    fmt.Printf("String: %s\n", v)
default:
    fmt.Printf("Unknown type: %T\n", v)
}
```

### Embedding

Compose types by embedding other types.

```go
type Person struct {
    Name string
    Age  int
}
type Employee struct {
    Person    // Embedded struct
    Company   string
    Salary    float64
}
// Usage
emp := Employee{
    Person:  Person{Name: "Alice", Age: 30},
    Company: "TechCorp",
    Salary:  75000,
}
// Access embedded fields directly
fmt.Println(emp.Name) // "Alice"
```

## Error Handling

### Basic Error Handling

Use the built-in error interface for error handling.

```go
import "errors"
// Function that returns an error
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
// Error checking
result, err := divide(10, 2)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Result: %.2f\n", result)
```

### Custom Errors

Create custom error types for specific error conditions.

```go
// Custom error type
type ValidationError struct {
    Field   string
    Message string
}
func (e ValidationError) Error() string {
    return fmt.Sprintf("validation error in %s: %s",
                       e.Field, e.Message)
}
// Function using custom error
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

### Error Wrapping

Add context to errors while preserving the original error.

```go
import "fmt"
// Wrap an error with additional context
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("failed to open file %s: %w",
                          filename, err)
    }
    defer file.Close()

    // Process file...
    return nil
}
// Unwrap errors
err := processFile("missing.txt")
if err != nil {
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        fmt.Println("Path error:", pathErr)
    }
}
```

### Panic & Recovery

Handle exceptional situations with panic and recover.

```go
// Function that might panic
func riskyOperation() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from panic:", r)
        }
    }()

    // This will cause a panic
    panic("something went wrong!")
}
// Usage
riskyOperation() // Program continues after panic
```

## Concurrency

### Goroutines

Lightweight threads managed by Go runtime.

```go
import "time"
// Simple goroutine
func sayHello() {
    fmt.Println("Hello from goroutine!")
}
func main() {
    // Start goroutine
    go sayHello()

    // Anonymous goroutine
    go func() {
        fmt.Println("Anonymous goroutine")
    }()

    // Wait for goroutines to finish
    time.Sleep(time.Second)
}
```

### Channels

Communication between goroutines using channels.

```go
// Create channel
ch := make(chan int)
// Buffered channel
buffered := make(chan string, 3)
// Send and receive
go func() {
    ch <- 42  // Send value
}()
value := <-ch  // Receive value
// Close channel
close(ch)
```

### Channel Patterns

Common patterns for channel communication.

```go
// Worker pattern
func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Worker %d processing job %d\n", id, job)
        results <- job * 2
    }
}
// Fan-out pattern
jobs := make(chan int, 100)
results := make(chan int, 100)
// Start workers
for w := 1; w <= 3; w++ {
    go worker(w, jobs, results)
}
// Send jobs
for j := 1; j <= 5; j++ {
    jobs <- j
}
close(jobs)
```

### Select Statement

Handle multiple channel operations simultaneously.

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

    // Select first available channel
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

## File I/O & JSON

### File Operations

Read and write files using various methods.

```go
import (
    "io/ioutil"
    "os"
)
// Read entire file
data, err := ioutil.ReadFile("file.txt")
if err != nil {
    log.Fatal(err)
}
content := string(data)
// Write to file
text := "Hello, World!"
err = ioutil.WriteFile("output.txt", []byte(text), 0644)
// Open file with more control
file, err := os.Open("data.txt")
if err != nil {
    log.Fatal(err)
}
defer file.Close()
```

### CSV Handling

Read and write CSV files.

```go
import (
    "encoding/csv"
    "os"
)
// Read CSV
file, _ := os.Open("data.csv")
defer file.Close()
reader := csv.NewReader(file)
records, _ := reader.ReadAll()
// Write CSV
file, _ = os.Create("output.csv")
defer file.Close()
writer := csv.NewWriter(file)
defer writer.Flush()
writer.Write([]string{"Name", "Age", "City"})
writer.Write([]string{"Alice", "30", "NYC"})
```

### JSON Processing

Encode and decode JSON data.

```go
import "encoding/json"
// Struct for JSON mapping
type Person struct {
    Name  string `json:"name"`
    Age   int    `json:"age"`
    Email string `json:"email,omitempty"`
}
// Marshal (Go to JSON)
person := Person{Name: "Alice", Age: 30}
jsonData, err := json.Marshal(person)
if err != nil {
    log.Fatal(err)
}
// Unmarshal (JSON to Go)
var p Person
err = json.Unmarshal(jsonData, &p)
```

### HTTP Requests

Make HTTP requests and handle responses.

```go
import "net/http"
// GET request
resp, err := http.Get("https://api.github.com/users/octocat")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
body, _ := ioutil.ReadAll(resp.Body)
// POST request with JSON
jsonData := []byte(`{"name":"Alice","age":30}`)
resp, err = http.Post("https://api.example.com/users",
                      "application/json",
                      bytes.NewBuffer(jsonData))
```

## Testing

### Unit Testing: `go test`

Write and run tests using Go's testing framework.

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
// Run tests
// go test
// go test -v (verbose)
```

### Table-Driven Tests

Test multiple cases efficiently.

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

### Benchmarking

Measure performance of functions.

```go
func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(2, 3)
    }
}
// Run benchmarks
// go test -bench=.
// go test -bench=BenchmarkAdd -benchmem
```

### Example Tests

Create executable examples that serve as documentation.

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
// Run examples
// go test -run Example
```

## Go Modules & Packages

### Module Management

Initialize and manage Go modules for dependency management.

```bash
# Initialize new module
go mod init github.com/username/project
# Add dependencies
go get github.com/gorilla/mux
go get -u github.com/gin-gonic/gin  # Update to latest
# Remove unused dependencies
go mod tidy
# Download dependencies
go mod download
# Vendor dependencies locally
go mod vendor
```

### go.mod File

Understanding the module definition file.

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

### Creating Packages

Structure code into reusable packages.

```go
// Package structure
// myproject/
//   ├── go.mod
//   ├── main.go
//   └── utils/
//       ├── math.go
//       └── string.go
// utils/math.go
package utils
// Exported function (starts with capital letter)
func Add(a, b int) int {
    return a + b
}
// Private function (starts with lowercase)
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

### Common Go Commands

Essential commands for Go development.

```bash
# Run Go program
go run main.go
# Build executable
go build
go build -o myapp  # Custom name
# Install binary to GOPATH/bin
go install
# Format code
go fmt ./...
# Vet code for issues
go vet ./...
# Clean build cache
go clean -cache
```

## Relevant Links

- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/shell">Shell Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/kubernetes">Kubernetes Cheatsheet</router-link>
- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/javascript">JavaScript Cheatsheet</router-link>
- <router-link to="/java">Java Cheatsheet</router-link>

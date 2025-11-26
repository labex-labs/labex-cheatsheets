---
title: 'Шпаргалка по Golang'
description: 'Изучите Golang с нашей подробной шпаргалкой по основным командам, концепциям и лучшим практикам.'
pdfUrl: '/cheatsheets/pdf/golang-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Golang
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/golang">Изучите Golang с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите программирование на Go с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по Go, охватывающие основной синтаксис, шаблоны параллелизма, обработку ошибок и продвинутые методы. Освойте уникальные возможности Go, такие как goroutines, каналы и интерфейсы, для создания эффективных, параллельных приложений.
</base-disclaimer-content>
</base-disclaimer>

## Установка и Настройка

### Установка Go: Загрузка и Распаковка

Загрузите и установите Go с официального сайта.

```bash
# Загрузить с https://golang.org/dl/
# Linux/macOS - распаковать в /usr/local
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
# Добавить в PATH в ~/.bashrc или ~/.zshrc
export PATH=$PATH:/usr/local/go/bin
# Проверить установку
go version
```

### Менеджер Пакетов: Использование Homebrew (macOS)

Установите Go с помощью Homebrew в macOS.

```bash
# Установить Go с помощью Homebrew
brew install go
# Проверить установку
go version
go env GOPATH
```

### Установка в Windows

Установка Go в системах Windows.

```bash
# Загрузить .msi установщик с https://golang.org/dl/
# Запустить установщик и следовать инструкциям
# Проверить в Командной Строке
go version
echo %GOPATH%
```

### Настройка Рабочей Области: `go mod init`

Инициализация нового модуля Go и рабочей области.

```bash
# Создать новую директорию и инициализировать модуль
mkdir my-go-project
cd my-go-project
go mod init my-go-project
# Создать main.go
echo 'package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}' > main.go
# Запустить программу
go run main.go
```

### Переменные Окружения

Важные переменные окружения Go.

```bash
# Просмотреть все переменные окружения Go
go env
# Ключевые переменные
go env GOROOT    # Директория установки Go
go env GOPATH    # Директория рабочей области
go env GOOS      # Операционная система
go env GOARCH    # Архитектура
```

### Настройка IDE: VS Code

Настройка VS Code для разработки на Go.

```bash
# Установить расширение Go в VS Code
# Ctrl+Shift+P -> Go: Install/Update Tools
# Включены ключевые функции:
# - Подсветка синтаксиса
# - IntelliSense
# - Отладка
# - Интеграция тестирования
```

## Базовый Синтаксис и Типы

### Пакет и Импорты

Каждый файл Go начинается с объявления пакета и импортов.

```go
package main
import (
    "fmt"
    "strings"
    "time"
)
// Единичный импорт
import "os"
```

### Переменные и Константы

Объявление и инициализация переменных и констант.

```go
// Объявление переменных
var name string = "Go"
var age int = 15
var isOpen bool
// Короткое объявление
name := "Golang"
count := 42
// Константы
const Pi = 3.14159
const Message = "Hello, Go!"
```

### Основные Типы Данных

Фундаментальные типы, доступные в Go.

```go
// Числовые типы
var i int = 42
var f float64 = 3.14
var c complex64 = 1 + 2i
// Текстовые типы
var s string = "Hello"
var r rune = 'A'
// Булевы
var b bool = true
```

## Управление Потоком

### Условные Операторы: `if` / `else` / `switch`

Управление потоком программы с помощью условных операторов.

```go
// Операторы If
if age >= 18 {
    fmt.Println("Adult")
} else if age >= 13 {
    fmt.Println("Teenager")
} else {
    fmt.Println("Child")
}
// Операторы Switch
switch day {
case "Monday":
    fmt.Println("Start of work week")
case "Friday":
    fmt.Println("TGIF")
default:
    fmt.Println("Regular day")
}
```

### Циклы: `for` / `range`

Итерация с использованием различных конструкций цикла.

```go
// Традиционный цикл for
for i := 0; i < 10; i++ {
    fmt.Println(i)
}
// Цикл в стиле While
for condition {
    // Тело цикла
}
// Бесконечный цикл
for {
    // прервать при необходимости
}
```

### Итерация Range

Итерация по срезам, массивам, картам и строкам.

```go
// Итерация по срезу
numbers := []int{1, 2, 3, 4, 5}
for index, value := range numbers {
    fmt.Printf("Index: %d, Value: %d\n", index, value)
}
// Итерация по карте
colors := map[string]string{"red": "#FF0000", "green": "#00FF00"}
for key, value := range colors {
    fmt.Printf("%s: %s\n", key, value)
}
// Итерация по строке
for i, char := range "Hello" {
    fmt.Printf("%d: %c\n", i, char)
}
```

### Операторы Управления: `break` / `continue`

Управление потоком выполнения цикла.

```go
// Выход из цикла
for i := 0; i < 10; i++ {
    if i == 5 {
        break
    }
    fmt.Println(i)
}
// Пропуск текущей итерации
for i := 0; i < 5; i++ {
    if i == 2 {
        continue
    }
    fmt.Println(i)
}
```

## Функции

### Объявление Функции: `func`

Определение функций с параметрами и возвращаемыми значениями.

```go
// Базовая функция
func greet(name string) {
    fmt.Printf("Hello, %s!\n", name)
}
// Функция с возвращаемым значением
func add(a, b int) int {
    return a + b
}
// Множественные возвращаемые значения
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
```

### Именованные Возвращаемые Значения и Вариативные Функции

Расширенные возможности функций и шаблоны.

```go
// Именованные возвращаемые значения
func split(sum int) (x, y int) {
    x = sum * 4 / 9
    y = sum - x
    return // голый возврат
}
// Вариативная функция
func sum(nums ...int) int {
    total := 0
    for _, num := range nums {
        total += num
    }
    return total
}
// Использование
result := sum(1, 2, 3, 4, 5)
```

### Типы Функций и Замыкания (Closures)

Функции как объекты первого класса в Go.

```go
// Функция как переменная
var multiply func(int, int) int
multiply = func(a, b int) int {
    return a * b
}
// Анонимная функция
square := func(x int) int {
    return x * x
}
// Замыкание
func counter() func() int {
    count := 0
    return func() int {
        count++
        return count
    }
}
// Использование
c := counter()
fmt.Println(c()) // 1
fmt.Println(c()) // 2
```

### Оператор Defer

Отложить выполнение функций до возврата окружающей функции.

```go
func processFile(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close() // Выполняется при возврате функции

    // Обработка содержимого файла
    // file.Close() будет вызван автоматически
}
```

## Структуры Данных

### Массивы и Срезы (Arrays & Slices)

Фиксированные и динамические последовательности элементов.

```go
// Массивы (фиксированный размер)
var arr [5]int = [5]int{1, 2, 3, 4, 5}
shortArr := [3]string{"a", "b", "c"}
// Срезы (динамические)
var slice []int
slice = append(slice, 1, 2, 3)
// Создать срез с емкостью
numbers := make([]int, 5, 10) // длина 5, емкость 10
// Операции со срезами
slice2 := slice[1:3]  // [2, 3]
copy(slice2, slice)   // Копировать элементы
```

### Карты (Maps)

Пары ключ-значение для эффективного поиска.

```go
// Объявление и инициализация карты
var m map[string]int
m = make(map[string]int)
// Короткое объявление
ages := map[string]int{
    "Alice": 30,
    "Bob":   25,
    "Carol": 35,
}
// Операции с картой
ages["David"] = 40        // Добавить/обновить
delete(ages, "Bob")       // Удалить
age, exists := ages["Alice"] // Проверить существование
```

### Структуры (Structs)

Группировка связанных данных с пользовательскими типами.

```go
// Определение структуры
type Person struct {
    Name    string
    Age     int
    Email   string
}
// Создание экземпляров структуры
p1 := Person{
    Name:  "Alice",
    Age:   30,
    Email: "alice@example.com",
}
p2 := Person{"Bob", 25, "bob@example.com"}
// Доступ к полям
fmt.Println(p1.Name)
p1.Age = 31
```

### Указатели (Pointers)

Ссылки на адреса памяти переменных.

```go
// Объявление указателя
var p *int
num := 42
p = &num  // Адрес num
// Разыменование
fmt.Println(*p) // Значение по адресу (42)
*p = 100        // Изменить значение через указатель
// Указатели со структурами
person := &Person{Name: "Alice", Age: 30}
person.Age = 31  // Автоматическое разыменование
```

## Методы и Интерфейсы

### Методы

Привязка функциональности к пользовательским типам.

```go
type Rectangle struct {
    Width, Height float64
}
// Метод с получателем (receiver)
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}
// Метод с указателем-получателем (может изменять)
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor
    r.Height *= factor
}
// Использование
rect := Rectangle{Width: 10, Height: 5}
fmt.Println(rect.Area()) // 50
rect.Scale(2)            // Изменяет rect
```

### Интерфейсы

Определение контрактов, которым должны соответствовать типы.

```go
// Определение интерфейса
type Shape interface {
    Area() float64
    Perimeter() float64
}
// Реализация интерфейса для Rectangle
func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}
// Rectangle теперь реализует интерфейс Shape
func printShapeInfo(s Shape) {
    fmt.Printf("Area: %.2f, Perimeter: %.2f\n",
               s.Area(), s.Perimeter())
}
```

### Пустой Интерфейс и Приведение Типов (Type Assertions)

Работа со значениями неизвестных типов.

```go
// Пустой интерфейс может хранить любое значение
var i interface{}
i = 42
i = "hello"
i = []int{1, 2, 3}
// Приведение типа
str, ok := i.(string)
if ok {
    fmt.Printf("String value: %s\n", str)
}
// Переключатель типов (Type switch)
switch v := i.(type) {
case int:
    fmt.Printf("Integer: %d\n", v)
case string:
    fmt.Printf("String: %s\n", v)
default:
    fmt.Printf("Unknown type: %T\n", v)
}
```

### Встраивание (Embedding)

Компоновка типов путем встраивания других типов.

```go
type Person struct {
    Name string
    Age  int
}
type Employee struct {
    Person    // Встроенная структура
    Company   string
    Salary    float64
}
// Использование
emp := Employee{
    Person:  Person{Name: "Alice", Age: 30},
    Company: "TechCorp",
    Salary:  75000,
}
// Прямой доступ к полям встроенного типа
fmt.Println(emp.Name) // "Alice"
```

## Обработка Ошибок

### Базовая Обработка Ошибок

Использование встроенного интерфейса error для обработки ошибок.

```go
import "errors"
// Функция, возвращающая ошибку
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
// Проверка ошибок
result, err := divide(10, 2)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Result: %.2f\n", result)
```

### Пользовательские Ошибки

Создание пользовательских типов ошибок для специфических условий.

```go
// Пользовательский тип ошибки
type ValidationError struct {
    Field   string
    Message string
}
func (e ValidationError) Error() string {
    return fmt.Sprintf("validation error in %s: %s",
                       e.Field, e.Message)
}
// Функция, использующая пользовательскую ошибку
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

### Оборачивание Ошибок (Error Wrapping)

Добавление контекста к ошибкам с сохранением исходной ошибки.

```go
import "fmt"
// Оборачивание ошибки с дополнительным контекстом
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("failed to open file %s: %w",
                          filename, err)
    }
    defer file.Close()

    // Обработка файла...
    return nil
}
// Разворачивание ошибок
err := processFile("missing.txt")
if err != nil {
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        fmt.Println("Path error:", pathErr)
    }
}
```

### Panic и Recovery

Обработка исключительных ситуаций с помощью panic и recover.

```go
// Функция, которая может вызвать panic
func riskyOperation() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from panic:", r)
        }
    }()

    // Это вызовет panic
    panic("something went wrong!")
}
// Использование
riskyOperation() // Программа продолжает работу после panic
```

## Параллелизм (Concurrency)

### Goroutines

Легковесные потоки, управляемые средой выполнения Go.

```go
import "time"
// Простая goroutine
func sayHello() {
    fmt.Println("Hello from goroutine!")
}
func main() {
    // Запуск goroutine
    go sayHello()

    // Анонимная goroutine
    go func() {
        fmt.Println("Anonymous goroutine")
    }()

    // Ожидание завершения goroutines
    time.Sleep(time.Second)
}
```

### Каналы (Channels)

Обмен данными между goroutines с использованием каналов.

```go
// Создание канала
ch := make(chan int)
// Буферизованный канал
buffered := make(chan string, 3)
// Отправка и получение
go func() {
    ch <- 42  // Отправить значение
}()
value := <-ch  // Получить значение
// Закрытие канала
close(ch)
```

### Шаблоны Каналов

Общие шаблоны для коммуникации по каналам.

```go
// Шаблон Рабочий (Worker)
func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Worker %d processing job %d\n", id, job)
        results <- job * 2
    }
}
// Шаблон Распределение (Fan-out)
jobs := make(chan int, 100)
results := make(chan int, 100)
// Запуск рабочих
for w := 1; w <= 3; w++ {
    go worker(w, jobs, results)
}
// Отправка заданий
for j := 1; j <= 5; j++ {
    jobs <- j
}
close(jobs)
```

### Оператор Select

Обработка нескольких канальных операций одновременно.

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

    // Выбрать первый доступный канал
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

## Файловый Ввод/Вывод и JSON

### Файловые Операции

Чтение и запись файлов с использованием различных методов.

```go
import (
    "io/ioutil"
    "os"
)
// Чтение всего файла
data, err := ioutil.ReadFile("file.txt")
if err != nil {
    log.Fatal(err)
}
content := string(data)
// Запись в файл
text := "Hello, World!"
err = ioutil.WriteFile("output.txt", []byte(text), 0644)
// Открытие файла с большим контролем
file, err := os.Open("data.txt")
if err != nil {
    log.Fatal(err)
}
defer file.Close()
```

### Обработка CSV

Чтение и запись CSV файлов.

```go
import (
    "encoding/csv"
    "os"
)
// Чтение CSV
file, _ := os.Open("data.csv")
defer file.Close()
reader := csv.NewReader(file)
records, _ := reader.ReadAll()
// Запись CSV
file, _ = os.Create("output.csv")
defer file.Close()
writer := csv.NewWriter(file)
defer writer.Flush()
writer.Write([]string{"Name", "Age", "City"})
writer.Write([]string{"Alice", "30", "NYC"})
```

### Обработка JSON

Кодирование и декодирование данных JSON.

```go
import "encoding/json"
// Структура для сопоставления с JSON
type Person struct {
    Name  string `json:"name"`
    Age   int    `json:"age"`
    Email string `json:"email,omitempty"`
}
// Маршалирование (Go в JSON)
person := Person{Name: "Alice", Age: 30}
jsonData, err := json.Marshal(person)
if err != nil {
    log.Fatal(err)
}
// Размаршалирование (JSON в Go)
var p Person
err = json.Unmarshal(jsonData, &p)
```

### HTTP Запросы

Выполнение HTTP-запросов и обработка ответов.

```go
import "net/http"
// GET запрос
resp, err := http.Get("https://api.github.com/users/octocat")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
body, _ := ioutil.ReadAll(resp.Body)
// POST запрос с JSON
jsonData := []byte(`{"name":"Alice","age":30}`)
resp, err = http.Post("https://api.example.com/users",
                      "application/json",
                      bytes.NewBuffer(jsonData))
```

## Тестирование

### Модульное Тестирование: `go test`

Написание и запуск тестов с использованием фреймворка тестирования Go.

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
// Запуск тестов
// go test
// go test -v (подробный)
```

### Табличные Тесты (Table-Driven Tests)

Эффективное тестирование нескольких случаев.

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

### Бенчмаркинг (Benchmarking)

Измерение производительности функций.

```go
func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(2, 3)
    }
}
// Запуск бенчмарков
// go test -bench=.
// go test -bench=BenchmarkAdd -benchmem
```

### Тесты-Примеры (Example Tests)

Создание исполняемых примеров, служащих документацией.

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
// Запуск примеров
// go test -run Example
```

## Go Модули и Пакеты

### Управление Модулями

Инициализация и управление модулями Go для управления зависимостями.

```bash
# Инициализировать новый модуль
go mod init github.com/username/project
# Добавить зависимости
go get github.com/gorilla/mux
go get -u github.com/gin-gonic/gin  # Обновить до последней версии
# Удалить неиспользуемые зависимости
go mod tidy
# Загрузить зависимости
go mod download
# Локально закешировать зависимости
go mod vendor
```

### Файл go.mod

Понимание файла определения модуля.

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

### Создание Пакетов

Структурирование кода в многократно используемые пакеты.

```go
// Структура пакета
// myproject/
//   ├── go.mod
//   ├── main.go
//   └── utils/
//       ├── math.go
//       └── string.go
// utils/math.go
package utils
// Экспортируемая функция (начинается с заглавной буквы)
func Add(a, b int) int {
    return a + b
}
// Приватная функция (начинается с маленькой буквы)
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

### Общие Команды Go

Основные команды для разработки на Go.

```bash
# Запустить программу Go
go run main.go
# Скомпилировать исполняемый файл
go build
go build -o myapp  # Пользовательское имя
# Установить бинарный файл в GOPATH/bin
go install
# Отформатировать код
go fmt ./...
# Проверить код на наличие проблем
go vet ./...
# Очистить кэш сборки
go clean -cache
```

## Соответствующие Ссылки

- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>
- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/java">Шпаргалка по Java</router-link>

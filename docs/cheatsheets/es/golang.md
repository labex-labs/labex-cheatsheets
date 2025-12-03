---
title: 'Hoja de Trucos de Golang | LabEx'
description: 'Aprenda programación Go con esta hoja de trucos completa. Referencia rápida de sintaxis de Go, gorutinas, canales, interfaces, manejo de errores y programación concurrente para desarrolladores backend.'
pdfUrl: '/cheatsheets/pdf/golang-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Golang
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/golang">Aprende Golang con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende programación Go a través de laboratorios prácticos y escenarios del mundo real. LabEx proporciona cursos completos de Go que cubren sintaxis esencial, patrones de concurrencia, manejo de errores y técnicas avanzadas. Domina las características únicas de Go como goroutines, canales e interfaces para construir aplicaciones concurrentes y eficientes.
</base-disclaimer-content>
</base-disclaimer>

## Instalación y Configuración

### Instalar Go: Descargar y Extraer

Descarga e instala Go desde el sitio web oficial.

```bash
# Descargar desde https://golang.org/dl/
# Linux/macOS - extraer en /usr/local
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
# Añadir a PATH en ~/.bashrc o ~/.zshrc
export PATH=$PATH:/usr/local/go/bin
# Verificar instalación
go version
```

### Gestor de Paquetes: Usando Homebrew (macOS)

Instala Go usando Homebrew en macOS.

```bash
# Instalar Go con Homebrew
brew install go
# Verificar instalación
go version
go env GOPATH
```

### Instalación en Windows

Instala Go en sistemas Windows.

```bash
# Descargar el instalador .msi desde https://golang.org/dl/
# Ejecutar el instalador y seguir las instrucciones
# Verificar en el Símbolo del sistema (Command Prompt)
go version
echo %GOPATH%
```

### Configuración del Espacio de Trabajo: `go mod init`

Inicializa un nuevo módulo y espacio de trabajo de Go.

```bash
# Crear nuevo directorio e inicializar módulo
mkdir my-go-project
cd my-go-project
go mod init my-go-project
# Crear main.go
echo 'package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}' > main.go
# Ejecutar el programa
go run main.go
```

### Variables de Entorno

Variables de entorno importantes de Go.

```bash
# Ver todas las variables de entorno de Go
go env
# Variables clave
go env GOROOT    # Directorio de instalación de Go
go env GOPATH    # Directorio del espacio de trabajo
go env GOOS      # Sistema operativo
go env GOARCH    # Arquitectura
```

### Configuración del IDE: VS Code

Configura VS Code para el desarrollo en Go.

```bash
# Instalar la extensión Go en VS Code
# Ctrl+Shift+P -> Go: Install/Update Tools
# Características clave habilitadas:
# - Resaltado de sintaxis
# - IntelliSense
# - Depuración (Debugging)
# - Integración de pruebas (Testing)
```

## Sintaxis Básica y Tipos

### Paquete e Importaciones

Cada archivo Go comienza con una declaración de paquete e importaciones.

```go
package main
import (
    "fmt"
    "strings"
    "time"
)
// Importación única
import "os"
```

### Variables y Constantes

Declara e inicializa variables y constantes.

```go
// Declaraciones de variables
var name string = "Go"
var age int = 15
var isOpen bool
// Declaración corta
name := "Golang"
count := 42
// Constantes
const Pi = 3.14159
const Message = "Hello, Go!"
```

<BaseQuiz id="golang-variables-1" correct="B">
  <template #question>
    ¿Cuál es la diferencia entre <code>var name string = "Go"</code> y <code>name := "Go"</code>?
  </template>
  
  <BaseQuizOption value="A">No hay diferencia</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>:=</code> es una declaración corta que infiere el tipo, <code>var</code> declara explícitamente el tipo</BaseQuizOption>
  <BaseQuizOption value="C"><code>:=</code> solo se puede usar para constantes</BaseQuizOption>
  <BaseQuizOption value="D"><code>var</code> solo se puede usar dentro de funciones</BaseQuizOption>
  
  <BaseQuizAnswer>
    El operador <code>:=</code> es una abreviatura para la declaración e inicialización de variables, y Go infiere el tipo automáticamente. <code>var</code> declara explícitamente el tipo de variable y se puede usar a nivel de paquete o función.
  </BaseQuizAnswer>
</BaseQuiz>

### Tipos de Datos Básicos

Tipos fundamentales disponibles en Go.

```go
// Tipos numéricos
var i int = 42
var f float64 = 3.14
var c complex64 = 1 + 2i
// Tipos de texto
var s string = "Hello"
var r rune = 'A'
// Booleano
var b bool = true
```

## Flujo de Control

### Condicionales: `if` / `else` / `switch`

Controla el flujo del programa con sentencias condicionales.

```go
// Sentencias If
if age >= 18 {
    fmt.Println("Adulto")
} else if age >= 13 {
    fmt.Println("Adolescente")
} else {
    fmt.Println("Niño")
}
// Sentencias Switch
switch day {
case "Lunes":
    fmt.Println("Inicio de la semana laboral")
case "Viernes":
    fmt.Println("Viernes")
default:
    fmt.Println("Día normal")
}
```

### Bucles: `for` / `range`

Itera usando varias construcciones de bucle.

```go
// Bucle for tradicional
for i := 0; i < 10; i++ {
    fmt.Println(i)
}
// Bucle estilo While
for condition {
    // cuerpo del bucle
}
// Bucle infinito
for {
    // romper cuando sea necesario
}
```

### Iteración con Range

Itera sobre slices, arrays, mapas y cadenas.

```go
// Iterar sobre slice
numbers := []int{1, 2, 3, 4, 5}
for index, value := range numbers {
    fmt.Printf("Índice: %d, Valor: %d\n", index, value)
}
// Iterar sobre mapa
colors := map[string]string{"red": "#FF0000", "green": "#00FF00"}
for key, value := range colors {
    fmt.Printf("%s: %s\n", key, value)
}
// Iterar sobre cadena (string)
for i, char := range "Hello" {
    fmt.Printf("%d: %c\n", i, char)
}
```

<BaseQuiz id="golang-range-1" correct="B">
  <template #question>
    ¿Qué devuelve <code>range</code> al iterar sobre un slice en Go?
  </template>
  
  <BaseQuizOption value="A">Solo el valor</BaseQuizOption>
  <BaseQuizOption value="B" correct>Tanto el índice como el valor</BaseQuizOption>
  <BaseQuizOption value="C">Solo el índice</BaseQuizOption>
  <BaseQuizOption value="D">La longitud del slice</BaseQuizOption>
  
  <BaseQuizAnswer>
    Cuando se usa <code>range</code> con un slice, devuelve dos valores: el índice (posición) y el valor en ese índice. Se puede usar <code>_</code> para ignorar cualquiera de los valores si no se necesita.
  </BaseQuizAnswer>
</BaseQuiz>

### Sentencias de Control: `break` / `continue`

Controla el flujo de ejecución del bucle.

```go
// Salir del bucle
for i := 0; i < 10; i++ {
    if i == 5 {
        break
    }
    fmt.Println(i)
}
// Omitir la iteración actual
for i := 0; i < 5; i++ {
    if i == 2 {
        continue
    }
    fmt.Println(i)
}
```

<BaseQuiz id="golang-control-1" correct="C">
  <template #question>
    ¿Cuál es la diferencia entre <code>break</code> y <code>continue</code> en los bucles de Go?
  </template>
  
  <BaseQuizOption value="A">No hay diferencia</BaseQuizOption>
  <BaseQuizOption value="B">break omite la iteración actual, continue sale del bucle</BaseQuizOption>
  <BaseQuizOption value="C" correct>break sale completamente del bucle, continue salta a la siguiente iteración</BaseQuizOption>
  <BaseQuizOption value="D">Ambos salen del bucle</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>break</code> sale inmediatamente del bucle y continúa la ejecución después del bucle. <code>continue</code> omite el resto de la iteración actual y pasa a la siguiente iteración del bucle.
  </BaseQuizAnswer>
</BaseQuiz>

## Funciones

### Declaración de Función: `func`

Define funciones con parámetros y valores de retorno.

```go
// Función básica
func greet(name string) {
    fmt.Printf("Hola, %s!\n", name)
}
// Función con valor de retorno
func add(a, b int) int {
    return a + b
}
// Múltiples valores de retorno
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("división por cero")
    }
    return a / b, nil
}
```

### Retornos Nombrados y Funciones Variádicas

Características avanzadas de las funciones y patrones.

```go
// Valores de retorno nombrados
func split(sum int) (x, y int) {
    x = sum * 4 / 9
    y = sum - x
    return // retorno desnudo
}
// Función variádica
func sum(nums ...int) int {
    total := 0
    for _, num := range nums {
        total += num
    }
    return total
}
// Uso
result := sum(1, 2, 3, 4, 5)
```

### Tipos de Función y Clausuras (Closures)

Funciones como ciudadanos de primera clase en Go.

```go
// Función como variable
var multiply func(int, int) int
multiply = func(a, b int) int {
    return a * b
}
// Función anónima
square := func(x int) int {
    return x * x
}
// Clausura (Closure)
func counter() func() int {
    count := 0
    return func() int {
        count++
        return count
    }
}
// Uso
c := counter()
fmt.Println(c()) // 1
fmt.Println(c()) // 2
```

### Sentencia Defer

Difiere la ejecución de funciones hasta que la función circundante retorna.

```go
func processFile(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close() // Se ejecuta cuando la función retorna

    // Procesar contenido del archivo
    // file.Close() se llamará automáticamente
}
```

## Estructuras de Datos

### Arrays y Slices

Secuencias fijas y dinámicas de elementos.

```go
// Arrays (tamaño fijo)
var arr [5]int = [5]int{1, 2, 3, 4, 5}
shortArr := [3]string{"a", "b", "c"}
// Slices (dinámicos)
var slice []int
slice = append(slice, 1, 2, 3)
// Crear slice con capacidad
numbers := make([]int, 5, 10) // longitud 5, capacidad 10
// Operaciones de slice
slice2 := slice[1:3]  // [2, 3]
copy(slice2, slice)   // Copiar elementos
```

### Mapas (Maps)

Pares clave-valor para búsquedas eficientes.

```go
// Declaración e inicialización de mapa
var m map[string]int
m = make(map[string]int)
// Declaración corta
ages := map[string]int{
    "Alice": 30,
    "Bob":   25,
    "Carol": 35,
}
// Operaciones de mapa
ages["David"] = 40        // Añadir/actualizar
delete(ages, "Bob")       // Eliminar
age, exists := ages["Alice"] // Comprobar existencia
```

### Estructuras (Structs)

Agrupa datos relacionados con tipos personalizados.

```go
// Definición de struct
type Person struct {
    Name    string
    Age     int
    Email   string
}
// Crear instancias de struct
p1 := Person{
    Name:  "Alice",
    Age:   30,
    Email: "alice@example.com",
}
p2 := Person{"Bob", 25, "bob@example.com"}
// Acceder a campos
fmt.Println(p1.Name)
p1.Age = 31
```

### Punteros (Pointers)

Referencia las direcciones de memoria de las variables.

```go
// Declaración de puntero
var p *int
num := 42
p = &num  // Dirección de num
// Desreferenciación
fmt.Println(*p) // Valor en la dirección (42)
*p = 100        // Cambiar valor a través del puntero
// Punteros con structs
person := &Person{Name: "Alice", Age: 30}
person.Age = 31  // Desreferenciación automática
```

## Métodos e Interfaces

### Métodos

Asocia funcionalidad a tipos personalizados.

```go
type Rectangle struct {
    Width, Height float64
}
// Método con receptor (receiver)
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}
// Receptor de puntero (puede modificar)
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor
    r.Height *= factor
}
// Uso
rect := Rectangle{Width: 10, Height: 5}
fmt.Println(rect.Area()) // 50
rect.Scale(2)            // Modifica rect
```

### Interfaces

Definen contratos que los tipos deben satisfacer.

```go
// Definición de interfaz
type Shape interface {
    Area() float64
    Perimeter() float64
}
// Implementar interfaz para Rectangle
func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}
// Rectangle ahora implementa la interfaz Shape
func printShapeInfo(s Shape) {
    fmt.Printf("Área: %.2f, Perímetro: %.2f\n",
               s.Area(), s.Perimeter())
}
```

### Interfaz Vacía y Asertos de Tipo (Type Assertions)

Trabaja con valores de tipos desconocidos.

```go
// La interfaz vacía puede contener cualquier valor
var i interface{}
i = 42
i = "hello"
i = []int{1, 2, 3}
// Aserto de tipo
str, ok := i.(string)
if ok {
    fmt.Printf("Valor de cadena: %s\n", str)
}
// Switch de tipo
switch v := i.(type) {
case int:
    fmt.Printf("Entero: %d\n", v)
case string:
    fmt.Printf("Cadena: %s\n", v)
default:
    fmt.Printf("Tipo desconocido: %T\n", v)
}
```

### Incrustación (Embedding)

Componer tipos incrustando otros tipos.

```go
type Person struct {
    Name string
    Age  int
}
type Employee struct {
    Person    // Struct incrustado
    Company   string
    Salary    float64
}
// Uso
emp := Employee{
    Person:  Person{Name: "Alice", Age: 30},
    Company: "TechCorp",
    Salary:  75000,
}
// Acceder a campos incrustados directamente
fmt.Println(emp.Name) // "Alice"
```

## Manejo de Errores

### Manejo Básico de Errores

Usa la interfaz de error incorporada para el manejo de errores.

```go
import "errors"
// Función que retorna un error
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("división por cero")
    }
    return a / b, nil
}
// Verificación de errores
result, err := divide(10, 2)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Resultado: %.2f\n", result)
```

### Errores Personalizados

Crea tipos de error personalizados para condiciones de error específicas.

```go
// Tipo de error personalizado
type ValidationError struct {
    Field   string
    Message string
}
func (e ValidationError) Error() string {
    return fmt.Sprintf("error de validación en %s: %s",
                       e.Field, e.Message)
}
// Función que usa error personalizado
func validateAge(age int) error {
    if age < 0 {
        return ValidationError{
            Field:   "age",
            Message: "debe ser no negativo",
        }
    }
    return nil
}
```

### Envoltura de Errores (Error Wrapping)

Añade contexto a los errores mientras se preserva el error original.

```go
import "fmt"
// Envolver un error con contexto adicional
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("falló al abrir el archivo %s: %w",
                          filename, err)
    }
    defer file.Close()

    // Procesar archivo...
    return nil
}
// Desenvolver errores
err := processFile("missing.txt")
if err != nil {
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        fmt.Println("Error de ruta:", pathErr)
    }
}
```

### Panic y Recuperación (Recovery)

Maneja situaciones excepcionales con `panic` y `recover`.

```go
// Función que podría causar pánico
func riskyOperation() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recuperado de pánico:", r)
        }
    }()

    // Esto causará un pánico
    panic("¡algo salió mal!")
}
// Uso
riskyOperation() // El programa continúa después del pánico
```

## Concurrencia

### Goroutines

Hilos ligeros gestionados por el runtime de Go.

```go
import "time"
// Goroutine simple
func sayHello() {
    fmt.Println("Hola desde goroutine!")
}
func main() {
    // Iniciar goroutine
    go sayHello()

    // Goroutine anónima
    go func() {
        fmt.Println("Goroutine anónima")
    }()

    // Esperar a que las goroutines terminen
    time.Sleep(time.Second)
}
```

### Canales (Channels)

Comunicación entre goroutines usando canales.

```go
// Crear canal
ch := make(chan int)
// Canal con buffer
buffered := make(chan string, 3)
// Enviar y recibir
go func() {
    ch <- 42  // Enviar valor
}()
value := <-ch  // Recibir valor
// Cerrar canal
close(ch)
```

### Patrones de Canal

Patrones comunes para la comunicación por canal.

```go
// Patrón de trabajador (Worker)
func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Trabajador %d procesando trabajo %d\n", id, job)
        results <- job * 2
    }
}
// Patrón Fan-out
jobs := make(chan int, 100)
results := make(chan int, 100)
// Iniciar trabajadores
for w := 1; w <= 3; w++ {
    go worker(w, jobs, results)
}
// Enviar trabajos
for j := 1; j <= 5; j++ {
    jobs <- j
}
close(jobs)
```

### Sentencia Select

Maneja múltiples operaciones de canal simultáneamente.

```go
func main() {
    ch1 := make(chan string)
    ch2 := make(chan string)

    go func() {
        time.Sleep(time.Second)
        ch1 <- "desde ch1"
    }()

    go func() {
        time.Sleep(2 * time.Second)
        ch2 <- "desde ch2"
    }()

    // Seleccionar el canal disponible primero
    select {
    case msg1 := <-ch1:
        fmt.Println(msg1)
    case msg2 := <-ch2:
        fmt.Println(msg2)
    case <-time.After(3 * time.Second):
        fmt.Println("tiempo de espera agotado")
    }
}
```

## E/S de Archivos y JSON

### Operaciones de Archivo

Leer y escribir archivos usando varios métodos.

```go
import (
    "io/ioutil"
    "os"
)
// Leer archivo completo
data, err := ioutil.ReadFile("file.txt")
if err != nil {
    log.Fatal(err)
}
content := string(data)
// Escribir en archivo
text := "Hello, World!"
err = ioutil.WriteFile("output.txt", []byte(text), 0644)
// Abrir archivo con más control
file, err := os.Open("data.txt")
if err != nil {
    log.Fatal(err)
}
defer file.Close()
```

### Manejo de CSV

Leer y escribir archivos CSV.

```go
import (
    "encoding/csv"
    "os"
)
// Leer CSV
file, _ := os.Open("data.csv")
defer file.Close()
reader := csv.NewReader(file)
records, _ := reader.ReadAll()
// Escribir CSV
file, _ = os.Create("output.csv")
defer file.Close()
writer := csv.NewWriter(file)
defer writer.Flush()
writer.Write([]string{"Nombre", "Edad", "Ciudad"})
writer.Write([]string{"Alice", "30", "NYC"})
```

### Procesamiento JSON

Codificar y decodificar datos JSON.

```go
import "encoding/json"
// Struct para mapeo JSON
type Person struct {
    Name  string `json:"name"`
    Age   int    `json:"age"`
    Email string `json:"email,omitempty"`
}
// Marshal (Go a JSON)
person := Person{Name: "Alice", Age: 30}
jsonData, err := json.Marshal(person)
if err != nil {
    log.Fatal(err)
}
// Unmarshal (JSON a Go)
var p Person
err = json.Unmarshal(jsonData, &p)
```

### Solicitudes HTTP

Realizar solicitudes HTTP y manejar respuestas.

```go
import "net/http"
// Solicitud GET
resp, err := http.Get("https://api.github.com/users/octocat")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
body, _ := ioutil.ReadAll(resp.Body)
// Solicitud POST con JSON
jsonData := []byte(`{"name":"Alice","age":30}`)
resp, err = http.Post("https://api.example.com/users",
                      "application/json",
                      bytes.NewBuffer(jsonData))
```

## Pruebas (Testing)

### Pruebas Unitarias: `go test`

Escribir y ejecutar pruebas usando el framework de pruebas de Go.

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
        t.Errorf("Add(2, 3) = %d; se esperaba %d", result, expected)
    }
}
// Ejecutar pruebas
// go test
// go test -v (verboso)
```

### Pruebas Basadas en Tablas (Table-Driven Tests)

Prueba múltiples casos de manera eficiente.

```go
func TestAddMultiple(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {"números positivos", 2, 3, 5},
        {"con cero", 0, 5, 5},
        {"números negativos", -1, -2, -3},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Add(tt.a, tt.b)
            if result != tt.expected {
                t.Errorf("obtuvo %d, se esperaba %d", result, tt.expected)
            }
        })
    }
}
```

### Benchmarking

Mide el rendimiento de las funciones.

```go
func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(2, 3)
    }
}
// Ejecutar benchmarks
// go test -bench=.
// go test -bench=BenchmarkAdd -benchmem
```

### Pruebas de Ejemplo (Example Tests)

Crea ejemplos ejecutables que sirven como documentación.

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
// Ejecutar ejemplos
// go test -run Example
```

## Módulos y Paquetes de Go

### Gestión de Módulos

Inicializa y gestiona módulos de Go para la gestión de dependencias.

```bash
# Inicializar nuevo módulo
go mod init github.com/username/project
# Añadir dependencias
go get github.com/gorilla/mux
go get -u github.com/gin-gonic/gin  # Actualizar a la última versión
# Eliminar dependencias no utilizadas
go mod tidy
# Descargar dependencias
go mod download
# Dependencias locales (vendor)
go mod vendor
```

### Archivo go.mod

Entendiendo el archivo de definición del módulo.

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

### Creación de Paquetes

Estructura el código en paquetes reutilizables.

```go
// Estructura del paquete
// myproject/
//   ├── go.mod
//   ├── main.go
//   └── utils/
//       ├── math.go
//       └── string.go
// utils/math.go
package utils
// Función exportada (comienza con mayúscula)
func Add(a, b int) int {
    return a + b
}
// Función privada (comienza con minúscula)
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

### Comandos Comunes de Go

Comandos esenciales para el desarrollo en Go.

```bash
# Ejecutar programa Go
go run main.go
# Compilar ejecutable
go build
go build -o myapp  # Nombre personalizado
# Instalar binario en GOPATH/bin
go install
# Formatear código
go fmt ./...
# Revisar código en busca de problemas
go vet ./...
# Limpiar caché de compilación
go clean -cache
```

## Enlaces Relevantes

- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>
- <router-link to="/kubernetes">Hoja de Trucos de Kubernetes</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/java">Hoja de Trucos de Java</router-link>

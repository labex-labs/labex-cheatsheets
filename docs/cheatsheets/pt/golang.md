---
title: 'Folha de Cola Go (Golang)'
description: 'Aprenda Golang com nossa folha de cola abrangente cobrindo comandos essenciais, conceitos e melhores práticas.'
pdfUrl: '/cheatsheets/pdf/golang-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas Golang
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/golang">Aprenda Golang com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda programação Go através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Go que cobrem sintaxe essencial, padrões de concorrência, tratamento de erros e técnicas avançadas. Domine os recursos exclusivos do Go, como goroutines, canais e interfaces, para construir aplicações eficientes e concorrentes.
</base-disclaimer-content>
</base-disclaimer>

## Instalação e Configuração

### Instalar Go: Baixar e Extrair

Baixe e instale o Go do site oficial.

```bash
# Baixar de https://golang.org/dl/
# Linux/macOS - extrair para /usr/local
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
# Adicionar ao PATH em ~/.bashrc ou ~/.zshrc
export PATH=$PATH:/usr/local/go/bin
# Verificar instalação
go version
```

### Gerenciador de Pacotes: Usando Homebrew (macOS)

Instalar Go usando Homebrew no macOS.

```bash
# Instalar Go com Homebrew
brew install go
# Verificar instalação
go version
go env GOPATH
```

### Instalação no Windows

Instalar Go em sistemas Windows.

```bash
# Baixar o instalador .msi de https://golang.org/dl/
# Executar o instalador e seguir as instruções
# Verificar no Prompt de Comando
go version
echo %GOPATH%
```

### Configuração do Espaço de Trabalho: `go mod init`

Inicializar um novo módulo e espaço de trabalho Go.

```bash
# Criar novo diretório e inicializar módulo
mkdir my-go-project
cd my-go-project
go mod init my-go-project
# Criar main.go
echo 'package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}' > main.go
# Executar o programa
go run main.go
```

### Variáveis de Ambiente

Variáveis de ambiente Go importantes.

```bash
# Visualizar todas as variáveis de ambiente Go
go env
# Variáveis chave
go env GOROOT    # Diretório de instalação do Go
go env GOPATH    # Diretório do espaço de trabalho
go env GOOS      # Sistema operacional
go env GOARCH    # Arquitetura
```

### Configuração do IDE: VS Code

Configurar o VS Code para desenvolvimento Go.

```bash
# Instalar a extensão Go no VS Code
# Ctrl+Shift+P -> Go: Install/Update Tools
# Principais recursos ativados:
# - Realce de sintaxe
# - IntelliSense
# - Debugging
# - Integração de testes
```

## Sintaxe Básica e Tipos

### Pacote e Imports

Todo arquivo Go começa com uma declaração de pacote e imports.

```go
package main
import (
    "fmt"
    "strings"
    "time"
)
// Importação única
import "os"
```

### Variáveis e Constantes

Declarar e inicializar variáveis e constantes.

```go
// Declarações de variáveis
var name string = "Go"
var age int = 15
var isOpen bool
// Declaração curta
name := "Golang"
count := 42
// Constantes
const Pi = 3.14159
const Message = "Hello, Go!"
```

### Tipos de Dados Básicos

Tipos fundamentais disponíveis em Go.

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

## Fluxo de Controle

### Condicionais: `if` / `else` / `switch`

Controlar o fluxo do programa com declarações condicionais.

```go
// Declarações If
if age >= 18 {
    fmt.Println("Adulto")
} else if age >= 13 {
    fmt.Println("Adolescente")
} else {
    fmt.Println("Criança")
}
// Declarações Switch
switch day {
case "Monday":
    fmt.Println("Início da semana de trabalho")
case "Friday":
    fmt.Println("Sextou")
default:
    fmt.Println("Dia normal")
}
```

### Loops: `for` / `range`

Iterar usando várias construções de loop.

```go
// Loop for tradicional
for i := 0; i < 10; i++ {
    fmt.Println(i)
}
// Loop estilo While
for condition {
    // corpo do loop
}
// Loop infinito
for {
    // sair quando necessário
}
```

### Iteração Range

Iterar sobre slices, arrays, mapas e strings.

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
// Iterar sobre string
for i, char := range "Hello" {
    fmt.Printf("%d: %c\n", i, char)
}
```

### Declarações de Controle: `break` / `continue`

Controlar o fluxo de execução do loop.

```go
// Sair do loop
for i := 0; i < 10; i++ {
    if i == 5 {
        break
    }
    fmt.Println(i)
}
// Pular iteração atual
for i := 0; i < 5; i++ {
    if i == 2 {
        continue
    }
    fmt.Println(i)
}
```

## Funções

### Declaração de Função: `func`

Definir funções com parâmetros e valores de retorno.

```go
// Função básica
func greet(name string) {
    fmt.Printf("Olá, %s!\n", name)
}
// Função com valor de retorno
func add(a, b int) int {
    return a + b
}
// Múltiplos valores de retorno
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("divisão por zero")
    }
    return a / b, nil
}
```

### Retornos Nomeados e Funções Variádicas

Recursos avançados de funções e padrões.

```go
// Valores de retorno nomeados
func split(sum int) (x, y int) {
    x = sum * 4 / 9
    y = sum - x
    return // retorno nu
}
// Função Variádica
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

### Tipos de Função e Fechamentos (Closures)

Funções como cidadãos de primeira classe em Go.

```go
// Função como variável
var multiply func(int, int) int
multiply = func(a, b int) int {
    return a * b
}
// Função anônima
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
// Uso
c := counter()
fmt.Println(c()) // 1
fmt.Println(c()) // 2
```

### Declaração Defer

Adiar a execução de funções até que a função circundante retorne.

```go
func processFile(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close() // Executado quando a função retorna

    // Processar conteúdo do arquivo
    // file.Close() será chamado automaticamente
}
```

## Estruturas de Dados

### Arrays e Slices

Sequências fixas e dinâmicas de elementos.

```go
// Arrays (tamanho fixo)
var arr [5]int = [5]int{1, 2, 3, 4, 5}
shortArr := [3]string{"a", "b", "c"}
// Slices (dinâmicos)
var slice []int
slice = append(slice, 1, 2, 3)
// Criar slice com capacidade
numbers := make([]int, 5, 10) // comprimento 5, capacidade 10
// Operações de Slice
slice2 := slice[1:3]  // [2, 3]
copy(slice2, slice)   // Copiar elementos
```

### Mapas (Maps)

Pares chave-valor para buscas eficientes.

```go
// Declaração e inicialização de Mapa
var m map[string]int
m = make(map[string]int)
// Declaração curta
ages := map[string]int{
    "Alice": 30,
    "Bob":   25,
    "Carol": 35,
}
// Operações de Mapa
ages["David"] = 40        // Adicionar/atualizar
delete(ages, "Bob")       // Excluir
age, exists := ages["Alice"] // Verificar existência
```

### Structs

Agrupar dados relacionados com tipos personalizados.

```go
// Definição de Struct
type Person struct {
    Name    string
    Age     int
    Email   string
}
// Criar instâncias de struct
p1 := Person{
    Name:  "Alice",
    Age:   30,
    Email: "alice@example.com",
}
p2 := Person{"Bob", 25, "bob@example.com"}
// Acessar campos
fmt.Println(p1.Name)
p1.Age = 31
```

### Ponteiros (Pointers)

Referenciar endereços de memória de variáveis.

```go
// Declaração de Ponteiro
var p *int
num := 42
p = &num  // Endereço de num
// Desreferenciação
fmt.Println(*p) // Valor no endereço (42)
*p = 100        // Mudar valor através do ponteiro
// Ponteiros com structs
person := &Person{Name: "Alice", Age: 30}
person.Age = 31  // Desreferenciação automática
```

## Métodos e Interfaces

### Métodos

Anexar funcionalidade a tipos personalizados.

```go
type Rectangle struct {
    Width, Height float64
}
// Método com receptor
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}
// Receptor de ponteiro (pode modificar)
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

Definir contratos que os tipos devem satisfazer.

```go
// Definição de Interface
type Shape interface {
    Area() float64
    Perimeter() float64
}
// Implementar interface para Rectangle
func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}
// Rectangle agora implementa a interface Shape
func printShapeInfo(s Shape) {
    fmt.Printf("Área: %.2f, Perímetro: %.2f\n",
               s.Area(), s.Perimeter())
}
```

### Interface Vazia e Asserções de Tipo

Trabalhar com valores de tipos desconhecidos.

```go
// Interface vazia pode conter qualquer valor
var i interface{}
i = 42
i = "hello"
i = []int{1, 2, 3}
// Asserção de tipo
str, ok := i.(string)
if ok {
    fmt.Printf("Valor da string: %s\n", str)
}
// Switch de tipo
switch v := i.(type) {
case int:
    fmt.Printf("Inteiro: %d\n", v)
case string:
    fmt.Printf("String: %s\n", v)
default:
    fmt.Printf("Tipo desconhecido: %T\n", v)
}
```

### Incorporação (Embedding)

Compor tipos incorporando outros tipos.

```go
type Person struct {
    Name string
    Age  int
}
type Employee struct {
    Person    // Struct incorporada
    Company   string
    Salary    float64
}
// Uso
emp := Employee{
    Person:  Person{Name: "Alice", Age: 30},
    Company: "TechCorp",
    Salary:  75000,
}
// Acessar campos incorporados diretamente
fmt.Println(emp.Name) // "Alice"
```

## Tratamento de Erros

### Tratamento Básico de Erros

Usar a interface de erro embutida para tratamento de erros.

```go
import "errors"
// Função que retorna um erro
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("divisão por zero")
    }
    return a / b, nil
}
// Verificação de erro
result, err := divide(10, 2)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Resultado: %.2f\n", result)
```

### Erros Personalizados

Criar tipos de erro personalizados para condições de erro específicas.

```go
// Tipo de erro personalizado
type ValidationError struct {
    Field   string
    Message string
}
func (e ValidationError) Error() string {
    return fmt.Sprintf("erro de validação em %s: %s",
                       e.Field, e.Message)
}
// Função usando erro personalizado
func validateAge(age int) error {
    if age < 0 {
        return ValidationError{
            Field:   "age",
            Message: "deve ser não negativo",
        }
    }
    return nil
}
```

### Encadeamento de Erros (Error Wrapping)

Adicionar contexto a erros, preservando o erro original.

```go
import "fmt"
// Encadeia um erro com contexto adicional
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("falha ao abrir arquivo %s: %w",
                          filename, err)
    }
    defer file.Close()

    // Processar arquivo...
    return nil
}
// Desencadear erros
err := processFile("missing.txt")
if err != nil {
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        fmt.Println("Erro de caminho:", pathErr)
    }
}
```

### Panic e Recovery

Lidar com situações excepcionais com `panic` e `recover`.

```go
// Função que pode entrar em pânico
func riskyOperation() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recuperado de pânico:", r)
        }
    }()

    // Isso causará um pânico
    panic("algo deu errado!")
}
// Uso
riskyOperation() // O programa continua após o pânico
```

## Concorrência

### Goroutines

Threads leves gerenciadas pelo runtime Go.

```go
import "time"
// Goroutine simples
func sayHello() {
    fmt.Println("Olá do goroutine!")
}
func main() {
    // Iniciar goroutine
    go sayHello()

    // Goroutine anônima
    go func() {
        fmt.Println("Goroutine anônima")
    }()

    // Esperar que os goroutines terminem
    time.Sleep(time.Second)
}
```

### Canais (Channels)

Comunicação entre goroutines usando canais.

```go
// Criar canal
ch := make(chan int)
// Canal com buffer
buffered := make(chan string, 3)
// Enviar e receber
go func() {
    ch <- 42  // Enviar valor
}()
value := <-ch  // Receber valor
// Fechar canal
close(ch)
```

### Padrões de Canal

Padrões comuns para comunicação de canal.

```go
// Padrão Worker
func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Trabalhador %d processando trabalho %d\n", id, job)
        results <- job * 2
    }
}
// Padrão Fan-out
jobs := make(chan int, 100)
results := make(chan int, 100)
// Iniciar trabalhadores
for w := 1; w <= 3; w++ {
    go worker(w, jobs, results)
}
// Enviar trabalhos
for j := 1; j <= 5; j++ {
    jobs <- j
}
close(jobs)
```

### Declaração Select

Lidar com múltiplas operações de canal simultaneamente.

```go
func main() {
    ch1 := make(chan string)
    ch2 := make(chan string)

    go func() {
        time.Sleep(time.Second)
        ch1 <- "de ch1"
    }()

    go func() {
        time.Sleep(2 * time.Second)
        ch2 <- "de ch2"
    }()

    // Selecionar o primeiro canal disponível
    select {
    case msg1 := <-ch1:
        fmt.Println(msg1)
    case msg2 := <-ch2:
        fmt.Println(msg2)
    case <-time.After(3 * time.Second):
        fmt.Println("tempo limite esgotado")
    }
}
```

## E/S de Arquivos e JSON

### Operações de Arquivo

Ler e escrever arquivos usando vários métodos.

```go
import (
    "io/ioutil"
    "os"
)
// Ler arquivo inteiro
data, err := ioutil.ReadFile("file.txt")
if err != nil {
    log.Fatal(err)
}
content := string(data)
// Escrever em arquivo
text := "Hello, World!"
err = ioutil.WriteFile("output.txt", []byte(text), 0644)
// Abrir arquivo com mais controle
file, err := os.Open("data.txt")
if err != nil {
    log.Fatal(err)
}
defer file.Close()
```

### Manipulação de CSV

Ler e escrever arquivos CSV.

```go
import (
    "encoding/csv"
    "os"
)
// Ler CSV
file, _ := os.Open("data.csv")
defer file.Close()
reader := csv.NewReader(file)
records, _ := reader.ReadAll()
// Escrever CSV
file, _ = os.Create("output.csv")
defer file.Close()
writer := csv.NewWriter(file)
defer writer.Flush()
writer.Write([]string{"Nome", "Idade", "Cidade"})
writer.Write([]string{"Alice", "30", "NYC"})
```

### Processamento JSON

Codificar e decodificar dados JSON.

```go
import "encoding/json"
// Struct para mapeamento JSON
type Person struct {
    Name  string `json:"name"`
    Age   int    `json:"age"`
    Email string `json:"email,omitempty"`
}
// Marshal (Go para JSON)
person := Person{Name: "Alice", Age: 30}
jsonData, err := json.Marshal(person)
if err != nil {
    log.Fatal(err)
}
// Unmarshal (JSON para Go)
var p Person
err = json.Unmarshal(jsonData, &p)
```

### Requisições HTTP

Fazer requisições HTTP e lidar com respostas.

```go
import "net/http"
// Requisição GET
resp, err := http.Get("https://api.github.com/users/octocat")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
body, _ := ioutil.ReadAll(resp.Body)
// Requisição POST com JSON
jsonData := []byte(`{"name":"Alice","age":30}`)
resp, err = http.Post("https://api.example.com/users",
                      "application/json",
                      bytes.NewBuffer(jsonData))
```

## Testes

### Teste Unitário: `go test`

Escrever e executar testes usando o framework de testes do Go.

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
        t.Errorf("Add(2, 3) = %d; esperado %d", result, expected)
    }
}
// Executar testes
// go test
// go test -v (verbose)
```

### Testes Orientados a Tabela

Testar múltiplos casos de forma eficiente.

```go
func TestAddMultiple(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {"números positivos", 2, 3, 5},
        {"com zero", 0, 5, 5},
        {"números negativos", -1, -2, -3},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Add(tt.a, tt.b)
            if result != tt.expected {
                t.Errorf("obtido %d, esperado %d", result, tt.expected)
            }
        })
    }
}
```

### Benchmarking

Medir o desempenho de funções.

```go
func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(2, 3)
    }
}
// Executar benchmarks
// go test -bench=.
// go test -bench=BenchmarkAdd -benchmem
```

### Testes de Exemplo

Criar exemplos executáveis que servem como documentação.

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
// Executar exemplos
// go test -run Example
```

## Módulos e Pacotes Go

### Gerenciamento de Módulos

Inicializar e gerenciar módulos Go para gerenciamento de dependências.

```bash
# Inicializar novo módulo
go mod init github.com/username/project
# Adicionar dependências
go get github.com/gorilla/mux
go get -u github.com/gin-gonic/gin  # Atualizar para o mais recente
# Remover dependências não utilizadas
go mod tidy
# Baixar dependências
go mod download
# Fornecer dependências localmente
go mod vendor
```

### Arquivo go.mod

Compreendendo o arquivo de definição de módulo.

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

### Criação de Pacotes

Estruturar código em pacotes reutilizáveis.

```go
// Estrutura do Pacote
// myproject/
//   ├── go.mod
//   ├── main.go
//   └── utils/
//       ├── math.go
//       └── string.go
// utils/math.go
package utils
// Função Exportada (começa com letra maiúscula)
func Add(a, b int) int {
    return a + b
}
// Função Privada (começa com letra minúscula)
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

### Comandos Go Comuns

Comandos essenciais para o desenvolvimento Go.

```bash
# Executar programa Go
go run main.go
# Construir executável
go build
go build -o myapp  # Nome personalizado
# Instalar binário em GOPATH/bin
go install
# Formatar código
go fmt ./...
# Verificar código em busca de problemas
go vet ./...
# Limpar cache de compilação
go clean -cache
```

## Links Relevantes

- <router-link to="/linux">Folha de Dicas Linux</router-link>
- <router-link to="/shell">Folha de Dicas Shell</router-link>
- <router-link to="/devops">Folha de Dicas DevOps</router-link>
- <router-link to="/docker">Folha de Dicas Docker</router-link>
- <router-link to="/kubernetes">Folha de Dicas Kubernetes</router-link>
- <router-link to="/python">Folha de Dicas Python</router-link>
- <router-link to="/javascript">Folha de Dicas JavaScript</router-link>
- <router-link to="/java">Folha de Dicas Java</router-link>

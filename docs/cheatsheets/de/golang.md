---
title: 'Golang Spickzettel | LabEx'
description: 'Lernen Sie Go-Programmierung mit diesem umfassenden Spickzettel. Schnelle Referenz für Go-Syntax, Goroutinen, Channels, Interfaces, Fehlerbehandlung und nebenläufige Programmierung für Backend-Entwickler.'
pdfUrl: '/cheatsheets/pdf/golang-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Golang Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/golang">Lernen Sie Golang mit Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Go-Programmierung durch praktische Labs und reale Szenarien. LabEx bietet umfassende Go-Kurse, die wesentliche Syntax, Nebenläufigkeitsmuster, Fehlerbehandlung und fortgeschrittene Techniken abdecken. Meistern Sie Go's einzigartige Funktionen wie Goroutinen, Channels und Interfaces, um effiziente, nebenläufige Anwendungen zu erstellen.
</base-disclaimer-content>
</base-disclaimer>

## Installation & Einrichtung

### Go installieren: Herunterladen & Entpacken

Laden Sie Go von der offiziellen Website herunter und installieren Sie es.

```bash
# Download von https://golang.org/dl/
# Linux/macOS - nach /usr/local entpacken
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
# Zu PATH in ~/.bashrc oder ~/.zshrc hinzufügen
export PATH=$PATH:/usr/local/go/bin
# Installation überprüfen
go version
```

### Paketmanager: Homebrew verwenden (macOS)

Installieren Sie Go mit Homebrew unter macOS.

```bash
# Go mit Homebrew installieren
brew install go
# Installation überprüfen
go version
go env GOPATH
```

### Windows-Installation

Installieren Sie Go auf Windows-Systemen.

```bash
# .msi-Installer von https://golang.org/dl/ herunterladen
# Installer ausführen und Anweisungen folgen
# In der Eingabeaufforderung überprüfen
go version
echo %GOPATH%
```

### Workspace-Einrichtung: `go mod init`

Initialisieren Sie ein neues Go-Modul und einen Workspace.

```bash
# Neuen Ordner erstellen und Modul initialisieren
mkdir my-go-project
cd my-go-project
go mod init my-go-project
# main.go erstellen
echo 'package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}' > main.go
# Programm ausführen
go run main.go
```

### Umgebungsvariablen

Wichtige Go-Umgebungsvariablen.

```bash
# Alle Go-Umgebungsvariablen anzeigen
go env
# Schlüsselvariablen
go env GOROOT    # Go Installationsverzeichnis
go env GOPATH    # Workspace-Verzeichnis
go env GOOS      # Betriebssystem
go env GOARCH    # Architektur
```

### IDE-Einrichtung: VS Code

Konfigurieren Sie VS Code für die Go-Entwicklung.

```bash
# Go-Erweiterung in VS Code installieren
# Strg+Umschalt+P -> Go: Install/Update Tools
# Hauptfunktionen aktiviert:
# - Syntaxhervorhebung
# - IntelliSense
# - Debugging
# - Testintegration
```

## Grundlegende Syntax & Typen

### Paket & Imports

Jede Go-Datei beginnt mit einer Paketdeklaration und Imports.

```go
package main
import (
    "fmt"
    "strings"
    "time"
)
// Einzelner Import
import "os"
```

### Variablen & Konstanten

Variablen und Konstanten deklarieren und initialisieren.

```go
// Variablendeklarationen
var name string = "Go"
var age int = 15
var isOpen bool
// Kurze Deklaration
name := "Golang"
count := 42
// Konstanten
const Pi = 3.14159
const Message = "Hello, Go!"
```

<BaseQuiz id="golang-variables-1" correct="B">
  <template #question>
    Was ist der Unterschied zwischen <code>var name string = "Go"</code> und <code>name := "Go"</code>?
  </template>
  
  <BaseQuizOption value="A">Es gibt keinen Unterschied</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>:=</code> ist eine kurze Deklaration, die den Typ ableitet, <code>var</code> deklariert den Typ explizit</BaseQuizOption>
  <BaseQuizOption value="C"><code>:=</code> kann nur für Konstanten verwendet werden</BaseQuizOption>
  <BaseQuizOption value="D"><code>var</code> kann nur innerhalb von Funktionen verwendet werden</BaseQuizOption>
  
  <BaseQuizAnswer>
    Der <code>:=</code>-Operator ist eine Kurzform für Variablendeklaration und -initialisierung, wobei Go den Typ automatisch ableitet. <code>var</code> deklariert den Variablentyp explizit und kann auf Paket- oder Funktionsebene verwendet werden.
  </BaseQuizAnswer>
</BaseQuiz>

### Grundlegende Datentypen

Grundlegende Typen, die in Go verfügbar sind.

```go
// Numerische Typen
var i int = 42
var f float64 = 3.14
var c complex64 = 1 + 2i
// Texttypen
var s string = "Hello"
var r rune = 'A'
// Boolescher Wert
var b bool = true
```

## Kontrollfluss

### Bedingte Anweisungen: `if` / `else` / `switch`

Steuern Sie den Programmfluss mit bedingten Anweisungen.

```go
// If-Anweisungen
if age >= 18 {
    fmt.Println("Erwachsen")
} else if age >= 13 {
    fmt.Println("Teenager")
} else {
    fmt.Println("Kind")
}
// Switch-Anweisungen
switch day {
case "Montag":
    fmt.Println("Wochenanfang")
case "Freitag":
    fmt.Println("TGIF")
default:
    fmt.Println("Regulärer Tag")
}
```

### Schleifen: `for` / `range`

Iterieren Sie mit verschiedenen Schleifenkonstrukten.

```go
// Traditionelle for-Schleife
for i := 0; i < 10; i++ {
    fmt.Println(i)
}
// While-ähnliche Schleife
for condition {
    // Schleifenkörper
}
// Endlosschleife
for {
    // Abbruch bei Bedarf
}
```

### Range-Iteration

Iterieren Sie über Slices, Arrays, Maps und Strings.

```go
// Über Slice iterieren
numbers := []int{1, 2, 3, 4, 5}
for index, value := range numbers {
    fmt.Printf("Index: %d, Wert: %d\n", index, value)
}
// Über Map iterieren
colors := map[string]string{"red": "#FF0000", "green": "#00FF00"}
for key, value := range colors {
    fmt.Printf("%s: %s\n", key, value)
}
// Über String iterieren
for i, char := range "Hello" {
    fmt.Printf("%d: %c\n", i, char)
}
```

<BaseQuiz id="golang-range-1" correct="B">
  <template #question>
    Was gibt <code>range</code> zurück, wenn über ein Slice in Go iteriert wird?
  </template>
  
  <BaseQuizOption value="A">Nur den Wert</BaseQuizOption>
  <BaseQuizOption value="B" correct>Sowohl den Index als auch den Wert</BaseQuizOption>
  <BaseQuizOption value="C">Nur den Index</BaseQuizOption>
  <BaseQuizOption value="D">Die Länge des Slices</BaseQuizOption>
  
  <BaseQuizAnswer>
    Bei der Verwendung von <code>range</code> mit einem Slice gibt es zwei Werte zurück: den Index (Position) und den Wert an diesem Index. Sie können <code>_</code> verwenden, um einen der Werte zu ignorieren, falls Sie ihn nicht benötigen.
  </BaseQuizAnswer>
</BaseQuiz>

### Kontrollanweisungen: `break` / `continue`

Steuern Sie den Schleifenausführungsfluss.

```go
// Aus der Schleife ausbrechen
for i := 0; i < 10; i++ {
    if i == 5 {
        break
    }
    fmt.Println(i)
}
// Aktuelle Iteration überspringen
for i := 0; i < 5; i++ {
    if i == 2 {
        continue
    }
    fmt.Println(i)
}
```

<BaseQuiz id="golang-control-1" correct="C">
  <template #question>
    Was ist der Unterschied zwischen <code>break</code> und <code>continue</code> in Go-Schleifen?
  </template>
  
  <BaseQuizOption value="A">Es gibt keinen Unterschied</BaseQuizOption>
  <BaseQuizOption value="B">break überspringt die aktuelle Iteration, continue beendet die Schleife</BaseQuizOption>
  <BaseQuizOption value="C" correct>break beendet die Schleife vollständig, continue springt zur nächsten Iteration</BaseQuizOption>
  <BaseQuizOption value="D">Beide beenden die Schleife</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>break</code> beendet die Schleife sofort und fährt mit der Ausführung nach der Schleife fort. <code>continue</code> überspringt den Rest der aktuellen Iteration und fährt mit der nächsten Iteration der Schleife fort.
  </BaseQuizAnswer>
</BaseQuiz>

## Funktionen

### Funktionsdeklaration: `func`

Funktionen mit Parametern und Rückgabewerten definieren.

```go
// Einfache Funktion
func greet(name string) {
    fmt.Printf("Hallo, %s!\n", name)
}
// Funktion mit Rückgabewert
func add(a, b int) int {
    return a + b
}
// Mehrere Rückgabewerte
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("Division durch Null")
    }
    return a / b, nil
}
```

### Benannte Rückgaben & Variadische Funktionen

Fortgeschrittene Funktionenmerkmale und Muster.

```go
// Benannte Rückgabewerte
func split(sum int) (x, y int) {
    x = sum * 4 / 9
    y = sum - x
    return // nackte Rückgabe
}
// Variadische Funktion
func sum(nums ...int) int {
    total := 0
    for _, num := range nums {
        total += num
    }
    return total
}
// Verwendung
result := sum(1, 2, 3, 4, 5)
```

### Funktionstypen & Closures

Funktionen als Bürger erster Klasse in Go.

```go
// Funktion als Variable
var multiply func(int, int) int
multiply = func(a, b int) int {
    return a * b
}
// Anonyme Funktion
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
// Verwendung
c := counter()
fmt.Println(c()) // 1
fmt.Println(c()) // 2
```

### Defer-Anweisung

Verzögert die Ausführung von Funktionen, bis die umgebende Funktion zurückkehrt.

```go
func processFile(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close() // Wird ausgeführt, wenn die Funktion zurückkehrt

    // Dateiinhalt verarbeiten
    // file.Close() wird automatisch aufgerufen
}
```

## Datenstrukturen

### Arrays & Slices

Feste und dynamische Sequenzen von Elementen.

```go
// Arrays (feste Größe)
var arr [5]int = [5]int{1, 2, 3, 4, 5}
shortArr := [3]string{"a", "b", "c"}
// Slices (dynamisch)
var slice []int
slice = append(slice, 1, 2, 3)
// Slice mit Kapazität erstellen
numbers := make([]int, 5, 10) // Länge 5, Kapazität 10
// Slice-Operationen
slice2 := slice[1:3]  // [2, 3]
copy(slice2, slice)   // Elemente kopieren
```

### Maps

Schlüssel-Wert-Paare für effiziente Nachschlagevorgänge.

```go
// Map-Deklaration und Initialisierung
var m map[string]int
m = make(map[string]int)
// Kurze Deklaration
ages := map[string]int{
    "Alice": 30,
    "Bob":   25,
    "Carol": 35,
}
// Map-Operationen
ages["David"] = 40        // Hinzufügen/Aktualisieren
delete(ages, "Bob")       // Löschen
age, exists := ages["Alice"] // Existenz prüfen
```

### Structs

Gruppieren Sie zusammengehörige Daten mit benutzerdefinierten Typen.

```go
// Struct-Definition
type Person struct {
    Name    string
    Age     int
    Email   string
}
// Struct-Instanzen erstellen
p1 := Person{
    Name:  "Alice",
    Age:   30,
    Email: "alice@example.com",
}
p2 := Person{"Bob", 25, "bob@example.com"}
// Felder zugreifen
fmt.Println(p1.Name)
p1.Age = 31
```

### Pointer

Referenzieren Sie Speicheradressen von Variablen.

```go
// Pointer-Deklaration
var p *int
num := 42
p = &num  // Adresse von num
// Dereferenzierung
fmt.Println(*p) // Wert an der Adresse (42)
*p = 100        // Wert über Pointer ändern
// Pointer mit Structs
person := &Person{Name: "Alice", Age: 30}
person.Age = 31  // Automatische Dereferenzierung
```

## Methoden & Interfaces

### Methoden

Funktionalität an benutzerdefinierte Typen binden.

```go
type Rectangle struct {
    Width, Height float64
}
// Methode mit Empfänger
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}
// Pointer-Empfänger (kann modifizieren)
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor
    r.Height *= factor
}
// Verwendung
rect := Rectangle{Width: 10, Height: 5}
fmt.Println(rect.Area()) // 50
rect.Scale(2)            // Modifiziert rect
```

### Interfaces

Definieren Sie Verträge, die Typen erfüllen müssen.

```go
// Interface-Definition
type Shape interface {
    Area() float64
    Perimeter() float64
}
// Implementierung des Interfaces für Rectangle
func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}
// Rectangle implementiert nun das Shape-Interface
func printShapeInfo(s Shape) {
    fmt.Printf("Fläche: %.2f, Umfang: %.2f\n",
               s.Area(), s.Perimeter())
}
```

### Leeres Interface & Typ-Assertionen

Arbeiten mit Werten unbekannter Typen.

```go
// Leeres Interface kann jeden Wert aufnehmen
var i interface{}
i = 42
i = "hallo"
i = []int{1, 2, 3}
// Typ-Assertion
str, ok := i.(string)
if ok {
    fmt.Printf("String-Wert: %s\n", str)
}
// Typ-Switch
switch v := i.(type) {
case int:
    fmt.Printf("Integer: %d\n", v)
case string:
    fmt.Printf("String: %s\n", v)
default:
    fmt.Printf("Unbekannter Typ: %T\n", v)
}
```

### Einbettung (Embedding)

Typen durch Einbetten anderer Typen zusammensetzen.

```go
type Person struct {
    Name string
    Age  int
}
type Employee struct {
    Person    // Eingebetteter Struct
    Company   string
    Salary    float64
}
// Verwendung
emp := Employee{
    Person:  Person{Name: "Alice", Age: 30},
    Company: "TechCorp",
    Salary:  75000,
}
// Direkter Zugriff auf eingebettete Felder
fmt.Println(emp.Name) // "Alice"
```

## Fehlerbehandlung

### Grundlegende Fehlerbehandlung

Verwenden Sie die eingebaute Fehler-Schnittstelle zur Fehlerbehandlung.

```go
import "errors"
// Funktion, die einen Fehler zurückgibt
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("Division durch Null")
    }
    return a / b, nil
}
// Fehlerprüfung
result, err := divide(10, 2)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Ergebnis: %.2f\n", result)
```

### Benutzerdefinierte Fehler

Erstellen Sie benutzerdefinierte Fehlertypen für spezifische Fehlerbedingungen.

```go
// Benutzerdefinierter Fehlertyp
type ValidationError struct {
    Field   string
    Message string
}
func (e ValidationError) Error() string {
    return fmt.Sprintf("Validierungsfehler in %s: %s",
                       e.Field, e.Message)
}
// Funktion, die benutzerdefinierten Fehler verwendet
func validateAge(age int) error {
    if age < 0 {
        return ValidationError{
            Field:   "age",
            Message: "muss nicht-negativ sein",
        }
    }
    return nil
}
```

### Fehler-Wrapping

Fügen Sie Kontext zu Fehlern hinzu, während der ursprüngliche Fehler erhalten bleibt.

```go
import "fmt"
// Einen Fehler mit zusätzlichem Kontext umhüllen
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("Fehler beim Öffnen der Datei %s: %w",
                          filename, err)
    }
    defer file.Close()

    // Datei verarbeiten...
    return nil
}
// Fehler entpacken
err := processFile("missing.txt")
if err != nil {
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        fmt.Println("Pfadfehler:", pathErr)
    }
}
```

### Panic & Recovery

Behandeln Sie außergewöhnliche Situationen mit `panic` und `recover`.

```go
// Funktion, die möglicherweise einen Panic auslöst
func riskyOperation() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Von Panic wiederhergestellt:", r)
        }
    }()

    // Dies löst einen Panic aus
    panic("etwas ist schiefgelaufen!")
}
// Verwendung
riskyOperation() // Programm läuft nach Panic weiter
```

## Nebenläufigkeit (Concurrency)

### Goroutinen

Leichtgewichtige Threads, die vom Go-Laufzeitsystem verwaltet werden.

```go
import "time"
// Einfache Goroutine
func sayHello() {
    fmt.Println("Hallo von Goroutine!")
}
func main() {
    // Goroutine starten
    go sayHello()

    // Anonyme Goroutine
    go func() {
        fmt.Println("Anonyme Goroutine")
    }()

    // Warten, bis Goroutinen fertig sind
    time.Sleep(time.Second)
}
```

### Channels

Kommunikation zwischen Goroutinen mithilfe von Channels.

```go
// Channel erstellen
ch := make(chan int)
// Gebufferter Channel
buffered := make(chan string, 3)
// Senden und Empfangen
go func() {
    ch <- 42  // Wert senden
}()
value := <-ch  // Wert empfangen
// Channel schließen
close(ch)
```

### Channel-Muster

Gängige Muster für die Channel-Kommunikation.

```go
// Worker-Muster
func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Worker %d verarbeitet Job %d\n", id, job)
        results <- job * 2
    }
}
// Fan-out-Muster
jobs := make(chan int, 100)
results := make(chan int, 100)
// Worker starten
for w := 1; w <= 3; w++ {
    go worker(w, jobs, results)
}
// Jobs senden
for j := 1; j <= 5; j++ {
    jobs <- j
}
close(jobs)
```

### Select-Anweisung

Behandeln Sie mehrere Channel-Operationen gleichzeitig.

```go
func main() {
    ch1 := make(chan string)
    ch2 := make(chan string)

    go func() {
        time.Sleep(time.Second)
        ch1 <- "von ch1"
    }()

    go func() {
        time.Sleep(2 * time.Second)
        ch2 <- "von ch2"
    }()

    // Wählt den zuerst verfügbaren Channel
    select {
    case msg1 := <-ch1:
        fmt.Println(msg1)
    case msg2 := <-ch2:
        fmt.Println(msg2)
    case <-time.After(3 * time.Second):
        fmt.Println("Timeout")
    }
}
```

## Datei-I/O & JSON

### Dateioperationen

Dateien mit verschiedenen Methoden lesen und schreiben.

```go
import (
    "io/ioutil"
    "os"
)
// Gesamte Datei lesen
data, err := ioutil.ReadFile("file.txt")
if err != nil {
    log.Fatal(err)
}
content := string(data)
// In Datei schreiben
text := "Hello, World!"
err = ioutil.WriteFile("output.txt", []byte(text), 0644)
// Datei mit mehr Kontrolle öffnen
file, err := os.Open("data.txt")
if err != nil {
    log.Fatal(err)
}
defer file.Close()
```

### CSV-Verarbeitung

CSV-Dateien lesen und schreiben.

```go
import (
    "encoding/csv"
    "os"
)
// CSV lesen
file, _ := os.Open("data.csv")
defer file.Close()
reader := csv.NewReader(file)
records, _ := reader.ReadAll()
// CSV schreiben
file, _ = os.Create("output.csv")
defer file.Close()
writer := csv.NewWriter(file)
defer writer.Flush()
writer.Write([]string{"Name", "Alter", "Stadt"})
writer.Write([]string{"Alice", "30", "NYC"})
```

### JSON-Verarbeitung

JSON-Daten kodieren und dekodieren.

```go
import "encoding/json"
// Struct für JSON-Mapping
type Person struct {
    Name  string `json:"name"`
    Age   int    `json:"age"`
    Email string `json:"email,omitempty"`
}
// Marshal (Go zu JSON)
person := Person{Name: "Alice", Age: 30}
jsonData, err := json.Marshal(person)
if err != nil {
    log.Fatal(err)
}
// Unmarshal (JSON zu Go)
var p Person
err = json.Unmarshal(jsonData, &p)
```

### HTTP-Anfragen

HTTP-Anfragen stellen und Antworten verarbeiten.

```go
import "net/http"
// GET-Anfrage
resp, err := http.Get("https://api.github.com/users/octocat")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
body, _ := ioutil.ReadAll(resp.Body)
// POST-Anfrage mit JSON
jsonData := []byte(`{"name":"Alice","age":30}`)
resp, err = http.Post("https://api.example.com/users",
                      "application/json",
                      bytes.NewBuffer(jsonData))
```

## Testen

### Unit-Tests: `go test`

Tests mit Go's Test-Framework schreiben und ausführen.

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
        t.Errorf("Add(2, 3) = %d; erwartet %d", result, expected)
    }
}
// Tests ausführen
// go test
// go test -v (ausführlich)
```

### Tabellengetriebene Tests

Mehrere Fälle effizient testen.

```go
func TestAddMultiple(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {"positive Zahlen", 2, 3, 5},
        {"mit Null", 0, 5, 5},
        {"negative Zahlen", -1, -2, -3},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Add(tt.a, tt.b)
            if result != tt.expected {
                t.Errorf("erhielt %d, erwartet %d", result, tt.expected)
            }
        })
    }
}
```

### Benchmarking

Leistungsmessung von Funktionen.

```go
func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(2, 3)
    }
}
// Benchmarks ausführen
// go test -bench=.
// go test -bench=BenchmarkAdd -benchmem
```

### Beispieltests

Erstellen Sie ausführbare Beispiele, die als Dokumentation dienen.

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
// Beispiele ausführen
// go test -run Example
```

## Go Modules & Pakete

### Modulverwaltung

Go-Module initialisieren und die Abhängigkeitsverwaltung verwalten.

```bash
# Neues Modul initialisieren
go mod init github.com/username/project
# Abhängigkeiten hinzufügen
go get github.com/gorilla/mux
go get -u github.com/gin-gonic/gin  # Auf neueste aktualisieren
# Unbenutzte Abhängigkeiten entfernen
go mod tidy
# Abhängigkeiten herunterladen
go mod download
# Abhängigkeiten lokal "vendorn"
go mod vendor
```

### go.mod Datei

Verständnis der Moduldefinitionsdatei.

```go
module github.com/username/myproject
go 1.21
require (
    github.com/gorilla/mux v1.8.0
    github.com/stretchr/testify v1.8.4
)
require (
    github.com/davecgh/go-spew v1.1.1 // indirekt
    github.com/pmezard/go-difflib v1.0.0 // indirekt
)
```

### Pakete erstellen

Code in wiederverwendbare Pakete strukturieren.

```go
// Paketstruktur
// myproject/
//   ├── go.mod
//   ├── main.go
//   └── utils/
//       ├── math.go
//       └── string.go
// utils/math.go
package utils
// Exportierte Funktion (beginnt mit Großbuchstaben)
func Add(a, b int) int {
    return a + b
}
// Private Funktion (beginnt mit Kleinbuchstaben)
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

### Häufige Go-Befehle

Wesentliche Befehle für die Go-Entwicklung.

```bash
# Go-Programm ausführen
go run main.go
# Ausführbare Datei erstellen
go build
go build -o myapp  # Benutzerdefinierter Name
# Binärdatei in GOPATH/bin installieren
go install
# Code formatieren
go fmt ./...
# Code auf Probleme überprüfen
go vet ./...
# Build-Cache bereinigen
go clean -cache
```

## Relevante Links

- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/java">Java Spickzettel</router-link>

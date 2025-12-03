---
title: 'Fiche de Référence Golang | LabEx'
description: 'Apprenez la programmation Go avec cette fiche de référence complète. Référence rapide pour la syntaxe Go, les goroutines, les canaux, les interfaces, la gestion des erreurs et la programmation concurrente pour les développeurs backend.'
pdfUrl: '/cheatsheets/pdf/golang-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Golang
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/golang">Apprenez Golang avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la programmation Go grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours Go complets couvrant la syntaxe essentielle, les modèles de concurrence, la gestion des erreurs et les techniques avancées. Maîtrisez les fonctionnalités uniques de Go telles que les goroutines, les canaux et les interfaces pour créer des applications concurrentes et efficaces.
</base-disclaimer-content>
</base-disclaimer>

## Installation et Configuration

### Installer Go : Télécharger et Extraire

Téléchargez et installez Go depuis le site officiel.

```bash
# Télécharger depuis https://golang.org/dl/
# Linux/macOS - extraire dans /usr/local
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
# Ajouter à PATH dans ~/.bashrc ou ~/.zshrc
export PATH=$PATH:/usr/local/go/bin
# Vérifier l'installation
go version
```

### Gestionnaire de Paquets : Utilisation de Homebrew (macOS)

Installer Go en utilisant Homebrew sur macOS.

```bash
# Installer Go avec Homebrew
brew install go
# Vérifier l'installation
go version
go env GOPATH
```

### Installation sous Windows

Installer Go sur les systèmes Windows.

```bash
# Télécharger le programme d'installation .msi depuis https://golang.org/dl/
# Exécuter l'installateur et suivre les instructions
# Vérifier dans l'Invite de commandes
go version
echo %GOPATH%
```

### Configuration de l'Espace de Travail : `go mod init`

Initialiser un nouveau module et un espace de travail Go.

```bash
# Créer un nouveau répertoire et initialiser le module
mkdir my-go-project
cd my-go-project
go mod init my-go-project
# Créer main.go
echo 'package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}' > main.go
# Exécuter le programme
go run main.go
```

### Variables d'Environnement

Variables d'environnement Go importantes.

```bash
# Afficher toutes les variables d'environnement Go
go env
# Variables clés
go env GOROOT    # Répertoire d'installation de Go
go env GOPATH    # Répertoire de l'espace de travail
go env GOOS      # Système d'exploitation
go env GOARCH    # Architecture
```

### Configuration de l'IDE : VS Code

Configurer VS Code pour le développement Go.

```bash
# Installer l'extension Go dans VS Code
# Ctrl+Shift+P -> Go: Install/Update Tools
# Fonctionnalités clés activées :
# - Coloration syntaxique
# - IntelliSense
# - Débogage
# - Intégration des tests
```

## Syntaxe et Types de Base

### Package et Imports

Chaque fichier Go commence par une déclaration de package et des imports.

```go
package main
import (
    "fmt"
    "strings"
    "time"
)
// Import unique
import "os"
```

### Variables et Constantes

Déclarer et initialiser des variables et des constantes.

```go
// Déclarations de variables
var name string = "Go"
var age int = 15
var isOpen bool
// Déclaration courte
name := "Golang"
count := 42
// Constantes
const Pi = 3.14159
const Message = "Hello, Go!"
```

<BaseQuiz id="golang-variables-1" correct="B">
  <template #question>
    Quelle est la différence entre `var name string = "Go"` et `name := "Go"` ?
  </template>
  
  <BaseQuizOption value="A">Il n'y a aucune différence</BaseQuizOption>
  <BaseQuizOption value="B" correct> `:=` est une déclaration courte qui infère le type, `var` déclare explicitement le type</BaseQuizOption>
  <BaseQuizOption value="C">`:=` ne peut être utilisé que pour les constantes</BaseQuizOption>
  <BaseQuizOption value="D">`var` ne peut être utilisé qu'à l'intérieur des fonctions</BaseQuizOption>
  
  <BaseQuizAnswer>
    L'opérateur `:=` est un raccourci pour la déclaration et l'initialisation de variables, et Go en déduit automatiquement le type. `var` déclare explicitement le type de la variable et peut être utilisé au niveau du package ou de la fonction.
  </BaseQuizAnswer>
</BaseQuiz>

### Types de Données de Base

Types fondamentaux disponibles en Go.

```go
// Types numériques
var i int = 42
var f float64 = 3.14
var c complex64 = 1 + 2i
// Types texte
var s string = "Hello"
var r rune = 'A'
// Booléen
var b bool = true
```

## Flux de Contrôle

### Conditionnelles : `if` / `else` / `switch`

Contrôler le flux d'exécution du programme avec des instructions conditionnelles.

```go
// Instructions If
if age >= 18 {
    fmt.Println("Adulte")
} else if age >= 13 {
    fmt.Println("Adolescent")
} else {
    fmt.Println("Enfant")
}
// Instructions Switch
switch day {
case "Lundi":
    fmt.Println("Début de la semaine de travail")
case "Vendredi":
    fmt.Println("TGIF")
default:
    fmt.Println("Journée normale")
}
```

### Boucles : `for` / `range`

Itérer en utilisant diverses constructions de boucles.

```go
// Boucle for traditionnelle
for i := 0; i < 10; i++ {
    fmt.Println(i)
}
// Boucle de style While
for condition {
    // corps de la boucle
}
// Boucle infinie
for {
    // break quand nécessaire
}
```

### Itération avec Range

Itérer sur des slices, des tableaux, des maps et des chaînes de caractères.

```go
// Itérer sur un slice
numbers := []int{1, 2, 3, 4, 5}
for index, value := range numbers {
    fmt.Printf("Index: %d, Valeur: %d\n", index, value)
}
// Itérer sur une map
colors := map[string]string{"red": "#FF0000", "green": "#00FF00"}
for key, value := range colors {
    fmt.Printf("%s: %s\n", key, value)
}
// Itérer sur une chaîne
for i, char := range "Hello" {
    fmt.Printf("%d: %c\n", i, char)
}
```

<BaseQuiz id="golang-range-1" correct="B">
  <template #question>
    Que retourne `range` lors de l'itération sur un slice en Go ?
  </template>
  
  <BaseQuizOption value="A">Seulement la valeur</BaseQuizOption>
  <BaseQuizOption value="B" correct>L'index et la valeur</BaseQuizOption>
  <BaseQuizOption value="C">Seulement l'index</BaseQuizOption>
  <BaseQuizOption value="D">La longueur du slice</BaseQuizOption>
  
  <BaseQuizAnswer>
    Lors de l'utilisation de `range` avec un slice, il retourne deux valeurs : l'index (position) et la valeur à cet index. Vous pouvez utiliser `_` pour ignorer l'une ou l'autre valeur si vous n'en avez pas besoin.
  </BaseQuizAnswer>
</BaseQuiz>

### Instructions de Contrôle : `break` / `continue`

Contrôler le flux d'exécution de la boucle.

```go
// Sortir de la boucle
for i := 0; i < 10; i++ {
    if i == 5 {
        break
    }
    fmt.Println(i)
}
// Sauter l'itération courante
for i := 0; i < 5; i++ {
    if i == 2 {
        continue
    }
    fmt.Println(i)
}
```

<BaseQuiz id="golang-control-1" correct="C">
  <template #question>
    Quelle est la différence entre `break` et `continue` dans les boucles Go ?
  </template>
  
  <BaseQuizOption value="A">Il n'y a aucune différence</BaseQuizOption>
  <BaseQuizOption value="B">break saute l'itération courante, continue quitte la boucle</BaseQuizOption>
  <BaseQuizOption value="C" correct>break quitte complètement la boucle, continue passe à l'itération suivante</BaseQuizOption>
  <BaseQuizOption value="D">Les deux quittent la boucle</BaseQuizOption>
  
  <BaseQuizAnswer>
    `break` sort immédiatement de la boucle et continue l'exécution après la boucle. `continue` saute le reste de l'itération courante et passe à l'itération suivante de la boucle.
  </BaseQuizAnswer>
</BaseQuiz>

## Fonctions

### Déclaration de Fonction : `func`

Définir des fonctions avec des paramètres et des valeurs de retour.

```go
// Fonction de base
func greet(name string) {
    fmt.Printf("Hello, %s!\n", name)
}
// Fonction avec valeur de retour
func add(a, b int) int {
    return a + b
}
// Valeurs de retour multiples
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division par zéro")
    }
    return a / b, nil
}
```

### Retours Nommés et Fonctions Variadiques

Fonctionnalités avancées des fonctions et modèles.

```go
// Valeurs de retour nommées
func split(sum int) (x, y int) {
    x = sum * 4 / 9
    y = sum - x
    return // retour nu
}
// Fonction variadique
func sum(nums ...int) int {
    total := 0
    for _, num := range nums {
        total += num
    }
    return total
}
// Utilisation
result := sum(1, 2, 3, 4, 5)
```

### Types de Fonctions et Fermetures (Closures)

Les fonctions comme citoyens de première classe en Go.

```go
// Fonction comme variable
var multiply func(int, int) int
multiply = func(a, b int) int {
    return a * b
}
// Fonction anonyme
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
// Utilisation
c := counter()
fmt.Println(c()) // 1
fmt.Println(c()) // 2
```

### Instruction Defer

Différer l'exécution des fonctions jusqu'à ce que la fonction environnante retourne.

```go
func processFile(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close() // Exécuté lorsque la fonction retourne

    // Traiter le contenu du fichier
    // file.Close() sera appelé automatiquement
}
```

## Structures de Données

### Tableaux et Slices

Séquences d'éléments fixes et dynamiques.

```go
// Tableaux (taille fixe)
var arr [5]int = [5]int{1, 2, 3, 4, 5}
shortArr := [3]string{"a", "b", "c"}
// Slices (dynamiques)
var slice []int
slice = append(slice, 1, 2, 3)
// Créer un slice avec capacité
numbers := make([]int, 5, 10) // longueur 5, capacité 10
// Opérations sur les slices
slice2 := slice[1:3]  // [2, 3]
copy(slice2, slice)   // Copier les éléments
```

### Maps

Paires clé-valeur pour des recherches efficaces.

```go
// Déclaration et initialisation de map
var m map[string]int
m = make(map[string]int)
// Déclaration courte
ages := map[string]int{
    "Alice": 30,
    "Bob":   25,
    "Carol": 35,
}
// Opérations sur les maps
ages["David"] = 40        // Ajouter/mettre à jour
delete(ages, "Bob")       // Supprimer
age, exists := ages["Alice"] // Vérifier l'existence
```

### Structs

Regrouper des données connexes avec des types personnalisés.

```go
// Définition de struct
type Person struct {
    Name    string
    Age     int
    Email   string
}
// Créer des instances de struct
p1 := Person{
    Name:  "Alice",
    Age:   30,
    Email: "alice@example.com",
}
p2 := Person{"Bob", 25, "bob@example.com"}
// Accéder aux champs
fmt.Println(p1.Name)
p1.Age = 31
```

### Pointeur

Référence les adresses mémoire des variables.

```go
// Déclaration de pointeur
var p *int
num := 42
p = &num  // Adresse de num
// Déréférencement
fmt.Println(*p) // Valeur à l'adresse (42)
*p = 100        // Changer la valeur via le pointeur
// Pointeur avec structs
person := &Person{Name: "Alice", Age: 30}
person.Age = 31  // Déréférencement automatique
```

## Méthodes et Interfaces

### Méthodes

Attacher des fonctionnalités à des types personnalisés.

```go
type Rectangle struct {
    Width, Height float64
}
// Méthode avec récepteur
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}
// Récepteur pointeur (peut modifier)
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor
    r.Height *= factor
}
// Utilisation
rect := Rectangle{Width: 10, Height: 5}
fmt.Println(rect.Area()) // 50
rect.Scale(2)            // Modifie rect
```

### Interfaces

Définir des contrats que les types doivent satisfaire.

```go
// Définition d'interface
type Shape interface {
    Area() float64
    Perimeter() float64
}
// Implémenter l'interface pour Rectangle
func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}
// Rectangle implémente maintenant l'interface Shape
func printShapeInfo(s Shape) {
    fmt.Printf("Aire: %.2f, Périmètre: %.2f\n",
               s.Area(), s.Perimeter())
}
```

### Interface Vide et Assertions de Type

Travailler avec des valeurs de types inconnus.

```go
// L'interface vide peut contenir n'importe quelle valeur
var i interface{}
i = 42
i = "hello"
i = []int{1, 2, 3}
// Assertion de type
str, ok := i.(string)
if ok {
    fmt.Printf("Valeur chaîne : %s\n", str)
}
// Switch de type
switch v := i.(type) {
case int:
    fmt.Printf("Entier : %d\n", v)
case string:
    fmt.Printf("Chaîne : %s\n", v)
default:
    fmt.Printf("Type inconnu : %T\n", v)
}
```

### Intégration (Embedding)

Composer des types en intégrant d'autres types.

```go
type Person struct {
    Name string
    Age  int
}
type Employee struct {
    Person    // Struct intégrée
    Company   string
    Salary    float64
}
// Utilisation
emp := Employee{
    Person:  Person{Name: "Alice", Age: 30},
    Company: "TechCorp",
    Salary:  75000,
}
// Accéder directement aux champs intégrés
fmt.Println(emp.Name) // "Alice"
```

## Gestion des Erreurs

### Gestion des Erreurs de Base

Utiliser l'interface d'erreur intégrée pour la gestion des erreurs.

```go
import "errors"
// Fonction qui retourne une erreur
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division par zéro")
    }
    return a / b, nil
}
// Vérification des erreurs
result, err := divide(10, 2)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Résultat: %.2f\n", result)
```

### Erreurs Personnalisées

Créer des types d'erreurs personnalisés pour des conditions d'erreur spécifiques.

```go
// Type d'erreur personnalisé
type ValidationError struct {
    Field   string
    Message string
}
func (e ValidationError) Error() string {
    return fmt.Sprintf("erreur de validation dans %s: %s",
                       e.Field, e.Message)
}
// Fonction utilisant une erreur personnalisée
func validateAge(age int) error {
    if age < 0 {
        return ValidationError{
            Field:   "age",
            Message: "doit être non négatif",
        }
    }
    return nil
}
```

### Enveloppement d'Erreurs (Error Wrapping)

Ajouter du contexte aux erreurs tout en préservant l'erreur d'origine.

```go
import "fmt"
// Envelopper une erreur avec un contexte supplémentaire
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("impossible d'ouvrir le fichier %s: %w",
                          filename, err)
    }
    defer file.Close()

    // Traiter le fichier...
    return nil
}
// Déballer les erreurs
err := processFile("missing.txt")
if err != nil {
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        fmt.Println("Erreur de chemin :", pathErr)
    }
}
```

### Panic et Recovery

Gérer les situations exceptionnelles avec `panic` et `recover`.

```go
// Fonction qui pourrait paniquer
func riskyOperation() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Récupéré de la panique :", r)
        }
    }()

    // Ceci provoquera une panique
    panic("quelque chose s'est mal passé !")
}
// Utilisation
riskyOperation() // Le programme continue après la panique
```

## Concurrence

### Goroutines

Threads légers gérés par le runtime Go.

```go
import "time"
// Goroutine simple
func sayHello() {
    fmt.Println("Hello depuis la goroutine !")
}
func main() {
    // Démarrer la goroutine
    go sayHello()

    // Goroutine anonyme
    go func() {
        fmt.Println("Goroutine anonyme")
    }()

    // Attendre que les goroutines se terminent
    time.Sleep(time.Second)
}
```

### Canaux (Channels)

Communication entre goroutines à l'aide de canaux.

```go
// Créer un canal
ch := make(chan int)
// Canal tamponné (buffered)
buffered := make(chan string, 3)
// Envoyer et recevoir
go func() {
    ch <- 42  // Envoyer la valeur
}()
value := <-ch  // Recevoir la valeur
// Fermer le canal
close(ch)
```

### Modèles de Canaux

Modèles courants pour la communication par canaux.

```go
// Modèle de travailleur (Worker pattern)
func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Travailleur %d traitant la tâche %d\n", id, job)
        results <- job * 2
    }
}
// Modèle Fan-out
jobs := make(chan int, 100)
results := make(chan int, 100)
// Démarrer les travailleurs
for w := 1; w <= 3; w++ {
    go worker(w, jobs, results)
}
// Envoyer les tâches
for j := 1; j <= 5; j++ {
    jobs <- j
}
close(jobs)
```

### Instruction Select

Gérer plusieurs opérations de canal simultanément.

```go
func main() {
    ch1 := make(chan string)
    ch2 := make(chan string)

    go func() {
        time.Sleep(time.Second)
        ch1 <- "depuis ch1"
    }()

    go func() {
        time.Sleep(2 * time.Second)
        ch2 <- "depuis ch2"
    }()

    // Sélectionner le premier canal disponible
    select {
    case msg1 := <-ch1:
        fmt.Println(msg1)
    case msg2 := <-ch2:
        fmt.Println(msg2)
    case <-time.After(3 * time.Second):
        fmt.Println("délai d'attente dépassé")
    }
}
```

## E/S de Fichiers et JSON

### Opérations sur les Fichiers

Lire et écrire des fichiers en utilisant diverses méthodes.

```go
import (
    "io/ioutil"
    "os"
)
// Lire le fichier entier
data, err := ioutil.ReadFile("file.txt")
if err != nil {
    log.Fatal(err)
}
content := string(data)
// Écrire dans un fichier
text := "Hello, World!"
err = ioutil.WriteFile("output.txt", []byte(text), 0644)
// Ouvrir un fichier avec plus de contrôle
file, err := os.Open("data.txt")
if err != nil {
    log.Fatal(err)
}
defer file.Close()
```

### Gestion des CSV

Lire et écrire des fichiers CSV.

```go
import (
    "encoding/csv"
    "os"
)
// Lire CSV
file, _ := os.Open("data.csv")
defer file.Close()
reader := csv.NewReader(file)
records, _ := reader.ReadAll()
// Écrire CSV
file, _ = os.Create("output.csv")
defer file.Close()
writer := csv.NewWriter(file)
defer writer.Flush()
writer.Write([]string{"Nom", "Âge", "Ville"})
writer.Write([]string{"Alice", "30", "NYC"})
```

### Traitement JSON

Encoder et décoder des données JSON.

```go
import "encoding/json"
// Struct pour le mappage JSON
type Person struct {
    Name  string `json:"name"`
    Age   int    `json:"age"`
    Email string `json:"email,omitempty"`
}
// Marshal (Go vers JSON)
person := Person{Name: "Alice", Age: 30}
jsonData, err := json.Marshal(person)
if err != nil {
    log.Fatal(err)
}
// Unmarshal (JSON vers Go)
var p Person
err = json.Unmarshal(jsonData, &p)
```

### Requêtes HTTP

Effectuer des requêtes HTTP et gérer les réponses.

```go
import "net/http"
// Requête GET
resp, err := http.Get("https://api.github.com/users/octocat")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
body, _ := ioutil.ReadAll(resp.Body)
// Requête POST avec JSON
jsonData := []byte(`{"name":"Alice","age":30}`)
resp, err = http.Post("https://api.example.com/users",
                      "application/json",
                      bytes.NewBuffer(jsonData))
```

## Tests

### Tests Unitaires : `go test`

Écrire et exécuter des tests en utilisant le framework de test de Go.

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
        t.Errorf("Add(2, 3) = %d; attendu %d", result, expected)
    }
}
// Exécuter les tests
// go test
// go test -v (verbeux)
```

### Tests Pilotés par Tableaux (Table-Driven Tests)

Tester plusieurs cas efficacement.

```go
func TestAddMultiple(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {"nombres positifs", 2, 3, 5},
        {"avec zéro", 0, 5, 5},
        {"nombres négatifs", -1, -2, -3},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Add(tt.a, tt.b)
            if result != tt.expected {
                t.Errorf("obtenu %d, attendu %d", result, tt.expected)
            }
        })
    }
}
```

### Benchmarking

Mesurer la performance des fonctions.

```go
func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(2, 3)
    }
}
// Exécuter les benchmarks
// go test -bench=.
// go test -bench=BenchmarkAdd -benchmem
```

### Tests d'Exemple

Créer des exemples exécutables qui servent de documentation.

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
// Exécuter les exemples
// go test -run Example
```

## Modules et Packages Go

### Gestion des Modules

Initialiser et gérer les modules Go pour la gestion des dépendances.

```bash
# Initialiser un nouveau module
go mod init github.com/username/project
# Ajouter des dépendances
go get github.com/gorilla/mux
go get -u github.com/gin-gonic/gin  # Mettre à jour vers la dernière version
# Supprimer les dépendances inutilisées
go mod tidy
# Télécharger les dépendances
go mod download
# Dépendances locales (vendor)
go mod vendor
```

### Fichier go.mod

Comprendre le fichier de définition du module.

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

### Création de Packages

Structurer le code en packages réutilisables.

```go
// Structure du package
// myproject/
//   ├── go.mod
//   ├── main.go
//   └── utils/
//       ├── math.go
//       └── string.go
// utils/math.go
package utils
// Fonction exportée (commence par une majuscule)
func Add(a, b int) int {
    return a + b
}
// Fonction privée (commence par une minuscule)
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

### Commandes Go Courantes

Commandes essentielles pour le développement Go.

```bash
# Exécuter un programme Go
go run main.go
# Compiler l'exécutable
go build
go build -o myapp  # Nom personnalisé
# Installer le binaire dans GOPATH/bin
go install
# Formater le code
go fmt ./...
# Vérifier le code pour les problèmes
go vet ./...
# Nettoyer le cache de construction
go clean -cache
```

## Liens Pertinents

- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>
- <router-link to="/docker">Feuille de triche Docker</router-link>
- <router-link to="/kubernetes">Feuille de triche Kubernetes</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/java">Feuille de triche Java</router-link>

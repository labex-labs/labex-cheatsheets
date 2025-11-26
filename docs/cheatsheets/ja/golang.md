---
title: 'Golang チートシート'
description: '必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートで Golang を習得しましょう。'
pdfUrl: '/cheatsheets/pdf/golang-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Golang チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/golang">ハンズオンラボで Golang を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて Go プログラミングを学びましょう。LabEx は、必須の構文、並行処理パターン、エラー処理、高度なテクニックを網羅した包括的な Go コースを提供します。goroutine、channel、interface といった Go 独自の機能を習得し、効率的で並行性の高いアプリケーションを構築します。
</base-disclaimer-content>
</base-disclaimer>

## インストールとセットアップ

### Go のインストール：ダウンロードと展開

公式ウェブサイトから Go をダウンロードしてインストールします。

```bash
# https://golang.org/dl/ からダウンロード
# Linux/macOS - /usr/local に展開
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
# ~/.bashrc または ~/.zshrc にPATHを追加
export PATH=$PATH:/usr/local/go/bin
# インストールを確認
go version
```

### パッケージマネージャ：Homebrew の使用 (macOS)

macOS で Homebrew を使用して Go をインストールします。

```bash
# HomebrewでGoをインストール
brew install go
# インストールを確認
go version
go env GOPATH
```

### Windows のインストール

Windows システムへの Go のインストール。

```bash
# https://golang.org/dl/ から .msi インストーラをダウンロード
# インストーラを実行し、プロンプトに従う
# コマンドプロンプトで確認
go version
echo %GOPATH%
```

### ワークスペースのセットアップ：`go mod init`

新しい Go モジュールとワークスペースを初期化します。

```bash
# 新しいディレクトリを作成し、モジュールを初期化
mkdir my-go-project
cd my-go-project
go mod init my-go-project
# main.goを作成
echo 'package main
import "fmt"
func main() {
    fmt.Println("Hello, World!")
}' > main.go
# プログラムを実行
go run main.go
```

### 環境変数

重要な Go 環境変数。

```bash
# すべてのGo環境変数を表示
go env
# 主要な変数
go env GOROOT    # Goのインストールディレクトリ
go env GOPATH    # ワークスペースディレクトリ
go env GOOS      # オペレーティングシステム
go env GOARCH    # アーキテクチャ
```

### IDE セットアップ：VS Code

Go 開発のために VS Code を設定します。

```bash
# VS CodeでGo拡張機能をインストール
# Ctrl+Shift+P -> Go: Install/Update Tools
# 有効になる主な機能:
# - 構文ハイライト
# - IntelliSense
# - デバッグ
# - テスト統合
```

## 基本構文と型

### パッケージとインポート

すべての Go ファイルはパッケージ宣言とインポートから始まります。

```go
package main
import (
    "fmt"
    "strings"
    "time"
)
// 単一インポート
import "os"
```

### 変数と定数

変数と定数を宣言および初期化します。

```go
// 変数宣言
var name string = "Go"
var age int = 15
var isOpen bool
// 短縮宣言
name := "Golang"
count := 42
// 定数
const Pi = 3.14159
const Message = "Hello, Go!"
```

### 基本データ型

Go で利用可能な基本的な型。

```go
// 数値型
var i int = 42
var f float64 = 3.14
var c complex64 = 1 + 2i
// テキスト型
var s string = "Hello"
var r rune = 'A'
// ブール値
var b bool = true
```

## 制御フロー

### 条件分岐：`if` / `else` / `switch`

条件文でプログラムの流れを制御します。

```go
// If 文
if age >= 18 {
    fmt.Println("Adult")
} else if age >= 13 {
    fmt.Println("Teenager")
} else {
    fmt.Println("Child")
}
// Switch 文
switch day {
case "Monday":
    fmt.Println("Start of work week")
case "Friday":
    fmt.Println("TGIF")
default:
    fmt.Println("Regular day")
}
```

### ループ：`for` / `range`

様々なループ構造を使用して反復処理を行います。

```go
// 従来の for ループ
for i := 0; i < 10; i++ {
    fmt.Println(i)
}
// While スタイルのループ
for condition {
    // ループ本体
}
// 無限ループ
for {
    // 必要なときに break
}
```

### Range による反復処理

スライス、配列、マップ、文字列を反復処理します。

```go
// スライスを反復処理
numbers := []int{1, 2, 3, 4, 5}
for index, value := range numbers {
    fmt.Printf("Index: %d, Value: %d\n", index, value)
}
// マップを反復処理
colors := map[string]string{"red": "#FF0000", "green": "#00FF00"}
for key, value := range colors {
    fmt.Printf("%s: %s\n", key, value)
}
// 文字列を反復処理
for i, char := range "Hello" {
    fmt.Printf("%d: %c\n", i, char)
}
```

### 制御文：`break` / `continue`

ループの実行フローを制御します。

```go
// ループを抜ける
for i := 0; i < 10; i++ {
    if i == 5 {
        break
    }
    fmt.Println(i)
}
// 現在のイテレーションをスキップ
for i := 0; i < 5; i++ {
    if i == 2 {
        continue
    }
    fmt.Println(i)
}
```

## 関数

### 関数宣言：`func`

パラメータと戻り値を持つ関数を定義します。

```go
// 基本的な関数
func greet(name string) {
    fmt.Printf("Hello, %s!\n", name)
}
// 戻り値を持つ関数
func add(a, b int) int {
    return a + b
}
// 複数の戻り値
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
```

### 名前付き戻り値と可変引数関数

高度な関数機能とパターン。

```go
// 名前付き戻り値
func split(sum int) (x, y int) {
    x = sum * 4 / 9
    y = sum - x
    return // ネイキッドリターン
}
// 可変引数関数 (Variadic function)
func sum(nums ...int) int {
    total := 0
    for _, num := range nums {
        total += num
    }
    return total
}
// 使用法
result := sum(1, 2, 3, 4, 5)
```

### 関数型とクロージャ

Go における第一級オブジェクトとしての関数。

```go
// 変数としての関数
var multiply func(int, int) int
multiply = func(a, b int) int {
    return a * b
}
// 無名関数
square := func(x int) int {
    return x * x
}
// クロージャ
func counter() func() int {
    count := 0
    return func() int {
        count++
        return count
    }
}
// 使用法
c := counter()
fmt.Println(c()) // 1
fmt.Println(c()) // 2
```

### Defer ステートメント

周囲の関数が戻るまで関数の実行を遅延させます。

```go
func processFile(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close() // 関数が戻るときに実行される

    // ファイル内容を処理
    // file.Close() は自動的に呼び出される
}
```

## データ構造

### 配列とスライス

要素の固定長および動的なシーケンス。

```go
// 配列 (固定サイズ)
var arr [5]int = [5]int{1, 2, 3, 4, 5}
shortArr := [3]string{"a", "b", "c"}
// スライス (動的)
var slice []int
slice = append(slice, 1, 2, 3)
// 容量を指定してスライスを作成
numbers := make([]int, 5, 10) // 長さ 5、容量 10
// スライス操作
slice2 := slice[1:3]  // [2, 3]
copy(slice2, slice)   // 要素をコピー
```

### マップ

効率的なルックアップのためのキーと値のペア。

```go
// マップの宣言と初期化
var m map[string]int
m = make(map[string]int)
// 短縮宣言
ages := map[string]int{
    "Alice": 30,
    "Bob":   25,
    "Carol": 35,
}
// マップ操作
ages["David"] = 40        // 追加/更新
delete(ages, "Bob")       // 削除
age, exists := ages["Alice"] // 存在確認
```

### 構造体 (Structs)

関連するデータをカスタム型でグループ化します。

```go
// 構造体の定義
type Person struct {
    Name    string
    Age     int
    Email   string
}
// 構造体インスタンスの作成
p1 := Person{
    Name:  "Alice",
    Age:   30,
    Email: "alice@example.com",
}
p2 := Person{"Bob", 25, "bob@example.com"}
// フィールドへのアクセス
fmt.Println(p1.Name)
p1.Age = 31
```

### ポインタ

変数のメモリ位置への参照。

```go
// ポインタ宣言
var p *int
num := 42
p = &num  // num のアドレス
// 間接参照 (Dereferencing)
fmt.Println(*p) // アドレスにある値 (42)
*p = 100        // ポインタ経由で値を変更
// 構造体とポインタ
person := &Person{Name: "Alice", Age: 30}
person.Age = 31  // 自動的な間接参照
```

## メソッドとインターフェース

### メソッド

カスタム型に機能（動作）を関連付けます。

```go
type Rectangle struct {
    Width, Height float64
}
// レシーバを持つメソッド
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}
// ポインタレシーバ (変更可能)
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor
    r.Height *= factor
}
// 使用法
rect := Rectangle{Width: 10, Height: 5}
fmt.Println(rect.Area()) // 50
rect.Scale(2)            // rect を変更する
```

### インターフェース

型が満たすべき契約を定義します。

```go
// インターフェースの定義
type Shape interface {
    Area() float64
    Perimeter() float64
}
// Rectangle に対するインターフェースの実装
func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}
// Rectangle は Shape インターフェースを実装した
func printShapeInfo(s Shape) {
    fmt.Printf("Area: %.2f, Perimeter: %.2f\n",
               s.Area(), s.Perimeter())
}
```

### 空のインターフェースと型アサーション

未知の型を持つ値の扱い。

```go
// 空のインターフェースはあらゆる値を保持できる
var i interface{}
i = 42
i = "hello"
i = []int{1, 2, 3}
// 型アサーション
str, ok := i.(string)
if ok {
    fmt.Printf("String value: %s\n", str)
}
// 型スイッチ
switch v := i.(type) {
case int:
    fmt.Printf("Integer: %d\n", v)
case string:
    fmt.Printf("String: %s\n", v)
default:
    fmt.Printf("Unknown type: %T\n", v)
}
```

### 埋め込み (Embedding)

他の型を埋め込むことで型を合成します。

```go
type Person struct {
    Name string
    Age  int
}
type Employee struct {
    Person    // 埋め込み構造体
    Company   string
    Salary    float64
}
// 使用法
emp := Employee{
    Person:  Person{Name: "Alice", Age: 30},
    Company: "TechCorp",
    Salary:  75000,
}
// 埋め込みフィールドへの直接アクセス
fmt.Println(emp.Name) // "Alice"
```

## エラー処理

### 基本的なエラー処理

組み込みの error インターフェースを使用してエラーを処理します。

```go
import "errors"
// エラーを返す関数
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
// エラーチェック
result, err := divide(10, 2)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Result: %.2f\n", result)
```

### カスタムエラー

特定のエラー条件のためにカスタムエラー型を作成します。

```go
// カスタムエラー型
type ValidationError struct {
    Field   string
    Message string
}
func (e ValidationError) Error() string {
    return fmt.Sprintf("validation error in %s: %s",
                       e.Field, e.Message)
}
// カスタムエラーを使用する関数
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

### エラーのラップ

元のエラーを保持しながら、エラーにコンテキストを追加します。

```go
import "fmt"
// 追加のコンテキストでエラーをラップ
func processFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("failed to open file %s: %w",
                          filename, err)
    }
    defer file.Close()

    // ファイルを処理...
    return nil
}
// エラーのアンラップ
err := processFile("missing.txt")
if err != nil {
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        fmt.Println("Path error:", pathErr)
    }
}
```

### Panic とリカバリ

panic と recover を使用して例外的な状況を処理します。

```go
// panic する可能性のある関数
func riskyOperation() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from panic:", r)
        }
    }()

    // これが panic を引き起こす
    panic("something went wrong!")
}
// 使用法
riskyOperation() // panic 後もプログラムは続行する
```

## 並行処理 (Concurrency)

### Goroutine

Go のランタイムによって管理される軽量スレッド。

```go
import "time"
// シンプルな goroutine
func sayHello() {
    fmt.Println("Hello from goroutine!")
}
func main() {
    // goroutine を開始
    go sayHello()

    // 無名 goroutine
    go func() {
        fmt.Println("Anonymous goroutine")
    }()

    // goroutine が終了するのを待つ
    time.Sleep(time.Second)
}
```

### Channel

チャネルを使用した goroutine 間の通信。

```go
// チャネルの作成
ch := make(chan int)
// バッファ付きチャネル
buffered := make(chan string, 3)
// 送信と受信
go func() {
    ch <- 42  // 値を送信
}()
value := <-ch  // 値を受信
// チャネルを閉じる
close(ch)
```

### Channel パターン

チャネル通信の一般的なパターン。

```go
// ワーカーパターン
func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Worker %d processing job %d\n", id, job)
        results <- job * 2
    }
}
// Fan-out パターン
jobs := make(chan int, 100)
results := make(chan int, 100)
// ワーカーを開始
for w := 1; w <= 3; w++ {
    go worker(w, jobs, results)
}
// ジョブを送信
for j := 1; j <= 5; j++ {
    jobs <- j
}
close(jobs)
```

### Select ステートメント

複数のチャネル操作を同時に処理します。

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

    // 最初に利用可能になったチャネルを処理
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

## ファイル I/O と JSON

### ファイル操作

様々なメソッドを使用したファイルの読み書き。

```go
import (
    "io/ioutil"
    "os"
)
// ファイル全体を読み込む
data, err := ioutil.ReadFile("file.txt")
if err != nil {
    log.Fatal(err)
}
content := string(data)
// ファイルへの書き込み
text := "Hello, World!"
err = ioutil.WriteFile("output.txt", []byte(text), 0644)
// より詳細な制御でファイルを開く
file, err := os.Open("data.txt")
if err != nil {
    log.Fatal(err)
}
defer file.Close()
```

### CSV の処理

CSV ファイルの読み書き。

```go
import (
    "encoding/csv"
    "os"
)
// CSV の読み込み
file, _ := os.Open("data.csv")
defer file.Close()
reader := csv.NewReader(file)
records, _ := reader.ReadAll()
// CSV の書き込み
file, _ = os.Create("output.csv")
defer file.Close()
writer := csv.NewWriter(file)
defer writer.Flush()
writer.Write([]string{"Name", "Age", "City"})
writer.Write([]string{"Alice", "30", "NYC"})
```

### JSON 処理

JSON データのエンコードとデコード。

```go
import "encoding/json"
// JSON マッピング用の構造体
type Person struct {
    Name  string `json:"name"`
    Age   int    `json:"age"`
    Email string `json:"email,omitempty"`
}
// マーシャル (Go から JSON へ)
person := Person{Name: "Alice", Age: 30}
jsonData, err := json.Marshal(person)
if err != nil {
    log.Fatal(err)
}
// アンマーシャル (JSON から Go へ)
var p Person
err = json.Unmarshal(jsonData, &p)
```

### HTTP リクエスト

HTTP リクエストの実行とレスポンスの処理。

```go
import "net/http"
// GET リクエスト
resp, err := http.Get("https://api.github.com/users/octocat")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
body, _ := ioutil.ReadAll(resp.Body)
// JSON 付き POST リクエスト
jsonData := []byte(`{"name":"Alice","age":30}`)
resp, err = http.Post("https://api.example.com/users",
                      "application/json",
                      bytes.NewBuffer(jsonData))
```

## テスト

### 単体テスト：`go test`

Go のテストフレームワークを使用したテストの記述と実行。

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
// テストの実行
// go test
// go test -v (詳細表示)
```

### テーブル駆動テスト

複数のケースを効率的にテストします。

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

### ベンチマーク

関数のパフォーマンスを測定します。

```go
func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(2, 3)
    }
}
// ベンチマークの実行
// go test -bench=.
// go test -bench=BenchmarkAdd -benchmem
```

### 例外テスト (Example Tests)

ドキュメントとして機能する実行可能な例を作成します。

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
// 例の実行
// go test -run Example
```

## Go モジュールとパッケージ

### モジュール管理

依存関係管理のための Go モジュールの初期化と管理。

```bash
# 新しいモジュールを初期化
go mod init github.com/username/project
# 依存関係の取得
go get github.com/gorilla/mux
go get -u github.com/gin-gonic/gin  # 最新版に更新
# 不要な依存関係の削除
go mod tidy
# 依存関係のダウンロード
go mod download
# 依存関係をローカルにベンダー化
go mod vendor
```

### go.mod ファイル

モジュール定義ファイルの理解。

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

### パッケージの作成

コードを再利用可能なパッケージに構造化します。

```go
// パッケージ構造
// myproject/
//   ├── go.mod
//   ├── main.go
//   └── utils/
//       ├── math.go
//       └── string.go
// utils/math.go
package utils
// エクスポートされる関数 (大文字で始まる)
func Add(a, b int) int {
    return a + b
}
// プライベート関数 (小文字で始まる)
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

### 一般的な Go コマンド

Go 開発のための必須コマンド。

```bash
# Goプログラムの実行
go run main.go
# 実行可能ファイルのビルド
go build
go build -o myapp  # カスタム名
# バイナリをGOPATH/binにインストール
go install
# コードのフォーマット
go fmt ./...
# 問題がないかコードを検証
go vet ./...
# ビルドキャッシュのクリーンアップ
go clean -cache
```

## 関連リンク

- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/kubernetes">Kubernetes チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/java">Java チートシート</router-link>

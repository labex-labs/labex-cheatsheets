---
title: 'Folha de Cola C++ | LabEx'
description: 'Aprenda programação C++ com esta folha de cola abrangente. Referência rápida para sintaxe C++, OOP, STL, templates, gestão de memória e recursos C++ modernos para desenvolvedores de software.'
pdfUrl: '/cheatsheets/pdf/cpp-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas de C++
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/cpp">Aprenda C++ com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda programação C++ através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de C++ cobrindo sintaxe essencial, programação orientada a objetos, contêineres STL, gerenciamento de memória e técnicas avançadas. Domine os recursos poderosos do C++ para construir aplicações de alto desempenho e software de sistema.
</base-disclaimer-content>
</base-disclaimer>

## Sintaxe Básica e Estrutura

### Programa Olá Mundo

Estrutura básica de um programa C++.

```cpp
#include <iostream>
using namespace std;
int main() {
    cout << "Hello, World!" << endl;
    return 0;
}
```

### Headers e Namespaces

Incluir bibliotecas e gerenciar namespaces.

```cpp
#include <iostream>  // Fluxo de entrada/saída
#include <vector>    // Arrays dinâmicos
#include <string>    // Classe string
#include <algorithm> // Algoritmos STL
using namespace std;
// Ou especificar individualmente:
// using std::cout;
// using std::cin;
```

### Comentários

Comentários de linha única e múltiplas linhas.

```cpp
// Comentário de linha única
/*
Comentário de
múltiplas linhas
que se estende por várias linhas
*/
// TODO: Implementar funcionalidade
/* FIXME: Bug nesta seção */
```

### Função Main

Ponto de entrada do programa com valores de retorno.

```cpp
int main() {
    // Código do programa aqui
    return 0;  // Sucesso
}
int main(int argc, char* argv[]) {
    // argc: contagem de argumentos
    // argv: valores dos argumentos (linha de comando)
    return 0;
}
```

<BaseQuiz id="cpp-main-1" correct="B">
  <template #question>
    Qual é a diferença entre as instruções de saída C e C++?
  </template>
  
  <BaseQuizOption value="A">Não há diferença</BaseQuizOption>
  <BaseQuizOption value="B" correct>C usa printf(), C++ usa cout com o operador &lt;&lt;</BaseQuizOption>
  <BaseQuizOption value="C">C++ não suporta saída</BaseQuizOption>
  <BaseQuizOption value="D">C usa cout, C++ usa printf</BaseQuizOption>
  
  <BaseQuizAnswer>
    C usa <code>printf()</code> de stdio.h, enquanto C++ usa <code>cout</code> de iostream com o operador de inserção de fluxo <code><<</code>. C++ também suporta printf para compatibilidade.
  </BaseQuizAnswer>
</BaseQuiz>

### Saída Básica

Exibir texto e variáveis no console.

```cpp
cout << "Hello" << endl;
cout << "Value: " << 42 << endl;
// Múltiplos valores em uma linha
cout << "Name: " << name << ", Age: " << age << endl;
```

### Entrada Básica

Ler a entrada do usuário pelo console.

```cpp
int age;
string name;
cin >> age;
cin >> name;
// Ler linha inteira com espaços
getline(cin, name);
```

## Tipos de Dados e Variáveis

### Tipos Primitivos

Tipos de dados básicos para armazenar diferentes tipos de valores.

```cpp
// Tipos inteiros
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// Tipos de ponto flutuante
float price = 19.99f;
double precise = 3.14159265359;
// Caractere e booleano
char grade = 'A';
bool is_valid = true;
```

### String e Arrays

Tipos de dados de texto e coleção.

```cpp
// Strings
string name = "John Doe";
string empty_str;
// Arrays
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// Arrays dinâmicos (vetores)
vector<int> dynamic_array = {10, 20, 30};
vector<string> names(5); // Tamanho 5, strings vazias
```

<BaseQuiz id="cpp-vector-1" correct="B">
  <template #question>
    Qual é a principal vantagem do <code>vector</code> sobre arrays regulares em C++?
  </template>
  
  <BaseQuizOption value="A">Vectors são mais rápidos</BaseQuizOption>
  <BaseQuizOption value="B" correct>Vectors podem redimensionar dinamicamente, enquanto arrays têm tamanho fixo</BaseQuizOption>
  <BaseQuizOption value="C">Vectors usam menos memória</BaseQuizOption>
  <BaseQuizOption value="D">Não há vantagem</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>vector</code> é um array dinâmico que pode crescer ou encolher em tempo de execução, ao contrário dos arrays regulares cujo tamanho fixo é determinado em tempo de compilação. Isso torna os vetores mais flexíveis para muitos casos de uso.
  </BaseQuizAnswer>
</BaseQuiz>

### Constantes e Auto

Valores imutáveis e dedução automática de tipo.

```cpp
// Constantes
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Palavra-chave Auto (C++11+)
auto x = 42;        // int
auto y = 3.14;      // double
auto name = "John"; // const char*
// Alias de tipo
typedef unsigned int uint;
using real = double;
```

## Estruturas de Controle de Fluxo

### Declarações Condicionais

Tomar decisões com base em condições.

```cpp
// Declaração If-else
if (age >= 18) {
    cout << "Adulto" << endl;
} else if (age >= 13) {
    cout << "Adolescente" << endl;
} else {
    cout << "Criança" << endl;
}
// Operador ternário
string status = (age >= 18) ? "Adulto" : "Menor";
// Declaração Switch
switch (grade) {
    case 'A':
        cout << "Excelente!" << endl;
        break;
    case 'B':
        cout << "Bom trabalho!" << endl;
        break;
    default:
        cout << "Continue tentando!" << endl;
}
```

### Loops For

Iterar com loops baseados em contador.

```cpp
// Loop for tradicional
for (int i = 0; i < 10; i++) {
    cout << i << " ";
}
// Loop for baseado em intervalo (C++11+)
vector<int> numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    cout << num << " ";
}
// Auto com loop baseado em intervalo
for (auto& item : container) {
    // Processar item
}
```

<BaseQuiz id="cpp-range-for-1" correct="B">
  <template #question>
    O que é um loop for baseado em intervalo em C++?
  </template>
  
  <BaseQuizOption value="A">Um loop que só funciona com arrays</BaseQuizOption>
  <BaseQuizOption value="B" correct>Um loop que itera sobre todos os elementos em um contêiner automaticamente</BaseQuizOption>
  <BaseQuizOption value="C">Um loop que roda para sempre</BaseQuizOption>
  <BaseQuizOption value="D">Um loop que requer gerenciamento manual de índice</BaseQuizOption>
  
  <BaseQuizAnswer>
    Loops for baseados em intervalo (introduzidos no C++11) iteram automaticamente sobre todos os elementos em um contêiner (como vetores, arrays, strings) sem a necessidade de gerenciar índices manualmente. A sintaxe é <code>for (auto item : container)</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### Loops While

Iteração baseada em condição.

```cpp
// Loop While
int count = 0;
while (count < 5) {
    cout << count << endl;
    count++;
}
// Loop Do-while (executa pelo menos uma vez)
int input;
do {
    cout << "Digite um número (0 para sair): ";
    cin >> input;
} while (input != 0);
```

### Controle de Loop

Declarações break e continue.

```cpp
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // Pular iteração
    }
    if (i == 7) {
        break;    // Sair do loop
    }
    cout << i << " ";
}
// Loops aninhados com break rotulado
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // Quebra apenas o loop interno
        cout << i << "," << j << " ";
    }
}
```

## Funções

### Declaração e Definição de Função

Criar blocos de código reutilizáveis.

```cpp
// Declaração de função (protótipo)
int add(int a, int b);
void printMessage(string msg);
// Definição de função
int add(int a, int b) {
    return a + b;
}
void printMessage(string msg) {
    cout << msg << endl;
}
// Chamada de função
int result = add(5, 3);
printMessage("Olá, funções!");
```

### Sobrecarga de Função (Function Overloading)

Múltiplas funções com o mesmo nome.

```cpp
// Tipos de parâmetros diferentes
int multiply(int a, int b) {
    return a * b;
}
double multiply(double a, double b) {
    return a * b;
}
// Número diferente de parâmetros
int multiply(int a, int b, int c) {
    return a * b * c;
}
```

### Parâmetros Padrão

Fornecer valores padrão para parâmetros de função.

```cpp
void greet(string name, string greeting = "Hello") {
    cout << greeting << ", " << name << "!" << endl;
}
// Chamadas de função
greet("Alice");              // Usa o padrão "Hello"
greet("Bob", "Good morning"); // Usa saudação personalizada
```

### Passagem por Referência

Modificar variáveis através de parâmetros de função.

```cpp
// Passagem por valor (cópia)
void changeValue(int x) {
    x = 100; // Variável original inalterada
}
// Passagem por referência
void changeReference(int& x) {
    x = 100; // Variável original modificada
}
// Referência const (somente leitura, eficiente)
void processLargeData(const vector<int>& data) {
    // Pode ler dados, mas não modificar
}
```

## Programação Orientada a Objetos

### Definição de Classe

Definir tipos de dados personalizados com atributos e métodos.

```cpp
class Rectangle {
private:
    double width, height;
public:
    // Construtor
    Rectangle(double w, double h) : width(w), height(h) {}

    // Construtor padrão
    Rectangle() : width(0), height(0) {}

    // Funções membro
    double area() const {
        return width * height;
    }

    void setDimensions(double w, double h) {
        width = w;
        height = h;
    }

    // Funções getter
    double getWidth() const { return width; }
    double getHeight() const { return height; }
};
```

### Criação e Uso de Objeto

Instanciar e usar objetos de classe.

```cpp
// Criar objetos
Rectangle rect1(5.0, 3.0);
Rectangle rect2; // Construtor padrão
// Usar funções membro
cout << "Area: " << rect1.area() << endl;
rect2.setDimensions(4.0, 2.0);
// Alocação dinâmica
Rectangle* rect3 = new Rectangle(6.0, 4.0);
cout << rect3->area() << endl;
delete rect3; // Limpar memória
```

### Herança

Criar classes especializadas a partir de classes base.

```cpp
class Shape {
protected:
    string color;

public:
    Shape(string c) : color(c) {}
    virtual double area() const = 0; // Virtual puro
    string getColor() const { return color; }
};
class Circle : public Shape {
private:
    double radius;

public:
    Circle(double r, string c) : Shape(c), radius(r) {}

    double area() const override {
        return 3.14159 * radius * radius;
    }
};
```

### Polimorfismo

Usar ponteiros de classe base para acessar objetos derivados.

```cpp
// Funções virtuais e polimorfismo
vector<Shape*> shapes;
shapes.push_back(new Circle(5.0, "red"));
shapes.push_back(new Rectangle(4.0, 6.0));
for (Shape* shape : shapes) {
    cout << "Area: " << shape->area() << endl;
    // Chama o método da classe derivada apropriado
}
```

## Gerenciamento de Memória

### Alocação Dinâmica de Memória

Alocar e desalocar memória em tempo de execução.

```cpp
// Objeto único
int* ptr = new int(42);
cout << *ptr << endl;
delete ptr;
ptr = nullptr;
// Alocação de Array
int* arr = new int[10];
for (int i = 0; i < 10; i++) {
    arr[i] = i * i;
}
delete[] arr;
// Verificar falha de alocação
int* large_array = new(nothrow) int[1000000];
if (large_array == nullptr) {
    cout << "Alocação falhou!" << endl;
}
```

### Ponteiros Inteligentes (Smart Pointers) (C++11+)

Gerenciamento automático de memória com RAII.

```cpp
#include <memory>
// unique_ptr (propriedade exclusiva)
unique_ptr<int> ptr1 = make_unique<int>(42);
unique_ptr<int> ptr2 = move(ptr1); // Transfere a propriedade
// shared_ptr (propriedade compartilhada)
shared_ptr<int> sptr1 = make_shared<int>(100);
shared_ptr<int> sptr2 = sptr1; // Compartilha a propriedade
cout << sptr1.use_count() << endl; // Contagem de referências
```

### Referências vs Ponteiros

Duas maneiras de acessar objetos indiretamente.

```cpp
int x = 10;
// Referência (alias)
int& ref = x;  // Deve ser inicializada
ref = 20;      // Altera x para 20
// Ponteiro
int* ptr = &x; // Aponta para o endereço de x
*ptr = 30;     // Desreferencia e altera x
ptr = nullptr; // Pode apontar para nada
// Variações const
const int* ptr1 = &x;    // Não pode mudar o valor
int* const ptr2 = &x;    // Não pode mudar o endereço
const int* const ptr3 = &x; // Não pode mudar nenhum dos dois
```

### Pilha vs Heap

Estratégias de alocação de memória.

```cpp
// Alocação na Pilha (automática)
int stack_var = 42;
int stack_array[100];
// Alocação no Heap (dinâmica)
int* heap_var = new int(42);
int* heap_array = new int[100];
// Objetos da pilha são limpos automaticamente
// Objetos do heap devem ser deletados manualmente
delete heap_var;
delete[] heap_array;
```

## Biblioteca Padrão de Templates (STL)

### Contêineres: Vector e String

Arrays dinâmicos e manipulação de strings.

```cpp
#include <vector>
#include <string>
// Operações com Vector
vector<int> nums = {1, 2, 3};
nums.push_back(4);        // Adicionar elemento
nums.pop_back();          // Remover o último
nums.insert(nums.begin() + 1, 10); // Inserir na posição
nums.erase(nums.begin()); // Remover o primeiro
// Operações com String
string text = "Hello";
text += " World";         // Concatenação
text.append("!");         // Anexar
cout << text.substr(0, 5) << endl; // Substring
text.replace(6, 5, "C++"); // Substituir "World" por "C++"
```

### Contêineres: Map e Set

Contêineres associativos para pares chave-valor e elementos únicos.

```cpp
#include <map>
#include <set>
// Map (pares chave-valor)
map<string, int> ages;
ages["Alice"] = 25;
ages["Bob"] = 30;
ages.insert({"Charlie", 35});
// Set (elementos únicos)
set<int> unique_nums = {3, 1, 4, 1, 5, 9};
unique_nums.insert(2);
unique_nums.erase(1);
// Automaticamente ordenado: {2, 3, 4, 5, 9}
```

### Algoritmos

Algoritmos STL para operações comuns.

```cpp
#include <algorithm>
vector<int> nums = {64, 34, 25, 12, 22, 11, 90};
// Ordenação
sort(nums.begin(), nums.end());
sort(nums.rbegin(), nums.rend()); // Ordenação reversa
// Busca
auto it = find(nums.begin(), nums.end(), 25);
if (it != nums.end()) {
    cout << "Encontrado na posição: " << it - nums.begin();
}
// Outros algoritmos úteis
reverse(nums.begin(), nums.end());
int max_val = *max_element(nums.begin(), nums.end());
int count = count_if(nums.begin(), nums.end(),
                    [](int x) { return x > 50; });
```

### Iteradores

Navegar pelos contêineres de forma eficiente.

```cpp
vector<string> words = {"hello", "world", "cpp"};
// Tipos de iterador
vector<string>::iterator it;
auto it2 = words.begin(); // Auto C++11
// Iterar pelo contêiner
for (it = words.begin(); it != words.end(); ++it) {
    cout << *it << " ";
}
// Loop baseado em intervalo (preferido)
for (const auto& word : words) {
    cout << word << " ";
}
```

## Operações de Entrada/Saída

### Entrada de Arquivo: Leitura de Arquivos

Ler dados de arquivos de texto.

```cpp
#include <fstream>
#include <sstream>
// Ler arquivo inteiro
ifstream file("data.txt");
if (file.is_open()) {
    string line;
    while (getline(file, line)) {
        cout << line << endl;
    }
    file.close();
}
// Ler palavra por palavra
ifstream file2("numbers.txt");
int number;
while (file2 >> number) {
    cout << number << " ";
}
// Leitura com verificação de erro
if (!file.good()) {
    cerr << "Erro ao ler o arquivo!" << endl;
}
```

### Processamento de Fluxo de String (String Stream)

Analisar e manipular strings como fluxos.

```cpp
#include <sstream>
// Analisar valores separados por vírgula
string data = "apple,banana,cherry";
stringstream ss(data);
string item;
vector<string> fruits;
while (getline(ss, item, ',')) {
    fruits.push_back(item);
}
// Converter strings para números
string num_str = "123";
int num = stoi(num_str);
double d = stod("3.14159");
string back_to_str = to_string(num);
```

### Saída de Arquivo: Escrita de Arquivos

Escrever dados em arquivos de texto.

```cpp
// Escrever no arquivo
ofstream outfile("output.txt");
if (outfile.is_open()) {
    outfile << "Hello, file!" << endl;
    outfile << "Number: " << 42 << endl;
    outfile.close();
}
// Anexar a arquivo existente
ofstream appendfile("log.txt", ios::app);
appendfile << "New log entry" << endl;
// Escrever vetor no arquivo
vector<int> numbers = {1, 2, 3, 4, 5};
ofstream numfile("numbers.txt");
for (int num : numbers) {
    numfile << num << " ";
}
```

### Formatação de Fluxo

Controlar o formato e a precisão da saída.

```cpp
#include <iomanip>
double pi = 3.14159265;
cout << fixed << setprecision(2) << pi << endl; // 3.14
cout << setw(10) << "Right" << endl;          // Alinhado à direita
cout << left << setw(10) << "Left" << endl;     // Alinhado à esquerda
cout << hex << 255 << endl;                    // Hexadecimal: ff
```

## Tratamento de Erros

### Blocos Try-Catch

Lidar com exceções que podem ocorrer durante a execução.

```cpp
try {
    int result = 10 / 0; // Isso pode lançar uma exceção
    vector<int> vec(5);
    vec.at(10) = 100;    // Acesso fora dos limites

} catch (const exception& e) {
    cout << "Exceção capturada: " << e.what() << endl;
} catch (...) {
    cout << "Exceção desconhecida capturada!" << endl;
}
// Tipos de exceção específicos
try {
    string str = "abc";
    int num = stoi(str); // Lança invalid_argument
} catch (const invalid_argument& e) {
    cout << "Argumento inválido: " << e.what() << endl;
} catch (const out_of_range& e) {
    cout << "Fora do intervalo: " << e.what() << endl;
}
```

### Lançamento de Exceções Personalizadas

Criar e lançar suas próprias exceções.

```cpp
// Classe de exceção personalizada
class CustomException : public exception {
    string message;
public:
    CustomException(const string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};
// Função que lança exceção
void validateAge(int age) {
    if (age < 0 || age > 150) {
        throw CustomException("Faixa de idade inválida!");
    }
}
// Uso
try {
    validateAge(-5);
} catch (const CustomException& e) {
    cout << e.what() << endl;
}
```

### Padrão RAII

Aquisição de Recurso É Inicialização para gerenciamento seguro de recursos.

```cpp
// RAII com ponteiros inteligentes
{
    unique_ptr<int[]> arr = make_unique<int[]>(1000);
    // Array deletado automaticamente ao sair do escopo
}
// RAII com manipulação de arquivos
{
    ifstream file("data.txt");
    // Arquivo fechado automaticamente ao sair do escopo
    if (file.is_open()) {
        // Processar arquivo
    }
}
// Classe RAII personalizada
class FileHandler {
    FILE* file;
public:
    FileHandler(const char* filename) {
        file = fopen(filename, "r");
    }
    ~FileHandler() {
        if (file) fclose(file);
    }
    FILE* get() { return file; }
};
```

### Asserções e Depuração (Debugging)

Depurar e validar suposições do programa.

```cpp
#include <cassert>
#include <iostream>
void processArray(int* arr, int size) {
    assert(arr != nullptr);  // Asserção de depuração
    assert(size > 0);        // Valida a suposição

    // Processar array...
}
// Compilação condicional para saída de depuração
#ifdef DEBUG
    #define DBG_PRINT(x) cout << "DEBUG: " << x << endl
#else
    #define DBG_PRINT(x)
#endif
// Uso
DBG_PRINT("Iniciando função");
```

## Processo de Compilação e Build

### Compilação GCC/G++

Coleção de Compiladores GNU para C++.

```bash
# Compilação básica
g++ -o program main.cpp
# Com informações de depuração
g++ -g -o program main.cpp
# Níveis de otimização
g++ -O2 -o program main.cpp
# Múltiplos arquivos fonte
g++ -o program main.cpp utils.cpp math.cpp
# Incluir diretórios adicionais
g++ -I/usr/local/include -o program main.cpp
# Ligar bibliotecas
g++ -o program main.cpp -lm -lpthread
```

### Padrões C++ Modernos

Compilar com versões de padrão C++ específicas.

```bash
# Padrão C++11
g++ -std=c++11 -o program main.cpp
# Padrão C++14
g++ -std=c++14 -o program main.cpp
# Padrão C++17 (recomendado)
g++ -std=c++17 -o program main.cpp
# Padrão C++20 (mais recente)
g++ -std=c++20 -o program main.cpp
# Habilitar todos os avisos
g++ -Wall -Wextra -std=c++17 -o program main.cpp
```

### Noções Básicas de Makefile

Automatizar a compilação com a utilidade make.

```makefile
# Makefile Simples
CXX = g++
CXXFLAGS = -std=c++17 -Wall -g
TARGET = program
SOURCES = main.cpp utils.cpp
$(TARGET): $(SOURCES)
$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES)
clean:
rm -f $(TARGET)
.PHONY: clean
```

## Melhores Práticas e Dicas

### Convenções de Nomenclatura

A nomenclatura consistente torna o código mais legível.

```cpp
// Variáveis e funções: snake_case ou camelCase
int student_count;
int studentCount;
void calculateAverage();
// Constantes: UPPER_CASE
const int MAX_BUFFER_SIZE = 1024;
const double PI = 3.14159;
// Classes: PascalCase
class StudentRecord {
    // Variáveis membro: prefixo com m_ ou sufixo _
    string m_name;
    int age_;

public:
    // Interface pública
    void setName(const string& name);
    string getName() const;
};
```

### Segurança de Memória

Prevenir bugs comuns relacionados à memória.

```cpp
// Usar ponteiros inteligentes em vez de ponteiros brutos
auto ptr = make_unique<int>(42);
auto shared = make_shared<vector<int>>(10);
// Inicializar variáveis
int count = 0;        // Bom
int count;            // Perigoso - não inicializado
// Loops baseados em intervalo são mais seguros
for (const auto& item : container) {
    // Processar item com segurança
}
// Verificar validade do ponteiro
if (ptr != nullptr) {
    // Seguro para desreferenciar
}
```

### Dicas de Desempenho

Escrever código C++ eficiente.

```cpp
// Passar objetos grandes por referência const
void processData(const vector<int>& data) {
    // Evitar copiar objetos grandes
}
// Usar pré-incremento para iteradores
for (auto it = vec.begin(); it != vec.end(); ++it) {
    // ++it é frequentemente mais rápido que it++
}
// Reservar capacidade do vetor quando o tamanho é conhecido
vector<int> numbers;
numbers.reserve(1000); // Evitar realocações
// Usar emplace em vez de push para objetos
vector<string> words;
words.emplace_back("Hello"); // Construir no local
words.push_back(string("World")); // Construir e depois copiar
```

### Organização do Código

Estruturar o código para manutenção.

```cpp
// Arquivo de cabeçalho (utils.h)
#ifndef UTILS_H
#define UTILS_H
class MathUtils {
public:
    static double calculateArea(double radius);
    static int fibonacci(int n);
};
#endif // UTILS_H
// Arquivo de implementação (utils.cpp)
#include "utils.h"
#include <cmath>
double MathUtils::calculateArea(double radius) {
    return M_PI * radius * radius;
}
// Usar funções membro const sempre que possível
double getRadius() const { return radius; }
```

## Links Relevantes

- <router-link to="/c-programming">Folha de Dicas de Programação C</router-link>
- <router-link to="/java">Folha de Dicas de Java</router-link>
- <router-link to="/python">Folha de Dicas de Python</router-link>
- <router-link to="/javascript">Folha de Dicas de JavaScript</router-link>
- <router-link to="/golang">Folha de Dicas de Golang</router-link>
- <router-link to="/linux">Folha de Dicas de Linux</router-link>
- <router-link to="/shell">Folha de Dicas de Shell</router-link>
- <router-link to="/devops">Folha de Dicas de DevOps</router-link>

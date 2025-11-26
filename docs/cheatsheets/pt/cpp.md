---
title: 'Folha de Cola C++'
description: 'Aprenda C++ com nossa folha de cola abrangente cobrindo comandos essenciais, conceitos e melhores práticas.'
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
    cout << "Olá, Mundo!" << endl;
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

### Saída Básica

Exibir texto e variáveis no console.

```cpp
cout << "Olá" << endl;
cout << "Valor: " << 42 << endl;
// Múltiplos valores em uma linha
cout << "Nome: " << nome << ", Idade: " << idade << endl;
```

### Entrada Básica

Ler entrada do usuário do console.

```cpp
int idade;
string nome;
cin >> idade;
cin >> nome;
// Ler linha inteira com espaços
getline(cin, nome);
```

## Tipos de Dados e Variáveis

### Tipos Primitivos

Tipos de dados básicos para armazenar diferentes tipos de valores.

```cpp
// Tipos inteiros
int idade = 25;
short num_pequeno = 100;
long num_grande = 1000000L;
long long num_enorme = 9223372036854775807LL;
// Tipos de ponto flutuante
float preco = 19.99f;
double preciso = 3.14159265359;
// Caractere e booleano
char nota = 'A';
bool eh_valido = true;
```

### String e Arrays

Tipos de dados de texto e coleção.

```cpp
// Strings
string nome = "John Doe";
string str_vazia;
// Arrays
int numeros[5] = {1, 2, 3, 4, 5};
int matriz[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// Arrays dinâmicos (vetores)
vector<int> array_dinamico = {10, 20, 30};
vector<string> nomes(5); // Tamanho 5, strings vazias
```

### Constantes e Auto

Valores imutáveis e dedução automática de tipo.

```cpp
// Constantes
const int TAMANHO_MAX = 100;
const double PI = 3.14159;
// Palavra-chave Auto (C++11+)
auto x = 42;        // int
auto y = 3.14;      // double
auto nome = "John"; // const char*
// Alias de tipo
typedef unsigned int uint;
using real = double;
```

## Estruturas de Fluxo de Controle

### Declarações Condicionais

Tomar decisões com base em condições.

```cpp
// Declaração If-else
if (idade >= 18) {
    cout << "Adulto" << endl;
} else if (idade >= 13) {
    cout << "Adolescente" << endl;
} else {
    cout << "Criança" << endl;
}
// Operador Ternário
string status = (idade >= 18) ? "Adulto" : "Menor";
// Declaração Switch
switch (nota) {
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
vector<int> numeros = {1, 2, 3, 4, 5};
for (int num : numeros) {
    cout << num << " ";
}
// Auto com loop baseado em intervalo
for (auto& item : container) {
    // Processar item
}
```

### Loops While

Iteração baseada em condição.

```cpp
// Loop While
int contador = 0;
while (contador < 5) {
    cout << contador << endl;
    contador++;
}
// Loop Do-while (executa pelo menos uma vez)
int entrada;
do {
    cout << "Digite um número (0 para sair): ";
    cin >> entrada;
} while (entrada != 0);
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
int somar(int a, int b);
void imprimirMensagem(string msg);
// Definição de função
int somar(int a, int b) {
    return a + b;
}
void imprimirMensagem(string msg) {
    cout << msg << endl;
}
// Chamada de função
int resultado = somar(5, 3);
imprimirMensagem("Olá, funções!");
```

### Sobrecarga de Função (Function Overloading)

Múltiplas funções com o mesmo nome.

```cpp
// Diferentes tipos de parâmetros
int multiplicar(int a, int b) {
    return a * b;
}
double multiplicar(double a, double b) {
    return a * b;
}
// Diferente número de parâmetros
int multiplicar(int a, int b, int c) {
    return a * b * c;
}
```

### Parâmetros Padrão

Fornecer valores padrão para parâmetros de função.

```cpp
void saudar(string nome, string saudacao = "Olá") {
    cout << saudacao << ", " << nome << "!" << endl;
}
// Chamadas de função
saudar("Alice");              // Usa o padrão "Olá"
saudar("Bob", "Bom dia"); // Usa saudação personalizada
```

### Passagem por Referência

Modificar variáveis através de parâmetros de função.

```cpp
// Passagem por valor (cópia)
void mudarValor(int x) {
    x = 100; // Variável original inalterada
}
// Passagem por referência
void mudarReferencia(int& x) {
    x = 100; // Variável original modificada
}
// Referência const (somente leitura, eficiente)
void processarDadosGrandes(const vector<int>& dados) {
    // Pode ler dados, mas não modificar
}
```

## Programação Orientada a Objetos

### Definição de Classe

Definir tipos de dados personalizados com atributos e métodos.

```cpp
class Retangulo {
private:
    double largura, altura;
public:
    // Construtor
    Retangulo(double l, double a) : largura(l), altura(a) {}

    // Construtor padrão
    Retangulo() : largura(0), altura(0) {}

    // Funções membro
    double area() const {
        return largura * altura;
    }

    void setDimensões(double l, double a) {
        largura = l;
        altura = a;
    }

    // Funções getter
    double getLargura() const { return largura; }
    double getAltura() const { return altura; }
};
```

### Criação e Uso de Objeto

Instanciar e usar objetos de classe.

```cpp
// Criar objetos
Retangulo rect1(5.0, 3.0);
Retangulo rect2; // Construtor padrão
// Usar funções membro
cout << "Área: " << rect1.area() << endl;
rect2.setDimensões(4.0, 2.0);
// Alocação dinâmica
Retangulo* rect3 = new Retangulo(6.0, 4.0);
cout << rect3->area() << endl;
delete rect3; // Limpar memória
```

### Herança

Criar classes especializadas a partir de classes base.

```cpp
class Forma {
protected:
    string cor;

public:
    Forma(string c) : cor(c) {}
    virtual double area() const = 0; // Virtual pura
    string getColor() const { return cor; }
};
class Circulo : public Forma {
private:
    double raio;

public:
    Circulo(double r, string c) : Forma(c), raio(r) {}

    double area() const override {
        return 3.14159 * raio * raio;
    }
};
```

### Polimorfismo

Usar ponteiros de classe base para acessar objetos derivados.

```cpp
// Funções virtuais e polimorfismo
vector<Forma*> formas;
formas.push_back(new Circulo(5.0, "vermelho"));
formas.push_back(new Retangulo(4.0, 6.0));
for (Forma* forma : formas) {
    cout << "Área: " << forma->area() << endl;
    // Chama o método da classe derivada apropriada
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
int* array_grande = new(nothrow) int[1000000];
if (array_grande == nullptr) {
    cout << "Falha na alocação!" << endl;
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
// Variações Const
const int* ptr1 = &x;    // Não pode mudar o valor
int* const ptr2 = &x;    // Não pode mudar o endereço
const int* const ptr3 = &x; // Não pode mudar nenhum dos dois
```

### Pilha (Stack) vs Heap

Estratégias de alocação de memória.

```cpp
// Alocação na Pilha (automática)
int var_pilha = 42;
int array_pilha[100];
// Alocação no Heap (dinâmica)
int* heap_var = new int(42);
int* heap_array = new int[100];
// Objetos da pilha são limpos automaticamente
// Objetos do heap devem ser deletados manualmente
delete heap_var;
delete[] heap_array;
```

## Standard Template Library (STL)

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
string texto = "Olá";
texto += " Mundo";         // Concatenação
texto.append("!");         // Anexar
cout << texto.substr(0, 5) << endl; // Substring
texto.replace(6, 5, "C++"); // Substituir "Mundo" por "C++"
```

### Contêineres: Map e Set

Contêineres associativos para pares chave-valor e elementos únicos.

```cpp
#include <map>
#include <set>
// Map (pares chave-valor)
map<string, int> idades;
idades["Alice"] = 25;
idades["Bob"] = 30;
idades.insert({"Charlie", 35});
// Set (elementos únicos)
set<int> nums_unicos = {3, 1, 4, 1, 5, 9};
nums_unicos.insert(2);
nums_unicos.erase(1);
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

Navegar por contêineres de forma eficiente.

```cpp
vector<string> palavras = {"olá", "mundo", "cpp"};
// Tipos de iterador
vector<string>::iterator it;
auto it2 = words.begin(); // Auto C++11
// Iterar pelo contêiner
for (it = words.begin(); it != words.end(); ++it) {
    cout << *it << " ";
}
// Loop baseado em intervalo (preferido)
for (const auto& palavra : palavras) {
    cout << palavra << " ";
}
```

## Operações de Entrada/Saída

### Entrada de Arquivo: Leitura de Arquivos

Ler dados de arquivos de texto.

```cpp
#include <fstream>
#include <sstream>
// Ler arquivo inteiro
ifstream arquivo("dados.txt");
if (arquivo.is_open()) {
    string linha;
    while (getline(arquivo, linha)) {
        cout << linha << endl;
    }
    arquivo.close();
}
// Ler palavra por palavra
ifstream arquivo2("numeros.txt");
int numero;
while (arquivo2 >> numero) {
    cout << numero << " ";
}
// Leitura com verificação de erro
if (!arquivo.good()) {
    cerr << "Erro ao ler o arquivo!" << endl;
}
```

### Processamento de Fluxo de String (String Stream)

Analisar e manipular strings como fluxos.

```cpp
#include <sstream>
// Analisar valores separados por vírgula
string dados = "maçã,banana,cereja";
stringstream ss(dados);
string item;
vector<string> frutas;
while (getline(ss, item, ',')) {
    frutas.push_back(item);
}
// Converter strings para números
string num_str = "123";
int num = stoi(num_str);
double d = stod("3.14159");
string de_volta_para_str = to_string(num);
```

### Saída de Arquivo: Escrita de Arquivos

Escrever dados em arquivos de texto.

```cpp
// Escrever em arquivo
ofstream saida_arquivo("saida.txt");
if (saida_arquivo.is_open()) {
    saida_arquivo << "Olá, arquivo!" << endl;
    saida_arquivo << "Número: " << 42 << endl;
    saida_arquivo.close();
}
// Anexar a arquivo existente
ofstream arquivo_anexar("log.txt", ios::app);
arquivo_anexar << "Nova entrada de log" << endl;
// Escrever vetor em arquivo
vector<int> numeros = {1, 2, 3, 4, 5};
ofstream num_arquivo("numeros.txt");
for (int num : numeros) {
    num_arquivo << num << " ";
}
```

### Formatação de Fluxo

Controlar o formato e a precisão da saída.

```cpp
#include <iomanip>
double pi = 3.14159265;
cout << fixed << setprecision(2) << pi << endl; // 3.14
cout << setw(10) << "Direita" << endl;          // Alinhado à direita
cout << left << setw(10) << "Esquerda" << endl;     // Alinhado à esquerda
cout << hex << 255 << endl;                    // Hexadecimal: ff
```

## Tratamento de Erros

### Blocos Try-Catch

Lidar com exceções que podem ocorrer durante a execução.

```cpp
try {
    int resultado = 10 / 0; // Isso pode lançar uma exceção
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
class ExcecaoPersonalizada : public exception {
    string mensagem;
public:
    ExcecaoPersonalizada(const string& msg) : mensagem(msg) {}
    const char* what() const noexcept override {
        return mensagem.c_str();
    }
};
// Função que lança exceção
void validarIdade(int idade) {
    if (idade < 0 || idade > 150) {
        throw ExcecaoPersonalizada("Faixa de idade inválida!");
    }
}
// Uso
try {
    validarIdade(-5);
} catch (const ExcecaoPersonalizada& e) {
    cout << e.what() << endl;
}
```

### Padrão RAII

Aquisição de Recurso é Inicialização para gerenciamento seguro de recursos.

```cpp
// RAII com ponteiros inteligentes
{
    unique_ptr<int[]> arr = make_unique<int[]>(1000);
    // Array deletado automaticamente ao sair do escopo
}
// RAII com manipulação de arquivos
{
    ifstream arquivo("dados.txt");
    // Arquivo fechado automaticamente ao sair do escopo
    if (arquivo.is_open()) {
        // Processar arquivo
    }
}
// Classe RAII personalizada
class ManipuladorArquivo {
    FILE* arquivo;
public:
    ManipuladorArquivo(const char* nome_arquivo) {
        arquivo = fopen(nome_arquivo, "r");
    }
    ~ManipuladorArquivo() {
        if (arquivo) fclose(arquivo);
    }
    FILE* get() { return arquivo; }
};
```

### Asserções e Depuração (Debugging)

Depurar e validar suposições do programa.

```cpp
#include <cassert>
#include <iostream>
void processarArray(int* arr, int tamanho) {
    assert(arr != nullptr);  // Asserção de depuração
    assert(tamanho > 0);        // Valida a suposição

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

GNU Compiler Collection para C++.

```bash
# Compilação básica
g++ -o programa main.cpp
# Com informações de depuração
g++ -g -o programa main.cpp
# Níveis de otimização
g++ -O2 -o programa main.cpp
# Múltiplos arquivos fonte
g++ -o programa main.cpp utils.cpp math.cpp
# Incluir diretórios adicionais
g++ -I/usr/local/include -o programa main.cpp
# Ligar bibliotecas
g++ -o programa main.cpp -lm -lpthread
```

### Padrões C++ Modernos

Compilar com versões de padrão C++ específicas.

```bash
# Padrão C++11
g++ -std=c++11 -o programa main.cpp
# Padrão C++14
g++ -std=c++14 -o programa main.cpp
# Padrão C++17 (recomendado)
g++ -std=c++17 -o programa main.cpp
# Padrão C++20 (mais recente)
g++ -std=c++20 -o programa main.cpp
# Habilitar todos os avisos
g++ -Wall -Wextra -std=c++17 -o programa main.cpp
```

### Noções Básicas de Makefile

Automatizar a compilação com o utilitário make.

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
int contagem_alunos;
int contagemAlunos;
void calcularMedia();
// Constantes: UPPER_CASE
const int TAMANHO_MAX_BUFFER = 1024;
const double PI = 3.14159;
// Classes: PascalCase
class RegistroEstudante {
    // Variáveis membro: prefixo com m_ ou sufixo _
    string m_nome;
    int idade_;

public:
    // Interface pública
    void setNome(const string& nome);
    string getNome() const;
};
```

### Segurança de Memória

Prevenir bugs comuns relacionados à memória.

```cpp
// Usar ponteiros inteligentes em vez de ponteiros brutos
auto ptr = make_unique<int>(42);
auto shared = make_shared<vector<int>>(10);
// Inicializar variáveis
int contador = 0;        // Bom
int contador;            // Perigoso - não inicializado
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
void processarDados(const vector<int>& dados) {
    // Evitar copiar objetos grandes
}
// Usar pré-incremento para iteradores
for (auto it = vec.begin(); it != vec.end(); ++it) {
    // ++it é frequentemente mais rápido que it++
}
// Reservar capacidade do vetor quando o tamanho é conhecido
vector<int> numeros;
numeros.reserve(1000); // Evitar realocações
// Usar emplace em vez de push para objetos
vector<string> palavras;
palavras.emplace_back("Olá"); // Constrói no local
palavras.push_back(string("Mundo")); // Constrói e depois copia
```

### Organização do Código

Estruturar o código para manutenção.

```cpp
// Arquivo de cabeçalho (utils.h)
#ifndef UTILS_H
#define UTILS_H
class UtilitariosMatematicos {
public:
    static double calcularArea(double raio);
    static int fibonacci(int n);
};
#endif // UTILS_H
// Arquivo de implementação (utils.cpp)
#include "utils.h"
#include <cmath>
double UtilitariosMatematicos::calcularArea(double raio) {
    return M_PI * raio * raio;
}
// Usar funções membro const quando possível
double getRaio() const { return raio; }
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

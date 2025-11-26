---
title: 'Hoja de Trucos de C++'
description: 'Aprenda C++ con nuestra hoja de trucos completa que cubre comandos esenciales, conceptos y mejores prácticas.'
pdfUrl: '/cheatsheets/pdf/cpp-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de C++
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/cpp">Aprende C++ con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende programación C++ a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de C++ que cubren sintaxis esencial, programación orientada a objetos, contenedores STL, gestión de memoria y técnicas avanzadas. Domina las potentes características de C++ para construir aplicaciones de alto rendimiento y software de sistemas.
</base-disclaimer-content>
</base-disclaimer>

## Sintaxis Básica y Estructura

### Programa "Hola Mundo"

Estructura básica de un programa C++.

```cpp
#include <iostream>
using namespace std;
int main() {
    cout << "Hola, Mundo!" << endl;
    return 0;
}
```

### Cabeceras y Espacios de Nombres

Incluir librerías y gestionar espacios de nombres.

```cpp
#include <iostream>  // Flujo de entrada/salida
#include <vector>    // Arrays dinámicos
#include <string>    // Clase string
#include <algorithm> // Algoritmos STL
using namespace std;
// O especificar individualmente:
// using std::cout;
// using std::cin;
```

### Comentarios

Comentarios de una sola línea y de múltiples líneas.

```cpp
// Comentario de una sola línea
/*
Comentario
de múltiples líneas
*/
// TODO: Implementar funcionalidad
/* FIXME: Error en esta sección */
```

### Función Main

Punto de entrada del programa con valores de retorno.

```cpp
int main() {
    // Código del programa aquí
    return 0;  // Éxito
}
int main(int argc, char* argv[]) {
    // argc: número de argumentos
    // argv: valores de los argumentos (línea de comandos)
    return 0;
}
```

### Salida Básica

Mostrar texto y variables en la consola.

```cpp
cout << "Hola" << endl;
cout << "Valor: " << 42 << endl;
// Múltiples valores en una línea
cout << "Nombre: " << name << ", Edad: " << age << endl;
```

### Entrada Básica

Leer la entrada del usuario desde la consola.

```cpp
int age;
string name;
cin >> age;
cin >> name;
// Leer línea completa con espacios
getline(cin, name);
```

## Tipos de Datos y Variables

### Tipos Primitivos

Tipos de datos básicos para almacenar diferentes clases de valores.

```cpp
// Tipos enteros
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// Tipos de punto flotante
float price = 19.99f;
double precise = 3.14159265359;
// Carácter y booleano
char grade = 'A';
bool is_valid = true;
```

### String y Arrays

Tipos de datos de texto y colección.

```cpp
// Strings
string name = "John Doe";
string empty_str;
// Arrays
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// Arrays dinámicos (vectores)
vector<int> dynamic_array = {10, 20, 30};
vector<string> names(5); // Tamaño 5, strings vacíos
```

### Constantes y Auto

Valores inmutables y deducción automática de tipos.

```cpp
// Constantes
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Palabra clave Auto (C++11+)
auto x = 42;        // int
auto y = 3.14;      // double
auto name = "John"; // const char*
// Alias de tipo
typedef unsigned int uint;
using real = double;
```

## Estructuras de Control de Flujo

### Sentencias Condicionales

Tomar decisiones basadas en condiciones.

```cpp
// Sentencia If-else
if (age >= 18) {
    cout << "Adulto" << endl;
} else if (age >= 13) {
    cout << "Adolescente" << endl;
} else {
    cout << "Niño" << endl;
}
// Operador ternario
string status = (age >= 18) ? "Adulto" : "Menor";
// Sentencia Switch
switch (grade) {
    case 'A':
        cout << "¡Excelente!" << endl;
        break;
    case 'B':
        cout << "¡Buen trabajo!" << endl;
        break;
    default:
        cout << "¡Sigue intentándolo!" << endl;
}
```

### Bucles For

Iterar con bucles basados en contadores.

```cpp
// Bucle for tradicional
for (int i = 0; i < 10; i++) {
    cout << i << " ";
}
// Bucle for basado en rango (C++11+)
vector<int> numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    cout << num << " ";
}
// Auto con bucle basado en rango
for (auto& item : container) {
    // Procesar item
}
```

### Bucles While

Iteración basada en condiciones.

```cpp
// Bucle While
int count = 0;
while (count < 5) {
    cout << count << endl;
    count++;
}
// Bucle Do-while (ejecuta al menos una vez)
int input;
do {
    cout << "Introduce un número (0 para salir): ";
    cin >> input;
} while (input != 0);
```

### Control de Bucles

Declaraciones break y continue.

```cpp
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // Saltar iteración
    }
    if (i == 7) {
        break;    // Salir del bucle
    }
    cout << i << " ";
}
// Bucles anidados con break etiquetado
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // Rompe solo el bucle interno
        cout << i << "," << j << " ";
    }
}
```

## Funciones

### Declaración y Definición de Funciones

Crear bloques de código reutilizables.

```cpp
// Declaración de función (prototipo)
int add(int a, int b);
void printMessage(string msg);
// Definición de función
int add(int a, int b) {
    return a + b;
}
void printMessage(string msg) {
    cout << msg << endl;
}
// Llamada a función
int result = add(5, 3);
printMessage("¡Hola, funciones!");
```

### Sobrecarga de Funciones

Múltiples funciones con el mismo nombre.

```cpp
// Diferentes tipos de parámetros
int multiply(int a, int b) {
    return a * b;
}
double multiply(double a, double b) {
    return a * b;
}
// Diferente número de parámetros
int multiply(int a, int b, int c) {
    return a * b * c;
}
```

### Parámetros Predeterminados

Proporcionar valores predeterminados para los parámetros de la función.

```cpp
void greet(string name, string greeting = "Hola") {
    cout << greeting << ", " << name << "!" << endl;
}
// Llamadas a función
greet("Alicia");              // Usa el valor predeterminado "Hola"
greet("Beto", "Buenos días"); // Usa el saludo personalizado
```

### Pasar por Referencia

Modificar variables a través de parámetros de función.

```cpp
// Pasar por valor (copia)
void changeValue(int x) {
    x = 100; // La variable original no cambia
}
// Pasar por referencia
void changeReference(int& x) {
    x = 100; // La variable original se modifica
}
// Referencia constante (solo lectura, eficiente)
void processLargeData(const vector<int>& data) {
    // Se puede leer data pero no modificarla
}
```

## Programación Orientada a Objetos

### Definición de Clase

Definir tipos de datos personalizados con atributos y métodos.

```cpp
class Rectangle {
private:
    double width, height;
public:
    // Constructor
    Rectangle(double w, double h) : width(w), height(h) {}

    // Constructor por defecto
    Rectangle() : width(0), height(0) {}

    // Funciones miembro
    double area() const {
        return width * height;
    }

    void setDimensions(double w, double h) {
        width = w;
        height = h;
    }

    // Funciones getter
    double getWidth() const { return width; }
    double getHeight() const { return height; }
};
```

### Creación y Uso de Objetos

Instanciar y utilizar objetos de clase.

```cpp
// Crear objetos
Rectangle rect1(5.0, 3.0);
Rectangle rect2; // Constructor por defecto
// Usar funciones miembro
cout << "Área: " << rect1.area() << endl;
rect2.setDimensions(4.0, 2.0);
// Asignación dinámica
Rectangle* rect3 = new Rectangle(6.0, 4.0);
cout << rect3->area() << endl;
delete rect3; // Limpiar memoria
```

### Herencia

Crear clases especializadas a partir de clases base.

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

Usar punteros de clase base para acceder a objetos derivados.

```cpp
// Funciones virtuales y polimorfismo
vector<Shape*> shapes;
shapes.push_back(new Circle(5.0, "rojo"));
shapes.push_back(new Rectangle(4.0, 6.0));
for (Shape* shape : shapes) {
    cout << "Área: " << shape->area() << endl;
    // Llama al método de la clase derivada apropiada
}
```

## Gestión de Memoria

### Asignación Dinámica de Memoria

Asignar y liberar memoria en tiempo de ejecución.

```cpp
// Objeto único
int* ptr = new int(42);
cout << *ptr << endl;
delete ptr;
ptr = nullptr;
// Asignación de array
int* arr = new int[10];
for (int i = 0; i < 10; i++) {
    arr[i] = i * i;
}
delete[] arr;
// Comprobar fallo de asignación
int* large_array = new(nothrow) int[1000000];
if (large_array == nullptr) {
    cout << "¡Asignación fallida!" << endl;
}
```

### Punteros Inteligentes (C++11+)

Gestión automática de memoria con RAII.

```cpp
#include <memory>
// unique_ptr (propiedad exclusiva)
unique_ptr<int> ptr1 = make_unique<int>(42);
unique_ptr<int> ptr2 = move(ptr1); // Transferir propiedad
// shared_ptr (propiedad compartida)
shared_ptr<int> sptr1 = make_shared<int>(100);
shared_ptr<int> sptr2 = sptr1; // Compartir propiedad
cout << sptr1.use_count() << endl; // Contador de referencias
```

### Referencias vs Punteros

Dos formas de acceder indirectamente a objetos.

```cpp
int x = 10;
// Referencia (alias)
int& ref = x;  // Debe inicializarse
ref = 20;      // Cambia x a 20
// Puntero
int* ptr = &x; // Apunta a la dirección de x
*ptr = 30;     // Desreferenciar y cambiar x
ptr = nullptr; // Puede apuntar a nada
// Variaciones const
const int* ptr1 = &x;    // No se puede cambiar el valor
int* const ptr2 = &x;    // No se puede cambiar la dirección
const int* const ptr3 = &x; // No se puede cambiar ninguno
```

### Pila vs Montón (Stack vs Heap)

Estrategias de asignación de memoria.

```cpp
// Asignación en Pila (automática)
int stack_var = 42;
int stack_array[100];
// Asignación en Montón (dinámica)
int* heap_var = new int(42);
int* heap_array = new int[100];
// Objetos de pila se limpian automáticamente
// Objetos de montón deben ser eliminados manualmente
delete heap_var;
delete[] heap_array;
```

## Biblioteca Estándar de Plantillas (STL)

### Contenedores: Vector y String

Arrays dinámicos y manipulación de strings.

```cpp
#include <vector>
#include <string>
// Operaciones de Vector
vector<int> nums = {1, 2, 3};
nums.push_back(4);        // Añadir elemento
nums.pop_back();          // Eliminar el último
nums.insert(nums.begin() + 1, 10); // Insertar en posición
nums.erase(nums.begin()); // Eliminar el primero
// Operaciones de String
string text = "Hola";
text += " Mundo";         // Concatenación
text.append("!");         // Añadir al final
cout << text.substr(0, 5) << endl; // Substring
text.replace(6, 5, "C++"); // Reemplazar "Mundo" con "C++"
```

### Contenedores: Map y Set

Contenedores asociativos para pares clave-valor y elementos únicos.

```cpp
#include <map>
#include <set>
// Map (pares clave-valor)
map<string, int> ages;
ages["Alice"] = 25;
ages["Bob"] = 30;
ages.insert({"Charlie", 35});
// Set (elementos únicos)
set<int> unique_nums = {3, 1, 4, 1, 5, 9};
unique_nums.insert(2);
unique_nums.erase(1);
// Ordenado automáticamente: {2, 3, 4, 5, 9}
```

### Algoritmos

Algoritmos STL para operaciones comunes.

```cpp
#include <algorithm>
vector<int> nums = {64, 34, 25, 12, 22, 11, 90};
// Ordenamiento
sort(nums.begin(), nums.end());
sort(nums.rbegin(), nums.rend()); // Ordenamiento inverso
// Búsqueda
auto it = find(nums.begin(), nums.end(), 25);
if (it != nums.end()) {
    cout << "Encontrado en la posición: " << it - nums.begin();
}
// Otros algoritmos útiles
reverse(nums.begin(), nums.end());
int max_val = *max_element(nums.begin(), nums.end());
int count = count_if(nums.begin(), nums.end(),
                    [](int x) { return x > 50; });
```

### Iteradores

Navegar por los contenedores de manera eficiente.

```cpp
vector<string> words = {"hola", "mundo", "cpp"};
// Tipos de iterador
vector<string>::iterator it;
auto it2 = words.begin(); // C++11 auto
// Iterar a través del contenedor
for (it = words.begin(); it != words.end(); ++it) {
    cout << *it << " ";
}
// Bucle basado en rango (preferido)
for (const auto& word : words) {
    cout << word << " ";
}
```

## Operaciones de Entrada/Salida

### Entrada de Archivos: Lectura de Archivos

Leer datos desde archivos de texto.

```cpp
#include <fstream>
#include <sstream>
// Leer archivo completo
ifstream file("data.txt");
if (file.is_open()) {
    string line;
    while (getline(file, line)) {
        cout << line << endl;
    }
    file.close();
}
// Leer palabra por palabra
ifstream file2("numbers.txt");
int number;
while (file2 >> number) {
    cout << number << " ";
}
// Lectura con comprobación de errores
if (!file.good()) {
    cerr << "¡Error al leer el archivo!" << endl;
}
```

### Procesamiento de Flujo de Cadenas (String Stream)

Analizar y manipular cadenas como flujos.

```cpp
#include <sstream>
// Analizar valores separados por comas
string data = "manzana,banana,cereza";
stringstream ss(data);
string item;
vector<string> fruits;
while (getline(ss, item, ',')) {
    fruits.push_back(item);
}
// Convertir strings a números
string num_str = "123";
int num = stoi(num_str);
double d = stod("3.14159");
string back_to_str = to_string(num);
```

### Salida de Archivos: Escritura de Archivos

Escribir datos en archivos de texto.

```cpp
// Escribir en archivo
ofstream outfile("output.txt");
if (outfile.is_open()) {
    outfile << "¡Hola, archivo!" << endl;
    outfile << "Número: " << 42 << endl;
    outfile.close();
}
// Añadir a archivo existente
ofstream appendfile("log.txt", ios::app);
appendfile << "Nueva entrada de registro" << endl;
// Escribir vector en archivo
vector<int> numbers = {1, 2, 3, 4, 5};
ofstream numfile("numbers.txt");
for (int num : numbers) {
    numfile << num << " ";
}
```

### Formato de Flujo

Controlar el formato y la precisión de la salida.

```cpp
#include <iomanip>
double pi = 3.14159265;
cout << fixed << setprecision(2) << pi << endl; // 3.14
cout << setw(10) << "Derecha" << endl;          // Alineado a la derecha
cout << left << setw(10) << "Izquierda" << endl;     // Alineado a la izquierda
cout << hex << 255 << endl;                    // Hexadecimal: ff
```

## Manejo de Errores

### Bloques Try-Catch

Manejar excepciones que pueden ocurrir durante la ejecución.

```cpp
try {
    int result = 10 / 0; // Esto podría lanzar una excepción
    vector<int> vec(5);
    vec.at(10) = 100;    // Acceso fuera de límites

} catch (const exception& e) {
    cout << "Excepción capturada: " << e.what() << endl;
} catch (...) {
    cout << "Excepción desconocida capturada!" << endl;
}
// Tipos de excepción específicos
try {
    string str = "abc";
    int num = stoi(str); // Lanza invalid_argument
} catch (const invalid_argument& e) {
    cout << "Argumento inválido: " << e.what() << endl;
} catch (const out_of_range& e) {
    cout << "Fuera de rango: " << e.what() << endl;
}
```

### Lanzamiento de Excepciones Personalizadas

Crear y lanzar sus propias excepciones.

```cpp
// Clase de excepción personalizada
class CustomException : public exception {
    string message;
public:
    CustomException(const string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};
// Función que lanza excepción
void validateAge(int age) {
    if (age < 0 || age > 150) {
        throw CustomException("¡Rango de edad inválido!");
    }
}
// Uso
try {
    validateAge(-5);
} catch (const CustomException& e) {
    cout << e.what() << endl;
}
```

### Patrón RAII

Adquisición de Recursos Es Inicialización para una gestión segura de recursos.

```cpp
// RAII con punteros inteligentes
{
    unique_ptr<int[]> arr = make_unique<int[]>(1000);
    // El array se elimina automáticamente al salir del ámbito
}
// RAII con manejo de archivos
{
    ifstream file("data.txt");
    // El archivo se cierra automáticamente al salir del ámbito
    if (file.is_open()) {
        // Procesar archivo
    }
}
// Clase RAII personalizada
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

### Asertos y Depuración

Depurar y validar suposiciones del programa.

```cpp
#include <cassert>
#include <iostream>
void processArray(int* arr, int size) {
    assert(arr != nullptr);  // Aserto de depuración
    assert(size > 0);        // Valida la suposición

    // Procesar array...
}
// Compilación condicional para salida de depuración
#ifdef DEBUG
    #define DBG_PRINT(x) cout << "DEBUG: " << x << endl
#else
    #define DBG_PRINT(x)
#endif
// Uso
DBG_PRINT("Iniciando función");
```

## Proceso de Compilación y Construcción

### Compilación GCC/G++

Colección de Compiladores GNU para C++.

```bash
# Compilación básica
g++ -o programa main.cpp
# Con información de depuración
g++ -g -o programa main.cpp
# Niveles de optimización
g++ -O2 -o programa main.cpp
# Múltiples archivos fuente
g++ -o programa main.cpp utils.cpp math.cpp
# Incluir directorios adicionales
g++ -I/usr/local/include -o programa main.cpp
# Enlazar librerías
g++ -o programa main.cpp -lm -lpthread
```

### Estándares de C++ Moderno

Compilar con versiones específicas del estándar C++.

```bash
# Estándar C++11
g++ -std=c++11 -o programa main.cpp
# Estándar C++14
g++ -std=c++14 -o programa main.cpp
# Estándar C++17 (recomendado)
g++ -std=c++17 -o programa main.cpp
# Estándar C++20 (más reciente)
g++ -std=c++20 -o programa main.cpp
# Habilitar todas las advertencias
g++ -Wall -Wextra -std=c++17 -o programa main.cpp
```

### Conceptos Básicos de Makefile

Automatizar la compilación con la utilidad make.

```makefile
# Makefile simple
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

## Mejores Prácticas y Consejos

### Convenciones de Nomenclatura

La nomenclatura consistente hace que el código sea más legible.

```cpp
// Variables y funciones: snake_case o camelCase
int student_count;
int studentCount;
void calculateAverage();
// Constantes: UPPER_CASE
const int MAX_BUFFER_SIZE = 1024;
const double PI = 3.14159;
// Clases: PascalCase
class StudentRecord {
    // Variables miembro: prefijo con m_ o sufijo _
    string m_name;
    int age_;

public:
    // Interfaz pública
    void setName(const string& name);
    string getName() const;
};
```

### Seguridad de Memoria

Prevenir errores comunes relacionados con la memoria.

```cpp
// Usar punteros inteligentes en lugar de punteros brutos
auto ptr = make_unique<int>(42);
auto shared = make_shared<vector<int>>(10);
// Inicializar variables
int count = 0;        // Bien
int count;            // Peligroso - no inicializado
// Los bucles basados en rango son más seguros
for (const auto& item : container) {
    // Procesar item de forma segura
}
// Comprobar validez del puntero
if (ptr != nullptr) {
    // Seguro para desreferenciar
}
```

### Consejos de Rendimiento

Escribir código C++ eficiente.

```cpp
// Pasar objetos grandes por referencia constante
void processData(const vector<int>& data) {
    // Evitar copiar objetos grandes
}
// Usar pre-incremento para iteradores
for (auto it = vec.begin(); it != vec.end(); ++it) {
    // ++it es a menudo más rápido que it++
}
// Reservar capacidad de vector cuando se conoce el tamaño
vector<int> numbers;
numbers.reserve(1000); // Evitar realocaciones
// Usar emplace en lugar de push para objetos
vector<string> words;
words.emplace_back("Hola"); // Construir in-situ
words.push_back(string("Mundo")); // Construir y luego copiar
```

### Organización del Código

Estructurar el código para su mantenimiento.

```cpp
// Archivo de cabecera (utils.h)
#ifndef UTILS_H
#define UTILS_H
class MathUtils {
public:
    static double calculateArea(double radius);
    static int fibonacci(int n);
};
#endif // UTILS_H
// Archivo de implementación (utils.cpp)
#include "utils.h"
#include <cmath>
double MathUtils::calculateArea(double radius) {
    return M_PI * radius * radius;
}
// Usar funciones miembro const siempre que sea posible
double getRadius() const { return radius; }
```

## Enlaces Relevantes

- <router-link to="/c-programming">Hoja de Trucos de Programación C</router-link>
- <router-link to="/java">Hoja de Trucos de Java</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/golang">Hoja de Trucos de Golang</router-link>
- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>

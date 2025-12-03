---
title: 'C++ Spickzettel | LabEx'
description: 'Lernen Sie C++ Programmierung mit diesem umfassenden Spickzettel. Schnelle Referenz für C++ Syntax, OOP, STL, Templates, Speichermanagement und moderne C++ Features für Softwareentwickler.'
pdfUrl: '/cheatsheets/pdf/cpp-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
C++ Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/cpp">C++ mit praxisnahen Labs lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie die C++-Programmierung durch praxisnahe Labs und reale Szenarien. LabEx bietet umfassende C++-Kurse, die wesentliche Syntax, objektorientierte Programmierung, STL-Container, Speicherverwaltung und fortgeschrittene Techniken abdecken. Meistern Sie die leistungsstarken Funktionen von C++, um Hochleistungsanwendungen und Systemsoftware zu erstellen.
</base-disclaimer-content>
</base-disclaimer>

## Grundlegende Syntax & Struktur

### Hallo Welt Programm

Grundstruktur eines C++-Programms.

```cpp
#include <iostream>
using namespace std;
int main() {
    cout << "Hallo, Welt!" << endl;
    return 0;
}
```

### Header und Namespaces

Bibliotheken einbinden und Namespaces verwalten.

```cpp
#include <iostream>  // Eingabe-/Ausgabestream
#include <vector>    // Dynamische Arrays
#include <string>    // String-Klasse
#include <algorithm> // STL-Algorithmen
using namespace std;
// Oder einzeln angeben:
// using std::cout;
// using std::cin;
```

### Kommentare

Einzeilige und mehrzeilige Kommentare.

```cpp
// Einzeiliger Kommentar
/*
Mehrzeiliger Kommentar
erstreckt sich über mehrere Zeilen
*/
// TODO: Funktion implementieren
/* FIXME: Bug in diesem Abschnitt */
```

### Main Funktion

Einstiegspunkt des Programms mit Rückgabewerten.

```cpp
int main() {
    // Programmcode hier
    return 0;  // Erfolg
}
int main(int argc, char* argv[]) {
    // argc: Argumentanzahl
    // argv: Argumentwerte (Kommandozeile)
    return 0;
}
```

<BaseQuiz id="cpp-main-1" correct="B">
  <template #question>
    Was ist der Unterschied zwischen C- und C++-Ausgabenanweisungen?
  </template>
  
  <BaseQuizOption value="A">Es gibt keinen Unterschied</BaseQuizOption>
  <BaseQuizOption value="B" correct>C verwendet printf(), C++ verwendet cout mit dem << Operator</BaseQuizOption>
  <BaseQuizOption value="C">C++ unterstützt keine Ausgabe</BaseQuizOption>
  <BaseQuizOption value="D">C verwendet cout, C++ verwendet printf</BaseQuizOption>
  
  <BaseQuizAnswer>
    C verwendet <code>printf()</code> aus stdio.h, während C++ <code>cout</code> aus iostream mit dem Stream-Einfügeoperator <code><<</code> verwendet. C++ unterstützt auch printf zur Kompatibilität.
  </BaseQuizAnswer>
</BaseQuiz>

### Einfache Ausgabe

Text und Variablen auf der Konsole anzeigen.

```cpp
cout << "Hallo" << endl;
cout << "Wert: " << 42 << endl;
// Mehrere Werte in einer Zeile
cout << "Name: " << name << ", Alter: " << age << endl;
```

### Einfache Eingabe

Benutzereingaben von der Konsole lesen.

```cpp
int age;
string name;
cin >> age;
cin >> name;
// Ganze Zeile inklusive Leerzeichen lesen
getline(cin, name);
```

## Datentypen & Variablen

### Primitive Typen

Grundlegende Datentypen zur Speicherung verschiedener Wertarten.

```cpp
// Integer-Typen
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// Gleitkommatypen
float price = 19.99f;
double precise = 3.14159265359;
// Zeichen und Boolescher Wert
char grade = 'A';
bool is_valid = true;
```

### String & Arrays

Text- und Sammlungstypen.

```cpp
// Strings
string name = "John Doe";
string empty_str;
// Arrays
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// Dynamische Arrays (Vektoren)
vector<int> dynamic_array = {10, 20, 30};
vector<string> names(5); // Größe 5, leere Strings
```

<BaseQuiz id="cpp-vector-1" correct="B">
  <template #question>
    Was ist der Hauptvorteil von <code>vector</code> gegenüber normalen Arrays in C++?
  </template>
  
  <BaseQuizOption value="A">Vektoren sind schneller</BaseQuizOption>
  <BaseQuizOption value="B" correct>Vektoren können dynamisch in der Größe geändert werden, während Arrays eine feste Größe haben</BaseQuizOption>
  <BaseQuizOption value="C">Vektoren verbrauchen weniger Speicher</BaseQuizOption>
  <BaseQuizOption value="D">Es gibt keinen Vorteil</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>vector</code> ist ein dynamisches Array, das zur Laufzeit wachsen oder schrumpfen kann, im Gegensatz zu normalen Arrays, deren Größe zur Kompilierzeit festgelegt wird. Dies macht Vektoren für viele Anwendungsfälle flexibler.
  </BaseQuizAnswer>
</BaseQuiz>

### Konstanten & Auto

Unveränderliche Werte und automatische Typableitung.

```cpp
// Konstanten
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Auto-Schlüsselwort (C++11+)
auto x = 42;        // int
auto y = 3.14;      // double
auto name = "John"; // const char*
// Typ-Aliase
typedef unsigned int uint;
using real = double;
```

## Kontrollflussstrukturen

### Bedingte Anweisungen

Entscheidungen basierend auf Bedingungen treffen.

```cpp
// If-else-Anweisung
if (age >= 18) {
    cout << "Erwachsen" << endl;
} else if (age >= 13) {
    cout << "Teenager" << endl;
} else {
    cout << "Kind" << endl;
}
// Ternärer Operator
string status = (age >= 18) ? "Erwachsen" : "Minderjährig";
// Switch-Anweisung
switch (grade) {
    case 'A':
        cout << "Ausgezeichnet!" << endl;
        break;
    case 'B':
        cout << "Gut gemacht!" << endl;
        break;
    default:
        cout << "Weiter versuchen!" << endl;
}
```

### For-Schleifen

Iteration mit zählerbasierten Schleifen.

```cpp
// Traditionelle for-Schleife
for (int i = 0; i < 10; i++) {
    cout << i << " ";
}
// Bereichsbasierte for-Schleife (C++11+)
vector<int> numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    cout << num << " ";
}
// Auto mit bereichsbasierter Schleife
for (auto& item : container) {
    // Element verarbeiten
}
```

<BaseQuiz id="cpp-range-for-1" correct="B">
  <template #question>
    Was ist eine bereichsbasierte for-Schleife in C++?
  </template>
  
  <BaseQuizOption value="A">Eine Schleife, die nur mit Arrays funktioniert</BaseQuizOption>
  <BaseQuizOption value="B" correct>Eine Schleife, die automatisch über alle Elemente in einem Container iteriert</BaseQuizOption>
  <BaseQuizOption value="C">Eine Schleife, die ewig läuft</BaseQuizOption>
  <BaseQuizOption value="D">Eine Schleife, die eine manuelle Indexverwaltung erfordert</BaseQuizOption>
  
  <BaseQuizAnswer>
    Bereichsbasierte for-Schleifen (eingeführt in C++11) iterieren automatisch über alle Elemente in einem Container (wie Vektoren, Arrays, Strings), ohne dass die Indizes manuell verwaltet werden müssen. Die Syntax lautet <code>for (auto item : container)</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### While-Schleifen

Zustandsbasierte Iteration.

```cpp
// While-Schleife
int count = 0;
while (count < 5) {
    cout << count << endl;
    count++;
}
// Do-while-Schleife (wird mindestens einmal ausgeführt)
int input;
do {
    cout << "Geben Sie eine Zahl ein (0 zum Beenden): ";
    cin >> input;
} while (input != 0);
```

### Schleifenkontrolle

Break- und Continue-Anweisungen.

```cpp
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // Iteration überspringen
    }
    if (i == 7) {
        break;    // Schleife verlassen
    }
    cout << i << " ";
}
// Geschachtelte Schleifen mit beschriftetem Break
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // Nur innere Schleife beenden
        cout << i << "," << j << " ";
    }
}
```

## Funktionen

### Funktionsdeklaration & Definition

Wiederverwendbare Codeblöcke erstellen.

```cpp
// Funktionsdeklaration (Prototyp)
int add(int a, int b);
void printMessage(string msg);
// Funktionsdefinition
int add(int a, int b) {
    return a + b;
}
void printMessage(string msg) {
    cout << msg << endl;
}
// Funktionsaufruf
int result = add(5, 3);
printMessage("Hallo, Funktionen!");
```

### Funktionsüberladung

Mehrere Funktionen mit demselben Namen.

```cpp
// Unterschiedliche Parametertypen
int multiply(int a, int b) {
    return a * b;
}
double multiply(double a, double b) {
    return a * b;
}
// Unterschiedliche Anzahl von Parametern
int multiply(int a, int b, int c) {
    return a * b * c;
}
```

### Standardparameter

Standardwerte für Funktionsparameter bereitstellen.

```cpp
void greet(string name, string greeting = "Hallo") {
    cout << greeting << ", " << name << "!" << endl;
}
// Funktionsaufrufe
greet("Alice");              // Verwendet Standard "Hallo"
greet("Bob", "Guten Morgen"); // Verwendet benutzerdefinierte Begrüßung
```

### Übergabe per Referenz

Variablen über Funktionsparameter modifizieren.

```cpp
// Übergabe per Wert (Kopie)
void changeValue(int x) {
    x = 100; // Originalvariable unverändert
}
// Übergabe per Referenz
void changeReference(int& x) {
    x = 100; // Originalvariable modifiziert
}
// Konstante Referenz (schreibgeschützt, effizient)
void processLargeData(const vector<int>& data) {
    // Daten lesen, aber nicht modifizieren
}
```

## Objektorientierte Programmierung

### Klassendefinition

Benutzerdefinierte Datentypen mit Attributen und Methoden definieren.

```cpp
class Rectangle {
private:
    double width, height;
public:
    // Konstruktor
    Rectangle(double w, double h) : width(w), height(h) {}

    // Standardkonstruktor
    Rectangle() : width(0), height(0) {}

    // Memberfunktionen
    double area() const {
        return width * height;
    }

    void setDimensions(double w, double h) {
        width = w;
        height = h;
    }

    // Getter-Funktionen
    double getWidth() const { return width; }
    double getHeight() const { return height; }
};
```

### Objekterstellung & Verwendung

Klassenobjekte instanziieren und verwenden.

```cpp
// Objekte erstellen
Rectangle rect1(5.0, 3.0);
Rectangle rect2; // Standardkonstruktor
// Memberfunktionen verwenden
cout << "Fläche: " << rect1.area() << endl;
rect2.setDimensions(4.0, 2.0);
// Dynamische Allokation
Rectangle* rect3 = new Rectangle(6.0, 4.0);
cout << rect3->area() << endl;
delete rect3; // Speicher freigeben
```

### Vererbung

Spezialisierte Klassen aus Basisklassen erstellen.

```cpp
class Shape {
protected:
    string color;

public:
    Shape(string c) : color(c) {}
    virtual double area() const = 0; // Reine virtuelle Funktion
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

### Polymorphismus

Basisklassenzeiger verwenden, um abgeleitete Objekte abzurufen.

```cpp
// Virtuelle Funktionen und Polymorphismus
vector<Shape*> shapes;
shapes.push_back(new Circle(5.0, "rot"));
shapes.push_back(new Rectangle(4.0, 6.0));
for (Shape* shape : shapes) {
    cout << "Fläche: " << shape->area() << endl;
    // Ruft die entsprechende abgeleitete Klassenmethode auf
}
```

## Speicherverwaltung

### Dynamische Speicherzuweisung

Speicher zur Laufzeit zuweisen und freigeben.

```cpp
// Einzelnes Objekt
int* ptr = new int(42);
cout << *ptr << endl;
delete ptr;
ptr = nullptr;
// Array-Zuweisung
int* arr = new int[10];
for (int i = 0; i < 10; i++) {
    arr[i] = i * i;
}
delete[] arr;
// Prüfen auf Zuweisungsfehler
int* large_array = new(nothrow) int[1000000];
if (large_array == nullptr) {
    cout << "Zuweisung fehlgeschlagen!" << endl;
}
```

### Smart Pointers (C++11+)

Automatische Speicherverwaltung mit RAII.

```cpp
#include <memory>
// unique_ptr (exklusives Eigentum)
unique_ptr<int> ptr1 = make_unique<int>(42);
unique_ptr<int> ptr2 = move(ptr1); // Eigentum übertragen
// shared_ptr (geteiltes Eigentum)
shared_ptr<int> sptr1 = make_shared<int>(100);
shared_ptr<int> sptr2 = sptr1; // Eigentum teilen
cout << sptr1.use_count() << endl; // Referenzzähler
```

### Referenzen vs Zeiger

Zwei Wege, um indirekt auf Objekte zuzugreifen.

```cpp
int x = 10;
// Referenz (Alias)
int& ref = x;  // Muss initialisiert werden
ref = 20;      // Ändert x zu 20
// Zeiger
int* ptr = &x; // Zeigt auf die Adresse von x
*ptr = 30;     // Dereferenzieren und x ändern
ptr = nullptr; // Kann auf nichts zeigen
// Const-Varianten
const int* ptr1 = &x;    // Wert kann nicht geändert werden
int* const ptr2 = &x;    // Adresse kann nicht geändert werden
const int* const ptr3 = &x; // Keines von beiden kann geändert werden
```

### Stack vs Heap

Speicherzuweisungsstrategien.

```cpp
// Stack-Zuweisung (automatisch)
int stack_var = 42;
int stack_array[100];
// Heap-Zuweisung (dynamisch)
int* heap_var = new int(42);
int* heap_array = new int[100];
// Stack-Objekte werden automatisch bereinigt
// Heap-Objekte müssen manuell gelöscht werden
delete heap_var;
delete[] heap_array;
```

## Standard Template Library (STL)

### Container: Vector & String

Dynamische Arrays und String-Manipulation.

```cpp
#include <vector>
#include <string>
// Vektor-Operationen
vector<int> nums = {1, 2, 3};
nums.push_back(4);        // Element hinzufügen
nums.pop_back();          // Letztes Element entfernen
nums.insert(nums.begin() + 1, 10); // An Position einfügen
nums.erase(nums.begin()); // Erstes Element entfernen
// String-Operationen
string text = "Hallo";
text += " Welt";         // Konkatenation
text.append("!");         // Anhängen
cout << text.substr(0, 5) << endl; // Substring
text.replace(6, 5, "C++"); // "Welt" durch "C++" ersetzen
```

### Container: Map & Set

Assoziative Container für Schlüssel-Wert-Paare und eindeutige Elemente.

```cpp
#include <map>
#include <set>
// Map (Schlüssel-Wert-Paare)
map<string, int> ages;
ages["Alice"] = 25;
ages["Bob"] = 30;
ages.insert({"Charlie", 35});
// Set (eindeutige Elemente)
set<int> unique_nums = {3, 1, 4, 1, 5, 9};
unique_nums.insert(2);
unique_nums.erase(1);
// Automatisch sortiert: {2, 3, 4, 5, 9}
```

### Algorithmen

STL-Algorithmen für gängige Operationen.

```cpp
#include <algorithm>
vector<int> nums = {64, 34, 25, 12, 22, 11, 90};
// Sortieren
sort(nums.begin(), nums.end());
sort(nums.rbegin(), nums.rend()); // Absteigend sortieren
// Suchen
auto it = find(nums.begin(), nums.end(), 25);
if (it != nums.end()) {
    cout << "Gefunden an Position: " << it - nums.begin();
}
// Andere nützliche Algorithmen
reverse(nums.begin(), nums.end());
int max_val = *max_element(nums.begin(), nums.end());
int count = count_if(nums.begin(), nums.end(),
                    [](int x) { return x > 50; });
```

### Iteratoren

Effiziente Navigation durch Container.

```cpp
vector<string> words = {"hallo", "welt", "cpp"};
// Iteratortypen
vector<string>::iterator it;
auto it2 = words.begin(); // C++11 auto
// Durch Container iterieren
for (it = words.begin(); it != words.end(); ++it) {
    cout << *it << " ";
}
// Bereichsbasierte Schleife (bevorzugt)
for (const auto& word : words) {
    cout << word << " ";
}
```

## Eingabe-/Ausgabeoperationen

### Dateieingabe: Dateien lesen

Daten aus Textdateien lesen.

```cpp
#include <fstream>
#include <sstream>
// Ganze Datei lesen
ifstream file("data.txt");
if (file.is_open()) {
    string line;
    while (getline(file, line)) {
        cout << line << endl;
    }
    file.close();
}
// Wort für Wort lesen
ifstream file2("numbers.txt");
int number;
while (file2 >> number) {
    cout << number << " ";
}
// Mit Fehlerprüfung
if (!file.good()) {
    cerr << "Fehler beim Lesen der Datei!" << endl;
}
```

### String Stream Verarbeitung

Strings als Streams parsen und manipulieren.

```cpp
#include <sstream>
// Kommagetrennte Werte parsen
string data = "apfel,banane,kirsche";
stringstream ss(data);
string item;
vector<string> fruits;
while (getline(ss, item, ',')) {
    fruits.push_back(item);
}
// Strings in Zahlen umwandeln
string num_str = "123";
int num = stoi(num_str);
double d = stod("3.14159");
string back_to_str = to_string(num);
```

### Dateiausgabe: Dateien schreiben

Daten in Textdateien schreiben.

```cpp
// In Datei schreiben
ofstream outfile("output.txt");
if (outfile.is_open()) {
    outfile << "Hallo, Datei!" << endl;
    outfile << "Zahl: " << 42 << endl;
    outfile.close();
}
// An bestehende Datei anhängen
ofstream appendfile("log.txt", ios::app);
appendfile << "Neuer Logeintrag" << endl;
// Vektor in Datei schreiben
vector<int> numbers = {1, 2, 3, 4, 5};
ofstream numfile("numbers.txt");
for (int num : numbers) {
    numfile << num << " ";
}
```

### Stream-Formatierung

Ausgabeformat und Präzision steuern.

```cpp
#include <iomanip>
double pi = 3.14159265;
cout << fixed << setprecision(2) << pi << endl; // 3.14
cout << setw(10) << "Rechts" << endl;          // Rechtsbündig
cout << left << setw(10) << "Links" << endl;     // Linksbündig
cout << hex << 255 << endl;                    // Hexadezimal: ff
```

## Fehlerbehandlung

### Try-Catch-Blöcke

Ausnahmen behandeln, die während der Ausführung auftreten können.

```cpp
try {
    int result = 10 / 0; // Dies könnte eine Ausnahme auslösen
    vector<int> vec(5);
    vec.at(10) = 100;    // Zugriff außerhalb der Grenzen

} catch (const exception& e) {
    cout << "Ausnahme abgefangen: " << e.what() << endl;
} catch (...) {
    cout << "Unbekannte Ausnahme abgefangen!" << endl;
}
// Spezifische Ausnahme-Typen
try {
    string str = "abc";
    int num = stoi(str); // Löst invalid_argument aus
} catch (const invalid_argument& e) {
    cout << "Ungültiges Argument: " << e.what() << endl;
} catch (const out_of_range& e) {
    cout << "Außerhalb des Bereichs: " << e.what() << endl;
}
```

### Benutzerdefinierte Ausnahmen werfen

Eigene Ausnahmen erstellen und auslösen.

```cpp
// Benutzerdefinierte Ausnahme-Klasse
class CustomException : public exception {
    string message;
public:
    CustomException(const string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};
// Funktion, die Ausnahme auslöst
void validateAge(int age) {
    if (age < 0 || age > 150) {
        throw CustomException("Ungültiger Altersbereich!");
    }
}
// Verwendung
try {
    validateAge(-5);
} catch (const CustomException& e) {
    cout << e.what() << endl;
}
```

### RAII-Muster

Resource Acquisition Is Initialization für sicheres Ressourcenmanagement.

```cpp
// RAII mit Smart Pointern
{
    unique_ptr<int[]> arr = make_unique<int[]>(1000);
    // Array wird automatisch gelöscht, wenn es den Gültigkeitsbereich verlässt
}
// RAII mit Dateihandhabung
{
    ifstream file("data.txt");
    // Datei wird automatisch geschlossen, wenn sie den Gültigkeitsbereich verlässt
    if (file.is_open()) {
        // Datei verarbeiten
    }
}
// Benutzerdefinierte RAII-Klasse
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

### Assertions & Debugging

Annahmen des Programms debuggen und validieren.

```cpp
#include <cassert>
#include <iostream>
void processArray(int* arr, int size) {
    assert(arr != nullptr);  // Debug-Assertion
    assert(size > 0);        // Annahme validieren

    // Array verarbeiten...
}
// Bedingte Kompilierung für Debug-Ausgabe
#ifdef DEBUG
    #define DBG_PRINT(x) cout << "DEBUG: " << x << endl
#else
    #define DBG_PRINT(x)
#endif
// Verwendung
DBG_PRINT("Funktion wird gestartet");
```

## Kompilierung & Build-Prozess

### GCC/G++ Kompilierung

GNU Compiler Collection für C++.

```bash
# Einfache Kompilierung
g++ -o program main.cpp
# Mit Debugging-Informationen
g++ -g -o program main.cpp
# Optimierungsstufen
g++ -O2 -o program main.cpp
# Mehrere Quelldateien
g++ -o program main.cpp utils.cpp math.cpp
# Zusätzliche Verzeichnisse einbinden
g++ -I/usr/local/include -o program main.cpp
# Bibliotheken verknüpfen
g++ -o program main.cpp -lm -lpthread
```

### Moderne C++ Standards

Kompilieren mit spezifischen C++-Standardversionen.

```bash
# C++11 Standard
g++ -std=c++11 -o program main.cpp
# C++14 Standard
g++ -std=c++14 -o program main.cpp
# C++17 Standard (empfohlen)
g++ -std=c++17 -o program main.cpp
# C++20 Standard (neueste)
g++ -std=c++20 -o program main.cpp
# Alle Warnungen aktivieren
g++ -Wall -Wextra -std=c++17 -o program main.cpp
```

### Makefile Grundlagen

Kompilierung mit dem make-Dienstprogramm automatisieren.

```makefile
# Einfaches Makefile
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

## Best Practices & Tipps

### Benennungskonventionen

Konsistente Benennung macht Code lesbarer.

```cpp
// Variablen und Funktionen: snake_case oder camelCase
int student_count;
int studentCount;
void calculateAverage();
// Konstanten: UPPER_CASE
const int MAX_BUFFER_SIZE = 1024;
const double PI = 3.14159;
// Klassen: PascalCase
class StudentRecord {
    // Membervariablen: Präfix mit m_ oder Suffix _
    string m_name;
    int age_;

public:
    // Öffentliche Schnittstelle
    void setName(const string& name);
    string getName() const;
};
```

### Speichersicherheit

Häufige speicherbezogene Fehler vermeiden.

```cpp
// Smart Pointer anstelle von Rohzeigern verwenden
auto ptr = make_unique<int>(42);
auto shared = make_shared<vector<int>>(10);
// Variablen initialisieren
int count = 0;        // Gut
int count;            // Gefährlich - nicht initialisiert
// Bereichsbasierte Schleifen sind sicherer
for (const auto& item : container) {
    // Element sicher verarbeiten
}
// Zeigergültigkeit prüfen
if (ptr != nullptr) {
    // Sicher dereferenzierbar
}
```

### Performance-Tipps

Effizienten C++-Code schreiben.

```cpp
// Große Objekte per const Referenz übergeben
void processData(const vector<int>& data) {
    // Kopieren großer Objekte vermeiden
}
// Prä-Inkrement für Iteratoren verwenden
for (auto it = vec.begin(); it != vec.end(); ++it) {
    // ++it ist oft schneller als it++
}
// Vektor-Kapazität reservieren, wenn die Größe bekannt ist
vector<int> numbers;
numbers.reserve(1000); // Neuallokationen vermeiden
// emplace anstelle von push für Objekte verwenden
vector<string> words;
words.emplace_back("Hallo"); // In-Place konstruieren
words.push_back(string("Welt")); // Konstruieren und dann kopieren
```

### Code-Organisation

Code für Wartbarkeit strukturieren.

```cpp
// Header-Datei (utils.h)
#ifndef UTILS_H
#define UTILS_H
class MathUtils {
public:
    static double calculateArea(double radius);
    static int fibonacci(int n);
};
#endif // UTILS_H
// Implementierungsdatei (utils.cpp)
#include "utils.h"
#include <cmath>
double MathUtils::calculateArea(double radius) {
    return M_PI * radius * radius;
}
// Memberfunktionen nach Möglichkeit als const deklarieren
double getRadius() const { return radius; }
```

## Relevante Links

- <router-link to="/c-programming">C Programmierung Spickzettel</router-link>
- <router-link to="/java">Java Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/golang">Golang Spickzettel</router-link>
- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>

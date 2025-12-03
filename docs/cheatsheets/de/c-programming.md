---
title: 'C Programmierung Spickzettel | LabEx'
description: 'C-Programmierung lernen mit diesem umfassenden Spickzettel. Schnelle Referenz für C-Syntax, Zeiger, Speicherverwaltung, Datenstrukturen und Systemprogrammierung für Entwickler.'
pdfUrl: '/cheatsheets/pdf/c-programming-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
C Programmier-Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/c">C-Programmierung mit praktischen Übungen lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie C-Programmierung durch praktische Übungen und reale Szenarien. LabEx bietet umfassende C-Kurse, die wesentliche Syntax, Speicherverwaltung, Zeiger, Datenstrukturen und fortgeschrittene Techniken abdecken. Meistern Sie die leistungsstarken Funktionen von C, um effiziente Systemanwendungen zu erstellen und Konzepte der Low-Level-Programmierung zu verstehen.
</base-disclaimer-content>
</base-disclaimer>

## Grundlegende Syntax & Struktur

### Hallo Welt Programm

Grundstruktur eines C-Programms.

```c
#include <stdio.h>
int main() {
    printf("Hallo, Welt!\n");
    return 0;
}
```

### Header und Präprozessor

Bibliotheken einbinden und Präprozessor-Direktiven verwenden.

```c
#include <stdio.h>    // Standard Ein-/Ausgabe
#include <stdlib.h>   // Standardbibliothek
#include <string.h>   // String-Funktionen
#include <math.h>     // Mathe-Funktionen
#define PI 3.14159
#define MAX_SIZE 100
```

### Kommentare

Einzeilige und mehrzeilige Kommentare.

```c
// Einzeiliger Kommentar
/*
Mehrzeiliger Kommentar
erstreckt sich über mehrere Zeilen
*/
// TODO: Funktion implementieren
/* FIXME: Fehler in diesem Abschnitt */
```

### Main Funktion

Einstiegspunkt des Programms mit Rückgabewerten.

```c
int main() {
    // Programmcode hier
    return 0;  // Erfolg
}
int main(int argc, char *argv[]) {
    // argc: Argumentanzahl
    // argv: Argumentwerte (Kommandozeile)
    return 0;
}
```

<BaseQuiz id="c-main-1" correct="C">
  <template #question>
    Was signalisiert <code>return 0</code> in der main-Funktion?
  </template>
  
  <BaseQuizOption value="A">Das Programm ist fehlgeschlagen</BaseQuizOption>
  <BaseQuizOption value="B">Das Programm läuft noch</BaseQuizOption>
  <BaseQuizOption value="C" correct>Programm erfolgreich ausgeführt</BaseQuizOption>
  <BaseQuizOption value="D">Das Programm gab keinen Wert zurück</BaseQuizOption>
  
  <BaseQuizAnswer>
    In C signalisiert <code>return 0</code> von der main-Funktion eine erfolgreiche Programmausführung. Rückgabewerte ungleich Null deuten typischerweise auf Fehler oder eine abnormale Beendigung hin.
  </BaseQuizAnswer>
</BaseQuiz>

### Grundlegende Ausgabe

Text und Variablen auf der Konsole anzeigen.

```c
printf("Hallo\n");
printf("Wert: %d\n", 42);
// Mehrere Werte in einer Zeile
printf("Name: %s, Alter: %d\n", name, age);
```

### Grundlegende Eingabe

Benutzereingaben von der Konsole lesen.

```c
int age;
char name[50];
scanf("%d", &age);
scanf("%s", name);
// Ganze Zeile mit Leerzeichen lesen
fgets(name, sizeof(name), stdin);
```

## Datentypen & Variablen

### Primitive Typen

Grundlegende Datentypen zur Speicherung verschiedener Wertarten.

```c
// Ganzzahltypen
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// Gleitkommatypen
float price = 19.99f;
double precise = 3.14159265359;
// Zeichen und Boolescher Wert (mittels int)
char grade = 'A';
int is_valid = 1;  // 1 für wahr, 0 für falsch
```

### Arrays & Strings

Arrays und String-Verarbeitung in C.

```c
// Arrays
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// Strings (Zeichen-Arrays)
char name[50] = "John Doe";
char greeting[] = "Hello";
char buffer[100];  // Nicht initialisiert
// String-Länge und Größe
int len = strlen(name);
int size = sizeof(buffer);
```

<BaseQuiz id="c-arrays-1" correct="C">
  <template #question>
    Wie werden Strings in C dargestellt?
  </template>
  
  <BaseQuizOption value="A">Als spezieller String-Typ</BaseQuizOption>
  <BaseQuizOption value="B">Als Ganzzahlen</BaseQuizOption>
  <BaseQuizOption value="C" correct>Als Zeichen-Arrays</BaseQuizOption>
  <BaseQuizOption value="D">Nur als Zeiger</BaseQuizOption>
  
  <BaseQuizAnswer>
    In C werden Strings als Zeichen-Arrays (<code>char</code>) dargestellt. Der String wird durch ein Nullzeichen (<code>\0</code>) terminiert, das das Ende des Strings markiert.
  </BaseQuizAnswer>
</BaseQuiz>

### Konstanten & Modifikatoren

Unveränderliche Werte und Speicher-Modifikatoren.

```c
// Konstanten
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Präprozessor-Konstanten
#define BUFFER_SIZE 512
#define TRUE 1
#define FALSE 0
// Speicher-Modifikatoren
static int count = 0;     // Statische Variable
extern int global_var;    // Externe Variable
register int fast_var;    // Register-Hinweis
```

## Kontrollflussstrukturen

### Bedingte Anweisungen

Entscheidungen basierend auf Bedingungen treffen.

```c
// If-else Anweisung
if (age >= 18) {
    printf("Erwachsen\n");
} else if (age >= 13) {
    printf("Teenager\n");
} else {
    printf("Kind\n");
}
// Ternärer Operator
char* status = (age >= 18) ? "Erwachsen" : "Minderjährig";
// Switch Anweisung
switch (grade) {
    case 'A':
        printf("Ausgezeichnet!\n");
        break;
    case 'B':
        printf("Gut gemacht!\n");
        break;
    default:
        printf("Weiter versuchen!\n");
}
```

### For Schleifen

Iteration mit zählerbasierten Schleifen.

```c
// Traditionelle for-Schleife
for (int i = 0; i < 10; i++) {
    printf("%d ", i);
}
// Array-Iteration
int numbers[] = {1, 2, 3, 4, 5};
int size = sizeof(numbers) / sizeof(numbers[0]);
for (int i = 0; i < size; i++) {
    printf("%d ", numbers[i]);
}
// Geschachtelte Schleifen
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        printf("%d,%d ", i, j);
    }
}
```

<BaseQuiz id="c-for-loop-1" correct="A">
  <template #question>
    Was berechnet <code>sizeof(numbers) / sizeof(numbers[0])</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Die Anzahl der Elemente im Array</BaseQuizOption>
  <BaseQuizOption value="B">Die Gesamtgröße des Arrays im Speicher</BaseQuizOption>
  <BaseQuizOption value="C">Der Index des letzten Elements</BaseQuizOption>
  <BaseQuizOption value="D">Die Größe eines Elements</BaseQuizOption>
  
  <BaseQuizAnswer>
    Dieser Ausdruck berechnet die Array-Länge, indem die Gesamtgröße des Arrays durch die Größe eines Elements geteilt wird. Dies ist ein gängiges C-Idiom, da Arrays ihre Länge nicht speichern.
  </BaseQuizAnswer>
</BaseQuiz>

### While Schleifen

Zustandsbasierte Iteration.

```c
// While-Schleife
int count = 0;
while (count < 5) {
    printf("%d\n", count);
    count++;
}
// Do-while-Schleife (wird mindestens einmal ausgeführt)
int input;
do {
    printf("Geben Sie eine Zahl ein (0 zum Beenden): ");
    scanf("%d", &input);
} while (input != 0);
```

### Schleifensteuerung

`break` und `continue` Anweisungen.

```c
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // Iteration überspringen
    }
    if (i == 7) {
        break;    // Schleife verlassen
    }
    printf("%d ", i);
}
// Geschachtelte Schleifen mit break
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // Nur innere Schleife verlassen
        printf("%d,%d ", i, j);
    }
}
```

## Funktionen

### Funktionsdeklaration & Definition

Wiederverwendbare Codeblöcke erstellen.

```c
// Funktionsdeklaration (Prototyp)
int add(int a, int b);
void printMessage(char* msg);
// Funktionsdefinition
int add(int a, int b) {
    return a + b;
}
void printMessage(char* msg) {
    printf("%s\n", msg);
}
// Funktionsaufruf
int result = add(5, 3);
printMessage("Hallo, Funktionen!");
```

### Arrays an Funktionen übergeben

Funktionen, die mit Arrays arbeiten.

```c
// Array als Parameter (Zeiger)
void printArray(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}
// Array-Elemente modifizieren
void doubleValues(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;
    }
}
```

### Rekursive Funktionen

Funktionen, die sich selbst aufrufen.

```c
// Fakultätsberechnung
int factorial(int n) {
    if (n <= 1) {
        return 1;  // Basisfall
    }
    return n * factorial(n - 1);
}
// Fibonacci-Folge
int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }
    return fibonacci(n-1) + fibonacci(n-2);
}
```

### Funktionszeiger

Zeiger auf Funktionen für dynamisches Verhalten.

```c
// Funktionszeiger-Deklaration
int (*operation)(int, int);
// Funktion dem Zeiger zuweisen
operation = add;
int result = operation(5, 3);
// Array von Funktionszeigern
int (*operations[])(int, int) = {add, subtract, multiply};
result = operations[0](10, 5);
```

## Zeiger & Speicherverwaltung

### Zeiger-Grundlagen

Zeiger deklarieren und verwenden, um auf Speicheradressen zuzugreifen.

```c
int x = 10;
int *ptr = &x;  // Zeiger auf x
printf("Wert von x: %d\n", x);
printf("Adresse von x: %p\n", &x);
printf("Wert von ptr: %p\n", ptr);
printf("Wert, auf den ptr zeigt: %d\n", *ptr);
// Wert über Zeiger ändern
*ptr = 20;
printf("Neuer Wert von x: %d\n", x);
// Null-Zeiger
int *null_ptr = NULL;
```

### Arrays und Zeiger

Beziehung zwischen Arrays und Zeigern.

```c
int arr[5] = {1, 2, 3, 4, 5};
int *p = arr;  // Zeigt auf das erste Element
// Array-Notation vs Zeigerarithmetik
printf("%d\n", arr[2]);   // Array-Notation
printf("%d\n", *(p + 2)); // Zeigerarithmetik
printf("%d\n", p[2]);     // Zeiger als Array
// Iteration mittels Zeiger
for (int i = 0; i < 5; i++) {
    printf("%d ", *(p + i));
}
```

### Dynamische Speicherzuweisung

Speicher zur Laufzeit zuweisen und freigeben.

```c
#include <stdlib.h>
// Speicher für einzelne Ganzzahl zuweisen
int *ptr = (int*)malloc(sizeof(int));
if (ptr != NULL) {
    *ptr = 42;
    printf("Wert: %d\n", *ptr);
    free(ptr);  // Immer zugewiesenen Speicher freigeben
}
// Array dynamisch zuweisen
int *arr = (int*)malloc(10 * sizeof(int));
if (arr != NULL) {
    for (int i = 0; i < 10; i++) {
        arr[i] = i * i;
    }
    free(arr);
}
```

### String-Zeiger

Arbeiten mit Strings und Zeichenzeigern.

```c
// String-Literale und Zeiger
char *str1 = "Hello";           // String-Literal
char str2[] = "World";          // Zeichen-Array
char *str3 = (char*)malloc(20); // Dynamischer String
// String-Funktionen
strcpy(str3, "Dynamic");
printf("Länge: %lu\n", strlen(str1));
printf("Vergleich: %d\n", strcmp(str1, str2));
strcat(str2, "!");
// Dynamische Strings immer freigeben
free(str3);
```

## Strukturen und benutzerdefinierte Typen

### Strukturdefinition

Benutzerdefinierte Datentypen mit mehreren Feldern definieren.

```c
// Strukturdefinition
struct Rectangle {
    double width;
    double height;
};
// Struktur mit typedef
typedef struct {
    char name[50];
    int age;
    double gpa;
} Student;
// Strukturen erstellen und initialisieren
struct Rectangle rect1 = {5.0, 3.0};
Student student1 = {"Alice", 20, 3.75};
// Auf Strukturmitglieder zugreifen
printf("Fläche: %.2f\n", rect1.width * rect1.height);
printf("Student: %s, Alter: %d\n", student1.name, student1.age);
```

### Geschachtelte Strukturen

Strukturen, die andere Strukturen enthalten.

```c
typedef struct {
    int day, month, year;
} Date;
typedef struct {
    char name[50];
    Date birthdate;
    double salary;
} Employee;
Employee emp = {
    "John Smith",
    {15, 6, 1985},
    50000.0
};
printf("Geboren: %d/%d/%d\n",
       emp.birthdate.day,
       emp.birthdate.month,
       emp.birthdate.year);
```

### Zeiger auf Strukturen

Zeiger verwenden, um auf Strukturen zuzugreifen und diese zu modifizieren.

```c
Student *student_ptr = &student1;
// Zugriff mittels Zeiger (zwei Methoden)
printf("Name: %s\n", (*student_ptr).name);
printf("Alter: %d\n", student_ptr->age);
// Modifikation über Zeiger
student_ptr->age = 21;
strcpy(student_ptr->name, "Alice Johnson");
// Dynamische Strukturzuweisung
Student *new_student = (Student*)malloc(sizeof(Student));
if (new_student != NULL) {
    strcpy(new_student->name, "Bob");
    new_student->age = 19;
    new_student->gpa = 3.2;
    free(new_student);
}
```

### Unions und Enums

Alternative Methoden zur Datenorganisation.

```c
// Union - gemeinsamer Speicherbereich
union Data {
    int integer;
    float floating;
    char character;
};
union Data data;
data.integer = 42;
printf("Integer: %d\n", data.integer);
// Enumeration
enum Weekday {
    MONDAY, TUESDAY, WEDNESDAY,
    THURSDAY, FRIDAY, SATURDAY, SUNDAY
};
enum Weekday today = FRIDAY;
printf("Heute ist Tag %d\n", today);
```

## Datei Ein-/Ausgabe Operationen

### Datei Lesen

Daten aus Textdateien lesen.

```c
#include <stdio.h>
// Ganze Datei Zeichen für Zeichen lesen
FILE *file = fopen("data.txt", "r");
if (file != NULL) {
    int ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}
// Zeile für Zeile lesen
FILE *file2 = fopen("lines.txt", "r");
char buffer[256];
while (fgets(buffer, sizeof(buffer), file2) != NULL) {
    printf("Zeile: %s", buffer);
}
fclose(file2);
// Formatierte Daten lesen
FILE *numbers = fopen("numbers.txt", "r");
int num;
while (fscanf(numbers, "%d", &num) == 1) {
    printf("Zahl: %d\n", num);
}
fclose(numbers);
```

### Fehlerprüfung

Dateivorgänge sicher behandeln.

```c
FILE *file = fopen("data.txt", "r");
if (file == NULL) {
    printf("Fehler beim Öffnen der Datei!\n");
    perror("fopen");  // Systemfehlermeldung ausgeben
    return 1;
}
// Auf Lesefehler prüfen
if (ferror(file)) {
    printf("Fehler beim Lesen der Datei!\n");
}
// Auf Dateiende prüfen
if (feof(file)) {
    printf("Dateiende erreicht\n");
}
fclose(file);
```

### Datei Schreiben

Daten in Textdateien schreiben.

```c
// In Datei schreiben
FILE *outfile = fopen("output.txt", "w");
if (outfile != NULL) {
    fprintf(outfile, "Hallo, Datei!\n");
    fprintf(outfile, "Zahl: %d\n", 42);
    fclose(outfile);
}
// An bestehende Datei anhängen
FILE *appendfile = fopen("log.txt", "a");
if (appendfile != NULL) {
    fprintf(appendfile, "Neuer Log-Eintrag\n");
    fclose(appendfile);
}
// Array in Datei schreiben
int numbers[] = {1, 2, 3, 4, 5};
FILE *numfile = fopen("numbers.txt", "w");
for (int i = 0; i < 5; i++) {
    fprintf(numfile, "%d ", numbers[i]);
}
fclose(numfile);
```

### Binäre Dateioperationen

Binärdaten effizient lesen und schreiben.

```c
// Binärdaten schreiben
Student students[3] = {
    {"Alice", 20, 3.75},
    {"Bob", 21, 3.2},
    {"Charlie", 19, 3.9}
};
FILE *binfile = fopen("students.bin", "wb");
fwrite(students, sizeof(Student), 3, binfile);
fclose(binfile);
// Binärdaten lesen
Student loaded_students[3];
FILE *readbin = fopen("students.bin", "rb");
fread(loaded_students, sizeof(Student), 3, readbin);
fclose(readbin);
```

## String-Manipulation

### String-Funktionen

Häufige String-Operationen aus der string.h Bibliothek.

```c
#include <string.h>
char str1[50] = "Hello";
char str2[] = "World";
char dest[100];
// String-Länge
int len = strlen(str1);
printf("Länge: %d\n", len);
// String kopieren
strcpy(dest, str1);
strncpy(dest, str1, 10); // Erste 10 Zeichen kopieren
// String-Verkettung
strcat(dest, " ");
strcat(dest, str2);
strncat(dest, "!", 1);   // 1 Zeichen anhängen
// String-Vergleich
int result = strcmp(str1, str2);
if (result == 0) {
    printf("Strings sind gleich\n");
}
```

### String-Suche

Teilstrings und Zeichen in Strings finden.

```c
char text[] = "The quick brown fox";
char *ptr;
// Erstes Vorkommen eines Zeichens finden
ptr = strchr(text, 'q');
if (ptr != NULL) {
    printf(" 'q' gefunden an Position: %ld\n", ptr - text);
}
// Letztes Vorkommen
ptr = strrchr(text, 'o');
printf("Letztes 'o' an Position: %ld\n", ptr - text);
// Teilstring suchen
ptr = strstr(text, "brown");
if (ptr != NULL) {
    printf(" 'brown' gefunden bei: %s\n", ptr);
}
```

### String-Konvertierung

Strings in Zahlen und umgekehrt konvertieren.

```c
#include <stdlib.h>
// String zu Zahl Konvertierung
char num_str[] = "12345";
char float_str[] = "3.14159";
int num = atoi(num_str);
long long_num = atol(num_str);
double float_num = atof(float_str);
printf("Ganzzahl: %d\n", num);
printf("Long: %ld\n", long_num);
printf("Double: %.2f\n", float_num);
// Zahl zu String (mittels sprintf)
char buffer[50];
sprintf(buffer, "%d", 42);
sprintf(buffer, "%.2f", 3.14159);
printf("String: %s\n", buffer);
```

### Benutzerdefinierte String-Verarbeitung

Manuelle Techniken zur String-Manipulation.

```c
// Zeichen im String zählen
int countChar(char *str, char target) {
    int count = 0;
    while (*str) {
        if (*str == target) count++;
        str++;
    }
    return count;
}
// String an Ort und Stelle umkehren
void reverseString(char *str) {
    int len = strlen(str);
    for (int i = 0; i < len/2; i++) {
        char temp = str[i];
        str[i] = str[len-1-i];
        str[len-1-i] = temp;
    }
}
```

## Kompilierung & Build-Prozess

### GCC Kompilierung

GNU Compiler Collection für C.

```bash
# Grundlegende Kompilierung
gcc -o program main.c
# Mit Debugging-Informationen
gcc -g -o program main.c
# Optimierungsstufen
gcc -O2 -o program main.c
# Mehrere Quelldateien
gcc -o program main.c utils.c math.c
# Zusätzliche Verzeichnisse einbeziehen
gcc -I/usr/local/include -o program main.c
# Bibliotheken verlinken
gcc -o program main.c -lm -lpthread
```

### C-Standards

Kompilieren mit spezifischen C-Standardversionen.

```bash
# C90/C89 Standard (ANSI C)
gcc -std=c89 -o program main.c
# C99 Standard
gcc -std=c99 -o program main.c
# C11 Standard (empfohlen)
gcc -std=c11 -o program main.c
# C18 Standard (neueste)
gcc -std=c18 -o program main.c
# Alle Warnungen aktivieren
gcc -Wall -Wextra -std=c11 -o program main.c
```

### Makefile Grundlagen

Kompilierung mit dem `make`-Dienstprogramm automatisieren.

```makefile
# Einfaches Makefile
CC = gcc
CFLAGS = -std=c11 -Wall -g
TARGET = program
SOURCES = main.c utils.c
$(TARGET): $(SOURCES)
$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)
clean:
rm -f $(TARGET)
.PHONY: clean
```

## Best Practices & Tipps

### Namenskonventionen

Konsistente Benennung macht Code lesbarer.

```c
// Variablen und Funktionen: snake_case
int student_count;
double calculate_average(int scores[], int size);
// Konstanten: UPPER_CASE
#define MAX_BUFFER_SIZE 1024
#define PI 3.14159
// Strukturen: PascalCase oder snake_case
typedef struct {
    char name[50];
    int age;
} Student;
// Globale Variablen: Präfix mit g_
int g_total_count = 0;
// Funktionsparameter: klare Namen
void process_data(int *input_array, int array_size);
```

### Speichersicherheit

Häufige speicherbezogene Fehler vermeiden.

```c
// Variablen immer initialisieren
int count = 0;        // Gut
int count;            // Gefährlich - nicht initialisiert
// malloc Rückgabewert prüfen
int *ptr = malloc(sizeof(int) * 10);
if (ptr == NULL) {
    printf("Speicherzuweisung fehlgeschlagen!\n");
    return -1;
}
// Zugewiesenen Speicher immer freigeben
free(ptr);
ptr = NULL;  // Versehentliche Wiederverwendung verhindern
// Array-Grenzenprüfung
for (int i = 0; i < array_size; i++) {
    // Sicherer Array-Zugriff
    array[i] = i;
}
```

### Performance-Tipps

Effizienten C-Code schreiben.

```c
// Geeignete Datentypen verwenden
char small_num = 10;   // Für kleine Werte
int normal_num = 1000; // Für typische Ganzzahlen
// Funktionsaufrufe in Schleifen minimieren
int len = strlen(str); // Einmal berechnen
for (int i = 0; i < len; i++) {
    // String verarbeiten
}
// 'register' für häufig verwendete Variablen bevorzugen
register int counter;
// Arrays gegenüber dynamischer Zuweisung bevorzugen, wenn die Größe bekannt ist
int fixed_array[100];  // Stack-Zuweisung
// vs
int *dynamic_array = malloc(100 * sizeof(int));
```

### Code-Organisation

Code für Wartbarkeit strukturieren.

```c
// Header-Datei (utils.h)
#ifndef UTILS_H
#define UTILS_H
// Funktionsprototypen
double calculate_area(double radius);
int fibonacci(int n);
// Strukturdefinitionen
typedef struct {
    int x, y;
} Point;
#endif // UTILS_H
// Implementierungsdatei (utils.c)
#include "utils.h"
#include <math.h>
double calculate_area(double radius) {
    return M_PI * radius * radius;
}
```

## Relevante Links

- <router-link to="/cpp">C++ Spickzettel</router-link>
- <router-link to="/java">Java Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/golang">Golang Spickzettel</router-link>
- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>

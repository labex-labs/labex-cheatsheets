---
title: 'Fiche de Référence C++'
description: 'Apprenez le C++ avec notre aide-mémoire complet couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/cpp-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Fiche de Référence C++
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/cpp">Apprendre le C++ avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la programmation C++ grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets en C++ couvrant la syntaxe essentielle, la programmation orientée objet, les conteneurs STL, la gestion de la mémoire et les techniques avancées. Maîtrisez les fonctionnalités puissantes de C++ pour construire des applications haute performance et des logiciels système.
</base-disclaimer-content>
</base-disclaimer>

## Syntaxe et Structure de Base

### Programme Hello World

Structure de base d'un programme C++.

```cpp
#include <iostream>
using namespace std;
int main() {
    cout << "Hello, World!" << endl;
    return 0;
}
```

### En-têtes et Espaces de Noms

Inclure des bibliothèques et gérer les espaces de noms.

```cpp
#include <iostream>  // Flux d'entrée/sortie
#include <vector>    // Tableaux dynamiques
#include <string>    // Classe string
#include <algorithm> // Algorithmes STL
using namespace std;
// Ou spécifier individuellement :
// using std::cout;
// using std::cin;
```

### Commentaires

Commentaires sur une seule ligne et sur plusieurs lignes.

```cpp
// Commentaire sur une seule ligne
/*
Commentaire
sur plusieurs lignes
*/
// TODO: Implémenter la fonctionnalité
/* FIXME: Bug dans cette section */
```

### Fonction Main

Point d'entrée du programme avec valeurs de retour.

```cpp
int main() {
    // Code du programme ici
    return 0;  // Succès
}
int main(int argc, char* argv[]) {
    // argc : nombre d'arguments
    // argv : valeurs des arguments (ligne de commande)
    return 0;
}
```

### Sortie de Base

Afficher du texte et des variables sur la console.

```cpp
cout << "Hello" << endl;
cout << "Valeur: " << 42 << endl;
// Plusieurs valeurs sur une seule ligne
cout << "Nom: " << name << ", Âge: " << age << endl;
```

### Entrée de Base

Lire l'entrée utilisateur depuis la console.

```cpp
int age;
string name;
cin >> age;
cin >> name;
// Lire la ligne entière avec espaces
getline(cin, name);
```

## Types de Données et Variables

### Types Primitifs

Types de données de base pour stocker différentes sortes de valeurs.

```cpp
// Types entiers
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// Types à virgule flottante
float price = 19.99f;
double precise = 3.14159265359;
// Caractère et booléen
char grade = 'A';
bool is_valid = true;
```

### String et Tableaux

Types de données pour le texte et les collections.

```cpp
// Strings
string name = "John Doe";
string empty_str;
// Tableaux (Arrays)
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// Tableaux dynamiques (vectors)
vector<int> dynamic_array = {10, 20, 30};
vector<string> names(5); // Taille 5, chaînes vides
```

### Constantes et Auto

Valeurs immuables et déduction automatique de type.

```cpp
// Constantes
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Mot-clé Auto (C++11+)
auto x = 42;        // int
auto y = 3.14;      // double
auto name = "John"; // const char*
// Alias de type
typedef unsigned int uint;
using real = double;
```

## Structures de Flux de Contrôle

### Instructions Conditionnelles

Prendre des décisions basées sur des conditions.

```cpp
// Instruction If-else
if (age >= 18) {
    cout << "Adulte" << endl;
} else if (age >= 13) {
    cout << "Adolescent" << endl;
} else {
    cout << "Enfant" << endl;
}
// Opérateur Ternaire
string status = (age >= 18) ? "Adulte" : "Mineur";
// Instruction Switch
switch (grade) {
    case 'A':
        cout << "Excellent!" << endl;
        break;
    case 'B':
        cout << "Bon travail!" << endl;
        break;
    default:
        cout << "Continuez d'essayer!" << endl;
}
```

### Boucles For

Itérer avec des boucles basées sur un compteur.

```cpp
// Boucle for traditionnelle
for (int i = 0; i < 10; i++) {
    cout << i << " ";
}
// Boucle for basée sur la plage (C++11+)
vector<int> numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    cout << num << " ";
}
// Auto avec boucle basée sur la plage
for (auto& item : container) {
    // Traiter l'élément
}
```

### Boucles While

Itération basée sur une condition.

```cpp
// Boucle While
int count = 0;
while (count < 5) {
    cout << count << endl;
    count++;
}
// Boucle Do-while (s'exécute au moins une fois)
int input;
do {
    cout << "Entrez un nombre (0 pour quitter): ";
    cin >> input;
} while (input != 0);
```

### Contrôle de Boucle

Instructions break et continue.

```cpp
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // Sauter l'itération
    }
    if (i == 7) {
        break;    // Quitter la boucle
    }
    cout << i << " ";
}
// Boucles imbriquées avec break étiqueté
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // Quitter uniquement la boucle interne
        cout << i << "," << j << " ";
    }
}
```

## Fonctions

### Déclaration et Définition de Fonction

Créer des blocs de code réutilisables.

```cpp
// Déclaration de fonction (prototype)
int add(int a, int b);
void printMessage(string msg);
// Définition de fonction
int add(int a, int b) {
    return a + b;
}
void printMessage(string msg) {
    cout << msg << endl;
}
// Appel de fonction
int result = add(5, 3);
printMessage("Hello, functions!");
```

### Surcharge de Fonction (Overloading)

Plusieurs fonctions avec le même nom.

```cpp
// Types de paramètres différents
int multiply(int a, int b) {
    return a * b;
}
double multiply(double a, double b) {
    return a * b;
}
// Nombre différent de paramètres
int multiply(int a, int b, int c) {
    return a * b * c;
}
```

### Paramètres par Défaut

Fournir des valeurs par défaut pour les paramètres de fonction.

```cpp
void greet(string name, string greeting = "Hello") {
    cout << greeting << ", " << name << "!" << endl;
}
// Appels de fonction
greet("Alice");              // Utilise le défaut "Hello"
greet("Bob", "Good morning"); // Utilise un salut personnalisé
```

### Passage par Référence

Modifier des variables via les paramètres de fonction.

```cpp
// Passage par valeur (copie)
void changeValue(int x) {
    x = 100; // Variable originale inchangée
}
// Passage par référence
void changeReference(int& x) {
    x = 100; // Variable originale modifiée
}
// Référence constante (lecture seule, efficace)
void processLargeData(const vector<int>& data) {
    // Peut lire les données mais pas les modifier
}
```

## Programmation Orientée Objet

### Définition de Classe

Définir des types de données personnalisés avec attributs et méthodes.

```cpp
class Rectangle {
private:
    double width, height;
public:
    // Constructeur
    Rectangle(double w, double h) : width(w), height(h) {}

    // Constructeur par défaut
    Rectangle() : width(0), height(0) {}

    // Fonctions membres
    double area() const {
        return width * height;
    }

    void setDimensions(double w, double h) {
        width = w;
        height = h;
    }

    // Fonctions getter
    double getWidth() const { return width; }
    double getHeight() const { return height; }
};
```

### Création et Utilisation d'Objets

Instancier et utiliser des objets de classe.

```cpp
// Créer des objets
Rectangle rect1(5.0, 3.0);
Rectangle rect2; // Constructeur par défaut
// Utiliser les fonctions membres
cout << "Area: " << rect1.area() << endl;
rect2.setDimensions(4.0, 2.0);
// Allocation dynamique
Rectangle* rect3 = new Rectangle(6.0, 4.0);
cout << rect3->area() << endl;
delete rect3; // Nettoyer la mémoire
```

### Héritage

Créer des classes spécialisées à partir de classes de base.

```cpp
class Shape {
protected:
    string color;

public:
    Shape(string c) : color(c) {}
    virtual double area() const = 0; // Virtuel pur
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

### Polymorphisme

Utiliser des pointeurs de classe de base pour accéder à des objets dérivés.

```cpp
// Fonctions virtuelles et polymorphisme
vector<Shape*> shapes;
shapes.push_back(new Circle(5.0, "red"));
shapes.push_back(new Rectangle(4.0, 6.0));
for (Shape* shape : shapes) {
    cout << "Area: " << shape->area() << endl;
    // Appelle la méthode de la classe dérivée appropriée
}
```

## Gestion de la Mémoire

### Allocation Dynamique de Mémoire

Allouer et désallouer la mémoire à l'exécution.

```cpp
// Objet unique
int* ptr = new int(42);
cout << *ptr << endl;
delete ptr;
ptr = nullptr;
// Allocation de tableau
int* arr = new int[10];
for (int i = 0; i < 10; i++) {
    arr[i] = i * i;
}
delete[] arr;
// Vérifier l'échec de l'allocation
int* large_array = new(nothrow) int[1000000];
if (large_array == nullptr) {
    cout << "Échec de l'allocation!" << endl;
}
```

### Pointeur Intelligents (Smart Pointers) (C++11+)

Gestion automatique de la mémoire avec RAII.

```cpp
#include <memory>
// unique_ptr (propriété exclusive)
unique_ptr<int> ptr1 = make_unique<int>(42);
unique_ptr<int> ptr2 = move(ptr1); // Transférer la propriété
// shared_ptr (propriété partagée)
shared_ptr<int> sptr1 = make_shared<int>(100);
shared_ptr<int> sptr2 = sptr1; // Partager la propriété
cout << sptr1.use_count() << endl; // Compte de références
```

### Références vs Pointeurs

Deux façons d'accéder indirectement aux objets.

```cpp
int x = 10;
// Référence (alias)
int& ref = x;  // Doit être initialisée
ref = 20;      // Modifie x à 20
// Pointeur
int* ptr = &x; // Pointeur vers l'adresse de x
*ptr = 30;     // Déréférencement et modification de x
ptr = nullptr; // Peut pointer vers rien
// Variations Const
const int* ptr1 = &x;    // Ne peut pas changer la valeur
int* const ptr2 = &x;    // Ne peut pas changer l'adresse
const int* const ptr3 = &x; // Ne peut changer ni l'un ni l'autre
```

### Pile (Stack) vs Tas (Heap)

Stratégies d'allocation de mémoire.

```cpp
// Allocation sur la pile (automatique)
int stack_var = 42;
int stack_array[100];
// Allocation sur le tas (dynamique)
int* heap_var = new int(42);
int* heap_array = new int[100];
// Objets sur la pile nettoyés automatiquement
// Objets sur le tas doivent être supprimés manuellement
delete heap_var;
delete[] heap_array;
```

## Bibliothèque Standard Template (STL)

### Conteneurs : Vector et String

Tableaux dynamiques et manipulation de chaînes.

```cpp
#include <vector>
#include <string>
// Opérations Vector
vector<int> nums = {1, 2, 3};
nums.push_back(4);        // Ajouter un élément
nums.pop_back();          // Supprimer le dernier
nums.insert(nums.begin() + 1, 10); // Insérer à une position
nums.erase(nums.begin()); // Supprimer le premier
// Opérations String
string text = "Hello";
text += " World";         // Concaténation
text.append("!");         // Ajouter
cout << text.substr(0, 5) << endl; // Sous-chaîne
text.replace(6, 5, "C++"); // Remplacer "World" par "C++"
```

### Conteneurs : Map et Set

Conteneurs associatifs pour les paires clé-valeur et les éléments uniques.

```cpp
#include <map>
#include <set>
// Map (paires clé-valeur)
map<string, int> ages;
ages["Alice"] = 25;
ages["Bob"] = 30;
ages.insert({"Charlie", 35});
// Set (éléments uniques)
set<int> unique_nums = {3, 1, 4, 1, 5, 9};
unique_nums.insert(2);
unique_nums.erase(1);
// Trié automatiquement : {2, 3, 4, 5, 9}
```

### Algorithmes

Algorithmes STL pour les opérations courantes.

```cpp
#include <algorithm>
vector<int> nums = {64, 34, 25, 12, 22, 11, 90};
// Tri
sort(nums.begin(), nums.end());
sort(nums.rbegin(), nums.rend()); // Tri inversé
// Recherche
auto it = find(nums.begin(), nums.end(), 25);
if (it != nums.end()) {
    cout << "Trouvé à la position: " << it - nums.begin();
}
// Autres algorithmes utiles
reverse(nums.begin(), nums.end());
int max_val = *max_element(nums.begin(), nums.end());
int count = count_if(nums.begin(), nums.end(),
                    [](int x) { return x > 50; });
```

### Itérateurs

Naviguer efficacement dans les conteneurs.

```cpp
vector<string> words = {"hello", "world", "cpp"};
// Types d'itérateurs
vector<string>::iterator it;
auto it2 = words.begin(); // Auto C++11
// Itérer sur le conteneur
for (it = words.begin(); it != words.end(); ++it) {
    cout << *it << " ";
}
// Boucle basée sur la plage (préférée)
for (const auto& word : words) {
    cout << word << " ";
}
```

## Opérations d'Entrée/Sortie

### Entrée Fichier : Lecture de Fichiers

Lire des données à partir de fichiers texte.

```cpp
#include <fstream>
#include <sstream>
// Lire le fichier entier
ifstream file("data.txt");
if (file.is_open()) {
    string line;
    while (getline(file, line)) {
        cout << line << endl;
    }
    file.close();
}
// Lire mot par mot
ifstream file2("numbers.txt");
int number;
while (file2 >> number) {
    cout << number << " ";
}
// Lecture avec vérification d'erreurs
if (!file.good()) {
    cerr << "Erreur de lecture de fichier!" << endl;
}
```

### Traitement de Flux de Chaînes

Analyser et manipuler des chaînes comme des flux.

```cpp
#include <sstream>
// Analyser des valeurs séparées par des virgules
string data = "apple,banana,cherry";
stringstream ss(data);
string item;
vector<string> fruits;
while (getline(ss, item, ',')) {
    fruits.push_back(item);
}
// Convertir des chaînes en nombres
string num_str = "123";
int num = stoi(num_str);
double d = stod("3.14159");
string back_to_str = to_string(num);
```

### Sortie Fichier : Écriture de Fichiers

Écrire des données dans des fichiers texte.

```cpp
// Écrire dans un fichier
ofstream outfile("output.txt");
if (outfile.is_open()) {
    outfile << "Hello, file!" << endl;
    outfile << "Number: " << 42 << endl;
    outfile.close();
}
// Ajouter à un fichier existant
ofstream appendfile("log.txt", ios::app);
appendfile << "Nouvelle entrée de journal" << endl;
// Écrire un vecteur dans un fichier
vector<int> numbers = {1, 2, 3, 4, 5};
ofstream numfile("numbers.txt");
for (int num : numbers) {
    numfile << num << " ";
}
```

### Formatage de Flux

Contrôler le format et la précision de la sortie.

```cpp
#include <iomanip>
double pi = 3.14159265;
cout << fixed << setprecision(2) << pi << endl; // 3.14
cout << setw(10) << "Right" << endl;          // Alignement à droite
cout << left << setw(10) << "Left" << endl;     // Alignement à gauche
cout << hex << 255 << endl;                    // Hexadécimal: ff
```

## Gestion des Erreurs

### Blocs Try-Catch

Gérer les exceptions qui peuvent survenir pendant l'exécution.

```cpp
try {
    int result = 10 / 0; // Ceci pourrait lancer une exception
    vector<int> vec(5);
    vec.at(10) = 100;    // Accès hors limites

} catch (const exception& e) {
    cout << "Exception attrapée: " << e.what() << endl;
} catch (...) {
    cout << "Exception inconnue attrapée!" << endl;
}
// Types d'exceptions spécifiques
try {
    string str = "abc";
    int num = stoi(str); // Lance invalid_argument
} catch (const invalid_argument& e) {
    cout << "Argument invalide: " << e.what() << endl;
} catch (const out_of_range& e) {
    cout << "Hors limites: " << e.what() << endl;
}
```

### Lancer des Exceptions Personnalisées

Créer et lancer vos propres exceptions.

```cpp
// Classe d'exception personnalisée
class CustomException : public exception {
    string message;
public:
    CustomException(const string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};
// Fonction qui lance une exception
void validateAge(int age) {
    if (age < 0 || age > 150) {
        throw CustomException("Plage d'âge invalide!");
    }
}
// Utilisation
try {
    validateAge(-5);
} catch (const CustomException& e) {
    cout << e.what() << endl;
}
```

### Modèle RAII

Resource Acquisition Is Initialization pour une gestion sûre des ressources.

```cpp
// RAII avec pointeurs intelligents
{
    unique_ptr<int[]> arr = make_unique<int[]>(1000);
    // Le tableau est automatiquement supprimé lorsqu'il sort du scope
}
// RAII avec gestion de fichiers
{
    ifstream file("data.txt");
    // Le fichier est automatiquement fermé lorsqu'il sort du scope
    if (file.is_open()) {
        // Traiter le fichier
    }
}
// Classe RAII personnalisée
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

### Assertions et Débogage

Déboguer et valider les hypothèses du programme.

```cpp
#include <cassert>
#include <iostream>
void processArray(int* arr, int size) {
    assert(arr != nullptr);  // Assertion de débogage
    assert(size > 0);        // Valide l'hypothèse

    // Traiter le tableau...
}
// Compilation conditionnelle pour la sortie de débogage
#ifdef DEBUG
    #define DBG_PRINT(x) cout << "DEBUG: " << x << endl
#else
    #define DBG_PRINT(x)
#endif
// Utilisation
DBG_PRINT("Démarrage de la fonction");
```

## Compilation et Processus de Construction

### Compilation GCC/G++

GNU Compiler Collection pour C++.

```bash
# Compilation de base
g++ -o program main.cpp
# Avec informations de débogage
g++ -g -o program main.cpp
# Niveaux d'optimisation
g++ -O2 -o program main.cpp
# Fichiers sources multiples
g++ -o program main.cpp utils.cpp math.cpp
# Inclure des répertoires supplémentaires
g++ -I/usr/local/include -o program main.cpp
# Lier des bibliothèques
g++ -o program main.cpp -lm -lpthread
```

### Normes C++ Modernes

Compiler avec des versions standard C++ spécifiques.

```bash
# Standard C++11
g++ -std=c++11 -o program main.cpp
# Standard C++14
g++ -std=c++14 -o program main.cpp
# Standard C++17 (recommandé)
g++ -std=c++17 -o program main.cpp
# Standard C++20 (le plus récent)
g++ -std=c++20 -o program main.cpp
# Activer tous les avertissements
g++ -Wall -Wextra -std=c++17 -o program main.cpp
```

### Bases de Makefile

Automatiser la compilation avec l'utilitaire make.

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

## Bonnes Pratiques et Conseils

### Conventions de Nommage

Un nommage cohérent rend le code plus lisible.

```cpp
// Variables et fonctions : snake_case ou camelCase
int student_count;
int studentCount;
void calculateAverage();
// Constantes : UPPER_CASE
const int MAX_BUFFER_SIZE = 1024;
const double PI = 3.14159;
// Classes : PascalCase
class StudentRecord {
    // Variables membres : préfixe avec m_ ou suffixe _
    string m_name;
    int age_;

public:
    // Interface publique
    void setName(const string& name);
    string getName() const;
};
```

### Sécurité de la Mémoire

Prévenir les bugs courants liés à la mémoire.

```cpp
// Utiliser des pointeurs intelligents au lieu de pointeurs bruts
auto ptr = make_unique<int>(42);
auto shared = make_shared<vector<int>>(10);
// Initialiser les variables
int count = 0;        // Bien
int count;            // Dangereux - non initialisé
// Les boucles basées sur la plage sont plus sûres
for (const auto& item : container) {
    // Traiter l'élément en toute sécurité
}
// Vérifier la validité du pointeur
if (ptr != nullptr) {
    // Sûr de déréférencer
}
```

### Conseils de Performance

Écrire du code C++ efficace.

```cpp
// Passer les objets volumineux par référence constante
void processData(const vector<int>& data) {
    // Éviter de copier les objets volumineux
}
// Utiliser l'incrémentation préfixée pour les itérateurs
for (auto it = vec.begin(); it != vec.end(); ++it) {
    // ++it est souvent plus rapide que it++
}
// Réserver la capacité du vecteur lorsque la taille est connue
vector<int> numbers;
numbers.reserve(1000); // Éviter les réallocations
// Utiliser emplace au lieu de push pour les objets
vector<string> words;
words.emplace_back("Hello"); // Construction sur place
words.push_back(string("World")); // Construction puis copie
```

### Organisation du Code

Structurer le code pour la maintenabilité.

```cpp
// Fichier d'en-tête (utils.h)
#ifndef UTILS_H
#define UTILS_H
class MathUtils {
public:
    static double calculateArea(double radius);
    static int fibonacci(int n);
};
#endif // UTILS_H
// Fichier d'implémentation (utils.cpp)
#include "utils.h"
#include <cmath>
double MathUtils::calculateArea(double radius) {
    return M_PI * radius * radius;
}
// Utiliser des fonctions membres const lorsque c'est possible
double getRadius() const { return radius; }
```

## Liens Pertinents

- <router-link to="/c-programming">Fiche de Référence Programmation C</router-link>
- <router-link to="/java">Fiche de Référence Java</router-link>
- <router-link to="/python">Fiche de Référence Python</router-link>
- <router-link to="/javascript">Fiche de Référence JavaScript</router-link>
- <router-link to="/golang">Fiche de Référence Golang</router-link>
- <router-link to="/linux">Fiche de Référence Linux</router-link>
- <router-link to="/shell">Fiche de Référence Shell</router-link>
- <router-link to="/devops">Fiche de Référence DevOps</router-link>

---
title: 'Fiche de Référence C | LabEx'
description: 'Apprenez la programmation C avec cette fiche de référence complète. Référence rapide pour la syntaxe C, les pointeurs, la gestion mémoire, les structures de données et les bases de la programmation système pour développeurs.'
pdfUrl: '/cheatsheets/pdf/c-programming-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche C
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/c">Apprenez la programmation C avec des laboratoires pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la programmation C grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours C complets couvrant la syntaxe essentielle, la gestion de la mémoire, les pointeurs, les structures de données et les techniques avancées. Maîtrisez les puissantes fonctionnalités de C pour créer des applications système efficaces et comprendre les concepts de programmation de bas niveau.
</base-disclaimer-content>
</base-disclaimer>

## Syntaxe et Structure de Base

### Programme Hello World

Structure de base d'un programme C.

```c
#include <stdio.h>
int main() {
    printf("Hello, World!\n");
    return 0;
}
```

### En-têtes et Préprocesseur

Inclure des bibliothèques et utiliser des directives de préprocesseur.

```c
#include <stdio.h>    // Entrée/sortie standard
#include <stdlib.h>   // Bibliothèque standard
#include <string.h>   // Fonctions de chaîne
#include <math.h>     // Fonctions mathématiques
#define PI 3.14159
#define MAX_SIZE 100
```

### Commentaires

Commentaires sur une seule ligne et sur plusieurs lignes.

```c
// Commentaire sur une seule ligne
/*
Commentaire
sur plusieurs
lignes
*/
// TODO: Implémenter la fonctionnalité
/* FIXME: Bug dans cette section */
```

### Fonction Main

Point d'entrée du programme avec valeurs de retour.

```c
int main() {
    // Code du programme ici
    return 0;  // Succès
}
int main(int argc, char *argv[]) {
    // argc : nombre d'arguments
    // argv : valeurs des arguments (ligne de commande)
    return 0;
}
```

<BaseQuiz id="c-main-1" correct="C">
  <template #question>
    Que signifie <code>return 0</code> dans la fonction main ?
  </template>
  
  <BaseQuizOption value="A">Le programme a échoué</BaseQuizOption>
  <BaseQuizOption value="B">Le programme est toujours en cours d'exécution</BaseQuizOption>
  <BaseQuizOption value="C" correct>Le programme s'est exécuté avec succès</BaseQuizOption>
  <BaseQuizOption value="D">Le programme n'a retourné aucune valeur</BaseQuizOption>
  
  <BaseQuizAnswer>
    En C, <code>return 0</code> depuis la fonction main indique une exécution réussie du programme. Les valeurs de retour non nulles indiquent généralement des erreurs ou une terminaison anormale.
  </BaseQuizAnswer>
</BaseQuiz>

### Sortie de Base

Afficher du texte et des variables sur la console.

```c
printf("Hello\n");
printf("Valeur: %d\n", 42);
// Plusieurs valeurs sur une seule ligne
printf("Nom: %s, Âge: %d\n", name, age);
```

### Entrée de Base

Lire l'entrée utilisateur depuis la console.

```c
int age;
char name[50];
scanf("%d", &age);
scanf("%s", name);
// Lire la ligne entière avec espaces
fgets(name, sizeof(name), stdin);
```

## Types de Données et Variables

### Types Primitifs

Types de données de base pour stocker différents types de valeurs.

```c
// Types entiers
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// Types à virgule flottante
float price = 19.99f;
double precise = 3.14159265359;
// Caractère et booléen (en utilisant int)
char grade = 'A';
int is_valid = 1;  // 1 pour vrai, 0 pour faux
```

### Tableaux et Chaînes

Tableaux et gestion des chaînes en C.

```c
// Tableaux
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// Chaînes (tableaux de caractères)
char name[50] = "John Doe";
char greeting[] = "Hello";
char buffer[100];  // Non initialisé
// Longueur et taille de la chaîne
int len = strlen(name);
int size = sizeof(buffer);
```

<BaseQuiz id="c-arrays-1" correct="C">
  <template #question>
    Comment les chaînes sont-elles représentées en C ?
  </template>
  
  <BaseQuizOption value="A">Comme un type chaîne spécial</BaseQuizOption>
  <BaseQuizOption value="B">Comme des entiers</BaseQuizOption>
  <BaseQuizOption value="C" correct>Comme des tableaux de caractères</BaseQuizOption>
  <BaseQuizOption value="D">Uniquement comme des pointeurs</BaseQuizOption>
  
  <BaseQuizAnswer>
    En C, les chaînes sont représentées comme des tableaux de caractères (<code>char</code>). La chaîne est terminée par un caractère nul (<code>\0</code>), qui marque la fin de la chaîne.
  </BaseQuizAnswer>
</BaseQuiz>

### Constantes et Modificateurs

Valeurs immuables et modificateurs de stockage.

```c
// Constantes
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Constantes de préprocesseur
#define BUFFER_SIZE 512
#define TRUE 1
#define FALSE 0
// Modificateurs de stockage
static int count = 0;     // Variable statique
extern int global_var;    // Variable externe
register int fast_var;    // Indice de registre
```

## Structures de Flux de Contrôle

### Instructions Conditionnelles

Prendre des décisions basées sur des conditions.

```c
// Instruction If-else
if (age >= 18) {
    printf("Adulte\n");
} else if (age >= 13) {
    printf("Adolescent\n");
} else {
    printf("Enfant\n");
}
// Opérateur ternaire
char* status = (age >= 18) ? "Adulte" : "Mineur";
// Instruction Switch
switch (grade) {
    case 'A':
        printf("Excellent !\n");
        break;
    case 'B':
        printf("Bon travail !\n");
        break;
    default:
        printf("Continuez d'essayer !\n");
}
```

### Boucles For

Itérer avec des boucles basées sur un compteur.

```c
// Boucle for traditionnelle
for (int i = 0; i < 10; i++) {
    printf("%d ", i);
}
// Itération de tableau
int numbers[] = {1, 2, 3, 4, 5};
int size = sizeof(numbers) / sizeof(numbers[0]);
for (int i = 0; i < size; i++) {
    printf("%d ", numbers[i]);
}
// Boucles imbriquées
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        printf("%d,%d ", i, j);
    }
}
```

<BaseQuiz id="c-for-loop-1" correct="A">
  <template #question>
    Que calcule <code>sizeof(numbers) / sizeof(numbers[0])</code> ?
  </template>
  
  <BaseQuizOption value="A" correct>Le nombre d'éléments dans le tableau</BaseQuizOption>
  <BaseQuizOption value="B">La taille mémoire totale du tableau</BaseQuizOption>
  <BaseQuizOption value="C">L'indice du dernier élément</BaseQuizOption>
  <BaseQuizOption value="D">La taille d'un élément</BaseQuizOption>
  
  <BaseQuizAnswer>
    Cette expression calcule la longueur du tableau en divisant la taille totale du tableau par la taille d'un élément. C'est une idiome C courante car les tableaux ne stockent pas leur longueur.
  </BaseQuizAnswer>
</BaseQuiz>

### Boucles While

Itération basée sur une condition.

```c
// Boucle While
int count = 0;
while (count < 5) {
    printf("%d\n", count);
    count++;
}
// Boucle Do-while (s'exécute au moins une fois)
int input;
do {
    printf("Entrez un nombre (0 pour quitter) : ");
    scanf("%d", &input);
} while (input != 0);
```

### Contrôle de Boucle

Instructions `break` et `continue`.

```c
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // Sauter l'itération
    }
    if (i == 7) {
        break;    // Quitter la boucle
    }
    printf("%d ", i);
}
// Boucles imbriquées avec break
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // Ne brise que la boucle interne
        printf("%d,%d ", i, j);
    }
}
```

## Fonctions

### Déclaration et Définition de Fonction

Créer des blocs de code réutilisables.

```c
// Déclaration de fonction (prototype)
int add(int a, int b);
void printMessage(char* msg);
// Définition de fonction
int add(int a, int b) {
    return a + b;
}
void printMessage(char* msg) {
    printf("%s\n", msg);
}
// Appel de fonction
int result = add(5, 3);
printMessage("Hello, functions!");
```

### Passage de Tableaux aux Fonctions

Fonctions qui travaillent avec des tableaux.

```c
// Tableau comme paramètre (pointeur)
void printArray(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}
// Modification des éléments du tableau
void doubleValues(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;
    }
}
```

### Fonctions Récursives

Fonctions qui s'appellent elles-mêmes.

```c
// Calcul de factorielle
int factorial(int n) {
    if (n <= 1) {
        return 1;  // Cas de base
    }
    return n * factorial(n - 1);
}
// Suite de Fibonacci
int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }
    return fibonacci(n-1) + fibonacci(n-2);
}
```

### Pointeurs de Fonction

Pointeurs vers des fonctions pour un comportement dynamique.

```c
// Déclaration de pointeur de fonction
int (*operation)(int, int);
// Assignation de fonction au pointeur
operation = add;
int result = operation(5, 3);
// Tableau de pointeurs de fonction
int (*operations[])(int, int) = {add, subtract, multiply};
result = operations[0](10, 5);
```

## Pointeurs et Gestion de la Mémoire

### Bases des Pointeurs

Déclarer et utiliser des pointeurs pour accéder aux adresses mémoire.

```c
int x = 10;
int *ptr = &x;  // Pointeur vers x
printf("Valeur de x: %d\n", x);
printf("Adresse de x: %p\n", &x);
printf("Valeur de ptr: %p\n", ptr);
printf("Valeur pointée par ptr: %d\n", *ptr);
// Modifier la valeur via le pointeur
*ptr = 20;
printf("Nouvelle valeur de x: %d\n", x);
// Pointeur nul
int *null_ptr = NULL;
```

### Tableaux et Pointeurs

Relation entre les tableaux et les pointeurs.

```c
int arr[5] = {1, 2, 3, 4, 5};
int *p = arr;  // Pointeur vers le premier élément
// Notation tableau vs arithmétique de pointeur
printf("%d\n", arr[2]);   // Notation tableau
printf("%d\n", *(p + 2)); // Arithmétique de pointeur
printf("%d\n", p[2]);     // Pointeur comme tableau
// Itérer en utilisant un pointeur
for (int i = 0; i < 5; i++) {
    printf("%d ", *(p + i));
}
```

### Allocation Dynamique de Mémoire

Allouer et libérer de la mémoire à l'exécution.

```c
#include <stdlib.h>
// Allouer de la mémoire pour un seul entier
int *ptr = (int*)malloc(sizeof(int));
if (ptr != NULL) {
    *ptr = 42;
    printf("Valeur: %d\n", *ptr);
    free(ptr);  // Toujours libérer la mémoire allouée
}
// Allouer un tableau dynamiquement
int *arr = (int*)malloc(10 * sizeof(int));
if (arr != NULL) {
    for (int i = 0; i < 10; i++) {
        arr[i] = i * i;
    }
    free(arr);
}
```

### Pointeurs de Chaînes

Travailler avec des chaînes et des pointeurs de caractères.

```c
// Littéraux de chaîne et pointeurs
char *str1 = "Hello";           // Littéral de chaîne
char str2[] = "World";          // Tableau de caractères
char *str3 = (char*)malloc(20); // Chaîne dynamique
// Fonctions de chaîne
strcpy(str3, "Dynamic");
printf("Longueur: %lu\n", strlen(str1));
printf("Comparaison: %d\n", strcmp(str1, str2));
strcat(str2, "!");
// Toujours libérer les chaînes dynamiques
free(str3);
```

## Structures et Types Définis par l'Utilisateur

### Définition de Structure

Définir des types de données personnalisés avec plusieurs champs.

```c
// Définition de structure
struct Rectangle {
    double width;
    double height;
};
// Structure avec typedef
typedef struct {
    char name[50];
    int age;
    double gpa;
} Student;
// Créer et initialiser des structures
struct Rectangle rect1 = {5.0, 3.0};
Student student1 = {"Alice", 20, 3.75};
// Accéder aux membres de la structure
printf("Aire: %.2f\n", rect1.width * rect1.height);
printf("Étudiant: %s, Âge: %d\n", student1.name, student1.age);
```

### Structures Imbriquées

Structures contenant d'autres structures.

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
printf("Né le : %d/%d/%d\n",
       emp.birthdate.day,
       emp.birthdate.month,
       emp.birthdate.year);
```

### Pointeurs vers des Structures

Utiliser des pointeurs pour accéder et modifier des structures.

```c
Student *student_ptr = &student1;
// Accès en utilisant un pointeur (deux méthodes)
printf("Nom: %s\n", (*student_ptr).name);
printf("Âge: %d\n", student_ptr->age);
// Modification via pointeur
student_ptr->age = 21;
strcpy(student_ptr->name, "Alice Johnson");
// Allocation dynamique de structure
Student *new_student = (Student*)malloc(sizeof(Student));
if (new_student != NULL) {
    strcpy(new_student->name, "Bob");
    new_student->age = 19;
    new_student->gpa = 3.2;
    free(new_student);
}
```

### Unions et Enums

Méthodes alternatives d'organisation des données.

```c
// Union - espace mémoire partagé
union Data {
    int integer;
    float floating;
    char character;
};
union Data data;
data.integer = 42;
printf("Entier: %d\n", data.integer);
// Énumération
enum Weekday {
    MONDAY, TUESDAY, WEDNESDAY,
    THURSDAY, FRIDAY, SATURDAY, SUNDAY
};
enum Weekday today = FRIDAY;
printf("Aujourd'hui est le jour %d\n", today);
```

## Opérations d'Entrée/Sortie de Fichiers

### Lecture de Fichiers

Lire des données à partir de fichiers texte.

```c
#include <stdio.h>
// Lire le fichier entier caractère par caractère
FILE *file = fopen("data.txt", "r");
if (file != NULL) {
    int ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}
// Lire ligne par ligne
FILE *file2 = fopen("lines.txt", "r");
char buffer[256];
while (fgets(buffer, sizeof(buffer), file2) != NULL) {
    printf("Ligne: %s", buffer);
}
fclose(file2);
// Lire des données formatées
FILE *numbers = fopen("numbers.txt", "r");
int num;
while (fscanf(numbers, "%d", &num) == 1) {
    printf("Nombre: %d\n", num);
}
fclose(numbers);
```

### Vérification des Erreurs

Gérer les opérations de fichiers en toute sécurité.

```c
FILE *file = fopen("data.txt", "r");
if (file == NULL) {
    printf("Erreur lors de l'ouverture du fichier !\n");
    perror("fopen");  // Afficher le message d'erreur système
    return 1;
}
// Vérifier les erreurs de lecture
if (ferror(file)) {
    printf("Erreur lors de la lecture du fichier !\n");
}
// Vérifier la fin du fichier
if (feof(file)) {
    printf("Fin du fichier atteinte\n");
}
fclose(file);
```

### Écriture de Fichiers

Écrire des données dans des fichiers texte.

```c
// Écrire dans un fichier
FILE *outfile = fopen("output.txt", "w");
if (outfile != NULL) {
    fprintf(outfile, "Hello, file!\n");
    fprintf(outfile, "Nombre: %d\n", 42);
    fclose(outfile);
}
// Ajouter à un fichier existant
FILE *appendfile = fopen("log.txt", "a");
if (appendfile != NULL) {
    fprintf(appendfile, "Nouvelle entrée de journal\n");
    fclose(appendfile);
}
// Écrire un tableau dans un fichier
int numbers[] = {1, 2, 3, 4, 5};
FILE *numfile = fopen("numbers.txt", "w");
for (int i = 0; i < 5; i++) {
    fprintf(numfile, "%d ", numbers[i]);
}
fclose(numfile);
```

### Opérations sur Fichiers Binaires

Lire et écrire des données binaires efficacement.

```c
// Écrire des données binaires
Student students[3] = {
    {"Alice", 20, 3.75},
    {"Bob", 21, 3.2},
    {"Charlie", 19, 3.9}
};
FILE *binfile = fopen("students.bin", "wb");
fwrite(students, sizeof(Student), 3, binfile);
fclose(binfile);
// Lire des données binaires
Student loaded_students[3];
FILE *readbin = fopen("students.bin", "rb");
fread(loaded_students, sizeof(Student), 3, readbin);
fclose(readbin);
```

## Manipulation de Chaînes

### Fonctions de Chaîne

Opérations courantes de chaîne issues de la bibliothèque string.h.

```c
#include <string.h>
char str1[50] = "Hello";
char str2[] = "World";
char dest[100];
// Longueur de la chaîne
int len = strlen(str1);
printf("Longueur: %d\n", len);
// Copie de chaîne
strcpy(dest, str1);
strncpy(dest, str1, 10); // Copier les 10 premiers caractères
// Concaténation de chaînes
strcat(dest, " ");
strcat(dest, str2);
strncat(dest, "!", 1);   // Ajouter 1 caractère
// Comparaison de chaînes
int result = strcmp(str1, str2);
if (result == 0) {
    printf("Les chaînes sont égales\n");
}
```

### Recherche de Chaînes

Trouver des sous-chaînes et des caractères dans des chaînes.

```c
char text[] = "The quick brown fox";
char *ptr;
// Trouver la première occurrence d'un caractère
ptr = strchr(text, 'q');
if (ptr != NULL) {
    printf("Trouvé 'q' à la position: %ld\n", ptr - text);
}
// Trouver la dernière occurrence
ptr = strrchr(text, 'o');
printf("Dernier 'o' à la position: %ld\n", ptr - text);
// Trouver une sous-chaîne
ptr = strstr(text, "brown");
if (ptr != NULL) {
    printf("Trouvé 'brown' à : %s\n", ptr);
}
```

### Conversion de Chaînes

Convertir des chaînes en nombres et vice versa.

```c
#include <stdlib.h>
// Conversion chaîne en nombre
char num_str[] = "12345";
char float_str[] = "3.14159";
int num = atoi(num_str);
long long_num = atol(num_str);
double float_num = atof(float_str);
printf("Entier: %d\n", num);
printf("Long: %ld\n", long_num);
printf("Double: %.2f\n", float_num);
// Nombre en chaîne (en utilisant sprintf)
char buffer[50];
sprintf(buffer, "%d", 42);
sprintf(buffer, "%.2f", 3.14159);
printf("Chaîne: %s\n", buffer);
```

### Traitement Personnalisé de Chaînes

Techniques manuelles de manipulation de chaînes.

```c
// Compter les caractères dans une chaîne
int countChar(char *str, char target) {
    int count = 0;
    while (*str) {
        if (*str == target) count++;
        str++;
    }
    return count;
}
// Inverser une chaîne sur place
void reverseString(char *str) {
    int len = strlen(str);
    for (int i = 0; i < len/2; i++) {
        char temp = str[i];
        str[i] = str[len-1-i];
        str[len-1-i] = temp;
    }
}
```

## Processus de Compilation et de Construction

### Compilation GCC

GNU Compiler Collection pour C.

```bash
# Compilation de base
gcc -o program main.c
# Avec informations de débogage
gcc -g -o program main.c
# Niveaux d'optimisation
gcc -O2 -o program main.c
# Fichiers source multiples
gcc -o program main.c utils.c math.c
# Inclure des répertoires supplémentaires
gcc -I/usr/local/include -o program main.c
# Lier des bibliothèques
gcc -o program main.c -lm -lpthread
```

### Normes C

Compiler avec des versions standard C spécifiques.

```bash
# Standard C90/C89 (ANSI C)
gcc -std=c89 -o program main.c
# Standard C99
gcc -std=c99 -o program main.c
# Standard C11 (recommandé)
gcc -std=c11 -o program main.c
# Standard C18 (le plus récent)
gcc -std=c18 -o program main.c
# Activer tous les avertissements
gcc -Wall -Wextra -std=c11 -o program main.c
```

### Bases de Makefile

Automatiser la compilation avec l'utilitaire make.

```makefile
# Makefile simple
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

## Bonnes Pratiques et Conseils

### Conventions de Nommage

Un nommage cohérent rend le code plus lisible.

```c
// Variables et fonctions : snake_case
int student_count;
double calculate_average(int scores[], int size);
// Constantes : MAJUSCULES_AVEC_UNDERSCORES
#define MAX_BUFFER_SIZE 1024
#define PI 3.14159
// Structures : PascalCase ou snake_case
typedef struct {
    char name[50];
    int age;
} Student;
// Variables globales : préfixées par g_
int g_total_count = 0;
// Paramètres de fonction : noms clairs
void process_data(int *input_array, int array_size);
```

### Sécurité de la Mémoire

Prévenir les bugs courants liés à la mémoire.

```c
// Toujours initialiser les variables
int count = 0;        // Bien
int count;            // Dangereux - non initialisé
// Vérifier la valeur de retour de malloc
int *ptr = malloc(sizeof(int) * 10);
if (ptr == NULL) {
    printf("Échec de l'allocation mémoire !\n");
    return -1;
}
// Toujours libérer la mémoire allouée
free(ptr);
ptr = NULL;  // Empêcher la réutilisation accidentelle
// Vérification des limites de tableau
for (int i = 0; i < array_size; i++) {
    // Accès sécurisé au tableau
    array[i] = i;
}
```

### Conseils de Performance

Écrire du code C efficace.

```c
// Utiliser les types de données appropriés
char small_num = 10;   // Pour les petites valeurs
int normal_num = 1000; // Pour les entiers typiques
// Minimiser les appels de fonction dans les boucles
int len = strlen(str); // Calculer une seule fois
for (int i = 0; i < len; i++) {
    // Traiter la chaîne
}
// Utiliser register pour les variables fréquemment accédées
register int counter;
// Préférer les tableaux à l'allocation dynamique lorsque la taille est connue
int fixed_array[100];  // Allocation sur la pile
// vs
int *dynamic_array = malloc(100 * sizeof(int));
```

### Organisation du Code

Structurer le code pour la maintenabilité.

```c
// Fichier d'en-tête (utils.h)
#ifndef UTILS_H
#define UTILS_H
// Prototypes de fonctions
double calculate_area(double radius);
int fibonacci(int n);
// Définitions de structures
typedef struct {
    int x, y;
} Point;
#endif // UTILS_H
// Fichier d'implémentation (utils.c)
#include "utils.h"
#include <math.h>
double calculate_area(double radius) {
    return M_PI * radius * radius;
}
```

## Liens Pertinents

- <router-link to="/cpp">Feuille de triche C++</router-link>
- <router-link to="/java">Feuille de triche Java</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/golang">Feuille de triche Golang</router-link>
- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>

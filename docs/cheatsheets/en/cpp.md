---
title: 'C++ Cheatsheet | LabEx'
description: 'Learn C++ programming with this comprehensive cheatsheet. Quick reference for C++ syntax, OOP, STL, templates, memory management, and modern C++ features for software developers.'
pdfUrl: '/cheatsheets/pdf/cpp-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
C++ Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/cpp">Learn C++ with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn C++ programming through hands-on labs and real-world scenarios. LabEx provides comprehensive C++ courses covering essential syntax, object-oriented programming, STL containers, memory management, and advanced techniques. Master C++'s powerful features to build high-performance applications and systems software.
</base-disclaimer-content>
</base-disclaimer>

## Basic Syntax & Structure

### Hello World Program

Basic structure of a C++ program.

```cpp
#include <iostream>
using namespace std;
int main() {
    cout << "Hello, World!" << endl;
    return 0;
}
```

### Headers & Namespaces

Include libraries and manage namespaces.

```cpp
#include <iostream>  // Input/output stream
#include <vector>    // Dynamic arrays
#include <string>    // String class
#include <algorithm> // STL algorithms
using namespace std;
// Or specify individually:
// using std::cout;
// using std::cin;
```

### Comments

Single-line and multi-line comments.

```cpp
// Single-line comment
/*
Multi-line comment
spans multiple lines
*/
// TODO: Implement feature
/* FIXME: Bug in this section */
```

### Main Function

Program entry point with return values.

```cpp
int main() {
    // Program code here
    return 0;  // Success
}
int main(int argc, char* argv[]) {
    // argc: argument count
    // argv: argument values (command line)
    return 0;
}
```

<BaseQuiz id="cpp-main-1" correct="B">
  <template #question>
    What is the difference between C and C++ output statements?
  </template>
  
  <BaseQuizOption value="A">There is no difference</BaseQuizOption>
  <BaseQuizOption value="B" correct>C uses printf(), C++ uses cout with << operator</BaseQuizOption>
  <BaseQuizOption value="C">C++ doesn't support output</BaseQuizOption>
  <BaseQuizOption value="D">C uses cout, C++ uses printf</BaseQuizOption>
  
  <BaseQuizAnswer>
    C uses <code>printf()</code> from stdio.h, while C++ uses <code>cout</code> from iostream with the stream insertion operator <code><<</code>. C++ also supports printf for compatibility.
  </BaseQuizAnswer>
</BaseQuiz>

### Basic Output

Display text and variables to console.

```cpp
cout << "Hello" << endl;
cout << "Value: " << 42 << endl;
// Multiple values in one line
cout << "Name: " << name << ", Age: " << age << endl;
```

### Basic Input

Read user input from console.

```cpp
int age;
string name;
cin >> age;
cin >> name;
// Read entire line with spaces
getline(cin, name);
```

## Data Types & Variables

### Primitive Types

Basic data types for storing different kinds of values.

```cpp
// Integer types
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// Floating-point types
float price = 19.99f;
double precise = 3.14159265359;
// Character and boolean
char grade = 'A';
bool is_valid = true;
```

### String & Arrays

Text and collection data types.

```cpp
// Strings
string name = "John Doe";
string empty_str;
// Arrays
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// Dynamic arrays (vectors)
vector<int> dynamic_array = {10, 20, 30};
vector<string> names(5); // Size 5, empty strings
```

<BaseQuiz id="cpp-vector-1" correct="B">
  <template #question>
    What is the main advantage of <code>vector</code> over regular arrays in C++?
  </template>
  
  <BaseQuizOption value="A">Vectors are faster</BaseQuizOption>
  <BaseQuizOption value="B" correct>Vectors can dynamically resize, while arrays have fixed size</BaseQuizOption>
  <BaseQuizOption value="C">Vectors use less memory</BaseQuizOption>
  <BaseQuizOption value="D">There is no advantage</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>vector</code> is a dynamic array that can grow or shrink at runtime, unlike regular arrays which have a fixed size determined at compile time. This makes vectors more flexible for many use cases.
  </BaseQuizAnswer>
</BaseQuiz>

### Constants & Auto

Immutable values and automatic type deduction.

```cpp
// Constants
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Auto keyword (C++11+)
auto x = 42;        // int
auto y = 3.14;      // double
auto name = "John"; // const char*
// Type aliases
typedef unsigned int uint;
using real = double;
```

## Control Flow Structures

### Conditional Statements

Make decisions based on conditions.

```cpp
// If-else statement
if (age >= 18) {
    cout << "Adult" << endl;
} else if (age >= 13) {
    cout << "Teenager" << endl;
} else {
    cout << "Child" << endl;
}
// Ternary operator
string status = (age >= 18) ? "Adult" : "Minor";
// Switch statement
switch (grade) {
    case 'A':
        cout << "Excellent!" << endl;
        break;
    case 'B':
        cout << "Good job!" << endl;
        break;
    default:
        cout << "Keep trying!" << endl;
}
```

### For Loops

Iterate with counter-based loops.

```cpp
// Traditional for loop
for (int i = 0; i < 10; i++) {
    cout << i << " ";
}
// Range-based for loop (C++11+)
vector<int> numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    cout << num << " ";
}
// Auto with range-based loop
for (auto& item : container) {
    // Process item
}
```

<BaseQuiz id="cpp-range-for-1" correct="B">
  <template #question>
    What is a range-based for loop in C++?
  </template>
  
  <BaseQuizOption value="A">A loop that only works with arrays</BaseQuizOption>
  <BaseQuizOption value="B" correct>A loop that iterates over all elements in a container automatically</BaseQuizOption>
  <BaseQuizOption value="C">A loop that runs forever</BaseQuizOption>
  <BaseQuizOption value="D">A loop that requires manual index management</BaseQuizOption>
  
  <BaseQuizAnswer>
    Range-based for loops (introduced in C++11) automatically iterate over all elements in a container (like vectors, arrays, strings) without needing to manage indices manually. The syntax is <code>for (auto item : container)</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### While Loops

Condition-based iteration.

```cpp
// While loop
int count = 0;
while (count < 5) {
    cout << count << endl;
    count++;
}
// Do-while loop (executes at least once)
int input;
do {
    cout << "Enter a number (0 to quit): ";
    cin >> input;
} while (input != 0);
```

### Loop Control

Break and continue statements.

```cpp
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // Skip iteration
    }
    if (i == 7) {
        break;    // Exit loop
    }
    cout << i << " ";
}
// Nested loops with labeled break
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // Break inner loop only
        cout << i << "," << j << " ";
    }
}
```

## Functions

### Function Declaration & Definition

Create reusable code blocks.

```cpp
// Function declaration (prototype)
int add(int a, int b);
void printMessage(string msg);
// Function definition
int add(int a, int b) {
    return a + b;
}
void printMessage(string msg) {
    cout << msg << endl;
}
// Function call
int result = add(5, 3);
printMessage("Hello, functions!");
```

### Function Overloading

Multiple functions with the same name.

```cpp
// Different parameter types
int multiply(int a, int b) {
    return a * b;
}
double multiply(double a, double b) {
    return a * b;
}
// Different number of parameters
int multiply(int a, int b, int c) {
    return a * b * c;
}
```

### Default Parameters

Provide default values for function parameters.

```cpp
void greet(string name, string greeting = "Hello") {
    cout << greeting << ", " << name << "!" << endl;
}
// Function calls
greet("Alice");              // Uses default "Hello"
greet("Bob", "Good morning"); // Uses custom greeting
```

### Pass by Reference

Modify variables through function parameters.

```cpp
// Pass by value (copy)
void changeValue(int x) {
    x = 100; // Original variable unchanged
}
// Pass by reference
void changeReference(int& x) {
    x = 100; // Original variable modified
}
// Const reference (read-only, efficient)
void processLargeData(const vector<int>& data) {
    // Can read data but not modify
}
```

## Object-Oriented Programming

### Class Definition

Define custom data types with attributes and methods.

```cpp
class Rectangle {
private:
    double width, height;
public:
    // Constructor
    Rectangle(double w, double h) : width(w), height(h) {}

    // Default constructor
    Rectangle() : width(0), height(0) {}

    // Member functions
    double area() const {
        return width * height;
    }

    void setDimensions(double w, double h) {
        width = w;
        height = h;
    }

    // Getter functions
    double getWidth() const { return width; }
    double getHeight() const { return height; }
};
```

### Object Creation & Usage

Instantiate and use class objects.

```cpp
// Create objects
Rectangle rect1(5.0, 3.0);
Rectangle rect2; // Default constructor
// Use member functions
cout << "Area: " << rect1.area() << endl;
rect2.setDimensions(4.0, 2.0);
// Dynamic allocation
Rectangle* rect3 = new Rectangle(6.0, 4.0);
cout << rect3->area() << endl;
delete rect3; // Clean up memory
```

### Inheritance

Create specialized classes from base classes.

```cpp
class Shape {
protected:
    string color;

public:
    Shape(string c) : color(c) {}
    virtual double area() const = 0; // Pure virtual
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

### Polymorphism

Use base class pointers to access derived objects.

```cpp
// Virtual functions and polymorphism
vector<Shape*> shapes;
shapes.push_back(new Circle(5.0, "red"));
shapes.push_back(new Rectangle(4.0, 6.0));
for (Shape* shape : shapes) {
    cout << "Area: " << shape->area() << endl;
    // Calls appropriate derived class method
}
```

## Memory Management

### Dynamic Memory Allocation

Allocate and deallocate memory at runtime.

```cpp
// Single object
int* ptr = new int(42);
cout << *ptr << endl;
delete ptr;
ptr = nullptr;
// Array allocation
int* arr = new int[10];
for (int i = 0; i < 10; i++) {
    arr[i] = i * i;
}
delete[] arr;
// Check for allocation failure
int* large_array = new(nothrow) int[1000000];
if (large_array == nullptr) {
    cout << "Allocation failed!" << endl;
}
```

### Smart Pointers (C++11+)

Automatic memory management with RAII.

```cpp
#include <memory>
// unique_ptr (exclusive ownership)
unique_ptr<int> ptr1 = make_unique<int>(42);
unique_ptr<int> ptr2 = move(ptr1); // Transfer ownership
// shared_ptr (shared ownership)
shared_ptr<int> sptr1 = make_shared<int>(100);
shared_ptr<int> sptr2 = sptr1; // Share ownership
cout << sptr1.use_count() << endl; // Reference count
```

### References vs Pointers

Two ways to indirectly access objects.

```cpp
int x = 10;
// Reference (alias)
int& ref = x;  // Must be initialized
ref = 20;      // Changes x to 20
// Pointer
int* ptr = &x; // Points to address of x
*ptr = 30;     // Dereference and change x
ptr = nullptr; // Can point to nothing
// Const variations
const int* ptr1 = &x;    // Can't change value
int* const ptr2 = &x;    // Can't change address
const int* const ptr3 = &x; // Can't change either
```

### Stack vs Heap

Memory allocation strategies.

```cpp
// Stack allocation (automatic)
int stack_var = 42;
int stack_array[100];
// Heap allocation (dynamic)
int* heap_var = new int(42);
int* heap_array = new int[100];
// Stack objects cleaned up automatically
// Heap objects must be deleted manually
delete heap_var;
delete[] heap_array;
```

## Standard Template Library (STL)

### Containers: Vector & String

Dynamic arrays and string manipulation.

```cpp
#include <vector>
#include <string>
// Vector operations
vector<int> nums = {1, 2, 3};
nums.push_back(4);        // Add element
nums.pop_back();          // Remove last
nums.insert(nums.begin() + 1, 10); // Insert at position
nums.erase(nums.begin()); // Remove first
// String operations
string text = "Hello";
text += " World";         // Concatenation
text.append("!");         // Append
cout << text.substr(0, 5) << endl; // Substring
text.replace(6, 5, "C++"); // Replace "World" with "C++"
```

### Containers: Map & Set

Associative containers for key-value pairs and unique elements.

```cpp
#include <map>
#include <set>
// Map (key-value pairs)
map<string, int> ages;
ages["Alice"] = 25;
ages["Bob"] = 30;
ages.insert({"Charlie", 35});
// Set (unique elements)
set<int> unique_nums = {3, 1, 4, 1, 5, 9};
unique_nums.insert(2);
unique_nums.erase(1);
// Automatically sorted: {2, 3, 4, 5, 9}
```

### Algorithms

STL algorithms for common operations.

```cpp
#include <algorithm>
vector<int> nums = {64, 34, 25, 12, 22, 11, 90};
// Sorting
sort(nums.begin(), nums.end());
sort(nums.rbegin(), nums.rend()); // Reverse sort
// Searching
auto it = find(nums.begin(), nums.end(), 25);
if (it != nums.end()) {
    cout << "Found at position: " << it - nums.begin();
}
// Other useful algorithms
reverse(nums.begin(), nums.end());
int max_val = *max_element(nums.begin(), nums.end());
int count = count_if(nums.begin(), nums.end(),
                    [](int x) { return x > 50; });
```

### Iterators

Navigate through containers efficiently.

```cpp
vector<string> words = {"hello", "world", "cpp"};
// Iterator types
vector<string>::iterator it;
auto it2 = words.begin(); // C++11 auto
// Iterate through container
for (it = words.begin(); it != words.end(); ++it) {
    cout << *it << " ";
}
// Range-based loop (preferred)
for (const auto& word : words) {
    cout << word << " ";
}
```

## Input/Output Operations

### File Input: Reading Files

Read data from text files.

```cpp
#include <fstream>
#include <sstream>
// Read entire file
ifstream file("data.txt");
if (file.is_open()) {
    string line;
    while (getline(file, line)) {
        cout << line << endl;
    }
    file.close();
}
// Read word by word
ifstream file2("numbers.txt");
int number;
while (file2 >> number) {
    cout << number << " ";
}
// Read with error checking
if (!file.good()) {
    cerr << "Error reading file!" << endl;
}
```

### String Stream Processing

Parse and manipulate strings as streams.

```cpp
#include <sstream>
// Parse comma-separated values
string data = "apple,banana,cherry";
stringstream ss(data);
string item;
vector<string> fruits;
while (getline(ss, item, ',')) {
    fruits.push_back(item);
}
// Convert strings to numbers
string num_str = "123";
int num = stoi(num_str);
double d = stod("3.14159");
string back_to_str = to_string(num);
```

### File Output: Writing Files

Write data to text files.

```cpp
// Write to file
ofstream outfile("output.txt");
if (outfile.is_open()) {
    outfile << "Hello, file!" << endl;
    outfile << "Number: " << 42 << endl;
    outfile.close();
}
// Append to existing file
ofstream appendfile("log.txt", ios::app);
appendfile << "New log entry" << endl;
// Write vector to file
vector<int> numbers = {1, 2, 3, 4, 5};
ofstream numfile("numbers.txt");
for (int num : numbers) {
    numfile << num << " ";
}
```

### Stream Formatting

Control output format and precision.

```cpp
#include <iomanip>
double pi = 3.14159265;
cout << fixed << setprecision(2) << pi << endl; // 3.14
cout << setw(10) << "Right" << endl;          // Right-aligned
cout << left << setw(10) << "Left" << endl;     // Left-aligned
cout << hex << 255 << endl;                    // Hexadecimal: ff
```

## Error Handling

### Try-Catch Blocks

Handle exceptions that may occur during execution.

```cpp
try {
    int result = 10 / 0; // This might throw an exception
    vector<int> vec(5);
    vec.at(10) = 100;    // Out of bounds access

} catch (const exception& e) {
    cout << "Exception caught: " << e.what() << endl;
} catch (...) {
    cout << "Unknown exception caught!" << endl;
}
// Specific exception types
try {
    string str = "abc";
    int num = stoi(str); // Throws invalid_argument
} catch (const invalid_argument& e) {
    cout << "Invalid argument: " << e.what() << endl;
} catch (const out_of_range& e) {
    cout << "Out of range: " << e.what() << endl;
}
```

### Throwing Custom Exceptions

Create and throw your own exceptions.

```cpp
// Custom exception class
class CustomException : public exception {
    string message;
public:
    CustomException(const string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};
// Function that throws exception
void validateAge(int age) {
    if (age < 0 || age > 150) {
        throw CustomException("Invalid age range!");
    }
}
// Usage
try {
    validateAge(-5);
} catch (const CustomException& e) {
    cout << e.what() << endl;
}
```

### RAII Pattern

Resource Acquisition Is Initialization for safe resource management.

```cpp
// RAII with smart pointers
{
    unique_ptr<int[]> arr = make_unique<int[]>(1000);
    // Array automatically deleted when out of scope
}
// RAII with file handling
{
    ifstream file("data.txt");
    // File automatically closed when out of scope
    if (file.is_open()) {
        // Process file
    }
}
// Custom RAII class
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

Debug and validate program assumptions.

```cpp
#include <cassert>
#include <iostream>
void processArray(int* arr, int size) {
    assert(arr != nullptr);  // Debug assertion
    assert(size > 0);        // Validates assumption

    // Process array...
}
// Conditional compilation for debug output
#ifdef DEBUG
    #define DBG_PRINT(x) cout << "DEBUG: " << x << endl
#else
    #define DBG_PRINT(x)
#endif
// Usage
DBG_PRINT("Starting function");
```

## Compilation & Build Process

### GCC/G++ Compilation

GNU Compiler Collection for C++.

```bash
# Basic compilation
g++ -o program main.cpp
# With debugging information
g++ -g -o program main.cpp
# Optimization levels
g++ -O2 -o program main.cpp
# Multiple source files
g++ -o program main.cpp utils.cpp math.cpp
# Include additional directories
g++ -I/usr/local/include -o program main.cpp
# Link libraries
g++ -o program main.cpp -lm -lpthread
```

### Modern C++ Standards

Compile with specific C++ standard versions.

```bash
# C++11 standard
g++ -std=c++11 -o program main.cpp
# C++14 standard
g++ -std=c++14 -o program main.cpp
# C++17 standard (recommended)
g++ -std=c++17 -o program main.cpp
# C++20 standard (latest)
g++ -std=c++20 -o program main.cpp
# Enable all warnings
g++ -Wall -Wextra -std=c++17 -o program main.cpp
```

### Makefile Basics

Automate compilation with make utility.

```makefile
# Simple Makefile
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

## Best Practices & Tips

### Naming Conventions

Consistent naming makes code more readable.

```cpp
// Variables and functions: snake_case or camelCase
int student_count;
int studentCount;
void calculateAverage();
// Constants: UPPER_CASE
const int MAX_BUFFER_SIZE = 1024;
const double PI = 3.14159;
// Classes: PascalCase
class StudentRecord {
    // Member variables: prefix with m_ or trailing _
    string m_name;
    int age_;

public:
    // Public interface
    void setName(const string& name);
    string getName() const;
};
```

### Memory Safety

Prevent common memory-related bugs.

```cpp
// Use smart pointers instead of raw pointers
auto ptr = make_unique<int>(42);
auto shared = make_shared<vector<int>>(10);
// Initialize variables
int count = 0;        // Good
int count;            // Dangerous - uninitialized
// Range-based loops are safer
for (const auto& item : container) {
    // Process item safely
}
// Check pointer validity
if (ptr != nullptr) {
    // Safe to dereference
}
```

### Performance Tips

Write efficient C++ code.

```cpp
// Pass large objects by const reference
void processData(const vector<int>& data) {
    // Avoid copying large objects
}
// Use pre-increment for iterators
for (auto it = vec.begin(); it != vec.end(); ++it) {
    // ++it is often faster than it++
}
// Reserve vector capacity when size is known
vector<int> numbers;
numbers.reserve(1000); // Avoid reallocations
// Use emplace instead of push for objects
vector<string> words;
words.emplace_back("Hello"); // Construct in-place
words.push_back(string("World")); // Construct then copy
```

### Code Organization

Structure code for maintainability.

```cpp
// Header file (utils.h)
#ifndef UTILS_H
#define UTILS_H
class MathUtils {
public:
    static double calculateArea(double radius);
    static int fibonacci(int n);
};
#endif // UTILS_H
// Implementation file (utils.cpp)
#include "utils.h"
#include <cmath>
double MathUtils::calculateArea(double radius) {
    return M_PI * radius * radius;
}
// Use const member functions when possible
double getRadius() const { return radius; }
```

## Relevant Links

- <router-link to="/c-programming">C Programming Cheatsheet</router-link>
- <router-link to="/java">Java Cheatsheet</router-link>
- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/javascript">JavaScript Cheatsheet</router-link>
- <router-link to="/golang">Golang Cheatsheet</router-link>
- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/shell">Shell Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>

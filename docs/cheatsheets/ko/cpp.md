---
title: 'C++ 치트 시트 | LabEx'
description: '이 포괄적인 치트 시트로 C++ 프로그래밍을 학습하세요. 소프트웨어 개발자를 위한 C++ 구문, OOP, STL, 템플릿, 메모리 관리 및 최신 C++ 기능에 대한 빠른 참조입니다.'
pdfUrl: '/cheatsheets/pdf/cpp-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
C++ 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/cpp">Hands-On 실습으로 C++ 배우기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 C++ 프로그래밍을 배우십시오. LabEx 는 필수 구문, 객체 지향 프로그래밍, STL 컨테이너, 메모리 관리 및 고급 기술을 다루는 포괄적인 C++ 강좌를 제공합니다. C++ 의 강력한 기능을 마스터하여 고성능 애플리케이션 및 시스템 소프트웨어를 구축하십시오.
</base-disclaimer-content>
</base-disclaimer>

## 기본 구문 및 구조

### Hello World 프로그램

C++ 프로그램의 기본 구조.

```cpp
#include <iostream>
using namespace std;
int main() {
    cout << "Hello, World!" << endl;
    return 0;
}
```

### 헤더 및 네임스페이스

라이브러리 포함 및 네임스페이스 관리.

```cpp
#include <iostream>  // 입출력 스트림
#include <vector>    // 동적 배열
#include <string>    // 문자열 클래스
#include <algorithm> // STL 알고리즘
using namespace std;
// 또는 개별적으로 지정:
// using std::cout;
// using std::cin;
```

### 주석

단일 행 및 다중 행 주석.

```cpp
// 단일 행 주석
/*
다중 행 주석은
여러 줄에 걸쳐 있습니다
*/
// TODO: 기능 구현
/* FIXME: 이 섹션의 버그 */
```

### 메인 함수

반환 값이 있는 프로그램 진입점.

```cpp
int main() {
    // 여기에 프로그램 코드
    return 0;  // 성공
}
int main(int argc, char* argv[]) {
    // argc: 인수 개수
    // argv: 인수 값 (명령줄)
    return 0;
}
```

<BaseQuiz id="cpp-main-1" correct="B">
  <template #question>
    C 와 C++ 출력문 간의 차이점은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">차이점이 없습니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>C 는 printf() 를 사용하고, C++ 는 << 연산자와 함께 cout 을 사용합니다</BaseQuizOption>
  <BaseQuizOption value="C">C++ 는 출력을 지원하지 않습니다</BaseQuizOption>
  <BaseQuizOption value="D">C 는 cout 을 사용하고, C++ 는 printf 를 사용합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    C 는 stdio.h 에서 `printf()`를 사용하는 반면, C++ 는 iostream 에서 스트림 삽입 연산자 `<<`와 함께 `cout`을 사용합니다. C++ 는 호환성을 위해 printf 도 지원합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 기본 출력

텍스트와 변수를 콘솔에 표시.

```cpp
cout << "Hello" << endl;
cout << "Value: " << 42 << endl;
// 한 줄에 여러 값 출력
cout << "Name: " << name << ", Age: " << age << endl;
```

### 기본 입력

콘솔에서 사용자 입력 읽기.

```cpp
int age;
string name;
cin >> age;
cin >> name;
// 공백을 포함한 전체 줄 읽기
getline(cin, name);
```

## 데이터 타입 및 변수

### 기본 타입

다양한 종류의 값을 저장하기 위한 기본 데이터 타입.

```cpp
// 정수 타입
int age = 25;
short small_num = 100;
long large_num = 1000000L;
long long huge_num = 9223372036854775807LL;
// 부동 소수점 타입
float price = 19.99f;
double precise = 3.14159265359;
// 문자 및 불리언
char grade = 'A';
bool is_valid = true;
```

### 문자열 및 배열

텍스트 및 컬렉션 데이터 타입.

```cpp
// 문자열
string name = "John Doe";
string empty_str;
// 배열
int numbers[5] = {1, 2, 3, 4, 5};
int matrix[3][3] = {{1,2,3}, {4,5,6}, {7,8,9}};
// 동적 배열 (벡터)
vector<int> dynamic_array = {10, 20, 30};
vector<string> names(5); // 크기 5, 빈 문자열
```

<BaseQuiz id="cpp-vector-1" correct="B">
  <template #question>
    일반 배열에 비해 `vector` 의 주요 장점은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">벡터가 더 빠릅니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>배열은 크기가 고정되어 있지만 벡터는 동적으로 크기를 조정할 수 있습니다</BaseQuizOption>
  <BaseQuizOption value="C">벡터가 메모리를 덜 사용합니다</BaseQuizOption>
  <BaseQuizOption value="D">장점이 없습니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `vector` 는 런타임에 크기가 늘어나거나 줄어들 수 있는 동적 배열인 반면, 일반 배열은 컴파일 시간에 크기가 고정됩니다. 이로 인해 벡터는 많은 사용 사례에서 더 유연합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 상수 및 Auto

불변 값 및 자동 타입 추론.

```cpp
// 상수
const int MAX_SIZE = 100;
const double PI = 3.14159;
// Auto 키워드 (C++11 이상)
auto x = 42;        // int
auto y = 3.14;      // double
auto name = "John"; // const char*
// 타입 별칭
typedef unsigned int uint;
using real = double;
```

## 제어 흐름 구조

### 조건문

조건에 따라 의사 결정.

```cpp
// If-else 문
if (age >= 18) {
    cout << "Adult" << endl;
} else if (age >= 13) {
    cout << "Teenager" << endl;
} else {
    cout << "Child" << endl;
}
// 삼항 연산자
string status = (age >= 18) ? "Adult" : "Minor";
// Switch 문
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

### For 루프

카운터 기반 루프로 반복.

```cpp
// 전통적인 for 루프
for (int i = 0; i < 10; i++) {
    cout << i << " ";
}
// 범위 기반 for 루프 (C++11 이상)
vector<int> numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    cout << num << " ";
}
// 범위 기반 루프에서 auto 사용
for (auto& item : container) {
    // item 처리
}
```

<BaseQuiz id="cpp-range-for-1" correct="B">
  <template #question>
    C++ 에서 범위 기반 for 루프란 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">배열에서만 작동하는 루프입니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>컨테이너의 모든 요소를 자동으로 반복하는 루프입니다</BaseQuizOption>
  <BaseQuizOption value="C">영원히 실행되는 루프입니다</BaseQuizOption>
  <BaseQuizOption value="D">수동 인덱스 관리가 필요한 루프입니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    범위 기반 for 루프 (C++11 에서 도입) 는 인덱스를 수동으로 관리할 필요 없이 컨테이너 (벡터, 배열, 문자열 등) 의 모든 요소를 자동으로 반복합니다. 구문은 `for (auto item : container)`입니다.
  </BaseQuizAnswer>
</BaseQuiz>

### While 루프

조건 기반 반복.

```cpp
// While 루프
int count = 0;
while (count < 5) {
    cout << count << endl;
    count++;
}
// Do-while 루프 (최소 한 번 실행)
int input;
do {
    cout << "Enter a number (0 to quit): ";
    cin >> input;
} while (input != 0);
```

### 루프 제어

Break 및 continue 문.

```cpp
for (int i = 0; i < 10; i++) {
    if (i == 3) {
        continue; // 현재 반복 건너뛰기
    }
    if (i == 7) {
        break;    // 루프 종료
    }
    cout << i << " ";
}
// 레이블이 지정된 break 를 사용한 중첩 루프
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == j) break; // 내부 루프만 종료
        cout << i << "," << j << " ";
    }
}
```

## 함수

### 함수 선언 및 정의

재사용 가능한 코드 블록 생성.

```cpp
// 함수 선언 (프로토타입)
int add(int a, int b);
void printMessage(string msg);
// 함수 정의
int add(int a, int b) {
    return a + b;
}
void printMessage(string msg) {
    cout << msg << endl;
}
// 함수 호출
int result = add(5, 3);
printMessage("Hello, functions!");
```

### 함수 오버로딩

동일한 이름을 가진 여러 함수.

```cpp
// 다른 매개변수 타입
int multiply(int a, int b) {
    return a * b;
}
double multiply(double a, double b) {
    return a * b;
}
// 다른 매개변수 개수
int multiply(int a, int b, int c) {
    return a * b * c;
}
```

### 기본 매개변수

함수 매개변수에 기본값 제공.

```cpp
void greet(string name, string greeting = "Hello") {
    cout << greeting << ", " << name << "!" << endl;
}
// 함수 호출
greet("Alice");              // 기본값 "Hello" 사용
greet("Bob", "Good morning"); // 사용자 지정 인사말 사용
```

### 참조로 전달

함수 매개변수를 통해 변수 수정.

```cpp
// 값으로 전달 (복사본)
void changeValue(int x) {
    x = 100; // 원본 변수는 변경되지 않음
}
// 참조로 전달
void changeReference(int& x) {
    x = 100; // 원본 변수 수정됨
}
// const 참조 (읽기 전용, 효율적)
void processLargeData(const vector<int>& data) {
    // 데이터를 읽을 수는 있지만 수정할 수는 없음
}
```

## 객체 지향 프로그래밍

### 클래스 정의

속성과 메서드를 가진 사용자 정의 데이터 타입 정의.

```cpp
class Rectangle {
private:
    double width, height;
public:
    // 생성자
    Rectangle(double w, double h) : width(w), height(h) {}

    // 기본 생성자
    Rectangle() : width(0), height(0) {}

    // 멤버 함수
    double area() const {
        return width * height;
    }

    void setDimensions(double w, double h) {
        width = w;
        height = h;
    }

    // Getter 함수
    double getWidth() const { return width; }
    double getHeight() const { return height; }
};
```

### 객체 생성 및 사용

클래스 객체 인스턴스화 및 사용.

```cpp
// 객체 생성
Rectangle rect1(5.0, 3.0);
Rectangle rect2; // 기본 생성자
// 멤버 함수 사용
cout << "Area: " << rect1.area() << endl;
rect2.setDimensions(4.0, 2.0);
// 동적 할당
Rectangle* rect3 = new Rectangle(6.0, 4.0);
cout << rect3->area() << endl;
delete rect3; // 메모리 정리
```

### 상속

기반 클래스로부터 특수화된 클래스 생성.

```cpp
class Shape {
protected:
    string color;

public:
    Shape(string c) : color(c) {}
    virtual double area() const = 0; // 순수 가상 함수
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

### 다형성

기반 클래스 포인터를 사용하여 파생 객체에 접근.

```cpp
// 가상 함수 및 다형성
vector<Shape*> shapes;
shapes.push_back(new Circle(5.0, "red"));
shapes.push_back(new Rectangle(4.0, 6.0));
for (Shape* shape : shapes) {
    cout << "Area: " << shape->area() << endl;
    // 적절한 파생 클래스 메서드 호출
}
```

## 메모리 관리

### 동적 메모리 할당

런타임에 메모리 할당 및 해제.

```cpp
// 단일 객체
int* ptr = new int(42);
cout << *ptr << endl;
delete ptr;
ptr = nullptr;
// 배열 할당
int* arr = new int[10];
for (int i = 0; i < 10; i++) {
    arr[i] = i * i;
}
delete[] arr;
// 할당 실패 확인
int* large_array = new(nothrow) int[1000000];
if (large_array == nullptr) {
    cout << "Allocation failed!" << endl;
}
```

### 스마트 포인터 (C++11 이상)

RAII 를 사용한 자동 메모리 관리.

```cpp
#include <memory>
// unique_ptr (독점 소유권)
unique_ptr<int> ptr1 = make_unique<int>(42);
unique_ptr<int> ptr2 = move(ptr1); // 소유권 이전
// shared_ptr (공유 소유권)
shared_ptr<int> sptr1 = make_shared<int>(100);
shared_ptr<int> sptr2 = sptr1; // 소유권 공유
cout << sptr1.use_count() << endl; // 참조 횟수
```

### 참조 대 포인터

객체에 간접적으로 접근하는 두 가지 방법.

```cpp
int x = 10;
// 참조 (별칭)
int& ref = x;  // 반드시 초기화해야 함
ref = 20;      // x 를 20 으로 변경
// 포인터
int* ptr = &x; // x 의 주소를 가리킴
*ptr = 30;     // 역참조하여 x 변경
ptr = nullptr; // 아무것도 가리키지 않을 수 있음
// const 변형
const int* ptr1 = &x;    // 값 변경 불가
int* const ptr2 = &x;    // 주소 변경 불가
const int* const ptr3 = &x; // 둘 다 변경 불가
```

### 스택 대 힙

메모리 할당 전략.

```cpp
// 스택 할당 (자동)
int stack_var = 42;
int stack_array[100];
// 힙 할당 (동적)
int* heap_var = new int(42);
int* heap_array = new int[100];
// 스택 객체는 자동으로 정리됨
// 힙 객체는 수동으로 삭제해야 함
delete heap_var;
delete[] heap_array;
```

## 표준 템플릿 라이브러리 (STL)

### 컨테이너: 벡터 및 문자열

동적 배열 및 문자열 조작.

```cpp
#include <vector>
#include <string>
// 벡터 작업
vector<int> nums = {1, 2, 3};
nums.push_back(4);        // 요소 추가
nums.pop_back();          // 마지막 요소 제거
nums.insert(nums.begin() + 1, 10); // 위치에 삽입
nums.erase(nums.begin()); // 첫 번째 요소 제거
// 문자열 작업
string text = "Hello";
text += " World";         // 연결
text.append("!");         // 추가
cout << text.substr(0, 5) << endl; // 부분 문자열
text.replace(6, 5, "C++"); // "World"를 "C++"로 대체
```

### 컨테이너: 맵 및 셋

키 - 값 쌍 및 고유 요소 저장을 위한 연관 컨테이너.

```cpp
#include <map>
#include <set>
// 맵 (키 - 값 쌍)
map<string, int> ages;
ages["Alice"] = 25;
ages["Bob"] = 30;
ages.insert({"Charlie", 35});
// 셋 (고유 요소)
set<int> unique_nums = {3, 1, 4, 1, 5, 9};
unique_nums.insert(2);
unique_nums.erase(1);
// 자동 정렬됨: {2, 3, 4, 5, 9}
```

### 알고리즘

일반적인 작업을 위한 STL 알고리즘.

```cpp
#include <algorithm>
vector<int> nums = {64, 34, 25, 12, 22, 11, 90};
// 정렬
sort(nums.begin(), nums.end());
sort(nums.rbegin(), nums.rend()); // 역순 정렬
// 검색
auto it = find(nums.begin(), nums.end(), 25);
if (it != nums.end()) {
    cout << "Found at position: " << it - nums.begin();
}
// 기타 유용한 알고리즘
reverse(nums.begin(), nums.end());
int max_val = *max_element(nums.begin(), nums.end());
int count = count_if(nums.begin(), nums.end(),
                    [](int x) { return x > 50; });
```

### 반복자 (Iterators)

컨테이너를 효율적으로 탐색.

```cpp
vector<string> words = {"hello", "world", "cpp"};
// 반복자 타입
vector<string>::iterator it;
auto it2 = words.begin(); // C++11 auto
// 컨테이너 반복
for (it = words.begin(); it != words.end(); ++it) {
    cout << *it << " ";
}
// 범위 기반 루프 (선호됨)
for (const auto& word : words) {
    cout << word << " ";
}
```

## 입출력 작업

### 파일 입력: 파일 읽기

텍스트 파일에서 데이터 읽기.

```cpp
#include <fstream>
#include <sstream>
// 파일 전체 읽기
ifstream file("data.txt");
if (file.is_open()) {
    string line;
    while (getline(file, line)) {
        cout << line << endl;
    }
    file.close();
}
// 단어별로 읽기
ifstream file2("numbers.txt");
int number;
while (file2 >> number) {
    cout << number << " ";
}
// 오류 확인
if (!file.good()) {
    cerr << "Error reading file!" << endl;
}
```

### 문자열 스트림 처리

문자열을 스트림처럼 구문 분석하고 조작.

```cpp
#include <sstream>
// 쉼표로 구분된 값 구문 분석
string data = "apple,banana,cherry";
stringstream ss(data);
string item;
vector<string> fruits;
while (getline(ss, item, ',')) {
    fruits.push_back(item);
}
// 문자열을 숫자로 변환
string num_str = "123";
int num = stoi(num_str);
double d = stod("3.14159");
string back_to_str = to_string(num);
```

### 파일 출력: 파일 쓰기

텍스트 파일에 데이터 쓰기.

```cpp
// 파일에 쓰기
ofstream outfile("output.txt");
if (outfile.is_open()) {
    outfile << "Hello, file!" << endl;
    outfile << "Number: " << 42 << endl;
    outfile.close();
}
// 기존 파일에 추가
ofstream appendfile("log.txt", ios::app);
appendfile << "New log entry" << endl;
// 벡터를 파일에 쓰기
vector<int> numbers = {1, 2, 3, 4, 5};
ofstream numfile("numbers.txt");
for (int num : numbers) {
    numfile << num << " ";
}
```

### 스트림 형식 지정

출력 형식 및 정밀도 제어.

```cpp
#include <iomanip>
double pi = 3.14159265;
cout << fixed << setprecision(2) << pi << endl; // 3.14
cout << setw(10) << "Right" << endl;          // 오른쪽 정렬
cout << left << setw(10) << "Left" << endl;     // 왼쪽 정렬
cout << hex << 255 << endl;                    // 16 진수: ff
```

## 오류 처리

### Try-Catch 블록

실행 중 발생할 수 있는 예외 처리.

```cpp
try {
    int result = 10 / 0; // 예외를 발생시킬 수 있음
    vector<int> vec(5);
    vec.at(10) = 100;    // 범위를 벗어난 접근

} catch (const exception& e) {
    cout << "Exception caught: " << e.what() << endl;
} catch (...) {
    cout << "Unknown exception caught!" << endl;
}
// 특정 예외 유형
try {
    string str = "abc";
    int num = stoi(str); // invalid_argument 발생
} catch (const invalid_argument& e) {
    cout << "Invalid argument: " << e.what() << endl;
} catch (const out_of_range& e) {
    cout << "Out of range: " << e.what() << endl;
}
```

### 사용자 정의 예외 던지기

자체 예외 생성 및 던지기.

```cpp
// 사용자 정의 예외 클래스
class CustomException : public exception {
    string message;
public:
    CustomException(const string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};
// 예외를 던지는 함수
void validateAge(int age) {
    if (age < 0 || age > 150) {
        throw CustomException("Invalid age range!");
    }
}
// 사용법
try {
    validateAge(-5);
} catch (const CustomException& e) {
    cout << e.what() << endl;
}
```

### RAII 패턴

안전한 리소스 관리를 위한 리소스 획득은 초기화 (RAII).

```cpp
// 스마트 포인터를 사용한 RAII
{
    unique_ptr<int[]> arr = make_unique<int[]>(1000);
    // 범위를 벗어나면 배열이 자동으로 삭제됨
}
// 파일 처리를 사용한 RAII
{
    ifstream file("data.txt");
    // 범위를 벗어나면 파일이 자동으로 닫힘
    if (file.is_open()) {
        // 파일 처리
    }
}
// 사용자 정의 RAII 클래스
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

### 어설션 및 디버깅

프로그램 가정을 디버깅하고 검증.

```cpp
#include <cassert>
#include <iostream>
void processArray(int* arr, int size) {
    assert(arr != nullptr);  // 디버그 어설션
    assert(size > 0);        // 가정 검증

    // 배열 처리...
}
// 조건부 컴파일을 사용한 디버그 출력
#ifdef DEBUG
    #define DBG_PRINT(x) cout << "DEBUG: " << x << endl
#else
    #define DBG_PRINT(x)
#endif
// 사용법
DBG_PRINT("Starting function");
```

## 컴파일 및 빌드 프로세스

### GCC/G++ 컴파일

C++ 용 GNU 컴파일러 모음.

```bash
# 기본 컴파일
g++ -o program main.cpp
# 디버깅 정보 포함
g++ -g -o program main.cpp
# 최적화 수준
g++ -O2 -o program main.cpp
# 여러 소스 파일
g++ -o program main.cpp utils.cpp math.cpp
# 추가 디렉토리 포함
g++ -I/usr/local/include -o program main.cpp
# 라이브러리 링크
g++ -o program main.cpp -lm -lpthread
```

### 최신 C++ 표준

특정 C++ 표준 버전으로 컴파일.

```bash
# C++11 표준
g++ -std=c++11 -o program main.cpp
# C++14 표준
g++ -std=c++14 -o program main.cpp
# C++17 표준 (권장)
g++ -std=c++17 -o program main.cpp
# C++20 표준 (최신)
g++ -std=c++20 -o program main.cpp
# 모든 경고 활성화
g++ -Wall -Wextra -std=c++17 -o program main.cpp
```

### Makefile 기본 사항

make 유틸리티를 사용하여 컴파일 자동화.

```makefile
# 간단한 Makefile
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

## 모범 사례 및 팁

### 명명 규칙

일관된 명명은 코드 가독성을 높입니다.

```cpp
// 변수 및 함수: snake_case 또는 camelCase
int student_count;
int studentCount;
void calculateAverage();
// 상수: UPPER_CASE
const int MAX_BUFFER_SIZE = 1024;
const double PI = 3.14159;
// 클래스: PascalCase
class StudentRecord {
    // 멤버 변수: m_ 또는 _ 접두사 사용
    string m_name;
    int age_;

public:
    // 공개 인터페이스
    void setName(const string& name);
    string getName() const;
};
```

### 메모리 안전성

일반적인 메모리 관련 버그 방지.

```cpp
// 원시 포인터 대신 스마트 포인터 사용
auto ptr = make_unique<int>(42);
auto shared = make_shared<vector<int>>(10);
// 변수 초기화
int count = 0;        // 좋음
int count;            // 위험 - 초기화되지 않음
// 범위 기반 루프가 더 안전함
for (const auto& item : container) {
    // 항목 안전하게 처리
}
// 포인터 유효성 검사
if (ptr != nullptr) {
    // 역참조해도 안전함
}
```

### 성능 팁

효율적인 C++ 코드 작성.

```cpp
// 큰 객체는 const 참조로 전달
void processData(const vector<int>& data) {
    // 큰 객체 복사 방지
}
// 반복자의 경우 전위 증가 (pre-increment) 사용
for (auto it = vec.begin(); it != vec.end(); ++it) {
    // ++it 가 it++ 보다 종종 빠름
}
// 크기를 알 때 벡터 용량 예약
vector<int> numbers;
numbers.reserve(1000); // 재할당 방지
// 객체의 경우 push 대신 emplace 사용
vector<string> words;
words.emplace_back("Hello"); // 제자리에서 생성
words.push_back(string("World")); // 생성 후 복사
```

### 코드 구성

유지 관리를 위해 코드 구조화.

```cpp
// 헤더 파일 (utils.h)
#ifndef UTILS_H
#define UTILS_H
class MathUtils {
public:
    static double calculateArea(double radius);
    static int fibonacci(int n);
};
#endif // UTILS_H
// 구현 파일 (utils.cpp)
#include "utils.h"
#include <cmath>
double MathUtils::calculateArea(double radius) {
    return M_PI * radius * radius;
}
// 가능한 경우 const 멤버 함수 사용
double getRadius() const { return radius; }
```

## 관련 링크

- <router-link to="/c-programming">C 프로그래밍 치트 시트</router-link>
- <router-link to="/java">Java 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/golang">Golang 치트 시트</router-link>
- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>

---
title: 'SQLite 치트 시트 | LabEx'
description: '이 포괄적인 치트 시트로 SQLite 데이터베이스를 학습하세요. SQLite SQL 구문, 트랜잭션, 트리거, 뷰 및 애플리케이션을 위한 경량 데이터베이스 관리를 위한 빠른 참조.'
pdfUrl: '/cheatsheets/pdf/sqlite-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
SQLite 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/sqlite">Hands-On Labs 로 SQLite 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩을 통해 SQLite 데이터베이스 관리를 학습하세요. LabEx 는 필수 SQL 작업, 데이터 조작, 쿼리 최적화, 데이터베이스 설계 및 성능 튜닝을 다루는 포괄적인 SQLite 과정을 제공합니다. 경량 데이터베이스 개발 및 효율적인 데이터 관리를 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 데이터베이스 생성 및 연결

### 데이터베이스 생성: `sqlite3 database.db`

새로운 SQLite 데이터베이스 파일을 생성합니다.

```bash
# 데이터베이스 생성 또는 열기
sqlite3 mydata.db
# 인메모리 데이터베이스 생성 (임시)
sqlite3 :memory:
# 명령어로 데이터베이스 생성
.open mydata.db
# 연결된 모든 데이터베이스 표시
.databases
# 모든 테이블의 스키마 표시
.schema
# 테이블 목록 표시
.tables
# SQLite 종료
.exit
# 대체 종료 명령
.quit
```

### 데이터베이스 정보: `.databases`

연결된 모든 데이터베이스와 해당 파일을 나열합니다.

```sql
-- 다른 데이터베이스 연결
ATTACH DATABASE 'backup.db' AS backup;
-- 연결된 데이터베이스에서 쿼리
SELECT * FROM backup.users;
-- 데이터베이스 연결 해제
DETACH DATABASE backup;
```

### SQLite 종료: `.exit` 또는 `.quit`

SQLite 명령줄 인터페이스를 닫습니다.

```bash
.exit
.quit
```

### 데이터베이스 백업: `.backup`

현재 데이터베이스의 백업을 생성합니다.

```bash
# 파일로 백업
.backup backup.db
# 백업에서 복원
.restore backup.db
# SQL 파일로 내보내기
.output backup.sql
.dump
# SQL 스크립트 가져오기
.read backup.sql
```

## 테이블 생성 및 스키마

### 테이블 생성: `CREATE TABLE`

제약 조건과 열을 사용하여 새 테이블을 데이터베이스에 생성합니다.

```sql
-- 기본 테이블 생성
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    age INTEGER,
    created_date DATE DEFAULT CURRENT_TIMESTAMP
);

-- 외래 키가 있는 테이블
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    amount REAL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

<BaseQuiz id="sqlite-create-table-1" correct="A">
  <template #question>
    SQLite 에서 <code>INTEGER PRIMARY KEY AUTOINCREMENT</code>는 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A" correct>자동 증가하는 정수 기본 키를 생성합니다</BaseQuizOption>
  <BaseQuizOption value="B">텍스트 기본 키를 생성합니다</BaseQuizOption>
  <BaseQuizOption value="C">외래 키 제약 조건을 생성합니다</BaseQuizOption>
  <BaseQuizOption value="D">고유 인덱스를 생성합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>INTEGER PRIMARY KEY AUTOINCREMENT</code>는 새 행마다 자동으로 증가하며 기본 키 역할을 하는 정수 열을 생성합니다. 이는 각 행에 고유 식별자가 있음을 보장합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 데이터 유형: `INTEGER`, `TEXT`, `REAL`, `BLOB`

SQLite 는 유연한 데이터 저장을 위해 동적 타이핑과 저장 클래스를 사용합니다.

```sql
-- 일반적인 데이터 유형
CREATE TABLE products (
    id INTEGER,           -- 정수
    name TEXT,           -- 텍스트 문자열
    price REAL,          -- 부동 소수점 숫자
    image BLOB,          -- 바이너리 데이터
    active BOOLEAN,      -- 부울 (INTEGER 로 저장됨)
    created_at DATETIME  -- 날짜 및 시간
);
```

### 제약 조건: `PRIMARY KEY`, `NOT NULL`, `UNIQUE`

데이터 무결성 및 테이블 관계를 적용하기 위해 제약 조건을 정의합니다.

```sql
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL,
    salary REAL CHECK(salary > 0),
    manager_id INTEGER REFERENCES employees(id)
);
```

## 데이터 삽입 및 수정

### 데이터 삽입: `INSERT INTO`

단일 또는 다중 행으로 테이블에 새 레코드를 추가합니다.

```sql
-- 단일 레코드 삽입
INSERT INTO users (name, email, age)
VALUES ('John Doe', 'john@email.com', 30);

-- 다중 레코드 삽입
INSERT INTO users (name, email, age) VALUES
    ('Jane Smith', 'jane@email.com', 25),
    ('Bob Wilson', 'bob@email.com', 35);

-- 모든 열에 삽입
INSERT INTO users VALUES
    (NULL, 'Alice Brown', 'alice@email.com', 28, datetime('now'));
```

### 데이터 업데이트: `UPDATE SET`

조건에 따라 기존 레코드를 수정합니다.

```sql
-- 단일 열 업데이트
UPDATE users SET age = 31 WHERE name = 'John Doe';

-- 다중 열 업데이트
UPDATE users SET
    email = 'newemail@example.com',
    age = age + 1
WHERE id = 1;

-- 서브쿼리를 사용한 업데이트
UPDATE products SET price = price * 1.1
WHERE category = 'Electronics';
```

<BaseQuiz id="sqlite-update-1" correct="D">
  <template #question>
    UPDATE 문에서 WHERE 절을 생략하면 어떻게 됩니까?
  </template>
  
  <BaseQuizOption value="A">업데이트가 실패합니다</BaseQuizOption>
  <BaseQuizOption value="B">첫 번째 행만 업데이트됩니다</BaseQuizOption>
  <BaseQuizOption value="C">아무 일도 일어나지 않습니다</BaseQuizOption>
  <BaseQuizOption value="D" correct>테이블의 모든 행이 업데이트됩니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    WHERE 절이 없으면 UPDATE 문은 테이블의 모든 행을 수정합니다. 의도하지 않은 데이터를 실수로 변경하는 것을 방지하려면 항상 WHERE 를 사용하여 업데이트할 행을 지정해야 합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 데이터 삭제: `DELETE FROM`

지정된 조건에 따라 테이블에서 레코드를 제거합니다.

```sql
-- 특정 레코드 삭제
DELETE FROM users WHERE age < 18;

-- 모든 레코드 삭제 (테이블 구조 유지)
DELETE FROM users;

-- 서브쿼리를 사용한 삭제
DELETE FROM orders
WHERE user_id IN (SELECT id FROM users WHERE active = 0);
```

### Upsert: `INSERT OR REPLACE`

충돌 시 새 레코드를 삽입하거나 기존 레코드를 업데이트합니다.

```sql
-- 충돌 시 삽입 또는 교체
INSERT OR REPLACE INTO users (id, name, email)
VALUES (1, 'Updated Name', 'updated@email.com');

-- 중복 시 삽입 무시
INSERT OR IGNORE INTO users (name, email)
VALUES ('Duplicate', 'existing@email.com');
```

<BaseQuiz id="sqlite-upsert-1" correct="A">
  <template #question>
    <code>INSERT OR REPLACE</code>와 <code>INSERT OR IGNORE</code>의 차이점은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A" correct>REPLACE 는 기존 행을 업데이트하고, IGNORE 는 중복을 건너뜁니다</BaseQuizOption>
  <BaseQuizOption value="B">차이점이 없습니다</BaseQuizOption>
  <BaseQuizOption value="C">REPLACE 는 행을 삭제하고, IGNORE 는 행을 업데이트합니다</BaseQuizOption>
  <BaseQuizOption value="D">REPLACE 는 테이블에 대해 작동하고, IGNORE 는 뷰에 대해 작동합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>INSERT OR REPLACE</code>는 충돌 (예: 중복 기본 키) 이 있는 경우 기존 행을 대체합니다. <code>INSERT OR IGNORE</code>는 충돌이 발생하면 삽입을 건너뛰고 기존 행을 변경하지 않습니다.
  </BaseQuizAnswer>
</BaseQuiz>

## 데이터 쿼리 및 선택

### 기본 쿼리: `SELECT`

다양한 옵션을 사용하여 SELECT 문으로 테이블에서 데이터를 쿼리합니다.

```sql
-- 모든 열 선택
SELECT * FROM users;

-- 특정 열 선택
SELECT name, email FROM users;

-- 별칭을 사용한 선택
SELECT name AS full_name, age AS years_old FROM users;

-- 고유 값 선택
SELECT DISTINCT department FROM employees;
```

<BaseQuiz id="sqlite-select-1" correct="B">
  <template #question>
    <code>SELECT DISTINCT</code>는 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A">모든 행을 선택합니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>중복을 제거하고 고유한 값만 반환합니다</BaseQuizOption>
  <BaseQuizOption value="C">첫 번째 행만 선택합니다</BaseQuizOption>
  <BaseQuizOption value="D">결과를 정렬합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>SELECT DISTINCT</code>는 결과 집합에서 중복 행을 제거하여 고유한 값만 반환합니다. 이는 열에서 모든 고유 값을 보려고 할 때 유용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 필터링: `WHERE`

다양한 조건 및 비교 연산자를 사용하여 행을 필터링합니다.

```sql
-- 간단한 조건
SELECT * FROM users WHERE age > 25;
SELECT * FROM users WHERE name = 'John Doe';

-- 다중 조건
SELECT * FROM users WHERE age > 18 AND age < 65;
SELECT * FROM users WHERE department = 'IT' OR salary > 50000;

-- 패턴 일치
SELECT * FROM users WHERE email LIKE '%@gmail.com';
SELECT * FROM users WHERE name GLOB 'J*';
```

### 정렬 및 제한: `ORDER BY` / `LIMIT`

결과를 정렬하고 반환되는 행 수를 제한하여 데이터 관리를 개선합니다.

```sql
-- 오름차순 정렬 (기본값)
SELECT * FROM users ORDER BY age;

-- 내림차순 정렬
SELECT * FROM users ORDER BY age DESC;

-- 다중 정렬 열
SELECT * FROM users ORDER BY department, salary DESC;

-- 결과 제한
SELECT * FROM users LIMIT 10;

-- 오프셋을 사용한 제한 (페이지네이션)
SELECT * FROM users LIMIT 10 OFFSET 20;
```

### 집계 함수: `COUNT`, `SUM`, `AVG`

통계 분석을 위해 행 그룹에 대한 계산을 수행합니다.

```sql
-- 레코드 수 계산
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT department) FROM employees;

-- 합계 및 평균
SELECT SUM(salary), AVG(salary) FROM employees;

-- 최소 및 최대 값
SELECT MIN(age), MAX(age) FROM users;
```

## 고급 쿼리

### 그룹화: `GROUP BY` / `HAVING`

지정된 기준별로 행을 그룹화하고 요약 보고서를 위해 그룹을 필터링합니다.

```sql
-- 단일 열로 그룹화
SELECT department, COUNT(*)
FROM employees
GROUP BY department;

-- 다중 열로 그룹화
SELECT department, job_title, AVG(salary)
FROM employees
GROUP BY department, job_title;

-- HAVING 으로 그룹 필터링
SELECT department, AVG(salary) as avg_salary
FROM employees
GROUP BY department
HAVING avg_salary > 60000;
```

### 서브쿼리

복잡한 데이터 검색 및 조건부 로직을 위해 중첩된 쿼리를 사용합니다.

```sql
-- WHERE 절의 서브쿼리
SELECT name FROM users
WHERE age > (SELECT AVG(age) FROM users);

-- FROM 절의 서브쿼리
SELECT dept, avg_salary FROM (
    SELECT department as dept, AVG(salary) as avg_salary
    FROM employees
    GROUP BY department
) WHERE avg_salary > 50000;

-- EXISTS 서브쿼리
SELECT * FROM users u
WHERE EXISTS (
    SELECT 1 FROM orders o WHERE o.user_id = u.id
);
```

### 조인: `INNER`, `LEFT`, `RIGHT`

다양한 조인 유형을 사용하여 여러 테이블의 데이터를 결합하여 관계형 쿼리를 수행합니다.

```sql
-- 내부 조인
SELECT u.name, o.amount
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- 왼쪽 조인 (모든 사용자 표시)
SELECT u.name, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- 자체 조인
SELECT e1.name as employee, e2.name as manager
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id;
```

### 집합 연산: `UNION` / `INTERSECT`

집합 연산을 사용하여 여러 쿼리의 결과를 결합합니다.

```sql
-- Union (결과 결합)
SELECT name FROM customers
UNION
SELECT name FROM suppliers;

-- Intersect (공통 결과)
SELECT email FROM users
INTERSECT
SELECT email FROM newsletter_subscribers;

-- Except (차이)
SELECT email FROM users
EXCEPT
SELECT email FROM unsubscribed;
```

## 인덱스 및 성능

### 인덱스 생성: `CREATE INDEX`

쿼리 속도를 높이고 성능을 개선하기 위해 열에 인덱스를 생성합니다.

```sql
-- 단일 열 인덱스
CREATE INDEX idx_user_email ON users(email);

-- 다중 열 인덱스
CREATE INDEX idx_order_user_date ON orders(user_id, order_date);

-- 고유 인덱스
CREATE UNIQUE INDEX idx_product_sku ON products(sku);

-- 부분 인덱스 (조건 포함)
CREATE INDEX idx_active_users ON users(name) WHERE active = 1;
```

### 쿼리 분석: `EXPLAIN QUERY PLAN`

쿼리 실행 계획을 분석하여 성능 병목 현상을 식별합니다.

```bash
# 쿼리 성능 분석
EXPLAIN QUERY PLAN SELECT * FROM users WHERE email = 'test@example.com';

-- 인덱스 사용 여부 확인
EXPLAIN QUERY PLAN SELECT * FROM orders WHERE user_id = 123;
```

### 데이터베이스 최적화: `VACUUM` / `ANALYZE`

데이터베이스 파일을 최적화하고 통계를 업데이트하여 성능을 개선합니다.

```bash
# 공간 확보를 위해 데이터베이스 재구축
VACUUM;

-- 인덱스 통계 업데이트
ANALYZE;

-- 데이터베이스 무결성 확인
PRAGMA integrity_check;
```

### 성능 설정: `PRAGMA`

최적화 및 구성을 위해 pragma 문을 통해 SQLite 설정을 구성합니다.

```sql
-- 더 나은 성능을 위한 저널 모드 설정
PRAGMA journal_mode = WAL;

-- 동기화 모드 설정
PRAGMA synchronous = NORMAL;

-- 외래 키 제약 조건 활성화
PRAGMA foreign_keys = ON;

-- 캐시 크기 설정 (페이지 단위)
PRAGMA cache_size = 10000;
```

## 뷰 및 트리거

### 뷰: `CREATE VIEW`

저장된 쿼리를 나타내는 가상 테이블을 생성하여 재사용 가능한 데이터 액세스를 제공합니다.

```sql
-- 간단한 뷰 생성
CREATE VIEW active_users AS
SELECT id, name, email
FROM users
WHERE active = 1;

-- 조인이 포함된 복잡한 뷰
CREATE VIEW order_summary AS
SELECT
    u.name,
    COUNT(o.id) as total_orders,
    SUM(o.amount) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- 뷰 쿼리
SELECT * FROM active_users WHERE name LIKE 'J%';

-- 뷰 삭제
DROP VIEW IF EXISTS order_summary;
```

### 뷰 사용

일반 테이블처럼 뷰를 쿼리하여 데이터 액세스를 단순화합니다.

```sql
SELECT * FROM active_users;
SELECT * FROM order_summary WHERE total_spent > 1000;
```

### 트리거: `CREATE TRIGGER`

데이터베이스 이벤트에 응답하여 코드를 자동으로 실행합니다.

```sql
-- INSERT 시 트리거
CREATE TRIGGER update_user_count
AFTER INSERT ON users
BEGIN
    UPDATE stats SET user_count = user_count + 1;
END;

-- UPDATE 시 트리거
CREATE TRIGGER log_salary_changes
AFTER UPDATE OF salary ON employees
BEGIN
    INSERT INTO audit_log (table_name, action, old_value, new_value)
    VALUES ('employees', 'salary_update', OLD.salary, NEW.salary);
END;

-- 트리거 삭제
DROP TRIGGER IF EXISTS update_user_count;
```

## 데이터 유형 및 함수

### 날짜 및 시간 함수

내장 함수를 사용하여 날짜 및 시간 작업을 처리합니다.

```sql
-- 현재 날짜/시간
SELECT datetime('now');
SELECT date('now');
SELECT time('now');

-- 날짜 산술 연산
SELECT date('now', '+1 day');
SELECT datetime('now', '-1 hour');
SELECT date('now', 'start of month');

-- 날짜 형식 지정
SELECT strftime('%Y-%m-%d %H:%M', 'now');
SELECT strftime('%w', 'now'); -- 요일
```

### 문자열 함수

다양한 문자열 작업을 사용하여 텍스트 데이터를 조작합니다.

```sql
-- 문자열 조작
SELECT upper(name) FROM users;
SELECT lower(email) FROM users;
SELECT length(name) FROM users;
SELECT substr(name, 1, 3) FROM users;

-- 문자열 연결
SELECT name || ' - ' || email as display FROM users;
SELECT printf('%s (%d)', name, age) FROM users;

-- 문자열 대체
SELECT replace(phone, '-', '') FROM users;
```

### 숫자 함수

수학적 연산 및 계산을 수행합니다.

```sql
-- 수학 함수
SELECT abs(-15);
SELECT round(price, 2) FROM products;
SELECT random(); -- 난수

-- 집계와 수학
SELECT department, round(AVG(salary), 2) as avg_salary
FROM employees
GROUP BY department;
```

### 조건부 로직: `CASE`

SQL 쿼리 내에서 조건부 로직을 구현합니다.

```sql
-- 간단한 CASE 문
SELECT name,
    CASE
        WHEN age < 18 THEN 'Minor'
        WHEN age < 65 THEN 'Adult'
        ELSE 'Senior'
    END as age_category
FROM users;

-- WHERE 절의 CASE
SELECT * FROM products
WHERE CASE WHEN category = 'Electronics' THEN price < 1000
          ELSE price < 100 END;
```

## 트랜잭션 및 동시성

### 트랜잭션 제어

SQLite 트랜잭션은 데이터 작업을 안정적으로 수행하기 위해 완전히 ACID 를 준수합니다.

```sql
-- 기본 트랜잭션
BEGIN TRANSACTION;
INSERT INTO users (name, email) VALUES ('Test User', 'test@example.com');
UPDATE users SET age = 25 WHERE name = 'Test User';
COMMIT;

-- 롤백을 포함한 트랜잭션
BEGIN;
DELETE FROM orders WHERE amount < 10;
-- 결과 확인 후 필요 시 롤백
ROLLBACK;

-- 중첩된 트랜잭션을 위한 세이브포인트
BEGIN;
SAVEPOINT sp1;
INSERT INTO products (name) VALUES ('Product A');
ROLLBACK TO sp1;
COMMIT;
```

### 잠금 및 동시성

데이터 무결성을 위해 데이터베이스 잠금 및 동시 액세스를 관리합니다.

```bash
# 잠금 상태 확인
PRAGMA locking_mode;

-- 더 나은 동시성을 위해 WAL 모드 설정
PRAGMA journal_mode = WAL;

-- 잠금 대기를 위한 바쁜 타임아웃 설정
PRAGMA busy_timeout = 5000;

-- 현재 데이터베이스 연결 확인
.databases
```

## SQLite 명령줄 도구

### 데이터베이스 명령: `.help`

사용 가능한 점 (dot) 명령에 대한 SQLite 명령줄 도움말 및 설명서를 액세스합니다.

```bash
# 사용 가능한 모든 명령 표시
.help
# 현재 설정 표시
.show
# 출력 형식 설정
.mode csv
.headers on
```

### 가져오기/내보내기: `.import` / `.export`

SQLite 와 외부 파일 간에 다양한 형식으로 데이터를 전송합니다.

```bash
# CSV 파일 가져오기
.mode csv
.import data.csv users

# CSV로 내보내기
.headers on
.mode csv
.output users.csv
SELECT * FROM users;
```

### 스키마 관리: `.schema` / `.tables`

개발 및 디버깅을 위해 데이터베이스 구조 및 테이블 정의를 검사합니다.

```bash
# 모든 테이블 표시
.tables
# 특정 테이블의 스키마 표시
.schema users
# 모든 스키마 표시
.schema
# 테이블 정보 표시
.mode column
.headers on
PRAGMA table_info(users);
```

### 출력 형식 지정: `.mode`

명령줄 인터페이스에서 쿼리 결과가 표시되는 방식을 제어합니다.

```bash
# 다양한 출력 모드
.mode csv        # 쉼표로 구분된 값
.mode column     # 정렬된 열
.mode html       # HTML 테이블 형식
.mode json       # JSON 형식
.mode list       # 목록 형식
.mode table      # 테이블 형식 (기본값)

# 열 너비 설정
.width 10 15 20

# 파일에 출력 저장
.output results.txt
SELECT * FROM users;
.output stdout

# 파일에서 SQL 읽기
.read script.sql

# 데이터베이스 파일 변경
.open another_database.db
```

## 구성 및 설정

### 데이터베이스 설정: `PRAGMA`

최적화 및 구성을 위해 pragma 문을 통해 SQLite 의 동작을 제어합니다.

```sql
-- 데이터베이스 정보
PRAGMA database_list;
PRAGMA table_info(users);
PRAGMA foreign_key_list(orders);

-- 성능 설정
PRAGMA cache_size = 10000;
PRAGMA temp_store = memory;
PRAGMA mmap_size = 268435456;

-- 외래 키 제약 조건 활성화
PRAGMA foreign_keys = ON;

-- 보안 삭제 모드 설정
PRAGMA secure_delete = ON;

-- 제약 조건 확인
PRAGMA foreign_key_check;
```

### 보안 설정

보안 관련 데이터베이스 옵션 및 제약 조건을 구성합니다.

```sql
-- 외래 키 제약 조건 활성화
PRAGMA foreign_keys = ON;

-- 보안 삭제 모드
PRAGMA secure_delete = ON;

-- 무결성 확인
PRAGMA integrity_check;
```

## 설치 및 설정

### 다운로드 및 설치

운영 체제용 SQLite 도구를 다운로드하고 명령줄 인터페이스를 설정합니다.

```bash
# sqlite.org에서 다운로드
# Windows용: sqlite-tools-win32-x86-*.zip
# Linux/Mac용: 패키지 관리자 사용

# Ubuntu/Debian
sudo apt-get install sqlite3

# macOS (Homebrew 사용)
brew install sqlite

# 설치 확인
sqlite3 --version
```

### 첫 번째 데이터베이스 생성

SQLite 데이터베이스 파일을 생성하고 간단한 명령을 사용하여 데이터 작업을 시작합니다.

```bash
# 새 데이터베이스 생성
sqlite3 myapp.db

# 테이블 생성 및 데이터 추가
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE
);

INSERT INTO users (name, email)
VALUES ('John Doe', 'john@example.com');
```

### 프로그래밍 언어 통합

내장 또는 타사 라이브러리를 통해 다양한 프로그래밍 언어에서 SQLite 를 사용합니다.

```python
# Python (내장 sqlite3 모듈)
import sqlite3
conn = sqlite3.connect('mydb.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users')
```

```javascript
// Node.js (sqlite3 패키지 필요)
const sqlite3 = require('sqlite3')
const db = new sqlite3.Database('mydb.db')
db.all('SELECT * FROM users', (err, rows) => {
  console.log(rows)
})
```

```php
// PHP (내장 PDO SQLite)
$pdo = new PDO('sqlite:mydb.db');
$stmt = $pdo->query('SELECT * FROM users');
```

## 관련 링크

- <router-link to="/database">데이터베이스 치트 시트</router-link>
- <router-link to="/mysql">MySQL 치트 시트</router-link>
- <router-link to="/postgresql">PostgreSQL 치트 시트</router-link>
- <router-link to="/mongodb">MongoDB 치트 시트</router-link>
- <router-link to="/redis">Redis 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>

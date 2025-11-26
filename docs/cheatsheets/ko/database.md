---
title: '데이터베이스 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 포괄적인 치트 시트로 데이터베이스를 학습하세요.'
pdfUrl: '/cheatsheets/pdf/database-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
데이터베이스 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/database">실습 랩을 통해 데이터베이스 학습</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 데이터베이스 관리 및 SQL 을 학습하세요. LabEx 는 필수 SQL 명령어, 데이터 조작, 쿼리 최적화, 데이터베이스 설계 및 관리를 다루는 포괄적인 데이터베이스 과정을 제공합니다. 관계형 데이터베이스, NoSQL 시스템 및 데이터베이스 보안 모범 사례를 숙달하세요.
</base-disclaimer-content>
</base-disclaimer>

## 데이터베이스 생성 및 관리

### 데이터베이스 생성: `CREATE DATABASE`

데이터 저장을 위한 새 데이터베이스를 생성합니다.

```sql
-- 새 데이터베이스 생성
CREATE DATABASE company_db;
-- 문자 집합을 사용하여 데이터베이스 생성
CREATE DATABASE company_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
-- 데이터베이스 사용
USE company_db;
```

### 데이터베이스 보기: `SHOW DATABASES`

서버에서 사용 가능한 모든 데이터베이스 목록을 표시합니다.

```sql
-- 모든 데이터베이스 나열
SHOW DATABASES;
-- 데이터베이스 정보 표시
SELECT SCHEMA_NAME FROM
INFORMATION_SCHEMA.SCHEMATA;
-- 현재 데이터베이스 표시
SELECT DATABASE();
```

### 데이터베이스 삭제: `DROP DATABASE`

전체 데이터베이스를 영구적으로 삭제합니다.

```sql
-- 데이터베이스 삭제 (주의!)
DROP DATABASE old_company_db;
-- 존재하는 경우 데이터베이스 삭제
DROP DATABASE IF EXISTS old_company_db;
```

### 데이터베이스 백업: `mysqldump`

데이터베이스의 백업 복사본을 만듭니다.

```sql
-- 명령줄 백업
mysqldump -u username -p database_name > backup.sql
-- 백업에서 복원
mysql -u username -p database_name < backup.sql
```

### 데이터베이스 사용자: `CREATE USER`

데이터베이스 사용자 계정 및 권한을 관리합니다.

```sql
-- 새 사용자 생성
CREATE USER 'newuser'@'localhost' IDENTIFIED BY
'password';
-- 권한 부여
GRANT SELECT, INSERT ON company_db.* TO
'newuser'@'localhost';
-- 사용자 권한 표시
SHOW GRANTS FOR 'newuser'@'localhost';
```

### 데이터베이스 정보: `INFORMATION_SCHEMA`

데이터베이스 메타데이터 및 구조 정보를 쿼리합니다.

```sql
-- 모든 테이블 표시
SELECT TABLE_NAME FROM
INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'company_db';
-- 테이블 열 표시
DESCRIBE employees;
```

## 테이블 구조 및 정보

### 테이블 생성: `CREATE TABLE`

열과 데이터 유형을 사용하여 새 테이블을 정의합니다.

```sql
-- 기본 테이블 생성
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY
KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE,
    salary DECIMAL(10,2),
    hire_date DATE,
    department VARCHAR(50)
);
-- 테이블 구조 표시
DESCRIBE employees;
SHOW COLUMNS FROM employees;
```

### 테이블 수정: `ALTER TABLE`

기존 테이블 구조 및 열을 수정합니다.

```sql
-- 새 열 추가
ALTER TABLE employees ADD
COLUMN phone VARCHAR(15);
-- 열 유형 수정
ALTER TABLE employees MODIFY
COLUMN salary DECIMAL(12,2);
-- 열 삭제
ALTER TABLE employees DROP
COLUMN phone;
-- 테이블 이름 변경
RENAME TABLE employees TO staff;
```

### 테이블 정보: `SHOW`

테이블 및 속성에 대한 자세한 정보를 얻습니다.

```sql
-- 모든 테이블 표시
SHOW TABLES;
-- 테이블 구조 표시
SHOW CREATE TABLE employees;
-- 테이블 상태 표시
SHOW TABLE STATUS LIKE
'employees';
-- 테이블의 행 수 계산
SELECT COUNT(*) FROM employees;
```

## 데이터 조작 및 CRUD 작업

### 데이터 삽입: `INSERT INTO`

테이블에 새 레코드를 추가합니다.

```sql
-- 단일 레코드 삽입
INSERT INTO employees (name, email, salary, hire_date,
department)
VALUES ('John Doe', 'john@company.com', 75000.00,
'2024-01-15', 'Engineering');
-- 여러 레코드 삽입
INSERT INTO employees (name, email, salary,
department) VALUES
('Jane Smith', 'jane@company.com', 80000.00,
'Marketing'),
('Bob Johnson', 'bob@company.com', 65000.00, 'Sales');
-- 다른 테이블에서 삽입
INSERT INTO backup_employees
SELECT * FROM employees WHERE department =
'Engineering';
```

### 데이터 업데이트: `UPDATE`

테이블의 기존 레코드를 수정합니다.

```sql
-- 단일 레코드 업데이트
UPDATE employees
SET salary = 85000.00, department = 'Senior Engineering'
WHERE id = 1;
-- 여러 레코드 업데이트
UPDATE employees
SET salary = salary * 1.05
WHERE hire_date < '2024-01-01';
-- JOIN 을 사용하여 업데이트
UPDATE employees e
JOIN departments d ON e.department = d.name
SET e.salary = e.salary + d.bonus;
```

### 데이터 삭제: `DELETE FROM`

테이블에서 레코드를 제거합니다.

```sql
-- 특정 레코드 삭제
DELETE FROM employees
WHERE department = 'Temporary';
-- 조건부 삭제
DELETE FROM employees
WHERE hire_date < '2020-01-01' AND salary < 50000;
-- 테이블 비우기 (모든 레코드에 대해 더 빠름)
TRUNCATE TABLE temp_employees;
```

### 데이터 대체: `REPLACE INTO`

기본 키를 기반으로 레코드를 삽입하거나 업데이트합니다.

```sql
-- 레코드 대체 (삽입 또는 업데이트)
REPLACE INTO employees (id, name, email, salary)
VALUES (1, 'John Doe Updated',
'john.new@company.com', 90000);
-- 키 중복 시 업데이트
INSERT INTO employees (id, name, salary)
VALUES (1, 'John Doe', 85000)
ON DUPLICATE KEY UPDATE salary = VALUES(salary);
```

## 데이터 쿼리 및 선택

### 기본 SELECT: `SELECT`

데이터베이스 테이블에서 데이터를 검색합니다.

```sql
-- 모든 열 선택
SELECT * FROM employees;
-- 특정 열 선택
SELECT name, email, salary FROM employees;
-- 별칭을 사용하여 선택
SELECT name AS employee_name, salary AS
annual_salary
FROM employees;
-- 고유 값 선택
SELECT DISTINCT department FROM employees;
```

### 데이터 필터링: `WHERE`

쿼리 결과를 필터링하기 위해 조건을 적용합니다.

```sql
-- 기본 조건
SELECT * FROM employees WHERE salary > 70000;
-- 다중 조건
SELECT * FROM employees
WHERE department = 'Engineering' AND salary > 75000;
-- 패턴 일치
SELECT * FROM employees WHERE name LIKE 'John%';
-- 범위 쿼리
SELECT * FROM employees
WHERE hire_date BETWEEN '2023-01-01' AND '2023-12-
31';
```

### 데이터 정렬: `ORDER BY`

쿼리 결과를 오름차순 또는 내림차순으로 정렬합니다.

```sql
-- 단일 열로 정렬
SELECT * FROM employees ORDER BY salary DESC;
-- 다중 열로 정렬
SELECT * FROM employees
ORDER BY department ASC, salary DESC;
-- LIMIT 과 함께 정렬
SELECT * FROM employees
ORDER BY hire_date DESC LIMIT 10;
```

### 결과 제한: `LIMIT`

반환되는 레코드 수를 제어합니다.

```sql
-- 결과 수 제한
SELECT * FROM employees LIMIT 5;
-- OFFSET 을 사용한 페이지네이션
SELECT * FROM employees
ORDER BY id LIMIT 10 OFFSET 20;
-- 상위 N 개 결과
SELECT * FROM employees
ORDER BY salary DESC LIMIT 5;
```

## 고급 쿼리

### 집계 함수: `COUNT`, `SUM`, `AVG`

데이터 그룹에 대한 계산을 수행합니다.

```sql
-- 레코드 수 계산
SELECT COUNT(*) FROM employees;
-- 합계 및 평균
SELECT SUM(salary) as total_payroll, AVG(salary) as
avg_salary
FROM employees;
-- 그룹 통계
SELECT department, COUNT(*) as employee_count,
AVG(salary) as avg_salary
FROM employees GROUP BY department;
-- 그룹 필터링을 위한 Having 절
SELECT department, COUNT(*) as count
FROM employees
GROUP BY department
HAVING COUNT(*) > 5;
```

### 서브쿼리: 중첩된 쿼리

복잡한 작업을 위해 다른 쿼리 내에서 쿼리를 사용합니다.

```sql
-- WHERE 절의 서브쿼리
SELECT * FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);
-- IN 을 사용한 서브쿼리
SELECT * FROM employees
WHERE department IN (
    SELECT name FROM departments WHERE budget >
100000
);
-- 상관 서브쿼리
SELECT * FROM employees e1
WHERE salary > (
    SELECT AVG(salary) FROM employees e2
    WHERE e2.department = e1.department
);
```

### 테이블 조인: `JOIN`

여러 테이블의 데이터를 결합합니다.

```sql
-- 내부 조인
SELECT e.name, e.salary, d.department_name
FROM employees e
INNER JOIN departments d ON e.department = d.id;
-- 왼쪽 조인
SELECT e.name, d.department_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id;
-- 다중 조인
SELECT e.name, d.department_name, p.project_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id
LEFT JOIN projects p ON e.id = p.employee_id;
```

### 윈도우 함수: 고급 분석

관련 행에 걸쳐 계산을 수행합니다.

```sql
-- 행 번호 매기기
SELECT name, salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
FROM employees;
-- 누계 합계
SELECT name, salary,
    SUM(salary) OVER (ORDER BY hire_date) as
running_total
FROM employees;
-- 그룹별 파티션
SELECT name, department, salary,
    AVG(salary) OVER (PARTITION BY department) as
dept_avg
FROM employees;
```

## 데이터베이스 제약 조건 및 무결성

### 기본 키: `PRIMARY KEY`

각 레코드에 대한 고유 식별을 보장합니다.

```sql
-- 단일 열 기본 키
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100)
);
-- 복합 기본 키
CREATE TABLE order_items (
    order_id INT,
    product_id INT,
    quantity INT,
    PRIMARY KEY (order_id, product_id)
);
```

### 외래 키: `FOREIGN KEY`

테이블 간의 참조 무결성을 유지합니다.

```sql
-- 외래 키 제약 조건 추가
CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);
-- 기존 테이블에 외래 키 추가
ALTER TABLE employees
ADD CONSTRAINT fk_department
FOREIGN KEY (department_id) REFERENCES
departments(id);
```

### 고유 제약 조건: `UNIQUE`

열의 중복 값을 방지합니다.

```sql
-- 단일 열의 고유 제약 조건
ALTER TABLE employees
ADD CONSTRAINT unique_email UNIQUE (email);
-- 복합 고유 제약 조건
ALTER TABLE employees
ADD CONSTRAINT unique_name_dept UNIQUE (name,
department);
```

### CHECK 제약 조건: `CHECK`

비즈니스 규칙 및 데이터 유효성 검사를 시행합니다.

```sql
-- 간단한 CHECK 제약 조건
ALTER TABLE employees
ADD CONSTRAINT check_salary CHECK (salary > 0);
-- 복합 CHECK 제약 조건
ALTER TABLE employees
ADD CONSTRAINT check_age
CHECK (YEAR(CURDATE()) - YEAR(birth_date) >= 18);
```

## 데이터베이스 성능 및 최적화

### 인덱스: `CREATE INDEX`

데이터베이스 인덱스를 사용하여 데이터 검색 속도를 높입니다.

```sql
-- 단일 열에 인덱스 생성
CREATE INDEX idx_employee_name ON
employees(name);
-- 복합 인덱스
CREATE INDEX idx_dept_salary ON
employees(department, salary);
-- 고유 인덱스
CREATE UNIQUE INDEX idx_employee_email ON
employees(email);
-- 테이블 인덱스 표시
SHOW INDEX FROM employees;
```

### 쿼리 최적화: `EXPLAIN`

쿼리 성능을 분석하고 최적화합니다.

```sql
-- 쿼리 실행 계획 분석
EXPLAIN SELECT * FROM employees WHERE salary >
75000;
-- 상세 분석
EXPLAIN ANALYZE SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department = d.id;
```

### 성능 모니터링

데이터베이스 활동 및 성능 병목 현상을 모니터링합니다.

```sql
-- 실행 중인 프로세스 표시
SHOW PROCESSLIST;
-- 데이터베이스 상태 표시
SHOW STATUS LIKE 'Slow_queries';
-- 쿼리 캐시 정보
SHOW STATUS LIKE 'Qcache%';
-- 데이터베이스 크기 쿼리
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

### 데이터베이스 유지 관리

최적의 성능을 위한 정기적인 유지 관리 작업.

```sql
-- 테이블 최적화
OPTIMIZE TABLE employees;
-- 테이블 통계 분석
ANALYZE TABLE employees;
-- 테이블 무결성 확인
CHECK TABLE employees;
-- 필요한 경우 테이블 복구
REPAIR TABLE employees;
```

## 데이터 가져오기/내보내기

### 데이터 가져오기: `LOAD DATA`

외부 파일에서 데이터베이스 테이블로 데이터를 가져옵니다.

```sql
-- CSV 파일에서 가져오기
LOAD DATA INFILE 'employees.csv'
INTO TABLE employees
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
-- 열 매핑으로 가져오기
LOAD DATA INFILE 'data.csv'
INTO TABLE employees (name, email, salary);
```

### 데이터 내보내기: `SELECT INTO`

쿼리 결과를 외부 파일로 내보냅니다.

```sql
-- CSV 파일로 내보내기
SELECT name, email, salary
INTO OUTFILE 'employee_export.csv'
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
FROM employees;
-- mysqldump 사용
mysqldump -u username -p --tab=/path/to/export
database_name table_name
```

### 데이터 마이그레이션: 데이터베이스 간

다른 데이터베이스 시스템 간에 데이터를 이동합니다.

```sql
-- 기존 구조에서 테이블 생성
CREATE TABLE employees_backup LIKE employees;
-- 테이블 간 데이터 복사
INSERT INTO employees_backup SELECT * FROM
employees;
-- 조건부로 마이그레이션
INSERT INTO new_employees
SELECT * FROM old_employees WHERE active = 1;
```

### 대량 작업

대규모 데이터 작업을 효율적으로 처리합니다.

```sql
-- INSERT IGNORE 를 사용한 대량 삽입
INSERT IGNORE INTO employees (name, email) VALUES
('John Doe', 'john@email.com'),
('Jane Smith', 'jane@email.com');
-- 일괄 업데이트
UPDATE employees SET salary = salary * 1.1 WHERE
department = 'Sales';
```

## 데이터베이스 보안 및 액세스 제어

### 사용자 관리: `CREATE USER`

데이터베이스 사용자 계정을 생성하고 관리합니다.

```sql
-- 암호로 사용자 생성
CREATE USER 'app_user'@'localhost' IDENTIFIED BY
'secure_password';
-- 특정 호스트용 사용자 생성
CREATE USER 'remote_user'@'192.168.1.%' IDENTIFIED
BY 'password';
-- 사용자 삭제
DROP USER 'old_user'@'localhost';
```

### 권한: `GRANT` & `REVOKE`

데이터베이스 개체 및 작업에 대한 액세스를 제어합니다.

```sql
-- 특정 권한 부여
GRANT SELECT, INSERT ON company_db.employees TO
'app_user'@'localhost';
-- 모든 권한 부여
GRANT ALL PRIVILEGES ON company_db.* TO
'admin_user'@'localhost';
-- 권한 취소
REVOKE INSERT ON company_db.employees FROM
'app_user'@'localhost';
-- 사용자 권한 표시
SHOW GRANTS FOR 'app_user'@'localhost';
```

### 데이터베이스 역할

데이터베이스 역할을 사용하여 권한을 구성합니다.

```sql
-- 역할 생성 (MySQL 8.0+)
CREATE ROLE 'app_read_role', 'app_write_role';
-- 역할에 권한 부여
GRANT SELECT ON company_db.* TO 'app_read_role';
GRANT INSERT, UPDATE, DELETE ON company_db.* TO
'app_write_role';
-- 사용자에게 역할 할당
GRANT 'app_read_role' TO 'readonly_user'@'localhost';
```

### SQL 삽입 방지

일반적인 보안 취약점으로부터 보호합니다.

```sql
-- 준비된 문 사용 (애플리케이션 수준)
-- 나쁨: SELECT * FROM users WHERE id = ' + userInput
-- 좋음: 매개변수화된 쿼리 사용
-- 입력 데이터 유형 검증
-- 가능한 경우 저장 프로시저 사용
-- 최소 권한 원칙 적용
```

## 데이터베이스 설치 및 설정

### MySQL 설치

대중적인 오픈 소스 관계형 데이터베이스.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# MySQL 서비스 시작
sudo systemctl start mysql
sudo systemctl enable mysql
# 보안 설치
sudo mysql_secure_installation
```

### PostgreSQL 설치

고급 오픈 소스 관계형 데이터베이스.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql
postgresql-contrib
# postgres 사용자로 전환
sudo -u postgres psql
# 데이터베이스 및 사용자 생성
CREATE DATABASE myapp;
CREATE USER myuser WITH
PASSWORD 'mypassword';
```

### SQLite 설정

경량 파일 기반 데이터베이스.

```bash
# SQLite 설치
sudo apt install sqlite3
# 데이터베이스 파일 생성
sqlite3 mydatabase.db
# 기본 SQLite 명령어
.help
.tables
.schema tablename
.quit
```

## 데이터베이스 구성 및 튜닝

### MySQL 구성

주요 MySQL 구성 매개변수.

```sql
-- my.cnf 구성 파일
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
-- 현재 설정 표시
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW STATUS LIKE 'Connections';
```

### 연결 관리

데이터베이스 연결 및 풀링을 관리합니다.

```sql
-- 현재 연결 표시
SHOW PROCESSLIST;
-- 특정 연결 종료
KILL CONNECTION 123;
-- 연결 시간 초과 설정
SET SESSION wait_timeout = 600;
SET SESSION interactive_timeout = 600;
```

### 백업 구성

자동화된 데이터베이스 백업을 설정합니다.

```sql
-- 자동 백업 스크립트
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mysqldump -u backup_user -p mydatabase >
backup_$DATE.sql
# cron을 사용하여 예약
0 2 * * * /path/to/backup_script.sh
```

### 모니터링 및 로깅

데이터베이스 활동 및 성능을 모니터링합니다.

```sql
-- 시점 복구 설정
SET GLOBAL log_bin = ON;
-- 느린 쿼리 로그 활성화
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
-- 데이터베이스 크기 표시
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

## SQL 모범 사례

### 쿼리 작성 모범 사례

깔끔하고 효율적이며 읽기 쉬운 SQL 쿼리를 작성합니다.

```sql
-- 의미 있는 테이블 별칭 사용
SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.dept_id = d.id;
-- SELECT * 대신 열 이름 지정
SELECT name, email, salary FROM employees;
-- 적절한 데이터 유형 사용
CREATE TABLE products (
    id INT PRIMARY KEY,
    price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP
);
```

### 성능 최적화 팁

더 나은 데이터베이스 성능을 위해 쿼리를 최적화합니다.

```sql
-- 자주 쿼리되는 열에 인덱스 사용
CREATE INDEX idx_employee_dept ON
employees(department);
-- 가능한 경우 결과 집합 제한
SELECT name FROM employees WHERE active = 1 LIMIT
100;
-- 서브쿼리에 IN 대신 EXISTS 사용
SELECT * FROM customers c
WHERE EXISTS (SELECT 1 FROM orders o WHERE
o.customer_id = c.id);
```

## 관련 링크

- <router-link to="/mysql">MySQL 치트 시트</router-link>
- <router-link to="/postgresql">PostgreSQL 치트 시트</router-link>
- <router-link to="/sqlite">SQLite 치트 시트</router-link>
- <router-link to="/mongodb">MongoDB 치트 시트</router-link>
- <router-link to="/redis">Redis 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>

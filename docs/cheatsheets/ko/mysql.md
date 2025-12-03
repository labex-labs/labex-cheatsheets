---
title: 'MySQL 치트 시트 | LabEx'
description: '이 종합 치트 시트로 MySQL 데이터베이스 관리를 학습하세요. SQL 쿼리, 조인, 인덱스, 트랜잭션, 저장 프로시저 및 데이터베이스 관리를 위한 빠른 참조 자료입니다.'
pdfUrl: '/cheatsheets/pdf/mysql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
MySQL 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/mysql">Hands-On 실습으로 MySQL 배우기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 기반 랩과 실제 시나리오를 통해 MySQL 데이터베이스 관리를 학습하세요. LabEx 는 필수 SQL 작업, 데이터베이스 관리, 성능 최적화 및 고급 쿼리 기술을 다루는 포괄적인 MySQL 과정을 제공합니다. 세계에서 가장 인기 있는 관계형 데이터베이스 시스템 중 하나를 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 데이터베이스 연결 및 관리

### 서버 연결: `mysql -u username -p`

명령줄을 사용하여 MySQL 서버에 연결합니다.

```bash
# 사용자 이름과 암호 프롬프트로 연결
mysql -u root -p
# 특정 데이터베이스에 연결
mysql -u username -p database_name
# 원격 서버에 연결
mysql -h hostname -u username -p
# 포트 지정하여 연결
mysql -h hostname -P 3306 -u username -p database_name
```

### 데이터베이스 작업: `CREATE` / `DROP` / `USE`

서버에서 데이터베이스를 관리합니다.

```sql
# 새 데이터베이스 생성
CREATE DATABASE company_db;
# 모든 데이터베이스 나열
SHOW DATABASES;
# 사용할 데이터베이스 선택
USE company_db;
# 데이터베이스 삭제 (영구 삭제)
DROP DATABASE old_database;
```

<BaseQuiz id="mysql-database-1" correct="C">
  <template #question>
    `USE database_name`은 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A">새 데이터베이스를 생성합니다</BaseQuizOption>
  <BaseQuizOption value="B">데이터베이스를 삭제합니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>후속 작업을 위해 데이터베이스를 선택합니다</BaseQuizOption>
  <BaseQuizOption value="D">데이터베이스의 모든 테이블을 표시합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `USE` 문은 데이터베이스를 선택하여 후속 SQL 문에 대해 활성 데이터베이스로 만듭니다. 이는 `mysql -u user -p database_name`으로 연결할 때 데이터베이스를 선택하는 것과 동일합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 데이터 내보내기: `mysqldump`

데이터베이스 데이터를 SQL 파일로 백업합니다.

```bash
# 전체 데이터베이스 내보내기
mysqldump -u username -p database_name > backup.sql
# 특정 테이블 내보내기
mysqldump -u username -p database_name table_name > table_backup.sql
# 구조만 내보내기
mysqldump -u username -p --no-data database_name > structure.sql
# 루틴 및 트리거를 포함한 전체 데이터베이스 백업
mysqldump -u username -p --routines --triggers database_name > backup.sql
```

### 데이터 가져오기: `mysql < file.sql`

MySQL 데이터베이스로 SQL 파일을 가져옵니다.

```bash
# SQL 파일을 데이터베이스로 가져오기
mysql -u username -p database_name < backup.sql
# (파일에 포함된 경우) 데이터베이스를 지정하지 않고 가져오기
mysql -u username -p < full_backup.sql
```

### 사용자 관리: `CREATE USER` / `GRANT`

데이터베이스 사용자 및 권한을 관리합니다.

```sql
# 새 사용자 생성
CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
# 모든 권한 부여
GRANT ALL PRIVILEGES ON database_name.* TO 'user'@'localhost';
# 특정 권한 부여
GRANT SELECT, INSERT, UPDATE ON table_name TO 'user'@'localhost';
# 권한 변경 사항 적용
FLUSH PRIVILEGES;
```

### 서버 정보 표시: `SHOW STATUS` / `SHOW VARIABLES`

서버 구성 및 상태를 표시합니다.

```sql
# 서버 상태 표시
SHOW STATUS;
# 구성 변수 표시
SHOW VARIABLES;
# 현재 프로세스 표시
SHOW PROCESSLIST;
```

## 테이블 구조 및 스키마

### 테이블 생성: `CREATE TABLE`

지정된 열과 데이터 유형으로 새 테이블을 생성합니다.

```sql
# 다양한 데이터 유형으로 테이블 생성
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    age INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# 외래 키가 있는 테이블 생성
CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### 테이블 정보: `DESCRIBE` / `SHOW`

테이블 구조와 데이터베이스 내용을 확인합니다.

```sql
# 테이블 구조 표시
DESCRIBE users;
# 대체 구문
SHOW COLUMNS FROM users;
# 모든 테이블 나열
SHOW TABLES;
# 테이블에 대한 CREATE 문 표시
SHOW CREATE TABLE users;
```

### 테이블 수정: `ALTER TABLE`

기존 테이블 구조를 변경하고 열을 추가하거나 삭제합니다.

```sql
# 새 열 추가
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
# 열 삭제
ALTER TABLE users DROP COLUMN age;
# 열 유형 수정
ALTER TABLE users MODIFY COLUMN username VARCHAR(100);
# 열 이름 변경
ALTER TABLE users CHANGE old_name new_name VARCHAR(50);
```

## 데이터 조작 및 CRUD 작업

### 데이터 삽입: `INSERT INTO`

테이블에 새 레코드를 추가합니다.

```sql
# 단일 레코드 삽입
INSERT INTO users (username, email, age)
VALUES ('john_doe', 'john@email.com', 25);
# 여러 레코드 삽입
INSERT INTO users (username, email, age) VALUES
('alice', 'alice@email.com', 30),
('bob', 'bob@email.com', 28);
# 다른 테이블에서 삽입
INSERT INTO users_backup SELECT * FROM users;
```

<BaseQuiz id="mysql-insert-1" correct="A">
  <template #question>
    단일 레코드를 삽입하는 올바른 구문은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A" correct>`INSERT INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="B">`INSERT table_name VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="C">`ADD INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="D">`INSERT table_name (column1, column2) = (value1, value2);`</BaseQuizOption>
  
  <BaseQuizAnswer>
    올바른 구문은 `INSERT INTO table_name (columns) VALUES (values)`입니다. `INTO` 키워드가 필요하며 열 이름과 해당 값을 모두 지정해야 합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 데이터 업데이트: `UPDATE`

테이블의 기존 레코드를 수정합니다.

```sql
# 특정 레코드 업데이트
UPDATE users SET age = 26 WHERE username = 'john_doe';
# 여러 열 업데이트
UPDATE users SET age = 31, email = 'alice_new@email.com'
WHERE username = 'alice';
# 계산을 통한 업데이트
UPDATE products SET price = price * 1.1 WHERE category = 'electronics';
```

### 데이터 삭제: `DELETE` / `TRUNCATE`

테이블에서 레코드를 제거합니다.

```sql
# 특정 레코드 삭제
DELETE FROM users WHERE age < 18;
# 모든 레코드 삭제 (구조 유지)
DELETE FROM users;
# 모든 레코드 삭제 (더 빠름, AUTO_INCREMENT 재설정)
TRUNCATE TABLE users;
# JOIN을 사용한 삭제
DELETE u FROM users u
JOIN inactive_accounts i ON u.id = i.user_id;
```

### 데이터 대체: `REPLACE` / `INSERT ... ON DUPLICATE KEY`

삽입 시 중복 키 상황을 처리합니다.

```sql
# 기존 항목 대체 또는 새 항목 삽입
REPLACE INTO users (id, username, email)
VALUES (1, 'updated_user', 'new@email.com');
# 중복 키 시 삽입 또는 업데이트
INSERT INTO users (username, email)
VALUES ('john', 'john@email.com')
ON DUPLICATE KEY UPDATE email = VALUES(email);
```

## 데이터 쿼리 및 선택

### 기본 SELECT: `SELECT * FROM`

다양한 조건으로 테이블에서 데이터를 검색합니다.

```sql
# 모든 열 선택
SELECT * FROM users;
# 특정 열 선택
SELECT username, email FROM users;
# WHERE 조건으로 선택
SELECT * FROM users WHERE age > 25;
# 다중 조건으로 선택
SELECT * FROM users WHERE age > 20 AND email LIKE '%gmail.com';
```

<BaseQuiz id="mysql-select-1" correct="D">
  <template #question>
    `SELECT * FROM users`는 무엇을 반환합니까?
  </template>
  
  <BaseQuizOption value="A">users 테이블의 첫 번째 행만</BaseQuizOption>
  <BaseQuizOption value="B">username 열만</BaseQuizOption>
  <BaseQuizOption value="C">테이블 구조</BaseQuizOption>
  <BaseQuizOption value="D" correct>users 테이블의 모든 열과 모든 행</BaseQuizOption>
  
  <BaseQuizAnswer>
    `*` 와일드카드는 모든 열을 선택하며, WHERE 절이 없으면 모든 행을 반환합니다. 이는 모든 데이터를 보는 데 유용하지만 대규모 테이블에서는 주의해서 사용해야 합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 정렬 및 제한: `ORDER BY` / `LIMIT`

반환되는 결과의 순서와 개수를 제어합니다.

```sql
# 결과 정렬
SELECT * FROM users ORDER BY age DESC;
# 다중 열로 정렬
SELECT * FROM users ORDER BY age DESC, username ASC;
# 결과 제한
SELECT * FROM users LIMIT 10;
# 페이지네이션 (처음 10개 건너뛰고 다음 10개 가져오기)
SELECT * FROM users LIMIT 10 OFFSET 10;
```

### 필터링: `WHERE` / `LIKE` / `IN`

다양한 비교 연산자를 사용하여 데이터를 필터링합니다.

```sql
# 패턴 일치
SELECT * FROM users WHERE username LIKE 'john%';
# 다중 값
SELECT * FROM users WHERE age IN (25, 30, 35);
# 범위 필터링
SELECT * FROM users WHERE age BETWEEN 20 AND 30;
# NULL 확인
SELECT * FROM users WHERE email IS NOT NULL;
```

### 그룹화: `GROUP BY` / `HAVING`

데이터를 그룹화하고 집계 함수를 적용합니다.

```sql
# 열별 그룹화
SELECT age, COUNT(*) FROM users GROUP BY age;
# 그룹에 대한 조건 포함
SELECT age, COUNT(*) as count FROM users
GROUP BY age HAVING count > 1;
# 다중 그룹화 열
SELECT age, gender, COUNT(*) FROM users
GROUP BY age, gender;
```

## 고급 쿼리

### JOIN 작업: `INNER` / `LEFT` / `RIGHT`

여러 테이블의 데이터를 결합합니다.

```sql
# 내부 조인 (일치하는 레코드만)
SELECT u.username, o.order_date
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# 왼쪽 조인 (모든 사용자, 일치하는 주문)
SELECT u.username, o.order_date
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# 다중 조인
SELECT u.username, o.order_date, p.product_name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

<BaseQuiz id="mysql-join-1" correct="B">
  <template #question>
    INNER JOIN 과 LEFT JOIN 의 차이점은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">차이가 없습니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>INNER JOIN 은 일치하는 행만 반환하고, LEFT JOIN 은 왼쪽 테이블의 모든 행을 반환합니다</BaseQuizOption>
  <BaseQuizOption value="C">INNER JOIN 이 더 빠릅니다</BaseQuizOption>
  <BaseQuizOption value="D">LEFT JOIN 은 두 테이블에서만 작동합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    INNER JOIN 은 두 테이블에서 일치하는 행만 반환합니다. LEFT JOIN 은 왼쪽 테이블의 모든 행과 오른쪽 테이블의 일치하는 행을 반환하며, 일치하지 않는 오른쪽 테이블 행에 대해서는 NULL 값을 반환합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 서브쿼리: `SELECT` 내의 `SELECT`

복잡한 데이터 검색을 위해 중첩된 쿼리를 사용합니다.

```sql
# WHERE 절의 서브쿼리
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders WHERE total > 100);
# 상관 관계가 있는 서브쿼리
SELECT username FROM users u1
WHERE age > (SELECT AVG(age) FROM users u2);
# SELECT 절의 서브쿼리
SELECT username,
(SELECT COUNT(*) FROM orders WHERE user_id = users.id) as order_count
FROM users;
```

### 집계 함수: `COUNT` / `SUM` / `AVG`

데이터에서 통계 및 요약을 계산합니다.

```sql
# 기본 집계
SELECT COUNT(*) FROM users;
SELECT AVG(age), MIN(age), MAX(age) FROM users;
SELECT SUM(total) FROM orders;
# 그룹화된 집계
SELECT department, AVG(salary)
FROM employees GROUP BY department;
# 다중 집계
SELECT
    COUNT(*) as total_users,
    AVG(age) as avg_age,
    MAX(created_at) as latest_signup
FROM users;
```

### 윈도우 함수: `OVER` / `PARTITION BY`

테이블 행 집합에 걸쳐 계산을 수행합니다.

```sql
# 순위 함수
SELECT username, age,
RANK() OVER (ORDER BY age DESC) as age_rank
FROM users;
# 그룹별 분할
SELECT username, department, salary,
AVG(salary) OVER (PARTITION BY department) as dept_avg
FROM employees;
# 누계 합계
SELECT order_date, total,
SUM(total) OVER (ORDER BY order_date) as running_total
FROM orders;
```

## 인덱스 및 성능

### 인덱스 생성: `CREATE INDEX`

데이터베이스 인덱스를 사용하여 쿼리 성능을 향상시킵니다.

```sql
# 일반 인덱스 생성
CREATE INDEX idx_username ON users(username);
# 복합 인덱스 생성
CREATE INDEX idx_user_age ON users(username, age);
# 고유 인덱스 생성
CREATE UNIQUE INDEX idx_email ON users(email);
# 테이블의 인덱스 표시
SHOW INDEXES FROM users;
```

### 쿼리 분석: `EXPLAIN`

쿼리 실행 계획 및 성능을 분석합니다.

```sql
# 쿼리 실행 계획 표시
EXPLAIN SELECT * FROM users WHERE age > 25;
# 상세 분석
EXPLAIN FORMAT=JSON SELECT u.*, o.total
FROM users u JOIN orders o ON u.id = o.user_id;
# 쿼리 성능 표시
SHOW PROFILES;
SET profiling = 1;
```

### 쿼리 최적화: 모범 사례

효율적인 SQL 쿼리 작성을 위한 기술.

```sql
# * 대신 특정 열 사용
SELECT username, email FROM users WHERE id = 1;
# 대규모 데이터 세트에 LIMIT 사용
SELECT * FROM logs ORDER BY created_at DESC LIMIT 1000;
# 적절한 WHERE 조건 사용
SELECT * FROM orders WHERE user_id = 123 AND status = 'pending';
-- 커버링 인덱스 사용 시도
```

### 테이블 유지 관리: `OPTIMIZE` / `ANALYZE`

테이블 성능 및 통계를 유지 관리합니다.

```sql
# 테이블 저장 공간 최적화
OPTIMIZE TABLE users;
# 테이블 통계 업데이트
ANALYZE TABLE users;
# 테이블 무결성 확인
CHECK TABLE users;
# 필요한 경우 테이블 복구
REPAIR TABLE users;
```

## 데이터 가져오기/내보내기

### 데이터 로드: `LOAD DATA INFILE`

CSV 및 텍스트 파일에서 데이터를 가져옵니다.

```sql
# CSV 파일 로드
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
# 특정 열 로드
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users (username, email, age);
```

### 데이터 내보내기: `SELECT INTO OUTFILE`

쿼리 결과를 파일로 내보냅니다.

```sql
# CSV 파일로 내보내기
SELECT username, email, age
FROM users
INTO OUTFILE '/path/to/export.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

### 백업 및 복원: `mysqldump` / `mysql`

데이터베이스 백업을 생성하고 복원합니다.

```bash
# 특정 테이블 백업
mysqldump -u username -p database_name table1 table2 > tables_backup.sql
# 백업에서 복원
mysql -u username -p database_name < backup.sql
# 원격 서버에서 내보내기
mysqldump -h remote_host -u username -p database_name > remote_backup.sql
# 로컬 데이터베이스로 가져오기
mysql -u local_user -p local_database < remote_backup.sql
# 서버 간 직접 데이터 복사
mysqldump -h source_host -u user -p db_name | mysql -h dest_host -u user -p db_name
```

## 데이터 유형 및 함수

### 일반 데이터 유형: 숫자, 텍스트, 날짜

열에 적절한 데이터 유형을 선택합니다.

```sql
# 숫자 유형
INT, BIGINT, DECIMAL(10,2), FLOAT, DOUBLE
# 문자열 유형
VARCHAR(255), TEXT, CHAR(10), MEDIUMTEXT, LONGTEXT
# 날짜 및 시간 유형
DATE, TIME, DATETIME, TIMESTAMP, YEAR
# 부울 및 바이너리
BOOLEAN, BLOB, VARBINARY

# 예제 테이블 생성
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 문자열 함수: `CONCAT` / `SUBSTRING` / `LENGTH`

내장 문자열 함수를 사용하여 텍스트 데이터를 조작합니다.

```sql
# 문자열 연결
SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users;
# 문자열 작업
SELECT SUBSTRING(email, 1, LOCATE('@', email)-1) as username FROM users;
SELECT LENGTH(username), UPPER(username) FROM users;
# 패턴 일치 및 대체
SELECT REPLACE(phone, '-', '.') FROM users WHERE phone LIKE '___-___-____';
```

### 날짜 함수: `NOW()` / `DATE_ADD` / `DATEDIFF`

날짜와 시간을 효과적으로 다룹니다.

```sql
# 현재 날짜 및 시간
SELECT NOW(), CURDATE(), CURTIME();
# 날짜 산술
SELECT DATE_ADD(created_at, INTERVAL 30 DAY) as expiry_date FROM users;
SELECT DATEDIFF(NOW(), created_at) as days_since_signup FROM users;
# 날짜 형식 지정
SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') as formatted_date FROM orders;
```

### 숫자 함수: `ROUND` / `ABS` / `RAND`

숫자 데이터에 대해 수학적 연산을 수행합니다.

```sql
# 수학 함수
SELECT ROUND(price, 2), ABS(profit_loss), SQRT(area) FROM products;
# 무작위 및 통계
SELECT RAND(), FLOOR(price), CEIL(rating) FROM products;
# 집계 수학
SELECT AVG(price), STDDEV(price), VARIANCE(price) FROM products;
```

## 트랜잭션 관리

### 트랜잭션 제어: `BEGIN` / `COMMIT` / `ROLLBACK`

데이터 일관성을 위해 데이터베이스 트랜잭션을 관리합니다.

```sql
# 트랜잭션 시작
BEGIN;
# 또는
START TRANSACTION;
# 작업 수행
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;
# 변경 사항 확정
COMMIT;
# 또는 오류 발생 시 롤백
ROLLBACK;
```

### 트랜잭션 격리 수준: `SET TRANSACTION ISOLATION`

트랜잭션이 서로 상호 작용하는 방식을 제어합니다.

```sql
# 격리 수준 설정
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
# 현재 격리 수준 표시
SELECT @@transaction_isolation;
```

### 잠금: `LOCK TABLES` / `SELECT FOR UPDATE`

데이터에 대한 동시 액세스를 제어합니다.

```sql
# 배타적 액세스를 위해 테이블 잠금
LOCK TABLES users WRITE, orders READ;
# 작업 수행
# ...
UNLOCK TABLES;
# 트랜잭션 내의 행 수준 잠금
BEGIN;
SELECT * FROM accounts WHERE id = 1 FOR UPDATE;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
COMMIT;
```

### 저장점: `SAVEPOINT` / `ROLLBACK TO`

트랜잭션 내에서 롤백 지점을 생성합니다.

```sql
BEGIN;
INSERT INTO users (username) VALUES ('user1');
SAVEPOINT sp1;
INSERT INTO users (username) VALUES ('user2');
SAVEPOINT sp2;
INSERT INTO users (username) VALUES ('user3');
# 저장점으로 롤백
ROLLBACK TO sp1;
COMMIT;
```

## 고급 SQL 기술

### 공통 테이블 표현식 (CTE): `WITH`

복잡한 쿼리를 위해 임시 결과 집합을 생성합니다.

```sql
# 단순 CTE
WITH user_orders AS (
    SELECT user_id, COUNT(*) as order_count,
           SUM(total) as total_spent
    FROM orders
    GROUP BY user_id
)
SELECT u.username, uo.order_count, uo.total_spent
FROM users u
JOIN user_orders uo ON u.id = uo.user_id
WHERE uo.total_spent > 1000;
```

### 저장 프로시저: `CREATE PROCEDURE`

재사용 가능한 데이터베이스 프로시저를 생성합니다.

```sql
# 저장 프로시저 생성
DELIMITER //
CREATE PROCEDURE GetUserOrders(IN user_id INT)
BEGIN
    SELECT o.*, p.product_name
    FROM orders o
    JOIN products p ON o.product_id = p.id
    WHERE o.user_id = user_id;
END //
DELIMITER ;
# 프로시저 호출
CALL GetUserOrders(123);
```

### 트리거: `CREATE TRIGGER`

데이터베이스 이벤트에 응답하여 코드를 자동으로 실행합니다.

```sql
# 감사 로깅을 위한 트리거 생성
CREATE TRIGGER user_update_audit
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    INSERT INTO user_audit (user_id, old_email, new_email, changed_at)
    VALUES (NEW.id, OLD.email, NEW.email, NOW());
END;
# 트리거 표시
SHOW TRIGGERS;
```

### 뷰: `CREATE VIEW`

쿼리 결과를 기반으로 가상 테이블을 생성합니다.

```sql
# 뷰 생성
CREATE VIEW active_users AS
SELECT id, username, email, created_at
FROM users
WHERE status = 'active' AND last_login > DATE_SUB(NOW(), INTERVAL 30 DAY);
# 테이블처럼 뷰 사용
SELECT * FROM active_users WHERE username LIKE 'john%';
# 뷰 삭제
DROP VIEW active_users;
```

## MySQL 설치 및 설정

### 설치: 패키지 관리자

시스템 패키지 관리자를 사용하여 MySQL 을 설치합니다.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# CentOS/RHEL
sudo yum install mysql-server
# macOS with Homebrew
brew install mysql
# MySQL 서비스 시작
sudo systemctl start mysql
```

### Docker: `docker run mysql`

개발을 위해 MySQL 을 Docker 컨테이너에서 실행합니다.

```bash
# MySQL 컨테이너 실행
docker run --name mysql-dev -e MYSQL_ROOT_PASSWORD=password -p 3306:3306 -d mysql:8.0
# 컨테이너화된 MySQL에 연결
docker exec -it mysql-dev mysql -u root -p
# 컨테이너에서 데이터베이스 생성
docker exec -it mysql-dev mysql -u root -p -e "CREATE DATABASE testdb;"
```

### 초기 설정 및 보안

MySQL 설치를 보호하고 설정을 확인합니다.

```bash
# 보안 스크립트 실행
sudo mysql_secure_installation
# MySQL에 연결
mysql -u root -p
# MySQL 버전 표시
SELECT VERSION();
# 연결 상태 확인
STATUS;
# 루트 암호 설정
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
```

## 구성 및 설정

### 구성 파일: `my.cnf`

MySQL 서버 구성을 수정합니다.

```ini
# 일반적인 구성 위치
# Linux: /etc/mysql/my.cnf
# Windows: C:\ProgramData\MySQL\MySQL Server\my.ini
# macOS: /usr/local/etc/my.cnf

[mysqld]
max_connections = 200
innodb_buffer_pool_size = 1G
query_cache_size = 64M
slow_query_log = 1
long_query_time = 2
```

### 런타임 구성: `SET GLOBAL`

MySQL 이 실행되는 동안 설정을 변경합니다.

```sql
# 전역 변수 설정
SET GLOBAL max_connections = 500;
SET GLOBAL slow_query_log = ON;
# 현재 설정 표시
SHOW VARIABLES LIKE 'max_connections';
SHOW GLOBAL STATUS LIKE 'Slow_queries';
```

### 성능 튜닝: 메모리 및 캐시

MySQL 성능 설정을 최적화합니다.

```sql
# 메모리 사용량 표시
SHOW VARIABLES LIKE '%buffer_pool_size%';
SHOW VARIABLES LIKE '%query_cache%';
# 성능 모니터링
SHOW STATUS LIKE 'Qcache%';
SHOW STATUS LIKE 'Created_tmp%';
# InnoDB 설정
SET GLOBAL innodb_buffer_pool_size = 2147483648; -- 2GB
```

### 로깅 구성: 오류 및 쿼리 로그

모니터링 및 디버깅을 위해 MySQL 로깅을 구성합니다.

```sql
# 쿼리 로깅 활성화
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/query.log';
# 느린 쿼리 로그
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
# 로그 설정 표시
SHOW VARIABLES LIKE '%log%';
```

## 관련 링크

- <router-link to="/database">데이터베이스 치트 시트</router-link>
- <router-link to="/postgresql">PostgreSQL 치트 시트</router-link>
- <router-link to="/sqlite">SQLite 치트 시트</router-link>
- <router-link to="/mongodb">MongoDB 치트 시트</router-link>
- <router-link to="/redis">Redis 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>

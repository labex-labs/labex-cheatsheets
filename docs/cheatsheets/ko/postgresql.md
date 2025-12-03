---
title: 'PostgreSQL 치트 시트 | LabEx'
description: '이 포괄적인 치트 시트로 PostgreSQL 데이터베이스 관리를 학습하세요. SQL 쿼리, 고급 기능, JSON 지원, 전문 검색 및 엔터프라이즈 데이터베이스 관리를 위한 빠른 참조 자료입니다.'
pdfUrl: '/cheatsheets/pdf/postgresql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
PostgreSQL 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/postgresql">Hands-On 실습으로 PostgreSQL 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 기반 랩과 실제 시나리오를 통해 PostgreSQL 데이터베이스 관리를 학습하세요. LabEx 는 필수 SQL 작업, 고급 쿼리, 성능 최적화, 데이터베이스 관리 및 보안을 다루는 포괄적인 PostgreSQL 과정을 제공합니다. 엔터프라이즈급 관계형 데이터베이스 개발 및 관리를 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 연결 및 데이터베이스 설정

### PostgreSQL 연결: `psql`

psql 명령줄 도구를 사용하여 로컬 또는 원격 PostgreSQL 데이터베이스에 연결합니다.

```bash
# 로컬 데이터베이스에 연결
psql -U username -d database_name
# 원격 데이터베이스에 연결
psql -h hostname -p 5432 -U username -d database_name
# 비밀번호 프롬프트로 연결
psql -U postgres -W
# 연결 문자열 사용으로 연결
psql "host=localhost port=5432 dbname=mydb user=myuser"
```

### 데이터베이스 생성: `CREATE DATABASE`

CREATE DATABASE 명령을 사용하여 PostgreSQL 에 새 데이터베이스를 생성합니다.

```sql
# 새 데이터베이스 생성
CREATE DATABASE mydatabase;
# 소유자와 함께 데이터베이스 생성
CREATE DATABASE mydatabase OWNER myuser;
# 인코딩과 함께 데이터베이스 생성
CREATE DATABASE mydatabase
  WITH ENCODING 'UTF8'
  LC_COLLATE='en_US.UTF-8'
  LC_CTYPE='en_US.UTF-8';
```

### 데이터베이스 목록 보기: `\l`

PostgreSQL 서버의 모든 데이터베이스를 나열합니다.

```bash
# 모든 데이터베이스 나열
\l
# 상세 정보와 함께 데이터베이스 나열
\l+
# 다른 데이터베이스로 연결
\c database_name
```

### 기본 psql 명령어

탐색 및 정보 확인을 위한 필수 psql 터미널 명령어입니다.

```bash
# psql 종료
\q
# SQL 명령어 도움말 보기
\help CREATE TABLE
# psql 명령어 도움말 보기
\?
# 현재 데이터베이스 및 사용자 표시
\conninfo
# 시스템 명령어 실행
\! ls
# 모든 테이블 나열
\dt
# 상세 정보와 함께 모든 테이블 나열
\dt+
# 특정 테이블 설명
\d table_name
# 모든 스키마 나열
\dn
# 모든 사용자/역할 나열
\du
```

### 버전 및 설정

PostgreSQL 버전 및 구성 설정을 확인합니다.

```sql
# PostgreSQL 버전 확인
SELECT version();
# 모든 현재 설정 보기
SHOW ALL;
# 특정 설정 보기
SHOW max_connections;
# 구성 매개변수 설정
SET work_mem = '256MB';
```

## 테이블 생성 및 관리

### 테이블 생성: `CREATE TABLE`

열, 데이터 유형 및 제약 조건을 정의하여 새 테이블을 정의합니다.

```sql
# 기본 테이블 생성
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

# 외래 키가 있는 테이블
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending'
);
```

<BaseQuiz id="postgresql-create-table-1" correct="A">
  <template #question>
    PostgreSQL 에서 <code>SERIAL PRIMARY KEY</code>는 어떤 역할을 하나요?
  </template>
  
  <BaseQuizOption value="A" correct>자동 증가하는 정수 열을 생성하고 기본 키 역할을 수행합니다</BaseQuizOption>
  <BaseQuizOption value="B">텍스트 열을 생성합니다</BaseQuizOption>
  <BaseQuizOption value="C">외래 키 제약 조건을 생성합니다</BaseQuizOption>
  <BaseQuizOption value="D">고유 인덱스를 생성합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>SERIAL</code> 은 PostgreSQL 고유의 데이터 유형으로 자동 증가하는 정수를 생성합니다. <code>PRIMARY KEY</code>와 결합되어 각 행에 대해 자동으로 증가하는 고유 식별자를 생성합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 테이블 수정: `ALTER TABLE`

기존 테이블에서 열 및 제약 조건을 추가, 수정 또는 제거합니다.

```sql
# 새 열 추가
ALTER TABLE users ADD COLUMN phone VARCHAR(15);
# 열 유형 변경
ALTER TABLE users ALTER COLUMN phone TYPE VARCHAR(20);
# 열 삭제
ALTER TABLE users DROP COLUMN phone;
# 제약 조건 추가
ALTER TABLE users ADD CONSTRAINT unique_email
    UNIQUE (email);
```

### 삭제 및 비우기: `DROP/TRUNCATE`

테이블을 제거하거나 테이블의 모든 데이터를 지웁니다.

```sql
# 테이블 전체 삭제
DROP TABLE IF EXISTS old_table;
# 구조는 유지하고 모든 데이터 제거
TRUNCATE TABLE users;
# IDENTITY 재시작과 함께 비우기
TRUNCATE TABLE users RESTART IDENTITY;
```

### 데이터 유형 및 제약 조건

다양한 종류의 데이터에 필수적인 PostgreSQL 데이터 유형입니다.

```sql
# 숫자 유형
INTEGER, BIGINT, SMALLINT
DECIMAL(10,2), NUMERIC(10,2)
REAL, DOUBLE PRECISION

# 문자열 유형
CHAR(n), VARCHAR(n), TEXT

# 날짜/시간 유형
DATE, TIME, TIMESTAMP
TIMESTAMPTZ (시간대 포함)

# 부울 및 기타
BOOLEAN
JSON, JSONB
UUID
ARRAY (예: INTEGER[])

# 기본 키
id SERIAL PRIMARY KEY

# 외래 키
user_id INTEGER REFERENCES users(id)

# 고유 제약 조건
email VARCHAR(100) UNIQUE

# CHECK 제약 조건
age INTEGER CHECK (age >= 0)

# NOT NULL
name VARCHAR(50) NOT NULL
```

### 인덱스: `CREATE INDEX`

데이터베이스 인덱스를 사용하여 쿼리 성능을 향상시킵니다.

```sql
# 기본 인덱스
CREATE INDEX idx_username ON users(username);
# 고유 인덱스
CREATE UNIQUE INDEX idx_unique_email
    ON users(email);
# 복합 인덱스
CREATE INDEX idx_user_date
    ON orders(user_id, created_at);
# 부분 인덱스
CREATE INDEX idx_active_users
    ON users(username) WHERE active = true;
# 인덱스 삭제
DROP INDEX IF EXISTS idx_username;
```

<BaseQuiz id="postgresql-index-1" correct="A">
  <template #question>
    PostgreSQL 에서 인덱스를 생성하는 주된 목적은 무엇인가요?
  </template>
  
  <BaseQuizOption value="A" correct>데이터 검색 속도를 높여 쿼리 성능을 개선하기 위함</BaseQuizOption>
  <BaseQuizOption value="B">데이터베이스 크기를 줄이기 위함</BaseQuizOption>
  <BaseQuizOption value="C">데이터를 암호화하기 위함</BaseQuizOption>
  <BaseQuizOption value="D">중복 항목 생성을 방지하기 위함</BaseQuizOption>
  
  <BaseQuizAnswer>
    인덱스는 데이터베이스가 전체 테이블을 스캔하지 않고도 행을 빠르게 찾을 수 있도록 데이터 구조를 생성합니다. 이는 특히 대규모 테이블에서 SELECT 쿼리를 크게 가속화합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 시퀀스: `CREATE SEQUENCE`

고유한 숫자 값을 자동으로 생성합니다.

```sql
# 시퀀스 생성
CREATE SEQUENCE user_id_seq;
# 테이블에서 시퀀스 사용
CREATE TABLE users (
    id INTEGER DEFAULT nextval('user_id_seq'),
    username VARCHAR(50)
);
# 시퀀스 재시작
ALTER SEQUENCE user_id_seq RESTART WITH 1000;
```

## CRUD 작업

### 데이터 삽입: `INSERT`

데이터베이스 테이블에 새 레코드를 추가합니다.

```sql
# 단일 레코드 삽입
INSERT INTO users (username, email)
VALUES ('john_doe', 'john@example.com');
# 여러 레코드 삽입
INSERT INTO users (username, email) VALUES
    ('alice', 'alice@example.com'),
    ('bob', 'bob@example.com');
# 반환 값과 함께 삽입
INSERT INTO users (username, email)
VALUES ('jane', 'jane@example.com')
RETURNING id, created_at;
# 선택(SELECT)으로부터 삽입
INSERT INTO archive_users
SELECT * FROM users WHERE active = false;
```

<BaseQuiz id="postgresql-insert-1" correct="C">
  <template #question>
    PostgreSQL 의 INSERT 문에서 <code>RETURNING</code> 은 무엇을 하나요?
  </template>
  
  <BaseQuizOption value="A">삽입을 롤백합니다</BaseQuizOption>
  <BaseQuizOption value="B">삽입을 방지합니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>삽입된 행 데이터를 반환합니다</BaseQuizOption>
  <BaseQuizOption value="D">기존 행을 업데이트합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    PostgreSQL 의 <code>RETURNING</code> 절은 삽입 후 즉시 삽입된 행 데이터 (또는 특정 열) 를 검색할 수 있게 해주며, 자동 생성된 ID 나 타임스탬프를 얻을 때 유용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 데이터 업데이트: `UPDATE`

데이터베이스 테이블의 기존 레코드를 수정합니다.

```sql
# 특정 레코드 업데이트
UPDATE users
SET email = 'newemail@example.com'
WHERE username = 'john_doe';
# 여러 열 업데이트
UPDATE users
SET email = 'new@example.com',
    updated_at = NOW()
WHERE id = 1;
# 서브쿼리와 함께 업데이트
UPDATE orders
SET total = (SELECT SUM(price) FROM order_items
            WHERE order_id = orders.id);
```

### 데이터 선택: `SELECT`

데이터베이스 테이블에서 데이터를 쿼리하고 검색합니다.

```sql
# 기본 선택
SELECT * FROM users;
# 특정 열 선택
SELECT id, username, email FROM users;
# 조건부 선택
SELECT * FROM users
WHERE active = true AND created_at > '2024-01-01';
# 정렬 및 제한 포함 선택
SELECT * FROM users
ORDER BY created_at DESC
LIMIT 10 OFFSET 20;
```

### 데이터 삭제: `DELETE`

데이터베이스 테이블에서 레코드를 제거합니다.

```sql
# 특정 레코드 삭제
DELETE FROM users
WHERE active = false;
# 서브쿼리와 함께 삭제
DELETE FROM orders
WHERE user_id IN (
    SELECT id FROM users WHERE active = false
);
# 모든 레코드 삭제
DELETE FROM temp_table;
# 반환 값과 함께 삭제
DELETE FROM users
WHERE id = 5
RETURNING *;
```

## 고급 쿼리

### 조인: `INNER/LEFT/RIGHT JOIN`

다양한 조인 유형을 사용하여 여러 테이블의 데이터를 결합합니다.

```sql
# 내부 조인 (Inner join)
SELECT u.username, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# 왼쪽 조인 (Left join)
SELECT u.username, o.total
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# 다중 조인
SELECT u.username, o.total, p.name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

### 서브쿼리 및 CTE

복잡한 작업을 위해 중첩된 쿼리와 공통 테이블 표현식 (CTE) 을 사용합니다.

```sql
# WHERE 절의 서브쿼리
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders);
# 공통 테이블 표현식 (CTE)
WITH active_users AS (
    SELECT * FROM users WHERE active = true
)
SELECT au.username, COUNT(o.id) as order_count
FROM active_users au
LEFT JOIN orders o ON au.id = o.user_id
GROUP BY au.username;
```

### 집계: `GROUP BY`

데이터를 그룹화하고 분석을 위해 집계 함수를 적용합니다.

```sql
# 기본 그룹화
SELECT status, COUNT(*) as count
FROM orders
GROUP BY status;
# 다중 집계
SELECT user_id,
       COUNT(*) as order_count,
       SUM(total) as total_spent,
       AVG(total) as avg_order
FROM orders
GROUP BY user_id
HAVING COUNT(*) > 5;
```

### 윈도우 함수 (Window Functions)

그룹화 없이 관련 행에 걸쳐 계산을 수행합니다.

```sql
# 행 번호 매기기
SELECT username, email,
       ROW_NUMBER() OVER (ORDER BY created_at) as row_num
FROM users;
# 누계 합계
SELECT date, amount,
       SUM(amount) OVER (ORDER BY date) as running_total
FROM sales;
# 순위 매기기
SELECT username, score,
       RANK() OVER (ORDER BY score DESC) as rank
FROM user_scores;
```

## 데이터 가져오기 및 내보내기

### CSV 가져오기: `COPY`

CSV 파일에서 PostgreSQL 테이블로 데이터를 가져옵니다.

```sql
# CSV 파일에서 가져오기
COPY users(username, email, age)
FROM '/path/to/users.csv'
DELIMITER ',' CSV HEADER;
# 특정 옵션으로 가져오기
COPY products
FROM '/path/to/products.csv'
WITH (FORMAT csv, HEADER true, DELIMITER ';');
# stdin에서 가져오기
\copy users(username, email) FROM STDIN WITH CSV;
```

### CSV 내보내기: `COPY TO`

PostgreSQL 데이터를 CSV 파일로 내보냅니다.

```sql
# CSV 파일로 내보내기
COPY users TO '/path/to/users_export.csv'
WITH (FORMAT csv, HEADER true);
# 쿼리 결과 내보내기
COPY (SELECT username, email FROM users WHERE active = true)
TO '/path/to/active_users.csv' CSV HEADER;
# stdout으로 내보내기
\copy (SELECT * FROM orders) TO STDOUT WITH CSV HEADER;
```

### 백업 및 복원: `pg_dump`

데이터베이스 백업을 생성하고 백업 파일에서 복원합니다.

```bash
# 전체 데이터베이스 덤프
pg_dump -U username -h hostname database_name > backup.sql
# 특정 테이블 덤프
pg_dump -U username -t table_name database_name > table_backup.sql
# 압축된 백업
pg_dump -U username -Fc database_name > backup.dump
# 백업에서 복원
psql -U username -d database_name < backup.sql
# 압축된 백업 복원
pg_restore -U username -d database_name backup.dump
```

### JSON 데이터 작업

반정형 데이터를 위해 JSON 및 JSONB 데이터 유형을 사용합니다.

```sql
# JSON 데이터 삽입
INSERT INTO products (name, metadata)
VALUES ('Laptop', '{"brand": "Dell", "price": 999.99}');
# JSON 필드 쿼리
SELECT name, metadata->>'brand' as brand
FROM products
WHERE metadata->>'price'::numeric > 500;
# JSON 배열 작업
SELECT name FROM products
WHERE metadata->'features' ? 'wireless';
```

## 사용자 관리 및 보안

### 사용자 및 역할 생성

사용자 및 역할을 사용하여 데이터베이스 액세스를 관리합니다.

```sql
# 사용자 생성
CREATE USER myuser WITH PASSWORD 'secretpassword';
# 역할 생성
CREATE ROLE readonly_user;
# 특정 권한을 가진 사용자 생성
CREATE USER admin_user WITH
    CREATEDB CREATEROLE PASSWORD 'adminpass';
# 사용자에게 역할 부여
GRANT readonly_user TO myuser;
```

### 권한: `GRANT/REVOKE`

권한을 통해 데이터베이스 객체에 대한 액세스를 제어합니다.

```sql
# 사용자에게 테이블 권한 부여
GRANT SELECT, INSERT ON users TO myuser;
# 테이블에 모든 권한 부여
GRANT ALL ON orders TO admin_user;
# 데이터베이스 권한 부여
GRANT CONNECT ON DATABASE mydb TO myuser;
# 권한 취소
REVOKE INSERT ON users FROM myuser;
```

### 사용자 정보 보기

기존 사용자 및 권한을 확인합니다.

```sql
# 모든 사용자 나열
\du
# 테이블 권한 보기
SELECT table_name, privilege_type, grantee
FROM information_schema.table_privileges
WHERE table_schema = 'public';
# 현재 사용자 보기
SELECT current_user;
# 역할 멤버십 보기
SELECT r.rolname, r.rolsuper, r.rolcreaterole
FROM pg_roles r;
```

### 비밀번호 및 보안

사용자 비밀번호 및 보안 설정을 관리합니다.

```sql
# 사용자 비밀번호 변경
ALTER USER myuser PASSWORD 'newpassword';
# 비밀번호 만료 설정
ALTER USER myuser VALID UNTIL '2025-12-31';
# 로그인 없이 역할 생성
CREATE ROLE reporting_role NOLOGIN;
# 사용자 활성화/비활성화
ALTER USER myuser WITH NOLOGIN;
ALTER USER myuser WITH LOGIN;
```

## 성능 및 모니터링

### 쿼리 분석: `EXPLAIN`

쿼리 실행 계획을 분석하고 성능을 최적화합니다.

```sql
# 쿼리 실행 계획 표시
EXPLAIN SELECT * FROM users WHERE active = true;
# 실제 실행 통계로 분석
EXPLAIN ANALYZE
SELECT u.username, COUNT(o.id)
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.username;
# 상세 실행 정보
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT * FROM large_table WHERE indexed_col = 'value';
```

### 데이터베이스 유지 관리: `VACUUM`

정기적인 정리 작업을 통해 데이터베이스 성능을 유지합니다.

```sql
# 기본 vacuum
VACUUM users;
# 전체 vacuum 및 분석
VACUUM FULL ANALYZE users;
# 자동 vacuum 상태
SELECT schemaname, tablename, last_vacuum, last_autovacuum
FROM pg_stat_user_tables;
# 테이블 재인덱싱
REINDEX TABLE users;
```

### 쿼리 모니터링

데이터베이스 활동을 추적하고 성능 문제를 식별합니다.

```sql
# 현재 활동
SELECT pid, usename, query, state
FROM pg_stat_activity
WHERE state != 'idle';
# 오래 실행되는 쿼리
SELECT pid, now() - query_start as duration, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC;
# 특정 쿼리 종료
SELECT pg_terminate_backend(pid) WHERE pid = 12345;
```

### 데이터베이스 통계

데이터베이스 사용량 및 성능 메트릭에 대한 통찰력을 얻습니다.

```sql
# 테이블 통계
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del
FROM pg_stat_user_tables;
# 인덱스 사용 통계
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes;
# 데이터베이스 크기
SELECT pg_size_pretty(pg_database_size('mydatabase'));
```

## 고급 기능

### 뷰: `CREATE VIEW`

복잡한 쿼리를 단순화하고 데이터 추상화를 제공하기 위해 가상 테이블을 생성합니다.

```sql
# 간단한 뷰 생성
CREATE VIEW active_users AS
SELECT id, username, email
FROM users WHERE active = true;
# 조인을 사용한 뷰 생성
CREATE OR REPLACE VIEW order_summary AS
SELECT u.username, COUNT(o.id) as total_orders,
       SUM(o.total) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.username;
# 뷰 삭제
DROP VIEW IF EXISTS order_summary;
```

### 트리거 및 함수

저장 프로시저 및 트리거를 사용하여 데이터베이스 작업을 자동화합니다.

```sql
# 함수 생성
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
# 트리거 생성
CREATE TRIGGER update_user_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();
```

### 트랜잭션

트랜잭션 제어를 통해 데이터 일관성을 보장합니다.

```sql
# 트랜잭션 시작
BEGIN;
UPDATE accounts SET balance = balance - 100
WHERE id = 1;
UPDATE accounts SET balance = balance + 100
WHERE id = 2;
# 트랜잭션 커밋
COMMIT;
# 필요한 경우 롤백
ROLLBACK;
# 저장점 (Savepoints)
SAVEPOINT my_savepoint;
ROLLBACK TO my_savepoint;
```

### 구성 및 튜닝

더 나은 성능을 위해 PostgreSQL 서버 설정을 최적화합니다.

```sql
# 현재 구성 보기
SHOW shared_buffers;
SHOW max_connections;
# 구성 매개변수 설정
SET work_mem = '256MB';
SET random_page_cost = 1.1;
# 구성 다시 로드
SELECT pg_reload_conf();
# 구성 파일 위치 보기
SHOW config_file;
```

## psql 구성 및 팁

### 연결 파일: `.pgpass`

자동 인증을 위해 데이터베이스 자격 증명을 안전하게 저장합니다.

```bash
# .pgpass 파일 생성 (형식: hostname:port:database:username:password)
echo "localhost:5432:mydatabase:myuser:mypassword" >> ~/.pgpass
# 적절한 권한 설정
chmod 600 ~/.pgpass
# 연결 서비스 파일 사용
# ~/.pg_service.conf
[mydb]
host=localhost
port=5432
dbname=mydatabase
user=myuser
```

### psql 구성: `.psqlrc`

psql 시작 설정을 사용자 지정하고 동작을 사용자 지정합니다.

```bash
# ~/.psqlrc 파일에 사용자 지정 설정 생성
\set QUIET on
\timing on
\set PROMPT1 '%n@%M:%> %`date` %R%# '
\set HISTSIZE 5000
\set COMP_KEYWORD_CASE upper
\x auto
\set QUIET off
# 사용자 지정 별칭
\set show_slow_queries 'SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;'
```

### 환경 변수

더 쉬운 연결을 위해 PostgreSQL 환경 변수를 설정합니다.

```bash
# 셸 프로필에 설정
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=mydatabase
export PGUSER=myuser
# 그런 다음 간단히 연결
psql
# 또는 특정 환경 사용
PGDATABASE=testdb psql
```

### 데이터베이스 정보

데이터베이스 객체 및 구조에 대한 정보를 얻습니다.

```bash
# 데이터베이스 나열
\l, \l+
# 현재 데이터베이스의 테이블 나열
\dt, \dt+
# 뷰 나열
\dv, \dv+
# 인덱스 나열
\di, \di+
# 함수 나열
\df, \df+
# 시퀀스 나열
\ds, \ds+
# 테이블 구조 설명
\d table_name
\d+ table_name
# 테이블 제약 조건 보기
\d+ table_name
# 테이블 권한 보기
\dp table_name
\z table_name
# 외래 키 나열
SELECT * FROM information_schema.table_constraints
WHERE constraint_type = 'FOREIGN KEY';
```

### 출력 및 형식 지정

psql 이 쿼리 결과 및 출력을 표시하는 방식을 제어합니다.

```bash
# 확장 출력 토글
\x
# 출력 형식 변경
\H  -- HTML 출력
\t  -- 튜플만 (헤더 없음)
# 파일로 출력
\o filename.txt
SELECT * FROM users;
\o  -- 파일 출력 중지
# 파일에서 SQL 실행
\i script.sql
# 외부 편집기에서 쿼리 편집
\e
```

### 타이밍 및 기록

쿼리 성능을 추적하고 명령 기록을 관리합니다.

```bash
# 타이밍 표시 토글
\timing
# 명령 기록 보기
\s
# 명령 기록을 파일에 저장
\s filename.txt
# 화면 지우기
\! clear  -- Linux/Mac
\! cls   -- Windows
# 마지막 오류 보기
\errverbose
```

## 관련 링크

- <router-link to="/database">데이터베이스 치트 시트</router-link>
- <router-link to="/mysql">MySQL 치트 시트</router-link>
- <router-link to="/sqlite">SQLite 치트 시트</router-link>
- <router-link to="/mongodb">MongoDB 치트 시트</router-link>
- <router-link to="/redis">Redis 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>

---
title: 'データベースチートシート | LabEx'
description: 'この包括的なチートシートでデータベース管理を学習。SQL クエリ、データベース設計、正規化、インデックス、トランザクション、リレーショナルデータベース管理のクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/database-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
データベース チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/database">ハンズオンラボでデータベースを学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、データベース管理と SQL を学びましょう。LabEx は、必須の SQL コマンド、データ操作、クエリ最適化、データベース設計、管理を網羅した包括的なデータベースコースを提供します。リレーショナルデータベース、NoSQL システム、データベースセキュリティのベストプラクティスを習得します。
</base-disclaimer-content>
</base-disclaimer>

## データベースの作成と管理

### データベースの作成：`CREATE DATABASE`

データを格納するための新しいデータベースを作成します。

```sql
-- 新しいデータベースを作成
CREATE DATABASE company_db;
-- 文字セットを指定してデータベースを作成
CREATE DATABASE company_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
-- データベースを使用
USE company_db;
```

<BaseQuiz id="database-create-1" correct="A">
  <template #question>
    <code>CREATE DATABASE company_db</code>は何をしますか？
  </template>
  
  <BaseQuizOption value="A" correct>company_db という名前の新しい空のデータベースを作成する</BaseQuizOption>
  <BaseQuizOption value="B">データベース内にテーブルを作成する</BaseQuizOption>
  <BaseQuizOption value="C">データベースを削除する</BaseQuizOption>
  <BaseQuizOption value="D">データベースをバックアップする</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>CREATE DATABASE</code>は新しい空のデータベースを作成します。作成後、<code>USE</code> を使用して選択し、その中にテーブルを作成する必要があります。
  </BaseQuizAnswer>
</BaseQuiz>

### データベースの表示：`SHOW DATABASES`

サーバー上の利用可能なすべてのデータベースを一覧表示します。

```sql
-- すべてのデータベースを一覧表示
SHOW DATABASES;
-- データベース情報を表示
SELECT SCHEMA_NAME FROM
INFORMATION_SCHEMA.SCHEMATA;
-- 現在のデータベースを表示
SELECT DATABASE();
```

### データベースの削除：`DROP DATABASE`

データベース全体を永続的に削除します。

```sql
-- データベースを削除（注意！）
DROP DATABASE old_company_db;
-- 存在する場合にのみデータベースを削除
DROP DATABASE IF EXISTS old_company_db;
```

### データベースのバックアップ：`mysqldump`

データベースのバックアップコピーを作成します。

```sql
-- コマンドラインからのバックアップ
mysqldump -u username -p database_name > backup.sql
-- バックアップからのリストア
mysql -u username -p database_name < backup.sql
```

### データベースユーザー: `CREATE USER`

データベースユーザーアカウントと権限を管理します。

```sql
-- 新しいユーザーを作成
CREATE USER 'newuser'@'localhost' IDENTIFIED BY
'password';
-- 権限を付与
GRANT SELECT, INSERT ON company_db.* TO
'newuser'@'localhost';
-- ユーザー権限を表示
SHOW GRANTS FOR 'newuser'@'localhost';
```

### データベース情報：`INFORMATION_SCHEMA`

データベースのメタデータと構造情報を照会します。

```sql
-- すべてのテーブルを表示
SELECT TABLE_NAME FROM
INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'company_db';
-- テーブルの列を表示
DESCRIBE employees;
```

## テーブル構造と情報

### テーブルの作成：`CREATE TABLE`

列とデータ型を指定して新しいテーブルを定義します。

```sql
-- 基本的なテーブル作成
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY
KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE,
    salary DECIMAL(10,2),
    hire_date DATE,
    department VARCHAR(50)
);
-- テーブル構造を表示
DESCRIBE employees;
SHOW COLUMNS FROM employees;
```

### テーブルの変更：`ALTER TABLE`

既存のテーブル構造と列を変更します。

```sql
-- 新しい列を追加
ALTER TABLE employees ADD
COLUMN phone VARCHAR(15);
-- 列の型を変更
ALTER TABLE employees MODIFY
COLUMN salary DECIMAL(12,2);
-- 列を削除
ALTER TABLE employees DROP
COLUMN phone;
-- テーブル名を変更
RENAME TABLE employees TO staff;
```

<BaseQuiz id="database-alter-1" correct="C">
  <template #question>
    <code>ALTER TABLE employees ADD COLUMN phone VARCHAR(15)</code>は何をしますか？
  </template>
  
  <BaseQuizOption value="A">phone 列を削除する</BaseQuizOption>
  <BaseQuizOption value="B">phone 列を変更する</BaseQuizOption>
  <BaseQuizOption value="C" correct>employees テーブルに phone という新しい列を追加する</BaseQuizOption>
  <BaseQuizOption value="D">テーブルの名前を変更する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>ALTER TABLE ... ADD COLUMN</code>は既存のテーブルに新しい列を追加します。デフォルト値を指定しない限り、既存の行に対して新しい列は NULL になります。
  </BaseQuizAnswer>
</BaseQuiz>

### テーブル情報：`SHOW`

テーブルとそのプロパティに関する詳細情報を取得します。

```sql
-- すべてのテーブルを表示
SHOW TABLES;
-- テーブル構造を表示
SHOW CREATE TABLE employees;
-- テーブルの状態を表示
SHOW TABLE STATUS LIKE
'employees';
-- テーブルの行数をカウント
SELECT COUNT(*) FROM employees;
```

## データ操作と CRUD 操作

### データの挿入：`INSERT INTO`

テーブルに新しいレコードを追加します。

```sql
-- 単一レコードの挿入
INSERT INTO employees (name, email, salary, hire_date,
department)
VALUES ('John Doe', 'john@company.com', 75000.00,
'2024-01-15', 'Engineering');
-- 複数レコードの挿入
INSERT INTO employees (name, email, salary,
department) VALUES
('Jane Smith', 'jane@company.com', 80000.00,
'Marketing'),
('Bob Johnson', 'bob@company.com', 65000.00, 'Sales');
-- 他のテーブルから挿入
INSERT INTO backup_employees
SELECT * FROM employees WHERE department =
'Engineering';
```

### データの更新：`UPDATE`

テーブル内の既存のレコードを変更します。

```sql
-- 単一レコードの更新
UPDATE employees
SET salary = 85000.00, department = 'Senior Engineering'
WHERE id = 1;
-- 複数レコードの更新
UPDATE employees
SET salary = salary * 1.05
WHERE hire_date < '2024-01-01';
-- JOIN を使用した更新
UPDATE employees e
JOIN departments d ON e.department = d.name
SET e.salary = e.salary + d.bonus;
```

### データの削除：`DELETE FROM`

テーブルからレコードを削除します。

```sql
-- 特定のレコードを削除
DELETE FROM employees
WHERE department = 'Temporary';
-- 条件付きで削除
DELETE FROM employees
WHERE hire_date < '2020-01-01' AND salary < 50000;
-- テーブル全体を切り詰める（すべてを削除する場合に高速）
TRUNCATE TABLE temp_employees;
```

### データの置換：`REPLACE INTO`

主キーに基づいてレコードを挿入または更新します。

```sql
-- レコードを置換（挿入または更新）
REPLACE INTO employees (id, name, email, salary)
VALUES (1, 'John Doe Updated',
'john.new@company.com', 90000);
-- 重複キー時の更新
INSERT INTO employees (id, name, salary)
VALUES (1, 'John Doe', 85000)
ON DUPLICATE KEY UPDATE salary = VALUES(salary);
```

## データ照会と選択

### 基本的な SELECT: `SELECT`

データベーステーブルからデータを取得します。

```sql
-- すべての列を選択
SELECT * FROM employees;
-- 特定の列を選択
SELECT name, email, salary FROM employees;
-- エイリアス付きの選択
SELECT name AS employee_name, salary AS
annual_salary
FROM employees;
-- 重複しない値を選択
SELECT DISTINCT department FROM employees;
```

### データのフィルタリング：`WHERE`

条件を適用してクエリ結果をフィルタリングします。

```sql
-- 基本的な条件
SELECT * FROM employees WHERE salary > 70000;
-- 複数の条件
SELECT * FROM employees
WHERE department = 'Engineering' AND salary > 75000;
-- パターンマッチング
SELECT * FROM employees WHERE name LIKE 'John%';
```

<BaseQuiz id="database-where-1" correct="C">
  <template #question>
    WHERE 句で<code>LIKE 'John%'</code>は何に一致しますか？
  </template>
  
  <BaseQuizOption value="A">"John"との完全一致のみ</BaseQuizOption>
  <BaseQuizOption value="B">"John"で終わる値</BaseQuizOption>
  <BaseQuizOption value="C" correct>"John"で始まる値</BaseQuizOption>
  <BaseQuizOption value="D">どこかに"John"を含む値</BaseQuizOption>
  
  <BaseQuizAnswer>
    SQL の <code>%</code> ワイルドカードは任意の文字列に一致します。<code>LIKE 'John%'</code>は、「John」、「Johnny」、「Johnson」など、「John」で始まる任意の値に一致します。
  </BaseQuizAnswer>
</BaseQuiz>

```sql
-- 範囲クエリ
SELECT * FROM employees
WHERE hire_date BETWEEN '2023-01-01' AND '2023-12-
31';
```

### データのソート：`ORDER BY`

クエリ結果を昇順または降順にソートします。

```sql
-- 単一列でのソート
SELECT * FROM employees ORDER BY salary DESC;
-- 複数列でのソート
SELECT * FROM employees
ORDER BY department ASC, salary DESC;
-- LIMIT 付きのソート
SELECT * FROM employees
ORDER BY hire_date DESC LIMIT 10;
```

### 結果の制限：`LIMIT`

返されるレコードの数を制御します。

```sql
-- 結果の数を制限
SELECT * FROM employees LIMIT 5;
-- OFFSET を使用したページネーション
SELECT * FROM employees
ORDER BY id LIMIT 10 OFFSET 20;
-- 上位 N 件の結果
SELECT * FROM employees
ORDER BY salary DESC LIMIT 5;
```

## 高度なクエリ

### 集計関数：`COUNT`, `SUM`, `AVG`

データのグループに対して計算を実行します。

```sql
-- レコードのカウント
SELECT COUNT(*) FROM employees;
-- 合計と平均
SELECT SUM(salary) as total_payroll, AVG(salary) as
avg_salary
FROM employees;
-- グループ統計
SELECT department, COUNT(*) as employee_count,
AVG(salary) as avg_salary
FROM employees GROUP BY department;
-- グループフィルタリングのための Having 句
SELECT department, COUNT(*) as count
FROM employees
GROUP BY department
HAVING COUNT(*) > 5;
```

### サブクエリ：ネストされたクエリ

複雑な操作のために、他のクエリ内にクエリを使用します。

```sql
-- WHERE 句内のサブクエリ
SELECT * FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);
-- IN 句内のサブクエリ
SELECT * FROM employees
WHERE department IN (
    SELECT name FROM departments WHERE budget >
100000
);
-- 相関サブクエリ
SELECT * FROM employees e1
WHERE salary > (
    SELECT AVG(salary) FROM employees e2
    WHERE e2.department = e1.department
);
```

### テーブル結合：`JOIN`

複数のテーブルからのデータを結合します。

```sql
-- 内部結合
SELECT e.name, e.salary, d.department_name
FROM employees e
INNER JOIN departments d ON e.department = d.id;
-- 左結合
SELECT e.name, d.department_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id;
-- 複数結合
SELECT e.name, d.department_name, p.project_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id
LEFT JOIN projects p ON e.id = p.employee_id;
```

### ウィンドウ関数：高度な分析

関連する行全体で計算を実行します。

```sql
-- 行番号付け
SELECT name, salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
FROM employees;
-- 累積合計
SELECT name, salary,
    SUM(salary) OVER (ORDER BY hire_date) as
running_total
FROM employees;
-- グループごとのパーティション
SELECT name, department, salary,
    AVG(salary) OVER (PARTITION BY department) as
dept_avg
FROM employees;
```

## データベースの制約と整合性

### 主キー: `PRIMARY KEY`

各レコードの一意な識別を保証します。

```sql
-- 単一列の主キー
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100)
);
-- 複合主キー
CREATE TABLE order_items (
    order_id INT,
    product_id INT,
    quantity INT,
    PRIMARY KEY (order_id, product_id)
);
```

### 外部キー: `FOREIGN KEY`

テーブル間の参照整合性を維持します。

```sql
-- 外部キー制約の追加
CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);
-- 既存のテーブルへの外部キーの追加
ALTER TABLE employees
ADD CONSTRAINT fk_department
FOREIGN KEY (department_id) REFERENCES
departments(id);
```

### UNIQUE 制約：`UNIQUE`

列内の重複する値を防ぎます。

```sql
-- 単一列の UNIQUE 制約
ALTER TABLE employees
ADD CONSTRAINT unique_email UNIQUE (email);
-- 複合 UNIQUE 制約
ALTER TABLE employees
ADD CONSTRAINT unique_name_dept UNIQUE (name,
department);
```

### CHECK 制約：`CHECK`

ビジネスルールとデータ検証を強制します。

```sql
-- シンプルな CHECK 制約
ALTER TABLE employees
ADD CONSTRAINT check_salary CHECK (salary > 0);
-- 複雑な CHECK 制約
ALTER TABLE employees
ADD CONSTRAINT check_age
CHECK (YEAR(CURDATE()) - YEAR(birth_date) >= 18);
```

## データベースのパフォーマンスと最適化

### インデックス：`CREATE INDEX`

データベースインデックスを使用してデータ検索を高速化します。

```sql
-- 単一列へのインデックス作成
CREATE INDEX idx_employee_name ON
employees(name);
-- 複合インデックス
CREATE INDEX idx_dept_salary ON
employees(department, salary);
-- ユニークインデックス
CREATE UNIQUE INDEX idx_employee_email ON
employees(email);
-- テーブルインデックスの表示
SHOW INDEX FROM employees;
```

### クエリ最適化：`EXPLAIN`

クエリのパフォーマンスを分析および最適化します。

```sql
-- クエリ実行計画の分析
EXPLAIN SELECT * FROM employees WHERE salary >
75000;
-- 詳細な分析
EXPLAIN ANALYZE SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department = d.id;
```

### パフォーマンス監視

データベースのパフォーマンスを監視し、ボトルネックを特定します。

```sql
-- 実行中のプロセスを表示
SHOW PROCESSLIST;
-- データベースステータスを表示
SHOW STATUS LIKE 'Slow_queries';
-- クエリキャッシュ情報を表示
SHOW STATUS LIKE 'Qcache%';
-- データベースサイズを照会
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

### データベースメンテナンス

最適なパフォーマンスのための定期的なメンテナンスタスク。

```sql
-- テーブルの最適化
OPTIMIZE TABLE employees;
-- テーブル統計の分析
ANALYZE TABLE employees;
-- テーブルの整合性チェック
CHECK TABLE employees;
-- 必要に応じてテーブルを修復
REPAIR TABLE employees;
```

## データのインポート/エクスポート

### データのインポート：`LOAD DATA`

外部ファイルからデータベーステーブルへデータをインポートします。

```sql
-- CSV ファイルからのインポート
LOAD DATA INFILE 'employees.csv'
INTO TABLE employees
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
-- 列マッピング付きのインポート
LOAD DATA INFILE 'data.csv'
INTO TABLE employees (name, email, salary);
```

### データの書き出し：`SELECT INTO`

クエリ結果を外部ファイルに書き出します。

```sql
-- CSV ファイルへのエクスポート
SELECT name, email, salary
INTO OUTFILE 'employee_export.csv'
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
FROM employees;
-- mysqldump を使用
mysqldump -u username -p --tab=/path/to/export
database_name table_name
```

### データ移行：データベース間

異なるデータベースシステム間でデータを移動します。

```sql
-- 既存の構造からテーブルを作成
CREATE TABLE employees_backup LIKE employees;
-- テーブル間でデータをコピー
INSERT INTO employees_backup SELECT * FROM
employees;
-- 条件付きでの移行
INSERT INTO new_employees
SELECT * FROM old_employees WHERE active = 1;
```

### バルク操作

大規模なデータ操作を効率的に処理します。

```sql
-- INSERT IGNORE を使用した一括挿入
INSERT IGNORE INTO employees (name, email) VALUES
('John Doe', 'john@email.com'),
('Jane Smith', 'jane@email.com');
-- バッチ更新
UPDATE employees SET salary = salary * 1.1 WHERE
department = 'Sales';
```

## データベースのセキュリティとアクセス制御

### ユーザー管理：`CREATE USER`

データベースユーザーアカウントの作成と管理。

```sql
-- パスワード付きでユーザーを作成
CREATE USER 'app_user'@'localhost' IDENTIFIED BY
'secure_password';
-- 特定のホスト用のユーザーを作成
CREATE USER 'remote_user'@'192.168.1.%' IDENTIFIED
BY 'password';
-- ユーザーを削除
DROP USER 'old_user'@'localhost';
```

### 権限：`GRANT` & `REVOKE`

データベースオブジェクトと操作へのアクセスを制御します。

```sql
-- 特定の権限を付与
GRANT SELECT, INSERT ON company_db.employees TO
'app_user'@'localhost';
-- すべての権限を付与
GRANT ALL PRIVILEGES ON company_db.* TO
'admin_user'@'localhost';
-- 権限を取り消す
REVOKE INSERT ON company_db.employees FROM
'app_user'@'localhost';
-- ユーザー権限を表示
SHOW GRANTS FOR 'app_user'@'localhost';
```

### データベースロール

データベースロールを使用して権限を整理します。

```sql
-- ロールの作成（MySQL 8.0+）
CREATE ROLE 'app_read_role', 'app_write_role';
-- ロールに権限を付与
GRANT SELECT ON company_db.* TO 'app_read_role';
GRANT INSERT, UPDATE, DELETE ON company_db.* TO
'app_write_role';
-- ユーザーにロールを割り当て
GRANT 'app_read_role' TO 'readonly_user'@'localhost';
```

### SQL インジェクションの防止

一般的なセキュリティ脆弱性から保護します。

```sql
-- プリペアドステートメントの使用（アプリケーションレベル）
-- 悪い例：SELECT * FROM users WHERE id = ' + userInput
-- 良い例：パラメータ化されたクエリを使用
-- 入力データ型を検証する
-- 可能な限り最小権限の原則を適用する
```

## データベースのインストールとセットアップ

### MySQL のインストール

人気の高いオープンソースのリレーショナルデータベース。

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# MySQLサービスを開始
sudo systemctl start mysql
sudo systemctl enable mysql
# インストールをセキュア化
sudo mysql_secure_installation
```

### PostgreSQL のインストール

高度なオープンソースのリレーショナルデータベース。

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql
postgresql-contrib
# postgresユーザーに切り替える
sudo -u postgres psql
# データベースとユーザーの作成
CREATE DATABASE myapp;
CREATE USER myuser WITH
PASSWORD 'mypassword';
```

### SQLite のセットアップ

軽量なファイルベースのデータベース。

```bash
# SQLiteのインストール
sudo apt install sqlite3
# データベースファイルの作成
sqlite3 mydatabase.db
# 基本的なSQLiteコマンド
.help
.tables
.schema tablename
.quit
```

## データベースの設定とチューニング

### MySQL の設定

主要な MySQL 設定パラメータ。

```sql
-- my.cnf 設定ファイル
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
-- 現在の設定を表示
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW STATUS LIKE 'Connections';
```

### 接続管理

データベース接続とプーリングを管理します。

```sql
-- 現在の接続を表示
SHOW PROCESSLIST;
-- 特定の接続をキル
KILL CONNECTION 123;
-- 接続タイムアウト設定
SET SESSION wait_timeout = 600;
SET SESSION interactive_timeout = 600;
```

### バックアップ設定

自動化されたデータベースバックアップを設定します。

```sql
-- 自動バックアップスクリプト
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mysqldump -u backup_user -p mydatabase >
backup_$DATE.sql
# cronでのスケジュール設定
0 2 * * * /path/to/backup_script.sh
```

### 監視とロギング

データベースの活動とパフォーマンスを監視します。

```sql
-- ポイントインタイムリカバリの設定
SET GLOBAL log_bin = ON;
-- スロークエリログを有効化
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
-- データベースサイズを照会
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

## SQL のベストプラクティス

### クエリ記述のベストプラクティス

クリーンで効率的で読みやすい SQL クエリを作成します。

```sql
-- 意味のあるテーブルエイリアスを使用
SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.dept_id = d.id;
-- SELECT * ではなく列名を指定する
SELECT name, email, salary FROM employees;
-- 適切なデータ型を使用する
CREATE TABLE products (
    id INT PRIMARY KEY,
    price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP
);
```

### パフォーマンス最適化のヒント

より良いデータベースパフォーマンスのためにクエリを最適化します。

```sql
-- 頻繁に照会される列にインデックスを使用する
CREATE INDEX idx_employee_dept ON
employees(department);
-- 可能な限り結果セットを制限する
SELECT name FROM employees WHERE active = 1 LIMIT
100;
-- サブクエリには IN の代わりに EXISTS を使用する
SELECT * FROM customers c
WHERE EXISTS (SELECT 1 FROM orders o WHERE
o.customer_id = c.id);
```

## 関連リンク

- <router-link to="/mysql">MySQL チートシート</router-link>
- <router-link to="/postgresql">PostgreSQL チートシート</router-link>
- <router-link to="/sqlite">SQLite チートシート</router-link>
- <router-link to="/mongodb">MongoDB チートシート</router-link>
- <router-link to="/redis">Redis チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>

---
title: 'MySQL チートシート | LabEx'
description: 'この包括的なチートシートで MySQL データベース管理を学習。SQL クエリ、結合、インデックス、トランザクション、ストアドプロシージャ、データベース管理のクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/mysql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
MySQL チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/mysql">ハンズオンラボで MySQL を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、MySQL データベース管理を学びます。LabEx は、必須の SQL 操作、データベース管理、パフォーマンス最適化、高度なクエリ技術を網羅した包括的な MySQL コースを提供します。世界で最も人気のあるリレーショナルデータベースシステムの一つを習得しましょう。
</base-disclaimer-content>
</base-disclaimer>

## データベース接続と管理

### サーバーへの接続：`mysql -u username -p`

コマンドラインを使用して MySQL サーバーに接続します。

```bash
# ユーザー名とパスワードプロンプトで接続
mysql -u root -p
# 特定のデータベースに接続
mysql -u username -p database_name
# リモートサーバーに接続
mysql -h hostname -u username -p
# ポート指定で接続
mysql -h hostname -P 3306 -u username -p database_name
```

### データベース操作：`CREATE` / `DROP` / `USE`

サーバー上のデータベースを管理します。

```sql
# 新しいデータベースを作成
CREATE DATABASE company_db;
# すべてのデータベースを一覧表示
SHOW DATABASES;
# 使用するデータベースを選択
USE company_db;
# データベースを削除（永続的に削除）
DROP DATABASE old_database;
```

<BaseQuiz id="mysql-database-1" correct="C">
  <template #question>
    `USE database_name`は何をしますか？
  </template>
  
  <BaseQuizOption value="A">新しいデータベースを作成する</BaseQuizOption>
  <BaseQuizOption value="B">データベースを削除する</BaseQuizOption>
  <BaseQuizOption value="C" correct>後続の操作のためにデータベースを選択する</BaseQuizOption>
  <BaseQuizOption value="D">データベース内のすべてのテーブルを表示する</BaseQuizOption>
  
  <BaseQuizAnswer>
    `USE` ステートメントはデータベースを選択し、後続のすべての SQL ステートメントのアクティブなデータベースにします。これは、`mysql -u user -p database_name`で接続する際にデータベースを選択するのと同じです。
  </BaseQuizAnswer>
</BaseQuiz>

### データの書き出し：`mysqldump`

データベースデータを SQL ファイルにバックアップします。

```bash
# データベース全体をエクスポート
mysqldump -u username -p database_name > backup.sql
# 特定のテーブルをエクスポート
mysqldump -u username -p database_name table_name > table_backup.sql
# 構造のみをエクスポート
mysqldump -u username -p --no-data database_name > structure.sql
# ルーチンとトリガーを含む完全なデータベースバックアップ
mysqldump -u username -p --routines --triggers database_name > backup.sql
```

### データのインポート：`mysql < file.sql`

SQL ファイルを MySQL データベースにインポートします。

```bash
# SQLファイルをデータベースにインポート
mysql -u username -p database_name < backup.sql
# データベースを指定せずにインポート（ファイル内に含まれている場合）
mysql -u username -p < full_backup.sql
```

### ユーザー管理：`CREATE USER` / `GRANT`

データベースユーザーと権限を管理します。

```sql
# 新しいユーザーを作成
CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
# すべての権限を付与
GRANT ALL PRIVILEGES ON database_name.* TO 'user'@'localhost';
# 特定の権限を付与
GRANT SELECT, INSERT, UPDATE ON table_name TO 'user'@'localhost';
# 権限の変更を適用
FLUSH PRIVILEGES;
```

### サーバー情報の表示：`SHOW STATUS` / `SHOW VARIABLES`

サーバーの設定とステータスを表示します。

```sql
# サーバーのステータスを表示
SHOW STATUS;
# 設定変数を表示
SHOW VARIABLES;
# 現在のプロセスを表示
SHOW PROCESSLIST;
```

## テーブル構造とスキーマ

### テーブルの作成：`CREATE TABLE`

指定された列とデータ型で新しいテーブルを作成します。

```sql
# さまざまなデータ型を持つテーブルを作成
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    age INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# 外部キーを持つテーブルを作成
CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### テーブル情報の表示：`DESCRIBE` / `SHOW`

テーブル構造とデータベースの内容を表示します。

```sql
# テーブル構造を表示
DESCRIBE users;
# 代替構文
SHOW COLUMNS FROM users;
# すべてのテーブルを一覧表示
SHOW TABLES;
# テーブルのCREATE文を表示
SHOW CREATE TABLE users;
```

### テーブルの変更：`ALTER TABLE`

既存のテーブル構造を変更し、列を追加または削除します。

```sql
# 新しい列を追加
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
# 列を削除
ALTER TABLE users DROP COLUMN age;
# 列の型を変更
ALTER TABLE users MODIFY COLUMN username VARCHAR(100);
# 列名を変更
ALTER TABLE users CHANGE old_name new_name VARCHAR(50);
```

## データ操作と CRUD 操作

### データの挿入：`INSERT INTO`

テーブルに新しいレコードを追加します。

```sql
# 単一レコードの挿入
INSERT INTO users (username, email, age)
VALUES ('john_doe', 'john@email.com', 25);
# 複数レコードの挿入
INSERT INTO users (username, email, age) VALUES
('alice', 'alice@email.com', 30),
('bob', 'bob@email.com', 28);
# 他のテーブルから挿入
INSERT INTO users_backup SELECT * FROM users;
```

<BaseQuiz id="mysql-insert-1" correct="A">
  <template #question>
    単一レコードを挿入する正しい構文は何ですか？
  </template>
  
  <BaseQuizOption value="A" correct>`INSERT INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="B">`INSERT table_name VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="C">`ADD INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="D">`INSERT table_name (column1, column2) = (value1, value2);`</BaseQuizOption>
  
  <BaseQuizAnswer>
    正しい構文は`INSERT INTO table_name (columns) VALUES (values)`です。`INTO` キーワードが必要であり、列名と対応する値の両方を指定する必要があります。
  </BaseQuizAnswer>
</BaseQuiz>

### データの更新：`UPDATE`

テーブル内の既存のレコードを変更します。

```sql
# 特定のレコードを更新
UPDATE users SET age = 26 WHERE username = 'john_doe';
# 複数の列を更新
UPDATE users SET age = 31, email = 'alice_new@email.com'
WHERE username = 'alice';
# 計算による更新
UPDATE products SET price = price * 1.1 WHERE category = 'electronics';
```

### データの削除：`DELETE` / `TRUNCATE`

テーブルからレコードを削除します。

```sql
# 特定のレコードを削除
DELETE FROM users WHERE age < 18;
# すべてのレコードを削除（構造は保持）
DELETE FROM users;
# すべてのレコードを削除（高速、AUTO_INCREMENTをリセット）
TRUNCATE TABLE users;
# JOINを使用した削除
DELETE u FROM users u
JOIN inactive_accounts i ON u.id = i.user_id;
```

### データの置換：`REPLACE` / `INSERT ... ON DUPLICATE KEY`

挿入時の重複キーの状況を処理します。

```sql
# 既存のものを置換または新規挿入
REPLACE INTO users (id, username, email)
VALUES (1, 'updated_user', 'new@email.com');
# 重複キーの場合に挿入または更新
INSERT INTO users (username, email)
VALUES ('john', 'john@email.com')
ON DUPLICATE KEY UPDATE email = VALUES(email);
```

## データクエリと選択

### 基本的な SELECT: `SELECT * FROM`

さまざまな条件でテーブルからデータを取得します。

```sql
# すべての列を選択
SELECT * FROM users;
# 特定の列を選択
SELECT username, email FROM users;
# WHERE条件付きで選択
SELECT * FROM users WHERE age > 25;
# 複数の条件付きで選択
SELECT * FROM users WHERE age > 20 AND email LIKE '%gmail.com';
```

<BaseQuiz id="mysql-select-1" correct="D">
  <template #question>
    `SELECT * FROM users`は何を返しますか？
  </template>
  
  <BaseQuizOption value="A">users テーブルの最初の行のみ</BaseQuizOption>
  <BaseQuizOption value="B">username 列のみ</BaseQuizOption>
  <BaseQuizOption value="C">テーブル構造</BaseQuizOption>
  <BaseQuizOption value="D" correct>users テーブルのすべての列とすべての行</BaseQuizOption>
  
  <BaseQuizAnswer>
    `*` ワイルドカードはすべての列を選択し、WHERE 句がない場合、すべての行を返します。これはすべてのデータを表示するのに役立ちますが、大きなテーブルでは注意が必要です。
  </BaseQuizAnswer>
</BaseQuiz>

### ソートと制限：`ORDER BY` / `LIMIT`

返される結果の順序と数を制御します。

```sql
# 結果をソート
SELECT * FROM users ORDER BY age DESC;
# 複数の列でソート
SELECT * FROM users ORDER BY age DESC, username ASC;
# 結果を制限
SELECT * FROM users LIMIT 10;
# ページネーション（最初の10件をスキップし、次の10件を取得）
SELECT * FROM users LIMIT 10 OFFSET 10;
```

### フィルタリング：`WHERE` / `LIKE` / `IN`

さまざまな比較演算子を使用してデータをフィルタリングします。

```sql
# パターンマッチング
SELECT * FROM users WHERE username LIKE 'john%';
# 複数の値
SELECT * FROM users WHERE age IN (25, 30, 35);
# 範囲フィルタリング
SELECT * FROM users WHERE age BETWEEN 20 AND 30;
# NULLチェック
SELECT * FROM users WHERE email IS NOT NULL;
```

### グループ化：`GROUP BY` / `HAVING`

データをグループ化し、集計関数を適用します。

```sql
# 列でグループ化
SELECT age, COUNT(*) FROM users GROUP BY age;
# グループに対する条件付き
SELECT age, COUNT(*) as count FROM users
GROUP BY age HAVING count > 1;
# 複数のグループ化列
SELECT age, gender, COUNT(*) FROM users
GROUP BY age, gender;
```

## 高度なクエリ

### JOIN 操作：`INNER` / `LEFT` / `RIGHT`

複数のテーブルからデータを結合します。

```sql
# 内部結合（一致するレコードのみ）
SELECT u.username, o.order_date
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# 左結合（すべてのユーザー、一致する注文）
SELECT u.username, o.order_date
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# 複数結合
SELECT u.username, o.order_date, p.product_name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

<BaseQuiz id="mysql-join-1" correct="B">
  <template #question>
    INNER JOIN と LEFT JOIN の違いは何ですか？
  </template>
  
  <BaseQuizOption value="A">違いはない</BaseQuizOption>
  <BaseQuizOption value="B" correct>INNER JOIN は一致する行のみを返し、LEFT JOIN は左側のテーブルのすべての行を返します</BaseQuizOption>
  <BaseQuizOption value="C">INNER JOIN の方が高速である</BaseQuizOption>
  <BaseQuizOption value="D">LEFT JOIN は 2 つのテーブルでのみ機能する</BaseQuizOption>
  
  <BaseQuizAnswer>
    INNER JOIN は両方のテーブルに一致がある行のみを返します。LEFT JOIN は左側のテーブルのすべての行と、右側のテーブルの一致する行を返し、一致しない場合は NULL 値を返します。
  </BaseQuizAnswer>
</BaseQuiz>

### サブクエリ：`SELECT` within `SELECT`

複雑なデータ取得のためにネストされたクエリを使用します。

```sql
# WHERE句内のサブクエリ
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders WHERE total > 100);
# 相関サブクエリ
SELECT username FROM users u1
WHERE age > (SELECT AVG(age) FROM users u2);
# SELECT句内のサブクエリ
SELECT username,
(SELECT COUNT(*) FROM orders WHERE user_id = users.id) as order_count
FROM users;
```

### 集計関数：`COUNT` / `SUM` / `AVG`

データから統計や要約を計算します。

```sql
# 基本的な集計
SELECT COUNT(*) FROM users;
SELECT AVG(age), MIN(age), MAX(age) FROM users;
SELECT SUM(total) FROM orders;
# グループ化を伴う集計
SELECT department, AVG(salary)
FROM employees GROUP BY department;
# 複数の集計
SELECT
    COUNT(*) as total_users,
    AVG(age) as avg_age,
    MAX(created_at) as latest_signup
FROM users;
```

### ウィンドウ関数：`OVER` / `PARTITION BY`

テーブル行のセット全体で計算を実行します。

```sql
# ランキング関数
SELECT username, age,
RANK() OVER (ORDER BY age DESC) as age_rank
FROM users;
# グループごとのパーティション
SELECT username, department, salary,
AVG(salary) OVER (PARTITION BY department) as dept_avg
FROM employees;
# 累積合計
SELECT order_date, total,
SUM(total) OVER (ORDER BY order_date) as running_total
FROM orders;
```

## インデックスとパフォーマンス

### インデックスの作成：`CREATE INDEX`

データベースインデックスを使用してクエリパフォーマンスを向上させます。

```sql
# 通常のインデックスを作成
CREATE INDEX idx_username ON users(username);
# 複合インデックスを作成
CREATE INDEX idx_user_age ON users(username, age);
# ユニークインデックスを作成
CREATE UNIQUE INDEX idx_email ON users(email);
# テーブルのインデックスを表示
SHOW INDEXES FROM users;
```

### クエリ分析：`EXPLAIN`

クエリの実行計画とパフォーマンスを分析します。

```sql
# クエリ実行計画を表示
EXPLAIN SELECT * FROM users WHERE age > 25;
# 詳細な分析
EXPLAIN FORMAT=JSON SELECT u.*, o.total
FROM users u JOIN orders o ON u.id = o.user_id;
# クエリパフォーマンスを表示
SHOW PROFILES;
SET profiling = 1;
```

### クエリの最適化：ベストプラクティス

効率的な SQL クエリを作成するためのテクニック。

```sql
# *ではなく特定の列を使用する
SELECT username, email FROM users WHERE id = 1;
# 大規模データセットにはLIMITを使用する
SELECT * FROM logs ORDER BY created_at DESC LIMIT 1000;
# 適切なWHERE条件を使用する
SELECT * FROM orders WHERE user_id = 123 AND status = 'pending';
-- カバリングインデックスを可能な限り使用する
```

### テーブルメンテナンス：`OPTIMIZE` / `ANALYZE`

テーブルのパフォーマンスと統計情報を維持します。

```sql
# テーブルストレージを最適化
OPTIMIZE TABLE users;
# テーブル統計を更新
ANALYZE TABLE users;
# テーブルの整合性をチェック
CHECK TABLE users;
# 必要に応じてテーブルを修復
REPAIR TABLE users;
```

## データインポート/エクスポート

### データのロード：`LOAD DATA INFILE`

CSV ファイルやテキストファイルからデータをインポートします。

```sql
# CSVファイルをロード
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
# 特定の列をロード
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users (username, email, age);
```

### データの書き出し：`SELECT INTO OUTFILE`

クエリ結果をファイルにエクスポートします。

```sql
# CSVファイルにエクスポート
SELECT username, email, age
FROM users
INTO OUTFILE '/path/to/export.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

### バックアップと復元：`mysqldump` / `mysql`

データベースバックアップの作成と復元を行います。

```bash
# 特定のテーブルをバックアップ
mysqldump -u username -p database_name table1 table2 > tables_backup.sql
# バックアップから復元
mysql -u username -p database_name < backup.sql
# リモートサーバーからエクスポート
mysqldump -h remote_host -u username -p database_name > remote_backup.sql
# ローカルデータベースにインポート
mysql -u local_user -p local_database < remote_backup.sql
# サーバー間での直接データコピー
mysqldump -h source_host -u user -p db_name | mysql -h dest_host -u user -p db_name
```

## データ型と関数

### 一般的なデータ型：数値、テキスト、日付

列に適切なデータ型を選択します。

```sql
# 数値型
INT, BIGINT, DECIMAL(10,2), FLOAT, DOUBLE
# 文字列型
VARCHAR(255), TEXT, CHAR(10), MEDIUMTEXT, LONGTEXT
# 日付と時刻の型
DATE, TIME, DATETIME, TIMESTAMP, YEAR
# ブール値とバイナリ
BOOLEAN, BLOB, VARBINARY

# テーブル作成例
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 文字列関数：`CONCAT` / `SUBSTRING` / `LENGTH`

組み込みの文字列関数でテキストデータを操作します。

```sql
# 文字列の連結
SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users;
# 文字列操作
SELECT SUBSTRING(email, 1, LOCATE('@', email)-1) as username FROM users;
SELECT LENGTH(username), UPPER(username) FROM users;
# パターンマッチングと置換
SELECT REPLACE(phone, '-', '.') FROM users WHERE phone LIKE '___-___-____';
```

### 日付関数：`NOW()` / `DATE_ADD` / `DATEDIFF`

日付と時刻を効果的に扱います。

```sql
# 現在の日付と時刻
SELECT NOW(), CURDATE(), CURTIME();
# 日付の算術演算
SELECT DATE_ADD(created_at, INTERVAL 30 DAY) as expiry_date FROM users;
SELECT DATEDIFF(NOW(), created_at) as days_since_signup FROM users;
# 日付のフォーマット
SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') as formatted_date FROM orders;
```

### 数値関数：`ROUND` / `ABS` / `RAND`

数値データに対して数学的な操作を実行します。

```sql
# 数学関数
SELECT ROUND(price, 2), ABS(profit_loss), SQRT(area) FROM products;
# ランダムと統計
SELECT RAND(), FLOOR(price), CEIL(rating) FROM products;
# 数値集計
SELECT AVG(price), STDDEV(price), VARIANCE(price) FROM products;
```

## トランザクション管理

### トランザクション制御：`BEGIN` / `COMMIT` / `ROLLBACK`

データの一貫性のためにデータベーストランザクションを管理します。

```sql
# トランザクションの開始
BEGIN;
# または
START TRANSACTION;
# 操作の実行
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;
# 変更をコミット
COMMIT;
# またはエラーの場合にロールバック
ROLLBACK;
```

### トランザクション分離レベル：`SET TRANSACTION ISOLATION`

トランザクションが互いにどのように相互作用するかを制御します。

```sql
# 分離レベルの設定
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
# 現在の分離レベルを表示
SELECT @@transaction_isolation;
```

### ロック：`LOCK TABLES` / `SELECT FOR UPDATE`

データへの同時アクセスを制御します。

```sql
# 排他的アクセス用にテーブルをロック
LOCK TABLES users WRITE, orders READ;
# ... 操作を実行
UNLOCK TABLES;
# トランザクション内の行レベルロック
BEGIN;
SELECT * FROM accounts WHERE id = 1 FOR UPDATE;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
COMMIT;
```

### セーブポイント：`SAVEPOINT` / `ROLLBACK TO`

トランザクション内でロールバックポイントを作成します。

```sql
BEGIN;
INSERT INTO users (username) VALUES ('user1');
SAVEPOINT sp1;
INSERT INTO users (username) VALUES ('user2');
SAVEPOINT sp2;
INSERT INTO users (username) VALUES ('user3');
# セーブポイントまでロールバック
ROLLBACK TO sp1;
COMMIT;
```

## 高度な SQL テクニック

### 共通テーブル式 (CTE): `WITH`

複雑なクエリのために一時的な結果セットを作成します。

```sql
# シンプルなCTE
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

### ストアドプロシージャ：`CREATE PROCEDURE`

再利用可能なデータベースプロシージャを作成します。

```sql
# ストアドプロシージャの作成
DELIMITER //
CREATE PROCEDURE GetUserOrders(IN user_id INT)
BEGIN
    SELECT o.*, p.product_name
    FROM orders o
    JOIN products p ON o.product_id = p.id
    WHERE o.user_id = user_id;
END //
DELIMITER ;
# プロシージャの呼び出し
CALL GetUserOrders(123);
```

### トリガー: `CREATE TRIGGER`

データベースイベントに応答してコードを自動的に実行します。

```sql
# 監査ログ用のトリガーを作成
CREATE TRIGGER user_update_audit
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    INSERT INTO user_audit (user_id, old_email, new_email, changed_at)
    VALUES (NEW.id, OLD.email, NEW.email, NOW());
END;
# トリガーを表示
SHOW TRIGGERS;
```

### ビュー: `CREATE VIEW`

クエリ結果に基づいて仮想テーブルを作成します。

```sql
# ビューの作成
CREATE VIEW active_users AS
SELECT id, username, email, created_at
FROM users
WHERE status = 'active' AND last_login > DATE_SUB(NOW(), INTERVAL 30 DAY);
# テーブルのようにビューを使用
SELECT * FROM active_users WHERE username LIKE 'john%';
# ビューの削除
DROP VIEW active_users;
```

## MySQL のインストールとセットアップ

### インストール：パッケージマネージャー

システムパッケージマネージャーを使用して MySQL をインストールします。

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# CentOS/RHEL
sudo yum install mysql-server
# macOS (Homebrew使用)
brew install mysql
# MySQLサービスを開始
sudo systemctl start mysql
```

### Docker: `docker run mysql`

開発用に MySQL を Docker コンテナで実行します。

```bash
# MySQLコンテナの実行
docker run --name mysql-dev -e MYSQL_ROOT_PASSWORD=password -p 3306:3306 -d mysql:8.0
# コンテナ化されたMySQLに接続
docker exec -it mysql-dev mysql -u root -p
# コンテナ内でデータベースを作成
docker exec -it mysql-dev mysql -u root -p -e "CREATE DATABASE testdb;"
```

### 初期セットアップとセキュリティ

MySQL のインストールを保護し、セットアップを確認します。

```bash
# セキュリティスクリプトの実行
sudo mysql_secure_installation
# MySQLに接続
mysql -u root -p
# MySQLのバージョンを表示
SELECT VERSION();
# 接続ステータスを確認
STATUS;
# rootパスワードを設定
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
```

## 設定と設定

### 設定ファイル：`my.cnf`

MySQL サーバーの設定設定を変更します。

```ini
# 一般的な設定場所
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

### 実行時設定：`SET GLOBAL`

MySQL が実行中に設定を変更します。

```sql
# グローバル変数を設定
SET GLOBAL max_connections = 500;
SET GLOBAL slow_query_log = ON;
# 現在の設定を表示
SHOW VARIABLES LIKE 'max_connections';
SHOW GLOBAL STATUS LIKE 'Slow_queries';
```

### パフォーマンスチューニング：メモリとキャッシュ

MySQL のパフォーマンス設定を最適化します。

```sql
# メモリ使用量を表示
SHOW VARIABLES LIKE '%buffer_pool_size%';
SHOW VARIABLES LIKE '%query_cache%';
# パフォーマンスを監視
SHOW STATUS LIKE 'Qcache%';
SHOW STATUS LIKE 'Created_tmp%';
# InnoDB設定
SET GLOBAL innodb_buffer_pool_size = 2147483648; -- 2GB
```

### ログ設定：エラーログとクエリログ

監視とデバッグのために MySQL のロギングを設定します。

```sql
# クエリロギングを有効化
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/query.log';
# スロークエリログ
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
# ログ設定を表示
SHOW VARIABLES LIKE '%log%';
```

## 関連リンク

- <router-link to="/database">データベース チートシート</router-link>
- <router-link to="/postgresql">PostgreSQL チートシート</router-link>
- <router-link to="/sqlite">SQLite チートシート</router-link>
- <router-link to="/mongodb">MongoDB チートシート</router-link>
- <router-link to="/redis">Redis チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>

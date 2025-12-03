---
title: 'PostgreSQL チートシート | LabEx'
description: 'この包括的なチートシートで PostgreSQL データベース管理を習得。SQL クエリ、高度な機能、JSON サポート、全文検索、エンタープライズデータベース管理のためのクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/postgresql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
PostgreSQL チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/postgresql">ハンズオンラボで PostgreSQL を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、PostgreSQL データベース管理を学びます。LabEx は、必須の SQL 操作、高度なクエリ、パフォーマンス最適化、データベース管理、セキュリティを網羅した包括的な PostgreSQL コースを提供します。エンタープライズグレードのリレーショナルデータベース開発と管理を習得しましょう。
</base-disclaimer-content>
</base-disclaimer>

## 接続とデータベース設定

### PostgreSQL への接続：`psql`

psql コマンドラインツールを使用して、ローカルまたはリモートの PostgreSQL データベースに接続します。

```bash
# ローカルデータベースに接続
psql -U ユーザー名 -d データベース名
# リモートデータベースに接続
psql -h ホスト名 -p 5432 -U ユーザー名 -d データベース名
# パスワード入力を促す接続
psql -U postgres -W
# 接続文字列を使用した接続
psql "host=localhost port=5432 dbname=mydb user=myuser"
```

### データベースの作成：`CREATE DATABASE`

CREATE DATABASE コマンドを使用して、PostgreSQL に新しいデータベースを作成します。

```sql
# 新しいデータベースの作成
CREATE DATABASE mydatabase;
# オーナーを指定したデータベースの作成
CREATE DATABASE mydatabase OWNER myuser;
# エンコーディングを指定したデータベースの作成
CREATE DATABASE mydatabase
  WITH ENCODING 'UTF8'
  LC_COLLATE='en_US.UTF-8'
  LC_CTYPE='en_US.UTF-8';
```

### データベースの一覧表示：`\l`

PostgreSQL サーバー上のすべてのデータベースを一覧表示します。

```bash
# すべてのデータベースを一覧表示
\l
# 詳細情報付きでデータベースを一覧表示
\l+
# 別のデータベースに接続
\c データベース名
```

### 基本的な psql コマンド

ナビゲーションと情報取得のための必須の psql ターミナルコマンド。

```bash
# psqlを終了
\q
# SQLコマンドのヘルプを取得
\help CREATE TABLE
# psqlコマンドのヘルプを取得
\?
# 現在のデータベースとユーザーを表示
\conninfo
# システムコマンドの実行
\! ls
# すべてのテーブルを一覧表示
\dt
# 詳細付きでテーブルを一覧表示
\dt+
# 特定のテーブルを記述
\d テーブル名
# すべてのスキーマを一覧表示
\dn
# すべてのユーザー/ロールを一覧表示
\du
```

### バージョンと設定

PostgreSQL のバージョンと設定パラメータを確認します。

```sql
# PostgreSQLのバージョンを確認
SELECT version();
# 現在の設定をすべて表示
SHOW ALL;
# 特定の設定を表示
SHOW max_connections;
# 設定パラメータを設定
SET work_mem = '256MB';
```

## テーブルの作成と管理

### テーブルの作成：`CREATE TABLE`

列、データ型、制約を指定して新しいテーブルを定義します。

```sql
# 基本的なテーブル作成
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

# 外部キーを持つテーブル
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending'
);
```

<BaseQuiz id="postgresql-create-table-1" correct="A">
  <template #question>
    PostgreSQL の<code>SERIAL PRIMARY KEY</code>は何をしますか？
  </template>
  
  <BaseQuizOption value="A" correct>自動インクリメントされる整数列を作成し、主キーとして機能させる</BaseQuizOption>
  <BaseQuizOption value="B">テキスト列を作成する</BaseQuizOption>
  <BaseQuizOption value="C">外部キー制約を作成する</BaseQuizOption>
  <BaseQuizOption value="D">一意なインデックスを作成する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>SERIAL</code> は PostgreSQL 固有のデータ型で、自動インクリメントされる整数を作成します。<code>PRIMARY KEY</code>と組み合わせることで、各行に一意の識別子を作成し、自動的にインクリメントされます。
  </BaseQuizAnswer>
</BaseQuiz>

### テーブルの変更：`ALTER TABLE`

既存のテーブルに列や制約を追加、変更、または削除します。

```sql
# 新しい列の追加
ALTER TABLE users ADD COLUMN phone VARCHAR(15);
# 列の型の変更
ALTER TABLE users ALTER COLUMN phone TYPE VARCHAR(20);
# 列の削除
ALTER TABLE users DROP COLUMN phone;
# 制約の追加
ALTER TABLE users ADD CONSTRAINT unique_email
    UNIQUE (email);
```

### 削除と切り詰め：`DROP/TRUNCATE`

テーブルを削除するか、テーブルからすべてのデータを消去します。

```sql
# テーブル全体を削除
DROP TABLE IF EXISTS old_table;
# 構造は保持し、すべてのデータを削除
TRUNCATE TABLE users;
# アイデンティティをリスタートして切り詰める
TRUNCATE TABLE users RESTART IDENTITY;
```

### データ型と制約

さまざまな種類のデータに対応する PostgreSQL の必須データ型。

```sql
# 数値型
INTEGER, BIGINT, SMALLINT
DECIMAL(10,2), NUMERIC(10,2)
REAL, DOUBLE PRECISION

# 文字列型
CHAR(n), VARCHAR(n), TEXT

# 日付/時刻型
DATE, TIME, TIMESTAMP
TIMESTAMPTZ (タイムゾーン付き)

# ブール値など
BOOLEAN
JSON, JSONB
UUID
ARRAY (例: INTEGER[])

# 主キー
id SERIAL PRIMARY KEY

# 外部キー
user_id INTEGER REFERENCES users(id)

# 一意制約
email VARCHAR(100) UNIQUE

# CHECK制約
age INTEGER CHECK (age >= 0)

# NOT NULL
name VARCHAR(50) NOT NULL
```

### インデックス：`CREATE INDEX`

データベースインデックスを使用してクエリパフォーマンスを向上させます。

```sql
# 基本的なインデックス
CREATE INDEX idx_username ON users(username);
# 一意インデックス
CREATE UNIQUE INDEX idx_unique_email
    ON users(email);
# 複合インデックス
CREATE INDEX idx_user_date
    ON orders(user_id, created_at);
# 部分インデックス
CREATE INDEX idx_active_users
    ON users(username) WHERE active = true;
# インデックスの削除
DROP INDEX IF EXISTS idx_username;
```

<BaseQuiz id="postgresql-index-1" correct="A">
  <template #question>
    PostgreSQL でインデックスを作成する主な目的は何ですか？
  </template>
  
  <BaseQuizOption value="A" correct>データ検索を高速化することでクエリパフォーマンスを向上させるため</BaseQuizOption>
  <BaseQuizOption value="B">データベースサイズを縮小するため</BaseQuizOption>
  <BaseQuizOption value="C">データを暗号化するため</BaseQuizOption>
  <BaseQuizOption value="D">重複エントリを防ぐため</BaseQuizOption>
  
  <BaseQuizAnswer>
    インデックスは、データベースがテーブル全体をスキャンすることなく行を素早く見つけられるようにするデータ構造を作成します。これにより、特に大規模なテーブルでの SELECT クエリが大幅に高速化されます。
  </BaseQuizAnswer>
</BaseQuiz>

### シーケンス：`CREATE SEQUENCE`

数値を自動的に生成して一意の数値を生成します。

```sql
# シーケンスの作成
CREATE SEQUENCE user_id_seq;
# テーブルでのシーケンスの使用
CREATE TABLE users (
    id INTEGER DEFAULT nextval('user_id_seq'),
    username VARCHAR(50)
);
# シーケンスのリセット
ALTER SEQUENCE user_id_seq RESTART WITH 1000;
```

## CRUD 操作

### データの挿入：`INSERT`

データベーステーブルに新しいレコードを追加します。

```sql
# 単一レコードの挿入
INSERT INTO users (username, email)
VALUES ('john_doe', 'john@example.com');
# 複数レコードの挿入
INSERT INTO users (username, email) VALUES
    ('alice', 'alice@example.com'),
    ('bob', 'bob@example.com');
# 返り値付きの挿入
INSERT INTO users (username, email)
VALUES ('jane', 'jane@example.com')
RETURNING id, created_at;
# SELECTからの挿入
INSERT INTO archive_users
SELECT * FROM users WHERE active = false;
```

<BaseQuiz id="postgresql-insert-1" correct="C">
  <template #question>
    PostgreSQL の INSERT 文における <code>RETURNING</code> は何をしますか？
  </template>
  
  <BaseQuizOption value="A">挿入をロールバックする</BaseQuizOption>
  <BaseQuizOption value="B">挿入を防ぐ</BaseQuizOption>
  <BaseQuizOption value="C" correct>挿入された行データを返す</BaseQuizOption>
  <BaseQuizOption value="D">既存の行を更新する</BaseQuizOption>
  
  <BaseQuizAnswer>
    PostgreSQL の <code>RETURNING</code> 句を使用すると、挿入直後に挿入された行データ（または特定の列）を取得でき、自動生成された ID やタイムスタンプを取得する場合などに便利です。
  </BaseQuizAnswer>
</BaseQuiz>

### データの更新：`UPDATE`

データベーステーブル内の既存のレコードを変更します。

```sql
# 特定のレコードの更新
UPDATE users
SET email = 'newemail@example.com'
WHERE username = 'john_doe';
# 複数列の更新
UPDATE users
SET email = 'new@example.com',
    updated_at = NOW()
WHERE id = 1;
# サブクエリを使用した更新
UPDATE orders
SET total = (SELECT SUM(price) FROM order_items
            WHERE order_id = orders.id);
```

### データの選択：`SELECT`

データベーステーブルからデータをクエリして取得します。

```sql
# 基本的な選択
SELECT * FROM users;
# 特定の列の選択
SELECT id, username, email FROM users;
# 条件付きの選択
SELECT * FROM users
WHERE active = true AND created_at > '2024-01-01';
# 順序付けと制限付きの選択
SELECT * FROM users
ORDER BY created_at DESC
LIMIT 10 OFFSET 20;
```

### データの削除：`DELETE`

データベーステーブルからレコードを削除します。

```sql
# 特定のレコードの削除
DELETE FROM users
WHERE active = false;
# サブクエリを使用した削除
DELETE FROM orders
WHERE user_id IN (
    SELECT id FROM users WHERE active = false
);
# すべてのレコードの削除
DELETE FROM temp_table;
# 返り値付きの削除
DELETE FROM users
WHERE id = 5
RETURNING *;
```

## 高度なクエリ

### JOIN: `INNER/LEFT/RIGHT JOIN`

さまざまな結合タイプを使用して複数のテーブルからのデータを結合します。

```sql
# 内部結合
SELECT u.username, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# 左結合
SELECT u.username, o.total
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# 複数結合
SELECT u.username, o.total, p.name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

### サブクエリと CTE

複雑な操作のためにネストされたクエリと共通テーブル式（CTE）を使用します。

```sql
# WHERE句のサブクエリ
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders);
# 共通テーブル式 (CTE)
WITH active_users AS (
    SELECT * FROM users WHERE active = true
)
SELECT au.username, COUNT(o.id) as order_count
FROM active_users au
LEFT JOIN orders o ON au.id = o.user_id
GROUP BY au.username;
```

### 集計：`GROUP BY`

データをグループ化し、分析のために集計関数を適用します。

```sql
# 基本的なグループ化
SELECT status, COUNT(*) as count
FROM orders
GROUP BY status;
# 複数集計
SELECT user_id,
       COUNT(*) as order_count,
       SUM(total) as total_spent,
       AVG(total) as avg_order
FROM orders
GROUP BY user_id
HAVING COUNT(*) > 5;
```

### ウィンドウ関数

グループ化せずに、関連する行全体にわたって計算を実行します。

```sql
# 行番号付け
SELECT username, email,
       ROW_NUMBER() OVER (ORDER BY created_at) as row_num
FROM users;
# 累積合計
SELECT date, amount,
       SUM(amount) OVER (ORDER BY date) as running_total
FROM sales;
# ランキング
SELECT username, score,
       RANK() OVER (ORDER BY score DESC) as rank
FROM user_scores;
```

## データのエクスポートとインポート

### CSV インポート：`COPY`

CSV ファイルから PostgreSQL テーブルにデータをインポートします。

```sql
# CSVファイルからのインポート
COPY users(username, email, age)
FROM '/path/to/users.csv'
DELIMITER ',' CSV HEADER;
# 特定のオプション付きのインポート
COPY products
FROM '/path/to/products.csv'
WITH (FORMAT csv, HEADER true, DELIMITER ';');
# 標準入力からのインポート
\copy users(username, email) FROM STDIN WITH CSV;
```

### CSV エクスポート：`COPY TO`

PostgreSQL データを CSV ファイルにエクスポートします。

```sql
# CSVファイルへのエクスポート
COPY users TO '/path/to/users_export.csv'
WITH (FORMAT csv, HEADER true);
# クエリ結果のエクスポート
COPY (SELECT username, email FROM users WHERE active = true)
TO '/path/to/active_users.csv' CSV HEADER;
# 標準出力へのエクスポート
\copy (SELECT * FROM orders) TO STDOUT WITH CSV HEADER;
```

### バックアップとリストア：`pg_dump`

データベースのバックアップを作成し、バックアップファイルからリストアします。

```bash
# データベース全体をダンプ
pg_dump -U ユーザー名 -h ホスト名 データベース名 > backup.sql
# 特定のテーブルをダンプ
pg_dump -U ユーザー名 -t テーブル名 データベース名 > table_backup.sql
# 圧縮されたバックアップ
pg_dump -U ユーザー名 -Fc データベース名 > backup.dump
# バックアップからのリストア
psql -U ユーザー名 -d データベース名 < backup.sql
# 圧縮されたバックアップのリストア
pg_restore -U ユーザー名 -d データベース名 backup.dump
```

### JSON データ操作

半構造化データのために JSON および JSONB データ型を扱います。

```sql
# JSONデータの挿入
INSERT INTO products (name, metadata)
VALUES ('Laptop', '{"brand": "Dell", "price": 999.99}');
# JSONフィールドのクエリ
SELECT name, metadata->>'brand' as brand
FROM products
WHERE metadata->>'price'::numeric > 500;
# JSON配列の操作
SELECT name FROM products
WHERE metadata->'features' ? 'wireless';
```

## ユーザー管理とセキュリティ

### ユーザーとロールの作成

ユーザーとロールを使用してデータベースアクセスを管理します。

```sql
# ユーザーの作成
CREATE USER myuser WITH PASSWORD 'secretpassword';
# ロールの作成
CREATE ROLE readonly_user;
# 特定の権限を持つユーザーの作成
CREATE USER admin_user WITH
    CREATEDB CREATEROLE PASSWORD 'adminpass';
# ユーザーへのロールの付与
GRANT readonly_user TO myuser;
```

### 権限：`GRANT/REVOKE`

権限を通じてデータベースオブジェクトへのアクセスを制御します。

```sql
# テーブル権限の付与
GRANT SELECT, INSERT ON users TO myuser;
# テーブルに対するすべての権限の付与
GRANT ALL ON orders TO admin_user;
# データベース権限の付与
GRANT CONNECT ON DATABASE mydb TO myuser;
# 権限の取り消し
REVOKE INSERT ON users FROM myuser;
```

### ユーザー情報の表示

既存のユーザーとその権限を確認します。

```sql
# すべてのユーザーを一覧表示
\du
# テーブル権限の表示
SELECT table_name, privilege_type, grantee
FROM information_schema.table_privileges
WHERE table_schema = 'public';
# 現在のユーザーの表示
SELECT current_user;
# ロールメンバーシップの表示
SELECT r.rolname, r.rolsuper, r.rolcreaterole
FROM pg_roles r;
```

### パスワードとセキュリティ

ユーザーパスワードとセキュリティ設定を管理します。

```sql
# ユーザーパスワードの変更
ALTER USER myuser PASSWORD 'newpassword';
# パスワードの有効期限設定
ALTER USER myuser VALID UNTIL '2025-12-31';
# ログインなしでユーザーを作成
CREATE ROLE reporting_role NOLOGIN;
# ユーザーの有効化/無効化
ALTER USER myuser WITH NOLOGIN;
ALTER USER myuser WITH LOGIN;
```

## パフォーマンスと監視

### クエリ分析：`EXPLAIN`

クエリ実行計画を分析し、パフォーマンスを最適化します。

```sql
# クエリ実行計画の表示
EXPLAIN SELECT * FROM users WHERE active = true;
# 実際の実行統計を使用した分析
EXPLAIN ANALYZE
SELECT u.username, COUNT(o.id)
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.username;
# 詳細な実行情報
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT * FROM large_table WHERE indexed_col = 'value';
```

### データベースメンテナンス：`VACUUM`

定期的なクリーンアップ操作を通じてデータベースパフォーマンスを維持します。

```sql
# 基本的なVACUUM
VACUUM users;
# FULL VACUUMとANALYZE
VACUUM FULL ANALYZE users;
# 自動VACUUMのステータス
SELECT schemaname, tablename, last_vacuum, last_autovacuum
FROM pg_stat_user_tables;
# テーブルの再インデックス
REINDEX TABLE users;
```

### クエリの監視

データベースアクティビティを追跡し、パフォーマンスの問題を特定します。

```sql
# 現在のアクティビティ
SELECT pid, usename, query, state
FROM pg_stat_activity
WHERE state != 'idle';
# 長時間実行されているクエリ
SELECT pid, now() - query_start as duration, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC;
# 特定のクエリの強制終了
SELECT pg_terminate_backend(pid) WHERE pid = 12345;
```

### データベース統計情報

データベースの使用状況とパフォーマンスメトリックに関する洞察を得ます。

```sql
# テーブル統計情報
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del
FROM pg_stat_user_tables;
# インデックス使用状況の統計情報
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes;
# データベースサイズの表示
SELECT pg_size_pretty(pg_database_size('mydatabase'));
```

## 高度な機能

### ビュー: `CREATE VIEW`

複雑なクエリを簡素化し、データ抽象化を提供するために仮想テーブルを作成します。

```sql
# シンプルなビューの作成
CREATE VIEW active_users AS
SELECT id, username, email
FROM users WHERE active = true;
# 結合を持つビューの作成
CREATE OR REPLACE VIEW order_summary AS
SELECT u.username, COUNT(o.id) as total_orders,
       SUM(o.total) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.username;
# ビューの削除
DROP VIEW IF EXISTS order_summary;
```

### トリガーと関数

ストアドプロシージャとトリガーを使用してデータベース操作を自動化します。

```sql
# 関数の作成
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
# トリガーの作成
CREATE TRIGGER update_user_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();
```

### トランザクション

トランザクション制御によりデータの一貫性を保証します。

```sql
# トランザクションの開始
BEGIN;
UPDATE accounts SET balance = balance - 100
WHERE id = 1;
UPDATE accounts SET balance = balance + 100
WHERE id = 2;
# トランザクションのコミット
COMMIT;
# 必要に応じたロールバック
ROLLBACK;
# セーブポイント
SAVEPOINT my_savepoint;
ROLLBACK TO my_savepoint;
```

### 設定とチューニング

より良いパフォーマンスのために PostgreSQL サーバー設定を最適化します。

```sql
# 現在の設定の表示
SHOW shared_buffers;
SHOW max_connections;
# 設定パラメータの設定
SET work_mem = '256MB';
SET random_page_cost = 1.1;
# 設定の再読み込み
SELECT pg_reload_conf();
# 設定ファイルの場所の表示
SHOW config_file;
```

## psql の設定とヒント

### 接続ファイル：`.pgpass`

自動認証のためにデータベースの資格情報を安全に保存します。

```bash
# .pgpass ファイルの作成 (形式: ホスト名:ポート:データベース:ユーザー名:パスワード)
echo "localhost:5432:mydatabase:myuser:mypassword" >> ~/.pgpass
# 適切な権限の設定
chmod 600 ~/.pgpass
# 接続サービスファイルの使用
# ~/.pg_service.conf
[mydb]
host=localhost
port=5432
dbname=mydatabase
user=myuser
```

### psql の設定：`.psqlrc`

psql の起動設定と動作をカスタマイズします。

```bash
# ~/.psqlrc ファイルをカスタム設定で作成
\set QUIET on
\timing on
\set PROMPT1 '%n@%M:%> %`date` %R%# '
\set HISTSIZE 5000
\set COMP_KEYWORD_CASE upper
\x auto
\set QUIET off
# カスタムエイリアス
\set show_slow_queries 'SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;'
```

### 環境変数

接続を容易にするために PostgreSQL 環境変数をシェルプロファイルに設定します。

```bash
# シェルプロファイルに設定
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=mydatabase
export PGUSER=myuser
# その後、単に接続
psql
# または特定環境を使用
PGDATABASE=testdb psql
```

### データベース情報

データベースオブジェクトと構造に関する情報を取得します。

```bash
# データベースの一覧表示
\l, \l+
# 現在のデータベースのテーブルの一覧表示
\dt, \dt+
# ビューの一覧表示
\dv, \dv+
# インデックスの一覧表示
\di, \di+
# 関数の⼀覧表⽰
\df, \df+
# シーケンスの一覧表示
\ds, \ds+
# テーブル構造の記述
\d テーブル名
\d+ テーブル名
# テーブルの制約の表示
\d+ テーブル名
# テーブル権限の表示
\dp テーブル名
\z テーブル名
# 外部キーの一覧表示
SELECT * FROM information_schema.table_constraints
WHERE constraint_type = 'FOREIGN KEY';
```

### 出力とフォーマット

psql がクエリ結果と出力を表示する方法を制御します。

```bash
# 拡張出力の切り替え
\x
# 出力形式の変更
\H  -- HTML出力
\t  -- タプルのみ (ヘッダーなし)
# ファイルへの出力
\o filename.txt
SELECT * FROM users;
\o  -- ファイルへの出力を停止
# ファイルからSQLを実行
\i script.sql
# 外部エディタでクエリを編集
\e
```

### タイミングと履歴

クエリパフォーマンスを追跡し、コマンド履歴を管理します。

```bash
# タイミング表示の切り替え
\timing
# コマンド履歴の表示
\s
# コマンド履歴をファイルに保存
\s filename.txt
# 画面のクリア
\! clear  -- Linux/Mac
\! cls   -- Windows
# 最後のエラーの表示
\errverbose
```

## 関連リンク

- <router-link to="/database">データベース チートシート</router-link>
- <router-link to="/mysql">MySQL チートシート</router-link>
- <router-link to="/sqlite">SQLite チートシート</router-link>
- <router-link to="/mongodb">MongoDB チートシート</router-link>
- <router-link to="/redis">Redis チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>

---
title: 'SQLite チートシート | LabEx'
description: 'この包括的なチートシートで SQLite データベースを学習。SQLite SQL 構文、トランザクション、トリガー、ビュー、およびアプリケーション向けの軽量データベース管理のクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/sqlite-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
SQLite チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/sqlite">ハンズオンラボで SQLite を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、SQLite データベース管理を学びます。LabEx は、必須の SQL 操作、データ操作、クエリ最適化、データベース設計、パフォーマンスチューニングを網羅した包括的な SQLite コースを提供します。軽量データベース開発と効率的なデータ管理を習得しましょう。
</base-disclaimer-content>
</base-disclaimer>

## データベースの作成と接続

### データベースの作成：`sqlite3 database.db`

新しい SQLite データベースファイルを作成します。

```bash
# データベースの作成または開く
sqlite3 mydata.db
# インメモリデータベースの作成（一時的）
sqlite3 :memory:
# コマンドによるデータベースの作成
.open mydata.db
# すべてのデータベースを表示
.databases
# すべてのテーブルのスキーマを表示
.schema
# テーブルリストの表示
.tables
# SQLiteの終了
.exit
# 代替終了コマンド
.quit
```

### データベース情報：`.databases`

アタッチされているすべてのデータベースとそのファイルを一覧表示します。

```sql
-- 別のデータベースのアタッチ
ATTACH DATABASE 'backup.db' AS backup;
-- アタッチされたデータベースからのクエリ
SELECT * FROM backup.users;
-- データベースのデタッチ
DETACH DATABASE backup;
```

### SQLite の終了：`.exit` または `.quit`

SQLite コマンドラインインターフェースを閉じます。

```bash
.exit
.quit
```

### データベースのバックアップ：`.backup`

現在のデータベースのバックアップを作成します。

```bash
# ファイルへのバックアップ
.backup backup.db
# バックアップからの復元
.restore backup.db
# SQLファイルへのエクスポート
.output backup.sql
.dump
# SQLスクリプトのインポート
.read backup.sql
```

## テーブルの作成とスキーマ

### テーブルの作成：`CREATE TABLE`

制約と列を指定して、データベース内に新しいテーブルを作成します。

```sql
-- 基本的なテーブル作成
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    age INTEGER,
    created_date DATE DEFAULT CURRENT_TIMESTAMP
);

-- 外部キーを持つテーブル
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    amount REAL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

<BaseQuiz id="sqlite-create-table-1" correct="A">
  <template #question>
    SQLite で<code>INTEGER PRIMARY KEY AUTOINCREMENT</code>は何をしますか？
  </template>
  
  <BaseQuizOption value="A" correct>自動インクリメントされる整数主キーを作成する</BaseQuizOption>
  <BaseQuizOption value="B">テキスト主キーを作成する</BaseQuizOption>
  <BaseQuizOption value="C">外部キー制約を作成する</BaseQuizOption>
  <BaseQuizOption value="D">一意なインデックスを作成する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>INTEGER PRIMARY KEY AUTOINCREMENT</code>は、新しい行ごとに自動的にインクリメントされ、主キーとして機能する整数列を作成します。これにより、各行に一意の識別子が保証されます。
  </BaseQuizAnswer>
</BaseQuiz>

### データ型：`INTEGER`, `TEXT`, `REAL`, `BLOB`

SQLite は動的型付けを使用し、柔軟なデータ格納のためにストレージクラスを提供します。

```sql
-- 一般的なデータ型
CREATE TABLE products (
    id INTEGER,           -- 整数
    name TEXT,           -- テキスト文字列
    price REAL,          -- 浮動小数点数
    image BLOB,          -- バイナリデータ
    active BOOLEAN,      -- ブール値（INTEGER として格納）
    created_at DATETIME  -- 日付と時刻
);
```

### 制約：`PRIMARY KEY`, `NOT NULL`, `UNIQUE`

データ整合性とテーブル間の関係を強制するために制約を定義します。

```sql
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL,
    salary REAL CHECK(salary > 0),
    manager_id INTEGER REFERENCES employees(id)
);
```

## データの挿入と変更

### データの挿入：`INSERT INTO`

単一行または複数行でテーブルに新しいレコードを追加します。

```sql
-- 単一レコードの挿入
INSERT INTO users (name, email, age)
VALUES ('John Doe', 'john@email.com', 30);

-- 複数レコードの挿入
INSERT INTO users (name, email, age) VALUES
    ('Jane Smith', 'jane@email.com', 25),
    ('Bob Wilson', 'bob@email.com', 35);

-- すべての列を指定した挿入
INSERT INTO users VALUES
    (NULL, 'Alice Brown', 'alice@email.com', 28, datetime('now'));
```

### データの更新：`UPDATE SET`

条件に基づいて既存のレコードを変更します。

```sql
-- 単一列の更新
UPDATE users SET age = 31 WHERE name = 'John Doe';

-- 複数列の更新
UPDATE users SET
    email = 'newemail@example.com',
    age = age + 1
WHERE id = 1;

-- サブクエリを使用した更新
UPDATE products SET price = price * 1.1
WHERE category = 'Electronics';
```

<BaseQuiz id="sqlite-update-1" correct="D">
  <template #question>
    UPDATE ステートメントで WHERE 句を忘れた場合、どうなりますか？
  </template>
  
  <BaseQuizOption value="A">更新は失敗する</BaseQuizOption>
  <BaseQuizOption value="B">最初の行のみが更新される</BaseQuizOption>
  <BaseQuizOption value="C">何も起こらない</BaseQuizOption>
  <BaseQuizOption value="D" correct>テーブル内のすべての行が更新される</BaseQuizOption>
  
  <BaseQuizAnswer>
    WHERE 句がない場合、UPDATE ステートメントはテーブル内のすべての行を変更します。意図しないデータを変更するのを避けるため、常に WHERE 句を使用して更新する行を指定する必要があります。
  </BaseQuizAnswer>
</BaseQuiz>

### データの削除：`DELETE FROM`

指定された条件に基づいてテーブルからレコードを削除します。

```sql
-- 特定のレコードの削除
DELETE FROM users WHERE age < 18;

-- すべてのレコードの削除（テーブル構造は保持）
DELETE FROM users;

-- サブクエリを使用した削除
DELETE FROM orders
WHERE user_id IN (SELECT id FROM users WHERE active = 0);
```

### Upsert: `INSERT OR REPLACE`

競合に基づいて新しいレコードを挿入するか、既存のレコードを更新します。

```sql
-- 競合時の挿入または置換
INSERT OR REPLACE INTO users (id, name, email)
VALUES (1, 'Updated Name', 'updated@email.com');

-- 重複時の挿入または無視
INSERT OR IGNORE INTO users (name, email)
VALUES ('Duplicate', 'existing@email.com');
```

<BaseQuiz id="sqlite-upsert-1" correct="A">
  <template #question>
    <code>INSERT OR REPLACE</code>と<code>INSERT OR IGNORE</code>の違いは何ですか？
  </template>
  
  <BaseQuizOption value="A" correct>REPLACE は既存の行を更新し、IGNORE は重複をスキップする</BaseQuizOption>
  <BaseQuizOption value="B">違いはない</BaseQuizOption>
  <BaseQuizOption value="C">REPLACE は行を削除し、IGNORE は更新する</BaseQuizOption>
  <BaseQuizOption value="D">REPLACE はテーブルで機能し、IGNORE はビューで機能する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>INSERT OR REPLACE</code>は、競合（例：重複する主キー）がある場合に既存の行を置き換えます。<code>INSERT OR IGNORE</code>は、競合がある場合に挿入を単にスキップし、既存の行は変更されません。
  </BaseQuizAnswer>
</BaseQuiz>

## データクエリと選択

### 基本的なクエリ：`SELECT`

さまざまなオプションを使用して SELECT ステートメントでテーブルからデータをクエリします。

```sql
-- すべての列を選択
SELECT * FROM users;

-- 特定の列を選択
SELECT name, email FROM users;

-- エイリアス付きの選択
SELECT name AS full_name, age AS years_old FROM users;

-- 一意な値の選択
SELECT DISTINCT department FROM employees;
```

<BaseQuiz id="sqlite-select-1" correct="B">
  <template #question>
    <code>SELECT DISTINCT</code>は何をしますか？
  </template>
  
  <BaseQuizOption value="A">すべての行を選択する</BaseQuizOption>
  <BaseQuizOption value="B" correct>重複を削除して一意の値のみを返す</BaseQuizOption>
  <BaseQuizOption value="C">最初の行のみを選択する</BaseQuizOption>
  <BaseQuizOption value="D">結果を並べ替える</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>SELECT DISTINCT</code>は、結果セットから重複する行を排除し、一意の値のみを返します。これは、列内のすべての一意の値を確認したい場合に役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

### フィルタリング：`WHERE`

さまざまな条件と比較演算子を使用して行をフィルタリングします。

```sql
-- 単純な条件
SELECT * FROM users WHERE age > 25;
SELECT * FROM users WHERE name = 'John Doe';

-- 複数の条件
SELECT * FROM users WHERE age > 18 AND age < 65;
SELECT * FROM users WHERE department = 'IT' OR salary > 50000;

-- パターンマッチング
SELECT * FROM users WHERE email LIKE '%@gmail.com';
SELECT * FROM users WHERE name GLOB 'J*';
```

### 並べ替えと制限：`ORDER BY` / `LIMIT`

結果を並べ替え、返される行数を制限して、データ管理を改善します。

```sql
-- 昇順ソート（デフォルト）
SELECT * FROM users ORDER BY age;

-- 降順ソート
SELECT * FROM users ORDER BY age DESC;

-- 複数ソート列
SELECT * FROM users ORDER BY department, salary DESC;

-- 結果の制限
SELECT * FROM users LIMIT 10;

-- オフセット付きの制限（ページネーション）
SELECT * FROM users LIMIT 10 OFFSET 20;
```

### 集計関数：`COUNT`, `SUM`, `AVG`

行のグループに対して計算を実行し、統計分析を行います。

```sql
-- レコードのカウント
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT department) FROM employees;

-- 合計と平均
SELECT SUM(salary), AVG(salary) FROM employees;

-- 最小値と最大値
SELECT MIN(age), MAX(age) FROM users;
```

## 高度なクエリ

### グループ化：`GROUP BY` / `HAVING`

指定された基準で行をグループ化し、サマリーレポートのためにグループをフィルタリングします。

```sql
-- 単一列でのグループ化
SELECT department, COUNT(*)
FROM employees
GROUP BY department;

-- 複数列でのグループ化
SELECT department, job_title, AVG(salary)
FROM employees
GROUP BY department, job_title;

-- HAVING を使用したグループのフィルタリング
SELECT department, AVG(salary) as avg_salary
FROM employees
GROUP BY department
HAVING avg_salary > 60000;
```

### サブクエリ

ネストされたクエリを使用して、複雑なデータ取得と条件付きロジックを実現します。

```sql
-- WHERE 句内のサブクエリ
SELECT name FROM users
WHERE age > (SELECT AVG(age) FROM users);

-- FROM 句内のサブクエリ
SELECT dept, avg_salary FROM (
    SELECT department as dept, AVG(salary) as avg_salary
    FROM employees
    GROUP BY department
) WHERE avg_salary > 50000;

-- EXISTS サブクエリ
SELECT * FROM users u
WHERE EXISTS (
    SELECT 1 FROM orders o WHERE o.user_id = u.id
);
```

### ジョイン：`INNER`, `LEFT`, `RIGHT`

リレーショナルクエリのために、さまざまな結合タイプを使用して複数のテーブルからのデータを結合します。

```sql
-- 内部結合
SELECT u.name, o.amount
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- 左結合（すべてのユーザーを表示）
SELECT u.name, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- 自己結合
SELECT e1.name as employee, e2.name as manager
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id;
```

### セット演算：`UNION` / `INTERSECT`

セット演算を使用して複数のクエリの結果を結合します。

```sql
-- Union（結果の結合）
SELECT name FROM customers
UNION
SELECT name FROM suppliers;

-- Intersect（共通の結果）
SELECT email FROM users
INTERSECT
SELECT email FROM newsletter_subscribers;

-- Except（差分）
SELECT email FROM users
EXCEPT
SELECT email FROM unsubscribed;
```

## インデックスとパフォーマンス

### インデックスの作成：`CREATE INDEX`

クエリの高速化とパフォーマンス向上のために、列にインデックスを作成します。

```sql
-- 単一列インデックス
CREATE INDEX idx_user_email ON users(email);

-- 複数列インデックス
CREATE INDEX idx_order_user_date ON orders(user_id, order_date);

-- 一意インデックス
CREATE UNIQUE INDEX idx_product_sku ON products(sku);

-- 複合インデックス（条件付き）
CREATE INDEX idx_active_users ON users(name) WHERE active = 1;
```

### クエリ分析：`EXPLAIN QUERY PLAN`

クエリ実行計画を分析し、パフォーマンスのボトルネックを特定します。

```bash
# クエリパフォーマンスの分析
EXPLAIN QUERY PLAN SELECT * FROM users WHERE email = 'test@example.com';

-- インデックスが使用されているか確認
EXPLAIN QUERY PLAN SELECT * FROM orders WHERE user_id = 123;
```

### データベースの最適化：`VACUUM` / `ANALYZE`

データベースファイルを最適化し、統計情報を更新してパフォーマンスを向上させます。

```bash
# スペースを回収するためにデータベースを再構築
VACUUM;

-- インデックス統計の更新
ANALYZE;

-- データベースの整合性チェック
PRAGMA integrity_check;
```

### パフォーマンス設定：`PRAGMA`

プラグマステートメントを使用して、最適化と構成のために SQLite の設定を構成します。

```sql
-- パフォーマンス向上のためのジャーナルモード設定
PRAGMA journal_mode = WAL;

-- 同期モードの設定
PRAGMA synchronous = NORMAL;

-- 外部キー制約の有効化
PRAGMA foreign_keys = ON;

-- キャッシュサイズの指定（ページ単位）
PRAGMA cache_size = 10000;
```

## ビューとトリガー

### ビュー: `CREATE VIEW`

保存されたクエリを表す仮想テーブルを作成し、再利用可能なデータアクセスを可能にします。

```sql
-- 単純なビューの作成
CREATE VIEW active_users AS
SELECT id, name, email
FROM users
WHERE active = 1;

-- 結合を含む複雑なビュー
CREATE VIEW order_summary AS
SELECT
    u.name,
    COUNT(o.id) as total_orders,
    SUM(o.amount) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- ビューのクエリ
SELECT * FROM active_users WHERE name LIKE 'J%';

-- ビューの削除
DROP VIEW IF EXISTS order_summary;
```

### ビューの使用

通常のテーブルのようにビューをクエリして、データアクセスを簡素化します。

```sql
SELECT * FROM active_users;
SELECT * FROM order_summary WHERE total_spent > 1000;
```

### トリガー: `CREATE TRIGGER`

データベースイベントに応答してコードを自動的に実行します。

```sql
-- INSERT 時のトリガー
CREATE TRIGGER update_user_count
AFTER INSERT ON users
BEGIN
    UPDATE stats SET user_count = user_count + 1;
END;

-- UPDATE 時のトリガー
CREATE TRIGGER log_salary_changes
AFTER UPDATE OF salary ON employees
BEGIN
    INSERT INTO audit_log (table_name, action, old_value, new_value)
    VALUES ('employees', 'salary_update', OLD.salary, NEW.salary);
END;

-- トリガーの削除
DROP TRIGGER IF EXISTS update_user_count;
```

## データ型と関数

### 日付と時刻の関数

組み込みの SQLite 関数を使用して、日付と時刻の操作を処理します。

```sql
-- 現在の日付/時刻
SELECT datetime('now');
SELECT date('now');
SELECT time('now');

-- 日付の算術演算
SELECT date('now', '+1 day');
SELECT datetime('now', '-1 hour');
SELECT date('now', 'start of month');

-- 日付のフォーマット
SELECT strftime('%Y-%m-%d %H:%M', 'now');
SELECT strftime('%w', 'now'); -- 曜日
```

### 文字列関数

さまざまな文字列操作でテキストデータを操作します。

```sql
-- 文字列操作
SELECT upper(name) FROM users;
SELECT lower(email) FROM users;
SELECT length(name) FROM users;
SELECT substr(name, 1, 3) FROM users;

-- 文字列の連結
SELECT name || ' - ' || email as display FROM users;
SELECT printf('%s (%d)', name, age) FROM users;

-- 文字列の置換
SELECT replace(phone, '-', '') FROM users;
```

### 数値関数

数学的な操作と計算を実行します。

```sql
-- 数学関数
SELECT abs(-15);
SELECT round(price, 2) FROM products;
SELECT random(); -- 乱数

-- 算術演算を伴う集計
SELECT department, round(AVG(salary), 2) as avg_salary
FROM employees
GROUP BY department;
```

### 条件付きロジック：`CASE`

SQL クエリ内で条件付きロジックを実装します。

```sql
-- 単純な CASE ステートメント
SELECT name,
    CASE
        WHEN age < 18 THEN 'Minor'
        WHEN age < 65 THEN 'Adult'
        ELSE 'Senior'
    END as age_category
FROM users;

-- WHERE 句での CASE
SELECT * FROM products
WHERE CASE WHEN category = 'Electronics' THEN price < 1000
          ELSE price < 100 END;
```

## トランザクションと並行性

### トランザクション制御

SQLite トランザクションは完全に ACID 準拠であり、信頼性の高いデータ操作を保証します。

```sql
-- 基本的なトランザクション
BEGIN TRANSACTION;
INSERT INTO users (name, email) VALUES ('Test User', 'test@example.com');
UPDATE users SET age = 25 WHERE name = 'Test User';
COMMIT;

-- ロールバックを伴うトランザクション
BEGIN;
DELETE FROM orders WHERE amount < 10;
-- 結果を確認し、必要に応じてロールバック
ROLLBACK;

-- ネストされたトランザクションのためのセーブポイント
BEGIN;
SAVEPOINT sp1;
INSERT INTO products (name) VALUES ('Product A');
ROLLBACK TO sp1;
COMMIT;
```

### ロックと並行性

データ整合性のためにデータベースロックと並行アクセスを管理します。

```sql
-- ロック状態の確認
PRAGMA locking_mode;

-- より良い並行性のための WAL モードの設定
PRAGMA journal_mode = WAL;

-- ロック待機のためのビジータイムアウト
PRAGMA busy_timeout = 5000;

-- 現在のデータベース接続の確認
.databases
```

## SQLite コマンドラインツール

### データベースコマンド：`.help`

利用可能なドットコマンドの SQLite コマンドラインヘルプとドキュメントにアクセスします。

```bash
# 利用可能なすべてのコマンドを表示
.help
# 現在の設定を表示
.show
# 出力形式の設定
.mode csv
.headers on
```

### インポート/エクスポート：`.import` / `.export`

SQLite と外部ファイル間でさまざまな形式でデータを転送します。

```bash
# CSVファイルのインポート
.mode csv
.import data.csv users

# CSVへのエクスポート
.headers on
.mode csv
.output users.csv
SELECT * FROM users;
```

### スキーマ管理：`.schema` / `.tables`

開発およびデバッグのために、データベース構造とテーブル定義を調べます。

```bash
# すべてのテーブルを表示
.tables
# 特定のテーブルのスキーマを表示
.schema users
# すべてのスキーマを表示
.schema
# テーブル情報の表示
.mode column
.headers on
PRAGMA table_info(users);
```

### 出力フォーマット：`.mode`

コマンドラインインターフェースでのクエリ結果の表示方法を制御します。

```bash
# さまざまな出力モード
.mode csv        # カンマ区切り値
.mode column     # アライメントされた列
.mode html       # HTMLテーブル形式
.mode json       # JSON形式
.mode list       # リスト形式
.mode table      # テーブル形式（デフォルト）

# 列幅の設定
.width 10 15 20

# 結果をファイルに保存
.output results.txt
SELECT * FROM users;
.output stdout

# ファイルからSQLを読み込む
.read script.sql

# データベースファイルの変更
.open another_database.db
```

## 設定とオプション

### データベース設定：`PRAGMA`

最適化と構成のためにプラグマステートメントを通じて SQLite の動作を制御します。

```sql
-- データベース情報
PRAGMA database_list;
PRAGMA table_info(users);
PRAGMA foreign_key_list(orders);

-- パフォーマンス設定
PRAGMA cache_size = 10000;
PRAGMA temp_store = memory;
PRAGMA mmap_size = 268435456;

-- 外部キー制約の有効化
PRAGMA foreign_keys = ON;

-- セキュア削除モードの設定
PRAGMA secure_delete = ON;

-- 整合性のチェック
PRAGMA foreign_key_check;
```

### セキュリティ設定

セキュリティ関連のデータベースオプションと制約を構成します。

```sql
-- 外部キー制約の有効化
PRAGMA foreign_keys = ON;

-- セキュア削除モード
PRAGMA secure_delete = ON;

-- 整合性のチェック
PRAGMA integrity_check;
```

## インストールとセットアップ

### ダウンロードとインストール

オペレーティングシステム用に SQLite ツールをダウンロードし、コマンドラインインターフェースをセットアップします。

```bash
# sqlite.orgからダウンロード
# Windowsの場合: sqlite-tools-win32-x86-*.zip
# Linux/Macの場合: パッケージマネージャを使用

# Ubuntu/Debian
sudo apt-get install sqlite3

# macOS (Homebrewを使用)
brew install sqlite

# インストールの確認
sqlite3 --version
```

### 最初のデータベースの作成

SQLite データベースファイルを作成し、簡単なコマンドを使用してデータ操作を開始します。

```bash
# 新しいデータベースの作成
sqlite3 myapp.db

# テーブルの作成とデータの追加
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE
);

INSERT INTO users (name, email)
VALUES ('John Doe', 'john@example.com');
```

### プログラミング言語との統合

組み込みライブラリまたはサードパーティライブラリを通じて、さまざまなプログラミング言語で SQLite を使用します。

```python
# Python（組み込み sqlite3 モジュール）
import sqlite3
conn = sqlite3.connect('mydb.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users')
```

```javascript
// Node.js（sqlite3 パッケージが必要）
const sqlite3 = require('sqlite3')
const db = new sqlite3.Database('mydb.db')
db.all('SELECT * FROM users', (err, rows) => {
  console.log(rows)
})
```

```php
// PHP（組み込み PDO SQLite）
$pdo = new PDO('sqlite:mydb.db');
$stmt = $pdo->query('SELECT * FROM users');
```

## 関連リンク

- <router-link to="/database">データベース チートシート</router-link>
- <router-link to="/mysql">MySQL チートシート</router-link>
- <router-link to="/postgresql">PostgreSQL チートシート</router-link>
- <router-link to="/mongodb">MongoDB チートシート</router-link>
- <router-link to="/redis">Redis チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>

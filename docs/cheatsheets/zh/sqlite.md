---
title: 'SQLite 速查表 | LabEx'
description: '使用此综合速查表学习 SQLite 数据库。SQLite SQL 语法、事务、触发器、视图和轻量级应用数据库管理的快速参考。'
pdfUrl: '/cheatsheets/pdf/sqlite-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
SQLite 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/sqlite">通过实践实验室学习 SQLite</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 SQLite 数据库管理。LabEx 提供全面的 SQLite 课程，涵盖基本的 SQL 操作、数据操作、查询优化、数据库设计和性能调优。掌握轻量级数据库开发和高效数据管理。
</base-disclaimer-content>
</base-disclaimer>

## 数据库创建与连接

### 创建数据库：`sqlite3 database.db`

创建一个新的 SQLite 数据库文件。

```bash
# 创建或打开一个数据库
sqlite3 mydata.db
# 创建内存数据库（临时）
sqlite3 :memory:
# 使用命令创建数据库
.open mydata.db
# 显示所有已连接的数据库
.databases
# 显示所有表的结构
.schema
# 显示表列表
.tables
# 退出 SQLite
.exit
# 替代退出命令
.quit
```

### 数据库信息：`.databases`

列出所有已连接的数据库及其文件。

```sql
-- 连接另一个数据库
ATTACH DATABASE 'backup.db' AS backup;
-- 从已连接的数据库查询
SELECT * FROM backup.users;
-- 断开连接
DETACH DATABASE backup;
```

### 退出 SQLite: `.exit` 或 `.quit`

关闭 SQLite 命令行界面。

```bash
.exit
.quit
```

### 备份数据库：`.backup`

创建当前数据库的备份。

```bash
# 备份到文件
.backup backup.db
# 从备份恢复
.restore backup.db
# 导出到 SQL 文件
.output backup.sql
.dump
# 导入 SQL 脚本
.read backup.sql
```

## 表创建与结构

### 创建表：`CREATE TABLE`

使用列和约束创建一个新表。

```sql
-- 基本表创建
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    age INTEGER,
    created_date DATE DEFAULT CURRENT_TIMESTAMP
);

-- 带外键的表
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    amount REAL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

<BaseQuiz id="sqlite-create-table-1" correct="A">
  <template #question>
    `INTEGER PRIMARY KEY AUTOINCREMENT` 在 SQLite 中做什么？
  </template>
  
  <BaseQuizOption value="A" correct>创建一个自动递增的整数主键</BaseQuizOption>
  <BaseQuizOption value="B">创建一个文本主键</BaseQuizOption>
  <BaseQuizOption value="C">创建一个外键约束</BaseQuizOption>
  <BaseQuizOption value="D">创建一个唯一索引</BaseQuizOption>
  
  <BaseQuizAnswer>
    `INTEGER PRIMARY KEY AUTOINCREMENT` 创建一个整数列，它为新行自动递增，并作为主键。这确保了每行都有一个唯一的标识符。
  </BaseQuizAnswer>
</BaseQuiz>

### 数据类型：`INTEGER`, `TEXT`, `REAL`, `BLOB`

SQLite 使用动态类型和存储类来实现灵活的数据存储。

```sql
-- 常见数据类型
CREATE TABLE products (
    id INTEGER,           -- 整数
    name TEXT,           -- 文本字符串
    price REAL,          -- 浮点数
    image BLOB,          -- 二进制数据
    active BOOLEAN,      -- 布尔值（存储为 INTEGER）
    created_at DATETIME  -- 日期和时间
);
```

### 约束：`PRIMARY KEY`, `NOT NULL`, `UNIQUE`

定义约束以强制执行数据完整性和表关系。

```sql
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL,
    salary REAL CHECK(salary > 0),
    manager_id INTEGER REFERENCES employees(id)
);
```

## 数据插入与修改

### 插入数据：`INSERT INTO`

添加单行或多行新记录到表中。

```sql
-- 插入单条记录
INSERT INTO users (name, email, age)
VALUES ('John Doe', 'john@email.com', 30);

-- 插入多条记录
INSERT INTO users (name, email, age) VALUES
    ('Jane Smith', 'jane@email.com', 25),
    ('Bob Wilson', 'bob@email.com', 35);

-- 插入所有列
INSERT INTO users VALUES
    (NULL, 'Alice Brown', 'alice@email.com', 28, datetime('now'));
```

### 更新数据：`UPDATE SET`

根据条件修改现有记录。

```sql
-- 更新单列
UPDATE users SET age = 31 WHERE name = 'John Doe';

-- 更新多列
UPDATE users SET
    email = 'newemail@example.com',
    age = age + 1
WHERE id = 1;

-- 带子查询的更新
UPDATE products SET price = price * 1.1
WHERE category = 'Electronics';
```

<BaseQuiz id="sqlite-update-1" correct="D">
  <template #question>
    如果在 UPDATE 语句中忘记了 WHERE 子句会发生什么？
  </template>
  
  <BaseQuizOption value="A">更新失败</BaseQuizOption>
  <BaseQuizOption value="B">只有第一行被更新</BaseQuizOption>
  <BaseQuizOption value="C">什么也不会发生</BaseQuizOption>
  <BaseQuizOption value="D" correct>表中的所有行都被更新</BaseQuizOption>
  
  <BaseQuizAnswer>
    如果没有 WHERE 子句，UPDATE 语句将修改表中的所有行。务必使用 WHERE 来指定要更新的行，以避免意外更改不需要的数据。
  </BaseQuizAnswer>
</BaseQuiz>

### 删除数据：`DELETE FROM`

根据指定的条件从表中删除记录。

```sql
-- 删除特定记录
DELETE FROM users WHERE age < 18;

-- 删除所有记录（保留表结构）
DELETE FROM users;

-- 带子查询的删除
DELETE FROM orders
WHERE user_id IN (SELECT id FROM users WHERE active = 0);
```

### Upsert: `INSERT OR REPLACE`

根据冲突插入新记录或更新现有记录。

```sql
-- 冲突时插入或替换
INSERT OR REPLACE INTO users (id, name, email)
VALUES (1, 'Updated Name', 'updated@email.com');

-- 冲突时插入或忽略
INSERT OR IGNORE INTO users (name, email)
VALUES ('Duplicate', 'existing@email.com');
```

<BaseQuiz id="sqlite-upsert-1" correct="A">
  <template #question>
    `INSERT OR REPLACE` 和 `INSERT OR IGNORE` 有什么区别？
  </template>
  
  <BaseQuizOption value="A" correct>REPLACE 更新现有行，IGNORE 跳过重复项</BaseQuizOption>
  <BaseQuizOption value="B">没有区别</BaseQuizOption>
  <BaseQuizOption value="C">REPLACE 删除该行，IGNORE 更新它</BaseQuizOption>
  <BaseQuizOption value="D">REPLACE 用于表，IGNORE 用于视图</BaseQuizOption>
  
  <BaseQuizAnswer>
    如果存在冲突（例如主键重复），`INSERT OR REPLACE` 将替换现有行。如果存在冲突，`INSERT OR IGNORE` 将简单地跳过插入，保持现有行不变。
  </BaseQuizAnswer>
</BaseQuiz>

## 数据查询与选择

### 基本查询：`SELECT`

使用带有各种选项的 SELECT 语句查询表中的数据。

```sql
-- 选择所有列
SELECT * FROM users;

-- 选择特定列
SELECT name, email FROM users;

-- 选择并使用别名
SELECT name AS full_name, age AS years_old FROM users;

-- 选择唯一值
SELECT DISTINCT department FROM employees;
```

<BaseQuiz id="sqlite-select-1" correct="B">
  <template #question>
    `SELECT DISTINCT` 做什么？
  </template>
  
  <BaseQuizOption value="A">选择所有行</BaseQuizOption>
  <BaseQuizOption value="B" correct>仅返回唯一值，去除重复项</BaseQuizOption>
  <BaseQuizOption value="C">仅选择第一行</BaseQuizOption>
  <BaseQuizOption value="D">对结果进行排序</BaseQuizOption>
  
  <BaseQuizAnswer>
    `SELECT DISTINCT` 从结果集中消除重复的行，只返回唯一值。当你想查看某一列中所有唯一值时，这很有用。
  </BaseQuizAnswer>
</BaseQuiz>

### 过滤：`WHERE`

使用各种条件和比较运算符过滤行。

```sql
-- 简单条件
SELECT * FROM users WHERE age > 25;
SELECT * FROM users WHERE name = 'John Doe';

-- 多重条件
SELECT * FROM users WHERE age > 18 AND age < 65;
SELECT * FROM users WHERE department = 'IT' OR salary > 50000;

-- 模式匹配
SELECT * FROM users WHERE email LIKE '%@gmail.com';
SELECT * FROM users WHERE name GLOB 'J*';
```

### 排序与限制：`ORDER BY` / `LIMIT`

对结果进行排序并限制返回的行数，以更好地管理数据。

```sql
-- 升序排序（默认）
SELECT * FROM users ORDER BY age;

-- 降序排序
SELECT * FROM users ORDER BY age DESC;

-- 多重排序
SELECT * FROM users ORDER BY department, salary DESC;

-- 限制结果
SELECT * FROM users LIMIT 10;

-- 带偏移量的限制（分页）
SELECT * FROM users LIMIT 10 OFFSET 20;
```

### 聚合函数：`COUNT`, `SUM`, `AVG`

对行组执行计算，用于统计分析。

```sql
-- 计数记录
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT department) FROM employees;

-- 求和与平均值
SELECT SUM(salary), AVG(salary) FROM employees;

-- 最小值和最大值
SELECT MIN(age), MAX(age) FROM users;
```

## 高级查询

### 分组：`GROUP BY` / `HAVING`

按指定标准对行进行分组，并过滤组以进行汇总报告。

```sql
-- 按单列分组
SELECT department, COUNT(*)
FROM employees
GROUP BY department;

-- 按多列分组
SELECT department, job_title, AVG(salary)
FROM employees
GROUP BY department, job_title;

-- 使用 HAVING 过滤组
SELECT department, AVG(salary) as avg_salary
FROM employees
GROUP BY department
HAVING avg_salary > 60000;
```

### 子查询

使用嵌套查询进行复杂的数据检索和条件逻辑。

```sql
-- 在 WHERE 子句中使用子查询
SELECT name FROM users
WHERE age > (SELECT AVG(age) FROM users);

-- 在 FROM 子句中使用子查询
SELECT dept, avg_salary FROM (
    SELECT department as dept, AVG(salary) as avg_salary
    FROM employees
    GROUP BY department
) WHERE avg_salary > 50000;

-- EXISTS 子查询
SELECT * FROM users u
WHERE EXISTS (
    SELECT 1 FROM orders o WHERE o.user_id = u.id
);
```

### 连接：`INNER`, `LEFT`, `RIGHT`

使用各种连接类型组合来自多个表的数据，用于关系查询。

```sql
-- 内连接
SELECT u.name, o.amount
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- 左连接（显示所有用户）
SELECT u.name, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- 自连接
SELECT e1.name as employee, e2.name as manager
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id;
```

### 集合操作：`UNION` / `INTERSECT`

使用集合操作组合多个查询的结果。

```sql
-- Union（合并结果）
SELECT name FROM customers
UNION
SELECT name FROM suppliers;

-- Intersect（共同结果）
SELECT email FROM users
INTERSECT
SELECT email FROM newsletter_subscribers;

-- Except（差集）
SELECT email FROM users
EXCEPT
SELECT email FROM unsubscribed;
```

## 索引与性能

### 创建索引：`CREATE INDEX`

在列上创建索引以加快查询速度并提高性能。

```sql
-- 单列索引
CREATE INDEX idx_user_email ON users(email);

-- 多列索引
CREATE INDEX idx_order_user_date ON orders(user_id, order_date);

-- 唯一索引
CREATE UNIQUE INDEX idx_product_sku ON products(sku);

-- 局部索引（带条件）
CREATE INDEX idx_active_users ON users(name) WHERE active = 1;
```

### 查询分析：`EXPLAIN QUERY PLAN`

分析查询执行计划以识别性能瓶颈。

```bash
# 分析查询性能
EXPLAIN QUERY PLAN SELECT * FROM users WHERE email = 'test@example.com';

-- 检查索引是否被使用
EXPLAIN QUERY PLAN SELECT * FROM orders WHERE user_id = 123;
```

### 数据库优化：`VACUUM` / `ANALYZE`

优化数据库文件并更新统计信息以获得更好的性能。

```bash
# 重建数据库以回收空间
VACUUM;

-- 更新索引统计信息
ANALYZE;

-- 检查数据库完整性
PRAGMA integrity_check;
```

### 性能设置：`PRAGMA`

通过 pragma 语句配置 SQLite 设置，以实现最佳性能和行为。

```sql
-- 设置日志模式以获得更好的性能
PRAGMA journal_mode = WAL;

-- 设置同步模式
PRAGMA synchronous = NORMAL;

-- 启用外键约束
PRAGMA foreign_keys = ON;

-- 设置缓存大小（以页为单位）
PRAGMA cache_size = 10000;
```

## 视图与触发器

### 视图：`CREATE VIEW`

创建代表存储查询的虚拟表，用于可重用的数据访问。

```sql
-- 创建一个简单视图
CREATE VIEW active_users AS
SELECT id, name, email
FROM users
WHERE active = 1;

-- 复杂视图带连接
CREATE VIEW order_summary AS
SELECT
    u.name,
    COUNT(o.id) as total_orders,
    SUM(o.amount) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- 查询视图
SELECT * FROM active_users WHERE name LIKE 'J%';

-- 删除视图
DROP VIEW IF EXISTS order_summary;
```

### 使用视图

像操作常规表一样查询视图，以简化数据访问。

```sql
SELECT * FROM active_users;
SELECT * FROM order_summary WHERE total_spent > 1000;
```

### 触发器：`CREATE TRIGGER`

自动执行代码以响应数据库事件。

```sql
-- INSERT 触发器
CREATE TRIGGER update_user_count
AFTER INSERT ON users
BEGIN
    UPDATE stats SET user_count = user_count + 1;
END;

-- UPDATE 触发器
CREATE TRIGGER log_salary_changes
AFTER UPDATE OF salary ON employees
BEGIN
    INSERT INTO audit_log (table_name, action, old_value, new_value)
    VALUES ('employees', 'salary_update', OLD.salary, NEW.salary);
END;

-- 删除触发器
DROP TRIGGER IF EXISTS update_user_count;
```

## 数据类型与函数

### 日期与时间函数

使用 SQLite 内置函数处理日期和时间操作。

```sql
-- 当前日期/时间
SELECT datetime('now');
SELECT date('now');
SELECT time('now');

-- 日期算术
SELECT date('now', '+1 day');
SELECT datetime('now', '-1 hour');
SELECT date('now', 'start of month');

-- 格式化日期
SELECT strftime('%Y-%m-%d %H:%M', 'now');
SELECT strftime('%w', 'now'); -- 星期几
```

### 字符串函数

使用各种字符串操作来处理文本数据。

```sql
-- 字符串操作
SELECT upper(name) FROM users;
SELECT lower(email) FROM users;
SELECT length(name) FROM users;
SELECT substr(name, 1, 3) FROM users;

-- 字符串连接
SELECT name || ' - ' || email as display FROM users;
SELECT printf('%s (%d)', name, age) FROM users;

-- 字符串替换
SELECT replace(phone, '-', '') FROM users;
```

### 数值函数

执行数学运算和计算。

```sql
-- 数学函数
SELECT abs(-15);
SELECT round(price, 2) FROM products;
SELECT random(); -- 随机数

-- 带数学的聚合
SELECT department, round(AVG(salary), 2) as avg_salary
FROM employees
GROUP BY department;
```

### 条件逻辑：`CASE`

在 SQL 查询中实现条件逻辑。

```sql
-- 简单的 CASE 语句
SELECT name,
    CASE
        WHEN age < 18 THEN 'Minor'
        WHEN age < 65 THEN 'Adult'
        ELSE 'Senior'
    END as age_category
FROM users;

-- 在 WHERE 子句中使用 CASE
SELECT * FROM products
WHERE CASE WHEN category = 'Electronics' THEN price < 1000
          ELSE price < 100 END;
```

## 事务与并发

### 事务控制

SQLite 事务完全符合 ACID，确保可靠的数据操作。

```sql
-- 基本事务
BEGIN TRANSACTION;
INSERT INTO users (name, email) VALUES ('Test User', 'test@example.com');
UPDATE users SET age = 25 WHERE name = 'Test User';
COMMIT;

-- 带回滚的事务
BEGIN;
DELETE FROM orders WHERE amount < 10;
-- 检查结果，如有需要则回滚
ROLLBACK;

-- 保存点用于嵌套事务
BEGIN;
SAVEPOINT sp1;
INSERT INTO products (name) VALUES ('Product A');
ROLLBACK TO sp1;
COMMIT;
```

### 锁定与并发

管理数据库锁定和并发访问以确保数据完整性。

```bash
# 检查锁定状态
PRAGMA locking_mode;

-- 设置 WAL 模式以获得更好的并发性
PRAGMA journal_mode = WAL;

-- 锁等待超时
PRAGMA busy_timeout = 5000;

-- 检查当前数据库连接
.databases
```

## SQLite 命令行工具

### 数据库命令：`.help`

访问 SQLite 命令行帮助和可用点命令的文档。

```bash
# 显示所有可用命令
.help
# 显示当前设置
.show
# 设置输出格式
.mode csv
.headers on
```

### 导入/导出：`.import` / `.export`

在 SQLite 和外部文件之间传输各种格式的数据。

```bash
# 导入 CSV 文件
.mode csv
.import data.csv users

# 导出到 CSV
.headers on
.mode csv
.output users.csv
SELECT * FROM users;
```

### 结构管理：`.schema` / `.tables`

检查数据库结构和表定义，用于开发和调试。

```bash
# 显示所有表
.tables
# 显示特定表的结构
.schema users
# 显示所有结构
.schema
# 显示表信息
.mode column
.headers on
PRAGMA table_info(users);
```

### 输出格式化：`.mode`

控制查询结果在命令行界面中的显示方式。

```bash
# 不同的输出模式
.mode csv        # 逗号分隔值
.mode column     # 对齐的列
.mode html       # HTML 表格格式
.mode json       # JSON 格式
.mode list       # 列表格式
.mode table      # 表格格式（默认）

# 设置列宽
.width 10 15 20

# 将输出保存到文件
.output results.txt
SELECT * FROM users;
.output stdout

# 从文件读取 SQL
.read script.sql

# 切换数据库文件
.open another_database.db
```

## 配置与设置

### 数据库设置：`PRAGMA`

通过 pragma 语句控制 SQLite 的行为，以实现优化和配置。

```sql
-- 数据库信息
PRAGMA database_list;
PRAGMA table_info(users);
PRAGMA foreign_key_list(orders);

-- 性能设置
PRAGMA cache_size = 10000;
PRAGMA temp_store = memory;
PRAGMA mmap_size = 268435456;

-- 启用外键约束
PRAGMA foreign_keys = ON;

-- 设置安全删除模式
PRAGMA secure_delete = ON;

-- 检查约束
PRAGMA foreign_key_check;
```

### 安全设置

配置与安全相关的数据库选项和约束。

```sql
-- 启用外键约束
PRAGMA foreign_keys = ON;

-- 安全删除模式
PRAGMA secure_delete = ON;

-- 检查完整性
PRAGMA integrity_check;
```

## 安装与设置

### 下载与安装

下载 SQLite 工具并为您的操作系统设置命令行界面。

```bash
# 从 sqlite.org 下载
# Windows: sqlite-tools-win32-x86-*.zip
# Linux/Mac: 使用包管理器

# Ubuntu/Debian
sudo apt-get install sqlite3

# macOS 使用 Homebrew
brew install sqlite

# 验证安装
sqlite3 --version
```

### 创建您的第一个数据库

创建 SQLite 数据库文件，并使用简单命令开始处理数据。

```bash
# 创建新数据库
sqlite3 myapp.db

# 创建表并添加数据
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE
);

INSERT INTO users (name, email)
VALUES ('John Doe', 'john@example.com');
```

### 编程语言集成

使用内置或第三方库在各种编程语言中使用 SQLite。

```python
# Python (内置 sqlite3 模块)
import sqlite3
conn = sqlite3.connect('mydb.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users')
```

```javascript
// Node.js (需要 sqlite3 包)
const sqlite3 = require('sqlite3')
const db = new sqlite3.Database('mydb.db')
db.all('SELECT * FROM users', (err, rows) => {
  console.log(rows)
})
```

```php
// PHP (内置 PDO SQLite)
$pdo = new PDO('sqlite:mydb.db');
$stmt = $pdo->query('SELECT * FROM users');
```

## 相关链接

- <router-link to="/database">数据库速查表</router-link>
- <router-link to="/mysql">MySQL 速查表</router-link>
- <router-link to="/postgresql">PostgreSQL 速查表</router-link>
- <router-link to="/mongodb">MongoDB 速查表</router-link>
- <router-link to="/redis">Redis 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>

---
title: 'PostgreSQL 速查表 | LabEx'
description: '使用此综合速查表学习 PostgreSQL 数据库管理。快速参考 SQL 查询、高级功能、JSON 支持、全文搜索和企业数据库管理。'
pdfUrl: '/cheatsheets/pdf/postgresql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
PostgreSQL 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/postgresql">通过动手实验学习 PostgreSQL</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过动手实验和真实场景学习 PostgreSQL 数据库管理。LabEx 提供全面的 PostgreSQL 课程，涵盖基本的 SQL 操作、高级查询、性能优化、数据库管理和安全。掌握企业级关系数据库的开发和管理。
</base-disclaimer-content>
</base-disclaimer>

## 连接与数据库设置

### 连接到 PostgreSQL: `psql`

使用 psql 命令行工具连接到本地或远程 PostgreSQL 数据库。

```bash
# 连接到本地数据库
psql -U username -d database_name
# 连接到远程数据库
psql -h hostname -p 5432 -U username -d database_name
# 使用密码提示连接
psql -U postgres -W
# 使用连接字符串连接
psql "host=localhost port=5432 dbname=mydb user=myuser"
```

### 创建数据库：`CREATE DATABASE`

使用 CREATE DATABASE 命令在 PostgreSQL 中创建一个新数据库。

```sql
# 创建一个新数据库
CREATE DATABASE mydatabase;
# 创建带所有者的数据库
CREATE DATABASE mydatabase OWNER myuser;
# 创建带编码的数据库
CREATE DATABASE mydatabase
  WITH ENCODING 'UTF8'
  LC_COLLATE='en_US.UTF-8'
  LC_CTYPE='en_US.UTF-8';
```

### 列出数据库：`\l`

列出 PostgreSQL 服务器中的所有数据库。

```bash
# 列出所有数据库
\l
# 列出带有详细信息的数据库
\l+
# 连接到不同的数据库
\c database_name
```

### 基本 psql 命令

用于导航和获取信息的常用 psql 终端命令。

```bash
# 退出 psql
\q
# 获取 SQL 命令的帮助
\help CREATE TABLE
# 获取 psql 命令的帮助
\?
# 显示当前数据库和用户
\conninfo
# 执行系统命令
\! ls
# 列出所有表
\dt
# 列出所有表及其详细信息
\dt+
# 描述特定表
\d table_name
# 列出所有模式 (schema)
\dn
# 列出所有用户/角色
\du
```

### 版本与设置

检查 PostgreSQL 版本和配置设置。

```sql
# 检查 PostgreSQL 版本
SELECT version();
# 查看当前设置
SHOW ALL;
# 查看特定设置
SHOW max_connections;
# 设置配置参数
SET work_mem = '256MB';
```

## 表的创建与管理

### 创建表：`CREATE TABLE`

定义带有列、数据类型和约束的新表。

```sql
# 基本表创建
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

# 带外键的表
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending'
);
```

<BaseQuiz id="postgresql-create-table-1" correct="A">
  <template #question>
    PostgreSQL 中的 <code>SERIAL PRIMARY KEY</code> 是做什么的？
  </template>
  
  <BaseQuizOption value="A" correct>创建一个自增整数列作为主键</BaseQuizOption>
  <BaseQuizOption value="B">创建一个文本列</BaseQuizOption>
  <BaseQuizOption value="C">创建一个外键约束</BaseQuizOption>
  <BaseQuizOption value="D">创建一个唯一索引</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>SERIAL</code> 是 PostgreSQL 特有的数据类型，它创建一个自增整数。与 <code>PRIMARY KEY</code> 结合使用时，它会为每一行创建一个自动递增的唯一标识符。
  </BaseQuizAnswer>
</BaseQuiz>

### 修改表：`ALTER TABLE`

向现有表中添加、修改或删除列和约束。

```sql
# 添加新列
ALTER TABLE users ADD COLUMN phone VARCHAR(15);
# 更改列类型
ALTER TABLE users ALTER COLUMN phone TYPE VARCHAR(20);
# 删除列
ALTER TABLE users DROP COLUMN phone;
# 添加约束
ALTER TABLE users ADD CONSTRAINT unique_email
    UNIQUE (email);
```

### 删除与截断：`DROP/TRUNCATE`

删除表或清除表中的所有数据。

```sql
# 完全删除表
DROP TABLE IF EXISTS old_table;
# 移除所有数据但保留结构
TRUNCATE TABLE users;
# 截断并重置标识符
TRUNCATE TABLE users RESTART IDENTITY;
```

### 数据类型与约束

用于不同类型数据的基本 PostgreSQL 数据类型。

```sql
# 数值类型
INTEGER, BIGINT, SMALLINT
DECIMAL(10,2), NUMERIC(10,2)
REAL, DOUBLE PRECISION

# 字符类型
CHAR(n), VARCHAR(n), TEXT

# 日期/时间类型
DATE, TIME, TIMESTAMP
TIMESTAMPTZ (带时区)

# 布尔值和其他
BOOLEAN
JSON, JSONB
UUID
ARRAY (例如 INTEGER[])

# 主键
id SERIAL PRIMARY KEY

# 外键
user_id INTEGER REFERENCES users(id)

# 唯一约束
email VARCHAR(100) UNIQUE

# 检查约束
age INTEGER CHECK (age >= 0)

# 非空
name VARCHAR(50) NOT NULL
```

### 索引：`CREATE INDEX`

使用数据库索引提高查询性能。

```sql
# 基本索引
CREATE INDEX idx_username ON users(username);
# 唯一索引
CREATE UNIQUE INDEX idx_unique_email
    ON users(email);
# 复合索引
CREATE INDEX idx_user_date
    ON orders(user_id, created_at);
# 局部索引
CREATE INDEX idx_active_users
    ON users(username) WHERE active = true;
# 删除索引
DROP INDEX IF EXISTS idx_username;
```

<BaseQuiz id="postgresql-index-1" correct="A">
  <template #question>
    在 PostgreSQL 中创建索引的主要目的是什么？
  </template>
  
  <BaseQuizOption value="A" correct>提高查询性能，加快数据检索速度</BaseQuizOption>
  <BaseQuizOption value="B">减小数据库大小</BaseQuizOption>
  <BaseQuizOption value="C">加密数据</BaseQuizOption>
  <BaseQuizOption value="D">防止重复条目</BaseQuizOption>
  
  <BaseQuizAnswer>
    索引创建了一个数据结构，允许数据库快速查找行而无需扫描整个表。这显著加快了 SELECT 查询的速度，尤其是在大型表上。
  </BaseQuizAnswer>
</BaseQuiz>

### 序列：`CREATE SEQUENCE`

自动生成唯一的数字值。

```sql
# 创建序列
CREATE SEQUENCE user_id_seq;
# 在表中用序列
CREATE TABLE users (
    id INTEGER DEFAULT nextval('user_id_seq'),
    username VARCHAR(50)
);
# 重置序列
ALTER SEQUENCE user_id_seq RESTART WITH 1000;
```

## CRUD 操作

### 插入数据：`INSERT`

向数据库表中添加新记录。

```sql
# 插入单条记录
INSERT INTO users (username, email)
VALUES ('john_doe', 'john@example.com');
# 插入多条记录
INSERT INTO users (username, email) VALUES
    ('alice', 'alice@example.com'),
    ('bob', 'bob@example.com');
# 插入并返回
INSERT INTO users (username, email)
VALUES ('jane', 'jane@example.com')
RETURNING id, created_at;
# 从选择中插入
INSERT INTO archive_users
SELECT * FROM users WHERE active = false;
```

<BaseQuiz id="postgresql-insert-1" correct="C">
  <template #question>
    PostgreSQL 的 <code>RETURNING</code> 子句有什么作用？
  </template>
  
  <BaseQuizOption value="A">回滚插入操作</BaseQuizOption>
  <BaseQuizOption value="B">阻止插入操作</BaseQuizOption>
  <BaseQuizOption value="C" correct>返回被插入的行数据</BaseQuizOption>
  <BaseQuizOption value="D">更新现有行</BaseQuizOption>
  
  <BaseQuizAnswer>
    PostgreSQL 中的 <code>RETURNING</code> 子句允许您在插入后立即检索被插入的行数据（或特定列），这对于获取自动生成的 ID 或时间戳非常有用。
  </BaseQuizAnswer>
</BaseQuiz>

### 更新数据：`UPDATE`

修改数据库表中的现有记录。

```sql
# 更新特定记录
UPDATE users
SET email = 'newemail@example.com'
WHERE username = 'john_doe';
# 更新多列
UPDATE users
SET email = 'new@example.com',
    updated_at = NOW()
WHERE id = 1;
# 带子查询的更新
UPDATE orders
SET total = (SELECT SUM(price) FROM order_items
            WHERE order_id = orders.id);
```

### 选择数据：`SELECT`

查询和检索数据库表中的数据。

```sql
# 基本选择
SELECT * FROM users;
# 选择特定列
SELECT id, username, email FROM users;
# 带条件的查询
SELECT * FROM users
WHERE active = true AND created_at > '2024-01-01';
# 带排序和限制的查询
SELECT * FROM users
ORDER BY created_at DESC
LIMIT 10 OFFSET 20;
```

### 删除数据：`DELETE`

从数据库表中删除记录。

```sql
# 删除特定记录
DELETE FROM users
WHERE active = false;
# 带子查询的删除
DELETE FROM orders
WHERE user_id IN (
    SELECT id FROM users WHERE active = false
);
# 删除所有记录
DELETE FROM temp_table;
# 带返回的删除
DELETE FROM users
WHERE id = 5
RETURNING *;
```

## 高级查询

### 连接：`INNER/LEFT/RIGHT JOIN`

使用各种连接类型组合来自多个表的数据。

```sql
# 内连接
SELECT u.username, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# 左连接
SELECT u.username, o.total
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# 多重连接
SELECT u.username, o.total, p.name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

### 子查询与 CTE

使用嵌套查询和公共表表达式进行复杂操作。

```sql
# WHERE 中的子查询
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders);
# 公共表表达式 (CTE)
WITH active_users AS (
    SELECT * FROM users WHERE active = true
)
SELECT au.username, COUNT(o.id) as order_count
FROM active_users au
LEFT JOIN orders o ON au.id = o.user_id
GROUP BY au.username;
```

### 聚合：`GROUP BY`

对数据进行分组并应用聚合函数进行分析。

```sql
# 基本分组
SELECT status, COUNT(*) as count
FROM orders
GROUP BY status;
# 多重聚合
SELECT user_id,
       COUNT(*) as order_count,
       SUM(total) as total_spent,
       AVG(total) as avg_order
FROM orders
GROUP BY user_id
HAVING COUNT(*) > 5;
```

### 窗口函数

在不分组的情况下对相关行执行计算。

```sql
# 行编号
SELECT username, email,
       ROW_NUMBER() OVER (ORDER BY created_at) as row_num
FROM users;
# 累计总计
SELECT date, amount,
       SUM(amount) OVER (ORDER BY date) as running_total
FROM sales;
# 排名
SELECT username, score,
       RANK() OVER (ORDER BY score DESC) as rank
FROM user_scores;
```

## 数据导入与导出

### CSV 导入：`COPY`

将 CSV 文件中的数据导入 PostgreSQL 表中。

```sql
# 从 CSV 文件导入
COPY users(username, email, age)
FROM '/path/to/users.csv'
DELIMITER ',' CSV HEADER;
# 带特定选项的导入
COPY products
FROM '/path/to/products.csv'
WITH (FORMAT csv, HEADER true, DELIMITER ';');
# 从标准输入导入
\copy users(username, email) FROM STDIN WITH CSV;
```

### CSV 导出：`COPY TO`

将 PostgreSQL 数据导出到 CSV 文件。

```sql
# 导出到 CSV 文件
COPY users TO '/path/to/users_export.csv'
WITH (FORMAT csv, HEADER true);
# 导出查询结果
COPY (SELECT username, email FROM users WHERE active = true)
TO '/path/to/active_users.csv' CSV HEADER;
# 导出到标准输出
\copy (SELECT * FROM orders) TO STDOUT WITH CSV HEADER;
```

### 备份与恢复：`pg_dump`

创建数据库备份并从备份文件中恢复。

```bash
# 转储整个数据库
pg_dump -U username -h hostname database_name > backup.sql
# 转储特定表
pg_dump -U username -t table_name database_name > table_backup.sql
# 压缩备份
pg_dump -U username -Fc database_name > backup.dump
# 从备份恢复
psql -U username -d database_name < backup.sql
# 恢复压缩备份
pg_restore -U username -d database_name backup.dump
```

### JSON 数据操作

处理 JSON 和 JSONB 数据类型以获取半结构化数据。

```sql
# 插入 JSON 数据
INSERT INTO products (name, metadata)
VALUES ('Laptop', '{"brand": "Dell", "price": 999.99}');
# 查询 JSON 字段
SELECT name, metadata->>'brand' as brand
FROM products
WHERE metadata->>'price'::numeric > 500;
# JSON 数组操作
SELECT name FROM products
WHERE metadata->'features' ? 'wireless';
```

## 用户管理与安全

### 创建用户与角色

使用用户和角色管理数据库访问权限。

```sql
# 创建用户
CREATE USER myuser WITH PASSWORD 'secretpassword';
# 创建角色
CREATE ROLE readonly_role;
# 创建带特定权限的用户
CREATE USER admin_user WITH
    CREATEDB CREATEROLE PASSWORD 'adminpass';
# 将角色授予用户
GRANT readonly_role TO myuser;
```

### 权限：`GRANT/REVOKE`

通过权限控制对数据库对象的访问。

```sql
# 授予表权限
GRANT SELECT, INSERT ON users TO myuser;
# 授予表上的所有权限
GRANT ALL ON orders TO admin_user;
# 授予数据库权限
GRANT CONNECT ON DATABASE mydb TO myuser;
# 撤销权限
REVOKE INSERT ON users FROM myuser;
```

### 查看用户信息

检查现有用户及其权限。

```sql
# 列出所有用户
\du
# 查看表权限
SELECT table_name, privilege_type, grantee
FROM information_schema.table_privileges
WHERE table_schema = 'public';
# 查看当前用户
SELECT current_user;
# 查看角色成员关系
SELECT r.rolname, r.rolsuper, r.rolcreaterole
FROM pg_roles r;
```

### 密码与安全

管理用户密码和安全设置。

```sql
# 更改用户密码
ALTER USER myuser PASSWORD 'newpassword';
# 设置密码过期时间
ALTER USER myuser VALID UNTIL '2025-12-31';
# 创建无登录权限的角色
CREATE ROLE reporting_role NOLOGIN;
# 启用/禁用用户
ALTER USER myuser WITH NOLOGIN;
ALTER USER myuser WITH LOGIN;
```

## 性能与监控

### 查询分析：`EXPLAIN`

分析查询执行计划并优化性能。

```sql
# 显示查询执行计划
EXPLAIN SELECT * FROM users WHERE active = true;
# 带实际执行统计信息的分析
EXPLAIN ANALYZE
SELECT u.username, COUNT(o.id)
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.username;
# 详细执行信息
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT * FROM large_table WHERE indexed_col = 'value';
```

### 数据库维护：`VACUUM`

通过定期清理操作维护数据库性能。

```sql
# 基本清理
VACUUM users;
# 完全清理并分析
VACUUM FULL ANALYZE users;
# 自动清理状态
SELECT schemaname, tablename, last_vacuum, last_autovacuum
FROM pg_stat_user_tables;
# 重新索引表
REINDEX TABLE users;
```

### 监控查询

跟踪数据库活动并识别性能问题。

```sql
# 当前活动
SELECT pid, usename, query, state
FROM pg_stat_activity
WHERE state != 'idle';
# 运行时间长的查询
SELECT pid, now() - query_start as duration, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC;
# 终止特定查询
SELECT pg_terminate_backend(pid) WHERE pid = 12345;
```

### 数据库统计信息

获取有关数据库使用情况和性能指标的见解。

```sql
# 表统计信息
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del
FROM pg_stat_user_tables;
# 索引使用统计信息
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes;
# 数据库大小
SELECT pg_size_pretty(pg_database_size('mydatabase'));
```

## 高级特性

### 视图：`CREATE VIEW`

创建虚拟表以简化复杂查询并提供数据抽象。

```sql
# 创建简单视图
CREATE VIEW active_users AS
SELECT id, username, email
FROM users WHERE active = true;
# 创建带连接的视图
CREATE OR REPLACE VIEW order_summary AS
SELECT u.username, COUNT(o.id) as total_orders,
       SUM(o.total) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.username;
# 删除视图
DROP VIEW IF EXISTS order_summary;
```

### 触发器与函数

使用存储过程和触发器自动化数据库操作。

```sql
# 创建函数
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
# 创建触发器
CREATE TRIGGER update_user_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();
```

### 事务

通过事务控制确保数据一致性。

```sql
# 开始事务
BEGIN;
UPDATE accounts SET balance = balance - 100
WHERE id = 1;
UPDATE accounts SET balance = balance + 100
WHERE id = 2;
# 提交事务
COMMIT;
# 如果需要回滚
ROLLBACK;
# 保存点
SAVEPOINT my_savepoint;
ROLLBACK TO my_savepoint;
```

### 配置与调优

优化 PostgreSQL 服务器设置以获得更好的性能。

```sql
# 查看当前配置
SHOW shared_buffers;
SHOW max_connections;
# 设置配置参数
SET work_mem = '256MB';
SET random_page_cost = 1.1;
# 重新加载配置
SELECT pg_reload_conf();
# 查看配置文件位置
SHOW config_file;
```

## psql 配置与技巧

### 连接文件：`.pgpass`

安全地存储数据库凭据以实现自动身份验证。

```bash
# 创建 .pgpass 文件 (格式: hostname:port:database:username:password)
echo "localhost:5432:mydatabase:myuser:mypassword" >> ~/.pgpass
# 设置正确的权限
chmod 600 ~/.pgpass
# 使用连接服务文件
# ~/.pg_service.conf
[mydb]
host=localhost
port=5432
dbname=mydatabase
user=myuser
```

### psql 配置：`.psqlrc`

自定义 psql 启动设置和行为。

```bash
# 创建 ~/.psqlrc 文件并设置自定义设置
\set QUIET on
\timing on
\set PROMPT1 '%n@%M:%> %`date` %R%# '
\set HISTSIZE 5000
\set COMP_KEYWORD_CASE upper
\x auto
\set QUIET off
# 自定义别名
\set show_slow_queries 'SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;'
```

### 环境变量

设置 PostgreSQL 环境变量以简化连接。

```bash
# 在您的 shell 配置文件中设置
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=mydatabase
export PGUSER=myuser
# 然后只需使用 psql 连接
psql
# 或使用特定环境变量
PGDATABASE=testdb psql
```

### 数据库信息

获取有关数据库对象和结构的​​信息。

```bash
# 列出数据库
\l, \l+
# 列出当前数据库中的表
\dt, \dt+
# 列出视图
\dv, \dv+
# 列出索引
\di, \di+
# 列出函数
\df, \df+
# 列出序列
\ds, \ds+
# 描述表结构
\d table_name
\d+ table_name
# 列出表约束
\d+ table_name
# 显示表权限
\dp table_name
\z table_name
# 列出外键
SELECT * FROM information_schema.table_constraints
WHERE constraint_type = 'FOREIGN KEY';
```

### 输出与格式化

控制 psql 如何显示查询结果和输出。

```bash
# 切换扩展输出
\x
# 更改输出格式
\H  -- HTML 输出
\t  -- 仅元组 (无标题)
# 输出到文件
\o filename.txt
SELECT * FROM users;
\o  -- 停止输出到文件
# 从文件执行 SQL
\i script.sql
# 在外部编辑器中编辑查询
\e
```

### 计时与历史记录

跟踪查询性能并管理命令历史记录。

```bash
# 切换计时显示
\timing
# 显示命令历史记录
\s
# 将命令历史记录保存到文件
\s filename.txt
# 清屏
\! clear  -- Linux/Mac
\! cls   -- Windows
# 显示最后一条错误
\errverbose
```

## 相关链接

- <router-link to="/database">数据库速查表</router-link>
- <router-link to="/mysql">MySQL 速查表</router-link>
- <router-link to="/sqlite">SQLite 速查表</router-link>
- <router-link to="/mongodb">MongoDB 速查表</router-link>
- <router-link to="/redis">Redis 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>

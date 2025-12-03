---
title: 'MySQL 速查表 | LabEx'
description: '使用此综合速查表学习 MySQL 数据库管理。快速参考 SQL 查询、连接、索引、事务、存储过程和数据库管理。'
pdfUrl: '/cheatsheets/pdf/mysql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
MySQL 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/mysql">通过实践实验室学习 MySQL</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 MySQL 数据库管理。LabEx 提供全面的 MySQL 课程，涵盖基本的 SQL 操作、数据库管理、性能优化和高级查询技术。掌握世界上最流行的关系数据库系统之一。
</base-disclaimer-content>
</base-disclaimer>

## 数据库连接与管理

### 连接到服务器：`mysql -u username -p`

使用命令行连接到 MySQL 服务器。

```bash
# 使用用户名和密码提示符连接
mysql -u root -p
# 连接到特定数据库
mysql -u username -p database_name
# 连接到远程服务器
mysql -h hostname -u username -p
# 使用端口规范连接
mysql -h hostname -P 3306 -u username -p database_name
```

### 数据库操作：`CREATE` / `DROP` / `USE`

管理服务器上的数据库。

```sql
# 创建新数据库
CREATE DATABASE company_db;
# 列出所有数据库
SHOW DATABASES;
# 选择要使用的数据库
USE company_db;
# 删除数据库（永久删除）
DROP DATABASE old_database;
```

<BaseQuiz id="mysql-database-1" correct="C">
  <template #question>
    `USE database_name` 的作用是什么？
  </template>
  
  <BaseQuizOption value="A">创建一个新数据库</BaseQuizOption>
  <BaseQuizOption value="B">删除数据库</BaseQuizOption>
  <BaseQuizOption value="C" correct>选择数据库以供后续操作使用</BaseQuizOption>
  <BaseQuizOption value="D">显示数据库中的所有表</BaseQuizOption>
  
  <BaseQuizAnswer>
    `USE` 语句选择一个数据库，使其成为所有后续 SQL 语句的活动数据库。这等同于使用 `mysql -u user -p database_name` 连接时选择数据库。
  </BaseQuizAnswer>
</BaseQuiz>

### 导出数据：`mysqldump`

将数据库数据备份到 SQL 文件。

```bash
# 导出整个数据库
mysqldump -u username -p database_name > backup.sql
# 导出特定表
mysqldump -u username -p database_name table_name > table_backup.sql
# 仅导出结构
mysqldump -u username -p --no-data database_name > structure.sql
# 包含存储过程和触发器的完整数据库备份
mysqldump -u username -p --routines --triggers database_name > backup.sql
```

### 导入数据：`mysql < file.sql`

将 SQL 文件导入到 MySQL 数据库中。

```bash
# 将 SQL 文件导入到数据库
mysql -u username -p database_name < backup.sql
# 不指定数据库导入（如果文件内包含）
mysql -u username -p < full_backup.sql
```

### 用户管理：`CREATE USER` / `GRANT`

管理数据库用户和权限。

```sql
# 创建新用户
CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
# 授予所有权限
GRANT ALL PRIVILEGES ON database_name.* TO 'user'@'localhost';
# 授予特定权限
GRANT SELECT, INSERT, UPDATE ON table_name TO 'user'@'localhost';
# 应用权限更改
FLUSH PRIVILEGES;
```

### 显示服务器信息：`SHOW STATUS` / `SHOW VARIABLES`

显示服务器配置和状态。

```sql
# 显示服务器状态
SHOW STATUS;
# 显示配置变量
SHOW VARIABLES;
# 显示当前进程
SHOW PROCESSLIST;
```

## 表结构与模式

### 创建表：`CREATE TABLE`

使用指定的列和数据类型创建新表。

```sql
# 创建包含各种数据类型的表
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    age INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# 创建带外键的表
CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### 表信息：`DESCRIBE` / `SHOW`

查看表结构和数据库内容。

```sql
# 显示表结构
DESCRIBE users;
# 替代语法
SHOW COLUMNS FROM users;
# 列出所有表
SHOW TABLES;
# 显示表的 CREATE 语句
SHOW CREATE TABLE users;
```

### 修改表：`ALTER TABLE`

更改现有表结构，添加或删除列。

```sql
# 添加新列
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
# 删除列
ALTER TABLE users DROP COLUMN age;
# 修改列类型
ALTER TABLE users MODIFY COLUMN username VARCHAR(100);
# 重命名列
ALTER TABLE users CHANGE old_name new_name VARCHAR(50);
```

## 数据操作与 CRUD 操作

### 插入数据：`INSERT INTO`

向表中添加新记录。

```sql
# 插入单条记录
INSERT INTO users (username, email, age)
VALUES ('john_doe', 'john@email.com', 25);
# 插入多条记录
INSERT INTO users (username, email, age) VALUES
('alice', 'alice@email.com', 30),
('bob', 'bob@email.com', 28);
# 从另一个表插入
INSERT INTO users_backup SELECT * FROM users;
```

<BaseQuiz id="mysql-insert-1" correct="A">
  <template #question>
    插入单条记录的正确语法是什么？
  </template>
  
  <BaseQuizOption value="A" correct>`INSERT INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="B">`INSERT table_name VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="C">`ADD INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="D">`INSERT table_name (column1, column2) = (value1, value2);`</BaseQuizOption>
  
  <BaseQuizAnswer>
    正确的语法是 `INSERT INTO table_name (columns) VALUES (values)`。需要 `INTO` 关键字，并且必须同时指定列名和对应的值。
  </BaseQuizAnswer>
</BaseQuiz>

### 更新数据：`UPDATE`

修改表中的现有记录。

```sql
# 更新特定记录
UPDATE users SET age = 26 WHERE username = 'john_doe';
# 更新多列
UPDATE users SET age = 31, email = 'alice_new@email.com'
WHERE username = 'alice';
# 带计算的更新
UPDATE products SET price = price * 1.1 WHERE category = 'electronics';
```

### 删除数据：`DELETE` / `TRUNCATE`

从表中删除记录。

```sql
# 删除特定记录
DELETE FROM users WHERE age < 18;
# 删除所有记录（保留结构）
DELETE FROM users;
# 删除所有记录（更快，重置 AUTO_INCREMENT）
TRUNCATE TABLE users;
# 带 JOIN 的删除
DELETE u FROM users u
JOIN inactive_accounts i ON u.id = i.user_id;
```

### 替换数据：`REPLACE` / `INSERT ... ON DUPLICATE KEY`

处理插入期间的重复键情况。

```sql
# 替换现有记录或插入新记录
REPLACE INTO users (id, username, email)
VALUES (1, 'updated_user', 'new@email.com');
# 插入或在重复键时更新
INSERT INTO users (username, email)
VALUES ('john', 'john@email.com')
ON DUPLICATE KEY UPDATE email = VALUES(email);
```

## 数据查询与选择

### 基本 SELECT: `SELECT * FROM`

检索具有各种条件的数据。

```sql
# 选择所有列
SELECT * FROM users;
# 选择特定列
SELECT username, email FROM users;
# 带 WHERE 条件的选择
SELECT * FROM users WHERE age > 25;
# 带多条件的选择
SELECT * FROM users WHERE age > 20 AND email LIKE '%gmail.com';
```

<BaseQuiz id="mysql-select-1" correct="D">
  <template #question>
    `SELECT * FROM users` 返回什么？
  </template>
  
  <BaseQuizOption value="A">仅返回 users 表的第一行</BaseQuizOption>
  <BaseQuizOption value="B">仅返回 username 列</BaseQuizOption>
  <BaseQuizOption value="C">表结构</BaseQuizOption>
  <BaseQuizOption value="D" correct>users 表中的所有列和所有行</BaseQuizOption>
  
  <BaseQuizAnswer>
    `*` 通配符选择所有列，在没有 WHERE 子句的情况下，它返回所有行。这对于查看所有数据很有用，但在处理大表时应谨慎使用。
  </BaseQuizAnswer>
</BaseQuiz>

### 排序与限制：`ORDER BY` / `LIMIT`

控制返回结果的顺序和数量。

```sql
# 排序结果
SELECT * FROM users ORDER BY age DESC;
# 按多列排序
SELECT * FROM users ORDER BY age DESC, username ASC;
# 限制结果数量
SELECT * FROM users LIMIT 10;
# 分页（跳过前 10 条，取接下来的 10 条）
SELECT * FROM users LIMIT 10 OFFSET 10;
```

### 筛选：`WHERE` / `LIKE` / `IN`

使用各种比较运算符过滤数据。

```sql
# 模式匹配
SELECT * FROM users WHERE username LIKE 'john%';
# 多个值
SELECT * FROM users WHERE age IN (25, 30, 35);
# 范围过滤
SELECT * FROM users WHERE age BETWEEN 20 AND 30;
# NULL 检查
SELECT * FROM users WHERE email IS NOT NULL;
```

### 分组：`GROUP BY` / `HAVING`

对数据进行分组并应用聚合函数。

```sql
# 按列分组
SELECT age, COUNT(*) FROM users GROUP BY age;
# 带分组条件的
SELECT age, COUNT(*) as count FROM users
GROUP BY age HAVING count > 1;
# 多分组列
SELECT age, gender, COUNT(*) FROM users
GROUP BY age, gender;
```

## 高级查询

### JOIN 操作：`INNER` / `LEFT` / `RIGHT`

合并来自多个表的数据。

```sql
# 内连接（仅匹配的记录）
SELECT u.username, o.order_date
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# 左连接（所有用户，匹配的订单）
SELECT u.username, o.order_date
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# 多连接
SELECT u.username, o.order_date, p.product_name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

<BaseQuiz id="mysql-join-1" correct="B">
  <template #question>
    INNER JOIN 和 LEFT JOIN 有什么区别？
  </template>
  
  <BaseQuizOption value="A">没有区别</BaseQuizOption>
  <BaseQuizOption value="B" correct>INNER JOIN 只返回匹配的行，LEFT JOIN 返回左表中的所有行</BaseQuizOption>
  <BaseQuizOption value="C">INNER JOIN 速度更快</BaseQuizOption>
  <BaseQuizOption value="D">LEFT JOIN 只适用于两个表</BaseQuizOption>
  
  <BaseQuizAnswer>
    INNER JOIN 只返回两个表中都有匹配的行。LEFT JOIN 返回左表中的所有行以及右表中匹配的行，对于不匹配的右表行则显示 NULL 值。
  </BaseQuizAnswer>
</BaseQuiz>

### 子查询：`SELECT` within `SELECT`

使用嵌套查询来检索复杂数据。

```sql
# WHERE 子查询
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders WHERE total > 100);
# 相关子查询
SELECT username FROM users u1
WHERE age > (SELECT AVG(age) FROM users u2);
# SELECT 子查询
SELECT username,
(SELECT COUNT(*) FROM orders WHERE user_id = users.id) as order_count
FROM users;
```

### 聚合函数：`COUNT` / `SUM` / `AVG`

从数据中计算统计信息和摘要。

```sql
# 基本聚合
SELECT COUNT(*) FROM users;
SELECT AVG(age), MIN(age), MAX(age) FROM users;
SELECT SUM(total) FROM orders;
# 带分组的聚合
SELECT department, AVG(salary)
FROM employees GROUP BY department;
# 多重聚合
SELECT
    COUNT(*) as total_users,
    AVG(age) as avg_age,
    MAX(created_at) as latest_signup
FROM users;
```

### 窗口函数：`OVER` / `PARTITION BY`

在行集上执行计算。

```sql
# 排名函数
SELECT username, age,
RANK() OVER (ORDER BY age DESC) as age_rank
FROM users;
# 按组分区
SELECT username, department, salary,
AVG(salary) OVER (PARTITION BY department) as dept_avg
FROM employees;
# 运行总计
SELECT order_date, total,
SUM(total) OVER (ORDER BY order_date) as running_total
FROM orders;
```

## 索引与性能

### 创建索引：`CREATE INDEX`

使用数据库索引提高查询性能。

```sql
# 创建普通索引
CREATE INDEX idx_username ON users(username);
# 创建复合索引
CREATE INDEX idx_user_age ON users(username, age);
# 创建唯一索引
CREATE UNIQUE INDEX idx_email ON users(email);
# 显示表上的索引
SHOW INDEXES FROM users;
```

### 查询分析：`EXPLAIN`

分析查询执行计划和性能。

```sql
# 显示查询执行计划
EXPLAIN SELECT * FROM users WHERE age > 25;
# 详细分析
EXPLAIN FORMAT=JSON SELECT u.*, o.total
FROM users u JOIN orders o ON u.id = o.user_id;
# 显示查询性能
SHOW PROFILES;
SET profiling = 1;
```

### 优化查询：最佳实践

编写高效 SQL 查询的技术。

```sql
# 使用特定列而不是 *
SELECT username, email FROM users WHERE id = 1;
# 对大数据集使用 LIMIT
SELECT * FROM logs ORDER BY created_at DESC LIMIT 1000;
# 使用正确的 WHERE 条件
SELECT * FROM orders WHERE user_id = 123 AND status = 'pending';
-- 尽可能使用覆盖索引
```

### 表维护：`OPTIMIZE` / `ANALYZE`

维护表性能和统计信息。

```sql
# 优化表存储
OPTIMIZE TABLE users;
# 更新表统计信息
ANALYZE TABLE users;
# 检查表完整性
CHECK TABLE users;
# 需要时修复表
REPAIR TABLE users;
```

## 数据导入/导出

### 加载数据：`LOAD DATA INFILE`

从 CSV 和文本文件导入数据。

```sql
# 加载 CSV 文件
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
# 加载特定列
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users (username, email, age);
```

### 导出数据：`SELECT INTO OUTFILE`

将查询结果导出到文件。

```sql
# 导出到 CSV 文件
SELECT username, email, age
FROM users
INTO OUTFILE '/path/to/export.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

### 备份与恢复：`mysqldump` / `mysql`

创建和恢复数据库备份。

```bash
# 备份特定表
mysqldump -u username -p database_name table1 table2 > tables_backup.sql
# 从备份恢复
mysql -u username -p database_name < backup.sql
# 从远程服务器导出
mysqldump -h remote_host -u username -p database_name > remote_backup.sql
# 导入到本地数据库
mysql -u local_user -p local_database < remote_backup.sql
# 服务器之间直接复制数据
mysqldump -h source_host -u user -p db_name | mysql -h dest_host -u user -p db_name
```

## 数据类型与函数

### 常见数据类型：数字、文本、日期

为列选择适当的数据类型。

```sql
# 数值类型
INT, BIGINT, DECIMAL(10,2), FLOAT, DOUBLE
# 字符串类型
VARCHAR(255), TEXT, CHAR(10), MEDIUMTEXT, LONGTEXT
# 日期和时间类型
DATE, TIME, DATETIME, TIMESTAMP, YEAR
# 布尔和二进制
BOOLEAN, BLOB, VARBINARY

# 示例表创建
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 字符串函数：`CONCAT` / `SUBSTRING` / `LENGTH`

使用内置字符串函数操作文本数据。

```sql
# 字符串连接
SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users;
# 字符串操作
SELECT SUBSTRING(email, 1, LOCATE('@', email)-1) as username FROM users;
SELECT LENGTH(username), UPPER(username) FROM users;
# 模式匹配和替换
SELECT REPLACE(phone, '-', '.') FROM users WHERE phone LIKE '___-___-____';
```

### 日期函数：`NOW()` / `DATE_ADD` / `DATEDIFF`

有效地处理日期和时间。

```sql
# 当前日期和时间
SELECT NOW(), CURDATE(), CURTIME();
# 日期算术
SELECT DATE_ADD(created_at, INTERVAL 30 DAY) as expiry_date FROM users;
SELECT DATEDIFF(NOW(), created_at) as days_since_signup FROM users;
# 日期格式化
SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') as formatted_date FROM orders;
```

### 数值函数：`ROUND` / `ABS` / `RAND`

对数值数据执行数学运算。

```sql
# 数学函数
SELECT ROUND(price, 2), ABS(profit_loss), SQRT(area) FROM products;
# 随机和统计
SELECT RAND(), FLOOR(price), CEIL(rating) FROM products;
# 数值聚合
SELECT AVG(price), STDDEV(price), VARIANCE(price) FROM products;
```

## 事务管理

### 事务控制：`BEGIN` / `COMMIT` / `ROLLBACK`

管理数据库事务以确保数据一致性。

```sql
# 开始事务
BEGIN;
# 或
START TRANSACTION;
# 执行操作
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;
# 提交更改
COMMIT;
# 或发生错误时回滚
ROLLBACK;
```

### 事务隔离级别：`SET TRANSACTION ISOLATION`

控制事务之间如何相互作用。

```sql
# 设置隔离级别
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
# 显示当前隔离级别
SELECT @@transaction_isolation;
```

### 锁定：`LOCK TABLES` / `SELECT FOR UPDATE`

控制对数据的并发访问。

```sql
# 锁定表以进行独占访问
LOCK TABLES users WRITE, orders READ;
# 执行操作
# ...
UNLOCK TABLES;
# 事务中的行级锁定
BEGIN;
SELECT * FROM accounts WHERE id = 1 FOR UPDATE;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
COMMIT;
```

### 保存点：`SAVEPOINT` / `ROLLBACK TO`

在事务内部创建回滚点。

```sql
BEGIN;
INSERT INTO users (username) VALUES ('user1');
SAVEPOINT sp1;
INSERT INTO users (username) VALUES ('user2');
SAVEPOINT sp2;
INSERT INTO users (username) VALUES ('user3');
# 回滚到保存点
ROLLBACK TO sp1;
COMMIT;
```

## 高级 SQL 技术

### 公用表表达式 (CTEs): `WITH`

创建临时结果集以用于复杂查询。

```sql
# 简单 CTE
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

### 存储过程：`CREATE PROCEDURE`

创建可重用的数据库过程。

```sql
# 创建存储过程
DELIMITER //
CREATE PROCEDURE GetUserOrders(IN user_id INT)
BEGIN
    SELECT o.*, p.product_name
    FROM orders o
    JOIN products p ON o.product_id = p.id
    WHERE o.user_id = user_id;
END //
DELIMITER ;
# 调用过程
CALL GetUserOrders(123);
```

### 触发器：`CREATE TRIGGER`

对数据库事件做出响应自动执行代码。

```sql
# 创建触发器以进行审计日志记录
CREATE TRIGGER user_update_audit
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    INSERT INTO user_audit (user_id, old_email, new_email, changed_at)
    VALUES (NEW.id, OLD.email, NEW.email, NOW());
END;
# 显示触发器
SHOW TRIGGERS;
```

### 视图：`CREATE VIEW`

基于查询结果创建虚拟表。

```sql
# 创建视图
CREATE VIEW active_users AS
SELECT id, username, email, created_at
FROM users
WHERE status = 'active' AND last_login > DATE_SUB(NOW(), INTERVAL 30 DAY);
# 像表一样使用视图
SELECT * FROM active_users WHERE username LIKE 'john%';
# 删除视图
DROP VIEW active_users;
```

## MySQL 安装与设置

### 安装：包管理器

使用系统包管理器安装 MySQL。

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# CentOS/RHEL
sudo yum install mysql-server
# macOS with Homebrew
brew install mysql
# 启动 MySQL 服务
sudo systemctl start mysql
```

### Docker: `docker run mysql`

在 Docker 容器中运行 MySQL 以进行开发。

```bash
# 运行 MySQL 容器
docker run --name mysql-dev -e MYSQL_ROOT_PASSWORD=password -p 3306:3306 -d mysql:8.0
# 连接到容器化的 MySQL
docker exec -it mysql-dev mysql -u root -p
# 在容器中创建数据库
docker exec -it mysql-dev mysql -u root -p -e "CREATE DATABASE testdb;"
```

### 初始设置与安全

保护您的 MySQL 安装并验证设置。

```bash
# 运行安全脚本
sudo mysql_secure_installation
# 连接到 MySQL
mysql -u root -p
# 显示 MySQL 版本
SELECT VERSION();
# 检查连接状态
STATUS;
# 设置 root 密码
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
```

## 配置与设置

### 配置文件：`my.cnf`

修改 MySQL 服务器配置设置。

```ini
# 常见配置文件位置
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

### 运行时配置：`SET GLOBAL`

在 MySQL 运行时更改设置。

```bash
# 设置全局变量
SET GLOBAL max_connections = 500;
SET GLOBAL slow_query_log = ON;
# 显示当前设置
SHOW VARIABLES LIKE 'max_connections';
SHOW GLOBAL STATUS LIKE 'Slow_queries';
```

### 性能调优：内存与缓存

优化 MySQL 性能设置。

```sql
# 显示内存使用情况
SHOW VARIABLES LIKE '%buffer_pool_size%';
SHOW VARIABLES LIKE '%query_cache%';
# 监控性能
SHOW STATUS LIKE 'Qcache%';
SHOW STATUS LIKE 'Created_tmp%';
# InnoDB 设置
SET GLOBAL innodb_buffer_pool_size = 2147483648; -- 2GB
```

### 日志配置：错误与查询日志

配置 MySQL 日志以进行监控和调试。

```sql
# 启用查询日志
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/query.log';
# 慢查询日志
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
# 显示日志设置
SHOW VARIABLES LIKE '%log%';
```

## 相关链接

- <router-link to="/database">数据库速查表</router-link>
- <router-link to="/postgresql">PostgreSQL 速查表</router-link>
- <router-link to="/sqlite">SQLite 速查表</router-link>
- <router-link to="/mongodb">MongoDB 速查表</router-link>
- <router-link to="/redis">Redis 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>

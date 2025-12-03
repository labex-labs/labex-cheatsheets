---
title: '数据库速查表 | LabEx'
description: '使用本综合速查表学习数据库管理。快速参考 SQL 查询、数据库设计、规范化、索引、事务和关系数据库管理。'
pdfUrl: '/cheatsheets/pdf/database-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
数据库速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/database">通过实践实验室学习数据库</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习数据库管理和 SQL。LabEx 提供全面的数据库课程，涵盖基本的 SQL 命令、数据操作、查询优化、数据库设计和管理。掌握关系数据库、NoSQL 系统和数据库安全最佳实践。
</base-disclaimer-content>
</base-disclaimer>

## 数据库创建与管理

### 创建数据库：`CREATE DATABASE`

创建一个新的数据库用于存储数据。

```sql
-- 创建一个新的数据库
CREATE DATABASE company_db;
-- 创建带字符集的数据库
CREATE DATABASE company_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
-- 使用数据库
USE company_db;
```

<BaseQuiz id="database-create-1" correct="A">
  <template #question>
    <code>CREATE DATABASE company_db</code> 的作用是什么？
  </template>
  
  <BaseQuizOption value="A" correct>创建一个名为 company_db 的新的空数据库</BaseQuizOption>
  <BaseQuizOption value="B">在数据库中创建一个表</BaseQuizOption>
  <BaseQuizOption value="C">删除数据库</BaseQuizOption>
  <BaseQuizOption value="D">备份数据库</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>CREATE DATABASE</code> 创建一个新的空数据库。创建后，您需要使用 <code>USE</code> 来选择它，然后才能在其中创建表。
  </BaseQuizAnswer>
</BaseQuiz>

### 显示数据库：`SHOW DATABASES`

列出服务器上所有可用的数据库。

```sql
-- 列出所有数据库
SHOW DATABASES;
-- 显示数据库信息
SELECT SCHEMA_NAME FROM
INFORMATION_SCHEMA.SCHEMATA;
-- 显示当前数据库
SELECT DATABASE();
```

### 删除数据库：`DROP DATABASE`

永久删除整个数据库。

```sql
-- 删除数据库（请谨慎操作！）
DROP DATABASE old_company_db;
-- 如果存在则删除数据库
DROP DATABASE IF EXISTS old_company_db;
```

### 备份数据库：`mysqldump`

创建数据库的备份副本。

```sql
-- 命令行备份
mysqldump -u username -p database_name > backup.sql
-- 从备份恢复
mysql -u username -p database_name < backup.sql
```

### 数据库用户：`CREATE USER`

管理数据库用户账户和权限。

```sql
-- 创建新用户
CREATE USER 'newuser'@'localhost' IDENTIFIED BY
'password';
-- 授予权限
GRANT SELECT, INSERT ON company_db.* TO
'newuser'@'localhost';
-- 显示用户权限
SHOW GRANTS FOR 'newuser'@'localhost';
```

### 数据库信息：`INFORMATION_SCHEMA`

查询数据库元数据和结构信息。

```sql
-- 显示所有表
SELECT TABLE_NAME FROM
INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'company_db';
-- 显示表结构
DESCRIBE employees;
```

## 表结构与信息

### 创建表：`CREATE TABLE`

定义带有列和数据类型的表。

```sql
-- 基本表创建
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY
KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE,
    salary DECIMAL(10,2),
    hire_date DATE,
    department VARCHAR(50)
);
-- 显示表结构
DESCRIBE employees;
SHOW COLUMNS FROM employees;
```

### 修改表：`ALTER TABLE`

修改现有表的结构和列。

```sql
-- 添加新列
ALTER TABLE employees ADD
COLUMN phone VARCHAR(15);
-- 修改列类型
ALTER TABLE employees MODIFY
COLUMN salary DECIMAL(12,2);
-- 删除列
ALTER TABLE employees DROP
COLUMN phone;
-- 重命名表
RENAME TABLE employees TO staff;
```

<BaseQuiz id="database-alter-1" correct="C">
  <template #question>
    <code>ALTER TABLE employees ADD COLUMN phone VARCHAR(15)</code> 的作用是什么？
  </template>
  
  <BaseQuizOption value="A">删除 phone 列</BaseQuizOption>
  <BaseQuizOption value="B">修改 phone 列</BaseQuizOption>
  <BaseQuizOption value="C" correct>向 employees 表中添加一个名为 phone 的新列</BaseQuizOption>
  <BaseQuizOption value="D">重命名表</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>ALTER TABLE ... ADD COLUMN</code> 向现有表中添加一个新列。对于现有行，新列将添加并默认为 NULL，除非您指定了默认值。
  </BaseQuizAnswer>
</BaseQuiz>

### 表信息：`SHOW`

获取有关表及其属性的详细信息。

```sql
-- 显示所有表
SHOW TABLES;
-- 显示表结构
SHOW CREATE TABLE employees;
-- 显示表状态
SHOW TABLE STATUS LIKE
'employees';
-- 计算表中的行数
SELECT COUNT(*) FROM employees;
```

## 数据操作与 CRUD 操作

### 插入数据：`INSERT INTO`

向表中添加新记录。

```sql
-- 插入单条记录
INSERT INTO employees (name, email, salary, hire_date,
department)
VALUES ('John Doe', 'john@company.com', 75000.00,
'2024-01-15', 'Engineering');
-- 插入多条记录
INSERT INTO employees (name, email, salary,
department) VALUES
('Jane Smith', 'jane@company.com', 80000.00,
'Marketing'),
('Bob Johnson', 'bob@company.com', 65000.00, 'Sales');
-- 从另一个表插入
INSERT INTO backup_employees
SELECT * FROM employees WHERE department =
'Engineering';
```

### 更新数据：`UPDATE`

修改表中的现有记录。

```sql
-- 更新单条记录
UPDATE employees
SET salary = 85000.00, department = 'Senior Engineering'
WHERE id = 1;
-- 更新多条记录
UPDATE employees
SET salary = salary * 1.05
WHERE hire_date < '2024-01-01';
-- 带 JOIN 的更新
UPDATE employees e
JOIN departments d ON e.department = d.name
SET e.salary = e.salary + d.bonus;
```

### 删除数据：`DELETE FROM`

从表中删除记录。

```sql
-- 删除特定记录
DELETE FROM employees
WHERE department = 'Temporary';
-- 带条件的删除
DELETE FROM employees
WHERE hire_date < '2020-01-01' AND salary < 50000;
-- 清空表（删除所有记录更快）
TRUNCATE TABLE temp_employees;
```

### 替换数据：`REPLACE INTO`

根据主键插入或更新记录。

```sql
-- 替换记录（插入或更新）
REPLACE INTO employees (id, name, email, salary)
VALUES (1, 'John Doe Updated',
'john.new@company.com', 90000);
-- 存在则更新
INSERT INTO employees (id, name, salary)
VALUES (1, 'John Doe', 85000)
ON DUPLICATE KEY UPDATE salary = VALUES(salary);
```

## 数据查询与选择

### 基本 SELECT: `SELECT`

从数据库表中检索数据。

```sql
-- 选择所有列
SELECT * FROM employees;
-- 选择特定列
SELECT name, email, salary FROM employees;
-- 带别名的选择
SELECT name AS employee_name, salary AS
annual_salary
FROM employees;
-- 选择唯一值
SELECT DISTINCT department FROM employees;
```

### 过滤数据：`WHERE`

应用条件来过滤查询结果。

```sql
-- 基本条件
SELECT * FROM employees WHERE salary > 70000;
-- 多条件
SELECT * FROM employees
WHERE department = 'Engineering' AND salary > 75000;
-- 模式匹配
SELECT * FROM employees WHERE name LIKE 'John%';
```

<BaseQuiz id="database-where-1" correct="C">
  <template #question>
    在 WHERE 子句中，<code>LIKE 'John%'</code> 匹配什么？
  </template>
  
  <BaseQuizOption value="A">仅精确匹配 "John"</BaseQuizOption>
  <BaseQuizOption value="B">以 "John" 结尾的值</BaseQuizOption>
  <BaseQuizOption value="C" correct>以 "John" 开头的值</BaseQuizOption>
  <BaseQuizOption value="D">包含 "John" 任意位置的值</BaseQuizOption>
  
  <BaseQuizAnswer>
    SQL 中的 <code>%</code> 通配符匹配任意字符序列。<code>LIKE 'John%'</code> 匹配任何以 "John" 开头的值，例如 "John"、"Johnny"、"Johnson" 等。
  </BaseQuizAnswer>
</BaseQuiz>

```sql
-- 范围查询
SELECT * FROM employees
WHERE hire_date BETWEEN '2023-01-01' AND '2023-12-
31';
```

### 排序数据：`ORDER BY`

按升序或降序对查询结果进行排序。

```sql
-- 按单列排序
SELECT * FROM employees ORDER BY salary DESC;
-- 按多列排序
SELECT * FROM employees
ORDER BY department ASC, salary DESC;
-- 带 LIMIT 的排序
SELECT * FROM employees
ORDER BY hire_date DESC LIMIT 10;
```

### 限制结果：`LIMIT`

控制返回的记录数量。

```sql
-- 限制结果数量
SELECT * FROM employees LIMIT 5;
-- 带 OFFSET 的分页
SELECT * FROM employees
ORDER BY id LIMIT 10 OFFSET 20;
-- 前 N 个结果
SELECT * FROM employees
ORDER BY salary DESC LIMIT 5;
```

## 高级查询

### 聚合函数：`COUNT`, `SUM`, `AVG`

对数据组执行计算。

```sql
-- 计数记录
SELECT COUNT(*) FROM employees;
-- 求和与平均值
SELECT SUM(salary) as total_payroll, AVG(salary) as
avg_salary
FROM employees;
-- 组统计
SELECT department, COUNT(*) as employee_count,
AVG(salary) as avg_salary
FROM employees GROUP BY department;
-- 用于组过滤的 HAVING 子句
SELECT department, COUNT(*) as count
FROM employees
GROUP BY department
HAVING COUNT(*) > 5;
```

### 子查询：嵌套查询

在其他查询中使用查询来进行复杂操作。

```sql
-- 在 WHERE 子句中的子查询
SELECT * FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);
-- 带 IN 的子查询
SELECT * FROM employees
WHERE department IN (
    SELECT name FROM departments WHERE budget >
100000
);
-- 关联子查询
SELECT * FROM employees e1
WHERE salary > (
    SELECT AVG(salary) FROM employees e2
    WHERE e2.department = e1.department
);
```

### 表连接：`JOIN`

合并来自多个表的数据。

```sql
-- 内连接
SELECT e.name, e.salary, d.department_name
FROM employees e
INNER JOIN departments d ON e.department = d.id;
-- 左连接
SELECT e.name, d.department_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id;
-- 多重连接
SELECT e.name, d.department_name, p.project_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id
LEFT JOIN projects p ON e.id = p.employee_id;
```

### 窗口函数：高级分析

跨相关行执行计算。

```sql
-- 行编号
SELECT name, salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
FROM employees;
-- 运行总计
SELECT name, salary,
    SUM(salary) OVER (ORDER BY hire_date) as
running_total
FROM employees;
-- 按组分区
SELECT name, department, salary,
    AVG(salary) OVER (PARTITION BY department) as
dept_avg
FROM employees;
```

## 数据库约束与完整性

### 主键：`PRIMARY KEY`

确保每条记录的唯一标识。

```sql
-- 单列主键
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100)
);
-- 复合主键
CREATE TABLE order_items (
    order_id INT,
    product_id INT,
    quantity INT,
    PRIMARY KEY (order_id, product_id)
);
```

### 外键：`FOREIGN KEY`

维护表之间的引用完整性。

```sql
-- 添加外键约束
CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);
-- 向现有表添加外键
ALTER TABLE employees
ADD CONSTRAINT fk_department
FOREIGN KEY (department_id) REFERENCES
departments(id);
```

### 唯一约束：`UNIQUE`

防止列中出现重复值。

```sql
-- 单列唯一约束
ALTER TABLE employees
ADD CONSTRAINT unique_email UNIQUE (email);
-- 复合唯一约束
ALTER TABLE employees
ADD CONSTRAINT unique_name_dept UNIQUE (name,
department);
```

### 检查约束：`CHECK`

强制执行业务规则和数据验证。

```sql
-- 简单检查约束
ALTER TABLE employees
ADD CONSTRAINT check_salary CHECK (salary > 0);
-- 复杂检查约束
ALTER TABLE employees
ADD CONSTRAINT check_age
CHECK (YEAR(CURDATE()) - YEAR(birth_date) >= 18);
```

## 数据库性能与优化

### 索引：`CREATE INDEX`

通过数据库索引加速数据检索。

```sql
-- 在单列上创建索引
CREATE INDEX idx_employee_name ON
employees(name);
-- 复合索引
CREATE INDEX idx_dept_salary ON
employees(department, salary);
-- 唯一索引
CREATE UNIQUE INDEX idx_employee_email ON
employees(email);
-- 显示表索引
SHOW INDEX FROM employees;
```

### 查询优化：`EXPLAIN`

分析和优化查询性能。

```sql
-- 分析查询执行计划
EXPLAIN SELECT * FROM employees WHERE salary >
75000;
-- 详细分析
EXPLAIN ANALYZE SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department = d.id;
```

### 性能监控

监控数据库活动和识别瓶颈。

```sql
-- 显示正在运行的进程
SHOW PROCESSLIST;
-- 显示数据库状态
SHOW STATUS LIKE 'Slow_queries';
-- 查询缓存信息
SHOW STATUS LIKE 'Qcache%';
```

### 数据库维护

定期的数据库维护任务以实现最佳性能。

```sql
-- 表优化
OPTIMIZE TABLE employees;
-- 分析表统计信息
ANALYZE TABLE employees;
-- 检查表完整性
CHECK TABLE employees;
-- 需要时修复表
REPAIR TABLE employees;
```

## 数据导入/导出

### 导入数据：`LOAD DATA`

将外部文件中的数据导入数据库表。

```sql
-- 从 CSV 文件导入
LOAD DATA INFILE 'employees.csv'
INTO TABLE employees
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
-- 带列映射的导入
LOAD DATA INFILE 'data.csv'
INTO TABLE employees (name, email, salary);
```

### 导出数据：`SELECT INTO`

将查询结果导出到外部文件。

```sql
-- 导出到 CSV 文件
SELECT name, email, salary
INTO OUTFILE 'employee_export.csv'
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
FROM employees;
-- 使用 mysqldump 导出
mysqldump -u username -p --tab=/path/to/export
database_name table_name
```

### 数据迁移：数据库之间

在不同数据库系统之间移动数据。

```sql
-- 从现有结构创建表
CREATE TABLE employees_backup LIKE employees;
-- 复制数据到表之间
INSERT INTO employees_backup SELECT * FROM
employees;
-- 带条件的迁移
INSERT INTO new_employees
SELECT * FROM old_employees WHERE active = 1;
```

### 批量操作

高效处理大规模数据操作。

```sql
-- 使用 INSERT IGNORE 进行批量插入
INSERT IGNORE INTO employees (name, email) VALUES
('John Doe', 'john@email.com'),
('Jane Smith', 'jane@email.com');
-- 批量更新
UPDATE employees SET salary = salary * 1.1 WHERE
department = 'Sales';
```

## 数据库安全与访问控制

### 用户管理：`CREATE USER`

创建和管理数据库用户账户。

```sql
-- 创建带密码的用户
CREATE USER 'app_user'@'localhost' IDENTIFIED BY
'secure_password';
-- 为特定主机创建用户
CREATE USER 'remote_user'@'192.168.1.%' IDENTIFIED
BY 'password';
-- 删除用户
DROP USER 'old_user'@'localhost';
```

### 权限：`GRANT` & `REVOKE`

控制对数据库对象和操作的访问。

```sql
-- 授予特定权限
GRANT SELECT, INSERT ON company_db.employees TO
'app_user'@'localhost';
-- 授予所有权限
GRANT ALL PRIVILEGES ON company_db.* TO
'admin_user'@'localhost';
-- 撤销权限
REVOKE INSERT ON company_db.employees FROM
'app_user'@'localhost';
-- 显示用户授权
SHOW GRANTS FOR 'app_user'@'localhost';
```

### 数据库角色

使用数据库角色组织权限。

```sql
-- 创建角色 (MySQL 8.0+)
CREATE ROLE 'app_read_role', 'app_write_role';
-- 授予角色权限
GRANT SELECT ON company_db.* TO 'app_read_role';
GRANT INSERT, UPDATE, DELETE ON company_db.* TO
'app_write_role';
-- 将角色分配给用户
GRANT 'app_read_role' TO 'readonly_user'@'localhost';
```

### SQL 注入预防

防范常见的安全漏洞。

```sql
-- 使用预处理语句（应用程序级别）
-- 错误：SELECT * FROM users WHERE id = ' + userInput
-- 正确：使用参数化查询
-- 验证输入数据类型
-- 尽可能使用存储过程
-- 遵循最小权限原则
```

## 数据库安装与设置

### MySQL 安装

流行的开源关系型数据库。

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# 启动 MySQL 服务
sudo systemctl start mysql
sudo systemctl enable mysql
# 安全安装
sudo mysql_secure_installation
```

### PostgreSQL 安装

先进的开源关系型数据库。

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql
postgresql-contrib
# 切换到 postgres 用户
sudo -u postgres psql
# 创建数据库和用户
CREATE DATABASE myapp;
CREATE USER myuser WITH
PASSWORD 'mypassword';
```

### SQLite 设置

轻量级基于文件的数据库。

```bash
# 安装 SQLite
sudo apt install sqlite3
# 创建数据库文件
sqlite3 mydatabase.db
# 基本 SQLite 命令
.help
.tables
.schema tablename
.quit
```

## 数据库配置与调优

### MySQL 配置

关键的 MySQL 配置参数。

```sql
-- my.cnf 配置文件
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
-- 显示当前设置
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW STATUS LIKE 'Connections';
```

### 连接管理

管理数据库连接和连接池。

```sql
-- 显示当前连接
SHOW PROCESSLIST;
-- 终止特定连接
KILL CONNECTION 123;
-- 连接超时设置
SET SESSION wait_timeout = 600;
SET SESSION interactive_timeout = 600;
```

### 备份配置

设置自动化数据库备份。

```bash
# 自动化备份脚本
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mysqldump -u backup_user -p mydatabase >
backup_$DATE.sql
# 使用 cron 调度
0 2 * * * /path/to/backup_script.sh
```

### 监控与日志

监控数据库活动和性能。

```sql
-- 启用即时恢复设置
SET GLOBAL log_bin = ON;
-- 启用慢查询日志
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
-- 显示数据库大小
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

## SQL 最佳实践

### 查询编写最佳实践

编写清晰、高效且易读的 SQL 查询。

```sql
-- 使用有意义的表别名
SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.dept_id = d.id;
-- 指定列名而不是 SELECT *
SELECT name, email, salary FROM employees;
-- 使用适当的数据类型
CREATE TABLE products (
    id INT PRIMARY KEY,
    price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP
);
```

### 性能优化技巧

优化查询以获得更好的数据库性能。

```sql
-- 在经常查询的列上使用索引
CREATE INDEX idx_employee_dept ON
employees(department);
-- 尽可能限制结果集
SELECT name FROM employees WHERE active = 1 LIMIT
100;
-- 在子查询中使用 EXISTS 代替 IN
SELECT * FROM customers c
WHERE EXISTS (SELECT 1 FROM orders o WHERE
o.customer_id = c.id);
```

## 相关链接

- <router-link to="/mysql">MySQL 速查表</router-link>
- <router-link to="/postgresql">PostgreSQL 速查表</router-link>
- <router-link to="/sqlite">SQLite 速查表</router-link>
- <router-link to="/mongodb">MongoDB 速查表</router-link>
- <router-link to="/redis">Redis 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>

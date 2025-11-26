---
title: 'Database Cheatsheet'
description: 'Learn Database with our comprehensive cheatsheet covering essential commands, concepts, and best practices.'
pdfUrl: '/cheatsheets/pdf/database-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Database Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/database">Learn Database with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn database management and SQL through hands-on labs and real-world scenarios. LabEx provides comprehensive database courses covering essential SQL commands, data manipulation, query optimization, database design, and administration. Master relational databases, NoSQL systems, and database security best practices.
</base-disclaimer-content>
</base-disclaimer>

## Database Creation & Management

### Create Database: `CREATE DATABASE`

Create a new database for storing your data.

```sql
-- Create a new database
CREATE DATABASE company_db;
-- Create database with character set
CREATE DATABASE company_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
-- Use the database
USE company_db;
```

### Show Databases: `SHOW DATABASES`

List all available databases on the server.

```sql
-- List all databases
SHOW DATABASES;
-- Show database information
SELECT SCHEMA_NAME FROM
INFORMATION_SCHEMA.SCHEMATA;
-- Show current database
SELECT DATABASE();
```

### Drop Database: `DROP DATABASE`

Delete an entire database permanently.

```sql
-- Drop database (be careful!)
DROP DATABASE old_company_db;
-- Drop database if it exists
DROP DATABASE IF EXISTS old_company_db;
```

### Backup Database: `mysqldump`

Create backup copies of your database.

```sql
-- Command line backup
mysqldump -u username -p database_name > backup.sql
-- Restore from backup
mysql -u username -p database_name < backup.sql
```

### Database Users: `CREATE USER`

Manage database user accounts and permissions.

```sql
-- Create new user
CREATE USER 'newuser'@'localhost' IDENTIFIED BY
'password';
-- Grant privileges
GRANT SELECT, INSERT ON company_db.* TO
'newuser'@'localhost';
-- Show user privileges
SHOW GRANTS FOR 'newuser'@'localhost';
```

### Database Information: `INFORMATION_SCHEMA`

Query database metadata and structure information.

```sql
-- Show all tables
SELECT TABLE_NAME FROM
INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'company_db';
-- Show table columns
DESCRIBE employees;
```

## Table Structure & Info

### Create Table: `CREATE TABLE`

Define new tables with columns and data types.

```sql
-- Basic table creation
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY
KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE,
    salary DECIMAL(10,2),
    hire_date DATE,
    department VARCHAR(50)
);
-- Show table structure
DESCRIBE employees;
SHOW COLUMNS FROM employees;
```

### Alter Table: `ALTER TABLE`

Modify existing table structure and columns.

```sql
-- Add new column
ALTER TABLE employees ADD
COLUMN phone VARCHAR(15);
-- Modify column type
ALTER TABLE employees MODIFY
COLUMN salary DECIMAL(12,2);
-- Drop column
ALTER TABLE employees DROP
COLUMN phone;
-- Rename table
RENAME TABLE employees TO staff;
```

### Table Information: `SHOW`

Get detailed information about tables and their properties.

```sql
-- Show all tables
SHOW TABLES;
-- Show table structure
SHOW CREATE TABLE employees;
-- Show table status
SHOW TABLE STATUS LIKE
'employees';
-- Count rows in table
SELECT COUNT(*) FROM employees;
```

## Data Manipulation & CRUD Operations

### Insert Data: `INSERT INTO`

Add new records to your tables.

```sql
-- Insert single record
INSERT INTO employees (name, email, salary, hire_date,
department)
VALUES ('John Doe', 'john@company.com', 75000.00,
'2024-01-15', 'Engineering');
-- Insert multiple records
INSERT INTO employees (name, email, salary,
department) VALUES
('Jane Smith', 'jane@company.com', 80000.00,
'Marketing'),
('Bob Johnson', 'bob@company.com', 65000.00, 'Sales');
-- Insert from another table
INSERT INTO backup_employees
SELECT * FROM employees WHERE department =
'Engineering';
```

### Update Data: `UPDATE`

Modify existing records in tables.

```sql
-- Update single record
UPDATE employees
SET salary = 85000.00, department = 'Senior Engineering'
WHERE id = 1;
-- Update multiple records
UPDATE employees
SET salary = salary * 1.05
WHERE hire_date < '2024-01-01';
-- Update with JOIN
UPDATE employees e
JOIN departments d ON e.department = d.name
SET e.salary = e.salary + d.bonus;
```

### Delete Data: `DELETE FROM`

Remove records from tables.

```sql
-- Delete specific records
DELETE FROM employees
WHERE department = 'Temporary';
-- Delete with conditions
DELETE FROM employees
WHERE hire_date < '2020-01-01' AND salary < 50000;
-- Truncate table (faster for all records)
TRUNCATE TABLE temp_employees;
```

### Replace Data: `REPLACE INTO`

Insert or update records based on primary key.

```sql
-- Replace record (insert or update)
REPLACE INTO employees (id, name, email, salary)
VALUES (1, 'John Doe Updated',
'john.new@company.com', 90000);
-- On duplicate key update
INSERT INTO employees (id, name, salary)
VALUES (1, 'John Doe', 85000)
ON DUPLICATE KEY UPDATE salary = VALUES(salary);
```

## Data Querying & Selection

### Basic SELECT: `SELECT`

Retrieve data from database tables.

```sql
-- Select all columns
SELECT * FROM employees;
-- Select specific columns
SELECT name, email, salary FROM employees;
-- Select with alias
SELECT name AS employee_name, salary AS
annual_salary
FROM employees;
-- Select distinct values
SELECT DISTINCT department FROM employees;
```

### Filtering Data: `WHERE`

Apply conditions to filter query results.

```sql
-- Basic conditions
SELECT * FROM employees WHERE salary > 70000;
-- Multiple conditions
SELECT * FROM employees
WHERE department = 'Engineering' AND salary > 75000;
-- Pattern matching
SELECT * FROM employees WHERE name LIKE 'John%';
-- Range queries
SELECT * FROM employees
WHERE hire_date BETWEEN '2023-01-01' AND '2023-12-
31';
```

### Sorting Data: `ORDER BY`

Sort query results in ascending or descending order.

```sql
-- Sort by single column
SELECT * FROM employees ORDER BY salary DESC;
-- Sort by multiple columns
SELECT * FROM employees
ORDER BY department ASC, salary DESC;
-- Sort with LIMIT
SELECT * FROM employees
ORDER BY hire_date DESC LIMIT 10;
```

### Limiting Results: `LIMIT`

Control the number of records returned.

```sql
-- Limit number of results
SELECT * FROM employees LIMIT 5;
-- Pagination with OFFSET
SELECT * FROM employees
ORDER BY id LIMIT 10 OFFSET 20;
-- Top N results
SELECT * FROM employees
ORDER BY salary DESC LIMIT 5;
```

## Advanced Querying

### Aggregate Functions: `COUNT`, `SUM`, `AVG`

Perform calculations on groups of data.

```sql
-- Count records
SELECT COUNT(*) FROM employees;
-- Sum and average
SELECT SUM(salary) as total_payroll, AVG(salary) as
avg_salary
FROM employees;
-- Group statistics
SELECT department, COUNT(*) as employee_count,
AVG(salary) as avg_salary
FROM employees GROUP BY department;
-- Having clause for group filtering
SELECT department, COUNT(*) as count
FROM employees
GROUP BY department
HAVING COUNT(*) > 5;
```

### Subqueries: Nested Queries

Use queries within other queries for complex operations.

```sql
-- Subquery in WHERE clause
SELECT * FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);
-- Subquery with IN
SELECT * FROM employees
WHERE department IN (
    SELECT name FROM departments WHERE budget >
100000
);
-- Correlated subquery
SELECT * FROM employees e1
WHERE salary > (
    SELECT AVG(salary) FROM employees e2
    WHERE e2.department = e1.department
);
```

### Table Joins: `JOIN`

Combine data from multiple tables.

```sql
-- Inner join
SELECT e.name, e.salary, d.department_name
FROM employees e
INNER JOIN departments d ON e.department = d.id;
-- Left join
SELECT e.name, d.department_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id;
-- Multiple joins
SELECT e.name, d.department_name, p.project_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id
LEFT JOIN projects p ON e.id = p.employee_id;
```

### Window Functions: Advanced Analytics

Perform calculations across related rows.

```sql
-- Row numbering
SELECT name, salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
FROM employees;
-- Running totals
SELECT name, salary,
    SUM(salary) OVER (ORDER BY hire_date) as
running_total
FROM employees;
-- Partition by groups
SELECT name, department, salary,
    AVG(salary) OVER (PARTITION BY department) as
dept_avg
FROM employees;
```

## Database Constraints & Integrity

### Primary Keys: `PRIMARY KEY`

Ensure unique identification for each record.

```sql
-- Single column primary key
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100)
);
-- Composite primary key
CREATE TABLE order_items (
    order_id INT,
    product_id INT,
    quantity INT,
    PRIMARY KEY (order_id, product_id)
);
```

### Foreign Keys: `FOREIGN KEY`

Maintain referential integrity between tables.

```sql
-- Add foreign key constraint
CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);
-- Add foreign key to existing table
ALTER TABLE employees
ADD CONSTRAINT fk_department
FOREIGN KEY (department_id) REFERENCES
departments(id);
```

### Unique Constraints: `UNIQUE`

Prevent duplicate values in columns.

```sql
-- Unique constraint on single column
ALTER TABLE employees
ADD CONSTRAINT unique_email UNIQUE (email);
-- Composite unique constraint
ALTER TABLE employees
ADD CONSTRAINT unique_name_dept UNIQUE (name,
department);
```

### Check Constraints: `CHECK`

Enforce business rules and data validation.

```sql
-- Simple check constraint
ALTER TABLE employees
ADD CONSTRAINT check_salary CHECK (salary > 0);
-- Complex check constraint
ALTER TABLE employees
ADD CONSTRAINT check_age
CHECK (YEAR(CURDATE()) - YEAR(birth_date) >= 18);
```

## Database Performance & Optimization

### Indexes: `CREATE INDEX`

Speed up data retrieval with database indexes.

```sql
-- Create index on single column
CREATE INDEX idx_employee_name ON
employees(name);
-- Composite index
CREATE INDEX idx_dept_salary ON
employees(department, salary);
-- Unique index
CREATE UNIQUE INDEX idx_employee_email ON
employees(email);
-- Show table indexes
SHOW INDEX FROM employees;
```

### Query Optimization: `EXPLAIN`

Analyze and optimize query performance.

```sql
-- Analyze query execution plan
EXPLAIN SELECT * FROM employees WHERE salary >
75000;
-- Detailed analysis
EXPLAIN ANALYZE SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department = d.id;
```

### Performance Monitoring

Monitor database performance and identify bottlenecks.

```sql
-- Show running processes
SHOW PROCESSLIST;
-- Show database status
SHOW STATUS LIKE 'Slow_queries';
-- Query cache information
SHOW STATUS LIKE 'Qcache%';
```

### Database Maintenance

Regular maintenance tasks for optimal performance.

```sql
-- Table optimization
OPTIMIZE TABLE employees;
-- Analyze table statistics
ANALYZE TABLE employees;
-- Check table integrity
CHECK TABLE employees;
-- Repair table if needed
REPAIR TABLE employees;
```

## Data Import/Export

### Import Data: `LOAD DATA`

Import data from external files into database tables.

```sql
-- Import from CSV file
LOAD DATA INFILE 'employees.csv'
INTO TABLE employees
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
-- Import with column mapping
LOAD DATA INFILE 'data.csv'
INTO TABLE employees (name, email, salary);
```

### Export Data: `SELECT INTO`

Export query results to external files.

```sql
-- Export to CSV file
SELECT name, email, salary
INTO OUTFILE 'employee_export.csv'
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
FROM employees;
-- Export with mysqldump
mysqldump -u username -p --tab=/path/to/export
database_name table_name
```

### Data Migration: Between Databases

Move data between different database systems.

```sql
-- Create table from existing structure
CREATE TABLE employees_backup LIKE employees;
-- Copy data between tables
INSERT INTO employees_backup SELECT * FROM
employees;
-- Migrate with conditions
INSERT INTO new_employees
SELECT * FROM old_employees WHERE active = 1;
```

### Bulk Operations

Handle large-scale data operations efficiently.

```sql
-- Bulk insert with INSERT IGNORE
INSERT IGNORE INTO employees (name, email) VALUES
('John Doe', 'john@email.com'),
('Jane Smith', 'jane@email.com');
-- Batch updates
UPDATE employees SET salary = salary * 1.1 WHERE
department = 'Sales';
```

## Database Security & Access Control

### User Management: `CREATE USER`

Create and manage database user accounts.

```sql
-- Create user with password
CREATE USER 'app_user'@'localhost' IDENTIFIED BY
'secure_password';
-- Create user for specific host
CREATE USER 'remote_user'@'192.168.1.%' IDENTIFIED
BY 'password';
-- Drop user
DROP USER 'old_user'@'localhost';
```

### Permissions: `GRANT` & `REVOKE`

Control access to database objects and operations.

```sql
-- Grant specific privileges
GRANT SELECT, INSERT ON company_db.employees TO
'app_user'@'localhost';
-- Grant all privileges
GRANT ALL PRIVILEGES ON company_db.* TO
'admin_user'@'localhost';
-- Revoke privileges
REVOKE INSERT ON company_db.employees FROM
'app_user'@'localhost';
-- Show user grants
SHOW GRANTS FOR 'app_user'@'localhost';
```

### Database Roles

Organize permissions using database roles.

```sql
-- Create role (MySQL 8.0+)
CREATE ROLE 'app_read_role', 'app_write_role';
-- Grant privileges to role
GRANT SELECT ON company_db.* TO 'app_read_role';
GRANT INSERT, UPDATE, DELETE ON company_db.* TO
'app_write_role';
-- Assign role to user
GRANT 'app_read_role' TO 'readonly_user'@'localhost';
```

### SQL Injection Prevention

Protect against common security vulnerabilities.

```sql
-- Use prepared statements (application level)
-- Bad: SELECT * FROM users WHERE id = ' + userInput
-- Good: Use parameterized queries
-- Validate input data types
-- Use stored procedures when possible
-- Apply principle of least privilege
```

## Database Installation & Setup

### MySQL Installation

Popular open-source relational database.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# Start MySQL service
sudo systemctl start mysql
sudo systemctl enable mysql
# Secure installation
sudo mysql_secure_installation
```

### PostgreSQL Installation

Advanced open-source relational database.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql
postgresql-contrib
# Switch to postgres user
sudo -u postgres psql
# Create database and user
CREATE DATABASE myapp;
CREATE USER myuser WITH
PASSWORD 'mypassword';
```

### SQLite Setup

Lightweight file-based database.

```bash
# Install SQLite
sudo apt install sqlite3
# Create database file
sqlite3 mydatabase.db
# Basic SQLite commands
.help
.tables
.schema tablename
.quit
```

## Database Configuration & Tuning

### MySQL Configuration

Key MySQL configuration parameters.

```sql
-- my.cnf configuration file
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
-- Show current settings
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW STATUS LIKE 'Connections';
```

### Connection Management

Manage database connections and pooling.

```sql
-- Show current connections
SHOW PROCESSLIST;
-- Kill specific connection
KILL CONNECTION 123;
-- Connection timeout settings
SET SESSION wait_timeout = 600;
SET SESSION interactive_timeout = 600;
```

### Backup Configuration

Set up automated database backups.

```bash
# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mysqldump -u backup_user -p mydatabase >
backup_$DATE.sql
# Schedule with cron
0 2 * * * /path/to/backup_script.sh
```

### Monitoring & Logging

Monitor database activity and performance.

```sql
-- Point-in-time recovery setup
SET GLOBAL log_bin = ON;
-- Enable slow query log
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
-- Show database size
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

## SQL Best Practices

### Query Writing Best Practices

Write clean, efficient, and readable SQL queries.

```sql
-- Use meaningful table aliases
SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.dept_id = d.id;
-- Specify column names instead of SELECT *
SELECT name, email, salary FROM employees;
-- Use appropriate data types
CREATE TABLE products (
    id INT PRIMARY KEY,
    price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP
);
```

### Performance Optimization Tips

Optimize queries for better database performance.

```sql
-- Use indexes on frequently queried columns
CREATE INDEX idx_employee_dept ON
employees(department);
-- Limit result sets when possible
SELECT name FROM employees WHERE active = 1 LIMIT
100;
-- Use EXISTS instead of IN for subqueries
SELECT * FROM customers c
WHERE EXISTS (SELECT 1 FROM orders o WHERE
o.customer_id = c.id);
```

## Relevant Links

- <router-link to="/mysql">MySQL Cheatsheet</router-link>
- <router-link to="/postgresql">PostgreSQL Cheatsheet</router-link>
- <router-link to="/sqlite">SQLite Cheatsheet</router-link>
- <router-link to="/mongodb">MongoDB Cheatsheet</router-link>
- <router-link to="/redis">Redis Cheatsheet</router-link>
- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/javascript">JavaScript Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>

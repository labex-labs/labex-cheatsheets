---
title: 'Шпаргалка по базам данных'
description: 'Изучите базы данных с нашей исчерпывающей шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/database-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по базам данных
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/database">Изучите базы данных с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите управление базами данных и SQL с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по базам данных, охватывающие основные команды SQL, манипулирование данными, оптимизацию запросов, проектирование баз данных и администрирование. Освойте реляционные базы данных, системы NoSQL и лучшие практики обеспечения безопасности баз данных.
</base-disclaimer-content>
</base-disclaimer>

## Создание и управление базами данных

### Создать базу данных: `CREATE DATABASE`

Создайте новую базу данных для хранения ваших данных.

```sql
-- Создать новую базу данных
CREATE DATABASE company_db;
-- Создать базу данных с набором символов
CREATE DATABASE company_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
-- Использовать базу данных
USE company_db;
```

### Показать базы данных: `SHOW DATABASES`

Вывести список всех доступных баз данных на сервере.

```sql
-- Вывести список всех баз данных
SHOW DATABASES;
-- Показать информацию о базе данных
SELECT SCHEMA_NAME FROM
INFORMATION_SCHEMA.SCHEMATA;
-- Показать текущую базу данных
SELECT DATABASE();
```

### Удалить базу данных: `DROP DATABASE`

Окончательно удалить всю базу данных.

```sql
-- Удалить базу данных (будьте осторожны!)
DROP DATABASE old_company_db;
-- Удалить базу данных, если она существует
DROP DATABASE IF EXISTS old_company_db;
```

### Резервное копирование базы данных: `mysqldump`

Создайте резервные копии вашей базы данных.

```sql
-- Резервное копирование в командной строке
mysqldump -u username -p database_name > backup.sql
-- Восстановление из резервной копии
mysql -u username -p database_name < backup.sql
```

### Пользователи базы данных: `CREATE USER`

Управление учетными записями пользователей базы данных и разрешениями.

```sql
-- Создать нового пользователя
CREATE USER 'newuser'@'localhost' IDENTIFIED BY
'password';
-- Предоставить привилегии
GRANT SELECT, INSERT ON company_db.* TO
'newuser'@'localhost';
-- Показать привилегии пользователя
SHOW GRANTS FOR 'newuser'@'localhost';
```

### Информация о базе данных: `INFORMATION_SCHEMA`

Запрашивать метаданные базы данных и информацию о структуре.

```sql
-- Показать все таблицы
SELECT TABLE_NAME FROM
INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'company_db';
-- Показать столбцы таблицы
DESCRIBE employees;
```

## Структура и информация о таблицах

### Создать таблицу: `CREATE TABLE`

Определите новые таблицы со столбцами и типами данных.

```sql
-- Базовое создание таблицы
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY
KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE,
    salary DECIMAL(10,2),
    hire_date DATE,
    department VARCHAR(50)
);
-- Показать структуру таблицы
DESCRIBE employees;
SHOW COLUMNS FROM employees;
```

### Изменить таблицу: `ALTER TABLE`

Измените существующую структуру таблицы и столбцы.

```sql
-- Добавить новый столбец
ALTER TABLE employees ADD
COLUMN phone VARCHAR(15);
-- Изменить тип столбца
ALTER TABLE employees MODIFY
COLUMN salary DECIMAL(12,2);
-- Удалить столбец
ALTER TABLE employees DROP
COLUMN phone;
-- Переименовать таблицу
RENAME TABLE employees TO staff;
```

### Информация о таблице: `SHOW`

Получите подробную информацию о таблицах и их свойствах.

```sql
-- Показать все таблицы
SHOW TABLES;
-- Показать структуру таблицы
SHOW CREATE TABLE employees;
-- Показать статус таблицы
SHOW TABLE STATUS LIKE
'employees';
-- Подсчитать строки в таблице
SELECT COUNT(*) FROM employees;
```

## Манипулирование данными и операции CRUD

### Вставить данные: `INSERT INTO`

Добавьте новые записи в ваши таблицы.

```sql
-- Вставить одну запись
INSERT INTO employees (name, email, salary, hire_date,
department)
VALUES ('John Doe', 'john@company.com', 75000.00,
'2024-01-15', 'Engineering');
-- Вставить несколько записей
INSERT INTO employees (name, email, salary,
department) VALUES
('Jane Smith', 'jane@company.com', 80000.00,
'Marketing'),
('Bob Johnson', 'bob@company.com', 65000.00, 'Sales');
-- Вставить из другой таблицы
INSERT INTO backup_employees
SELECT * FROM employees WHERE department =
'Engineering';
```

### Обновить данные: `UPDATE`

Измените существующие записи в таблицах.

```sql
-- Обновить одну запись
UPDATE employees
SET salary = 85000.00, department = 'Senior Engineering'
WHERE id = 1;
-- Обновить несколько записей
UPDATE employees
SET salary = salary * 1.05
WHERE hire_date < '2024-01-01';
-- Обновить с JOIN
UPDATE employees e
JOIN departments d ON e.department = d.name
SET e.salary = e.salary + d.bonus;
```

### Удалить данные: `DELETE FROM`

Удалите записи из таблиц.

```sql
-- Удалить определенные записи
DELETE FROM employees
WHERE department = 'Temporary';
-- Удалить с условиями
DELETE FROM employees
WHERE hire_date < '2020-01-01' AND salary < 50000;
-- Truncate table (быстрее для всех записей)
TRUNCATE TABLE temp_employees;
```

### Заменить данные: `REPLACE INTO`

Вставить или обновить записи на основе первичного ключа.

```sql
-- Заменить запись (вставить или обновить)
REPLACE INTO employees (id, name, email, salary)
VALUES (1, 'John Doe Updated',
'john.new@company.com', 90000);
-- При дублировании ключа обновить
INSERT INTO employees (id, name, salary)
VALUES (1, 'John Doe', 85000)
ON DUPLICATE KEY UPDATE salary = VALUES(salary);
```

## Запросы и выборка данных

### Базовый SELECT: `SELECT`

Извлечение данных из таблиц базы данных.

```sql
-- Выбрать все столбцы
SELECT * FROM employees;
-- Выбрать определенные столбцы
SELECT name, email, salary FROM employees;
-- Выбрать с псевдонимом
SELECT name AS employee_name, salary AS
annual_salary
FROM employees;
-- Выбрать уникальные значения
SELECT DISTINCT department FROM employees;
```

### Фильтрация данных: `WHERE`

Применение условий для фильтрации результатов запроса.

```sql
-- Базовые условия
SELECT * FROM employees WHERE salary > 70000;
-- Множественные условия
SELECT * FROM employees
WHERE department = 'Engineering' AND salary > 75000;
-- Сопоставление с шаблоном
SELECT * FROM employees WHERE name LIKE 'John%';
-- Запросы диапазона
SELECT * FROM employees
WHERE hire_date BETWEEN '2023-01-01' AND '2023-12-
31';
```

### Сортировка данных: `ORDER BY`

Сортировка результатов запроса по возрастанию или убыванию.

```sql
-- Сортировка по одному столбцу
SELECT * FROM employees ORDER BY salary DESC;
-- Сортировка по нескольким столбцам
SELECT * FROM employees
ORDER BY department ASC, salary DESC;
-- Сортировка с LIMIT
SELECT * FROM employees
ORDER BY hire_date DESC LIMIT 10;
```

### Ограничение результатов: `LIMIT`

Управление количеством возвращаемых записей.

```sql
-- Ограничить количество результатов
SELECT * FROM employees LIMIT 5;
-- Пагинация с OFFSET
SELECT * FROM employees
ORDER BY id LIMIT 10 OFFSET 20;
-- Топ N результатов
SELECT * FROM employees
ORDER BY salary DESC LIMIT 5;
```

## Расширенные запросы

### Агрегатные функции: `COUNT`, `SUM`, `AVG`

Выполнение вычислений над группами данных.

```sql
-- Подсчет записей
SELECT COUNT(*) FROM employees;
-- Сумма и среднее
SELECT SUM(salary) as total_payroll, AVG(salary) as
avg_salary
FROM employees;
-- Статистика по группам
SELECT department, COUNT(*) as employee_count,
AVG(salary) as avg_salary
FROM employees GROUP BY department;
-- Условие Having для фильтрации групп
SELECT department, COUNT(*) as count
FROM employees
GROUP BY department
HAVING COUNT(*) > 5;
```

### Подзапросы: Вложенные запросы

Использование запросов внутри других запросов для сложных операций.

```sql
-- Подзапрос в предложении WHERE
SELECT * FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);
-- Подзапрос с IN
SELECT * FROM employees
WHERE department IN (
    SELECT name FROM departments WHERE budget >
100000
);
-- Коррелированный подзапрос
SELECT * FROM employees e1
WHERE salary > (
    SELECT AVG(salary) FROM employees e2
    WHERE e2.department = e1.department
);
```

### Объединение таблиц: `JOIN`

Объединение данных из нескольких таблиц.

```sql
-- Внутреннее объединение
SELECT e.name, e.salary, d.department_name
FROM employees e
INNER JOIN departments d ON e.department = d.id;
-- Левое объединение
SELECT e.name, d.department_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id;
-- Множественные объединения
SELECT e.name, d.department_name, p.project_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id
LEFT JOIN projects p ON e.id = p.employee_id;
```

### Оконные функции: Расширенная аналитика

Выполнение вычислений по связанным строкам.

```sql
-- Нумерация строк
SELECT name, salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
FROM employees;
-- Накопительные суммы
SELECT name, salary,
    SUM(salary) OVER (ORDER BY hire_date) as
running_total
FROM employees;
-- Разделение по группам
SELECT name, department, salary,
    AVG(salary) OVER (PARTITION BY department) as
dept_avg
FROM employees;
```

## Ограничения и целостность базы данных

### Первичные ключи: `PRIMARY KEY`

Обеспечение уникальной идентификации для каждой записи.

```sql
-- Первичный ключ из одного столбца
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100)
);
-- Составной первичный ключ
CREATE TABLE order_items (
    order_id INT,
    product_id INT,
    quantity INT,
    PRIMARY KEY (order_id, product_id)
);
```

### Внешние ключи: `FOREIGN KEY`

Поддержание ссылочной целостности между таблицами.

```sql
-- Добавить ограничение внешнего ключа
CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);
-- Добавить внешний ключ к существующей таблице
ALTER TABLE employees
ADD CONSTRAINT fk_department
FOREIGN KEY (department_id) REFERENCES
departments(id);
```

### Уникальные ограничения: `UNIQUE`

Предотвращение дублирования значений в столбцах.

```sql
-- Уникальное ограничение для одного столбца
ALTER TABLE employees
ADD CONSTRAINT unique_email UNIQUE (email);
-- Составное уникальное ограничение
ALTER TABLE employees
ADD CONSTRAINT unique_name_dept UNIQUE (name,
department);
```

### Ограничения CHECK: `CHECK`

Обеспечение бизнес-правил и проверки данных.

```sql
-- Простое ограничение check
ALTER TABLE employees
ADD CONSTRAINT check_salary CHECK (salary > 0);
-- Сложное ограничение check
ALTER TABLE employees
ADD CONSTRAINT check_age
CHECK (YEAR(CURDATE()) - YEAR(birth_date) >= 18);
```

## Производительность и оптимизация базы данных

### Индексы: `CREATE INDEX`

Ускорение выборки данных с помощью индексов базы данных.

```sql
-- Создать индекс по одному столбцу
CREATE INDEX idx_employee_name ON
employees(name);
-- Составной индекс
CREATE INDEX idx_dept_salary ON
employees(department, salary);
-- Уникальный индекс
CREATE UNIQUE INDEX idx_employee_email ON
employees(email);
-- Показать индексы таблицы
SHOW INDEX FROM employees;
```

### Оптимизация запросов: `EXPLAIN`

Анализ и оптимизация производительности запросов.

```sql
-- Анализ плана выполнения запроса
EXPLAIN SELECT * FROM employees WHERE salary >
75000;
-- Детальный анализ
EXPLAIN ANALYZE SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department = d.id;
```

### Мониторинг производительности

Мониторинг активности базы данных и выявление узких мест.

```sql
-- Показать выполняющиеся процессы
SHOW PROCESSLIST;
-- Показать статус базы данных
SHOW STATUS LIKE 'Slow_queries';
-- Информация о кэше запросов
SHOW STATUS LIKE 'Qcache%';
```

### Обслуживание базы данных

Регулярные задачи обслуживания для оптимальной производительности.

```sql
-- Оптимизация таблицы
OPTIMIZE TABLE employees;
-- Анализ статистики таблицы
ANALYZE TABLE employees;
-- Проверка целостности таблицы
CHECK TABLE employees;
-- Восстановление таблицы при необходимости
REPAIR TABLE employees;
```

## Импорт/Экспорт данных

### Импорт данных: `LOAD DATA`

Импорт данных из внешних файлов в таблицы базы данных.

```sql
-- Импорт из CSV файла
LOAD DATA INFILE 'employees.csv'
INTO TABLE employees
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
-- Импорт с сопоставлением столбцов
LOAD DATA INFILE 'data.csv'
INTO TABLE employees (name, email, salary);
```

### Экспорт данных: `SELECT INTO`

Экспорт результатов запроса во внешние файлы.

```sql
-- Экспорт в CSV файл
SELECT name, email, salary
INTO OUTFILE 'employee_export.csv'
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
FROM employees;
-- Экспорт с помощью mysqldump
mysqldump -u username -p --tab=/path/to/export
database_name table_name
```

### Миграция данных: Между базами данных

Перемещение данных между различными системами баз данных.

```sql
-- Создать таблицу по существующей структуре
CREATE TABLE employees_backup LIKE employees;
-- Копировать данные между таблицами
INSERT INTO employees_backup SELECT * FROM
employees;
-- Миграция с условиями
INSERT INTO new_employees
SELECT * FROM old_employees WHERE active = 1;
```

### Массовые операции

Эффективная обработка крупномасштабных операций с данными.

```sql
-- Массовая вставка с INSERT IGNORE
INSERT IGNORE INTO employees (name, email) VALUES
('John Doe', 'john@email.com'),
('Jane Smith', 'jane@email.com');
-- Пакетные обновления
UPDATE employees SET salary = salary * 1.1 WHERE
department = 'Sales';
```

## Безопасность базы данных и контроль доступа

### Управление пользователями: `CREATE USER`

Создание и управление учетными записями пользователей базы данных.

```sql
-- Создать пользователя с паролем
CREATE USER 'app_user'@'localhost' IDENTIFIED BY
'secure_password';
-- Создать пользователя для определенного хоста
CREATE USER 'remote_user'@'192.168.1.%' IDENTIFIED
BY 'password';
-- Удалить пользователя
DROP USER 'old_user'@'localhost';
```

### Разрешения: `GRANT` & `REVOKE`

Управление доступом к объектам базы данных и операциям.

```sql
-- Предоставить определенные привилегии
GRANT SELECT, INSERT ON company_db.employees TO
'app_user'@'localhost';
-- Предоставить все привилегии
GRANT ALL PRIVILEGES ON company_db.* TO
'admin_user'@'localhost';
-- Отозвать привилегии
REVOKE INSERT ON company_db.employees FROM
'app_user'@'localhost';
-- Показать права пользователя
SHOW GRANTS FOR 'app_user'@'localhost';
```

### Роли базы данных

Организация разрешений с использованием ролей базы данных.

```sql
-- Создать роль (MySQL 8.0+)
CREATE ROLE 'app_read_role', 'app_write_role';
-- Предоставить привилегии роли
GRANT SELECT ON company_db.* TO 'app_read_role';
GRANT INSERT, UPDATE, DELETE ON company_db.* TO
'app_write_role';
-- Назначить роль пользователю
GRANT 'app_read_role' TO 'readonly_user'@'localhost';
```

### Предотвращение SQL-инъекций

Защита от распространенных уязвимостей безопасности.

```sql
-- Использовать подготовленные операторы (на уровне приложения)
-- Плохо: SELECT * FROM users WHERE id = ' + userInput
-- Хорошо: Использовать параметризованные запросы
-- Проверять типы вводимых данных
-- Использовать хранимые процедуры, когда это возможно
-- Применять принцип наименьших привилегий
```

## Установка и настройка базы данных

### Установка MySQL

Популярная реляционная база данных с открытым исходным кодом.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# Запустить службу MySQL
sudo systemctl start mysql
sudo systemctl enable mysql
# Безопасная установка
sudo mysql_secure_installation
```

### Установка PostgreSQL

Передовая реляционная база данных с открытым исходным кодом.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql
postgresql-contrib
# Переключиться на пользователя postgres
sudo -u postgres psql
# Создать базу данных и пользователя
CREATE DATABASE myapp;
CREATE USER myuser WITH
PASSWORD 'mypassword';
```

### Настройка SQLite

Легковесная база данных на основе файлов.

```bash
# Установить SQLite
sudo apt install sqlite3
# Создать файл базы данных
sqlite3 mydatabase.db
# Базовые команды SQLite
.help
.tables
.schema tablename
.quit
```

## Конфигурация и настройка базы данных

### Конфигурация MySQL

Ключевые параметры конфигурации MySQL.

```sql
-- Конфигурационный файл my.cnf
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
-- Показать текущие настройки
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW STATUS LIKE 'Connections';
```

### Управление соединениями

Управление соединениями с базой данных и их пулингом.

```sql
-- Показать текущие соединения
SHOW PROCESSLIST;
-- Убить конкретное соединение
KILL CONNECTION 123;
-- Настройки таймаута соединения
SET SESSION wait_timeout = 600;
SET SESSION interactive_timeout = 600;
```

### Настройка резервного копирования

Настройка автоматического резервного копирования базы данных.

```sql
-- Скрипт автоматического резервного копирования
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mysqldump -u backup_user -p mydatabase >
backup_$DATE.sql
# Планирование с помощью cron
0 2 * * * /path/to/backup_script.sh
```

### Мониторинг и логирование

Мониторинг активности базы данных и производительности.

```sql
-- Настройка восстановления на момент времени
SET GLOBAL log_bin = ON;
-- Включить лог медленных запросов
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
-- Показать размер базы данных
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

## Лучшие практики SQL

### Лучшие практики написания запросов

Пишите чистые, эффективные и читаемые SQL-запросы.

```sql
-- Использовать значимые псевдонимы таблиц
SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.dept_id = d.id;
-- Указывать имена столбцов вместо SELECT *
SELECT name, email, salary FROM employees;
-- Использовать соответствующие типы данных
CREATE TABLE products (
    id INT PRIMARY KEY,
    price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP
);
```

### Советы по оптимизации производительности

Оптимизируйте запросы для лучшей производительности базы данных.

```sql
-- Использовать индексы в часто запрашиваемых столбцах
CREATE INDEX idx_employee_dept ON
employees(department);
-- Ограничивать наборы результатов, когда это возможно
SELECT name FROM employees WHERE active = 1 LIMIT
100;
-- Использовать EXISTS вместо IN для подзапросов
SELECT * FROM customers c
WHERE EXISTS (SELECT 1 FROM orders o WHERE
o.customer_id = c.id);
```

## Соответствующие ссылки

- <router-link to="/mysql">Шпаргалка по MySQL</router-link>
- <router-link to="/postgresql">Шпаргалка по PostgreSQL</router-link>
- <router-link to="/sqlite">Шпаргалка по SQLite</router-link>
- <router-link to="/mongodb">Шпаргалка по MongoDB</router-link>
- <router-link to="/redis">Шпаргалка по Redis</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>

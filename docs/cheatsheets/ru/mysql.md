---
title: 'Шпаргалка по MySQL | LabEx'
description: 'Изучите управление базами данных MySQL с помощью этой исчерпывающей шпаргалки. Краткий справочник по SQL-запросам, соединениям, индексам, транзакциям, хранимым процедурам и администрированию баз данных.'
pdfUrl: '/cheatsheets/pdf/mysql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по MySQL
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/mysql">Изучите MySQL с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите управление базами данных MySQL с помощью практических лабораторий и сценариев реального мира. LabEx предлагает комплексные курсы по MySQL, охватывающие основные операции SQL, администрирование баз данных, оптимизацию производительности и расширенные методы запросов. Освойте одну из самых популярных в мире реляционных систем баз данных.
</base-disclaimer-content>
</base-disclaimer>

## Подключение и управление базами данных

### Подключение к серверу: `mysql -u username -p`

Подключение к серверу MySQL через командную строку.

```bash
# Подключение с запросом имени пользователя и пароля
mysql -u root -p
# Подключение к определенной базе данных
mysql -u username -p database_name
# Подключение к удаленному серверу
mysql -h hostname -u username -p
# Подключение с указанием порта
mysql -h hostname -P 3306 -u username -p database_name
```

### Операции с базами данных: `CREATE` / `DROP` / `USE`

Управление базами данных на сервере.

```sql
# Создать новую базу данных
CREATE DATABASE company_db;
# Показать все базы данных
SHOW DATABASES;
# Выбрать базу данных для использования
USE company_db;
# Удалить базу данных (удалить навсегда)
DROP DATABASE old_database;
```

<BaseQuiz id="mysql-database-1" correct="C">
  <template #question>
    Что делает команда `USE database_name`?
  </template>
  
  <BaseQuizOption value="A">Создает новую базу данных</BaseQuizOption>
  <BaseQuizOption value="B">Удаляет базу данных</BaseQuizOption>
  <BaseQuizOption value="C" correct>Выбирает базу данных для последующих операций</BaseQuizOption>
  <BaseQuizOption value="D">Показывает все таблицы в базе данных</BaseQuizOption>
  
  <BaseQuizAnswer>
    Команда `USE` выбирает базу данных, делая ее активной для всех последующих SQL-операторов. Это эквивалентно выбору базы данных при подключении с помощью `mysql -u user -p database_name`.
  </BaseQuizAnswer>
</BaseQuiz>

### Экспорт данных: `mysqldump`

Резервное копирование данных базы данных в SQL-файл.

```bash
# Экспорт всей базы данных
mysqldump -u username -p database_name > backup.sql
# Экспорт отдельной таблицы
mysqldump -u username -p database_name table_name > table_backup.sql
# Экспорт только структуры
mysqldump -u username -p --no-data database_name > structure.sql
# Полное резервное копирование базы данных с процедурами и триггерами
mysqldump -u username -p --routines --triggers database_name > backup.sql
```

### Импорт данных: `mysql < file.sql`

Импорт SQL-файла в базу данных MySQL.

```bash
# Импорт SQL-файла в базу данных
mysql -u username -p database_name < backup.sql
# Импорт без указания базы данных (если она включена в файл)
mysql -u username -p < full_backup.sql
```

### Управление пользователями: `CREATE USER` / `GRANT`

Управление пользователями базы данных и их правами.

```sql
# Создать нового пользователя
CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
# Предоставить все привилегии
GRANT ALL PRIVILEGES ON database_name.* TO 'user'@'localhost';
# Предоставить определенные привилегии
GRANT SELECT, INSERT, UPDATE ON table_name TO 'user'@'localhost';
# Применить изменения привилегий
FLUSH PRIVILEGES;
```

### Показать информацию о сервере: `SHOW STATUS` / `SHOW VARIABLES`

Отображение конфигурации и состояния сервера.

```sql
# Показать статус сервера
SHOW STATUS;
# Показать переменные конфигурации
SHOW VARIABLES;
# Показать текущие процессы
SHOW PROCESSLIST;
```

## Структура и схема таблиц

### Создание таблицы: `CREATE TABLE`

Создание новых таблиц с указанием столбцов и типов данных.

```sql
# Создать таблицу с различными типами данных
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    age INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# Создать таблицу с внешним ключом
CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Информация о таблице: `DESCRIBE` / `SHOW`

Просмотр структуры таблицы и содержимого базы данных.

```sql
# Показать структуру таблицы
DESCRIBE users;
# Альтернативный синтаксис
SHOW COLUMNS FROM users;
# Показать все таблицы
SHOW TABLES;
# Показать оператор CREATE для таблицы
SHOW CREATE TABLE users;
```

### Изменение таблиц: `ALTER TABLE`

Изменение существующей структуры таблицы, добавление или удаление столбцов.

```sql
# Добавить новый столбец
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
# Удалить столбец
ALTER TABLE users DROP COLUMN age;
# Изменить тип столбца
ALTER TABLE users MODIFY COLUMN username VARCHAR(100);
# Переименовать столбец
ALTER TABLE users CHANGE old_name new_name VARCHAR(50);
```

## Манипулирование данными и CRUD операции

### Вставка данных: `INSERT INTO`

Добавление новых записей в таблицы.

```sql
# Вставить одну запись
INSERT INTO users (username, email, age)
VALUES ('john_doe', 'john@email.com', 25);
# Вставить несколько записей
INSERT INTO users (username, email, age) VALUES
('alice', 'alice@email.com', 30),
('bob', 'bob@email.com', 28);
# Вставить из другой таблицы
INSERT INTO users_backup SELECT * FROM users;
```

<BaseQuiz id="mysql-insert-1" correct="A">
  <template #question>
    Какой синтаксис правильный для вставки одной записи?
  </template>
  
  <BaseQuizOption value="A" correct>`INSERT INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="B">`INSERT table_name VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="C">`ADD INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="D">`INSERT table_name (column1, column2) = (value1, value2);`</BaseQuizOption>
  
  <BaseQuizAnswer>
    Правильный синтаксис: `INSERT INTO table_name (columns) VALUES (values)`. Ключевое слово `INTO` является обязательным, и необходимо указать как имена столбцов, так и соответствующие им значения.
  </BaseQuizAnswer>
</BaseQuiz>

### Обновление данных: `UPDATE`

Изменение существующих записей в таблицах.

```sql
# Обновить конкретную запись
UPDATE users SET age = 26 WHERE username = 'john_doe';
# Обновить несколько столбцов
UPDATE users SET age = 31, email = 'alice_new@email.com'
WHERE username = 'alice';
# Обновить с расчетом
UPDATE products SET price = price * 1.1 WHERE category = 'electronics';
```

### Удаление данных: `DELETE` / `TRUNCATE`

Удаление записей из таблиц.

```sql
# Удалить конкретные записи
DELETE FROM users WHERE age < 18;
# Удалить все записи (сохранить структуру)
DELETE FROM users;
# Удалить все записи (быстрее, сбрасывает AUTO_INCREMENT)
TRUNCATE TABLE users;
# Удалить с JOIN
DELETE u FROM users u
JOIN inactive_accounts i ON u.id = i.user_id;
```

### Замена данных: `REPLACE` / `INSERT ... ON DUPLICATE KEY`

Обработка ситуаций с дублированием ключей при вставке.

```sql
# Заменить существующую или вставить новую
REPLACE INTO users (id, username, email)
VALUES (1, 'updated_user', 'new@email.com');
# Вставить или обновить при дублировании ключа
INSERT INTO users (username, email)
VALUES ('john', 'john@email.com')
ON DUPLICATE KEY UPDATE email = VALUES(email);
```

## Запросы данных и выборка

### Базовый SELECT: `SELECT * FROM`

Извлечение данных из таблиц с различными условиями.

```sql
# Выбрать все столбцы
SELECT * FROM users;
# Выбрать определенные столбцы
SELECT username, email FROM users;
# Выбрать с условием WHERE
SELECT * FROM users WHERE age > 25;
# Выбрать с несколькими условиями
SELECT * FROM users WHERE age > 20 AND email LIKE '%gmail.com';
```

<BaseQuiz id="mysql-select-1" correct="D">
  <template #question>
    Что возвращает `SELECT * FROM users`?
  </template>
  
  <BaseQuizOption value="A">Только первую строку из таблицы users</BaseQuizOption>
  <BaseQuizOption value="B">Только столбец username</BaseQuizOption>
  <BaseQuizOption value="C">Структуру таблицы</BaseQuizOption>
  <BaseQuizOption value="D" correct>Все столбцы и все строки из таблицы users</BaseQuizOption>
  
  <BaseQuizAnswer>
    Символ `*` выбирает все столбцы, а без условия WHERE возвращаются все строки. Это полезно для просмотра всех данных, но следует использовать с осторожностью для больших таблиц.
  </BaseQuizAnswer>
</BaseQuiz>

### Сортировка и ограничение: `ORDER BY` / `LIMIT`

Управление порядком и количеством возвращаемых результатов.

```sql
# Сортировать результаты
SELECT * FROM users ORDER BY age DESC;
# Сортировать по нескольким столбцам
SELECT * FROM users ORDER BY age DESC, username ASC;
# Ограничить результаты
SELECT * FROM users LIMIT 10;
# Пагинация (пропустить первые 10, взять следующие 10)
SELECT * FROM users LIMIT 10 OFFSET 10;
```

### Фильтрация: `WHERE` / `LIKE` / `IN`

Фильтрация данных с использованием различных операторов сравнения.

```sql
# Сопоставление с шаблоном
SELECT * FROM users WHERE username LIKE 'john%';
# Несколько значений
SELECT * FROM users WHERE age IN (25, 30, 35);
# Фильтрация диапазона
SELECT * FROM users WHERE age BETWEEN 20 AND 30;
# Проверка на NULL
SELECT * FROM users WHERE email IS NOT NULL;
```

### Группировка: `GROUP BY` / `HAVING`

Группировка данных и применение агрегатных функций.

```sql
# Группировка по столбцу
SELECT age, COUNT(*) FROM users GROUP BY age;
# Группировка с условием по группам
SELECT age, COUNT(*) as count FROM users
GROUP BY age HAVING count > 1;
# Группировка по нескольким столбцам
SELECT age, gender, COUNT(*) FROM users
GROUP BY age, gender;
```

## Расширенные запросы

### Операции JOIN: `INNER` / `LEFT` / `RIGHT`

Объединение данных из нескольких таблиц.

```sql
# Внутреннее соединение (только совпадающие записи)
SELECT u.username, o.order_date
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# Левое соединение (все пользователи, совпадающие заказы)
SELECT u.username, o.order_date
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# Множественные соединения
SELECT u.username, o.order_date, p.product_name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

<BaseQuiz id="mysql-join-1" correct="B">
  <template #question>
    В чем разница между INNER JOIN и LEFT JOIN?
  </template>
  
  <BaseQuizOption value="A">Разницы нет</BaseQuizOption>
  <BaseQuizOption value="B" correct>INNER JOIN возвращает только совпадающие строки, LEFT JOIN возвращает все строки из левой таблицы</BaseQuizOption>
  <BaseQuizOption value="C">INNER JOIN работает быстрее</BaseQuizOption>
  <BaseQuizOption value="D">LEFT JOIN работает только с двумя таблицами</BaseQuizOption>
  
  <BaseQuizAnswer>
    INNER JOIN возвращает только строки, имеющие совпадения в обеих таблицах. LEFT JOIN возвращает все строки из левой таблицы и совпадающие строки из правой таблицы, с NULL значениями для несовпадающих строк правой таблицы.
  </BaseQuizAnswer>
</BaseQuiz>

### Подзапросы: `SELECT` внутри `SELECT`

Использование вложенных запросов для сложного извлечения данных.

```sql
# Подзапрос в предложении WHERE
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders WHERE total > 100);
# Коррелированный подзапрос
SELECT username FROM users u1
WHERE age > (SELECT AVG(age) FROM users u2);
# Подзапрос в SELECT
SELECT username,
(SELECT COUNT(*) FROM orders WHERE user_id = users.id) as order_count
FROM users;
```

### Агрегатные функции: `COUNT` / `SUM` / `AVG`

Вычисление статистики и сводок по данным.

```sql
# Базовые агрегаты
SELECT COUNT(*) FROM users;
SELECT AVG(age), MIN(age), MAX(age) FROM users;
SELECT SUM(total) FROM orders;
# Агрегация с группировкой
SELECT department, AVG(salary)
FROM employees GROUP BY department;
# Множественные агрегаты
SELECT
    COUNT(*) as total_users,
    AVG(age) as avg_age,
    MAX(created_at) as latest_signup
FROM users;
```

### Оконные функции: `OVER` / `PARTITION BY`

Выполнение вычислений над наборами строк таблицы.

```sql
# Функции ранжирования
SELECT username, age,
RANK() OVER (ORDER BY age DESC) as age_rank
FROM users;
# Разделение по группам
SELECT username, department, salary,
AVG(salary) OVER (PARTITION BY department) as dept_avg
FROM employees;
# Накопительные итоги
SELECT order_date, total,
SUM(total) OVER (ORDER BY order_date) as running_total
FROM orders;
```

## Индексы и производительность

### Создание индексов: `CREATE INDEX`

Улучшение производительности запросов с помощью индексов базы данных.

```sql
# Создать обычный индекс
CREATE INDEX idx_username ON users(username);
# Создать составной индекс
CREATE INDEX idx_user_age ON users(username, age);
# Создать уникальный индекс
CREATE UNIQUE INDEX idx_email ON users(email);
# Показать индексы таблицы
SHOW INDEXES FROM users;
```

### Анализ запросов: `EXPLAIN`

Анализ планов выполнения запросов и производительности.

```sql
# Показать план выполнения запроса
EXPLAIN SELECT * FROM users WHERE age > 25;
# Детальный анализ
EXPLAIN FORMAT=JSON SELECT u.*, o.total
FROM users u JOIN orders o ON u.id = o.user_id;
# Показать производительность запроса
SHOW PROFILES;
SET profiling = 1;
```

### Оптимизация запросов: Лучшие практики

Методы написания эффективных SQL-запросов.

```sql
# Использовать конкретные столбцы вместо *
SELECT username, email FROM users WHERE id = 1;
# Использовать LIMIT для больших наборов данных
SELECT * FROM logs ORDER BY created_at DESC LIMIT 1000;
# Использовать правильные условия WHERE
SELECT * FROM orders WHERE user_id = 123 AND status = 'pending';
-- Использовать покрывающие индексы, когда это возможно
```

### Обслуживание таблиц: `OPTIMIZE` / `ANALYZE`

Поддержание производительности и статистики таблиц.

```sql
# Оптимизировать хранение таблицы
OPTIMIZE TABLE users;
# Обновить статистику таблицы
ANALYZE TABLE users;
# Проверить целостность таблицы
CHECK TABLE users;
# Восстановить таблицу при необходимости
REPAIR TABLE users;
```

## Импорт/Экспорт данных

### Загрузка данных: `LOAD DATA INFILE`

Импорт данных из CSV и текстовых файлов.

```sql
# Загрузить CSV-файл
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
# Загрузить с указанием столбцов
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users (username, email, age);
```

### Экспорт данных: `SELECT INTO OUTFILE`

Экспорт результатов запроса в файлы.

```sql
# Экспорт в CSV-файл
SELECT username, email, age
FROM users
INTO OUTFILE '/path/to/export.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

### Резервное копирование и восстановление: `mysqldump` / `mysql`

Создание и восстановление резервных копий баз данных.

```bash
# Резервное копирование конкретных таблиц
mysqldump -u username -p database_name table1 table2 > tables_backup.sql
# Восстановление из резервной копии
mysql -u username -p database_name < backup.sql
# Экспорт с удаленного сервера
mysqldump -h remote_host -u username -p database_name > remote_backup.sql
# Импорт в локальную базу данных
mysql -u local_user -p local_database < remote_backup.sql
# Прямое копирование данных между серверами
mysqldump -h source_host -u user -p db_name | mysql -h dest_host -u user -p db_name
```

## Типы данных и функции

### Общие типы данных: Числа, Текст, Даты

Выбор подходящих типов данных для столбцов.

```sql
# Числовые типы
INT, BIGINT, DECIMAL(10,2), FLOAT, DOUBLE
# Строковые типы
VARCHAR(255), TEXT, CHAR(10), MEDIUMTEXT, LONGTEXT
# Типы даты и времени
DATE, TIME, DATETIME, TIMESTAMP, YEAR
# Логический и бинарный
BOOLEAN, BLOB, VARBINARY

# Пример создания таблицы
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Строковые функции: `CONCAT` / `SUBSTRING` / `LENGTH`

Манипулирование текстовыми данными с помощью встроенных строковых функций.

```sql
# Конкатенация строк
SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users;
# Строковые операции
SELECT SUBSTRING(email, 1, LOCATE('@', email)-1) as username FROM users;
SELECT LENGTH(username), UPPER(username) FROM users;
# Сопоставление с шаблоном и замена
SELECT REPLACE(phone, '-', '.') FROM users WHERE phone LIKE '___-___-____';
```

### Функции даты: `NOW()` / `DATE_ADD` / `DATEDIFF`

Эффективная работа с датами и временем.

```sql
# Текущая дата и время
SELECT NOW(), CURDATE(), CURTIME();
# Арифметика с датами
SELECT DATE_ADD(created_at, INTERVAL 30 DAY) as expiry_date FROM users;
SELECT DATEDIFF(NOW(), created_at) as days_since_signup FROM users;
# Форматирование даты
SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') as formatted_date FROM orders;
```

### Числовые функции: `ROUND` / `ABS` / `RAND`

Выполнение математических операций с числовыми данными.

```sql
# Математические функции
SELECT ROUND(price, 2), ABS(profit_loss), SQRT(area) FROM products;
# Случайные и статистические
SELECT RAND(), FLOOR(price), CEIL(rating) FROM products;
# Математическая агрегация
SELECT AVG(price), STDDEV(price), VARIANCE(price) FROM products;
```

## Управление транзакциями

### Управление транзакциями: `BEGIN` / `COMMIT` / `ROLLBACK`

Управление транзакциями базы данных для согласованности данных.

```sql
# Начать транзакцию
BEGIN;
# или
START TRANSACTION;
# Выполнить операции
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;
# Зафиксировать изменения
COMMIT;
# Или отменить в случае ошибки
ROLLBACK;
```

### Уровень изоляции транзакций: `SET TRANSACTION ISOLATION`

Контроль взаимодействия транзакций друг с другом.

```sql
# Установить уровень изоляции
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
# Показать текущий уровень изоляции
SELECT @@transaction_isolation;
```

### Блокировки: `LOCK TABLES` / `SELECT FOR UPDATE`

Управление параллельным доступом к данным.

```sql
# Блокировать таблицы для эксклюзивного доступа
LOCK TABLES users WRITE, orders READ;
# Выполнить операции
# ...
UNLOCK TABLES;
# Блокировка строк на уровне транзакции
BEGIN;
SELECT * FROM accounts WHERE id = 1 FOR UPDATE;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
COMMIT;
```

### Точки сохранения: `SAVEPOINT` / `ROLLBACK TO`

Создание точек отката внутри транзакций.

```sql
BEGIN;
INSERT INTO users (username) VALUES ('user1');
SAVEPOINT sp1;
INSERT INTO users (username) VALUES ('user2');
SAVEPOINT sp2;
INSERT INTO users (username) VALUES ('user3');
# Откат к точке сохранения
ROLLBACK TO sp1;
COMMIT;
```

## Расширенные техники SQL

### Общие табличные выражения (CTE): `WITH`

Создание временных наборов результатов для сложных запросов.

```sql
# Простой CTE
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

### Хранимые процедуры: `CREATE PROCEDURE`

Создание многократно используемых процедур базы данных.

```sql
# Создать хранимую процедуру
DELIMITER //
CREATE PROCEDURE GetUserOrders(IN user_id INT)
BEGIN
    SELECT o.*, p.product_name
    FROM orders o
    JOIN products p ON o.product_id = p.id
    WHERE o.user_id = user_id;
END //
DELIMITER ;
# Вызвать процедуру
CALL GetUserOrders(123);
```

### Триггеры: `CREATE TRIGGER`

Автоматическое выполнение кода в ответ на события базы данных.

```sql
# Создать триггер для аудита
CREATE TRIGGER user_update_audit
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    INSERT INTO user_audit (user_id, old_email, new_email, changed_at)
    VALUES (NEW.id, OLD.email, NEW.email, NOW());
END;
# Показать триггеры
SHOW TRIGGERS;
```

### Представления (Views): `CREATE VIEW`

Создание виртуальных таблиц на основе результатов запросов.

```sql
# Создать представление
CREATE VIEW active_users AS
SELECT id, username, email, created_at
FROM users
WHERE status = 'active' AND last_login > DATE_SUB(NOW(), INTERVAL 30 DAY);
# Использовать представление как таблицу
SELECT * FROM active_users WHERE username LIKE 'john%';
# Удалить представление
DROP VIEW active_users;
```

## Установка и настройка MySQL

### Установка: Менеджеры пакетов

Установка MySQL с использованием системных менеджеров пакетов.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# CentOS/RHEL
sudo yum install mysql-server
# macOS с Homebrew
brew install mysql
# Запустить службу MySQL
sudo systemctl start mysql
```

### Docker: `docker run mysql`

Запуск MySQL в контейнерах Docker для разработки.

```bash
# Запустить контейнер MySQL
docker run --name mysql-dev -e MYSQL_ROOT_PASSWORD=password -p 3306:3306 -d mysql:8.0
# Подключиться к контейнеризованному MySQL
docker exec -it mysql-dev mysql -u root -p
# Создать базу данных в контейнере
docker exec -it mysql-dev mysql -u root -p -e "CREATE DATABASE testdb;"
```

### Начальная настройка и безопасность

Обеспечение безопасности установки MySQL и проверка настройки.

```bash
# Запустить скрипт безопасности
sudo mysql_secure_installation
# Подключиться к MySQL
mysql -u root -p
# Показать версию MySQL
SELECT VERSION();
# Проверить статус подключения
STATUS;
# Установить пароль root
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
```

## Конфигурация и настройки

### Файлы конфигурации: `my.cnf`

Изменение настроек конфигурации сервера MySQL.

```ini
# Общие расположения конфигурации
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

### Конфигурация в реальном времени: `SET GLOBAL`

Изменение настроек во время работы MySQL.

```sql
# Установить глобальные переменные
SET GLOBAL max_connections = 500;
SET GLOBAL slow_query_log = ON;
# Показать текущие настройки
SHOW VARIABLES LIKE 'max_connections';
SHOW GLOBAL STATUS LIKE 'Slow_queries';
```

### Тюнинг производительности: Память и кэш

Оптимизация настроек производительности MySQL.

```sql
# Показать использование памяти
SHOW VARIABLES LIKE '%buffer_pool_size%';
SHOW VARIABLES LIKE '%query_cache%';
# Мониторинг производительности
SHOW STATUS LIKE 'Qcache%';
SHOW STATUS LIKE 'Created_tmp%';
# Настройки InnoDB
SET GLOBAL innodb_buffer_pool_size = 2147483648; -- 2GB
```

### Конфигурация логирования: Журналы ошибок и запросов

Настройка логирования MySQL для мониторинга и отладки.

```sql
# Включить логирование общих запросов
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/query.log';
# Журнал медленных запросов
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
# Показать настройки логов
SHOW VARIABLES LIKE '%log%';
```

## Связанные ссылки

- <router-link to="/database">Шпаргалка по базам данных</router-link>
- <router-link to="/postgresql">Шпаргалка по PostgreSQL</router-link>
- <router-link to="/sqlite">Шпаргалка по SQLite</router-link>
- <router-link to="/mongodb">Шпаргалка по MongoDB</router-link>
- <router-link to="/redis">Шпаргалка по Redis</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>

---
title: 'Шпаргалка по PostgreSQL'
description: 'Изучите PostgreSQL с нашей полной шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/postgresql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
PostgreSQL Шпаргалка
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/postgresql">Изучите PostgreSQL с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите управление базами данных PostgreSQL с помощью практических лабораторных работ и сценариев реального мира. LabEx предлагает комплексные курсы по PostgreSQL, охватывающие основные операции SQL, расширенный запрос, оптимизацию производительности, администрирование баз данных и безопасность. Освойте разработку и администрирование реляционных баз данных корпоративного уровня.
</base-disclaimer-content>
</base-disclaimer>

## Соединение и Настройка Базы Данных

### Подключение к PostgreSQL: `psql`

Подключение к локальной или удаленной базе данных PostgreSQL с помощью инструмента командной строки psql.

```bash
# Подключение к локальной базе данных
psql -U username -d database_name
# Подключение к удаленной базе данных
psql -h hostname -p 5432 -U username -d database_name
# Подключение с запросом пароля
psql -U postgres -W
# Подключение с использованием строки соединения
psql "host=localhost port=5432 dbname=mydb user=myuser"
```

### Создание Базы Данных: `CREATE DATABASE`

Создание новой базы данных в PostgreSQL с помощью команды CREATE DATABASE.

```sql
# Создание новой базы данных
CREATE DATABASE mydatabase;
# Создание базы данных с владельцем
CREATE DATABASE mydatabase OWNER myuser;
# Создание базы данных с кодировкой
CREATE DATABASE mydatabase
  WITH ENCODING 'UTF8'
  LC_COLLATE='en_US.UTF-8'
  LC_CTYPE='en_US.UTF-8';
```

### Список Баз Данных: `\l`

Вывод списка всех баз данных на сервере PostgreSQL.

```bash
# Вывод списка всех баз данных
\l
# Вывод списка баз данных с подробной информацией
\l+
# Подключение к другой базе данных
\c database_name
```

### Основные Команды psql

Важные команды терминала psql для навигации и получения информации.

```bash
# Выход из psql
\q
# Получить справку по командам SQL
\help CREATE TABLE
# Получить справку по командам psql
\?
# Показать текущую базу данных и пользователя
\conninfo
# Выполнение системных команд
\! ls
# Вывод списка всех таблиц
\dt
# Вывод списка всех таблиц с деталями
\dt+
# Описание конкретной таблицы
\d table_name
# Вывод списка всех схем
\dn
# Вывод списка всех пользователей/ролей
\du
```

### Версия и Настройки

Проверка версии PostgreSQL и настроек конфигурации.

```sql
# Проверка версии PostgreSQL
SELECT version();
# Показать все настройки
SHOW ALL;
# Показать конкретную настройку
SHOW max_connections;
# Установка параметра конфигурации
SET work_mem = '256MB';
```

## Создание и Управление Таблицами

### Создание Таблицы: `CREATE TABLE`

Определение новых таблиц с колонками, типами данных и ограничениями.

```sql
# Базовое создание таблицы
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

# Таблица с внешним ключом
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending'
);
```

### Изменение Таблиц: `ALTER TABLE`

Добавление, изменение или удаление колонок и ограничений из существующих таблиц.

```sql
# Добавить новую колонку
ALTER TABLE users ADD COLUMN phone VARCHAR(15);
# Изменить тип колонки
ALTER TABLE users ALTER COLUMN phone TYPE VARCHAR(20);
# Удалить колонку
ALTER TABLE users DROP COLUMN phone;
# Добавить ограничение
ALTER TABLE users ADD CONSTRAINT unique_email
    UNIQUE (email);
```

### Удаление и Очистка: `DROP/TRUNCATE`

Удаление таблиц или очистка всех данных из таблиц.

```sql
# Полное удаление таблицы
DROP TABLE IF EXISTS old_table;
# Удалить все данные, но сохранить структуру
TRUNCATE TABLE users;
# Очистка с перезапуском счетчика
TRUNCATE TABLE users RESTART IDENTITY;
```

### Типы Данных и Ограничения

Основные типы данных PostgreSQL для различных видов данных.

```sql
# Числовые типы
INTEGER, BIGINT, SMALLINT
DECIMAL(10,2), NUMERIC(10,2)
REAL, DOUBLE PRECISION

# Символьные типы
CHAR(n), VARCHAR(n), TEXT

# Типы даты/времени
DATE, TIME, TIMESTAMP
TIMESTAMPTZ (с часовым поясом)

# Логический и другие
BOOLEAN
JSON, JSONB
UUID
ARRAY (например, INTEGER[])

# Первичный ключ
id SERIAL PRIMARY KEY

# Внешний ключ
user_id INTEGER REFERENCES users(id)

# Ограничение UNIQUE
email VARCHAR(100) UNIQUE

# Ограничение CHECK
age INTEGER CHECK (age >= 0)

# Not null
name VARCHAR(50) NOT NULL
```

### Индексы: `CREATE INDEX`

Улучшение производительности запросов с помощью индексов базы данных.

```sql
# Базовый индекс
CREATE INDEX idx_username ON users(username);
# Уникальный индекс
CREATE UNIQUE INDEX idx_unique_email
    ON users(email);
# Составной индекс
CREATE INDEX idx_user_date
    ON orders(user_id, created_at);
# Частичный индекс
CREATE INDEX idx_active_users
    ON users(username) WHERE active = true;
# Удалить индекс
DROP INDEX IF EXISTS idx_username;
```

### Последовательности: `CREATE SEQUENCE`

Автоматическая генерация уникальных числовых значений.

```sql
# Создать последовательность
CREATE SEQUENCE user_id_seq;
# Использовать последовательность в таблице
CREATE TABLE users (
    id INTEGER DEFAULT nextval('user_id_seq'),
    username VARCHAR(50)
);
# Сбросить последовательность
ALTER SEQUENCE user_id_seq RESTART WITH 1000;
```

## Операции CRUD

### Вставка Данных: `INSERT`

Добавление новых записей в таблицы базы данных.

```sql
# Вставка одной записи
INSERT INTO users (username, email)
VALUES ('john_doe', 'john@example.com');
# Вставка нескольких записей
INSERT INTO users (username, email) VALUES
    ('alice', 'alice@example.com'),
    ('bob', 'bob@example.com');
# Вставка с возвратом значений
INSERT INTO users (username, email)
VALUES ('jane', 'jane@example.com')
RETURNING id, created_at;
# Вставка из выборки
INSERT INTO archive_users
SELECT * FROM users WHERE active = false;
```

### Обновление Данных: `UPDATE`

Изменение существующих записей в таблицах базы данных.

```sql
# Обновление конкретных записей
UPDATE users
SET email = 'newemail@example.com'
WHERE username = 'john_doe';
# Обновление нескольких колонок
UPDATE users
SET email = 'new@example.com',
    updated_at = NOW()
WHERE id = 1;
# Обновление с подзапросом
UPDATE orders
SET total = (SELECT SUM(price) FROM order_items
            WHERE order_id = orders.id);
```

### Выборка Данных: `SELECT`

Запрос и извлечение данных из таблиц базы данных.

```sql
# Базовая выборка
SELECT * FROM users;
# Выборка конкретных колонок
SELECT id, username, email FROM users;
# Выборка с условиями
SELECT * FROM users
WHERE active = true AND created_at > '2024-01-01';
# Выборка с сортировкой и ограничением
SELECT * FROM users
ORDER BY created_at DESC
LIMIT 10 OFFSET 20;
```

### Удаление Данных: `DELETE`

Удаление записей из таблиц базы данных.

```sql
# Удаление конкретных записей
DELETE FROM users
WHERE active = false;
# Удаление с подзапросом
DELETE FROM orders
WHERE user_id IN (
    SELECT id FROM users WHERE active = false
);
# Удаление всех записей
DELETE FROM temp_table;
# Удаление с возвратом
DELETE FROM users
WHERE id = 5
RETURNING *;
```

## Расширенный Запрос

### Соединения: `INNER/LEFT/RIGHT JOIN`

Объединение данных из нескольких таблиц с использованием различных типов соединений.

```sql
# Внутреннее соединение (Inner join)
SELECT u.username, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# Левое соединение (Left join)
SELECT u.username, o.total
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# Множественные соединения
SELECT u.username, o.total, p.name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

### Подзапросы и CTE

Использование вложенных запросов и общих табличных выражений для сложных операций.

```sql
# Подзапрос в WHERE
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders);
# Общее табличное выражение (CTE)
WITH active_users AS (
    SELECT * FROM users WHERE active = true
)
SELECT au.username, COUNT(o.id) as order_count
FROM active_users au
LEFT JOIN orders o ON au.id = o.user_id
GROUP BY au.username;
```

### Агрегация: `GROUP BY`

Группировка данных и применение агрегатных функций для анализа.

```sql
# Базовая группировка
SELECT status, COUNT(*) as count
FROM orders
GROUP BY status;
# Множественные агрегации
SELECT user_id,
       COUNT(*) as order_count,
       SUM(total) as total_spent,
       AVG(total) as avg_order
FROM orders
GROUP BY user_id
HAVING COUNT(*) > 5;
```

### Оконные Функции

Выполнение вычислений по связанным строкам без группировки.

```sql
# Нумерация строк
SELECT username, email,
       ROW_NUMBER() OVER (ORDER BY created_at) as row_num
FROM users;
# Накопительные суммы
SELECT date, amount,
       SUM(amount) OVER (ORDER BY date) as running_total
FROM sales;
# Ранжирование
SELECT username, score,
       RANK() OVER (ORDER BY score DESC) as rank
FROM user_scores;
```

## Импорт и Экспорт Данных

### Импорт CSV: `COPY`

Импорт данных из CSV-файлов в таблицы PostgreSQL.

```sql
# Импорт из CSV файла
COPY users(username, email, age)
FROM '/path/to/users.csv'
DELIMITER ',' CSV HEADER;
# Импорт с конкретными опциями
COPY products
FROM '/path/to/products.csv'
WITH (FORMAT csv, HEADER true, DELIMITER ';');
# Импорт из stdin
\copy users(username, email) FROM STDIN WITH CSV;
```

### Экспорт CSV: `COPY TO`

Экспорт данных PostgreSQL в CSV-файлы.

```sql
# Экспорт в CSV файл
COPY users TO '/path/to/users_export.csv'
WITH (FORMAT csv, HEADER true);
# Экспорт результатов запроса
COPY (SELECT username, email FROM users WHERE active = true)
TO '/path/to/active_users.csv' CSV HEADER;
# Экспорт в stdout
\copy (SELECT * FROM orders) TO STDOUT WITH CSV HEADER;
```

### Резервное Копирование и Восстановление: `pg_dump`

Создание резервных копий базы данных и восстановление из файлов резервных копий.

```bash
# Дамп всей базы данных
pg_dump -U username -h hostname database_name > backup.sql
# Дамп конкретной таблицы
pg_dump -U username -t table_name database_name > table_backup.sql
# Сжатый дамп
pg_dump -U username -Fc database_name > backup.dump
# Восстановление из резервной копии
psql -U username -d database_name < backup.sql
# Восстановление сжатой резервной копии
pg_restore -U username -d database_name backup.dump
```

### Операции с JSON Данными

Работа с типами данных JSON и JSONB для полуструктурированных данных.

```sql
# Вставка JSON данных
INSERT INTO products (name, metadata)
VALUES ('Laptop', '{"brand": "Dell", "price": 999.99}');
# Запрос полей JSON
SELECT name, metadata->>'brand' as brand
FROM products
WHERE metadata->>'price'::numeric > 500;
# Операции с JSON массивами
SELECT name FROM products
WHERE metadata->'features' ? 'wireless';
```

## Управление Пользователями и Безопасность

### Создание Пользователей и Ролей

Управление доступом к базе данных с помощью пользователей и ролей.

```sql
# Создать пользователя
CREATE USER myuser WITH PASSWORD 'secretpassword';
# Создать роль
CREATE ROLE readonly_user;
# Создать пользователя с конкретными привилегиями
CREATE USER admin_user WITH
    CREATEDB CREATEROLE PASSWORD 'adminpass';
# Назначить роль пользователю
GRANT readonly_user TO myuser;
```

### Разрешения: `GRANT/REVOKE`

Управление доступом к объектам базы данных через разрешения.

```sql
# Предоставить права на таблицу
GRANT SELECT, INSERT ON users TO myuser;
# Предоставить все привилегии на таблицу
GRANT ALL ON orders TO admin_user;
# Предоставить права на базу данных
GRANT CONNECT ON DATABASE mydb TO myuser;
# Отозвать разрешения
REVOKE INSERT ON users FROM myuser;
```

### Просмотр Информации о Пользователях

Проверка существующих пользователей и их разрешений.

```sql
# Список всех пользователей
\du
# Просмотр разрешений на таблицу
SELECT table_name, privilege_type, grantee
FROM information_schema.table_privileges
WHERE table_schema = 'public';
# Проверка текущего пользователя
SELECT current_user;
# Просмотр членства в ролях
SELECT r.rolname, r.rolsuper, r.rolcreaterole
FROM pg_roles r;
```

### Пароль и Безопасность

Управление паролями пользователей и настройками безопасности.

```sql
# Изменить пароль пользователя
ALTER USER myuser PASSWORD 'newpassword';
# Установить срок действия пароля
ALTER USER myuser VALID UNTIL '2025-12-31';
# Создать пользователя без возможности входа
CREATE ROLE reporting_role NOLOGIN;
# Включить/отключить пользователя
ALTER USER myuser WITH NOLOGIN;
ALTER USER myuser WITH LOGIN;
```

## Производительность и Мониторинг

### Анализ Запросов: `EXPLAIN`

Анализ планов выполнения запросов и оптимизация производительности.

```sql
# Показать план выполнения запроса
EXPLAIN SELECT * FROM users WHERE active = true;
# Анализ с фактическими статистиками выполнения
EXPLAIN ANALYZE
SELECT u.username, COUNT(o.id)
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.username;
# Подробная информация о выполнении
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT * FROM large_table WHERE indexed_col = 'value';
```

### Обслуживание Базы Данных: `VACUUM`

Поддержание производительности базы данных с помощью регулярных операций очистки.

```sql
# Базовый vacuum
VACUUM users;
# Полный vacuum с анализом
VACUUM FULL ANALYZE users;
# Статус авто-вакуума
SELECT schemaname, tablename, last_vacuum, last_autovacuum
FROM pg_stat_user_tables;
# Переиндексация таблицы
REINDEX TABLE users;
```

### Мониторинг Запросов

Отслеживание активности базы данных и выявление проблем с производительностью.

```sql
# Текущая активность
SELECT pid, usename, query, state
FROM pg_stat_activity
WHERE state != 'idle';
# Долго выполняющиеся запросы
SELECT pid, now() - query_start as duration, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC;
# Убить конкретный запрос
SELECT pg_terminate_backend(pid) WHERE pid = 12345;
```

### Статистика Базы Данных

Получение информации об использовании базы данных и метриках производительности.

```sql
# Статистика таблиц
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del
FROM pg_stat_user_tables;
# Статистика использования индексов
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes;
# Размер базы данных
SELECT pg_size_pretty(pg_database_size('mydatabase'));
```

## Расширенные Возможности

### Представления: `CREATE VIEW`

Создание виртуальных таблиц для упрощения сложных запросов и предоставления абстракции данных.

```sql
# Создать простое представление
CREATE VIEW active_users AS
SELECT id, username, email
FROM users WHERE active = true;
# Создать представление с соединениями
CREATE OR REPLACE VIEW order_summary AS
SELECT u.username, COUNT(o.id) as total_orders,
       SUM(o.total) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.username;
# Удалить представление
DROP VIEW IF EXISTS order_summary;
```

### Триггеры и Функции

Автоматизация операций базы данных с помощью хранимых процедур и триггеров.

```sql
# Создать функцию
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
# Создать триггер
CREATE TRIGGER update_user_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();
```

### Транзакции

Обеспечение согласованности данных с помощью управления транзакциями.

```sql
# Начать транзакцию
BEGIN;
UPDATE accounts SET balance = balance - 100
WHERE id = 1;
UPDATE accounts SET balance = balance + 100
WHERE id = 2;
# Зафиксировать транзакцию
COMMIT;
# Откатить при необходимости
ROLLBACK;
# Точки сохранения
SAVEPOINT my_savepoint;
ROLLBACK TO my_savepoint;
```

### Конфигурация и Тюнинг

Оптимизация настроек сервера PostgreSQL для лучшей производительности.

```sql
# Просмотр текущей конфигурации
SHOW shared_buffers;
SHOW max_connections;
# Установка параметров конфигурации
SET work_mem = '256MB';
SET random_page_cost = 1.1;
# Перезагрузка конфигурации
SELECT pg_reload_conf();
# Показать расположение файла конфигурации
SHOW config_file;
```

## Конфигурация и Советы psql

### Файлы Соединения: `.pgpass`

Безопасное хранение учетных данных базы данных для автоматической аутентификации.

```bash
# Создать файл .pgpass (формат: hostname:port:database:username:password)
echo "localhost:5432:mydatabase:myuser:mypassword" >> ~/.pgpass
# Установить правильные разрешения
chmod 600 ~/.pgpass
# Использовать файл сервиса соединения
# ~/.pg_service.conf
[mydb]
host=localhost
port=5432
dbname=mydatabase
user=myuser
```

### Конфигурация psql: `.psqlrc`

Настройка параметров запуска psql и поведения.

```bash
# Создать файл ~/.psqlrc с пользовательскими настройками
\set QUIET on
\timing on
\set PROMPT1 '%n@%M:%> %`date` %R%# '
\set HISTSIZE 5000
\set COMP_KEYWORD_CASE upper
\x auto
\set QUIET off
# Пользовательские псевдонимы
\set show_slow_queries 'SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;'
```

### Переменные Окружения

Установка переменных окружения PostgreSQL для упрощения подключений.

```bash
# Установить в вашем shell профиле
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=mydatabase
export PGUSER=myuser
# Затем просто подключиться с помощью
psql
# Или использовать конкретное окружение
PGDATABASE=testdb psql
```

### Информация о Базе Данных

Получение информации об объектах и структуре базы данных.

```bash
# Список баз данных
\l, \l+
# Список таблиц в текущей базе данных
\dt, \dt+
# Список представлений
\dv, \dv+
# Список индексов
\di, \di+
# Список функций
\df, \df+
# Список последовательностей
\ds, \ds+
# Описание структуры таблицы
\d table_name
\d+ table_name
# Список ограничений таблицы
\d+ table_name
# Показать права на таблицу
\dp table_name
\z table_name
# Список внешних ключей
SELECT * FROM information_schema.table_constraints
WHERE constraint_type = 'FOREIGN KEY';
```

### Вывод и Форматирование

Управление тем, как psql отображает результаты запросов и вывод.

```bash
# Переключение расширенного вывода
\x
# Изменить формат вывода
\H  -- Вывод в формате HTML
\t  -- Только кортежи (без заголовков)
# Вывод в файл
\o filename.txt
SELECT * FROM users;
\o  -- Остановить вывод в файл
# Выполнение SQL из файла
\i script.sql
# Редактировать запрос во внешнем редакторе
\e
```

### Время и История

Отслеживание производительности запросов и управление историей команд.

```bash
# Переключить отображение времени
\timing
# Показать историю команд
\s
# Сохранить историю команд в файл
\s filename.txt
# Очистить экран
\! clear  -- Linux/Mac
\! cls   -- Windows
# Показать последнюю ошибку
\errverbose
```

## Соответствующие Ссылки

- <router-link to="/database">Шпаргалка по Базам Данных</router-link>
- <router-link to="/mysql">Шпаргалка по MySQL</router-link>
- <router-link to="/sqlite">Шпаргалка по SQLite</router-link>
- <router-link to="/mongodb">Шпаргалка по MongoDB</router-link>
- <router-link to="/redis">Шпаргалка по Redis</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>

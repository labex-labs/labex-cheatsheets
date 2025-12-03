---
title: 'Шпаргалка по SQLite | LabEx'
description: 'Изучите базу данных SQLite с помощью этой исчерпывающей шпаргалки. Краткий справочник по синтаксису SQL SQLite, транзакциям, триггерам, представлениям и легковесному управлению базами данных для приложений.'
pdfUrl: '/cheatsheets/pdf/sqlite-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по SQLite
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/sqlite">Изучите SQLite с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите управление базами данных SQLite с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по SQLite, охватывающие основные операции SQL, манипулирование данными, оптимизацию запросов, проектирование баз данных и настройку производительности. Освойте разработку легковесных баз данных и эффективное управление данными.
</base-disclaimer-content>
</base-disclaimer>

## Создание базы данных и подключение

### Создание базы данных: `sqlite3 database.db`

Создает новый файл базы данных SQLite.

```bash
# Создать или открыть базу данных
sqlite3 mydata.db
# Создать базу данных в памяти (временную)
sqlite3 :memory:
# Создать базу данных командой
.open mydata.db
# Показать все присоединенные базы данных
.databases
# Показать схему всех таблиц
.schema
# Показать список таблиц
.tables
# Выход из SQLite
.exit
# Альтернативная команда выхода
.quit
```

### Информация о базе данных: `.databases`

Перечисляет все присоединенные базы данных и их файлы.

```sql
-- Присоединить другую базу данных
ATTACH DATABASE 'backup.db' AS backup;
-- Запрос из присоединенной базы данных
SELECT * FROM backup.users;
-- Отсоединить базу данных
DETACH DATABASE backup;
```

### Выход из SQLite: `.exit` или `.quit`

Закрывает интерфейс командной строки SQLite.

```bash
.exit
.quit
```

### Резервное копирование базы данных: `.backup`

Создает резервную копию текущей базы данных.

```bash
# Резервное копирование в файл
.backup backup.db
# Восстановление из резервной копии
.restore backup.db
# Экспорт в SQL-файл
.output backup.sql
.dump
# Импорт SQL-скрипта
.read backup.sql
```

## Создание таблицы и схема

### Создание таблицы: `CREATE TABLE`

Создает новую таблицу в базе данных с колонками и ограничениями.

```sql
-- Базовое создание таблицы
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    age INTEGER,
    created_date DATE DEFAULT CURRENT_TIMESTAMP
);

-- Таблица с внешним ключом
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    amount REAL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

<BaseQuiz id="sqlite-create-table-1" correct="A">
  <template #question>
    Что делает `INTEGER PRIMARY KEY AUTOINCREMENT` в SQLite?
  </template>
  
  <BaseQuizOption value="A" correct>Создает целочисленный первичный ключ с автоматической нумерацией</BaseQuizOption>
  <BaseQuizOption value="B">Создает текстовый первичный ключ</BaseQuizOption>
  <BaseQuizOption value="C">Создает ограничение внешнего ключа</BaseQuizOption>
  <BaseQuizOption value="D">Создает уникальный индекс</BaseQuizOption>
  
  <BaseQuizAnswer>
    `INTEGER PRIMARY KEY AUTOINCREMENT` создает целочисленный столбец, который автоматически увеличивается для каждой новой строки и служит первичным ключом. Это гарантирует, что каждая строка имеет уникальный идентификатор.
  </BaseQuizAnswer>
</BaseQuiz>

### Типы данных: `INTEGER`, `TEXT`, `REAL`, `BLOB`

SQLite использует динамическую типизацию с классами хранения для гибкого хранения данных.

```sql
-- Общие типы данных
CREATE TABLE products (
    id INTEGER,           -- Целые числа
    name TEXT,           -- Текстовые строки
    price REAL,          -- Числа с плавающей запятой
    image BLOB,          -- Двоичные данные
    active BOOLEAN,      -- Булево (хранится как INTEGER)
    created_at DATETIME  -- Дата и время
);
```

### Ограничения: `PRIMARY KEY`, `NOT NULL`, `UNIQUE`

Определяют ограничения для обеспечения целостности данных и связей между таблицами.

```sql
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL,
    salary REAL CHECK(salary > 0),
    manager_id INTEGER REFERENCES employees(id)
);
```

## Вставка и изменение данных

### Вставка данных: `INSERT INTO`

Добавляет новые записи в таблицы с одной или несколькими строками.

```sql
-- Вставка одной записи
INSERT INTO users (name, email, age)
VALUES ('John Doe', 'john@email.com', 30);

-- Вставка нескольких записей
INSERT INTO users (name, email, age) VALUES
    ('Jane Smith', 'jane@email.com', 25),
    ('Bob Wilson', 'bob@email.com', 35);

-- Вставка со всеми столбцами
INSERT INTO users VALUES
    (NULL, 'Alice Brown', 'alice@email.com', 28, datetime('now'));
```

### Обновление данных: `UPDATE SET`

Изменяет существующие записи на основе условий.

```sql
-- Обновление одного столбца
UPDATE users SET age = 31 WHERE name = 'John Doe';

-- Обновление нескольких столбцов
UPDATE users SET
    email = 'newemail@example.com',
    age = age + 1
WHERE id = 1;

-- Обновление с подзапросом
UPDATE products SET price = price * 1.1
WHERE category = 'Electronics';
```

<BaseQuiz id="sqlite-update-1" correct="D">
  <template #question>
    Что произойдет, если вы забудете предложение WHERE в операторе UPDATE?
  </template>
  
  <BaseQuizOption value="A">Обновление завершится ошибкой</BaseQuizOption>
  <BaseQuizOption value="B">Обновляется только первая строка</BaseQuizOption>
  <BaseQuizOption value="C">Ничего не произойдет</BaseQuizOption>
  <BaseQuizOption value="D" correct>Обновляются все строки в таблице</BaseQuizOption>
  
  <BaseQuizAnswer>
    Без предложения WHERE оператор UPDATE изменит все строки в таблице. Всегда используйте WHERE, чтобы указать, какие строки следует обновить, чтобы избежать случайного изменения непреднамеренных данных.
  </BaseQuizAnswer>
</BaseQuiz>

### Удаление данных: `DELETE FROM`

Удаляет записи из таблиц на основе указанных условий.

```sql
-- Удаление конкретных записей
DELETE FROM users WHERE age < 18;

-- Удаление всех записей (сохранение структуры таблицы)
DELETE FROM users;

-- Удаление с подзапросом
DELETE FROM orders
WHERE user_id IN (SELECT id FROM users WHERE active = 0);
```

### Upsert: `INSERT OR REPLACE`

Вставляет новые записи или обновляет существующие на основе конфликтов.

```sql
-- Вставка или замена при конфликте
INSERT OR REPLACE INTO users (id, name, email)
VALUES (1, 'Updated Name', 'updated@email.com');

-- Вставка или игнорирование дубликатов
INSERT OR IGNORE INTO users (name, email)
VALUES ('Duplicate', 'existing@email.com');
```

<BaseQuiz id="sqlite-upsert-1" correct="A">
  <template #question>
    В чем разница между `INSERT OR REPLACE` и `INSERT OR IGNORE`?
  </template>
  
  <BaseQuizOption value="A" correct>REPLACE обновляет существующие строки, IGNORE пропускает дубликаты</BaseQuizOption>
  <BaseQuizOption value="B">Разницы нет</BaseQuizOption>
  <BaseQuizOption value="C">REPLACE удаляет строку, IGNORE обновляет ее</BaseQuizOption>
  <BaseQuizOption value="D">REPLACE работает с таблицами, IGNORE работает с представлениями</BaseQuizOption>
  
  <BaseQuizAnswer>
    `INSERT OR REPLACE` заменит существующую строку, если возникнет конфликт (например, дубликат первичного ключа). `INSERT OR IGNORE` просто пропустит вставку, если возникнет конфликт, оставив существующую строку без изменений.
  </BaseQuizAnswer>
</BaseQuiz>

## Запросы данных и выборка

### Базовые запросы: `SELECT`

Запрашивает данные из таблиц с использованием оператора SELECT с различными опциями.

```sql
-- Выбрать все столбцы
SELECT * FROM users;

-- Выбрать определенные столбцы
SELECT name, email FROM users;

-- Выбрать с псевдонимом
SELECT name AS full_name, age AS years_old FROM users;

-- Выбрать уникальные значения
SELECT DISTINCT department FROM employees;
```

<BaseQuiz id="sqlite-select-1" correct="B">
  <template #question>
    Что делает `SELECT DISTINCT`?
  </template>
  
  <BaseQuizOption value="A">Выбирает все строки</BaseQuizOption>
  <BaseQuizOption value="B" correct>Возвращает только уникальные значения, удаляя дубликаты</BaseQuizOption>
  <BaseQuizOption value="C">Выбирает только первую строку</BaseQuizOption>
  <BaseQuizOption value="D">Сортирует результаты</BaseQuizOption>
  
  <BaseQuizAnswer>
    `SELECT DISTINCT` устраняет дублирующиеся строки из результирующего набора, возвращая только уникальные значения. Это полезно, когда вы хотите увидеть все уникальные значения в столбце.
  </BaseQuizAnswer>
</BaseQuiz>

### Фильтрация: `WHERE`

Фильтрует строки с использованием различных условий и операторов сравнения.

```sql
-- Простые условия
SELECT * FROM users WHERE age > 25;
SELECT * FROM users WHERE name = 'John Doe';

-- Множественные условия
SELECT * FROM users WHERE age > 18 AND age < 65;
SELECT * FROM users WHERE department = 'IT' OR salary > 50000;

-- Сопоставление с шаблоном
SELECT * FROM users WHERE email LIKE '%@gmail.com';
SELECT * FROM users WHERE name GLOB 'J*';
```

### Сортировка и ограничение: `ORDER BY` / `LIMIT`

Сортирует результаты и ограничивает количество возвращаемых строк для лучшего управления данными.

```sql
-- Сортировка по возрастанию (по умолчанию)
SELECT * FROM users ORDER BY age;

-- Сортировка по убыванию
SELECT * FROM users ORDER BY age DESC;

-- Множественные столбцы сортировки
SELECT * FROM users ORDER BY department, salary DESC;

-- Ограничение результатов
SELECT * FROM users LIMIT 10;

-- Ограничение с смещением (пагинация)
SELECT * FROM users LIMIT 10 OFFSET 20;
```

### Агрегатные функции: `COUNT`, `SUM`, `AVG`

Выполняет вычисления над группами строк для статистического анализа.

```sql
-- Подсчет записей
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT department) FROM employees;

-- Сумма и среднее
SELECT SUM(salary), AVG(salary) FROM employees;

-- Минимальное и максимальное значения
SELECT MIN(age), MAX(age) FROM users;
```

## Расширенные запросы

### Группировка: `GROUP BY` / `HAVING`

Группирует строки по заданным критериям и фильтрует группы для сводной отчетности.

```sql
-- Группировка по одному столбцу
SELECT department, COUNT(*)
FROM employees
GROUP BY department;

-- Группировка по нескольким столбцам
SELECT department, job_title, AVG(salary)
FROM employees
GROUP BY department, job_title;

-- Фильтрация групп с помощью HAVING
SELECT department, AVG(salary) as avg_salary
FROM employees
GROUP BY department
HAVING avg_salary > 60000;
```

### Подзапросы

Использует вложенные запросы для сложного извлечения данных и условной логики.

```sql
-- Подзапрос в предложении WHERE
SELECT name FROM users
WHERE age > (SELECT AVG(age) FROM users);

-- Подзапрос в предложении FROM
SELECT dept, avg_salary FROM (
    SELECT department as dept, AVG(salary) as avg_salary
    FROM employees
    GROUP BY department
) WHERE avg_salary > 50000;

-- Подзапрос EXISTS
SELECT * FROM users u
WHERE EXISTS (
    SELECT 1 FROM orders o WHERE o.user_id = u.id
);
```

### Объединения: `INNER`, `LEFT`, `RIGHT`

Объединяет данные из нескольких таблиц с использованием различных типов объединений для реляционных запросов.

```sql
-- Внутреннее объединение (Inner join)
SELECT u.name, o.amount
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- Левое объединение (Left join) (показать всех пользователей)
SELECT u.name, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- Самосоединение (Self join)
SELECT e1.name as employee, e2.name as manager
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id;
```

### Операции с множествами: `UNION` / `INTERSECT`

Объединяет результаты нескольких запросов с использованием операций с множествами.

```sql
-- Union (объединение результатов)
SELECT name FROM customers
UNION
SELECT name FROM suppliers;

-- Intersect (общие результаты)
SELECT email FROM users
INTERSECT
SELECT email FROM newsletter_subscribers;

-- Except (разница)
SELECT email FROM users
EXCEPT
SELECT email FROM unsubscribed;
```

## Индексы и производительность

### Создание индексов: `CREATE INDEX`

Создает индексы по столбцам для ускорения запросов и повышения производительности.

```sql
-- Индекс по одному столбцу
CREATE INDEX idx_user_email ON users(email);

-- Индекс по нескольким столбцам
CREATE INDEX idx_order_user_date ON orders(user_id, order_date);

-- Уникальный индекс
CREATE UNIQUE INDEX idx_product_sku ON products(sku);

-- Частичный индекс (с условием)
CREATE INDEX idx_active_users ON users(name) WHERE active = 1;
```

### Анализ запросов: `EXPLAIN QUERY PLAN`

Анализирует планы выполнения запросов для выявления узких мест производительности.

```sql
-- Анализ производительности запроса
EXPLAIN QUERY PLAN SELECT * FROM users WHERE email = 'test@example.com';

-- Проверка использования индекса
EXPLAIN QUERY PLAN SELECT * FROM orders WHERE user_id = 123;
```

### Оптимизация базы данных: `VACUUM` / `ANALYZE`

Оптимизирует файлы базы данных и обновляет статистику для лучшей производительности.

```sql
-- Перестроить базу данных для освобождения места
VACUUM;

-- Обновить статистику индексов
ANALYZE;

-- Проверить целостность базы данных
PRAGMA integrity_check;
```

### Настройки производительности: `PRAGMA`

Настраивает параметры SQLite для оптимальной производительности и поведения.

```sql
-- Установить режим журнала для лучшей производительности
PRAGMA journal_mode = WAL;

-- Установить режим синхронизации
PRAGMA synchronous = NORMAL;

-- Включить ограничения внешних ключей
PRAGMA foreign_keys = ON;

-- Установить размер кэша (в страницах)
PRAGMA cache_size = 10000;
```

## Представления и триггеры

### Представления: `CREATE VIEW`

Создает виртуальные таблицы, которые представляют собой сохраненные запросы для повторного использования доступа к данным.

```sql
-- Создание простого представления
CREATE VIEW active_users AS
SELECT id, name, email
FROM users
WHERE active = 1;

-- Сложное представление с объединениями
CREATE VIEW order_summary AS
SELECT
    u.name,
    COUNT(o.id) as total_orders,
    SUM(o.amount) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- Запрос представления
SELECT * FROM active_users WHERE name LIKE 'J%';

-- Удалить представление
DROP VIEW IF EXISTS order_summary;
```

### Использование представлений

Запрашивает представления как обычные таблицы для упрощения доступа к данным.

```sql
SELECT * FROM active_users;
SELECT * FROM order_summary WHERE total_spent > 1000;
```

### Триггеры: `CREATE TRIGGER`

Автоматически выполняет код в ответ на события базы данных.

```sql
-- Триггер при INSERT
CREATE TRIGGER update_user_count
AFTER INSERT ON users
BEGIN
    UPDATE stats SET user_count = user_count + 1;
END;

-- Триггер при UPDATE
CREATE TRIGGER log_salary_changes
AFTER UPDATE OF salary ON employees
BEGIN
    INSERT INTO audit_log (table_name, action, old_value, new_value)
    VALUES ('employees', 'salary_update', OLD.salary, NEW.salary);
END;

-- Удалить триггер
DROP TRIGGER IF EXISTS update_user_count;
```

## Типы данных и функции

### Функции даты и времени

Обрабатывает операции с датой и временем с помощью встроенных функций SQLite.

```sql
-- Текущая дата/время
SELECT datetime('now');
SELECT date('now');
SELECT time('now');

-- Арифметика дат
SELECT date('now', '+1 day');
SELECT datetime('now', '-1 hour');
SELECT date('now', 'start of month');

-- Форматирование дат
SELECT strftime('%Y-%m-%d %H:%M', 'now');
SELECT strftime('%w', 'now'); -- день недели
```

### Функции строк

Манипулирует текстовыми данными с помощью различных строковых операций.

```sql
-- Манипуляции со строками
SELECT upper(name) FROM users;
SELECT lower(email) FROM users;
SELECT length(name) FROM users;
SELECT substr(name, 1, 3) FROM users;

-- Конкатенация строк
SELECT name || ' - ' || email as display FROM users;
SELECT printf('%s (%d)', name, age) FROM users;

-- Замена строк
SELECT replace(phone, '-', '') FROM users;
```

### Числовые функции

Выполняет математические операции и вычисления.

```sql
-- Математические функции
SELECT abs(-15);
SELECT round(price, 2) FROM products;
SELECT random(); -- случайное число

-- Агрегация с математикой
SELECT department, round(AVG(salary), 2) as avg_salary
FROM employees
GROUP BY department;
```

### Условная логика: `CASE`

Реализует условную логику внутри SQL-запросов.

```sql
-- Простое выражение CASE
SELECT name,
    CASE
        WHEN age < 18 THEN 'Minor'
        WHEN age < 65 THEN 'Adult'
        ELSE 'Senior'
    END as age_category
FROM users;

-- CASE в предложении WHERE
SELECT * FROM products
WHERE CASE WHEN category = 'Electronics' THEN price < 1000
          ELSE price < 100 END;
```

## Транзакции и параллелизм

### Управление транзакциями

Транзакции SQLite полностью соответствуют требованиям ACID для надежных операций с данными.

```sql
-- Базовая транзакция
BEGIN TRANSACTION;
INSERT INTO users (name, email) VALUES ('Test User', 'test@example.com');
UPDATE users SET age = 25 WHERE name = 'Test User';
COMMIT;

-- Транзакция с откатом
BEGIN;
DELETE FROM orders WHERE amount < 10;
-- Проверить результаты, при необходимости отменить
ROLLBACK;

-- Точки сохранения для вложенных транзакций
BEGIN;
SAVEPOINT sp1;
INSERT INTO products (name) VALUES ('Product A');
ROLLBACK TO sp1;
COMMIT;
```

### Блокировка и параллелизм

Управляет блокировками базы данных и параллельным доступом для обеспечения целостности данных.

```sql
-- Проверить статус блокировки
PRAGMA locking_mode;

-- Установить режим WAL для лучшего параллелизма
PRAGMA journal_mode = WAL;

-- Таймаут занятости для ожидания блокировок
PRAGMA busy_timeout = 5000;

-- Проверить текущие подключения к базе данных
.databases
```

## Инструменты командной строки SQLite

### Команды базы данных: `.help`

Получите доступ к справке командной строки SQLite и документации по доступным точечным командам.

```bash
# Показать все доступные команды
.help
# Показать текущие настройки
.show
# Установить формат вывода
.mode csv
.headers on
```

### Импорт/Экспорт: `.import` / `.export`

Передача данных между SQLite и внешними файлами в различных форматах.

```bash
# Импорт CSV-файла
.mode csv
.import data.csv users

# Экспорт в CSV
.headers on
.mode csv
.output users.csv
SELECT * FROM users;
```

### Управление схемой: `.schema` / `.tables`

Просмотр структуры базы данных и определений таблиц для разработки и отладки.

```bash
# Показать все таблицы
.tables
# Показать схему для конкретной таблицы
.schema users
# Показать все схемы
.schema
# Показать информацию о таблице
.mode column
.headers on
PRAGMA table_info(users);
```

### Форматирование вывода: `.mode`

Управляет отображением результатов запросов в интерфейсе командной строки.

```bash
# Различные режимы вывода
.mode csv        # Значения, разделенные запятыми
.mode column     # Выровненные столбцы
.mode html       # Формат HTML-таблицы
.mode json       # Формат JSON
.mode list       # Формат списка
.mode table      # Формат таблицы (по умолчанию)

# Установить ширину столбца
.width 10 15 20

# Сохранить вывод в файл
.output results.txt
SELECT * FROM users;
.output stdout

# Чтение SQL из файла
.read script.sql

# Сменить файл базы данных
.open another_database.db
```

## Конфигурация и настройки

### Настройки базы данных: `PRAGMA`

Управляет поведением SQLite с помощью прагма-инструкций для оптимизации и конфигурации.

```sql
-- Информация о базе данных
PRAGMA database_list;
PRAGMA table_info(users);
PRAGMA foreign_key_list(orders);

-- Настройки производительности
PRAGMA cache_size = 10000;
PRAGMA temp_store = memory;
PRAGMA mmap_size = 268435456;

-- Включить ограничения внешних ключей
PRAGMA foreign_keys = ON;

-- Установить режим безопасного удаления
PRAGMA secure_delete = ON;

-- Проверить ограничения
PRAGMA foreign_key_check;
```

### Настройки безопасности

Настраивает параметры и ограничения, связанные с безопасностью базы данных.

```sql
-- Включить ограничения внешних ключей
PRAGMA foreign_keys = ON;

-- Режим безопасного удаления
PRAGMA secure_delete = ON;

-- Проверить целостность
PRAGMA integrity_check;
```

## Установка и настройка

### Загрузка и установка

Загрузите инструменты SQLite и настройте интерфейс командной строки для вашей операционной системы.

```bash
# Загрузить с sqlite.org
# Для Windows: sqlite-tools-win32-x86-*.zip
# Для Linux/Mac: Используйте менеджер пакетов

# Ubuntu/Debian
sudo apt-get install sqlite3

# macOS с Homebrew
brew install sqlite

# Проверить установку
sqlite3 --version
```

### Создание первой базы данных

Создайте файлы базы данных SQLite и начните работу с данными с помощью простых команд.

```bash
# Создать новую базу данных
sqlite3 myapp.db

# Создать таблицу и добавить данные
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE
);

INSERT INTO users (name, email)
VALUES ('John Doe', 'john@example.com');
```

### Интеграция с языками программирования

Используйте SQLite с различными языками программирования через встроенные или сторонние библиотеки.

```python
# Python (встроенный модуль sqlite3)
import sqlite3
conn = sqlite3.connect('mydb.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users')
```

```javascript
// Node.js (требуется пакет sqlite3)
const sqlite3 = require('sqlite3')
const db = new sqlite3.Database('mydb.db')
db.all('SELECT * FROM users', (err, rows) => {
  console.log(rows)
})
```

```php
// PHP (встроенный PDO SQLite)
$pdo = new PDO('sqlite:mydb.db');
$stmt = $pdo->query('SELECT * FROM users');
```

## Связанные ссылки

- <router-link to="/database">Шпаргалка по базам данных</router-link>
- <router-link to="/mysql">Шпаргалка по MySQL</router-link>
- <router-link to="/postgresql">Шпаргалка по PostgreSQL</router-link>
- <router-link to="/mongodb">Шпаргалка по MongoDB</router-link>
- <router-link to="/redis">Шпаргалка по Redis</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>

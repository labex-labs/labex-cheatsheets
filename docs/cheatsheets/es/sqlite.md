---
title: 'Hoja de Trucos de SQLite | LabEx'
description: 'Aprenda la base de datos SQLite con esta hoja de trucos completa. Referencia rápida para la sintaxis SQL de SQLite, transacciones, disparadores, vistas y gestión ligera de bases de datos para aplicaciones.'
pdfUrl: '/cheatsheets/pdf/sqlite-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de SQLite
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/sqlite">Aprende SQLite con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda la gestión de bases de datos SQLite a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de SQLite que cubren operaciones SQL esenciales, manipulación de datos, optimización de consultas, diseño de bases de datos y ajuste de rendimiento. Domine el desarrollo de bases de datos ligeras y la gestión eficiente de datos.
</base-disclaimer-content>
</base-disclaimer>

## Creación de Base de Datos y Conexión

### Crear Base de Datos: `sqlite3 database.db`

Crea un nuevo archivo de base de datos SQLite.

```bash
# Crear o abrir una base de datos
sqlite3 mydata.db
# Crear base de datos en memoria (temporal)
sqlite3 :memory:
# Crear base de datos con comando
.open mydata.db
# Mostrar todas las bases de datos
.databases
# Mostrar esquema de todas las tablas
.schema
# Mostrar lista de tablas
.tables
# Salir de SQLite
.exit
# Comando de salida alternativo
.quit
```

### Información de Base de Datos: `.databases`

Lista todas las bases de datos adjuntas y sus archivos.

```sql
-- Adjuntar otra base de datos
ATTACH DATABASE 'backup.db' AS backup;
-- Consultar desde la base de datos adjunta
SELECT * FROM backup.users;
-- Desadjuntar base de datos
DETACH DATABASE backup;
```

### Salir de SQLite: `.exit` o `.quit`

Cierra la interfaz de línea de comandos de SQLite.

```bash
.exit
.quit
```

### Copia de Seguridad de Base de Datos: `.backup`

Crea una copia de seguridad de la base de datos actual.

```bash
# Copia de seguridad a un archivo
.backup backup.db
# Restaurar desde copia de seguridad
.restore backup.db
# Exportar a archivo SQL
.output backup.sql
.dump
# Importar script SQL
.read backup.sql
```

## Creación de Esquema y Tablas

### Crear Tabla: `CREATE TABLE`

Crea una nueva tabla en la base de datos con columnas y restricciones.

```sql
-- Creación básica de tabla
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    age INTEGER,
    created_date DATE DEFAULT CURRENT_TIMESTAMP
);

-- Tabla con clave foránea
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    amount REAL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

<BaseQuiz id="sqlite-create-table-1" correct="A">
  <template #question>
    ¿Qué hace <code>INTEGER PRIMARY KEY AUTOINCREMENT</code> en SQLite?
  </template>
  
  <BaseQuizOption value="A" correct>Crea una clave primaria entera que se incrementa automáticamente</BaseQuizOption>
  <BaseQuizOption value="B">Crea una clave primaria de texto</BaseQuizOption>
  <BaseQuizOption value="C">Crea una restricción de clave foránea</BaseQuizOption>
  <BaseQuizOption value="D">Crea un índice único</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>INTEGER PRIMARY KEY AUTOINCREMENT</code> crea una columna entera que se incrementa automáticamente para cada nueva fila y sirve como clave primaria. Esto asegura que cada fila tenga un identificador único.
  </BaseQuizAnswer>
</BaseQuiz>

### Tipos de Datos: `INTEGER`, `TEXT`, `REAL`, `BLOB`

SQLite utiliza tipado dinámico con clases de almacenamiento para un almacenamiento de datos flexible.

```sql
-- Tipos de datos comunes
CREATE TABLE products (
    id INTEGER,           -- Números enteros
    name TEXT,           -- Cadenas de texto
    price REAL,          -- Números de punto flotante
    image BLOB,          -- Datos binarios
    active BOOLEAN,      -- Booleano (almacenado como INTEGER)
    created_at DATETIME  -- Fecha y hora
);
```

### Restricciones: `PRIMARY KEY`, `NOT NULL`, `UNIQUE`

Define restricciones para forzar la integridad de los datos y las relaciones de las tablas.

```sql
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL,
    salary REAL CHECK(salary > 0),
    manager_id INTEGER REFERENCES employees(id)
);
```

## Inserción y Modificación de Datos

### Insertar Datos: `INSERT INTO`

Añade nuevos registros a las tablas con una o múltiples filas.

```sql
-- Insertar un solo registro
INSERT INTO users (name, email, age)
VALUES ('John Doe', 'john@email.com', 30);

-- Insertar múltiples registros
INSERT INTO users (name, email, age) VALUES
    ('Jane Smith', 'jane@email.com', 25),
    ('Bob Wilson', 'bob@email.com', 35);

-- Insertar con todas las columnas
INSERT INTO users VALUES
    (NULL, 'Alice Brown', 'alice@email.com', 28, datetime('now'));
```

### Actualizar Datos: `UPDATE SET`

Modifica registros existentes basándose en condiciones.

```sql
-- Actualizar una sola columna
UPDATE users SET age = 31 WHERE name = 'John Doe';

-- Actualizar múltiples columnas
UPDATE users SET
    email = 'newemail@example.com',
    age = age + 1
WHERE id = 1;

-- Actualizar con subconsulta
UPDATE products SET price = price * 1.1
WHERE category = 'Electronics';
```

<BaseQuiz id="sqlite-update-1" correct="D">
  <template #question>
    ¿Qué sucede si olvidas la cláusula WHERE en una sentencia UPDATE?
  </template>
  
  <BaseQuizOption value="A">La actualización falla</BaseQuizOption>
  <BaseQuizOption value="B">Solo se actualiza la primera fila</BaseQuizOption>
  <BaseQuizOption value="C">No sucede nada</BaseQuizOption>
  <BaseQuizOption value="D" correct>Se actualizan todas las filas de la tabla</BaseQuizOption>
  
  <BaseQuizAnswer>
    Sin una cláusula WHERE, la sentencia UPDATE modificará todas las filas de la tabla. Utiliza siempre WHERE para especificar qué filas deben actualizarse y evitar modificar datos no deseados accidentalmente.
  </BaseQuizAnswer>
</BaseQuiz>

### Eliminar Datos: `DELETE FROM`

Elimina registros de las tablas basándose en condiciones especificadas.

```sql
-- Eliminar registros específicos
DELETE FROM users WHERE age < 18;

-- Eliminar todos los registros (mantener la estructura de la tabla)
DELETE FROM users;

-- Eliminar con subconsulta
DELETE FROM orders
WHERE user_id IN (SELECT id FROM users WHERE active = 0);
```

### Upsert: `INSERT OR REPLACE`

Inserta nuevos registros o actualiza los existentes basándose en conflictos.

```sql
-- Insertar o reemplazar en caso de conflicto
INSERT OR REPLACE INTO users (id, name, email)
VALUES (1, 'Updated Name', 'updated@email.com');

-- Insertar o ignorar duplicados
INSERT OR IGNORE INTO users (name, email)
VALUES ('Duplicate', 'existing@email.com');
```

<BaseQuiz id="sqlite-upsert-1" correct="A">
  <template #question>
    ¿Cuál es la diferencia entre <code>INSERT OR REPLACE</code> e <code>INSERT OR IGNORE</code>?
  </template>
  
  <BaseQuizOption value="A" correct>REPLACE actualiza filas existentes, IGNORE omite duplicados</BaseQuizOption>
  <BaseQuizOption value="B">No hay diferencia</BaseQuizOption>
  <BaseQuizOption value="C">REPLACE elimina la fila, IGNORE la actualiza</BaseQuizOption>
  <BaseQuizOption value="D">REPLACE funciona con tablas, IGNORE funciona con vistas</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>INSERT OR REPLACE</code> reemplazará una fila existente si hay un conflicto (ej. clave primaria duplicada). <code>INSERT OR IGNORE</code> simplemente omitirá la inserción si hay un conflicto, dejando la fila existente sin cambios.
  </BaseQuizAnswer>
</BaseQuiz>

## Consulta y Selección de Datos

### Consultas Básicas: `SELECT`

Consulta datos de tablas usando la sentencia SELECT con varias opciones.

```sql
-- Seleccionar todas las columnas
SELECT * FROM users;

-- Seleccionar columnas específicas
SELECT name, email FROM users;

-- Seleccionar con alias
SELECT name AS full_name, age AS years_old FROM users;

-- Seleccionar valores únicos
SELECT DISTINCT department FROM employees;
```

<BaseQuiz id="sqlite-select-1" correct="B">
  <template #question>
    ¿Qué hace <code>SELECT DISTINCT</code>?
  </template>
  
  <BaseQuizOption value="A">Selecciona todas las filas</BaseQuizOption>
  <BaseQuizOption value="B" correct>Devuelve solo valores únicos, eliminando duplicados</BaseQuizOption>
  <BaseQuizOption value="C">Selecciona solo la primera fila</BaseQuizOption>
  <BaseQuizOption value="D">Ordena los resultados</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>SELECT DISTINCT</code> elimina filas duplicadas del conjunto de resultados, devolviendo solo valores únicos. Esto es útil cuando se desean ver todos los valores únicos en una columna.
  </BaseQuizAnswer>
</BaseQuiz>

### Filtrado: `WHERE`

Filtra filas usando varias condiciones y operadores de comparación.

```sql
-- Condiciones simples
SELECT * FROM users WHERE age > 25;
SELECT * FROM users WHERE name = 'John Doe';

-- Múltiples condiciones
SELECT * FROM users WHERE age > 18 AND age < 65;
SELECT * FROM users WHERE department = 'IT' OR salary > 50000;

-- Coincidencia de patrones
SELECT * FROM users WHERE email LIKE '%@gmail.com';
SELECT * FROM users WHERE name GLOB 'J*';
```

### Ordenación y Limitación: `ORDER BY` / `LIMIT`

Ordena los resultados y limita el número de filas devueltas para una mejor gestión de datos.

```sql
-- Ordenar ascendente (por defecto)
SELECT * FROM users ORDER BY age;

-- Ordenar descendente
SELECT * FROM users ORDER BY age DESC;

-- Múltiples columnas de ordenación
SELECT * FROM users ORDER BY department, salary DESC;

-- Limitar resultados
SELECT * FROM users LIMIT 10;

-- Limitar con desplazamiento (paginación)
SELECT * FROM users LIMIT 10 OFFSET 20;
```

### Funciones de Agregación: `COUNT`, `SUM`, `AVG`

Realiza cálculos sobre grupos de filas para análisis estadístico.

```sql
-- Contar registros
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT department) FROM employees;

-- Suma y promedio
SELECT SUM(salary), AVG(salary) FROM employees;

-- Valores Mínimo y Máximo
SELECT MIN(age), MAX(age) FROM users;
```

## Consultas Avanzadas

### Agrupación: `GROUP BY` / `HAVING`

Agrupa filas por criterios especificados y filtra grupos para informes resumidos.

```sql
-- Agrupar por una sola columna
SELECT department, COUNT(*)
FROM employees
GROUP BY department;

-- Agrupar por múltiples columnas
SELECT department, job_title, AVG(salary)
FROM employees
GROUP BY department, job_title;

-- Filtrar grupos con HAVING
SELECT department, AVG(salary) as avg_salary
FROM employees
GROUP BY department
HAVING avg_salary > 60000;
```

### Subconsultas

Utiliza consultas anidadas para la recuperación compleja de datos y la lógica condicional.

```sql
-- Subconsulta en la cláusula WHERE
SELECT name FROM users
WHERE age > (SELECT AVG(age) FROM users);

-- Subconsulta en la cláusula FROM
SELECT dept, avg_salary FROM (
    SELECT department as dept, AVG(salary) as avg_salary
    FROM employees
    GROUP BY department
) WHERE avg_salary > 50000;

-- Subconsulta EXISTS
SELECT * FROM users u
WHERE EXISTS (
    SELECT 1 FROM orders o WHERE o.user_id = u.id
);
```

### Joins: `INNER`, `LEFT`, `RIGHT`

Combina datos de múltiples tablas utilizando varios tipos de join para consultas relacionales.

```sql
-- Inner join
SELECT u.name, o.amount
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- Left join (mostrar todos los usuarios)
SELECT u.name, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- Self join
SELECT e1.name as employee, e2.name as manager
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id;
```

### Operaciones de Conjunto: `UNION` / `INTERSECT`

Combina resultados de múltiples consultas utilizando operaciones de conjunto.

```sql
-- Union (combinar resultados)
SELECT name FROM customers
UNION
SELECT name FROM suppliers;

-- Intersect (resultados comunes)
SELECT email FROM users
INTERSECT
SELECT email FROM newsletter_subscribers;

-- Except (diferencia)
SELECT email FROM users
EXCEPT
SELECT email FROM unsubscribed;
```

## Índices y Rendimiento

### Crear Índices: `CREATE INDEX`

Crea índices en columnas para acelerar las consultas y mejorar el rendimiento.

```sql
-- Índice de columna única
CREATE INDEX idx_user_email ON users(email);

-- Índice de múltiples columnas
CREATE INDEX idx_order_user_date ON orders(user_id, order_date);

-- Índice único
CREATE UNIQUE INDEX idx_product_sku ON products(sku);

-- Índice parcial (con condición)
CREATE INDEX idx_active_users ON users(name) WHERE active = 1;
```

### Análisis de Consultas: `EXPLAIN QUERY PLAN`

Analiza los planes de ejecución de consultas para identificar cuellos de botella de rendimiento.

```sql
-- Analizar rendimiento de la consulta
EXPLAIN QUERY PLAN SELECT * FROM users WHERE email = 'test@example.com';

-- Comprobar si se utiliza un índice
EXPLAIN QUERY PLAN SELECT * FROM orders WHERE user_id = 123;
```

### Optimización de Base de Datos: `VACUUM` / `ANALYZE`

Optimiza los archivos de la base de datos y actualiza las estadísticas para un mejor rendimiento.

```bash
# Reconstruir la base de datos para recuperar espacio
VACUUM;

-- Actualizar estadísticas de índices
ANALYZE;

-- Comprobar la integridad de la base de datos
PRAGMA integrity_check;
```

### Configuración de Rendimiento: `PRAGMA`

Configura los ajustes de SQLite para un rendimiento y comportamiento óptimos.

```sql
-- Modo journal para mejor rendimiento
PRAGMA journal_mode = WAL;

-- Modo síncrono
PRAGMA synchronous = NORMAL;

-- Habilitar restricciones de clave foránea
PRAGMA foreign_keys = ON;

-- Establecer tamaño de caché (en páginas)
PRAGMA cache_size = 10000;
```

## Vistas y Triggers

### Vistas: `CREATE VIEW`

Crea tablas virtuales que representan consultas almacenadas para acceso a datos reutilizable.

```sql
-- Crear una vista simple
CREATE VIEW active_users AS
SELECT id, name, email
FROM users
WHERE active = 1;

-- Vista compleja con joins
CREATE VIEW order_summary AS
SELECT
    u.name,
    COUNT(o.id) as total_orders,
    SUM(o.amount) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- Consultar una vista
SELECT * FROM active_users WHERE name LIKE 'J%';

-- Eliminar una vista
DROP VIEW IF EXISTS order_summary;
```

### Uso de Vistas

Consulta vistas como tablas regulares para simplificar el acceso a los datos.

```sql
SELECT * FROM active_users;
SELECT * FROM order_summary WHERE total_spent > 1000;
```

### Triggers: `CREATE TRIGGER`

Ejecuta automáticamente código en respuesta a eventos de la base de datos.

```sql
-- Trigger en INSERT
CREATE TRIGGER update_user_count
AFTER INSERT ON users
BEGIN
    UPDATE stats SET user_count = user_count + 1;
END;

-- Trigger en UPDATE
CREATE TRIGGER log_salary_changes
AFTER UPDATE OF salary ON employees
BEGIN
    INSERT INTO audit_log (table_name, action, old_value, new_value)
    VALUES ('employees', 'salary_update', OLD.salary, NEW.salary);
END;

-- Eliminar trigger
DROP TRIGGER IF EXISTS update_user_count;
```

## Tipos de Datos y Funciones

### Funciones de Fecha y Hora

Maneja operaciones de fecha y hora con las funciones integradas de SQLite.

```sql
-- Fecha/hora actual
SELECT datetime('now');
SELECT date('now');
SELECT time('now');

-- Aritmética de fechas
SELECT date('now', '+1 day');
SELECT datetime('now', '-1 hour');
SELECT date('now', 'start of month');

-- Formatear fechas
SELECT strftime('%Y-%m-%d %H:%M', 'now');
SELECT strftime('%w', 'now'); -- día de la semana
```

### Funciones de Cadena

Manipula datos de texto con varias operaciones de cadena.

```sql
-- Manipulación de cadenas
SELECT upper(name) FROM users;
SELECT lower(email) FROM users;
SELECT length(name) FROM users;
SELECT substr(name, 1, 3) FROM users;

-- Concatenación de cadenas
SELECT name || ' - ' || email as display FROM users;
SELECT printf('%s (%d)', name, age) FROM users;

-- Reemplazo de cadenas
SELECT replace(phone, '-', '') FROM users;
```

### Funciones Numéricas

Realiza operaciones matemáticas y cálculos.

```sql
-- Funciones matemáticas
SELECT abs(-15);
SELECT round(price, 2) FROM products;
SELECT random(); -- número aleatorio

-- Agregación con matemáticas
SELECT department, round(AVG(salary), 2) as avg_salary
FROM employees
GROUP BY department;
```

### Lógica Condicional: `CASE`

Implementa lógica condicional dentro de las consultas SQL.

```sql
-- Sentencia CASE simple
SELECT name,
    CASE
        WHEN age < 18 THEN 'Minor'
        WHEN age < 65 THEN 'Adult'
        ELSE 'Senior'
    END as age_category
FROM users;

-- CASE en la cláusula WHERE
SELECT * FROM products
WHERE CASE WHEN category = 'Electronics' THEN price < 1000
          ELSE price < 100 END;
```

## Transacciones y Concurrencia

### Control de Transacciones

Las transacciones de SQLite son totalmente compatibles con ACID para operaciones de datos fiables.

```sql
-- Transacción básica
BEGIN TRANSACTION;
INSERT INTO users (name, email) VALUES ('Test User', 'test@example.com');
UPDATE users SET age = 25 WHERE name = 'Test User';
COMMIT;

-- Transacción con rollback
BEGIN;
DELETE FROM orders WHERE amount < 10;
-- Revisar resultados, hacer rollback si es necesario
ROLLBACK;

-- Puntos de guardado para transacciones anidadas
BEGIN;
SAVEPOINT sp1;
INSERT INTO products (name) VALUES ('Product A');
ROLLBACK TO sp1;
COMMIT;
```

### Bloqueo y Concurrencia

Gestiona bloqueos de bases de datos y acceso concurrente para la integridad de los datos.

```sql
-- Comprobar estado de bloqueo
PRAGMA locking_mode;

-- Establecer modo WAL para mejor concurrencia
PRAGMA journal_mode = WAL;

-- Tiempo de espera ocupado para esperar bloqueos
PRAGMA busy_timeout = 5000;

-- Comprobar conexiones actuales a la base de datos
.databases
```

## Herramientas de Línea de Comandos de SQLite

### Comandos de Base de Datos: `.help`

Accede a la ayuda de la interfaz de línea de comandos de SQLite y a la documentación para los comandos de punto disponibles.

```bash
# Mostrar todos los comandos disponibles
.help
# Mostrar configuración actual
.show
# Establecer formato de salida
.mode csv
.headers on
```

### Importar/Exportar: `.import` / `.export`

Transfiere datos entre SQLite y archivos externos en varios formatos.

```bash
# Importar archivo CSV
.mode csv
.import data.csv users

# Exportar a CSV
.headers on
.mode csv
.output users.csv
SELECT * FROM users;
```

### Gestión de Esquema: `.schema` / `.tables`

Examina la estructura de la base de datos y las definiciones de tablas para desarrollo y depuración.

```bash
# Mostrar todas las tablas
.tables
# Mostrar esquema para tabla específica
.schema users
# Mostrar todos los esquemas
.schema
# Mostrar información de la tabla
.mode column
.headers on
PRAGMA table_info(users);
```

### Formato de Salida: `.mode`

Controla cómo se muestran los resultados de las consultas en la interfaz de línea de comandos.

```bash
# Diferentes modos de salida
.mode csv        # Valores separados por comas
.mode column     # Columnas alineadas
.mode html       # Formato de tabla HTML
.mode json       # Formato JSON
.mode list       # Formato de lista
.mode table      # Formato de tabla (por defecto)

# Establecer ancho de columna
.width 10 15 20

# Guardar salida en archivo
.output results.txt
SELECT * FROM users;
.output stdout

# Leer SQL desde archivo
.read script.sql

# Cambiar archivo de base de datos
.open another_database.db
```

## Configuración y Ajustes

### Ajustes de Base de Datos: `PRAGMA`

Controla el comportamiento de SQLite a través de sentencias pragma para optimización y configuración.

```sql
-- Información de la base de datos
PRAGMA database_list;
PRAGMA table_info(users);
PRAGMA foreign_key_list(orders);

-- Ajustes de rendimiento
PRAGMA cache_size = 10000;
PRAGMA temp_store = memory;
PRAGMA mmap_size = 268435456;

-- Habilitar restricciones de clave foránea
PRAGMA foreign_keys = ON;

-- Establecer modo de borrado seguro
PRAGMA secure_delete = ON;

-- Comprobar restricciones
PRAGMA foreign_key_check;
```

### Ajustes de Seguridad

Configura opciones y restricciones relacionadas con la seguridad de la base de datos.

```sql
-- Habilitar restricciones de clave foránea
PRAGMA foreign_keys = ON;

-- Modo de borrado seguro
PRAGMA secure_delete = ON;

-- Comprobar integridad
PRAGMA integrity_check;
```

## Instalación y Configuración

### Descarga e Instalación

Descarga las herramientas de SQLite y configura la interfaz de línea de comandos para tu sistema operativo.

```bash
# Descargar desde sqlite.org
# Para Windows: sqlite-tools-win32-x86-*.zip
# Para Linux/Mac: Usar gestor de paquetes

# Ubuntu/Debian
sudo apt-get install sqlite3

# macOS con Homebrew
brew install sqlite

# Verificar instalación
sqlite3 --version
```

### Creación de Tu Primera Base de Datos

Crea archivos de base de datos SQLite e inicia el trabajo con datos usando comandos simples.

```bash
# Crear nueva base de datos
sqlite3 myapp.db

# Crear tabla y añadir datos
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE
);

INSERT INTO users (name, email)
VALUES ('John Doe', 'john@example.com');
```

### Integración con Lenguajes de Programación

Utiliza SQLite con varios lenguajes de programación a través de librerías integradas o de terceros.

```python
# Python (módulo sqlite3 incorporado)
import sqlite3
conn = sqlite3.connect('mydb.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users')
```

```javascript
// Node.js (requiere paquete sqlite3)
const sqlite3 = require('sqlite3')
const db = new sqlite3.Database('mydb.db')
db.all('SELECT * FROM users', (err, rows) => {
  console.log(rows)
})
```

```php
// PHP (PDO SQLite incorporado)
$pdo = new PDO('sqlite:mydb.db');
$stmt = $pdo->query('SELECT * FROM users');
```

## Enlaces Relevantes

- <router-link to="/database">Hoja de Trucos de Base de Datos</router-link>
- <router-link to="/mysql">Hoja de Trucos de MySQL</router-link>
- <router-link to="/postgresql">Hoja de Trucos de PostgreSQL</router-link>
- <router-link to="/mongodb">Hoja de Trucos de MongoDB</router-link>
- <router-link to="/redis">Hoja de Trucos de Redis</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>

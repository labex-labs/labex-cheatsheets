---
title: 'Hoja de Trucos de MySQL | LabEx'
description: 'Aprenda gestión de bases de datos MySQL con esta hoja de trucos completa. Referencia rápida para consultas SQL, uniones (joins), índices, transacciones, procedimientos almacenados y administración de bases de datos.'
pdfUrl: '/cheatsheets/pdf/mysql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de MySQL
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/mysql">Aprende MySQL con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende gestión de bases de datos MySQL a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de MySQL que cubren operaciones SQL esenciales, administración de bases de datos, optimización de rendimiento y técnicas avanzadas de consulta. Domina uno de los sistemas de gestión de bases de datos relacionales más populares del mundo.
</base-disclaimer-content>
</base-disclaimer>

## Conexión y Gestión de Bases de Datos

### Conexión al Servidor: `mysql -u username -p`

Conéctate al servidor MySQL usando la línea de comandos.

```bash
# Conectar con nombre de usuario y solicitud de contraseña
mysql -u root -p
# Conectar a una base de datos específica
mysql -u username -p database_name
# Conectar a un servidor remoto
mysql -h hostname -u username -p
# Conectar especificando el puerto
mysql -h hostname -P 3306 -u username -p database_name
```

### Operaciones de Base de Datos: `CREATE` / `DROP` / `USE`

Gestiona bases de datos en el servidor.

```sql
# Crear una nueva base de datos
CREATE DATABASE company_db;
# Listar todas las bases de datos
SHOW DATABASES;
# Seleccionar una base de datos para usar
USE company_db;
# Eliminar una base de datos (borrar permanentemente)
DROP DATABASE old_database;
```

<BaseQuiz id="mysql-database-1" correct="C">
  <template #question>
    ¿Qué hace `USE database_name`?
  </template>
  
  <BaseQuizOption value="A">Crea una nueva base de datos</BaseQuizOption>
  <BaseQuizOption value="B">Elimina la base de datos</BaseQuizOption>
  <BaseQuizOption value="C" correct>Selecciona la base de datos para operaciones subsiguientes</BaseQuizOption>
  <BaseQuizOption value="D">Muestra todas las tablas en la base de datos</BaseQuizOption>
  
  <BaseQuizAnswer>
    La instrucción `USE` selecciona una base de datos, convirtiéndola en la base de datos activa para todas las sentencias SQL subsiguientes. Esto es equivalente a seleccionar una base de datos al conectarse con `mysql -u user -p database_name`.
  </BaseQuizAnswer>
</BaseQuiz>

### Exportar Datos: `mysqldump`

Copia de seguridad de los datos de la base de datos a un archivo SQL.

```bash
# Exportar base de datos completa
mysqldump -u username -p database_name > backup.sql
# Exportar tabla específica
mysqldump -u username -p database_name table_name > table_backup.sql
# Exportar solo la estructura
mysqldump -u username -p --no-data database_name > structure.sql
# Copia de seguridad completa de la base de datos con rutinas y triggers
mysqldump -u username -p --routines --triggers database_name > backup.sql
```

### Importar Datos: `mysql < file.sql`

Importa un archivo SQL a una base de datos MySQL.

```bash
# Importar archivo SQL a la base de datos
mysql -u username -p database_name < backup.sql
# Importar sin especificar la base de datos (si está incluida en el archivo)
mysql -u username -p < full_backup.sql
```

### Gestión de Usuarios: `CREATE USER` / `GRANT`

Gestiona usuarios y permisos de la base de datos.

```sql
# Crear nuevo usuario
CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
# Otorgar todos los privilegios
GRANT ALL PRIVILEGES ON database_name.* TO 'user'@'localhost';
# Otorgar privilegios específicos
GRANT SELECT, INSERT, UPDATE ON table_name TO 'user'@'localhost';
# Aplicar cambios de privilegios
FLUSH PRIVILEGES;
```

### Mostrar Información del Servidor: `SHOW STATUS` / `SHOW VARIABLES`

Muestra la configuración y el estado del servidor.

```sql
# Mostrar estado del servidor
SHOW STATUS;
# Mostrar variables de configuración
SHOW VARIABLES;
# Mostrar procesos actuales
SHOW PROCESSLIST;
```

## Estructura y Esquema de la Tabla

### Creación de Tabla: `CREATE TABLE`

Crea nuevas tablas con columnas y tipos de datos especificados.

```sql
# Crear tabla con varios tipos de datos
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    age INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# Crear tabla con clave foránea
CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Información de la Tabla: `DESCRIBE` / `SHOW`

Ver la estructura de la tabla y el contenido de la base de datos.

```sql
# Mostrar estructura de la tabla
DESCRIBE users;
# Sintaxis alternativa
SHOW COLUMNS FROM users;
# Listar todas las tablas
SHOW TABLES;
# Mostrar la sentencia CREATE de la tabla
SHOW CREATE TABLE users;
```

### Modificar Tablas: `ALTER TABLE`

Cambia la estructura de la tabla existente, añade o elimina columnas.

```sql
# Añadir nueva columna
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
# Eliminar columna
ALTER TABLE users DROP COLUMN age;
# Modificar tipo de columna
ALTER TABLE users MODIFY COLUMN username VARCHAR(100);
# Renombrar columna
ALTER TABLE users CHANGE old_name new_name VARCHAR(50);
```

## Manipulación de Datos y Operaciones CRUD

### Insertar Datos: `INSERT INTO`

Añade nuevos registros a las tablas.

```sql
# Insertar un solo registro
INSERT INTO users (username, email, age)
VALUES ('john_doe', 'john@email.com', 25);
# Insertar múltiples registros
INSERT INTO users (username, email, age) VALUES
('alice', 'alice@email.com', 30),
('bob', 'bob@email.com', 28);
# Insertar desde otra tabla
INSERT INTO users_backup SELECT * FROM users;
```

<BaseQuiz id="mysql-insert-1" correct="A">
  <template #question>
    ¿Cuál es la sintaxis correcta para insertar un solo registro?
  </template>
  
  <BaseQuizOption value="A" correct>`INSERT INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="B">`INSERT table_name VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="C">`ADD INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="D">`INSERT table_name (column1, column2) = (value1, value2);`</BaseQuizOption>
  
  <BaseQuizAnswer>
    La sintaxis correcta es `INSERT INTO table_name (columnas) VALUES (valores)`. La palabra clave `INTO` es requerida, y debes especificar tanto los nombres de las columnas como los valores correspondientes.
  </BaseQuizAnswer>
</BaseQuiz>

### Actualizar Datos: `UPDATE`

Modifica registros existentes en las tablas.

```sql
# Actualizar registro específico
UPDATE users SET age = 26 WHERE username = 'john_doe';
# Actualizar múltiples columnas
UPDATE users SET age = 31, email = 'alice_new@email.com'
WHERE username = 'alice';
# Actualizar con cálculo
UPDATE products SET price = price * 1.1 WHERE category = 'electronics';
```

### Eliminar Datos: `DELETE` / `TRUNCATE`

Elimina registros de las tablas.

```sql
# Eliminar registros específicos
DELETE FROM users WHERE age < 18;
# Eliminar todos los registros (mantener estructura)
DELETE FROM users;
# Eliminar todos los registros (más rápido, reinicia AUTO_INCREMENT)
TRUNCATE TABLE users;
# Eliminar con JOIN
DELETE u FROM users u
JOIN inactive_accounts i ON u.id = i.user_id;
```

### Reemplazar Datos: `REPLACE` / `INSERT ... ON DUPLICATE KEY`

Maneja situaciones de clave duplicada durante la inserción.

```sql
# Reemplazar existente o insertar nuevo
REPLACE INTO users (id, username, email)
VALUES (1, 'updated_user', 'new@email.com');
# Insertar o actualizar en caso de clave duplicada
INSERT INTO users (username, email)
VALUES ('john', 'john@email.com')
ON DUPLICATE KEY UPDATE email = VALUES(email);
```

## Consulta y Selección de Datos

### SELECT Básico: `SELECT * FROM`

Recupera datos de tablas con varias condiciones.

```sql
# Seleccionar todas las columnas
SELECT * FROM users;
# Seleccionar columnas específicas
SELECT username, email FROM users;
# Seleccionar con condición WHERE
SELECT * FROM users WHERE age > 25;
# Seleccionar con múltiples condiciones
SELECT * FROM users WHERE age > 20 AND email LIKE '%gmail.com';
```

<BaseQuiz id="mysql-select-1" correct="D">
  <template #question>
    ¿Qué devuelve `SELECT * FROM users`?
  </template>
  
  <BaseQuizOption value="A">Solo la primera fila de la tabla users</BaseQuizOption>
  <BaseQuizOption value="B">Solo la columna username</BaseQuizOption>
  <BaseQuizOption value="C">La estructura de la tabla</BaseQuizOption>
  <BaseQuizOption value="D" correct>Todas las columnas y todas las filas de la tabla users</BaseQuizOption>
  
  <BaseQuizAnswer>
    El comodín `*` selecciona todas las columnas, y sin una cláusula WHERE, devuelve todas las filas. Esto es útil para ver todos los datos, pero debe usarse con precaución en tablas grandes.
  </BaseQuizAnswer>
</BaseQuiz>

### Ordenación y Limitación: `ORDER BY` / `LIMIT`

Controla el orden y el número de resultados devueltos.

```sql
# Ordenar resultados
SELECT * FROM users ORDER BY age DESC;
# Ordenar por múltiples columnas
SELECT * FROM users ORDER BY age DESC, username ASC;
# Limitar resultados
SELECT * FROM users LIMIT 10;
# Paginación (saltar las primeras 10, tomar las siguientes 10)
SELECT * FROM users LIMIT 10 OFFSET 10;
```

### Filtrado: `WHERE` / `LIKE` / `IN`

Filtra datos usando varios operadores de comparación.

```sql
# Coincidencia de patrones
SELECT * FROM users WHERE username LIKE 'john%';
# Múltiples valores
SELECT * FROM users WHERE age IN (25, 30, 35);
# Filtrado por rango
SELECT * FROM users WHERE age BETWEEN 20 AND 30;
# Comprobaciones de NULL
SELECT * FROM users WHERE email IS NOT NULL;
```

### Agrupación: `GROUP BY` / `HAVING`

Agrupa datos y aplica funciones de agregación.

```sql
# Agrupar por columna
SELECT age, COUNT(*) FROM users GROUP BY age;
# Agrupar con condición sobre los grupos
SELECT age, COUNT(*) as count FROM users
GROUP BY age HAVING count > 1;
# Múltiples columnas de agrupación
SELECT age, gender, COUNT(*) FROM users
GROUP BY age, gender;
```

## Consultas Avanzadas

### Operaciones JOIN: `INNER` / `LEFT` / `RIGHT`

Combina datos de múltiples tablas.

```sql
# Inner join (solo registros coincidentes)
SELECT u.username, o.order_date
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# Left join (todos los usuarios, pedidos coincidentes)
SELECT u.username, o.order_date
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# Múltiples joins
SELECT u.username, o.order_date, p.product_name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

<BaseQuiz id="mysql-join-1" correct="B">
  <template #question>
    ¿Cuál es la diferencia entre INNER JOIN y LEFT JOIN?
  </template>
  
  <BaseQuizOption value="A">No hay diferencia</BaseQuizOption>
  <BaseQuizOption value="B" correct>INNER JOIN devuelve solo filas coincidentes, LEFT JOIN devuelve todas las filas de la tabla izquierda</BaseQuizOption>
  <BaseQuizOption value="C">INNER JOIN es más rápido</BaseQuizOption>
  <BaseQuizOption value="D">LEFT JOIN solo funciona con dos tablas</BaseQuizOption>
  
  <BaseQuizAnswer>
    INNER JOIN devuelve solo filas donde hay una coincidencia en ambas tablas. LEFT JOIN devuelve todas las filas de la tabla izquierda y las filas coincidentes de la tabla derecha, con valores NULL para las filas no coincidentes de la tabla derecha.
  </BaseQuizAnswer>
</BaseQuiz>

### Subconsultas: `SELECT` dentro de `SELECT`

Utiliza consultas anidadas para la recuperación compleja de datos.

```sql
# Subconsulta en la cláusula WHERE
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders WHERE total > 100);
# Subconsulta correlacionada
SELECT username FROM users u1
WHERE age > (SELECT AVG(age) FROM users u2);
# Subconsulta en SELECT
SELECT username,
(SELECT COUNT(*) FROM orders WHERE user_id = users.id) as order_count
FROM users;
```

### Funciones de Agregación: `COUNT` / `SUM` / `AVG`

Calcula estadísticas y resúmenes a partir de los datos.

```sql
# Agregados básicos
SELECT COUNT(*) FROM users;
SELECT AVG(age), MIN(age), MAX(age) FROM users;
SELECT SUM(total) FROM orders;
# Agregado con agrupación
SELECT department, AVG(salary)
FROM employees GROUP BY department;
# Múltiples agregados
SELECT
    COUNT(*) as total_users,
    AVG(age) as avg_age,
    MAX(created_at) as latest_signup
FROM users;
```

### Funciones de Ventana: `OVER` / `PARTITION BY`

Realiza cálculos en conjuntos de filas de tablas.

```sql
# Funciones de clasificación (ranking)
SELECT username, age,
RANK() OVER (ORDER BY age DESC) as age_rank
FROM users;
# Partición por grupo
SELECT username, department, salary,
AVG(salary) OVER (PARTITION BY department) as dept_avg
FROM employees;
# Totales acumulados (running totals)
SELECT order_date, total,
SUM(total) OVER (ORDER BY order_date) as running_total
FROM orders;
```

## Índices y Rendimiento

### Crear Índices: `CREATE INDEX`

Mejora el rendimiento de las consultas con índices de base de datos.

```sql
# Crear índice regular
CREATE INDEX idx_username ON users(username);
# Crear índice compuesto
CREATE INDEX idx_user_age ON users(username, age);
# Crear índice único
CREATE UNIQUE INDEX idx_email ON users(email);
# Mostrar índices en la tabla
SHOW INDEXES FROM users;
```

### Análisis de Consultas: `EXPLAIN`

Analiza los planes de ejecución de consultas y el rendimiento.

```sql
# Mostrar plan de ejecución de consulta
EXPLAIN SELECT * FROM users WHERE age > 25;
# Análisis detallado
EXPLAIN FORMAT=JSON SELECT u.*, o.total
FROM users u JOIN orders o ON u.id = o.user_id;
# Mostrar rendimiento de la consulta
SHOW PROFILES;
SET profiling = 1;
```

### Optimizar Consultas: Mejores Prácticas

Técnicas para escribir consultas SQL eficientes.

```sql
# Usar columnas específicas en lugar de *
SELECT username, email FROM users WHERE id = 1;
# Usar LIMIT para grandes conjuntos de datos
SELECT * FROM logs ORDER BY created_at DESC LIMIT 1000;
# Usar condiciones WHERE adecuadas
SELECT * FROM orders WHERE user_id = 123 AND status = 'pending';
-- Usar índices que cubran (covering indexes) cuando sea posible
```

### Mantenimiento de Tablas: `OPTIMIZE` / `ANALYZE`

Mantiene el rendimiento y las estadísticas de las tablas.

```sql
# Optimizar almacenamiento de la tabla
OPTIMIZE TABLE users;
# Actualizar estadísticas de la tabla
ANALYZE TABLE users;
# Comprobar integridad de la tabla
CHECK TABLE users;
# Reparar tabla si es necesario
REPAIR TABLE users;
```

## Importación/Exportación de Datos

### Cargar Datos: `LOAD DATA INFILE`

Importa datos desde archivos CSV y de texto.

```sql
# Cargar archivo CSV
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
# Cargar con columnas específicas
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users (username, email, age);
```

### Exportar Datos: `SELECT INTO OUTFILE`

Exporta los resultados de la consulta a archivos.

```sql
# Exportar a archivo CSV
SELECT username, email, age
FROM users
INTO OUTFILE '/path/to/export.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

### Copia de Seguridad y Restauración: `mysqldump` / `mysql`

Crea y restaura copias de seguridad de bases de datos.

```bash
# Copia de seguridad de tablas específicas
mysqldump -u username -p database_name table1 table2 > tables_backup.sql
# Restaurar desde copia de seguridad
mysql -u username -p database_name < backup.sql
# Exportar desde servidor remoto
mysqldump -h remote_host -u username -p database_name > remote_backup.sql
# Importar a base de datos local
mysql -u local_user -p local_database < remote_backup.sql
# Copia directa de datos entre servidores
mysqldump -h source_host -u user -p db_name | mysql -h dest_host -u user -p db_name
```

## Tipos de Datos y Funciones

### Tipos de Datos Comunes: Números, Texto, Fechas

Elige tipos de datos apropiados para tus columnas.

```sql
# Tipos numéricos
INT, BIGINT, DECIMAL(10,2), FLOAT, DOUBLE
# Tipos de cadena
VARCHAR(255), TEXT, CHAR(10), MEDIUMTEXT, LONGTEXT
# Tipos de fecha y hora
DATE, TIME, DATETIME, TIMESTAMP, YEAR
# Booleano y binario
BOOLEAN, BLOB, VARBINARY

# Creación de tabla de ejemplo
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Funciones de Cadena: `CONCAT` / `SUBSTRING` / `LENGTH`

Manipula datos de texto con funciones de cadena integradas.

```sql
# Concatenación de cadenas
SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users;
# Operaciones de cadena
SELECT SUBSTRING(email, 1, LOCATE('@', email)-1) as username FROM users;
SELECT LENGTH(username), UPPER(username) FROM users;
# Coincidencia de patrones y reemplazo
SELECT REPLACE(phone, '-', '.') FROM users WHERE phone LIKE '___-___-____';
```

### Funciones de Fecha: `NOW()` / `DATE_ADD` / `DATEDIFF`

Trabaja con fechas y horas de manera efectiva.

```sql
# Fecha y hora actuales
SELECT NOW(), CURDATE(), CURTIME();
# Aritmética de fechas
SELECT DATE_ADD(created_at, INTERVAL 30 DAY) as expiry_date FROM users;
SELECT DATEDIFF(NOW(), created_at) as days_since_signup FROM users;
# Formato de fecha
SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') as formatted_date FROM orders;
```

### Funciones Numéricas: `ROUND` / `ABS` / `RAND`

Realiza operaciones matemáticas sobre datos numéricos.

```sql
# Funciones matemáticas
SELECT ROUND(price, 2), ABS(profit_loss), SQRT(area) FROM products;
# Aleatorio y estadístico
SELECT RAND(), FLOOR(price), CEIL(rating) FROM products;
# Matemáticas de agregación
SELECT AVG(price), STDDEV(price), VARIANCE(price) FROM products;
```

## Gestión de Transacciones

### Control de Transacciones: `BEGIN` / `COMMIT` / `ROLLBACK`

Gestiona transacciones de base de datos para la consistencia de los datos.

```sql
# Iniciar transacción
BEGIN;
# o
START TRANSACTION;
# Realizar operaciones
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;
# Confirmar cambios
COMMIT;
# O deshacer si hay error
ROLLBACK;
```

### Nivel de Aislamiento de Transacciones: `SET TRANSACTION ISOLATION`

Controla cómo interactúan las transacciones entre sí.

```sql
# Establecer nivel de aislamiento
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
# Mostrar nivel de aislamiento actual
SELECT @@transaction_isolation;
```

### Bloqueo: `LOCK TABLES` / `SELECT FOR UPDATE`

Controla el acceso concurrente a los datos.

```sql
# Bloquear tablas para acceso exclusivo
LOCK TABLES users WRITE, orders READ;
# Realizar operaciones
# ...
UNLOCK TABLES;
# Bloqueo a nivel de fila en transacciones
BEGIN;
SELECT * FROM accounts WHERE id = 1 FOR UPDATE;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
COMMIT;
```

### Puntos de Retorno (Savepoints): `SAVEPOINT` / `ROLLBACK TO`

Crea puntos de retroceso dentro de las transacciones.

```sql
BEGIN;
INSERT INTO users (username) VALUES ('user1');
SAVEPOINT sp1;
INSERT INTO users (username) VALUES ('user2');
SAVEPOINT sp2;
INSERT INTO users (username) VALUES ('user3');
# Deshacer hasta el punto de retorno
ROLLBACK TO sp1;
COMMIT;
```

## Técnicas SQL Avanzadas

### Expresiones de Tabla Comunes (CTEs): `WITH`

Crea conjuntos de resultados temporales para consultas complejas.

```sql
# CTE simple
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

### Procedimientos Almacenados: `CREATE PROCEDURE`

Crea procedimientos de base de datos reutilizables.

```sql
# Crear procedimiento almacenado
DELIMITER //
CREATE PROCEDURE GetUserOrders(IN user_id INT)
BEGIN
    SELECT o.*, p.product_name
    FROM orders o
    JOIN products p ON o.product_id = p.id
    WHERE o.user_id = user_id;
END //
DELIMITER ;
# Llamar al procedimiento
CALL GetUserOrders(123);
```

### Triggers: `CREATE TRIGGER`

Ejecuta código automáticamente en respuesta a eventos de la base de datos.

```sql
# Crear trigger para registro de auditoría de usuario
CREATE TRIGGER user_update_audit
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    INSERT INTO user_audit (user_id, old_email, new_email, changed_at)
    VALUES (NEW.id, OLD.email, NEW.email, NOW());
END;
# Mostrar triggers
SHOW TRIGGERS;
```

### Vistas: `CREATE VIEW`

Crea tablas virtuales basadas en resultados de consultas.

```sql
# Crear vista
CREATE VIEW active_users AS
SELECT id, username, email, created_at
FROM users
WHERE status = 'active' AND last_login > DATE_SUB(NOW(), INTERVAL 30 DAY);
# Usar vista como una tabla
SELECT * FROM active_users WHERE username LIKE 'john%';
# Eliminar vista
DROP VIEW active_users;
```

## Instalación y Configuración de MySQL

### Instalación: Gestores de Paquetes

Instala MySQL usando los gestores de paquetes del sistema.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# CentOS/RHEL
sudo yum install mysql-server
# macOS con Homebrew
brew install mysql
# Iniciar servicio MySQL
sudo systemctl start mysql
```

### Docker: `docker run mysql`

Ejecuta MySQL en contenedores Docker para desarrollo.

```bash
# Ejecutar contenedor MySQL
docker run --name mysql-dev -e MYSQL_ROOT_PASSWORD=password -p 3306:3306 -d mysql:8.0
# Conectar al MySQL contenedorizado
docker exec -it mysql-dev mysql -u root -p
# Crear base de datos en el contenedor
docker exec -it mysql-dev mysql -u root -p -e "CREATE DATABASE testdb;"
```

### Configuración Inicial y Seguridad

Asegura tu instalación de MySQL y verifica la configuración.

```bash
# Ejecutar script de seguridad
sudo mysql_secure_installation
# Conectar a MySQL
mysql -u root -p
# Mostrar versión de MySQL
SELECT VERSION();
# Verificar estado de conexión
STATUS;
# Establecer contraseña de root
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
```

## Configuración y Ajustes

### Archivos de Configuración: `my.cnf`

Modifica la configuración del servidor MySQL.

```ini
# Ubicaciones comunes de configuración
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

### Configuración en Tiempo de Ejecución: `SET GLOBAL`

Cambia la configuración mientras MySQL se está ejecutando.

```sql
# Establecer variables globales
SET GLOBAL max_connections = 500;
SET GLOBAL slow_query_log = ON;
# Mostrar configuración actual
SHOW VARIABLES LIKE 'max_connections';
SHOW GLOBAL STATUS LIKE 'Slow_queries';
```

### Optimización de Rendimiento: Memoria y Caché

Optimiza la configuración de rendimiento de MySQL.

```sql
# Mostrar uso de memoria
SHOW VARIABLES LIKE '%buffer_pool_size%';
SHOW VARIABLES LIKE '%query_cache%';
# Monitorear rendimiento
SHOW STATUS LIKE 'Qcache%';
SHOW STATUS LIKE 'Created_tmp%';
# Configuración de InnoDB
SET GLOBAL innodb_buffer_pool_size = 2147483648; -- 2GB
```

### Configuración de Registros: Registros de Errores y Consultas

Configura el registro de MySQL para monitoreo y depuración.

```sql
# Habilitar registro general de consultas
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/query.log';
# Registro de consultas lentas (slow query log)
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
# Mostrar configuración de registros
SHOW VARIABLES LIKE '%log%';
```

## Enlaces Relevantes

- <router-link to="/database">Hoja de Trucos de Bases de Datos</router-link>
- <router-link to="/postgresql">Hoja de Trucos de PostgreSQL</router-link>
- <router-link to="/sqlite">Hoja de Trucos de SQLite</router-link>
- <router-link to="/mongodb">Hoja de Trucos de MongoDB</router-link>
- <router-link to="/redis">Hoja de Trucos de Redis</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>

---
title: 'Hoja de Trucos de Bases de Datos | LabEx'
description: 'Aprenda gestión de bases de datos con esta hoja de trucos completa. Referencia rápida para consultas SQL, diseño de bases de datos, normalización, indexación, transacciones y administración de bases de datos relacionales.'
pdfUrl: '/cheatsheets/pdf/database-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Bases de Datos
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/database">Aprenda Bases de Datos con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda gestión de bases de datos y SQL a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de bases de datos que cubren comandos SQL esenciales, manipulación de datos, optimización de consultas, diseño de bases de datos y mejores prácticas de administración. Domine las bases de datos relacionales, los sistemas NoSQL y las mejores prácticas de seguridad de bases de datos.
</base-disclaimer-content>
</base-disclaimer>

## Creación y Gestión de Bases de Datos

### Crear Base de Datos: `CREATE DATABASE`

Cree una nueva base de datos para almacenar sus datos.

```sql
-- Crear una nueva base de datos
CREATE DATABASE company_db;
-- Crear base de datos con conjunto de caracteres
CREATE DATABASE company_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
-- Usar la base de datos
USE company_db;
```

<BaseQuiz id="database-create-1" correct="A">
  <template #question>
    ¿Qué hace <code>CREATE DATABASE company_db</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Crea una nueva base de datos vacía llamada company_db</BaseQuizOption>
  <BaseQuizOption value="B">Crea una tabla en la base de datos</BaseQuizOption>
  <BaseQuizOption value="C">Elimina la base de datos</BaseQuizOption>
  <BaseQuizOption value="D">Realiza una copia de seguridad de la base de datos</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>CREATE DATABASE</code> crea una nueva base de datos vacía. Después de la creación, debe usar <code>USE</code> para seleccionarla y luego crear tablas dentro de ella.
  </BaseQuizAnswer>
</BaseQuiz>

### Mostrar Bases de Datos: `SHOW DATABASES`

Liste todas las bases de datos disponibles en el servidor.

```sql
-- Listar todas las bases de datos
SHOW DATABASES;
-- Mostrar información de la base de datos
SELECT SCHEMA_NAME FROM
INFORMATION_SCHEMA.SCHEMATA;
-- Mostrar base de datos actual
SELECT DATABASE();
```

### Eliminar Base de Datos: `DROP DATABASE`

Elimine una base de datos completa permanentemente.

```sql
-- Eliminar base de datos (¡tenga cuidado!)
DROP DATABASE old_company_db;
-- Eliminar base de datos si existe
DROP DATABASE IF EXISTS old_company_db;
```

### Copia de Seguridad de Base de Datos: `mysqldump`

Cree copias de seguridad de su base de datos.

```sql
-- Copia de seguridad desde la línea de comandos
mysqldump -u username -p database_name > backup.sql
-- Restaurar desde copia de seguridad
mysql -u username -p database_name < backup.sql
```

### Usuarios de Base de Datos: `CREATE USER`

Administre cuentas de usuario y permisos de la base de datos.

```sql
-- Crear nuevo usuario
CREATE USER 'newuser'@'localhost' IDENTIFIED BY
'password';
-- Otorgar privilegios
GRANT SELECT, INSERT ON company_db.* TO
'newuser'@'localhost';
-- Mostrar privilegios del usuario
SHOW GRANTS FOR 'newuser'@'localhost';
```

### Información de Base de Datos: `INFORMATION_SCHEMA`

Consulte metadatos y estructura de la base de datos.

```sql
-- Mostrar todas las tablas
SELECT TABLE_NAME FROM
INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'company_db';
-- Mostrar columnas de la tabla
DESCRIBE employees;
```

## Estructura e Información de Tablas

### Crear Tabla: `CREATE TABLE`

Defina nuevas tablas con columnas y tipos de datos.

```sql
-- Creación básica de tabla
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY
KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE,
    salary DECIMAL(10,2),
    hire_date DATE,
    department VARCHAR(50)
);
-- Mostrar estructura de la tabla
DESCRIBE employees;
SHOW COLUMNS FROM employees;
```

### Alterar Tabla: `ALTER TABLE`

Modifique la estructura y las columnas de la tabla existente.

```sql
-- Añadir nueva columna
ALTER TABLE employees ADD
COLUMN phone VARCHAR(15);
-- Modificar tipo de columna
ALTER TABLE employees MODIFY
COLUMN salary DECIMAL(12,2);
-- Eliminar columna
ALTER TABLE employees DROP
COLUMN phone;
-- Renombrar tabla
RENAME TABLE employees TO staff;
```

<BaseQuiz id="database-alter-1" correct="C">
  <template #question>
    ¿Qué hace <code>ALTER TABLE employees ADD COLUMN phone VARCHAR(15)</code>?
  </template>
  
  <BaseQuizOption value="A">Elimina la columna phone</BaseQuizOption>
  <BaseQuizOption value="B">Modifica la columna phone</BaseQuizOption>
  <BaseQuizOption value="C" correct>Añade una nueva columna llamada phone a la tabla employees</BaseQuizOption>
  <BaseQuizOption value="D">Renombra la tabla</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>ALTER TABLE ... ADD COLUMN</code> añade una nueva columna a una tabla existente. La nueva columna se añadirá con el tipo de dato especificado y será NULL para las filas existentes a menos que especifique un valor predeterminado.
  </BaseQuizAnswer>
</BaseQuiz>

### Información de Tabla: `SHOW`

Obtenga información detallada sobre las tablas y sus propiedades.

```sql
-- Mostrar todas las tablas
SHOW TABLES;
-- Mostrar estructura de la tabla
SHOW CREATE TABLE employees;
-- Mostrar estado de la tabla
SHOW TABLE STATUS LIKE
'employees';
-- Contar filas en la tabla
SELECT COUNT(*) FROM employees;
```

## Manipulación de Datos y Operaciones CRUD

### Insertar Datos: `INSERT INTO`

Añada nuevos registros a sus tablas.

```sql
-- Insertar registro único
INSERT INTO employees (name, email, salary, hire_date,
department)
VALUES ('John Doe', 'john@company.com', 75000.00,
'2024-01-15', 'Engineering');
-- Insertar múltiples registros
INSERT INTO employees (name, email, salary,
department) VALUES
('Jane Smith', 'jane@company.com', 80000.00,
'Marketing'),
('Bob Johnson', 'bob@company.com', 65000.00, 'Sales');
-- Insertar desde otra tabla
INSERT INTO backup_employees
SELECT * FROM employees WHERE department =
'Engineering';
```

### Actualizar Datos: `UPDATE`

Modifique registros existentes en las tablas.

```sql
-- Actualizar registro único
UPDATE employees
SET salary = 85000.00, department = 'Senior Engineering'
WHERE id = 1;
-- Actualizar múltiples registros
UPDATE employees
SET salary = salary * 1.05
WHERE hire_date < '2024-01-01';
-- Actualizar con JOIN
UPDATE employees e
JOIN departments d ON e.department = d.name
SET e.salary = e.salary + d.bonus;
```

### Eliminar Datos: `DELETE FROM`

Elimine registros de las tablas.

```sql
-- Eliminar registros específicos
DELETE FROM employees
WHERE department = 'Temporary';
-- Eliminar con condiciones
DELETE FROM employees
WHERE hire_date < '2020-01-01' AND salary < 50000;
-- Truncar tabla (más rápido para todos los registros)
TRUNCATE TABLE temp_employees;
```

### Reemplazar Datos: `REPLACE INTO`

Insertar o actualizar registros basándose en la clave primaria.

```sql
-- Reemplazar registro (insertar o actualizar)
REPLACE INTO employees (id, name, email, salary)
VALUES (1, 'John Doe Updated',
'john.new@company.com', 90000);
-- En caso de clave duplicada, actualizar
INSERT INTO employees (id, name, salary)
VALUES (1, 'John Doe', 85000)
ON DUPLICATE KEY UPDATE salary = VALUES(salary);
```

## Consulta y Selección de Datos

### SELECT Básico: `SELECT`

Recupere datos de las tablas de la base de datos.

```sql
-- Seleccionar todas las columnas
SELECT * FROM employees;
-- Seleccionar columnas específicas
SELECT name, email, salary FROM employees;
-- Seleccionar con alias
SELECT name AS employee_name, salary AS
annual_salary
FROM employees;
-- Seleccionar valores distintos
SELECT DISTINCT department FROM employees;
```

### Filtrado de Datos: `WHERE`

Aplique condiciones para filtrar los resultados de la consulta.

```sql
-- Condiciones básicas
SELECT * FROM employees WHERE salary > 70000;
-- Múltiples condiciones
SELECT * FROM employees
WHERE department = 'Engineering' AND salary > 75000;
-- Coincidencia de patrones
SELECT * FROM employees WHERE name LIKE 'John%';
```

<BaseQuiz id="database-where-1" correct="C">
  <template #question>
    ¿Qué coincide <code>LIKE 'John%'</code> en una cláusula WHERE?
  </template>
  
  <BaseQuizOption value="A">Solo coincidencias exactas con "John"</BaseQuizOption>
  <BaseQuizOption value="B">Valores que terminan en "John"</BaseQuizOption>
  <BaseQuizOption value="C" correct>Valores que comienzan con "John"</BaseQuizOption>
  <BaseQuizOption value="D">Valores que contienen "John" en cualquier lugar</BaseQuizOption>
  
  <BaseQuizAnswer>
    El comodín <code>%</code> en SQL coincide con cualquier secuencia de caracteres. <code>LIKE 'John%'</code> coincide con cualquier valor que comience con "John", como "John", "Johnny", "Johnson", etc.
  </BaseQuizAnswer>
</BaseQuiz>

```sql
-- Consultas de rango
SELECT * FROM employees
WHERE hire_date BETWEEN '2023-01-01' AND '2023-12-
31';
```

### Ordenación de Datos: `ORDER BY`

Ordene los resultados de la consulta en orden ascendente o descendente.

```sql
-- Ordenar por columna única
SELECT * FROM employees ORDER BY salary DESC;
-- Ordenar por múltiples columnas
SELECT * FROM employees
ORDER BY department ASC, salary DESC;
-- Ordenar con LIMIT
SELECT * FROM employees
ORDER BY hire_date DESC LIMIT 10;
```

### Limitación de Resultados: `LIMIT`

Controle el número de registros devueltos.

```sql
-- Limitar número de resultados
SELECT * FROM employees LIMIT 5;
-- Paginación con OFFSET
SELECT * FROM employees
ORDER BY id LIMIT 10 OFFSET 20;
-- Resultados Top N
SELECT * FROM employees
ORDER BY salary DESC LIMIT 5;
```

## Consultas Avanzadas

### Funciones de Agregación: `COUNT`, `SUM`, `AVG`

Realice cálculos en grupos de datos.

```sql
-- Contar registros
SELECT COUNT(*) FROM employees;
-- Suma y promedio
SELECT SUM(salary) as total_payroll, AVG(salary) as
avg_salary
FROM employees;
-- Estadísticas de grupo
SELECT department, COUNT(*) as employee_count,
AVG(salary) as avg_salary
FROM employees GROUP BY department;
-- Cláusula HAVING para filtrado de grupo
SELECT department, COUNT(*) as count
FROM employees
GROUP BY department
HAVING COUNT(*) > 5;
```

### Subconsultas: Consultas Anidadas

Utilice consultas dentro de otras consultas para operaciones complejas.

```sql
-- Subconsulta en cláusula WHERE
SELECT * FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);
-- Subconsulta con IN
SELECT * FROM employees
WHERE department IN (
    SELECT name FROM departments WHERE budget >
100000
);
-- Subconsulta correlacionada
SELECT * FROM employees e1
WHERE salary > (
    SELECT AVG(salary) FROM employees e2
    WHERE e2.department = e1.department
);
```

### Uniones de Tablas: `JOIN`

Combine datos de múltiples tablas.

```sql
-- Inner join
SELECT e.name, e.salary, d.department_name
FROM employees e
INNER JOIN departments d ON e.department = d.id;
-- Left join
SELECT e.name, d.department_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id;
-- Múltiples uniones
SELECT e.name, d.department_name, p.project_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id
LEFT JOIN projects p ON e.id = p.employee_id;
```

### Funciones de Ventana: Analítica Avanzada

Realice cálculos en filas relacionadas.

```sql
-- Numeración de filas
SELECT name, salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
FROM employees;
-- Totales acumulados
SELECT name, salary,
    SUM(salary) OVER (ORDER BY hire_date) as
running_total
FROM employees;
-- Particionar por grupos
SELECT name, department, salary,
    AVG(salary) OVER (PARTITION BY department) as
dept_avg
FROM employees;
```

## Restricciones e Integridad de Bases de Datos

### Claves Primarias: `PRIMARY KEY`

Asegure la identificación única para cada registro.

```sql
-- Clave primaria de columna única
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100)
);
-- Clave primaria compuesta
CREATE TABLE order_items (
    order_id INT,
    product_id INT,
    quantity INT,
    PRIMARY KEY (order_id, product_id)
);
```

### Claves Foráneas: `FOREIGN KEY`

Mantenga la integridad referencial entre tablas.

```sql
-- Añadir restricción de clave foránea
CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);
-- Añadir clave foránea a tabla existente
ALTER TABLE employees
ADD CONSTRAINT fk_department
FOREIGN KEY (department_id) REFERENCES
departments(id);
```

### Restricciones Únicas: `UNIQUE`

Evite valores duplicados en las columnas.

```sql
-- Restricción única en columna única
ALTER TABLE employees
ADD CONSTRAINT unique_email UNIQUE (email);
-- Restricción única compuesta
ALTER TABLE employees
ADD CONSTRAINT unique_name_dept UNIQUE (name,
department);
```

### Restricciones CHECK: `CHECK`

Aplique reglas de negocio y validación de datos.

```sql
-- Restricción check simple
ALTER TABLE employees
ADD CONSTRAINT check_salary CHECK (salary > 0);
-- Restricción check compleja
ALTER TABLE employees
ADD CONSTRAINT check_age
CHECK (YEAR(CURDATE()) - YEAR(birth_date) >= 18);
```

## Rendimiento y Optimización de Bases de Datos

### Índices: `CREATE INDEX`

Acelere la recuperación de datos con índices de base de datos.

```sql
-- Crear índice en columna única
CREATE INDEX idx_employee_name ON
employees(name);
-- Índice compuesto
CREATE INDEX idx_dept_salary ON
employees(department, salary);
-- Índice único
CREATE UNIQUE INDEX idx_employee_email ON
employees(email);
-- Mostrar índices de la tabla
SHOW INDEX FROM employees;
```

### Optimización de Consultas: `EXPLAIN`

Analice y optimice el rendimiento de las consultas.

```sql
-- Analizar plan de ejecución de consulta
EXPLAIN SELECT * FROM employees WHERE salary >
75000;
-- Análisis detallado
EXPLAIN ANALYZE SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department = d.id;
```

### Monitoreo de Rendimiento

Monitoree la actividad y el rendimiento de la base de datos.

```sql
-- Mostrar procesos en ejecución
SHOW PROCESSLIST;
-- Mostrar estado de la base de datos
SHOW STATUS LIKE 'Slow_queries';
-- Información de la caché de consultas
SHOW STATUS LIKE 'Qcache%';
```

### Mantenimiento de Bases de Datos

Tareas de mantenimiento regulares para un rendimiento óptimo.

```sql
-- Optimización de tabla
OPTIMIZE TABLE employees;
-- Analizar estadísticas de tabla
ANALYZE TABLE employees;
-- Comprobar integridad de la tabla
CHECK TABLE employees;
-- Reparar tabla si es necesario
REPAIR TABLE employees;
```

## Importación/Exportación de Datos

### Importar Datos: `LOAD DATA`

Importe datos de archivos externos a las tablas de la base de datos.

```sql
-- Importar desde archivo CSV
LOAD DATA INFILE 'employees.csv'
INTO TABLE employees
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
-- Importar con mapeo de columnas
LOAD DATA INFILE 'data.csv'
INTO TABLE employees (name, email, salary);
```

### Exportar Datos: `SELECT INTO`

Exporte los resultados de la consulta a archivos externos.

```sql
-- Exportar a archivo CSV
SELECT name, email, salary
INTO OUTFILE 'employee_export.csv'
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
FROM employees;
-- Exportar con mysqldump
mysqldump -u username -p --tab=/path/to/export
database_name table_name
```

### Migración de Datos: Entre Bases de Datos

Mueva datos entre diferentes sistemas de bases de datos.

```sql
-- Crear tabla a partir de estructura existente
CREATE TABLE employees_backup LIKE employees;
-- Copiar datos entre tablas
INSERT INTO employees_backup SELECT * FROM
employees;
-- Migrar con condiciones
INSERT INTO new_employees
SELECT * FROM old_employees WHERE active = 1;
```

### Operaciones Masivas

Maneje operaciones de datos a gran escala de manera eficiente.

```sql
-- Inserción masiva con INSERT IGNORE
INSERT IGNORE INTO employees (name, email) VALUES
('John Doe', 'john@email.com'),
('Jane Smith', 'jane@email.com');
-- Actualizaciones por lotes
UPDATE employees SET salary = salary * 1.1 WHERE
department = 'Sales';
```

## Seguridad y Control de Acceso de Bases de Datos

### Gestión de Usuarios: `CREATE USER`

Cree y administre cuentas de usuario de bases de datos.

```sql
-- Crear usuario con contraseña
CREATE USER 'app_user'@'localhost' IDENTIFIED BY
'secure_password';
-- Crear usuario para host específico
CREATE USER 'remote_user'@'192.168.1.%' IDENTIFIED
BY 'password';
-- Eliminar usuario
DROP USER 'old_user'@'localhost';
```

### Permisos: `GRANT` & `REVOKE`

Controle el acceso a objetos y operaciones de la base de datos.

```sql
-- Otorgar privilegios específicos
GRANT SELECT, INSERT ON company_db.employees TO
'app_user'@'localhost';
-- Otorgar todos los privilegios
GRANT ALL PRIVILEGES ON company_db.* TO
'admin_user'@'localhost';
-- Revocar privilegios
REVOKE INSERT ON company_db.employees FROM
'app_user'@'localhost';
-- Mostrar concesiones de usuario
SHOW GRANTS FOR 'app_user'@'localhost';
```

### Roles de Base de Datos

Organice los permisos utilizando roles de base de datos.

```sql
-- Crear rol (MySQL 8.0+)
CREATE ROLE 'app_read_role', 'app_write_role';
-- Otorgar privilegios al rol
GRANT SELECT ON company_db.* TO 'app_read_role';
GRANT INSERT, UPDATE, DELETE ON company_db.* TO
'app_write_role';
-- Asignar rol a usuario
GRANT 'app_read_role' TO 'readonly_user'@'localhost';
```

### Prevención de Inyección SQL

Proteja contra vulnerabilidades de seguridad comunes.

```sql
-- Usar sentencias preparadas (nivel de aplicación)
-- Malo: SELECT * FROM users WHERE id = ' + userInput
-- Bueno: Usar consultas parametrizadas
-- Validar tipos de datos de entrada
-- Usar procedimientos almacenados cuando sea posible
-- Aplicar principio de mínimo privilegio
```

## Instalación y Configuración de Bases de Datos

### Instalación de MySQL

Base de datos relacional de código abierto popular.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# Iniciar servicio MySQL
sudo systemctl start mysql
sudo systemctl enable mysql
# Instalación segura
sudo mysql_secure_installation
```

### Instalación de PostgreSQL

Base de datos relacional de código abierto avanzada.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql
postgresql-contrib
# Cambiar al usuario postgres
sudo -u postgres psql
# Crear base de datos y usuario
CREATE DATABASE myapp;
CREATE USER myuser WITH
PASSWORD 'mypassword';
```

### Configuración de SQLite

Base de datos ligera basada en archivos.

```bash
# Instalar SQLite
sudo apt install sqlite3
# Crear archivo de base de datos
sqlite3 mydatabase.db
# Comandos básicos de SQLite
.help
.tables
.schema tablename
.quit
```

## Configuración y Ajuste de Bases de Datos

### Configuración de MySQL

Parámetros clave de configuración de MySQL.

```sql
-- Archivo de configuración my.cnf
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
-- Mostrar configuración actual
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW STATUS LIKE 'Connections';
```

### Gestión de Conexiones

Administre las conexiones y el pooling de la base de datos.

```sql
-- Mostrar conexiones actuales
SHOW PROCESSLIST;
-- Matar conexión específica
KILL CONNECTION 123;
-- Configuración de tiempo de espera de conexión
SET SESSION wait_timeout = 600;
SET SESSION interactive_timeout = 600;
```

### Configuración de Copias de Seguridad

Configure copias de seguridad automatizadas de la base de datos.

```bash
# Script de copia de seguridad automatizado
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mysqldump -u backup_user -p mydatabase >
backup_$DATE.sql
# Programar con cron
0 2 * * * /path/to/backup_script.sh
```

### Monitoreo y Registro (Logging)

Monitoree la actividad y el rendimiento de la base de datos.

```sql
-- Configuración de recuperación punto en el tiempo
SET GLOBAL log_bin = ON;
-- Habilitar registro de consultas lentas
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
-- Mostrar tamaño de la base de datos
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

## Mejores Prácticas de SQL

### Mejores Prácticas de Escritura de Consultas

Escriba SQL limpio, eficiente y legible.

```sql
-- Usar alias de tabla significativos
SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.dept_id = d.id;
-- Especificar nombres de columna en lugar de SELECT *
SELECT name, email, salary FROM employees;
-- Usar tipos de datos apropiados
CREATE TABLE products (
    id INT PRIMARY KEY,
    price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP
);
```

### Consejos de Optimización de Rendimiento

Optimice las consultas para un mejor rendimiento de la base de datos.

```sql
-- Usar índices en columnas consultadas frecuentemente
CREATE INDEX idx_employee_dept ON
employees(department);
-- Limitar conjuntos de resultados cuando sea posible
SELECT name FROM employees WHERE active = 1 LIMIT
100;
-- Usar EXISTS en lugar de IN para subconsultas
SELECT * FROM customers c
WHERE EXISTS (SELECT 1 FROM orders o WHERE
o.customer_id = c.id);
```

## Enlaces Relevantes

- <router-link to="/mysql">Hoja de Trucos de MySQL</router-link>
- <router-link to="/postgresql">Hoja de Trucos de PostgreSQL</router-link>
- <router-link to="/sqlite">Hoja de Trucos de SQLite</router-link>
- <router-link to="/mongodb">Hoja de Trucos de MongoDB</router-link>
- <router-link to="/redis">Hoja de Trucos de Redis</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>

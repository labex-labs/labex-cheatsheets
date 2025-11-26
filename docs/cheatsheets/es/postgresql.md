---
title: 'Hoja de Trucos de PostgreSQL'
description: 'Aprenda PostgreSQL con nuestra hoja de trucos completa que cubre comandos esenciales, conceptos y mejores prácticas.'
pdfUrl: '/cheatsheets/pdf/postgresql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de PostgreSQL
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/postgresql">Aprenda PostgreSQL con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda la gestión de bases de datos PostgreSQL a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de PostgreSQL que cubren operaciones SQL esenciales, consultas avanzadas, optimización del rendimiento, administración de bases de datos y seguridad. Domine el desarrollo y la administración de bases de datos relacionales de nivel empresarial.
</base-disclaimer-content>
</base-disclaimer>

## Conexión y Configuración de la Base de Datos

### Conectarse a PostgreSQL: `psql`

Conéctese a una base de datos PostgreSQL local o remota usando la herramienta de línea de comandos psql.

```bash
# Conectarse a la base de datos local
psql -U nombre_usuario -d nombre_base_datos
# Conectarse a la base de datos remota
psql -h nombre_host -p 5432 -U nombre_usuario -d nombre_base_datos
# Conectarse con solicitud de contraseña
psql -U postgres -W
# Conectarse usando cadena de conexión
psql "host=localhost port=5432 dbname=midb user=miusuario"
```

### Crear Base de Datos: `CREATE DATABASE`

Cree una nueva base de datos en PostgreSQL usando el comando CREATE DATABASE.

```sql
# Crear una nueva base de datos
CREATE DATABASE midatabase;
# Crear base de datos con propietario
CREATE DATABASE midatabase OWNER miusuario;
# Crear base de datos con codificación
CREATE DATABASE midatabase
  WITH ENCODING 'UTF8'
  LC_COLLATE='en_US.UTF-8'
  LC_CTYPE='en_US.UTF-8';
```

### Listar Bases de Datos: `\l`

Liste todas las bases de datos en el servidor PostgreSQL.

```bash
# Listar todas las bases de datos
\l
# Listar bases de datos con información detallada
\l+
# Conectarse a una base de datos diferente
\c nombre_base_datos
```

### Comandos Básicos de psql

Comandos esenciales de la terminal psql para navegación e información.

```bash
# Salir de psql
\q
# Obtener ayuda para comandos SQL
\help CREATE TABLE
# Obtener ayuda para comandos psql
\?
# Mostrar base de datos y usuario actuales
\conninfo
# Ejecutar comandos del sistema
\! ls
# Listar todas las tablas
\dt
# Listar todas las tablas con detalles
\dt+
# Describir tabla específica
\d nombre_tabla
# Listar todos los esquemas
\dn
# Listar todos los usuarios/roles
\du
```

### Versión y Configuración

Verificar la versión de PostgreSQL y la configuración.

```sql
# Verificar versión de PostgreSQL
SELECT version();
# Mostrar toda la configuración actual
SHOW ALL;
# Mostrar configuración específica
SHOW max_connections;
# Establecer parámetro de configuración
SET work_mem = '256MB';
```

## Creación y Gestión de Tablas

### Crear Tabla: `CREATE TABLE`

Definir nuevas tablas con columnas, tipos de datos y restricciones.

```sql
# Creación básica de tabla
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

# Tabla con clave foránea
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending'
);
```

### Modificar Tablas: `ALTER TABLE`

Añadir, modificar o eliminar columnas y restricciones de tablas existentes.

```sql
# Añadir nueva columna
ALTER TABLE users ADD COLUMN phone VARCHAR(15);
# Cambiar tipo de columna
ALTER TABLE users ALTER COLUMN phone TYPE VARCHAR(20);
# Eliminar columna
ALTER TABLE users DROP COLUMN phone;
# Añadir restricción
ALTER TABLE users ADD CONSTRAINT unique_email
    UNIQUE (email);
```

### Eliminar y Truncar: `DROP/TRUNCATE`

Eliminar tablas o borrar todos los datos de las tablas.

```sql
# Eliminar tabla completamente
DROP TABLE IF EXISTS old_table;
# Eliminar todos los datos pero mantener la estructura
TRUNCATE TABLE users;
# Truncar con reinicio de identidad
TRUNCATE TABLE users RESTART IDENTITY;
```

### Tipos de Datos y Restricciones

Tipos de datos esenciales de PostgreSQL para diferentes tipos de datos.

```sql
# Tipos numéricos
INTEGER, BIGINT, SMALLINT
DECIMAL(10,2), NUMERIC(10,2)
REAL, DOUBLE PRECISION

# Tipos de caracteres
CHAR(n), VARCHAR(n), TEXT

# Tipos de Fecha/Hora
DATE, TIME, TIMESTAMP
TIMESTAMPTZ (con zona horaria)

# Booleano y otros
BOOLEAN
JSON, JSONB
UUID
ARRAY (ej. INTEGER[])

# Clave primaria
id SERIAL PRIMARY KEY

# Clave foránea
user_id INTEGER REFERENCES users(id)

# Restricción única
email VARCHAR(100) UNIQUE

# Restricción CHECK
age INTEGER CHECK (age >= 0)

# No nulo
name VARCHAR(50) NOT NULL
```

### Índices: `CREATE INDEX`

Mejorar el rendimiento de las consultas con índices de base de datos.

```sql
# Índice básico
CREATE INDEX idx_username ON users(username);
# Índice único
CREATE UNIQUE INDEX idx_unique_email
    ON users(email);
# Índice compuesto
CREATE INDEX idx_user_date
    ON orders(user_id, created_at);
# Índice parcial
CREATE INDEX idx_active_users
    ON users(username) WHERE active = true;
# Eliminar índice
DROP INDEX IF EXISTS idx_username;
```

### Secuencias: `CREATE SEQUENCE`

Generar valores numéricos únicos automáticamente.

```sql
# Crear secuencia
CREATE SEQUENCE user_id_seq;
# Usar secuencia en tabla
CREATE TABLE users (
    id INTEGER DEFAULT nextval('user_id_seq'),
    username VARCHAR(50)
);
# Reiniciar secuencia
ALTER SEQUENCE user_id_seq RESTART WITH 1000;
```

## Operaciones CRUD

### Insertar Datos: `INSERT`

Añadir nuevos registros a las tablas de la base de datos.

```sql
# Insertar registro único
INSERT INTO users (username, email)
VALUES ('john_doe', 'john@example.com');
# Insertar múltiples registros
INSERT INTO users (username, email) VALUES
    ('alice', 'alice@example.com'),
    ('bob', 'bob@example.com');
# Insertar con retorno
INSERT INTO users (username, email)
VALUES ('jane', 'jane@example.com')
RETURNING id, created_at;
# Insertar desde selección
INSERT INTO archive_users
SELECT * FROM users WHERE active = false;
```

### Actualizar Datos: `UPDATE`

Modificar registros existentes en las tablas de la base de datos.

```sql
# Actualizar registros específicos
UPDATE users
SET email = 'newemail@example.com'
WHERE username = 'john_doe';
# Actualizar múltiples columnas
UPDATE users
SET email = 'new@example.com',
    updated_at = NOW()
WHERE id = 1;
# Actualizar con subconsulta
UPDATE orders
SET total = (SELECT SUM(price) FROM order_items
            WHERE order_id = orders.id);
```

### Seleccionar Datos: `SELECT`

Consultar y recuperar datos de las tablas de la base de datos.

```sql
# Select básico
SELECT * FROM users;
# Seleccionar columnas específicas
SELECT id, username, email FROM users;
# Select con condiciones
SELECT * FROM users
WHERE active = true AND created_at > '2024-01-01';
# Select con ordenación y límites
SELECT * FROM users
ORDER BY created_at DESC
LIMIT 10 OFFSET 20;
```

### Eliminar Datos: `DELETE`

Eliminar registros de las tablas de la base de datos.

```sql
# Eliminar registros específicos
DELETE FROM users
WHERE active = false;
# Eliminar con subconsulta
DELETE FROM orders
WHERE user_id IN (
    SELECT id FROM users WHERE active = false
);
# Eliminar todos los registros
DELETE FROM temp_table;
# Eliminar con retorno
DELETE FROM users
WHERE id = 5
RETURNING *;
```

## Consultas Avanzadas

### Joins: `INNER/LEFT/RIGHT JOIN`

Combinar datos de múltiples tablas usando varios tipos de unión.

```sql
# Inner join
SELECT u.username, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# Left join
SELECT u.username, o.total
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# Múltiples uniones
SELECT u.username, o.total, p.name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

### Subconsultas y CTEs

Usar consultas anidadas y expresiones de tabla comunes para operaciones complejas.

```sql
# Subconsulta en WHERE
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders);
# Expresión de Tabla Común (CTE)
WITH active_users AS (
    SELECT * FROM users WHERE active = true
)
SELECT au.username, COUNT(o.id) as order_count
FROM active_users au
LEFT JOIN orders o ON au.id = o.user_id
GROUP BY au.username;
```

### Agregación: `GROUP BY`

Agrupar datos y aplicar funciones agregadas para el análisis.

```sql
# Agrupación básica
SELECT status, COUNT(*) as count
FROM orders
GROUP BY status;
# Múltiples agregaciones
SELECT user_id,
       COUNT(*) as order_count,
       SUM(total) as total_spent,
       AVG(total) as avg_order
FROM orders
GROUP BY user_id
HAVING COUNT(*) > 5;
```

### Funciones de Ventana

Realizar cálculos a través de filas relacionadas sin agrupar.

```sql
# Numeración de filas
SELECT username, email,
       ROW_NUMBER() OVER (ORDER BY created_at) as row_num
FROM users;
# Totales acumulados
SELECT date, amount,
       SUM(amount) OVER (ORDER BY date) as running_total
FROM sales;
# Clasificación
SELECT username, score,
       RANK() OVER (ORDER BY score DESC) as rank
FROM user_scores;
```

## Importación y Exportación de Datos

### Importación CSV: `COPY`

Importar datos desde archivos CSV a tablas de PostgreSQL.

```sql
# Importar desde archivo CSV
COPY users(username, email, age)
FROM '/ruta/a/users.csv'
DELIMITER ',' CSV HEADER;
# Importar con opciones específicas
COPY products
FROM '/ruta/a/products.csv'
WITH (FORMAT csv, HEADER true, DELIMITER ';');
# Importar desde stdin
\copy users(username, email) FROM STDIN WITH CSV;
```

### Exportación CSV: `COPY TO`

Exportar datos de PostgreSQL a archivos CSV.

```sql
# Exportar a archivo CSV
COPY users TO '/ruta/a/users_export.csv'
WITH (FORMAT csv, HEADER true);
# Exportar resultados de consulta
COPY (SELECT username, email FROM users WHERE active = true)
TO '/ruta/a/active_users.csv' CSV HEADER;
# Exportar a stdout
\copy (SELECT * FROM orders) TO STDOUT WITH CSV HEADER;
```

### Copia de Seguridad y Restauración: `pg_dump`

Crear copias de seguridad de bases de datos y restaurar desde archivos de copia de seguridad.

```bash
# Volcar base de datos completa
pg_dump -U nombre_usuario -h nombre_host nombre_base_datos > backup.sql
# Volcar tabla específica
pg_dump -U nombre_usuario -t nombre_tabla nombre_base_datos > table_backup.sql
# Copia de seguridad comprimida
pg_dump -U nombre_usuario -Fc nombre_base_datos > backup.dump
# Restaurar desde copia de seguridad
psql -U nombre_usuario -d nombre_base_datos < backup.sql
# Restaurar copia de seguridad comprimida
pg_restore -U nombre_usuario -d nombre_base_datos backup.dump
```

### Operaciones de Datos JSON

Trabajar con tipos de datos JSON y JSONB para datos semiestructurados.

```sql
# Insertar datos JSON
INSERT INTO products (name, metadata)
VALUES ('Laptop', '{"brand": "Dell", "price": 999.99}');
# Consultar campos JSON
SELECT name, metadata->>'brand' as brand
FROM products
WHERE metadata->>'price'::numeric > 500;
# Operaciones de array JSON
SELECT name FROM products
WHERE metadata->'features' ? 'wireless';
```

## Gestión de Usuarios y Seguridad

### Crear Usuarios y Roles

Administrar el acceso a la base de datos con usuarios y roles.

```sql
# Crear usuario
CREATE USER miusuario WITH PASSWORD 'contraseñasecreta';
# Crear rol
CREATE ROLE readonly_user;
# Crear usuario con privilegios específicos
CREATE USER admin_user WITH
    CREATEDB CREATEROLE PASSWORD 'adminpass';
# Otorgar rol a usuario
GRANT readonly_user TO miusuario;
```

### Permisos: `GRANT/REVOKE`

Controlar el acceso a los objetos de la base de datos a través de permisos.

```sql
# Otorgar permisos de tabla
GRANT SELECT, INSERT ON users TO miusuario;
# Otorgar todos los privilegios en la tabla
GRANT ALL ON orders TO admin_user;
# Otorgar permisos de base de datos
GRANT CONNECT ON DATABASE midb TO miusuario;
# Revocar permisos
REVOKE INSERT ON users FROM miusuario;
```

### Ver Información del Usuario

Verificar usuarios existentes y sus permisos.

```sql
# Listar todos los usuarios
\du
# Ver permisos de tabla
SELECT table_name, privilege_type, grantee
FROM information_schema.table_privileges
WHERE table_schema = 'public';
# Ver usuario actual
SELECT current_user;
# Ver membresías de rol
SELECT r.rolname, r.rolsuper, r.rolcreaterole
FROM pg_roles r;
```

### Contraseña y Seguridad

Administrar contraseñas de usuario y configuraciones de seguridad.

```sql
# Cambiar contraseña de usuario
ALTER USER miusuario PASSWORD 'nuevacontraseña';
# Establecer expiración de contraseña
ALTER USER miusuario VALID UNTIL '2025-12-31';
# Crear usuario sin inicio de sesión
CREATE ROLE reporting_role NOLOGIN;
# Habilitar/deshabilitar usuario
ALTER USER miusuario WITH NOLOGIN;
ALTER USER miusuario WITH LOGIN;
```

## Rendimiento y Monitoreo

### Análisis de Consultas: `EXPLAIN`

Analizar planes de ejecución de consultas y optimizar el rendimiento.

```sql
# Mostrar plan de ejecución de consulta
EXPLAIN SELECT * FROM users WHERE active = true;
# Analizar con estadísticas de ejecución reales
EXPLAIN ANALYZE
SELECT u.username, COUNT(o.id)
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.username;
# Información detallada de ejecución
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT * FROM large_table WHERE indexed_col = 'value';
```

### Mantenimiento de Base de Datos: `VACUUM`

Mantener el rendimiento de la base de datos a través de operaciones de limpieza regulares.

```sql
# Vacuum básico
VACUUM users;
# Vacuum completo con análisis
VACUUM FULL ANALYZE users;
# Estado de auto-vacuum
SELECT schemaname, tablename, last_vacuum, last_autovacuum
FROM pg_stat_user_tables;
# Reindexar tabla
REINDEX TABLE users;
```

### Monitoreo de Consultas

Rastrear la actividad de la base de datos e identificar problemas de rendimiento.

```sql
# Actividad actual
SELECT pid, usename, query, state
FROM pg_stat_activity
WHERE state != 'idle';
# Consultas de larga duración
SELECT pid, now() - query_start as duration, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC;
# Matar consulta específica
SELECT pg_terminate_backend(pid) WHERE pid = 12345;
```

### Estadísticas de la Base de Datos

Obtener información sobre el uso de la base de datos y métricas de rendimiento.

```sql
# Estadísticas de la tabla
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del
FROM pg_stat_user_tables;
# Estadísticas de uso de índice
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes;
# Tamaño de la base de datos
SELECT pg_size_pretty(pg_database_size('midatabase'));
```

## Características Avanzadas

### Vistas: `CREATE VIEW`

Crear tablas virtuales para simplificar consultas complejas y proporcionar abstracción de datos.

```sql
# Crear vista simple
CREATE VIEW active_users AS
SELECT id, username, email
FROM users WHERE active = true;
# Crear vista con uniones
CREATE OR REPLACE VIEW order_summary AS
SELECT u.username, COUNT(o.id) as total_orders,
       SUM(o.total) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.username;
# Eliminar vista
DROP VIEW IF EXISTS order_summary;
```

### Triggers y Funciones

Automatizar operaciones de base de datos con procedimientos almacenados y triggers.

```sql
# Crear función
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
# Crear trigger
CREATE TRIGGER update_user_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();
```

### Transacciones

Asegurar la consistencia de los datos con el control de transacciones.

```sql
# Iniciar transacción
BEGIN;
UPDATE accounts SET balance = balance - 100
WHERE id = 1;
UPDATE accounts SET balance = balance + 100
WHERE id = 2;
# Confirmar transacción
COMMIT;
# Deshacer si es necesario
ROLLBACK;
# Puntos de guardado
SAVEPOINT my_savepoint;
ROLLBACK TO my_savepoint;
```

### Configuración y Ajuste

Optimizar la configuración del servidor PostgreSQL para un mejor rendimiento.

```sql
# Ver configuración actual
SHOW shared_buffers;
SHOW max_connections;
# Establecer parámetros de configuración
SET work_mem = '256MB';
SET random_page_cost = 1.1;
# Recargar configuración
SELECT pg_reload_conf();
# Mostrar ubicación del archivo de configuración
SHOW config_file;
```

## Configuración y Consejos de psql

### Archivos de Conexión: `.pgpass`

Almacenar credenciales de base de datos de forma segura para la autenticación automática.

```bash
# Crear archivo .pgpass (formato: hostname:port:database:username:password)
echo "localhost:5432:midatabase:miusuario:micontraseñasecreta" >> ~/.pgpass
# Establecer permisos adecuados
chmod 600 ~/.pgpass
# Usar archivo de servicio de conexión
# ~/.pg_service.conf
[midb]
host=localhost
port=5432
dbname=midatabase
user=miusuario
```

### Configuración de psql: `.psqlrc`

Personalizar la configuración de inicio y el comportamiento de psql.

```bash
# Crear archivo ~/.psqlrc con configuraciones personalizadas
\set QUIET on
\timing on
\set PROMPT1 '%n@%M:%> %`date` %R%# '
\set HISTSIZE 5000
\set COMP_KEYWORD_CASE upper
\x auto
\set QUIET off
# Alias personalizados
\set show_slow_queries 'SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;'
```

### Variables de Entorno

Establecer variables de entorno de PostgreSQL para facilitar las conexiones.

```bash
# Establecer en su perfil de shell
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=midatabase
export PGUSER=miusuario
# Luego simplemente conéctese con
psql
# O usar entorno específico
PGDATABASE=testdb psql
```

### Información de la Base de Datos

Obtener información sobre los objetos y la estructura de la base de datos.

```bash
# Listar bases de datos
\l, \l+
# Listar tablas en la base de datos actual
\dt, \dt+
# Listar vistas
\dv, \dv+
# Listar índices
\di, \di+
# Listar funciones
\df, \df+
# Listar secuencias
\ds, \ds+
# Describir estructura de tabla
\d nombre_tabla
\d+ nombre_tabla
# Listar restricciones de tabla
\d+ nombre_tabla
# Mostrar permisos de tabla
\dp nombre_tabla
\z nombre_tabla
# Listar claves foráneas
SELECT * FROM information_schema.table_constraints
WHERE constraint_type = 'FOREIGN KEY';
```

### Salida y Formato

Controlar cómo psql muestra los resultados de las consultas y la salida.

```bash
# Alternar salida expandida
\x
# Cambiar formato de salida
\H  -- Salida HTML
\t  -- Solo tuplas (sin encabezados)
# Salida a archivo
\o filename.txt
SELECT * FROM users;
\o  -- Detener salida a archivo
# Ejecutar SQL desde archivo
\i script.sql
# Editar consulta en editor externo
\e
```

### Tiempos e Historial

Rastrear el rendimiento de las consultas y administrar el historial de comandos.

```bash
# Alternar visualización de tiempos
\timing
# Mostrar historial de comandos
\s
# Guardar historial de comandos en archivo
\s filename.txt
# Limpiar pantalla
\! clear  -- Linux/Mac
\! cls   -- Windows
# Mostrar último error
\errverbose
```

## Enlaces Relevantes

- <router-link to="/database">Hoja de Trucos de Base de Datos</router-link>
- <router-link to="/mysql">Hoja de Trucos de MySQL</router-link>
- <router-link to="/sqlite">Hoja de Trucos de SQLite</router-link>
- <router-link to="/mongodb">Hoja de Trucos de MongoDB</router-link>
- <router-link to="/redis">Hoja de Trucos de Redis</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>

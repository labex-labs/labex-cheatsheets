---
title: 'Datenbank Spickzettel | LabEx'
description: 'Lernen Sie Datenbankmanagement mit diesem umfassenden Spickzettel. Schnelle Referenz für SQL-Abfragen, Datenbankdesign, Normalisierung, Indizierung, Transaktionen und relationale Datenbankadministration.'
pdfUrl: '/cheatsheets/pdf/database-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Datenbank Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/database">Lernen Sie Datenbankmanagement mit Hands-On-Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Erlernen Sie Datenbankmanagement und SQL durch praktische Übungen und reale Szenarien. LabEx bietet umfassende Datenbankkurse, die wesentliche SQL-Befehle, Datenmanipulation, Abfrageoptimierung, Datenbankdesign und -administration abdecken. Meistern Sie relationale Datenbanken, NoSQL-Systeme und Best Practices für die Datenbank-Sicherheit.
</base-disclaimer-content>
</base-disclaimer>

## Datenbankerstellung & -verwaltung

### Datenbank erstellen: `CREATE DATABASE`

Erstellt eine neue Datenbank zur Speicherung Ihrer Daten.

```sql
-- Neue Datenbank erstellen
CREATE DATABASE company_db;
-- Datenbank mit Zeichensatz erstellen
CREATE DATABASE company_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
-- Datenbank verwenden
USE company_db;
```

<BaseQuiz id="database-create-1" correct="A">
  <template #question>
    Was bewirkt `CREATE DATABASE company_db`?
  </template>
  
  <BaseQuizOption value="A" correct>Erstellt eine neue, leere Datenbank namens company_db</BaseQuizOption>
  <BaseQuizOption value="B">Erstellt eine Tabelle in der Datenbank</BaseQuizOption>
  <BaseQuizOption value="C">Löscht die Datenbank</BaseQuizOption>
  <BaseQuizOption value="D">Sichert die Datenbank</BaseQuizOption>
  
  <BaseQuizAnswer>
    `CREATE DATABASE` erstellt eine neue, leere Datenbank. Nach der Erstellung müssen Sie `USE` verwenden, um sie auszuwählen, und dann Tabellen darin erstellen.
  </BaseQuizAnswer>
</BaseQuiz>

### Datenbanken anzeigen: `SHOW DATABASES`

Listet alle verfügbaren Datenbanken auf dem Server auf.

```sql
-- Alle Datenbanken auflisten
SHOW DATABASES;
-- Datenbankinformationen anzeigen
SELECT SCHEMA_NAME FROM
INFORMATION_SCHEMA.SCHEMATA;
-- Aktuelle Datenbank anzeigen
SELECT DATABASE();
```

### Datenbank löschen: `DROP DATABASE`

Löscht eine gesamte Datenbank dauerhaft.

```sql
-- Datenbank löschen (Vorsicht!)
DROP DATABASE old_company_db;
-- Datenbank löschen, falls sie existiert
DROP DATABASE IF EXISTS old_company_db;
```

### Datenbank sichern: `mysqldump`

Erstellt Sicherungskopien Ihrer Datenbank.

```sql
-- Kommandozeilen-Sicherung
mysqldump -u username -p database_name > backup.sql
-- Wiederherstellen aus Sicherung
mysql -u username -p database_name < backup.sql
```

### Datenbankbenutzer: `CREATE USER`

Verwaltet Datenbankbenutzerkonten und Berechtigungen.

```sql
-- Neuen Benutzer erstellen
CREATE USER 'newuser'@'localhost' IDENTIFIED BY
'password';
-- Berechtigungen erteilen
GRANT SELECT, INSERT ON company_db.* TO
'newuser'@'localhost';
-- Benutzerberechtigungen anzeigen
SHOW GRANTS FOR 'newuser'@'localhost';
```

### Datenbankinformationen: `INFORMATION_SCHEMA`

Fragt Metadaten und Strukturinformationen der Datenbank ab.

```sql
-- Alle Tabellen anzeigen
SELECT TABLE_NAME FROM
INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'company_db';
-- Tabellenspalten anzeigen
DESCRIBE employees;
```

## Tabellenstruktur & Infos

### Tabelle erstellen: `CREATE TABLE`

Definiert neue Tabellen mit Spalten und Datentypen.

```sql
-- Grundlegende Tabellenerstellung
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY
KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE,
    salary DECIMAL(10,2),
    hire_date DATE,
    department VARCHAR(50)
);
-- Tabellenstruktur anzeigen
DESCRIBE employees;
SHOW COLUMNS FROM employees;
```

### Tabelle ändern: `ALTER TABLE`

Modifiziert die vorhandene Tabellenstruktur und Spalten.

```sql
-- Neue Spalte hinzufügen
ALTER TABLE employees ADD
COLUMN phone VARCHAR(15);
-- Spaltentyp ändern
ALTER TABLE employees MODIFY
COLUMN salary DECIMAL(12,2);
-- Spalte löschen
ALTER TABLE employees DROP
COLUMN phone;
-- Tabelle umbenennen
RENAME TABLE employees TO staff;
```

<BaseQuiz id="database-alter-1" correct="C">
  <template #question>
    Was bewirkt `ALTER TABLE employees ADD COLUMN phone VARCHAR(15)`?
  </template>
  
  <BaseQuizOption value="A">Löscht die Spalte phone</BaseQuizOption>
  <BaseQuizOption value="B">Modifiziert die Spalte phone</BaseQuizOption>
  <BaseQuizOption value="C" correct>Fügt der Tabelle employees eine neue Spalte namens phone hinzu</BaseQuizOption>
  <BaseQuizOption value="D">Benennt die Tabelle um</BaseQuizOption>
  
  <BaseQuizAnswer>
    `ALTER TABLE ... ADD COLUMN` fügt einer bestehenden Tabelle eine neue Spalte hinzu. Die neue Spalte wird mit dem angegebenen Datentyp hinzugefügt und ist für vorhandene Zeilen NULL, sofern kein Standardwert angegeben wird.
  </BaseQuizAnswer>
</BaseQuiz>

### Tabelleninformationen: `SHOW`

Ruft detaillierte Informationen über Tabellen und deren Eigenschaften ab.

```sql
-- Alle Tabellen anzeigen
SHOW TABLES;
-- Tabellenstruktur anzeigen
SHOW CREATE TABLE employees;
-- Tabellenstatus anzeigen
SHOW TABLE STATUS LIKE
'employees';
-- Zeilen in Tabelle zählen
SELECT COUNT(*) FROM employees;
```

## Datenmanipulation & CRUD-Operationen

### Daten einfügen: `INSERT INTO`

Fügt neue Datensätze in Ihre Tabellen ein.

```sql
-- Einzelnen Datensatz einfügen
INSERT INTO employees (name, email, salary, hire_date,
department)
VALUES ('John Doe', 'john@company.com', 75000.00,
'2024-01-15', 'Engineering');
-- Mehrere Datensätze einfügen
INSERT INTO employees (name, email, salary,
department) VALUES
('Jane Smith', 'jane@company.com', 80000.00,
'Marketing'),
('Bob Johnson', 'bob@company.com', 65000.00, 'Sales');
-- Aus einer anderen Tabelle einfügen
INSERT INTO backup_employees
SELECT * FROM employees WHERE department =
'Engineering';
```

### Daten aktualisieren: `UPDATE`

Modifiziert vorhandene Datensätze in Tabellen.

```sql
-- Einzelnen Datensatz aktualisieren
UPDATE employees
SET salary = 85000.00, department = 'Senior Engineering'
WHERE id = 1;
-- Mehrere Datensätze aktualisieren
UPDATE employees
SET salary = salary * 1.05
WHERE hire_date < '2024-01-01';
-- Aktualisieren mit JOIN
UPDATE employees e
JOIN departments d ON e.department = d.name
SET e.salary = e.salary + d.bonus;
```

### Daten löschen: `DELETE FROM`

Entfernt Datensätze aus Tabellen.

```sql
-- Spezifische Datensätze löschen
DELETE FROM employees
WHERE department = 'Temporary';
-- Löschen mit Bedingungen
DELETE FROM employees
WHERE hire_date < '2020-01-01' AND salary < 50000;
-- Tabelle leeren (schneller für alle Datensätze)
TRUNCATE TABLE temp_employees;
```

### Daten ersetzen: `REPLACE INTO`

Fügt Datensätze ein oder aktualisiert sie basierend auf dem Primärschlüssel.

```sql
-- Datensatz ersetzen (einfügen oder aktualisieren)
REPLACE INTO employees (id, name, email, salary)
VALUES (1, 'John Doe Updated',
'john.new@company.com', 90000);
-- Bei doppelter Schlüsselverletzung aktualisieren
INSERT INTO employees (id, name, salary)
VALUES (1, 'John Doe', 85000)
ON DUPLICATE KEY UPDATE salary = VALUES(salary);
```

## Datenabfrage & Auswahl

### Basis-SELECT: `SELECT`

Ruft Daten aus Datenbanktabellen ab.

```sql
-- Alle Spalten auswählen
SELECT * FROM employees;
-- Spezifische Spalten auswählen
SELECT name, email, salary FROM employees;
-- Auswahl mit Alias
SELECT name AS employee_name, salary AS
annual_salary
FROM employees;
-- Eindeutige Werte auswählen
SELECT DISTINCT department FROM employees;
```

### Daten filtern: `WHERE`

Wendet Bedingungen an, um Abfrageergebnisse zu filtern.

```sql
-- Grundlegende Bedingungen
SELECT * FROM employees WHERE salary > 70000;
-- Mehrere Bedingungen
SELECT * FROM employees
WHERE department = 'Engineering' AND salary > 75000;
-- Musterabgleich
SELECT * FROM employees WHERE name LIKE 'John%';
```

<BaseQuiz id="database-where-1" correct="C">
  <template #question>
    Was entspricht `LIKE 'John%'` in einer WHERE-Klausel?
  </template>
  
  <BaseQuizOption value="A">Nur exakte Übereinstimmungen mit "John"</BaseQuizOption>
  <BaseQuizOption value="B">Werte, die mit "John" enden</BaseQuizOption>
  <BaseQuizOption value="C" correct>Werte, die mit "John" beginnen</BaseQuizOption>
  <BaseQuizOption value="D">Werte, die irgendwo "John" enthalten</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das `%`-Platzhalterzeichen in SQL steht für eine beliebige Zeichenfolge. `LIKE 'John%'` passt auf jeden Wert, der mit "John" beginnt, wie z.B. "John", "Johnny", "Johnson" usw.
  </BaseQuizAnswer>
</BaseQuiz>

```sql
-- Bereichsabfragen
SELECT * FROM employees
WHERE hire_date BETWEEN '2023-01-01' AND '2023-12-
31';
```

### Daten sortieren: `ORDER BY`

Sortiert Abfrageergebnisse in aufsteigender oder absteigender Reihenfolge.

```sql
-- Nach einer einzelnen Spalte sortieren
SELECT * FROM employees ORDER BY salary DESC;
-- Nach mehreren Spalten sortieren
SELECT * FROM employees
ORDER BY department ASC, salary DESC;
-- Sortieren mit LIMIT
SELECT * FROM employees
ORDER BY hire_date DESC LIMIT 10;
```

### Ergebnisse begrenzen: `LIMIT`

Steuert die Anzahl der zurückgegebenen Datensätze.

```sql
-- Anzahl der Ergebnisse begrenzen
SELECT * FROM employees LIMIT 5;
-- Paginierung mit OFFSET
SELECT * FROM employees
ORDER BY id LIMIT 10 OFFSET 20;
-- Top N Ergebnisse
SELECT * FROM employees
ORDER BY salary DESC LIMIT 5;
```

## Erweiterte Abfragen

### Aggregatfunktionen: `COUNT`, `SUM`, `AVG`

Führt Berechnungen für Datengruppen durch.

```sql
-- Datensätze zählen
SELECT COUNT(*) FROM employees;
-- Summe und Durchschnitt
SELECT SUM(salary) as total_payroll, AVG(salary) as
avg_salary
FROM employees;
-- Gruppenstatistiken
SELECT department, COUNT(*) as employee_count,
AVG(salary) as avg_salary
FROM employees GROUP BY department;
-- Having-Klausel zur Gruppenfilterung
SELECT department, COUNT(*) as count
FROM employees
GROUP BY department
HAVING COUNT(*) > 5;
```

### Unterabfragen: Geschachtelte Abfragen

Verwendet Abfragen innerhalb anderer Abfragen für komplexe Operationen.

```sql
-- Unterabfrage in der WHERE-Klausel
SELECT * FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);
-- Unterabfrage mit IN
SELECT * FROM employees
WHERE department IN (
    SELECT name FROM departments WHERE budget >
100000
);
-- Korrelierte Unterabfrage
SELECT * FROM employees e1
WHERE salary > (
    SELECT AVG(salary) FROM employees e2
    WHERE e2.department = e1.department
);
```

### Tabellen-Joins: `JOIN`

Kombiniert Daten aus mehreren Tabellen.

```sql
-- Inner Join
SELECT e.name, e.salary, d.department_name
FROM employees e
INNER JOIN departments d ON e.department = d.id;
-- Left Join
SELECT e.name, d.department_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id;
-- Mehrere Joins
SELECT e.name, d.department_name, p.project_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id
LEFT JOIN projects p ON e.id = p.employee_id;
```

### Fensterfunktionen: Erweiterte Analysen

Führt Berechnungen über zusammengehörige Zeilen durch.

```sql
-- Zeilennummerierung
SELECT name, salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
FROM employees;
-- Laufende Summen
SELECT name, salary,
    SUM(salary) OVER (ORDER BY hire_date) as
running_total
FROM employees;
-- Partitionierung nach Gruppen
SELECT name, department, salary,
    AVG(salary) OVER (PARTITION BY department) as
dept_avg
FROM employees;
```

## Datenbank-Constraints & Integrität

### Primärschlüssel: `PRIMARY KEY`

Stellt die eindeutige Identifizierung jedes Datensatzes sicher.

```sql
-- Primärschlüssel mit einer Spalte
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100)
);
-- Zusammengesetzter Primärschlüssel
CREATE TABLE order_items (
    order_id INT,
    product_id INT,
    quantity INT,
    PRIMARY KEY (order_id, product_id)
);
```

### Fremdschlüssel: `FOREIGN KEY`

Erhält die referentielle Integrität zwischen Tabellen.

```sql
-- Fremdschlüssel-Constraint hinzufügen
CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);
-- Fremdschlüssel zu bestehender Tabelle hinzufügen
ALTER TABLE employees
ADD CONSTRAINT fk_department
FOREIGN KEY (department_id) REFERENCES
departments(id);
```

### Eindeutigkeits-Constraints: `UNIQUE`

Verhindert doppelte Werte in Spalten.

```sql
-- Eindeutigkeits-Constraint für eine einzelne Spalte
ALTER TABLE employees
ADD CONSTRAINT unique_email UNIQUE (email);
-- Zusammengesetzter Eindeutigkeits-Constraint
ALTER TABLE employees
ADD CONSTRAINT unique_name_dept UNIQUE (name,
department);
```

### Check-Constraints: `CHECK`

Erzwingt Geschäftsregeln und Datenvalidierung.

```sql
-- Einfacher Check-Constraint
ALTER TABLE employees
ADD CONSTRAINT check_salary CHECK (salary > 0);
-- Komplexer Check-Constraint
ALTER TABLE employees
ADD CONSTRAINT check_age
CHECK (YEAR(CURDATE()) - YEAR(birth_date) >= 18);
```

## Datenbankleistung & Optimierung

### Indizes: `CREATE INDEX`

Beschleunigt den Datenabruf durch Datenbankindizes.

```sql
-- Index für eine einzelne Spalte erstellen
CREATE INDEX idx_employee_name ON
employees(name);
-- Zusammengesetzter Index
CREATE INDEX idx_dept_salary ON
employees(department, salary);
-- Eindeutiger Index
CREATE UNIQUE INDEX idx_employee_email ON
employees(email);
-- Tabellenindizes anzeigen
SHOW INDEX FROM employees;
```

### Abfrageoptimierung: `EXPLAIN`

Analysiert und optimiert die Abfrageleistung.

```sql
-- Analyse des Abfrageausführungsplans
EXPLAIN SELECT * FROM employees WHERE salary >
75000;
-- Detaillierte Analyse
EXPLAIN ANALYZE SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department = d.id;
```

### Leistungsüberwachung

Überwacht die Datenbankleistung und identifiziert Engpässe.

```sql
-- Laufende Prozesse anzeigen
SHOW PROCESSLIST;
-- Datenbankstatus anzeigen
SHOW STATUS LIKE 'Slow_queries';
-- Informationen zum Abfrage-Cache
SHOW STATUS LIKE 'Qcache%';
```

### Datenbankwartung

Regelmäßige Wartungsaufgaben für optimale Leistung.

```sql
-- Tabellenoptimierung
OPTIMIZE TABLE employees;
-- Tabellenstatistiken analysieren
ANALYZE TABLE employees;
-- Tabellenintegrität prüfen
CHECK TABLE employees;
-- Tabelle bei Bedarf reparieren
REPAIR TABLE employees;
```

## Datenimport/Export

### Daten importieren: `LOAD DATA`

Importiert Daten aus externen Dateien in Datenbanktabellen.

```sql
-- Aus CSV-Datei importieren
LOAD DATA INFILE 'employees.csv'
INTO TABLE employees
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
-- Import mit Spaltenzuordnung
LOAD DATA INFILE 'data.csv'
INTO TABLE employees (name, email, salary);
```

### Daten exportieren: `SELECT INTO`

Exportiert Abfrageergebnisse in externe Dateien.

```sql
-- Export in CSV-Datei
SELECT name, email, salary
INTO OUTFILE 'employee_export.csv'
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
FROM employees;
-- Export mit mysqldump
mysqldump -u username -p --tab=/path/to/export
database_name table_name
```

### Datenmigration: Zwischen Datenbanken

Verschiebt Daten zwischen verschiedenen Datenbanksystemen.

```sql
-- Tabelle aus bestehender Struktur erstellen
CREATE TABLE employees_backup LIKE employees;
-- Daten zwischen Tabellen kopieren
INSERT INTO employees_backup SELECT * FROM
employees;
-- Migration mit Bedingungen
INSERT INTO new_employees
SELECT * FROM old_employees WHERE active = 1;
```

### Massenoperationen

Effiziente Handhabung von groß angelegten Datenoperationen.

```sql
-- Masseneinfügung mit INSERT IGNORE
INSERT IGNORE INTO employees (name, email) VALUES
('John Doe', 'john@email.com'),
('Jane Smith', 'jane@email.com');
-- Stapelaktualisierungen
UPDATE employees SET salary = salary * 1.1 WHERE
department = 'Sales';
```

## Datenbank-Sicherheit & Zugriffskontrolle

### Benutzerverwaltung: `CREATE USER`

Erstellt und verwaltet Datenbankbenutzerkonten.

```sql
-- Benutzer mit Passwort erstellen
CREATE USER 'app_user'@'localhost' IDENTIFIED BY
'secure_password';
-- Benutzer für spezifischen Host erstellen
CREATE USER 'remote_user'@'192.168.1.%' IDENTIFIED
BY 'password';
-- Benutzer löschen
DROP USER 'old_user'@'localhost';
```

### Berechtigungen: `GRANT` & `REVOKE`

Steuert den Zugriff auf Datenbankobjekte und Operationen.

```sql
-- Spezifische Berechtigungen erteilen
GRANT SELECT, INSERT ON company_db.employees TO
'app_user'@'localhost';
-- Alle Berechtigungen erteilen
GRANT ALL PRIVILEGES ON company_db.* TO
'admin_user'@'localhost';
-- Berechtigungen entziehen
REVOKE INSERT ON company_db.employees FROM
'app_user'@'localhost';
-- Benutzerberechtigungen anzeigen
SHOW GRANTS FOR 'app_user'@'localhost';
```

### Datenbankrollen

Organisiert Berechtigungen mithilfe von Datenbankrollen.

```sql
-- Rolle erstellen (MySQL 8.0+)
CREATE ROLE 'app_read_role', 'app_write_role';
-- Berechtigungen der Rolle erteilen
GRANT SELECT ON company_db.* TO 'app_read_role';
GRANT INSERT, UPDATE, DELETE ON company_db.* TO
'app_write_role';
-- Rolle dem Benutzer zuweisen
GRANT 'app_read_role' TO 'readonly_user'@'localhost';
```

### Schutz vor SQL-Injection

Schutz vor gängigen Sicherheitslücken.

```sql
-- Prepared Statements verwenden (Anwendungsebene)
-- Schlecht: SELECT * FROM users WHERE id = ' + userInput
-- Gut: Parameterisierte Abfragen verwenden
-- Eingabedaten typvalidieren
-- Gespeicherte Prozeduren verwenden, wenn möglich
-- Prinzip der geringsten Rechte anwenden
```

## Datenbankinstallation & Einrichtung

### MySQL-Installation

Beliebte Open-Source relationale Datenbank.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# MySQL-Dienst starten
sudo systemctl start mysql
sudo systemctl enable mysql
# Installation absichern
sudo mysql_secure_installation
```

### PostgreSQL-Installation

Fortschrittliche Open-Source relationale Datenbank.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql
postgresql-contrib
# Zum postgres-Benutzer wechseln
sudo -u postgres psql
# Datenbank und Benutzer erstellen
CREATE DATABASE myapp;
CREATE USER myuser WITH
PASSWORD 'mypassword';
```

### SQLite-Einrichtung

Leichtgewichtige, dateibasierte Datenbank.

```bash
# SQLite installieren
sudo apt install sqlite3
# Datenbankdatei erstellen
sqlite3 mydatabase.db
# Grundlegende SQLite-Befehle
.help
.tables
.schema tablename
.quit
```

## Datenbankkonfiguration & Tuning

### MySQL-Konfiguration

Wichtige MySQL-Konfigurationsparameter.

```sql
-- my.cnf Konfigurationsdatei
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
-- Aktuelle Einstellungen anzeigen
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW STATUS LIKE 'Connections';
```

### Verbindungsverwaltung

Verbindungen und Pooling verwalten.

```sql
-- Aktuelle Verbindungen anzeigen
SHOW PROCESSLIST;
-- Spezifische Verbindung beenden
KILL CONNECTION 123;
-- Timeout-Einstellungen für Verbindungen
SET SESSION wait_timeout = 600;
SET SESSION interactive_timeout = 600;
```

### Backup-Konfiguration

Einrichtung automatisierter Datenbank-Backups.

```bash
# Automatisiertes Backup-Skript
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mysqldump -u backup_user -p mydatabase >
backup_$DATE.sql
# Planung mit Cron
0 2 * * * /path/to/backup_script.sh
```

### Überwachung & Protokollierung

Überwachung der Datenbankaktivität und Leistung.

```sql
-- Point-in-Time Recovery Einrichtung
SET GLOBAL log_bin = ON;
-- Slow Query Log aktivieren
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
-- Datenbankgröße anzeigen
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

## SQL Best Practices

### Best Practices für das Schreiben von Abfragen

Schreiben Sie saubere, effiziente und lesbare SQL-Abfragen.

```sql
-- Aussagekräftige Tabellenaliase verwenden
SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.dept_id = d.id;
-- Spaltennamen anstelle von SELECT * angeben
SELECT name, email, salary FROM employees;
-- Angemessene Datentypen verwenden
CREATE TABLE products (
    id INT PRIMARY KEY,
    price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP
);
```

### Tipps zur Leistungsoptimierung

Optimieren Sie Abfragen für eine bessere Datenbankleistung.

```sql
-- Indizes für häufig abgefragte Spalten verwenden
CREATE INDEX idx_employee_dept ON
employees(department);
-- Ergebnissets begrenzen, wenn möglich
SELECT name FROM employees WHERE active = 1 LIMIT
100;
-- EXISTS anstelle von IN für Unterabfragen verwenden
SELECT * FROM customers c
WHERE EXISTS (SELECT 1 FROM orders o WHERE
o.customer_id = c.id);
```

## Relevante Links

- <router-link to="/mysql">MySQL Spickzettel</router-link>
- <router-link to="/postgresql">PostgreSQL Spickzettel</router-link>
- <router-link to="/sqlite">SQLite Spickzettel</router-link>
- <router-link to="/mongodb">MongoDB Spickzettel</router-link>
- <router-link to="/redis">Redis Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>

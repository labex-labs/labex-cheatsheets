---
title: 'SQLite Spickzettel'
description: 'Lernen Sie SQLite mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/sqlite-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
SQLite Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/sqlite">Lernen Sie SQLite mit Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie das SQLite-Datenbankmanagement durch praktische Übungen und reale Szenarien. LabEx bietet umfassende SQLite-Kurse, die wesentliche SQL-Operationen, Datenmanipulation, Abfrageoptimierung, Datenbankdesign und Leistungsabstimmung abdecken. Meistern Sie die Entwicklung von leichtgewichtigen Datenbanken und effizientes Datenmanagement.
</base-disclaimer-content>
</base-disclaimer>

## Datenbankerstellung & Verbindung

### Datenbank erstellen: `sqlite3 database.db`

Erstellt eine neue SQLite-Datenbankdatei.

```bash
# Datenbank erstellen oder öffnen
sqlite3 mydata.db
# Im-Speicher-Datenbank erstellen (temporär)
sqlite3 :memory:
# Datenbank mit Befehl erstellen
.open mydata.db
# Alle Datenbanken anzeigen
.databases
# Schema aller Tabellen anzeigen
.schema
# Tabellenliste anzeigen
.tables
# SQLite beenden
.exit
# Alternativer Beendigungsbefehl
.quit
```

### Datenbankinformationen: `.databases`

Listet alle angehängten Datenbanken und ihre Dateien auf.

```sql
-- Eine weitere Datenbank anhängen
ATTACH DATABASE 'backup.db' AS backup;
-- Aus angehängter Datenbank abfragen
SELECT * FROM backup.users;
-- Datenbank trennen
DETACH DATABASE backup;
```

### SQLite beenden: `.exit` oder `.quit`

Schließt die SQLite-Kommandozeilenschnittstelle.

```bash
.exit
.quit
```

### Datenbank sichern: `.backup`

Erstellt eine Sicherungskopie der aktuellen Datenbank.

```bash
# Sicherung in Datei
.backup backup.db
# Aus Sicherung wiederherstellen
.restore backup.db
# In SQL-Datei exportieren
.output backup.sql
.dump
# SQL-Skript importieren
.read backup.sql
```

## Tabellenerstellung & Schema

### Tabelle erstellen: `CREATE TABLE`

Erstellt eine neue Tabelle in der Datenbank mit Spalten und Einschränkungen.

```sql
-- Grundlegende Tabellenerstellung
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    age INTEGER,
    created_date DATE DEFAULT CURRENT_TIMESTAMP
);

-- Tabelle mit Fremdschlüssel
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    amount REAL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Datentypen: `INTEGER`, `TEXT`, `REAL`, `BLOB`

SQLite verwendet dynamische Typisierung mit Speicherkategorien für flexible Datenspeicherung.

```sql
-- Gängige Datentypen
CREATE TABLE products (
    id INTEGER,           -- Ganze Zahlen
    name TEXT,           -- Textzeichenketten
    price REAL,          -- Gleitkommazahlen
    image BLOB,          -- Binärdaten
    active BOOLEAN,      -- Boolean (als INTEGER gespeichert)
    created_at DATETIME  -- Datum und Uhrzeit
);
```

### Einschränkungen: `PRIMARY KEY`, `NOT NULL`, `UNIQUE`

Definieren Sie Einschränkungen, um die Datenintegrität und Tabellenbeziehungen zu gewährleisten.

```sql
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL,
    salary REAL CHECK(salary > 0),
    manager_id INTEGER REFERENCES employees(id)
);
```

## Dateneinfügung & -änderung

### Daten einfügen: `INSERT INTO`

Fügt neue Datensätze mit einer oder mehreren Zeilen in Tabellen ein.

```sql
-- Einzelnen Datensatz einfügen
INSERT INTO users (name, email, age)
VALUES ('John Doe', 'john@email.com', 30);

-- Mehrere Datensätze einfügen
INSERT INTO users (name, email, age) VALUES
    ('Jane Smith', 'jane@email.com', 25),
    ('Bob Wilson', 'bob@email.com', 35);

-- Einfügen mit allen Spalten
INSERT INTO users VALUES
    (NULL, 'Alice Brown', 'alice@email.com', 28, datetime('now'));
```

### Daten aktualisieren: `UPDATE SET`

Ändert bestehende Datensätze basierend auf Bedingungen.

```sql
-- Einzelne Spalte aktualisieren
UPDATE users SET age = 31 WHERE name = 'John Doe';

-- Mehrere Spalten aktualisieren
UPDATE users SET
    email = 'newemail@example.com',
    age = age + 1
WHERE id = 1;

-- Mit Unterabfrage aktualisieren
UPDATE products SET price = price * 1.1
WHERE category = 'Electronics';
```

### Daten löschen: `DELETE FROM`

Entfernt Datensätze aus Tabellen basierend auf angegebenen Bedingungen.

```sql
-- Spezifische Datensätze löschen
DELETE FROM users WHERE age < 18;

-- Alle Datensätze löschen (Tabellenstruktur beibehalten)
DELETE FROM users;

-- Mit Unterabfrage löschen
DELETE FROM orders
WHERE user_id IN (SELECT id FROM users WHERE active = 0);
```

### Upsert: `INSERT OR REPLACE`

Fügt neue Datensätze ein oder aktualisiert bestehende bei Konflikten.

```sql
-- Einfügen oder Ersetzen bei Konflikt
INSERT OR REPLACE INTO users (id, name, email)
VALUES (1, 'Updated Name', 'updated@email.com');

-- Bei Duplikaten ignorieren
INSERT OR IGNORE INTO users (name, email)
VALUES ('Duplicate', 'existing@email.com');
```

## Datenabfrage & Auswahl

### Basisabfragen: `SELECT`

Fragt Daten aus Tabellen mit der SELECT-Anweisung und verschiedenen Optionen ab.

```sql
-- Alle Spalten auswählen
SELECT * FROM users;

-- Spezifische Spalten auswählen
SELECT name, email FROM users;

-- Auswahl mit Alias
SELECT name AS full_name, age AS years_old FROM users;

-- Eindeutige Werte auswählen
SELECT DISTINCT department FROM employees;
```

### Filtern: `WHERE`

Filtert Zeilen mithilfe verschiedener Bedingungen und Vergleichsoperatoren.

```sql
-- Einfache Bedingungen
SELECT * FROM users WHERE age > 25;
SELECT * FROM users WHERE name = 'John Doe';

-- Mehrere Bedingungen
SELECT * FROM users WHERE age > 18 AND age < 65;
SELECT * FROM users WHERE department = 'IT' OR salary > 50000;

-- Musterabgleich
SELECT * FROM users WHERE email LIKE '%@gmail.com';
SELECT * FROM users WHERE name GLOB 'J*';
```

### Sortieren & Begrenzen: `ORDER BY` / `LIMIT`

Sortiert Ergebnisse und begrenzt die Anzahl der zurückgegebenen Zeilen für eine bessere Datenverwaltung.

```sql
-- Aufsteigend sortieren (Standard)
SELECT * FROM users ORDER BY age;

-- Absteigend sortieren
SELECT * FROM users ORDER BY age DESC;

-- Mehrere Sortierspalten
SELECT * FROM users ORDER BY department, salary DESC;

-- Ergebnisse begrenzen
SELECT * FROM users LIMIT 10;

-- Begrenzen mit Offset (Paginierung)
SELECT * FROM users LIMIT 10 OFFSET 20;
```

### Aggregatfunktionen: `COUNT`, `SUM`, `AVG`

Führt Berechnungen für Gruppen von Zeilen zur statistischen Analyse durch.

```sql
-- Datensätze zählen
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT department) FROM employees;

-- Summe und Durchschnitt
SELECT SUM(salary), AVG(salary) FROM employees;

-- Min- und Max-Werte
SELECT MIN(age), MAX(age) FROM users;
```

## Erweiterte Abfragen

### Gruppierung: `GROUP BY` / `HAVING`

Gruppiert Zeilen nach angegebenen Kriterien und filtert Gruppen für zusammenfassende Berichte.

```sql
-- Nach einer Spalte gruppieren
SELECT department, COUNT(*)
FROM employees
GROUP BY department;

-- Nach mehreren Spalten gruppieren
SELECT department, job_title, AVG(salary)
FROM employees
GROUP BY department, job_title;

-- Gruppen mit HAVING filtern
SELECT department, AVG(salary) as avg_salary
FROM employees
GROUP BY department
HAVING avg_salary > 60000;
```

### Unterabfragen

Verwendet verschachtelte Abfragen für komplexe Datenabrufe und bedingte Logik.

```sql
-- Unterabfrage in der WHERE-Klausel
SELECT name FROM users
WHERE age > (SELECT AVG(age) FROM users);

-- Unterabfrage in der FROM-Klausel
SELECT dept, avg_salary FROM (
    SELECT department as dept, AVG(salary) as avg_salary
    FROM employees
    GROUP BY department
) WHERE avg_salary > 50000;

-- EXISTS Unterabfrage
SELECT * FROM users u
WHERE EXISTS (
    SELECT 1 FROM orders o WHERE o.user_id = u.id
);
```

### Joins: `INNER`, `LEFT`, `RIGHT`

Kombiniert Daten aus mehreren Tabellen mithilfe verschiedener Join-Typen für relationale Abfragen.

```sql
-- Inner Join
SELECT u.name, o.amount
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- Left Join (alle Benutzer anzeigen)
SELECT u.name, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- Self Join
SELECT e1.name as employee, e2.name as manager
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id;
```

### Set-Operationen: `UNION` / `INTERSECT`

Kombiniert Ergebnisse aus mehreren Abfragen mithilfe von Set-Operationen.

```sql
-- Union (Ergebnisse kombinieren)
SELECT name FROM customers
UNION
SELECT name FROM suppliers;

-- Intersect (gemeinsame Ergebnisse)
SELECT email FROM users
INTERSECT
SELECT email FROM newsletter_subscribers;

-- Except (Differenz)
SELECT email FROM users
EXCEPT
SELECT email FROM unsubscribed;
```

## Indizes & Leistung

### Index erstellen: `CREATE INDEX`

Erstellt Indizes für Spalten, um Abfragen zu beschleunigen und die Leistung zu verbessern.

```sql
-- Einzelspaltenindex
CREATE INDEX idx_user_email ON users(email);

-- Mehrspaltenindex
CREATE INDEX idx_order_user_date ON orders(user_id, order_date);

-- Eindeutiger Index
CREATE UNIQUE INDEX idx_product_sku ON products(sku);

-- Partieller Index (mit Bedingung)
CREATE INDEX idx_active_users ON users(name) WHERE active = 1;
```

### Abfrageanalyse: `EXPLAIN QUERY PLAN`

Analysiert Abfrageausführungspläne, um Leistungsengpässe zu identifizieren.

```sql
-- Abfrageleistung analysieren
EXPLAIN QUERY PLAN SELECT * FROM users WHERE email = 'test@example.com';

-- Prüfen, ob ein Index verwendet wird
EXPLAIN QUERY PLAN SELECT * FROM orders WHERE user_id = 123;
```

### Datenbankoptimierung: `VACUUM` / `ANALYZE`

Optimiert Datenbankdateien und aktualisiert Statistiken für bessere Leistung.

```sql
-- Datenbank zur Platzrückgewinnung neu erstellen
VACUUM;

-- Indexstatistiken aktualisieren
ANALYZE;

-- Datenbankintegrität prüfen
PRAGMA integrity_check;
```

### Leistungseinstellungen: `PRAGMA`

Konfiguriert SQLite-Einstellungen für optimale Leistung und Verhalten.

```sql
-- Journalmodus für bessere Leistung einstellen
PRAGMA journal_mode = WAL;

-- Synchronisationsmodus einstellen
PRAGMA synchronous = NORMAL;

-- Fremdschlüssel-Einschränkungen aktivieren
PRAGMA foreign_keys = ON;

-- Cache-Größe einstellen (in Seiten)
PRAGMA cache_size = 10000;
```

## Views & Trigger

### Views: `CREATE VIEW`

Erstellt virtuelle Tabellen, die gespeicherte Abfragen für wiederverwendbaren Datenzugriff darstellen.

```sql
-- Eine einfache View erstellen
CREATE VIEW active_users AS
SELECT id, name, email
FROM users
WHERE active = 1;

-- Komplexe View mit Joins
CREATE VIEW order_summary AS
SELECT
    u.name,
    COUNT(o.id) as total_orders,
    SUM(o.amount) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- Eine View abfragen
SELECT * FROM active_users WHERE name LIKE 'J%';

-- Eine View löschen
DROP VIEW IF EXISTS order_summary;
```

### Views verwenden

Fragt Views wie reguläre Tabellen für vereinfachten Datenzugriff ab.

```sql
SELECT * FROM active_users;
SELECT * FROM order_summary WHERE total_spent > 1000;
```

### Trigger: `CREATE TRIGGER`

Führt automatisch Code als Reaktion auf Datenbankereignisse aus.

```sql
-- Trigger bei INSERT
CREATE TRIGGER update_user_count
AFTER INSERT ON users
BEGIN
    UPDATE stats SET user_count = user_count + 1;
END;

-- Trigger bei UPDATE
CREATE TRIGGER log_salary_changes
AFTER UPDATE OF salary ON employees
BEGIN
    INSERT INTO audit_log (table_name, action, old_value, new_value)
    VALUES ('employees', 'salary_update', OLD.salary, NEW.salary);
END;

-- Trigger löschen
DROP TRIGGER IF EXISTS update_user_count;
```

## Datentypen & Funktionen

### Datums- & Zeitfunktionen

Verarbeitet Datums- und Zeitvorgänge mit den integrierten Funktionen von SQLite.

```sql
-- Aktuelles Datum/Uhrzeit
SELECT datetime('now');
SELECT date('now');
SELECT time('now');

-- Datumsarithmetik
SELECT date('now', '+1 day');
SELECT datetime('now', '-1 hour');
SELECT date('now', 'start of month');

-- Datum formatieren
SELECT strftime('%Y-%m-%d %H:%M', 'now');
SELECT strftime('%w', 'now'); -- Wochentag
```

### Stringfunktionen

Manipuliert Textdaten mit verschiedenen String-Operationen.

```sql
-- String-Manipulation
SELECT upper(name) FROM users;
SELECT lower(email) FROM users;
SELECT length(name) FROM users;
SELECT substr(name, 1, 3) FROM users;

-- String-Verkettung
SELECT name || ' - ' || email as display FROM users;
SELECT printf('%s (%d)', name, age) FROM users;

-- String-Ersetzung
SELECT replace(phone, '-', '') FROM users;
```

### Numerische Funktionen

Führt mathematische Operationen und Berechnungen durch.

```sql
-- Mathematische Funktionen
SELECT abs(-15);
SELECT round(price, 2) FROM products;
SELECT random(); -- Zufallszahl

-- Aggregation mit Mathematik
SELECT department, round(AVG(salary), 2) as avg_salary
FROM employees
GROUP BY department;
```

### Bedingte Logik: `CASE`

Implementiert bedingte Logik innerhalb von SQL-Abfragen.

```sql
-- Einfache CASE-Anweisung
SELECT name,
    CASE
        WHEN age < 18 THEN 'Minor'
        WHEN age < 65 THEN 'Adult'
        ELSE 'Senior'
    END as age_category
FROM users;

-- CASE in der WHERE-Klausel
SELECT * FROM products
WHERE CASE WHEN category = 'Electronics' THEN price < 1000
          ELSE price < 100 END;
```

## Transaktionen & Nebenläufigkeit

### Transaktionssteuerung

SQLite-Transaktionen sind vollständig ACID-konform für zuverlässige Datenoperationen.

```sql
-- Grundlegende Transaktion
BEGIN TRANSACTION;
INSERT INTO users (name, email) VALUES ('Test User', 'test@example.com');
UPDATE users SET age = 25 WHERE name = 'Test User';
COMMIT;

-- Transaktion mit Rollback
BEGIN;
DELETE FROM orders WHERE amount < 10;
-- Ergebnisse prüfen, bei Bedarf Rollback
ROLLBACK;

-- Savepoints für verschachtelte Transaktionen
BEGIN;
SAVEPOINT sp1;
INSERT INTO products (name) VALUES ('Product A');
ROLLBACK TO sp1;
COMMIT;
```

### Sperrung & Nebenläufigkeit

Verwaltet Datenbank-Sperren und gleichzeitigen Zugriff zur Gewährleistung der Datenintegrität.

```sql
-- Sperrstatus prüfen
PRAGMA locking_mode;

-- WAL-Modus für bessere Nebenläufigkeit einstellen
PRAGMA journal_mode = WAL;

-- Busy Timeout zum Warten auf Sperren
PRAGMA busy_timeout = 5000;

-- Aktuelle Datenbankverbindungen prüfen
.databases
```

## SQLite Kommandozeilen-Tools

### Datenbankbefehle: `.help`

Greift auf die Hilfe der SQLite-Kommandozeile und Dokumentation für verfügbare Punktbefehle zu.

```bash
# Alle verfügbaren Befehle anzeigen
.help
# Aktuelle Einstellungen anzeigen
.show
# Ausgabeformat einstellen
.mode csv
.headers on
```

### Import/Export: `.import` / `.export`

Überträgt Daten zwischen SQLite und externen Dateien in verschiedenen Formaten.

```bash
# CSV-Datei importieren
.mode csv
.import data.csv users

# Export nach CSV
.headers on
.mode csv
.output users.csv
SELECT * FROM users;
```

### Schemaverwaltung: `.schema` / `.tables`

Untersucht die Datenbankstruktur und Tabellendefinitionen für Entwicklung und Debugging.

```bash
# Alle Tabellen anzeigen
.tables
# Schema für spezifische Tabelle anzeigen
.schema users
# Alle Schemata anzeigen
.schema
# Tabelleninformationen anzeigen
.mode column
.headers on
PRAGMA table_info(users);
```

### Ausgabeformatierung: `.mode`

Steuert, wie Abfrageergebnisse in der Kommandozeilenschnittstelle angezeigt werden.

```bash
# Verschiedene Ausgabeformate
.mode csv        # Kommagetrennte Werte
.mode column     # Ausgerichtete Spalten
.mode html       # HTML-Tabellenformat
.mode json       # JSON-Format
.mode list       # Listenformat
.mode table      # Tabellenformat (Standard)

# Spaltenbreite einstellen
.width 10 15 20

# Ausgabe in Datei speichern
.output results.txt
SELECT * FROM users;
.output stdout

# SQL aus Datei lesen
.read script.sql

# Datenbankdatei wechseln
.open another_database.db
```

## Konfiguration & Einstellungen

### Datenbankeinstellungen: `PRAGMA`

Steuert das Verhalten von SQLite durch Pragma-Anweisungen zur Optimierung und Konfiguration.

```sql
-- Datenbankinformationen
PRAGMA database_list;
PRAGMA table_info(users);
PRAGMA foreign_key_list(orders);

-- Leistungseinstellungen
PRAGMA cache_size = 10000;
PRAGMA temp_store = memory;
PRAGMA mmap_size = 268435456;

-- Fremdschlüssel-Einschränkungen aktivieren
PRAGMA foreign_keys = ON;

-- Sicheren Löschmodus einstellen
PRAGMA secure_delete = ON;

-- Integrität prüfen
PRAGMA foreign_key_check;
```

### Sicherheitseinstellungen

Konfiguriert sicherheitsrelevante Datenbankoptionen und Einschränkungen.

```sql
-- Fremdschlüssel-Einschränkungen aktivieren
PRAGMA foreign_keys = ON;

-- Sicherer Löschmodus
PRAGMA secure_delete = ON;

-- Integrität prüfen
PRAGMA integrity_check;
```

## Installation & Einrichtung

### Herunterladen & Installieren

Laden Sie die SQLite-Tools herunter und richten Sie die Kommandozeilenschnittstelle für Ihr Betriebssystem ein.

```bash
# Von sqlite.org herunterladen
# Für Windows: sqlite-tools-win32-x86-*.zip
# Für Linux/Mac: Paketmanager verwenden

# Ubuntu/Debian
sudo apt-get install sqlite3

# macOS mit Homebrew
brew install sqlite

# Installation überprüfen
sqlite3 --version
```

### Erstellen Ihrer ersten Datenbank

Erstellt SQLite-Datenbankdateien und beginnt mit der Arbeit mit Daten mithilfe einfacher Befehle.

```bash
# Neue Datenbank erstellen
sqlite3 myapp.db

# Tabelle erstellen und Daten hinzufügen
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE
);

INSERT INTO users (name, email)
VALUES ('John Doe', 'john@example.com');
```

### Integration in Programmiersprachen

Verwendet SQLite mit verschiedenen Programmiersprachen über integrierte oder Drittanbieter-Bibliotheken.

```python
# Python (integriertes sqlite3-Modul)
import sqlite3
conn = sqlite3.connect('mydb.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users')
```

```javascript
// Node.js (erfordert sqlite3-Paket)
const sqlite3 = require('sqlite3')
const db = new sqlite3.Database('mydb.db')
db.all('SELECT * FROM users', (err, rows) => {
  console.log(rows)
})
```

```php
// PHP (integriertes PDO SQLite)
$pdo = new PDO('sqlite:mydb.db');
$stmt = $pdo->query('SELECT * FROM users');
```

## Relevante Links

- <router-link to="/database">Datenbank Spickzettel</router-link>
- <router-link to="/mysql">MySQL Spickzettel</router-link>
- <router-link to="/postgresql">PostgreSQL Spickzettel</router-link>
- <router-link to="/mongodb">MongoDB Spickzettel</router-link>
- <router-link to="/redis">Redis Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>

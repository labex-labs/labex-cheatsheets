---
title: 'PostgreSQL Spickzettel'
description: 'Lernen Sie PostgreSQL mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/postgresql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
PostgreSQL Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/postgresql">Lernen Sie PostgreSQL mit praktischen Übungen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie das PostgreSQL-Datenbankmanagement durch praktische Übungen und reale Szenarien. LabEx bietet umfassende PostgreSQL-Kurse, die wesentliche SQL-Operationen, erweiterte Abfragen, Leistungsoptimierung, Datenbankadministration und Sicherheit abdecken. Meistern Sie die Entwicklung und Administration von relationalen Datenbanken auf Unternehmensniveau.
</base-disclaimer-content>
</base-disclaimer>

## Verbindung & Datenbank-Setup

### Mit PostgreSQL verbinden: `psql`

Stellen Sie eine Verbindung zu einer lokalen oder Remote-PostgreSQL-Datenbank mit dem psql-Kommandozeilenwerkzeug her.

```bash
# Verbindung zur lokalen Datenbank herstellen
psql -U benutzername -d datenbankname
# Verbindung zur Remote-Datenbank herstellen
psql -h hostname -p 5432 -U benutzername -d datenbankname
# Verbindung mit Passwortabfrage
psql -U postgres -W
# Verbindung über Verbindungszeichenfolge
psql "host=localhost port=5432 dbname=mydb user=myuser"
```

### Datenbank erstellen: `CREATE DATABASE`

Erstellen Sie eine neue Datenbank in PostgreSQL mit dem CREATE DATABASE Befehl.

```sql
# Neue Datenbank erstellen
CREATE DATABASE mydatabase;
# Datenbank mit Besitzer erstellen
CREATE DATABASE mydatabase OWNER myuser;
# Datenbank mit Kodierung erstellen
CREATE DATABASE mydatabase
  WITH ENCODING 'UTF8'
  LC_COLLATE='en_US.UTF-8'
  LC_CTYPE='en_US.UTF-8';
```

### Datenbanken auflisten: `\l`

Listen Sie alle Datenbanken auf dem PostgreSQL-Server auf.

```bash
# Alle Datenbanken auflisten
\l
# Datenbanken mit detaillierten Informationen auflisten
\l+
# Zu einer anderen Datenbank wechseln
\c datenbankname
```

### Grundlegende psql-Befehle

Wesentliche psql-Terminalbefehle zur Navigation und Informationsabfrage.

```bash
# psql beenden
\q
# Hilfe für SQL-Befehle erhalten
\help CREATE TABLE
# Hilfe für psql-Befehle erhalten
\?
# Aktuelle Datenbank und Benutzer anzeigen
\conninfo
# Systembefehle ausführen
\! ls
# Alle Tabellen auflisten
\dt
# Alle Tabellen mit Details auflisten
\dt+
# Spezifische Tabelle beschreiben
\d tabellenname
# Alle Schemata auflisten
\dn
# Alle Benutzer/Rollen auflisten
\du
```

### Version & Einstellungen

Überprüfen Sie die PostgreSQL-Version und Konfigurationseinstellungen.

```sql
# PostgreSQL-Version prüfen
SELECT version();
# Aktuelle Einstellungen anzeigen
SHOW ALL;
# Spezifische Einstellung anzeigen
SHOW max_connections;
# Konfigurationsparameter setzen
SET work_mem = '256MB';
```

## Tabellenerstellung & -verwaltung

### Tabelle erstellen: `CREATE TABLE`

Definieren Sie neue Tabellen mit Spalten, Datentypen und Einschränkungen.

```sql
# Grundlegende Tabellenerstellung
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

# Tabelle mit Fremdschlüssel
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending'
);
```

### Tabellen ändern: `ALTER TABLE`

Fügen Sie Spalten und Einschränkungen zu bestehenden Tabellen hinzu, ändern oder entfernen Sie diese.

```sql
# Neue Spalte hinzufügen
ALTER TABLE users ADD COLUMN phone VARCHAR(15);
# Spaltentyp ändern
ALTER TABLE users ALTER COLUMN phone TYPE VARCHAR(20);
# Spalte löschen
ALTER TABLE users DROP COLUMN phone;
# Einschränkung hinzufügen
ALTER TABLE users ADD CONSTRAINT unique_email
    UNIQUE (email);
```

### Löschen & Leeren: `DROP/TRUNCATE`

Tabellen entfernen oder alle Daten aus Tabellen löschen.

```sql
# Tabelle vollständig löschen
DROP TABLE IF EXISTS old_table;
# Alle Daten behalten, aber Struktur beibehalten
TRUNCATE TABLE users;
# Leeren mit Identität neu starten
TRUNCATE TABLE users RESTART IDENTITY;
```

### Datentypen & Einschränkungen

Wesentliche PostgreSQL-Datentypen für verschiedene Datenarten.

```sql
# Numerische Typen
INTEGER, BIGINT, SMALLINT
DECIMAL(10,2), NUMERIC(10,2)
REAL, DOUBLE PRECISION

# Zeichentypen
CHAR(n), VARCHAR(n), TEXT

# Datums-/Zeit-Typen
DATE, TIME, TIMESTAMP
TIMESTAMPTZ (mit Zeitzone)

# Boolean und andere
BOOLEAN
JSON, JSONB
UUID
ARRAY (z.B. INTEGER[])

# Primärschlüssel
id SERIAL PRIMARY KEY

# Fremdschlüssel
user_id INTEGER REFERENCES users(id)

# Eindeutige Einschränkung
email VARCHAR(100) UNIQUE

# Prüfeinschränkung
age INTEGER CHECK (age >= 0)

# Nicht Null
name VARCHAR(50) NOT NULL
```

### Indizes: `CREATE INDEX`

Verbessern Sie die Abfrageleistung mit Datenbankindizes.

```sql
# Grundlegender Index
CREATE INDEX idx_username ON users(username);
# Eindeutiger Index
CREATE UNIQUE INDEX idx_unique_email
    ON users(email);
# Zusammengesetzter Index
CREATE INDEX idx_user_date
    ON orders(user_id, created_at);
# Partieller Index
CREATE INDEX idx_active_users
    ON users(username) WHERE active = true;
# Index löschen
DROP INDEX IF EXISTS idx_username;
```

### Sequenzen: `CREATE SEQUENCE`

Generieren Sie automatisch eindeutige numerische Werte.

```sql
# Sequenz erstellen
CREATE SEQUENCE user_id_seq;
# Sequenz in Tabelle verwenden
CREATE TABLE users (
    id INTEGER DEFAULT nextval('user_id_seq'),
    username VARCHAR(50)
);
# Sequenz zurücksetzen
ALTER SEQUENCE user_id_seq RESTART WITH 1000;
```

## CRUD-Operationen

### Daten einfügen: `INSERT`

Neue Datensätze zu Datenbanktabellen hinzufügen.

```sql
# Einzelnen Datensatz einfügen
INSERT INTO users (username, email)
VALUES ('john_doe', 'john@example.com');
# Mehrere Datensätze einfügen
INSERT INTO users (username, email) VALUES
    ('alice', 'alice@example.com'),
    ('bob', 'bob@example.com');
# Einfügen mit Rückgabe
INSERT INTO users (username, email)
VALUES ('jane', 'jane@example.com')
RETURNING id, created_at;
# Einfügen aus Auswahl
INSERT INTO archive_users
SELECT * FROM users WHERE active = false;
```

### Daten aktualisieren: `UPDATE`

Bestehende Datensätze in Datenbanktabellen ändern.

```sql
# Spezifische Datensätze aktualisieren
UPDATE users
SET email = 'newemail@example.com'
WHERE username = 'john_doe';
# Mehrere Spalten aktualisieren
UPDATE users
SET email = 'new@example.com',
    updated_at = NOW()
WHERE id = 1;
# Aktualisieren mit Unterabfrage
UPDATE orders
SET total = (SELECT SUM(price) FROM order_items
            WHERE order_id = orders.id);
```

### Daten auswählen: `SELECT`

Daten aus Datenbanktabellen abfragen und abrufen.

```sql
# Grundlegendes Auswählen
SELECT * FROM users;
# Spezifische Spalten auswählen
SELECT id, username, email FROM users;
# Auswählen mit Bedingungen
SELECT * FROM users
WHERE active = true AND created_at > '2024-01-01';
# Auswählen mit Sortierung und Begrenzung
SELECT * FROM users
ORDER BY created_at DESC
LIMIT 10 OFFSET 20;
```

### Daten löschen: `DELETE`

Datensätze aus Datenbanktabellen entfernen.

```sql
# Spezifische Datensätze löschen
DELETE FROM users
WHERE active = false;
# Löschen mit Unterabfrage
DELETE FROM orders
WHERE user_id IN (
    SELECT id FROM users WHERE active = false
);
# Alle Datensätze löschen
DELETE FROM temp_table;
# Löschen mit Rückgabe
DELETE FROM users
WHERE id = 5
RETURNING *;
```

## Erweiterte Abfragen

### Joins: `INNER/LEFT/RIGHT JOIN`

Daten aus mehreren Tabellen mithilfe verschiedener Join-Typen kombinieren.

```sql
# Inner Join
SELECT u.username, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# Left Join
SELECT u.username, o.total
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# Mehrere Joins
SELECT u.username, o.total, p.name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

### Subqueries & CTEs

Verschachtelte Abfragen und Common Table Expressions für komplexe Operationen verwenden.

```sql
# Unterabfrage in WHERE
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders);
# Common Table Expression (CTE)
WITH active_users AS (
    SELECT * FROM users WHERE active = true
)
SELECT au.username, COUNT(o.id) as order_count
FROM active_users au
LEFT JOIN orders o ON au.id = o.user_id
GROUP BY au.username;
```

### Aggregation: `GROUP BY`

Daten gruppieren und Aggregatfunktionen zur Analyse anwenden.

```sql
# Grundlegende Gruppierung
SELECT status, COUNT(*) as count
FROM orders
GROUP BY status;
# Mehrere Aggregationen
SELECT user_id,
       COUNT(*) as order_count,
       SUM(total) as total_spent,
       AVG(total) as avg_order
FROM orders
GROUP BY user_id
HAVING COUNT(*) > 5;
```

### Fensterfunktionen

Berechnungen über zusammengehörige Zeilen durchführen, ohne zu gruppieren.

```sql
# Zeilennummerierung
SELECT username, email,
       ROW_NUMBER() OVER (ORDER BY created_at) as row_num
FROM users;
# Laufende Summen
SELECT date, amount,
       SUM(amount) OVER (ORDER BY date) as running_total
FROM sales;
# Rangfolge
SELECT username, score,
       RANK() OVER (ORDER BY score DESC) as rank
FROM user_scores;
```

## Datenimport & -export

### CSV-Import: `COPY`

Daten aus CSV-Dateien in PostgreSQL-Tabellen importieren.

```sql
# Import aus CSV-Datei
COPY users(username, email, age)
FROM '/path/to/users.csv'
DELIMITER ',' CSV HEADER;
# Import mit spezifischen Optionen
COPY products
FROM '/path/to/products.csv'
WITH (FORMAT csv, HEADER true, DELIMITER ';');
# Import von stdin
\copy users(username, email) FROM STDIN WITH CSV;
```

### CSV-Export: `COPY TO`

PostgreSQL-Daten in CSV-Dateien exportieren.

```sql
# Export in CSV-Datei
COPY users TO '/path/to/users_export.csv'
WITH (FORMAT csv, HEADER true);
# Abfrageergebnisse exportieren
COPY (SELECT username, email FROM users WHERE active = true)
TO '/path/to/active_users.csv' CSV HEADER;
# Export nach stdout
\copy (SELECT * FROM orders) TO STDOUT WITH CSV HEADER;
```

### Backup & Wiederherstellung: `pg_dump`

Datenbank-Backups erstellen und aus Backup-Dateien wiederherstellen.

```bash
# Gesamte Datenbank sichern
pg_dump -U benutzername -h hostname datenbankname > backup.sql
# Spezifische Tabelle sichern
pg_dump -U benutzername -t tabellenname datenbankname > table_backup.sql
# Komprimiertes Backup
pg_dump -U benutzername -Fc datenbankname > backup.dump
# Aus Backup wiederherstellen
psql -U benutzername -d datenbankname < backup.sql
# Komprimiertes Backup wiederherstellen
pg_restore -U benutzername -d datenbankname backup.dump
```

### JSON-Datenoperationen

Mit JSON- und JSONB-Datentypen für semi-strukturierte Daten arbeiten.

```sql
# JSON-Daten einfügen
INSERT INTO products (name, metadata)
VALUES ('Laptop', '{"brand": "Dell", "price": 999.99}');
# JSON-Felder abfragen
SELECT name, metadata->>'brand' as brand
FROM products
WHERE metadata->>'price'::numeric > 500;
# JSON-Array-Operationen
SELECT name FROM products
WHERE metadata->'features' ? 'wireless';
```

## Benutzerverwaltung & Sicherheit

### Benutzer & Rollen erstellen

Datenbankzugriff mit Benutzern und Rollen verwalten.

```sql
# Benutzer erstellen
CREATE USER myuser WITH PASSWORD 'secretpassword';
# Rolle erstellen
CREATE ROLE readonly_user;
# Benutzer mit spezifischen Berechtigungen erstellen
CREATE USER admin_user WITH
    CREATEDB CREATEROLE PASSWORD 'adminpass';
# Rolle einem Benutzer zuweisen
GRANT readonly_user TO myuser;
```

### Berechtigungen: `GRANT/REVOKE`

Zugriff auf Datenbankobjekte über Berechtigungen steuern.

```sql
# Tabellenberechtigungen erteilen
GRANT SELECT, INSERT ON users TO myuser;
# Alle Berechtigungen für Tabelle erteilen
GRANT ALL ON orders TO admin_user;
# Datenbankberechtigungen erteilen
GRANT CONNECT ON DATABASE mydb TO myuser;
# Berechtigungen entziehen
REVOKE INSERT ON users FROM myuser;
```

### Benutzerinformationen anzeigen

Vorhandene Benutzer und deren Berechtigungen überprüfen.

```sql
# Alle Benutzer auflisten
\du
# Tabellenberechtigungen anzeigen
SELECT table_name, privilege_type, grantee
FROM information_schema.table_privileges
WHERE table_schema = 'public';
# Aktuellen Benutzer anzeigen
SELECT current_user;
# Rollenzugehörigkeiten anzeigen
SELECT r.rolname, r.rolsuper, r.rolcreaterole
FROM pg_roles r;
```

### Passwort & Sicherheit

Benutzerpasswörter und Sicherheitseinstellungen verwalten.

```sql
# Benutzerpasswort ändern
ALTER USER myuser PASSWORD 'newpassword';
# Passwortablauf festlegen
ALTER USER myuser VALID UNTIL '2025-12-31';
# Benutzer ohne Login erstellen
CREATE ROLE reporting_role NOLOGIN;
# Benutzer aktivieren/deaktivieren
ALTER USER myuser WITH NOLOGIN;
ALTER USER myuser WITH LOGIN;
```

## Leistung & Überwachung

### Abfrageanalyse: `EXPLAIN`

Abfrageausführungspläne analysieren und die Leistung optimieren.

```sql
# Abfrageausführungsplan anzeigen
EXPLAIN SELECT * FROM users WHERE active = true;
# Mit tatsächlichen Ausführungsstatistiken analysieren
EXPLAIN ANALYZE
SELECT u.username, COUNT(o.id)
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.username;
# Detaillierte Ausführungsinformationen
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT * FROM large_table WHERE indexed_col = 'value';
```

### Datenbankwartung: `VACUUM`

Die Datenbankleistung durch regelmäßige Bereinigungsoperationen aufrechterhalten.

```sql
# Grundlegendes Vacuum
VACUUM users;
# Full Vacuum mit Analyse
VACUUM FULL ANALYZE users;
# Auto-Vacuum-Status
SELECT schemaname, tablename, last_vacuum, last_autovacuum
FROM pg_stat_user_tables;
# Tabelle neu indizieren
REINDEX TABLE users;
```

### Abfragen überwachen

Datenbankaktivität verfolgen und Leistungsprobleme identifizieren.

```sql
# Aktuelle Aktivität
SELECT pid, usename, query, state
FROM pg_stat_activity
WHERE state != 'idle';
# Lang laufende Abfragen
SELECT pid, now() - query_start as duration, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC;
# Spezifische Abfrage beenden
SELECT pg_terminate_backend(pid) WHERE pid = 12345;
```

### Datenbankstatistiken

Einblicke in die Datenbanknutzung und Leistungsmetriken erhalten.

```sql
# Tabellenstatistiken
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del
FROM pg_stat_user_tables;
# Indexnutzungsstatistiken
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes;
# Datenbankgröße
SELECT pg_size_pretty(pg_database_size('mydatabase'));
```

## Erweiterte Funktionen

### Views: `CREATE VIEW`

Erstellen Sie virtuelle Tabellen, um komplexe Abfragen zu vereinfachen und Datenabstraktion bereitzustellen.

```sql
# Einfache View erstellen
CREATE VIEW active_users AS
SELECT id, username, email
FROM users WHERE active = true;
# View mit Joins erstellen
CREATE OR REPLACE VIEW order_summary AS
SELECT u.username, COUNT(o.id) as total_orders,
       SUM(o.total) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.username;
# View löschen
DROP VIEW IF EXISTS order_summary;
```

### Trigger & Funktionen

Datenbankoperationen mit gespeicherten Prozeduren und Triggern automatisieren.

```sql
# Funktion erstellen
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
# Trigger erstellen
CREATE TRIGGER update_user_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();
```

### Transaktionen

Gewährleistung der Datenkonsistenz durch Transaktionskontrolle.

```sql
# Transaktion beginnen
BEGIN;
UPDATE accounts SET balance = balance - 100
WHERE id = 1;
UPDATE accounts SET balance = balance + 100
WHERE id = 2;
# Transaktion bestätigen
COMMIT;
# Bei Bedarf zurückrollen
ROLLBACK;
# Speicherpunkte
SAVEPOINT my_savepoint;
ROLLBACK TO my_savepoint;
```

### Konfiguration & Tuning

PostgreSQL-Servereinstellungen für bessere Leistung optimieren.

```sql
# Aktuelle Konfiguration anzeigen
SHOW shared_buffers;
SHOW max_connections;
# Konfigurationsparameter setzen
SET work_mem = '256MB';
SET random_page_cost = 1.1;
# Konfiguration neu laden
SELECT pg_reload_conf();
# Speicherort der Konfigurationsdatei anzeigen
SHOW config_file;
```

## psql Konfiguration & Tipps

### Verbindungsdateien: `.pgpass`

Datenbankanmeldeinformationen sicher für die automatische Authentifizierung speichern.

```bash
# .pgpass Datei erstellen (Format: hostname:port:datenbank:benutzername:passwort)
echo "localhost:5432:mydatabase:myuser:mypassword" >> ~/.pgpass
# Korrekte Berechtigungen festlegen
chmod 600 ~/.pgpass
# Verbindungsdienstdatei verwenden
# ~/.pg_service.conf
[mydb]
host=localhost
port=5432
dbname=mydatabase
user=myuser
```

### psql Konfiguration: `.psqlrc`

psql-Starteinstellungen und Verhalten anpassen.

```bash
# ~/.psqlrc Datei mit benutzerdefinierten Einstellungen erstellen
\set QUIET on
\timing on
\set PROMPT1 '%n@%M:%> %`date` %R%# '
\set HISTSIZE 5000
\set COMP_KEYWORD_CASE upper
\x auto
\set QUIET off
# Benutzerdefinierte Aliase
\set show_slow_queries 'SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;'
```

### Umgebungsvariablen

PostgreSQL-Umgebungsvariablen für einfachere Verbindungen festlegen.

```bash
# Im Shell-Profil festlegen
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=mydatabase
export PGUSER=myuser
# Dann einfach mit psql verbinden
psql
# Oder spezifische Umgebung verwenden
PGDATABASE=testdb psql
```

### Datenbankinformationen

Informationen zu Datenbankobjekten und Struktur abrufen.

```bash
# Datenbanken auflisten
\l, \l+
# Tabellen in der aktuellen Datenbank auflisten
\dt, \dt+
# Views auflisten
\dv, \dv+
# Indizes auflisten
\di, \di+
# Funktionen auflisten
\df, \df+
# Sequenzen auflisten
\ds, \ds+
# Tabellenstruktur beschreiben
\d tabellenname
\d+ tabellenname
# Tabellenbeschränkungen anzeigen
\d+ tabellenname
# Tabellenberechtigungen anzeigen
\dp tabellenname
\z tabellenname
# Fremdschlüssel auflisten
SELECT * FROM information_schema.table_constraints
WHERE constraint_type = 'FOREIGN KEY';
```

### Ausgabe & Formatierung

Steuern, wie psql Abfrageergebnisse und Ausgaben anzeigt.

```bash
# Erweiterten Modus umschalten
\x
# Ausgabeformat ändern
\H  -- HTML-Ausgabe
\t  -- Nur Tupel (keine Header)
# Ausgabe in Datei umleiten
\o dateiname.txt
SELECT * FROM users;
\o  -- Ausgabe in Datei stoppen
# SQL aus Datei ausführen
\i script.sql
# Abfrage im externen Editor bearbeiten
\e
```

### Timing & Verlauf

Abfrageleistung verfolgen und den Befehlsverlauf verwalten.

```bash
# Zeitanzeige umschalten
\timing
# Befehlsverlauf anzeigen
\s
# Befehlsverlauf in Datei speichern
\s dateiname.txt
# Bildschirm löschen
\! clear  -- Linux/Mac
\! cls   -- Windows
# Letzten Fehler anzeigen
\errverbose
```

## Relevante Links

- <router-link to="/database">Datenbank Spickzettel</router-link>
- <router-link to="/mysql">MySQL Spickzettel</router-link>
- <router-link to="/sqlite">SQLite Spickzettel</router-link>
- <router-link to="/mongodb">MongoDB Spickzettel</router-link>
- <router-link to="/redis">Redis Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>

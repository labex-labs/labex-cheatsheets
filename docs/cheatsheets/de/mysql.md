---
title: 'MySQL Spickzettel'
description: 'Lernen Sie MySQL mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/mysql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
MySQL Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/mysql">Lernen Sie MySQL mit praktischen Übungen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie das MySQL-Datenbankmanagement durch praktische Übungen und reale Szenarien. LabEx bietet umfassende MySQL-Kurse, die wesentliche SQL-Operationen, Datenbankadministration, Leistungsoptimierung und fortgeschrittene Abfragetechniken abdecken. Meistern Sie eines der weltweit beliebtesten relationalen Datenbanksysteme.
</base-disclaimer-content>
</base-disclaimer>

## Datenbankverbindung & -verwaltung

### Verbindung zum Server: `mysql -u benutzername -p`

Verbindung zur MySQL-Datenbank über die Kommandozeile herstellen.

```bash
# Verbindung mit Benutzername und Passwortabfrage
mysql -u root -p
# Verbindung zu einer bestimmten Datenbank
mysql -u benutzername -p datenbankname
# Verbindung zu einem Remote-Server
mysql -h hostname -u benutzername -p
# Verbindung mit Portangabe
mysql -h hostname -P 3306 -u benutzername -p datenbankname
```

### Datenbankoperationen: `CREATE` / `DROP` / `USE`

Datenbanken auf dem Server verwalten.

```sql
# Neue Datenbank erstellen
CREATE DATABASE firmen_db;
# Alle Datenbanken auflisten
SHOW DATABASES;
# Eine Datenbank zur Verwendung auswählen
USE firmen_db;
# Eine Datenbank löschen (dauerhaft entfernen)
DROP DATABASE alte_datenbank;
```

### Daten exportieren: `mysqldump`

Datenbankdaten in eine SQL-Datei sichern.

```bash
# Gesamte Datenbank exportieren
mysqldump -u benutzername -p datenbankname > backup.sql
# Spezifische Tabelle exportieren
mysqldump -u benutzername -p datenbankname tabellenname > tabellen_backup.sql
# Nur Struktur exportieren
mysqldump -u benutzername -p --no-data datenbankname > struktur.sql
# Vollständiges Datenbank-Backup mit Routinen und Triggern
mysqldump -u benutzername -p --routines --triggers datenbankname > backup.sql
```

### Daten importieren: `mysql < datei.sql`

SQL-Datei in eine MySQL-Datenbank importieren.

```bash
# SQL-Datei in Datenbank importieren
mysql -u benutzername -p datenbankname < backup.sql
# Importieren ohne Datenbankangabe (falls in Datei enthalten)
mysql -u benutzername -p < vollstaendiges_backup.sql
```

### Benutzerverwaltung: `CREATE USER` / `GRANT`

Datenbankbenutzer und Berechtigungen verwalten.

```sql
# Neuen Benutzer erstellen
CREATE USER 'neueruser'@'localhost' IDENTIFIED BY 'passwort';
# Alle Privilegien gewähren
GRANT ALL PRIVILEGES ON datenbankname.* TO 'user'@'localhost';
# Spezifische Privilegien gewähren
GRANT SELECT, INSERT, UPDATE ON tabellenname TO 'user'@'localhost';
# Änderungen der Privilegien anwenden
FLUSH PRIVILEGES;
```

### Serverinformationen anzeigen: `SHOW STATUS` / `SHOW VARIABLES`

Serverkonfiguration und Status anzeigen.

```sql
# Serverstatus anzeigen
SHOW STATUS;
# Konfigurationsvariablen anzeigen
SHOW VARIABLES;
# Aktuelle Prozesse anzeigen
SHOW PROCESSLIST;
```

## Tabellenstruktur & Schema

### Tabellenerstellung: `CREATE TABLE`

Neue Tabellen mit angegebenen Spalten und Datentypen erstellen.

```sql
# Tabelle mit verschiedenen Datentypen erstellen
CREATE TABLE benutzer (
    id INT AUTO_INCREMENT PRIMARY KEY,
    benutzername VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    alter INT,
    erstellt_am TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# Tabelle mit Fremdschlüssel erstellen
CREATE TABLE bestellungen (
    bestell_id INT AUTO_INCREMENT PRIMARY KEY,
    benutzer_id INT,
    FOREIGN KEY (benutzer_id) REFERENCES benutzer(id)
);
```

### Tabelleninformationen: `DESCRIBE` / `SHOW`

Tabellenstruktur und Datenbankinhalte anzeigen.

```sql
# Tabellenstruktur anzeigen
DESCRIBE benutzer;
# Alternative Syntax
SHOW COLUMNS FROM benutzer;
# Alle Tabellen auflisten
SHOW TABLES;
# CREATE-Anweisung für die Tabelle anzeigen
SHOW CREATE TABLE benutzer;
```

### Tabellen ändern: `ALTER TABLE`

Bestehende Tabellenstruktur ändern, Spalten hinzufügen oder löschen.

```sql
# Neue Spalte hinzufügen
ALTER TABLE benutzer ADD COLUMN telefon VARCHAR(20);
# Spalte löschen
ALTER TABLE benutzer DROP COLUMN alter;
# Spaltentyp ändern
ALTER TABLE benutzer MODIFY COLUMN benutzername VARCHAR(100);
# Spalte umbenennen
ALTER TABLE benutzer CHANGE alter_name neuer_name VARCHAR(50);
```

## Datenmanipulation & CRUD-Operationen

### Daten einfügen: `INSERT INTO`

Neue Datensätze in Tabellen hinzufügen.

```sql
# Einzelnen Datensatz einfügen
INSERT INTO benutzer (benutzername, email, alter)
VALUES ('max_mustermann', 'max@email.de', 25);
# Mehrere Datensätze einfügen
INSERT INTO benutzer (benutzername, email, alter) VALUES
('anna', 'anna@email.de', 30),
('bernd', 'bernd@email.de', 28);
# Aus einer anderen Tabelle einfügen
INSERT INTO benutzer_backup SELECT * FROM benutzer;
```

### Daten aktualisieren: `UPDATE`

Bestehende Datensätze in Tabellen ändern.

```sql
# Spezifischen Datensatz aktualisieren
UPDATE benutzer SET alter = 26 WHERE benutzername = 'max_mustermann';
# Mehrere Spalten aktualisieren
UPDATE benutzer SET alter = 31, email = 'anna_neu@email.de'
WHERE benutzername = 'anna';
# Aktualisierung mit Berechnung
UPDATE produkte SET preis = preis * 1.1 WHERE kategorie = 'elektronik';
```

### Daten löschen: `DELETE` / `TRUNCATE`

Datensätze aus Tabellen entfernen.

```sql
# Spezifische Datensätze löschen
DELETE FROM benutzer WHERE alter < 18;
# Alle Datensätze löschen (Struktur beibehalten)
DELETE FROM benutzer;
# Alle Datensätze löschen (schneller, AUTO_INCREMENT zurücksetzen)
TRUNCATE TABLE benutzer;
# Löschen mit JOIN
DELETE b FROM benutzer b
JOIN inaktive_konten i ON b.id = i.benutzer_id;
```

### Daten ersetzen: `REPLACE` / `INSERT ... ON DUPLICATE KEY`

Umgang mit doppelten Schlüsselwerten beim Einfügen.

```sql
# Vorhandenen ersetzen oder neuen einfügen
REPLACE INTO benutzer (id, benutzername, email)
VALUES (1, 'aktualisierter_user', 'neu@email.de');
# Einfügen oder Aktualisieren bei doppeltem Schlüssel
INSERT INTO benutzer (benutzername, email)
VALUES ('max', 'max@email.de')
ON DUPLICATE KEY UPDATE email = VALUES(email);
```

## Datenabfragen & Auswahl

### Basis-SELECT: `SELECT * FROM`

Daten aus Tabellen mit verschiedenen Bedingungen abrufen.

```sql
# Alle Spalten auswählen
SELECT * FROM benutzer;
# Spezifische Spalten auswählen
SELECT benutzername, email FROM benutzer;
# Mit WHERE-Bedingung auswählen
SELECT * FROM benutzer WHERE alter > 25;
# Mit mehreren Bedingungen auswählen
SELECT * FROM benutzer WHERE alter > 20 AND email LIKE '%gmail.com';
```

### Sortierung & Begrenzung: `ORDER BY` / `LIMIT`

Reihenfolge und Anzahl der zurückgegebenen Ergebnisse steuern.

```sql
# Ergebnisse sortieren
SELECT * FROM benutzer ORDER BY alter DESC;
# Nach mehreren Spalten sortieren
SELECT * FROM benutzer ORDER BY alter DESC, benutzername ASC;
# Ergebnisse begrenzen
SELECT * FROM benutzer LIMIT 10;
# Paginierung (die ersten 10 überspringen, die nächsten 10 nehmen)
SELECT * FROM benutzer LIMIT 10 OFFSET 10;
```

### Filterung: `WHERE` / `LIKE` / `IN`

Daten mithilfe verschiedener Vergleichsoperatoren filtern.

```sql
# Musterabgleich
SELECT * FROM benutzer WHERE benutzername LIKE 'max%';
# Mehrere Werte
SELECT * FROM benutzer WHERE alter IN (25, 30, 35);
# Bereichsfilterung
SELECT * FROM benutzer WHERE alter BETWEEN 20 AND 30;
# NULL-Prüfungen
SELECT * FROM benutzer WHERE email IS NOT NULL;
```

### Gruppierung: `GROUP BY` / `HAVING`

Daten gruppieren und Aggregatfunktionen anwenden.

```sql
# Nach Spalte gruppieren
SELECT alter, COUNT(*) FROM benutzer GROUP BY alter;
# Gruppierung mit Bedingung für Gruppen
SELECT alter, COUNT(*) as anzahl FROM benutzer
GROUP BY alter HAVING anzahl > 1;
# Mehrere Gruppierungsspalten
SELECT alter, geschlecht, COUNT(*) FROM benutzer
GROUP BY alter, geschlecht;
```

## Erweiterte Abfragen

### JOIN-Operationen: `INNER` / `LEFT` / `RIGHT`

Daten aus mehreren Tabellen kombinieren.

```sql
# Inner Join (nur übereinstimmende Datensätze)
SELECT b.benutzername, o.bestelldatum
FROM benutzer b
INNER JOIN bestellungen o ON b.id = o.benutzer_id;
# Left Join (alle Benutzer, passende Bestellungen)
SELECT b.benutzername, o.bestelldatum
FROM benutzer b
LEFT JOIN bestellungen o ON b.id = o.benutzer_id;
# Mehrere Joins
SELECT b.benutzername, o.bestelldatum, p.produktname
FROM benutzer b
JOIN bestellungen o ON b.id = o.benutzer_id
JOIN produkte p ON o.produkt_id = p.id;
```

### Subqueries: `SELECT` innerhalb von `SELECT`

Verschachtelte Abfragen für komplexe Datenabrufe verwenden.

```sql
# Subquery in der WHERE-Klausel
SELECT * FROM benutzer
WHERE id IN (SELECT benutzer_id FROM bestellungen WHERE gesamt > 100);
# Korrelierte Subquery
SELECT benutzername FROM benutzer b1
WHERE alter > (SELECT AVG(alter) FROM benutzer b2);
# Subquery in SELECT
SELECT benutzername,
(SELECT COUNT(*) FROM bestellungen WHERE benutzer_id = benutzer.id) as bestell_anzahl
FROM benutzer;
```

### Aggregatfunktionen: `COUNT` / `SUM` / `AVG`

Statistiken und Zusammenfassungen aus Daten berechnen.

```sql
# Basis-Aggregate
SELECT COUNT(*) FROM benutzer;
SELECT AVG(alter), MIN(alter), MAX(alter) FROM benutzer;
SELECT SUM(gesamt) FROM bestellungen;
# Aggregat mit Gruppierung
SELECT abteilung, AVG(gehalt)
FROM mitarbeiter GROUP BY abteilung;
# Mehrere Aggregate
SELECT
    COUNT(*) as gesamt_benutzer,
    AVG(alter) as durchschnitts_alter,
    MAX(erstellt_am) as neueste_anmeldung
FROM benutzer;
```

### Fensterfunktionen: `OVER` / `PARTITION BY`

Berechnungen über Mengen von Tabellenzeilen durchführen.

```sql
# Ranking-Funktionen
SELECT benutzername, alter,
RANK() OVER (ORDER BY alter DESC) as alter_rang
FROM benutzer;
# Partitionieren nach Gruppe
SELECT benutzername, abteilung, gehalt,
AVG(gehalt) OVER (PARTITION BY abteilung) as abt_durchschnitt
FROM mitarbeiter;
# Laufende Summen
SELECT bestelldatum, gesamt,
SUM(gesamt) OVER (ORDER BY bestelldatum) as laufende_summe
FROM bestellungen;
```

## Indizes & Leistung

### Indizes erstellen: `CREATE INDEX`

Abfrageleistung durch Datenbankindizes verbessern.

```sql
# Regulären Index erstellen
CREATE INDEX idx_benutzername ON benutzer(benutzername);
# Kompositindex erstellen
CREATE INDEX idx_benutzer_alter ON benutzer(benutzername, alter);
# Eindeutigen Index erstellen
CREATE UNIQUE INDEX idx_email ON benutzer(email);
# Indizes für Tabelle anzeigen
SHOW INDEXES FROM benutzer;
```

### Abfrageanalyse: `EXPLAIN`

Analyse der Abfrageausführungspläne und Leistung.

```sql
# Abfrageausführungsplan anzeigen
EXPLAIN SELECT * FROM benutzer WHERE alter > 25;
# Detaillierte Analyse
EXPLAIN FORMAT=JSON SELECT b.*, o.gesamt
FROM benutzer b JOIN bestellungen o ON b.id = o.benutzer_id;
# Abfrageleistung anzeigen
SHOW PROFILES;
SET profiling = 1;
```

### Abfragen optimieren: Best Practices

Techniken zum Schreiben effizienter SQL-Abfragen.

```sql
# Spezifische Spalten anstelle von * verwenden
SELECT benutzername, email FROM benutzer WHERE id = 1;
# LIMIT für große Datensätze verwenden
SELECT * FROM protokolle ORDER BY erstellt_am DESC LIMIT 1000;
# Korrekte WHERE-Bedingungen verwenden
SELECT * FROM bestellungen WHERE benutzer_id = 123 AND status = 'ausstehend';
-- Covering Indexes verwenden, wenn möglich
```

### Tabellenwartung: `OPTIMIZE` / `ANALYZE`

Tabellenleistung und Statistiken pflegen.

```sql
# Tabellenspeicher optimieren
OPTIMIZE TABLE benutzer;
# Tabellenstatistiken aktualisieren
ANALYZE TABLE benutzer;
# Tabellenintegrität prüfen
CHECK TABLE benutzer;
# Tabelle bei Bedarf reparieren
REPAIR TABLE benutzer;
```

## Datenimport/Export

### Daten laden: `LOAD DATA INFILE`

Daten aus CSV- und Textdateien importieren.

```sql
# CSV-Datei laden
LOAD DATA INFILE '/pfad/zu/daten.csv'
INTO TABLE benutzer
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
# Laden mit spezifischen Spalten
LOAD DATA INFILE '/pfad/zu/daten.csv'
INTO TABLE benutzer (benutzername, email, alter);
```

### Daten exportieren: `SELECT INTO OUTFILE`

Abfrageergebnisse in Dateien exportieren.

```sql
# Exportieren in CSV-Datei
SELECT benutzername, email, alter
FROM benutzer
INTO OUTFILE '/pfad/zu/export.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

### Backup & Wiederherstellung: `mysqldump` / `mysql`

Datenbank-Backups erstellen und wiederherstellen.

```bash
# Spezifische Tabellen sichern
mysqldump -u benutzername -p datenbankname tabelle1 tabelle2 > tabellen_backup.sql
# Aus Backup wiederherstellen
mysql -u benutzername -p datenbankname < backup.sql
# Von Remote-Server exportieren
mysqldump -h remote_host -u benutzername -p datenbankname > remote_backup.sql
# Auf lokale Datenbank importieren
mysql -u lokaler_user -p lokale_datenbank < remote_backup.sql
# Direkte Datenkopie zwischen Servern
mysqldump -h quelle_host -u user -p db_name | mysql -h ziel_host -u user -p db_name
```

## Datentypen & Funktionen

### Gängige Datentypen: Zahlen, Text, Daten

Geeignete Datentypen für Ihre Spalten auswählen.

```sql
# Numerische Typen
INT, BIGINT, DECIMAL(10,2), FLOAT, DOUBLE
# String-Typen
VARCHAR(255), TEXT, CHAR(10), MEDIUMTEXT, LONGTEXT
# Datums- und Zeit-Typen
DATE, TIME, DATETIME, TIMESTAMP, YEAR
# Boolean und Binär
BOOLEAN, BLOB, VARBINARY

# Beispiel Tabellenerstellung
CREATE TABLE produkte (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    preis DECIMAL(10,2),
    erstellt_am TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### String-Funktionen: `CONCAT` / `SUBSTRING` / `LENGTH`

Textdaten mit integrierten String-Funktionen bearbeiten.

```sql
# String-Verkettung
SELECT CONCAT(vorname, ' ', nachname) as vollstaendiger_name FROM benutzer;
# String-Operationen
SELECT SUBSTRING(email, 1, LOCATE('@', email)-1) as benutzername FROM benutzer;
SELECT LENGTH(benutzername), UPPER(benutzername) FROM benutzer;
# Musterabgleich und Ersetzung
SELECT REPLACE(telefon, '-', '.') FROM benutzer WHERE telefon LIKE '___-___-____';
```

### Datumsfunktionen: `NOW()` / `DATE_ADD` / `DATEDIFF`

Effektiver Umgang mit Datums- und Zeitangaben.

```sql
# Aktuelles Datum und Uhrzeit
SELECT NOW(), CURDATE(), CURTIME();
# Datumsarithmetik
SELECT DATE_ADD(erstellt_am, INTERVAL 30 DAY) as ablaufdatum FROM benutzer;
SELECT DATEDIFF(NOW(), erstellt_am) as tage_seit_anmeldung FROM benutzer;
# Datumsformatierung
SELECT DATE_FORMAT(erstellt_am, '%Y-%m-%d %H:%i') as formatiertes_datum FROM bestellungen;
```

### Numerische Funktionen: `ROUND` / `ABS` / `RAND`

Mathematische Operationen auf numerischen Daten durchführen.

```sql
# Mathematische Funktionen
SELECT ROUND(preis, 2), ABS(gewinn_verlust), SQRT(flaeche) FROM produkte;
# Zufall und Statistik
SELECT RAND(), FLOOR(preis), CEIL(bewertung) FROM produkte;
# Mathematische Aggregate
SELECT AVG(preis), STDDEV(preis), VARIANCE(preis) FROM produkte;
```

## Transaktionsverwaltung

### Transaktionssteuerung: `BEGIN` / `COMMIT` / `ROLLBACK`

Datenbanktransaktionen zur Gewährleistung der Datenkonsistenz verwalten.

```sql
# Transaktion starten
BEGIN;
# oder
START TRANSACTION;
# Operationen durchführen
UPDATE konten SET saldo = saldo - 100 WHERE id = 1;
UPDATE konten SET saldo = saldo + 100 WHERE id = 2;
# Änderungen übernehmen
COMMIT;
# Oder bei Fehler zurücksetzen
ROLLBACK;
```

### Transaktionsisolation: `SET TRANSACTION ISOLATION`

Steuern, wie Transaktionen miteinander interagieren.

```sql
# Isolationsstufe festlegen
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
# Aktuelle Isolationsstufe anzeigen
SELECT @@transaction_isolation;
```

### Sperren: `LOCK TABLES` / `SELECT FOR UPDATE`

Gleichzeitigen Zugriff auf Daten steuern.

```sql
# Tabellen für exklusiven Zugriff sperren
LOCK TABLES benutzer WRITE, bestellungen READ;
# Operationen durchführen
# ...
UNLOCK TABLES;
# Zeilen-Level-Sperrung in Transaktionen
BEGIN;
SELECT * FROM konten WHERE id = 1 FOR UPDATE;
UPDATE konten SET saldo = saldo - 100 WHERE id = 1;
COMMIT;
```

### Savepoints: `SAVEPOINT` / `ROLLBACK TO`

Rücksetzpunkte innerhalb von Transaktionen erstellen.

```sql
BEGIN;
INSERT INTO benutzer (benutzername) VALUES ('user1');
SAVEPOINT sp1;
INSERT INTO benutzer (benutzername) VALUES ('user2');
SAVEPOINT sp2;
INSERT INTO benutzer (benutzername) VALUES ('user3');
# Zurücksetzen auf Savepoint
ROLLBACK TO sp1;
COMMIT;
```

## Erweiterte SQL-Techniken

### Common Table Expressions (CTEs): `WITH`

Temporäre Ergebnismengen für komplexe Abfragen erstellen.

```sql
# Einfache CTE
WITH benutzer_bestellungen AS (
    SELECT benutzer_id, COUNT(*) as bestell_anzahl,
           SUM(gesamt) as gesamt_ausgaben
    FROM bestellungen
    GROUP BY benutzer_id
)
SELECT b.benutzername, bo.bestell_anzahl, bo.gesamt_ausgaben
FROM benutzer b
JOIN benutzer_bestellungen bo ON b.id = bo.benutzer_id
WHERE bo.gesamt_ausgaben > 1000;
```

### Stored Procedures: `CREATE PROCEDURE`

Wiederverwendbare Datenbankprozeduren erstellen.

```sql
# Stored Procedure erstellen
DELIMITER //
CREATE PROCEDURE HoleBenutzerBestellungen(IN benutzer_id INT)
BEGIN
    SELECT o.*, p.produktname
    FROM bestellungen o
    JOIN produkte p ON o.produkt_id = p.id
    WHERE o.benutzer_id = benutzer_id;
END //
DELIMITER ;
# Prozedur aufrufen
CALL HoleBenutzerBestellungen(123);
```

### Trigger: `CREATE TRIGGER`

Code automatisch als Reaktion auf Datenbankereignisse ausführen.

```sql
# Trigger für Audit-Protokollierung erstellen
CREATE TRIGGER benutzer_update_audit
AFTER UPDATE ON benutzer
FOR EACH ROW
BEGIN
    INSERT INTO benutzer_audit (benutzer_id, alte_email, neue_email, geaendert_am)
    VALUES (NEW.id, OLD.email, NEW.email, NOW());
END;
# Trigger anzeigen
SHOW TRIGGERS;
```

### Views: `CREATE VIEW`

Virtuelle Tabellen basierend auf Abfrageergebnissen erstellen.

```sql
# View erstellen
CREATE VIEW aktive_benutzer AS
SELECT id, benutzername, email, erstellt_am
FROM benutzer
WHERE status = 'aktiv' AND letzte_anmeldung > DATE_SUB(NOW(), INTERVAL 30 DAY);
# View wie eine Tabelle verwenden
SELECT * FROM aktive_benutzer WHERE benutzername LIKE 'max%';
# View löschen
DROP VIEW aktive_benutzer;
```

## MySQL Installation & Einrichtung

### Installation: Paketmanager

MySQL mithilfe von Systempaketmanagern installieren.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# CentOS/RHEL
sudo yum install mysql-server
# macOS mit Homebrew
brew install mysql
# MySQL-Dienst starten
sudo systemctl start mysql
```

### Docker: `docker run mysql`

MySQL in Docker-Containern für die Entwicklung ausführen.

```bash
# MySQL-Container ausführen
docker run --name mysql-dev -e MYSQL_ROOT_PASSWORD=passwort -p 3306:3306 -d mysql:8.0
# Mit dem containerisierten MySQL verbinden
docker exec -it mysql-dev mysql -u root -p
# Datenbank im Container erstellen
docker exec -it mysql-dev mysql -u root -p -e "CREATE DATABASE testdb;"
```

### Ersteinrichtung & Sicherheit

MySQL-Installation absichern und Einrichtung überprüfen.

```bash
# Sicherheits-Skript ausführen
sudo mysql_secure_installation
# Mit MySQL verbinden
mysql -u root -p
# MySQL-Version anzeigen
SELECT VERSION();
# Verbindungsstatus prüfen
STATUS;
# Root-Passwort festlegen
ALTER USER 'root'@'localhost' IDENTIFIED BY 'neues_passwort';
```

## Konfiguration & Einstellungen

### Konfigurationsdateien: `my.cnf`

MySQL-Serverkonfigurationseinstellungen ändern.

```ini
# Gängige Konfigurationspfade
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

### Laufzeitkonfiguration: `SET GLOBAL`

Einstellungen ändern, während MySQL läuft.

```sql
# Globale Variablen setzen
SET GLOBAL max_connections = 500;
SET GLOBAL slow_query_log = ON;
# Aktuelle Einstellungen anzeigen
SHOW VARIABLES LIKE 'max_connections';
SHOW GLOBAL STATUS LIKE 'Slow_queries';
```

### Leistungsoptimierung: Speicher & Cache

MySQL-Leistungseinstellungen optimieren.

```sql
# Speichernutzung anzeigen
SHOW VARIABLES LIKE '%buffer_pool_size%';
SHOW VARIABLES LIKE '%query_cache%';
# Leistung überwachen
SHOW STATUS LIKE 'Qcache%';
SHOW STATUS LIKE 'Created_tmp%';
# InnoDB-Einstellungen
SET GLOBAL innodb_buffer_pool_size = 2147483648; -- 2GB
```

### Protokollkonfiguration: Fehler- & Abfrageprotokolle

MySQL-Protokollierung für Überwachung und Debugging konfigurieren.

```sql
# Abfrageprotokollierung aktivieren
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/query.log';
# Slow Query Log
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
# Protokolleinstellungen anzeigen
SHOW VARIABLES LIKE '%log%';
```

## Relevante Links

- <router-link to="/database">Datenbank Spickzettel</router-link>
- <router-link to="/postgresql">PostgreSQL Spickzettel</router-link>
- <router-link to="/sqlite">SQLite Spickzettel</router-link>
- <router-link to="/mongodb">MongoDB Spickzettel</router-link>
- <router-link to="/redis">Redis Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>

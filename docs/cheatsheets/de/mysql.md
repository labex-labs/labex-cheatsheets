---
title: 'MySQL Spickzettel | LabEx'
description: 'Erlernen Sie die MySQL-Datenbankverwaltung mit diesem umfassenden Spickzettel. Schnelle Referenz für SQL-Abfragen, Joins, Indizes, Transaktionen, gespeicherte Prozeduren und Datenbankadministration.'
pdfUrl: '/cheatsheets/pdf/mysql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
MySQL Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/mysql">MySQL mit praktischen Übungen lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie das Management von MySQL-Datenbanken durch praktische Übungen und reale Szenarien. LabEx bietet umfassende MySQL-Kurse, die wesentliche SQL-Operationen, Datenbankadministration, Leistungsoptimierung und fortgeschrittene Abfragetechniken abdecken. Meistern Sie eines der weltweit beliebtesten relationalen Datenbanksysteme.
</base-disclaimer-content>
</base-disclaimer>

## Datenbankverbindung & -verwaltung

### Mit Server verbinden: `mysql -u benutzername -p`

Verbindung zum MySQL-Server über die Kommandozeile herstellen.

```bash
# Mit Benutzername und Passwortabfrage verbinden
mysql -u root -p
# Mit spezifischer Datenbank verbinden
mysql -u benutzername -p datenbankname
# Mit Remote-Server verbinden
mysql -h hostname -u benutzername -p
# Verbindung mit Port-Spezifikation
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

<BaseQuiz id="mysql-database-1" correct="C">
  <template #question>
    Was bewirkt `USE datenbankname`?
  </template>
  
  <BaseQuizOption value="A">Erstellt eine neue Datenbank</BaseQuizOption>
  <BaseQuizOption value="B">Löscht die Datenbank</BaseQuizOption>
  <BaseQuizOption value="C" correct>Wählt die Datenbank für nachfolgende Operationen aus</BaseQuizOption>
  <BaseQuizOption value="D">Zeigt alle Tabellen in der Datenbank an</BaseQuizOption>
  
  <BaseQuizAnswer>
    Die `USE`-Anweisung wählt eine Datenbank aus und macht sie zur aktiven Datenbank für alle nachfolgenden SQL-Anweisungen. Dies entspricht der Auswahl einer Datenbank bei der Verbindung mit `mysql -u benutzer -p datenbankname`.
  </BaseQuizAnswer>
</BaseQuiz>

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
mysql -u benutzername -p < voll_backup.sql
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
# Berechtigungsänderungen anwenden
FLUSH PRIVILEGES;
```

### Serverinformationen anzeigen: `SHOW STATUS` / `SHOW VARIABLES`

Konfiguration und Status des Servers anzeigen.

```sql
# Serverstatus anzeigen
SHOW STATUS;
# Konfigurationsvariablen anzeigen
SHOW VARIABLES;
# Aktuelle Prozesse anzeigen
SHOW PROCESSLIST;
```

## Tabellenstruktur & Schema

### Tabelle erstellen: `CREATE TABLE`

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
# CREATE-Anweisung für Tabelle anzeigen
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

<BaseQuiz id="mysql-insert-1" correct="A">
  <template #question>
    Wie lautet die korrekte Syntax zum Einfügen eines einzelnen Datensatzes?
  </template>
  
  <BaseQuizOption value="A" correct>`INSERT INTO tabellenname (spalte1, spalte2) VALUES (wert1, wert2);`</BaseQuizOption>
  <BaseQuizOption value="B">`INSERT tabellenname VALUES (wert1, wert2);`</BaseQuizOption>
  <BaseQuizOption value="C">`ADD INTO tabellenname (spalte1, spalte2) VALUES (wert1, wert2);`</BaseQuizOption>
  <BaseQuizOption value="D">`INSERT tabellenname (spalte1, spalte2) = (wert1, wert2);`</BaseQuizOption>
  
  <BaseQuizAnswer>
    Die korrekte Syntax lautet `INSERT INTO tabellenname (spalten) VALUES (werte)`. Das Schlüsselwort `INTO` ist erforderlich, und Sie müssen sowohl die Spaltennamen als auch die entsprechenden Werte angeben.
  </BaseQuizAnswer>
</BaseQuiz>

### Daten aktualisieren: `UPDATE`

Bestehende Datensätze in Tabellen ändern.

```sql
# Spezifischen Datensatz aktualisieren
UPDATE benutzer SET alter = 26 WHERE benutzername = 'max_mustermann';
# Mehrere Spalten aktualisieren
UPDATE benutzer SET alter = 31, email = 'anna_neu@email.de'
WHERE benutzername = 'anna';
# Mit Berechnung aktualisieren
UPDATE produkte SET preis = preis * 1.1 WHERE kategorie = 'elektronik';
```

### Daten löschen: `DELETE` / `TRUNCATE`

Datensätze aus Tabellen entfernen.

```sql
# Spezifische Datensätze löschen
DELETE FROM benutzer WHERE alter < 18;
# Alle Datensätze löschen (Struktur beibehalten)
DELETE FROM benutzer;
# Alle Datensätze löschen (schneller, setzt AUTO_INCREMENT zurück)
TRUNCATE TABLE benutzer;
# Löschen mit JOIN
DELETE b FROM benutzer b
JOIN inaktive_konten i ON b.id = i.benutzer_id;
```

### Daten ersetzen: `REPLACE` / `INSERT ... ON DUPLICATE KEY`

Umgang mit doppelten Schlüsselwerten beim Einfügen.

```sql
# Vorhandenen ersetzen oder neu einfügen
REPLACE INTO benutzer (id, benutzername, email)
VALUES (1, 'aktualisierter_user', 'neu@email.de');
# Einfügen oder Aktualisieren bei doppeltem Schlüssel
INSERT INTO benutzer (benutzername, email)
VALUES ('max', 'max@email.de')
ON DUPLICATE KEY UPDATE email = VALUES(email);
```

## Datenabfrage & Auswahl

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

<BaseQuiz id="mysql-select-1" correct="D">
  <template #question>
    Was gibt `SELECT * FROM benutzer` zurück?
  </template>
  
  <BaseQuizOption value="A">Nur die erste Zeile aus der Benutzer-Tabelle</BaseQuizOption>
  <BaseQuizOption value="B">Nur die Spalte benutzername</BaseQuizOption>
  <BaseQuizOption value="C">Die Tabellenstruktur</BaseQuizOption>
  <BaseQuizOption value="D" correct>Alle Spalten und alle Zeilen aus der Benutzer-Tabelle</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das `*`-Wildcard wählt alle Spalten aus, und ohne eine WHERE-Klausel werden alle Zeilen zurückgegeben. Dies ist nützlich, um alle Daten anzuzeigen, sollte aber bei großen Tabellen mit Vorsicht verwendet werden.
  </BaseQuizAnswer>
</BaseQuiz>

### Sortieren & Begrenzen: `ORDER BY` / `LIMIT`

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

### Filtern: `WHERE` / `LIKE` / `IN`

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

### Gruppieren: `GROUP BY` / `HAVING`

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
SELECT b.benutzername, bst.bestelldatum
FROM benutzer b
INNER JOIN bestellungen bst ON b.id = bst.benutzer_id;
# Left Join (alle Benutzer, übereinstimmende Bestellungen)
SELECT b.benutzername, bst.bestelldatum
FROM benutzer b
LEFT JOIN bestellungen bst ON b.id = bst.benutzer_id;
# Mehrere Joins
SELECT b.benutzername, bst.bestelldatum, p.produktname
FROM benutzer b
JOIN bestellungen bst ON b.id = bst.benutzer_id
JOIN produkte p ON bst.produkt_id = p.id;
```

<BaseQuiz id="mysql-join-1" correct="B">
  <template #question>
    Was ist der Unterschied zwischen INNER JOIN und LEFT JOIN?
  </template>
  
  <BaseQuizOption value="A">Es gibt keinen Unterschied</BaseQuizOption>
  <BaseQuizOption value="B" correct>INNER JOIN gibt nur übereinstimmende Zeilen zurück, LEFT JOIN gibt alle Zeilen aus der linken Tabelle zurück</BaseQuizOption>
  <BaseQuizOption value="C">INNER JOIN ist schneller</BaseQuizOption>
  <BaseQuizOption value="D">LEFT JOIN funktioniert nur mit zwei Tabellen</BaseQuizOption>
  
  <BaseQuizAnswer>
    INNER JOIN gibt nur Zeilen zurück, für die es eine Übereinstimmung in beiden Tabellen gibt. LEFT JOIN gibt alle Zeilen aus der linken Tabelle und übereinstimmende Zeilen aus der rechten Tabelle zurück, wobei für nicht übereinstimmende Zeilen der rechten Tabelle NULL-Werte verwendet werden.
  </BaseQuizAnswer>
</BaseQuiz>

### Subqueries: `SELECT` innerhalb von `SELECT`

Verschachtelte Abfragen für komplexe Datenabrufe verwenden.

```sql
# Subquery in WHERE-Klausel
SELECT * FROM benutzer
WHERE id IN (SELECT benutzer_id FROM bestellungen WHERE gesamt > 100);
# Korrelierte Subquery
SELECT benutzername FROM benutzer b1
WHERE alter > (SELECT AVG(alter) FROM benutzer b2);
# Subquery in SELECT
SELECT benutzername,
(SELECT COUNT(*) FROM bestellungen WHERE benutzer_id = benutzer.id) as anzahl_bestellungen
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

### Window Functions: `OVER` / `PARTITION BY`

Berechnungen über Mengen von Tabellenzeilen durchführen.

```sql
# Ranking-Funktionen
SELECT benutzername, alter,
RANK() OVER (ORDER BY alter DESC) as alter_rang
FROM benutzer;
# Partitionierung nach Gruppe
SELECT benutzername, abteilung, gehalt,
AVG(gehalt) OVER (PARTITION BY abteilung) as abt_durchschnitt
FROM mitarbeiter;
# Laufende Summen
SELECT bestelldatum, gesamt,
SUM(gesamt) OVER (ORDER BY bestelldatum) as laufende_summe
FROM bestellungen;
```

## Indizes & Leistung

### Index erstellen: `CREATE INDEX`

Abfrageleistung durch Datenbankindizes verbessern.

```sql
# Regulären Index erstellen
CREATE INDEX idx_benutzername ON benutzer(benutzername);
# Zusammengesetzten Index erstellen
CREATE INDEX idx_benutzer_alter ON benutzer(benutzername, alter);
# Eindeutigen Index erstellen
CREATE UNIQUE INDEX idx_email ON benutzer(email);
# Indizes für Tabelle anzeigen
SHOW INDEXES FROM benutzer;
```

### Abfrageanalyse: `EXPLAIN`

Ausführungspläne von Abfragen und Leistung analysieren.

```sql
# Abfrageausführungsplan anzeigen
EXPLAIN SELECT * FROM benutzer WHERE alter > 25;
# Detaillierte Analyse
EXPLAIN FORMAT=JSON SELECT b.*, bst.gesamt
FROM benutzer b JOIN bestellungen bst ON b.id = bst.benutzer_id;
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
# Mit spezifischen Spalten laden
LOAD DATA INFILE '/pfad/zu/daten.csv'
INTO TABLE benutzer (benutzername, email, alter);
```

### Daten exportieren: `SELECT INTO OUTFILE`

Abfrageergebnisse in Dateien exportieren.

```sql
# In CSV-Datei exportieren
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
# In lokale Datenbank importieren
mysql -u lokaler_user -p lokale_datenbank < remote_backup.sql
# Direkte Datenkopie zwischen Servern
mysqldump -h quelle_host -u user -p db_name | mysql -h ziel_host -u user -p db_name
```

## Datentypen & Funktionen

### Häufige Datentypen: Zahlen, Text, Daten

Geeignete Datentypen für Ihre Spalten auswählen.

```sql
# Numerische Typen
INT, BIGINT, DECIMAL(10,2), FLOAT, DOUBLE
# String-Typen
VARCHAR(255), TEXT, CHAR(10), MEDIUMTEXT, LONGTEXT
# Datums- und Uhrzeittypen
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
SELECT CONCAT(vorname, ' ', nachname) as vollname FROM benutzer;
# String-Operationen
SELECT SUBSTRING(email, 1, LOCATE('@', email)-1) as benutzername FROM benutzer;
SELECT LENGTH(benutzername), UPPER(benutzername) FROM benutzer;
# Musterabgleich und Ersetzung
SELECT REPLACE(telefon, '-', '.') FROM benutzer WHERE telefon LIKE '___-___-____';
```

### Datumsfunktionen: `NOW()` / `DATE_ADD` / `DATEDIFF`

Effektiver Umgang mit Daten und Zeiten.

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
# Aggregierte Mathematik
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
# Oder bei Fehler zurückrollen
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
# Zeilensperrung in Transaktionen
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
# Zurückrollen zum Savepoint
ROLLBACK TO sp1;
COMMIT;
```

## Erweiterte SQL-Techniken

### Common Table Expressions (CTEs): `WITH`

Temporäre Ergebnismengen für komplexe Abfragen erstellen.

```sql
# Einfache CTE
WITH benutzer_bestellungen AS (
    SELECT benutzer_id, COUNT(*) as anzahl_bestellungen,
           SUM(gesamt) as gesamtbetrag
    FROM bestellungen
    GROUP BY benutzer_id
)
SELECT b.benutzername, uo.anzahl_bestellungen, uo.gesamtbetrag
FROM benutzer b
JOIN benutzer_bestellungen uo ON b.id = uo.benutzer_id
WHERE uo.gesamtbetrag > 1000;
```

### Stored Procedures: `CREATE PROCEDURE`

Wiederverwendbare Prozeduren für die Datenbank erstellen.

```sql
# Stored Procedure erstellen
DELIMITER //
CREATE PROCEDURE HoleBenutzerBestellungen(IN benutzer_id INT)
BEGIN
    SELECT bst.*, p.produktname
    FROM bestellungen bst
    JOIN produkte p ON bst.produkt_id = p.id
    WHERE bst.benutzer_id = benutzer_id;
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
SELECT * FROM aktive_benutzer WHERE benutzername LIKE 'john%';
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

Die MySQL-Installation absichern und die Einrichtung überprüfen.

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
# Häufige Speicherorte
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
# Globale Variablen festlegen
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

MySQL-Protokollierung zur Überwachung und Fehlerbehebung konfigurieren.

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

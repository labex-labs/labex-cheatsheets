---
title: 'Redis Spickzettel'
description: 'Lernen Sie Redis mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/redis-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Redis Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/redis">Lernen Sie Redis mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Redis In-Memory-Datenstrukturoperationen durch praktische Labs und reale Szenarien. LabEx bietet umfassende Redis-Kurse, die wesentliche Befehle, Datenstrukturen, Caching-Strategien, Pub/Sub-Messaging und Leistungsoptimierung abdecken. Meistern Sie Hochleistungs-Caching und Echtzeit-Datenverarbeitung.
</base-disclaimer-content>
</base-disclaimer>

## Redis Installation & Einrichtung

### Docker: `docker run redis`

Der schnellste Weg, Redis lokal zum Laufen zu bringen.

```bash
# Redis in Docker ausführen
docker run --name my-redis -p 6379:6379 -d redis
# Mit Redis CLI verbinden
docker exec -it my-redis redis-cli
# Mit persistenter Speicherung ausführen
docker run --name redis-persistent -p 6379:6379 -v redis-data:/data -d redis
```

### Linux: `sudo apt install redis`

Installiert den Redis-Server auf Ubuntu/Debian-Systemen.

```bash
# Redis installieren
sudo apt update
sudo apt install redis-server
# Redis-Dienst starten
sudo systemctl start redis-server
# Auto-Start beim Booten aktivieren
sudo systemctl enable redis-server
# Status prüfen
sudo systemctl status redis
```

### Verbinden & Testen: `redis-cli`

Verbinden Sie sich mit dem Redis-Server und überprüfen Sie die Installation.

```bash
# Mit lokalem Redis verbinden
redis-cli
# Verbindung testen
redis-cli PING
# Mit Remote-Redis verbinden
redis-cli -h hostname -p 6379 -a password
# Einzelnen Befehl ausführen
redis-cli SET mykey "Hello Redis"
```

## Grundlegende String-Operationen

### Setzen & Abrufen: `SET` / `GET`

Speichern einfacher Werte (Text, Zahlen, JSON usw.).

```redis
# Schlüssel-Wert-Paar setzen
SET mykey "Hello World"
# Wert nach Schlüssel abrufen
GET mykey
# Setzen mit Ablaufzeit (in Sekunden)
SET session:123 "user_data" EX 3600
# Nur setzen, wenn Schlüssel nicht existiert
SET mykey "new_value" NX
```

### String-Manipulation: `APPEND` / `STRLEN`

String-Werte modifizieren und inspizieren.

```redis
# An bestehenden String anhängen
APPEND mykey " - Welcome!"
# String-Länge abrufen
STRLEN mykey
# Teilstring abrufen
GETRANGE mykey 0 4
# Teilstring setzen
SETRANGE mykey 6 "Redis"
```

### Zahlenoperationen: `INCR` / `DECR`

Ganzzahlwerte, die in Redis gespeichert sind, inkrementieren oder dekrementieren.

```redis
# Um 1 inkrementieren
INCR counter
# Um 1 dekrementieren
DECR counter
# Um bestimmten Betrag inkrementieren
INCRBY counter 5
# Float inkrementieren
INCRBYFLOAT price 0.1
```

### Mehrfachoperationen: `MSET` / `MGET`

Effizient mit mehreren Schlüssel-Wert-Paaren arbeiten.

```redis
# Mehrere Schlüssel auf einmal setzen
MSET key1 "value1" key2 "value2" key3 "value3"
# Mehrere Werte abrufen
MGET key1 key2 key3
# Mehrere nur setzen, wenn keiner existiert
MSETNX key1 "val1" key2 "val2"
```

## Listen-Operationen

Listen sind geordnete Sequenzen von Strings, nützlich als Warteschlangen oder Stacks.

### Elemente hinzufügen: `LPUSH` / `RPUSH`

Elemente am linken (Kopf) oder rechten (Schwanz) Ende einer Liste hinzufügen.

```redis
# Am Kopf (links) hinzufügen
LPUSH mylist "first"
# Am Schwanz (rechts) hinzufügen
RPUSH mylist "last"
# Mehrere Elemente hinzufügen
LPUSH mylist "item1" "item2" "item3"
```

### Elemente entfernen: `LPOP` / `RPOP`

Elemente von den Enden der Liste entfernen und zurückgeben.

```redis
# Vom Kopf entfernen
LPOP mylist
# Vom Schwanz entfernen
RPOP mylist
# Blockierendes Pop (auf Element warten)
BLPOP mylist 10
```

### Elemente abrufen: `LRANGE` / `LINDEX`

Elemente oder Bereiche aus Listen abrufen.

```redis
# Gesamte Liste abrufen
LRANGE mylist 0 -1
# Erste 3 Elemente abrufen
LRANGE mylist 0 2
# Spezifisches Element nach Index abrufen
LINDEX mylist 0
# Listenlänge abrufen
LLEN mylist
```

### Listen-Dienstprogramme: `LSET` / `LTRIM`

Listeninhalte und -struktur modifizieren.

```redis
# Element am Index setzen
LSET mylist 0 "new_value"
# Liste auf Bereich zuschneiden
LTRIM mylist 0 99
# Position des Elements finden
LPOS mylist "search_value"
```

## Set-Operationen

Sets sind Sammlungen einzigartiger, ungeordneter String-Elemente.

### Grundlegende Set-Operationen: `SADD` / `SMEMBERS`

Eindeutige Elemente zu Sets hinzufügen und alle Mitglieder abrufen.

```redis
# Elemente zum Set hinzufügen
SADD myset "apple" "banana" "cherry"
# Alle Set-Mitglieder abrufen
SMEMBERS myset
# Prüfen, ob Element existiert
SISMEMBER myset "apple"
# Set-Größe abrufen
SCARD myset
```

### Set-Modifikationen: `SREM` / `SPOP`

Elemente auf unterschiedliche Weise aus Sets entfernen.

```redis
# Spezifische Elemente entfernen
SREM myset "banana"
# Zufälliges Element entfernen und zurückgeben
SPOP myset
# Zufälliges Element ohne Entfernen abrufen
SRANDMEMBER myset
```

### Set-Operationen: `SINTER` / `SUNION`

Mathematische Set-Operationen durchführen.

```redis
# Schnittmenge von Sets
SINTER set1 set2
# Vereinigungsmenge von Sets
SUNION set1 set2
# Differenz von Sets
SDIFF set1 set2
# Ergebnis in neuem Set speichern
SINTERSTORE result set1 set2
```

### Set-Dienstprogramme: `SMOVE` / `SSCAN`

Erweiterte Set-Manipulation und -Scan.

```redis
# Element zwischen Sets verschieben
SMOVE source_set dest_set "element"
# Set inkrementell scannen
SSCAN myset 0 MATCH "a*" COUNT 10
```

## Hash-Operationen

Hashes speichern Feld-Wert-Paare, ähnlich wie kleine JSON-Objekte oder Dictionaries.

### Grundlegende Hash-Operationen: `HSET` / `HGET`

Einzelne Hash-Felder setzen und abrufen.

```redis
# Hash-Feld setzen
HSET user:123 name "John Doe" age 30
# Hash-Feld abrufen
HGET user:123 name
# Mehrere Felder setzen
HMSET user:123 email "john@example.com" city "NYC"
# Mehrere Felder abrufen
HMGET user:123 name age email
```

### Hash-Inspektion: `HKEYS` / `HVALS`

Hash-Struktur und Inhalt untersuchen.

```redis
# Alle Feldnamen abrufen
HKEYS user:123
# Alle Werte abrufen
HVALS user:123
# Alle Felder und Werte abrufen
HGETALL user:123
# Anzahl der Felder abrufen
HLEN user:123
```

### Hash-Dienstprogramme: `HEXISTS` / `HDEL`

Existenz prüfen und Hash-Felder entfernen.

```redis
# Prüfen, ob Feld existiert
HEXISTS user:123 email
# Felder löschen
HDEL user:123 age city
# Feld inkrementieren
HINCRBY user:123 age 1
# Float inkrementieren
HINCRBYFLOAT user:123 balance 10.50
```

### Hash-Scanning: `HSCAN`

Große Hashes inkrementell durchlaufen.

```redis
# Hash-Felder scannen
HSCAN user:123 0
# Scannen mit Musterabgleich
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## Sortierte Set-Operationen

Sortierte Sets kombinieren die Einzigartigkeit von Sets mit der Reihenfolge basierend auf Scores.

### Grundlegende Operationen: `ZADD` / `ZRANGE`

Scored Members hinzufügen und Bereiche abrufen.

```redis
# Mitglieder mit Scores hinzufügen
ZADD leaderboard 100 "player1" 200 "player2"
# Mitglieder nach Rang abrufen (0-basiert)
ZRANGE leaderboard 0 -1
# Mit Scores abrufen
ZRANGE leaderboard 0 -1 WITHSCORES
# Nach Score-Bereich abrufen
ZRANGEBYSCORE leaderboard 100 200
```

### Sortiertes Set Info: `ZCARD` / `ZSCORE`

Informationen über Mitglieder sortierter Sets abrufen.

```redis
# Set-Größe abrufen
ZCARD leaderboard
# Mitglieds-Score abrufen
ZSCORE leaderboard "player1"
# Mitglieds-Rang abrufen
ZRANK leaderboard "player1"
# Mitglieder im Score-Bereich zählen
ZCOUNT leaderboard 100 200
```

### Modifikationen: `ZREM` / `ZINCRBY`

Mitglieder entfernen und Scores modifizieren.

```redis
# Mitglieder entfernen
ZREM leaderboard "player1"
# Mitglieds-Score inkrementieren
ZINCRBY leaderboard 10 "player2"
# Entfernen nach Rang
ZREMRANGEBYRANK leaderboard 0 2
# Entfernen nach Score
ZREMRANGEBYSCORE leaderboard 0 100
```

### Erweitert: `ZUNIONSTORE` / `ZINTERSTORE`

Mehrere sortierte Sets kombinieren.

```redis
# Vereinigung sortierter Sets
ZUNIONSTORE result 2 set1 set2
# Schnittmenge mit Gewichten
ZINTERSTORE result 2 set1 set2 WEIGHTS 1 2
# Mit Aggregationsfunktion
ZUNIONSTORE result 2 set1 set2 AGGREGATE MAX
```

## Schlüsselverwaltung

### Schlüsselinspektion: `KEYS` / `EXISTS`

Schlüssel anhand von Mustern finden und Existenz prüfen.

```redis
# Alle Schlüssel abrufen (vorsichtig in Produktion verwenden)
KEYS *
# Schlüssel mit Muster
KEYS user:*
# Schlüssel, die mit Muster enden
KEYS *:profile
# Einzelzeichen-Platzhalter
KEYS order:?
# Prüfen, ob Schlüssel existiert
EXISTS mykey
```

### Schlüsselinformationen: `TYPE` / `TTL`

Schlüsselmetadaten und Ablaufinformationen abrufen.

```redis
# Schlüssel-Datentyp abrufen
TYPE mykey
# Verbleibende Zeit bis zum Ablauf (Sekunden)
TTL mykey
# TTL in Millisekunden
PTTL mykey
# Ablaufzeit entfernen
PERSIST mykey
```

### Schlüsseloperationen: `RENAME` / `DEL`

Schlüssel umbenennen, löschen und verschieben.

```redis
# Schlüssel umbenennen
RENAME oldkey newkey
# Nur umbenennen, wenn neuer Schlüssel nicht existiert
RENAMENX oldkey newkey
# Schlüssel löschen
DEL key1 key2 key3
# Schlüssel in eine andere Datenbank verschieben
MOVE mykey 1
```

### Ablaufzeit: `EXPIRE` / `EXPIREAT`

Ablaufzeiten für Schlüssel festlegen.

```redis
# Ablaufzeit in Sekunden festlegen
EXPIRE mykey 3600
# Ablaufzeit zu einem bestimmten Zeitstempel festlegen
EXPIREAT mykey 1609459200
# Ablaufzeit in Millisekunden festlegen
PEXPIRE mykey 60000
```

## Datenbankverwaltung

### Datenbankauswahl: `SELECT` / `FLUSHDB`

Mehrere Datenbanken innerhalb von Redis verwalten.

```redis
# Datenbank auswählen (standardmäßig 0-15)
SELECT 0
# Aktuelle Datenbank leeren
FLUSHDB
# Alle Datenbanken leeren
FLUSHALL
# Aktuelle Datenbankgröße abrufen
DBSIZE
```

### Server-Infos: `INFO` / `PING`

Serverstatistiken abrufen und Konnektivität testen.

```redis
# Serververbindung testen
PING
# Serverinformationen abrufen
INFO
# Spezifischen Info-Abschnitt abrufen
INFO memory
INFO replication
# Serverzeit abrufen
TIME
```

### Persistenz: `SAVE` / `BGSAVE`

Redis-Datenspeicherung und Backups steuern.

```redis
# Synchrone Speicherung (blockiert Server)
SAVE
# Hintergrundspeicherung (nicht blockierend)
BGSAVE
# Letzte Speicherzeit abrufen
LASTSAVE
# AOF-Datei neu schreiben
BGREWRITEAOF
```

### Konfiguration: `CONFIG GET` / `CONFIG SET`

Redis-Konfiguration anzeigen und ändern.

```redis
# Gesamte Konfiguration abrufen
CONFIG GET *
# Spezifische Konfiguration abrufen
CONFIG GET maxmemory
# Konfiguration setzen
CONFIG SET timeout 300
# Statistik zurücksetzen
CONFIG RESETSTAT
```

## Leistungsüberwachung

### Echtzeitüberwachung: `MONITOR` / `SLOWLOG`

Befehle verfolgen und Leistungsengpässe identifizieren.

```redis
# Alle Befehle in Echtzeit überwachen
MONITOR
# Langsame Abfrageprotokolle abrufen
SLOWLOG GET 10
# Länge des langsamen Protokolls abrufen
SLOWLOG LEN
# Langsames Protokoll zurücksetzen
SLOWLOG RESET
```

### Speicheranalyse: `MEMORY USAGE` / `MEMORY STATS`

Speichernutzung analysieren und Optimierung.

```redis
# Speichernutzung eines Schlüssels abrufen
MEMORY USAGE mykey
# Speicherstatistiken abrufen
MEMORY STATS
# Speicher-Doktorbericht abrufen
MEMORY DOCTOR
# Speicher bereinigen
MEMORY PURGE
```

### Client-Informationen: `CLIENT LIST`

Verbundene Clients und Verbindungen überwachen.

```redis
# Alle Clients auflisten
CLIENT LIST
# Client-Infos abrufen
CLIENT INFO
# Client-Verbindung beenden
CLIENT KILL ip:port
# Client-Namen setzen
CLIENT SETNAME "my-app"
```

### Benchmarking: `redis-benchmark`

Redis-Leistung mit dem integrierten Benchmark-Tool testen.

```bash
# Basis-Benchmark
redis-benchmark
# Spezifische Operationen
redis-benchmark -t SET,GET -n 100000
# Benutzerdefinierte Payload-Größe
redis-benchmark -d 1024 -t SET -n 10000
```

## Erweiterte Funktionen

### Transaktionen: `MULTI` / `EXEC`

Mehrere Befehle atomar ausführen.

```redis
# Transaktion starten
MULTI
SET key1 "value1"
INCR counter
# Alle Befehle ausführen
EXEC
# Transaktion verwerfen
DISCARD
# Schlüssel beobachten
WATCH mykey
```

### Pub/Sub: `PUBLISH` / `SUBSCRIBE`

Nachrichtenübermittlung zwischen Clients implementieren.

```redis
# Kanal abonnieren
SUBSCRIBE news sports
# Nachricht veröffentlichen
PUBLISH news "Breaking: Redis 7.0 released!"
# Musterabonnement
PSUBSCRIBE news:*
# Abonnement aufheben
UNSUBSCRIBE news
```

### Lua-Skripting: `EVAL` / `SCRIPT`

Benutzerdefinierte Lua-Skripte atomar ausführen.

```redis
# Lua-Skript ausführen
EVAL "return redis.call('SET', 'key', 'value')" 0
# Skript laden und SHA erhalten
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# Nach SHA ausführen
EVALSHA sha1 1 mykey
# Skript-Existenz prüfen
SCRIPT EXISTS sha1
```

### Streams: `XADD` / `XREAD`

Mit Redis-Streams für log-ähnliche Daten arbeiten.

```redis
# Eintrag zum Stream hinzufügen
XADD mystream * field1 value1 field2 value2
# Aus dem Stream lesen
XREAD STREAMS mystream 0
# Stream-Länge abrufen
XLEN mystream
# Konsumentengruppe erstellen
XGROUP CREATE mystream mygroup 0
```

## Datentypen Übersicht

### Strings: Vielseitigster Typ

Kann Text, Zahlen, JSON, Binärdaten speichern. Maximale Größe: 512MB. Verwendung für: Caching, Zähler, Flags.

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### Listen: Geordnete Sammlungen

Verkettete Listen von Strings. Verwendung für: Warteschlangen, Stacks, Aktivitäts-Feeds, aktuelle Elemente.

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### Sets: Eindeutige Sammlungen

Ungeordnete Sammlungen eindeutiger Strings. Verwendung für: Tags, eindeutige Besucher, Beziehungen.

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Redis Konfigurationstipps

### Speicherverwaltung

Speicherlimits und Eviction-Richtlinien konfigurieren.

```redis
# Speichergrenze setzen
CONFIG SET maxmemory 2gb
# Eviction-Richtlinie setzen
CONFIG SET maxmemory-policy allkeys-lru
# Speichernutzung prüfen
INFO memory
```

### Persistenz-Einstellungen

Einstellungen zur Datendauerhaftigkeit konfigurieren.

```redis
# AOF aktivieren
CONFIG SET appendonly yes
# Speicherintervalle festlegen
CONFIG SET save "900 1 300 10 60 10000"
# AOF-Rewrite-Einstellungen
CONFIG SET auto-aof-rewrite-percentage 100
```

### Sicherheitseinstellungen

Grundlegende Sicherheitseinstellungen für Redis.

```redis
# Passwort setzen
CONFIG SET requirepass mypassword
# Authentifizieren
AUTH mypassword
# Gefährliche Befehle deaktivieren
CONFIG SET rename-command FLUSHALL ""
# Timeout setzen
CONFIG SET timeout 300
# TCP Keep Alive
CONFIG SET tcp-keepalive 60
# Maximale Clients
CONFIG SET maxclients 10000
```

### Leistungsoptimierung

Redis für bessere Leistung optimieren.

```redis
# Pipelining für mehrere Befehle aktivieren
# Connection Pooling verwenden
# Angemessene maxmemory-policy konfigurieren
# Langsame Abfragen regelmäßig überwachen
# Geeignete Datenstrukturen für Anwendungsfälle verwenden
```

## Relevante Links

- <router-link to="/database">Datenbank Spickzettel</router-link>
- <router-link to="/mysql">MySQL Spickzettel</router-link>
- <router-link to="/postgresql">PostgreSQL Spickzettel</router-link>
- <router-link to="/mongodb">MongoDB Spickzettel</router-link>
- <router-link to="/sqlite">SQLite Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>

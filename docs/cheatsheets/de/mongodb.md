---
title: 'MongoDB Spickzettel'
description: 'Lernen Sie MongoDB mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/mongodb-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
MongoDB Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/mongodb">Lernen Sie MongoDB mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie das Management der NoSQL-Datenbank MongoDB durch praktische Labs und reale Szenarien. LabEx bietet umfassende MongoDB-Kurse, die wesentliche Operationen, Dokumentabfragen, Aggregations-Pipelines, Indexierungsstrategien und fortgeschrittene Techniken abdecken. Meistern Sie das dokumentenbasierte Datenmodell von MongoDB, um skalierbare und flexible Datenbankanwendungen zu erstellen.
</base-disclaimer-content>
</base-disclaimer>

## Datenbank- & Collection-Verwaltung

### Datenbanken anzeigen: `show dbs`

Zeigt alle Datenbanken auf dem MongoDB-Server an.

```javascript
// Alle Datenbanken anzeigen
show dbs
// Aktuelle Datenbank anzeigen
db
// Datenbank-Statistiken abrufen
db.stats()
// Datenbank-Hilfe abrufen
db.help()
```

### Datenbank verwenden: `use database_name`

Wechselt zu einer bestimmten Datenbank (wird erstellt, falls nicht vorhanden).

```javascript
// Zu myapp Datenbank wechseln
use myapp
// Datenbank durch Einfügen von Daten erstellen
use newdb
db.users.insertOne({name: "John"})
```

### Datenbank löschen: `db.dropDatabase()`

Löscht die aktuelle Datenbank und alle ihre Collections.

```javascript
// Aktuelle Datenbank löschen
db.dropDatabase()
// Mit Datenbanknamen bestätigen
use myapp
db.dropDatabase()
```

### Collections anzeigen: `show collections`

Listet alle Collections in der aktuellen Datenbank auf.

```javascript
// Alle Collections anzeigen
show collections
// Alternative Methode
db.runCommand("listCollections")
```

### Collection erstellen: `db.createCollection()`

Erstellt eine neue Collection mit optionaler Konfiguration.

```javascript
// Einfache Collection erstellen
db.createCollection('users')
// Mit Optionen erstellen
db.createCollection('logs', {
  capped: true,
  size: 1000000,
  max: 1000,
})
```

### Collection löschen: `db.collection.drop()`

Löscht eine Collection und alle darin enthaltenen Dokumente.

```javascript
// Users Collection löschen
db.users.drop()
// Prüfen, ob die Collection gelöscht wurde
show collections
```

## Dokumentstruktur & Infos

### Collection-Statistiken: `db.collection.stats()`

Zeigt umfassende Statistiken zu einer Collection an, einschließlich Größe, Dokumentanzahl und Indexinformationen.

```javascript
// Collection-Statistiken
db.users.stats()
// Dokumente zählen
db.users.countDocuments()
// Geschätzte Anzahl (schneller)
db.users.estimatedDocumentCount()
// Collection-Indizes prüfen
db.users.getIndexes()
```

### Beispiel-Dokumente: `db.collection.findOne()`

Ruft Beispieldokumente ab, um Struktur und Datentypen zu verstehen.

```javascript
// Ein Dokument abrufen
db.users.findOne()
// Spezifisches Dokument abrufen
db.users.findOne({ name: 'John' })
// Dokument mit allen angezeigten Feldern abrufen
db.users.findOne({}, { _id: 0 })
```

### Daten durchsuchen: `db.collection.find().limit()`

Durchsuchen Sie Collection-Daten mit Paginierung und Formatierung.

```javascript
// Erste 5 Dokumente
db.users.find().limit(5)
// Überspringen und Limitieren (Paginierung)
db.users.find().skip(10).limit(5)
// Pretty Format
db.users.find().pretty()
```

## Dokumente einfügen (Erstellen)

### Ein Dokument einfügen: `db.collection.insertOne()`

Fügt ein einzelnes Dokument in eine Collection ein.

```javascript
// Einzelnes Dokument einfügen
db.users.insertOne({
  name: 'John Doe',
  age: 30,
  email: 'john@example.com',
})
// Mit benutzerdefiniertem _id einfügen
db.users.insertOne({
  _id: 'custom_id_123',
  name: 'Jane Doe',
  status: 'active',
})
```

### Mehrere Dokumente einfügen: `db.collection.insertMany()`

Fügt mehrere Dokumente in einer einzigen Operation hinzu.

```javascript
// Mehrere Dokumente einfügen
db.users.insertMany([
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 35 },
  { name: 'Charlie', age: 28 },
])
// Mit Optionen einfügen
db.users.insertMany(
  [
    { name: 'Dave', age: 40 },
    { name: 'Eve', age: 22 },
  ],
  { ordered: false },
)
```

### Mit Datum einfügen: `new Date()`

Fügt Dokumente mit Zeitstempel-Feldern hinzu.

```javascript
// Mit aktuellem Datum einfügen
db.posts.insertOne({
  title: 'Mein Blogbeitrag',
  content: 'Beitragsinhalt hier',
  createdAt: new Date(),
  publishDate: ISODate('2024-01-15'),
})
```

### Verschachtelte Dokumente einfügen

Fügt Dokumente mit eingebetteten Objekten und Arrays hinzu.

```javascript
// Mit verschachtelten Objekten einfügen
db.users.insertOne({
  name: 'John Doe',
  address: {
    street: '123 Main St',
    city: 'New York',
    zip: '10001',
  },
  hobbies: ['reading', 'swimming', 'coding'],
})
```

## Dokumentabfragen (Lesen)

### Basisabfrage: `db.collection.find()`

Ruft Dokumente basierend auf Abfragebedingungen ab.

```javascript
// Alle Dokumente abrufen
db.users.find()
// Mit Bedingung abrufen
db.users.find({ age: 30 })
// Mit mehreren Bedingungen (AND) abrufen
db.users.find({ age: 30, status: 'active' })
// Mit OR-Bedingung abrufen
db.users.find({ $or: [{ age: 25 }, { age: 30 }] })
```

### Projektion: `db.collection.find({}, {})`

Steuert, welche Felder in den Ergebnissen zurückgegeben werden.

```javascript
// Spezifische Felder einschließen
db.users.find({}, { name: 1, age: 1 })
// Spezifische Felder ausschließen
db.users.find({}, { password: 0, _id: 0 })
// Verschachtelte Feldprojektion
db.users.find({}, { 'address.city': 1 })
```

### Abfrageoperatoren: `$gt`, `$lt`, `$in` usw.

Verwenden Sie Vergleichs- und logische Operatoren für komplexe Abfragen.

```javascript
// Größer als, kleiner als
db.users.find({ age: { $gt: 25, $lt: 40 } })
// In Array
db.users.find({ status: { $in: ['active', 'pending'] } })
// Nicht gleich
db.users.find({ status: { $ne: 'inactive' } })
// Existiert
db.users.find({ email: { $exists: true } })
```

### Textsuche: `$text`, `$regex`

Durchsucht Dokumente mithilfe von Text und Musterabgleich.

```javascript
// Textsuche (erfordert Text-Index)
db.posts.find({ $text: { $search: 'mongodb tutorial' } })
// Regex-Suche
db.users.find({ name: { $regex: '^John', $options: 'i' } })
// Nicht-Groß-/Kleinschreibung-sensitive Suche
db.users.find({ email: { $regex: '@gmail.com$' } })
```

## Dokumentaktualisierungen

### Ein Dokument aktualisieren: `db.collection.updateOne()`

Ändert das erste Dokument, das mit der Abfrage übereinstimmt.

```javascript
// Einzelnes Feld aktualisieren
db.users.updateOne({ name: 'John Doe' }, { $set: { age: 31 } })
// Mehrere Felder aktualisieren
db.users.updateOne(
  { _id: ObjectId('...') },
  { $set: { age: 31, status: 'updated' } },
)
// Upsert (einfügen, falls nicht gefunden)
db.users.updateOne(
  { name: 'New User' },
  { $set: { age: 25 } },
  { upsert: true },
)
```

### Mehrere Dokumente aktualisieren: `db.collection.updateMany()`

Ändert alle Dokumente, die mit der Abfrage übereinstimmen.

```javascript
// Mehrere Dokumente aktualisieren
db.users.updateMany({ status: 'inactive' }, { $set: { status: 'archived' } })
// Werte inkrementieren
db.posts.updateMany({ category: 'tech' }, { $inc: { views: 1 } })
```

### Aktualisierungsoperatoren: `$set`, `$unset`, `$push`

Verwenden Sie verschiedene Operatoren, um Dokumentfelder zu ändern.

```javascript
// Felder setzen und entfernen
db.users.updateOne(
  { name: 'John' },
  { $set: { lastLogin: new Date() }, $unset: { temp: '' } },
)
// Zu Array hinzufügen
db.users.updateOne({ name: 'John' }, { $push: { hobbies: 'gaming' } })
// Aus Array entfernen
db.users.updateOne({ name: 'John' }, { $pull: { hobbies: 'reading' } })
```

### Dokument ersetzen: `db.collection.replaceOne()`

Ersetzt ein gesamtes Dokument außer dem \_id-Feld.

```javascript
// Gesamtes Dokument ersetzen
db.users.replaceOne(
  { name: 'John Doe' },
  {
    name: 'John Smith',
    age: 35,
    email: 'johnsmith@example.com',
  },
)
```

## Datenaggregation

### Basisaggregation: `db.collection.aggregate()`

Verarbeitet Daten durch Aggregations-Pipeline-Stufen.

```javascript
// Gruppieren und zählen
db.users.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }])
// Filtern und gruppieren
db.orders.aggregate([
  { $match: { status: 'completed' } },
  { $group: { _id: '$customerId', total: { $sum: '$amount' } } },
])
```

### Häufige Stufen: `$match`, `$group`, `$sort`

Verwenden Sie Pipeline-Stufen, um Daten zu transformieren und zu analysieren.

```javascript
// Komplexe Aggregations-Pipeline
db.sales.aggregate([
  { $match: { date: { $gte: ISODate('2024-01-01') } } },
  {
    $group: {
      _id: '$product',
      totalSales: { $sum: '$amount' },
      avgPrice: { $avg: '$price' },
    },
  },
  { $sort: { totalSales: -1 } },
  { $limit: 10 },
])
```

### Aggregationsoperatoren: `$sum`, `$avg`, `$max`

Berechnen Sie statistische Werte und führen Sie mathematische Operationen durch.

```javascript
// Statistische Operationen
db.products.aggregate([
  {
    $group: {
      _id: '$category',
      maxPrice: { $max: '$price' },
      minPrice: { $min: '$price' },
      avgPrice: { $avg: '$price' },
      count: { $sum: 1 },
    },
  },
])
```

### Projektionsstufe: `$project`

Transformiert die Dokumentstruktur und erstellt berechnete Felder.

```javascript
// Projektion und Berechnung von Feldern
db.users.aggregate([
  {
    $project: {
      name: 1,
      age: 1,
      isAdult: { $gte: ['$age', 18] },
      fullName: { $concat: ['$firstName', ' ', '$lastName'] },
    },
  },
])
```

## Dokumentenlöschung

### Ein Dokument löschen: `db.collection.deleteOne()`

Entfernt das erste Dokument, das der Abfragebedingung entspricht.

```javascript
// Einzelnes Dokument löschen
db.users.deleteOne({ name: 'John Doe' })
// Nach ID löschen
db.users.deleteOne({ _id: ObjectId('...') })
// Mit Bedingung löschen
db.posts.deleteOne({ status: 'draft', author: 'unknown' })
```

### Mehrere Dokumente löschen: `db.collection.deleteMany()`

Entfernt alle Dokumente, die der Abfragebedingung entsprechen.

```javascript
// Mehrere Dokumente löschen
db.users.deleteMany({ status: 'inactive' })
// Alle Dokumente löschen (Vorsicht!)
db.temp_collection.deleteMany({})
// Mit Datumsbedingung löschen
db.logs.deleteMany({
  createdAt: { $lt: new Date('2024-01-01') },
})
```

### Finden und Löschen: `db.collection.findOneAndDelete()`

Findet ein Dokument und löscht es in einer einzigen atomaren Operation.

```javascript
// Finden und löschen
const deletedDoc = db.users.findOneAndDelete({ status: 'pending' })
// Finden und löschen mit Optionen
db.queue.findOneAndDelete({ processed: false }, { sort: { priority: -1 } })
```

## Indizierung & Performance

### Index erstellen: `db.collection.createIndex()`

Erstellt Indizes für Felder, um Abfragen zu beschleunigen.

```javascript
// Einzel-Feld-Index
db.users.createIndex({ email: 1 })
// Zusammengesetzter Index
db.users.createIndex({ status: 1, createdAt: -1 })
// Text-Index für Suche
db.posts.createIndex({ title: 'text', content: 'text' })
// Eindeutiger Index
db.users.createIndex({ email: 1 }, { unique: true })
```

### Indexverwaltung: `getIndexes()`, `dropIndex()`

Anzeigen und Verwalten vorhandener Indizes auf Collections.

```javascript
// Alle Indizes auflisten
db.users.getIndexes()
// Spezifischen Index löschen
db.users.dropIndex({ email: 1 })
// Index nach Namen löschen
db.users.dropIndex('email_1')
// Alle Indizes außer _id löschen
db.users.dropIndexes()
```

### Abfrage-Performance: `explain()`

Analysiert die Abfrageausführung und Leistungsstatistiken.

```javascript
// Abfrageausführung erklären
db.users.find({ age: { $gt: 25 } }).explain('executionStats')
// Prüfen, ob ein Index verwendet wird
db.users.find({ email: 'john@example.com' }).explain()
// Aggregations-Performance analysieren
db.users
  .aggregate([
    { $match: { status: 'active' } },
    { $group: { _id: '$department', count: { $sum: 1 } } },
  ])
  .explain('executionStats')
```

### Performance-Tipps

Bewährte Verfahren zur Optimierung von MongoDB-Abfragen und -Operationen.

```javascript
// Projektion verwenden, um Datenübertragung zu begrenzen
db.users.find({ status: 'active' }, { name: 1, email: 1 })
// Limit für bessere Performance verwenden
db.posts.find().sort({ createdAt: -1 }).limit(10)
// Hint verwenden, um einen bestimmten Index zu erzwingen
db.users.find({ age: 25 }).hint({ age: 1 })
```

## MongoDB Shell & Verbindung

### Verbindung zu MongoDB: `mongosh`

Startet die MongoDB Shell und stellt Verbindungen zu verschiedenen Instanzen her.

```bash
# Verbindung zu lokalem MongoDB
mongosh
# Verbindung zu spezifischem Host und Port
mongosh "mongodb://localhost:27017"
# Verbindung zu Remote-Server
mongosh "mongodb://username:password@host:port/database"
# Verbindung mit Optionen
mongosh --host localhost --port 27017
```

### Shell-Helfer: `help`, `exit`

Ruft Hilfeinformationen ab und verwaltet Shell-Sitzungen.

```javascript
// Allgemeine Hilfe
help
// Datenbankspezifische Hilfe
db.help()
// Collection-spezifische Hilfe
db.users.help()
// Shell beenden
exit
```

### Shell-Variablen und Einstellungen

Konfiguriert das Shell-Verhalten und verwendet JavaScript-Variablen.

```javascript
// Variable setzen
var myQuery = { status: 'active' }
db.users.find(myQuery)
// Anzeigeoptionen konfigurieren
db.users.find().pretty()
// Ausführungszeit anzeigen
db.users.find({ age: 25 }).explain('executionStats')
// JavaScript in der Shell verwenden
var user = db.users.findOne({ name: 'John' })
print('Alter des Benutzers: ' + user.age)
```

## Datenimport & -export

### Daten importieren: `mongoimport`

Lädt Daten aus JSON-, CSV- oder TSV-Dateien in MongoDB.

```bash
# JSON-Datei importieren
mongoimport --db myapp --collection users --file users.json
# CSV-Datei importieren
mongoimport --db myapp --collection products \
  --type csv --headerline --file products.csv
# Import mit Upsert
mongoimport --db myapp --collection users \
  --file users.json --mode upsert
```

### Daten exportieren: `mongoexport`

Exportiert MongoDB-Daten in das JSON- oder CSV-Format.

```bash
# Export nach JSON
mongoexport --db myapp --collection users \
  --out users.json
# Export nach CSV
mongoexport --db myapp --collection users \
  --type csv --fields name,email,age --out users.csv
# Export mit Abfrage
mongoexport --db myapp --collection users \
  --query '{"status":"active"}' --out active_users.json
```

### Backup: `mongodump`

Erstellt binäre Backups von MongoDB-Datenbanken.

```bash
# Gesamte Datenbank sichern
mongodump --db myapp --out /backup/
# Spezifische Collection sichern
mongodump --db myapp --collection users --out /backup/
# Backup mit Komprimierung
mongodump --db myapp --gzip --out /backup/
```

### Wiederherstellung: `mongorestore`

Stellt MongoDB-Daten aus binären Backups wieder her.

```bash
# Datenbank wiederherstellen
mongorestore --db myapp /backup/myapp/
# Wiederherstellen mit Löschen
mongorestore --db myapp --drop /backup/myapp/
# Komprimiertes Backup wiederherstellen
mongorestore --gzip --db myapp /backup/myapp/
```

## MongoDB Installation & Einrichtung

### MongoDB Community Server

Laden Sie die MongoDB Community Edition herunter und installieren Sie sie.

```bash
# Ubuntu/Debian
sudo apt-get install -y mongodb-org
# MongoDB-Dienst starten
sudo systemctl start mongod
# Auto-Start aktivieren
sudo systemctl enable mongod
# Status prüfen
sudo systemctl status mongod
```

### Docker-Installation

Führen Sie MongoDB mithilfe von Docker-Containern aus.

```bash
# MongoDB Image ziehen
docker pull mongo
# MongoDB Container ausführen
docker run --name mongodb -d \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  mongo
# Mit Container verbinden
docker exec -it mongodb mongosh
```

### MongoDB Compass (GUI)

Installieren und verwenden Sie das offizielle GUI-Tool von MongoDB.

```bash
# Von mongodb.com herunterladen
# Mit Verbindungszeichenfolge verbinden
mongodb://localhost:27017
# Verfügbare Funktionen:
# - Visueller Abfrage-Builder
# - Schema-Analyse
# - Leistungsüberwachung
# - Indexverwaltung
```

## Konfiguration & Sicherheit

### Authentifizierung: Benutzer erstellen

Richten Sie Datenbankbenutzer mit den richtigen Rollen und Berechtigungen ein.

```javascript
// Admin-Benutzer erstellen
use admin
db.createUser({
  user: "admin",
  pwd: "securepassword",
  roles: [{role: "root", db: "admin"}]
})
// Datenbankbenutzer erstellen
use myapp
db.createUser({
  user: "appuser",
  pwd: "password123",
  roles: [{role: "readWrite", db: "myapp"}]
})
```

### Authentifizierung aktivieren

Konfigurieren Sie MongoDB so, dass eine Authentifizierung erforderlich ist.

```bash
# /etc/mongod.conf bearbeiten
security:
  authorization: enabled
# MongoDB neu starten
sudo systemctl restart mongod
# Mit Authentifizierung verbinden
mongosh -u admin -p --authenticationDatabase admin
```

### Replica Sets: `rs.initiate()`

Richten Sie Replica Sets für hohe Verfügbarkeit ein.

```javascript
// Replica Set initialisieren
rs.initiate({
  _id: 'myReplicaSet',
  members: [
    { _id: 0, host: 'mongodb1:27017' },
    { _id: 1, host: 'mongodb2:27017' },
    { _id: 2, host: 'mongodb3:27017' },
  ],
})
// Replica Set Status prüfen
rs.status()
```

### Konfigurationsoptionen

Häufige MongoDB-Konfigurationseinstellungen.

```yaml
# Beispiel für mongod.conf
storage:
  dbPath: /var/lib/mongodb
systemLog:
  destination: file
  path: /var/log/mongodb/mongod.log
net:
  port: 27017
  bindIp: 127.0.0.1
processManagement:
  fork: true
```

## Fehlerbehandlung & Debugging

### Häufige Fehler und Lösungen

Identifizieren und beheben Sie häufig auftretende MongoDB-Probleme.

```javascript
// Verbindungsfehler
// Prüfen, ob MongoDB läuft
sudo systemctl status mongod
// Verfügbarkeit des Ports prüfen
netstat -tuln | grep 27017
// Fehlerbehandlung bei doppelten Schlüsseln
try {
  db.users.insertOne({email: "existing@example.com"})
} catch (e) {
  if (e.code === 11000) {
    print("E-Mail existiert bereits")
  }
}
```

### Überwachung: `db.currentOp()`, `db.serverStatus()`

Überwachen Sie Datenbankoperationen und Serverleistung.

```javascript
// Aktuelle Operationen prüfen
db.currentOp()
// Langlaufende Operation beenden
db.killOp(operationId)
// Serverstatus
db.serverStatus()
// Verbindungsstatistiken
db.runCommand({ connPoolStats: 1 })
```

### Profiling: `db.setProfilingLevel()`

Aktivieren Sie das Profiling, um langsame Operationen zu analysieren.

```javascript
// Profiling für langsame Operationen (>100ms) aktivieren
db.setProfilingLevel(1, { slowms: 100 })
// Profiling für alle Operationen aktivieren
db.setProfilingLevel(2)
// Profildaten anzeigen
db.system.profile.find().sort({ ts: -1 }).limit(5)
// Profiling deaktivieren
db.setProfilingLevel(0)
```

## Fortgeschrittene Operationen

### Transaktionen: `session.startTransaction()`

Verwenden Sie Multi-Dokument-Transaktionen für Datenkonsistenz.

```javascript
// Sitzung und Transaktion starten
const session = db.getMongo().startSession()
session.startTransaction()
try {
  const users = session.getDatabase('myapp').users
  const accounts = session.getDatabase('myapp').accounts

  users.insertOne({ name: 'John', balance: 100 })
  accounts.updateOne({ userId: 'john' }, { $inc: { balance: -100 } })

  session.commitTransaction()
} catch (error) {
  session.abortTransaction()
} finally {
  session.endSession()
}
```

### Change Streams: `db.collection.watch()`

Beobachten Sie Echtzeitänderungen in Collections.

```javascript
// Collection-Änderungen beobachten
const changeStream = db.users.watch()
changeStream.on('change', (change) => {
  console.log('Änderung erkannt:', change)
})
// Mit Filter beobachten
const pipeline = [{ $match: { operationType: 'insert' } }]
const changeStream = db.users.watch(pipeline)
```

## Relevante Links

- <router-link to="/database">Datenbank Spickzettel</router-link>
- <router-link to="/mysql">MySQL Spickzettel</router-link>
- <router-link to="/postgresql">PostgreSQL Spickzettel</router-link>
- <router-link to="/redis">Redis Spickzettel</router-link>
- <router-link to="/sqlite">SQLite Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>

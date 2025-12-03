---
title: 'Mémento MongoDB | LabEx'
description: "Apprenez la base de données NoSQL MongoDB avec ce mémento complet. Référence rapide pour les requêtes, l'agrégation, l'indexation, le sharding, la réplication et la gestion de bases de données documentaires MongoDB."
pdfUrl: '/cheatsheets/pdf/mongodb-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche MongoDB
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/mongodb">Apprenez MongoDB avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la gestion de base de données NoSQL MongoDB grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets sur MongoDB couvrant les opérations essentielles, les requêtes de documents, les pipelines d'agrégation, les stratégies d'indexation et les techniques avancées. Maîtrisez le modèle de données basé sur les documents de MongoDB pour construire des applications de base de données évolutives et flexibles.
</base-disclaimer-content>
</base-disclaimer>

## Gestion des Bases de Données et des Collections

### Afficher les Bases de Données : `show dbs`

Affiche toutes les bases de données sur le serveur MongoDB.

```javascript
// Afficher toutes les bases de données
show dbs
// Afficher la base de données actuelle
db
// Obtenir les statistiques de la base de données
db.stats()
// Obtenir l'aide de la base de données
db.help()
```

### Utiliser une Base de Données : `use database_name`

Passe à une base de données spécifique (la crée si elle n'existe pas).

```javascript
// Passer à la base de données myapp
use myapp
// Créer une base de données en insérant des données
use newdb
db.users.insertOne({name: "John"})
```

<BaseQuiz id="mongodb-use-1" correct="B">
  <template #question>
    Que se passe-t-il lorsque vous exécutez `use newdb` dans MongoDB ?
  </template>
  
  <BaseQuizOption value="A">Elle crée immédiatement la base de données</BaseQuizOption>
  <BaseQuizOption value="B" correct>Elle passe à la base de données (la crée lors de la première insertion de données)</BaseQuizOption>
  <BaseQuizOption value="C">Elle supprime la base de données</BaseQuizOption>
  <BaseQuizOption value="D">Elle affiche toutes les collections de la base de données</BaseQuizOption>
  
  <BaseQuizAnswer>
    La commande `use` passe à une base de données, mais MongoDB ne la crée que lorsque vous insérez le premier document. C'est une approche de création paresseuse.
  </BaseQuizAnswer>
</BaseQuiz>

### Supprimer une Base de Données : `db.dropDatabase()`

Supprime la base de données actuelle et toutes ses collections.

```javascript
// Supprimer la base de données actuelle
db.dropDatabase()
// Confirmer avec le nom de la base de données
use myapp
db.dropDatabase()
```

### Afficher les Collections : `show collections`

Liste toutes les collections de la base de données actuelle.

```javascript
// Afficher toutes les collections
show collections
// Méthode alternative
db.runCommand("listCollections")
```

### Créer une Collection : `db.createCollection()`

Crée une nouvelle collection avec une configuration optionnelle.

```javascript
// Créer une collection simple
db.createCollection('users')
// Créer avec des options
db.createCollection('logs', {
  capped: true,
  size: 1000000,
  max: 1000,
})
```

### Supprimer une Collection : `db.collection.drop()`

Supprime une collection et tous ses documents.

```javascript
// Supprimer la collection users
db.users.drop()
// Vérifier si la collection a été supprimée
show collections
```

## Structure et Informations sur les Documents

### Statistiques de Collection : `db.collection.stats()`

Affiche des statistiques complètes sur une collection, y compris la taille, le nombre de documents et les informations sur les index.

```javascript
// Statistiques de la collection
db.users.stats()
// Compter les documents
db.users.countDocuments()
// Compte estimé (plus rapide)
db.users.estimatedDocumentCount()
// Vérifier les index de la collection
db.users.getIndexes()
```

### Documents d'Exemple : `db.collection.findOne()`

Récupère des documents d'exemple pour comprendre la structure et les types de données.

```javascript
// Obtenir un document
db.users.findOne()
// Obtenir un document spécifique
db.users.findOne({ name: 'John' })
// Obtenir un document avec tous les champs affichés
db.users.findOne({}, { _id: 0 })
```

### Explorer les Données : `db.collection.find().limit()`

Parcourir les données de la collection avec pagination et formatage.

```javascript
// Les 5 premiers documents
db.users.find().limit(5)
// Sauter et limiter (pagination)
db.users.find().skip(10).limit(5)
// Format joli
db.users.find().pretty()
```

## Insertion de Documents (Création)

### Insérer Un : `db.collection.insertOne()`

Ajoute un seul document à une collection.

```javascript
// Insérer un seul document
db.users.insertOne({
  name: 'John Doe',
  age: 30,
  email: 'john@example.com',
})
// Insérer avec _id personnalisé
db.users.insertOne({
  _id: 'custom_id_123',
  name: 'Jane Doe',
  status: 'active',
})
```

<BaseQuiz id="mongodb-insert-1" correct="A">
  <template #question>
    Que retourne `db.users.insertOne()` ?
  </template>
  
  <BaseQuizOption value="A" correct>Un objet d'acquittement avec l'_id du document inséré</BaseQuizOption>
  <BaseQuizOption value="B">Le document inséré</BaseQuizOption>
  <BaseQuizOption value="C">Rien</BaseQuizOption>
  <BaseQuizOption value="D">Le nombre de documents insérés</BaseQuizOption>
  
  <BaseQuizAnswer>
    `insertOne()` retourne un objet d'acquittement contenant `acknowledged: true` et `insertedId` avec l'`_id` du document inséré (ou l'`_id` personnalisé s'il est fourni).
  </BaseQuizAnswer>
</BaseQuiz>

### Insérer Plusieurs : `db.collection.insertMany()`

Ajoute plusieurs documents en une seule opération.

```javascript
// Insérer plusieurs documents
db.users.insertMany([
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 35 },
  { name: 'Charlie', age: 28 },
])
// Insérer avec des options
db.users.insertMany(
  [
    { name: 'Dave', age: 40 },
    { name: 'Eve', age: 22 },
  ],
  { ordered: false },
)
```

### Insérer avec Date : `new Date()`

Ajoute des documents avec des champs horodatés.

```javascript
// Insérer avec la date actuelle
db.posts.insertOne({
  title: 'Mon Article de Blog',
  content: "Contenu de l'article ici",
  createdAt: new Date(),
  publishDate: ISODate('2024-01-15'),
})
```

### Insérer des Documents Imbriqués

Ajoute des documents avec des objets et des tableaux intégrés.

```javascript
// Insérer avec des objets imbriqués
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

## Interrogation de Documents (Lecture)

### Recherche de Base : `db.collection.find()`

Récupère les documents en fonction des conditions de requête.

```javascript
// Trouver tous les documents
db.users.find()
// Trouver avec condition
db.users.find({ age: 30 })
// Trouver avec conditions multiples (ET)
db.users.find({ age: 30, status: 'active' })
// Trouver avec condition OU
db.users.find({ $or: [{ age: 25 }, { age: 30 }] })
```

### Projection : `db.collection.find({}, {})`

Contrôle quels champs sont retournés dans les résultats.

```javascript
// Inclure des champs spécifiques
db.users.find({}, { name: 1, age: 1 })
// Exclure des champs spécifiques
db.users.find({}, { password: 0, _id: 0 })
// Projection de champ imbriqué
db.users.find({}, { 'address.city': 1 })
```

### Opérateurs de Requête : `$gt`, `$lt`, `$in`, etc.

Utilise des opérateurs de comparaison et logiques pour des requêtes complexes.

```javascript
// Supérieur à, inférieur à
db.users.find({ age: { $gt: 25, $lt: 40 } })
// Dans un tableau
db.users.find({ status: { $in: ['active', 'pending'] } })
// Différent de
db.users.find({ status: { $ne: 'inactive' } })
// Existe
db.users.find({ email: { $exists: true } })
```

<BaseQuiz id="mongodb-query-1" correct="B">
  <template #question>
    Que signifie `$gt` dans les requêtes MongoDB ?
  </template>
  
  <BaseQuizOption value="A">Supérieur ou égal à</BaseQuizOption>
  <BaseQuizOption value="B" correct>Strictement supérieur à</BaseQuizOption>
  <BaseQuizOption value="C">Grouper par</BaseQuizOption>
  <BaseQuizOption value="D">Obtenir le total</BaseQuizOption>
  
  <BaseQuizAnswer>
    `$gt` est un opérateur de comparaison qui signifie "strictement supérieur à" (Greater Than). Il est utilisé dans des requêtes comme `{ age: { $gt: 25 } }` pour trouver des documents où le champ âge est supérieur à 25.
  </BaseQuizAnswer>
</BaseQuiz>

### Recherche de Texte : `$text`, `$regex`

Recherche des documents en utilisant du texte et la correspondance de motifs.

```javascript
// Recherche de texte (nécessite un index textuel)
db.posts.find({ $text: { $search: 'tutoriel mongodb' } })
// Recherche Regex
db.users.find({ name: { $regex: '^John', $options: 'i' } })
// Recherche insensible à la casse
db.users.find({ email: { $regex: '@gmail.com$' } })
```

## Mises à Jour de Documents

### Mettre à Jour Un : `db.collection.updateOne()`

Modifie le premier document qui correspond à la requête.

```javascript
// Mettre à jour un champ unique
db.users.updateOne({ name: 'John Doe' }, { $set: { age: 31 } })
// Mettre à jour plusieurs champs
db.users.updateOne(
  { _id: ObjectId('...') },
  { $set: { age: 31, status: 'updated' } },
)
// Upsert (insérer si non trouvé)
db.users.updateOne(
  { name: 'New User' },
  { $set: { age: 25 } },
  { upsert: true },
)
```

### Mettre à Jour Plusieurs : `db.collection.updateMany()`

Modifie tous les documents qui correspondent à la condition de requête.

```javascript
// Mettre à jour plusieurs documents
db.users.updateMany({ status: 'inactive' }, { $set: { status: 'archived' } })
// Incrémenter les valeurs
db.posts.updateMany({ category: 'tech' }, { $inc: { views: 1 } })
```

### Opérateurs de Mise à Jour : `$set`, `$unset`, `$push`

Utilise divers opérateurs pour modifier les champs de document.

```javascript
// Définir et supprimer des champs
db.users.updateOne(
  { name: 'John' },
  { $set: { lastLogin: new Date() }, $unset: { temp: '' } },
)
// Ajouter à un tableau
db.users.updateOne({ name: 'John' }, { $push: { hobbies: 'gaming' } })
```

<BaseQuiz id="mongodb-update-1" correct="C">
  <template #question>
    Que fait `$set` dans les opérations de mise à jour MongoDB ?
  </template>
  
  <BaseQuizOption value="A">Supprime un champ</BaseQuizOption>
  <BaseQuizOption value="B">Ajoute un élément à un tableau</BaseQuizOption>
  <BaseQuizOption value="C" correct>Définit la valeur d'un champ</BaseQuizOption>
  <BaseQuizOption value="D">Supprime un élément d'un tableau</BaseQuizOption>
  
  <BaseQuizAnswer>
    L'opérateur `$set` définit la valeur d'un champ dans un document. Si le champ n'existe pas, il le crée. S'il existe, il met à jour la valeur.
  </BaseQuizAnswer>
</BaseQuiz>

```javascript
// Retirer d'un tableau
db.users.updateOne({ name: 'John' }, { $pull: { hobbies: 'reading' } })
```

### Remplacer le Document : `db.collection.replaceOne()`

Remplace un document entier à l'exception du champ \_id.

```javascript
// Remplacer le document entier
db.users.replaceOne(
  { name: 'John Doe' },
  {
    name: 'John Smith',
    age: 35,
    email: 'johnsmith@example.com',
  },
)
```

## Agrégation de Données

### Agrégation de Base : `db.collection.aggregate()`

Traite les données via des étapes de pipeline d'agrégation.

```javascript
// Grouper et compter
db.users.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }])
// Filtrer et grouper
db.orders.aggregate([
  { $match: { status: 'completed' } },
  { $group: { _id: '$customerId', total: { $sum: '$amount' } } },
])
```

### Étapes Courantes : `$match`, `$group`, `$sort`

Utilise des étapes de pipeline pour transformer et analyser les données.

```javascript
// Pipeline d'agrégation complexe
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

### Opérateurs d'Agrégation : `$sum`, `$avg`, `$max`

Calcule des valeurs statistiques et effectue des opérations mathématiques.

```javascript
// Opérations statistiques
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

### Étape de Projection : `$project`

Transforme la structure du document et crée des champs calculés.

```javascript
// Projeter et calculer des champs
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

## Suppression de Documents

### Supprimer Un : `db.collection.deleteOne()`

Supprime le premier document qui correspond à la condition de requête.

```javascript
// Supprimer un seul document
db.users.deleteOne({ name: 'John Doe' })
// Supprimer par ID
db.users.deleteOne({ _id: ObjectId('...') })
// Supprimer avec condition
db.posts.deleteOne({ status: 'draft', author: 'unknown' })
```

### Supprimer Plusieurs : `db.collection.deleteMany()`

Supprime tous les documents qui correspondent à la condition de requête.

```javascript
// Supprimer plusieurs documents
db.users.deleteMany({ status: 'inactive' })
// Supprimer tous les documents (attention !)
db.temp_collection.deleteMany({})
// Supprimer avec condition de date
db.logs.deleteMany({
  createdAt: { $lt: new Date('2024-01-01') },
})
```

### Trouver et Supprimer : `db.collection.findOneAndDelete()`

Trouve un document et le supprime en une seule opération atomique.

```javascript
// Trouver et supprimer
const deletedDoc = db.users.findOneAndDelete({ status: 'pending' })
// Trouver et supprimer avec options
db.queue.findOneAndDelete({ processed: false }, { sort: { priority: -1 } })
```

## Indexation et Performance

### Créer un Index : `db.collection.createIndex()`

Crée des index sur les champs pour accélérer les requêtes.

```javascript
// Index sur un seul champ
db.users.createIndex({ email: 1 })
// Index composé
db.users.createIndex({ status: 1, createdAt: -1 })
// Index textuel pour la recherche
db.posts.createIndex({ title: 'text', content: 'text' })
// Index unique
db.users.createIndex({ email: 1 }, { unique: true })
```

### Gestion des Index : `getIndexes()`, `dropIndex()`

Visualiser et gérer les index existants sur les collections.

```javascript
// Lister tous les index
db.users.getIndexes()
// Supprimer un index spécifique
db.users.dropIndex({ email: 1 })
// Supprimer un index par son nom
db.users.dropIndex('email_1')
// Supprimer tous les index sauf _id
db.users.dropIndexes()
```

### Performance des Requêtes : `explain()`

Analyser l'exécution des requêtes et les statistiques de performance.

```javascript
// Expliquer l'exécution de la requête
db.users.find({ age: { $gt: 25 } }).explain('executionStats')
// Vérifier si un index est utilisé
db.users.find({ email: 'john@example.com' }).explain()
// Analyser la performance de l'agrégation
db.users
  .aggregate([
    { $match: { status: 'active' } },
    { $group: { _id: '$department', count: { $sum: 1 } } },
  ])
  .explain('executionStats')
```

### Conseils de Performance

Meilleures pratiques pour optimiser les requêtes et les opérations MongoDB.

```javascript
// Utiliser la projection pour limiter le transfert de données
db.users.find({ status: 'active' }, { name: 1, email: 1 })
// Limiter les résultats pour de meilleures performances
db.posts.find().sort({ createdAt: -1 }).limit(10)
// Utiliser hint pour forcer un index spécifique
db.users.find({ age: 25 }).hint({ age: 1 })
```

## Shell et Connexion MongoDB

### Se Connecter à MongoDB : `mongosh`

Démarrer le shell MongoDB et se connecter à différentes instances.

```bash
# Se connecter à MongoDB local
mongosh
# Se connecter à un hôte et un port spécifiques
mongosh "mongodb://localhost:27017"
# Se connecter à un serveur distant
mongosh "mongodb://username:password@host:port/database"
# Se connecter avec des options
mongosh --host localhost --port 27017
```

### Aides du Shell : `help`, `exit`

Obtenir des informations d'aide et gérer les sessions du shell.

```javascript
// Aide générale
help
// Aide spécifique à la base de données
db.help()
// Aide spécifique à la collection
db.users.help()
// Quitter le shell
exit
```

### Variables et Paramètres du Shell

Configurer le comportement du shell et utiliser des variables JavaScript.

```javascript
// Définir une variable
var myQuery = { status: 'active' }
db.users.find(myQuery)
// Configurer les options d'affichage
db.users.find().pretty()
// Afficher le temps d'exécution
db.users.find({ age: 25 }).explain('executionStats')
// Utiliser JavaScript dans le shell
var user = db.users.findOne({ name: 'John' })
print("Âge de l'utilisateur : " + user.age)
```

## Importation et Exportation de Données

### Importer des Données : `mongoimport`

Charger des données à partir de fichiers JSON, CSV ou TSV dans MongoDB.

```bash
# Importer un fichier JSON
mongoimport --db myapp --collection users --file users.json
# Importer un fichier CSV
mongoimport --db myapp --collection products \
  --type csv --headerline --file products.csv
# Importer avec upsert
mongoimport --db myapp --collection users \
  --file users.json --mode upsert
```

### Exporter des Données : `mongoexport`

Exporter des données MongoDB au format JSON ou CSV.

```bash
# Exporter en JSON
mongoexport --db myapp --collection users \
  --out users.json
# Exporter en CSV
mongoexport --db myapp --collection users \
  --type csv --fields name,email,age --out users.csv
# Exporter avec requête
mongoexport --db myapp --collection users \
  --query '{"status":"active"}' --out active_users.json
```

### Sauvegarde : `mongodump`

Créer des sauvegardes binaires des bases de données MongoDB.

```bash
# Sauvegarder la base de données entière
mongodump --db myapp --out /backup/
# Sauvegarder une collection spécifique
mongodump --db myapp --collection users --out /backup/
# Sauvegarder avec compression
mongodump --db myapp --gzip --out /backup/
```

### Restauration : `mongorestore`

Restaurer les données MongoDB à partir de sauvegardes binaires.

```bash
# Restaurer la base de données
mongorestore --db myapp /backup/myapp/
# Restaurer avec suppression
mongorestore --db myapp --drop /backup/myapp/
# Restaurer une sauvegarde compressée
mongorestore --gzip --db myapp /backup/myapp/
```

## Installation et Configuration de MongoDB

### Serveur Communautaire MongoDB

Télécharger et installer l'édition Community de MongoDB.

```bash
# Ubuntu/Debian
sudo apt-get install -y mongodb-org
# Démarrer le service MongoDB
sudo systemctl start mongod
# Activer le démarrage automatique
sudo systemctl enable mongod
# Vérifier le statut
sudo systemctl status mongod
```

### Installation Docker

Exécuter MongoDB à l'aide de conteneurs Docker.

```bash
# Tirer l'image MongoDB
docker pull mongo
# Exécuter le conteneur MongoDB
docker run --name mongodb -d \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  mongo
# Se connecter au conteneur
docker exec -it mongodb mongosh
```

### MongoDB Compass (GUI)

Installer et utiliser l'outil GUI officiel de MongoDB.

```bash
# Télécharger depuis mongodb.com
# Se connecter en utilisant la chaîne de connexion
mongodb://localhost:27017
# Fonctionnalités disponibles :
# - Constructeur de requêtes visuel
# - Analyse de schéma
# - Surveillance des performances
# - Gestion des index
```

## Configuration et Sécurité

### Authentification : Créer des Utilisateurs

Configurer des utilisateurs de base de données avec les rôles et permissions appropriés.

```javascript
// Créer un utilisateur admin
use admin
db.createUser({
  user: "admin",
  pwd: "securepassword",
  roles: [{role: "root", db: "admin"}]
})
// Créer un utilisateur de base de données
use myapp
db.createUser({
  user: "appuser",
  pwd: "password123",
  roles: [{role: "readWrite", db: "myapp"}]
})
```

### Activer l'Authentification

Configurer MongoDB pour exiger l'authentification.

```bash
# Modifier /etc/mongod.conf
security:
  authorization: enabled
# Redémarrer MongoDB
sudo systemctl restart mongod
# Se connecter avec authentification
mongosh -u admin -p --authenticationDatabase admin
```

### Ensembles de Répliques : `rs.initiate()`

Configurer des ensembles de répliques pour une haute disponibilité.

```javascript
// Initialiser l'ensemble de répliques
rs.initiate({
  _id: 'myReplicaSet',
  members: [
    { _id: 0, host: 'mongodb1:27017' },
    { _id: 1, host: 'mongodb2:27017' },
    { _id: 2, host: 'mongodb3:27017' },
  ],
})
// Vérifier le statut de l'ensemble de répliques
rs.status()
```

### Options de Configuration

Paramètres de configuration courants de MongoDB.

```yaml
# Exemple mongod.conf
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

## Gestion des Erreurs et Débogage

### Erreurs Courantes et Solutions

Identifier et corriger les problèmes fréquemment rencontrés avec MongoDB.

```javascript
// Erreurs de connexion
// Vérifier si MongoDB est en cours d'exécution
sudo systemctl status mongod
// Vérifier la disponibilité du port
netstat -tuln | grep 27017
// Gestion des erreurs de clé en double
try {
  db.users.insertOne({email: "existing@example.com"})
} catch (e) {
  if (e.code === 11000) {
    print("L'email existe déjà")
  }
}
```

### Surveillance : `db.currentOp()`, `db.serverStatus()`

Surveiller les opérations de base de données et les performances du serveur.

```javascript
// Vérifier les opérations en cours
db.currentOp()
// Tuer une opération longue
db.killOp(operationId)
// Statut du serveur
db.serverStatus()
// Statistiques de connexion
db.runCommand({ connPoolStats: 1 })
```

### Profilage : `db.setProfilingLevel()`

Activer le profilage pour analyser les opérations lentes.

```javascript
// Activer le profilage pour les opérations lentes (>100ms)
db.setProfilingLevel(1, { slowms: 100 })
// Activer le profilage pour toutes les opérations
db.setProfilingLevel(2)
// Voir les données du profileur
db.system.profile.find().sort({ ts: -1 }).limit(5)
// Désactiver le profilage
db.setProfilingLevel(0)
```

## Opérations Avancées

### Transactions : `session.startTransaction()`

Utiliser des transactions multi-documents pour la cohérence des données.

```javascript
// Démarrer la session et la transaction
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

### Flux de Changement : `db.collection.watch()`

Observer les changements en temps réel dans les collections.

```javascript
// Surveiller les changements de la collection
const changeStream = db.users.watch()
changeStream.on('change', (change) => {
  console.log('Changement détecté :', change)
})
// Surveiller avec filtre
const pipeline = [{ $match: { operationType: 'insert' } }]
const changeStream = db.users.watch(pipeline)
```

## Liens Pertinents

- <router-link to="/database">Feuille de triche Base de Données</router-link>
- <router-link to="/mysql">Feuille de triche MySQL</router-link>
- <router-link to="/postgresql">Feuille de triche PostgreSQL</router-link>
- <router-link to="/redis">Feuille de triche Redis</router-link>
- <router-link to="/sqlite">Feuille de triche SQLite</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/docker">Feuille de triche Docker</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>

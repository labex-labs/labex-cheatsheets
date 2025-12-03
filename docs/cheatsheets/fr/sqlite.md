---
title: 'Fiche de Référence SQLite | LabEx'
description: 'Apprenez SQLite avec cette fiche de référence complète. Référence rapide pour la syntaxe SQL SQLite, les transactions, les déclencheurs, les vues et la gestion de bases de données légères pour applications.'
pdfUrl: '/cheatsheets/pdf/sqlite-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche SQLite
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/sqlite">Apprenez SQLite avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la gestion de bases de données SQLite grâce à des laboratoires pratiques et des scénarios du monde réel. LabEx propose des cours complets sur SQLite couvrant les opérations SQL essentielles, la manipulation de données, l'optimisation des requêtes, la conception de bases de données et le réglage des performances. Maîtrisez le développement de bases de données légères et la gestion efficace des données.
</base-disclaimer-content>
</base-disclaimer>

## Création de Base de Données et Connexion

### Créer une Base de Données : `sqlite3 database.db`

Créez un nouveau fichier de base de données SQLite.

```bash
# Créer ou ouvrir une base de données
sqlite3 mydata.db
# Créer une base de données en mémoire (temporaire)
sqlite3 :memory:
# Créer une base de données avec une commande
.open mydata.db
# Afficher toutes les bases de données
.databases
# Afficher le schéma de toutes les tables
.schema
# Afficher la liste des tables
.tables
# Quitter SQLite
.exit
# Commande de sortie alternative
.quit
```

### Informations sur la Base de Données : `.databases`

Liste toutes les bases de données attachées et leurs fichiers.

```sql
-- Attacher une autre base de données
ATTACH DATABASE 'backup.db' AS backup;
-- Interroger la base de données attachée
SELECT * FROM backup.users;
-- Détacher la base de données
DETACH DATABASE backup;
```

### Quitter SQLite : `.exit` ou `.quit`

Fermer l'interface en ligne de commande SQLite.

```bash
.exit
.quit
```

### Sauvegarde de la Base de Données : `.backup`

Créer une sauvegarde de la base de données actuelle.

```bash
# Sauvegarde vers un fichier
.backup backup.db
# Restaurer à partir de la sauvegarde
.restore backup.db
# Exporter vers un fichier SQL
.output backup.sql
.dump
# Importer un script SQL
.read backup.sql
```

## Création de Table et Schéma

### Créer une Table : `CREATE TABLE`

Créer une nouvelle table dans la base de données avec des colonnes et des contraintes.

```sql
-- Création de table de base
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    age INTEGER,
    created_date DATE DEFAULT CURRENT_TIMESTAMP
);

-- Table avec clé étrangère
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    amount REAL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

<BaseQuiz id="sqlite-create-table-1" correct="A">
  <template #question>
    Que fait <code>INTEGER PRIMARY KEY AUTOINCREMENT</code> dans SQLite ?
  </template>
  
  <BaseQuizOption value="A" correct>Crée une clé primaire entière à incrémentation automatique</BaseQuizOption>
  <BaseQuizOption value="B">Crée une clé primaire de type texte</BaseQuizOption>
  <BaseQuizOption value="C">Crée une contrainte de clé étrangère</BaseQuizOption>
  <BaseQuizOption value="D">Crée un index unique</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>INTEGER PRIMARY KEY AUTOINCREMENT</code> crée une colonne entière qui s'incrémente automatiquement pour chaque nouvelle ligne et sert de clé primaire. Cela garantit que chaque ligne possède un identifiant unique.
  </BaseQuizAnswer>
</BaseQuiz>

### Types de Données : `INTEGER`, `TEXT`, `REAL`, `BLOB`

SQLite utilise le typage dynamique avec des classes de stockage pour un stockage de données flexible.

```sql
-- Types de données courants
CREATE TABLE products (
    id INTEGER,           -- Nombres entiers
    name TEXT,           -- Chaînes de caractères
    price REAL,          -- Nombres à virgule flottante
    image BLOB,          -- Données binaires
    active BOOLEAN,      -- Booléen (stocké comme INTEGER)
    created_at DATETIME  -- Date et heure
);
```

### Contraintes : `PRIMARY KEY`, `NOT NULL`, `UNIQUE`

Définir des contraintes pour garantir l'intégrité des données et les relations entre les tables.

```sql
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL,
    salary REAL CHECK(salary > 0),
    manager_id INTEGER REFERENCES employees(id)
);
```

## Insertion et Modification des Données

### Insérer des Données : `INSERT INTO`

Ajouter de nouveaux enregistrements aux tables avec une ou plusieurs lignes.

```sql
-- Insérer un enregistrement unique
INSERT INTO users (name, email, age)
VALUES ('John Doe', 'john@email.com', 30);

-- Insérer plusieurs enregistrements
INSERT INTO users (name, email, age) VALUES
    ('Jane Smith', 'jane@email.com', 25),
    ('Bob Wilson', 'bob@email.com', 35);

-- Insérer avec toutes les colonnes
INSERT INTO users VALUES
    (NULL, 'Alice Brown', 'alice@email.com', 28, datetime('now'));
```

### Mettre à Jour les Données : `UPDATE SET`

Modifier les enregistrements existants en fonction de conditions.

```sql
-- Mettre à jour une seule colonne
UPDATE users SET age = 31 WHERE name = 'John Doe';

-- Mettre à jour plusieurs colonnes
UPDATE users SET
    email = 'newemail@example.com',
    age = age + 1
WHERE id = 1;

-- Mettre à jour avec sous-requête
UPDATE products SET price = price * 1.1
WHERE category = 'Electronics';
```

<BaseQuiz id="sqlite-update-1" correct="D">
  <template #question>
    Que se passe-t-il si vous oubliez la clause WHERE dans une instruction UPDATE ?
  </template>
  
  <BaseQuizOption value="A">La mise à jour échoue</BaseQuizOption>
  <BaseQuizOption value="B">Seule la première ligne est mise à jour</BaseQuizOption>
  <BaseQuizOption value="C">Rien ne se passe</BaseQuizOption>
  <BaseQuizOption value="D" correct>Toutes les lignes de la table sont mises à jour</BaseQuizOption>
  
  <BaseQuizAnswer>
    Sans clause WHERE, l'instruction UPDATE modifiera toutes les lignes de la table. Utilisez toujours WHERE pour spécifier quelles lignes doivent être mises à jour afin d'éviter de modifier accidentellement des données non désirées.
  </BaseQuizAnswer>
</BaseQuiz>

### Supprimer des Données : `DELETE FROM`

Supprimer des enregistrements des tables en fonction des conditions spécifiées.

```sql
-- Supprimer des enregistrements spécifiques
DELETE FROM users WHERE age < 18;

-- Supprimer tous les enregistrements (conserver la structure de la table)
DELETE FROM users;

-- Supprimer avec sous-requête
DELETE FROM orders
WHERE user_id IN (SELECT id FROM users WHERE active = 0);
```

### Upsert : `INSERT OR REPLACE`

Insérer de nouveaux enregistrements ou mettre à jour ceux qui existent en cas de conflit.

```sql
-- Insérer ou remplacer en cas de conflit
INSERT OR REPLACE INTO users (id, name, email)
VALUES (1, 'Updated Name', 'updated@email.com');

-- Insérer ou ignorer les doublons
INSERT OR IGNORE INTO users (name, email)
VALUES ('Duplicate', 'existing@email.com');
```

<BaseQuiz id="sqlite-upsert-1" correct="A">
  <template #question>
    Quelle est la différence entre <code>INSERT OR REPLACE</code> et <code>INSERT OR IGNORE</code> ?
  </template>
  
  <BaseQuizOption value="A" correct>REPLACE met à jour les lignes existantes, IGNORE ignore les doublons</BaseQuizOption>
  <BaseQuizOption value="B">Il n'y a pas de différence</BaseQuizOption>
  <BaseQuizOption value="C">REPLACE supprime la ligne, IGNORE la met à jour</BaseQuizOption>
  <BaseQuizOption value="D">REPLACE fonctionne avec les tables, IGNORE fonctionne avec les vues</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>INSERT OR REPLACE</code> remplacera une ligne existante en cas de conflit (par exemple, clé primaire en double). <code>INSERT OR IGNORE</code> ignorera simplement l'insertion en cas de conflit, laissant la ligne existante inchangée.
  </BaseQuizAnswer>
</BaseQuiz>

## Requêtes et Sélection de Données

### Requêtes de Base : `SELECT`

Interroger des données à partir de tables en utilisant l'instruction SELECT avec diverses options.

```sql
-- Sélectionner toutes les colonnes
SELECT * FROM users;

-- Sélectionner des colonnes spécifiques
SELECT name, email FROM users;

-- Sélectionner avec alias
SELECT name AS full_name, age AS years_old FROM users;

-- Sélectionner des valeurs uniques
SELECT DISTINCT department FROM employees;
```

<BaseQuiz id="sqlite-select-1" correct="B">
  <template #question>
    Que fait <code>SELECT DISTINCT</code> ?
  </template>
  
  <BaseQuizOption value="A">Sélectionne toutes les lignes</BaseQuizOption>
  <BaseQuizOption value="B" correct>Retourne uniquement les valeurs uniques, supprimant les doublons</BaseQuizOption>
  <BaseQuizOption value="C">Sélectionne uniquement la première ligne</BaseQuizOption>
  <BaseQuizOption value="D">Ordonne les résultats</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>SELECT DISTINCT</code> élimine les lignes dupliquées de l'ensemble de résultats, ne retournant que les valeurs uniques. Ceci est utile lorsque vous souhaitez voir toutes les valeurs uniques d'une colonne.
  </BaseQuizAnswer>
</BaseQuiz>

### Filtrage : `WHERE`

Filtrer les lignes en utilisant diverses conditions et opérateurs de comparaison.

```sql
-- Conditions simples
SELECT * FROM users WHERE age > 25;
SELECT * FROM users WHERE name = 'John Doe';

-- Conditions multiples
SELECT * FROM users WHERE age > 18 AND age < 65;
SELECT * FROM users WHERE department = 'IT' OR salary > 50000;

-- Correspondance de motifs
SELECT * FROM users WHERE email LIKE '%@gmail.com';
SELECT * FROM users WHERE name GLOB 'J*';
```

### Tri et Limitation : `ORDER BY` / `LIMIT`

Trier les résultats et limiter le nombre de lignes retournées pour une meilleure gestion des données.

```sql
-- Trier par ordre croissant (par défaut)
SELECT * FROM users ORDER BY age;

-- Trier par ordre décroissant
SELECT * FROM users ORDER BY age DESC;

-- Colonnes de tri multiples
SELECT * FROM users ORDER BY department, salary DESC;

-- Limiter les résultats
SELECT * FROM users LIMIT 10;

-- Limiter avec décalage (pagination)
SELECT * FROM users LIMIT 10 OFFSET 20;
```

### Fonctions d'Agrégation : `COUNT`, `SUM`, `AVG`

Effectuer des calculs sur des groupes de lignes pour l'analyse statistique.

```sql
-- Compter les enregistrements
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT department) FROM employees;

-- Somme et moyenne
SELECT SUM(salary), AVG(salary) FROM employees;

-- Valeurs min et max
SELECT MIN(age), MAX(age) FROM users;
```

## Requêtes Avancées

### Regroupement : `GROUP BY` / `HAVING`

Regrouper les lignes selon des critères spécifiés et filtrer les groupes pour les rapports récapitulatifs.

```sql
-- Grouper par une seule colonne
SELECT department, COUNT(*)
FROM employees
GROUP BY department;

-- Grouper par plusieurs colonnes
SELECT department, job_title, AVG(salary)
FROM employees
GROUP BY department, job_title;

-- Filtrer les groupes avec HAVING
SELECT department, AVG(salary) as avg_salary
FROM employees
GROUP BY department
HAVING avg_salary > 60000;
```

### Sous-requêtes

Utiliser des requêtes imbriquées pour une récupération de données complexe et une logique conditionnelle.

```sql
-- Sous-requête dans la clause WHERE
SELECT name FROM users
WHERE age > (SELECT AVG(age) FROM users);

-- Sous-requête dans la clause FROM
SELECT dept, avg_salary FROM (
    SELECT department as dept, AVG(salary) as avg_salary
    FROM employees
    GROUP BY department
) WHERE avg_salary > 50000;

-- Sous-requête EXISTS
SELECT * FROM users u
WHERE EXISTS (
    SELECT 1 FROM orders o WHERE o.user_id = u.id
);
```

### Jointures : `INNER`, `LEFT`, `RIGHT`

Combiner des données provenant de plusieurs tables en utilisant différents types de jointures pour des requêtes relationnelles.

```sql
-- Jointure interne (Inner join)
SELECT u.name, o.amount
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- Jointure gauche (Left join) (afficher tous les utilisateurs)
SELECT u.name, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- Jointure réflexive (Self join)
SELECT e1.name as employee, e2.name as manager
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id;
```

### Opérations d'Ensemble : `UNION` / `INTERSECT`

Combiner les résultats de plusieurs requêtes à l'aide d'opérations d'ensemble.

```sql
-- Union (combiner les résultats)
SELECT name FROM customers
UNION
SELECT name FROM suppliers;

-- Intersect (résultats communs)
SELECT email FROM users
INTERSECT
SELECT email FROM newsletter_subscribers;

-- Except (différence)
SELECT email FROM users
EXCEPT
SELECT email FROM unsubscribed;
```

## Index et Performances

### Créer des Index : `CREATE INDEX`

Créer des index sur des colonnes pour accélérer les requêtes et améliorer les performances.

```sql
-- Index sur une seule colonne
CREATE INDEX idx_user_email ON users(email);

-- Index multi-colonnes
CREATE INDEX idx_order_user_date ON orders(user_id, order_date);

-- Index unique
CREATE UNIQUE INDEX idx_product_sku ON products(sku);

-- Index partiel (avec condition)
CREATE INDEX idx_active_users ON users(name) WHERE active = 1;
```

### Analyse de Requête : `EXPLAIN QUERY PLAN`

Analyser les plans d'exécution des requêtes pour identifier les goulots d'étranglement de performance.

```sql
-- Analyser la performance de la requête
EXPLAIN QUERY PLAN SELECT * FROM users WHERE email = 'test@example.com';

-- Vérifier si l'index est utilisé
EXPLAIN QUERY PLAN SELECT * FROM orders WHERE user_id = 123;
```

### Optimisation de la Base de Données : `VACUUM` / `ANALYZE`

Optimiser les fichiers de base de données et mettre à jour les statistiques pour de meilleures performances.

```sql
-- Reconstruire la base de données pour récupérer de l'espace
VACUUM;

-- Mettre à jour les statistiques des index
ANALYZE;

-- Vérifier l'intégrité de la base de données
PRAGMA integrity_check;
```

### Paramètres de Performance : `PRAGMA`

Configurer les paramètres SQLite pour des performances et un comportement optimaux.

```sql
-- Définir le mode journal pour de meilleures performances
PRAGMA journal_mode = WAL;

-- Définir le mode synchrone
PRAGMA synchronous = NORMAL;

-- Activer les contraintes de clé étrangère
PRAGMA foreign_keys = ON;

-- Définir la taille du cache (en pages)
PRAGMA cache_size = 10000;
```

## Vues et Déclencheurs

### Vues : `CREATE VIEW`

Créer des tables virtuelles qui représentent des requêtes stockées pour un accès aux données réutilisable.

```sql
-- Créer une vue simple
CREATE VIEW active_users AS
SELECT id, name, email
FROM users
WHERE active = 1;

-- Vue complexe avec jointures
CREATE VIEW order_summary AS
SELECT
    u.name,
    COUNT(o.id) as total_orders,
    SUM(o.amount) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- Interroger une vue
SELECT * FROM active_users WHERE name LIKE 'J%';

-- Supprimer une vue
DROP VIEW IF EXISTS order_summary;
```

### Utilisation des Vues

Interroger les vues comme des tables régulières pour simplifier l'accès aux données.

```sql
SELECT * FROM active_users;
SELECT * FROM order_summary WHERE total_spent > 1000;
```

### Déclencheurs : `CREATE TRIGGER`

Exécuter automatiquement du code en réponse à des événements de base de données.

```sql
-- Déclencheur sur INSERT
CREATE TRIGGER update_user_count
AFTER INSERT ON users
BEGIN
    UPDATE stats SET user_count = user_count + 1;
END;

-- Déclencheur sur UPDATE
CREATE TRIGGER log_salary_changes
AFTER UPDATE OF salary ON employees
BEGIN
    INSERT INTO audit_log (table_name, action, old_value, new_value)
    VALUES ('employees', 'salary_update', OLD.salary, NEW.salary);
END;

-- Supprimer un déclencheur
DROP TRIGGER IF EXISTS update_user_count;
```

## Types de Données et Fonctions

### Fonctions de Date et Heure

Gérer les opérations de date et d'heure avec les fonctions intégrées de SQLite.

```sql
-- Date/heure actuelles
SELECT datetime('now');
SELECT date('now');
SELECT time('now');

-- Arithmétique des dates
SELECT date('now', '+1 day');
SELECT datetime('now', '-1 hour');
SELECT date('now', 'start of month');

-- Formater les dates
SELECT strftime('%Y-%m-%d %H:%M', 'now');
SELECT strftime('%w', 'now'); -- jour de la semaine
```

### Fonctions de Chaîne

Manipuler des données textuelles avec diverses opérations sur les chaînes.

```sql
-- Manipulation de chaînes
SELECT upper(name) FROM users;
SELECT lower(email) FROM users;
SELECT length(name) FROM users;
SELECT substr(name, 1, 3) FROM users;

-- Concaténation de chaînes
SELECT name || ' - ' || email as display FROM users;
SELECT printf('%s (%d)', name, age) FROM users;

-- Remplacement de chaîne
SELECT replace(phone, '-', '') FROM users;
```

### Fonctions Numériques

Effectuer des opérations mathématiques et des calculs.

```sql
-- Fonctions mathématiques
SELECT abs(-15);
SELECT round(price, 2) FROM products;
SELECT random(); -- nombre aléatoire

-- Agrégation avec mathématiques
SELECT department, round(AVG(salary), 2) as avg_salary
FROM employees
GROUP BY department;
```

### Logique Conditionnelle : `CASE`

Implémenter une logique conditionnelle dans les requêtes SQL.

```sql
-- Instruction CASE simple
SELECT name,
    CASE
        WHEN age < 18 THEN 'Minor'
        WHEN age < 65 THEN 'Adult'
        ELSE 'Senior'
    END as age_category
FROM users;

-- CASE dans la clause WHERE
SELECT * FROM products
WHERE CASE WHEN category = 'Electronics' THEN price < 1000
          ELSE price < 100 END;
```

## Transactions et Concurrence

### Contrôle des Transactions

Les transactions SQLite sont entièrement conformes ACID pour des opérations de données fiables.

```sql
-- Transaction de base
BEGIN TRANSACTION;
INSERT INTO users (name, email) VALUES ('Test User', 'test@example.com');
UPDATE users SET age = 25 WHERE name = 'Test User';
COMMIT;

-- Transaction avec annulation (rollback)
BEGIN;
DELETE FROM orders WHERE amount < 10;
-- Vérifier les résultats, annuler si nécessaire
ROLLBACK;

-- Points de sauvegarde pour les transactions imbriquées
BEGIN;
SAVEPOINT sp1;
INSERT INTO products (name) VALUES ('Product A');
ROLLBACK TO sp1;
COMMIT;
```

### Verrouillage et Concurrence

Gérer les verrous de base de données et l'accès concurrent pour l'intégrité des données.

```sql
-- Vérifier l'état du verrouillage
PRAGMA locking_mode;

-- Définir le mode WAL pour une meilleure concurrence
PRAGMA journal_mode = WAL;

-- Délai d'attente en cas d'occupation pour les verrous
PRAGMA busy_timeout = 5000;

-- Vérifier les connexions de base de données actuelles
.databases
```

## Outils en Ligne de Commande SQLite

### Commandes de Base de Données : `.help`

Accéder à l'aide et à la documentation de l'interface en ligne de commande SQLite pour les commandes point disponibles.

```bash
# Afficher toutes les commandes disponibles
.help
# Afficher les paramètres actuels
.show
# Définir le format de sortie
.mode csv
.headers on
```

### Importation/Exportation : `.import` / `.export`

Transférer des données entre SQLite et des fichiers externes dans divers formats.

```bash
# Importer un fichier CSV
.mode csv
.import data.csv users

# Exporter vers CSV
.headers on
.mode csv
.output users.csv
SELECT * FROM users;
```

### Gestion du Schéma : `.schema` / `.tables`

Examiner la structure de la base de données et les définitions de table pour le développement et le débogage.

```bash
# Afficher toutes les tables
.tables
# Afficher le schéma pour une table spécifique
.schema users
# Afficher tous les schémas
.schema
# Afficher les informations de la table
.mode column
.headers on
PRAGMA table_info(users);
```

### Formatage de la Sortie : `.mode`

Contrôler la manière dont les résultats des requêtes sont affichés dans l'interface en ligne de commande.

```bash
# Différents modes de sortie
.mode csv        # Valeurs séparées par des virgules
.mode column     # Colonnes alignées
.mode html       # Format de table HTML
.mode json       # Format JSON
.mode list       # Format liste
.mode table      # Format tableau (par défaut)

# Définir la largeur des colonnes
.width 10 15 20

# Enregistrer la sortie dans un fichier
.output results.txt
SELECT * FROM users;
.output stdout

# Lire le SQL à partir d'un fichier
.read script.sql

# Changer de fichier de base de données
.open another_database.db
```

## Configuration et Paramètres

### Paramètres de Base de Données : `PRAGMA`

Contrôler le comportement de SQLite via des instructions pragma pour l'optimisation et la configuration.

```sql
-- Informations sur la base de données
PRAGMA database_list;
PRAGMA table_info(users);
PRAGMA foreign_key_list(orders);

-- Paramètres de performance
PRAGMA cache_size = 10000;
PRAGMA temp_store = memory;
PRAGMA mmap_size = 268435456;

-- Activer les contraintes de clé étrangère
PRAGMA foreign_keys = ON;

-- Définir le mode de suppression sécurisée
PRAGMA secure_delete = ON;

-- Vérifier les contraintes
PRAGMA foreign_key_check;
```

### Paramètres de Sécurité

Configurer les options et contraintes liées à la sécurité de la base de données.

```sql
-- Activer les contraintes de clé étrangère
PRAGMA foreign_keys = ON;

-- Mode de suppression sécurisée
PRAGMA secure_delete = ON;

-- Vérifier l'intégrité
PRAGMA integrity_check;
```

## Installation et Configuration

### Téléchargement et Installation

Télécharger les outils SQLite et configurer l'interface en ligne de commande pour votre système d'exploitation.

```bash
# Télécharger depuis sqlite.org
# Pour Windows : sqlite-tools-win32-x86-*.zip
# Pour Linux/Mac : Utiliser le gestionnaire de paquets

# Ubuntu/Debian
sudo apt-get install sqlite3

# macOS avec Homebrew
brew install sqlite

# Vérifier l'installation
sqlite3 --version
```

### Créer Votre Première Base de Données

Créer des fichiers de base de données SQLite et commencer à travailler avec des données en utilisant des commandes simples.

```bash
# Créer une nouvelle base de données
sqlite3 myapp.db

# Créer une table et ajouter des données
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE
);

INSERT INTO users (name, email)
VALUES ('John Doe', 'john@example.com');
```

### Intégration des Langages de Programmation

Utiliser SQLite avec divers langages de programmation via des bibliothèques intégrées ou tierces.

```python
# Python (module sqlite3 intégré)
import sqlite3
conn = sqlite3.connect('mydb.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users')
```

```javascript
// Node.js (nécessite le paquet sqlite3)
const sqlite3 = require('sqlite3')
const db = new sqlite3.Database('mydb.db')
db.all('SELECT * FROM users', (err, rows) => {
  console.log(rows)
})
```

```php
// PHP (PDO SQLite intégré)
$pdo = new PDO('sqlite:mydb.db');
$stmt = $pdo->query('SELECT * FROM users');
```

## Liens Pertinents

- <router-link to="/database">Feuille de triche Base de Données</router-link>
- <router-link to="/mysql">Feuille de triche MySQL</router-link>
- <router-link to="/postgresql">Feuille de triche PostgreSQL</router-link>
- <router-link to="/mongodb">Feuille de triche MongoDB</router-link>
- <router-link to="/redis">Feuille de triche Redis</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>

---
title: 'Fiche de Référence MySQL | LabEx'
description: "Maîtrisez la gestion des bases de données MySQL avec cette fiche complète. Référence rapide pour les requêtes SQL, les jointures, les index, les transactions, les procédures stockées et l'administration de bases de données."
pdfUrl: '/cheatsheets/pdf/mysql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche MySQL
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/mysql">Apprenez MySQL avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la gestion de bases de données MySQL grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours MySQL complets couvrant les opérations SQL essentielles, l'administration de bases de données, l'optimisation des performances et les techniques de requête avancées. Maîtrisez l'un des systèmes de gestion de bases de données relationnelles les plus populaires au monde.
</base-disclaimer-content>
</base-disclaimer>

## Connexion et Gestion de Base de Données

### Se connecter au Serveur : `mysql -u username -p`

Se connecter au serveur MySQL via la ligne de commande.

```bash
# Se connecter avec le nom d'utilisateur et l'invite de mot de passe
mysql -u root -p
# Se connecter à une base de données spécifique
mysql -u username -p nom_base_de_donnees
# Se connecter à un serveur distant
mysql -h hostname -u username -p
# Se connecter avec spécification de port
mysql -h hostname -P 3306 -u username -p nom_base_de_donnees
```

### Opérations sur les Bases de Données : `CREATE` / `DROP` / `USE`

Gérer les bases de données sur le serveur.

```sql
# Créer une nouvelle base de données
CREATE DATABASE company_db;
# Lister toutes les bases de données
SHOW DATABASES;
# Sélectionner une base de données à utiliser
USE company_db;
# Supprimer une base de données (suppression permanente)
DROP DATABASE old_database;
```

<BaseQuiz id="mysql-database-1" correct="C">
  <template #question>
    Que fait <code>USE nom_base_de_donnees</code> ?
  </template>
  
  <BaseQuizOption value="A">Crée une nouvelle base de données</BaseQuizOption>
  <BaseQuizOption value="B">Supprime la base de données</BaseQuizOption>
  <BaseQuizOption value="C" correct>Sélectionne la base de données pour les opérations suivantes</BaseQuizOption>
  <BaseQuizOption value="D">Affiche toutes les tables de la base de données</BaseQuizOption>
  
  <BaseQuizAnswer>
    L'instruction <code>USE</code> sélectionne une base de données, la rendant active pour toutes les instructions SQL suivantes. Ceci est équivalent à sélectionner une base de données lors de la connexion avec <code>mysql -u user -p database_name</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### Exporter des Données : `mysqldump`

Sauvegarder les données de la base de données dans un fichier SQL.

```bash
# Exporter la base de données entière
mysqldump -u username -p nom_base_de_donnees > backup.sql
# Exporter une table spécifique
mysqldump -u username -p nom_base_de_donnees nom_table > table_backup.sql
# Exporter avec structure seule
mysqldump -u username -p --no-data nom_base_de_donnees > structure.sql
# Sauvegarde complète de la base de données avec routines et déclencheurs
mysqldump -u username -p --routines --triggers nom_base_de_donnees > backup.sql
```

### Importer des Données : `mysql < file.sql`

Importer un fichier SQL dans une base de données MySQL.

```bash
# Importer un fichier SQL dans une base de données
mysql -u username -p nom_base_de_donnees < backup.sql
# Importer sans spécifier de base de données (si inclus dans le fichier)
mysql -u username -p < full_backup.sql
```

### Gestion des Utilisateurs : `CREATE USER` / `GRANT`

Gérer les utilisateurs et les permissions de la base de données.

```sql
# Créer un nouvel utilisateur
CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
# Accorder tous les privilèges
GRANT ALL PRIVILEGES ON nom_base_de_donnees.* TO 'user'@'localhost';
# Accorder des privilèges spécifiques
GRANT SELECT, INSERT, UPDATE ON nom_table TO 'user'@'localhost';
# Appliquer les changements de privilèges
FLUSH PRIVILEGES;
```

### Afficher les Informations du Serveur : `SHOW STATUS` / `SHOW VARIABLES`

Afficher la configuration et l'état du serveur.

```sql
# Afficher l'état du serveur
SHOW STATUS;
# Afficher les variables de configuration
SHOW VARIABLES;
# Afficher les processus en cours
SHOW PROCESSLIST;
```

## Structure et Schéma des Tables

### Création de Table : `CREATE TABLE`

Créer de nouvelles tables avec des colonnes et des types de données spécifiés.

```sql
# Créer une table avec divers types de données
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    age INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# Créer une table avec clé étrangère
CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Informations sur la Table : `DESCRIBE` / `SHOW`

Visualiser la structure de la table et le contenu de la base de données.

```sql
# Afficher la structure de la table
DESCRIBE users;
# Syntaxe alternative
SHOW COLUMNS FROM users;
# Lister toutes les tables
SHOW TABLES;
# Afficher l'instruction CREATE pour la table
SHOW CREATE TABLE users;
```

### Modifier les Tables : `ALTER TABLE`

Modifier la structure existante de la table, ajouter ou supprimer des colonnes.

```sql
# Ajouter une nouvelle colonne
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
# Supprimer une colonne
ALTER TABLE users DROP COLUMN age;
# Modifier le type de colonne
ALTER TABLE users MODIFY COLUMN username VARCHAR(100);
# Renommer une colonne
ALTER TABLE users CHANGE old_name new_name VARCHAR(50);
```

## Manipulation et Opérations CRUD de Données

### Insérer des Données : `INSERT INTO`

Ajouter de nouveaux enregistrements dans les tables.

```sql
# Insérer un seul enregistrement
INSERT INTO users (username, email, age)
VALUES ('john_doe', 'john@email.com', 25);
# Insérer plusieurs enregistrements
INSERT INTO users (username, email, age) VALUES
('alice', 'alice@email.com', 30),
('bob', 'bob@email.com', 28);
# Insérer à partir d'une autre table
INSERT INTO users_backup SELECT * FROM users;
```

<BaseQuiz id="mysql-insert-1" correct="A">
  <template #question>
    Quelle est la syntaxe correcte pour insérer un seul enregistrement ?
  </template>
  
  <BaseQuizOption value="A" correct><code>INSERT INTO table_name (column1, column2) VALUES (value1, value2);</code></BaseQuizOption>
  <BaseQuizOption value="B"><code>INSERT table_name VALUES (value1, value2);</code></BaseQuizOption>
  <BaseQuizOption value="C"><code>ADD INTO table_name (column1, column2) VALUES (value1, value2);</code></BaseQuizOption>
  <BaseQuizOption value="D"><code>INSERT table_name (column1, column2) = (value1, value2);</code></BaseQuizOption>
  
  <BaseQuizAnswer>
    La syntaxe correcte est <code>INSERT INTO nom_table (colonnes) VALUES (valeurs)</code>. Le mot-clé <code>INTO</code> est requis, et vous devez spécifier à la fois les noms des colonnes et les valeurs correspondantes.
  </BaseQuizAnswer>
</BaseQuiz>

### Mettre à Jour les Données : `UPDATE`

Modifier les enregistrements existants dans les tables.

```sql
# Mettre à jour un enregistrement spécifique
UPDATE users SET age = 26 WHERE username = 'john_doe';
# Mettre à jour plusieurs colonnes
UPDATE users SET age = 31, email = 'alice_new@email.com'
WHERE username = 'alice';
# Mettre à jour avec calcul
UPDATE products SET price = price * 1.1 WHERE category = 'electronics';
```

### Supprimer des Données : `DELETE` / `TRUNCATE`

Supprimer des enregistrements des tables.

```sql
# Supprimer des enregistrements spécifiques
DELETE FROM users WHERE age < 18;
# Supprimer tous les enregistrements (conserver la structure)
DELETE FROM users;
# Supprimer tous les enregistrements (plus rapide, réinitialise AUTO_INCREMENT)
TRUNCATE TABLE users;
# Supprimer avec JOIN
DELETE u FROM users u
JOIN inactive_accounts i ON u.id = i.user_id;
```

### Remplacer des Données : `REPLACE` / `INSERT ... ON DUPLICATE KEY`

Gérer les situations de clé dupliquée lors des insertions.

```sql
# Remplacer l'existant ou insérer un nouveau
REPLACE INTO users (id, username, email)
VALUES (1, 'updated_user', 'new@email.com');
# Insérer ou mettre à jour en cas de clé dupliquée
INSERT INTO users (username, email)
VALUES ('john', 'john@email.com')
ON DUPLICATE KEY UPDATE email = VALUES(email);
```

## Interrogation et Sélection des Données

### SELECT de Base : `SELECT * FROM`

Récupérer des données des tables avec diverses conditions.

```sql
# Sélectionner toutes les colonnes
SELECT * FROM users;
# Sélectionner des colonnes spécifiques
SELECT username, email FROM users;
# Sélectionner avec condition WHERE
SELECT * FROM users WHERE age > 25;
# Sélectionner avec conditions multiples
SELECT * FROM users WHERE age > 20 AND email LIKE '%gmail.com';
```

<BaseQuiz id="mysql-select-1" correct="D">
  <template #question>
    Que retourne <code>SELECT * FROM users</code> ?
  </template>
  
  <BaseQuizOption value="A">Seule la première ligne de la table users</BaseQuizOption>
  <BaseQuizOption value="B">Seule la colonne username</BaseQuizOption>
  <BaseQuizOption value="C">La structure de la table</BaseQuizOption>
  <BaseQuizOption value="D" correct>Toutes les colonnes et toutes les lignes de la table users</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le joker <code>*</code> sélectionne toutes les colonnes, et sans clause WHERE, il retourne toutes les lignes. Ceci est utile pour visualiser toutes les données mais doit être utilisé avec prudence sur de grandes tables.
  </BaseQuizAnswer>
</BaseQuiz>

### Tri et Limitation : `ORDER BY` / `LIMIT`

Contrôler l'ordre et le nombre de résultats retournés.

```sql
# Trier les résultats
SELECT * FROM users ORDER BY age DESC;
# Trier par plusieurs colonnes
SELECT * FROM users ORDER BY age DESC, username ASC;
# Limiter les résultats
SELECT * FROM users LIMIT 10;
# Pagination (sauter les 10 premiers, prendre les 10 suivants)
SELECT * FROM users LIMIT 10 OFFSET 10;
```

### Filtrage : `WHERE` / `LIKE` / `IN`

Filtrer les données en utilisant divers opérateurs de comparaison.

```sql
# Correspondance de motif
SELECT * FROM users WHERE username LIKE 'john%';
# Valeurs multiples
SELECT * FROM users WHERE age IN (25, 30, 35);
# Filtrage par plage
SELECT * FROM users WHERE age BETWEEN 20 AND 30;
# Vérifications NULL
SELECT * FROM users WHERE email IS NOT NULL;
```

### Regroupement : `GROUP BY` / `HAVING`

Regrouper les données et appliquer des fonctions d'agrégation.

```sql
# Grouper par colonne
SELECT age, COUNT(*) FROM users GROUP BY age;
# Grouper avec condition sur les groupes
SELECT age, COUNT(*) as count FROM users
GROUP BY age HAVING count > 1;
# Colonnes de regroupement multiples
SELECT age, gender, COUNT(*) FROM users
GROUP BY age, gender;
```

## Interrogation Avancée

### Opérations JOIN : `INNER` / `LEFT` / `RIGHT`

Combiner des données provenant de plusieurs tables.

```sql
# Jointure interne (enregistrements correspondants uniquement)
SELECT u.username, o.order_date
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# Jointure gauche (tous les utilisateurs, commandes correspondantes)
SELECT u.username, o.order_date
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# Jointures multiples
SELECT u.username, o.order_date, p.product_name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

<BaseQuiz id="mysql-join-1" correct="B">
  <template #question>
    Quelle est la différence entre INNER JOIN et LEFT JOIN ?
  </template>
  
  <BaseQuizOption value="A">Il n'y a pas de différence</BaseQuizOption>
  <BaseQuizOption value="B" correct>INNER JOIN retourne uniquement les lignes correspondantes, LEFT JOIN retourne toutes les lignes de la table de gauche</BaseQuizOption>
  <BaseQuizOption value="C">INNER JOIN est plus rapide</BaseQuizOption>
  <BaseQuizOption value="D">LEFT JOIN ne fonctionne qu'avec deux tables</BaseQuizOption>
  
  <BaseQuizAnswer>
    INNER JOIN retourne uniquement les lignes où il y a une correspondance dans les deux tables. LEFT JOIN retourne toutes les lignes de la table de gauche et les lignes correspondantes de la table de droite, avec des valeurs NULL pour les lignes non correspondantes de la table de droite.
  </BaseQuizAnswer>
</BaseQuiz>

### Sous-requêtes : `SELECT` dans `SELECT`

Utiliser des requêtes imbriquées pour une récupération de données complexe.

```sql
# Sous-requête dans la clause WHERE
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders WHERE total > 100);
# Sous-requête corrélée
SELECT username FROM users u1
WHERE age > (SELECT AVG(age) FROM users u2);
# Sous-requête dans SELECT
SELECT username,
(SELECT COUNT(*) FROM orders WHERE user_id = users.id) as order_count
FROM users;
```

### Fonctions d'Agrégation : `COUNT` / `SUM` / `AVG`

Calculer des statistiques et des résumés à partir des données.

```sql
# Agrégats de base
SELECT COUNT(*) FROM users;
SELECT AVG(age), MIN(age), MAX(age) FROM users;
SELECT SUM(total) FROM orders;
# Agrégat avec regroupement
SELECT department, AVG(salary)
FROM employees GROUP BY department;
# Agrégats multiples
SELECT
    COUNT(*) as total_users,
    AVG(age) as avg_age,
    MAX(created_at) as latest_signup
FROM users;
```

### Fonctions de Fenêtre : `OVER` / `PARTITION BY`

Effectuer des calculs sur des ensembles de lignes de table.

```sql
# Fonctions de classement
SELECT username, age,
RANK() OVER (ORDER BY age DESC) as age_rank
FROM users;
# Partition par groupe
SELECT username, department, salary,
AVG(salary) OVER (PARTITION BY department) as dept_avg
FROM employees;
# Totaux courants
SELECT order_date, total,
SUM(total) OVER (ORDER BY order_date) as running_total
FROM orders;
```

## Index et Performances

### Créer des Index : `CREATE INDEX`

Améliorer les performances des requêtes avec des index de base de données.

```sql
# Créer un index régulier
CREATE INDEX idx_username ON users(username);
# Créer un index composite
CREATE INDEX idx_user_age ON users(username, age);
# Créer un index unique
CREATE UNIQUE INDEX idx_email ON users(email);
# Afficher les index sur la table
SHOW INDEXES FROM users;
```

### Analyse des Requêtes : `EXPLAIN`

Analyser les plans d'exécution des requêtes et les performances.

```sql
# Afficher le plan d'exécution de la requête
EXPLAIN SELECT * FROM users WHERE age > 25;
# Analyse détaillée
EXPLAIN FORMAT=JSON SELECT u.*, o.total
FROM users u JOIN orders o ON u.id = o.user_id;
# Afficher les performances de la requête
SHOW PROFILES;
SET profiling = 1;
```

### Optimiser les Requêtes : Bonnes Pratiques

Techniques pour écrire des requêtes SQL efficaces.

```sql
# Utiliser des colonnes spécifiques au lieu de *
SELECT username, email FROM users WHERE id = 1;
# Utiliser LIMIT pour les grands ensembles de données
SELECT * FROM logs ORDER BY created_at DESC LIMIT 1000;
# Utiliser des conditions WHERE appropriées
SELECT * FROM orders WHERE user_id = 123 AND status = 'pending';
-- Utiliser des index couvrant si possible
```

### Maintenance des Tables : `OPTIMIZE` / `ANALYZE`

Maintenir les performances et les statistiques des tables.

```sql
# Optimiser le stockage de la table
OPTIMIZE TABLE users;
# Mettre à jour les statistiques de la table
ANALYZE TABLE users;
# Vérifier l'intégrité de la table
CHECK TABLE users;
# Réparer la table si nécessaire
REPAIR TABLE users;
```

## Importation/Exportation de Données

### Charger des Données : `LOAD DATA INFILE`

Importer des données à partir de fichiers CSV et texte.

```sql
# Charger un fichier CSV
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
# Charger avec des colonnes spécifiques
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users (username, email, age);
```

### Exporter des Données : `SELECT INTO OUTFILE`

Exporter les résultats des requêtes vers des fichiers.

```sql
# Exporter vers un fichier CSV
SELECT username, email, age
FROM users
INTO OUTFILE '/path/to/export.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

### Sauvegarde et Restauration : `mysqldump` / `mysql`

Créer et restaurer des sauvegardes de bases de données.

```bash
# Sauvegarder des tables spécifiques
mysqldump -u username -p nom_base_de_donnees table1 table2 > tables_backup.sql
# Restaurer à partir d'une sauvegarde
mysql -u username -p nom_base_de_donnees < backup.sql
# Exporter depuis un serveur distant
mysqldump -h remote_host -u username -p nom_base_de_donnees > remote_backup.sql
# Importer vers une base de données locale
mysql -u local_user -p local_database < remote_backup.sql
# Copie directe de données entre serveurs
mysqldump -h source_host -u user -p db_name | mysql -h dest_host -u user -p db_name
```

## Types de Données et Fonctions

### Types de Données Courants : Nombres, Texte, Dates

Choisir les types de données appropriés pour vos colonnes.

```sql
# Types numériques
INT, BIGINT, DECIMAL(10,2), FLOAT, DOUBLE
# Types chaîne
VARCHAR(255), TEXT, CHAR(10), MEDIUMTEXT, LONGTEXT
# Types date et heure
DATE, TIME, DATETIME, TIMESTAMP, YEAR
# Booléen et binaire
BOOLEAN, BLOB, VARBINARY

# Création de table exemple
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Fonctions de Chaîne : `CONCAT` / `SUBSTRING` / `LENGTH`

Manipuler des données textuelles avec des fonctions de chaîne intégrées.

```sql
# Concaténation de chaînes
SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users;
# Opérations sur les chaînes
SELECT SUBSTRING(email, 1, LOCATE('@', email)-1) as username FROM users;
SELECT LENGTH(username), UPPER(username) FROM users;
# Correspondance de motif et remplacement
SELECT REPLACE(phone, '-', '.') FROM users WHERE phone LIKE '___-___-____';
```

### Fonctions de Date : `NOW()` / `DATE_ADD` / `DATEDIFF`

Travailler efficacement avec les dates et les heures.

```sql
# Date et heure actuelles
SELECT NOW(), CURDATE(), CURTIME();
# Arithmétique de date
SELECT DATE_ADD(created_at, INTERVAL 30 DAY) as expiry_date FROM users;
SELECT DATEDIFF(NOW(), created_at) as days_since_signup FROM users;
# Formatage de date
SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') as formatted_date FROM orders;
```

### Fonctions Numériques : `ROUND` / `ABS` / `RAND`

Effectuer des opérations mathématiques sur des données numériques.

```sql
# Fonctions mathématiques
SELECT ROUND(price, 2), ABS(profit_loss), SQRT(area) FROM products;
# Aléatoire et statistique
SELECT RAND(), FLOOR(price), CEIL(rating) FROM products;
# Mathématiques d'agrégation
SELECT AVG(price), STDDEV(price), VARIANCE(price) FROM products;
```

## Gestion des Transactions

### Contrôle des Transactions : `BEGIN` / `COMMIT` / `ROLLBACK`

Gérer les transactions de base de données pour la cohérence des données.

```sql
# Démarrer la transaction
BEGIN;
# ou
START TRANSACTION;
# Effectuer des opérations
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;
# Valider les changements
COMMIT;
# Ou annuler en cas d'erreur
ROLLBACK;
```

### Niveau d'Isolation des Transactions : `SET TRANSACTION ISOLATION`

Contrôler la manière dont les transactions interagissent les unes avec les autres.

```sql
# Définir le niveau d'isolation
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
# Afficher le niveau d'isolation actuel
SELECT @@transaction_isolation;
```

### Verrouillage : `LOCK TABLES` / `SELECT FOR UPDATE`

Contrôler l'accès concurrent aux données.

```sql
# Verrouiller les tables pour un accès exclusif
LOCK TABLES users WRITE, orders READ;
# Effectuer des opérations
# ...
UNLOCK TABLES;
# Verrouillage au niveau des lignes dans les transactions
BEGIN;
SELECT * FROM accounts WHERE id = 1 FOR UPDATE;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
COMMIT;
```

### Points de Sauvegarde : `SAVEPOINT` / `ROLLBACK TO`

Créer des points de retour arrière au sein des transactions.

```sql
BEGIN;
INSERT INTO users (username) VALUES ('user1');
SAVEPOINT sp1;
INSERT INTO users (username) VALUES ('user2');
SAVEPOINT sp2;
INSERT INTO users (username) VALUES ('user3');
# Retour arrière au point de sauvegarde
ROLLBACK TO sp1;
COMMIT;
```

## Techniques SQL Avancées

### Expressions de Table Communes (CTE) : `WITH`

Créer des ensembles de résultats temporaires pour des requêtes complexes.

```sql
# CTE simple
WITH user_orders AS (
    SELECT user_id, COUNT(*) as order_count,
           SUM(total) as total_spent
    FROM orders
    GROUP BY user_id
)
SELECT u.username, uo.order_count, uo.total_spent
FROM users u
JOIN user_orders uo ON u.id = uo.user_id
WHERE uo.total_spent > 1000;
```

### Procédures Stockées : `CREATE PROCEDURE`

Créer des procédures de base de données réutilisables.

```sql
# Créer une procédure stockée
DELIMITER //
CREATE PROCEDURE GetUserOrders(IN user_id INT)
BEGIN
    SELECT o.*, p.product_name
    FROM orders o
    JOIN products p ON o.product_id = p.id
    WHERE o.user_id = user_id;
END //
DELIMITER ;
# Appeler la procédure
CALL GetUserOrders(123);
```

### Triggers : `CREATE TRIGGER`

Exécuter automatiquement du code en réponse à des événements de base de données.

```sql
# Créer un déclencheur pour la journalisation des mises à jour d'utilisateur
CREATE TRIGGER user_update_audit
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    INSERT INTO user_audit (user_id, old_email, new_email, changed_at)
    VALUES (NEW.id, OLD.email, NEW.email, NOW());
END;
# Afficher les déclencheurs
SHOW TRIGGERS;
```

### Vues : `CREATE VIEW`

Créer des tables virtuelles basées sur les résultats de requêtes.

```sql
# Créer une vue
CREATE VIEW active_users AS
SELECT id, username, email, created_at
FROM users
WHERE status = 'active' AND last_login > DATE_SUB(NOW(), INTERVAL 30 DAY);
# Utiliser la vue comme une table
SELECT * FROM active_users WHERE username LIKE 'john%';
# Supprimer la vue
DROP VIEW active_users;
```

## Installation et Configuration MySQL

### Installation : Gestionnaires de Paquets

Installer MySQL à l'aide des gestionnaires de paquets du système.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# CentOS/RHEL
sudo yum install mysql-server
# macOS avec Homebrew
brew install mysql
# Démarrer le service MySQL
sudo systemctl start mysql
```

### Docker : `docker run mysql`

Exécuter MySQL dans des conteneurs Docker pour le développement.

```bash
# Exécuter le conteneur MySQL
docker run --name mysql-dev -e MYSQL_ROOT_PASSWORD=password -p 3306:3306 -d mysql:8.0
# Se connecter au MySQL conteneurisé
docker exec -it mysql-dev mysql -u root -p
# Créer une base de données dans le conteneur
docker exec -it mysql-dev mysql -u root -p -e "CREATE DATABASE testdb;"
```

### Configuration Initiale et Sécurité

Sécuriser votre installation MySQL et vérifier la configuration.

```bash
# Exécuter le script de sécurité
sudo mysql_secure_installation
# Se connecter à MySQL
mysql -u root -p
# Afficher la version de MySQL
SELECT VERSION();
# Vérifier l'état de la connexion
STATUS;
# Définir le mot de passe root
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
```

## Configuration et Paramètres

### Fichiers de Configuration : `my.cnf`

Modifier les paramètres de configuration du serveur MySQL.

```ini
# Emplacements de configuration courants
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

### Configuration à l'Exécution : `SET GLOBAL`

Modifier les paramètres pendant que MySQL est en cours d'exécution.

```sql
# Définir les variables globales
SET GLOBAL max_connections = 500;
SET GLOBAL slow_query_log = ON;
# Afficher les paramètres actuels
SHOW VARIABLES LIKE 'max_connections';
SHOW GLOBAL STATUS LIKE 'Slow_queries';
```

### Optimisation des Performances : Mémoire et Cache

Optimiser les paramètres de performance de MySQL.

```sql
# Afficher l'utilisation de la mémoire
SHOW VARIABLES LIKE '%buffer_pool_size%';
SHOW VARIABLES LIKE '%query_cache%';
# Surveiller les performances
SHOW STATUS LIKE 'Qcache%';
SHOW STATUS LIKE 'Created_tmp%';
# Paramètres InnoDB
SET GLOBAL innodb_buffer_pool_size = 2147483648; -- 2GB
```

### Configuration des Journaux : Journaux d'Erreur et de Requête

Configurer la journalisation MySQL pour la surveillance et le débogage.

```sql
# Activer la journalisation des requêtes
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/query.log';
# Journal des requêtes lentes
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
# Afficher les paramètres de journalisation
SHOW VARIABLES LIKE '%log%';
```

## Liens Pertinents

- <router-link to="/database">Feuille de triche Base de Données</router-link>
- <router-link to="/postgresql">Feuille de triche PostgreSQL</router-link>
- <router-link to="/sqlite">Feuille de triche SQLite</router-link>
- <router-link to="/mongodb">Feuille de triche MongoDB</router-link>
- <router-link to="/redis">Feuille de triche Redis</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>

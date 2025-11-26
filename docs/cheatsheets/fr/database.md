---
title: 'Fiche Mémo Base de Données'
description: 'Apprenez les bases de données avec notre fiche mémo complète couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/database-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche sur les bases de données
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/database">Apprenez la gestion de bases de données avec des laboratoires pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la gestion de bases de données et SQL grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets sur les bases de données couvrant les commandes SQL essentielles, la manipulation de données, l'optimisation des requêtes, la conception de bases de données et l'administration. Maîtrisez les bases de données relationnelles, les systèmes NoSQL et les meilleures pratiques de sécurité des bases de données.
</base-disclaimer-content>
</base-disclaimer>

## Création et Gestion de Bases de Données

### Créer une Base de Données : `CREATE DATABASE`

Créez une nouvelle base de données pour stocker vos données.

```sql
-- Créer une nouvelle base de données
CREATE DATABASE company_db;
-- Créer une base de données avec jeu de caractères
CREATE DATABASE company_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
-- Utiliser la base de données
USE company_db;
```

### Afficher les Bases de Données : `SHOW DATABASES`

Liste de toutes les bases de données disponibles sur le serveur.

```sql
-- Lister toutes les bases de données
SHOW DATABASES;
-- Afficher les informations sur la base de données
SELECT SCHEMA_NAME FROM
INFORMATION_SCHEMA.SCHEMATA;
-- Afficher la base de données actuelle
SELECT DATABASE();
```

### Supprimer une Base de Données : `DROP DATABASE`

Supprimez définitivement une base de données entière.

```sql
-- Supprimer la base de données (attention !)
DROP DATABASE old_company_db;
-- Supprimer la base de données si elle existe
DROP DATABASE IF EXISTS old_company_db;
```

### Sauvegarder une Base de Données : `mysqldump`

Créez des copies de sauvegarde de votre base de données.

```sql
-- Sauvegarde en ligne de commande
mysqldump -u username -p database_name > backup.sql
-- Restaurer à partir de la sauvegarde
mysql -u username -p database_name < backup.sql
```

### Utilisateurs de Base de Données : `CREATE USER`

Gérez les comptes utilisateurs de la base de données et les autorisations.

```sql
-- Créer un nouvel utilisateur
CREATE USER 'newuser'@'localhost' IDENTIFIED BY
'password';
-- Accorder des privilèges
GRANT SELECT, INSERT ON company_db.* TO
'newuser'@'localhost';
-- Afficher les privilèges de l'utilisateur
SHOW GRANTS FOR 'newuser'@'localhost';
```

### Informations sur la Base de Données : `INFORMATION_SCHEMA`

Interrogez les métadonnées et les informations de structure de la base de données.

```sql
-- Afficher toutes les tables
SELECT TABLE_NAME FROM
INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'company_db';
-- Afficher les colonnes de la table
DESCRIBE employees;
```

## Structure et Informations sur les Tables

### Créer une Table : `CREATE TABLE`

Définissez de nouvelles tables avec des colonnes et des types de données.

```sql
-- Création de table de base
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY
KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE,
    salary DECIMAL(10,2),
    hire_date DATE,
    department VARCHAR(50)
);
-- Afficher la structure de la table
DESCRIBE employees;
SHOW COLUMNS FROM employees;
```

### Modifier une Table : `ALTER TABLE`

Modifiez la structure et les colonnes des tables existantes.

```sql
-- Ajouter une nouvelle colonne
ALTER TABLE employees ADD
COLUMN phone VARCHAR(15);
-- Modifier le type de colonne
ALTER TABLE employees MODIFY
COLUMN salary DECIMAL(12,2);
-- Supprimer une colonne
ALTER TABLE employees DROP
COLUMN phone;
-- Renommer la table
RENAME TABLE employees TO staff;
```

### Informations sur la Table : `SHOW`

Obtenez des informations détaillées sur les tables et leurs propriétés.

```sql
-- Afficher toutes les tables
SHOW TABLES;
-- Afficher la structure de la table
SHOW CREATE TABLE employees;
-- Afficher le statut de la table
SHOW TABLE STATUS LIKE
'employees';
-- Compter les lignes dans la table
SELECT COUNT(*) FROM employees;
```

## Manipulation de Données et Opérations CRUD

### Insérer des Données : `INSERT INTO`

Ajoutez de nouveaux enregistrements à vos tables.

```sql
-- Insérer un seul enregistrement
INSERT INTO employees (name, email, salary, hire_date,
department)
VALUES ('John Doe', 'john@company.com', 75000.00,
'2024-01-15', 'Engineering');
-- Insérer plusieurs enregistrements
INSERT INTO employees (name, email, salary,
department) VALUES
('Jane Smith', 'jane@company.com', 80000.00,
'Marketing'),
('Bob Johnson', 'bob@company.com', 65000.00, 'Sales');
-- Insérer à partir d'une autre table
INSERT INTO backup_employees
SELECT * FROM employees WHERE department =
'Engineering';
```

### Mettre à Jour les Données : `UPDATE`

Modifiez les enregistrements existants dans les tables.

```sql
-- Mettre à jour un seul enregistrement
UPDATE employees
SET salary = 85000.00, department = 'Senior Engineering'
WHERE id = 1;
-- Mettre à jour plusieurs enregistrements
UPDATE employees
SET salary = salary * 1.05
WHERE hire_date < '2024-01-01';
-- Mettre à jour avec JOIN
UPDATE employees e
JOIN departments d ON e.department = d.name
SET e.salary = e.salary + d.bonus;
```

### Supprimer des Données : `DELETE FROM`

Supprimez des enregistrements des tables.

```sql
-- Supprimer des enregistrements spécifiques
DELETE FROM employees
WHERE department = 'Temporary';
-- Supprimer avec des conditions
DELETE FROM employees
WHERE hire_date < '2020-01-01' AND salary < 50000;
-- Tronquer la table (plus rapide pour tous les enregistrements)
TRUNCATE TABLE temp_employees;
```

### Remplacer des Données : `REPLACE INTO`

Insérez ou mettez à jour des enregistrements en fonction de la clé primaire.

```sql
-- Remplacer l'enregistrement (insérer ou mettre à jour)
REPLACE INTO employees (id, name, email, salary)
VALUES (1, 'John Doe Updated',
'john.new@company.com', 90000);
-- En cas de clé en double, mettre à jour
INSERT INTO employees (id, name, salary)
VALUES (1, 'John Doe', 85000)
ON DUPLICATE KEY UPDATE salary = VALUES(salary);
```

## Requêtes et Sélection de Données

### SELECT de Base : `SELECT`

Récupérez des données à partir des tables de la base de données.

```sql
-- Sélectionner toutes les colonnes
SELECT * FROM employees;
-- Sélectionner des colonnes spécifiques
SELECT name, email, salary FROM employees;
-- Sélectionner avec alias
SELECT name AS employee_name, salary AS
annual_salary
FROM employees;
-- Sélectionner des valeurs distinctes
SELECT DISTINCT department FROM employees;
```

### Filtrage des Données : `WHERE`

Appliquez des conditions pour filtrer les résultats des requêtes.

```sql
-- Conditions de base
SELECT * FROM employees WHERE salary > 70000;
-- Conditions multiples
SELECT * FROM employees
WHERE department = 'Engineering' AND salary > 75000;
-- Correspondance de modèle
SELECT * FROM employees WHERE name LIKE 'John%';
-- Requêtes de plage
SELECT * FROM employees
WHERE hire_date BETWEEN '2023-01-01' AND '2023-12-
31';
```

### Tri des Données : `ORDER BY`

Triez les résultats de la requête en ordre croissant ou décroissant.

```sql
-- Trier par colonne unique
SELECT * FROM employees ORDER BY salary DESC;
-- Trier par colonnes multiples
SELECT * FROM employees
ORDER BY department ASC, salary DESC;
-- Trier avec LIMIT
SELECT * FROM employees
ORDER BY hire_date DESC LIMIT 10;
```

### Limiter les Résultats : `LIMIT`

Contrôlez le nombre d'enregistrements retournés.

```sql
-- Limiter le nombre de résultats
SELECT * FROM employees LIMIT 5;
-- Pagination avec OFFSET
SELECT * FROM employees
ORDER BY id LIMIT 10 OFFSET 20;
-- Top N résultats
SELECT * FROM employees
ORDER BY salary DESC LIMIT 5;
```

## Requêtes Avancées

### Fonctions d'Agrégation : `COUNT`, `SUM`, `AVG`

Effectuez des calculs sur des groupes de données.

```sql
-- Compter les enregistrements
SELECT COUNT(*) FROM employees;
-- Somme et moyenne
SELECT SUM(salary) as total_payroll, AVG(salary) as
avg_salary
FROM employees;
-- Statistiques de groupe
SELECT department, COUNT(*) as employee_count,
AVG(salary) as avg_salary
FROM employees GROUP BY department;
-- Clause HAVING pour le filtrage de groupe
SELECT department, COUNT(*) as count
FROM employees
GROUP BY department
HAVING COUNT(*) > 5;
```

### Sous-requêtes : Requêtes Imbriquées

Utilisez des requêtes dans d'autres requêtes pour des opérations complexes.

```sql
-- Sous-requête dans la clause WHERE
SELECT * FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);
-- Sous-requête avec IN
SELECT * FROM employees
WHERE department IN (
    SELECT name FROM departments WHERE budget >
100000
);
-- Sous-requête corrélée
SELECT * FROM employees e1
WHERE salary > (
    SELECT AVG(salary) FROM employees e2
    WHERE e2.department = e1.department
);
```

### Jointures de Tables : `JOIN`

Combinez des données provenant de plusieurs tables.

```sql
-- Jointure interne (Inner join)
SELECT e.name, e.salary, d.department_name
FROM employees e
INNER JOIN departments d ON e.department = d.id;
-- Jointure gauche (Left join)
SELECT e.name, d.department_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id;
-- Jointures multiples
SELECT e.name, d.department_name, p.project_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id
LEFT JOIN projects p ON e.id = p.employee_id;
```

### Fonctions de Fenêtre : Analyses Avancées

Effectuez des calculs sur des lignes connexes.

```sql
-- Numérotation des lignes
SELECT name, salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
FROM employees;
-- Totaux courants
SELECT name, salary,
    SUM(salary) OVER (ORDER BY hire_date) as
running_total
FROM employees;
-- Partition par groupes
SELECT name, department, salary,
    AVG(salary) OVER (PARTITION BY department) as
dept_avg
FROM employees;
```

## Contraintes et Intégrité de la Base de Données

### Clés Primaires : `PRIMARY KEY`

Assurez une identification unique pour chaque enregistrement.

```sql
-- Clé primaire sur colonne unique
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100)
);
-- Clé primaire composite
CREATE TABLE order_items (
    order_id INT,
    product_id INT,
    quantity INT,
    PRIMARY KEY (order_id, product_id)
);
```

### Clés Étrangères : `FOREIGN KEY`

Maintenez l'intégrité référentielle entre les tables.

```sql
-- Ajouter une contrainte de clé étrangère
CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);
-- Ajouter une clé étrangère à une table existante
ALTER TABLE employees
ADD CONSTRAINT fk_department
FOREIGN KEY (department_id) REFERENCES
departments(id);
```

### Contraintes d'Unicité : `UNIQUE`

Empêchez les valeurs dupliquées dans les colonnes.

```sql
-- Contrainte d'unicité sur colonne unique
ALTER TABLE employees
ADD CONSTRAINT unique_email UNIQUE (email);
-- Contrainte d'unicité composite
ALTER TABLE employees
ADD CONSTRAINT unique_name_dept UNIQUE (name,
department);
```

### Contraintes de Vérification : `CHECK`

Appliquez des règles métier et la validation des données.

```sql
-- Contrainte de vérification simple
ALTER TABLE employees
ADD CONSTRAINT check_salary CHECK (salary > 0);
-- Contrainte de vérification complexe
ALTER TABLE employees
ADD CONSTRAINT check_age
CHECK (YEAR(CURDATE()) - YEAR(birth_date) >= 18);
```

## Performance et Optimisation des Bases de Données

### Index : `CREATE INDEX`

Accélérez la récupération des données grâce aux index de base de données.

```sql
-- Créer un index sur une colonne unique
CREATE INDEX idx_employee_name ON
employees(name);
-- Index composite
CREATE INDEX idx_dept_salary ON
employees(department, salary);
-- Index unique
CREATE UNIQUE INDEX idx_employee_email ON
employees(email);
-- Afficher les index de la table
SHOW INDEX FROM employees;
```

### Optimisation des Requêtes : `EXPLAIN`

Analysez et optimisez les performances des requêtes.

```sql
-- Analyser le plan d'exécution de la requête
EXPLAIN SELECT * FROM employees WHERE salary >
75000;
-- Analyse détaillée
EXPLAIN ANALYZE SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department = d.id;
```

### Surveillance des Performances

Surveillez l'activité et identifiez les goulots d'étranglement des performances de la base de données.

```sql
-- Afficher les processus en cours d'exécution
SHOW PROCESSLIST;
-- Afficher le statut de la base de données
SHOW STATUS LIKE 'Slow_queries';
-- Informations sur le cache de requêtes
SHOW STATUS LIKE 'Qcache%';
```

### Maintenance de la Base de Données

Tâches de maintenance régulières pour des performances optimales.

```sql
-- Optimisation de la table
OPTIMIZE TABLE employees;
-- Analyser les statistiques de la table
ANALYZE TABLE employees;
-- Vérifier l'intégrité de la table
CHECK TABLE employees;
-- Réparer la table si nécessaire
REPAIR TABLE employees;
```

## Importation/Exportation de Données

### Importer des Données : `LOAD DATA`

Importez des données à partir de fichiers externes dans les tables de la base de données.

```sql
-- Importer à partir d'un fichier CSV
LOAD DATA INFILE 'employees.csv'
INTO TABLE employees
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
-- Importer avec mappage de colonnes
LOAD DATA INFILE 'data.csv'
INTO TABLE employees (name, email, salary);
```

### Exporter des Données : `SELECT INTO`

Exportez les résultats des requêtes vers des fichiers externes.

```sql
-- Exporter vers un fichier CSV
SELECT name, email, salary
INTO OUTFILE 'employee_export.csv'
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
FROM employees;
-- Exporter avec mysqldump
mysqldump -u username -p --tab=/path/to/export
database_name table_name
```

### Migration de Données : Entre Bases de Données

Déplacez des données entre différents systèmes de bases de données.

```sql
-- Créer une table à partir d'une structure existante
CREATE TABLE employees_backup LIKE employees;
-- Copier les données entre les tables
INSERT INTO employees_backup SELECT * FROM
employees;
-- Migrer avec des conditions
INSERT INTO new_employees
SELECT * FROM old_employees WHERE active = 1;
```

### Opérations en Masse

Gérez les opérations de données à grande échelle efficacement.

```sql
-- Insertion en masse avec INSERT IGNORE
INSERT IGNORE INTO employees (name, email) VALUES
('John Doe', 'john@email.com'),
('Jane Smith', 'jane@email.com');
-- Mises à jour par lots
UPDATE employees SET salary = salary * 1.1 WHERE
department = 'Sales';
```

## Sécurité et Contrôle d'Accès des Bases de Données

### Gestion des Utilisateurs : `CREATE USER`

Créez et gérez les comptes utilisateurs de la base de données.

```sql
-- Créer un utilisateur avec mot de passe
CREATE USER 'app_user'@'localhost' IDENTIFIED BY
'secure_password';
-- Créer un utilisateur pour un hôte spécifique
CREATE USER 'remote_user'@'192.168.1.%' IDENTIFIED
BY 'password';
-- Supprimer un utilisateur
DROP USER 'old_user'@'localhost';
```

### Autorisations : `GRANT` & `REVOKE`

Contrôlez l'accès aux objets et aux opérations de la base de données.

```sql
-- Accorder des privilèges spécifiques
GRANT SELECT, INSERT ON company_db.employees TO
'app_user'@'localhost';
-- Accorder tous les privilèges
GRANT ALL PRIVILEGES ON company_db.* TO
'admin_user'@'localhost';
-- Révoquer des privilèges
REVOKE INSERT ON company_db.employees FROM
'app_user'@'localhost';
-- Afficher les autorisations de l'utilisateur
SHOW GRANTS FOR 'app_user'@'localhost';
```

### Rôles de Base de Données

Organisez les autorisations à l'aide de rôles de base de données.

```sql
-- Créer un rôle (MySQL 8.0+)
CREATE ROLE 'app_read_role', 'app_write_role';
-- Accorder des privilèges au rôle
GRANT SELECT ON company_db.* TO 'app_read_role';
GRANT INSERT, UPDATE, DELETE ON company_db.* TO
'app_write_role';
-- Assigner un rôle à un utilisateur
GRANT 'app_read_role' TO 'readonly_user'@'localhost';
```

### Prévention des Injections SQL

Protégez-vous contre les vulnérabilités de sécurité courantes.

```sql
-- Utiliser des instructions préparées (niveau application)
-- Mauvais : SELECT * FROM users WHERE id = ' + userInput
-- Bon : Utiliser des requêtes paramétrées
-- Valider les types de données d'entrée
-- Utiliser des procédures stockées si possible
-- Appliquer le principe du moindre privilège
```

## Installation et Configuration de la Base de Données

### Installation de MySQL

Base de données relationnelle open-source populaire.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# Démarrer le service MySQL
sudo systemctl start mysql
sudo systemctl enable mysql
# Installation sécurisée
sudo mysql_secure_installation
```

### Installation de PostgreSQL

Base de données relationnelle open-source avancée.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql
postgresql-contrib
# Passer à l'utilisateur postgres
sudo -u postgres psql
# Créer une base de données et un utilisateur
CREATE DATABASE myapp;
CREATE USER myuser WITH
PASSWORD 'mypassword';
```

### Configuration de SQLite

Base de données légère basée sur des fichiers.

```bash
# Installer SQLite
sudo apt install sqlite3
# Créer un fichier de base de données
sqlite3 mydatabase.db
# Commandes SQLite de base
.help
.tables
.schema tablename
.quit
```

## Configuration et Optimisation de la Base de Données

### Configuration de MySQL

Paramètres de configuration clés de MySQL.

```sql
-- Fichier de configuration my.cnf
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
-- Afficher les paramètres actuels
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW STATUS LIKE 'Connections';
```

### Gestion des Connexions

Gérez les connexions à la base de données et le pooling.

```sql
-- Afficher les connexions actuelles
SHOW PROCESSLIST;
-- Tuer une connexion spécifique
KILL CONNECTION 123;
-- Paramètres de délai d'attente de connexion
SET SESSION wait_timeout = 600;
SET SESSION interactive_timeout = 600;
```

### Configuration des Sauvegardes

Configurez des sauvegardes automatisées de la base de données.

```sql
-- Script de sauvegarde automatisé
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mysqldump -u backup_user -p mydatabase >
backup_$DATE.sql
# Planification avec cron
0 2 * * * /path/to/backup_script.sh
```

### Surveillance et Journalisation

Surveillez l'activité et les performances de la base de données.

```sql
-- Configuration de la récupération à un instant T
SET GLOBAL log_bin = ON;
-- Activer le journal des requêtes lentes
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
-- Afficher la taille de la base de données
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

## Bonnes Pratiques SQL

### Bonnes Pratiques d'Écriture de Requêtes

Écrivez des requêtes SQL propres, efficaces et lisibles.

```sql
-- Utiliser des alias de table significatifs
SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.dept_id = d.id;
-- Spécifier les noms de colonnes au lieu de SELECT *
SELECT name, email, salary FROM employees;
-- Utiliser des types de données appropriés
CREATE TABLE products (
    id INT PRIMARY KEY,
    price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP
);
```

### Conseils d'Optimisation des Performances

Optimisez les requêtes pour de meilleures performances de base de données.

```sql
-- Utiliser des index sur les colonnes fréquemment interrogées
CREATE INDEX idx_employee_dept ON
employees(department);
-- Limiter les ensembles de résultats lorsque cela est possible
SELECT name FROM employees WHERE active = 1 LIMIT
100;
-- Utiliser EXISTS au lieu de IN pour les sous-requêtes
SELECT * FROM customers c
WHERE EXISTS (SELECT 1 FROM orders o WHERE
o.customer_id = c.id);
```

## Liens Pertinents

- <router-link to="/mysql">Feuille de triche MySQL</router-link>
- <router-link to="/postgresql">Feuille de triche PostgreSQL</router-link>
- <router-link to="/sqlite">Feuille de triche SQLite</router-link>
- <router-link to="/mongodb">Feuille de triche MongoDB</router-link>
- <router-link to="/redis">Feuille de triche Redis</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>

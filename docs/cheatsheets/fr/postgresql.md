---
title: 'Fiche Mémo PostgreSQL | LabEx'
description: "Maîtrisez la gestion de base de données PostgreSQL avec cette fiche mémo complète. Référence rapide pour les requêtes SQL, les fonctionnalités avancées, le support JSON, la recherche plein texte et l'administration de bases de données d'entreprise."
pdfUrl: '/cheatsheets/pdf/postgresql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche PostgreSQL
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/postgresql">Apprenez PostgreSQL avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la gestion de bases de données PostgreSQL grâce à des laboratoires pratiques et des scénarios du monde réel. LabEx propose des cours PostgreSQL complets couvrant les opérations SQL essentielles, les requêtes avancées, l'optimisation des performances, l'administration des bases de données et la sécurité. Maîtrisez le développement et l'administration de bases de données relationnelles de niveau entreprise.
</base-disclaimer-content>
</base-disclaimer>

## Connexion & Configuration de la Base de Données

### Se Connecter à PostgreSQL : `psql`

Se connecter à une base de données PostgreSQL locale ou distante à l'aide de l'outil en ligne de commande psql.

```bash
# Se connecter à la base de données locale
psql -U nom_utilisateur -d nom_base_de_donnees
# Se connecter à la base de données distante
psql -h nom_hote -p 5432 -U nom_utilisateur -d nom_base_de_donnees
# Se connecter avec invite de mot de passe
psql -U postgres -W
# Se connecter en utilisant une chaîne de connexion
psql "host=localhost port=5432 dbname=mdb monutilisateur"
```

### Créer une Base de Données : `CREATE DATABASE`

Créer une nouvelle base de données dans PostgreSQL en utilisant la commande CREATE DATABASE.

```sql
# Créer une nouvelle base de données
CREATE DATABASE ma_base_de_donnees;
# Créer une base de données avec un propriétaire
CREATE DATABASE ma_base_de_donnees OWNER monutilisateur;
# Créer une base de données avec encodage
CREATE DATABASE ma_base_de_donnees
  WITH ENCODING 'UTF8'
  LC_COLLATE='fr_FR.UTF-8'
  LC_CTYPE='fr_FR.UTF-8';
```

### Lister les Bases de Données : `\l`

Lister toutes les bases de données dans le serveur PostgreSQL.

```bash
# Lister toutes les bases de données
\l
# Lister les bases de données avec des informations détaillées
\l+
# Se connecter à une base de données différente
\c nom_base_de_donnees
```

### Commandes psql de Base

Commandes essentielles du terminal psql pour la navigation et l'information.

```bash
# Quitter psql
\q
# Obtenir de l'aide pour les commandes SQL
\help CREATE TABLE
# Obtenir de l'aide pour les commandes psql
\?
# Afficher la base de données et l'utilisateur actuels
\conninfo
# Exécuter des commandes système
\! ls
# Lister toutes les tables
\dt
# Lister toutes les tables avec détails
\dt+
# Décrire une table spécifique
\d nom_table
# Lister tous les schémas
\dn
# Lister tous les utilisateurs/rôles
\du
```

### Version & Paramètres

Vérifier la version de PostgreSQL et les paramètres de configuration.

```sql
# Vérifier la version de PostgreSQL
SELECT version();
# Afficher tous les paramètres
SHOW ALL;
# Afficher un paramètre spécifique
SHOW max_connections;
# Définir un paramètre de configuration
SET work_mem = '256MB';
```

## Création et Gestion des Tables

### Créer une Table : `CREATE TABLE`

Définir de nouvelles tables avec des colonnes, des types de données et des contraintes.

```sql
# Création de table de base
CREATE TABLE utilisateurs (
    id SERIAL PRIMARY KEY,
    nom_utilisateur VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    cree_le TIMESTAMP DEFAULT NOW()
);

# Table avec clé étrangère
CREATE TABLE commandes (
    id SERIAL PRIMARY KEY,
    utilisateur_id INTEGER REFERENCES utilisateurs(id),
    total DECIMAL(10,2) NOT NULL,
    statut VARCHAR(20) DEFAULT 'en_attente'
);
```

<BaseQuiz id="postgresql-create-table-1" correct="A">
  <template #question>
    Que fait <code>SERIAL PRIMARY KEY</code> dans PostgreSQL ?
  </template>
  
  <BaseQuizOption value="A" correct>Crée une colonne entière auto-incrémentée qui sert de clé primaire</BaseQuizOption>
  <BaseQuizOption value="B">Crée une colonne de texte</BaseQuizOption>
  <BaseQuizOption value="C">Crée une contrainte de clé étrangère</BaseQuizOption>
  <BaseQuizOption value="D">Crée un index unique</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>SERIAL</code> est un type de données spécifique à PostgreSQL qui crée un entier auto-incrémenté. Combiné avec <code>PRIMARY KEY</code>, il crée un identifiant unique pour chaque ligne qui s'incrémente automatiquement.
  </BaseQuizAnswer>
</BaseQuiz>

### Modifier les Tables : `ALTER TABLE`

Ajouter, modifier ou supprimer des colonnes et des contraintes de tables existantes.

```sql
# Ajouter une nouvelle colonne
ALTER TABLE utilisateurs ADD COLUMN telephone VARCHAR(15);
# Changer le type de colonne
ALTER TABLE utilisateurs ALTER COLUMN telephone TYPE VARCHAR(20);
# Supprimer une colonne
ALTER TABLE utilisateurs DROP COLUMN telephone;
# Ajouter une contrainte
ALTER TABLE utilisateurs ADD CONSTRAINT email_unique
    UNIQUE (email);
```

### Supprimer et Tronquer : `DROP/TRUNCATE`

Supprimer des tables ou vider toutes les données des tables.

```sql
# Supprimer complètement la table
DROP TABLE IF EXISTS ancienne_table;
# Supprimer toutes les données mais conserver la structure
TRUNCATE TABLE utilisateurs;
# Tronquer avec réinitialisation de l'identité
TRUNCATE TABLE utilisateurs RESTART IDENTITY;
```

### Types de Données & Contraintes

Types de données PostgreSQL essentiels pour différents types de données.

```sql
# Types numériques
INTEGER, BIGINT, SMALLINT
DECIMAL(10,2), NUMERIC(10,2)
REAL, DOUBLE PRECISION

# Types de caractères
CHAR(n), VARCHAR(n), TEXT

# Types Date/Heure
DATE, TIME, TIMESTAMP
TIMESTAMPTZ (avec fuseau horaire)

# Booléen et autres
BOOLEAN
JSON, JSONB
UUID
ARRAY (ex: INTEGER[])

# Clé primaire
id SERIAL PRIMARY KEY

# Clé étrangère
utilisateur_id INTEGER REFERENCES utilisateurs(id)

# Contrainte unique
email VARCHAR(100) UNIQUE

# Contrainte CHECK
age INTEGER CHECK (age >= 0)

# Not null
nom VARCHAR(50) NOT NULL
```

### Index : `CREATE INDEX`

Améliorer les performances des requêtes avec des index de base de données.

```sql
# Index de base
CREATE INDEX idx_nom_utilisateur ON utilisateurs(nom_utilisateur);
# Index unique
CREATE UNIQUE INDEX idx_email_unique
    ON utilisateurs(email);
# Index composite
CREATE INDEX idx_utilisateur_date
    ON commandes(utilisateur_id, cree_le);
# Index partiel
CREATE INDEX idx_utilisateurs_actifs
    ON utilisateurs(nom_utilisateur) WHERE actif = true;
# Supprimer l'index
DROP INDEX IF EXISTS idx_nom_utilisateur;
```

<BaseQuiz id="postgresql-index-1" correct="A">
  <template #question>
    Quel est l'objectif principal de la création d'un index dans PostgreSQL ?
  </template>
  
  <BaseQuizOption value="A" correct>Améliorer les performances des requêtes en accélérant la récupération des données</BaseQuizOption>
  <BaseQuizOption value="B">Réduire la taille de la base de données</BaseQuizOption>
  <BaseQuizOption value="C">Chiffrer les données</BaseQuizOption>
  <BaseQuizOption value="D">Empêcher les entrées dupliquées</BaseQuizOption>
  
  <BaseQuizAnswer>
    Les index créent une structure de données qui permet à la base de données de trouver rapidement les lignes sans avoir à parcourir toute la table. Cela accélère considérablement les requêtes SELECT, en particulier sur les grandes tables.
  </BaseQuizAnswer>
</BaseQuiz>

### Séquences : `CREATE SEQUENCE`

Générer automatiquement des valeurs numériques uniques.

```sql
# Créer une séquence
CREATE SEQUENCE seq_id_utilisateur;
# Utiliser la séquence dans la table
CREATE TABLE utilisateurs (
    id INTEGER DEFAULT nextval('seq_id_utilisateur'),
    nom_utilisateur VARCHAR(50)
);
# Réinitialiser la séquence
ALTER SEQUENCE seq_id_utilisateur RESTART WITH 1000;
```

## Opérations CRUD

### Insérer des Données : `INSERT`

Ajouter de nouveaux enregistrements aux tables de la base de données.

```sql
# Insérer un seul enregistrement
INSERT INTO utilisateurs (nom_utilisateur, email)
VALUES ('jean_doe', 'jean@exemple.com');
# Insérer plusieurs enregistrements
INSERT INTO utilisateurs (nom_utilisateur, email) VALUES
    ('alice', 'alice@exemple.com'),
    ('bob', 'bob@exemple.com');
# Insérer avec retour
INSERT INTO utilisateurs (nom_utilisateur, email)
VALUES ('jane', 'jane@exemple.com')
RETURNING id, cree_le;
# Insérer à partir d'une sélection
INSERT INTO utilisateurs_archives
SELECT * FROM utilisateurs WHERE actif = false;
```

<BaseQuiz id="postgresql-insert-1" correct="C">
  <template #question>
    Que fait <code>RETURNING</code> dans une instruction INSERT de PostgreSQL ?
  </template>
  
  <BaseQuizOption value="A">Il annule l'insertion</BaseQuizOption>
  <BaseQuizOption value="B">Il empêche l'insertion</BaseQuizOption>
  <BaseQuizOption value="C" correct>Il renvoie les données de la ligne insérée</BaseQuizOption>
  <BaseQuizOption value="D">Il met à jour les lignes existantes</BaseQuizOption>
  
  <BaseQuizAnswer>
    La clause <code>RETURNING</code> dans PostgreSQL vous permet de récupérer les données de la ligne insérée (ou des colonnes spécifiques) immédiatement après l'insertion, ce qui est utile pour obtenir des identifiants ou des horodatages générés automatiquement.
  </BaseQuizAnswer>
</BaseQuiz>

### Mettre à Jour les Données : `UPDATE`

Modifier les enregistrements existants dans les tables de la base de données.

```sql
# Mettre à jour des enregistrements spécifiques
UPDATE utilisateurs
SET email = 'nouvelleadresse@exemple.com'
WHERE nom_utilisateur = 'jean_doe';
# Mettre à jour plusieurs colonnes
UPDATE utilisateurs
SET email = 'nouveau@exemple.com',
    mis_a_jour_le = NOW()
WHERE id = 1;
# Mettre à jour avec sous-requête
UPDATE commandes
SET total = (SELECT SUM(prix) FROM items_commande
            WHERE commande_id = commandes.id);
```

### Sélectionner des Données : `SELECT`

Interroger et récupérer des données à partir des tables de la base de données.

```sql
# Sélection de base
SELECT * FROM utilisateurs;
# Sélectionner des colonnes spécifiques
SELECT id, nom_utilisateur, email FROM utilisateurs;
# Sélection avec conditions
SELECT * FROM utilisateurs
WHERE actif = true AND cree_le > '2024-01-01';
# Sélection avec tri et limites
SELECT * FROM utilisateurs
ORDER BY cree_le DESC
LIMIT 10 OFFSET 20;
```

### Supprimer des Données : `DELETE`

Supprimer des enregistrements des tables de la base de données.

```sql
# Supprimer des enregistrements spécifiques
DELETE FROM utilisateurs
WHERE actif = false;
# Supprimer avec sous-requête
DELETE FROM commandes
WHERE utilisateur_id IN (
    SELECT id FROM utilisateurs WHERE actif = false
);
# Supprimer tous les enregistrements
DELETE FROM table_temporaire;
# Supprimer avec retour
DELETE FROM utilisateurs
WHERE id = 5
RETURNING *;
```

## Requêtes Avancées

### Jointures : `INNER/LEFT/RIGHT JOIN`

Combiner des données provenant de plusieurs tables en utilisant différents types de jointures.

```sql
# Jointure interne
SELECT u.nom_utilisateur, o.total
FROM utilisateurs u
INNER JOIN commandes o ON u.id = o.utilisateur_id;
# Jointure gauche
SELECT u.nom_utilisateur, o.total
FROM utilisateurs u
LEFT JOIN commandes o ON u.id = o.utilisateur_id;
# Jointures multiples
SELECT u.nom_utilisateur, o.total, p.nom
FROM utilisateurs u
JOIN commandes o ON u.id = o.utilisateur_id
JOIN produits p ON o.produit_id = p.id;
```

### Sous-requêtes & CTEs

Utiliser des requêtes imbriquées et des expressions de table communes pour des opérations complexes.

```sql
# Sous-requête dans WHERE
SELECT * FROM utilisateurs
WHERE id IN (SELECT utilisateur_id FROM commandes);
# Expression de Table Commune (CTE)
WITH utilisateurs_actifs AS (
    SELECT * FROM utilisateurs WHERE actif = true
)
SELECT ua.nom_utilisateur, COUNT(o.id) as nombre_commandes
FROM utilisateurs_actifs ua
LEFT JOIN commandes o ON ua.id = o.utilisateur_id
GROUP BY ua.nom_utilisateur;
```

### Agrégation : `GROUP BY`

Grouper les données et appliquer des fonctions d'agrégation pour l'analyse.

```sql
# Groupement de base
SELECT statut, COUNT(*) as compte
FROM commandes
GROUP BY statut;
# Agrégations multiples
SELECT utilisateur_id,
       COUNT(*) as compte_commandes,
       SUM(total) as total_depense,
       AVG(total) as commande_moyenne
FROM commandes
GROUP BY utilisateur_id
HAVING COUNT(*) > 5;
```

### Fonctions Fenêtres

Effectuer des calculs sur des lignes connexes sans regroupement.

```sql
# Numérotation des lignes
SELECT nom_utilisateur, email,
       ROW_NUMBER() OVER (ORDER BY cree_le) as num_ligne
FROM utilisateurs;
# Totaux courants
SELECT date, montant,
       SUM(montant) OVER (ORDER BY date) as total_courant
FROM ventes;
# Classement
SELECT nom_utilisateur, score,
       RANK() OVER (ORDER BY score DESC) as rang
FROM scores_utilisateurs;
```

## Importation & Exportation de Données

### Importation CSV : `COPY`

Importer des données à partir de fichiers CSV dans des tables PostgreSQL.

```sql
# Importer depuis un fichier CSV
COPY utilisateurs(nom_utilisateur, email, age)
FROM '/chemin/vers/utilisateurs.csv'
DELIMITER ',' CSV HEADER;
# Importer avec des options spécifiques
COPY produits
FROM '/chemin/vers/produits.csv'
WITH (FORMAT csv, HEADER true, DELIMITER ';');
# Importer depuis stdin
\copy utilisateurs(nom_utilisateur, email) FROM STDIN WITH CSV;
```

### Exportation CSV : `COPY TO`

Exporter des données PostgreSQL vers des fichiers CSV.

```sql
# Exporter vers un fichier CSV
COPY utilisateurs TO '/chemin/vers/utilisateurs_export.csv'
WITH (FORMAT csv, HEADER true);
# Exporter les résultats d'une requête
COPY (SELECT nom_utilisateur, email FROM utilisateurs WHERE actif = true)
TO '/chemin/vers/utilisateurs_actifs.csv' CSV HEADER;
# Exporter vers stdout
\copy (SELECT * FROM commandes) TO STDOUT WITH CSV HEADER;
```

### Sauvegarde & Restauration : `pg_dump`

Créer des sauvegardes de bases de données et restaurer à partir de fichiers de sauvegarde.

```bash
# Sauvegarder toute la base de données
pg_dump -U nom_utilisateur -h nom_hote nom_base_de_donnees > sauvegarde.sql
# Sauvegarder une table spécifique
pg_dump -U nom_utilisateur -t nom_table nom_base_de_donnees > sauvegarde_table.sql
# Sauvegarde compressée
pg_dump -U nom_utilisateur -Fc nom_base_de_donnees > sauvegarde.dump
# Restaurer à partir de la sauvegarde
psql -U nom_utilisateur -d nom_base_de_donnees < sauvegarde.sql
# Restaurer la sauvegarde compressée
pg_restore -U nom_utilisateur -d nom_base_de_donnees sauvegarde.dump
```

### Opérations sur Données JSON

Travailler avec les types de données JSON et JSONB pour les données semi-structurées.

```sql
# Insérer des données JSON
INSERT INTO produits (nom, metadonnees)
VALUES ('Ordinateur Portable', '{"marque": "Dell", "prix": 999.99}');
# Interroger les champs JSON
SELECT nom, metadonnees->>'marque' as marque
FROM produits
WHERE metadonnees->>'prix'::numeric > 500;
# Opérations sur les tableaux JSON
SELECT nom FROM produits
WHERE metadonnees->'caracteristiques' ? 'sans_fil';
```

## Gestion des Utilisateurs et Sécurité

### Créer des Utilisateurs et des Rôles

Gérer l'accès à la base de données avec des utilisateurs et des rôles.

```sql
# Créer un utilisateur
CREATE USER monutilisateur WITH PASSWORD 'motdepasse_secret';
# Créer un rôle
CREATE ROLE utilisateur_lecture_seule;
# Créer un utilisateur avec des privilèges spécifiques
CREATE USER utilisateur_admin WITH
    CREATEDB CREATEROLE PASSWORD 'motdepasse_admin';
# Accorder un rôle à un utilisateur
GRANT utilisateur_lecture_seule TO monutilisateur;
```

### Permissions : `GRANT/REVOKE`

Contrôler l'accès aux objets de la base de données via les permissions.

```sql
# Accorder des permissions de table
GRANT SELECT, INSERT ON utilisateurs TO monutilisateur;
# Accorder tous les privilèges sur la table
GRANT ALL ON commandes TO utilisateur_admin;
# Accorder des permissions de base de données
GRANT CONNECT ON DATABASE mdb TO monutilisateur;
# Révoquer des permissions
REVOKE INSERT ON utilisateurs FROM monutilisateur;
```

### Consulter les Informations Utilisateur

Vérifier les utilisateurs existants et leurs autorisations.

```bash
# Lister tous les utilisateurs
\du
# Voir les permissions de table
SELECT table_name, privilege_type, grantee
FROM information_schema.table_privileges
WHERE table_schema = 'public';
# Voir l'utilisateur actuel
SELECT current_user;
# Voir les appartenances aux rôles
SELECT r.rolname, r.rolsuper, r.rolcreaterole
FROM pg_roles r;
```

### Mot de Passe et Sécurité

Gérer les mots de passe des utilisateurs et les paramètres de sécurité.

```sql
# Changer le mot de passe de l'utilisateur
ALTER USER monutilisateur PASSWORD 'nouveau_mot_de_passe';
# Définir l'expiration du mot de passe
ALTER USER monutilisateur VALID UNTIL '2025-12-31';
# Créer un utilisateur sans connexion
CREATE ROLE role_rapport NOLOGIN;
# Activer/désactiver l'utilisateur
ALTER USER monutilisateur WITH NOLOGIN;
ALTER USER monutilisateur WITH LOGIN;
```

## Performances et Surveillance

### Analyse des Requêtes : `EXPLAIN`

Analyser les plans d'exécution des requêtes et optimiser les performances.

```bash
# Afficher le plan d'exécution de la requête
EXPLAIN SELECT * FROM utilisateurs WHERE actif = true;
# Analyser avec les statistiques d'exécution réelles
EXPLAIN ANALYZE
SELECT u.nom_utilisateur, COUNT(o.id)
FROM utilisateurs u
LEFT JOIN commandes o ON u.id = o.utilisateur_id
GROUP BY u.nom_utilisateur;
# Informations d'exécution détaillées
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT * FROM grande_table WHERE colonne_indexee = 'valeur';
```

### Maintenance de la Base de Données : `VACUUM`

Maintenir les performances de la base de données grâce à des opérations de nettoyage régulières.

```sql
# Vacuum de base
VACUUM utilisateurs;
# Vacuum complet avec analyse
VACUUM FULL ANALYZE utilisateurs;
# Statut de l'auto-vacuum
SELECT schemaname, tablename, last_vacuum, last_autovacuum
FROM pg_stat_user_tables;
# Réindexer la table
REINDEX TABLE utilisateurs;
```

### Surveillance des Requêtes

Suivre l'activité de la base de données et identifier les problèmes de performance.

```sql
# Activité actuelle
SELECT pid, usename, query, state
FROM pg_stat_activity
WHERE state != 'idle';
# Requêtes de longue durée
SELECT pid, now() - query_start as duree, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duree DESC;
# Tuer une requête spécifique
SELECT pg_terminate_backend(pid) WHERE pid = 12345;
```

### Statistiques de la Base de Données

Obtenir des informations sur l'utilisation et les métriques de performance de la base de données.

```sql
# Statistiques des tables
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del
FROM pg_stat_user_tables;
# Statistiques d'utilisation des index
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes;
# Taille de la base de données
SELECT pg_size_pretty(pg_database_size('mdb'));
```

## Fonctionnalités Avancées

### Vues : `CREATE VIEW`

Créer des tables virtuelles pour simplifier les requêtes complexes et fournir une abstraction des données.

```sql
# Créer une vue simple
CREATE VIEW utilisateurs_actifs AS
SELECT id, nom_utilisateur, email
FROM utilisateurs WHERE actif = true;
# Créer une vue avec des jointures
CREATE OR REPLACE VIEW resume_commandes AS
SELECT u.nom_utilisateur, COUNT(o.id) as total_commandes,
       SUM(o.total) as total_depense
FROM utilisateurs u
LEFT JOIN commandes o ON u.id = o.utilisateur_id
GROUP BY u.id, u.nom_utilisateur;
# Supprimer la vue
DROP VIEW IF EXISTS resume_commandes;
```

### Déclencheurs et Fonctions

Automatiser les opérations de base de données avec des procédures stockées et des déclencheurs.

```sql
# Créer une fonction
CREATE OR REPLACE FUNCTION mettre_a_jour_horodatage()
RETURNS TRIGGER AS $$
BEGIN
    NEW.mis_a_jour_le = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
# Créer un déclencheur
CREATE TRIGGER mise_a_jour_horodatage_utilisateur
    BEFORE UPDATE ON utilisateurs
    FOR EACH ROW
    EXECUTE FUNCTION mettre_a_jour_horodatage();
```

### Transactions

Assurer la cohérence des données avec le contrôle des transactions.

```sql
# Début de transaction
BEGIN;
UPDATE comptes SET solde = solde - 100
WHERE id = 1;
UPDATE comptes SET solde = solde + 100
WHERE id = 2;
# Valider la transaction
COMMIT;
# Annuler si nécessaire
ROLLBACK;
# Points de sauvegarde
SAVEPOINT point_de_sauvegarde;
ROLLBACK TO point_de_sauvegarde;
```

### Configuration et Optimisation

Optimiser les paramètres du serveur PostgreSQL pour de meilleures performances.

```sql
# Voir la configuration actuelle
SHOW shared_buffers;
SHOW max_connections;
# Définir les paramètres de configuration
SET work_mem = '256MB';
SET random_page_cost = 1.1;
# Recharger la configuration
SELECT pg_reload_conf();
# Voir l'emplacement du fichier de configuration
SHOW config_file;
```

## Configuration et Conseils psql

### Fichiers de Connexion : `.pgpass`

Stocker les informations d'identification de la base de données en toute sécurité pour une authentification automatique.

```bash
# Créer le fichier .pgpass (format : nom_hote:port:base_de_donnees:nom_utilisateur:mot_de_passe)
echo "localhost:5432:mdb:monutilisateur:monmotdepasse" >> ~/.pgpass
# Définir les autorisations appropriées
chmod 600 ~/.pgpass
# Utiliser le fichier de service de connexion
# ~/.pg_service.conf
[mdb]
host=localhost
port=5432
dbname=mdb
user=monutilisateur
```

### Configuration psql : `.psqlrc`

Personnaliser les paramètres de démarrage et le comportement de psql.

```bash
# Créer le fichier ~/.psqlrc avec des paramètres personnalisés
\set QUIET on
\timing on
\set PROMPT1 '%n@%M:%> %`date` %R%# '
\set HISTSIZE 5000
\set COMP_KEYWORD_CASE upper
\x auto
\set QUIET off
# Alias personnalisés
\set afficher_requetes_lentes 'SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;'
```

### Variables d'Environnement

Définir les variables d'environnement PostgreSQL pour faciliter les connexions.

```bash
# Définir dans votre profil shell
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=mdb
export PGUSER=monutilisateur
# Puis se connecter simplement avec
psql
# Ou utiliser un environnement spécifique
PGDATABASE=testdb psql
```

### Informations sur la Base de Données

Obtenir des informations sur les objets et la structure de la base de données.

```bash
# Lister les bases de données
\l, \l+
# Lister les tables dans la base de données actuelle
\dt, \dt+
# Lister les vues
\dv, \dv+
# Lister les index
\di, \di+
# Lister les fonctions
\df, \df+
# Lister les séquences
\ds, \ds+
# Décrire la structure de la table
\d nom_table
\d+ nom_table
# Afficher les contraintes de la table
\d+ nom_table
# Afficher les permissions de la table
\dp nom_table
\z nom_table
# Lister les clés étrangères
SELECT * FROM information_schema.table_constraints
WHERE constraint_type = 'FOREIGN KEY';
```

### Sortie et Formatage

Contrôler la manière dont psql affiche les résultats des requêtes et la sortie.

```bash
# Basculer la sortie étendue
\x
# Changer le format de sortie
\H  -- Sortie HTML
\t  -- Tuples seulement (sans en-têtes)
# Sortie vers un fichier
\o nom_fichier.txt
SELECT * FROM utilisateurs;
\o  -- Arrêter la sortie vers le fichier
# Exécuter le SQL à partir d'un fichier
\i script.sql
# Modifier la requête dans un éditeur externe
\e
```

### Chronométrage et Historique

Suivre les performances des requêtes et gérer l'historique des commandes.

```bash
# Basculer l'affichage du chronométrage
\timing
# Afficher l'historique des commandes
\s
# Enregistrer l'historique des commandes dans un fichier
\s nom_fichier.txt
# Effacer l'écran
\! clear  -- Linux/Mac
\! cls   -- Windows
# Afficher la dernière erreur
\errverbose
```

## Liens Pertinents

- <router-link to="/database">Feuille de triche Base de Données</router-link>
- <router-link to="/mysql">Feuille de triche MySQL</router-link>
- <router-link to="/sqlite">Feuille de triche SQLite</router-link>
- <router-link to="/mongodb">Feuille de triche MongoDB</router-link>
- <router-link to="/redis">Feuille de triche Redis</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>

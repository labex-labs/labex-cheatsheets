---
title: 'Fiche de Référence Redis | LabEx'
description: 'Apprenez le magasin de données en mémoire Redis avec cette fiche de référence complète. Référence rapide des commandes Redis, structures de données, mise en cache, pub/sub, persistance et solutions de mise en cache haute performance.'
pdfUrl: '/cheatsheets/pdf/redis-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Redis
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/redis">Apprenez Redis avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez les opérations de structure de données en mémoire de Redis grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets sur Redis couvrant les commandes essentielles, les structures de données, les stratégies de mise en cache, la messagerie pub/sub et l'optimisation des performances. Maîtrisez la mise en cache haute performance et le traitement des données en temps réel.
</base-disclaimer-content>
</base-disclaimer>

## Installation et Configuration de Redis

### Docker : `docker run redis`

Le moyen le plus rapide de faire fonctionner Redis localement.

```bash
# Exécuter Redis dans Docker
docker run --name my-redis -p 6379:6379 -d redis
# Se connecter à l'interface de ligne de commande Redis
docker exec -it my-redis redis-cli
# Exécuter avec stockage persistant
docker run --name redis-persistent -p 6379:6379 -v redis-data:/data -d redis
```

### Linux : `sudo apt install redis`

Installer le serveur Redis sur les systèmes Ubuntu/Debian.

```bash
# Installer Redis
sudo apt update
sudo apt install redis-server
# Démarrer le service Redis
sudo systemctl start redis-server
# Activer le démarrage automatique au démarrage
sudo systemctl enable redis-server
# Vérifier l'état
sudo systemctl status redis
```

### Connexion et Test : `redis-cli`

Se connecter au serveur Redis et vérifier l'installation.

```bash
# Se connecter à Redis local
redis-cli
# Tester la connexion
redis-cli PING
# Se connecter à Redis distant
redis-cli -h hostname -p 6379 -a password
# Exécuter une seule commande
redis-cli SET mykey "Hello Redis"
```

## Opérations de Base sur les Chaînes (Strings)

### Définir et Obtenir : `SET` / `GET`

Stocker des valeurs simples (texte, nombres, JSON, etc.).

```redis
# Définir une paire clé-valeur
SET mykey "Hello World"
# Obtenir la valeur par clé
GET mykey
# Définir avec expiration (en secondes)
SET session:123 "user_data" EX 3600
# Définir seulement si la clé n'existe pas
SET mykey "new_value" NX
```

<BaseQuiz id="redis-set-get-1" correct="C">
  <template #question>
    Que fait `SET mykey "value" EX 3600` ?
  </template>
  
  <BaseQuizOption value="A">Définit la clé avec une valeur de 3600 octets</BaseQuizOption>
  <BaseQuizOption value="B">Définit la clé seulement si elle existe</BaseQuizOption>
  <BaseQuizOption value="C" correct>Définit la clé avec une valeur qui expire après 3600 secondes</BaseQuizOption>
  <BaseQuizOption value="D">Définit la clé avec 3600 valeurs différentes</BaseQuizOption>
  
  <BaseQuizAnswer>
    L'option `EX` définit un temps d'expiration en secondes. `SET mykey "value" EX 3600` stocke la valeur et la supprime automatiquement après 3600 secondes (1 heure).
  </BaseQuizAnswer>
</BaseQuiz>

### Manipulation de Chaînes : `APPEND` / `STRLEN`

Modifier et inspecter les valeurs de chaînes.

```redis
# Ajouter à la chaîne existante
APPEND mykey " - Welcome!"
# Obtenir la longueur de la chaîne
STRLEN mykey
# Obtenir une sous-chaîne
GETRANGE mykey 0 4
# Définir une sous-chaîne
SETRANGE mykey 6 "Redis"
```

### Opérations Numériques : `INCR` / `DECR`

Incrémenter ou décrémenter les valeurs entières stockées dans Redis.

```redis
# Incrémenter de 1
INCR counter
# Décrémenter de 1
DECR counter
# Incrémenter d'un montant spécifique
INCRBY counter 5
# Incrémenter un flottant
INCRBYFLOAT price 0.1
```

<BaseQuiz id="redis-incr-1" correct="A">
  <template #question>
    Que se passe-t-il si vous utilisez `INCR` sur une clé qui n'existe pas ?
  </template>
  
  <BaseQuizOption value="A" correct>Redis crée la clé avec la valeur 1</BaseQuizOption>
  <BaseQuizOption value="B">Redis renvoie une erreur</BaseQuizOption>
  <BaseQuizOption value="C">Redis crée la clé avec la valeur 0</BaseQuizOption>
  <BaseQuizOption value="D">Rien ne se passe</BaseQuizOption>
  
  <BaseQuizAnswer>
    Si une clé n'existe pas, `INCR` la traite comme si elle avait une valeur de 0, l'incrémente à 1 et crée la clé. Cela rend `INCR` utile pour initialiser des compteurs.
  </BaseQuizAnswer>
</BaseQuiz>

### Opérations Multiples : `MSET` / `MGET`

Travailler avec plusieurs paires clé-valeur efficacement.

```redis
# Définir plusieurs clés à la fois
MSET key1 "value1" key2 "value2" key3 "value3"
# Obtenir plusieurs valeurs
MGET key1 key2 key3
# Définir plusieurs seulement si aucune n'existe
MSETNX key1 "val1" key2 "val2"
```

## Opérations sur les Listes (Lists)

Les listes sont des séquences ordonnées de chaînes, utiles comme files d'attente ou piles.

### Ajouter des Éléments : `LPUSH` / `RPUSH`

Ajouter des éléments à gauche (tête) ou à droite (queue) d'une liste.

```redis
# Ajouter à la tête (gauche)
LPUSH mylist "first"
# Ajouter à la queue (droite)
RPUSH mylist "last"
# Ajouter plusieurs éléments
LPUSH mylist "item1" "item2" "item3"
```

### Supprimer des Éléments : `LPOP` / `RPOP`

Supprimer et retourner les éléments des extrémités de la liste.

```redis
# Supprimer de la tête
LPOP mylist
# Supprimer de la queue
RPOP mylist
# Pop bloquant (attend un élément)
BLPOP mylist 10
```

### Accéder aux Éléments : `LRANGE` / `LINDEX`

Récupérer des éléments ou des plages de listes.

```redis
# Obtenir la liste entière
LRANGE mylist 0 -1
# Obtenir les 3 premiers éléments
LRANGE mylist 0 2
# Obtenir un élément spécifique par index
LINDEX mylist 0
# Obtenir la longueur de la liste
LLEN mylist
```

<BaseQuiz id="redis-list-1" correct="B">
  <template #question>
    Que retourne `LRANGE mylist 0 -1` ?
  </template>
  
  <BaseQuizOption value="A">Seulement le premier élément</BaseQuizOption>
  <BaseQuizOption value="B" correct>Tous les éléments de la liste</BaseQuizOption>
  <BaseQuizOption value="C">Seulement le dernier élément</BaseQuizOption>
  <BaseQuizOption value="D">Une erreur</BaseQuizOption>
  
  <BaseQuizAnswer>
    `LRANGE` avec `0 -1` retourne tous les éléments de la liste. Le `0` est l'index de départ et `-1` représente le dernier élément, donc cela récupère tout du premier au dernier élément.
  </BaseQuizAnswer>
</BaseQuiz>

### Utilitaires de Liste : `LSET` / `LTRIM`

Modifier le contenu et la structure de la liste.

```redis
# Définir un élément à un index
LSET mylist 0 "new_value"
# Tronquer la liste à une plage
LTRIM mylist 0 99
# Trouver la position d'un élément
LPOS mylist "search_value"
```

## Opérations sur les Ensembles (Sets)

Les ensembles sont des collections d'éléments de chaîne uniques et non ordonnés.

### Opérations de Base sur les Ensembles : `SADD` / `SMEMBERS`

Ajouter des éléments uniques aux ensembles et récupérer tous les membres.

```redis
# Ajouter des éléments à l'ensemble
SADD myset "apple" "banana" "cherry"
# Obtenir tous les membres de l'ensemble
SMEMBERS myset
# Vérifier si l'élément existe
SISMEMBER myset "apple"
```

<BaseQuiz id="redis-set-1" correct="C">
  <template #question>
    Que se passe-t-il si vous essayez d'ajouter un élément en double à un ensemble Redis ?
  </template>
  
  <BaseQuizOption value="A">Cela crée une erreur</BaseQuizOption>
  <BaseQuizOption value="B">Cela remplace l'élément existant</BaseQuizOption>
  <BaseQuizOption value="C" correct>Le doublon est ignoré et l'ensemble reste inchangé</BaseQuizOption>
  <BaseQuizOption value="D">Cela crée une liste à la place</BaseQuizOption>
  
  <BaseQuizAnswer>
    Les ensembles Redis ne contiennent que des éléments uniques. Si vous essayez d'ajouter un élément qui existe déjà, Redis l'ignore et retourne 0 (indiquant qu'aucun élément n'a été ajouté). L'ensemble reste inchangé.
  </BaseQuizAnswer>
</BaseQuiz>
# Obtenir la taille de l'ensemble
SCARD myset
```

### Modifications d'Ensemble : `SREM` / `SPOP`

Supprimer des éléments des ensembles de différentes manières.

```redis
# Supprimer des éléments spécifiques
SREM myset "banana"
# Supprimer et retourner un élément aléatoire
SPOP myset
# Obtenir un élément aléatoire sans le supprimer
SRANDMEMBER myset
```

### Opérations d'Ensemble : `SINTER` / `SUNION`

Effectuer des opérations d'ensemble mathématiques.

```redis
# Intersection des ensembles
SINTER set1 set2
# Union des ensembles
SUNION set1 set2
# Différence des ensembles
SDIFF set1 set2
# Stocker le résultat dans un nouvel ensemble
SINTERSTORE result set1 set2
```

### Utilitaires d'Ensemble : `SMOVE` / `SSCAN`

Manipulation et balayage avancés des ensembles.

```redis
# Déplacer un élément entre ensembles
SMOVE source_set dest_set "element"
# Balayer l'ensemble par incréments
SSCAN myset 0 MATCH "a*" COUNT 10
```

## Opérations sur les Hachages (Hashes)

Les hachages stockent des paires champ-valeur, comme de mini objets JSON ou des dictionnaires.

### Opérations de Hachage de Base : `HSET` / `HGET`

Définir et récupérer des champs de hachage individuels.

```redis
# Définir un champ de hachage
HSET user:123 name "John Doe" age 30
# Obtenir un champ de hachage
HGET user:123 name
# Définir plusieurs champs
HMSET user:123 email "john@example.com" city "NYC"
# Obtenir plusieurs champs
HMGET user:123 name age email
```

### Inspection de Hachage : `HKEYS` / `HVALS`

Examiner la structure et le contenu du hachage.

```redis
# Obtenir tous les noms de champs
HKEYS user:123
# Obtenir toutes les valeurs
HVALS user:123
# Obtenir tous les champs et valeurs
HGETALL user:123
# Obtenir le nombre de champs
HLEN user:123
```

### Utilitaires de Hachage : `HEXISTS` / `HDEL`

Vérifier l'existence et supprimer des champs de hachage.

```redis
# Vérifier si le champ existe
HEXISTS user:123 email
# Supprimer des champs
HDEL user:123 age city
# Incrémenter un champ de hachage
HINCRBY user:123 age 1
# Incrémenter par flottant
HINCRBYFLOAT user:123 balance 10.50
```

### Balayage de Hachage : `HSCAN`

Itérer sur les grands hachages par incréments.

```redis
# Balayer les champs du hachage
HSCAN user:123 0
# Balayer avec correspondance de motif
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## Opérations sur les Ensembles Ordonnés (Sorted Sets)

Les ensembles ordonnés combinent l'unicité des ensembles avec un classement basé sur des scores.

### Opérations de Base : `ZADD` / `ZRANGE`

Ajouter des membres avec des scores et récupérer des plages.

```redis
# Ajouter des membres avec des scores
ZADD leaderboard 100 "player1" 200 "player2"
# Obtenir les membres par rang (indexé à 0)
ZRANGE leaderboard 0 -1
# Obtenir avec les scores
ZRANGE leaderboard 0 -1 WITHSCORES
# Obtenir par plage de score
ZRANGEBYSCORE leaderboard 100 200
```

### Informations sur l'Ensemble Ordonné : `ZCARD` / `ZSCORE`

Obtenir des informations sur les membres de l'ensemble ordonné.

```redis
# Obtenir la taille de l'ensemble
ZCARD leaderboard
# Obtenir le score du membre
ZSCORE leaderboard "player1"
# Obtenir le rang du membre
ZRANK leaderboard "player1"
# Compter les membres dans la plage de score
ZCOUNT leaderboard 100 200
```

### Modifications : `ZREM` / `ZINCRBY`

Supprimer des membres et modifier les scores.

```redis
# Supprimer des membres
ZREM leaderboard "player1"
# Incrémenter le score du membre
ZINCRBY leaderboard 10 "player2"
# Supprimer par rang
ZREMRANGEBYRANK leaderboard 0 2
# Supprimer par score
ZREMRANGEBYSCORE leaderboard 0 100
```

### Avancé : `ZUNIONSTORE` / `ZINTERSTORE`

Combiner plusieurs ensembles ordonnés.

```redis
# Union des ensembles ordonnés
ZUNIONSTORE result 2 set1 set2
# Intersection avec des poids
ZINTERSTORE result 2 set1 set2 WEIGHTS 1 2
# Avec fonction d'agrégation
ZUNIONSTORE result 2 set1 set2 AGGREGATE MAX
```

## Gestion des Clés

### Inspection des Clés : `KEYS` / `EXISTS`

Trouver des clés à l'aide de motifs et vérifier leur existence.

```redis
# Obtenir toutes les clés (à utiliser avec prudence en production)
KEYS *
# Clés avec motif
KEYS user:*
# Clés se terminant par un motif
KEYS *:profile
# Caractère générique pour un seul caractère
KEYS order:?
# Vérifier si la clé existe
EXISTS mykey
```

### Informations sur les Clés : `TYPE` / `TTL`

Obtenir les métadonnées de la clé et les informations d'expiration.

```redis
# Obtenir le type de données de la clé
TYPE mykey
# Obtenir le temps de vie (secondes)
TTL mykey
# Obtenir le TTL en millisecondes
PTTL mykey
# Supprimer l'expiration
PERSIST mykey
```

### Opérations sur les Clés : `RENAME` / `DEL`

Renommer, supprimer et déplacer des clés.

```redis
# Renommer la clé
RENAME oldkey newkey
# Renommer seulement si la nouvelle clé n'existe pas
RENAMENX oldkey newkey
# Supprimer des clés
DEL key1 key2 key3
# Déplacer la clé vers une base de données différente
MOVE mykey 1
```

### Expiration : `EXPIRE` / `EXPIREAT`

Définir les temps d'expiration des clés.

```redis
# Définir l'expiration en secondes
EXPIRE mykey 3600
# Définir l'expiration à un horodatage spécifique
EXPIREAT mykey 1609459200
# Définir l'expiration en millisecondes
PEXPIRE mykey 60000
```

## Gestion des Bases de Données

### Sélection de Base de Données : `SELECT` / `FLUSHDB`

Gérer plusieurs bases de données au sein de Redis.

```redis
# Sélectionner la base de données (0-15 par défaut)
SELECT 0
# Vider la base de données actuelle
FLUSHDB
# Vider toutes les bases de données
FLUSHALL
# Obtenir la taille de la base de données actuelle
DBSIZE
```

### Informations sur le Serveur : `INFO` / `PING`

Obtenir les statistiques du serveur et tester la connectivité.

```redis
# Tester la connexion au serveur
PING
# Obtenir les informations du serveur
INFO
# Obtenir une section d'information spécifique
INFO memory
INFO replication
# Obtenir l'heure du serveur
TIME
```

### Persistance : `SAVE` / `BGSAVE`

Contrôler la persistance des données et les sauvegardes de Redis.

```redis
# Sauvegarde synchrone (bloque le serveur)
SAVE
# Sauvegarde en arrière-plan (non bloquante)
BGSAVE
# Obtenir l'heure de la dernière sauvegarde
LASTSAVE
# Réécrire le fichier AOF
BGREWRITEAOF
```

### Configuration : `CONFIG GET` / `CONFIG SET`

Afficher et modifier la configuration de Redis.

```redis
# Obtenir toute la configuration
CONFIG GET *
# Obtenir une configuration spécifique
CONFIG GET maxmemory
# Définir la configuration
CONFIG SET timeout 300
# Réinitialiser les statistiques
CONFIG RESETSTAT
```

## Surveillance des Performances

### Surveillance en Temps Réel : `MONITOR` / `SLOWLOG`

Suivre les commandes et identifier les goulots d'étranglement de performance.

```redis
# Surveiller toutes les commandes en temps réel
MONITOR
# Obtenir le journal des requêtes lentes
SLOWLOG GET 10
# Obtenir la longueur du journal lent
SLOWLOG LEN
# Réinitialiser le journal lent
SLOWLOG RESET
```

### Analyse de la Mémoire : `MEMORY USAGE` / `MEMORY STATS`

Analyser la consommation de mémoire et l'optimisation.

```redis
# Obtenir l'utilisation de la mémoire d'une clé
MEMORY USAGE mykey
# Obtenir les statistiques de mémoire
MEMORY STATS
# Obtenir le rapport du docteur de la mémoire
MEMORY DOCTOR
# Purger la mémoire
MEMORY PURGE
```

### Informations Client : `CLIENT LIST`

Surveiller les clients connectés et les connexions.

```redis
# Lister tous les clients
CLIENT LIST
# Obtenir les informations du client
CLIENT INFO
# Tuer la connexion client
CLIENT KILL ip:port
# Définir le nom du client
CLIENT SETNAME "my-app"
```

### Étalonnage (Benchmarking) : `redis-benchmark`

Tester les performances de Redis avec l'outil d'étalonnage intégré.

```bash
# Étalonnage de base
redis-benchmark
# Opérations spécifiques
redis-benchmark -t SET,GET -n 100000
# Taille de charge utile personnalisée
redis-benchmark -d 1024 -t SET -n 10000
```

## Fonctionnalités Avancées

### Transactions : `MULTI` / `EXEC`

Exécuter plusieurs commandes de manière atomique.

```redis
# Démarrer la transaction
MULTI
SET key1 "value1"
INCR counter
# Exécuter toutes les commandes
EXEC
# Annuler la transaction
DISCARD
# Surveiller les clés pour les changements
WATCH mykey
```

### Pub/Sub : `PUBLISH` / `SUBSCRIBE`

Implémenter le passage de messages entre clients.

```redis
# S'abonner à un canal
SUBSCRIBE news sports
# Publier un message
PUBLISH news "Breaking: Redis 7.0 released!"
# Abonnement par motif
PSUBSCRIBE news:*
# Se désabonner
UNSUBSCRIBE news
```

### Scripting Lua : `EVAL` / `SCRIPT`

Exécuter des scripts Lua personnalisés de manière atomique.

```redis
# Exécuter un script Lua
EVAL "return redis.call('SET', 'key', 'value')" 0
# Charger le script et obtenir le SHA
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# Exécuter par SHA
EVALSHA sha1 1 mykey
# Vérifier l'existence du script
SCRIPT EXISTS sha1
```

### Flux (Streams) : `XADD` / `XREAD`

Travailler avec les flux Redis pour des données de type journal.

```redis
# Ajouter une entrée au flux
XADD mystream * field1 value1 field2 value2
# Lire depuis le flux
XREAD STREAMS mystream 0
# Obtenir la longueur du flux
XLEN mystream
# Créer un groupe de consommateurs
XGROUP CREATE mystream mygroup 0
```

## Aperçu des Types de Données

### Chaînes (Strings) : Le type le plus polyvalent

Peut stocker du texte, des nombres, du JSON, des données binaires. Taille max : 512 Mo. Utiliser pour : mise en cache, compteurs, drapeaux (flags).

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### Listes (Lists) : Collections ordonnées

Listes chaînées de chaînes. Utiliser pour : files d'attente, piles, flux d'activité, éléments récents.

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### Ensembles (Sets) : Collections uniques

Collections non ordonnées de chaînes uniques. Utiliser pour : étiquettes (tags), visiteurs uniques, relations.

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Conseils de Configuration Redis

### Gestion de la Mémoire

Configurer les limites de mémoire et les politiques d'éviction.

```redis
# Définir la limite de mémoire
CONFIG SET maxmemory 2gb
# Définir la politique d'éviction
CONFIG SET maxmemory-policy allkeys-lru
# Vérifier l'utilisation de la mémoire
INFO memory
```

### Paramètres de Persistance

Configurer les options de durabilité des données.

```redis
# Activer AOF
CONFIG SET appendonly yes
# Définir les intervalles de sauvegarde
CONFIG SET save "900 1 300 10 60 10000"
# Paramètres de réécriture AOF
CONFIG SET auto-aof-rewrite-percentage 100
```

### Paramètres de Sécurité

Configurations de sécurité de base pour Redis.

```redis
# Définir le mot de passe
CONFIG SET requirepass mypassword
# Authentification
AUTH mypassword
# Désactiver les commandes dangereuses
CONFIG SET rename-command FLUSHALL ""
# Définir le délai d'attente
CONFIG SET timeout 300
# Maintien de la connexion TCP
CONFIG SET tcp-keepalive 60
# Clients maximum
CONFIG SET maxclients 10000
```

### Optimisation des Performances

Optimiser Redis pour de meilleures performances.

```redis
# Activer le pipelining pour plusieurs commandes
# Utiliser le pool de connexions
# Configurer la politique maxmemory appropriée
# Surveiller régulièrement les requêtes lentes
# Utiliser les structures de données appropriées pour les cas d'utilisation
```

## Liens Pertinents

- <router-link to="/database">Feuille de triche Bases de données</router-link>
- <router-link to="/mysql">Feuille de triche MySQL</router-link>
- <router-link to="/postgresql">Feuille de triche PostgreSQL</router-link>
- <router-link to="/mongodb">Feuille de triche MongoDB</router-link>
- <router-link to="/sqlite">Feuille de triche SQLite</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>
- <router-link to="/javascript">Feuille de triche JavaScript</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>

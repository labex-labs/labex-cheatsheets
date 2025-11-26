---
title: 'Cheat Sheet Nmap'
description: 'Apprenez Nmap avec notre aide-mémoire complet couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/nmap-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Nmap Aide-mémoire
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/nmap">Apprendre Nmap avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la numérisation de réseau Nmap grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours Nmap complets couvrant la découverte de réseau essentielle, la numérisation de ports, la détection de services, l'empreinte du système d'exploitation (OS fingerprinting) et l'évaluation des vulnérabilités. Maîtrisez les techniques de reconnaissance de réseau et d'audit de sécurité.
</base-disclaimer-content>
</base-disclaimer>

## Installation et Configuration

### Installation sous Linux

Installez Nmap à l'aide du gestionnaire de paquets de votre distribution.

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap
# RHEL/Fedora/CentOS
sudo dnf install nmap
# Vérifier l'installation
nmap --version
```

### Installation sous macOS

Installez via le gestionnaire de paquets Homebrew.

```bash
# Installer via Homebrew
brew install nmap
# Téléchargement direct depuis nmap.org
# Télécharger le .dmg depuis https://nmap.org/download.html
```

### Installation sous Windows

Téléchargez et installez depuis le site officiel.

```bash
# Télécharger l'installeur depuis
https://nmap.org/download.html
# Exécuter l'installeur .exe avec des privilèges d'administrateur
# Inclut l'interface graphique Zenmap et la version ligne de commande
```

### Vérification de Base

Testez votre installation et obtenez de l'aide.

```bash
# Afficher les informations de version
nmap --version
# Afficher le menu d'aide
nmap -h
# Aide étendue et options
man nmap
```

## Techniques de Balayage de Base

### Balayage d'Hôte Simple : `nmap [cible]`

Balayage de base d'un seul hôte ou d'une adresse IP.

```bash
# Balayer une IP unique
nmap 192.168.1.1
# Balayer un nom d'hôte
nmap example.com
# Balayer plusieurs IPs
nmap 192.168.1.1 192.168.1.5
192.168.1.10
```

### Balayage de Plage Réseau

Nmap accepte les noms d'hôtes, les adresses IP, les sous-réseaux.

```bash
# Balayer une plage d'IP
nmap 192.168.1.1-254
# Balayer un sous-réseau avec notation CIDR
nmap 192.168.1.0/24
# Balayer plusieurs réseaux
nmap 192.168.1.0/24 10.0.0.0/8
```

### Entrée depuis un Fichier

Balayer les cibles listées dans un fichier.

```bash
# Lire les cibles depuis un fichier
nmap -iL targets.txt
# Exclure des hôtes spécifiques
nmap 192.168.1.0/24 --exclude
192.168.1.1
# Exclure depuis un fichier
nmap 192.168.1.0/24 --excludefile
exclude.txt
```

## Techniques de Découverte d'Hôtes

### Balayage Ping : `nmap -sn`

La découverte d'hôtes est une manière clé que de nombreux analystes et pentesters utilisent Nmap. Son objectif est d'obtenir un aperçu des systèmes en ligne.

```bash
# Balayage Ping uniquement (pas de balayage de ports)
nmap -sn 192.168.1.0/24
# Sauter la découverte d'hôtes (supposer que tous les hôtes sont actifs)
nmap -Pn 192.168.1.1
# Ping echo ICMP
nmap -PE 192.168.1.0/24
```

### Techniques de Ping TCP

Utiliser des paquets TCP pour la découverte d'hôtes.

```bash
# Ping SYN TCP vers le port 80
nmap -PS80 192.168.1.0/24
# Ping ACK TCP
nmap -PA80 192.168.1.0/24
# Ping SYN TCP vers plusieurs ports
nmap -PS22,80,443 192.168.1.0/24
```

### Ping UDP : `nmap -PU`

Utiliser des paquets UDP pour la découverte d'hôtes.

```bash
# Ping UDP vers des ports courants
nmap -PU53,67,68,137 192.168.1.0/24
# Ping UDP vers les ports par défaut
nmap -PU 192.168.1.0/24
```

### Ping ARP : `nmap -PR`

Utiliser des requêtes ARP pour la découverte de réseau local.

```bash
# Ping ARP (par défaut pour les réseaux locaux)
nmap -PR 192.168.1.0/24
# Désactiver le ping ARP
nmap --disable-arp-ping 192.168.1.0/24
```

## Types de Balayage de Ports

### Balayage SYN TCP : `nmap -sS`

Ce balayage est plus furtif, car Nmap envoie un paquet RST, ce qui empêche de multiples requêtes et raccourcit le temps de balayage.

```bash
# Balayage par défaut (nécessite root)
nmap -sS 192.168.1.1
# Balayage SYN de ports spécifiques
nmap -sS -p 80,443 192.168.1.1
# Balayage SYN rapide
nmap -sS -T4 192.168.1.1
```

### Balayage de Connexion TCP : `nmap -sT`

Nmap envoie un paquet TCP à un port avec le drapeau SYN défini. Cela permet à l'utilisateur de savoir si les ports sont ouverts, fermés ou inconnus.

```bash
# Balayage de connexion TCP (aucune racine requise)
nmap -sT 192.168.1.1
# Balayage de connexion avec temporisation
nmap -sT -T3 192.168.1.1
```

### Balayage UDP : `nmap -sU`

Balayer les ports UDP pour les services.

```bash
# Balayage UDP (lent, nécessite root)
nmap -sU 192.168.1.1
# Balayage UDP des ports courants
nmap -sU -p 53,67,68,161 192.168.1.1
# Balayage TCP/UDP combiné
nmap -sS -sU -p T:80,443,U:53,161 192.168.1.1
```

### Balayages Furtifs

Techniques de balayage avancées pour l'évasion.

```bash
# Balayage FIN
nmap -sF 192.168.1.1
# Balayage NULL
nmap -sN 192.168.1.1
# Balayage Xmas
nmap -sX 192.168.1.1
```

## Spécification des Ports

### Plages de Ports : `nmap -p`

Cibler des ports spécifiques, des plages ou des combinaisons de ports TCP et UDP pour des balayages plus précis.

```bash
# Port unique
nmap -p 80 192.168.1.1
# Ports multiples
nmap -p 22,80,443 192.168.1.1
# Plage de ports
nmap -p 1-1000 192.168.1.1
# Tous les ports
nmap -p- 192.168.1.1
```

### Ports Spécifiques au Protocole

Spécifier explicitement les ports TCP ou UDP.

```bash
# Ports TCP uniquement
nmap -p T:80,443 192.168.1.1
# Ports UDP uniquement
nmap -p U:53,161 192.168.1.1
# TCP et UDP mélangés
nmap -p T:80,U:53 192.168.1.1
```

### Ensembles de Ports Courants

Balayer rapidement les ports fréquemment utilisés.

```bash
# Top 1000 ports (par défaut)
nmap 192.168.1.1
# Top 100 ports
nmap --top-ports 100 192.168.1.1
# Balayage rapide (100 ports les plus courants)
nmap -F 192.168.1.1
# Afficher uniquement les ports ouverts
nmap --open 192.168.1.1
# Afficher tous les états des ports
nmap -v 192.168.1.1
```

## Détection de Service et de Version

### Détection de Service : `nmap -sV`

Détecter quels services sont en cours d'exécution et tenter d'identifier leur logiciel, leurs versions et leurs configurations.

```bash
# Détection de version de base
nmap -sV 192.168.1.1
# Détection de version agressive
nmap -sV --version-intensity 9 192.168.1.1
# Détection de version légère
nmap -sV --version-intensity 0 192.168.1.1
# Scripts par défaut avec détection de version
nmap -sC -sV 192.168.1.1
```

### Scripts de Service

Utiliser des scripts pour une détection de service améliorée.

```bash
# Saisie de bannière (Banner grabbing)
nmap --script banner 192.168.1.1
# Énumération de service HTTP
nmap --script http-* 192.168.1.1
```

### Détection du Système d'Exploitation : `nmap -O`

Utiliser l'empreinte TCP/IP pour deviner le système d'exploitation des hôtes cibles.

```bash
# Détection d'OS
nmap -O 192.168.1.1
# Détection d'OS agressive
nmap -O --osscan-guess 192.168.1.1
# Limiter les tentatives de détection d'OS
nmap -O --max-os-tries 1 192.168.1.1
```

### Détection Complète

Combiner plusieurs techniques de détection.

```bash
# Balayage agressif (OS, version, scripts)
nmap -A 192.168.1.1
# Balayage agressif personnalisé
nmap -sS -sV -O -sC 192.168.1.1
```

## Temporisation et Performance

### Modèles de Temporisation : `nmap -T`

Ajuster la vitesse du balayage en fonction de votre environnement cible et du risque de détection.

```bash
# Paranoïaque (très lent, furtif)
nmap -T0 192.168.1.1
# Furtif (lent, furtif)
nmap -T1 192.168.1.1
# Poli (plus lent, moins de bande passante)
nmap -T2 192.168.1.1
# Normal (par défaut)
nmap -T3 192.168.1.1
# Agressif (plus rapide)
nmap -T4 192.168.1.1
# Insensé (très rapide, peut manquer des résultats)
nmap -T5 192.168.1.1
```

### Options de Temporisation Personnalisées

Ajuster finement la manière dont Nmap gère les délais d'attente, les nouvelles tentatives et le balayage parallèle pour optimiser les performances.

```bash
# Définir le taux minimum (paquets par seconde)
nmap --min-rate 1000 192.168.1.1
# Définir le taux maximum
nmap --max-rate 100 192.168.1.1
# Balayage d'hôtes parallèle
nmap --min-hostgroup 10 192.168.1.0/24
# Délai d'attente personnalisé
nmap --host-timeout 5m 192.168.1.1
```

## Moteur de Script Nmap (NSE)

### Catégories de Scripts : `nmap --script`

Exécuter des scripts par catégorie ou par nom.

```bash
# Scripts par défaut
nmap --script default 192.168.1.1
# Scripts de vulnérabilité
nmap --script vuln 192.168.1.1
# Scripts de découverte
nmap --script discovery 192.168.1.1
# Scripts d'authentification
nmap --script auth 192.168.1.1
```

### Scripts Spécifiques

Cibler des vulnérabilités ou des services spécifiques.

```bash
# Énumération SMB
nmap --script smb-enum-* 192.168.1.1
# Méthodes HTTP
nmap --script http-methods 192.168.1.1
# Informations sur le certificat SSL
nmap --script ssl-cert 192.168.1.1
```

### Arguments de Script

Passer des arguments pour personnaliser le comportement du script.

```bash
# Force brute HTTP avec liste de mots personnalisée
nmap --script http-brute --script-args
userdb=users.txt,passdb=pass.txt 192.168.1.1
# Force brute SMB
nmap --script smb-brute 192.168.1.1
# Force brute DNS
nmap --script dns-brute example.com
```

### Gestion des Scripts

Gérer et mettre à jour les scripts NSE.

```bash
# Mettre à jour la base de données des scripts
nmap --script-updatedb
# Lister les scripts disponibles
ls /usr/share/nmap/scripts/ | grep http
# Obtenir l'aide sur un script
nmap --script-help vuln
```

## Formats de Sortie et Sauvegarde des Résultats

### Formats de Sortie

Sauvegarder les résultats dans différents formats.

```bash
# Sortie normale
nmap -oN scan_results.txt 192.168.1.1
# Sortie XML
nmap -oX scan_results.xml 192.168.1.1
# Sortie "Grepable"
nmap -oG scan_results.gnmap 192.168.1.1
# Tous les formats
nmap -oA scan_results 192.168.1.1
```

### Sortie Verbeuse

Contrôler la quantité d'informations affichées.

```bash
# Sortie verbeuse
nmap -v 192.168.1.1
# Très verbeuse
nmap -vv 192.168.1.1
# Mode débogage
nmap --packet-trace 192.168.1.1
```

### Reprendre et Ajouter

Continuer ou ajouter à des balayages précédents.

```bash
# Reprendre un balayage interrompu
nmap --resume scan_results.gnmap
# Ajouter à un fichier existant
nmap --append-output -oN existing_scan.txt 192.168.1.1
```

### Traitement des Résultats en Direct

Combiner la sortie Nmap avec des outils en ligne de commande pour extraire des informations utiles.

```bash
# Extraire les hôtes actifs
nmap -sn 192.168.1.0/24 | grep "Nmap scan report"
# Trouver les serveurs web
nmap -p 80,443 --open 192.168.1.0/24 | grep "open"
# Exporter au format CSV
nmap -oX - 192.168.1.1 | xsltproc --html -
```

## Techniques d'Évasion de Pare-feu

### Fragmentation de Paquets : `nmap -f`

Contourner les mesures de sécurité en utilisant la fragmentation de paquets, les IPs usurpées et les méthodes de balayage furtives.

```bash
# Fragmenter les paquets
nmap -f 192.168.1.1
# Taille MTU personnalisée
nmap --mtu 16 192.168.1.1
# Unité de transmission maximale
nmap --mtu 24 192.168.1.1
```

### Balayage avec Leurres : `nmap -D`

Masquer votre balayage parmi des adresses IP leurres.

```bash
# Utiliser des IPs leurres
nmap -D 192.168.1.100,192.168.1.101 192.168.1.1
# Leurres aléatoires
nmap -D RND:5 192.168.1.1
# Mélanger leurres réels et aléatoires
nmap -D 192.168.1.100,RND:3 192.168.1.1
```

### Manipulation de l'IP/Port Source

Usurper les informations source.

```bash
# Usurper l'IP source
nmap -S 192.168.1.100 192.168.1.1
# Port source personnalisé
nmap --source-port 53 192.168.1.1
# Longueur de données aléatoire
nmap --data-length 25 192.168.1.1
```

### Balayage Inactif/Zombie : `nmap -sI`

Utiliser un hôte zombie pour masquer l'origine du balayage.

```bash
# Balayage zombie (nécessite un hôte inactif)
nmap -sI zombie_host 192.168.1.1
# Lister les candidats inactifs
nmap --script ipidseq 192.168.1.0/24
```

## Options de Balayage Avancées

### Contrôle de la Résolution DNS

Contrôler comment Nmap gère les recherches DNS.

```bash
# Désactiver la résolution DNS
nmap -n 192.168.1.1
# Forcer la résolution DNS
nmap -R 192.168.1.1
# Serveurs DNS personnalisés
nmap --dns-servers 8.8.8.8,1.1.1.1 192.168.1.1
```

### Balayage IPv6 : `nmap -6`

Utiliser ces drapeaux Nmap pour des fonctionnalités supplémentaires comme le support IPv6.

```bash
# Balayage IPv6
nmap -6 2001:db8::1
# Balayage de réseau IPv6
nmap -6 2001:db8::/32
```

### Interface et Routage

Contrôler l'interface réseau et le routage.

```bash
# Spécifier l'interface réseau
nmap -e eth0 192.168.1.1
# Afficher l'interface et les routes
nmap --iflist
# Traceroute
nmap --traceroute 192.168.1.1
```

### Options Diverses

Drapeaux utiles supplémentaires.

```bash
# Afficher la version et quitter
nmap --version
# Envoyer au niveau ethernet
nmap --send-eth 192.168.1.1
# Envoyer au niveau IP
nmap --send-ip 192.168.1.1
```

## Exemples du Monde Réel

### Flux de Travail de Découverte de Réseau

Processus complet d'énumération de réseau.

```bash
# Étape 1 : Découvrir les hôtes actifs
nmap -sn 192.168.1.0/24
# Étape 2 : Balayage rapide des ports
nmap -sS -T4 --top-ports 1000 192.168.1.0/24
# Étape 3 : Balayage détaillé des hôtes intéressants
nmap -sS -sV -sC -O 192.168.1.50
# Étape 4 : Balayage complet
nmap -p- -A -T4 192.168.1.50
```

### Évaluation de Serveur Web

Se concentrer sur les services web et les vulnérabilités.

```bash
# Trouver les serveurs web
nmap -sS -p 80,443,8080,8443 --open 192.168.1.0/24
# Énumérer les services HTTP
nmap -sS -sV --script http-* 192.168.1.50
# Vérifier les vulnérabilités courantes
nmap --script vuln -p 80,443 192.168.1.50
```

### Énumération SMB/NetBIOS

L'exemple suivant énumère Netbios sur les réseaux cibles.

```bash
# Détection de service SMB
nmap -sV -p 139,445 192.168.1.0/24
# Découverte de nom NetBIOS
nmap -sU --script nbstat -p 137 192.168.1.0/24
# Scripts d'énumération SMB
nmap --script smb-enum-* -p 445 192.168.1.50
# Vérification des vulnérabilités SMB
nmap --script smb-vuln-* -p 445 192.168.1.50
```

### Évaluation Furtive

Reconnaissance à faible profil.

```bash
# Balayage ultra-furtif
nmap -sS -T0 -f --data-length 200 -D RND:10 192.168.1.1
# Balayage SYN fragmenté
nmap -sS -f --mtu 8 -T1 192.168.1.1
```

## Optimisation des Performances

### Stratégies de Balayage Rapide

Optimiser la vitesse de balayage pour les grands réseaux.

```bash
# Sweep réseau rapide
nmap -sS -T4 --min-rate 1000 --max-retries 1
192.168.1.0/24
# Balayage d'hôtes parallèle
nmap --min-hostgroup 50 --max-hostgroup 100
192.168.1.0/24
# Sauter les opérations lentes
nmap -sS -T4 --defeat-rst-ratelimit 192.168.1.0/24
```

### Gestion de la Mémoire et des Ressources

Contrôler l'utilisation des ressources pour la stabilité.

```bash
# Limiter les sondes parallèles
nmap --max-parallelism 10 192.168.1.0/24
# Contrôler les délais de balayage
nmap --scan-delay 100ms 192.168.1.1
# Définir le délai d'attente de l'hôte
nmap --host-timeout 10m 192.168.1.0/24
```

## Liens Pertinents

- <router-link to="/wireshark">Wireshark Aide-mémoire</router-link>
- <router-link to="/kali">Kali Linux Aide-mémoire</router-link>
- <router-link to="/cybersecurity">Cybersecurity Aide-mémoire</router-link>
- <router-link to="/linux">Linux Aide-mémoire</router-link>
- <router-link to="/shell">Shell Aide-mémoire</router-link>
- <router-link to="/network">Network Aide-mémoire</router-link>
- <router-link to="/devops">DevOps Aide-mémoire</router-link>
- <router-link to="/docker">Docker Aide-mémoire</router-link>

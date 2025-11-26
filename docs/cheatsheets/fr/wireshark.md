---
title: 'Fiche Mémo Wireshark'
description: 'Maîtrisez Wireshark avec notre fiche mémo complète : commandes essentielles, concepts clés et meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/wireshark-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Wireshark
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/wireshark">Apprenez Wireshark avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez l'analyse de paquets réseau avec Wireshark grâce à des laboratoires pratiques et des scénarios du monde réel. LabEx propose des cours complets sur Wireshark couvrant la capture de paquets essentielle, les filtres d'affichage, l'analyse de protocoles, le dépannage réseau et la surveillance de la sécurité. Maîtrisez l'analyse du trafic réseau et les techniques d'inspection des paquets.
</base-disclaimer-content>
</base-disclaimer>

## Filtres de Capture et Capture de Trafic

### Filtrage par Hôte

Capturez le trafic vers/depuis des hôtes spécifiques.

```bash
# Capturer le trafic depuis/vers une IP spécifique
host 192.168.1.100
# Capturer le trafic depuis une source spécifique
src host 192.168.1.100
# Capturer le trafic vers une destination spécifique
dst host 192.168.1.100
# Capturer le trafic depuis un sous-réseau
net 192.168.1.0/24
```

### Filtrage par Port

Capturez le trafic sur des ports spécifiques.

```bash
# Trafic HTTP (port 80)
port 80
# Trafic HTTPS (port 443)
port 443
# Trafic SSH (port 22)
port 22
# Trafic DNS (port 53)
port 53
# Plage de ports
portrange 1000-2000
```

### Filtrage par Protocole

Capturez le trafic d'un protocole spécifique.

```bash
# Trafic TCP uniquement
tcp
# Trafic UDP uniquement
udp
# Trafic ICMP uniquement
icmp
# Trafic ARP uniquement
arp
```

### Filtres de Capture Avancés

Combinez plusieurs conditions pour une capture précise.

```bash
# Trafic HTTP vers/depuis un hôte spécifique
host 192.168.1.100 and port 80
# Trafic TCP sauf SSH
tcp and not port 22
# Trafic entre deux hôtes
host 192.168.1.100 and host 192.168.1.200
# Trafic HTTP ou HTTPS
port 80 or port 443
```

### Sélection d'Interface

Choisissez les interfaces réseau pour la capture.

```bash
# Lister les interfaces disponibles
tshark -D
# Capturer sur une interface spécifique
# Interface Ethernet
eth0
# Interface WiFi
wlan0
# Interface de bouclage (loopback)
lo
```

### Options de Capture

Configurez les paramètres de capture.

```bash
# Limiter la taille du fichier de capture (Mo)
-a filesize:100
# Limiter la durée de la capture (secondes)
-a duration:300
# Tampon circulaire avec 10 fichiers
-b files:10
# Mode Promiscuous (capturer tout le trafic)
-p
```

## Filtres d'Affichage et Analyse de Paquets

### Filtres d'Affichage de Base

Filtres essentiels pour les protocoles courants et les types de trafic.

```bash
# Afficher uniquement le trafic HTTP
http
# Afficher uniquement le trafic HTTPS/TLS
tls
# Afficher uniquement le trafic DNS
dns
# Afficher uniquement le trafic TCP
tcp
# Afficher uniquement le trafic UDP
udp
# Afficher uniquement le trafic ICMP
icmp
```

### Filtrage par Adresse IP

Filtrez les paquets par adresses IP source et destination.

```bash
# Trafic depuis une IP spécifique
ip.src == 192.168.1.100
# Trafic vers une IP spécifique
ip.dst == 192.168.1.200
# Trafic entre deux IPs
ip.addr == 192.168.1.100
# Trafic depuis un sous-réseau
ip.src_net == 192.168.1.0/24
# Exclure une IP spécifique
not ip.addr == 192.168.1.1
```

### Filtrage par Port et Protocole

Filtrez par ports spécifiques et détails de protocole.

```bash
# Trafic sur un port spécifique
tcp.port == 80
# Filtrage du port source
tcp.srcport == 443
# Filtrage du port de destination
tcp.dstport == 22
# Plage de ports
tcp.port >= 1000 and tcp.port <=
2000
# Ports multiples
tcp.port in {80 443 8080}
```

## Analyse Spécifique aux Protocoles

### Analyse HTTP

Analysez les requêtes et réponses HTTP.

```bash
# Requêtes GET HTTP
http.request.method == "GET"
# Requêtes POST HTTP
http.request.method == "POST"
# Codes de statut HTTP spécifiques
http.response.code == 404
# Requêtes HTTP vers un hôte spécifique
http.host == "example.com"
# Requêtes HTTP contenant une chaîne
http contains "login"
```

### Analyse DNS

Examinez les requêtes et réponses DNS.

```bash
# Requêtes DNS uniquement
dns.flags.response == 0
# Réponses DNS uniquement
dns.flags.response == 1
# Requêtes DNS pour un domaine spécifique
dns.qry.name == "example.com"
# Requêtes DNS de type A
dns.qry.type == 1
# Erreurs/échecs DNS
dns.flags.rcode != 0
```

### Analyse TCP

Analysez les détails de la connexion TCP.

```bash
# Paquets TCP SYN (tentatives de connexion)
tcp.flags.syn == 1
# Paquets TCP RST (réinitialisations de connexion)
tcp.flags.reset == 1
# Retransmissions TCP
tcp.analysis.retransmission
# Problèmes de fenêtre TCP
tcp.analysis.window_update
# Établissement de connexion TCP
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### Analyse TLS/SSL

Examinez les détails de la connexion chiffrée.

```bash
# Paquets de handshake TLS
tls.handshake
# Informations de certificat TLS
tls.handshake.certificate
# Alertes et erreurs TLS
tls.alert
# Version TLS spécifique
tls.handshake.version == 0x0303
# Server Name Indication TLS
tls.handshake.extensions_server_name
```

### Dépannage Réseau

Identifiez les problèmes réseau courants.

```bash
# Messages d'inaccessibilité ICMP
icmp.type == 3
# Requêtes/réponses ARP
arp.opcode == 1 or arp.opcode == 2
# Trafic de diffusion (broadcast)
eth.dst == ff:ff:ff:ff:ff:ff
# Paquets fragmentés
ip.flags.mf == 1
# Paquets volumineux (problèmes MTU potentiels)
frame.len > 1500
```

### Filtrage Basé sur le Temps

Filtrez les paquets par horodatage et synchronisation.

```bash
# Paquets dans une plage horaire
frame.time >= "2024-01-01 10:00:00"
# Paquets de la dernière heure
frame.time_relative >= -3600
# Analyse du temps de réponse
tcp.time_delta > 1.0
# Temps d'inter-arrivée
frame.time_delta > 0.1
```

## Statistiques et Outils d'Analyse

### Hiérarchie des Protocoles

Visualisez la distribution des protocoles dans la capture.

```bash
# Accès via : Statistiques > Hiérarchie des protocoles
# Affiche le pourcentage de chaque protocole
# Identifie les protocoles les plus courants
# Utile pour un aperçu du trafic
# Équivalent en ligne de commande
tshark -r capture.pcap -q -z io,phs
```

### Conversations

Analysez la communication entre les points d'extrémité.

```bash
# Accès via : Statistiques > Conversations
# Conversations Ethernet
# Conversations IPv4/IPv6
# Conversations TCP/UDP
# Affiche les octets transférés, le nombre de paquets
# Équivalent en ligne de commande
tshark -r capture.pcap -q -z conv,tcp
```

### Graphiques I/O

Visualisez les tendances du trafic dans le temps.

```bash
# Accès via : Statistiques > Graphiques I/O
# Volume de trafic dans le temps
# Paquets par seconde
# Octets par seconde
# Appliquez des filtres pour un trafic spécifique
# Utile pour identifier les pics de trafic
```

### Informations d'Expert

Identifiez les problèmes réseau potentiels.

```bash
# Accès via : Analyser > Infos d'Expert
# Avertissements concernant les problèmes réseau
# Erreurs dans la transmission des paquets
# Problèmes de performance
# Préoccupations de sécurité
# Filtrer par sévérité des infos d'expert
tcp.analysis.flags
```

### Graphiques de Flux

Visualisez la séquence des paquets entre les points d'extrémité.

```bash
# Accès via : Statistiques > Graphique de Flux
# Montre la séquence des paquets
# Visualisation basée sur le temps
# Utile pour le dépannage
# Identifie les schémas de communication
```

### Analyse du Temps de Réponse

Mesurez les temps de réponse des applications.

```bash
# Temps de réponse HTTP
# Statistiques > HTTP > Requêtes
# Temps de réponse DNS
# Statistiques > DNS
# Temps de réponse du service TCP
# Statistiques > Graphiques de Flux TCP > Séquence Temporelle
```

## Opérations sur les Fichiers et Exportation

### Sauvegarde et Chargement des Captures

Gérez les fichiers de capture dans divers formats.

```bash
# Sauvegarder le fichier de capture
# Fichier > Enregistrer sous > capture.pcap
# Charger un fichier de capture
# Fichier > Ouvrir > existing.pcap
# Fusionner plusieurs fichiers de capture
# Fichier > Fusionner > sélectionner les fichiers
# Sauvegarder uniquement les paquets filtrés
# Fichier > Exporter les paquets spécifiés
```

### Options d'Exportation

Exportez des données spécifiques ou des sous-ensembles de paquets.

```bash
# Exporter les paquets sélectionnés
# Fichier > Exporter les paquets spécifiés
# Exporter les dissections de paquets
# Fichier > Exporter les dissections de paquets
# Exporter des objets depuis HTTP
# Fichier > Exporter les Objets > HTTP
# Exporter les clés SSL/TLS
# Édition > Préférences > Protocoles > TLS
```

### Capture en Ligne de Commande

Utilisez tshark pour la capture et l'analyse automatisées.

```bash
# Capturer vers un fichier
tshark -i eth0 -w capture.pcap
# Capturer avec filtre
tshark -i eth0 -f "port 80" -w http.pcap
# Lire et afficher les paquets
tshark -r capture.pcap
# Appliquer un filtre d'affichage au fichier
tshark -r capture.pcap -Y "tcp.port == 80"
```

### Traitement par Lots

Traitez plusieurs fichiers de capture automatiquement.

```bash
# Fusionner plusieurs fichiers
mergecap -w merged.pcap file1.pcap file2.pcap
# Diviser les fichiers de capture volumineux
editcap -c 1000 large.pcap split.pcap
# Extraire une plage horaire
editcap -A "2024-01-01 10:00:00" \
        -B "2024-01-01 11:00:00" \
        input.pcap output.pcap
```

## Performance et Optimisation

### Gestion de la Mémoire

Gérez efficacement les fichiers de capture volumineux.

```bash
# Utiliser un tampon circulaire pour la capture continue
-b filesize:100 -b files:10
# Limiter la taille de la capture de paquets
-s 96  # Capturer seulement les 96 premiers octets
# Utiliser des filtres de capture pour réduire les données
host 192.168.1.100 and port 80
# Désactiver la dissection de protocole pour la vitesse
-d tcp.port==80,http
```

### Optimisation de l'Affichage

Améliorez les performances de l'interface graphique avec de grands ensembles de données.

```bash
# Préférences à ajuster :
# Édition > Préférences > Apparence
# Sélection du schéma de couleurs
# Taille et type de police
# Options d'affichage des colonnes
# Paramètres du format d'heure
# Vue > Format d'Affichage de l'Heure
# Secondes depuis le début de la capture
# Heure du jour
# Heure UTC
```

### Flux de Travail d'Analyse Efficace

Meilleures pratiques pour l'analyse du trafic réseau.

```bash
# 1. Commencer par les filtres de capture
# Capturer uniquement le trafic pertinent
# 2. Utiliser progressivement les filtres d'affichage
# Commencer large, puis affiner
# 3. Utiliser les statistiques en premier
# Obtenir un aperçu avant l'analyse détaillée
# 4. Se concentrer sur des flux spécifiques
# Clic droit sur le paquet > Suivre > Flux TCP
```

### Automatisation et Scripting

Automatisez les tâches d'analyse courantes.

```bash
# Créer des boutons de filtre d'affichage personnalisés
# Vue > Expression de Filtre d'Affichage
# Utiliser des profils pour différents scénarios
# Édition > Profils de Configuration
# Script avec tshark
#!/bin/bash
tshark -r $1 -q -z endpoints,tcp | \
grep -v "Filter:" | head -20
```

## Installation et Configuration

### Installation Windows

Téléchargez et installez depuis le site officiel.

```bash
# Télécharger depuis wireshark.org
# Exécuter l'installateur en tant qu'Administrateur
# Inclure WinPcap/Npcap
pendant l'installation
# Installation en ligne de commande
(chocolatey)
choco install wireshark
# Vérifier l'installation
wireshark --version
```

### Installation Linux

Installez via le gestionnaire de paquets ou à partir des sources.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install wireshark
# Red Hat/CentOS/Fedora
sudo yum install wireshark
# ou
sudo dnf install wireshark
# Ajouter l'utilisateur au groupe wireshark
sudo usermod -a -G wireshark
$USER
```

### Installation macOS

Installez en utilisant Homebrew ou l'installateur officiel.

```bash
# Utilisation de Homebrew
brew install --cask wireshark
# Télécharger depuis wireshark.org
# Installer le paquet .dmg
# Outils en ligne de commande
brew install wireshark
```

## Configuration et Préférences

### Préférences d'Interface

Configurez les interfaces de capture et les options.

```bash
# Édition > Préférences > Capture
# Interface de capture par défaut
# Paramètres du mode Promiscuous
# Configuration de la taille du tampon
# Défilement automatique en capture en direct
# Paramètres spécifiques à l'interface
# Capture > Options > Détails de l'Interface
```

### Paramètres de Protocole

Configurez les dissections de protocoles et le décodage.

```bash
# Édition > Préférences > Protocoles
# Activer/désactiver les dissections de protocoles
# Configuration de l'attribution des ports
# Clés de déchiffrement (TLS, WEP, etc.)
# Options de réassemblage TCP
# Fonctionnalité Decode As
# Analyser > Décoder Comme
```

### Préférences d'Affichage

Personnalisez l'interface utilisateur et les options d'affichage.

```bash
# Édition > Préférences > Apparence
# Sélection du schéma de couleurs
# Taille et type de police
# Options d'affichage des colonnes
# Paramètres du format d'heure
# Vue > Format d'Affichage de l'Heure
# Secondes depuis le début de la capture
# Heure du jour
# Heure UTC
```

### Paramètres de Sécurité

Configurez les options liées à la sécurité et au déchiffrement.

```bash
# Configuration du déchiffrement TLS
# Édition > Préférences > Protocoles > TLS
# Liste des clés RSA
# Clés pré-partagées
# Emplacement du fichier journal des clés
# Désactiver les fonctionnalités potentiellement dangereuses
# Exécution des scripts Lua
# Résolveurs externes
```

## Techniques de Filtrage Avancées

### Opérateurs Logiques

Combinez plusieurs conditions de filtre.

```bash
# Opérateur ET (AND)
tcp.port == 80 and ip.src == 192.168.1.100
# Opérateur OU (OR)
tcp.port == 80 or tcp.port == 443
# Opérateur NON (NOT)
not icmp
# Parenthèses pour le regroupement
(tcp.port == 80 or tcp.port == 443) and ip.src ==
192.168.1.0/24
```

### Correspondance de Chaînes

Recherchez un contenu spécifique dans les paquets.

```bash
# Contient une chaîne (sensible à la casse)
tcp contains "password"
# Contient une chaîne (insensible à la casse)
tcp matches "(?i)login"
# Expressions régulières
http.request.uri matches "\.php$"
# Séquences d'octets
eth.src[0:3] == 00:11:22
```

### Comparaisons de Champs

Comparez les champs de paquets avec des valeurs et des plages.

```bash
# Égalité
tcp.srcport == 80
# Supérieur à/inférieur à
frame.len > 1000
# Vérifications de plage
tcp.port >= 1024 and tcp.port <= 65535
# Appartenance à un ensemble
tcp.port in {80 443 8080 8443}
# Existence du champ
tcp.options
```

### Analyse de Paquets Avancée

Identifiez des caractéristiques spécifiques des paquets et des anomalies.

```bash
# Paquets mal formés
_ws.malformed
# Paquets dupliqués
frame.number == tcp.analysis.duplicate_ack_num
# Paquets hors séquence
tcp.analysis.out_of_order
# Problèmes de fenêtre TCP
tcp.analysis.window_full
```

## Cas d'Utilisation Courants

### Dépannage Réseau

Identifiez et résolvez les problèmes de connectivité réseau.

```bash
# Trouver les délais d'expiration de connexion
tcp.analysis.retransmission and tcp.analysis.rto
# Identifier les connexions lentes
tcp.time_delta > 1.0
# Trouver la congestion réseau
tcp.analysis.window_full
# Problèmes de résolution DNS
dns.flags.rcode != 0
# Problèmes de découverte MTU
icmp.type == 3 and icmp.code == 4
```

### Analyse de Sécurité

Détectez les menaces de sécurité potentielles et les activités suspectes.

```bash
# Détection de scan de ports
tcp.flags.syn == 1 and tcp.flags.ack == 0
# Nombre important de connexions depuis une seule IP
# Utiliser Statistiques > Conversations
# Requêtes DNS suspectes
dns.qry.name contains "dga" or dns.qry.name matches
"^[a-z]{8,}\.com$"
# POST HTTP vers des URL suspectes
http.request.method == "POST" and http.request.uri
contains "/upload"
# Modèles de trafic inhabituels
# Vérifier les graphiques I/O pour les pics
```

### Performance Applicative

Surveillez et analysez les temps de réponse des applications.

```bash
# Analyse des applications Web
http.time > 2.0
# Surveillance des connexions à la base de données
tcp.port == 3306 and tcp.analysis.initial_rtt > 0.1
# Performance des transferts de fichiers
tcp.stream eq X and tcp.analysis.bytes_in_flight
# Analyse de la qualité VoIP
rtp.jitter > 30 or rtp.marker == 1
```

### Investigation de Protocoles

Plongez dans des protocoles spécifiques et leur comportement.

```bash
# Trafic Email
tcp.port == 25 or tcp.port == 587 or tcp.port == 993
# Transferts de fichiers FTP
ftp-data or ftp.request.command == "RETR"
# Partage de fichiers SMB/CIFS
smb2 or smb
# Analyse des baux DHCP
bootp.option.dhcp == 1 or bootp.option.dhcp == 2
```

## Liens Pertinents

- <router-link to="/nmap">Feuille de triche Nmap</router-link>
- <router-link to="/cybersecurity">Feuille de triche Cybersécurité</router-link>
- <router-link to="/kali">Feuille de triche Kali Linux</router-link>
- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/network">Feuille de triche Réseau</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>
- <router-link to="/docker">Feuille de triche Docker</router-link>

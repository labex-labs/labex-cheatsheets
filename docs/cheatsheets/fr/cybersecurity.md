---
title: 'Fiche de triche Cybersécurité | LabEx'
description: "Apprenez la cybersécurité avec cette fiche de triche complète. Référence rapide sur les concepts de sécurité, la détection des menaces, l'évaluation des vulnérabilités, les tests d'intrusion et les meilleures pratiques de sécurité de l'information."
pdfUrl: '/cheatsheets/pdf/cybersecurity-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche en cybersécurité
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/cybersecurity">Apprenez la cybersécurité avec des laboratoires pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la cybersécurité grâce à des laboratoires pratiques et des scénarios du monde réel. LabEx propose des cours complets en cybersécurité couvrant l'identification des menaces, l'évaluation de la sécurité, le durcissement des systèmes, la réponse aux incidents et les techniques de surveillance. Apprenez à protéger les systèmes et les données contre les cybermenaces en utilisant des outils standard de l'industrie et les meilleures pratiques.
</base-disclaimer-content>
</base-disclaimer>

## Fondamentaux de la sécurité des systèmes

### Gestion des comptes utilisateurs

Contrôler l'accès aux systèmes et aux données.

```bash
# Ajouter un nouvel utilisateur
sudo adduser username
# Définir la politique de mot de passe
sudo passwd -l username
# Accorder les privilèges sudo
sudo usermod -aG sudo username
# Voir les informations de l'utilisateur
id username
# Lister tous les utilisateurs
cat /etc/passwd
```

### Permissions et sécurité des fichiers

Configurer un accès sécurisé aux fichiers et aux répertoires.

```bash
# Changer les permissions de fichier (lecture, écriture, exécution)
chmod 644 file.txt
# Changer le propriétaire
chown user:group file.txt
# Définir les permissions de manière récursive
chmod -R 755 directory/
# Voir les permissions de fichier
ls -la
```

<BaseQuiz id="cybersecurity-chmod-1" correct="C">
  <template #question>
    Que définit <code>chmod 644 file.txt</code> pour les permissions de fichier ?
  </template>
  
  <BaseQuizOption value="A">Lecture, écriture, exécution pour tous les utilisateurs</BaseQuizOption>
  <BaseQuizOption value="B">Lecture, écriture, exécution pour le propriétaire ; lecture pour les autres</BaseQuizOption>
  <BaseQuizOption value="C" correct>Lecture, écriture pour le propriétaire ; lecture pour le groupe et les autres</BaseQuizOption>
  <BaseQuizOption value="D">Lecture seule pour tous les utilisateurs</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 644</code> définit : propriétaire = 6 (rw-), groupe = 4 (r--), autres = 4 (r--). C'est un ensemble de permissions courant pour les fichiers qui doivent être lisibles par tous mais modifiables uniquement par le propriétaire.
  </BaseQuizAnswer>
</BaseQuiz>

### Configuration de la sécurité réseau

Sécuriser les connexions réseau et les services.

```bash
# Configurer le pare-feu (UFW)
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw deny 23/tcp
# Vérifier les ports ouverts
netstat -tuln
sudo ss -tuln
```

<BaseQuiz id="cybersecurity-firewall-1" correct="B">
  <template #question>
    Que fait <code>sudo ufw allow 22/tcp</code> ?
  </template>
  
  <BaseQuizOption value="A">Bloque le port 22</BaseQuizOption>
  <BaseQuizOption value="B" correct>Autorise le trafic TCP sur le port 22 (SSH)</BaseQuizOption>
  <BaseQuizOption value="C">Active l'UDP sur le port 22</BaseQuizOption>
  <BaseQuizOption value="D">Affiche l'état du pare-feu</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>ufw allow 22/tcp</code> crée une règle de pare-feu qui autorise les connexions TCP entrantes sur le port 22, qui est le port SSH par défaut. Ceci est essentiel pour l'accès distant au serveur.
  </BaseQuizAnswer>
</BaseQuiz>

### Mises à jour et correctifs du système

Maintenir les systèmes à jour avec les derniers correctifs de sécurité.

```bash
# Mettre à jour les listes de paquets (Ubuntu/Debian)
sudo apt update
# Mettre à niveau tous les paquets
sudo apt upgrade
# Mises à jour de sécurité automatiques
sudo apt install unattended-upgrades
```

### Gestion des services

Contrôler et surveiller les services système.

```bash
# Arrêter les services inutiles
sudo systemctl stop service_name
sudo systemctl disable service_name
# Vérifier l'état du service
sudo systemctl status ssh
# Voir les services en cours d'exécution
systemctl list-units --type=service --state=running
```

### Surveillance des journaux

Surveiller les journaux système pour les événements de sécurité.

```bash
# Voir les journaux d'authentification
sudo tail -f /var/log/auth.log
# Vérifier les journaux système
sudo journalctl -f
# Rechercher les échecs de connexion
grep "Failed password" /var/log/auth.log
```

<BaseQuiz id="cybersecurity-logs-1" correct="A">
  <template #question>
    Que fait <code>tail -f /var/log/auth.log</code> ?
  </template>
  
  <BaseQuizOption value="A" correct>Suit le fichier journal d'authentification en temps réel</BaseQuizOption>
  <BaseQuizOption value="B">Affiche uniquement les tentatives de connexion échouées</BaseQuizOption>
  <BaseQuizOption value="C">Supprime les anciennes entrées de journal</BaseQuizOption>
  <BaseQuizOption value="D">Archive le fichier journal</BaseQuizOption>
  
  <BaseQuizAnswer>
    L'option <code>-f</code> fait en sorte que <code>tail</code> suive le fichier, affichant les nouvelles entrées de journal au fur et à mesure qu'elles sont écrites. Ceci est utile pour la surveillance en temps réel des événements d'authentification et des incidents de sécurité.
  </BaseQuizAnswer>
</BaseQuiz>

## Sécurité des mots de passe et authentification

Mettre en œuvre des mécanismes d'authentification robustes et des politiques de mots de passe.

### Création de mots de passe robustes

Générer et gérer des mots de passe sécurisés en suivant les meilleures pratiques.

```bash
# Générer un mot de passe fort
openssl rand -base64 32
# Exigences de force du mot de passe :
# - Minimum 12 caractères
# - Mélange de majuscules, minuscules, chiffres, symboles
# - Pas de mots de dictionnaire ni d'informations personnelles
# - Unique pour chaque compte
```

### Authentification multifacteur (MFA)

Ajouter des couches d'authentification supplémentaires au-delà des mots de passe.

```bash
# Installer Google Authenticator
sudo apt install libpam-googleauthenticator
# Configurer le MFA pour SSH
google-authenticator
# Activer dans la configuration SSH
sudo nano /etc/pam.d/sshd
# Ajouter : auth required pam_google_authenticator.so
```

### Gestion des mots de passe

Utiliser des gestionnaires de mots de passe et des pratiques de stockage sécurisé.

```bash
# Installer un gestionnaire de mots de passe (KeePassXC)
sudo apt install keepassxc
# Meilleures pratiques :
# - Utiliser des mots de passe uniques pour chaque service
# - Activer les fonctionnalités de verrouillage automatique
# - Rotation régulière des mots de passe pour les comptes critiques
# - Sauvegarde sécurisée de la base de données des mots de passe
```

## Sécurité et surveillance du réseau

### Analyse de ports et découverte

Identifier les ports ouverts et les services en cours d'exécution.

```bash
# Analyse de ports de base avec Nmap
nmap -sT target_ip
# Détection de version de service
nmap -sV target_ip
# Analyse complète
nmap -A target_ip
# Analyser des ports spécifiques
nmap -p 22,80,443 target_ip
# Analyser une plage d'adresses IP
nmap 192.168.1.1-254
```

### Analyse du trafic réseau

Surveiller et analyser les communications réseau.

```bash
# Capturer des paquets avec tcpdump
sudo tcpdump -i eth0
# Sauvegarder dans un fichier
sudo tcpdump -w capture.pcap
# Filtrer le trafic spécifique
sudo tcpdump host 192.168.1.1
# Surveiller un port spécifique
sudo tcpdump port 80
```

### Configuration du pare-feu

Contrôler le trafic réseau entrant et sortant.

```bash
# UFW (Uncomplicated Firewall)
sudo ufw status
sudo ufw allow ssh
sudo ufw deny 23
# Règles iptables
sudo iptables -L
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

### Gestion des certificats SSL/TLS

Mettre en œuvre des communications sécurisées avec chiffrement.

```bash
# Générer un certificat auto-signé
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
# Vérifier les détails du certificat
openssl x509 -in cert.pem -text -noout
# Tester la connexion SSL
openssl s_client -connect example.com:443
```

## Évaluation des vulnérabilités

### Analyse des vulnérabilités du système

Identifier les faiblesses de sécurité dans les systèmes et les applications.

```bash
# Installer le scanner Nessus
# Télécharger depuis tenable.com
sudo dpkg -i Nessus-X.X.X-ubuntu1404_amd64.deb
# Démarrer le service Nessus
sudo systemctl start nessusd
# Accéder à l'interface web à https://localhost:8834
# Utilisation d'OpenVAS (alternative gratuite)
sudo apt install openvas
sudo gvm-setup
```

### Tests de sécurité des applications Web

Tester les applications Web pour les vulnérabilités courantes.

```bash
# Utilisation du scanner web Nikto
nikto -h http://target.com
# Énumération de répertoires
dirb http://target.com
# Test d'injection SQL
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

### Outils d'audit de sécurité

Utilitaires d'évaluation de sécurité complets.

```bash
# Audit de sécurité Lynis
sudo apt install lynis
sudo lynis audit system
# Vérifier les rootkits
sudo apt install chkrootkit
sudo chkrootkit
# Surveillance de l'intégrité des fichiers
sudo apt install aide
sudo aideinit
```

### Sécurité de la configuration

Vérifier la configuration sécurisée du système et des applications.

```bash
# Vérification de la sécurité SSH
ssh-audit target_ip
# Test de configuration SSL
testssl.sh https://target.com
# Vérifier les permissions des fichiers sensibles
ls -la /etc/shadow /etc/passwd /etc/group
```

## Réponse aux incidents et criminalistique

### Analyse des journaux et enquête

Analyser les journaux système pour identifier les incidents de sécurité.

```bash
# Rechercher des activités suspectes
grep -i "failed\|error\|denied" /var/log/auth.log
# Compter les échecs de connexion
grep "Failed password" /var/log/auth.log | wc -l
# Trouver les adresses IP uniques dans les journaux
awk '/Failed password/ {print $11}' /var/log/auth.log | sort | uniq -c
# Surveiller l'activité des journaux en direct
tail -f /var/log/syslog
```

### Criminalistique réseau

Enquêter sur les incidents de sécurité basés sur le réseau.

```bash
# Analyser le trafic réseau avec Wireshark
# Installation : sudo apt install wireshark
# Capturer le trafic en direct
sudo wireshark
# Analyser les fichiers capturés
wireshark capture.pcap
# Analyse en ligne de commande avec tshark
tshark -r capture.pcap -Y "http.request"
```

### Criminalistique système

Préserver et analyser les preuves numériques.

```bash
# Créer une image disque
sudo dd if=/dev/sda of=/mnt/evidence/disk_image.dd bs=4096
# Calculer les hachages de fichiers pour l'intégrité
md5sum important_file.txt
sha256sum important_file.txt
# Rechercher un contenu de fichier spécifique
grep -r "password" /home/user/
# Lister les fichiers modifiés récemment
find /home -mtime -7 -type f
```

### Documentation des incidents

Documenter correctement les incidents de sécurité pour analyse.

```bash
# Liste de contrôle de réponse aux incidents :
# 1. Isoler les systèmes affectés
# 2. Préserver les preuves
# 3. Documenter la chronologie des événements
# 4. Identifier les vecteurs d'attaque
# 5. Évaluer les dommages et l'exposition des données
# 6. Mettre en œuvre des mesures de confinement
# 7. Planifier les procédures de récupération
```

## Renseignements sur les menaces

Recueillir et analyser des informations sur les menaces de sécurité actuelles et émergentes.

### OSINT (Open Source Intelligence)

Collecter des informations sur les menaces disponibles publiquement.

```bash
# Rechercher des informations sur le domaine
whois example.com
# Requête DNS
dig example.com
nslookup example.com
# Trouver des sous-domaines
sublist3r -d example.com
# Vérifier les bases de données de réputation
# VirusTotal, URLVoid, AbuseIPDB
```

### Outils de chasse aux menaces (Threat Hunting)

Rechercher de manière proactive des menaces dans votre environnement.

```bash
# Recherche d'IOC (Indicateurs de compromission)
grep -r "suspicious_hash" /var/log/
# Vérifier la présence d'IP malveillantes
grep "192.168.1.100" /var/log/auth.log
# Comparaison de hachage de fichiers
find /tmp -type f -exec sha256sum {} \;
```

### Flux de menaces et renseignements

Se tenir au courant des dernières informations sur les menaces.

```bash
# Sources populaires de renseignements sur les menaces :
# - MISP (Malware Information Sharing Platform)
# - Flux STIX/TAXII
# - Flux commerciaux (CrowdStrike, FireEye)
# - Flux gouvernementaux (US-CERT, CISA)
# Exemple : Vérifier l'IP par rapport aux flux de menaces
curl -s "https://api.threatintel.com/check?ip=1.2.3.4"
```

### Modélisation des menaces

Identifier et évaluer les menaces de sécurité potentielles.

```bash
# Catégories du modèle de menace STRIDE :
# - Spoofing (usurpation d'identité)
# - Tampering (altération des données)
# - Repudiation (répudiation des actions)
# - Information Disclosure (divulgation d'informations)
# - Denial of Service (déni de service)
# - Elevation of Privilege (élévation de privilèges)
```

## Chiffrement et protection des données

Mettre en œuvre un chiffrement fort pour protéger les données sensibles.

### Chiffrement de fichiers et de disques

Chiffrer les fichiers et les périphériques de stockage pour protéger les données au repos.

```bash
# Chiffrer un fichier avec GPG
gpg -c sensitive_file.txt
# Déchiffrer le fichier
gpg sensitive_file.txt.gpg
# Chiffrement complet du disque avec LUKS
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup luksOpen /dev/sdb encrypted_drive
# Générer des clés SSH
ssh-keygen -t rsa -b 4096
# Configurer l'authentification par clé SSH
ssh-copy-id user@server
```

### Chiffrement réseau

Sécuriser les communications réseau avec des protocoles de chiffrement.

```bash
# Configuration VPN avec OpenVPN
sudo apt install openvpn
sudo openvpn --config client.ovpn
```

### Gestion des certificats

Gérer les certificats numériques pour des communications sécurisées.

```bash
# Créer une autorité de certification
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -key ca-key.pem -out ca.pem
# Générer un certificat serveur
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr
# Signer le certificat avec l'AC
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -out server.pem
```

### Prévention de la perte de données

Empêcher l'exfiltration et la fuite non autorisées de données.

```bash
# Surveiller l'accès aux fichiers
sudo apt install auditd
# Configurer les règles d'audit
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
# Rechercher dans les journaux d'audit
sudo ausearch -k passwd_changes
```

## Automatisation et orchestration de la sécurité

Automatiser les tâches de sécurité et les procédures de réponse.

### Automatisation de l'analyse de sécurité

Planifier des analyses de sécurité et des évaluations régulières.

```bash
# Script d'analyse Nmap automatisée
#!/bin/bash
DATE=$(date +%Y-%m-%d)
nmap -sS -O 192.168.1.0/24 > /var/log/nmap-scan-$DATE.log
# Planifier avec cron
# 0 2 * * * /path/to/security-scan.sh
```

```bash
# Analyse de vulnérabilités automatisée
#!/bin/bash
nikto -h $1 -o /var/log/nikto-$(date +%Y%m%d).txt
```

### Scripts de surveillance des journaux

Automatiser l'analyse des journaux et l'alerte.

```bash
# Surveillance des échecs de connexion
#!/bin/bash
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | tail -n 100 | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    echo "Nombre élevé d'échecs de connexion détecté : $FAILED_LOGINS" | mail -s "Alerte de sécurité" admin@company.com
fi
```

### Automatisation de la réponse aux incidents

Automatiser les procédures initiales de réponse aux incidents.

```bash
# Script de réponse automatisée aux menaces
#!/bin/bash
SUSPICIOUS_IP=$1
# Bloquer l'IP au pare-feu
sudo ufw deny from $SUSPICIOUS_IP
# Enregistrer l'action
echo "$(date): IP suspecte bloquée $SUSPICIOUS_IP" >> /var/log/security-actions.log
# Envoyer une alerte
echo "IP suspecte bloquée : $SUSPICIOUS_IP" | mail -s "IP Bloquée" security@company.com
```

### Gestion de la configuration

Maintenir des configurations système sécurisées.

```bash
# Exemple de playbook Ansible
---
- name: Durcir la configuration SSH
  hosts: all
  tasks:
    - name: Désactiver la connexion root
      lineinfile:
        path: /etc/ssh/sshd_config
        line: 'PermitRootLogin no'
    - name: Redémarrer le service SSH
      service:
        name: sshd
        state: restarted
```

## Conformité et gestion des risques

### Mise en œuvre de la politique de sécurité

Mettre en œuvre et maintenir les politiques et procédures de sécurité.

```bash
# Application de la politique de mot de passe (PAM)
sudo nano /etc/pam.d/common-password
# Ajouter : password required pam_pwquality.so minlen=12
# Politique de verrouillage de compte
sudo nano /etc/pam.d/common-auth
# Ajouter : auth required pam_tally2.so deny=5 unlock_time=900
```

### Vérification de l'audit et de la conformité

Vérifier la conformité aux normes et réglementations de sécurité.

```bash
# Outils CIS (Center for Internet Security)
sudo apt install cis-cat-lite
# Exécuter l'évaluation CIS
./CIS-CAT.sh -a -s
```

### Outils d'évaluation des risques

Évaluer et quantifier les risques de sécurité.

```bash
# Calcul de la matrice de risque :
# Risque = Probabilité × Impact
# Faible (1-3), Moyen (4-6), Élevé (7-9)
# Priorisation des vulnérabilités
# Calcul du score CVSS
# Score de base = Impact × Exploitabilité
```

### Documentation et rapports

Maintenir une documentation et des rapports de sécurité appropriés.

```bash
# Modèle de rapport d'incident de sécurité :
# - Date et heure de l'incident
# - Systèmes affectés
# - Vecteurs d'attaque identifiés
# - Données compromises
# - Actions entreprises
# - Leçons apprises
# - Plan de remédiation
```

## Installation d'outils de sécurité

Installer et configurer les outils de cybersécurité essentiels.

### Gestionnaires de paquets

Installer des outils à l'aide des gestionnaires de paquets du système.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap wireshark tcpdump
# CentOS/RHEL
sudo yum install nmap wireshark tcpdump
# Arch Linux
sudo pacman -S nmap wireshark-qt tcpdump
```

### Distributions de sécurité

Distributions Linux spécialisées pour les professionnels de la sécurité.

```bash
# Kali Linux - Tests d'intrusion
# Télécharger depuis : https://www.kali.org/
# Parrot Security OS
# Télécharger depuis : https://www.parrotsec.org/
# BlackArch Linux
# Télécharger depuis : https://blackarch.org/
```

### Vérification des outils

Vérifier l'installation et la configuration de base des outils.

```bash
# Vérifier les versions des outils
nmap --version
wireshark --version
# Test de fonctionnalité de base
nmap 127.0.0.1
# Configurer les chemins d'accès des outils
export PATH=$PATH:/opt/tools/bin
echo 'export PATH=$PATH:/opt/tools/bin' >> ~/.bashrc
```

## Meilleures pratiques de configuration de sécurité

Appliquer des configurations de durcissement de la sécurité sur les systèmes et les applications.

### Durcissement du système

Sécuriser les configurations du système d'exploitation.

```bash
# Désactiver les services inutiles
sudo systemctl disable telnet
sudo systemctl disable ftp
# Définir des permissions de fichier sécurisées
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 644 /etc/passwd
# Configurer les limites du système
echo "* hard core 0" >> /etc/security/limits.conf
```

### Paramètres de sécurité réseau

Mettre en œuvre des configurations réseau sécurisées.

```bash
# Désactiver le transfert IP (si ce n'est pas un routeur)
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
# Activer les cookies SYN
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
# Désactiver les redirections ICMP
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
```

### Sécurité des applications

Sécuriser les configurations des applications et des services.

```bash
# En-têtes de sécurité Apache
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
# Configuration de sécurité Nginx
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
```

### Sécurité des sauvegardes et récupération

Mettre en œuvre des procédures sécurisées de sauvegarde et de reprise après sinistre.

```bash
# Sauvegardes chiffrées avec rsync
rsync -av --password-file=/etc/rsyncd.secrets /data/ backup@server::backups/
# Tester l'intégrité de la sauvegarde
tar -tzf backup.tar.gz > /dev/null && echo "Sauvegarde OK"
# Vérification automatisée des sauvegardes
#!/bin/bash
find /backups -name "*.tar.gz" -exec tar -tzf {} \; > /dev/null
```

## Techniques de sécurité avancées

Mettre en œuvre des mesures de sécurité avancées et des stratégies de défense.

### Systèmes de détection d'intrusion

Déployer et configurer des IDS/IPS pour la détection des menaces.

```bash
# Installer Suricata IDS
sudo apt install suricata
# Configurer les règles
sudo nano /etc/suricata/suricata.yaml
# Mettre à jour les règles
sudo suricata-update
# Démarrer Suricata
sudo systemctl start suricata
# Surveiller les alertes
tail -f /var/log/suricata/fast.log
```

### Gestion des informations et des événements de sécurité (SIEM)

Centraliser et analyser les journaux de sécurité et les événements.

```bash
# Pile ELK (Elasticsearch, Logstash, Kibana)
# Installer Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update && sudo apt install elasticsearch
```

## Sensibilisation et formation à la sécurité

### Défense contre l'ingénierie sociale

Reconnaître et prévenir les attaques d'ingénierie sociale.

```bash
# Techniques d'identification du phishing :
# - Vérifier attentivement l'e-mail de l'expéditeur
# - Vérifier les liens avant de cliquer (survol)
# - Rechercher les erreurs d'orthographe/grammaire
# - Se méfier des demandes urgentes
# - Vérifier les demandes via un canal séparé
# En-têtes de sécurité des e-mails à vérifier :
# Enregistrements SPF, DKIM, DMARC
```

### Développement de la culture de sécurité

Construire une culture organisationnelle consciente de la sécurité.

```bash
# Éléments du programme de sensibilisation à la sécurité :
# - Sessions de formation régulières
# - Tests de simulation de phishing
# - Mises à jour des politiques de sécurité
# - Procédures de signalement d'incidents
# - Reconnaissance des bonnes pratiques de sécurité
# Métriques à suivre :
# - Taux d'achèvement de la formation
# - Taux de clics lors des simulations de phishing
# - Signalement des incidents de sécurité
```

## Liens pertinents

- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/kali">Feuille de triche Kali Linux</router-link>
- <router-link to="/nmap">Feuille de triche Nmap</router-link>
- <router-link to="/wireshark">Feuille de triche Wireshark</router-link>
- <router-link to="/hydra">Feuille de triche Hydra</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>
- <router-link to="/git">Feuille de triche Git</router-link>

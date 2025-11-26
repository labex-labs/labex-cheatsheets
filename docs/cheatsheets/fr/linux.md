---
title: 'Fiche Mémo Linux'
description: 'Apprenez Linux avec notre fiche mémo complète couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a href="https://linux-commands.labex.io/" target="_blank">Visiter Commandes Linux</a>
</base-disclaimer-title>
<base-disclaimer-content>
Pour obtenir des documents de référence complets sur les commandes Linux, des exemples de syntaxe et une documentation détaillée, veuillez visiter <a href="https://linux-commands.labex.io/" target="_blank">linux-commands.labex.io</a>. Ce site indépendant fournit des feuilles de triche Linux complètes couvrant les commandes essentielles, les concepts et les meilleures pratiques pour les administrateurs et développeurs Linux.
</base-disclaimer-content>
</base-disclaimer>

## Informations et État du Système

### Informations Système : `uname`

Afficher les informations système, y compris le noyau et l'architecture.

```bash
# Afficher le nom du noyau
uname
# Afficher toutes les informations système
uname -a
# Afficher la version du noyau
uname -r
# Afficher l'architecture
uname -m
# Afficher le système d'exploitation
uname -o
```

### Informations Matérielles : `lscpu`, `lsblk`

Visualiser les spécifications matérielles détaillées et les périphériques de bloc.

```bash
# Informations CPU
lscpu
# Périphériques de bloc (disques, partitions)
lsblk
# Informations mémoire
free -h
# Utilisation du disque par système de fichiers
df -h
```

### Temps de Fonctionnement du Système : `uptime`

Afficher le temps de fonctionnement du système et les moyennes de charge.

```bash
# Temps de fonctionnement et charge du système
uptime
# Informations de temps de fonctionnement plus détaillées
uptime -p
# Afficher le temps de fonctionnement depuis une date spécifique
uptime -s
```

### Utilisateurs Actuels : `who`, `w`

Afficher les utilisateurs actuellement connectés et leurs activités.

```bash
# Afficher les utilisateurs connectés
who
# Informations utilisateur détaillées avec activités
w
# Afficher le nom d'utilisateur actuel
whoami
# Afficher l'historique de connexion
last
```

### Variables d'Environnement : `env`

Afficher et gérer les variables d'environnement.

```bash
# Afficher toutes les variables d'environnement
env
# Afficher une variable spécifique
echo $HOME
# Définir une variable d'environnement
export PATH=$PATH:/nouveau/chemin
# Afficher la variable PATH
echo $PATH
```

### Date et Heure : `date`, `timedatectl`

Afficher et définir la date et l'heure du système.

```bash
# Date et heure actuelles
date
# Définir l'heure du système (en tant que root)
date MMddhhmmyyyy
# Informations sur le fuseau horaire
timedatectl
# Définir le fuseau horaire
timedatectl set-timezone America/New_York
```

## Opérations sur les Fichiers et Répertoires

### Lister les Fichiers : `ls`

Afficher les fichiers et répertoires avec diverses options de formatage.

```bash
# Lister les fichiers dans le répertoire courant
ls
# Liste détaillée avec permissions
ls -l
# Afficher les fichiers cachés
ls -la
# Tailles de fichiers lisibles par l'homme
ls -lh
# Trier par heure de modification
ls -lt
```

### Naviguer dans les Répertoires : `cd`, `pwd`

Changer de répertoire et afficher l'emplacement actuel.

```bash
# Aller au répertoire personnel
cd
# Aller à un répertoire spécifique
cd /chemin/vers/repertoire
# Monter d'un niveau
cd ..
# Afficher le répertoire courant
pwd
# Aller au répertoire précédent
cd -
```

### Créer et Supprimer : `mkdir`, `rmdir`, `rm`

Créer et supprimer des fichiers et des répertoires.

```bash
# Créer un répertoire
mkdir nouveau_repertoire
# Créer des répertoires imbriqués
mkdir -p chemin/vers/repertoire/imbrique
# Supprimer un répertoire vide
rmdir nom_repertoire
# Supprimer un fichier
rm nom_fichier
# Supprimer un répertoire récursivement
rm -rf nom_repertoire
```

### Voir le Contenu des Fichiers : `cat`, `less`, `head`, `tail`

Afficher le contenu des fichiers en utilisant diverses méthodes et pagination.

```bash
# Afficher le fichier entier
cat nom_fichier
# Voir le fichier avec pagination
less nom_fichier
# Afficher les 10 premières lignes
head nom_fichier
# Afficher les 10 dernières lignes
tail nom_fichier
# Suivre les changements de fichier en temps réel
tail -f fichier_log
```

### Copier et Déplacer : `cp`, `mv`

Copier et déplacer des fichiers et des répertoires.

```bash
# Copier un fichier
cp source.txt destination.txt
# Copier un répertoire récursivement
cp -r repertoire_source/ repertoire_destination/
# Déplacer/renommer un fichier
mv ancien_nom.txt nouveau_nom.txt
# Déplacer vers un répertoire différent
mv fichier.txt /chemin/vers/destination/
# Copier avec préservation des attributs
cp -p fichier.txt sauvegarde.txt
```

### Rechercher des Fichiers : `find`, `locate`

Rechercher des fichiers et des répertoires par nom, type ou propriétés.

```bash
# Rechercher par nom
find /chemin -name "nom_fichier"
# Trouver les fichiers modifiés dans les 7 derniers jours
find /chemin -mtime -7
# Rechercher par type de fichier
find /chemin -type f -name "*.txt"
# Localiser rapidement les fichiers (nécessite updatedb)
locate nom_fichier
# Trouver et exécuter une commande
find /chemin -name "*.log" -exec rm {} \;
```

### Permissions de Fichier : `chmod`, `chown`

Modifier les permissions et la propriété des fichiers.

```bash
# Changer les permissions (numérique)
chmod 755 nom_fichier
# Ajouter la permission d'exécution
chmod +x script.sh
# Changer la propriété
chown utilisateur:groupe nom_fichier
# Changer la propriété récursivement
chown -R utilisateur:groupe repertoire/
# Voir les permissions du fichier
ls -l nom_fichier
```

## Gestion des Processus

### Liste des Processus : `ps`

Afficher les processus en cours d'exécution et leurs détails.

```bash
# Afficher les processus de l'utilisateur
ps
# Afficher tous les processus avec détails
ps aux
# Afficher l'arborescence des processus
ps -ef --forest
# Afficher les processus par utilisateur
ps -u nom_utilisateur
```

### Tuer les Processus : `kill`, `killall`

Terminer les processus par PID ou par nom.

```bash
# Moniteur de processus en temps réel
top
# Tuer un processus par PID
kill 1234
# Tuer un processus de force
kill -9 1234
# Tuer par nom de processus
killall nom_processus
# Lister tous les signaux
kill -l
# Envoyer un signal spécifique
kill -HUP 1234
```

### Tâches d'Arrière-plan : `jobs`, `bg`, `fg`

Gérer les processus d'arrière-plan et de premier plan.

```bash
# Lister les tâches actives
jobs
# Envoyer une tâche à l'arrière-plan
bg %1
# Ramener une tâche au premier plan
fg %1
# Exécuter une commande en arrière-plan
commande &
# Détacher du terminal
nohup commande &
```

### Moniteur Système : `htop`, `systemctl`

Surveiller les ressources système et gérer les services.

```bash
# Visionneuse de processus améliorée (si installé)
htop
# Vérifier l'état du service
systemctl status nom_service
# Démarrer le service
systemctl start nom_service
# Activer le service au démarrage
systemctl enable nom_service
# Voir les journaux système
journalctl -f
```

## Opérations Réseau

### Configuration Réseau : `ip`, `ifconfig`

Afficher et configurer les interfaces réseau.

```bash
# Afficher les interfaces réseau
ip addr show
# Afficher la table de routage
ip route show
# Configurer l'interface (temporaire)
ip addr add 192.168.1.10/24 dev eth0
# Mettre l'interface en marche/arrêt
ip link set eth0 up
# Configuration d'interface héritée
ifconfig
```

### Test Réseau : `ping`, `traceroute`

Tester la connectivité réseau et tracer les chemins des paquets.

```bash
# Tester la connectivité
ping google.com
# Ping avec limite de compte
ping -c 4 192.168.1.1
# Tracer la route vers la destination
traceroute google.com
# MTR - outil de diagnostic réseau
mtr google.com
```

### Analyse des Ports et Connexions : `netstat`, `ss`

Afficher les connexions réseau et les ports en écoute.

```bash
# Afficher toutes les connexions
netstat -tuln
# Afficher les ports en écoute
netstat -tuln | grep LISTEN
# Remplacement moderne de netstat
ss -tuln
# Afficher les processus utilisant les ports
netstat -tulnp
# Vérifier un port spécifique
netstat -tuln | grep :80
```

### Transfert de Fichiers : `scp`, `rsync`

Transférer des fichiers en toute sécurité entre systèmes.

```bash
# Copier un fichier vers un hôte distant
scp fichier.txt utilisateur@hote:/chemin/
# Copier depuis un hôte distant
scp utilisateur@hote:/chemin/fichier.txt ./
# Synchroniser les répertoires
rsync -avz repertoire_local/ utilisateur@hote:/repertoire_distant/
# Rsync avec progression
rsync -avz --progress source/ destination/
```

## Traitement de Texte et Recherche

### Recherche de Texte : `grep`

Rechercher des motifs dans le contenu des fichiers et la sortie des commandes.

```bash
# Rechercher un motif dans un fichier
grep "motif" nom_fichier
# Recherche insensible à la casse
grep -i "motif" nom_fichier
# Recherche récursive dans les répertoires
grep -r "motif" /chemin/
# Afficher les numéros de ligne
grep -n "motif" nom_fichier
# Compter les lignes correspondantes
grep -c "motif" nom_fichier
```

### Manipulation de Texte : `sed`, `awk`

Éditer et traiter du texte à l'aide d'éditeurs de flux et d'analyseurs de motifs.

```bash
# Remplacer le texte dans le fichier
sed 's/ancien/nouveau/g' nom_fichier
# Supprimer les lignes contenant un motif
sed '/motif/d' nom_fichier
# Afficher des champs spécifiques
awk '{print $1, $3}' nom_fichier
# Sommer les valeurs dans une colonne
awk '{somme += $1} END {print somme}' nom_fichier
```

### Trier et Compter : `sort`, `uniq`, `wc`

Trier les données, supprimer les doublons et compter les lignes, les mots ou les caractères.

```bash
# Trier le contenu du fichier
sort nom_fichier
# Trier numériquement
sort -n nombres.txt
# Supprimer les lignes dupliquées
uniq nom_fichier
# Trier et supprimer les doublons
sort nom_fichier | uniq
# Compter les lignes, mots, caractères
wc nom_fichier
# Compter uniquement les lignes
wc -l nom_fichier
```

### Couper et Coller : `cut`, `paste`

Extraire des colonnes spécifiques et combiner des fichiers.

```bash
# Extraire la première colonne
cut -d',' -f1 fichier.csv
# Extraire une plage de caractères
cut -c1-10 nom_fichier
# Combiner les fichiers côte à côte
paste fichier1.txt fichier2.txt
# Utiliser un délimiteur personnalisé
cut -d':' -f1,3 /etc/passwd
```

## Archive et Compression

### Créer des Archives : `tar`

Créer et extraire des archives compressées.

```bash
# Créer une archive tar
tar -cf archive.tar fichiers/
# Créer une archive compressée
tar -czf archive.tar.gz fichiers/
# Extraire l'archive
tar -xf archive.tar
# Extraire l'archive compressée
tar -xzf archive.tar.gz
# Lister le contenu de l'archive
tar -tf archive.tar
```

### Compression : `gzip`, `zip`

Compresser et décompresser des fichiers en utilisant divers algorithmes.

```bash
# Compresser un fichier avec gzip
gzip nom_fichier
# Décompresser un fichier gzip
gunzip nom_fichier.gz
# Créer une archive zip
zip archive.zip fichier1 fichier2
# Extraire une archive zip
unzip archive.zip
# Lister le contenu zip
unzip -l archive.zip
```

### Archives Avancées : `tar` Options

Opérations tar avancées pour la sauvegarde et la restauration.

```bash
# Créer une archive avec compression
tar -czvf sauvegarde.tar.gz /home/utilisateur/
# Extraire vers un répertoire spécifique
tar -xzf archive.tar.gz -C /destination/
# Ajouter des fichiers à une archive existante
tar -rf archive.tar nouveau_fichier.txt
# Mettre à jour l'archive avec des fichiers plus récents
tar -uf archive.tar fichiers/
```

### Espace Disque : `du`

Analyser l'utilisation de l'espace disque et la taille des répertoires.

```bash
# Afficher les tailles des répertoires
du -h /chemin/
# Résumé de la taille totale
du -sh /chemin/
# Afficher les tailles de tous les sous-répertoires
du -h --max-depth=1 /chemin/
# Les plus grands répertoires en premier
du -h | sort -hr | head -10
```

## Surveillance et Performance du Système

### Utilisation de la Mémoire : `free`, `vmstat`

Surveiller l'utilisation de la mémoire et les statistiques de mémoire virtuelle.

```bash
# Résumé de l'utilisation de la mémoire
free -h
# Statistiques mémoire détaillées
cat /proc/meminfo
# Statistiques de mémoire virtuelle
vmstat
# Utilisation de la mémoire toutes les 2 secondes
vmstat 2
# Afficher l'utilisation du swap
swapon --show
```

### E/S Disque : `iostat`, `iotop`

Surveiller les performances d'entrée/sortie disque et identifier les goulots d'étranglement.

```bash
# Statistiques d'E/S (nécessite sysstat)
iostat
# Statistiques d'E/S toutes les 2 secondes
iostat 2
# Surveiller les E/S disque par processus
iotop
# Afficher l'utilisation des E/S pour un périphérique spécifique
iostat -x /dev/sda
```

### Charge Système : `top`, `htop`

Surveiller la charge système, l'utilisation du CPU et les processus en cours d'exécution.

```bash
# Moniteur de processus en temps réel
top
# Visionneuse de processus améliorée
htop
# Afficher les moyennes de charge
uptime
# Afficher les informations CPU
lscpu
# Surveiller un processus spécifique
top -p PID
```

### Fichiers Journaux : `journalctl`, `dmesg`

Visualiser et analyser les journaux système pour le dépannage.

```bash
# Voir les journaux système
journalctl
# Suivre les journaux en temps réel
journalctl -f
# Afficher les journaux pour un service spécifique
journalctl -u nom_service
# Messages du noyau
dmesg
# Messages du dernier démarrage
dmesg | tail
```

## Gestion des Utilisateurs et des Permissions

### Opérations Utilisateur : `useradd`, `usermod`, `userdel`

Créer, modifier et supprimer des comptes utilisateurs.

```bash
# Ajouter un nouvel utilisateur
useradd nom_utilisateur
# Ajouter un utilisateur avec répertoire personnel
useradd -m nom_utilisateur
# Modifier le compte utilisateur
usermod -aG groupe_nom nom_utilisateur
# Supprimer un compte utilisateur
userdel nom_utilisateur
# Supprimer un compte utilisateur avec répertoire personnel
userdel -r nom_utilisateur
```

### Gestion des Groupes : `groupadd`, `groups`

Créer et gérer des groupes d'utilisateurs.

```bash
# Créer un nouveau groupe
groupadd nom_groupe
# Afficher les groupes de l'utilisateur
groups nom_utilisateur
# Afficher tous les groupes
cat /etc/group
# Ajouter un utilisateur à un groupe
usermod -aG groupe_nom nom_utilisateur
# Changer le groupe principal de l'utilisateur
usermod -g groupe_nom nom_utilisateur
```

### Changer d'Utilisateur : `su`, `sudo`

Changer d'utilisateur et exécuter des commandes avec des privilèges élevés.

```bash
# Changer en utilisateur root
su -
# Changer en utilisateur spécifique
su - nom_utilisateur
# Exécuter une commande en tant que root
sudo commande
# Exécuter une commande en tant qu'utilisateur spécifique
sudo -u nom_utilisateur commande
# Éditer le fichier sudoers
visudo
```

### Gestion des Mots de Passe : `passwd`, `chage`

Gérer les mots de passe des utilisateurs et les politiques de compte.

```bash
# Changer son propre mot de passe
passwd
# Changer le mot de passe d'un autre utilisateur (en tant que root)
passwd nom_utilisateur
# Afficher les informations d'expiration du mot de passe
chage -l nom_utilisateur
# Définir l'expiration du mot de passe à 90 jours
chage -M 90 nom_utilisateur
# Forcer le changement de mot de passe à la prochaine connexion
passwd -e nom_utilisateur
```

## Gestion des Paquets

### APT (Debian/Ubuntu) : `apt`, `apt-get`

Gérer les paquets sur les systèmes basés sur Debian.

```bash
# Mettre à jour la liste des paquets
apt update
# Mettre à niveau tous les paquets
apt upgrade
# Installer un paquet
apt install nom_paquet
# Supprimer un paquet
apt remove nom_paquet
# Rechercher des paquets
apt search nom_paquet
# Afficher les informations sur le paquet
apt show nom_paquet
```

### YUM/DNF (RHEL/Fedora) : `yum`, `dnf`

Gérer les paquets sur les systèmes basés sur Red Hat.

```bash
# Installer un paquet
yum install nom_paquet
# Mettre à jour tous les paquets
yum update
# Supprimer un paquet
yum remove nom_paquet
# Rechercher des paquets
yum search nom_paquet
# Lister les paquets installés
yum list installed
```

### Paquets Snap : `snap`

Installer et gérer les paquets snap sur différentes distributions.

```bash
# Installer un paquet snap
snap install nom_paquet
# Lister les snaps installés
snap list
# Mettre à jour les paquets snap
snap refresh
# Supprimer un paquet snap
snap remove nom_paquet
# Rechercher des paquets snap
snap find nom_paquet
```

### Paquets Flatpak : `flatpak`

Gérer les applications Flatpak pour les logiciels sandboxed.

```bash
# Installer flatpak
flatpak install nom_paquet
# Lister les flatpaks installés
flatpak list
# Mettre à jour les paquets flatpak
flatpak update
# Supprimer flatpak
flatpak uninstall nom_paquet
# Rechercher des paquets flatpak
flatpak search nom_paquet
```

## Shell et Scripting

### Historique des Commandes : `history`

Accéder et gérer l'historique de la ligne de commande.

```bash
# Afficher l'historique des commandes
history
# Afficher les 10 dernières commandes
history 10
# Exécuter la commande précédente
!!
# Exécuter une commande par son numéro
!123
# Rechercher dans l'historique interactivement
Ctrl+R
```

### Alias et Fonctions : `alias`

Créer des raccourcis pour les commandes fréquemment utilisées.

```bash
# Créer un alias
alias ll='ls -la'
# Afficher tous les alias
alias
# Supprimer un alias
unalias ll
# Rendre l'alias permanent (ajouter à .bashrc)
echo "alias ll='ls -la'" >> ~/.bashrc
```

### Redirection d'Entrée/Sortie

Rediriger l'entrée et la sortie des commandes vers des fichiers ou d'autres commandes.

```bash
# Rediriger la sortie vers un fichier
commande > sortie.txt
# Ajouter la sortie à un fichier
commande >> sortie.txt
# Rediriger l'entrée depuis un fichier
commande < entree.txt
# Rediriger stdout et stderr
commande &> sortie.txt
# Transmettre la sortie à une autre commande
commande1 | commande2
```

### Configuration de l'Environnement : `.bashrc`, `.profile`

Configurer l'environnement du shell et les scripts de démarrage.

```bash
# Éditer la configuration bash
nano ~/.bashrc
# Recharger la configuration
source ~/.bashrc
# Définir une variable d'environnement
export VARIABLE=valeur
# Ajouter au PATH
export PATH=$PATH:/nouveau/chemin
# Afficher les variables d'environnement
printenv
```

## Installation et Configuration du Système

### Options de Distribution : Ubuntu, CentOS, Debian

Choisir et installer des distributions Linux pour différents cas d'utilisation.

```bash
# Ubuntu Server
wget ubuntu-server.iso
# CentOS Stream
wget centos-stream.iso
# Debian Stable
wget debian.iso
# Vérifier l'intégrité de l'ISO
sha256sum linux.iso
```

### Amorçage et Installation : USB, Réseau

Créer des supports amorçables et effectuer l'installation du système.

```bash
# Créer une clé USB amorçable (Linux)
dd if=linux.iso of=/dev/sdX bs=4M
# Créer une clé USB amorçable (multiplateforme)
# Utiliser des outils comme Rufus, Etcher ou UNetbootin
# Installation réseau
# Configurer le démarrage PXE pour les installations réseau
```

### Configuration Initiale : Utilisateurs, Réseau, SSH

Configurer la configuration de base du système après l'installation.

```bash
# Définir le nom d'hôte
hostnamectl set-hostname nouveau_nom
# Configurer l'IP statique
# Éditer /etc/netplan/ (Ubuntu) ou /etc/network/interfaces
# Activer le service SSH
systemctl enable ssh
systemctl start ssh
# Configurer le pare-feu
ufw enable
ufw allow ssh
```

## Sécurité et Bonnes Pratiques

### Configuration du Pare-feu : `ufw`, `iptables`

Configurer les règles de pare-feu pour protéger le système contre les menaces réseau.

```bash
# Activer le pare-feu UFW
ufw enable
# Autoriser un port spécifique
ufw allow 22/tcp
# Autoriser un service par son nom
ufw allow ssh
# Refuser l'accès
ufw deny 23
# Afficher l'état du pare-feu
ufw status verbose
# Règles avancées avec iptables
iptables -L
```

### Intégrité des Fichiers : `checksums`

Vérifier l'intégrité des fichiers et détecter les modifications non autorisées.

```bash
# Générer le checksum MD5
md5sum nom_fichier
# Générer le checksum SHA256
sha256sum nom_fichier
# Vérifier le checksum
sha256sum -c checksums.txt
# Créer un fichier de checksum
sha256sum *.txt > checksums.txt
```

### Mises à Jour du Système : Correctifs de Sécurité

Maintenir le système sécurisé avec des mises à jour régulières et des correctifs de sécurité.

```bash
# Mises à jour de sécurité Ubuntu
apt update && apt upgrade
# Mises à jour de sécurité automatiques
unattended-upgrades
# Mises à jour RHEL/CentOS
yum update --security
# Lister les mises à jour disponibles
apt list --upgradable
```

### Surveillance des Journaux : Événements de Sécurité

Surveiller les journaux système pour les événements de sécurité et les anomalies.

```bash
# Surveiller les journaux d'authentification
tail -f /var/log/auth.log
# Vérifier les tentatives de connexion échouées
grep "Failed password" /var/log/auth.log
# Surveiller les journaux système
tail -f /var/log/syslog
# Voir l'historique de connexion
last
# Vérifier les activités suspectes
journalctl -p err
```

## Dépannage et Récupération

### Problèmes de Démarrage : Récupération GRUB

Récupérer à partir de problèmes de chargeur de démarrage et de noyau.

```bash
# Démarrer en mode de secours
# Accéder au menu GRUB pendant le démarrage
# Monter le système de fichiers racine
mount /dev/sda1 /mnt
# Chroot dans le système
chroot /mnt
# Réinstaller GRUB
grub-install /dev/sda
# Mettre à jour la configuration GRUB
update-grub
```

### Réparation du Système de Fichiers : `fsck`

Vérifier et réparer la corruption du système de fichiers.

```bash
# Vérifier le système de fichiers
fsck /dev/sda1
# Vérification forcée du système de fichiers
fsck -f /dev/sda1
# Réparation automatique
fsck -y /dev/sda1
# Vérifier tous les systèmes de fichiers montés
fsck -A
```

### Problèmes de Service : `systemctl`

Diagnostiquer et corriger les problèmes liés aux services.

```bash
# Vérifier l'état du service
systemctl status nom_service
# Voir les journaux du service
journalctl -u nom_service
# Redémarrer le service défaillant
systemctl restart nom_service
# Activer le service au démarrage
systemctl enable nom_service
# Lister les services défaillants
systemctl --failed
```

### Problèmes de Performance : Analyse des Ressources

Identifier et résoudre les goulots d'étranglement de performance du système.

```bash
# Vérifier l'espace disque
df -h
# Surveiller l'utilisation des E/S
iotop
# Vérifier l'utilisation de la mémoire
free -h
# Identifier l'utilisation du CPU
top
# Lister les fichiers ouverts
lsof
```

## Liens Pertinents

- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/rhel">Feuille de triche Red Hat Enterprise Linux</router-link>
- <router-link to="/docker">Feuille de triche Docker</router-link>
- <router-link to="/kubernetes">Feuille de triche Kubernetes</router-link>
- <router-link to="/git">Feuille de triche Git</router-link>
- <router-link to="/ansible">Feuille de triche Ansible</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>
- <router-link to="/cybersecurity">Feuille de triche Cybersécurité</router-link>

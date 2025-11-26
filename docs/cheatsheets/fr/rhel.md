---
title: 'Fiche de Référence Red Hat Enterprise Linux'
description: 'Apprenez Red Hat Enterprise Linux avec notre fiche complète couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/red-hat-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Red Hat Enterprise Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/rhel">Apprenez Red Hat Enterprise Linux avec des laboratoires pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez Red Hat Enterprise Linux grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours RHEL complets couvrant l'administration système essentielle, la gestion des paquets, la gestion des services, la configuration réseau, la gestion du stockage et la sécurité. Maîtrisez les opérations Linux d'entreprise et les techniques de gestion de système.
</base-disclaimer-content>
</base-disclaimer>

## Informations Système et Surveillance

### Version du Système : `cat /etc/redhat-release`

Afficher la version et les informations de publication de RHEL.

```bash
# Afficher la version RHEL
cat /etc/redhat-release
# Méthode alternative
cat /etc/os-release
# Afficher la version du noyau
uname -r
# Afficher l'architecture du système
uname -m
```

### Performance du Système : `top` / `htop`

Afficher les processus en cours d'exécution et l'utilisation des ressources système.

```bash
# Moniteur de processus en temps réel
top
# Visionneuse de processus améliorée (si installée)
htop
# Afficher l'arborescence des processus
pstree
# Afficher tous les processus
ps aux
```

### Informations Mémoire : `free` / `cat /proc/meminfo`

Afficher l'utilisation et la disponibilité de la mémoire.

```bash
# Afficher l'utilisation de la mémoire au format lisible par l'homme
free -h
# Afficher les informations détaillées sur la mémoire
cat /proc/meminfo
# Afficher l'utilisation du swap
swapon --show
```

### Utilisation du Disque : `df` / `du`

Surveiller l'utilisation du système de fichiers et des répertoires.

```bash
# Afficher l'utilisation du système de fichiers
df -h
# Afficher les tailles des répertoires
du -sh /var/log/*
# Afficher les plus grands répertoires
du -h --max-depth=1 / | sort -hr
```

### Temps de Fonctionnement du Système : `uptime` / `who`

Vérifier le temps de fonctionnement du système et les utilisateurs connectés.

```bash
# Afficher le temps de fonctionnement et la charge du système
uptime
# Afficher les utilisateurs connectés
who
# Afficher l'utilisateur actuel
whoami
# Afficher les dernières connexions
last
```

### Informations Matérielles : `lscpu` / `lsblk`

Afficher les composants matériels et la configuration.

```bash
# Afficher les informations du CPU
lscpu
# Afficher les périphériques en bloc
lsblk
# Afficher les périphériques PCI
lspci
# Afficher les périphériques USB
lsusb
```

## Gestion des Paquets

### Installation de Paquets : `dnf install` / `yum install`

Installer des paquets logiciels et leurs dépendances.

```bash
# Installer un paquet (RHEL 8+)
sudo dnf install package-name
# Installer un paquet (RHEL 7)
sudo yum install package-name
# Installer un fichier RPM local
sudo rpm -i package.rpm
# Installer depuis un dépôt spécifique
sudo dnf install --enablerepo=repo-
name package
```

### Mises à Jour de Paquets : `dnf update` / `yum update`

Mettre à jour les paquets vers les dernières versions.

```bash
# Mettre à jour tous les paquets
sudo dnf update
# Mettre à jour un paquet spécifique
sudo dnf update package-name
# Vérifier les mises à jour disponibles
dnf check-update
# Mettre à jour uniquement les correctifs de sécurité
sudo dnf update --security
```

### Informations sur les Paquets : `dnf info` / `rpm -q`

Interroger les informations et les dépendances des paquets.

```bash
# Afficher les informations du paquet
dnf info package-name
# Lister les paquets installés
rpm -qa
# Rechercher des paquets
dnf search keyword
# Afficher les dépendances du paquet
dnf deplist package-name
```

## Opérations sur les Fichiers et Répertoires

### Navigation : `cd` / `pwd` / `ls`

Naviguer dans le système de fichiers et lister le contenu.

```bash
# Changer de répertoire
cd /path/to/directory
# Afficher le répertoire courant
pwd
# Lister les fichiers et répertoires
ls -la
# Lister avec les tailles de fichiers
ls -lh
# Afficher les fichiers cachés
ls -a
```

### Opérations sur les Fichiers : `cp` / `mv` / `rm`

Copier, déplacer et supprimer des fichiers et répertoires.

```bash
# Copier un fichier
cp source.txt destination.txt
# Copier un répertoire récursivement
cp -r /source/dir/ /dest/dir/
# Déplacer/Renommer un fichier
mv oldname.txt newname.txt
# Supprimer un fichier
rm filename.txt
# Supprimer un répertoire récursivement
rm -rf directory/
```

### Contenu des Fichiers : `cat` / `less` / `head` / `tail`

Visualiser et examiner le contenu des fichiers.

```bash
# Afficher le contenu du fichier
cat filename.txt
# Voir le fichier page par page
less filename.txt
# Afficher les 10 premières lignes
head filename.txt
# Afficher les 10 dernières lignes
tail filename.txt
# Suivre un fichier journal en temps réel
tail -f /var/log/messages
```

### Permissions des Fichiers : `chmod` / `chown` / `chgrp`

Gérer les permissions et la propriété des fichiers.

```bash
# Changer les permissions du fichier
chmod 755 script.sh
# Changer la propriété du fichier
sudo chown user:group filename.txt
# Changer la propriété du groupe
sudo chgrp newgroup filename.txt
# Changement de permission récursif
sudo chmod -R 644 /path/to/directory/
```

### Recherche de Fichiers : `find` / `locate` / `grep`

Rechercher des fichiers et du contenu dans les fichiers.

```bash
# Trouver des fichiers par nom
find /path -name "*.txt"
# Trouver des fichiers par taille
find /path -size +100M
# Rechercher du texte dans les fichiers
grep "pattern" filename.txt
# Recherche de texte récursive
grep -r "pattern" /path/to/directory/
```

### Archive et Compression : `tar` / `gzip`

Créer et extraire des archives compressées.

```bash
# Créer une archive tar
tar -czf archive.tar.gz /path/to/directory/
# Extraire une archive tar
tar -xzf archive.tar.gz
# Créer une archive zip
zip -r archive.zip /path/to/directory/
# Extraire une archive zip
unzip archive.zip
```

## Gestion des Services

### Contrôle des Services : `systemctl`

Gérer les services système à l'aide de systemd.

```bash
# Démarrer un service
sudo systemctl start service-name
# Arrêter un service
sudo systemctl stop service-name
# Redémarrer un service
sudo systemctl restart service-name
# Vérifier l'état du service
systemctl status service-name
# Activer le service au démarrage
sudo systemctl enable service-name
# Désactiver le service au démarrage
sudo systemctl disable service-name
```

### Informations sur les Services : `systemctl list-units`

Lister et interroger les services système.

```bash
# Lister tous les services actifs
systemctl list-units --type=service
# Lister tous les services activés
systemctl list-unit-files --type=service --state=enabled
# Afficher les dépendances du service
systemctl list-dependencies service-name
```

### Journaux Système : `journalctl`

Visualiser et analyser les journaux système à l'aide de journald.

```bash
# Voir tous les journaux
journalctl
# Voir les journaux pour un service spécifique
journalctl -u service-name
# Suivre les journaux en temps réel
journalctl -f
# Voir les journaux du dernier démarrage
journalctl -b
# Voir les journaux par plage horaire
journalctl --since "2024-01-01" --until "2024-01-31"
```

### Gestion des Processus : `ps` / `kill` / `killall`

Surveiller et contrôler les processus en cours d'exécution.

```bash
# Afficher les processus en cours d'exécution
ps aux
# Tuer un processus par PID
kill 1234
# Tuer un processus par nom
killall process-name
# Forcer la terminaison d'un processus
kill -9 1234
# Afficher la hiérarchie des processus
pstree
```

## Gestion des Utilisateurs et Groupes

### Gestion des Utilisateurs : `useradd` / `usermod` / `userdel`

Créer, modifier et supprimer des comptes utilisateurs.

```bash
# Ajouter un nouvel utilisateur
sudo useradd -m username
# Définir le mot de passe de l'utilisateur
sudo passwd username
# Modifier le compte utilisateur
sudo usermod -aG groupname
username
# Supprimer le compte utilisateur
sudo userdel -r username
# Verrouiller le compte utilisateur
sudo usermod -L username
```

### Gestion des Groupes : `groupadd` / `groupmod` / `groupdel`

Créer, modifier et supprimer des groupes.

```bash
# Ajouter un nouveau groupe
sudo groupadd groupname
# Ajouter un utilisateur au groupe
sudo usermod -aG groupname
username
# Supprimer un utilisateur du groupe
sudo gpasswd -d username
groupname
# Supprimer un groupe
sudo groupdel groupname
# Lister les groupes d'un utilisateur
groups username
```

### Contrôle d'Accès : `su` / `sudo`

Changer d'utilisateur et exécuter des commandes avec des privilèges élevés.

```bash
# Changer pour l'utilisateur root
su -
# Changer pour un utilisateur spécifique
su - username
# Exécuter une commande en tant que root
sudo command
# Éditer le fichier sudoers
sudo visudo
# Vérifier les permissions sudo
sudo -l
```

## Configuration Réseau

### Informations Réseau : `ip` / `nmcli`

Afficher les détails de l'interface et de la configuration réseau.

```bash
# Afficher les interfaces réseau
ip addr show
# Afficher la table de routage
ip route show
# Afficher les connexions du gestionnaire de réseau
nmcli connection show
# Afficher l'état du périphérique
nmcli device status
```

### Configuration Réseau : `nmtui` / `nmcli`

Configurer les paramètres réseau à l'aide de NetworkManager.

```bash
# Configuration réseau textuelle
sudo nmtui
# Ajouter une nouvelle connexion
sudo nmcli connection add type ethernet con-name
"eth0" ifname eth0
# Modifier une connexion
sudo nmcli connection modify "eth0" ipv4.addresses
192.168.1.100/24
# Activer la connexion
sudo nmcli connection up "eth0"
```

### Test Réseau : `ping` / `curl` / `wget`

Tester la connectivité réseau et télécharger des fichiers.

```bash
# Tester la connectivité
ping google.com
# Tester un port spécifique
telnet hostname 80
# Télécharger un fichier
wget http://example.com/file.txt
# Tester les requêtes HTTP
curl -I http://example.com
```

### Gestion du Pare-feu : `firewall-cmd`

Configurer les règles du pare-feu à l'aide de firewalld.

```bash
# Afficher l'état du pare-feu
sudo firewall-cmd --state
# Lister les zones actives
sudo firewall-cmd --get-active-zones
# Ajouter un service au pare-feu
sudo firewall-cmd --permanent --add-service=http
# Recharger les règles du pare-feu
sudo firewall-cmd --reload
```

## Gestion du Stockage

### Gestion des Disques : `fdisk` / `parted`

Créer et gérer les partitions de disque.

```bash
# Lister les partitions de disque
sudo fdisk -l
# Éditeur de partition interactif
sudo fdisk /dev/sda
# Créer une table de partition
sudo parted /dev/sda mklabel gpt
# Créer une nouvelle partition
sudo parted /dev/sda mkpart primary ext4 1MiB 100GiB
```

### Gestion des Systèmes de Fichiers : `mkfs` / `mount`

Créer des systèmes de fichiers et monter des périphériques de stockage.

```bash
# Créer un système de fichiers ext4
sudo mkfs.ext4 /dev/sda1
# Monter un système de fichiers
sudo mount /dev/sda1 /mnt/data
# Démonter un système de fichiers
sudo umount /mnt/data
# Vérifier le système de fichiers
sudo fsck /dev/sda1
```

### Gestion LVM : `pvcreate` / `vgcreate` / `lvcreate`

Gérer le stockage Logical Volume Manager (LVM).

```bash
# Créer un volume physique
sudo pvcreate /dev/sdb
# Créer un groupe de volumes
sudo vgcreate vg_data /dev/sdb
# Créer un volume logique
sudo lvcreate -L 10G -n lv_data vg_data
# Étendre un volume logique
sudo lvextend -L +5G /dev/vg_data/lv_data
```

### Configuration de Montage : `/etc/fstab`

Configurer les points de montage permanents.

```bash
# Éditer le fichier fstab
sudo vi /etc/fstab
# Tester les entrées fstab
sudo mount -a
# Afficher les systèmes de fichiers montés
mount | column -t
```

## Sécurité et SELinux

### Gestion SELinux : `getenforce` / `setenforce`

Contrôler l'application et les politiques SELinux.

```bash
# Vérifier l'état SELinux
getenforce
# Définir SELinux en mode permissif
sudo setenforce 0
# Définir SELinux en mode d'application
sudo setenforce 1
# Vérifier le contexte SELinux
ls -Z filename
# Changer le contexte SELinux
sudo chcon -t httpd_exec_t /path/to/file
```

### Outils SELinux : `sealert` / `ausearch`

Analyser les refus SELinux et les journaux d'audit.

```bash
# Vérifier les alertes SELinux
sudo sealert -a /var/log/audit/audit.log
# Rechercher dans les journaux d'audit
sudo ausearch -m avc -ts recent
# Générer une politique SELinux
sudo audit2allow -M mypolicy < /var/log/audit/audit.log
```

### Configuration SSH : `/etc/ssh/sshd_config`

Configurer le démon SSH pour un accès distant sécurisé.

```bash
# Éditer la configuration SSH
sudo vi /etc/ssh/sshd_config
# Redémarrer le service SSH
sudo systemctl restart sshd
# Tester la connexion SSH
ssh user@hostname
# Copier la clé SSH
ssh-copy-id user@hostname
```

### Mises à Jour du Système : `dnf update`

Maintenir le système sécurisé avec des mises à jour régulières.

```bash
# Mettre à jour tous les paquets
sudo dnf update
# Mettre à jour uniquement les correctifs de sécurité
sudo dnf update --security
# Vérifier les mises à jour disponibles
dnf check-update --security
# Activer les mises à jour automatiques
sudo systemctl enable dnf-automatic.timer
```

## Surveillance des Performances

### Surveillance du Système : `iostat` / `vmstat`

Surveiller les performances du système et l'utilisation des ressources.

```bash
# Afficher les statistiques d'E/S
iostat -x 1
# Afficher les statistiques de mémoire virtuelle
vmstat 1
# Afficher les statistiques réseau
ss -tuln
# Afficher les E/S disque
iotop
```

### Utilisation des Ressources : `sar` / `top`

Analyser les métriques système historiques et en temps réel.

```bash
# Rapport d'activité système
sar -u 1 3
# Rapport d'utilisation de la mémoire
sar -r
# Rapport d'activité réseau
sar -n DEV
# Surveillance de la charge moyenne
uptime
```

### Analyse des Processus : `strace` / `lsof`

Déboguer les processus et l'accès aux fichiers.

```bash
# Tracer les appels système
strace -p 1234
# Lister les fichiers ouverts
lsof
# Afficher les fichiers ouverts par un processus
lsof -p 1234
# Afficher les connexions réseau
lsof -i
```

### Optimisation des Performances : `tuned`

Optimiser les performances du système pour des charges de travail spécifiques.

```bash
# Lister les profils disponibles
tuned-adm list
# Afficher le profil actif
tuned-adm active
# Définir le profil de performance
sudo tuned-adm profile throughput-performance
# Créer un profil personnalisé
sudo tuned-adm profile_mode
```

## Installation et Configuration RHEL

### Enregistrement du Système : `subscription-manager`

Enregistrer le système auprès du Portail Client Red Hat.

```bash
# Enregistrer le système
sudo subscription-manager
register --username
your_username
# Attacher automatiquement les abonnements
sudo subscription-manager
attach --auto
# Lister les abonnements disponibles
subscription-manager list --
available
# Afficher l'état du système
subscription-manager status
```

### Gestion des Dépôts : `dnf config-manager`

Gérer les dépôts logiciels.

```bash
# Lister les dépôts activés
dnf repolist
# Activer un dépôt
sudo dnf config-manager --
enable repository-name
# Désactiver un dépôt
sudo dnf config-manager --
disable repository-name
# Ajouter un nouveau dépôt
sudo dnf config-manager --add-
repo https://example.com/repo
```

### Configuration Système : `hostnamectl` / `timedatectl`

Configurer les paramètres système de base.

```bash
# Définir le nom d'hôte
sudo hostnamectl set-hostname
new-hostname
# Afficher les informations système
hostnamectl
# Définir le fuseau horaire
sudo timedatectl set-timezone
America/New_York
# Afficher les paramètres d'heure
timedatectl
```

## Dépannage et Diagnostic

### Journaux Système : `/var/log/`

Examiner les fichiers journaux système pour les problèmes.

```bash
# Voir les messages système
sudo tail -f /var/log/messages
# Voir les journaux d'authentification
sudo tail -f /var/log/secure
# Voir les journaux de démarrage
sudo journalctl -b
# Voir les messages du noyau
dmesg | tail
```

### Diagnostic Matériel : `dmidecode` / `lshw`

Examiner les informations et l'état du matériel.

```bash
# Afficher les informations matérielles
sudo dmidecode -t system
# Lister les composants matériels
sudo lshw -short
# Vérifier les informations mémoire
sudo dmidecode -t memory
# Afficher les informations CPU
lscpu
```

### Dépannage Réseau : `netstat` / `ss`

Outils de diagnostic réseau et utilitaires.

```bash
# Afficher les connexions réseau
ss -tuln
# Afficher la table de routage
ip route show
# Tester la résolution DNS
nslookup google.com
# Tracer le chemin réseau
traceroute google.com
```

### Récupération et Secours : `systemctl rescue`

Procédures de récupération et d'urgence du système.

```bash
# Entrer en mode secours
sudo systemctl rescue
# Entrer en mode urgence
sudo systemctl emergency
# Réinitialiser les services échoués
sudo systemctl reset-failed
# Reconfigurer le chargeur de démarrage
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

## Automatisation et Scripting

### Tâches Cron : `crontab`

Planifier des tâches automatisées et de maintenance.

```bash
# Éditer la crontab de l'utilisateur
crontab -e
# Lister la crontab de l'utilisateur
crontab -l
# Supprimer la crontab de l'utilisateur
crontab -r
# Exemple : Exécuter un script tous les jours à 2h du matin
0 2 * * * /path/to/script.sh
```

### Scripting Shell : `bash`

Créer et exécuter des scripts shell pour l'automatisation.

```bash
#!/bin/bash
# Script de sauvegarde simple
DATE=$(date +%Y%m%d)
tar -czf backup_$DATE.tar.gz /home/user/documents
echo "Sauvegarde terminée : backup_$DATE.tar.gz"
```

### Variables d'Environnement : `export` / `env`

Gérer les variables d'environnement et les paramètres du shell.

```bash
# Définir une variable d'environnement
export MY_VAR="value"
# Afficher toutes les variables d'environnement
env
# Afficher une variable spécifique
echo $PATH
# Ajouter à PATH
export PATH=$PATH:/new/directory
```

### Automatisation Système : `systemd timers`

Créer des tâches planifiées basées sur systemd.

```bash
# Créer un fichier d'unité timer
sudo vi /etc/systemd/system/backup.timer
# Activer et démarrer le timer
sudo systemctl enable backup.timer
sudo systemctl start backup.timer
# Lister les timers actifs
systemctl list-timers
```

## Liens Pertinents

- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/git">Feuille de triche Git</router-link>
- <router-link to="/docker">Feuille de triche Docker</router-link>
- <router-link to="/kubernetes">Feuille de triche Kubernetes</router-link>
- <router-link to="/ansible">Feuille de triche Ansible</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>
- <router-link to="/cybersecurity">Feuille de triche Cybersécurité</router-link>

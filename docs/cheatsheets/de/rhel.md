---
title: 'Red Hat Enterprise Linux Spickzettel'
description: 'Lernen Sie Red Hat Enterprise Linux mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/red-hat-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Red Hat Enterprise Linux Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/rhel">Lernen Sie Red Hat Enterprise Linux mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Red Hat Enterprise Linux durch praktische Labs und reale Szenarien. LabEx bietet umfassende RHEL-Kurse, die wesentliche Systemadministration, Paketverwaltung, Dienstverwaltung, Netzwerkkonfiguration, Speicherverwaltung und Sicherheit abdecken. Meistern Sie Enterprise-Linux-Operationen und Techniken zur Systemverwaltung.
</base-disclaimer-content>
</base-disclaimer>

## Systeminformationen & Überwachung

### Systemversion: `cat /etc/redhat-release`

Zeigt die RHEL-Version und die Release-Informationen an.

```bash
# RHEL-Version anzeigen
cat /etc/redhat-release
# Alternative Methode
cat /etc/os-release
# Kernel-Version anzeigen
uname -r
# Systemarchitektur anzeigen
uname -m
```

### Systemleistung: `top` / `htop`

Zeigt laufende Prozesse und die Auslastung der Systemressourcen an.

```bash
# Echtzeit-Prozessmonitor
top
# Verbesserter Prozess-Viewer (falls installiert)
htop
# Prozessbaum anzeigen
pstree
# Alle Prozesse anzeigen
ps aux
```

### Speicherinformationen: `free` / `cat /proc/meminfo`

Zeigt die Speichernutzung und Verfügbarkeit an.

```bash
# Speichernutzung im menschenlesbaren Format anzeigen
free -h
# Detaillierte Speicherinformationen anzeigen
cat /proc/meminfo
# Swap-Nutzung anzeigen
swapon --show
```

### Festplattennutzung: `df` / `du`

Überwacht die Nutzung von Dateisystemen und Verzeichnissen.

```bash
# Dateisystemnutzung anzeigen
df -h
# Verzeichnisgrößen anzeigen
du -sh /var/log/*
# Größte Verzeichnisse anzeigen
du -h --max-depth=1 / | sort -hr
```

### Systemlaufzeit: `uptime` / `who`

Überprüft die Systemlaufzeit und die angemeldeten Benutzer.

```bash
# Systemlaufzeit und Last anzeigen
uptime
# Angemeldete Benutzer anzeigen
who
# Aktuellen Benutzer anzeigen
whoami
# Letzte Anmeldungen anzeigen
last
```

### Hardwareinformationen: `lscpu` / `lsblk`

Zeigt Hardwarekomponenten und Konfiguration an.

```bash
# CPU-Informationen anzeigen
lscpu
# Blockgeräte anzeigen
lsblk
# PCI-Geräte anzeigen
lspci
# USB-Geräte anzeigen
lsusb
```

## Paketverwaltung

### Paketinstallation: `dnf install` / `yum install`

Installiert Softwarepakete und Abhängigkeiten.

```bash
# Ein Paket installieren (RHEL 8+)
sudo dnf install package-name
# Ein Paket installieren (RHEL 7)
sudo yum install package-name
# Lokale RPM-Datei installieren
sudo rpm -i package.rpm
# Aus spezifischem Repository installieren
sudo dnf install --enablerepo=repo-
name package
```

### Paketaktualisierungen: `dnf update` / `yum update`

Aktualisiert Pakete auf die neuesten Versionen.

```bash
# Alle Pakete aktualisieren
sudo dnf update
# Spezifisches Paket aktualisieren
sudo dnf update package-name
# Nach verfügbaren Updates suchen
dnf check-update
# Nur Sicherheitspatches aktualisieren
sudo dnf update --security
```

### Paketinformationen: `dnf info` / `rpm -q`

Fragt Paketinformationen und Abhängigkeiten ab.

```bash
# Paketinformationen anzeigen
dnf info package-name
# Installierte Pakete auflisten
rpm -qa
# Nach Paketen suchen
dnf search keyword
# Paketabhängigkeiten anzeigen
dnf deplist package-name
```

## Datei- & Verzeichnisoperationen

### Navigation: `cd` / `pwd` / `ls`

Navigiert im Dateisystem und listet Inhalte auf.

```bash
# Verzeichnis wechseln
cd /path/to/directory
# Aktuelles Verzeichnis anzeigen
pwd
# Dateien und Verzeichnisse auflisten
ls -la
# Auflisten mit Dateigrößen
ls -lh
# Versteckte Dateien anzeigen
ls -a
```

### Dateioperationen: `cp` / `mv` / `rm`

Kopiert, verschiebt und löscht Dateien und Verzeichnisse.

```bash
# Datei kopieren
cp source.txt destination.txt
# Verzeichnis rekursiv kopieren
cp -r /source/dir/ /dest/dir/
# Datei verschieben/umbenennen
mv oldname.txt newname.txt
# Datei entfernen
rm filename.txt
# Verzeichnis rekursiv entfernen
rm -rf directory/
```

### Dateiinhalt: `cat` / `less` / `head` / `tail`

Zeigt Dateiinhalte an und untersucht sie.

```bash
# Dateiinhalt anzeigen
cat filename.txt
# Datei seitenweise anzeigen
less filename.txt
# Erste 10 Zeilen anzeigen
head filename.txt
# Letzte 10 Zeilen anzeigen
tail filename.txt
# Logdatei in Echtzeit verfolgen
tail -f /var/log/messages
```

### Dateiberechtigungen: `chmod` / `chown` / `chgrp`

Verwaltet Dateiberechtigungen und Eigentümerschaft.

```bash
# Dateiberechtigungen ändern
chmod 755 script.sh
# Dateieigentümerschaft ändern
sudo chown user:group filename.txt
# Gruppeneigentümerschaft ändern
sudo chgrp newgroup filename.txt
# Rekursive Berechtigungsänderung
sudo chmod -R 644 /path/to/directory/
```

### Dateisuche: `find` / `locate` / `grep`

Sucht nach Dateien und Inhalten in Dateien.

```bash
# Dateien nach Namen finden
find /path -name "*.txt"
# Dateien nach Größe finden
find /path -size +100M
# Text in Dateien suchen
grep "pattern" filename.txt
# Rekursive Textsuche
grep -r "pattern" /path/to/directory/
```

### Archiv & Komprimierung: `tar` / `gzip`

Erstellt und extrahiert komprimierte Archive.

```bash
# Tar-Archiv erstellen
tar -czf archive.tar.gz /path/to/directory/
# Tar-Archiv extrahieren
tar -xzf archive.tar.gz
# Zip-Archiv erstellen
zip -r archive.zip /path/to/directory/
# Zip-Archiv extrahieren
unzip archive.zip
```

## Dienstverwaltung

### Dienststeuerung: `systemctl`

Verwaltet Systemdienste mit systemd.

```bash
# Dienst starten
sudo systemctl start service-name
# Dienst stoppen
sudo systemctl stop service-name
# Dienst neu starten
sudo systemctl restart service-name
# Dienststatus prüfen
systemctl status service-name
# Dienst beim Booten aktivieren
sudo systemctl enable service-name
# Dienst beim Booten deaktivieren
sudo systemctl disable service-name
```

### Dienstinformationen: `systemctl list-units`

Listet Systemdienste auf und fragt sie ab.

```bash
# Alle aktiven Dienste auflisten
systemctl list-units --type=service
# Alle aktivierten Dienste auflisten
systemctl list-unit-files --type=service --state=enabled
# Abhängigkeiten des Dienstes anzeigen
systemctl list-dependencies service-name
```

### Systemprotokolle: `journalctl`

Zeigt Systemprotokolle mit journald an und analysiert sie.

```bash
# Alle Protokolle anzeigen
journalctl
# Protokolle für spezifischen Dienst anzeigen
journalctl -u service-name
# Protokolle in Echtzeit verfolgen
journalctl -f
# Protokolle vom letzten Boot anzeigen
journalctl -b
# Protokolle nach Zeitbereich anzeigen
journalctl --since "2024-01-01" --until "2024-01-31"
```

### Prozessverwaltung: `ps` / `kill` / `killall`

Überwacht und steuert laufende Prozesse.

```bash
# Laufende Prozesse anzeigen
ps aux
# Prozess nach PID beenden
kill 1234
# Prozess nach Namen beenden
killall process-name
# Prozess erzwingen
kill -9 1234
# Prozesshierarchie anzeigen
pstree
```

## Benutzer- & Gruppenverwaltung

### Benutzerverwaltung: `useradd` / `usermod` / `userdel`

Erstellt, modifiziert und löscht Benutzerkonten.

```bash
# Neuen Benutzer hinzufügen
sudo useradd -m username
# Benutzerpasswort festlegen
sudo passwd username
# Benutzerkonto modifizieren
sudo usermod -aG groupname
username
# Benutzerkonto löschen
sudo userdel -r username
# Benutzerkonto sperren
sudo usermod -L username
```

### Gruppenverwaltung: `groupadd` / `groupmod` / `groupdel`

Erstellt, modifiziert und löscht Gruppen.

```bash
# Neue Gruppe hinzufügen
sudo groupadd groupname
# Benutzer zur Gruppe hinzufügen
sudo usermod -aG groupname
username
# Benutzer aus Gruppe entfernen
sudo gpasswd -d username
groupname
# Gruppe löschen
sudo groupdel groupname
# Benutzergruppen auflisten
groups username
```

### Zugriffskontrolle: `su` / `sudo`

Benutzer wechseln und Befehle mit erhöhten Rechten ausführen.

```bash
# Zu Root-Benutzer wechseln
su -
# Zu spezifischem Benutzer wechseln
su - username
# Befehl als Root ausführen
sudo command
# sudoers-Datei bearbeiten
sudo visudo
# Sudo-Berechtigungen prüfen
sudo -l
```

## Netzwerkkonfiguration

### Netzwerkinformationen: `ip` / `nmcli`

Zeigt Netzwerkschnittstellen- und Konfigurationsdetails an.

```bash
# Netzwerkschnittstellen anzeigen
ip addr show
# Routing-Tabelle anzeigen
ip route show
# Network Manager Verbindungen anzeigen
nmcli connection show
# Gerätestatus anzeigen
nmcli device status
```

### Netzwerkkonfiguration: `nmtui` / `nmcli`

Konfiguriert Netzwerkeinstellungen mit NetworkManager.

```bash
# Textbasierte Netzwerkkonfiguration
sudo nmtui
# Neue Verbindung hinzufügen
sudo nmcli connection add type ethernet con-name
"eth0" ifname eth0
# Verbindung modifizieren
sudo nmcli connection modify "eth0" ipv4.addresses
192.168.1.100/24
# Verbindung aktivieren
sudo nmcli connection up "eth0"
```

### Netzwerktests: `ping` / `curl` / `wget`

Testet die Netzwerkkonnektivität und lädt Dateien herunter.

```bash
# Konnektivität testen
ping google.com
# Spezifischen Port testen
telnet hostname 80
# Datei herunterladen
wget http://example.com/file.txt
# HTTP-Anfragen testen
curl -I http://example.com
```

### Firewall-Verwaltung: `firewall-cmd`

Konfiguriert Firewall-Regeln mit firewalld.

```bash
# Firewall-Status anzeigen
sudo firewall-cmd --state
# Aktive Zonen auflisten
sudo firewall-cmd --get-active-zones
# Dienst zur Firewall hinzufügen
sudo firewall-cmd --permanent --add-service=http
# Firewall-Regeln neu laden
sudo firewall-cmd --reload
```

## Speicherverwaltung

### Festplattenverwaltung: `fdisk` / `parted`

Erstellt und verwaltet Festplattenpartitionen.

```bash
# Festplattenpartitionen auflisten
sudo fdisk -l
# Interaktiver Partitionierer
sudo fdisk /dev/sda
# Partitionstabelle erstellen
sudo parted /dev/sda mklabel gpt
# Neue Partition erstellen
sudo parted /dev/sda mkpart primary ext4 1MiB 100GiB
```

### Dateisystemverwaltung: `mkfs` / `mount`

Erstellt Dateisysteme und bindet Speichergeräte ein.

```bash
# Ext4-Dateisystem erstellen
sudo mkfs.ext4 /dev/sda1
# Dateisystem einbinden
sudo mount /dev/sda1 /mnt/data
# Dateisystem aushängen
sudo umount /mnt/data
# Dateisystem prüfen
sudo fsck /dev/sda1
```

### LVM-Verwaltung: `pvcreate` / `vgcreate` / `lvcreate`

Verwaltet Logical Volume Manager (LVM) Speicher.

```bash
# Physisches Volume erstellen
sudo pvcreate /dev/sdb
# Volume Group erstellen
sudo vgcreate vg_data /dev/sdb
# Logisches Volume erstellen
sudo lvcreate -L 10G -n lv_data vg_data
# Logisches Volume erweitern
sudo lvextend -L +5G /dev/vg_data/lv_data
```

### Mount-Konfiguration: `/etc/fstab`

Konfiguriert permanente Mount-Punkte.

```bash
# fstab-Datei bearbeiten
sudo vi /etc/fstab
# fstab-Einträge testen
sudo mount -a
# Eingebundene Dateisysteme anzeigen
mount | column -t
```

## Sicherheit & SELinux

### SELinux-Verwaltung: `getenforce` / `setenforce`

Steuert die SELinux-Durchsetzung und Richtlinien.

```bash
# SELinux-Status prüfen
getenforce
# SELinux auf permissiv setzen
sudo setenforce 0
# SELinux auf enforcing setzen
sudo setenforce 1
# SELinux-Kontext prüfen
ls -Z filename
# SELinux-Kontext ändern
sudo chcon -t httpd_exec_t /path/to/file
```

### SELinux-Tools: `sealert` / `ausearch`

Analysiert SELinux-Verweigerungen und Audit-Protokolle.

```bash
# SELinux-Warnungen prüfen
sudo sealert -a /var/log/audit/audit.log
# Audit-Protokolle durchsuchen
sudo ausearch -m avc -ts recent
# SELinux-Richtlinie generieren
sudo audit2allow -M mypolicy < /var/log/audit/audit.log
```

### SSH-Konfiguration: `/etc/ssh/sshd_config`

Konfiguriert den SSH-Daemon für sicheren Remote-Zugriff.

```bash
# SSH-Konfiguration bearbeiten
sudo vi /etc/ssh/sshd_config
# SSH-Dienst neu starten
sudo systemctl restart sshd
# SSH-Verbindung testen
ssh user@hostname
# SSH-Schlüssel kopieren
ssh-copy-id user@hostname
```

### Systemaktualisierungen: `dnf update`

Hält das System durch regelmäßige Aktualisierungen sicher.

```bash
# Alle Pakete aktualisieren
sudo dnf update
# Nur Sicherheitspatches aktualisieren
sudo dnf update --security
# Nach verfügbaren Updates suchen
dnf check-update --security
# Automatische Updates aktivieren
sudo systemctl enable dnf-automatic.timer
```

## Leistungsüberwachung

### Systemüberwachung: `iostat` / `vmstat`

Überwacht die Systemleistung und Ressourcennutzung.

```bash
# E/A-Statistiken anzeigen
iostat -x 1
# Virtuelle Speicherstatistiken anzeigen
vmstat 1
# Netzwerksstatistiken anzeigen
ss -tuln
# Festplatten-E/A anzeigen
iotop
```

### Ressourcennutzung: `sar` / `top`

Analysiert historische und Echtzeit-Systemmetriken.

```bash
# Systemaktivitätsbericht
sar -u 1 3
# Speichernutzungsbericht
sar -r
# Netzwerkaktivitätsbericht
sar -n DEV
# Lastdurchschnitt überwachen
uptime
```

### Prozessanalyse: `strace` / `lsof`

Debuggt Prozesse und Dateizugriffe.

```bash
# Systemaufrufe verfolgen
strace -p 1234
# Geöffnete Dateien auflisten
lsof
# Von Prozess geöffnete Dateien anzeigen
lsof -p 1234
# Netzwerkverbindungen anzeigen
lsof -i
```

### Leistungsoptimierung: `tuned`

Optimiert die Systemleistung für spezifische Workloads.

```bash
# Verfügbare Profile auflisten
tuned-adm list
# Aktives Profil anzeigen
tuned-adm active
# Leistungsprofil einstellen
sudo tuned-adm profile throughput-performance
# Benutzerdefiniertes Profil erstellen
sudo tuned-adm profile_mode
```

## RHEL Installation & Einrichtung

### Systemregistrierung: `subscription-manager`

Registriert das System beim Red Hat Customer Portal.

```bash
# System registrieren
sudo subscription-manager
register --username
your_username
# Abonnements automatisch anhängen
sudo subscription-manager
attach --auto
# Verfügbare Abonnements auflisten
subscription-manager list --
available
# Systemstatus anzeigen
subscription-manager status
```

### Repository-Verwaltung: `dnf config-manager`

Verwaltet Software-Repositories.

```bash
# Aktivierte Repositories auflisten
dnf repolist
# Repository aktivieren
sudo dnf config-manager --
enable repository-name
# Repository deaktivieren
sudo dnf config-manager --
disable repository-name
# Neues Repository hinzufügen
sudo dnf config-manager --add-
repo https://example.com/repo
```

### Systemkonfiguration: `hostnamectl` / `timedatectl`

Konfiguriert grundlegende Systemeinstellungen.

```bash
# Hostname festlegen
sudo hostnamectl set-hostname
new-hostname
# Systeminformationen anzeigen
hostnamectl
# Zeitzone festlegen
sudo timedatectl set-timezone
America/New_York
# Zeiteinstellungen anzeigen
timedatectl
```

## Fehlerbehebung & Diagnose

### Systemprotokolle: `/var/log/`

Untersucht Systemprotokolldateien auf Probleme.

```bash
# Systemmeldungen anzeigen
sudo tail -f /var/log/messages
# Authentifizierungsprotokolle anzeigen
sudo tail -f /var/log/secure
# Boot-Protokolle anzeigen
sudo journalctl -b
# Kernel-Meldungen anzeigen
dmesg | tail
```

### Hardware-Diagnose: `dmidecode` / `lshw`

Untersucht Hardwareinformationen und -zustand.

```bash
# Hardwareinformationen anzeigen
sudo dmidecode -t system
# Hardwarekomponenten auflisten
sudo lshw -short
# Speicherinformationen prüfen
sudo dmidecode -t memory
# CPU-Informationen anzeigen
lscpu
```

### Netzwerk-Fehlerbehebung: `netstat` / `ss`

Netzwerkdiagnosewerkzeuge und -dienstprogramme.

```bash
# Netzwerkverbindungen anzeigen
ss -tuln
# Routing-Tabelle anzeigen
ip route show
# DNS-Auflösung testen
nslookup google.com
# Netzwerkpfad verfolgen
traceroute google.com
```

### Wiederherstellung & Rettung: `systemctl rescue`

Systemwiederherstellung und Notfallverfahren.

```bash
# In den Rettungsmodus wechseln
sudo systemctl rescue
# In den Notfallmodus wechseln
sudo systemctl emergency
# Fehlgeschlagene Dienste zurücksetzen
sudo systemctl reset-failed
# Bootloader neu konfigurieren
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

## Automatisierung & Skripterstellung

### Cron-Jobs: `crontab`

Plant automatisierte Aufgaben und Wartungsarbeiten.

```bash
# Benutzer-Crontab bearbeiten
crontab -e
# Benutzer-Crontab auflisten
crontab -l
# Benutzer-Crontab entfernen
crontab -r
# Beispiel: Skript täglich um 2 Uhr morgens ausführen
0 2 * * * /path/to/script.sh
```

### Shell-Skripterstellung: `bash`

Erstellt und führt Shell-Skripte zur Automatisierung aus.

```bash
#!/bin/bash
# Einfaches Backup-Skript
DATE=$(date +%Y%m%d)
tar -czf backup_$DATE.tar.gz /home/user/documents
echo "Backup abgeschlossen: backup_$DATE.tar.gz"
```

### Umgebungsvariablen: `export` / `env`

Verwaltet Umgebungsvariablen und Shell-Einstellungen.

```bash
# Umgebungsvariable setzen
export MY_VAR="value"
# Alle Umgebungsvariablen anzeigen
env
# Spezifische Variable anzeigen
echo $PATH
# Zu PATH hinzufügen
export PATH=$PATH:/new/directory
```

### Systemautomatisierung: `systemd timers`

Erstellt systemd-basierte geplante Aufgaben.

```bash
# Timer-Unit-Datei erstellen
sudo vi /etc/systemd/system/backup.timer
# Timer aktivieren und starten
sudo systemctl enable backup.timer
sudo systemctl start backup.timer
# Aktive Timer auflisten
systemctl list-timers
```

## Relevante Links

- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/git">Git Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>
- <router-link to="/ansible">Ansible Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/cybersecurity">Cybersicherheit Spickzettel</router-link>

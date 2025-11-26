---
title: 'Linux Spickzettel'
description: 'Lernen Sie Linux mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Linux Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a href="https://linux-commands.labex.io/" target="_blank">Besuchen Sie Linux Commands</a>
</base-disclaimer-title>
<base-disclaimer-content>
Für umfassende Nachschlagewerke zu Linux-Befehlen, Syntaxbeispielen und detaillierter Dokumentation besuchen Sie bitte <a href="https://linux-commands.labex.io/" target="_blank">linux-commands.labex.io</a>. Diese unabhängige Seite bietet umfangreiche Linux-Spickzettel, die wesentliche Befehle, Konzepte und Best Practices für Linux-Administratoren und Entwickler abdecken.
</base-disclaimer-content>
</base-disclaimer>

## Systeminformationen & Status

### Systeminformationen: `uname`

Anzeige von Systeminformationen einschließlich Kernel und Architektur.

```bash
# Kernelnamen anzeigen
uname
# Alle Systeminformationen anzeigen
uname -a
# Kernelversion anzeigen
uname -r
# Architektur anzeigen
uname -m
# Betriebssystem anzeigen
uname -o
```

### Hardwareinformationen: `lscpu`, `lsblk`

Anzeige detaillierter Hardware-Spezifikationen und Blockgeräte.

```bash
# CPU-Informationen
lscpu
# Blockgeräte (Festplatten, Partitionen)
lsblk
# Speicherinformationen
free -h
# Festplattennutzung nach Dateisystem
df -h
```

### Systemlaufzeit: `uptime`

Anzeige der Systemlaufzeit und der Lastdurchschnitte.

```bash
# Systemlaufzeit und Last
uptime
# Detailliertere Laufzeitanzeige
uptime -p
# Laufzeit seit einem bestimmten Datum anzeigen
uptime -s
```

### Aktuelle Benutzer: `who`, `w`

Anzeige der aktuell angemeldeten Benutzer und ihrer Aktivitäten.

```bash
# Angemeldete Benutzer anzeigen
who
# Detaillierte Benutzerinformationen mit Aktivitäten
w
# Aktuellen Benutzernamen anzeigen
whoami
# Anmeldehistorie anzeigen
last
```

### Umgebungsvariablen: `env`

Anzeige und Verwaltung von Umgebungsvariablen.

```bash
# Alle Umgebungsvariablen anzeigen
env
# Spezifische Variable anzeigen
echo $HOME
# Umgebungsvariable setzen
export PATH=$PATH:/new/path
# PATH-Variable anzeigen
echo $PATH
```

### Datum & Uhrzeit: `date`, `timedatectl`

Anzeige und Einstellung von Systemdatum und -uhrzeit.

```bash
# Aktuelles Datum und Uhrzeit
date
# Systemzeit einstellen (als root)
date MMddhhmmyyyy
# Zeitzoneninformationen
timedatectl
# Zeitzone einstellen
timedatectl set-timezone America/New_York
```

## Datei- & Verzeichnisoperationen

### Dateien auflisten: `ls`

Anzeige von Dateien und Verzeichnissen mit verschiedenen Formatierungsoptionen.

```bash
# Dateien im aktuellen Verzeichnis auflisten
ls
# Detaillierte Auflistung mit Berechtigungen
ls -l
# Versteckte Dateien anzeigen
ls -la
# Dateigrößen in menschenlesbarem Format
ls -lh
# Nach Änderungszeit sortieren
ls -lt
```

### Verzeichnisse navigieren: `cd`, `pwd`

Verzeichnis wechseln und aktuellen Speicherort anzeigen.

```bash
# Zum Home-Verzeichnis wechseln
cd
# Zu einem bestimmten Verzeichnis wechseln
cd /path/to/directory
# Eine Ebene nach oben wechseln
cd ..
# Aktuelles Verzeichnis anzeigen
pwd
# Zum vorherigen Verzeichnis wechseln
cd -
```

### Erstellen & Entfernen: `mkdir`, `rmdir`, `rm`

Dateien und Verzeichnisse erstellen und löschen.

```bash
# Verzeichnis erstellen
mkdir newdir
# Verschachtelte Verzeichnisse erstellen
mkdir -p path/to/nested/dir
# Leeres Verzeichnis entfernen
rmdir dirname
# Datei entfernen
rm filename
# Verzeichnis rekursiv entfernen
rm -rf dirname
```

### Dateiinhalt anzeigen: `cat`, `less`, `head`, `tail`

Anzeige von Dateiinhalt mit verschiedenen Methoden und Paginierung.

```bash
# Gesamte Datei anzeigen
cat filename
# Datei mit Paginierung anzeigen
less filename
# Erste 10 Zeilen anzeigen
head filename
# Letzte 10 Zeilen anzeigen
tail filename
# Dateiänderungen in Echtzeit verfolgen
tail -f logfile
```

### Kopieren & Verschieben: `cp`, `mv`

Dateien und Verzeichnisse kopieren und verschieben.

```bash
# Datei kopieren
cp source.txt destination.txt
# Verzeichnis rekursiv kopieren
cp -r sourcedir/ destdir/
# Datei verschieben/umbenennen
mv oldname.txt newname.txt
# In ein anderes Verzeichnis verschieben
mv file.txt /path/to/destination/
# Kopieren mit Beibehaltung der Attribute
cp -p file.txt backup.txt
```

### Dateien finden: `find`, `locate`

Nach Dateien und Verzeichnissen nach Name, Typ oder Eigenschaften suchen.

```bash
# Nach Namen suchen
find /path -name "filename"
# Dateien suchen, die in den letzten 7 Tagen geändert wurden
find /path -mtime -7
# Nach Dateityp suchen
find /path -type f -name "*.txt"
# Dateien schnell lokalisieren (erfordert aktualisierte Datenbank)
locate filename
# Finden und Befehl ausführen
find /path -name "*.log" -exec rm {} \;
```

### Dateiberechtigungen: `chmod`, `chown`

Dateiberechtigungen und Besitzverhältnisse ändern.

```bash
# Berechtigungen ändern (numerisch)
chmod 755 filename
# Ausführungsberechtigung hinzufügen
chmod +x script.sh
# Besitzverhältnis ändern
chown user:group filename
# Besitzverhältnis rekursiv ändern
chown -R user:group directory/
# Dateiberechtigungen anzeigen
ls -l filename
```

## Prozessverwaltung

### Prozessauflistung: `ps`

Anzeige laufender Prozesse und ihrer Details.

```bash
# Benutzerprozesse anzeigen
ps
# Alle Prozesse mit Details anzeigen
ps aux
# Prozessbaum anzeigen
ps -ef --forest
# Prozesse nach Benutzer anzeigen
ps -u username
```

### Prozesse beenden: `kill`, `killall`

Prozesse nach PID oder Namen beenden.

```bash
# Prozessüberwachung in Echtzeit
top
# Prozess nach PID beenden
kill 1234
# Prozess erzwingen
kill -9 1234
# Nach Prozessname beenden
killall processname
# Alle Signale auflisten
kill -l
# Spezifisches Signal senden
kill -HUP 1234
```

### Hintergrundjobs: `jobs`, `bg`, `fg`

Hintergrund- und Vordergrundprozesse verwalten.

```bash
# Aktive Jobs auflisten
jobs
# Job in den Hintergrund senden
bg %1
# Job in den Vordergrund bringen
fg %1
# Befehl im Hintergrund ausführen
command &
# Vom Terminal trennen
nohup command &
```

### Systemmonitor: `htop`, `systemctl`

Systemressourcen überwachen und Dienste verwalten.

```bash
# Verbesserter Prozessbetrachter (falls installiert)
htop
# Dienststatus prüfen
systemctl status servicename
# Dienst starten
systemctl start servicename
# Dienst beim Booten aktivieren
systemctl enable servicename
# Systemprotokolle anzeigen
journalctl -f
```

## Netzwerkoperationen

### Netzwerkkonfiguration: `ip`, `ifconfig`

Netzwerkschnittstellen anzeigen und konfigurieren.

```bash
# Netzwerkschnittstellen anzeigen
ip addr show
# Routing-Tabelle anzeigen
ip route show
# Schnittstelle konfigurieren (temporär)
ip addr add 192.168.1.10/24 dev eth0
# Schnittstelle aktivieren/deaktivieren
ip link set eth0 up
# Veraltete Schnittstellenkonfiguration
ifconfig
```

### Netzwerktests: `ping`, `traceroute`

Netzwerkkonnektivität testen und Paketrouten verfolgen.

```bash
# Konnektivität testen
ping google.com
# Ping mit begrenzter Anzahl
ping -c 4 192.168.1.1
# Route zum Ziel verfolgen
traceroute google.com
# MTR - Netzwerkdiagnosetool
mtr google.com
```

### Port- & Verbindungsanalyse: `netstat`, `ss`

Netzwerkverbindungen und lauschende Ports anzeigen.

```bash
# Alle Verbindungen anzeigen
netstat -tuln
# Lauschende Ports anzeigen
netstat -tuln | grep LISTEN
# Moderner Ersatz für netstat
ss -tuln
# Prozesse anzeigen, die Ports verwenden
netstat -tulnp
# Spezifischen Port prüfen
netstat -tuln | grep :80
```

### Dateiübertragung: `scp`, `rsync`

Dateien sicher zwischen Systemen übertragen.

```bash
# Datei auf einen Remote-Host kopieren
scp file.txt user@host:/path/
# Von einem Remote-Host kopieren
scp user@host:/path/file.txt ./
# Verzeichnisse synchronisieren
rsync -avz localdir/ user@host:/remotedir/
# Rsync mit Fortschrittsanzeige
rsync -avz --progress src/ dest/
```

## Textverarbeitung & Suche

### Textsuche: `grep`

Muster in Dateien und Befehlsausgaben suchen.

```bash
# Nach Muster in Datei suchen
grep "pattern" filename
# Suche ohne Berücksichtigung der Groß-/Kleinschreibung
grep -i "pattern" filename
# Rekursive Suche in Verzeichnissen
grep -r "pattern" /path/
# Zeilennummern anzeigen
grep -n "pattern" filename
# Übereinstimmende Zeilen zählen
grep -c "pattern" filename
```

### Textmanipulation: `sed`, `awk`

Text mit Stream-Editoren und Muster-Scannern bearbeiten und verarbeiten.

```bash
# Text in Datei ersetzen
sed 's/old/new/g' filename
# Zeilen löschen, die Muster enthalten
sed '/pattern/d' filename
# Spezifische Felder ausgeben
awk '{print $1, $3}' filename
# Werte in einer Spalte summieren
awk '{sum += $1} END {print sum}' filename
```

### Sortieren & Zählen: `sort`, `uniq`, `wc`

Daten sortieren, Duplikate entfernen und Zeilen, Wörter oder Zeichen zählen.

```bash
# Dateiinhalt sortieren
sort filename
# Numerisch sortieren
sort -n numbers.txt
# Duplizierte Zeilen entfernen
uniq filename
# Sortieren und Duplikate entfernen
sort filename | uniq
# Zeilen, Wörter, Zeichen zählen
wc filename
# Nur Zeilen zählen
wc -l filename
```

### Ausschneiden & Einfügen: `cut`, `paste`

Spezifische Spalten extrahieren und Dateien kombinieren.

```bash
# Erste Spalte extrahieren
cut -d',' -f1 file.csv
# Zeichenbereich extrahieren
cut -c1-10 filename
# Dateien nebeneinander zusammenfügen
paste file1.txt file2.txt
# Benutzerdefinierten Trennwert verwenden
cut -d':' -f1,3 /etc/passwd
```

## Archivierung & Komprimierung

### Archive erstellen: `tar`

Komprimierte Archive erstellen und extrahieren.

```bash
# Tar-Archiv erstellen
tar -cf archive.tar files/
# Komprimiertes Archiv erstellen
tar -czf archive.tar.gz files/
# Archiv extrahieren
tar -xf archive.tar
# Komprimiertes Archiv extrahieren
tar -xzf archive.tar.gz
# Archivinhalt auflisten
tar -tf archive.tar
```

### Komprimierung: `gzip`, `zip`

Dateien mit verschiedenen Algorithmen komprimieren und dekomprimieren.

```bash
# Datei mit gzip komprimieren
gzip filename
# Gzip-Datei dekomprimieren
gunzip filename.gz
# Zip-Archiv erstellen
zip archive.zip file1 file2
# Zip-Archiv extrahieren
unzip archive.zip
# Zip-Inhalt auflisten
unzip -l archive.zip
```

### Erweiterte Archive: `tar` Optionen

Erweiterte Tar-Operationen für Backup und Wiederherstellung.

```bash
# Archiv mit Komprimierung erstellen
tar -czvf backup.tar.gz /home/user/
# In ein bestimmtes Verzeichnis extrahieren
tar -xzf archive.tar.gz -C /destination/
# Dateien zu bestehendem Archiv hinzufügen
tar -rf archive.tar newfile.txt
# Archiv mit neueren Dateien aktualisieren
tar -uf archive.tar files/
```

### Speicherplatz: `du`

Festplattennutzung und Verzeichnisgrößen analysieren.

```bash
# Verzeichnisgrößen anzeigen
du -h /path/
# Zusammenfassung der Gesamtgröße
du -sh /path/
# Größen aller Unterverzeichnisse anzeigen
du -h --max-depth=1 /path/
# Größte Verzeichnisse zuerst
du -h | sort -hr | head -10
```

## Systemüberwachung & Leistung

### Speichernutzung: `free`, `vmstat`

Speichernutzung und virtuelle Speicherstatistiken überwachen.

```bash
# Speicherbelegung Zusammenfassung
free -h
# Detaillierte Speicherstatistiken
cat /proc/meminfo
# Virtuelle Speicherstatistiken
vmstat
# Speichernutzung alle 2 Sekunden
vmstat 2
# Swap-Nutzung anzeigen
swapon --show
```

### Festplatten-I/O: `iostat`, `iotop`

Festplatten-Eingabe-/Ausgabe-Leistung überwachen und Engpässe identifizieren.

```bash
# I/O-Statistiken (erfordert sysstat)
iostat
# I/O-Statistiken alle 2 Sekunden
iostat 2
# Festplatten-I/O nach Prozess überwachen
iotop
# I/O-Nutzung für spezifisches Gerät anzeigen
iostat -x /dev/sda
```

### Systemlast: `top`, `htop`

Systemlast, CPU-Auslastung und laufende Prozesse überwachen.

```bash
# Prozessüberwachung in Echtzeit
top
# Verbesserter Prozessbetrachter
htop
# Lastdurchschnitte anzeigen
uptime
# CPU-Informationen anzeigen
lscpu
# Spezifischen Prozess überwachen
top -p PID
```

### Protokolldateien: `journalctl`, `dmesg`

Systemprotokolle zur Fehlerbehebung anzeigen und analysieren.

```bash
# Systemprotokolle anzeigen
journalctl
# Protokolle in Echtzeit verfolgen
journalctl -f
# Protokolle für einen bestimmten Dienst anzeigen
journalctl -u servicename
# Kernelmeldungen
dmesg
# Letzte Boot-Meldungen
dmesg | tail
```

## Benutzer- & Berechtigungsverwaltung

### Benutzeroperationen: `useradd`, `usermod`, `userdel`

Benutzerkonten erstellen, ändern und löschen.

```bash
# Neuen Benutzer hinzufügen
useradd username
# Benutzer mit Home-Verzeichnis hinzufügen
useradd -m username
# Benutzerkonto ändern
usermod -aG groupname username
# Benutzerkonto löschen
userdel username
# Benutzerkonto mit Home-Verzeichnis löschen
userdel -r username
```

### Gruppenverwaltung: `groupadd`, `groups`

Benutzergruppen erstellen und verwalten.

```bash
# Neue Gruppe erstellen
groupadd groupname
# Gruppen des Benutzers anzeigen
groups username
# Alle Gruppen anzeigen
cat /etc/group
# Benutzer zur Gruppe hinzufügen
usermod -aG groupname username
# Primäre Gruppe des Benutzers ändern
usermod -g groupname username
```

### Benutzer wechseln: `su`, `sudo`

Benutzer wechseln und Befehle mit erhöhten Rechten ausführen.

```bash
# Zu Root-Benutzer wechseln
su -
# Zu einem bestimmten Benutzer wechseln
su - username
# Befehl als Root ausführen
sudo command
# Befehl als spezifischer Benutzer ausführen
sudo -u username command
# Sudoers-Datei bearbeiten
visudo
```

### Passwortverwaltung: `passwd`, `chage`

Benutzerpasswörter und Kontenrichtlinien verwalten.

```bash
# Passwort ändern
passwd
# Passwort eines anderen Benutzers ändern (als root)
passwd username
# Passwortalterungsinformationen anzeigen
chage -l username
# Passwortablauf auf 90 Tage festlegen
chage -M 90 username
# Passwortwechsel beim nächsten Login erzwingen
passwd -e username
```

## Paketverwaltung

### APT (Debian/Ubuntu): `apt`, `apt-get`

Pakete auf Debian-basierten Systemen verwalten.

```bash
# Paketliste aktualisieren
apt update
# Alle Pakete aktualisieren
apt upgrade
# Paket installieren
apt install packagename
# Paket entfernen
apt remove packagename
# Nach Paketen suchen
apt search packagename
# Paketinformationen anzeigen
apt show packagename
```

### YUM/DNF (RHEL/Fedora): `yum`, `dnf`

Pakete auf Red Hat-basierten Systemen verwalten.

```bash
# Paket installieren
yum install packagename
# Alle Pakete aktualisieren
yum update
# Paket entfernen
yum remove packagename
# Nach Paketen suchen
yum search packagename
# Installierte Pakete auflisten
yum list installed
```

### Snap-Pakete: `snap`

Snap-Pakete über verschiedene Distributionen hinweg installieren und verwalten.

```bash
# Snap-Paket installieren
snap install packagename
# Installierte Snaps auflisten
snap list
# Snap-Pakete aktualisieren
snap refresh
# Snap-Paket entfernen
snap remove packagename
# Nach Snap-Paketen suchen
snap find packagename
```

### Flatpak-Pakete: `flatpak`

Flatpak-Anwendungen für sandboxed Software verwalten.

```bash
# Flatpak installieren
flatpak install packagename
# Installierte Flatpaks auflisten
flatpak list
# Flatpak-Pakete aktualisieren
flatpak update
# Flatpak deinstallieren
flatpak uninstall packagename
# Nach Flatpak-Paketen suchen
flatpak search packagename
```

## Shell & Scripting

### Befehlshistorie: `history`

Auf die Befehlszeilenhistorie zugreifen und diese verwalten.

```bash
# Befehlshistorie anzeigen
history
# Letzte 10 Befehle anzeigen
history 10
# Vorherigen Befehl ausführen
!!
# Befehl nach Nummer ausführen
!123
# Historie interaktiv durchsuchen
Ctrl+R
```

### Aliase & Funktionen: `alias`

Verknüpfungen für häufig verwendete Befehle erstellen.

```bash
# Alias erstellen
alias ll='ls -la'
# Alle Aliase anzeigen
alias
# Alias entfernen
unalias ll
# Alias permanent machen (zu .bashrc hinzufügen)
echo "alias ll='ls -la'" >> ~/.bashrc
```

### Eingabe-/Ausgabe-Umleitung

Befehlseingabe und -ausgabe auf Dateien oder andere Befehle umleiten.

```bash
# Ausgabe in Datei umleiten
command > output.txt
# Ausgabe an Datei anhängen
command >> output.txt
# Eingabe von Datei umleiten
command < input.txt
# Sowohl stdout als auch stderr umleiten
command &> output.txt
# Ausgabe an einen anderen Befehl weiterleiten (Pipe)
command1 | command2
```

### Umgebungseinrichtung: `.bashrc`, `.profile`

Shell-Umgebung und Startskripte konfigurieren.

```bash
# Bash-Konfiguration bearbeiten
nano ~/.bashrc
# Konfiguration neu laden
source ~/.bashrc
# Umgebungsvariable setzen
export VARIABLE=value
# Zu PATH hinzufügen
export PATH=$PATH:/new/path
# Umgebungsvariablen anzeigen
printenv
```

## Systeminstallation & Einrichtung

### Distributionsoptionen: Ubuntu, CentOS, Debian

Linux-Distributionen für verschiedene Anwendungsfälle auswählen und installieren.

```bash
# Ubuntu Server
wget ubuntu-server.iso
# CentOS Stream
wget centos-stream.iso
# Debian Stable
wget debian.iso
# ISO-Integrität überprüfen
sha256sum linux.iso
```

### Boot & Installation: USB, Netzwerk

Bootfähige Medien erstellen und Systeminstallation durchführen.

```bash
# Bootfähiges USB erstellen (Linux)
dd if=linux.iso of=/dev/sdX bs=4M
# Bootfähiges USB erstellen (plattformübergreifend)
# Tools wie Rufus, Etcher oder UNetbootin verwenden
# Netzwerkinstallation
# PXE-Boot für Netzwerkinstallationen konfigurieren
```

### Erste Konfiguration: Benutzer, Netzwerk, SSH

Grundlegende Systemkonfiguration nach der Installation einrichten.

```bash
# Hostname setzen
hostnamectl set-hostname newname
# Statische IP konfigurieren
# /etc/netplan/ (Ubuntu) oder /etc/network/interfaces bearbeiten
# SSH-Dienst aktivieren
systemctl enable ssh
systemctl start ssh
# Firewall konfigurieren
ufw enable
ufw allow ssh
```

## Sicherheit & Best Practices

### Firewall-Konfiguration: `ufw`, `iptables`

Firewall-Regeln konfigurieren, um das System vor Netzwerkbedrohungen zu schützen.

```bash
# UFW Firewall aktivieren
ufw enable
# Spezifischen Port erlauben
ufw allow 22/tcp
# Dienst nach Namen erlauben
ufw allow ssh
# Zugriff verweigern
ufw deny 23
# Firewall-Status anzeigen
ufw status verbose
# Erweiterte Regeln mit iptables
iptables -L
```

### Dateiintegrität: `checksums`

Dateiintegrität überprüfen und unbefugte Änderungen erkennen.

```bash
# MD5-Prüfsumme generieren
md5sum filename
# SHA256-Prüfsumme generieren
sha256sum filename
# Prüfsumme verifizieren
sha256sum -c checksums.txt
# Prüfsummen-Datei erstellen
sha256sum *.txt > checksums.txt
```

### System-Updates: Sicherheitspatches

System durch regelmäßige Updates und Sicherheitspatches sicher halten.

```bash
# Ubuntu Sicherheitsupdates
apt update && apt upgrade
# Automatische Sicherheitsupdates
unattended-upgrades
# CentOS/RHEL Updates
yum update --security
# Verfügbare Updates auflisten
apt list --upgradable
```

### Protokollüberwachung: Sicherheitsereignisse

Systemprotokolle auf Sicherheitsereignisse und Anomalien überwachen.

```bash
# Authentifizierungsprotokolle überwachen
tail -f /var/log/auth.log
# Fehlgeschlagene Anmeldeversuche prüfen
grep "Failed password" /var/log/auth.log
# Systemprotokolle überwachen
tail -f /var/log/syslog
# Anmeldehistorie prüfen
last
# Nach verdächtigen Aktivitäten suchen
journalctl -p err
```

## Fehlerbehebung & Wiederherstellung

### Boot-Probleme: GRUB-Wiederherstellung

Probleme mit dem Bootloader und dem Kernel beheben.

```bash
# Aus dem Rettungsmodus booten
# GRUB-Menü beim Booten aufrufen
# Root-Dateisystem einbinden
mount /dev/sda1 /mnt
# In das System wechseln (chroot)
chroot /mnt
# GRUB neu installieren
grub-install /dev/sda
# GRUB-Konfiguration aktualisieren
update-grub
```

### Dateisystemreparatur: `fsck`

Dateisystemfehler überprüfen und reparieren.

```bash
# Dateisystem prüfen
fsck /dev/sda1
# Erzwingen einer Dateisystemprüfung
fsck -f /dev/sda1
# Automatische Reparatur
fsck -y /dev/sda1
# Alle gemounteten Dateisysteme prüfen
fsck -A
```

### Dienstprobleme: `systemctl`

Dienstbezogene Probleme diagnostizieren und beheben.

```bash
# Dienststatus prüfen
systemctl status servicename
# Dienstprotokolle anzeigen
journalctl -u servicename
# Fehlgeschlagenen Dienst neu starten
systemctl restart servicename
# Dienst beim Booten aktivieren
systemctl enable servicename
# Fehlgeschlagene Dienste auflisten
systemctl --failed
```

### Leistungsprobleme: Ressourcenanalyse

Systemleistungsengpässe identifizieren und beheben.

```bash
# Speicherplatz prüfen
df -h
# I/O-Nutzung überwachen
iotop
# Speicherbelegung prüfen
free -h
# CPU-Auslastung identifizieren
top
# Geöffnete Dateien auflisten
lsof
```

## Relevante Links

- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>
- <router-link to="/git">Git Spickzettel</router-link>
- <router-link to="/ansible">Ansible Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/cybersecurity">Cybersicherheit Spickzettel</router-link>

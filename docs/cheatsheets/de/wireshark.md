---
title: 'Wireshark Spickzettel | LabEx'
description: 'Lernen Sie die Wireshark-Netzwerkanalyse mit diesem umfassenden Spickzettel. Schnelle Referenz für Paketaufnahme, Netzwerkanalyse, Verkehrsinspektion, Fehlerbehebung und Netzwerksicherheitsüberwachung.'
pdfUrl: '/cheatsheets/pdf/wireshark-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Wireshark Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/wireshark">Lernen Sie Wireshark mit Hands-On-Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie die Netzwerkanalyse von Paketen mit Wireshark durch praktische Übungen und reale Szenarien. LabEx bietet umfassende Wireshark-Kurse, die sich mit dem wesentlichen Paket-Sniffing, Anzeigefiltern, Protokollanalyse, Netzwerk-Fehlerbehebung und Sicherheitsüberwachung befassen. Meistern Sie Techniken zur Analyse des Netzwerkverkehrs und zur Paketinspektion.
</base-disclaimer-content>
</base-disclaimer>

## Erfassungsfilter & Verkehrsaufnahme

### Host-Filterung

Erfassen Sie den Verkehr zu/von bestimmten Hosts.

```bash
# Erfassen von Verkehr von/zu spezifischer IP
host 192.168.1.100
# Erfassen von Verkehr von spezifischer Quelle
src host 192.168.1.100
# Erfassen von Verkehr zu spezifischem Ziel
dst host 192.168.1.100
# Erfassen von Verkehr aus Subnetz
net 192.168.1.0/24
```

<BaseQuiz id="wireshark-filter-1" correct="A">
  <template #question>
    Was filtert `host 192.168.1.100` in Wireshark?
  </template>
  
  <BaseQuizOption value="A" correct>Jeglicher Verkehr zu oder von 192.168.1.100</BaseQuizOption>
  <BaseQuizOption value="B">Nur Verkehr von 192.168.1.100</BaseQuizOption>
  <BaseQuizOption value="C">Nur Verkehr zu 192.168.1.100</BaseQuizOption>
  <BaseQuizOption value="D">Verkehr auf Port 192.168.1.100</BaseQuizOption>
  
  <BaseQuizAnswer>
    Der `host`-Filter erfasst jeglichen Verkehr, bei dem die angegebene IP-Adresse entweder die Quelle oder das Ziel ist. Verwenden Sie `src host` für Quelle-nur oder `dst host` für Ziel-nur Filterung.
  </BaseQuizAnswer>
</BaseQuiz>

### Port-Filterung

Erfassen Sie Verkehr auf bestimmten Ports.

```bash
# HTTP-Verkehr (Port 80)
port 80
# HTTPS-Verkehr (Port 443)
port 443
# SSH-Verkehr (Port 22)
port 22
# DNS-Verkehr (Port 53)
port 53
# Port-Bereich
portrange 1000-2000
```

<BaseQuiz id="wireshark-port-1" correct="D">
  <template #question>
    Was filtert `port 80` in Wireshark?
  </template>
  
  <BaseQuizOption value="A">Nur HTTP-Anfragen</BaseQuizOption>
  <BaseQuizOption value="B">Nur HTTP-Antworten</BaseQuizOption>
  <BaseQuizOption value="C">Nur TCP-Pakete</BaseQuizOption>
  <BaseQuizOption value="D" correct>Jeglicher Verkehr auf Port 80 (sowohl Quelle als auch Ziel)</BaseQuizOption>
  
  <BaseQuizAnswer>
    Der `port`-Filter erfasst jeglichen Verkehr, bei dem Port 80 entweder der Quell- oder Zielport ist. Dies schließt sowohl HTTP-Anfragen als auch Antworten ein, sowie jeglichen anderen Verkehr, der Port 80 verwendet.
  </BaseQuizAnswer>
</BaseQuiz>

### Protokoll-Filterung

Erfassen Sie spezifischen Protokollverkehr.

```bash
# Nur TCP-Verkehr
tcp
# Nur UDP-Verkehr
udp
# Nur ICMP-Verkehr
icmp
# Nur ARP-Verkehr
arp
```

### Erweiterte Erfassungsfilter

Kombinieren Sie mehrere Bedingungen für präzise Erfassung.

```bash
# HTTP-Verkehr zu/von spezifischem Host
host 192.168.1.100 and port 80
# TCP-Verkehr außer SSH
tcp and not port 22
# Verkehr zwischen zwei Hosts
host 192.168.1.100 and host 192.168.1.200
# HTTP oder HTTPS Verkehr
port 80 or port 443
```

<BaseQuiz id="wireshark-advanced-1" correct="B">
  <template #question>
    Was filtert `tcp and not port 22` an Verkehr?
  </template>
  
  <BaseQuizOption value="A">Nur SSH-Verkehr</BaseQuizOption>
  <BaseQuizOption value="B" correct>Jeglicher TCP-Verkehr außer SSH (Port 22)</BaseQuizOption>
  <BaseQuizOption value="C">UDP-Verkehr auf Port 22</BaseQuizOption>
  <BaseQuizOption value="D">Jeglicher Netzwerkverkehr</BaseQuizOption>
  
  <BaseQuizAnswer>
    Dieser Filter erfasst jeglichen TCP-Verkehr, schließt jedoch Pakete auf Port 22 (SSH) aus. Der Operator `and not` schließt den angegebenen Port aus, behält aber den gesamten anderen TCP-Verkehr bei.
  </BaseQuizAnswer>
</BaseQuiz>

### Schnittstellenauswahl

Wählen Sie Netzwerkschnittstellen für die Erfassung aus.

```bash
# Verfügbare Schnittstellen auflisten
tshark -D
# Erfassung auf spezifischer Schnittstelle
# Ethernet-Schnittstelle
eth0
# WiFi-Schnittstelle
wlan0
# Loopback-Schnittstelle
lo
```

### Erfassungsoptionen

Konfigurieren Sie Erfassungsparameter.

```bash
# Erfassungsdateigröße begrenzen (MB)
-a filesize:100
# Erfassungsdauer begrenzen (Sekunden)
-a duration:300
# Ringpuffer mit 10 Dateien
-b files:10
# Promiscuous Mode (allen Verkehr erfassen)
-p
```

## Anzeigefilter & Paket-Analyse

### Grundlegende Anzeigefilter

Wesentliche Filter für gängige Protokolle und Verkehrstypen.

```bash
# Nur HTTP-Verkehr anzeigen
http
# Nur HTTPS/TLS-Verkehr anzeigen
tls
# Nur DNS-Verkehr anzeigen
dns
# Nur TCP-Verkehr anzeigen
tcp
# Nur UDP-Verkehr anzeigen
udp
# Nur ICMP-Verkehr anzeigen
icmp
```

### IP-Adressfilterung

Filtern Sie Pakete nach Quell- und Ziel-IP-Adressen.

```bash
# Verkehr von spezifischer IP
ip.src == 192.168.1.100
# Verkehr zu spezifischer IP
ip.dst == 192.168.1.200
# Verkehr zwischen zwei IPs
ip.addr == 192.168.1.100
# Verkehr aus Subnetz
ip.src_net == 192.168.1.0/24
# Spezifische IP ausschließen
not ip.addr == 192.168.1.1
```

### Port- & Protokollfilter

Filtern nach spezifischen Ports und Protokolldetails.

```bash
# Verkehr auf spezifischem Port
tcp.port == 80
# Quellport-Filter
tcp.srcport == 443
# Zielport-Filter
tcp.dstport == 22
# Port-Bereich
tcp.port >= 1000 and tcp.port <=
2000
# Mehrere Ports
tcp.port in {80 443 8080}
```

## Protokollspezifische Analyse

### HTTP-Analyse

Analysieren Sie HTTP-Anfragen und -Antworten.

```bash
# HTTP GET Anfragen
http.request.method == "GET"
# HTTP POST Anfragen
http.request.method == "POST"
# Spezifische HTTP-Statuscodes
http.response.code == 404
# HTTP-Anfragen an spezifischen Host
http.host == "example.com"
# HTTP-Anfragen, die Zeichenfolge enthalten
http contains "login"
```

### DNS-Analyse

Untersuchen Sie DNS-Abfragen und -Antworten.

```bash
# Nur DNS-Abfragen
dns.flags.response == 0
# Nur DNS-Antworten
dns.flags.response == 1
# DNS-Abfragen für spezifische Domain
dns.qry.name == "example.com"
# DNS A-Record Abfragen
dns.qry.type == 1
# DNS Fehler/Fehlschläge
dns.flags.rcode != 0
```

### TCP-Analyse

Analysieren Sie TCP-Verbindungsdetails.

```bash
# TCP SYN Pakete (Verbindungsversuche)
tcp.flags.syn == 1
# TCP RST Pakete (Verbindungsabbrüche)
tcp.flags.reset == 1
# TCP-Wiederholungen
tcp.analysis.retransmission
# TCP-Fenstergrößenprobleme
tcp.analysis.window_update
# TCP-Verbindungsaufbau
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### TLS/SSL-Analyse

Untersuchen Sie Details verschlüsselter Verbindungen.

```bash
# TLS-Handshake-Pakete
tls.handshake
# TLS-Zertifikatsinformationen
tls.handshake.certificate
# TLS-Warnungen und Fehler
tls.alert
# Spezifische TLS-Version
tls.handshake.version == 0x0303
# TLS Server Name Indication
tls.handshake.extensions_server_name
```

### Netzwerk-Fehlerbehebung

Identifizieren Sie gängige Netzwerkprobleme.

```bash
# ICMP Unreachable Nachrichten
icmp.type == 3
# ARP-Anfragen/Antworten
arp.opcode == 1 or arp.opcode == 2
# Broadcast-Verkehr
eth.dst == ff:ff:ff:ff:ff:ff
# Fragmentierte Pakete
ip.flags.mf == 1
# Große Pakete (potenzielle MTU-Probleme)
frame.len > 1500
```

### Zeitbasierte Filterung

Filtern Sie Pakete nach Zeitstempel und Timing.

```bash
# Pakete innerhalb eines Zeitbereichs
frame.time >= "2024-01-01 10:00:00"
# Pakete der letzten Stunde
frame.time_relative >= -3600
# Antwortzeit-Analyse
tcp.time_delta > 1.0
# Zeit zwischen Ankünften
frame.time_delta > 0.1
```

## Statistiken & Analysewerkzeuge

### Protokollhierarchie

Zeigt die Protokollverteilung in der Erfassung.

```bash
# Zugriff über: Statistics > Protocol Hierarchy
# Zeigt den Prozentsatz jedes Protokolls
# Identifiziert die häufigsten Protokolle
# Nützlich für Verkehrsüberblick
# Kommandozeilen-Äquivalent
tshark -r capture.pcap -q -z io,phs
```

### Konversationen

Analysiert die Kommunikation zwischen Endpunkten.

```bash
# Zugriff über: Statistics > Conversations
# Ethernet-Konversationen
# IPv4/IPv6-Konversationen
# TCP/UDP-Konversationen
# Zeigt übertragene Bytes, Paketanzahl
# Kommandozeilen-Äquivalent
tshark -r capture.pcap -q -z conv,tcp
```

### I/O-Graphen

Visualisiert Verkehrsmuster über die Zeit.

```bash
# Zugriff über: Statistics > I/O Graphs
# Verkehrsvolumen über die Zeit
# Pakete pro Sekunde
# Bytes pro Sekunde
# Filter anwenden für spezifischen Verkehr
# Nützlich zur Identifizierung von Verkehrsanstiegen
```

### Experteninformationen

Identifiziert potenzielle Netzwerkprobleme.

```bash
# Zugriff über: Analyze > Expert Info
# Warnungen zu Netzwerkproblemen
# Fehler bei der Paketübertragung
# Leistungsprobleme
# Sicherheitsbedenken
# Nach Schweregrad der Experteninformationen filtern
tcp.analysis.flags
```

### Flussdiagramme (Flow Graphs)

Visualisiert den Paketfluss zwischen Endpunkten.

```bash
# Zugriff über: Statistics > Flow Graph
# Zeigt Paketsequenz
# Zeitbasierte Visualisierung
# Nützlich zur Fehlerbehebung
# Identifiziert Kommunikationsmuster
```

### Antwortzeit-Analyse

Misst Anwendungsantwortzeiten.

```bash
# HTTP-Antwortzeiten
# Statistics > HTTP > Requests
# DNS-Antwortzeiten
# Statistics > DNS
# TCP-Dienst-Antwortzeit
# Statistics > TCP Stream Graphs > Time Sequence
```

## Dateioperationen & Export

### Erfassungen speichern & laden

Verwalten Sie Erfassungsdateien in verschiedenen Formaten.

```bash
# Erfassungsdatei speichern
# File > Save As > capture.pcap
# Erfassungsdatei laden
# File > Open > existing.pcap
# Mehrere Erfassungsdateien zusammenführen
# File > Merge > Dateien auswählen
# Nur gefilterte Pakete speichern
# File > Export Specified Packets
```

### Exportoptionen

Exportieren Sie spezifische Daten oder Paketsubsets.

```bash
# Ausgewählte Pakete exportieren
# File > Export Specified Packets
# Paket-Dissektionen exportieren
# File > Export Packet Dissections
# Objekte aus HTTP exportieren
# File > Export Objects > HTTP
# SSL/TLS-Schlüssel exportieren
# Edit > Preferences > Protocols > TLS
```

### Kommandozeilen-Erfassung

Verwenden Sie tshark für automatisierte Erfassung und Analyse.

```bash
# Erfassung in Datei
tshark -i eth0 -w capture.pcap
# Erfassung mit Filter
tshark -i eth0 -f "port 80" -w http.pcap
# Pakete lesen und anzeigen
tshark -r capture.pcap
# Anzeigefilter auf Datei anwenden
tshark -r capture.pcap -Y "tcp.port == 80"
```

### Stapelverarbeitung

Verarbeiten Sie automatisch mehrere Erfassungsdateien.

```bash
# Mehrere Dateien zusammenführen
mergecap -w merged.pcap file1.pcap file2.pcap
# Große Erfassungsdateien aufteilen
editcap -c 1000 large.pcap split.pcap
# Zeitbereich extrahieren
editcap -A "2024-01-01 10:00:00" \
        -B "2024-01-01 11:00:00" \
        input.pcap output.pcap
```

## Leistung & Optimierung

### Speichermanagement

Effizienter Umgang mit großen Erfassungsdateien.

```bash
# Ringpuffer für kontinuierliche Erfassung verwenden
-b filesize:100 -b files:10
# Größe der Paketerfassung begrenzen
-s 96  # Nur die ersten 96 Bytes erfassen
# Speicherplatz durch Erfassungsfilter reduzieren
host 192.168.1.100 and port 80
# Protokolldekodierung zur Beschleunigung deaktivieren
-d tcp.port==80,http
```

### Anzeigeoptimierung

Verbessern Sie die GUI-Leistung bei großen Datensätzen.

```bash
# Einstellungen zur Anpassung:
# Edit > Preferences > Appearance
# Farbschema-Auswahl
# Schriftgröße und -typ
# Optionen für Spaltenanzeige
# Einstellungen für das Zeitformat
# View > Time Display Format
# Seit Erfassungsbeginn vergangene Sekunden
# Tageszeit
# UTC-Zeit
```

### Effizienter Analyse-Workflow

Best Practices für die Analyse von Netzwerkverkehr.

```bash
# 1. Mit Erfassungsfiltern beginnen
# Nur relevanten Verkehr erfassen
# 2. Anzeigefilter schrittweise verwenden
# Breit beginnen, dann eingrenzen
# 3. Zuerst Statistiken verwenden
# Überblick gewinnen vor detaillierter Analyse
# 4. Auf spezifische Flows konzentrieren
# Rechtsklick auf Paket > Follow > TCP Stream
```

### Automatisierung & Skripterstellung

Automatisieren Sie gängige Analyseaufgaben.

```bash
# Benutzerdefinierte Schaltflächen für Anzeigefilter erstellen
# View > Display Filter Expression
# Profile für verschiedene Szenarien verwenden
# Edit > Configuration Profiles
# Mit tshark skripten
#!/bin/bash
tshark -r $1 -q -z endpoints,tcp | \
grep -v "Filter:" | head -20
```

## Installation & Einrichtung

### Windows-Installation

Download und Installation von der offiziellen Website.

```bash
# Von wireshark.org herunterladen
# Installer als Administrator ausführen
# WinPcap/Npcap einschließen
während der Installation
# Kommandozeilen-Installation
(chocolatey)
choco install wireshark
# Installation überprüfen
wireshark --version
```

### Linux-Installation

Installation über den Paketmanager oder aus dem Quellcode.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install wireshark
# Red Hat/CentOS/Fedora
sudo yum install wireshark
# oder
sudo dnf install wireshark
# Benutzer zur wireshark-Gruppe hinzufügen
sudo usermod -a -G wireshark
$USER
```

### macOS-Installation

Installation mit Homebrew oder dem offiziellen Installer.

```bash
# Mit Homebrew
brew install --cask wireshark
# Von wireshark.org herunterladen
# .dmg-Paket installieren
# Kommandozeilen-Tools
brew install wireshark
```

## Konfiguration & Voreinstellungen

### Schnittstellenvoreinstellungen

Konfigurieren Sie Erfassungsschnittstellen und Optionen.

```bash
# Edit > Preferences > Capture
# Standard-Erfassungsschnittstelle
# Einstellungen für Promiscuous Mode
# Konfiguration der Puffergröße
# Auto-Scroll bei Live-Erfassung
# Schnittstellenspezifische Einstellungen
# Capture > Options > Interface Details
```

### Protokolleinstellungen

Konfigurieren Sie Protokolldekodierer und Dekodierung.

```bash
# Edit > Preferences > Protocols
# Protokolldekodierer aktivieren/deaktivieren
# Portzuweisungen konfigurieren
# Entschlüsselungsschlüssel einstellen (TLS, WEP, etc.)
# TCP-Wiederzusammensetzungsoptionen
# Decode As-Funktionalität
# Analyze > Decode As
```

### Anzeigevoreinstellungen

Passen Sie die Benutzeroberfläche und Anzeigeoptionen an.

```bash
# Edit > Preferences > Appearance
# Auswahl des Farbschemas
# Schriftgröße und -typ
# Optionen für die Spaltenanzeige
# Einstellungen für das Zeitformat
# View > Time Display Format
# Seit Erfassungsbeginn vergangene Sekunden
# Tageszeit
# UTC-Zeit
```

### Sicherheitseinstellungen

Konfigurieren Sie sicherheitsrelevante Optionen und Entschlüsselung.

```bash
# TLS-Entschlüsselung einrichten
# Edit > Preferences > Protocols > TLS
# Liste der RSA-Schlüssel
# Pre-Shared Keys
# Speicherort der Schlüsselprotokolldatei
# Potenziell gefährliche Funktionen deaktivieren
# Ausführung von Lua-Skripten
# Externe Resolver
```

## Erweiterte Filtertechniken

### Logische Operatoren

Kombinieren Sie mehrere Filterbedingungen.

```bash
# AND-Operator
tcp.port == 80 and ip.src == 192.168.1.100
# OR-Operator
tcp.port == 80 or tcp.port == 443
# NOT-Operator
not icmp
# Klammern zur Gruppierung
(tcp.port == 80 or tcp.port == 443) and ip.src ==
192.168.1.0/24
```

### Zeichenkettenabgleich

Suchen Sie nach spezifischem Inhalt in Paketen.

```bash
# Enthält Zeichenfolge (groß-/kleingeschrieben)
tcp contains "password"
# Enthält Zeichenfolge (unabhängig von Groß-/Kleinschreibung)
tcp matches "(?i)login"
# Reguläre Ausdrücke
http.request.uri matches "\.php$"
# Byte-Sequenzen
eth.src[0:3] == 00:11:22
```

### Feldvergleiche

Vergleichen Sie Paketfelder mit Werten und Bereichen.

```bash
# Gleichheit
tcp.srcport == 80
# Größer als/kleiner als
frame.len > 1000
# Bereichsprüfungen
tcp.port >= 1024 and tcp.port <= 65535
# Mengenmitgliedschaft
tcp.port in {80 443 8080 8443}
# Feldexistenz
tcp.options
```

### Erweiterte Paket-Analyse

Identifizieren Sie spezifische Paketeigenschaften und Anomalien.

```bash
# Fehlformatierte Pakete
_ws.malformed
# Duplizierte Pakete
frame.number == tcp.analysis.duplicate_ack_num
# Außer Reihenfolge Pakete
tcp.analysis.out_of_order
# TCP-Fensterskalierungsprobleme
tcp.analysis.window_full
```

## Häufige Anwendungsfälle

### Netzwerk-Fehlerbehebung

Identifizieren und beheben Sie Netzwerkverbindungsprobleme.

```bash
# Verbindungsabbrüche finden
tcp.analysis.retransmission and tcp.analysis.rto
# Langsame Verbindungen finden
tcp.time_delta > 1.0
# Netzwerküberlastung finden
tcp.analysis.window_full
# DNS-Auflösungsprobleme
dns.flags.rcode != 0
# MTU-Discovery-Probleme
icmp.type == 3 and icmp.code == 4
```

### Sicherheitsanalyse

Erkennen potenzieller Sicherheitsbedrohungen und verdächtiger Aktivitäten.

```bash
# Port-Scan-Erkennung
tcp.flags.syn == 1 and tcp.flags.ack == 0
# Große Anzahl von Verbindungen von einer einzelnen IP
# Verwenden Sie Statistics > Conversations
# Verdächtige DNS-Abfragen
dns.qry.name contains "dga" or dns.qry.name matches
"^[a-z]{8,}\.com$"
# HTTP POST an verdächtige URLs
http.request.method == "POST" and http.request.uri
contains "/upload"
# Ungewöhnliche Verkehrsmuster
# Überprüfen Sie I/O Graphs auf Spitzen
```

### Anwendungsleistung

Überwachen und analysieren Sie Anwendungsantwortzeiten.

```bash
# Webanwendungsanalyse
http.time > 2.0
# Datenbankverbindungsüberwachung
tcp.port == 3306 and tcp.analysis.initial_rtt > 0.1
# Dateiübertragungsleistung
tcp.stream eq X and tcp.analysis.bytes_in_flight
# VoIP-Qualitätsanalyse
rtp.jitter > 30 or rtp.marker == 1
```

### Protokolluntersuchung

Tauchen Sie tief in spezifische Protokolle und deren Verhalten ein.

```bash
# E-Mail-Verkehrsanalyse
tcp.port == 25 or tcp.port == 587 or tcp.port == 993
# FTP-Dateiübertragungen
ftp-data or ftp.request.command == "RETR"
# SMB/CIFS-Dateifreigabe
smb2 or smb
# DHCP-Lease-Analyse
bootp.option.dhcp == 1 or bootp.option.dhcp == 2
```

## Relevante Links

- <router-link to="/nmap">Nmap Spickzettel</router-link>
- <router-link to="/cybersecurity">Cybersicherheit Spickzettel</router-link>
- <router-link to="/kali">Kali Linux Spickzettel</router-link>
- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/network">Netzwerk Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>

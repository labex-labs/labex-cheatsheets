---
title: 'CompTIA Spickzettel'
description: 'Lernen Sie CompTIA mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/comptia-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
CompTIA Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/comptia">Lernen Sie CompTIA mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie CompTIA-Zertifizierungen durch praktische Labs und reale Szenarien. LabEx bietet umfassende CompTIA-Kurse, die A+, Network+, Security+ und spezialisierte Zertifizierungen abdecken. Meistern Sie IT-Grundlagen, Netzwerke, Sicherheit und fördern Sie Ihre IT-Karriere mit branchenweit anerkannten Qualifikationen.
</base-disclaimer-content>
</base-disclaimer>

## CompTIA Zertifizierungsübersicht

### Kernzertifizierungen

Grundlagenzertifizierungen für den Erfolg in der IT-Karriere.

```text
# CompTIA A+ (220-1101, 220-1102)
- Hardware und mobile Geräte
- Betriebssysteme und Software
- Sicherheits- und Netzwerk-Grundlagen
- Betriebsabläufe

# CompTIA Network+ (N10-008)
- Netzwerkgrundlagen
- Netzwerkimplementierungen
- Netzwerkbetrieb
- Netzwerksicherheit
- Netzwerk-Fehlerbehebung

# CompTIA Security+ (SY0-601)
- Angriffe, Bedrohungen und Schwachstellen
- Architektur und Design
- Implementierung
- Betrieb und Reaktion auf Vorfälle
- Governance, Risiko und Compliance
```

### Spezialisierte Zertifizierungen

Fortgeschrittene und spezialisierte IT-Qualifikationen.

```text
# CompTIA PenTest+ (PT0-002)
- Planung und Umfang von Penetrationstests
- Informationsbeschaffung und Schwachstellenidentifizierung
- Angriffe und Exploits
- Berichterstattung und Kommunikation

# CompTIA CySA+ (CS0-002)
- Bedrohungs- und Schwachstellenmanagement
- Software- und Systemsicherheit
- Sicherheitsbetrieb und -überwachung
- Reaktion auf Vorfälle
- Compliance und Bewertung

# CompTIA Cloud+ (CV0-003)
- Cloud-Architektur und Design
- Sicherheit
- Bereitstellung
- Betrieb und Support
- Fehlerbehebung

# CompTIA Server+ (SK0-005)
- Installation und Verwaltung von Server-Hardware
- Server-Administration
- Sicherheit und Disaster Recovery
- Fehlerbehebung

# CompTIA Project+ (PK0-005)
- Projektlebenszyklus
- Projektwerkzeuge und Dokumentation
- Grundlagen des Projektkosten- und Zeitmanagements
- Projektdurchführung und -abschluss

# CompTIA Linux+ (XK0-005)
- Systemverwaltung
- Sicherheit
- Scripting und Container
- Fehlerbehebung
```

## CompTIA A+ Grundlagen

### Hardware-Komponenten

Wesentliches Wissen über Computer-Hardware und Fehlerbehebung.

```text
# CPU-Typen und -Funktionen
- Intel vs AMD Prozessoren
- Sockeltypen (LGA, PGA, BGA)
- Kernanzahl und Threading
- Cache-Level (L1, L2, L3)

# Speicher (RAM)
- DDR4, DDR5 Spezifikationen
- ECC vs nicht-ECC Speicher
- SODIMM vs DIMM Formfaktoren
- Speicherkanäle und Geschwindigkeiten

# Speichertechnologien
- HDD vs SSD vs NVMe
- SATA, PCIe Schnittstellen
- RAID-Konfigurationen (0,1,5,10)
- M.2 Formfaktoren
```

### Mobile Geräte

Smartphones, Tablets und Verwaltung mobiler Geräte.

```text
# Mobile Gerätetypen
- iOS vs Android Architektur
- Laptop vs Tablet Formfaktoren
- Wearable Devices
- E-Reader und Smart Devices

# Mobile Konnektivität
- Wi-Fi Standards (802.11a/b/g/n/ac/ax)
- Zelluläre Technologien (3G, 4G, 5G)
- Bluetooth Versionen und Profile
- NFC und mobile Zahlungen

# Mobile Sicherheit
- Bildschirmsperren und Biometrie
- Mobile Device Management (MDM)
- App-Sicherheit und Berechtigungen
- Remote-Löschfunktionen
```

### Betriebssysteme

Verwaltung von Windows, macOS, Linux und mobilen Betriebssystemen.

```text
# Windows-Administration
- Windows 10/11 Editionen
- User Account Control (UAC)
- Gruppenrichtlinien und Registrierung
- Windows Update Verwaltung

# macOS Verwaltung
- Systemeinstellungen
- Schlüsselbundverwaltung (Keychain Access)
- Time Machine Backups
- App Store und Gatekeeper

# Linux Grundlagen
- Dateisystemhierarchie
- Befehlszeilenoperationen
- Paketverwaltung
- Benutzer- und Gruppenberechtigungen
```

## Network+ Grundlagen

### OSI-Modell & TCP/IP

Verständnis der Netzwerkschichten und Protokollkenntnisse.

```text
# OSI 7-Schichten-Modell
Schicht 7: Anwendung (HTTP, HTTPS, FTP)
Schicht 6: Darstellung (SSL, TLS)
Schicht 5: Sitzung (NetBIOS, RPC)
Schicht 4: Transport (TCP, UDP)
Schicht 3: Netzwerk (IP, ICMP, OSPF)
Schicht 2: Sicherung (Ethernet, PPP)
Schicht 1: Bitübertragung (Kabel, Hubs)

# TCP/IP Suite
- IPv4 vs IPv6 Adressierung
- Subnetting und CIDR Notation
- DHCP und DNS Dienste
- ARP und ICMP Protokolle
```

### Netzwerkgeräte

Router, Switches und Netzwerk-Equipment.

```text
# Schicht-2-Geräte
- Switches und VLANs
- Spanning Tree Protocol (STP)
- Port-Sicherheit und MAC-Filterung

# Schicht-3-Geräte
- Router und Routing-Tabellen
- Statisches vs dynamisches Routing
- OSPF, EIGRP, BGP Protokolle
- NAT und PAT Übersetzung
```

### Drahtlose Netzwerke

WLAN-Standards, Sicherheit und Fehlerbehebung.

```text
# WLAN-Standards
802.11a: 5GHz, 54Mbps
802.11b: 2.4GHz, 11Mbps
802.11g: 2.4GHz, 54Mbps
802.11n: 2.4/5GHz, 600Mbps
802.11ac: 5GHz, 6.9Gbps
802.11ax (Wi-Fi 6): 9.6Gbps

# WLAN-Sicherheit
- WEP (veraltet)
- WPA/WPA2-PSK
- WPA2/WPA3-Enterprise
- EAP-Authentifizierungsmethoden
```

### Netzwerk-Fehlerbehebung

Gängige Werkzeuge und Diagnoseverfahren.

```bash
# Befehlszeilen-Tools
ping                    # Konnektivität testen
tracert/traceroute      # Pfadanalyse
nslookup/dig            # DNS-Abfragen
netstat                 # Netzwerkverbindungen
ipconfig/ifconfig       # IP-Konfiguration

# Netzwerktests
- Kabeltester und Tongeber
- Protokollanalysatoren (Wireshark)
- Geschwindigkeits- und Durchsatztests
- WLAN-Analysatoren
```

## Security+ Grundkonzepte

### Sicherheitsgrundlagen

CIA-Triade und grundlegende Sicherheitsprinzipien.

```text
# CIA Triade
Vertraulichkeit: Datenschutz und Verschlüsselung
Integrität: Datenrichtigkeit und Authentizität
Verfügbarkeit: System-Uptime und Zugänglichkeit

# Authentifizierungsfaktoren
Etwas, das Sie wissen: Passwörter, PINs
Etwas, das Sie besitzen: Tokens, Smartcards
Etwas, das Sie sind: Biometrie
Etwas, das Sie tun: Verhaltensmuster
Etwas, wo Sie sind: Standortbasiert
```

### Bedrohungslandschaft

Häufige Angriffe und Bedrohungsakteure.

```text
# Angriffstypen
- Phishing und Social Engineering
- Malware (Viren, Trojaner, Ransomware)
- DDoS- und DoS-Angriffe
- Man-in-the-Middle-Angriffe
- SQL Injection und XSS
- Zero-Day-Exploits

# Bedrohungsakteure
- Script Kiddies
- Hacktivisten
- Organisierte Kriminalität
- Staatlich geförderte Akteure
- Insider-Bedrohungen
```

### Kryptographie

Verschlüsselungsmethoden und Schlüsselverwaltung.

```text
# Verschlüsselungstypen
Symmetrisch: AES, 3DES (gleicher Schlüssel)
Asymmetrisch: RSA, ECC (Schlüsselpaare)
Hashing: SHA-256, MD5 (Einweg)
Digitale Signaturen: Nichtabstreitbarkeit

# Schlüsselverwaltung
- Schlüsselerzeugung und -verteilung
- Schlüsselhinterlegung und -wiederherstellung
- Zertifizierungsstellen (CA)
- Public Key Infrastructure (PKI)
```

### Zugriffskontrolle

Identitätsmanagement und Autorisierungsmodelle.

```text
# Zugriffskontrollmodelle
DAC: Discretionary Access Control (Diskretionäre Zugriffskontrolle)
MAC: Mandatory Access Control (Obligatorische Zugriffskontrolle)
RBAC: Role-Based Access Control (Rollenbasierte Zugriffskontrolle)
ABAC: Attribute-Based Access Control (Attributbasierte Zugriffskontrolle)

# Identitätsmanagement
- Single Sign-On (SSO)
- Multi-Factor Authentication (MFA)
- LDAP und Active Directory
- Föderation und SAML
```

## Lernstrategien & Tipps

### Studienplanung

Erstellen Sie einen strukturierten Ansatz zur Zertifizierungsvorbereitung.

```text
# Studienplan
Woche 1-2: Prüfungsziele überprüfen
Woche 3-6: Kernmaterial studieren
Woche 7-8: Praktische Übungen
Woche 9-10: Übungsprüfungen
Woche 11-12: Endgültige Wiederholung und Prüfung

# Lernmaterialien
- Offizielle CompTIA Studienführer
- Video-Schulungskurse
- Übungsprüfungen und Simulatoren
- Praktische Laborübungen
- Lerngruppen und Foren
```

### Praktische Übungen

Praktische Erfahrung zur Festigung theoretischen Wissens.

```text
# Laborumgebungen
- VMware oder VirtualBox VMs
- Heimlabor-Setup
- Cloud-basierte Labs (AWS, Azure)
- CompTIA Simulationssoftware

# Praktische Fähigkeiten
- Aufbau und Fehlerbehebung von PCs
- Netzwerkkonfiguration
- Implementierung von Sicherheitstools
- Beherrschung der Befehlszeile
```

### Prüfungsstrategien

Testtechniken für CompTIA-Prüfungen.

```text
# Fragetypen
Multiple Choice: Alle Optionen lesen
Performance-basiert: Simulationen üben
Drag-and-Drop: Beziehungen verstehen
Hot Spot: Benutzeroberflächen-Layouts kennen

# Zeitmanagement
- Zeit pro Frage zuweisen
- Schwierige Fragen zur Überprüfung markieren
- Nicht zu lange bei einzelnen Fragen verweilen
- Markierte Fragen am Ende überprüfen
```

### Häufige Prüfungsthemen

Häufig vorkommende Themen in CompTIA-Prüfungen.

```text
# Häufig geprüfte Bereiche
- Methoden zur Fehlerbehebung
- Best Practices für Sicherheit
- Netzwerkprotokolle und Ports
- Betriebssystemfunktionen
- Hardware-Spezifikationen
- Konzepte des Risikomanagements
```

## Technische Akronyme & Terminologie

### Netzwerk-Akronyme

Gängige Netzwerkbegriffe und Abkürzungen.

```text
# Protokolle & Standards
HTTP/HTTPS: Webprotokolle
FTP/SFTP: Dateiübertragung
SMTP/POP3/IMAP: E-Mail
DNS: Domain Name System
DHCP: Dynamic Host Configuration
TCP/UDP: Transportprotokolle
IP: Internet Protocol
ICMP: Internet Control Message

# Drahtlos & Sicherheit
WPA/WPA2: Wi-Fi Protected Access
SSID: Service Set Identifier
MAC: Media Access Control
VPN: Virtual Private Network
VLAN: Virtual Local Area Network
QoS: Quality of Service
```

### Hardware & Software

Computer-Hardware- und Software-Terminologie.

```text
# Speicher & Arbeitsspeicher
HDD: Hard Disk Drive (Festplattenlaufwerk)
SSD: Solid State Drive (Solid-State-Laufwerk)
RAM: Random Access Memory (Flüchtiger Speicher)
ROM: Read-Only Memory (Nur-Lese-Speicher)
BIOS/UEFI: System-Firmware
RAID: Redundant Array of Independent Disks

# Schnittstellen & Ports
USB: Universal Serial Bus
SATA: Serial ATA
PCIe: Peripheral Component Interconnect Express
HDMI: High-Definition Multimedia Interface
VGA: Video Graphics Array
RJ45: Ethernet-Anschluss
```

### Sicherheitsterminologie

Begriffe und Konzepte der Informationssicherheit.

```text
# Sicherheits-Frameworks
CIA: Vertraulichkeit, Integrität, Verfügbarkeit
AAA: Authentifizierung, Autorisierung, Abrechnung
PKI: Public Key Infrastructure
IAM: Identity and Access Management
SIEM: Security Information and Event Management
SOC: Security Operations Center

# Compliance & Risiko
GDPR: General Data Protection Regulation (DSGVO)
HIPAA: Health Insurance Portability Act
PCI DSS: Payment Card Industry Data Security
SOX: Sarbanes-Oxley Act
NIST: National Institute of Standards
ISO 27001: Sicherheitsmanagementstandard
```

### Cloud & Virtualisierung

Terminologie der modernen IT-Infrastruktur.

```text
# Cloud-Dienste
IaaS: Infrastructure as a Service (Infrastruktur als Dienstleistung)
PaaS: Platform as a Service (Plattform als Dienstleistung)
SaaS: Software as a Service (Software als Dienstleistung)
VM: Virtual Machine (Virtuelle Maschine)
API: Application Programming Interface
CDN: Content Delivery Network
```

## Zertifizierungs-Karrierepfade

### Einstiegsniveau

Grundlagenzertifizierung für IT-Support-Rollen, die Hardware, Software und grundlegende Fehlerbehebungsfähigkeiten abdeckt.

```text
1. Einstiegsniveau
CompTIA A+
Grundlagenzertifizierung für IT-Support-Rollen, die
Hardware, Software und grundlegende Fehlerbehebungsfähigkeiten
abdeckt.
```

### Infrastruktur

Aufbau von Fachwissen in Netzwerken und Server-Administration für Infrastrukturrollen.

```text
2. Infrastruktur
Network+ & Server+
Aufbau von Fachwissen in Netzwerken und Server-Administration
für Infrastrukturrollen.
```

### Sicherheitsfokus

Entwicklung von Cybersicherheitskenntnissen für Positionen als Sicherheitsanalyst und -administrator.

```text
3. Sicherheitsfokus
Security+ & CySA+
Entwicklung von Cybersicherheitskenntnissen für Positionen als
Sicherheitsanalyst und -administrator.
```

### Spezialisierung

Fortgeschrittene Spezialisierungen in Penetrationstests und Cloud-Technologien.

```text
4. Spezialisierung
PenTest+ & Cloud+
Fortgeschrittene Spezialisierungen in Penetrationstests und
Cloud-Technologien.
```

## Häufige Portnummern

### Bekannte Ports (0-1023)

Standard-Ports für gängige Netzwerkdienste.

```text
Port 20/21: FTP (File Transfer Protocol)
Port 22: SSH (Secure Shell)
Port 23: Telnet
Port 25: SMTP (Simple Mail Transfer Protocol)
Port 53: DNS (Domain Name System)
Port 67/68: DHCP (Dynamic Host Configuration)
Port 69: TFTP (Trivial File Transfer Protocol)
Port 80: HTTP (Hypertext Transfer Protocol)
Port 110: POP3 (Post Office Protocol v3)
Port 143: IMAP (Internet Message Access Protocol)
Port 161/162: SNMP (Simple Network Management)
Port 443: HTTPS (HTTP Secure)
Port 993: IMAPS (IMAP Secure)
Port 995: POP3S (POP3 Secure)
```

### Registrierte Ports (1024-49151)

Gängige Anwendungs- und Datenbank-Ports.

```text
# Datenbank & Anwendungen
Port 1433: Microsoft SQL Server
Port 1521: Oracle Database
Port 3306: MySQL Database
Port 3389: RDP (Remote Desktop Protocol)
Port 5432: PostgreSQL Database

# Netzwerkdienste
Port 1812/1813: RADIUS Authentifizierung
Port 1701: L2TP (Layer 2 Tunneling Protocol)
Port 1723: PPTP (Point-to-Point Tunneling)
Port 5060/5061: SIP (Session Initiation Protocol)

# Sicherheitsdienste
Port 636: LDAPS (LDAP Secure)
Port 989/990: FTPS (FTP Secure)
```

## Methoden zur Fehlerbehebung

### CompTIA Fehlerbehebungsschritte

Standardmethodik zur technischen Problemlösung.

```text
# 6-Schritte-Prozess
1. Problem identifizieren
   - Informationen sammeln
   - Benutzer nach Symptomen befragen
   - Änderungen am System identifizieren
   - Problem bei Möglichkeit reproduzieren

2. Theorie der wahrscheinlichen Ursache aufstellen
   - Das Offensichtliche hinterfragen
   - Mehrere Ansätze in Betracht ziehen
   - Mit einfachen Lösungen beginnen

3. Theorie testen, um Ursache festzustellen
   - Wenn Theorie bestätigt, fortfahren
   - Wenn nicht, neue Theorie aufstellen
   - Bei Bedarf eskalieren
```

### Implementierung & Dokumentation

Abschließende Schritte im Fehlerbehebungsprozess.

```text
# Verbleibende Schritte
4. Maßnahmeplan festlegen
   - Schritte zur Behebung bestimmen
   - Mögliche Auswirkungen identifizieren
   - Lösung implementieren oder eskalieren

5. Lösung implementieren oder eskalieren
   - Geeignete Korrektur anwenden
   - Lösung gründlich testen
   - Volle Funktionalität überprüfen

6. Ergebnisse, Maßnahmen und Ergebnisse dokumentieren
   - Ticketsysteme aktualisieren
   - Erkenntnisse teilen
   - Zukünftiges Auftreten verhindern
```

## Tipps für Performance-Based Questions

### A+ Performance-Fragen

Häufige Simulationsszenarien und Lösungen.

```text
# Hardware-Fehlerbehebung
- Fehlerhafte Komponenten in PC-Builds identifizieren
- BIOS/UEFI-Einstellungen konfigurieren
- RAM installieren und konfigurieren
- Speichergeräte korrekt anschließen
- Probleme mit dem Netzteil beheben

# Betriebssystem-Aufgaben
- Windows-Installation und -Konfiguration
- Benutzerkonten- und Berechtigungsverwaltung
- Netzwerkeinstellungen konfigurieren
- Gerätetreiber installieren
- Systemdateien und Registrierung reparieren
```

### Network+ Simulationen

Netzwerkkonfigurations- und Fehlerbehebungsszenarien.

```text
# Netzwerkkonfiguration
- VLAN-Einrichtung und Portzuweisungen
- Router ACL-Konfiguration
- Switch-Port-Sicherheitseinstellungen
- WLAN-Einrichtung
- IP-Adressierung und Subnetting

# Fehlerbehebungsaufgaben
- Kabeltests und -austausch
- Diagnose der Netzwerkkonnektivität
- DNS- und DHCP-Fehlerbehebung
- Leistungsoptimierung
- Sicherheitsimplementierung
```

### Security+ Szenarien

Sicherheitsimplementierung und Reaktion auf Vorfälle.

```text
# Sicherheitskonfiguration
- Firewall-Regelerstellung
- Einrichtung der Benutzerzugriffskontrolle
- Zertifikatsverwaltung
- Implementierung von Verschlüsselung
- Netzwerksegmentierung

# Reaktion auf Vorfälle
- Protokollanalyse und -interpretation
- Bedrohungserkennung
- Schwachstellenbewertung
- Implementierung von Sicherheitskontrollen
- Risikominderungsstrategien
```

### Allgemeine Simulations-Tipps

Best Practices für Performance-Based Questions.

```text
# Erfolgsstrategien
- Anweisungen sorgfältig und vollständig lesen
- Screenshots machen, bevor Änderungen vorgenommen werden
- Konfigurationen nach der Implementierung testen
- Ausschlussverfahren anwenden
- Zeitmanagement effektiv gestalten
- Mit Simulationssoftware üben
- Grundlegende Konzepte verstehen, nicht nur Schritte
```

## Prüfungsanmeldung & Logistik

### Prüfungsanmeldungsprozess

Schritte zur Terminierung und Vorbereitung für CompTIA-Prüfungen.

```text
# Anmeldeschritte
1. Pearson VUE Konto erstellen
2. Zertifizierungsprüfung auswählen
3. Testzentrum oder Online-Option wählen
4. Prüfungsdatum und -zeit planen
5. Prüfungsgebühr bezahlen
6. Bestätigungs-E-Mail erhalten

# Prüfungskosten (USD, ungefähre Angaben)
CompTIA A+: $239 pro Prüfung (2 Prüfungen)
CompTIA Network+: $358
CompTIA Security+: $370
CompTIA Cloud+: $358
CompTIA PenTest+: $370
CompTIA CySA+: $392
```

### Vorbereitung auf den Prüfungstag

Was am Prüfungstag erwartet wird und was mitzubringen ist.

```text
# Erforderliche Gegenstände
- Gültiger amtlicher Lichtbildausweis
- Bestätigungs-E-Mail/Nummer
- 30 Minuten früher eintreffen
- Keine persönlichen Gegenstände im Prüfungsraum

# Prüfungsformat
- Multiple-Choice-Fragen
- Performance-Based Questions (Simulationen)
- Drag-and-Drop-Fragen
- Hot-Spot-Fragen
- Zeitlimits variieren je nach Prüfung (90-165 Minuten)
```

## Zertifizierungs-Wartung

### Gültigkeit der Zertifizierung

Weiterbildung und Erneuerung der Zertifizierung.

```text
# Gültigkeit der Zertifizierung
Die meisten CompTIA-Zertifizierungen: 3 Jahre
CompTIA A+: Permanent (kein Ablaufdatum)

# Continuing Education Units (CEUs)
Security+: 50 CEUs über 3 Jahre
Network+: 30 CEUs über 3 Jahre
Cloud+: 30 CEUs über 3 Jahre

# CEU-Aktivitäten
- Schulungskurse und Webinare
- Branchenkonferenzen
- Veröffentlichung von Artikeln
- Freiwilligenarbeit
- Höherstufige Zertifizierungen
```

### Karrierevorteile

Wert und Anerkennung von CompTIA-Zertifizierungen.

```text
# Branchenanerkennung
- DOD 8570 genehmigt (Security+)
- Anforderungen von Regierungskontraktoren
- HR-Filterung für Bewerbungen
- Gehaltssteigerungen
- Möglichkeiten zur Karriereentwicklung
- Technische Glaubwürdigkeit
- Grundlage für fortgeschrittene Zertifizierungen
```

## Relevante Links

- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/cybersecurity">Cybersicherheit Spickzettel</router-link>
- <router-link to="/network">Netzwerk Spickzettel</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>
- <router-link to="/ansible">Ansible Spickzettel</router-link>

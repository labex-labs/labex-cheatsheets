---
title: 'Nmap Spickzettel'
description: 'Lernen Sie Nmap mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/nmap-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Nmap Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/nmap">Lernen Sie Nmap mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Nmap Network Scanning durch praktische Labs und reale Szenarien. LabEx bietet umfassende Nmap-Kurse, die wesentliche Netzwerkentdeckung, Port-Scanning, Service-Erkennung, OS-Fingerprinting und Schwachstellenbewertung abdecken. Meistern Sie Techniken zur Netzwerkerkundung und Sicherheitsprüfung.
</base-disclaimer-content>
</base-disclaimer>

## Installation & Einrichtung

### Linux Installation

Installieren Sie Nmap mit dem Paketmanager Ihrer Distribution.

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap
# RHEL/Fedora/CentOS
sudo dnf install nmap
# Installation überprüfen
nmap --version
```

### macOS Installation

Installation über den Homebrew Paketmanager.

```bash
# Installation via Homebrew
brew install nmap
# Direkter Download von nmap.org
# .dmg herunterladen von https://nmap.org/download.html
```

### Windows Installation

Herunterladen und installieren von der offiziellen Webseite.

```bash
# Installer herunterladen von
https://nmap.org/download.html
# Den .exe Installer mit Administratorrechten ausführen
# Beinhaltet Zenmap GUI und Kommandozeilenversion
```

### Grundlegende Überprüfung

Testen Sie Ihre Installation und rufen Sie die Hilfe auf.

```bash
# Versionsinformationen anzeigen
nmap --version
# Hilfemenü anzeigen
nmap -h
# Erweiterte Hilfe und Optionen
man nmap
```

## Grundlegende Scan-Techniken

### Einfacher Host-Scan: `nmap [ziel]`

Basis-Scan eines einzelnen Hosts oder einer IP-Adresse.

```bash
# Einzelne IP scannen
nmap 192.168.1.1
# Hostnamen scannen
nmap example.com
# Mehrere IPs scannen
nmap 192.168.1.1 192.168.1.5
192.168.1.10
```

### Netzwerkbereichs-Scan

Nmap akzeptiert Hostnamen, IP-Adressen, Subnetze.

```bash
# IP-Bereich scannen
nmap 192.168.1.1-254
# Subnetz mit CIDR-Notation scannen
nmap 192.168.1.0/24
# Mehrere Netzwerke scannen
nmap 192.168.1.0/24 10.0.0.0/8
```

### Eingabe aus Datei

Ziele scannen, die in einer Datei aufgelistet sind.

```bash
# Ziele aus Datei lesen
nmap -iL targets.txt
# Spezifische Hosts ausschließen
nmap 192.168.1.0/24 --exclude
192.168.1.1
# Aus Datei ausschließen
nmap 192.168.1.0/24 --excludefile
exclude.txt
```

## Host-Erkennungstechniken

### Ping-Scan: `nmap -sn`

Die Host-Erkennung ist eine Schlüsselmethode, die viele Analysten und Penetrationstester mit Nmap verwenden. Ihr Zweck ist es, einen Überblick darüber zu gewinnen, welche Systeme online sind.

```bash
# Nur Ping-Scan (kein Port-Scan)
nmap -sn 192.168.1.0/24
# Host-Erkennung überspringen (alle Hosts als aktiv annehmen)
nmap -Pn 192.168.1.1
# ICMP Echo Ping
nmap -PE 192.168.1.0/24
```

### TCP Ping-Techniken

Verwenden Sie TCP-Pakete zur Host-Erkennung.

```bash
# TCP SYN Ping an Port 80
nmap -PS80 192.168.1.0/24
# TCP ACK Ping
nmap -PA80 192.168.1.0/24
# TCP SYN Ping an mehrere Ports
nmap -PS22,80,443 192.168.1.0/24
```

### UDP Ping: `nmap -PU`

Verwenden Sie UDP-Pakete zur Host-Erkennung.

```bash
# UDP Ping an gängige Ports
nmap -PU53,67,68,137 192.168.1.0/24
# UDP Ping an Standardports
nmap -PU 192.168.1.0/24
```

### ARP Ping: `nmap -PR`

Verwenden Sie ARP-Anfragen zur Erkennung im lokalen Netzwerk.

```bash
# ARP Ping (Standard für lokale Netzwerke)
nmap -PR 192.168.1.0/24
# ARP Ping deaktivieren
nmap --disable-arp-ping 192.168.1.0/24
```

## Port-Scan-Typen

### TCP SYN Scan: `nmap -sS`

Dieser Scan ist heimlicher, da Nmap ein RST-Paket sendet, was mehrere Anfragen verhindert und die Scan-Zeit verkürzt.

```bash
# Standard-Scan (erfordert root)
nmap -sS 192.168.1.1
# SYN-Scan spezifischer Ports
nmap -sS -p 80,443 192.168.1.1
# Schneller SYN-Scan
nmap -sS -T4 192.168.1.1
```

### TCP Connect Scan: `nmap -sT`

Nmap sendet ein TCP-Paket mit gesetztem SYN-Flag an einen Port. Dies teilt dem Benutzer mit, ob Ports offen, geschlossen oder unbekannt sind.

```bash
# TCP Connect Scan (kein Root erforderlich)
nmap -sT 192.168.1.1
# Connect Scan mit Timing
nmap -sT -T3 192.168.1.1
```

### UDP Scan: `nmap -sU`

Scannen von UDP-Ports auf Dienste.

```bash
# UDP Scan (langsam, erfordert root)
nmap -sU 192.168.1.1
# UDP Scan gängiger Ports
nmap -sU -p 53,67,68,161 192.168.1.1
# Kombinierter TCP/UDP Scan
nmap -sS -sU -p T:80,443,U:53,161 192.168.1.1
```

### Stealth Scans

Fortgeschrittene Scan-Techniken zur Umgehung von Erkennung.

```bash
# FIN Scan
nmap -sF 192.168.1.1
# NULL Scan
nmap -sN 192.168.1.1
# Xmas Scan
nmap -sX 192.168.1.1
```

## Port-Spezifikation

### Port-Bereiche: `nmap -p`

Zielen Sie auf spezifische Ports, Bereiche oder Kombinationen von TCP- und UDP-Ports für präzisere Scans.

```bash
# Einzelner Port
nmap -p 80 192.168.1.1
# Mehrere Ports
nmap -p 22,80,443 192.168.1.1
# Port-Bereich
nmap -p 1-1000 192.168.1.1
# Alle Ports
nmap -p- 192.168.1.1
```

### Protokollspezifische Ports

Geben Sie TCP- oder UDP-Ports explizit an.

```bash
# Nur TCP-Ports
nmap -p T:80,443 192.168.1.1
# Nur UDP-Ports
nmap -p U:53,161 192.168.1.1
# Gemischte TCP und UDP
nmap -p T:80,U:53 192.168.1.1
```

### Gängige Port-Sets

Scannen Sie häufig verwendete Ports schnell.

```bash
# Top 1000 Ports (Standard)
nmap 192.168.1.1
# Top 100 Ports
nmap --top-ports 100 192.168.1.1
# Schneller Scan (100 häufigste Ports)
nmap -F 192.168.1.1
# Nur offene Ports anzeigen
nmap --open 192.168.1.1
# Alle Port-Zustände anzeigen
nmap -v 192.168.1.1
```

## Service- & Versionserkennung

### Service-Erkennung: `nmap -sV`

Erkennen Sie, welche Dienste laufen, und versuchen Sie, deren Softwareversionen und Konfigurationen zu identifizieren.

```bash
# Basis-Versionserkennung
nmap -sV 192.168.1.1
# Aggressive Versionserkennung
nmap -sV --version-intensity 9 192.168.1.1
# Leichte Versionserkennung
nmap -sV --version-intensity 0 192.168.1.1
# Standard-Skripte mit Versionserkennung
nmap -sC -sV 192.168.1.1
```

### Service-Skripte

Verwenden Sie Skripte für eine verbesserte Service-Erkennung.

```bash
# Banner Grabbing
nmap --script banner 192.168.1.1
# HTTP-Dienst-Enumeration
nmap --script http-* 192.168.1.1
```

### Betriebssystem-Erkennung: `nmap -O`

Verwenden Sie TCP/IP-Fingerprinting, um das Betriebssystem von Zielhosts zu erraten.

```bash
# OS-Erkennung
nmap -O 192.168.1.1
# Aggressive OS-Erkennung
nmap -O --osscan-guess 192.168.1.1
# OS-Erkennungsversuche begrenzen
nmap -O --max-os-tries 1 192.168.1.1
```

### Umfassende Erkennung

Kombinieren Sie mehrere Erkennungstechniken.

```bash
# Aggressiver Scan (OS, Version, Skripte)
nmap -A 192.168.1.1
# Benutzerdefinierter aggressiver Scan
nmap -sS -sV -O -sC 192.168.1.1
```

## Timing & Leistung

### Timing-Vorlagen: `nmap -T`

Passen Sie die Scan-Geschwindigkeit basierend auf Ihrer Zielumgebung und dem Erkennungsrisiko an.

```bash
# Paranoid (sehr langsam, heimlich)
nmap -T0 192.168.1.1
# Sneaky (langsam, heimlich)
nmap -T1 192.168.1.1
# Polite (langsamer, weniger Bandbreite)
nmap -T2 192.168.1.1
# Normal (Standard)
nmap -T3 192.168.1.1
# Aggressiv (schneller)
nmap -T4 192.168.1.1
# Insane (sehr schnell, kann Ergebnisse verpassen)
nmap -T5 192.168.1.1
```

### Benutzerdefinierte Timing-Optionen

Feinabstimmung, wie Nmap Timeouts, Wiederholungen und paralleles Scannen handhabt, um die Leistung zu optimieren.

```bash
# Minimale Rate festlegen (Pakete pro Sekunde)
nmap --min-rate 1000 192.168.1.1
# Maximale Rate festlegen
nmap --max-rate 100 192.168.1.1
# Paralleles Host-Scannen
nmap --min-hostgroup 10 192.168.1.0/24
# Benutzerdefiniertes Timeout
nmap --host-timeout 5m 192.168.1.1
```

## Nmap Scripting Engine (NSE)

### Skript-Kategorien: `nmap --script`

Führen Sie Skripte nach Kategorie oder Namen aus.

```bash
# Standard-Skripte
nmap --script default 192.168.1.1
# Schwachstellen-Skripte
nmap --script vuln 192.168.1.1
# Entdeckungs-Skripte
nmap --script discovery 192.168.1.1
# Authentifizierungs-Skripte
nmap --script auth 192.168.1.1
```

### Spezifische Skripte

Zielen auf spezifische Schwachstellen oder Dienste ab.

```bash
# SMB-Enumeration
nmap --script smb-enum-* 192.168.1.1
# HTTP-Methoden
nmap --script http-methods 192.168.1.1
# SSL-Zertifikatsinformationen
nmap --script ssl-cert 192.168.1.1
```

### Skript-Argumente

Übergeben Sie Argumente, um das Skriptverhalten anzupassen.

```bash
# HTTP Brute Force mit benutzerdefinierter Wortliste
nmap --script http-brute --script-args
userdb=users.txt,passdb=pass.txt 192.168.1.1
# SMB Brute Force
nmap --script smb-brute 192.168.1.1
# DNS Brute Force
nmap --script dns-brute example.com
```

### Skript-Verwaltung

Verwalten und aktualisieren Sie NSE-Skripte.

```bash
# Skript-Datenbank aktualisieren
nmap --script-updatedb
# Verfügbare Skripte auflisten
ls /usr/share/nmap/scripts/ | grep http
# Skript-Hilfe abrufen
nmap --script-help vuln
```

## Ausgabeformate & Speichern von Ergebnissen

### Ausgabeformate

Ergebnisse in verschiedenen Formaten speichern.

```bash
# Normale Ausgabe
nmap -oN scan_results.txt 192.168.1.1
# XML-Ausgabe
nmap -oX scan_results.xml 192.168.1.1
# Grepable Ausgabe
nmap -oG scan_results.gnmap 192.168.1.1
# Alle Formate
nmap -oA scan_results 192.168.1.1
```

### Ausführliche Ausgabe

Steuern Sie die Menge der angezeigten Informationen.

```bash
# Ausführliche Ausgabe
nmap -v 192.168.1.1
# Sehr ausführlich
nmap -vv 192.168.1.1
# Debug-Modus
nmap --packet-trace 192.168.1.1
```

### Fortsetzen & Anhängen

Unterbrochene Scans fortsetzen oder zu bestehenden hinzufügen.

```bash
# Unterbrochenen Scan fortsetzen
nmap --resume scan_results.gnmap
# An vorhandene Datei anhängen
nmap --append-output -oN existing_scan.txt 192.168.1.1
```

### Live-Ergebnisverarbeitung

Kombinieren Sie Nmap-Ausgabe mit Kommandozeilen-Tools, um nützliche Erkenntnisse zu extrahieren.

```bash
# Live-Hosts finden
nmap -sn 192.168.1.0/24 | grep "Nmap scan report"
# Webserver finden
nmap -p 80,443 --open 192.168.1.0/24 | grep "open"
# Nach CSV exportieren
nmap -oX - 192.168.1.1 | xsltproc --html -
```

## Firewall-Umgehungstechniken

### Paketfragmentierung: `nmap -f`

Umgehung von Sicherheitsmaßnahmen durch Paketfragmentierung, IP-Spoofing und heimliche Scan-Methoden.

```bash
# Pakete fragmentieren
nmap -f 192.168.1.1
# Benutzerdefinierte MTU-Größe
nmap --mtu 16 192.168.1.1
# Maximale Übertragungseinheit
nmap --mtu 24 192.168.1.1
```

### Decoy-Scanning: `nmap -D`

Verstecken Sie Ihren Scan inmitten von Decoy-IP-Adressen.

```bash
# Decoy-IPs verwenden
nmap -D 192.168.1.100,192.168.1.101 192.168.1.1
# Zufällige Decoys
nmap -D RND:5 192.168.1.1
# Echte und zufällige Decoys mischen
nmap -D 192.168.1.100,RND:3 192.168.1.1
```

### Quell-IP/Port-Manipulation

Spoofing von Quellinformationen.

```bash
# Quell-IP spoofen
nmap -S 192.168.1.100 192.168.1.1
# Benutzerdefinierter Quellport
nmap --source-port 53 192.168.1.1
# Zufällige Datenlänge
nmap --data-length 25 192.168.1.1
```

### Idle/Zombie Scan: `nmap -sI`

Verwenden Sie einen Zombie-Host, um den Scan-Ursprung zu verbergen.

```bash
# Zombie Scan (erfordert Idle-Host)
nmap -sI zombie_host 192.168.1.1
# Idle-Kandidaten auflisten
nmap --script ipidseq 192.168.1.0/24
```

## Erweiterte Scan-Optionen

### DNS-Auflösungssteuerung

Steuern Sie, wie Nmap DNS-Abfragen behandelt.

```bash
# DNS-Auflösung deaktivieren
nmap -n 192.168.1.1
# DNS-Auflösung erzwingen
nmap -R 192.168.1.1
# Benutzerdefinierte DNS-Server
nmap --dns-servers 8.8.8.8,1.1.1.1 192.168.1.1
```

### IPv6 Scanning: `nmap -6`

Verwenden Sie diese Nmap-Flags für zusätzliche Funktionalität wie IPv6-Unterstützung.

```bash
# IPv6 Scan
nmap -6 2001:db8::1
# IPv6 Netzwerk-Scan
nmap -6 2001:db8::/32
```

### Schnittstellen- & Routing-Steuerung

Steuern Sie die Netzwerkschnittstelle und das Routing.

```bash
# Netzwerkschnittstelle angeben
nmap -e eth0 192.168.1.1
# Schnittstellen und Routen drucken
nmap --iflist
# Traceroute
nmap --traceroute 192.168.1.1
```

### Verschiedene Optionen

Zusätzliche nützliche Flags.

```bash
# Version drucken und beenden
nmap --version
# Auf Ethernet-Ebene senden
nmap --send-eth 192.168.1.1
# Auf IP-Ebene senden
nmap --send-ip 192.168.1.1
```

## Praxisbeispiele

### Netzwerk-Entdeckungs-Workflow

Vollständiger Prozess der Netzwerkerfassung.

```bash
# Schritt 1: Live-Hosts entdecken
nmap -sn 192.168.1.0/24
# Schritt 2: Schneller Port-Scan
nmap -sS -T4 --top-ports 1000 192.168.1.0/24
# Schritt 3: Detaillierter Scan interessanter Hosts
nmap -sS -sV -sC -O 192.168.1.50
# Schritt 4: Umfassender Scan
nmap -p- -A -T4 192.168.1.50
```

### Webserver-Bewertung

Fokus auf Webdienste und Schwachstellen.

```bash
# Webserver finden
nmap -sS -p 80,443,8080,8443 --open 192.168.1.0/24
# HTTP-Dienste enumerieren
nmap -sS -sV --script http-* 192.168.1.50
# Auf gängige Schwachstellen prüfen
nmap --script vuln -p 80,443 192.168.1.50
```

### SMB/NetBIOS-Enumeration

Das folgende Beispiel listet Netbios auf den Zielnetzwerken auf.

```bash
# SMB-Dienst-Erkennung
nmap -sV -p 139,445 192.168.1.0/24
# NetBIOS-Namensauflösung
nmap -sU --script nbstat -p 137 192.168.1.0/24
# SMB-Enumerations-Skripte
nmap --script smb-enum-* -p 445 192.168.1.50
# SMB-Schwachstellenprüfung
nmap --script smb-vuln-* -p 445 192.168.1.50
```

### Stealth-Bewertung

Aufklärung mit geringem Profil.

```bash
# Ultra-Stealth Scan
nmap -sS -T0 -f --data-length 200 -D RND:10 192.168.1.1
# Fragmentierter SYN-Scan
nmap -sS -f --mtu 8 -T1 192.168.1.1
```

## Leistungsoptimierung

### Schnelle Scan-Strategien

Optimieren Sie die Scan-Geschwindigkeit für große Netzwerke.

```bash
# Schneller Netzwerk-Sweep
nmap -sS -T4 --min-rate 1000 --max-retries 1
192.168.1.0/24
# Paralleles Host-Scannen
nmap --min-hostgroup 50 --max-hostgroup 100
192.168.1.0/24
# Langsame Operationen überspringen
nmap -sS -T4 --defeat-rst-ratelimit 192.168.1.0/24
```

### Speicher- & Ressourcenverwaltung

Steuern Sie die Ressourcennutzung für Stabilität.

```bash
# Parallele Sonden begrenzen
nmap --max-parallelism 10 192.168.1.0/24
# Scan-Verzögerungen steuern
nmap --scan-delay 100ms 192.168.1.1
# Host-Timeout festlegen
nmap --host-timeout 10m 192.168.1.0/24
```

## Relevante Links

- <router-link to="/wireshark">Wireshark Spickzettel</router-link>
- <router-link to="/kali">Kali Linux Spickzettel</router-link>
- <router-link to="/cybersecurity">Cybersicherheit Spickzettel</router-link>
- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/network">Netzwerk Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>

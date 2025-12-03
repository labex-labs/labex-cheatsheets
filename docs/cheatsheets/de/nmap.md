---
title: 'Nmap Spickzettel | LabEx'
description: 'Lernen Sie Nmap-Netzwerk-Scanning mit diesem umfassenden Spickzettel. Schnelle Referenz für Port-Scanning, Netzwerkerkennung, Schwachstellenerkennung, Sicherheitsaudits und Netzwerkerkundung.'
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
Lernen Sie Nmap Network Scanning durch praktische Labs und reale Szenarien. LabEx bietet umfassende Nmap-Kurse, die wesentliche Netzwerkentdeckung, Port-Scanning, Dienst-Erkennung, OS-Fingerprinting und Schwachstellenanalyse abdecken. Meistern Sie Techniken zur Netzwerkerkundung und Sicherheitsprüfung.
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

Laden Sie die Installationsdatei von der offiziellen Website herunter und installieren Sie sie.

```bash
# Installer herunterladen von
https://nmap.org/download.html
# Führen Sie die .exe-Installationsdatei mit Administratorrechten aus
# Enthält Zenmap GUI und Kommandozeilenversion
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

<BaseQuiz id="nmap-scan-1" correct="A">
  <template #question>
    Was bewirkt ein einfacher `nmap 192.168.1.1` Scan standardmäßig?
  </template>
  
  <BaseQuizOption value="A" correct>Scannt die 1000 häufigsten TCP-Ports</BaseQuizOption>
  <BaseQuizOption value="B">Scannt alle 65535 Ports</BaseQuizOption>
  <BaseQuizOption value="C">Führt nur Host-Discovery durch</BaseQuizOption>
  <BaseQuizOption value="D">Scannt nur Port 80</BaseQuizOption>
  
  <BaseQuizAnswer>
    Standardmäßig scannt Nmap die 1000 häufigsten TCP-Ports. Um alle Ports zu scannen, verwenden Sie `-p-` oder geben Sie spezifische Ports mit `-p 80,443,22` an.
  </BaseQuizAnswer>
</BaseQuiz>

### Netzwerkbereichs-Scan

Nmap akzeptiert Hostnamen, IP-Adressen und Subnetze.

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

## Host-Discovery-Techniken

### Ping Scan: `nmap -sn`

Host-Discovery ist eine Schlüsselmethode, die viele Analysten und Penetrationstester mit Nmap verwenden. Ihr Zweck ist es, einen Überblick darüber zu gewinnen, welche Systeme online sind.

```bash
# Nur Ping-Scan (kein Port-Scan)
nmap -sn 192.168.1.0/24
# Host-Discovery überspringen (alle Hosts als aktiv annehmen)
nmap -Pn 192.168.1.1
# ICMP Echo Ping
nmap -PE 192.168.1.0/24
```

<BaseQuiz id="nmap-ping-1" correct="A">
  <template #question>
    Was bewirkt `nmap -sn`?
  </template>
  
  <BaseQuizOption value="A" correct>Führt nur Host-Discovery ohne Port-Scanning durch</BaseQuizOption>
  <BaseQuizOption value="B">Scannt alle Ports auf dem Ziel</BaseQuizOption>
  <BaseQuizOption value="C">Führt einen Stealth-Scan durch</BaseQuizOption>
  <BaseQuizOption value="D">Scannt nur UDP-Ports</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das Flag `-sn` weist Nmap an, nur die Host-Discovery (Ping-Scan) durchzuführen, ohne Ports zu scannen. Dies ist nützlich, um schnell zu identifizieren, welche Hosts in einem Netzwerk online sind.
  </BaseQuizAnswer>
</BaseQuiz>

### TCP Ping-Techniken

Verwenden Sie TCP-Pakete für die Host-Discovery.

```bash
# TCP SYN Ping an Port 80
nmap -PS80 192.168.1.0/24
# TCP ACK Ping
nmap -PA80 192.168.1.0/24
# TCP SYN Ping an mehrere Ports
nmap -PS22,80,443 192.168.1.0/24
```

### UDP Ping: `nmap -PU`

Verwenden Sie UDP-Pakete für die Host-Discovery.

```bash
# UDP Ping an gängige Ports
nmap -PU53,67,68,137 192.168.1.0/24
```

<BaseQuiz id="nmap-udp-1" correct="B">
  <template #question>
    Warum sollte man UDP Ping anstelle von ICMP Ping verwenden?
  </template>
  
  <BaseQuizOption value="A">UDP Ping ist immer schneller</BaseQuizOption>
  <BaseQuizOption value="B" correct>Einige Netzwerke blockieren ICMP, erlauben aber UDP-Pakete</BaseQuizOption>
  <BaseQuizOption value="C">UDP Ping scannt Ports automatisch</BaseQuizOption>
  <BaseQuizOption value="D">UDP Ping funktioniert nur in lokalen Netzwerken</BaseQuizOption>
  
  <BaseQuizAnswer>
    UDP Ping kann nützlich sein, wenn ICMP durch Firewalls blockiert wird. Viele Netzwerke erlauben UDP-Pakete an gängige Ports (wie DNS Port 53), selbst wenn ICMP gefiltert wird, was UDP Ping für die Host-Discovery effektiv macht.
  </BaseQuizAnswer>
</BaseQuiz>
# UDP Ping an Standard-Ports
nmap -PU 192.168.1.0/24
```

### ARP Ping: `nmap -PR`

Verwenden Sie ARP-Anfragen für die lokale Netzwerk-Discovery.

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

Nmap sendet ein TCP-Paket mit gesetztem SYN-Flag an einen Port. Dies informiert den Benutzer darüber, ob Ports offen, geschlossen oder unbekannt sind.

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

Fortgeschrittene Scan-Techniken zur Umgehung von Sicherheitsmaßnahmen.

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

## Dienst- & Versionserkennung

### Dienst-Erkennung: `nmap -sV`

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

Verwenden Sie Skripte für eine verbesserte Dienst-Erkennung.

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
# Mindestrate festlegen (Pakete pro Sekunde)
nmap --min-rate 1000 192.168.1.1
# Maximalrate festlegen
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
# Discovery-Skripte
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

Speichern Sie Ergebnisse in verschiedenen Formaten.

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

Unterbrochene Scans fortsetzen oder vorhandene Dateien erweitern.

```bash
# Unterbrochenen Scan fortsetzen
nmap --resume scan_results.gnmap
# An vorhandene Datei anhängen
nmap --append-output -oN existing_scan.txt 192.168.1.1
```

### Live-Ergebnisverarbeitung

Kombinieren Sie Nmap-Ausgabe mit Kommandozeilen-Tools, um nützliche Erkenntnisse zu gewinnen.

```bash
# Live-Hosts extrahieren
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

Verstecken Sie Ihren Scan inmitten von Köder-IP-Adressen.

```bash
# Köder-IPs verwenden
nmap -D 192.168.1.100,192.168.1.101 192.168.1.1
# Zufällige Köder
nmap -D RND:5 192.168.1.1
# Echte und zufällige Köder mischen
nmap -D 192.168.1.100,RND:3 192.168.1.1
```

### Quell-IP/Port-Manipulation

Quellinformationen fälschen.

```bash
# Quell-IP fälschen
nmap -S 192.168.1.100 192.168.1.1
# Benutzerdefinierter Quellport
nmap --source-port 53 192.168.1.1
# Zufällige Datenlänge
nmap --data-length 25 192.168.1.1
```

### Idle/Zombie Scan: `nmap -sI`

Verwenden Sie einen Zombie-Host, um den Scan-Ursprung zu verbergen.

```bash
# Zombie-Scan (erfordert einen inaktiven Host)
nmap -sI zombie_host 192.168.1.1
# Idle-Kandidaten auflisten
nmap --script ipidseq 192.168.1.0/24
```

## Erweiterte Scan-Optionen

### DNS-Auflösungssteuerung

Steuern Sie, wie Nmap DNS-Lookups behandelt.

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

### Schnittstelle & Routing

Steuern Sie die Netzwerkschnittstelle und das Routing.

```bash
# Netzwerkschnittstelle angeben
nmap -e eth0 192.168.1.1
# Schnittstelle und Routen drucken
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

### Netzwerk-Discovery-Workflow

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
# NetBIOS-Namens-Discovery
nmap -sU --script nbstat -p 137 192.168.1.0/24
# SMB-Enumerationsskripte
nmap --script smb-enum-* -p 445 192.168.1.50
# SMB-Schwachstellenprüfung
nmap --script smb-vuln-* -p 445 192.168.1.50
```

### Stealth-Bewertung

Aufklärung mit niedrigem Profil.

```bash
# Ultra-Stealth-Scan
nmap -sS -T0 -f --data-length 200 -D RND:10 192.168.1.1
# Fragmentierter SYN-Scan
nmap -sS -f --mtu 8 -T1 192.168.1.1
```

## Leistungsoptimierung

### Schnelle Scan-Strategien

Scan-Geschwindigkeit für große Netzwerke optimieren.

```bash
# Schneller Netzwerk-Sweep
nmap -sS -T4 --min-rate 1000 --max-retries 1
192.168.1.0/24
# Paralleles Host-Scannen
nmap --min-hostgroup 50 --max-hostgroup 100
192.168.1.0/24
# Langsame Vorgänge überspringen
nmap -sS -T4 --defeat-rst-ratelimit 192.168.1.0/24
```

### Speicher- & Ressourcenverwaltung

Steuerung der Ressourcennutzung für Stabilität.

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

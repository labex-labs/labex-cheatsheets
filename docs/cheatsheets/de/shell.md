---
title: 'Shell Spickzettel | LabEx'
description: 'Lernen Sie Shell-Skripterstellung mit diesem umfassenden Spickzettel. Schnelle Referenz für Bash-Befehle, Shell-Skripte, Automatisierung, Befehlszeilen-Tools und Linux/Unix-Systemadministration.'
pdfUrl: '/cheatsheets/pdf/shell-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Shell Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/shell">Shell mit Hands-on-Labs lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Shell-Skripterstellung und Befehlszeilenoperationen durch praktische Labs und reale Szenarien. LabEx bietet umfassende Shell-Kurse, die wesentliche Bash-Befehle, Dateioperationen, Textverarbeitung, Prozessverwaltung und Automatisierung abdecken. Meistern Sie die Effizienz der Befehlszeile und Techniken des Shell-Skriptings.
</base-disclaimer-content>
</base-disclaimer>

## Datei- & Verzeichnisoperationen

### Dateien auflisten: `ls`

Dateien und Verzeichnisse am aktuellen Ort anzeigen.

```bash
# Dateien im aktuellen Verzeichnis auflisten
ls
# Mit detaillierten Informationen auflisten
ls -l
# Versteckte Dateien anzeigen
ls -a
# Mit menschenlesbaren Dateigrößen auflisten
ls -lh
# Nach Änderungszeit sortieren
ls -lt
```

### Dateien erstellen: `touch`

Leere Dateien erstellen oder Zeitstempel aktualisieren.

```bash
# Eine neue Datei erstellen
touch neue_datei.txt
# Mehrere Dateien erstellen
touch datei1.txt datei2.txt datei3.txt
# Zeitstempel der vorhandenen Datei aktualisieren
touch vorhandene_datei.txt
```

### Verzeichnisse erstellen: `mkdir`

Neue Verzeichnisse erstellen.

```bash
# Ein Verzeichnis erstellen
mkdir mein_verzeichnis
# Verschachtelte Verzeichnisse erstellen
mkdir -p eltern/kind/enkel
# Mehrere Verzeichnisse erstellen
mkdir verz1 verz2 verz3
```

### Dateien kopieren: `cp`

Dateien und Verzeichnisse kopieren.

```bash
# Eine Datei kopieren
cp quelle.txt ziel.txt
# Verzeichnis rekursiv kopieren
cp -r quelle_verz ziel_verz
# Mit Bestätigungsaufforderung kopieren
cp -i datei1.txt datei2.txt
# Dateiattribute beibehalten
cp -p original.txt kopie.txt
```

### Verschieben/Umbenennen: `mv`

Dateien und Verzeichnisse verschieben oder umbenennen.

```bash
# Eine Datei umbenennen
mv alter_name.txt neuer_name.txt
# Datei in Verzeichnis verschieben
mv datei.txt /pfad/zum/verzeichnis/
# Mehrere Dateien verschieben
mv datei1 datei2 datei3 ziel_verzeichnis/
```

### Dateien löschen: `rm`

Dateien und Verzeichnisse entfernen.

```bash
# Eine Datei löschen
rm datei.txt
# Verzeichnis und Inhalt löschen
rm -r verzeichnis/
# Ohne Bestätigung erzwingen
rm -f datei.txt
# Interaktives Löschen (jede bestätigen)
rm -i *.txt
```

## Navigation & Pfadverwaltung

### Aktuelles Verzeichnis: `pwd`

Den Pfad des aktuellen Arbeitsverzeichnisses ausgeben.

```bash
# Aktuelles Verzeichnis anzeigen
pwd
# Beispielausgabe:
/home/benutzer/dokumente
```

### Verzeichnis wechseln: `cd`

In ein anderes Verzeichnis wechseln.

```bash
# Zum Home-Verzeichnis wechseln
cd ~
# Zum Elternverzeichnis wechseln
cd ..
# Zum vorherigen Verzeichnis wechseln
cd -
# Zu einem bestimmten Verzeichnis wechseln
cd /pfad/zum/verzeichnis
```

<BaseQuiz id="shell-cd-1" correct="A">
  <template #question>
    Was bewirkt <code>cd ~</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Wechselt in das Home-Verzeichnis</BaseQuizOption>
  <BaseQuizOption value="B">Wechselt in das Root-Verzeichnis</BaseQuizOption>
  <BaseQuizOption value="C">Wechselt in das Elternverzeichnis</BaseQuizOption>
  <BaseQuizOption value="D">Erstellt ein neues Verzeichnis</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das Symbol <code>~</code> ist eine Abkürzung für das Home-Verzeichnis. <code>cd ~</code> navigiert zu Ihrem Home-Verzeichnis, was äquivalent zu <code>cd $HOME</code> oder <code>cd /home/benutzername</code> ist.
  </BaseQuizAnswer>
</BaseQuiz>

### Verzeichnisstruktur: `tree`

Anzeige der Verzeichnisstruktur im Baumformat.

```bash
# Verzeichnisbaum anzeigen
tree
# Tiefe auf 2 Ebenen begrenzen
tree -L 2
# Nur Verzeichnisse anzeigen
tree -d
```

## Textverarbeitung & Suche

### Dateien anzeigen: `cat` / `less` / `head` / `tail`

Dateiinhalte auf unterschiedliche Weise anzeigen.

```bash
# Gesamte Datei anzeigen
cat datei.txt
# Datei seitenweise anzeigen
less datei.txt
# Erste 10 Zeilen anzeigen
head datei.txt
# Letzte 10 Zeilen anzeigen
tail datei.txt
# Letzte 20 Zeilen anzeigen
tail -n 20 datei.txt
# Dateiänderungen verfolgen (nützlich für Logs)
tail -f protokoll.txt
```

### In Dateien suchen: `grep`

Nach Mustern in Textdateien suchen.

```bash
# Nach Muster in Datei suchen
grep "muster" datei.txt
# Suche ohne Berücksichtigung der Groß-/Kleinschreibung
grep -i "muster" datei.txt
# Rekursiv in Verzeichnissen suchen
grep -r "muster" verzeichnis/
# Zeilennummern anzeigen
grep -n "muster" datei.txt
# Übereinstimmende Zeilen zählen
grep -c "muster" datei.txt
```

<BaseQuiz id="shell-grep-1" correct="B">
  <template #question>
    Was bewirkt <code>grep -r "muster" verzeichnis/</code>?
  </template>
  
  <BaseQuizOption value="A">Sucht nur in der aktuellen Datei</BaseQuizOption>
  <BaseQuizOption value="B" correct>Sucht rekursiv in allen Dateien im Verzeichnis</BaseQuizOption>
  <BaseQuizOption value="C">Ersetzt das Muster in Dateien</BaseQuizOption>
  <BaseQuizOption value="D">Löscht Dateien, die das Muster enthalten</BaseQuizOption>
  
  <BaseQuizAnswer>
    Die Option <code>-r</code> bewirkt, dass grep rekursiv alle Dateien und Unterverzeichnisse durchsucht. Dies ist nützlich, um Textmuster in einer gesamten Verzeichnisstruktur zu finden.
  </BaseQuizAnswer>
</BaseQuiz>

### Dateien finden: `find`

Dateien und Verzeichnisse anhand von Kriterien lokalisieren.

```bash
# Dateien nach Namen finden
find . -name "*.txt"
# Dateien nach Typ finden
find . -type f -name "konfig*"
# Verzeichnisse finden
find . -type d -name "backup"
# Dateien finden, die in den letzten 7 Tagen geändert wurden
find . -mtime -7
# Finden und Befehl ausführen
find . -name "*.log" -delete
```

### Textmanipulation: `sed` / `awk` / `sort`

Textdaten verarbeiten und manipulieren.

```bash
# Text in Datei ersetzen
sed 's/alt/neu/g' datei.txt
# Spezifische Spalten extrahieren
awk '{print $1, $3}' datei.txt
# Dateiinhalt sortieren
sort datei.txt
# Doppelte Zeilen entfernen
sort datei.txt | uniq
# Worthäufigkeit zählen
cat datei.txt | tr ' ' '\n' | sort | uniq -c
```

## Dateiberechtigungen & Eigentümerschaft

### Berechtigungen anzeigen: `ls -l`

Detaillierte Datei- und Eigentümerberechtigungen anzeigen.

```bash
# Detaillierte Dateiinformationen anzeigen
ls -l
# Beispielausgabe:
# -rw-r--r-- 1 benutzer gruppe 1024 Jan 1 12:00 datei.txt
# d = Verzeichnis, r = lesen, w = schreiben, x = ausführen
```

### Berechtigungen ändern: `chmod`

Datei- und Verzeichnisberechtigungen ändern.

```bash
# Ausführungsberechtigung für den Besitzer geben
chmod +x script.sh
# Spezifische Berechtigungen setzen (755)
chmod 755 datei.txt
# Schreibberechtigung für Gruppe/Andere entfernen
chmod go-w datei.txt
# Rekursive Berechtigungsänderung
chmod -R 644 verzeichnis/
```

<BaseQuiz id="shell-chmod-1" correct="C">
  <template #question>
    Was setzt <code>chmod 755 datei.txt</code>?
  </template>
  
  <BaseQuizOption value="A">Lesen, Schreiben, Ausführen für alle Benutzer</BaseQuizOption>
  <BaseQuizOption value="B">Lesen und Schreiben für den Besitzer, Lesen für andere</BaseQuizOption>
  <BaseQuizOption value="C" correct>Lesen, Schreiben, Ausführen für den Besitzer; Lesen, Ausführen für Gruppe und andere</BaseQuizOption>
  <BaseQuizOption value="D">Nur Lesen für alle Benutzer</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 755</code> setzt die Berechtigungen wie folgt: Besitzer = 7 (rwx), Gruppe = 5 (r-x), andere = 5 (r-x). Dies ist eine übliche Berechtigungseinstellung für ausführbare Dateien und Verzeichnisse.
  </BaseQuizAnswer>
</BaseQuiz>

### Eigentümerschaft ändern: `chown` / `chgrp`

Datei-Eigentümer und Gruppe ändern.

```bash
# Eigentümer ändern
chown neuer_eigentuemer datei.txt
# Eigentümer und Gruppe ändern
chown neuer_eigentuemer:neue_gruppe datei.txt
# Nur Gruppe ändern
chgrp neue_gruppe datei.txt
# Rekursive Eigentümeränderung
chown -R benutzer:gruppe verzeichnis/
```

### Berechtigungszahlen

Verständnis der numerischen Berechtigungsnotation.

```text
# Berechnungsformel:
# 4 = lesen (r), 2 = schreiben (w), 1 = ausführen (x)
# 755 = rwxr-xr-x (Besitzer: rwx, Gruppe: r-x, andere: r-x)
# 644 = rw-r--r-- (Besitzer: rw-, Gruppe: r--, andere: r--)
# 777 = rwxrwxrwx (volle Berechtigungen für alle)
# 600 = rw------- (Besitzer: rw-, Gruppe: ---, andere: ---)
```

## Prozessverwaltung

### Prozesse anzeigen: `ps` / `top` / `htop`

Informationen über laufende Prozesse anzeigen.

```bash
# Prozesse für den aktuellen Benutzer anzeigen
ps
# Alle Prozesse mit Details anzeigen
ps aux
# Prozesse im Baumformat anzeigen
ps -ef --forest
# Interaktiver Prozess-Viewer
top
# Verbesserter Prozess-Viewer (falls verfügbar)
htop
```

### Hintergrundjobs: `&` / `jobs` / `fg` / `bg`

Hintergrund- und Vordergrundprozesse verwalten.

```bash
# Befehl im Hintergrund ausführen
befehl &
# Aktive Jobs auflisten
jobs
# Job in den Vordergrund holen
fg %1
# Job in den Hintergrund senden
bg %1
# Aktuellen Prozess anhalten
Ctrl+Z
```

### Prozesse beenden: `kill` / `killall`

Prozesse nach PID oder Namen beenden.

```bash
# Prozess nach PID beenden
kill 1234
# Prozess erzwingen
kill -9 1234
# Alle Prozesse mit Namen beenden
killall firefox
# Spezifisches Signal senden
kill -TERM 1234
```

### Systemüberwachung: `free` / `df` / `du`

Systemressourcen und Festplattennutzung überwachen.

```bash
# Speichernutzung anzeigen
free -h
# Festplattenspeicher anzeigen
df -h
# Verzeichnisgröße anzeigen
du -sh verzeichnis/
# Größte Verzeichnisse anzeigen
du -h --max-depth=1 | sort -hr
```

## Eingabe-/Ausgabe-Umleitung

### Umleitung: `>` / `>>` / `<`

Befehlsausgabe und Eingabe umleiten.

```bash
# Ausgabe in Datei umleiten (überschreiben)
befehl > ausgabe.txt
# Ausgabe an Datei anhängen
befehl >> ausgabe.txt
# Eingabe von Datei umleiten
befehl < eingabe.txt
# Ausgabe und Fehler umleiten
befehl > ausgabe.txt 2>&1
# Ausgabe verwerfen
befehl > /dev/null
```

<BaseQuiz id="shell-redirect-1" correct="B">
  <template #question>
    Was ist der Unterschied zwischen <code>></code> und <code>>></code> bei der Shell-Umleitung?
  </template>
  
  <BaseQuizOption value="A"><code>></code> hängt an, <code>>></code> überschreibt</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>></code> überschreibt die Datei, <code>>></code> hängt an die Datei an</BaseQuizOption>
  <BaseQuizOption value="C"><code>></code> leitet stdout um, <code>>></code> leitet stderr um</BaseQuizOption>
  <BaseQuizOption value="D">Es gibt keinen Unterschied</BaseQuizOption>
  
  <BaseQuizAnswer>
    Der Operator <code>></code> überschreibt die Zieldatei, falls sie existiert, während <code>>></code> die Ausgabe am Ende der Datei anhängt. Verwenden Sie <code>>></code>, wenn Sie vorhandene Inhalte beibehalten möchten.
  </BaseQuizAnswer>
</BaseQuiz>

### Pipes: `|`

Befehle mithilfe von Pipes verketten.

```bash
# Grundlegende Pipe-Verwendung
befehl1 | befehl2
# Mehrere Pipes
cat datei.txt | grep "muster" | sort | uniq
# Zeilenanzahl der Ausgabe
ps aux | wc -l
# Lange Ausgabe seitenweise anzeigen
ls -la | less
```

### Tee: `tee`

Ausgabe sowohl in Datei als auch in stdout schreiben.

```bash
# Ausgabe speichern und anzeigen
befehl | tee ausgabe.txt
# An Datei anhängen
befehl | tee -a ausgabe.txt
# Mehrere Ausgaben
befehl | tee datei1.txt datei2.txt
```

### Here Documents: `<<`

Mehrzeilige Eingabe für Befehle bereitstellen.

```bash
# Datei mit Here Document erstellen
cat << EOF > datei.txt
Zeile 1
Zeile 2
Zeile 3
EOF
# E-Mail mit Here Document senden
mail benutzer@beispiel.com << EOF
Betreff: Test
Dies ist eine Testnachricht.
EOF
```

## Variablen & Umgebung

### Variablen: Zuweisung & Verwendung

Shell-Variablen erstellen und verwenden.

```bash
# Variablen zuweisen (keine Leerzeichen um =)
name="John"
anzahl=42
# Variablen verwenden
echo $name
echo "Hallo, $name"
echo "Anzahl: ${anzahl}"
# Befehlssubstitution
aktuelles_verzeichnis=$(pwd)
heutiges_datum=$(date +%Y-%m-%d)
```

### Umgebungsvariablen: `export` / `env`

Umgebungsvariablen verwalten.

```bash
# Variable in die Umgebung exportieren
export PATH="/neu/pfad:$PATH"
export MEINE_VAR="wert"
# Alle Umgebungsvariablen anzeigen
env
# Spezifische Variable anzeigen
echo $HOME
echo $PATH
# Variable entfernen
unset MEINE_VAR
```

### Spezielle Variablen

Eingebaute Shell-Variablen mit spezieller Bedeutung.

```bash
# Skriptargumente
$0  # Skriptname
$1, $2, $3...  # Erstes, zweites, drittes Argument
$#  # Anzahl der Argumente
$@  # Alle Argumente als separate Wörter
$*  # Alle Argumente als ein Wort
$?  # Exit-Status des letzten Befehls
# Prozessinformationen
$$  # Aktuelle Shell-PID
$!  # PID des letzten Hintergrundbefehls
```

### Parameter-Expansion

Fortgeschrittene Techniken zur Variablenmanipulation.

```bash
# Standardwerte
${var:-standard}  # Standardwert verwenden, wenn var leer ist
${var:=standard}  # var auf Standardwert setzen, wenn leer
# String-Manipulation
${var#muster}   # Kürzeste Übereinstimmung vom Anfang entfernen
${var##muster}  # Längste Übereinstimmung vom Anfang entfernen
${var%muster}   # Kürzeste Übereinstimmung vom Ende entfernen
${var%%muster}  # Längste Übereinstimmung vom Ende entfernen
```

## Skripting-Grundlagen

### Skriptstruktur

Grundlegendes Skriptformat und Ausführung.

```bash
#!/bin/bash
# Dies ist ein Kommentar
# Variablen
begruessung="Hallo, Welt!"
benutzer=$(whoami)
# Ausgabe
echo $begruessung
echo "Aktueller Benutzer: $benutzer"
# Skript ausführbar machen:
chmod +x script.sh
# Skript ausführen:
./script.sh
```

### Bedingte Anweisungen: `if`

Steuerung des Skriptflusses mit Bedingungen.

```bash
#!/bin/bash
if [ -f "datei.txt" ]; then
    echo "Datei existiert"
elif [ -d "verzeichnis" ]; then
    echo "Verzeichnis existiert"
else
    echo "Keines von beiden existiert"
fi
# String-Vergleich
if [ "$USER" = "root" ]; then
    echo "Als Root ausgeführt"
fi
# Numerischer Vergleich
if [ $anzahl -gt 10 ]; then
    echo "Anzahl ist größer als 10"
fi
```

### Schleifen: `for` / `while`

Befehle mithilfe von Schleifen wiederholen.

```bash
#!/bin/bash
# For-Schleife mit Bereich
for i in {1..5}; do
    echo "Zahl: $i"
done
# For-Schleife mit Dateien
for datei in *.txt; do
    echo "Verarbeite: $datei"
done
# While-Schleife
anzahl=1
while [ $anzahl -le 5 ]; do
    echo "Anzahl: $anzahl"
    anzahl=$((anzahl + 1))
done
```

### Funktionen

Wiederverwendbare Codeblöcke erstellen.

```bash
#!/bin/bash
# Funktion definieren
begruessen() {
    local name=$1
    echo "Hallo, $name!"
}
# Funktion mit Rückgabewert
addiere_zahlen() {
    local summe=$(($1 + $2))
    echo $summe
}
# Funktionen aufrufen
begruessen "Alice"
ergebnis=$(addiere_zahlen 5 3)
echo "Summe: $ergebnis"
```

## Netzwerk- & Systembefehle

### Netzwerkbefehle

Konnektivität und Netzwerkkonfiguration testen.

```bash
# Netzwerkverbindung testen
ping google.com
ping -c 4 google.com  # Nur 4 Pakete senden
# DNS-Abfrage
nslookup google.com
dig google.com
# Netzwerkkonfiguration
ip addr show  # IP-Adressen anzeigen
ip route show # Routing-Tabelle anzeigen
# Dateien herunterladen
wget https://example.com/datei.txt
curl -O https://example.com/datei.txt
```

### Systeminformationen: `uname` / `whoami` / `date`

System- und Benutzerinformationen abrufen.

```bash
# Systeminformationen
uname -a      # Alle Systeminfos
uname -r      # Kernel-Version
hostname      # Computername
whoami        # Aktueller Benutzername
id            # Benutzer-ID und Gruppen
# Datum und Uhrzeit
date          # Aktuelles Datum/Uhrzeit
date +%Y-%m-%d # Benutzerdefiniertes Format
uptime        # Systemlaufzeit
```

### Archiv & Komprimierung: `tar` / `zip`

Komprimierte Archive erstellen und extrahieren.

```bash
# Tar-Archiv erstellen
tar -czf archiv.tar.gz verzeichnis/
# Tar-Archiv extrahieren
tar -xzf archiv.tar.gz
# Zip-Archiv erstellen
zip -r archiv.zip verzeichnis/
# Zip-Archiv extrahieren
unzip archiv.zip
# Archivinhalt anzeigen
tar -tzf archiv.tar.gz
unzip -l archiv.zip
```

### Dateiübertragung: `scp` / `rsync`

Dateien zwischen Systemen übertragen.

```bash
# Datei auf entfernten Server kopieren
scp datei.txt benutzer@server:/pfad/zum/ziel
# Von entferntem Server kopieren
scp benutzer@server:/pfad/zur/datei.txt .
# Verzeichnisse synchronisieren (lokal zu remote)
rsync -avz lokales_verz/ benutzer@server:/entferntes_verz/
# Synchronisieren mit Löschen (Spiegeln)
rsync -avz --delete lokales_verz/ benutzer@server:/entferntes_verz/
```

## Befehlshistorie & Tastenkürzel

### Befehlshistorie: `history`

Vorherige Befehle anzeigen und wiederverwenden.

```bash
# Befehlshistorie anzeigen
history
# Letzte 10 Befehle anzeigen
history 10
# Vorherigen Befehl ausführen
!!
# Befehl nach Nummer ausführen
!123
# Letzten Befehl ausführen, der mit 'ls' beginnt
!ls
# Interaktive Suche in der Historie
Ctrl+R
```

### Historie-Expansion

Teile vorheriger Befehle wiederverwenden.

```bash
# Argumente des letzten Befehls
!$    # Letztes Argument des vorherigen Befehls
!^    # Erstes Argument des vorherigen Befehls
!*    # Alle Argumente des vorherigen Befehls
# Beispielverwendung:
ls /sehr/langer/pfad/zur/datei.txt
cd !$  # Wechselt zu /sehr/langer/pfad/zur/datei.txt
```

### Tastenkürzel

Wesentliche Abkürzungen für effiziente Befehlszeilennutzung.

```bash
# Navigation
Ctrl+A  # Zum Zeilenanfang bewegen
Ctrl+E  # Zum Zeilenende bewegen
Ctrl+F  # Ein Zeichen vorwärts bewegen
Ctrl+B  # Ein Zeichen rückwärts bewegen
Alt+F   # Ein Wort vorwärts bewegen
Alt+B   # Ein Wort rückwärts bewegen
# Bearbeitung
Ctrl+U  # Zeile vor dem Cursor löschen
Ctrl+K  # Zeile nach dem Cursor löschen
Ctrl+W  # Wort vor dem Cursor löschen
Ctrl+Y  # Zuletzt gelöschten Text einfügen
# Prozesssteuerung
Ctrl+C  # Aktuellen Befehl unterbrechen
Ctrl+Z  # Aktuellen Befehl suspendieren
Ctrl+D  # Shell beenden oder EOF
```

## Befehlskombinationen & Tipps

### Nützliche Befehlskombinationen

Leistungsstarke Einzeiler für häufige Aufgaben.

```bash
# Text in mehreren Dateien finden und ersetzen
find . -name "*.txt" -exec sed -i 's/alt/neu/g' {} \;
# Größte Dateien im aktuellen Verzeichnis finden
du -ah . | sort -rh | head -10
# Log-Datei auf bestimmtes Muster überwachen
tail -f /var/log/syslog | grep "FEHLER"
# Dateien in einem Verzeichnis zählen
ls -1 | wc -l
# Backup mit Zeitstempel erstellen
cp datei.txt datei.txt.backup.$(date +%Y%m%d-%H%M%S)
```

### Aliase & Funktionen

Verknüpfungen für häufig verwendete Befehle erstellen.

```bash
# Aliase erstellen (zu ~/.bashrc hinzufügen)
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
# Alle Aliase anzeigen
alias
# Persistente Aliase in ~/.bashrc erstellen:
echo "alias meinbefehl='langer befehl hier'" >>
~/.bashrc
source ~/.bashrc
```

### Jobsteuerung & Screen-Sitzungen

Langlaufende Prozesse und Sitzungen verwalten.

```bash
# Befehl im Hintergrund starten
nohup langlaufender_befehl &
# Screen-Sitzung starten
screen -S meine_sitzung
# Von Screen trennen: Strg+A dann D
# Erneut mit Screen verbinden
screen -r meine_sitzung
# Screen-Sitzungen auflisten
screen -ls
# Alternative: tmux
tmux new -s meine_sitzung
# Trennen: Strg+B dann D
tmux attach -t meine_sitzung
```

### Systemwartung

Häufige Systemadministrationsaufgaben.

```bash
# Festplattennutzung prüfen
df -h
du -sh /*
# Speichernutzung prüfen
free -h
cat /proc/meminfo
# Laufende Dienste prüfen
systemctl status dienst_name
systemctl list-units --type=service
# Paketlisten aktualisieren (Ubuntu/Debian)
sudo apt update && sudo apt upgrade
# Nach installierten Paketen suchen
dpkg -l | grep paket_name
```

## Relevante Links

- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Spickzettel</router-link>
- <router-link to="/git">Git Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>
- <router-link to="/ansible">Ansible Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>

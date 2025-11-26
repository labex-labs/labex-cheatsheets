---
title: 'Git Spickzettel'
description: 'Lernen Sie Git mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/git-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Git Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/git">Git mit praktischen Übungen lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie die Git-Versionskontrolle durch praktische Übungen und reale Szenarien. LabEx bietet umfassende Git-Kurse, die wesentliche Befehle, Branching-Strategien, Kollaborations-Workflows und fortgeschrittene Techniken abdecken. Lernen Sie, Code-Repositories zu verwalten, Konflikte zu lösen und effektiv mit Teams mithilfe von Git und GitHub zusammenzuarbeiten.
</base-disclaimer-content>
</base-disclaimer>

## Repository-Einrichtung & Konfiguration

### Repository initialisieren: `git init`

Erstellt ein neues Git-Repository im aktuellen Verzeichnis.

```bash
# Neues Repository initialisieren
git init
# In neuem Verzeichnis initialisieren
git init projekt-name
# Bare Repository initialisieren (kein Arbeitsverzeichnis)
git init --bare
# Benutzerdefiniertes Vorlagenverzeichnis verwenden
git init --template=path
```

### Repository klonen: `git clone`

Erstellt eine lokale Kopie eines Remote-Repositories.

```bash
# Klonen via HTTPS
git clone https://github.com/user/repo.git
# Klonen via SSH
git clone git@github.com:user/repo.git
# Klonen mit benutzerdefiniertem Namen
git clone repo.git lokaler-name
# Flaches Klonen (nur letzter Commit)
git clone --depth 1 repo.git
```

### Globale Konfiguration: `git config`

Einrichten von Benutzerinformationen und Präferenzen global.

```bash
git config --global user.name "Ihr Name"
git config --global user.email "ihre.email@example.com"
git config --global init.defaultBranch main
# Alle Konfigurationseinstellungen anzeigen
git config --list
```

### Lokale Konfiguration: `git config --local`

Festlegen der Repository-spezifischen Konfiguration.

```bash
# Nur für das aktuelle Repo festlegen
git config user.name "Projektname"
# Projekt-spezifische E-Mail
git config user.email "projekt@example.com"
```

### Remote-Verwaltung: `git remote`

Verwalten von Verbindungen zu Remote-Repositories.

```bash
# Remote hinzufügen
git remote add origin https://github.com/user/repo.git
# Alle Remotes mit URLs auflisten
git remote -v
# Detaillierte Remote-Infos anzeigen
git remote show origin
# Remote umbenennen
git remote rename origin upstream
# Remote entfernen
git remote remove upstream
```

### Anmeldeinformationsspeicherung: `git config credential`

Speichern von Authentifizierungsdaten, um wiederholtes Anmelden zu vermeiden.

```bash
# Für 15 Minuten cachen
git config --global credential.helper cache
# Permanent speichern
git config --global credential.helper store
# Für 1 Stunde cachen
git config --global credential.helper 'cache --timeout=3600'
```

## Repository-Informationen & Status

### Status prüfen: `git status`

Anzeigen des aktuellen Zustands des Arbeitsverzeichnisses und des Staging-Bereichs.

```bash
# Vollständige Statusinformationen
git status
# Kurzes Statusformat
git status -s
# Maschinenlesbares Format
git status --porcelain
# Ignorierte Dateien ebenfalls anzeigen
git status --ignored
```

### Unterschiede anzeigen: `git diff`

Anzeigen von Änderungen zwischen verschiedenen Zuständen des Repositorys.

```bash
# Änderungen im Arbeitsverzeichnis vs. Staging
git diff
# Änderungen im Staging vs. letzter Commit
git diff --staged
# Alle nicht festgeschriebenen Änderungen
git diff HEAD
# Änderungen in spezifischer Datei
git diff datei.txt
```

### Verlauf anzeigen: `git log`

Anzeigen der Commit-Historie und der Repository-Zeitleiste.

```bash
# Vollständige Commit-Historie
git log
# Kondensiertes Einzeilenformat
git log --oneline
# Letzte 5 Commits anzeigen
git log -5
# Visueller Branch-Graph
git log --graph --all
```

## Änderungen stagen & committen

### Dateien stagen: `git add`

Hinzufügen von Änderungen zum Staging-Bereich für den nächsten Commit.

```bash
# Spezifische Datei stagen
git add datei.txt
# Alle Änderungen im aktuellen Verzeichnis stagen
git add .
# Alle Änderungen stagen (einschließlich Löschungen)
git add -A
# Alle JavaScript-Dateien stagen
git add *.js
# Interaktives Staging (Patch-Modus)
git add -p
```

### Änderungen committen: `git commit`

Speichern von gestagten Änderungen im Repository mit einer beschreibenden Nachricht.

```bash
# Commit mit Nachricht
git commit -m "Füge Benutzerauthentifizierung hinzu"
# Modifizierte Dateien stagen und committen
git commit -a -m "Dokumentation aktualisieren"
# Letzten Commit modifizieren
git commit --amend
# Amend ohne Nachrichtenänderung
git commit --no-edit --amend
```

### Dateien entstagen: `git reset`

Entfernen von Dateien aus dem Staging-Bereich oder Rückgängigmachen von Commits.

```bash
# Spezifische Datei entstagen
git reset datei.txt
# Alle Dateien entstagen
git reset
# Letzten Commit rückgängig machen, Änderungen gestaged lassen
git reset --soft HEAD~1
# Letzten Commit rückgängig machen, Änderungen verwerfen
git reset --hard HEAD~1
```

### Änderungen verwerfen: `git checkout` / `git restore`

Änderungen im Arbeitsverzeichnis auf den letzten Commit-Zustand zurücksetzen.

```bash
# Änderungen in Datei verwerfen (alte Syntax)
git checkout -- datei.txt
# Änderungen in Datei verwerfen (neue Syntax)
git restore datei.txt
# Datei entstagen (neue Syntax)
git restore --staged datei.txt
# Alle nicht festgeschriebenen Änderungen verwerfen
git checkout .
```

## Branch-Operationen

### Branches auflisten: `git branch`

Anzeigen und Verwalten von Repository-Branches.

```bash
# Lokale Branches auflisten
git branch
# Alle Branches auflisten (lokal und remote)
git branch -a
# Nur Remote-Branches auflisten
git branch -r
# Letzten Commit auf jedem Branch anzeigen
git branch -v
```

### Erstellen & Wechseln: `git checkout` / `git switch`

Erstellen neuer Branches und Wechseln zwischen ihnen.

```bash
# Neuen Branch erstellen und wechseln
git checkout -b feature-branch
# Neuen Branch erstellen und wechseln (neue Syntax)
git switch -c feature-branch
# Zu existierendem Branch wechseln
git checkout main
# Zu existierendem Branch wechseln (neue Syntax)
git switch main
```

### Branches mergen: `git merge`

Kombinieren von Änderungen aus verschiedenen Branches.

```bash
# feature-branch in den aktuellen Branch mergen
git merge feature-branch
# Merge-Commit erzwingen
git merge --no-ff feature-branch
# Commits vor dem Mergen zusammenfassen (Squash)
git merge --squash feature-branch
```

### Branches löschen: `git branch -d`

Entfernen von Branches, die nicht mehr benötigt werden.

```bash
# Gemergten Branch löschen
git branch -d feature-branch
# Unvermergten Branch erzwingend löschen
git branch -D feature-branch
# Remote-Branch löschen
git push origin --delete feature-branch
```

## Remote Repository Operationen

### Updates holen: `git fetch`

Herunterladen von Änderungen vom Remote-Repository ohne Mergen.

```bash
# Vom Standard-Remote holen
git fetch
# Von spezifischem Remote holen
git fetch origin
# Von allen Remotes holen
git fetch --all
# Spezifischen Branch holen
git fetch origin main
```

### Änderungen ziehen: `git pull`

Herunterladen und Mergen von Änderungen vom Remote-Repository.

```bash
# Vom verfolgten Branch ziehen
git pull
# Von spezifischem Remote-Branch ziehen
git pull origin main
# Ziehen mit Rebase statt Merge
git pull --rebase
# Nur Fast-Forward, keine Merge-Commits
git pull --ff-only
```

### Änderungen pushen: `git push`

Hochladen lokaler Commits zum Remote-Repository.

```bash
# Zum verfolgten Branch pushen
git push
# Zu spezifischem Remote-Branch pushen
git push origin main
# Pushen und Upstream-Tracking einrichten
git push -u origin feature
# Erzwingendes Pushen mit Sicherheitsprüfung
git push --force-with-lease
```

### Remote-Branches verfolgen: `git branch --track`

Einrichten der Verfolgung zwischen lokalen und Remote-Branches.

```bash
# Tracking einrichten
git branch --set-upstream-to=origin/main main
# Remote-Branch verfolgen
git checkout -b lokaler-branch origin/remote-branch
```

## Stashing & Temporäre Speicherung

### Änderungen stashen: `git stash`

Temporäres Speichern von nicht festgeschriebenen Änderungen zur späteren Verwendung.

```bash
# Aktuelle Änderungen stashen
git stash
# Stash mit Nachricht speichern
git stash save "Arbeit an Feature X im Gange"
# Untracked Dateien einschließen
git stash -u
# Nur ungestagte Änderungen stashen
git stash --keep-index
```

### Stashes auflisten: `git stash list`

Anzeigen aller gespeicherten Stashes.

```bash
# Alle Stashes anzeigen
git stash list
# Änderungen im neuesten Stash anzeigen
git stash show
# Änderungen in spezifischem Stash anzeigen
git stash show stash@{1}
```

### Stashes anwenden: `git stash apply`

Wiederherstellen zuvor gestasher Änderungen.

```bash
# Neuesten Stash anwenden
git stash apply
# Spezifischen Stash anwenden
git stash apply stash@{1}
# Anwenden und neuesten Stash entfernen
git stash pop
# Neuesten Stash löschen
git stash drop
# Branch aus Stash erstellen
git stash branch neuer-branch stash@{1}
# Alle Stashes löschen
git stash clear
```

## Historie & Log-Analyse

### Commit-Historie anzeigen: `git log`

Untersuchen der Repository-Historie mit verschiedenen Formatierungsoptionen.

```bash
# Visuelle Branch-Historie
git log --oneline --graph --all
# Commits eines bestimmten Autors
git log --author="Max Mustermann"
# Kürzliche Commits
git log --since="2 weeks ago"
# Commit-Nachrichten durchsuchen
git log --grep="Bugfix"
```

### Blame & Annotation: `git blame`

Sehen, wer zuletzt welche Zeile einer Datei geändert hat.

```bash
# Zeilenweise Autorenschaft anzeigen
git blame datei.txt
# Spezifische Zeilen anzeigen
git blame -L 10,20 datei.txt
# Alternative zu blame
git annotate datei.txt
```

### Repository durchsuchen: `git grep`

Suchen nach Textmustern in der gesamten Repository-Historie.

```bash
# Nach Text in verfolgten Dateien suchen
git grep "funktion"
# Suche mit Zeilennummern
git grep -n "TODO"
# Suche in gestagten Dateien
git grep --cached "fehler"
```

### Commit-Details anzeigen: `git show`

Anzeigen detaillierter Informationen zu spezifischen Commits.

```bash
# Neueste Commit-Details anzeigen
git show
# Vorherigen Commit anzeigen
git show HEAD~1
# Spezifischen Commit nach Hash anzeigen
git show abc123
# Commit mit Datei-Statistiken anzeigen
git show --stat
```

## Änderungen rückgängig machen & Historie bearbeiten

### Commits rückgängig machen: `git revert`

Erstellen neuer Commits, die frühere Änderungen sicher rückgängig machen.

```bash
# Letzten Commit rückgängig machen
git revert HEAD
# Spezifischen Commit rückgängig machen
git revert abc123
# Commit-Bereich rückgängig machen
git revert HEAD~3..HEAD
# Rückgängig machen ohne automatischen Commit
git revert --no-commit abc123
```

### Historie zurücksetzen: `git reset`

Bewegen des Branch-Zeigers und optionales Ändern des Arbeitsverzeichnisses.

```bash
# Commit rückgängig machen, Änderungen gestaged lassen
git reset --soft HEAD~1
# Commit und Staging rückgängig machen
git reset --mixed HEAD~1
# Commit, Staging und Arbeitsverzeichnis rückgängig machen
git reset --hard HEAD~1
```

### Interaktives Rebase: `git rebase -i`

Interaktives Bearbeiten, Neuordnen oder Zusammenfassen von Commits.

```bash
# Interaktives Rebase der letzten 3 Commits
git rebase -i HEAD~3
# Aktuellen Branch auf main rebasen
git rebase -i main
# Nach Behebung von Konflikten fortfahren
git rebase --continue
# Rebase-Vorgang abbrechen
git rebase --abort
```

### Cherry-pick: `git cherry-pick`

Anwenden spezifischer Commits von anderen Branches.

```bash
# Spezifischen Commit auf aktuellen Branch anwenden
git cherry-pick abc123
# Commit-Bereich anwenden
git cherry-pick abc123..def456
# Cherry-pick ohne Commit
git cherry-pick -n abc123
```

## Konfliktlösung

### Merge-Konflikte: Lösungsprozess

Schritte zur Behebung von Konflikten während Merge-Vorgängen.

```bash
# Konfliktbehaftete Dateien prüfen
git status
# Konflikt als gelöst markieren
git add gelöste-datei.txt
# Merge abschließen
git commit
# Merge abbrechen und zum vorherigen Zustand zurückkehren
git merge --abort
```

### Merge-Tools: `git mergetool`

Starten externer Tools zur visuellen Behebung von Konflikten.

```bash
# Standard-Merge-Tool starten
git mergetool
# Standard-Merge-Tool festlegen
git config --global merge.tool vimdiff
# Spezifisches Tool für diesen Merge verwenden
git mergetool --tool=meld
```

### Konfliktmarkierungen: Format verstehen

Interpretation der Konfliktmarkierungen von Git in Dateien.

```text
<<<<<<< HEAD
Inhalt des aktuellen Branches
=======
Eingehender Inhalt des anderen Branches
>>>>>>> feature-branch
```

Nachdem die Datei zur Lösung bearbeitet wurde:

```bash
git add konfliktbehaftete-datei.txt
git commit
```

### Diff-Tools: `git difftool`

Verwendung externer Diff-Tools zur besseren Visualisierung von Konflikten.

```bash
# Diff-Tool für Änderungen starten
git difftool
# Standard-Diff-Tool festlegen
git config --global diff.tool vimdiff
```

## Tagging & Releases

### Tags erstellen: `git tag`

Markieren spezifischer Commits mit Versionsbezeichnungen.

```bash
# Leichtgewichtigen Tag erstellen
git tag v1.0
# Annotierten Tag erstellen
git tag -a v1.0 -m "Version 1.0 Release"
# Spezifischen Commit taggen
git tag -a v1.0 abc123
# Signierten Tag erstellen
git tag -s v1.0
```

### Tags auflisten & anzeigen: `git tag -l`

Anzeigen vorhandener Tags und ihrer Informationen.

```bash
# Alle Tags auflisten
git tag
# Tags anzeigen, die einem Muster entsprechen
git tag -l "v1.*"
# Tag-Details anzeigen
git show v1.0
```

### Tags pushen: `git push --tags`

Teilen von Tags mit Remote-Repositories.

```bash
# Spezifischen Tag pushen
git push origin v1.0
# Alle Tags pushen
git push --tags
# Alle Tags zu spezifischem Remote pushen
git push origin --tags
```

### Tags löschen: `git tag -d`

Entfernen von Tags aus lokalen und Remote-Repositories.

```bash
# Lokalen Tag löschen
git tag -d v1.0
# Remote-Tag löschen
git push origin --delete tag v1.0
# Alternative Lösch-Syntax
git push origin :refs/tags/v1.0
```

## Git Konfiguration & Aliase

### Konfiguration anzeigen: `git config --list`

Anzeigen der aktuellen Git-Konfigurationseinstellungen.

```bash
# Alle Konfigurationseinstellungen anzeigen
git config --list
# Nur globale Einstellungen anzeigen
git config --global --list
# Nur Repository-spezifische Einstellungen anzeigen
git config --local --list
# Spezifische Einstellung anzeigen
git config user.name
```

### Aliase erstellen: `git config alias`

Einrichten von Abkürzungen für häufig verwendete Befehle.

```bash
# git st = git status
git config --global alias.st status
# git co = git checkout
git config --global alias.co checkout
# git br = git branch
git config --global alias.br branch
# git ci = git commit
git config --global alias.ci commit
```

### Erweiterte Aliase: Komplexe Befehle

Erstellen von Aliasen für komplexe Befehlskombinationen.

```bash
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.unstage "reset HEAD --"
git config --global alias.last "log -1 HEAD"
git config --global alias.visual "!gitk"
```

### Editor-Konfiguration: `git config core.editor`

Festlegen des bevorzugten Texteditors für Commit-Nachrichten und Konflikte.

```bash
# VS Code
git config --global core.editor "code --wait"
# Vim
git config --global core.editor "vim"
# Nano
git config --global core.editor "nano"
```

## Performance & Optimierung

### Repository-Wartung: `git gc`

Optimieren der Repository-Leistung und Speicherung.

```bash
# Standard-Garbage Collection
git gc
# Gründlichere Optimierung
git gc --aggressive
# Nur bei Bedarf ausführen
git gc --auto
# Repository-Integrität prüfen
git fsck
```

### Umgang mit großen Dateien: `git lfs`

Effiziente Verwaltung großer Binärdateien mit Git LFS.

```bash
# LFS im Repository installieren
git lfs install
# PDF-Dateien mit LFS verfolgen
git lfs track "*.pdf"
# Von LFS verfolgte Dateien auflisten
git lfs ls-files
# Bestehende Dateien migrieren
git lfs migrate import --include="*.zip"
```

### Flache Klone: Reduzierung der Repository-Größe

Repositorys mit begrenzter Historie für schnellere Operationen klonen.

```bash
# Nur letzter Commit
git clone --depth 1 https://github.com/user/repo.git
# Letzte 10 Commits
git clone --depth 10 repo.git
# Flachen Klon in vollen Klon umwandeln
git fetch --unshallow
```

### Sparse Checkout: Arbeiten mit Unterverzeichnissen

Nur bestimmte Teile großer Repositorys auschecken.

```bash
git config core.sparseCheckout true
echo "src/*" > .git/info/sparse-checkout
# Sparse Checkout anwenden
git read-tree -m -u HEAD
```

## Git Installation & Einrichtung

### Paketmanager: `apt`, `yum`, `brew`

Installieren von Git mithilfe von System-Paketmanagern.

```bash
# Ubuntu/Debian
sudo apt install git
# CentOS/RHEL
sudo yum install git
# macOS mit Homebrew
brew install git
# Windows mit winget
winget install Git.Git
```

### Herunterladen & Installieren: Offizielle Installer

Verwendung offizieller Git-Installer für Ihre Plattform.

```bash
# Herunterladen von https://git-scm.com/downloads
# Installation überprüfen
git --version
# Pfad zur Git-Ausführungsdatei anzeigen
which git
```

### Ersteinrichtung: Benutzerkonfiguration

Git mit Ihrer Identität für Commits konfigurieren.

```bash
git config --global user.name "Ihr Vollständiger Name"
git config --global user.email "ihre.email@example.com"
git config --global init.defaultBranch main
# Merge-Verhalten festlegen
git config --global pull.rebase false
```

## Git Workflows & Best Practices

### Feature Branch Workflow

Standard-Workflow für die Feature-Entwicklung mit isolierten Branches.

```bash
# Vom main Branch starten
git checkout main
# Neueste Änderungen holen
git pull origin main
# Feature Branch erstellen
git checkout -b feature/user-auth
# ... Änderungen vornehmen und committen ...
# Feature Branch pushen
git push -u origin feature/user-auth
# ... Pull Request erstellen ...
```

### Git Flow: Strukturiertes Branching-Modell

Systematischer Ansatz mit dedizierten Branches für verschiedene Zwecke.

```bash
# Git Flow initialisieren
git flow init
# Feature starten
git flow feature start neues-feature
# Feature beenden
git flow feature finish neues-feature
# Release Branch starten
git flow release start 1.0.0
```

### Commit Message Konventionen

Befolgen Sie das Conventional Commit Format für eine klare Projekthistorie.

```bash
# Format: <typ>(<umfang>): <betreff>
git commit -m "feat(auth): Benutzer-Login-Funktionalität hinzufügen"
git commit -m "fix(api): Null-Pointer-Exception beheben"
git commit -m "docs(readme): Installationsanweisungen aktualisieren"
git commit -m "refactor(utils): Datumsformatierung vereinfachen"
```

### Atomare Commits: Best Practices

Erstellen Sie fokussierte Commits mit einem einzigen Zweck für eine bessere Historie.

```bash
# Änderungen interaktiv stagen
git add -p
# Spezifische Änderung
git commit -m "Validierung zum E-Mail-Feld hinzufügen"
# Vermeiden: git commit -m "Kram beheben" # Zu vage
# Gut:  git commit -m "Regex-Muster für E-Mail-Validierung korrigieren"
```

## Fehlerbehebung & Wiederherstellung

### Reflog: Wiederherstellungswerkzeug

Verwenden Sie das Referenzprotokoll von Git, um verlorene Commits wiederherzustellen.

```bash
# Referenzprotokoll anzeigen
git reflog
# HEAD-Bewegungen anzeigen
git reflog show HEAD
# Verlorenen Commit wiederherstellen
git checkout abc123
# Branch aus verlorenem Commit erstellen
git branch recovery-branch abc123
```

### Beschädigtes Repository: Reparatur

Beheben von Repository-Beschädigungen und Integritätsproblemen.

```bash
# Repository-Integrität prüfen
git fsck --full
# Aggressive Bereinigung
git gc --aggressive --prune=now
# Index neu erstellen, falls beschädigt
rm .git/index; git reset
```

### Authentifizierungsprobleme

Beheben häufiger Authentifizierungs- und Berechtigungsprobleme.

```bash
# Token verwenden
git remote set-url origin https://token@github.com/user/repo.git
# SSH-Schlüssel zum Agenten hinzufügen
ssh-add ~/.ssh/id_rsa
# Windows Credential Manager
git config --global credential.helper manager-core
```

### Performance-Probleme: Debugging

Identifizieren und Beheben von Repository-Performance-Problemen.

```bash
# Repository-Größe anzeigen
git count-objects -vH
# Gesamtzahl der Commits zählen
git log --oneline | wc -l
# Anzahl der Branches zählen
git for-each-ref --format='%(refname:short)' | wc -l
```

## Relevante Links

- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>
- <router-link to="/ansible">Ansible Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>
- <router-link to="/javascript">JavaScript Spickzettel</router-link>

---
title: 'Git Spickzettel | LabEx'
description: 'Git-Versionskontrolle mit diesem umfassenden Spickzettel lernen. Schnelle Referenz für Git-Befehle, Branching, Merging, Rebasing, GitHub-Workflows und kollaborative Entwicklung.'
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
git init --template=pfad
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

Richtet Benutzerinformationen und Präferenzen global ein.

```bash
git config --global user.name "Ihr Name"
git config --global user.email "ihre.email@example.com"
git config --global init.defaultBranch main
# Alle Konfigurationseinstellungen anzeigen
git config --list
```

### Lokale Konfiguration: `git config --local`

Legt Repository-spezifische Konfigurationen fest.

```bash
# Für das aktuelle Repo festlegen
git config user.name "Projektname"
# Projekt-spezifische E-Mail
git config user.email "projekt@example.com"
```

### Remote-Verwaltung: `git remote`

Verwaltet Verbindungen zu Remote-Repositories.

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

### Anmeldeinformationsspeicher: `git config credential`

Speichert Authentifizierungsdaten, um wiederholtes Anmelden zu vermeiden.

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

Zeigt den aktuellen Zustand des Arbeitsverzeichnisses und der Staging Area an.

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

Zeigt Änderungen zwischen verschiedenen Zuständen des Repositories an.

```bash
# Änderungen im Arbeitsverzeichnis vs. Staging Area
git diff
# Änderungen in der Staging Area vs. letzter Commit
git diff --staged
# Alle unvermerkten Änderungen
git diff HEAD
# Änderungen in spezifischer Datei
git diff datei.txt
```

### Verlauf anzeigen: `git log`

Zeigt die Commit-Historie und die Timeline des Repositories an.

```bash
# Voller Commit-Verlauf
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

Fügt Änderungen zur Staging Area für den nächsten Commit hinzu.

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

Speichert gestagte Änderungen mit einer beschreibenden Nachricht im Repository.

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

<BaseQuiz id="git-commit-1" correct="A">
  <template #question>
    Was bewirkt `git commit -m "Nachricht"`?
  </template>
  
  <BaseQuizOption value="A" correct>Erstellt einen neuen Commit mit der angegebenen Nachricht</BaseQuizOption>
  <BaseQuizOption value="B">Staged alle Änderungen im Arbeitsverzeichnis</BaseQuizOption>
  <BaseQuizOption value="C">Pusht Änderungen zum Remote-Repository</BaseQuizOption>
  <BaseQuizOption value="D">Erstellt einen neuen Branch</BaseQuizOption>
  
  <BaseQuizAnswer>
    Der Befehl `git commit -m` erstellt einen neuen Commit mit gestagten Änderungen und speichert ihn mit der angegebenen Nachricht in der Repository-Historie. Er pusht nicht zum Remote und erstellt keine Branches.
  </BaseQuizAnswer>
</BaseQuiz>

### Dateien entstagen: `git reset`

Entfernt Dateien aus der Staging Area oder macht Commits rückgängig.

```bash
# Spezifische Datei entstagen
git reset datei.txt
# Alle Dateien entstagen
git reset
# Letzten Commit rückgängig machen, Änderungen gestaged behalten
git reset --soft HEAD~1
# Letzten Commit rückgängig machen, Änderungen verwerfen
git reset --hard HEAD~1
```

### Änderungen verwerfen: `git checkout` / `git restore`

Stellt Änderungen im Arbeitsverzeichnis auf den letzten Commit-Zustand zurück.

```bash
# Änderungen in Datei verwerfen (alte Syntax)
git checkout -- datei.txt
# Änderungen in Datei verwerfen (neue Syntax)
git restore datei.txt
# Datei entstagen (neue Syntax)
git restore --staged datei.txt
# Alle unvermerkten Änderungen verwerfen
git checkout .
```

## Branch-Operationen

### Branches auflisten: `git branch`

Zeigt Branches an und verwaltet sie.

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

Erstellt neue Branches und wechselt zwischen ihnen.

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

<BaseQuiz id="git-branch-1" correct="B">
  <template #question>
    Was bewirkt `git checkout -b feature-branch`?
  </template>
  
  <BaseQuizOption value="A">Löscht den feature-branch</BaseQuizOption>
  <BaseQuizOption value="B" correct>Erstellt einen neuen Branch namens feature-branch und wechselt dorthin</BaseQuizOption>
  <BaseQuizOption value="C">Führt feature-branch in den aktuellen Branch zusammen</BaseQuizOption>
  <BaseQuizOption value="D">Zeigt die Commit-Historie von feature-branch an</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das Flag `-b` erstellt einen neuen Branch, und `checkout` wechselt dorthin. Dieser Befehl kombiniert beide Operationen: Erstellen des Branches und sofortiges Wechseln dorthin.
  </BaseQuizAnswer>
</BaseQuiz>

### Branches zusammenführen: `git merge`

Kombiniert Änderungen aus verschiedenen Branches.

```bash
# feature-branch in den aktuellen Branch mergen
git merge feature-branch
# Merge-Commit erzwingen
git merge --no-ff feature-branch
# Commits vor dem Mergen zusammenfassen (Squash)
git merge --squash feature-branch
```

### Branches löschen: `git branch -d`

Entfernt Branches, die nicht mehr benötigt werden.

```bash
# Gemergten Branch löschen
git branch -d feature-branch
# Nicht gemergten Branch zwangsweise löschen
git branch -D feature-branch
# Remote-Branch löschen
git push origin --delete feature-branch
```

## Remote-Repository-Operationen

### Updates holen: `git fetch`

Lädt Änderungen vom Remote-Repository herunter, ohne sie zusammenzuführen.

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

Lädt Änderungen vom Remote-Repository herunter und führt sie zusammen.

```bash
# Vom verfolgten Branch ziehen
git pull
# Von spezifischem Remote-Branch ziehen
git pull origin main
# Mit Rebase statt Merge ziehen
git pull --rebase
# Nur Fast-Forward, keine Merge-Commits
git pull --ff-only
```

<BaseQuiz id="git-pull-1" correct="C">
  <template #question>
    Was ist der Unterschied zwischen `git fetch` und `git pull`?
  </template>
  
  <BaseQuizOption value="A">Es gibt keinen Unterschied; sie tun dasselbe</BaseQuizOption>
  <BaseQuizOption value="B">git fetch pusht Änderungen, git pull lädt Änderungen herunter</BaseQuizOption>
  <BaseQuizOption value="C" correct>git fetch lädt Änderungen herunter, ohne sie zusammenzuführen, git pull lädt herunter und führt sie zusammen</BaseQuizOption>
  <BaseQuizOption value="D">git fetch funktioniert mit lokalen Repos, git pull funktioniert mit Remote-Repos</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git fetch` lädt Änderungen vom Remote-Repository herunter, führt sie aber nicht in Ihren aktuellen Branch zusammen. `git pull` führt beide Operationen aus: Es holt die Änderungen und führt sie dann in Ihren aktuellen Branch zusammen.
  </BaseQuizAnswer>
</BaseQuiz>

### Änderungen pushen: `git push`

Lädt lokale Commits in das Remote-Repository hoch.

```bash
# Zum verfolgten Branch pushen
git push
# Zu spezifischem Remote-Branch pushen
git push origin main
# Pushen und Upstream-Tracking einrichten
git push -u origin feature
# Sicher erzwingen (Force Push)
git push --force-with-lease
```

<BaseQuiz id="git-push-1" correct="D">
  <template #question>
    Was bewirkt `git push -u origin feature`?
  </template>
  
  <BaseQuizOption value="A">Löscht den feature-Branch vom Remote</BaseQuizOption>
  <BaseQuizOption value="B">Zieht Änderungen vom feature-Branch</BaseQuizOption>
  <BaseQuizOption value="C">Führt den feature-Branch in main zusammen</BaseQuizOption>
  <BaseQuizOption value="D" correct>Pusht den feature-Branch zu origin und richtet das Tracking ein</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das Flag `-u` (oder `--set-upstream`) pusht den Branch zum Remote-Repository und richtet das Tracking ein, sodass zukünftige `git push`- und `git pull`-Befehle wissen, welchen Remote-Branch sie verwenden sollen.
  </BaseQuizAnswer>
</BaseQuiz>

### Remote-Branches verfolgen: `git branch --track`

Richtet die Verfolgung zwischen lokalen und Remote-Branches ein.

```bash
# Tracking einrichten
git branch --set-upstream-to=origin/main main
# Remote-Branch verfolgen
git checkout -b lokaler-branch origin/remote-branch
```

## Stashing & Temporäre Speicherung

### Änderungen stashen: `git stash`

Speichert unvermerkte Änderungen vorübergehend zur späteren Verwendung.

```bash
# Aktuelle Änderungen stashen
git stash
# Stash mit Nachricht
git stash save "Arbeit an Feature X in Bearbeitung"
# Untracked Dateien einschließen
git stash -u
# Nur ungestagte Änderungen stashen
git stash --keep-index
```

### Stashes auflisten: `git stash list`

Zeigt alle gespeicherten Stashes an.

```bash
# Alle Stashes anzeigen
git stash list
# Änderungen im neuesten Stash anzeigen
git stash show
# Änderungen in spezifischem Stash anzeigen
git stash show stash@{1}
```

### Stashes anwenden: `git stash apply`

Stellt zuvor gestashte Änderungen wieder her.

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

<BaseQuiz id="git-stash-1" correct="B">
  <template #question>
    Was ist der Unterschied zwischen `git stash apply` und `git stash pop`?
  </template>
  
  <BaseQuizOption value="A">git stash apply entfernt den Stash, git stash pop behält ihn</BaseQuizOption>
  <BaseQuizOption value="B" correct>git stash apply behält den Stash, git stash pop entfernt ihn nach dem Anwenden</BaseQuizOption>
  <BaseQuizOption value="C">git stash apply funktioniert mit Remote-Repos, git stash pop funktioniert lokal</BaseQuizOption>
  <BaseQuizOption value="D">Es gibt keinen Unterschied; sie tun dasselbe</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git stash apply` stellt die gestashten Änderungen wieder her, behält den Stash aber in der Stash-Liste. `git stash pop` wendet den Stash an und entfernt ihn dann aus der Stash-Liste, was nützlich ist, wenn Sie den Stash nicht mehr benötigen.
  </BaseQuizAnswer>
</BaseQuiz>

## Historie & Log-Analyse

### Commit-Historie anzeigen: `git log`

Untersuchen Sie die Repository-Historie mit verschiedenen Formatierungsoptionen.

```bash
# Visuelle Branch-Historie
git log --oneline --graph --all
# Commits eines bestimmten Autors
git log --author="Max Mustermann"
# Neueste Commits
git log --since="2 weeks ago"
# Commit-Nachrichten durchsuchen
git log --grep="bug fix"
```

### Blame & Annotation: `git blame`

Zeigt an, wer zuletzt welche Zeile einer Datei geändert hat.

```bash
# Zeilenweise Autorenschaft anzeigen
git blame datei.txt
# Spezifische Zeilen anzeigen
git blame -L 10,20 datei.txt
# Alternative zu blame
git annotate datei.txt
```

### Repository durchsuchen: `git grep`

Sucht nach Textmustern im gesamten Repository-Verlauf.

```bash
# Nach Text in verfolgten Dateien suchen
git grep "funktion"
# Suche mit Zeilennummern
git grep -n "TODO"
# Suche in gestagten Dateien
git grep --cached "bug"
```

### Commit-Details anzeigen: `git show`

Zeigt detaillierte Informationen zu spezifischen Commits an.

```bash
# Details des neuesten Commits anzeigen
git show
# Vorherigen Commit anzeigen
git show HEAD~1
# Spezifischen Commit anhand des Hashs anzeigen
git show abc123
# Commit mit Statistik anzeigen
git show --stat
```

## Änderungen rückgängig machen & Historie bearbeiten

### Commits rückgängig machen: `git revert`

Erstellt neue Commits, die frühere Änderungen sicher rückgängig machen.

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

Bewegt den Branch-Zeiger und modifiziert optional das Arbeitsverzeichnis.

```bash
# Commit rückgängig machen, Änderungen gestaged behalten
git reset --soft HEAD~1
# Commit und Staging rückgängig machen
git reset --mixed HEAD~1
# Commit, Staging und Arbeitsverzeichnis rückgängig machen
git reset --hard HEAD~1
```

### Interaktives Rebase: `git rebase -i`

Commits interaktiv bearbeiten, neu anordnen oder zusammenfassen (squash).

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

Wendet spezifische Commits von anderen Branches an.

```bash
# Spezifischen Commit auf den aktuellen Branch anwenden
git cherry-pick abc123
# Commit-Bereich anwenden
git cherry-pick abc123..def456
# Cherry-pick ohne Commit
git cherry-pick -n abc123
```

## Konfliktlösung

### Merge-Konflikte: Lösungsprozess

Schritte zur Behebung von Konflikten während Merge-Operationen.

```bash
# Konfliktdateien prüfen
git status
# Konflikt als gelöst markieren
git add gelöste-datei.txt
# Merge abschließen
git commit
# Merge abbrechen und zum vorherigen Zustand zurückkehren
git merge --abort
```

### Merge-Tools: `git mergetool`

Startet externe Tools zur visuellen Konfliktlösung.

```bash
# Standard-Merge-Tool starten
git mergetool
# Standard-Merge-Tool festlegen
git config --global merge.tool vimdiff
# Spezifisches Tool für diesen Merge verwenden
git mergetool --tool=meld
```

### Konfliktmarker: Das Format verstehen

Interpretation der Konfliktmarker von Git in Dateien.

```text
<<<<<<< HEAD
Inhalt des aktuellen Branches
=======
Inhalt des eingehenden Branches
>>>>>>> feature-branch
```

Nachdem die Datei zur Lösung bearbeitet wurde:

```bash
git add konfliktbehaftete-datei.txt
git commit
```

### Diff-Tools: `git difftool`

Verwendet externe Diff-Tools zur besseren Visualisierung von Konflikten.

```bash
# Diff-Tool für Änderungen starten
git difftool
# Standard-Diff-Tool festlegen
git config --global diff.tool vimdiff
```

## Tagging & Releases

### Tags erstellen: `git tag`

Markiert spezifische Commits mit Versionsbezeichnungen.

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

Zeigt vorhandene Tags und deren Informationen an.

```bash
# Alle Tags auflisten
git tag
# Tags anzeigen, die einem Muster entsprechen
git tag -l "v1.*"
# Tag-Details anzeigen
git show v1.0
```

### Tags pushen: `git push --tags`

Teilt Tags mit Remote-Repositories.

```bash
# Spezifischen Tag pushen
git push origin v1.0
# Alle Tags pushen
git push --tags
# Alle Tags zu einem spezifischen Remote pushen
git push origin --tags
```

### Tags löschen: `git tag -d`

Entfernt Tags aus lokalen und Remote-Repositories.

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

Zeigt die aktuellen Git-Konfigurationseinstellungen an.

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

Richtet Abkürzungen für häufig verwendete Befehle ein.

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

Erstellt Aliase für komplexe Befehlskombinationen.

```bash
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.unstage "reset HEAD --"
git config --global alias.last "log -1 HEAD"
git config --global alias.visual "!gitk"
```

### Editor-Konfiguration: `git config core.editor`

Legt den bevorzugten Texteditor für Commit-Nachrichten und Konflikte fest.

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

Optimiert die Repository-Leistung und Speicherung.

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

Verwaltet große Binärdateien effizient mit Git LFS.

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

Klone Repositories mit begrenzter Historie für schnellere Operationen.

```bash
# Nur letzter Commit
git clone --depth 1 https://github.com/user/repo.git
# Letzte 10 Commits
git clone --depth 10 repo.git
# Flaches Klon in volles Klon umwandeln
git fetch --unshallow
```

### Sparse Checkout: Arbeiten mit Unterverzeichnissen

Prüft nur bestimmte Teile großer Repositories aus.

```bash
git config core.sparseCheckout true
echo "src/*" > .git/info/sparse-checkout
# Sparse Checkout anwenden
git read-tree -m -u HEAD
```

## Git Installation & Einrichtung

### Paketmanager: `apt`, `yum`, `brew`

Installiert Git mithilfe von System-Paketmanagern.

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

Verwendet offizielle Git-Installer für Ihre Plattform.

```bash
# Herunterladen von https://git-scm.com/downloads
# Installation überprüfen
git --version
# Pfad zur Git-Ausführungsdatei anzeigen
which git
```

### Ersteinrichtung: Benutzerkonfiguration

Konfiguriert Git mit Ihrer Identität für Commits.

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

### Commit-Nachrichten-Konventionen

Folgen Sie dem konventionellen Commit-Format für eine klare Projekt-Historie.

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

Behebt Repository-Beschädigungen und Integritätsprobleme.

```bash
# Repository-Integrität prüfen
git fsck --full
# Aggressives Aufräumen
git gc --aggressive --prune=now
# Index neu erstellen, falls beschädigt
rm .git/index; git reset
```

### Authentifizierungsprobleme

Löst häufige Probleme mit Authentifizierung und Berechtigungen.

```bash
# Token verwenden
git remote set-url origin https://token@github.com/user/repo.git
# SSH-Schlüssel zum Agenten hinzufügen
ssh-add ~/.ssh/id_rsa
# Windows Credential Manager
git config --global credential.helper manager-core
```

### Performance-Probleme: Debugging

Identifiziert und behebt Probleme mit der Repository-Leistung.

```bash
# Repository-Größe anzeigen
git count-objects -vH
# Gesamtanzahl der Commits zählen
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

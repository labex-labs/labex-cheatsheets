---
title: 'Jenkins Spickzettel | LabEx'
description: 'Lernen Sie Jenkins CI/CD mit diesem umfassenden Spickzettel. Schnelle Referenz für Jenkins Pipelines, Jobs, Plugins, Automatisierung, Continuous Integration und DevOps-Workflows.'
pdfUrl: '/cheatsheets/pdf/jenkins-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Jenkins Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/jenkins">Lernen Sie Jenkins mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Jenkins CI/CD-Automatisierung durch praktische Labs und reale Szenarien. LabEx bietet umfassende Jenkins-Kurse, die wesentliche Operationen, Pipeline-Erstellung, Plugin-Verwaltung, Build-Automatisierung und fortgeschrittene Techniken abdecken. Meistern Sie Jenkins, um effiziente Continuous Integration und Deployment Pipelines für die moderne Softwareentwicklung aufzubauen.
</base-disclaimer-content>
</base-disclaimer>

## Installation & Einrichtung

### Linux Installation

Jenkins auf Ubuntu/Debian-Systemen installieren.

```bash
# Paketmanager aktualisieren und Java installieren
sudo apt update
sudo apt install fontconfig openjdk-21-jre
java -version
# Jenkins GPG-Schlüssel hinzufügen
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
# Jenkins-Repository hinzufügen
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
/etc/apt/sources.list.d/jenkins.list > /dev/null
# Jenkins installieren
sudo apt update && sudo apt install jenkins
# Jenkins-Dienst starten
sudo systemctl start jenkins
sudo systemctl enable jenkins
```

### Windows & macOS

Jenkins mithilfe von Installationsprogrammen oder Paketmanagern installieren.

```bash
# Windows: Jenkins Installer von jenkins.io herunterladen
# Oder Chocolatey verwenden
choco install jenkins
# macOS: Homebrew verwenden
brew install jenkins-lts
# Oder direkt herunterladen von:
# https://www.jenkins.io/download/
# Jenkins-Dienst starten
brew services start jenkins-lts
```

### Nachinstallations-Setup

Erste Konfiguration und Entsperren von Jenkins.

```bash
# Initiales Admin-Passwort abrufen
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# Oder bei Docker-Installationen
docker exec jenkins_container cat /var/jenkins_home/secrets/initialAdminPassword
# Auf die Jenkins-Weboberfläche zugreifen
# Navigieren Sie zu http://localhost:8080
# Das initiale Admin-Passwort eingeben
# Vorgeschlagene Plugins installieren oder benutzerdefinierte Plugins auswählen
```

### Erste Konfiguration

Den Setup-Assistenten abschließen und den Admin-Benutzer erstellen.

```bash
# Nach dem Entsperren von Jenkins:
# 1. Vorgeschlagene Plugins installieren (empfohlen)
# 2. Ersten Admin-Benutzer erstellen
# 3. Jenkins URL konfigurieren
# 4. Mit der Nutzung von Jenkins beginnen
# Überprüfen, ob Jenkins läuft
sudo systemctl status jenkins
# Jenkins-Logs bei Bedarf überprüfen
sudo journalctl -u jenkins.service
```

## Grundlegende Jenkins-Operationen

### Auf Jenkins zugreifen: Weboberfläche & CLI-Setup

Auf Jenkins über den Browser zugreifen und CLI-Tools einrichten.

```bash
# Auf die Jenkins-Weboberfläche zugreifen
http://localhost:8080
# Jenkins CLI herunterladen
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
# CLI-Verbindung testen
java -jar jenkins-cli.jar -s http://localhost:8080 help
# Verfügbare Befehle auflisten
java -jar jenkins-cli.jar -s http://localhost:8080 help
```

### Job-Erstellung: `create-job` / Web-UI

Neue Build-Jobs mithilfe der CLI oder der Weboberfläche erstellen.

```bash
# Job aus XML-Konfiguration erstellen
java -jar jenkins-cli.jar -auth user:token create-job my-job < job-config.xml
# Einfachen Freestyle-Job über die Weboberfläche erstellen:
# 1. Auf "Neues Element" klicken
# 2. Job-Namen eingeben
# 3. "Freestyle-Projekt" auswählen
# 4. Build-Schritte konfigurieren
# 5. Konfiguration speichern
```

### Jobs auflisten: `list-jobs`

Alle konfigurierten Jobs in Jenkins anzeigen.

```bash
# Alle Jobs auflisten
java -jar jenkins-cli.jar -auth user:token list-jobs
# Jobs mit Musterabgleich auflisten
java -jar jenkins-cli.jar -auth user:token list-jobs "*test*"
# Job-Konfiguration abrufen
java -jar jenkins-cli.jar -auth user:token get-job my-job > job-config.xml
```

## Job-Verwaltung

### Jobs bauen: `build`

Builds von Jobs auslösen und verwalten.

```bash
# Einen Job bauen
java -jar jenkins-cli.jar -auth user:token build my-job
# Mit Parametern bauen
java -jar jenkins-cli.jar -auth user:token build my-job -p PARAM=value
# Bauen und auf Abschluss warten
java -jar jenkins-cli.jar -auth user:token build my-job -s -v
# Bauen und Konsolenausgabe folgen
java -jar jenkins-cli.jar -auth user:token build my-job -f
```

<BaseQuiz id="jenkins-build-1" correct="B">
  <template #question>
    Was bewirkt das Flag <code>-s</code> in <code>jenkins-cli.jar build my-job -s</code>?
  </template>
  
  <BaseQuizOption value="A">Überspringt den Build</BaseQuizOption>
  <BaseQuizOption value="B" correct>Wartet auf den Abschluss des Builds (synchron)</BaseQuizOption>
  <BaseQuizOption value="C">Zeigt den Build-Status an</BaseQuizOption>
  <BaseQuizOption value="D">Stoppt den Build</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das Flag <code>-s</code> macht den Build-Befehl synchron, d.h. er wartet, bis der Build abgeschlossen ist, bevor er zurückkehrt. Ohne dieses Flag gibt der Befehl sofort nach dem Auslösen des Builds zurück.
  </BaseQuizAnswer>
</BaseQuiz>

### Job-Steuerung: `enable-job` / `disable-job`

Jobs aktivieren oder deaktivieren.

```bash
# Einen Job aktivieren
java -jar jenkins-cli.jar -auth user:token enable-job my-job
# Einen Job deaktivieren
java -jar jenkins-cli.jar -auth user:token disable-job my-job
# Job-Status in der Weboberfläche prüfen
# Zum Job-Dashboard navigieren
# Nach dem "Deaktivieren/Aktivieren"-Button suchen
```

<BaseQuiz id="jenkins-job-control-1" correct="B">
  <template #question>
    Was passiert, wenn Sie einen Jenkins-Job deaktivieren?
  </template>
  
  <BaseQuizOption value="A">Der Job wird dauerhaft gelöscht</BaseQuizOption>
  <BaseQuizOption value="B" correct>Die Job-Konfiguration bleibt erhalten, aber er wird nicht mehr automatisch ausgeführt</BaseQuizOption>
  <BaseQuizOption value="C">Der Job wird in einen anderen Ordner verschoben</BaseQuizOption>
  <BaseQuizOption value="D">Der gesamte Build-Verlauf wird gelöscht</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das Deaktivieren eines Jobs verhindert, dass er automatisch ausgeführt wird (geplante Builds, Trigger usw.), bewahrt jedoch die Job-Konfiguration und den Build-Verlauf. Sie können ihn später wieder aktivieren.
  </BaseQuizAnswer>
</BaseQuiz>

### Job-Löschung: `delete-job`

Jobs aus Jenkins entfernen.

```bash
# Einen Job löschen
java -jar jenkins-cli.jar -auth user:token delete-job my-job
# Jobs in großen Mengen löschen (mit Vorsicht)
for job in job1 job2 job3; do
  java -jar jenkins-cli.jar -auth user:token delete-job $job
done
```

### Konsolenausgabe: `console`

Build-Logs und Konsolenausgabe anzeigen.

```bash
# Konsolenausgabe des letzten Builds anzeigen
java -jar jenkins-cli.jar -auth user:token console my-job
# Spezifische Build-Nummer anzeigen
java -jar jenkins-cli.jar -auth user:token console my-job 15
# Konsolenausgabe in Echtzeit verfolgen
java -jar jenkins-cli.jar -auth user:token console my-job -f
```

<BaseQuiz id="jenkins-console-1" correct="C">
  <template #question>
    Was bewirkt das Flag <code>-f</code> in <code>jenkins-cli.jar console my-job -f</code>?
  </template>
  
  <BaseQuizOption value="A">Erzwingt das Stoppen des Builds</BaseQuizOption>
  <BaseQuizOption value="B">Zeigt nur fehlgeschlagene Builds an</BaseQuizOption>
  <BaseQuizOption value="C" correct>Verfolgt die Konsolenausgabe in Echtzeit</BaseQuizOption>
  <BaseQuizOption value="D">Formatiert die Ausgabe als JSON</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das Flag <code>-f</code> verfolgt die Konsolenausgabe in Echtzeit, ähnlich wie <code>tail -f</code> unter Linux. Dies ist nützlich, um Builds während ihrer Ausführung zu überwachen.
  </BaseQuizAnswer>
</BaseQuiz>

## Pipeline-Verwaltung

### Pipeline-Erstellung

Jenkins Pipelines erstellen und konfigurieren.

```groovy
// Grundlegender Jenkinsfile (Deklarative Pipeline)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Building application...'
                sh 'make build'
            }
        }

        stage('Test') {
            steps {
                echo 'Running tests...'
                sh 'make test'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Deploying application...'
                sh 'make deploy'
            }
        }
    }
}
```

### Pipeline-Syntax

Gängige Pipeline-Syntax und Direktiven.

```groovy
// Scripted Pipeline Syntax
node {
    stage('Checkout') {
        checkout scm
    }

    stage('Build') {
        sh 'make build'
    }

    stage('Test') {
        sh 'make test'
        junit 'target/test-results/*.xml'
    }
}
// Parallele Ausführung
stages {
    stage('Parallel Tests') {
        parallel {
            stage('Unit Tests') {
                steps {
                    sh 'make unit-test'
                }
            }
            stage('Integration Tests') {
                steps {
                    sh 'make integration-test'
                }
            }
        }
    }
}
```

### Pipeline-Konfiguration

Fortgeschrittene Pipeline-Konfiguration und Optionen.

```groovy
// Pipeline mit Post-Build-Aktionen
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }

    post {
        always {
            echo 'This always runs'
        }
        success {
            echo 'Build succeeded'
        }
        failure {
            echo 'Build failed'
            emailext subject: 'Build Failed',
                     body: 'Build failed',
                     to: 'team@company.com'
        }
    }
}
```

### Pipeline-Trigger

Konfigurieren von automatischen Pipeline-Triggern.

```groovy
// Pipeline mit Triggern
pipeline {
    agent any

    triggers {
        // SCM alle 5 Minuten abfragen
        pollSCM('H/5 * * * *')

        // Cron-ähnliche Planung
        cron('H 2 * * *')  // Täglich um 2 Uhr morgens

        // Upstream-Job-Trigger
        upstream(upstreamProjects: 'upstream-job',
                threshold: hudson.model.Result.SUCCESS)
    }

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}
```

## Plugin-Verwaltung

### Plugin-Installation: CLI

Plugins mithilfe der Befehlszeilenschnittstelle installieren.

```bash
# Plugin über CLI installieren (Neustart erforderlich)
java -jar jenkins-cli.jar -auth user:token install-plugin git
# Mehrere Plugins installieren
java -jar jenkins-cli.jar -auth user:token install-plugin \
  git maven-plugin docker-plugin
# Von .hpi-Datei installieren
java -jar jenkins-cli.jar -auth user:token install-plugin \
  /path/to/plugin.hpi
# Installierte Plugins auflisten
java -jar jenkins-cli.jar -auth user:token list-plugins
# Plugin-Installation über plugins.txt (für Docker)
# Erstellen Sie die Datei plugins.txt:
git:latest
maven-plugin:latest
docker-plugin:latest
pipeline-stage-view:latest
# Verwenden Sie das Tool jenkins-plugin-cli
jenkins-plugin-cli --plugins git maven-plugin docker-plugin
```

### Wesentliche Plugins

Häufig verwendete Jenkins-Plugins für verschiedene Zwecke.

```bash
# Build & SCM Plugins
git                    # Git-Integration
github                 # GitHub-Integration
maven-plugin          # Maven Build-Unterstützung
gradle                # Gradle Build-Unterstützung
# Pipeline Plugins
workflow-aggregator   # Pipeline Plugin-Suite
pipeline-stage-view   # Pipeline Stage View
blue-ocean           # Moderne UI für Pipelines
# Deployment & Integration
docker-plugin        # Docker-Integration
kubernetes           # Kubernetes-Deployment
ansible              # Ansible-Automatisierung
# Qualität & Tests
junit                # JUnit Testberichte
jacoco              # Code Coverage
sonarqube           # Codequalitätsanalyse
```

### Plugin-Verwaltung Weboberfläche

Plugins über die Jenkins-Weboberfläche verwalten.

```bash
# Auf den Plugin-Manager zugreifen:
# 1. Zu Verwalten Sie Jenkins navigieren
# 2. Auf "Plugins verwalten" klicken
# 3. Die Registerkarten Verfügbar/Installiert/Updates verwenden
# 4. Nach Plugins suchen
# 5. Auswählen und installieren
# 6. Jenkins bei Bedarf neu starten
# Plugin-Update-Prozess:
# 1. Registerkarte "Updates" prüfen
# 2. Zu aktualisierende Plugins auswählen
# 3. Auf "Jetzt herunterladen und nach Neustart installieren" klicken
```

## Benutzerverwaltung & Sicherheit

### Benutzerverwaltung

Jenkins-Benutzer erstellen und verwalten.

```bash
# Jenkins-Sicherheit aktivieren:
# 1. Verwalten Sie Jenkins → Globale Sicherheit konfigurieren
# 2. "Jenkins' eigene Benutzerdatenbank" aktivieren
# 3. Benutzern die Anmeldung erlauben (Ersteinrichtung)
# 4. Autorisierungsstrategie festlegen
# Benutzer über CLI erstellen (erfordert entsprechende Berechtigungen)
# Benutzer werden typischerweise über die Weboberfläche erstellt:
# 1. Verwalten Sie Jenkins → Benutzer verwalten
# 2. Auf "Benutzer erstellen" klicken
# 3. Benutzerdetails ausfüllen
# 4. Rollen/Berechtigungen zuweisen
```

### Authentifizierung & Autorisierung

Sicherheitsdomänen und Autorisierungsstrategien konfigurieren.

```bash
# Optionen zur Sicherheitskonfiguration:
# 1. Sicherheitsdomäne (wie sich Benutzer authentifizieren):
#    - Jenkins' eigene Benutzerdatenbank
#    - LDAP
#    - Active Directory
#    - Matrix-basierte Sicherheit
#    - Rollenbasierte Autorisierung
# 2. Autorisierungsstrategie:
#    - Jeder kann alles tun
#    - Legacy-Modus
#    - Angemeldete Benutzer können alles tun
#    - Matrix-basierte Sicherheit
#    - Projektbasierte Matrix-Autorisierung
```

### API-Tokens

API-Tokens für den CLI-Zugriff generieren und verwalten.

```bash
# API-Token generieren:
# 1. Auf den Benutzernamen klicken → Konfigurieren
# 2. Abschnitt API-Token
# 3. Auf "Neues Token hinzufügen" klicken
# 4. Token-Namen eingeben
# 5. Generieren und Token kopieren
# API-Token mit CLI verwenden
java -jar jenkins-cli.jar -auth benutzername:api-token \
  -s http://localhost:8080 list-jobs
# Anmeldeinformationen sicher speichern
echo "benutzername:api-token" > ~/.jenkins-cli-auth
chmod 600 ~/.jenkins-cli-auth
```

### Anmeldeinformationsverwaltung

Gespeicherte Anmeldeinformationen für Jobs und Pipelines verwalten.

```bash
# Anmeldeinformationen über CLI verwalten
java -jar jenkins-cli.jar -auth user:token \
  list-credentials system::system::jenkins
# Anmeldeinformationen als XML erstellen und importieren
java -jar jenkins-cli.jar -auth user:token \
  create-credentials-by-xml system::system::jenkins \
  < credential.xml
```

```groovy
// Auf Anmeldeinformationen in Pipelines zugreifen
withCredentials([usernamePassword(
  credentialsId: 'my-credentials',
  usernameVariable: 'USERNAME',
  passwordVariable: 'PASSWORD'
)]) {
  sh 'docker login -u $USERNAME -p $PASSWORD'
}
```

## Build-Überwachung & Fehlerbehebung

### Build-Status & Logs

Build-Status überwachen und auf detaillierte Logs zugreifen.

```bash
# Build-Status prüfen
java -jar jenkins-cli.jar -auth user:token console my-job
# Job-Informationen abrufen
java -jar jenkins-cli.jar -auth user:token get-job my-job
# Build-Warteschlange überwachen
# Weboberfläche: Jenkins Dashboard → Build-Warteschlange
# Zeigt ausstehende Builds und deren Status an
# Zugriff auf den Build-Verlauf
# Weboberfläche: Job → Build-Verlauf
# Zeigt alle vorherigen Builds mit Status
```

### Systeminformationen

Jenkins-Systeminformationen und Diagnosen abrufen.

```bash
# Systeminformationen
java -jar jenkins-cli.jar -auth user:token version
# Knoteninformationen
java -jar jenkins-cli.jar -auth user:token list-computers
# Groovy-Konsole (nur Admin)
# Verwalten Sie Jenkins → Skriptkonsole
# Groovy-Skripte zur Systeminformation ausführen:
println Jenkins.instance.version
println Jenkins.instance.getRootDir()
println System.getProperty("java.version")
```

### Log-Analyse

Jenkins-Systemprotokolle abrufen und analysieren.

```bash
# Speicherort der Systemprotokolle
# Linux: /var/log/jenkins/jenkins.log
# Windows: C:\Program Files\Jenkins\jenkins.out.log
# Protokolle anzeigen
tail -f /var/log/jenkins/jenkins.log
# Protokollebenen konfigurieren
# Verwalten Sie Jenkins → Systemprotokoll
# Neuen Protokollrekorder für bestimmte Komponenten hinzufügen
# Häufige Protokollspeicherorte:
sudo journalctl -u jenkins.service     # Systemd-Logs
sudo cat /var/lib/jenkins/jenkins.log  # Jenkins-Protokolldatei
```

### Leistungsüberwachung

Jenkins auf bessere Leistung und Skalierbarkeit überwachen.

```bash
# Eingebaute Überwachung
# Verwalten Sie Jenkins → Laststatistiken
# Zeigt die Auslastung der Executor im Zeitverlauf
# JVM-Überwachung
# Verwalten Sie Jenkins → Knoten verwalten → Master
# Zeigt Speicher-, CPU-Auslastung und Systemeigenschaften
# Build-Trends
# Installieren Sie das Plugin "Build History Metrics"
# Zeigt Trends für Build-Dauer und Erfolgsquoten
# Überwachung der Festplattennutzung
# Installieren Sie das Plugin "Disk Usage"
# Überwacht Workspace- und Build-Artefakt-Speicherplatz
```

## Jenkins-Konfiguration & Einstellungen

### Globale Konfiguration

Globale Jenkins-Einstellungen und Tools konfigurieren.

```bash
# Globale Tool-Konfiguration
# Verwalten Sie Jenkins → Globale Tool-Konfiguration
# Konfigurieren Sie:
# - JDK-Installationen
# - Git-Installationen
# - Maven-Installationen
# - Docker-Installationen
# Systemkonfiguration
# Verwalten Sie Jenkins → System konfigurieren
# Festlegen von:
# - Jenkins URL
# - Systemnachricht
# - Anzahl der Executor
# - Quiet Period
# - SCM-Polling-Limits
```

### Umgebungsvariablen

Jenkins-Umgebungsvariablen und Systemeigenschaften konfigurieren.

```bash
# Eingebaute Umgebungsvariablen
BUILD_NUMBER          # Build-Nummer
BUILD_ID              # Build-ID
JOB_NAME             # Job-Name
WORKSPACE            # Job-Workspace-Pfad
JENKINS_URL          # Jenkins URL
NODE_NAME            # Knotenname
# Benutzerdefinierte Umgebungsvariablen
# Verwalten Sie Jenkins → System konfigurieren
# Globale Eigenschaften → Umgebungsvariablen
# Schlüssel-Wert-Paare für globalen Zugriff hinzufügen
```

### Jenkins-Konfiguration als Code

Jenkins-Konfiguration mithilfe des JCasC-Plugins verwalten.

```yaml
# JCasC Konfigurationsdatei (jenkins.yaml)
jenkins:
  systemMessage: "Jenkins configured as code"
  numExecutors: 4
  securityRealm:
    local:
      allowsSignup: false
      users:
       - id: "admin"
         password: "admin123"
# Konfiguration anwenden
# Setzen Sie die Umgebungsvariable CASC_JENKINS_CONFIG
export CASC_JENKINS_CONFIG=/path/to/jenkins.yaml
```

## Best Practices

### Sicherheitspraktiken

Halten Sie Ihre Jenkins-Instanz sicher und produktionsbereit.

```bash
# Sicherheitsempfehlungen:
# 1. Sicherheit und Authentifizierung aktivieren
# 2. Matrix-basierte Autorisierung verwenden
# 3. Regelmäßige Sicherheitsupdates
# 4. Benutzerberechtigungen einschränken
# 5. API-Tokens anstelle von Passwörtern verwenden
# Jenkins-Konfiguration absichern:
# - CLI über Remoting deaktivieren
# - HTTPS mit gültigen Zertifikaten verwenden
# - Regelmäßige Sicherung von JENKINS_HOME
# - Sicherheitsmitteilungen überwachen
# - Anmeldeinformations-Plugins für Geheimnisse verwenden
```

### Leistungsoptimierung

Jenkins für bessere Leistung und Skalierbarkeit optimieren.

```bash
# Leistungstipps:
# 1. Verteilte Builds mit Agents verwenden
# 2. Build-Skripte und Abhängigkeiten optimieren
# 3. Alte Builds automatisch bereinigen
# 4. Pipeline-Bibliotheken für Wiederverwendbarkeit nutzen
# 5. Festplattenspeicher und Speichernutzung überwachen
# Build-Optimierung:
# - Wo möglich inkrementelle Builds verwenden
# - Parallele Ausführung von Stages
# - Artefakt-Caching
# - Workspace-Bereinigung
# - Optimierung der Ressourcenzuweisung
```

## Relevante Links

- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>
- <router-link to="/ansible">Ansible Spickzettel</router-link>
- <router-link to="/git">Git Spickzettel</router-link>
- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>

---
title: 'Jenkins Spickzettel'
description: 'Lernen Sie Jenkins mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
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

Den Setup-Assistenten abschließen und Admin-Benutzer erstellen.

```bash
# Nach dem Entsperren von Jenkins:
# 1. Vorgeschlagene Plugins installieren (empfohlen)
# 2. Ersten Admin-Benutzer erstellen
# 3. Jenkins-URL konfigurieren
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
java -jar jenkins-cli.jar -auth benutzer:token create-job mein-job < job-config.xml
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
java -jar jenkins-cli.jar -auth benutzer:token list-jobs
# Jobs nach Muster auflisten
java -jar jenkins-cli.jar -auth benutzer:token list-jobs "*test*"
# Job-Konfiguration abrufen
java -jar jenkins-cli.jar -auth benutzer:token get-job mein-job > job-config.xml
```

## Job-Verwaltung

### Jobs bauen: `build`

Build-Jobs auslösen und verwalten.

```bash
# Einen Job bauen
java -jar jenkins-cli.jar -auth benutzer:token build mein-job
# Mit Parametern bauen
java -jar jenkins-cli.jar -auth benutzer:token build mein-job -p PARAM=wert
# Bauen und auf Abschluss warten
java -jar jenkins-cli.jar -auth benutzer:token build mein-job -s -v
# Bauen und Konsolenausgabe verfolgen
java -jar jenkins-cli.jar -auth benutzer:token build mein-job -f
```

### Job-Steuerung: `enable-job` / `disable-job`

Jobs aktivieren oder deaktivieren.

```bash
# Einen Job aktivieren
java -jar jenkins-cli.jar -auth benutzer:token enable-job mein-job
# Einen Job deaktivieren
java -jar jenkins-cli.jar -auth benutzer:token disable-job mein-job
# Job-Status in der Weboberfläche prüfen
# Zum Job-Dashboard navigieren
# Nach der Schaltfläche "Deaktivieren/Aktivieren" suchen
```

### Job-Löschung: `delete-job`

Jobs aus Jenkins entfernen.

```bash
# Einen Job löschen
java -jar jenkins-cli.jar -auth benutzer:token delete-job mein-job
# Mehrere Jobs löschen (mit Vorsicht)
for job in job1 job2 job3; do
  java -jar jenkins-cli.jar -auth benutzer:token delete-job $job
done
```

### Konsolenausgabe: `console`

Build-Protokolle und Konsolenausgabe anzeigen.

```bash
# Konsolenausgabe des letzten Builds anzeigen
java -jar jenkins-cli.jar -auth benutzer:token console mein-job
# Konsolenausgabe einer bestimmten Build-Nummer anzeigen
java -jar jenkins-cli.jar -auth benutzer:token console mein-job 15
# Konsolenausgabe in Echtzeit verfolgen
java -jar jenkins-cli.jar -auth benutzer:token console mein-job -f
```

## Pipeline-Verwaltung

### Pipeline-Erstellung

Jenkins Pipelines erstellen und konfigurieren.

```groovy
// Grundlegende Jenkinsfile (Deklarative Pipeline)
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

Häufige Pipeline-Syntax und Direktiven.

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

Erweiterte Pipeline-Konfiguration und Optionen.

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

Konfigurieren automatischer Pipeline-Auslöser.

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

Plugins über die Kommandozeilenschnittstelle installieren.

```bash
# Plugin über CLI installieren (Neustart erforderlich)
java -jar jenkins-cli.jar -auth benutzer:token install-plugin git
# Mehrere Plugins installieren
java -jar jenkins-cli.jar -auth benutzer:token install-plugin \
  git maven-plugin docker-plugin
# Von .hpi-Datei installieren
java -jar jenkins-cli.jar -auth benutzer:token install-plugin \
  /path/to/plugin.hpi
# Installierte Plugins auflisten
java -jar jenkins-cli.jar -auth benutzer:token list-plugins
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
junit                # JUnit-Testberichte
jacoco              # Code-Abdeckung
sonarqube           # Codequalitätsanalyse
```

### Plugin-Verwaltung Weboberfläche

Plugins über die Jenkins-Weboberfläche verwalten.

```bash
# Auf den Plugin-Manager zugreifen:
# 1. Zu Verwalte Jenkins navigieren
# 2. Auf "Plugins verwalten" klicken
# 3. Die Tabs Verfügbar/Installiert/Updates verwenden
# 4. Nach Plugins suchen
# 5. Auswählen und installieren
# 6. Jenkins bei Bedarf neu starten
# Plugin-Update-Prozess:
# 1. Reiter "Updates" prüfen
# 2. Zu aktualisierende Plugins auswählen
# 3. Auf "Jetzt herunterladen und nach Neustart installieren" klicken
```

## Benutzerverwaltung & Sicherheit

### Benutzerverwaltung

Jenkins-Benutzer erstellen und verwalten.

```bash
# Jenkins-Sicherheit aktivieren:
# 1. Verwalte Jenkins → Globale Sicherheit konfigurieren
# 2. "Jenkins' eigene Benutzerdatenbank" aktivieren
# 3. Benutzern das Anmelden erlauben (Initial-Setup)
# 4. Autorisierungsstrategie festlegen
# Benutzer über CLI erstellen (erfordert entsprechende Berechtigungen)
# Benutzer werden typischerweise über die Weboberfläche erstellt:
# 1. Verwalte Jenkins → Benutzer verwalten
# 2. Auf "Benutzer erstellen" klicken
# 3. Benutzerdetails ausfüllen
# 4. Rollen/Berechtigungen zuweisen
```

### Authentifizierung & Autorisierung

Sicherheitsbereiche und Autorisierungsstrategien konfigurieren.

```bash
# Optionen zur Sicherheitskonfiguration:
# 1. Security Realm (wie Benutzer sich authentifizieren):
#    - Jenkins' eigene Benutzerdatenbank
#    - LDAP
#    - Active Directory
#    - Matrix-basierte Sicherheit
#    - Rollenbasierte Autorisierung
# 2. Autorisierungsstrategie:
#    - Jeder darf alles tun
#    - Legacy-Modus
#    - Angemeldete Benutzer dürfen alles tun
#    - Matrix-basierte Sicherheit
#    - Projektbasierte Matrix-Autorisierung
```

### API-Tokens

API-Tokens für den CLI-Zugriff generieren und verwalten.

```bash
# API-Token generieren:
# 1. Auf Benutzername klicken → Konfigurieren
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
java -jar jenkins-cli.jar -auth benutzer:token \
  list-credentials system::system::jenkins
# Anmeldeinformationen XML erstellen und importieren
java -jar jenkins-cli.jar -auth benutzer:token \
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

### Build-Status & Protokolle

Build-Status überwachen und auf detaillierte Protokolle zugreifen.

```bash
# Build-Status prüfen
java -jar jenkins-cli.jar -auth benutzer:token console mein-job
# Build-Informationen abrufen
java -jar jenkins-cli.jar -auth benutzer:token get-job mein-job
# Build-Warteschlange überwachen
# Weboberfläche: Jenkins Dashboard → Build Queue
# Zeigt ausstehende Builds und deren Status an
# Zugriff auf Build-Verlauf
# Weboberfläche: Job → Build History
# Zeigt alle vorherigen Builds mit Status an
```

### Systeminformationen

Jenkins-Systeminformationen und Diagnosedaten abrufen.

```bash
# Systeminformationen
java -jar jenkins-cli.jar -auth benutzer:token version
# Knoteninformationen
java -jar jenkins-cli.jar -auth benutzer:token list-computers
# Groovy-Konsole (nur Admin)
# Verwalte Jenkins → Script Console
# Groovy-Skripte für Systeminformationen ausführen:
println Jenkins.instance.version
println Jenkins.instance.getRootDir()
println System.getProperty("java.version")
```

### Protokollanalyse

Jenkins-Systemprotokolle abrufen und analysieren.

```bash
# Speicherort der Systemprotokolle
# Linux: /var/log/jenkins/jenkins.log
# Windows: C:\Program Files\Jenkins\jenkins.out.log
# Protokolle anzeigen
tail -f /var/log/jenkins/jenkins.log
# Protokollstufen konfigurieren
# Verwalte Jenkins → Systemprotokoll
# Neuen Protokoll-Recorder für spezifische Komponenten hinzufügen
# Häufige Protokollspeicherorte:
sudo journalctl -u jenkins.service     # Systemd-Protokolle
sudo cat /var/lib/jenkins/jenkins.log  # Jenkins-Protokolldatei
```

### Leistungsüberwachung

Jenkins-Leistung und Ressourcennutzung überwachen.

```bash
# Eingebaute Überwachung
# Verwalte Jenkins → Laststatistiken
# Zeigt die Auslastung der Executor im Zeitverlauf
# JVM-Überwachung
# Verwalte Jenkins → Knoten verwalten → Master
# Zeigt Speicher-, CPU-Nutzung und Systemeigenschaften
# Build-Trends
# Plugin "Build History Metrics" installieren
# Build-Dauer-Trends und Erfolgsquoten anzeigen
# Festplattennutzungsüberwachung
# Plugin "Disk Usage" installieren
# Überwachung von Workspace- und Build-Artefakt-Speicher
```

## Jenkins Konfiguration & Einstellungen

### Globale Konfiguration

Globale Jenkins-Einstellungen und Tools konfigurieren.

```bash
# Globale Tool-Konfiguration
# Verwalte Jenkins → Globale Tool-Konfiguration
# Konfigurieren:
# - JDK-Installationen
# - Git-Installationen
# - Maven-Installationen
# - Docker-Installationen
# Systemkonfiguration
# Verwalte Jenkins → System konfigurieren
# Festlegen:
# - Jenkins-URL
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
# Verwalte Jenkins → System konfigurieren
# Globale Eigenschaften → Umgebungsvariablen
# Schlüssel-Wert-Paare für globalen Zugriff hinzufügen
```

### Jenkins Configuration as Code

Jenkins-Konfiguration mithilfe des JCasC-Plugins verwalten.

```yaml
# JCasC Konfigurationsdatei (jenkins.yaml)
jenkins:
  systemMessage: "Jenkins konfiguriert als Code"
  numExecutors: 4
  securityRealm:
    local:
      allowsSignup: false
      users:
       - id: "admin"
         password: "admin123"
# Konfiguration anwenden
# Umgebungsvariable CASC_JENKINS_CONFIG setzen
export CASC_JENKINS_CONFIG=/path/to/jenkins.yaml
```

## Best Practices

### Sicherheits-Best-Practices

Ihre Jenkins-Instanz sicher und produktionsbereit halten.

```bash
# Sicherheitsempfehlungen:
# 1. Sicherheit und Authentifizierung aktivieren
# 2. Matrix-basierte Autorisierung verwenden
# 3. Regelmäßige Sicherheitsupdates
# 4. Benutzerberechtigungen begrenzen
# 5. API-Tokens anstelle von Passwörtern verwenden
# Jenkins-Konfiguration absichern:
# - CLI über Remoting deaktivieren
# - HTTPS mit gültigen Zertifikaten verwenden
# - Regelmäßige Sicherung von JENKINS_HOME
# - Sicherheitswarnungen überwachen
# - Anmeldeinformations-Plugins für Geheimnisse verwenden
```

### Leistungsoptimierung

Jenkins für bessere Leistung und Skalierbarkeit optimieren.

```bash
# Performance-Tipps:
# 1. Verteilte Builds mit Agents verwenden
# 2. Build-Skripte und Abhängigkeiten optimieren
# 3. Alte Builds automatisch bereinigen
# 4. Pipeline-Bibliotheken für Wiederverwendbarkeit nutzen
# 5. Festplattenspeicher und Speichernutzung überwachen
# Build-Optimierung:
# - Inkrementelle Builds verwenden, wo möglich
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

---
title: 'DevOps Spickzettel | LabEx'
description: 'Erlernen Sie DevOps-Praktiken mit diesem umfassenden Spickzettel. Schnelle Referenz für CI/CD, Automatisierung, Infrastructure as Code, Monitoring, Containerisierung und moderne Softwarebereitstellungs-Workflows.'
pdfUrl: '/cheatsheets/pdf/devops-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
DevOps Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/devops">DevOps mit Hands-On Labs lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie DevOps-Praktiken durch praktische Labs und reale Szenarien. LabEx bietet umfassende DevOps-Kurse, die wesentliche Operationen, Infrastrukturmanagement, CI/CD-Pipelines, Containerisierung, Überwachung und Automatisierung abdecken. Lernen Sie, Anwendungen bereitzustellen, Infrastruktur als Code zu verwalten, Workflows zu automatisieren und moderne DevOps-Praktiken für eine effiziente Softwarebereitstellung zu implementieren.
</base-disclaimer-content>
</base-disclaimer>

## Infrastructure as Code (IaC)

### Terraform: Infrastrukturbereitstellung

Infrastruktur mithilfe einer deklarativen Konfigurationssprache definieren und bereitstellen.

```bash
# Terraform initialisieren
terraform init
# Infrastrukturänderungen planen
terraform plan
# Infrastrukturänderungen anwenden
terraform apply
# Infrastruktur zerstören
terraform destroy
# Konfigurationsdateien formatieren
terraform fmt
# Konfiguration validieren
terraform validate
```

<BaseQuiz id="devops-terraform-1" correct="B">
  <template #question>
    Was bewirkt `terraform plan`?
  </template>
  
  <BaseQuizOption value="A">Wendet Infrastrukturänderungen sofort an</BaseQuizOption>
  <BaseQuizOption value="B" correct>Zeigt an, welche Änderungen vorgenommen werden, ohne sie anzuwenden</BaseQuizOption>
  <BaseQuizOption value="C">Zerstört die gesamte Infrastruktur</BaseQuizOption>
  <BaseQuizOption value="D">Initialisiert Terraform</BaseQuizOption>
  
  <BaseQuizAnswer>
    `terraform plan` erstellt einen Ausführungsplan, der zeigt, was Terraform tun wird, wenn Sie `terraform apply` ausführen. Es ist ein Trockenlauf, der Ihnen hilft, Änderungen zu überprüfen, bevor Sie sie anwenden.
  </BaseQuizAnswer>
</BaseQuiz>

### Ansible: Konfigurationsmanagement

Anwendungsbereitstellung und Konfigurationsmanagement automatisieren.

```bash
# Playbook ausführen
ansible-playbook site.yml
# Playbook auf bestimmten Hosts ausführen
ansible-playbook -i inventory site.yml
# Syntax prüfen
ansible-playbook --syntax-check site.yml
# Mit spezifischem Benutzer ausführen
ansible-playbook -u ubuntu site.yml
```

### CloudFormation: AWS Native IaC

AWS-Ressourcen mithilfe von JSON/YAML-Vorlagen bereitstellen.

```bash
# Stack erstellen
aws cloudformation create-stack --stack-name mystack --template-body file://template.yml
# Stack aktualisieren
aws cloudformation update-stack --stack-name mystack --template-body file://template.yml
# Stack löschen
aws cloudformation delete-stack --stack-name mystack
```

## Container-Verwaltung

### Docker: Containerisierung

Anwendungen in Containern erstellen, versenden und ausführen.

```bash
# Image erstellen
docker build -t myapp:latest .
# Container ausführen
docker run -d -p 8080:80 myapp:latest
# Laufende Container auflisten
docker ps
# Container stoppen
docker stop container_id
# Container entfernen
docker rm container_id
```

### Kubernetes: Container-Orchestrierung

Containerisierte Anwendungen in großem Maßstab bereitstellen und verwalten.

```bash
# Konfiguration anwenden
kubectl apply -f deployment.yml
# Pods abrufen
kubectl get pods
# Deployment skalieren
kubectl scale deployment myapp --replicas=5
# Logs anzeigen
kubectl logs pod_name
# Ressourcen löschen
kubectl delete -f deployment.yml
```

<BaseQuiz id="devops-k8s-1" correct="A">
  <template #question>
    Was bewirkt `kubectl apply -f deployment.yml`?
  </template>
  
  <BaseQuizOption value="A" correct>Erstellt oder aktualisiert Ressourcen, die in der YAML-Datei definiert sind</BaseQuizOption>
  <BaseQuizOption value="B">Löscht alle Ressourcen im Cluster</BaseQuizOption>
  <BaseQuizOption value="C">Erstellt nur neue Ressourcen</BaseQuizOption>
  <BaseQuizOption value="D">Zeigt an, was erstellt würde, ohne es anzuwenden</BaseQuizOption>
  
  <BaseQuizAnswer>
    `kubectl apply` ist ein deklarativer Befehl, der Ressourcen erstellt, falls sie nicht existieren, oder sie aktualisiert, falls sie existieren. Er ist idempotent, was bedeutet, dass Sie ihn mehrmals sicher ausführen können.
  </BaseQuizAnswer>
</BaseQuiz>

### Helm: Kubernetes Paketmanager

Kubernetes-Anwendungen mithilfe von Charts verwalten.

```bash
# Chart installieren
helm install myrelease stable/nginx
# Release aktualisieren
helm upgrade myrelease stable/nginx
# Releases auflisten
helm list
# Release deinstallieren
helm uninstall myrelease
```

## CI/CD-Pipeline-Verwaltung

### Jenkins: Build-Automatisierung

CI-Pipelines einrichten und verwalten.

```groovy
// Jenkinsfile Beispiel
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'mvn clean compile'
            }
        }
        stage('Test') {
            steps {
                sh 'mvn test'
            }
        }
        stage('Deploy') {
            steps {
                sh './deploy.sh'
            }
        }
    }
}
```

### GitHub Actions: Cloud CI/CD

Workflows direkt aus GitHub-Repositories automatisieren.

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Node
        uses: actions/setup-node@v2
        with:
          node-version: '14'
      - run: npm install
      - run: npm test
```

### GitLab CI: Integriertes DevOps

Die integrierten CI/CD-Funktionen von GitLab für vollständige DevOps-Workflows nutzen.

```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - deploy
build_job:
  stage: build
  script:
    - echo "Building the app"
test_job:
  stage: test
  script:
    - echo "Running tests"
```

## Versionskontrolle & Zusammenarbeit

### Git: Versionskontrollsystem

Änderungen verfolgen und an der Codeentwicklung zusammenarbeiten.

```bash
# Repository klonen
git clone https://github.com/user/repo.git
# Status prüfen
git status
# Änderungen hinzufügen
git add .
# Änderungen committen
git commit -m "Add feature"
# Auf Remote pushen
git push origin main
# Neueste Änderungen ziehen
git pull origin main
```

<BaseQuiz id="devops-git-1" correct="D">
  <template #question>
    Was ist der Unterschied zwischen `git pull` und `git fetch`?
  </template>
  
  <BaseQuizOption value="A">Es gibt keinen Unterschied</BaseQuizOption>
  <BaseQuizOption value="B">git pull pusht Änderungen, git fetch zieht Änderungen</BaseQuizOption>
  <BaseQuizOption value="C">git pull funktioniert lokal, git fetch funktioniert remote</BaseQuizOption>
  <BaseQuizOption value="D" correct>git fetch lädt Änderungen ohne Mergen herunter, git pull lädt herunter und merged Änderungen</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git fetch` lädt Änderungen aus dem Remote-Repository herunter, merged sie aber nicht in Ihren aktuellen Branch. `git pull` führt beide Operationen aus: es fetched und merged dann die Änderungen.
  </BaseQuizAnswer>
</BaseQuiz>

### Branch-Verwaltung

Verschiedene Entwicklungsströme und Releases verwalten.

```bash
# Branch erstellen
git checkout -b feature-branch
# Branch mergen
git merge feature-branch
# Branches auflisten
git branch -a
# Branch wechseln
git checkout main
# Branch löschen
git branch -d feature-branch
# Auf vorherigen Commit zurücksetzen
git reset --hard HEAD~1
# Commit-Historie anzeigen
git log --oneline
```

### GitHub: Code-Hosting & Zusammenarbeit

Repositories hosten und die kollaborative Entwicklung verwalten.

```bash
# GitHub CLI Befehle
gh repo create myrepo
gh repo clone user/repo
gh pr create --title "New feature"
gh pr list
gh pr merge 123
gh issue create --title "Bug report"
gh release create v1.0.0
# Pull Request erstellen
git push -u origin feature-branch
# Dann PR auf GitHub/GitLab erstellen
```

### Code Review & Qualität

Codequalität durch Peer-Reviews und automatisierte Prüfungen sicherstellen.

```bash
# Beispiel für Pre-commit Hooks
#!/bin/sh
# Tests vor dem Commit ausführen
npm test
if [ $? -ne 0 ]; then
  echo "Tests failed"
  exit 1
fi
```

## Überwachung & Beobachtbarkeit

### Prometheus: Metriksammlung

System- und Anwendungsmetriken mit Zeitreihendaten überwachen.

```promql
# CPU-Auslastung
cpu_usage_percent{instance="server1"}
# Speichernutzung
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
# HTTP-Anforderungsrate
rate(http_requests_total[5m])
# Alarmregel Beispiel
ALERT HighCPUUsage
  IF cpu_usage_percent > 80
  FOR 5m
```

### Grafana: Visualisierungs-Dashboard

Dashboards und Visualisierungen für Überwachungsdaten erstellen.

```bash
# Dashboard erstellen
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json
# Dashboard abrufen
curl http://admin:admin@localhost:3000/api/dashboards/uid/dashboard-uid
```

### ELK Stack: Protokollverwaltung

Protokolldaten über die Infrastruktur hinweg sammeln, suchen und analysieren.

```json
# Elasticsearch Abfragen
# Protokolle suchen
GET /logs/_search
{
  "query": {
    "match": {
      "message": "error"
    }
  }
}
```

```ruby
# Logstash Konfiguration
input {
  file {
    path => "/var/log/app.log"
  }
}
filter {
  grok {
    match => { "message" => "%{TIMESTAMP_ISO8601:timestamp}" }
  }
}
output {
  elasticsearch {
    hosts => ["localhost:9200"]
  }
}
```

### Application Performance Monitoring

Anwendungsleistung und Benutzererfahrung Metriken verfolgen.

```ruby
# New Relic Agent Einrichtung
# Zur Anwendung hinzufügen
require 'newrelic_rpm'
```

```python
# Datadog Metriken
from datadog import DogStatsdClient
statsd = DogStatsdClient('localhost', 8125)
statsd.increment('web.requests')
statsd.histogram('web.response_time', 0.75)
```

## Cloud-Plattform-Verwaltung

### AWS CLI: Amazon Web Services

Mit AWS-Diensten über die Befehlszeile interagieren.

```bash
# AWS CLI konfigurieren
aws configure
# EC2-Instanzen auflisten
aws ec2 describe-instances
# S3 Bucket erstellen
aws s3 mb s3://my-bucket-name
# Lambda-Funktion bereitstellen
aws lambda create-function --function-name myfunction --runtime python3.8 --role arn:aws:iam::123456789:role/lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip
# Laufende Dienste auflisten
aws ecs list-services --cluster my-cluster
```

### Azure CLI: Microsoft Azure

Azure-Ressourcen und -Dienste verwalten.

```bash
# Bei Azure anmelden
az login
# Ressourcengruppe erstellen
az group create --name myResourceGroup --location eastus
# Virtuelle Maschine erstellen
az vm create --resource-group myResourceGroup --name myVM --image Ubuntu2204 --admin-username azureuser --generate-ssh-keys
# Web-Apps auflisten
az webapp list
```

### Google Cloud: GCP

Anwendungen auf der Google Cloud Platform bereitstellen und verwalten.

```bash
# Bei GCP authentifizieren
gcloud auth login
# Projekt festlegen
gcloud config set project my-project-id
# App Engine Anwendung bereitstellen
gcloud app deploy
# Compute Engine Instanz erstellen
gcloud compute instances create my-instance --zone=us-central1-a
# Kubernetes Cluster verwalten
gcloud container clusters create my-cluster --num-nodes=3
```

### Multi-Cloud-Verwaltung

Tools zur Verwaltung von Ressourcen über mehrere Cloud-Anbieter hinweg.

```python
# Pulumi (Multi-Cloud IaC)
import pulumi_aws as aws
import pulumi_gcp as gcp
# AWS S3 Bucket erstellen
bucket = aws.s3.Bucket("my-bucket")
# GCP Storage Bucket erstellen
gcp_bucket = gcp.storage.Bucket("my-gcp-bucket")
```

## Sicherheits- & Geheimnisverwaltung

### HashiCorp Vault: Geheimnisverwaltung

HashiCorp Vault ist ein Tool für den sicheren Zugriff auf Geheimnisse. Ein Geheimnis ist alles, dessen Zugriff Sie streng kontrollieren möchten, wie z. B. API-Schlüssel, Passwörter oder Zertifikate.

```bash
# Ein Geheimnis schreiben
vault kv put secret/myapp/config username=myuser password=mypassword
# Ein Geheimnis lesen
vault kv get secret/myapp/config
# Ein Geheimnis löschen
vault kv delete secret/myapp/config
# Authentifizierungsmethode aktivieren
vault auth enable kubernetes
# Richtlinie erstellen
vault policy write myapp-policy myapp-policy.hcl
```

### Sicherheitsprüfung: Trivy & SonarQube

Container und Code auf Sicherheitslücken prüfen.

```bash
# Trivy Container-Scan
trivy image nginx:latest
# Dateisystem scannen
trivy fs /path/to/project
# SonarQube Analyse
sonar-scanner -Dsonar.projectKey=myproject -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000
```

### SSL/TLS-Zertifikatsverwaltung

SSL-Zertifikate für sichere Kommunikation verwalten.

```bash
# Let's Encrypt mit Certbot
certbot --nginx -d example.com
# Zertifikate erneuern
certbot renew
# Zertifikatablauf prüfen
openssl x509 -in cert.pem -text -noout | grep "Not After"
# Selbstsigniertes Zertifikat generieren
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

### Containersicherheit

Containerisierte Anwendungen und Laufzeitumgebungen absichern.

```bash
# Container als Nicht-Root-Benutzer ausführen
docker run --user 1000:1000 myapp
# Image auf Schwachstellen prüfen
docker scan myapp:latest
```

```dockerfile
# Distroless Images verwenden
FROM gcr.io/distroless/java:11
COPY app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## Leistungsoptimierung

### Systemleistungsüberwachung

Egal, ob Sie Server verwalten, Bereitstellungen einrichten oder etwas reparieren, das gerade in der Produktion ausgefallen ist, diese Befehle helfen Ihnen, schneller voranzukommen und intelligenter zu arbeiten.

```bash
# CPU- und Speichernutzung
htop
# Festplattennutzung
df -h
# Netzwerkverbindungen
netstat -tulpn
# Prozessüberwachung
ps aux | grep process_name
# Systemlast
uptime
# Speicherdetails
free -h
```

### Anwendungsleistungsabstimmung

Anwendungsleistung und Ressourcennutzung optimieren.

```bash
# JVM Leistungsüberwachung
jstat -gc -t PID 1s
# Node.js Leistung
node --inspect app.js
# Datenbankabfrageoptimierung
EXPLAIN ANALYZE SELECT * FROM table WHERE condition;
# Nginx Leistungsabstimmung
nginx -t && nginx -s reload
```

### Lasttests & Benchmarking

Anwendungsleistung unter verschiedenen Lastbedingungen testen.

```bash
# Apache Bench
ab -n 1000 -c 10 http://example.com/
# wrk HTTP-Benchmarking
wrk -t12 -c400 -d30s http://example.com/
# Artillery Lasttest
artillery run load-test.yml
# Kubernetes Horizontal Pod Autoscaler
kubectl autoscale deployment myapp --cpu-percent=70 --min=1 --max=10
```

### Datenbankleistung

Datenbankleistung und Abfragen überwachen und optimieren.

```sql
# MySQL Leistung
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Threads_connected';
```

```sql
# PostgreSQL Überwachung
SELECT * FROM pg_stat_activity;
```

```bash
# Redis Überwachung
redis-cli --latency
redis-cli info memory
```

## Tool-Installation

### Paketmanager

Tools mithilfe von Systempaketmanagern installieren.

```bash
# Ubuntu/Debian
apt update && apt install -y docker.io kubectl terraform
# CentOS/RHEL
yum install -y docker kubernetes-client terraform
# macOS Homebrew
brew install docker kubectl terraform ansible
```

### Container-Laufzeitinstallation

Docker und Container-Orchestrierungstools einrichten.

```bash
# Docker installieren
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker
# Docker Compose installieren
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
```

### Cloud CLI Tools

Befehlszeilenschnittstellen für große Cloud-Anbieter installieren.

```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && ./aws/install
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
# Google Cloud SDK
curl https://sdk.cloud.google.com | bash
```

## Umgebungskonfiguration

### Verwaltung von Umgebungsvariablen

Konfigurationen über verschiedene Umgebungen hinweg sicher verwalten.

```bash
# .env Datei Beispiel
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=your-api-key-here
ENVIRONMENT=production
# Umgebungsvariablen laden
export $(cat .env | xargs)
# Docker Umgebungsvariablen
docker run -e NODE_ENV=production -e API_KEY=secret myapp
# Kubernetes ConfigMap
kubectl create configmap app-config --from-env-file=.env
```

### Service Discovery & Konfiguration

Service Discovery und dynamische Konfiguration verwalten.

```bash
# Consul Service Registrierung
consul services register myservice.json
# Service-Zustand abrufen
consul health service web
# Etcd Schlüssel-Wert-Speicher
etcdctl put /config/database/host localhost
etcdctl get /config/database/host
```

### Entwicklungsumgebungs-Setup

Konsistente Entwicklungsumgebungen mithilfe von Containern einrichten.

```dockerfile
# Entwicklung Dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

```yaml
# Docker Compose für die Entwicklung
version: '3.8'
services:
  app:
    build: .
    ports:
      - '3000:3000'
    volumes:
      - .:/app
      - /app/node_modules
  database:
    image: postgres:13
    environment:
      POSTGRES_DB: myapp
```

### Härtung der Produktionsumgebung

Produktionsumgebungen absichern und optimieren.

```ini
# Systemd Service Konfiguration
[Unit]
Description=My Application
After=network.target
[Service]
Type=simple
User=myapp
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/start
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
```

## Automatisierung & Orchestrierung

### Infrastrukturautomatisierung mit Ansible

Infrastrukturbereitstellung und Konfigurationsmanagement automatisieren.

```yaml
# Ansible Playbook Beispiel
---
- hosts: webservers
  become: yes
  tasks:
    - name: Install nginx
      apt:
        name: nginx
        state: present
    - name: Start nginx
      service:
        name: nginx
        state: started
        enabled: yes
    - name: Deploy application
      copy:
        src: /local/app
        dest: /var/www/html
```

### Workflow-Orchestrierung

Komplexe Workflows und Datenpipelines orchestrieren.

```python
# Apache Airflow DAG Beispiel
from airflow import DAG
from airflow.operators.bash_operator import BashOperator
from datetime import datetime

dag = DAG('data_pipeline',
          start_date=datetime(2023, 1, 1),
          schedule_interval='@daily')

extract = BashOperator(task_id='extract_data',
                       bash_command='extract.sh',
                       dag=dag)
transform = BashOperator(task_id='transform_data',
                         bash_command='transform.sh',
                         dag=dag)
extract >> transform
```

### Ereignisgesteuerte Automatisierung

Automatisierung basierend auf Systemereignissen und Webhooks auslösen.

```bash
# GitHub Webhook Handler
#!/bin/bash
if [ "$1" == "push" ]; then
  git pull origin main
  docker build -t myapp .
  docker run -d --name myapp-$(date +%s) myapp
fi
# Prometheus Alertmanager Webhook
curl -X POST http://webhook-handler/deploy \
  -H "Content-Type: application/json" \
  -d '{"service": "myapp", "action": "restart"}'
```

### ChatOps-Integration

DevOps-Operationen in Chat-Plattformen für kollaborative Automatisierung integrieren.

```bash
# Slack Bot Befehl Beispiel
/deploy myapp to production
/rollback myapp to v1.2.3
/scale myapp replicas=5
/status infrastructure
# Microsoft Teams Webhook
curl -H "Content-Type: application/json" \
  -d '{"text": "Deployment completed successfully"}' \
  $TEAMS_WEBHOOK_URL
```

## Relevante Links

- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/git">Git Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>
- <router-link to="/ansible">Ansible Spickzettel</router-link>
- <router-link to="/jenkins">Jenkins Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>

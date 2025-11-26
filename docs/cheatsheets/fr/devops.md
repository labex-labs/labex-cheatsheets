---
title: 'Aide-mémoire DevOps'
description: 'Maîtrisez le DevOps avec notre aide-mémoire complet couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/devops-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Trombinoscope DevOps
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/devops">Apprenez le DevOps avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez les pratiques DevOps grâce à des laboratoires pratiques et des scénarios du monde réel. LabEx propose des cours DevOps complets couvrant les opérations essentielles, la gestion de l'infrastructure, les pipelines CI/CD, la conteneurisation, la surveillance et l'automatisation. Apprenez à déployer des applications, à gérer l'infrastructure en tant que code, à automatiser les flux de travail et à mettre en œuvre des pratiques DevOps modernes pour une livraison de logiciels efficace.
</base-disclaimer-content>
</base-disclaimer>

## Infrastructure as Code (IaC)

### Terraform: Provisionnement d'Infrastructure

Définir et provisionner l'infrastructure à l'aide d'un langage de configuration déclaratif.

```bash
# Initialiser Terraform
terraform init
# Planifier les changements d'infrastructure
terraform plan
# Appliquer les changements d'infrastructure
terraform apply
# Détruire l'infrastructure
terraform destroy
# Formater les fichiers de configuration
terraform fmt
# Valider la configuration
terraform validate
```

### Ansible: Gestion de Configuration

Automatiser le déploiement d'applications et la gestion de la configuration.

```bash
# Exécuter le playbook
ansible-playbook site.yml
# Exécuter le playbook sur des hôtes spécifiques
ansible-playbook -i inventory site.yml
# Vérifier la syntaxe
ansible-playbook --syntax-check site.yml
# Exécuter avec un utilisateur spécifique
ansible-playbook -u ubuntu site.yml
```

### CloudFormation: IaC Natif AWS

Provisionner des ressources AWS à l'aide de modèles JSON/YAML.

```bash
# Créer une pile
aws cloudformation create-stack --stack-name mystack --template-body file://template.yml
# Mettre à jour la pile
aws cloudformation update-stack --stack-name mystack --template-body file://template.yml
# Supprimer la pile
aws cloudformation delete-stack --stack-name mystack
```

## Gestion des Conteneurs

### Docker: Conteneurisation

Construire, expédier et exécuter des applications dans des conteneurs.

```bash
# Construire l'image
docker build -t myapp:latest .
# Exécuter le conteneur
docker run -d -p 8080:80 myapp:latest
# Lister les conteneurs en cours d'exécution
docker ps
# Arrêter le conteneur
docker stop container_id
# Supprimer le conteneur
docker rm container_id
```

### Kubernetes: Orchestration de Conteneurs

Déployer et gérer des applications conteneurisées à grande échelle.

```bash
# Appliquer la configuration
kubectl apply -f deployment.yml
# Obtenir les pods
kubectl get pods
# Mettre à l'échelle le déploiement
kubectl scale deployment myapp --replicas=5
# Voir les logs
kubectl logs pod_name
# Supprimer les ressources
kubectl delete -f deployment.yml
```

### Helm: Gestionnaire de Paquets Kubernetes

Gérer les applications Kubernetes à l'aide de charts.

```bash
# Installer le chart
helm install myrelease stable/nginx
# Mettre à jour la version
helm upgrade myrelease stable/nginx
# Lister les versions
helm list
# Désinstaller la version
helm uninstall myrelease
```

## Gestion des Pipelines CI/CD

### Jenkins: Automatisation de la Construction

Configurer et gérer les pipelines d'intégration continue.

```groovy
// Exemple Jenkinsfile
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

### GitHub Actions: CI/CD Cloud

Automatiser les flux de travail directement depuis les dépôts GitHub.

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

### GitLab CI: DevOps Intégré

Utiliser les capacités CI/CD intégrées de GitLab pour des flux de travail DevOps complets.

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

## Contrôle de Version et Collaboration

### Git: Système de Contrôle de Version

Suivre les changements et collaborer sur le développement de code.

```bash
# Cloner le dépôt
git clone https://github.com/user/repo.git
# Vérifier le statut
git status
# Ajouter les changements
git add .
# Commiter les changements
git commit -m "Add feature"
# Pousser vers le distant
git push origin main
# Tirer les derniers changements
git pull origin main
```

### Gestion des Branches

Gérer différents flux de développement et de publication.

```bash
# Créer une branche
git checkout -b feature-branch
# Fusionner la branche
git merge feature-branch
# Lister les branches
git branch -a
# Changer de branche
git checkout main
# Supprimer la branche
git branch -d feature-branch
# Réinitialiser à un commit précédent
git reset --hard HEAD~1
# Voir l'historique des commits
git log --oneline
```

### GitHub: Hébergement de Code et Collaboration

Héberger des dépôts et gérer le développement collaboratif.

```bash
# Commandes GitHub CLI
gh repo create myrepo
gh repo clone user/repo
gh pr create --title "New feature"
gh pr list
gh pr merge 123
gh issue create --title "Bug report"
gh release create v1.0.0
# Créer une pull request
git push -u origin feature-branch
# Puis créer une PR sur GitHub/GitLab
```

### Revue de Code et Qualité

Assurer la qualité du code par la revue par les pairs et les vérifications automatisées.

```bash
# Exemple de hooks pre-commit
#!/bin/sh
# Exécuter les tests avant le commit
npm test
if [ $? -ne 0 ]; then
  echo "Tests failed"
  exit 1
fi
```

## Surveillance et Observabilité

### Prometheus: Collecte de Métriques

Surveiller les métriques système et applicatives avec des données de séries temporelles.

```promql
# Utilisation du CPU
cpu_usage_percent{instance="server1"}
# Utilisation de la mémoire
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
# Taux de requêtes HTTP
rate(http_requests_total[5m])
# Exemple de règles d'alerte
ALERT HighCPUUsage
  IF cpu_usage_percent > 80
  FOR 5m
```

### Grafana: Tableau de Bord de Visualisation

Créer des tableaux de bord et des visualisations pour les données de surveillance.

```bash
# Créer un tableau de bord
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json
# Obtenir un tableau de bord
curl http://admin:admin@localhost:3000/api/dashboards/uid/dashboard-uid
```

### Pile ELK: Gestion des Logs

Collecter, rechercher et analyser les données de logs à travers l'infrastructure.

```json
# Requêtes Elasticsearch
# Rechercher des logs
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
# Configuration Logstash
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

### Surveillance des Performances Applicatives

Suivre les performances des applications et les métriques d'expérience utilisateur.

```ruby
# Configuration de l'agent New Relic
# Ajouter à l'application
require 'newrelic_rpm'
```

```python
# Métriques Datadog
from datadog import DogStatsdClient
statsd = DogStatsdClient('localhost', 8125)
statsd.increment('web.requests')
statsd.histogram('web.response_time', 0.75)
```

## Gestion des Plateformes Cloud

### AWS CLI: Amazon Web Services

Interagir avec les services AWS depuis la ligne de commande.

```bash
# Configurer AWS CLI
aws configure
# Lister les instances EC2
aws ec2 describe-instances
# Créer un bucket S3
aws s3 mb s3://my-bucket-name
# Déployer une fonction Lambda
aws lambda create-function --function-name myfunction --runtime python3.8 --role arn:aws:iam::123456789:role/lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip
# Lister les services en cours d'exécution
aws ecs list-services --cluster my-cluster
```

### Azure CLI: Microsoft Azure

Gérer les ressources et services Azure.

```bash
# Se connecter à Azure
az login
# Créer un groupe de ressources
az group create --name myResourceGroup --location eastus
# Créer une machine virtuelle
az vm create --resource-group myResourceGroup --name myVM --image Ubuntu2204 --admin-username azureuser --generate-ssh-keys
# Lister les applications web
az webapp list
```

### Google Cloud: GCP

Déployer et gérer des applications sur Google Cloud Platform.

```bash
# S'authentifier auprès de GCP
gcloud auth login
# Définir le projet
gcloud config set project my-project-id
# Déployer l'application App Engine
gcloud app deploy
# Créer une instance Compute Engine
gcloud compute instances create my-instance --zone=us-central1-a
# Gérer le cluster Kubernetes
gcloud container clusters create my-cluster --num-nodes=3
```

### Gestion Multi-Cloud

Outils pour gérer les ressources sur plusieurs fournisseurs de cloud.

```python
# Pulumi (IaC multi-cloud)
import pulumi_aws as aws
import pulumi_gcp as gcp
# Créer un bucket S3 AWS
bucket = aws.s3.Bucket("my-bucket")
# Créer un bucket de stockage GCP
gcp_bucket = gcp.storage.Bucket("my-gcp-bucket")
```

## Gestion de la Sécurité et des Secrets

### HashiCorp Vault: Gestion des Secrets

HashiCorp Vault est un outil permettant d'accéder aux secrets de manière sécurisée. Un secret est tout ce que vous souhaitez contrôler strictement l'accès, comme les clés API, les mots de passe ou les certificats.

```bash
# Écrire un secret
vault kv put secret/myapp/config username=myuser password=mypassword
# Lire un secret
vault kv get secret/myapp/config
# Supprimer un secret
vault kv delete secret/myapp/config
# Activer la méthode d'authentification
vault auth enable kubernetes
# Créer une politique
vault policy write myapp-policy myapp-policy.hcl
```

### Analyse de Sécurité: Trivy & SonarQube

Analyser les conteneurs et le code pour les vulnérabilités de sécurité.

```bash
# Analyse de conteneur Trivy
trivy image nginx:latest
# Analyser le système de fichiers
trivy fs /path/to/project
# Analyse SonarQube
sonar-scanner -Dsonar.projectKey=myproject -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000
```

### Gestion des Certificats SSL/TLS

Gérer les certificats SSL pour les communications sécurisées.

```bash
# Let's Encrypt avec Certbot
certbot --nginx -d example.com
# Renouveler les certificats
certbot renew
# Vérifier l'expiration du certificat
openssl x509 -in cert.pem -text -noout | grep "Not After"
# Générer un certificat auto-signé
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

### Sécurité des Conteneurs

Sécuriser les applications conteneurisées et les environnements d'exécution.

```bash
# Exécuter le conteneur en tant qu'utilisateur non-root
docker run --user 1000:1000 myapp
# Analyser l'image pour les vulnérabilités
docker scan myapp:latest
```

```dockerfile
# Utiliser des images distroless
FROM gcr.io/distroless/java:11
COPY app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## Optimisation des Performances

### Surveillance des Performances Système

Que vous gériez des serveurs, configuriez des déploiements ou répariez quelque chose qui vient de tomber en panne en production, ces commandes vous aident à avancer plus vite et à travailler plus intelligemment.

```bash
# Utilisation du CPU et de la mémoire
htop
# Utilisation du disque
df -h
# Connexions réseau
netstat -tulpn
# Surveillance des processus
ps aux | grep process_name
# Charge du système
uptime
# Détails de la mémoire
free -h
```

### Réglage des Performances Applicatives

Optimiser les performances des applications et l'utilisation des ressources.

```bash
# Surveillance des performances JVM
jstat -gc -t PID 1s
# Performances Node.js
node --inspect app.js
# Optimisation des requêtes de base de données
EXPLAIN ANALYZE SELECT * FROM table WHERE condition;
# Réglage des performances Nginx
nginx -t && nginx -s reload
```

### Tests de Charge et Benchmarking

Tester les performances de l'application sous diverses conditions de charge.

```bash
# Apache Bench
ab -n 1000 -c 10 http://example.com/
# wrk HTTP benchmarking
wrk -t12 -c400 -d30s http://example.com/
# Test de charge Artillery
artillery run load-test.yml
# Autoscaler de Pod Horizontal Kubernetes
kubectl autoscale deployment myapp --cpu-percent=70 --min=1 --max=10
```

### Performances des Bases de Données

Surveiller et optimiser les performances et les requêtes des bases de données.

```sql
# Performances MySQL
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Threads_connected';
```

```sql
# Surveillance PostgreSQL
SELECT * FROM pg_stat_activity;
```

```bash
# Surveillance Redis
redis-cli --latency
redis-cli info memory
```

## Installation d'Outils DevOps

### Gestionnaires de Paquets

Installer des outils à l'aide des gestionnaires de paquets du système.

```bash
# Ubuntu/Debian
apt update && apt install -y docker.io kubectl terraform
# CentOS/RHEL
yum install -y docker kubernetes-client terraform
# macOS Homebrew
brew install docker kubectl terraform ansible
```

### Installation du Moteur de Conteneurs

Configurer Docker et les outils d'orchestration de conteneurs.

```bash
# Installer Docker
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker
# Installer Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
```

### Outils CLI Cloud

Installer les interfaces de ligne de commande pour les principaux fournisseurs de cloud.

```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && ./aws/install
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
# SDK Google Cloud
curl https://sdk.cloud.google.com | bash
```

## Configuration de l'Environnement

### Gestion des Variables d'Environnement

Gérer la configuration à travers différents environnements de manière sécurisée.

```bash
# Exemple de fichier .env
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=your-api-key-here
ENVIRONMENT=production
# Charger les variables d'environnement
export $(cat .env | xargs)
# Variables d'environnement Docker
docker run -e NODE_ENV=production -e API_KEY=secret myapp
# ConfigMap Kubernetes
kubectl create configmap app-config --from-env-file=.env
```

### Découverte de Services et Configuration

Gérer la découverte de services et la configuration dynamique.

```bash
# Enregistrement de service Consul
consul services register myservice.json
# Santé du service
consul health service web
# Magasin clé-valeur Etcd
etcdctl put /config/database/host localhost
etcdctl get /config/database/host
```

### Configuration de l'Environnement de Développement

Configurer des environnements de développement cohérents à l'aide de conteneurs.

```dockerfile
# Dockerfile de Développement
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

```yaml
# Docker Compose pour le développement
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

### Durcissement de l'Environnement de Production

Sécuriser et optimiser les environnements de production.

```ini
# Configuration de service Systemd
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

## Automatisation et Orchestration

### Automatisation d'Infrastructure avec Ansible

Automatiser le provisionnement d'infrastructure et la gestion de la configuration.

```yaml
# Exemple de playbook Ansible
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

### Orchestration de Flux de Travail

Orchestrer des flux de travail complexes et des pipelines de données.

```python
# Exemple DAG Apache Airflow
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

### Automatisation Pilotée par les Événements

Déclencher l'automatisation en fonction des événements système et des webhooks.

```bash
# Gestionnaire de webhook GitHub
#!/bin/bash
if [ "$1" == "push" ]; then
  git pull origin main
  docker build -t myapp .
  docker run -d --name myapp-$(date +%s) myapp
fi
# Webhook Prometheus alertmanager
curl -X POST http://webhook-handler/deploy \
  -H "Content-Type: application/json" \
  -d '{"service": "myapp", "action": "restart"}'
```

### Intégration ChatOps

Intégrer les opérations DevOps avec des plateformes de chat pour une automatisation collaborative.

```bash
# Exemple de commande de bot Slack
/deploy myapp to production
/rollback myapp to v1.2.3
/scale myapp replicas=5
/status infrastructure
# Webhook Microsoft Teams
curl -H "Content-Type: application/json" \
  -d '{"text": "Deployment completed successfully"}' \
  $TEAMS_WEBHOOK_URL
```

## Liens Pertinents

- <router-link to="/linux">Trombinoscope Linux</router-link>
- <router-link to="/shell">Trombinoscope Shell</router-link>
- <router-link to="/git">Trombinoscope Git</router-link>
- <router-link to="/docker">Trombinoscope Docker</router-link>
- <router-link to="/kubernetes">Trombinoscope Kubernetes</router-link>
- <router-link to="/ansible">Trombinoscope Ansible</router-link>
- <router-link to="/jenkins">Trombinoscope Jenkins</router-link>
- <router-link to="/python">Trombinoscope Python</router-link>

---
title: 'Шпаргалка по DevOps'
description: 'Изучите DevOps с нашей исчерпывающей шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/devops-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
DevOps Шпаргалка
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/devops">Изучите DevOps с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите практики DevOps с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по DevOps, охватывающие основные операции, управление инфраструктурой, конвейеры CI/CD, контейнеризацию, мониторинг и автоматизацию. Научитесь развертывать приложения, управлять инфраструктурой как кодом, автоматизировать рабочие процессы и внедрять современные практики DevOps для эффективной поставки программного обеспечения.
</base-disclaimer-content>
</base-disclaimer>

## Infrastructure as Code (IaC)

### Terraform: Provisioning Инфраструктуры

Определение и предоставление инфраструктуры с использованием декларативного языка конфигурации.

```bash
# Initialize Terraform
terraform init
# Plan infrastructure changes
terraform plan
# Apply infrastructure changes
terraform apply
# Destroy infrastructure
terraform destroy
# Format configuration files
terraform fmt
# Validate configuration
terraform validate
```

### Ansible: Управление Конфигурацией

Автоматизация развертывания приложений и управления конфигурацией.

```bash
# Run playbook
ansible-playbook site.yml
# Run playbook on specific hosts
ansible-playbook -i inventory site.yml
# Check syntax
ansible-playbook --syntax-check site.yml
# Run with specific user
ansible-playbook -u ubuntu site.yml
```

### CloudFormation: Собственный IaC AWS

Предоставление ресурсов AWS с использованием шаблонов JSON/YAML.

```bash
# Create stack
aws cloudformation create-stack --stack-name mystack --template-body file://template.yml
# Update stack
aws cloudformation update-stack --stack-name mystack --template-body file://template.yml
# Delete stack
aws cloudformation delete-stack --stack-name mystack
```

## Управление Контейнерами

### Docker: Контейнеризация

Сборка, доставка и запуск приложений в контейнерах.

```bash
# Build image
docker build -t myapp:latest .
# Run container
docker run -d -p 8080:80 myapp:latest
# List running containers
docker ps
# Stop container
docker stop container_id
# Remove container
docker rm container_id
```

### Kubernetes: Оркестрация Контейнеров

Развертывание и управление контейнеризированными приложениями в масштабе.

```bash
# Apply configuration
kubectl apply -f deployment.yml
# Get pods
kubectl get pods
# Scale deployment
kubectl scale deployment myapp --replicas=5
# View logs
kubectl logs pod_name
# Delete resources
kubectl delete -f deployment.yml
```

### Helm: Менеджер Пакетов Kubernetes

Управление приложениями Kubernetes с помощью чартов.

```bash
# Install chart
helm install myrelease stable/nginx
# Upgrade release
helm upgrade myrelease stable/nginx
# List releases
helm list
# Uninstall release
helm uninstall myrelease
```

## Управление CI/CD Конвейерами

### Jenkins: Автоматизация Сборки

Настройка и управление конвейерами непрерывной интеграции.

```groovy
// Jenkinsfile example
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

### GitHub Actions: Облачный CI/CD

Автоматизация рабочих процессов непосредственно из репозиториев GitHub.

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

### GitLab CI: Интегрированный DevOps

Использование встроенных возможностей CI/CD GitLab для полных рабочих процессов DevOps.

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

## Контроль Версий и Сотрудничество

### Git: Система Контроля Версий

Отслеживание изменений и совместная работа над разработкой кода.

```bash
# Clone repository
git clone https://github.com/user/repo.git
# Check status
git status
# Add changes
git add .
# Commit changes
git commit -m "Add feature"
# Push to remote
git push origin main
# Pull latest changes
git pull origin main
```

### Управление Ветками

Управление различными потоками разработки и выпусками.

```bash
# Create branch
git checkout -b feature-branch
# Merge branch
git merge feature-branch
# List branches
git branch -a
# Switch branch
git checkout main
# Delete branch
git branch -d feature-branch
# Reset to previous commit
git reset --hard HEAD~1
# View commit history
git log --oneline
```

### GitHub: Хостинг Кода и Сотрудничество

Размещение репозиториев и управление совместной разработкой.

```bash
# GitHub CLI commands
gh repo create myrepo
gh repo clone user/repo
gh pr create --title "New feature"
gh pr list
gh pr merge 123
gh issue create --title "Bug report"
gh release create v1.0.0
# Create pull request
git push -u origin feature-branch
# Then create PR on GitHub/GitLab
```

### Code Review и Качество Кода

Обеспечение качества кода посредством взаимного обзора и автоматизированных проверок.

```bash
# Pre-commit hooks example
#!/bin/sh
# Run tests before commit
npm test
if [ $? -ne 0 ]; then
  echo "Tests failed"
  exit 1
fi
```

## Мониторинг и Наблюдаемость

### Prometheus: Сбор Метрик

Мониторинг системных и прикладных метрик с помощью временных рядов данных.

```promql
# CPU usage
cpu_usage_percent{instance="server1"}
# Memory usage
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
# HTTP request rate
rate(http_requests_total[5m])
# Alert rules example
ALERT HighCPUUsage
  IF cpu_usage_percent > 80
  FOR 5m
```

### Grafana: Панель Визуализации

Создание панелей мониторинга и визуализаций для данных мониторинга.

```bash
# Create dashboard
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json
# Get dashboard
curl http://admin:admin@localhost:3000/api/dashboards/uid/dashboard-uid
```

### Стек ELK: Управление Логами

Сбор, поиск и анализ данных журналов в инфраструктуре.

```json
# Elasticsearch queries
# Search logs
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
# Logstash configuration
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

### Мониторинг Производительности Приложений

Отслеживание производительности приложений и метрик пользовательского опыта.

```ruby
# New Relic agent setup
# Add to application
require 'newrelic_rpm'
```

```python
# Datadog metrics
from datadog import DogStatsdClient
statsd = DogStatsdClient('localhost', 8125)
statsd.increment('web.requests')
statsd.histogram('web.response_time', 0.75)
```

## Управление Облачными Платформами

### AWS CLI: Amazon Web Services

Взаимодействие с сервисами AWS из командной строки.

```bash
# Configure AWS CLI
aws configure
# List EC2 instances
aws ec2 describe-instances
# Create S3 bucket
aws s3 mb s3://my-bucket-name
# Deploy Lambda function
aws lambda create-function --function-name myfunction --runtime python3.8 --role arn:aws:iam::123456789:role/lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip
# List running services
aws ecs list-services --cluster my-cluster
```

### Azure CLI: Microsoft Azure

Управление ресурсами и сервисами Azure.

```bash
# Login to Azure
az login
# Create resource group
az group create --name myResourceGroup --location eastus
# Create virtual machine
az vm create --resource-group myResourceGroup --name myVM --image Ubuntu2204 --admin-username azureuser --generate-ssh-keys
# List web apps
az webapp list
```

### Google Cloud: GCP

Развертывание и управление приложениями на Google Cloud Platform.

```bash
# Authenticate with GCP
gcloud auth login
# Set project
gcloud config set project my-project-id
# Deploy App Engine application
gcloud app deploy
# Create Compute Engine instance
gcloud compute instances create my-instance --zone=us-central1-a
# Manage Kubernetes cluster
gcloud container clusters create my-cluster --num-nodes=3
```

### Multi-Cloud Management

Инструменты для управления ресурсами в нескольких облачных провайдерах.

```python
# Pulumi (multi-cloud IaC)
import pulumi_aws as aws
import pulumi_gcp as gcp
# Create AWS S3 bucket
bucket = aws.s3.Bucket("my-bucket")
# Create GCP storage bucket
gcp_bucket = gcp.storage.Bucket("my-gcp-bucket")
```

## Управление Безопасностью и Секретами

### HashiCorp Vault: Управление Секретами

HashiCorp Vault — это инструмент для безопасного доступа к секретам. Секрет — это все, к чему вы хотите строго контролировать доступ, например, ключи API, пароли или сертификаты.

```bash
# Write a secret
vault kv put secret/myapp/config username=myuser password=mypassword
# Read a secret
vault kv get secret/myapp/config
# Delete a secret
vault kv delete secret/myapp/config
# Enable auth method
vault auth enable kubernetes
# Create policy
vault policy write myapp-policy myapp-policy.hcl
```

### Сканирование Безопасности: Trivy & SonarQube

Сканирование контейнеров и кода на наличие уязвимостей безопасности.

```bash
# Trivy container scanning
trivy image nginx:latest
# Scan filesystem
trivy fs /path/to/project
# SonarQube analysis
sonar-scanner -Dsonar.projectKey=myproject -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000
```

### Управление SSL/TLS Сертификатами

Управление SSL-сертификатами для безопасной связи.

```bash
# Let's Encrypt with Certbot
certbot --nginx -d example.com
# Renew certificates
certbot renew
# Check certificate expiry
openssl x509 -in cert.pem -text -noout | grep "Not After"
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

### Безопасность Контейнеров

Защита контейнеризированных приложений и сред выполнения.

```bash
# Run container as non-root user
docker run --user 1000:1000 myapp
# Scan image for vulnerabilities
docker scan myapp:latest
```

```dockerfile
# Use distroless images
FROM gcr.io/distroless/java:11
COPY app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## Оптимизация Производительности

### Мониторинг Производительности Системы

Независимо от того, управляете ли вы серверами, настраиваете развертывания или исправляете что-то, что только что сломалось в продакшене, эти команды помогут вам работать быстрее и умнее.

```bash
# CPU and memory usage
htop
# Disk usage
df -h
# Network connections
netstat -tulpn
# Process monitoring
ps aux | grep process_name
# System load
uptime
# Memory details
free -h
```

### Настройка Производительности Приложений

Оптимизация производительности приложений и утилизации ресурсов.

```bash
# JVM performance monitoring
jstat -gc -t PID 1s
# Node.js performance
node --inspect app.js
# Database query optimization
EXPLAIN ANALYZE SELECT * FROM table WHERE condition;
# Nginx performance tuning
nginx -t && nginx -s reload
```

### Тестирование Нагрузки и Бенчмаркинг

Тестирование производительности приложений в различных условиях нагрузки.

```bash
# Apache Bench
ab -n 1000 -c 10 http://example.com/
# wrk HTTP benchmarking
wrk -t12 -c400 -d30s http://example.com/
# Artillery load testing
artillery run load-test.yml
# Kubernetes horizontal pod autoscaler
kubectl autoscale deployment myapp --cpu-percent=70 --min=1 --max=10
```

### Производительность Базы Данных

Мониторинг и оптимизация производительности и запросов базы данных.

```sql
# MySQL performance
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Threads_connected';
```

```sql
# PostgreSQL monitoring
SELECT * FROM pg_stat_activity;
```

```bash
# Redis monitoring
redis-cli --latency
redis-cli info memory
```

## Установка Инструментов DevOps

### Менеджеры Пакетов

Установка инструментов с использованием системных менеджеров пакетов.

```bash
# Ubuntu/Debian
apt update && apt install -y docker.io kubectl terraform
# CentOS/RHEL
yum install -y docker kubernetes-client terraform
# macOS Homebrew
brew install docker kubectl terraform ansible
```

### Установка Среды Выполнения Контейнеров

Настройка Docker и инструментов оркестрации контейнеров.

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker
# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
```

### Инструменты Командной Строки Облачных Платформ

Установка интерфейсов командной строки для основных облачных провайдеров.

```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && ./aws/install
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
# Google Cloud SDK
curl https://sdk.cloud.google.com | bash
```

## Конфигурация Среды

### Управление Переменными Окружения

Безопасное управление конфигурацией в различных средах.

```bash
# .env file example
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=your-api-key-here
ENVIRONMENT=production
# Load environment variables
export $(cat .env | xargs)
# Docker environment variables
docker run -e NODE_ENV=production -e API_KEY=secret myapp
# Kubernetes configmap
kubectl create configmap app-config --from-env-file=.env
```

### Обнаружение Сервисов и Конфигурация

Управление обнаружением сервисов и динамической конфигурацией.

```bash
# Consul service registration
consul services register myservice.json
# Get service health
consul health service web
# Etcd key-value store
etcdctl put /config/database/host localhost
etcdctl get /config/database/host
```

### Настройка Среды Разработки

Настройка согласованных сред разработки с использованием контейнеров.

```dockerfile
# Development Dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

```yaml
# Docker Compose for development
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

### Укрепление Производственной Среды

Защита и оптимизация производственных сред.

```ini
# Systemd service configuration
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

## Автоматизация и Оркестрация

### Автоматизация Инфраструктуры с Ansible

Автоматизация предоставления инфраструктуры и управления конфигурацией.

```yaml
# Ansible playbook example
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

### Оркестрация Рабочих Процессов

Оркестрация сложных рабочих процессов и конвейеров данных.

```python
# Apache Airflow DAG example
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

### Автоматизация, Управляемая Событиями

Запуск автоматизации на основе системных событий и вебхуков.

```bash
# GitHub webhook handler
#!/bin/bash
if [ "$1" == "push" ]; then
  git pull origin main
  docker build -t myapp .
  docker run -d --name myapp-$(date +%s) myapp
fi
# Prometheus alertmanager webhook
curl -X POST http://webhook-handler/deploy \
  -H "Content-Type: application/json" \
  -d '{"service": "myapp", "action": "restart"}'
```

### Интеграция ChatOps

Интеграция операций DevOps с платформами чата для совместной автоматизации.

```bash
# Slack bot command example
/deploy myapp to production
/rollback myapp to v1.2.3
/scale myapp replicas=5
/status infrastructure
# Microsoft Teams webhook
curl -H "Content-Type: application/json" \
  -d '{"text": "Deployment completed successfully"}' \
  $TEAMS_WEBHOOK_URL
```

## Соответствующие Ссылки

- <router-link to="/linux">Linux Шпаргалка</router-link>
- <router-link to="/shell">Shell Шпаргалка</router-link>
- <router-link to="/git">Git Шпаргалка</router-link>
- <router-link to="/docker">Docker Шпаргалка</router-link>
- <router-link to="/kubernetes">Kubernetes Шпаргалка</router-link>
- <router-link to="/ansible">Ansible Шпаргалка</router-link>
- <router-link to="/jenkins">Jenkins Шпаргалка</router-link>
- <router-link to="/python">Python Шпаргалка</router-link>

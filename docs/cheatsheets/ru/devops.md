---
title: 'Шпаргалка по DevOps | LabEx'
description: 'Изучите практики DevOps с помощью этой комплексной шпаргалки. Краткий справочник по CI/CD, автоматизации, инфраструктуре как коду, мониторингу, контейнеризации и современным рабочим процессам доставки ПО.'
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
Изучите практики DevOps с помощью практических лабораторий и сценариев реального мира. LabEx предлагает комплексные курсы по DevOps, охватывающие основные операции, управление инфраструктурой, конвейеры CI/CD, контейнеризацию, мониторинг и автоматизацию. Научитесь развертывать приложения, управлять инфраструктурой как кодом, автоматизировать рабочие процессы и внедрять современные практики DevOps для эффективной поставки программного обеспечения.
</base-disclaimer-content>
</base-disclaimer>

## Infrastructure as Code (IaC)

### Terraform: Provisioning Инфраструктуры

Определение и предоставление инфраструктуры с использованием декларативного языка конфигурации.

```bash
# Инициализация Terraform
terraform init
# Планирование изменений инфраструктуры
terraform plan
# Применение изменений инфраструктуры
terraform apply
# Уничтожение инфраструктуры
terraform destroy
# Форматирование файлов конфигурации
terraform fmt
# Проверка конфигурации
terraform validate
```

<BaseQuiz id="devops-terraform-1" correct="B">
  <template #question>
    Что делает команда <code>terraform plan</code>?
  </template>
  
  <BaseQuizOption value="A">Немедленно применяет изменения инфраструктуры</BaseQuizOption>
  <BaseQuizOption value="B" correct>Показывает, какие изменения будут внесены, без их применения</BaseQuizOption>
  <BaseQuizOption value="C">Уничтожает всю инфраструктуру</BaseQuizOption>
  <BaseQuizOption value="D">Инициализирует Terraform</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>terraform plan</code> создает план выполнения, показывающий, что Terraform сделает при запуске <code>terraform apply</code>. Это пробный запуск, который помогает просмотреть изменения перед их применением.
  </BaseQuizAnswer>
</BaseQuiz>

### Ansible: Управление Конфигурацией

Автоматизация развертывания приложений и управления конфигурацией.

```bash
# Запуск плейбука
ansible-playbook site.yml
# Запуск плейбука на определенных хостах
ansible-playbook -i inventory site.yml
# Проверка синтаксиса
ansible-playbook --syntax-check site.yml
# Запуск с указанием пользователя
ansible-playbook -u ubuntu site.yml
```

### CloudFormation: Собственный IaC для AWS

Предоставление ресурсов AWS с использованием шаблонов JSON/YAML.

```bash
# Создание стека
aws cloudformation create-stack --stack-name mystack --template-body file://template.yml
# Обновление стека
aws cloudformation update-stack --stack-name mystack --template-body file://template.yml
# Удаление стека
aws cloudformation delete-stack --stack-name mystack
```

## Управление Контейнерами

### Docker: Контейнеризация

Сборка, доставка и запуск приложений в контейнерах.

```bash
# Сборка образа
docker build -t myapp:latest .
# Запуск контейнера
docker run -d -p 8080:80 myapp:latest
# Список запущенных контейнеров
docker ps
# Остановка контейнера
docker stop container_id
# Удаление контейнера
docker rm container_id
```

### Kubernetes: Оркестрация Контейнеров

Развертывание и управление контейнеризированными приложениями в масштабе.

```bash
# Применение конфигурации
kubectl apply -f deployment.yml
# Получение подов
kubectl get pods
# Масштабирование развертывания
kubectl scale deployment myapp --replicas=5
# Просмотр логов
kubectl logs pod_name
# Удаление ресурсов
kubectl delete -f deployment.yml
```

<BaseQuiz id="devops-k8s-1" correct="A">
  <template #question>
    Что делает команда <code>kubectl apply -f deployment.yml</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Создает или обновляет ресурсы, определенные в YAML-файле</BaseQuizOption>
  <BaseQuizOption value="B">Удаляет все ресурсы в кластере</BaseQuizOption>
  <BaseQuizOption value="C">Создает только новые ресурсы</BaseQuizOption>
  <BaseQuizOption value="D">Показывает, что будет создано, без применения</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>kubectl apply</code> — это декларативная команда, которая создает ресурсы, если они не существуют, или обновляет их, если существуют. Она идемпотентна, то есть ее можно безопасно запускать несколько раз.
  </BaseQuizAnswer>
</BaseQuiz>

### Helm: Менеджер Пакетов Kubernetes

Управление приложениями Kubernetes с помощью чартов.

```bash
# Установка чарта
helm install myrelease stable/nginx
# Обновление релиза
helm upgrade myrelease stable/nginx
# Список релизов
helm list
# Удаление релиза
helm uninstall myrelease
```

## Управление CI/CD Конвейерами

### Jenkins: Автоматизация Сборки

Настройка и управление конвейерами непрерывной интеграции.

```groovy
// Пример Jenkinsfile
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
# Клонирование репозитория
git clone https://github.com/user/repo.git
# Проверка статуса
git status
# Добавление изменений
git add .
# Фиксация изменений
git commit -m "Add feature"
# Отправка на удаленный репозиторий
git push origin main
# Получение последних изменений
git pull origin main
```

<BaseQuiz id="devops-git-1" correct="D">
  <template #question>
    В чем разница между <code>git pull</code> и <code>git fetch</code>?
  </template>
  
  <BaseQuizOption value="A">Разницы нет</BaseQuizOption>
  <BaseQuizOption value="B">git pull отправляет изменения, git fetch получает изменения</BaseQuizOption>
  <BaseQuizOption value="C">git pull работает локально, git fetch работает удаленно</BaseQuizOption>
  <BaseQuizOption value="D" correct>git fetch загружает изменения без слияния, git pull загружает и сливает изменения</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>git fetch</code> загружает изменения из удаленного репозитория, но не сливает их в вашу текущую ветку. <code>git pull</code> выполняет обе операции: он получает, а затем сливает изменения.
  </BaseQuizAnswer>
</BaseQuiz>

### Управление Ветками

Управление различными потоками разработки и выпусками.

```bash
# Создание ветки
git checkout -b feature-branch
# Слияние ветки
git merge feature-branch
# Список веток
git branch -a
# Переключение ветки
git checkout main
# Удаление ветки
git branch -d feature-branch
# Сброс к предыдущему коммиту
git reset --hard HEAD~1
# Просмотр истории коммитов
git log --oneline
```

### GitHub: Хостинг Кода и Сотрудничество

Размещение репозиториев и управление совместной разработкой.

```bash
# Команды GitHub CLI
gh repo create myrepo
gh repo clone user/repo
gh pr create --title "New feature"
gh pr list
gh pr merge 123
gh issue create --title "Bug report"
gh release create v1.0.0
# Создание pull request
git push -u origin feature-branch
# Затем создание PR на GitHub/GitLab
```

### Code Review и Качество Кода

Обеспечение качества кода посредством взаимного обзора и автоматизированных проверок.

```bash
# Пример pre-commit хуков
#!/bin/sh
# Запуск тестов перед коммитом
npm test
if [ $? -ne 0 ]; then
  echo "Tests failed"
  exit 1
fi
```

## Мониторинг и Наблюдаемость

### Prometheus: Сбор Метрик

Мониторинг метрик системы и приложений с помощью данных временных рядов.

```promql
# Использование ЦП
cpu_usage_percent{instance="server1"}
# Использование памяти
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
# Частота HTTP-запросов
rate(http_requests_total[5m])
# Пример правил оповещения
ALERT HighCPUUsage
  IF cpu_usage_percent > 80
  FOR 5m
```

### Grafana: Панели Визуализации

Создание панелей и визуализаций для данных мониторинга.

```bash
# Создание панели
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json
# Получение панели
curl http://admin:admin@localhost:3000/api/dashboards/uid/dashboard-uid
```

### Стек ELK: Управление Логами

Сбор, поиск и анализ данных логов в инфраструктуре.

```json
# Запросы Elasticsearch
# Поиск логов
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
# Конфигурация Logstash
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
# Настройка агента New Relic
# Добавить в приложение
require 'newrelic_rpm'
```

```python
# Метрики Datadog
from datadog import DogStatsdClient
statsd = DogStatsdClient('localhost', 8125)
statsd.increment('web.requests')
statsd.histogram('web.response_time', 0.75)
```

## Управление Облачными Платформами

### AWS CLI: Amazon Web Services

Взаимодействие с сервисами AWS из командной строки.

```bash
# Настройка AWS CLI
aws configure
# Список инстансов EC2
aws ec2 describe-instances
# Создание бакета S3
aws s3 mb s3://my-bucket-name
# Развертывание функции Lambda
aws lambda create-function --function-name myfunction --runtime python3.8 --role arn:aws:iam::123456789:role/lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip
# Список запущенных сервисов
aws ecs list-services --cluster my-cluster
```

### Azure CLI: Microsoft Azure

Управление ресурсами и сервисами Azure.

```bash
# Вход в Azure
az login
# Создание группы ресурсов
az group create --name myResourceGroup --location eastus
# Создание виртуальной машины
az vm create --resource-group myResourceGroup --name myVM --image Ubuntu2204 --admin-username azureuser --generate-ssh-keys
# Список веб-приложений
az webapp list
```

### Google Cloud: GCP

Развертывание и управление приложениями на Google Cloud Platform.

```bash
# Аутентификация в GCP
gcloud auth login
# Установка проекта
gcloud config set project my-project-id
# Развертывание приложения App Engine
gcloud app deploy
# Создание инстанса Compute Engine
gcloud compute instances create my-instance --zone=us-central1-a
# Управление кластером Kubernetes
gcloud container clusters create my-cluster --num-nodes=3
```

### Мультиоблачное Управление

Инструменты для управления ресурсами в нескольких облачных провайдерах.

```python
# Pulumi (мультиоблачный IaC)
import pulumi_aws as aws
import pulumi_gcp as gcp
# Создание бакета AWS S3
bucket = aws.s3.Bucket("my-bucket")
# Создание бакета GCP storage
gcp_bucket = gcp.storage.Bucket("my-gcp-bucket")
```

## Управление Безопасностью и Секретами

### HashiCorp Vault: Управление Секретами

HashiCorp Vault — это инструмент для безопасного доступа к секретам. Секрет — это все, к чему вы хотите строго контролировать доступ, например, ключи API, пароли или сертификаты.

```bash
# Запись секрета
vault kv put secret/myapp/config username=myuser password=mypassword
# Чтение секрета
vault kv get secret/myapp/config
# Удаление секрета
vault kv delete secret/myapp/config
# Включение метода аутентификации
vault auth enable kubernetes
# Создание политики
vault policy write myapp-policy myapp-policy.hcl
```

### Сканирование Безопасности: Trivy & SonarQube

Сканирование контейнеров и кода на наличие уязвимостей безопасности.

```bash
# Сканирование контейнера Trivy
trivy image nginx:latest
# Сканирование файловой системы
trivy fs /path/to/project
# Анализ SonarQube
sonar-scanner -Dsonar.projectKey=myproject -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000
```

### Управление SSL/TLS Сертификатами

Управление SSL-сертификатами для безопасной связи.

```bash
# Let's Encrypt с Certbot
certbot --nginx -d example.com
# Продление сертификатов
certbot renew
# Проверка срока действия сертификата
openssl x509 -in cert.pem -text -noout | grep "Not After"
# Генерация самоподписанного сертификата
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

### Безопасность Контейнеров

Защита контейнеризированных приложений и сред выполнения.

```bash
# Запуск контейнера от имени непривилегированного пользователя
docker run --user 1000:1000 myapp
# Сканирование образа на уязвимости
docker scan myapp:latest
```

```dockerfile
# Использование образов distroless
FROM gcr.io/distroless/java:11
COPY app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## Оптимизация Производительности

### Мониторинг Производительности Системы

Независимо от того, управляете ли вы серверами, настраиваете развертывания или исправляете что-то, что только что сломалось в продакшене, эти команды помогут вам работать быстрее и умнее.

```bash
# Использование ЦП и памяти
htop
# Использование диска
df -h
# Сетевые подключения
netstat -tulpn
# Мониторинг процессов
ps aux | grep process_name
# Нагрузка системы
uptime
# Детали памяти
free -h
```

### Настройка Производительности Приложений

Оптимизация производительности приложений и утилизации ресурсов.

```bash
# Мониторинг производительности JVM
jstat -gc -t PID 1s
# Производительность Node.js
node --inspect app.js
# Оптимизация запросов к базе данных
EXPLAIN ANALYZE SELECT * FROM table WHERE condition;
# Настройка Nginx
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
# Производительность MySQL
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Threads_connected';
```

```sql
# Мониторинг PostgreSQL
SELECT * FROM pg_stat_activity;
```

```bash
# Мониторинг Redis
redis-cli --latency
redis-cli info memory
```

## Установка Инструментов

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
# Установка Docker
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker
# Установка Docker Compose
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

## Конфигурация Окружения

### Управление Переменными Окружения

Управление конфигурацией в различных средах безопасно.

```bash
# Пример файла .env
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=your-api-key-here
ENVIRONMENT=production
# Загрузка переменных окружения
export $(cat .env | xargs)
# Переменные окружения Docker
docker run -e NODE_ENV=production -e API_KEY=secret myapp
# Kubernetes configmap
kubectl create configmap app-config --from-env-file=.env
```

### Обнаружение Сервисов и Конфигурация

Управление обнаружением сервисов и динамической конфигурацией.

```bash
# Регистрация сервиса Consul
consul services register myservice.json
# Проверка здоровья сервиса
consul health service web
# Хранилище ключ-значение Etcd
etcdctl put /config/database/host localhost
etcdctl get /config/database/host
```

### Настройка Среды Разработки

Настройка согласованных сред разработки с использованием контейнеров.

```dockerfile
# Dockerfile для разработки
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

```yaml
# Docker Compose для разработки
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
# Конфигурация сервиса Systemd
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
# Пример плейбука Ansible
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
# Пример DAG Apache Airflow
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

### Автоматизация на Основе Событий

Запуск автоматизации на основе системных событий и вебхуков.

```bash
# Обработчик вебхука GitHub
#!/bin/bash
if [ "$1" == "push" ]; then
  git pull origin main
  docker build -t myapp .
  docker run -d --name myapp-$(date +%s) myapp
fi
# Вебхук Prometheus alertmanager
curl -X POST http://webhook-handler/deploy \
  -H "Content-Type: application/json" \
  -d '{"service": "myapp", "action": "restart"}'
```

### Интеграция ChatOps

Интеграция операций DevOps с платформами чата для совместной автоматизации.

```bash
# Пример команды бота Slack
/deploy myapp to production
/rollback myapp to v1.2.3
/scale myapp replicas=5
/status infrastructure
# Вебхук Microsoft Teams
curl -H "Content-Type: application/json" \
  -d '{"text": "Deployment completed successfully"}' \
  $TEAMS_WEBHOOK_URL
```

## Соответствующие Ссылки

- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/git">Шпаргалка по Git</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>
- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>
- <router-link to="/ansible">Шпаргалка по Ansible</router-link>
- <router-link to="/jenkins">Шпаргалка по Jenkins</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>

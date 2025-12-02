---
title: 'DevOps Cheatsheet | LabEx'
description: 'Learn DevOps practices with this comprehensive cheatsheet. Quick reference for CI/CD, automation, infrastructure as code, monitoring, containerization, and modern software delivery workflows.'
pdfUrl: '/cheatsheets/pdf/devops-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
DevOps Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/devops">Learn DevOps with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn DevOps practices through hands-on labs and real-world scenarios. LabEx provides comprehensive DevOps courses covering essential operations, infrastructure management, CI/CD pipelines, containerization, monitoring, and automation. Learn to deploy applications, manage infrastructure as code, automate workflows, and implement modern DevOps practices for efficient software delivery.
</base-disclaimer-content>
</base-disclaimer>

## Infrastructure as Code (IaC)

### Terraform: Infrastructure Provisioning

Define and provision infrastructure using declarative configuration language.

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

<BaseQuiz id="devops-terraform-1" correct="B">
  <template #question>
    What does `terraform plan` do?
  </template>
  
  <BaseQuizOption value="A">Applies infrastructure changes immediately</BaseQuizOption>
  <BaseQuizOption value="B" correct>Shows what changes will be made without applying them</BaseQuizOption>
  <BaseQuizOption value="C">Destroys all infrastructure</BaseQuizOption>
  <BaseQuizOption value="D">Initializes Terraform</BaseQuizOption>
  
  <BaseQuizAnswer>
    `terraform plan` creates an execution plan showing what Terraform will do when you run `terraform apply`. It's a dry-run that helps you review changes before applying them.
  </BaseQuizAnswer>
</BaseQuiz>

### Ansible: Configuration Management

Automate application deployment and configuration management.

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

### CloudFormation: AWS Native IaC

Provision AWS resources using JSON/YAML templates.

```bash
# Create stack
aws cloudformation create-stack --stack-name mystack --template-body file://template.yml
# Update stack
aws cloudformation update-stack --stack-name mystack --template-body file://template.yml
# Delete stack
aws cloudformation delete-stack --stack-name mystack
```

## Container Management

### Docker: Containerization

Build, ship, and run applications in containers.

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

### Kubernetes: Container Orchestration

Deploy and manage containerized applications at scale.

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

<BaseQuiz id="devops-k8s-1" correct="A">
  <template #question>
    What does `kubectl apply -f deployment.yml` do?
  </template>
  
  <BaseQuizOption value="A" correct>Creates or updates resources defined in the YAML file</BaseQuizOption>
  <BaseQuizOption value="B">Deletes all resources in the cluster</BaseQuizOption>
  <BaseQuizOption value="C">Only creates new resources</BaseQuizOption>
  <BaseQuizOption value="D">Shows what would be created without applying</BaseQuizOption>
  
  <BaseQuizAnswer>
    `kubectl apply` is a declarative command that creates resources if they don't exist or updates them if they do. It's idempotent, meaning you can run it multiple times safely.
  </BaseQuizAnswer>
</BaseQuiz>

### Helm: Kubernetes Package Manager

Manage Kubernetes applications using charts.

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

## CI/CD Pipeline Management

### Jenkins: Build Automation

Set up and manage continuous integration pipelines.

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

### GitHub Actions: Cloud CI/CD

Automate workflows directly from GitHub repositories.

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

### GitLab CI: Integrated DevOps

Use GitLab's built-in CI/CD capabilities for complete DevOps workflows.

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

## Version Control & Collaboration

### Git: Version Control System

Track changes and collaborate on code development.

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

<BaseQuiz id="devops-git-1" correct="D">
  <template #question>
    What is the difference between `git pull` and `git fetch`?
  </template>
  
  <BaseQuizOption value="A">There is no difference</BaseQuizOption>
  <BaseQuizOption value="B">git pull pushes changes, git fetch pulls changes</BaseQuizOption>
  <BaseQuizOption value="C">git pull works locally, git fetch works remotely</BaseQuizOption>
  <BaseQuizOption value="D" correct>git fetch downloads changes without merging, git pull downloads and merges changes</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git fetch` downloads changes from the remote repository but doesn't merge them into your current branch. `git pull` performs both operations: it fetches and then merges the changes.
  </BaseQuizAnswer>
</BaseQuiz>

### Branch Management

Manage different development streams and releases.

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

### GitHub: Code Hosting & Collaboration

Host repositories and manage collaborative development.

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

### Code Review & Quality

Ensure code quality through peer review and automated checks.

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

## Monitoring & Observability

### Prometheus: Metrics Collection

Monitor system and application metrics with time-series data.

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

### Grafana: Visualization Dashboard

Create dashboards and visualizations for monitoring data.

```bash
# Create dashboard
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json
# Get dashboard
curl http://admin:admin@localhost:3000/api/dashboards/uid/dashboard-uid
```

### ELK Stack: Log Management

Collect, search, and analyze log data across infrastructure.

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

### Application Performance Monitoring

Track application performance and user experience metrics.

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

## Cloud Platform Management

### AWS CLI: Amazon Web Services

Interact with AWS services from command line.

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

Manage Azure resources and services.

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

Deploy and manage applications on Google Cloud Platform.

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

Tools for managing resources across multiple cloud providers.

```python
# Pulumi (multi-cloud IaC)
import pulumi_aws as aws
import pulumi_gcp as gcp
# Create AWS S3 bucket
bucket = aws.s3.Bucket("my-bucket")
# Create GCP storage bucket
gcp_bucket = gcp.storage.Bucket("my-gcp-bucket")
```

## Security & Secrets Management

### HashiCorp Vault: Secrets Management

HashiCorp Vault is a tool for securely accessing secrets. A secret is anything that you want to tightly control access to, such as API keys, passwords, or certificates.

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

### Security Scanning: Trivy & SonarQube

Scan containers and code for security vulnerabilities.

```bash
# Trivy container scanning
trivy image nginx:latest
# Scan filesystem
trivy fs /path/to/project
# SonarQube analysis
sonar-scanner -Dsonar.projectKey=myproject -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000
```

### SSL/TLS Certificate Management

Manage SSL certificates for secure communications.

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

### Container Security

Secure containerized applications and runtime environments.

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

## Performance Optimization

### System Performance Monitoring

Whether you're managing servers, setting up deployments, or fixing something that just broke in production, these commands help you move faster and work smarter.

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

### Application Performance Tuning

Optimize application performance and resource utilization.

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

### Load Testing & Benchmarking

Test application performance under various load conditions.

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

### Database Performance

Monitor and optimize database performance and queries.

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

## DevOps Tool Installation

### Package Managers

Install tools using system package managers.

```bash
# Ubuntu/Debian
apt update && apt install -y docker.io kubectl terraform
# CentOS/RHEL
yum install -y docker kubernetes-client terraform
# macOS Homebrew
brew install docker kubectl terraform ansible
```

### Container Runtime Installation

Set up Docker and container orchestration tools.

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker
# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
```

### Cloud CLI Tools

Install command-line interfaces for major cloud providers.

```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && ./aws/install
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
# Google Cloud SDK
curl https://sdk.cloud.google.com | bash
```

## Environment Configuration

### Environment Variables Management

Manage configuration across different environments securely.

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

### Service Discovery & Configuration

Manage service discovery and dynamic configuration.

```bash
# Consul service registration
consul services register myservice.json
# Get service health
consul health service web
# Etcd key-value store
etcdctl put /config/database/host localhost
etcdctl get /config/database/host
```

### Development Environment Setup

Set up consistent development environments using containers.

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

### Production Environment Hardening

Secure and optimize production environments.

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

## Automation & Orchestration

### Infrastructure Automation with Ansible

Automate infrastructure provisioning and configuration management.

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

### Workflow Orchestration

Orchestrate complex workflows and data pipelines.

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

### Event-Driven Automation

Trigger automation based on system events and webhooks.

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

### ChatOps Integration

Integrate DevOps operations with chat platforms for collaborative automation.

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

## Relevant Links

- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/shell">Shell Cheatsheet</router-link>
- <router-link to="/git">Git Cheatsheet</router-link>
- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/kubernetes">Kubernetes Cheatsheet</router-link>
- <router-link to="/ansible">Ansible Cheatsheet</router-link>
- <router-link to="/jenkins">Jenkins Cheatsheet</router-link>
- <router-link to="/python">Python Cheatsheet</router-link>

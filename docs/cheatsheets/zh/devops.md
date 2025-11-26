---
title: 'DevOps 速查表'
description: '使用我们的综合速查表学习 DevOps，涵盖基本命令、概念和最佳实践。'
pdfUrl: '/cheatsheets/pdf/devops-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
DevOps 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/devops">通过实践实验室学习 DevOps</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 DevOps 实践。LabEx 提供全面的 DevOps 课程，涵盖基本操作、基础设施管理、CI/CD 流水线、容器化、监控和自动化。学习部署应用程序、将基础设施即代码化、自动化工作流程以及实施现代 DevOps 实践以实现高效的软件交付。
</base-disclaimer-content>
</base-disclaimer>

## 基础设施即代码 (IaC)

### Terraform: 基础设施配置

使用声明性配置文件语言定义和配置基础设施。

```bash
# 初始化 Terraform
terraform init
# 规划基础设施变更
terraform plan
# 应用基础设施变更
terraform apply
# 销毁基础设施
terraform destroy
# 格式化配置文件
terraform fmt
# 验证配置
terraform validate
```

### Ansible: 配置管理

自动化应用程序部署和配置管理。

```bash
# 运行 playbook
ansible-playbook site.yml
# 在特定主机上运行 playbook
ansible-playbook -i inventory site.yml
# 检查语法
ansible-playbook --syntax-check site.yml
# 使用特定用户运行
ansible-playbook -u ubuntu site.yml
```

### CloudFormation: AWS 原生 IaC

使用 JSON/YAML 模板配置 AWS 资源。

```bash
# 创建堆栈
aws cloudformation create-stack --stack-name mystack --template-body file://template.yml
# 更新堆栈
aws cloudformation update-stack --stack-name mystack --template-body file://template.yml
# 删除堆栈
aws cloudformation delete-stack --stack-name mystack
```

## 容器管理

### Docker: 容器化

构建、分发和运行容器中的应用程序。

```bash
# 构建镜像
docker build -t myapp:latest .
# 运行容器
docker run -d -p 8080:80 myapp:latest
# 列出正在运行的容器
docker ps
# 停止容器
docker stop container_id
# 删除容器
docker rm container_id
```

### Kubernetes: 容器编排

大规模部署和管理容器化应用程序。

```bash
# 应用配置
kubectl apply -f deployment.yml
# 获取 Pods
kubectl get pods
# 缩放部署
kubectl scale deployment myapp --replicas=5
# 查看日志
kubectl logs pod_name
# 删除资源
kubectl delete -f deployment.yml
```

### Helm: Kubernetes 包管理器

使用 Chart 管理 Kubernetes 应用程序。

```bash
# 安装 Chart
helm install myrelease stable/nginx
# 升级发布
helm upgrade myrelease stable/nginx
# 列出发布
helm list
# 卸载发布
helm uninstall myrelease
```

## CI/CD 流水线管理

### Jenkins: 构建自动化

设置和管理持续集成流水线。

```groovy
// Jenkinsfile 示例
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

### GitHub Actions: 云 CI/CD

直接从 GitHub 仓库自动化工作流程。

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

### GitLab CI: 集成 DevOps

使用 GitLab 内置的 CI/CD 功能实现完整的 DevOps 工作流程。

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

## 版本控制与协作

### Git: 版本控制系统

跟踪变更并在代码开发中进行协作。

```bash
# 克隆仓库
git clone https://github.com/user/repo.git
# 查看状态
git status
# 添加变更
git add .
# 提交变更
git commit -m "Add feature"
# 推送到远程
git push origin main
# 拉取最新变更
git pull origin main
```

### 分支管理

管理不同的开发流和发布版本。

```bash
# 创建分支
git checkout -b feature-branch
# 合并分支
git merge feature-branch
# 列出分支
git branch -a
# 切换分支
git checkout main
# 删除分支
git branch -d feature-branch
# 硬重置到上一个提交
git reset --hard HEAD~1
# 查看提交历史
git log --oneline
```

### GitHub: 代码托管与协作

托管仓库并管理协作开发。

```bash
# GitHub CLI 命令
gh repo create myrepo
gh repo clone user/repo
gh pr create --title "New feature"
gh pr list
gh pr merge 123
gh issue create --title "Bug report"
gh release create v1.0.0
# 创建 pull request
git push -u origin feature-branch
# 然后在 GitHub/GitLab 上创建 PR
```

### 代码审查与质量

通过同行评审和自动化检查确保代码质量。

```bash
# Pre-commit hooks 示例
#!/bin/sh
# 提交前运行测试
npm test
if [ $? -ne 0 ]; then
  echo "Tests failed"
  exit 1
fi
```

## 监控与可观测性

### Prometheus: 指标收集

使用时间序列数据监控系统和应用程序指标。

```promql
# CPU 使用率
cpu_usage_percent{instance="server1"}
# 内存使用率
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
# HTTP 请求速率
rate(http_requests_total[5m])
# 告警规则示例
ALERT HighCPUUsage
  IF cpu_usage_percent > 80
  FOR 5m
```

### Grafana: 可视化仪表板

为监控数据创建仪表板和可视化。

```bash
# 创建仪表板
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json
# 获取仪表板
curl http://admin:admin@localhost:3000/api/dashboards/uid/dashboard-uid
```

### ELK Stack: 日志管理

收集、搜索和分析跨基础设施的日志数据。

```json
# Elasticsearch 查询
# 搜索日志
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
# Logstash 配置
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

### 应用程序性能监控

跟踪应用程序性能和用户体验指标。

```ruby
# New Relic 代理设置
# 添加到应用程序
require 'newrelic_rpm'
```

```python
# Datadog 指标
from datadog import DogStatsdClient
statsd = DogStatsdClient('localhost', 8125)
statsd.increment('web.requests')
statsd.histogram('web.response_time', 0.75)
```

## 云平台管理

### AWS CLI: Amazon Web Services

从命令行与 AWS 服务进行交互。

```bash
# 配置 AWS CLI
aws configure
# 列出 EC2 实例
aws ec2 describe-instances
# 创建 S3 存储桶
aws s3 mb s3://my-bucket-name
# 部署 Lambda 函数
aws lambda create-function --function-name myfunction --runtime python3.8 --role arn:aws:iam::123456789:role/lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip
# 列出正在运行的服务
aws ecs list-services --cluster my-cluster
```

### Azure CLI: Microsoft Azure

管理 Azure 资源和服务。

```bash
# 登录 Azure
az login
# 创建资源组
az group create --name myResourceGroup --location eastus
# 创建虚拟机
az vm create --resource-group myResourceGroup --name myVM --image Ubuntu2204 --admin-username azureuser --generate-ssh-keys
# 列出 Web 应用
az webapp list
```

### Google Cloud: GCP

在 Google Cloud Platform 上部署和管理应用程序。

```bash
# 使用 GCP 进行身份验证
gcloud auth login
# 设置项目
gcloud config set project my-project-id
# 部署 App Engine 应用程序
gcloud app deploy
# 创建 Compute Engine 实例
gcloud compute instances create my-instance --zone=us-central1-a
# 管理 Kubernetes 集群
gcloud container clusters create my-cluster --num-nodes=3
```

### 多云管理

用于跨多个云提供商管理资源的工具。

```python
# Pulumi (多云 IaC)
import pulumi_aws as aws
import pulumi_gcp as gcp
# 创建 AWS S3 存储桶
bucket = aws.s3.Bucket("my-bucket")
# 创建 GCP 存储桶
gcp_bucket = gcp.storage.Bucket("my-gcp-bucket")
```

## 安全与密钥管理

### HashiCorp Vault: 密钥管理

HashiCorp Vault 是一种安全访问密钥的工具。密钥是您希望严格控制访问的任何内容，例如 API 密钥、密码或证书。

```bash
# 写入密钥
vault kv put secret/myapp/config username=myuser password=mypassword
# 读取密钥
vault kv get secret/myapp/config
# 删除密钥
vault kv delete secret/myapp/config
# 启用认证方法
vault auth enable kubernetes
# 创建策略
vault policy write myapp-policy myapp-policy.hcl
```

### 安全扫描：Trivy & SonarQube

扫描容器和代码中的安全漏洞。

```bash
# Trivy 容器扫描
trivy image nginx:latest
# 扫描文件系统
trivy fs /path/to/project
# SonarQube 分析
sonar-scanner -Dsonar.projectKey=myproject -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000
```

### SSL/TLS 证书管理

管理 SSL 证书以实现安全通信。

```bash
# 使用 Certbot 的 Let's Encrypt
certbot --nginx -d example.com
# 续订证书
certbot renew
# 检查证书有效期
openssl x509 -in cert.pem -text -noout | grep "Not After"
# 生成自签名证书
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

### 容器安全

保护容器化应用程序和运行时环境。

```bash
# 以非 root 用户运行容器
docker run --user 1000:1000 myapp
# 扫描镜像中的漏洞
docker scan myapp:latest
```

```dockerfile
# 使用 distroless 镜像
FROM gcr.io/distroless/java:11
COPY app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## 性能优化

### 系统性能监控

无论您是管理服务器、设置部署还是修复生产中出现的问题，这些命令都能帮助您更快地工作，更智能地工作。

```bash
# CPU 和内存使用情况
htop
# 磁盘使用情况
df -h
# 网络连接
netstat -tulpn
# 进程监控
ps aux | grep process_name
# 系统负载
uptime
# 内存详情
free -h
```

### 应用程序性能调优

优化应用程序性能和资源利用率。

```bash
# JVM 性能监控
jstat -gc -t PID 1s
# Node.js 性能
node --inspect app.js
# 数据库查询优化
EXPLAIN ANALYZE SELECT * FROM table WHERE condition;
# Nginx 性能调优
nginx -t && nginx -s reload
```

### 负载测试与基准测试

在各种负载条件下测试应用程序性能。

```bash
# Apache Bench
ab -n 1000 -c 10 http://example.com/
# wrk HTTP 基准测试
wrk -t12 -c400 -d30s http://example.com/
# Artillery 负载测试
artillery run load-test.yml
# Kubernetes 水平 Pod 自动伸缩器
kubectl autoscale deployment myapp --cpu-percent=70 --min=1 --max=10
```

### 数据库性能

监控和优化数据库性能和查询。

```sql
# MySQL 性能
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Threads_connected';
```

```sql
# PostgreSQL 监控
SELECT * FROM pg_stat_activity;
```

```bash
# Redis 监控
redis-cli --latency
redis-cli info memory
```

## 环境配置

### 环境变量管理

安全地管理跨不同环境的配置。

```bash
# .env 文件示例
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=your-api-key-here
ENVIRONMENT=production
# 加载环境变量
export $(cat .env | xargs)
# Docker 环境变量
docker run -e NODE_ENV=production -e API_KEY=secret myapp
# Kubernetes configmap
kubectl create configmap app-config --from-env-file=.env
```

### 服务发现与配置

管理服务发现和动态配置。

```bash
# Consul 服务注册
consul services register myservice.json
# 获取服务健康状态
consul health service web
# Etcd 键值存储
etcdctl put /config/database/host localhost
etcdctl get /config/database/host
```

### 开发环境设置

使用容器设置一致的开发环境。

```dockerfile
# 开发 Dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

```yaml
# 用于开发的 Docker Compose
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

### 生产环境加固

保护和优化生产环境。

```ini
# Systemd 服务配置
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

## 自动化与编排

### 使用 Ansible 进行基础设施自动化

自动化基础设施配置和配置管理。

```yaml
# Ansible playbook 示例
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

### 工作流编排

编排复杂的工作流程和数据管道。

```python
# Apache Airflow DAG 示例
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

### 事件驱动自动化

根据系统事件和 Webhook 触发自动化。

```bash
# GitHub webhook 处理程序
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

### ChatOps 集成

将 DevOps 操作与聊天平台集成以实现协作自动化。

```bash
# Slack 机器人命令示例
/deploy myapp to production
/rollback myapp to v1.2.3
/scale myapp replicas=5
/status infrastructure
# Microsoft Teams webhook
curl -H "Content-Type: application/json" \
  -d '{"text": "Deployment completed successfully"}' \
  $TEAMS_WEBHOOK_URL
```

## 相关链接

- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/git">Git 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/kubernetes">Kubernetes 速查表</router-link>
- <router-link to="/ansible">Ansible 速查表</router-link>
- <router-link to="/jenkins">Jenkins 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>

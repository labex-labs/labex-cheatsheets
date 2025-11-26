---
title: 'DevOps 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 종합 치트 시트로 DevOps 를 학습하세요.'
pdfUrl: '/cheatsheets/pdf/devops-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
DevOps 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/devops">실습 랩을 통한 DevOps 학습</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 DevOps 관행을 학습하십시오. LabEx 는 필수 운영, 인프라 관리, CI/CD 파이프라인, 컨테이너화, 모니터링 및 자동화를 다루는 포괄적인 DevOps 과정을 제공합니다. 애플리케이션 배포, 코드형 인프라 관리, 워크플로우 자동화 및 효율적인 소프트웨어 제공을 위한 최신 DevOps 관행 구현 방법을 학습합니다.
</base-disclaimer-content>
</base-disclaimer>

## Infrastructure as Code (IaC)

### Terraform: 인프라 프로비저닝

선언적 구성 언어를 사용하여 인프라를 정의하고 프로비저닝합니다.

```bash
# Terraform 초기화
terraform init
# 인프라 변경 사항 계획
terraform plan
# 인프라 변경 사항 적용
terraform apply
# 인프라 파괴
terraform destroy
# 구성 파일 형식 지정
terraform fmt
# 구성 유효성 검사
terraform validate
```

### Ansible: 구성 관리

애플리케이션 배포 및 구성 관리를 자동화합니다.

```bash
# 플레이북 실행
ansible-playbook site.yml
# 특정 호스트에서 플레이북 실행
ansible-playbook -i inventory site.yml
# 구문 확인
ansible-playbook --syntax-check site.yml
# 특정 사용자로 실행
ansible-playbook -u ubuntu site.yml
```

### CloudFormation: AWS 네이티브 IaC

JSON/YAML 템플릿을 사용하여 AWS 리소스를 프로비저닝합니다.

```bash
# 스택 생성
aws cloudformation create-stack --stack-name mystack --template-body file://template.yml
# 스택 업데이트
aws cloudformation update-stack --stack-name mystack --template-body file://template.yml
# 스택 삭제
aws cloudformation delete-stack --stack-name mystack
```

## 컨테이너 관리

### Docker: 컨테이너화

컨테이너에서 애플리케이션을 빌드, 배송 및 실행합니다.

```bash
# 이미지 빌드
docker build -t myapp:latest .
# 컨테이너 실행
docker run -d -p 8080:80 myapp:latest
# 실행 중인 컨테이너 나열
docker ps
# 컨테이너 중지
docker stop container_id
# 컨테이너 제거
docker rm container_id
```

### Kubernetes: 컨테이너 오케스트레이션

대규모로 컨테이너화된 애플리케이션을 배포하고 관리합니다.

```bash
# 구성 적용
kubectl apply -f deployment.yml
# 파드 가져오기
kubectl get pods
# 배포 확장
kubectl scale deployment myapp --replicas=5
# 로그 보기
kubectl logs pod_name
# 리소스 삭제
kubectl delete -f deployment.yml
```

### Helm: Kubernetes 패키지 관리자

차트를 사용하여 Kubernetes 애플리케이션을 관리합니다.

```bash
# 차트 설치
helm install myrelease stable/nginx
# 릴리스 업그레이드
helm upgrade myrelease stable/nginx
# 릴리스 나열
helm list
# 릴리스 제거
helm uninstall myrelease
```

## CI/CD 파이프라인 관리

### Jenkins: 빌드 자동화

지속적인 통합 파이프라인을 설정하고 관리합니다.

```groovy
// Jenkinsfile 예시
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

### GitHub Actions: 클라우드 CI/CD

GitHub 리포지토리에서 직접 워크플로우를 자동화합니다.

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

### GitLab CI: 통합된 DevOps

완벽한 DevOps 워크플로우를 위해 GitLab 의 내장 CI/CD 기능을 사용합니다.

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

## 버전 관리 및 협업

### Git: 버전 관리 시스템

변경 사항을 추적하고 코드 개발에 협업합니다.

```bash
# 리포지토리 복제
git clone https://github.com/user/repo.git
# 상태 확인
git status
# 변경 사항 추가
git add .
# 변경 사항 커밋
git commit -m "Add feature"
# 원격으로 푸시
git push origin main
# 최신 변경 사항 가져오기
git pull origin main
```

### 브랜치 관리

다양한 개발 스트림 및 릴리스를 관리합니다.

```bash
# 브랜치 생성
git checkout -b feature-branch
# 브랜치 병합
git merge feature-branch
# 브랜치 목록 보기
git branch -a
# 브랜치 전환
git checkout main
# 브랜치 삭제
git branch -d feature-branch
# 이전 커밋으로 되돌리기
git reset --hard HEAD~1
# 커밋 기록 보기
git log --oneline
```

### GitHub: 코드 호스팅 및 협업

리포지토리를 호스팅하고 협업 개발을 관리합니다.

```bash
# GitHub CLI 명령어
gh repo create myrepo
gh repo clone user/repo
gh pr create --title "New feature"
gh pr list
gh pr merge 123
gh issue create --title "Bug report"
gh release create v1.0.0
# 풀 리퀘스트 생성
git push -u origin feature-branch
# 그런 다음 GitHub/GitLab에서 PR 생성
```

### 코드 검토 및 품질

동료 검토 및 자동화된 확인을 통해 코드 품질을 보장합니다.

```bash
# Pre-commit 훅 예시
#!/bin/sh
# 커밋 전 테스트 실행
npm test
if [ $? -ne 0 ]; then
  echo "Tests failed"
  exit 1
fi
```

## 모니터링 및 관측 가능성

### Prometheus: 메트릭 수집

시계열 데이터를 사용하여 시스템 및 애플리케이션 메트릭을 모니터링합니다.

```promql
# CPU 사용량
cpu_usage_percent{instance="server1"}
# 메모리 사용량
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
# HTTP 요청 속도
rate(http_requests_total[5m])
# 경고 규칙 예시
ALERT HighCPUUsage
  IF cpu_usage_percent > 80
  FOR 5m
```

### Grafana: 시각화 대시보드

모니터링 데이터를 위한 대시보드 및 시각화를 생성합니다.

```bash
# 대시보드 생성
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json
# 대시보드 가져오기
curl http://admin:admin@localhost:3000/api/dashboards/uid/dashboard-uid
```

### ELK Stack: 로그 관리

인프라 전반의 로그 데이터를 수집, 검색 및 분석합니다.

```json
# Elasticsearch 쿼리
# 로그 검색
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
# Logstash 구성
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

### 애플리케이션 성능 모니터링

애플리케이션 성능 및 사용자 경험 메트릭을 추적합니다.

```ruby
# New Relic 에이전트 설정
# 애플리케이션에 추가
require 'newrelic_rpm'
```

```python
# Datadog 메트릭
from datadog import DogStatsdClient
statsd = DogStatsdClient('localhost', 8125)
statsd.increment('web.requests')
statsd.histogram('web.response_time', 0.75)
```

## 클라우드 플랫폼 관리

### AWS CLI: Amazon Web Services

명령줄에서 AWS 서비스와 상호 작용합니다.

```bash
# AWS CLI 구성
aws configure
# EC2 인스턴스 나열
aws ec2 describe-instances
# S3 버킷 생성
aws s3 mb s3://my-bucket-name
# Lambda 함수 배포
aws lambda create-function --function-name myfunction --runtime python3.8 --role arn:aws:iam::123456789:role/lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip
# 실행 중인 서비스 나열
aws ecs list-services --cluster my-cluster
```

### Azure CLI: Microsoft Azure

Azure 리소스 및 서비스를 관리합니다.

```bash
# Azure 로그인
az login
# 리소스 그룹 생성
az group create --name myResourceGroup --location eastus
# 가상 머신 생성
az vm create --resource-group myResourceGroup --name myVM --image Ubuntu2204 --admin-username azureuser --generate-ssh-keys
# 웹 앱 나열
az webapp list
```

### Google Cloud: GCP

Google Cloud Platform 에서 애플리케이션을 배포하고 관리합니다.

```bash
# GCP 인증
gcloud auth login
# 프로젝트 설정
gcloud config set project my-project-id
# App Engine 애플리케이션 배포
gcloud app deploy
# Compute Engine 인스턴스 생성
gcloud compute instances create my-instance --zone=us-central1-a
# Kubernetes 클러스터 관리
gcloud container clusters create my-cluster --num-nodes=3
```

### 멀티 클라우드 관리

여러 클라우드 공급자 전반의 리소스를 관리하기 위한 도구.

```python
# Pulumi (멀티 클라우드 IaC)
import pulumi_aws as aws
import pulumi_gcp as gcp
# AWS S3 버킷 생성
bucket = aws.s3.Bucket("my-bucket")
# GCP 스토리지 버킷 생성
gcp_bucket = gcp.storage.Bucket("my-gcp-bucket")
```

## 보안 및 비밀 관리

### HashiCorp Vault: 비밀 관리

HashiCorp Vault 는 비밀에 안전하게 액세스하기 위한 도구입니다. 비밀은 API 키, 암호 또는 인증서와 같이 액세스를 엄격하게 제어하려는 모든 것입니다.

```bash
# 비밀 쓰기
vault kv put secret/myapp/config username=myuser password=mypassword
# 비밀 읽기
vault kv get secret/myapp/config
# 비밀 삭제
vault kv delete secret/myapp/config
# 인증 방법 활성화
vault auth enable kubernetes
# 정책 생성
vault policy write myapp-policy myapp-policy.hcl
```

### 보안 스캐닝: Trivy 및 SonarQube

컨테이너 및 코드를 보안 취약점에 대해 스캔합니다.

```bash
# Trivy 컨테이너 스캔
trivy image nginx:latest
# 파일 시스템 스캔
trivy fs /path/to/project
# SonarQube 분석
sonar-scanner -Dsonar.projectKey=myproject -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000
```

### SSL/TLS 인증서 관리

보안 통신을 위한 SSL 인증서를 관리합니다.

```bash
# Certbot을 사용한 Let's Encrypt
certbot --nginx -d example.com
# 인증서 갱신
certbot renew
# 인증서 만료 확인
openssl x509 -in cert.pem -text -noout | grep "Not After"
# 자체 서명 인증서 생성
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

### 컨테이너 보안

컨테이너화된 애플리케이션 및 런타임 환경을 보호합니다.

```bash
# 비루트 사용자로 컨테이너 실행
docker run --user 1000:1000 myapp
# 취약점에 대해 이미지 스캔
docker scan myapp:latest
```

```dockerfile
# Distroless 이미지 사용
FROM gcr.io/distroless/java:11
COPY app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## 성능 최적화

### 시스템 성능 모니터링

서버를 관리하든, 배포를 설정하든, 프로덕션에서 방금 발생한 문제를 해결하든, 이 명령어들은 더 빠르고 스마트하게 작업하는 데 도움이 됩니다.

```bash
# CPU 및 메모리 사용량
htop
# 디스크 사용량
df -h
# 네트워크 연결
netstat -tulpn
# 프로세스 모니터링
ps aux | grep process_name
# 시스템 부하
uptime
# 메모리 세부 정보
free -h
```

### 애플리케이션 성능 튜닝

애플리케이션 성능 및 리소스 활용률을 최적화합니다.

```bash
# JVM 성능 모니터링
jstat -gc -t PID 1s
# Node.js 성능
node --inspect app.js
# 데이터베이스 쿼리 최적화
EXPLAIN ANALYZE SELECT * FROM table WHERE condition;
# Nginx 성능 튜닝
nginx -t && nginx -s reload
```

### 부하 테스트 및 벤치마킹

다양한 부하 조건에서 애플리케이션 성능을 테스트합니다.

```bash
# Apache Bench
ab -n 1000 -c 10 http://example.com/
# wrk HTTP 벤치마킹
wrk -t12 -c400 -d30s http://example.com/
# Artillery 부하 테스트
artillery run load-test.yml
# Kubernetes 수평 포드 자동 스케일러
kubectl autoscale deployment myapp --cpu-percent=70 --min=1 --max=10
```

### 데이터베이스 성능

데이터베이스 성능 및 쿼리를 모니터링하고 최적화합니다.

```sql
# MySQL 성능
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Threads_connected';
```

```sql
# PostgreSQL 모니터링
SELECT * FROM pg_stat_activity;
```

```bash
# Redis 모니터링
redis-cli --latency
redis-cli info memory
```

## DevOps 도구 설치

### 패키지 관리자

시스템 패키지 관리자를 사용하여 도구를 설치합니다.

```bash
# Ubuntu/Debian
apt update && apt install -y docker.io kubectl terraform
# CentOS/RHEL
yum install -y docker kubernetes-client terraform
# macOS Homebrew
brew install docker kubectl terraform ansible
```

### 컨테이너 런타임 설치

Docker 및 컨테이너 오케스트레이션 도구를 설정합니다.

```bash
# Docker 설치
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker
# Docker Compose 설치
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
```

### 클라우드 CLI 도구

주요 클라우드 공급자를 위한 명령줄 인터페이스를 설치합니다.

```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && ./aws/install
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
# Google Cloud SDK
curl https://sdk.cloud.google.com | bash
```

## 환경 구성

### 환경 변수 관리

다양한 환경 전반에서 구성을 안전하게 관리합니다.

```bash
# .env 파일 예시
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=your-api-key-here
ENVIRONMENT=production
# 환경 변수 로드
export $(cat .env | xargs)
# Docker 환경 변수
docker run -e NODE_ENV=production -e API_KEY=secret myapp
# Kubernetes configmap
kubectl create configmap app-config --from-env-file=.env
```

### 서비스 검색 및 구성

서비스 검색 및 동적 구성을 관리합니다.

```bash
# Consul 서비스 등록
consul services register myservice.json
# 서비스 상태 가져오기
consul health service web
# Etcd 키-값 저장소
etcdctl put /config/database/host localhost
etcdctl get /config/database/host
```

### 개발 환경 설정

컨테이너를 사용하여 일관된 개발 환경을 설정합니다.

```dockerfile
# 개발 Dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

```yaml
# 개발용 Docker Compose
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

### 프로덕션 환경 강화

프로덕션 환경을 보호하고 최적화합니다.

```ini
# Systemd 서비스 구성
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

## 자동화 및 오케스트레이션

### Ansible 을 사용한 인프라 자동화

인프라 프로비저닝 및 구성 관리를 자동화합니다.

```yaml
# Ansible 플레이북 예시
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

### 워크플로우 오케스트레이션

복잡한 워크플로우 및 데이터 파이프라인을 오케스트레이션합니다.

```python
# Apache Airflow DAG 예시
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

### 이벤트 기반 자동화

시스템 이벤트 및 웹훅을 기반으로 자동화를 트리거합니다.

```bash
# GitHub 웹훅 핸들러
#!/bin/bash
if [ "$1" == "push" ]; then
  git pull origin main
  docker build -t myapp .
  docker run -d --name myapp-$(date +%s) myapp
fi
# Prometheus alertmanager 웹훅
curl -X POST http://webhook-handler/deploy \
  -H "Content-Type: application/json" \
  -d '{"service": "myapp", "action": "restart"}'
```

### ChatOps 통합

협업 자동화를 위해 DevOps 작업을 채팅 플랫폼과 통합합니다.

```bash
# Slack 봇 명령어 예시
/deploy myapp to production
/rollback myapp to v1.2.3
/scale myapp replicas=5
/status infrastructure
# Microsoft Teams 웹훅
curl -H "Content-Type: application/json" \
  -d '{"text": "Deployment completed successfully"}' \
  $TEAMS_WEBHOOK_URL
```

## 관련 링크

- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/git">Git 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>
- <router-link to="/ansible">Ansible 치트 시트</router-link>
- <router-link to="/jenkins">Jenkins 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>

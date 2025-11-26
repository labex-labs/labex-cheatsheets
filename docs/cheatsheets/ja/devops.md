---
title: 'DevOps チートシート'
description: '必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートで DevOps を習得しましょう。'
pdfUrl: '/cheatsheets/pdf/devops-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
DevOps チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/devops">ハンズオンラボで DevOps を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと現実世界のシナリオを通じて DevOps プラクティスを学びます。LabEx は、必須のオペレーション、インフラストラクチャ管理、CI/CD パイプライン、コンテナ化、モニタリング、自動化を網羅する包括的な DevOps コースを提供します。アプリケーションのデプロイ、Infrastructure as Code によるインフラストラクチャ管理、ワークフローの自動化、効率的なソフトウェア配信のための最新の DevOps プラクティスの実装方法を学びます。
</base-disclaimer-content>
</base-disclaimer>

## Infrastructure as Code (IaC)

### Terraform: インフラストラクチャのプロビジョニング

宣言的な構成言語を使用してインフラストラクチャを定義し、プロビジョニングします。

```bash
# Terraformの初期化
terraform init
# インフラストラクチャの変更を計画
terraform plan
# インフラストラクチャの変更を適用
terraform apply
# インフラストラクチャの破棄
terraform destroy
# 構成ファイルのフォーマット
terraform fmt
# 構成の検証
terraform validate
```

### Ansible: 構成管理

アプリケーションのデプロイと構成管理を自動化します。

```bash
# プレイブックの実行
ansible-playbook site.yml
# 特定のホストでプレイブックを実行
ansible-playbook -i inventory site.yml
# 構文チェック
ansible-playbook --syntax-check site.yml
# 特定のユーザーで実行
ansible-playbook -u ubuntu site.yml
```

### CloudFormation: AWS ネイティブ IaC

JSON/YAMLテンプレートを使用してAWSリソースをプロビジョニングします。

```bash
# スタックの作成
aws cloudformation create-stack --stack-name mystack --template-body file://template.yml
# スタックの更新
aws cloudformation update-stack --stack-name mystack --template-body file://template.yml
# スタックの削除
aws cloudformation delete-stack --stack-name mystack
```

## コンテナ管理

### Docker: コンテナ化

アプリケーションをコンテナ内でビルド、出荷、実行します。

```bash
# イメージのビルド
docker build -t myapp:latest .
# コンテナの実行
docker run -d -p 8080:80 myapp:latest
# 実行中のコンテナの一覧表示
docker ps
# コンテナの停止
docker stop container_id
# コンテナの削除
docker rm container_id
```

### Kubernetes: コンテナオーケストレーション

コンテナ化されたアプリケーションを大規模にデプロイおよび管理します。

```bash
# 構成の適用
kubectl apply -f deployment.yml
# Podの取得
kubectl get pods
# デプロイメントのスケール
kubectl scale deployment myapp --replicas=5
# ログの表示
kubectl logs pod_name
# リソースの削除
kubectl delete -f deployment.yml
```

### Helm: Kubernetes パッケージマネージャ

チャートを使用して Kubernetes アプリケーションを管理します。

```bash
# チャートのインストール
helm install myrelease stable/nginx
# リリースのアップグレード
helm upgrade myrelease stable/nginx
# リリースの一覧表示
helm list
# リリースのアンインストール
helm uninstall myrelease
```

## CI/CD パイプライン管理

### Jenkins: ビルド自動化

継続的インテグレーションパイプラインを設定および管理します。

```groovy
// Jenkinsfile の例
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

### GitHub Actions: クラウド CI/CD

GitHub リポジトリから直接ワークフローを自動化します。

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

### GitLab CI: 統合された DevOps

GitLab の組み込み CI/CD 機能を使用して、完全な DevOps ワークフローを実現します。

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

## バージョン管理とコラボレーション

### Git: バージョン管理システム

変更を追跡し、コード開発でのコラボレーションを行います。

```bash
# リポジトリのクローン
git clone https://github.com/user/repo.git
# ステータスの確認
git status
# 変更の追加
git add .
# 変更のコミット
git commit -m "Add feature"
# リモートへのプッシュ
git push origin main
# 最新の変更のプル
git pull origin main
```

### ブランチ管理

異なる開発ストリームとリリースを管理します。

```bash
# ブランチの作成
git checkout -b feature-branch
# ブランチのマージ
git merge feature-branch
# ブランチの一覧表示
git branch -a
# ブランチの切り替え
git checkout main
# ブランチの削除
git branch -d feature-branch
# 以前のコミットへのリセット
git reset --hard HEAD~1
# コミット履歴の表示
git log --oneline
```

### GitHub: コードホスティングとコラボレーション

リポジトリをホストし、共同開発を管理します。

```bash
# GitHub CLI コマンド
gh repo create myrepo
gh repo clone user/repo
gh pr create --title "New feature"
gh pr list
gh pr merge 123
gh issue create --title "Bug report"
gh release create v1.0.0
# プルリクエストの作成
git push -u origin feature-branch
# その後、GitHub/GitLabでPRを作成
```

### コードレビューと品質

ピアレビューと自動チェックを通じてコード品質を保証します。

```bash
# Pre-commit フックの例
#!/bin/sh
# コミット前のテスト実行
npm test
if [ $? -ne 0 ]; then
  echo "Tests failed"
  exit 1
fi
```

## モニタリングと可観測性

### Prometheus: メトリクス収集

時系列データを使用してシステムおよびアプリケーションのメトリクスを監視します。

```promql
# CPU使用率
cpu_usage_percent{instance="server1"}
# メモリ使用量
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
# HTTPリクエスト率
rate(http_requests_total[5m])
# アラートルール例
ALERT HighCPUUsage
  IF cpu_usage_percent > 80
  FOR 5m
```

### Grafana: 視覚化ダッシュボード

監視データのためのダッシュボードと視覚化を作成します。

```bash
# ダッシュボードの作成
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json
# ダッシュボードの取得
curl http://admin:admin@localhost:3000/api/dashboards/uid/dashboard-uid
```

### ELK Stack: ログ管理

インフラストラクチャ全体でログデータを収集、検索、分析します。

```json
# Elasticsearch クエリ
# ログの検索
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
# Logstash 構成
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

### アプリケーションパフォーマンスモニタリング

アプリケーションのパフォーマンスとユーザーエクスペリエンスのメトリクスを追跡します。

```ruby
# New Relic エージェントの設定
# アプリケーションへの追加
require 'newrelic_rpm'
```

```python
# Datadog メトリクス
from datadog import DogStatsdClient
statsd = DogStatsdClient('localhost', 8125)
statsd.increment('web.requests')
statsd.histogram('web.response_time', 0.75)
```

## クラウドプラットフォーム管理

### AWS CLI: Amazon Web Services

コマンドラインから AWS サービスと対話します。

```bash
# AWS CLI の設定
aws configure
# EC2 インスタンスの一覧表示
aws ec2 describe-instances
# S3 バケットの作成
aws s3 mb s3://my-bucket-name
# Lambda 関数のデプロイ
aws lambda create-function --function-name myfunction --runtime python3.8 --role arn:aws:iam::123456789:role/lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip
# 実行中のサービスの一覧表示
aws ecs list-services --cluster my-cluster
```

### Azure CLI: Microsoft Azure

Azure リソースとサービスを管理します。

```bash
# Azure へのログイン
az login
# リソースグループの作成
az group create --name myResourceGroup --location eastus
# 仮想マシンの作成
az vm create --resource-group myResourceGroup --name myVM --image Ubuntu2204 --admin-username azureuser --generate-ssh-keys
# Webアプリの一覧表示
az webapp list
```

### Google Cloud: GCP

Google Cloud Platform でアプリケーションをデプロイおよび管理します。

```bash
# GCP 認証
gcloud auth login
# プロジェクトの設定
gcloud config set project my-project-id
# App Engine アプリケーションのデプロイ
gcloud app deploy
# Compute Engine インスタンスの作成
gcloud compute instances create my-instance --zone=us-central1-a
# Kubernetes クラスターの管理
gcloud container clusters create my-cluster --num-nodes=3
```

### マルチクラウド管理

複数のクラウドプロバイダーにわたるリソースを管理するためのツール。

```python
# Pulumi (マルチクラウド IaC)
import pulumi_aws as aws
import pulumi_gcp as gcp
# AWS S3 バケットの作成
bucket = aws.s3.Bucket("my-bucket")
# GCP ストレージバケットの作成
gcp_bucket = gcp.storage.Bucket("my-gcp-bucket")
```

## セキュリティとシークレット管理

### HashiCorp Vault: シークレット管理

HashiCorp Vault は、シークレットに安全にアクセスするためのツールです。シークレットとは、API キー、パスワード、証明書など、アクセスを厳密に制御したいあらゆるものを指します。

```bash
# シークレットの書き込み
vault kv put secret/myapp/config username=myuser password=mypassword
# シークレットの読み取り
vault kv get secret/myapp/config
# シークレットの削除
vault kv delete secret/myapp/config
# 認証メソッドの有効化
vault auth enable kubernetes
# ポリシーの作成
vault policy write myapp-policy myapp-policy.hcl
```

### セキュリティスキャン：Trivy & SonarQube

コンテナとコードをスキャンしてセキュリティの脆弱性を検出します。

```bash
# Trivy コンテナスキャン
trivy image nginx:latest
# ファイルシステムのスキャン
trivy fs /path/to/project
# SonarQube 分析
sonar-scanner -Dsonar.projectKey=myproject -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000
```

### SSL/TLS 証明書管理

安全な通信のために SSL 証明書を管理します。

```bash
# Certbot を使用した Let's Encrypt
certbot --nginx -d example.com
# 証明書の更新
certbot renew
# 証明書の有効期限の確認
openssl x509 -in cert.pem -text -noout | grep "Not After"
# 自己署名証明書の生成
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

### コンテナセキュリティ

コンテナ化されたアプリケーションとランタイム環境を保護します。

```bash
# 非ルートユーザーとしてコンテナを実行
docker run --user 1000:1000 myapp
# イメージの脆弱性スキャン
docker scan myapp:latest
```

```dockerfile
# distroless イメージの使用
FROM gcr.io/distroless/java:11
COPY app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## パフォーマンス最適化

### システムパフォーマンス監視

サーバーの管理、デプロイの設定、本番環境で発生した問題の修正を行う際、これらのコマンドはより速く、よりスマートに作業するのに役立ちます。

```bash
# CPUとメモリの使用率
htop
# ディスク使用量
df -h
# ネットワーク接続
netstat -tulpn
# プロセス監視
ps aux | grep process_name
# システムロード
uptime
# メモリ詳細
free -h
```

### アプリケーションパフォーマンスチューニング

アプリケーションのパフォーマンスとリソース利用率を最適化します。

```bash
# JVM パフォーマンス監視
jstat -gc -t PID 1s
# Node.js パフォーマンス
node --inspect app.js
# データベースクエリの最適化
EXPLAIN ANALYZE SELECT * FROM table WHERE condition;
# Nginx パフォーマンスチューニング
nginx -t && nginx -s reload
```

### 負荷テストとベンチマーク

さまざまな負荷条件下でのアプリケーションパフォーマンスをテストします。

```bash
# Apache Bench
ab -n 1000 -c 10 http://example.com/
# wrk HTTPベンチマーキング
wrk -t12 -c400 -d30s http://example.com/
# Artillery 負荷テスト
artillery run load-test.yml
# Kubernetes 水平 Pod 自動スケーラー
kubectl autoscale deployment myapp --cpu-percent=70 --min=1 --max=10
```

### データベースパフォーマンス

データベースのパフォーマンスとクエリを監視および最適化します。

```sql
# MySQL パフォーマンス
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Threads_connected';
```

```sql
# PostgreSQL モニタリング
SELECT * FROM pg_stat_activity;
```

```bash
# Redis モニタリング
redis-cli --latency
redis-cli info memory
```

## DevOps ツールインストール

### パッケージマネージャ

システムパッケージマネージャを使用してツールをインストールします。

```bash
# Ubuntu/Debian
apt update && apt install -y docker.io kubectl terraform
# CentOS/RHEL
yum install -y docker kubernetes-client terraform
# macOS Homebrew
brew install docker kubectl terraform ansible
```

### コンテナランタイムのインストール

Docker とコンテナオーケストレーションツールを設定します。

```bash
# Docker のインストール
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker
# Docker Compose のインストール
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
```

### クラウド CLI ツールのインストール

主要なクラウドプロバイダーのコマンドラインインターフェイスをインストールします。

```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && ./aws/install
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
# Google Cloud SDK
curl https://sdk.cloud.google.com | bash
```

## 環境設定

### 環境変数管理

異なる環境全体で構成を安全に管理します。

```bash
# .env ファイルの例
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=your-api-key-here
ENVIRONMENT=production
# 環境変数のロード
export $(cat .env | xargs)
# Docker 環境変数
docker run -e NODE_ENV=production -e API_KEY=secret myapp
# Kubernetes configmap
kubectl create configmap app-config --from-env-file=.env
```

### サービスディスカバリと構成

サービスディスカバリと動的構成を管理します。

```bash
# Consul サービス登録
consul services register myservice.json
# サービスヘルスチェックの取得
consul health service web
# Etcd キーバリューストア
etcdctl put /config/database/host localhost
etcdctl get /config/database/host
```

### 開発環境セットアップ

コンテナを使用して一貫した開発環境をセットアップします。

```dockerfile
# 開発用 Dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

```yaml
# 開発用 Docker Compose
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

### 本番環境の強化

本番環境を保護し、最適化します。

```ini
# Systemd サービス構成
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

## 自動化とオーケストレーション

### Ansible によるインフラストラクチャ自動化

インフラストラクチャのプロビジョニングと構成管理を自動化します。

```yaml
# Ansible プレイブックの例
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

### ワークフローオーケストレーション

複雑なワークフローとデータパイプラインをオーケストレーションします。

```python
# Apache Airflow DAG の例
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

### イベント駆動型自動化

システムイベントと Webhook に基づいて自動化をトリガーします。

```bash
# GitHub webhook ハンドラ
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

### ChatOps 統合

共同自動化のために DevOps 操作をチャットプラットフォームに統合します。

```bash
# Slack ボットコマンドの例
/deploy myapp to production
/rollback myapp to v1.2.3
/scale myapp replicas=5
/status infrastructure
# Microsoft Teams webhook
curl -H "Content-Type: application/json" \
  -d '{"text": "Deployment completed successfully"}' \
  $TEAMS_WEBHOOK_URL
```

## 関連リンク

- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/git">Git チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/kubernetes">Kubernetes チートシート</router-link>
- <router-link to="/ansible">Ansible チートシート</router-link>
- <router-link to="/jenkins">Jenkins チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>

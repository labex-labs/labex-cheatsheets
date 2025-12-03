---
title: 'Guia Rápido DevOps | LabEx'
description: 'Aprenda práticas DevOps com este guia rápido abrangente. Referência rápida para CI/CD, automação, infraestrutura como código, monitoramento, conteinerização e fluxos de trabalho modernos de entrega de software.'
pdfUrl: '/cheatsheets/pdf/devops-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas DevOps
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/devops">Aprenda DevOps com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda práticas de DevOps através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de DevOps que cobrem operações essenciais, gerenciamento de infraestrutura, pipelines de CI/CD, conteinerização, monitoramento e automação. Aprenda a implantar aplicações, gerenciar infraestrutura como código, automatizar fluxos de trabalho e implementar práticas modernas de DevOps para entrega eficiente de software.
</base-disclaimer-content>
</base-disclaimer>

## Infraestrutura como Código (IaC)

### Terraform: Provisionamento de Infraestrutura

Defina e provisione infraestrutura usando linguagem de configuração declarativa.

```bash
# Inicializar Terraform
terraform init
# Planejar mudanças na infraestrutura
terraform plan
# Aplicar mudanças na infraestrutura
terraform apply
# Destruir infraestrutura
terraform destroy
# Formatar arquivos de configuração
terraform fmt
# Validar configuração
terraform validate
```

<BaseQuiz id="devops-terraform-1" correct="B">
  <template #question>
    O que `terraform plan` faz?
  </template>
  
  <BaseQuizOption value="A">Aplica mudanças na infraestrutura imediatamente</BaseQuizOption>
  <BaseQuizOption value="B" correct>Mostra quais mudanças serão feitas sem aplicá-las</BaseQuizOption>
  <BaseQuizOption value="C">Destrói toda a infraestrutura</BaseQuizOption>
  <BaseQuizOption value="D">Inicializa o Terraform</BaseQuizOption>
  
  <BaseQuizAnswer>
    `terraform plan` cria um plano de execução mostrando o que o Terraform fará quando você executar `terraform apply`. É uma simulação (dry-run) que ajuda você a revisar as mudanças antes de aplicá-las.
  </BaseQuizAnswer>
</BaseQuiz>

### Ansible: Gerenciamento de Configuração

Automatize a implantação de aplicações e o gerenciamento de configuração.

```bash
# Executar playbook
ansible-playbook site.yml
# Executar playbook em hosts específicos
ansible-playbook -i inventory site.yml
# Verificar sintaxe
ansible-playbook --syntax-check site.yml
# Executar com usuário específico
ansible-playbook -u ubuntu site.yml
```

### CloudFormation: IaC Nativo da AWS

Provisão de recursos AWS usando templates JSON/YAML.

```bash
# Criar stack
aws cloudformation create-stack --stack-name mystack --template-body file://template.yml
# Atualizar stack
aws cloudformation update-stack --stack-name mystack --template-body file://template.yml
# Deletar stack
aws cloudformation delete-stack --stack-name mystack
```

## Gerenciamento de Contêineres

### Docker: Conteinerização

Construa, envie e execute aplicações em contêineres.

```bash
# Construir imagem
docker build -t myapp:latest .
# Executar contêiner
docker run -d -p 8080:80 myapp:latest
# Listar contêineres em execução
docker ps
# Parar contêiner
docker stop container_id
# Remover contêiner
docker rm container_id
```

### Kubernetes: Orquestração de Contêineres

Implante e gerencie aplicações conteinerizadas em escala.

```bash
# Aplicar configuração
kubectl apply -f deployment.yml
# Obter pods
kubectl get pods
# Escalar deployment
kubectl scale deployment myapp --replicas=5
# Visualizar logs
kubectl logs pod_name
# Deletar recursos
kubectl delete -f deployment.yml
```

<BaseQuiz id="devops-k8s-1" correct="A">
  <template #question>
    O que `kubectl apply -f deployment.yml` faz?
  </template>
  
  <BaseQuizOption value="A" correct>Cria ou atualiza recursos definidos no arquivo YAML</BaseQuizOption>
  <BaseQuizOption value="B">Deleta todos os recursos no cluster</BaseQuizOption>
  <BaseQuizOption value="C">Apenas cria novos recursos</BaseQuizOption>
  <BaseQuizOption value="D">Mostra o que seria criado sem aplicar</BaseQuizOption>
  
  <BaseQuizAnswer>
    `kubectl apply` é um comando declarativo que cria recursos se eles não existirem ou os atualiza se existirem. É idempotente, o que significa que você pode executá-lo várias vezes com segurança.
  </BaseQuizAnswer>
</BaseQuiz>

### Helm: Gerenciador de Pacotes Kubernetes

Gerencie aplicações Kubernetes usando charts.

```bash
# Instalar chart
helm install myrelease stable/nginx
# Atualizar release
helm upgrade myrelease stable/nginx
# Listar releases
helm list
# Desinstalar release
helm uninstall myrelease
```

## Gerenciamento de Pipeline CI/CD

### Jenkins: Automação de Build

Configure e gerencie pipelines de integração contínua.

```groovy
// Exemplo de Jenkinsfile
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

### GitHub Actions: CI/CD em Nuvem

Automatize fluxos de trabalho diretamente de repositórios GitHub.

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

### GitLab CI: DevOps Integrado

Use as capacidades de CI/CD integradas do GitLab para fluxos de trabalho DevOps completos.

```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - deploy
build_job:
  stage: build
  script:
    - echo "Construindo a aplicação"
test_job:
  stage: test
  script:
    - echo "Executando testes"
```

## Controle de Versão e Colaboração

### Git: Sistema de Controle de Versão

Rastreie mudanças e colabore no desenvolvimento de código.

```bash
# Clonar repositório
git clone https://github.com/user/repo.git
# Verificar status
git status
# Adicionar mudanças
git add .
# Comitar mudanças
git commit -m "Adiciona funcionalidade"
# Enviar para remoto
git push origin main
# Puxar últimas mudanças
git pull origin main
```

<BaseQuiz id="devops-git-1" correct="D">
  <template #question>
    Qual é a diferença entre `git pull` e `git fetch`?
  </template>
  
  <BaseQuizOption value="A">Não há diferença</BaseQuizOption>
  <BaseQuizOption value="B">git pull envia mudanças, git fetch puxa mudanças</BaseQuizOption>
  <BaseQuizOption value="C">git pull funciona localmente, git fetch funciona remotamente</BaseQuizOption>
  <BaseQuizOption value="D" correct>git fetch baixa mudanças sem mesclar, git pull baixa e mescla mudanças</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git fetch` baixa mudanças do repositório remoto, mas não as mescla no seu branch atual. `git pull` executa ambas as operações: ele busca e depois mescla as mudanças.
  </BaseQuizAnswer>
</BaseQuiz>

### Gerenciamento de Branch

Gerencie diferentes fluxos de desenvolvimento e lançamentos.

```bash
# Criar branch
git checkout -b feature-branch
# Mesclar branch
git merge feature-branch
# Listar branches
git branch -a
# Mudar branch
git checkout main
# Deletar branch
git branch -d feature-branch
# Resetar para commit anterior
git reset --hard HEAD~1
# Visualizar histórico de commits
git log --oneline
```

### GitHub: Hospedagem de Código e Colaboração

Hospede repositórios e gerencie o desenvolvimento colaborativo.

```bash
# Comandos do GitHub CLI
gh repo create myrepo
gh repo clone user/repo
gh pr create --title "Nova funcionalidade"
gh pr list
gh pr merge 123
gh issue create --title "Relatório de bug"
gh release create v1.0.0
# Criar pull request
git push -u origin feature-branch
# Então crie PR no GitHub/GitLab
```

### Revisão de Código e Qualidade

Garanta a qualidade do código através de revisão por pares e verificações automatizadas.

```bash
# Exemplo de hooks pre-commit
#!/bin/sh
# Executar testes antes do commit
npm test
if [ $? -ne 0 ]; then
  echo "Testes falharam"
  exit 1
fi
```

## Monitoramento e Observabilidade

### Prometheus: Coleta de Métricas

Monitore métricas de sistema e aplicação com dados de séries temporais.

```promql
# Uso da CPU
cpu_usage_percent{instance="server1"}
# Uso de memória
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
# Taxa de requisições HTTP
rate(http_requests_total[5m])
# Exemplo de regras de alerta
ALERT HighCPUUsage
  IF cpu_usage_percent > 80
  FOR 5m
```

### Grafana: Dashboard de Visualização

Crie dashboards e visualizações para dados de monitoramento.

```bash
# Criar dashboard
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json
# Obter dashboard
curl http://admin:admin@localhost:3000/api/dashboards/uid/dashboard-uid
```

### ELK Stack: Gerenciamento de Logs

Colete, pesquise e analise dados de log em toda a infraestrutura.

```json
# Consultas Elasticsearch
# Pesquisar logs
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
# Configuração Logstash
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

### Monitoramento de Desempenho de Aplicações

Rastreie o desempenho da aplicação e métricas de experiência do usuário.

```ruby
# Configuração do agente New Relic
# Adicionar à aplicação
require 'newrelic_rpm'
```

```python
# Métricas Datadog
from datadog import DogStatsdClient
statsd = DogStatsdClient('localhost', 8125)
statsd.increment('web.requests')
statsd.histogram('web.response_time', 0.75)
```

## Gerenciamento de Plataforma em Nuvem

### AWS CLI: Amazon Web Services

Interaja com serviços AWS a partir da linha de comando.

```bash
# Configurar AWS CLI
aws configure
# Listar instâncias EC2
aws ec2 describe-instances
# Criar bucket S3
aws s3 mb s3://my-bucket-name
# Implantar função Lambda
aws lambda create-function --function-name myfunction --runtime python3.8 --role arn:aws:iam::123456789:role/lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip
# Listar serviços em execução
aws ecs list-services --cluster my-cluster
```

### Azure CLI: Microsoft Azure

Gerencie recursos e serviços do Azure.

```bash
# Fazer login no Azure
az login
# Criar grupo de recursos
az group create --name myResourceGroup --location eastus
# Criar máquina virtual
az vm create --resource-group myResourceGroup --name myVM --image Ubuntu2204 --admin-username azureuser --generate-ssh-keys
# Listar web apps
az webapp list
```

### Google Cloud: GCP

Implante e gerencie aplicações na Google Cloud Platform.

```bash
# Autenticar com GCP
gcloud auth login
# Definir projeto
gcloud config set project my-project-id
# Implantar aplicação App Engine
gcloud app deploy
# Criar instância Compute Engine
gcloud compute instances create my-instance --zone=us-central1-a
# Gerenciar cluster Kubernetes
gcloud container clusters create my-cluster --num-nodes=3
```

### Gerenciamento Multi-Cloud

Ferramentas para gerenciar recursos em múltiplos provedores de nuvem.

```python
# Pulumi (IaC multi-cloud)
import pulumi_aws as aws
import pulumi_gcp as gcp
# Criar bucket S3 AWS
bucket = aws.s3.Bucket("my-bucket")
# Criar bucket de armazenamento GCP
gcp_bucket = gcp.storage.Bucket("my-gcp-bucket")
```

## Gerenciamento de Segurança e Segredos

### HashiCorp Vault: Gerenciamento de Segredos

HashiCorp Vault é uma ferramenta para acessar segredos de forma segura. Um segredo é qualquer coisa que você deseja controlar rigorosamente o acesso, como chaves de API, senhas ou certificados.

```bash
# Escrever um segredo
vault kv put secret/myapp/config username=myuser password=mypassword
# Ler um segredo
vault kv get secret/myapp/config
# Deletar um segredo
vault kv delete secret/myapp/config
# Habilitar método de autenticação
vault auth enable kubernetes
# Criar política
vault policy write myapp-policy myapp-policy.hcl
```

### Verificação de Segurança: Trivy & SonarQube

Verifique contêineres e código em busca de vulnerabilidades de segurança.

```bash
# Verificação de contêiner Trivy
trivy image nginx:latest
# Verificar sistema de arquivos
trivy fs /path/to/project
# Análise SonarQube
sonar-scanner -Dsonar.projectKey=myproject -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000
```

### Gerenciamento de Certificados SSL/TLS

Gerencie certificados SSL para comunicações seguras.

```bash
# Let's Encrypt com Certbot
certbot --nginx -d example.com
# Renovar certificados
certbot renew
# Verificar expiração do certificado
openssl x509 -in cert.pem -text -noout | grep "Not After"
# Gerar certificado autoassinado
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

### Segurança de Contêineres

Proteja aplicações conteinerizadas e ambientes de tempo de execução.

```bash
# Executar contêiner como usuário não-root
docker run --user 1000:1000 myapp
# Verificar imagem em busca de vulnerabilidades
docker scan myapp:latest
```

```dockerfile
# Usar imagens distroless
FROM gcr.io/distroless/java:11
COPY app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## Otimização de Desempenho

### Monitoramento de Desempenho do Sistema

Se você está gerenciando servidores, configurando implantações ou consertando algo que acabou de quebrar em produção, estes comandos ajudam você a se mover mais rápido e trabalhar de forma mais inteligente.

```bash
# Uso de CPU e memória
htop
# Uso de disco
df -h
# Conexões de rede
netstat -tulpn
# Monitoramento de processos
ps aux | grep process_name
# Carga do sistema
uptime
# Detalhes da memória
free -h
```

### Ajuste Fino de Desempenho de Aplicações

Otimize o desempenho da aplicação e a utilização de recursos.

```bash
# Monitoramento de desempenho JVM
jstat -gc -t PID 1s
# Desempenho Node.js
node --inspect app.js
# Otimização de consulta de banco de dados
EXPLAIN ANALYZE SELECT * FROM table WHERE condition;
# Ajuste fino do Nginx
nginx -t && nginx -s reload
```

### Teste de Carga e Benchmarking

Teste o desempenho da aplicação sob várias condições de carga.

```bash
# Apache Bench
ab -n 1000 -c 10 http://example.com/
# wrk HTTP benchmarking
wrk -t12 -c400 -d30s http://example.com/
# Teste de carga Artillery
artillery run load-test.yml
# Horizontal Pod Autoscaler do Kubernetes
kubectl autoscale deployment myapp --cpu-percent=70 --min=1 --max=10
```

### Desempenho do Banco de Dados

Monitore e otimize o desempenho e as consultas do banco de dados.

```sql
# Desempenho MySQL
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Threads_connected';
```

```sql
# Monitoramento PostgreSQL
SELECT * FROM pg_stat_activity;
```

```bash
# Monitoramento Redis
redis-cli --latency
redis-cli info memory
```

## Instalação de Ferramentas DevOps

### Gerenciadores de Pacotes

Instale ferramentas usando gerenciadores de pacotes do sistema.

```bash
# Ubuntu/Debian
apt update && apt install -y docker.io kubectl terraform
# CentOS/RHEL
yum install -y docker kubernetes-client terraform
# macOS Homebrew
brew install docker kubectl terraform ansible
```

### Instalação de Runtime de Contêiner

Configure Docker e ferramentas de orquestração de contêineres.

```bash
# Instalar Docker
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker
# Instalar Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
```

### Ferramentas de Linha de Comando da Nuvem

Instale interfaces de linha de comando para os principais provedores de nuvem.

```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && ./aws/install
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
# Google Cloud SDK
curl https://sdk.cloud.google.com | bash
```

## Configuração de Ambiente

### Gerenciamento de Variáveis de Ambiente

Gerencie a configuração em diferentes ambientes de forma segura.

```bash
# Exemplo de arquivo .env
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=your-api-key-here
ENVIRONMENT=production
# Carregar variáveis de ambiente
export $(cat .env | xargs)
# Variáveis de ambiente Docker
docker run -e NODE_ENV=production -e API_KEY=secret myapp
# Configmap do Kubernetes
kubectl create configmap app-config --from-env-file=.env
```

### Descoberta de Serviço e Configuração

Gerencie a descoberta de serviços e a configuração dinâmica.

```bash
# Registro de serviço Consul
consul services register myservice.json
# Obter saúde do serviço
consul health service web
# Armazenamento chave-valor Etcd
etcdctl put /config/database/host localhost
etcdctl get /config/database/host
```

### Configuração de Ambiente de Desenvolvimento

Configure ambientes de desenvolvimento consistentes usando contêineres.

```dockerfile
# Dockerfile de Desenvolvimento
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

```yaml
# Docker Compose para desenvolvimento
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

### Endurecimento do Ambiente de Produção

Proteja e otimize ambientes de produção.

```ini
# Configuração de serviço Systemd
[Unit]
Description=Minha Aplicação
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

## Automação e Orquestração

### Automação de Infraestrutura com Ansible

Automatize o provisionamento de infraestrutura e o gerenciamento de configuração.

```yaml
# Exemplo de playbook Ansible
---
- hosts: webservers
  become: yes
  tasks:
    - name: Instalar nginx
      apt:
        name: nginx
        state: present
    - name: Iniciar nginx
      service:
        name: nginx
        state: started
        enabled: yes
    - name: Implantar aplicação
      copy:
        src: /local/app
        dest: /var/www/html
```

### Orquestração de Fluxo de Trabalho

Orquestre fluxos de trabalho complexos e pipelines de dados.

```python
# Exemplo de DAG Apache Airflow
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

### Automação Orientada a Eventos

Acione a automação com base em eventos do sistema e webhooks.

```bash
# Manipulador de webhook do GitHub
#!/bin/bash
if [ "$1" == "push" ]; then
  git pull origin main
  docker build -t myapp .
  docker run -d --name myapp-$(date +%s) myapp
fi
# Webhook de alerta Prometheus
curl -X POST http://webhook-handler/deploy \
  -H "Content-Type: application/json" \
  -d '{"service": "myapp", "action": "restart"}'
```

### Integração ChatOps

Integre operações DevOps com plataformas de chat para automação colaborativa.

```bash
# Exemplo de comando de bot Slack
/deploy myapp to production
/rollback myapp to v1.2.3
/scale myapp replicas=5
/status infrastructure
# Webhook do Microsoft Teams
curl -H "Content-Type: application/json" \
  -d '{"text": "Implantação concluída com sucesso"}' \
  $TEAMS_WEBHOOK_URL
```

## Links Relevantes

- <router-link to="/linux">Folha de Dicas Linux</router-link>
- <router-link to="/shell">Folha de Dicas Shell</router-link>
- <router-link to="/git">Folha de Dicas Git</router-link>
- <router-link to="/docker">Folha de Dicas Docker</router-link>
- <router-link to="/kubernetes">Folha de Dicas Kubernetes</router-link>
- <router-link to="/ansible">Folha de Dicas Ansible</router-link>
- <router-link to="/jenkins">Folha de Dicas Jenkins</router-link>
- <router-link to="/python">Folha de Dicas Python</router-link>

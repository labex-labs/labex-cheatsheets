---
title: 'Hoja de Trucos de DevOps | LabEx'
description: 'Aprenda prácticas de DevOps con esta hoja de trucos completa. Referencia rápida para CI/CD, automatización, infraestructura como código, monitoreo, contenerización y flujos de trabajo modernos de entrega de software.'
pdfUrl: '/cheatsheets/pdf/devops-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de DevOps
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/devops">Aprenda DevOps con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda prácticas de DevOps a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de DevOps que cubren operaciones esenciales, gestión de infraestructura, pipelines de CI/CD, contenerización, monitoreo y automatización. Aprenda a desplegar aplicaciones, gestionar infraestructura como código, automatizar flujos de trabajo e implementar prácticas modernas de DevOps para una entrega de software eficiente.
</base-disclaimer-content>
</base-disclaimer>

## Infraestructura como Código (IaC)

### Terraform: Aprovisionamiento de Infraestructura

Defina y aprovisione infraestructura usando lenguaje de configuración declarativo.

```bash
# Inicializar Terraform
terraform init
# Planificar cambios de infraestructura
terraform plan
# Aplicar cambios de infraestructura
terraform apply
# Destruir infraestructura
terraform destroy
# Formatear archivos de configuración
terraform fmt
# Validar configuración
terraform validate
```

<BaseQuiz id="devops-terraform-1" correct="B">
  <template #question>
    ¿Qué hace `terraform plan`?
  </template>
  
  <BaseQuizOption value="A">Aplica cambios de infraestructura inmediatamente</BaseQuizOption>
  <BaseQuizOption value="B" correct>Muestra qué cambios se realizarán sin aplicarlos</BaseQuizOption>
  <BaseQuizOption value="C">Destruye toda la infraestructura</BaseQuizOption>
  <BaseQuizOption value="D">Inicializa Terraform</BaseQuizOption>
  
  <BaseQuizAnswer>
    `terraform plan` crea un plan de ejecución que muestra lo que Terraform hará cuando ejecute `terraform apply`. Es una simulación (dry-run) que le ayuda a revisar los cambios antes de aplicarlos.
  </BaseQuizAnswer>
</BaseQuiz>

### Ansible: Gestión de Configuración

Automatice el despliegue de aplicaciones y la gestión de configuración.

```bash
# Ejecutar playbook
ansible-playbook site.yml
# Ejecutar playbook en hosts específicos
ansible-playbook -i inventory site.yml
# Verificar sintaxis
ansible-playbook --syntax-check site.yml
# Ejecutar con usuario específico
ansible-playbook -u ubuntu site.yml
```

### CloudFormation: IaC Nativo de AWS

Aprovisione recursos de AWS usando plantillas JSON/YAML.

```bash
# Crear stack
aws cloudformation create-stack --stack-name mystack --template-body file://template.yml
# Actualizar stack
aws cloudformation update-stack --stack-name mystack --template-body file://template.yml
# Eliminar stack
aws cloudformation delete-stack --stack-name mystack
```

## Gestión de Contenedores

### Docker: Contenerización

Construya, envíe y ejecute aplicaciones en contenedores.

```bash
# Construir imagen
docker build -t myapp:latest .
# Ejecutar contenedor
docker run -d -p 8080:80 myapp:latest
# Listar contenedores en ejecución
docker ps
# Detener contenedor
docker stop container_id
# Eliminar contenedor
docker rm container_id
```

### Kubernetes: Orquestación de Contenedores

Despliegue y gestione aplicaciones contenerizadas a escala.

```bash
# Aplicar configuración
kubectl apply -f deployment.yml
# Obtener pods
kubectl get pods
# Escalar despliegue
kubectl scale deployment myapp --replicas=5
# Ver logs
kubectl logs pod_name
# Eliminar recursos
kubectl delete -f deployment.yml
```

<BaseQuiz id="devops-k8s-1" correct="A">
  <template #question>
    ¿Qué hace `kubectl apply -f deployment.yml`?
  </template>
  
  <BaseQuizOption value="A" correct>Crea o actualiza los recursos definidos en el archivo YAML</BaseQuizOption>
  <BaseQuizOption value="B">Elimina todos los recursos en el clúster</BaseQuizOption>
  <BaseQuizOption value="C">Solo crea nuevos recursos</BaseQuizOption>
  <BaseQuizOption value="D">Muestra lo que se crearía sin aplicar</BaseQuizOption>
  
  <BaseQuizAnswer>
    `kubectl apply` es un comando declarativo que crea recursos si no existen o los actualiza si ya existen. Es idempotente, lo que significa que puede ejecutarlo varias veces de forma segura.
  </BaseQuizAnswer>
</BaseQuiz>

### Helm: Gestor de Paquetes de Kubernetes

Gestione aplicaciones de Kubernetes usando charts.

```bash
# Instalar chart
helm install myrelease stable/nginx
# Actualizar release
helm upgrade myrelease stable/nginx
# Listar releases
helm list
# Desinstalar release
helm uninstall myrelease
```

## Gestión de Pipelines CI/CD

### Jenkins: Automatización de Construcción

Configure y gestione pipelines de integración continua.

```groovy
// Ejemplo de Jenkinsfile
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

### GitHub Actions: CI/CD en la Nube

Automatice flujos de trabajo directamente desde repositorios de GitHub.

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

Utilice las capacidades de CI/CD integradas de GitLab para flujos de trabajo DevOps completos.

```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - deploy
build_job:
  stage: build
  script:
    - echo "Construyendo la aplicación"
test_job:
  stage: test
  script:
    - echo "Ejecutando pruebas"
```

## Control de Versiones y Colaboración

### Git: Sistema de Control de Versiones

Rastree cambios y colabore en el desarrollo de código.

```bash
# Clonar repositorio
git clone https://github.com/user/repo.git
# Verificar estado
git status
# Añadir cambios
git add .
# Confirmar cambios
git commit -m "Añadir característica"
# Subir a remoto
git push origin main
# Bajar últimos cambios
git pull origin main
```

<BaseQuiz id="devops-git-1" correct="D">
  <template #question>
    ¿Cuál es la diferencia entre `git pull` y `git fetch`?
  </template>
  
  <BaseQuizOption value="A">No hay diferencia</BaseQuizOption>
  <BaseQuizOption value="B">git pull sube cambios, git fetch baja cambios</BaseQuizOption>
  <BaseQuizOption value="C">git pull funciona localmente, git fetch funciona remotamente</BaseQuizOption>
  <BaseQuizOption value="D" correct>git fetch descarga cambios sin fusionar, git pull descarga y fusiona cambios</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git fetch` descarga cambios del repositorio remoto pero no los fusiona en su rama actual. `git pull` realiza ambas operaciones: obtiene y luego fusiona los cambios.
  </BaseQuizAnswer>
</BaseQuiz>

### Gestión de Ramas

Administre diferentes flujos de desarrollo y lanzamientos.

```bash
# Crear rama
git checkout -b feature-branch
# Fusionar rama
git merge feature-branch
# Listar ramas
git branch -a
# Cambiar rama
git checkout main
# Eliminar rama
git branch -d feature-branch
# Revertir al commit anterior
git reset --hard HEAD~1
# Ver historial de commits
git log --oneline
```

### GitHub: Alojamiento y Colaboración de Código

Aloje repositorios y gestione el desarrollo colaborativo.

```bash
# Comandos de GitHub CLI
gh repo create myrepo
gh repo clone user/repo
gh pr create --title "Nueva característica"
gh pr list
gh pr merge 123
gh issue create --title "Reporte de error"
gh release create v1.0.0
# Crear pull request
git push -u origin feature-branch
# Luego crear PR en GitHub/GitLab
```

### Revisión de Código y Calidad

Asegure la calidad del código a través de la revisión por pares y comprobaciones automatizadas.

```bash
# Ejemplo de ganchos pre-commit
#!/bin/sh
# Ejecutar pruebas antes de confirmar
npm test
if [ $? -ne 0 ]; then
  echo "Las pruebas fallaron"
  exit 1
fi
```

## Monitoreo y Observabilidad

### Prometheus: Recolección de Métricas

Monitoree métricas de sistema y aplicación con datos de series temporales.

```promql
# Uso de CPU
cpu_usage_percent{instance="server1"}
# Uso de memoria
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
# Tasa de solicitudes HTTP
rate(http_requests_total[5m])
# Ejemplo de reglas de alerta
ALERT HighCPUUsage
  IF cpu_usage_percent > 80
  FOR 5m
```

### Grafana: Panel de Visualización

Cree paneles y visualizaciones para datos de monitoreo.

```bash
# Crear panel
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json
# Obtener panel
curl http://admin:admin@localhost:3000/api/dashboards/uid/dashboard-uid
```

### Pila ELK: Gestión de Logs

Recopile, busque y analice datos de logs en toda la infraestructura.

```json
# Consultas de Elasticsearch
# Buscar logs
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
# Configuración de Logstash
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

### Monitoreo del Rendimiento de Aplicaciones

Rastree el rendimiento de la aplicación y las métricas de experiencia del usuario.

```ruby
# Configuración del agente New Relic
# Añadir a la aplicación
require 'newrelic_rpm'
```

```python
# Métricas de Datadog
from datadog import DogStatsdClient
statsd = DogStatsdClient('localhost', 8125)
statsd.increment('web.requests')
statsd.histogram('web.response_time', 0.75)
```

## Gestión de Plataformas en la Nube

### AWS CLI: Amazon Web Services

Interactúe con los servicios de AWS desde la línea de comandos.

```bash
# Configurar AWS CLI
aws configure
# Listar instancias EC2
aws ec2 describe-instances
# Crear bucket S3
aws s3 mb s3://my-bucket-name
# Desplegar función Lambda
aws lambda create-function --function-name myfunction --runtime python3.8 --role arn:aws:iam::123456789:role/lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip
# Listar servicios en ejecución
aws ecs list-services --cluster my-cluster
```

### Azure CLI: Microsoft Azure

Administre recursos y servicios de Azure.

```bash
# Iniciar sesión en Azure
az login
# Crear grupo de recursos
az group create --name myResourceGroup --location eastus
# Crear máquina virtual
az vm create --resource-group myResourceGroup --name myVM --image Ubuntu2204 --admin-username azureuser --generate-ssh-keys
# Listar aplicaciones web
az webapp list
```

### Google Cloud: GCP

Despliegue y gestione aplicaciones en Google Cloud Platform.

```bash
# Autenticar con GCP
gcloud auth login
# Establecer proyecto
gcloud config set project my-project-id
# Desplegar aplicación App Engine
gcloud app deploy
# Crear instancia de Compute Engine
gcloud compute instances create my-instance --zone=us-central1-a
# Gestionar clúster de Kubernetes
gcloud container clusters create my-cluster --num-nodes=3
```

### Gestión Multi-Nube

Herramientas para gestionar recursos a través de múltiples proveedores de nube.

```python
# Pulumi (IaC multi-nube)
import pulumi_aws as aws
import pulumi_gcp as gcp
# Crear bucket S3 de AWS
bucket = aws.s3.Bucket("my-bucket")
# Crear bucket de almacenamiento de GCP
gcp_bucket = gcp.storage.Bucket("my-gcp-bucket")
```

## Gestión de Seguridad y Secretos

### HashiCorp Vault: Gestión de Secretos

HashiCorp Vault es una herramienta para acceder a secretos de forma segura. Un secreto es cualquier cosa cuyo acceso desee controlar estrictamente, como claves API, contraseñas o certificados.

```bash
# Escribir un secreto
vault kv put secret/myapp/config username=myuser password=mypassword
# Leer un secreto
vault kv get secret/myapp/config
# Eliminar un secreto
vault kv delete secret/myapp/config
# Habilitar método de autenticación
vault auth enable kubernetes
# Crear política
vault policy write myapp-policy myapp-policy.hcl
```

### Escaneo de Seguridad: Trivy y SonarQube

Escanee contenedores y código en busca de vulnerabilidades de seguridad.

```bash
# Escaneo de contenedores con Trivy
trivy image nginx:latest
# Escanear sistema de archivos
trivy fs /path/to/project
# Análisis de SonarQube
sonar-scanner -Dsonar.projectKey=myproject -Dsonar.sources=. -Dsonar.host.url=http://localhost:9000
```

### Gestión de Certificados SSL/TLS

Administre certificados SSL para comunicaciones seguras.

```bash
# Let's Encrypt con Certbot
certbot --nginx -d example.com
# Renovar certificados
certbot renew
# Verificar caducidad del certificado
openssl x509 -in cert.pem -text -noout | grep "Not After"
# Generar certificado autofirmado
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

### Seguridad de Contenedores

Asegure aplicaciones contenerizadas y entornos de ejecución.

```bash
# Ejecutar contenedor como usuario no root
docker run --user 1000:1000 myapp
# Escanear imagen en busca de vulnerabilidades
docker scan myapp:latest
```

```dockerfile
# Usar imágenes distroless
FROM gcr.io/distroless/java:11
COPY app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## Optimización del Rendimiento

### Monitoreo del Rendimiento del Sistema

Ya sea que esté administrando servidores, configurando despliegues o arreglando algo que acaba de romperse en producción, estos comandos le ayudan a moverse más rápido y a trabajar de manera más inteligente.

```bash
# Uso de CPU y memoria
htop
# Uso de disco
df -h
# Conexiones de red
netstat -tulpn
# Monitoreo de procesos
ps aux | grep process_name
# Carga del sistema
uptime
# Detalles de memoria
free -h
```

### Ajuste del Rendimiento de Aplicaciones

Optimice el rendimiento de la aplicación y la utilización de recursos.

```bash
# Monitoreo de rendimiento de JVM
jstat -gc -t PID 1s
# Rendimiento de Node.js
node --inspect app.js
# Optimización de consultas de base de datos
EXPLAIN ANALYZE SELECT * FROM table WHERE condition;
# Ajuste de rendimiento de Nginx
nginx -t && nginx -s reload
```

### Pruebas de Carga y Benchmarking

Pruebe el rendimiento de la aplicación bajo diversas condiciones de carga.

```bash
# Apache Bench
ab -n 1000 -c 10 http://example.com/
# wrk HTTP benchmarking
wrk -t12 -c400 -d30s http://example.com/
# Pruebas de carga con Artillery
artillery run load-test.yml
# Autoscaler horizontal de pods de Kubernetes
kubectl autoscale deployment myapp --cpu-percent=70 --min=1 --max=10
```

### Rendimiento de Bases de Datos

Monitoree y optimice el rendimiento y las consultas de la base de datos.

```sql
# Rendimiento de MySQL
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Threads_connected';
```

```sql
# Monitoreo de PostgreSQL
SELECT * FROM pg_stat_activity;
```

```bash
# Monitoreo de Redis
redis-cli --latency
redis-cli info memory
```

## Instalación de Herramientas DevOps

### Gestores de Paquetes

Instale herramientas usando gestores de paquetes del sistema.

```bash
# Ubuntu/Debian
apt update && apt install -y docker.io kubectl terraform
# CentOS/RHEL
yum install -y docker kubernetes-client terraform
# macOS Homebrew
brew install docker kubectl terraform ansible
```

### Instalación de Entornos de Ejecución de Contenedores

Configure Docker y herramientas de orquestación de contenedores.

```bash
# Instalar Docker
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker
# Instalar Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
```

### Herramientas de Línea de Comandos de la Nube

Instale interfaces de línea de comandos para los principales proveedores de nube.

```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && ./aws/install
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
# SDK de Google Cloud
curl https://sdk.cloud.google.com | bash
```

## Configuración del Entorno

### Gestión de Variables de Entorno

Administre la configuración a través de diferentes entornos de forma segura.

```bash
# Ejemplo de archivo .env
DATABASE_URL=postgresql://user:pass@localhost/db
API_KEY=your-api-key-here
ENVIRONMENT=production
# Cargar variables de entorno
export $(cat .env | xargs)
# Variables de entorno de Docker
docker run -e NODE_ENV=production -e API_KEY=secret myapp
# Configmap de Kubernetes
kubectl create configmap app-config --from-env-file=.env
```

### Descubrimiento de Servicios y Configuración

Administre el descubrimiento de servicios y la configuración dinámica.

```bash
# Registro de servicio de Consul
consul services register myservice.json
# Obtener salud del servicio
consul health service web
# Almacén de clave-valor de Etcd
etcdctl put /config/database/host localhost
etcdctl get /config/database/host
```

### Configuración del Entorno de Desarrollo

Configure entornos de desarrollo consistentes utilizando contenedores.

```dockerfile
# Dockerfile de Desarrollo
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
```

```yaml
# Docker Compose para desarrollo
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

### Endurecimiento del Entorno de Producción

Asegure y optimice los entornos de producción.

```ini
# Configuración de servicio Systemd
[Unit]
Description=Mi Aplicación
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

## Automatización y Orquestación

### Automatización de Infraestructura con Ansible

Automatice el aprovisionamiento de infraestructura y la gestión de configuración.

```yaml
# Ejemplo de playbook de Ansible
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
    - name: Desplegar aplicación
      copy:
        src: /local/app
        dest: /var/www/html
```

### Orquestación de Flujos de Trabajo

Orqueste flujos de trabajo complejos y pipelines de datos.

```python
# Ejemplo de DAG de Apache Airflow
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

### Automatización Basada en Eventos

Active la automatización basada en eventos del sistema y webhooks.

```bash
# Manejador de webhook de GitHub
#!/bin/bash
if [ "$1" == "push" ]; then
  git pull origin main
  docker build -t myapp .
  docker run -d --name myapp-$(date +%s) myapp
fi
# Webhook de alerta de Prometheus alertmanager
curl -X POST http://webhook-handler/deploy \
  -H "Content-Type: application/json" \
  -d '{"service": "myapp", "action": "restart"}'
```

### Integración ChatOps

Integre operaciones DevOps con plataformas de chat para automatización colaborativa.

```bash
# Ejemplo de comando de bot de Slack
/deploy myapp to production
/rollback myapp to v1.2.3
/scale myapp replicas=5
/status infrastructure
# Webhook de Microsoft Teams
curl -H "Content-Type: application/json" \
  -d '{"text": "Despliegue completado con éxito"}' \
  $TEAMS_WEBHOOK_URL
```

## Enlaces Relevantes

- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/git">Hoja de Trucos de Git</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>
- <router-link to="/kubernetes">Hoja de Trucos de Kubernetes</router-link>
- <router-link to="/ansible">Hoja de Trucos de Ansible</router-link>
- <router-link to="/jenkins">Hoja de Trucos de Jenkins</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>

---
title: 'Chuleta de Jenkins'
description: 'Aprenda Jenkins con nuestra hoja de trucos completa que cubre comandos esenciales, conceptos y mejores prácticas.'
pdfUrl: '/cheatsheets/pdf/jenkins-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Jenkins
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/jenkins">Aprende Jenkins con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende la automatización CI/CD de Jenkins a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Jenkins que cubren operaciones esenciales, creación de pipelines, gestión de plugins, automatización de compilaciones y técnicas avanzadas. Domina Jenkins para construir pipelines eficientes de integración y despliegue continuos para el desarrollo de software moderno.
</base-disclaimer-content>
</base-disclaimer>

## Instalación y Configuración

### Instalación en Linux

Instalar Jenkins en sistemas Ubuntu/Debian.

```bash
# Actualizar gestor de paquetes e instalar Java
sudo apt update
sudo apt install fontconfig openjdk-21-jre
java -version
# Añadir clave GPG de Jenkins
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
# Añadir repositorio de Jenkins
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
/etc/apt/sources.list.d/jenkins.list > /dev/null
# Instalar Jenkins
sudo apt update && sudo apt install jenkins
# Iniciar servicio de Jenkins
sudo systemctl start jenkins
sudo systemctl enable jenkins
```

### Windows y macOS

Instalar Jenkins usando instaladores o gestores de paquetes.

```bash
# Windows: Descargar instalador de Jenkins desde jenkins.io
# O usar Chocolatey
choco install jenkins
# macOS: Usar Homebrew
brew install jenkins-lts
# O descargar directamente desde:
# https://www.jenkins.io/download/
# Iniciar servicio de Jenkins
brew services start jenkins-lts
```

### Configuración Post-Instalación

Configuración inicial y desbloqueo de Jenkins.

```bash
# Obtener contraseña de administrador inicial
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# O para instalaciones de Docker
docker exec jenkins_container cat /var/jenkins_home/secrets/initialAdminPassword
# Acceder a la interfaz web de Jenkins
# Navegar a http://localhost:8080
# Ingresar la contraseña de administrador inicial
# Instalar plugins sugeridos o seleccionar plugins personalizados
```

### Configuración Inicial

Completar el asistente de configuración y crear el usuario administrador.

```bash
# Después de desbloquear Jenkins:
# 1. Instalar plugins sugeridos (recomendado)
# 2. Crear primer usuario administrador
# 3. Configurar URL de Jenkins
# 4. Empezar a usar Jenkins
# Verificar que Jenkins se está ejecutando
sudo systemctl status jenkins
# Revisar logs de Jenkins si es necesario
sudo journalctl -u jenkins.service
```

## Operaciones Básicas de Jenkins

### Acceso a Jenkins: Interfaz Web y Configuración de CLI

Acceder a Jenkins a través del navegador y configurar herramientas CLI.

```bash
# Acceder a la interfaz web de Jenkins
http://localhost:8080
# Descargar Jenkins CLI
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
# Probar conexión CLI
java -jar jenkins-cli.jar -s http://localhost:8080 help
# Listar comandos disponibles
java -jar jenkins-cli.jar -s http://localhost:8080 help
```

### Creación de Trabajo (Job): `create-job` / Interfaz Web

Crear nuevos trabajos de compilación usando CLI o interfaz web.

```bash
# Crear trabajo desde configuración XML
java -jar jenkins-cli.jar -auth user:token create-job my-job < job-config.xml
# Crear trabajo freestyle simple vía UI web:
# 1. Hacer clic en "New Item" (Nuevo Elemento)
# 2. Ingresar nombre del trabajo
# 3. Seleccionar "Freestyle project"
# 4. Configurar pasos de compilación
# 5. Guardar configuración
```

### Listar Trabajos: `list-jobs`

Ver todos los trabajos configurados en Jenkins.

```bash
# Listar todos los trabajos
java -jar jenkins-cli.jar -auth user:token list-jobs
# Listar trabajos que coinciden con un patrón
java -jar jenkins-cli.jar -auth user:token list-jobs "*test*"
# Obtener configuración del trabajo
java -jar jenkins-cli.jar -auth user:token get-job my-job > job-config.xml
```

## Gestión de Trabajos

### Compilar Trabajos: `build`

Desencadenar y gestionar compilaciones de trabajos.

```bash
# Compilar un trabajo
java -jar jenkins-cli.jar -auth user:token build my-job
# Compilar con parámetros
java -jar jenkins-cli.jar -auth user:token build my-job -p PARAM=value
# Compilar y esperar finalización
java -jar jenkins-cli.jar -auth user:token build my-job -s -v
# Compilar y seguir la salida de la consola
java -jar jenkins-cli.jar -auth user:token build my-job -f
```

### Control de Trabajos: `enable-job` / `disable-job`

Habilitar o deshabilitar trabajos.

```bash
# Habilitar un trabajo
java -jar jenkins-cli.jar -auth user:token enable-job my-job
# Deshabilitar un trabajo
java -jar jenkins-cli.jar -auth user:token disable-job my-job
# Verificar estado del trabajo en la UI web
# Navegar al dashboard del trabajo
# Buscar botón "Disable/Enable" (Deshabilitar/Habilitar)
```

### Eliminación de Trabajos: `delete-job`

Eliminar trabajos de Jenkins.

```bash
# Eliminar un trabajo
java -jar jenkins-cli.jar -auth user:token delete-job my-job
# Eliminar trabajos en lote (con precaución)
for job in job1 job2 job3; do
  java -jar jenkins-cli.jar -auth user:token delete-job $job
done
```

### Salida de Consola: `console`

Ver logs de compilación y salida de consola.

```bash
# Ver salida de consola de la última compilación
java -jar jenkins-cli.jar -auth user:token console my-job
# Ver número de compilación específico
java -jar jenkins-cli.jar -auth user:token console my-job 15
# Seguir salida de consola en tiempo real
java -jar jenkins-cli.jar -auth user:token console my-job -f
```

## Gestión de Pipelines

### Creación de Pipeline

Crear y configurar pipelines de Jenkins.

```groovy
// Jenkinsfile básico (Pipeline Declarativo)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Building application...'
                sh 'make build'
            }
        }

        stage('Test') {
            steps {
                echo 'Running tests...'
                sh 'make test'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Deploying application...'
                sh 'make deploy'
            }
        }
    }
}
```

### Sintaxis de Pipeline

Sintaxis y directivas comunes de pipeline.

```groovy
// Sintaxis de Pipeline Scripted
node {
    stage('Checkout') {
        checkout scm
    }

    stage('Build') {
        sh 'make build'
    }

    stage('Test') {
        sh 'make test'
        junit 'target/test-results/*.xml'
    }
}
// Ejecución paralela
stages {
    stage('Parallel Tests') {
        parallel {
            stage('Unit Tests') {
                steps {
                    sh 'make unit-test'
                }
            }
            stage('Integration Tests') {
                steps {
                    sh 'make integration-test'
                }
            }
        }
    }
}
```

### Configuración de Pipeline

Configuración avanzada de pipelines y opciones.

```groovy
// Pipeline con acciones post-compilación
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }

    post {
        always {
            echo 'Esto siempre se ejecuta'
        }
        success {
            echo 'La compilación fue exitosa'
        }
        failure {
            echo 'La compilación falló'
            emailext subject: 'Build Failed',
                     body: 'Build failed',
                     to: 'team@company.com'
        }
    }
}
```

### Desencadenadores de Pipeline (Triggers)

Configurar desencadenadores automáticos de pipelines.

```groovy
// Pipeline con desencadenadores
pipeline {
    agent any

    triggers {
        // Encuesta SCM cada 5 minutos
        pollSCM('H/5 * * * *')

        // Programación tipo Cron
        cron('H 2 * * *')  // Diario a las 2 AM

        // Desencadenador de trabajo upstream
        upstream(upstreamProjects: 'upstream-job',
                threshold: hudson.model.Result.SUCCESS)
    }

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}
```

## Gestión de Plugins

### Instalación de Plugins: CLI

Instalar plugins usando la interfaz de línea de comandos.

```bash
# Instalar plugin vía CLI (requiere reinicio)
java -jar jenkins-cli.jar -auth user:token install-plugin git
# Instalar múltiples plugins
java -jar jenkins-cli.jar -auth user:token install-plugin \
  git maven-plugin docker-plugin
# Instalar desde archivo .hpi
java -jar jenkins-cli.jar -auth user:token install-plugin \
  /path/to/plugin.hpi
# Listar plugins instalados
java -jar jenkins-cli.jar -auth user:token list-plugins
# Instalación de plugins vía plugins.txt (para Docker)
# Crear archivo plugins.txt:
git:latest
maven-plugin:latest
docker-plugin:latest
pipeline-stage-view:latest
# Usar la herramienta jenkins-plugin-cli
jenkins-plugin-cli --plugins git maven-plugin docker-plugin
```

### Plugins Esenciales

Plugins comúnmente utilizados para diferentes propósitos.

```bash
# Plugins de Compilación y SCM
git                    # Integración con Git
github                 # Integración con GitHub
maven-plugin          # Soporte para compilaciones Maven
gradle                # Soporte para compilaciones Gradle
# Plugins de Pipeline
workflow-aggregator   # Suite de plugins de Pipeline
pipeline-stage-view   # Vista de etapas de Pipeline
blue-ocean           # UI moderna para pipelines
# Despliegue e Integración
docker-plugin        # Integración con Docker
kubernetes           # Despliegue en Kubernetes
ansible              # Automatización con Ansible
# Calidad y Pruebas
junit                # Reportes de pruebas JUnit
jacoco              # Cobertura de código
sonarqube           # Análisis de calidad de código
```

### Interfaz Web de Gestión de Plugins

Administrar plugins a través de la interfaz web de Jenkins.

```bash
# Acceder al Administrador de Plugins:
# 1. Navegar a Manage Jenkins (Administrar Jenkins)
# 2. Hacer clic en "Manage Plugins" (Administrar Plugins)
# 3. Usar las pestañas Available/Installed/Updates (Disponibles/Instalados/Actualizaciones)
# 4. Buscar plugins
# 5. Seleccionar e instalar
# 6. Reiniciar Jenkins si es necesario
# Proceso de actualización de plugins:
# 1. Revisar pestaña "Updates" (Actualizaciones)
# 2. Seleccionar plugins a actualizar
# 3. Hacer clic en "Download now and install after restart" (Descargar ahora e instalar después de reiniciar)
```

## Gestión de Usuarios y Seguridad

### Gestión de Usuarios

Crear y administrar usuarios de Jenkins.

```bash
# Habilitar seguridad en Jenkins:
# 1. Manage Jenkins → Configure Global Security
# 2. Habilitar "Jenkins' own user database" (Base de datos de usuarios propia de Jenkins)
# 3. Permitir registro de usuarios (configuración inicial)
# 4. Establecer estrategia de autorización
# Crear usuario vía CLI (requiere permisos apropiados)
# Los usuarios se crean típicamente a través de la UI web:
# 1. Manage Jenkins → Manage Users (Administrar Usuarios)
# 2. Hacer clic en "Create User" (Crear Usuario)
# 3. Rellenar detalles del usuario
# 4. Asignar roles/permisos
```

### Autenticación y Autorización

Configurar reinos de seguridad y estrategias de autorización.

```bash
# Opciones de configuración de seguridad:
# 1. Security Realm (Reino de Seguridad - cómo se autentican los usuarios):
#    - Jenkins' own user database
#    - LDAP
#    - Active Directory
#    - Matrix-based security
#    - Role-based authorization
# 2. Authorization Strategy (Estrategia de Autorización):
#    - Anyone can do anything (Cualquiera puede hacer cualquier cosa)
#    - Legacy mode
#    - Logged-in users can do anything (Usuarios registrados pueden hacer cualquier cosa)
#    - Matrix-based security
#    - Project-based Matrix Authorization
```

### Tokens API

Generar y administrar tokens API para acceso CLI.

```bash
# Generar token API:
# 1. Clic en nombre de usuario → Configure (Configurar)
# 2. Sección API Token
# 3. Clic en "Add new Token" (Añadir nuevo Token)
# 4. Ingresar nombre del token
# 5. Generar y copiar token
# Usar token API con CLI
java -jar jenkins-cli.jar -auth username:api-token \
  -s http://localhost:8080 list-jobs
# Almacenar credenciales de forma segura
echo "username:api-token" > ~/.jenkins-cli-auth
chmod 600 ~/.jenkins-cli-auth
```

### Gestión de Credenciales

Administrar credenciales almacenadas para trabajos y pipelines.

```bash
# Administrar credenciales vía CLI
java -jar jenkins-cli.jar -auth user:token \
  list-credentials system::system::jenkins
# Crear credenciales XML e importar
java -jar jenkins-cli.jar -auth user:token \
  create-credentials-by-xml system::system::jenkins \
  < credential.xml
```

```groovy
// Acceder a credenciales en pipelines
withCredentials([usernamePassword(
  credentialsId: 'my-credentials',
  usernameVariable: 'USERNAME',
  passwordVariable: 'PASSWORD'
)]) {
  sh 'docker login -u $USERNAME -p $PASSWORD'
}
```

## Monitoreo de Compilaciones y Solución de Problemas

### Estado y Logs de Compilación

Monitorear el estado de la compilación y acceder a logs detallados.

```bash
# Verificar estado de compilación
java -jar jenkins-cli.jar -auth user:token console my-job
# Obtener información del trabajo
java -jar jenkins-cli.jar -auth user:token get-job my-job
# Monitorear cola de compilación
# UI Web: Jenkins Dashboard → Build Queue
# Muestra compilaciones pendientes y su estado
# Acceso al historial de compilaciones
# UI Web: Job → Build History
# Muestra todas las compilaciones anteriores con su estado
```

### Información del Sistema

Obtener información del sistema Jenkins y diagnósticos.

```bash
# Información del sistema
java -jar jenkins-cli.jar -auth user:token version
# Información de nodos
java -jar jenkins-cli.jar -auth user:token list-computers
# Consola Groovy (solo administradores)
# Manage Jenkins → Script Console
# Ejecutar scripts Groovy para obtener información del sistema:
println Jenkins.instance.version
println Jenkins.instance.getRootDir()
println System.getProperty("java.version")
```

### Análisis de Logs

Acceder y analizar los logs del sistema Jenkins.

```bash
# Ubicación de logs del sistema
# Linux: /var/log/jenkins/jenkins.log
# Windows: C:\Program Files\Jenkins\jenkins.out.log
# Ver logs
tail -f /var/log/jenkins/jenkins.log
# Configuración de niveles de log
# Manage Jenkins → System Log
# Añadir nuevo registrador de logs para componentes específicos
# Ubicaciones comunes de logs:
sudo journalctl -u jenkins.service     # Logs de Systemd
sudo cat /var/lib/jenkins/jenkins.log  # Archivo de log de Jenkins
```

### Monitoreo de Rendimiento

Monitorear el rendimiento y uso de recursos de Jenkins.

```bash
# Monitoreo incorporado
# Manage Jenkins → Load Statistics
# Muestra la utilización de ejecutores a lo largo del tiempo
# Monitoreo de JVM
# Manage Jenkins → Manage Nodes → Master
# Muestra uso de memoria, CPU y propiedades del sistema
# Tendencias de compilación
# Instalar el plugin "Build History Metrics"
# Ver tendencias de duración de compilación y tasas de éxito
# Monitoreo de uso de disco
# Instalar el plugin "Disk Usage"
# Monitorear espacio de trabajo y almacenamiento de artefactos de compilación
```

## Configuración y Ajustes de Jenkins

### Configuración Global

Configurar ajustes globales de Jenkins y herramientas.

```bash
# Configuración Global de Herramientas
# Manage Jenkins → Global Tool Configuration
# Configurar:
# - Instalaciones de JDK
# - Instalaciones de Git
# - Instalaciones de Maven
# - Instalaciones de Docker
# Configuración del Sistema
# Manage Jenkins → Configure System
# Establecer:
# - URL de Jenkins
# - Mensaje del sistema
# - # de ejecutores
# - Quiet period (Período de silencio)
# - Límites de sondeo SCM
```

### Variables de Entorno

Configurar variables de entorno y propiedades del sistema de Jenkins.

```bash
# Variables de entorno incorporadas
BUILD_NUMBER          # Número de compilación
BUILD_ID              # ID de compilación
JOB_NAME             # Nombre del trabajo
WORKSPACE            # Ruta del espacio de trabajo del trabajo
JENKINS_URL          # URL de Jenkins
NODE_NAME            # Nombre del nodo
# Variables de entorno personalizadas
# Manage Jenkins → Configure System
# Global properties → Environment variables
# Añadir pares clave-valor para acceso global
```

### Configuración de Jenkins como Código

Administrar la configuración de Jenkins usando el plugin JCasC.

```yaml
# Archivo de configuración JCasC (jenkins.yaml)
jenkins:
  systemMessage: "Jenkins configurado como código"
  numExecutors: 4
  securityRealm:
    local:
      allowsSignup: false
      users:
       - id: "admin"
         password: "admin123"
# Aplicar configuración
# Establecer variable de entorno CASC_JENKINS_CONFIG
export CASC_JENKINS_CONFIG=/path/to/jenkins.yaml
```

## Mejores Prácticas

### Mejores Prácticas de Seguridad

Mantener su instancia de Jenkins segura y lista para producción.

```bash
# Recomendaciones de seguridad:
# 1. Habilitar seguridad y autenticación
# 2. Usar autorización basada en matriz
# 3. Actualizaciones de seguridad regulares
# 4. Limitar permisos de usuario
# 5. Usar tokens API en lugar de contraseñas
# Asegurar la configuración de Jenkins:
# - Deshabilitar CLI sobre remoting
# - Usar HTTPS con certificados válidos
# - Copia de seguridad regular de JENKINS_HOME
# - Monitorear avisos de seguridad
# - Usar plugins de credenciales para secretos
```

### Optimización del Rendimiento

Optimizar Jenkins para un mejor rendimiento y escalabilidad.

```bash
# Consejos de rendimiento:
# 1. Usar compilaciones distribuidas con agentes
# 2. Optimizar scripts de compilación y dependencias
# 3. Limpiar compilaciones antiguas automáticamente
# 4. Usar librerías de pipeline para reutilización
# 5. Monitorear el espacio en disco y el uso de memoria
# Optimización de compilación:
# - Usar compilaciones incrementales siempre que sea posible
# - Ejecución paralela de etapas
# - Caché de artefactos
# - Limpieza del espacio de trabajo
# - Ajuste de asignación de recursos
```

## Enlaces Relevantes

- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>
- <router-link to="/kubernetes">Hoja de Trucos de Kubernetes</router-link>
- <router-link to="/ansible">Hoja de Trucos de Ansible</router-link>
- <router-link to="/git">Hoja de Trucos de Git</router-link>
- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>

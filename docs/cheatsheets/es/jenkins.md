---
title: 'Chuleta de Jenkins | LabEx'
description: 'Aprenda CI/CD con Jenkins con esta hoja de trucos completa. Referencia rápida para pipelines, trabajos, plugins, automatización, integración continua y flujos de trabajo DevOps de Jenkins.'
pdfUrl: '/cheatsheets/pdf/jenkins-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Jenkins
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/jenkins">Aprenda Jenkins con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda la automatización CI/CD de Jenkins a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Jenkins que cubren operaciones esenciales, creación de pipelines, gestión de plugins, automatización de compilaciones y técnicas avanzadas. Domine Jenkins para construir pipelines eficientes de integración y despliegue continuos para el desarrollo de software moderno.
</base-disclaimer-content>
</base-disclaimer>

## Instalación y Configuración

### Instalación en Linux

Instalar Jenkins en sistemas Ubuntu/Debian.

```bash
# Actualizar el gestor de paquetes e instalar Java
sudo apt update
sudo apt install fontconfig openjdk-21-jre
java -version
# Añadir la clave GPG de Jenkins
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
# Añadir el repositorio de Jenkins
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
/etc/apt/sources.list.d/jenkins.list > /dev/null
# Instalar Jenkins
sudo apt update && sudo apt install jenkins
# Iniciar el servicio de Jenkins
sudo systemctl start jenkins
sudo systemctl enable jenkins
```

### Windows y macOS

Instalar Jenkins usando instaladores o gestores de paquetes.

```bash
# Windows: Descargar el instalador de Jenkins desde jenkins.io
# O usar Chocolatey
choco install jenkins
# macOS: Usar Homebrew
brew install jenkins-lts
# O descargar directamente desde:
# https://www.jenkins.io/download/
# Iniciar el servicio de Jenkins
brew services start jenkins-lts
```

### Configuración Post-Instalación

Configuración inicial y desbloqueo de Jenkins.

```bash
# Obtener la contraseña de administrador inicial
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# O para instalaciones de Docker
docker exec jenkins_container cat /var/jenkins_home/secrets/initialAdminPassword
# Acceder a la interfaz web de Jenkins
# Navegar a http://localhost:8080
# Introducir la contraseña de administrador inicial
# Instalar plugins sugeridos o seleccionar plugins personalizados
```

### Configuración Inicial

Completar el asistente de configuración y crear el usuario administrador.

```bash
# Después de desbloquear Jenkins:
# 1. Instalar plugins sugeridos (recomendado)
# 2. Crear el primer usuario administrador
# 3. Configurar la URL de Jenkins
# 4. Empezar a usar Jenkins
# Verificar que Jenkins se está ejecutando
sudo systemctl status jenkins
# Revisar los logs de Jenkins si es necesario
sudo journalctl -u jenkins.service
```

## Operaciones Básicas de Jenkins

### Acceder a Jenkins: Interfaz Web y Configuración de CLI

Acceder a Jenkins a través del navegador y configurar las herramientas CLI.

```bash
# Acceder a la interfaz web de Jenkins
http://localhost:8080
# Descargar Jenkins CLI
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
# Probar la conexión CLI
java -jar jenkins-cli.jar -s http://localhost:8080 help
# Listar comandos disponibles
java -jar jenkins-cli.jar -s http://localhost:8080 help
```

### Creación de Trabajos: `create-job` / Interfaz Web

Crear nuevos trabajos de compilación usando CLI o interfaz web.

```bash
# Crear trabajo a partir de configuración XML
java -jar jenkins-cli.jar -auth usuario:token create-job mi-trabajo < job-config.xml
# Crear trabajo freestyle simple a través de la interfaz web:
# 1. Hacer clic en "Nuevo Elemento"
# 2. Introducir el nombre del trabajo
# 3. Seleccionar "Proyecto Freestyle"
# 4. Configurar pasos de compilación
# 5. Guardar configuración
```

### Listar Trabajos: `list-jobs`

Ver todos los trabajos configurados en Jenkins.

```bash
# Listar todos los trabajos
java -jar jenkins-cli.jar -auth usuario:token list-jobs
# Listar trabajos que coinciden con un patrón
java -jar jenkins-cli.jar -auth usuario:token list-jobs "*test*"
# Obtener la configuración del trabajo
java -jar jenkins-cli.jar -auth usuario:token get-job mi-trabajo > job-config.xml
```

## Gestión de Trabajos

### Compilar Trabajos: `build`

Activar y gestionar compilaciones de trabajos.

```bash
# Compilar un trabajo
java -jar jenkins-cli.jar -auth usuario:token build mi-trabajo
# Compilar con parámetros
java -jar jenkins-cli.jar -auth usuario:token build mi-trabajo -p PARAM=valor
# Compilar y esperar a que finalice
java -jar jenkins-cli.jar -auth usuario:token build mi-trabajo -s -v
# Compilar y seguir la salida de la consola
java -jar jenkins-cli.jar -auth usuario:token build mi-trabajo -f
```

<BaseQuiz id="jenkins-build-1" correct="B">
  <template #question>
    ¿Qué hace la bandera `-s` en `jenkins-cli.jar build mi-trabajo -s`?
  </template>
  
  <BaseQuizOption value="A">Omite la compilación</BaseQuizOption>
  <BaseQuizOption value="B" correct>Espera a que la compilación finalice (síncrono)</BaseQuizOption>
  <BaseQuizOption value="C">Muestra el estado de la compilación</BaseQuizOption>
  <BaseQuizOption value="D">Detiene la compilación</BaseQuizOption>
  
  <BaseQuizAnswer>
    La bandera `-s` hace que el comando de compilación sea síncrono, lo que significa que espera a que la compilación finalice antes de devolver el control. Sin ella, el comando se devuelve inmediatamente después de activar la compilación.
  </BaseQuizAnswer>
</BaseQuiz>

### Control de Trabajos: `enable-job` / `disable-job`

Habilitar o deshabilitar trabajos.

```bash
# Habilitar un trabajo
java -jar jenkins-cli.jar -auth usuario:token enable-job mi-trabajo
# Deshabilitar un trabajo
java -jar jenkins-cli.jar -auth usuario:token disable-job mi-trabajo
# Verificar el estado del trabajo en la interfaz web
# Navegar al panel del trabajo
# Buscar el botón "Deshabilitar/Habilitar"
```

<BaseQuiz id="jenkins-job-control-1" correct="B">
  <template #question>
    ¿Qué sucede cuando se deshabilita un trabajo de Jenkins?
  </template>
  
  <BaseQuizOption value="A">El trabajo se elimina permanentemente</BaseQuizOption>
  <BaseQuizOption value="B" correct>La configuración del trabajo se conserva pero no se ejecutará automáticamente</BaseQuizOption>
  <BaseQuizOption value="C">El trabajo se mueve a una carpeta diferente</BaseQuizOption>
  <BaseQuizOption value="D">Se elimina todo el historial de compilaciones</BaseQuizOption>
  
  <BaseQuizAnswer>
    Deshabilitar un trabajo evita que se ejecute automáticamente (compilaciones programadas, activadores, etc.) pero conserva la configuración del trabajo y el historial de compilaciones. Se puede volver a habilitar más tarde.
  </BaseQuizAnswer>
</BaseQuiz>

### Eliminación de Trabajos: `delete-job`

Eliminar trabajos de Jenkins.

```bash
# Eliminar un trabajo
java -jar jenkins-cli.jar -auth usuario:token delete-job mi-trabajo
# Eliminar trabajos en lote (con precaución)
for job in trabajo1 trabajo2 trabajo3; do
  java -jar jenkins-cli.jar -auth usuario:token delete-job $job
done
```

### Salida de Consola: `console`

Ver los logs de compilación y la salida de la consola.

```bash
# Ver la salida de la consola de la última compilación
java -jar jenkins-cli.jar -auth usuario:token console mi-trabajo
# Ver un número de compilación específico
java -jar jenkins-cli.jar -auth usuario:token console mi-trabajo 15
# Seguir la salida de la consola en tiempo real
java -jar jenkins-cli.jar -auth usuario:token console mi-trabajo -f
```

<BaseQuiz id="jenkins-console-1" correct="C">
  <template #question>
    ¿Qué hace la bandera `-f` en `jenkins-cli.jar console mi-trabajo -f`?
  </template>
  
  <BaseQuizOption value="A">Fuerza la detención de la compilación</BaseQuizOption>
  <BaseQuizOption value="B">Muestra solo las compilaciones fallidas</BaseQuizOption>
  <BaseQuizOption value="C" correct>Sigue la salida de la consola en tiempo real</BaseQuizOption>
  <BaseQuizOption value="D">Formatea la salida como JSON</BaseQuizOption>
  
  <BaseQuizAnswer>
    La bandera `-f` sigue la salida de la consola en tiempo real, similar a `tail -f` en Linux. Esto es útil para monitorear las compilaciones mientras se ejecutan.
  </BaseQuizAnswer>
</BaseQuiz>

## Gestión de Pipelines

### Creación de Pipelines

Crear y configurar pipelines de Jenkins.

```groovy
// Jenkinsfile básico (Pipeline Declarativo)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Construyendo la aplicación...'
                sh 'make build'
            }
        }

        stage('Test') {
            steps {
                echo 'Ejecutando pruebas...'
                sh 'make test'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Desplegando la aplicación...'
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
            emailext subject: 'Compilación Fallida',
                     body: 'La compilación falló',
                     to: 'equipo@empresa.com'
        }
    }
}
```

### Activadores de Pipeline

Configurar activadores automáticos de pipeline.

```groovy
// Pipeline con activadores
pipeline {
    agent any

    triggers {
        // Encuesta SCM cada 5 minutos
        pollSCM('H/5 * * * *')

        // Programación tipo Cron
        cron('H 2 * * *')  // Diario a las 2 AM

        // Activador de trabajo upstream
        upstream(upstreamProjects: 'trabajo-upstream',
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
java -jar jenkins-cli.jar -auth usuario:token install-plugin git
# Instalar múltiples plugins
java -jar jenkins-cli.jar -auth usuario:token install-plugin \
  git maven-plugin docker-plugin
# Instalar desde archivo .hpi
java -jar jenkins-cli.jar -auth usuario:token install-plugin \
  /ruta/al/plugin.hpi
# Listar plugins instalados
java -jar jenkins-cli.jar -auth usuario:token list-plugins
# Instalación de plugins a través de plugins.txt (para Docker)
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
# 1. Navegar a Administrar Jenkins
# 2. Hacer clic en "Administrar Plugins"
# 3. Usar las pestañas Disponible/Instalado/Actualizaciones
# 4. Buscar plugins
# 5. Seleccionar e instalar
# 6. Reiniciar Jenkins si es necesario
# Proceso de actualización de plugins:
# 1. Revisar la pestaña "Actualizaciones"
# 2. Seleccionar plugins a actualizar
# 3. Hacer clic en "Descargar ahora e instalar después de reiniciar"
```

## Gestión de Usuarios y Seguridad

### Gestión de Usuarios

Crear y administrar usuarios de Jenkins.

```bash
# Habilitar seguridad en Jenkins:
# 1. Administrar Jenkins → Configurar Seguridad Global
# 2. Habilitar "Base de datos de usuarios propia de Jenkins"
# 3. Permitir que los usuarios se registren (configuración inicial)
# 4. Establecer estrategia de autorización
# Crear usuario a través de CLI (requiere permisos apropiados)
# Los usuarios se crean típicamente a través de la interfaz web:
# 1. Administrar Jenkins → Administrar Usuarios
# 2. Hacer clic en "Crear Usuario"
# 3. Rellenar detalles del usuario
# 4. Asignar roles/permisos
```

### Autenticación y Autorización

Configurar reinos de seguridad y estrategias de autorización.

```bash
# Opciones de configuración de seguridad:
# 1. Reino de Seguridad (cómo se autentican los usuarios):
#    - Base de datos de usuarios propia de Jenkins
#    - LDAP
#    - Active Directory
#    - Seguridad basada en matriz
#    - Autorización basada en roles
# 2. Estrategia de Autorización:
#    - Cualquiera puede hacer cualquier cosa
#    - Modo heredado (Legacy mode)
#    - Usuarios conectados pueden hacer cualquier cosa
#    - Seguridad basada en matriz
#    - Autorización de Matriz basada en Proyectos
```

### Tokens de API

Generar y administrar tokens de API para acceso CLI.

```bash
# Generar token de API:
# 1. Hacer clic en nombre de usuario → Configurar
# 2. Sección Token de API
# 3. Hacer clic en "Añadir nuevo Token"
# 4. Introducir nombre del token
# 5. Generar y copiar el token
# Usar el token de API con CLI
java -jar jenkins-cli.jar -auth nombreusuario:token-api \
  -s http://localhost:8080 list-jobs
# Almacenar credenciales de forma segura
echo "nombreusuario:token-api" > ~/.jenkins-cli-auth
chmod 600 ~/.jenkins-cli-auth
```

### Gestión de Credenciales

Administrar credenciales almacenadas para trabajos y pipelines.

```bash
# Administrar credenciales vía CLI
java -jar jenkins-cli.jar -auth usuario:token \
  list-credentials system::system::jenkins
# Crear XML de credenciales e importar
java -jar jenkins-cli.jar -auth usuario:token \
  create-credentials-by-xml system::system::jenkins \
  < credential.xml
```

```groovy
// Acceder a credenciales en pipelines
withCredentials([usernamePassword(
  credentialsId: 'mis-credenciales',
  usernameVariable: 'USUARIO',
  passwordVariable: 'CONTRASEÑA'
)]) {
  sh 'docker login -u $USUARIO -p $CONTRASEÑA'
}
```

## Monitoreo de Compilaciones y Solución de Problemas

### Estado y Logs de Compilación

Monitorear el estado de la compilación y acceder a logs detallados.

```bash
# Verificar estado de compilación
java -jar jenkins-cli.jar -auth usuario:token console mi-trabajo
# Obtener información del trabajo
java -jar jenkins-cli.jar -auth usuario:token get-job mi-trabajo
# Monitorear la cola de compilación
# Interfaz Web: Panel de Jenkins → Cola de Compilación
# Muestra las compilaciones pendientes y su estado
# Acceso al historial de compilaciones
# Interfaz Web: Trabajo → Historial de Compilaciones
# Muestra todas las compilaciones anteriores con su estado
```

### Información del Sistema

Obtener información del sistema Jenkins y diagnósticos.

```bash
# Información del sistema
java -jar jenkins-cli.jar -auth usuario:token version
# Información de nodos
java -jar jenkins-cli.jar -auth usuario:token list-computers
# Consola Groovy (solo administradores)
# Administrar Jenkins → Consola de Scripts
# Ejecutar scripts Groovy para obtener información del sistema:
println Jenkins.instance.version
println Jenkins.instance.getRootDir()
println System.getProperty("java.version")
```

### Análisis de Logs

Acceder y analizar los logs del sistema Jenkins.

```bash
# Ubicación de los logs del sistema
# Linux: /var/log/jenkins/jenkins.log
# Windows: C:\Program Files\Jenkins\jenkins.out.log
# Ver logs
tail -f /var/log/jenkins/jenkins.log
# Configuración de niveles de log
# Administrar Jenkins → Log del Sistema
# Añadir nuevo registrador de logs para componentes específicos
# Ubicaciones comunes de logs:
sudo journalctl -u jenkins.service     # Logs de Systemd
sudo cat /var/lib/jenkins/jenkins.log  # Archivo de log de Jenkins
```

### Monitoreo de Rendimiento

Monitorear el rendimiento y el uso de recursos de Jenkins.

```bash
# Monitoreo incorporado
# Administrar Jenkins → Estadísticas de Carga
# Muestra la utilización del ejecutor a lo largo del tiempo
# Monitoreo de JVM
# Administrar Jenkins → Administrar Nodos → Maestro
# Muestra el uso de memoria, CPU y propiedades del sistema
# Tendencias de compilación
# Instalar el plugin "Build History Metrics"
# Ver tendencias de duración de compilación y tasas de éxito
# Monitoreo de uso de disco
# Instalar el plugin "Disk Usage"
# Monitorear el espacio de trabajo y el almacenamiento de artefactos de compilación
```

## Configuración y Ajustes de Jenkins

### Configuración Global

Configurar ajustes globales y herramientas de Jenkins.

```bash
# Configuración Global de Herramientas
# Administrar Jenkins → Configuración Global de Herramientas
# Configurar:
# - Instalaciones de JDK
# - Instalaciones de Git
# - Instalaciones de Maven
# - Instalaciones de Docker
# Configuración del Sistema
# Administrar Jenkins → Configurar Sistema
# Establecer:
# - URL de Jenkins
# - Mensaje del sistema
# - # de ejecutores
# - Período de silencio (Quiet period)
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
# Administrar Jenkins → Configurar Sistema
# Propiedades globales → Variables de entorno
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
# Establecer la variable de entorno CASC_JENKINS_CONFIG
export CASC_JENKINS_CONFIG=/ruta/a/jenkins.yaml
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
# 5. Usar tokens de API en lugar de contraseñas
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

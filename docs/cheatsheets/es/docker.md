---
title: 'Hoja de Trucos de Docker | LabEx'
description: 'Aprenda la contenerización con Docker con esta hoja de trucos completa. Referencia rápida para comandos de Docker, imágenes, contenedores, Dockerfile, Docker Compose y orquestación de contenedores.'
pdfUrl: '/cheatsheets/pdf/docker-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Docker
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/docker">Aprende Docker con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende la contenerización con Docker a través de laboratorios prácticos y escenarios del mundo real. LabEx proporciona cursos completos de Docker que cubren la gestión esencial de contenedores, la construcción de imágenes, Docker Compose, redes, volúmenes y despliegue. Domina la orquestación de contenedores y las técnicas modernas de despliegue de aplicaciones.
</base-disclaimer-content>
</base-disclaimer>

## Instalación y Configuración

### Instalación en Linux

Instalar Docker en sistemas Ubuntu/Debian.

```bash
# Actualizar gestor de paquetes
sudo apt update
# Instalar prerrequisitos
sudo apt install apt-transport-https ca-certificates curl
software-properties-common
# Añadir la clave GPG oficial de Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg
| sudo apt-key add -
# Añadir repositorio de Docker
sudo add-apt-repository "deb [arch=amd64]
https://download.docker.com/linux/ubuntu bionic stable"
# Instalar Docker
sudo apt update && sudo apt install docker-ce
# Iniciar servicio Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### Windows y macOS

Instalar Docker Desktop para gestión basada en GUI.

```bash
# Windows: Descargar Docker Desktop desde docker.com
# macOS: Usar Homebrew o descargar desde docker.com
brew install --cask docker
# O descargar directamente desde:
# https://www.docker.com/products/docker-desktop
```

### Configuración Post-Instalación

Configurar Docker para uso sin root y verificar la instalación.

```bash
# Añadir usuario al grupo docker (Linux)
sudo usermod -aG docker $USER
# Cerrar sesión y volver a iniciar para cambios de grupo
# Verificar instalación de Docker
docker --version
docker run hello-world
```

### Instalación de Docker Compose

Instalar Docker Compose para aplicaciones multi-contenedor.

```bash
# Linux: Instalar vía curl
sudo curl -L
"https://github.com/docker/compose/releases/download
/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o
/usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
# Verificar instalación
docker-compose --version
# Nota: Docker Desktop incluye Compose
```

## Comandos Básicos de Docker

### Información del Sistema: `docker version` / `docker system info`

Comprobar los detalles de la instalación y el entorno de Docker.

```bash
# Mostrar información de la versión de Docker
docker version
# Mostrar información del sistema Docker
information
docker system info
# Mostrar ayuda para comandos Docker
docker help
docker <comando> --help
```

### Ejecutar Contenedores: `docker run`

Crear e iniciar un contenedor a partir de una imagen.

```bash
# Ejecutar un contenedor interactivamente
docker run -it ubuntu:latest bash
# Ejecutar contenedor en segundo plano
(detached)
docker run -d --name mi-contenedor
nginx
# Ejecutar con mapeo de puertos
docker run -p 8080:80 nginx
# Ejecutar con auto-eliminación después de salir
docker run --rm hello-world
```

<BaseQuiz id="docker-run-1" correct="C">
  <template #question>
    ¿Qué hace <code>docker run -d</code>?
  </template>
  
  <BaseQuizOption value="A">Ejecuta el contenedor en modo depuración</BaseQuizOption>
  <BaseQuizOption value="B">Elimina el contenedor después de que se detiene</BaseQuizOption>
  <BaseQuizOption value="C" correct>Ejecuta el contenedor en modo separado (background)</BaseQuizOption>
  <BaseQuizOption value="D">Ejecuta el contenedor con la configuración predeterminada</BaseQuizOption>
  
  <BaseQuizAnswer>
    El flag <code>-d</code> ejecuta el contenedor en modo separado, lo que significa que se ejecuta en segundo plano y devuelve el control a la terminal inmediatamente. Esto es útil para servicios de larga ejecución.
  </BaseQuizAnswer>
</BaseQuiz>

### Listar Contenedores: `docker ps`

Ver contenedores en ejecución y detenidos.

```bash
# Listar contenedores en ejecución
docker ps
# Listar todos los contenedores (incluidos los detenidos)
docker ps -a
# Listar solo IDs de contenedores
docker ps -q
# Mostrar el último contenedor creado
docker ps -l
```

## Gestión de Contenedores

### Ciclo de Vida del Contenedor: `start` / `stop` / `restart`

Controlar el estado de ejecución del contenedor.

```bash
# Detener un contenedor en ejecución
docker stop nombre_contenedor
# Iniciar un contenedor detenido
docker start nombre_contenedor
# Reiniciar un contenedor
docker restart nombre_contenedor
# Pausar/reanudar procesos del contenedor
docker pause nombre_contenedor
docker unpause nombre_contenedor
```

### Ejecutar Comandos: `docker exec`

Ejecutar comandos dentro de contenedores en ejecución.

```bash
# Ejecutar shell bash interactiva
docker exec -it nombre_contenedor bash
# Ejecutar un solo comando
docker exec nombre_contenedor ls -la
# Ejecutar como usuario diferente
docker exec -u root nombre_contenedor whoami
# Ejecutar en directorio específico
docker exec -w /app nombre_contenedor pwd
```

### Eliminación de Contenedores: `docker rm`

Eliminar contenedores del sistema.

```bash
# Eliminar un contenedor detenido
docker rm nombre_contenedor
# Eliminar forzosamente un contenedor en ejecución
docker rm -f nombre_contenedor
# Eliminar múltiples contenedores
docker rm contenedor1 contenedor2
# Eliminar todos los contenedores detenidos
docker container prune
```

### Registros de Contenedores: `docker logs`

Ver la salida del contenedor y depurar problemas.

```bash
# Ver registros del contenedor
docker logs nombre_contenedor
# Seguir registros en tiempo real
docker logs -f nombre_contenedor
# Mostrar solo registros recientes
docker logs --tail 50 nombre_contenedor
# Mostrar registros con marcas de tiempo
docker logs -t nombre_contenedor
```

## Gestión de Imágenes

### Construcción de Imágenes: `docker build`

Crear imágenes Docker a partir de Dockerfiles.

```bash
# Construir imagen desde el directorio actual
docker build .
# Construir y etiquetar una imagen
docker build -t mi_app:latest .
# Construir con argumentos de construcción
docker build --build-arg VERSION=1.0 -t mi_app .
# Construir sin usar caché
docker build --no-cache -t mi_app .
```

<BaseQuiz id="docker-build-1" correct="A">
  <template #question>
    ¿Qué hace <code>docker build -t mi_app:latest .</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Construye una imagen Docker con la etiqueta "mi_app:latest" desde el directorio actual</BaseQuizOption>
  <BaseQuizOption value="B">Ejecuta un contenedor llamado "mi_app"</BaseQuizOption>
  <BaseQuizOption value="C">Descarga la imagen "mi_app:latest" de Docker Hub</BaseQuizOption>
  <BaseQuizOption value="D">Elimina la imagen "mi_app:latest"</BaseQuizOption>
  
  <BaseQuizAnswer>
    El flag <code>-t</code> etiqueta la imagen con el nombre "mi_app:latest", y el <code>.</code> especifica el contexto de construcción (directorio actual). Este comando construye una nueva imagen a partir de un Dockerfile en el directorio actual.
  </BaseQuizAnswer>
</BaseQuiz>

### Inspección de Imágenes: `docker images` / `docker inspect`

Listar y examinar imágenes Docker.

```bash
# Listar todas las imágenes locales
docker images
# Listar imágenes con filtros específicos
docker images nginx
# Mostrar detalles de la imagen
docker inspect nombre_imagen
# Ver historial de construcción de la imagen
docker history nombre_imagen
```

### Operaciones de Registro: `docker pull` / `docker push`

Descargar y subir imágenes a registros.

```bash
# Descargar imagen de Docker Hub
docker pull nginx:latest
# Descargar versión específica
docker pull ubuntu:20.04
# Subir imagen al registro
docker push miusuario/mi_app:latest
# Etiquetar imagen antes de subir
docker tag mi_app:latest miusuario/mi_app:v1.0
```

### Limpieza de Imágenes: `docker rmi` / `docker image prune`

Eliminar imágenes no utilizadas para liberar espacio en disco.

```bash
# Eliminar una imagen específica
docker rmi nombre_imagen
# Eliminar imágenes no utilizadas
docker image prune
# Eliminar todas las imágenes no utilizadas (no solo las colgantes)
docker image prune -a
# Eliminar forzosamente la imagen
docker rmi -f nombre_imagen
```

## Conceptos Básicos de Dockerfile

### Instrucciones Esenciales

Comandos principales de Dockerfile para construir imágenes.

```dockerfile
# Imagen base
FROM ubuntu:20.04
# Establecer información del mantenedor
LABEL maintainer="usuario@ejemplo.com"
# Instalar paquetes
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# Copiar archivos del host al contenedor
COPY app.py /app/
# Establecer directorio de trabajo
WORKDIR /app
# Exponer puerto
EXPOSE 8000
```

<BaseQuiz id="dockerfile-1" correct="B">
  <template #question>
    ¿Cuál es el propósito de la instrucción <code>FROM</code> en un Dockerfile?
  </template>
  
  <BaseQuizOption value="A">Copia archivos del host al contenedor</BaseQuizOption>
  <BaseQuizOption value="B" correct>Especifica la imagen base sobre la cual construir</BaseQuizOption>
  <BaseQuizOption value="C">Establece variables de entorno</BaseQuizOption>
  <BaseQuizOption value="D">Define el comando a ejecutar cuando el contenedor arranca</BaseQuizOption>
  
  <BaseQuizAnswer>
    La instrucción <code>FROM</code> debe ser la primera instrucción no comentada en un Dockerfile. Especifica la imagen base sobre la cual se construirá su imagen, proporcionando la base para su contenedor.
  </BaseQuizAnswer>
</BaseQuiz>

### Configuración de Ejecución

Configurar cómo se ejecuta el contenedor.

```dockerfile
# Establecer variables de entorno
ENV PYTHON_ENV=production
ENV PORT=8000
# Crear usuario para seguridad
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser
# Definir comando de inicio
CMD ["python3", "app.py"]
# O usar ENTRYPOINT para comandos fijos
ENTRYPOINT ["python3"]
CMD ["app.py"]
# Establecer comprobación de salud
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/ || exit 1
```

## Docker Compose

### Comandos Básicos de Compose: `docker-compose up` / `docker-compose down`

Iniciar y detener aplicaciones multi-contenedor.

```bash
# Iniciar servicios en primer plano
docker-compose up
# Iniciar servicios en segundo plano
docker-compose up -d
# Construir e iniciar servicios
docker-compose up --build
# Detener y eliminar servicios
docker-compose down
# Detener y eliminar con volúmenes
docker-compose down -v
```

<BaseQuiz id="docker-compose-1" correct="D">
  <template #question>
    ¿Qué hace <code>docker-compose up -d</code>?
  </template>
  
  <BaseQuizOption value="A">Detiene todos los contenedores en ejecución</BaseQuizOption>
  <BaseQuizOption value="B">Construye imágenes sin iniciar contenedores</BaseQuizOption>
  <BaseQuizOption value="C">Muestra los registros de todos los servicios</BaseQuizOption>
  <BaseQuizOption value="D" correct>Inicia todos los servicios definidos en docker-compose.yml en modo separado</BaseQuizOption>
  
  <BaseQuizAnswer>
    El flag <code>-d</code> ejecuta los contenedores en modo separado (background). <code>docker-compose up</code> lee el archivo docker-compose.yml e inicia todos los servicios definidos, facilitando la gestión de aplicaciones multi-contenedor.
  </BaseQuizAnswer>
</BaseQuiz>

### Gestión de Servicios

Controlar servicios individuales dentro de aplicaciones Compose.

```bash
# Listar servicios en ejecución
docker-compose ps
# Ver registros de un servicio
docker-compose logs nombre_servicio
# Seguir registros para todos los servicios
docker-compose logs -f
# Reiniciar un servicio específico
docker-compose restart nombre_servicio
```

### Ejemplo de docker-compose.yml

Configuración de ejemplo para una aplicación multi-servicio.

```yaml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      -
DATABASE_URL=postgresql://user:pass@db:5432/myapp
    depends_on:
      - db
    volumes:
      - .:/app

  db:
    image: postgres:13
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - db_data:/var/lib/postgresql/data
volumes:
  db_data:
```

## Redes y Volúmenes

### Redes de Contenedores

Conectar contenedores y exponer servicios.

```bash
# Listar redes
docker network ls
# Crear una red personalizada
docker network create mi_red
# Ejecutar contenedor en red específica
docker run --network mi_red nginx
# Conectar contenedor en ejecución a la red
docker network connect mi_red nombre_contenedor
# Inspeccionar detalles de la red
docker network inspect mi_red
```

### Mapeo de Puertos

Exponer puertos de contenedores al sistema host.

```bash
# Mapear un solo puerto
docker run -p 8080:80 nginx
```

<BaseQuiz id="docker-port-1" correct="A">
  <template #question>
    En <code>docker run -p 8080:80 nginx</code>, ¿qué significan los números de puerto?
  </template>
  
  <BaseQuizOption value="A" correct>8080 es el puerto del host, 80 es el puerto del contenedor</BaseQuizOption>
  <BaseQuizOption value="B">80 es el puerto del host, 8080 es el puerto del contenedor</BaseQuizOption>
  <BaseQuizOption value="C">Ambos puertos son puertos de contenedor</BaseQuizOption>
  <BaseQuizOption value="D">Ambos puertos son puertos de host</BaseQuizOption>
  
  <BaseQuizAnswer>
    El formato es <code>-p puerto_host:puerto_contenedor</code>. El puerto 8080 en su máquina host se mapea al puerto 80 dentro del contenedor, lo que le permite acceder al servidor web nginx que se ejecuta en el contenedor a través de localhost:8080.
  </BaseQuizAnswer>
</BaseQuiz>

```bash
# Mapear múltiples puertos
docker run -p 8080:80 -p 8443:443 nginx
# Mapear a una interfaz de host específica
docker run -p 127.0.0.1:8080:80 nginx
# Exponer todos los puertos definidos en la imagen
docker run -P nginx
```

### Volúmenes de Datos: `docker volume`

Persistir y compartir datos entre contenedores.

```bash
# Crear un volumen con nombre
docker volume create mi_volumen
# Listar todos los volúmenes
docker volume ls
# Inspeccionar detalles del volumen
docker volume inspect mi_volumen
# Eliminar volumen
docker volume rm mi_volumen
# Eliminar volúmenes no utilizados
docker volume prune
```

### Montaje de Volúmenes

Montar volúmenes con nombre y directorios del host en contenedores.

```bash
# Montar volumen con nombre
docker run -v mi_volumen:/data nginx
# Montar directorio del host (bind mount)
docker run -v /ruta/en/host:/ruta/en/contenedor nginx
# Montar directorio actual
docker run -v $(pwd):/app nginx
# Montaje de solo lectura
docker run -v /ruta/en/host:/ruta/en/contenedor:ro nginx
```

## Inspección y Depuración de Contenedores

### Detalles del Contenedor: `docker inspect`

Obtener información detallada sobre contenedores e imágenes.

```bash
# Inspeccionar configuración del contenedor
docker inspect nombre_contenedor
# Obtener información específica usando formato
docker inspect --format='{{.State.Status}}'
nombre_contenedor
# Obtener dirección IP
docker inspect --format='{{.NetworkSettings.IPAddress}}'
nombre_contenedor
# Obtener volúmenes montados
docker inspect --format='{{.Mounts}}' nombre_contenedor
```

### Monitoreo de Recursos

Monitorear el uso de recursos y el rendimiento del contenedor.

```bash
# Mostrar procesos en ejecución en el contenedor
docker top nombre_contenedor
# Mostrar estadísticas de uso de recursos en vivo
docker stats
# Mostrar estadísticas para un contenedor específico
docker stats nombre_contenedor
# Monitorear eventos en tiempo real
docker events
```

### Operaciones de Archivos: `docker cp`

Copiar archivos entre contenedores y el sistema host.

```bash
# Copiar archivo del contenedor al host
docker cp nombre_contenedor:/ruta/al/archivo ./
# Copiar archivo del host al contenedor
docker cp ./archivo nombre_contenedor:/ruta/al/destino
# Copiar directorio
docker cp ./directorio
nombre_contenedor:/ruta/al/destino/
# Copiar con modo archivo para preservar permisos
docker cp -a ./directorio nombre_contenedor:/ruta/
```

### Solución de Problemas

Depurar problemas de contenedores y conectividad.

```bash
# Comprobar código de salida del contenedor
docker inspect --format='{{.State.ExitCode}}'
nombre_contenedor
# Ver procesos del contenedor
docker exec nombre_contenedor ps aux
# Probar conectividad de red
docker exec nombre_contenedor ping google.com
# Comprobar uso de disco
docker exec nombre_contenedor df -h
```

## Registro y Autenticación

### Operaciones de Docker Hub: `docker login` / `docker search`

Autenticarse e interactuar con Docker Hub.

```bash
# Iniciar sesión en Docker Hub
docker login
# Iniciar sesión en registro específico
docker login registry.ejemplo.com
# Buscar imágenes en Docker Hub
docker search nginx
# Buscar con filtro
docker search --filter stars=100 nginx
```

### Etiquetado y Publicación de Imágenes

Preparar y publicar imágenes en registros.

```bash
# Etiquetar imagen para el registro
docker tag mi_app:latest miusuario/mi_app:v1.0
docker tag mi_app:latest
registry.ejemplo.com/mi_app:latest
# Subir a Docker Hub
docker push miusuario/mi_app:v1.0
# Subir a registro privado
docker push registry.ejemplo.com/mi_app:latest
```

### Registro Privado

Trabajar con registros Docker privados.

```bash
# Descargar de registro privado
docker pull registry.empresa.com/mi_app:latest
# Ejecutar registro local
docker run -d -p 5000:5000 --name registro registry:2
# Subir al registro local
docker tag mi_app localhost:5000/mi_app
docker push localhost:5000/mi_app
```

### Seguridad de Imágenes

Verificar la integridad y seguridad de las imágenes.

```bash
# Habilitar la Confianza de Contenido de Docker
export DOCKER_CONTENT_TRUST=1
# Firmar y subir imagen
docker push miusuario/mi_app:signed
# Inspeccionar firmas de imágenes
docker trust inspect miusuario/mi_app:signed
# Escanear imágenes en busca de vulnerabilidades
docker scan mi_app:latest
```

## Limpieza y Mantenimiento del Sistema

### Limpieza del Sistema: `docker system prune`

Eliminar recursos no utilizados de Docker para liberar espacio en disco.

```bash
# Eliminar contenedores, redes, imágenes no utilizadas
docker system prune
# Incluir volúmenes no utilizados en la limpieza
docker system prune -a --volumes
# Eliminar todo (usar con precaución)
docker system prune -a -f
# Mostrar uso de espacio
docker system df
```

### Limpieza Dirigida

Eliminar tipos específicos de recursos no utilizados.

```bash
# Eliminar contenedores detenidos
docker container prune
# Eliminar imágenes no utilizadas
docker image prune -a
# Eliminar volúmenes no utilizados
docker volume prune
# Eliminar redes no utilizadas
docker network prune
```

### Operaciones Masivas

Realizar operaciones en múltiples contenedores/imágenes.

```bash
# Detener todos los contenedores en ejecución
docker stop $(docker ps -q)
# Eliminar todos los contenedores
docker rm $(docker ps -aq)
# Eliminar todas las imágenes
docker rmi $(docker images -q)
# Eliminar solo imágenes colgantes (dangling)
docker rmi $(docker images -f "dangling=true" -q)
```

### Límites de Recursos

Controlar el consumo de recursos de los contenedores.

```bash
# Limitar el uso de memoria
docker run --memory=512m nginx
# Limitar el uso de CPU
docker run --cpus="1.5" nginx
# Limitar tanto CPU como memoria
docker run --memory=1g --cpus="2.0" nginx
# Establecer política de reinicio
docker run --restart=always nginx
```

## Configuración y Ajustes de Docker

### Configuración del Daemon

Configurar el daemon de Docker para uso en producción.

```bash
# Editar configuración del daemon
sudo nano
/etc/docker/daemon.json
# Configuración de ejemplo:
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
# Reiniciar servicio Docker
sudo systemctl restart docker
```

### Variables de Entorno

Configurar el comportamiento del cliente Docker con variables de entorno.

```bash
# Establecer host de Docker
export
DOCKER_HOST=tcp://docker-remoto:2376
# Habilitar verificación TLS
export DOCKER_TLS_VERIFY=1
export
DOCKER_CERT_PATH=/ruta/a/cert
# Establecer registro predeterminado
export
DOCKER_REGISTRY=registry.empresa.com
# Salida de depuración
export DOCKER_BUILDKIT=1
```

### Ajuste de Rendimiento

Optimizar Docker para un mejor rendimiento.

```bash
# Habilitar características experimentales
echo '{"experimental": true}' |
sudo tee
/etc/docker/daemon.json
# Opciones del controlador de almacenamiento
{
  "storage-driver": "overlay2",
  "storage-opts": [

"overlay2.override_kernel_check
=true"
  ]
}
# Configurar logging
{
  "log-driver": "syslog",
  "log-opts": {"syslog-address":
"udp://logs.empresa.com:514"}
}
```

## Mejores Prácticas

### Mejores Prácticas de Seguridad

Mantener sus contenedores seguros y listos para producción.

```dockerfile
# Ejecutar como usuario no root en Dockerfile
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# Usar etiquetas de imagen específicas, no 'latest'
FROM node:16.20.0-alpine
# Usar sistemas de archivos de solo lectura cuando sea posible
docker run --read-only nginx
```

### Optimización del Rendimiento

Optimizar contenedores para velocidad y eficiencia de recursos.

```dockerfile
# Usar compilaciones multi-etapa para reducir el tamaño de la imagen
FROM node:16 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
FROM node:16-alpine
WORKDIR /app
COPY --from=builder /app/node_modules
./node_modules
COPY . .
CMD ["node", "server.js"]
```

## Enlaces Relevantes

- <router-link to="/kubernetes">Hoja de Trucos de Kubernetes</router-link>
- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/ansible">Hoja de Trucos de Ansible</router-link>
- <router-link to="/git">Hoja de Trucos de Git</router-link>
- <router-link to="/rhel">Hoja de Trucos de Red Hat Enterprise Linux</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>

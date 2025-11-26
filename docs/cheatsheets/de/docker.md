---
title: 'Docker Spickzettel'
description: 'Lernen Sie Docker mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/docker-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Docker Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/docker">Docker mit Hands-On Labs lernen</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Docker-Containerisierung durch praktische Labs und reale Szenarien. LabEx bietet umfassende Docker-Kurse, die wesentliches Container-Management, Image-Erstellung, Docker Compose, Networking, Volumes und Deployment abdecken. Meistern Sie Container-Orchestrierung und moderne Anwendungseinsatztechniken.
</base-disclaimer-content>
</base-disclaimer>

## Installation & Einrichtung

### Linux Installation

Docker auf Ubuntu/Debian-Systemen installieren.

```bash
# Paketmanager aktualisieren
sudo apt update
# Voraussetzungen installieren
sudo apt install apt-transport-https ca-certificates curl
software-properties-common
# GPG-Schlüssel von Docker hinzufügen
curl -fsSL https://download.docker.com/linux/ubuntu/gpg
| sudo apt-key add -
# Docker-Repository hinzufügen
sudo add-apt-repository "deb [arch=amd64]
https://download.docker.com/linux/ubuntu bionic stable"
# Docker installieren
sudo apt update && sudo apt install docker-ce
# Docker-Dienst starten
sudo systemctl start docker
sudo systemctl enable docker
```

### Windows & macOS

Docker Desktop für GUI-basiertes Management installieren.

```bash
# Windows: Docker Desktop von docker.com herunterladen
# macOS: Homebrew verwenden oder direkt von docker.com herunterladen
brew install --cask docker
# Oder direkt herunterladen von:
# https://www.docker.com/products/docker-desktop
```

### Post-Installation Einrichtung

Docker für die Nutzung ohne Root-Rechte konfigurieren und Installation überprüfen.

```bash
# Benutzer zur Docker-Gruppe hinzufügen (Linux)
sudo usermod -aG docker $USER
# Abmelden und erneut anmelden, damit Gruppenänderungen wirksam werden
# Docker-Installation überprüfen
docker --version
docker run hello-world
```

### Docker Compose Installation

Docker Compose für Multi-Container-Anwendungen installieren.

```bash
# Linux: Installation via curl
sudo curl -L
"https://github.com/docker/compose/releases/download
/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o
/usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
# Installation überprüfen
docker-compose --version
# Hinweis: Docker Desktop beinhaltet Compose
```

## Grundlegende Docker-Befehle

### Systeminformationen: `docker version` / `docker system info`

Docker-Installation und Umgebungsdetails prüfen.

```bash
# Docker Versionsinformationen anzeigen
docker version
# Systemweite Docker-Informationen anzeigen
docker system info
# Hilfe für Docker-Befehle anzeigen
docker help
docker <command> --help
```

### Container ausführen: `docker run`

Einen Container aus einem Image erstellen und starten.

```bash
# Container interaktiv ausführen
docker run -it ubuntu:latest bash
# Container im Hintergrund ausführen
(detached)
docker run -d --name my-container
nginx
# Mit Port-Mapping ausführen
docker run -p 8080:80 nginx
# Container mit automatischer Entfernung nach Beendigung ausführen
docker run --rm hello-world
```

### Container auflisten: `docker ps`

Laufende und gestoppte Container anzeigen.

```bash
# Laufende Container auflisten
docker ps
# Alle Container auflisten (einschließlich gestoppter)
docker ps -a
# Nur Container-IDs auflisten
docker ps -q
# Zuletzt erstellten Container anzeigen
docker ps -l
```

## Container-Management

### Container-Lebenszyklus: `start` / `stop` / `restart`

Zustand der Container-Ausführung steuern.

```bash
# Einen laufenden Container stoppen
docker stop container_name
# Einen gestoppten Container starten
docker start container_name
# Einen Container neu starten
docker restart container_name
# Container-Prozesse pausieren/fortsetzen
docker pause container_name
docker unpause container_name
```

### Befehle ausführen: `docker exec`

Befehle innerhalb laufender Container ausführen.

```bash
# Interaktive Bash-Shell ausführen
docker exec -it container_name bash
# Einen einzelnen Befehl ausführen
docker exec container_name ls -la
# Als anderer Benutzer ausführen
docker exec -u root container_name whoami
# In spezifischem Verzeichnis ausführen
docker exec -w /app container_name pwd
```

### Container entfernen: `docker rm`

Container vom System entfernen.

```bash
# Einen gestoppten Container entfernen
docker rm container_name
# Einen laufenden Container zwangsweise entfernen
docker rm -f container_name
# Mehrere Container entfernen
docker rm container1 container2
# Alle gestoppten Container entfernen
docker container prune
```

### Container-Logs: `docker logs`

Container-Ausgaben anzeigen und Probleme debuggen.

```bash
# Container-Logs anzeigen
docker logs container_name
# Logs in Echtzeit verfolgen
docker logs -f container_name
# Nur die letzten Logs anzeigen
docker logs --tail 50 container_name
# Logs mit Zeitstempeln anzeigen
docker logs -t container_name
```

## Image-Management

### Images bauen: `docker build`

Docker Images aus Dockerfiles erstellen.

```bash
# Image aus dem aktuellen Verzeichnis bauen
docker build .
# Image bauen und taggen
docker build -t myapp:latest .
# Mit Build-Argumenten bauen
docker build --build-arg VERSION=1.0 -t myapp .
# Ohne Cache bauen
docker build --no-cache -t myapp .
```

### Image-Inspektion: `docker images` / `docker inspect`

Docker Images auflisten und untersuchen.

```bash
# Alle lokalen Images auflisten
docker images
# Images mit spezifischen Filtern auflisten
docker images nginx
# Image-Details anzeigen
docker inspect image_name
# Image-Build-Historie anzeigen
docker history image_name
```

### Registry-Operationen: `docker pull` / `docker push`

Images von Registries herunterladen und hochladen.

```bash
# Image von Docker Hub ziehen
docker pull nginx:latest
# Spezifische Version ziehen
docker pull ubuntu:20.04
# Image in Registry pushen
docker push myusername/myapp:latest
# Image vor dem Pushen taggen
docker tag myapp:latest myusername/myapp:v1.0
```

### Image-Bereinigung: `docker rmi` / `docker image prune`

Unbenutzte Images entfernen, um Speicherplatz freizugeben.

```bash
# Ein spezifisches Image entfernen
docker rmi image_name
# Unbenutzte Images entfernen
docker image prune
# Alle unbenutzten Images entfernen (nicht nur Dangling)
docker image prune -a
# Image zwangsweise entfernen
docker rmi -f image_name
```

## Dockerfile Grundlagen

### Wesentliche Anweisungen

Kernbefehle der Dockerfile zur Image-Erstellung.

```dockerfile
# Basis-Image
FROM ubuntu:20.04
# Wartungsinformationen festlegen
LABEL maintainer="user@example.com"
# Pakete installieren
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# Dateien vom Host in den Container kopieren
COPY app.py /app/
# Arbeitsverzeichnis festlegen
WORKDIR /app
# Port freigeben
EXPOSE 8000
```

### Laufzeitkonfiguration

Konfigurieren, wie der Container ausgeführt wird.

```dockerfile
# Umgebungsvariablen setzen
ENV PYTHON_ENV=production
ENV PORT=8000
# Benutzer für Sicherheit erstellen
RUN useradd -m appuser
USER appuser
# Startbefehl definieren
CMD ["python3", "app.py"]
# Oder ENTRYPOINT für feste Befehle verwenden
ENTRYPOINT ["python3"]
CMD ["app.py"]
# Health Check setzen
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/ || exit 1
```

## Docker Compose

### Grundlegende Compose-Befehle: `docker-compose up` / `docker-compose down`

Multi-Container-Anwendungen starten und stoppen.

```bash
# Dienste im Vordergrund starten
docker-compose up
# Dienste im Hintergrund starten
docker-compose up -d
# Dienste bauen und starten
docker-compose up --build
# Dienste stoppen und entfernen
docker-compose down
# Stoppen und mit Volumes entfernen
docker-compose down -v
```

### Dienstverwaltung

Einzelne Dienste innerhalb von Compose-Anwendungen steuern.

```bash
# Laufende Dienste auflisten
docker-compose ps
# Dienst-Logs anzeigen
docker-compose logs service_name
# Logs für alle Dienste verfolgen
docker-compose logs -f
# Einen spezifischen Dienst neu starten
docker-compose restart service_name
```

### Beispiel docker-compose.yml

Konfiguration einer Beispiel-Multi-Service-Anwendung.

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

## Networking & Volumes

### Container-Netzwerke

Container verbinden und Dienste freigeben.

```bash
# Netzwerke auflisten
docker network ls
# Ein benutzerdefiniertes Netzwerk erstellen
docker network create mynetwork
# Container in spezifischem Netzwerk ausführen
docker run --network mynetwork nginx
# Laufenden Container mit Netzwerk verbinden
docker network connect mynetwork container_name
# Netzwerkdetails inspizieren
docker network inspect mynetwork
```

### Port-Mapping

Container-Ports für das Host-System freigeben.

```bash
# Einzelnen Port mappen
docker run -p 8080:80 nginx
# Mehrere Ports mappen
docker run -p 8080:80 -p 8443:443 nginx
# Auf spezifische Host-Schnittstelle mappen
docker run -p 127.0.0.1:8080:80 nginx
# Alle in Image definierten Ports freigeben
docker run -P nginx
```

### Daten-Volumes: `docker volume`

Daten zwischen Containern persistent speichern und teilen.

```bash
# Ein benanntes Volume erstellen
docker volume create myvolume
# Alle Volumes auflisten
docker volume ls
# Volume-Details inspizieren
docker volume inspect myvolume
# Volume entfernen
docker volume rm myvolume
# Unbenutzte Volumes entfernen
docker volume prune
```

### Volume-Mounting

Volumes und Host-Verzeichnisse in Container einbinden.

```bash
# Benanntes Volume mounten
docker run -v myvolume:/data nginx
# Host-Verzeichnis mounten (Bind Mount)
docker run -v /host/path:/container/path nginx
# Aktuelles Verzeichnis mounten
docker run -v $(pwd):/app nginx
# Nur Lesezugriff auf Mount
docker run -v /host/path:/container/path:ro nginx
```

## Container-Inspektion & Debugging

### Container-Details: `docker inspect`

Detaillierte Informationen über Container und Images abrufen.

```bash
# Container-Konfiguration inspizieren
docker inspect container_name
# Spezifische Informationen mit Format abrufen
docker inspect --format='{{.State.Status}}'
container_name
# IP-Adresse abrufen
docker inspect --format='{{.NetworkSettings.IPAddress}}'
container_name
# Gemountete Volumes abrufen
docker inspect --format='{{.Mounts}}' container_name
```

### Ressourcen-Überwachung

Ressourcennutzung und Leistung von Containern überwachen.

```bash
# Laufende Prozesse im Container anzeigen
docker top container_name
# Live-Ressourcennutzungsstatistiken anzeigen
docker stats
# Statistiken für spezifischen Container anzeigen
docker stats container_name
# Ereignisse in Echtzeit überwachen
docker events
```

### Dateioperationen: `docker cp`

Dateien zwischen Containern und dem Host-System kopieren.

```bash
# Datei vom Container zum Host kopieren
docker cp container_name:/path/to/file ./
# Datei vom Host in den Container kopieren
docker cp ./file container_name:/path/to/destination
# Verzeichnis kopieren
docker cp ./directory
container_name:/path/to/destination/
# Kopieren mit Archivmodus, um Berechtigungen zu erhalten
docker cp -a ./directory container_name:/path/
```

### Fehlerbehebung

Container-Probleme und Verbindungsprobleme debuggen.

```bash
# Exit-Code des Containers prüfen
docker inspect --format='{{.State.ExitCode}}'
container_name
# Container-Prozesse anzeigen
docker exec container_name ps aux
# Netzwerkkonnektivität testen
docker exec container_name ping google.com
# Festplattennutzung prüfen
docker exec container_name df -h
```

## Registry & Authentifizierung

### Docker Hub Operationen: `docker login` / `docker search`

Authentifizieren und mit Docker Hub interagieren.

```bash
# Bei Docker Hub anmelden
docker login
# Bei spezifischer Registry anmelden
docker login registry.example.com
# Nach Images auf Docker Hub suchen
docker search nginx
# Suche mit Filter
docker search --filter stars=100 nginx
```

### Image-Tagging & Veröffentlichung

Images für Registries vorbereiten und veröffentlichen.

```bash
# Image für Registry taggen
docker tag myapp:latest username/myapp:v1.0
docker tag myapp:latest
registry.example.com/myapp:latest
# Auf Docker Hub pushen
docker push username/myapp:v1.0
# Auf private Registry pushen
docker push registry.example.com/myapp:latest
```

### Private Registry

Mit privaten Docker Registries arbeiten.

```bash
# Von privater Registry ziehen
docker pull registry.company.com/myapp:latest
# Lokale Registry starten
docker run -d -p 5000:5000 --name registry registry:2
# Auf lokale Registry pushen
docker tag myapp localhost:5000/myapp
docker push localhost:5000/myapp
```

### Image-Sicherheit

Image-Integrität und Sicherheit überprüfen.

```bash
# Docker Content Trust aktivieren
export DOCKER_CONTENT_TRUST=1
# Image signieren und pushen
docker push username/myapp:signed
# Image-Signaturen überprüfen
docker trust inspect username/myapp:signed
# Images auf Schwachstellen scannen
docker scan myapp:latest
```

## Systembereinigung & Wartung

### Systembereinigung: `docker system prune`

Unbenutzte Docker-Ressourcen entfernen, um Speicherplatz freizugeben.

```bash
# Unbenutzte Container, Netzwerke, Images entfernen
docker system prune
# Unbenutzte Volumes in die Bereinigung einbeziehen
docker system prune -a --volumes
# Alles entfernen (mit Vorsicht verwenden)
docker system prune -a -f
# Speicherplatznutzung anzeigen
docker system df
```

### Gezielte Bereinigung

Spezifische Arten ungenutzter Ressourcen entfernen.

```bash
# Gestoppte Container entfernen
docker container prune
# Unbenutzte Images entfernen
docker image prune -a
# Unbenutzte Volumes entfernen
docker volume prune
# Unbenutzte Netzwerke entfernen
docker network prune
```

### Massenoperationen

Operationen für mehrere Container/Images durchführen.

```bash
# Alle laufenden Container stoppen
docker stop $(docker ps -q)
# Alle Container entfernen
docker rm $(docker ps -aq)
# Alle Images entfernen
docker rmi $(docker images -q)
# Nur Dangling Images entfernen
docker rmi $(docker images -f "dangling=true" -q)
```

### Ressourcenlimits

Die Ressourcenverbrauchssteuerung von Containern festlegen.

```bash
# Speichernutzung begrenzen
docker run --memory=512m nginx
# CPU-Nutzung begrenzen
docker run --cpus="1.5" nginx
# Beide begrenzen (CPU und Speicher)
docker run --memory=1g --cpus="2.0" nginx
# Neustartrichtlinie festlegen
docker run --restart=always nginx
```

## Docker Konfiguration & Einstellungen

### Daemon-Konfiguration

Den Docker-Daemon für den Produktionseinsatz konfigurieren.

```bash
# Daemon-Konfiguration bearbeiten
sudo nano
/etc/docker/daemon.json
# Beispielkonfiguration:
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
# Docker-Dienst neu starten
sudo systemctl restart docker
```

### Umgebungsvariablen

Das Verhalten des Docker-Clients über Umgebungsvariablen konfigurieren.

```bash
# Docker-Host festlegen
export
DOCKER_HOST=tcp://remote-
docker:2376
# TLS-Verifizierung aktivieren
export DOCKER_TLS_VERIFY=1
export
DOCKER_CERT_PATH=/path/to/c
erts
# Standard-Registry festlegen
export
DOCKER_REGISTRY=registry.co
mpany.com
# Debug-Ausgabe
export DOCKER_BUILDKIT=1
```

### Performance-Tuning

Docker für bessere Leistung optimieren.

```bash
# Experimentelle Funktionen aktivieren
echo '{"experimental": true}' |
sudo tee
/etc/docker/daemon.json
# Speicher-Treiber-Optionen festlegen
{
  "storage-driver": "overlay2",
  "storage-opts": [

"overlay2.override_kernel_check
=true"
  ]
}
# Protokollierung konfigurieren
{
  "log-driver": "syslog",
  "log-opts": {"syslog-address":
"udp://logs.company.com:514"}
}
```

## Best Practices

### Sicherheits-Best Practices

Container sicher und produktionsreif halten.

```dockerfile
# Als Nicht-Root-Benutzer in Dockerfile ausführen
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# Spezifische Image-Tags verwenden, nicht 'latest'
FROM node:16.20.0-alpine
# Dateisysteme, wenn möglich, nur lesbar verwenden
docker run --read-only nginx
```

### Performance-Optimierung

Container für Geschwindigkeit und Ressourceneffizienz optimieren.

```dockerfile
# Multi-Stage Builds verwenden, um die Image-Größe zu reduzieren
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

## Relevante Links

- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>
- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/ansible">Ansible Spickzettel</router-link>
- <router-link to="/git">Git Spickzettel</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>

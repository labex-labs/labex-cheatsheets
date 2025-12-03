---
title: 'Cheat Sheet Docker | LabEx'
description: "Apprenez la conteneurisation Docker avec ce mémo complet. Référence rapide pour les commandes Docker, les images, les conteneurs, le Dockerfile, Docker Compose et l'orchestration de conteneurs."
pdfUrl: '/cheatsheets/pdf/docker-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Docker
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/docker">Apprenez Docker avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez la conteneurisation Docker grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours Docker complets couvrant la gestion essentielle des conteneurs, la construction d'images, Docker Compose, le réseau, les volumes et le déploiement. Maîtrisez l'orchestration de conteneurs et les techniques de déploiement d'applications modernes.
</base-disclaimer-content>
</base-disclaimer>

## Installation et Configuration

### Installation sous Linux

Installer Docker sur les systèmes Ubuntu/Debian.

```bash
# Mettre à jour le gestionnaire de paquets
sudo apt update
# Installer les prérequis
sudo apt install apt-transport-https ca-certificates curl
software-properties-common
# Ajouter la clé GPG officielle de Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg
| sudo apt-key add -
# Ajouter le dépôt Docker
sudo add-apt-repository "deb [arch=amd64]
https://download.docker.com/linux/ubuntu bionic stable"
# Installer Docker
sudo apt update && sudo apt install docker-ce
# Démarrer le service Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### Windows et macOS

Installer Docker Desktop pour une gestion basée sur une interface graphique.

```bash
# Windows : Télécharger Docker Desktop depuis docker.com
# macOS : Utiliser Homebrew ou télécharger depuis docker.com
brew install --cask docker
# Ou télécharger directement depuis :
# https://www.docker.com/products/docker-desktop
```

### Configuration Post-Installation

Configurer Docker pour une utilisation sans privilèges root et vérifier l'installation.

```bash
# Ajouter l'utilisateur au groupe docker (Linux)
sudo usermod -aG docker $USER
# Se déconnecter et se reconnecter pour que les changements de groupe prennent effet
# Vérifier l'installation de Docker
docker --version
docker run hello-world
```

### Installation de Docker Compose

Installer Docker Compose pour les applications multi-conteneurs.

```bash
# Linux : Installer via curl
sudo curl -L
"https://github.com/docker/compose/releases/download
/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o
/usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
# Vérifier l'installation
docker-compose --version
# Note : Docker Desktop inclut Compose
```

## Commandes Docker de Base

### Informations Système : `docker version` / `docker system info`

Vérifier les détails de l'installation et de l'environnement Docker.

```bash
# Afficher les informations de version de Docker
docker version
# Afficher les informations système Docker
information
docker system info
# Afficher l'aide pour les commandes Docker
docker help
docker <commande> --help
```

### Exécution de Conteneurs : `docker run`

Créer et démarrer un conteneur à partir d'une image.

```bash
# Exécuter un conteneur de manière interactive
docker run -it ubuntu:latest bash
# Exécuter le conteneur en arrière-plan
(detached)
docker run -d --name my-container
nginx
# Exécuter avec mappage de port
docker run -p 8080:80 nginx
# Exécuter avec suppression automatique après l'arrêt
docker run --rm hello-world
```

<BaseQuiz id="docker-run-1" correct="C">
  <template #question>
    Que fait <code>docker run -d</code> ?
  </template>
  
  <BaseQuizOption value="A">Exécute le conteneur en mode débogage</BaseQuizOption>
  <BaseQuizOption value="B">Supprime le conteneur après son arrêt</BaseQuizOption>
  <BaseQuizOption value="C" correct>Exécute le conteneur en mode détaché (arrière-plan)</BaseQuizOption>
  <BaseQuizOption value="D">Exécute le conteneur avec les paramètres par défaut</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le drapeau <code>-d</code> exécute le conteneur en mode détaché, ce qui signifie qu'il s'exécute en arrière-plan et rend immédiatement le contrôle au terminal. Ceci est utile pour les services de longue durée.
  </BaseQuizAnswer>
</BaseQuiz>

### Lister les Conteneurs : `docker ps`

Afficher les conteneurs en cours d'exécution et arrêtés.

```bash
# Lister les conteneurs en cours d'exécution
docker ps
# Lister tous les conteneurs (y compris les
arrêtés)
docker ps -a
# Lister uniquement les IDs des conteneurs
docker ps -q
# Afficher le conteneur créé le plus récemment
docker ps -l
```

## Gestion des Conteneurs

### Cycle de Vie du Conteneur : `start` / `stop` / `restart`

Contrôler l'état d'exécution du conteneur.

```bash
# Arrêter un conteneur en cours d'exécution
docker stop nom_conteneur
# Démarrer un conteneur arrêté
docker start nom_conteneur
# Redémarrer un conteneur
docker restart nom_conteneur
# Mettre en pause/reprendre les processus du conteneur
docker pause nom_conteneur
docker unpause nom_conteneur
```

### Exécuter des Commandes : `docker exec`

Exécuter des commandes à l'intérieur de conteneurs en cours d'exécution.

```bash
# Exécuter un shell bash interactif
docker exec -it nom_conteneur bash
# Exécuter une seule commande
docker exec nom_conteneur ls -la
# Exécuter en tant qu'utilisateur différent
docker exec -u root nom_conteneur whoami
# Exécuter dans un répertoire spécifique
docker exec -w /app nom_conteneur pwd
```

### Suppression de Conteneurs : `docker rm`

Supprimer des conteneurs du système.

```bash
# Supprimer un conteneur arrêté
docker rm nom_conteneur
# Supprimer de force un conteneur en cours d'exécution
docker rm -f nom_conteneur
# Supprimer plusieurs conteneurs
docker rm conteneur1 conteneur2
# Supprimer tous les conteneurs arrêtés
docker container prune
```

### Journaux des Conteneurs : `docker logs`

Afficher la sortie du conteneur et déboguer les problèmes.

```bash
# Voir les journaux du conteneur
docker logs nom_conteneur
# Suivre les journaux en temps réel
docker logs -f nom_conteneur
# Afficher uniquement les journaux récents
docker logs --tail 50 nom_conteneur
# Afficher les journaux avec horodatages
docker logs -t nom_conteneur
```

## Gestion des Images

### Construction d'Images : `docker build`

Créer des images Docker à partir de Dockerfiles.

```bash
# Construire l'image depuis le répertoire courant
docker build .
# Construire et étiqueter une image
docker build -t monapp:latest .
# Construire avec des arguments de construction
docker build --build-arg VERSION=1.0 -t monapp .
# Construire sans utiliser le cache
docker build --no-cache -t monapp .
```

<BaseQuiz id="docker-build-1" correct="A">
  <template #question>
    Que fait <code>docker build -t monapp:latest .</code> ?
  </template>
  
  <BaseQuizOption value="A" correct>Construit une image Docker avec l'étiquette "monapp:latest" à partir du répertoire courant</BaseQuizOption>
  <BaseQuizOption value="B">Exécute un conteneur nommé "monapp"</BaseQuizOption>
  <BaseQuizOption value="C">Tire l'image "monapp:latest" depuis Docker Hub</BaseQuizOption>
  <BaseQuizOption value="D">Supprime l'image "monapp:latest"</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le drapeau <code>-t</code> étiquette l'image avec le nom "monapp:latest", et le <code>.</code> spécifie le contexte de construction (répertoire courant). Cette commande construit une nouvelle image à partir d'un Dockerfile dans le répertoire courant.
  </BaseQuizAnswer>
</BaseQuiz>

### Inspection d'Image : `docker images` / `docker inspect`

Lister et examiner les images Docker.

```bash
# Lister toutes les images locales
docker images
# Lister les images avec des filtres spécifiques
docker images nginx
# Afficher les détails de l'image
docker inspect nom_image
# Voir l'historique de construction de l'image
docker history nom_image
```

### Opérations de Registre : `docker pull` / `docker push`

Télécharger et téléverser des images vers des registres.

```bash
# Tirer l'image depuis Docker Hub
docker pull nginx:latest
# Tirer une version spécifique
docker pull ubuntu:20.04
# Pousser l'image vers un registre
docker push monutilisateur/monapp:latest
# Étiqueter l'image avant de pousser
docker tag monapp:latest monutilisateur/monapp:v1.0
```

### Nettoyage d'Image : `docker rmi` / `docker image prune`

Supprimer les images inutilisées pour libérer de l'espace disque.

```bash
# Supprimer une image spécifique
docker rmi nom_image
# Supprimer les images inutilisées
docker image prune
# Supprimer toutes les images inutilisées (pas seulement les pendantes)
docker image prune -a
# Supprimer de force l'image
docker rmi -f nom_image
```

## Bases du Dockerfile

### Instructions Essentielles

Commandes Dockerfile fondamentales pour la construction d'images.

```dockerfile
# Image de base
FROM ubuntu:20.04
# Définir les informations du mainteneur
LABEL maintainer="user@example.com"
# Installer des paquets
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# Copier des fichiers de l'hôte vers le conteneur
COPY app.py /app/
# Définir le répertoire de travail
WORKDIR /app
# Exposer le port
EXPOSE 8000
```

<BaseQuiz id="dockerfile-1" correct="B">
  <template #question>
    Quel est le but de l'instruction <code>FROM</code> dans un Dockerfile ?
  </template>
  
  <BaseQuizOption value="A">Elle copie des fichiers de l'hôte vers le conteneur</BaseQuizOption>
  <BaseQuizOption value="B" correct>Elle spécifie l'image de base sur laquelle construire</BaseQuizOption>
  <BaseQuizOption value="C">Elle définit des variables d'environnement</BaseQuizOption>
  <BaseQuizOption value="D">Elle définit la commande à exécuter lorsque le conteneur démarre</BaseQuizOption>
  
  <BaseQuizAnswer>
    L'instruction <code>FROM</code> doit être la première instruction non commentée dans un Dockerfile. Elle spécifie l'image de base sur laquelle votre image sera construite, fournissant la fondation pour votre conteneur.
  </BaseQuizAnswer>
</BaseQuiz>

### Configuration d'Exécution

Configurer la manière dont le conteneur s'exécute.

```dockerfile
# Définir les variables d'environnement
ENV PYTHON_ENV=production
ENV PORT=8000
# Créer un utilisateur pour la sécurité
RUN useradd -m appuser
USER appuser
# Définir la commande de démarrage
CMD ["python3", "app.py"]
# Ou utiliser ENTRYPOINT pour des commandes fixes
ENTRYPOINT ["python3"]
CMD ["app.py"]
# Définir la vérification de santé
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/ || exit 1
```

## Docker Compose

### Commandes Compose de Base : `docker-compose up` / `docker-compose down`

Démarrer et arrêter des applications multi-conteneurs.

```bash
# Démarrer les services au premier plan
docker-compose up
# Démarrer les services en arrière-plan
docker-compose up -d
# Construire et démarrer les services
docker-compose up --build
# Arrêter et supprimer les services
docker-compose down
# Arrêter et supprimer avec les volumes
docker-compose down -v
```

<BaseQuiz id="docker-compose-1" correct="D">
  <template #question>
    Que fait <code>docker-compose up -d</code> ?
  </template>
  
  <BaseQuizOption value="A">Arrête tous les conteneurs en cours d'exécution</BaseQuizOption>
  <BaseQuizOption value="B">Construit les images sans démarrer les conteneurs</BaseQuizOption>
  <BaseQuizOption value="C">Affiche les journaux de tous les services</BaseQuizOption>
  <BaseQuizOption value="D" correct>Démarre tous les services définis dans docker-compose.yml en mode détaché</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le drapeau <code>-d</code> exécute les conteneurs en mode détaché (arrière-plan). <code>docker-compose up</code> lit le fichier docker-compose.yml et démarre tous les services définis, ce qui facilite la gestion des applications multi-conteneurs.
  </BaseQuizAnswer>
</BaseQuiz>

### Gestion des Services

Contrôler les services individuels dans les applications Compose.

```bash
# Lister les services en cours d'exécution
docker-compose ps
# Voir les journaux d'un service
docker-compose logs nom_service
# Suivre les journaux pour tous les services
docker-compose logs -f
# Redémarrer un service spécifique
docker-compose restart nom_service
```

### Exemple docker-compose.yml

Configuration d'exemple pour une application multi-services.

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

## Réseau et Volumes

### Réseau de Conteneurs

Connecter des conteneurs et exposer des services.

```bash
# Lister les réseaux
docker network ls
# Créer un réseau personnalisé
docker network create monreseau
# Exécuter un conteneur sur un réseau spécifique
docker run --network monreseau nginx
# Connecter un conteneur en cours d'exécution au réseau
docker network connect monreseau nom_conteneur
# Inspecter les détails du réseau
docker network inspect monreseau
```

### Mappage de Ports

Exposer les ports des conteneurs au système hôte.

```bash
# Mapper un seul port
docker run -p 8080:80 nginx
```

<BaseQuiz id="docker-port-1" correct="A">
  <template #question>
    Dans <code>docker run -p 8080:80 nginx</code>, que signifient les numéros de port ?
  </template>
  
  <BaseQuizOption value="A" correct>8080 est le port hôte, 80 est le port conteneur</BaseQuizOption>
  <BaseQuizOption value="B">80 est le port hôte, 8080 est le port conteneur</BaseQuizOption>
  <BaseQuizOption value="C">Les deux ports sont des ports conteneur</BaseQuizOption>
  <BaseQuizOption value="D">Les deux ports sont des ports hôte</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le format est <code>-p port_hote:port_conteneur</code>. Le port 8080 sur votre machine hôte est mappé au port 80 à l'intérieur du conteneur, vous permettant d'accéder au serveur web nginx s'exécutant dans le conteneur via localhost:8080.
  </BaseQuizAnswer>
</BaseQuiz>

```bash
# Mapper plusieurs ports
docker run -p 8080:80 -p 8443:443 nginx
# Mapper à une interface hôte spécifique
docker run -p 127.0.0.1:8080:80 nginx
# Exposer tous les ports définis dans l'image
docker run -P nginx
```

### Volumes de Données : `docker volume`

Persister et partager des données entre conteneurs.

```bash
# Créer un volume nommé
docker volume create monvolume
# Lister tous les volumes
docker volume ls
# Inspecter les détails du volume
docker volume inspect monvolume
# Supprimer un volume
docker volume rm monvolume
# Supprimer les volumes inutilisés
docker volume prune
```

### Montage de Volumes

Monter des volumes et des répertoires hôtes dans les conteneurs.

```bash
# Monter un volume nommé
docker run -v monvolume:/data nginx
# Monter un répertoire hôte (bind mount)
docker run -v /chemin/hote:/chemin/conteneur nginx
# Monter le répertoire courant
docker run -v $(pwd):/app nginx
# Montage en lecture seule
docker run -v /chemin/hote:/chemin/conteneur:ro nginx
```

## Inspection et Débogage de Conteneurs

### Détails du Conteneur : `docker inspect`

Obtenir des informations détaillées sur les conteneurs et les images.

```bash
# Inspecter la configuration du conteneur
docker inspect nom_conteneur
# Obtenir des informations spécifiques en utilisant le format
docker inspect --format='{{.State.Status}}'
nom_conteneur
# Obtenir l'adresse IP
docker inspect --format='{{.NetworkSettings.IPAddress}}'
nom_conteneur
# Obtenir les volumes montés
docker inspect --format='{{.Mounts}}' nom_conteneur
```

### Surveillance des Ressources

Surveiller l'utilisation des ressources et les performances des conteneurs.

```bash
# Afficher les processus en cours d'exécution dans le conteneur
docker top nom_conteneur
# Afficher les statistiques d'utilisation des ressources en direct
docker stats
# Afficher les statistiques pour un conteneur spécifique
docker stats nom_conteneur
# Surveiller les événements en temps réel
docker events
```

### Opérations de Fichiers : `docker cp`

Copier des fichiers entre les conteneurs et le système hôte.

```bash
# Copier un fichier du conteneur vers l'hôte
docker cp nom_conteneur:/chemin/vers/fichier ./
# Copier un fichier de l'hôte vers le conteneur
docker cp ./fichier nom_conteneur:/chemin/vers/destination
# Copier un répertoire
docker cp ./repertoire
nom_conteneur:/chemin/vers/destination/
# Copier avec le mode archive pour préserver les permissions
docker cp -a ./repertoire nom_conteneur:/chemin/
```

### Dépannage

Déboguer les problèmes de conteneur et de connectivité.

```bash
# Vérifier le code de sortie du conteneur
docker inspect --format='{{.State.ExitCode}}'
nom_conteneur
# Voir les processus du conteneur
docker exec nom_conteneur ps aux
# Tester la connectivité réseau
docker exec nom_conteneur ping google.com
# Vérifier l'utilisation du disque
docker exec nom_conteneur df -h
```

## Registre et Authentification

### Opérations Docker Hub : `docker login` / `docker search`

S'authentifier et interagir avec Docker Hub.

```bash
# Se connecter à Docker Hub
docker login
# Se connecter à un registre spécifique
docker login registry.example.com
# Rechercher des images sur Docker Hub
docker search nginx
# Rechercher avec un filtre
docker search --filter stars=100 nginx
```

### Étiquetage et Publication d'Images

Préparer et publier des images vers des registres.

```bash
# Étiqueter l'image pour le registre
docker tag monapp:latest nomutilisateur/monapp:v1.0
docker tag monapp:latest
registry.example.com/monapp:latest
# Pousser vers Docker Hub
docker push nomutilisateur/monapp:v1.0
# Pousser vers un registre privé
docker push registry.example.com/monapp:latest
```

### Registre Privé

Travailler avec des registres Docker privés.

```bash
# Tirer depuis un registre privé
docker pull registry.company.com/monapp:latest
# Exécuter un registre local
docker run -d -p 5000:5000 --name registry registry:2
# Pousser vers le registre local
docker tag monapp localhost:5000/monapp
docker push localhost:5000/monapp
```

### Sécurité des Images

Vérifier l'intégrité et la sécurité des images.

```bash
# Activer la confiance de contenu Docker
export DOCKER_CONTENT_TRUST=1
# Signer et pousser l'image
docker push nomutilisateur/monapp:signed
# Vérifier les signatures d'image
docker trust inspect nomutilisateur/monapp:signed
# Scanner les images pour les vulnérabilités
docker scan monapp:latest
```

## Nettoyage et Maintenance du Système

### Nettoyage du Système : `docker system prune`

Supprimer les ressources Docker inutilisées pour libérer de l'espace disque.

```bash
# Supprimer les conteneurs, réseaux, images inutilisés
docker system prune
# Inclure les volumes inutilisés dans le nettoyage
docker system prune -a --volumes
# Supprimer tout (à utiliser avec prudence)
docker system prune -a -f
# Afficher l'utilisation de l'espace
docker system df
```

### Nettoyage Ciblé

Supprimer des types spécifiques de ressources inutilisées.

```bash
# Supprimer les conteneurs arrêtés
docker container prune
# Supprimer les images inutilisées
docker image prune -a
# Supprimer les volumes inutilisés
docker volume prune
# Supprimer les réseaux inutilisés
docker network prune
```

### Opérations en Masse

Effectuer des opérations sur plusieurs conteneurs/images.

```bash
# Arrêter tous les conteneurs en cours d'exécution
docker stop $(docker ps -q)
# Supprimer tous les conteneurs
docker rm $(docker ps -aq)
# Supprimer toutes les images
docker rmi $(docker images -q)
# Supprimer uniquement les images pendantes
docker rmi $(docker images -f "dangling=true" -q)
```

### Limites de Ressources

Contrôler la consommation de ressources des conteneurs.

```bash
# Limiter l'utilisation de la mémoire
docker run --memory=512m nginx
# Limiter l'utilisation du CPU
docker run --cpus="1.5" nginx
# Limiter le CPU et la mémoire
docker run --memory=1g --cpus="2.0" nginx
# Définir la politique de redémarrage
docker run --restart=always nginx
```

## Configuration et Paramètres Docker

### Configuration du Démon

Configurer le démon Docker pour une utilisation en production.

```bash
# Modifier la configuration du démon
sudo nano
/etc/docker/daemon.json
# Configuration exemple :
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
# Redémarrer le service Docker
sudo systemctl restart docker
```

### Variables d'Environnement

Configurer le comportement du client Docker avec des variables d'environnement.

```bash
# Définir l'hôte Docker
export
DOCKER_HOST=tcp://remote-
docker:2376
# Activer la vérification TLS
export DOCKER_TLS_VERIFY=1
export
DOCKER_CERT_PATH=/chemin/vers/cert
s
# Définir le registre par défaut
export
DOCKER_REGISTRY=registry.co
mpany.com
# Sortie de débogage
export DOCKER_BUILDKIT=1
```

### Optimisation des Performances

Optimiser Docker pour une meilleure performance.

```bash
# Activer les fonctionnalités expérimentales
echo '{"experimental": true}' |
sudo tee
/etc/docker/daemon.json
# Options du pilote de stockage
{
  "storage-driver": "overlay2",
  "storage-opts": [

"overlay2.override_kernel_check
=true"
  ]
}
# Configurer la journalisation
{
  "log-driver": "syslog",
  "log-opts": {"syslog-address":
"udp://logs.company.com:514"}
}
```

## Bonnes Pratiques

### Bonnes Pratiques de Sécurité

Gardez vos conteneurs sécurisés et prêts pour la production.

```dockerfile
# Exécuter en tant qu'utilisateur non-root dans le Dockerfile
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# Utiliser des étiquettes d'image spécifiques, pas 'latest'
FROM node:16.20.0-alpine
# Utiliser des systèmes de fichiers en lecture seule si possible
docker run --read-only nginx
```

### Optimisation des Performances

Optimiser les conteneurs pour la vitesse et l'efficacité des ressources.

```dockerfile
# Utiliser des constructions multi-étapes pour réduire la taille de l'image
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

## Liens Pertinents

- <router-link to="/kubernetes">Feuille de triche Kubernetes</router-link>
- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>
- <router-link to="/ansible">Feuille de triche Ansible</router-link>
- <router-link to="/git">Feuille de triche Git</router-link>
- <router-link to="/rhel">Feuille de triche Red Hat Enterprise Linux</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>

---
title: 'Mémento Jenkins'
description: 'Apprenez Jenkins avec notre mémento complet couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/jenkins-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Jenkins
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/jenkins">Apprenez Jenkins avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez l'automatisation CI/CD de Jenkins grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets sur Jenkins couvrant les opérations essentielles, la création de pipelines, la gestion des plugins, l'automatisation des builds et les techniques avancées. Maîtrisez Jenkins pour construire des pipelines d'intégration et de déploiement continus efficaces pour le développement logiciel moderne.
</base-disclaimer-content>
</base-disclaimer>

## Installation et Configuration

### Installation Linux

Installer Jenkins sur les systèmes Ubuntu/Debian.

```bash
# Mettre à jour le gestionnaire de paquets et installer Java
sudo apt update
sudo apt install fontconfig openjdk-21-jre
java -version
# Ajouter la clé GPG de Jenkins
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
# Ajouter le dépôt Jenkins
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
/etc/apt/sources.list.d/jenkins.list > /dev/null
# Installer Jenkins
sudo apt update && sudo apt install jenkins
# Démarrer le service Jenkins
sudo systemctl start jenkins
sudo systemctl enable jenkins
```

### Windows et macOS

Installer Jenkins à l'aide d'installateurs ou de gestionnaires de paquets.

```bash
# Windows : Télécharger l'installeur Jenkins depuis jenkins.io
# Ou utiliser Chocolatey
choco install jenkins
# macOS : Utiliser Homebrew
brew install jenkins-lts
# Ou télécharger directement depuis :
# https://www.jenkins.io/download/
# Démarrer le service Jenkins
brew services start jenkins-lts
```

### Configuration Post-Installation

Configuration initiale et déverrouillage de Jenkins.

```bash
# Obtenir le mot de passe administrateur initial
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# Ou pour les installations Docker
docker exec jenkins_container cat /var/jenkins_home/secrets/initialAdminPassword
# Accéder à l'interface web de Jenkins
# Naviguer vers http://localhost:8080
# Entrer le mot de passe administrateur initial
# Installer les plugins suggérés ou sélectionner des plugins personnalisés
```

### Configuration Initiale

Terminer l'assistant de configuration et créer l'utilisateur administrateur.

```bash
# Après avoir déverrouillé Jenkins :
# 1. Installer les plugins suggérés (recommandé)
# 2. Créer le premier utilisateur administrateur
# 3. Configurer l'URL de Jenkins
# 4. Commencer à utiliser Jenkins
# Vérifier que Jenkins fonctionne
sudo systemctl status jenkins
# Consulter les logs de Jenkins si nécessaire
sudo journalctl -u jenkins.service
```

## Opérations Jenkins de Base

### Accès à Jenkins : Interface Web et Configuration CLI

Accéder à Jenkins via le navigateur et configurer les outils CLI.

```bash
# Accéder à l'interface web de Jenkins
http://localhost:8080
# Télécharger le CLI de Jenkins
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
# Tester la connexion CLI
java -jar jenkins-cli.jar -s http://localhost:8080 help
# Lister les commandes disponibles
java -jar jenkins-cli.jar -s http://localhost:8080 help
```

### Création de Job : `create-job` / Interface Web

Créer de nouveaux jobs de build en utilisant la CLI ou l'interface web.

```bash
# Créer un job à partir d'une configuration XML
java -jar jenkins-cli.jar -auth user:token create-job mon-job < job-config.xml
# Créer un projet freestyle simple via l'interface web :
# 1. Cliquer sur "Nouveau Projet"
# 2. Entrer le nom du job
# 3. Sélectionner "Projet Freestyle"
# 4. Configurer les étapes de build
# 5. Sauvegarder la configuration
```

### Lister les Jobs : `list-jobs`

Visualiser tous les jobs configurés dans Jenkins.

```bash
# Lister tous les jobs
java -jar jenkins-cli.jar -auth user:token list-jobs
# Lister les jobs correspondant à un motif
java -jar jenkins-cli.jar -auth user:token list-jobs "*test*"
# Obtenir la configuration du job
java -jar jenkins-cli.jar -auth user:token get-job mon-job > job-config.xml
```

## Gestion des Jobs

### Builder les Jobs : `build`

Déclencher et gérer les builds de jobs.

```bash
# Builder un job
java -jar jenkins-cli.jar -auth user:token build mon-job
# Builder avec des paramètres
java -jar jenkins-cli.jar -auth user:token build mon-job -p PARAM=valeur
# Builder et attendre la complétion
java -jar jenkins-cli.jar -auth user:token build mon-job -s -v
# Builder et suivre la sortie de la console
java -jar jenkins-cli.jar -auth user:token build mon-job -f
```

### Contrôle des Jobs : `enable-job` / `disable-job`

Activer ou désactiver les jobs.

```bash
# Activer un job
java -jar jenkins-cli.jar -auth user:token enable-job mon-job
# Désactiver un job
java -jar jenkins-cli.jar -auth user:token disable-job mon-job
# Vérifier le statut du job dans l'interface web
# Naviguer vers le tableau de bord du job
# Rechercher le bouton "Désactiver/Activer"
```

### Suppression de Job : `delete-job`

Supprimer des jobs de Jenkins.

```bash
# Supprimer un job
java -jar jenkins-cli.jar -auth user:token delete-job mon-job
# Suppression en masse de jobs (avec prudence)
for job in job1 job2 job3; do
  java -jar jenkins-cli.jar -auth user:token delete-job $job
done
```

### Sortie de Console : `console`

Visualiser les logs de build et la sortie de la console.

```bash
# Voir la sortie de la console du dernier build
java -jar jenkins-cli.jar -auth user:token console mon-job
# Voir un numéro de build spécifique
java -jar jenkins-cli.jar -auth user:token console mon-job 15
# Suivre la sortie de la console en temps réel
java -jar jenkins-cli.jar -auth user:token console mon-job -f
```

## Gestion des Pipelines

### Création de Pipeline

Créer et configurer des pipelines Jenkins.

```groovy
// Jenkinsfile de base (Pipeline Déclaratif)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Construction de l'application...'
                sh 'make build'
            }
        }

        stage('Test') {
            steps {
                echo 'Exécution des tests...'
                sh 'make test'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Déploiement de l'application...'
                sh 'make deploy'
            }
        }
    }
}
```

### Syntaxe de Pipeline

Syntaxe et directives courantes des pipelines.

```groovy
// Syntaxe de Pipeline Scripté
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
// Exécution parallèle
stages {
    stage('Tests Parallèles') {
        parallel {
            stage('Tests Unitaires') {
                steps {
                    sh 'make unit-test'
                }
            }
            stage('Tests d\'Intégration') {
                steps {
                    sh 'make integration-test'
                }
            }
        }
    }
}
```

### Configuration de Pipeline

Configuration avancée et options des pipelines.

```groovy
// Pipeline avec actions post-build
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
            echo 'Ceci s\'exécute toujours'
        }
        success {
            echo 'Le build a réussi'
        }
        failure {
            echo 'Le build a échoué'
            emailext subject: 'Build Échoué',
                     body: 'Le build a échoué',
                     to: 'equipe@entreprise.com'
        }
    }
}
```

### Déclencheurs de Pipeline

Configurer les déclencheurs automatiques de pipeline.

```groovy
// Pipeline avec déclencheurs
pipeline {
    agent any

    triggers {
        // Interroger SCM toutes les 5 minutes
        pollSCM('H/5 * * * *')

        // Planification de type Cron
        cron('H 2 * * *')  // Quotidien à 2h du matin

        // Déclenchement par job amont
        upstream(upstreamProjects: 'job-amont',
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

## Gestion des Plugins

### Installation de Plugin : CLI

Installer des plugins via l'interface de ligne de commande.

```bash
# Installer un plugin via CLI (nécessite un redémarrage)
java -jar jenkins-cli.jar -auth user:token install-plugin git
# Installer plusieurs plugins
java -jar jenkins-cli.jar -auth user:token install-plugin \
  git maven-plugin docker-plugin
# Installer à partir d'un fichier .hpi
java -jar jenkins-cli.jar -auth user:token install-plugin \
  /chemin/vers/plugin.hpi
# Lister les plugins installés
java -jar jenkins-cli.jar -auth user:token list-plugins
# Installation de plugin via plugins.txt (pour Docker)
# Créer le fichier plugins.txt :
git:latest
maven-plugin:latest
docker-plugin:latest
pipeline-stage-view:latest
# Utiliser l'outil jenkins-plugin-cli
jenkins-plugin-cli --plugins git maven-plugin docker-plugin
```

### Plugins Essentiels

Plugins couramment utilisés pour différentes tâches.

```bash
# Plugins de Build et SCM
git                    # Intégration Git
github                 # Intégration GitHub
maven-plugin          # Support de build Maven
gradle                # Support de build Gradle
# Plugins de Pipeline
workflow-aggregator   # Suite de plugins Pipeline
pipeline-stage-view   # Vue des étapes de pipeline
blue-ocean           # UI moderne pour les pipelines
# Déploiement et Intégration
docker-plugin        # Intégration Docker
kubernetes           # Déploiement Kubernetes
ansible              # Automatisation Ansible
# Qualité et Tests
junit                # Rapports de tests JUnit
jacoco              # Couverture de code
sonarqube           # Analyse de qualité de code
```

### Interface Web de Gestion des Plugins

Gérer les plugins via l'interface web de Jenkins.

```bash
# Accéder au Gestionnaire de Plugins :
# 1. Naviguer vers Gérer Jenkins
# 2. Cliquer sur "Gérer les Plugins"
# 3. Utiliser les onglets Disponible/Installé/Mises à jour
# 4. Rechercher des plugins
# 5. Sélectionner et installer
# 6. Redémarrer Jenkins si nécessaire
# Processus de mise à jour des plugins :
# 1. Vérifier l'onglet "Mises à jour"
# 2. Sélectionner les plugins à mettre à jour
# 3. Cliquer sur "Télécharger maintenant et installer après redémarrage"
```

## Gestion des Utilisateurs et Sécurité

### Gestion des Utilisateurs

Créer et gérer les utilisateurs Jenkins.

```bash
# Activer la sécurité Jenkins :
# 1. Gérer Jenkins → Configurer la Sécurité Globale
# 2. Activer la "Base de données des utilisateurs de Jenkins"
# 3. Autoriser l'inscription (configuration initiale)
# 4. Définir la stratégie d'autorisation
# Créer un utilisateur via CLI (nécessite des permissions appropriées)
# Les utilisateurs sont généralement créés via l'interface web :
# 1. Gérer Jenkins → Gérer les Utilisateurs
# 2. Cliquer sur "Créer un Utilisateur"
# 3. Remplir les détails de l'utilisateur
# 4. Assigner des rôles/permissions
```

### Authentification et Autorisation

Configurer les domaines de sécurité et les stratégies d'autorisation.

```bash
# Options de configuration de sécurité :
# 1. Domaine de Sécurité (comment les utilisateurs s'authentifient) :
#    - Base de données des utilisateurs de Jenkins
#    - LDAP
#    - Active Directory
#    - Sécurité basée sur une matrice
#    - Autorisation basée sur les rôles
# 2. Stratégie d'Autorisation :
#    - Tout le monde peut tout faire
#    - Mode hérité
#    - Les utilisateurs connectés peuvent tout faire
#    - Sécurité basée sur une matrice
#    - Autorisation basée sur une matrice par projet
```

### Jetons API

Générer et gérer les jetons API pour l'accès CLI.

```bash
# Générer un jeton API :
# 1. Cliquer sur le nom d'utilisateur → Configurer
# 2. Section Jeton API
# 3. Cliquer sur "Ajouter un nouveau Jeton"
# 4. Entrer le nom du jeton
# 5. Générer et copier le jeton
# Utiliser le jeton API avec la CLI
java -jar jenkins-cli.jar -auth nom_utilisateur:jeton-api \
  -s http://localhost:8080 list-jobs
# Stocker les identifiants en toute sécurité
echo "nom_utilisateur:jeton-api" > ~/.jenkins-cli-auth
chmod 600 ~/.jenkins-cli-auth
```

### Gestion des Identifiants

Gérer les identifiants stockés pour les jobs et les pipelines.

```bash
# Gérer les identifiants via CLI
java -jar jenkins-cli.jar -auth user:token \
  list-credentials system::system::jenkins
# Créer des identifiants XML et importer
java -jar jenkins-cli.jar -auth user:token \
  create-credentials-by-xml system::system::jenkins \
  < identifiant.xml
```

```groovy
// Accéder aux identifiants dans les pipelines
withCredentials([usernamePassword(
  credentialsId: 'mes-identifiants',
  usernameVariable: 'NOMUTILISATEUR',
  passwordVariable: 'MOTDEPASSE'
)]) {
  sh 'docker login -u $NOMUTILISATEUR -p $MOTDEPASSE'
}
```

## Surveillance et Dépannage des Builds

### Statut et Logs des Builds

Surveiller le statut des builds et accéder aux logs détaillés.

```bash
# Vérifier le statut du build
java -jar jenkins-cli.jar -auth user:token console mon-job
# Obtenir les informations du job
java -jar jenkins-cli.jar -auth user:token get-job mon-job
# Surveiller la file d'attente des builds
# Interface Web : Tableau de bord Jenkins → File d'attente des Builds
# Affiche les builds en attente et leur statut
# Accès à l'historique des builds
# Interface Web : Job → Historique des Builds
# Affiche tous les builds précédents avec leur statut
```

### Informations Système

Obtenir des informations système et de diagnostic Jenkins.

```bash
# Informations système
java -jar jenkins-cli.jar -auth user:token version
# Informations sur les nœuds
java -jar jenkins-cli.jar -auth user:token list-computers
# Console Groovy (admin uniquement)
# Gérer Jenkins → Console de Script
# Exécuter des scripts Groovy pour obtenir des informations système :
println Jenkins.instance.version
println Jenkins.instance.getRootDir()
println System.getProperty("java.version")
```

### Analyse des Logs

Accéder et analyser les logs système de Jenkins.

```bash
# Emplacement des logs système
# Linux : /var/log/jenkins/jenkins.log
# Windows : C:\Program Files\Jenkins\jenkins.out.log
# Voir les logs
tail -f /var/log/jenkins/jenkins.log
# Configuration des niveaux de log
# Gérer Jenkins → Log Système
# Ajouter un nouvel enregistreur de log pour des composants spécifiques
# Emplacements de logs courants :
sudo journalctl -u jenkins.service     # Logs Systemd
sudo cat /var/lib/jenkins/jenkins.log  # Fichier log Jenkins
```

### Surveillance des Performances

Surveiller les performances et l'utilisation des ressources de Jenkins.

```bash
# Surveillance intégrée
# Gérer Jenkins → Statistiques de Charge
# Affiche l'utilisation des exécuteurs au fil du temps
# Surveillance JVM
# Gérer Jenkins → Gérer les Nœuds → Maître
# Affiche l'utilisation de la mémoire, du CPU et les propriétés système
# Tendances des builds
# Installer le plugin "Build History Metrics"
# Voir les tendances de durée des builds et les taux de succès
# Surveillance de l'utilisation du disque
# Installer le plugin "Disk Usage"
# Surveiller l'espace disque des espaces de travail et des artefacts de build
```

## Configuration et Paramètres Jenkins

### Configuration Globale

Configurer les paramètres système globaux et les outils.

```bash
# Configuration Globale des Outils
# Gérer Jenkins → Configuration Globale des Outils
# Configurer :
# - Installations JDK
# - Installations Git
# - Installations Maven
# - Installations Docker
# Configuration Système
# Gérer Jenkins → Configurer le Système
# Définir :
# - URL de Jenkins
# - Message système
# - # d'exécuteurs
# - Période de silence (Quiet period)
# - Limites de sondage SCM
```

### Variables d'Environnement

Configurer les variables d'environnement et les propriétés système de Jenkins.

```bash
# Variables d'environnement intégrées
BUILD_NUMBER          # Numéro de build
BUILD_ID              # ID du build
JOB_NAME             # Nom du job
WORKSPACE            # Chemin de l'espace de travail du job
JENKINS_URL          # URL de Jenkins
NODE_NAME            # Nom du nœud
# Variables d'environnement personnalisées
# Gérer Jenkins → Configurer le Système
# Propriétés globales → Variables d'environnement
# Ajouter des paires clé-valeur pour un accès global
```

### Configuration de Jenkins en tant que Code

Gérer la configuration de Jenkins en utilisant le plugin JCasC.

```yaml
# Fichier de configuration JCasC (jenkins.yaml)
jenkins:
  systemMessage: "Jenkins configuré en tant que code"
  numExecutors: 4
  securityRealm:
    local:
      allowsSignup: false
      users:
       - id: "admin"
         password: "admin123"
# Appliquer la configuration
# Définir la variable d'environnement CASC_JENKINS_CONFIG
export CASC_JENKINS_CONFIG=/chemin/vers/jenkins.yaml
```

## Bonnes Pratiques

### Bonnes Pratiques de Sécurité

Maintenir votre instance Jenkins sécurisée et prête pour la production.

```bash
# Recommandations de sécurité :
# 1. Activer la sécurité et l'authentification
# 2. Utiliser l'autorisation basée sur une matrice
# 3. Mises à jour de sécurité régulières
# 4. Limiter les permissions des utilisateurs
# 5. Utiliser des jetons API au lieu de mots de passe
# Sécuriser la configuration Jenkins :
# - Désactiver CLI sur remoting
# - Utiliser HTTPS avec des certificats valides
# - Sauvegarde régulière de JENKINS_HOME
# - Surveiller les avis de sécurité
# - Utiliser des plugins d'identifiants pour les secrets
```

### Optimisation des Performances

Optimiser Jenkins pour de meilleures performances et évolutivité.

```bash
# Conseils de performance :
# 1. Utiliser des builds distribués avec des agents
# 2. Optimiser les scripts de build et les dépendances
# 3. Nettoyer automatiquement les anciens builds
# 4. Utiliser des bibliothèques de pipeline pour la réutilisabilité
# 5. Surveiller l'espace disque et l'utilisation de la mémoire
# Optimisation du build :
# - Utiliser des builds incrémentiels si possible
# - Exécution parallèle des étapes
# - Mise en cache des artefacts
# - Nettoyage de l'espace de travail
# - Réglage de l'allocation des ressources
```

## Liens Pertinents

- <router-link to="/devops">Feuille de triche DevOps</router-link>
- <router-link to="/docker">Feuille de triche Docker</router-link>
- <router-link to="/kubernetes">Feuille de triche Kubernetes</router-link>
- <router-link to="/ansible">Feuille de triche Ansible</router-link>
- <router-link to="/git">Feuille de triche Git</router-link>
- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>

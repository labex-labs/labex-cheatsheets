---
title: 'Cheat Sheet Kubernetes'
description: 'Maîtrisez Kubernetes avec notre aide-mémoire complet couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/kubernetes-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Trombinoscope Kubernetes
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/kubernetes">Apprendre Kubernetes avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez l'orchestration de conteneurs Kubernetes grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours complets sur Kubernetes couvrant les commandes kubectl essentielles, la gestion des pods, les déploiements, les services, le réseau et l'administration de cluster. Maîtrisez l'orchestration de conteneurs et le déploiement d'applications cloud-natives.
</base-disclaimer-content>
</base-disclaimer>

## Installation et Configuration

### Installer kubectl

Installer l'outil de ligne de commande Kubernetes.

```bash
# macOS avec Homebrew
brew install kubectl
# Linux (binaire officiel)
curl -LO "https://dl.k8s.io/release/$(curl -L -s
https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kube
ctl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
# Windows avec Chocolatey
choco install kubernetes-cli
```

### Vérifier l'Installation

Vérifier la version de kubectl et la connexion au cluster.

```bash
# Vérifier la version de kubectl
kubectl version --client
# Vérifier les versions client et serveur
kubectl version
# Obtenir les informations du cluster
kubectl cluster-info
```

### Configurer kubectl

Configurer l'accès au cluster et le contexte.

```bash
# Voir la configuration actuelle
kubectl config view
# Lister tous les contextes
kubectl config get-contexts
# Basculer vers un contexte
kubectl config use-context my-cluster
# Définir l'espace de noms par défaut
kubectl config set-context --current --namespace=my-
namespace
```

### Configuration Minikube

Cluster Kubernetes local rapide pour le développement.

```bash
# Démarrer Minikube
minikube start
# Vérifier le statut
minikube status
# Accéder au tableau de bord
minikube dashboard
# Arrêter le cluster
minikube stop
```

## Commandes de Base et Informations sur le Cluster

### Informations sur le Cluster : `kubectl cluster-info`

Afficher les détails essentiels du cluster et les points d'accès des services.

```bash
# Obtenir les informations du cluster
kubectl cluster-info
# Voir la configuration du cluster
kubectl config view
# Vérifier les ressources API disponibles
kubectl api-resources
# Afficher les versions API supportées
kubectl api-versions
```

### Gestion des Nœuds : `kubectl get nodes`

Visualiser et gérer les nœuds du cluster.

```bash
# Lister tous les nœuds
kubectl get nodes
# Informations détaillées sur les nœuds
kubectl get nodes -o wide
# Décrire un nœud spécifique
kubectl describe node
# Obtenir l'utilisation des ressources des nœuds
kubectl top nodes
```

### Opérations sur les Espaces de Noms : `kubectl get namespaces`

Organiser et isoler les ressources à l'aide des espaces de noms.

```bash
# Lister tous les espaces de noms
kubectl get namespaces
# Créer un espace de noms
kubectl create namespace my-
namespace
# Supprimer un espace de noms
kubectl delete namespace my-
namespace
# Obtenir les ressources dans un espace de noms spécifique
kubectl get all -n my-namespace
```

## Gestion des Pods

### Créer et Exécuter des Pods : `kubectl run` / `kubectl create`

Lancer des conteneurs et gérer leur cycle de vie.

```bash
# Exécuter un pod simple
kubectl run nginx --image=nginx
# Créer un pod à partir d'un fichier YAML
kubectl create -f pod.yaml
# Exécuter un pod avec une commande
kubectl run busybox --image=busybox -- echo "Hello
World"
# Créer un job
kubectl create job hello --image=busybox:1.28 -- echo
"Hello World"
```

### Voir les Informations sur les Pods : `kubectl get pods`

Lister et inspecter les pods en cours d'exécution.

```bash
# Lister tous les pods dans l'espace de noms par défaut
kubectl get pods
# Lister les pods avec plus de détails
kubectl get pods -o wide
# Lister les pods dans tous les espaces de noms
kubectl get pods --all-namespaces
# Surveiller les changements d'état des pods
kubectl get pods --watch
```

### Détails des Pods : `kubectl describe pod`

Obtenir des informations complètes sur des pods spécifiques.

```bash
# Décrire un pod spécifique
kubectl describe pod
# Décrire un pod dans un espace de noms spécifique
kubectl describe pod  -n
```

### Opérations sur les Pods : `kubectl exec` / `kubectl delete`

Exécuter des commandes dans les pods et gérer leur cycle de vie.

```bash
# Obtenir les logs du pod
kubectl logs
# Suivre les logs en temps réel
kubectl logs -f
# Exécuter une commande dans le pod
kubectl exec -it  -- /bin/bash
# Exécuter une commande dans un conteneur spécifique
kubectl exec -it  -c  -- sh
# Supprimer un pod
kubectl delete pod
# Supprimer un pod de force
kubectl delete pod  --grace-period=0 --force
```

## Déploiements et ReplicaSets

### Créer des Déploiements : `kubectl create deployment`

Déployer et gérer des applications de manière déclarative.

```bash
# Créer un déploiement
kubectl create deployment nginx --image=nginx
# Créer un déploiement avec des réplicas
kubectl create deployment webapp --image=nginx --
replicas=3
# Créer à partir d'un fichier YAML
kubectl apply -f deployment.yaml
# Exposer le déploiement comme service
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
```

### Gérer les Déploiements : `kubectl get deployments`

Visualiser et contrôler l'état et la configuration des déploiements.

```bash
# Lister les déploiements
kubectl get deployments
# Décrire le déploiement
kubectl describe deployment
# Éditer le déploiement
kubectl edit deployment
# Supprimer le déploiement
kubectl delete deployment
```

### Mise à l'Échelle : `kubectl scale`

Ajuster le nombre de réplicas en cours d'exécution.

```bash
# Mettre à l'échelle un déploiement
kubectl scale deployment nginx --replicas=5
# Mettre à l'échelle un ReplicaSet
kubectl scale rs  --replicas=3
# Mise à l'échelle automatique d'un déploiement
kubectl autoscale deployment nginx --min=2 --max=10 --
cpu-percent=80
```

### Mises à Jour Progressives : `kubectl rollout`

Gérer les mises à jour et les retours en arrière des déploiements.

```bash
# Vérifier le statut du déploiement
kubectl rollout status deployment/nginx
# Voir l'historique des déploiements
kubectl rollout history deployment/nginx
# Retour en arrière vers la version précédente
kubectl rollout undo deployment/nginx
# Retour en arrière vers une révision spécifique
kubectl rollout undo deployment/nginx --to-revision=2
```

## Services et Réseau

### Exposer des Services : `kubectl expose`

Rendre les applications accessibles via des services réseau.

```bash
# Exposer un déploiement comme service ClusterIP
kubectl expose deployment nginx --port=80
# Exposer comme service NodePort
kubectl expose deployment nginx --port=80 --
type=NodePort
# Exposer comme LoadBalancer
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
# Créer un service à partir d'un YAML
kubectl apply -f service.yaml
```

### Découverte de Services : `kubectl get services`

Lister et inspecter les services dans votre cluster.

```bash
# Lister tous les services
kubectl get services
# Lister les services avec plus de détails
kubectl get svc -o wide
# Décrire un service spécifique
kubectl describe service
# Obtenir les points de terminaison du service
kubectl get endpoints
```

### Transfert de Ports : `kubectl port-forward`

Accéder aux applications localement pour les tests et le débogage.

```bash
# Transférer le port du pod vers la machine locale
kubectl port-forward pod/ 8080:80
# Transférer le port du service
kubectl port-forward svc/ 8080:80
# Transférer le port du déploiement
kubectl port-forward deployment/ 8080:80
# Transférer plusieurs ports
kubectl port-forward pod/ 8080:80 8443:443
```

### Gestion d'Ingress

Gérer l'accès externe aux services via des routes HTTP/HTTPS.

```bash
# Lister les ressources ingress
kubectl get ingress
# Décrire l'ingress
kubectl describe ingress
# Créer un ingress à partir d'un YAML
kubectl apply -f ingress.yaml
```

## ConfigMaps et Secrets

### ConfigMaps : `kubectl create configmap`

Stocker des données de configuration non confidentielles sous forme de paires clé-valeur.

```bash
# Créer un ConfigMap à partir de littéraux
kubectl create configmap app-config --from-
literal=database_url=localhost --from-literal=debug=true
# Créer à partir d'un fichier
kubectl create configmap app-config --from-
file=app.properties
# Créer à partir d'un répertoire
kubectl create configmap app-config --from-file=config/
```

### Utilisation de ConfigMap

Utiliser des ConfigMaps dans les pods comme variables d'environnement ou volumes.

```bash
# Voir le ConfigMap
kubectl get configmaps
kubectl describe configmap app-config
# Obtenir le YAML du ConfigMap
kubectl get configmap app-config -o yaml
# Éditer le ConfigMap
kubectl edit configmap app-config
# Supprimer le ConfigMap
kubectl delete configmap app-config
```

### Secrets : `kubectl create secret`

Stocker et gérer des informations sensibles comme les mots de passe et les clés API.

```bash
# Créer un secret générique
kubectl create secret generic db-secret --from-
literal=username=admin --from-
literal=password=secret123
# Créer un secret à partir d'un fichier
kubectl create secret generic ssl-certs --from-file=tls.crt --
from-file=tls.key
# Créer un secret de registre docker
kubectl create secret docker-registry my-registry --
docker-server=myregistry.com --docker-username=user -
-docker-password=pass
```

### Gestion des Secrets

Visualiser et gérer les secrets en toute sécurité.

```bash
# Lister les secrets
kubectl get secrets
# Décrire le secret (les valeurs sont masquées)
kubectl describe secret db-secret
# Décoder les valeurs des secrets
kubectl get secret db-secret -o
jsonpath='{.data.password}' | base64 -d
# Supprimer le secret
kubectl delete secret db-secret
```

## Stockage et Volumes

### Volumes Persistants : `kubectl get pv`

Gérer les ressources de stockage à l'échelle du cluster.

```bash
# Lister les volumes persistants
kubectl get pv
# Décrire un volume persistant
kubectl describe pv
# Créer un PV à partir d'un YAML
kubectl apply -f persistent-volume.yaml
# Supprimer un volume persistant
kubectl delete pv
```

### Demandes de Volume Persistant : `kubectl get pvc`

Demander des ressources de stockage pour les pods.

```bash
# Lister les PVC
kubectl get pvc
# Décrire un PVC
kubectl describe pvc
# Créer un PVC à partir d'un YAML
kubectl apply -f pvc.yaml
# Supprimer un PVC
kubectl delete pvc
```

### Classes de Stockage : `kubectl get storageclass`

Définir différents types de stockage avec diverses propriétés.

```bash
# Lister les classes de stockage
kubectl get storageclass
# Décrire une classe de stockage
kubectl describe storageclass
# Définir la classe de stockage par défaut
kubectl patch storageclass  -p '{"metadata":
{"annotations":{"storageclass.kubernetes.io/is-default-
class":"true"}}}'
```

### Opérations sur les Volumes

Travailler avec différents types de volumes dans vos pods.

```bash
# Vérifier les montages de volume dans le pod
kubectl describe pod  | grep -A5 "Mounts:"
# Lister les volumes dans le pod
kubectl get pod  -o yaml | grep -A10 "volumes:"
```

## Dépannage et Débogage

### Logs et Événements : `kubectl logs` / `kubectl get events`

Examiner les logs des applications et les événements du cluster pour le débogage.

```bash
# Voir les logs du pod
kubectl logs
# Suivre les logs en temps réel
kubectl logs -f
# Voir les logs du conteneur précédent
kubectl logs  --previous
# Voir les logs d'un conteneur spécifique
kubectl logs  -c
# Voir les événements du cluster
kubectl get events --sort-
by=.metadata.creationTimestamp
```

### Inspection des Ressources : `kubectl describe`

Obtenir des informations détaillées sur toute ressource Kubernetes.

```bash
# Décrire un pod
kubectl describe pod
# Décrire un déploiement
kubectl describe deployment
# Décrire un service
kubectl describe service
# Décrire un nœud
kubectl describe node
```

### Utilisation des Ressources : `kubectl top`

Surveiller la consommation des ressources à travers les pods et les nœuds.

```bash
# Voir l'utilisation des ressources des nœuds
kubectl top nodes
# Voir l'utilisation des ressources des pods
kubectl top pods
# Voir l'utilisation des ressources des pods dans un espace de noms
kubectl top pods -n
# Trier les pods par utilisation CPU
kubectl top pods --sort-by=cpu
```

### Débogage Interactif : `kubectl exec` / `kubectl debug`

Accéder aux conteneurs en cours d'exécution pour le dépannage pratique.

```bash
# Exécuter un shell interactif
kubectl exec -it  -- /bin/bash
# Déboguer avec un conteneur éphémère (K8s 1.23+)
kubectl debug  -it --image=busybox
# Copier des fichiers depuis le pod
kubectl cp :/path/to/file ./local-file
# Copier des fichiers vers le pod
kubectl cp ./local-file :/path/to/destination
```

## Gestion des Ressources

### Appliquer des Ressources : `kubectl apply`

Créer ou mettre à jour des ressources à l'aide de fichiers de configuration déclaratifs.

```bash
# Appliquer un fichier unique
kubectl apply -f deployment.yaml
# Appliquer plusieurs fichiers
kubectl apply -f deployment.yaml -f service.yaml
# Appliquer un répertoire entier
kubectl apply -f ./k8s-configs/
# Appliquer depuis une URL
kubectl apply -f https://example.com/manifest.yaml
# Montrer ce qui serait appliqué (essai à blanc)
kubectl apply -f deployment.yaml --dry-run=client -o yaml
```

### Opérations sur les Ressources : `kubectl get` / `kubectl delete`

Lister, inspecter et supprimer les ressources Kubernetes.

```bash
# Obtenir toutes les ressources dans l'espace de noms
kubectl get all
# Obtenir les ressources avec des colonnes personnalisées
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# Obtenir les ressources en format YAML/JSON
kubectl get deployment nginx -o yaml
kubectl get pod  -o json
# Supprimer des ressources
kubectl delete -f deployment.yaml
kubectl delete pod,service -l app=nginx
```

### Édition des Ressources : `kubectl edit` / `kubectl patch`

Modifier les ressources existantes directement.

```bash
# Éditer une ressource interactivement
kubectl edit deployment
# Patch de ressource avec fusion stratégique
kubectl patch deployment nginx -p '{"spec":
{"replicas":3}}'
# Patch de ressource avec fusion JSON
kubectl patch pod  --type='json' -p='[{"op": "replace",
"path": "/metadata/labels/env", "value": "prod"}]'
# Remplacer entièrement la ressource
kubectl replace -f updated-deployment.yaml
```

### Validation des Ressources : `kubectl diff` / `kubectl explain`

Comparer les configurations et comprendre les schémas de ressources.

```bash
# Montrer les différences avant l'application
kubectl diff -f deployment.yaml
# Expliquer la structure de la ressource
kubectl explain pod.spec.containers
# Expliquer avec des exemples
kubectl explain deployment --recursive
# Valider la ressource sans appliquer
kubectl apply -f deployment.yaml --dry-run=client --
validate=true
```

## Opérations Avancées

### Gestion des Nœuds : `kubectl cordon` / `kubectl drain`

Gérer la disponibilité des nœuds pour la maintenance et les mises à jour.

```bash
# Marquer un nœud comme non planifiable
kubectl cordon
# Marquer un nœud comme planifiable
kubectl uncordon
# Vider un nœud pour maintenance
kubectl drain  --ignore-daemonsets --delete-emptydir-
data
# Ajouter un taint à un nœud
kubectl taint nodes  key=value:NoSchedule
# Supprimer un taint d'un nœud
kubectl taint nodes  key:NoSchedule-
```

### Étiquetage et Annotations : `kubectl label` / `kubectl annotate`

Ajouter des métadonnées aux ressources pour l'organisation et la sélection.

```bash
# Ajouter une étiquette à une ressource
kubectl label pod  environment=production
# Supprimer une étiquette d'une ressource
kubectl label pod  environment-
# Ajouter une annotation à une ressource
kubectl annotate pod  description="Frontend web
server"
# Sélectionner des ressources par étiquette
kubectl get pods -l environment=production
kubectl get pods -l 'environment in (production,staging)'
```

### Proxy et Authentification : `kubectl proxy` / `kubectl auth`

Accéder aux API du cluster et gérer l'authentification.

```bash
# Démarrer un proxy vers l'API Kubernetes
kubectl proxy --port=8080
# Vérifier si l'utilisateur peut effectuer une action
kubectl auth can-i create pods
kubectl auth can-i '*' '*' --
as=system:serviceaccount:default:my-sa
# Imiter un utilisateur
kubectl get pods --as=system:serviceaccount:default:my-
sa
# Voir les informations d'authentification de l'utilisateur
kubectl config view --raw -o jsonpath='{.users[*].name}'
```

### Commandes Utilitaires

Commandes utiles supplémentaires pour les opérations Kubernetes.

```bash
# Attendre une condition
kubectl wait --for=condition=Ready pod/ --timeout=300s
# Exécuter un pod temporaire pour le test
kubectl run tmp-pod --rm -i --tty --image=busybox --
/bin/sh
# Générer le YAML de la ressource sans la créer
kubectl create deployment nginx --image=nginx --dry-
run=client -o yaml
# Trier les ressources par date de création
kubectl get pods --sort-by=.metadata.creationTimestamp
```

## Performance et Surveillance

### Métriques des Ressources : `kubectl top`

Visualiser l'utilisation des ressources en temps réel à travers le cluster.

```bash
# Utilisation des ressources des nœuds
kubectl top nodes --sort-by=cpu
kubectl top nodes --sort-by=memory
# Utilisation des ressources des pods
kubectl top pods --sort-by=cpu
kubectl top pods --sort-by=memory -A
# Utilisation des ressources des conteneurs
kubectl top pods --containers=true
# Utilisation des ressources historiques (nécessite metrics-server)
kubectl top pods --previous
```

### Vérifications d'État

Surveiller la santé des applications et du cluster.

```bash
# Vérifier le statut du déploiement
kubectl rollout status deployment/
# Vérifier la préparation des pods
kubectl get pods --field-selector=status.phase=Running
# Surveiller les quotas de ressources
kubectl get resourcequota
kubectl describe resourcequota
# Vérifier le statut des composants du cluster
kubectl get componentstatuses
```

### Optimisation des Performances

Commandes pour aider à optimiser les performances du cluster.

```bash
# Voir les requêtes et limites de ressources
kubectl describe node  | grep -A5 "Allocated resources:"
# Vérifier les budgets de perturbation des pods
kubectl get pdb
# Voir les autoscalers de pods horizontaux
kubectl get hpa
# Vérifier les politiques réseau
kubectl get networkpolicy
```

### Sauvegarde et Récupération

Commandes essentielles pour la sauvegarde et la reprise après sinistre du cluster.

```bash
# Sauvegarder toutes les ressources dans l'espace de noms
kubectl get all -o yaml -n  > backup.yaml
# Exporter une ressource spécifique
kubectl get deployment  -o yaml > deployment-
backup.yaml
# Lister toutes les ressources pour la sauvegarde
kubectl api-resources --verbs=list --namespaced -o name
| xargs -n 1 kubectl get --show-kind --ignore-not-found -n
```

## Gestion de la Configuration et du Contexte

### Gestion des Contextes

Basculer entre différents clusters et utilisateurs Kubernetes.

```bash
# Voir le contexte actuel
kubectl config current-context
# Lister tous les contextes
kubectl config get-contexts
# Changer de contexte
kubectl config use-context
# Créer un nouveau contexte
kubectl config set-context dev-
context --cluster=dev-cluster --
user=dev-user --
namespace=development
```

### Gestion Kubeconfig

Configurer kubectl pour fonctionner avec plusieurs clusters.

```bash
# Voir le kubeconfig fusionné
kubectl config view
# Définir les informations du cluster
kubectl config set-cluster  --
server=https://cluster-api-url --
certificate-
authority=/path/to/ca.crt
# Définir les informations d'identification de l'utilisateur
kubectl config set-credentials  --
client-
certificate=/path/to/client.crt --
client-key=/path/to/client.key
# Fusionner les fichiers kubeconfig
KUBECONFIG=~/.kube/config:~/.
kube/config2 kubectl config
view --merge --flatten >
~/.kube/merged-config
```

### Paramètres par Défaut

Définir les espaces de noms et les préférences par défaut pour les opérations kubectl.

```bash
# Définir l'espace de noms par défaut pour le contexte
actuel
kubectl config set-context --
current --namespace=
# Définir le format de sortie par défaut
kubectl config set-context --
current --output=yaml
# Voir les détails de la configuration
kubectl config view -o
jsonpath='{.users[*].name}'
kubectl config view --raw
```

## Bonnes Pratiques et Astuces

### Efficacité des Commandes

Raccourcis et alias pour accélérer les opérations quotidiennes.

```bash
# Alias kubectl courants
alias k=kubectl
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'
# Utiliser des noms courts pour les ressources
kubectl get po        # pods
kubectl get svc       # services
kubectl get deploy    # deployments
kubectl get ns        # namespaces
kubectl get no        # nodes
# Surveiller les ressources pour les changements
kubectl get pods --watch
kubectl get events --watch
```

### Sélection des Ressources

Manières efficaces de sélectionner et filtrer les ressources.

```bash
# Sélectionner par étiquettes
kubectl get pods -l app=nginx
kubectl get pods -l 'environment in (prod,staging)'
kubectl get pods -l app=nginx,version!=v1.0
# Sélectionner par champ
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --field-
selector=spec.nodeName=worker-node-1
# Combiner les sélecteurs
kubectl get pods -l app=nginx --field-
selector=status.phase=Running
```

### Formatage de la Sortie

Personnaliser la sortie des commandes pour une meilleure lisibilité et un meilleur traitement.

```bash
# Différents formats de sortie
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json
kubectl get pods -o name
# Colonnes personnalisées
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# Requêtes JSONPath
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o
jsonpath='{.items[*].spec.containers[*].image}'
```

### Sécurité et Validation

Commandes pour assurer des opérations sûres et valider les configurations.

```bash
# Essai à blanc pour prévisualiser les changements
kubectl apply -f deployment.yaml --dry-run=client -o yaml
# Valider la configuration
kubectl apply -f deployment.yaml --validate=true --dry-
run=client
# Montrer les différences avant l'application
kubectl diff -f deployment.yaml
# Suppression forcée avec délai d'attente nul
kubectl delete pod  --grace-period=0 --force
```

## Liens Pertinents

- <router-link to="/docker">Trombinoscope Docker</router-link>
- <router-link to="/linux">Trombinoscope Linux</router-link>
- <router-link to="/shell">Trombinoscope Shell</router-link>
- <router-link to="/devops">Trombinoscope DevOps</router-link>
- <router-link to="/ansible">Trombinoscope Ansible</router-link>
- <router-link to="/git">Trombinoscope Git</router-link>
- <router-link to="/rhel">Trombinoscope Red Hat Enterprise Linux</router-link>
- <router-link to="/cybersecurity">Trombinoscope Cybersécurité</router-link>

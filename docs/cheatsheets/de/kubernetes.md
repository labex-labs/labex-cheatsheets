---
title: 'Kubernetes Spickzettel | LabEx'
description: 'Lernen Sie Kubernetes-Orchestrierung mit diesem umfassenden Spickzettel. Schnelle Referenz für kubectl-Befehle, Pods, Deployments, Services, Ingress und Cloud-Native-Containerverwaltung.'
pdfUrl: '/cheatsheets/pdf/kubernetes-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kubernetes Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/kubernetes">Lernen Sie Kubernetes mit Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Kubernetes Container-Orchestrierung durch praktische Labs und reale Szenarien. LabEx bietet umfassende Kubernetes-Kurse, die wesentliche kubectl-Befehle, Pod-Verwaltung, Deployments, Services, Networking und Cluster-Administration abdecken. Meistern Sie Container-Orchestrierung und Cloud-Native-Anwendungsbereitstellung.
</base-disclaimer-content>
</base-disclaimer>

## Installation & Einrichtung

### kubectl installieren

Installieren Sie das Kubernetes-Kommandozeilenwerkzeug.

```bash
# macOS mit Homebrew
brew install kubectl
# Linux (offizielle Binärdatei)
curl -LO "https://dl.k8s.io/release/$(curl -L -s
https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kube
ctl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
# Windows mit Chocolatey
choco install kubernetes-cli
```

### Installation überprüfen

Überprüfen Sie die kubectl-Version und die Cluster-Verbindung.

```bash
# kubectl-Version prüfen
kubectl version --client
# Sowohl Client- als auch Serverversion prüfen
kubectl version
# Cluster-Informationen abrufen
kubectl cluster-info
```

### kubectl konfigurieren

Richten Sie den Cluster-Zugriff und den Kontext ein.

```bash
# Aktuelle Konfiguration anzeigen
kubectl config view
# Alle Kontexte auflisten
kubectl config get-contexts
# Zu einem Kontext wechseln
kubectl config use-context my-cluster
# Standard-Namespace festlegen
kubectl config set-context --current --namespace=my-
namespace
```

### Minikube-Einrichtung

Schneller lokaler Kubernetes-Cluster für die Entwicklung.

```bash
# Minikube starten
minikube start
# Status prüfen
minikube status
# Auf Dashboard zugreifen
minikube dashboard
# Cluster stoppen
minikube stop
```

## Grundlegende Befehle & Cluster-Infos

### Cluster-Informationen: `kubectl cluster-info`

Zeigt wesentliche Cluster-Details und Service-Endpunkte an.

```bash
# Cluster-Informationen abrufen
kubectl cluster-info
# Cluster-Konfiguration anzeigen
kubectl config view
# Verfügbare API-Ressourcen prüfen
kubectl api-resources
# Unterstützte API-Versionen anzeigen
kubectl api-versions
```

### Knotenverwaltung: `kubectl get nodes`

Cluster-Knoten anzeigen und verwalten.

```bash
# Alle Knoten auflisten
kubectl get nodes
# Detaillierte Knoteninformationen
kubectl get nodes -o wide
# Bestimmten Knoten beschreiben
kubectl describe node
# Knotenauslastung abrufen
kubectl top nodes
```

### Namespace-Operationen: `kubectl get namespaces`

Ressourcen mithilfe von Namespaces organisieren und isolieren.

```bash
# Alle Namespaces auflisten
kubectl get namespaces
# Einen Namespace erstellen
kubectl create namespace my-
namespace
# Einen Namespace löschen
kubectl delete namespace my-
namespace
# Ressourcen in einem bestimmten Namespace abrufen
kubectl get all -n my-namespace
```

<BaseQuiz id="kubernetes-namespace-1" correct="B">
  <template #question>
    Was ist der Hauptzweck von Kubernetes Namespaces?
  </template>
  
  <BaseQuizOption value="A">Zur Verbesserung der Cluster-Leistung</BaseQuizOption>
  <BaseQuizOption value="B" correct>Zur Organisation und Isolierung von Ressourcen innerhalb eines Clusters</BaseQuizOption>
  <BaseQuizOption value="C">Zur Verbindung von Clustern miteinander</BaseQuizOption>
  <BaseQuizOption value="D">Zum Speichern von Container-Images</BaseQuizOption>
  
  <BaseQuizAnswer>
    Namespaces bieten eine Möglichkeit, Cluster-Ressourcen zwischen mehreren Benutzern oder Teams aufzuteilen. Sie helfen bei der Organisation von Ressourcen und bieten einen Namensbereich, sodass Sie Ressourcen mit demselben Namen in verschiedenen Namespaces haben können.
  </BaseQuizAnswer>
</BaseQuiz>

## Pod-Verwaltung

### Pods erstellen & ausführen: `kubectl run` / `kubectl create`

Container starten und deren Lebenszyklus verwalten.

```bash
# Einfachen Pod ausführen
kubectl run nginx --image=nginx
# Pod aus YAML-Datei erstellen
kubectl create -f pod.yaml
# Pod mit Befehl ausführen
kubectl run busybox --image=busybox -- echo "Hello
World"
# Job erstellen
kubectl create job hello --image=busybox:1.28 -- echo
"Hello World"
```

### Pod-Informationen anzeigen: `kubectl get pods`

Laufende Pods auflisten und inspizieren.

```bash
# Alle Pods im Standard-Namespace auflisten
kubectl get pods
# Pods mit mehr Details auflisten
kubectl get pods -o wide
# Pods in allen Namespaces auflisten
kubectl get pods --all-namespaces
# Pod-Statusänderungen beobachten
kubectl get pods --watch
```

<BaseQuiz id="kubernetes-pods-1" correct="C">
  <template #question>
    Was bewirkt `kubectl get pods --all-namespaces`?
  </template>
  
  <BaseQuizOption value="A">Listet nur laufende Pods auf</BaseQuizOption>
  <BaseQuizOption value="B">Listet Pods im Standard-Namespace auf</BaseQuizOption>
  <BaseQuizOption value="C" correct>Listet Pods in allen Namespaces des Clusters auf</BaseQuizOption>
  <BaseQuizOption value="D">Löscht alle Pods</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das Flag `--all-namespaces` (oder `-A`) zeigt Pods aus allen Namespaces an, nicht nur aus dem Standard-Namespace. Dies ist nützlich für die clusterweite Sichtbarkeit.
  </BaseQuizAnswer>
</BaseQuiz>

### Pod-Details: `kubectl describe pod`

Umfassende Informationen zu bestimmten Pods abrufen.

```bash
# Bestimmten Pod beschreiben
kubectl describe pod
# Pod in spezifischem Namespace beschreiben
kubectl describe pod  -n
```

### Pod-Operationen: `kubectl exec` / `kubectl delete`

Befehle in Pods ausführen und den Pod-Lebenszyklus verwalten.

```bash
# Pod-Logs abrufen
kubectl logs
# Logs in Echtzeit verfolgen
kubectl logs -f
# Befehl im Pod ausführen
kubectl exec -it  -- /bin/bash
# Befehl in spezifischem Container ausführen
kubectl exec -it  -c  -- sh
# Einen Pod löschen
kubectl delete pod
# Pod erzwingend löschen
kubectl delete pod  --grace-period=0 --force
```

## Deployments & ReplicaSets

### Deployments erstellen: `kubectl create deployment`

Anwendungen deklarativ bereitstellen und verwalten.

```bash
# Deployment erstellen
kubectl create deployment nginx --image=nginx
# Deployment mit Replikaten erstellen
kubectl create deployment webapp --image=nginx --
replicas=3
# Erstellung aus YAML-Datei
kubectl apply -f deployment.yaml
# Deployment als Service verfügbar machen
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
```

<BaseQuiz id="kubernetes-deployment-1" correct="A">
  <template #question>
    Was ist der Hauptzweck eines Kubernetes Deployments?
  </template>
  
  <BaseQuizOption value="A" correct>Zur Verwaltung und Aufrechterhaltung einer gewünschten Anzahl von Pod-Replikaten</BaseQuizOption>
  <BaseQuizOption value="B">Zur Exposition von Pods gegenüber externem Traffic</BaseQuizOption>
  <BaseQuizOption value="C">Zur Speicherung von Konfigurationsdaten</BaseQuizOption>
  <BaseQuizOption value="D">Zur Verwaltung von Cluster-Knoten</BaseQuizOption>
  
  <BaseQuizAnswer>
    Ein Deployment verwaltet ein ReplicaSet, das sicherstellt, dass eine bestimmte Anzahl von Pod-Replikaten läuft. Es bietet deklarative Updates, Rolling Updates und Rollback-Funktionen.
  </BaseQuizAnswer>
</BaseQuiz>

### Deployments verwalten: `kubectl get deployments`

Deployment-Status und Konfiguration anzeigen und steuern.

```bash
# Deployments auflisten
kubectl get deployments
# Deployment beschreiben
kubectl describe deployment
# Deployment bearbeiten
kubectl edit deployment
# Deployment löschen
kubectl delete deployment
```

### Skalierung: `kubectl scale`

Die Anzahl der laufenden Replikate anpassen.

```bash
# Deployment skalieren
kubectl scale deployment nginx --replicas=5
# ReplicaSet skalieren
kubectl scale rs  --replicas=3
# Deployment automatisch skalieren
kubectl autoscale deployment nginx --min=2 --max=10 --
cpu-percent=80
```

<BaseQuiz id="kubernetes-scale-1" correct="B">
  <template #question>
    Was bewirkt `kubectl scale deployment nginx --replicas=5`?
  </template>
  
  <BaseQuizOption value="A">Erstellt 5 neue Deployments</BaseQuizOption>
  <BaseQuizOption value="B" correct>Skaliert das nginx Deployment auf 5 Pod-Replikate</BaseQuizOption>
  <BaseQuizOption value="C">Löscht 5 Pods aus dem Deployment</BaseQuizOption>
  <BaseQuizOption value="D">Aktualisiert das Deployment-Image</BaseQuizOption>
  
  <BaseQuizAnswer>
    Der Befehl `scale` passt die Anzahl der Replikate für ein Deployment an. Dieser Befehl stellt sicher, dass das nginx Deployment genau 5 Pod-Replikate ausführt, indem bei Bedarf Pods erstellt oder gelöscht werden.
  </BaseQuizAnswer>
</BaseQuiz>

### Rolling Updates: `kubectl rollout`

Deployment-Updates und Rollbacks verwalten.

```bash
# Rollout-Status prüfen
kubectl rollout status deployment/nginx
# Rollout-Verlauf anzeigen
kubectl rollout history deployment/nginx
# Zurückrollen auf vorherige Version
kubectl rollout undo deployment/nginx
# Zurückrollen auf spezifische Revision
kubectl rollout undo deployment/nginx --to-revision=2
```

## Services & Networking

### Services verfügbar machen: `kubectl expose`

Anwendungen über Netzwerkdienste zugänglich machen.

```bash
# Deployment als ClusterIP Service verfügbar machen
kubectl expose deployment nginx --port=80
# Als NodePort Service verfügbar machen
kubectl expose deployment nginx --port=80 --
type=NodePort
# Als LoadBalancer verfügbar machen
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
# Service aus YAML erstellen
kubectl apply -f service.yaml
```

<BaseQuiz id="kubernetes-service-1" correct="A">
  <template #question>
    Welcher Servicetyp ist standardmäßig bei Verwendung von `kubectl expose`?
  </template>
  
  <BaseQuizOption value="A" correct>ClusterIP</BaseQuizOption>
  <BaseQuizOption value="B">NodePort</BaseQuizOption>
  <BaseQuizOption value="C">LoadBalancer</BaseQuizOption>
  <BaseQuizOption value="D">ExternalName</BaseQuizOption>
  
  <BaseQuizAnswer>
    ClusterIP ist der Standard-Servicetyp. Er macht den Service über eine interne IP des Clusters verfügbar, sodass er nur innerhalb des Clusters zugänglich ist. NodePort- und LoadBalancer-Typen bieten externen Zugriff.
  </BaseQuizAnswer>
</BaseQuiz>

### Service Discovery: `kubectl get services`

Services in Ihrem Cluster auflisten und inspizieren.

```bash
# Alle Services auflisten
kubectl get services
# Services mit mehr Details auflisten
kubectl get svc -o wide
# Spezifischen Service beschreiben
kubectl describe service
# Endpunkte des Services abrufen
kubectl get endpoints
```

### Port-Weiterleitung: `kubectl port-forward`

Lokaler Zugriff auf Anwendungen zum Testen und Debuggen.

```bash
# Pod-Port auf lokale Maschine weiterleiten
kubectl port-forward pod/ 8080:80
# Service-Port weiterleiten
kubectl port-forward svc/ 8080:80
# Deployment-Port weiterleiten
kubectl port-forward deployment/ 8080:80
# Mehrere Ports weiterleiten
kubectl port-forward pod/ 8080:80 8443:443
```

### Ingress-Verwaltung

Externe Zugriffe auf Services über HTTP/HTTPS-Routen verwalten.

```bash
# Ingress-Ressourcen auflisten
kubectl get ingress
# Ingress beschreiben
kubectl describe ingress
# Ingress aus YAML erstellen
kubectl apply -f ingress.yaml
```

## ConfigMaps & Secrets

### ConfigMaps: `kubectl create configmap`

Nicht-vertrauliche Konfigurationsdaten in Schlüssel-Wert-Paaren speichern.

```bash
# ConfigMap aus Literalen erstellen
kubectl create configmap app-config --from-
literal=database_url=localhost --from-literal=debug=true
# Aus Datei erstellen
kubectl create configmap app-config --from-
file=app.properties
# Aus Verzeichnis erstellen
kubectl create configmap app-config --from-file=config/
```

### ConfigMap-Nutzung

ConfigMaps in Pods als Umgebungsvariablen oder Volumes verwenden.

```bash
# ConfigMap anzeigen
kubectl get configmaps
kubectl describe configmap app-config
# ConfigMap YAML abrufen
kubectl get configmap app-config -o yaml
# ConfigMap bearbeiten
kubectl edit configmap app-config
# ConfigMap löschen
kubectl delete configmap app-config
```

### Secrets: `kubectl create secret`

Sensible Informationen wie Passwörter und API-Schlüssel speichern und verwalten.

```bash
# Generisches Secret erstellen
kubectl create secret generic db-secret --from-
literal=username=admin --from-
literal=password=secret123
# Secret aus Datei erstellen
kubectl create secret generic ssl-certs --from-file=tls.crt --
from-file=tls.key
# Docker Registry Secret erstellen
kubectl create secret docker-registry my-registry --
docker-server=myregistry.com --docker-username=user -
-docker-password=pass
```

### Secret-Verwaltung

Secrets sicher anzeigen und verwalten.

```bash
# Secrets auflisten
kubectl get secrets
# Secret beschreiben (Werte sind verborgen)
kubectl describe secret db-secret
# Secret-Werte dekodieren
kubectl get secret db-secret -o
jsonpath='{.data.password}' | base64 -d
# Secret löschen
kubectl delete secret db-secret
```

## Speicher & Volumes

### Persistent Volumes: `kubectl get pv`

Clusterweite Speicherressourcen verwalten.

```bash
# Persistent Volumes auflisten
kubectl get pv
# Persistent Volume beschreiben
kubectl describe pv
# PV aus YAML erstellen
kubectl apply -f persistent-volume.yaml
# Persistent Volume löschen
kubectl delete pv
```

### Persistent Volume Claims: `kubectl get pvc`

Speicheranforderungen für Pods anfordern.

```bash
# PVCs auflisten
kubectl get pvc
# PVC beschreiben
kubectl describe pvc
# PVC aus YAML erstellen
kubectl apply -f pvc.yaml
# PVC löschen
kubectl delete pvc
```

### Storage Classes: `kubectl get storageclass`

Verschiedene Speichertypen mit unterschiedlichen Eigenschaften definieren.

```bash
# Storage Classes auflisten
kubectl get storageclass
# Storage Class beschreiben
kubectl describe storageclass
# Standard-Storage-Klasse festlegen
kubectl patch storageclass  -p '{"metadata":
{"annotations":{"storageclass.kubernetes.io/is-default-
class":"true"}}}'
```

### Volume-Operationen

Mit verschiedenen Volume-Typen in Ihren Pods arbeiten.

```bash
# Volume-Mounts im Pod prüfen
kubectl describe pod  | grep -A5 "Mounts:"
# Volumes im Pod auflisten
kubectl get pod  -o yaml | grep -A10 "volumes:"
```

## Fehlerbehebung & Debugging

### Logs & Events: `kubectl logs` / `kubectl get events`

Anwendungslogs und Cluster-Ereignisse zur Fehlerbehebung untersuchen.

```bash
# Pod-Logs anzeigen
kubectl logs
# Logs in Echtzeit verfolgen
kubectl logs -f
# Logs des vorherigen Containers anzeigen
kubectl logs  --previous
# Logs aus spezifischem Container anzeigen
kubectl logs  -c
# Cluster-Ereignisse anzeigen
kubectl get events --sort-
by=.metadata.creationTimestamp
```

### Ressourceninspektion: `kubectl describe`

Detaillierte Informationen zu jeder Kubernetes-Ressource abrufen.

```bash
# Pod beschreiben
kubectl describe pod
# Deployment beschreiben
kubectl describe deployment
# Service beschreiben
kubectl describe service
# Knoten beschreiben
kubectl describe node
```

### Ressourcennutzung: `kubectl top`

Ressourcenverbrauch über Pods und Knoten überwachen.

```bash
# Knotenauslastung anzeigen
kubectl top nodes
# Pod-Auslastung anzeigen
kubectl top pods
# Pod-Auslastung im Namespace anzeigen
kubectl top pods -n
# Pods nach CPU-Auslastung sortieren
kubectl top pods --sort-by=cpu
```

### Interaktives Debugging: `kubectl exec` / `kubectl debug`

Auf laufende Container für praktische Fehlerbehebung zugreifen.

```bash
# Interaktive Shell ausführen
kubectl exec -it  -- /bin/bash
# Debuggen mit ephemerem Container (K8s 1.23+)
kubectl debug  -it --image=busybox
# Dateien aus Pod kopieren
kubectl cp :/path/to/file ./local-file
# Dateien in Pod kopieren
kubectl cp ./local-file :/path/to/destination
```

## Ressourcenverwaltung

### Ressourcen anwenden: `kubectl apply`

Ressourcen mithilfe deklarativer Konfigurationsdateien erstellen oder aktualisieren.

```bash
# Einzelne Datei anwenden
kubectl apply -f deployment.yaml
# Mehrere Dateien anwenden
kubectl apply -f deployment.yaml -f service.yaml
# Gesamtes Verzeichnis anwenden
kubectl apply -f ./k8s-configs/
# Von URL anwenden
kubectl apply -f https://example.com/manifest.yaml
# Zeigen, was angewendet würde (Trockenlauf)
kubectl apply -f deployment.yaml --dry-run=client -o yaml
```

### Ressourcenoperationen: `kubectl get` / `kubectl delete`

Kubernetes-Ressourcen auflisten, inspizieren und entfernen.

```bash
# Alle Ressourcen im Namespace abrufen
kubectl get all
# Ressourcen mit benutzerdefinierten Spalten abrufen
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase
# Ressourcen als JSON/YAML abrufen
kubectl get deployment nginx -o yaml
kubectl get pod  -o json
# Ressourcen löschen
kubectl delete -f deployment.yaml
kubectl delete pod,service -l app=nginx
```

### Ressourcen bearbeiten: `kubectl edit` / `kubectl patch`

Bestehende Ressourcen direkt ändern.

```bash
# Ressource interaktiv bearbeiten
kubectl edit deployment
# Ressource mit strategischer Zusammenführung patchen
kubectl patch deployment nginx -p '{"spec":
{"replicas":3}}'
# Ressource mit JSON-Merge patchen
kubectl patch pod  --type='json' -p='[{"op": "replace",
"path": "/metadata/labels/env", "value": "prod"}]'
# Ressource vollständig ersetzen
kubectl replace -f updated-deployment.yaml
```

### Ressourcenvalidierung: `kubectl diff` / `kubectl explain`

Konfigurationen vergleichen und Ressourcenschemata verstehen.

```bash
# Unterschiede vor dem Anwenden anzeigen
kubectl diff -f deployment.yaml
# Ressourcenstruktur erklären
kubectl explain pod.spec.containers
# Mit Beispielen erklären
kubectl explain deployment --recursive
# Ressource validieren ohne Anwenden
kubectl apply -f deployment.yaml --dry-run=client --
validate=true
```

## Erweiterte Operationen

### Knotenverwaltung: `kubectl cordon` / `kubectl drain`

Knotenverfügbarkeit für Wartung und Updates verwalten.

```bash
# Knoten als nicht planbar markieren
kubectl cordon
# Knoten als planbar markieren
kubectl uncordon
# Knoten für Wartung ablassen
kubectl drain  --ignore-daemonsets --delete-emptydir-
data
# Taint zu Knoten hinzufügen
kubectl taint nodes  key=value:NoSchedule
# Taint vom Knoten entfernen
kubectl taint nodes  key:NoSchedule-
```

### Labeling & Annotationen: `kubectl label` / `kubectl annotate`

Metadaten zu Ressourcen hinzufügen, um sie zu organisieren und auszuwählen.

```bash
# Label zu Ressource hinzufügen
kubectl label pod  environment=production
# Label von Ressource entfernen
kubectl label pod  environment-
# Annotation zu Ressource hinzufügen
kubectl annotate pod  description="Frontend web
server"
# Ressourcen nach Label auswählen
kubectl get pods -l environment=production
kubectl get pods -l 'environment in (production,staging)'
```

### Proxy & Authentifizierung: `kubectl proxy` / `kubectl auth`

Auf Cluster-APIs zugreifen und Authentifizierung verwalten.

```bash
# Proxy zum Kubernetes API starten
kubectl proxy --port=8080
# Prüfen, ob Benutzer Aktion ausführen kann
kubectl auth can-i create pods
kubectl auth can-i '*' '*' --
as=system:serviceaccount:default:my-sa
# Benutzer vortäuschen
kubectl get pods --as=system:serviceaccount:default:my-
sa
# Benutzer-Authentifizierungsinformationen anzeigen
kubectl config view --raw -o jsonpath='{.users[*].name}'
```

### Hilfsprogramme

Zusätzliche nützliche Befehle für Kubernetes-Operationen.

```bash
# Auf Bedingung warten
kubectl wait --for=condition=Ready pod/ --timeout=300s
# Temporären Pod für Tests ausführen
kubectl run tmp-pod --rm -i --tty --image=busybox --
/bin/sh
# YAML für Ressource generieren, ohne sie zu erstellen
kubectl create deployment nginx --image=nginx --dry-
run=client -o yaml
# Ressourcen nach Erstellungszeit sortieren
kubectl get pods --sort-by=.metadata.creationTimestamp
```

## Leistung & Überwachung

### Ressourcenmetriken: `kubectl top`

Echtzeit-Ressourcenverbrauch im gesamten Cluster anzeigen.

```bash
# Knotenauslastung
kubectl top nodes --sort-by=cpu
kubectl top nodes --sort-by=memory
# Pod-Auslastung
kubectl top pods --sort-by=cpu
kubectl top pods --sort-by=memory -A
# Container-Auslastung
kubectl top pods --containers=true
# Historische Ressourcennutzung (erfordert metrics-server)
kubectl top pods --previous
```

### Gesundheitsprüfungen & Status

Anwendungs- und Cluster-Gesundheit überwachen.

```bash
# Rollout-Status des Deployments prüfen
kubectl rollout status deployment/
# Pod-Bereitschaft prüfen
kubectl get pods --field-selector=status.phase=Running
# Ressourcenkontingente überwachen
kubectl get resourcequota
kubectl describe resourcequota
# Status der Cluster-Komponenten prüfen
kubectl get componentstatuses
```

### Leistungsoptimierung

Befehle zur Optimierung der Cluster-Leistung.

```bash
# Ressourcenanforderungen und Limits anzeigen
kubectl describe node  | grep -A5 "Allocated resources:"
# Pod Disruption Budgets prüfen
kubectl get pdb
# Horizontal Pod Autoscaler anzeigen
kubectl get hpa
# Netzwerkrichtlinien prüfen
kubectl get networkpolicy
```

### Backup & Wiederherstellung

Wesentliche Befehle für Cluster-Backup und Disaster Recovery.

```bash
# Alle Ressourcen im Namespace sichern
kubectl get all -o yaml -n  > backup.yaml
# Spezifische Ressource exportieren
kubectl get deployment  -o yaml > deployment-
backup.yaml
# Alle Ressourcen für das Backup auflisten
kubectl api-resources --verbs=list --namespaced -o name
| xargs -n 1 kubectl get --show-kind --ignore-not-found -n
```

## Konfiguration & Kontextverwaltung

### Kontextverwaltung

Zwischen verschiedenen Kubernetes-Clustern und Benutzern wechseln.

```bash
# Aktuellen Kontext anzeigen
kubectl config current-context
# Alle Kontexte auflisten
kubectl config get-contexts
# Kontext wechseln
kubectl config use-context
# Neuen Kontext erstellen
kubectl config set-context dev-
context --cluster=dev-cluster --
user=dev-user --
namespace=development
```

### Kubeconfig-Verwaltung

Konfigurieren von kubectl für die Arbeit mit mehreren Clustern.

```bash
# Zusammengeführte kubeconfig anzeigen
kubectl config view
# Cluster-Informationen festlegen
kubectl config set-cluster  --
server=https://cluster-api-url --
certificate-
authority=/path/to/ca.crt
# Benutzeranmeldeinformationen festlegen
kubectl config set-credentials  --
client-
certificate=/path/to/client.crt --
client-key=/path/to/client.key
# Kubeconfig-Dateien zusammenführen
KUBECONFIG=~/.kube/config:~/.
kube/config2 kubectl config
view --merge --flatten >
~/.kube/merged-config
```

### Standardeinstellungen

Standard-Namespaces und Präferenzen für kubectl-Operationen festlegen.

```bash
# Standard-Namespace für
aktuellen Kontext festlegen
kubectl config set-context --
current --namespace=
# Anderes Ausgabeformat als
Standard festlegen
kubectl config set-context --
current --output=yaml
# Konfigurationsdetails anzeigen
kubectl config view -o
jsonpath='{.users[*].name}'
kubectl config view --raw
```

## Best Practices & Tipps

### Befehlseffizienz

Abkürzungen und Aliase zur Beschleunigung täglicher Operationen.

```bash
# Häufige kubectl-Aliase
alias k=kubectl
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'
# Kurze Namen für Ressourcen verwenden
kubectl get po        # pods
kubectl get svc       # services
kubectl get deploy    # deployments
kubectl get ns        # namespaces
kubectl get no        # nodes
# Ressourcen auf Änderungen beobachten
kubectl get pods --watch
kubectl get events --watch
```

### Ressourcenauswahl

Effiziente Wege zur Auswahl und Filterung von Ressourcen.

```bash
# Nach Labels auswählen
kubectl get pods -l app=nginx
kubectl get pods -l 'environment in (prod,staging)'
kubectl get pods -l app=nginx,version!=v1.0
# Nach Feld auswählen
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --field-
selector=spec.nodeName=worker-node-1
# Selektoren kombinieren
kubectl get pods -l app=nginx --field-
selector=status.phase=Running
```

### Ausgabeformatierung

Anpassen der Befehlsausgabe für bessere Lesbarkeit und Verarbeitung.

```bash
# Verschiedene Ausgabeformate
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json
kubectl get pods -o name
# Benutzerdefinierte Spalten
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# JSONPath-Abfragen
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o
jsonpath='{.items[*].spec.containers[*].image}'
```

### Sicherheit & Validierung

Befehle zur Gewährleistung sicherer Operationen und zur Validierung von Konfigurationen.

```bash
# Trockenlauf zur Vorschau von Änderungen
kubectl apply -f deployment.yaml --dry-run=client -o yaml
# Konfiguration validieren
kubectl apply -f deployment.yaml --validate=true --dry-
run=client
# Unterschiede vor dem Anwenden anzeigen
kubectl diff -f deployment.yaml
# Erzwingendes Löschen mit Grace Period
kubectl delete pod  --grace-period=0 --force
```

## Relevante Links

- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/ansible">Ansible Spickzettel</router-link>
- <router-link to="/git">Git Spickzettel</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Spickzettel</router-link>
- <router-link to="/cybersecurity">Cybersecurity Spickzettel</router-link>

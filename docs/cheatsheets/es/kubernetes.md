---
title: 'Lista de Comandos de Kubernetes | LabEx'
description: 'Aprenda orquestación con Kubernetes con esta hoja de trucos completa. Referencia rápida para comandos kubectl, pods, despliegues, servicios, ingress y gestión de contenedores nativos de la nube.'
pdfUrl: '/cheatsheets/pdf/kubernetes-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kubernetes Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/kubernetes">Aprender Kubernetes con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda orquestación de contenedores con Kubernetes a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Kubernetes que cubren comandos esenciales de kubectl, gestión de pods, implementaciones (deployments), servicios, redes y administración de clústeres. Domine la orquestación de contenedores y el despliegue de aplicaciones nativas de la nube.
</base-disclaimer-content>
</base-disclaimer>

## Instalación y Configuración

### Instalar kubectl

Instale la herramienta de línea de comandos de Kubernetes.

```bash
# macOS con Homebrew
brew install kubectl
# Linux (binario oficial)
curl -LO "https://dl.k8s.io/release/$(curl -L -s
https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kube
ctl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
# Windows con Chocolatey
choco install kubernetes-cli
```

### Verificar Instalación

Compruebe la versión de kubectl y la conexión al clúster.

```bash
# Comprobar versión de kubectl
kubectl version --client
# Comprobar versiones del cliente y del servidor
kubectl version
# Obtener información del clúster
kubectl cluster-info
```

### Configurar kubectl

Configure el acceso al clúster y el contexto.

```bash
# Ver configuración actual
kubectl config view
# Listar todos los contextos
kubectl config get-contexts
# Cambiar a un contexto
kubectl config use-context my-cluster
# Establecer el namespace por defecto
kubectl config set-context --current --namespace=my-
namespace
```

### Configuración de Minikube

Clúster local rápido de Kubernetes para desarrollo.

```bash
# Iniciar Minikube
minikube start
# Comprobar estado
minikube status
# Acceder al dashboard
minikube dashboard
# Detener clúster
minikube stop
```

## Comandos Básicos e Información del Clúster

### Información del Clúster: `kubectl cluster-info`

Muestra detalles esenciales del clúster y puntos finales de servicio.

```bash
# Obtener información del clúster
kubectl cluster-info
# Ver configuración del clúster
kubectl config view
# Comprobar recursos de API disponibles
kubectl api-resources
# Mostrar versiones de API soportadas
kubectl api-versions
```

### Gestión de Nodos: `kubectl get nodes`

Ver y gestionar los nodos del clúster.

```bash
# Listar todos los nodos
kubectl get nodes
# Información detallada de los nodos
kubectl get nodes -o wide
# Describir nodo específico
kubectl describe node
# Obtener uso de recursos del nodo
kubectl top nodes
```

### Operaciones de Namespace: `kubectl get namespaces`

Organizar y aislar recursos usando namespaces.

```bash
# Listar todos los namespaces
kubectl get namespaces
# Crear un namespace
kubectl create namespace my-
namespace
# Eliminar un namespace
kubectl delete namespace my-
namespace
# Obtener recursos en un namespace específico
kubectl get all -n my-namespace
```

<BaseQuiz id="kubernetes-namespace-1" correct="B">
  <template #question>
    ¿Cuál es el propósito principal de los namespaces de Kubernetes?
  </template>
  
  <BaseQuizOption value="A">Para mejorar el rendimiento del clúster</BaseQuizOption>
  <BaseQuizOption value="B" correct>Para organizar y aislar recursos dentro de un clúster</BaseQuizOption>
  <BaseQuizOption value="C">Para conectar clústeres entre sí</BaseQuizOption>
  <BaseQuizOption value="D">Para almacenar imágenes de contenedores</BaseQuizOption>
  
  <BaseQuizAnswer>
    Los namespaces proporcionan una forma de dividir los recursos del clúster entre múltiples usuarios o equipos. Ayudan a organizar los recursos y proporcionan un ámbito para los nombres, permitiendo tener recursos con el mismo nombre en diferentes namespaces.
  </BaseQuizAnswer>
</BaseQuiz>

## Gestión de Pods

### Crear y Ejecutar Pods: `kubectl run` / `kubectl create`

Lanzar contenedores y gestionar su ciclo de vida.

```bash
# Ejecutar un pod simple
kubectl run nginx --image=nginx
# Crear pod desde archivo YAML
kubectl create -f pod.yaml
# Ejecutar pod con comando
kubectl run busybox --image=busybox -- echo "Hello
World"
# Crear trabajo (job)
kubectl create job hello --image=busybox:1.28 -- echo
"Hello World"
```

### Ver Información de Pods: `kubectl get pods`

Listar e inspeccionar pods en ejecución.

```bash
# Listar todos los pods en el namespace por defecto
kubectl get pods
# Listar pods con más detalles
kubectl get pods -o wide
# Listar pods en todos los namespaces
kubectl get pods --all-namespaces
# Observar cambios de estado del pod
kubectl get pods --watch
```

<BaseQuiz id="kubernetes-pods-1" correct="C">
  <template #question>
    ¿Qué hace <code>kubectl get pods --all-namespaces</code>?
  </template>
  
  <BaseQuizOption value="A">Lista solo pods en ejecución</BaseQuizOption>
  <BaseQuizOption value="B">Lista pods en el namespace por defecto</BaseQuizOption>
  <BaseQuizOption value="C" correct>Lista pods en todos los namespaces del clúster</BaseQuizOption>
  <BaseQuizOption value="D">Elimina todos los pods</BaseQuizOption>
  
  <BaseQuizAnswer>
    El flag <code>--all-namespaces</code> (o <code>-A</code>) muestra pods de todos los namespaces, no solo del namespace por defecto. Esto es útil para la visibilidad a nivel de clúster.
  </BaseQuizAnswer>
</BaseQuiz>

### Detalles del Pod: `kubectl describe pod`

Obtener información completa sobre pods específicos.

```bash
# Describir un pod específico
kubectl describe pod
# Describir pod en un namespace específico
kubectl describe pod  -n
```

### Operaciones de Pod: `kubectl exec` / `kubectl delete`

Ejecutar comandos en pods y gestionar el ciclo de vida del pod.

```bash
# Obtener logs del pod
kubectl logs
# Seguir logs en tiempo real
kubectl logs -f
# Ejecutar comando en pod
kubectl exec -it  -- /bin/bash
# Ejecutar comando en contenedor específico
kubectl exec -it  -c  -- sh
# Eliminar un pod
kubectl delete pod
# Forzar eliminación de un pod
kubectl delete pod  --grace-period=0 --force
```

## Deployments y ReplicaSets

### Crear Deployments: `kubectl create deployment`

Desplegar y gestionar aplicaciones de forma declarativa.

```bash
# Crear deployment
kubectl create deployment nginx --image=nginx
# Crear deployment con réplicas
kubectl create deployment webapp --image=nginx --
replicas=3
# Crear desde archivo YAML
kubectl apply -f deployment.yaml
# Exponer deployment como servicio
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
```

<BaseQuiz id="kubernetes-deployment-1" correct="A">
  <template #question>
    ¿Cuál es el propósito principal de un Deployment de Kubernetes?
  </template>
  
  <BaseQuizOption value="A" correct>Gestionar y mantener un número deseado de réplicas de pods</BaseQuizOption>
  <BaseQuizOption value="B">Exponer pods al tráfico externo</BaseQuizOption>
  <BaseQuizOption value="C">Almacenar datos de configuración</BaseQuizOption>
  <BaseQuizOption value="D">Gestionar nodos del clúster</BaseQuizOption>
  
  <BaseQuizAnswer>
    Un Deployment gestiona un ReplicaSet, que asegura que se ejecute un número especificado de réplicas de pods. Proporciona actualizaciones declarativas, actualizaciones progresivas (rolling updates) y capacidades de reversión (rollback).
  </BaseQuizAnswer>
</BaseQuiz>

### Gestionar Deployments: `kubectl get deployments`

Ver y controlar el estado y la configuración del deployment.

```bash
# Listar deployments
kubectl get deployments
# Describir deployment
kubectl describe deployment
# Editar deployment
kubectl edit deployment
# Eliminar deployment
kubectl delete deployment
```

### Escalado: `kubectl scale`

Ajustar el número de réplicas en ejecución.

```bash
# Escalar deployment
kubectl scale deployment nginx --replicas=5
# Escalar ReplicaSet
kubectl scale rs  --replicas=3
# Auto-escalar deployment
kubectl autoscale deployment nginx --min=2 --max=10 --
cpu-percent=80
```

<BaseQuiz id="kubernetes-scale-1" correct="B">
  <template #question>
    ¿Qué hace <code>kubectl scale deployment nginx --replicas=5</code>?
  </template>
  
  <BaseQuizOption value="A">Crea 5 nuevos deployments</BaseQuizOption>
  <BaseQuizOption value="B" correct>Escala el deployment nginx para ejecutar 5 réplicas de pods</BaseQuizOption>
  <BaseQuizOption value="C">Elimina 5 pods del deployment</BaseQuizOption>
  <BaseQuizOption value="D">Actualiza la imagen del deployment</BaseQuizOption>
  
  <BaseQuizAnswer>
    El comando <code>scale</code> ajusta el número de réplicas para un deployment. Este comando asegura que el deployment nginx ejecute exactamente 5 réplicas de pods, creando o eliminando pods según sea necesario.
  </BaseQuizAnswer>
</BaseQuiz>

### Actualizaciones Progresivas (Rolling Updates): `kubectl rollout`

Gestionar actualizaciones de despliegue y reversiones.

```bash
# Comprobar estado del rollout
kubectl rollout status deployment/nginx
# Ver historial de rollout
kubectl rollout history deployment/nginx
# Revertir a versión anterior
kubectl rollout undo deployment/nginx
# Revertir a revisión específica
kubectl rollout undo deployment/nginx --to-revision=2
```

## Servicios y Redes

### Exponer Servicios: `kubectl expose`

Hacer que las aplicaciones sean accesibles a través de servicios de red.

```bash
# Exponer deployment como servicio ClusterIP
kubectl expose deployment nginx --port=80
# Exponer como servicio NodePort
kubectl expose deployment nginx --port=80 --
type=NodePort
# Exponer como LoadBalancer
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
# Crear servicio desde YAML
kubectl apply -f service.yaml
```

<BaseQuiz id="kubernetes-service-1" correct="A">
  <template #question>
    ¿Cuál es el tipo de servicio por defecto al usar <code>kubectl expose</code>?
  </template>
  
  <BaseQuizOption value="A" correct>ClusterIP</BaseQuizOption>
  <BaseQuizOption value="B">NodePort</BaseQuizOption>
  <BaseQuizOption value="C">LoadBalancer</BaseQuizOption>
  <BaseQuizOption value="D">ExternalName</BaseQuizOption>
  
  <BaseQuizAnswer>
    ClusterIP es el tipo de servicio por defecto. Expone el servicio en una IP interna del clúster, haciéndolo accesible solo dentro del clúster. Los tipos NodePort y LoadBalancer proporcionan acceso externo.
  </BaseQuizAnswer>
</BaseQuiz>

### Descubrimiento de Servicios: `kubectl get services`

Listar e inspeccionar servicios en su clúster.

```bash
# Listar todos los servicios
kubectl get services
# Listar servicios con más detalles
kubectl get svc -o wide
# Describir servicio específico
kubectl describe service
# Obtener endpoints del servicio
kubectl get endpoints
```

### Reenvío de Puertos (Port Forwarding): `kubectl port-forward`

Acceder a aplicaciones localmente para pruebas y depuración.

```bash
# Reenviar puerto de pod a máquina local
kubectl port-forward pod/ 8080:80
# Reenviar puerto de servicio
kubectl port-forward svc/ 8080:80
# Reenviar puerto de deployment
kubectl port-forward deployment/ 8080:80
# Reenviar múltiples puertos
kubectl port-forward pod/ 8080:80 8443:443
```

### Gestión de Ingress

Gestionar el acceso externo a los servicios a través de rutas HTTP/HTTPS.

```bash
# Listar recursos de ingress
kubectl get ingress
# Describir ingress
kubectl describe ingress
# Crear ingress desde YAML
kubectl apply -f ingress.yaml
```

## ConfigMaps y Secrets

### ConfigMaps: `kubectl create configmap`

Almacenar datos de configuración no confidenciales en pares clave-valor.

```bash
# Crear ConfigMap desde literales
kubectl create configmap app-config --from-
literal=database_url=localhost --from-literal=debug=true
# Crear desde archivo
kubectl create configmap app-config --from-
file=app.properties
# Crear desde directorio
kubectl create configmap app-config --from-file=config/
```

### Uso de ConfigMap

Usar ConfigMaps en pods como variables de entorno o volúmenes.

```bash
# Ver ConfigMap
kubectl get configmaps
kubectl describe configmap app-config
# Obtener YAML de ConfigMap
kubectl get configmap app-config -o yaml
# Editar ConfigMap
kubectl edit configmap app-config
# Eliminar ConfigMap
kubectl delete configmap app-config
```

### Secrets: `kubectl create secret`

Almacenar y gestionar información sensible como contraseñas y claves API.

```bash
# Crear secreto genérico
kubectl create secret generic db-secret --from-
literal=username=admin --from-
literal=password=secret123
# Crear secreto desde archivo
kubectl create secret generic ssl-certs --from-file=tls.crt --
from-file=tls.key
# Crear secreto de registro docker
kubectl create secret docker-registry my-registry --
docker-server=myregistry.com --docker-username=user -
-docker-password=pass
```

### Gestión de Secrets

Ver y gestionar secretos de forma segura.

```bash
# Listar secretos
kubectl get secrets
# Describir secreto (los valores están ocultos)
kubectl describe secret db-secret
# Decodificar valores de secreto
kubectl get secret db-secret -o
jsonpath='{.data.password}' | base64 -d
# Eliminar secreto
kubectl delete secret db-secret
```

## Almacenamiento y Volúmenes

### Persistent Volumes: `kubectl get pv`

Gestionar recursos de almacenamiento a nivel de clúster.

```bash
# Listar persistent volumes
kubectl get pv
# Describir persistent volume
kubectl describe pv
# Crear PV desde YAML
kubectl apply -f persistent-volume.yaml
# Eliminar persistent volume
kubectl delete pv
```

### Persistent Volume Claims: `kubectl get pvc`

Solicitar recursos de almacenamiento para pods.

```bash
# Listar PVCs
kubectl get pvc
# Describir PVC
kubectl describe pvc
# Crear PVC desde YAML
kubectl apply -f pvc.yaml
# Eliminar PVC
kubectl delete pvc
```

### Storage Classes: `kubectl get storageclass`

Definir diferentes tipos de almacenamiento con diversas propiedades.

```bash
# Listar storage classes
kubectl get storageclass
# Describir storage class
kubectl describe storageclass
# Establecer storage class por defecto
kubectl patch storageclass  -p '{"metadata":
{"annotations":{"storageclass.kubernetes.io/is-default-
class":"true"}}}'
```

### Operaciones de Volumen

Trabajar con diferentes tipos de volumen en sus pods.

```bash
# Comprobar montajes de volumen en el pod
kubectl describe pod  | grep -A5 "Mounts:"
# Listar volúmenes en el pod
kubectl get pod  -o yaml | grep -A10 "volumes:"
```

## Solución de Problemas y Depuración

### Logs y Eventos: `kubectl logs` / `kubectl get events`

Examinar logs de aplicaciones y eventos del clúster para depuración.

```bash
# Ver logs del pod
kubectl logs
# Seguir logs en tiempo real
kubectl logs -f
# Ver logs del contenedor anterior
kubectl logs  --previous
# Ver logs de un contenedor específico
kubectl logs  -c
# Ver eventos del clúster
kubectl get events --sort-
by=.metadata.creationTimestamp
```

### Inspección de Recursos: `kubectl describe`

Obtener información detallada sobre cualquier recurso de Kubernetes.

```bash
# Describir pod
kubectl describe pod
# Describir deployment
kubectl describe deployment
# Describir servicio
kubectl describe service
# Describir nodo
kubectl describe node
```

### Uso de Recursos: `kubectl top`

Monitorear el consumo de recursos en pods y nodos.

```bash
# Uso de recursos del nodo
kubectl top nodes
# Uso de recursos del pod
kubectl top pods
# Uso de recursos del pod en namespace
kubectl top pods -n
# Ordenar pods por uso de CPU
kubectl top pods --sort-by=cpu
```

### Depuración Interactiva: `kubectl exec` / `kubectl debug`

Acceder a contenedores en ejecución para solución de problemas práctica.

```bash
# Ejecutar shell interactivo
kubectl exec -it  -- /bin/bash
# Depurar con contenedor efímero (K8s 1.23+)
kubectl debug  -it --image=busybox
# Copiar archivos desde el pod
kubectl cp :/path/to/file ./local-file
# Copiar archivos al pod
kubectl cp ./local-file :/path/to/destination
```

## Gestión de Recursos

### Aplicar Recursos: `kubectl apply`

Crear o actualizar recursos utilizando archivos de configuración declarativos.

```bash
# Aplicar archivo único
kubectl apply -f deployment.yaml
# Aplicar múltiples archivos
kubectl apply -f deployment.yaml -f service.yaml
# Aplicar directorio completo
kubectl apply -f ./k8s-configs/
# Aplicar desde URL
kubectl apply -f https://example.com/manifest.yaml
# Mostrar lo que se aplicaría (dry run)
kubectl apply -f deployment.yaml --dry-run=client -o yaml
```

### Operaciones de Recursos: `kubectl get` / `kubectl delete`

Listar, inspeccionar y eliminar recursos de Kubernetes.

```bash
# Obtener todos los recursos en el namespace
kubectl get all
# Obtener recursos con columnas personalizadas
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase
# Obtener recursos como JSON/YAML
kubectl get deployment nginx -o yaml
kubectl get pod  -o json
# Eliminar recursos
kubectl delete -f deployment.yaml
kubectl delete pod,service -l app=nginx
```

### Edición de Recursos: `kubectl edit` / `kubectl patch`

Modificar recursos existentes directamente.

```bash
# Editar recurso interactivamente
kubectl edit deployment
# Aplicar parche al recurso con merge estratégico
kubectl patch deployment nginx -p '{"spec":
{"replicas":3}}'
# Aplicar parche al recurso con merge JSON
kubectl patch pod  --type='json' -p='[{"op": "replace",
"path": "/metadata/labels/env", "value": "prod"}]'
# Reemplazar recurso completamente
kubectl replace -f updated-deployment.yaml
```

### Validación de Recursos: `kubectl diff` / `kubectl explain`

Comparar configuraciones y entender los esquemas de recursos.

```bash
# Mostrar diferencias antes de aplicar
kubectl diff -f deployment.yaml
# Explicar estructura del recurso
kubectl explain pod.spec.containers
# Explicar con ejemplos
kubectl explain deployment --recursive
# Validar recurso sin aplicar
kubectl apply -f deployment.yaml --dry-run=client --
validate=true
```

## Operaciones Avanzadas

### Gestión de Nodos: `kubectl cordon` / `kubectl drain`

Gestionar la disponibilidad de nodos para mantenimiento y actualizaciones.

```bash
# Marcar nodo como no programable
kubectl cordon
# Marcar nodo como programable
kubectl uncordon
# Drenar nodo para mantenimiento
kubectl drain  --ignore-daemonsets --delete-emptydir-
data
# Añadir taint a nodo
kubectl taint nodes  key=value:NoSchedule
# Eliminar taint de nodo
kubectl taint nodes  key:NoSchedule-
```

### Etiquetado y Anotaciones: `kubectl label` / `kubectl annotate`

Añadir metadatos a recursos para organización y selección.

```bash
# Añadir etiqueta a recurso
kubectl label pod  environment=production
# Eliminar etiqueta de recurso
kubectl label pod  environment-
# Añadir anotación a recurso
kubectl annotate pod  description="Frontend web
server"
# Seleccionar recursos por etiqueta
kubectl get pods -l environment=production
kubectl get pods -l 'environment in (production,staging)'
```

### Proxy y Autenticación: `kubectl proxy` / `kubectl auth`

Acceder a las APIs del clúster y gestionar la autenticación.

```bash
# Iniciar proxy a la API de Kubernetes
kubectl proxy --port=8080
# Comprobar si el usuario puede realizar una acción
kubectl auth can-i create pods
kubectl auth can-i '*' '*' --
as=system:serviceaccount:default:my-sa
# Suplantar usuario
kubectl get pods --as=system:serviceaccount:default:my-
sa
# Ver información de autenticación de usuario
kubectl config view --raw -o jsonpath='{.users[*].name}'
```

### Comandos de Utilidad

Comandos adicionales útiles para operaciones de Kubernetes.

```bash
# Esperar a que se cumpla una condición
kubectl wait --for=condition=Ready pod/ --timeout=300s
# Ejecutar pod temporal para pruebas
kubectl run tmp-pod --rm -i --tty --image=busybox --
/bin/sh
# Generar YAML de recurso sin crear
kubectl create deployment nginx --image=nginx --dry-
run=client -o yaml
# Ordenar recursos por marca de tiempo de creación
kubectl get pods --sort-by=.metadata.creationTimestamp
```

## Rendimiento y Monitoreo

### Métricas de Recursos: `kubectl top`

Ver el uso de recursos en tiempo real en todo el clúster.

```bash
# Uso de recursos del nodo
kubectl top nodes --sort-by=cpu
kubectl top nodes --sort-by=memory
# Uso de recursos del pod
kubectl top pods --sort-by=cpu
kubectl top pods --sort-by=memory -A
# Uso de recursos del contenedor
kubectl top pods --containers=true
# Uso de recursos histórico (requiere metrics-server)
kubectl top pods --previous
```

### Comprobaciones de Estado

Monitorear la salud de la aplicación y del clúster.

```bash
# Comprobar estado del rollout del deployment
kubectl rollout status deployment/
# Comprobar la preparación del pod
kubectl get pods --field-selector=status.phase=Running
# Monitorear cuotas de recursos
kubectl get resourcequota
kubectl describe resourcequota
# Comprobar estado de los componentes del clúster
kubectl get componentstatuses
```

### Optimización del Rendimiento

Comandos para ayudar a optimizar el rendimiento del clúster.

```bash
# Ver peticiones y límites de recursos
kubectl describe node  | grep -A5 "Allocated resources:"
# Comprobar presupuestos de interrupción de pods
kubectl get pdb
# Ver autoscalers horizontales de pods
kubectl get hpa
# Comprobar políticas de red
kubectl get networkpolicy
```

### Copia de Seguridad y Recuperación

Comandos esenciales para la copia de seguridad y recuperación ante desastres del clúster.

```bash
# Copia de seguridad de todos los recursos en el namespace
kubectl get all -o yaml -n  > backup.yaml
# Exportar recurso específico
kubectl get deployment  -o yaml > deployment-
backup.yaml
# Listar todos los recursos para copia de seguridad
kubectl api-resources --verbs=list --namespaced -o name
| xargs -n 1 kubectl get --show-kind --ignore-not-found -n
```

## Gestión de Configuración y Contexto

### Gestión de Contextos

Cambiar entre diferentes clústeres y usuarios de Kubernetes.

```bash
# Ver contexto actual
kubectl config current-context
# Listar todos los contextos
kubectl config get-contexts
# Cambiar contexto
kubectl config use-context
# Crear nuevo contexto
kubectl config set-context dev-
context --cluster=dev-cluster --
user=dev-user --
namespace=development
```

### Gestión de Kubeconfig

Configurar kubectl para trabajar con múltiples clústeres.

```bash
# Ver kubeconfig fusionado
kubectl config view
# Establecer información del clúster
kubectl config set-cluster  --
server=https://cluster-api-url --
certificate-
authority=/path/to/ca.crt
# Establecer credenciales de usuario
kubectl config set-credentials  --
client-
certificate=/path/to/client.crt --
client-key=/path/to/client.key
# Fusionar archivos kubeconfig
KUBECONFIG=~/.kube/config:~/.
kube/config2 kubectl config
view --merge --flatten >
~/.kube/merged-config
```

### Configuración por Defecto

Establecer namespaces y preferencias por defecto para las operaciones de kubectl.

```bash
# Establecer namespace por defecto para el contexto actual
kubectl config set-context --
current --namespace=
# Establecer formato de salida por defecto
kubectl config set-context --
current --output=yaml
# Ver detalles de configuración
kubectl config view -o
jsonpath='{.users[*].name}'
kubectl config view --raw
```

## Mejores Prácticas y Consejos

### Eficiencia de Comandos

Atajos y alias para acelerar las operaciones diarias.

```bash
# Alias comunes de kubectl
alias k=kubectl
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'
# Usar nombres cortos para recursos
kubectl get po        # pods
kubectl get svc       # services
kubectl get deploy    # deployments
kubectl get ns        # namespaces
kubectl get no        # nodes
# Observar recursos para cambios
kubectl get pods --watch
kubectl get events --watch
```

### Selección de Recursos

Formas eficientes de seleccionar y filtrar recursos.

```bash
# Seleccionar por etiquetas
kubectl get pods -l app=nginx
kubectl get pods -l 'environment in (prod,staging)'
kubectl get pods -l app=nginx,version!=v1.0
# Seleccionar por campo
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --field-
selector=spec.nodeName=worker-node-1
# Combinar selectores
kubectl get pods -l app=nginx --field-
selector=status.phase=Running
```

### Formato de Salida

Personalizar la salida del comando para una mejor legibilidad y procesamiento.

```bash
# Diferentes formatos de salida
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json
kubectl get pods -o name
# Columnas personalizadas
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# Consultas JSONPath
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o
jsonpath='{.items[*].spec.containers[*].image}'
```

### Seguridad y Validación

Comandos para asegurar operaciones y validar configuraciones.

```bash
# Dry run para previsualizar cambios
kubectl apply -f deployment.yaml --dry-run=client -o yaml
# Validar configuración
kubectl apply -f deployment.yaml --validate=true --dry-
run=client
# Mostrar diferencias antes de aplicar
kubectl diff -f deployment.yaml
# Eliminación forzada con período de gracia
kubectl delete pod  --grace-period=0 --force
```

## Enlaces Relevantes

- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/shell">Shell Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/ansible">Ansible Cheatsheet</router-link>
- <router-link to="/git">Git Cheatsheet</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Cheatsheet</router-link>
- <router-link to="/cybersecurity">Cybersecurity Cheatsheet</router-link>

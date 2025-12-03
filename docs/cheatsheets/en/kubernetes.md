---
title: 'Kubernetes Cheatsheet | LabEx'
description: 'Learn Kubernetes orchestration with this comprehensive cheatsheet. Quick reference for kubectl commands, pods, deployments, services, ingress, and cloud-native container management.'
pdfUrl: '/cheatsheets/pdf/kubernetes-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kubernetes Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/kubernetes">Learn Kubernetes with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn Kubernetes container orchestration through hands-on labs and real-world scenarios. LabEx provides comprehensive Kubernetes courses covering essential kubectl commands, pod management, deployments, services, networking, and cluster administration. Master container orchestration and cloud-native application deployment.
</base-disclaimer-content>
</base-disclaimer>

## Installation & Setup

### Install kubectl

Install the Kubernetes command-line tool.

```bash
# macOS with Homebrew
brew install kubectl
# Linux (official binary)
curl -LO "https://dl.k8s.io/release/$(curl -L -s
https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kube
ctl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
# Windows with Chocolatey
choco install kubernetes-cli
```

### Verify Installation

Check kubectl version and cluster connection.

```bash
# Check kubectl version
kubectl version --client
# Check both client and server versions
kubectl version
# Get cluster information
kubectl cluster-info
```

### Configure kubectl

Set up cluster access and context.

```bash
# View current config
kubectl config view
# List all contexts
kubectl config get-contexts
# Switch to a context
kubectl config use-context my-cluster
# Set default namespace
kubectl config set-context --current --namespace=my-
namespace
```

### Minikube Setup

Quick local Kubernetes cluster for development.

```bash
# Start Minikube
minikube start
# Check status
minikube status
# Access dashboard
minikube dashboard
# Stop cluster
minikube stop
```

## Basic Commands & Cluster Info

### Cluster Information: `kubectl cluster-info`

Display essential cluster details and service endpoints.

```bash
# Get cluster information
kubectl cluster-info
# Get cluster configuration
kubectl config view
# Check available API resources
kubectl api-resources
# Display supported API versions
kubectl api-versions
```

### Node Management: `kubectl get nodes`

View and manage cluster nodes.

```bash
# List all nodes
kubectl get nodes
# Detailed node information
kubectl get nodes -o wide
# Describe specific node
kubectl describe node
# Get node resource usage
kubectl top nodes
```

### Namespace Operations: `kubectl get namespaces`

Organize and isolate resources using namespaces.

```bash
# List all namespaces
kubectl get namespaces
# Create a namespace
kubectl create namespace my-
namespace
# Delete a namespace
kubectl delete namespace my-
namespace
# Get resources in a specific
namespace
kubectl get all -n my-namespace
```

<BaseQuiz id="kubernetes-namespace-1" correct="B">
  <template #question>
    What is the primary purpose of Kubernetes namespaces?
  </template>
  
  <BaseQuizOption value="A">To improve cluster performance</BaseQuizOption>
  <BaseQuizOption value="B" correct>To organize and isolate resources within a cluster</BaseQuizOption>
  <BaseQuizOption value="C">To connect clusters together</BaseQuizOption>
  <BaseQuizOption value="D">To store container images</BaseQuizOption>
  
  <BaseQuizAnswer>
    Namespaces provide a way to divide cluster resources between multiple users or teams. They help organize resources and provide scope for names, allowing you to have resources with the same name in different namespaces.
  </BaseQuizAnswer>
</BaseQuiz>

## Pod Management

### Create & Run Pods: `kubectl run` / `kubectl create`

Launch containers and manage their lifecycle.

```bash
# Run a simple pod
kubectl run nginx --image=nginx
# Create pod from YAML file
kubectl create -f pod.yaml
# Run pod with command
kubectl run busybox --image=busybox -- echo "Hello
World"
# Create job
kubectl create job hello --image=busybox:1.28 -- echo
"Hello World"
```

### View Pod Information: `kubectl get pods`

List and inspect running pods.

```bash
# List all pods in default namespace
kubectl get pods
# List pods with more details
kubectl get pods -o wide
# List pods in all namespaces
kubectl get pods --all-namespaces
# Watch pod status changes
kubectl get pods --watch
```

<BaseQuiz id="kubernetes-pods-1" correct="C">
  <template #question>
    What does <code>kubectl get pods --all-namespaces</code> do?
  </template>
  
  <BaseQuizOption value="A">Lists only running pods</BaseQuizOption>
  <BaseQuizOption value="B">Lists pods in the default namespace</BaseQuizOption>
  <BaseQuizOption value="C" correct>Lists pods across all namespaces in the cluster</BaseQuizOption>
  <BaseQuizOption value="D">Deletes all pods</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code>--all-namespaces</code> flag (or <code>-A</code>) shows pods from all namespaces, not just the default namespace. This is useful for cluster-wide visibility.
  </BaseQuizAnswer>
</BaseQuiz>

### Pod Details: `kubectl describe pod`

Get comprehensive information about specific pods.

```bash
# Describe a specific pod
kubectl describe pod
# Describe pod in specific namespace
kubectl describe pod  -n
```

### Pod Operations: `kubectl exec` / `kubectl delete`

Execute commands in pods and manage pod lifecycle.

```bash
# Get pod logs
kubectl logs
# Follow logs in real-time
kubectl logs -f
# Execute command in pod
kubectl exec -it  -- /bin/bash
# Execute command in specific container
kubectl exec -it  -c  -- sh
# Delete a pod
kubectl delete pod
# Force delete a pod
kubectl delete pod  --grace-period=0 --force
```

## Deployments & ReplicaSets

### Create Deployments: `kubectl create deployment`

Deploy and manage applications declaratively.

```bash
# Create deployment
kubectl create deployment nginx --image=nginx
# Create deployment with replicas
kubectl create deployment webapp --image=nginx --
replicas=3
# Create from YAML file
kubectl apply -f deployment.yaml
# Expose deployment as service
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
```

<BaseQuiz id="kubernetes-deployment-1" correct="A">
  <template #question>
    What is the main purpose of a Kubernetes Deployment?
  </template>
  
  <BaseQuizOption value="A" correct>To manage and maintain a desired number of pod replicas</BaseQuizOption>
  <BaseQuizOption value="B">To expose pods to external traffic</BaseQuizOption>
  <BaseQuizOption value="C">To store configuration data</BaseQuizOption>
  <BaseQuizOption value="D">To manage cluster nodes</BaseQuizOption>
  
  <BaseQuizAnswer>
    A Deployment manages a ReplicaSet, which ensures a specified number of pod replicas are running. It provides declarative updates, rolling updates, and rollback capabilities.
  </BaseQuizAnswer>
</BaseQuiz>

### Manage Deployments: `kubectl get deployments`

View and control deployment status and configuration.

```bash
# List deployments
kubectl get deployments
# Describe deployment
kubectl describe deployment
# Edit deployment
kubectl edit deployment
# Delete deployment
kubectl delete deployment
```

### Scaling: `kubectl scale`

Adjust the number of running replicas.

```bash
# Scale deployment
kubectl scale deployment nginx --replicas=5
# Scale ReplicaSet
kubectl scale rs  --replicas=3
# Auto-scale deployment
kubectl autoscale deployment nginx --min=2 --max=10 --
cpu-percent=80
```

<BaseQuiz id="kubernetes-scale-1" correct="B">
  <template #question>
    What does <code>kubectl scale deployment nginx --replicas=5</code> do?
  </template>
  
  <BaseQuizOption value="A">Creates 5 new deployments</BaseQuizOption>
  <BaseQuizOption value="B" correct>Scales the nginx deployment to run 5 pod replicas</BaseQuizOption>
  <BaseQuizOption value="C">Deletes 5 pods from the deployment</BaseQuizOption>
  <BaseQuizOption value="D">Updates the deployment image</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code>scale</code> command adjusts the number of replicas for a deployment. This command ensures the nginx deployment runs exactly 5 pod replicas, creating or deleting pods as needed.
  </BaseQuizAnswer>
</BaseQuiz>

### Rolling Updates: `kubectl rollout`

Manage deployment updates and rollbacks.

```bash
# Check rollout status
kubectl rollout status deployment/nginx
# View rollout history
kubectl rollout history deployment/nginx
# Rollback to previous version
kubectl rollout undo deployment/nginx
# Rollback to specific revision
kubectl rollout undo deployment/nginx --to-revision=2
```

## Services & Networking

### Expose Services: `kubectl expose`

Make applications accessible via network services.

```bash
# Expose deployment as ClusterIP service
kubectl expose deployment nginx --port=80
# Expose as NodePort service
kubectl expose deployment nginx --port=80 --
type=NodePort
# Expose as LoadBalancer
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
# Create service from YAML
kubectl apply -f service.yaml
```

<BaseQuiz id="kubernetes-service-1" correct="A">
  <template #question>
    What is the default service type when using <code>kubectl expose</code>?
  </template>
  
  <BaseQuizOption value="A" correct>ClusterIP</BaseQuizOption>
  <BaseQuizOption value="B">NodePort</BaseQuizOption>
  <BaseQuizOption value="C">LoadBalancer</BaseQuizOption>
  <BaseQuizOption value="D">ExternalName</BaseQuizOption>
  
  <BaseQuizAnswer>
    ClusterIP is the default service type. It exposes the service on a cluster-internal IP, making it only accessible within the cluster. NodePort and LoadBalancer types provide external access.
  </BaseQuizAnswer>
</BaseQuiz>

### Service Discovery: `kubectl get services`

List and inspect services in your cluster.

```bash
# List all services
kubectl get services
# List services with more details
kubectl get svc -o wide
# Describe specific service
kubectl describe service
# Get service endpoints
kubectl get endpoints
```

### Port Forwarding: `kubectl port-forward`

Access applications locally for testing and debugging.

```bash
# Forward pod port to local machine
kubectl port-forward pod/ 8080:80
# Forward service port
kubectl port-forward svc/ 8080:80
# Forward deployment port
kubectl port-forward deployment/ 8080:80
# Forward multiple ports
kubectl port-forward pod/ 8080:80 8443:443
```

### Ingress Management

Manage external access to services via HTTP/HTTPS routes.

```bash
# List ingress resources
kubectl get ingress
# Describe ingress
kubectl describe ingress
# Create ingress from YAML
kubectl apply -f ingress.yaml
```

## ConfigMaps & Secrets

### ConfigMaps: `kubectl create configmap`

Store non-confidential configuration data in key-value pairs.

```bash
# Create ConfigMap from literals
kubectl create configmap app-config --from-
literal=database_url=localhost --from-literal=debug=true
# Create from file
kubectl create configmap app-config --from-
file=app.properties
# Create from directory
kubectl create configmap app-config --from-file=config/
```

### ConfigMap Usage

Use ConfigMaps in pods as environment variables or volumes.

```bash
# View ConfigMap
kubectl get configmaps
kubectl describe configmap app-config
# Get ConfigMap YAML
kubectl get configmap app-config -o yaml
# Edit ConfigMap
kubectl edit configmap app-config
# Delete ConfigMap
kubectl delete configmap app-config
```

### Secrets: `kubectl create secret`

Store and manage sensitive information like passwords and API keys.

```bash
# Create generic secret
kubectl create secret generic db-secret --from-
literal=username=admin --from-
literal=password=secret123
# Create secret from file
kubectl create secret generic ssl-certs --from-file=tls.crt --
from-file=tls.key
# Create docker registry secret
kubectl create secret docker-registry my-registry --
docker-server=myregistry.com --docker-username=user -
-docker-password=pass
```

### Secret Management

View and manage secrets securely.

```bash
# List secrets
kubectl get secrets
# Describe secret (values are hidden)
kubectl describe secret db-secret
# Decode secret values
kubectl get secret db-secret -o
jsonpath='{.data.password}' | base64 -d
# Delete secret
kubectl delete secret db-secret
```

## Storage & Volumes

### Persistent Volumes: `kubectl get pv`

Manage cluster-wide storage resources.

```bash
# List persistent volumes
kubectl get pv
# Describe persistent volume
kubectl describe pv
# Create PV from YAML
kubectl apply -f persistent-volume.yaml
# Delete persistent volume
kubectl delete pv
```

### Persistent Volume Claims: `kubectl get pvc`

Request storage resources for pods.

```bash
# List PVCs
kubectl get pvc
# Describe PVC
kubectl describe pvc
# Create PVC from YAML
kubectl apply -f pvc.yaml
# Delete PVC
kubectl delete pvc
```

### Storage Classes: `kubectl get storageclass`

Define different types of storage with various properties.

```bash
# List storage classes
kubectl get storageclass
# Describe storage class
kubectl describe storageclass
# Set default storage class
kubectl patch storageclass  -p '{"metadata":
{"annotations":{"storageclass.kubernetes.io/is-default-
class":"true"}}}'
```

### Volume Operations

Work with different volume types in your pods.

```bash
# Check volume mounts in pod
kubectl describe pod  | grep -A5 "Mounts:"
# List volumes in pod
kubectl get pod  -o yaml | grep -A10 "volumes:"
```

## Troubleshooting & Debugging

### Logs & Events: `kubectl logs` / `kubectl get events`

Examine application logs and cluster events for debugging.

```bash
# View pod logs
kubectl logs
# Follow logs in real-time
kubectl logs -f
# View previous container logs
kubectl logs  --previous
# View logs from specific container
kubectl logs  -c
# View cluster events
kubectl get events --sort-
by=.metadata.creationTimestamp
```

### Resource Inspection: `kubectl describe`

Get detailed information about any Kubernetes resource.

```bash
# Describe pod
kubectl describe pod
# Describe deployment
kubectl describe deployment
# Describe service
kubectl describe service
# Describe node
kubectl describe node
```

### Resource Usage: `kubectl top`

Monitor resource consumption across pods and nodes.

```bash
# View node resource usage
kubectl top nodes
# View pod resource usage
kubectl top pods
# View pod resource usage in namespace
kubectl top pods -n
# Sort pods by CPU usage
kubectl top pods --sort-by=cpu
```

### Interactive Debugging: `kubectl exec` / `kubectl debug`

Access running containers for hands-on troubleshooting.

```bash
# Execute interactive shell
kubectl exec -it  -- /bin/bash
# Debug with ephemeral container (K8s 1.23+)
kubectl debug  -it --image=busybox
# Copy files from pod
kubectl cp :/path/to/file ./local-file
# Copy files to pod
kubectl cp ./local-file :/path/to/destination
```

## Resource Management

### Apply Resources: `kubectl apply`

Create or update resources using declarative configuration files.

```bash
# Apply single file
kubectl apply -f deployment.yaml
# Apply multiple files
kubectl apply -f deployment.yaml -f service.yaml
# Apply entire directory
kubectl apply -f ./k8s-configs/
# Apply from URL
kubectl apply -f https://example.com/manifest.yaml
# Show what would be applied (dry run)
kubectl apply -f deployment.yaml --dry-run=client -o yaml
```

### Resource Operations: `kubectl get` / `kubectl delete`

List, inspect, and remove Kubernetes resources.

```bash
# Get all resources in namespace
kubectl get all
# Get resources with custom columns
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase
# Get resources as JSON/YAML
kubectl get deployment nginx -o yaml
kubectl get pod  -o json
# Delete resources
kubectl delete -f deployment.yaml
kubectl delete pod,service -l app=nginx
```

### Resource Editing: `kubectl edit` / `kubectl patch`

Modify existing resources directly.

```bash
# Edit resource interactively
kubectl edit deployment
# Patch resource with strategic merge
kubectl patch deployment nginx -p '{"spec":
{"replicas":3}}'
# Patch with JSON merge
kubectl patch pod  --type='json' -p='[{"op": "replace",
"path": "/metadata/labels/env", "value": "prod"}]'
# Replace resource entirely
kubectl replace -f updated-deployment.yaml
```

### Resource Validation: `kubectl diff` / `kubectl explain`

Compare configurations and understand resource schemas.

```bash
# Show differences before applying
kubectl diff -f deployment.yaml
# Explain resource structure
kubectl explain pod.spec.containers
# Explain with examples
kubectl explain deployment --recursive
# Validate resource without applying
kubectl apply -f deployment.yaml --dry-run=client --
validate=true
```

## Advanced Operations

### Node Management: `kubectl cordon` / `kubectl drain`

Manage node availability for maintenance and updates.

```bash
# Mark node as unschedulable
kubectl cordon
# Mark node as schedulable
kubectl uncordon
# Drain node for maintenance
kubectl drain  --ignore-daemonsets --delete-emptydir-
data
# Add taint to node
kubectl taint nodes  key=value:NoSchedule
# Remove taint from node
kubectl taint nodes  key:NoSchedule-
```

### Labeling & Annotations: `kubectl label` / `kubectl annotate`

Add metadata to resources for organization and selection.

```bash
# Add label to resource
kubectl label pod  environment=production
# Remove label from resource
kubectl label pod  environment-
# Add annotation to resource
kubectl annotate pod  description="Frontend web
server"
# Select resources by label
kubectl get pods -l environment=production
kubectl get pods -l 'environment in (production,staging)'
```

### Proxy & Authentication: `kubectl proxy` / `kubectl auth`

Access cluster APIs and manage authentication.

```bash
# Start proxy to Kubernetes API
kubectl proxy --port=8080
# Check if user can perform action
kubectl auth can-i create pods
kubectl auth can-i '*' '*' --
as=system:serviceaccount:default:my-sa
# Impersonate user
kubectl get pods --as=system:serviceaccount:default:my-
sa
# View user authentication info
kubectl config view --raw -o jsonpath='{.users[*].name}'
```

### Utility Commands

Additional helpful commands for Kubernetes operations.

```bash
# Wait for condition
kubectl wait --for=condition=Ready pod/ --timeout=300s
# Run temporary pod for testing
kubectl run tmp-pod --rm -i --tty --image=busybox --
/bin/sh
# Generate resource YAML without creating
kubectl create deployment nginx --image=nginx --dry-
run=client -o yaml
# Sort resources by creation time
kubectl get pods --sort-by=.metadata.creationTimestamp
```

## Performance & Monitoring

### Resource Metrics: `kubectl top`

View real-time resource usage across the cluster.

```bash
# Node resource usage
kubectl top nodes --sort-by=cpu
kubectl top nodes --sort-by=memory
# Pod resource usage
kubectl top pods --sort-by=cpu
kubectl top pods --sort-by=memory -A
# Container resource usage
kubectl top pods --containers=true
# Historical resource usage (requires metrics-server)
kubectl top pods --previous
```

### Health Checks & Status

Monitor application and cluster health.

```bash
# Check deployment rollout status
kubectl rollout status deployment/
# Check pod readiness
kubectl get pods --field-selector=status.phase=Running
# Monitor resource quotas
kubectl get resourcequota
kubectl describe resourcequota
# Check cluster component status
kubectl get componentstatuses
```

### Performance Optimization

Commands to help optimize cluster performance.

```bash
# View resource requests and limits
kubectl describe node  | grep -A5 "Allocated resources:"
# Check pod disruption budgets
kubectl get pdb
# View horizontal pod autoscalers
kubectl get hpa
# Check network policies
kubectl get networkpolicy
```

### Backup & Recovery

Essential commands for cluster backup and disaster recovery.

```bash
# Backup all resources in namespace
kubectl get all -o yaml -n  > backup.yaml
# Export specific resource
kubectl get deployment  -o yaml > deployment-
backup.yaml
# List all resources for backup
kubectl api-resources --verbs=list --namespaced -o name
| xargs -n 1 kubectl get --show-kind --ignore-not-found -n
```

## Configuration & Context Management

### Context Management

Switch between different Kubernetes clusters and users.

```bash
# View current context
kubectl config current-context
# List all contexts
kubectl config get-contexts
# Switch context
kubectl config use-context
# Create new context
kubectl config set-context dev-
context --cluster=dev-cluster --
user=dev-user --
namespace=development
```

### Kubeconfig Management

Configure kubectl to work with multiple clusters.

```bash
# View merged kubeconfig
kubectl config view
# Set cluster information
kubectl config set-cluster  --
server=https://cluster-api-url --
certificate-
authority=/path/to/ca.crt
# Set user credentials
kubectl config set-credentials  --
client-
certificate=/path/to/client.crt --
client-key=/path/to/client.key
# Merge kubeconfig files
KUBECONFIG=~/.kube/config:~/.
kube/config2 kubectl config
view --merge --flatten >
~/.kube/merged-config
```

### Default Settings

Set default namespaces and preferences for kubectl operations.

```bash
# Set default namespace for
current context
kubectl config set-context --
current --namespace=
# Set different output format as
default
kubectl config set-context --
current --output=yaml
# View configuration details
kubectl config view -o
jsonpath='{.users[*].name}'
kubectl config view --raw
```

## Best Practices & Tips

### Command Efficiency

Shortcuts and aliases to speed up daily operations.

```bash
# Common kubectl aliases
alias k=kubectl
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'
# Use short names for resources
kubectl get po        # pods
kubectl get svc       # services
kubectl get deploy    # deployments
kubectl get ns        # namespaces
kubectl get no        # nodes
# Watch resources for changes
kubectl get pods --watch
kubectl get events --watch
```

### Resource Selection

Efficient ways to select and filter resources.

```bash
# Select by labels
kubectl get pods -l app=nginx
kubectl get pods -l 'environment in (prod,staging)'
kubectl get pods -l app=nginx,version!=v1.0
# Select by field
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --field-
selector=spec.nodeName=worker-node-1
# Combine selectors
kubectl get pods -l app=nginx --field-
selector=status.phase=Running
```

### Output Formatting

Customize command output for better readability and processing.

```bash
# Different output formats
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json
kubectl get pods -o name
# Custom columns
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# JSONPath queries
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o
jsonpath='{.items[*].spec.containers[*].image}'
```

### Safety & Validation

Commands to ensure safe operations and validate configurations.

```bash
# Dry run to preview changes
kubectl apply -f deployment.yaml --dry-run=client -o yaml
# Validate configuration
kubectl apply -f deployment.yaml --validate=true --dry-
run=client
# Show differences before applying
kubectl diff -f deployment.yaml
# Force delete with grace period
kubectl delete pod  --grace-period=0 --force
```

## Relevant Links

- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/shell">Shell Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/ansible">Ansible Cheatsheet</router-link>
- <router-link to="/git">Git Cheatsheet</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Cheatsheet</router-link>
- <router-link to="/cybersecurity">Cybersecurity Cheatsheet</router-link>

---
title: 'Kubernetes Guia Rápido | LabEx'
description: 'Aprenda orquestração Kubernetes com este guia rápido abrangente. Referência rápida para comandos kubectl, pods, deployments, services, ingress e gerenciamento de contêineres nativos da nuvem.'
pdfUrl: '/cheatsheets/pdf/kubernetes-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kubernetes Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/kubernetes">Aprenda Kubernetes com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda orquestração de contêineres Kubernetes através de laboratórios práticos e cenários do mundo real. O LabEx fornece cursos abrangentes de Kubernetes cobrindo comandos essenciais do kubectl, gerenciamento de pods, implantações, serviços, rede e administração de cluster. Domine a orquestração de contêineres e a implantação de aplicações cloud-native.
</base-disclaimer-content>
</base-disclaimer>

## Instalação e Configuração

### Instalar kubectl

Instale a ferramenta de linha de comando do Kubernetes.

```bash
# macOS com Homebrew
brew install kubectl
# Linux (binário oficial)
curl -LO "https://dl.k8s.io/release/$(curl -L -s
https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kube
ctl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
# Windows com Chocolatey
choco install kubernetes-cli
```

### Verificar Instalação

Verifique a versão do kubectl e a conexão com o cluster.

```bash
# Verificar versão do kubectl
kubectl version --client
# Verificar versões do cliente e do servidor
kubectl version
# Obter informações do cluster
kubectl cluster-info
```

### Configurar kubectl

Configure o acesso ao cluster e o contexto.

```bash
# Visualizar configuração atual
kubectl config view
# Listar todos os contextos
kubectl config get-contexts
# Mudar para um contexto
kubectl config use-context meu-cluster
# Definir namespace padrão
kubectl config set-context --current --namespace=meu-
namespace
```

### Configuração Minikube

Cluster Kubernetes local rápido para desenvolvimento.

```bash
# Iniciar Minikube
minikube start
# Verificar status
minikube status
# Acessar dashboard
minikube dashboard
# Parar cluster
minikube stop
```

## Comandos Básicos e Informações do Cluster

### Informações do Cluster: `kubectl cluster-info`

Exibir detalhes essenciais do cluster e endpoints de serviço.

```bash
# Obter informações do cluster
kubectl cluster-info
# Obter configuração do cluster
kubectl config view
# Verificar recursos da API disponíveis
kubectl api-resources
# Exibir versões da API suportadas
kubectl api-versions
```

### Gerenciamento de Nós: `kubectl get nodes`

Visualizar e gerenciar os nós do cluster.

```bash
# Listar todos os nós
kubectl get nodes
# Informações detalhadas dos nós
kubectl get nodes -o wide
# Descrever nó específico
kubectl describe node
# Obter uso de recursos do nó
kubectl top nodes
```

### Operações de Namespace: `kubectl get namespaces`

Organizar e isolar recursos usando namespaces.

```bash
# Listar todos os namespaces
kubectl get namespaces
# Criar um namespace
kubectl create namespace meu-
namespace
# Excluir um namespace
kubectl delete namespace meu-
namespace
# Obter recursos em um namespace específico
kubectl get all -n meu-namespace
```

<BaseQuiz id="kubernetes-namespace-1" correct="B">
  <template #question>
    Qual é o propósito principal dos namespaces do Kubernetes?
  </template>
  
  <BaseQuizOption value="A">Para melhorar o desempenho do cluster</BaseQuizOption>
  <BaseQuizOption value="B" correct>Para organizar e isolar recursos dentro de um cluster</BaseQuizOption>
  <BaseQuizOption value="C">Para conectar clusters entre si</BaseQuizOption>
  <BaseQuizOption value="D">Para armazenar imagens de contêineres</BaseQuizOption>
  
  <BaseQuizAnswer>
    Namespaces fornecem uma maneira de dividir os recursos do cluster entre vários usuários ou equipes. Eles ajudam a organizar recursos e fornecem escopo para nomes, permitindo que você tenha recursos com o mesmo nome em namespaces diferentes.
  </BaseQuizAnswer>
</BaseQuiz>

## Gerenciamento de Pods

### Criar e Executar Pods: `kubectl run` / `kubectl create`

Iniciar contêineres e gerenciar seu ciclo de vida.

```bash
# Executar um pod simples
kubectl run nginx --image=nginx
# Criar pod a partir de arquivo YAML
kubectl create -f pod.yaml
# Executar pod com comando
kubectl run busybox --image=busybox -- echo "Hello
World"
# Criar job
kubectl create job hello --image=busybox:1.28 -- echo
"Hello World"
```

### Visualizar Informações do Pod: `kubectl get pods`

Listar e inspecionar pods em execução.

```bash
# Listar todos os pods no namespace padrão
kubectl get pods
# Listar pods com mais detalhes
kubectl get pods -o wide
# Listar pods em todos os namespaces
kubectl get pods --all-namespaces
# Observar mudanças de status do pod
kubectl get pods --watch
```

<BaseQuiz id="kubernetes-pods-1" correct="C">
  <template #question>
    O que `kubectl get pods --all-namespaces` faz?
  </template>
  
  <BaseQuizOption value="A">Lista apenas pods em execução</BaseQuizOption>
  <BaseQuizOption value="B">Lista pods no namespace padrão</BaseQuizOption>
  <BaseQuizOption value="C" correct>Lista pods em todos os namespaces do cluster</BaseQuizOption>
  <BaseQuizOption value="D">Exclui todos os pods</BaseQuizOption>
  
  <BaseQuizAnswer>
    O flag `--all-namespaces` (ou `-A`) mostra pods de todos os namespaces, não apenas do namespace padrão. Isso é útil para visibilidade em todo o cluster.
  </BaseQuizAnswer>
</BaseQuiz>

### Detalhes do Pod: `kubectl describe pod`

Obter informações abrangentes sobre pods específicos.

```bash
# Descrever um pod específico
kubectl describe pod
# Descrever pod em namespace específico
kubectl describe pod  -n
```

### Operações de Pod: `kubectl exec` / `kubectl delete`

Executar comandos em pods e gerenciar o ciclo de vida do pod.

```bash
# Obter logs do pod
kubectl logs
# Seguir logs em tempo real
kubectl logs -f
# Executar comando no pod
kubectl exec -it  -- /bin/bash
# Executar comando em contêiner específico
kubectl exec -it  -c  -- sh
# Excluir um pod
kubectl delete pod
# Forçar exclusão de um pod
kubectl delete pod  --grace-period=0 --force
```

## Deployments e ReplicaSets

### Criar Deployments: `kubectl create deployment`

Implantar e gerenciar aplicações de forma declarativa.

```bash
# Criar deployment
kubectl create deployment nginx --image=nginx
# Criar deployment com réplicas
kubectl create deployment webapp --image=nginx --
replicas=3
# Criar a partir de arquivo YAML
kubectl apply -f deployment.yaml
# Expor deployment como serviço
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
```

<BaseQuiz id="kubernetes-deployment-1" correct="A">
  <template #question>
    Qual é o principal propósito de um Deployment do Kubernetes?
  </template>
  
  <BaseQuizOption value="A" correct>Gerenciar e manter um número desejado de réplicas de pod</BaseQuizOption>
  <BaseQuizOption value="B">Expor pods ao tráfego externo</BaseQuizOption>
  <BaseQuizOption value="C">Armazenar dados de configuração</BaseQuizOption>
  <BaseQuizOption value="D">Gerenciar nós do cluster</BaseQuizOption>
  
  <BaseQuizAnswer>
    Um Deployment gerencia um ReplicaSet, que garante que um número especificado de réplicas de pod esteja em execução. Ele fornece atualizações declarativas, atualizações progressivas (rolling updates) e capacidades de rollback.
  </BaseQuizAnswer>
</BaseQuiz>

### Gerenciar Deployments: `kubectl get deployments`

Visualizar e controlar o status e a configuração do deployment.

```bash
# Listar deployments
kubectl get deployments
# Descrever deployment
kubectl describe deployment
# Editar deployment
kubectl edit deployment
# Excluir deployment
kubectl delete deployment
```

### Escalonamento: `kubectl scale`

Ajustar o número de réplicas em execução.

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
    O que `kubectl scale deployment nginx --replicas=5` faz?
  </template>
  
  <BaseQuizOption value="A">Cria 5 novos deployments</BaseQuizOption>
  <BaseQuizOption value="B" correct>Escala o deployment nginx para executar 5 réplicas de pod</BaseQuizOption>
  <BaseQuizOption value="C">Exclui 5 pods do deployment</BaseQuizOption>
  <BaseQuizOption value="D">Atualiza a imagem do deployment</BaseQuizOption>
  
  <BaseQuizAnswer>
    O comando `scale` ajusta o número de réplicas para um deployment. Este comando garante que o deployment nginx execute exatamente 5 réplicas de pod, criando ou excluindo pods conforme necessário.
  </BaseQuizAnswer>
</BaseQuiz>

### Rolling Updates: `kubectl rollout`

Gerenciar atualizações de deployment e rollbacks.

```bash
# Verificar status do rollout
kubectl rollout status deployment/nginx
# Visualizar histórico de rollout
kubectl rollout history deployment/nginx
# Reverter para versão anterior
kubectl rollout undo deployment/nginx
# Reverter para revisão específica
kubectl rollout undo deployment/nginx --to-revision=2
```

## Serviços e Rede

### Expor Serviços: `kubectl expose`

Tornar aplicações acessíveis através de serviços de rede.

```bash
# Expor deployment como serviço ClusterIP
kubectl expose deployment nginx --port=80
# Expor como serviço NodePort
kubectl expose deployment nginx --port=80 --
type=NodePort
# Expor como LoadBalancer
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
# Criar serviço a partir de YAML
kubectl apply -f service.yaml
```

<BaseQuiz id="kubernetes-service-1" correct="A">
  <template #question>
    Qual é o tipo de serviço padrão ao usar `kubectl expose`?
  </template>
  
  <BaseQuizOption value="A" correct>ClusterIP</BaseQuizOption>
  <BaseQuizOption value="B">NodePort</BaseQuizOption>
  <BaseQuizOption value="C">LoadBalancer</BaseQuizOption>
  <BaseQuizOption value="D">ExternalName</BaseQuizOption>
  
  <BaseQuizAnswer>
    ClusterIP é o tipo de serviço padrão. Ele expõe o serviço em um IP interno do cluster, tornando-o acessível apenas dentro do cluster. Os tipos NodePort e LoadBalancer fornecem acesso externo.
  </BaseQuizAnswer>
</BaseQuiz>

### Descoberta de Serviço: `kubectl get services`

Listar e inspecionar serviços no seu cluster.

```bash
# Listar todos os serviços
kubectl get services
# Listar serviços com mais detalhes
kubectl get svc -o wide
# Descrever serviço específico
kubectl describe service
# Obter endpoints do serviço
kubectl get endpoints
```

### Port Forwarding: `kubectl port-forward`

Acessar aplicações localmente para testes e depuração.

```bash
# Encaminhar porta do pod para a máquina local
kubectl port-forward pod/ 8080:80
# Encaminhar porta do serviço
kubectl port-forward svc/ 8080:80
# Encaminhar porta do deployment
kubectl port-forward deployment/ 8080:80
# Encaminhar múltiplas portas
kubectl port-forward pod/ 8080:80 8443:443
```

### Gerenciamento de Ingress

Gerenciar o acesso externo a serviços via rotas HTTP/HTTPS.

```bash
# Listar recursos de ingress
kubectl get ingress
# Descrever ingress
kubectl describe ingress
# Criar ingress a partir de YAML
kubectl apply -f ingress.yaml
```

## ConfigMaps e Secrets

### ConfigMaps: `kubectl create configmap`

Armazenar dados de configuração não confidenciais em pares chave-valor.

```bash
# Criar ConfigMap a partir de literais
kubectl create configmap app-config --from-
literal=database_url=localhost --from-literal=debug=true
# Criar a partir de arquivo
kubectl create configmap app-config --from-
file=app.properties
# Criar a partir de diretório
kubectl create configmap app-config --from-file=config/
```

### Uso de ConfigMap

Usar ConfigMaps em pods como variáveis de ambiente ou volumes.

```bash
# Visualizar ConfigMap
kubectl get configmaps
kubectl describe configmap app-config
# Obter YAML do ConfigMap
kubectl get configmap app-config -o yaml
# Editar ConfigMap
kubectl edit configmap app-config
# Excluir ConfigMap
kubectl delete configmap app-config
```

### Secrets: `kubectl create secret`

Armazenar e gerenciar informações sensíveis como senhas e chaves de API.

```bash
# Criar segredo genérico
kubectl create secret generic db-secret --from-
literal=username=admin --from-
literal=password=secret123
# Criar segredo a partir de arquivo
kubectl create secret generic ssl-certs --from-file=tls.crt --
from-file=tls.key
# Criar segredo de registro docker
kubectl create secret docker-registry my-registry --
docker-server=myregistry.com --docker-username=user -
-docker-password=pass
```

### Gerenciamento de Secrets

Visualizar e gerenciar segredos com segurança.

```bash
# Listar segredos
kubectl get secrets
# Descrever segredo (valores são ocultos)
kubectl describe secret db-secret
# Decodificar valores de segredo
kubectl get secret db-secret -o
jsonpath='{.data.password}' | base64 -d
# Excluir segredo
kubectl delete secret db-secret
```

## Armazenamento e Volumes

### Persistent Volumes: `kubectl get pv`

Gerenciar recursos de armazenamento em todo o cluster.

```bash
# Listar volumes persistentes
kubectl get pv
# Descrever volume persistente
kubectl describe pv
# Criar PV a partir de YAML
kubectl apply -f persistent-volume.yaml
# Excluir volume persistente
kubectl delete pv
```

### Persistent Volume Claims: `kubectl get pvc`

Solicitar recursos de armazenamento para pods.

```bash
# Listar PVCs
kubectl get pvc
# Descrever PVC
kubectl describe pvc
# Criar PVC a partir de YAML
kubectl apply -f pvc.yaml
# Excluir PVC
kubectl delete pvc
```

### Storage Classes: `kubectl get storageclass`

Definir diferentes tipos de armazenamento com várias propriedades.

```bash
# Listar classes de armazenamento
kubectl get storageclass
# Descrever classe de armazenamento
kubectl describe storageclass
# Definir classe de armazenamento padrão
kubectl patch storageclass  -p '{"metadata":
{"annotations":{"storageclass.kubernetes.io/is-default-
class":"true"}}}'
```

### Operações de Volume

Trabalhar com diferentes tipos de volume em seus pods.

```bash
# Verificar montagens de volume no pod
kubectl describe pod  | grep -A5 "Mounts:"
# Listar volumes no pod
kubectl get pod  -o yaml | grep -A10 "volumes:"
```

## Solução de Problemas e Depuração

### Logs e Eventos: `kubectl logs` / `kubectl get events`

Examinar logs de aplicação e eventos do cluster para depuração.

```bash
# Visualizar logs do pod
kubectl logs
# Seguir logs em tempo real
kubectl logs -f
# Visualizar logs do contêiner anterior
kubectl logs  --previous
# Visualizar logs de contêiner específico
kubectl logs  -c
# Visualizar eventos do cluster
kubectl get events --sort-
by=.metadata.creationTimestamp
```

### Inspeção de Recursos: `kubectl describe`

Obter informações detalhadas sobre qualquer recurso do Kubernetes.

```bash
# Descrever pod
kubectl describe pod
# Descrever deployment
kubectl describe deployment
# Descrever serviço
kubectl describe service
# Descrever nó
kubectl describe node
```

### Uso de Recursos: `kubectl top`

Monitorar o consumo de recursos em pods e nós.

```bash
# Uso de recursos do nó
kubectl top nodes --sort-by=cpu
# Uso de recursos do pod
kubectl top pods --sort-by=cpu
# Uso de recursos do pod em namespace
kubectl top pods -n
# Ordenar pods por uso de CPU
kubectl top pods --sort-by=cpu
```

### Depuração Interativa: `kubectl exec` / `kubectl debug`

Acessar contêineres em execução para solução de problemas prática.

```bash
# Executar shell interativo
kubectl exec -it  -- /bin/bash
# Depurar com contêiner efêmero (K8s 1.23+)
kubectl debug  -it --image=busybox
# Copiar arquivos do pod
kubectl cp :/path/to/file ./local-file
# Copiar arquivos para o pod
kubectl cp ./local-file :/path/to/destination
```

## Gerenciamento de Recursos

### Aplicar Recursos: `kubectl apply`

Criar ou atualizar recursos usando arquivos de configuração declarativos.

```bash
# Aplicar arquivo único
kubectl apply -f deployment.yaml
# Aplicar múltiplos arquivos
kubectl apply -f deployment.yaml -f service.yaml
# Aplicar diretório inteiro
kubectl apply -f ./k8s-configs/
# Aplicar a partir de URL
kubectl apply -f https://example.com/manifest.yaml
# Mostrar o que seria aplicado (dry run)
kubectl apply -f deployment.yaml --dry-run=client -o yaml
```

### Operações de Recursos: `kubectl get` / `kubectl delete`

Listar, inspecionar e remover recursos do Kubernetes.

```bash
# Obter todos os recursos no namespace
kubectl get all
# Obter recursos com colunas personalizadas
kubectl get pods -o custom-
columns=NOME:.metadata.name,STATUS:.status.phase
# Obter recursos como JSON/YAML
kubectl get deployment nginx -o yaml
kubectl get pod  -o json
# Excluir recursos
kubectl delete -f deployment.yaml
kubectl delete pod,service -l app=nginx
```

### Edição de Recursos: `kubectl edit` / `kubectl patch`

Modificar recursos existentes diretamente.

```bash
# Editar recurso interativamente
kubectl edit deployment
# Aplicar patch no recurso com merge estratégico
kubectl patch deployment nginx -p '{"spec":
{"replicas":3}}'
# Aplicar patch no recurso com merge JSON
kubectl patch pod  --type='json' -p='[{"op": "replace",
"path": "/metadata/labels/env", "value": "prod"}]'
# Substituir recurso inteiramente
kubectl replace -f updated-deployment.yaml
```

### Validação de Recursos: `kubectl diff` / `kubectl explain`

Comparar configurações e entender esquemas de recursos.

```bash
# Mostrar diferenças antes de aplicar
kubectl diff -f deployment.yaml
# Explicar estrutura do recurso
kubectl explain pod.spec.containers
# Explicar com exemplos
kubectl explain deployment --recursive
# Validar recurso sem aplicar
kubectl apply -f deployment.yaml --dry-run=client --
validate=true
```

## Operações Avançadas

### Gerenciamento de Nós: `kubectl cordon` / `kubectl drain`

Gerenciar a disponibilidade do nó para manutenção e atualizações.

```bash
# Marcar nó como não agendável
kubectl cordon
# Marcar nó como agendável
kubectl uncordon
# Drenar nó para manutenção
kubectl drain  --ignore-daemonsets --delete-emptydir-
data
# Adicionar taint ao nó
kubectl taint nodes  key=value:NoSchedule
# Remover taint do nó
kubectl taint nodes  key:NoSchedule-
```

### Rotulagem e Anotações: `kubectl label` / `kubectl annotate`

Adicionar metadados a recursos para organização e seleção.

```bash
# Adicionar rótulo a recurso
kubectl label pod  environment=production
# Remover rótulo de recurso
kubectl label pod  environment-
# Adicionar anotação a recurso
kubectl annotate pod  description="Frontend web
server"
# Selecionar recursos por rótulo
kubectl get pods -l environment=production
kubectl get pods -l 'environment in (production,staging)'
```

### Proxy e Autenticação: `kubectl proxy` / `kubectl auth`

Acessar APIs do cluster e gerenciar autenticação.

```bash
# Iniciar proxy para API do Kubernetes
kubectl proxy --port=8080
# Verificar se o usuário pode realizar ação
kubectl auth can-i create pods
kubectl auth can-i '*' '*' --
as=system:serviceaccount:default:my-sa
# Impersonar usuário
kubectl get pods --as=system:serviceaccount:default:my-
sa
# Visualizar informações de autenticação do usuário
kubectl config view --raw -o jsonpath='{.users[*].name}'
```

### Comandos de Utilidade

Comandos úteis adicionais para operações do Kubernetes.

```bash
# Esperar por condição
kubectl wait --for=condition=Ready pod/ --timeout=300s
# Executar pod temporário para teste
kubectl run tmp-pod --rm -i --tty --image=busybox --
/bin/sh
# Gerar YAML de recurso sem criar
kubectl create deployment nginx --image=nginx --dry-
run=client -o yaml
# Ordenar recursos por data de criação
kubectl get pods --sort-by=.metadata.creationTimestamp
```

## Desempenho e Monitoramento

### Métricas de Recursos: `kubectl top`

Visualizar o uso de recursos em tempo real em todo o cluster.

```bash
# Uso de recursos do nó
kubectl top nodes --sort-by=cpu
kubectl top nodes --sort-by=memory
# Uso de recursos do pod
kubectl top pods --sort-by=cpu
kubectl top pods --sort-by=memory -A
# Uso de recursos do contêiner
kubectl top pods --containers=true
# Uso de recursos histórico (requer metrics-server)
kubectl top pods --previous
```

### Verificações de Saúde e Status

Monitorar a saúde da aplicação e do cluster.

```bash
# Verificar status do rollout do deployment
kubectl rollout status deployment/
# Verificar prontidão do pod
kubectl get pods --field-selector=status.phase=Running
# Monitorar cotas de recursos
kubectl get resourcequota
kubectl describe resourcequota
# Verificar status dos componentes do cluster
kubectl get componentstatuses
```

### Otimização de Desempenho

Comandos para ajudar a otimizar o desempenho do cluster.

```bash
# Visualizar solicitações e limites de recursos
kubectl describe node  | grep -A5 "Allocated resources:"
# Verificar orçamentos de interrupção de pod
kubectl get pdb
# Visualizar autoscalers de pod horizontal
kubectl get hpa
# Verificar políticas de rede
kubectl get networkpolicy
```

### Backup e Recuperação

Comandos essenciais para backup e recuperação de desastres do cluster.

```bash
# Fazer backup de todos os recursos no namespace
kubectl get all -o yaml -n  > backup.yaml
# Exportar recurso específico
kubectl get deployment  -o yaml > deployment-
backup.yaml
# Listar todos os recursos para backup
kubectl api-resources --verbs=list --namespaced -o name
| xargs -n 1 kubectl get --show-kind --ignore-not-found -n
```

## Gerenciamento de Configuração e Contexto

### Gerenciamento de Contexto

Alternar entre diferentes clusters e usuários do Kubernetes.

```bash
# Visualizar contexto atual
kubectl config current-context
# Listar todos os contextos
kubectl config get-contexts
# Mudar contexto
kubectl config use-context
# Criar novo contexto
kubectl config set-context dev-
context --cluster=dev-cluster --
user=dev-user --
namespace=development
```

### Gerenciamento de Kubeconfig

Configurar o kubectl para funcionar com múltiplos clusters.

```bash
# Visualizar kubeconfig mesclado
kubectl config view
# Definir informações do cluster
kubectl config set-cluster  --
server=https://cluster-api-url --
certificate-
authority=/path/to/ca.crt
# Definir credenciais do usuário
kubectl config set-credentials  --
client-
certificate=/path/to/client.crt --
client-key=/path/to/client.key
# Mesclar arquivos kubeconfig
KUBECONFIG=~/.kube/config:~/.
kube/config2 kubectl config
view --merge --flatten >
~/.kube/merged-config
```

### Configurações Padrão

Definir namespaces e preferências padrão para operações do kubectl.

```bash
# Definir namespace padrão para
contexto atual
kubectl config set-context --
current --namespace=
# Definir formato de saída padrão
kubectl config set-context --
current --output=yaml
# Visualizar detalhes da configuração
kubectl config view -o
jsonpath='{.users[*].name}'
kubectl config view --raw
```

## Melhores Práticas e Dicas

### Eficiência de Comando

Atalhos e aliases para acelerar as operações diárias.

```bash
# Aliases comuns do kubectl
alias k=kubectl
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'
# Usar nomes curtos para recursos
kubectl get po        # pods
kubectl get svc       # services
kubectl get deploy    # deployments
kubectl get ns        # namespaces
kubectl get no        # nodes
# Observar recursos para mudanças
kubectl get pods --watch
kubectl get events --watch
```

### Seleção de Recursos

Maneiras eficientes de selecionar e filtrar recursos.

```bash
# Selecionar por rótulos
kubectl get pods -l app=nginx
kubectl get pods -l 'environment in (prod,staging)'
kubectl get pods -l app=nginx,version!=v1.0
# Selecionar por campo
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --field-
selector=spec.nodeName=worker-node-1
# Combinar seletores
kubectl get pods -l app=nginx --field-
selector=status.phase=Running
```

### Formatação de Saída

Personalizar a saída do comando para melhor legibilidade e processamento.

```bash
# Diferentes formatos de saída
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json
kubectl get pods -o name
# Colunas personalizadas
kubectl get pods -o custom-
columns=NOME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# Consultas JSONPath
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o
jsonpath='{.items[*].spec.containers[*].image}'
```

### Segurança e Validação

Comandos para garantir operações seguras e validar configurações.

```bash
# Dry run para pré-visualizar mudanças
kubectl apply -f deployment.yaml --dry-run=client -o yaml
# Validar configuração
kubectl apply -f deployment.yaml --validate=true --dry-
run=client
# Mostrar diferenças antes de aplicar
kubectl diff -f deployment.yaml
# Excluir forçadamente com período de carência
kubectl delete pod  --grace-period=0 --force
```

## Links Relevantes

- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/shell">Shell Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/ansible">Ansible Cheatsheet</router-link>
- <router-link to="/git">Git Cheatsheet</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Cheatsheet</router-link>
- <router-link to="/cybersecurity">Cybersecurity Cheatsheet</router-link>

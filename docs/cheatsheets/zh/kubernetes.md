---
title: 'Kubernetes 速查表 | LabEx'
description: '使用此综合速查表学习 Kubernetes 编排。kubectl 命令、Pod、部署、服务、Ingress 和云原生容器管理的快速参考。'
pdfUrl: '/cheatsheets/pdf/kubernetes-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kubernetes 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/kubernetes">使用实战实验学习 Kubernetes</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实战实验和真实场景学习 Kubernetes 容器编排。LabEx 提供全面的 Kubernetes 课程，涵盖基本的 kubectl 命令、Pod 管理、部署、服务、网络和集群管理。掌握容器编排和云原生应用部署。
</base-disclaimer-content>
</base-disclaimer>

## 安装与设置

### 安装 kubectl

安装 Kubernetes 命令行工具。

```bash
# 使用 Homebrew (macOS)
brew install kubectl
# Linux (官方二进制文件)
curl -LO "https://dl.k8s.io/release/$(curl -L -s
https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kube
ctl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
# 使用 Chocolatey (Windows)
choco install kubernetes-cli
```

### 验证安装

检查 kubectl 版本和集群连接状态。

```bash
# 检查 kubectl 版本
kubectl version --client
# 检查客户端和服务器版本
kubectl version
# 获取集群信息
kubectl cluster-info
```

### 配置 kubectl

设置集群访问和上下文。

```bash
# 查看当前配置
kubectl config view
# 列出所有上下文
kubectl config get-contexts
# 切换到特定上下文
kubectl config use-context my-cluster
# 设置默认命名空间
kubectl config set-context --current --namespace=my-
namespace
```

### Minikube 设置

用于开发的快速本地 Kubernetes 集群。

```bash
# 启动 Minikube
minikube start
# 检查状态
minikube status
# 访问仪表板
minikube dashboard
# 停止集群
minikube stop
```

## 基本命令与集群信息

### 集群信息：`kubectl cluster-info`

显示基本的集群详细信息和服务端点。

```bash
# 获取集群信息
kubectl cluster-info
# 查看集群配置
kubectl config view
# 检查可用的 API 资源
kubectl api-resources
# 显示支持的 API 版本
kubectl api-versions
```

### 节点管理：`kubectl get nodes`

查看和管理集群节点。

```bash
# 列出所有节点
kubectl get nodes
# 详细的节点信息
kubectl get nodes -o wide
# 描述特定节点
kubectl describe node
# 获取节点资源使用情况
kubectl top nodes
```

### 命名空间操作：`kubectl get namespaces`

使用命名空间组织和隔离资源。

```bash
# 列出所有命名空间
kubectl get namespaces
# 创建一个命名空间
kubectl create namespace my-
namespace
# 删除一个命名空间
kubectl delete namespace my-
namespace
# 获取特定命名空间中的资源
kubectl get all -n my-namespace
```

<BaseQuiz id="kubernetes-namespace-1" correct="B">
  <template #question>
    Kubernetes 命名空间的主要目的是什么？
  </template>
  
  <BaseQuizOption value="A">提高集群性能</BaseQuizOption>
  <BaseQuizOption value="B" correct>在集群内组织和隔离资源</BaseQuizOption>
  <BaseQuizOption value="C">将集群连接在一起</BaseQuizOption>
  <BaseQuizOption value="D">存储容器镜像</BaseQuizOption>
  
  <BaseQuizAnswer>
    命名空间提供了一种在多个用户或团队之间划分集群资源的方式。它们有助于组织资源并为名称提供范围，允许您在不同的命名空间中使用相同名称的资源。
  </BaseQuizAnswer>
</BaseQuiz>

## Pod 管理

### 创建与运行 Pod: `kubectl run` / `kubectl create`

启动容器并管理其生命周期。

```bash
# 运行一个简单的 Pod
kubectl run nginx --image=nginx
# 从 YAML 文件创建 Pod
kubectl create -f pod.yaml
# 使用命令运行 Pod
kubectl run busybox --image=busybox -- echo "Hello
World"
# 创建 Job
kubectl create job hello --image=busybox:1.28 -- echo
"Hello World"
```

### 查看 Pod 信息：`kubectl get pods`

列出和检查正在运行的 Pod。

```bash
# 列出默认命名空间中的所有 Pod
kubectl get pods
# 使用更多细节列出 Pod
kubectl get pods -o wide
# 列出所有命名空间中的 Pod
kubectl get pods --all-namespaces
# 监视 Pod 状态变化
kubectl get pods --watch
```

<BaseQuiz id="kubernetes-pods-1" correct="C">
  <template #question>
    `kubectl get pods --all-namespaces` 的作用是什么？
  </template>
  
  <BaseQuizOption value="A">仅列出正在运行的 Pod</BaseQuizOption>
  <BaseQuizOption value="B">列出默认命名空间中的 Pod</BaseQuizOption>
  <BaseQuizOption value="C" correct>列出集群中所有命名空间中的 Pod</BaseQuizOption>
  <BaseQuizOption value="D">删除所有 Pod</BaseQuizOption>
  
  <BaseQuizAnswer>
    `--all-namespaces` 标志 (或 `-A`) 会显示所有命名空间中的 Pod，而不仅仅是默认命名空间。这对于集群范围的可见性非常有用。
  </BaseQuizAnswer>
</BaseQuiz>

### Pod 详情：`kubectl describe pod`

获取关于特定 Pod 的全面信息。

```bash
# 描述特定 Pod
kubectl describe pod
# 描述特定命名空间中的 Pod
kubectl describe pod  -n
```

### Pod 操作：`kubectl exec` / `kubectl delete`

在 Pod 中执行命令并管理 Pod 生命周期。

```bash
# 获取 Pod 日志
kubectl logs
# 实时跟踪日志
kubectl logs -f
# 在 Pod 中执行命令
kubectl exec -it  -- /bin/bash
# 在特定容器中执行命令
kubectl exec -it  -c  -- sh
# 删除一个 Pod
kubectl delete pod
# 强制删除一个 Pod
kubectl delete pod  --grace-period=0 --force
```

## Deployment 与 ReplicaSet

### 创建 Deployment: `kubectl create deployment`

声明式地部署和管理应用程序。

```bash
# 创建 Deployment
kubectl create deployment nginx --image=nginx
# 创建带有副本数的 Deployment
kubectl create deployment webapp --image=nginx --
replicas=3
# 从 YAML 文件创建
kubectl apply -f deployment.yaml
# 将 Deployment 暴露为 Service
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
```

<BaseQuiz id="kubernetes-deployment-1" correct="A">
  <template #question>
    Kubernetes Deployment 的主要目的是什么？
  </template>
  
  <BaseQuizOption value="A" correct>管理和维护所需数量的 Pod 副本</BaseQuizOption>
  <BaseQuizOption value="B">将 Pod 暴露给外部流量</BaseQuizOption>
  <BaseQuizOption value="C">存储配置数据</BaseQuizOption>
  <BaseQuizOption value="D">管理集群节点</BaseQuizOption>
  
  <BaseQuizAnswer>
    Deployment 管理 ReplicaSet，后者确保指定数量的 Pod 副本正在运行。它提供声明式更新、滚动更新和回滚功能。
  </BaseQuizAnswer>
</BaseQuiz>

### 管理 Deployment: `kubectl get deployments`

查看和控制 Deployment 状态和配置。

```bash
# 列出 Deployment
kubectl get deployments
# 描述 Deployment
kubectl describe deployment
# 编辑 Deployment
kubectl edit deployment
# 删除 Deployment
kubectl delete deployment
```

### 伸缩：`kubectl scale`

调整运行中的副本数量。

```bash
# 伸缩 Deployment
kubectl scale deployment nginx --replicas=5
# 伸缩 ReplicaSet
kubectl scale rs  --replicas=3
# 自动伸缩 Deployment
kubectl autoscale deployment nginx --min=2 --max=10 --
cpu-percent=80
```

<BaseQuiz id="kubernetes-scale-1" correct="B">
  <template #question>
    `kubectl scale deployment nginx --replicas=5` 会执行什么操作？
  </template>
  
  <BaseQuizOption value="A">创建 5 个新的 Deployment</BaseQuizOption>
  <BaseQuizOption value="B" correct>将 nginx Deployment 伸缩到运行 5 个 Pod 副本</BaseQuizOption>
  <BaseQuizOption value="C">从 Deployment 中删除 5 个 Pod</BaseQuizOption>
  <BaseQuizOption value="D">更新 Deployment 镜像</BaseQuizOption>
  
  <BaseQuizAnswer>
    `scale` 命令用于调整 Deployment 的副本数量。此命令确保 nginx Deployment 运行正好 5 个 Pod 副本，根据需要创建或删除 Pod。
  </BaseQuizAnswer>
</BaseQuiz>

### 滚动更新：`kubectl rollout`

管理 Deployment 更新和回滚。

```bash
# 检查滚动更新状态
kubectl rollout status deployment/nginx
# 查看滚动更新历史
kubectl rollout history deployment/nginx
# 回滚到上一个版本
kubectl rollout undo deployment/nginx
# 回滚到特定修订版本
kubectl rollout undo deployment/nginx --to-revision=2
```

## Service 与网络

### 暴露 Service: `kubectl expose`

通过网络服务使应用程序可访问。

```bash
# 将 Deployment 暴露为 ClusterIP Service
kubectl expose deployment nginx --port=80
# 暴露为 NodePort Service
kubectl expose deployment nginx --port=80 --
type=NodePort
# 暴露为 LoadBalancer
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
# 从 YAML 创建 Service
kubectl apply -f service.yaml
```

<BaseQuiz id="kubernetes-service-1" correct="A">
  <template #question>
    使用 `kubectl expose` 时的默认 Service 类型是什么？
  </template>
  
  <BaseQuizOption value="A" correct>ClusterIP</BaseQuizOption>
  <BaseQuizOption value="B">NodePort</BaseQuizOption>
  <BaseQuizOption value="C">LoadBalancer</BaseQuizOption>
  <BaseQuizOption value="D">ExternalName</BaseQuizOption>
  
  <BaseQuizAnswer>
    ClusterIP 是默认的 Service 类型。它在集群内部 IP 上暴露 Service，使其只能在集群内部访问。NodePort 和 LoadBalancer 类型提供外部访问。
  </BaseQuizAnswer>
</BaseQuiz>

### 服务发现：`kubectl get services`

列出和检查集群中的服务。

```bash
# 列出所有 Service
kubectl get services
# 使用更多细节列出 Service
kubectl get svc -o wide
# 描述特定 Service
kubectl describe service
# 获取 Service 端点
kubectl get endpoints
```

### 端口转发：`kubectl port-forward`

在本地机器上访问应用程序以进行测试和调试。

```bash
# 将 Pod 端口转发到本地机器
kubectl port-forward pod/ 8080:80
# 转发 Service 端口
kubectl port-forward svc/ 8080:80
# 转发 Deployment 端口
kubectl port-forward deployment/ 8080:80
# 转发多个端口
kubectl port-forward pod/ 8080:80 8443:443
```

### Ingress 管理

通过 HTTP/HTTPS 路由管理对服务的外部访问。

```bash
# 列出 Ingress 资源
kubectl get ingress
# 描述 Ingress
kubectl describe ingress
# 从 YAML 创建 Ingress
kubectl apply -f ingress.yaml
```

## ConfigMaps 与 Secrets

### ConfigMaps: `kubectl create configmap`

以键值对的形式存储非机密配置数据。

```bash
# 从字面量创建 ConfigMap
kubectl create configmap app-config --from-
literal=database_url=localhost --from-literal=debug=true
# 从文件创建
kubectl create configmap app-config --from-
file=app.properties
# 从目录创建
kubectl create configmap app-config --from-file=config/
```

### ConfigMap 用法

在 Pod 中将 ConfigMaps 作为环境变量或卷使用。

```bash
# 查看 ConfigMap
kubectl get configmaps
kubectl describe configmap app-config
# 获取 ConfigMap YAML
kubectl get configmap app-config -o yaml
# 编辑 ConfigMap
kubectl edit configmap app-config
# 删除 ConfigMap
kubectl delete configmap app-config
```

### Secrets: `kubectl create secret`

存储和管理敏感信息，如密码和 API 密钥。

```bash
# 创建通用 Secret
kubectl create secret generic db-secret --from-
literal=username=admin --from-
literal=password=secret123
# 从文件创建 Secret
kubectl create secret generic ssl-certs --from-file=tls.crt --
from-file=tls.key
# 创建 Docker 注册表 Secret
kubectl create secret docker-registry my-registry --
docker-server=myregistry.com --docker-username=user -
-docker-password=pass
```

### Secret 管理

安全地查看和管理 Secret。

```bash
# 列出 Secret
kubectl get secrets
# 描述 Secret (值被隐藏)
kubectl describe secret db-secret
# 解码 Secret 值
kubectl get secret db-secret -o
jsonpath='{.data.password}' | base64 -d
# 删除 Secret
kubectl delete secret db-secret
```

## 存储与卷

### Persistent Volumes: `kubectl get pv`

管理集群范围的存储资源。

```bash
# 列出持久卷
kubectl get pv
# 描述持久卷
kubectl describe pv
# 从 YAML 创建 PV
kubectl apply -f persistent-volume.yaml
# 删除持久卷
kubectl delete pv
```

### Persistent Volume Claims: `kubectl get pvc`

为 Pod 请求存储资源。

```bash
# 列出 PVC
kubectl get pvc
# 描述 PVC
kubectl describe pvc
# 从 YAML 创建 PVC
kubectl apply -f pvc.yaml
# 删除 PVC
kubectl delete pvc
```

### Storage Classes

定义具有不同属性的不同类型的存储。

```bash
# 列出存储类
kubectl get storageclass
# 描述存储类
kubectl describe storageclass
# 设置默认存储类
kubectl patch storageclass  -p '{"metadata":
{"annotations":{"storageclass.kubernetes.io/is-default-
class":"true"}}}'
```

### 卷操作

在 Pod 中使用不同类型的卷。

```bash
# 检查 Pod 中的卷挂载
kubectl describe pod  | grep -A5 "Mounts:"
# 列出 Pod 中的卷
kubectl get pod  -o yaml | grep -A10 "volumes:"
```

## 故障排除与调试

### 日志与事件：`kubectl logs` / `kubectl get events`

检查应用程序日志和集群事件以进行调试。

```bash
# 查看 Pod 日志
kubectl logs
# 实时跟踪日志
kubectl logs -f
# 查看上一个容器的日志
kubectl logs  --previous
# 查看特定容器的日志
kubectl logs  -c
# 查看集群事件
kubectl get events --sort-
by=.metadata.creationTimestamp
```

### 资源检查：`kubectl describe`

获取关于任何 Kubernetes 资源的详细信息。

```bash
# 描述 Pod
kubectl describe pod
# 描述 Deployment
kubectl describe deployment
# 描述 Service
kubectl describe service
# 描述节点
kubectl describe node
```

### 资源使用率：`kubectl top`

监控集群中 Pod 和节点的资源消耗。

```bash
# 查看节点资源使用情况
kubectl top nodes
# 查看 Pod 资源使用情况
kubectl top pods
# 查看命名空间中的 Pod 资源使用情况
kubectl top pods -n
# 按 CPU 使用率排序 Pod
kubectl top pods --sort-by=cpu
```

### 交互式调试：`kubectl exec` / `kubectl debug`

访问正在运行的容器以进行动手故障排除。

```bash
# 执行交互式 shell
kubectl exec -it  -- /bin/bash
# 使用临时容器进行调试 (K8s 1.23+)
kubectl debug  -it --image=busybox
# 从 Pod 复制文件
kubectl cp :/path/to/file ./local-file
# 复制文件到 Pod
kubectl cp ./local-file :/path/to/destination
```

## 资源管理

### 应用资源：`kubectl apply`

使用声明式配置文件创建或更新资源。

```bash
# 应用单个文件
kubectl apply -f deployment.yaml
# 应用多个文件
kubectl apply -f deployment.yaml -f service.yaml
# 应用整个目录
kubectl apply -f ./k8s-configs/
# 从 URL 应用
kubectl apply -f https://example.com/manifest.yaml
# 显示将要应用的内容 (试运行)
kubectl apply -f deployment.yaml --dry-run=client -o yaml
```

### 资源操作：`kubectl get` / `kubectl delete`

列出、检查和删除 Kubernetes 资源。

```bash
# 获取命名空间中的所有资源
kubectl get all
# 使用自定义列获取资源
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# 以 JSON/YAML 格式获取资源
kubectl get deployment nginx -o yaml
kubectl get pod  -o json
# 删除资源
kubectl delete -f deployment.yaml
kubectl delete pod,service -l app=nginx
```

### 资源编辑：`kubectl edit` / `kubectl patch`

直接修改现有资源。

```bash
# 交互式编辑资源
kubectl edit deployment
# 使用战略合并补丁
kubectl patch deployment nginx -p '{"spec":
{"replicas":3}}'
# 使用 JSON 合并补丁
kubectl patch pod  --type='json' -p='[{"op": "replace",
"path": "/metadata/labels/env", "value": "prod"}]'
# 完全替换资源
kubectl replace -f updated-deployment.yaml
```

### 资源验证：`kubectl diff` / `kubectl explain`

比较配置并理解资源结构。

```bash
# 在应用前显示差异
kubectl diff -f deployment.yaml
# 解释资源结构
kubectl explain pod.spec.containers
# 递归解释
kubectl explain deployment --recursive
# 验证资源而不应用
kubectl apply -f deployment.yaml --dry-run=client --
validate=true
```

## 高级操作

### 节点管理：`kubectl cordon` / `kubectl drain`

管理节点可用性以进行维护和更新。

```bash
# 标记节点为不可调度
kubectl cordon
# 标记节点为可调度
kubectl uncordon
# 疏散节点以进行维护
kubectl drain  --ignore-daemonsets --delete-emptydir-
data
# 向节点添加污点
kubectl taint nodes  key=value:NoSchedule
# 移除节点污点
kubectl taint nodes  key:NoSchedule-
```

### 标签与注解：`kubectl label` / `kubectl annotate`

向资源添加元数据以进行组织和选择。

```bash
# 向资源添加标签
kubectl label pod  environment=production
# 从资源移除标签
kubectl label pod  environment-
# 向资源添加注解
kubectl annotate pod  description="Frontend web
server"
# 按标签选择资源
kubectl get pods -l environment=production
kubectl get pods -l 'environment in (production,staging)'
```

### 代理与认证：`kubectl proxy` / `kubectl auth`

访问集群 API 和管理身份验证。

```bash
# 启动代理访问 Kubernetes API
kubectl proxy --port=8080
# 检查用户是否可以执行操作
kubectl auth can-i create pods
kubectl auth can-i '*' '*' --
as=system:serviceaccount:default:my-sa
# 模拟用户
kubectl get pods --as=system:serviceaccount:default:my-
sa
# 查看用户认证信息
kubectl config view --raw -o jsonpath='{.users[*].name}'
```

### 实用命令

用于 Kubernetes 操作的其他有用命令。

```bash
# 等待条件满足
kubectl wait --for=condition=Ready pod/ --timeout=300s
# 运行临时 Pod 进行测试
kubectl run tmp-pod --rm -i --tty --image=busybox --
/bin/sh
# 在不创建的情况下生成资源 YAML
kubectl create deployment nginx --image=nginx --dry-
run=client -o yaml
# 按创建时间排序资源
kubectl get pods --sort-by=.metadata.creationTimestamp
```

## 性能与监控

### 资源指标：`kubectl top`

查看集群中资源的实时使用情况。

```bash
# 节点资源使用情况
kubectl top nodes --sort-by=cpu
kubectl top nodes --sort-by=memory
# Pod 资源使用情况
kubectl top pods --sort-by=cpu
kubectl top pods --sort-by=memory -A
# 容器资源使用情况
kubectl top pods --containers=true
# 历史资源使用情况 (需要 metrics-server)
kubectl top pods --previous
```

### 健康检查与状态

监控应用程序和集群的健康状况。

```bash
# 检查 Deployment 滚动更新状态
kubectl rollout status deployment/
# 检查 Pod 就绪状态
kubectl get pods --field-selector=status.phase=Running
# 监控资源配额
kubectl get resourcequota
kubectl describe resourcequota
# 检查集群组件状态
kubectl get componentstatuses
```

### 性能优化

帮助优化集群性能的命令。

```bash
# 查看资源请求和限制
kubectl describe node  | grep -A5 "Allocated resources:"
# 检查 Pod 中断预算
kubectl get pdb
# 查看水平 Pod 自动伸缩器
kubectl get hpa
# 检查网络策略
kubectl get networkpolicy
```

### 备份与恢复

集群备份和灾难恢复的基本命令。

```bash
# 备份命名空间中的所有资源
kubectl get all -o yaml -n  > backup.yaml
# 导出特定资源
kubectl get deployment  -o yaml > deployment-
backup.yaml
# 列出所有资源以供备份
kubectl api-resources --verbs=list --namespaced -o name
| xargs -n 1 kubectl get --show-kind --ignore-not-found -n
```

## 配置与上下文管理

### 上下文管理

在不同的 Kubernetes 集群和用户之间切换。

```bash
# 查看当前上下文
kubectl config current-context
# 列出所有上下文
kubectl config get-contexts
# 切换上下文
kubectl config use-context
# 创建新上下文
kubectl config set-context dev-
context --cluster=dev-cluster --
user=dev-user --
namespace=development
```

### Kubeconfig 管理

配置 kubectl 以便与多个集群协同工作。

```bash
# 查看合并后的 kubeconfig
kubectl config view
# 设置集群信息
kubectl config set-cluster  --
server=https://cluster-api-url --
certificate-
authority=/path/to/ca.crt
# 设置用户凭证
kubectl config set-credentials  --
client-
certificate=/path/to/client.crt --
client-key=/path/to/client.key
# 合并 kubeconfig 文件
KUBECONFIG=~/.kube/config:~/.
kube/config2 kubectl config
view --merge --flatten >
~/.kube/merged-config
```

### 默认设置

为 kubectl 操作设置默认命名空间和首选项。

```bash
# 为当前上下文设置默认命名空间
kubectl config set-context --
current --namespace=
# 将不同输出格式设置为默认
kubectl config set-context --
current --output=yaml
# 查看配置详情
kubectl config view -o
jsonpath='{.users[*].name}'
kubectl config view --raw
```

## 最佳实践与技巧

### 命令效率

用于加快日常操作的快捷方式和别名。

```bash
# 常见的 kubectl 别名
alias k=kubectl
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'
# 使用资源的短名称
kubectl get po        # pods
kubectl get svc       # services
kubectl get deploy    # deployments
kubectl get ns        # namespaces
kubectl get no        # nodes
# 监视资源变化
kubectl get pods --watch
kubectl get events --watch
```

### 资源选择

高效选择和过滤资源的方法。

```bash
# 按标签选择
kubectl get pods -l app=nginx
kubectl get pods -l 'environment in (prod,staging)'
kubectl get pods -l app=nginx,version!=v1.0
# 按字段选择
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --field-
selector=spec.nodeName=worker-node-1
# 组合选择器
kubectl get pods -l app=nginx --field-
selector=status.phase=Running
```

### 输出格式化

自定义命令输出以提高可读性和处理性。

```bash
# 不同输出格式
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json
kubectl get pods -o name
# 自定义列
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# JSONPath 查询
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o
jsonpath='{.items[*].spec.containers[*].image}'
```

### 安全与验证

确保安全操作和验证配置的命令。

```bash
# 试运行以预览更改
kubectl apply -f deployment.yaml --dry-run=client -o yaml
# 验证配置
kubectl apply -f deployment.yaml --validate=true --dry-
run=client
# 在应用前显示差异
kubectl diff -f deployment.yaml
# 强制删除，设置宽限期
kubectl delete pod  --grace-period=0 --force
```

## 相关链接

- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/ansible">Ansible 速查表</router-link>
- <router-link to="/git">Git 速查表</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux 速查表</router-link>
- <router-link to="/cybersecurity">网络安全速查表</router-link>

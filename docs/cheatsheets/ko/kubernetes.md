---
title: '쿠버네티스 치트 시트 | LabEx'
description: '이 포괄적인 치트 시트로 쿠버네티스 오케스트레이션을 학습하세요. kubectl 명령어, 파드, 배포, 서비스, 인그레스 및 클라우드 네이티브 컨테이너 관리를 위한 빠른 참조 자료입니다.'
pdfUrl: '/cheatsheets/pdf/kubernetes-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kubernetes 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/kubernetes">Hands-On Labs 로 Kubernetes 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
핸즈온 랩과 실제 시나리오를 통해 Kubernetes 컨테이너 오케스트레이션을 학습하세요. LabEx 는 필수적인 kubectl 명령어, 파드 관리, 배포, 서비스, 네트워킹 및 클러스터 관리를 다루는 포괄적인 Kubernetes 과정을 제공합니다. 컨테이너 오케스트레이션 및 클라우드 네이티브 애플리케이션 배포를 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 설치 및 설정 (Installation & Setup)

### kubectl 설치

Kubernetes 명령줄 도구를 설치합니다.

```bash
# macOS with Homebrew
brew install kubectl
# Linux (공식 바이너리)
curl -LO "https://dl.k8s.io/release/$(curl -L -s
https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kube
ctl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
# Windows with Chocolatey
choco install kubernetes-cli
```

### 설치 확인

kubectl 버전과 클러스터 연결을 확인합니다.

```bash
# kubectl 버전 확인
kubectl version --client
# 클라이언트 및 서버 버전 모두 확인
kubectl version
# 클러스터 정보 가져오기
kubectl cluster-info
```

### kubectl 구성

클러스터 액세스 및 컨텍스트를 설정합니다.

```bash
# 현재 구성 보기
kubectl config view
# 모든 컨텍스트 나열
kubectl config get-contexts
# 컨텍스트 전환
kubectl config use-context my-cluster
# 기본 네임스페이스 설정
kubectl config set-context --current --namespace=my-
namespace
```

### Minikube 설정

개발을 위한 빠른 로컬 Kubernetes 클러스터입니다.

```bash
# Minikube 시작
minikube start
# 상태 확인
minikube status
# 대시보드 액세스
minikube dashboard
# 클러스터 중지
minikube stop
```

## 기본 명령어 및 클러스터 정보 (Basic Commands & Cluster Info)

### 클러스터 정보: `kubectl cluster-info`

필수적인 클러스터 세부 정보 및 서비스 엔드포인트를 표시합니다.

```bash
# 클러스터 정보 가져오기
kubectl cluster-info
# 클러스터 구성 보기
kubectl config view
# 사용 가능한 API 리소스 확인
kubectl api-resources
# 지원되는 API 버전 표시
kubectl api-versions
```

### 노드 관리: `kubectl get nodes`

클러스터 노드를 보고 관리합니다.

```bash
# 모든 노드 나열
kubectl get nodes
# 상세 노드 정보
kubectl get nodes -o wide
# 특정 노드 설명
kubectl describe node
# 노드 리소스 사용량 가져오기
kubectl top nodes
```

### 네임스페이스 작업: `kubectl get namespaces`

네임스페이스를 사용하여 리소스를 구성하고 격리합니다.

```bash
# 모든 네임스페이스 나열
kubectl get namespaces
# 네임스페이스 생성
kubectl create namespace my-
namespace
# 네임스페이스 삭제
kubectl delete namespace my-
namespace
# 특정 네임스페이스의 리소스 가져오기
kubectl get all -n my-namespace
```

<BaseQuiz id="kubernetes-namespace-1" correct="B">
  <template #question>
    Kubernetes 네임스페이스의 주요 목적은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">클러스터 성능 향상</BaseQuizOption>
  <BaseQuizOption value="B" correct>클러스터 내 리소스 구성 및 격리</BaseQuizOption>
  <BaseQuizOption value="C">클러스터 연결</BaseQuizOption>
  <BaseQuizOption value="D">컨테이너 이미지 저장</BaseQuizOption>
  
  <BaseQuizAnswer>
    네임스페이스는 여러 사용자 또는 팀 간에 클러스터 리소스를 분할하는 방법을 제공합니다. 리소스를 구성하고 이름에 대한 범위를 제공하여 서로 다른 네임스페이스에서 동일한 이름을 가진 리소스를 가질 수 있도록 돕습니다.
  </BaseQuizAnswer>
</BaseQuiz>

## 파드 관리 (Pod Management)

### 파드 생성 및 실행: `kubectl run` / `kubectl create`

컨테이너를 시작하고 수명 주기를 관리합니다.

```bash
# 간단한 파드 실행
kubectl run nginx --image=nginx
# YAML 파일에서 파드 생성
kubectl create -f pod.yaml
# 명령어를 사용하여 파드 실행
kubectl run busybox --image=busybox -- echo "Hello
World"
# 작업 생성
kubectl create job hello --image=busybox:1.28 -- echo
"Hello World"
```

### 파드 정보 보기: `kubectl get pods`

실행 중인 파드를 나열하고 검사합니다.

```bash
# 기본 네임스페이스의 모든 파드 나열
kubectl get pods
# 더 자세한 정보로 파드 나열
kubectl get pods -o wide
# 모든 네임스페이스의 파드 나열
kubectl get pods --all-namespaces
# 파드 상태 변경 감시
kubectl get pods --watch
```

<BaseQuiz id="kubernetes-pods-1" correct="C">
  <template #question>
    <code>kubectl get pods --all-namespaces</code>는 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A">실행 중인 파드만 나열</BaseQuizOption>
  <BaseQuizOption value="B">기본 네임스페이스의 파드 나열</BaseQuizOption>
  <BaseQuizOption value="C" correct>클러스터의 모든 네임스페이스에 걸쳐 파드 나열</BaseQuizOption>
  <BaseQuizOption value="D">모든 파드 삭제</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>--all-namespaces</code> 플래그 (또는 <code>-A</code>) 는 기본 네임스페이스뿐만 아니라 모든 네임스페이스의 파드를 표시합니다. 이는 클러스터 전체 가시성에 유용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 파드 세부 정보: `kubectl describe pod`

특정 파드에 대한 포괄적인 정보를 얻습니다.

```bash
# 특정 파드 설명
kubectl describe pod
# 특정 네임스페이스의 파드 설명
kubectl describe pod  -n
```

### 파드 작업: `kubectl exec` / `kubectl delete`

파드 내에서 명령을 실행하고 파드 수명 주기를 관리합니다.

```bash
# 파드 로그 가져오기
kubectl logs
# 실시간으로 로그 추적
kubectl logs -f
# 파드 내에서 명령 실행
kubectl exec -it  -- /bin/bash
# 특정 컨테이너에서 명령 실행
kubectl exec -it  -c  -- sh
# 파드 삭제
kubectl delete pod
# 파드 강제 삭제
kubectl delete pod  --grace-period=0 --force
```

## 배포 및 레플리카셋 (Deployments & ReplicaSets)

### 배포 생성: `kubectl create deployment`

선언적으로 애플리케이션을 배포하고 관리합니다.

```bash
# 배포 생성
kubectl create deployment nginx --image=nginx
# 복제본 수로 배포 생성
kubectl create deployment webapp --image=nginx --
replicas=3
# YAML 파일에서 생성
kubectl apply -f deployment.yaml
# 서비스를 통해 배포 노출
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
```

<BaseQuiz id="kubernetes-deployment-1" correct="A">
  <template #question>
    Kubernetes 배포 (Deployment) 의 주요 목적은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A" correct>원하는 수의 파드 복제본을 관리 및 유지</BaseQuizOption>
  <BaseQuizOption value="B">파드를 외부 트래픽에 노출</BaseQuizOption>
  <BaseQuizOption value="C">구성 데이터 저장</BaseQuizOption>
  <BaseQuizOption value="D">클러스터 노드 관리</BaseQuizOption>
  
  <BaseQuizAnswer>
    배포는 지정된 수의 파드 복제본이 실행되도록 보장하는 ReplicaSet 을 관리합니다. 선언적 업데이트, 롤링 업데이트 및 롤백 기능을 제공합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 배포 관리: `kubectl get deployments`

배포 상태 및 구성을 보고 제어합니다.

```bash
# 배포 나열
kubectl get deployments
# 배포 설명
kubectl describe deployment
# 배포 편집
kubectl edit deployment
# 배포 삭제
kubectl delete deployment
```

### 스케일링: `kubectl scale`

실행 중인 복제본 수를 조정합니다.

```bash
# 배포 스케일 조정
kubectl scale deployment nginx --replicas=5
# 레플리카셋 스케일 조정
kubectl scale rs  --replicas=3
# 배포 자동 스케일 조정
kubectl autoscale deployment nginx --min=2 --max=10 --
cpu-percent=80
```

<BaseQuiz id="kubernetes-scale-1" correct="B">
  <template #question>
    <code>kubectl scale deployment nginx --replicas=5</code>는 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A">새 배포 5 개 생성</BaseQuizOption>
  <BaseQuizOption value="B" correct>nginx 배포를 5 개의 파드 복제본으로 스케일 조정</BaseQuizOption>
  <BaseQuizOption value="C">배포에서 파드 5 개 삭제</BaseQuizOption>
  <BaseQuizOption value="D">배포 이미지 업데이트</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>scale</code> 명령어는 배포의 복제본 수를 조정합니다. 이 명령어는 필요에 따라 파드를 생성하거나 삭제하여 nginx 배포가 정확히 5 개의 파드 복제본을 실행하도록 보장합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 롤링 업데이트: `kubectl rollout`

배포 업데이트 및 롤백을 관리합니다.

```bash
# 배포 롤아웃 상태 확인
kubectl rollout status deployment/nginx
# 롤아웃 기록 보기
kubectl rollout history deployment/nginx
# 이전 버전으로 롤백
kubectl rollout undo deployment/nginx
# 특정 리비전으로 롤백
kubectl rollout undo deployment/nginx --to-revision=2
```

## 서비스 및 네트워킹 (Services & Networking)

### 서비스 노출: `kubectl expose`

네트워크 서비스를 통해 애플리케이션에 대한 액세스를 제공합니다.

```bash
# 배포를 ClusterIP 서비스로 노출
kubectl expose deployment nginx --port=80
# NodePort 서비스로 노출
kubectl expose deployment nginx --port=80 --
type=NodePort
# LoadBalancer로 노출
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
# YAML에서 서비스 생성
kubectl apply -f service.yaml
```

<BaseQuiz id="kubernetes-service-1" correct="A">
  <template #question>
    <code>kubectl expose</code>를 사용할 때 기본 서비스 유형은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A" correct>ClusterIP</BaseQuizOption>
  <BaseQuizOption value="B">NodePort</BaseQuizOption>
  <BaseQuizOption value="C">LoadBalancer</BaseQuizOption>
  <BaseQuizOption value="D">ExternalName</BaseQuizOption>
  
  <BaseQuizAnswer>
    ClusterIP 가 기본 서비스 유형입니다. 이는 클러스터 내부 IP 에서 서비스를 노출하여 클러스터 내에서만 액세스할 수 있도록 합니다. NodePort 및 LoadBalancer 유형은 외부 액세스를 제공합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 서비스 검색: `kubectl get services`

클러스터 내의 서비스를 나열하고 검사합니다.

```bash
# 모든 서비스 나열
kubectl get services
# 더 자세한 정보로 서비스 나열
kubectl get svc -o wide
# 특정 서비스 설명
kubectl describe service
# 서비스 엔드포인트 가져오기
kubectl get endpoints
```

### 포트 포워딩: `kubectl port-forward`

테스트 및 디버깅을 위해 로컬 머신에서 애플리케이션에 액세스합니다.

```bash
# 파드 포트를 로컬 머신으로 포워딩
kubectl port-forward pod/ 8080:80
# 서비스 포트 포워딩
kubectl port-forward svc/ 8080:80
# 배포 포트 포워딩
kubectl port-forward deployment/ 8080:80
# 여러 포트 포워딩
kubectl port-forward pod/ 8080:80 8443:443
```

### Ingress 관리

HTTP/HTTPS 경로를 통해 서비스에 대한 외부 액세스를 관리합니다.

```bash
# ingress 리소스 나열
kubectl get ingress
# ingress 설명
kubectl describe ingress
# YAML에서 ingress 생성
kubectl apply -f ingress.yaml
```

## ConfigMaps 및 Secrets

### ConfigMaps: `kubectl create configmap`

키 - 값 쌍으로 비기밀 구성 데이터를 저장합니다.

```bash
# 리터럴에서 ConfigMap 생성
kubectl create configmap app-config --from-
literal=database_url=localhost --from-literal=debug=true
# 파일에서 생성
kubectl create configmap app-config --from-
file=app.properties
# 디렉토리에서 생성
kubectl create configmap app-config --from-file=config/
```

### ConfigMap 사용

파드에서 환경 변수 또는 볼륨으로 ConfigMap 을 사용합니다.

```bash
# ConfigMap 보기
kubectl get configmaps
kubectl describe configmap app-config
# ConfigMap YAML 가져오기
kubectl get configmap app-config -o yaml
# ConfigMap 편집
kubectl edit configmap app-config
# ConfigMap 삭제
kubectl delete configmap app-config
```

### Secrets: `kubectl create secret`

암호 및 API 키와 같은 민감한 정보를 저장하고 관리합니다.

```bash
# 일반 비밀 생성
kubectl create secret generic db-secret --from-
literal=username=admin --from-
literal=password=secret123
# 파일에서 비밀 생성
kubectl create secret generic ssl-certs --from-file=tls.crt --
from-file=tls.key
# 도커 레지스트리 비밀 생성
kubectl create secret docker-registry my-registry --
docker-server=myregistry.com --docker-username=user -
-docker-password=pass
```

### Secret 관리

비밀을 안전하게 보고 관리합니다.

```bash
# 비밀 나열
kubectl get secrets
# 비밀 설명 (값은 숨겨짐)
kubectl describe secret db-secret
# 비밀 값 디코딩
kubectl get secret db-secret -o
jsonpath='{.data.password}' | base64 -d
# 비밀 삭제
kubectl delete secret db-secret
```

## 스토리지 및 볼륨 (Storage & Volumes)

### 영구 볼륨: `kubectl get pv`

클러스터 전체 스토리지 리소스를 관리합니다.

```bash
# 영구 볼륨 나열
kubectl get pv
# 영구 볼륨 설명
kubectl describe pv
# YAML에서 PV 생성
kubectl apply -f persistent-volume.yaml
# 영구 볼륨 삭제
kubectl delete pv
```

### 영구 볼륨 클레임: `kubectl get pvc`

파드를 위한 스토리지 리소스를 요청합니다.

```bash
# PVC 나열
kubectl get pvc
# PVC 설명
kubectl describe pvc
# YAML에서 PVC 생성
kubectl apply -f pvc.yaml
# PVC 삭제
kubectl delete pvc
```

### 스토리지 클래스: `kubectl get storageclass`

다양한 속성을 가진 스토리지 유형을 정의합니다.

```bash
# 스토리지 클래스 나열
kubectl get storageclass
# 스토리지 클래스 설명
kubectl describe storageclass
# 기본 스토리지 클래스 설정
kubectl patch storageclass  -p '{"metadata":
{"annotations":{"storageclass.kubernetes.io/is-default-
class":"true"}}}'
```

### 볼륨 작업

파드에서 다양한 볼륨 유형 작업

```bash
# 파드에서 볼륨 마운트 확인
kubectl describe pod  | grep -A5 "Mounts:"
# 파드의 볼륨 나열
kubectl get pod  -o yaml | grep -A10 "volumes:"
```

## 문제 해결 및 디버깅 (Troubleshooting & Debugging)

### 로그 및 이벤트: `kubectl logs` / `kubectl get events`

애플리케이션 로그 및 클러스터 이벤트를 검사하여 디버깅합니다.

```bash
# 파드 로그 보기
kubectl logs
# 실시간으로 로그 추적
kubectl logs -f
# 이전 컨테이너 로그 보기
kubectl logs  --previous
# 특정 컨테이너 로그 보기
kubectl logs  -c
# 클러스터 이벤트 보기
kubectl get events --sort-
by=.metadata.creationTimestamp
```

### 리소스 검사: `kubectl describe`

모든 Kubernetes 리소스에 대한 세부 정보를 얻습니다.

```bash
# 파드 설명
kubectl describe pod
# 배포 설명
kubectl describe deployment
# 서비스 설명
kubectl describe service
# 노드 설명
kubectl describe node
```

### 리소스 사용량: `kubectl top`

클러스터 전반의 파드 및 노드에 대한 실시간 리소스 사용량을 모니터링합니다.

```bash
# 노드 리소스 사용량 보기
kubectl top nodes
# 파드 리소스 사용량 보기
kubectl top pods
# 네임스페이스의 파드 리소스 사용량 보기
kubectl top pods -n
# CPU 사용량별 파드 정렬
kubectl top pods --sort-by=cpu
```

### 대화형 디버깅: `kubectl exec` / `kubectl debug`

실행 중인 컨테이너에 액세스하여 수동 문제 해결을 수행합니다.

```bash
# 대화형 셸 액세스
kubectl exec -it  -- /bin/bash
# 임시 컨테이너로 디버깅 (K8s 1.23+)
kubectl debug  -it --image=busybox
# 파드에서 파일 복사
kubectl cp :/path/to/file ./local-file
# 파드로 파일 복사
kubectl cp ./local-file :/path/to/destination
```

## 리소스 관리 (Resource Management)

### 리소스 적용: `kubectl apply`

선언적 구성 파일을 사용하여 리소스를 생성하거나 업데이트합니다.

```bash
# 단일 파일 적용
kubectl apply -f deployment.yaml
# 여러 파일 적용
kubectl apply -f deployment.yaml -f service.yaml
# 전체 디렉토리 적용
kubectl apply -f ./k8s-configs/
# URL에서 적용
kubectl apply -f https://example.com/manifest.yaml
# 적용될 내용 표시 (드라이 런)
kubectl apply -f deployment.yaml --dry-run=client -o yaml
```

### 리소스 작업: `kubectl get` / `kubectl delete`

Kubernetes 리소스를 나열, 검사 및 제거합니다.

```bash
# 네임스페이스의 모든 리소스 가져오기
kubectl get all
# 사용자 지정 열로 리소스 가져오기
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase
# JSON/YAML로 리소스 가져오기
kubectl get deployment nginx -o yaml
kubectl get pod  -o json
# 리소스 삭제
kubectl delete -f deployment.yaml
kubectl delete pod,service -l app=nginx
```

### 리소스 편집: `kubectl edit` / `kubectl patch`

기존 리소스를 직접 수정합니다.

```bash
# 리소스 대화형 편집
kubectl edit deployment
# 전략적 병합으로 리소스 패치
kubectl patch deployment nginx -p '{"spec":
{"replicas":3}}'
# JSON 병합으로 패치
kubectl patch pod  --type='json' -p='[{"op": "replace",
"path": "/metadata/labels/env", "value": "prod"}]'
# 리소스를 완전히 교체
kubectl replace -f updated-deployment.yaml
```

### 리소스 유효성 검사: `kubectl diff` / `kubectl explain`

구성을 비교하고 리소스 스키마를 이해합니다.

```bash
# 적용 전 차이점 표시
kubectl diff -f deployment.yaml
# 리소스 구조 설명
kubectl explain pod.spec.containers
# 예시와 함께 설명
kubectl explain deployment --recursive
# 적용 없이 리소스 유효성 검사
kubectl apply -f deployment.yaml --dry-run=client --
validate=true
```

## 고급 작업 (Advanced Operations)

### 노드 관리: `kubectl cordon` / `kubectl drain`

유지 관리 및 업데이트를 위해 노드 가용성을 관리합니다.

```bash
# 노드를 스케줄링 불가로 표시
kubectl cordon
# 노드를 스케줄링 가능으로 표시
kubectl uncordon
# 유지 관리를 위해 노드 비우기
kubectl drain  --ignore-daemonsets --delete-emptydir-
data
# 노드에 톨(taint) 추가
kubectl taint nodes  key=value:NoSchedule
# 노드에서 톨 제거
kubectl taint nodes  key:NoSchedule-
```

### 레이블 지정 및 주석: `kubectl label` / `kubectl annotate`

리소스에 메타데이터를 추가하여 구성 및 선택을 용이하게 합니다.

```bash
# 리소스에 레이블 추가
kubectl label pod  environment=production
# 리소스에서 레이블 제거
kubectl label pod  environment-
# 리소스에 주석 추가
kubectl annotate pod  description="Frontend web
server"
# 레이블로 리소스 선택
kubectl get pods -l environment=production
kubectl get pods -l 'environment in (production,staging)'
```

### 프록시 및 인증: `kubectl proxy` / `kubectl auth`

클러스터 API 에 액세스하고 인증을 관리합니다.

```bash
# Kubernetes API 프록시 시작
kubectl proxy --port=8080
# 사용자가 작업을 수행할 수 있는지 확인
kubectl auth can-i create pods
kubectl auth can-i '*' '*' --
as=system:serviceaccount:default:my-sa
# 사용자 가장
kubectl get pods --as=system:serviceaccount:default:my-
sa
# 사용자 인증 정보 보기
kubectl config view --raw -o jsonpath='{.users[*].name}'
```

### 유틸리티 명령어

Kubernetes 작업을 위한 추가 유용한 명령어입니다.

```bash
# 조건 대기
kubectl wait --for=condition=Ready pod/ --timeout=300s
# 테스트를 위해 임시 파드 실행
kubectl run tmp-pod --rm -i --tty --image=busybox --
/bin/sh
# 생성 없이 리소스 YAML 생성
kubectl create deployment nginx --image=nginx --dry-
run=client -o yaml
# 생성 타임스탬프별로 리소스 정렬
kubectl get pods --sort-by=.metadata.creationTimestamp
```

## 성능 및 모니터링 (Performance & Monitoring)

### 리소스 메트릭: `kubectl top`

클러스터 전반의 실시간 리소스 사용량을 확인합니다.

```bash
# 노드 리소스 사용량
kubectl top nodes --sort-by=cpu
kubectl top nodes --sort-by=memory
# 파드 리소스 사용량
kubectl top pods --sort-by=cpu
kubectl top pods --sort-by=memory -A
# 컨테이너 리소스 사용량
kubectl top pods --containers=true
# 기록 리소스 사용량 (metrics-server 필요)
kubectl top pods --previous
```

### 상태 확인 및 모니터링

애플리케이션 및 클러스터 상태 모니터링.

```bash
# 배포 롤아웃 상태 확인
kubectl rollout status deployment/
# 파드 준비 상태 확인
kubectl get pods --field-selector=status.phase=Running
# 리소스 쿼터 모니터링
kubectl get resourcequota
kubectl describe resourcequota
# 클러스터 구성 요소 상태 확인
kubectl get componentstatuses
```

### 성능 최적화

클러스터 성능 최적화에 도움이 되는 명령어.

```bash
# 리소스 요청 및 제한 보기
kubectl describe node  | grep -A5 "Allocated resources:"
# 파드 중단 예산 확인
kubectl get pdb
# 수평 파드 자동 스케일러 보기
kubectl get hpa
# 네트워크 정책 확인
kubectl get networkpolicy
```

### 백업 및 복구

클러스터 백업 및 재해 복구를 위한 필수 명령어.

```bash
# 네임스페이스의 모든 리소스 백업
kubectl get all -o yaml -n  > backup.yaml
# 특정 리소스 내보내기
kubectl get deployment  -o yaml > deployment-
backup.yaml
# 백업을 위한 모든 리소스 나열
kubectl api-resources --verbs=list --namespaced -o name
| xargs -n 1 kubectl get --show-kind --ignore-not-found -n
```

## 구성 및 컨텍스트 관리 (Configuration & Context Management)

### 컨텍스트 관리

다양한 Kubernetes 클러스터 및 사용자 간 전환.

```bash
# 현재 컨텍스트 보기
kubectl config current-context
# 모든 컨텍스트 나열
kubectl config get-contexts
# 컨텍스트 전환
kubectl config use-context
# 새 컨텍스트 생성
kubectl config set-context dev-
context --cluster=dev-cluster --
user=dev-user --
namespace=development
```

### Kubeconfig 관리

여러 클러스터에서 kubectl 이 작동하도록 구성합니다.

```bash
# 병합된 kubeconfig 보기
kubectl config view
# 클러스터 정보 설정
kubectl config set-cluster  --
server=https://cluster-api-url --
certificate-
authority=/path/to/ca.crt
# 사용자 자격 증명 설정
kubectl config set-credentials  --
client-
certificate=/path/to/client.crt --
client-key=/path/to/client.key
# kubeconfig 파일 병합
KUBECONFIG=~/.kube/config:~/.
kube/config2 kubectl config
view --merge --flatten >
~/.kube/merged-config
```

### 기본 설정

kubectl 작업에 대한 기본 네임스페이스 및 환경 설정을 설정합니다.

```bash
# 현재 컨텍스트에 대한 기본 네임스페이스 설정
kubectl config set-context --
current --namespace=
# 기본 출력 형식으로 다른 출력 형식 설정
kubectl config set-context --
current --output=yaml
# 구성 세부 정보 보기
kubectl config view -o
jsonpath='{.users[*].name}'
kubectl config view --raw
```

## 모범 사례 및 팁 (Best Practices & Tips)

### 명령어 효율성

일일 작업을 가속화하기 위한 단축키 및 별칭.

```bash
# 일반적인 kubectl 별칭
alias k=kubectl
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'
# 리소스에 대한 짧은 이름 사용
kubectl get po        # pods
kubectl get svc       # services
kubectl get deploy    # deployments
kubectl get ns        # namespaces
kubectl get no        # nodes
# 변경 사항 감시
kubectl get pods --watch
kubectl get events --watch
```

### 리소스 선택

리소스 선택 및 필터링을 위한 효율적인 방법.

```bash
# 레이블로 선택
kubectl get pods -l app=nginx
kubectl get pods -l 'environment in (prod,staging)'
kubectl get pods -l app=nginx,version!=v1.0
# 필드로 선택
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --field-
selector=spec.nodeName=worker-node-1
# 선택기 결합
kubectl get pods -l app=nginx --field-
selector=status.phase=Running
```

### 출력 형식 지정

가독성 및 처리를 위해 명령 출력 사용자 지정.

```bash
# 다른 출력 형식
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json
kubectl get pods -o name
# 사용자 지정 열
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# JSONPath 쿼리
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o
jsonpath='{.items[*].spec.containers[*].image}'
```

### 안전 및 유효성 검사

안전한 작업 및 구성 유효성 검사를 위한 명령어.

```bash
# 변경 사항 미리 보기 (드라이 런)
kubectl apply -f deployment.yaml --dry-run=client -o yaml
# 구성 유효성 검사
kubectl apply -f deployment.yaml --validate=true --dry-
run=client
# 적용 전 차이점 표시
kubectl diff -f deployment.yaml
# 유예 기간을 두고 강제 삭제
kubectl delete pod  --grace-period=0 --force
```

## 관련 링크 (Relevant Links)

- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/ansible">Ansible 치트 시트</router-link>
- <router-link to="/git">Git 치트 시트</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux 치트 시트</router-link>
- <router-link to="/cybersecurity">사이버 보안 치트 시트</router-link>

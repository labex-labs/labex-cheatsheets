---
title: 'Kubernetes チートシート | LabEx'
description: 'この包括的なチートシートで Kubernetes オーケストレーションを学習。kubectl コマンド、Pod、デプロイメント、サービス、Ingress、クラウドネイティブコンテナ管理のクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/kubernetes-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kubernetes チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/kubernetes">ハンズオンラボで Kubernetes を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、Kubernetes コンテナオーケストレーションを学びましょう。LabEx は、必須の kubectl コマンド、Pod 管理、デプロイメント、サービス、ネットワーキング、クラスター管理を網羅した包括的な Kubernetes コースを提供します。コンテナオーケストレーションとクラウドネイティブアプリケーションのデプロイを習得します。
</base-disclaimer-content>
</base-disclaimer>

## インストールとセットアップ

### kubectl のインストール

Kubernetes コマンドラインツールをインストールします。

```bash
# macOS (Homebrew使用)
brew install kubectl
# Linux (公式バイナリ)
curl -LO "https://dl.k8s.io/release/$(curl -L -s
https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kube
ctl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
# Windows (Chocolatey使用)
choco install kubernetes-cli
```

### インストールの確認

kubectl のバージョンとクラスター接続を確認します。

```bash
# kubectlのバージョンを確認
kubectl version --client
# クライアントとサーバーの両方のバージョンを確認
kubectl version
# クラスター情報を取得
kubectl cluster-info
```

### kubectl の設定

クラスターアクセスとコンテキストを設定します。

```bash
# 現在の設定を表示
kubectl config view
# すべてのコンテキストを一覧表示
kubectl config get-contexts
# コンテキストを切り替え
kubectl config use-context my-cluster
# デフォルトネームスペースを設定
kubectl config set-context --current --namespace=my-
namespace
```

### Minikube のセットアップ

開発用のローカル Kubernetes クラスターを素早く立ち上げます。

```bash
# Minikubeを開始
minikube start
# ステータスを確認
minikube status
# ダッシュボードにアクセス
minikube dashboard
# クラスターを停止
minikube stop
```

## 基本コマンドとクラスター情報

### クラスター情報：`kubectl cluster-info`

重要なクラスターの詳細とサービスのエンドポイントを表示します。

```bash
# クラスター情報を取得
kubectl cluster-info
# クラスター設定を取得
kubectl config view
# 利用可能なAPIリソースを確認
kubectl api-resources
# サポートされているAPIバージョンを表示
kubectl api-versions
```

### ノード管理：`kubectl get nodes`

クラスターノードを表示および管理します。

```bash
# すべてのノードを一覧表示
kubectl get nodes
# 詳細なノード情報
kubectl get nodes -o wide
# 特定のノードを記述
kubectl describe node
# ノードのリソース使用量を取得
kubectl top nodes
```

### ネームスペース操作：`kubectl get namespaces`

ネームスペースを使用してクラスターリソースを整理および分離します。

```bash
# すべてのネームスペースを一覧表示
kubectl get namespaces
# ネームスペースを作成
kubectl create namespace my-
namespace
# ネームスペースを削除
kubectl delete namespace my-
namespace
# 特定のネームスペースのリソースを取得
kubectl get all -n my-namespace
```

<BaseQuiz id="kubernetes-namespace-1" correct="B">
  <template #question>
    Kubernetes ネームスペースの主な目的は何ですか？
  </template>
  
  <BaseQuizOption value="A">クラスターパフォーマンスを向上させるため</BaseQuizOption>
  <BaseQuizOption value="B" correct>クラスター内のリソースを整理および分離するため</BaseQuizOption>
  <BaseQuizOption value="C">クラスター同士を接続するため</BaseQuizOption>
  <BaseQuizOption value="D">コンテナイメージを保存するため</BaseQuizOption>
  
  <BaseQuizAnswer>
    ネームスペースは、複数のユーザーまたはチーム間でクラスターリソースを分割する方法を提供します。リソースの整理に役立ち、名前のスコープを提供することで、異なるネームスペースで同じ名前のリソースを持つことができます。
  </BaseQuizAnswer>
</BaseQuiz>

## Pod の管理

### Pod の作成と実行：`kubectl run` / `kubectl create`

コンテナを起動し、そのライフサイクルを管理します。

```bash
# シンプルなPodを実行
kubectl run nginx --image=nginx
# YAMLファイルからPodを作成
kubectl create -f pod.yaml
# コマンド付きでPodを実行
kubectl run busybox --image=busybox -- echo "Hello
World"
# ジョブを作成
kubectl create job hello --image=busybox:1.28 -- echo
"Hello World"
```

### Pod 情報の表示：`kubectl get pods`

実行中の Pod を一覧表示し、検査します。

```bash
# デフォルトネームスペース内のすべてのPodを一覧表示
kubectl get pods
# より詳細なPodを一覧表示
kubectl get pods -o wide
# すべてのネームスペースのPodを一覧表示
kubectl get pods --all-namespaces
# Podの状態変更を監視
kubectl get pods --watch
```

<BaseQuiz id="kubernetes-pods-1" correct="C">
  <template #question>
    `kubectl get pods --all-namespaces`は何をしますか？
  </template>
  
  <BaseQuizOption value="A">実行中の Pod のみを一覧表示する</BaseQuizOption>
  <BaseQuizOption value="B">デフォルトネームスペース内の Pod を一覧表示する</BaseQuizOption>
  <BaseQuizOption value="C" correct>クラスター内のすべてのネームスペースの Pod を一覧表示する</BaseQuizOption>
  <BaseQuizOption value="D">すべての Pod を削除する</BaseQuizOption>
  
  <BaseQuizAnswer>
    `--all-namespaces` フラグ（または `-A`）は、デフォルトネームスペースだけでなく、すべてのネームスペースの Pod を表示します。これはクラスター全体の可視化に役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

### Pod の詳細：`kubectl describe pod`

特定の Pod に関する包括的な情報を取得します。

```bash
# 特定のPodを記述
kubectl describe pod
# 特定のネームスペースのPodを記述
kubectl describe pod  -n
```

### Pod 操作：`kubectl exec` / `kubectl delete`

Pod 内でコマンドを実行し、Pod のライフサイクルを管理します。

```bash
# Podのログを取得
kubectl logs
# リアルタイムでログをフォロー
kubectl logs -f
# Pod内でコマンドを実行
kubectl exec -it  -- /bin/bash
# 特定のコンテナ内でコマンドを実行
kubectl exec -it  -c  -- sh
# Podを削除
kubectl delete pod
# Podを強制削除
kubectl delete pod  --grace-period=0 --force
```

## デプロイメントと ReplicaSet

### デプロイメントの作成：`kubectl create deployment`

宣言的にアプリケーションのデプロイと管理を行います。

```bash
# デプロイメントを作成
kubectl create deployment nginx --image=nginx
# レプリカ数を持つデプロイメントを作成
kubectl create deployment webapp --image=nginx --
replicas=3
# YAMLファイルから作成
kubectl apply -f deployment.yaml
# サービスとしてデプロイメントを公開
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
```

<BaseQuiz id="kubernetes-deployment-1" correct="A">
  <template #question>
    Kubernetes デプロイメントの主な目的は何ですか？
  </template>
  
  <BaseQuizOption value="A" correct>指定された数の Pod レプリカを管理および維持すること</BaseQuizOption>
  <BaseQuizOption value="B">Pod を外部トラフィックに公開すること</BaseQuizOption>
  <BaseQuizOption value="C">設定データを保存すること</BaseQuizOption>
  <BaseQuizOption value="D">クラスターノードを管理すること</BaseQuizOption>
  
  <BaseQuizAnswer>
    デプロイメントは ReplicaSet を管理し、指定された数の Pod レプリカが実行されていることを保証します。宣言的な更新、ローリングアップデート、ロールバック機能を提供します。
  </BaseQuizAnswer>
</BaseQuiz>

### デプロイメントの管理：`kubectl get deployments`

デプロイメントのステータスと設定を表示および制御します。

```bash
# デプロイメントを一覧表示
kubectl get deployments
# デプロイメントを記述
kubectl describe deployment
# デプロイメントを編集
kubectl edit deployment
# デプロイメントを削除
kubectl delete deployment
```

### スケーリング：`kubectl scale`

実行中のレプリカ数を調整します。

```bash
# デプロイメントをスケーリング
kubectl scale deployment nginx --replicas=5
# ReplicaSetをスケーリング
kubectl scale rs  --replicas=3
# デプロイメントを自動スケーリング
kubectl autoscale deployment nginx --min=2 --max=10 --
cpu-percent=80
```

<BaseQuiz id="kubernetes-scale-1" correct="B">
  <template #question>
    `kubectl scale deployment nginx --replicas=5`は何をしますか？
  </template>
  
  <BaseQuizOption value="A">5 つの新しいデプロイメントを作成する</BaseQuizOption>
  <BaseQuizOption value="B" correct>nginx デプロイメントを 5 つの Pod レプリカでスケーリングする</BaseQuizOption>
  <BaseQuizOption value="C">デプロイメントから 5 つの Pod を削除する</BaseQuizOption>
  <BaseQuizOption value="D">デプロイメントイメージを更新する</BaseQuizOption>
  
  <BaseQuizAnswer>
    `scale` コマンドはデプロイメントのレプリカ数を調整します。このコマンドは、nginx デプロイメントが正確に 5 つの Pod レプリカを実行するように保証し、必要に応じて Pod を作成または削除します。
  </BaseQuizAnswer>
</BaseQuiz>

### ローリングアップデート：`kubectl rollout`

デプロイメントの更新とロールバックを管理します。

```bash
# デプロイメントのロールアウトステータスを確認
kubectl rollout status deployment/nginx
# ロールアウト履歴を表示
kubectl rollout history deployment/nginx
# 以前のバージョンにロールバック
kubectl rollout undo deployment/nginx
# 特定のリビジョンにロールバック
kubectl rollout undo deployment/nginx --to-revision=2
```

## サービスとネットワーキング

### サービスの公開：`kubectl expose`

ネットワークサービスを介してアプリケーションへのアクセスを可能にします。

```bash
# デプロイメントをClusterIPサービスとして公開
kubectl expose deployment nginx --port=80
# NodePortサービスとして公開
kubectl expose deployment nginx --port=80 --
type=NodePort
# LoadBalancerとして公開
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
# YAMLからサービスを作成
kubectl apply -f service.yaml
```

<BaseQuiz id="kubernetes-service-1" correct="A">
  <template #question>
    `kubectl expose`を使用した場合のデフォルトのサービスタイプは何ですか？
  </template>
  
  <BaseQuizOption value="A" correct>ClusterIP</BaseQuizOption>
  <BaseQuizOption value="B">NodePort</BaseQuizOption>
  <BaseQuizOption value="C">LoadBalancer</BaseQuizOption>
  <BaseQuizOption value="D">ExternalName</BaseQuizOption>
  
  <BaseQuizAnswer>
    ClusterIP がデフォルトのサービスタイプです。これはサービスをクラスター内部 IP で公開し、クラスター内からのみアクセス可能にします。NodePort および LoadBalancer タイプは外部アクセスを提供します。
  </BaseQuizAnswer>
</BaseQuiz>

### サービスディスカバリ：`kubectl get services`

クラスター内のサービスを一覧表示し、検査します。

```bash
# すべてのサービスを一覧表示
kubectl get services
# より詳細なサービスを一覧表示
kubectl get svc -o wide
# 特定のサービスを記述
kubectl describe service
# サービスのENDPOINTを取得
kubectl get endpoints
```

### ポートフォワーディング：`kubectl port-forward`

テストおよびデバッグのためにローカルマシンからアプリケーションにアクセスします。

```bash
# Podポートをローカルマシンにフォワード
kubectl port-forward pod/ 8080:80
# サービスポートをフォワード
kubectl port-forward svc/ 8080:80
# デプロイメントポートをフォワード
kubectl port-forward deployment/ 8080:80
# 複数のポートをフォワード
kubectl port-forward pod/ 8080:80 8443:443
```

### Ingress の管理

HTTP/HTTPSルートを介したサービスへの外部アクセスを管理します。

```bash
# Ingressリソースを一覧表示
kubectl get ingress
# Ingressを記述
kubectl describe ingress
# YAMLからIngressを作成
kubectl apply -f ingress.yaml
```

## ConfigMap と Secret

### ConfigMap: `kubectl create configmap`

機密性のない設定データをキーと値のペアで保存します。

```bash
# リテラルからConfigMapを作成
kubectl create configmap app-config --from-
literal=database_url=localhost --from-literal=debug=true
# ファイルから作成
kubectl create configmap app-config --from-
file=app.properties
# ディレクトリから作成
kubectl create configmap app-config --from-file=config/
```

### ConfigMap の使用

Pod 内で環境変数またはボリュームとして ConfigMap を使用します。

```bash
# ConfigMapを表示
kubectl get configmaps
kubectl describe configmap app-config
# ConfigMapのYAMLを取得
kubectl get configmap app-config -o yaml
# ConfigMapを編集
kubectl edit configmap app-config
# ConfigMapを削除
kubectl delete configmap app-config
```

### Secret: `kubectl create secret`

パスワードや API キーなどの機密情報を保存および管理します。

```bash
# ジェネリックシークレットを作成
kubectl create secret generic db-secret --from-
literal=username=admin --from-
literal=password=secret123
# ファイルからシークレットを作成
kubectl create secret generic ssl-certs --from-file=tls.crt --
from-file=tls.key
# Dockerレジストリシークレットを作成
kubectl create secret docker-registry my-registry --
docker-server=myregistry.com --docker-username=user -
-docker-password=pass
```

### Secret の管理

シークレットを安全に表示および管理します。

```bash
# シークレットを一覧表示
kubectl get secrets
# シークレットを記述（値は隠されている）
kubectl describe secret db-secret
# シークレットの値をデコード
kubectl get secret db-secret -o
jsonpath='{.data.password}' | base64 -d
# シークレットを削除
kubectl delete secret db-secret
```

## ストレージとボリューム

### Persistent Volume: `kubectl get pv`

クラスター全体のストレージリソースを管理します。

```bash
# Persistent Volumeを一覧表示
kubectl get pv
# Persistent Volumeを記述
kubectl describe pv
# YAMLからPVを作成
kubectl apply -f persistent-volume.yaml
# Persistent Volumeを削除
kubectl delete pv
```

### Persistent Volume Claim: `kubectl get pvc`

Pod 用のストレージリソースを要求します。

```bash
# PVCを一覧表示
kubectl get pvc
# PVCを記述
kubectl describe pvc
# YAMLからPVCを作成
kubectl apply -f pvc.yaml
# PVCを削除
kubectl delete pvc
```

### StorageClass: `kubectl get storageclass`

さまざまなプロパティを持つストレージタイプを定義します。

```bash
# StorageClassを一覧表示
kubectl get storageclass
# StorageClassを記述
kubectl describe storageclass
# デフォルトのStorageClassを設定
kubectl patch storageclass  -p '{"metadata":
{"annotations":{"storageclass.kubernetes.io/is-default-
class":"true"}}}'
```

### ボリューム操作

Pod 内でさまざまなボリュームタイプを操作します。

```bash
# Pod内のボリュームマウントを確認
kubectl describe pod  | grep -A5 "Mounts:"
# Pod内のボリュームを一覧表示
kubectl get pod  -o yaml | grep -A10 "volumes:"
```

## トラブルシューティングとデバッグ

### ログとイベント：`kubectl logs` / `kubectl get events`

デバッグのためにアプリケーションログとクラスターイベントを調べます。

```bash
# Podのログを表示
kubectl logs
# リアルタイムでログをフォロー
kubectl logs -f
# 前回のコンテナのログを表示
kubectl logs  --previous
# 特定のコンテナのログを表示
kubectl logs  -c
# クラスターイベントを表示
kubectl get events --sort-
by=.metadata.creationTimestamp
```

### リソースの検査：`kubectl describe`

任意の Kubernetes リソースに関する詳細情報を取得します。

```bash
# Podを記述
kubectl describe pod
# デプロイメントを記述
kubectl describe deployment
# サービスを記述
kubectl describe service
# ノードを記述
kubectl describe node
```

### リソース使用率：`kubectl top`

クラスター全体の Pod とノードのリソース消費量を監視します。

```bash
# ノードのリソース使用量を確認
kubectl top nodes
# Podのリソース使用量を確認
kubectl top pods
# ネームスペース内のPodのリソース使用量を確認
kubectl top pods -n
# CPU使用率でPodをソート
kubectl top pods --sort-by=cpu
```

### 対話型デバッグ：`kubectl exec` / `kubectl debug`

実行中のコンテナにアクセスして、ハンズオンでのトラブルシューティングを行います。

```bash
# 対話型シェルを実行
kubectl exec -it  -- /bin/bash
# エフェメラルコンテナでデバッグ (K8s 1.23以降)
kubectl debug  -it --image=busybox
# Podからファイルをコピー
kubectl cp :/path/to/file ./local-file
# Podにファイルをコピー
kubectl cp ./local-file :/path/to/destination
```

## リソース管理

### リソースの適用：`kubectl apply`

宣言的な設定ファイルを使用してリソースを作成または更新します。

```bash
# 単一ファイルを適用
kubectl apply -f deployment.yaml
# 複数ファイルを適用
kubectl apply -f deployment.yaml -f service.yaml
# ディレクトリ全体を適用
kubectl apply -f ./k8s-configs/
# URLから適用
kubectl apply -f https://example.com/manifest.yaml
# 適用内容を表示（ドライラン）
kubectl apply -f deployment.yaml --dry-run=client -o yaml
```

### リソース操作：`kubectl get` / `kubectl delete`

Kubernetes リソースを一覧表示、検査、および削除します。

```bash
# ネームスペース内のすべてのリソースを取得
kubectl get all
# カスタム列でリソースを取得
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase
# リソースをJSON/YAMLとして取得
kubectl get deployment nginx -o yaml
kubectl get pod  -o json
# リソースを削除
kubectl delete -f deployment.yaml
kubectl delete pod,service -l app=nginx
```

### リソースの編集：`kubectl edit` / `kubectl patch`

既存のリソースを直接変更します。

```bash
# リソースを対話形式で編集
kubectl edit deployment
# 戦略的マージでリソースをパッチ
kubectl patch deployment nginx -p '{"spec":
{"replicas":3}}'
# JSONマージでパッチ
kubectl patch pod  --type='json' -p='[{"op": "replace",
"path": "/metadata/labels/env", "value": "prod"}]'
# リソース全体を置き換え
kubectl replace -f updated-deployment.yaml
```

### リソースの検証：`kubectl diff` / `kubectl explain`

設定を比較し、リソーススキーマを理解します。

```bash
# 適用前の差分を表示
kubectl diff -f deployment.yaml
# リソース構造を説明
kubectl explain pod.spec.containers
# 例付きで説明
kubectl explain deployment --recursive
# 適用せずにリソースを検証
kubectl apply -f deployment.yaml --dry-run=client --
validate=true
```

## 高度な操作

### ノード管理：`kubectl cordon` / `kubectl drain`

メンテナンスと更新のためにノードの可用性を管理します。

```bash
# ノードをスケジューリング不可としてマーク
kubectl cordon
# ノードをスケジューリング可能としてマーク
kubectl uncordon
# メンテナンスのためにノードをドレイン
kubectl drain  --ignore-daemonsets --delete-emptydir-
data
# ノードにテイントを追加
kubectl taint nodes  key=value:NoSchedule
# ノードからテイントを削除
kubectl taint nodes  key:NoSchedule-
```

### ラベル付けとアノテーション：`kubectl label` / `kubectl annotate`

リソースにメタデータを追加して整理し、選択できるようにします。

```bash
# リソースにラベルを追加
kubectl label pod  environment=production
# リソースからラベルを削除
kubectl label pod  environment-
# リソースにアノテーションを追加
kubectl annotate pod  description="Frontend web
server"
# ラベルでリソースを選択
kubectl get pods -l environment=production
kubectl get pods -l 'environment in (production,staging)'
```

### プロキシと認証：`kubectl proxy` / `kubectl auth`

クラスターAPI へのアクセスと認証の管理を行います。

```bash
# Kubernetes APIへのプロキシを開始
kubectl proxy --port=8080
# ユーザーがアクションを実行できるか確認
kubectl auth can-i create pods
kubectl auth can-i '*' '*' --
as=system:serviceaccount:default:my-sa
# ユーザーをなりすまし
kubectl get pods --as=system:serviceaccount:default:my-
sa
# ユーザー認証情報を表示
kubectl config view --raw -o jsonpath='{.users[*].name}'
```

### ユーティリティコマンド

Kubernetes 操作に役立つ追加のコマンド。

```bash
# 条件を待機
kubectl wait --for=condition=Ready pod/ --timeout=300s
# テスト用に一時的なPodを実行
kubectl run tmp-pod --rm -i --tty --image=busybox --
/bin/sh
# 作成せずにリソースYAMLを生成
kubectl create deployment nginx --image=nginx --dry-
run=client -o yaml
# 作成タイムスタンプでリソースをソート
kubectl get pods --sort-by=.metadata.creationTimestamp
```

## パフォーマンスと監視

### リソースメトリック：`kubectl top`

クラスター全体のリアルタイムのリソース使用状況を表示します。

```bash
# ノードのリソース使用量
kubectl top nodes --sort-by=cpu
kubectl top nodes --sort-by=memory
# Podのリソース使用量
kubectl top pods --sort-by=cpu
kubectl top pods --sort-by=memory -A
# コンテナのリソース使用量
kubectl top pods --containers=true
# 履歴のリソース使用量 (metrics-serverが必要)
kubectl top pods --previous
```

### ヘルスチェックとステータス

アプリケーションとクラスターのヘルスを監視します。

```bash
# デプロイメントのロールアウトステータスを確認
kubectl rollout status deployment/
# Podの準備完了状態を確認
kubectl get pods --field-selector=status.phase=Running
# リソースクォータを監視
kubectl get resourcequota
kubectl describe resourcequota
# クラスターコンポーネントのステータスを確認
kubectl get componentstatuses
```

### パフォーマンス最適化

クラスターのパフォーマンス最適化に役立つコマンド。

```bash
# リソースのリクエストと制限を表示
kubectl describe node  | grep -A5 "Allocated resources:"
# Pod Disruption Budgetを確認
kubectl get pdb
# Horizontal Pod Autoscalerを確認
kubectl get hpa
# ネットワークポリシーを確認
kubectl get networkpolicy
```

### バックアップとリカバリ

クラスターのバックアップと災害復旧のための必須コマンド。

```bash
# ネームスペース内のすべてのリソースをバックアップ
kubectl get all -o yaml -n  > backup.yaml
# 特定のリソースをエクスポート
kubectl get deployment  -o yaml > deployment-
backup.yaml
# バックアップ用のすべてのリソース名を一覧表示
kubectl api-resources --verbs=list --namespaced -o name
| xargs -n 1 kubectl get --show-kind --ignore-not-found -n
```

## 設定とコンテキスト管理

### コンテキスト管理

異なる Kubernetes クラスターとユーザーを切り替えます。

```bash
# 現在のコンテキストを表示
kubectl config current-context
# すべてのコンテキストを一覧表示
kubectl config get-contexts
# コンテキストを切り替え
kubectl config use-context
# 新しいコンテキストを作成
kubectl config set-context dev-
context --cluster=dev-cluster --
user=dev-user --
namespace=development
```

### Kubeconfig 管理

複数のクラスターで kubectl が動作するように設定します。

```bash
# マージされたkubeconfigを表示
kubectl config view
# クラスター情報を設定
kubectl config set-cluster  --
server=https://cluster-api-url --
certificate-
authority=/path/to/ca.crt
# ユーザー認証情報を設定
kubectl config set-credentials  --
client-
certificate=/path/to/client.crt --
client-key=/path/to/client.key
# kubeconfigファイルをマージ
KUBECONFIG=~/.kube/config:~/.
kube/config2 kubectl config
view --merge --flatten >
~/.kube/merged-config
```

### デフォルト設定

kubectl 操作のデフォルトのネームスペースと環境設定を行います。

```bash
# 現在のコンテキストのデフォルトネームスペースを設定
kubectl config set-context --
current --namespace=
# デフォルトの出力形式を設定
kubectl config set-context --
current --output=yaml
# 設定の詳細を表示
kubectl config view -o
jsonpath='{.users[*].name}'
kubectl config view --raw
```

## ベストプラクティスとヒント

### コマンド効率化

日々の操作を高速化するためのショートカットとエイリアス。

```bash
# 一般的なkubectlエイリアス
alias k=kubectl
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'
# リソースの短縮名を使用
kubectl get po        # pods
kubectl get svc       # services
kubectl get deploy    # deployments
kubectl get ns        # namespaces
kubectl get no        # nodes
# 変更を監視
kubectl get pods --watch
kubectl get events --watch
```

### リソース選択

リソースを選択しフィルタリングするための効率的な方法。

```bash
# ラベルで選択
kubectl get pods -l app=nginx
kubectl get pods -l 'environment in (prod,staging)'
kubectl get pods -l app=nginx,version!=v1.0
# フィールドで選択
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --field-
selector=spec.nodeName=worker-node-1
# セレクターの組み合わせ
kubectl get pods -l app=nginx --field-
selector=status.phase=Running
```

### 出力形式

読みやすさや処理のためにコマンド出力をカスタマイズします。

```bash
# 異なる出力形式
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json
kubectl get pods -o name
# カスタム列
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# JSONPathクエリ
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o
jsonpath='{.items[*].spec.containers[*].image}'
```

### 安全性と検証

安全な操作と設定の検証のためのコマンド。

```bash
# 変更をプレビューするためのドライラン
kubectl apply -f deployment.yaml --dry-run=client -o yaml
# 設定の検証
kubectl apply -f deployment.yaml --validate=true --dry-
run=client
# 適用前の差分を表示
kubectl diff -f deployment.yaml
# グレース期間を指定して強制削除
kubectl delete pod  --grace-period=0 --force
```

## 関連リンク

- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/ansible">Ansible チートシート</router-link>
- <router-link to="/git">Git チートシート</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux チートシート</router-link>
- <router-link to="/cybersecurity">サイバーセキュリティ チートシート</router-link>

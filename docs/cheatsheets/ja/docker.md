---
title: 'Docker チートシート'
description: '必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートで Docker を習得しましょう。'
pdfUrl: '/cheatsheets/pdf/docker-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Docker チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/docker">ハンズオンラボで Docker を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと現実世界のシナリオを通じて、Docker コンテナ化を学びます。LabEx は、必須のコンテナ管理、イメージビルド、Docker Compose、ネットワーキング、ボリューム、デプロイメントを網羅した包括的な Docker コースを提供します。コンテナオーケストレーションと最新のアプリケーションデプロイメント技術を習得しましょう。
</base-disclaimer-content>
</base-disclaimer>

## インストールとセットアップ

### Linux インストール

Ubuntu/Debian システムに Docker をインストールします。

```bash
# パッケージマネージャーを更新
sudo apt update
# 必須パッケージをインストール
sudo apt install apt-transport-https ca-certificates curl
software-properties-common
# Docker の公式 GPG キーを追加
curl -fsSL https://download.docker.com/linux/ubuntu/gpg
| sudo apt-key add -
# Docker リポジトリを追加
sudo add-apt-repository "deb [arch=amd64]
https://download.docker.com/linux/ubuntu bionic stable"
# Docker をインストール
sudo apt update && sudo apt install docker-ce
# Docker サービスを開始
sudo systemctl start docker
sudo systemctl enable docker
```

### Windows および macOS

GUI ベースの管理のために Docker Desktop をインストールします。

```bash
# Windows: docker.com から Docker Desktop をダウンロード
# macOS: Homebrew を使用するか、docker.com からダウンロード
brew install --cask docker
# または直接ダウンロード:
# https://www.docker.com/products/docker-desktop
```

### インストール後のセットアップ

非 root ユーザーでの Docker の使用を設定し、インストールを確認します。

```bash
# Linux: ユーザーを docker グループに追加
sudo usermod -aG docker $USER
# グループ変更を反映させるためにログアウト/ログイン
# Docker のインストールを確認
docker --version
docker run hello-world
```

### Docker Compose のインストール

マルチコンテナアプリケーションのために Docker Compose をインストールします。

```bash
# Linux: curl を使用してインストール
sudo curl -L
"https://github.com/docker/compose/releases/download
/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o
/usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
# インストールを確認
docker-compose --version
# 注: Docker Desktop には Compose が含まれています
```

## 基本的な Docker コマンド

### システム情報：`docker version` / `docker system info`

Docker のインストールと環境の詳細を確認します。

```bash
# Docker のバージョン情報を表示
docker version
# システム全体の Docker 情報を表示
docker system info
# Docker コマンドのヘルプを表示
docker help
docker <command> --help
```

### コンテナの実行：`docker run`

イメージからコンテナを作成し、起動します。

```bash
# 対話モードでコンテナを実行
docker run -it ubuntu:latest bash
# コンテナをバックグラウンドで実行 (デタッチ)
docker run -d --name my-container
nginx
# ポートマッピングを指定して実行
docker run -p 8080:80 nginx
# 終了後に自動的に削除して実行
docker run --rm hello-world
```

### コンテナの一覧表示：`docker ps`

実行中および停止中のコンテナを表示します。

```bash
# 実行中のコンテナを一覧表示
docker ps
# すべてのコンテナ (停止中のものも含む) を一覧表示
docker ps -a
# コンテナ ID のみ一覧表示
docker ps -q
# 最後に作成されたコンテナを表示
docker ps -l
```

## コンテナ管理

### コンテナのライフサイクル：`start` / `stop` / `restart`

コンテナの実行状態を制御します。

```bash
# 実行中のコンテナを停止
docker stop container_name
# 停止中のコンテナを開始
docker start container_name
# コンテナを再起動
docker restart container_name
# コンテナのプロセスを一時停止/再開
docker pause container_name
docker unpause container_name
```

### コマンドの実行：`docker exec`

実行中のコンテナ内でコマンドを実行します。

```bash
# 対話的な bash シェルを実行
docker exec -it container_name bash
# 単一のコマンドを実行
docker exec container_name ls -la
# 別のユーザーとして実行
docker exec -u root container_name whoami
# 特定のディレクトリで実行
docker exec -w /app container_name pwd
```

### コンテナの削除：`docker rm`

システムからコンテナを削除します。

```bash
# 停止中のコンテナを削除
docker rm container_name
# 実行中のコンテナを強制削除
docker rm -f container_name
# 複数のコンテナを削除
docker rm container1 container2
# 停止中のすべてのコンテナを削除
docker container prune
```

### コンテナログ：`docker logs`

コンテナの出力を表示し、問題をデバッグします。

```bash
# コンテナのログを表示
docker logs container_name
# リアルタイムでログを追跡
docker logs -f container_name
# 最近のログのみを表示
docker logs --tail 50 container_name
# タイムスタンプ付きでログを表示
docker logs -t container_name
```

## イメージ管理

### イメージのビルド：`docker build`

Dockerfile から Docker イメージを作成します。

```bash
# カレントディレクトリからイメージをビルド
docker build .
# イメージをタグ付けしてビルド
docker build -t myapp:latest .
# ビルド引数を使用してビルド
docker build --build-arg VERSION=1.0 -t myapp .
# キャッシュを使用せずにビルド
docker build --no-cache -t myapp .
```

### イメージの検査：`docker images` / `docker inspect`

Docker イメージを一覧表示し、検査します。

```bash
# すべてのローカルイメージを一覧表示
docker images
# 特定のフィルタでイメージを一覧表示
docker images nginx
# イメージの詳細を表示
docker inspect image_name
# イメージのビルド履歴を表示
docker history image_name
```

### レジストリ操作：`docker pull` / `docker push`

レジストリからイメージをダウンロードし、アップロードします。

```bash
# Docker Hub からイメージをプル
docker pull nginx:latest
# 特定のバージョンをプル
docker pull ubuntu:20.04
# イメージをレジストリにプッシュ
docker push myusername/myapp:latest
# プッシュ前にイメージにタグ付け
docker tag myapp:latest myusername/myapp:v1.0
```

### イメージのクリーンアップ：`docker rmi` / `docker image prune`

未使用のイメージを削除してディスク容量を解放します。

```bash
# 特定のイメージを削除
docker rmi image_name
# 未使用のイメージを削除
docker image prune
# すべての未使用イメージを削除 (dangling ではないものも含む)
docker image prune -a
# イメージを強制削除
docker rmi -f image_name
```

## Dockerfile の基本

### 必須の命令

イメージビルドのための主要な Dockerfile コマンド。

```dockerfile
# ベースイメージ
FROM ubuntu:20.04
# メンテナー情報を設定
LABEL maintainer="user@example.com"
# パッケージをインストール
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# ホストからコンテナにファイルをコピー
COPY app.py /app/
# 作業ディレクトリを設定
WORKDIR /app
# ポートを公開
EXPOSE 8000
```

### 実行時の設定

コンテナの実行方法を設定します。

```dockerfile
# 環境変数を設定
ENV PYTHON_ENV=production
ENV PORT=8000
# セキュリティのためにユーザーを作成
RUN useradd -m appuser
USER appuser
# 起動コマンドを定義
CMD ["python3", "app.py"]
# または固定コマンドとして ENTRYPOINT を使用
ENTRYPOINT ["python3"]
CMD ["app.py"]
# ヘルスチェックを設定
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/ || exit 1
```

## Docker Compose

### 基本的な Compose コマンド：`docker-compose up` / `docker-compose down`

マルチコンテナアプリケーションを起動および停止します。

```bash
# フォアグラウンドでサービスを起動
docker-compose up
# バックグラウンドでサービスを起動
docker-compose up -d
# サービスをビルドして起動
docker-compose up --build
# サービスを停止して削除
docker-compose down
# ボリューム付きで停止して削除
docker-compose down -v
```

### サービス管理

Compose アプリケーション内の個々のサービスを制御します。

```bash
# 実行中のサービスを一覧表示
docker-compose ps
# 特定のサービスのログを表示
docker-compose logs service_name
# すべてのサービスのログを追跡
docker-compose logs -f
# 特定のサービスを再起動
docker-compose restart service_name
```

### サンプル docker-compose.yml

マルチサービスアプリケーションの設定例。

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

## ネットワーキングとボリューム

### コンテナネットワーキング

コンテナを接続し、サービスを公開します。

```bash
# ネットワークを一覧表示
docker network ls
# カスタムネットワークを作成
docker network create mynetwork
# 特定のネットワーク上でコンテナを実行
docker run --network mynetwork nginx
# 実行中のコンテナをネットワークに接続
docker network connect mynetwork container_name
# ネットワークの詳細を検査
docker network inspect mynetwork
```

### ポートマッピング

コンテナポートをホストシステムに公開します。

```bash
# 単一ポートのマッピング
docker run -p 8080:80 nginx
# 複数ポートのマッピング
docker run -p 8080:80 -p 8443:443 nginx
# 特定のホストインターフェースへのマッピング
docker run -p 127.0.0.1:8080:80 nginx
# イメージで定義されたすべてのポートを公開
docker run -P nginx
```

### データボリューム：`docker volume`

コンテナ間でデータを永続化および共有します。

```bash
# 名前付きボリュームを作成
docker volume create myvolume
# すべてのボリュームを一覧表示
docker volume ls
# ボリュームの詳細を検査
docker volume inspect myvolume
# ボリュームを削除
docker volume rm myvolume
# 未使用のボリュームを削除
docker volume prune
```

### ボリュームのマウント

コンテナにボリュームとホストディレクトリをマウントします。

```bash
# 名前付きボリュームをマウント
docker run -v myvolume:/data nginx
# ホストディレクトリをマウント (バインドマウント)
docker run -v /host/path:/container/path nginx
# カレントディレクトリをマウント
docker run -v $(pwd):/app nginx
# 読み取り専用マウント
docker run -v /host/path:/container/path:ro nginx
```

## コンテナの検査とデバッグ

### コンテナの詳細：`docker inspect`

コンテナやイメージに関する詳細情報を取得します。

```bash
# コンテナの設定を検査
docker inspect container_name
# フォーマットを使用して特定情報を取得
docker inspect --format='{{.State.Status}}'
container_name
# IP アドレスを取得
docker inspect --format='{{.NetworkSettings.IPAddress}}'
container_name
# マウントされているボリュームを取得
docker inspect --format='{{.Mounts}}' container_name
```

### リソース監視

コンテナのリソース使用率とパフォーマンスを監視します。

```bash
# コンテナ内の実行中のプロセスを表示
docker top container_name
# ライブのリソース使用率統計を表示
docker stats
# 特定のコンテナの統計を表示
docker stats container_name
# リアルタイムでイベントを監視
docker events
```

### ファイル操作：`docker cp`

コンテナとホストシステム間でファイルをコピーします。

```bash
# コンテナからホストへファイルをコピー
docker cp container_name:/path/to/file ./
# ホストからコンテナへファイルをコピー
docker cp ./file container_name:/path/to/destination
# ディレクトリをコピー
docker cp ./directory
container_name:/path/to/destination/
# 権限を保持するためにアーカイブモードを使用
docker cp -a ./directory container_name:/path/
```

### トラブルシューティング

コンテナの問題や接続の問題をデバッグします。

```bash
# コンテナの終了コードを確認
docker inspect --format='{{.State.ExitCode}}'
container_name
# コンテナのプロセスを表示
docker exec container_name ps aux
# ネットワーク接続性をテスト
docker exec container_name ping google.com
# ディスク使用量を確認
docker exec container_name df -h
```

## レジストリと認証

### Docker Hub 操作：`docker login` / `docker search`

Docker Hub と認証し、対話します。

```bash
# Docker Hub にログイン
docker login
# 特定のレジストリにログイン
docker login registry.example.com
# Docker Hub でイメージを検索
docker search nginx
# フィルタ付きで検索
docker search --filter stars=100 nginx
```

### イメージのタグ付けと公開

イメージを準備し、レジストリに公開します。

```bash
# レジストリ用にイメージにタグ付け
docker tag myapp:latest username/myapp:v1.0
docker tag myapp:latest
registry.example.com/myapp:latest
# Docker Hub にプッシュ
docker push username/myapp:v1.0
# プライベートレジストリにプッシュ
docker push registry.example.com/myapp:latest
```

### プライベートレジストリ

プライベート Docker レジストリを操作します。

```bash
# プライベートレジストリからプル
docker pull registry.company.com/myapp:latest
# ローカルレジストリを起動
docker run -d -p 5000:5000 --name registry registry:2
# ローカルレジストリにタグ付け
docker tag myapp localhost:5000/myapp
docker push localhost:5000/myapp
```

### イメージのセキュリティ

イメージの整合性とセキュリティを確認します。

```bash
# Docker Content Trust を有効化
export DOCKER_CONTENT_TRUST=1
# イメージに署名してプッシュ
docker push username/myapp:signed
# イメージの署名を検査
docker trust inspect username/myapp:signed
# イメージの脆弱性をスキャン
docker scan myapp:latest
```

## システムクリーンアップとメンテナンス

### システムクリーンアップ：`docker system prune`

未使用の Docker リソースを削除してディスク容量を解放します。

```bash
# 未使用のコンテナ、ネットワーク、イメージを削除
docker system prune
# 未使用のボリュームもクリーンアップに含める
docker system prune -a --volumes
# すべてを削除 (注意して使用)
docker system prune -a -f
# スペース使用量を表示
docker system df
```

### ターゲットを絞ったクリーンアップ

未使用のリソースタイプを削除します。

```bash
# 停止中のコンテナを削除
docker container prune
# 未使用のイメージを削除
docker image prune -a
# 未使用のボリュームを削除
docker volume prune
# 未使用のネットワークを削除
docker network prune
```

### バルク操作

複数のコンテナ/イメージに対して操作を実行します。

```bash
# 実行中のすべてのコンテナを停止
docker stop $(docker ps -q)
# すべてのコンテナを削除
docker rm $(docker ps -aq)
# すべてのイメージを削除
docker rmi $(docker images -q)
# dangling イメージのみを削除
docker rmi $(docker images -f "dangling=true" -q)
```

### リソース制限

コンテナのリソース消費を制御します。

```bash
# メモリ使用量を制限
docker run --memory=512m nginx
# CPU 使用量を制限
docker run --cpus="1.5" nginx
# CPU とメモリの両方を制限
docker run --memory=1g --cpus="2.0" nginx
# 再起動ポリシーを設定
docker run --restart=always nginx
```

## Docker の設定と設定

### デーモン設定

本番環境向けに Docker デーモンを設定します。

```bash
# デーモン設定を編集
sudo nano
/etc/docker/daemon.json
# 設定例:
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
# Docker サービスを再起動
sudo systemctl restart docker
```

### 環境変数

環境変数を使用して Docker クライアントの動作を設定します。

```bash
# Docker ホストを設定
export
DOCKER_HOST=tcp://remote-
docker:2376
# TLS 検証を有効化
export DOCKER_TLS_VERIFY=1
export
DOCKER_CERT_PATH=/path/to/c
erts
# デフォルトレジストリを設定
export
DOCKER_REGISTRY=registry.co
mpany.com
# デバッグ出力を有効化
export DOCKER_BUILDKIT=1
```

### パフォーマンスチューニング

パフォーマンス向上のために Docker を最適化します。

```bash
# 実験的機能を有効化
echo '{"experimental": true}' |
sudo tee
/etc/docker/daemon.json
# ストレージドライバのオプションを設定
{
  "storage-driver": "overlay2",
  "storage-opts": [

"overlay2.override_kernel_check
=true"
  ]
}
# ロギングを設定
{
  "log-driver": "syslog",
  "log-opts": {"syslog-address":
"udp://logs.company.com:514"}
}
```

## ベストプラクティス

### セキュリティのベストプラクティス

コンテナを安全に保ち、本番環境に対応させます。

```dockerfile
# Dockerfile 内で非 root ユーザーとして実行
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# 'latest' ではなく、特定のイメージタグを使用
FROM node:16.20.0-alpine
# 可能な限り読み取り専用ファイルシステムを使用
docker run --read-only nginx
```

### パフォーマンスの最適化

コンテナを速度とリソース効率のために最適化します。

```dockerfile
# イメージサイズを削減するためにマルチステージビルドを使用
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

## 関連リンク

- <router-link to="/kubernetes">Kubernetes チートシート</router-link>
- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/ansible">Ansible チートシート</router-link>
- <router-link to="/git">Git チートシート</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>

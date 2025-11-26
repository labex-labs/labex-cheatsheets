---
title: 'Jenkins チートシート'
description: '必須のコマンド、概念、ベストプラクティスを網羅した包括的なチートシートで Jenkins を習得しましょう。'
pdfUrl: '/cheatsheets/pdf/jenkins-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Jenkins チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/jenkins">ハンズオンラボで Jenkins を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、Jenkins CI/CDオートメーションを学びます。LabExは、基本的な操作、パイプライン作成、プラグイン管理、ビルド自動化、高度なテクニックを網羅した包括的なJenkinsコースを提供します。Jenkinsを習得し、モダンなソフトウェア開発のための効率的な継続的インテグレーションおよびデプロイメントパイプラインを構築しましょう。
</base-disclaimer-content>
</base-disclaimer>

## インストールとセットアップ

### Linux インストール

Ubuntu/DebianシステムへのJenkinsのインストール。

```bash
# パッケージマネージャを更新し、Javaをインストール
sudo apt update
sudo apt install fontconfig openjdk-21-jre
java -version
# Jenkins GPGキーの追加
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
# Jenkinsリポジトリの追加
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
/etc/apt/sources.list.d/jenkins.list > /dev/null
# Jenkinsのインストール
sudo apt update && sudo apt install jenkins
# Jenkinsサービスの開始
sudo systemctl start jenkins
sudo systemctl enable jenkins
```

### Windows および macOS

インストーラまたはパッケージマネージャを使用した Jenkins のインストール。

```bash
# Windows: jenkins.ioからJenkinsインストーラをダウンロード
# またはChocolateyを使用
choco install jenkins
# macOS: Homebrewを使用
brew install jenkins-lts
# または直接ダウンロード:
# https://www.jenkins.io/download/
# Jenkinsサービスの開始
brew services start jenkins-lts
```

### インストール後のセットアップ

初期設定と Jenkins のロック解除。

```bash
# 初期管理者パスワードの取得
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# またはDockerインストールの場合は
docker exec jenkins_container cat /var/jenkins_home/secrets/initialAdminPassword
# Jenkinsウェブインターフェースへのアクセス
# http://localhost:8080 にアクセス
# 初期管理者パスワードを入力
# 推奨プラグインのインストール、またはカスタムプラグインの選択
```

### 初期設定

セットアップウィザードを完了し、管理者ユーザーを作成します。

```bash
# Jenkinsのロック解除後:
# 1. 推奨プラグインのインストール（推奨）
# 2. 最初の管理者ユーザーの作成
# 3. Jenkins URLの設定
# 4. Jenkinsの使用開始
# Jenkinsが実行中であることを確認
sudo systemctl status jenkins
# 必要に応じてJenkinsログを確認
sudo journalctl -u jenkins.service
```

## 基本的な Jenkins 操作

### Jenkins へのアクセス：Web インターフェースと CLI セットアップ

ブラウザ経由での Jenkins アクセスと CLI ツールのセットアップ。

```bash
# Jenkinsウェブインターフェースへのアクセス
http://localhost:8080
# Jenkins CLIのダウンロード
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
# CLI接続のテスト
java -jar jenkins-cli.jar -s http://localhost:8080 help
# 利用可能なコマンドの一覧表示
java -jar jenkins-cli.jar -s http://localhost:8080 help
```

### ジョブ作成：`create-job` / Web UI

CLI または Web インターフェースを使用して新しいビルドジョブを作成します。

```bash
# XML設定からジョブを作成
java -jar jenkins-cli.jar -auth user:token create-job my-job < job-config.xml
# Web UIでシンプルなフリースタイルジョブを作成:
# 1. 「新規ジョブ作成」をクリック
# 2. ジョブ名を入力
# 3. 「フリースタイルプロジェクト」を選択
# 4. ビルドステップを設定
# 5. 設定を保存
```

### ジョブ一覧表示：`list-jobs`

設定されているすべてのジョブを表示します。

```bash
# すべてのジョブを一覧表示
java -jar jenkins-cli.jar -auth user:token list-jobs
# パターンに一致するジョブを一覧表示
java -jar jenkins-cli.jar -auth user:token list-jobs "*test*"
# ジョブの設定を取得
java -jar jenkins-cli.jar -auth user:token get-job my-job > job-config.xml
```

## ジョブ管理

### ジョブのビルド：`build`

ジョブのビルドを実行し、管理します。

```bash
# ジョブをビルド
java -jar jenkins-cli.jar -auth user:token build my-job
# パラメータ付きでビルド
java -jar jenkins-cli.jar -auth user:token build my-job -p PARAM=value
# ビルドを実行し、完了を待機
java -jar jenkins-cli.jar -auth user:token build my-job -s -v
# ビルドを実行し、コンソール出力を追跡
java -jar jenkins-cli.jar -auth user:token build my-job -f
```

### ジョブ制御：`enable-job` / `disable-job`

ジョブを有効化または無効化します。

```bash
# ジョブを有効化
java -jar jenkins-cli.jar -auth user:token enable-job my-job
# ジョブを無効化
java -jar jenkins-cli.jar -auth user:token disable-job my-job
# Web UIでジョブの状態を確認
# ジョブダッシュボードに移動
# 「無効化/有効化」ボタンを探す
```

### ジョブの削除：`delete-job`

Jenkins からジョブを削除します。

```bash
# ジョブを削除
java -jar jenkins-cli.jar -auth user:token delete-job my-job
# 複数ジョブの一括削除（注意が必要）
for job in job1 job2 job3; do
  java -jar jenkins-cli.jar -auth user:token delete-job $job
done
```

### コンソール出力：`console`

ビルドログとコンソール出力を表示します。

```bash
# 最新のビルドのコンソール出力を表示
java -jar jenkins-cli.jar -auth user:token console my-job
# 特定のビルド番号の出力を表示
java -jar jenkins-cli.jar -auth user:token console my-job 15
# コンソール出力をリアルタイムで追跡
java -jar jenkins-cli.jar -auth user:token console my-job -f
```

## パイプライン管理

### パイプライン作成

Jenkins パイプラインの作成と設定。

```groovy
// 基本的なJenkinsfile (宣言的パイプライン)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Building application...'
                sh 'make build'
            }
        }

        stage('Test') {
            steps {
                echo 'Running tests...'
                sh 'make test'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Deploying application...'
                sh 'make deploy'
            }
        }
    }
}
```

### パイプライン構文

一般的なパイプライン構文とディレクティブ。

```groovy
// スクリプト型パイプライン構文
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
// 並列実行
stages {
    stage('Parallel Tests') {
        parallel {
            stage('Unit Tests') {
                steps {
                    sh 'make unit-test'
                }
            }
            stage('Integration Tests') {
                steps {
                    sh 'make integration-test'
                }
            }
        }
    }
}
```

### パイプライン設定

高度なパイプライン設定とオプション。

```groovy
// ビルド後アクションを持つパイプライン
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
            echo 'This always runs'
        }
        success {
            echo 'Build succeeded'
        }
        failure {
            echo 'Build failed'
            emailext subject: 'Build Failed',
                     body: 'Build failed',
                     to: 'team@company.com'
        }
    }
}
```

### パイプライントリガー

パイプラインの自動トリガーを設定します。

```groovy
// トリガー付きパイプライン
pipeline {
    agent any

    triggers {
        // SCMを5分ごとにポーリング
        pollSCM('H/5 * * * *')

        // Cron形式のスケジュール
        cron('H 2 * * *')  // 毎日午前2時

        // アップストリームジョブのトリガー
        upstream(upstreamProjects: 'upstream-job',
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

## プラグイン管理

### プラグインのインストール：CLI

コマンドラインインターフェースを使用してプラグインをインストールします。

```bash
# CLI経由でプラグインをインストール（再起動が必要）
java -jar jenkins-cli.jar -auth user:token install-plugin git
# 複数のプラグインをインストール
java -jar jenkins-cli.jar -auth user:token install-plugin \
  git maven-plugin docker-plugin
# .hpiファイルからインストール
java -jar jenkins-cli.jar -auth user:token install-plugin \
  /path/to/plugin.hpi
# インストール済みプラグインの一覧表示
java -jar jenkins-cli.jar -auth user:token list-plugins
# plugins.txtを使用したプラグインインストール（Docker用）
# plugins.txtファイルを作成:
git:latest
maven-plugin:latest
docker-plugin:latest
pipeline-stage-view:latest
# jenkins-plugin-cli ツールを使用
jenkins-plugin-cli --plugins git maven-plugin docker-plugin
```

### 必須プラグイン

さまざまな目的に使用される一般的な Jenkins プラグイン。

```bash
# ビルド & SCM プラグイン
git                    # Git連携
github                 # GitHub連携
maven-plugin          # Mavenビルドサポート
gradle                # Gradleビルドサポート
# パイプライン プラグイン
workflow-aggregator   # パイプラインプラグインスイート
pipeline-stage-view   # パイプラインステージビュー
blue-ocean           # パイプラインのモダンなUI
# デプロイ & 連携
docker-plugin        # Docker連携
kubernetes           # Kubernetesデプロイ
ansible              # Ansibleオートメーション
# 品質 & テスト
junit                # JUnitテストレポート
jacoco              # コードカバレッジ
sonarqube           # コード品質分析
```

### プラグイン管理 Web UI

Jenkins ウェブインターフェース経由でのプラグイン管理。

```bash
# プラグインマネージャへのアクセス:
# 1. Jenkinsの管理 → 「プラグインの管理」に移動
# 2. 「利用可能」「インストール済み」「更新」タブを使用
# 3. プラグインを検索
# 4. 選択してインストール
# 5. 必要に応じてJenkinsを再起動
# プラグイン更新プロセス:
# 1. 「更新」タブを確認
# 2. 更新するプラグインを選択
# 3. 「ダウンロードして再起動後にインストール」をクリック
```

## ユーザー管理とセキュリティ

### ユーザー管理

Jenkins ユーザーの作成と管理。

```bash
# Jenkinsセキュリティの有効化:
# 1. Jenkinsの管理 → 「システムの設定」
# 2. 「Jenkinsの独自のユーザーデータベース」を有効化
# 3. ユーザー登録を許可（初期設定時）
# 4. 認可戦略を設定
# CLI経由でのユーザー作成（適切な権限が必要）
# ユーザーは通常Web UI経由で作成されます:
# 1. Jenkinsの管理 → 「ユーザーの管理」
# 2. 「ユーザーの作成」をクリック
# 3. ユーザー詳細を入力
# 4. ロール/権限を割り当て
```

### 認証と認可

セキュリティレルムと認可戦略の設定。

```bash
# セキュリティ設定のオプション:
# 1. セキュリティレルム（ユーザー認証方法）:
#    - Jenkinsの独自のユーザーデータベース
#    - LDAP
#    - Active Directory
#    - Matrixベースのセキュリティ
#    - ロールベースの認可
# 2. 認可戦略:
#    - 何でも許可
#    - レガシーモード
#    - ログイン済みユーザーなら何でも許可
#    - Matrixベースのセキュリティ
#    - プロジェクトベースのMatrix認可
```

### API トークン

CLI アクセス用の API トークンの生成と管理。

```bash
# APIトークンの生成:
# 1. ユーザー名をクリック → 「設定」
# 2. APIトークンセクション
# 3. 「新しいトークンの追加」をクリック
# 4. トークン名を入力
# 5. 生成し、コピー
# CLIでのAPIトークンの使用
java -jar jenkins-cli.jar -auth username:api-token \
  -s http://localhost:8080 list-jobs
# 認証情報を安全に保存
echo "username:api-token" > ~/.jenkins-cli-auth
chmod 600 ~/.jenkins-cli-auth
```

### 認証情報管理

ジョブやパイプラインのために保存された認証情報を管理します。

```bash
# CLI経由での認証情報の管理
java -jar jenkins-cli.jar -auth user:token \
  list-credentials system::system::jenkins
# 認証情報XMLを作成しインポート
java -jar jenkins-cli.jar -auth user:token \
  create-credentials-by-xml system::system::jenkins \
  < credential.xml
```

```groovy
// パイプラインでの認証情報へのアクセス
withCredentials([usernamePassword(
  credentialsId: 'my-credentials',
  usernameVariable: 'USERNAME',
  passwordVariable: 'PASSWORD'
)]) {
  sh 'docker login -u $USERNAME -p $PASSWORD'
}
```

## ビルド監視とトラブルシューティング

### ビルドステータスとログ

ビルドステータスの監視と詳細なログへのアクセス。

```bash
# ビルドステータスの確認
java -jar jenkins-cli.jar -auth user:token console my-job
# ジョブ情報の取得
java -jar jenkins-cli.jar -auth user:token get-job my-job
# ビルドキューの監視
# Web UI: Jenkinsダッシュボード → ビルドキュー
# 保留中のビルドとそのステータスが表示される
# ビルド履歴へのアクセス
# Web UI: ジョブ → ビルド履歴
# ステータス付きの過去の全ビルドが表示される
```

### システム情報

Jenkins のシステム情報と診断を取得します。

```bash
# システム情報
java -jar jenkins-cli.jar -auth user:token version
# ノード情報
java -jar jenkins-cli.jar -auth user:token list-computers
# Groovyコンソール（管理者のみ）
# Jenkinsの管理 → スクリプトコンソール
# システム情報を取得するためのGroovyスクリプトの実行:
println Jenkins.instance.version
println Jenkins.instance.getRootDir()
println System.getProperty("java.version")
```

### ログ分析

Jenkins システムログへのアクセスと分析。

```bash
# システムログの場所
# Linux: /var/log/jenkins/jenkins.log
# Windows: C:\Program Files\Jenkins\jenkins.out.log
# ログの表示
tail -f /var/log/jenkins/jenkins.log
# ログレベルの設定
# Jenkinsの管理 → システムログ
# 特定のコンポーネントに対して新しいログレコーダーを追加
# 一般的なログの場所:
sudo journalctl -u jenkins.service     # Systemdログ
sudo cat /var/lib/jenkins/jenkins.log  # Jenkinsログファイル
```

### パフォーマンス監視

Jenkins のパフォーマンスとリソース使用率を監視します。

```bash
# 組み込み監視
# Jenkinsの管理 → 負荷統計
# 時間経過に伴うエグゼキュータの使用状況を表示
# JVM監視
# Jenkinsの管理 → ノードの管理 → マスター
# メモリ、CPU使用率、システムプロパティを表示
# ビルドトレンド
# 「ビルド履歴」プラグインをインストール
# ビルド期間のトレンドと成功率を表示
# ディスク使用量監視
# 「ディスク使用量」プラグインをインストール
# ワークスペースとビルド成果物のストレージを監視
```

## Jenkins 設定とオプション

### グローバル設定

グローバルな Jenkins 設定とツールの設定。

```bash
# グローバルツール設定
# Jenkinsの管理 → グローバルツール設定
# 設定するもの:
# - JDKインストール
# - Gitインストール
# - Mavenインストール
# - Dockerインストール
# システム設定
# Jenkinsの管理 → システム設定
# 設定するもの:
# - Jenkins URL
# - システムメッセージ
# - エグゼキュータ数
# - クワイエット期間
# - SCMポーリング制限
```

### 環境変数

Jenkins の環境変数とシステムプロパティの設定。

```bash
# 組み込み環境変数
BUILD_NUMBER          # ビルド番号
BUILD_ID              # ビルドID
JOB_NAME             # ジョブ名
WORKSPACE            # ジョブのワークスペースパス
JENKINS_URL          # Jenkins URL
NODE_NAME            # ノード名
# カスタム環境変数
# Jenkinsの管理 → システム設定
# グローバルプロパティ → 環境変数
# グローバルアクセス用のキーと値のペアを追加
```

### コードとしての Jenkins 設定 (JCasC)

JCasC プラグインを使用した Jenkins 設定の管理。

```yaml
# JCasC 設定ファイル (jenkins.yaml)
jenkins:
  systemMessage: "Jenkins configured as code"
  numExecutors: 4
  securityRealm:
    local:
      allowsSignup: false
      users:
       - id: "admin"
         password: "admin123"
# 設定の適用
# CASC_JENKINS_CONFIG 環境変数を設定
export CASC_JENKINS_CONFIG=/path/to/jenkins.yaml
```

## ベストプラクティス

### セキュリティのベストプラクティス

Jenkins インスタンスを安全に保ち、本番環境に対応させます。

```bash
# セキュリティに関する推奨事項:
# 1. セキュリティと認証を有効化
# 2. Matrixベースの認可を使用
# 3. 定期的なセキュリティアップデート
# 4. ユーザー権限の制限
# 5. パスワードの代わりにAPIトークンを使用
# Jenkins設定の保護:
# - リモート経由のCLIを無効化
# - 有効な証明書を使用してHTTPSを使用
# - JENKINS_HOMEの定期的なバックアップ
# - セキュリティアドバイザリの監視
# - シークレットには認証情報プラグインを使用
```

### パフォーマンス最適化

パフォーマンスとスケーラビリティのために Jenkins を最適化します。

```bash
# パフォーマンスのヒント:
# 1. 分散ビルドをエージェントと共​​に使用
# 2. ビルドスクリプトと依存関係の最適化
# 3. 古いビルドの自動クリーンアップ
# 4. 再利用性のためのパイプラインライブラリの使用
# 5. ディスク容量とメモリ使用率の監視
# ビルドの最適化:
# - 可能な限りインクリメンタルビルドを使用
# - ステージの並列実行
# - アーティファクトのキャッシュ
# - ワークスペースのクリーンアップ
# - リソース割り当ての調整
```

## 関連リンク

- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/kubernetes">Kubernetes チートシート</router-link>
- <router-link to="/ansible">Ansible チートシート</router-link>
- <router-link to="/git">Git チートシート</router-link>
- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>

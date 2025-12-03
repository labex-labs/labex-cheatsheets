---
title: 'Jenkins チートシート | LabEx'
description: 'この包括的なチートシートで Jenkins CI/CDを学ぶ。Jenkinsパイプライン、ジョブ、プラグイン、自動化、継続的インテグレーション、DevOpsワークフローのクイックリファレンス。'
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
ハンズオンラボと実世界のシナリオを通じて、Jenkins CI/CDオートメーションを学びます。LabExは、必須操作、パイプライン作成、プラグイン管理、ビルド自動化、高度なテクニックを網羅した包括的なJenkinsコースを提供します。Jenkinsを習得し、モダンなソフトウェア開発のための効率的な継続的インテグレーションおよびデプロイメントパイプラインを構築しましょう。
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

### Windows & macOS

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

初期設定と Jenkins のアンロック。

```bash
# 初期管理者パスワードの取得
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# またはDockerインストールの場合は
docker exec jenkins_container cat /var/jenkins_home/secrets/initialAdminPassword
# Jenkins Webインターフェースへのアクセス
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
# Jenkins Webインターフェースへのアクセス
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

### ジョブの一覧表示：`list-jobs`

設定されているすべてのジョブを表示します。

```bash
# すべてのジョブを一覧表示
java -jar jenkins-cli.jar -auth user:token list-jobs
# パターンマッチングでジョブを一覧表示
java -jar jenkins-cli.jar -auth user:token list-jobs "*test*"
# ジョブの設定を取得
java -jar jenkins-cli.jar -auth user:token get-job my-job > job-config.xml
```

## ジョブ管理

### ジョブのビルド：`build`

ジョブのビルドをトリガーおよび管理します。

```bash
# ジョブをビルド
java -jar jenkins-cli.jar -auth user:token build my-job
# パラメータ付きでビルド
java -jar jenkins-cli.jar -auth user:token build my-job -p PARAM=value
# ビルド完了を待機してビルド
java -jar jenkins-cli.jar -auth user:token build my-job -s -v
# コンソール出力を追跡してビルド
java -jar jenkins-cli.jar -auth user:token build my-job -f
```

<BaseQuiz id="jenkins-build-1" correct="B">
  <template #question>
    <code>jenkins-cli.jar build my-job -s</code> の <code>-s</code> フラグは何をしますか？
  </template>
  
  <BaseQuizOption value="A">ビルドをスキップする</BaseQuizOption>
  <BaseQuizOption value="B" correct>ビルド完了を待機する（同期）</BaseQuizOption>
  <BaseQuizOption value="C">ビルドステータスを表示する</BaseQuizOption>
  <BaseQuizOption value="D">ビルドを停止する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-s</code> フラグはビルドコマンドを同期的にし、ビルドが完了するまで待機します。このフラグがない場合、コマンドはビルドをトリガーした直後に返されます。
  </BaseQuizAnswer>
</BaseQuiz>

### ジョブ制御：`enable-job` / `disable-job`

ジョブを有効化または無効化します。

```bash
# ジョブを有効化
java -jar jenkins-cli.jar -auth user:token enable-job my-job
# ジョブを無効化
java -jar jenkins-cli.jar -auth user:token disable-job my-job
# Web UIでジョブステータスを確認
# ジョブダッシュボードに移動
# 「無効化/有効化」ボタンを探す
```

<BaseQuiz id="jenkins-job-control-1" correct="B">
  <template #question>
    Jenkins ジョブを無効化するとどうなりますか？
  </template>
  
  <BaseQuizOption value="A">ジョブは完全に削除される</BaseQuizOption>
  <BaseQuizOption value="B" correct>ジョブの設定は保持されるが、自動的には実行されなくなる</BaseQuizOption>
  <BaseQuizOption value="C">ジョブは別のフォルダに移動される</BaseQuizOption>
  <BaseQuizOption value="D">すべてのビルド履歴が削除される</BaseQuizOption>
  
  <BaseQuizAnswer>
    ジョブを無効化すると、自動実行（スケジュールされたビルド、トリガーなど）は防止されますが、ジョブの設定とビルド履歴は保持されます。後で再度有効にできます。
  </BaseQuizAnswer>
</BaseQuiz>

### ジョブの削除：`delete-job`

Jenkins からジョブを削除します。

```bash
# ジョブを削除
java -jar jenkins-cli.jar -auth user:token delete-job my-job
# 複数ジョブの削除（注意が必要）
for job in job1 job2 job3; do
  java -jar jenkins-cli.jar -auth user:token delete-job $job
done
```

### コンソール出力：`console`

ビルドログとコンソール出力を表示します。

```bash
# 最新のビルドコンソール出力を表示
java -jar jenkins-cli.jar -auth user:token console my-job
# 特定のビルド番号を表示
java -jar jenkins-cli.jar -auth user:token console my-job 15
# コンソール出力をリアルタイムで追跡
java -jar jenkins-cli.jar -auth user:token console my-job -f
```

<BaseQuiz id="jenkins-console-1" correct="C">
  <template #question>
    <code>jenkins-cli.jar console my-job -f</code> の <code>-f</code> フラグは何をしますか？
  </template>
  
  <BaseQuizOption value="A">ビルドの停止を強制する</BaseQuizOption>
  <BaseQuizOption value="B">失敗したビルドのみを表示する</BaseQuizOption>
  <BaseQuizOption value="C" correct>コンソール出力をリアルタイムで追跡する</BaseQuizOption>
  <BaseQuizOption value="D">出力を JSON 形式でフォーマットする</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-f</code> フラグは、Linux の <code>tail -f</code> と同様に、コンソール出力をリアルタイムで追跡します。これはビルドの実行中に監視するのに役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

## パイプライン管理

### パイプラインの作成

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

### パイプラインの設定

高度なパイプライン設定とオプション。

```groovy
// ビルド後のアクションを持つパイプライン
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
// トリガーを持つパイプライン
pipeline {
    agent any

    triggers {
        // 5分ごとにSCMをポーリング
        pollSCM('H/5 * * * *')

        // Cronライクなスケジューリング
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
# plugins.txtを使用したプラグインのインストール（Docker用）
# plugins.txtファイルを作成:
git:latest
maven-plugin:latest
docker-plugin:latest
pipeline-stage-view:latest
# jenkins-plugin-cli ツールを使用
jenkins-plugin-cli --plugins git maven-plugin docker-plugin
```

### 必須プラグイン

さまざまな目的のために一般的に使用される Jenkins プラグイン。

```bash
# ビルド & SCM プラグイン
git                    # Git連携
github                 # GitHub連携
maven-plugin          # Mavenビルドサポート
gradle                # Gradleビルドサポート
# パイプライン プラグイン
workflow-aggregator   # パイプラインプラグインスイート
pipeline-stage-view   # パイプラインステージビュー
blue-ocean           # パイプラインのモダンUI
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

Jenkins Web インターフェース経由でのプラグイン管理。

```bash
# プラグインマネージャへのアクセス:
# 1. Manage Jenkins → Manage Plugins に移動
# 2. Available/Installed/Updates タブを使用
# 3. プラグインを検索
# 4. 選択してインストール
# 5. 必要に応じてJenkinsを再起動
# プラグイン更新プロセス:
# 1. "Updates" タブをクリック
# 2. 更新するプラグインを選択
# 3. "Download now and install after restart" をクリック
```

## ユーザー管理とセキュリティ

### ユーザー管理

Jenkins ユーザーの作成と管理。

```bash
# Jenkinsセキュリティの有効化:
# 1. Manage Jenkins → Configure Global Security
# 2. 「Jenkins独自のユーザーデータベース」を有効化
# 3. ユーザー登録を許可（初期セットアップ用）
# 4. 認証戦略を設定
# CLI経由でのユーザー作成（適切な権限が必要）
# ユーザーは通常Web UI経由で作成されます:
# 1. Manage Jenkins → Manage Users
# 2. 「ユーザー作成」をクリック
# 3. ユーザー詳細を入力
# 4. ロール/権限を割り当て
```

### 認証と認可

セキュリティレルムと認可戦略の設定。

```bash
# セキュリティ設定のオプション:
# 1. Security Realm (ユーザー認証方法):
#    - Jenkins' own user database
#    - LDAP
#    - Active Directory
#    - Matrix-based security
#    - Role-based authorization
# 2. Authorization Strategy:
#    - Anyone can do anything
#    - Legacy mode
#    - Logged-in users can do anything
#    - Matrix-based security
#    - Project-based Matrix Authorization
```

### API トークン

CLI アクセス用の API トークンの生成と管理。

```bash
# APIトークンの生成:
# 1. ユーザー名をクリック → Configure
# 2. API Tokenセクション
# 3. 「新しいトークンの追加」をクリック
# 4. トークン名を入力
# 5. 生成し、トークンをコピー
# APIトークンをCLIで使用
java -jar jenkins-cli.jar -auth username:api-token \
  -s http://localhost:8080 list-jobs
# 認証情報を安全に保存
echo "username:api-token" > ~/.jenkins-cli-auth
chmod 600 ~/.jenkins-cli-auth
```

### 認証情報管理

ジョブやパイプラインのために保存された認証情報を管理します。

```bash
# CLI経由での認証情報管理
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

ビルドステータスを監視し、詳細なログにアクセスします。

```bash
# ビルドステータスの確認
java -jar jenkins-cli.jar -auth user:token console my-job
# ビルド情報の取得
java -jar jenkins-cli.jar -auth user:token get-job my-job
# ビルドキューの監視
# Web UI: Jenkinsダッシュボード → Build Queue
# 保留中のビルドとそのステータスが表示される
# ビルド履歴へのアクセス
# Web UI: Job → Build History
# すべての過去のビルドとステータスが表示される
```

### システム情報

Jenkins システム情報を取得し、診断を行います。

```bash
# システム情報
java -jar jenkins-cli.jar -auth user:token version
# ノード情報
java -jar jenkins-cli.jar -auth user:token list-computers
# Groovyコンソール（管理者のみ）
# Manage Jenkins → Script Console
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
# Manage Jenkins → System Log
# 特定のコンポーネントの新しいログレコーダーを追加
# 一般的なログの場所:
sudo journalctl -u jenkins.service     # Systemdログ
sudo cat /var/lib/jenkins/jenkins.log  # Jenkinsログファイル
```

### パフォーマンス監視

Jenkins のパフォーマンスとリソース使用率を監視します。

```bash
# 組み込み監視
# Manage Jenkins → Load Statistics
# 実行中のエグゼキュータの利用状況を時間経過とともに表示
# JVM監視
# Manage Jenkins → Manage Nodes → Master
# メモリ、CPU使用率、システムプロパティを表示
# ビルドトレンド
# "Build History Metrics" プラグインをインストール
# ビルド期間のトレンドと成功率を表示
# ディスク使用量監視
# "Disk Usage" プラグインをインストール
# ワークスペースとビルド成果物のストレージを監視
```

## Jenkins 設定と環境設定

### グローバル設定

グローバルな Jenkins 設定とツールの設定。

```bash
# グローバルツール設定
# Manage Jenkins → Global Tool Configuration
# 設定するもの:
# - JDKインストール
# - Gitインストール
# - Mavenインストール
# - Dockerインストール
# システム設定
# Manage Jenkins → Configure System
# 設定するもの:
# - Jenkins URL
# - システムメッセージ
# - エグゼキュータ数
# - Quiet period
# - SCMポーリング制限
```

### 環境変数

Jenkins 環境変数とシステムプロパティの設定。

```bash
# 組み込み環境変数
BUILD_NUMBER          # ビルド番号
BUILD_ID              # ビルドID
JOB_NAME             # ジョブ名
WORKSPACE            # ジョブのワークスペースパス
JENKINS_URL          # Jenkins URL
NODE_NAME            # ノード名
# カスタム環境変数
# Manage Jenkins → Configure System
# Global properties → Environment variables
# グローバルアクセス用にキーと値のペアを追加
```

### コードとしての Jenkins 設定 (JCasC)

JCasC プラグインを使用して Jenkins 設定を管理します。

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
# セキュリティ推奨事項:
# 1. セキュリティと認証を有効化
# 2. マトリックスベースの認可を使用
# 3. 定期的なセキュリティアップデート
# 4. ユーザー権限の制限
# 5. パスワードの代わりにAPIトークンを使用
# Jenkins設定の保護:
# - CLI over remoting を無効化
# - 有効な証明書を使用してHTTPSを使用
# - JENKINS_HOMEの定期的なバックアップ
# - セキュリティアドバイザリの監視
# - シークレットには認証情報プラグインを使用
```

### パフォーマンス最適化

パフォーマンスとスケーラビリティ向上のために Jenkins を最適化します。

```bash
# パフォーマンスのヒント:
# 1. 分散ビルドをエージェントと共に行う
# 2. ビルドスクリプトと依存関係の最適化
# 3. 古いビルドの自動クリーンアップ
# 4. 再利用性のためにパイプラインライブラリを使用
# 5. ディスク容量とメモリ使用率の監視
# ビルドの最適化:
# - 可能な限りインクリメンタルビルドを使用
# - ステージの並列実行
# - アーティファクトのキャッシュ
# - ワークスペースのクリーンアップ
# - リソース割り当てのチューニング
```

## 関連リンク

- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/kubernetes">Kubernetes チートシート</router-link>
- <router-link to="/ansible">Ansible チートシート</router-link>
- <router-link to="/git">Git チートシート</router-link>
- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>

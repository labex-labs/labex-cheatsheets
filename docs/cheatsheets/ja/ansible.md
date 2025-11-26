---
title: 'Ansible チートシート'
description: '必須のコマンド、概念、ベストプラクティスを網羅した包括的なチートシートで Ansible を習得しましょう。'
pdfUrl: '/cheatsheets/pdf/ansible-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Ansible チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/ansible">ハンズオンラボで Ansible を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、Ansible インフラストラクチャ自動化を学びます。LabEx は、必須のプレイブック作成、インベントリ管理、モジュール使用、ロール編成を網羅した包括的な Ansible コースを提供します。DevOps ワークフローのための構成管理とインフラストラクチャ自動化を習得します。
</base-disclaimer-content>
</base-disclaimer>

## インストールとセットアップ

### Ubuntu/Debian: `apt install ansible`

Debian ベースの Linux システムに Ansible をインストールします。

```bash
# Ansible リポジトリを追加
sudo apt-add-repository ppa:ansible/ansible
# パッケージリストを更新
sudo apt-get update
# Ansible をインストール
sudo apt-get install ansible
# インストールを確認
ansible --version
```

### CentOS/RHEL: `yum install ansible`

Red Hat ベースのシステムに Ansible をインストールします。

```bash
# EPEL リポジトリをインストール
sudo yum install epel-release -y
# Ansible をインストール
sudo yum install ansible -y
# インストールを確認
ansible --version
```

### macOS: `brew install ansible`

Homebrew を使用して macOS に Ansible をインストールします。

```bash
# Homebrew を使用してインストール
brew install ansible
# インストールを確認
ansible --version
```

### 設定：`/etc/ansible/ansible.cfg`

Ansible の設定とデフォルト値を構成します。

```bash
# 現在の設定を表示
ansible-config list
# 有効な設定を表示
ansible-config view
# カスタム設定ファイル
export ANSIBLE_CONFIG=/path/to/ansible.cfg
```

### SSH セットアップ：キーベース認証

Ansible は SSH を使用してノード間で通信します。

```bash
# SSH キーを生成
ssh-keygen -t rsa -b 4096
# 公開鍵をリモートホストにコピー
ssh-copy-id user@hostname
# SSH 接続をテスト
ssh user@hostname
```

### 環境セットアップ

Ansible 環境変数とパスを設定します。

```bash
# インベントリファイルの位置を設定
export ANSIBLE_INVENTORY=/path/to/inventory
# ホストキーチェックを設定
export ANSIBLE_HOST_KEY_CHECKING=False
# リモートユーザーを設定
export ANSIBLE_REMOTE_USER=ubuntu
```

## インベントリ管理

### 基本インベントリ：`/etc/ansible/hosts`

ホストグループは、角括弧内にグループ名を与えることで作成できます。

```ini
# 基本ホストファイル (INI 形式)
[webservers]
web1.example.com
web2.example.com
[databases]
db1.example.com
db2.example.com
[all:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/id_rsa
```

### YAML インベントリ形式

インベントリファイルは INI 形式または YAML 形式にできます。

```yaml
# inventory.yml
all:
  children:
    webservers:
      hosts:
        web1.example.com:
        web2.example.com:
    databases:
      hosts:
        db1.example.com:
      vars:
        mysql_port: 3306
```

### ホスト変数とグループ

ホスト固有の変数とグループ構成を定義します。

```ini
# 変数を持つインベントリ
[webservers]
web1.example.com http_port=80
web2.example.com http_port=8080
[webservers:vars]
ansible_user=nginx
nginx_version=1.18

# インベントリをテスト
ansible-inventory --list
ansible-inventory --graph
```

## アドホックコマンド

### 基本コマンド構造

Ansible コマンドの基本構造：`ansible <hosts> -m <module> -a "<arguments>"`

```bash
# 接続性をテスト
ansible all -m ping
# 特定のグループを確認
ansible webservers -m ping
# すべてのホストでコマンドを実行
ansible all -m command -a "uptime"
# sudo 権限で実行
ansible all -m command -a "systemctl status nginx" --become
```

### ファイル操作

ホスト上でディレクトリ、ファイル、シンボリックリンクを作成します。

```bash
# ディレクトリを作成
ansible all -m file -a "path=/tmp/test state=directory mode=0755"
# ファイルを作成
ansible all -m file -a "path=/tmp/test.txt state=touch"
# ファイル/ディレクトリを削除
ansible all -m file -a "path=/tmp/test state=absent"
# シンボリックリンクを作成
ansible all -m file -a "src=/etc/nginx dest=/tmp/nginx state=link"
```

### パッケージ管理

異なるシステム間でパッケージをインストール、更新、削除します。

```bash
# パッケージをインストール (apt)
ansible webservers -m apt -a "name=nginx state=present" --become
# パッケージをインストール (yum)
ansible webservers -m yum -a "name=httpd state=present" --become
# すべてのパッケージを更新
ansible all -m apt -a "upgrade=dist" --become
# パッケージを削除
ansible all -m apt -a "name=apache2 state=absent" --become
```

### サービス管理

システムサービスを開始、停止、管理します。

```bash
# サービスを開始
ansible webservers -m service -a "name=nginx state=started" --become
# サービスを停止
ansible webservers -m service -a "name=apache2 state=stopped" --become
# サービスを再起動
ansible webservers -m service -a "name=ssh state=restarted" --become
# ブート時にサービスを有効化
ansible all -m service -a "name=nginx enabled=yes" --become
```

## プレイブックとタスク

### 基本的なプレイブック構造

どのタスクをどのホストで実行するかを定義する YAML ファイル。

```yaml
---
- name: Web サーバー設定
  hosts: webservers
  become: yes
  vars:
    nginx_port: 80

  tasks:
    - name: nginx をインストール
      apt:
        name: nginx
        state: present

    - name: nginx サービスを開始
      service:
        name: nginx
        state: started
        enabled: yes
```

### プレイブックの実行

様々なオプションと設定でプレイブックを実行します。

```bash
# プレイブックを実行
ansible-playbook site.yml
# 特定のインベントリで実行
ansible-playbook -i inventory.yml site.yml
# ドライラン (チェックモード)
ansible-playbook site.yml --check
# 特定のホストで実行
ansible-playbook site.yml --limit webservers
# 追加変数で実行
ansible-playbook site.yml --extra-vars "nginx_port=8080"
```

### タスクオプションと条件分岐

タスクに条件、ループ、エラー処理を追加します。

```yaml
tasks:
  - name: パッケージをインストール
    apt:
      name: '{{ item }}'
      state: present
    loop:
      - nginx
      - mysql-server
      - php
    when: ansible_os_family == "Debian"

  - name: ユーザーを作成
    user:
      name: webuser
      state: present
    register: user_result

  - name: ユーザー作成結果を表示
    debug:
      msg: 'ユーザー作成済み：{{ user_result.changed }}'
```

### ハンドラと通知

タスクから通知されたときに実行されるハンドラを定義します。

```yaml
tasks:
  - name: nginx 設定を更新
    template:
      src: nginx.conf.j2
      dest: /etc/nginx/nginx.conf
    notify: nginx を再起動

handlers:
  - name: nginx を再起動
    service:
      name: nginx
      state: restarted
```

## 変数とテンプレート

### 変数の定義

異なるレベルとスコープで変数を定義します。

```yaml
# プレイブック内
vars:
  app_name: myapp
  app_port: 8080

# group_vars/all.yml 内
database_host: db.example.com
database_port: 5432

# host_vars/web1.yml 内
server_role: frontend
max_connections: 100

# コマンドライン変数
ansible-playbook site.yml -e "env=production"
```

### Jinja2 テンプレート

テンプレートを使用して動的な設定ファイルを作成します。

```jinja2
# テンプレートファイル: nginx.conf.j2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};

    location / {
        proxy_pass http://{{ backend_host }}:{{ backend_port }};
    }
}
```

```yaml
# template モジュールを使用
- name: nginx 設定をデプロイ
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/sites-available/default
  notify: nginx をリロード
```

### ファクトとシステム情報

プレイブック内でシステムファクトを収集し、使用します。

```bash
# ファクトを手動で収集
ansible all -m setup
# 特定のファクトを収集
ansible all -m setup -a "filter=ansible_eth*"
```

```yaml
# プレイブックでファクトを使用
- name: システム情報を表示
  debug:
    msg: '{{ ansible_hostname }} は {{ ansible_distribution }} を実行中'

- name: OS に基づいてパッケージをインストール
  apt:
    name: apache2
  when: ansible_os_family == "Debian"
```

### Vault とシークレット管理

Ansible Vault を使用して機密データを暗号化します。

```bash
# 暗号化されたファイルを作成
ansible-vault create secrets.yml
# 暗号化されたファイルを編集
ansible-vault edit secrets.yml
# 既存のファイルを暗号化
ansible-vault encrypt passwords.yml
# Vault を使用してプレイブックを実行
ansible-playbook site.yml --ask-vault-pass
# Vault パスワードファイルを使用
ansible-playbook site.yml --vault-password-file .vault_pass
```

## ロールと構成

### ロール構造

プレイブックを再利用可能なロールに整理します。

```bash
# ロール構造を作成
ansible-galaxy init webserver
```

```
# ロールディレクトリ構造
webserver/
├── tasks/
│   └── main.yml
├── handlers/
│   └── main.yml
├── templates/
├── files/
├── vars/
│   └── main.yml
├── defaults/
│   └── main.yml
└── meta/
    └── main.yml
```

### プレイブックでのロールの使用

プレイブック内でホストにロールを適用します。

```yaml
---
- hosts: webservers
  roles:
    - common
    - webserver
    - { role: database, database_type: mysql }

# または include_role を使用
- hosts: webservers
  tasks:
    - include_role:
        name: webserver
      vars:
        nginx_port: 8080
```

### Ansible Galaxy

Ansible Galaxy からコミュニティロールをダウンロードして管理します。

```bash
# Galaxy からロールをインストール
ansible-galaxy install geerlingguy.nginx
# 特定のバージョンをインストール
ansible-galaxy install geerlingguy.nginx,2.8.0
# 要件ファイルからインストール
ansible-galaxy install -r requirements.yml
# インストールされているロールを一覧表示
ansible-galaxy list
# ロールを削除
ansible-galaxy remove geerlingguy.nginx
```

### コレクション

Ansible コレクションを使用して拡張機能で作業します。

```bash
# コレクションをインストール
ansible-galaxy collection install community.general
```

```yaml
# プレイブックでコレクションを使用
collections:
  - community.general
tasks:
  - name: パッケージをインストール
    community.general.snap:
      name: code
      state: present
```

## デバッグとトラブルシューティング

### タスクのデバッグ

プレイブックの実行をデバッグおよびトラブルシューティングします。

```yaml
# デバッグタスクを追加
- name: 変数の値の表示
  debug:
    var: my_variable
- name: カスタムメッセージの表示
  debug:
    msg: 'サーバー {{ inventory_hostname }} は IP {{ ansible_default_ipv4.address }} を使用'
```

```bash
# 詳細な実行
ansible-playbook site.yml -v
ansible-playbook site.yml -vvv  # 最大の詳細度
```

### エラー処理

エラーを適切に処理します。

```yaml
- name: 失敗する可能性のあるタスク
  command: /bin/false
  ignore_errors: yes

- name: rescue を持つタスク
  block:
    - command: /bin/false
  rescue:
    - debug:
        msg: 'タスクが失敗したため、rescue を実行'
  always:
    - debug:
        msg: 'これは常に実行されます'
```

### テストと検証

プレイブックをテストし、構成を検証します。

```bash
# 構文チェック
ansible-playbook site.yml --syntax-check
# タスクを一覧表示
ansible-playbook site.yml --list-tasks
# ホストを一覧表示
ansible-playbook site.yml --list-hosts
# プレイブックをステップ実行
ansible-playbook site.yml --step
# チェックモードでテスト
ansible-playbook site.yml --check --diff
```

### パフォーマンスと最適化

プレイブックのパフォーマンスと実行を最適化します。

```yaml
# タスクを並列で実行
- name: パッケージをインストール
  apt:
    name: '{{ packages }}'
  vars:
    packages:
      - nginx
      - mysql-server

# 長時間実行されるタスクに async を使用
- name: 長時間実行されるタスク
  command: /usr/bin/long-task
  async: 300
  poll: 5
```

## ベストプラクティスとヒント

### セキュリティのベストプラクティス

Ansible インフラストラクチャと操作を保護します。

```bash
# 機密情報には Ansible Vault を使用
ansible-vault create group_vars/all/vault.yml
# ホストキーチェックは慎重に使用
host_key_checking = False
# 必要な場合にのみ become を使用
become: yes
become_user: root
# プレイブックのスコープを制限
ansible-playbook site.yml --limit production
```

### コードの構成

Ansible プロジェクトを効果的に構造化します。

```
# 推奨されるディレクトリ構造
ansible-project/
├── inventories/
│   ├── production/
│   └── staging/
├── group_vars/
├── host_vars/
├── roles/
├── playbooks/
└── ansible.cfg
```

```yaml
# 意味のある名前とドキュメントを使用
- name: 説明的なタスク名
  # 複雑なロジックにはコメントを追加
```

### バージョン管理とテスト

適切なバージョン管理で Ansible コードを管理します。

```bash
# バージョン管理に Git を使用
git init
git add .
git commit -m "初期 Ansible セットアップ"
# 本番環境の前にステージングでテスト
ansible-playbook -i staging site.yml
# 選択的実行のためにタグを使用
ansible-playbook site.yml --tags "nginx,ssl"
```

## 設定と高度な機能

### Ansible 設定

設定オプションで Ansible の動作をカスタマイズします。

```ini
# ansible.cfg
[defaults]
inventory = ./inventory
remote_user = ansible
host_key_checking = False
timeout = 30
forks = 5

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
pipelining = True
```

### コールバックプラグイン

コールバックプラグインで出力とロギングを強化します。

```ini
# ansible.cfg でコールバックプラグインを有効化
[defaults]
stdout_callback = yaml
callbacks_enabled = profile_tasks, timer

# カスタムコールバック設定
[callback_profile_tasks]
task_output_limit = 20
```

### フィルターとルックアップ

Jinja2 フィルターとルックアッププラグインを使用してデータを操作します。

```jinja2
# テンプレート内の一般的なフィルター
{{ variable | default('default_value') }}
{{ list_var | length }}
{{ string_var | upper }}
{{ dict_var | to_nice_yaml }}
```

```yaml
# ルックアッププラグイン
- name: ファイルの内容を読み込む
  debug:
    msg: "{{ lookup('file', '/etc/hostname') }}"

- name: 環境変数
  debug:
    msg: "{{ lookup('env', 'HOME') }}"
```

### 動的インベントリ

クラウドやコンテナ環境のために動的インベントリを使用します。

```bash
# AWS EC2 動的インベントリ
ansible-playbook -i ec2.py site.yml
# Docker 動的インベントリ
ansible-playbook -i docker.yml site.yml
# カスタムインベントリスクリプト
ansible-playbook -i ./dynamic_inventory.py site.yml
```

## 関連リンク

- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/kubernetes">Kubernetes チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>

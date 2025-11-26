---
title: 'サイバーセキュリティチートシート'
description: '必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートでサイバーセキュリティを学ぶ。'
pdfUrl: '/cheatsheets/pdf/cybersecurity-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
サイバーセキュリティ チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/cybersecurity">ハンズオンラボでサイバーセキュリティを学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと現実世界のシナリオを通じてサイバーセキュリティを学びましょう。LabEx は、脅威の特定、セキュリティ評価、システム強化、インシデント対応、監視技術を網羅した包括的なサイバーセキュリティコースを提供します。業界標準のツールとベストプラクティスを使用して、サイバー脅威からシステムとデータを保護する方法を学びます。
</base-disclaimer-content>
</base-disclaimer>

## システムセキュリティの基礎

### ユーザーアカウント管理

システムとデータへのアクセスを制御します。

```bash
# 新しいユーザーの追加
sudo adduser username
# パスワードポリシーの設定
sudo passwd -l username
# sudo権限の付与
sudo usermod -aG sudo username
# ユーザー情報の表示
id username
# 全ユーザーのリスト表示
cat /etc/passwd
```

### ファイルパーミッションとセキュリティ

安全なファイルおよびディレクトリのアクセスを設定します。

```bash
# ファイルパーミッションの変更 (読み取り、書き込み、実行)
chmod 644 file.txt
# 所有権の変更
chown user:group file.txt
# パーミッションの再帰的設定
chmod -R 755 directory/
# ファイルパーミッションの表示
ls -la
```

### ネットワークセキュリティ設定

ネットワーク接続とサービスを保護します。

```bash
# ファイアウォール (UFW) の設定
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw deny 23/tcp
# 開いているポートの確認
netstat -tuln
sudo ss -tuln
```

### システムアップデートとパッチ

システムを最新のセキュリティパッチで最新の状態に保ちます。

```bash
# パッケージリストの更新 (Ubuntu/Debian)
sudo apt update
# 全パッケージのアップグレード
sudo apt upgrade
# 自動セキュリティアップデート
sudo apt install unattended-upgrades
```

### サービス管理

システムサービスを制御および監視します。

```bash
# 不要なサービスの停止
sudo systemctl stop service_name
sudo systemctl disable service_name
# サービスステータスの確認
sudo systemctl status ssh
# 実行中のサービスの表示
systemctl list-units --type=service --state=running
```

### ログ監視

セキュリティイベントのためにシステムログを監視します。

```bash
# 認証ログの表示
sudo tail -f /var/log/auth.log
# システムログの確認
sudo journalctl -f
# ログイン失敗の検索
grep "Failed password" /var/log/auth.log
```

## パスワードセキュリティと認証

強力な認証メカニズムとパスワードポリシーを実装します。

### 強力なパスワードの作成

ベストプラクティスに従って安全なパスワードを生成・管理します。

```bash
# 強力なパスワードの生成
openssl rand -base64 32
# パスワードの強度要件:
# - 最小12文字
# - 大文字、小文字、数字、記号の組み合わせ
# - 辞書語や個人情報は使用しない
# - アカウントごとに一意であること
```

### 多要素認証 (MFA)

パスワード以外に追加の認証レイヤーを追加します。

```bash
# Google Authenticatorのインストール
sudo apt install libpam-googleauthenticator
# SSHでのMFAの設定
google-authenticator
# SSH設定での有効化
sudo nano /etc/pam.d/sshd
# 追加: auth required pam_google_authenticator.so
```

### パスワード管理

パスワードマネージャーと安全なストレージプラクティスを使用します。

```bash
# パスワードマネージャーのインストール (KeePassXC)
sudo apt install keepassxc
# ベストプラクティス:
# - 各サービスに一意のパスワードを使用する
# - 自動ロック機能を有効にする
# - 重要なアカウントの定期的なパスワードローテーション
# - パスワードデータベースの安全なバックアップ
```

## ネットワークセキュリティと監視

### ポートスキャンと検出

開いているポートと実行中のサービスを特定します。

```bash
# Nmapによる基本的なポートスキャン
nmap -sT target_ip
# サービスバージョンの検出
nmap -sV target_ip
# 総合スキャン
nmap -A target_ip
# 特定のポートのスキャン
nmap -p 22,80,443 target_ip
# IP範囲のスキャン
nmap 192.168.1.1-254
```

### ネットワークトラフィック分析

ネットワーク通信を監視および分析します。

```bash
# tcpdumpによるパケットキャプチャ
sudo tcpdump -i eth0
# ファイルへの保存
sudo tcpdump -w capture.pcap
# 特定のトラフィックのフィルタリング
sudo tcpdump host 192.168.1.1
# 特定のポートの監視
sudo tcpdump port 80
```

### ファイアウォール設定

送受信のネットワークトラフィックを制御します。

```bash
# UFW (Uncomplicated Firewall)
sudo ufw status
sudo ufw allow ssh
sudo ufw deny 23
# iptablesルール
sudo iptables -L
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

### SSL/TLS証明書管理

暗号化による安全な通信を実装します。

```bash
# 自己署名証明書の発行
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
# 証明書詳細の確認
openssl x509 -in cert.pem -text -noout
# SSL接続のテスト
openssl s_client -connect example.com:443
```

## 脆弱性評価

### システム脆弱性スキャン

システムとアプリケーションのセキュリティ上の弱点を特定します。

```bash
# Nessusスキャナーのインストール
# tenable.comからダウンロード
sudo dpkg -i Nessus-X.X.X-ubuntu1404_amd64.deb
# Nessusサービスの起動
sudo systemctl start nessusd
# Webインターフェースにhttps://localhost:8834でアクセス
# OpenVASの使用 (無料の代替手段)
sudo apt install openvas
sudo gvm-setup
```

### Web アプリケーションセキュリティテスト

一般的な脆弱性に対する Web アプリケーションのテスト。

```bash
# Nikto Webスキャナーの使用
nikto -h http://target.com
# ディレクトリ列挙
dirb http://target.com
# SQLインジェクションテスト
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

### セキュリティ監査ツール

包括的なセキュリティ評価ユーティリティ。

```bash
# Lynisセキュリティ監査
sudo apt install lynis
sudo lynis audit system
# ルートキットの確認
sudo apt install chkrootkit
sudo chkrootkit
# ファイル整合性監視
sudo apt install aide
sudo aideinit
```

### 設定セキュリティ

安全なシステムおよびアプリケーション設定の検証。

```bash
# SSHセキュリティチェック
ssh-audit target_ip
# SSL設定テスト
testssl.sh https://target.com
# 秘密ファイルに対するファイルパーミッションの確認
ls -la /etc/shadow /etc/passwd /etc/group
```

## インシデント対応とフォレンジック

### ログ分析と調査

システムログを分析してセキュリティインシデントを特定します。

```bash
# 不審なアクティビティの検索
grep -i "failed\|error\|denied" /var/log/auth.log
# ログイン失敗回数のカウント
grep "Failed password" /var/log/auth.log | wc -l
# ログ内のユニークなIPアドレスの検索
awk '/Failed password/ {print $11}' /var/log/auth.log | sort | uniq -c
# ライブログアクティビティの監視
tail -f /var/log/syslog
```

### ネットワークフォレンジック

ネットワークベースのセキュリティインシデントを調査します。

```bash
# Wiresharkによるネットワークトラフィックの分析
# インストール: sudo apt install wireshark
# ライブトラフィックのキャプチャ
sudo wireshark
# キャプチャファイルの分析
wireshark capture.pcap
# tsharkによるコマンドライン分析
tshark -r capture.pcap -Y "http.request"
```

### システムフォレンジック

デジタル証拠の保全と分析。

```bash
# ディスクイメージの作成
sudo dd if=/dev/sda of=/mnt/evidence/disk_image.dd bs=4096
# 整合性のためのファイルハッシュの計算
md5sum important_file.txt
sha256sum important_file.txt
# 特定のファイルコンテンツの検索
grep -r "password" /home/user/
# 最近変更されたファイルのリスト表示
find /home -mtime -7 -type f
```

### インシデント文書化

分析のためにセキュリティインシデントを適切に文書化します。

```bash
# インシデント対応チェックリスト:
# 1. 影響を受けたシステムの隔離
# 2. 証拠の保全
# 3. イベントのタイムラインの文書化
# 4. 攻撃ベクトルの特定
# 5. 被害とデータ漏洩の評価
# 6. 封じ込め措置の実施
# 7. 回復手順の計画
```

## 脅威インテリジェンス

現在の脅威と新たなセキュリティ脅威に関する情報を収集・分析します。

### OSINT (オープンソースインテリジェンス)

公開されている脅威情報を収集します。

```bash
# ドメイン情報の検索
whois example.com
# DNSルックアップ
dig example.com
nslookup example.com
# サブドメインの検索
sublist3r -d example.com
# 評判データベースの確認
# VirusTotal, URLVoid, AbuseIPDB
```

### 脅威ハンティングツール

環境内で積極的に脅威を検索します。

```bash
# IOC (侵害の痕跡) 検索
grep -r "suspicious_hash" /var/log/
# 悪意のあるIPの確認
grep "192.168.1.100" /var/log/auth.log
# ファイルハッシュの比較
find /tmp -type f -exec sha256sum {} \;
```

### 脅威フィードとインテリジェンス

最新の脅威情報で最新の状態を維持します。

```bash
# 主要な脅威インテリジェンスソース:
# - MISP (Malware Information Sharing Platform)
# - STIX/TAXII フィード
# - 商用フィード (CrowdStrike, FireEye)
# - 政府フィード (US-CERT, CISA)
# 例: 脅威フィードに対してIPをチェック
curl -s "https://api.threatintel.com/check?ip=1.2.3.4"
```

### 脅威モデリング

潜在的なセキュリティ脅威を特定し評価します。

```bash
# STRIDE脅威モデルのカテゴリ:
# - なりすまし (ID)
# - データの改ざん (データ)
# - 否認 (アクション)
# - 情報漏洩
# - サービス拒否 (DoS)
# - 権限昇格
```

## 暗号化とデータ保護

機密データを保護するために強力な暗号化を実装します。

### ファイルとディスクの暗号化

保存時のデータを保護するためにファイルとストレージデバイスを暗号化します。

```bash
# GPGによるファイルの暗号化
gpg -c sensitive_file.txt
# ファイルの復号化
gpg sensitive_file.txt.gpg
# LUKSによるフルディスク暗号化
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup luksOpen /dev/sdb encrypted_drive
# SSHキーの生成
ssh-keygen -t rsa -b 4096
# SSHキー認証の設定
ssh-copy-id user@server
```

### ネットワーク暗号化

暗号化プロトコルでネットワーク通信を保護します。

```bash
# OpenVPNによるVPNセットアップ
sudo apt install openvpn
sudo openvpn --config client.ovpn
```

### 証明書管理

安全な通信のためにデジタル証明書を管理します。

```bash
# 認証局 (CA) の作成
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -key ca-key.pem -out ca.pem
# サーバー証明書の発行
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr
# CAによる証明書への署名
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -out server.pem
```

### データ損失防止 (DLP)

不正なデータ流出や漏洩を防ぎます。

```bash
# ファイルアクセス監視
sudo apt install auditd
# 監査ルールの設定
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
# 監査ログの検索
sudo ausearch -k passwd_changes
```

## セキュリティの自動化とオーケストレーション

セキュリティタスクと対応手順を自動化します。

### セキュリティスキャン自動化

定期的なセキュリティスキャンと評価をスケジュールします。

```bash
# 自動Nmapスキャン スクリプト
#!/bin/bash
DATE=$(date +%Y-%m-%d)
nmap -sS -O 192.168.1.0/24 > /var/log/nmap-scan-$DATE.log
# cronによるスケジュール設定
# 0 2 * * * /path/to/security-scan.sh
```

```bash
# 自動脆弱性スキャン
#!/bin/bash
nikto -h $1 -o /var/log/nikto-$(date +%Y%m%d).txt
```

### ログ監視スクリプト

ログ分析とアラートを自動化します。

```bash
# ログイン失敗の監視
#!/bin/bash
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | tail -n 100 | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    echo "High number of failed logins detected: $FAILED_LOGINS" | mail -s "Security Alert" admin@company.com
fi
```

### インシデント対応の自動化

初期のインシデント対応手順を自動化します。

```bash
# 疑わしいIPの自動対応スクリプト
#!/bin/bash
SUSPICIOUS_IP=$1
# ファイアウォールでのIPブロック
sudo ufw deny from $SUSPICIOUS_IP
# アクションのログ記録
echo "$(date): Blocked suspicious IP $SUSPICIOUS_IP" >> /var/log/security-actions.log
# アラートの送信
echo "Blocked suspicious IP: $SUSPICIOUS_IP" | mail -s "IP Blocked" security@company.com
```

### 構成管理

安全なシステム構成を維持します。

```bash
# Ansibleセキュリティプレイブックの例
---
- name: Harden SSH configuration
  hosts: all
  tasks:
    - name: Disable root login
      lineinfile:
        path: /etc/ssh/sshd_config
        line: 'PermitRootLogin no'
    - name: Restart SSH service
      service:
        name: sshd
        state: restarted
```

## コンプライアンスとリスク管理

セキュリティポリシーと手順を実装し維持します。

### セキュリティポリシーの実装

セキュリティポリシーと手順を実装し維持します。

```bash
# PAMによるパスワードポリシーの強制
sudo nano /etc/pam.d/common-password
# 追加: password required pam_pwquality.so minlen=12
# アカウントロックアウトポリシー
sudo nano /etc/pam.d/common-auth
# 追加: auth required pam_tally2.so deny=5 unlock_time=900
```

### 監査とコンプライアンスチェック

セキュリティ標準および規制へのコンプライアンスを確認します。

```bash
# CIS (Center for Internet Security) ベンチマークツール
sudo apt install cis-cat-lite
# CIS評価の実行
./CIS-CAT.sh -a -s
```

### リスク評価ツール

セキュリティリスクを評価し定量化します。

```bash
# リスクマトリックス計算:
# リスク = 発生可能性 × 影響度
# 低 (1-3)、中 (4-6)、高 (7-9)
# 脆弱性の優先順位付け
# CVSSスコア計算
# 基本スコア = 影響度 × 悪用可能性
```

### 文書化とレポート作成

適切なセキュリティ文書化とレポート作成を維持します。

```bash
# セキュリティインシデントレポートテンプレート:
# - インシデントの日時
# - 影響を受けたシステム
# - 特定された攻撃ベクトル
# - 侵害されたデータ
# - 実行されたアクション
# - 学んだ教訓
# - 修復計画
```

## セキュリティツールのインストール

必須のサイバーセキュリティツールをインストールし設定します。

### パッケージマネージャー

システムパッケージマネージャーを使用してツールをインストールします。

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap wireshark tcpdump
# CentOS/RHEL
sudo yum install nmap wireshark tcpdump
# Arch Linux
sudo pacman -S nmap wireshark-qt tcpdump
```

### セキュリティディストリビューション

セキュリティ専門家向けの専門的な Linux ディストリビューション。

```bash
# Kali Linux - ペネトレーションテスト用
# ダウンロード元: https://www.kali.org/
# Parrot Security OS
# ダウンロード元: https://www.parrotsec.org/
# BlackArch Linux
# ダウンロード元: https://blackarch.org/
```

### ツール検証

ツールのインストールと基本的な設定を確認します。

```bash
# ツールバージョンの確認
nmap --version
wireshark --version
# 基本的な機能テスト
nmap 127.0.0.1
# ツールパスの設定
export PATH=$PATH:/opt/tools/bin
echo 'export PATH=$PATH:/opt/tools/bin' >> ~/.bashrc
```

## セキュリティ設定のベストプラクティス

システムおよびアプリケーション全体でセキュリティ強化設定を適用します。

### システム強化

オペレーティングシステムのセキュリティ設定。

```bash
# 不要なサービスの無効化
sudo systemctl disable telnet
sudo systemctl disable ftp
# 安全なファイルパーミッションの設定
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 644 /etc/passwd
# システム制限の設定
echo "* hard core 0" >> /etc/security/limits.conf
```

### ネットワークセキュリティ設定

安全なネットワーク構成を実装します。

```bash
# IPフォワーディングの無効化 (ルーターでない場合)
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
# SYNクッキーの有効化
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
# ICMPリダイレクトの無効化
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
```

### アプリケーションセキュリティ

アプリケーションおよびサービスの設定を保護します。

```bash
# Apacheセキュリティヘッダー
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
# Nginxセキュリティ設定
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
```

### バックアップとリカバリのセキュリティ

安全なバックアップおよび災害復旧手順を実装します。

```bash
# rsyncによる暗号化バックアップ
rsync -av --password-file=/etc/rsyncd.secrets /data/ backup@server::backups/
# バックアップの整合性テスト
tar -tzf backup.tar.gz > /dev/null && echo "Backup OK"
# 自動バックアップ検証
#!/bin/bash
find /backups -name "*.tar.gz" -exec tar -tzf {} \; > /dev/null
```

## 高度なセキュリティ技術

高度なセキュリティ対策と防御戦略を実装します。

### 侵入検知システム

脅威検出のために IDS/IPS を導入し設定します。

```bash
# Suricata IDSのインストール
sudo apt install suricata
# ルールの設定
sudo nano /etc/suricata/suricata.yaml
# ルールの更新
sudo suricata-update
# Suricataの起動
sudo systemctl start suricata
# アラートの監視
tail -f /var/log/suricata/fast.log
```

### セキュリティ情報イベント管理 (SIEM)

セキュリティログとイベントを一元化し分析します。

```bash
# ELKスタック (Elasticsearch, Logstash, Kibana)
# Elasticsearchのインストール
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update && sudo apt install elasticsearch
```

## セキュリティ意識向上トレーニング

ソーシャルエンジニアリング攻撃を認識し防止します。

### ソーシャルエンジニアリング防御

ソーシャルエンジニアリング攻撃を認識し防止します。

```bash
# フィッシングの特定技術:
# - 送信元メールアドレスを注意深く確認する
# - クリックする前にリンクを確認する (ホバー)
# - スペルミスや文法ミスに注意する
# - 緊急の要求に疑いを持つ
# - 別のチャネルを通じて要求を確認する
# 確認すべきメールセキュリティヘッダー:
# SPF, DKIM, DMARCレコード
```

### セキュリティ文化の醸成

セキュリティ意識の高い組織文化を構築します。

```bash
# セキュリティ意識向上プログラムの要素:
# - 定期的なトレーニングセッション
# - フィッシングシミュレーションテスト
# - セキュリティポリシーの更新
# - インシデント報告手順
# - 優れたセキュリティプラクティスに対する表彰
# 追跡すべき指標:
# - トレーニング完了率
# - フィッシングシミュレーションのクリック率
# - セキュリティインシデント報告件数
```

## 関連リンク

- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/kali">Kali Linux チートシート</router-link>
- <router-link to="/nmap">Nmap チートシート</router-link>
- <router-link to="/wireshark">Wireshark チートシート</router-link>
- <router-link to="/hydra">Hydra チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/git">Git チートシート</router-link>

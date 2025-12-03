---
title: 'Nmap チートシート | LabEx'
description: 'この包括的なチートシートで Nmap ネットワークスキャンを学ぶ。ポートスキャン、ネットワーク検出、脆弱性検出、セキュリティ監査、ネットワーク偵察のためのクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/nmap-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Nmap チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/nmap">ハンズオンラボで Nmap を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、Nmap ネットワークスキャンを学びましょう。LabEx は、必須のネットワークディスカバリ、ポートスキャン、サービス検出、OS フィンガープリンティング、脆弱性評価を網羅した包括的な Nmap コースを提供します。ネットワーク偵察とセキュリティ監査の技術を習得してください。
</base-disclaimer-content>
</base-disclaimer>

## インストールとセットアップ

### Linux インストール

お使いのディストリビューションのパッケージマネージャを使用して Nmap をインストールします。

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap
# RHEL/Fedora/CentOS
sudo dnf install nmap
# インストール確認
nmap --version
```

### macOS インストール

Homebrew パッケージマネージャを使用してインストールします。

```bash
# Homebrew経由でインストール
brew install nmap
# nmap.orgから直接ダウンロード
# https://nmap.org/download.html から .dmg をダウンロード
```

### Windows インストール

公式ウェブサイトからダウンロードしてインストールします。

```bash
# 公式サイトからインストーラをダウンロード
https://nmap.org/download.html
# 管理者権限で .exe インストーラを実行
# Zenmap GUIとコマンドライン版が含まれます
```

### 基本的な確認

インストールを確認し、ヘルプを表示します。

```bash
# バージョン情報を表示
nmap --version
# ヘルプメニューを表示
nmap -h
# 詳細なヘルプとオプション
man nmap
```

## 基本的なスキャン技術

### シンプルなホストスキャン：`nmap [ターゲット]`

単一のホストまたは IP アドレスのスキャン。

```bash
# 単一IPのスキャン
nmap 192.168.1.1
# ホスト名のスキャン
nmap example.com
# 複数IPのスキャン
nmap 192.168.1.1 192.168.1.5
192.168.1.10
```

<BaseQuiz id="nmap-scan-1" correct="A">
  <template #question>
    基本的な <code>nmap 192.168.1.1</code> スキャンはデフォルトで何を行いますか？
  </template>
  
  <BaseQuizOption value="A" correct>最も一般的な 1000 の TCP ポートをスキャンする</BaseQuizOption>
  <BaseQuizOption value="B">全 65535 ポートをスキャンする</BaseQuizOption>
  <BaseQuizOption value="C">ホストディスカバリのみを実行する</BaseQuizOption>
  <BaseQuizOption value="D">ポート 80 のみをスキャンする</BaseQuizOption>
  
  <BaseQuizAnswer>
    デフォルトでは、Nmap は最も一般的な 1000 の TCP ポートをスキャンします。全ポートをスキャンするには <code>-p-</code> を使用するか、<code>-p 80,443,22</code> で特定のポートを指定します。
  </BaseQuizAnswer>
</BaseQuiz>

### ネットワーク範囲スキャン

Nmap はホスト名、IP アドレス、サブネットを指定できます。

```bash
# IP範囲のスキャン
nmap 192.168.1.1-254
# CIDR表記でのサブネットのスキャン
nmap 192.168.1.0/24
# 複数ネットワークのスキャン
nmap 192.168.1.0/24 10.0.0.0/8
```

### ファイルからの入力

ファイルに記載されたターゲットをスキャンします。

```bash
# ファイルからターゲットを読み込む
nmap -iL targets.txt
# 特定のホストを除外
nmap 192.168.1.0/24 --exclude
192.168.1.1
# ファイルから除外
nmap 192.168.1.0/24 --excludefile
exclude.txt
```

## ホストディスカバ技術

### Ping スキャン：`nmap -sn`

ホストディスカバリは、多くの分析者やペンテスターが Nmap を使用する主要な方法です。その目的は、どのシステムがオンラインであるかの概要を把握することです。

```bash
# Pingスキャンのみ（ポートスキャンなし）
nmap -sn 192.168.1.0/24
# ホストディスカバリをスキップ（全ホストが稼働していると仮定）
nmap -Pn 192.168.1.1
# ICMPエコーping
nmap -PE 192.168.1.0/24
```

<BaseQuiz id="nmap-ping-1" correct="A">
  <template #question>
    <code>nmap -sn</code> は何を行いますか？
  </template>
  
  <BaseQuizOption value="A" correct>ポートスキャンを行わず、ホストディスカバリのみを実行する</BaseQuizOption>
  <BaseQuizOption value="B">ターゲットの全ポートをスキャンする</BaseQuizOption>
  <BaseQuizOption value="C">ステルススキャンを実行する</BaseQuizOption>
  <BaseQuizOption value="D">UDP ポートのみをスキャンする</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-sn</code> フラグは、Nmap にホストディスカバリ（ping スキャン）のみを実行し、ポートスキャンは行わないように指示します。これは、ネットワーク上でどのホストがオンラインであるかを素早く特定するのに役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

### TCP Ping 技術

ホストディスカバリに TCP パケットを使用します。

```bash
# ポート80へのTCP SYN ping
nmap -PS80 192.168.1.0/24
# TCP ACK ping
nmap -PA80 192.168.1.0/24
# 複数ポートへのTCP SYN ping
nmap -PS22,80,443 192.168.1.0/24
```

### UDP Ping: `nmap -PU`

ホストディスカバリに UDP パケットを使用します。

```bash
# 一般的なポートへのUDP ping
nmap -PU53,67,68,137 192.168.1.0/24
```

<BaseQuiz id="nmap-udp-1" correct="B">
  <template #question>
    ICMP ping の代わりに UDP ping を使用する理由は何ですか？
  </template>
  
  <BaseQuizOption value="A">UDP ping は常に高速である</BaseQuizOption>
  <BaseQuizOption value="B" correct>一部のネットワークは ICMP をブロックするが UDP パケットは許可する</BaseQuizOption>
  <BaseQuizOption value="C">UDP ping はポートを自動的にスキャンする</BaseQuizOption>
  <BaseQuizOption value="D">UDP ping はローカルネットワークでのみ機能する</BaseQuizOption>
  
  <BaseQuizAnswer>
    UDP ping は、ファイアウォールによって ICMP がブロックされている場合に役立ちます。多くのネットワークでは、ICMP がフィルタリングされていても、一般的なポート（DNS ポート 53 など）への UDP パケットは許可されており、ホストディスカバリに有効です。
  </BaseQuizAnswer>
</BaseQuiz>
# デフォルトポートへの UDP ping
nmap -PU 192.168.1.0/24
```

### ARP Ping: `nmap -PR`

ローカルネットワークのディスカバリにARPリクエストを使用します。

```bash
# ARP ping（ローカルネットワークのデフォルト）
nmap -PR 192.168.1.0/24
# ARP ping を無効にする
nmap --disable-arp-ping 192.168.1.0/24
```

## ポートスキャンタイプ

### TCP SYNスキャン: `nmap -sS`

このスキャンはステルス性が高く、NmapがRSTパケットを送信するため、複数のリクエストを防ぎ、スキャン時間を短縮します。

```bash
# デフォルトスキャン（root 権限が必要）
nmap -sS 192.168.1.1
# 特定ポートの SYN スキャン
nmap -sS -p 80,443 192.168.1.1
# 高速 SYN スキャン
nmap -sS -T4 192.168.1.1
```

### TCP Connectスキャン: `nmap -sT`

NmapはSYNフラグを設定したTCPパケットをポートに送信します。これにより、ポートが開いているか、閉じているか、不明であるかを知ることができます。

```bash
# TCP connect スキャン（root 権限不要）
nmap -sT 192.168.1.1
# タイミング付きの Connect スキャン
nmap -sT -T3 192.168.1.1
```

### UDPスキャン: `nmap -sU`

サービスに対してUDPポートをスキャンします。

```bash
# UDP スキャン（遅い、root 権限が必要）
nmap -sU 192.168.1.1
# 一般的な UDP ポートのスキャン
nmap -sU -p 53,67,68,161 192.168.1.1
# TCP/UDPの組み合わせスキャン
nmap -sS -sU -p T:80,443,U:53,161 192.168.1.1
```

### ステルシースキャン

エバシブ（回避）のための高度なスキャン技術。

```bash
# FIN スキャン
nmap -sF 192.168.1.1
# NULL スキャン
nmap -sN 192.168.1.1
# Xmas スキャン
nmap -sX 192.168.1.1
```

## ポート指定

### ポート範囲: `nmap -p`

より正確なスキャンのために、特定のポート、範囲、またはTCPとUDPの組み合わせをターゲットにします。

```bash
# 単一ポート
nmap -p 80 192.168.1.1
# 複数ポート
nmap -p 22,80,443 192.168.1.1
# ポート範囲
nmap -p 1-1000 192.168.1.1
# 全ポート
nmap -p- 192.168.1.1
```

### プロトコルごとのポート指定

TCPまたはUDPポートを明示的に指定します。

```bash
# TCP ポートのみ
nmap -p T:80,443 192.168.1.1
# UDP ポートのみ
nmap -p U:53,161 192.168.1.1
# TCP と UDP の混在
nmap -p T:80,U:53 192.168.1.1
```

### 一般的なポートセット

頻繁に使用されるポートを素早くスキャンします。

```bash
# トップ 1000 ポート（デフォルト）
nmap 192.168.1.1
# トップ 100 ポート
nmap --top-ports 100 192.168.1.1
# 高速スキャン（最も一般的な 100 ポート）
nmap -F 192.168.1.1
# 開いているポートのみ表示
nmap --open 192.168.1.1
# 全てのポート状態を表示
nmap -v 192.168.1.1
```

## サービスとバージョン検出

### サービス検出: `nmap -sV`

実行中のサービスと、そのソフトウェアのバージョンおよび設定を特定しようとします。

```bash
# 基本的なバージョン検出
nmap -sV 192.168.1.1
# アグレッシブなバージョン検出
nmap -sV --version-intensity 9 192.168.1.1
# 軽量なバージョン検出
nmap -sV --version-intensity 0 192.168.1.1
# バージョン検出付きのデフォルトスクリプト
nmap -sC -sV 192.168.1.1
```

### サービススクリプト

拡張されたサービス検出のためにスクリプトを使用します。

```bash
# バナーグラビング
nmap --script banner 192.168.1.1
# HTTP サービス列挙
nmap --script http-* 192.168.1.1
```

### オペレーティングシステム検出: `nmap -O`

TCP/IPフィンガープリンティングを使用して、ターゲットホストのオペレーティングシステムを推測します。

```bash
# OS 検出
nmap -O 192.168.1.1
# アグレッシブな OS 検出
nmap -O --osscan-guess 192.168.1.1
# OS 検出の試行回数を制限
nmap -O --max-os-tries 1 192.168.1.1
```

### 総合的な検出

複数の検出技術を組み合わせます。

```bash
# アグレッシブスキャン（OS、バージョン、スクリプト）
nmap -A 192.168.1.1
# カスタムアグレッシブスキャン
nmap -sS -sV -O -sC 192.168.1.1
```

## タイミングとパフォーマンス

### タイミングテンプレート: `nmap -T`

ターゲット環境と検出リスクに基づいて、スキャン速度を調整します。

```bash
# Paranoid（非常に遅い、ステルス性が高い）
nmap -T0 192.168.1.1
# Sneaky（遅い、ステルス性が高い）
nmap -T1 192.168.1.1
# Polite（遅い、帯域幅を抑える）
nmap -T2 192.168.1.1
# Normal（デフォルト）
nmap -T3 192.168.1.1
# Aggressive（より速い）
nmap -T4 192.168.1.1
# Insane（非常に速い、結果を見逃す可能性がある）
nmap -T5 192.168.1.1
```

### カスタムタイミングオプション

パフォーマンスを最適化するために、Nmapがタイムアウト、再試行、並列スキャンを処理する方法を微調整します。

```bash
# 最小レートを設定（1 秒あたりのパケット数）
nmap --min-rate 1000 192.168.1.1
# 最大レートを設定
nmap --max-rate 100 192.168.1.1
# 並列ホストスキャン
nmap --min-hostgroup 10 192.168.1.0/24
# カスタムタイムアウト
nmap --host-timeout 5m 192.168.1.1
```

## Nmap スクリプトエンジン (NSE)

### スクリプトカテゴリ: `nmap --script`

カテゴリまたは名前でスクリプトを実行します。

```bash
# デフォルトスクリプト
nmap --script default 192.168.1.1
# 脆弱性スクリプト
nmap --script vuln 192.168.1.1
# ディスカバリスクリプト
nmap --script discovery 192.168.1.1
# 認証スクリプト
nmap --script auth 192.168.1.1
```

### 特定のスクリプト

特定の脆弱性やサービスをターゲットにします。

```bash
# SMB 列挙
nmap --script smb-enum-* 192.168.1.1
# HTTP メソッド
nmap --script http-methods 192.168.1.1
# SSL 証明書情報
nmap --script ssl-cert 192.168.1.1
```

### スクリプト引数

スクリプトの動作をカスタマイズするために引数を渡します。

```bash
# カスタム単語リストを使用した HTTP ブルートフォース
nmap --script http-brute --script-args
userdb=users.txt,passdb=pass.txt 192.168.1.1
# SMB ブルートフォース
nmap --script smb-brute 192.168.1.1
# DNS ブルートフォース
nmap --script dns-brute example.com
```

### スクリプト管理

NSEスクリプトの管理と更新を行います。

```bash
# スクリプトデータベースを更新
nmap --script-updatedb
# 利用可能なスクリプトを一覧表示
ls /usr/share/nmap/scripts/ | grep http
# スクリプトのヘルプを取得
nmap --script-help vuln
```

## 出力形式と結果の保存

### 出力形式

結果を異なる形式で保存します。

```bash
# 通常出力
nmap -oN scan_results.txt 192.168.1.1
# XML 出力
nmap -oX scan_results.xml 192.168.1.1
# Grep 可能出力
nmap -oG scan_results.gnmap 192.168.1.1
# 全ての形式
nmap -oA scan_results 192.168.1.1
```

### 詳細出力

表示される情報の量を制御します。

```bash
# 詳細出力
nmap -v 192.168.1.1
# 非常に詳細
nmap -vv 192.168.1.1
# デバッグモード
nmap --packet-trace 192.168.1.1
```

### 再開と追記

以前のスキャンを続行または追加します。

```bash
# 中断されたスキャンを再開
nmap --resume scan_results.gnmap
# 既存のファイルに追記
nmap --append-output -oN existing_scan.txt 192.168.1.1
```

### ライブ結果の処理

Nmapの出力をコマンドラインツールと組み合わせて、有用な洞察を抽出します。

```bash
# 稼働中のホストを抽出
nmap -sn 192.168.1.0/24 | grep "Nmap scan report"
# Web サーバーを見つける
nmap -p 80,443,8080,8443 --open 192.168.1.0/24 | grep "open"
# CSV にエクスポート
nmap -oX - 192.168.1.1 | xsltproc --html -
```

## ファイアウォール回避技術

### パケットフラグメンテーション: `nmap -f`

パケットのフラグメンテーション、IPアドレスのなりすまし、ステルススキャンを使用してセキュリティ対策を回避します。

```bash
# パケットをフラグメント化
nmap -f 192.168.1.1
# カスタム MTU サイズ
nmap --mtu 16 192.168.1.1
# 最大伝送単位
nmap --mtu 24 192.168.1.1
```

### デコイ（おとり）スキャン: `nmap -D`

おとりIPアドレスの中にスキャンを隠します。

```bash
# おとり IP アドレスを使用
nmap -D 192.168.1.100,192.168.1.101 192.168.1.1
# ランダムなおとり
nmap -D RND:5 192.168.1.1
# 実際のおとりとランダムなおとりの混合
nmap -D 192.168.1.100,RND:3 192.168.1.1
```

### 送信元IP/ポート操作

送信元情報を偽装します。

```bash
# 送信元 IP を偽装
nmap -S 192.168.1.100 192.168.1.1
# カスタム送信元ポート
nmap --source-port 53 192.168.1.1
# ランダムなデータ長
nmap --data-length 25 192.168.1.1
```

### アイドル/ゾンビスキャン: `nmap -sI`

ゾンビホストを使用してスキャンの起源を隠します。

```bash
# ゾンビスキャン（アイドルホストが必要）
nmap -sI zombie_host 192.168.1.1
# アイドル候補をリスト表示
nmap --script ipidseq 192.168.1.0/24
```

## 高度なスキャンオプション

### DNS解決の制御

NmapがDNSルックアップをどのように処理するかを制御します。

```bash
# DNS 解決を無効にする
nmap -n 192.168.1.1
# DNS 解決を強制する
nmap -R 192.168.1.1
# カスタム DNS サーバー
nmap --dns-servers 8.8.8.8,1.1.1.1 192.168.1.1
```

### IPv6スキャン: `nmap -6`

IPv6サポートなどの追加機能には、これらのNmapフラグを使用します。

```bash
# IPv6 スキャン
nmap -6 2001:db8::1
# IPv6 ネットワークスキャン
nmap -6 2001:db8::/32
```

### インターフェースとルーティング

ネットワークインターフェースとルーティングを制御します。

```bash
# ネットワークインターフェースの指定
nmap -e eth0 192.168.1.1
# インターフェースとルートの表示
nmap --iflist
# 経路トレース
nmap --traceroute 192.168.1.1
```

### その他のオプション

追加の便利なフラグ。

```bash
# バージョン情報を表示して終了
nmap --version
# イーサネットレベルで送信
nmap --send-eth 192.168.1.1
# IP レベルで送信
nmap --send-ip 192.168.1.1
```

## 実世界の例

### ネットワークディスカバリワークフロー

完全なネットワーク列挙プロセス。

```bash
# ステップ 1: 稼働中のホストを発見
nmap -sn 192.168.1.0/24
# ステップ 2: クイックポートスキャン
nmap -sS -T4 --top-ports 1000 192.168.1.0/24
# ステップ 3: 興味深いホストの詳細スキャン
nmap -sS -sV -sC -O 192.168.1.50
# ステップ 4: 総合スキャン
nmap -p- -A -T4 192.168.1.50
```

### Webサーバー評価

Webサービスと脆弱性に焦点を当てます。

```bash
# Web サーバーを見つける
nmap -sS -p 80,443,8080,8443 --open 192.168.1.0/24
# HTTP サービスを列挙
nmap -sS -sV --script http-* 192.168.1.50
# 一般的な脆弱性をチェック
nmap --script vuln -p 80,443 192.168.1.50
```

### SMB/NetBIOS列挙

以下の例は、ターゲットネットワーク上のNetbiosを列挙します。

```bash
# SMB サービス検出
nmap -sV -p 139,445 192.168.1.0/24
# NetBIOS 名前解決
nmap -sU --script nbstat -p 137 192.168.1.0/24
# SMB 列挙スクリプト
nmap --script smb-enum-* -p 445 192.168.1.50
# SMB 脆弱性チェック
nmap --script smb-vuln-* -p 445 192.168.1.50
```

### ステルス評価

低プロファイルの偵察。

```bash
# ウルトラステルススキャン
nmap -sS -T0 -f --data-length 200 -D RND:10 192.168.1.1
# フラグメント化された SYN スキャン
nmap -sS -f --mtu 8 -T1 192.168.1.1
```

## パフォーマンスの最適化

### 高速スキャン戦略

大規模ネットワークのスキャン速度を最適化します。

```bash
# 高速ネットワークスイープ
nmap -sS -T4 --min-rate 1000 --max-retries 1
192.168.1.0/24
# 並列ホストスキャン
nmap --min-hostgroup 50 --max-hostgroup 100
192.168.1.0/24
# 遅い操作をスキップ
nmap -sS -T4 --defeat-rst-ratelimit 192.168.1.0/24
```

### メモリとリソース管理

安定性のためにリソース使用量を制御します。

```bash
# 並列プローブの制限
nmap --max-parallelism 10 192.168.1.0/24
# スキャン遅延の制御
nmap --scan-delay 100ms 192.168.1.1
# ホストタイムアウトの設定
nmap --host-timeout 10m 192.168.1.0/24
```

## 関連リンク

- <router-link to="/wireshark">Wireshark チートシート</router-link>
- <router-link to="/kali">Kali Linux チートシート</router-link>
- <router-link to="/cybersecurity">サイバーセキュリティ チートシート</router-link>
- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/network">ネットワーク チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>

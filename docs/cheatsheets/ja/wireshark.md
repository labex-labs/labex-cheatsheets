---
title: 'Wireshark チートシート | LabEx'
description: 'この包括的なチートシートで Wireshark のネットワーク解析を学ぶ。パケットキャプチャ、ネットワークプロトコル解析、トラフィック検査、トラブルシューティング、ネットワークセキュリティ監視のためのクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/wireshark-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Wireshark チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/wireshark">ハンズオンラボで Wireshark を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、Wireshark ネットワークパケット解析を学びます。LabEx は、必須のパケットキャプチャ、表示フィルター、プロトコル解析、ネットワークトラブルシューティング、セキュリティ監視を網羅した包括的な Wireshark コースを提供します。ネットワークトラフィック分析とパケット検査技術を習得しましょう。
</base-disclaimer-content>
</base-disclaimer>

## キャプチャフィルターとトラフィックキャプチャ

### ホストフィルタリング

特定のホストとの間で送受信されるトラフィックをキャプチャします。

```bash
# 特定のIPとのトラフィックをキャプチャ
host 192.168.1.100
# 特定の送信元からのトラフィックをキャプチャ
src host 192.168.1.100
# 特定の宛先へのトラフィックをキャプチャ
dst host 192.168.1.100
# サブネットからのトラフィックをキャプチャ
net 192.168.1.0/24
```

<BaseQuiz id="wireshark-filter-1" correct="A">
  <template #question>
    Wireshark で`host 192.168.1.100`は何をフィルタリングしますか？
  </template>
  
  <BaseQuizOption value="A" correct>192.168.1.100 とのすべてのトラフィック（送受信）</BaseQuizOption>
  <BaseQuizOption value="B">192.168.1.100 からのトラフィックのみ</BaseQuizOption>
  <BaseQuizOption value="C">192.168.1.100 へのトラフィックのみ</BaseQuizOption>
  <BaseQuizOption value="D">192.168.1.100 のポート上のトラフィック</BaseQuizOption>
  
  <BaseQuizAnswer>
    `host` フィルターは、指定された IP アドレスが送信元または宛先のすべてのトラフィックをキャプチャします。送信元のみの場合は`src host`、宛先のみの場合は`dst host`を使用します。
  </BaseQuizAnswer>
</BaseQuiz>

### ポートフィルタリング

特定のポート上のトラフィックをキャプチャします。

```bash
# HTTPトラフィック (ポート 80)
port 80
# HTTPSトラフィック (ポート 443)
port 443
# SSHトラフィック (ポート 22)
port 22
# DNSトラフィック (ポート 53)
port 53
# ポート範囲
portrange 1000-2000
```

<BaseQuiz id="wireshark-port-1" correct="D">
  <template #question>
    Wireshark で`port 80`は何をフィルタリングしますか？
  </template>
  
  <BaseQuizOption value="A">HTTP リクエストのみ</BaseQuizOption>
  <BaseQuizOption value="B">HTTP レスポンスのみ</BaseQuizOption>
  <BaseQuizOption value="C">TCP パケットのみ</BaseQuizOption>
  <BaseQuizOption value="D" correct>ポート 80 上のすべてのトラフィック（送信元と宛先の両方）</BaseQuizOption>
  
  <BaseQuizAnswer>
    `port` フィルターは、ポート 80 が送信元ポートまたは宛先ポートのいずれかであるすべてのトラフィックをキャプチャします。これには、ポート 80 を使用する HTTP リクエストとレスポンスの両方が含まれます。
  </BaseQuizAnswer>
</BaseQuiz>

### プロトコルフィルタリング

特定のプロトコルトラフィックをキャプチャします。

```bash
# TCPトラフィックのみ
tcp
# UDPトラフィックのみ
udp
# ICMPトラフィックのみ
icmp
# ARPトラフィックのみ
arp
```

### 高度なキャプチャフィルター

複数の条件を組み合わせて正確なキャプチャを行います。

```bash
# 特定のホストとのHTTPトラフィック
host 192.168.1.100 and port 80
# SSH（ポート22）を除くTCPトラフィック
tcp and not port 22
# 2つのホスト間のトラフィック
host 192.168.1.100 and host 192.168.1.200
# HTTPまたはHTTPSトラフィック
port 80 or port 443
```

<BaseQuiz id="wireshark-advanced-1" correct="B">
  <template #question>
    `tcp and not port 22`は何をキャプチャしますか？
  </template>
  
  <BaseQuizOption value="A">SSH トラフィックのみ</BaseQuizOption>
  <BaseQuizOption value="B" correct>SSH（ポート 22）を除くすべての TCP トラフィック</BaseQuizOption>
  <BaseQuizOption value="C">ポート 22 の UDP トラフィック</BaseQuizOption>
  <BaseQuizOption value="D">すべてのネットワークトラフィック</BaseQuizOption>
  
  <BaseQuizAnswer>
    このフィルターは、ポート 22（SSH）を除くすべての TCP トラフィックをキャプチャします。`and not`演算子は、指定されたポートを除外しながら、他のすべての TCP トラフィックを保持します。
  </BaseQuizAnswer>
</BaseQuiz>

### インターフェイスの選択

キャプチャ対象のネットワークインターフェイスを選択します。

```bash
# 利用可能なインターフェイスを一覧表示
tshark -D
# 特定のインターフェイスでキャプチャ
# Ethernetインターフェイス
eth0
# WiFiインターフェイス
wlan0
# ループバックインターフェイス
lo
```

### キャプチャオプション

キャプチャパラメータを設定します。

```bash
# キャプチャファイルサイズを制限 (MB)
-a filesize:100
# キャプチャ期間を制限 (秒)
-a duration:300
# 10ファイルでのリングバッファ
-b files:10
# プロミスキャスモード (すべてのトラフィックをキャプチャ)
-p
```

## 表示フィルターとパケット解析

### 基本的な表示フィルター

一般的なプロトコルやトラフィックタイプのための必須フィルター。

```bash
# HTTPトラフィックのみを表示
http
# HTTPS/TLSトラフィックのみを表示
tls
# DNSトラフィックのみを表示
dns
# TCPトラフィックのみを表示
tcp
# UDPトラフィックのみを表示
udp
# ICMPトラフィックのみを表示
icmp
```

### IP アドレスフィルタリング

送信元および宛先 IP アドレスでパケットをフィルタリングします。

```bash
# 特定のIPからのトラフィック
ip.src == 192.168.1.100
# 特定のIPへのトラフィック
ip.dst == 192.168.1.200
# 2つのIP間のトラフィック
ip.addr == 192.168.1.100
# サブネットからのトラフィック
ip.src_net == 192.168.1.0/24
# 特定のIPを除く
not ip.addr == 192.168.1.1
```

### ポートとプロトコルフィルター

特定のポートとプロトコルの詳細でフィルタリングします。

```bash
# 特定のポート上のトラフィック
tcp.port == 80
# 送信元ポートフィルター
tcp.srcport == 443
# 宛先ポートフィルター
tcp.dstport == 22
# ポート範囲
tcp.port >= 1000 and tcp.port <=
2000
# 複数のポート
tcp.port in {80 443 8080}
```

## プロトコル固有の解析

### HTTP 解析

HTTP リクエストとレスポンスを解析します。

```bash
# HTTP GETリクエスト
http.request.method == "GET"
# HTTP POSTリクエスト
http.request.method == "POST"
# 特定のHTTPステータスコード
http.response.code == 404
# 特定のホストへのHTTPリクエスト
http.host == "example.com"
# 文字列を含むHTTPリクエスト
http contains "login"
```

### DNS 解析

DNS クエリと応答を検査します。

```bash
# DNSクエリのみ
dns.flags.response == 0
# DNS応答のみ
dns.flags.response == 1
# 特定のドメインのDNSクエリ
dns.qry.name == "example.com"
# DNS Aレコードクエリ
dns.qry.type == 1
# DNSエラー/失敗
dns.flags.rcode != 0
```

### TCP 解析

TCP 接続の詳細を解析します。

```bash
# TCP SYNパケット（接続試行）
tcp.flags.syn == 1
# TCP RSTパケット（接続リセット）
tcp.flags.reset == 1
# TCP再送信
tcp.analysis.retransmission
# TCPウィンドウサイズの問題
tcp.analysis.window_update
# TCP接続確立
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### TLS/SSL解析

暗号化された接続の詳細を検査します。

```bash
# TLSハンドシェイクパケット
tls.handshake
# TLS証明書情報
tls.handshake.certificate
# TLSアラートとエラー
tls.alert
# 特定のTLSバージョン
tls.handshake.version == 0x0303
# TLS Server Name Indication
tls.handshake.extensions_server_name
```

### ネットワークトラブルシューティング

一般的なネットワークの問題を特定します。

```bash
# ICMP到達不能メッセージ
icmp.type == 3
# ARPリクエスト/レスポンス
arp.opcode == 1 or arp.opcode == 2
# ブロードキャストトラフィック
eth.dst == ff:ff:ff:ff:ff:ff
# フラグメント化されたパケット
ip.flags.mf == 1
# 大きなパケット（MTU問題の可能性）
frame.len > 1500
```

### 時間ベースのフィルタリング

タイムスタンプとタイミングに基づいてフィルタリングします。

```bash
# 時間範囲内のパケット
frame.time >= "2024-01-01 10:00:00"
# 過去1時間以内のパケット
frame.time_relative >= -3600
# 応答時間の分析
tcp.time_delta > 1.0
# パケット間隔時間
frame.time_delta > 0.1
```

## 統計と解析ツール

### プロトコル階層

キャプチャ内のプロトコル分布を表示します。

```bash
# アクセス方法: Statistics > Protocol Hierarchy
# 各プロトコルのパーセンテージを表示
# 最も一般的なプロトコルを特定
# トラフィックの概要把握に役立つ
# コマンドライン相当
tshark -r capture.pcap -q -z io,phs
```

### 通信 (Conversations)

エンドポイント間の通信を分析します。

```bash
# アクセス方法: Statistics > Conversations
# Ethernet通信
# IPv4/IPv6通信
# TCP/UDP通信
# 転送されたバイト数、パケット数を表示
# コマンドライン相当
tshark -r capture.pcap -q -z conv,tcp
```

### I/O グラフ

トラフィックパターンを時間軸で視覚化します。

```bash
# アクセス方法: Statistics > I/O Graphs
# 時間経過に伴うトラフィック量
# 1秒あたりのパケット数
# 1秒あたりのバイト数
# 特定のトラフィックに対してフィルターを適用
# トラフィックの急増を特定するのに役立つ
```

### エキスパート情報

潜在的なネットワークの問題を特定します。

```bash
# アクセス方法: Analyze > Expert Info
# ネットワーク問題に関する警告
# パケット送信におけるエラー
# パフォーマンスの問題
# セキュリティに関する懸念
# エキスパート情報の深刻度でフィルタリング
tcp.analysis.flags
```

### フローグラフ

エンドポイント間のパケットフローを視覚化します。

```bash
# アクセス方法: Statistics > Flow Graph
# パケットシーケンスを表示
# 時間ベースの視覚化
# トラブルシューティングに役立つ
# 通信パターンを特定
```

### 応答時間分析

アプリケーションの応答時間を測定します。

```bash
# HTTP応答時間
# Statistics > HTTP > Requests
# DNS応答時間
# Statistics > DNS
# TCPサービス応答時間
# Statistics > TCP Stream Graphs > Time Sequence
```

## ファイル操作とエクスポート

### キャプチャの保存と読み込み

さまざまな形式でキャプチャファイルを管理します。

```bash
# キャプチャファイルを保存
# File > Save As > capture.pcap
# キャプチャファイルを読み込む
# File > Open > existing.pcap
# 複数のキャプチャファイルをマージ
# File > Merge > select files
# フィルタリングされたパケットのみを保存
# File > Export Specified Packets
```

### エクスポートオプション

特定のデータやパケットのサブセットをエクスポートします。

```bash
# 選択したパケットをエクスポート
# File > Export Specified Packets
# パケットの詳細をエクスポート
# File > Export Packet Dissections
# HTTPからオブジェクトをエクスポート
# File > Export Objects > HTTP
# SSL/TLSキーをエクスポート
# Edit > Preferences > Protocols > TLS
```

### コマンドラインキャプチャ

tshark を使用して自動化されたキャプチャと分析を実行します。

```bash
# ファイルにキャプチャ
tshark -i eth0 -w capture.pcap
# フィルター付きでキャプチャ
tshark -i eth0 -f "port 80" -w http.pcap
# パケットを読み取り、表示
tshark -r capture.pcap
# ファイルに表示フィルターを適用
tshark -r capture.pcap -Y "tcp.port == 80"
```

### バッチ処理

複数のキャプチャファイルを自動的に処理します。

```bash
# 複数のファイルをマージ
mergecap -w merged.pcap file1.pcap file2.pcap
# 大きなキャプチャファイルを分割
editcap -c 1000 large.pcap split.pcap
# 時間範囲を抽出
editcap -A "2024-01-01 10:00:00" \
        -B "2024-01-01 11:00:00" \
        input.pcap output.pcap
```

## パフォーマンスと最適化

### メモリ管理

大きなキャプチャファイルを効率的に処理します。

```bash
# 連続キャプチャのためにリングバッファを使用
-b filesize:100 -b files:10
# パケットキャプチャサイズを制限
-s 96  # 最初の96バイトのみキャプチャ
# データを減らすためにキャプチャフィルターを使用
host 192.168.1.100 and port 80
# 速度向上のためにプロトコルディセクションを無効化
-d tcp.port==80,http
```

### 表示の最適化

大規模データセットでの GUI パフォーマンスを向上させます。

```bash
# 調整する設定:
# Edit > Preferences > Appearance
# 配色スキームの選択
# フォントサイズや種類の調整
# カラム表示オプションの調整
# 時間表示設定の調整
# View > Time Display Format
# キャプチャ開始からの秒数
# 時刻
# UTC時刻
# tsharkを大規模ファイル分析に使用
tshark -r large.pcap -q -z conv,tcp
```

### 効率的な分析ワークフロー

ネットワークトラフィックを分析するためのベストプラクティス。

```bash
# 1. キャプチャフィルターから始める
# 関連するトラフィックのみをキャプチャ
# 2. 表示フィルターを段階的に使用する
# 広く始めて、徐々に絞り込む
# 3. 統計情報をまず使用する
# 詳細な分析の前に概要を把握する
# 4. 特定のフローに焦点を当てる
# パケットを右クリック > Follow > TCP Stream
```

### 自動化とスクリプト作成

一般的な分析タスクを自動化します。

```bash
# カスタム表示フィルターボタンの作成
# View > Display Filter Expression
# シナリオごとにプロファイルを使用
# Edit > Configuration Profiles
# tsharkでスクリプト化
#!/bin/bash
tshark -r $1 -q -z endpoints,tcp | \
grep -v "Filter:" | head -20
```

## インストールとセットアップ

### Windows インストール

公式ウェブサイトからダウンロードしてインストールします。

```bash
# wireshark.orgからダウンロード
# 管理者としてインストーラーを実行
# インストール中にWinPcap/Npcapを含める
# コマンドラインインストール
(chocolatey)
choco install wireshark
# インストールを確認
wireshark --version
```

### Linux インストール

パッケージマネージャー経由、またはソースからインストールします。

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install wireshark
# Red Hat/CentOS/Fedora
sudo yum install wireshark
# または
sudo dnf install wireshark
# ユーザーをwiresharkグループに追加
sudo usermod -a -G wireshark
$USER
```

### macOS インストール

Homebrew または公式インストーラーを使用してインストールします。

```bash
# Homebrewを使用
brew install --cask wireshark
# wireshark.orgからダウンロード
# .dmgパッケージをインストール
# コマンドラインツール
brew install wireshark
```

## 設定と環境設定

### インターフェイス設定

キャプチャインターフェイスとオプションを設定します。

```bash
# Edit > Preferences > Capture
# デフォルトのキャプチャインターフェイス
# プロミスキャスモード設定
# バッファサイズの設定
# ライブキャプチャでの自動スクロール
# インターフェイス固有の設定
# Capture > Options > Interface Details
```

### プロトコル設定

プロトコルディセクタとデコードを設定します。

```bash
# Edit > Preferences > Protocols
# プロトコルディセクタの有効化/無効化
# ポート割り当ての設定
# 復号化キーの設定 (TLS, WEPなど)
# TCP再アセンブリオプション
# Decode As機能
# Analyze > Decode As
```

### 表示設定

ユーザーインターフェイスと表示オプションをカスタマイズします。

```bash
# Edit > Preferences > Appearance
# 配色スキームの選択
# フォントサイズと種類
# カラム表示オプション
# 時間表示設定
# View > Time Display Format
# キャプチャ開始からの秒数
# 時刻
# UTC時刻
```

### セキュリティ設定

セキュリティ関連のオプションと復号化を設定します。

```bash
# TLS復号化の設定
# Edit > Preferences > Protocols > TLS
# RSAキーリスト
# 事前共有キー
# キーログファイルの位置
# 潜在的に危険な機能の無効化
# Luaスクリプトの実行
# 外部リゾルバ
```

## 高度なフィルタリング技術

### 論理演算子

複数のフィルター条件を組み合わせます。

```bash
# AND演算子
tcp.port == 80 and ip.src == 192.168.1.100
# OR演算子
tcp.port == 80 or tcp.port == 443
# NOT演算子
not icmp
# グループ化のための括弧
(tcp.port == 80 or tcp.port == 443) and ip.src ==
192.168.1.0/24
```

### 文字列マッチング

パケット内の特定のコンテンツを検索します。

```bash
# 文字列を含む (大文字と小文字を区別)
tcp contains "password"
# 文字列を含む (大文字と小文字を区別しない)
tcp matches "(?i)login"
# 正規表現
http.request.uri matches "\.php$"
# バイトシーケンス
eth.src[0:3] == 00:11:22
```

### フィールド比較

パケットフィールドを値や範囲と比較します。

```bash
# 等価性
tcp.srcport == 80
# より大きい/より小さい
frame.len > 1000
# 範囲チェック
tcp.port >= 1024 and tcp.port <= 65535
# セットメンバーシップ
tcp.port in {80 443 8080}
# フィールドの存在
tcp.options
```

### 高度なパケット分析

特定のパケット特性や異常を特定します。

```bash
# 破損したパケット
_ws.malformed
# 重複パケット
frame.number == tcp.analysis.duplicate_ack_num
# 順序が狂ったパケット
tcp.analysis.out_of_order
# TCPウィンドウのスケール問題
tcp.analysis.window_full
```

## 一般的なユースケース

### ネットワークトラブルシューティング

ネットワーク接続の問題を特定し解決します。

```bash
# 接続タイムアウトの検出
tcp.analysis.retransmission and tcp.analysis.rto
# 遅い接続の特定
tcp.time_delta > 1.0
# ネットワーク輻輳の検出
tcp.analysis.window_full
# DNS解決の問題
dns.flags.rcode != 0
# MTU発見の問題
icmp.type == 3 and icmp.code == 4
```

### セキュリティ分析

潜在的なセキュリティ脅威や疑わしいアクティビティを検出します。

```bash
# ポートスキャン検出
tcp.flags.syn == 1 and tcp.flags.ack == 0
# 単一IPからの大量接続
# Statistics > Conversations を使用
# 疑わしいDNSクエリ
dns.qry.name contains "dga" or dns.qry.name matches
"^[a-z]{8,}\.com$"
# 疑わしいURLへのHTTP POST
http.request.method == "POST" and http.request.uri
contains "/upload"
# 異常なトラフィックパターン
# I/Oグラフで急増を確認
```

### アプリケーションパフォーマンス

アプリケーションの応答時間を監視および分析します。

```bash
# Webアプリケーション分析
http.time > 2.0
# データベース接続監視
tcp.port == 3306 and tcp.analysis.initial_rtt > 0.1
# ファイル転送パフォーマンス
tcp.stream eq X and tcp.analysis.bytes_in_flight
# VoIP品質分析
rtp.jitter > 30 or rtp.marker == 1
```

### プロトコル調査

特定のプロトコルとその動作を深く掘り下げます。

```bash
# Eメールトラフィック
tcp.port == 25 or tcp.port == 587 or tcp.port == 993
# FTPファイル転送
ftp-data or ftp.request.command == "RETR"
# SMB/CIFSファイル共有
smb2 or smb
# DHCPリース分析
bootp.option.dhcp == 1 or bootp.option.dhcp == 2
```

## 関連リンク

- <router-link to="/nmap">Nmap チートシート</router-link>
- <router-link to="/cybersecurity">サイバーセキュリティ チートシート</router-link>
- <router-link to="/kali">Kali Linux チートシート</router-link>
- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/network">ネットワーク チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>

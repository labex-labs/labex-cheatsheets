---
title: 'Hydra チートシート | LabEx'
description: 'Hydra パスワードクラッキングを学ぶための包括的なチートシート。ブルートフォース攻撃、パスワード監査、セキュリティテスト、認証プロトコル、ペネトレーションテストツールのクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/hydra-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hydra チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/hydra">ハンズオンラボで Hydra を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
LabEx では、プロトコル攻撃、Web フォームの悪用、パフォーマンス最適化、倫理的な使用法を網羅した包括的な Hydra コースを提供しています。ハンズオンラボと現実世界のシナリオを通じて、Hydra のパスワードクラッキングとペネトレーションテストを学びましょう。正規のセキュリティテストと脆弱性評価のために、ブルートフォース技術を習得してください。
</base-disclaimer-content>
</base-disclaimer>

## 基本構文とインストール

### インストール：`sudo apt install hydra`

Hydra は通常 Kali Linux にプリインストールされていますが、他のディストリビューションにもインストール可能です。

```bash
# Debian/Ubuntuシステムへのインストール
sudo apt install hydra
# 他のシステムへのインストール
sudo apt-get install hydra
# インストールの確認
hydra -h
# サポートされているプロトコルの確認
hydra
```

### 基本構文：`hydra [options] target service`

基本構文：`hydra -l <username> -P <password_file> <target_protocol>://<target_address>`

```bash
# ユーザー名1つ、パスワードリスト
hydra -l username -P passwords.txt target.com ssh
# ユーザー名リスト、パスワードリスト
hydra -L users.txt -P passwords.txt target.com ssh
# ユーザー名1つ、パスワード1つ
hydra -l admin -p password123 192.168.1.100 ftp
```

<BaseQuiz id="hydra-syntax-1" correct="B">
  <template #question>
    Hydra の <code>-l</code>と<code>-L</code> の違いは何ですか？
  </template>
  
  <BaseQuizOption value="A"><code>-l</code>はパスワード用、<code>-L</code> はユーザー名用です</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>-l</code>は単一のユーザー名を指定し、<code>-L</code> はユーザー名のリストファイル指定です</BaseQuizOption>
  <BaseQuizOption value="C">違いはありません</BaseQuizOption>
  <BaseQuizOption value="D"><code>-l</code>は小文字、<code>-L</code> は大文字です</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-l</code>オプションは単一のユーザー名に使用され、<code>-L</code>はユーザー名のリストを含むファイルに使用されます。同様に、<code>-p</code>は単一のパスワード、<code>-P</code> はパスワードリストファイルに使用されます。
  </BaseQuizAnswer>
</BaseQuiz>

### コアオプション：`-l`, `-L`, `-p`, `-P`

ブルートフォース攻撃に使用するユーザー名とパスワードを指定します。

```bash
# ユーザー名オプション
-l username          # 単一のユーザー名
-L userlist.txt      # ユーザー名リストファイル
# パスワードオプション
-p password          # 単一のパスワード
-P passwordlist.txt  # パスワードリストファイル
# 一般的なワードリストの場所
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/metasploit/unix_passwords.txt
```

### 出力オプション：`-o`, `-b`

結果をファイルに保存し、後で分析できるようにします。

```bash
# 結果をファイルに保存
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# JSON出力形式
hydra -l admin -P passwords.txt target.com ssh -b json
# 詳細出力
hydra -l admin -P passwords.txt target.com ssh -V
```

<BaseQuiz id="hydra-output-1" correct="A">
  <template #question>
    <code>hydra -V</code>は何をしますか？
  </template>
  
  <BaseQuizOption value="A" correct>詳細な進捗を表示する詳細出力を有効にします</BaseQuizOption>
  <BaseQuizOption value="B">ワードリストファイルを検証します</BaseQuizOption>
  <BaseQuizOption value="C">Hydra のバージョンを表示します</BaseQuizOption>
  <BaseQuizOption value="D">詳細モードでのみ実行します</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-V</code> フラグは詳細モードを有効にし、各ログイン試行を含む詳細な出力を表示するため、パスワード攻撃中の進捗監視やデバッグが容易になります。
  </BaseQuizAnswer>
</BaseQuiz>

## プロトコル固有の攻撃

### SSH: `hydra target ssh`

ユーザー名とパスワードの組み合わせで SSH サービスを攻撃します。

```bash
# 基本的なSSH攻撃
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh
# 複数のユーザー名
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
# カスタムSSHポート
hydra -l admin -P passwords.txt 192.168.1.100 -s 2222 ssh
# スレッディングあり
hydra -l root -P passwords.txt -t 6 ssh://192.168.1.100
```

<BaseQuiz id="hydra-ssh-1" correct="C">
  <template #question>
    Hydra の <code>-s</code> フラグは何をしますか？
  </template>
  
  <BaseQuizOption value="A">サービスタイプを設定します</BaseQuizOption>
  <BaseQuizOption value="B">ステルスモードを有効にします</BaseQuizOption>
  <BaseQuizOption value="C" correct>カスタムポート番号を指定します</BaseQuizOption>
  <BaseQuizOption value="D">スレッド数を設定します</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-s</code> フラグは、サービスが標準ポート以外で実行されている場合にカスタムポート番号を指定します。例えば、<code>-s 2222</code>はデフォルトのポート 22 ではなくポート 2222 の SSH をターゲットにします。
  </BaseQuizAnswer>
</BaseQuiz>

### FTP: `hydra target ftp`

FTP ログイン認証情報をブルートフォースします。

```bash
# 基本的なFTP攻撃
hydra -l admin -P passwords.txt ftp://192.168.1.100
# アノニマスFTPチェック
hydra -l anonymous -p "" ftp://192.168.1.100
# カスタムFTPポート
hydra -l user -P passwords.txt -s 2121 192.168.1.100 ftp
```

### データベース攻撃：`mysql`, `postgres`, `mssql`

認証情報のブルートフォースでデータベースサービスを攻撃します。

```bash
# MySQL攻撃
hydra -l root -P passwords.txt 192.168.1.100 mysql
# PostgreSQL攻撃
hydra -l postgres -P passwords.txt 192.168.1.100 postgres
# MSSQL攻撃
hydra -l sa -P passwords.txt 192.168.1.100 mssql
# MongoDB攻撃
hydra -l admin -P passwords.txt 192.168.1.100 mongodb
```

### SMTP/Eメール: `hydra target smtp`

メールサーバー認証を攻撃します。

```bash
# SMTPブルートフォース
hydra -l admin -P passwords.txt smtp://mail.target.com
# NULL/空のパスワードを使用
hydra -P passwords.txt -e ns -V -s 25 smtp.target.com smtp
# IMAP攻撃
hydra -l user -P passwords.txt imap://mail.target.com
```

## Web アプリケーション攻撃

### HTTP POST フォーム：`http-post-form`

プレースホルダー`^USER^`と`^PASS^`を使用して、Web ログインフォームを HTTP POST メソッドで攻撃します。

```bash
# 基本的なPOSTフォーム攻撃
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
# カスタムエラーメッセージ付き
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid password"
# 成功条件付き
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/admin:username=^USER^&password=^PASS^:S=Dashboard"
```

### HTTP GET フォーム：`http-get-form`

POST フォームと似ていますが、GET リクエストをターゲットにします。

```bash
# GETフォーム攻撃
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# カスタムヘッダー付き
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/auth:user=^USER^&pass=^PASS^:F=Error:H=Cookie: session=abc123"
```

### HTTP Basic Auth: `http-get`/`http-post`

HTTP 基本認証を使用して Web サーバーを攻撃します。

```bash
# HTTP基本認証
hydra -l admin -P passwords.txt http-get://192.168.1.100
# HTTPS基本認証
hydra -l admin -P passwords.txt https-get://secure.target.com
# カスタムパス付き
hydra -l admin -P passwords.txt http-get://192.168.1.100/admin
```

### 高度な Web 攻撃

CSRF トークンや Cookie を扱う複雑な Web アプリケーションに対応します。

```bash
# CSRFトークン処理あり
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^&csrf=^CSRF^:F=Error:H=Cookie: csrf=^CSRF^"
# セッションCookieあり
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: PHPSESSID=abc123"
```

## パフォーマンスとスレッディングオプション

### スレッディング：`-t` (タスク)

攻撃中の同時接続数を制御します。

```bash
# デフォルトのスレッディング (16タスク)
hydra -l admin -P passwords.txt target.com ssh
# カスタムスレッド数
hydra -l admin -P passwords.txt -t 4 target.com ssh
# 高性能攻撃 (注意して使用)
hydra -l admin -P passwords.txt -t 64 target.com ssh
# 控えめなスレッディング (検出回避)
hydra -l admin -P passwords.txt -t 1 target.com ssh
```

### 待機時間：`-w` (遅延)

レート制限や検出を避けるために、試行間に遅延を追加します。

```bash
# 試行間に30秒待機
hydra -l admin -P passwords.txt -w 30 target.com ssh
# スレッディングと組み合わせ
hydra -l admin -P passwords.txt -t 2 -w 10 target.com ssh
# ランダムな遅延 (1〜5秒)
hydra -l admin -P passwords.txt -W 5 target.com ssh
```

### 複数ターゲット：`-M` (ターゲットファイル)

ファイルに指定された複数のホストを攻撃します。

```bash
# ターゲットファイルを作成
echo "192.168.1.100" > targets.txt
echo "192.168.1.101" >> targets.txt
echo "192.168.1.102" >> targets.txt
# 複数ターゲットの攻撃
hydra -L users.txt -P passwords.txt -M targets.txt ssh
# カスタムスレッディング付き
hydra -L users.txt -P passwords.txt -M targets.txt -t 2 ssh
```

### 再開と停止オプション

中断された攻撃を再開し、停止動作を制御します。

```bash
# 最初の成功で停止
hydra -l admin -P passwords.txt -f target.com ssh
# 以前の攻撃を再開
hydra -R
# リストアファイルを作成
hydra -l admin -P passwords.txt -I restore.txt target.com ssh
```

## 高度な機能とオプション

### パスワード生成：`-e` (追加テスト)

追加のパスワードバリエーションを自動的にテストします。

```bash
# NULLパスワードのテスト
hydra -l admin -e n target.com ssh
# ユーザー名をパスワードとしてテスト
hydra -l admin -e s target.com ssh
# ユーザー名の逆順をテスト
hydra -l admin -e r target.com ssh
# すべてのオプションを組み合わせる
hydra -l admin -e nsr -P passwords.txt target.com ssh
```

### コロン区切り形式：`-C`

ユーザー名：パスワードの組み合わせを使用して、攻撃時間を短縮します。

```bash
# 認証情報ファイルを作成
echo "admin:admin" > creds.txt
echo "root:password" >> creds.txt
echo "user:123456" >> creds.txt
# コロン形式を使用
hydra -C creds.txt target.com ssh
# 全組み合わせテストよりも高速
```

### プロキシサポート：`HYDRA_PROXY`

環境変数を使用してプロキシサーバー経由で攻撃を実行します。

```bash
# HTTPプロキシ
export HYDRA_PROXY=connect://proxy.example.com:8080
hydra -l admin -P passwords.txt target.com ssh
# 認証付きSOCKS4プロキシ
export HYDRA_PROXY=socks4://user:pass@127.0.0.1:1080
# SOCKS5プロキシ
export HYDRA_PROXY=socks5://proxy.example.com:1080
```

### パスワードリストの最適化：`pw-inspector`

pw-inspector を使用して、ポリシーに基づいてパスワードリストをフィルタリングします。

```bash
# パスワードをフィルタリング (最小6文字、2文字クラス)
cat passwords.txt | pw-inspector -m 6 -c 2 -n > filtered.txt
# フィルタリングされたリストをHydraで使用
hydra -l admin -P filtered.txt target.com ssh
# 重複を先に削除
cat passwords.txt | sort | uniq > unique_passwords.txt
```

## 倫理的な使用法とベストプラクティス

### 法的および倫理的ガイドライン

Hydra は合法的に、また違法に使用される可能性があります。ブルートフォース攻撃を実行する前に、適切な許可と承認を得てください。

```text
明示的な許可を得たシステムでのみ攻撃を実行する
必ずシステム所有者または管理者から明示的な許可を得ていることを確認する
コンプライアンスのためにすべてのテスト活動を文書化する
正規のペネトレーションテスト中にのみ使用する
不正なアクセス試行には絶対に使用しない
```

### 防御策

強力なパスワードとポリシーでブルートフォース攻撃から防御します。

```text
失敗した試行後にアカウントを一時的にロックするアカウントロックアウトポリシーを実装する
多要素認証 (MFA) を使用する
自動化ツールを防ぐために CAPTCHA システムを実装する
認証試行を監視およびログに記録する
レート制限と IP ブロッキングを実装する
```

### テストのベストプラクティス

控えめな設定から開始し、透明性のためにすべての活動を文書化します。

```text
サービスの中断を避けるために、低いスレッド数から開始する
ターゲット環境に適したワードリストを使用する
可能な限り、承認されたメンテナンスウィンドウ中にテストする
テスト中にターゲットシステムのパフォーマンスを監視する
インシデント対応手順を準備しておく
```

### 一般的な使用例

レッドチームとブルーチームの両方が、パスワード監査、セキュリティ評価、ペネトレーションテストのために恩恵を受けます。

```text
弱いパスワードを特定し、パスワード強度を評価するためのパスワードクラッキング
ネットワークサービスのセキュリティ監査
ペネトレーションテストと脆弱性評価
パスワードポリシーのコンプライアンステスト
トレーニングと教育デモンストレーション
```

## GUI の代替と追加ツール

### XHydra: GUI インターフェース

XHydra は Hydra の GUI であり、コマンドラインスイッチの代わりに GUI を介して設定を選択できます。

```bash
# XHydra GUIを起動
xhydra
# 利用できない場合はインストール
sudo apt install hydra-gtk
# 特徴:
# - ポイントアンドクリックインターフェース
# - 事前設定された攻撃テンプレート
# - 視覚的な進捗監視
# - ターゲットとワードリストの簡単な選択
```

### Hydra Wizard: 対話型セットアップ

Hydra セットアップを簡単な質問で案内する対話型ウィザードです。

```bash
# 対話型ウィザードを起動
hydra-wizard
# ウィザードが尋ねること:
# 1. 攻撃するサービス
# 2. 攻撃するターゲット
# 3. ユーザー名またはユーザー名ファイル
# 4. パスワードまたはパスワードファイル
# 5. 追加のパスワードテスト
# 6. ポート番号
# 7. 最終確認
```

### デフォルトパスワードリスト：`dpl4hydra`

特定のブランドやシステム用のデフォルトパスワードリストを生成します。

```bash
# デフォルトパスワードデータベースを更新
dpl4hydra refresh
# 特定のブランドのリストを生成
dpl4hydra cisco
dpl4hydra netgear
dpl4hydra linksys
# 生成されたリストを使用
hydra -C dpl4hydra_cisco.lst 192.168.1.1 ssh
# すべてのブランド
dpl4hydra all
```

### 他のツールとの統合

偵察および列挙ツールと Hydra を組み合わせます。

```bash
# Nmapサービス検出と組み合わせる
nmap -sV 192.168.1.0/24 | grep -E "(ssh|ftp|http)"
# ユーザー名列挙結果と組み合わせる
enum4linux 192.168.1.100 | grep "user:" > users.txt
# Metasploitのワードリストとの統合
ls /usr/share/wordlists/metasploit/
```

## トラブルシューティングとパフォーマンス

### 一般的な問題と解決策

Hydra の使用中に遭遇する一般的な問題を解決します。

```bash
# 接続タイムアウトエラー
hydra -l admin -P passwords.txt -t 1 -w 30 target.com ssh
# 接続数が多すぎるエラー
hydra -l admin -P passwords.txt -t 2 target.com ssh
# メモリ使用量の最適化
hydra -l admin -P small_list.txt target.com ssh
# サポートされているプロトコルの確認
hydra
# サポートされているサービスリストでプロトコルを探す
```

### パフォーマンスの最適化

パスワードリストを最適化し、可能性の高い順にソートして結果を高速化します。

```bash
# パスワードを可能性順にソート
hydra -l admin -P passwords.txt -u target.com ssh
# 重複を削除
sort passwords.txt | uniq > clean_passwords.txt
# ターゲットに基づいたスレッディングの最適化
# ローカルネットワーク: -t 16
# インターネットターゲット: -t 4
# 低速なサービス: -t 1
```

### 出力形式と分析

結果の分析とレポート作成のために、異なる出力形式を使用します。

```bash
# 標準テキスト出力
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# 解析用のJSON形式
hydra -l admin -P passwords.txt target.com ssh -b json -o results.json
# デバッグ用の詳細出力
hydra -l admin -P passwords.txt target.com ssh -V
# 成功した結果のみの出力
hydra -l admin -P passwords.txt target.com ssh | grep "password:"
```

### リソース監視

攻撃中にシステムおよびネットワークリソースを監視します。

```bash
# CPU使用率の監視
top -p $(pidof hydra)
# ネットワーク接続の監視
netstat -an | grep :22
# メモリ使用量の監視
ps aux | grep hydra
# システムへの影響を制限
nice -n 19 hydra -l admin -P passwords.txt target.com ssh
```

## 関連リンク

- <router-link to="/kali">Kali Linux チートシート</router-link>
- <router-link to="/cybersecurity">サイバーセキュリティチートシート</router-link>
- <router-link to="/nmap">Nmap チートシート</router-link>
- <router-link to="/wireshark">Wireshark チートシート</router-link>
- <router-link to="/comptia">CompTIA チートシート</router-link>
- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">シェルチートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>

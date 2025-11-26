---
title: 'シェルチートシート'
description: '必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートでシェルを習得しましょう。'
pdfUrl: '/cheatsheets/pdf/shell-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Shell チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/shell">ハンズオンラボで Shell を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、Shell スクリプティングとコマンドライン操作を学びましょう。LabEx は、必須の Bash コマンド、ファイル操作、テキスト処理、プロセス管理、自動化を網羅した包括的な Shell コースを提供します。コマンドラインの効率性とシェルスクリプト技術を習得してください。
</base-disclaimer-content>
</base-disclaimer>

## ファイルとディレクトリの操作

### ファイル一覧表示：`ls`

現在の場所にあるファイルとディレクトリを表示します。

```bash
# 現在のディレクトリ内のファイルを一覧表示
ls
# 詳細情報付きで一覧表示
ls -l
# 隠しファイルを表示
ls -a
# 人間が読みやすいファイルサイズで一覧表示
ls -lh
# 変更時刻順にソート
ls -lt
```

### ファイル作成：`touch`

空のファイルを作成するか、タイムスタンプを更新します。

```bash
# 新しいファイルを作成
touch newfile.txt
# 複数のファイルを作成
touch file1.txt file2.txt file3.txt
# 既存のファイルのタイムスタンプを更新
touch existing_file.txt
```

### ディレクトリ作成：`mkdir`

新しいディレクトリを作成します。

```bash
# ディレクトリを作成
mkdir my_directory
# ネストされたディレクトリを作成
mkdir -p parent/child/grandchild
# 複数のディレクトリを作成
mkdir dir1 dir2 dir3
```

### ファイルコピー: `cp`

ファイルとディレクトリをコピーします。

```bash
# ファイルをコピー
cp source.txt destination.txt
# ディレクトリを再帰的にコピー
cp -r source_dir dest_dir
# 確認プロンプト付きでコピー
cp -i file1.txt file2.txt
# ファイル属性を保持してコピー
cp -p original.txt copy.txt
```

### 移動/名前変更：`mv`

ファイルやディレクトリを移動または名前変更します。

```bash
# ファイルの名前を変更
mv oldname.txt newname.txt
# ファイルをディレクトリに移動
mv file.txt /path/to/directory/
# 複数のファイルを移動
mv file1 file2 file3 target_directory/
```

### ファイル削除：`rm`

ファイルとディレクトリを削除します。

```bash
# ファイルを削除
rm file.txt
# ディレクトリとその内容を削除
rm -r directory/
# 確認なしで強制削除
rm -f file.txt
# 対話的に削除（それぞれ確認）
rm -i *.txt
```

## 移動とパス管理

### 現在のディレクトリ：`pwd`

現在の作業ディレクトリのパスを表示します。

```bash
# 現在のディレクトリを表示
pwd
# 出力例:
/home/user/documents
```

### ディレクトリ変更：`cd`

別のディレクトリに変更します。

```bash
# ホームディレクトリに移動
cd ~
# 親ディレクトリに移動
cd ..
# 前のディレクトリに移動
cd -
# 特定のディレクトリに移動
cd /path/to/directory
```

### ディレクトリツリー: `tree`

ディレクトリ構造をツリー形式で表示します。

```bash
# ディレクトリツリーを表示
tree
# 2階層までに制限
tree -L 2
# ディレクトリのみ表示
tree -d
```

## テキスト処理と検索

### ファイル表示：`cat` / `less` / `head` / `tail`

ファイルの内容を異なる方法で表示します。

```bash
# ファイル全体を表示
cat file.txt
# ページごとにファイルを表示
less file.txt
# 最初の10行を表示
head file.txt
# 最後の10行を表示
tail file.txt
# 最後の20行を表示
tail -n 20 file.txt
# ファイルの変更を追跡（ログなどに便利）
tail -f logfile.txt
```

### ファイル内検索：`grep`

テキストファイル内のパターンを検索します。

```bash
# ファイル内でパターンを検索
grep "pattern" file.txt
# 大文字・小文字を区別しない検索
grep -i "pattern" file.txt
# ディレクトリ内で再帰的に検索
grep -r "pattern" directory/
# 行番号を表示
grep -n "pattern" file.txt
# マッチした行数をカウント
grep -c "pattern" file.txt
```

### ファイル検索：`find`

基準に基づいてファイルとディレクトリを見つけます。

```bash
# 名前でファイルを検索
find . -name "*.txt"
# タイプでファイルを検索
find . -type f -name "config*"
# ディレクトリを検索
find . -type d -name "backup"
# 過去7日間に変更されたファイルを検索
find . -mtime -7
# 検索してコマンドを実行
find . -name "*.log" -delete
```

### テキスト操作：`sed` / `awk` / `sort`

テキストデータを処理および操作します。

```bash
# ファイル内のテキストを置換
sed 's/old/new/g' file.txt
# 特定の列を抽出
awk '{print $1, $3}' file.txt
# ファイルの内容をソート
sort file.txt
# 重複行を削除
sort file.txt | uniq
# 単語の頻度をカウント
cat file.txt | tr ' ' '\n' | sort | uniq -c
```

## ファイルパーミッションと所有権

### パーミッション表示：`ls -l`

詳細なファイルパーミッションと所有権を表示します。

```bash
# 詳細なファイル情報を表示
ls -l
# 出力例:
# -rw-r--r-- 1 user group 1024 Jan 1 12:00 file.txt
# d = directory, r = read, w = write, x = execute
```

### パーミッション変更：`chmod`

ファイルとディレクトリのパーミッションを変更します。

```bash
# オーナーに実行権限を付与
chmod +x script.sh
# 特定のパーミッション (755) を設定
chmod 755 file.txt
# グループ/その他の書き込み権限を削除
chmod go-w file.txt
# 再帰的なパーミッション変更
chmod -R 644 directory/
```

### 所有権変更：`chown` / `chgrp`

ファイル所有者とグループを変更します。

```bash
# 所有者を変更
chown newowner file.txt
# 所有者とグループを変更
chown newowner:newgroup file.txt
# グループのみ変更
chgrp newgroup file.txt
# 再帰的な所有権変更
chown -R user:group directory/
```

### パーミッション番号

数値表記のパーミッションの理解。

```text
# パーミッション計算：
# 4 = 読み取り (r), 2 = 書き込み (w), 1 = 実行 (x)
# 755 = rwxr-xr-x (所有者：rwx, グループ：r-x, その他：r-x)
# 644 = rw-r--r-- (所有者：rw-, グループ：r--, その他：r--)
# 777 = rwxrwxrwx (全員に完全な権限)
# 600 = rw------- (所有者：rw-, グループ：---, その他：---)
```

## プロセス管理

### プロセス表示：`ps` / `top` / `htop`

実行中のプロセスに関する情報を表示します。

```bash
# 現在のユーザーのプロセスを表示
ps
# 全てのプロセスを詳細表示
ps aux
# ツリー形式でプロセスを表示
ps -ef --forest
# 対話的なプロセスビューア
top
# 強化されたプロセスビューア (利用可能な場合)
htop
```

### バックグラウンドジョブ：`&` / `jobs` / `fg` / `bg`

バックグラウンドおよびフォアグラウンドのプロセスを管理します。

```bash
# コマンドをバックグラウンドで実行
command &
# アクティブなジョブを一覧表示
jobs
# ジョブをフォアグラウンドに持ってくる
fg %1
# ジョブをバックグラウンドに送る
bg %1
# 現在のプロセスを一時停止
Ctrl+Z
```

### プロセス終了：`kill` / `killall`

PID または名前でプロセスを終了します。

```bash
# PIDでプロセスを終了
kill 1234
# プロセスを強制終了
kill -9 1234
# 名前を持つすべてのプロセスを終了
killall firefox
# 特定のシグナルを送信
kill -TERM 1234
```

### システム監視：`free` / `df` / `du`

システムリソースとディスク使用量を監視します。

```bash
# メモリ使用量を表示
free -h
# ディスク空き容量を表示
df -h
# ディレクトリサイズを表示
du -sh directory/
# 最も大きいディレクトリを表示
du -h --max-depth=1 | sort -hr
```

## 入出力のリダイレクト

### リダイレクト：`>` / `>>` / `<`

コマンドの出力と入力をリダイレクトします。

```bash
# 出力をファイルにリダイレクト（上書き）
command > output.txt
# 出力をファイルに追加
command >> output.txt
# ファイルから入力をリダイレクト
command < input.txt
# 出力とエラーの両方をリダイレクト
command > output.txt 2>&1
# 出力を破棄
command > /dev/null
```

### パイプ：`|`

パイプを使用してコマンドを連鎖させます。

```bash
# 基本的なパイプの使用
command1 | command2
# 複数のパイプ
cat file.txt | grep "pattern" | sort | uniq
# 出力行数をカウント
ps aux | wc -l
# 長い出力をページング
ls -la | less
```

### Tee: `tee`

出力をファイルと標準出力の両方に書き込みます。

```bash
# 出力を保存し、表示する
command | tee output.txt
# ファイルに追加
command | tee -a output.txt
# 複数の出力先
command | tee file1.txt file2.txt
```

### Here Document: `<<`

コマンドに複数行の入力を提供します。

```bash
# Here documentでファイルを作成
cat << EOF > file.txt
Line 1
Line 2
Line 3
EOF
# Here documentでメールを送信
mail user@example.com << EOF
Subject: Test
This is a test message.
EOF
```

## 変数と環境

### 変数：代入と使用

シェル変数の作成と使用。

```bash
# 変数の代入（=の周りにスペースなし）
name="John"
count=42
# 変数の使用
echo $name
echo "Hello, $name"
echo "Count: ${count}"
# コマンド置換
current_dir=$(pwd)
date_today=$(date +%Y-%m-%d)
```

### 環境変数：`export` / `env`

環境変数を管理します。

```bash
# 変数を環境にエクスポート
export PATH="/new/path:$PATH"
export MY_VAR="value"
# すべての環境変数を表示
env
# 特定の変数を表示
echo $HOME
echo $PATH
# 変数を解除
unset MY_VAR
```

### 特殊変数

特別な意味を持つ組み込みシェル変数。

```bash
# スクリプト引数
$0  # スクリプト名
$1, $2, $3...  # 1番目、2番目、3番目の引数
$#  # 引数の数
$@  # すべての引数（単語として分離）
$*  # すべての引数（単一の単語として）
$?  # 最後のコマンドの終了ステータス
# プロセス情報
$$  # 現在のシェルのPID
$!  # 最後のバックグラウンドプロセスのPID
```

### パラメータ展開

高度な変数操作技術。

```bash
# デフォルト値
${var:-default}  # varが空の場合にデフォルトを使用
${var:=default}  # varが空の場合にデフォルトを設定
# 文字列操作
${var#pattern}   # 先頭から最短一致を削除
${var##pattern}  # 先頭から最長一致を削除
${var%pattern}   # 末尾から最短一致を削除
${var%%pattern}  # 末尾から最長一致を削除
```

## スクリプトの基本

### スクリプト構造

基本的なスクリプト形式と実行方法。

```bash
#!/bin/bash
# これはコメントです
# 変数
greeting="Hello, World!"
user=$(whoami)
# 出力
echo $greeting
echo "Current user: $user"
# スクリプトの実行権限を付与:
chmod +x script.sh
# スクリプトの実行:
./script.sh
```

### 条件文：`if`

条件に基づいてスクリプトの流れを制御します。

```bash
#!/bin/bash
if [ -f "file.txt" ]; then
    echo "File exists"
elif [ -d "directory" ]; then
    echo "Directory exists"
else
    echo "Neither exists"
fi
# 文字列比較
if [ "$USER" = "root" ]; then
    echo "Running as root"
fi
# 数値比較
if [ $count -gt 10 ]; then
    echo "Count is greater than 10"
fi
```

### ループ：`for` / `while`

ループを使用してコマンドを繰り返します。

```bash
#!/bin/bash
# 範囲指定のForループ
for i in {1..5}; do
    echo "Number: $i"
done
# ファイル指定のForループ
for file in *.txt; do
    echo "Processing: $file"
done
# Whileループ
count=1
while [ $count -le 5 ]; do
    echo "Count: $count"
    count=$((count + 1))
done
```

### 関数

再利用可能なコードブロックを作成します。

```bash
#!/bin/bash
# 関数の定義
greet() {
    local name=$1
    echo "Hello, $name!"
}
# 戻り値を持つ関数
add_numbers() {
    local sum=$(($1 + $2))
    echo $sum
}
# 関数の呼び出し
greet "Alice"
result=$(add_numbers 5 3)
echo "Sum: $result"
```

## ネットワークとシステムコマンド

### ネットワークコマンド

接続性をテストし、ネットワーク構成を表示します。

```bash
# ネットワーク接続性をテスト
ping google.com
ping -c 4 google.com  # 4パケットのみ送信
# DNSルックアップ
nslookup google.com
dig google.com
# ネットワーク構成
ip addr show  # IPアドレスを表示
ip route show # ルーティングテーブルを表示
# ファイルのダウンロード
wget https://example.com/file.txt
curl -O https://example.com/file.txt
```

### システム情報：`uname` / `whoami` / `date`

システムおよびユーザー情報を取得します。

```bash
# システム情報
uname -a      # 全システム情報
uname -r      # カーネルバージョン
hostname      # コンピュータ名
whoami        # 現在のユーザー名
id            # ユーザーIDとグループ
# 日付と時刻
date          # 現在の日付/時刻
date +%Y-%m-%d # カスタム形式
uptime        # システム稼働時間
```

### アーカイブと圧縮：`tar` / `zip`

圧縮アーカイブの作成と展開を行います。

```bash
# tarアーカイブの作成
tar -czf archive.tar.gz directory/
# tarアーカイブの展開
tar -xzf archive.tar.gz
# zipアーカイブの作成
zip -r archive.zip directory/
# zipアーカイブの展開
unzip archive.zip
# アーカイブの内容の表示
tar -tzf archive.tar.gz
unzip -l archive.zip
```

### ファイル転送：`scp` / `rsync`

システム間でファイルを転送します。

```bash
# ファイルをリモートサーバーにコピー
scp file.txt user@server:/path/to/destination
# リモートサーバーからコピー
scp user@server:/path/to/file.txt .
# ディレクトリの同期（ローカルからリモートへ）
rsync -avz local_dir/ user@server:/remote_dir/
# 削除付き同期（ミラーリング）
rsync -avz --delete local_dir/ user@server:/remote_dir/
```

## コマンド履歴とショートカット

### コマンド履歴：`history`

以前のコマンドを表示し、再利用します。

```bash
# コマンド履歴を表示
history
# 最後の10個のコマンドを表示
history 10
# 直前のコマンドを実行
!!
# 番号でコマンドを実行
!123
# 'ls'で始まる最後のコマンドを実行
!ls
# 対話的に履歴を検索
Ctrl+R
```

### 履歴展開

以前のコマンドの一部を再利用します。

```bash
# 前のコマンドの引数
!$    # 前のコマンドの最後の引数
!^    # 前のコマンドの最初の引数
!*    # 前のコマンドのすべての引数
# 使用例:
ls /very/long/path/to/file.txt
cd !$  # /very/long/path/to/file.txt に移動
```

### キーボードショートカット

効率的なコマンドライン操作のための必須ショートカット。

```bash
# ナビゲーション
Ctrl+A  # 行の先頭に移動
Ctrl+E  # 行の末尾に移動
Ctrl+F  # 1文字前に移動
Ctrl+B  # 1文字後ろに移動
Alt+F   # 1単語前に移動
Alt+B   # 1単語後ろに移動
# 編集
Ctrl+U  # カーソルより前の行をクリア
Ctrl+K  # カーソルより後の行をクリア
Ctrl+W  # カーソル前の単語を削除
Ctrl+Y  # 最後に削除したテキストを貼り付け
# プロセス制御
Ctrl+C  # 現在のコマンドを中断
Ctrl+Z  # 現在のコマンドを一時停止
Ctrl+D  # シェルを終了またはEOF
```

## コマンドの組み合わせとヒント

### 役立つコマンドの組み合わせ

一般的なタスクのための強力なワンライナー。

```bash
# 複数ファイル内のテキストを検索・置換
find . -name "*.txt" -exec sed -i 's/old/new/g' {} \;
# 現在のディレクトリ内の最大ファイルを見つける
du -ah . | sort -rh | head -10
# 特定のパターンについてログファイルを監視
tail -f /var/log/syslog | grep "ERROR"
# ディレクトリ内のファイルをカウント
ls -1 | wc -l
# タイムスタンプ付きでバックアップを作成
cp file.txt file.txt.backup.$(date +%Y%m%d-%H%M%S)
```

### エイリアスと関数

頻繁に使用するコマンドのショートカットを作成します。

```bash
# エイリアスの作成（~/.bashrc に追加）
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
# すべてのエイリアスを表示
alias
# 永続的なエイリアスを ~/.bashrc に作成:
echo "alias mycommand='long command here'" >>
~/.bashrc
source ~/.bashrc
```

### ジョブ制御と画面セッション

長時間実行されるプロセスとセッションを管理します。

```bash
# コマンドをバックグラウンドで開始
nohup long_running_command &
# screenセッションの開始
screen -S mysession
# screenからデタッチ: Ctrl+A の後に D
# screenに再アタッチ
screen -r mysession
# screenセッションの一覧表示
screen -ls
# 代替: tmux
tmux new -s mysession
# デタッチ: Ctrl+B の後に D
tmux attach -t mysession
```

### システムメンテナンス

一般的なシステム管理タスク。

```bash
# ディスク使用量の確認
df -h
du -sh /*
# メモリ使用量の確認
free -h
cat /proc/meminfo
# 実行中のサービスの状態確認
systemctl status service_name
systemctl list-units --type=service
# パッケージリストの更新 (Ubuntu/Debian)
sudo apt update && sudo apt upgrade
# インストール済みパッケージの検索
dpkg -l | grep package_name
```

## 関連リンク

- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux チートシート</router-link>
- <router-link to="/git">Git チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/kubernetes">Kubernetes チートシート</router-link>
- <router-link to="/ansible">Ansible チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>

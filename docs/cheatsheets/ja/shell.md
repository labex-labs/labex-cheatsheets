---
title: 'シェルチートシート | LabEx'
description: 'この包括的なチートシートでシェルスクリプトを習得しましょう。Bash コマンド、シェルスクリプト、自動化、コマンドラインツール、Linux/Unix システム管理のクイックリファレンス。'
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
ハンズオンラボと実世界のシナリオを通じて、シェルスクリプトとコマンドライン操作を学びましょう。LabEx は、必須の Bash コマンド、ファイル操作、テキスト処理、プロセス管理、自動化を網羅した包括的な Shell コースを提供します。コマンドラインの効率性とシェルスクリプト技術を習得してください。
</base-disclaimer-content>
</base-disclaimer>

## ファイルとディレクトリの操作

### ファイル一覧表示：`ls`

現在の場所にあるファイルとディレクトリを表示します。

```bash
# 現在のディレクトリのファイルを一覧表示
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
# 既存ファイルのタイムスタンプを更新
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
# 対話形式で削除 (それぞれ確認)
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

<BaseQuiz id="shell-cd-1" correct="A">
  <template #question>
    <code>cd ~</code> は何を行いますか？
  </template>
  
  <BaseQuizOption value="A" correct>ホームディレクトリに変更する</BaseQuizOption>
  <BaseQuizOption value="B">ルートディレクトリに変更する</BaseQuizOption>
  <BaseQuizOption value="C">親ディレクトリに変更する</BaseQuizOption>
  <BaseQuizOption value="D">新しいディレクトリを作成する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>~</code> 記号はホームディレクトリのショートカットです。<code>cd ~</code> はホームディレクトリに移動し、<code>cd $HOME</code> または <code>cd /home/username</code> と同等です。
  </BaseQuizAnswer>
</BaseQuiz>

### ディレクトリツリー: `tree`

ディレクトリ構造をツリー形式で表示します。

```bash
# ディレクトリツリーを表示
tree
# 階層を2レベルに制限
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
# ページごとに表示
less file.txt
# 最初の10行を表示
head file.txt
# 最後の10行を表示
tail file.txt
# 最後の20行を表示
tail -n 20 file.txt
# ファイルの変更を追跡 (ログに便利)
tail -f logfile.txt
```

### ファイル内検索：`grep`

テキストファイル内のパターンを検索します。

```bash
# ファイル内のパターンを検索
grep "pattern" file.txt
# 大文字・小文字を区別しない検索
grep -i "pattern" file.txt
# ディレクトリ内で再帰的に検索
grep -r "pattern" directory/
# 行番号を表示
grep -n "pattern" file.txt
# 一致した行数をカウント
grep -c "pattern" file.txt
```

<BaseQuiz id="shell-grep-1" correct="B">
  <template #question>
    <code>grep -r "pattern" directory/</code> は何を行いますか？
  </template>
  
  <BaseQuizOption value="A">現在のファイルのみを検索する</BaseQuizOption>
  <BaseQuizOption value="B" correct>ディレクトリ内のすべてのファイルを再帰的に検索する</BaseQuizOption>
  <BaseQuizOption value="C">ファイル内のパターンを置換する</BaseQuizOption>
  <BaseQuizOption value="D">パターンを含むファイルを削除する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-r</code> フラグにより、grep はすべてのファイルとサブディレクトリを再帰的に検索します。これはディレクトリツリー全体でテキストパターンを見つけるのに役立ちます。
  </BaseQuizAnswer>
</BaseQuiz>

### ファイル検索：`find`

基準に基づいてファイルやディレクトリを見つけます。

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
# ファイル内容をソート
sort file.txt
# 重複行を削除
sort file.txt | uniq
# 単語の頻度をカウント
cat file.txt | tr ' ' '\n' | sort | uniq -c
```

## ファイルの権限と所有権

### 権限表示：`ls -l`

詳細なファイル権限と所有権を表示します。

```bash
# 詳細なファイル情報を表示
ls -l
# 出力例:
# -rw-r--r-- 1 user group 1024 Jan 1 12:00 file.txt
# d = directory, r = read, w = write, x = execute
```

### 権限変更：`chmod`

ファイルとディレクトリの権限を変更します。

```bash
# オーナーに実行権限を付与
chmod +x script.sh
# 特定の権限 (755) を設定
chmod 755 file.txt
# グループとその他の書き込み権限を削除
chmod go-w file.txt
# 再帰的な権限変更
chmod -R 644 directory/
```

<BaseQuiz id="shell-chmod-1" correct="C">
  <template #question>
    <code>chmod 755 file.txt</code> は何をセットしますか？
  </template>
  
  <BaseQuizOption value="A">すべてのユーザーに読み取り、書き込み、実行</BaseQuizOption>
  <BaseQuizOption value="B">オーナーに読み取りと書き込み、その他に読み取り</BaseQuizOption>
  <BaseQuizOption value="C" correct>オーナーに読み取り、書き込み、実行。グループとその他に読み取り、実行</BaseQuizOption>
  <BaseQuizOption value="D">すべてのユーザーに読み取りのみ</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 755</code> は権限を次のように設定します：オーナー = 7 (rwx)、グループ = 5 (r-x)、その他 = 5 (r-x)。これは実行可能ファイルやディレクトリの一般的な権限設定です。
  </BaseQuizAnswer>
</BaseQuiz>

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

### 権限の数値

数値による権限表記の理解。

```text
# 権限の計算：
# 4 = 読み取り (r), 2 = 書き込み (w), 1 = 実行 (x)
# 755 = rwxr-xr-x (オーナー: rwx, グループ：r-x, その他：r-x)
# 644 = rw-r--r-- (オーナー: rw-, グループ：r--, その他：r--)
# 777 = rwxrwxrwx (すべてに完全な権限)
# 600 = rw------- (オーナー: rw-, グループ：---, その他：---)
```

## プロセス管理

### プロセス表示：`ps` / `top` / `htop`

実行中のプロセスに関する情報を表示します。

```bash
# 現在のユーザーのプロセスを表示
ps
# すべてのプロセスを詳細付きで表示
ps aux
# ツリー形式でプロセスを表示
ps -ef --forest
# 対話型プロセスビューア
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
# 現在のプロセスを中断
Ctrl+Z
```

### プロセス終了：`kill` / `killall`

PID または名前でプロセスを終了させます。

```bash
# PIDでプロセスを終了
kill 1234
# プロセスを強制終了
kill -9 1234
# 名前が一致するすべてのプロセスを終了
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
# 出力をファイルにリダイレクト (上書き)
command > output.txt
# 出力をファイルに追加
command >> output.txt
# 入力をファイルからリダイレクト
command < input.txt
# 出力とエラーの両方をリダイレクト
command > output.txt 2>&1
# 出力を破棄
command > /dev/null
```

<BaseQuiz id="shell-redirect-1" correct="B">
  <template #question>
    シェルリダイレクトにおける <code>></code> と <code>>></code> の違いは何ですか？
  </template>
  
  <BaseQuizOption value="A"><code>></code> は追加し、<code>>></code> は上書きする</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>></code> はファイルを上書きし、<code>>></code> はファイルに追加する</BaseQuizOption>
  <BaseQuizOption value="C"><code>></code> は stdout をリダイレクトし、<code>>></code> は stderr をリダイレクトする</BaseQuizOption>
  <BaseQuizOption value="D">違いはない</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>></code> 演算子は、ファイルが存在する場合にターゲットファイルを上書きしますが、<code>>></code> は出力の末尾に追記します。既存のコンテンツを保持したい場合は <code>>></code> を使用します。
  </BaseQuizAnswer>
</BaseQuiz>

### パイプ：`|`

パイプを使用してコマンドを連鎖させます。

```bash
# 基本的なパイプの使用
command1 | command2
# 複数のパイプ
cat file.txt | grep "pattern" | sort | uniq
# 出力行数をカウント
ps aux | wc -l
# 長い出力をページ送り
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
# Here Document を使用してファイルを作成
cat << EOF > file.txt
Line 1
Line 2
Line 3
EOF
# Here Document を使用してメールを送信
mail user@example.com << EOF
Subject: Test
This is a test message.
EOF
```

## 変数と環境

### 変数：代入と使用

シェル変数を作成し、使用します。

```bash
# 変数の代入 ( = の周りにスペースなし)
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
$@  # すべての引数 (単語ごとに分離)
$*  # すべての引数 (単一の単語として)
$?  # 最後のコマンドの終了ステータス
# プロセス情報
$$  # 現在のシェルのPID
$!  # 最後にバックグラウンド実行されたプロセスのPID
```

### パラメータ展開

高度な変数操作技術。

```bash
# デフォルト値
${var:-default}  # varが空の場合にデフォルトを使用
${var:=default}  # varが空の場合にvarをデフォルトに設定
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
# スクリプトを実行:
./script.sh
```

### 条件文：`if`

条件によってスクリプトの流れを制御します。

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
# ネットワーク設定
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
uname -a      # すべてのシステム情報
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
# リモートサーバーにファイルをコピー
scp file.txt user@server:/path/to/destination
# リモートサーバーからコピー
scp user@server:/path/to/file.txt .
# ディレクトリの同期 (ローカルからリモートへ)
rsync -avz local_dir/ user@server:/remote_dir/
# 削除付きの同期 (ミラーリング)
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
# 対話形式で履歴を検索
Ctrl+R
```

### 履歴展開

以前のコマンドの一部を再利用します。

```bash
# 前のコマンドの引数
!$    # 直前のコマンドの最後の引数
!^    # 直前のコマンドの最初の引数
!*    # 直前のコマンドのすべての引数
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
Ctrl+U  # カーソルより前の行全体をクリア
Ctrl+K  # カーソルより後の行全体をクリア
Ctrl+W  # カーソルより前の単語を削除
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
# 現在のディレクトリで最大のファイルを見つける
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
# エイリアスの作成 ( ~/.bashrc に追加)
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

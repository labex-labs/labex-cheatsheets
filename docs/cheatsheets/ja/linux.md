---
title: 'Linux チートシート'
description: '必須のコマンド、概念、ベストプラクティスを網羅した包括的なチートシートで Linux を学習しましょう。'
pdfUrl: '/cheatsheets/pdf/linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Linux チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a href="https://linux-commands.labex.io/" target="_blank">Linux コマンドにアクセス</a>
</base-disclaimer-title>
<base-disclaimer-content>
包括的な Linux コマンドリファレンス資料、構文例、および詳細なドキュメントについては、<a href="https://linux-commands.labex.io/" target="_blank">linux-commands.labex.io</a>をご覧ください。この独立したサイトでは、Linux 管理者および開発者向けの必須コマンド、概念、ベストプラクティスを網羅した広範な Linux チートシートを提供しています。
</base-disclaimer-content>
</base-disclaimer>

## システム情報とステータス

### システム情報：`uname`

カーネルやアーキテクチャを含むシステム情報を表示します。

```bash
# カーネル名を表示
uname
# すべてのシステム情報を表示
uname -a
# カーネルバージョンを表示
uname -r
# アーキテクチャを表示
uname -m
# オペレーティングシステムを表示
uname -o
```

### ハードウェア情報：`lscpu`, `lsblk`

詳細なハードウェア仕様とブロックデバイスを表示します。

```bash
# CPU情報
lscpu
# ブロックデバイス（ディスク、パーティション）
lsblk
# メモリ情報
free -h
# ファイルシステムごとのディスク使用量
df -h
```

### システム稼働時間：`uptime`

システムの稼働時間と負荷平均を表示します。

```bash
# システム稼働時間と負荷
uptime
# より詳細な稼働時間情報
uptime -p
# 特定の日付からの稼働時間を表示
uptime -s
```

### 現在のユーザー: `who`, `w`

現在ログインしているユーザーとそのアクティビティを表示します。

```bash
# ログイン中のユーザーを表示
who
# アクティビティを含む詳細なユーザー情報
w
# 現在のユーザー名を表示
whoami
# ログイン履歴を表示
last
```

### 環境変数：`env`

環境変数を表示および管理します。

```bash
# すべての環境変数を表示
env
# 特定の変数を表示
echo $HOME
# 環境変数を設定
export PATH=$PATH:/new/path
# PATH変数を表示
echo $PATH
```

### 日付と時刻：`date`, `timedatectl`

システムの日付と時刻を表示および設定します。

```bash
# 現在の日付と時刻
date
# システム時刻を設定（rootとして）
date MMddhhmmyyyy
# タイムゾーン情報
timedatectl
# タイムゾーンを設定
timedatectl set-timezone America/New_York
```

## ファイルとディレクトリの操作

### ファイル一覧表示：`ls`

様々なフォーマットオプションでファイルとディレクトリを表示します。

```bash
# 現在のディレクトリのファイルを一覧表示
ls
# 権限付きの詳細リスト
ls -l
# 隠しファイルを表示
ls -la
# 人間が読みやすいファイルサイズ
ls -lh
# 更新時刻でソート
ls -lt
```

### ディレクトリの移動：`cd`, `pwd`

ディレクトリを変更し、現在の場所を表示します。

```bash
# ホームディレクトリに移動
cd
# 特定のディレクトリに移動
cd /path/to/directory
# 1レベル上に移動
cd ..
# 現在のディレクトリを表示
pwd
# 前のディレクトリに移動
cd -
```

### 作成と削除：`mkdir`, `rmdir`, `rm`

ファイルとディレクトリを作成および削除します。

```bash
# ディレクトリを作成
mkdir newdir
# ネストされたディレクトリを作成
mkdir -p path/to/nested/dir
# 空のディレクトリを削除
rmdir dirname
# ファイルを削除
rm filename
# ディレクトリを再帰的に削除
rm -rf dirname
```

### ファイル内容の表示：`cat`, `less`, `head`, `tail`

様々な方法とページネーションを使用してファイル内容を表示します。

```bash
# ファイル全体を表示
cat filename
# ページネーション付きで表示
less filename
# 最初の10行を表示
head filename
# 最後の10行を表示
tail filename
# リアルタイムでファイルの変更を追跡
tail -f logfile
```

### コピーと移動：`cp`, `mv`

ファイルとディレクトリをコピーおよび移動します。

```bash
# ファイルをコピー
cp source.txt destination.txt
# ディレクトリを再帰的にコピー
cp -r sourcedir/ destdir/
# ファイルを移動/名前変更
mv oldname.txt newname.txt
# 別のディレクトリに移動
mv file.txt /path/to/destination/
# 属性を保持してコピー
cp -p file.txt backup.txt
```

### ファイル検索：`find`, `locate`

名前、タイプ、またはプロパティでファイルとディレクトリを検索します。

```bash
# 名前で検索
find /path -name "filename"
# 過去7日間に変更されたファイルを検索
find /path -mtime -7
# ファイルタイプで検索
find /path -type f -name "*.txt"
# 迅速にファイルを検索（updatedbが必要）
locate filename
# 検索してコマンドを実行
find /path -name "*.log" -exec rm {} \;
```

### ファイルパーミッション：`chmod`, `chown`

ファイルパーミッションと所有権を変更します。

```bash
# パーミッションの変更（数値）
chmod 755 filename
# 実行権限の追加
chmod +x script.sh
# 所有権の変更
chown user:group filename
# 所有権の再帰的な変更
chown -R user:group directory/
# ファイルパーミッションの表示
ls -l filename
```

## プロセス管理

### プロセス一覧表示：`ps`

実行中のプロセスとその詳細を表示します。

```bash
# ユーザープロセスを表示
ps
# 詳細付きですべてのプロセスを表示
ps aux
# プロセスツリーを表示
ps -ef --forest
# ユーザーごとのプロセスを表示
ps -u username
```

### プロセスの終了：`kill`, `killall`

PID または名前でプロセスを終了します。

```bash
# リアルタイムプロセスモニター
top
# PIDでプロセスを終了
kill 1234
# プロセスを強制終了
kill -9 1234
# プロセス名で終了
killall processname
# すべてのシグナルを一覧表示
kill -l
# 特定のシグナルを送信
kill -HUP 1234
```

### バックグラウンドジョブ：`jobs`, `bg`, `fg`

バックグラウンドおよびフォアグラウンドのプロセスを管理します。

```bash
# アクティブなジョブを一覧表示
jobs
# ジョブをバックグラウンドに送信
bg %1
# ジョブをフォアグラウンドに移動
fg %1
# コマンドをバックグラウンドで実行
command &
# ターミナルからデタッチ
nohup command &
```

### システムモニター: `htop`, `systemctl`

システムリソースを監視し、サービスを管理します。

```bash
# 強化されたプロセスビューア（インストールされている場合）
htop
# サービスの状態を確認
systemctl status servicename
# サービスを開始
systemctl start servicename
# ブート時にサービスを有効化
systemctl enable servicename
# システムログを表示
journalctl -f
```

## ネットワーク操作

### ネットワーク設定：`ip`, `ifconfig`

ネットワークインターフェースを表示および設定します。

```bash
# ネットワークインターフェースを表示
ip addr show
# ルーティングテーブルを表示
ip route show
# インターフェースの設定（一時的）
ip addr add 192.168.1.10/24 dev eth0
# インターフェースのアップ/ダウン
ip link set eth0 up
# 従来のインターフェース設定
ifconfig
```

### ネットワークテスト：`ping`, `traceroute`

ネットワーク接続をテストし、パケットルートをトレースします。

```bash
# 接続性をテスト
ping google.com
# カウント制限付きでping
ping -c 4 192.168.1.1
# 宛先へのルートトレース
traceroute google.com
# MTR - ネットワーク診断ツール
mtr google.com
```

### ポートと接続分析：`netstat`, `ss`

ネットワーク接続とリッスンポートを表示します。

```bash
# すべての接続を表示
netstat -tuln
# リッスン中のポートを表示
netstat -tuln | grep LISTEN
# netstatのモダンな代替
ss -tuln
# ポートを使用しているプロセスを表示
netstat -tulnp
# 特定のポートを確認
netstat -tuln | grep :80
```

### ファイル転送：`scp`, `rsync`

システム間でファイルを安全に転送します。

```bash
# リモートホストにファイルをコピー
scp file.txt user@host:/path/
# リモートホストからコピー
scp user@host:/path/file.txt ./
# ディレクトリを同期
rsync -avz localdir/ user@host:/remotedir/
# 進捗を表示してrsync
rsync -avz --progress src/ dest/
```

## テキスト処理と検索

### テキスト検索：`grep`

ファイル内およびコマンド出力内のパターンを検索します。

```bash
# ファイル内のパターンを検索
grep "pattern" filename
# 大文字・小文字を区別しない検索
grep -i "pattern" filename
# ディレクトリ内での再帰的検索
grep -r "pattern" /path/
# 行番号を表示
grep -n "pattern" filename
# 一致した行数をカウント
grep -c "pattern" filename
```

### テキスト操作：`sed`, `awk`

ストリームエディタとパターン走査を使用してテキストを編集および処理します。

```bash
# ファイル内のテキストを置換
sed 's/old/new/g' filename
# パターンを含む行を削除
sed '/pattern/d' filename
# 特定のフィールドを出力
awk '{print $1, $3}' filename
# 列の値を合計
awk '{sum += $1} END {print sum}' filename
```

### ソートとカウント：`sort`, `uniq`, `wc`

データをソートし、重複を削除し、行、単語、文字をカウントします。

```bash
# ファイル内容をソート
sort filename
# 数値でソート
sort -n numbers.txt
# 重複行を削除
uniq filename
# ソートして重複を削除
sort filename | uniq
# ファイルの行数、単語数、文字数をカウント
wc filename
# 行数のみカウント
wc -l filename
```

### カットとペースト：`cut`, `paste`

特定の列を抽出し、ファイルを結合します。

```bash
# 最初の列を抽出
cut -d',' -f1 file.csv
# 文字範囲を抽出
cut -c1-10 filename
# ファイルを並べて結合
paste file1.txt file2.txt
# カスタム区切り文字を使用
cut -d':' -f1,3 /etc/passwd
```

## アーカイブと圧縮

### アーカイブの作成：`tar`

圧縮アーカイブの作成と展開を行います。

```bash
# tarアーカイブを作成
tar -cf archive.tar files/
# 圧縮アーカイブを作成
tar -czf archive.tar.gz files/
# アーカイブを展開
tar -xf archive.tar
# 圧縮アーカイブを展開
tar -xzf archive.tar.gz
# アーカイブの内容を一覧表示
tar -tf archive.tar
```

### 圧縮：`gzip`, `zip`

様々なアルゴリズムを使用してファイルを圧縮および解凍します。

```bash
# gzipでファイルを圧縮
gzip filename
# gzipファイルを解凍
gunzip filename.gz
# zipアーカイブを作成
zip archive.zip file1 file2
# zipアーカイブを展開
unzip archive.zip
# zipの内容を一覧表示
unzip -l archive.zip
```

### 高度なアーカイブ：`tar` オプション

バックアップとリストアのための高度な tar 操作。

```bash
# 圧縮付きでアーカイブを作成
tar -czvf backup.tar.gz /home/user/
# 特定のディレクトリに展開
tar -xzf archive.tar.gz -C /destination/
# 既存のアーカイブにファイルを追加
tar -rf archive.tar newfile.txt
# 新しいファイルでアーカイブを更新
tar -uf archive.tar files/
```

### ディスク使用量：`du`

ディスク使用量を分析し、ディレクトリサイズを確認します。

```bash
# ディレクトリサイズを表示
du -h /path/
# 合計サイズ
du -sh /path/
# すべてのサブディレクトリのサイズを表示
du -h --max-depth=1 /path/
# 降順で上位10件のディレクトリを表示
du -h | sort -hr | head -10
```

## システム監視とパフォーマンス

### メモリ使用量：`free`, `vmstat`

メモリ使用量と仮想メモリ統計を監視します。

```bash
# メモリ使用量の概要
free -h
# 詳細なメモリ統計
cat /proc/meminfo
# 仮想メモリ統計
vmstat
# 2秒ごとにメモリ使用量を表示
vmstat 2
# スワップ使用量を表示
swapon --show
```

### ディスク I/O: `iostat`, `iotop`

ディスクの入出力パフォーマンスを監視し、ボトルネックを特定します。

```bash
# I/O統計（sysstatが必要）
iostat
# 2秒ごとにI/O統計
iostat 2
# プロセスごとのディスクI/Oを監視
iotop
# 特定のデバイスのI/O使用量を表示
iostat -x /dev/sda
```

### システム負荷：`top`, `htop`

システム負荷、CPU 使用率、実行中のプロセスを監視します。

```bash
# リアルタイムプロセスモニター
top
# 強化されたプロセスビューア
htop
# 負荷平均を表示
uptime
# CPU情報を表示
lscpu
# 特定のプロセスを監視
top -p PID
```

### ログファイル：`journalctl`, `dmesg`

トラブルシューティングのためにシステムログを表示および分析します。

```bash
# システムログを表示
journalctl
# リアルタイムでログを追跡
journalctl -f
# 特定のサービスに関するログを表示
journalctl -u servicename
# カーネルメッセージ
dmesg
# 最後のブートメッセージ
dmesg | tail
```

## ユーザーとパーミッションの管理

### ユーザー操作：`useradd`, `usermod`, `userdel`

ユーザーアカウントの作成、変更、削除を行います。

```bash
# 新しいユーザーを追加
useradd username
# ホームディレクトリ付きでユーザーを追加
useradd -m username
# ユーザーアカウントを変更
usermod -aG groupname username
# ユーザーアカウントを削除
userdel username
# ホームディレクトリ付きでユーザーを削除
userdel -r username
```

### グループ管理：`groupadd`, `groups`

ユーザーグループの作成と管理を行います。

```bash
# 新しいグループを作成
groupadd groupname
# ユーザーのグループを表示
groups username
# すべてのグループを表示
cat /etc/group
# ユーザーをグループに追加
usermod -aG groupname username
# ユーザーのプライマリグループを変更
usermod -g groupname username
```

### ユーザーの切り替え：`su`, `sudo`

ユーザーを切り替え、特権付きでコマンドを実行します。

```bash
# rootユーザーに切り替え
su -
# 特定のユーザーに切り替え
su - username
# rootとしてコマンドを実行
sudo command
# 特定のユーザーとしてコマンドを実行
sudo -u username command
# sudoersファイルを編集
visudo
```

### パスワード管理：`passwd`, `chage`

ユーザーパスワードとアカウントポリシーを管理します。

```bash
# パスワードを変更
passwd
# 他のユーザーのパスワードを変更（rootとして）
passwd username
# パスワードの有効期限情報を表示
chage -l username
# パスワードの有効期限を設定
chage -M 90 username
# 次回ログイン時にパスワード変更を強制
passwd -e username
```

## パッケージ管理

### APT (Debian/Ubuntu): `apt`, `apt-get`

Debian ベースのシステムでパッケージを管理します。

```bash
# パッケージリストを更新
apt update
# すべてのパッケージをアップグレード
apt upgrade
# パッケージをインストール
apt install packagename
# パッケージを削除
apt remove packagename
# パッケージを検索
apt search packagename
# パッケージ情報を表示
apt show packagename
```

### YUM/DNF (RHEL/Fedora): `yum`, `dnf`

Red Hat ベースのシステムでパッケージを管理します。

```bash
# パッケージをインストール
yum install packagename
# すべてのパッケージを更新
yum update
# パッケージを削除
yum remove packagename
# パッケージを検索
yum search packagename
# インストール済みパッケージを一覧表示
yum list installed
```

### Snap パッケージ：`snap`

ディストリビューション全体で snap パッケージをインストールおよび管理します。

```bash
# snapパッケージをインストール
snap install packagename
# インストール済みsnapを一覧表示
snap list
# snapパッケージを更新
snap refresh
# snapパッケージを削除
snap remove packagename
# snapパッケージを検索
snap find packagename
```

### Flatpak パッケージ：`flatpak`

サンドボックス化されたソフトウェアのために Flatpak アプリケーションを管理します。

```bash
# flatpakをインストール
flatpak install packagename
# インストール済みflatpakを一覧表示
flatpak list
# flatpakパッケージを更新
flatpak update
# flatpakを削除
flatpak uninstall packagename
# flatpakパッケージを検索
flatpak search packagename
```

## シェルとスクリプティング

### コマンド履歴：`history`

コマンドライン履歴にアクセスし、管理します。

```bash
# コマンド履歴を表示
history
# 最後の10件を表示
history 10
# 直前のコマンドを実行
!!
# 番号でコマンドを実行
!123
# 対話的に履歴を検索
Ctrl+R
```

### エイリアスと関数：`alias`

頻繁に使用するコマンドのショートカットを作成します。

```bash
# エイリアスを作成
alias ll='ls -la'
# すべてのエイリアスを表示
alias
# エイリアスを削除
unalias ll
# エイリアスを永続化（.bashrcに追加）
echo "alias ll='ls -la'" >> ~/.bashrc
```

### 入出力のリダイレクト

コマンドの入出力をファイルや他のコマンドにリダイレクトします。

```bash
# 出力をファイルにリダイレクト
command > output.txt
# 出力をファイルに追加
command >> output.txt
# 入力をファイルからリダイレクト
command < input.txt
# stdoutとstderrの両方をリダイレクト
command &> output.txt
# 出力を別のコマンドにパイプ
command1 | command2
```

### 環境設定：`.bashrc`, `.profile`

シェル環境と起動スクリプトを設定します。

```bash
# bash設定を編集
nano ~/.bashrc
# 設定をリロード
source ~/.bashrc
# 環境変数を設定
export VARIABLE=value
# PATHに追加
export PATH=$PATH:/new/path
# 環境変数を表示
printenv
```

## システムのインストールと設定

### ディストリビューションの選択肢：Ubuntu, CentOS, Debian

異なるユースケースのために Linux ディストリビューションを選択しインストールします。

```bash
# Ubuntu Server
wget ubuntu-server.iso
# CentOS Stream
wget centos-stream.iso
# Debian Stable
wget debian.iso
# ISOの整合性を検証
sha256sum linux.iso
```

### ブートとインストール：USB、ネットワーク

ブータブルメディアを作成し、システムインストールを実行します。

```bash
# ブータブルUSBを作成（Linux）
dd if=linux.iso of=/dev/sdX bs=4M
# ブータブルUSBを作成（クロスプラットフォーム）
# Rufus、Etcher、またはUNetbootinなどのツールを使用
# ネットワークインストール
# ネットワークインストール用にPXEブートを設定
```

### 初期設定：ユーザー、ネットワーク、SSH

インストール後の基本的なシステム設定。

```bash
# ホスト名を設定
hostnamectl set-hostname newname
# 静的IPを設定
# Ubuntuでは /etc/netplan/ を編集
# ネットワークサービスを有効化
systemctl enable ssh
systemctl start ssh
# ファイアウォールを設定
ufw enable
ufw allow ssh
```

## セキュリティとベストプラクティス

### ファイアウォール設定：`ufw`, `iptables`

ネットワークの脅威からシステムを保護するためにファイアウォールルールを設定します。

```bash
# UFWファイアウォールを有効化
ufw enable
# 特定のポートを許可
ufw allow 22/tcp
# サービス名でSSHを許可
ufw allow ssh
# アクセスを拒否
ufw deny 23
# ファイアウォールステータスを表示
ufw status verbose
# 高度なルールはiptablesで
iptables -L
```

### ファイルの整合性：`checksums`

ファイルの整合性を検証し、不正な変更を検出します。

```bash
# MD5チェックサムを生成
md5sum filename
# SHA256チェックサムを生成
sha256sum filename
# チェックサムを検証
sha256sum -c checksums.txt
# チェックサムファイルを作成
sha256sum *.txt > checksums.txt
```

### システム更新：セキュリティパッチ

定期的な更新とセキュリティパッチでシステムを安全に保ちます。

```bash
# Ubuntuのセキュリティ更新
apt update && apt upgrade
# 自動セキュリティ更新
unattended-upgrades
# CentOS/RHELの更新
yum update --security
# アップグレード可能なパッケージを一覧表示
apt list --upgradable
```

### ログ監視：セキュリティイベント

セキュリティイベントと異常を検出するためにシステムログを監視します。

```bash
# 認証ログを監視
tail -f /var/log/auth.log
# ログイン失敗を検索
grep "Failed password" /var/log/auth.log
# システムログを監視
tail -f /var/log/syslog
# ログイン履歴を確認
last
# 不審なアクティビティを確認
journalctl -p err
```

## トラブルシューティングとリカバリ

### ブートの問題：GRUB リカバリ

ブートローダーとカーネルの問題から復旧します。

```bash
# リスキューモードで起動
# ブート中にGRUBメニューにアクセス
# ルートファイルシステムをマウント
mount /dev/sda1 /mnt
# システムにchroot
chroot /mnt
# GRUBを再インストール
grub-install /dev/sda
# GRUB設定を更新
update-grub
```

### ファイルシステム修復：`fsck`

ファイルシステムの破損をチェックおよび修復します。

```bash
# ファイルシステムをチェック
fsck /dev/sda1
# ファイルシステムチェックを強制
fsck -f /dev/sda1
# 自動修復
fsck -y /dev/sda1
# マウントされているすべてのファイルシステムをチェック
fsck -A
```

### サービスの問題：`systemctl`

サービス関連の問題を診断し修正します。

```bash
# サービスの状態を確認
systemctl status servicename
# サービスログを表示
journalctl -u servicename
# 失敗したサービスを再起動
systemctl restart servicename
# ブート時にサービスを有効化
systemctl enable servicename
# 失敗したサービスを一覧表示
systemctl --failed
```

### パフォーマンスの問題：リソース分析

システムパフォーマンスのボトルネックを特定し解決します。

```bash
# ディスク空き容量を確認
df -h
# I/O使用率を監視
iotop
# メモリ使用量を確認
free -h
# CPU使用率を特定
top
# 開いているファイルを一覧表示
lsof
```

## 関連リンク

- <router-link to="/shell">シェル チートシート</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/kubernetes">Kubernetes チートシート</router-link>
- <router-link to="/git">Git チートシート</router-link>
- <router-link to="/ansible">Ansible チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/cybersecurity">サイバーセキュリティ チートシート</router-link>

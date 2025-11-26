---
title: 'Red Hat Enterprise Linux チートシート'
description: '必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートで Red Hat Enterprise Linux を習得しましょう。'
pdfUrl: '/cheatsheets/pdf/red-hat-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Red Hat Enterprise Linux チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/rhel">ハンズオンラボで Red Hat Enterprise Linux を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて Red Hat Enterprise Linux を学びましょう。LabEx は、基本的なシステム管理、パッケージ管理、サービス管理、ネットワーク設定、ストレージ管理、セキュリティを網羅した包括的な RHEL コースを提供します。エンタープライズ Linux の運用とシステム管理技術を習得してください。
</base-disclaimer-content>
</base-disclaimer>

## システム情報と監視

### システムバージョン：`cat /etc/redhat-release`

RHEL のバージョンとリリース情報を表示します。

```bash
# RHEL バージョンの表示
cat /etc/redhat-release
# 代替方法
cat /etc/os-release
# カーネルバージョンの表示
uname -r
# システムアーキテクチャの表示
uname -m
```

### システムパフォーマンス：`top` / `htop`

実行中のプロセスとシステムリソースの使用状況を表示します。

```bash
# リアルタイムプロセスモニター
top
# 強化されたプロセスビューア (インストールされている場合)
htop
# プロセスツリーの表示
pstree
# すべてのプロセスの表示
ps aux
```

### メモリ情報：`free` / `cat /proc/meminfo`

メモリの使用状況と利用可能性を表示します。

```bash
# 人間が読みやすい形式でメモリ使用量を表示
free -h
# 詳細なメモリ情報を表示
cat /proc/meminfo
# スワップ使用量の表示
swapon --show
```

### ディスク使用量：`df` / `du`

ファイルシステムとディレクトリの使用状況を監視します。

```bash
# ファイルシステム使用量の表示
df -h
# ディレクトリサイズの表示
du -sh /var/log/*
# 最大のディレクトリの表示
du -h --max-depth=1 / | sort -hr
```

### システム稼働時間：`uptime` / `who`

システムの稼働時間とログインユーザーを確認します。

```bash
# システムの稼働時間とロードアベレージの表示
uptime
# ログインユーザーの表示
who
# 現在のユーザーの表示
whoami
# 最終ログインの表示
last
```

### ハードウェア情報：`lscpu` / `lsblk`

ハードウェアコンポーネントと設定を表示します。

```bash
# CPU 情報の表示
lscpu
# ブロックデバイスの表示
lsblk
# PCI デバイスの表示
lspci
# USB デバイスの表示
lsusb
```

## パッケージ管理

### パッケージのインストール：`dnf install` / `yum install`

ソフトウェアパッケージと依存関係をインストールします。

```bash
# パッケージのインストール (RHEL 8 以降)
sudo dnf install package-name
# パッケージのインストール (RHEL 7)
sudo yum install package-name
# ローカル RPM ファイルのインストール
sudo rpm -i package.rpm
# 特定のリポジトリからのインストール
sudo dnf install --enablerepo=repo-
name package
```

### パッケージの更新：`dnf update` / `yum update`

パッケージを最新バージョンに更新します。

```bash
# すべてのパッケージを更新
sudo dnf update
# 特定のパッケージを更新
sudo dnf update package-name
# 利用可能な更新の確認
dnf check-update
# セキュリティパッチのみを更新
sudo dnf update --security
```

### パッケージ情報：`dnf info` / `rpm -q`

パッケージ情報と依存関係を照会します。

```bash
# パッケージ情報の表示
dnf info package-name
# インストール済みパッケージの一覧表示
rpm -qa
# パッケージの検索
dnf search keyword
# パッケージの依存関係の表示
dnf deplist package-name
```

## ファイルとディレクトリの操作

### 移動：`cd` / `pwd` / `ls`

ファイルシステムを移動し、内容を一覧表示します。

```bash
# ディレクトリの変更
cd /path/to/directory
# 現在のディレクトリの表示
pwd
# ファイルとディレクトリの一覧表示
ls -la
# ファイルサイズ付きの一覧表示
ls -lh
# 隠しファイルの表示
ls -a
```

### ファイル操作：`cp` / `mv` / `rm`

ファイルとディレクトリのコピー、移動、削除を行います。

```bash
# ファイルのコピー
cp source.txt destination.txt
# ディレクトリの再帰的コピー
cp -r /source/dir/ /dest/dir/
# ファイルの移動/名前変更
mv oldname.txt newname.txt
# ファイルの削除
rm filename.txt
# ディレクトリの再帰的削除
rm -rf directory/
```

### ファイル内容：`cat` / `less` / `head` / `tail`

ファイル内容の表示と検査を行います。

```bash
# ファイル内容の表示
cat filename.txt
# ページごとにファイルを表示
less filename.txt
# 最初の10行の表示
head filename.txt
# 最後の10行の表示
tail filename.txt
# ログファイルをリアルタイムで追跡
tail -f /var/log/messages
```

### ファイルパーミッション：`chmod` / `chown` / `chgrp`

ファイルパーミッションと所有権を管理します。

```bash
# ファイルパーミッションの変更
chmod 755 script.sh
# ファイルの所有権の変更
sudo chown user:group filename.txt
# グループ所有権の変更
sudo chgrp newgroup filename.txt
# 再帰的なパーミッション変更
sudo chmod -R 644 /path/to/directory/
```

### ファイル検索：`find` / `locate` / `grep`

ファイルとファイル内のコンテンツを検索します。

```bash
# 名前によるファイルの検索
find /path -name "*.txt"
# サイズによるファイルの検索
find /path -size +100M
# ファイル内のテキスト検索
grep "pattern" filename.txt
# 再帰的なテキスト検索
grep -r "pattern" /path/to/directory/
```

### アーカイブと圧縮：`tar` / `gzip`

圧縮アーカイブの作成と展開を行います。

```bash
# tar アーカイブの作成
tar -czf archive.tar.gz /path/to/directory/
# tar アーカイブの展開
tar -xzf archive.tar.gz
# zip アーカイブの作成
zip -r archive.zip /path/to/directory/
# zip アーカイブの展開
unzip archive.zip
```

## サービス管理

### サービス制御：`systemctl`

systemd を使用してシステムサービスを管理します。

```bash
# サービスの起動
sudo systemctl start service-name
# サービスの停止
sudo systemctl stop service-name
# サービスの再起動
sudo systemctl restart service-name
# サービスの状態確認
systemctl status service-name
# ブート時のサービス有効化
sudo systemctl enable service-name
# ブート時のサービス無効化
sudo systemctl disable service-name
```

### サービス情報：`systemctl list-units`

システムサービスの一覧表示と照会を行います。

```bash
# すべてのアクティブなサービスの一覧表示
systemctl list-units --type=service
# 有効化されているすべてのサービスの一覧表示
systemctl list-unit-files --type=service --state=enabled
# サービスの依存関係の表示
systemctl list-dependencies service-name
```

### システムログ：`journalctl`

journald を使用してシステムログの表示と分析を行います。

```bash
# すべてのログの表示
journalctl
# 特定のサービスに関するログの表示
journalctl -u service-name
# リアルタイムでのログの追跡
journalctl -f
# 前回のブートからのログの表示
journalctl -b
# 時間範囲によるログの表示
journalctl --since "2024-01-01" --until "2024-01-31"
```

### プロセス管理：`ps` / `kill` / `killall`

実行中のプロセスを監視および制御します。

```bash
# 実行中のプロセスの表示
ps aux
# PID によるプロセスの終了
kill 1234
# プロセス名によるプロセスの終了
killall process-name
# プロセスの強制終了
kill -9 1234
# プロセス階層の表示
pstree
```

## ユーザーとグループの管理

### ユーザー管理：`useradd` / `usermod` / `userdel`

ユーザーアカウントの作成、変更、削除を行います。

```bash
# 新規ユーザーの追加
sudo useradd -m username
# ユーザーパスワードの設定
sudo passwd username
# ユーザーアカウントの変更
sudo usermod -aG groupname
username
# ユーザーアカウントの削除
sudo userdel -r username
# ユーザーアカウントのロック
sudo usermod -L username
```

### グループ管理：`groupadd` / `groupmod` / `groupdel`

グループの作成、変更、削除を行います。

```bash
# 新規グループの追加
sudo groupadd groupname
# ユーザーをグループに追加
sudo usermod -aG groupname
username
# ユーザーをグループから削除
sudo gpasswd -d username
groupname
# グループの削除
sudo groupdel groupname
# ユーザーのグループ一覧表示
groups username
```

### アクセス制御：`su` / `sudo`

ユーザーの切り替えと、昇格された権限でのコマンド実行を行います。

```bash
# root ユーザーへの切り替え
su -
# 特定のユーザーへの切り替え
su - username
# root としてコマンドの実行
sudo command
# sudoers ファイルの編集
sudo visudo
# sudo 権限の確認
sudo -l
```

## ネットワーク設定

### ネットワーク情報：`ip` / `nmcli`

ネットワークインターフェースと設定の詳細を表示します。

```bash
# ネットワークインターフェースの表示
ip addr show
# ルーティングテーブルの表示
ip route show
# ネットワークマネージャー接続の表示
nmcli connection show
# デバイスの状態の表示
nmcli device status
```

### ネットワーク設定：`nmtui` / `nmcli`

NetworkManager を使用してネットワーク設定を行います。

```bash
# テキストベースのネットワーク設定
sudo nmtui
# 新規接続の追加
sudo nmcli connection add type ethernet con-name
"eth0" ifname eth0
# 接続の変更
sudo nmcli connection modify "eth0" ipv4.addresses
192.168.1.100/24
# 接続のアクティブ化
sudo nmcli connection up "eth0"
```

### ネットワークテスト：`ping` / `curl` / `wget`

ネットワーク接続のテストとファイルのダウンロードを行います。

```bash
# 接続性のテスト
ping google.com
# 特定ポートのテスト
telnet hostname 80
# ファイルのダウンロード
wget http://example.com/file.txt
# HTTPリクエストのテスト
curl -I http://example.com
```

### ファイアウォール管理：`firewall-cmd`

firewalld を使用してファイアウォールルールを設定します。

```bash
# ファイアウォールの状態表示
sudo firewall-cmd --state
# アクティブなゾーンの一覧表示
sudo firewall-cmd --get-active-zones
# ファイアウォールへのサービスの追加
sudo firewall-cmd --permanent --add-service=http
# ファイアウォールルールのリロード
sudo firewall-cmd --reload
```

## ストレージ管理

### ディスク管理：`fdisk` / `parted`

ディスクパーティションの作成と管理を行います。

```bash
# ディスクパーティションの一覧表示
sudo fdisk -l
# 対話型パーティションエディタ
sudo fdisk /dev/sda
# パーティションテーブルの作成
sudo parted /dev/sda mklabel gpt
# 新しいパーティションの作成
sudo parted /dev/sda mkpart primary ext4 1MiB 100GiB
```

### ファイルシステム管理：`mkfs` / `mount`

ファイルシステムの作成とストレージデバイスのマウントを行います。

```bash
# ext4 ファイルシステムの作成
sudo mkfs.ext4 /dev/sda1
# ファイルシステムのマウント
sudo mount /dev/sda1 /mnt/data
# ファイルシステムのアンマウント
sudo umount /mnt/data
# ファイルシステムのチェック
sudo fsck /dev/sda1
```

### LVM 管理：`pvcreate` / `vgcreate` / `lvcreate`

論理ボリュームマネージャー (LVM) ストレージを管理します。

```bash
# 物理ボリュームの作成
sudo pvcreate /dev/sdb
# ボリュームグループの作成
sudo vgcreate vg_data /dev/sdb
# 論理ボリュームの作成
sudo lvcreate -L 10G -n lv_data vg_data
# 論理ボリュームの拡張
sudo lvextend -L +5G /dev/vg_data/lv_data
```

### マウント設定：`/etc/fstab`

永続的なマウントポイントを設定します。

```bash
# fstab ファイルの編集
sudo vi /etc/fstab
# fstab エントリのテスト
sudo mount -a
# マウントされているファイルシステムの一覧表示
mount | column -t
```

## セキュリティと SELinux

### SELinux 管理：`getenforce` / `setenforce`

SELinux の強制モードとポリシーを制御します。

```bash
# SELinux ステータスの確認
getenforce
# SELinux を permissive モードに設定
sudo setenforce 0
# SELinux を enforcing モードに設定
sudo setenforce 1
# SELinux コンテキストの確認
ls -Z filename
# SELinux コンテキストの変更
sudo chcon -t httpd_exec_t /path/to/file
```

### SELinux ツール：`sealert` / `ausearch`

SELinux の拒否と監査ログを分析します。

```bash
# SELinux アラートの確認
sudo sealert -a /var/log/audit/audit.log
# 監査ログの検索
sudo ausearch -m avc -ts recent
# SELinux ポリシーの生成
sudo audit2allow -M mypolicy < /var/log/audit/audit.log
```

### SSH 設定：`/etc/ssh/sshd_config`

安全なリモートアクセス用に SSH デーモンを設定します。

```bash
# SSH 設定の編集
sudo vi /etc/ssh/sshd_config
# SSH サービスの再起動
sudo systemctl restart sshd
# SSH 接続のテスト
ssh user@hostname
# SSH キーのコピー
ssh-copy-id user@hostname
```

### システム更新：`dnf update`

定期的な更新でシステムを安全に保ちます。

```bash
# すべてのパッケージを更新
sudo dnf update
# セキュリティパッチのみを更新
sudo dnf update --security
# 利用可能な更新の確認
dnf check-update --security
# 自動更新の有効化
sudo systemctl enable dnf-automatic.timer
```

## パフォーマンス監視

### システム監視：`iostat` / `vmstat`

システムパフォーマンスとリソース使用状況を監視します。

```bash
# I/O 統計の表示
iostat -x 1
# 仮想メモリ統計の表示
vmstat 1
# ネットワーク統計の表示
ss -tuln
# ディスク I/O の表示
iotop
```

### リソース使用状況：`sar` / `top`

履歴およびリアルタイムのシステムメトリクスを分析します。

```bash
# システムアクティビティレポート
sar -u 1 3
# メモリ使用状況レポート
sar -r
# ネットワークアクティビティレポート
sar -n DEV
# ロードアベレージの監視
uptime
```

### プロセス分析：`strace` / `lsof`

プロセスのデバッグとファイルアクセスを分析します。

```bash
# システムコールのトレース
strace -p 1234
# 開いているファイルのリスト表示
lsof
# プロセスが開いているファイルの表示
lsof -p 1234
# ネットワーク接続の表示
lsof -i
```

### パフォーマンスチューニング：`tuned`

特定のワークロードに対してシステムパフォーマンスを最適化します。

```bash
# 利用可能なプロファイルの一覧表示
tuned-adm list
# アクティブなプロファイルの表示
tuned-adm active
# パフォーマンスプロファイルの設定
sudo tuned-adm profile throughput-performance
# カスタムプロファイルの作成
sudo tuned-adm profile_mode
```

## RHEL インストールとセットアップ

### システム登録：`subscription-manager`

システムを Red Hat カスタマーポータルに登録します。

```bash
# システムの登録
sudo subscription-manager
register --username
your_username
# サブスクリプションの自動アタッチ
sudo subscription-manager
attach --auto
# 利用可能なサブスクリプションの一覧表示
subscription-manager list --
available
# システムステータスの表示
subscription-manager status
```

### リポジトリ管理：`dnf config-manager`

ソフトウェアリポジトリを管理します。

```bash
# 有効なリポジトリの一覧表示
dnf repolist
# リポジトリの有効化
sudo dnf config-manager --
enable repository-name
# リポジトリの無効化
sudo dnf config-manager --
disable repository-name
# 新しいリポジトリの追加
sudo dnf config-manager --add-
repo https://example.com/repo
```

### システム設定：`hostnamectl` / `timedatectl`

基本的なシステム設定を行います。

```bash
# ホスト名の設定
sudo hostnamectl set-hostname
new-hostname
# システム情報の表示
hostnamectl
# タイムゾーンの設定
sudo timedatectl set-timezone
America/New_York
# 時刻設定の表示
timedatectl
```

## トラブルシューティングと診断

### システムログ：`/var/log/`

ハードウェア情報の確認と健全性の検査を行います。

```bash
# システムメッセージの表示
sudo tail -f /var/log/messages
# 認証ログの表示
sudo tail -f /var/log/secure
# ブートログの表示
sudo journalctl -b
# カーネルメッセージの表示
dmesg | tail
```

### ハードウェア診断：`dmidecode` / `lshw`

ハードウェア情報と健全性を検査します。

```bash
# ハードウェア情報の表示
sudo dmidecode -t system
# ハードウェアコンポーネントの一覧表示
sudo lshw -short
# メモリ情報の確認
sudo dmidecode -t memory
# CPU 情報の表示
lscpu
```

### ネットワークトラブルシューティング：`netstat` / `ss`

ネットワーク診断ツールとユーティリティ。

```bash
# ネットワーク接続の表示
ss -tuln
# ルーティングテーブルの表示
ip route show
# DNS 解決のテスト
nslookup google.com
# ネットワークパスのトレース
traceroute google.com
```

### 回復とレスキュー: `systemctl rescue`

システム回復と緊急手順。

```bash
# レスキューモードに入る
sudo systemctl rescue
# 緊急モードに入る
sudo systemctl emergency
# 失敗したサービスの再設定
sudo systemctl reset-failed
# ブートローダーの再設定
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

## 自動化とスクリプティング

### Cron ジョブ：`crontab`

自動化されたタスクとメンテナンスをスケジュールします。

```bash
# ユーザーの crontab の編集
crontab -e
# ユーザーの crontab の一覧表示
crontab -l
# ユーザーの crontab の削除
crontab -r
# 例: 毎日午前2時にスクリプトを実行
0 2 * * * /path/to/script.sh
```

### シェルスクリプティング：`bash`

自動化のためのシェルスクリプトの作成と実行。

```bash
#!/bin/bash
# シンプルなバックアップスクリプト
DATE=$(date +%Y%m%d)
tar -czf backup_$DATE.tar.gz /home/user/documents
echo "Backup completed: backup_$DATE.tar.gz"
```

### 環境変数：`export` / `env`

環境変数とシェル設定を管理します。

```bash
# 環境変数の設定
export MY_VAR="value"
# すべての環境変数の表示
env
# 特定の変数の表示
echo $PATH
# PATH への追加
export PATH=$PATH:/new/directory
```

### システム自動化：`systemd timers`

systemd ベースのスケジュールされたタスクを作成します。

```bash
# タイマーユニットファイルの作成
sudo vi /etc/systemd/system/backup.timer
# タイマーの有効化と開始
sudo systemctl enable backup.timer
sudo systemctl start backup.timer
# アクティブなタイマーの一覧表示
systemctl list-timers
```

## 関連リンク

- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/git">Git チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/kubernetes">Kubernetes チートシート</router-link>
- <router-link to="/ansible">Ansible チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/cybersecurity">サイバーセキュリティ チートシート</router-link>

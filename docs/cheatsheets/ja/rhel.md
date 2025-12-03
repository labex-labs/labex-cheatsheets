---
title: 'Red Hat Enterprise Linux チートシート | LabEx'
description: 'この包括的なチートシートで Red Hat Enterprise Linux (RHEL) 管理を学習しましょう。RHEL コマンド、システム管理、SELinux、パッケージ管理、エンタープライズ Linux 管理のクイックリファレンス。'
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
ハンズオンラボと現実世界のシナリオを通じて Red Hat Enterprise Linux を学びましょう。LabEx は、基本的なシステム管理、パッケージ管理、サービス管理、ネットワーク設定、ストレージ管理、セキュリティを網羅した包括的な RHEL コースを提供します。エンタープライズ Linux の操作とシステム管理技術を習得します。
</base-disclaimer-content>
</base-disclaimer>

## システム情報と監視

### システムバージョン：`cat /etc/redhat-release`

RHEL のバージョンとリリース情報を表示します。

```bash
# RHEL バージョンを表示
cat /etc/redhat-release
# 代替方法
cat /etc/os-release
# カーネルバージョンを表示
uname -r
# システムアーキテクチャを表示
uname -m
```

### システムパフォーマンス：`top` / `htop`

実行中のプロセスとシステムリソースの使用状況を表示します。

```bash
# リアルタイムプロセスモニター
top
# 強化されたプロセスビューア (インストールされている場合)
htop
# プロセスツリーを表示
pstree
# すべてのプロセスを表示
ps aux
```

### メモリ情報：`free` / `cat /proc/meminfo`

メモリの使用状況と空き容量を表示します。

```bash
# 人間が読みやすい形式でメモリ使用状況を表示
free -h
# 詳細なメモリ情報を表示
cat /proc/meminfo
# スワップ使用状況を表示
swapon --show
```

### ディスク使用量：`df` / `du`

ファイルシステムとディレクトリの使用状況を監視します。

```bash
# ファイルシステムの使用状況を表示
df -h
# ディレクトリサイズを表示
du -sh /var/log/*
# 最大のディレクトリを表示
du -h --max-depth=1 / | sort -hr
```

### システム稼働時間：`uptime` / `who`

システムの稼働時間とログイン中のユーザーを確認します。

```bash
# システムの稼働時間とロードアベレージを表示
uptime
# ログイン中のユーザーを表示
who
# 現在のユーザーを表示
whoami
# 最終ログインを表示
last
```

### ハードウェア情報：`lscpu` / `lsblk`

ハードウェアコンポーネントと設定を表示します。

```bash
# CPU 情報を表示
lscpu
# ブロックデバイスを表示
lsblk
# PCI デバイスを表示
lspci
# USB デバイスを表示
lsusb
```

## パッケージ管理

### パッケージのインストール：`dnf install` / `yum install`

ソフトウェアパッケージと依存関係をインストールします。

```bash
# パッケージをインストール (RHEL 8 以降)
sudo dnf install package-name
# パッケージをインストール (RHEL 7)
sudo yum install package-name
# ローカル RPM ファイルをインストール
sudo rpm -i package.rpm
# 特定のリポジトリからインストール
sudo dnf install --enablerepo=repo-
name package
```

<BaseQuiz id="rhel-package-1" correct="A">
  <template #question>
    RHEL における <code>dnf</code> と <code>yum</code> の違いは何ですか？
  </template>
  
  <BaseQuizOption value="A" correct>dnf は RHEL 8 以降の新しいパッケージマネージャーであり、yum は RHEL 7 で使用されます</BaseQuizOption>
  <BaseQuizOption value="B">dnf は開発パッケージ用、yum は本番環境用です</BaseQuizOption>
  <BaseQuizOption value="C">違いはなく、同じものです</BaseQuizOption>
  <BaseQuizOption value="D">dnf は非推奨であり、常に yum を使用すべきです</BaseQuizOption>
  
  <BaseQuizAnswer>
    DNF (Dandified YUM) は YUM の次世代バージョンであり、RHEL 8 以降のデフォルトのパッケージマネージャーです。YUM は RHEL 7 で引き続き使用されます。DNF はパフォーマンスと依存関係の解決が優れています。
  </BaseQuizAnswer>
</BaseQuiz>

### パッケージの更新：`dnf update` / `yum update`

パッケージを最新バージョンに更新します。

```bash
# すべてのパッケージを更新
sudo dnf update
# 特定のパッケージを更新
sudo dnf update package-name
# 利用可能な更新を確認
dnf check-update
# セキュリティパッチのみを更新
sudo dnf update --security
```

### パッケージ情報：`dnf info` / `rpm -q`

パッケージ情報と依存関係を照会します。

```bash
# パッケージ情報を表示
dnf info package-name
# インストールされているパッケージを一覧表示
rpm -qa
# パッケージを検索
dnf search keyword
# パッケージの依存関係を表示
dnf deplist package-name
```

## ファイルとディレクトリの操作

### 移動：`cd` / `pwd` / `ls`

ファイルシステムを移動し、内容を一覧表示します。

```bash
# ディレクトリを変更
cd /path/to/directory
# 現在のディレクトリを表示
pwd
# ファイルとディレクトリを一覧表示
ls -la
# ファイルサイズ付きで一覧表示
ls -lh
# 隠しファイルを表示
ls -a
```

### ファイル操作：`cp` / `mv` / `rm`

ファイルとディレクトリのコピー、移動、削除を行います。

```bash
# ファイルをコピー
cp source.txt destination.txt
# ディレクトリを再帰的にコピー
cp -r /source/dir/ /dest/dir/
# ファイルの移動/名前変更
mv oldname.txt newname.txt
# ファイルを削除
rm filename.txt
# ディレクトリを再帰的に削除
rm -rf directory/
```

<BaseQuiz id="rhel-file-ops-1" correct="B">
  <template #question>
    <code>cp -r</code> は何を行いますか？
  </template>
  
  <BaseQuizOption value="A">ファイルのみをコピーします</BaseQuizOption>
  <BaseQuizOption value="B" correct>ディレクトリを再帰的にコピーし、すべてのサブディレクトリとファイルを含めます</BaseQuizOption>
  <BaseQuizOption value="C">ファイルを削除します</BaseQuizOption>
  <BaseQuizOption value="D">ファイルを名前変更します</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-r</code> フラグ (再帰的) は、<code>cp</code> がディレクトリとその内容（すべてのサブディレクトリとファイルを含む）をコピーできるようにします。<code>-r</code> がないと、<code>cp</code> はディレクトリをコピーできません。
  </BaseQuizAnswer>
</BaseQuiz>

### ファイル内容：`cat` / `less` / `head` / `tail`

ファイルの内容を表示および検査します。

```bash
# ファイル内容を表示
cat filename.txt
# ページごとにファイルを表示
less filename.txt
# 最初の10行を表示
head filename.txt
# 最後の10行を表示
tail filename.txt
# ログファイルをリアルタイムで追跡
tail -f /var/log/messages
```

<BaseQuiz id="rhel-tail-1" correct="C">
  <template #question>
    <code>tail -f /var/log/messages</code> は何を行いますか？
  </template>
  
  <BaseQuizOption value="A">最初の 10 行のみを表示します</BaseQuizOption>
  <BaseQuizOption value="B">ログファイルを削除します</BaseQuizOption>
  <BaseQuizOption value="C" correct>最後の 10 行を表示し、新しいエントリをリアルタイムで追跡します</BaseQuizOption>
  <BaseQuizOption value="D">ログファイルをアーカイブします</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-f</code> フラグは <code>tail</code> にファイルを追跡させ、ログが書き込まれる新しいエントリを表示します。これはリアルタイムのログ監視とトラブルシューティングに不可欠です。
  </BaseQuizAnswer>
</BaseQuiz>

### ファイルパーミッション：`chmod` / `chown` / `chgrp`

ファイルパーミッションと所有権を管理します。

```bash
# ファイルパーミッションを変更
chmod 755 script.sh
# ファイルの所有権を変更
sudo chown user:group filename.txt
# グループ所有権を変更
sudo chgrp newgroup filename.txt
# 再帰的なパーミッション変更
sudo chmod -R 644 /path/to/directory/
```

### ファイル検索：`find` / `locate` / `grep`

ファイルやファイル内のコンテンツを検索します。

```bash
# 名前でファイルを検索
find /path -name "*.txt"
# サイズでファイルを検索
find /path -size +100M
# ファイル内のテキストを検索
grep "pattern" filename.txt
# ディレクトリ内を再帰的にテキスト検索
grep -r "pattern" /path/to/directory/
```

### アーカイブと圧縮：`tar` / `gzip`

圧縮アーカイブの作成と展開を行います。

```bash
# tar アーカイブを作成
tar -czf archive.tar.gz /path/to/directory/
# tar アーカイブを展開
tar -xzf archive.tar.gz
# zip アーカイブを作成
zip -r archive.zip /path/to/directory/
# zip アーカイブを展開
unzip archive.zip
```

## サービス管理

### サービス制御：`systemctl`

systemd を使用してシステムサービスを管理します。

```bash
# サービスを開始
sudo systemctl start service-name
# サービスを停止
sudo systemctl stop service-name
# サービスを再起動
sudo systemctl restart service-name
# サービスの状態を確認
systemctl status service-name
# ブート時にサービスを有効化
sudo systemctl enable service-name
# ブート時にサービスを無効化
sudo systemctl disable service-name
```

### サービス情報：`systemctl list-units`

システムサービスを一覧表示および照会します。

```bash
# すべてのアクティブなサービスを一覧表示
systemctl list-units --type=service
# 有効化されているすべてのサービスを一覧表示
systemctl list-unit-files --type=service --state=enabled
# サービスの依存関係を表示
systemctl list-dependencies service-name
```

### システムログ：`journalctl`

journald を使用してシステムログを表示および分析します。

```bash
# すべてのログを表示
journalctl
# 特定のサービスに関するログを表示
journalctl -u service-name
# リアルタイムでログを追跡
journalctl -f
# 前回のブートからのログを表示
journalctl -b
# 時間範囲でログを表示
journalctl --since "2024-01-01" --until "2024-01-31"
```

### プロセス管理：`ps` / `kill` / `killall`

実行中のプロセスを監視および制御します。

```bash
# 実行中のプロセスを表示
ps aux
# PID でプロセスを終了
kill 1234
# 名前でプロセスを終了
killall process-name
# プロセスを強制終了
kill -9 1234
# プロセス階層を表示
pstree
```

## ユーザーとグループの管理

### ユーザー管理：`useradd` / `usermod` / `userdel`

ユーザーアカウントの作成、変更、削除を行います。

```bash
# 新しいユーザーを追加
sudo useradd -m username
# ユーザーパスワードを設定
sudo passwd username
# ユーザーアカウントを変更
sudo usermod -aG groupname
username
# ユーザーアカウントを削除
sudo userdel -r username
# ユーザーアカウントをロック
sudo usermod -L username
```

### グループ管理：`groupadd` / `groupmod` / `groupdel`

グループの作成、変更、削除を行います。

```bash
# 新しいグループを追加
sudo groupadd groupname
# ユーザーをグループに追加
sudo usermod -aG groupname
username
# ユーザーをグループから削除
sudo gpasswd -d username
groupname
# グループを削除
sudo groupdel groupname
# ユーザーのグループを一覧表示
groups username
```

### アクセス制御：`su` / `sudo`

ユーザーの切り替えと、昇格された権限でのコマンド実行を行います。

```bash
# root ユーザーに切り替え
su -
# 特定のユーザーに切り替え
su - username
# root としてコマンドを実行
sudo command
# sudoers ファイルを編集
sudo visudo
# sudo 権限を確認
sudo -l
```

## ネットワーク設定

### ネットワーク情報：`ip` / `nmcli`

ネットワークインターフェースと設定の詳細を表示します。

```bash
# ネットワークインターフェースを表示
ip addr show
# ルーティングテーブルを表示
ip route show
# ネットワークマネージャー接続を表示
nmcli connection show
# デバイスの状態を表示
nmcli device status
```

### ネットワーク設定：`nmtui` / `nmcli`

NetworkManager を使用してネットワーク設定を行います。

```bash
# テキストベースのネットワーク設定
sudo nmtui
# 新しい接続を追加
sudo nmcli connection add type ethernet con-name
"eth0" ifname eth0
# 接続を変更
sudo nmcli connection modify "eth0" ipv4.addresses
192.168.1.100/24
# 接続をアクティブ化
sudo nmcli connection up "eth0"
```

### ネットワークテスト：`ping` / `curl` / `wget`

ネットワーク接続をテストし、ファイルをダウンロードします。

```bash
# 接続性をテスト
ping google.com
# 特定のポートをテスト
telnet hostname 80
# ファイルをダウンロード
wget http://example.com/file.txt
# HTTP リクエストをテスト
curl -I http://example.com
```

### ファイアウォール管理：`firewall-cmd`

firewalld を使用してファイアウォールルールを設定します。

```bash
# ファイアウォールの状態を表示
sudo firewall-cmd --state
# アクティブなゾーンを一覧表示
sudo firewall-cmd --get-active-zones
# ファイアウォールにサービスを追加
sudo firewall-cmd --permanent --add-service=http
# ファイアウォールルールをリロード
sudo firewall-cmd --reload
```

## ストレージ管理

### ディスク管理：`fdisk` / `parted`

ディスクパーティションの作成と管理を行います。

```bash
# ディスクパーティションを一覧表示
sudo fdisk -l
# 対話型パーティションエディタ
sudo fdisk /dev/sda
# パーティションテーブルを作成
sudo parted /dev/sda mklabel gpt
# 新しいパーティションを作成
sudo parted /dev/sda mkpart primary ext4 1MiB 100GiB
```

### ファイルシステム管理：`mkfs` / `mount`

ファイルシステムを作成し、ストレージデバイスをマウントします。

```bash
# ext4 ファイルシステムを作成
sudo mkfs.ext4 /dev/sda1
# ファイルシステムをマウント
sudo mount /dev/sda1 /mnt/data
# ファイルシステムをアンマウント
sudo umount /mnt/data
# ファイルシステムをチェック
sudo fsck /dev/sda1
```

### LVM 管理：`pvcreate` / `vgcreate` / `lvcreate`

論理ボリュームマネージャー (LVM) ストレージを管理します。

```bash
# 物理ボリュームを作成
sudo pvcreate /dev/sdb
# ボリュームグループを作成
sudo vgcreate vg_data /dev/sdb
# 論理ボリュームを作成
sudo lvcreate -L 10G -n lv_data vg_data
# 論理ボリュームを拡張
sudo lvextend -L +5G /dev/vg_data/lv_data
```

### マウント設定：`/etc/fstab`

永続的なマウントポイントを設定します。

```bash
# fstab ファイルを編集
sudo vi /etc/fstab
# fstab エントリをテスト
sudo mount -a
# マウントされているファイルシステムを表示
mount | column -t
```

## セキュリティと SELinux

### SELinux 管理：`getenforce` / `setenforce`

SELinux の強制モードとポリシーを制御します。

```bash
# SELinux の状態を確認
getenforce
# SELinux を permissive モードに設定
sudo setenforce 0
# SELinux を enforcing モードに設定
sudo setenforce 1
# SELinux コンテキストを確認
ls -Z filename
# SELinux コンテキストを変更
sudo chcon -t httpd_exec_t /path/to/file
```

### SELinux ツール：`sealert` / `ausearch`

SELinux の拒否と監査ログを分析します。

```bash
# SELinux アラートを確認
sudo sealert -a /var/log/audit/audit.log
# 監査ログを検索
sudo ausearch -m avc -ts recent
# SELinux ポリシーを生成
sudo audit2allow -M mypolicy < /var/log/audit/audit.log
```

### SSH 設定：`/etc/ssh/sshd_config`

安全なリモートアクセス用に SSH デーモンを設定します。

```bash
# SSH 設定を編集
sudo vi /etc/ssh/sshd_config
# SSH サービスを再起動
sudo systemctl restart sshd
# SSH 接続をテスト
ssh user@hostname
# SSH キーをコピー
ssh-copy-id user@hostname
```

### システム更新：`dnf update`

定期的な更新でシステムを安全に保ちます。

```bash
# すべてのパッケージを更新
sudo dnf update
# セキュリティパッチのみを更新
sudo dnf update --security
# 利用可能な更新を確認
dnf check-update --security
# 自動更新を有効化
sudo systemctl enable dnf-automatic.timer
```

## パフォーマンス監視

### システム監視：`iostat` / `vmstat`

システムパフォーマンスとリソース使用状況を監視します。

```bash
# I/O 統計情報を表示
iostat -x 1
# 仮想メモリ統計情報を表示
vmstat 1
# ネットワーク統計情報を表示
ss -tuln
# ディスク I/O を表示
iotop
```

### リソース使用状況：`sar` / `top`

履歴およびリアルタイムのシステムメトリックを分析します。

```bash
# システムアクティビティレポート
sar -u 1 3
# メモリ使用状況レポート
sar -r
# ネットワークアクティビティレポート
sar -n DEV
# ロードアベレージ監視
uptime
```

### プロセス分析：`strace` / `lsof`

プロセスをデバッグし、ファイルアクセスを検査します。

```bash
# システムコールをトレース
strace -p 1234
# 開いているファイルを一覧表示
lsof
# プロセスが開いているファイルを表示
lsof -p 1234
# ネットワーク接続を表示
lsof -i
```

### パフォーマンスチューニング：`tuned`

特定のワークロードに合わせてシステムパフォーマンスを最適化します。

```bash
# 利用可能なプロファイルを一覧表示
tuned-adm list
# アクティブなプロファイルを表示
tuned-adm active
# パフォーマンスプロファイルを設定
sudo tuned-adm profile throughput-performance
# カスタムプロファイルを作成
sudo tuned-adm profile_mode
```

## RHEL インストールとセットアップ

### システム登録：`subscription-manager`

システムを Red Hat カスタマーポータルに登録します。

```bash
# システムを登録
sudo subscription-manager
register --username
your_username
# サブスクリプションを自動アタッチ
sudo subscription-manager
attach --auto
# 利用可能なサブスクリプションを一覧表示
subscription-manager list --
available
# システムステータスを表示
subscription-manager status
```

### リポジトリ管理：`dnf config-manager`

ソフトウェアリポジトリを管理します。

```bash
# 有効なリポジトリを一覧表示
dnf repolist
# リポジトリを有効化
sudo dnf config-manager --
enable repository-name
# リポジトリを無効化
sudo dnf config-manager --
disable repository-name
# 新しいリポジトリを追加
sudo dnf config-manager --add-
repo https://example.com/repo
```

### システム設定：`hostnamectl` / `timedatectl`

基本的なシステム設定を行います。

```bash
# ホスト名を設定
sudo hostnamectl set-hostname
new-hostname
# システム情報を表示
hostnamectl
# タイムゾーンを設定
sudo timedatectl set-timezone
America/New_York
# 時間設定を表示
timedatectl
```

## トラブルシューティングと診断

### システムログ：`/var/log/`

問題の調査のためにシステムログファイルを確認します。

```bash
# システムメッセージを表示
sudo tail -f /var/log/messages
# 認証ログを表示
sudo tail -f /var/log/secure
# ブートログを表示
sudo journalctl -b
# カーネルメッセージを表示
dmesg | tail
```

### ハードウェア診断：`dmidecode` / `lshw`

ハードウェア情報と健全性を検査します。

```bash
# ハードウェア情報を表示
sudo dmidecode -t system
# ハードウェアコンポーネントを一覧表示
sudo lshw -short
# メモリ情報を確認
sudo dmidecode -t memory
# CPU 情報を表示
lscpu
```

### ネットワークトラブルシューティング：`netstat` / `ss`

ネットワーク診断ツールとユーティリティ。

```bash
# ネットワーク接続を表示
ss -tuln
# ルーティングテーブルを表示
ip route show
# DNS 解決をテスト
nslookup google.com
# ネットワークパスをトレース
traceroute google.com
```

### 回復とレスキュー: `systemctl rescue`

システム回復と緊急手順。

```bash
# レスキューモードに入る
sudo systemctl rescue
# 緊急モードに入る
sudo systemctl emergency
# 失敗したサービスをリセット
sudo systemctl reset-failed
# ブートローダーを再設定
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

## 自動化とスクリプティング

### Cron ジョブ：`crontab`

自動化されたタスクとメンテナンスをスケジュールします。

```bash
# ユーザーの crontab を編集
crontab -e
# ユーザーの crontab を一覧表示
crontab -l
# ユーザーの crontab を削除
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
# 環境変数を設定
export MY_VAR="value"
# すべての環境変数を表示
env
# 特定の変数を表示
echo $PATH
# PATH に追加
export PATH=$PATH:/new/directory
```

### システム自動化：`systemd timers`

systemd ベースのスケジュールされたタスクを作成します。

```bash
# タイマーユニットファイルを作成
sudo vi /etc/systemd/system/backup.timer
# タイマーを有効化して開始
sudo systemctl enable backup.timer
sudo systemctl start backup.timer
# アクティブなタイマーを一覧表示
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

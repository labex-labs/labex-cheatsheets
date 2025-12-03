---
title: '网络安全速查表 | LabEx'
description: '使用本综合速查表学习网络安全。快速参考安全概念、威胁检测、漏洞评估、渗透测试和信息安全最佳实践。'
pdfUrl: '/cheatsheets/pdf/cybersecurity-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
网络安全速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/cybersecurity">通过实践实验室学习网络安全</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习网络安全。LabEx 提供全面的网络安全课程，涵盖威胁识别、安全评估、系统加固、事件响应和监控技术。学习如何使用行业标准工具和最佳实践来保护系统和数据免受网络威胁。
</base-disclaimer-content>
</base-disclaimer>

## 系统安全基础

### 用户账户管理

控制对系统和数据的访问权限。

```bash
# 添加新用户
sudo adduser username
# 设置密码策略
sudo passwd -l username
# 授予 sudo 权限
sudo usermod -aG sudo username
# 查看用户信息
id username
# 列出所有用户
cat /etc/passwd
```

### 文件权限与安全

配置安全的文件和目录访问权限。

```bash
# 更改文件权限（读、写、执行）
chmod 644 file.txt
# 更改所有权
chown user:group file.txt
# 递归设置权限
chmod -R 755 directory/
# 查看文件权限
ls -la
```

<BaseQuiz id="cybersecurity-chmod-1" correct="C">
  <template #question>
    <code>chmod 644 file.txt</code> 设置的文件权限是什么？
  </template>
  
  <BaseQuizOption value="A">所有用户都具有读、写、执行权限</BaseQuizOption>
  <BaseQuizOption value="B">所有者具有读、写、执行权限；其他用户具有读权限</BaseQuizOption>
  <BaseQuizOption value="C" correct>所有者具有读、写权限；组和其他用户具有读权限</BaseQuizOption>
  <BaseQuizOption value="D">所有用户都只有读权限</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 644</code> 设置为：所有者 = 6 (rw-)，组 = 4 (r--)，其他用户 = 4 (r--)。这是一种常见的文件权限设置，文件应可被所有人读取，但只能被所有者写入。
  </BaseQuizAnswer>
</BaseQuiz>

### 网络安全配置

保护网络连接和服务。

```bash
# 配置防火墙 (UFW)
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw deny 23/tcp
# 检查开放端口
netstat -tuln
sudo ss -tuln
```

<BaseQuiz id="cybersecurity-firewall-1" correct="B">
  <template #question>
    <code>sudo ufw allow 22/tcp</code> 的作用是什么？
  </template>
  
  <BaseQuizOption value="A">阻止端口 22</BaseQuizOption>
  <BaseQuizOption value="B" correct>允许端口 22 (SSH) 上的 TCP 流量</BaseQuizOption>
  <BaseQuizOption value="C">启用端口 22 上的 UDP</BaseQuizOption>
  <BaseQuizOption value="D">显示防火墙状态</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>ufw allow 22/tcp</code> 创建了一个防火墙规则，允许传入到端口 22（默认的 SSH 端口）的 TCP 连接。这对于远程服务器访问至关重要。
  </BaseQuizAnswer>
</BaseQuiz>

### 系统更新与补丁

使用最新的安全补丁保持系统更新。

```bash
# 更新软件包列表 (Ubuntu/Debian)
sudo apt update
# 升级所有软件包
sudo apt upgrade
# 自动安全更新
sudo apt install unattended-upgrades
```

### 服务管理

控制和监控系统服务。

```bash
# 停止不必要的服务
sudo systemctl stop service_name
sudo systemctl disable service_name
# 检查服务状态
sudo systemctl status ssh
# 查看正在运行的服务
systemctl list-units --type=service --state=running
```

### 日志监控

监控系统日志以发现安全事件。

```bash
# 查看身份验证日志
sudo tail -f /var/log/auth.log
# 检查系统日志
sudo journalctl -f
# 搜索失败的登录尝试
grep "Failed password" /var/log/auth.log
```

<BaseQuiz id="cybersecurity-logs-1" correct="A">
  <template #question>
    <code>tail -f /var/log/auth.log</code> 的作用是什么？
  </template>
  
  <BaseQuizOption value="A" correct>实时跟踪身份验证日志文件</BaseQuizOption>
  <BaseQuizOption value="B">仅显示失败的登录尝试</BaseQuizOption>
  <BaseQuizOption value="C">删除旧的日志条目</BaseQuizOption>
  <BaseQuizOption value="D">归档日志文件</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-f</code> 标志使 <code>tail</code> 跟踪文件，在新条目写入时显示它们。这对于实时监控身份验证事件和安全事件非常有用。
  </BaseQuizAnswer>
</BaseQuiz>

## 密码安全与身份验证

实施强大的身份验证机制和密码策略。

### 强密码创建

遵循最佳实践生成和管理安全密码。

```bash
# 生成强密码
openssl rand -base64 32
# 密码强度要求：
# - 最少 12 个字符
# - 大小写字母、数字、符号的混合
# - 不要使用字典词或个人信息
# - 每个账户使用唯一的密码
```

### 多因素身份验证 (MFA)

在密码之外增加额外的身份验证层。

```bash
# 安装 Google Authenticator
sudo apt install libpam-googleauthenticator
# 为 SSH 配置 MFA
google-authenticator
# 在 SSH 配置中启用
sudo nano /etc/pam.d/sshd
# 添加: auth required pam_google_authenticator.so
```

### 密码管理

使用密码管理器和安全存储实践。

```bash
# 安装密码管理器 (KeePassXC)
sudo apt install keepassxc
# 最佳实践：
# - 为每个服务使用唯一的密码
# - 启用自动锁定功能
# - 关键账户定期轮换密码
# - 安全备份密码数据库
```

## 网络安全与监控

### 端口扫描与发现

识别开放端口和正在运行的服务。

```bash
# 使用 Nmap 进行基本端口扫描
nmap -sT target_ip
# 服务版本检测
nmap -sV target_ip
# 全面扫描
nmap -A target_ip
# 扫描特定端口
nmap -p 22,80,443 target_ip
# 扫描 IP 范围
nmap 192.168.1.1-254
```

### 网络流量分析

监控和分析网络通信。

```bash
# 使用 tcpdump 捕获数据包
sudo tcpdump -i eth0
# 保存到文件
sudo tcpdump -w capture.pcap
# 过滤特定主机流量
sudo tcpdump host 192.168.1.1
# 监控特定端口
sudo tcpdump port 80
```

### 防火墙配置

控制传入和传出的网络流量。

```bash
# UFW (Uncomplicated Firewall)
sudo ufw status
sudo ufw allow ssh
sudo ufw deny 23
# iptables 规则
sudo iptables -L
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

### SSL/TLS 证书管理

使用加密实现安全通信。

```bash
# 生成自签名证书
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
# 检查证书详情
openssl x509 -in cert.pem -text -noout
# 测试 SSL 连接
openssl s_client -connect example.com:443
```

## 漏洞评估

### 系统漏洞扫描

识别系统和应用程序中的安全弱点。

```bash
# 安装 Nessus 扫描器
# 从 tenable.com 下载
sudo dpkg -i Nessus-X.X.X-ubuntu1404_amd64.deb
# 启动 Nessus 服务
sudo systemctl start nessusd
# 在 https://localhost:8834 访问 Web 界面
# 使用 OpenVAS (免费替代方案)
sudo apt install openvas
sudo gvm-setup
```

### Web 应用程序安全测试

测试 Web 应用程序中常见的漏洞。

```bash
# 使用 Nikto Web 扫描器
nikto -h http://target.com
# 目录枚举
dirb http://target.com
# SQL 注入测试
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

### 安全审计工具

全面的安全评估工具。

```bash
# Lynis 安全审计
sudo apt install lynis
sudo lynis audit system
# 检查 rootkit
sudo apt install chkrootkit
sudo chkrootkit
# 文件完整性监控
sudo apt install aide
sudo aideinit
```

### 配置安全

验证系统和应用程序的安全配置。

```bash
# SSH 安全检查
ssh-audit target_ip
# SSL 配置测试
testssl.sh https://target.com
# 检查敏感文件的权限
ls -la /etc/shadow /etc/passwd /etc/group
```

## 事件响应与取证

### 日志分析与调查

分析系统日志以识别安全事件。

```bash
# 搜索可疑活动
grep -i "failed\|error\|denied" /var/log/auth.log
# 统计失败的登录尝试次数
grep "Failed password" /var/log/auth.log | wc -l
# 从日志中查找唯一的 IP 地址
awk '/Failed password/ {print $11}' /var/log/auth.log | sort | uniq -c
# 实时监控日志活动
tail -f /var/log/syslog
```

### 网络取证

调查基于网络的安全性事件。

```bash
# 使用 Wireshark 分析网络流量
# 安装: sudo apt install wireshark
# 实时捕获流量
sudo wireshark
# 分析捕获的文件
wireshark capture.pcap
# 使用 tshark 进行命令行分析
tshark -r capture.pcap -Y "http.request"
```

### 系统取证

保存和分析数字证据。

```bash
# 创建磁盘镜像
sudo dd if=/dev/sda of=/mnt/evidence/disk_image.dd bs=4096
# 计算文件哈希以保证完整性
md5sum important_file.txt
sha256sum important_file.txt
# 搜索特定文件内容
grep -r "password" /home/user/
# 列出最近修改的文件
find /home -mtime -7 -type f
```

### 事件文档记录

妥善记录安全事件以供分析。

```bash
# 事件响应清单：
# 1. 隔离受影响的系统
# 2. 保存证据
# 3. 记录事件时间线
# 4. 识别攻击媒介
# 5. 评估损害和数据泄露情况
# 6. 实施遏制措施
# 7. 规划恢复程序
```

## 威胁情报

收集和分析有关当前和新兴安全威胁的信息。

### OSINT (开源情报)

收集公开可用的威胁信息。

```bash
# 搜索域名信息
whois example.com
# DNS 查询
dig example.com
nslookup example.com
# 查找子域名
sublist3r -d example.com
# 检查信誉数据库
# VirusTotal, URLVoid, AbuseIPDB
```

### 威胁狩猎工具

主动在您的环境中搜索威胁。

```bash
# IOC (入侵指标) 搜索
grep -r "suspicious_hash" /var/log/
# 检查恶意 IP
grep "192.168.1.100" /var/log/auth.log
# 文件哈希比较
find /tmp -type f -exec sha256sum {} \;
```

### 威胁源与情报

及时了解最新的威胁信息。

```bash
# 流行威胁情报来源：
# - MISP (恶意软件信息共享平台)
# - STIX/TAXII 源
# - 商业源 (CrowdStrike, FireEye)
# - 政府源 (US-CERT, CISA)
# 示例：检查 IP 是否在威胁源中
curl -s "https://api.threatintel.com/check?ip=1.2.3.4"
```

### 威胁建模

识别和评估潜在的安全威胁。

```bash
# STRIDE 威胁模型类别：
# - 欺骗 (Spoofing) (身份)
# - 篡改 (Tampering) (数据)
# - 抵赖 (Repudiation) (操作)
# - 信息泄露 (Information Disclosure)
# - 拒绝服务 (Denial of Service)
# - 权限提升 (Elevation of Privilege)
```

## 加密与数据保护

实施强大的加密来保护敏感数据。

### 文件与磁盘加密

加密文件和存储设备，保护静态数据。

```bash
# 使用 GPG 加密文件
gpg -c sensitive_file.txt
# 解密文件
gpg sensitive_file.txt.gpg
# 使用 LUKS 进行全盘加密
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup luksOpen /dev/sdb encrypted_drive
# 生成 SSH 密钥
ssh-keygen -t rsa -b 4096
# 设置 SSH 密钥身份验证
ssh-copy-id user@server
```

### 网络加密

使用加密协议保护网络通信。

```bash
# 使用 OpenVPN 设置 VPN
sudo apt install openvpn
sudo openvpn --config client.ovpn
```

### 证书管理

管理数字证书以实现安全通信。

```bash
# 创建证书颁发机构 (CA)
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -key ca-key.pem -out ca.pem
# 生成服务器证书
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr
# 使用 CA 签名证书
openssl x509 -req -in server.csr -CA pem -CAkey ca-key.pem -out server.pem
```

### 数据丢失防护

防止未经授权的数据泄露和泄漏。

```bash
# 监控文件访问
sudo apt install auditd
# 配置审计规则
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
# 搜索审计日志
sudo ausearch -k passwd_changes
```

## 安全自动化与编排

自动化安全任务和响应程序。

### 安全扫描自动化

安排定期的安全扫描和评估。

```bash
# 自动 Nmap 扫描脚本
#!/bin/bash
DATE=$(date +%Y-%m-%d)
nmap -sS -O 192.168.1.0/24 > /var/log/nmap-scan-$DATE.log
# 使用 cron 安排
# 0 2 * * * /path/to/security-scan.sh
```

```bash
# 自动化漏洞扫描
#!/bin/bash
nikto -h $1 -o /var/log/nikto-$(date +%Y%m%d).txt
```

### 日志监控脚本

自动化日志分析和警报。

```bash
# 失败登录监控
#!/bin/bash
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | tail -n 100 | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    echo "检测到大量失败登录尝试: $FAILED_LOGINS" | mail -s "安全警报" admin@company.com
fi
```

### 事件响应自动化

自动化初始事件响应程序。

```bash
# 自动化威胁响应脚本
#!/bin/bash
SUSPICIOUS_IP=$1
# 在防火墙中阻止 IP
sudo ufw deny from $SUSPICIOUS_IP
# 记录操作
echo "$(date): Blocked suspicious IP $SUSPICIOUS_IP" >> /var/log/security-actions.log
# 发送警报
echo "Blocked suspicious IP: $SUSPICIOUS_IP" | mail -s "IP Blocked" security@company.com
```

### 配置管理

维护安全系统配置。

```bash
# Ansible 安全剧本示例
---
- name: Harden SSH configuration
  hosts: all
  tasks:
    - name: Disable root login
      lineinfile:
        path: /etc/ssh/sshd_config
        line: 'PermitRootLogin no'
    - name: Restart SSH service
      service:
        name: sshd
        state: restarted
```

## 合规性与风险管理

实施和维护安全策略和程序。

### 安全策略实施

实施和维护安全策略和程序。

```bash
# 密码策略执行 (PAM)
sudo nano /etc/pam.d/common-password
# 添加: password required pam_pwquality.so minlen=12
# 账户锁定策略
sudo nano /etc/pam.d/common-auth
# 添加: auth required pam_tally2.so deny=5 unlock_time=900
```

### 审计与合规性检查

验证是否符合安全标准和法规。

```bash
# CIS (Center for Internet Security) 基准测试工具
sudo apt install cis-cat-lite
# 运行 CIS 评估
./CIS-CAT.sh -a -s
```

### 风险评估工具

评估和量化安全风险。

```bash
# 风险矩阵计算：
# 风险 = 可能性 × 影响
# 低 (1-3)，中 (4-6)，高 (7-9)
# 漏洞优先级排序
# CVSS 分数计算
# 基础分数 = 影响 × 可利用性
```

### 文档记录与报告

维护适当的安全文档和报告。

```bash
# 安全事件报告模板：
# - 事件日期和时间
# - 受影响的系统
# - 识别的攻击媒介
# - 泄露的数据
# - 采取的措施
# - 吸取的教训
# - 补救计划
```

## 安全工具安装

安装和配置必要的网络安全工具。

### 包管理器

使用系统包管理器安装工具。

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap wireshark tcpdump
# CentOS/RHEL
sudo yum install nmap wireshark tcpdump
# Arch Linux
sudo pacman -S nmap wireshark-qt tcpdump
```

### 安全发行版

专为安全专业人员设计的 Linux 发行版。

```bash
# Kali Linux - 渗透测试
# 下载地址: https://www.kali.org/
# Parrot Security OS
# 下载地址: https://www.parrotsec.org/
# BlackArch Linux
# 下载地址: https://blackarch.org/
```

### 工具验证

验证工具安装和基本配置。

```bash
# 检查工具版本
nmap --version
wireshark --version
# 基本功能测试
nmap 127.0.0.1
# 配置工具路径
export PATH=$PATH:/opt/tools/bin
echo 'export PATH=$PATH:/opt/tools/bin' >> ~/.bashrc
```

## 安全配置最佳实践

在系统和应用程序中应用安全加固配置。

### 系统加固

保护操作系统配置。

```bash
# 禁用不必要的服务
sudo systemctl disable telnet
sudo systemctl disable ftp
# 设置安全的文件权限
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 644 /etc/passwd
# 配置系统限制
echo "* hard core 0" >> /etc/security/limits.conf
```

### 网络安全设置

实施安全网络配置。

```bash
# 如果不是路由器，禁用 IP 转发
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
# 启用 SYN cookies
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
# 禁用 ICMP 重定向
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
```

### 应用程序安全

保护应用程序和服务配置。

```bash
# Apache 安全头
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
# Nginx 安全配置
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
```

### 备份与恢复安全

实施安全的备份和灾难恢复程序。

```bash
# 使用 rsync 进行加密备份
rsync -av --password-file=/etc/rsyncd.secrets /data/ backup@server::backups/
# 测试备份完整性
tar -tzf backup.tar.gz > /dev/null && echo "备份正常"
# 自动化备份验证
#!/bin/bash
find /backups -name "*.tar.gz" -exec tar -tzf {} \; > /dev/null
```

## 高级安全技术

实施先进的安全措施和防御策略。

### 入侵检测系统

部署和配置 IDS/IPS 以检测威胁。

```bash
# 安装 Suricata IDS
sudo apt install suricata
# 配置规则
sudo nano /etc/suricata/suricata.yaml
# 更新规则
sudo suricata-update
# 启动 Suricata
sudo systemctl start suricata
# 监控警报
tail -f /var/log/suricata/fast.log
```

### 安全信息和事件管理 (SIEM)

集中化和分析安全日志和事件。

```bash
# ELK 堆栈 (Elasticsearch, Logstash, Kibana)
# 安装 Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update && sudo apt install elasticsearch
```

## 安全意识与培训

识别并预防社会工程学攻击。

### 社会工程学防御

识别并预防社会工程学攻击。

```bash
# 网络钓鱼识别技术：
# - 仔细检查发件人电子邮件
# - 点击前验证链接（悬停）
# - 寻找拼写/语法错误
# - 对紧急请求保持警惕
# - 通过单独的渠道验证请求
# 需要检查的电子邮件安全头：
# SPF, DKIM, DMARC 记录
```

### 安全文化培养

培养具有安全意识的组织文化。

```bash
# 安全意识计划要素：
# - 定期培训课程
# - 网络钓鱼模拟测试
# - 安全策略更新
# - 事件报告程序
# - 对良好安全实践的认可
# 需要跟踪的指标：
# - 培训完成率
# - 网络钓鱼模拟点击率
# - 安全事件报告数量
```

## 相关链接

- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/kali">Kali Linux 速查表</router-link>
- <router-link to="/nmap">Nmap 速查表</router-link>
- <router-link to="/wireshark">Wireshark 速查表</router-link>
- <router-link to="/hydra">Hydra 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/git">Git 速查表</router-link>

---
title: 'Nmap 速查表 | LabEx'
description: '使用此综合速查表学习 Nmap 网络扫描。端口扫描、网络发现、漏洞检测、安全审计和网络侦察的快速参考。'
pdfUrl: '/cheatsheets/pdf/nmap-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Nmap 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/nmap">通过动手实验学习 Nmap</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过动手实验和真实场景学习 Nmap 网络扫描。LabEx 提供全面的 Nmap 课程，涵盖基本的网络发现、端口扫描、服务检测、操作系统指纹识别和漏洞评估。掌握网络侦察和安全审计技术。
</base-disclaimer-content>
</base-disclaimer>

## 安装与设置

### Linux 安装

使用您发行版的包管理器安装 Nmap。

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap
# RHEL/Fedora/CentOS
sudo dnf install nmap
# 验证安装
nmap --version
```

### macOS 安装

使用 Homebrew 包管理器安装。

```bash
# 通过 Homebrew 安装
brew install nmap
# 从 nmap.org 直接下载
# 从 https://nmap.org/download.html 下载 .dmg
```

### Windows 安装

从官方网站下载并安装。

```bash
# 从以下链接下载安装程序
https://nmap.org/download.html
# 使用管理员权限运行 .exe 安装程序
# 包括 Zenmap GUI 和命令行版本
```

### 基本验证

测试安装并获取帮助。

```bash
# 显示版本信息
nmap --version
# 显示帮助菜单
nmap -h
# 扩展帮助和选项
man nmap
```

## 基本扫描技术

### 简单主机扫描：`nmap [目标]`

对单个主机或 IP 地址进行基本扫描。

```bash
# 扫描单个 IP
nmap 192.168.1.1
# 扫描主机名
nmap example.com
# 扫描多个 IP
nmap 192.168.1.1 192.168.1.5
192.168.1.10
```

<BaseQuiz id="nmap-scan-1" correct="A">
  <template #question>
    默认情况下，`nmap 192.168.1.1` 扫描执行什么操作？
  </template>
  
  <BaseQuizOption value="A" correct>扫描最常见的 1000 个 TCP 端口</BaseQuizOption>
  <BaseQuizOption value="B">扫描所有 65535 个端口</BaseQuizOption>
  <BaseQuizOption value="C">仅执行主机发现</BaseQuizOption>
  <BaseQuizOption value="D">仅扫描端口 80</BaseQuizOption>
  
  <BaseQuizAnswer>
    默认情况下，Nmap 扫描最常见的 1000 个 TCP 端口。要扫描所有端口，请使用 `-p-`，或使用 `-p 80,443,22` 指定特定端口。
  </BaseQuizAnswer>
</BaseQuiz>

### 网络范围扫描

Nmap 允许使用主机名、IP 地址、子网。

```bash
# 扫描 IP 范围
nmap 192.168.1.1-254
# 使用 CIDR 表示法扫描子网
nmap 192.168.1.0/24
# 扫描多个网络
nmap 192.168.1.0/24 10.0.0.0/8
```

### 从文件输入

扫描文件中列出的目标。

```bash
# 从文件读取目标
nmap -iL targets.txt
# 排除特定主机
nmap 192.168.1.0/24 --exclude
192.168.1.1
# 从文件排除
nmap 192.168.1.0/24 --excludefile
exclude.txt
```

## 主机发现技术

### Ping 扫描：`nmap -sn`

主机发现是许多分析师和渗透测试人员使用 Nmap 的关键方式。其目的是概述哪些系统在线。

```bash
# 仅进行 Ping 扫描（不进行端口扫描）
nmap -sn 192.168.1.0/24
# 跳过主机发现（假设所有主机都已启动）
nmap -Pn 192.168.1.1
# ICMP echo ping
nmap -PE 192.168.1.0/24
```

<BaseQuiz id="nmap-ping-1" correct="A">
  <template #question>
    `nmap -sn` 执行什么操作？
  </template>
  
  <BaseQuizOption value="A" correct>仅执行主机发现，不进行端口扫描</BaseQuizOption>
  <BaseQuizOption value="B">扫描目标上的所有端口</BaseQuizOption>
  <BaseQuizOption value="C">执行隐蔽扫描</BaseQuizOption>
  <BaseQuizOption value="D">仅扫描 UDP 端口</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-sn` 标志告诉 Nmap 只执行主机发现（Ping 扫描），而不扫描端口。这对于快速识别网络上有哪些主机在线很有用。
  </BaseQuizAnswer>
</BaseQuiz>

### TCP Ping 技术

使用 TCP 数据包进行主机发现。

```bash
# 对端口 80 进行 TCP SYN ping
nmap -PS80 192.168.1.0/24
# TCP ACK ping
nmap -PA80 192.168.1.0/24
# 对多个端口进行 TCP SYN ping
nmap -PS22,80,443 192.168.1.0/24
```

### UDP Ping: `nmap -PU`

使用 UDP 数据包进行主机发现。

```bash
# 对常见端口进行 UDP ping
nmap -PU53,67,68,137 192.168.1.0/24
```

<BaseQuiz id="nmap-udp-1" correct="B">
  <template #question>
    为什么可能使用 UDP ping 而不是 ICMP ping？
  </template>
  
  <BaseQuizOption value="A">UDP ping 总是更快</BaseQuizOption>
  <BaseQuizOption value="B" correct>某些网络会阻止 ICMP 但允许 UDP 数据包</BaseQuizOption>
  <BaseQuizOption value="C">UDP ping 会自动扫描端口</BaseQuizOption>
  <BaseQuizOption value="D">UDP ping 仅在本地网络上有效</BaseQuizOption>
  
  <BaseQuizAnswer>
    当防火墙阻止 ICMP 时，UDP ping 可能很有用。许多网络即使在 ICMP 被过滤的情况下也允许向常见端口（如 DNS 端口 53）发送 UDP 数据包，这使得 UDP ping 对主机发现有效。
  </BaseQuizAnswer>
</BaseQuiz>
# 对默认端口进行 UDP ping
nmap -PU 192.168.1.0/24
```

### ARP Ping: `nmap -PR`

使用 ARP 请求进行本地网络发现。

```bash
# ARP ping（本地网络的默认设置）
nmap -PR 192.168.1.0/24
# 禁用 ARP ping
nmap --disable-arp-ping 192.168.1.0/24
```

## 端口扫描类型

### TCP SYN 扫描: `nmap -sS`

这种扫描更隐蔽，因为 Nmap 发送一个 RST 数据包，从而避免了多次请求并缩短了扫描时间。

```bash
# 默认扫描（需要 root 权限）
nmap -sS 192.168.1.1
# 扫描特定 TCP 端口
nmap -sS -p 80,443 192.168.1.1
# 快速 SYN 扫描
nmap -sS -T4 192.168.1.1
```

### TCP Connect 扫描: `nmap -sT`

Nmap 向端口发送一个设置了 SYN 标志的 TCP 数据包。这使用户能够知道端口是打开、关闭还是未知。

```bash
# TCP connect 扫描（不需要 root 权限）
nmap -sT 192.168.1.1
# 带有时序的 Connect 扫描
nmap -sT -T3 192.168.1.1
```

### UDP 扫描: `nmap -sU`

扫描 UDP 端口以发现服务。

```bash
# UDP 扫描（慢，需要 root 权限）
nmap -sU 192.168.1.1
# UDP 扫描常见端口
nmap -sU -p 53,67,68,161 192.168.1.1
# 组合 TCP/UDP 扫描
nmap -sS -sU -p T:80,443,U:53,161 192.168.1.1
```

### 隐蔽扫描

用于规避检测的高级扫描技术。

```bash
# FIN 扫描
nmap -sF 192.168.1.1
# NULL 扫描
nmap -sN 192.168.1.1
# Xmas 扫描
nmap -sX 192.168.1.1
```

## 端口指定

### 端口范围: `nmap -p`

针对特定端口、范围或 TCP 和 UDP 端口的组合进行更精确的扫描。

```bash
# 单个端口
nmap -p 80 192.168.1.1
# 多个端口
nmap -p 22,80,443 192.168.1.1
# 端口范围
nmap -p 1-1000 192.168.1.1
# 所有端口
nmap -p- 192.168.1.1
```

### 特定协议的端口

明确指定 TCP 或 UDP 端口。

```bash
# 仅 TCP 端口
nmap -p T:80,443 192.168.1.1
# 仅 UDP 端口
nmap -p U:53,161 192.168.1.1
# 混合 TCP 和 UDP
nmap -p T:80,U:53 192.168.1.1
```

### 常见端口集合

快速扫描常用的端口。

```bash
# 最常见的 1000 个端口（默认）
nmap 192.168.1.1
# 最常见的 100 个端口
nmap --top-ports 100 192.168.1.1
# 快速扫描（最常见的 100 个端口）
nmap -F 192.168.1.1
# 仅显示开放端口
nmap --open 192.168.1.1
# 显示所有端口状态
nmap -v 192.168.1.1
```

## 服务与版本检测

### 服务检测: `nmap -sV`

检测正在运行的服务，并尝试识别其软件版本和配置。

```bash
# 基本版本检测
nmap -sV 192.168.1.1
# 积极的版本检测
nmap -sV --version-intensity 9 192.168.1.1
# 轻量级版本检测
nmap -sV --version-intensity 0 192.168.1.1
# 带版本检测的默认脚本
nmap -sC -sV 192.168.1.1
```

### 服务脚本

使用脚本增强服务检测。

```bash
# Banner 抓取
nmap --script banner 192.168.1.1
# HTTP 服务枚举
nmap --script http-* 192.168.1.1
```

### 操作系统检测: `nmap -O`

使用 TCP/IP 指纹识别来猜测目标主机的操作系统。

```bash
# 操作系统检测
nmap -O 192.168.1.1
# 积极的操作系统检测
nmap -O --osscan-guess 192.168.1.1
# 限制操作系统检测尝试次数
nmap -O --max-os-tries 1 192.168.1.1
```

### 全面检测

组合多种检测技术。

```bash
# 积极扫描（OS、版本、脚本）
nmap -A 192.168.1.1
# 自定义积极扫描
nmap -sS -sV -O -sC 192.168.1.1
```

## 时序与性能

### 时序模板: `nmap -T`

根据目标环境和检测风险调整扫描速度。

```bash
# 偏执（非常慢，隐蔽）
nmap -T0 192.168.1.1
# 鬼祟（慢，隐蔽）
nmap -T1 192.168.1.1
# 礼貌（较慢，带宽较少）
nmap -T2 192.168.1.1
# 普通（默认）
nmap -T3 192.168.1.1
# 积极（更快）
nmap -T4 192.168.1.1
# 疯狂（非常快，可能遗漏结果）
nmap -T5 192.168.1.1
```

### 自定义时序选项

微调 Nmap 如何处理超时、重试和并行扫描，以优化性能。

```bash
# 设置最小速率（每秒数据包数）
nmap --min-rate 1000 192.168.1.1
# 设置最大速率
nmap --max-rate 100 192.168.1.1
# 并行主机扫描
nmap --min-hostgroup 10 192.168.1.0/24
# 自定义超时
nmap --host-timeout 5m 192.168.1.1
```

## Nmap 脚本引擎 (NSE)

### 脚本类别: `nmap --script`

按类别或名称运行脚本。

```bash
# 默认脚本
nmap --script default 192.168.1.1
# 漏洞脚本
nmap --script vuln 192.168.1.1
# 发现脚本
nmap --script discovery 192.168.1.1
# 认证脚本
nmap --script auth 192.168.1.1
```

### 特定脚本

针对特定漏洞或服务。

```bash
# SMB 枚举
nmap --script smb-enum-* 192.168.1.1
# HTTP 方法
nmap --script http-methods 192.168.1.1
# SSL 证书信息
nmap --script ssl-cert 192.168.1.1
```

### 脚本参数

向脚本传递参数以自定义其行为。

```bash
# 使用自定义字典进行 HTTP 暴力破解
nmap --script http-brute --script-args
userdb=users.txt,passdb=pass.txt 192.168.1.1
# SMB 暴力破解
nmap --script smb-brute 192.168.1.1
# DNS 暴力破解
nmap --script dns-brute example.com
```

### 脚本管理

管理和更新 NSE 脚本。

```bash
# 更新脚本数据库
nmap --script-updatedb
# 列出可用脚本
ls /usr/share/nmap/scripts/ | grep http
# 获取脚本帮助
nmap --script-help vuln
```

## 输出格式与保存结果

### 输出格式

以不同格式保存结果。

```bash
# 普通输出
nmap -oN scan_results.txt 192.168.1.1
# XML 输出
nmap -oX scan_results.xml 192.168.1.1
# 可 Grep 输出
nmap -oG scan_results.gnmap 192.168.1.1
# 所有格式
nmap -oA scan_results 192.168.1.1
```

### 详细输出

控制显示信息的量。

```bash
# 详细输出
nmap -v 192.168.1.1
# 非常详细
nmap -vv 192.168.1.1
# 调试模式
nmap --packet-trace 192.168.1.1
```

### 恢复与追加

继续或向现有扫描添加内容。

```bash
# 恢复中断的扫描
nmap --resume scan_results.gnmap
# 追加到现有文件
nmap --append-output -oN existing_scan.txt 192.168.1.1
```

### 实时结果处理

将 Nmap 输出与命令行工具结合以提取有用信息。

```bash
# 提取在线主机
nmap -sn 192.168.1.0/24 | grep "Nmap scan report"
# 查找 Web 服务器
nmap -p 80,443 --open 192.168.1.0/24 | grep "open"
# 导出到 CSV
nmap -oX - 192.168.1.1 | xsltproc --html -
```

## 防火墙规避技术

### 数据包分段: `nmap -f`

使用数据包分段、IP 欺骗和隐蔽扫描方法来绕过安全措施。

```bash
# 分段数据包
nmap -f 192.168.1.1
# 自定义 MTU 大小
nmap --mtu 16 192.168.1.1
# 最大传输单元
nmap --mtu 24 192.168.1.1
```

### 诱饵扫描: `nmap -D`

在诱饵 IP 地址中隐藏您的扫描。

```bash
# 使用诱饵 IP
nmap -D 192.168.1.100,192.168.1.101 192.168.1.1
# 随机诱饵
nmap -D RND:5 192.168.1.1
# 混合真实和随机诱饵
nmap -D 192.168.1.100,RND:3 192.168.1.1
```

### 源 IP/端口操作

欺骗源信息。

```bash
# 欺骗源 IP
nmap -S 192.168.1.100 192.168.1.1
# 自定义源端口
nmap --source-port 53 192.168.1.1
# 随机数据长度
nmap --data-length 25 192.168.1.1
```

### 僵尸/空闲扫描: `nmap -sI`

使用僵尸主机来隐藏扫描来源。

```bash
# 僵尸扫描（需要空闲主机）
nmap -sI zombie_host 192.168.1.1
# 列出空闲候选主机
nmap --script ipidseq 192.168.1.0/24
```

## 高级扫描选项

### DNS 解析控制

控制 Nmap 如何处理 DNS 查询。

```bash
# 禁用 DNS 解析
nmap -n 192.168.1.1
# 强制 DNS 解析
nmap -R 192.168.1.1
# 自定义 DNS 服务器
nmap --dns-servers 8.8.8.8,1.1.1.1 192.168.1.1
```

### IPv6 扫描: `nmap -6`

使用这些 Nmap 标志以获得额外功能，例如 IPv6 支持。

```bash
# IPv6 扫描
nmap -6 2001:db8::1
# IPv6 网络扫描
nmap -6 2001:db8::/32
```

### 接口与路由

控制网络接口和路由。

```bash
# 指定网络接口
nmap -e eth0 192.168.1.1
# 打印接口和路由
nmap --iflist
# 路由跟踪
nmap --traceroute 192.168.1.1
```

### 杂项选项

其他有用的标志。

```bash
# 打印版本并退出
nmap --version
# 在以太网级别发送
nmap --send-eth 192.168.1.1
# 在 IP 级别发送
nmap --send-ip 192.168.1.1
```

## 实际示例

### 网络发现工作流程

完整的网络枚举过程。

```bash
# 步骤 1：发现在线主机
nmap -sn 192.168.1.0/24
# 步骤 2：快速端口扫描
nmap -sS -T4 --top-ports 1000 192.168.1.0/24
# 步骤 3：对感兴趣的主机进行详细扫描
nmap -sS -sV -sC -O 192.168.1.50
# 步骤 4：全面扫描
nmap -p- -A -T4 192.168.1.50
```

### Web 服务器评估

专注于 Web 服务和漏洞。

```bash
# 查找 Web 服务器
nmap -sS -p 80,443,8080,8443 --open 192.168.1.0/24
# 枚举 HTTP 服务
nmap -sS -sV --script http-* 192.168.1.50
# 检查常见漏洞
nmap --script vuln -p 80,443 192.168.1.50
```

### SMB/NetBIOS 枚举

以下示例枚举目标网络上的 Netbios。

```bash
# SMB 服务检测
nmap -sV -p 139,445 192.168.1.0/24
# NetBIOS 名称发现
nmap -sU --script nbstat -p 137 192.168.1.0/24
# SMB 枚举脚本
nmap --script smb-enum-* -p 445 192.168.1.50
# SMB 漏洞检查
nmap --script smb-vuln-* -p 445 192.168.1.50
```

### 隐蔽评估

低调的侦察。

```bash
# 超隐蔽扫描
nmap -sS -T0 -f --data-length 200 -D RND:10 192.168.1.1
# 分段 SYN 扫描
nmap -sS -f --mtu 8 -T1 192.168.1.1
```

## 性能优化

### 快速扫描策略

优化大型网络的扫描速度。

```bash
# 快速网络扫描
nmap -sS -T4 --min-rate 1000 --max-retries 1
192.168.1.0/24
# 并行主机扫描
nmap --min-hostgroup 50 --max-hostgroup 100
192.168.1.0/24
# 跳过慢速操作
nmap -sS -T4 --defeat-rst-ratelimit 192.168.1.0/24
```

### 内存与资源管理

控制资源使用以保持稳定性。

```bash
# 限制并行探测数
nmap --max-parallelism 10 192.168.1.0/24
# 控制扫描延迟
nmap --scan-delay 100ms 192.168.1.1
# 设置主机超时
nmap --host-timeout 10m 192.168.1.0/24
```

## 相关链接

- <router-link to="/wireshark">Wireshark 速查表</router-link>
- <router-link to="/kali">Kali Linux 速查表</router-link>
- <router-link to="/cybersecurity">网络安全速查表</router-link>
- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/network">网络速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>

---
title: 'Wireshark 速查表 | LabEx'
description: '使用这份综合速查表学习 Wireshark 网络分析。快速参考数据包捕获、网络协议分析、流量检查、故障排除和网络安全监控。'
pdfUrl: '/cheatsheets/pdf/wireshark-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Wireshark 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/wireshark">通过实践实验室学习 Wireshark</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Wireshark 网络数据包分析。LabEx 提供全面的 Wireshark 课程，涵盖基本的包捕获、显示过滤器、协议分析、网络故障排除和安全监控。掌握网络流量分析和数据包检查技术。
</base-disclaimer-content>
</base-disclaimer>

## 捕获过滤器和流量捕获

### 主机过滤

捕获到/来自特定主机的流量。

```bash
# 捕获到/来自特定 IP 的流量
host 192.168.1.100
# 捕获来自特定源的流量
src host 192.168.1.100
# 捕获到特定目标的流量
dst host 192.168.1.100
# 捕获来自子网的流量
net 192.168.1.0/24
```

<BaseQuiz id="wireshark-filter-1" correct="A">
  <template #question>
    Wireshark 中的 <code>host 192.168.1.100</code> 过滤器捕获什么？
  </template>
  
  <BaseQuizOption value="A" correct>所有到或来自 192.168.1.100 的流量</BaseQuizOption>
  <BaseQuizOption value="B">仅来自 192.168.1.100 的流量</BaseQuizOption>
  <BaseQuizOption value="C">仅到 192.168.1.100 的流量</BaseQuizOption>
  <BaseQuizOption value="D">192.168.1.100 端口上的流量</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>host</code> 过滤器捕获指定 IP 地址作为源或目的地的所有流量。使用 <code>src host</code> 进行仅源过滤或 <code>dst host</code> 进行仅目的过滤。
  </BaseQuizAnswer>
</BaseQuiz>

### 端口过滤

捕获特定端口上的流量。

```bash
# HTTP 流量 (端口 80)
port 80
# HTTPS 流量 (端口 443)
port 443
# SSH 流量 (端口 22)
port 22
# DNS 流量 (端口 53)
port 53
# 端口范围
portrange 1000-2000
```

<BaseQuiz id="wireshark-port-1" correct="D">
  <template #question>
    Wireshark 中的 <code>port 80</code> 过滤器捕获什么？
  </template>
  
  <BaseQuizOption value="A">仅 HTTP 请求</BaseQuizOption>
  <BaseQuizOption value="B">仅 HTTP 响应</BaseQuizOption>
  <BaseQuizOption value="C">仅 TCP 数据包</BaseQuizOption>
  <BaseQuizOption value="D" correct>端口 80 上的所有流量（源和目的）</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>port</code> 过滤器捕获端口 80 作为源端口或目的端口的所有流量。这包括 HTTP 请求和响应，以及使用端口 80 的任何其他流量。
  </BaseQuizAnswer>
</BaseQuiz>

### 协议过滤

捕获特定协议流量。

```bash
# 仅 TCP 流量
tcp
# 仅 UDP 流量
udp
# 仅 ICMP 流量
icmp
# 仅 ARP 流量
arp
```

### 高级捕获过滤器

组合多个条件以实现精确捕获。

```bash
# 到/来自特定主机的 HTTP 流量
host 192.168.1.100 and port 80
# 除 SSH 之外的 TCP 流量
tcp and not port 22
# 两个主机之间的流量
host 192.168.1.100 and host 192.168.1.200
# HTTP 或 HTTPS 流量
port 80 or port 443
```

<BaseQuiz id="wireshark-advanced-1" correct="B">
  <template #question>
    <code>tcp and not port 22</code> 过滤器捕获什么？
  </template>
  
  <BaseQuizOption value="A">仅 SSH 流量</BaseQuizOption>
  <BaseQuizOption value="B" correct>除 SSH (端口 22) 之外的所有 TCP 流量</BaseQuizOption>
  <BaseQuizOption value="C">端口 22 上的 UDP 流量</BaseQuizOption>
  <BaseQuizOption value="D">所有网络流量</BaseQuizOption>
  
  <BaseQuizAnswer>
    此过滤器捕获所有 TCP 流量，但排除了端口 22 (SSH) 上的数据包。<code>and not</code> 运算符在保留所有其他 TCP 流量的同时排除了指定的端口。
  </BaseQuizAnswer>
</BaseQuiz>

### 接口选择

选择用于捕获的网络接口。

```bash
# 列出可用接口
tshark -D
# 在特定接口上捕获
# 以太网接口
eth0
# WiFi 接口
wlan0
# 回环接口
lo
```

### 捕获选项

配置捕获参数。

```bash
# 限制捕获文件大小 (MB)
-a filesize:100
# 限制捕获持续时间 (秒)
-a duration:300
# 带有 10 个文件的环形缓冲区
-b files:10
# 混杂模式 (捕获所有流量)
-p
```

## 显示过滤器和数据包分析

### 基本显示过滤器

用于常见协议和流量类型的基本过滤器。

```bash
# 仅显示 HTTP 流量
http
# 显示仅 HTTPS/TLS 流量
tls
# 仅显示 DNS 流量
dns
# 仅显示 TCP 流量
tcp
# 仅显示 UDP 流量
udp
# 仅显示 ICMP 流量
icmp
```

### IP 地址过滤

按源和目的 IP 地址过滤数据包。

```bash
# 来自特定 IP 的流量
ip.src == 192.168.1.100
# 到特定 IP 的流量
ip.dst == 192.168.1.200
# 两个 IP 之间的流量
ip.addr == 192.168.1.100
# 来自子网的流量
ip.src_net == 192.168.1.0/24
# 排除特定 IP
not ip.addr == 192.168.1.1
```

### 端口和协议过滤

按特定端口和协议详细信息过滤。

```bash
# 特定端口上的流量
tcp.port == 80
# 源端口过滤
tcp.srcport == 443
# 目的端口过滤
tcp.dstport == 22
# 端口范围
tcp.port >= 1000 and tcp.port <=
2000
# 多个端口
tcp.port in {80 443 8080}
```

## 特定于协议的分析

### HTTP 分析

分析 HTTP 请求和响应。

```bash
# HTTP GET 请求
http.request.method == "GET"
# HTTP POST 请求
http.request.method == "POST"
# 特定 HTTP 状态码
http.response.code == 404
# 到特定主机的 HTTP 请求
http.host == "example.com"
# 包含字符串的 HTTP 请求
http contains "login"
```

### DNS 分析

检查 DNS 查询和响应。

```bash
# 仅 DNS 查询
dns.flags.response == 0
# 仅 DNS 响应
dns.flags.response == 1
# 对特定域名的 DNS 查询
dns.qry.name == "example.com"
# DNS A 记录查询
dns.qry.type == 1
# DNS 错误/失败
dns.flags.rcode != 0
```

### TCP 分析

分析 TCP 连接详细信息。

```bash
# TCP SYN 数据包 (连接尝试)
tcp.flags.syn == 1
# TCP RST 数据包 (连接重置)
tcp.flags.reset == 1
# TCP 重传
tcp.analysis.retransmission
# TCP 窗口问题
tcp.analysis.window_update
# TCP 连接建立
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### TLS/SSL 分析

检查加密连接详细信息。

```bash
# TLS 握手数据包
tls.handshake
# TLS 证书信息
tls.handshake.certificate
# TLS 警报和错误
tls.alert
# 特定 TLS 版本
tls.handshake.version == 0x0303
# TLS 服务器名称指示
tls.handshake.extensions_server_name
```

### 网络故障排除

识别常见的网络问题。

```bash
# ICMP 不可达消息
icmp.type == 3
# ARP 请求/响应
arp.opcode == 1 or arp.opcode == 2
# 广播流量
eth.dst == ff:ff:ff:ff:ff:ff
# 分片数据包
ip.flags.mf == 1
# 大数据包 (潜在的 MTU 问题)
frame.len > 1500
```

### 基于时间的过滤

按时间戳和定时过滤数据包。

```bash
# 时间范围内的包
frame.time >= "2024-01-01 10:00:00"
# 过去一小时的包
frame.time_relative >= -3600
# 响应时间分析
tcp.time_delta > 1.0
# 包间到达时间
frame.time_delta > 0.1
```

## 统计和分析工具

### 协议层次结构

查看捕获中协议的分布情况。

```bash
# 通过以下方式访问: 统计信息 > 协议层次结构
# 显示每个协议的百分比
# 识别最常见的协议
# 有助于流量概览
# 命令行等效项
tshark -r capture.pcap -q -z io,phs
```

### 会话

分析端点之间的通信。

```bash
# 通过以下方式访问: 统计信息 > 会话
# 以太网会话
# IPv4/IPv6 会话
# TCP/UDP 会话
# 显示传输的字节数、数据包计数
# 命令行等效项
tshark -r capture.pcap -q -z conv,tcp
```

### I/O 图表

可视化随时间变化的流量模式。

```bash
# 通过以下方式访问: 统计信息 > I/O 图表
# 随时间变化的流量量
# 每秒数据包数
# 每秒字节数
# 应用过滤器以获得特定流量
# 有助于识别流量高峰
```

### 专家信息

识别潜在的网络问题。

```bash
# 通过以下方式访问: 分析 > 专家信息
# 关于网络问题的警告
# 数据包传输中的错误
# 性能问题
# 安全问题
# 按专家信息严重性过滤
tcp.analysis.flags
```

### 流图

可视化端点之间的数据包流。

```bash
# 通过以下方式访问: 统计信息 > 流图
# 显示数据包序列
# 基于时间的视觉化
# 有助于故障排除
# 识别通信模式
```

### 响应时间分析

测量应用程序响应时间。

```bash
# HTTP 响应时间
# 统计信息 > HTTP > 请求
# DNS 响应时间
# 统计信息 > DNS
# TCP 服务响应时间
# 统计信息 > TCP 流图 > 时间序列
```

## 文件操作和导出

### 保存和加载捕获

以各种格式管理捕获文件。

```bash
# 保存捕获文件
# 文件 > 另存为 > capture.pcap
# 加载捕获文件
# 文件 > 打开 > existing.pcap
# 合并多个捕获文件
# 文件 > 合并 > 选择文件
# 仅保存过滤后的数据包
# 文件 > 导出指定数据包
```

### 导出选项

导出特定数据或数据包子集。

```bash
# 导出选定的数据包
# 文件 > 导出指定数据包
# 导出数据包解析
# 文件 > 导出数据包解析
# 从 HTTP 导出对象
# 文件 > 导出对象 > HTTP
# 导出 SSL/TLS 密钥
# 编辑 > 首选项 > 协议 > TLS
```

### 命令行捕获

使用 tshark 进行自动化捕获和分析。

```bash
# 捕获到文件
tshark -i eth0 -w capture.pcap
# 带过滤器的捕获
tshark -i eth0 -f "port 80" -w http.pcap
# 读取并显示数据包
tshark -r capture.pcap
# 对文件应用显示过滤器
tshark -r capture.pcap -Y "tcp.port == 80"
```

### 批量处理

自动处理多个捕获文件。

```bash
# 合并多个文件
mergecap -w merged.pcap file1.pcap file2.pcap
# 分割大型捕获文件
editcap -c 1000 large.pcap split.pcap
# 提取时间范围
editcap -A "2024-01-01 10:00:00" \
        -B "2024-01-01 11:00:00" \
        input.pcap output.pcap
```

## 性能和优化

### 内存管理

高效处理大型捕获文件。

```bash
# 使用环形缓冲区进行连续捕获
-b filesize:100 -b files:10
# 限制数据包捕获大小
-s 96  # 仅捕获前 96 字节
# 使用捕获过滤器减少数据量
host 192.168.1.100 and port 80
# 为提高速度禁用协议解析
-d tcp.port==80,http
```

### 显示优化

提高大型数据集的 GUI 性能。

```bash
# 要调整的首选项:
# 编辑 > 首选项 > 外观
# 颜色方案选择
# 字体大小和类型
# 列显示选项
# 时间格式设置
# 视图 > 时间显示格式
# 自捕获开始以来的秒数
# 当天时间
# UTC 时间
# 使用 tshark 分析大文件
tshark -r large.pcap -q -z conv,tcp
```

### 高效分析工作流程

分析网络流量的最佳实践。

```bash
# 1. 从捕获过滤器开始
# 仅捕获相关流量
# 2. 逐步使用显示过滤器
# 从宽泛到精确
# 3. 首先使用统计信息
# 在详细分析之前获得概览
# 4. 关注特定流
# 右键单击数据包 > 跟踪 > TCP 流
```

### 自动化和脚本编写

自动化常见的分析任务。

```bash
# 创建自定义显示过滤器按钮
# 视图 > 显示过滤器表达式
# 为不同场景使用配置文件
# 编辑 > 配置配置文件
# 使用 tshark 脚本编写
#!/bin/bash
tshark -r $1 -q -z endpoints,tcp | \
grep -v "Filter:" | head -20
```

## 安装和设置

### Windows 安装

从官方网站下载并安装。

```bash
# 从 wireshark.org 下载
# 以管理员身份运行安装程序
# 包括 WinPcap/Npcap
during installation
# 命令行安装
(chocolatey)
choco install wireshark
# 验证安装
wireshark --version
```

### Linux 安装

通过包管理器或从源代码安装。

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install wireshark
# Red Hat/CentOS/Fedora
sudo yum install wireshark
# or
sudo dnf install wireshark
# 将用户添加到 wireshark 组
sudo usermod -a -G wireshark
$USER
```

### macOS 安装

使用 Homebrew 或官方安装程序安装。

```bash
# 使用 Homebrew
brew install --cask wireshark
# 从 wireshark.org 下载
# 安装 .dmg 包
# 命令行工具
brew install wireshark
```

## 配置和首选项

### 接口首选项

配置捕获接口和选项。

```bash
# 编辑 > 首选项 > 捕获
# 默认捕获接口
# 混杂模式设置
# 缓冲区大小配置
# 实时捕获中的自动滚动
# 接口特定设置
# 捕获 > 选项 > 接口详细信息
```

### 协议设置

配置协议解析器和解码。

```bash
# 编辑 > 首选项 > 协议
# 启用/禁用协议解析器
# 配置端口分配
# 设置解密密钥 (TLS, WEP 等)
# TCP 重组选项
# 解码为功能
# 分析 > 解码为
```

### 显示首选项

自定义用户界面和显示选项。

```bash
# 编辑 > 首选项 > 外观
# 颜色方案选择
# 字体大小和类型
# 列显示选项
# 时间格式设置
# 视图 > 时间显示格式
# 自捕获开始以来的秒数
# 当天时间
# UTC 时间
```

### 安全设置

配置与安全相关的选项和解密。

```bash
# TLS 解密设置
# 编辑 > 首选项 > 协议 > TLS
# RSA 密钥列表
# 预共享密钥
# 密钥日志文件位置
# 禁用潜在危险的功能
# Lua 脚本执行
# 外部解析器
```

## 高级过滤技术

### 逻辑运算符

组合多个过滤条件。

```bash
# AND 运算符
tcp.port == 80 and ip.src == 192.168.1.100
# OR 运算符
tcp.port == 80 or tcp.port == 443
# NOT 运算符
not icmp
# 用于分组的括号
(tcp.port == 80 or tcp.port == 443) and ip.src ==
192.168.1.0/24
```

### 字符串匹配

在数据包中搜索特定内容。

```bash
# 包含字符串 (区分大小写)
tcp contains "password"
# 包含字符串 (不区分大小写)
tcp matches "(?i)login"
# 正则表达式
http.request.uri matches "\.php$"
# 字节序列
eth.src[0:3] == 00:11:22
```

### 字段比较

将数据包字段与值和范围进行比较。

```bash
# 等于
tcp.srcport == 80
# 大于/小于
frame.len > 1000
# 范围检查
tcp.port >= 1024 and tcp.port <= 65535
# 集合成员资格
tcp.port in {80 443 8080 8443}
# 字段存在性
tcp.options
```

### 高级数据包分析

识别特定的数据包特征和异常。

```bash
# 格式错误的包
_ws.malformed
# 重复数据包
frame.number == tcp.analysis.duplicate_ack_num
# 乱序数据包
tcp.analysis.out_of_order
# TCP 窗口满问题
tcp.analysis.window_full
```

## 常见用例

### 网络故障排除

识别并解决网络连接问题。

```bash
# 查找连接超时
tcp.analysis.retransmission and tcp.analysis.rto
# 识别慢速连接
tcp.time_delta > 1.0
# 查找网络拥塞
tcp.analysis.window_full
# DNS 解析问题
dns.flags.rcode != 0
# MTU 发现问题
icmp.type == 3 and icmp.code == 4
```

### 安全分析

检测潜在的安全威胁和可疑活动。

```bash
# 端口扫描检测
tcp.flags.syn == 1 and tcp.flags.ack == 0
# 单个 IP 的大量连接
# 使用 统计信息 > 会话
# 可疑 DNS 查询
dns.qry.name contains "dga" or dns.qry.name matches
"^[a-z]{8,}\.com$"
# HTTP POST 到可疑 URL
http.request.method == "POST" and http.request.uri
contains "/upload"
# 不寻常的流量模式
# 检查 I/O 图表中的高峰
```

### 应用程序性能

监控和分析应用程序响应时间。

```bash
# Web 应用程序分析
http.time > 2.0
# 数据库连接监控
tcp.port == 3306 and tcp.analysis.initial_rtt > 0.1
# 文件传输性能
tcp.stream eq X and tcp.analysis.bytes_in_flight
# VoIP 质量分析
rtp.jitter > 30 or rtp.marker == 1
```

### 协议调查

深入研究特定协议及其行为。

```bash
# 电子邮件流量分析
tcp.port == 25 or tcp.port == 587 or tcp.port == 993
# FTP 文件传输
ftp-data or ftp.request.command == "RETR"
# SMB/CIFS 文件共享
smb2 or smb
# DHCP 租约分析
bootp.option.dhcp == 1 or bootp.option.dhcp == 2
```

## 相关链接

- <router-link to="/nmap">Nmap 速查表</router-link>
- <router-link to="/cybersecurity">网络安全速查表</router-link>
- <router-link to="/kali">Kali Linux 速查表</router-link>
- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/network">网络速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>

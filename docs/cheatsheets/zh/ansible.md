---
title: 'Ansible 速查表'
description: '使用我们涵盖核心命令、概念和最佳实践的 Ansible 速查表，快速掌握 Ansible。'
pdfUrl: '/cheatsheets/pdf/ansible-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Ansible 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/ansible">通过动手实验学习 Ansible</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过动手实验和真实场景学习 Ansible 基础设施自动化。LabEx 提供全面的 Ansible 课程，涵盖基本的 Playbook 创建、清单管理、模块使用和角色组织。掌握配置管理和基础设施自动化，以实现 DevOps 工作流程。
</base-disclaimer-content>
</base-disclaimer>

## 安装和设置

### Ubuntu/Debian: `apt install ansible`

在基于 Debian 的 Linux 系统上安装 Ansible。

```bash
# 添加 Ansible 仓库
sudo apt-add-repository ppa:ansible/ansible
# 更新软件包列表
sudo apt-get update
# 安装 Ansible
sudo apt-get install ansible
# 验证安装
ansible --version
```

### CentOS/RHEL: `yum install ansible`

在基于 Red Hat 的系统上安装 Ansible。

```bash
# 安装 EPEL 仓库
sudo yum install epel-release -y
# 安装 Ansible
sudo yum install ansible -y
# 验证安装
ansible --version
```

### macOS: `brew install ansible`

使用 Homebrew 在 macOS 上安装 Ansible。

```bash
# 使用 Homebrew 安装
brew install ansible
# 验证安装
ansible --version
```

### 配置：`/etc/ansible/ansible.cfg`

配置 Ansible 设置和默认值。

```bash
# 查看当前配置
ansible-config list
# 查看有效配置
ansible-config view
# 自定义配置文件
export ANSIBLE_CONFIG=/path/to/ansible.cfg
```

### SSH 设置：基于密钥的身份验证

Ansible 使用 SSH 在节点间通信。

```bash
# 生成 SSH 密钥
ssh-keygen -t rsa -b 4096
# 将公钥复制到远程主机
ssh-copy-id user@hostname
# 测试 SSH 连接
ssh user@hostname
```

### 环境设置

设置 Ansible 环境变量和路径。

```bash
# 设置清单文件位置
export ANSIBLE_INVENTORY=/path/to/inventory
# 设置主机密钥检查
export ANSIBLE_HOST_KEY_CHECKING=False
# 设置远程用户
export ANSIBLE_REMOTE_USER=ubuntu
```

## 清单管理

### 基本清单：`/etc/ansible/hosts`

主机组可以通过在方括号内给出组名来创建。

```ini
# 基本主机文件 (INI 格式)
[webservers]
web1.example.com
web2.example.com
[databases]
db1.example.com
db2.example.com
[all:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/id_rsa
```

### YAML 清单格式

清单文件可以是 INI 或 YAML 格式。

```yaml
# inventory.yml
all:
  children:
    webservers:
      hosts:
        web1.example.com:
        web2.example.com:
    databases:
      hosts:
        db1.example.com:
      vars:
        mysql_port: 3306
```

### 主机变量和组

定义特定于主机的变量和组配置。

```ini
# 带有变量的清单
[webservers]
web1.example.com http_port=80
web2.example.com http_port=8080
[webservers:vars]
ansible_user=nginx
nginx_version=1.18

# 测试清单
ansible-inventory --list
ansible-inventory --graph
```

## Ad-Hoc 命令

### 基本命令结构

Ansible 命令的基本结构：`ansible <hosts> -m <module> -a "<arguments>"`

```bash
# 测试连通性
ansible all -m ping
# 检查特定组
ansible webservers -m ping
# 在所有主机上运行命令
ansible all -m command -a "uptime"
# 使用 sudo 权限运行
ansible all -m command -a "systemctl status nginx" --become
```

### 文件操作

在主机上创建目录、文件和符号链接。

```bash
# 创建目录
ansible all -m file -a "path=/tmp/test state=directory mode=0755"
# 创建文件
ansible all -m file -a "path=/tmp/test.txt state=touch"
# 删除文件/目录
ansible all -m file -a "path=/tmp/test state=absent"
# 创建符号链接
ansible all -m file -a "src=/etc/nginx dest=/tmp/nginx state=link"
```

### 包管理

在不同系统上安装、更新和删除软件包。

```bash
# 安装软件包 (apt)
ansible webservers -m apt -a "name=nginx state=present" --become
# 安装软件包 (yum)
ansible webservers -m yum -a "name=httpd state=present" --become
# 更新所有软件包
ansible all -m apt -a "upgrade=dist" --become
# 删除软件包
ansible all -m apt -a "name=apache2 state=absent" --become
```

### 服务管理

启动、停止和管理系统服务。

```bash
# 启动服务
ansible webservers -m service -a "name=nginx state=started" --become
# 停止服务
ansible webservers -m service -a "name=apache2 state=stopped" --become
# 重启服务
ansible webservers -m service -a "name=ssh state=restarted" --become
# 在启动时启用服务
ansible all -m service -a "name=nginx enabled=yes" --become
```

## Playbooks 和任务

### 基本 Playbook 结构

YAML 文件，定义应在哪些主机上运行哪些任务。

```yaml
---
- name: Web server setup
  hosts: webservers
  become: yes
  vars:
    nginx_port: 80

  tasks:
    - name: Install nginx
      apt:
        name: nginx
        state: present

    - name: Start nginx service
      service:
        name: nginx
        state: started
        enabled: yes
```

### 运行 Playbooks

使用各种选项和配置运行 Playbooks。

```bash
# 运行 Playbook
ansible-playbook site.yml
# 使用特定清单运行
ansible-playbook -i inventory.yml site.yml
# 演练 (check 模式)
ansible-playbook site.yml --check
# 在特定主机上运行
ansible-playbook site.yml --limit webservers
# 使用额外变量运行
ansible-playbook site.yml --extra-vars "nginx_port=8080"
```

### 任务选项和条件

向任务添加条件、循环和错误处理。

```yaml
tasks:
  - name: Install packages
    apt:
      name: '{{ item }}'
      state: present
    loop:
      - nginx
      - mysql-server
      - php
    when: ansible_os_family == "Debian"

  - name: Create user
    user:
      name: webuser
      state: present
    register: user_result

  - name: Show user creation result
    debug:
      msg: 'User created: {{ user_result.changed }}'
```

### 处理器和通知

定义在被任务通知时运行的处理器。

```yaml
tasks:
  - name: Update nginx config
    template:
      src: nginx.conf.j2
      dest: /etc/nginx/nginx.conf
    notify: restart nginx

handlers:
  - name: restart nginx
    service:
      name: nginx
      state: restarted
```

## 变量和模板

### 变量定义

在不同级别和作用域定义变量。

```yaml
# 在 Playbook 中
vars:
  app_name: myapp
  app_port: 8080

# 在 group_vars/all.yml 中
database_host: db.example.com
database_port: 5432

# 在 host_vars/web1.yml 中
server_role: frontend
max_connections: 100

# 命令行变量
ansible-playbook site.yml -e "env=production"
```

### Jinja2 模板

使用模板创建动态配置文件。

```jinja2
# 模板文件: nginx.conf.j2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};

    location / {
        proxy_pass http://{{ backend_host }}:{{ backend_port }};
    }
}
```

```yaml
# 使用 template 模块
- name: Deploy nginx config
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/sites-available/default
  notify: reload nginx
```

### Facts 和系统信息

在 Playbook 中收集和使用系统 Facts。

```bash
# 手动收集 facts
ansible all -m setup
# 收集特定 facts
ansible all -m setup -a "filter=ansible_eth*"
```

```yaml
# 在 Playbook 中使用 facts
- name: Show system info
  debug:
    msg: '{{ ansible_hostname }} runs {{ ansible_distribution }}'

- name: Install package based on OS
  apt:
    name: apache2
  when: ansible_os_family == "Debian"
```

### Vault 和秘密管理

使用 Ansible Vault 加密敏感数据。

```bash
# 创建加密文件
ansible-vault create secrets.yml
# 编辑加密文件
ansible-vault edit secrets.yml
# 加密现有文件
ansible-vault encrypt passwords.yml
# 使用 vault 运行 Playbook
ansible-playbook site.yml --ask-vault-pass
# 使用 vault 密码文件
ansible-playbook site.yml --vault-password-file .vault_pass
```

## 角色和组织

### 角色结构

将 Playbook 组织成可重用的角色。

```bash
# 创建角色结构
ansible-galaxy init webserver
```

```
# 角色目录结构
webserver/
├── tasks/
│   └── main.yml
├── handlers/
│   └── main.yml
├── templates/
├── files/
├── vars/
│   └── main.yml
├── defaults/
│   └── main.yml
└── meta/
    └── main.yml
```

### 在 Playbook 中使用角色

将角色应用于 Playbook 中的主机。

```yaml
---
- hosts: webservers
  roles:
    - common
    - webserver
    - { role: database, database_type: mysql }

# 或使用 include_role
- hosts: webservers
  tasks:
    - include_role:
        name: webserver
      vars:
        nginx_port: 8080
```

### Ansible Galaxy

从 Ansible Galaxy 下载和管理社区角色。

```bash
# 从 Galaxy 安装角色
ansible-galaxy install geerlingguy.nginx
# 安装特定版本
ansible-galaxy install geerlingguy.nginx,2.8.0
# 从 requirements 文件安装
ansible-galaxy install -r requirements.yml
# 列出已安装的角色
ansible-galaxy list
# 移除角色
ansible-galaxy remove geerlingguy.nginx
```

### 集合 (Collections)

使用 Ansible 集合以获得扩展功能。

```bash
# 安装集合
ansible-galaxy collection install community.general
```

```yaml
# 在 Playbook 中使用集合
collections:
  - community.general
tasks:
  - name: Install package
    community.general.snap:
      name: code
      state: present
```

## 调试和故障排除

### 调试任务

调试和排除 Playbook 执行故障。

```yaml
# 添加调试任务
- name: Show variable value
  debug:
    var: my_variable
- name: Show custom message
  debug:
    msg: 'Server {{ inventory_hostname }} has IP {{ ansible_default_ipv4.address }}'
```

```bash
# 详细执行
ansible-playbook site.yml -v
ansible-playbook site.yml -vvv  # 最大详细程度
```

### 错误处理

优雅地处理错误和失败。

```yaml
- name: Task that might fail
  command: /bin/false
  ignore_errors: yes

- name: Task with rescue
  block:
    - command: /bin/false
  rescue:
    - debug:
        msg: 'Task failed, running rescue'
  always:
    - debug:
        msg: 'This always runs'
```

### 测试和验证

测试 Playbook 和验证配置。

```bash
# 检查语法
ansible-playbook site.yml --syntax-check
# 列出任务
ansible-playbook site.yml --list-tasks
# 列出主机
ansible-playbook site.yml --list-hosts
# 逐步执行
ansible-playbook site.yml --step
# 使用 check 模式测试
ansible-playbook site.yml --check --diff
```

### 性能和优化

优化 Playbook 性能和执行。

```yaml
# 并行运行任务
- name: Install packages
  apt:
    name: '{{ packages }}'
  vars:
    packages:
      - nginx
      - mysql-server

# 对长时间运行的任务使用 async
- name: Long running task
  command: /usr/bin/long-task
  async: 300
  poll: 5
```

## 最佳实践和技巧

### 安全最佳实践

保护您的 Ansible 基础设施和操作。

```bash
# 使用 Ansible Vault 加密秘密信息
ansible-vault create group_vars/all/vault.yml
# 谨慎禁用主机密钥检查
host_key_checking = False
# 仅在必要时使用 become
become: yes
become_user: root
# 限制 Playbook 范围
ansible-playbook site.yml --limit production
```

### 代码组织

有效地组织您的 Ansible 项目。

```bash
# 推荐的目录结构
ansible-project/
├── inventories/
│   ├── production/
│   └── staging/
├── group_vars/
├── host_vars/
├── roles/
├── playbooks/
└── ansible.cfg
```

```yaml
# 使用有意义的名称和文档
- name: 描述性的任务名称
  # 为复杂逻辑添加注释
```

### 版本控制和测试

使用适当的版本控制管理 Ansible 代码。

```bash
# 使用 Git 进行版本控制
git init
git add .
git commit -m "Initial Ansible setup"
# 在生产环境之前在 staging 环境中测试
ansible-playbook -i staging site.yml
# 使用标签进行选择性执行
ansible-playbook site.yml --tags "nginx,ssl"
```

## 相关链接

- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/kubernetes">Kubernetes 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>

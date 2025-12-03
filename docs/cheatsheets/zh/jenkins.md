---
title: 'Jenkins 速查表 | LabEx'
description: '使用这份全面的速查表学习 Jenkins CI/CD。快速参考 Jenkins 管道、作业、插件、自动化、持续集成和 DevOps 工作流程。'
pdfUrl: '/cheatsheets/pdf/jenkins-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Jenkins 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/jenkins">使用实战实验学习 Jenkins</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实战实验和真实场景学习 Jenkins CI/CD 自动化。LabEx 提供全面的 Jenkins 课程，涵盖基本操作、Pipeline 创建、插件管理、构建自动化和高级技术。掌握 Jenkins，为现代软件开发构建高效的持续集成和部署流水线。
</base-disclaimer-content>
</base-disclaimer>

## 安装与设置

### Linux 安装

在 Ubuntu/Debian 系统上安装 Jenkins。

```bash
# 更新包管理器并安装 Java
sudo apt update
sudo apt install fontconfig openjdk-21-jre
java -version
# 添加 Jenkins GPG 密钥
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
# 添加 Jenkins 仓库
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
/etc/apt/sources.list.d/jenkins.list > /dev/null
# 安装 Jenkins
sudo apt update && sudo apt install jenkins
# 启动 Jenkins 服务
sudo systemctl start jenkins
sudo systemctl enable jenkins
```

### Windows 和 macOS

使用安装程序或包管理器安装 Jenkins。

```bash
# Windows: 从 jenkins.io 下载安装程序
# 或使用 Chocolatey
choco install jenkins
# macOS: 使用 Homebrew
brew install jenkins-lts
# 或直接从以下链接下载：
# https://www.jenkins.io/download/
# 启动 Jenkins 服务
brew services start jenkins-lts
```

### 安装后设置

初始配置和解锁 Jenkins。

```bash
# 获取初始管理员密码
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# 或对于 Docker 安装
docker exec jenkins_container cat /var/jenkins_home/secrets/initialAdminPassword
# 访问 Jenkins Web 界面
# 浏览至 http://localhost:8080
# 输入初始管理员密码
# 安装建议的插件或选择自定义插件
```

### 初始配置

完成设置向导并创建管理员用户。

```bash
# 解锁 Jenkins 后：
# 1. 安装建议的插件（推荐）
# 2. 创建第一个管理员用户
# 3. 配置 Jenkins URL
# 4. 开始使用 Jenkins
# 验证 Jenkins 是否正在运行
sudo systemctl status jenkins
# 如有需要，检查 Jenkins 日志
sudo journalctl -u jenkins.service
```

## Jenkins 基本操作

### 访问 Jenkins：Web 界面和 CLI 设置

通过浏览器访问 Jenkins 并设置 CLI 工具。

```bash
# 访问 Jenkins Web 界面
http://localhost:8080
# 下载 Jenkins CLI
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
# 测试 CLI 连接
java -jar jenkins-cli.jar -s http://localhost:8080 help
# 列出可用命令
java -jar jenkins-cli.jar -s http://localhost:8080 help
```

### 创建任务：`create-job` / Web UI

使用 CLI 或 Web 界面创建新的构建任务。

```bash
# 从 XML 配置创建任务
java -jar jenkins-cli.jar -auth user:token create-job my-job < job-config.xml
# 通过 Web UI 创建简单的自由风格项目：
# 1. 点击“新建任务”
# 2. 输入任务名称
# 3. 选择“自由风格项目”
# 4. 配置构建步骤
# 5. 保存配置
```

### 列出任务：`list-jobs`

查看 Jenkins 中所有已配置的任务。

```bash
# 列出所有任务
java -jar jenkins-cli.jar -auth user:token list-jobs
# 使用模式匹配列出任务
java -jar jenkins-cli.jar -auth user:token list-jobs "*test*"
# 获取任务配置
java -jar jenkins-cli.jar -auth user:token get-job my-job > job-config.xml
```

## 任务管理

### 构建任务：`build`

触发和管理任务构建。

```bash
# 构建一个任务
java -jar jenkins-cli.jar -auth user:token build my-job
# 带参数构建
java -jar jenkins-cli.jar -auth user:token build my-job -p PARAM=value
# 构建并等待完成
java -jar jenkins-cli.jar -auth user:token build my-job -s -v
# 构建并跟踪控制台输出
java -jar jenkins-cli.jar -auth user:token build my-job -f
```

<BaseQuiz id="jenkins-build-1" correct="B">
  <template #question>
    <code>jenkins-cli.jar build my-job -s</code> 中的 <code>-s</code> 标志是做什么的？
  </template>
  
  <BaseQuizOption value="A">跳过构建</BaseQuizOption>
  <BaseQuizOption value="B" correct>等待构建完成（同步）</BaseQuizOption>
  <BaseQuizOption value="C">显示构建状态</BaseQuizOption>
  <BaseQuizOption value="D">停止构建</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-s</code> 标志使构建命令同步，意味着它在返回之前会等待构建完成。如果没有此标志，命令在触发构建后会立即返回。
  </BaseQuizAnswer>
</BaseQuiz>

### 任务控制：`enable-job` / `disable-job`

启用或禁用任务。

```bash
# 启用一个任务
java -jar jenkins-cli.jar -auth user:token enable-job my-job
# 禁用一个任务
java -jar jenkins-cli.jar -auth user:token disable-job my-job
# 在 Web UI 中检查任务状态
# 导航到任务仪表板
# 查看“禁用/启用”按钮
```

<BaseQuiz id="jenkins-job-control-1" correct="B">
  <template #question>
    禁用 Jenkins 任务时会发生什么？
  </template>
  
  <BaseQuizOption value="A">任务被永久删除</BaseQuizOption>
  <BaseQuizOption value="B" correct>任务配置被保留，但它不会自动运行</BaseQuizOption>
  <BaseQuizOption value="C">任务被移动到另一个文件夹</BaseQuizOption>
  <BaseQuizOption value="D">所有构建历史记录被删除</BaseQuizOption>
  
  <BaseQuizAnswer>
    禁用任务会阻止它自动运行（计划构建、触发器等），但会保留任务配置和构建历史记录。之后可以重新启用它。
  </BaseQuizAnswer>
</BaseQuiz>

### 任务删除：`delete-job`

从 Jenkins 中删除任务。

```bash
# 删除一个任务
java -jar jenkins-cli.jar -auth user:token delete-job my-job
# 批量删除任务（请谨慎操作）
for job in job1 job2 job3; do
  java -jar jenkins-cli.jar -auth user:token delete-job $job
done
```

### 控制台输出：`console`

查看构建日志和控制台输出。

```bash
# 查看最新构建的控制台输出
java -jar jenkins-cli.jar -auth user:token console my-job
# 查看特定构建编号
java -jar jenkins-cli.jar -auth user:token console my-job 15
# 实时跟踪控制台输出
java -jar jenkins-cli.jar -auth user:token console my-job -f
```

<BaseQuiz id="jenkins-console-1" correct="C">
  <template #question>
    <code>jenkins-cli.jar console my-job -f</code> 中的 <code>-f</code> 标志是做什么的？
  </template>
  
  <BaseQuizOption value="A">强制停止构建</BaseQuizOption>
  <BaseQuizOption value="B">仅显示失败的构建</BaseQuizOption>
  <BaseQuizOption value="C" correct>实时跟踪控制台输出</BaseQuizOption>
  <BaseQuizOption value="D">将输出格式化为 JSON</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-f</code> 标志实时跟踪控制台输出，类似于 Linux 中的 <code>tail -f</code>。这对于在构建执行时进行监控非常有用。
  </BaseQuizAnswer>
</BaseQuiz>

## Pipeline 管理

### Pipeline 创建

创建和配置 Jenkins Pipeline。

```groovy
// 基本 Jenkinsfile (声明式 Pipeline)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Building application...'
                sh 'make build'
            }
        }

        stage('Test') {
            steps {
                echo 'Running tests...'
                sh 'make test'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Deploying application...'
                sh 'make deploy'
            }
        }
    }
}
```

### Pipeline 语法

常见的 Pipeline 语法和指令。

```groovy
// 脚本式 Pipeline 语法
node {
    stage('Checkout') {
        checkout scm
    }

    stage('Build') {
        sh 'make build'
    }

    stage('Test') {
        sh 'make test'
        junit 'target/test-results/*.xml'
    }
}
// 并行执行
stages {
    stage('Parallel Tests') {
        parallel {
            stage('Unit Tests') {
                steps {
                    sh 'make unit-test'
                }
            }
            stage('Integration Tests') {
                steps {
                    sh 'make integration-test'
                }
            }
        }
    }
}
```

### Pipeline 配置

高级 Pipeline 配置和选项。

```groovy
// 带有构建后操作的 Pipeline
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }

    post {
        always {
            echo 'This always runs'
        }
        success {
            echo 'Build succeeded'
        }
        failure {
            echo 'Build failed'
            emailext subject: 'Build Failed',
                     body: 'Build failed',
                     to: 'team@company.com'
        }
    }
}
```

### Pipeline 触发器

配置 Pipeline 自动触发器。

```groovy
// 带有触发器的 Pipeline
pipeline {
    agent any

    triggers {
        // 每 5 分钟轮询一次 SCM
        pollSCM('H/5 * * * *')

        // 类似 Cron 的调度
        cron('H 2 * * *')  // 每天凌晨 2 点

        // 上游任务触发
        upstream(upstreamProjects: 'upstream-job',
                threshold: hudson.model.Result.SUCCESS)
    }

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}
```

## 插件管理

### 插件安装：CLI

使用命令行界面安装插件。

```bash
# 通过 CLI 安装插件（需要重启）
java -jar jenkins-cli.jar -auth user:token install-plugin git
# 安装多个插件
java -jar jenkins-cli.jar -auth user:token install-plugin \
  git maven-plugin docker-plugin
# 从 .hpi 文件安装
java -jar jenkins-cli.jar -auth user:token install-plugin \
  /path/to/plugin.hpi
# 列出已安装的插件
java -jar jenkins-cli.jar -auth user:token list-plugins
# 使用 plugins.txt 进行安装（适用于 Docker）
# 创建 plugins.txt 文件：
git:latest
maven-plugin:latest
docker-plugin:latest
pipeline-stage-view:latest
# 使用 jenkins-plugin-cli 工具
jenkins-plugin-cli --plugins git maven-plugin docker-plugin
```

### 核心插件

用于不同目的的常用 Jenkins 插件。

```bash
# 构建和 SCM 插件
git                    # Git 集成
github                 # GitHub 集成
maven-plugin          # Maven 构建支持
gradle                # Gradle 构建支持
# Pipeline 插件
workflow-aggregator   # Pipeline 插件套件
pipeline-stage-view   # Pipeline 阶段视图
blue-ocean           # Pipeline 的现代 UI
# 部署和集成
docker-plugin        # Docker 集成
kubernetes           # Kubernetes 部署
ansible              # Ansible 自动化
# 质量和测试
junit                # JUnit 测试报告
jacoco              # 代码覆盖率
sonarqube           # 代码质量分析
```

### 插件管理 Web UI

通过 Jenkins Web 界面管理插件。

```bash
# 访问插件管理器：
# 1. 导航到 管理 Jenkins → 管理插件
# 2. 使用 可用/已安装/更新 选项卡
# 3. 搜索插件
# 4. 选择并安装
# 5. 如果需要，重启 Jenkins
# 插件更新流程：
# 1. 检查“更新”选项卡
# 2. 选择要更新的插件
# 3. 点击“现在下载并重启后安装”
```

## 用户管理与安全

### 用户管理

创建和管理 Jenkins 用户。

```bash
# 启用 Jenkins 安全性：
# 1. 管理 Jenkins → 配置全局安全
# 2. 启用“Jenkins 自己的用户数据库”
# 3. 允许用户注册（初始设置）
# 4. 设置授权策略
# 通过 CLI 创建用户（需要适当的权限）
# 用户通常通过 Web UI 创建：
# 1. 管理 Jenkins → 管理用户
# 2. 点击“创建用户”
# 3. 填写用户信息
# 4. 分配角色/权限
```

### 认证与授权

配置安全领域和授权策略。

```bash
# 安全配置选项：
# 1. 安全领域（用户如何认证）：
#    - Jenkins 自己的用户数据库
#    - LDAP
#    - Active Directory
#    - 基于矩阵的安全
#    - 基于角色的授权
# 2. 授权策略：
#    - 任何人都可以做任何事
#    - 遗留模式
#    - 已登录用户可以做任何事
#    - 基于矩阵的安全
#    - 基于项目的矩阵授权
```

### API 令牌

生成和管理用于 CLI 访问的 API 令牌。

```bash
# 生成 API 令牌：
# 1. 点击用户名 → 配置
# 2. API 令牌部分
# 3. 点击“添加新令牌”
# 4. 输入令牌名称
# 5. 生成并复制令牌
# 使用 API 令牌与 CLI
java -jar jenkins-cli.jar -auth username:api-token \
  -s http://localhost:8080 list-jobs
# 安全存储凭证
echo "username:api-token" > ~/.jenkins-cli-auth
chmod 600 ~/.jenkins-cli-auth
```

### 凭证管理

管理存储在 Jenkins 中的凭证，供任务和 Pipeline 使用。

```bash
# 通过 CLI 管理凭证
java -jar jenkins-cli.jar -auth user:token \
  list-credentials system::system::jenkins
# 创建凭证 XML 并导入
java -jar jenkins-cli.jar -auth user:token \
  create-credentials-by-xml system::system::jenkins \
  < credential.xml
```

```groovy
// 在 Pipeline 中访问凭证
withCredentials([usernamePassword(
  credentialsId: 'my-credentials',
  usernameVariable: 'USERNAME',
  passwordVariable: 'PASSWORD'
)]) {
  sh 'docker login -u $USERNAME -p $PASSWORD'
}
```

## 构建监控与故障排除

### 构建状态与日志

监控构建状态并访问详细日志。

```bash
# 检查构建状态
java -jar jenkins-cli.jar -auth user:token console my-job
# 获取构建信息
java -jar jenkins-cli.jar -auth user:token get-job my-job
# 监控构建队列
# Web UI: Jenkins 仪表板 → 构建队列
# 显示待定构建及其状态
# 构建历史访问
# Web UI: 任务 → 构建历史
# 显示所有先前构建及其状态
```

### 系统信息

获取 Jenkins 系统信息和诊断信息。

```bash
# 系统信息
java -jar jenkins-cli.jar -auth user:token version
# 节点信息
java -jar jenkins-cli.jar -auth user:token list-computers
# Groovy 控制台（仅限管理员）
# 管理 Jenkins → 脚本控制台
# 执行 Groovy 脚本以获取系统信息：
println Jenkins.instance.version
println Jenkins.instance.getRootDir()
println System.getProperty("java.version")
```

### 日志分析

访问和分析 Jenkins 系统日志。

```bash
# 系统日志位置
# Linux: /var/log/jenkins/jenkins.log
# Windows: C:\Program Files\Jenkins\jenkins.out.log
# 查看日志
tail -f /var/log/jenkins/jenkins.log
# 日志级别配置
# 管理 Jenkins → 系统日志
# 为特定组件添加新的日志记录器
# 常见日志位置：
sudo journalctl -u jenkins.service     # Systemd 日志
sudo cat /var/lib/jenkins/jenkins.log  # Jenkins 日志文件
```

### 性能监控

监控 Jenkins 性能和资源使用情况。

```bash
# 内置监控
# 管理 Jenkins → 负载统计
# 显示随时间变化的执行器利用率
# JVM 监控
# 管理 Jenkins → 管理节点 → Master
# 显示内存、CPU 使用率和系统属性
# 构建趋势
# 安装“构建历史”插件
# 查看构建持续时间趋势和成功率
# 磁盘使用情况监控
# 安装“磁盘使用情况”插件
# 监控工作区和构建产物存储
```

## Jenkins 配置与设置

### 全局配置

配置 Jenkins 全局设置和工具。

```bash
# 全局工具配置
# 管理 Jenkins → 全局工具配置
# 配置：
# - JDK 安装
# - Git 安装
# - Maven 安装
# - Docker 安装
# 系统配置
# 管理 Jenkins → 配置系统
# 设置：
# - Jenkins URL
# - 系统消息
# - 执行器数量
# - 安静期
# - SCM 轮询限制
```

### 环境变量

配置 Jenkins 环境变量和系统属性。

```bash
# 内置环境变量
BUILD_NUMBER          # 构建编号
BUILD_ID              # 构建 ID
JOB_NAME             # 任务名称
WORKSPACE            # 任务工作区路径
JENKINS_URL          # Jenkins URL
NODE_NAME            # 节点名称
# 自定义环境变量
# 管理 Jenkins → 配置系统
# 全局属性 → 环境变量
# 添加全局可用的键值对
```

### 配置即代码 (JCasC)

使用 JCasC 插件通过代码管理 Jenkins 配置。

```yaml
# JCasC 配置文件 (jenkins.yaml)
jenkins:
  systemMessage: "Jenkins configured as code"
  numExecutors: 4
  securityRealm:
    local:
      allowsSignup: false
      users:
       - id: "admin"
         password: "admin123"
# 应用配置
# 设置 CASC_JENKINS_CONFIG 环境变量
export CASC_JENKINS_CONFIG=/path/to/jenkins.yaml
```

## 最佳实践

### 安全最佳实践

保持 Jenkins 实例安全并可用于生产环境。

```bash
# 安全建议：
# 1. 启用安全和身份验证
# 2. 使用基于矩阵的授权
# 3. 定期进行安全更新
# 4. 限制用户权限
# 5. 使用 API 令牌代替密码
# 安全 Jenkins 配置：
# - 禁用通过 remoting 的 CLI
# - 使用带有有效证书的 HTTPS
# - 定期备份 JENKINS_HOME
# - 监控安全公告
# - 使用凭证插件存储敏感信息
```

### 性能优化

优化 Jenkins 以获得更好的性能和可扩展性。

```bash
# 性能优化技巧：
# 1. 使用带有代理的分布式构建
# 2. 优化构建脚本和依赖项
# 3. 自动清理旧构建
# 4. 使用 Pipeline 库实现可重用性
# 5. 监控磁盘空间和内存使用情况
# 构建优化：
# - 尽可能使用增量构建
# - 阶段并行执行
# - 产物缓存
# - 工作区清理
# - 资源分配调整
```

## 相关链接

- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/kubernetes">Kubernetes 速查表</router-link>
- <router-link to="/ansible">Ansible 速查表</router-link>
- <router-link to="/git">Git 速查表</router-link>
- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>

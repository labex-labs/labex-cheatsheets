---
title: 'Docker 速查表 | LabEx'
description: '使用本综合速查表学习 Docker 容器化技术。快速参考 Docker 命令、镜像、容器、Dockerfile、Docker Compose 和容器编排。'
pdfUrl: '/cheatsheets/pdf/docker-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Docker 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/docker">通过实践实验室学习 Docker</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Docker 容器化。LabEx 提供全面的 Docker 课程，涵盖基本的容器管理、镜像构建、Docker Compose、网络、卷和部署。掌握容器编排和现代应用程序部署技术。
</base-disclaimer-content>
</base-disclaimer>

## 安装与设置

### Linux 安装

在 Ubuntu/Debian 系统上安装 Docker。

```bash
# 更新包管理器
sudo apt update
# 安装先决条件
sudo apt install apt-transport-https ca-certificates curl
software-properties-common
# 添加 Docker 官方 GPG 密钥
curl -fsSL https://download.docker.com/linux/ubuntu/gpg
| sudo apt-key add -
# 添加 Docker 仓库
sudo add-apt-repository "deb [arch=amd64]
https://download.docker.com/linux/ubuntu bionic stable"
# 安装 Docker
sudo apt update && sudo apt install docker-ce
# 启动 Docker 服务
sudo systemctl start docker
sudo systemctl enable docker
```

### Windows 和 macOS

安装 Docker Desktop 以进行基于 GUI 的管理。

```bash
# Windows: 从 docker.com 下载 Docker Desktop
# macOS: 使用 Homebrew 或从 docker.com 下载
brew install --cask docker
# 或直接从以下地址下载：
# https://www.docker.com/products/docker-desktop
```

### 安装后设置

配置 Docker 以供非 root 用户使用并验证安装。

```bash
# 将用户添加到 docker 组 (Linux)
sudo usermod -aG docker $USER
# 登出并重新登录以使组更改生效
# 验证 Docker 安装
docker --version
docker run hello-world
```

### Docker Compose 安装

安装 Docker Compose 以用于多容器应用程序。

```bash
# Linux: 通过 curl 安装
sudo curl -L
"https://github.com/docker/compose/releases/download
/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o
/usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
# 验证安装
docker-compose --version
# 注意：Docker Desktop 包含 Compose
```

## 基础 Docker 命令

### 系统信息：`docker version` / `docker system info`

检查 Docker 安装和环境详情。

```bash
# 显示 Docker 版本信息
docker version
# 显示系统范围的 Docker
信息
docker system info
# 显示 Docker 命令的帮助信息
docker help
docker <command> --help
```

### 运行容器：`docker run`

从镜像创建并启动一个容器。

```bash
# 交互式运行一个容器
docker run -it ubuntu:latest bash
# 在后台运行容器
(分离模式)
docker run -d --name my-container
nginx
# 运行并映射端口
docker run -p 8080:80 nginx
# 运行后自动移除容器
docker run --rm hello-world
```

<BaseQuiz id="docker-run-1" correct="C">
  <template #question>
    `docker run -d` 的作用是什么？
  </template>
  
  <BaseQuizOption value="A">以调试模式运行容器</BaseQuizOption>
  <BaseQuizOption value="B">容器停止后删除它</BaseQuizOption>
  <BaseQuizOption value="C" correct>以分离模式（后台）运行容器</BaseQuizOption>
  <BaseQuizOption value="D">以默认设置运行容器</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-d` 标志以分离模式运行容器，意味着它在后台运行并立即将控制权返回给终端。这对于长期运行的服务很有用。
  </BaseQuizAnswer>
</BaseQuiz>

### 列出容器：`docker ps`

查看正在运行和已停止的容器。

```bash
# 列出正在运行的容器
docker ps
# 列出所有容器（包括
已停止的）
docker ps -a
# 仅列出容器 ID
docker ps -q
# 显示最近创建的容器
docker ps -l
```

## 容器管理

### 容器生命周期：`start` / `stop` / `restart`

控制容器的执行状态。

```bash
# 停止一个正在运行的容器
docker stop container_name
# 启动一个已停止的容器
docker start container_name
# 重启一个容器
docker restart container_name
# 暂停/取消暂停容器进程
docker pause container_name
docker unpause container_name
```

### 执行命令：`docker exec`

在正在运行的容器内执行命令。

```bash
# 执行交互式 bash shell
docker exec -it container_name bash
# 执行单个命令
docker exec container_name ls -la
# 以不同用户执行
docker exec -u root container_name whoami
# 在特定目录下执行
docker exec -w /app container_name pwd
```

### 容器移除：`docker rm`

从系统中移除容器。

```bash
# 移除一个已停止的容器
docker rm container_name
# 强制移除一个正在运行的容器
docker rm -f container_name
# 移除多个容器
docker rm container1 container2
# 移除所有已停止的容器
docker container prune
```

### 容器日志：`docker logs`

查看容器输出并调试问题。

```bash
# 查看容器日志
docker logs container_name
# 实时跟踪日志
docker logs -f container_name
# 仅显示最近的日志
docker logs --tail 50 container_name
# 显示带时间戳的日志
docker logs -t container_name
```

## 镜像管理

### 构建镜像：`docker build`

从 Dockerfile 创建 Docker 镜像。

```bash
# 从当前目录构建镜像
docker build .
# 构建并标记镜像
docker build -t myapp:latest .
# 使用构建参数构建
docker build --build-arg VERSION=1.0 -t myapp .
# 不使用缓存构建
docker build --no-cache -t myapp .
```

<BaseQuiz id="docker-build-1" correct="A">
  <template #question>
    `docker build -t myapp:latest .` 的作用是什么？
  </template>
  
  <BaseQuizOption value="A" correct>从当前目录构建一个标记为 "myapp:latest" 的 Docker 镜像</BaseQuizOption>
  <BaseQuizOption value="B">运行一个名为 "myapp" 的容器</BaseQuizOption>
  <BaseQuizOption value="C">从 Docker Hub 拉取 "myapp:latest" 镜像</BaseQuizOption>
  <BaseQuizOption value="D">删除 "myapp:latest" 镜像</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-t` 标志将镜像标记为 "myapp:latest"，而 `.` 指定了构建上下文（当前目录）。此命令从当前目录中的 Dockerfile 构建一个新镜像。
  </BaseQuizAnswer>
</BaseQuiz>

### 镜像检查：`docker images` / `docker inspect`

列出和检查 Docker 镜像。

```bash
# 列出所有本地镜像
docker images
# 使用特定过滤器列出镜像
docker images nginx
# 显示镜像详情
docker inspect image_name
# 查看镜像构建历史
docker history image_name
```

### 仓库操作：`docker pull` / `docker push`

下载和上传镜像到仓库。

```bash
# 从 Docker Hub 拉取镜像
docker pull nginx:latest
# 拉取特定版本
docker pull ubuntu:20.04
# 推送镜像到仓库
docker push myusername/myapp:latest
# 推送前标记镜像
docker tag myapp:latest myusername/myapp:v1.0
```

### 镜像清理：`docker rmi` / `docker image prune`

移除未使用的镜像以释放磁盘空间。

```bash
# 移除特定镜像
docker rmi image_name
# 移除未使用的镜像
docker image prune
# 移除所有未使用的镜像（不只是悬空镜像）
docker image prune -a
# 强制移除镜像
docker rmi -f image_name
```

## Dockerfile 基础

### 核心指令

构建镜像所需的核心 Dockerfile 命令。

```dockerfile
# 基础镜像
FROM ubuntu:20.04
# 设置维护者信息
LABEL maintainer="user@example.com"
# 安装包
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# 从宿主机复制文件到容器
COPY app.py /app/
# 设置工作目录
WORKDIR /app
# 暴露端口
EXPOSE 8000
```

<BaseQuiz id="dockerfile-1" correct="B">
  <template #question>
    Dockerfile 中 `FROM` 指令的目的是什么？
  </template>
  
  <BaseQuizOption value="A">它将文件从宿主机复制到容器</BaseQuizOption>
  <BaseQuizOption value="B" correct>它指定了构建所基于的基础镜像</BaseQuizOption>
  <BaseQuizOption value="C">它设置了环境变量</BaseQuizOption>
  <BaseQuizOption value="D">它定义了容器启动时运行的命令</BaseQuizOption>
  
  <BaseQuizAnswer>
    `FROM` 指令必须是 Dockerfile 中第一个非注释指令。它指定了你的镜像将构建在其之上的基础镜像，为容器提供了基础。
  </BaseQuizAnswer>
</BaseQuiz>

### 运行时配置

配置容器的运行方式。

```dockerfile
# 设置环境变量
ENV PYTHON_ENV=production
ENV PORT=8000
# 创建用户以保证安全
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# 定义启动命令
CMD ["python3", "app.py"]
# 或者使用 ENTRYPOINT 来固定命令
ENTRYPOINT ["python3"]
CMD ["app.py"]
# 设置健康检查
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/ || exit 1
```

## Docker Compose

### 基础 Compose 命令：`docker-compose up` / `docker-compose down`

启动和停止多容器应用程序。

```bash
# 前台启动服务
docker-compose up
# 后台启动服务
docker-compose up -d
# 构建并启动服务
docker-compose up --build
# 停止并移除服务
docker-compose down
# 停止并移除（包括卷）
docker-compose down -v
```

<BaseQuiz id="docker-compose-1" correct="D">
  <template #question>
    `docker-compose up -d` 的作用是什么？
  </template>
  
  <BaseQuizOption value="A">停止所有正在运行的容器</BaseQuizOption>
  <BaseQuizOption value="B">构建镜像但不启动容器</BaseQuizOption>
  <BaseQuizOption value="C">显示所有服务的日志</BaseQuizOption>
  <BaseQuizOption value="D" correct>以分离模式（后台）启动 docker-compose.yml 中定义的所有服务</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-d` 标志以分离模式（后台）运行容器。`docker-compose up` 读取 docker-compose.yml 文件并启动所有定义的服务，便于管理多容器应用程序。
  </BaseQuizAnswer>
</BaseQuiz>

### 服务管理

控制 Compose 应用程序中的单个服务。

```bash
# 列出正在运行的服务
docker-compose ps
# 查看服务日志
docker-compose logs service_name
# 跟踪所有服务的日志
docker-compose logs -f
# 重启特定服务
docker-compose restart service_name
```

### 示例 docker-compose.yml

多服务应用程序配置示例。

```yaml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      -
DATABASE_URL=postgresql://user:pass@db:5432/myapp
    depends_on:
      - db
    volumes:
      - .:/app

  db:
    image: postgres:13
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - db_data:/var/lib/postgresql/data
volumes:
  db_data:
```

## 网络和卷

### 容器网络

连接容器并暴露服务。

```bash
# 列出网络
docker network ls
# 创建一个自定义网络
docker network create mynetwork
# 在特定网络上运行容器
docker run --network mynetwork nginx
# 将正在运行的容器连接到网络
docker network connect mynetwork container_name
# 检查网络详情
docker network inspect mynetwork
```

### 端口映射

将容器端口暴露给宿主机系统。

```bash
# 映射单个端口
docker run -p 8080:80 nginx
```

<BaseQuiz id="docker-port-1" correct="A">
  <template #question>
    在 `docker run -p 8080:80 nginx` 中，端口号的含义是什么？
  </template>
  
  <BaseQuizOption value="A" correct>8080 是宿主机端口，80 是容器端口</BaseQuizOption>
  <BaseQuizOption value="B">80 是宿主机端口，8080 是容器端口</BaseQuizOption>
  <BaseQuizOption value="C">两个端口都是容器端口</BaseQuizOption>
  <BaseQuizOption value="D">两个端口都是宿主机端口</BaseQuizOption>
  
  <BaseQuizAnswer>
    格式是 `-p host_port:container_port`。宿主机上的 8080 端口映射到容器内的 80 端口，允许你通过 localhost:8080 访问容器中运行的 nginx Web 服务器。
  </BaseQuizAnswer>
</BaseQuiz>

```bash
# 映射多个端口
docker run -p 8080:80 -p 8443:443 nginx
# 映射到特定宿主机接口
docker run -p 127.0.0.1:8080:80 nginx
# 暴露镜像中定义的所有端口
docker run -P nginx
```

### 数据卷：`docker volume`

在容器之间持久化和共享数据。

```bash
# 创建一个命名卷
docker volume create myvolume
# 列出所有卷
docker volume ls
# 检查卷详情
docker volume inspect myvolume
# 移除卷
docker volume rm myvolume
# 移除未使用的卷
docker volume prune
```

### 卷挂载

在容器中挂载卷和宿主机目录。

```bash
# 挂载命名卷
docker run -v myvolume:/data nginx
# 挂载宿主机目录（绑定挂载）
docker run -v /host/path:/container/path nginx
# 挂载当前目录
docker run -v $(pwd):/app nginx
# 只读挂载
docker run -v /host/path:/container/path:ro nginx
```

## 容器检查与调试

### 容器详情：`docker inspect`

获取有关容器和镜像的详细信息。

```bash
# 检查容器配置
docker inspect container_name
# 使用 format 获取特定信息
docker inspect --format='{{.State.Status}}'
container_name
# 获取 IP 地址
docker inspect --format='{{.NetworkSettings.IPAddress}}'
container_name
# 获取挂载的卷
docker inspect --format='{{.Mounts}}' container_name
```

### 资源监控

监控容器的资源使用情况和性能。

```bash
# 查看容器中正在运行的进程
docker top container_name
# 显示实时资源使用统计信息
docker stats
# 查看特定容器的统计信息
docker stats container_name
# 实时监控事件
docker events
```

### 文件操作：`docker cp`

在容器和宿主机系统之间复制文件。

```bash
# 从容器复制文件到宿主机
docker cp container_name:/path/to/file ./
# 从宿主机复制文件到容器
docker cp ./file container_name:/path/to/destination
# 复制目录
docker cp ./directory
container_name:/path/to/destination/
# 使用归档模式复制以保留权限
docker cp -a ./directory container_name:/path/
```

### 故障排除

调试容器问题和连接问题。

```bash
# 检查容器退出代码
docker inspect --format='{{.State.ExitCode}}'
container_name
# 查看容器进程
docker exec container_name ps aux
# 测试网络连接
docker exec container_name ping google.com
# 检查磁盘使用情况
docker exec container_name df -h
```

## 仓库与认证

### Docker Hub 操作：`docker login` / `docker search`

认证并与 Docker Hub 交互。

```bash
# 登录 Docker Hub
docker login
# 登录到特定仓库
docker login registry.example.com
# 在 Docker Hub 上搜索镜像
docker search nginx
# 带过滤条件的搜索
docker search --filter stars=100 nginx
```

### 镜像标记与发布

准备并将镜像发布到仓库。

```bash
# 标记镜像以供仓库使用
docker tag myapp:latest username/myapp:v1.0
docker tag myapp:latest
registry.example.com/myapp:latest
# 推送到 Docker Hub
docker push username/myapp:v1.0
# 推送到私有仓库
docker push registry.example.com/myapp:latest
```

### 私有仓库

使用私有 Docker 仓库。

```bash
# 从私有仓库拉取
docker pull registry.company.com/myapp:latest
# 在本地运行私有仓库
docker run -d -p 5000:5000 --name registry registry:2
# 推送到本地仓库
docker tag myapp localhost:5000/myapp
docker push localhost:5000/myapp
```

### 镜像安全

验证镜像的完整性和安全性。

```bash
# 启用 Docker 内容信任
export DOCKER_CONTENT_TRUST=1
# 签名并推送镜像
docker push username/myapp:signed
# 检查镜像签名
docker trust inspect username/myapp:signed
# 扫描镜像漏洞
docker scan myapp:latest
```

## 系统清理与维护

### 系统清理：`docker system prune`

移除未使用的 Docker 资源以释放磁盘空间。

```bash
# 移除未使用的容器、网络、镜像
docker system prune
# 包含未使用的卷进行清理
docker system prune -a --volumes
# 移除所有内容（谨慎使用）
docker system prune -a -f
# 显示空间使用情况
docker system df
```

### 目标清理

移除特定类型的未使用的资源。

```bash
# 移除已停止的容器
docker container prune
# 移除未使用的镜像
docker image prune -a
# 移除未使用的卷
docker volume prune
# 移除未使用的网络
docker network prune
```

### 批量操作

对多个容器/镜像执行操作。

```bash
# 停止所有正在运行的容器
docker stop $(docker ps -q)
# 移除所有容器
docker rm $(docker ps -aq)
# 移除所有镜像
docker rmi $(docker images -q)
# 仅移除悬空镜像
docker rmi $(docker images -f "dangling=true" -q)
```

### 资源限制

控制容器的资源消耗。

```bash
# 限制内存使用
docker run --memory=512m nginx
# 限制 CPU 使用
docker run --cpus="1.5" nginx
# 限制 CPU 和内存
docker run --memory=1g --cpus="2.0" nginx
# 设置重启策略
docker run --restart=always nginx
```

## Docker 配置与设置

### 守护进程配置

为生产环境配置 Docker 守护进程。

```bash
# 编辑守护进程配置文件
sudo nano
/etc/docker/daemon.json
# 示例配置：
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
# 重启 Docker 服务
sudo systemctl restart docker
```

### 环境变量

使用环境变量配置 Docker 客户端行为。

```bash
# 设置 Docker 主机
export
DOCKER_HOST=tcp://remote-
docker:2376
# 启用 TLS 验证
export DOCKER_TLS_VERIFY=1
export
DOCKER_CERT_PATH=/path/to/c
erts
# 设置默认仓库
export
DOCKER_REGISTRY=registry.co
mpany.com
# 调试输出
export DOCKER_BUILDKIT=1
```

### 性能调优

优化 Docker 以获得更好的性能。

```bash
# 启用实验性功能
echo '{"experimental": true}' |
sudo tee
/etc/docker/daemon.json
# 配置存储驱动选项
{
  "storage-driver": "overlay2",
  "storage-opts": [

"overlay2.override_kernel_check
=true"
  ]
}
# 配置日志
{
  "log-driver": "syslog",
  "log-opts": {"syslog-address":
"udp://logs.company.com:514"}
}
```

## 最佳实践

### 安全最佳实践

保持容器安全并为生产做好准备。

```dockerfile
# 在 Dockerfile 中以非 root 用户运行
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# 使用特定的镜像标签，而不是 'latest'
FROM node:16.20.0-alpine
# 尽可能使用只读文件系统
docker run --read-only nginx
```

### 性能优化

优化容器以提高速度和资源效率。

```dockerfile
# 使用多阶段构建来减小镜像大小
FROM node:16 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
FROM node:16-alpine
WORKDIR /app
COPY --from=builder /app/node_modules
./node_modules
COPY . .
CMD ["node", "server.js"]
```

## 相关链接

- <router-link to="/kubernetes">Kubernetes 速查表</router-link>
- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/ansible">Ansible 速查表</router-link>
- <router-link to="/git">Git 速查表</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>

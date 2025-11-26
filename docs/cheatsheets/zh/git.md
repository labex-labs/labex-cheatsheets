---
title: 'Git 速查表'
description: '使用我们涵盖基本命令、概念和最佳实践的综合 Git 速查表来学习 Git。'
pdfUrl: '/cheatsheets/pdf/git-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Git 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/git">通过实践实验室学习 Git</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Git 版本控制。LabEx 提供全面的 Git 课程，涵盖基本命令、分支策略、协作工作流程和高级技术。学习如何使用 Git 和 GitHub 管理代码仓库、解决冲突以及与团队有效协作。
</base-disclaimer-content>
</base-disclaimer>

## 仓库设置与配置

### 初始化仓库：`git init`

在当前目录中创建一个新的 Git 仓库。

```bash
# 初始化新仓库
git init
# 在新目录中初始化
git init project-name
# 初始化裸仓库（无工作目录）
git init --bare
# 使用自定义模板目录
git init --template=path
```

### 克隆仓库：`git clone`

创建远程仓库的本地副本。

```bash
# 通过 HTTPS 克隆
git clone https://github.com/user/repo.git
# 通过 SSH 克隆
git clone git@github.com:user/repo.git
# 使用自定义名称克隆
git clone repo.git local-name
# 浅克隆（仅最新提交）
git clone --depth 1 repo.git
```

### 全局配置：`git config`

全局设置用户信息和偏好。

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# 查看所有配置设置
git config --list
```

### 本地配置：`git config --local`

设置特定于仓库的配置。

```bash
# 仅为当前仓库设置
git config user.name "Project Name"
# 项目特定的电子邮件
git config user.email "project@example.com"
```

### 远程管理：`git remote`

管理到远程仓库的连接。

```bash
# 添加远程仓库
git remote add origin https://github.com/user/repo.git
# 列出所有远程仓库及其 URL
git remote -v
# 显示详细的远程信息
git remote show origin
# 重命名远程仓库
git remote rename origin upstream
# 移除远程仓库
git remote remove upstream
```

### 凭证存储：`git config credential`

存储身份验证凭证以避免重复登录。

```bash
# 缓存 15 分钟
git config --global credential.helper cache
# 永久存储
git config --global credential.helper store
# 缓存 1 小时
git config --global credential.helper 'cache --timeout=3600'
```

## 仓库信息与状态

### 检查状态：`git status`

显示工作目录和暂存区的当前状态。

```bash
# 完整状态信息
git status
# 简短状态格式
git status -s
# 机器可读格式
git status --porcelain
# 也显示忽略的文件
git status --ignored
```

### 查看差异：`git diff`

显示仓库不同状态之间的更改。

```bash
# 工作目录与暂存区的更改
git diff
# 暂存区与上一次提交的更改
git diff --staged
# 所有未提交的更改
git diff HEAD
# 特定文件的更改
git diff file.txt
```

### 查看历史：`git log`

显示提交历史和仓库时间线。

```bash
# 完整提交历史
git log
# 简洁的单行格式
git log --oneline
# 显示最后 5 次提交
git log -5
# 可视化分支图
git log --graph --all
```

## 暂存与提交更改

### 暂存文件：`git add`

将更改添加到暂存区以供下次提交。

```bash
# 暂存特定文件
git add file.txt
# 暂存当前目录中的所有更改
git add .
# 暂存所有更改（包括删除）
git add -A
# 暂存所有 JavaScript 文件
git add *.js
# 交互式暂存（补丁模式）
git add -p
```

### 提交更改：`git commit`

使用描述性消息将暂存的更改保存到仓库。

```bash
# 带消息提交
git commit -m "Add user authentication"
# 暂存并提交修改过的文件
git commit -a -m "Update docs"
# 修改上一次提交
git commit --amend
# 不修改消息地修改上一次提交
git commit --no-edit --amend
```

### 取消暂存文件：`git reset`

从暂存区移除文件或撤销提交。

```bash
# 取消暂存特定文件
git reset file.txt
# 取消暂存所有文件
git reset
# 撤销上一次提交，保留更改在暂存区
git reset --soft HEAD~1
# 撤销上一次提交，丢弃更改
git reset --hard HEAD~1
```

### 丢弃更改：`git checkout` / `git restore`

将工作目录中的更改恢复到上一次提交的状态。

```bash
# 丢弃文件中的更改（旧语法）
git checkout -- file.txt
# 丢弃文件中的更改（新语法）
git restore file.txt
# 取消暂存文件（新语法）
git restore --staged file.txt
# 丢弃所有未提交的更改
git checkout .
```

## 分支操作

### 列出分支：`git branch`

查看和管理仓库分支。

```bash
# 列出本地分支
git branch
# 列出所有分支（本地和远程）
git branch -a
# 仅列出远程分支
git branch -r
# 显示每个分支上的最后一次提交
git branch -v
```

### 创建与切换：`git checkout` / `git switch`

创建新分支并在它们之间切换。

```bash
# 创建并切换到新分支
git checkout -b feature-branch
# 创建并切换（新语法）
git switch -c feature-branch
# 切换到现有分支
git checkout main
# 切换到现有分支（新语法）
git switch main
```

### 合并分支：`git merge`

合并来自不同分支的更改。

```bash
# 将 feature-branch 合并到当前分支
git merge feature-branch
# 强制合并提交
git merge --no-ff feature-branch
# 在合并前压缩提交
git merge --squash feature-branch
```

### 删除分支：`git branch -d`

删除不再需要的分支。

```bash
# 删除已合并的分支
git branch -d feature-branch
# 强制删除未合并的分支
git branch -D feature-branch
# 删除远程分支
git push origin --delete feature-branch
```

## 远程仓库操作

### 获取更新：`git fetch`

从远程仓库下载更改，但不合并。

```bash
# 从默认远程仓库获取
git fetch
# 从特定远程仓库获取
git fetch origin
# 从所有远程仓库获取
git fetch --all
# 获取特定分支
git fetch origin main
```

### 拉取更改：`git pull`

从远程仓库下载并合并更改。

```bash
# 从跟踪分支拉取
git pull
# 从特定远程分支拉取
git pull origin main
# 使用 rebase 而非 merge 拉取
git pull --rebase
# 仅快进，不产生合并提交
git pull --ff-only
```

### 推送更改：`git push`

将本地提交上传到远程仓库。

```bash
# 推送到跟踪分支
git push
# 推送到特定远程分支
git push origin main
# 推送并设置上游跟踪
git push -u origin feature
# 安全地强制推送
git push --force-with-lease
```

### 跟踪远程分支：`git branch --track`

设置本地分支与远程分支之间的跟踪关系。

```bash
# 设置跟踪
git branch --set-upstream-to=origin/main main
# 跟踪远程分支
git checkout -b local-branch origin/remote-branch
```

## 暂存与临时存储

### 暂存更改：`git stash`

临时保存未提交的更改以供以后使用。

```bash
# 暂存当前更改
git stash
# 带消息暂存
git stash save "Work in progress on feature X"
# 包含未跟踪的文件
git stash -u
# 仅暂存未暂存的更改
git stash --keep-index
```

### 列出暂存：`git stash list`

查看所有保存的暂存。

```bash
# 显示所有暂存
git stash list
# 显示最新暂存的更改
git stash show
# 显示特定暂存的更改
git stash show stash@{1}
```

### 应用暂存：`git stash apply`

恢复先前暂存的更改。

```bash
# 应用最新暂存
git stash apply
# 应用特定暂存
git stash apply stash@{1}
# 应用最新暂存并移除它
git stash pop
# 删除最新暂存
git stash drop
# 从暂存创建分支
git stash branch new-branch stash@{1}
# 删除所有暂存
git stash clear
```

## 历史与日志分析

### 查看提交历史：`git log`

使用各种格式选项探索仓库历史。

```bash
# 可视化分支历史
git log --oneline --graph --all
# 特定作者的提交
git log --author="John Doe"
# 最近的提交
git log --since="2 weeks ago"
# 搜索提交消息
git log --grep="bug fix"
```

### 追溯与注释：`git blame`

查看文件中每一行的最后修改者。

```bash
# 显示逐行作者信息
git blame file.txt
# 注释特定行
git blame -L 10,20 file.txt
# Blame 的替代方案
git annotate file.txt
```

### 搜索仓库：`git grep`

在仓库历史中搜索文本模式。

```bash
# 搜索跟踪文件中的文本
git grep "function"
# 带行号搜索
git grep -n "TODO"
# 搜索暂存区中的内容
git grep --cached "bug"
```

### 显示提交详情：`git show`

显示特定提交的详细信息。

```bash
# 显示最新提交详情
git show
# 显示前一次提交
git show HEAD~1
# 显示特定提交（通过哈希值）
git show abc123
# 显示提交及文件统计信息
git show --stat
```

## 撤销更改与编辑历史

### 撤销提交：`git revert`

创建新的提交来安全地撤销先前的更改。

```bash
# 撤销最新提交
git revert HEAD
# 撤销特定提交
git revert abc123
# 撤销提交范围
git revert HEAD~3..HEAD
# 撤销但不自动提交
git revert --no-commit abc123
```

### 重置历史：`git reset`

移动分支指针，并可选地修改工作目录。

```bash
# 撤销提交，保留更改在暂存区
git reset --soft HEAD~1
# 撤销提交和暂存
git reset --mixed HEAD~1
# 撤销提交、暂存和工作目录
git reset --hard HEAD~1
```

### 交互式 Rebase: `git rebase -i`

交互式地编辑、重新排序或压缩提交。

```bash
# 交互式 rebase 最后 3 次提交
git rebase -i HEAD~3
# 将当前分支 rebase 到 main 上
git rebase -i main
# 解决冲突后继续
git rebase --continue
# 取消 rebase 操作
git rebase --abort
```

### 挑选提交：`git cherry-pick`

将其他分支上的特定提交应用到当前分支。

```bash
# 将特定提交应用到当前分支
git cherry-pick abc123
# 应用提交范围
git cherry-pick abc123..def456
# 不提交地进行 cherry-pick
git cherry-pick -n abc123
```

## 冲突解决

### 合并冲突：解决流程

合并操作期间解决冲突的步骤。

```bash
# 检查冲突文件
git status
# 标记冲突已解决
git add resolved-file.txt
# 完成合并
git commit
# 取消合并并返回到先前状态
git merge --abort
```

### 合并工具：`git mergetool`

启动外部工具以通过可视化方式帮助解决冲突。

```bash
# 启动默认合并工具
git mergetool
# 设置默认合并工具
git config --global merge.tool vimdiff
# 本次合并使用特定工具
git mergetool --tool=meld
```

### 冲突标记：理解格式

解释 Git 在文件中使用的冲突标记。

```text
<<<<<<< HEAD
当前分支内容
=======
传入分支内容
>>>>>>> feature-branch
```

解决后编辑文件：

```bash
git add conflicted-file.txt
git commit
```

### Diff 工具：`git difftool`

使用外部 diff 工具更好地可视化冲突。

```bash
# 启动 diff 工具查看更改
git difftool
# 设置默认 diff 工具
git config --global diff.tool vimdiff
```

## 标记与发布

### 创建标签：`git tag`

使用版本标签标记特定提交。

```bash
# 创建轻量级标签
git tag v1.0
# 创建带注释的标签
git tag -a v1.0 -m "Version 1.0 release"
# 标记特定提交
git tag -a v1.0 abc123
# 创建签名标签
git tag -s v1.0
```

### 列出和显示标签：`git tag -l`

查看现有标签及其信息。

```bash
# 列出所有标签
git tag
# 列出匹配模式的标签
git tag -l "v1.*"
# 显示标签详情
git show v1.0
```

### 推送标签：`git push --tags`

将标签共享到远程仓库。

```bash
# 推送特定标签
git push origin v1.0
# 推送所有标签
git push --tags
# 推送到特定远程仓库的所有标签
git push origin --tags
```

### 删除标签：`git tag -d`

从本地和远程仓库中删除标签。

```bash
# 删除本地标签
git tag -d v1.0
# 删除远程标签
git push origin --delete tag v1.0
# 替代删除语法
git push origin :refs/tags/v1.0
```

## Git 配置与别名

### 查看配置：`git config --list`

显示当前的 Git 配置设置。

```bash
# 显示所有配置设置
git config --list
# 仅显示全局设置
git config --global --list
# 仅显示特定于仓库的设置
git config --local --list
# 显示特定设置
git config user.name
```

### 创建别名：`git config alias`

为常用命令设置快捷方式。

```bash
# git st = git status
git config --global alias.st status
# git co = git checkout
git config --global alias.co checkout
# git br = git branch
git config --global alias.br branch
# git ci = git commit
git config --global alias.ci commit
```

### 高级别名：复杂命令

创建用于复杂命令组合的别名。

```bash
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.unstage "reset HEAD --"
git config --global alias.last "log -1 HEAD"
git config --global alias.visual "!gitk"
```

### 编辑器配置：`git config core.editor`

设置用于提交消息和冲突的文本编辑器。

```bash
# VS Code
git config --global core.editor "code --wait"
# Vim
git config --global core.editor "vim"
# Nano
git config --global core.editor "nano"
```

## 性能与优化

### 仓库维护：`git gc`

优化仓库性能和存储。

```bash
# 标准垃圾回收
git gc
# 更彻底的优化
git gc --aggressive
# 仅在需要时运行
git gc --auto
# 检查仓库完整性
git fsck
```

### 大文件处理：`git lfs`

使用 Git LFS 有效管理大型二进制文件。

```bash
# 在仓库中安装 LFS
git lfs install
# 使用 LFS 跟踪 PDF 文件
git lfs track "*.pdf"
# 列出 LFS 跟踪的文件
git lfs ls-files
# 迁移现有文件
git lfs migrate import --include="*.zip"
```

### 浅克隆：减小仓库大小

使用有限的历史记录克隆仓库以加快操作。

```bash
# 仅最新提交
git clone --depth 1 https://github.com/user/repo.git
# 最后 10 次提交
git clone --depth 10 repo.git
# 将浅层克隆转换为完整克隆
git fetch --unshallow
```

### 稀疏检出：处理子目录

仅检出大型仓库的特定部分。

```bash
git config core.sparseCheckout true
echo "src/*" > .git/info/sparse-checkout
# 应用稀疏检出
git read-tree -m -u HEAD
```

## Git 安装与设置

### 包管理器：`apt`, `yum`, `brew`

使用系统包管理器安装 Git。

```bash
# Ubuntu/Debian
sudo apt install git
# CentOS/RHEL
sudo yum install git
# macOS with Homebrew
brew install git
# Windows with winget
winget install Git.Git
```

### 下载与安装：官方安装程序

使用官方安装程序安装您的平台上的 Git。

```bash
# 从 https://git-scm.com/downloads 下载
# 验证安装
git --version
# 显示 Git 可执行文件路径
which git
```

### 首次设置：用户配置

使用您的身份配置 Git 以进行提交。

```bash
git config --global user.name "Your Full Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# 设置合并行为
git config --global pull.rebase false
```

## Git 工作流程与最佳实践

### 功能分支工作流

使用隔离分支进行功能开发。

```bash
# 从 main 分支开始
git checkout main
# 获取最新更改
git pull origin main
# 创建功能分支
git checkout -b feature/user-auth
# ... 进行更改并提交 ...
# 推送功能分支
git push -u origin feature/user-auth
# ... 创建 pull request ...
```

### Git Flow: 结构化分支模型

用于不同目的的专用分支的系统化方法。

```bash
# 初始化 Git Flow
git flow init
# 开始功能分支
git flow feature start new-feature
# 完成功能分支
git flow feature finish new-feature
# 开始发布分支
git flow release start 1.0.0
```

### 提交消息约定

遵循约定提交格式以保持清晰的项目历史。

```bash
# 格式: <类型>(<范围>): <主题>
git commit -m "feat(auth): add user login functionality"
git commit -m "fix(api): resolve null pointer exception"
git commit -m "docs(readme): update installation instructions"
git commit -m "refactor(utils): simplify date formatting"
```

### 原子提交：最佳实践

创建专注的、单一目的的提交，以获得更好的历史记录。

```bash
# 交互式暂存更改
git add -p
# 特定更改
git commit -m "Add validation to email field"
# 避免: git commit -m "Fix stuff" # 太模糊
# 好的:  git commit -m "Fix email validation regex pattern"
```

## 故障排除与恢复

### Reflog: 恢复工具

使用 Git 的引用日志来恢复丢失的提交。

```bash
# 显示引用日志
git reflog
# 显示 HEAD 移动记录
git reflog show HEAD
# 恢复丢失的提交
git checkout abc123
# 从丢失的提交创建分支
git branch recovery-branch abc123
```

### 仓库损坏：修复

修复仓库损坏和完整性问题。

```bash
# 检查仓库完整性
git fsck --full
# 积极清理
git gc --aggressive --prune=now
# 如果索引损坏，则重建
rm .git/index; git reset
```

### 身份验证问题

解决常见的身份验证和权限问题。

```bash
# 使用令牌
git remote set-url origin https://token@github.com/user/repo.git
# 将 SSH 密钥添加到代理
ssh-add ~/.ssh/id_rsa
# Windows 凭证管理器
git config --global credential.helper manager-core
```

### 性能问题：调试

识别并解决仓库性能问题。

```bash
# 显示仓库大小
git count-objects -vH
# 计算总提交数
git log --oneline | wc -l
# 计算分支数
git for-each-ref --format='%(refname:short)' | wc -l
```

## 相关链接

- <router-link to="/linux">Linux 速查表</router-link>
- <router-link to="/shell">Shell 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/kubernetes">Kubernetes 速查表</router-link>
- <router-link to="/ansible">Ansible 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>

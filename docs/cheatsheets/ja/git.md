---
title: 'Git チートシート | LabEx'
description: 'この包括的なチートシートで Git バージョン管理を習得しましょう。Git コマンド、ブランチ、マージ、リベース、GitHub ワークフロー、共同開発のためのクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/git-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Git チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/git">ハンズオンラボで Git を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、Git バージョン管理を学びます。LabEx は、必須コマンド、ブランチ戦略、コラボレーションワークフロー、高度なテクニックを網羅した包括的な Git コースを提供します。Git と GitHub を使用して、コードリポジトリの管理、競合の解決、チームとの効果的な作業方法を習得します。
</base-disclaimer-content>
</base-disclaimer>

## リポジトリのセットアップと設定

### リポジトリの初期化：`git init`

現在のディレクトリに新しい Git リポジトリを作成します。

```bash
# 新しいリポジトリを初期化
git init
# 新しいディレクトリで初期化
git init project-name
# ベア（bare）リポジトリを初期化（作業ディレクトリなし）
git init --bare
# カスタムテンプレートディレクトリを使用
git init --template=path
```

### リポジトリのクローン：`git clone`

リモートリポジトリのローカルコピーを作成します。

```bash
# HTTPS 経由でクローン
git clone https://github.com/user/repo.git
# SSH 経由でクローン
git clone git@github.com:user/repo.git
# カスタム名でクローン
git clone repo.git local-name
# シャロークローン（最新コミットのみ）
git clone --depth 1 repo.git
```

### グローバル設定：`git config`

ユーザー情報と環境設定をグローバルに設定します。

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# すべての設定を表示
git config --list
```

### ローカル設定：`git config --local`

リポジトリ固有の設定を行います。

```bash
# 現在のリポジトリのみに設定
git config user.name "Project Name"
# プロジェクト固有のメールアドレス
git config user.email "project@example.com"
```

### リモート管理：`git remote`

リモートリポジトリへの接続を管理します。

```bash
# リモートの追加
git remote add origin https://github.com/user/repo.git
# URL を含むすべて のリモートを一覧表示
git remote -v
# リモートの詳細情報を表示
git remote show origin
# リモート名の変更
git remote rename origin upstream
# リモートの削除
git remote remove upstream
```

### クレデンシャルストレージ：`git config credential`

認証情報を保存し、繰り返しログインするのを防ぎます。

```bash
# 15 分間キャッシュ
git config --global credential.helper cache
# 永続的に保存
git config --global credential.helper store
# 1 時間キャッシュ
git config --global credential.helper 'cache --timeout=3600'
```

## リポジトリ情報の確認とステータス

### ステータスの確認：`git status`

作業ディレクトリとステージングエリアの現在の状態を表示します。

```bash
# 完全なステータス情報
git status
# 短いステータス形式
git status -s
# 機械可読形式
git status --porcelain
# 追跡されていないファイルも表示
git status --ignored
```

### 差分の表示：`git diff`

リポジトリの異なる状態間の変更を表示します。

```bash
# 作業ディレクトリとステージングエリアの変更
git diff
# ステージングエリアと前回のコミットの変更
git diff --staged
# すべての未コミットの変更
git diff HEAD
# 特定ファイルの変更
git diff file.txt
```

### 履歴の表示：`git log`

コミット履歴とリポジトリのタイムラインを表示します。

```bash
# 完全なコミット履歴
git log
# 凝縮された一行形式
git log --oneline
# 最後の 5 件のコミットを表示
git log -5
# 分岐のグラフを視覚化
git log --graph --all
```

## 変更のステージングとコミット

### ファイルのステージング：`git add`

次のコミットのために変更をステージングエリアに追加します。

```bash
# 特定のファイルをステージング
git add file.txt
# 現在ディレクトリ内のすべての変更をステージング
git add .
# すべての変更（削除を含む）をステージング
git add -A
# すべての JavaScript ファイルをステージング
git add *.js
# 対話的なステージング（パッチモード）
git add -p
```

### 変更のコミット：`git commit`

ステージングされた変更を説明的なメッセージとともにリポジトリに保存します。

```bash
# メッセージ付きでコミット
git commit -m "Add user authentication"
# 変更されたファイルをステージングしてコミット
git commit -a -m "Update docs"
# 前回のコミットを変更
git commit --amend
# メッセージを変更せずに修正
git commit --no-edit --amend
```

<BaseQuiz id="git-commit-1" correct="A">
  <template #question>
    <code>git commit -m "message"</code> は何を行いますか？
  </template>
  
  <BaseQuizOption value="A" correct>指定されたメッセージで新しいコミットを作成する</BaseQuizOption>
  <BaseQuizOption value="B">作業ディレクトリ内のすべての変更をステージングする</BaseQuizOption>
  <BaseQuizOption value="C">リモートリポジトリに変更をプッシュする</BaseQuizOption>
  <BaseQuizOption value="D">新しいブランチを作成する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>git commit -m</code> コマンドは、ステージングされた変更で新しいコミットを作成し、提供されたメッセージでリポジトリの履歴に保存します。リモートへのプッシュやブランチの作成は行いません。
  </BaseQuizAnswer>
</BaseQuiz>

### ファイルのアンステージ：`git reset`

ステージングエリアからファイルを削除したり、コミットを取り消したりします。

```bash
# 特定のファイルをアンステージ
git reset file.txt
# すべてのファイルをアンステージ
git reset
# 前回のコミットを取り消し、変更はステージングされたままにする
git reset --soft HEAD~1
# 前回のコミットを取り消し、変更を破棄する
git reset --hard HEAD~1
```

### 変更の破棄：`git checkout` / `git restore`

作業ディレクトリ内の変更を前回のコミット状態に戻します。

```bash
# ファイルの変更を破棄する（古い構文）
git checkout -- file.txt
# ファイルの変更を破棄する（新しい構文）
git restore file.txt
# ファイルのステージングを解除する（新しい構文）
git restore --staged file.txt
# すべての未コミットの変更を破棄する
git checkout .
```

## ブランチ操作

### ブランチの一覧表示：`git branch`

リポジトリのブランチを表示および管理します。

```bash
# ローカルブランチを一覧表示
git branch
# すべてのブランチ（ローカルおよびリモート）を一覧表示
git branch -a
# リモートブランチのみを一覧表示
git branch -r
# 各ブランチの最新コミットを表示
git branch -v
```

### 作成と切り替え：`git checkout` / `git switch`

新しいブランチを作成し、ブランチを切り替えます。

```bash
# 新しいブランチを作成して切り替え
git checkout -b feature-branch
# 新しいブランチを作成して切り替え（新しい構文）
git switch -c feature-branch
# 既存のブランチに切り替え
git checkout main
# 既存のブランチに切り替え（新しい構文）
git switch main
```

<BaseQuiz id="git-branch-1" correct="B">
  <template #question>
    <code>git checkout -b feature-branch</code> は何を行いますか？
  </template>
  
  <BaseQuizOption value="A">feature-branch を削除する</BaseQuizOption>
  <BaseQuizOption value="B" correct>feature-branch という名前の新しいブランチを作成し、それに切り替える</BaseQuizOption>
  <BaseQuizOption value="C">feature-branch を現在のブランチにマージする</BaseQuizOption>
  <BaseQuizOption value="D">feature-branch のコミット履歴を表示する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-b</code> フラグは新しいブランチを作成し、<code>checkout</code> はそれに切り替えます。このコマンドは両方の操作を結合します：ブランチを作成し、直ちにそれに切り替えます。
  </BaseQuizAnswer>
</BaseQuiz>

### ブランチのマージ：`git merge`

異なるブランチからの変更を結合します。

```bash
# feature-branch を現在のブランチにマージ
git merge feature-branch
# フォースマージコミット
git merge --no-ff feature-branch
# マージ前にコミットをスクワッシュする
git merge --squash feature-branch
```

### ブランチの削除：`git branch -d`

不要になったブランチを削除します。

```bash
# マージ済みのブランチを削除
git branch -d feature-branch
# マージされていないブランチを強制削除
git branch -D feature-branch
# リモートブランチを削除
git push origin --delete feature-branch
```

## リモートリポジトリ操作

### 更新のフェッチ：`git fetch`

リモートリポジトリから変更をダウンロードしますが、マージは行いません。

```bash
# デフォルトのリモートからフェッチ
git fetch
# 特定のリモートからフェッチ
git fetch origin
# すべてのリモートからフェッチ
git fetch --all
# 特定のブランチをフェッチ
git fetch origin main
```

### 変更のプル：`git pull`

リモートリポジトリから変更をダウンロードし、マージします。

```bash
# トラッキングブランチからプル
git pull
# 特定のリモートブランチからプル
git pull origin main
# マージではなくリベースでプル
git pull --rebase
# マージコミットなしでファストフォワードのみ
git pull --ff-only
```

<BaseQuiz id="git-pull-1" correct="C">
  <template #question>
    <code>git fetch</code> と <code>git pull</code> の違いは何ですか？
  </template>
  
  <BaseQuizOption value="A">違いはありません。同じことを行います</BaseQuizOption>
  <BaseQuizOption value="B">git fetch は変更をプッシュし、git pull は変更をダウンロードします</BaseQuizOption>
  <BaseQuizOption value="C" correct>git fetch はマージせずに変更をダウンロードし、git pull は変更をダウンロードしてマージします</BaseQuizOption>
  <BaseQuizOption value="D">git fetch はローカルリポジトリで機能し、git pull はリモートリポジトリで機能します</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>git fetch</code> はリモートリポジトリから変更をダウンロードしますが、現在のブランチにはマージしません。<code>git pull</code> は両方の操作を実行します：変更をフェッチし、次に現在のブランチにマージします。
  </BaseQuizAnswer>
</BaseQuiz>

### 変更のプッシュ：`git push`

ローカルコミットをリモートリポジトリにアップロードします。

```bash
# トラッキングブランチにプッシュ
git push
# 特定のリモートブランチにプッシュ
git push origin main
# プッシュしてアップストリームのトラッキングを設定
git push -u origin feature
# 安全なフォースプッシュ
git push --force-with-lease
```

<BaseQuiz id="git-push-1" correct="D">
  <template #question>
    <code>git push -u origin feature</code> は何を行いますか？
  </template>
  
  <BaseQuizOption value="A">リモートから feature ブランチを削除する</BaseQuizOption>
  <BaseQuizOption value="B">feature ブランチから変更をプルする</BaseQuizOption>
  <BaseQuizOption value="C">feature ブランチを main にマージする</BaseQuizOption>
  <BaseQuizOption value="D" correct>feature ブランチを origin にプッシュし、トラッキングを設定する</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-u</code> フラグ（または <code>--set-upstream</code>）は、ブランチをリモートリポジトリにプッシュし、トラッキングを設定するため、将来の <code>git push</code> および <code>git pull</code> コマンドは使用するリモートブランチを認識します。
  </BaseQuizAnswer>
</BaseQuiz>

### リモートブランチの追跡：`git branch --track`

ローカルブランチとリモートブランチ間のトラッキングを設定します。

```bash
# トラッキングを設定
git branch --set-upstream-to=origin/main main
# リモートブランチを追跡
git checkout -b local-branch origin/remote-branch
```

## スタッシュと一時ストレージ

### 変更のスタッシュ：`git stash`

コミットされていない変更を一時的に保存し、後で使えるようにします。

```bash
# 現在の変更をスタッシュ
git stash
# メッセージ付きでスタッシュ
git stash save "Work in progress on feature X"
# 未追跡ファイルを含める
git stash -u
# ステージされていない変更のみをスタッシュ
git stash --keep-index
```

### スタッシュの一覧表示：`git stash list`

保存されているすべてのスタッシュを表示します。

```bash
# すべてのスタッシュを表示
git stash list
# 最新のスタッシュの変更を表示
git stash show
# 特定のスタッシュの変更を表示
git stash show stash@{1}
```

### スタッシュの適用：`git stash apply`

以前スタッシュした変更を復元します。

```bash
# 最新のスタッシュを適用
git stash apply
# 特定のスタッシュを適用
git stash apply stash@{1}
# 適用後に最新のスタッシュを削除
git stash pop
# 最新のスタッシュを削除
git stash drop
# スタッシュからブランチを作成
git stash branch new-branch stash@{1}
# すべてのスタッシュを削除
git stash clear
```

<BaseQuiz id="git-stash-1" correct="B">
  <template #question>
    <code>git stash apply</code> と <code>git stash pop</code> の違いは何ですか？
  </template>
  
  <BaseQuizOption value="A">git stash apply はスタッシュを削除し、git stash pop は保持します</BaseQuizOption>
  <BaseQuizOption value="B" correct>git stash apply はスタッシュを保持し、git stash pop は適用後に削除します</BaseQuizOption>
  <BaseQuizOption value="C">git stash apply はリモートリポジトリで機能し、git stash pop はローカルで機能します</BaseQuizOption>
  <BaseQuizOption value="D">違いはありません。同じことを行います</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>git stash apply</code> はスタッシュされた変更を復元しますが、スタッシュリストにはスタッシュを残します。<code>git stash pop</code> はスタッシュを適用し、その後スタッシュリストから削除します。これはスタッシュが不要になった場合に便利です。
  </BaseQuizAnswer>
</BaseQuiz>

## 履歴とログの分析

### コミット履歴の表示：`git log`

さまざまな書式設定オプションを使用してリポジトリの履歴を調査します。

```bash
# 分岐の履歴を視覚化
git log --oneline --graph --all
# 特定の作成者によるコミット
git log --author="John Doe"
# 最近のコミット
git log --since="2 weeks ago"
# コミットメッセージの検索
git log --grep="bug fix"
```

### 責務の追跡：`git blame`

ファイルの各行を最後に変更した人を確認します。

```bash
# 行ごとの作成者を表示
git blame file.txt
# 特定の行範囲を責務追跡
git blame -L 10,20 file.txt
# blame の代替
git annotate file.txt
```

### リポジトリの検索：`git grep`

リポジトリの履歴全体でテキストパターンを検索します。

```bash
# トラッキングされているファイル内のテキストを検索
git grep "function"
# 行番号付きで検索
git grep -n "TODO"
# ステージングされたファイル内を検索
git grep --cached "bug"
```

### コミット詳細の表示：`git show`

特定のコミットに関する詳細情報を表示します。

```bash
# 最新のコミットの詳細を表示
git show
# 前回のコミットを表示
git show HEAD~1
# ハッシュで特定のコミットを表示
git show abc123
# 統計情報とともにコミットを表示
git show --stat
```

## 変更の取り消しと履歴の編集

### コミットの取り消し：`git revert`

安全に以前の変更を打ち消す新しいコミットを作成します。

```bash
# 最新のコミットを取り消す
git revert HEAD
# 特定のコミットを取り消す
git revert abc123
# コミット範囲を取り消す
git revert HEAD~3..HEAD
# 自動コミットなしで取り消す
git revert --no-commit abc123
```

### 履歴のリセット：`git reset`

ブランチポインタを移動し、必要に応じて作業ディレクトリを変更します。

```bash
# コミットを取り消し、変更はステージングされたままにする
git reset --soft HEAD~1
# コミットとステージングを取り消す
git reset --mixed HEAD~1
# コミット、ステージング、作業ディレクトリを取り消す
git reset --hard HEAD~1
```

### 対話型リベース：`git rebase -i`

コミットを対話的に編集、並べ替え、またはスクワッシュします。

```bash
# 最後の 3 つのコミットを対話的にリベース
git rebase -i HEAD~3
# 現在のブランチを main にリベース
git rebase -i main
# 競合解決後に続行
git rebase --continue
# リベース操作を中止
git rebase --abort
```

### チェリーピック：`git cherry-pick`

他のブランチから特定のコミットを適用します。

```bash
# 特定のコミットを現在のブランチに適用
git cherry-pick abc123
# コミット範囲を適用
git cherry-pick abc123..def456
# コミットせずにチェリーピック
git cherry-pick -n abc123
```

## 競合の解決

### マージの競合：解決プロセス

マージ操作中に競合を解決するための手順。

```bash
# 競合しているファイルを確認
git status
# 競合を解決済みとしてマーク
git add resolved-file.txt
# マージを完了
git commit
# マージを中止し、以前の状態に戻す
git merge --abort
```

### マージツール：`git mergetool`

視覚的な競合解決を支援するために外部ツールを起動します。

```bash
# デフォルトのマージツールを起動
git mergetool
# デフォルトのマージツールを設定
git config --global merge.tool vimdiff
# このマージに特定ツールを使用
git mergetool --tool=meld
```

### 競合マーカー: フォーマットの理解

ファイル内の Git の競合マーカーの形式を解釈します。

```text
<<<<<<< HEAD
現在のブランチの内容
=======
取り込み中のブランチの内容
>>>>>>> feature-branch
```

ファイルを編集して解決した後：

```bash
git add conflicted-file.txt
git commit
```

### Diff ツール：`git difftool`

より良い競合の視覚化のために外部の diff ツールを使用します。

```bash
# 変更のために diff ツールを起動
git difftool
# デフォルトの diff ツールを設定
git config --global diff.tool vimdiff
```

## タグ付けとリリース

### タグの作成：`git tag`

特定のコミットにバージョンラベルを付けてマークします。

```bash
# 軽量タグの作成
git tag v1.0
# アノテーション付きタグの作成
git tag -a v1.0 -m "Version 1.0 release"
# 特定のコミットにタグ付け
git tag -a v1.0 abc123
# サイン付きタグの作成
git tag -s v1.0
```

### タグの一覧表示と表示：`git tag -l`

既存のタグとその情報を表示します。

```bash
# すべてのタグを一覧表示
git tag
# パターンに一致するタグを一覧表示
git tag -l "v1.*"
# タグの詳細を表示
git show v1.0
```

### タグのプッシュ：`git push --tags`

タグをリモートリポジトリと共有します。

```bash
# 特定のタグをプッシュ
git push origin v1.0
# すべてのタグをプッシュ
git push --tags
# 特定のリモートにすべてのタグをプッシュ
git push origin --tags
```

### タグの削除：`git tag -d`

ローカルおよびリモートリポジトリからタグを削除します。

```bash
# ローカルタグを削除
git tag -d v1.0
# リモートタグを削除
git push origin --delete tag v1.0
# 代替の削除構文
git push origin :refs/tags/v1.0
```

## Git の設定とエイリアス

### 設定の表示：`git config --list`

現在の Git 設定設定を表示します。

```bash
# すべての設定を表示
git config --list
# グローバル設定のみを表示
git config --global --list
# リポジトリ固有の設定を表示
git config --local --list
# 特定の設定を表示
git config user.name
```

### エイリアスの作成：`git config alias`

頻繁に使用するコマンドのショートカットを設定します。

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

### 高度なエイリアス：複雑なコマンド

複雑なコマンドの組み合わせのためのエイリアスを作成します。

```bash
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.unstage "reset HEAD --"
git config --global alias.last "log -1 HEAD"
git config --global alias.visual "!gitk"
```

### エディタの設定：`git config core.editor`

コミットメッセージや競合のために優先するテキストエディタを設定します。

```bash
# VS Code
git config --global core.editor "code --wait"
# Vim
git config --global core.editor "vim"
# Nano
git config --global core.editor "nano"
```

## パフォーマンスと最適化

### リポジトリのメンテナンス：`git gc`

リポジトリのパフォーマンスとストレージを最適化します。

```bash
# 標準のガベージコレクション
git gc
# より徹底的な最適化
git gc --aggressive
# 必要な場合にのみ実行
git gc --auto
# リポジトリの整合性をチェック
git fsck
```

### 大容量ファイル処理：`git lfs`

Git LFS を使用して大容量バイナリファイルを効率的に管理します。

```bash
# リポジトリで LFS をインストール
git lfs install
# PDF ファイルを LFS で追跡
git lfs track "*.pdf"
# LFS によって追跡されているファイルを一覧表示
git lfs ls-files
# 既存のファイルを移行
git lfs migrate import --include="*.zip"
```

### シャロークローン：リポジトリサイズの削減

より高速な操作のために履歴を制限してリポジトリをクローンします。

```bash
# 最新のコミットのみ
git clone --depth 1 https://github.com/user/repo.git
# 最後の 10 件のコミット
git clone --depth 10 repo.git
# シャローをフルクローンに変換
git fetch --unshallow
```

### スパースチェックアウト：サブディレクトリの操作

大規模なリポジトリの特定の部分のみをチェックアウトします。

```bash
git config core.sparseCheckout true
echo "src/*" > .git/info/sparse-checkout
# スパースチェックアウトを適用
git read-tree -m -u HEAD
```

## Git のインストールとセットアップ

### パッケージマネージャ：`apt`, `yum`, `brew`

システムパッケージマネージャを使用して Git をインストールします。

```bash
# Ubuntu/Debian
sudo apt install git
# CentOS/RHEL
sudo yum install git
# macOS (Homebrew)
brew install git
# Windows (winget)
winget install Git.Git
```

### ダウンロードとインストール：公式インストーラ

プラットフォームに応じた公式の Git インストーラを使用します。

```bash
# https://git-scm.com/downloads からダウンロード
# インストールを確認
git --version
# Git 実行可能ファイルのパスを表示
which git
```

### 初回セットアップ：ユーザー設定

コミットのために Git に自分の ID を設定します。

```bash
git config --global user.name "Your Full Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# マージ動作を設定
git config --global pull.rebase false
```

## Git ワークフローとベストプラクティス

### 機能ブランチワークフロー

分離されたブランチを使用した機能開発の標準ワークフロー。

```bash
# main ブランチから開始
git checkout main
# 最新の変更を取得
git pull origin main
# 機能ブランチを作成
git checkout -b feature/user-auth
# ... 変更を加えてコミット ...
# 機能ブランチをプッシュ
git push -u origin feature/user-auth
# ... プルリクエストを作成 ...
```

### Git Flow: 構造化されたブランチモデル

さまざまな目的に特化したブランチを使用した体系的なアプローチ。

```bash
# Git Flow を初期化
git flow init
# 機能の開始
git flow feature start new-feature
# 機能の終了
git flow feature finish new-feature
# リリースブランチの開始
git flow release start 1.0.0
```

### コミットメッセージの規約

明確なプロジェクト履歴のために、従来のコミット形式に従います。

```bash
# フォーマット: <type>(<scope>): <subject>
git commit -m "feat(auth): add user login functionality"
git commit -m "fix(api): resolve null pointer exception"
git commit -m "docs(readme): update installation instructions"
git commit -m "refactor(utils): simplify date formatting"
```

### アトミックコミット：ベストプラクティス

履歴を改善するために、焦点を絞った単一目的のコミットを作成します。

```bash
# 対話的に変更をステージング
git add -p
# 特定の変更
git commit -m "Add validation to email field"
# 避けるべき: git commit -m "Fix stuff" # 曖昧すぎる
# 良い例:  git commit -m "Fix email validation regex pattern"
```

## トラブルシューティングとリカバリ

### Reflog: 回復ツール

失われたコミットを回復するために Git の参照ログを使用します。

```bash
# 参照ログを表示
git reflog
# HEAD の移動を表示
git reflog show HEAD
# 失われたコミットを回復
git checkout abc123
# 失われたコミットからブランチを作成
git branch recovery-branch abc123
```

### 破損したリポジトリ：修復

リポジトリの破損と整合性の問題を修正します。

```bash
# リポジトリの整合性をチェック
git fsck --full
# 積極的なクリーンアップ
git gc --aggressive --prune=now
# 破損した場合にインデックスを再構築
rm .git/index; git reset
```

### 認証の問題

一般的な認証および権限の問題を解決します。

```bash
# トークンを使用
git remote set-url origin https://token@github.com/user/repo.git
# SSH キーをエージェントに追加
ssh-add ~/.ssh/id_rsa
# Windows の資格情報マネージャー
git config --global credential.helper manager-core
```

### パフォーマンスの問題：デバッグ

リポジトリのパフォーマンスの問題を特定して解決します。

```bash
# リポジトリサイズを表示
git count-objects -vH
# 合計コミット数をカウント
git log --oneline | wc -l
# ブランチ数をカウント
git for-each-ref --format='%(refname:short)' | wc -l
```

## 関連リンク

- <router-link to="/linux">Linux チートシート</router-link>
- <router-link to="/shell">Shell チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/kubernetes">Kubernetes チートシート</router-link>
- <router-link to="/ansible">Ansible チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>

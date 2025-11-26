---
title: 'Git 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 종합 치트 시트로 Git 을 학습하세요.'
pdfUrl: '/cheatsheets/pdf/git-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Git 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/git">Hands-On 실습으로 Git 배우기</a>
</base-disclaimer-title>
<base-disclaimer-content>
Hands-On 실습과 실제 시나리오를 통해 Git 버전 관리를 배우세요. LabEx 는 필수 명령어, 브랜칭 전략, 협업 워크플로우 및 고급 기술을 다루는 포괄적인 Git 강좌를 제공합니다. Git 과 GitHub 를 사용하여 코드 저장소를 관리하고, 충돌을 해결하며, 팀과 효과적으로 협업하는 방법을 배우십시오.
</base-disclaimer-content>
</base-disclaimer>

## 저장소 설정 및 구성

### 저장소 초기화: `git init`

현재 디렉토리에 새 Git 저장소를 생성합니다.

```bash
# 새 저장소 초기화
git init
# 새 디렉토리에 초기화
git init project-name
# 베어 저장소 초기화 (작업 디렉토리 없음)
git init --bare
# 사용자 정의 템플릿 디렉토리 사용
git init --template=path
```

### 저장소 복제: `git clone`

원격 저장소의 로컬 복사본을 생성합니다.

```bash
# HTTPS를 통한 복제
git clone https://github.com/user/repo.git
# SSH를 통한 복제
git clone git@github.com:user/repo.git
# 사용자 정의 이름으로 복제
git clone repo.git local-name
# 얕은 복제 (최신 커밋만)
git clone --depth 1 repo.git
```

### 전역 구성: `git config`

사용자 정보 및 기본 설정을 전역적으로 설정합니다.

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# 모든 구성 설정 보기
git config --list
```

### 로컬 구성: `git config --local`

저장소별 구성을 설정합니다.

```bash
# 현재 저장소에만 설정
git config user.name "Project Name"
# 프로젝트별 이메일
git config user.email "project@example.com"
```

### 원격 관리: `git remote`

원격 저장소 연결을 관리합니다.

```bash
# 원격 추가
git remote add origin https://github.com/user/repo.git
# URL과 함께 모든 원격 목록 보기
git remote -v
# 원격에 대한 자세한 정보 보기
git remote show origin
# 원격 이름 변경
git remote rename origin upstream
# 원격 제거
git remote remove upstream
```

### 자격 증명 저장: `git config credential`

반복적인 로그인을 피하기 위해 인증 자격 증명을 저장합니다.

```bash
# 15분 동안 캐시
git config --global credential.helper cache
# 영구적으로 저장
git config --global credential.helper store
# 1시간 동안 캐시
git config --global credential.helper 'cache --timeout=3600'
```

## 저장소 정보 및 상태

### 상태 확인: `git status`

작업 디렉토리와 스테이징 영역의 현재 상태를 표시합니다.

```bash
# 전체 상태 정보
git status
# 짧은 상태 형식
git status -s
# 기계가 읽을 수 있는 형식
git status --porcelain
# 무시된 파일도 표시
git status --ignored
```

### 차이점 보기: `git diff`

저장소의 다른 상태 간의 변경 사항을 표시합니다.

```bash
# 작업 디렉토리 대 스테이징 영역의 변경 사항
git diff
# 스테이징 영역 대 마지막 커밋의 변경 사항
git diff --staged
# 모든 커밋되지 않은 변경 사항
git diff HEAD
# 특정 파일의 변경 사항
git diff file.txt
```

### 기록 보기: `git log`

커밋 기록 및 저장소 타임라인을 표시합니다.

```bash
# 전체 커밋 기록
git log
# 간결한 한 줄 형식
git log --oneline
# 마지막 5개 커밋 표시
git log -5
# 시각적 브랜치 그래프
git log --graph --all
```

## 변경 사항 스테이징 및 커밋

### 파일 스테이징: `git add`

다음 커밋을 위해 변경 사항을 스테이징 영역에 추가합니다.

```bash
# 특정 파일 스테이징
git add file.txt
# 현재 디렉토리의 모든 변경 사항 스테이징
git add .
# 모든 변경 사항 스테이징 (삭제 포함)
git add -A
# 모든 JavaScript 파일 스테이징
git add *.js
# 대화형 스테이징 (패치 모드)
git add -p
```

### 변경 사항 커밋: `git commit`

설명 메시지와 함께 스테이징된 변경 사항을 저장소에 저장합니다.

```bash
# 메시지와 함께 커밋
git commit -m "Add user authentication"
# 수정된 파일 스테이징 및 커밋
git commit -a -m "Update docs"
# 마지막 커밋 수정
git commit --amend
# 메시지 변경 없이 수정
git commit --no-edit --amend
```

### 파일 언스테이징: `git reset`

스테이징 영역에서 파일을 제거하거나 커밋을 취소합니다.

```bash
# 특정 파일 언스테이징
git reset file.txt
# 모든 파일 언스테이징
git reset
# 마지막 커밋 취소, 변경 사항 스테이징 유지
git reset --soft HEAD~1
# 마지막 커밋 취소, 변경 사항 삭제
git reset --hard HEAD~1
```

### 변경 사항 폐기: `git checkout` / `git restore`

작업 디렉토리의 변경 사항을 마지막 커밋 상태로 되돌립니다.

```bash
# 파일의 변경 사항 폐기 (이전 구문)
git checkout -- file.txt
# 파일의 변경 사항 폐기 (새 구문)
git restore file.txt
# 파일 언스테이징 (새 구문)
git restore --staged file.txt
# 모든 커밋되지 않은 변경 사항 폐기
git checkout .
```

## 브랜치 작업

### 브랜치 목록: `git branch`

저장소 브랜치를 보고 관리합니다.

```bash
# 로컬 브랜치 목록
git branch
# 모든 브랜치 목록 (로컬 및 원격)
git branch -a
# 원격 브랜치만 목록 표시
git branch -r
# 각 브랜치의 마지막 커밋 표시
git branch -v
```

### 생성 및 전환: `git checkout` / `git switch`

새 브랜치를 생성하고 그 사이를 전환합니다.

```bash
# 새 브랜치 생성 및 전환
git checkout -b feature-branch
# 새 브랜치 생성 및 전환 (새 구문)
git switch -c feature-branch
# 기존 브랜치로 전환
git checkout main
# 기존 브랜치로 전환 (새 구문)
git switch main
```

### 브랜치 병합: `git merge`

다른 브랜치의 변경 사항을 결합합니다.

```bash
# feature-branch를 현재 브랜치로 병합
git merge feature-branch
# 강제 병합 커밋
git merge --no-ff feature-branch
# 병합 전에 커밋 스쿼시
git merge --squash feature-branch
```

### 브랜치 삭제: `git branch -d`

더 이상 필요하지 않은 브랜치를 제거합니다.

```bash
# 병합된 브랜치 삭제
git branch -d feature-branch
# 병합되지 않은 브랜치 강제 삭제
git branch -D feature-branch
# 원격 브랜치 삭제
git push origin --delete feature-branch
```

## 원격 저장소 작업

### 업데이트 가져오기: `git fetch`

원격 저장소에서 변경 사항을 가져오지만 병합하지는 않습니다.

```bash
# 기본 원격에서 가져오기
git fetch
# 특정 원격에서 가져오기
git fetch origin
# 모든 원격에서 가져오기
git fetch --all
# 특정 브랜치 가져오기
git fetch origin main
```

### 변경 사항 가져오기: `git pull`

원격 저장소에서 변경 사항을 다운로드하고 병합합니다.

```bash
# 추적 브랜치에서 가져오기
git pull
# 특정 원격 브랜치에서 가져오기
git pull origin main
# 병합 대신 rebase 사용
git pull --rebase
# Fast-forward만 허용, 병합 커밋 없음
git pull --ff-only
```

### 변경 사항 푸시: `git push`

로컬 커밋을 원격 저장소로 업로드합니다.

```bash
# 추적 브랜치로 푸시
git push
# 특정 원격 브랜치로 푸시
git push origin main
# 푸시 및 상위 추적 설정
git push -u origin feature
# 안전하게 강제 푸시
git push --force-with-lease
```

### 원격 브랜치 추적: `git branch --track`

로컬 및 원격 브랜치 간의 추적을 설정합니다.

```bash
# 추적 설정
git branch --set-upstream-to=origin/main main
# 원격 브랜치 추적
git checkout -b local-branch origin/remote-branch
```

## Stashing 및 임시 저장소

### 변경 사항 Stash: `git stash`

나중에 사용하기 위해 커밋되지 않은 변경 사항을 임시로 저장합니다.

```bash
# 현재 변경 사항 Stash
git stash
# 메시지와 함께 Stash 저장
git stash save "Work in progress on feature X"
# 추적되지 않은 파일 포함
git stash -u
# 스테이징되지 않은 변경 사항만 Stash
git stash --keep-index
```

### Stash 목록 보기: `git stash list`

저장된 모든 stash 를 확인합니다.

```bash
# 모든 stash 표시
git stash list
# 최신 stash의 변경 사항 표시
git stash show
# 특정 stash의 변경 사항 표시
git stash show stash@{1}
```

### Stash 적용: `git stash apply`

이전에 저장한 변경 사항을 복원합니다.

```bash
# 최신 stash 적용
git stash apply
# 특정 stash 적용
git stash apply stash@{1}
# 적용 후 최신 stash 제거
git stash pop
# 최신 stash 삭제
git stash drop
# stash에서 브랜치 생성
git stash branch new-branch stash@{1}
# 모든 stash 삭제
git stash clear
```

## 기록 및 로그 분석

### 커밋 기록 보기: `git log`

다양한 형식 옵션으로 저장소 기록을 탐색합니다.

```bash
# 시각적 브랜치 기록
git log --oneline --graph --all
# 특정 작성자의 커밋
git log --author="John Doe"
# 최근 커밋
git log --since="2 weeks ago"
# 커밋 메시지 검색
git log --grep="bug fix"
```

### Blame 및 주석: `git blame`

파일의 각 줄을 마지막으로 수정한 사람을 확인합니다.

```bash
# 줄별 작성자 표시
git blame file.txt
# 특정 줄 범위에 대한 Blame
git blame -L 10,20 file.txt
# blame의 대안
git annotate file.txt
```

### 저장소 검색: `git grep`

저장소 기록 전체에서 텍스트 패턴을 검색합니다.

```bash
# 추적 파일에서 텍스트 검색
git grep "function"
# 줄 번호와 함께 검색
git grep -n "TODO"
# 스테이징된 파일에서 검색
git grep --cached "bug"
```

### 커밋 세부 정보 보기: `git show`

특정 커밋에 대한 자세한 정보를 표시합니다.

```bash
# 최신 커밋 세부 정보 표시
git show
# 이전 커밋 표시
git show HEAD~1
# 해시로 특정 커밋 표시
git show abc123
# 파일 통계와 함께 커밋 표시
git show --stat
```

## 변경 사항 취소 및 기록 편집

### 커밋 되돌리기: `git revert`

안전하게 이전 변경 사항을 취소하는 새 커밋을 생성합니다.

```bash
# 최신 커밋 되돌리기
git revert HEAD
# 특정 커밋 되돌리기
git revert abc123
# 커밋 범위 되돌리기
git revert HEAD~3..HEAD
# 자동 커밋 없이 되돌리기
git revert --no-commit abc123
```

### 기록 재설정: `git reset`

브랜치 포인터를 이동하고 선택적으로 작업 디렉토리를 수정합니다.

```bash
# 커밋 취소, 변경 사항 스테이징 유지
git reset --soft HEAD~1
# 커밋 및 스테이징 취소
git reset --mixed HEAD~1
# 커밋, 스테이징 및 작업 디렉토리 취소
git reset --hard HEAD~1
```

### 대화형 Rebase: `git rebase -i`

커밋을 대화형으로 편집, 재정렬 또는 스쿼시합니다.

```bash
# 마지막 3개 커밋 대화형으로 rebase
git rebase -i HEAD~3
# 현재 브랜치를 main 위에 rebase
git rebase -i main
# 충돌 해결 후 계속
git rebase --continue
# rebase 작업 취소
git rebase --abort
```

### Cherry-pick: `git cherry-pick`

다른 브랜치의 특정 커밋을 적용합니다.

```bash
# 현재 브랜치에 특정 커밋 적용
git cherry-pick abc123
# 커밋 범위 적용
git cherry-pick abc123..def456
# 커밋하지 않고 cherry-pick
git cherry-pick -n abc123
```

## 충돌 해결

### 병합 충돌: 해결 프로세스

병합 작업 중 충돌을 해결하기 위한 단계입니다.

```bash
# 충돌 파일 확인
git status
# 충돌 해결됨으로 표시
git add resolved-file.txt
# 병합 완료
git commit
# 병합을 취소하고 이전 상태로 돌아가기
git merge --abort
```

### 병합 도구: `git mergetool`

시각적으로 충돌을 해결하는 데 도움이 되는 외부 도구를 실행합니다.

```bash
# 기본 병합 도구 실행
git mergetool
# 기본 병합 도구 설정
git config --global merge.tool vimdiff
# 이 병합에 특정 도구 사용
git mergetool --tool=meld
```

### 충돌 마커: 형식 이해

파일에서 Git 의 충돌 마커 형식을 해석합니다.

```text
<<<<<<< HEAD
현재 브랜치 내용
=======
들어오는 브랜치 내용
>>>>>>> feature-branch
```

파일을 편집하여 해결한 후:

```bash
git add conflicted-file.txt
git commit
```

### Diff 도구: `git difftool`

더 나은 충돌 시각화를 위해 외부 diff 도구를 사용합니다.

```bash
# 변경 사항에 대한 diff 도구 실행
git difftool
# 기본 diff 도구 설정
git config --global diff.tool vimdiff
```

## 태그 지정 및 릴리스

### 태그 생성: `git tag`

특정 커밋에 버전 레이블을 지정합니다.

```bash
# 경량 태그 생성
git tag v1.0
# 주석 태그 생성
git tag -a v1.0 -m "Version 1.0 release"
# 특정 커밋 태그 지정
git tag -a v1.0 abc123
# 서명된 태그 생성
git tag -s v1.0
```

### 태그 목록 및 보기: `git tag -l`

기존 태그와 그 정보를 확인합니다.

```bash
# 모든 태그 목록 표시
git tag
# 패턴과 일치하는 태그 목록 표시
git tag -l "v1.*"
# 태그 세부 정보 표시
git show v1.0
```

### 태그 푸시: `git push --tags`

태그를 원격 저장소와 공유합니다.

```bash
# 특정 태그 푸시
git push origin v1.0
# 모든 태그 푸시
git push --tags
# 특정 원격에 모든 태그 푸시
git push origin --tags
```

### 태그 삭제: `git tag -d`

로컬 및 원격 저장소에서 태그를 제거합니다.

```bash
# 로컬 태그 삭제
git tag -d v1.0
# 원격 태그 삭제
git push origin --delete tag v1.0
# 대안 삭제 구문
git push origin :refs/tags/v1.0
```

## Git 구성 및 별칭

### 구성 보기: `git config --list`

현재 Git 구성 설정을 표시합니다.

```bash
# 모든 구성 설정 표시
git config --list
# 전역 설정만 표시
git config --global --list
# 저장소별 설정 표시
git config --local --list
# 특정 설정 표시
git config user.name
```

### 별칭 생성: `git config alias`

자주 사용하는 명령어에 대한 단축키를 설정합니다.

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

### 고급 별칭: 복잡한 명령어

복잡한 명령어 조합을 위한 별칭을 만듭니다.

```bash
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.unstage "reset HEAD --"
git config --global alias.last "log -1 HEAD"
git config --global alias.visual "!gitk"
```

### 편집기 구성: `git config core.editor`

커밋 메시지 및 충돌을 위한 기본 텍스트 편집기를 설정합니다.

```bash
# VS Code
git config --global core.editor "code --wait"
# Vim
git config --global core.editor "vim"
# Nano
git config --global core.editor "nano"
```

## 성능 및 최적화

### 저장소 유지 관리: `git gc`

저장소 성능 및 스토리지를 최적화합니다.

```bash
# 표준 가비지 컬렉션
git gc
# 더 철저한 최적화
git gc --aggressive
# 필요할 때만 실행
git gc --auto
# 저장소 무결성 확인
git fsck
```

### 대용량 파일 처리: `git lfs`

Git LFS 를 사용하여 대용량 바이너리 파일을 효율적으로 관리합니다.

```bash
# 저장소에 LFS 설치
git lfs install
# LFS로 PDF 파일 추적
git lfs track "*.pdf"
# LFS로 추적되는 파일 목록 보기
git lfs ls-files
# 기존 파일 마이그레이션
git lfs migrate import --include="*.zip"
```

### 얕은 복제: 저장소 크기 줄이기

더 빠른 작업을 위해 제한된 기록으로 저장소를 복제합니다.

```bash
# 최신 커밋만
git clone --depth 1 https://github.com/user/repo.git
# 마지막 10개 커밋
git clone --depth 10 repo.git
# 얕은 복제를 전체 복제로 변환
git fetch --unshallow
```

### 희소 체크아웃: 하위 디렉토리 작업

대규모 저장소의 특정 부분만 체크아웃합니다.

```bash
git config core.sparseCheckout true
echo "src/*" > .git/info/sparse-checkout
# 희소 체크아웃 적용
git read-tree -m -u HEAD
```

## Git 설치 및 설정

### 패키지 관리자: `apt`, `yum`, `brew`

시스템 패키지 관리자를 사용하여 Git 을 설치합니다.

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

### 다운로드 및 설치: 공식 설치 관리자

플랫폼별 공식 Git 설치 관리자를 사용합니다.

```bash
# https://git-scm.com/downloads 에서 다운로드
# 설치 확인
git --version
# Git 실행 파일 경로 표시
which git
```

### 첫 실행 설정: 사용자 구성

커밋을 위해 Git 에 사용자 정보를 구성합니다.

```bash
git config --global user.name "Your Full Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# 병합 동작 설정
git config --global pull.rebase false
```

## Git 워크플로우 및 모범 사례

### 기능 브랜치 워크플로우

격리된 브랜치를 사용한 기능 개발을 위한 표준 워크플로우.

```bash
# main 브랜치에서 시작
git checkout main
# 최신 변경 사항 가져오기
git pull origin main
# 기능 브랜치 생성
git checkout -b feature/user-auth
# ... 변경 사항을 만들고 커밋 ...
# 기능 브랜치 푸시
git push -u origin feature/user-auth
# ... 풀 리퀘스트 생성 ...
```

### Git Flow: 구조화된 브랜칭 모델

다양한 목적을 위한 전용 브랜치를 사용하는 체계적인 접근 방식.

```bash
# Git Flow 초기화
git flow init
# 기능 시작
git flow feature start new-feature
# 기능 완료
git flow feature finish new-feature
# 릴리스 브랜치 시작
git flow release start 1.0.0
```

### 커밋 메시지 규칙

명확한 프로젝트 기록을 위해 컨벤셔널 커밋 형식을 따릅니다.

```bash
# 형식: <유형>(<범위>): <제목>
git commit -m "feat(auth): add user login functionality"
git commit -m "fix(api): resolve null pointer exception"
git commit -m "docs(readme): update installation instructions"
git commit -m "refactor(utils): simplify date formatting"
```

### 원자적 커밋: 모범 사례

더 나은 기록을 위해 단일 목적의 커밋을 생성합니다.

```bash
# 대화형으로 변경 사항 스테이징
git add -p
# 특정 변경 사항
git commit -m "Add validation to email field"
# 피해야 할 것: git commit -m "Fix stuff" # 너무 모호함
# 좋은 예:  git commit -m "Fix email validation regex pattern"
```

## 문제 해결 및 복구

### Reflog: 복구 도구

손실된 커밋을 복구하기 위해 Git 의 참조 로그를 사용합니다.

```bash
# 참조 로그 표시
git reflog
# HEAD 이동 표시
git reflog show HEAD
# 손실된 커밋 복구
git checkout abc123
# 손실된 커밋에서 브랜치 생성
git branch recovery-branch abc123
```

### 손상된 저장소: 복구

저장소 무결성 문제를 해결합니다.

```bash
# 저장소 무결성 확인
git fsck --full
# 공격적인 정리
git gc --aggressive --prune=now
# 손상된 경우 인덱스 재구축
rm .git/index; git reset
```

### 인증 문제

일반적인 인증 및 권한 문제를 해결합니다.

```bash
# 토큰 사용
git remote set-url origin https://token@github.com/user/repo.git
# SSH 키를 에이전트에 추가
ssh-add ~/.ssh/id_rsa
# Windows 자격 증명 관리자
git config --global credential.helper manager-core
```

### 성능 문제: 디버깅

저장소 성능 문제를 식별하고 해결합니다.

```bash
# 저장소 크기 표시
git count-objects -vH
# 총 커밋 수 계산
git log --oneline | wc -l
# 브랜치 수 계산
git for-each-ref --format='%(refname:short)' | wc -l
```

## 관련 링크

- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>
- <router-link to="/ansible">Ansible 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>

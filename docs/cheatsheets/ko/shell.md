---
title: '쉘 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 포괄적인 치트 시트로 쉘을 학습하세요.'
pdfUrl: '/cheatsheets/pdf/shell-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Shell 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/shell">실습 랩을 통해 Shell 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 쉘 스크립팅 및 명령줄 작업을 학습하세요. LabEx 는 필수 Bash 명령어, 파일 작업, 텍스트 처리, 프로세스 관리 및 자동화를 다루는 포괄적인 Shell 강좌를 제공합니다. 명령줄 효율성과 쉘 스크립팅 기술을 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 파일 및 디렉토리 작업

### 파일 목록 보기: `ls`

현재 위치의 파일 및 디렉토리를 표시합니다.

```bash
# 현재 디렉토리의 파일 목록 보기
ls
# 상세 정보와 함께 목록 보기
ls -l
# 숨겨진 파일 표시
ls -a
# 사람이 읽기 쉬운 파일 크기와 함께 목록 보기
ls -lh
# 수정 시간순으로 정렬
ls -lt
```

### 파일 생성: `touch`

빈 파일을 생성하거나 타임스탬프를 업데이트합니다.

```bash
# 새 파일 생성
touch newfile.txt
# 여러 파일 생성
touch file1.txt file2.txt file3.txt
# 기존 파일의 타임스탬프 업데이트
touch existing_file.txt
```

### 디렉토리 생성: `mkdir`

새 디렉토리를 생성합니다.

```bash
# 디렉토리 생성
mkdir my_directory
# 중첩된 디렉토리 생성
mkdir -p parent/child/grandchild
# 여러 디렉토리 생성
mkdir dir1 dir2 dir3
```

### 파일 복사: `cp`

파일 및 디렉토리를 복사합니다.

```bash
# 파일 복사
cp source.txt destination.txt
# 디렉토리 재귀적으로 복사
cp -r source_dir dest_dir
# 확인 프롬프트와 함께 복사
cp -i file1.txt file2.txt
# 파일 속성 보존
cp -p original.txt copy.txt
```

### 이동/이름 변경: `mv`

파일 및 디렉토리를 이동하거나 이름을 변경합니다.

```bash
# 파일 이름 변경
mv oldname.txt newname.txt
# 파일을 디렉토리로 이동
mv file.txt /path/to/directory/
# 여러 파일 이동
mv file1 file2 file3 target_directory/
```

### 파일 삭제: `rm`

파일 및 디렉토리를 제거합니다.

```bash
# 파일 삭제
rm file.txt
# 디렉토리 및 내용 삭제
rm -r directory/
# 확인 없이 강제 삭제
rm -f file.txt
# 대화형 삭제 (각각 확인)
rm -i *.txt
```

## 탐색 및 경로 관리

### 현재 디렉토리: `pwd`

현재 작업 디렉토리 경로를 출력합니다.

```bash
# 현재 디렉토리 표시
pwd
# 예시 출력:
/home/user/documents
```

### 디렉토리 변경: `cd`

다른 디렉토리로 변경합니다.

```bash
# 홈 디렉토리로 이동
cd ~
# 상위 디렉토리로 이동
cd ..
# 이전 디렉토리로 이동
cd -
# 특정 디렉토리로 이동
cd /path/to/directory
```

### 디렉토리 트리: `tree`

디렉토리 구조를 트리 형식으로 표시합니다.

```bash
# 디렉토리 트리 표시
tree
# 깊이를 2단계로 제한
tree -L 2
# 디렉토리만 표시
tree -d
```

## 텍스트 처리 및 검색

### 파일 보기: `cat` / `less` / `head` / `tail`

다양한 방식으로 파일 내용을 표시합니다.

```bash
# 전체 파일 표시
cat file.txt
# 페이지별로 파일 보기
less file.txt
# 처음 10줄 표시
head file.txt
# 마지막 10줄 표시
tail file.txt
# 마지막 20줄 표시
tail -n 20 file.txt
# 파일 변경 사항 추적 (로그에 유용)
tail -f logfile.txt
```

### 파일 내 검색: `grep`

텍스트 파일에서 패턴을 검색합니다.

```bash
# 파일에서 패턴 검색
grep "pattern" file.txt
# 대소문자 구분 없이 검색
grep -i "pattern" file.txt
# 디렉토리에서 재귀적으로 검색
grep -r "pattern" directory/
# 줄 번호 표시
grep -n "pattern" file.txt
# 일치하는 줄 수 세기
grep -c "pattern" file.txt
```

### 파일 찾기: `find`

기준에 따라 파일 및 디렉토리를 찾습니다.

```bash
# 이름으로 파일 찾기
find . -name "*.txt"
# 유형으로 파일 찾기
find . -type f -name "config*"
# 디렉토리 찾기
find . -type d -name "backup"
# 지난 7일 이내에 수정된 파일 찾기
find . -mtime -7
# 찾아서 명령어 실행
find . -name "*.log" -delete
```

### 텍스트 조작: `sed` / `awk` / `sort`

텍스트 데이터를 처리하고 조작합니다.

```bash
# 파일 내 텍스트 바꾸기
sed 's/old/new/g' file.txt
# 특정 열 추출
awk '{print $1, $3}' file.txt
# 파일 내용 정렬
sort file.txt
# 중복 줄 제거
sort file.txt | uniq
# 단어 빈도수 세기
cat file.txt | tr ' ' '\n' | sort | uniq -c
```

## 파일 권한 및 소유권

### 권한 보기: `ls -l`

상세 파일 권한 및 소유권을 표시합니다.

```bash
# 상세 파일 정보 표시
ls -l
# 예시 출력:
# -rw-r--r-- 1 user group 1024 Jan 1 12:00 file.txt
# d = 디렉토리, r = 읽기, w = 쓰기, x = 실행
```

### 권한 변경: `chmod`

파일 및 디렉토리 권한을 수정합니다.

```bash
# 소유자에게 실행 권한 부여
chmod +x script.sh
# 특정 권한 설정 (755)
chmod 755 file.txt
# 그룹/다른 사용자에 대한 쓰기 권한 제거
chmod go-w file.txt
# 재귀적 권한 변경
chmod -R 644 directory/
```

### 소유권 변경: `chown` / `chgrp`

파일 소유자 및 그룹을 변경합니다.

```bash
# 소유자 변경
chown newowner file.txt
# 소유자 및 그룹 변경
chown newowner:newgroup file.txt
# 그룹만 변경
chgrp newgroup file.txt
# 재귀적 소유권 변경
chown -R user:group directory/
```

### 권한 숫자

숫자 권한 표기법 이해.

```text
# 권한 계산:
# 4 = 읽기 (r), 2 = 쓰기 (w), 1 = 실행 (x)
# 755 = rwxr-xr-x (소유자: rwx, 그룹: r-x, 다른 사용자: r-x)
# 644 = rw-r--r-- (소유자: rw-, 그룹: r--, 다른 사용자: r--)
# 777 = rwxrwxrwx (모두에 대한 전체 권한)
# 600 = rw------- (소유자: rw-, 그룹: ---, 다른 사용자: ---)
```

## 프로세스 관리

### 프로세스 보기: `ps` / `top` / `htop`

실행 중인 프로세스 정보를 표시합니다.

```bash
# 현재 사용자의 프로세스 표시
ps
# 상세 정보와 함께 모든 프로세스 표시
ps aux
# 트리 형식으로 프로세스 표시
ps -ef --forest
# 대화형 프로세스 뷰어
top
# 향상된 프로세스 뷰어 (사용 가능한 경우)
htop
```

### 백그라운드 작업: `&` / `jobs` / `fg` / `bg`

백그라운드 및 포그라운드 프로세스를 관리합니다.

```bash
# 명령을 백그라운드에서 실행
command &
# 활성 작업 목록 보기
jobs
# 작업을 포그라운드로 가져오기
fg %1
# 작업을 백그라운드로 보내기
bg %1
# 현재 프로세스 일시 중지
Ctrl+Z
```

### 프로세스 종료: `kill` / `killall`

PID 또는 이름으로 프로세스를 종료합니다.

```bash
# PID로 프로세스 종료
kill 1234
# 프로세스 강제 종료
kill -9 1234
# 이름이 같은 모든 프로세스 종료
killall firefox
# 특정 시그널 보내기
kill -TERM 1234
```

### 시스템 모니터링: `free` / `df` / `du`

시스템 리소스 및 디스크 사용량을 모니터링합니다.

```bash
# 메모리 사용량 표시
free -h
# 디스크 공간 표시
df -h
# 디렉토리 크기 표시
du -sh directory/
# 가장 큰 디렉토리 표시
du -h --max-depth=1 | sort -hr
```

## 입력/출력 리디렉션

### 리디렉션: `>` / `>>` / `<`

명령어 출력 및 입력을 리디렉션합니다.

```bash
# 출력을 파일로 리디렉션 (덮어쓰기)
command > output.txt
# 출력을 파일에 추가
command >> output.txt
# 파일에서 입력 리디렉션
command < input.txt
# 출력 및 오류 모두 리디렉션
command > output.txt 2>&1
# 출력 폐기
command > /dev/null
```

### 파이프: `|`

파이프를 사용하여 명령을 연결합니다.

```bash
# 기본 파이프 사용법
command1 | command2
# 다중 파이프
cat file.txt | grep "pattern" | sort | uniq
# 출력 줄 수 세기
ps aux | wc -l
# 긴 출력 페이지 넘기기
ls -la | less
```

### Tee: `tee`

출력을 파일과 stdout 모두에 씁니다.

```bash
# 출력 저장 및 표시
command | tee output.txt
# 파일에 추가
command | tee -a output.txt
# 다중 출력
command | tee file1.txt file2.txt
```

### Here Documents: `<<`

명령어에 여러 줄 입력을 제공합니다.

```bash
# Here document로 파일 생성
cat << EOF > file.txt
Line 1
Line 2
Line 3
EOF
# Here document로 이메일 보내기
mail user@example.com << EOF
Subject: Test
This is a test message.
EOF
```

## 변수 및 환경

### 변수: 할당 및 사용

쉘 변수를 생성하고 사용합니다.

```bash
# 변수 할당 ( = 주변에 공백 없음)
name="John"
count=42
# 변수 사용
echo $name
echo "Hello, $name"
echo "Count: ${count}"
# 명령어 치환
current_dir=$(pwd)
date_today=$(date +%Y-%m-%d)
```

### 환경 변수: `export` / `env`

환경 변수를 관리합니다.

```bash
# 변수를 환경으로 내보내기
export PATH="/new/path:$PATH"
export MY_VAR="value"
# 모든 환경 변수 보기
env
# 특정 변수 보기
echo $HOME
echo $PATH
# 변수 해제
unset MY_VAR
```

### 특수 변수

특별한 의미를 갖는 내장 쉘 변수.

```bash
# 스크립트 인수
$0  # 스크립트 이름
$1, $2, $3...  # 첫 번째, 두 번째, 세 번째 인수
$#  # 인수의 개수
$@  # 모든 인수를 개별 단어로
$*  # 모든 인수를 단일 단어로
$?  # 마지막 명령어의 종료 상태
# 프로세스 정보
$$  # 현재 쉘 PID
$!  # 마지막 백그라운드 명령어의 PID
```

### 매개변수 확장

고급 변수 조작 기술.

```bash
# 기본값
${var:-default}  # var가 비어 있으면 기본값 사용
${var:=default}  # var가 비어 있으면 기본값으로 설정
# 문자열 조작
${var#pattern}   # 시작 부분에서 가장 짧은 일치 항목 제거
${var##pattern}  # 시작 부분에서 가장 긴 일치 항목 제거
${var%pattern}   # 끝 부분에서 가장 짧은 일치 항목 제거
${var%%pattern}  # 끝 부분에서 가장 긴 일치 항목 제거
```

## 스크립팅 기본 사항

### 스크립트 구조

기본 스크립트 형식 및 실행.

```bash
#!/bin/bash
# 이것은 주석입니다
# 변수
greeting="Hello, World!"
user=$(whoami)
# 출력
echo $greeting
echo "Current user: $user"
# 스크립트 실행 가능하게 만들기:
chmod +x script.sh
# 스크립트 실행:
./script.sh
```

### 조건문: `if`

조건을 사용하여 스크립트 흐름을 제어합니다.

```bash
#!/bin/bash
if [ -f "file.txt" ]; then
    echo "File exists"
elif [ -d "directory" ]; then
    echo "Directory exists"
else
    echo "Neither exists"
fi
# 문자열 비교
if [ "$USER" = "root" ]; then
    echo "Running as root"
fi
# 숫자 비교
if [ $count -gt 10 ]; then
    echo "Count is greater than 10"
fi
```

### 루프: `for` / `while`

루프를 사용하여 명령을 반복합니다.

```bash
#!/bin/bash
# 범위가 있는 for 루프
for i in {1..5}; do
    echo "Number: $i"
done
# 파일을 대상으로 하는 for 루프
for file in *.txt; do
    echo "Processing: $file"
done
# While 루프
count=1
while [ $count -le 5 ]; do
    echo "Count: $count"
    count=$((count + 1))
done
```

### 함수

재사용 가능한 코드 블록을 생성합니다.

```bash
#!/bin/bash
# 함수 정의
greet() {
    local name=$1
    echo "Hello, $name!"
}
# 반환 값이 있는 함수
add_numbers() {
    local sum=$(($1 + $2))
    echo $sum
}
# 함수 호출
greet "Alice"
result=$(add_numbers 5 3)
echo "Sum: $result"
```

## 네트워크 및 시스템 명령어

### 네트워크 명령어

연결 상태를 테스트하고 네트워크 구성을 확인합니다.

```bash
# 네트워크 연결 테스트
ping google.com
ping -c 4 google.com  # 4개 패킷만 보내기
# DNS 조회
nslookup google.com
dig google.com
# 네트워크 구성
ip addr show  # IP 주소 표시
ip route show # 라우팅 테이블 표시
# 파일 다운로드
wget https://example.com/file.txt
curl -O https://example.com/file.txt
```

### 시스템 정보: `uname` / `whoami` / `date`

시스템 및 사용자 정보를 가져옵니다.

```bash
# 시스템 정보
uname -a      # 모든 시스템 정보
uname -r      # 커널 버전
hostname      # 컴퓨터 이름
whoami        # 현재 사용자 이름
id            # 사용자 ID 및 그룹
# 날짜 및 시간
date          # 현재 날짜/시간
date +%Y-%m-%d # 사용자 지정 형식
uptime        # 시스템 가동 시간
```

### 아카이브 및 압축: `tar` / `zip`

압축된 아카이브를 생성 및 추출합니다.

```bash
# tar 아카이브 생성
tar -czf archive.tar.gz directory/
# tar 아카이브 추출
tar -xzf archive.tar.gz
# zip 아카이브 생성
zip -r archive.zip directory/
# zip 아카이브 추출
unzip archive.zip
# 아카이브 내용 보기
tar -tzf archive.tar.gz
unzip -l archive.zip
```

### 파일 전송: `scp` / `rsync`

시스템 간에 파일을 전송합니다.

```bash
# 원격 서버로 파일 복사
scp file.txt user@server:/path/to/destination
# 원격 서버에서 복사
scp user@server:/path/to/file.txt .
# 디렉토리 동기화 (로컬에서 원격으로)
rsync -avz local_dir/ user@server:/remote_dir/
# 삭제 포함 동기화 (미러링)
rsync -avz --delete local_dir/ user@server:/remote_dir/
```

## 명령어 기록 및 단축키

### 명령어 기록: `history`

이전 명령어를 보고 재사용합니다.

```bash
# 명령어 기록 표시
history
# 마지막 10개 명령어 표시
history 10
# 이전 명령어 실행
!!
# 번호로 명령어 실행
!123
# 'ls'로 시작하는 마지막 명령어 실행
!ls
# 대화형으로 기록 검색
Ctrl+R
```

### 기록 확장

이전 명령어의 일부를 재사용합니다.

```bash
# 마지막 명령어의 인수
!$    # 이전 명령어의 마지막 인수
!^    # 이전 명령어의 첫 번째 인수
!*    # 이전 명령어의 모든 인수
# 사용 예시:
ls /very/long/path/to/file.txt
cd !$  # /very/long/path/to/file.txt 로 이동
```

### 키보드 단축키

효율적인 명령줄 사용을 위한 필수 단축키.

```bash
# 탐색
Ctrl+A  # 줄의 시작으로 이동
Ctrl+E  # 줄의 끝으로 이동
Ctrl+F  # 한 문자 앞으로 이동
Ctrl+B  # 한 문자 뒤로 이동
Alt+F   # 한 단어 앞으로 이동
Alt+B   # 한 단어 뒤로 이동
# 편집
Ctrl+U  # 커서 앞 줄 지우기
Ctrl+K  # 커서 뒤 줄 지우기
Ctrl+W  # 커서 앞 단어 삭제
Ctrl+Y  # 마지막으로 삭제된 텍스트 붙여넣기
# 프로세스 제어
Ctrl+C  # 현재 명령어 중단
Ctrl+Z  # 현재 명령어 일시 중지
Ctrl+D  # 쉘 종료 또는 EOF
```

## 명령어 조합 및 팁

### 유용한 명령어 조합

일반적인 작업을 위한 강력한 한 줄 명령어.

```bash
# 여러 파일에서 텍스트 찾기 및 바꾸기
find . -name "*.txt" -exec sed -i 's/old/new/g' {} \;
# 현재 디렉토리에서 가장 큰 파일 찾기
du -ah . | sort -rh | head -10
# 특정 패턴에 대해 로그 파일 모니터링
tail -f /var/log/syslog | grep "ERROR"
# 디렉토리의 파일 수 세기
ls -1 | wc -l
# 타임스탬프를 사용하여 백업 생성
cp file.txt file.txt.backup.$(date +%Y%m%d-%H%M%S)
```

### 별칭 및 함수

자주 사용하는 명령어에 대한 바로 가기를 만듭니다.

```bash
# 별칭 생성 ( ~/.bashrc 에 추가)
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
# 모든 별칭 보기
alias
# 영구적인 별칭 생성 ~/.bashrc:
echo "alias mycommand='long command here'" >>
~/.bashrc
source ~/.bashrc
```

### 작업 제어 및 화면 세션

장기 실행 프로세스 및 세션 관리.

```bash
# 명령을 백그라운드에서 시작
nohup long_running_command &
# screen 세션 시작
screen -S mysession
# screen에서 분리: Ctrl+A 다음 D
# screen에 다시 연결
screen -r mysession
# screen 세션 목록
screen -ls
# 대안: tmux
tmux new -s mysession
# 분리: Ctrl+B 다음 D
tmux attach -t mysession
```

### 시스템 유지보수

일반적인 시스템 관리 작업.

```bash
# 디스크 사용량 확인
df -h
du -sh /*
# 메모리 사용량 확인
free -h
cat /proc/meminfo
# 실행 중인 서비스 확인
systemctl status service_name
systemctl list-units --type=service
# 패키지 목록 업데이트 (Ubuntu/Debian)
sudo apt update && sudo apt upgrade
# 설치된 패키지 검색
dpkg -l | grep package_name
```

## 관련 링크

- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux 치트 시트</router-link>
- <router-link to="/git">Git 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>
- <router-link to="/ansible">Ansible 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>

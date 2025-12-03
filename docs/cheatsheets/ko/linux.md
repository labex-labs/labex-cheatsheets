---
title: '리눅스 치트 시트 | LabEx'
description: '포괄적인 치트 시트로 리눅스 관리를 배우세요. 리눅스 명령어, 파일 관리, 시스템 관리, 네트워킹 및 셸 스크립팅을 위한 빠른 참조 가이드입니다.'
pdfUrl: '/cheatsheets/pdf/linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Linux 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a href="https://linux-commands.labex.io/" target="_blank">Linux 명령어 방문</a>
</base-disclaimer-title>
<base-disclaimer-content>
포괄적인 Linux 명령어 참조 자료, 구문 예제 및 상세 문서를 보려면 <a href="https://linux-commands.labex.io/" target="_blank">linux-commands.labex.io</a>를 방문하십시오. 이 독립 사이트는 Linux 관리자 및 개발자를 위한 필수 명령어, 개념 및 모범 사례를 다루는 광범위한 Linux 치트 시트를 제공합니다.
</base-disclaimer-content>
</base-disclaimer>

## 시스템 정보 및 상태

### 시스템 정보: `uname`

커널 및 아키텍처를 포함한 시스템 정보를 표시합니다.

```bash
# 커널 이름 표시
uname
# 모든 시스템 정보 표시
uname -a
# 커널 버전 표시
uname -r
# 아키텍처 표시
uname -m
# 운영 체제 표시
uname -o
```

### 하드웨어 정보: `lscpu`, `lsblk`

상세한 하드웨어 사양 및 블록 장치를 확인합니다.

```bash
# CPU 정보
lscpu
# 블록 장치 (디스크, 파티션)
lsblk
# 메모리 정보
free -h
# 파일 시스템별 디스크 사용량
df -h
```

### 시스템 가동 시간: `uptime`

시스템 가동 시간 및 로드 평균을 표시합니다.

```bash
# 시스템 가동 시간 및 로드
uptime
# 보다 상세한 가동 시간 정보
uptime -p
# 특정 날짜 이후의 가동 시간 표시
uptime -s
```

### 현재 사용자: `who`, `w`

현재 로그인된 사용자와 그들의 활동을 표시합니다.

```bash
# 로그인된 사용자 표시
who
# 활동을 포함한 상세 사용자 정보
w
# 현재 사용자 이름 표시
whoami
# 로그인 기록 표시
last
```

### 환경 변수: `env`

환경 변수를 표시하고 관리합니다.

```bash
# 모든 환경 변수 표시
env
# 특정 변수 표시
echo $HOME
# 환경 변수 설정
export PATH=$PATH:/new/path
# PATH 변수 표시
echo $PATH
```

### 날짜 및 시간: `date`, `timedatectl`

시스템 날짜와 시간을 표시하고 설정합니다.

```bash
# 현재 날짜와 시간
date
# 시스템 시간 설정 (root 권한 필요)
date MMddhhmmyyyy
# 시간대 정보
timedatectl
# 시간대 설정
timedatectl set-timezone America/New_York
```

## 파일 및 디렉토리 작업

### 파일 목록: `ls`

다양한 형식 옵션으로 파일 및 디렉토리를 표시합니다.

```bash
# 현재 디렉토리의 파일 목록
ls
# 권한을 포함한 상세 목록
ls -l
# 숨겨진 파일 표시
ls -la
# 사람이 읽기 쉬운 파일 크기
ls -lh
# 수정 시간순으로 정렬
ls -lt
```

### 디렉토리 탐색: `cd`, `pwd`

디렉토리를 변경하고 현재 위치를 표시합니다.

```bash
# 홈 디렉토리로 이동
cd
# 특정 디렉토리로 이동
cd /path/to/directory
# 한 단계 위로 이동
cd ..
# 현재 디렉토리 표시
pwd
# 이전 디렉토리로 이동
cd -
```

<BaseQuiz id="linux-cd-pwd-1" correct="B">
  <template #question>
    현재 작업 디렉토리를 보여주는 명령어는 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">cd</BaseQuizOption>
  <BaseQuizOption value="B" correct>pwd</BaseQuizOption>
  <BaseQuizOption value="C">ls</BaseQuizOption>
  <BaseQuizOption value="D">whoami</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>pwd</code> 명령어 (print working directory) 는 현재 위치한 디렉토리의 전체 경로를 표시합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 생성 및 제거: `mkdir`, `rmdir`, `rm`

파일 및 디렉토리를 생성하고 삭제합니다.

```bash
# 디렉토리 생성
mkdir newdir
# 중첩된 디렉토리 생성
mkdir -p path/to/nested/dir
# 빈 디렉토리 제거
rmdir dirname
# 파일 제거
rm filename
# 디렉토리 재귀적으로 제거
rm -rf dirname
```

### 파일 내용 보기: `cat`, `less`, `head`, `tail`

다양한 방법과 페이지 매김을 사용하여 파일 내용을 표시합니다.

```bash
# 파일 전체 표시
cat filename
# 페이지 매김으로 파일 보기
less filename
# 처음 10줄 표시
head filename
# 마지막 10줄 표시
tail filename
# 실시간으로 파일 변경 사항 추적
tail -f logfile
```

### 복사 및 이동: `cp`, `mv`

파일 및 디렉토리를 복사하고 이동합니다.

```bash
# 파일 복사
cp source.txt destination.txt
# 디렉토리 재귀적으로 복사
cp -r sourcedir/ destdir/
# 파일 이동/이름 변경
mv oldname.txt newname.txt
# 다른 디렉토리로 이동
mv file.txt /path/to/destination/
# 속성 보존하며 복사
cp -p file.txt backup.txt
```

### 파일 찾기: `find`, `locate`

이름, 유형 또는 속성별로 파일 및 디렉토리를 검색합니다.

```bash
# 이름으로 찾기
find /path -name "filename"
# 지난 7일 동안 수정된 파일 찾기
find /path -mtime -7
# 파일 유형으로 찾기
find /path -type f -name "*.txt"
# 빠르게 파일 찾기 (updatedb 필요)
locate filename
# 찾아서 명령어 실행
find /path -name "*.log" -exec rm {} \;
```

### 파일 권한: `chmod`, `chown`

파일 권한 및 소유권을 수정합니다.

```bash
# 권한 변경 (숫자)
chmod 755 filename
# 실행 권한 추가
chmod +x script.sh
# 소유권 변경
chown user:group filename
# 소유권 재귀적으로 변경
chown -R user:group directory/
# 파일 권한 보기
ls -l filename
```

<BaseQuiz id="linux-chmod-1" correct="C">
  <template #question>
    <code>chmod 755 filename</code>은 권한을 어떻게 설정합니까?
  </template>
  
  <BaseQuizOption value="A">소유자에게 읽기, 쓰기, 실행; 그룹 및 다른 사용자에게 읽기</BaseQuizOption>
  <BaseQuizOption value="B">소유자에게 읽기, 쓰기; 그룹 및 다른 사용자에게 읽기, 실행</BaseQuizOption>
  <BaseQuizOption value="C" correct>소유자에게 읽기, 쓰기, 실행; 그룹 및 다른 사용자에게 읽기, 실행</BaseQuizOption>
  <BaseQuizOption value="D">소유자에게 읽기, 쓰기; 그룹 및 다른 사용자에게 읽기</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 755</code>는 다음과 같이 설정합니다: 소유자 = 7 (rwx), 그룹 = 5 (r-x), 다른 사용자 = 5 (r-x). 이는 실행 가능한 파일 및 디렉토리에 대한 일반적인 권한 설정입니다.
  </BaseQuizAnswer>
</BaseQuiz>

## 프로세스 관리

### 프로세스 목록: `ps`

실행 중인 프로세스 및 세부 정보를 표시합니다.

```bash
# 사용자 프로세스 표시
ps
# 상세 정보와 함께 모든 프로세스 표시
ps aux
# 프로세스 트리 표시
ps -ef --forest
# 사용자에 따른 프로세스 표시
ps -u username
```

### 프로세스 종료: `kill`, `killall`

PID 또는 이름으로 프로세스를 종료합니다.

```bash
# 실시간 프로세스 모니터
top
# PID로 프로세스 종료
kill 1234
# 프로세스 강제 종료
kill -9 1234
# 프로세스 이름으로 종료
killall processname
# 모든 시그널 목록 표시
kill -l
# 특정 시그널 전송
kill -HUP 1234
```

<BaseQuiz id="linux-kill-1" correct="D">
  <template #question>
    <code>kill -9</code>는 프로세스에 어떤 시그널을 보냅니까?
  </template>
  
  <BaseQuizOption value="A">SIGTERM (정상 종료)</BaseQuizOption>
  <BaseQuizOption value="B">SIGHUP (연결 끊기)</BaseQuizOption>
  <BaseQuizOption value="C">SIGINT (인터럽트)</BaseQuizOption>
  <BaseQuizOption value="D" correct>SIGKILL (강제 종료, 무시 불가)</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>kill -9</code>는 SIGKILL 을 보내 프로세스를 즉시 강제 종료합니다. 이 시그널은 프로세스에 의해 캡처되거나 무시될 수 없으므로 응답하지 않는 프로세스를 종료하는 데 유용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 백그라운드 작업: `jobs`, `bg`, `fg`

백그라운드 및 포그라운드 프로세스를 관리합니다.

```bash
# 활성 작업 목록
jobs
# 작업을 백그라운드로 전송
bg %1
# 작업을 포그라운드로 가져오기
fg %1
# 명령을 백그라운드에서 실행
command &
# 터미널에서 분리
nohup command &
```

### 시스템 모니터: `htop`, `systemctl`

시스템 리소스를 모니터링하고 서비스를 관리합니다.

```bash
# 향상된 프로세스 뷰어 (설치된 경우)
htop
# 서비스 상태 확인
systemctl status servicename
# 서비스 시작
systemctl start servicename
# 부팅 시 서비스 활성화
systemctl enable servicename
# 시스템 로그 보기
journalctl -f
```

## 네트워크 작업

### 네트워크 구성: `ip`, `ifconfig`

네트워크 인터페이스를 표시하고 구성합니다.

```bash
# 네트워크 인터페이스 표시
ip addr show
# 라우팅 테이블 표시
ip route show
# 인터페이스 구성 (임시)
ip addr add 192.168.1.10/24 dev eth0
# 인터페이스 활성화/비활성화
ip link set eth0 up
# 레거시 인터페이스 구성
ifconfig
```

### 네트워크 테스트: `ping`, `traceroute`

네트워크 연결을 테스트하고 패킷 경로를 추적합니다.

```bash
# 연결 테스트
ping google.com
# 횟수 제한을 두고 핑
ping -c 4 192.168.1.1
# 목적지까지 경로 추적
traceroute google.com
# MTR - 네트워크 진단 도구
mtr google.com
```

<BaseQuiz id="linux-ping-1" correct="B">
  <template #question>
    <code>ping -c 4</code> 명령어는 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A">4 초 타임아웃으로 핑</BaseQuizOption>
  <BaseQuizOption value="B" correct>4 개의 핑 패킷을 보내고 중지</BaseQuizOption>
  <BaseQuizOption value="C">4 개의 다른 호스트에 핑</BaseQuizOption>
  <BaseQuizOption value="D">핑 사이에 4 초 대기</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-c</code> 옵션은 보낼 패킷 수를 지정합니다. <code>ping -c 4</code>는 정확히 4 개의 ICMP 에코 요청 패킷을 보내고 결과를 표시한 후 중지합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 포트 및 연결 분석: `netstat`, `ss`

네트워크 연결 및 수신 대기 중인 포트를 표시합니다.

```bash
# 모든 연결 표시
netstat -tuln
# 수신 대기 중인 포트 표시
netstat -tuln | grep LISTEN
# netstat의 최신 대체 도구
ss -tuln
# 포트를 사용하는 프로세스 표시
netstat -tulnp
# 특정 포트 확인
netstat -tuln | grep :80
```

### 파일 전송: `scp`, `rsync`

시스템 간에 파일을 안전하게 전송합니다.

```bash
# 원격 호스트로 파일 복사
scp file.txt user@host:/path/
# 원격 호스트에서 복사
scp user@host:/path/file.txt ./
# 디렉토리 동기화
rsync -avz localdir/ user@host:/remotedir/
# 진행률 표시하며 Rsync
rsync -avz --progress src/ dest/
```

## 텍스트 처리 및 검색

### 텍스트 검색: `grep`

파일 및 명령어 출력에서 패턴을 검색합니다.

```bash
# 파일에서 패턴 검색
grep "pattern" filename
# 대소문자 구분 없는 검색
grep -i "pattern" filename
# 디렉토리에서 재귀적 검색
grep -r "pattern" /path/
# 줄 번호 표시
grep -n "pattern" filename
# 일치하는 줄 수 계산
grep -c "pattern" filename
```

<BaseQuiz id="linux-grep-1" correct="A">
  <template #question>
    대소문자를 구분하지 않는 검색을 수행하는 <code>grep</code> 옵션은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A" correct>-i</BaseQuizOption>
  <BaseQuizOption value="B">-c</BaseQuizOption>
  <BaseQuizOption value="C">-n</BaseQuizOption>
  <BaseQuizOption value="D">-r</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-i</code> 옵션은 grep 을 대소문자 구분 없이 만들어 "Error", "ERROR", "error" 모두 일치시킵니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 텍스트 조작: `sed`, `awk`

스트림 편집기와 패턴 스캐너를 사용하여 텍스트를 편집하고 처리합니다.

```bash
# 파일 내 텍스트 바꾸기
sed 's/old/new/g' filename
# 패턴을 포함하는 줄 삭제
sed '/pattern/d' filename
# 특정 필드 출력
awk '{print $1, $3}' filename
# 열의 값 합산
awk '{sum += $1} END {print sum}' filename
```

### 정렬 및 개수: `sort`, `uniq`, `wc`

데이터 정렬, 중복 제거, 줄/단어/문자 수 계산.

```bash
# 파일 내용 정렬
sort filename
# 숫자순 정렬
sort -n numbers.txt
# 중복 줄 제거
uniq filename
# 정렬 후 중복 제거
sort filename | uniq
# 줄, 단어, 문자 수 계산
wc filename
# 줄 수만 계산
wc -l filename
```

### 잘라내기 및 붙여넣기: `cut`, `paste`

특정 열 추출 및 파일 결합.

```bash
# 첫 번째 열 추출
cut -d',' -f1 file.csv
# 문자 범위 추출
cut -c1-10 filename
# 파일들을 나란히 결합
paste file1.txt file2.txt
# 사용자 지정 구분자 사용
cut -d':' -f1,3 /etc/passwd
```

## 아카이브 및 압축

### 아카이브 생성: `tar`

압축 아카이브를 생성하고 추출합니다.

```bash
# tar 아카이브 생성
tar -cf archive.tar files/
# 압축 아카이브 생성
tar -czf archive.tar.gz files/
# 아카이브 추출
tar -xf archive.tar
# 압축 아카이브 추출
tar -xzf archive.tar.gz
# 아카이브 내용 목록 보기
tar -tf archive.tar
```

### 압축: `gzip`, `zip`

다양한 알고리즘을 사용하여 파일을 압축 및 압축 해제합니다.

```bash
# gzip으로 파일 압축
gzip filename
# gzip 파일 압축 해제
gunzip filename.gz
# zip 아카이브 생성
zip archive.zip file1 file2
# zip 아카이브 추출
unzip archive.zip
# zip 내용 목록 보기
unzip -l archive.zip
```

### 고급 아카이브: `tar` 옵션

백업 및 복원을 위한 고급 tar 작업.

```bash
# 압축을 사용하여 아카이브 생성
tar -czvf backup.tar.gz /home/user/
# 특정 디렉토리에 추출
tar -xzf archive.tar.gz -C /destination/
# 기존 아카이브에 파일 추가
tar -rf archive.tar newfile.txt
# 최신 파일로 아카이브 업데이트
tar -uf archive.tar files/
```

### 디스크 공간: `du`

디스크 사용량을 분석하고 디렉토리 크기를 확인합니다.

```bash
# 디렉토리 크기 표시
du -h /path/
# 총 크기 요약
du -sh /path/
# 모든 하위 디렉토리 크기 표시
du -h --max-depth=1 /path/
# 가장 큰 디렉토리 먼저
du -h | sort -hr | head -10
```

## 시스템 모니터링 및 성능

### 메모리 사용량: `free`, `vmstat`

메모리 사용량 및 가상 메모리 통계를 모니터링합니다.

```bash
# 메모리 사용량 요약
free -h
# 상세 메모리 통계
cat /proc/meminfo
# 가상 메모리 통계
vmstat
# 2초마다 메모리 사용량
vmstat 2
# 스왑 사용량 표시
swapon --show
```

### 디스크 I/O: `iostat`, `iotop`

디스크 입출력 성능을 모니터링하고 병목 현상을 식별합니다.

```bash
# I/O 통계 (sysstat 필요)
iostat
# 2초마다 I/O 통계
iostat 2
# 프로세스별 디스크 I/O 모니터링
iotop
# 특정 장치의 I/O 사용량 표시
iostat -x /dev/sda
```

### 시스템 로드: `top`, `htop`

시스템 로드, CPU 사용량 및 실행 중인 프로세스를 모니터링합니다.

```bash
# 실시간 프로세스 모니터
top
# 향상된 프로세스 뷰어
htop
# 로드 평균 표시
uptime
# CPU 정보 표시
lscpu
# 특정 프로세스 모니터링
top -p PID
```

### 로그 파일: `journalctl`, `dmesg`

시스템 로그를 보고 분석하여 문제 해결에 사용합니다.

```bash
# 시스템 로그 보기
journalctl
# 실시간으로 로그 추적
journalctl -f
# 특정 서비스의 로그 보기
journalctl -u servicename
# 커널 메시지
dmesg
# 마지막 부팅 메시지
dmesg | tail
```

## 사용자 및 권한 관리

### 사용자 작업: `useradd`, `usermod`, `userdel`

사용자 계정을 생성, 수정 및 삭제합니다.

```bash
# 새 사용자 추가
useradd username
# 홈 디렉토리와 함께 사용자 추가
useradd -m username
# 사용자 계정 수정
usermod -aG groupname username
# 사용자 계정 삭제
userdel username
# 홈 디렉토리와 함께 사용자 삭제
userdel -r username
```

### 그룹 관리: `groupadd`, `groups`

사용자 그룹을 생성하고 관리합니다.

```bash
# 새 그룹 생성
groupadd groupname
# 사용자의 그룹 표시
groups username
# 모든 그룹 표시
cat /etc/group
# 사용자를 그룹에 추가
usermod -aG groupname username
# 사용자의 기본 그룹 변경
usermod -g groupname username
```

### 사용자 전환: `su`, `sudo`

사용자를 전환하고 권한 상승하여 명령을 실행합니다.

```bash
# root 사용자로 전환
su -
# 특정 사용자로 전환
su - username
# root 권한으로 명령어 실행
sudo command
# 특정 사용자로 명령어 실행
sudo -u username command
# sudoers 파일 편집
visudo
```

### 암호 관리: `passwd`, `chage`

사용자 암호 및 계정 정책을 관리합니다.

```bash
# 암호 변경
passwd
# 다른 사용자의 암호 변경 (root 권한 필요)
passwd username
# 암호 만료 정보 표시
chage -l username
# 다음 로그인 시 암호 변경 강제 적용
passwd -e username
```

## 패키지 관리

### APT (Debian/Ubuntu): `apt`, `apt-get`

Debian 기반 시스템에서 패키지를 관리합니다.

```bash
# 패키지 목록 업데이트
apt update
# 모든 패키지 업그레이드
apt upgrade
# 패키지 설치
apt install packagename
# 패키지 제거
apt remove packagename
# 패키지 검색
apt search packagename
# 패키지 정보 표시
apt show packagename
```

### YUM/DNF (RHEL/Fedora): `yum`, `dnf`

Red Hat 기반 시스템에서 패키지를 관리합니다.

```bash
# 패키지 설치
yum install packagename
# 모든 패키지 업데이트
yum update
# 패키지 제거
yum remove packagename
# 패키지 검색
yum search packagename
# 설치된 패키지 목록
yum list installed
```

### Snap 패키지: `snap`

배포판 전반에 걸쳐 snap 패키지를 설치 및 관리합니다.

```bash
# snap 패키지 설치
snap install packagename
# 설치된 snap 목록
snap list
# snap 패키지 업데이트
snap refresh
# snap 패키지 제거
snap remove packagename
# snap 패키지 검색
snap find packagename
```

### Flatpak 패키지: `flatpak`

샌드박스 소프트웨어를 위한 Flatpak 애플리케이션을 관리합니다.

```bash
# flatpak 설치
flatpak install packagename
# 설치된 flatpak 목록
flatpak list
# flatpak 패키지 업데이트
flatpak update
# flatpak 제거
flatpak uninstall packagename
# flatpak 패키지 검색
flatpak search packagename
```

## 셸 및 스크립팅

### 명령어 기록: `history`

명령줄 기록에 접근하고 관리합니다.

```bash
# 명령어 기록 표시
history
# 마지막 10개 명령어 표시
history 10
# 이전 명령어 실행
!!
# 번호로 명령어 실행
!123
# 대화형으로 기록 검색
Ctrl+R
```

### 별칭 및 함수: `alias`

자주 사용하는 명령어에 대한 바로 가기를 만듭니다.

```bash
# 별칭 생성
alias ll='ls -la'
# 모든 별칭 표시
alias
# 별칭 제거
unalias ll
# 별칭 영구화 (.bashrc에 추가)
echo "alias ll='ls -la'" >> ~/.bashrc
```

### 입출력 리디렉션

명령어 입출력을 파일이나 다른 명령어로 리디렉션합니다.

```bash
# 파일로 출력 리디렉션
command > output.txt
# 파일에 출력 추가
command >> output.txt
# 파일에서 입력 리디렉션
command < input.txt
# stdout 및 stderr 모두 리디렉션
command &> output.txt
# 출력을 다른 명령어로 파이프
command1 | command2
```

### 환경 설정: `.bashrc`, `.profile`

셸 환경 및 시작 스크립트를 구성합니다.

```bash
# bash 구성 편집
nano ~/.bashrc
# 구성 다시 불러오기
source ~/.bashrc
# 환경 변수 설정
export VARIABLE=value
# PATH에 추가
export PATH=$PATH:/new/path
# 환경 변수 표시
printenv
```

## 시스템 설치 및 설정

### 배포판 옵션: Ubuntu, CentOS, Debian

다양한 사용 사례를 위한 Linux 배포판 선택 및 설치.

```bash
# Ubuntu 서버
wget ubuntu-server.iso
# CentOS Stream
wget centos-stream.iso
# Debian 안정 버전
wget debian.iso
# ISO 무결성 확인
sha256sum linux.iso
```

### 부팅 및 설치: USB, 네트워크

부팅 가능한 미디어 생성 및 시스템 설치 수행.

```bash
# 부팅 가능한 USB 생성 (Linux)
dd if=linux.iso of=/dev/sdX bs=4M
# 부팅 가능한 USB 생성 (크로스 플랫폼)
# Rufus, Etcher 또는 UNetbootin과 같은 도구 사용
# 네트워크 설치
# 네트워크 설치를 위한 PXE 부팅 구성
```

### 초기 구성: 사용자, 네트워크, SSH

설치 후 기본 시스템 구성.

```bash
# 호스트 이름 설정
hostnamectl set-hostname newname
# 정적 IP 구성
# Ubuntu의 경우 /etc/netplan/ 또는 /etc/network/interfaces 편집
# SSH 서비스 활성화
systemctl enable ssh
systemctl start ssh
# 방화벽 구성
ufw enable
ufw allow ssh
```

## 보안 및 모범 사례

### 방화벽 구성: `ufw`, `iptables`

네트워크 위협으로부터 시스템을 보호하기 위해 방화벽 규칙을 구성합니다.

```bash
# UFW 방화벽 활성화
ufw enable
# 특정 포트 허용
ufw allow 22/tcp
# 서비스 이름으로 허용
ufw allow ssh
# 액세스 거부
ufw deny 23
# 방화벽 상태 보기
ufw status verbose
# 고급 규칙은 iptables 사용
iptables -L
```

### 파일 무결성: `checksums`

파일 무결성을 확인하고 무단 변경을 감지합니다.

```bash
# MD5 체크섬 생성
md5sum filename
# SHA256 체크섬 생성
sha256sum filename
# 체크섬 확인
sha256sum -c checksums.txt
# 체크섬 파일 생성
sha256sum *.txt > checksums.txt
```

### 시스템 업데이트: 보안 패치

정기적인 업데이트 및 보안 패치로 시스템을 안전하게 유지합니다.

```bash
# Ubuntu 보안 업데이트
apt update && apt upgrade
# 자동 보안 업데이트
unattended-upgrades
# CentOS/RHEL 업데이트
yum update --security
# 사용 가능한 업데이트 목록
apt list --upgradable
```

### 로그 모니터링: 보안 이벤트

보안 이벤트 및 이상 징후를 위해 시스템 로그를 모니터링합니다.

```bash
# 인증 로그 모니터링
tail -f /var/log/auth.log
# 실패한 로그인 시도 확인
grep "Failed password" /var/log/auth.log
# 시스템 로그 모니터링
tail -f /var/log/syslog
# 로그인 기록 확인
last
# 의심스러운 활동 확인
journalctl -p err
```

## 문제 해결 및 복구

### 부팅 문제: GRUB 복구

부트 로더 및 커널 문제를 해결하기 위해 복구합니다.

```bash
# 복구 모드로 부팅
# 부팅 중 GRUB 메뉴 액세스
# 루트 파일 시스템 마운트
mount /dev/sda1 /mnt
# 시스템에 chroot
chroot /mnt
# GRUB 재설치
grub-install /dev/sda
# GRUB 구성 업데이트
update-grub
```

### 파일 시스템 복구: `fsck`

파일 시스템 손상을 확인하고 복구합니다.

```bash
# 파일 시스템 확인
fsck /dev/sda1
# 파일 시스템 강제 확인
fsck -f /dev/sda1
# 자동 복구
fsck -y /dev/sda1
# 마운트된 모든 파일 시스템 확인
fsck -A
```

### 서비스 문제: `systemctl`

서비스 관련 문제를 진단하고 해결합니다.

```bash
# 서비스 상태 확인
systemctl status servicename
# 서비스 로그 보기
journalctl -u servicename
# 실패한 서비스 재시작
systemctl restart servicename
# 부팅 시 서비스 활성화
systemctl enable servicename
# 실패한 서비스 목록
systemctl --failed
```

### 성능 문제: 리소스 분석

시스템 성능 병목 현상을 식별하고 해결합니다.

```bash
# 디스크 공간 확인
df -h
# I/O 사용량 모니터링
iotop
# 메모리 사용량 확인
free -h
# CPU 사용량 식별
top
# 열린 파일 목록
lsof
```

## 관련 링크

- <router-link to="/shell">셸 치트 시트</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>
- <router-link to="/git">Git 치트 시트</router-link>
- <router-link to="/ansible">Ansible 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/cybersecurity">사이버 보안 치트 시트</router-link>

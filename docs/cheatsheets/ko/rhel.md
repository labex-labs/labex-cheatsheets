---
title: 'Red Hat Enterprise Linux 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 포괄적인 치트 시트로 Red Hat Enterprise Linux 를 학습하세요.'
pdfUrl: '/cheatsheets/pdf/red-hat-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Red Hat Enterprise Linux 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/rhel">Hands-On Labs 로 Red Hat Enterprise Linux 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 Red Hat Enterprise Linux 를 학습하십시오. LabEx 는 필수 시스템 관리, 패키지 관리, 서비스 관리, 네트워크 구성, 스토리지 관리 및 보안을 다루는 포괄적인 RHEL 과정을 제공합니다. 엔터프라이즈 Linux 운영 및 시스템 관리 기술을 숙달하십시오.
</base-disclaimer-content>
</base-disclaimer>

## 시스템 정보 및 모니터링

### 시스템 버전: `cat /etc/redhat-release`

RHEL 버전 및 릴리스 정보를 표시합니다.

```bash
# RHEL 버전 표시
cat /etc/redhat-release
# 대체 방법
cat /etc/os-release
# 커널 버전 표시
uname -r
# 시스템 아키텍처 표시
uname -m
```

### 시스템 성능: `top` / `htop`

실행 중인 프로세스와 시스템 리소스 사용량을 표시합니다.

```bash
# 실시간 프로세스 모니터
top
# 향상된 프로세스 뷰어 (설치된 경우)
htop
# 프로세스 트리 표시
pstree
# 모든 프로세스 표시
ps aux
```

### 메모리 정보: `free` / `cat /proc/meminfo`

메모리 사용량 및 가용성을 표시합니다.

```bash
# 사람이 읽기 쉬운 형식으로 메모리 사용량 표시
free -h
# 상세 메모리 정보 표시
cat /proc/meminfo
# 스왑 사용량 표시
swapon --show
```

### 디스크 사용량: `df` / `du`

파일 시스템 및 디렉터리 사용량을 모니터링합니다.

```bash
# 파일 시스템 사용량 표시
df -h
# 디렉터리 크기 표시
du -sh /var/log/*
# 가장 큰 디렉터리 표시
du -h --max-depth=1 / | sort -hr
```

### 시스템 가동 시간: `uptime` / `who`

시스템 가동 시간과 로그인한 사용자를 확인합니다.

```bash
# 시스템 가동 시간 및 로드 표시
uptime
# 로그인한 사용자 표시
who
# 현재 사용자 표시
whoami
# 마지막 로그인 표시
last
```

### 하드웨어 정보: `lscpu` / `lsblk`

하드웨어 구성 요소를 표시합니다.

```bash
# CPU 정보 표시
lscpu
# 블록 장치 표시
lsblk
# PCI 장치 표시
lspci
# USB 장치 표시
lsusb
```

## 패키지 관리

### 패키지 설치: `dnf install` / `yum install`

소프트웨어 패키지 및 종속성을 설치합니다.

```bash
# 패키지 설치 (RHEL 8 이상)
sudo dnf install package-name
# 패키지 설치 (RHEL 7)
sudo yum install package-name
# 로컬 RPM 파일 설치
sudo rpm -i package.rpm
# 특정 저장소에서 설치
sudo dnf install --enablerepo=repo-
name package
```

### 패키지 업데이트: `dnf update` / `yum update`

패키지를 최신 버전으로 업데이트합니다.

```bash
# 모든 패키지 업데이트
sudo dnf update
# 특정 패키지 업데이트
sudo dnf update package-name
# 사용 가능한 업데이트 확인
dnf check-update
# 보안 패치만 업데이트
sudo dnf update --security
```

### 패키지 정보: `dnf info` / `rpm -q`

패키지 정보 및 종속성을 조회합니다.

```bash
# 패키지 정보 표시
dnf info package-name
# 설치된 패키지 목록
rpm -qa
# 패키지 검색
dnf search keyword
# 패키지 종속성 표시
dnf deplist package-name
```

## 파일 및 디렉터리 작업

### 탐색: `cd` / `pwd` / `ls`

파일 시스템을 탐색하고 내용을 나열합니다.

```bash
# 디렉터리 변경
cd /path/to/directory
# 현재 디렉터리 표시
pwd
# 파일 및 디렉터리 나열
ls -la
# 파일 크기와 함께 나열
ls -lh
# 숨겨진 파일 표시
ls -a
```

### 파일 작업: `cp` / `mv` / `rm`

파일 및 디렉터리를 복사, 이동 및 삭제합니다.

```bash
# 파일 복사
cp source.txt destination.txt
# 디렉터리 재귀적으로 복사
cp -r /source/dir/ /dest/dir/
# 파일 이동/이름 변경
mv oldname.txt newname.txt
# 파일 제거
rm filename.txt
# 디렉터리 재귀적으로 제거
rm -rf directory/
```

### 파일 내용: `cat` / `less` / `head` / `tail`

파일 내용을 보고 검사합니다.

```bash
# 파일 내용 표시
cat filename.txt
# 페이지별 파일 보기
less filename.txt
# 처음 10줄 표시
head filename.txt
# 마지막 10줄 표시
tail filename.txt
# 로그 파일 실시간 추적
tail -f /var/log/messages
```

### 파일 권한: `chmod` / `chown` / `chgrp`

파일 권한 및 소유권을 관리합니다.

```bash
# 파일 권한 변경
chmod 755 script.sh
# 파일 소유권 변경
sudo chown user:group filename.txt
# 그룹 소유권 변경
sudo chgrp newgroup filename.txt
# 재귀적 권한 변경
sudo chmod -R 644 /path/to/directory/
```

### 파일 검색: `find` / `locate` / `grep`

파일을 검색하고 파일 내의 내용을 검색합니다.

```bash
# 이름으로 파일 찾기
find /path -name "*.txt"
# 크기로 파일 찾기
find /path -size +100M
# 파일 내 텍스트 검색
grep "pattern" filename.txt
# 디렉터리 내 재귀적 텍스트 검색
grep -r "pattern" /path/to/directory/
```

### 아카이브 및 압축: `tar` / `gzip`

압축된 아카이브를 생성 및 추출합니다.

```bash
# tar 아카이브 생성
tar -czf archive.tar.gz /path/to/directory/
# tar 아카이브 추출
tar -xzf archive.tar.gz
# zip 아카이브 생성
zip -r archive.zip /path/to/directory/
# zip 아카이브 추출
unzip archive.zip
```

## 서비스 관리

### 서비스 제어: `systemctl`

systemd 를 사용하여 시스템 서비스를 관리합니다.

```bash
# 서비스 시작
sudo systemctl start service-name
# 서비스 중지
sudo systemctl stop service-name
# 서비스 재시작
sudo systemctl restart service-name
# 서비스 상태 확인
systemctl status service-name
# 부팅 시 서비스 활성화
sudo systemctl enable service-name
# 부팅 시 서비스 비활성화
sudo systemctl disable service-name
```

### 서비스 정보: `systemctl list-units`

시스템 서비스를 나열하고 조회합니다.

```bash
# 활성 서비스 목록
systemctl list-units --type=service
# 활성화된 모든 서비스 목록
systemctl list-unit-files --type=service --state=enabled
# 서비스 종속성 표시
systemctl list-dependencies service-name
```

### 시스템 로그: `journalctl`

journald 를 사용하여 시스템 로그를 보고 분석합니다.

```bash
# 모든 로그 보기
journalctl
# 특정 서비스 로그 보기
journalctl -u service-name
# 실시간으로 로그 추적
journalctl -f
# 마지막 부팅 로그 보기
journalctl -b
# 시간 범위별 로그 보기
journalctl --since "2024-01-01" --until "2024-01-31"
```

### 프로세스 관리: `ps` / `kill` / `killall`

실행 중인 프로세스를 모니터링하고 제어합니다.

```bash
# 실행 중인 프로세스 표시
ps aux
# PID로 프로세스 종료
kill 1234
# 이름으로 프로세스 종료
killall process-name
# 프로세스 강제 종료
kill -9 1234
# 프로세스 계층 구조 표시
pstree
```

## 사용자 및 그룹 관리

### 사용자 관리: `useradd` / `usermod` / `userdel`

사용자 계정을 생성, 수정 및 삭제합니다.

```bash
# 새 사용자 추가
sudo useradd -m username
# 사용자 암호 설정
sudo passwd username
# 사용자 계정 수정
sudo usermod -aG groupname
username
# 사용자 계정 삭제
sudo userdel -r username
# 사용자 계정 잠금
sudo usermod -L username
```

### 그룹 관리: `groupadd` / `groupmod` / `groupdel`

그룹을 생성, 수정 및 삭제합니다.

```bash
# 새 그룹 추가
sudo groupadd groupname
# 사용자를 그룹에 추가
sudo usermod -aG groupname
username
# 사용자를 그룹에서 제거
sudo gpasswd -d username
groupname
# 그룹 삭제
sudo groupdel groupname
# 사용자 그룹 목록
groups username
```

### 접근 제어: `su` / `sudo`

사용자 전환 및 권한 상승 명령 실행.

```bash
# root 사용자로 전환
su -
# 특정 사용자로 전환
su - username
# root 권한으로 명령 실행
sudo command
# sudoers 파일 편집
sudo visudo
# sudo 권한 확인
sudo -l
```

## 네트워크 구성

### 네트워크 정보: `ip` / `nmcli`

네트워크 인터페이스 및 구성 세부 정보를 표시합니다.

```bash
# 네트워크 인터페이스 표시
ip addr show
# 라우팅 테이블 표시
ip route show
# 네트워크 관리자 연결 표시
nmcli connection show
# 인터페이스 상태 표시
nmcli device status
```

### 네트워크 구성: `nmtui` / `nmcli`

NetworkManager 를 사용하여 네트워크 설정을 구성합니다.

```bash
# 텍스트 기반 네트워크 구성
sudo nmtui
# 새 연결 추가
sudo nmcli connection add type ethernet con-name
"eth0" ifname eth0
# 연결 수정
sudo nmcli connection modify "eth0" ipv4.addresses
192.168.1.100/24
# 연결 활성화
sudo nmcli connection up "eth0"
```

### 네트워크 테스트: `ping` / `curl` / `wget`

네트워크 연결을 테스트하고 파일을 다운로드합니다.

```bash
# 연결 테스트
ping google.com
# 특정 포트 테스트
telnet hostname 80
# 파일 다운로드
wget http://example.com/file.txt
# HTTP 요청 테스트
curl -I http://example.com
```

### 방화벽 관리: `firewall-cmd`

firewalld 를 사용하여 방화벽 규칙을 구성합니다.

```bash
# 방화벽 상태 표시
sudo firewall-cmd --state
# 활성 영역 목록
sudo firewall-cmd --get-active-zones
# 방화벽에 서비스 추가
sudo firewall-cmd --permanent --add-service=http
# 방화벽 규칙 다시 로드
sudo firewall-cmd --reload
```

## 스토리지 관리

### 디스크 관리: `fdisk` / `parted`

디스크 파티션을 생성하고 관리합니다.

```bash
# 디스크 파티션 목록
sudo fdisk -l
# 대화형 파티션 편집기
sudo fdisk /dev/sda
# 파티션 테이블 생성
sudo parted /dev/sda mklabel gpt
# 새 파티션 생성
sudo parted /dev/sda mkpart primary ext4 1MiB 100GiB
```

### 파일 시스템 관리: `mkfs` / `mount`

파일 시스템을 생성하고 스토리지 장치를 마운트합니다.

```bash
# ext4 파일 시스템 생성
sudo mkfs.ext4 /dev/sda1
# 파일 시스템 마운트
sudo mount /dev/sda1 /mnt/data
# 파일 시스템 마운트 해제
sudo umount /mnt/data
# 파일 시스템 검사
sudo fsck /dev/sda1
```

### LVM 관리: `pvcreate` / `vgcreate` / `lvcreate`

논리 볼륨 관리자 (LVM) 스토리지를 관리합니다.

```bash
# 물리적 볼륨 생성
sudo pvcreate /dev/sdb
# 볼륨 그룹 생성
sudo vgcreate vg_data /dev/sdb
# 논리 볼륨 생성
sudo lvcreate -L 10G -n lv_data vg_data
# 논리 볼륨 확장
sudo lvextend -L +5G /dev/vg_data/lv_data
```

### 마운트 구성: `/etc/fstab`

영구적인 마운트 지점을 구성합니다.

```bash
# fstab 파일 편집
sudo vi /etc/fstab
# fstab 항목 테스트
sudo mount -a
# 마운트된 파일 시스템 표시
mount | column -t
```

## 보안 및 SELinux

### SELinux 관리: `getenforce` / `setenforce`

SELinux 강제 적용 및 정책을 제어합니다.

```bash
# SELinux 상태 확인
getenforce
# SELinux를 허용 모드로 설정
sudo setenforce 0
# SELinux를 강제 모드로 설정
sudo setenforce 1
# SELinux 컨텍스트 확인
ls -Z filename
# SELinux 컨텍스트 변경
sudo chcon -t httpd_exec_t /path/to/file
```

### SELinux 도구: `sealert` / `ausearch`

SELinux 거부 및 감사 로그를 분석합니다.

```bash
# SELinux 경고 확인
sudo sealert -a /var/log/audit/audit.log
# 감사 로그 검색
sudo ausearch -m avc -ts recent
# SELinux 정책 생성
sudo audit2allow -M mypolicy < /var/log/audit/audit.log
```

### SSH 구성: `/etc/ssh/sshd_config`

안전한 원격 액세스를 위해 SSH 데몬을 구성합니다.

```bash
# SSH 구성 편집
sudo vi /etc/ssh/sshd_config
# SSH 서비스 재시작
sudo systemctl restart sshd
# SSH 연결 테스트
ssh user@hostname
# SSH 키 복사
ssh-copy-id user@hostname
```

### 시스템 업데이트: `dnf update`

정기적인 업데이트로 시스템을 안전하게 유지합니다.

```bash
# 모든 패키지 업데이트
sudo dnf update
# 보안 패치만 업데이트
sudo dnf update --security
# 사용 가능한 업데이트 확인
dnf check-update --security
# 자동 업데이트 활성화
sudo systemctl enable dnf-automatic.timer
```

## 성능 모니터링

### 시스템 모니터링: `iostat` / `vmstat`

시스템 성능 및 리소스 사용량을 모니터링합니다.

```bash
# I/O 통계 표시
iostat -x 1
# 가상 메모리 통계 표시
vmstat 1
# 네트워크 통계 표시
ss -tuln
# 디스크 I/O 표시
iotop
```

### 리소스 사용량: `sar` / `top`

과거 및 실시간 시스템 메트릭을 분석합니다.

```bash
# 시스템 활동 보고서
sar -u 1 3
# 메모리 사용량 보고서
sar -r
# 네트워크 활동 보고서
sar -n DEV
# 로드 평균 모니터링
uptime
```

### 프로세스 분석: `strace` / `lsof`

프로세스를 디버깅하고 파일 액세스를 확인합니다.

```bash
# 시스템 호출 추적
strace -p 1234
# 열린 파일 목록
lsof
# 프로세스가 연 파일 표시
lsof -p 1234
# 네트워크 연결 표시
lsof -i
```

### 성능 튜닝: `tuned`

특정 워크로드를 위해 시스템 성능을 최적화합니다.

```bash
# 사용 가능한 프로필 목록
tuned-adm list
# 활성 프로필 표시
tuned-adm active
# 성능 프로필 설정
sudo tuned-adm profile throughput-performance
# 사용자 정의 프로필 생성
sudo tuned-adm profile_mode
```

## RHEL 설치 및 설정

### 시스템 등록: `subscription-manager`

시스템을 Red Hat 고객 포털에 등록합니다.

```bash
# 시스템 등록
sudo subscription-manager
register --username
your_username
# 구독 자동 연결
sudo subscription-manager
attach --auto
# 사용 가능한 구독 목록
subscription-manager list --
available
# 시스템 상태 표시
subscription-manager status
```

### 저장소 관리: `dnf config-manager`

소프트웨어 저장소를 관리합니다.

```bash
# 활성화된 저장소 목록
dnf repolist
# 저장소 활성화
sudo dnf config-manager --
enable repository-name
# 저장소 비활성화
sudo dnf config-manager --
disable repository-name
# 새 저장소 추가
sudo dnf config-manager --add-
repo https://example.com/repo
```

### 시스템 구성: `hostnamectl` / `timedatectl`

기본 시스템 설정을 구성합니다.

```bash
# 호스트 이름 설정
sudo hostnamectl set-hostname
new-hostname
# 시스템 정보 표시
hostnamectl
# 시간대 설정
sudo timedatectl set-timezone
America/New_York
# 시간 설정 표시
timedatectl
```

## 문제 해결 및 진단

### 시스템 로그: `/var/log/`

문제 해결을 위해 시스템 로그 파일을 검사합니다.

```bash
# 시스템 메시지 보기
sudo tail -f /var/log/messages
# 인증 로그 보기
sudo tail -f /var/log/secure
# 부팅 로그 보기
sudo journalctl -b
# 커널 메시지 보기
dmesg | tail
```

### 하드웨어 진단: `dmidecode` / `lshw`

하드웨어 정보 및 상태를 검사합니다.

```bash
# 하드웨어 정보 표시
sudo dmidecode -t system
# 하드웨어 구성 요소 목록
sudo lshw -short
# 메모리 정보 확인
sudo dmidecode -t memory
# CPU 정보 표시
lscpu
```

### 네트워크 문제 해결: `netstat` / `ss`

네트워크 진단 도구 및 유틸리티.

```bash
# 네트워크 연결 표시
ss -tuln
# 라우팅 테이블 표시
ip route show
# DNS 확인 테스트
nslookup google.com
# 네트워크 경로 추적
traceroute google.com
```

### 복구 및 구조: `systemctl rescue`

시스템 복구 및 비상 절차.

```bash
# 구조 모드 진입
sudo systemctl rescue
# 비상 모드 진입
sudo systemctl emergency
# 실패한 서비스 재설정
sudo systemctl reset-failed
# 부트 로더 재구성
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

## 자동화 및 스크립팅

### Cron 작업: `crontab`

자동화된 작업 및 유지 관리를 예약합니다.

```bash
# 사용자 crontab 편집
crontab -e
# 사용자 crontab 목록
crontab -l
# 사용자 crontab 제거
crontab -r
# 예: 매일 오전 2시에 스크립트 실행
0 2 * * * /path/to/script.sh
```

### 쉘 스크립팅: `bash`

자동화를 위한 쉘 스크립트를 생성하고 실행합니다.

```bash
#!/bin/bash
# 간단한 백업 스크립트
DATE=$(date +%Y%m%d)
tar -czf backup_$DATE.tar.gz /home/user/documents
echo "백업 완료: backup_$DATE.tar.gz"
```

### 환경 변수: `export` / `env`

환경 변수 및 쉘 설정을 관리합니다.

```bash
# 환경 변수 설정
export MY_VAR="value"
# 모든 환경 변수 표시
env
# 특정 변수 표시
echo $PATH
# PATH에 추가
export PATH=$PATH:/new/directory
```

### 시스템 자동화: `systemd timers`

systemd 기반 예약 작업을 생성합니다.

```bash
# 타이머 유닛 파일 생성
sudo vi /etc/systemd/system/backup.timer
# 타이머 활성화 및 시작
sudo systemctl enable backup.timer
sudo systemctl start backup.timer
# 활성 타이머 목록
systemctl list-timers
```

## 관련 링크

- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/git">Git 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>
- <router-link to="/ansible">Ansible 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/cybersecurity">사이버 보안 치트 시트</router-link>

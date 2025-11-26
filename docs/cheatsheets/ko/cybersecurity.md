---
title: '사이버 보안 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 종합 치트 시트로 사이버 보안을 학습하세요.'
pdfUrl: '/cheatsheets/pdf/cybersecurity-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
사이버 보안 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/cybersecurity">실습형 랩을 통해 사이버 보안 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습형 랩과 실제 시나리오를 통해 사이버 보안을 학습하세요. LabEx 는 위협 식별, 보안 평가, 시스템 강화, 사고 대응 및 모니터링 기술을 다루는 포괄적인 사이버 보안 과정을 제공합니다. 업계 표준 도구와 모범 사례를 사용하여 시스템과 데이터를 사이버 위협으로부터 보호하는 방법을 배우십시오.
</base-disclaimer-content>
</base-disclaimer>

## 시스템 보안 기초

### 사용자 계정 관리

시스템 및 데이터 접근을 제어합니다.

```bash
# 새 사용자 추가
sudo adduser username
# 암호 정책 설정
sudo passwd -l username
# sudo 권한 부여
sudo usermod -aG sudo username
# 사용자 정보 보기
id username
# 모든 사용자 목록 보기
cat /etc/passwd
```

### 파일 권한 및 보안

안전한 파일 및 디렉터리 접근을 구성합니다.

```bash
# 파일 권한 변경 (읽기, 쓰기, 실행)
chmod 644 file.txt
# 소유권 변경
chown user:group file.txt
# 권한 재귀적으로 설정
chmod -R 755 directory/
# 파일 권한 보기
ls -la
```

### 네트워크 보안 구성

네트워크 연결 및 서비스를 보호합니다.

```bash
# 방화벽 구성 (UFW)
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw deny 23/tcp
# 열린 포트 확인
netstat -tuln
sudo ss -tuln
```

### 시스템 업데이트 및 패치

시스템을 최신 보안 패치로 유지합니다.

```bash
# 패키지 목록 업데이트 (Ubuntu/Debian)
sudo apt update
# 모든 패키지 업그레이드
sudo apt upgrade
# 자동 보안 업데이트
sudo apt install unattended-upgrades
```

### 서비스 관리

시스템 서비스를 제어하고 모니터링합니다.

```bash
# 불필요한 서비스 중지
sudo systemctl stop service_name
sudo systemctl disable service_name
# 서비스 상태 확인
sudo systemctl status ssh
# 실행 중인 서비스 보기
systemctl list-units --type=service --state=running
```

### 로그 모니터링

보안 이벤트를 위해 시스템 로그를 모니터링합니다.

```bash
# 인증 로그 보기
sudo tail -f /var/log/auth.log
# 시스템 로그 확인
sudo journalctl -f
# 실패한 로그인 검색
grep "Failed password" /var/log/auth.log
```

## 암호 보안 및 인증

강력한 인증 메커니즘과 암호 정책을 구현합니다.

### 강력한 암호 생성

모범 사례에 따라 안전한 암호를 생성하고 관리합니다.

```bash
# 강력한 암호 생성
openssl rand -base64 32
# 암호 강도 요구 사항:
# - 최소 12자
# - 대문자, 소문자, 숫자, 기호 혼합
# - 사전 단어 또는 개인 정보 사용 금지
# - 각 계정마다 고유해야 함
```

### 다중 요소 인증 (MFA)

암호 외에 추가 인증 계층을 추가합니다.

```bash
# Google Authenticator 설치
sudo apt install libpam-googleauthenticator
# SSH에 MFA 구성
google-authenticator
# SSH 구성에서 활성화
sudo nano /etc/pam.d/sshd
# 추가: auth required pam_google_authenticator.so
```

### 암호 관리

암호 관리자와 안전한 저장 관행을 사용합니다.

```bash
# 암호 관리자 설치 (KeePassXC)
sudo apt install keepassxc
# 모범 사례:
# - 각 서비스마다 고유한 암호 사용
# - 자동 잠금 기능 활성화
# - 중요 계정에 대한 정기적인 암호 로테이션
# - 암호 데이터베이스의 안전한 백업
```

## 네트워크 보안 및 모니터링

### 포트 스캐닝 및 검색

열린 포트와 실행 중인 서비스를 식별합니다.

```bash
# Nmap을 사용한 기본 포트 스캔
nmap -sT target_ip
# 서비스 버전 감지
nmap -sV target_ip
# 포괄적인 스캔
nmap -A target_ip
# 특정 포트 스캔
nmap -p 22,80,443 target_ip
# IP 범위 스캔
nmap 192.168.1.1-254
```

### 네트워크 트래픽 분석

네트워크 통신을 모니터링하고 분석합니다.

```bash
# tcpdump로 패킷 캡처
sudo tcpdump -i eth0
# 파일로 저장
sudo tcpdump -w capture.pcap
# 특정 트래픽 필터링
sudo tcpdump host 192.168.1.1
# 특정 포트 모니터링
sudo tcpdump port 80
```

### 방화벽 구성

들어오고 나가는 네트워크 트래픽을 제어합니다.

```bash
# UFW (Uncomplicated Firewall)
sudo ufw status
sudo ufw allow ssh
sudo ufw deny 23
# iptables 규칙
sudo iptables -L
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

### SSL/TLS 인증서 관리

암호화를 통해 안전한 통신을 구현합니다.

```bash
# 자체 서명 인증서 생성
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
# 인증서 세부 정보 확인
openssl x509 -in cert.pem -text -noout
# SSL 연결 테스트
openssl s_client -connect example.com:443
```

## 취약점 평가

### 시스템 취약점 스캐닝

시스템 및 애플리케이션의 보안 약점을 식별합니다.

```bash
# Nessus 스캐너 설치
# tenable.com에서 다운로드
sudo dpkg -i Nessus-X.X.X-ubuntu1404_amd64.deb
# Nessus 서비스 시작
sudo systemctl start nessusd
# 웹 인터페이스 접속: https://localhost:8834
# OpenVAS 사용 (무료 대안)
sudo apt install openvas
sudo gvm-setup
```

### 웹 애플리케이션 보안 테스트

웹 애플리케이션에 일반적인 취약점이 있는지 테스트합니다.

```bash
# Nikto 웹 스캐너 사용
nikto -h http://target.com
# 디렉터리 열거
dirb http://target.com
# SQL 인젝션 테스트
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

### 보안 감사 도구

포괄적인 보안 평가 유틸리티입니다.

```bash
# Lynis 보안 감사
sudo apt install lynis
sudo lynis audit system
# 루트킷 확인
sudo apt install chkrootkit
sudo chkrootkit
# 파일 무결성 모니터링
sudo apt install aide
sudo aideinit
```

### 구성 보안

안전한 시스템 및 애플리케이션 구성을 확인합니다.

```bash
# SSH 보안 검사
ssh-audit target_ip
# SSL 구성 테스트
testssl.sh https://target.com
# 민감한 파일의 파일 권한 확인
ls -la /etc/shadow /etc/passwd /etc/group
```

## 사고 대응 및 포렌식

### 로그 분석 및 조사

시스템 로그를 분석하여 보안 사고를 식별합니다.

```bash
# 의심스러운 활동 검색
grep -i "failed\|error\|denied" /var/log/auth.log
# 실패한 로그인 횟수 계산
grep "Failed password" /var/log/auth.log | wc -l
# 로그에서 고유 IP 주소 찾기
awk '/Failed password/ {print $11}' /var/log/auth.log | sort | uniq -c
# 실시간 로그 활동 모니터링
tail -f /var/log/syslog
```

### 네트워크 포렌식

네트워크 기반 보안 사고를 조사합니다.

```bash
# Wireshark로 네트워크 트래픽 분석
# 설치: sudo apt install wireshark
# 실시간 트래픽 캡처
sudo wireshark
# 캡처된 파일 분석
wireshark capture.pcap
# tshark를 사용한 명령줄 분석
tshark -r capture.pcap -Y "http.request"
```

### 시스템 포렌식

디지털 증거를 보존하고 분석합니다.

```bash
# 디스크 이미지 생성
sudo dd if=/dev/sda of=/mnt/evidence/disk_image.dd bs=4096
# 무결성 확인을 위한 파일 해시 계산
md5sum important_file.txt
sha256sum important_file.txt
# 특정 파일 내용 검색
grep -r "password" /home/user/
# 최근 수정된 파일 목록 보기
find /home -mtime -7 -type f
```

### 사고 문서화

분석을 위해 보안 사고를 적절하게 문서화합니다.

```bash
# 사고 대응 체크리스트:
# 1. 영향받는 시스템 격리
# 2. 증거 보존
# 3. 이벤트 타임라인 문서화
# 4. 공격 벡터 식별
# 5. 손상 및 데이터 노출 평가
# 6. 격리 조치 구현
# 7. 복구 절차 계획
```

## 위협 인텔리전스

현재 및 새로운 보안 위협에 대한 정보를 수집하고 분석합니다.

### OSINT (공개 출처 정보)

공개적으로 사용 가능한 위협 정보를 수집합니다.

```bash
# 도메인 정보 검색
whois example.com
# DNS 조회
dig example.com
nslookup example.com
# 하위 도메인 찾기
sublist3r -d example.com
# 평판 데이터베이스 확인
# VirusTotal, URLVoid, AbuseIPDB
```

### 위협 헌팅 도구

환경 내에서 위협을 선제적으로 검색합니다.

```bash
# IOC (침해 지표) 검색
grep -r "suspicious_hash" /var/log/
# 악성 IP 확인
grep "192.168.1.100" /var/log/auth.log
# 파일 해시 비교
find /tmp -type f -exec sha256sum {} \;
```

### 위협 피드 및 인텔리전스

최신 위협 정보로 최신 상태를 유지합니다.

```bash
# 인기 있는 위협 인텔리전스 출처:
# - MISP (Malware Information Sharing Platform)
# - STIX/TAXII 피드
# - 상용 피드 (CrowdStrike, FireEye)
# - 정부 피드 (US-CERT, CISA)
# 예시: 위협 피드에 IP 확인
curl -s "https://api.threatintel.com/check?ip=1.2.3.4"
```

### 위협 모델링

잠재적인 보안 위협을 식별하고 평가합니다.

```bash
# STRIDE 위협 모델 범주:
# - 스푸핑 (신원)
# - 변조 (데이터)
# - 부인 (행위)
# - 정보 공개
# - 서비스 거부
# - 권한 상승
```

## 암호화 및 데이터 보호

민감한 데이터를 보호하기 위해 강력한 암호화를 구현합니다.

### 파일 및 디스크 암호화

저장된 데이터를 보호하기 위해 파일 및 저장 장치를 암호화합니다.

```bash
# GPG로 파일 암호화
gpg -c sensitive_file.txt
# 파일 복호화
gpg sensitive_file.txt.gpg
# LUKS를 사용한 전체 디스크 암호화
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup luksOpen /dev/sdb encrypted_drive
# SSH 키 생성
ssh-keygen -t rsa -b 4096
# SSH 키 인증 설정
ssh-copy-id user@server
```

### 네트워크 암호화

암호화 프로토콜을 사용하여 네트워크 통신을 보호합니다.

```bash
# OpenVPN을 사용한 VPN 설정
sudo apt install openvpn
sudo openvpn --config client.ovpn
```

### 인증서 관리

안전한 통신을 위해 디지털 인증서를 관리합니다.

```bash
# 인증 기관 생성
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -key ca-key.pem -out ca.pem
# 서버 인증서 생성
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr
# CA로 인증서 서명
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -out server.pem
```

### 데이터 손실 방지

무단 데이터 유출 및 누출을 방지합니다.

```bash
# 파일 접근 모니터링
sudo apt install auditd
# 감사 규칙 구성
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
# 감사 로그 검색
sudo ausearch -k passwd_changes
```

## 보안 자동화 및 오케스트레이션

보안 작업을 자동화하고 대응 절차를 조정합니다.

### 보안 스캔 자동화

정기적인 보안 스캔 및 평가를 예약합니다.

```bash
# 자동화된 Nmap 스캔 스크립트
#!/bin/bash
DATE=$(date +%Y-%m-%d)
nmap -sS -O 192.168.1.0/24 > /var/log/nmap-scan-$DATE.log
# cron으로 예약
# 0 2 * * * /path/to/security-scan.sh
```

```bash
# 자동화된 취약점 스캔
#!/bin/bash
nikto -h $1 -o /var/log/nikto-$(date +%Y%m%d).txt
```

### 로그 모니터링 스크립트

로그 분석 및 경고를 자동화합니다.

```bash
# 실패한 로그인 모니터링
#!/bin/bash
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | tail -n 100 | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    echo "High number of failed logins detected: $FAILED_LOGINS" | mail -s "Security Alert" admin@company.com
fi
```

### 사고 대응 자동화

초기 사고 대응 절차를 자동화합니다.

```bash
# 자동화된 위협 대응 스크립트
#!/bin/bash
SUSPICIOUS_IP=$1
# 방화벽에서 IP 차단
sudo ufw deny from $SUSPICIOUS_IP
# 조치 기록
echo "$(date): Blocked suspicious IP $SUSPICIOUS_IP" >> /var/log/security-actions.log
# 경고 전송
echo "Blocked suspicious IP: $SUSPICIOUS_IP" | mail -s "IP Blocked" security@company.com
```

### 구성 관리

안전한 시스템 구성을 유지합니다.

```bash
# Ansible 보안 플레이북 예시
---
- name: Harden SSH configuration
  hosts: all
  tasks:
    - name: Disable root login
      lineinfile:
        path: /etc/ssh/sshd_config
        line: 'PermitRootLogin no'
    - name: Restart SSH service
      service:
        name: sshd
        state: restarted
```

## 규정 준수 및 위험 관리

보안 정책 및 절차를 구현하고 유지합니다.

### 보안 정책 구현

보안 정책 및 절차를 구현하고 유지합니다.

```bash
# PAM을 통한 암호 정책 시행
sudo nano /etc/pam.d/common-password
# 추가: password required pam_pwquality.so minlen=12
# 계정 잠금 정책
sudo nano /etc/pam.d/common-auth
# 추가: auth required pam_tally2.so deny=5 unlock_time=900
```

### 감사 및 규정 준수 확인

보안 표준 및 규정에 대한 준수 여부를 확인합니다.

```bash
# CIS (Center for Internet Security) 벤치마크 도구
sudo apt install cis-cat-lite
# CIS 평가 실행
./CIS-CAT.sh -a -s
```

### 위험 평가 도구

보안 위험을 평가하고 정량화합니다.

```bash
# 위험 행렬 계산:
# 위험 = 가능성 × 영향
# 낮음 (1-3), 중간 (4-6), 높음 (7-9)
# 취약점 우선순위 지정
# CVSS 점수 계산
# 기본 점수 = 영향 × 공격 용이성
```

### 문서화 및 보고

적절한 보안 문서화 및 보고를 유지합니다.

```bash
# 보안 사고 보고서 템플릿:
# - 사고 날짜 및 시간
# - 영향받은 시스템
# - 식별된 공격 벡터
# - 손상된 데이터
# - 취한 조치
# - 얻은 교훈
# - 복구 계획
```

## 보안 도구 설치

필수 사이버 보안 도구를 설치하고 구성합니다.

### 패키지 관리자

시스템 패키지 관리자를 사용하여 도구를 설치합니다.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap wireshark tcpdump
# CentOS/RHEL
sudo yum install nmap wireshark tcpdump
# Arch Linux
sudo pacman -S nmap wireshark-qt tcpdump
```

### 보안 배포판

보안 전문가를 위한 특수 Linux 배포판입니다.

```bash
# Kali Linux - 침투 테스트
# 다운로드: https://www.kali.org/
# Parrot Security OS
# 다운로드: https://www.parrotsec.org/
# BlackArch Linux
# 다운로드: https://blackarch.org/
```

### 도구 확인

도구 설치 및 기본 구성을 확인합니다.

```bash
# 도구 버전 확인
nmap --version
wireshark --version
# 기본 기능 테스트
nmap 127.0.0.1
# 도구 경로 구성
export PATH=$PATH:/opt/tools/bin
echo 'export PATH=$PATH:/opt/tools/bin' >> ~/.bashrc
```

## 보안 구성 모범 사례

시스템 및 애플리케이션 전반에 걸쳐 보안 강화 구성을 적용합니다.

### 시스템 강화

운영 체제 구성을 보호합니다.

```bash
# 불필요한 서비스 비활성화
sudo systemctl disable telnet
sudo systemctl disable ftp
# 안전한 파일 권한 설정
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 644 /etc/passwd
# 시스템 제한 구성
echo "* hard core 0" >> /etc/security/limits.conf
```

### 네트워크 보안 설정

안전한 네트워크 구성을 구현합니다.

```bash
# IP 포워딩 비활성화 (라우터가 아닌 경우)
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
# SYN 쿠키 활성화
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
# ICMP 리디렉션 비활성화
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
```

### 애플리케이션 보안

애플리케이션 및 서비스 구성을 보호합니다.

```bash
# Apache 보안 헤더
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
# Nginx 보안 구성
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
```

### 백업 및 복구 보안

안전한 백업 및 재해 복구 절차를 구현합니다.

```bash
# rsync를 사용한 암호화된 백업
rsync -av --password-file=/etc/rsyncd.secrets /data/ backup@server::backups/
# 백업 무결성 테스트
tar -tzf backup.tar.gz > /dev/null && echo "Backup OK"
# 자동 백업 확인
#!/bin/bash
find /backups -name "*.tar.gz" -exec tar -tzf {} \; > /dev/null
```

## 고급 보안 기술

고급 보안 조치 및 방어 전략을 구현합니다.

### 침입 탐지 시스템

위협 탐지를 위해 IDS/IPS를 배포하고 구성합니다.

```bash
# Suricata IDS 설치
sudo apt install suricata
# 규칙 구성
sudo nano /etc/suricata/suricata.yaml
# 규칙 업데이트
sudo suricata-update
# Suricata 시작
sudo systemctl start suricata
# 경고 모니터링
tail -f /var/log/suricata/fast.log
```

### 보안 정보 및 이벤트 관리 (SIEM)

보안 로그 및 이벤트를 중앙 집중화하고 분석합니다.

```bash
# ELK 스택 (Elasticsearch, Logstash, Kibana)
# Elasticsearch 설치
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update && sudo apt install elasticsearch
```

## 보안 인식 및 교육

사회 공학 공격을 인식하고 방지합니다.

### 사회 공학 방어

사회 공학 공격을 인식하고 방지합니다.

```bash
# 피싱 식별 기술:
# - 보낸 사람 이메일 주의 깊게 확인
# - 클릭하기 전에 링크 확인 (마우스 오버)
# - 철자/문법 오류 확인
# - 긴급한 요청에 대해 의심하기
# - 별도의 채널을 통해 요청 확인
# 확인해야 할 이메일 보안 헤더:
# SPF, DKIM, DMARC 레코드
```

### 보안 문화 개발

보안 인식을 갖춘 조직 문화를 구축합니다.

```bash
# 보안 인식 프로그램 요소:
# - 정기적인 교육 세션
# - 피싱 시뮬레이션 테스트
# - 보안 정책 업데이트
# - 사고 보고 절차
# - 우수한 보안 관행에 대한 인정
# 추적할 메트릭:
# - 교육 완료율
# - 피싱 시뮬레이션 클릭률
# - 보안 사고 보고 건수
```

## 관련 링크

- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/kali">Kali Linux 치트 시트</router-link>
- <router-link to="/nmap">Nmap 치트 시트</router-link>
- <router-link to="/wireshark">Wireshark 치트 시트</router-link>
- <router-link to="/hydra">Hydra 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/git">Git 치트 시트</router-link>

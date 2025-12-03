---
title: 'Hydra 치트 시트 | LabEx'
description: '포괄적인 치트 시트로 Hydra 비밀번호 크래킹을 학습하세요. 무차별 대입 공격, 비밀번호 감사, 보안 테스트, 인증 프로토콜 및 침투 테스트 도구에 대한 빠른 참조 자료입니다.'
pdfUrl: '/cheatsheets/pdf/hydra-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hydra 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/hydra">핸즈온 랩으로 Hydra 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
핸즈온 랩과 실제 시나리오를 통해 Hydra 암호 크래킹 및 침투 테스트를 학습하세요. LabEx 는 프로토콜 공격, 웹 양식 악용, 성능 최적화 및 윤리적 사용을 다루는 포괄적인 Hydra 과정을 제공합니다. 승인된 보안 테스트 및 취약성 평가를 위한 무차별 대입 기술을 마스터하세요.
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

<BaseQuiz id="hydra-syntax-1" correct="B">
  <template #question>
    Hydra 에서 <code>-l</code> 과 <code>-L</code> 의 차이점은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A"><code>-l</code> 은 암호용이고, <code>-L</code> 은 사용자 이름용입니다</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>-l</code> 은 단일 사용자 이름을 지정하고, <code>-L</code> 은 사용자 이름 목록 파일을 지정합니다</BaseQuizOption>
  <BaseQuizOption value="C">차이점이 없습니다</BaseQuizOption>
  <BaseQuizOption value="D"><code>-l</code> 은 소문자이고, <code>-L</code> 은 대문자입니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-l</code> 옵션은 단일 사용자 이름에 사용되며, <code>-L</code> 은 사용자 이름 목록이 포함된 파일을 지정하는 데 사용됩니다. 마찬가지로 <code>-p</code> 는 단일 암호에 사용되고 <code>-P</code> 는 암호 목록 파일에 사용됩니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 핵심 옵션: `-l`, `-L`, `-p`, `-P`

무차별 대입 공격에 사용할 사용자 이름과 암호를 지정합니다.

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

결과를 파일에 저장하여 나중에 분석합니다.

```bash
# 결과를 파일에 저장
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# JSON 출력 형식
hydra -l admin -P passwords.txt target.com ssh -b json
# 자세한 출력
hydra -l admin -P passwords.txt target.com ssh -V
```

<BaseQuiz id="hydra-output-1" correct="A">
  <template #question>
    <code>hydra -V</code>는 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A" correct>자세한 진행 상황을 보여주는 자세한 출력을 활성화합니다</BaseQuizOption>
  <BaseQuizOption value="B">단어 목록 파일을 확인합니다</BaseQuizOption>
  <BaseQuizOption value="C">Hydra 버전을 표시합니다</BaseQuizOption>
  <BaseQuizOption value="D">자세한 모드로만 실행됩니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-V</code> 플래그는 자세한 모드를 활성화하여 각 로그인 시도를 포함한 상세 출력을 표시하므로 암호 공격 중 진행 상황을 모니터링하고 문제를 디버깅하기가 더 쉽습니다.
  </BaseQuizAnswer>
</BaseQuiz>

## 프로토콜별 공격

### SSH: `hydra 대상 ssh`

사용자 이름과 암호 조합으로 SSH 서비스 공격.

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

<BaseQuiz id="hydra-ssh-1" correct="C">
  <template #question>
    Hydra 에서 <code>-s</code> 플래그는 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A">서비스 유형을 설정합니다</BaseQuizOption>
  <BaseQuizOption value="B">스텔스 모드를 활성화합니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>사용자 지정 포트 번호를 지정합니다</BaseQuizOption>
  <BaseQuizOption value="D">스레드 수를 설정합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-s</code> 플래그는 서비스가 표준 포트 22 가 아닌 다른 포트에서 실행될 때 사용자 지정 포트 번호를 지정합니다. 예를 들어, <code>-s 2222</code>는 포트 2222 의 SSH 를 대상으로 합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### FTP: `hydra 대상 ftp`

FTP 로그인 자격 증명 무차별 대입 공격.

```bash
# 기본 FTP 공격
hydra -l admin -P passwords.txt ftp://192.168.1.100
# 익명 FTP 확인
hydra -l anonymous -p "" ftp://192.168.1.100
# 사용자 지정 FTP 포트
hydra -l user -P passwords.txt -s 2121 192.168.1.100 ftp
```

### 데이터베이스 공격: `mysql`, `postgres`, `mssql`

자격 증명 무차별 대입 공격으로 데이터베이스 서비스 공격.

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

이메일 서버 인증 공격.

```bash
# SMTP 무차별 대입 공격
hydra -l admin -P passwords.txt smtp://mail.target.com
# 널/빈 암호 사용
hydra -P passwords.txt -e ns -V -s 25 smtp.target.com smtp
# IMAP 공격
hydra -l user -P passwords.txt imap://mail.target.com
```

## 웹 애플리케이션 공격

### HTTP POST 양식: `http-post-form`

플레이스홀더 `^USER^` 및 `^PASS^`를 사용하여 HTTP POST 메서드로 웹 로그인 양식 공격.

```bash
# 기본 POST 양식 공격
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
# 사용자 지정 오류 메시지 사용
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid password"
# 성공 조건 사용
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/admin:username=^USER^&password=^PASS^:S=Dashboard"
```

### HTTP GET 양식: `http-get-form`

GET 요청을 대상으로 한다는 점을 제외하고 POST 양식과 유사합니다.

```bash
# GET 양식 공격
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# 사용자 지정 헤더 사용
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/auth:user=^USER^&pass=^PASS^:F=Error:H=Cookie: session=abc123"
```

### HTTP 기본 인증: `http-get`/`http-post`

HTTP 기본 인증을 사용하여 웹 서버 공격.

```bash
# HTTP 기본 인증
hydra -l admin -P passwords.txt http-get://192.168.1.100
# HTTPS 기본 인증
hydra -l admin -P passwords.txt https-get://secure.target.com
# 사용자 지정 경로 사용
hydra -l admin -P passwords.txt http-get://192.168.1.100/admin
```

### 고급 웹 공격

CSRF 토큰 및 쿠키를 사용하여 복잡한 웹 애플리케이션 처리.

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
# 보수적인 스레딩 (탐지 방지)
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

파일에 지정하여 여러 호스트 공격.

```bash
# 대상 파일 생성
echo "192.168.1.100" > targets.txt
echo "192.168.1.101" >> targets.txt
echo "192.168.1.102" >> targets.txt
# 여러 대상 공격
hydra -L users.txt -P passwords.txt -M targets.txt ssh
# 대상별 사용자 지정 스레딩 사용
hydra -L users.txt -P passwords.txt -M targets.txt -t 2 ssh
```

### 재개 및 중지 옵션

중단된 공격 재개 및 중지 동작 제어.

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
# 널 암호 테스트
hydra -l admin -e n target.com ssh
# 사용자 이름을 암호로 테스트
hydra -l admin -e s target.com ssh
# 사용자 이름 역순 테스트
hydra -l admin -e r target.com ssh
# 모든 옵션 결합
hydra -l admin -e nsr -P passwords.txt target.com ssh
```

### 콜론 구분 형식: `-C`

공격 시간을 줄이기 위해 사용자 이름:암호 조합 사용.

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

환경 변수를 사용하여 프록시 서버를 통해 공격.

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

정책에 따라 암호 목록을 필터링하기 위해 pw-inspector 사용.

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
승인된 권한을 얻은 후에만 시스템에 대한 공격 수행
항상 시스템 소유자 또는 관리자로부터 명시적인 승인을 받았는지 확인
규정 준수를 위해 모든 테스트 활동 문서화
승인된 침투 테스트 중에만 사용
무단 액세스 시도에 절대 사용하지 않음
```

### 방어 조치

강력한 암호 및 정책으로 무차별 대입 공격 방어.

```text
실패 시도 후 계정을 일시적으로 잠그는 계정 잠금 정책 구현
다단계 인증 (MFA) 사용
자동화 도구 방지를 위해 CAPTCHA 시스템 구현
인증 시도 모니터링 및 로깅
속도 제한 및 IP 차단 구현
```

### 테스트 모범 사례

보수적인 설정으로 시작하고 투명성을 위해 모든 활동을 문서화합니다.

```text
서비스 중단을 방지하기 위해 낮은 스레드 수로 시작
대상 환경에 적합한 단어 목록 사용
가능한 경우 승인된 유지 관리 기간 동안 테스트
테스트 중 대상 시스템 성능 모니터링
사고 대응 절차 준비
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

XHydra 는 명령줄 스위치 대신 GUI 를 통해 구성을 선택할 수 있도록 하는 Hydra 의 GUI 입니다.

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

간단한 질문을 통해 hydra 설정을 안내하는 대화형 마법사.

```bash
# 대화형 마법사 실행
hydra-wizard
# 마법사가 요청하는 항목:
# 1. 공격할 서비스
# 2. 공격할 대상
# 3. 사용자 이름 또는 사용자 이름 파일
# 4. 암호 또는 암호 파일
# 5. 추가 암호 테스트
# 6. 포트 번호
# 7. 최종 확인
```

### 기본 암호 목록: `dpl4hydra`

특정 브랜드 및 시스템에 대한 기본 암호 목록 생성.

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

정찰 및 열거 도구와 Hydra 결합.

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

Hydra 사용 중 발생하는 일반적인 문제 해결.

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
# 성공만 출력
hydra -l admin -P passwords.txt target.com ssh | grep "password:"
```

### 리소스 모니터링

공격 중 시스템 및 네트워크 리소스 모니터링.

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

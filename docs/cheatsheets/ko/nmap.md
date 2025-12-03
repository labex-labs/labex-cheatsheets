---
title: 'Nmap 치트 시트 | LabEx'
description: '이 포괄적인 치트 시트로 Nmap 네트워크 스캐닝을 배우세요. 포트 스캐닝, 네트워크 검색, 취약점 탐지, 보안 감사 및 네트워크 정찰을 위한 빠른 참조 자료입니다.'
pdfUrl: '/cheatsheets/pdf/nmap-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Nmap 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/nmap">Hands-On Labs 로 Nmap 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 기반 랩과 실제 시나리오를 통해 Nmap 네트워크 스캐닝을 학습하세요. LabEx 는 필수적인 네트워크 검색, 포트 스캐닝, 서비스 감지, OS 핑거프린팅 및 취약점 평가를 다루는 포괄적인 Nmap 과정을 제공합니다. 네트워크 정찰 및 보안 감사 기술을 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 설치 및 설정

### Linux 설치

배포판의 패키지 관리자를 사용하여 Nmap 을 설치합니다.

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap
# RHEL/Fedora/CentOS
sudo dnf install nmap
# 설치 확인
nmap --version
```

### macOS 설치

Homebrew 패키지 관리자를 사용하여 설치합니다.

```bash
# Homebrew를 통한 설치
brew install nmap
# nmap.org에서 직접 다운로드
# https://nmap.org/download.html 에서 .dmg 다운로드
```

### Windows 설치

공식 웹사이트에서 다운로드하여 설치합니다.

```bash
# 공식 웹사이트에서 설치 프로그램 다운로드
https://nmap.org/download.html
# 관리자 권한으로 .exe 설치 프로그램 실행
# Zenmap GUI 및 명령줄 버전 포함
```

### 기본 확인

설치를 테스트하고 도움말을 확인합니다.

```bash
# 버전 정보 표시
nmap --version
# 도움말 메뉴 표시
nmap -h
# 확장 도움말 및 옵션
man nmap
```

## 기본 스캐닝 기술

### 간단한 호스트 스캔: `nmap [대상]`

단일 호스트 또는 IP 주소에 대한 기본 스캔입니다.

```bash
# 단일 IP 스캔
nmap 192.168.1.1
# 호스트 이름 스캔
nmap example.com
# 여러 IP 스캔
nmap 192.168.1.1 192.168.1.5
192.168.1.10
```

<BaseQuiz id="nmap-scan-1" correct="A">
  <template #question>
    기본 <code>nmap 192.168.1.1</code> 스캔은 기본적으로 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A" correct>가장 일반적인 1000 개 TCP 포트를 스캔합니다</BaseQuizOption>
  <BaseQuizOption value="B">모든 65535 개 포트를 스캔합니다</BaseQuizOption>
  <BaseQuizOption value="C">호스트 검색만 수행합니다</BaseQuizOption>
  <BaseQuizOption value="D">포트 80 만 스캔합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    기본적으로 Nmap 은 가장 일반적인 1000 개 TCP 포트를 스캔합니다. 모든 포트를 스캔하려면 <code>-p-</code> 를 사용하거나 <code>-p 80,443,22</code>로 특정 포트를 지정합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 네트워크 범위 스캔

Nmap 은 호스트 이름, IP 주소, 서브넷을 허용합니다.

```bash
# IP 범위 스캔
nmap 192.168.1.1-254
# CIDR 표기법을 사용한 서브넷 스캔
nmap 192.168.1.0/24
# 여러 네트워크 스캔
nmap 192.168.1.0/24 10.0.0.0/8
```

### 파일에서 입력받기

파일에 나열된 대상을 스캔합니다.

```bash
# 파일에서 대상 읽기
nmap -iL targets.txt
# 특정 호스트 제외
nmap 192.168.1.0/24 --exclude
192.168.1.1
# 파일에서 제외
nmap 192.168.1.0/24 --excludefile
exclude.txt
```

## 호스트 검색 기술

### 핑 스캔: `nmap -sn`

호스트 검색은 많은 분석가와 침투 테스터가 Nmap 을 사용하는 주요 방법입니다. 그 목적은 어떤 시스템이 온라인 상태인지에 대한 개요를 얻는 것입니다.

```bash
# 핑 스캔만 (포트 스캔 없음)
nmap -sn 192.168.1.0/24
# 호스트 검색 건너뛰기 (모든 호스트가 활성 상태라고 가정)
nmap -Pn 192.168.1.1
# ICMP 에코 핑
nmap -PE 192.168.1.0/24
```

<BaseQuiz id="nmap-ping-1" correct="A">
  <template #question>
    <code>nmap -sn</code>은 무엇을 합니까?
  </template>
  
  <BaseQuizOption value="A" correct>포트 스캔 없이 호스트 검색만 수행합니다</BaseQuizOption>
  <BaseQuizOption value="B">대상의 모든 포트를 스캔합니다</BaseQuizOption>
  <BaseQuizOption value="C">은밀한 스캔을 수행합니다</BaseQuizOption>
  <BaseQuizOption value="D">UDP 포트만 스캔합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-sn</code> 플래그는 Nmap 에게 포트 스캔 없이 호스트 검색 (핑 스캔) 만 수행하도록 지시합니다. 이는 네트워크에서 어떤 호스트가 온라인 상태인지 빠르게 식별하는 데 유용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### TCP 핑 기술

호스트 검색을 위해 TCP 패킷을 사용합니다.

```bash
# 포트 80으로 TCP SYN 핑
nmap -PS80 192.168.1.0/24
# TCP ACK 핑
nmap -PA80 192.168.1.0/24
# 여러 포트로 TCP SYN 핑
nmap -PS22,80,443 192.168.1.0/24
```

### UDP 핑: `nmap -PU`

호스트 검색을 위해 UDP 패킷을 사용합니다.

```bash
# 일반적인 포트로 UDP 핑
nmap -PU53,67,68,137 192.168.1.0/24
```

<BaseQuiz id="nmap-udp-1" correct="B">
  <template #question>
    ICMP 핑 대신 UDP 핑을 사용하는 이유는 무엇일 수 있습니까?
  </template>
  
  <BaseQuizOption value="A">UDP 핑이 항상 더 빠릅니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>일부 네트워크는 ICMP 를 차단하지만 UDP 패킷은 허용합니다</BaseQuizOption>
  <BaseQuizOption value="C">UDP 핑은 포트를 자동으로 스캔합니다</BaseQuizOption>
  <BaseQuizOption value="D">UDP 핑은 로컬 네트워크에서만 작동합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    UDP 핑은 ICMP 가 방화벽에 의해 차단될 때 유용할 수 있습니다. 많은 네트워크에서 ICMP 는 필터링되더라도 일반 포트 (예: DNS 포트 53) 로의 UDP 패킷은 허용하므로 UDP 핑은 호스트 검색에 효과적입니다.
  </BaseQuizAnswer>
</BaseQuiz>
# 기본 포트로 UDP 핑
nmap -PU 192.168.1.0/24
```

### ARP 핑: `nmap -PR`

로컬 네트워크 검색을 위해 ARP 요청을 사용합니다.

```bash
# ARP 핑 (로컬 네트워크의 기본값)
nmap -PR 192.168.1.0/24
# ARP 핑 비활성화
nmap --disable-arp-ping 192.168.1.0/24
```

## 포트 스캐닝 유형

### TCP SYN 스캔: `nmap -sS`

이 스캔은 Nmap이 RST 패킷을 보내므로 더 은밀하며, 여러 요청을 방지하고 스캔 시간을 단축합니다.

```bash
# 기본 스캔 (루트 필요)
nmap -sS 192.168.1.1
# 특정 포트 SYN 스캔
nmap -sS -p 80,443 192.168.1.1
# 빠른 SYN 스캔
nmap -sS -T4 192.168.1.1
```

### TCP Connect 스캔: `nmap -sT`

Nmap은 SYN 플래그가 설정된 TCP 패킷을 포트로 보냅니다. 이를 통해 사용자는 포트가 열려 있는지, 닫혀 있는지 또는 알 수 없는지 알 수 있습니다.

```bash
# TCP connect 스캔 (루트 불필요)
nmap -sT 192.168.1.1
# 타이밍을 사용한 Connect 스캔
nmap -sT -T3 192.168.1.1
```

### UDP 스캔: `nmap -sU`

서비스에 대해 UDP 포트를 스캔합니다.

```bash
# UDP 스캔 (느림, 루트 필요)
nmap -sU 192.168.1.1
# 일반적인 UDP 포트 스캔
nmap -sU -p 53,67,68,161 192.168.1.1
# 결합된 TCP/UDP 스캔
nmap -sS -sU -p T:80,443,U:53,161 192.168.1.1
```

### 은밀한 스캔

회피를 위한 고급 스캐닝 기술입니다.

```bash
# FIN 스캔
nmap -sF 192.168.1.1
# NULL 스캔
nmap -sN 192.168.1.1
# Xmas 스캔
nmap -sX 192.168.1.1
```

## 포트 지정

### 포트 범위: `nmap -p`

더 정확한 스캔을 위해 특정 포트, 범위 또는 TCP 및 UDP 포트 조합을 대상으로 지정합니다.

```bash
# 단일 포트
nmap -p 80 192.168.1.1
# 여러 포트
nmap -p 22,80,443 192.168.1.1
# 포트 범위
nmap -p 1-1000 192.168.1.1
# 모든 포트
nmap -p- 192.168.1.1
```

### 프로토콜별 포트

TCP 또는 UDP 포트를 명시적으로 지정합니다.

```bash
# TCP 포트만
nmap -p T:80,443 192.168.1.1
# UDP 포트만
nmap -p U:53,161 192.168.1.1
# 혼합 TCP 및 UDP
nmap -p T:80,U:53 192.168.1.1
```

### 일반적인 포트 세트

사용 빈도가 높은 포트를 빠르게 스캔합니다.

```bash
# 상위 1000 개 포트 (기본값)
nmap 192.168.1.1
# 상위 100 개 포트
nmap --top-ports 100 192.168.1.1
# 빠른 스캔 (가장 일반적인 100 개 포트)
nmap -F 192.168.1.1
# 열린 포트만 표시
nmap --open 192.168.1.1
# 모든 포트 상태 표시
nmap -v 192.168.1.1
```

## 서비스 및 버전 감지

### 서비스 감지: `nmap -sV`

실행 중인 서비스를 감지하고 해당 소프트웨어 버전 및 구성을 식별하려고 시도합니다.

```bash
# 기본 버전 감지
nmap -sV 192.168.1.1
# 공격적인 버전 감지
nmap -sV --version-intensity 9 192.168.1.1
# 가벼운 버전 감지
nmap -sV --version-intensity 0 192.168.1.1
# 버전 감지를 사용한 기본 스크립트
nmap -sC -sV 192.168.1.1
```

### 서비스 스크립트

향상된 서비스 감지를 위해 스크립트를 사용합니다.

```bash
# 배너 캡처
nmap --script banner 192.168.1.1
# HTTP 서비스 열거
nmap --script http-* 192.168.1.1
```

### 운영 체제 감지: `nmap -O`

TCP/IP 핑거프린팅을 사용하여 대상 호스트의 운영 체제를 추측합니다.

```bash
# OS 감지
nmap -O 192.168.1.1
# 공격적인 OS 감지
nmap -O --osscan-guess 192.168.1.1
# OS 감지 시도 횟수 제한
nmap -O --max-os-tries 1 192.168.1.1
```

### 포괄적인 감지

여러 감지 기술을 결합합니다.

```bash
# 공격적인 스캔 (OS, 버전, 스크립트)
nmap -A 192.168.1.1
# 사용자 지정 공격적 스캔
nmap -sS -sV -O -sC 192.168.1.1
```

## 타이밍 및 성능

### 타이밍 템플릿: `nmap -T`

대상 환경 및 탐지 위험에 따라 스캔 속도를 조정합니다.

```bash
# Paranoid (매우 느림, 은밀함)
nmap -T0 192.168.1.1
# Sneaky (느림, 은밀함)
nmap -T1 192.168.1.1
# Polite (느림, 대역폭 적게 사용)
nmap -T2 192.168.1.1
# Normal (기본값)
nmap -T3 192.168.1.1
# Aggressive (더 빠름)
nmap -T4 192.168.1.1
# Insane (매우 빠름, 결과 누락 가능)
nmap -T5 192.168.1.1
```

### 사용자 지정 타이밍 옵션

성능 최적화를 위해 타임아웃, 재시도 및 병렬 스캔 방식을 세밀하게 조정합니다.

```bash
# 최소 속도 설정 (초당 패킷 수)
nmap --min-rate 1000 192.168.1.1
# 최대 속도 설정
nmap --max-rate 100 192.168.1.1
# 병렬 호스트 스캐닝
nmap --min-hostgroup 10 192.168.1.0/24
# 사용자 지정 타임아웃
nmap --host-timeout 5m 192.168.1.1
```

## Nmap 스크립팅 엔진 (NSE)

### 스크립트 카테고리: `nmap --script`

카테고리 또는 이름별로 스크립트를 실행합니다.

```bash
# 기본 스크립트
nmap --script default 192.168.1.1
# 취약점 스크립트
nmap --script vuln 192.168.1.1
# 검색 스크립트
nmap --script discovery 192.168.1.1
# 인증 스크립트
nmap --script auth 192.168.1.1
```

### 특정 스크립트

특정 취약점 또는 서비스를 대상으로 지정합니다.

```bash
# SMB 열거
nmap --script smb-enum-* 192.168.1.1
# HTTP 메서드
nmap --script http-methods 192.168.1.1
# SSL 인증서 정보
nmap --script ssl-cert 192.168.1.1
```

### 스크립트 인수

스크립트 동작을 사용자 지정하기 위해 인수를 전달합니다.

```bash
# 사용자 지정 단어 목록을 사용한 HTTP 무차별 대입
nmap --script http-brute --script-args
userdb=users.txt,passdb=pass.txt 192.168.1.1
# SMB 무차별 대입
nmap --script smb-brute 192.168.1.1
# DNS 무차별 대입
nmap --script dns-brute example.com
```

### 스크립트 관리

NSE 스크립트를 관리하고 업데이트합니다.

```bash
# 스크립트 데이터베이스 업데이트
nmap --script-updatedb
# 사용 가능한 스크립트 나열
ls /usr/share/nmap/scripts/ | grep http
# 스크립트 도움말 가져오기
nmap --script-help vuln
```

## 출력 형식 및 결과 저장

### 출력 형식

결과를 다른 형식으로 저장합니다.

```bash
# 일반 출력
nmap -oN scan_results.txt 192.168.1.1
# XML 출력
nmap -oX scan_results.xml 192.168.1.1
# Grep 가능한 출력
nmap -oG scan_results.gnmap 192.168.1.1
# 모든 형식
nmap -oA scan_results 192.168.1.1
```

### 자세한 출력

표시되는 정보의 양을 제어합니다.

```bash
# 자세한 출력
nmap -v 192.168.1.1
# 매우 자세한 출력
nmap -vv 192.168.1.1
# 디버그 모드
nmap --packet-trace 192.168.1.1
```

### 재개 및 추가

이전 스캔을 계속하거나 기존 파일에 추가합니다.

```bash
# 중단된 스캔 재개
nmap --resume scan_results.gnmap
# 기존 파일에 추가
nmap --append-output -oN existing_scan.txt 192.168.1.1
```

### 실시간 결과 처리

Nmap 출력을 명령줄 도구와 결합하여 유용한 통찰력을 추출합니다.

```bash
# 활성 호스트 추출
nmap -sn 192.168.1.0/24 | grep "Nmap scan report"
# 웹 서버 찾기
nmap -p 80,443 --open 192.168.1.0/24 | grep "open"
# CSV 로 내보내기
nmap -oX - 192.168.1.1 | xsltproc --html -
```

## 방화벽 회피 기술

### 패킷 조각화: `nmap -f`

패킷 조각화, IP 스푸핑 및 은밀한 스캔 방법을 사용하여 보안 조치를 우회합니다.

```bash
# 패킷 조각화
nmap -f 192.168.1.1
# 사용자 지정 MTU 크기
nmap --mtu 16 192.168.1.1
# 최대 전송 단위
nmap --mtu 24 192.168.1.1
```

### 데코이 스캐닝: `nmap -D`

가짜 IP 주소들 사이에서 스캔을 숨깁니다.

```bash
# 데코이 IP 사용
nmap -D 192.168.1.100,192.168.1.101 192.168.1.1
# 무작위 데코이
nmap -D RND:5 192.168.1.1
# 실제 및 무작위 데코이 혼합
nmap -D 192.168.1.100,RND:3 192.168.1.1
```

### 소스 IP/포트 조작

소스 정보를 스푸핑합니다.

```bash
# 소스 IP 스푸핑
nmap -S 192.168.1.100 192.168.1.1
# 사용자 지정 소스 포트
nmap --source-port 53 192.168.1.1
# 무작위 데이터 길이
nmap --data-length 25 192.168.1.1
```

### Idle/좀비 스캔: `nmap -sI`

좀비 호스트를 사용하여 스캔 출처를 숨깁니다.

```bash
# 좀비 스캔 (유휴 호스트 필요)
nmap -sI zombie_host 192.168.1.1
# 유휴 후보 목록 표시
nmap --script ipidseq 192.168.1.0/24
```

## 고급 스캐닝 옵션

### DNS 확인 제어

Nmap이 DNS 조회를 처리하는 방식을 제어합니다.

```bash
# DNS 확인 비활성화
nmap -n 192.168.1.1
# DNS 확인 강제 실행
nmap -R 192.168.1.1
# 사용자 지정 DNS 서버
nmap --dns-servers 8.8.8.8,1.1.1.1 192.168.1.1
```

### IPv6 스캐닝: `nmap -6`

IPv6 지원과 같은 추가 기능을 위해 이러한 Nmap 플래그를 사용합니다.

```bash
# IPv6 스캔
nmap -6 2001:db8::1
# IPv6 네트워크 스캔
nmap -6 2001:db8::/32
```

### 인터페이스 및 라우팅

네트워크 인터페이스 및 라우팅을 제어합니다.

```bash
# 네트워크 인터페이스 지정
nmap -e eth0 192.168.1.1
# 인터페이스 및 경로 인쇄
nmap --iflist
# 추적 경로
nmap --traceroute 192.168.1.1
```

### 기타 옵션

추가로 유용한 플래그입니다.

```bash
# 버전 인쇄 및 종료
nmap --version
# 이더넷 레벨에서 전송
nmap --send-eth 192.168.1.1
# IP 레벨에서 전송
nmap --send-ip 192.168.1.1
```

## 실제 시나리오 예시

### 네트워크 검색 워크플로우

완벽한 네트워크 열거 프로세스입니다.

```bash
# 1 단계: 활성 호스트 검색
nmap -sn 192.168.1.0/24
# 2 단계: 빠른 포트 스캔
nmap -sS -T4 --top-ports 1000 192.168.1.0/24
# 3 단계: 흥미로운 호스트에 대한 상세 스캔
nmap -sS -sV -sC -O 192.168.1.50
# 4 단계: 포괄적인 스캔
nmap -p- -A -T4 192.168.1.50
```

### 웹 서버 평가

웹 서비스 및 취약점에 중점을 둡니다.

```bash
# 웹 서버 찾기
nmap -sS -p 80,443,8080,8443 --open 192.168.1.0/24
# HTTP 서비스 열거
nmap -sS -sV --script http-* 192.168.1.50
# 일반적인 취약점 확인
nmap --script vuln -p 80,443 192.168.1.50
```

### SMB/NetBIOS 열거

다음 예시는 대상 네트워크에서 Netbios를 열거합니다.

```bash
# SMB 서비스 감지
nmap -sV -p 139,445 192.168.1.0/24
# NetBIOS 이름 검색
nmap -sU --script nbstat -p 137 192.168.1.0/24
# SMB 열거 스크립트
nmap --script smb-enum-* -p 445 192.168.1.50
# SMB 취약점 확인
nmap --script smb-vuln-* -p 445 192.168.1.50
```

### 은밀한 평가

저자세 정찰입니다.

```bash
# 초은밀 스캔
nmap -sS -T0 -f --data-length 200 -D RND:10 192.168.1.1
# 조각화된 SYN 스캔
nmap -sS -f --mtu 8 -T1 192.168.1.1
```

## 성능 최적화

### 빠른 스캐닝 전략

대규모 네트워크에 대한 스캔 속도를 최적화합니다.

```bash
# 빠른 네트워크 스윕
nmap -sS -T4 --min-rate 1000 --max-retries 1
192.168.1.0/24
# 병렬 호스트 스캐닝
nmap --min-hostgroup 50 --max-hostgroup 100
192.168.1.0/24
# 느린 작업 건너뛰기
nmap -sS -T4 --defeat-rst-ratelimit 192.168.1.0/24
```

### 메모리 및 리소스 관리

안정성을 위해 리소스 사용량을 제어합니다.

```bash
# 병렬 프로브 제한
nmap --max-parallelism 10 192.168.1.0/24
# 스캔 지연 제어
nmap --scan-delay 100ms 192.168.1.1
# 호스트 타임아웃 설정
nmap --host-timeout 10m 192.168.1.0/24
```

## 관련 링크

- <router-link to="/wireshark">Wireshark 치트 시트</router-link>
- <router-link to="/kali">Kali Linux 치트 시트</router-link>
- <router-link to="/cybersecurity">사이버 보안 치트 시트</router-link>
- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/network">네트워크 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>

---
title: '와이어샤크 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 포괄적인 치트 시트로 와이어샤크를 학습하세요.'
pdfUrl: '/cheatsheets/pdf/wireshark-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Wireshark 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/wireshark">실습 랩을 통해 Wireshark 배우기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 랩과 실제 시나리오를 통해 Wireshark 네트워크 패킷 분석을 학습하세요. LabEx 는 필수 패킷 캡처, 디스플레이 필터, 프로토콜 분석, 네트워크 문제 해결 및 보안 모니터링을 다루는 포괄적인 Wireshark 과정을 제공합니다. 네트워크 트래픽 분석 및 패킷 검사 기술을 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 캡처 필터 & 트래픽 캡처

### 호스트 필터링

특정 호스트와/또는 특정 호스트로의 트래픽을 캡처합니다.

```bash
# 특정 IP로부터/으로의 트래픽 캡처
host 192.168.1.100
# 특정 소스로부터의 트래픽 캡처
src host 192.168.1.100
# 특정 목적지로의 트래픽 캡처
dst host 192.168.1.100
# 서브넷 트래픽 캡처
net 192.168.1.0/24
```

### 포트 필터링

특정 포트의 트래픽을 캡처합니다.

```bash
# HTTP 트래픽 (포트 80)
port 80
# HTTPS 트래픽 (포트 443)
port 443
# SSH 트래픽 (포트 22)
port 22
# DNS 트래픽 (포트 53)
port 53
# 포트 범위
portrange 1000-2000
```

### 프로토콜 필터링

특정 프로토콜 트래픽을 캡처합니다.

```bash
# TCP 트래픽만
tcp
# UDP 트래픽만
udp
# ICMP 트래픽만
icmp
# ARP 트래픽만
arp
```

### 고급 캡처 필터

여러 조건을 결합하여 정확하게 캡처합니다.

```bash
# 특정 호스트와/또는 특정 호스트로의 HTTP 트래픽
host 192.168.1.100 and port 80
# SSH를 제외한 TCP 트래픽
tcp and not port 22
# 두 호스트 간의 트래픽
host 192.168.1.100 and host 192.168.1.200
# HTTP 또는 HTTPS 트래픽
port 80 or port 443
```

### 인터페이스 선택

캡처할 네트워크 인터페이스를 선택합니다.

```bash
# 사용 가능한 인터페이스 목록 보기
tshark -D
# 특정 인터페이스에서 캡처
# 이더넷 인터페이스
eth0
# WiFi 인터페이스
wlan0
# 루프백 인터페이스
lo
```

### 캡처 옵션

캡처 매개변수를 구성합니다.

```bash
# 캡처 파일 크기 제한 (MB)
-a filesize:100
# 캡처 기간 제한 (초)
-a duration:300
# 10개 파일의 링 버퍼
-b files:10
# 무차별 모드 (모든 트래픽 캡처)
-p
```

## 디스플레이 필터 & 패킷 분석

### 기본 디스플레이 필터

일반적인 프로토콜 및 트래픽 유형에 대한 필수 필터입니다.

```bash
# HTTP 트래픽만 표시
http
# HTTPS/TLS 트래픽만 표시
tls
# DNS 트래픽만 표시
dns
# TCP 트래픽만 표시
tcp
# UDP 트래픽만 표시
udp
# ICMP 트래픽만 표시
icmp
```

### IP 주소 필터링

소스 및 목적지 IP 주소로 패킷을 필터링합니다.

```bash
# 특정 IP로부터의 트래픽
ip.src == 192.168.1.100
# 특정 IP로의 트래픽
ip.dst == 192.168.1.200
# 두 IP 간의 트래픽
ip.addr == 192.168.1.100
# 서브넷으로부터의 트래픽
ip.src_net == 192.168.1.0/24
# 특정 IP 제외
not ip.addr == 192.168.1.1
```

### 포트 및 프로토콜 필터

특정 포트 및 프로토콜 세부 정보로 필터링합니다.

```bash
# 특정 포트의 트래픽
tcp.port == 80
# 소스 포트 필터
tcp.srcport == 443
# 목적지 포트 필터
tcp.dstport == 22
# 포트 범위
tcp.port >= 1000 and tcp.port <=
2000
# 여러 포트
tcp.port in {80 443 8080}
```

## 프로토콜별 분석

### HTTP 분석

HTTP 요청 및 응답을 분석합니다.

```bash
# HTTP GET 요청
http.request.method == "GET"
# HTTP POST 요청
http.request.method == "POST"
# 특정 HTTP 상태 코드
http.response.code == 404
# 특정 호스트로의 HTTP 요청
http.host == "example.com"
# 문자열을 포함하는 HTTP 요청
http contains "login"
```

### DNS 분석

DNS 쿼리 및 응답을 검사합니다.

```bash
# DNS 쿼리만
dns.flags.response == 0
# DNS 응답만
dns.flags.response == 1
# 특정 도메인에 대한 DNS 쿼리
dns.qry.name == "example.com"
# DNS A 레코드 쿼리
dns.qry.type == 1
# DNS 오류/실패
dns.flags.rcode != 0
```

### TCP 분석

TCP 연결 세부 정보를 분석합니다.

```bash
# TCP SYN 패킷 (연결 시도)
tcp.flags.syn == 1
# TCP RST 패킷 (연결 재설정)
tcp.flags.reset == 1
# TCP 재전송
tcp.analysis.retransmission
# TCP 윈도우 업데이트 문제
tcp.analysis.window_update
# TCP 연결 설정
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### TLS/SSL 분석

암호화된 연결 세부 정보를 검사합니다.

```bash
# TLS 핸드셰이크 패킷
tls.handshake
# TLS 인증서 정보
tls.handshake.certificate
# TLS 경고 및 오류
tls.alert
# 특정 TLS 버전
tls.handshake.version == 0x0303
# TLS 서버 이름 표시 (SNI)
tls.handshake.extensions_server_name
```

### 네트워크 문제 해결

일반적인 네트워크 문제를 식별합니다.

```bash
# ICMP 목적지 도달 불가 메시지
icmp.type == 3
# ARP 요청/응답
arp.opcode == 1 or arp.opcode == 2
# 브로드캐스트 트래픽
eth.dst == ff:ff:ff:ff:ff:ff
# 조각난 패킷
ip.flags.mf == 1
# 큰 패킷 (잠재적 MTU 문제)
frame.len > 1500
```

### 시간 기반 필터링

타임스탬프 및 타이밍별로 패킷을 필터링합니다.

```bash
# 시간 범위 내의 패킷
frame.time >= "2024-01-01 10:00:00"
# 지난 1시간 이내의 패킷
frame.time_relative >= -3600
# 응답 시간 분석
tcp.time_delta > 1.0
# 패킷 간격 시간
frame.time_delta > 0.1
```

## 통계 & 분석 도구

### 프로토콜 계층 구조

캡처에서 프로토콜 분포를 확인합니다.

```bash
# 다음을 통해 액세스: 통계 > 프로토콜 계층 구조
# 각 프로토콜의 백분율 표시
# 가장 일반적인 프로토콜 식별
# 트래픽 개요에 유용
# 명령줄 동등 항목
tshark -r capture.pcap -q -z io,phs
```

### 대화 (Conversations)

엔드포인트 간의 통신을 분석합니다.

```bash
# 다음을 통해 액세스: 통계 > 대화
# 이더넷 대화
# IPv4/IPv6 대화
# TCP/UDP 대화
# 전송된 바이트, 패킷 수 표시
# 명령줄 동등 항목
tshark -r capture.pcap -q -z conv,tcp
```

### I/O 그래프

시간 경과에 따른 트래픽 패턴을 시각화합니다.

```bash
# 다음을 통해 액세스: 통계 > I/O 그래프
# 시간 경과에 따른 트래픽 볼륨
# 초당 패킷 수
# 초당 바이트 수
# 특정 트래픽에 필터 적용
# 트래픽 급증 식별에 유용
```

### 전문가 정보 (Expert Information)

잠재적인 네트워크 문제를 식별합니다.

```bash
# 다음을 통해 액세스: 분석 > 전문가 정보
# 네트워크 문제에 대한 경고
# 패킷 전송 오류
# 성능 문제
# 보안 우려 사항
# 전문가 정보 심각도별 필터링
tcp.analysis.flags
```

### 흐름 그래프 (Flow Graphs)

엔드포인트 간의 패킷 흐름을 시각화합니다.

```bash
# 다음을 통해 액세스: 통계 > 흐름 그래프
# 패킷 시퀀스 표시
# 시간 기반 시각화
# 문제 해결에 유용
# 통신 패턴 식별
```

### 응답 시간 분석

애플리케이션 응답 시간을 측정합니다.

```bash
# HTTP 응답 시간
# 통계 > HTTP > 요청
# DNS 응답 시간
# 통계 > DNS
# TCP 서비스 응답 시간
# 통계 > TCP 스트림 그래프 > 시간 순서
```

## 파일 작업 및 내보내기

### 캡처 저장 및 로드

다양한 형식으로 캡처 파일을 관리합니다.

```bash
# 캡처 파일 저장
# 파일 > 다른 이름으로 저장 > capture.pcap
# 캡처 파일 로드
# 파일 > 열기 > existing.pcap
# 여러 캡처 파일 병합
# 파일 > 병합 > 파일 선택
# 필터링된 패킷만 저장
# 파일 > 지정된 패킷 내보내기
```

### 내보내기 옵션

특정 데이터 또는 패킷 하위 집합을 내보냅니다.

```bash
# 선택된 패킷 내보내기
# 파일 > 지정된 패킷 내보내기
# 패킷 분해 내보내기
# 파일 > 패킷 분해 내보내기
# HTTP에서 객체 내보내기
# 파일 > 객체 내보내기 > HTTP
# SSL/TLS 키 내보내기
# 편집 > 환경 설정 > 프로토콜 > TLS
```

### 명령줄 캡처

자동화된 캡처 및 분석을 위해 tshark 사용.

```bash
# 파일로 캡처
tshark -i eth0 -w capture.pcap
# 필터와 함께 캡처
tshark -i eth0 -f "port 80" -w http.pcap
# 패킷 읽기 및 표시
tshark -r capture.pcap
# 파일에 디스플레이 필터 적용
tshark -r capture.pcap -Y "tcp.port == 80"
```

### 일괄 처리 (Batch Processing)

여러 캡처 파일을 자동으로 처리합니다.

```bash
# 여러 파일 병합
mergecap -w merged.pcap file1.pcap file2.pcap
# 큰 캡처 파일 분할
editcap -c 1000 large.pcap split.pcap
# 시간 범위 추출
editcap -A "2024-01-01 10:00:00" \
        -B "2024-01-01 11:00:00" \
        input.pcap output.pcap
```

## 성능 및 최적화

### 메모리 관리

대용량 캡처 파일을 효율적으로 처리합니다.

```bash
# 연속 캡처를 위해 링 버퍼 사용
-b filesize:100 -b files:10
# 패킷 캡처 크기 제한
-s 96  # 처음 96바이트만 캡처
# 데이터를 줄이기 위해 캡처 필터 사용
host 192.168.1.100 and port 80
# 속도를 위해 프로토콜 분해 비활성화
-d tcp.port==80,http
```

### 디스플레이 최적화

대용량 데이터 세트에서 GUI 성능 개선.

```bash
# 조정할 환경 설정:
# 편집 > 환경 설정 > 모양
# 색 구성표 선택
# 글꼴 크기 및 유형
# 열 표시 옵션
# 시간 형식 설정
# 보기 > 시간 표시 형식
# 캡처 시작 이후 경과 시간
# 현재 시간
# UTC 시간
# 대용량 파일 분석을 위해 tshark 사용
tshark -r large.pcap -q -z conv,tcp
```

### 효율적인 분석 워크플로우

네트워크 트래픽 분석을 위한 모범 사례.

```bash
# 1. 캡처 필터로 시작
# 관련 트래픽만 캡처
# 2. 점진적으로 디스플레이 필터 사용
# 광범위하게 시작하여 좁혀가기
# 3. 먼저 통계 사용
# 상세 분석 전에 개요 파악
# 4. 특정 흐름에 집중
# 패킷에서 마우스 오른쪽 버튼 클릭 > 흐름 따라가기 > TCP 스트림
```

### 자동화 및 스크립팅

일반적인 분석 작업을 자동화합니다.

```bash
# 사용자 지정 디스플레이 필터 버튼 생성
# 보기 > 디스플레이 필터 표현식
# 시나리오별 프로필 사용
# 편집 > 구성 프로필
# tshark로 스크립팅
#!/bin/bash
tshark -r $1 -q -z endpoints,tcp | \
grep -v "Filter:" | head -20
```

## 설치 및 설정

### Windows 설치

공식 웹사이트에서 다운로드하여 설치합니다.

```bash
# wireshark.org에서 다운로드
# 관리자 권한으로 설치 프로그램 실행
# 설치 중 WinPcap/Npcap 포함
# (초콜릿) 명령줄 설치
choco install wireshark
# 설치 확인
wireshark --version
```

### Linux 설치

패키지 관리자 또는 소스에서 설치합니다.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install wireshark
# Red Hat/CentOS/Fedora
sudo yum install wireshark
# 또는
sudo dnf install wireshark
# wireshark 그룹에 사용자 추가
sudo usermod -a -G wireshark
$USER
```

### macOS 설치

Homebrew 또는 공식 설치 프로그램을 사용하여 설치합니다.

```bash
# Homebrew 사용
brew install --cask wireshark
# wireshark.org에서 다운로드
# .dmg 패키지 설치
# 명령줄 도구
brew install wireshark
```

## 구성 및 환경 설정

### 인터페이스 환경 설정

캡처 인터페이스 및 옵션을 구성합니다.

```bash
# 편집 > 환경 설정 > 캡처
# 기본 캡처 인터페이스
# 무차별 모드 설정
# 버퍼 크기 구성
# 라이브 캡처에서 자동 스크롤
# 인터페이스별 설정
# 캡처 > 옵션 > 인터페이스 세부 정보
```

### 프로토콜 설정

프로토콜 분해 및 디코딩을 구성합니다.

```bash
# 편집 > 환경 설정 > 프로토콜
# 프로토콜 분해 프로그램 활성화/비활성화
# 포트 할당 구성
# 암호 해독 키 설정 (TLS, WEP 등)
# TCP 재조립 옵션
# Decode As 기능
# 분석 > 다른 것으로 디코드
```

### 디스플레이 환경 설정

사용자 인터페이스 및 디스플레이 옵션을 사용자 정의합니다.

```bash
# 편집 > 환경 설정 > 모양
# 색 구성표 선택
# 글꼴 크기 및 유형
# 열 표시 옵션
# 시간 형식 설정
# 보기 > 시간 표시 형식
# 캡처 시작 이후 경과 시간
# 현재 시간
# UTC 시간
```

### 보안 설정

보안 관련 옵션 및 암호 해독을 구성합니다.

```bash
# TLS 암호 해독 설정
# 편집 > 환경 설정 > 프로토콜 > TLS
# RSA 키 목록
# 사전 공유 키
# 키 로그 파일 위치
# 잠재적으로 위험한 기능 비활성화
# Lua 스크립트 실행
# 외부 확인자
```

## 고급 필터링 기술

### 논리 연산자

여러 필터 조건을 결합합니다.

```bash
# AND 연산자
tcp.port == 80 and ip.src == 192.168.1.100
# OR 연산자
tcp.port == 80 or tcp.port == 443
# NOT 연산자
not icmp
# 그룹화를 위한 괄호
(tcp.port == 80 or tcp.port == 443) and ip.src ==
192.168.1.0/24
```

### 문자열 일치

패킷 내의 특정 콘텐츠를 검색합니다.

```bash
# 문자열 포함 (대소문자 구분)
tcp contains "password"
# 문자열 포함 (대소문자 구분 안 함)
tcp matches "(?i)login"
# 정규 표현식
http.request.uri matches "\.php$"
# 바이트 시퀀스
eth.src[0:3] == 00:11:22
```

### 필드 비교

패킷 필드를 값 및 범위와 비교합니다.

```bash
# 등가성
tcp.srcport == 80
# 보다 큼/보다 작음
frame.len > 1000
# 범위 확인
tcp.port >= 1024 and tcp.port <= 65535
# 집합 멤버십
tcp.port in {80 443 8080 8443}
# 필드 존재 여부
tcp.options
```

### 고급 패킷 분석

특정 패킷 특성 및 이상 징후를 식별합니다.

```bash
# 잘못된 형식의 패킷
_ws.malformed
# 중복 패킷
frame.number == tcp.analysis.duplicate_ack_num
# 순서가 잘못된 패킷
tcp.analysis.out_of_order
# TCP 윈도우 크기 문제
tcp.analysis.window_full
```

## 일반적인 사용 사례

### 네트워크 문제 해결

네트워크 연결 문제를 식별하고 해결합니다.

```bash
# 연결 시간 초과 찾기
tcp.analysis.retransmission and tcp.analysis.rto
# 느린 연결 식별
tcp.time_delta > 1.0
# 네트워크 혼잡 찾기
tcp.analysis.window_full
# DNS 확인 문제
dns.flags.rcode != 0
# MTU 검색 문제
icmp.type == 3 and icmp.code == 4
```

### 보안 분석

잠재적인 보안 위협 및 의심스러운 활동을 감지합니다.

```bash
# 포트 스캔 감지
tcp.flags.syn == 1 and tcp.flags.ack == 0
# 단일 IP로부터의 많은 연결 수
# 통계 > 대화 참조
# 의심스러운 DNS 쿼리
dns.qry.name contains "dga" or dns.qry.name matches
"^[a-z]{8,}\.com$"
# 의심스러운 URL로의 HTTP POST
http.request.method == "POST" and http.request.uri
contains "/upload"
# 비정상적인 트래픽 패턴
# I/O 그래프에서 급증 확인
```

### 애플리케이션 성능

애플리케이션 응답 시간을 모니터링하고 분석합니다.

```bash
# 웹 애플리케이션 분석
http.time > 2.0
# 데이터베이스 연결 모니터링
tcp.port == 3306 and tcp.analysis.initial_rtt > 0.1
# 파일 전송 성능
tcp.stream eq X and tcp.analysis.bytes_in_flight
# VoIP 품질 분석
rtp.jitter > 30 or rtp.marker == 1
```

### 프로토콜 조사

특정 프로토콜 및 동작에 대해 심층적으로 조사합니다.

```bash
# 이메일 트래픽 분석
tcp.port == 25 or tcp.port == 587 or tcp.port == 993
# FTP 파일 전송
ftp-data or ftp.request.command == "RETR"
# SMB/CIFS 파일 공유
smb2 or smb
# DHCP 임대 분석
bootp.option.dhcp == 1 or bootp.option.dhcp == 2
```

## 관련 링크

- <router-link to="/nmap">Nmap 치트 시트</router-link>
- <router-link to="/cybersecurity">사이버 보안 치트 시트</router-link>
- <router-link to="/kali">Kali Linux 치트 시트</router-link>
- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/network">네트워크 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>

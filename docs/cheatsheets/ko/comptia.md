---
title: 'CompTIA 치트 시트 | LabEx'
description: '이 종합 치트 시트로 CompTIA IT 자격증을 학습하세요. CompTIA A+, Network+, Security+, Linux+ 및 IT 기초 지식에 대한 빠른 참고 자료로 자격증 시험 준비에 유용합니다.'
pdfUrl: '/cheatsheets/pdf/comptia-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
CompTIA 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/comptia">Hands-On Labs 로 CompTIA 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 기반 랩과 실제 시나리오를 통해 CompTIA 자격증을 학습하세요. LabEx 는 A+, Network+, Security+ 및 전문 자격증을 다루는 포괄적인 CompTIA 과정을 제공합니다. IT 기초, 네트워킹, 보안을 마스터하고 업계에서 인정받는 자격증으로 IT 경력을 발전시키십시오.
</base-disclaimer-content>
</base-disclaimer>

## CompTIA 자격증 개요

### 핵심 자격증 (Core Certifications)

IT 경력 성공을 위한 기초 자격증.

```text
# CompTIA A+ (220-1101, 220-1102)
- 하드웨어 및 모바일 장치
- 운영 체제 및 소프트웨어
- 보안 및 네트워킹 기초
- 운영 절차

# CompTIA Network+ (N10-008)
- 네트워크 기초
- 네트워크 구현
- 네트워크 운영
- 네트워크 보안
- 네트워크 문제 해결

# CompTIA Security+ (SY0-601)
- 공격, 위협 및 취약점
- 아키텍처 및 설계
- 구현
- 운영 및 사고 대응
- 거버넌스, 위험 및 규정 준수
```

<BaseQuiz id="comptia-core-1" correct="B">
  <template #question>
    네트워크 기초 및 문제 해결에 중점을 두는 CompTIA 자격증은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">CompTIA A+</BaseQuizOption>
  <BaseQuizOption value="B" correct>CompTIA Network+</BaseQuizOption>
  <BaseQuizOption value="C">CompTIA Security+</BaseQuizOption>
  <BaseQuizOption value="D">CompTIA Linux+</BaseQuizOption>
  
  <BaseQuizAnswer>
    CompTIA Network+ (N10-008) 는 네트워크 기초, 구현, 운영, 보안 및 문제 해결에 중점을 둡니다. 네트워크 관리자 및 기술자를 위해 설계되었습니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 전문 자격증 (Specialized Certifications)

고급 및 전문 IT 자격증.

```text
# CompTIA PenTest+ (PT0-002)
- 침투 테스트 계획 및 범위 설정
- 정보 수집 및 취약점 식별
- 공격 및 익스플로잇
- 보고 및 커뮤니케이션

# CompTIA CySA+ (CS0-002)
- 위협 및 취약점 관리
- 소프트웨어 및 시스템 보안
- 보안 운영 및 모니터링
- 사고 대응
- 규정 준수 및 평가

# CompTIA Cloud+ (CV0-003)
- 클라우드 아키텍처 및 설계
- 보안
- 배포
- 운영 및 지원
- 문제 해결

# CompTIA Server+ (SK0-005)
- 서버 하드웨어 설치 및 관리
- 서버 관리
- 보안 및 재해 복구
- 문제 해결

# CompTIA Project+ (PK0-005)
- 프로젝트 수명 주기
- 프로젝트 도구 및 문서화
- 프로젝트 비용 및 시간 관리 기초
- 프로젝트 실행 및 종료

# CompTIA Linux+ (XK0-005)
- 시스템 관리
- 보안
- 스크립팅 및 컨테이너
- 문제 해결
```

## CompTIA A+ 필수 사항

### 하드웨어 구성 요소

필수 컴퓨터 하드웨어 지식 및 문제 해결.

```text
# CPU 유형 및 기능
- Intel 대 AMD 프로세서
- 소켓 유형 (LGA, PGA, BGA)
- 코어 수 및 스레딩
- 캐시 레벨 (L1, L2, L3)

# 메모리 (RAM)
- DDR4, DDR5 사양
- ECC 대 비-ECC 메모리
- SODIMM 대 DIMM 폼 팩터
- 메모리 채널 및 속도

# 스토리지 기술
- HDD 대 SSD 대 NVMe
- SATA, PCIe 인터페이스
- RAID 구성 (0,1,5,10)
- M.2 폼 팩터
```

### 모바일 장치

스마트폰, 태블릿 및 모바일 장치 관리.

```text
# 모바일 장치 유형
- iOS 대 Android 아키텍처
- 노트북 대 태블릿 폼 팩터
- 웨어러블 장치
- 전자책 리더 및 스마트 장치

# 모바일 연결성
- Wi-Fi 표준 (802.11a/b/g/n/ac/ax)
- 셀룰러 기술 (3G, 4G, 5G)
- Bluetooth 버전 및 프로필
- NFC 및 모바일 결제

# 모바일 보안
- 화면 잠금 및 생체 인식
- 모바일 장치 관리 (MDM)
- 앱 보안 및 권한
- 원격 삭제 기능
```

### 운영 체제

Windows, macOS, Linux 및 모바일 OS 관리.

```text
# Windows 관리
- Windows 10/11 에디션
- 사용자 계정 컨트롤 (UAC)
- 그룹 정책 및 레지스트리
- Windows 업데이트 관리

# macOS 관리
- 시스템 환경설정
- 키체인 접근
- Time Machine 백업
- 앱 스토어 및 Gatekeeper

# Linux 기초
- 파일 시스템 계층 구조
- 명령줄 작업
- 패키지 관리
- 사용자 및 그룹 권한
```

## Network+ 기초

### OSI 모델 및 TCP/IP

네트워크 계층 이해 및 프로토콜 지식.

```text
# OSI 7 계층 모델
Layer 7: Application (HTTP, HTTPS, FTP)
Layer 6: Presentation (SSL, TLS)
Layer 5: Session (NetBIOS, RPC)
Layer 4: Transport (TCP, UDP)
Layer 3: Network (IP, ICMP, OSPF)
Layer 2: Data Link (Ethernet, PPP)
Layer 1: Physical (케이블, 허브)

# TCP/IP 스위트
- IPv4 대 IPv6 주소 지정
- 서브넷팅 및 CIDR 표기법
- DHCP 및 DNS 서비스
- ARP 및 ICMP 프로토콜
```

<BaseQuiz id="comptia-osi-1" correct="C">
  <template #question>
    TCP 는 OSI 모델의 어느 계층에서 작동합니까?
  </template>
  
  <BaseQuizOption value="A">Layer 3 (Network)</BaseQuizOption>
  <BaseQuizOption value="B">Layer 5 (Session)</BaseQuizOption>
  <BaseQuizOption value="C" correct>Layer 4 (Transport)</BaseQuizOption>
  <BaseQuizOption value="D">Layer 7 (Application)</BaseQuizOption>
  
  <BaseQuizAnswer>
    TCP(전송 제어 프로토콜) 는 OSI 모델의 4 계층 (전송 계층) 에서 작동합니다. 이 계층은 안정적인 데이터 전송, 오류 확인 및 흐름 제어를 담당합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 네트워크 장치

라우터, 스위치 및 네트워킹 장비.

```text
# Layer 2 장치
- 스위치 및 VLAN
- 스패닝 트리 프로토콜 (STP)
- 포트 보안 및 MAC 필터링

# Layer 3 장치
- 라우터 및 라우팅 테이블
- 정적 대 동적 라우팅
- OSPF, EIGRP, BGP 프로토콜
- NAT 및 PAT 변환
```

### 무선 네트워킹

Wi-Fi 표준, 보안 및 문제 해결.

```text
# Wi-Fi 표준
802.11a: 5GHz, 54Mbps
802.11b: 2.4GHz, 11Mbps
802.11g: 2.4GHz, 54Mbps
802.11n: 2.4/5GHz, 600Mbps
802.11ac: 5GHz, 6.9Gbps
802.11ax (Wi-Fi 6): 9.6Gbps

# 무선 보안
- WEP (사용 중단됨)
- WPA/WPA2-PSK
- WPA2/WPA3-Enterprise
- EAP 인증 방법
```

### 네트워크 문제 해결

일반적인 도구 및 진단 절차.

```bash
# 명령줄 도구
ping                    # 연결 테스트
tracert/traceroute      # 경로 분석
nslookup/dig            # DNS 쿼리
netstat                 # 네트워크 연결
ipconfig/ifconfig       # IP 구성

# 네트워크 테스트
- 케이블 테스터 및 톤 발생기
- 프로토콜 분석기 (Wireshark)
- 속도 및 처리량 테스트
- Wi-Fi 분석기
```

## Security+ 핵심 개념

### 보안 기초

CIA 트라이어드 및 기본 보안 원칙.

```text
# CIA 트라이어드
Confidentiality: 데이터 기밀성 및 암호화
Integrity: 데이터 정확성 및 무결성
Availability: 시스템 가동 시간 및 접근성

# 인증 요소
Something you know: 암호, PIN
Something you have: 토큰, 스마트 카드
Something you are: 생체 인식
Something you do: 행동 패턴
Somewhere you are: 위치 기반
```

<BaseQuiz id="comptia-cia-1" correct="A">
  <template #question>
    CIA 트라이어드는 사이버 보안에서 무엇을 나타냅니까?
  </template>
  
  <BaseQuizOption value="A" correct>기밀성, 무결성 및 가용성 - 세 가지 핵심 보안 원칙</BaseQuizOption>
  <BaseQuizOption value="B">정부 기관</BaseQuizOption>
  <BaseQuizOption value="C">세 가지 공격 유형</BaseQuizOption>
  <BaseQuizOption value="D">세 가지 인증 방법</BaseQuizOption>
  
  <BaseQuizAnswer>
    CIA 트라이어드는 정보 보안의 세 가지 기본 원칙인 기밀성 (무단 액세스로부터 데이터 보호), 무결성 (데이터 정확성 및 진위 보장), 가용성 (필요할 때 시스템 및 데이터에 접근 가능하도록 보장) 을 나타냅니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 위협 환경

일반적인 공격 및 위협 행위자.

```text
# 공격 유형
- 피싱 및 사회 공학
- 멀웨어 (바이러스, 트로이 목마, 랜섬웨어)
- DDoS 및 DoS 공격
- 중간자 공격 (Man-in-the-middle)
- SQL 인젝션 및 XSS
- 제로데이 익스플로잇

# 위협 행위자
- 스크립트 키디
- 해커 활동가 (Hacktivists)
- 조직 범죄
- 국가 지원 행위자
- 내부자 위협
```

### 암호학

암호화 방법 및 키 관리.

```text
# 암호화 유형
대칭: AES, 3DES (동일 키 사용)
비대칭: RSA, ECC (키 쌍 사용)
해싱: SHA-256, MD5 (단방향)
디지털 서명: 부인 방지

# 키 관리
- 키 생성 및 배포
- 키 에스크로 및 복구
- 인증 기관 (CA)
- 공개 키 기반 구조 (PKI)
```

<BaseQuiz id="comptia-crypto-1" correct="B">
  <template #question>
    대칭 암호화와 비대칭 암호화의 주요 차이점은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">대칭이 더 빠르고, 비대칭이 더 느립니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>대칭은 암호화/복호화에 하나의 키를 사용하고, 비대칭은 키 쌍을 사용합니다</BaseQuizOption>
  <BaseQuizOption value="C">대칭은 이메일에 사용되고, 비대칭은 파일에 사용됩니다</BaseQuizOption>
  <BaseQuizOption value="D">차이점이 없습니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    대칭 암호화는 암호화와 복호화에 동일한 키를 사용하여 빠르지만 안전한 키 분배가 필요합니다. 비대칭 암호화는 공개/개인 키 쌍을 사용하여 키 분배 문제를 해결하지만 계산 비용이 더 많이 듭니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 액세스 제어

ID 관리 및 권한 부여 모델.

```text
# 액세스 제어 모델
DAC: 임의적 액세스 제어
MAC: 필수적 액세스 제어
RBAC: 역할 기반 액세스 제어
ABAC: 속성 기반 액세스 제어

# ID 관리
- 단일 사인온 (SSO)
- 다단계 인증 (MFA)
- LDAP 및 Active Directory
- 연동 및 SAML
```

## 학습 전략 및 팁

### 학습 계획

자격증 준비를 위한 구조화된 접근 방식 생성.

```text
# 학습 일정
1-2 주차: 시험 목표 검토
3-6 주차: 핵심 자료 학습
7-8 주차: 실습 연습
9-10 주차: 모의고사
11-12 주차: 최종 검토 및 시험
```

### 실습 연습

이론 지식을 강화하기 위한 실제 경험.

```text
# 랩 환경
- VMware 또는 VirtualBox VM
- 홈 랩 설정
- 클라우드 기반 랩 (AWS, Azure)
- CompTIA 시뮬레이션 소프트웨어

# 실무 기술
- PC 구축 및 문제 해결
- 네트워크 구성
- 보안 도구 구현
- 명령줄 숙련도
```

### 시험 전략

CompTIA 시험을 위한 시험 응시 기술.

```text
# 문제 유형
객관식: 모든 옵션 읽기
성능 기반: 시뮬레이션 연습
드래그 앤 드롭: 관계 이해
핫스팟: 인터페이스 레이아웃 숙지

# 시간 관리
- 질문당 시간 할당
- 검토를 위해 어려운 질문 표시
- 단일 질문에 너무 오래 소비하지 않기
- 마지막에 표시된 질문 검토
```

### 일반적인 시험 주제

CompTIA 시험 전반에 걸친 고빈도 주제.

```text
# 자주 출제되는 영역
- 문제 해결 방법론
- 보안 모범 사례
- 네트워크 프로토콜 및 포트
- 운영 체제 기능
- 하드웨어 사양
- 위험 관리 개념
```

## 기술 약어 및 용어

### 네트워킹 약어

일반적인 네트워킹 용어 및 약어.

```text
# 프로토콜 및 표준
HTTP/HTTPS: 웹 프로토콜
FTP/SFTP: 파일 전송
SMTP/POP3/IMAP: 이메일
DNS: 도메인 이름 시스템
DHCP: 동적 호스트 구성
TCP/UDP: 전송 프로토콜
IP: 인터넷 프로토콜
ICMP: 인터넷 제어 메시지

# 무선 및 보안
WPA/WPA2: Wi-Fi 보호 액세스
SSID: 서비스 세트 식별자
MAC: 매체 액세스 제어
VPN: 가상 사설망
VLAN: 가상 근거리 통신망
QoS: 서비스 품질
```

### 하드웨어 및 소프트웨어

컴퓨터 하드웨어 및 소프트웨어 용어.

```text
# 스토리지 및 메모리
HDD: 하드 디스크 드라이브
SSD: 솔리드 스테이트 드라이브
RAM: 랜덤 액세스 메모리
ROM: 읽기 전용 메모리
BIOS/UEFI: 시스템 펌웨어
RAID: 중복 독립 디스크 배열

# 인터페이스 및 포트
USB: 범용 직렬 버스
SATA: 시리얼 ATA
PCIe: PCI 익스프레스
HDMI: 고화질 멀티미디어 인터페이스
VGA: 비디오 그래픽스 배열
RJ45: 이더넷 커넥터
```

### 보안 용어

정보 보안 용어 및 개념.

```text
# 보안 프레임워크
CIA: 기밀성, 무결성, 가용성
AAA: 인증, 권한 부여, 계정 관리
PKI: 공개 키 기반 구조
IAM: ID 및 액세스 관리
SIEM: 보안 정보 및 이벤트 관리
SOC: 보안 운영 센터

# 규정 준수 및 위험
GDPR: 일반 데이터 보호 규정
HIPAA: 건강 보험 이동성 및 책임에 관한 법률
PCI DSS: 결제 카드 산업 데이터 보안 표준
SOX: 사베인스 - 옥슬리 법
NIST: 미국 국립 표준 기술 연구소
ISO 27001: 보안 관리 표준
```

### 클라우드 및 가상화

현대 IT 인프라 용어.

```text
# 클라우드 서비스
IaaS: 서비스형 인프라
PaaS: 서비스형 플랫폼
SaaS: 서비스형 소프트웨어
VM: 가상 머신
API: 애플리케이션 프로그래밍 인터페이스
CDN: 콘텐츠 전송 네트워크
```

## 자격증 경력 경로

### 입문 수준

하드웨어, 소프트웨어 및 기본 문제 해결 기술을 다루는 IT 지원 역할을 위한 기초 자격증.

```text
1. 입문 수준
CompTIA A+
하드웨어, 소프트웨어 및 기본 문제 해결 기술을 다루는
IT 지원 역할을 위한 기초 자격증.
```

### 인프라

인프라 역할을 위한 네트워킹 및 서버 관리 전문 지식 구축.

```text
2. 인프라
Network+ & Server+
인프라 역할을 위한 네트워킹 및 서버 관리 전문 지식 구축.
```

### 보안 집중

보안 분석가 및 관리자 직책을 위한 사이버 보안 지식 개발.

```text
3. 보안 집중
Security+ & CySA+
보안 분석가 및 관리자 직책을 위한 사이버 보안 지식 개발.
```

### 전문화

침투 테스트 및 클라우드 기술의 고급 전문화.

```text
4. 전문화
PenTest+ & Cloud+
침투 테스트 및 클라우드 기술의 고급 전문화.
```

## 일반적인 포트 번호

### 잘 알려진 포트 (0-1023)

일반적인 네트워크 서비스에 대한 표준 포트.

```text
Port 20/21: FTP (파일 전송 프로토콜)
Port 22: SSH (보안 셸)
Port 23: Telnet
Port 25: SMTP (단순 메일 전송 프로토콜)
Port 53: DNS (도메인 이름 시스템)
Port 67/68: DHCP (동적 호스트 구성)
Port 69: TFTP (간단한 파일 전송 프로토콜)
Port 80: HTTP (하이퍼텍스트 전송 프로토콜)
Port 110: POP3 (우체국 프로토콜 v3)
Port 143: IMAP (인터넷 메시지 액세스 프로토콜)
Port 161/162: SNMP (단순 네트워크 관리)
Port 443: HTTPS (HTTP 보안)
Port 993: IMAPS (IMAP 보안)
Port 995: POP3S (POP3 보안)
```

### 등록된 포트 (1024-49151)

일반적인 애플리케이션 및 데이터베이스 포트.

```text
# 데이터베이스 및 애플리케이션
Port 1433: Microsoft SQL Server
Port 1521: Oracle Database
Port 3306: MySQL Database
Port 3389: RDP (원격 데스크톱 프로토콜)
Port 5432: PostgreSQL Database

# 네트워크 서비스
Port 1812/1813: RADIUS 인증
Port 1701: L2TP (레이어 2 터널링 프로토콜)
Port 1723: PPTP (점 대 점 터널링 프로토콜)
Port 5060/5061: SIP (세션 개시 프로토콜)

# 보안 서비스
Port 636: LDAPS (LDAP 보안)
Port 989/990: FTPS (FTP 보안)
```

## 문제 해결 방법론

### CompTIA 문제 해결 단계

기술적 문제 해결을 위한 표준 방법론.

```text
# 6 단계 프로세스
1. 문제 식별
   - 정보 수집
   - 사용자에게 증상 문의
   - 시스템 변경 사항 식별
   - 가능한 경우 문제 복제

2. 추정 원인 이론 수립
   - 명백한 것부터 질문하기
   - 여러 접근 방식 고려
   - 간단한 해결책부터 시작

3. 원인 확인을 위해 이론 테스트
   - 이론이 확인되면 진행
   - 그렇지 않으면 새 이론 수립
   - 필요한 경우 에스컬레이션
```

### 구현 및 문서화

문제 해결 프로세스의 나머지 단계.

```text
# 나머지 단계
4. 실행 계획 수립
   - 해결 단계 결정
   - 잠재적 영향 식별
   - 솔루션 구현 또는 에스컬레이션

5. 솔루션 구현 또는 에스컬레이션
   - 적절한 수정 적용
   - 솔루션 철저히 테스트
   - 전체 기능 확인

6. 발견 사항, 조치 및 결과 문서화
   - 티켓 시스템 업데이트
   - 학습 내용 공유
   - 향후 발생 방지
```

## 성능 기반 질문 팁

### A+ 성능 질문

일반적인 시뮬레이션 시나리오 및 해결 방법.

```text
# 하드웨어 문제 해결
- PC 빌드에서 실패한 구성 요소 식별
- BIOS/UEFI 설정 구성
- RAM 설치 및 구성
- 스토리지 장치 올바르게 연결
- 전원 공급 장치 문제 해결

# 운영 체제 작업
- Windows 설치 및 구성
- 사용자 계정 및 권한 관리
- 네트워크 설정 구성
- 장치 드라이버 설치
- 시스템 파일 및 레지스트리 복구
```

### Network+ 시뮬레이션

네트워크 구성 및 문제 해결 시나리오.

```text
# 네트워크 구성
- VLAN 설정 및 포트 할당
- 라우터 ACL 구성
- 스위치 포트 보안 설정
- 무선 네트워크 설정
- IP 주소 지정 및 서브넷팅

# 문제 해결 작업
- 케이블 테스트 및 교체
- 네트워크 연결 진단
- DNS 및 DHCP 문제 해결
- 성능 최적화
- 보안 구현
```

### Security+ 시나리오

보안 구현 및 사고 대응.

```text
# 보안 구성
- 방화벽 규칙 생성
- 사용자 액세스 제어 설정
- 인증서 관리
- 암호화 구현
- 네트워크 분할

# 사고 대응
- 로그 분석 및 해석
- 위협 식별
- 취약점 평가
- 보안 제어 구현
- 위험 완화 전략
```

### 일반 시뮬레이션 팁

성능 기반 질문에 대한 모범 사례.

```text
# 성공 전략
- 지침을 주의 깊고 완전히 읽기
- 변경하기 전에 스크린샷 찍기
- 구현 후 구성 테스트
- 제거 과정을 통한 추론
- 시간 효과적으로 관리
- 시뮬레이션 소프트웨어로 연습
- 단계뿐만 아니라 근본적인 개념 이해
```

## 시험 등록 및 물류

### 시험 등록 절차

CompTIA 시험 예약 및 준비 단계.

```text
# 등록 단계
1. Pearson VUE 계정 생성
2. 인증 시험 선택
3. 테스트 센터 또는 온라인 옵션 선택
4. 시험 날짜 및 시간 예약
5. 시험 비용 지불
6. 확인 이메일 수신

# 시험 비용 (USD, 근사치)
CompTIA A+: $239 (시험당, 2 회 시험)
CompTIA Network+: $358
CompTIA Security+: $370
CompTIA Cloud+: $358
CompTIA PenTest+: $370
CompTIA CySA+: $392
```

### 시험 당일 준비

시험 당일 예상되는 사항 및 지참물.

```text
# 필수 지참물
- 유효한 정부 발행 사진 ID
- 확인 이메일/번호
- 30 분 일찍 도착
- 시험실에 개인 소지품 반입 금지

# 시험 형식
- 객관식 문제
- 성능 기반 문제 (시뮬레이션)
- 드래그 앤 드롭 문제
- 핫스팟 문제
- 시간 제한은 시험마다 다름 (90-165 분)
```

## 자격증 유지 관리

### 자격증 유효성

지속적인 교육 및 자격증 갱신.

```text
# 자격증 유효성
대부분의 CompTIA 자격증: 3 년
CompTIA A+: 영구적 (만료 없음)

# 지속 교육 단위 (CEU)
Security+: 3 년 동안 50 CEU
Network+: 3 년 동안 30 CEU
Cloud+: 3 년 동안 30 CEU

# CEU 활동
- 교육 과정 및 웨비나
- 산업 컨퍼런스
- 기사 출판
- 자원봉사
- 상위 수준 자격증 취득
```

### 경력 혜택

CompTIA 자격증의 가치와 인정도.

```text
# 업계 인정
- DOD 8570 승인 (Security+)
- 정부 계약자 요구 사항
- 채용 지원서 HR 필터링
- 급여 인상
- 경력 발전 기회
- 기술적 신뢰성
- 고급 자격증을 위한 기반
```

## 관련 링크

- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/cybersecurity">사이버 보안 치트 시트</router-link>
- <router-link to="/network">네트워크 치트 시트</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>
- <router-link to="/ansible">Ansible 치트 시트</router-link>

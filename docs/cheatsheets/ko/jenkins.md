---
title: 'Jenkins 치트 시트 | LabEx'
description: '이 종합 치트 시트로 Jenkins CI/CD를 학습하세요. Jenkins 파이프라인, 작업, 플러그인, 자동화, 지속적 통합 및 DevOps 워크플로우를 위한 빠른 참조 자료입니다.'
pdfUrl: '/cheatsheets/pdf/jenkins-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Jenkins 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/jenkins">Hands-On Labs 로 Jenkins 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
핸즈온 랩과 실제 시나리오를 통해 Jenkins CI/CD 자동화를 학습하세요. LabEx 는 필수 작업, 파이프라인 생성, 플러그인 관리, 빌드 자동화 및 고급 기술을 다루는 포괄적인 Jenkins 과정을 제공합니다. 현대 소프트웨어 개발을 위한 효율적인 지속적 통합 및 배포 파이프라인을 구축하기 위해 Jenkins 를 마스터하십시오.
</base-disclaimer-content>
</base-disclaimer>

## 설치 및 설정 (Installation & Setup)

### Linux 설치 (Linux Installation)

Ubuntu/Debian 시스템에 Jenkins 를 설치합니다.

```bash
# 패키지 관리자 업데이트 및 Java 설치
sudo apt update
sudo apt install fontconfig openjdk-21-jre
java -version
# Jenkins GPG 키 추가
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
# Jenkins 리포지토리 추가
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
/etc/apt/sources.list.d/jenkins.list > /dev/null
# Jenkins 설치
sudo apt update && sudo apt install jenkins
# Jenkins 서비스 시작
sudo systemctl start jenkins
sudo systemctl enable jenkins
```

### Windows 및 macOS (Windows & macOS)

설치 관리자 또는 패키지 관리자를 사용하여 Jenkins 를 설치합니다.

```bash
# Windows: jenkins.io에서 Jenkins 설치 관리자 다운로드
# 또는 Chocolatey 사용
choco install jenkins
# macOS: Homebrew 사용
brew install jenkins-lts
# 또는 다음에서 직접 다운로드:
# https://www.jenkins.io/download/
# Jenkins 서비스 시작
brew services start jenkins-lts
```

### 설치 후 설정 (Post-Installation Setup)

초기 구성 및 Jenkins 잠금 해제.

```bash
# 초기 관리자 비밀번호 가져오기
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# 또는 Docker 설치의 경우
docker exec jenkins_container cat /var/jenkins_home/secrets/initialAdminPassword
# Jenkins 웹 인터페이스 액세스
# http://localhost:8080 으로 이동
# 초기 관리자 비밀번호 입력
# 제안된 플러그인 설치 또는 사용자 지정 플러그인 선택
```

### 초기 구성 (Initial Configuration)

설정 마법사를 완료하고 관리자 사용자를 생성합니다.

```bash
# Jenkins 잠금 해제 후:
# 1. 제안된 플러그인 설치 (권장)
# 2. 첫 번째 관리자 사용자 생성
# 3. Jenkins URL 구성
# 4. Jenkins 사용 시작
# Jenkins 실행 확인
sudo systemctl status jenkins
# 필요한 경우 Jenkins 로그 확인
sudo journalctl -u jenkins.service
```

## 기본 Jenkins 작업 (Basic Jenkins Operations)

### Jenkins 액세스: 웹 인터페이스 및 CLI 설정 (Access Jenkins: Web Interface & CLI Setup)

브라우저를 통해 Jenkins 에 액세스하고 CLI 도구를 설정합니다.

```bash
# Jenkins 웹 인터페이스 액세스
http://localhost:8080
# Jenkins CLI 다운로드
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
# CLI 연결 테스트
java -jar jenkins-cli.jar -s http://localhost:8080 help
# 사용 가능한 명령어 목록 보기
java -jar jenkins-cli.jar -s http://localhost:8080 help
```

### 작업 생성: `create-job` / 웹 UI (Job Creation: `create-job` / Web UI)

CLI 또는 웹 인터페이스를 사용하여 새 빌드 작업을 생성합니다.

```bash
# XML 구성을 사용하여 작업 생성
java -jar jenkins-cli.jar -auth user:token create-job my-job < job-config.xml
# 웹 UI를 통해 간단한 프리스타일 작업 생성:
# 1. "새 항목(New Item)" 클릭
# 2. 작업 이름 입력
# 3. "프리스타일 프로젝트(Freestyle project)" 선택
# 4. 빌드 단계 구성
# 5. 구성 저장
```

### 작업 목록: `list-jobs` (List Jobs: `list-jobs`)

Jenkins 에 구성된 모든 작업을 확인합니다.

```bash
# 모든 작업 목록 보기
java -jar jenkins-cli.jar -auth user:token list-jobs
# 패턴 일치로 작업 목록 보기
java -jar jenkins-cli.jar -auth user:token list-jobs "*test*"
# 작업 구성 가져오기
java -jar jenkins-cli.jar -auth user:token get-job my-job > job-config.xml
```

## 작업 관리 (Job Management)

### 작업 빌드: `build` (Build Jobs: `build`)

작업 빌드를 트리거하고 관리합니다.

```bash
# 작업 빌드
java -jar jenkins-cli.jar -auth user:token build my-job
# 매개변수와 함께 빌드
java -jar jenkins-cli.jar -auth user:token build my-job -p PARAM=value
# 빌드가 완료될 때까지 대기
java -jar jenkins-cli.jar -auth user:token build my-job -s -v
# 빌드 및 콘솔 출력 팔로우
java -jar jenkins-cli.jar -auth user:token build my-job -f
```

<BaseQuiz id="jenkins-build-1" correct="B">
  <template #question>
    <code>jenkins-cli.jar build my-job -s</code>에서 <code>-s</code> 플래그는 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A">빌드를 건너뜁니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>빌드가 완료될 때까지 기다립니다 (동기식)</BaseQuizOption>
  <BaseQuizOption value="C">빌드 상태를 표시합니다</BaseQuizOption>
  <BaseQuizOption value="D">빌드를 중지합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-s</code> 플래그는 빌드 명령을 동기식으로 만들어 빌드가 완료될 때까지 기다린 후 반환합니다. 이 플래그가 없으면 명령은 빌드를 트리거한 직후에 반환됩니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 작업 제어: `enable-job` / `disable-job` (Job Control: `enable-job` / `disable-job`)

작업을 활성화하거나 비활성화합니다.

```bash
# 작업 활성화
java -jar jenkins-cli.jar -auth user:token enable-job my-job
# 작업 비활성화
java -jar jenkins-cli.jar -auth user:token disable-job my-job
# 웹 UI에서 작업 상태 확인
# 작업 대시보드로 이동
# "비활성화/활성화(Disable/Enable)" 버튼 확인
```

<BaseQuiz id="jenkins-job-control-1" correct="B">
  <template #question>
    Jenkins 작업을 비활성화하면 어떻게 됩니까?
  </template>
  
  <BaseQuizOption value="A">작업이 영구적으로 삭제됩니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>작업 구성은 보존되지만 자동으로 실행되지 않습니다</BaseQuizOption>
  <BaseQuizOption value="C">작업이 다른 폴더로 이동됩니다</BaseQuizOption>
  <BaseQuizOption value="D">모든 빌드 기록이 삭제됩니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    작업을 비활성화하면 자동으로 실행되는 것 (예약된 빌드, 트리거 등) 을 방지하지만 작업 구성과 빌드 기록은 보존됩니다. 나중에 다시 활성화할 수 있습니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 작업 삭제: `delete-job` (Job Deletion: `delete-job`)

Jenkins 에서 작업을 제거합니다.

```bash
# 작업 삭제
java -jar jenkins-cli.jar -auth user:token delete-job my-job
# 일괄 작업 삭제 (주의 필요)
for job in job1 job2 job3; do
  java -jar jenkins-cli.jar -auth user:token delete-job $job
done
```

### 콘솔 출력: `console` (Console Output: `console`)

빌드 로그 및 콘솔 출력을 확인합니다.

```bash
# 최신 빌드 콘솔 출력 보기
java -jar jenkins-cli.jar -auth user:token console my-job
# 특정 빌드 번호 보기
java -jar jenkins-cli.jar -auth user:token console my-job 15
# 실시간으로 콘솔 출력 팔로우
java -jar jenkins-cli.jar -auth user:token console my-job -f
```

<BaseQuiz id="jenkins-console-1" correct="C">
  <template #question>
    <code>jenkins-cli.jar console my-job -f</code>에서 <code>-f</code> 플래그는 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A">빌드를 강제로 중지합니다</BaseQuizOption>
  <BaseQuizOption value="B">실패한 빌드만 표시합니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>콘솔 출력을 실시간으로 팔로우합니다</BaseQuizOption>
  <BaseQuizOption value="D">출력을 JSON 형식으로 지정합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>-f</code> 플래그는 Linux 의 <code>tail -f</code>와 유사하게 콘솔 출력을 실시간으로 팔로우합니다. 이는 빌드가 실행되는 동안 모니터링하는 데 유용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

## 파이프라인 관리 (Pipeline Management)

### 파이프라인 생성 (Pipeline Creation)

Jenkins 파이프라인을 생성하고 구성합니다.

```groovy
// 기본 Jenkinsfile (선언적 파이프라인)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Building application...'
                sh 'make build'
            }
        }

        stage('Test') {
            steps {
                echo 'Running tests...'
                sh 'make test'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Deploying application...'
                sh 'make deploy'
            }
        }
    }
}
```

### 파이프라인 구문 (Pipeline Syntax)

일반적인 파이프라인 구문 및 지시문.

```groovy
// 스크립트 기반 파이프라인 구문
node {
    stage('Checkout') {
        checkout scm
    }

    stage('Build') {
        sh 'make build'
    }

    stage('Test') {
        sh 'make test'
        junit 'target/test-results/*.xml'
    }
}
// 병렬 실행
stages {
    stage('Parallel Tests') {
        parallel {
            stage('Unit Tests') {
                steps {
                    sh 'make unit-test'
                }
            }
            stage('Integration Tests') {
                steps {
                    sh 'make integration-test'
                }
            }
        }
    }
}
```

### 파이프라인 구성 (Pipeline Configuration)

고급 파이프라인 구성 및 옵션.

```groovy
// 빌드 후 조치가 있는 파이프라인
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }

    post {
        always {
            echo 'This always runs'
        }
        success {
            echo 'Build succeeded'
        }
        failure {
            echo 'Build failed'
            emailext subject: 'Build Failed',
                     body: 'Build failed',
                     to: 'team@company.com'
        }
    }
}
```

### 파이프라인 트리거 (Pipeline Triggers)

파이프라인 자동 트리거를 구성합니다.

```groovy
// 트리거가 있는 파이프라인
pipeline {
    agent any

    triggers {
        // 5분마다 SCM 폴링
        pollSCM('H/5 * * * *')

        // Cron과 유사한 스케줄링
        cron('H 2 * * *')  // 매일 오전 2시

        // 상위 작업 트리거
        upstream(upstreamProjects: 'upstream-job',
                threshold: hudson.model.Result.SUCCESS)
    }

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}
```

## 플러그인 관리 (Plugin Management)

### 플러그인 설치: CLI (Plugin Installation: CLI)

명령줄 인터페이스를 사용하여 플러그인을 설치합니다.

```bash
# CLI를 통해 플러그인 설치 (재시작 필요)
java -jar jenkins-cli.jar -auth user:token install-plugin git
# 여러 플러그인 설치
java -jar jenkins-cli.jar -auth user:token install-plugin \
  git maven-plugin docker-plugin
# .hpi 파일에서 설치
java -jar jenkins-cli.jar -auth user:token install-plugin \
  /path/to/plugin.hpi
# 설치된 플러그인 목록 보기
java -jar jenkins-cli.jar -auth user:token list-plugins
# plugins.txt를 사용한 플러그인 설치 (Docker용)
# plugins.txt 파일 생성:
git:latest
maven-plugin:latest
docker-plugin:latest
pipeline-stage-view:latest
# jenkins-plugin-cli 도구 사용
jenkins-plugin-cli --plugins git maven-plugin docker-plugin
```

### 필수 플러그인 (Essential Plugins)

다양한 목적으로 일반적으로 사용되는 Jenkins 플러그인.

```bash
# 빌드 및 SCM 플러그인
git                    # Git 통합
github                 # GitHub 통합
maven-plugin          # Maven 빌드 지원
gradle                # Gradle 빌드 지원
# 파이프라인 플러그인
workflow-aggregator   # 파이프라인 플러그인 모음
pipeline-stage-view   # 파이프라인 단계 보기
blue-ocean           # 파이프라인을 위한 최신 UI
# 배포 및 통합
docker-plugin        # Docker 통합
kubernetes           # Kubernetes 배포
ansible              # Ansible 자동화
# 품질 및 테스트
junit                # JUnit 테스트 보고서
jacoco              # 코드 커버리지
sonarqube           # 코드 품질 분석
```

### 플러그인 관리 웹 UI (Plugin Management Web UI)

Jenkins 웹 인터페이스를 통해 플러그인을 관리합니다.

```bash
# 플러그인 관리자 액세스:
# 1. Jenkins 관리 → 플러그인 관리로 이동
# 2. "사용 가능(Available)"/"설치됨(Installed)"/"업데이트(Updates)" 탭 사용
# 3. 플러그인 검색
# 4. 선택 및 설치
# 5. 필요한 경우 Jenkins 재시작
# 플러그인 업데이트 프로세스:
# 1. "업데이트(Updates)" 탭 확인
# 2. 업데이트할 플러그인 선택
# 3. "지금 다운로드하고 재시작 후 설치(Download now and install after restart)" 클릭
```

## 사용자 관리 및 보안 (User Management & Security)

### 사용자 관리 (User Management)

Jenkins 사용자 생성 및 관리.

```bash
# Jenkins 보안 활성화:
# 1. Jenkins 관리 → 보안 구성으로 이동
# 2. "Jenkins 자체 사용자 데이터베이스" 활성화
# 3. 사용자 가입 허용 (초기 설정 시)
# 4. 권한 부여 전략 설정
# CLI를 통한 사용자 생성 (적절한 권한 필요)
# 사용자는 일반적으로 웹 UI를 통해 생성됩니다:
# 1. Jenkins 관리 → 사용자 관리
# 2. "사용자 생성(Create User)" 클릭
# 3. 사용자 세부 정보 입력
# 4. 역할/권한 할당
```

### 인증 및 권한 부여 (Authentication & Authorization)

보안 영역 및 권한 부여 전략 구성.

```bash
# 보안 구성 옵션:
# 1. 보안 영역 (사용자 인증 방식):
#    - Jenkins 자체 사용자 데이터베이스
#    - LDAP
#    - Active Directory
#    - 행렬 기반 보안
#    - 역할 기반 권한 부여
# 2. 권한 부여 전략:
#    - 누구나 모든 작업 수행 가능
#    - 레거시 모드
#    - 로그인한 사용자는 모든 작업 수행 가능
#    - 행렬 기반 보안
#    - 프로젝트 기반 행렬 권한 부여
```

### API 토큰 (API Tokens)

CLI 액세스를 위한 API 토큰 생성 및 관리.

```bash
# API 토큰 생성:
# 1. 사용자 이름 클릭 → 구성
# 2. API 토큰 섹션
# 3. "새 토큰 추가(Add new Token)" 클릭
# 4. 토큰 이름 입력
# 5. 생성 및 복사
# CLI에서 API 토큰 사용
java -jar jenkins-cli.jar -auth username:api-token \
  -s http://localhost:8080 list-jobs
# 자격 증명 안전하게 저장
echo "username:api-token" > ~/.jenkins-cli-auth
chmod 600 ~/.jenkins-cli-auth
```

### 자격 증명 관리 (Credentials Management)

작업 및 파이프라인을 위한 저장된 자격 증명 관리.

```bash
# CLI를 통한 자격 증명 관리
java -jar jenkins-cli.jar -auth user:token \
  list-credentials system::system::jenkins
# 자격 증명 XML 생성 및 가져오기
java -jar jenkins-cli.jar -auth user:token \
  create-credentials-by-xml system::system::jenkins \
  < credential.xml
```

```groovy
// 파이프라인에서 자격 증명 액세스
withCredentials([usernamePassword(
  credentialsId: 'my-credentials',
  usernameVariable: 'USERNAME',
  passwordVariable: 'PASSWORD'
)]) {
  sh 'docker login -u $USERNAME -p $PASSWORD'
}
```

## 빌드 모니터링 및 문제 해결 (Build Monitoring & Troubleshooting)

### 빌드 상태 및 로그 (Build Status & Logs)

빌드 상태를 모니터링하고 상세 로그에 액세스합니다.

```bash
# 빌드 상태 확인
java -jar jenkins-cli.jar -auth user:token console my-job
# 빌드 정보 가져오기
java -jar jenkins-cli.jar -auth user:token get-job my-job
# 빌드 대기열 모니터링
# 웹 UI: Jenkins 대시보드 → 빌드 대기열
# 보류 중인 빌드 및 상태 표시
# 빌드 기록 액세스
# 웹 UI: 작업 → 빌드 기록
# 상태와 함께 이전의 모든 빌드 표시
```

### 시스템 정보 (System Information)

Jenkins 시스템 정보 및 진단 정보 가져오기.

```bash
# 시스템 정보
java -jar jenkins-cli.jar -auth user:token version
# 노드 정보
java -jar jenkins-cli.jar -auth user:token list-computers
# Groovy 콘솔 (관리자 전용)
# Jenkins 관리 → 스크립트 콘솔
# 시스템 정보를 위해 Groovy 스크립트 실행:
println Jenkins.instance.version
println Jenkins.instance.getRootDir()
println System.getProperty("java.version")
```

### 로그 분석 (Log Analysis)

Jenkins 시스템 로그 액세스 및 분석.

```bash
# 시스템 로그 위치
# Linux: /var/log/jenkins/jenkins.log
# Windows: C:\Program Files\Jenkins\jenkins.out.log
# 로그 보기
tail -f /var/log/jenkins/jenkins.log
# 로그 수준 구성
# Jenkins 관리 → 시스템 로그
# 특정 구성 요소에 대한 새 로그 기록기 추가
# 일반적인 로그 위치:
sudo journalctl -u jenkins.service     # Systemd 로그
sudo cat /var/lib/jenkins/jenkins.log  # Jenkins 로그 파일
```

### 성능 모니터링 (Performance Monitoring)

Jenkins 성능 및 리소스 사용량 모니터링.

```bash
# 내장 모니터링
# Jenkins 관리 → 부하 통계
# 시간 경과에 따른 실행기 활용도 표시
# JVM 모니터링
# Jenkins 관리 → 노드 관리 → 마스터
# 메모리, CPU 사용량 및 시스템 속성 표시
# 빌드 추세
# "빌드 기록(Build History)" 플러그인 설치
# 빌드 기간 추세 및 성공률 보기
# 디스크 사용량 모니터링
# "디스크 사용량(Disk Usage)" 플러그인 설치
# 작업 공간 및 빌드 아티팩트 저장 공간 모니터링
```

## Jenkins 구성 및 설정 (Jenkins Configuration & Settings)

### 전역 구성 (Global Configuration)

Jenkins 전역 설정 및 도구 구성.

```bash
# 전역 도구 구성
# Jenkins 관리 → 전역 도구 구성
# 구성 항목:
# - JDK 설치
# - Git 설치
# - Maven 설치
# - Docker 설치
# 시스템 구성
# Jenkins 관리 → 시스템 구성
# 설정 항목:
# - Jenkins URL
# - 시스템 메시지
# - 실행기 수 (# of executors)
# - 조용한 기간 (Quiet period)
# - SCM 폴링 제한
```

### 환경 변수 (Environment Variables)

Jenkins 환경 변수 및 시스템 속성 구성.

```bash
# 내장 환경 변수
BUILD_NUMBER          # 빌드 번호
BUILD_ID              # 빌드 ID
JOB_NAME             # 작업 이름
WORKSPACE            # 작업 작업 공간 경로
JENKINS_URL          # Jenkins URL
NODE_NAME            # 노드 이름
# 사용자 지정 환경 변수
# Jenkins 관리 → 시스템 구성
# 전역 속성 → 환경 변수
# 전역 액세스를 위한 키-값 쌍 추가
```

### 코드로써의 Jenkins 구성 (Jenkins Configuration as Code)

JCasC 플러그인을 사용하여 Jenkins 구성 관리.

```yaml
# JCasC 구성 파일 (jenkins.yaml)
jenkins:
  systemMessage: "Jenkins configured as code"
  numExecutors: 4
  securityRealm:
    local:
      allowsSignup: false
      users:
       - id: "admin"
         password: "admin123"
# 구성 적용
# CASC_JENKINS_CONFIG 환경 변수 설정
export CASC_JENKINS_CONFIG=/path/to/jenkins.yaml
```

## 모범 사례 (Best Practices)

### 보안 모범 사례 (Security Best Practices)

Jenkins 인스턴스를 안전하게 유지하고 프로덕션 준비 상태로 유지합니다.

```bash
# 보안 권장 사항:
# 1. 보안 및 인증 활성화
# 2. 행렬 기반 권한 부여 사용
# 3. 정기적인 보안 업데이트
# 4. 사용자 권한 제한
# 5. 비밀번호 대신 API 토큰 사용
# Jenkins 구성 보안:
# - Remoting을 통한 CLI 비활성화
# - 유효한 인증서로 HTTPS 사용
# - JENKINS_HOME 정기 백업
# - 보안 권고 모니터링
# - 비밀 정보를 위해 자격 증명 플러그인 사용
```

### 성능 최적화 (Performance Optimization)

더 나은 성능과 확장성을 위해 Jenkins 를 최적화합니다.

```bash
# 성능 팁:
# 1. 에이전트를 사용하여 분산 빌드 사용
# 2. 빌드 스크립트 및 종속성 최적화
# 3. 오래된 빌드 자동 정리
# 4. 재사용성을 위해 파이프라인 라이브러리 사용
# 5. 디스크 공간 및 메모리 사용량 모니터링
# 빌드 최적화:
# - 가능한 경우 증분 빌드 사용
# - 단계 병렬 실행
# - 아티팩트 캐싱
# - 작업 공간 정리
# - 리소스 할당 조정
```

## 관련 링크 (Relevant Links)

- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>
- <router-link to="/ansible">Ansible 치트 시트</router-link>
- <router-link to="/git">Git 치트 시트</router-link>
- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>

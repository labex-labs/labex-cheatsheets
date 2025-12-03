---
title: '도커 치트 시트 | LabEx'
description: '포괄적인 치트 시트로 도커 컨테이너화를 학습하세요. 도커 명령어, 이미지, 컨테이너, Dockerfile, Docker Compose 및 컨테이너 오케스트레이션에 대한 빠른 참조.'
pdfUrl: '/cheatsheets/pdf/docker-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Docker 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/docker">Hands-On Labs 로 Docker 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
Hands-On 랩 및 실제 시나리오를 통해 Docker 컨테이너화를 학습하십시오. LabEx 는 필수 컨테이너 관리, 이미지 빌드, Docker Compose, 네트워킹, 볼륨 및 배포를 다루는 포괄적인 Docker 과정을 제공합니다. 컨테이너 오케스트레이션 및 최신 애플리케이션 배포 기술을 마스터하십시오.
</base-disclaimer-content>
</base-disclaimer>

## 설치 및 설정

### Linux 설치

Ubuntu/Debian 시스템에 Docker 를 설치합니다.

```bash
# 패키지 관리자 업데이트
sudo apt update
# 필수 패키지 설치
sudo apt install apt-transport-https ca-certificates curl
software-properties-common
# Docker 공식 GPG 키 추가
curl -fsSL https://download.docker.com/linux/ubuntu/gpg
| sudo apt-key add -
# Docker 리포지토리 추가
sudo add-apt-repository "deb [arch=amd64]
https://download.docker.com/linux/ubuntu bionic stable"
# Docker 설치
sudo apt update && sudo apt install docker-ce
# Docker 서비스 시작
sudo systemctl start docker
sudo systemctl enable docker
```

### Windows 및 macOS

GUI 기반 관리를 위해 Docker Desktop 을 설치합니다.

```bash
# Windows: docker.com에서 Docker Desktop 다운로드
# macOS: Homebrew 사용 또는 docker.com에서 다운로드
brew install --cask docker
# 또는 다음에서 직접 다운로드:
# https://www.docker.com/products/docker-desktop
```

### 설치 후 설정

비-root 사용을 위한 Docker 구성 및 설치 확인.

```bash
# Docker 그룹에 사용자 추가 (Linux)
sudo usermod -aG docker $USER
# 그룹 변경 사항 적용을 위해 로그아웃 후 다시 로그인
# Docker 설치 확인
docker --version
docker run hello-world
```

### Docker Compose 설치

다중 컨테이너 애플리케이션을 위해 Docker Compose 를 설치합니다.

```bash
# Linux: curl을 통해 설치
sudo curl -L
"https://github.com/docker/compose/releases/download
/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o
/usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
# 설치 확인
docker-compose --version
# 참고: Docker Desktop에는 Compose가 포함되어 있습니다
```

## 기본 Docker 명령어

### 시스템 정보: `docker version` / `docker system info`

Docker 설치 및 환경 세부 정보를 확인합니다.

```bash
# Docker 버전 정보 표시
docker version
# 시스템 전체 Docker 정보 표시
docker system info
# Docker 명령어 도움말 표시
docker help
docker <command> --help
```

### 컨테이너 실행: `docker run`

이미지로부터 컨테이너를 생성하고 시작합니다.

```bash
# 대화형으로 컨테이너 실행
docker run -it ubuntu:latest bash
# 컨테이너를 백그라운드에서 실행 (분리 모드)
docker run -d --name my-container
nginx
# 포트 매핑을 사용하여 실행
docker run -p 8080:80 nginx
# 종료 후 자동 제거하며 실행
docker run --rm hello-world
```

<BaseQuiz id="docker-run-1" correct="C">
  <template #question>
    `docker run -d`는 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A">컨테이너를 디버그 모드로 실행합니다</BaseQuizOption>
  <BaseQuizOption value="B">컨테이너가 중지되면 삭제합니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>컨테이너를 분리 모드 (백그라운드) 로 실행합니다</BaseQuizOption>
  <BaseQuizOption value="D">기본 설정으로 컨테이너를 실행합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-d` 플래그는 컨테이너를 분리 모드로 실행하여 백그라운드에서 실행하고 즉시 터미널 제어권을 반환합니다. 이는 장기 실행 서비스에 유용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 컨테이너 목록: `docker ps`

실행 중인 컨테이너와 중지된 컨테이너를 확인합니다.

```bash
# 실행 중인 컨테이너 목록
docker ps
# 모든 컨테이너 목록 (중지된 컨테이너 포함)
docker ps -a
# 컨테이너 ID만 목록화
docker ps -q
# 가장 최근에 생성된 컨테이너 표시
docker ps -l
```

## 컨테이너 관리

### 컨테이너 수명 주기: `start` / `stop` / `restart`

컨테이너 실행 상태를 제어합니다.

```bash
# 실행 중인 컨테이너 중지
docker stop container_name
# 중지된 컨테이너 시작
docker start container_name
# 컨테이너 재시작
docker restart container_name
# 컨테이너 프로세스 일시 중지/재개
docker pause container_name
docker unpause container_name
```

### 명령어 실행: `docker exec`

실행 중인 컨테이너 내에서 명령어를 실행합니다.

```bash
# 대화형 bash 셸 실행
docker exec -it container_name bash
# 단일 명령어 실행
docker exec container_name ls -la
# 다른 사용자로 실행
docker exec -u root container_name whoami
# 특정 디렉토리에서 실행
docker exec -w /app container_name pwd
```

### 컨테이너 제거: `docker rm`

시스템에서 컨테이너를 제거합니다.

```bash
# 중지된 컨테이너 제거
docker rm container_name
# 실행 중인 컨테이너 강제 제거
docker rm -f container_name
# 여러 컨테이너 제거
docker rm container1 container2
# 중지된 모든 컨테이너 제거
docker container prune
```

### 컨테이너 로그: `docker logs`

컨테이너 출력을 보고 문제를 디버깅합니다.

```bash
# 컨테이너 로그 보기
docker logs container_name
# 실시간으로 로그 추적
docker logs -f container_name
# 최근 로그만 표시
docker logs --tail 50 container_name
# 타임스탬프와 함께 로그 보기
docker logs -t container_name
```

## 이미지 관리

### 이미지 빌드: `docker build`

Dockerfile 로부터 Docker 이미지를 생성합니다.

```bash
# 현재 디렉토리에서 이미지 빌드
docker build .
# 이미지 빌드 및 태그 지정
docker build -t myapp:latest .
# 빌드 인수를 사용하여 빌드
docker build --build-arg VERSION=1.0 -t myapp .
# 캐시를 사용하지 않고 빌드
docker build --no-cache -t myapp .
```

<BaseQuiz id="docker-build-1" correct="A">
  <template #question>
    `docker build -t myapp:latest .`는 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A" correct>현재 디렉토리에서 "myapp:latest" 태그로 Docker 이미지를 빌드합니다</BaseQuizOption>
  <BaseQuizOption value="B">"myapp"이라는 컨테이너를 실행합니다</BaseQuizOption>
  <BaseQuizOption value="C">Docker Hub 에서 "myapp:latest" 이미지를 가져옵니다</BaseQuizOption>
  <BaseQuizOption value="D">"myapp:latest" 이미지를 삭제합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-t` 플래그는 이미지를 "myapp:latest"로 태그 지정하며, `.` 은 빌드 컨텍스트 (현재 디렉토리) 를 지정합니다. 이 명령어는 현재 디렉토리의 Dockerfile 로부터 새 이미지를 빌드합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 이미지 검사: `docker images` / `docker inspect`

Docker 이미지를 나열하고 검사합니다.

```bash
# 모든 로컬 이미지 목록
docker images
# 특정 필터로 이미지 목록화
docker images nginx
# 이미지 세부 정보 표시
docker inspect image_name
# 이미지 빌드 기록 보기
docker history image_name
```

### 레지스트리 작업: `docker pull` / `docker push`

이미지를 레지스트리에서 다운로드하고 업로드합니다.

```bash
# Docker Hub에서 이미지 가져오기
docker pull nginx:latest
# 특정 버전 가져오기
docker pull ubuntu:20.04
# 레지스트리로 이미지 푸시
docker push myusername/myapp:latest
# 푸시 전 이미지 태그 지정
docker tag myapp:latest myusername/myapp:v1.0
```

### 이미지 정리: `docker rmi` / `docker image prune`

디스크 공간 확보를 위해 사용하지 않는 이미지를 제거합니다.

```bash
# 특정 이미지 제거
docker rmi image_name
# 사용하지 않는 이미지 제거
docker image prune
# 모든 사용하지 않는 이미지 제거 (댕글링 이미지뿐만 아니라)
docker image prune -a
# 이미지 강제 제거
docker rmi -f image_name
```

## Dockerfile 기본 사항

### 필수 명령어

이미지 빌드를 위한 핵심 Dockerfile 명령어.

```dockerfile
# 베이스 이미지
FROM ubuntu:20.04
# 유지 관리자 정보 설정
LABEL maintainer="user@example.com"
# 패키지 설치
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# 호스트에서 컨테이너로 파일 복사
COPY app.py /app/
# 작업 디렉토리 설정
WORKDIR /app
# 포트 노출
EXPOSE 8000
```

<BaseQuiz id="dockerfile-1" correct="B">
  <template #question>
    Dockerfile 에서 `FROM` 명령어의 목적은 무엇입니까?
  </template>
  
  <BaseQuizOption value="A">호스트에서 컨테이너로 파일을 복사합니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>기반이 될 베이스 이미지를 지정합니다</BaseQuizOption>
  <BaseQuizOption value="C">환경 변수를 설정합니다</BaseQuizOption>
  <BaseQuizOption value="D">컨테이너 시작 시 실행될 명령어를 정의합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `FROM` 명령어는 Dockerfile 의 첫 번째 주석이 아닌 명령어여야 합니다. 이는 이미지 빌드의 기반이 될 베이스 이미지를 지정하여 컨테이너의 토대를 제공합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 런타임 구성

컨테이너 실행 방식을 구성합니다.

```dockerfile
# 환경 변수 설정
ENV PYTHON_ENV=production
ENV PORT=8000
# 보안을 위해 사용자 생성
RUN useradd -m appuser
USER appuser
# 시작 명령어 정의
CMD ["python3", "app.py"]
# 고정된 명령어를 위해 ENTRYPOINT 사용
ENTRYPOINT ["python3"]
CMD ["app.py"]
# 헬스 체크 설정
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/ || exit 1
```

## Docker Compose

### 기본 Compose 명령어: `docker-compose up` / `docker-compose down`

다중 컨테이너 애플리케이션을 시작하고 중지합니다.

```bash
# 포그라운드에서 서비스 시작
docker-compose up
# 백그라운드에서 서비스 시작
docker-compose up -d
# 서비스 빌드 및 시작
docker-compose up --build
# 서비스 중지 및 제거
docker-compose down
# 볼륨과 함께 중지 및 제거
docker-compose down -v
```

<BaseQuiz id="docker-compose-1" correct="D">
  <template #question>
    `docker-compose up -d`는 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A">실행 중인 모든 컨테이너를 중지합니다</BaseQuizOption>
  <BaseQuizOption value="B">컨테이너를 시작하지 않고 이미지를 빌드합니다</BaseQuizOption>
  <BaseQuizOption value="C">모든 서비스의 로그를 표시합니다</BaseQuizOption>
  <BaseQuizOption value="D" correct>docker-compose.yml 에 정의된 모든 서비스를 분리 모드 (detached mode) 로 시작합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `-d` 플래그는 컨테이너를 분리 모드 (백그라운드) 로 실행합니다. `docker-compose up`은 docker-compose.yml 파일을 읽고 정의된 모든 서비스를 시작하여 다중 컨테이너 애플리케이션 관리를 용이하게 합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 서비스 관리

Compose 애플리케이션 내의 개별 서비스를 제어합니다.

```bash
# 실행 중인 서비스 목록
docker-compose ps
# 서비스 로그 보기
docker-compose logs service_name
# 모든 서비스 로그 추적
docker-compose logs -f
# 특정 서비스 재시작
docker-compose restart service_name
```

### 샘플 docker-compose.yml

다중 서비스 애플리케이션 구성 예시.

```yaml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      -
DATABASE_URL=postgresql://user:pass@db:5432/myapp
    depends_on:
      - db
    volumes:
      - .:/app

  db:
    image: postgres:13
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - db_data:/var/lib/postgresql/data
volumes:
  db_data:
```

## 네트워킹 및 볼륨

### 컨테이너 네트워킹

컨테이너를 연결하고 서비스를 노출합니다.

```bash
# 네트워크 목록
docker network ls
# 사용자 정의 네트워크 생성
docker network create mynetwork
# 특정 네트워크에서 컨테이너 실행
docker run --network mynetwork nginx
# 실행 중인 컨테이너를 네트워크에 연결
docker network connect mynetwork container_name
# 네트워크 세부 정보 검사
docker network inspect mynetwork
```

### 포트 매핑

컨테이너 포트를 호스트 시스템에 노출합니다.

```bash
# 단일 포트 매핑
docker run -p 8080:80 nginx
```

<BaseQuiz id="docker-port-1" correct="A">
  <template #question>
    `docker run -p 8080:80 nginx`에서 포트 번호는 무엇을 의미합니까?
  </template>
  
  <BaseQuizOption value="A" correct>8080 은 호스트 포트, 80 은 컨테이너 포트입니다</BaseQuizOption>
  <BaseQuizOption value="B">80 은 호스트 포트, 8080 은 컨테이너 포트입니다</BaseQuizOption>
  <BaseQuizOption value="C">두 포트 모두 컨테이너 포트입니다</BaseQuizOption>
  <BaseQuizOption value="D">두 포트 모두 호스트 포트입니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    형식은 `-p host_port:container_port`입니다. 호스트 머신의 8080 포트가 컨테이너 내부의 80 포트에 매핑되어, localhost:8080 을 통해 컨테이너에서 실행 중인 nginx 웹 서버에 액세스할 수 있습니다.
  </BaseQuizAnswer>
</BaseQuiz>

```bash
# 여러 포트 매핑
docker run -p 8080:80 -p 8443:443 nginx
# 특정 호스트 인터페이스에 매핑
docker run -p 127.0.0.1:8080:80 nginx
# 이미지에 정의된 모든 포트 노출
docker run -P nginx
```

### 데이터 볼륨: `docker volume`

컨테이너 간 데이터 영속화 및 공유.

```bash
# 이름 있는 볼륨 생성
docker volume create myvolume
# 모든 볼륨 목록
docker volume ls
# 볼륨 세부 정보 검사
docker volume inspect myvolume
# 볼륨 제거
docker volume rm myvolume
# 사용하지 않는 볼륨 제거
docker volume prune
```

### 볼륨 마운트

컨테이너에 볼륨 및 호스트 디렉토리를 마운트합니다.

```bash
# 이름 있는 볼륨 마운트
docker run -v myvolume:/data nginx
# 호스트 디렉토리 마운트 (바인드 마운트)
docker run -v /host/path:/container/path nginx
# 현재 디렉토리 마운트
docker run -v $(pwd):/app nginx
# 읽기 전용 마운트
docker run -v /host/path:/container/path:ro nginx
```

## 컨테이너 검사 및 디버깅

### 컨테이너 세부 정보: `docker inspect`

컨테이너 및 이미지에 대한 자세한 정보를 얻습니다.

```bash
# 컨테이너 구성 검사
docker inspect container_name
# 포맷을 사용하여 특정 정보 가져오기
docker inspect --format='{{.State.Status}}'
container_name
# IP 주소 가져오기
docker inspect --format='{{.NetworkSettings.IPAddress}}'
container_name
# 마운트된 볼륨 가져오기
docker inspect --format='{{.Mounts}}' container_name
```

### 리소스 모니터링

컨테이너 리소스 사용량 및 성능을 모니터링합니다.

```bash
# 컨테이너 내 실행 중인 프로세스 표시
docker top container_name
# 실시간 리소스 사용량 통계 표시
docker stats
# 특정 컨테이너 통계 표시
docker stats container_name
# 실시간으로 이벤트 모니터링
docker events
```

### 파일 작업: `docker cp`

컨테이너와 호스트 시스템 간에 파일을 복사합니다.

```bash
# 컨테이너에서 호스트로 파일 복사
docker cp container_name:/path/to/file ./
# 호스트에서 컨테이너로 파일 복사
docker cp ./file container_name:/path/to/destination
# 디렉토리 복사
docker cp ./directory
container_name:/path/to/destination/
# 권한 유지를 위해 아카이브 모드로 복사
docker cp -a ./directory container_name:/path/
```

### 문제 해결

컨테이너 문제 및 연결 문제를 디버깅합니다.

```bash
# 컨테이너 종료 코드 확인
docker inspect --format='{{.State.ExitCode}}'
container_name
# 컨테이너 프로세스 보기
docker exec container_name ps aux
# 네트워크 연결 테스트
docker exec container_name ping google.com
# 디스크 사용량 확인
docker exec container_name df -h
```

## 레지스트리 및 인증

### Docker Hub 작업: `docker login` / `docker search`

Docker Hub 에 인증하고 상호 작용합니다.

```bash
# Docker Hub 로그인
docker login
# 특정 레지스트리에 로그인
docker login registry.example.com
# Docker Hub에서 이미지 검색
docker search nginx
# 필터를 사용하여 검색
docker search --filter stars=100 nginx
```

### 이미지 태그 지정 및 게시

레지스트리에 이미지를 준비하고 게시합니다.

```bash
# 레지스트리를 위한 이미지 태그 지정
docker tag myapp:latest username/myapp:v1.0
docker tag myapp:latest
registry.example.com/myapp:latest
# Docker Hub로 푸시
docker push username/myapp:v1.0
# 비공개 레지스트리로 푸시
docker push registry.example.com/myapp:latest
```

### 비공개 레지스트리

비공개 Docker 레지스트리 작업.

```bash
# 비공개 레지스트리에서 가져오기
docker pull registry.company.com/myapp:latest
# 로컬 레지스트리 실행
docker run -d -p 5000:5000 --name registry registry:2
# 로컬 레지스트리로 태그 지정
docker tag myapp localhost:5000/myapp
docker push localhost:5000/myapp
```

### 이미지 보안

이미지 무결성 및 보안 확인.

```bash
# Docker Content Trust 활성화
export DOCKER_CONTENT_TRUST=1
# 이미지 서명 및 푸시
docker push username/myapp:signed
# 이미지 서명 검증
docker trust inspect username/myapp:signed
# 취약점에 대해 이미지 스캔
docker scan myapp:latest
```

## 시스템 정리 및 유지 관리

### 시스템 정리: `docker system prune`

디스크 공간 확보를 위해 사용하지 않는 Docker 리소스 제거.

```bash
# 사용하지 않는 컨테이너, 네트워크, 이미지 제거
docker system prune
# 정리 시 사용하지 않는 볼륨 포함
docker system prune -a --volumes
# 모든 것 제거 (주의하여 사용)
docker system prune -a -f
# 공간 사용량 표시
docker system df
```

### 대상 정리

사용하지 않는 특정 유형의 리소스 제거.

```bash
# 중지된 컨테이너 제거
docker container prune
# 사용하지 않는 이미지 제거
docker image prune -a
# 사용하지 않는 볼륨 제거
docker volume prune
# 사용하지 않는 네트워크 제거
docker network prune
```

### 일괄 작업

여러 컨테이너/이미지에 작업 수행.

```bash
# 실행 중인 모든 컨테이너 중지
docker stop $(docker ps -q)
# 모든 컨테이너 제거
docker rm $(docker ps -aq)
# 모든 이미지 제거
docker rmi $(docker images -q)
# 댕글링 이미지(dangling images)만 제거
docker rmi $(docker images -f "dangling=true" -q)
```

### 리소스 제한

컨테이너 리소스 소비 제어.

```bash
# 메모리 사용량 제한
docker run --memory=512m nginx
# CPU 사용량 제한
docker run --cpus="1.5" nginx
# CPU 및 메모리 모두 제한
docker run --memory=1g --cpus="2.0" nginx
# 재시작 정책 설정
docker run --restart=always nginx
```

## Docker 구성 및 설정

### 데몬 구성

프로덕션 사용을 위해 Docker 데몬 구성.

```bash
# 데몬 구성 편집
sudo nano
/etc/docker/daemon.json
# 예시 구성:
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
# Docker 서비스 재시작
sudo systemctl restart docker
```

### 환경 변수

환경 변수를 사용하여 Docker 클라이언트 동작 구성.

```bash
# Docker 호스트 설정
export
DOCKER_HOST=tcp://remote-
docker:2376
# TLS 인증 활성화
export DOCKER_TLS_VERIFY=1
export
DOCKER_CERT_PATH=/path/to/c
erts
# 기본 레지스트리 설정
export
DOCKER_REGISTRY=registry.co
mpany.com
# 디버그 출력
export DOCKER_BUILDKIT=1
```

### 성능 튜닝

더 나은 성능을 위해 Docker 최적화.

```bash
# 실험적 기능 활성화
echo '{"experimental": true}' |
sudo tee
/etc/docker/daemon.json
# 스토리지 드라이버 옵션 구성
{
  "storage-driver": "overlay2",
  "storage-opts": [

"overlay2.override_kernel_check
=true"
  ]
}
# 로깅 구성
{
  "log-driver": "syslog",
  "log-opts": {"syslog-address":
"udp://logs.company.com:514"}
}
```

## 모범 사례

### 보안 모범 사례

컨테이너를 안전하게 유지하고 프로덕션 준비 상태로 유지.

```dockerfile
# Dockerfile에서 비-root 사용자로 실행
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# 'latest' 대신 특정 이미지 태그 사용
FROM node:16.20.0-alpine
# 가능한 경우 읽기 전용 파일 시스템 사용
docker run --read-only nginx
```

### 성능 최적화

속도와 리소스 효율성을 위해 컨테이너 최적화.

```dockerfile
# 이미지 크기를 줄이기 위해 다단계 빌드 사용
FROM node:16 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
FROM node:16-alpine
WORKDIR /app
COPY --from=builder /app/node_modules
./node_modules
COPY . .
CMD ["node", "server.js"]
```

## 관련 링크

- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>
- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/ansible">Ansible 치트 시트</router-link>
- <router-link to="/git">Git 치트 시트</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>

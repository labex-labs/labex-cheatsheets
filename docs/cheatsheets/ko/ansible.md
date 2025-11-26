---
title: 'Ansible 치트 시트'
description: '필수 명령어, 개념 및 모범 사례를 다루는 포괄적인 치트 시트로 Ansible 을 학습하세요.'
pdfUrl: '/cheatsheets/pdf/ansible-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Ansible 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/ansible">Hands-On Labs 로 Ansible 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
Hands-On 랩과 실제 시나리오를 통해 Ansible 인프라 자동화를 학습하세요. LabEx 는 필수적인 플레이북 생성, 인벤토리 관리, 모듈 사용 및 역할 구성을 다루는 포괄적인 Ansible 과정을 제공합니다. DevOps 워크플로우를 위한 구성 관리 및 인프라 자동화를 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## 설치 및 설정 (Installation & Setup)

### Ubuntu/Debian: `apt install ansible`

Debian 기반 Linux 시스템에 Ansible 설치.

```bash
# Ansible 리포지토리 추가
sudo apt-add-repository ppa:ansible/ansible
# 패키지 목록 업데이트
sudo apt-get update
# Ansible 설치
sudo apt-get install ansible
# 설치 확인
ansible --version
```

### CentOS/RHEL: `yum install ansible`

Red Hat 기반 시스템에 Ansible 설치.

```bash
# EPEL 리포지토리 설치
sudo yum install epel-release -y
# Ansible 설치
sudo yum install ansible -y
# 설치 확인
ansible --version
```

### macOS: `brew install ansible`

Homebrew 를 사용하여 macOS 에 Ansible 설치.

```bash
# Homebrew를 사용하여 설치
brew install ansible
# 설치 확인
ansible --version
```

### 구성: `/etc/ansible/ansible.cfg`

Ansible 설정 및 기본값 구성.

```bash
# 현재 구성 보기
ansible-config list
# 적용되는 구성 보기
ansible-config view
# 사용자 지정 구성 파일
export ANSIBLE_CONFIG=/path/to/ansible.cfg
```

### SSH 설정: 키 기반 인증

Ansible 은 노드 간 통신을 위해 SSH 를 사용합니다.

```bash
# SSH 키 생성
ssh-keygen -t rsa -b 4096
# 공개 키를 원격 호스트에 복사
ssh-copy-id user@hostname
# SSH 연결 테스트
ssh user@hostname
```

### 환경 설정 (Environment Setup)

Ansible 환경 변수 및 경로 설정.

```bash
# 인벤토리 파일 위치 설정
export ANSIBLE_INVENTORY=/path/to/inventory
# 호스트 키 확인 설정
export ANSIBLE_HOST_KEY_CHECKING=False
# 원격 사용자 설정
export ANSIBLE_REMOTE_USER=ubuntu
```

## 인벤토리 관리 (Inventory Management)

### 기본 인벤토리: `/etc/ansible/hosts`

그룹 이름은 대괄호 안에 그룹 이름을 지정하여 생성할 수 있습니다.

```ini
# 기본 호스트 파일 (INI 형식)
[webservers]
web1.example.com
web2.example.com
[databases]
db1.example.com
db2.example.com
[all:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/id_rsa
```

### YAML 인벤토리 형식

인벤토리 파일은 INI 또는 YAML 형식일 수 있습니다.

```yaml
# inventory.yml
all:
  children:
    webservers:
      hosts:
        web1.example.com:
        web2.example.com:
    databases:
      hosts:
        db1.example.com:
      vars:
        mysql_port: 3306
```

### 호스트 변수 및 그룹 (Host Variables & Groups)

호스트별 변수 및 그룹 구성 정의.

```ini
# 변수가 포함된 인벤토리
[webservers]
web1.example.com http_port=80
web2.example.com http_port=8080
[webservers:vars]
ansible_user=nginx
nginx_version=1.18

# 인벤토리 테스트
ansible-inventory --list
ansible-inventory --graph
```

## 임시 명령어 (Ad-Hoc Commands)

### 기본 명령어 구조

Ansible 명령어의 기본 구조: `ansible <호스트> -m <모듈> -a "<인수>"`

```bash
# 연결 테스트
ansible all -m ping
# 특정 그룹 확인
ansible webservers -m ping
# 모든 호스트에서 명령어 실행
ansible all -m command -a "uptime"
# sudo 권한으로 실행
ansible all -m command -a "systemctl status nginx" --become
```

### 파일 작업 (File Operations)

호스트에 디렉터리, 파일 및 심볼릭 링크 생성.

```bash
# 디렉터리 생성
ansible all -m file -a "path=/tmp/test state=directory mode=0755"
# 파일 생성
ansible all -m file -a "path=/tmp/test.txt state=touch"
# 파일/디렉터리 삭제
ansible all -m file -a "path=/tmp/test state=absent"
# 심볼릭 링크 생성
ansible all -m file -a "src=/etc/nginx dest=/tmp/nginx state=link"
```

### 패키지 관리 (Package Management)

다양한 시스템에서 패키지 설치, 업데이트 및 제거.

```bash
# 패키지 설치 (apt)
ansible webservers -m apt -a "name=nginx state=present" --become
# 패키지 설치 (yum)
ansible webservers -m yum -a "name=httpd state=present" --become
# 모든 패키지 업데이트
ansible all -m apt -a "upgrade=dist" --become
# 패키지 제거
ansible all -m apt -a "name=apache2 state=absent" --become
```

### 서비스 관리 (Service Management)

시스템 서비스 시작, 중지 및 관리.

```bash
# 서비스 시작
ansible webservers -m service -a "name=nginx state=started" --become
# 서비스 중지
ansible webservers -m service -a "name=apache2 state=stopped" --become
# 서비스 재시작
ansible webservers -m service -a "name=ssh state=restarted" --become
# 부팅 시 서비스 활성화
ansible all -m service -a "name=nginx enabled=yes" --become
```

## 플레이북 및 태스크 (Playbooks & Tasks)

### 기본 플레이북 구조

어떤 태스크를 어떤 호스트에서 실행할지 정의하는 YAML 파일.

```yaml
---
- name: 웹 서버 설정
  hosts: webservers
  become: yes
  vars:
    nginx_port: 80

  tasks:
    - name: nginx 설치
      apt:
        name: nginx
        state: present

    - name: nginx 서비스 시작
      service:
        name: nginx
        state: started
        enabled: yes
```

### 플레이북 실행

다양한 옵션과 구성을 사용하여 플레이북 실행.

```bash
# 플레이북 실행
ansible-playbook site.yml
# 특정 인벤토리로 실행
ansible-playbook -i inventory.yml site.yml
# 드라이 런 (체크 모드)
ansible-playbook site.yml --check
# 특정 호스트에서 실행
ansible-playbook site.yml --limit webservers
# 추가 변수로 실행
ansible-playbook site.yml --extra-vars "nginx_port=8080"
```

### 태스크 옵션 및 조건문 (Task Options & Conditionals)

조건, 루프 및 오류 처리를 태스크에 추가.

```yaml
tasks:
  - name: 패키지 설치
    apt:
      name: '{{ item }}'
      state: present
    loop:
      - nginx
      - mysql-server
      - php
    when: ansible_os_family == "Debian"

  - name: 사용자 생성
    user:
      name: webuser
      state: present
    register: user_result

  - name: 사용자 생성 결과 표시
    debug:
      msg: '사용자 생성됨: {{ user_result.changed }}'
```

### 핸들러 및 알림 (Handlers & Notifications)

알림을 받을 때 실행되는 핸들러 정의.

```yaml
tasks:
  - name: nginx 구성 업데이트
    template:
      src: nginx.conf.j2
      dest: /etc/nginx/nginx.conf
    notify: nginx 재시작

handlers:
  - name: nginx 재시작
    service:
      name: nginx
      state: restarted
```

## 변수 및 템플릿 (Variables & Templates)

### 변수 정의 (Variable Definition)

다양한 수준과 범위에서 변수 정의.

```yaml
# 플레이북 내에서
vars:
  app_name: myapp
  app_port: 8080

# group_vars/all.yml 내에서
database_host: db.example.com
database_port: 5432

# host_vars/web1.yml 내에서
server_role: frontend
max_connections: 100

# 명령줄 변수
ansible-playbook site.yml -e "env=production"
```

### Jinja2 템플릿

템플릿을 사용하여 동적 구성 파일 생성.

```jinja2
# 템플릿 파일: nginx.conf.j2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};

    location / {
        proxy_pass http://{{ backend_host }}:{{ backend_port }};
    }
}
```

```yaml
# template 모듈 사용
- name: nginx 구성 배포
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/sites-available/default
  notify: nginx 리로드
```

### 팩트 및 시스템 정보 (Facts & System Information)

플레이북에서 시스템 팩트 수집 및 사용.

```bash
# 수동으로 팩트 수집
ansible all -m setup
# 특정 팩트 수집
ansible all -m setup -a "filter=ansible_eth*"
```

```yaml
# 플레이북에서 팩트 사용
- name: 시스템 정보 표시
  debug:
    msg: '{{ ansible_hostname }} 는 {{ ansible_distribution }} 에서 실행됨'

- name: OS 기반 패키지 설치
  apt:
    name: apache2
  when: ansible_os_family == "Debian"
```

### 볼트 및 비밀 관리 (Vault & Secrets Management)

Ansible Vault 를 사용하여 민감한 데이터 암호화.

```bash
# 암호화된 파일 생성
ansible-vault create secrets.yml
# 암호화된 파일 편집
ansible-vault edit secrets.yml
# 기존 파일 암호화
ansible-vault encrypt passwords.yml
# 볼트를 사용하여 플레이북 실행
ansible-playbook site.yml --ask-vault-pass
# 볼트 암호 파일 사용
ansible-playbook site.yml --vault-password-file .vault_pass
```

## 역할 및 구성 (Roles & Organization)

### 역할 구조 (Role Structure)

플레이북을 재사용 가능한 역할로 구성.

```bash
# 역할 구조 생성
ansible-galaxy init webserver
```

```
# 역할 디렉터리 구조
webserver/
├── tasks/
│   └── main.yml
├── handlers/
│   └── main.yml
├── templates/
├── files/
├── vars/
│   └── main.yml
├── defaults/
│   └── main.yml
└── meta/
    └── main.yml
```

### 플레이북에서 역할 사용

플레이북에서 호스트에 역할을 적용.

```yaml
---
- hosts: webservers
  roles:
    - common
    - webserver
    - { role: database, database_type: mysql }

# 또는 include_role 사용
- hosts: webservers
  tasks:
    - include_role:
        name: webserver
      vars:
        nginx_port: 8080
```

### Ansible Galaxy

Ansible Galaxy 에서 커뮤니티 역할 다운로드 및 관리.

```bash
# Galaxy에서 역할 설치
ansible-galaxy install geerlingguy.nginx
# 특정 버전 설치
ansible-galaxy install geerlingguy.nginx,2.8.0
# 요구 사항 파일에서 설치
ansible-galaxy install -r requirements.yml
# 설치된 역할 목록 보기
ansible-galaxy list
# 역할 제거
ansible-galaxy remove geerlingguy.nginx
```

### 컬렉션 (Collections)

확장된 기능을 위해 Ansible 컬렉션 사용.

```bash
# 컬렉션 설치
ansible-galaxy collection install community.general
```

```yaml
# 플레이북에서 컬렉션 사용
collections:
  - community.general
tasks:
  - name: 패키지 설치
    community.general.snap:
      name: code
      state: present
```

## 디버깅 및 문제 해결 (Debugging & Troubleshooting)

### 태스크 디버깅

플레이북 실행 디버깅 및 문제 해결.

```yaml
# 디버그 태스크 추가
- name: 변수 값 표시
  debug:
    var: my_variable
- name: 사용자 지정 메시지 표시
  debug:
    msg: '호스트 {{ inventory_hostname }} 는 IP {{ ansible_default_ipv4.address }} 를 사용함'
```

```bash
# 상세 실행
ansible-playbook site.yml -v
ansible-playbook site.yml -vvv  # 최대 상세 수준
```

### 오류 처리 (Error Handling)

오류를 우아하게 처리.

```yaml
- name: 실패할 수 있는 태스크
  command: /bin/false
  ignore_errors: yes

- name: rescue 포함된 태스크
  block:
    - command: /bin/false
  rescue:
    - debug:
        msg: '태스크 실패, rescue 실행 중'
  always:
    - debug:
        msg: '이것은 항상 실행됨'
```

### 테스트 및 검증 (Testing & Validation)

플레이북 테스트 및 구성 검증.

```bash
# 구문 확인
ansible-playbook site.yml --syntax-check
# 태스크 목록 보기
ansible-playbook site.yml --list-tasks
# 호스트 목록 보기
ansible-playbook site.yml --list-hosts
# 플레이북 단계별 실행
ansible-playbook site.yml --step
# 체크 모드로 테스트
ansible-playbook site.yml --check --diff
```

### 성능 및 최적화 (Performance & Optimization)

플레이북 성능 및 실행 최적화.

```yaml
# 병렬로 태스크 실행
- name: 패키지 설치
  apt:
    name: '{{ packages }}'
  vars:
    packages:
      - nginx
      - mysql-server

# 장기 실행 태스크에 async 사용
- name: 장기 실행 태스크
  command: /usr/bin/long-task
  async: 300
  poll: 5
```

## 모범 사례 및 팁 (Best Practices & Tips)

### 보안 모범 사례 (Security Best Practices)

Ansible 인프라 및 운영 보안 강화.

```bash
# 비밀 정보에 Ansible Vault 사용
ansible-vault create group_vars/all/vault.yml
# 호스트 키 확인은 신중하게 비활성화
host_key_checking = False
# 필요한 경우에만 become 사용
become: yes
become_user: root
# 플레이북 범위 제한
ansible-playbook site.yml --limit production
```

### 코드 구성 (Code Organization)

Ansible 프로젝트를 효과적으로 구조화.

```bash
# 권장 디렉터리 구조
ansible-project/
├── inventories/
│   ├── production/
│   └── staging/
├── group_vars/
├── host_vars/
├── roles/
├── playbooks/
└── ansible.cfg
```

```yaml
# 의미 있는 이름과 문서화 사용
- name: 설명이 풍부한 태스크 이름
  # 복잡한 로직에 대한 주석 추가
```

### 버전 제어 및 테스트 (Version Control & Testing)

적절한 버전 제어를 통해 Ansible 코드 관리.

```bash
# 버전 제어를 위해 Git 사용
git init
git add .
git commit -m "초기 Ansible 설정"
# 프로덕션 전에 스테이징에서 테스트
ansible-playbook -i staging site.yml
# 선택적 실행을 위해 태그 사용
ansible-playbook site.yml --tags "nginx,ssl"
```

## 구성 및 고급 기능 (Configuration & Advanced Features)

### Ansible 구성 (Ansible Configuration)

구성 옵션으로 Ansible 동작 사용자 정의.

```ini
# ansible.cfg
[defaults]
inventory = ./inventory
remote_user = ansible
host_key_checking = False
timeout = 30
forks = 5

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
pipelining = True
```

### 콜백 플러그인 (Callback Plugins)

콜백 플러그인을 사용하여 출력 및 로깅 향상.

```ini
# ansible.cfg 에서 콜백 플러그인 활성화
[defaults]
stdout_callback = yaml
callbacks_enabled = profile_tasks, timer

# 사용자 지정 콜백 구성
[callback_profile_tasks]
task_output_limit = 20
```

### 필터 및 조회 플러그인 (Filters & Lookups)

Jinja2 필터 및 조회 플러그인을 사용하여 데이터 조작.

```jinja2
# 템플릿에서 일반적인 필터
{{ variable | default('default_value') }}
{{ list_var | length }}
{{ string_var | upper }}
{{ dict_var | to_nice_yaml }}
```

```yaml
# 조회 플러그인
- name: 파일 내용 읽기
  debug:
    msg: "{{ lookup('file', '/etc/hostname') }}"

- name: 환경 변수
  debug:
    msg: "{{ lookup('env', 'HOME') }}"
```

### 동적 인벤토리 (Dynamic Inventories)

클라우드 및 컨테이너 환경을 위해 동적 인벤토리 사용.

```bash
# AWS EC2 동적 인벤토리
ansible-playbook -i ec2.py site.yml
# Docker 동적 인벤토리
ansible-playbook -i docker.yml site.yml
# 사용자 지정 인벤토리 스크립트
ansible-playbook -i ./dynamic_inventory.py site.yml
```

## 관련 링크 (Relevant Links)

- <router-link to="/linux">Linux 치트 시트</router-link>
- <router-link to="/shell">Shell 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/kubernetes">Kubernetes 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>

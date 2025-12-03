---
title: 'Guia Rápido Ansible | LabEx'
description: 'Aprenda automação Ansible com este guia completo. Referência rápida para playbooks, módulos, gerenciamento de inventário, configuração e automação de infraestrutura Ansible.'
pdfUrl: '/cheatsheets/pdf/ansible-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas Ansible
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/ansible">Aprenda Ansible com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda automação de infraestrutura com Ansible através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Ansible cobrindo criação essencial de playbooks, gerenciamento de inventário, uso de módulos e organização de funções. Domine o gerenciamento de configuração e a automação de infraestrutura para fluxos de trabalho DevOps.
</base-disclaimer-content>
</base-disclaimer>

## Instalação e Configuração

### Ubuntu/Debian: `apt install ansible`

Instale o Ansible em sistemas Linux baseados em Debian.

```bash
# Adicionar repositório Ansible
sudo apt-add-repository ppa:ansible/ansible
# Atualizar listas de pacotes
sudo apt-get update
# Instalar Ansible
sudo apt-get install ansible
# Verificar instalação
ansible --version
```

### CentOS/RHEL: `yum install ansible`

Instale o Ansible em sistemas baseados em Red Hat.

```bash
# Instalar repositório EPEL
sudo yum install epel-release -y
# Instalar Ansible
sudo yum install ansible -y
# Verificar instalação
ansible --version
```

### macOS: `brew install ansible`

Instale o Ansible no macOS usando Homebrew.

```bash
# Instalar usando Homebrew
brew install ansible
# Verificar instalação
ansible --version
```

### Configuração: `/etc/ansible/ansible.cfg`

Configure as configurações e padrões do Ansible.

```bash
# Visualizar configuração atual
ansible-config list
# Visualizar configuração efetiva
ansible-config view
# Arquivo de configuração personalizado
export ANSIBLE_CONFIG=/caminho/para/ansible.cfg
```

### Configuração SSH: Autenticação Baseada em Chave

O Ansible usa SSH para se comunicar entre os nós.

```bash
# Gerar chave SSH
ssh-keygen -t rsa -b 4096
# Copiar chave pública para hosts remotos
ssh-copy-id user@hostname
# Testar conexão SSH
ssh user@hostname
```

### Configuração do Ambiente

Configure variáveis de ambiente e caminhos do ambiente Ansible.

```bash
# Definir localização do arquivo de inventário
export ANSIBLE_INVENTORY=/caminho/para/inventario
# Definir verificação de chave de host
export ANSIBLE_HOST_KEY_CHECKING=False
# Definir usuário remoto
export ANSIBLE_REMOTE_USER=ubuntu
```

## Gerenciamento de Inventário

### Inventário Básico: `/etc/ansible/hosts`

Grupos de hosts podem ser criados dando um nome de grupo entre colchetes.

```ini
# Arquivo de hosts básico (formato INI)
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

### Formato de Inventário YAML

Arquivos de inventário podem estar nos formatos INI ou YAML.

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

### Variáveis de Host e Grupos

Defina variáveis específicas de host e configurações de grupo.

```ini
# Inventário com variáveis
[webservers]
web1.example.com http_port=80
web2.example.com http_port=8080
[webservers:vars]
ansible_user=nginx
nginx_version=1.18

# Testar inventário
ansible-inventory --list
ansible-inventory --graph
```

## Comandos Ad-Hoc

### Estrutura Básica do Comando

Estrutura básica de um comando Ansible: `ansible <hosts> -m <module> -a "<arguments>"`

```bash
# Testar conectividade
ansible all -m ping
# Verificar grupo específico
ansible webservers -m ping
# Executar comando em todos os hosts
ansible all -m command -a "uptime"
# Executar com privilégios sudo
ansible all -m command -a "systemctl status nginx" --become
```

<BaseQuiz id="ansible-command-1" correct="C">
  <template #question>
    O que `ansible all -m ping` faz?
  </template>
  
  <BaseQuizOption value="A">Testa a conectividade de rede usando ping ICMP</BaseQuizOption>
  <BaseQuizOption value="B">Instala o pacote ping em todos os hosts</BaseQuizOption>
  <BaseQuizOption value="C" correct>Testa a conectividade do Ansible com todos os hosts no inventário</BaseQuizOption>
  <BaseQuizOption value="D">Verifica se os hosts estão online</BaseQuizOption>
  
  <BaseQuizAnswer>
    O módulo `ping` no Ansible não usa ICMP. É um módulo de teste que verifica se o Ansible pode se conectar aos hosts, executar Python e retornar resultados. É usado para verificar conectividade e configuração.
  </BaseQuizAnswer>
</BaseQuiz>

### Operações de Arquivo

Crie diretórios, arquivos e links simbólicos nos hosts.

```bash
# Criar diretório
ansible all -m file -a "path=/tmp/test state=directory mode=0755"
# Criar arquivo
ansible all -m file -a "path=/tmp/test.txt state=touch"
# Excluir arquivo/diretório
ansible all -m file -a "path=/tmp/test state=absent"
# Criar link simbólico
ansible all -m file -a "src=/etc/nginx dest=/tmp/nginx state=link"
```

### Gerenciamento de Pacotes

Instale, atualize e remova pacotes em diferentes sistemas.

```bash
# Instalar pacote (apt)
ansible webservers -m apt -a "name=nginx state=present" --become
# Instalar pacote (yum)
ansible webservers -m yum -a "name=httpd state=present" --become
# Atualizar todos os pacotes
ansible all -m apt -a "upgrade=dist" --become
# Remover pacote
ansible all -m apt -a "name=apache2 state=absent" --become
```

### Gerenciamento de Serviços

Inicie, pare e gerencie serviços do sistema.

```bash
# Iniciar serviço
ansible webservers -m service -a "name=nginx state=started" --become
# Parar serviço
ansible webservers -m service -a "name=apache2 state=stopped" --become
# Reiniciar serviço
ansible webservers -m service -a "name=ssh state=restarted" --become
# Habilitar serviço na inicialização
ansible all -m service -a "name=nginx enabled=yes" --become
```

## Playbooks e Tarefas

### Estrutura Básica do Playbook

Arquivos YAML que definem quais tarefas devem ser executadas e em quais hosts.

```yaml
---
- name: Configuração do servidor web
  hosts: webservers
  become: yes
  vars:
    nginx_port: 80

  tasks:
    - name: Instalar nginx
      apt:
        name: nginx
        state: present

    - name: Iniciar serviço nginx
      service:
        name: nginx
        state: started
        enabled: yes
```

### Executando Playbooks

Execute playbooks com várias opções e configurações.

```bash
# Executar playbook
ansible-playbook site.yml
# Executar com inventário específico
ansible-playbook -i inventory.yml site.yml
# Simulação (modo de verificação)
ansible-playbook site.yml --check
# Executar em hosts específicos
ansible-playbook site.yml --limit webservers
# Executar com variáveis extras
ansible-playbook site.yml --extra-vars "nginx_port=8080"
```

<BaseQuiz id="ansible-playbook-1" correct="B">
  <template #question>
    O que `ansible-playbook site.yml --check` faz?
  </template>
  
  <BaseQuizOption value="A">Executa o playbook duas vezes</BaseQuizOption>
  <BaseQuizOption value="B" correct>Executa o playbook em modo de verificação (simulação) sem fazer alterações</BaseQuizOption>
  <BaseQuizOption value="C">Verifica a sintaxe do playbook</BaseQuizOption>
  <BaseQuizOption value="D">Executa apenas a primeira tarefa</BaseQuizOption>
  
  <BaseQuizAnswer>
    O flag `--check` executa o Ansible em modo de verificação (simulação), que simula o que aconteceria sem realmente fazer alterações. Isso é útil para testar playbooks antes de aplicá-los.
  </BaseQuizAnswer>
</BaseQuiz>

### Opções de Tarefa e Condicionais

Adicione condições, loops e tratamento de erros às tarefas.

```yaml
tasks:
  - name: Instalar pacotes
    apt:
      name: '{{ item }}'
      state: present
    loop:
      - nginx
      - mysql-server
      - php
    when: ansible_os_family == "Debian"

  - name: Criar usuário
    user:
      name: webuser
      state: present
    register: user_result

  - name: Mostrar resultado da criação do usuário
    debug:
      msg: 'Usuário criado: {{ user_result.changed }}'
```

### Handlers e Notificações

Defina handlers que são executados quando notificados por tarefas.

```yaml
tasks:
  - name: Atualizar configuração nginx
    template:
      src: nginx.conf.j2
      dest: /etc/nginx/nginx.conf
    notify: reiniciar nginx

handlers:
  - name: reiniciar nginx
    service:
      name: nginx
      state: restarted
```

<BaseQuiz id="ansible-handlers-1" correct="C">
  <template #question>
    Quando os handlers do Ansible são executados?
  </template>
  
  <BaseQuizOption value="A">Imediatamente após serem definidos</BaseQuizOption>
  <BaseQuizOption value="B">No início do playbook</BaseQuizOption>
  <BaseQuizOption value="C" correct>No final do playbook, apenas se notificados por uma tarefa</BaseQuizOption>
  <BaseQuizOption value="D">Toda vez que uma tarefa é executada</BaseQuizOption>
  
  <BaseQuizAnswer>
    Handlers são executados no final do playbook, e somente se forem notificados por uma tarefa que alterou algo. Isso garante que os serviços sejam reiniciados apenas quando os arquivos de configuração são realmente modificados.
  </BaseQuizAnswer>
</BaseQuiz>

## Variáveis e Templates

### Definição de Variáveis

Defina variáveis em diferentes níveis e escopos.

```yaml
# No playbook
vars:
  app_name: myapp
  app_port: 8080

# Em group_vars/all.yml
database_host: db.example.com
database_port: 5432

# Em host_vars/web1.yml
server_role: frontend
max_connections: 100

# Variáveis de linha de comando
ansible-playbook site.yml -e "env=production"
```

### Templates Jinja2

Crie arquivos de configuração dinâmicos usando templates.

```jinja2
# Arquivo de template: nginx.conf.j2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};

    location / {
        proxy_pass http://{{ backend_host }}:{{ backend_port }};
    }
}
```

```yaml
# Usando o módulo template
- name: Implantar configuração nginx
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/sites-available/default
  notify: recarregar nginx
```

### Fatos e Informações do Sistema

Colete e use fatos do sistema em playbooks.

```bash
# Coletar fatos manualmente
ansible all -m setup
# Coletar fatos específicos
ansible all -m setup -a "filter=ansible_eth*"
```

```yaml
# Usar fatos em playbooks
- name: Mostrar informações do sistema
  debug:
    msg: '{{ ansible_hostname }} executa {{ ansible_distribution }}'

- name: Instalar pacote baseado no SO
  apt:
    name: apache2
  when: ansible_os_family == "Debian"
```

### Cofre (Vault) e Gerenciamento de Segredos

Criptografe dados sensíveis usando o Ansible Vault.

```bash
# Criar arquivo criptografado
ansible-vault create secrets.yml
# Editar arquivo criptografado
ansible-vault edit secrets.yml
# Criptografar arquivo existente
ansible-vault encrypt passwords.yml
# Executar playbook com cofre
ansible-playbook site.yml --ask-vault-pass
# Usar arquivo de senha do cofre
ansible-playbook site.yml --vault-password-file .vault_pass
```

## Funções (Roles) e Organização

### Estrutura de Função

Organize playbooks em funções reutilizáveis.

```bash
# Criar estrutura de função
ansible-galaxy init webserver
```

```
# Estrutura de diretório da função
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

### Usando Funções em Playbooks

Aplique funções aos hosts em seus playbooks.

```yaml
---
- hosts: webservers
  roles:
    - common
    - webserver
    - { role: database, database_type: mysql }

# Ou com include_role
- hosts: webservers
  tasks:
    - include_role:
        name: webserver
      vars:
        nginx_port: 8080
```

### Ansible Galaxy

Baixe e gerencie funções da comunidade do Ansible Galaxy.

```bash
# Instalar função do Galaxy
ansible-galaxy install geerlingguy.nginx
# Instalar versão específica
ansible-galaxy install geerlingguy.nginx,2.8.0
# Instalar de arquivo de requisitos
ansible-galaxy install -r requirements.yml
# Listar funções instaladas
ansible-galaxy list
# Remover função
ansible-galaxy remove geerlingguy.nginx
```

### Coleções (Collections)

Trabalhe com Coleções Ansible para funcionalidade estendida.

```bash
# Instalar coleção
ansible-galaxy collection install community.general
```

```yaml
# Usar coleção no playbook
collections:
  - community.general
tasks:
  - name: Instalar pacote
    community.general.snap:
      name: code
      state: present
```

## Depuração e Solução de Problemas

### Depurando Tarefas

Depure e solucione problemas na execução do playbook.

```yaml
# Adicionar tarefas de depuração
- name: Mostrar valor da variável
  debug:
    var: my_variable
- name: Mostrar mensagem personalizada
  debug:
    msg: 'O host {{ inventory_hostname }} executa IP {{ ansible_default_ipv4.address }}'
```

```bash
# Execução detalhada (verbose)
ansible-playbook site.yml -v
ansible-playbook site.yml -vvv  # Verbosidade máxima
```

### Tratamento de Erros

Lide com erros e falhas de forma graciosa.

```yaml
- name: Tarefa que pode falhar
  command: /bin/false
  ignore_errors: yes

- name: Tarefa com resgate (rescue)
  block:
    - command: /bin/false
  rescue:
    - debug:
        msg: 'A tarefa falhou, executando resgate'
  always:
    - debug:
        msg: 'Isso sempre será executado'
```

### Teste e Validação

Teste playbooks e valide configurações.

```bash
# Verificar sintaxe
ansible-playbook site.yml --syntax-check
# Listar tarefas
ansible-playbook site.yml --list-tasks
# Listar hosts
ansible-playbook site.yml --list-hosts
# Executar passo a passo
ansible-playbook site.yml --step
# Testar com modo de verificação
ansible-playbook site.yml --check --diff
```

### Desempenho e Otimização

Otimize o desempenho e a execução do playbook.

```yaml
# Executar tarefas em paralelo
- name: Instalar pacotes
  apt:
    name: '{{ packages }}'
  vars:
    packages:
      - nginx
      - mysql-server

# Usar async para tarefas de longa duração
- name: Tarefa de longa duração
  command: /usr/bin/long-task
  async: 300
  poll: 5
```

## Melhores Práticas e Dicas

### Melhores Práticas de Segurança

Proteja sua infraestrutura e operações Ansible.

```bash
# Usar Ansible Vault para segredos
ansible-vault create group_vars/all/vault.yml
# Desabilitar verificação de chave de host com cautela
host_key_checking = False
# Usar become apenas quando necessário
become: yes
become_user: root
# Limitar o escopo do playbook
ansible-playbook site.yml --limit production
```

### Organização do Código

Estruture seus projetos Ansible de forma eficaz.

```bash
# Estrutura de diretório recomendada
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
# Usar nomes significativos e documentação
- name: Nome descritivo da tarefa
  # Adicionar comentários para lógica complexa
```

### Controle de Versão e Testes

Gerencie o código Ansible com controle de versão adequado.

```bash
# Usar Git para controle de versão
git init
git add .
git commit -m "Configuração inicial do Ansible"
# Testar em staging antes da produção
ansible-playbook -i staging site.yml
# Usar tags para execução seletiva
ansible-playbook site.yml --tags "nginx,ssl"
```

## Configuração e Recursos Avançados

### Configuração do Ansible

Personalize o comportamento do Ansible com opções de configuração.

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

### Plugins de Callback

Aprimore a saída e o registro com plugins de callback.

```ini
# Habilitar plugins de callback em ansible.cfg
[defaults]
stdout_callback = yaml
callbacks_enabled = profile_tasks, timer

# Configuração de callback personalizada
[callback_profile_tasks]
task_output_limit = 20
```

### Filtros e Lookups

Use filtros Jinja2 e plugins de lookup para manipulação de dados.

```jinja2
# Filtros comuns em templates
{{ variable | default('default_value') }}
{{ list_var | length }}
{{ string_var | upper }}
{{ dict_var | to_nice_yaml }}
```

```yaml
# Plugins de lookup
- name: Ler conteúdo do arquivo
  debug:
    msg: "{{ lookup('file', '/etc/hostname') }}"

- name: Variável de ambiente
  debug:
    msg: "{{ lookup('env', 'HOME') }}"
```

### Inventários Dinâmicos

Use inventários dinâmicos para ambientes de nuvem e contêineres.

```bash
# Inventário dinâmico AWS EC2
ansible-playbook -i ec2.py site.yml
# Inventário dinâmico Docker
ansible-playbook -i docker.yml site.yml
# Script de inventário personalizado
ansible-playbook -i ./dynamic_inventory.py site.yml
```

## Links Relevantes

- <router-link to="/linux">Folha de Dicas Linux</router-link>
- <router-link to="/shell">Folha de Dicas Shell</router-link>
- <router-link to="/devops">Folha de Dicas DevOps</router-link>
- <router-link to="/docker">Folha de Dicas Docker</router-link>
- <router-link to="/kubernetes">Folha de Dicas Kubernetes</router-link>
- <router-link to="/python">Folha de Dicas Python</router-link>

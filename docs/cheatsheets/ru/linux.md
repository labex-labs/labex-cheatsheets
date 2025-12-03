---
title: 'Шпаргалка по Linux | LabEx'
description: 'Изучите администрирование Linux с помощью этой комплексной шпаргалки. Быстрый справочник по командам Linux, управлению файлами, системному администрированию, сетям и написанию сценариев оболочки.'
pdfUrl: '/cheatsheets/pdf/linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a href="https://linux-commands.labex.io/" target="_blank">Посетите Linux Commands</a>
</base-disclaimer-title>
<base-disclaimer-content>
Для получения исчерпывающих справочных материалов по командам Linux, примеров синтаксиса и подробной документации, пожалуйста, посетите <a href="https://linux-commands.labex.io/" target="_blank">linux-commands.labex.io</a>. Этот независимый сайт предоставляет обширные шпаргалки по Linux, охватывающие основные команды, концепции и лучшие практики для администраторов и разработчиков Linux.
</base-disclaimer-content>
</base-disclaimer>

## Информация о системе и статус

### Информация о системе: `uname`

Отображение информации о системе, включая ядро и архитектуру.

```bash
# Показать имя ядра
uname
# Показать всю системную информацию
uname -a
# Показать версию ядра
uname -r
# Показать архитектуру
uname -m
# Показать операционную систему
uname -o
```

### Информация об оборудовании: `lscpu`, `lsblk`

Просмотр подробных спецификаций оборудования и блочных устройств.

```bash
# Информация о ЦП
lscpu
# Блочные устройства (диски, разделы)
lsblk
# Информация о памяти
free -h
# Использование диска по файловой системе
df -h
```

### Время работы системы: `uptime`

Показать время работы системы и среднюю загрузку.

```bash
# Время работы системы и загрузка
uptime
# Более подробная информация о времени работы
uptime -p
# Показать время работы с указанной даты
uptime -s
```

### Текущие пользователи: `who`, `w`

Отображение вошедших в систему пользователей и их активности.

```bash
# Показать вошедших пользователей
who
# Подробная информация о пользователях с активностью
w
# Показать текущее имя пользователя
whoami
# Показать историю входов
last
```

### Переменные окружения: `env`

Отображение и управление переменными окружения.

```bash
# Показать все переменные окружения
env
# Показать конкретную переменную
echo $HOME
# Установить переменную окружения
export PATH=$PATH:/new/path
# Показать переменную PATH
echo $PATH
```

### Дата и время: `date`, `timedatectl`

Отображение и установка системной даты и времени.

```bash
# Текущая дата и время
date
# Установить системное время (от root)
date MMddhhmmyyyy
# Информация о часовом поясе
timedatectl
# Установить часовой пояс
timedatectl set-timezone America/New_York
```

## Операции с файлами и каталогами

### Листинг файлов: `ls`

Отображение файлов и каталогов с различными опциями форматирования.

```bash
# Листинг файлов в текущем каталоге
ls
# Подробный листинг с правами доступа
ls -l
# Показать скрытые файлы
ls -la
# Файловые размеры в человекочитаемом формате
ls -lh
# Сортировка по времени изменения
ls -lt
```

### Навигация по каталогам: `cd`, `pwd`

Смена каталогов и отображение текущего местоположения.

```bash
# Перейти в домашний каталог
cd
# Перейти в указанный каталог
cd /path/to/directory
# Перейти на один уровень вверх
cd ..
# Показать текущий каталог
pwd
# Перейти в предыдущий каталог
cd -
```

<BaseQuiz id="linux-cd-pwd-1" correct="B">
  <template #question>
    Какая команда показывает текущий рабочий каталог?
  </template>
  
  <BaseQuizOption value="A">cd</BaseQuizOption>
  <BaseQuizOption value="B" correct>pwd</BaseQuizOption>
  <BaseQuizOption value="C">ls</BaseQuizOption>
  <BaseQuizOption value="D">whoami</BaseQuizOption>
  
  <BaseQuizAnswer>
    Команда <code>pwd</code> (print working directory) отображает полный путь к каталогу, в котором вы находитесь.
  </BaseQuizAnswer>
</BaseQuiz>

### Создание и удаление: `mkdir`, `rmdir`, `rm`

Создание и удаление файлов и каталогов.

```bash
# Создать каталог
mkdir newdir
# Создать вложенные каталоги
mkdir -p path/to/nested/dir
# Удалить пустой каталог
rmdir dirname
# Удалить файл
rm filename
# Рекурсивно удалить каталог
rm -rf dirname
```

### Просмотр содержимого файла: `cat`, `less`, `head`, `tail`

Отображение содержимого файла различными методами и постраничным просмотром.

```bash
# Отобразить весь файл
cat filename
# Просмотр файла с постраничным выводом
less filename
# Показать первые 10 строк
head filename
# Показать последние 10 строк
tail filename
# Следить за изменениями в файле в реальном времени
tail -f logfile
```

### Копирование и перемещение: `cp`, `mv`

Копирование и перемещение файлов и каталогов.

```bash
# Скопировать файл
cp source.txt destination.txt
# Рекурсивно скопировать каталог
cp -r sourcedir/ destdir/
# Переместить/переименовать файл
mv oldname.txt newname.txt
# Переместить в другой каталог
mv file.txt /path/to/destination/
# Копировать с сохранением атрибутов
cp -p file.txt backup.txt
```

### Поиск файлов: `find`, `locate`

Поиск файлов и каталогов по имени, типу или свойствам.

```bash
# Поиск по имени
find /path -name "filename"
# Найти файлы, измененные за последние 7 дней
find /path -mtime -7
# Поиск по типу файла
find /path -type f -name "*.txt"
# Быстрый поиск файлов (требует обновления базы)
locate filename
# Найти и выполнить команду
find /path -name "*.log" -exec rm {} \;
```

### Права доступа к файлам: `chmod`, `chown`

Изменение прав доступа и владельца файлов.

```bash
# Изменить права доступа (числовой)
chmod 755 filename
# Добавить право на выполнение
chmod +x script.sh
# Изменить владельца
chown user:group filename
# Изменить владельца рекурсивно
chown -R user:group directory/
# Посмотреть права доступа к файлу
ls -l filename
```

<BaseQuiz id="linux-chmod-1" correct="C">
  <template #question>
    Что устанавливает <code>chmod 755 filename</code> для прав доступа?
  </template>
  
  <BaseQuizOption value="A">Чтение, запись, выполнение для владельца; чтение для группы и остальных</BaseQuizOption>
  <BaseQuizOption value="B">Чтение, запись для владельца; чтение, выполнение для группы и остальных</BaseQuizOption>
  <BaseQuizOption value="C" correct>Чтение, запись, выполнение для владельца; чтение, выполнение для группы и остальных</BaseQuizOption>
  <BaseQuizOption value="D">Чтение, запись для владельца; чтение для группы и остальных</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 755</code> устанавливает: владелец = 7 (rwx), группа = 5 (r-x), остальные = 5 (r-x). Это распространенный набор прав для исполняемых файлов и каталогов.
  </BaseQuizAnswer>
</BaseQuiz>

## Управление процессами

### Листинг процессов: `ps`

Отображение запущенных процессов и их деталей.

```bash
# Показать процессы пользователя
ps
# Показать все процессы с деталями
ps aux
# Показать дерево процессов
ps -ef --forest
# Показать процессы по пользователю
ps -u username
```

### Завершение процессов: `kill`, `killall`

Завершение процессов по PID или имени.

```bash
# Монитор процессов в реальном времени
top
# Завершить процесс по PID
kill 1234
# Принудительное завершение процесса
kill -9 1234
# Завершить по имени процесса
killall processname
# Показать все сигналы
kill -l
# Отправить определенный сигнал
kill -HUP 1234
```

<BaseQuiz id="linux-kill-1" correct="D">
  <template #question>
    Какой сигнал отправляет команда <code>kill -9</code> процессу?
  </template>
  
  <BaseQuizOption value="A">SIGTERM (мягкое завершение)</BaseQuizOption>
  <BaseQuizOption value="B">SIGHUP (повесить трубку)</BaseQuizOption>
  <BaseQuizOption value="C">SIGINT (прерывание)</BaseQuizOption>
  <BaseQuizOption value="D" correct>SIGKILL (принудительное завершение, нельзя игнорировать)</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>kill -9</code> отправляет SIGKILL, который принудительно немедленно завершает процесс. Этот сигнал не может быть перехвачен или проигнорирован процессом, что полезно для завершения зависших процессов.
  </BaseQuizAnswer>
</BaseQuiz>

### Фоновые задачи: `jobs`, `bg`, `fg`

Управление фоновыми и активными процессами.

```bash
# Листинг активных задач
jobs
# Отправить задачу в фон
bg %1
# Вывести задачу на передний план
fg %1
# Запустить команду в фоне
command &
# Отключиться от терминала
nohup command &
```

### Монитор системы: `htop`, `systemctl`

Мониторинг системных ресурсов и управление службами.

```bash
# Улучшенный просмотрщик процессов (если установлен)
htop
# Проверить статус службы
systemctl status servicename
# Запустить службу
systemctl start servicename
# Включить службу при загрузке
systemctl enable servicename
# Просмотр системных журналов
journalctl -f
```

## Сетевые операции

### Сетевая конфигурация: `ip`, `ifconfig`

Отображение и настройка сетевых интерфейсов.

```bash
# Показать сетевые интерфейсы
ip addr show
# Показать таблицу маршрутизации
ip route show
# Настроить интерфейс (временно)
ip addr add 192.168.1.10/24 dev eth0
# Активировать/деактивировать интерфейс
ip link set eth0 up
# Устаревшая конфигурация интерфейса
ifconfig
```

### Тестирование сети: `ping`, `traceroute`

Проверка сетевого подключения и трассировка маршрутов пакетов.

```bash
# Проверить подключение
ping google.com
# Ping с ограничением по количеству
ping -c 4 192.168.1.1
# Трассировка маршрута до цели
traceroute google.com
# MTR - инструмент диагностики сети
mtr google.com
```

<BaseQuiz id="linux-ping-1" correct="B">
  <template #question>
    Что делает команда <code>ping -c 4</code>?
  </template>
  
  <BaseQuizOption value="A">Пинговать с таймаутом 4 секунды</BaseQuizOption>
  <BaseQuizOption value="B" correct>Отправить 4 пакета ping и остановиться</BaseQuizOption>
  <BaseQuizOption value="C">Пинговать 4 разных хоста</BaseQuizOption>
  <BaseQuizOption value="D">Ждать 4 секунды между пингами</BaseQuizOption>
  
  <BaseQuizAnswer>
    Опция <code>-c</code> указывает количество отправляемых пакетов. <code>ping -c 4</code> отправит ровно 4 пакета ICMP echo request и затем остановится, отобразив результаты.
  </BaseQuizAnswer>
</BaseQuiz>

### Анализ портов и соединений: `netstat`, `ss`

Отображение сетевых соединений и прослушиваемых портов.

```bash
# Показать все соединения
netstat -tuln
# Показать прослушиваемые порты
netstat -tuln | grep LISTEN
# Современная замена netstat
ss -tuln
# Показать процессы, использующие порты
netstat -tulnp
# Проверить конкретный порт
netstat -tuln | grep :80
```

### Передача файлов: `scp`, `rsync`

Безопасная передача файлов между системами.

```bash
# Скопировать файл на удаленный хост
scp file.txt user@host:/path/
# Скопировать с удаленного хоста
scp user@host:/path/file.txt ./
# Синхронизировать каталоги
rsync -avz localdir/ user@host:/remotedir/
# Rsync с прогрессом
rsync -avz --progress src/ dest/
```

## Обработка текста и поиск

### Поиск текста: `grep`

Поиск шаблонов в файлах и выводе команд.

```bash
# Поиск шаблона в файле
grep "pattern" filename
# Поиск без учета регистра
grep -i "pattern" filename
# Рекурсивный поиск в каталогах
grep -r "pattern" /path/
# Показать номера строк
grep -n "pattern" filename
# Посчитать совпадающие строки
grep -c "pattern" filename
```

<BaseQuiz id="linux-grep-1" correct="A">
  <template #question>
    Какая опция <code>grep</code> выполняет поиск без учета регистра?
  </template>
  
  <BaseQuizOption value="A" correct>-i</BaseQuizOption>
  <BaseQuizOption value="B">-c</BaseQuizOption>
  <BaseQuizOption value="C">-n</BaseQuizOption>
  <BaseQuizOption value="D">-r</BaseQuizOption>
  
  <BaseQuizAnswer>
    Опция <code>-i</code> делает grep нечувствительным к регистру, поэтому она будет соответствовать как заглавным, так и строчным буквам. Например, <code>grep -i "error" file.txt</code> найдет "Error", "ERROR" и "error".
  </BaseQuizAnswer>
</BaseQuiz>

### Манипуляция текстом: `sed`, `awk`

Редактирование и обработка текста с помощью потоковых редакторов и сканеров шаблонов.

```bash
# Заменить текст в файле
sed 's/old/new/g' filename
# Удалить строки, содержащие шаблон
sed '/pattern/d' filename
# Вывести указанные поля
awk '{print $1, $3}' filename
# Суммировать значения в столбце
awk '{sum += $1} END {print sum}' filename
```

### Сортировка и подсчет: `sort`, `uniq`, `wc`

Сортировка данных, удаление дубликатов и подсчет строк, слов или символов.

```bash
# Сортировать содержимое файла
sort filename
# Числовая сортировка
sort -n numbers.txt
# Удалить повторяющиеся строки
uniq filename
# Сортировать и удалить дубликаты
sort filename | uniq
# Подсчет строк, слов, символов
wc filename
# Подсчет только строк
wc -l filename
```

### Вырезание и вставка: `cut`, `paste`

Извлечение определенных столбцов и объединение файлов.

```bash
# Извлечь первый столбец
cut -d',' -f1 file.csv
# Извлечь диапазон символов
cut -c1-10 filename
# Объединить файлы бок о бок
paste file1.txt file2.txt
# Использовать пользовательский разделитель
cut -d':' -f1,3 /etc/passwd
```

## Архивы и сжатие

### Создание архивов: `tar`

Создание и извлечение сжатых архивов.

```bash
# Создать архив tar
tar -cf archive.tar files/
# Создать сжатый архив
tar -czf archive.tar.gz files/
# Извлечь архив
tar -xf archive.tar
# Извлечь сжатый архив
tar -xzf archive.tar.gz
# Листинг содержимого архива
tar -tf archive.tar
```

### Сжатие: `gzip`, `zip`

Сжатие и распаковка файлов с использованием различных алгоритмов.

```bash
# Сжать файл с помощью gzip
gzip filename
# Распаковать файл gzip
gunzip filename.gz
# Создать zip архив
zip archive.zip file1 file2
# Извлечь zip архив
unzip archive.zip
# Листинг содержимого zip
unzip -l archive.zip
```

### Расширенные архивы: `tar` Опции

Расширенные операции tar для резервного копирования и восстановления.

```bash
# Создать архив со сжатием
tar -czvf backup.tar.gz /home/user/
# Извлечь в указанный каталог
tar -xzf archive.tar.gz -C /destination/
# Добавить файлы в существующий архив
tar -rf archive.tar newfile.txt
# Обновить архив более новыми файлами
tar -uf archive.tar files/
```

### Место на диске: `du`

Анализ использования дискового пространства и размеров каталогов.

```bash
# Показать размеры каталогов
du -h /path/
# Сводка общего размера
du -sh /path/
# Показать размеры всех подкаталогов
du -h --max-depth=1 /path/
# Сначала самые большие каталоги
du -h | sort -hr | head -10
```

## Мониторинг системы и производительность

### Использование памяти: `free`, `vmstat`

Мониторинг использования памяти и статистики виртуальной памяти.

```bash
# Сводка использования памяти
free -h
# Подробная статистика памяти
cat /proc/meminfo
# Статистика виртуальной памяти
vmstat
# Использование памяти каждые 2 секунды
vmstat 2
# Показать использование swap
swapon --show
```

### Дисковый ввод/вывод: `iostat`, `iotop`

Мониторинг производительности дискового ввода/вывода и выявление узких мест.

```bash
# Статистика ввода/вывода (требуется sysstat)
iostat
# Статистика ввода/вывода каждые 2 секунды
iostat 2
# Мониторинг ввода/вывода диска по процессам
iotop
# Показать использование ввода/вывода для конкретного устройства
iostat -x /dev/sda
```

### Нагрузка системы: `top`, `htop`

Мониторинг системной нагрузки, использования ЦП и запущенных процессов.

```bash
# Монитор процессов в реальном времени
top
# Улучшенный просмотрщик процессов
htop
# Показать среднюю загрузку
uptime
# Показать информацию о ЦП
lscpu
# Мониторинг конкретного процесса
top -p PID
```

### Файлы журналов: `journalctl`, `dmesg`

Просмотр и анализ системных журналов для устранения неполадок.

```bash
# Просмотр системных журналов
journalctl
# Следить за журналами в реальном времени
journalctl -f
# Показать журналы для конкретной службы
journalctl -u servicename
# Сообщения ядра
dmesg
# Сообщения последнего запуска
dmesg | tail
```

## Управление пользователями и правами доступа

### Операции с пользователями: `useradd`, `usermod`, `userdel`

Создание, изменение и удаление учетных записей пользователей.

```bash
# Добавить нового пользователя
useradd username
# Добавить пользователя с домашним каталогом
useradd -m username
# Изменить учетную запись пользователя
usermod -aG groupname username
# Удалить учетную запись пользователя
userdel username
# Удалить учетную запись с домашним каталогом
userdel -r username
```

### Управление группами: `groupadd`, `groups`

Создание и управление группами пользователей.

```bash
# Создать новую группу
groupadd groupname
# Показать группы пользователя
groups username
# Показать все группы
cat /etc/group
# Добавить пользователя в группу
usermod -aG groupname username
# Изменить основную группу пользователя
usermod -g groupname username
```

### Смена пользователей: `su`, `sudo`

Смена пользователей и выполнение команд с повышенными привилегиями.

```bash
# Сменить на пользователя root
su -
# Сменить на указанного пользователя
su - username
# Выполнить команду как root
sudo command
# Выполнить команду от имени указанного пользователя
sudo -u username command
# Редактировать файл sudoers
visudo
```

### Управление паролями: `passwd`, `chage`

Управление паролями пользователей и политиками учетных записей.

```bash
# Сменить пароль
passwd
# Сменить пароль другого пользователя (от root)
passwd username
# Показать информацию о сроке действия пароля
chage -l username
# Установить срок действия пароля
chage -M 90 username
# Принудительно сменить пароль при следующем входе
passwd -e username
```

## Управление пакетами

### APT (Debian/Ubuntu): `apt`, `apt-get`

Управление пакетами в системах на базе Debian.

```bash
# Обновить список пакетов
apt update
# Обновить все пакеты
apt upgrade
# Установить пакет
apt install packagename
# Удалить пакет
apt remove packagename
# Поиск пакетов
apt search packagename
# Показать информацию о пакете
apt show packagename
```

### YUM/DNF (RHEL/Fedora): `yum`, `dnf`

Управление пакетами в системах на базе Red Hat.

```bash
# Установить пакет
yum install packagename
# Обновить все пакеты
yum update
# Удалить пакет
yum remove packagename
# Поиск пакетов
yum search packagename
# Листинг установленных пакетов
yum list installed
```

### Пакеты Snap: `snap`

Установка и управление пакетами snap в различных дистрибутивах.

```bash
# Установить пакет snap
snap install packagename
# Листинг установленных snap
snap list
# Обновить пакеты snap
snap refresh
# Удалить пакет snap
snap remove packagename
# Поиск пакетов snap
snap find packagename
```

### Пакеты Flatpak: `flatpak`

Управление приложениями Flatpak для программного обеспечения в песочнице.

```bash
# Установить flatpak
flatpak install packagename
# Листинг установленных flatpak
flatpak list
# Обновить пакеты flatpak
flatpak update
# Удалить flatpak
flatpak uninstall packagename
# Поиск пакетов flatpak
flatpak search packagename
```

## Оболочка и скриптинг

### История команд: `history`

Доступ и управление историей командной строки.

```bash
# Показать историю команд
history
# Показать последние 10 команд
history 10
# Выполнить предыдущую команду
!!
# Выполнить команду по номеру
!123
# Интерактивный поиск по истории
Ctrl+R
```

### Псевдонимы и функции: `alias`

Создание ярлыков для часто используемых команд.

```bash
# Создать псевдоним
alias ll='ls -la'
# Показать все псевдонимы
alias
# Удалить псевдоним
unalias ll
# Сделать псевдоним постоянным (добавить в .bashrc)
echo "alias ll='ls -la'" >> ~/.bashrc
```

### Перенаправление ввода/вывода

Перенаправление ввода и вывода команд в файлы или другие команды.

```bash
# Перенаправить вывод в файл
command > output.txt
# Добавить вывод в файл
command >> output.txt
# Перенаправить ввод из файла
command < input.txt
# Перенаправить stdout и stderr
command &> output.txt
# Передать вывод одной команды другой
command1 | command2
```

### Настройка окружения: `.bashrc`, `.profile`

Настройка окружения оболочки и скриптов запуска.

```bash
# Редактировать конфигурацию bash
nano ~/.bashrc
# Перезагрузить конфигурацию
source ~/.bashrc
# Установить переменную окружения
export VARIABLE=value
# Добавить в PATH
export PATH=$PATH:/new/path
# Показать переменные окружения
printenv
```

## Установка и настройка системы

### Варианты дистрибутивов: Ubuntu, CentOS, Debian

Выбор и установка дистрибутивов Linux для различных сценариев использования.

```bash
# Ubuntu Server
wget ubuntu-server.iso
# CentOS Stream
wget centos-stream.iso
# Debian Stable
wget debian.iso
# Проверить целостность ISO
sha256sum linux.iso
```

### Загрузка и установка: USB, Сеть

Создание загрузочных носителей и выполнение установки системы.

```bash
# Создать загрузочную USB (Linux)
dd if=linux.iso of=/dev/sdX bs=4M
# Создать загрузочную USB (кроссплатформенная)
# Используйте такие инструменты, как Rufus, Etcher или UNetbootin
# Сетевая установка
# Настройка PXE загрузки для сетевых установок
```

### Начальная настройка: Пользователи, Сеть, SSH

Настройка базовой конфигурации системы после установки.

```bash
# Установить имя хоста
hostnamectl set-hostname newname
# Настроить статический IP
# Редактировать /etc/netplan/ (Ubuntu) или /etc/network/interfaces
# Включить службу SSH
systemctl enable ssh
systemctl start ssh
# Настроить брандмауэр
ufw enable
ufw allow ssh
```

## Безопасность и лучшие практики

### Настройка брандмауэра: `ufw`, `iptables`

Настройка правил брандмауэра для защиты системы от сетевых угроз.

```bash
# Включить брандмауэр UFW
ufw enable
# Разрешить конкретный порт
ufw allow 22/tcp
# Разрешить службу по имени
ufw allow ssh
# Запретить доступ
ufw deny 23
# Показать статус брандмауэра
ufw status verbose
# Расширенные правила с iptables
iptables -L
```

### Целостность файлов: `checksums`

Проверка целостности файлов и обнаружение несанкционированных изменений.

```bash
# Сгенерировать контрольную сумму MD5
md5sum filename
# Сгенерировать контрольную сумму SHA256
sha256sum filename
# Проверить контрольную сумму
sha256sum -c checksums.txt
# Создать файл контрольных сумм
sha256sum *.txt > checksums.txt
```

### Обновления системы: Патчи безопасности

Поддержание безопасности системы с помощью регулярных обновлений и исправлений безопасности.

```bash
# Обновления безопасности Ubuntu
apt update && apt upgrade
# Автоматические обновления безопасности
unattended-upgrades
# Обновления CentOS/RHEL
yum update --security
# Показать доступные обновления
apt list --upgradable
```

### Мониторинг журналов: События безопасности

Мониторинг системных журналов на предмет событий безопасности и аномалий.

```bash
# Мониторинг журналов аутентификации
tail -f /var/log/auth.log
# Проверить неудачные попытки входа
grep "Failed password" /var/log/auth.log
# Мониторинг системных журналов
tail -f /var/log/syslog
# Проверить историю входов
last
# Проверить на подозрительную активность
journalctl -p err
```

## Устранение неполадок и восстановление

### Проблемы с загрузкой: Восстановление GRUB

Восстановление после проблем с загрузчиком и ядром.

```bash
# Загрузка в режиме восстановления
# Доступ к меню GRUB во время загрузки
# Смонтировать корневую файловую систему
mount /dev/sda1 /mnt
# Chroot в систему
chroot /mnt
# Переустановить GRUB
grub-install /dev/sda
# Обновить конфигурацию GRUB
update-grub
```

### Ремонт файловой системы: `fsck`

Проверка и исправление повреждений файловой системы.

```bash
# Проверить файловую систему
fsck /dev/sda1
# Принудительная проверка файловой системы
fsck -f /dev/sda1
# Автоматическое исправление
fsck -y /dev/sda1
# Проверить все смонтированные файловые системы
fsck -A
```

### Проблемы со службами: `systemctl`

Диагностика и исправление проблем, связанных со службами.

```bash
# Проверить статус службы
systemctl status servicename
# Посмотреть журналы службы
journalctl -u servicename
# Перезапустить сбойную службу
systemctl restart servicename
# Включить службу при загрузке
systemctl enable servicename
# Показать сбойные службы
systemctl --failed
```

### Проблемы с производительностью: Анализ ресурсов

Выявление и устранение узких мест производительности системы.

```bash
# Проверить свободное место на диске
df -h
# Мониторинг использования ввода/вывода
iotop
# Проверить использование памяти
free -h
# Выявить использование ЦП
top
# Листинг открытых файлов
lsof
```

## Соответствующие ссылки

- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/rhel">Шпаргалка по Red Hat Enterprise Linux</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>
- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>
- <router-link to="/git">Шпаргалка по Git</router-link>
- <router-link to="/ansible">Шпаргалка по Ansible</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/cybersecurity">Шпаргалка по кибербезопасности</router-link>

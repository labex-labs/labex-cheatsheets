---
title: 'Шпаргалка по Shell | LabEx'
description: 'Изучите shell-скриптинг с помощью этой исчерпывающей шпаргалки. Быстрый справочник по командам bash, shell-скриптам, автоматизации, инструментам командной строки и администрированию систем Linux/Unix.'
pdfUrl: '/cheatsheets/pdf/shell-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Shell
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/shell">Изучите Shell с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите написание сценариев Shell и операции командной строки с помощью практических лабораторий и сценариев реального мира. LabEx предлагает комплексные курсы по Shell, охватывающие основные команды Bash, файловые операции, обработку текста, управление процессами и автоматизацию. Освойте эффективность командной строки и методы написания сценариев Shell.
</base-disclaimer-content>
</base-disclaimer>

## Операции с Файлами и Каталогами

### Просмотр Файлов: `ls`

Отображает файлы и каталоги в текущем местоположении.

```bash
# Показать файлы в текущем каталоге
ls
# Показать с подробной информацией
ls -l
# Показать скрытые файлы
ls -a
# Показать с удобочитаемыми размерами файлов
ls -lh
# Сортировать по времени изменения
ls -lt
```

### Создание Файлов: `touch`

Создает пустые файлы или обновляет временные метки.

```bash
# Создать новый файл
touch newfile.txt
# Создать несколько файлов
touch file1.txt file2.txt file3.txt
# Обновить временную метку существующего файла
touch existing_file.txt
```

### Создание Каталогов: `mkdir`

Создает новые каталоги.

```bash
# Создать каталог
mkdir my_directory
# Создать вложенные каталоги
mkdir -p parent/child/grandchild
# Создать несколько каталогов
mkdir dir1 dir2 dir3
```

### Копирование Файлов: `cp`

Копирует файлы и каталоги.

```bash
# Скопировать файл
cp source.txt destination.txt
# Рекурсивно скопировать каталог
cp -r source_dir dest_dir
# Копировать с запросом подтверждения
cp -i file1.txt file2.txt
# Сохранить атрибуты файла
cp -p original.txt copy.txt
```

### Перемещение/Переименование: `mv`

Перемещает или переименовывает файлы и каталоги.

```bash
# Переименовать файл
mv oldname.txt newname.txt
# Переместить файл в каталог
mv file.txt /path/to/directory/
# Переместить несколько файлов
mv file1 file2 file3 target_directory/
```

### Удаление Файлов: `rm`

Удаляет файлы и каталоги.

```bash
# Удалить файл
rm file.txt
# Удалить каталог и содержимое
rm -r directory/
# Принудительное удаление без подтверждения
rm -f file.txt
# Интерактивное удаление (подтверждение каждого)
rm -i *.txt
```

## Навигация и Управление Путями

### Текущий Каталог: `pwd`

Выводит путь к текущему рабочему каталогу.

```bash
# Показать текущий каталог
pwd
# Пример вывода:
/home/user/documents
```

### Смена Каталога: `cd`

Переключается на другой каталог.

```bash
# Перейти в домашний каталог
cd ~
# Перейти в родительский каталог
cd ..
# Перейти в предыдущий каталог
cd -
# Перейти в определенный каталог
cd /path/to/directory
```

<BaseQuiz id="shell-cd-1" correct="A">
  <template #question>
    Что делает <code>cd ~</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Переходит в домашний каталог</BaseQuizOption>
  <BaseQuizOption value="B">Переходит в корневой каталог</BaseQuizOption>
  <BaseQuizOption value="C">Переходит в родительский каталог</BaseQuizOption>
  <BaseQuizOption value="D">Создает новый каталог</BaseQuizOption>
  
  <BaseQuizAnswer>
    Символ <code>~</code> является сокращением для домашнего каталога. <code>cd ~</code> переходит в ваш домашний каталог, что эквивалентно <code>cd $HOME</code> или <code>cd /home/username</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### Дерево Каталогов: `tree`

Отображает структуру каталогов в виде дерева.

```bash
# Показать дерево каталогов
tree
# Ограничить глубину до 2 уровней
tree -L 2
# Показать только каталоги
tree -d
```

## Обработка Текста и Поиск

### Просмотр Файлов: `cat` / `less` / `head` / `tail`

Отображает содержимое файлов различными способами.

```bash
# Показать весь файл
cat file.txt
# Просмотр файла постранично
less file.txt
# Показать первые 10 строк
head file.txt
# Показать последние 10 строк
tail file.txt
# Показать последние 20 строк
tail -n 20 file.txt
# Следить за изменениями файла (полезно для логов)
tail -f logfile.txt
```

### Поиск в Файлах: `grep`

Ищет шаблоны в текстовых файлах.

```bash
# Поиск шаблона в файле
grep "pattern" file.txt
# Поиск без учета регистра
grep -i "pattern" file.txt
# Рекурсивный поиск в каталогах
grep -r "pattern" directory/
# Показать номера строк
grep -n "pattern" file.txt
# Посчитать совпадающие строки
grep -c "pattern" file.txt
```

<BaseQuiz id="shell-grep-1" correct="B">
  <template #question>
    Что делает <code>grep -r "pattern" directory/</code>?
  </template>
  
  <BaseQuizOption value="A">Ищет только в текущем файле</BaseQuizOption>
  <BaseQuizOption value="B" correct>Рекурсивно ищет во всех файлах в каталоге</BaseQuizOption>
  <BaseQuizOption value="C">Заменяет шаблон в файлах</BaseQuizOption>
  <BaseQuizOption value="D">Удаляет файлы, содержащие шаблон</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг <code>-r</code> заставляет grep рекурсивно искать во всех файлах и подкаталогах. Это полезно для поиска текстовых шаблонов по всему дереву каталогов.
  </BaseQuizAnswer>
</BaseQuiz>

### Поиск Файлов: `find`

Находит файлы и каталоги по критериям.

```bash
# Найти файлы по имени
find . -name "*.txt"
# Найти файлы по типу
find . -type f -name "config*"
# Найти каталоги
find . -type d -name "backup"
# Найти файлы, измененные за последние 7 дней
find . -mtime -7
# Найти и выполнить команду
find . -name "*.log" -delete
```

### Манипуляция Текстом: `sed` / `awk` / `sort`

Обрабатывает и манипулирует текстовыми данными.

```bash
# Заменить текст в файле
sed 's/old/new/g' file.txt
# Извлечь определенные столбцы
awk '{print $1, $3}' file.txt
# Сортировать содержимое файла
sort file.txt
# Удалить дублирующиеся строки
sort file.txt | uniq
# Посчитать частоту слов
cat file.txt | tr ' ' '\n' | sort | uniq -c
```

## Разрешения и Владение Файлами

### Просмотр Разрешений: `ls -l`

Отображает подробные разрешения и владение файлами.

```bash
# Показать подробную информацию о файле
ls -l
# Пример вывода:
# -rw-r--r-- 1 user group 1024 Jan 1 12:00 file.txt
# d = каталог, r = чтение, w = запись, x = выполнение
```

### Изменение Разрешений: `chmod`

Изменяет разрешения файлов и каталогов.

```bash
# Дать разрешение на выполнение владельцу
chmod +x script.sh
# Установить определенные разрешения (755)
chmod 755 file.txt
# Удалить разрешение на запись для группы/других
chmod go-w file.txt
# Рекурсивное изменение разрешений
chmod -R 644 directory/
```

<BaseQuiz id="shell-chmod-1" correct="C">
  <template #question>
    Что устанавливает <code>chmod 755 file.txt</code>?
  </template>
  
  <BaseQuizOption value="A">Чтение, запись, выполнение для всех пользователей</BaseQuizOption>
  <BaseQuizOption value="B">Чтение и запись для владельца, чтение для остальных</BaseQuizOption>
  <BaseQuizOption value="C" correct>Чтение, запись, выполнение для владельца; чтение, выполнение для группы и остальных</BaseQuizOption>
  <BaseQuizOption value="D">Только чтение для всех пользователей</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 755</code> устанавливает разрешения как: владелец = 7 (rwx), группа = 5 (r-x), остальные = 5 (r-x). Это распространенный набор разрешений для исполняемых файлов и каталогов.
  </BaseQuizAnswer>
</BaseQuiz>

### Изменение Владения: `chown` / `chgrp`

Изменяет владельца и группу файла.

```bash
# Изменить владельца
chown newowner file.txt
# Изменить владельца и группу
chown newowner:newgroup file.txt
# Изменить только группу
chgrp newgroup file.txt
# Рекурсивное изменение владения
chown -R user:group directory/
```

### Числа Разрешений

Понимание числовой нотации разрешений.

```text
# Расчет разрешений:
# 4 = чтение (r), 2 = запись (w), 1 = выполнение (x)
# 755 = rwxr-xr-x (владелец: rwx, группа: r-x, остальные: r-x)
# 644 = rw-r--r-- (владелец: rw-, группа: r--, остальные: r--)
# 777 = rwxrwxrwx (полные разрешения для всех)
# 600 = rw------- (владелец: rw-, группа: ---, остальные: ---)
```

## Управление Процессами

### Просмотр Процессов: `ps` / `top` / `htop`

Отображает информацию о запущенных процессах.

```bash
# Показать процессы для текущего пользователя
ps
# Показать все процессы с деталями
ps aux
# Показать процессы в виде дерева
ps -ef --forest
# Интерактивный просмотр процессов
top
# Улучшенный просмотр процессов (если доступен)
htop
```

### Фоновые Задания: `&` / `jobs` / `fg` / `bg`

Управляет фоновыми и переднеплановыми процессами.

```bash
# Запустить команду в фоне
command &
# Показать активные задания
jobs
# Вывести задание на передний план
fg %1
# Отправить задание в фон
bg %1
# Приостановить текущий процесс
Ctrl+Z
```

### Завершение Процессов: `kill` / `killall`

Завершает процессы по PID или имени.

```bash
# Завершить процесс по PID
kill 1234
# Принудительно завершить процесс
kill -9 1234
# Завершить все процессы с именем
killall firefox
# Отправить определенный сигнал
kill -TERM 1234
```

### Мониторинг Системы: `free` / `df` / `du`

Мониторинг системных ресурсов и использования диска.

```bash
# Показать использование памяти
free -h
# Показать дисковое пространство
df -h
# Показать размер каталога
du -sh directory/
# Показать самые большие каталоги
du -h --max-depth=1 | sort -hr
```

## Перенаправление Ввода/Вывода

### Перенаправление: `>` / `>>` / `<`

Перенаправляет вывод команд и ввод.

```bash
# Перенаправить вывод в файл (перезаписать)
command > output.txt
# Добавить вывод в файл
command >> output.txt
# Перенаправить ввод из файла
command < input.txt
# Перенаправить и вывод, и ошибки
command > output.txt 2>&1
# Отбросить вывод
command > /dev/null
```

<BaseQuiz id="shell-redirect-1" correct="B">
  <template #question>
    В чем разница между <code>></code> и <code>>></code> при перенаправлении в оболочке?
  </template>
  
  <BaseQuizOption value="A"><code>></code> добавляет, <code>>></code> перезаписывает</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>></code> перезаписывает файл, <code>>></code> добавляет в файл</BaseQuizOption>
  <BaseQuizOption value="C"><code>></code> перенаправляет stdout, <code>>></code> перенаправляет stderr</BaseQuizOption>
  <BaseQuizOption value="D">Разницы нет</BaseQuizOption>
  
  <BaseQuizAnswer>
    Оператор <code>></code> перезаписывает целевой файл, если он существует, в то время как <code>>></code> добавляет вывод в конец файла. Используйте <code>>></code>, если хотите сохранить существующее содержимое.
  </BaseQuizAnswer>
</BaseQuiz>

### Конвейеры (Pipes): `|`

Соединяет команды с помощью конвейеров.

```bash
# Базовое использование конвейера
command1 | command2
# Множественные конвейеры
cat file.txt | grep "pattern" | sort | uniq
# Посчитать строки в выводе
ps aux | wc -l
# Просмотреть длинный вывод постранично
ls -la | less
```

### Tee: `tee`

Записывает вывод как в файл, так и в stdout.

```bash
# Сохранить вывод и отобразить его
command | tee output.txt
# Добавить в файл
command | tee -a output.txt
# Множественные выводы
command | tee file1.txt file2.txt
```

### Here Documents: `<<`

Предоставляет многострочный ввод командам.

```bash
# Создать файл с помощью here document
cat << EOF > file.txt
Line 1
Line 2
Line 3
EOF
# Отправить письмо с помощью here document
mail user@example.com << EOF
Subject: Test
This is a test message.
EOF
```

## Переменные и Окружение

### Переменные: Присвоение и Использование

Создание и использование переменных оболочки.

```bash
# Присвоение переменных (без пробелов вокруг =)
name="John"
count=42
# Использование переменных
echo $name
echo "Hello, $name"
echo "Count: ${count}"
# Подстановка команд
current_dir=$(pwd)
date_today=$(date +%Y-%m-%d)
```

### Переменные Окружения: `export` / `env`

Управление переменными окружения.

```bash
# Экспортировать переменную в окружение
export PATH="/new/path:$PATH"
export MY_VAR="value"
# Просмотреть все переменные окружения
env
# Просмотреть конкретную переменную
echo $HOME
echo $PATH
# Сбросить переменную
unset MY_VAR
```

### Специальные Переменные

Встроенные переменные со специальным значением.

```bash
# Аргументы скрипта
$0  # Имя скрипта
$1, $2, $3...  # Первый, второй, третий аргумент
$#  # Количество аргументов
$@  # Все аргументы как отдельные слова
$*  # Все аргументы как одно слово
$?  # Код завершения последней команды
# Информация о процессе
$$  # PID текущей оболочки
$!  # PID последней фоновой команды
```

### Развертывание Параметров

Продвинутые методы манипулирования переменными.

```bash
# Значения по умолчанию
${var:-default}  # Использовать значение по умолчанию, если var пусто
${var:=default}  # Установить var в значение по умолчанию, если пусто
# Манипуляции со строками
${var#pattern}   # Удалить кратчайшее совпадение с начала
${var##pattern}  # Удалить самое длинное совпадение с начала
${var%pattern}   # Удалить кратчайшее совпадение с конца
${var%%pattern}  # Удалить самое длинное совпадение с конца
```

## Основы Скриптинга

### Структура Скрипта

Базовый формат скрипта и его выполнение.

```bash
#!/bin/bash
# Это комментарий
# Переменные
greeting="Hello, World!"
user=$(whoami)
# Вывод
echo $greeting
echo "Current user: $user"
# Сделать скрипт исполняемым:
chmod +x script.sh
# Запустить скрипт:
./script.sh
```

### Условные Операторы: `if`

Управление потоком скрипта с помощью условий.

```bash
#!/bin/bash
if [ -f "file.txt" ]; then
    echo "File exists"
elif [ -d "directory" ]; then
    echo "Directory exists"
else
    echo "Neither exists"
fi
# Сравнение строк
if [ "$USER" = "root" ]; then
    echo "Running as root"
fi
# Сравнение чисел
if [ $count -gt 10 ]; then
    echo "Count is greater than 10"
fi
```

### Циклы: `for` / `while`

Повторение команд с использованием циклов.

```bash
#!/bin/bash
# Цикл for с диапазоном
for i in {1..5}; do
    echo "Number: $i"
done
# Цикл for с файлами
for file in *.txt; do
    echo "Processing: $file"
done
# Цикл while
count=1
while [ $count -le 5 ]; do
    echo "Count: $count"
    count=$((count + 1))
done
```

### Функции

Создание многократно используемых блоков кода.

```bash
#!/bin/bash
# Определение функции
greet() {
    local name=$1
    echo "Hello, $name!"
}
# Функция с возвращаемым значением
add_numbers() {
    local sum=$(($1 + $2))
    echo $sum
}
# Вызов функций
greet "Alice"
result=$(add_numbers 5 3)
echo "Sum: $result"
```

## Сетевые и Системные Команды

### Сетевые Команды

Проверка подключения и сетевой конфигурации.

```bash
# Проверить сетевое подключение
ping google.com
ping -c 4 google.com  # Отправить только 4 пакета
# DNS-запрос
nslookup google.com
dig google.com
# Сетевая конфигурация
ip addr show  # Показать IP-адреса
ip route show # Показать таблицу маршрутизации
# Загрузка файлов
wget https://example.com/file.txt
curl -O https://example.com/file.txt
```

### Системная Информация: `uname` / `whoami` / `date`

Получение информации о системе и пользователе.

```bash
# Информация о системе
uname -a      # Вся системная информация
uname -r      # Версия ядра
hostname      # Имя компьютера
whoami        # Текущее имя пользователя
id            # ID пользователя и группы
# Дата и время
date          # Текущая дата/время
date +%Y-%m-%d # Пользовательский формат
uptime        # Время работы системы
```

### Архив и Сжатие: `tar` / `zip`

Создание и извлечение сжатых архивов.

```bash
# Создать архив tar
tar -czf archive.tar.gz directory/
# Извлечь архив tar
tar -xzf archive.tar.gz
# Создать zip архив
zip -r archive.zip directory/
# Извлечь zip архив
unzip archive.zip
# Просмотреть содержимое архива
tar -tzf archive.tar.gz
unzip -l archive.zip
```

### Передача Файлов: `scp` / `rsync`

Передача файлов между системами.

```bash
# Скопировать файл на удаленный сервер
scp file.txt user@server:/path/to/destination
# Скопировать с удаленного сервера
scp user@server:/path/to/file.txt .
# Синхронизировать каталоги (локальный на удаленный)
rsync -avz local_dir/ user@server:/remote_dir/
# Синхронизировать с удалением (зеркалирование)
rsync -avz --delete local_dir/ user@server:/remote_dir/
```

## История Команд и Сокращения

### История Команд: `history`

Просмотр и повторное использование предыдущих команд.

```bash
# Показать историю команд
history
# Показать последние 10 команд
history 10
# Выполнить предыдущую команду
!!
# Выполнить команду по номеру
!123
# Выполнить последнюю команду, начинающуюся с 'ls'
!ls
# Интерактивный поиск по истории
Ctrl+R
```

### Расширение Истории

Повторное использование частей предыдущих команд.

```bash
# Аргументы последней команды
!$    # Последний аргумент предыдущей команды
!^    # Первый аргумент предыдущей команды
!*    # Все аргументы предыдущей команды
# Пример использования:
ls /very/long/path/to/file.txt
cd !$  # Переходит в /very/long/path/to/file.txt
```

### Сочетания Клавиш

Основные сочетания клавиш для эффективной работы в командной строке.

```bash
# Навигация
Ctrl+A  # Переместиться в начало строки
Ctrl+E  # Переместиться в конец строки
Ctrl+F  # Переместиться вперед на один символ
Ctrl+B  # Переместиться назад на один символ
Alt+F   # Переместиться вперед на одно слово
Alt+B   # Переместиться назад на одно слово
# Редактирование
Ctrl+U  # Очистить строку перед курсором
Ctrl+K  # Очистить строку после курсора
Ctrl+W  # Удалить слово перед курсором
Ctrl+Y  # Вставить последний удаленный текст
# Управление процессами
Ctrl+C  # Прервать текущую команду
Ctrl+Z  # Приостановить текущую команду
Ctrl+D  # Выход из оболочки или EOF
```

## Комбинации Команд и Советы

### Полезные Комбинации Команд

Мощные однострочники для общих задач.

```bash
# Найти и заменить текст в нескольких файлах
find . -name "*.txt" -exec sed -i 's/old/new/g' {} \;
# Найти самые большие файлы в текущем каталоге
du -ah . | sort -rh | head -10
# Мониторинг лог-файла на наличие определенного шаблона
tail -f /var/log/syslog | grep "ERROR"
# Посчитать файлы в каталоге
ls -1 | wc -l
# Создать резервную копию с временной меткой
cp file.txt file.txt.backup.$(date +%Y%m%d-%H%M%S)
```

### Псевдонимы (Aliases) и Функции

Создание ярлыков для часто используемых команд.

```bash
# Создать псевдонимы (добавить в ~/.bashrc)
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
# Просмотреть все псевдонимы
alias
# Создать постоянные псевдонимы в ~/.bashrc:
echo "alias mycommand='long command here'" >>
~/.bashrc
source ~/.bashrc
```

### Управление Заданиями и Сессии Screen

Управление долго выполняющимися процессами и сессиями.

```bash
# Запустить команду в фоне
nohup long_running_command &
# Запустить сессию screen
screen -S mysession
# Отключиться от screen: Ctrl+A затем D
# Повторно подключиться к screen
screen -r mysession
# Показать список сессий screen
screen -ls
# Альтернатива: tmux
tmux new -s mysession
# Отключиться: Ctrl+B затем D
tmux attach -t mysession
```

### Системное Обслуживание

Общие задачи системного администрирования.

```bash
# Проверить использование диска
df -h
du -sh /*
# Проверить использование памяти
free -h
cat /proc/meminfo
# Проверить запущенные службы
systemctl status service_name
systemctl list-units --type=service
# Обновить списки пакетов (Ubuntu/Debian)
sudo apt update && sudo apt upgrade
# Поиск установленных пакетов
dpkg -l | grep package_name
```

## Соответствующие Ссылки

- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/rhel">Шпаргалка по Red Hat Enterprise Linux</router-link>
- <router-link to="/git">Шпаргалка по Git</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>
- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>
- <router-link to="/ansible">Шпаргалка по Ansible</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>

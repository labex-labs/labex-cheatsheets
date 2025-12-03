---
title: 'Шпаргалка по Hydra | LabEx'
description: 'Изучите взлом паролей с помощью Hydra с этой исчерпывающей шпаргалкой. Краткий справочник по атакам методом перебора, аудиту паролей, тестированию безопасности, протоколам аутентификации и инструментам тестирования на проникновение.'
pdfUrl: '/cheatsheets/pdf/hydra-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Hydra
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/hydra">Изучите Hydra с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите взлом паролей Hydra и тестирование на проникновение с помощью практических лабораторий и сценариев реального мира. LabEx предлагает комплексные курсы по Hydra, охватывающие атаки на протоколы, эксплуатацию веб-форм, оптимизацию производительности и этичное использование. Освойте методы перебора для авторизованного тестирования безопасности и оценки уязвимостей.
</base-disclaimer-content>
</base-disclaimer>

## Базовый синтаксис и установка

### Установка: `sudo apt install hydra`

Hydra обычно предустановлена в Kali Linux, но может быть установлена и в других дистрибутивах.

```bash
# Установка в системах Debian/Ubuntu
sudo apt install hydra
# Установка в других системах
sudo apt-get install hydra
# Проверка установки
hydra -h
# Проверка поддерживаемых протоколов
hydra
```

### Базовый синтаксис: `hydra [options] target service`

Базовый синтаксис: `hydra -l <username> -P <password_file> <target_protocol>://<target_address>`

```bash
# Одиночное имя пользователя, список паролей
hydra -l username -P passwords.txt target.com ssh
# Список имен пользователей, список паролей
hydra -L users.txt -P passwords.txt target.com ssh
# Одиночное имя пользователя, одиночный пароль
hydra -l admin -p password123 192.168.1.100 ftp
```

<BaseQuiz id="hydra-syntax-1" correct="B">
  <template #question>
    В чем разница между <code>-l</code> и <code>-L</code> в Hydra?
  </template>
  
  <BaseQuizOption value="A"><code>-l</code> для паролей, <code>-L</code> для имен пользователей</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>-l</code> указывает одно имя пользователя, <code>-L</code> указывает файл со списком имен пользователей</BaseQuizOption>
  <BaseQuizOption value="C">Разницы нет</BaseQuizOption>
  <BaseQuizOption value="D"><code>-l</code> в нижнем регистре, <code>-L</code> в верхнем регистре</BaseQuizOption>
  
  <BaseQuizAnswer>
    Опция <code>-l</code> используется для одного имени пользователя, в то время как <code>-L</code> используется для файла, содержащего список имен пользователей. Аналогично, <code>-p</code> для одного пароля и <code>-P</code> для файла со списком паролей.
  </BaseQuizAnswer>
</BaseQuiz>

### Основные опции: `-l`, `-L`, `-p`, `-P`

Указывают имена пользователей и пароли для атаки методом перебора.

```bash
# Опции имени пользователя
-l username          # Одиночное имя пользователя
-L userlist.txt      # Файл со списком имен пользователей
# Опции пароля
-p password          # Одиночный пароль
-P passwordlist.txt  # Файл со списком паролей
# Общее расположение списков слов
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/metasploit/unix_passwords.txt
```

### Опции вывода: `-o`, `-b`

Сохранение результатов в файл для последующего анализа.

```bash
# Сохранить результаты в файл
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# Формат вывода JSON
hydra -l admin -P passwords.txt target.com ssh -b json
# Подробный вывод
hydra -l admin -P passwords.txt target.com ssh -V
```

<BaseQuiz id="hydra-output-1" correct="A">
  <template #question>
    Что делает команда <code>hydra -V</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Включает подробный вывод, показывающий детальный прогресс</BaseQuizOption>
  <BaseQuizOption value="B">Проверяет файл списка слов</BaseQuizOption>
  <BaseQuizOption value="C">Показывает версию Hydra</BaseQuizOption>
  <BaseQuizOption value="D">Работает только в подробном режиме</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг <code>-V</code> включает подробный режим, который показывает детальный вывод, включая каждую попытку входа, что упрощает мониторинг прогресса и отладку проблем во время атак по подбору паролей.
  </BaseQuizAnswer>
</BaseQuiz>

## Атаки, специфичные для протоколов

### SSH: `hydra target ssh`

Атака на SSH-сервисы с комбинациями имен пользователей и паролей.

```bash
# Базовая атака SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh
# Несколько имен пользователей
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
# Пользовательский порт SSH
hydra -l admin -P passwords.txt 192.168.1.100 -s 2222 ssh
# С использованием потоков (threading)
hydra -l root -P passwords.txt -t 6 ssh://192.168.1.100
```

<BaseQuiz id="hydra-ssh-1" correct="C">
  <template #question>
    Что делает флаг <code>-s</code> в Hydra?
  </template>
  
  <BaseQuizOption value="A">Устанавливает тип сервиса</BaseQuizOption>
  <BaseQuizOption value="B">Включает скрытый режим</BaseQuizOption>
  <BaseQuizOption value="C" correct>Указывает пользовательский номер порта</BaseQuizOption>
  <BaseQuizOption value="D">Устанавливает количество потоков</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг <code>-s</code> указывает пользовательский номер порта, когда сервис работает на нестандартном порту. Например, <code>-s 2222</code> нацелен на SSH на порту 2222 вместо порта по умолчанию 22.
  </BaseQuizAnswer>
</BaseQuiz>

### FTP: `hydra target ftp`

Перебор учетных данных для входа в FTP.

```bash
# Базовая атака FTP
hydra -l admin -P passwords.txt ftp://192.168.1.100
# Проверка анонимного FTP
hydra -l anonymous -p "" ftp://192.168.1.100
# Пользовательский порт FTP
hydra -l user -P passwords.txt -s 2121 192.168.1.100 ftp
```

### Атаки на базы данных: `mysql`, `postgres`, `mssql`

Атака на сервисы баз данных методом перебора учетных данных.

```bash
# Атака MySQL
hydra -l root -P passwords.txt 192.168.1.100 mysql
# Атака PostgreSQL
hydra -l postgres -P passwords.txt 192.168.1.100 postgres
# Атака MSSQL
hydra -l sa -P passwords.txt 192.168.1.100 mssql
# Атака MongoDB
hydra -l admin -P passwords.txt 192.168.1.100 mongodb
```

### SMTP/Email: `hydra target smtp`

Атака на аутентификацию почтового сервера.

```bash
# Перебор SMTP
hydra -l admin -P passwords.txt smtp://mail.target.com
# С пустыми паролями
hydra -P passwords.txt -e ns -V -s 25 smtp.target.com smtp
# Атака IMAP
hydra -l user -P passwords.txt imap://mail.target.com
```

## Атаки на веб-приложения

### Веб-формы HTTP POST: `http-post-form`

Атака на веб-формы входа с использованием метода HTTP POST с заполнителями `^USER^` и `^PASS^`.

```bash
# Базовая атака формы POST
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
# С пользовательским сообщением об ошибке
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid password"
# С условием успеха
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/admin:username=^USER^&password=^PASS^:S=Dashboard"
```

### Веб-формы HTTP GET: `http-get-form`

Аналогично формам POST, но нацелено на GET-запросы.

```bash
# Атака формы GET
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# С пользовательскими заголовками
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/auth:user=^USER^&pass=^PASS^:F=Error:H=Cookie: session=abc123"
```

### HTTP Basic Auth: `http-get`/`http-post`

Атака на веб-серверы с использованием базовой HTTP-аутентификации.

```bash
# Базовая HTTP-аутентификация
hydra -l admin -P passwords.txt http-get://192.168.1.100
# Базовая HTTPS-аутентификация
hydra -l admin -P passwords.txt https-get://secure.target.com
# С пользовательским путем
hydra -l admin -P passwords.txt http-get://192.168.1.100/admin
```

### Расширенные веб-атаки

Обработка сложных веб-приложений с токенами CSRF и файлами cookie.

```bash
# С обработкой токена CSRF
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^&csrf=^CSRF^:F=Error:H=Cookie: csrf=^CSRF^"
# С файлами cookie сессии
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: PHPSESSID=abc123"
```

## Опции производительности и потоков

### Потоки (Threading): `-t` (Задачи)

Управление количеством одновременных соединений при атаке.

```bash
# Потоки по умолчанию (16 задач)
hydra -l admin -P passwords.txt target.com ssh
# Пользовательское количество потоков
hydra -l admin -P passwords.txt -t 4 target.com ssh
# Высокопроизводительная атака (использовать с осторожностью)
hydra -l admin -P passwords.txt -t 64 target.com ssh
# Консервативные потоки (избегать обнаружения)
hydra -l admin -P passwords.txt -t 1 target.com ssh
```

### Время ожидания: `-w` (Задержка)

Добавление задержек между попытками, чтобы избежать ограничения скорости и обнаружения.

```bash
# Ожидание 30 секунд между попытками
hydra -l admin -P passwords.txt -w 30 target.com ssh
# Комбинация с потоками
hydra -l admin -P passwords.txt -t 2 -w 10 target.com ssh
# Случайная задержка (1-5 секунд)
hydra -l admin -P passwords.txt -W 5 target.com ssh
```

### Несколько целей: `-M` (Файл целей)

Атака на несколько хостов, указанных в файле.

```bash
# Создать файл целей
echo "192.168.1.100" > targets.txt
echo "192.168.1.101" >> targets.txt
echo "192.168.1.102" >> targets.txt
# Атака на несколько целей
hydra -L users.txt -P passwords.txt -M targets.txt ssh
# С пользовательскими потоками для каждой цели
hydra -L users.txt -P passwords.txt -M targets.txt -t 2 ssh
```

### Опции возобновления и остановки

Возобновление прерванных атак и управление поведением остановки.

```bash
# Остановить после первого успеха
hydra -l admin -P passwords.txt -f target.com ssh
# Возобновить предыдущую атаку
hydra -R
# Создать файл восстановления
hydra -l admin -P passwords.txt -I restore.txt target.com ssh
```

## Расширенные функции и опции

### Генерация паролей: `-e` (Дополнительные тесты)

Автоматическое тестирование дополнительных вариаций паролей.

```bash
# Проверить пустые пароли
hydra -l admin -e n target.com ssh
# Проверить имя пользователя как пароль
hydra -l admin -e s target.com ssh
# Проверить обратное имя пользователя
hydra -l admin -e r target.com ssh
# Комбинировать все опции
hydra -l admin -e nsr -P passwords.txt target.com ssh
```

### Формат, разделенный двоеточием: `-C`

Использование комбинаций имя_пользователя:пароль для сокращения времени атаки.

```bash
# Создать файл учетных данных
echo "admin:admin" > creds.txt
echo "root:password" >> creds.txt
echo "user:123456" >> creds.txt
# Использовать формат с двоеточием
hydra -C creds.txt target.com ssh
# Быстрее, чем тестирование полных комбинаций
```

### Поддержка прокси: `HYDRA_PROXY`

Использование прокси-серверов для атак через переменные окружения.

```bash
# HTTP прокси
export HYDRA_PROXY=connect://proxy.example.com:8080
hydra -l admin -P passwords.txt target.com ssh
# SOCKS4 прокси с аутентификацией
export HYDRA_PROXY=socks4://user:pass@127.0.0.1:1080
# SOCKS5 прокси
export HYDRA_PROXY=socks5://proxy.example.com:1080
```

### Оптимизация списка паролей: `pw-inspector`

Использование pw-inspector для фильтрации списков паролей на основе политик.

```bash
# Фильтрация паролей (мин. 6 символов, 2 класса символов)
cat passwords.txt | pw-inspector -m 6 -c 2 -n > filtered.txt
# Использование отфильтрованного списка с Hydra
hydra -l admin -P filtered.txt target.com ssh
# Сначала удалить дубликаты
cat passwords.txt | sort | uniq > unique_passwords.txt
```

## Этичное использование и лучшие практики

### Юридические и этические нормы

Hydra может использоваться как в законных, так и в незаконных целях. Получите соответствующее разрешение и одобрение перед выполнением атак методом перебора.

```text
Выполняйте атаки только на системы, на которые получено явное разрешение
Всегда убедитесь, что у вас есть явное разрешение от владельца системы или администратора
Документируйте все тестовые действия для соблюдения требований
Используйте только во время авторизованного тестирования на проникновение
Никогда не используйте для несанкционированных попыток доступа
```

### Меры защиты

Защита от атак методом перебора с помощью надежных паролей и политик.

```text
Внедряйте политики блокировки учетных записей для временной блокировки учетных записей после неудачных попыток
Используйте многофакторную аутентификацию (MFA)
Внедряйте системы CAPTCHA для предотвращения использования автоматизированных инструментов
Мониторинг и логирование попыток аутентификации
Внедрение ограничения скорости и блокировки по IP
```

### Лучшие практики тестирования

Начинайте с консервативных настроек и документируйте все действия для обеспечения прозрачности.

```text
Начинайте с низкого количества потоков, чтобы избежать сбоев в работе сервиса
Используйте списки слов, подходящие для целевой среды
По возможности проводите тестирование в утвержденные окна обслуживания
Отслеживайте производительность целевой системы во время тестирования
Имейте готовые процедуры реагирования на инциденты
```

### Общие сценарии использования

Команды Red и Blue Team извлекают выгоду из аудита паролей, оценки безопасности и тестирования на проникновение.

```text
Взлом паролей для выявления слабых паролей и оценки надежности паролей
Аудит безопасности сетевых служб
Тестирование на проникновение и оценка уязвимостей
Тестирование соответствия политикам паролей
Учебные демонстрации
```

## Альтернатива GUI и дополнительные инструменты

### XHydra: Графический интерфейс

XHydra — это графический интерфейс для Hydra, который позволяет выбирать конфигурацию с помощью элементов управления GUI вместо переключателей командной строки.

```bash
# Запуск графического интерфейса XHydra
xhydra
# Установка, если недоступно
sudo apt install hydra-gtk
# Возможности:
# - Интерфейс "наведи и щелкни"
# - Предварительно настроенные шаблоны атак
# - Визуальный мониторинг прогресса
# - Простой выбор цели и списка слов
```

### Hydra Wizard: Интерактивная настройка

Интерактивный мастер, который помогает пользователям настроить Hydra с помощью простых вопросов.

```bash
# Запуск интерактивного мастера
hydra-wizard
# Мастер запрашивает:
# 1. Сервис для атаки
# 2. Цель для атаки
# 3. Имя пользователя или файл с именами пользователей
# 4. Пароль или файл с паролями
# 5. Дополнительные тесты паролей
# 6. Номер порта
# 7. Финальное подтверждение
```

### Списки паролей по умолчанию: `dpl4hydra`

Генерация списков паролей по умолчанию для конкретных брендов и систем.

```bash
# Обновить базу данных по умолчанию
dpl4hydra refresh
# Сгенерировать список для конкретного бренда
dpl4hydra cisco
dpl4hydra netgear
dpl4hydra linksys
# Использовать сгенерированные списки
hydra -C dpl4hydra_cisco.lst 192.168.1.1 ssh
# Все бренды
dpl4hydra all
```

### Интеграция с другими инструментами

Объединение Hydra с инструментами разведки и перечисления.

```bash
# Объединение с обнаружением сервисов Nmap
nmap -sV 192.168.1.0/24 | grep -E "(ssh|ftp|http)"
# Использование результатов перечисления имен пользователей
enum4linux 192.168.1.100 | grep "user:" > users.txt
# Интеграция со списками слов Metasploit
ls /usr/share/wordlists/metasploit/
```

## Устранение неполадок и производительность

### Распространенные проблемы и решения

Решение типичных проблем, возникающих при использовании Hydra.

```bash
# Ошибки таймаута соединения
hydra -l admin -P passwords.txt -t 1 -w 30 target.com ssh
# Ошибка "слишком много соединений"
hydra -l admin -P passwords.txt -t 2 target.com ssh
# Оптимизация использования памяти
hydra -l admin -P small_list.txt target.com ssh
# Проверить поддерживаемые протоколы
hydra
# Посмотреть список поддерживаемых сервисов
```

### Оптимизация производительности

Оптимизация списков паролей и сортировка по вероятности для более быстрых результатов.

```bash
# Сортировать пароли по вероятности
hydra -l admin -P passwords.txt -u target.com ssh
# Удалить дубликаты
sort passwords.txt | uniq > clean_passwords.txt
# Оптимизация потоков в зависимости от цели
# Локальная сеть: -t 16
# Цель в Интернете: -t 4
# Медленный сервис: -t 1
```

### Форматы вывода и анализ

Различные форматы вывода для анализа результатов и составления отчетов.

```bash
# Стандартный текстовый вывод
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# Формат JSON для парсинга
hydra -l admin -P passwords.txt target.com ssh -b json -o results.json
# Подробный вывод для отладки
hydra -l admin -P passwords.txt target.com ssh -V
# Вывод только успешных результатов
hydra -l admin -P passwords.txt target.com ssh | grep "password:"
```

### Мониторинг ресурсов

Мониторинг системных и сетевых ресурсов во время атак.

```bash
# Мониторинг использования ЦП
top -p $(pidof hydra)
# Мониторинг сетевых соединений
netstat -an | grep :22
# Мониторинг использования памяти
ps aux | grep hydra
# Ограничение влияния на систему
nice -n 19 hydra -l admin -P passwords.txt target.com ssh
```

## Связанные ссылки

- <router-link to="/kali">Шпаргалка по Kali Linux</router-link>
- <router-link to="/cybersecurity">Шпаргалка по кибербезопасности</router-link>
- <router-link to="/nmap">Шпаргалка по Nmap</router-link>
- <router-link to="/wireshark">Шпаргалка по Wireshark</router-link>
- <router-link to="/comptia">Шпаргалка по CompTIA</router-link>
- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>

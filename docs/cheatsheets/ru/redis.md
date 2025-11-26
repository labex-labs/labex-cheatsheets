---
title: 'Шпаргалка по Redis'
description: 'Изучите Redis с нашей полной шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/redis-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Redis Справочник
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/redis">Изучите Redis с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите операции со структурами данных в памяти Redis с помощью практических лабораторий и реальных сценариев. LabEx предлагает комплексные курсы по Redis, охватывающие основные команды, структуры данных, стратегии кэширования, обмен сообщениями pub/sub и оптимизацию производительности. Освойте высокопроизводительное кэширование и обработку данных в реальном времени.
</base-disclaimer-content>
</base-disclaimer>

## Установка и Настройка Redis

### Docker: `docker run redis`

Самый быстрый способ запустить Redis локально.

```bash
# Запуск Redis в Docker
docker run --name my-redis -p 6379:6379 -d redis
# Подключение к Redis CLI
docker exec -it my-redis redis-cli
# Запуск с постоянным хранилищем
docker run --name redis-persistent -p 6379:6379 -v redis-data:/data -d redis
```

### Linux: `sudo apt install redis`

Установка сервера Redis в системах Ubuntu/Debian.

```bash
# Установка Redis
sudo apt update
sudo apt install redis-server
# Запуск службы Redis
sudo systemctl start redis-server
# Включение автозапуска при загрузке
sudo systemctl enable redis-server
# Проверка статуса
sudo systemctl status redis
```

### Подключение и Тестирование: `redis-cli`

Подключение к серверу Redis и проверка установки.

```bash
# Подключение к локальному Redis
redis-cli
# Тест соединения
redis-cli PING
# Подключение к удаленному Redis
redis-cli -h hostname -p 6379 -a password
# Выполнение одной команды
redis-cli SET mykey "Hello Redis"
```

## Базовые Операции со Строками

### Установка и Получение: `SET` / `GET`

Хранение простых значений (текст, числа, JSON и т. д.).

```redis
# Установка пары ключ-значение
SET mykey "Hello World"
# Получение значения по ключу
GET mykey
# Установка с истечением срока действия (в секундах)
SET session:123 "user_data" EX 3600
# Установка только если ключ не существует
SET mykey "new_value" NX
```

### Манипуляции со Строками: `APPEND` / `STRLEN`

Изменение и просмотр строковых значений.

```redis
# Добавление к существующей строке
APPEND mykey " - Welcome!"
# Получение длины строки
STRLEN mykey
# Получение подстроки
GETRANGE mykey 0 4
# Установка подстроки
SETRANGE mykey 6 "Redis"
```

### Числовые Операции: `INCR` / `DECR`

Увеличение или уменьшение целочисленных значений, хранящихся в Redis.

```redis
# Увеличение на 1
INCR counter
# Уменьшение на 1
DECR counter
# Увеличение на определенную величину
INCRBY counter 5
# Увеличение с плавающей точкой
INCRBYFLOAT price 0.1
```

### Множественные Операции: `MSET` / `MGET`

Эффективная работа с несколькими парами ключ-значение.

```redis
# Установка нескольких ключей одновременно
MSET key1 "value1" key2 "value2" key3 "value3"
# Получение нескольких значений
MGET key1 key2 key3
# Установка нескольких, только если ни один не существует
MSETNX key1 "val1" key2 "val2"
```

## Операции со Списками (Lists)

Списки — это упорядоченные последовательности строк, полезные в качестве очередей или стеков.

### Добавление Элементов: `LPUSH` / `RPUSH`

Добавление элементов в левый (голову) или правый (хвост) список.

```redis
# Добавление в голову (слева)
LPUSH mylist "first"
# Добавление в хвост (справа)
RPUSH mylist "last"
# Добавление нескольких элементов
LPUSH mylist "item1" "item2" "item3"
```

### Удаление Элементов: `LPOP` / `RPOP`

Удаление и возврат элементов с концов списка.

```redis
# Удаление из головы
LPOP mylist
# Удаление из хвоста
RPOP mylist
# Блокирующий pop (ожидание элемента)
BLPOP mylist 10
```

### Доступ к Элементам: `LRANGE` / `LINDEX`

Получение элементов или диапазонов из списков.

```redis
# Получить весь список
LRANGE mylist 0 -1
# Получить первые 3 элемента
LRANGE mylist 0 2
# Получить конкретный элемент по индексу
LINDEX mylist 0
# Получить длину списка
LLEN mylist
```

### Утилиты Списков: `LSET` / `LTRIM`

Изменение содержимого и структуры списка.

```redis
# Установка элемента по индексу
LSET mylist 0 "new_value"
# Обрезка списка до диапазона
LTRIM mylist 0 99
# Поиск позиции элемента
LPOS mylist "search_value"
```

## Операции с Множествами (Sets)

Множества — это коллекции уникальных, неупорядоченных строковых элементов.

### Базовые Операции с Множествами: `SADD` / `SMEMBERS`

Добавление уникальных элементов во множество и получение всех членов.

```redis
# Добавление элементов во множество
SADD myset "apple" "banana" "cherry"
# Получить все члены множества
SMEMBERS myset
# Проверка существования элемента
SISMEMBER myset "apple"
# Получить размер множества
SCARD myset
```

### Модификации Множеств: `SREM` / `SPOP`

Удаление элементов из множеств различными способами.

```redis
# Удаление конкретных элементов
SREM myset "banana"
# Удаление и возврат случайного элемента
SPOP myset
# Получить случайный элемент без удаления
SRANDMEMBER myset
```

### Операции с Множествами: `SINTER` / `SUNION`

Выполнение математических операций с множествами.

```redis
# Пересечение множеств
SINTER set1 set2
# Объединение множеств
SUNION set1 set2
# Разность множеств
SDIFF set1 set2
# Сохранение результата в новом множестве
SINTERSTORE result set1 set2
```

### Утилиты Множеств: `SMOVE` / `SSCAN`

Расширенное манипулирование множествами и инкрементное сканирование.

```redis
# Перемещение элемента между множествами
SMOVE source_set dest_set "element"
# Инкрементное сканирование множества
SSCAN myset 0 MATCH "a*" COUNT 10
```

## Операции с Хешами (Hashes)

Хеши хранят пары поле-значение, похожие на мини-объекты JSON или словари.

### Базовые Операции с Хешами: `HSET` / `HGET`

Установка и получение отдельных полей хеша.

```redis
# Установка поля хеша
HSET user:123 name "John Doe" age 30
# Получение поля хеша
HGET user:123 name
# Установка нескольких полей
HMSET user:123 email "john@example.com" city "NYC"
# Получение нескольких полей
HMGET user:123 name age email
```

### Инспекция Хешей: `HKEYS` / `HVALS`

Просмотр структуры и содержимого хеша.

```redis
# Получить все имена полей
HKEYS user:123
# Получить все значения
HVALS user:123
# Получить все поля и значения
HGETALL user:123
# Получить количество полей
HLEN user:123
```

### Утилиты Хешей: `HEXISTS` / `HDEL`

Проверка существования и удаление полей хеша.

```redis
# Проверить существование поля
HEXISTS user:123 email
# Удалить поля
HDEL user:123 age city
# Увеличить поле хеша
HINCRBY user:123 age 1
# Увеличение с плавающей точкой
HINCRBYFLOAT user:123 balance 10.50
```

### Сканирование Хешей: `HSCAN`

Инкрементная итерация по большим хешам.

```redis
# Сканирование полей хеша
HSCAN user:123 0
# Сканирование с сопоставлением по шаблону
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## Операции с Отсортированными Множествами (Sorted Sets)

Отсортированные множества сочетают уникальность множеств с упорядочиванием на основе баллов (scores).

### Базовые Операции: `ZADD` / `ZRANGE`

Добавление членов с баллами и получение диапазонов.

```redis
# Добавление членов с баллами
ZADD leaderboard 100 "player1" 200 "player2"
# Получить членов по рангу (с 0-индексацией)
ZRANGE leaderboard 0 -1
# Получить с баллами
ZRANGE leaderboard 0 -1 WITHSCORES
# Получить по диапазону баллов
ZRANGEBYSCORE leaderboard 100 200
```

### Информация об Отсортированном Множестве: `ZCARD` / `ZSCORE`

Получение информации о членах отсортированного множества.

```redis
# Получить размер множества
ZCARD leaderboard
# Получить балл члена
ZSCORE leaderboard "player1"
# Получить ранг члена
ZRANK leaderboard "player1"
# Подсчет членов в диапазоне баллов
ZCOUNT leaderboard 100 200
```

### Модификации: `ZREM` / `ZINCRBY`

Удаление членов и изменение баллов.

```redis
# Удалить членов
ZREM leaderboard "player1"
# Увеличить балл члена
ZINCRBY leaderboard 10 "player2"
# Удалить по рангу
ZREMRANGEBYRANK leaderboard 0 2
# Удалить по баллам
ZREMRANGEBYSCORE leaderboard 0 100
```

### Расширенные: `ZUNIONSTORE` / `ZINTERSTORE`

Объединение нескольких отсортированных множеств.

```redis
# Объединение отсортированных множеств
ZUNIONSTORE result 2 set1 set2
# Пересечение с весами
ZINTERSTORE result 2 set1 set2 WEIGHTS 1 2
# С функцией агрегации
ZUNIONSTORE result 2 set1 set2 AGGREGATE MAX
```

## Управление Ключами

### Инспекция Ключей: `KEYS` / `EXISTS`

Поиск ключей по шаблонам и проверка существования.

```redis
# Получить все ключи (использовать осторожно в продакшене)
KEYS *
# Ключи с шаблоном
KEYS user:*
# Ключи, оканчивающиеся на шаблон
KEYS *:profile
# Одиночный символ-заполнитель
KEYS order:?
# Проверить существование ключа
EXISTS mykey
```

### Информация о Ключах: `TYPE` / `TTL`

Получение метаданных ключа и информации об истечении срока действия.

```redis
# Получить тип данных ключа
TYPE mykey
# Получить время жизни (секунды)
TTL mykey
# Получить TTL в миллисекундах
PTTL mykey
# Удалить срок действия
PERSIST mykey
```

### Операции с Ключами: `RENAME` / `DEL`

Переименование, удаление и перемещение ключей.

```redis
# Переименовать ключ
RENAME oldkey newkey
# Переименовать только если новый ключ не существует
RENAMENX oldkey newkey
# Удалить ключи
DEL key1 key2 key3
# Переместить ключ в другую базу данных
MOVE mykey 1
```

### Срок Действия: `EXPIRE` / `EXPIREAT`

Установка времени истечения срока действия ключей.

```redis
# Установить срок действия в секундах
EXPIRE mykey 3600
# Установить срок действия в определенный момент времени (timestamp)
EXPIREAT mykey 1609459200
# Установить срок действия в миллисекундах
PEXPIRE mykey 60000
```

## Управление Базами Данных

### Выбор Базы Данных: `SELECT` / `FLUSHDB`

Управление несколькими базами данных в Redis.

```redis
# Выбор базы данных (по умолчанию 0-15)
SELECT 0
# Очистить текущую базу данных
FLUSHDB
# Очистить все базы данных
FLUSHALL
# Получить размер текущей базы данных
DBSIZE
```

### Информация о Сервере: `INFO` / `PING`

Получение статистики сервера и проверка соединения.

```redis
# Проверить соединение с сервером
PING
# Получить информацию о сервере
INFO
# Получить определенный раздел информации
INFO memory
INFO replication
# Получить время сервера
TIME
```

### Персистентность: `SAVE` / `BGSAVE`

Управление персистентностью данных и резервным копированием Redis.

```redis
# Синхронное сохранение (блокирует сервер)
SAVE
# Фоновое сохранение (неблокирующее)
BGSAVE
# Получить время последнего сохранения
LASTSAVE
# Перезапись AOF файла
BGREWRITEAOF
```

### Конфигурация: `CONFIG GET` / `CONFIG SET`

Просмотр и изменение конфигурации Redis.

```redis
# Получить всю конфигурацию
CONFIG GET *
# Получить конкретную настройку
CONFIG GET maxmemory
# Установить конфигурацию
CONFIG SET timeout 300
# Сбросить статистику
CONFIG RESETSTAT
```

## Мониторинг Производительности

### Мониторинг в Реальном Времени: `MONITOR` / `SLOWLOG`

Отслеживание команд и выявление узких мест производительности.

```redis
# Мониторинг всех команд в реальном времени
MONITOR
# Получить журнал медленных запросов
SLOWLOG GET 10
# Получить длину журнала медленных запросов
SLOWLOG LEN
# Сбросить журнал медленных запросов
SLOWLOG RESET
```

### Анализ Памяти: `MEMORY USAGE` / `MEMORY STATS`

Анализ потребления памяти и оптимизация.

```redis
# Получить использование памяти ключом
MEMORY USAGE mykey
# Получить статистику памяти
MEMORY STATS
# Получить отчет "doctor" по памяти
MEMORY DOCTOR
# Очистка памяти
MEMORY PURGE
```

### Информация о Клиентах: `CLIENT LIST`

Мониторинг подключенных клиентов и соединений.

```redis
# Список всех клиентов
CLIENT LIST
# Получить информацию о клиенте
CLIENT INFO
# Завершить соединение клиента
CLIENT KILL ip:port
# Установить имя клиента
CLIENT SETNAME "my-app"
```

### Бенчмаркинг: `redis-benchmark`

Тестирование производительности Redis с помощью встроенного инструмента бенчмаркинга.

```bash
# Базовый бенчмарк
redis-benchmark
# Конкретные операции
redis-benchmark -t SET,GET -n 100000
# Размер полезной нагрузки
redis-benchmark -d 1024 -t SET -n 10000
```

## Расширенные Возможности

### Транзакции: `MULTI` / `EXEC`

Атомарное выполнение нескольких команд.

```redis
# Начало транзакции
MULTI
SET key1 "value1"
INCR counter
# Выполнение всех команд
EXEC
# Отмена транзакции
DISCARD
# Наблюдение за ключами на предмет изменений
WATCH mykey
```

### Pub/Sub: `PUBLISH` / `SUBSCRIBE`

Реализация обмена сообщениями между клиентами.

```redis
# Подписка на канал
SUBSCRIBE news sports
# Публикация сообщения
PUBLISH news "Breaking: Redis 7.0 released!"
# Подписка по шаблону
PSUBSCRIBE news:*
# Отписка
UNSUBSCRIBE news
```

### Скриптинг Lua: `EVAL` / `SCRIPT`

Выполнение пользовательских скриптов Lua атомарно.

```redis
# Выполнение скрипта Lua
EVAL "return redis.call('SET', 'key', 'value')" 0
# Загрузка скрипта и получение SHA
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# Выполнение по SHA
EVALSHA sha1 1 mykey
# Проверка существования скрипта
SCRIPT EXISTS sha1
```

### Потоки (Streams): `XADD` / `XREAD`

Работа с потоками Redis для данных, похожих на журналы.

```redis
# Добавление записи в поток
XADD mystream * field1 value1 field2 value2
# Чтение из потока
XREAD STREAMS mystream 0
# Получить длину потока
XLEN mystream
# Создание группы потребителей
XGROUP CREATE mystream mygroup 0
```

## Обзор Типов Данных

### Строки (Strings): Самый универсальный тип

Могут хранить текст, числа, JSON, двоичные данные. Максимальный размер: 512 МБ. Используются для: кэширования, счетчиков, флагов.

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### Списки (Lists): Упорядоченные коллекции

Связные списки строк. Используются для: очередей, стеков, лент активности, недавних элементов.

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### Множества (Sets): Уникальные коллекции

Неупорядоченные коллекции уникальных строк. Используются для: тегов, уникальных посетителей, связей.

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Советы по Конфигурации Redis

### Управление Памятью

Настройка лимитов памяти и политик вытеснения.

```redis
# Установка лимита памяти
CONFIG SET maxmemory 2gb
# Установка политики вытеснения
CONFIG SET maxmemory-policy allkeys-lru
# Проверка использования памяти
INFO memory
```

### Настройки Персистентности

Настройка параметров надежности хранения данных.

```redis
# Включение AOF
CONFIG SET appendonly yes
# Установка интервалов сохранения
CONFIG SET save "900 1 300 10 60 10000"
# Настройки перезаписи AOF
CONFIG SET auto-aof-rewrite-percentage 100
```

### Настройки Безопасности

Базовые настройки безопасности для Redis.

```redis
# Установка пароля
CONFIG SET requirepass mypassword
# Аутентификация
AUTH mypassword
# Отключение опасных команд
CONFIG SET rename-command FLUSHALL ""
# Установка таймаута
CONFIG SET timeout 300
# TCP keep alive
CONFIG SET tcp-keepalive 60
# Максимальное количество клиентов
CONFIG SET maxclients 10000
```

### Оптимизация Производительности

Оптимизация Redis для лучшей производительности.

```redis
# Включение конвейеризации (pipelining) для нескольких команд
# Использование пула соединений
# Настройка соответствующей политики maxmemory-policy
# Регулярный мониторинг медленных запросов
# Использование подходящих структур данных для конкретных случаев использования
```

## Связанные Ссылки

- <router-link to="/database">Справочник по Базам Данных</router-link>
- <router-link to="/mysql">Справочник по MySQL</router-link>
- <router-link to="/postgresql">Справочник по PostgreSQL</router-link>
- <router-link to="/mongodb">Справочник по MongoDB</router-link>
- <router-link to="/sqlite">Справочник по SQLite</router-link>
- <router-link to="/python">Справочник по Python</router-link>
- <router-link to="/javascript">Справочник по JavaScript</router-link>
- <router-link to="/devops">Справочник по DevOps</router-link>

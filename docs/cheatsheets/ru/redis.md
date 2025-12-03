---
title: 'Шпаргалка по Redis | LabEx'
description: 'Изучите хранилище данных в памяти Redis с помощью этой исчерпывающей шпаргалки. Краткий справочник по командам Redis, структурам данных, кэшированию, pub/sub, персистентности и высокопроизводительным решениям для кэширования.'
pdfUrl: '/cheatsheets/pdf/redis-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Redis
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/redis">Изучите Redis с практическими лабораторными работами</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите операции со структурами данных в памяти Redis с помощью практических лабораторных работ и сценариев реального мира. LabEx предлагает комплексные курсы по Redis, охватывающие основные команды, структуры данных, стратегии кэширования, обмен сообщениями pub/sub и оптимизацию производительности. Освойте высокопроизводительное кэширование и обработку данных в реальном времени.
</base-disclaimer-content>
</base-disclaimer>

## Установка и настройка Redis

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

### Подключение и проверка: `redis-cli`

Подключение к серверу Redis и проверка установки.

```bash
# Подключение к локальному Redis
redis-cli
# Проверка соединения
redis-cli PING
# Подключение к удаленному Redis
redis-cli -h hostname -p 6379 -a password
# Выполнение одной команды
redis-cli SET mykey "Hello Redis"
```

## Базовые операции со строками

### Установка и получение: `SET` / `GET`

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

<BaseQuiz id="redis-set-get-1" correct="C">
  <template #question>
    Что делает команда <code>SET mykey "value" EX 3600</code>?
  </template>
  
  <BaseQuizOption value="A">Устанавливает ключ со значением в 3600 байт</BaseQuizOption>
  <BaseQuizOption value="B">Устанавливает ключ, только если он существует</BaseQuizOption>
  <BaseQuizOption value="C" correct>Устанавливает ключ со значением, которое истекает через 3600 секунд</BaseQuizOption>
  <BaseQuizOption value="D">Устанавливает ключ с 3600 различными значениями</BaseQuizOption>
  
  <BaseQuizAnswer>
    Опция <code>EX</code> устанавливает время истечения срока действия в секундах. <code>SET mykey "value" EX 3600</code> сохраняет значение и автоматически удаляет его через 3600 секунд (1 час).
  </BaseQuizAnswer>
</BaseQuiz>

### Манипуляции со строками: `APPEND` / `STRLEN`

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

### Числовые операции: `INCR` / `DECR`

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

<BaseQuiz id="redis-incr-1" correct="A">
  <template #question>
    Что произойдет, если использовать <code>INCR</code> для ключа, которого не существует?
  </template>
  
  <BaseQuizOption value="A" correct>Redis создает ключ со значением 1</BaseQuizOption>
  <BaseQuizOption value="B">Redis возвращает ошибку</BaseQuizOption>
  <BaseQuizOption value="C">Redis создает ключ со значением 0</BaseQuizOption>
  <BaseQuizOption value="D">Ничего не происходит</BaseQuizOption>
  
  <BaseQuizAnswer>
    Если ключ не существует, <code>INCR</code> рассматривает его так, как будто у него значение 0, увеличивает его до 1 и создает ключ. Это делает <code>INCR</code> полезным для инициализации счетчиков.
  </BaseQuizAnswer>
</BaseQuiz>

### Множественные операции: `MSET` / `MGET`

Эффективная работа с несколькими парами ключ-значение.

```redis
# Установка нескольких ключей одновременно
MSET key1 "value1" key2 "value2" key3 "value3"
# Получение нескольких значений
MGET key1 key2 key3
# Установка нескольких, только если ни один не существует
MSETNX key1 "val1" key2 "val2"
```

## Операции со списками

Списки — это упорядоченные последовательности строк, полезные в качестве очередей или стеков.

### Добавление элементов: `LPUSH` / `RPUSH`

Добавление элементов в левую (голову) или правую (хвост) часть списка.

```redis
# Добавить в голову (слева)
LPUSH mylist "first"
# Добавить в хвост (справа)
RPUSH mylist "last"
# Добавить несколько элементов
LPUSH mylist "item1" "item2" "item3"
```

### Удаление элементов: `LPOP` / `RPOP`

Удаление и возврат элементов из концов списка.

```redis
# Удалить из головы
LPOP mylist
# Удалить из хвоста
RPOP mylist
# Блокирующий pop (ожидание элемента)
BLPOP mylist 10
```

### Доступ к элементам: `LRANGE` / `LINDEX`

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

<BaseQuiz id="redis-list-1" correct="B">
  <template #question>
    Что возвращает команда <code>LRANGE mylist 0 -1</code>?
  </template>
  
  <BaseQuizOption value="A">Только первый элемент</BaseQuizOption>
  <BaseQuizOption value="B" correct>Все элементы в списке</BaseQuizOption>
  <BaseQuizOption value="C">Только последний элемент</BaseQuizOption>
  <BaseQuizOption value="D">Ошибка</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>LRANGE</code> с <code>0 -1</code> возвращает все элементы в списке. <code>0</code> — это начальный индекс, а <code>-1</code> представляет последний элемент, поэтому это извлекает все от первого до последнего элемента.
  </BaseQuizAnswer>
</BaseQuiz>

### Утилиты для списков: `LSET` / `LTRIM`

Изменение содержимого и структуры списка.

```redis
# Установить элемент по индексу
LSET mylist 0 "new_value"
# Обрезать список до диапазона
LTRIM mylist 0 99
# Найти позицию элемента
LPOS mylist "search_value"
```

## Операции с множествами (Set)

Множества — это коллекции уникальных, неупорядоченных строковых элементов.

### Базовые операции с множествами: `SADD` / `SMEMBERS`

Добавление уникальных элементов во множество и получение всех членов.

```redis
# Добавить элементы во множество
SADD myset "apple" "banana" "cherry"
# Получить всех членов множества
SMEMBERS myset
# Проверить, существует ли элемент
SISMEMBER myset "apple"
```

<BaseQuiz id="redis-set-1" correct="C">
  <template #question>
    Что произойдет, если попытаться добавить дублирующийся элемент в множество Redis?
  </template>
  
  <BaseQuizOption value="A">Будет создана ошибка</BaseQuizOption>
  <BaseQuizOption value="B">Он заменит существующий элемент</BaseQuizOption>
  <BaseQuizOption value="C" correct>Дубликат игнорируется, и множество остается без изменений</BaseQuizOption>
  <BaseQuizOption value="D">Будет создан список</BaseQuizOption>
  
  <BaseQuizAnswer>
    Множества Redis содержат только уникальные элементы. Если вы попытаетесь добавить элемент, который уже существует, Redis проигнорирует его и вернет 0 (указывая, что элементы не были добавлены). Множество остается без изменений.
  </BaseQuizAnswer>
</BaseQuiz>
# Получить размер множества
SCARD myset
```

### Модификации множеств: `SREM` / `SPOP`

Удаление элементов из множеств различными способами.

```redis
# Удалить конкретные элементы
SREM myset "banana"
# Удалить и вернуть случайный элемент
SPOP myset
# Получить случайный элемент без удаления
SRANDMEMBER myset
```

### Операции с множествами: `SINTER` / `SUNION`

Выполнение математических операций с множествами.

```redis
# Пересечение множеств
SINTER set1 set2
# Объединение множеств
SUNION set1 set2
# Разность множеств
SDIFF set1 set2
# Сохранить результат в новом множестве
SINTERSTORE result set1 set2
```

### Утилиты для множеств: `SMOVE` / `SSCAN`

Расширенное манипулирование множествами и сканирование.

```redis
# Переместить элемент между множествами
SMOVE source_set dest_set "element"
# Инкрементное сканирование множества
SSCAN myset 0 MATCH "a*" COUNT 10
```

## Операции с хэшами

Хэши хранят пары поле-значение, похожие на мини-объекты JSON или словари.

### Базовые операции с хэшами: `HSET` / `HGET`

Установка и получение отдельных полей хэша.

```redis
# Установить поле хэша
HSET user:123 name "John Doe" age 30
# Получить поле хэша
HGET user:123 name
# Установить несколько полей
HMSET user:123 email "john@example.com" city "NYC"
# Получить несколько полей
HMGET user:123 name age email
```

### Просмотр хэша: `HKEYS` / `HVALS`

Проверка структуры и содержимого хэша.

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

### Утилиты для хэшей: `HEXISTS` / `HDEL`

Проверка существования и удаление полей хэша.

```redis
# Проверить существование поля
HEXISTS user:123 email
# Удалить поля
HDEL user:123 age city
# Увеличить поле хэша
HINCRBY user:123 age 1
# Увеличить на число с плавающей точкой
HINCRBYFLOAT user:123 balance 10.50
```

### Сканирование хэша: `HSCAN`

Инкрементная итерация по большим хэшам.

```redis
# Сканировать поля хэша
HSCAN user:123 0
# Сканировать с сопоставлением по шаблону
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## Операции с отсортированными множествами

Отсортированные множества сочетают уникальность множеств с упорядочиванием на основе баллов (scores).

### Базовые операции: `ZADD` / `ZRANGE`

Добавление членов с баллами и получение диапазонов.

```redis
# Добавить членов с баллами
ZADD leaderboard 100 "player1" 200 "player2"
# Получить членов по рангу (с 0-й индексацией)
ZRANGE leaderboard 0 -1
# Получить с баллами
ZRANGE leaderboard 0 -1 WITHSCORES
# Получить по диапазону баллов
ZRANGEBYSCORE leaderboard 100 200
```

### Информация об отсортированном множестве: `ZCARD` / `ZSCORE`

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
# Удалить по баллу
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

## Управление ключами

### Просмотр ключей: `KEYS` / `EXISTS`

Поиск ключей по шаблонам и проверка их существования.

```redis
# Получить все ключи (использовать осторожно в продакшене)
KEYS *
# Ключи с шаблоном
KEYS user:*
# Ключи, оканчивающиеся на шаблон
KEYS *:profile
# Одиночный подстановочный знак
KEYS order:?
# Проверить, существует ли ключ
EXISTS mykey
```

### Информация о ключе: `TYPE` / `TTL`

Получение метаданных ключа и информации об истечении срока действия.

```redis
# Получить тип данных ключа
TYPE mykey
# Получить время жизни (в секундах)
TTL mykey
# Получить TTL в миллисекундах
PTTL mykey
# Удалить срок действия
PERSIST mykey
```

### Операции с ключами: `RENAME` / `DEL`

Переименование, удаление и перемещение ключей.

```redis
# Переименовать ключ
RENAME oldkey newkey
# Переименовать, только если новый ключ не существует
RENAMENX oldkey newkey
# Удалить ключи
DEL key1 key2 key3
# Переместить ключ в другую базу данных
MOVE mykey 1
```

### Срок действия: `EXPIRE` / `EXPIREAT`

Установка времени истечения срока действия ключей.

```redis
# Установить срок действия в секундах
EXPIRE mykey 3600
# Установить срок действия в определенный момент времени (timestamp)
EXPIREAT mykey 1609459200
# Установить срок действия в миллисекундах
PEXPIRE mykey 60000
```

## Управление базами данных

### Выбор базы данных: `SELECT` / `FLUSHDB`

Управление несколькими базами данных в Redis.

```redis
# Выбрать базу данных (по умолчанию 0-15)
SELECT 0
# Очистить текущую базу данных
FLUSHDB
# Очистить все базы данных
FLUSHALL
# Получить размер текущей базы данных
DBSIZE
```

### Информация о сервере: `INFO` / `PING`

Получение статистики сервера и проверка подключения.

```redis
# Проверить соединение с сервером
PING
# Получить информацию о сервере
INFO
# Получить конкретный раздел информации
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
# Сохранение в фоновом режиме (неблокирующее)
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
# Получить конкретную конфигурацию
CONFIG GET maxmemory
# Установить конфигурацию
CONFIG SET timeout 300
# Сбросить статистику
CONFIG RESETSTAT
```

## Мониторинг производительности

### Мониторинг в реальном времени: `MONITOR` / `SLOWLOG`

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

### Анализ памяти: `MEMORY USAGE` / `MEMORY STATS`

Анализ потребления памяти и оптимизация.

```redis
# Получить использование памяти ключом
MEMORY USAGE mykey
# Получить статистику памяти
MEMORY STATS
# Получить отчет "врача" памяти
MEMORY DOCTOR
# Очистить память
MEMORY PURGE
```

### Информация о клиентах: `CLIENT LIST`

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

## Расширенные функции

### Транзакции: `MULTI` / `EXEC`

Атомарное выполнение нескольких команд.

```redis
# Начать транзакцию
MULTI
SET key1 "value1"
INCR counter
# Выполнить все команды
EXEC
# Отменить транзакцию
DISCARD
# Наблюдать за ключами на предмет изменений
WATCH mykey
```

### Pub/Sub: `PUBLISH` / `SUBSCRIBE`

Реализация обмена сообщениями между клиентами.

```redis
# Подписаться на канал
SUBSCRIBE news sports
# Опубликовать сообщение
PUBLISH news "Breaking: Redis 7.0 released!"
# Подписка по шаблону
PSUBSCRIBE news:*
# Отписаться
UNSUBSCRIBE news
```

### Скриптинг Lua: `EVAL` / `SCRIPT`

Атомарное выполнение пользовательских скриптов Lua.

```redis
# Выполнить скрипт Lua
EVAL "return redis.call('SET', 'key', 'value')" 0
# Загрузить скрипт и получить SHA
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# Выполнить по SHA
EVALSHA sha1 1 mykey
# Проверить существование скрипта
SCRIPT EXISTS sha1
```

### Потоки (Streams): `XADD` / `XREAD`

Работа с потоками Redis для данных типа журнала.

```redis
# Добавить запись в поток
XADD mystream * field1 value1 field2 value2
# Читать из потока
XREAD STREAMS mystream 0
# Получить длину потока
XLEN mystream
# Создать группу потребителей
XGROUP CREATE mystream mygroup 0
```

## Обзор типов данных

### Строки (Strings): Самый универсальный тип

Могут хранить текст, числа, JSON, двоичные данные. Максимальный размер: 512 МБ. Использовать для: кэширования, счетчиков, флагов.

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### Списки (Lists): Упорядоченные коллекции

Связные списки строк. Использовать для: очередей, стеков, лент активности, недавних элементов.

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### Множества (Sets): Уникальные коллекции

Неупорядоченные коллекции уникальных строк. Использовать для: тегов, уникальных посетителей, отношений.

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Советы по конфигурации Redis

### Управление памятью

Настройка лимитов памяти и политик вытеснения.

```redis
# Установить лимит памяти
CONFIG SET maxmemory 2gb
# Установить политику вытеснения
CONFIG SET maxmemory-policy allkeys-lru
# Проверить использование памяти
INFO memory
```

### Настройки персистентности

Настройка параметров надежности данных.

```redis
# Включить AOF
CONFIG SET appendonly yes
# Установить интервалы сохранения
CONFIG SET save "900 1 300 10 60 10000"
# Настройки перезаписи AOF
CONFIG SET auto-aof-rewrite-percentage 100
```

### Настройки безопасности

Базовые настройки безопасности для Redis.

```redis
# Установить пароль
CONFIG SET requirepass mypassword
# Аутентификация
AUTH mypassword
# Отключить опасные команды
CONFIG SET rename-command FLUSHALL ""
# Установить таймаут
CONFIG SET timeout 300
# TCP keep alive
CONFIG SET tcp-keepalive 60
# Максимальное количество клиентов
CONFIG SET maxclients 10000
```

### Настройка производительности

Оптимизация Redis для лучшей производительности.

```redis
# Включить конвейеризацию (pipelining) для нескольких команд
# Использовать пулинг соединений
# Настроить соответствующую политику maxmemory-policy
# Регулярно отслеживать медленные запросы
# Использовать подходящие структуры данных для сценариев использования
```

## Связанные ссылки

- <router-link to="/database">Шпаргалка по базам данных</router-link>
- <router-link to="/mysql">Шпаргалка по MySQL</router-link>
- <router-link to="/postgresql">Шпаргалка по PostgreSQL</router-link>
- <router-link to="/mongodb">Шпаргалка по MongoDB</router-link>
- <router-link to="/sqlite">Шпаргалка по SQLite</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>

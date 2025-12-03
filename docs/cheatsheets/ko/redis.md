---
title: 'Redis 치트 시트 | LabEx'
description: '포괄적인 치트 시트로 Redis 인메모리 데이터 저장소를 학습하세요. Redis 명령어, 데이터 구조, 캐싱, Pub/Sub, 영속성 및 고성능 캐싱 솔루션을 위한 빠른 참조 가이드입니다.'
pdfUrl: '/cheatsheets/pdf/redis-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Redis 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/redis">Hands-On 실습으로 Redis 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
실습 및 실제 시나리오를 통해 Redis 인메모리 데이터 구조 작업을 학습하세요. LabEx 는 필수 명령어, 데이터 구조, 캐싱 전략, pub/sub 메시징 및 성능 최적화를 다루는 포괄적인 Redis 과정을 제공합니다. 고성능 캐싱 및 실시간 데이터 처리를 마스터하세요.
</base-disclaimer-content>
</base-disclaimer>

## Redis 설치 및 설정

### Docker: `docker run redis`

로컬에서 Redis 를 실행하는 가장 빠른 방법입니다.

```bash
# Docker에서 Redis 실행
docker run --name my-redis -p 6379:6379 -d redis
# Redis CLI 연결
docker exec -it my-redis redis-cli
# 영구 저장소로 실행
docker run --name redis-persistent -p 6379:6379 -v redis-data:/data -d redis
```

### Linux: `sudo apt install redis`

Ubuntu/Debian 시스템에 Redis 서버를 설치합니다.

```bash
# Redis 설치
sudo apt update
sudo apt install redis-server
# Redis 서비스 시작
sudo systemctl start redis-server
# 부팅 시 자동 시작 활성화
sudo systemctl enable redis-server
# 상태 확인
sudo systemctl status redis
```

### 연결 및 테스트: `redis-cli`

Redis 서버에 연결하고 설치를 확인합니다.

```bash
# 로컬 Redis에 연결
redis-cli
# 연결 테스트
redis-cli PING
# 원격 Redis에 연결
redis-cli -h hostname -p 6379 -a password
# 단일 명령어 실행
redis-cli SET mykey "Hello Redis"
```

## 기본 문자열 작업

### 설정 및 가져오기: `SET` / `GET`

단순 값 (텍스트, 숫자, JSON 등) 을 저장합니다.

```redis
# 키-값 쌍 설정
SET mykey "Hello World"
# 값 가져오기
GET mykey
# 만료 시간 설정 (초 단위)
SET session:123 "user_data" EX 3600
# 키가 존재하지 않을 경우에만 설정
SET mykey "new_value" NX
```

<BaseQuiz id="redis-set-get-1" correct="C">
  <template #question>
    <code>SET mykey "value" EX 3600</code>은 무엇을 수행합니까?
  </template>
  
  <BaseQuizOption value="A">3600 바이트 값으로 키를 설정합니다</BaseQuizOption>
  <BaseQuizOption value="B">키가 존재할 경우에만 설정합니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>3600 초 후에 만료되는 값으로 키를 설정합니다</BaseQuizOption>
  <BaseQuizOption value="D">3600 개의 다른 값으로 키를 설정합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>EX</code> 옵션은 만료 시간을 초 단위로 설정합니다. <code>SET mykey "value" EX 3600</code>은 값을 저장하고 3600 초 (1 시간) 후에 자동으로 삭제합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 문자열 조작: `APPEND` / `STRLEN`

문자열 값을 수정하고 검사합니다.

```redis
# 기존 문자열에 추가
APPEND mykey " - Welcome!"
# 문자열 길이 가져오기
STRLEN mykey
# 부분 문자열 가져오기
GETRANGE mykey 0 4
# 부분 문자열 설정
SETRANGE mykey 6 "Redis"
```

### 숫자 작업: `INCR` / `DECR`

Redis 에 저장된 정수 값을 증가시키거나 감소시킵니다.

```redis
# 1씩 증가
INCR counter
# 1씩 감소
DECR counter
# 지정된 양만큼 증가
INCRBY counter 5
# 실수 증가
INCRBYFLOAT price 0.1
```

<BaseQuiz id="redis-incr-1" correct="A">
  <template #question>
    존재하지 않는 키에 <code>INCR</code> 을 사용하면 어떻게 됩니까?
  </template>
  
  <BaseQuizOption value="A" correct>Redis 는 키를 값 1 로 생성합니다</BaseQuizOption>
  <BaseQuizOption value="B">Redis 는 오류를 반환합니다</BaseQuizOption>
  <BaseQuizOption value="C">Redis 는 키를 값 0 으로 생성합니다</BaseQuizOption>
  <BaseQuizOption value="D">아무 일도 일어나지 않습니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    키가 존재하지 않으면 <code>INCR</code> 은 해당 키의 값이 0 이라고 간주하고 1 로 증가시킨 후 키를 생성합니다. 이로 인해 <code>INCR</code> 은 카운터를 초기화하는 데 유용합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 다중 작업: `MSET` / `MGET`

여러 키 - 값 쌍을 효율적으로 처리합니다.

```redis
# 여러 키를 한 번에 설정
MSET key1 "value1" key2 "value2" key3 "value3"
# 여러 값 가져오기
MGET key1 key2 key3
# 존재하지 않을 경우에만 여러 개 설정
MSETNX key1 "val1" key2 "val2"
```

## 리스트 작업

리스트는 문자열의 순서가 있는 시퀀스로, 큐 또는 스택으로 유용합니다.

### 요소 추가: `LPUSH` / `RPUSH`

리스트의 왼쪽 (머리) 또는 오른쪽 (꼬리) 에 요소를 추가합니다.

```redis
# 머리(왼쪽)에 추가
LPUSH mylist "first"
# 꼬리(오른쪽)에 추가
RPUSH mylist "last"
# 여러 요소 추가
LPUSH mylist "item1" "item2" "item3"
```

### 요소 제거: `LPOP` / `RPOP`

리스트 끝에서 요소를 제거하고 반환합니다.

```redis
# 머리에서 제거
LPOP mylist
# 꼬리에서 제거
RPOP mylist
# 블로킹 팝 (요소가 올 때까지 대기)
BLPOP mylist 10
```

### 요소 접근: `LRANGE` / `LINDEX`

리스트에서 요소 또는 범위를 검색합니다.

```redis
# 전체 리스트 가져오기
LRANGE mylist 0 -1
# 처음 3개 요소 가져오기
LRANGE mylist 0 2
# 인덱스로 특정 요소 가져오기
LINDEX mylist 0
# 리스트 길이 가져오기
LLEN mylist
```

<BaseQuiz id="redis-list-1" correct="B">
  <template #question>
    <code>LRANGE mylist 0 -1</code>은 무엇을 반환합니까?
  </template>
  
  <BaseQuizOption value="A">첫 번째 요소만</BaseQuizOption>
  <BaseQuizOption value="B" correct>리스트의 모든 요소</BaseQuizOption>
  <BaseQuizOption value="C">마지막 요소만</BaseQuizOption>
  <BaseQuizOption value="D">오류</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>0 -1</code>을 사용한 <code>LRANGE</code> 는 리스트의 모든 요소를 반환합니다. <code>0</code> 은 시작 인덱스이고 <code>-1</code> 은 마지막 요소를 나타내므로 첫 번째 요소부터 마지막 요소까지 모두 검색합니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 리스트 유틸리티: `LSET` / `LTRIM`

리스트 내용을 수정하고 구조를 변경합니다.

```redis
# 인덱스에 요소 설정
LSET mylist 0 "new_value"
# 리스트를 범위로 자르기
LTRIM mylist 0 99
# 요소 위치 찾기
LPOS mylist "search_value"
```

## 집합 (Set) 작업

집합은 고유하고 순서가 없는 문자열 요소들의 모음입니다.

### 기본 집합 작업: `SADD` / `SMEMBERS`

집합에 고유한 요소를 추가하고 모든 멤버를 검색합니다.

```redis
# 집합에 요소 추가
SADD myset "apple" "banana" "cherry"
# 모든 집합 멤버 가져오기
SMEMBERS myset
# 요소 존재 여부 확인
SISMEMBER myset "apple"
```

<BaseQuiz id="redis-set-1" correct="C">
  <template #question>
    Redis 집합에 중복 요소를 추가하려고 하면 어떻게 됩니까?
  </template>
  
  <BaseQuizOption value="A">오류가 발생합니다</BaseQuizOption>
  <BaseQuizOption value="B">기존 요소를 덮어씁니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>중복은 무시되며 집합은 변경되지 않습니다</BaseQuizOption>
  <BaseQuizOption value="D">리스트를 생성합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    Redis 집합은 고유한 요소만 포함합니다. 이미 존재하는 요소를 추가하려고 하면 Redis 는 이를 무시하고 0(추가된 요소가 없음을 나타냄) 을 반환합니다. 집합은 변경되지 않습니다.
  </BaseQuizAnswer>
</BaseQuiz>
# 집합 크기 가져오기
SCARD myset
```

### 집합 수정: `SREM` / `SPOP`

다양한 방식으로 집합에서 요소를 제거합니다.

```redis
# 특정 요소 제거
SREM myset "banana"
# 임의의 요소 제거 및 반환
SPOP myset
# 제거하지 않고 임의의 요소 가져오기
SRANDMEMBER myset
```

### 집합 연산: `SINTER` / `SUNION`

수학적 집합 연산을 수행합니다.

```redis
# 집합의 교집합
SINTER set1 set2
# 집합의 합집합
SUNION set1 set2
# 집합의 차집합
SDIFF set1 set2
# 결과를 새 집합에 저장
SINTERSTORE result set1 set2
```

### 집합 유틸리티: `SMOVE` / `SSCAN`

고급 집합 조작 및 스캐닝.

```redis
# 집합 간 요소 이동
SMOVE source_set dest_set "element"
# 증분적으로 집합 스캔
SSCAN myset 0 MATCH "a*" COUNT 10
```

## 해시(Hash) 작업

해시는 필드-값 쌍을 저장하며, 미니 JSON 객체 또는 딕셔너리와 유사합니다.

### 기본 해시 작업: `HSET` / `HGET`

개별 해시 필드를 설정하고 검색합니다.

```redis
# 해시 필드 설정
HSET user:123 name "John Doe" age 30
# 해시 필드 가져오기
HGET user:123 name
# 여러 필드 설정
HMSET user:123 email "john@example.com" city "NYC"
# 여러 필드 가져오기
HMGET user:123 name age email
```

### 해시 검사: `HKEYS` / `HVALS`

해시 구조와 내용을 검사합니다.

```redis
# 모든 필드 이름 가져오기
HKEYS user:123
# 모든 값 가져오기
HVALS user:123
# 모든 필드와 값 가져오기
HGETALL user:123
# 필드 개수 가져오기
HLEN user:123
```

### 해시 유틸리티: `HEXISTS` / `HDEL`

존재 여부를 확인하고 해시 필드를 제거합니다.

```redis
# 필드 존재 여부 확인
HEXISTS user:123 email
# 필드 삭제
HDEL user:123 age city
# 해시 필드 증가
HINCRBY user:123 age 1
# 실수만큼 증가
HINCRBYFLOAT user:123 balance 10.50
```

### 해시 스캐닝: `HSCAN`

대규모 해시를 점진적으로 반복합니다.

```redis
# 해시 필드 스캔
HSCAN user:123 0
# 패턴 일치로 스캔
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## 정렬된 집합(Sorted Set) 작업

정렬된 집합은 점수를 기반으로 한 순서 지정 기능과 집합의 고유성을 결합합니다.

### 기본 작업: `ZADD` / `ZRANGE`

점수가 매겨진 멤버를 추가하고 범위를 검색합니다.

```redis
# 점수와 함께 멤버 추가
ZADD leaderboard 100 "player1" 200 "player2"
# 순위 (0 부터 시작) 별 멤버 가져오기
ZRANGE leaderboard 0 -1
# 점수 포함하여 가져오기
ZRANGE leaderboard 0 -1 WITHSCORES
# 점수 범위별 가져오기
ZRANGEBYSCORE leaderboard 100 200
```

### 정렬된 집합 정보: `ZCARD` / `ZSCORE`

정렬된 집합 멤버에 대한 정보를 가져옵니다.

```redis
# 집합 크기 가져오기
ZCARD leaderboard
# 멤버 점수 가져오기
ZSCORE leaderboard "player1"
# 멤버 순위 가져오기
ZRANK leaderboard "player1"
# 점수 범위 내 멤버 수 계산
ZCOUNT leaderboard 100 200
```

### 수정: `ZREM` / `ZINCRBY`

멤버를 제거하고 점수를 수정합니다.

```redis
# 멤버 제거
ZREM leaderboard "player1"
# 멤버 점수 증가
ZINCRBY leaderboard 10 "player2"
# 순위별 범위 제거
ZREMRANGEBYRANK leaderboard 0 2
# 점수별 범위 제거
ZREMRANGEBYSCORE leaderboard 0 100
```

### 고급: `ZUNIONSTORE` / `ZINTERSTORE`

여러 정렬된 집합을 결합합니다.

```redis
# 정렬된 집합의 합집합
ZUNIONSTORE result 2 set1 set2
# 가중치를 사용한 교집합
ZINTERSTORE result 2 set1 set2 WEIGHTS 1 2
# 집계 함수 사용
ZUNIONSTORE result 2 set1 set2 AGGREGATE MAX
```

## 키 관리

### 키 검사: `KEYS` / `EXISTS`

패턴을 사용하여 키를 찾고 존재 여부를 확인합니다.

```redis
# 모든 키 가져오기 (프로덕션에서 주의해서 사용)
KEYS *
# 패턴이 있는 키
KEYS user:*
# 패턴으로 끝나는 키
KEYS *:profile
# 단일 문자 와일드카드
KEYS order:?
# 키 존재 여부 확인
EXISTS mykey
```

### 키 정보: `TYPE` / `TTL`

키 메타데이터 및 만료 정보를 가져옵니다.

```redis
# 키 데이터 유형 가져오기
TYPE mykey
# 남은 수명 (초) 가져오기
TTL mykey
# 남은 수명 (밀리초) 가져오기
PTTL mykey
# 만료 제거
PERSIST mykey
```

### 키 작업: `RENAME` / `DEL`

키의 이름을 바꾸고, 삭제하고, 이동합니다.

```redis
# 키 이름 변경
RENAME oldkey newkey
# 새 키가 존재하지 않을 경우에만 이름 변경
RENAMENX oldkey newkey
# 키 삭제
DEL key1 key2 key3
# 키를 다른 데이터베이스로 이동
MOVE mykey 1
```

### 만료: `EXPIRE` / `EXPIREAT`

키 만료 시간을 설정합니다.

```redis
# 초 단위로 만료 설정
EXPIRE mykey 3600
# 특정 타임스탬프에 만료 설정
EXPIREAT mykey 1609459200
# 밀리초 단위로 만료 설정
PEXPIRE mykey 60000
```

## 데이터베이스 관리

### 데이터베이스 선택: `SELECT` / `FLUSHDB`

Redis 내에서 여러 데이터베이스를 관리합니다.

```redis
# 데이터베이스 선택 (기본값 0-15)
SELECT 0
# 현재 데이터베이스 비우기
FLUSHDB
# 모든 데이터베이스 비우기
FLUSHALL
# 현재 데이터베이스 크기 가져오기
DBSIZE
```

### 서버 정보: `INFO` / `PING`

서버 통계를 가져오고 연결을 테스트합니다.

```redis
# 서버 연결 테스트
PING
# 서버 정보 가져오기
INFO
# 특정 정보 섹션 가져오기
INFO memory
INFO replication
# 서버 시간 가져오기
TIME
```

### 영속성: `SAVE` / `BGSAVE`

Redis 데이터 영속성 및 백업을 제어합니다.

```redis
# 동기식 저장 (서버 차단)
SAVE
# 백그라운드 저장 (비차단)
BGSAVE
# 마지막 저장 시간 가져오기
LASTSAVE
# AOF 파일 재작성
BGREWRITEAOF
```

### 구성: `CONFIG GET` / `CONFIG SET`

Redis 구성을 보고 수정합니다.

```redis
# 모든 구성 가져오기
CONFIG GET *
# 특정 구성 가져오기
CONFIG GET maxmemory
# 구성 설정
CONFIG SET timeout 300
# 통계 재설정
CONFIG RESETSTAT
```

## 성능 모니터링

### 실시간 모니터링: `MONITOR` / `SLOWLOG`

명령어를 추적하고 성능 병목 현상을 식별합니다.

```redis
# 실시간으로 모든 명령어 모니터링
MONITOR
# 느린 쿼리 로그 가져오기
SLOWLOG GET 10
# 느린 로그 길이 가져오기
SLOWLOG LEN
# 느린 로그 재설정
SLOWLOG RESET
```

### 메모리 분석: `MEMORY USAGE` / `MEMORY STATS`

메모리 소비 및 최적화를 분석합니다.

```redis
# 키 메모리 사용량 가져오기
MEMORY USAGE mykey
# 메모리 통계 가져오기
MEMORY STATS
# 메모리 닥터 보고서 가져오기
MEMORY DOCTOR
# 메모리 비우기
MEMORY PURGE
```

### 클라이언트 정보: `CLIENT LIST`

연결된 클라이언트 및 연결을 모니터링합니다.

```redis
# 모든 클라이언트 목록 보기
CLIENT LIST
# 클라이언트 정보 가져오기
CLIENT INFO
# 클라이언트 연결 종료
CLIENT KILL ip:port
# 클라이언트 이름 설정
CLIENT SETNAME "my-app"
```

### 벤치마킹: `redis-benchmark`

내장 벤치마크 도구로 Redis 성능을 테스트합니다.

```bash
# 기본 벤치마크
redis-benchmark
# 특정 작업
redis-benchmark -t SET,GET -n 100000
# 사용자 정의 페이로드 크기
redis-benchmark -d 1024 -t SET -n 10000
```

## 고급 기능

### 트랜잭션: `MULTI` / `EXEC`

여러 명령어를 원자적으로 실행합니다.

```redis
# 트랜잭션 시작
MULTI
SET key1 "value1"
INCR counter
# 모든 명령어 실행
EXEC
# 트랜잭션 취소
DISCARD
# 변경 사항 감시
WATCH mykey
```

### Pub/Sub: `PUBLISH` / `SUBSCRIBE`

클라이언트 간의 메시지 전달을 구현합니다.

```redis
# 채널 구독
SUBSCRIBE news sports
# 메시지 게시
PUBLISH news "Breaking: Redis 7.0 released!"
# 패턴 구독
PSUBSCRIBE news:*
# 구독 취소
UNSUBSCRIBE news
```

### Lua 스크립팅: `EVAL` / `SCRIPT`

원자적으로 사용자 지정 Lua 스크립트를 실행합니다.

```redis
# Lua 스크립트 실행
EVAL "return redis.call('SET', 'key', 'value')" 0
# 스크립트 로드 및 SHA 가져오기
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# SHA 로 실행
EVALSHA sha1 1 mykey
# 스크립트 존재 여부 확인
SCRIPT EXISTS sha1
```

### 스트림: `XADD` / `XREAD`

로그와 같은 데이터 처리를 위해 Redis 스트림을 사용합니다.

```redis
# 스트림에 항목 추가
XADD mystream * field1 value1 field2 value2
# 스트림에서 읽기
XREAD STREAMS mystream 0
# 스트림 길이 가져오기
XLEN mystream
# 소비자 그룹 생성
XGROUP CREATE mystream mygroup 0
```

## 데이터 유형 개요

### 문자열(Strings): 가장 다재다능한 유형

텍스트, 숫자, JSON, 바이너리 데이터를 저장할 수 있습니다. 최대 크기: 512MB. 용도: 캐싱, 카운터, 플래그.

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### 리스트(Lists): 순서가 있는 컬렉션

문자열의 연결 리스트입니다. 용도: 큐, 스택, 활동 피드, 최근 항목.

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### 집합(Sets): 고유한 컬렉션

고유한 문자열의 순서 없는 모음입니다. 용도: 태그, 고유 방문자, 관계.

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Redis 구성 팁

### 메모리 관리

메모리 제한 및 제거 정책을 구성합니다.

```redis
# 메모리 제한 설정
CONFIG SET maxmemory 2gb
# 제거 정책 설정
CONFIG SET maxmemory-policy allkeys-lru
# 메모리 사용량 확인
INFO memory
```

### 영속성 설정

데이터 내구성 옵션을 구성합니다.

```redis
# AOF 활성화
CONFIG SET appendonly yes
# 저장 간격 설정
CONFIG SET save "900 1 300 10 60 10000"
# AOF 재작성 설정
CONFIG SET auto-aof-rewrite-percentage 100
```

### 보안 설정

Redis를 위한 기본 보안 구성입니다.

```redis
# 비밀번호 설정
CONFIG SET requirepass mypassword
# 인증
AUTH mypassword
# 위험한 명령어 비활성화
CONFIG SET rename-command FLUSHALL ""
# 타임아웃 설정
CONFIG SET timeout 300
# TCP keep alive
CONFIG SET tcp-keepalive 60
# 최대 클라이언트 수
CONFIG SET maxclients 10000
```

### 성능 튜닝

더 나은 성능을 위해 Redis를 최적화합니다.

```redis
# 여러 명령어를 위한 파이프라이닝 활성화
# 연결 풀링 사용
# 사용 사례에 적합한 maxmemory-policy 구성
# 정기적으로 느린 쿼리 모니터링
# 사용 사례에 적합한 데이터 구조 사용
```

## 관련 링크

- <router-link to="/database">데이터베이스 치트 시트</router-link>
- <router-link to="/mysql">MySQL 치트 시트</router-link>
- <router-link to="/postgresql">PostgreSQL 치트 시트</router-link>
- <router-link to="/mongodb">MongoDB 치트 시트</router-link>
- <router-link to="/sqlite">SQLite 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>

---
title: 'Redis 速查表 | LabEx'
description: '使用本综合速查表学习 Redis 内存数据存储。Redis 命令、数据结构、缓存、发布/订阅、持久化和高性能缓存解决方案的快速参考。'
pdfUrl: '/cheatsheets/pdf/redis-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Redis 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/redis">通过实践实验室学习 Redis</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 Redis in-memory 数据结构操作。LabEx 提供全面的 Redis 课程，涵盖基本命令、数据结构、缓存策略、pub/sub 消息传递和性能优化。掌握高性能缓存和实时数据处理。
</base-disclaimer-content>
</base-disclaimer>

## Redis 安装与设置

### Docker: `docker run redis`

在本地快速运行 Redis 的方法。

```bash
# 在 Docker 中运行 Redis
docker run --name my-redis -p 6379:6379 -d redis
# 连接到 Redis CLI
docker exec -it my-redis redis-cli
# 使用持久化存储运行
docker run --name redis-persistent -p 6379:6379 -v redis-data:/data -d redis
```

### Linux: `sudo apt install redis`

在 Ubuntu/Debian 系统上安装 Redis 服务器。

```bash
# 安装 Redis
sudo apt update
sudo apt install redis-server
# 启动 Redis 服务
sudo systemctl start redis-server
# 启用启动时自动启动
sudo systemctl enable redis-server
# 检查状态
sudo systemctl status redis
```

### 连接与测试：`redis-cli`

连接到 Redis 服务器并验证安装。

```bash
# 连接到本地 Redis
redis-cli
# 测试连接
redis-cli PING
# 连接到远程 Redis
redis-cli -h hostname -p 6379 -a password
# 执行单个命令
redis-cli SET mykey "Hello Redis"
```

## 基本字符串操作

### 设置与获取：`SET` / `GET`

存储简单值（文本、数字、JSON 等）。

```redis
# 设置键值对
SET mykey "Hello World"
# 按键获取值
GET mykey
# 设置带过期时间（秒）
SET session:123 "user_data" EX 3600
# 仅在键不存在时设置
SET mykey "new_value" NX
```

<BaseQuiz id="redis-set-get-1" correct="C">
  <template #question>
    <code>SET mykey "value" EX 3600</code> 执行什么操作？
  </template>
  
  <BaseQuizOption value="A">以 3600 字节的值设置键</BaseQuizOption>
  <BaseQuizOption value="B">仅在键存在时设置</BaseQuizOption>
  <BaseQuizOption value="C" correct>设置键的值，并在 3600 秒后过期</BaseQuizOption>
  <BaseQuizOption value="D">用 3600 个不同的值设置键</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>EX</code> 选项以秒为单位设置过期时间。<code>SET mykey "value" EX 3600</code> 存储该值并在 3600 秒（1 小时）后自动删除它。
  </BaseQuizAnswer>
</BaseQuiz>

### 字符串操作：`APPEND` / `STRLEN`

修改和检查字符串值。

```redis
# 追加到现有字符串
APPEND mykey " - Welcome!"
# 获取字符串长度
STRLEN mykey
# 获取子字符串
GETRANGE mykey 0 4
# 设置子字符串
SETRANGE mykey 6 "Redis"
```

### 数字操作：`INCR` / `DECR`

递增或递减存储在 Redis 中的整数值。

```redis
# 递增 1
INCR counter
# 递减 1
DECR counter
# 按指定量递增
INCRBY counter 5
# 浮点数递增
INCRBYFLOAT price 0.1
```

<BaseQuiz id="redis-incr-1" correct="A">
  <template #question>
    如果对一个不存在的键使用 <code>INCR</code> 会发生什么？
  </template>
  
  <BaseQuizOption value="A" correct>Redis 创建该键，值为 1</BaseQuizOption>
  <BaseQuizOption value="B">Redis 返回一个错误</BaseQuizOption>
  <BaseQuizOption value="C">Redis 创建该键，值为 0</BaseQuizOption>
  <BaseQuizOption value="D">什么也不发生</BaseQuizOption>
  
  <BaseQuizAnswer>
    如果键不存在，<code>INCR</code> 会将其视为值为 0，递增到 1，并创建该键。这使得 <code>INCR</code> 对初始化计数器非常有用。
  </BaseQuizAnswer>
</BaseQuiz>

### 多个操作：`MSET` / `MGET`

高效地处理多个键值对。

```redis
# 一次设置多个键
MSET key1 "value1" key2 "value2" key3 "value3"
# 获取多个值
MGET key1 key2 key3
# 仅在所有键都不存在时设置多个
MSETNX key1 "val1" key2 "val2"
```

## 列表操作

列表是字符串的有序序列，可用作队列或堆栈。

### 添加元素：`LPUSH` / `RPUSH`

将元素添加到列表的左侧（头部）或右侧（尾部）。

```redis
# 添加到头部（左侧）
LPUSH mylist "first"
# 添加到尾部（右侧）
RPUSH mylist "last"
# 添加多个元素
LPUSH mylist "item1" "item2" "item3"
```

### 移除元素：`LPOP` / `RPOP`

从列表末端移除并返回元素。

```redis
# 从头部移除
LPOP mylist
# 从尾部移除
RPOP mylist
# 阻塞式弹出（等待元素出现）
BLPOP mylist 10
```

### 访问元素：`LRANGE` / `LINDEX`

检索列表中的元素或范围。

```redis
# 获取整个列表
LRANGE mylist 0 -1
# 获取前 3 个元素
LRANGE mylist 0 2
# 按索引获取特定元素
LINDEX mylist 0
# 获取列表长度
LLEN mylist
```

<BaseQuiz id="redis-list-1" correct="B">
  <template #question>
    <code>LRANGE mylist 0 -1</code> 返回什么？
  </template>
  
  <BaseQuizOption value="A">仅第一个元素</BaseQuizOption>
  <BaseQuizOption value="B" correct>列表中的所有元素</BaseQuizOption>
  <BaseQuizOption value="C">仅最后一个元素</BaseQuizOption>
  <BaseQuizOption value="D">一个错误</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>LRANGE</code> 使用 <code>0 -1</code> 返回列表中的所有元素。<code>0</code> 是起始索引，<code>-1</code> 代表最后一个元素，因此检索从第一个到最后一个的所有内容。
  </BaseQuizAnswer>
</BaseQuiz>

### 列表工具：`LSET` / `LTRIM`

修改列表内容和结构。

```redis
# 设置指定索引的元素
LSET mylist 0 "new_value"
# 修剪列表到指定范围
LTRIM mylist 0 99
# 查找元素位置
LPOS mylist "search_value"
```

## 集合操作

集合是唯一的、无序的字符串元素集合。

### 基本集合操作：`SADD` / `SMEMBERS`

向集合中添加唯一元素并检索所有成员。

```redis
# 向集合中添加元素
SADD myset "apple" "banana" "cherry"
# 获取所有集合成员
SMEMBERS myset
# 检查元素是否存在
SISMEMBER myset "apple"
```

<BaseQuiz id="redis-set-1" correct="C">
  <template #question>
    尝试向 Redis 集合中添加重复元素时会发生什么？
  </template>
  
  <BaseQuizOption value="A">会产生一个错误</BaseQuizOption>
  <BaseQuizOption value="B">会替换现有元素</BaseQuizOption>
  <BaseQuizOption value="C" correct>重复项被忽略，集合保持不变</BaseQuizOption>
  <BaseQuizOption value="D">会创建一个列表</BaseQuizOption>
  
  <BaseQuizAnswer>
    Redis 集合只包含唯一元素。如果尝试添加已存在的元素，Redis 会忽略它并返回 0（表示没有元素被添加）。集合保持不变。
  </BaseQuizAnswer>
</BaseQuiz>
# 获取集合大小
SCARD myset
```

### 集合修改: `SREM` / `SPOP`

以不同方式从集合中移除元素。

```redis
# 移除特定元素
SREM myset "banana"
# 移除并返回一个随机元素
SPOP myset
# 不移除地获取一个随机元素
SRANDMEMBER myset
```

### 集合运算: `SINTER` / `SUNION`

执行数学集合运算。

```redis
# 集合的交集
SINTER set1 set2
# 集合的并集
SUNION set1 set2
# 集合的差集
SDIFF set1 set2
# 存储结果到新集合
SINTERSTORE result set1 set2
```

### 集合工具: `SMOVE` / `SSCAN`

高级集合操作和增量扫描。

```redis
# 在集合间移动元素
SMOVE source_set dest_set "element"
# 增量扫描集合
SSCAN myset 0 MATCH "a*" COUNT 10
```

## 哈希操作

哈希存储字段-值对，类似于迷你 JSON 对象或字典。

### 基本哈希操作: `HSET` / `HGET`

设置和检索单个哈希字段。

```redis
# 设置哈希字段
HSET user:123 name "John Doe" age 30
# 获取哈希字段
HGET user:123 name
# 设置多个字段
HMSET user:123 email "john@example.com" city "NYC"
# 获取多个字段
HMGET user:123 name age email
```

### 哈希检查: `HKEYS` / `HVALS`

检查哈希结构和内容。

```redis
# 获取所有字段名
HKEYS user:123
# 获取所有值
HVALS user:123
# 获取所有字段和值
HGETALL user:123
# 获取字段数量
HLEN user:123
```

### 哈希工具: `HEXISTS` / `HDEL`

检查存在性和移除哈希字段。

```redis
# 检查字段是否存在
HEXISTS user:123 email
# 删除字段
HDEL user:123 age city
# 递增哈希字段
HINCRBY user:123 age 1
# 浮点数递增
HINCRBYFLOAT user:123 balance 10.50
```

### 哈希扫描: `HSCAN`

增量迭代大型哈希。

```redis
# 扫描哈希字段
HSCAN user:123 0
# 带模式匹配的扫描
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## 有序集合操作

有序集合结合了集合的唯一性和基于分数的排序。

### 基本操作: `ZADD` / `ZRANGE`

添加带分数的成员并检索范围。

```redis
# 添加带分数的成员
ZADD leaderboard 100 "player1" 200 "player2"
# 按排名获取成员 (0-based)
ZRANGE leaderboard 0 -1
# 获取带分数的成员
ZRANGE leaderboard 0 -1 WITHSCORES
# 按分数范围获取
ZRANGEBYSCORE leaderboard 100 200
```

### 有序集合信息: `ZCARD` / `ZSCORE`

获取有序集合成员的信息。

```redis
# 获取集合大小
ZCARD leaderboard
# 获取成员分数
ZSCORE leaderboard "player1"
# 获取成员排名
ZRANK leaderboard "player1"
# 计算分数范围内的成员数
ZCOUNT leaderboard 100 200
```

### 修改: `ZREM` / `ZINCRBY`

移除成员和修改分数。

```redis
# 移除成员
ZREM leaderboard "player1"
# 增加成员分数
ZINCRBY leaderboard 10 "player2"
# 按排名范围移除
ZREMRANGEBYRANK leaderboard 0 2
# 按分数范围移除
ZREMRANGEBYSCORE leaderboard 0 100
```

### 高级操作: `ZUNIONSTORE` / `ZINTERSTORE`

合并多个有序集合。

```redis
# 有序集合的并集
ZUNIONSTORE result 2 set1 set2
# 带权重的交集
ZINTERSTORE result 2 set1 set2 WEIGHTS 1 2
# 带聚合函数的并集
ZUNIONSTORE result 2 set1 set2 AGGREGATE MAX
```

## 键管理

### 键检查: `KEYS` / `EXISTS`

使用模式查找键并检查存在性。

```redis
# 获取所有键（生产环境谨慎使用）
KEYS *
# 带模式的键
KEYS user:*
# 以特定模式结尾的键
KEYS *:profile
# 单字符通配符
KEYS order:?
# 检查键是否存在
EXISTS mykey
```

### 键信息: `TYPE` / `TTL`

获取键的元数据和过期信息。

```redis
# 获取键的数据类型
TYPE mykey
# 获取剩余生存时间（秒）
TTL mykey
# 获取剩余生存时间（毫秒）
PTTL mykey
# 移除过期时间
PERSIST mykey
```

### 键操作: `RENAME` / `DEL`

重命名、删除和移动键。

```redis
# 重命名键
RENAME oldkey newkey
# 仅在新键不存在时重命名
RENAMENX oldkey newkey
# 删除键
DEL key1 key2 key3
# 将键移动到不同数据库
MOVE mykey 1
```

### 过期时间: `EXPIRE` / `EXPIREAT`

设置键的过期时间。

```redis
# 设置以秒为单位的过期时间
EXPIRE mykey 3600
# 设置在特定时间戳过期
EXPIREAT mykey 1609459200
# 设置以毫秒为单位的过期时间
PEXPIRE mykey 60000
```

## 数据库管理

### 数据库选择: `SELECT` / `FLUSHDB`

管理 Redis 中的多个数据库。

```redis
# 选择数据库 (默认 0-15)
SELECT 0
# 清空当前数据库
FLUSHDB
# 清空所有数据库
FLUSHALL
# 获取当前数据库大小
DBSIZE
```

### 服务器信息: `INFO` / `PING`

获取服务器统计信息并测试连接性。

```redis
# 测试服务器连接
PING
# 获取服务器信息
INFO
# 获取特定信息部分
INFO memory
INFO replication
# 获取服务器时间
TIME
```

### 持久化: `SAVE` / `BGSAVE`

控制 Redis 数据持久化和备份。

```redis
# 同步保存（阻塞服务器）
SAVE
# 后台保存（非阻塞）
BGSAVE
# 获取上次保存时间
LASTSAVE
# 重写 AOF 文件
BGREWRITEAOF
```

### 配置: `CONFIG GET` / `CONFIG SET`

查看和修改 Redis 配置。

```redis
# 获取所有配置
CONFIG GET *
# 获取特定配置
CONFIG GET maxmemory
# 设置配置
CONFIG SET timeout 300
# 重置统计信息
CONFIG RESETSTAT
```

## 性能监控

### 实时监控: `MONITOR` / `SLOWLOG`

跟踪命令并识别性能瓶颈。

```redis
# 实时监控所有命令
MONITOR
# 获取慢查询日志
SLOWLOG GET 10
# 获取慢日志长度
SLOWLOG LEN
# 重置慢日志
SLOWLOG RESET
```

### 内存分析: `MEMORY USAGE` / `MEMORY STATS`

分析内存消耗和优化。

```redis
# 获取键的内存使用情况
MEMORY USAGE mykey
# 获取内存统计信息
MEMORY STATS
# 获取内存医生报告
MEMORY DOCTOR
# 释放内存
MEMORY PURGE
```

### 客户端信息: `CLIENT LIST`

监控连接的客户端和连接。

```redis
# 列出所有客户端
CLIENT LIST
# 获取客户端信息
CLIENT INFO
# 杀死客户端连接
CLIENT KILL ip:port
# 设置客户端名称
CLIENT SETNAME "my-app"
```

### 基准测试: `redis-benchmark`

使用内置基准测试工具测试 Redis 性能。

```bash
# 基本基准测试
redis-benchmark
# 特定操作
redis-benchmark -t SET,GET -n 100000
# 自定义负载大小
redis-benchmark -d 1024 -t SET -n 10000
```

## 高级特性

### 事务: `MULTI` / `EXEC`

原子性地执行多个命令。

```redis
# 开始事务
MULTI
SET key1 "value1"
INCR counter
# 执行所有命令
EXEC
# 放弃事务
DISCARD
# 监视键的变化
WATCH mykey
```

### 发布/订阅: `PUBLISH` / `SUBSCRIBE`

在客户端之间实现消息传递。

```redis
# 订阅频道
SUBSCRIBE news sports
# 发布消息
PUBLISH news "Breaking: Redis 7.0 released!"
# 模式订阅
PSUBSCRIBE news:*
# 取消订阅
UNSUBSCRIBE news
```

### Lua 脚本: `EVAL` / `SCRIPT`

原子性地执行自定义 Lua 脚本。

```redis
# 执行 Lua 脚本
EVAL "return redis.call('SET', 'key', 'value')" 0
# 加载脚本并获取 SHA
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# 通过 SHA 执行
EVALSHA sha1 1 mykey
# 检查脚本是否存在
SCRIPT EXISTS sha1
```

### 流: `XADD` / `XREAD`

处理类似日志的 Redis 流数据。

```redis
# 向流中添加条目
XADD mystream * field1 value1 field2 value2
# 从流中读取
XREAD STREAMS mystream 0
# 获取流长度
XLEN mystream
# 创建消费者组
XGROUP CREATE mystream mygroup 0
```

## 数据类型概述

### 字符串 (Strings): 最通用的类型

可以存储文本、数字、JSON、二进制数据。最大尺寸：512MB。用途：缓存、计数器、标志。

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### 列表 (Lists): 有序集合

字符串的链表。用途：队列、堆栈、活动信息流、最近项目。

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### 集合 (Sets): 唯一集合

唯一的字符串集合，无序。用途：标签、唯一访客、关系。

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Redis 配置提示

### 内存管理

配置内存限制和驱逐策略。

```redis
# 设置内存限制
CONFIG SET maxmemory 2gb
# 设置驱逐策略
CONFIG SET maxmemory-policy allkeys-lru
# 检查内存使用情况
INFO memory
```

### 持久化设置

配置数据持久性选项。

```redis
# 启用 AOF
CONFIG SET appendonly yes
# 设置保存时间间隔
CONFIG SET save "900 1 300 10 60 10000"
# AOF 重写设置
CONFIG SET auto-aof-rewrite-percentage 100
```

### 安全设置

Redis 的基本安全配置。

```redis
# 设置密码
CONFIG SET requirepass mypassword
# 认证
AUTH mypassword
# 禁用危险命令
CONFIG SET rename-command FLUSHALL ""
# 设置超时时间
CONFIG SET timeout 300
# TCP keep alive
CONFIG SET tcp-keepalive 60
# 最大客户端数
CONFIG SET maxclients 10000
```

### 性能调优

优化 Redis 以获得更好的性能。

```redis
# 为多个命令启用管道 (pipelining)
# 使用连接池
# 为用例配置适当的 maxmemory-policy
# 定期监控慢查询
# 为用例使用适当的数据结构
```

## 相关链接

- <router-link to="/database">数据库速查表</router-link>
- <router-link to="/mysql">MySQL 速查表</router-link>
- <router-link to="/postgresql">PostgreSQL 速查表</router-link>
- <router-link to="/mongodb">MongoDB 速查表</router-link>
- <router-link to="/sqlite">SQLite 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>

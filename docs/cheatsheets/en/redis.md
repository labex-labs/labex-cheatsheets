---
title: 'Redis Cheatsheet | LabEx'
description: 'Learn Redis in-memory data store with this comprehensive cheatsheet. Quick reference for Redis commands, data structures, caching, pub/sub, persistence, and high-performance caching solutions.'
pdfUrl: '/cheatsheets/pdf/redis-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Redis Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/redis">Learn Redis with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn Redis in-memory data structure operations through hands-on labs and real-world scenarios. LabEx provides comprehensive Redis courses covering essential commands, data structures, caching strategies, pub/sub messaging, and performance optimization. Master high-performance caching and real-time data processing.
</base-disclaimer-content>
</base-disclaimer>

## Redis Installation & Setup

### Docker: `docker run redis`

Quickest way to get Redis running locally.

```bash
# Run Redis in Docker
docker run --name my-redis -p 6379:6379 -d redis
# Connect to Redis CLI
docker exec -it my-redis redis-cli
# Run with persistent storage
docker run --name redis-persistent -p 6379:6379 -v redis-data:/data -d redis
```

### Linux: `sudo apt install redis`

Install Redis server on Ubuntu/Debian systems.

```bash
# Install Redis
sudo apt update
sudo apt install redis-server
# Start Redis service
sudo systemctl start redis-server
# Enable auto-start on boot
sudo systemctl enable redis-server
# Check status
sudo systemctl status redis
```

### Connect & Test: `redis-cli`

Connect to Redis server and verify installation.

```bash
# Connect to local Redis
redis-cli
# Test connection
redis-cli PING
# Connect to remote Redis
redis-cli -h hostname -p 6379 -a password
# Execute single command
redis-cli SET mykey "Hello Redis"
```

## Basic String Operations

### Set & Get: `SET` / `GET`

Store simple values (text, numbers, JSON, etc.).

```redis
# Set a key-value pair
SET mykey "Hello World"
# Get value by key
GET mykey
# Set with expiration (in seconds)
SET session:123 "user_data" EX 3600
# Set only if key doesn't exist
SET mykey "new_value" NX
```

<BaseQuiz id="redis-set-get-1" correct="C">
  <template #question>
    What does `SET mykey "value" EX 3600` do?
  </template>
  
  <BaseQuizOption value="A">Sets the key with a 3600-byte value</BaseQuizOption>
  <BaseQuizOption value="B">Sets the key only if it exists</BaseQuizOption>
  <BaseQuizOption value="C" correct>Sets the key with a value that expires after 3600 seconds</BaseQuizOption>
  <BaseQuizOption value="D">Sets the key with 3600 different values</BaseQuizOption>
  
  <BaseQuizAnswer>
    The `EX` option sets an expiration time in seconds. `SET mykey "value" EX 3600` stores the value and automatically deletes it after 3600 seconds (1 hour).
  </BaseQuizAnswer>
</BaseQuiz>

### String Manipulation: `APPEND` / `STRLEN`

Modify and inspect string values.

```redis
# Append to existing string
APPEND mykey " - Welcome!"
# Get string length
STRLEN mykey
# Get substring
GETRANGE mykey 0 4
# Set substring
SETRANGE mykey 6 "Redis"
```

### Number Operations: `INCR` / `DECR`

Increment or decrement integer values stored in Redis.

```redis
# Increment by 1
INCR counter
# Decrement by 1
DECR counter
# Increment by specific amount
INCRBY counter 5
# Increment float
INCRBYFLOAT price 0.1
```

<BaseQuiz id="redis-incr-1" correct="A">
  <template #question>
    What happens if you use `INCR` on a key that doesn't exist?
  </template>
  
  <BaseQuizOption value="A" correct>Redis creates the key with value 1</BaseQuizOption>
  <BaseQuizOption value="B">Redis returns an error</BaseQuizOption>
  <BaseQuizOption value="C">Redis creates the key with value 0</BaseQuizOption>
  <BaseQuizOption value="D">Nothing happens</BaseQuizOption>
  
  <BaseQuizAnswer>
    If a key doesn't exist, `INCR` treats it as if it had a value of 0, increments it to 1, and creates the key. This makes `INCR` useful for initializing counters.
  </BaseQuizAnswer>
</BaseQuiz>

### Multiple Operations: `MSET` / `MGET`

Work with multiple key-value pairs efficiently.

```redis
# Set multiple keys at once
MSET key1 "value1" key2 "value2" key3 "value3"
# Get multiple values
MGET key1 key2 key3
# Set multiple only if none exist
MSETNX key1 "val1" key2 "val2"
```

## List Operations

Lists are ordered sequences of strings, useful as queues or stacks.

### Add Elements: `LPUSH` / `RPUSH`

Add elements to the left (head) or right (tail) of a list.

```redis
# Add to head (left)
LPUSH mylist "first"
# Add to tail (right)
RPUSH mylist "last"
# Add multiple elements
LPUSH mylist "item1" "item2" "item3"
```

### Remove Elements: `LPOP` / `RPOP`

Remove and return elements from list ends.

```redis
# Remove from head
LPOP mylist
# Remove from tail
RPOP mylist
# Blocking pop (wait for element)
BLPOP mylist 10
```

### Access Elements: `LRANGE` / `LINDEX`

Retrieve elements or ranges from lists.

```redis
# Get entire list
LRANGE mylist 0 -1
# Get first 3 elements
LRANGE mylist 0 2
# Get specific element by index
LINDEX mylist 0
# Get list length
LLEN mylist
```

<BaseQuiz id="redis-list-1" correct="B">
  <template #question>
    What does `LRANGE mylist 0 -1` return?
  </template>
  
  <BaseQuizOption value="A">Only the first element</BaseQuizOption>
  <BaseQuizOption value="B" correct>All elements in the list</BaseQuizOption>
  <BaseQuizOption value="C">Only the last element</BaseQuizOption>
  <BaseQuizOption value="D">An error</BaseQuizOption>
  
  <BaseQuizAnswer>
    `LRANGE` with `0 -1` returns all elements in the list. The `0` is the start index and `-1` represents the last element, so this retrieves everything from the first to the last element.
  </BaseQuizAnswer>
</BaseQuiz>

### List Utilities: `LSET` / `LTRIM`

Modify list contents and structure.

```redis
# Set element at index
LSET mylist 0 "new_value"
# Trim list to range
LTRIM mylist 0 99
# Find position of element
LPOS mylist "search_value"
```

## Set Operations

Sets are collections of unique, unordered string elements.

### Basic Set Operations: `SADD` / `SMEMBERS`

Add unique elements to sets and retrieve all members.

```redis
# Add elements to set
SADD myset "apple" "banana" "cherry"
# Get all set members
SMEMBERS myset
# Check if element exists
SISMEMBER myset "apple"
```

<BaseQuiz id="redis-set-1" correct="C">
  <template #question>
    What happens if you try to add a duplicate element to a Redis set?
  </template>
  
  <BaseQuizOption value="A">It creates an error</BaseQuizOption>
  <BaseQuizOption value="B">It replaces the existing element</BaseQuizOption>
  <BaseQuizOption value="C" correct>The duplicate is ignored, and the set remains unchanged</BaseQuizOption>
  <BaseQuizOption value="D">It creates a list instead</BaseQuizOption>
  
  <BaseQuizAnswer>
    Redis sets only contain unique elements. If you try to add an element that already exists, Redis ignores it and returns 0 (indicating no elements were added). The set remains unchanged.
  </BaseQuizAnswer>
</BaseQuiz>
# Get set size
SCARD myset
```

### Set Modifications: `SREM` / `SPOP`

Remove elements from sets in different ways.

```redis
# Remove specific elements
SREM myset "banana"
# Remove and return random element
SPOP myset
# Get random element without removing
SRANDMEMBER myset
```

### Set Operations: `SINTER` / `SUNION`

Perform mathematical set operations.

```redis
# Intersection of sets
SINTER set1 set2
# Union of sets
SUNION set1 set2
# Difference of sets
SDIFF set1 set2
# Store result in new set
SINTERSTORE result set1 set2
```

### Set Utilities: `SMOVE` / `SSCAN`

Advanced set manipulation and scanning.

```redis
# Move element between sets
SMOVE source_set dest_set "element"
# Scan set incrementally
SSCAN myset 0 MATCH "a*" COUNT 10
```

## Hash Operations

Hashes store field-value pairs, like mini JSON objects or dictionaries.

### Basic Hash Operations: `HSET` / `HGET`

Set and retrieve individual hash fields.

```redis
# Set hash field
HSET user:123 name "John Doe" age 30
# Get hash field
HGET user:123 name
# Set multiple fields
HMSET user:123 email "john@example.com" city "NYC"
# Get multiple fields
HMGET user:123 name age email
```

### Hash Inspection: `HKEYS` / `HVALS`

Examine hash structure and contents.

```redis
# Get all field names
HKEYS user:123
# Get all values
HVALS user:123
# Get all fields and values
HGETALL user:123
# Get number of fields
HLEN user:123
```

### Hash Utilities: `HEXISTS` / `HDEL`

Check existence and remove hash fields.

```redis
# Check if field exists
HEXISTS user:123 email
# Delete fields
HDEL user:123 age city
# Increment hash field
HINCRBY user:123 age 1
# Increment by float
HINCRBYFLOAT user:123 balance 10.50
```

### Hash Scanning: `HSCAN`

Iterate through large hashes incrementally.

```redis
# Scan hash fields
HSCAN user:123 0
# Scan with pattern matching
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## Sorted Set Operations

Sorted sets combine uniqueness of sets with ordering based on scores.

### Basic Operations: `ZADD` / `ZRANGE`

Add scored members and retrieve ranges.

```redis
# Add members with scores
ZADD leaderboard 100 "player1" 200 "player2"
# Get members by rank (0-based)
ZRANGE leaderboard 0 -1
# Get with scores
ZRANGE leaderboard 0 -1 WITHSCORES
# Get by score range
ZRANGEBYSCORE leaderboard 100 200
```

### Sorted Set Info: `ZCARD` / `ZSCORE`

Get information about sorted set members.

```redis
# Get set size
ZCARD leaderboard
# Get member score
ZSCORE leaderboard "player1"
# Get member rank
ZRANK leaderboard "player1"
# Count members in score range
ZCOUNT leaderboard 100 200
```

### Modifications: `ZREM` / `ZINCRBY`

Remove members and modify scores.

```redis
# Remove members
ZREM leaderboard "player1"
# Increment member score
ZINCRBY leaderboard 10 "player2"
# Remove by rank
ZREMRANGEBYRANK leaderboard 0 2
# Remove by score
ZREMRANGEBYSCORE leaderboard 0 100
```

### Advanced: `ZUNIONSTORE` / `ZINTERSTORE`

Combine multiple sorted sets.

```redis
# Union of sorted sets
ZUNIONSTORE result 2 set1 set2
# Intersection with weights
ZINTERSTORE result 2 set1 set2 WEIGHTS 1 2
# With aggregation function
ZUNIONSTORE result 2 set1 set2 AGGREGATE MAX
```

## Key Management

### Key Inspection: `KEYS` / `EXISTS`

Find keys using patterns and check existence.

```redis
# Get all keys (use carefully in production)
KEYS *
# Keys with pattern
KEYS user:*
# Keys ending with pattern
KEYS *:profile
# Single character wildcard
KEYS order:?
# Check if key exists
EXISTS mykey
```

### Key Information: `TYPE` / `TTL`

Get key metadata and expiration information.

```redis
# Get key data type
TYPE mykey
# Get time to live (seconds)
TTL mykey
# Get TTL in milliseconds
PTTL mykey
# Remove expiration
PERSIST mykey
```

### Key Operations: `RENAME` / `DEL`

Rename, delete, and move keys.

```redis
# Rename key
RENAME oldkey newkey
# Rename only if new key doesn't exist
RENAMENX oldkey newkey
# Delete keys
DEL key1 key2 key3
# Move key to different database
MOVE mykey 1
```

### Expiration: `EXPIRE` / `EXPIREAT`

Set key expiration times.

```redis
# Set expiration in seconds
EXPIRE mykey 3600
# Set expiration at specific timestamp
EXPIREAT mykey 1609459200
# Set expiration in milliseconds
PEXPIRE mykey 60000
```

## Database Management

### Database Selection: `SELECT` / `FLUSHDB`

Manage multiple databases within Redis.

```redis
# Select database (0-15 by default)
SELECT 0
# Clear current database
FLUSHDB
# Clear all databases
FLUSHALL
# Get current database size
DBSIZE
```

### Server Info: `INFO` / `PING`

Get server statistics and test connectivity.

```redis
# Test server connection
PING
# Get server information
INFO
# Get specific info section
INFO memory
INFO replication
# Get server time
TIME
```

### Persistence: `SAVE` / `BGSAVE`

Control Redis data persistence and backups.

```redis
# Synchronous save (blocks server)
SAVE
# Background save (non-blocking)
BGSAVE
# Get last save time
LASTSAVE
# Rewrite AOF file
BGREWRITEAOF
```

### Configuration: `CONFIG GET` / `CONFIG SET`

View and modify Redis configuration.

```redis
# Get all configuration
CONFIG GET *
# Get specific config
CONFIG GET maxmemory
# Set configuration
CONFIG SET timeout 300
# Reset configuration
CONFIG RESETSTAT
```

## Performance Monitoring

### Real-time Monitoring: `MONITOR` / `SLOWLOG`

Track commands and identify performance bottlenecks.

```redis
# Monitor all commands in real-time
MONITOR
# Get slow query log
SLOWLOG GET 10
# Get slow log length
SLOWLOG LEN
# Reset slow log
SLOWLOG RESET
```

### Memory Analysis: `MEMORY USAGE` / `MEMORY STATS`

Analyze memory consumption and optimization.

```redis
# Get key memory usage
MEMORY USAGE mykey
# Get memory statistics
MEMORY STATS
# Get memory doctor report
MEMORY DOCTOR
# Purge memory
MEMORY PURGE
```

### Client Information: `CLIENT LIST`

Monitor connected clients and connections.

```redis
# List all clients
CLIENT LIST
# Get client info
CLIENT INFO
# Kill client connection
CLIENT KILL ip:port
# Set client name
CLIENT SETNAME "my-app"
```

### Benchmarking: `redis-benchmark`

Test Redis performance with built-in benchmark tool.

```bash
# Basic benchmark
redis-benchmark
# Specific operations
redis-benchmark -t SET,GET -n 100000
# Custom payload size
redis-benchmark -d 1024 -t SET -n 10000
```

## Advanced Features

### Transactions: `MULTI` / `EXEC`

Execute multiple commands atomically.

```redis
# Start transaction
MULTI
SET key1 "value1"
INCR counter
# Execute all commands
EXEC
# Discard transaction
DISCARD
# Watch keys for changes
WATCH mykey
```

### Pub/Sub: `PUBLISH` / `SUBSCRIBE`

Implement message passing between clients.

```redis
# Subscribe to channel
SUBSCRIBE news sports
# Publish message
PUBLISH news "Breaking: Redis 7.0 released!"
# Pattern subscription
PSUBSCRIBE news:*
# Unsubscribe
UNSUBSCRIBE news
```

### Lua Scripting: `EVAL` / `SCRIPT`

Execute custom Lua scripts atomically.

```redis
# Execute Lua script
EVAL "return redis.call('SET', 'key', 'value')" 0
# Load script and get SHA
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# Execute by SHA
EVALSHA sha1 1 mykey
# Check script existence
SCRIPT EXISTS sha1
```

### Streams: `XADD` / `XREAD`

Work with Redis streams for log-like data.

```redis
# Add entry to stream
XADD mystream * field1 value1 field2 value2
# Read from stream
XREAD STREAMS mystream 0
# Get stream length
XLEN mystream
# Create consumer group
XGROUP CREATE mystream mygroup 0
```

## Data Types Overview

### Strings: Most versatile type

Can store text, numbers, JSON, binary data. Max size: 512MB. Use for: caching, counters, flags.

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### Lists: Ordered collections

Linked lists of strings. Use for: queues, stacks, activity feeds, recent items.

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### Sets: Unique collections

Unordered collections of unique strings. Use for: tags, unique visitors, relationships.

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Redis Configuration Tips

### Memory Management

Configure memory limits and eviction policies.

```redis
# Set memory limit
CONFIG SET maxmemory 2gb
# Set eviction policy
CONFIG SET maxmemory-policy allkeys-lru
# Check memory usage
INFO memory
```

### Persistence Settings

Configure data durability options.

```redis
# Enable AOF
CONFIG SET appendonly yes
# Set save intervals
CONFIG SET save "900 1 300 10 60 10000"
# AOF rewrite settings
CONFIG SET auto-aof-rewrite-percentage 100
```

### Security Settings

Basic security configurations for Redis.

```redis
# Set password
CONFIG SET requirepass mypassword
# Authenticate
AUTH mypassword
# Disable dangerous commands
CONFIG SET rename-command FLUSHALL ""
# Set timeout
CONFIG SET timeout 300
# TCP keep alive
CONFIG SET tcp-keepalive 60
# Max clients
CONFIG SET maxclients 10000
```

### Performance Tuning

Optimize Redis for better performance.

```redis
# Enable pipelining for multiple commands
# Use connection pooling
# Configure appropriate maxmemory-policy
# Monitor slow queries regularly
# Use appropriate data structures for use cases
```

## Relevant Links

- <router-link to="/database">Database Cheatsheet</router-link>
- <router-link to="/mysql">MySQL Cheatsheet</router-link>
- <router-link to="/postgresql">PostgreSQL Cheatsheet</router-link>
- <router-link to="/mongodb">MongoDB Cheatsheet</router-link>
- <router-link to="/sqlite">SQLite Cheatsheet</router-link>
- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/javascript">JavaScript Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>

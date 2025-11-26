---
title: 'Redis チートシート'
description: '必須コマンド、概念、ベストプラクティスを網羅した包括的なチートシートで Redis を習得しましょう。'
pdfUrl: '/cheatsheets/pdf/redis-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Redis チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/redis">ハンズオンラボで Redis を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
ハンズオンラボと実世界のシナリオを通じて、Redis インメモリデータ構造の操作を学びます。LabEx は、必須コマンド、データ構造、キャッシング戦略、pub/sub メッセージング、パフォーマンス最適化を網羅した包括的な Redis コースを提供します。高性能キャッシングとリアルタイムデータ処理を習得しましょう。
</base-disclaimer-content>
</base-disclaimer>

## Redis のインストールとセットアップ

### Docker: `docker run redis`

ローカルで Redis を起動する最も簡単な方法。

```bash
# DockerでRedisを実行
docker run --name my-redis -p 6379:6379 -d redis
# Redis CLIに接続
docker exec -it my-redis redis-cli
# 永続ストレージで実行
docker run --name redis-persistent -p 6379:6379 -v redis-data:/data -d redis
```

### Linux: `sudo apt install redis`

Ubuntu/DebianシステムへのRedisサーバーのインストール。

```bash
# Redisをインストール
sudo apt update
sudo apt install redis-server
# Redisサービスを開始
sudo systemctl start redis-server
# ブート時の自動起動を有効化
sudo systemctl enable redis-server
# ステータスを確認
sudo systemctl status redis
```

### 接続とテスト：`redis-cli`

Redis サーバーに接続し、インストールを確認します。

```bash
# ローカルRedisに接続
redis-cli
# 接続テスト
redis-cli PING
# リモートRedisに接続
redis-cli -h hostname -p 6379 -a password
# 単一コマンドの実行
redis-cli SET mykey "Hello Redis"
```

## 基本的な String 操作

### Set と Get: `SET` / `GET`

単純な値（テキスト、数値、JSON など）を保存します。

```redis
# キーと値のペアを設定
SET mykey "Hello World"
# 値を取得
GET mykey
# 有効期限付きで設定（秒単位）
SET session:123 "user_data" EX 3600
# キーが存在しない場合のみ設定
SET mykey "new_value" NX
```

### String 操作：`APPEND` / `STRLEN`

文字列値を変更および検査します。

```redis
# 既存の文字列に追加
APPEND mykey " - Welcome!"
# 文字列の長さを取得
STRLEN mykey
# 部分文字列を取得
GETRANGE mykey 0 4
# 部分文字列を設定
SETRANGE mykey 6 "Redis"
```

### 数値操作：`INCR` / `DECR`

Redis に格納されている整数値をインクリメントまたはデクリメントします。

```redis
# 1ずつインクリメント
INCR counter
# 1ずつデクリメント
DECR counter
# 指定した量だけインクリメント
INCRBY counter 5
# 浮動小数点数をインクリメント
INCRBYFLOAT price 0.1
```

### 複数操作：`MSET` / `MGET`

複数のキーと値のペアを効率的に扱います。

```redis
# 複数のキーを一度に設定
MSET key1 "value1" key2 "value2" key3 "value3"
# 複数の値を取得
MGET key1 key2 key3
# すべて存在しない場合のみ複数設定
MSETNX key1 "val1" key2 "val2"
```

## List 操作

リストは文字列の順序付きシーケンスであり、キューやスタックとして役立ちます。

### 要素の追加：`LPUSH` / `RPUSH`

リストの左端（先頭）または右端（末尾）に要素を追加します。

```redis
# 先頭（左）に追加
LPUSH mylist "first"
# 末尾（右）に追加
RPUSH mylist "last"
# 複数の要素を追加
LPUSH mylist "item1" "item2" "item3"
```

### 要素の削除：`LPOP` / `RPOP`

リストの端から要素を削除して返します。

```redis
# 先頭から削除
LPOP mylist
# 末尾から削除
RPOP mylist
# ブロッキングポップ（要素を待機）
BLPOP mylist 10
```

### 要素へのアクセス：`LRANGE` / `LINDEX`

リストから要素または範囲を取得します。

```redis
# リスト全体を取得
LRANGE mylist 0 -1
# 最初の3つの要素を取得
LRANGE mylist 0 2
# インデックスで特定の要素を取得
LINDEX mylist 0
# リストの長さを取得
LLEN mylist
```

### List ユーティリティ：`LSET` / `LTRIM`

リストの内容と構造を変更します。

```redis
# インデックスの要素を設定
LSET mylist 0 "new_value"
# リストを指定範囲にトリム
LTRIM mylist 0 99
# 要素の位置を検索
LPOS mylist "search_value"
```

## Set 操作

セットは、一意で順序付けられていない文字列要素のコレクションです。

### 基本的な Set 操作：`SADD` / `SMEMBERS`

セットに一意の要素を追加し、すべてのメンバーを取得します。

```redis
# セットに要素を追加
SADD myset "apple" "banana" "cherry"
# すべてのセットメンバーを取得
SMEMBERS myset
# 要素が存在するか確認
SISMEMBER myset "apple"
# セットのサイズを取得
SCARD myset
```

### Set の変更：`SREM` / `SPOP`

異なる方法でセットから要素を削除します。

```redis
# 特定の要素を削除
SREM myset "banana"
# ランダムな要素を削除して返す
SPOP myset
# 削除せずにランダムな要素を取得
SRANDMEMBER myset
```

### Set 演算：`SINTER` / `SUNION`

数学的なセット演算を実行します。

```redis
# 集合の積集合
SINTER set1 set2
# 集合の和集合
SUNION set1 set2
# 集合の差集合
SDIFF set1 set2
# 結果を新しいセットに保存
SINTERSTORE result set1 set2
```

### Set ユーティリティ：`SMOVE` / `SSCAN`

高度なセット操作とインクリメンタルスキャン。

```redis
# セット間で要素を移動
SMOVE source_set dest_set "element"
# セットをインクリメンタルにスキャン
SSCAN myset 0 MATCH "a*" COUNT 10
```

## Hash 操作

ハッシュはフィールドと値のペアを格納し、小さな JSON オブジェクトや辞書のようなものです。

### 基本的な Hash 操作：`HSET` / `HGET`

ハッシュの個々のフィールドを設定および取得します。

```redis
# ハッシュフィールドを設定
HSET user:123 name "John Doe" age 30
# ハッシュフィールドを取得
HGET user:123 name
# 複数のフィールドを設定
HMSET user:123 email "john@example.com" city "NYC"
# 複数のフィールドを取得
HMGET user:123 name age email
```

### Hash の検査：`HKEYS` / `HVALS`

ハッシュの構造と内容を調べます。

```redis
# すべてのフィールド名を取得
HKEYS user:123
# すべての値を取得
HVALS user:123
# すべてのフィールドと値を取得
HGETALL user:123
# フィールド数を取得
HLEN user:123
```

### Hash ユーティリティ：`HEXISTS` / `HDEL`

存在を確認し、ハッシュフィールドを削除します。

```redis
# フィールドが存在するか確認
HEXISTS user:123 email
# フィールドを削除
HDEL user:123 age city
# ハッシュフィールドをインクリメント
HINCRBY user:123 age 1
# 浮動小数点数をインクリメント
HINCRBYFLOAT user:123 balance 10.50
```

### Hash スキャン：`HSCAN`

大きなハッシュをインクリメンタルに反復処理します。

```redis
# ハッシュをスキャン
HSCAN user:123 0
# パターンマッチングでスキャン
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## Sorted Set 操作

Sorted Set は、スコアに基づく順序付けとセットの一意性を組み合わせたものです。

### 基本操作：`ZADD` / `ZRANGE`

スコア付きメンバーを追加し、範囲を取得します。

```redis
# スコア付きメンバーを追加
ZADD leaderboard 100 "player1" 200 "player2"
# ランク順にメンバーを取得（0から始まる）
ZRANGE leaderboard 0 -1
# スコア付きで取得
ZRANGE leaderboard 0 -1 WITHSCORES
# スコア範囲で取得
ZRANGEBYSCORE leaderboard 100 200
```

### Sorted Set 情報：`ZCARD` / `ZSCORE`

Sorted Set メンバーに関する情報を取得します。

```redis
# セットサイズを取得
ZCARD leaderboard
# メンバーのスコアを取得
ZSCORE leaderboard "player1"
# メンバーのランクを取得
ZRANK leaderboard "player1"
# スコア範囲内のメンバー数をカウント
ZCOUNT leaderboard 100 200
```

### 変更：`ZREM` / `ZINCRBY`

メンバーを削除し、スコアを変更します。

```redis
# メンバーを削除
ZREM leaderboard "player1"
# メンバーのスコアをインクリメント
ZINCRBY leaderboard 10 "player2"
# ランク順に範囲を削除
ZREMRANGEBYRANK leaderboard 0 2
# スコア範囲で削除
ZREMRANGEBYSCORE leaderboard 0 100
```

### 高度な操作：`ZUNIONSTORE` / `ZINTERSTORE`

複数の Sorted Set を結合します。

```redis
# Sorted Setの和集合
ZUNIONSTORE result 2 set1 set2
# 重み付きの積集合
ZINTERSTORE result 2 set1 set2 WEIGHTS 1 2
# 集約関数付きの和集合
ZUNIONSTORE result 2 set1 set2 AGGREGATE MAX
```

## Key 管理

### Key の検査：`KEYS` / `EXISTS`

パターンを使用してキーを見つけ、存在を確認します。

```redis
# すべてのキーを取得（本番環境では注意が必要）
KEYS *
# パターンに一致するキー
KEYS user:*
# パターンで終わるキー
KEYS *:profile
# 単一文字ワイルドカード
KEYS order:?
# キーの存在を確認
EXISTS mykey
```

### Key 情報：`TYPE` / `TTL`

キーのメタデータと有効期限情報を取得します。

```redis
# キーのデータ型を取得
TYPE mykey
# 有効期限までの時間（秒）を取得
TTL mykey
# 有効期限までの時間（ミリ秒）を取得
PTTL mykey
# 有効期限を削除
PERSIST mykey
```

### Key 操作：`RENAME` / `DEL`

キーの名前変更、削除、移動を行います。

```redis
# キーの名前を変更
RENAME oldkey newkey
# 新しいキーが存在しない場合のみ名前を変更
RENAMENX oldkey newkey
# キーを削除
DEL key1 key2 key3
# キーを別のデータベースに移動
MOVE mykey 1
```

### 有効期限：`EXPIRE` / `EXPIREAT`

キーの有効期限を設定します。

```redis
# 秒単位で有効期限を設定
EXPIRE mykey 3600
# 特定のタイムスタンプで有効期限を設定
EXPIREAT mykey 1609459200
# ミリ秒単位で有効期限を設定
PEXPIRE mykey 60000
```

## データベース管理

### データベース選択：`SELECT` / `FLUSHDB`

Redis 内の複数のデータベースを管理します。

```redis
# データベースを選択（デフォルトでは0-15）
SELECT 0
# 現在のデータベースをクリア
FLUSHDB
# すべてのデータベースをクリア
FLUSHALL
# 現在のデータベースのサイズを取得
DBSIZE
```

### サーバー情報：`INFO` / `PING`

サーバー統計情報を取得し、接続をテストします。

```bash
# サーバー接続テスト
PING
# サーバー情報を取得
INFO
# 特定のインフォセクションを取得
INFO memory
INFO replication
# サーバー時刻を取得
TIME
```

### 永続化：`SAVE` / `BGSAVE`

Redis のデータ永続化とバックアップを制御します。

```redis
# 同期セーブ（サーバーをブロック）
SAVE
# バックグラウンドセーブ（非ブロッキング）
BGSAVE
# 最終セーブ時刻を取得
LASTSAVE
# AOFファイルを書き直す
BGREWRITEAOF
```

### 設定：`CONFIG GET` / `CONFIG SET`

Redis の設定を表示および変更します。

```redis
# すべての設定を取得
CONFIG GET *
# 特定の設定を取得
CONFIG GET maxmemory
# 設定を変更
CONFIG SET timeout 300
# 統計をリセット
CONFIG RESETSTAT
```

## パフォーマンス監視

### リアルタイム監視：`MONITOR` / `SLOWLOG`

コマンドを追跡し、パフォーマンスのボトルネックを特定します。

```redis
# すべてのコマンドをリアルタイムで監視
MONITOR
# スロークエリログを取得
SLOWLOG GET 10
# スローログの長さを取得
SLOWLOG LEN
# スローログをリセット
SLOWLOG RESET
```

### メモリ分析：`MEMORY USAGE` / `MEMORY STATS`

メモリ消費量を分析し、最適化します。

```redis
# キーのメモリ使用量を取得
MEMORY USAGE mykey
# メモリ統計情報を取得
MEMORY STATS
# メモリドクターレポートを取得
MEMORY DOCTOR
# メモリをパージ
MEMORY PURGE
```

### クライアント情報：`CLIENT LIST`

接続されているクライアントと接続を監視します。

```redis
# すべてのクライアントをリスト表示
CLIENT LIST
# クライアント情報を取得
CLIENT INFO
# クライアント接続をキル
CLIENT KILL ip:port
# クライアント名を設定
CLIENT SETNAME "my-app"
```

### ベンチマーク：`redis-benchmark`

組み込みのベンチマークツールで Redis のパフォーマンスをテストします。

```bash
# 基本的なベンチマーク
redis-benchmark
# 特定の操作
redis-benchmark -t SET,GET -n 100000
# カスタムペイロードサイズ
redis-benchmark -d 1024 -t SET -n 10000
```

## 高度な機能

### トランザクション：`MULTI` / `EXEC`

複数のコマンドをアトミックに実行します。

```redis
# トランザクションを開始
MULTI
SET key1 "value1"
INCR counter
# すべてのコマンドを実行
EXEC
# トランザクションを破棄
DISCARD
# キーの変更を監視
WATCH mykey
```

### Pub/Sub: `PUBLISH` / `SUBSCRIBE`

クライアント間のメッセージング機能を実装します。

```redis
# チャンネルを購読
SUBSCRIBE news sports
# メッセージを公開
PUBLISH news "Breaking: Redis 7.0 released!"
# パターン購読
PSUBSCRIBE news:*
# 購読解除
UNSUBSCRIBE news
```

### Lua スクリプティング：`EVAL` / `SCRIPT`

アトミックにカスタム Lua スクリプトを実行します。

```redis
# Luaスクリプトを実行
EVAL "return redis.call('SET', 'key', 'value')" 0
# スクリプトをロードしSHAを取得
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# SHAで実行
EVALSHA sha1 1 mykey
# スクリプトの存在を確認
SCRIPT EXISTS sha1
```

### Streams: `XADD` / `XREAD`

ログのようなデータを扱うために Redis ストリームを使用します。

```redis
# ストリームにエントリを追加
XADD mystream * field1 value1 field2 value2
# ストリームから読み取り
XREAD STREAMS mystream 0
# ストリームの長さを取得
XLEN mystream
# コンシューマーグループを作成
XGROUP CREATE mystream mygroup 0
```

## データ型概要

### Strings: 最も汎用的な型

テキスト、数値、JSON、バイナリデータを格納可能。最大サイズ：512MB。用途：キャッシング、カウンター、フラグ。

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### Lists: 順序付きコレクション

文字列の連結リスト。用途：キュー、スタック、アクティビティフィード、最近のアイテム。

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### Sets: 一意なコレクション

一意な文字列の順序付けられていないコレクション。用途：タグ、ユニークビジター、リレーションシップ。

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Redis 設定のヒント

### メモリ管理

メモリ制限とデータ削除ポリシーを設定します。

```redis
# メモリ制限を設定
CONFIG SET maxmemory 2gb
# 削除ポリシーを設定
CONFIG SET maxmemory-policy allkeys-lru
# メモリ使用量を確認
INFO memory
```

### 永続化設定

データの耐久性オプションを設定します。

```redis
# AOFを有効化
CONFIG SET appendonly yes
# 保存間隔を設定
CONFIG SET save "900 1 300 10 60 10000"
# AOF書き込み設定
CONFIG SET auto-aof-rewrite-percentage 100
```

### セキュリティ設定

Redis の基本的なセキュリティ設定。

```redis
# パスワードを設定
CONFIG SET requirepass mypassword
# 認証
AUTH mypassword
# 危険なコマンドを無効化
CONFIG SET rename-command FLUSHALL ""
# タイムアウトを設定
CONFIG SET timeout 300
# TCPキープアライブ
CONFIG SET tcp-keepalive 60
# 最大クライアント数
CONFIG SET maxclients 10000
```

### パフォーマンスチューニング

パフォーマンス向上のために Redis を最適化します。

```redis
# 複数のコマンドのためにパイプラインを有効化
# コネクションプーリングを使用
# ユースケースに適したmaxmemory-policyを設定
# 定期的にスロークエリを監視
# ユースケースに適したデータ構造を使用
```

## 関連リンク

- <router-link to="/database">データベース チートシート</router-link>
- <router-link to="/mysql">MySQL チートシート</router-link>
- <router-link to="/postgresql">PostgreSQL チートシート</router-link>
- <router-link to="/mongodb">MongoDB チートシート</router-link>
- <router-link to="/sqlite">SQLite チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>

---
title: 'MongoDB チートシート | LabEx'
description: 'この包括的なチートシートで MongoDB NoSQL データベースを学習。MongoDB クエリ、集計、インデックス、シャーディング、レプリケーション、ドキュメントデータベース管理のクイックリファレンス。'
pdfUrl: '/cheatsheets/pdf/mongodb-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
MongoDB チートシート
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ja/learn/mongodb">ハンズオンラボで MongoDB を学ぶ</a>
</base-disclaimer-title>
<base-disclaimer-content>
LabEx では、ハンズオンラボと実世界のシナリオを通じて、MongoDB NoSQL データベース管理を学習できます。LabEx は、必須操作、ドキュメントクエリ、集計パイプライン、インデックス戦略、高度なテクニックを網羅した包括的な MongoDB コースを提供しています。MongoDB のドキュメントベースのデータモデルを習得し、スケーラブルで柔軟なデータベースアプリケーションを構築しましょう。
</base-disclaimer-content>
</base-disclaimer>

## データベースとコレクションの管理

### データベースの表示：`show dbs`

MongoDB サーバー上のすべてのデータベースを表示します。

```javascript
// すべてのデータベースを表示
show dbs
// 現在のデータベースを表示
db
// データベースの統計情報を取得
db.stats()
// データベースのヘルプを取得
db.help()
```

### データベースの使用：`use database_name`

特定のデータベースに切り替えます（存在しない場合は作成されます）。

```javascript
// myapp データベースに切り替え
use myapp
// データを挿入してデータベースを作成
use newdb
db.users.insertOne({name: "John"})
```

<BaseQuiz id="mongodb-use-1" correct="B">
  <template #question>
    MongoDB で`use newdb`を実行するとどうなりますか？
  </template>
  
  <BaseQuizOption value="A">データベースがすぐに作成される</BaseQuizOption>
  <BaseQuizOption value="B" correct>データベースに切り替わる（最初にデータを挿入したときに作成される）</BaseQuizOption>
  <BaseQuizOption value="C">データベースが削除される</BaseQuizOption>
  <BaseQuizOption value="D">データベース内のすべてのコレクションが表示される</BaseQuizOption>
  
  <BaseQuizAnswer>
    `use` コマンドはデータベースに切り替えますが、MongoDB は最初のドキュメントを挿入するまでデータベースを作成しません。これは遅延作成アプローチです。
  </BaseQuizAnswer>
</BaseQuiz>

### データベースの削除：`db.dropDatabase()`

現在のデータベースとそのすべてのコレクションを削除します。

```javascript
// 現在のデータベースを削除
db.dropDatabase()
// データベース名で確認
use myapp
db.dropDatabase()
```

### コレクションの表示：`show collections`

現在のデータベース内のすべてのコレクションを一覧表示します。

```javascript
// すべてのコレクションを表示
show collections
// 代替メソッド
db.runCommand("listCollections")
```

### コレクションの作成：`db.createCollection()`

オプションの設定を指定して新しいコレクションを作成します。

```javascript
// シンプルなコレクションを作成
db.createCollection('users')
// オプション付きで作成
db.createCollection('logs', {
  capped: true,
  size: 1000000,
  max: 1000,
})
```

### コレクションの削除：`db.collection.drop()`

コレクションとそのすべてのドキュメントを削除します。

```javascript
// users コレクションを削除
db.users.drop()
// コレクションが削除されたか確認
show collections
```

## ドキュメント構造と情報

### コレクションの統計情報：`db.collection.stats()`

サイズ、ドキュメント数、インデックス情報など、コレクションに関する包括的な統計情報を表示します。

```javascript
// コレクションの統計情報
db.users.stats()
// ドキュメント数をカウント
db.users.countDocuments()
// 推定ドキュメント数（より高速）
db.users.estimatedDocumentCount()
// コレクションのインデックスを確認
db.users.getIndexes()
```

### サンプルドキュメント：`db.collection.findOne()`

構造とデータ型を理解するために、サンプルドキュメントを取得します。

```javascript
// ドキュメントを 1 つ取得
db.users.findOne()
// 特定のドキュメントを取得
db.users.findOne({ name: 'John' })
// すべてのフィールドを表示してドキュメントを取得
db.users.findOne({}, { _id: 0 })
```

### データの閲覧：`db.collection.find().limit()`

ページネーションと書式設定を使用してコレクションデータを閲覧します。

```javascript
// 最初の 5 つのドキュメント
db.users.find().limit(5)
// スキップとリミット（ページネーション）
db.users.find().skip(10).limit(5)
// 読みやすい形式で表示
db.users.find().pretty()
```

## ドキュメントの挿入 (作成)

### 1 件挿入：`db.collection.insertOne()`

コレクションに単一のドキュメントを追加します。

```javascript
// 単一ドキュメントを挿入
db.users.insertOne({
  name: 'John Doe',
  age: 30,
  email: 'john@example.com',
})
// カスタム_id で挿入
db.users.insertOne({
  _id: 'custom_id_123',
  name: 'Jane Doe',
  status: 'active',
})
```

<BaseQuiz id="mongodb-insert-1" correct="A">
  <template #question>
    `db.users.insertOne()` は何を返しますか？
  </template>
  
  <BaseQuizOption value="A" correct>挿入されたドキュメントの_id を含む確認オブジェクト</BaseQuizOption>
  <BaseQuizOption value="B">挿入されたドキュメント</BaseQuizOption>
  <BaseQuizOption value="C">何も返さない</BaseQuizOption>
  <BaseQuizOption value="D">挿入されたドキュメント数</BaseQuizOption>
  
  <BaseQuizAnswer>
    `insertOne()` は、`acknowledged: true`と、挿入されたドキュメントの `_id`（または提供されたカスタム`_id`）を含む`insertedId` を含む確認オブジェクトを返します。
  </BaseQuizAnswer>
</BaseQuiz>

### 複数挿入：`db.collection.insertMany()`

単一の操作で複数のドキュメントを追加します。

```javascript
// 複数のドキュメントを挿入
db.users.insertMany([
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 35 },
  { name: 'Charlie', age: 28 },
])
// オプション付きで挿入
db.users.insertMany(
  [
    { name: 'Dave', age: 40 },
    { name: 'Eve', age: 22 },
  ],
  { ordered: false },
)
```

### 日付付き挿入：`new Date()`

タイムスタンプフィールドを持つドキュメントを追加します。

```javascript
// 現在の日付で挿入
db.posts.insertOne({
  title: 'My Blog Post',
  content: 'Post content here',
  createdAt: new Date(),
  publishDate: ISODate('2024-01-15'),
})
```

### ネストされたドキュメントの挿入

埋め込みオブジェクトと配列を持つドキュメントを追加します。

```javascript
// ネストされたオブジェクトで挿入
db.users.insertOne({
  name: 'John Doe',
  address: {
    street: '123 Main St',
    city: 'New York',
    zip: '10001',
  },
  hobbies: ['reading', 'swimming', 'coding'],
})
```

## ドキュメントのクエリ (読み取り)

### 基本的な検索：`db.collection.find()`

クエリ条件に基づいてドキュメントを取得します。

```javascript
// すべてのドキュメントを検索
db.users.find()
// 条件を指定して検索
db.users.find({ age: 30 })
// 複数の条件（AND）で検索
db.users.find({ age: 30, status: 'active' })
// OR 条件で検索
db.users.find({ $or: [{ age: 25 }, { age: 30 }] })
```

### プロジェクション：`db.collection.find({}, {})`

結果に返されるフィールドを制御します。

```javascript
// 特定のフィールドを含める
db.users.find({}, { name: 1, age: 1 })
// 特定のフィールドを除外する
db.users.find({}, { password: 0, _id: 0 })
// ネストされたフィールドのプロジェクション
db.users.find({}, { 'address.city': 1 })
```

### クエリ演算子：`$gt`, `$lt`, `$in`など

複雑なクエリのために比較演算子と論理演算子を使用します。

```javascript
// より大きい、より小さい
db.users.find({ age: { $gt: 25, $lt: 40 } })
// 配列内
db.users.find({ status: { $in: ['active', 'pending'] } })
// 等しくない
db.users.find({ status: { $ne: 'inactive' } })
// 存在する
db.users.find({ email: { $exists: true } })
```

<BaseQuiz id="mongodb-query-1" correct="B">
  <template #question>
    MongoDB クエリにおける `$gt` は何を意味しますか？
  </template>
  
  <BaseQuizOption value="A">以上</BaseQuizOption>
  <BaseQuizOption value="B" correct>より大きい</BaseQuizOption>
  <BaseQuizOption value="C">グループ化</BaseQuizOption>
  <BaseQuizOption value="D">合計を取得</BaseQuizOption>
  
  <BaseQuizAnswer>
    `$gt` は「より大きい」を意味する比較演算子です。`{ age: { $gt: 25 } }`のようなクエリで使用され、age フィールドが 25 より大きいドキュメントを検索します。
  </BaseQuizAnswer>
</BaseQuiz>

### テキスト検索：`$text`, `$regex`

テキストとパターンマッチングを使用してドキュメントを検索します。

```javascript
// テキスト検索（テキストインデックスが必要）
db.posts.find({ $text: { $search: 'mongodb tutorial' } })
// Regex 検索
db.users.find({ name: { $regex: '^John', $options: 'i' } })
// 大文字・小文字を区別しない検索
db.users.find({ email: { $regex: '@gmail.com$' } })
```

## ドキュメントの更新

### 1 件更新：`db.collection.updateOne()`

クエリに一致する最初のドキュメントを変更します。

```javascript
// 単一フィールドを更新
db.users.updateOne({ name: 'John Doe' }, { $set: { age: 31 } })
// 複数のフィールドを更新
db.users.updateOne(
  { _id: ObjectId('...') },
  { $set: { age: 31, status: 'updated' } },
)
// Upsert（見つからない場合は挿入）
db.users.updateOne(
  { name: 'New User' },
  { $set: { age: 25 } },
  { upsert: true },
)
```

### 複数更新：`db.collection.updateMany()`

クエリに一致するすべてのドキュメントを変更します。

```javascript
// 複数のドキュメントを更新
db.users.updateMany({ status: 'inactive' }, { $set: { status: 'archived' } })
// 値をインクリメント
db.posts.updateMany({ category: 'tech' }, { $inc: { views: 1 } })
```

### 更新演算子：`$set`, `$unset`, `$push`

さまざまな演算子を使用してドキュメントフィールドを変更します。

```javascript
// フィールドの設定と削除
db.users.updateOne(
  { name: 'John' },
  { $set: { lastLogin: new Date() }, $unset: { temp: '' } },
)
// 配列にプッシュ
db.users.updateOne({ name: 'John' }, { $push: { hobbies: 'gaming' } })
```

<BaseQuiz id="mongodb-update-1" correct="C">
  <template #question>
    MongoDB の更新操作における `$set` は何をしますか？
  </template>
  
  <BaseQuizOption value="A">フィールドを削除する</BaseQuizOption>
  <BaseQuizOption value="B">配列に要素を追加する</BaseQuizOption>
  <BaseQuizOption value="C" correct>フィールドの値を設定する</BaseQuizOption>
  <BaseQuizOption value="D">配列から要素を削除する</BaseQuizOption>
  
  <BaseQuizAnswer>
    `$set` 演算子は、ドキュメント内のフィールドの値を設定します。フィールドが存在しない場合は作成され、存在する場合は値を更新します。
  </BaseQuizAnswer>
</BaseQuiz>

```javascript
// 配列からプル（削除）
db.users.updateOne({ name: 'John' }, { $pull: { hobbies: 'reading' } })
```

### ドキュメントの置換：`db.collection.replaceOne()`

\_id フィールドを除くドキュメント全体を置き換えます。

```javascript
// ドキュメント全体を置換
db.users.replaceOne(
  { name: 'John Doe' },
  {
    name: 'John Smith',
    age: 35,
    email: 'johnsmith@example.com',
  },
)
```

## データ集計

### 基本的な集計：`db.collection.aggregate()`

集計パイプラインステージを通じてデータを処理します。

```javascript
// グループ化とカウント
db.users.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }])
// マッチングとグループ化
db.orders.aggregate([
  { $match: { status: 'completed' } },
  { $group: { _id: '$customerId', total: { $sum: '$amount' } } },
])
```

### 一般的なステージ：`$match`, `$group`, `$sort`

パイプラインステージを使用してデータを変換および分析します。

```javascript
// 複雑な集計パイプライン
db.sales.aggregate([
  { $match: { date: { $gte: ISODate('2024-01-01') } } },
  {
    $group: {
      _id: '$product',
      totalSales: { $sum: '$amount' },
      avgPrice: { $avg: '$price' },
    },
  },
  { $sort: { totalSales: -1 } },
  { $limit: 10 },
])
```

### 集計演算子：`$sum`, `$avg`, `$max`

統計値を計算し、数学的演算を実行します。

```javascript
// 統計演算
db.products.aggregate([
  {
    $group: {
      _id: '$category',
      maxPrice: { $max: '$price' },
      minPrice: { $min: '$price' },
      avgPrice: { $avg: '$price' },
      count: { $sum: 1 },
    },
  },
])
```

### プロジェクションステージ：`$project`

ドキュメント構造を変換し、計算フィールドを作成します。

```javascript
// フィールドのプロジェクションと計算
db.users.aggregate([
  {
    $project: {
      name: 1,
      age: 1,
      isAdult: { $gte: ['$age', 18] },
      fullName: { $concat: ['$firstName', ' ', '$lastName'] },
    },
  },
])
```

## ドキュメントの削除

### 1 件削除：`db.collection.deleteOne()`

クエリ条件に一致する最初のドキュメントを削除します。

```javascript
// 単一ドキュメントを削除
db.users.deleteOne({ name: 'John Doe' })
// ID で削除
db.users.deleteOne({ _id: ObjectId('...') })
// 条件付きで削除
db.posts.deleteOne({ status: 'draft', author: 'unknown' })
```

### 複数削除：`db.collection.deleteMany()`

クエリ条件に一致するすべてのドキュメントを削除します。

```javascript
// 複数のドキュメントを削除
db.users.deleteMany({ status: 'inactive' })
// すべてのドキュメントを削除（注意！）
db.temp_collection.deleteMany({})
// 日付条件で削除
db.logs.deleteMany({
  createdAt: { $lt: new Date('2024-01-01') },
})
```

### 検索して削除：`db.collection.findOneAndDelete()`

単一の原子的な操作でドキュメントを検索して削除します。

```javascript
// 検索して削除
const deletedDoc = db.users.findOneAndDelete({ status: 'pending' })
// オプション付きで検索して削除
db.queue.findOneAndDelete({ processed: false }, { sort: { priority: -1 } })
```

## インデックスとパフォーマンス

### インデックスの作成：`db.collection.createIndex()`

クエリを高速化するためにフィールドにインデックスを作成します。

```javascript
// 単一フィールドインデックス
db.users.createIndex({ email: 1 })
// 複合インデックス
db.users.createIndex({ status: 1, createdAt: -1 })
// 検索用のテキストインデックス
db.posts.createIndex({ title: 'text', content: 'text' })
// ユニークインデックス
db.users.createIndex({ email: 1 }, { unique: true })
```

### インデックス管理：`getIndexes()`, `dropIndex()`

コレクション上に存在するインデックスを表示および管理します。

```javascript
// すべてのインデックスを一覧表示
db.users.getIndexes()
// 特定のインデックスを削除
db.users.dropIndex({ email: 1 })
// インデックス名で削除
db.users.dropIndex('email_1')
// すべてのインデックスを削除（_id を除く）
db.users.dropIndexes()
```

### クエリパフォーマンス：`explain()`

クエリの実行とパフォーマンス統計を分析します。

```javascript
// クエリ実行を説明
db.users.find({ age: { $gt: 25 } }).explain('executionStats')
// インデックスが使用されているか確認
db.users.find({ email: 'john@example.com' }).explain()
// 集計パフォーマンスの分析
db.users
  .aggregate([
    { $match: { status: 'active' } },
    { $group: { _id: '$department', count: { $sum: 1 } } },
  ])
  .explain('executionStats')
```

### パフォーマンスのヒント

MongoDB のクエリと操作を最適化するためのベストプラクティス。

```javascript
// データ転送量を制限するためにプロジェクションを使用
db.users.find({ status: 'active' }, { name: 1, email: 1 })
// パフォーマンス向上のために結果を制限
db.posts.find().sort({ createdAt: -1 }).limit(10)
// 特定のインデックスを強制的に使用するためにヒントを使用
db.users.find({ age: 25 }).hint({ age: 1 })
```

## MongoDB シェルと接続

### MongoDB への接続：`mongosh`

MongoDB シェルを起動し、異なるインスタンスに接続します。

```bash
# ローカルMongoDBに接続
mongosh
# 特定のホストとポートに接続
mongosh "mongodb://localhost:27017"
# リモートサーバーに接続
mongosh "mongodb://username:password@host:port/database"
# オプション付きで接続
mongosh --host localhost --port 27017
```

### シェルヘルパー: `help`, `exit`

ヘルプ情報の取得とシェルセッションの管理。

```javascript
// 一般的なヘルプ
help
// データベース固有のヘルプ
db.help()
// コレクション固有のヘルプ
db.users.help()
// シェルを終了
exit
```

### シェル変数と設定

シェル動作の設定と JavaScript 変数の使用。

```javascript
// 変数を設定
var myQuery = { status: 'active' }
db.users.find(myQuery)
// 表示オプションを設定
db.users.find().pretty()
// 実行時間を表示
db.users.find({ age: 25 }).explain('executionStats')
// シェルで JavaScript を使用
var user = db.users.findOne({ name: 'John' })
print('User age: ' + user.age)
```

## データのエクスポートとインポート

### データのインポート：`mongoimport`

JSON、CSV、または TSV ファイルから MongoDB にデータをロードします。

```bash
# JSONファイルをインポート
mongoimport --db myapp --collection users --file users.json
# CSVファイルをインポート
mongoimport --db myapp --collection products \
  --type csv --headerline --file products.csv
# Upsertモードでインポート
mongoimport --db myapp --collection users \
  --file users.json --mode upsert
```

### データの書き出し：`mongoexport`

MongoDB のデータを JSON または CSV 形式でエクスポートします。

```bash
# JSONにエクスポート
mongoexport --db myapp --collection users \
  --out users.json
# CSVにエクスポート
mongoexport --db myapp --collection users \
  --type csv --fields name,email,age --out users.csv
# クエリ付きでエクスポート
mongoexport --db myapp --collection users \
  --query '{"status":"active"}' --out active_users.json
```

### バックアップ：`mongodump`

MongoDB データベースのバイナリバックアップを作成します。

```bash
# データベース全体をバックアップ
mongodump --db myapp --out /backup/
# 特定のコレクションをバックアップ
mongodump --db myapp --collection users --out /backup/
# 圧縮付きでバックアップ
mongodump --db myapp --gzip --out /backup/
```

### リストア：`mongorestore`

バイナリバックアップから MongoDB データをリストアします。

```bash
# データベースをリストア
mongorestore --db myapp /backup/myapp/
# --dropオプション付きでリストア
mongorestore --db myapp --drop /backup/myapp/
# 圧縮されたバックアップをリストア
mongorestore --gzip --db myapp /backup/myapp/
```

## MongoDB のインストールとセットアップ

### MongoDB Community Server

MongoDB Community Edition のダウンロードとインストール。

```bash
# Ubuntu/Debian
sudo apt-get install -y mongodb-org
# MongoDBサービスを開始
sudo systemctl start mongod
# 自動起動を有効化
sudo systemctl enable mongod
# ステータスを確認
sudo systemctl status mongod
```

### Docker インストール

Docker コンテナを使用して MongoDB を実行します。

```bash
# MongoDBイメージをプル
docker pull mongo
# MongoDBコンテナを実行
docker run --name mongodb -d \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  mongo
# コンテナに接続
docker exec -it mongodb mongosh
```

### MongoDB Compass (GUI)

MongoDB の公式 GUI ツールのインストールと使用。

```bash
# mongodb.comからダウンロード
# 接続文字列を使用して接続
mongodb://localhost:27017
# 利用可能な機能:
# - ビジュアルクエリビルダー
# - スキーマ分析
# - パフォーマンス監視
# - インデックス管理
```

## 設定とセキュリティ

### 認証：ユーザーの作成

適切なロールと権限を持つデータベースユーザーを設定します。

```javascript
// 管理者ユーザーの作成
use admin
db.createUser({
  user: "admin",
  pwd: "securepassword",
  roles: [{role: "root", db: "admin"}]
})
// データベースユーザーの作成
use myapp
db.createUser({
  user: "appuser",
  pwd: "password123",
  roles: [{role: "readWrite", db: "myapp"}]
})
```

### 認証の有効化

MongoDB に認証を要求するように設定します。

```bash
# /etc/mongod.confを編集
security:
  authorization: enabled
# MongoDBを再起動
sudo systemctl restart mongod
# 認証を使用して接続
mongosh -u admin -p --authenticationDatabase admin
```

### レプリカセット：`rs.initiate()`

高可用性のためにレプリカセットを設定します。

```javascript
// レプリカセットの初期化
rs.initiate({
  _id: 'myReplicaSet',
  members: [
    { _id: 0, host: 'mongodb1:27017' },
    { _id: 1, host: 'mongodb2:27017' },
    { _id: 2, host: 'mongodb3:27017' },
  ],
})
// レプリカセットの状態を確認
rs.status()
```

### 設定オプション

一般的な MongoDB の設定項目。

```yaml
# mongod.conf の例
storage:
  dbPath: /var/lib/mongodb
systemLog:
  destination: file
  path: /var/log/mongodb/mongod.log
net:
  port: 27017
  bindIp: 127.0.0.1
processManagement:
  fork: true
```

## エラー処理とデバッグ

### 一般的なエラーと解決策

頻繁に発生する MongoDB の問題を特定し修正します。

```javascript
// 接続エラー
// MongoDB が実行中か確認
sudo systemctl status mongod
// ポートの空き状況を確認
netstat -tuln | grep 27017
// 重複キーエラーの処理
try {
  db.users.insertOne({email: "existing@example.com"})
} catch (e) {
  if (e.code === 11000) {
    print("Email already exists")
  }
}
```

### モニタリング：`db.currentOp()`, `db.serverStatus()`

データベース操作とサーバーパフォーマンスを監視します。

```javascript
// 現在の操作を確認
db.currentOp()
// 長時間実行中の操作をキル
db.killOp(operationId)
// サーバーの状態
db.serverStatus()
// 接続統計
db.runCommand({ connPoolStats: 1 })
```

### プロファイリング：`db.setProfilingLevel()`

遅い操作を分析するためにプロファイリングを有効にします。

```javascript
// 遅い操作（>100ms）のプロファイリングを有効化
db.setProfilingLevel(1, { slowms: 100 })
// すべての操作のプロファイリングを有効化
db.setProfilingLevel(2)
// プロファイラデータを表示
db.system.profile.find().sort({ ts: -1 }).limit(5)
// プロファイリングを無効化
db.setProfilingLevel(0)
```

## 高度な操作

### トランザクション：`session.startTransaction()`

データの一貫性のためにマルチドキュメントトランザクションを使用します。

```javascript
// セッションとトランザクションを開始
const session = db.getMongo().startSession()
session.startTransaction()
try {
  const users = session.getDatabase('myapp').users
  const accounts = session.getDatabase('myapp').accounts

  users.insertOne({ name: 'John', balance: 100 })
  accounts.updateOne({ userId: 'john' }, { $inc: { balance: -100 } })

  session.commitTransaction()
} catch (error) {
  session.abortTransaction()
} finally {
  session.endSession()
}
```

### 変更ストリーム：`db.collection.watch()`

コレクションの変更をリアルタイムで監視します。

```javascript
// コレクションの変更を監視
const changeStream = db.users.watch()
changeStream.on('change', (change) => {
  console.log('Change detected:', change)
})
// フィルター付きで監視
const pipeline = [{ $match: { operationType: 'insert' } }]
const changeStream = db.users.watch(pipeline)
```

## 関連リンク

- <router-link to="/database">データベース チートシート</router-link>
- <router-link to="/mysql">MySQL チートシート</router-link>
- <router-link to="/postgresql">PostgreSQL チートシート</router-link>
- <router-link to="/redis">Redis チートシート</router-link>
- <router-link to="/sqlite">SQLite チートシート</router-link>
- <router-link to="/python">Python チートシート</router-link>
- <router-link to="/javascript">JavaScript チートシート</router-link>
- <router-link to="/docker">Docker チートシート</router-link>
- <router-link to="/devops">DevOps チートシート</router-link>

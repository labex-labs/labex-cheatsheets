---
title: 'MongoDB 速查表'
description: '使用我们的 MongoDB 速查表学习，涵盖核心命令、概念和最佳实践。'
pdfUrl: '/cheatsheets/pdf/mongodb-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
MongoDB 速查表
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/zh/learn/mongodb">通过实践实验室学习 MongoDB</a>
</base-disclaimer-title>
<base-disclaimer-content>
通过实践实验室和真实场景学习 MongoDB NoSQL 数据库管理。LabEx 提供全面的 MongoDB 课程，涵盖基本操作、文档查询、聚合管道、索引策略和高级技术。掌握 MongoDB 的面向文档的数据模型，以构建可扩展且灵活的数据库应用程序。
</base-disclaimer-content>
</base-disclaimer>

## 数据库和集合管理

### 显示数据库：`show dbs`

显示 MongoDB 服务器上的所有数据库。

```javascript
// 显示所有数据库
show dbs
// 显示当前数据库
db
// 获取数据库统计信息
db.stats()
// 获取数据库帮助
db.help()
```

### 使用数据库：`use database_name`

切换到指定的数据库（如果不存在则创建）。

```javascript
// 切换到 myapp 数据库
use myapp
// 通过插入数据创建数据库
use newdb
db.users.insertOne({name: "John"})
```

### 删除数据库：`db.dropDatabase()`

删除当前数据库及其所有集合。

```javascript
// 删除当前数据库
db.dropDatabase()
// 确认数据库名称
use myapp
db.dropDatabase()
```

### 显示集合：`show collections`

列出当前数据库中的所有集合。

```javascript
// 显示所有集合
show collections
// 替代方法
db.runCommand("listCollections")
```

### 创建集合：`db.createCollection()`

创建具有可选配置的新集合。

```javascript
// 创建简单集合
db.createCollection('users')
// 创建带选项的集合
db.createCollection('logs', {
  capped: true,
  size: 1000000,
  max: 1000,
})
```

### 删除集合：`db.collection.drop()`

删除集合及其所有文档。

```javascript
// 删除 users 集合
db.users.drop()
// 检查集合是否已删除
show collections
```

## 文档结构与信息

### 集合统计信息：`db.collection.stats()`

显示有关集合的全面统计信息，包括大小、文档计数和索引信息。

```javascript
// 集合统计信息
db.users.stats()
// 计数文档
db.users.countDocuments()
// 估计计数（更快）
db.users.estimatedDocumentCount()
// 检查集合索引
db.users.getIndexes()
```

### 示例文档：`db.collection.findOne()`

检索示例文档以了解结构和数据类型。

```javascript
// 获取一个文档
db.users.findOne()
// 获取特定文档
db.users.findOne({ name: 'John' })
// 获取显示所有字段的文档
db.users.findOne({}, { _id: 0 })
```

### 浏览数据：`db.collection.find().limit()`

通过分页和格式化浏览集合数据。

```javascript
// 前 5 个文档
db.users.find().limit(5)
// 跳过和限制（分页）
db.users.find().skip(10).limit(5)
// 漂亮的格式
db.users.find().pretty()
```

## 文档插入 (创建)

### 插入一个：`db.collection.insertOne()`

向集合中添加单个文档。

```javascript
// 插入单个文档
db.users.insertOne({
  name: 'John Doe',
  age: 30,
  email: 'john@example.com',
})
// 插入自定义 _id
db.users.insertOne({
  _id: 'custom_id_123',
  name: 'Jane Doe',
  status: 'active',
})
```

### 插入多个：`db.collection.insertMany()`

在单个操作中添加多个文档。

```javascript
// 插入多个文档
db.users.insertMany([
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 35 },
  { name: 'Charlie', age: 28 },
])
// 插入带选项的多个文档
db.users.insertMany(
  [
    { name: 'Dave', age: 40 },
    { name: 'Eve', age: 22 },
  ],
  { ordered: false },
)
```

### 插入日期：`new Date()`

添加带有时间戳字段的文档。

```javascript
// 插入当前日期
db.posts.insertOne({
  title: '我的博客文章',
  content: '此处是文章内容',
  createdAt: new Date(),
  publishDate: ISODate('2024-01-15'),
})
```

### 插入嵌套文档

添加包含嵌入式对象和数组的文档。

```javascript
// 插入带嵌套对象的文档
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

## 文档查询 (读取)

### 基本查找：`db.collection.find()`

根据查询条件检索文档。

```javascript
// 查找所有文档
db.users.find()
// 带条件的查找
db.users.find({ age: 30 })
// 带多个条件的查找 (AND)
db.users.find({ age: 30, status: 'active' })
// 带 OR 条件的查找
db.users.find({ $or: [{ age: 25 }, { age: 30 }] })
```

### 投影：`db.collection.find({}, {})`

控制结果中返回哪些字段。

```javascript
// 包含特定字段
db.users.find({}, { name: 1, age: 1 })
// 排除特定字段
db.users.find({}, { password: 0, _id: 0 })
// 嵌套字段投影
db.users.find({}, { 'address.city': 1 })
```

### 查询操作符：`$gt`, `$lt`, `$in`, 等

使用比较和逻辑操作符进行复杂查询。

```javascript
// 大于，小于
db.users.find({ age: { $gt: 25, $lt: 40 } })
// 在数组中
db.users.find({ status: { $in: ['active', 'pending'] } })
// 不等于
db.users.find({ status: { $ne: 'inactive' } })
// 存在
db.users.find({ email: { $exists: true } })
```

### 文本搜索：`$text`, `$regex`

使用文本和模式匹配搜索文档。

```javascript
// 文本搜索 (需要文本索引)
db.posts.find({ $text: { $search: 'mongodb tutorial' } })
// Regex 搜索
db.users.find({ name: { $regex: '^John', $options: 'i' } })
// 不区分大小写的搜索
db.users.find({ email: { $regex: '@gmail.com$' } })
```

## 文档更新

### 更新一个：`db.collection.updateOne()`

修改第一个匹配查询条件的文档。

```javascript
// 更新单个字段
db.users.updateOne({ name: 'John Doe' }, { $set: { age: 31 } })
// 更新多个字段
db.users.updateOne(
  { _id: ObjectId('...') },
  { $set: { age: 31, status: 'updated' } },
)
// Upsert (如果未找到则插入)
db.users.updateOne(
  { name: 'New User' },
  { $set: { age: 25 } },
  { upsert: true },
)
```

### 更新多个：`db.collection.updateMany()`

修改所有匹配查询条件的文档。

```javascript
// 更新多个文档
db.users.updateMany({ status: 'inactive' }, { $set: { status: 'archived' } })
// 增加值
db.posts.updateMany({ category: 'tech' }, { $inc: { views: 1 } })
```

### 更新操作符：`$set`, `$unset`, `$push`

使用各种操作符修改文档字段。

```javascript
// 设置和取消设置字段
db.users.updateOne(
  { name: 'John' },
  { $set: { lastLogin: new Date() }, $unset: { temp: '' } },
)
// 推送到数组
db.users.updateOne({ name: 'John' }, { $push: { hobbies: 'gaming' } })
// 从数组中拉取
db.users.updateOne({ name: 'John' }, { $pull: { hobbies: 'reading' } })
```

### 替换文档：`db.collection.replaceOne()`

替换整个文档，但 \_id 字段除外。

```javascript
// 替换整个文档
db.users.replaceOne(
  { name: 'John Doe' },
  {
    name: 'John Smith',
    age: 35,
    email: 'johnsmith@example.com',
  },
)
```

## 数据聚合

### 基本聚合：`db.collection.aggregate()`

通过聚合管道阶段处理数据。

```javascript
// 分组和计数
db.users.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }])
// 匹配和分组
db.orders.aggregate([
  { $match: { status: 'completed' } },
  { $group: { _id: '$customerId', total: { $sum: '$amount' } } },
])
```

### 常用阶段：`$match`, `$group`, `$sort`

使用管道阶段来转换和分析数据。

```javascript
// 复杂聚合管道
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

### 聚合操作符：`$sum`, `$avg`, `$max`

计算统计值并执行数学运算。

```javascript
// 统计操作
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

### 投影阶段：`$project`

转换文档结构并创建计算字段。

```javascript
// 投影和计算字段
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

## 文档删除

### 删除一个：`db.collection.deleteOne()`

删除第一个匹配查询条件的文档。

```javascript
// 删除单个文档
db.users.deleteOne({ name: 'John Doe' })
// 按 ID 删除
db.users.deleteOne({ _id: ObjectId('...') })
// 带条件的删除
db.posts.deleteOne({ status: 'draft', author: 'unknown' })
```

### 删除多个：`db.collection.deleteMany()`

删除所有匹配查询条件的文档。

```javascript
// 删除多个文档
db.users.deleteMany({ status: 'inactive' })
// 删除所有文档 (请小心!)
db.temp_collection.deleteMany({})
// 带日期条件的删除
db.logs.deleteMany({
  createdAt: { $lt: new Date('2024-01-01') },
})
```

### 查找并删除：`db.collection.findOneAndDelete()`

在一个原子操作中查找并删除文档。

```javascript
// 查找并删除
const deletedDoc = db.users.findOneAndDelete({ status: 'pending' })
// 带选项的查找并删除
db.queue.findOneAndDelete({ processed: false }, { sort: { priority: -1 } })
```

## 索引与性能

### 创建索引：`db.collection.createIndex()`

在字段上创建索引以加速查询。

```javascript
// 单字段索引
db.users.createIndex({ email: 1 })
// 复合索引
db.users.createIndex({ status: 1, createdAt: -1 })
// 用于搜索的文本索引
db.posts.createIndex({ title: 'text', content: 'text' })
// 唯一索引
db.users.createIndex({ email: 1 }, { unique: true })
```

### 索引管理：`getIndexes()`, `dropIndex()`

查看和管理集合上现有的索引。

```javascript
// 列出所有索引
db.users.getIndexes()
// 删除特定索引
db.users.dropIndex({ email: 1 })
// 按名称删除索引
db.users.dropIndex('email_1')
// 删除所有索引，_id 除外
db.users.dropIndexes()
```

### 查询性能：`explain()`

分析查询执行和性能统计信息。

```javascript
// 解释查询执行
db.users.find({ age: { $gt: 25 } }).explain('executionStats')
// 检查是否使用了索引
db.users.find({ email: 'john@example.com' }).explain()
// 分析聚合性能
db.users
  .aggregate([
    { $match: { status: 'active' } },
    { $group: { _id: '$department', count: { $sum: 1 } } },
  ])
  .explain('executionStats')
```

### 性能提示

优化 MongoDB 查询和操作的最佳实践。

```javascript
// 使用投影限制数据传输
db.users.find({ status: 'active' }, { name: 1, email: 1 })
// 限制结果以获得更好的性能
db.posts.find().sort({ createdAt: -1 }).limit(10)
// 使用 hint 强制使用特定索引
db.users.find({ age: 25 }).hint({ age: 1 })
```

## MongoDB Shell 与连接

### 连接到 MongoDB: `mongosh`

启动 MongoDB shell 并连接到不同的实例。

```bash
# 连接到本地 MongoDB
mongosh
# 连接到特定主机和端口
mongosh "mongodb://localhost:27017"
# 连接到远程服务器
mongosh "mongodb://username:password@host:port/database"
# 带选项连接
mongosh --host localhost --port 27017
```

### Shell 帮助程序：`help`, `exit`

获取帮助信息并管理 shell 会话。

```javascript
// 一般帮助
help
// 数据库特定帮助
db.help()
// 集合特定帮助
db.users.help()
// 退出 shell
exit
```

### Shell 变量和设置

配置 shell 行为并使用 JavaScript 变量。

```javascript
// 设置变量
var myQuery = { status: 'active' }
db.users.find(myQuery)
// 配置显示选项
db.users.find().pretty()
// 显示执行时间
db.users.find({ age: 25 }).explain('executionStats')
// 在 shell 中使用 JavaScript
var user = db.users.findOne({ name: 'John' })
print('用户年龄：' + user.age)
```

## 数据导入与导出

### 导入数据：`mongoimport`

从 JSON、CSV 或 TSV 文件加载数据到 MongoDB。

```bash
# 导入 JSON 文件
mongoimport --db myapp --collection users --file users.json
# 导入 CSV 文件
mongoimport --db myapp --collection products \
  --type csv --headerline --file products.csv
# 带 upsert 导入
mongoimport --db myapp --collection users \
  --file users.json --mode upsert
```

### 导出数据：`mongoexport`

将 MongoDB 数据导出为 JSON 或 CSV 格式。

```bash
# 导出为 JSON
mongoexport --db myapp --collection users \
  --out users.json
# 导出为 CSV
mongoexport --db myapp --collection users \
  --type csv --fields name,email,age --out users.csv
# 带查询导出
mongoexport --db myapp --collection users \
  --query '{"status":"active"}' --out active_users.json
```

### 备份：`mongodump`

创建 MongoDB 数据库的二进制备份。

```bash
# 备份整个数据库
mongodump --db myapp --out /backup/
# 备份特定集合
mongodump --db myapp --collection users --out /backup/
# 带压缩备份
mongodump --db myapp --gzip --out /backup/
```

### 恢复：`mongorestore`

从二进制备份中恢复 MongoDB 数据。

```bash
# 恢复数据库
mongorestore --db myapp /backup/myapp/
# 带 drop 恢复
mongorestore --db myapp --drop /backup/myapp/
# 恢复压缩备份
mongorestore --gzip --db myapp /backup/myapp/
```

## MongoDB 安装与设置

### MongoDB 社区服务器

下载并安装 MongoDB 社区版。

```bash
# Ubuntu/Debian
sudo apt-get install -y mongodb-org
# 启动 MongoDB 服务
sudo systemctl start mongod
# 启用自动启动
sudo systemctl enable mongod
# 检查状态
sudo systemctl status mongod
```

### Docker 安装

使用 Docker 容器运行 MongoDB。

```bash
# 拉取 MongoDB 镜像
docker pull mongo
# 运行 MongoDB 容器
docker run --name mongodb -d \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  mongo
# 连接到容器
docker exec -it mongodb mongosh
```

### MongoDB Compass (GUI)

安装并使用 MongoDB 的官方图形界面工具。

```bash
# 从 mongodb.com 下载
# 使用连接字符串连接
mongodb://localhost:27017
# 可用功能:
# - 可视化查询构建器
# - 模式分析
# - 性能监控
# - 索引管理
```

## 配置与安全

### 身份验证：创建用户

设置具有适当角色和权限的数据库用户。

```javascript
// 创建管理员用户
use admin
db.createUser({
  user: "admin",
  pwd: "securepassword",
  roles: [{role: "root", db: "admin"}]
})
// 创建数据库用户
use myapp
db.createUser({
  user: "appuser",
  pwd: "password123",
  roles: [{role: "readWrite", db: "myapp"}]
})
```

### 启用身份验证

配置 MongoDB 要求进行身份验证。

```bash
# 编辑 /etc/mongod.conf
security:
  authorization: enabled
# 重启 MongoDB
sudo systemctl restart mongod
# 带身份验证连接
mongosh -u admin -p --authenticationDatabase admin
```

### 副本集：`rs.initiate()`

设置副本集以实现高可用性。

```javascript
// 初始化副本集
rs.initiate({
  _id: 'myReplicaSet',
  members: [
    { _id: 0, host: 'mongodb1:27017' },
    { _id: 1, host: 'mongodb2:27017' },
    { _id: 2, host: 'mongodb3:27017' },
  ],
})
// 检查副本集状态
rs.status()
```

### 配置选项

常见的 MongoDB 配置设置。

```yaml
# mongod.conf 示例
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

## 错误处理与调试

### 常见错误及解决方案

识别并修复经常遇到的 MongoDB 问题。

```javascript
// 连接错误
// 检查 MongoDB 是否正在运行
sudo systemctl status mongod
// 检查端口是否可用
netstat -tuln | grep 27017
// 重复键错误处理
try {
  db.users.insertOne({email: "existing@example.com"})
} catch (e) {
  if (e.code === 11000) {
    print("电子邮件已存在")
  }
}
```

### 监控：`db.currentOp()`, `db.serverStatus()`

监控数据库操作和服务器性能。

```javascript
// 检查当前操作
db.currentOp()
// 终止长时间运行的操作
db.killOp(operationId)
// 服务器状态
db.serverStatus()
// 连接统计信息
db.runCommand({ connPoolStats: 1 })
```

### 分析：`db.setProfilingLevel()`

启用分析以分析慢速操作。

```javascript
// 启用慢速操作 (>100ms) 的分析
db.setProfilingLevel(1, { slowms: 100 })
// 启用所有操作的分析
db.setProfilingLevel(2)
// 查看分析器数据
db.system.profile.find().sort({ ts: -1 }).limit(5)
// 禁用分析
db.setProfilingLevel(0)
```

## 高级操作

### 事务：`session.startTransaction()`

使用多文档事务来保证数据一致性。

```javascript
// 启动会话和事务
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

### 变更流：`db.collection.watch()`

实时监控集合中的变化。

```javascript
// 监控集合变化
const changeStream = db.users.watch()
changeStream.on('change', (change) => {
  console.log('检测到变更：', change)
})
// 带过滤器的监控
const pipeline = [{ $match: { operationType: 'insert' } }]
const changeStream = db.users.watch(pipeline)
```

## 相关链接

- <router-link to="/database">数据库速查表</router-link>
- <router-link to="/mysql">MySQL 速查表</router-link>
- <router-link to="/postgresql">PostgreSQL 速查表</router-link>
- <router-link to="/redis">Redis 速查表</router-link>
- <router-link to="/sqlite">SQLite 速查表</router-link>
- <router-link to="/python">Python 速查表</router-link>
- <router-link to="/javascript">JavaScript 速查表</router-link>
- <router-link to="/docker">Docker 速查表</router-link>
- <router-link to="/devops">DevOps 速查表</router-link>

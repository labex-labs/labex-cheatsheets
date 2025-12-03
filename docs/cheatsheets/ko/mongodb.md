---
title: 'MongoDB 치트 시트 | LabEx'
description: '이 포괄적인 치트 시트로 MongoDB NoSQL 데이터베이스를 학습하세요. MongoDB 쿼리, 집계, 인덱싱, 샤딩, 복제 및 문서 데이터베이스 관리를 위한 빠른 참조.'
pdfUrl: '/cheatsheets/pdf/mongodb-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
MongoDB 치트 시트
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ko/learn/mongodb">핸즈온 랩으로 MongoDB 학습하기</a>
</base-disclaimer-title>
<base-disclaimer-content>
핸즈온 랩과 실제 시나리오를 통해 MongoDB NoSQL 데이터베이스 관리를 학습하세요. LabEx 는 필수 작업, 문서 쿼리, 집계 파이프라인, 인덱싱 전략 및 고급 기술을 다루는 포괄적인 MongoDB 과정을 제공합니다. MongoDB 의 문서 기반 데이터 모델을 마스터하여 확장 가능하고 유연한 데이터베이스 애플리케이션을 구축하세요.
</base-disclaimer-content>
</base-disclaimer>

## 데이터베이스 및 컬렉션 관리

### 데이터베이스 보기: `show dbs`

MongoDB 서버의 모든 데이터베이스를 표시합니다.

```javascript
// 모든 데이터베이스 보기
show dbs
// 현재 데이터베이스 보기
db
// 데이터베이스 통계 보기
db.stats()
// 데이터베이스 도움말 보기
db.help()
```

### 데이터베이스 사용: `use database_name`

특정 데이터베이스로 전환합니다 (존재하지 않으면 생성됨).

```javascript
// myapp 데이터베이스로 전환
use myapp
// 데이터 삽입을 통해 데이터베이스 생성
use newdb
db.users.insertOne({name: "John"})
```

<BaseQuiz id="mongodb-use-1" correct="B">
  <template #question>
    MongoDB 에서 `use newdb`를 실행하면 어떻게 되나요?
  </template>
  
  <BaseQuizOption value="A">즉시 데이터베이스를 생성합니다</BaseQuizOption>
  <BaseQuizOption value="B" correct>데이터베이스로 전환합니다 (첫 번째 문서를 삽입할 때 생성됨)</BaseQuizOption>
  <BaseQuizOption value="C">데이터베이스를 삭제합니다</BaseQuizOption>
  <BaseQuizOption value="D">데이터베이스의 모든 컬렉션을 표시합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `use` 명령어는 데이터베이스로 전환하지만, MongoDB 는 첫 번째 문서를 삽입할 때까지 데이터베이스를 생성하지 않습니다. 이는 지연 생성 접근 방식입니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 데이터베이스 삭제: `db.dropDatabase()`

현재 데이터베이스와 그 안의 모든 컬렉션을 삭제합니다.

```javascript
// 현재 데이터베이스 삭제
db.dropDatabase()
// 데이터베이스 이름으로 확인
use myapp
db.dropDatabase()
```

### 컬렉션 보기: `show collections`

현재 데이터베이스의 모든 컬렉션을 나열합니다.

```javascript
// 모든 컬렉션 보기
show collections
// 대안 메서드
db.runCommand("listCollections")
```

### 컬렉션 생성: `db.createCollection()`

선택적 구성으로 새 컬렉션을 생성합니다.

```javascript
// 간단한 컬렉션 생성
db.createCollection('users')
// 옵션과 함께 생성
db.createCollection('logs', {
  capped: true,
  size: 1000000,
  max: 1000,
})
```

### 컬렉션 삭제: `db.collection.drop()`

컬렉션과 그 안의 모든 문서를 삭제합니다.

```javascript
// users 컬렉션 삭제
db.users.drop()
// 컬렉션이 삭제되었는지 확인
show collections
```

## 문서 구조 및 정보

### 컬렉션 통계: `db.collection.stats()`

컬렉션의 크기, 문서 수, 인덱스 정보를 포함한 포괄적인 통계를 표시합니다.

```javascript
// 컬렉션 통계
db.users.stats()
// 문서 수 세기
db.users.countDocuments()
// 추정 문서 수 (더 빠름)
db.users.estimatedDocumentCount()
// 컬렉션 인덱스 확인
db.users.getIndexes()
```

### 샘플 문서: `db.collection.findOne()`

구조와 데이터 유형을 이해하기 위해 샘플 문서를 검색합니다.

```javascript
// 문서 하나 가져오기
db.users.findOne()
// 특정 문서 가져오기
db.users.findOne({ name: 'John' })
// 모든 필드를 표시하며 문서 가져오기
db.users.findOne({}, { _id: 0 })
```

### 데이터 탐색: `db.collection.find().limit()`

페이지네이션 및 서식을 사용하여 컬렉션 데이터를 탐색합니다.

```javascript
// 처음 5 개 문서
db.users.find().limit(5)
// 건너뛰기 및 제한 (페이지네이션)
db.users.find().skip(10).limit(5)
// 보기 좋게 서식 지정
db.users.find().pretty()
```

## 문서 삽입 (Create)

### 하나 삽입: `db.collection.insertOne()`

컬렉션에 단일 문서를 추가합니다.

```javascript
// 단일 문서 삽입
db.users.insertOne({
  name: 'John Doe',
  age: 30,
  email: 'john@example.com',
})
// 사용자 지정 _id 로 삽입
db.users.insertOne({
  _id: 'custom_id_123',
  name: 'Jane Doe',
  status: 'active',
})
```

<BaseQuiz id="mongodb-insert-1" correct="A">
  <template #question>
    `db.users.insertOne()` 은 무엇을 반환하나요?
  </template>
  
  <BaseQuizOption value="A" correct>삽입된 문서의 _id 가 포함된 승인 객체</BaseQuizOption>
  <BaseQuizOption value="B">삽입된 문서</BaseQuizOption>
  <BaseQuizOption value="C">아무것도 반환하지 않음</BaseQuizOption>
  <BaseQuizOption value="D">삽입된 문서 수</BaseQuizOption>
  
  <BaseQuizAnswer>
    `insertOne()` 은 `acknowledged: true`와 삽입된 문서의 `_id` 를 포함하는 `insertedId` 를 포함하는 승인 객체를 반환합니다 (사용자 지정 `_id` 가 제공된 경우 해당 `_id` 포함).
  </BaseQuizAnswer>
</BaseQuiz>

### 여러 개 삽입: `db.collection.insertMany()`

단일 작업으로 여러 문서를 추가합니다.

```javascript
// 여러 문서 삽입
db.users.insertMany([
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 35 },
  { name: 'Charlie', age: 28 },
])
// 옵션과 함께 삽입
db.users.insertMany(
  [
    { name: 'Dave', age: 40 },
    { name: 'Eve', age: 22 },
  ],
  { ordered: false },
)
```

### 날짜와 함께 삽입: `new Date()`

타임스탬프 필드를 사용하여 문서를 추가합니다.

```javascript
// 현재 날짜와 함께 삽입
db.posts.insertOne({
  title: 'My Blog Post',
  content: 'Post content here',
  createdAt: new Date(),
  publishDate: ISODate('2024-01-15'),
})
```

### 중첩된 문서 삽입

임베디드 객체 및 배열을 사용하여 문서 추가.

```javascript
// 중첩된 객체와 함께 삽입
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

## 문서 쿼리 (Read)

### 기본 찾기: `db.collection.find()`

쿼리 조건에 따라 문서를 검색합니다.

```javascript
// 모든 문서 찾기
db.users.find()
// 조건과 함께 찾기
db.users.find({ age: 30 })
// 여러 조건 (AND) 과 함께 찾기
db.users.find({ age: 30, status: 'active' })
// OR 조건과 함께 찾기
db.users.find({ $or: [{ age: 25 }, { age: 30 }] })
```

### 투영: `db.collection.find({}, {})`

결과에 반환될 필드를 제어합니다.

```javascript
// 특정 필드 포함
db.users.find({}, { name: 1, age: 1 })
// 특정 필드 제외
db.users.find({}, { password: 0, _id: 0 })
// 중첩된 필드 투영
db.users.find({}, { 'address.city': 1 })
```

### 쿼리 연산자: `$gt`, `$lt`, `$in` 등

복잡한 쿼리를 위해 비교 및 논리 연산자를 사용합니다.

```javascript
// 보다 큼, 보다 작음
db.users.find({ age: { $gt: 25, $lt: 40 } })
// 배열 내
db.users.find({ status: { $in: ['active', 'pending'] } })
// 같지 않음
db.users.find({ status: { $ne: 'inactive' } })
// 존재 여부
db.users.find({ email: { $exists: true } })
```

<BaseQuiz id="mongodb-query-1" correct="B">
  <template #question>
    MongoDB 쿼리에서 `$gt` 는 무엇을 의미하나요?
  </template>
  
  <BaseQuizOption value="A">크거나 같음</BaseQuizOption>
  <BaseQuizOption value="B" correct>보다 큼</BaseQuizOption>
  <BaseQuizOption value="C">그룹화</BaseQuizOption>
  <BaseQuizOption value="D">총합 구하기</BaseQuizOption>
  
  <BaseQuizAnswer>
    `$gt` 는 "보다 큼"을 의미하는 비교 연산자입니다. `{ age: { $gt: 25 } }`와 같은 쿼리에서 사용되어 age 필드가 25 보다 큰 문서를 찾습니다.
  </BaseQuizAnswer>
</BaseQuiz>

### 텍스트 검색: `$text`, `$regex`

텍스트 및 패턴 일치를 사용하여 문서를 검색합니다.

```javascript
// 텍스트 검색 (텍스트 인덱스 필요)
db.posts.find({ $text: { $search: 'mongodb tutorial' } })
// 정규 표현식 검색
db.users.find({ name: { $regex: '^John', $options: 'i' } })
// 대소문자 구분 없는 검색
db.users.find({ email: { $regex: '@gmail.com$' } })
```

## 문서 업데이트

### 하나 업데이트: `db.collection.updateOne()`

쿼리와 일치하는 첫 번째 문서를 수정합니다.

```javascript
// 단일 필드 업데이트
db.users.updateOne({ name: 'John Doe' }, { $set: { age: 31 } })
// 여러 필드 업데이트
db.users.updateOne(
  { _id: ObjectId('...') },
  { $set: { age: 31, status: 'updated' } },
)
// Upsert (찾지 못하면 삽입)
db.users.updateOne(
  { name: 'New User' },
  { $set: { age: 25 } },
  { upsert: true },
)
```

### 여러 개 업데이트: `db.collection.updateMany()`

쿼리와 일치하는 모든 문서를 수정합니다.

```javascript
// 여러 문서 업데이트
db.users.updateMany({ status: 'inactive' }, { $set: { status: 'archived' } })
// 값 증가
db.posts.updateMany({ category: 'tech' }, { $inc: { views: 1 } })
```

### 업데이트 연산자: `$set`, `$unset`, `$push`

다양한 연산자를 사용하여 문서 필드를 수정합니다.

```javascript
// 필드 설정 및 제거
db.users.updateOne(
  { name: 'John' },
  { $set: { lastLogin: new Date() }, $unset: { temp: '' } },
)
// 배열에 추가
db.users.updateOne({ name: 'John' }, { $push: { hobbies: 'gaming' } })
```

<BaseQuiz id="mongodb-update-1" correct="C">
  <template #question>
    MongoDB 업데이트 작업에서 `$set` 은 무엇을 하나요?
  </template>
  
  <BaseQuizOption value="A">필드를 삭제합니다</BaseQuizOption>
  <BaseQuizOption value="B">배열에 요소를 추가합니다</BaseQuizOption>
  <BaseQuizOption value="C" correct>필드의 값을 설정합니다</BaseQuizOption>
  <BaseQuizOption value="D">배열에서 요소를 제거합니다</BaseQuizOption>
  
  <BaseQuizAnswer>
    `$set` 연산자는 문서 내 필드의 값을 설정합니다. 필드가 없으면 생성하고, 존재하면 값을 업데이트합니다.
  </BaseQuizAnswer>
</BaseQuiz>

```javascript
// 배열에서 제거
db.users.updateOne({ name: 'John' }, { $pull: { hobbies: 'reading' } })
```

### 문서 교체: `db.collection.replaceOne()`

\_id 필드를 제외하고 전체 문서를 교체합니다.

```javascript
// 전체 문서 교체
db.users.replaceOne(
  { name: 'John Doe' },
  {
    name: 'John Smith',
    age: 35,
    email: 'johnsmith@example.com',
  },
)
```

## 데이터 집계

### 기본 집계: `db.collection.aggregate()`

집계 파이프라인 단계를 통해 데이터를 처리합니다.

```javascript
// 그룹화 및 개수 세기
db.users.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }])
// 일치 및 그룹화
db.orders.aggregate([
  { $match: { status: 'completed' } },
  { $group: { _id: '$customerId', total: { $sum: '$amount' } } },
])
```

### 일반적인 단계: `$match`, `$group`, `$sort`

파이프라인 단계를 사용하여 데이터를 변환하고 분석합니다.

```javascript
// 복잡한 집계 파이프라인
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

### 집계 연산자: `$sum`, `$avg`, `$max`

통계 값을 계산하고 수학적 연산을 수행합니다.

```javascript
// 통계 연산
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

### 투영 단계: `$project`

문서 구조를 변환하고 계산된 필드를 생성합니다.

```javascript
// 필드 투영 및 계산
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

## 문서 삭제

### 하나 삭제: `db.collection.deleteOne()`

쿼리 조건과 일치하는 첫 번째 문서를 제거합니다.

```javascript
// 단일 문서 삭제
db.users.deleteOne({ name: 'John Doe' })
// ID 로 삭제
db.users.deleteOne({ _id: ObjectId('...') })
// 조건과 함께 삭제
db.posts.deleteOne({ status: 'draft', author: 'unknown' })
```

### 여러 개 삭제: `db.collection.deleteMany()`

쿼리 조건과 일치하는 모든 문서를 제거합니다.

```javascript
// 여러 문서 삭제
db.users.deleteMany({ status: 'inactive' })
// 모든 문서 삭제 (주의!)
db.temp_collection.deleteMany({})
// 날짜 조건과 함께 삭제
db.logs.deleteMany({
  createdAt: { $lt: new Date('2024-01-01') },
})
```

### 찾아서 삭제: `db.collection.findOneAndDelete()`

단일 원자적 작업으로 문서를 찾고 삭제합니다.

```javascript
// 찾아서 삭제
const deletedDoc = db.users.findOneAndDelete({ status: 'pending' })
// 옵션과 함께 찾아서 삭제
db.queue.findOneAndDelete({ processed: false }, { sort: { priority: -1 } })
```

## 인덱싱 및 성능

### 인덱스 생성: `db.collection.createIndex()`

쿼리 속도를 높이기 위해 필드에 인덱스를 생성합니다.

```javascript
// 단일 필드 인덱스
db.users.createIndex({ email: 1 })
// 복합 인덱스
db.users.createIndex({ status: 1, createdAt: -1 })
// 검색을 위한 텍스트 인덱스
db.posts.createIndex({ title: 'text', content: 'text' })
// 고유 인덱스
db.users.createIndex({ email: 1 }, { unique: true })
```

### 인덱스 관리: `getIndexes()`, `dropIndex()`

컬렉션의 기존 인덱스를 보고 관리합니다.

```javascript
// 모든 인덱스 나열
db.users.getIndexes()
// 특정 인덱스 삭제
db.users.dropIndex({ email: 1 })
// 이름으로 인덱스 삭제
db.users.dropIndex('email_1')
// _id 를 제외한 모든 인덱스 삭제
db.users.dropIndexes()
```

### 쿼리 성능: `explain()`

쿼리 실행 및 성능 통계를 분석합니다.

```javascript
// 쿼리 실행 분석
db.users.find({ age: { $gt: 25 } }).explain('executionStats')
// 인덱스 사용 여부 확인
db.users.find({ email: 'john@example.com' }).explain()
// 집계 성능 분석
db.users
  .aggregate([
    { $match: { status: 'active' } },
    { $group: { _id: '$department', count: { $sum: 1 } } },
  ])
  .explain('executionStats')
```

### 성능 팁

MongoDB 쿼리 및 작업을 최적화하기 위한 모범 사례.

```javascript
// 데이터 전송 제한을 위해 투영 사용
db.users.find({ status: 'active' }, { name: 1, email: 1 })
// 성능 향상을 위해 결과 제한
db.posts.find().sort({ createdAt: -1 }).limit(10)
// 특정 인덱스를 강제하기 위해 힌트 사용
db.users.find({ age: 25 }).hint({ age: 1 })
```

## MongoDB 셸 및 연결

### MongoDB 연결: `mongosh`

MongoDB 셸을 시작하고 다른 인스턴스에 연결합니다.

```bash
# 로컬 MongoDB에 연결
mongosh
# 특정 호스트 및 포트에 연결
mongosh "mongodb://localhost:27017"
# 원격 서버에 연결
mongosh "mongodb://username:password@host:port/database"
# 옵션과 함께 연결
mongosh --host localhost --port 27017
```

### 셸 도우미: `help`, `exit`

도움말 정보를 얻고 셸 세션을 관리합니다.

```javascript
// 일반 도움말
help
// 데이터베이스별 도움말
db.help()
// 컬렉션별 도움말
db.users.help()
// 셸 종료
exit
```

### 셸 변수 및 설정

셸 동작을 구성하고 JavaScript 변수를 사용합니다.

```javascript
// 변수 설정
var myQuery = { status: 'active' }
db.users.find(myQuery)
// 표시 옵션 구성
db.users.find().pretty()
// 실행 시간 표시
db.users.find({ age: 25 }).explain('executionStats')
// 셸에서 JavaScript 사용
var user = db.users.findOne({ name: 'John' })
print('User age: ' + user.age)
```

## 데이터 가져오기 및 내보내기

### 데이터 가져오기: `mongoimport`

JSON, CSV 또는 TSV 파일에서 MongoDB 로 데이터를 로드합니다.

```bash
# JSON 파일 가져오기
mongoimport --db myapp --collection users --file users.json
# CSV 파일 가져오기
mongoimport --db myapp --collection products \
  --type csv --headerline --file products.csv
# upsert 모드로 가져오기
mongoimport --db myapp --collection users \
  --file users.json --mode upsert
```

### 데이터 내보내기: `mongoexport`

MongoDB 데이터를 JSON 또는 CSV 형식으로 내보냅니다.

```bash
# JSON으로 내보내기
mongoexport --db myapp --collection users \
  --out users.json
# CSV로 내보내기
mongoexport --db myapp --collection users \
  --type csv --fields name,email,age --out users.csv
# 쿼리와 함께 내보내기
mongoexport --db myapp --collection users \
  --query '{"status":"active"}' --out active_users.json
```

### 백업: `mongodump`

MongoDB 데이터베이스의 바이너리 백업을 생성합니다.

```bash
# 전체 데이터베이스 백업
mongodump --db myapp --out /backup/
# 특정 컬렉션 백업
mongodump --db myapp --collection users --out /backup/
# 압축과 함께 백업
mongodump --db myapp --gzip --out /backup/
```

### 복원: `mongorestore`

바이너리 백업에서 MongoDB 데이터를 복원합니다.

```bash
# 데이터베이스 복원
mongorestore --db myapp /backup/myapp/
# drop 옵션과 함께 복원
mongorestore --db myapp --drop /backup/myapp/
# 압축된 백업 복원
mongorestore --gzip --db myapp /backup/myapp/
```

## MongoDB 설치 및 설정

### MongoDB 커뮤니티 서버

MongoDB 커뮤니티 에디션을 다운로드하고 설치합니다.

```bash
# Ubuntu/Debian
sudo apt-get install -y mongodb-org
# MongoDB 서비스 시작
sudo systemctl start mongod
# 자동 시작 활성화
sudo systemctl enable mongod
# 상태 확인
sudo systemctl status mongod
```

### Docker 설치

Docker 컨테이너를 사용하여 MongoDB 를 실행합니다.

```bash
# MongoDB 이미지 풀
docker pull mongo
# MongoDB 컨테이너 실행
docker run --name mongodb -d \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  mongo
# 컨테이너에 연결
docker exec -it mongodb mongosh
```

### MongoDB Compass (GUI)

MongoDB 의 공식 GUI 도구를 설치하고 사용합니다.

```bash
# mongodb.com에서 다운로드
# 연결 문자열 사용
mongodb://localhost:27017
# 사용 가능한 기능:
# - 시각적 쿼리 빌더
# - 스키마 분석
# - 성능 모니터링
# - 인덱스 관리
```

## 구성 및 보안

### 인증: 사용자 생성

적절한 역할과 권한을 가진 데이터베이스 사용자를 설정합니다.

```javascript
// 관리자 사용자 생성
use admin
db.createUser({
  user: "admin",
  pwd: "securepassword",
  roles: [{role: "root", db: "admin"}]
})
// 데이터베이스 사용자 생성
use myapp
db.createUser({
  user: "appuser",
  pwd: "password123",
  roles: [{role: "readWrite", db: "myapp"}]
})
```

### 인증 활성화

MongoDB 가 인증을 요구하도록 구성합니다.

```bash
# /etc/mongod.conf 편집
security:
  authorization: enabled
# MongoDB 재시작
sudo systemctl restart mongod
# 인증을 사용하여 연결
mongosh -u admin -p --authenticationDatabase admin
```

### 복제본 세트: `rs.initiate()`

고가용성을 위해 복제본 세트를 설정합니다.

```javascript
// 복제본 세트 초기화
rs.initiate({
  _id: 'myReplicaSet',
  members: [
    { _id: 0, host: 'mongodb1:27017' },
    { _id: 1, host: 'mongodb2:27017' },
    { _id: 2, host: 'mongodb3:27017' },
  ],
})
// 복제본 세트 상태 확인
rs.status()
```

### 구성 옵션

일반적인 MongoDB 구성 설정.

```yaml
# mongod.conf 예시
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

## 오류 처리 및 디버깅

### 일반적인 오류 및 해결 방법

자주 발생하는 MongoDB 문제를 식별하고 해결합니다.

```javascript
// 연결 오류
// MongoDB 가 실행 중인지 확인
sudo systemctl status mongod
// 포트 가용성 확인
netstat -tuln | grep 27017
// 중복 키 오류 처리
try {
  db.users.insertOne({email: "existing@example.com"})
} catch (e) {
  if (e.code === 11000) {
    print("Email already exists")
  }
}
```

### 모니터링: `db.currentOp()`, `db.serverStatus()`

데이터베이스 작업 및 서버 성능을 모니터링합니다.

```javascript
// 현재 작업 확인
db.currentOp()
// 장기 실행 작업 종료
db.killOp(operationId)
// 서버 상태
db.serverStatus()
// 연결 통계
db.runCommand({ connPoolStats: 1 })
```

### 프로파일링: `db.setProfilingLevel()`

느린 작업을 분석하기 위해 프로파일링을 활성화합니다.

```javascript
// 느린 작업 (>100ms) 에 대한 프로파일링 활성화
db.setProfilingLevel(1, { slowms: 100 })
// 모든 작업에 대한 프로파일링 활성화
db.setProfilingLevel(2)
// 프로파일러 데이터 보기
db.system.profile.find().sort({ ts: -1 }).limit(5)
// 프로파일링 비활성화
db.setProfilingLevel(0)
```

## 고급 작업

### 트랜잭션: `session.startTransaction()`

데이터 일관성을 위해 다중 문서 트랜잭션을 사용합니다.

```javascript
// 세션 시작 및 트랜잭션
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

### 변경 스트림: `db.collection.watch()`

컬렉션의 실시간 변경 사항을 모니터링합니다.

```javascript
// 컬렉션 변경 사항 모니터링
const changeStream = db.users.watch()
changeStream.on('change', (change) => {
  console.log('Change detected:', change)
})
// 필터와 함께 모니터링
const pipeline = [{ $match: { operationType: 'insert' } }]
const changeStream = db.users.watch(pipeline)
```

## 관련 링크

- <router-link to="/database">데이터베이스 치트 시트</router-link>
- <router-link to="/mysql">MySQL 치트 시트</router-link>
- <router-link to="/postgresql">PostgreSQL 치트 시트</router-link>
- <router-link to="/redis">Redis 치트 시트</router-link>
- <router-link to="/sqlite">SQLite 치트 시트</router-link>
- <router-link to="/python">Python 치트 시트</router-link>
- <router-link to="/javascript">JavaScript 치트 시트</router-link>
- <router-link to="/docker">Docker 치트 시트</router-link>
- <router-link to="/devops">DevOps 치트 시트</router-link>

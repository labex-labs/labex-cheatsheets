---
title: 'Шпаргалка по MongoDB | LabEx'
description: 'Изучите базу данных NoSQL MongoDB с помощью этой исчерпывающей шпаргалки. Краткий справочник по запросам MongoDB, агрегации, индексированию, шардингу, репликации и управлению документоориентированными базами данных.'
pdfUrl: '/cheatsheets/pdf/mongodb-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по MongoDB
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/mongodb">Изучите MongoDB с практическими лабораторными работами</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите управление базами данных NoSQL MongoDB с помощью практических лабораторных работ и сценариев реального мира. LabEx предлагает комплексные курсы по MongoDB, охватывающие основные операции, запросы документов, конвейеры агрегации, стратегии индексирования и продвинутые методы. Освойте документо-ориентированную модель данных MongoDB для создания масштабируемых и гибких приложений баз данных.
</base-disclaimer-content>
</base-disclaimer>

## Управление Базами Данных и Коллекциями

### Показать Базы Данных: `show dbs`

Отображает все базы данных на сервере MongoDB.

```javascript
// Показать все базы данных
show dbs
// Показать текущую базу данных
db
// Получить статистику базы данных
db.stats()
// Получить справку по базе данных
db.help()
```

### Использовать Базу Данных: `use database_name`

Переключиться на определенную базу данных (создается, если не существует).

```javascript
// Переключиться на базу данных myapp
use myapp
// Создать базу данных, вставив данные
use newdb
db.users.insertOne({name: "John"})
```

<BaseQuiz id="mongodb-use-1" correct="B">
  <template #question>
    Что произойдет при выполнении команды <code>use newdb</code> в MongoDB?
  </template>
  
  <BaseQuizOption value="A">Она немедленно создает базу данных</BaseQuizOption>
  <BaseQuizOption value="B" correct>Она переключается на базу данных (создает ее при первой вставке данных)</BaseQuizOption>
  <BaseQuizOption value="C">Она удаляет базу данных</BaseQuizOption>
  <BaseQuizOption value="D">Она показывает все коллекции в базе данных</BaseQuizOption>
  
  <BaseQuizAnswer>
    Команда <code>use</code> переключается на базу данных, но MongoDB не создает базу данных до тех пор, пока вы не вставите первый документ. Это подход ленивого создания.
  </BaseQuizAnswer>
</BaseQuiz>

### Удалить Базу Данных: `db.dropDatabase()`

Удаляет текущую базу данных и все ее коллекции.

```javascript
// Удалить текущую базу данных
db.dropDatabase()
// Подтвердить с именем базы данных
use myapp
db.dropDatabase()
```

### Показать Коллекции: `show collections`

Выводит список всех коллекций в текущей базе данных.

```javascript
// Показать все коллекции
show collections
// Альтернативный метод
db.runCommand("listCollections")
```

### Создать Коллекцию: `db.createCollection()`

Создает новую коллекцию с необязательной конфигурацией.

```javascript
// Создать простую коллекцию
db.createCollection('users')
// Создать с опциями
db.createCollection('logs', {
  capped: true,
  size: 1000000,
  max: 1000,
})
```

### Удалить Коллекцию: `db.collection.drop()`

Удаляет коллекцию и все ее документы.

```javascript
// Удалить коллекцию users
db.users.drop()
// Проверить, была ли коллекция удалена
show collections
```

## Структура и Информация о Документах

### Статистика Коллекции: `db.collection.stats()`

Отображает подробную статистику о коллекции, включая размер, количество документов и информацию об индексах.

```javascript
// Статистика коллекции
db.users.stats()
// Посчитать документы
db.users.countDocuments()
// Оценочное количество (быстрее)
db.users.estimatedDocumentCount()
// Проверить индексы коллекции
db.users.getIndexes()
```

### Образцы Документов: `db.collection.findOne()`

Извлекает образцы документов для понимания структуры и типов данных.

```javascript
// Получить один документ
db.users.findOne()
// Получить конкретный документ
db.users.findOne({ name: 'John' })
// Получить документ со всеми полями
db.users.findOne({}, { _id: 0 })
```

### Исследовать Данные: `db.collection.find().limit()`

Просмотр данных коллекции с постраничной навигацией и форматированием.

```javascript
// Первые 5 документов
db.users.find().limit(5)
// Пропустить и ограничить (пагинация)
db.users.find().skip(10).limit(5)
// Красивое форматирование
db.users.find().pretty()
```

## Вставка Документов (Create)

### Вставить Один: `db.collection.insertOne()`

Добавляет один документ в коллекцию.

```javascript
// Вставить один документ
db.users.insertOne({
  name: 'John Doe',
  age: 30,
  email: 'john@example.com',
})
// Вставить с пользовательским _id
db.users.insertOne({
  _id: 'custom_id_123',
  name: 'Jane Doe',
  status: 'active',
})
```

<BaseQuiz id="mongodb-insert-1" correct="A">
  <template #question>
    Что возвращает <code>db.users.insertOne()</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Объект подтверждения с _id вставленного документа</BaseQuizOption>
  <BaseQuizOption value="B">Вставленный документ</BaseQuizOption>
  <BaseQuizOption value="C">Ничего</BaseQuizOption>
  <BaseQuizOption value="D">Количество вставленных документов</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>insertOne()</code> возвращает объект подтверждения, содержащий <code>acknowledged: true</code> и <code>insertedId</code> с <code>_id</code> вставленного документа (или пользовательский <code>_id</code>, если он был предоставлен).
  </BaseQuizAnswer>
</BaseQuiz>

### Вставить Несколько: `db.collection.insertMany()`

Добавляет несколько документов за одну операцию.

```javascript
// Вставить несколько документов
db.users.insertMany([
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 35 },
  { name: 'Charlie', age: 28 },
])
// Вставить с опциями
db.users.insertMany(
  [
    { name: 'Dave', age: 40 },
    { name: 'Eve', age: 22 },
  ],
  { ordered: false },
)
```

### Вставка с Датой: `new Date()`

Добавление документов с полями временных меток.

```javascript
// Вставить с текущей датой
db.posts.insertOne({
  title: 'Мой Блогпост',
  content: 'Содержимое поста здесь',
  createdAt: new Date(),
  publishDate: ISODate('2024-01-15'),
})
```

### Вставка Вложенных Документов

Добавление документов с внедренными объектами и массивами.

```javascript
// Вставить с вложенными объектами
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

## Запросы Документов (Read)

### Базовый Поиск: `db.collection.find()`

Извлечение документов на основе условий запроса.

```javascript
// Найти все документы
db.users.find()
// Найти с условием
db.users.find({ age: 30 })
// Найти с несколькими условиями (AND)
db.users.find({ age: 30, status: 'active' })
// Найти с условием OR
db.users.find({ $or: [{ age: 25 }, { age: 30 }] })
```

### Проекция: `db.collection.find({}, {})`

Управление тем, какие поля возвращаются в результатах.

```javascript
// Включить определенные поля
db.users.find({}, { name: 1, age: 1 })
// Исключить определенные поля
db.users.find({}, { password: 0, _id: 0 })
// Проекция вложенного поля
db.users.find({}, { 'address.city': 1 })
```

### Операторы Запроса: `$gt`, `$lt`, `$in` и т.д.

Использование операторов сравнения и логических операторов для сложных запросов.

```javascript
// Больше чем, меньше чем
db.users.find({ age: { $gt: 25, $lt: 40 } })
// В массиве
db.users.find({ status: { $in: ['active', 'pending'] } })
// Не равно
db.users.find({ status: { $ne: 'inactive' } })
// Существует
db.users.find({ email: { $exists: true } })
```

<BaseQuiz id="mongodb-query-1" correct="B">
  <template #question>
    Что означает <code>$gt</code> в запросах MongoDB?
  </template>
  
  <BaseQuizOption value="A">Больше или равно</BaseQuizOption>
  <BaseQuizOption value="B" correct>Больше чем</BaseQuizOption>
  <BaseQuizOption value="C">Группировать по</BaseQuizOption>
  <BaseQuizOption value="D">Получить общее</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>$gt</code> — это оператор сравнения, означающий "больше чем". Он используется в запросах вида <code>{ age: { $gt: 25 } }</code> для поиска документов, где поле age больше 25.
  </BaseQuizAnswer>
</BaseQuiz>

### Поиск по Тексту: `$text`, `$regex`

Поиск документов с использованием текста и сопоставления с образцом.

```javascript
// Поиск по тексту (требуется текстовый индекс)
db.posts.find({ $text: { $search: 'mongodb tutorial' } })
// Поиск по регулярному выражению
db.users.find({ name: { $regex: '^John', $options: 'i' } })
// Поиск без учета регистра
db.users.find({ email: { $regex: '@gmail.com$' } })
```

## Обновление Документов

### Обновить Один: `db.collection.updateOne()`

Изменяет первый документ, соответствующий запросу.

```javascript
// Обновить одно поле
db.users.updateOne({ name: 'John Doe' }, { $set: { age: 31 } })
// Обновить несколько полей
db.users.updateOne(
  { _id: ObjectId('...') },
  { $set: { age: 31, status: 'updated' } },
)
// Upsert (вставить, если не найдено)
db.users.updateOne(
  { name: 'New User' },
  { $set: { age: 25 } },
  { upsert: true },
)
```

### Обновить Несколько: `db.collection.updateMany()`

Изменяет все документы, соответствующие запросу.

```javascript
// Обновить несколько документов
db.users.updateMany({ status: 'inactive' }, { $set: { status: 'archived' } })
// Увеличить значения
db.posts.updateMany({ category: 'tech' }, { $inc: { views: 1 } })
```

### Операторы Обновления: `$set`, `$unset`, `$push`

Используйте различные операторы для изменения полей документа.

```javascript
// Установить и удалить поля
db.users.updateOne(
  { name: 'John' },
  { $set: { lastLogin: new Date() }, $unset: { temp: '' } },
)
// Добавить в массив
db.users.updateOne({ name: 'John' }, { $push: { hobbies: 'gaming' } })
```

<BaseQuiz id="mongodb-update-1" correct="C">
  <template #question>
    Что делает <code>$set</code> в операциях обновления MongoDB?
  </template>
  
  <BaseQuizOption value="A">Удаляет поле</BaseQuizOption>
  <BaseQuizOption value="B">Добавляет элемент в массив</BaseQuizOption>
  <BaseQuizOption value="C" correct>Устанавливает значение поля</BaseQuizOption>
  <BaseQuizOption value="D">Удаляет элемент из массива</BaseQuizOption>
  
  <BaseQuizAnswer>
    Оператор <code>$set</code> устанавливает значение поля в документе. Если поле не существует, он его создает. Если оно существует, он обновляет значение.
  </BaseQuizAnswer>
</BaseQuiz>

```javascript
// Удалить из массива
db.users.updateOne({ name: 'John' }, { $pull: { hobbies: 'reading' } })
```

### Заменить Документ: `db.collection.replaceOne()`

Заменяет весь документ, кроме поля \_id.

```javascript
// Заменить весь документ
db.users.replaceOne(
  { name: 'John Doe' },
  {
    name: 'John Smith',
    age: 35,
    email: 'johnsmith@example.com',
  },
)
```

## Агрегация Данных

### Базовая Агрегация: `db.collection.aggregate()`

Обработка данных через конвейер стадий агрегации.

```javascript
// Группировать и считать
db.users.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }])
// Фильтровать и группировать
db.orders.aggregate([
  { $match: { status: 'completed' } },
  { $group: { _id: '$customerId', total: { $sum: '$amount' } } },
])
```

### Общие Стадии: `$match`, `$group`, `$sort`

Используйте стадии конвейера для преобразования и анализа данных.

```javascript
// Сложный конвейер агрегации
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

### Операторы Агрегации: `$sum`, `$avg`, `$max`

Вычисление статистических значений и выполнение математических операций.

```javascript
// Статистические операции
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

### Стадия Проекции: `$project`

Преобразование структуры документа и создание вычисляемых полей.

```javascript
// Проекция и вычисление полей
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

## Удаление Документов

### Удалить Один: `db.collection.deleteOne()`

Удаляет первый документ, соответствующий условию запроса.

```javascript
// Удалить один документ
db.users.deleteOne({ name: 'John Doe' })
// Удалить по ID
db.users.deleteOne({ _id: ObjectId('...') })
// Удалить с условием
db.posts.deleteOne({ status: 'draft', author: 'unknown' })
```

### Удалить Несколько: `db.collection.deleteMany()`

Удаляет все документы, соответствующие условию запроса.

```javascript
// Удалить несколько документов
db.users.deleteMany({ status: 'inactive' })
// Удалить все документы (будьте осторожны!)
db.temp_collection.deleteMany({})
// Удалить с условием по дате
db.logs.deleteMany({
  createdAt: { $lt: new Date('2024-01-01') },
})
```

### Найти и Удалить: `db.collection.findOneAndDelete()`

Находит документ и удаляет его за одну атомарную операцию.

```javascript
// Найти и удалить
const deletedDoc = db.users.findOneAndDelete({ status: 'pending' })
// Найти и удалить с опциями
db.queue.findOneAndDelete({ processed: false }, { sort: { priority: -1 } })
```

## Индексирование и Производительность

### Создать Индекс: `db.collection.createIndex()`

Создает индексы по полям для ускорения запросов.

```javascript
// Индекс по одному полю
db.users.createIndex({ email: 1 })
// Составной индекс
db.users.createIndex({ status: 1, createdAt: -1 })
// Текстовый индекс для поиска
db.posts.createIndex({ title: 'text', content: 'text' })
// Уникальный индекс
db.users.createIndex({ email: 1 }, { unique: true })
```

### Управление Индексами: `getIndexes()`, `dropIndex()`

Просмотр и управление существующими индексами коллекций.

```javascript
// Список всех индексов
db.users.getIndexes()
// Удалить конкретный индекс
db.users.dropIndex({ email: 1 })
// Удалить индекс по имени
db.users.dropIndex('email_1')
// Удалить все индексы, кроме _id
db.users.dropIndexes()
```

### Производительность Запросов: `explain()`

Анализ выполнения запросов и статистики производительности.

```javascript
// Объяснить выполнение запроса
db.users.find({ age: { $gt: 25 } }).explain('executionStats')
// Проверить, используется ли индекс
db.users.find({ email: 'john@example.com' }).explain()
// Проанализировать производительность агрегации
db.users
  .aggregate([
    { $match: { status: 'active' } },
    { $group: { _id: '$department', count: { $sum: 1 } } },
  ])
  .explain('executionStats')
```

### Советы по Производительности

Рекомендуемые практики для оптимизации запросов и операций MongoDB.

```javascript
// Использовать проекцию для ограничения объема передаваемых данных
db.users.find({ status: 'active' }, { name: 1, email: 1 })
// Ограничить результаты для лучшей производительности
db.posts.find().sort({ createdAt: -1 }).limit(10)
// Использовать hint для принудительного использования индекса
db.users.find({ age: 25 }).hint({ age: 1 })
```

## Оболочка MongoDB и Подключение

### Подключение к MongoDB: `mongosh`

Запуск оболочки MongoDB и подключение к различным экземплярам.

```bash
# Подключение к локальному MongoDB
mongosh
# Подключение к определенному хосту и порту
mongosh "mongodb://localhost:27017"
# Подключение к удаленному серверу
mongosh "mongodb://username:password@host:port/database"
# Подключение с опциями
mongosh --host localhost --port 27017
```

### Помощники Оболочки: `help`, `exit`

Получение справочной информации и управление сеансами оболочки.

```javascript
// Общая справка
help
// Справка по базе данных
db.help()
// Справка по коллекции
db.users.help()
// Выход из оболочки
exit
```

### Переменные Оболочки и Настройки

Настройка поведения оболочки и использование переменных JavaScript.

```javascript
// Установить переменную
var myQuery = { status: 'active' }
db.users.find(myQuery)
// Настроить параметры отображения
db.users.find().pretty()
// Показать время выполнения
db.users.find({ age: 25 }).explain('executionStats')
// Использование JavaScript в оболочке
var user = db.users.findOne({ name: 'John' })
print('User age: ' + user.age)
```

## Импорт и Экспорт Данных

### Импорт Данных: `mongoimport`

Загрузка данных из файлов JSON, CSV или TSV в MongoDB.

```bash
# Импорт JSON файла
mongoimport --db myapp --collection users --file users.json
# Импорт CSV файла
mongoimport --db myapp --collection products \
  --type csv --headerline --file products.csv
# Импорт с upsert
mongoimport --db myapp --collection users \
  --file users.json --mode upsert
```

### Экспорт Данных: `mongoexport`

Экспорт данных MongoDB в формат JSON или CSV.

```bash
# Экспорт в JSON
mongoexport --db myapp --collection users \
  --out users.json
# Экспорт в CSV
mongoexport --db myapp --collection users \
  --type csv --fields name,email,age --out users.csv
# Экспорт с запросом
mongoexport --db myapp --collection users \
  --query '{"status":"active"}' --out active_users.json
```

### Резервное Копирование: `mongodump`

Создание бинарных резервных копий баз данных MongoDB.

```bash
# Резервное копирование всей базы данных
mongodump --db myapp --out /backup/
# Резервное копирование конкретной коллекции
mongodump --db myapp --collection users --out /backup/
# Резервное копирование с сжатием
mongodump --db myapp --gzip --out /backup/
```

### Восстановление: `mongorestore`

Восстановление данных MongoDB из бинарных резервных копий.

```bash
# Восстановление базы данных
mongorestore --db myapp /backup/myapp/
# Восстановление с удалением (drop)
mongorestore --db myapp --drop /backup/myapp/
# Восстановление сжатой резервной копии
mongorestore --gzip --db myapp /backup/myapp/
```

## Установка и Настройка MongoDB

### Сервер MongoDB Community

Загрузка и установка MongoDB Community Edition.

```bash
# Ubuntu/Debian
sudo apt-get install -y mongodb-org
# Запуск службы MongoDB
sudo systemctl start mongod
# Включение автозапуска
sudo systemctl enable mongod
# Проверка статуса
sudo systemctl status mongod
```

### Установка через Docker

Запуск MongoDB с использованием контейнеров Docker.

```bash
# Загрузить образ MongoDB
docker pull mongo
# Запустить контейнер MongoDB
docker run --name mongodb -d \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  mongo
# Подключение к контейнеру
docker exec -it mongodb mongosh
```

### MongoDB Compass (GUI)

Установка и использование официального графического инструмента MongoDB.

```bash
# Загрузить с mongodb.com
# Подключение с использованием строки подключения
mongodb://localhost:27017
# Доступные функции:
# - Визуальный конструктор запросов
# - Анализ схемы
# - Мониторинг производительности
# - Управление индексами
```

## Конфигурация и Безопасность

### Аутентификация: Создание Пользователей

Настройка пользователей базы данных с соответствующими ролями и разрешениями.

```javascript
// Создать администратора
use admin
db.createUser({
  user: "admin",
  pwd: "securepassword",
  roles: [{role: "root", db: "admin"}]
})
// Создать пользователя базы данных
use myapp
db.createUser({
  user: "appuser",
  pwd: "password123",
  roles: [{role: "readWrite", db: "myapp"}]
})
```

### Включение Аутентификации

Настройка MongoDB для требования аутентификации.

```bash
# Редактировать /etc/mongod.conf
security:
  authorization: enabled
# Перезапустить MongoDB
sudo systemctl restart mongod
# Подключение с аутентификацией
mongosh -u admin -p --authenticationDatabase admin
```

### Репликация: `rs.initiate()`

Настройка реплика-сетов для высокой доступности.

```javascript
// Инициализировать реплика-сет
rs.initiate({
  _id: 'myReplicaSet',
  members: [
    { _id: 0, host: 'mongodb1:27017' },
    { _id: 1, host: 'mongodb2:27017' },
    { _id: 2, host: 'mongodb3:27017' },
  ],
})
// Проверить статус реплика-сета
rs.status()
```

### Опции Конфигурации

Общие настройки конфигурации MongoDB.

```yaml
# Пример mongod.conf
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

## Обработка Ошибок и Отладка

### Распространенные Ошибки и Решения

Определение и исправление часто встречающихся проблем с MongoDB.

```javascript
// Ошибки подключения
// Проверить, запущена ли MongoDB
sudo systemctl status mongod
// Проверить доступность порта
netstat -tuln | grep 27017
// Обработка ошибок дублирования ключа
try {
  db.users.insertOne({email: "existing@example.com"})
} catch (e) {
  if (e.code === 11000) {
    print("Email already exists")
  }
}
```

### Мониторинг: `db.currentOp()`, `db.serverStatus()`

Мониторинг операций базы данных и производительности сервера.

```javascript
// Проверить текущие операции
db.currentOp()
// Убить долго выполняющуюся операцию
db.killOp(operationId)
// Статус сервера
db.serverStatus()
// Статистика подключения
db.runCommand({ connPoolStats: 1 })
```

### Профилирование: `db.setProfilingLevel()`

Включение профилирования для анализа медленных операций.

```javascript
// Включить профилирование для медленных операций (>100 мс)
db.setProfilingLevel(1, { slowms: 100 })
// Включить профилирование для всех операций
db.setProfilingLevel(2)
// Просмотреть данные профилировщика
db.system.profile.find().sort({ ts: -1 }).limit(5)
// Отключить профилирование
db.setProfilingLevel(0)
```

## Продвинутые Операции

### Транзакции: `session.startTransaction()`

Использование многодокументных транзакций для согласованности данных.

```javascript
// Начать сеанс и транзакцию
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

### Потоки Изменений: `db.collection.watch()`

Наблюдение за изменениями в коллекциях в реальном времени.

```javascript
// Наблюдать за изменениями в коллекции
const changeStream = db.users.watch()
changeStream.on('change', (change) => {
  console.log('Change detected:', change)
})
// Наблюдать с фильтром
const pipeline = [{ $match: { operationType: 'insert' } }]
const changeStream = db.users.watch(pipeline)
```

## Связанные Ссылки

- <router-link to="/database">Шпаргалка по Базам Данных</router-link>
- <router-link to="/mysql">Шпаргалка по MySQL</router-link>
- <router-link to="/postgresql">Шпаргалка по PostgreSQL</router-link>
- <router-link to="/redis">Шпаргалка по Redis</router-link>
- <router-link to="/sqlite">Шпаргалка по SQLite</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>
- <router-link to="/javascript">Шпаргалка по JavaScript</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>

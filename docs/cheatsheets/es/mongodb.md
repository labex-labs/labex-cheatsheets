---
title: 'Hoja de Trucos de MongoDB | LabEx'
description: 'Aprenda la base de datos NoSQL MongoDB con esta hoja de trucos completa. Referencia rápida para consultas, agregación, indexación, sharding, replicación y gestión de bases de datos de documentos en MongoDB.'
pdfUrl: '/cheatsheets/pdf/mongodb-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de MongoDB
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/mongodb">Aprenda MongoDB con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda la gestión de bases de datos NoSQL de MongoDB a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de MongoDB que cubren operaciones esenciales, consultas de documentos, pipelines de agregación, estrategias de indexación y técnicas avanzadas. Domine el modelo de datos basado en documentos de MongoDB para construir aplicaciones de bases de datos escalables y flexibles.
</base-disclaimer-content>
</base-disclaimer>

## Gestión de Bases de Datos y Colecciones

### Mostrar Bases de Datos: `show dbs`

Muestra todas las bases de datos en el servidor MongoDB.

```javascript
// Mostrar todas las bases de datos
show dbs
// Mostrar la base de datos actual
db
// Obtener estadísticas de la base de datos
db.stats()
// Obtener ayuda de la base de datos
db.help()
```

### Usar Base de Datos: `use database_name`

Cambia a una base de datos específica (se crea si no existe).

```javascript
// Cambiar a la base de datos myapp
use myapp
// Crear base de datos insertando datos
use newdb
db.users.insertOne({name: "John"})
```

<BaseQuiz id="mongodb-use-1" correct="B">
  <template #question>
    ¿Qué sucede cuando ejecutas <code>use newdb</code> en MongoDB?
  </template>
  
  <BaseQuizOption value="A">Crea la base de datos inmediatamente</BaseQuizOption>
  <BaseQuizOption value="B" correct>Cambia a la base de datos (la crea cuando insertas datos por primera vez)</BaseQuizOption>
  <BaseQuizOption value="C">Elimina la base de datos</BaseQuizOption>
  <BaseQuizOption value="D">Muestra todas las colecciones en la base de datos</BaseQuizOption>
  
  <BaseQuizAnswer>
    El comando <code>use</code> cambia a una base de datos, pero MongoDB no la crea hasta que insertas el primer documento. Este es un enfoque de creación perezosa.
  </BaseQuizAnswer>
</BaseQuiz>

### Eliminar Base de Datos: `db.dropDatabase()`

Elimina la base de datos actual y todas sus colecciones.

```javascript
// Eliminar la base de datos actual
db.dropDatabase()
// Confirmar con el nombre de la base de datos
use myapp
db.dropDatabase()
```

### Mostrar Colecciones: `show collections`

Lista todas las colecciones en la base de datos actual.

```javascript
// Mostrar todas las colecciones
show collections
// Método alternativo
db.runCommand("listCollections")
```

### Crear Colección: `db.createCollection()`

Crea una nueva colección con configuración opcional.

```javascript
// Crear colección simple
db.createCollection('users')
// Crear con opciones
db.createCollection('logs', {
  capped: true,
  size: 1000000,
  max: 1000,
})
```

### Eliminar Colección: `db.collection.drop()`

Elimina una colección y todos sus documentos.

```javascript
// Eliminar colección users
db.users.drop()
// Verificar si la colección fue eliminada
show collections
```

## Estructura e Información del Documento

### Estadísticas de Colección: `db.collection.stats()`

Muestra estadísticas completas sobre una colección, incluyendo tamaño, recuento de documentos e información de índices.

```javascript
// Estadísticas de la colección
db.users.stats()
// Contar documentos
db.users.countDocuments()
// Conteo estimado (más rápido)
db.users.estimatedDocumentCount()
// Verificar índices de la colección
db.users.getIndexes()
```

### Documentos de Muestra: `db.collection.findOne()`

Recupera documentos de muestra para comprender la estructura y los tipos de datos.

```javascript
// Obtener un documento
db.users.findOne()
// Obtener documento específico
db.users.findOne({ name: 'John' })
// Obtener documento mostrando todos los campos
db.users.findOne({}, { _id: 0 })
```

### Explorar Datos: `db.collection.find().limit()`

Navega por los datos de la colección con paginación y formato.

```javascript
// Primeros 5 documentos
db.users.find().limit(5)
// Omitir y limitar (paginación)
db.users.find().skip(10).limit(5)
// Formato bonito
db.users.find().pretty()
```

## Inserción de Documentos (Crear)

### Insertar Uno: `db.collection.insertOne()`

Añade un único documento a una colección.

```javascript
// Insertar documento único
db.users.insertOne({
  name: 'John Doe',
  age: 30,
  email: 'john@example.com',
})
// Insertar con _id personalizado
db.users.insertOne({
  _id: 'custom_id_123',
  name: 'Jane Doe',
  status: 'active',
})
```

<BaseQuiz id="mongodb-insert-1" correct="A">
  <template #question>
    ¿Qué devuelve <code>db.users.insertOne()</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Un objeto de acuse de recibo con el _id del documento insertado</BaseQuizOption>
  <BaseQuizOption value="B">El documento insertado</BaseQuizOption>
  <BaseQuizOption value="C">Nada</BaseQuizOption>
  <BaseQuizOption value="D">El número de documentos insertados</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>insertOne()</code> devuelve un objeto de acuse de recibo que contiene <code>acknowledged: true</code> y <code>insertedId</code> con el <code>_id</code> del documento insertado (o el <code>_id</code> personalizado si se proporcionó).
  </BaseQuizAnswer>
</BaseQuiz>

### Insertar Varios: `db.collection.insertMany()`

Añade múltiples documentos en una sola operación.

```javascript
// Insertar múltiples documentos
db.users.insertMany([
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 35 },
  { name: 'Charlie', age: 28 },
])
// Insertar con opciones
db.users.insertMany(
  [
    { name: 'Dave', age: 40 },
    { name: 'Eve', age: 22 },
  ],
  { ordered: false },
)
```

### Insertar con Fecha: `new Date()`

Añade documentos con campos de marca de tiempo.

```javascript
// Insertar con fecha actual
db.posts.insertOne({
  title: 'Mi Publicación de Blog',
  content: 'Contenido de la publicación aquí',
  createdAt: new Date(),
  publishDate: ISODate('2024-01-15'),
})
```

### Insertar Documentos Anidados

Añade documentos con objetos y arrays incrustados.

```javascript
// Insertar con objetos anidados
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

## Consulta de Documentos (Leer)

### Búsqueda Básica: `db.collection.find()`

Recupera documentos basados en condiciones de consulta.

```javascript
// Encontrar todos los documentos
db.users.find()
// Encontrar con condición
db.users.find({ age: 30 })
// Encontrar con múltiples condiciones (AND)
db.users.find({ age: 30, status: 'active' })
// Encontrar con condición OR
db.users.find({ $or: [{ age: 25 }, { age: 30 }] })
```

### Proyección: `db.collection.find({}, {})`

Controla qué campos se devuelven en los resultados.

```javascript
// Incluir campos específicos
db.users.find({}, { name: 1, age: 1 })
// Excluir campos específicos
db.users.find({}, { password: 0, _id: 0 })
// Proyección de campo anidado
db.users.find({}, { 'address.city': 1 })
```

### Operadores de Consulta: `$gt`, `$lt`, `$in`, etc.

Utiliza operadores de comparación y lógicos para consultas complejas.

```javascript
// Mayor que, menor que
db.users.find({ age: { $gt: 25, $lt: 40 } })
// En array
db.users.find({ status: { $in: ['active', 'pending'] } })
// No igual
db.users.find({ status: { $ne: 'inactive' } })
// Existe
db.users.find({ email: { $exists: true } })
```

<BaseQuiz id="mongodb-query-1" correct="B">
  <template #question>
    ¿Qué significa <code>$gt</code> en las consultas de MongoDB?
  </template>
  
  <BaseQuizOption value="A">Mayor o igual que</BaseQuizOption>
  <BaseQuizOption value="B" correct>Mayor que</BaseQuizOption>
  <BaseQuizOption value="C">Agrupar por</BaseQuizOption>
  <BaseQuizOption value="D">Obtener total</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>$gt</code> es un operador de comparación que significa "mayor que". Se utiliza en consultas como <code>{ age: { $gt: 25 } }</code> para encontrar documentos donde el campo edad es mayor que 25.
  </BaseQuizAnswer>
</BaseQuiz>

### Búsqueda de Texto: `$text`, `$regex`

Busca documentos usando texto y coincidencia de patrones.

```javascript
// Búsqueda de texto (requiere índice de texto)
db.posts.find({ $text: { $search: 'mongodb tutorial' } })
// Búsqueda Regex
db.users.find({ name: { $regex: '^John', $options: 'i' } })
// Búsqueda insensible a mayúsculas y minúsculas
db.users.find({ email: { $regex: '@gmail.com$' } })
```

## Actualizaciones de Documentos

### Actualizar Uno: `db.collection.updateOne()`

Modifica el primer documento que coincide con la consulta.

```javascript
// Actualizar campo único
db.users.updateOne({ name: 'John Doe' }, { $set: { age: 31 } })
// Actualizar múltiples campos
db.users.updateOne(
  { _id: ObjectId('...') },
  { $set: { age: 31, status: 'updated' } },
)
// Upsert (insertar si no se encuentra)
db.users.updateOne(
  { name: 'New User' },
  { $set: { age: 25 } },
  { upsert: true },
)
```

### Actualizar Varios: `db.collection.updateMany()`

Modifica todos los documentos que coinciden con la condición de consulta.

```javascript
// Actualizar múltiples documentos
db.users.updateMany({ status: 'inactive' }, { $set: { status: 'archived' } })
// Incrementar valores
db.posts.updateMany({ category: 'tech' }, { $inc: { views: 1 } })
```

### Operadores de Actualización: `$set`, `$unset`, `$push`

Utiliza varios operadores para modificar campos de documentos.

```javascript
// Establecer y anular campos
db.users.updateOne(
  { name: 'John' },
  { $set: { lastLogin: new Date() }, $unset: { temp: '' } },
)
// Añadir a array
db.users.updateOne({ name: 'John' }, { $push: { hobbies: 'gaming' } })
```

<BaseQuiz id="mongodb-update-1" correct="C">
  <template #question>
    ¿Qué hace <code>$set</code> en las operaciones de actualización de MongoDB?
  </template>
  
  <BaseQuizOption value="A">Elimina un campo</BaseQuizOption>
  <BaseQuizOption value="B">Añade un elemento a un array</BaseQuizOption>
  <BaseQuizOption value="C" correct>Establece el valor de un campo</BaseQuizOption>
  <BaseQuizOption value="D">Elimina un elemento de un array</BaseQuizOption>
  
  <BaseQuizAnswer>
    El operador <code>$set</code> establece el valor de un campo en un documento. Si el campo no existe, lo crea. Si existe, actualiza el valor.
  </BaseQuizAnswer>
</BaseQuiz>

```javascript
// Extraer de array
db.users.updateOne({ name: 'John' }, { $pull: { hobbies: 'reading' } })
```

### Reemplazar Documento: `db.collection.replaceOne()`

Reemplaza un documento completo excepto el campo \_id.

```javascript
// Reemplazar documento completo
db.users.replaceOne(
  { name: 'John Doe' },
  {
    name: 'John Smith',
    age: 35,
    email: 'johnsmith@example.com',
  },
)
```

## Agregación de Datos

### Agregación Básica: `db.collection.aggregate()`

Procesa datos a través de etapas del pipeline de agregación.

```javascript
// Agrupar y contar
db.users.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }])
// Coincidir y agrupar
db.orders.aggregate([
  { $match: { status: 'completed' } },
  { $group: { _id: '$customerId', total: { $sum: '$amount' } } },
])
```

### Etapas Comunes: `$match`, `$group`, `$sort`

Utiliza etapas del pipeline para transformar y analizar datos.

```javascript
// Pipeline de agregación complejo
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

### Operadores de Agregación: `$sum`, `$avg`, `$max`

Calcula valores estadísticos y realiza operaciones matemáticas.

```javascript
// Operaciones estadísticas
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

### Etapa de Proyección: `$project`

Transforma la estructura del documento y crea campos calculados.

```javascript
// Proyectar y calcular campos
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

## Eliminación de Documentos

### Eliminar Uno: `db.collection.deleteOne()`

Elimina el primer documento que coincide con la condición de consulta.

```javascript
// Eliminar documento único
db.users.deleteOne({ name: 'John Doe' })
// Eliminar por ID
db.users.deleteOne({ _id: ObjectId('...') })
// Eliminar con condición
db.posts.deleteOne({ status: 'draft', author: 'unknown' })
```

### Eliminar Varios: `db.collection.deleteMany()`

Elimina todos los documentos que coinciden con la condición de consulta.

```javascript
// Eliminar múltiples documentos
db.users.deleteMany({ status: 'inactive' })
// Eliminar todos los documentos (¡cuidado!)
db.temp_collection.deleteMany({})
// Eliminar con condición de fecha
db.logs.deleteMany({
  createdAt: { $lt: new Date('2024-01-01') },
})
```

### Encontrar y Eliminar: `db.collection.findOneAndDelete()`

Encuentra un documento y lo elimina en una sola operación atómica.

```javascript
// Encontrar y eliminar
const deletedDoc = db.users.findOneAndDelete({ status: 'pending' })
// Encontrar y eliminar con opciones
db.queue.findOneAndDelete({ processed: false }, { sort: { priority: -1 } })
```

## Indexación y Rendimiento

### Crear Índice: `db.collection.createIndex()`

Crea índices en campos para acelerar las consultas.

```javascript
// Índice de campo único
db.users.createIndex({ email: 1 })
// Índice compuesto
db.users.createIndex({ status: 1, createdAt: -1 })
// Índice de texto para búsqueda
db.posts.createIndex({ title: 'text', content: 'text' })
// Índice único
db.users.createIndex({ email: 1 }, { unique: true })
```

### Gestión de Índices: `getIndexes()`, `dropIndex()`

Ver y gestionar índices existentes en colecciones.

```javascript
// Listar todos los índices
db.users.getIndexes()
// Eliminar índice específico
db.users.dropIndex({ email: 1 })
// Eliminar índice por nombre
db.users.dropIndex('email_1')
// Eliminar todos los índices excepto _id
db.users.dropIndexes()
```

### Rendimiento de Consultas: `explain()`

Analiza la ejecución de consultas y las estadísticas de rendimiento.

```javascript
// Explicar ejecución de consulta
db.users.find({ age: { $gt: 25 } }).explain('executionStats')
// Verificar si se utiliza un índice
db.users.find({ email: 'john@example.com' }).explain()
// Analizar rendimiento de agregación
db.users
  .aggregate([
    { $match: { status: 'active' } },
    { $group: { _id: '$department', count: { $sum: 1 } } },
  ])
  .explain('executionStats')
```

### Consejos de Rendimiento

Prácticas recomendadas para optimizar consultas y operaciones de MongoDB.

```javascript
// Usar proyección para limitar la transferencia de datos
db.users.find({ status: 'active' }, { name: 1, email: 1 })
// Limitar resultados para un mejor rendimiento
db.posts.find().sort({ createdAt: -1 }).limit(10)
// Usar hint para forzar un índice específico
db.users.find({ age: 25 }).hint({ age: 1 })
```

## Shell de MongoDB y Conexión

### Conectarse a MongoDB: `mongosh`

Inicia el shell de MongoDB y conéctate a diferentes instancias.

```bash
# Conectarse a MongoDB local
mongosh
# Conectarse a host y puerto específicos
mongosh "mongodb://localhost:27017"
# Conectarse a servidor remoto
mongosh "mongodb://username:password@host:port/database"
# Conectarse con opciones
mongosh --host localhost --port 27017
```

### Ayudas del Shell: `help`, `exit`

Obtén información de ayuda y gestiona sesiones del shell.

```javascript
// Ayuda general
help
// Ayuda específica de la base de datos
db.help()
// Ayuda específica de la colección
db.users.help()
// Salir del shell
exit
```

### Variables y Configuración del Shell

Configura el comportamiento del shell y utiliza variables de JavaScript.

```javascript
// Establecer variable
var myQuery = { status: 'active' }
db.users.find(myQuery)
// Configurar opciones de visualización
db.users.find().pretty()
// Mostrar tiempo de ejecución
db.users.find({ age: 25 }).explain('executionStats')
// Usar JavaScript en el shell
var user = db.users.findOne({ name: 'John' })
print('User age: ' + user.age)
```

## Importación y Exportación de Datos

### Importar Datos: `mongoimport`

Carga datos desde archivos JSON, CSV o TSV a MongoDB.

```bash
# Importar archivo JSON
mongoimport --db myapp --collection users --file users.json
# Importar archivo CSV
mongoimport --db myapp --collection products \
  --type csv --headerline --file products.csv
# Importar con upsert
mongoimport --db myapp --collection users \
  --file users.json --mode upsert
```

### Exportar Datos: `mongoexport`

Exporta datos de MongoDB a formato JSON o CSV.

```bash
# Exportar a JSON
mongoexport --db myapp --collection users \
  --out users.json
# Exportar a CSV
mongoexport --db myapp --collection users \
  --type csv --fields name,email,age --out users.csv
# Exportar con consulta
mongoexport --db myapp --collection users \
  --query '{"status":"active"}' --out active_users.json
```

### Copia de Seguridad: `mongodump`

Crea copias de seguridad binarias de bases de datos MongoDB.

```bash
# Copia de seguridad de toda la base de datos
mongodump --db myapp --out /backup/
# Copia de seguridad de colección específica
mongodump --db myapp --collection users --out /backup/
# Copia de seguridad con compresión
mongodump --db myapp --gzip --out /backup/
```

### Restauración: `mongorestore`

Restaura datos de MongoDB desde copias de seguridad binarias.

```bash
# Restaurar base de datos
mongorestore --db myapp /backup/myapp/
# Restaurar con eliminación previa
mongorestore --db myapp --drop /backup/myapp/
# Restaurar copia de seguridad comprimida
mongorestore --gzip --db myapp /backup/myapp/
```

## Instalación y Configuración de MongoDB

### Servidor Comunitario de MongoDB

Descarga e instala MongoDB Community Edition.

```bash
# Ubuntu/Debian
sudo apt-get install -y mongodb-org
# Iniciar servicio MongoDB
sudo systemctl start mongod
# Habilitar autoarranque
sudo systemctl enable mongod
# Verificar estado
sudo systemctl status mongod
```

### Instalación con Docker

Ejecuta MongoDB usando contenedores Docker.

```bash
# Descargar imagen de MongoDB
docker pull mongo
# Ejecutar contenedor MongoDB
docker run --name mongodb -d \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  mongo
# Conectarse al contenedor
docker exec -it mongodb mongosh
```

### MongoDB Compass (GUI)

Instala y utiliza la herramienta GUI oficial de MongoDB.

```bash
# Descargar desde mongodb.com
# Conectar usando cadena de conexión
mongodb://localhost:27017
# Características disponibles:
# - Constructor visual de consultas
# - Análisis de esquemas
# - Monitoreo de rendimiento
# - Gestión de índices
```

## Configuración y Seguridad

### Autenticación: Crear Usuarios

Configura usuarios de base de datos con roles y permisos adecuados.

```javascript
// Crear usuario administrador
use admin
db.createUser({
  user: "admin",
  pwd: "securepassword",
  roles: [{role: "root", db: "admin"}]
})
// Crear usuario de base de datos
use myapp
db.createUser({
  user: "appuser",
  pwd: "password123",
  roles: [{role: "readWrite", db: "myapp"}]
})
```

### Habilitar Autenticación

Configura MongoDB para requerir autenticación.

```bash
# Editar /etc/mongod.conf
security:
  authorization: enabled
# Reiniciar MongoDB
sudo systemctl restart mongod
# Conectarse con autenticación
mongosh -u admin -p --authenticationDatabase admin
```

### Conjuntos de Réplicas: `rs.initiate()`

Configura conjuntos de réplicas para alta disponibilidad.

```javascript
// Inicializar conjunto de réplicas
rs.initiate({
  _id: 'myReplicaSet',
  members: [
    { _id: 0, host: 'mongodb1:27017' },
    { _id: 1, host: 'mongodb2:27017' },
    { _id: 2, host: 'mongodb3:27017' },
  ],
})
// Verificar estado del conjunto de réplicas
rs.status()
```

### Opciones de Configuración

Configuraciones comunes de MongoDB.

```yaml
# Ejemplo de mongod.conf
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

## Manejo de Errores y Depuración

### Errores Comunes y Soluciones

Identifica y soluciona problemas frecuentes de MongoDB.

```javascript
// Errores de conexión
// Verificar si MongoDB se está ejecutando
sudo systemctl status mongod
// Verificar disponibilidad del puerto
netstat -tuln | grep 27017
// Manejo de error de clave duplicada
try {
  db.users.insertOne({email: "existing@example.com"})
} catch (e) {
  if (e.code === 11000) {
    print("Email already exists")
  }
}
```

### Monitoreo: `db.currentOp()`, `db.serverStatus()`

Monitorea operaciones de base de datos y rendimiento del servidor.

```javascript
// Revisar operaciones actuales
db.currentOp()
// Matar operación de larga duración
db.killOp(operationId)
// Estado del servidor
db.serverStatus()
// Estadísticas de conexión
db.runCommand({ connPoolStats: 1 })
```

### Perfilado: `db.setProfilingLevel()`

Habilita el perfilado para analizar operaciones lentas.

```javascript
// Habilitar perfilado para operaciones lentas (>100ms)
db.setProfilingLevel(1, { slowms: 100 })
// Habilitar perfilado para todas las operaciones
db.setProfilingLevel(2)
// Ver datos del perfilador
db.system.profile.find().sort({ ts: -1 }).limit(5)
// Deshabilitar perfilado
db.setProfilingLevel(0)
```

## Operaciones Avanzadas

### Transacciones: `session.startTransaction()`

Utiliza transacciones de múltiples documentos para la consistencia de los datos.

```javascript
// Iniciar sesión y transacción
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

### Flujos de Cambio: `db.collection.watch()`

Observa cambios en tiempo real en las colecciones.

```javascript
// Observar cambios en la colección
const changeStream = db.users.watch()
changeStream.on('change', (change) => {
  console.log('Change detected:', change)
})
// Observar con filtro
const pipeline = [{ $match: { operationType: 'insert' } }]
const changeStream = db.users.watch(pipeline)
```

## Enlaces Relevantes

- <router-link to="/database">Hoja de Trucos de Base de Datos</router-link>
- <router-link to="/mysql">Hoja de Trucos de MySQL</router-link>
- <router-link to="/postgresql">Hoja de Trucos de PostgreSQL</router-link>
- <router-link to="/redis">Hoja de Trucos de Redis</router-link>
- <router-link to="/sqlite">Hoja de Trucos de SQLite</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>

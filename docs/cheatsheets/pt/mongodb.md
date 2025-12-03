---
title: 'Folha de Referência MongoDB | LabEx'
description: 'Aprenda o banco de dados NoSQL MongoDB com esta folha de referência abrangente. Referência rápida para consultas MongoDB, agregação, indexação, sharding, replicação e gerenciamento de banco de dados de documentos.'
pdfUrl: '/cheatsheets/pdf/mongodb-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas do MongoDB
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/mongodb">Aprenda MongoDB com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda o gerenciamento de banco de dados NoSQL MongoDB através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de MongoDB cobrindo operações essenciais, consultas de documentos, pipelines de agregação, estratégias de indexação e técnicas avançadas. Domine o modelo de dados baseado em documentos do MongoDB para construir aplicações de banco de dados escaláveis e flexíveis.
</base-disclaimer-content>
</base-disclaimer>

## Gerenciamento de Banco de Dados e Coleções

### Mostrar Bancos de Dados: `show dbs`

Exibe todos os bancos de dados no servidor MongoDB.

```javascript
// Mostrar todos os bancos de dados
show dbs
// Mostrar banco de dados atual
db
// Obter estatísticas do banco de dados
db.stats()
// Obter ajuda do banco de dados
db.help()
```

### Usar Banco de Dados: `use database_name`

Muda para um banco de dados específico (cria se não existir).

```javascript
// Mudar para o banco de dados myapp
use myapp
// Criar banco de dados inserindo dados
use newdb
db.users.insertOne({name: "John"})
```

<BaseQuiz id="mongodb-use-1" correct="B">
  <template #question>
    O que acontece quando você executa `use newdb` no MongoDB?
  </template>
  
  <BaseQuizOption value="A">Ele cria o banco de dados imediatamente</BaseQuizOption>
  <BaseQuizOption value="B" correct>Ele muda para o banco de dados (o cria quando você insere dados pela primeira vez)</BaseQuizOption>
  <BaseQuizOption value="C">Ele deleta o banco de dados</BaseQuizOption>
  <BaseQuizOption value="D">Ele mostra todas as coleções no banco de dados</BaseQuizOption>
  
  <BaseQuizAnswer>
    O comando `use` muda para um banco de dados, mas o MongoDB não o cria até que você insira o primeiro documento. Esta é uma abordagem de criação preguiçosa (lazy creation).
  </BaseQuizAnswer>
</BaseQuiz>

### Deletar Banco de Dados: `db.dropDatabase()`

Exclui o banco de dados atual e todas as suas coleções.

```javascript
// Deletar banco de dados atual
db.dropDatabase()
// Confirmar com o nome do banco de dados
use myapp
db.dropDatabase()
```

### Mostrar Coleções: `show collections`

Lista todas as coleções no banco de dados atual.

```javascript
// Mostrar todas as coleções
show collections
// Método alternativo
db.runCommand("listCollections")
```

### Criar Coleção: `db.createCollection()`

Cria uma nova coleção com configuração opcional.

```javascript
// Criar coleção simples
db.createCollection('users')
// Criar com opções
db.createCollection('logs', {
  capped: true,
  size: 1000000,
  max: 1000,
})
```

### Deletar Coleção: `db.collection.drop()`

Exclui uma coleção e todos os seus documentos.

```javascript
// Deletar coleção users
db.users.drop()
// Verificar se a coleção foi deletada
show collections
```

## Estrutura e Informações do Documento

### Estatísticas da Coleção: `db.collection.stats()`

Exibe estatísticas abrangentes sobre uma coleção, incluindo tamanho, contagem de documentos e informações de índice.

```javascript
// Estatísticas da coleção
db.users.stats()
// Contar documentos
db.users.countDocuments()
// Contagem estimada (mais rápida)
db.users.estimatedDocumentCount()
// Verificar índices da coleção
db.users.getIndexes()
```

### Documentos de Exemplo: `db.collection.findOne()`

Recupera documentos de exemplo para entender a estrutura e os tipos de dados.

```javascript
// Obter um documento
db.users.findOne()
// Obter documento específico
db.users.findOne({ name: 'John' })
// Obter documento com todos os campos mostrados
db.users.findOne({}, { _id: 0 })
```

### Explorar Dados: `db.collection.find().limit()`

Navega pelos dados da coleção com paginação e formatação.

```javascript
// Primeiros 5 documentos
db.users.find().limit(5)
// Pular e limitar (paginação)
db.users.find().skip(10).limit(5)
// Formato bonito (Pretty format)
db.users.find().pretty()
```

## Inserção de Documentos (Criar)

### Inserir Um: `db.collection.insertOne()`

Adiciona um único documento a uma coleção.

```javascript
// Inserir documento único
db.users.insertOne({
  name: 'John Doe',
  age: 30,
  email: 'john@example.com',
})
// Inserir com _id personalizado
db.users.insertOne({
  _id: 'custom_id_123',
  name: 'Jane Doe',
  status: 'active',
})
```

<BaseQuiz id="mongodb-insert-1" correct="A">
  <template #question>
    O que `db.users.insertOne()` retorna?
  </template>
  
  <BaseQuizOption value="A" correct>Um objeto de reconhecimento com o _id do documento inserido</BaseQuizOption>
  <BaseQuizOption value="B">O documento inserido</BaseQuizOption>
  <BaseQuizOption value="C">Nada</BaseQuizOption>
  <BaseQuizOption value="D">O número de documentos inseridos</BaseQuizOption>
  
  <BaseQuizAnswer>
    `insertOne()` retorna um objeto de reconhecimento contendo `acknowledged: true` e `insertedId` com o `_id` do documento inserido (ou o `_id` personalizado, se fornecido).
  </BaseQuizAnswer>
</BaseQuiz>

### Inserir Muitos: `db.collection.insertMany()`

Adiciona múltiplos documentos em uma única operação.

```javascript
// Inserir múltiplos documentos
db.users.insertMany([
  { name: 'Alice', age: 25 },
  { name: 'Bob', age: 35 },
  { name: 'Charlie', age: 28 },
])
// Inserir com opções
db.users.insertMany(
  [
    { name: 'Dave', age: 40 },
    { name: 'Eve', age: 22 },
  ],
  { ordered: false },
)
```

### Inserir com Data: `new Date()`

Adiciona documentos com campos de carimbo de data/hora.

```javascript
// Inserir com data atual
db.posts.insertOne({
  title: 'Meu Post de Blog',
  content: 'Conteúdo do post aqui',
  createdAt: new Date(),
  publishDate: ISODate('2024-01-15'),
})
```

### Inserir Documentos Aninhados

Adiciona documentos com objetos e arrays embutidos.

```javascript
// Inserir com objetos aninhados
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

## Consulta de Documentos (Ler)

### Busca Básica: `db.collection.find()`

Recupera documentos com base em condições de consulta.

```javascript
// Encontrar todos os documentos
db.users.find()
// Encontrar com condição
db.users.find({ age: 30 })
// Encontrar com múltiplas condições (AND)
db.users.find({ age: 30, status: 'active' })
// Encontrar com condição OR
db.users.find({ $or: [{ age: 25 }, { age: 30 }] })
```

### Projeção: `db.collection.find({}, {})`

Controla quais campos são retornados nos resultados.

```javascript
// Incluir campos específicos
db.users.find({}, { name: 1, age: 1 })
// Excluir campos específicos
db.users.find({}, { password: 0, _id: 0 })
// Projeção de campo aninhado
db.users.find({}, { 'address.city': 1 })
```

### Operadores de Consulta: `$gt`, `$lt`, `$in`, etc.

Use operadores de comparação e lógicos para consultas complexas.

```javascript
// Maior que, menor que
db.users.find({ age: { $gt: 25, $lt: 40 } })
// Em array
db.users.find({ status: { $in: ['active', 'pending'] } })
// Diferente de
db.users.find({ status: { $ne: 'inactive' } })
// Existe
db.users.find({ email: { $exists: true } })
```

<BaseQuiz id="mongodb-query-1" correct="B">
  <template #question>
    O que `$gt` significa em consultas MongoDB?
  </template>
  
  <BaseQuizOption value="A">Maior ou igual a</BaseQuizOption>
  <BaseQuizOption value="B" correct>Maior que</BaseQuizOption>
  <BaseQuizOption value="C">Agrupar por</BaseQuizOption>
  <BaseQuizOption value="D">Obter total</BaseQuizOption>
  
  <BaseQuizAnswer>
    `$gt` é um operador de comparação que significa "greater than" (maior que). É usado em consultas como `{ age: { $gt: 25 } }` para encontrar documentos onde o campo idade é maior que 25.
  </BaseQuizAnswer>
</BaseQuiz>

### Busca de Texto: `$text`, `$regex`

Pesquisa documentos usando texto e correspondência de padrões.

```javascript
// Busca de texto (requer índice de texto)
db.posts.find({ $text: { $search: 'mongodb tutorial' } })
// Busca Regex
db.users.find({ name: { $regex: '^John', $options: 'i' } })
// Busca insensível a maiúsculas e minúsculas
db.users.find({ email: { $regex: '@gmail.com$' } })
```

## Atualizações de Documentos

### Atualizar Um: `db.collection.updateOne()`

Modifica o primeiro documento que corresponde à consulta.

```javascript
// Atualizar campo único
db.users.updateOne({ name: 'John Doe' }, { $set: { age: 31 } })
// Atualizar múltiplos campos
db.users.updateOne(
  { _id: ObjectId('...') },
  { $set: { age: 31, status: 'updated' } },
)
// Upsert (inserir se não encontrado)
db.users.updateOne(
  { name: 'New User' },
  { $set: { age: 25 } },
  { upsert: true },
)
```

### Atualizar Muitos: `db.collection.updateMany()`

Modifica todos os documentos que correspondem à consulta.

```javascript
// Atualizar múltiplos documentos
db.users.updateMany({ status: 'inactive' }, { $set: { status: 'archived' } })
// Incrementar valores
db.posts.updateMany({ category: 'tech' }, { $inc: { views: 1 } })
```

### Operadores de Atualização: `$set`, `$unset`, `$push`

Use vários operadores para modificar campos de documentos.

```javascript
// Definir e desdefinir campos
db.users.updateOne(
  { name: 'John' },
  { $set: { lastLogin: new Date() }, $unset: { temp: '' } },
)
// Adicionar a um array
db.users.updateOne({ name: 'John' }, { $push: { hobbies: 'gaming' } })
```

<BaseQuiz id="mongodb-update-1" correct="C">
  <template #question>
    O que `$set` faz nas operações de atualização do MongoDB?
  </template>
  
  <BaseQuizOption value="A">Deleta um campo</BaseQuizOption>
  <BaseQuizOption value="B">Adiciona um elemento a um array</BaseQuizOption>
  <BaseQuizOption value="C" correct>Define o valor de um campo</BaseQuizOption>
  <BaseQuizOption value="D">Remove um elemento de um array</BaseQuizOption>
  
  <BaseQuizAnswer>
    O operador `$set` define o valor de um campo em um documento. Se o campo não existir, ele o cria. Se existir, ele atualiza o valor.
  </BaseQuizAnswer>
</BaseQuiz>

```javascript
// Puxar de um array
db.users.updateOne({ name: 'John' }, { $pull: { hobbies: 'reading' } })
```

### Substituir Documento: `db.collection.replaceOne()`

Substitui um documento inteiro, exceto o campo \_id.

```javascript
// Substituir documento inteiro
db.users.replaceOne(
  { name: 'John Doe' },
  {
    name: 'John Smith',
    age: 35,
    email: 'johnsmith@example.com',
  },
)
```

## Agregação de Dados

### Agregação Básica: `db.collection.aggregate()`

Processa dados através de estágios do pipeline de agregação.

```javascript
// Agrupar e contar
db.users.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }])
// Filtrar e agrupar
db.orders.aggregate([
  { $match: { status: 'completed' } },
  { $group: { _id: '$customerId', total: { $sum: '$amount' } } },
])
```

### Estágios Comuns: `$match`, `$group`, `$sort`

Use estágios de pipeline para transformar e analisar dados.

```javascript
// Pipeline de agregação complexa
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

### Operadores de Agregação: `$sum`, `$avg`, `$max`

Calcula valores estatísticos e realiza operações matemáticas.

```javascript
// Operações estatísticas
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

### Estágio de Projeção: `$project`

Transforma a estrutura do documento e cria campos calculados.

```javascript
// Projetar e calcular campos
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

## Exclusão de Documentos

### Deletar Um: `db.collection.deleteOne()`

Remove o primeiro documento que corresponde à condição de consulta.

```javascript
// Deletar documento único
db.users.deleteOne({ name: 'John Doe' })
// Deletar por ID
db.users.deleteOne({ _id: ObjectId('...') })
// Deletar com condição
db.posts.deleteOne({ status: 'draft', author: 'unknown' })
```

### Deletar Muitos: `db.collection.deleteMany()`

Remove todos os documentos que correspondem à condição de consulta.

```javascript
// Deletar múltiplos documentos
db.users.deleteMany({ status: 'inactive' })
// Deletar todos os documentos (tenha cuidado!)
db.temp_collection.deleteMany({})
// Deletar com condição de data
db.logs.deleteMany({
  createdAt: { $lt: new Date('2024-01-01') },
})
```

### Encontrar e Deletar: `db.collection.findOneAndDelete()`

Encontra um documento e o deleta em uma única operação atômica.

```javascript
// Encontrar e deletar
const deletedDoc = db.users.findOneAndDelete({ status: 'pending' })
// Encontrar e deletar com opções
db.queue.findOneAndDelete({ processed: false }, { sort: { priority: -1 } })
```

## Indexação e Desempenho

### Criar Índice: `db.collection.createIndex()`

Cria índices em campos para acelerar as consultas.

```javascript
// Índice de campo único
db.users.createIndex({ email: 1 })
// Índice composto
db.users.createIndex({ status: 1, createdAt: -1 })
// Índice de texto para busca
db.posts.createIndex({ title: 'text', content: 'text' })
// Índice único
db.users.createIndex({ email: 1 }, { unique: true })
```

### Gerenciamento de Índice: `getIndexes()`, `dropIndex()`

Visualiza e gerencia índices existentes em coleções.

```javascript
// Listar todos os índices
db.users.getIndexes()
// Deletar índice específico
db.users.dropIndex({ email: 1 })
// Deletar índice por nome
db.users.dropIndex('email_1')
// Deletar todos os índices, exceto _id
db.users.dropIndexes()
```

### Desempenho da Consulta: `explain()`

Analisa a execução da consulta e as estatísticas de desempenho.

```javascript
// Explicar execução da consulta
db.users.find({ age: { $gt: 25 } }).explain('executionStats')
// Verificar se o índice é usado
db.users.find({ email: 'john@example.com' }).explain()
// Analisar desempenho da agregação
db.users
  .aggregate([
    { $match: { status: 'active' } },
    { $group: { _id: '$department', count: { $sum: 1 } } },
  ])
  .explain('executionStats')
```

### Dicas de Desempenho

Melhores práticas para otimizar consultas e operações do MongoDB.

```javascript
// Usar projeção para limitar a transferência de dados
db.users.find({ status: 'active' }, { name: 1, email: 1 })
// Limitar resultados para melhor desempenho
db.posts.find().sort({ createdAt: -1 }).limit(10)
// Usar hint para forçar índice específico
db.users.find({ age: 25 }).hint({ age: 1 })
```

## Shell do MongoDB e Conexão

### Conectar ao MongoDB: `mongosh`

Inicia o shell do MongoDB e conecta a diferentes instâncias.

```bash
# Conectar ao MongoDB local
mongosh
# Conectar a host e porta específicos
mongosh "mongodb://localhost:27017"
# Conectar ao servidor remoto
mongosh "mongodb://username:password@host:port/database"
# Conectar com opções
mongosh --host localhost --port 27017
```

### Auxiliares do Shell: `help`, `exit`

Obtém informações de ajuda e gerencia sessões de shell.

```javascript
// Ajuda geral
help
// Ajuda específica do banco de dados
db.help()
// Ajuda específica da coleção
db.users.help()
// Sair do shell
exit
```

### Variáveis e Configurações do Shell

Configura o comportamento do shell e usa variáveis JavaScript.

```javascript
// Definir variável
var myQuery = { status: 'active' }
db.users.find(myQuery)
// Configurar opções de exibição
db.users.find().pretty()
// Mostrar tempo de execução
db.users.find({ age: 25 }).explain('executionStats')
// Usar JavaScript no shell
var user = db.users.findOne({ name: 'John' })
print('User age: ' + user.age)
```

## Importação e Exportação de Dados

### Importar Dados: `mongoimport`

Carrega dados de arquivos JSON, CSV ou TSV para o MongoDB.

```bash
# Importar arquivo JSON
mongoimport --db myapp --collection users --file users.json
# Importar arquivo CSV
mongoimport --db myapp --collection products \
  --type csv --headerline --file products.csv
# Importar com upsert
mongoimport --db myapp --collection users \
  --file users.json --mode upsert
```

### Exportar Dados: `mongoexport`

Exporta dados do MongoDB para o formato JSON ou CSV.

```bash
# Exportar para JSON
mongoexport --db myapp --collection users \
  --out users.json
# Exportar para CSV
mongoexport --db myapp --collection users \
  --type csv --fields name,email,age --out users.csv
# Exportar com consulta
mongoexport --db myapp --collection users \
  --query '{"status":"active"}' --out active_users.json
```

### Backup: `mongodump`

Cria backups binários de bancos de dados MongoDB.

```bash
# Backup de banco de dados inteiro
mongodump --db myapp --out /backup/
# Backup de coleção específica
mongodump --db myapp --collection users --out /backup/
# Backup com compressão
mongodump --db myapp --gzip --out /backup/
```

### Restauração: `mongorestore`

Restaura dados do MongoDB a partir de backups binários.

```bash
# Restaurar banco de dados
mongorestore --db myapp /backup/myapp/
# Restaurar com drop
mongorestore --db myapp --drop /backup/myapp/
# Restaurar backup comprimido
mongorestore --gzip --db myapp /backup/myapp/
```

## Instalação e Configuração do MongoDB

### Servidor Comunitário do MongoDB

Baixa e instala a Edição Comunitária do MongoDB.

```bash
# Ubuntu/Debian
sudo apt-get install -y mongodb-org
# Iniciar serviço MongoDB
sudo systemctl start mongod
# Habilitar inicialização automática
sudo systemctl enable mongod
# Verificar status
sudo systemctl status mongod
```

### Instalação com Docker

Executa o MongoDB usando contêineres Docker.

```bash
# Puxar imagem do MongoDB
docker pull mongo
# Executar contêiner do MongoDB
docker run --name mongodb -d \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  mongo
# Conectar ao contêiner
docker exec -it mongodb mongosh
```

### MongoDB Compass (GUI)

Instala e usa a ferramenta GUI oficial do MongoDB.

```bash
# Baixar de mongodb.com
# Conectar usando string de conexão
mongodb://localhost:27017
# Funcionalidades disponíveis:
# - Construtor de consultas visual
# - Análise de esquema
# - Monitoramento de desempenho
# - Gerenciamento de índices
```

## Configuração e Segurança

### Autenticação: Criar Usuários

Configura usuários de banco de dados com funções e permissões adequadas.

```javascript
// Criar usuário admin
use admin
db.createUser({
  user: "admin",
  pwd: "securepassword",
  roles: [{role: "root", db: "admin"}]
})
// Criar usuário de banco de dados
use myapp
db.createUser({
  user: "appuser",
  pwd: "password123",
  roles: [{role: "readWrite", db: "myapp"}]
})
```

### Habilitar Autenticação

Configura o MongoDB para exigir autenticação.

```bash
# Editar /etc/mongod.conf
security:
  authorization: enabled
# Reiniciar MongoDB
sudo systemctl restart mongod
# Conectar com autenticação
mongosh -u admin -p --authenticationDatabase admin
```

### Conjuntos de Réplicas: `rs.initiate()`

Configura conjuntos de réplicas para alta disponibilidade.

```javascript
// Iniciar conjunto de réplicas
rs.initiate({
  _id: 'myReplicaSet',
  members: [
    { _id: 0, host: 'mongodb1:27017' },
    { _id: 1, host: 'mongodb2:27017' },
    { _id: 2, host: 'mongodb3:27017' },
  ],
})
// Verificar status do conjunto de réplicas
rs.status()
```

### Opções de Configuração

Configurações comuns de configuração do MongoDB.

```yaml
# Exemplo de mongod.conf
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

## Tratamento de Erros e Depuração

### Erros Comuns e Soluções

Identifica e corrige problemas frequentemente encontrados no MongoDB.

```javascript
// Erros de conexão
// Verificar se o MongoDB está rodando
sudo systemctl status mongod
// Verificar disponibilidade da porta
netstat -tuln | grep 27017
// Tratamento de erro de chave duplicada
try {
  db.users.insertOne({email: "existing@example.com"})
} catch (e) {
  if (e.code === 11000) {
    print("Email já existe")
  }
}
```

### Monitoramento: `db.currentOp()`, `db.serverStatus()`

Monitora operações de banco de dados e desempenho do servidor.

```javascript
// Verificar operações atuais
db.currentOp()
// Matar operação de longa duração
db.killOp(operationId)
// Status do servidor
db.serverStatus()
// Estatísticas de conexão
db.runCommand({ connPoolStats: 1 })
```

### Perfilagem: `db.setProfilingLevel()`

Habilita a perfilagem para analisar operações lentas.

```javascript
// Habilitar perfilagem para operações lentas (>100ms)
db.setProfilingLevel(1, { slowms: 100 })
// Habilitar perfilagem para todas as operações
db.setProfilingLevel(2)
// Visualizar dados do perfilador
db.system.profile.find().sort({ ts: -1 }).limit(5)
// Desabilitar perfilagem
db.setProfilingLevel(0)
```

## Operações Avançadas

### Transações: `session.startTransaction()`

Usa transações multi-documento para consistência de dados.

```javascript
// Iniciar sessão e transação
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

### Fluxos de Alteração: `db.collection.watch()`

Observa alterações em tempo real em coleções.

```javascript
// Observar alterações na coleção
const changeStream = db.users.watch()
changeStream.on('change', (change) => {
  console.log('Mudança detectada:', change)
})
// Observar com filtro
const pipeline = [{ $match: { operationType: 'insert' } }]
const changeStream = db.users.watch(pipeline)
```

## Links Relevantes

- <router-link to="/database">Folha de Dicas de Banco de Dados</router-link>
- <router-link to="/mysql">Folha de Dicas de MySQL</router-link>
- <router-link to="/postgresql">Folha de Dicas de PostgreSQL</router-link>
- <router-link to="/redis">Folha de Dicas de Redis</router-link>
- <router-link to="/sqlite">Folha de Dicas de SQLite</router-link>
- <router-link to="/python">Folha de Dicas de Python</router-link>
- <router-link to="/javascript">Folha de Dicas de JavaScript</router-link>
- <router-link to="/docker">Folha de Dicas de Docker</router-link>
- <router-link to="/devops">Folha de Dicas de DevOps</router-link>

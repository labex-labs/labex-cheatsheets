---
title: 'Guia Rápido Redis | LabEx'
description: 'Aprenda o Redis, o armazenamento de dados em memória, com este guia completo. Referência rápida para comandos Redis, estruturas de dados, cache, pub/sub, persistência e soluções de cache de alto desempenho.'
pdfUrl: '/cheatsheets/pdf/redis-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas do Redis
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/redis">Aprenda Redis com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda operações de estrutura de dados na memória do Redis através de laboratórios práticos e cenários do mundo real. O LabEx fornece cursos abrangentes de Redis cobrindo comandos essenciais, estruturas de dados, estratégias de cache, mensagens pub/sub e otimização de desempenho. Domine o cache de alto desempenho e o processamento de dados em tempo real.
</base-disclaimer-content>
</base-disclaimer>

## Instalação e Configuração do Redis

### Docker: `docker run redis`

A maneira mais rápida de colocar o Redis em execução localmente.

```bash
# Execute o Redis no Docker
docker run --name my-redis -p 6379:6379 -d redis
# Conecte-se ao CLI do Redis
docker exec -it my-redis redis-cli
# Execute com armazenamento persistente
docker run --name redis-persistent -p 6379:6379 -v redis-data:/data -d redis
```

### Linux: `sudo apt install redis`

Instale o servidor Redis em sistemas Ubuntu/Debian.

```bash
# Instalar Redis
sudo apt update
sudo apt install redis-server
# Iniciar o serviço Redis
sudo systemctl start redis-server
# Habilitar inicialização automática na inicialização
sudo systemctl enable redis-server
# Verificar status
sudo systemctl status redis
```

### Conectar e Testar: `redis-cli`

Conecte-se ao servidor Redis e verifique a instalação.

```bash
# Conectar ao Redis local
redis-cli
# Testar conexão
redis-cli PING
# Conectar ao Redis remoto
redis-cli -h hostname -p 6379 -a password
# Executar comando único
redis-cli SET mykey "Hello Redis"
```

## Operações Básicas de String

### Definir e Obter: `SET` / `GET`

Armazene valores simples (texto, números, JSON, etc.).

```redis
# Definir um par chave-valor
SET mykey "Hello World"
# Obter valor pela chave
GET mykey
# Definir com expiração (em segundos)
SET session:123 "user_data" EX 3600
# Definir apenas se a chave não existir
SET mykey "new_value" NX
```

<BaseQuiz id="redis-set-get-1" correct="C">
  <template #question>
    O que faz <code>SET mykey "value" EX 3600</code>?
  </template>
  
  <BaseQuizOption value="A">Define a chave com um valor de 3600 bytes</BaseQuizOption>
  <BaseQuizOption value="B">Define a chave apenas se ela existir</BaseQuizOption>
  <BaseQuizOption value="C" correct>Define a chave com um valor que expira após 3600 segundos</BaseQuizOption>
  <BaseQuizOption value="D">Define a chave com 3600 valores diferentes</BaseQuizOption>
  
  <BaseQuizAnswer>
    A opção <code>EX</code> define um tempo de expiração em segundos. <code>SET mykey "value" EX 3600</code> armazena o valor e o exclui automaticamente após 3600 segundos (1 hora).
  </BaseQuizAnswer>
</BaseQuiz>

### Manipulação de String: `APPEND` / `STRLEN`

Modifique e inspecione valores de string.

```redis
# Anexar à string existente
APPEND mykey " - Welcome!"
# Obter o comprimento da string
STRLEN mykey
# Obter substring
GETRANGE mykey 0 4
# Definir substring
SETRANGE mykey 6 "Redis"
```

### Operações Numéricas: `INCR` / `DECR`

Incrementar ou decrementar valores inteiros armazenados no Redis.

```redis
# Incrementar em 1
INCR counter
# Decrementar em 1
DECR counter
# Incrementar por quantidade específica
INCRBY counter 5
# Incrementar float
INCRBYFLOAT price 0.1
```

<BaseQuiz id="redis-incr-1" correct="A">
  <template #question>
    O que acontece se você usar <code>INCR</code> em uma chave que não existe?
  </template>
  
  <BaseQuizOption value="A" correct>O Redis cria a chave com o valor 1</BaseQuizOption>
  <BaseQuizOption value="B">O Redis retorna um erro</BaseQuizOption>
  <BaseQuizOption value="C">O Redis cria a chave com o valor 0</BaseQuizOption>
  <BaseQuizOption value="D">Nada acontece</BaseQuizOption>
  
  <BaseQuizAnswer>
    Se uma chave não existir, <code>INCR</code> a trata como se tivesse o valor 0, a incrementa para 1 e cria a chave. Isso torna <code>INCR</code> útil para inicializar contadores.
  </BaseQuizAnswer>
</BaseQuiz>

### Operações Múltiplas: `MSET` / `MGET`

Trabalhe com múltiplos pares chave-valor de forma eficiente.

```redis
# Definir múltiplas chaves de uma vez
MSET key1 "value1" key2 "value2" key3 "value3"
# Obter múltiplos valores
MGET key1 key2 key3
# Definir múltiplos apenas se nenhum existir
MSETNX key1 "val1" key2 "val2"
```

## Operações de Lista

Listas são sequências ordenadas de strings, úteis como filas ou pilhas.

### Adicionar Elementos: `LPUSH` / `RPUSH`

Adicione elementos à esquerda (cabeça) ou à direita (cauda) de uma lista.

```redis
# Adicionar à cabeça (esquerda)
LPUSH mylist "first"
# Adicionar à cauda (direita)
RPUSH mylist "last"
# Adicionar múltiplos elementos
LPUSH mylist "item1" "item2" "item3"
```

### Remover Elementos: `LPOP` / `RPOP`

Remova e retorne elementos das extremidades da lista.

```redis
# Remover da cabeça
LPOP mylist
# Remover da cauda
RPOP mylist
# Pop bloqueante (espera por elemento)
BLPOP mylist 10
```

### Acessar Elementos: `LRANGE` / `LINDEX`

Recupere elementos ou intervalos de listas.

```redis
# Obter a lista inteira
LRANGE mylist 0 -1
# Obter os 3 primeiros elementos
LRANGE mylist 0 2
# Obter elemento específico pelo índice
LINDEX mylist 0
# Obter o comprimento da lista
LLEN mylist
```

<BaseQuiz id="redis-list-1" correct="B">
  <template #question>
    O que retorna <code>LRANGE mylist 0 -1</code>?
  </template>
  
  <BaseQuizOption value="A">Apenas o primeiro elemento</BaseQuizOption>
  <BaseQuizOption value="B" correct>Todos os elementos na lista</BaseQuizOption>
  <BaseQuizOption value="C">Apenas o último elemento</BaseQuizOption>
  <BaseQuizOption value="D">Um erro</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>LRANGE</code> com <code>0 -1</code> retorna todos os elementos da lista. O <code>0</code> é o índice inicial e <code>-1</code> representa o último elemento, então isso recupera tudo do primeiro ao último elemento.
  </BaseQuizAnswer>
</BaseQuiz>

### Utilitários de Lista: `LSET` / `LTRIM`

Modificar o conteúdo e a estrutura da lista.

```redis
# Definir elemento no índice
LSET mylist 0 "new_value"
# Aparar lista para intervalo
LTRIM mylist 0 99
# Encontrar posição do elemento
LPOS mylist "search_value"
```

## Operações de Conjunto (Set)

Conjuntos são coleções de elementos de string únicos e não ordenados.

### Operações Básicas de Conjunto: `SADD` / `SMEMBERS`

Adicione elementos únicos a conjuntos e recupere todos os membros.

```redis
# Adicionar elementos ao conjunto
SADD myset "apple" "banana" "cherry"
# Obter todos os membros do conjunto
SMEMBERS myset
# Verificar se o elemento existe
SISMEMBER myset "apple"
```

<BaseQuiz id="redis-set-1" correct="C">
  <template #question>
    O que acontece se você tentar adicionar um elemento duplicado a um conjunto Redis?
  </template>
  
  <BaseQuizOption value="A">Cria um erro</BaseQuizOption>
  <BaseQuizOption value="B">Substitui o elemento existente</BaseQuizOption>
  <BaseQuizOption value="C" correct>O duplicado é ignorado e o conjunto permanece inalterado</BaseQuizOption>
  <BaseQuizOption value="D">Cria uma lista em vez disso</BaseQuizOption>
  
  <BaseQuizAnswer>
    Os conjuntos Redis contêm apenas elementos únicos. Se você tentar adicionar um elemento que já existe, o Redis o ignora e retorna 0 (indicando que nenhum elemento foi adicionado). O conjunto permanece inalterado.
  </BaseQuizAnswer>
</BaseQuiz>
# Obter tamanho do conjunto
SCARD myset
```

### Modificações de Conjunto: `SREM` / `SPOP`

Remova elementos de conjuntos de maneiras diferentes.

```redis
# Remover elementos específicos
SREM myset "banana"
# Remover e retornar elemento aleatório
SPOP myset
# Obter elemento aleatório sem remover
SRANDMEMBER myset
```

### Operações de Conjunto: `SINTER` / `SUNION`

Execute operações matemáticas de conjunto.

```redis
# Interseção de conjuntos
SINTER set1 set2
# União de conjuntos
SUNION set1 set2
# Diferença de conjuntos
SDIFF set1 set2
# Armazenar resultado em novo conjunto
SINTERSTORE result set1 set2
```

### Utilitários de Conjunto: `SMOVE` / `SSCAN`

Manipulação avançada de conjuntos e varredura.

```redis
# Mover elemento entre conjuntos
SMOVE source_set dest_set "element"
# Varredura de conjunto incrementalmente
SSCAN myset 0 MATCH "a*" COUNT 10
```

## Operações de Hash

Hashes armazenam pares campo-valor, como mini objetos JSON ou dicionários.

### Operações Básicas de Hash: `HSET` / `HGET`

Defina e recupere campos de hash individuais.

```redis
# Definir campo de hash
HSET user:123 name "John Doe" age 30
# Obter campo de hash
HGET user:123 name
# Definir múltiplos campos
HMSET user:123 email "john@example.com" city "NYC"
# Obter múltiplos campos
HMGET user:123 name age email
```

### Inspeção de Hash: `HKEYS` / `HVALS`

Examine a estrutura e o conteúdo do hash.

```redis
# Obter todos os nomes de campo
HKEYS user:123
# Obter todos os valores
HVALS user:123
# Obter todos os campos e valores
HGETALL user:123
# Obter número de campos
HLEN user:123
```

### Utilitários de Hash: `HEXISTS` / `HDEL`

Verifique a existência e remova campos de hash.

```redis
# Verificar se o campo existe
HEXISTS user:123 email
# Excluir campos
HDEL user:123 age city
# Incrementar campo de hash
HINCRBY user:123 age 1
# Incrementar por float
HINCRBYFLOAT user:123 balance 10.50
```

### Varredura de Hash: `HSCAN`

Iterar sobre hashes grandes incrementalmente.

```redis
# Varredura de campos de hash
HSCAN user:123 0
# Varredura com correspondência de padrão
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## Operações de Conjunto Ordenado (Sorted Set)

Conjuntos ordenados combinam a exclusividade de conjuntos com ordenação baseada em pontuações.

### Operações Básicas: `ZADD` / `ZRANGE`

Adicione membros pontuados e recupere intervalos.

```redis
# Adicionar membros com pontuações
ZADD leaderboard 100 "player1" 200 "player2"
# Obter membros por classificação (baseado em 0)
ZRANGE leaderboard 0 -1
# Obter com pontuações
ZRANGE leaderboard 0 -1 WITHSCORES
# Obter por intervalo de pontuação
ZRANGEBYSCORE leaderboard 100 200
```

### Informações do Conjunto Ordenado: `ZCARD` / `ZSCORE`

Obtenha informações sobre membros do conjunto ordenado.

```redis
# Obter tamanho do conjunto
ZCARD leaderboard
# Obter pontuação do membro
ZSCORE leaderboard "player1"
# Obter classificação do membro
ZRANK leaderboard "player1"
# Contar membros no intervalo de pontuação
ZCOUNT leaderboard 100 200
```

### Modificações: `ZREM` / `ZINCRBY`

Remova membros e modifique pontuações.

```redis
# Remover membros
ZREM leaderboard "player1"
# Incrementar pontuação do membro
ZINCRBY leaderboard 10 "player2"
# Remover por classificação
ZREMRANGEBYRANK leaderboard 0 2
# Remover por pontuação
ZREMRANGEBYSCORE leaderboard 0 100
```

### Avançado: `ZUNIONSTORE` / `ZINTERSTORE`

Combine múltiplos conjuntos ordenados.

```redis
# União de conjuntos ordenados
ZUNIONSTORE result 2 set1 set2
# Interseção com pesos
ZINTERSTORE result 2 set1 set2 WEIGHTS 1 2
# Com função de agregação
ZUNIONSTORE result 2 set1 set2 AGGREGATE MAX
```

## Gerenciamento de Chaves

### Inspeção de Chaves: `KEYS` / `EXISTS`

Encontre chaves usando padrões e verifique a existência.

```redis
# Obter todas as chaves (use com cuidado em produção)
KEYS *
# Chaves com padrão
KEYS user:*
# Chaves terminando com padrão
KEYS *:profile
# Coringa de caractere único
KEYS order:?
# Verificar se a chave existe
EXISTS mykey
```

### Informações da Chave: `TYPE` / `TTL`

Obtenha metadados da chave e informações de expiração.

```redis
# Obter tipo de dados da chave
TYPE mykey
# Obter tempo de vida (segundos)
TTL mykey
# Obter TTL em milissegundos
PTTL mykey
# Remover expiração
PERSIST mykey
```

### Operações de Chave: `RENAME` / `DEL`

Renomear, excluir e mover chaves.

```redis
# Renomear chave
RENAME oldkey newkey
# Renomear apenas se a nova chave não existir
RENAMENX oldkey newkey
# Excluir chaves
DEL key1 key2 key3
# Mover chave para banco de dados diferente
MOVE mykey 1
```

### Expiração: `EXPIRE` / `EXPIREAT`

Defina tempos de expiração de chave.

```redis
# Definir expiração em segundos
EXPIRE mykey 3600
# Definir expiração em carimbo de data/hora específico
EXPIREAT mykey 1609459200
# Definir expiração em milissegundos
PEXPIRE mykey 60000
```

## Gerenciamento de Banco de Dados

### Seleção de Banco de Dados: `SELECT` / `FLUSHDB`

Gerencie múltiplos bancos de dados dentro do Redis.

```redis
# Selecionar banco de dados (0-15 por padrão)
SELECT 0
# Limpar banco de dados atual
FLUSHDB
# Limpar todos os bancos de dados
FLUSHALL
# Obter tamanho do banco de dados atual
DBSIZE
```

### Informações do Servidor: `INFO` / `PING`

Obtenha estatísticas do servidor e teste a conectividade.

```redis
# Testar conexão com o servidor
PING
# Obter informações do servidor
INFO
# Obter seção de informações específica
INFO memory
INFO replication
# Obter tempo do servidor
TIME
```

### Persistência: `SAVE` / `BGSAVE`

Controle a persistência de dados e backups do Redis.

```redis
# Salvamento síncrono (bloqueia o servidor)
SAVE
# Salvamento em segundo plano (não bloqueante)
BGSAVE
# Obter hora do último salvamento
LASTSAVE
# Reescrever arquivo AOF
BGREWRITEAOF
```

### Configuração: `CONFIG GET` / `CONFIG SET`

Visualizar e modificar a configuração do Redis.

```redis
# Obter toda a configuração
CONFIG GET *
# Obter configuração específica
CONFIG GET maxmemory
# Definir configuração
CONFIG SET timeout 300
# Resetar estatísticas
CONFIG RESETSTAT
```

## Monitoramento de Desempenho

### Monitoramento em Tempo Real: `MONITOR` / `SLOWLOG`

Rastreie comandos e identifique gargalos de desempenho.

```redis
# Monitorar todos os comandos em tempo real
MONITOR
# Obter log de consultas lentas
SLOWLOG GET 10
# Obter comprimento do log lento
SLOWLOG LEN
# Resetar log lento
SLOWLOG RESET
```

### Análise de Memória: `MEMORY USAGE` / `MEMORY STATS`

Analise o consumo de memória e otimização.

```redis
# Obter uso de memória da chave
MEMORY USAGE mykey
# Obter estatísticas de memória
MEMORY STATS
# Obter relatório do médico de memória
MEMORY DOCTOR
# Limpar memória
MEMORY PURGE
```

### Informações do Cliente: `CLIENT LIST`

Monitore clientes conectados e conexões.

```redis
# Listar todos os clientes
CLIENT LIST
# Obter informações do cliente
CLIENT INFO
# Encerrar conexão do cliente
CLIENT KILL ip:port
# Definir nome do cliente
CLIENT SETNAME "my-app"
```

### Benchmarking: `redis-benchmark`

Teste o desempenho do Redis com a ferramenta de benchmark integrada.

```bash
# Benchmark básico
redis-benchmark
# Operações específicas
redis-benchmark -t SET,GET -n 100000
# Tamanho de carga útil personalizado
redis-benchmark -d 1024 -t SET -n 10000
```

## Recursos Avançados

### Transações: `MULTI` / `EXEC`

Execute múltiplos comandos atomicamente.

```redis
# Iniciar transação
MULTI
SET key1 "value1"
INCR counter
# Executar todos os comandos
EXEC
# Descartar transação
DISCARD
# Observar chaves para alterações
WATCH mykey
```

### Pub/Sub: `PUBLISH` / `SUBSCRIBE`

Implemente passagem de mensagens entre clientes.

```redis
# Assinar canal
SUBSCRIBE news sports
# Publicar mensagem
PUBLISH news "Breaking: Redis 7.0 released!"
# Assinatura de padrão
PSUBSCRIBE news:*
# Cancelar assinatura
UNSUBSCRIBE news
```

### Scripting Lua: `EVAL` / `SCRIPT`

Execute scripts Lua personalizados atomicamente.

```redis
# Executar script Lua
EVAL "return redis.call('SET', 'key', 'value')" 0
# Carregar script e obter SHA
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# Executar por SHA
EVALSHA sha1 1 mykey
# Verificar existência do script
SCRIPT EXISTS sha1
```

### Streams: `XADD` / `XREAD`

Trabalhe com streams do Redis para dados semelhantes a logs.

```redis
# Adicionar entrada ao stream
XADD mystream * field1 value1 field2 value2
# Ler do stream
XREAD STREAMS mystream 0
# Obter comprimento do stream
XLEN mystream
# Criar grupo de consumidores
XGROUP CREATE mystream mygroup 0
```

## Visão Geral dos Tipos de Dados

### Strings: Tipo mais versátil

Pode armazenar texto, números, JSON, dados binários. Tamanho máximo: 512MB. Usado para: cache, contadores, flags.

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### Listas: Coleções ordenadas

Listas ligadas de strings. Usado para: filas, pilhas, feeds de atividade, itens recentes.

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### Conjuntos (Sets): Coleções únicas

Coleções não ordenadas de strings únicas. Usado para: tags, visitantes únicos, relacionamentos.

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Dicas de Configuração do Redis

### Gerenciamento de Memória

Configure limites de memória e políticas de despejo (eviction).

```redis
# Definir limite de memória
CONFIG SET maxmemory 2gb
# Definir política de despejo
CONFIG SET maxmemory-policy allkeys-lru
# Verificar uso de memória
INFO memory
```

### Configurações de Persistência

Configure opções de durabilidade de dados.

```redis
# Habilitar AOF
CONFIG SET appendonly yes
# Definir intervalos de salvamento
CONFIG SET save "900 1 300 10 60 10000"
# Configurações de reescrita AOF
CONFIG SET auto-aof-rewrite-percentage 100
```

### Configurações de Segurança

Configurações básicas de segurança para o Redis.

```redis
# Definir senha
CONFIG SET requirepass mypassword
# Autenticar
AUTH mypassword
# Desabilitar comandos perigosos
CONFIG SET rename-command FLUSHALL ""
# Definir timeout
CONFIG SET timeout 300
# TCP keep alive
CONFIG SET tcp-keepalive 60
# Máximo de clientes
CONFIG SET maxclients 10000
```

### Ajuste de Desempenho

Otimize o Redis para melhor desempenho.

```redis
# Habilitar pipelining para múltiplos comandos
# Usar pool de conexões
# Configurar política maxmemory apropriada
# Monitorar consultas lentas regularmente
# Usar estruturas de dados apropriadas para casos de uso
```

## Links Relevantes

- <router-link to="/database">Folha de Dicas de Banco de Dados</router-link>
- <router-link to="/mysql">Folha de Dicas do MySQL</router-link>
- <router-link to="/postgresql">Folha de Dicas do PostgreSQL</router-link>
- <router-link to="/mongodb">Folha de Dicas do MongoDB</router-link>
- <router-link to="/sqlite">Folha de Dicas do SQLite</router-link>
- <router-link to="/python">Folha de Dicas do Python</router-link>
- <router-link to="/javascript">Folha de Dicas do JavaScript</router-link>
- <router-link to="/devops">Folha de Dicas de DevOps</router-link>

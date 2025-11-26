---
title: 'Guia Rápido Redis'
description: 'Aprenda Redis com nosso guia completo cobrindo comandos essenciais, conceitos e melhores práticas.'
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
Aprenda operações de estrutura de dados na memória do Redis através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Redis cobrindo comandos essenciais, estruturas de dados, estratégias de cache, mensagens pub/sub e otimização de desempenho. Domine o cache de alto desempenho e o processamento de dados em tempo real.
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
# Instale o Redis
sudo apt update
sudo apt install redis-server
# Inicie o serviço Redis
sudo systemctl start redis-server
# Habilite a inicialização automática na inicialização
sudo systemctl enable redis-server
# Verifique o status
sudo systemctl status redis
```

### Conectar e Testar: `redis-cli`

Conecte-se ao servidor Redis e verifique a instalação.

```bash
# Conecte-se ao Redis local
redis-cli
# Teste a conexão
redis-cli PING
# Conecte-se ao Redis remoto
redis-cli -h hostname -p 6379 -a password
# Execute um único comando
redis-cli SET mykey "Hello Redis"
```

## Operações Básicas de String

### Definir e Obter: `SET` / `GET`

Armazene valores simples (texto, números, JSON, etc.).

```redis
# Defina um par chave-valor
SET mykey "Hello World"
# Obtenha o valor pela chave
GET mykey
# Defina com expiração (em segundos)
SET session:123 "user_data" EX 3600
# Defina apenas se a chave não existir
SET mykey "new_value" NX
```

### Manipulação de String: `APPEND` / `STRLEN`

Modifique e inspecione valores de string.

```redis
# Anexe à string existente
APPEND mykey " - Welcome!"
# Obtenha o comprimento da string
STRLEN mykey
# Obtenha substring
GETRANGE mykey 0 4
# Defina substring
SETRANGE mykey 6 "Redis"
```

### Operações Numéricas: `INCR` / `DECR`

Incremente ou decremente valores inteiros armazenados no Redis.

```redis
# Incremente em 1
INCR counter
# Decremente em 1
DECR counter
# Incremente por um valor específico
INCRBY counter 5
# Incremente float
INCRBYFLOAT price 0.1
```

### Operações Múltiplas: `MSET` / `MGET`

Trabalhe com vários pares chave-valor de forma eficiente.

```redis
# Defina várias chaves de uma vez
MSET key1 "value1" key2 "value2" key3 "value3"
# Obtenha múltiplos valores
MGET key1 key2 key3
# Defina múltiplos apenas se nenhum existir
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
# Obtenha a lista inteira
LRANGE mylist 0 -1
# Obtenha os primeiros 3 elementos
LRANGE mylist 0 2
# Obtenha um elemento específico pelo índice
LINDEX mylist 0
# Obtenha o comprimento da lista
LLEN mylist
```

### Utilitários de Lista: `LSET` / `LTRIM`

Modifique o conteúdo e a estrutura da lista.

```redis
# Defina o elemento no índice
LSET mylist 0 "new_value"
# Corte a lista para o intervalo
LTRIM mylist 0 99
# Encontre a posição do elemento
LPOS mylist "search_value"
```

## Operações de Conjunto (Set)

Conjuntos são coleções de elementos de string únicos e não ordenados.

### Operações Básicas de Conjunto: `SADD` / `SMEMBERS`

Adicione elementos únicos a conjuntos e recupere todos os membros.

```redis
# Adicione elementos ao conjunto
SADD myset "apple" "banana" "cherry"
# Obtenha todos os membros do conjunto
SMEMBERS myset
# Verifique se o elemento existe
SISMEMBER myset "apple"
# Obtenha o tamanho do conjunto
SCARD myset
```

### Modificações de Conjunto: `SREM` / `SPOP`

Remova elementos de conjuntos de maneiras diferentes.

```redis
# Remova elementos específicos
SREM myset "banana"
# Remova e retorne um elemento aleatório
SPOP myset
# Obtenha um elemento aleatório sem remover
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
# Armazene o resultado em um novo conjunto
SINTERSTORE result set1 set2
```

### Utilitários de Conjunto: `SMOVE` / `SSCAN`

Manipulação avançada de conjuntos e varredura.

```redis
# Mova o elemento entre conjuntos
SMOVE source_set dest_set "element"
# Varra o conjunto incrementalmente
SSCAN myset 0 MATCH "a*" COUNT 10
```

## Operações de Hash

Hashes armazenam pares de campo-valor, como mini objetos JSON ou dicionários.

### Operações Básicas de Hash: `HSET` / `HGET`

Defina e recupere campos de hash individuais.

```redis
# Defina o campo do hash
HSET user:123 name "John Doe" age 30
# Obtenha o campo do hash
HGET user:123 name
# Defina múltiplos campos
HMSET user:123 email "john@example.com" city "NYC"
# Obtenha múltiplos campos
HMGET user:123 name age email
```

### Inspeção de Hash: `HKEYS` / `HVALS`

Examine a estrutura e o conteúdo do hash.

```redis
# Obtenha todos os nomes de campo
HKEYS user:123
# Obtenha todos os valores
HVALS user:123
# Obtenha todos os campos e valores
HGETALL user:123
# Obtenha o número de campos
HLEN user:123
```

### Utilitários de Hash: `HEXISTS` / `HDEL`

Verifique a existência e remova campos de hash.

```redis
# Verifique se o campo existe
HEXISTS user:123 email
# Exclua campos
HDEL user:123 city
# Incremente o campo do hash
HINCRBY user:123 age 1
# Incremente por float
HINCRBYFLOAT user:123 balance 10.50
```

### Varredura de Hash: `HSCAN`

Itere sobre hashes grandes incrementalmente.

```redis
# Varra os campos do hash
HSCAN user:123 0
# Varra com correspondência de padrão
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## Operações de Conjunto Ordenado (Sorted Set)

Conjuntos ordenados combinam a exclusividade de conjuntos com a ordenação baseada em pontuações.

### Operações Básicas: `ZADD` / `ZRANGE`

Adicione membros pontuados e recupere intervalos.

```redis
# Adicione membros com pontuações
ZADD leaderboard 100 "player1" 200 "player2"
# Obtenha membros por classificação (baseado em 0)
ZRANGE leaderboard 0 -1
# Obtenha com pontuações
ZRANGE leaderboard 0 -1 WITHSCORES
# Obtenha por intervalo de pontuação
ZRANGEBYSCORE leaderboard 100 200
```

### Informações do Conjunto Ordenado: `ZCARD` / `ZSCORE`

Obtenha informações sobre membros do conjunto ordenado.

```redis
# Obtenha o tamanho do conjunto
ZCARD leaderboard
# Obtenha a pontuação do membro
ZSCORE leaderboard "player1"
# Obtenha a classificação do membro
ZRANK leaderboard "player1"
# Conte membros no intervalo de pontuação
ZCOUNT leaderboard 100 200
```

### Modificações: `ZREM` / `ZINCRBY`

Remova membros e modifique pontuações.

```redis
# Remova membros
ZREM leaderboard "player1"
# Incremente a pontuação do membro
ZINCRBY leaderboard 10 "player2"
# Remova por classificação
ZREMRANGEBYRANK leaderboard 0 2
# Remova por pontuação
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
# Obtenha todas as chaves (use com cuidado em produção)
KEYS *
# Chaves com padrão
KEYS user:*
# Chaves terminando com padrão
KEYS *:profile
# Coringa de caractere único
KEYS order:?
# Verifique se a chave existe
EXISTS mykey
```

### Informações da Chave: `TYPE` / `TTL`

Obtenha metadados da chave e informações de expiração.

```redis
# Obtenha o tipo de dados da chave
TYPE mykey
# Obtenha o tempo de vida (segundos)
TTL mykey
# Obtenha o TTL em milissegundos
PTTL mykey
# Remova a expiração
PERSIST mykey
```

### Operações de Chave: `RENAME` / `DEL`

Renomeie, exclua e mova chaves.

```redis
# Renomeie a chave
RENAME oldkey newkey
# Renomeie apenas se a nova chave não existir
RENAMENX oldkey newkey
# Exclua chaves
DEL key1 key2 key3
# Mova a chave para um banco de dados diferente
MOVE mykey 1
```

### Expiração: `EXPIRE` / `EXPIREAT`

Defina tempos de expiração de chave.

```redis
# Defina a expiração em segundos
EXPIRE mykey 3600
# Defina a expiração em um timestamp específico
EXPIREAT mykey 1609459200
# Defina a expiração em milissegundos
PEXPIRE mykey 60000
```

## Gerenciamento de Banco de Dados

### Seleção de Banco de Dados: `SELECT` / `FLUSHDB`

Gerencie múltiplos bancos de dados dentro do Redis.

```redis
# Selecione o banco de dados (0-15 por padrão)
SELECT 0
# Limpe o banco de dados atual
FLUSHDB
# Limpe todos os bancos de dados
FLUSHALL
# Obtenha o tamanho do banco de dados atual
DBSIZE
```

### Informações do Servidor: `INFO` / `PING`

Obtenha estatísticas do servidor e teste a conectividade.

```redis
# Teste a conexão com o servidor
PING
# Obtenha informações do servidor
INFO
# Obtenha seção de informações específica
INFO memory
INFO replication
# Obtenha o tempo do servidor
TIME
```

### Persistência: `SAVE` / `BGSAVE`

Controle a persistência de dados e backups do Redis.

```redis
# Salvamento síncrono (bloqueia o servidor)
SAVE
# Salvamento em segundo plano (não bloqueante)
BGSAVE
# Obtenha a hora do último salvamento
LASTSAVE
# Reescreva o arquivo AOF
BGREWRITEAOF
```

### Configuração: `CONFIG GET` / `CONFIG SET`

Visualize e modifique a configuração do Redis.

```redis
# Obtenha toda a configuração
CONFIG GET *
# Obtenha configuração específica
CONFIG GET maxmemory
# Defina a configuração
CONFIG SET timeout 300
# Redefina estatísticas
CONFIG RESETSTAT
```

## Monitoramento de Desempenho

### Monitoramento em Tempo Real: `MONITOR` / `SLOWLOG`

Rastreie comandos e identifique gargalos de desempenho.

```redis
# Monitore todos os comandos em tempo real
MONITOR
# Obtenha o log de consultas lentas
SLOWLOG GET 10
# Obtenha o comprimento do log lento
SLOWLOG LEN
# Redefina o log lento
SLOWLOG RESET
```

### Análise de Memória: `MEMORY USAGE` / `MEMORY STATS`

Analise o consumo de memória e otimização.

```redis
# Obtenha o uso de memória da chave
MEMORY USAGE mykey
# Obtenha estatísticas de memória
MEMORY STATS
# Obtenha relatório de diagnóstico de memória
MEMORY DOCTOR
# Limpe a memória
MEMORY PURGE
```

### Informações do Cliente: `CLIENT LIST`

Monitore clientes conectados e conexões.

```redis
# Liste todos os clientes
CLIENT LIST
# Obtenha informações do cliente
CLIENT INFO
# Mate a conexão do cliente
CLIENT KILL ip:port
# Defina o nome do cliente
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
# Inicie a transação
MULTI
SET key1 "value1"
INCR counter
# Execute todos os comandos
EXEC
# Descarte a transação
DISCARD
# Observe as chaves em busca de alterações
WATCH mykey
```

### Pub/Sub: `PUBLISH` / `SUBSCRIBE`

Implemente passagem de mensagens entre clientes.

```redis
# Assine um canal
SUBSCRIBE news sports
# Publique mensagem
PUBLISH news "Breaking: Redis 7.0 released!"
# Assinatura de padrão
PSUBSCRIBE news:*
# Desassinar
UNSUBSCRIBE news
```

### Scripting Lua: `EVAL` / `SCRIPT`

Execute scripts Lua personalizados atomicamente.

```redis
# Execute o script Lua
EVAL "return redis.call('SET', 'key', 'value')" 0
# Carregue o script e obtenha o SHA
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# Execute por SHA
EVALSHA sha1 1 mykey
# Verifique a existência do script
SCRIPT EXISTS sha1
```

### Streams: `XADD` / `XREAD`

Trabalhe com streams do Redis para dados semelhantes a logs.

```redis
# Adicione entrada ao stream
XADD mystream * field1 value1 field2 value2
# Leia do stream
XREAD STREAMS mystream 0
# Obtenha o comprimento do stream
XLEN mystream
# Crie um grupo de consumidores
XGROUP CREATE mystream mygroup 0
```

## Visão Geral dos Tipos de Dados

### Strings: Tipo mais versátil

Pode armazenar texto, números, JSON, dados binários. Tamanho máximo: 512MB. Use para: cache, contadores, flags.

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### Listas: Coleções ordenadas

Listas encadeadas de strings. Use para: filas, pilhas, feeds de atividade, itens recentes.

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### Conjuntos (Sets): Coleções únicas

Coleções não ordenadas de strings exclusivas. Use para: tags, visitantes únicos, relacionamentos.

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Dicas de Configuração do Redis

### Gerenciamento de Memória

Configure limites de memória e políticas de evacuação.

```redis
# Defina o limite de memória
CONFIG SET maxmemory 2gb
# Defina a política de evacuação
CONFIG SET maxmemory-policy allkeys-lru
# Verifique o uso da memória
INFO memory
```

### Configurações de Persistência

Configure opções de durabilidade de dados.

```redis
# Habilite AOF
CONFIG SET appendonly yes
# Defina intervalos de salvamento
CONFIG SET save "900 1 300 10 60 10000"
# Configurações de reescrita AOF
CONFIG SET auto-aof-rewrite-percentage 100
```

### Configurações de Segurança

Configurações básicas de segurança para o Redis.

```redis
# Defina a senha
CONFIG SET requirepass mypassword
# Autenticar
AUTH mypassword
# Desabilite comandos perigosos
CONFIG SET rename-command FLUSHALL ""
# Defina o tempo limite
CONFIG SET timeout 300
# TCP keep alive
CONFIG SET tcp-keepalive 60
# Máximo de clientes
CONFIG SET maxclients 10000
```

### Ajuste de Desempenho

Otimize o Redis para melhor desempenho.

```bash
# Habilite o pipelining para múltiplos comandos
# Use pool de conexões
# Configure a política maxmemory apropriada
# Monitore consultas lentas regularmente
# Use estruturas de dados apropriadas para casos de uso
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

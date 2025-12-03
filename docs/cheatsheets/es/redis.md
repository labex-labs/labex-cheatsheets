---
title: 'Hoja de Trucos de Redis | LabEx'
description: 'Aprenda el almacén de datos en memoria Redis con esta hoja de trucos completa. Referencia rápida para comandos de Redis, estructuras de datos, caché, pub/sub, persistencia y soluciones de caché de alto rendimiento.'
pdfUrl: '/cheatsheets/pdf/redis-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Redis
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/redis">Aprende Redis con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda las operaciones de estructuras de datos en memoria de Redis a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Redis que cubren comandos esenciales, estructuras de datos, estrategias de almacenamiento en caché, mensajería pub/sub y optimización del rendimiento. Domine el almacenamiento en caché de alto rendimiento y el procesamiento de datos en tiempo real.
</base-disclaimer-content>
</base-disclaimer>

## Instalación y Configuración de Redis

### Docker: `docker run redis`

La forma más rápida de ejecutar Redis localmente.

```bash
# Ejecutar Redis en Docker
docker run --name my-redis -p 6379:6379 -d redis
# Conectarse a la CLI de Redis
docker exec -it my-redis redis-cli
# Ejecutar con almacenamiento persistente
docker run --name redis-persistent -p 6379:6379 -v redis-data:/data -d redis
```

### Linux: `sudo apt install redis`

Instalar el servidor Redis en sistemas Ubuntu/Debian.

```bash
# Instalar Redis
sudo apt update
sudo apt install redis-server
# Iniciar el servicio Redis
sudo systemctl start redis-server
# Habilitar el autoarranque al iniciar
sudo systemctl enable redis-server
# Verificar estado
sudo systemctl status redis
```

### Conectar y Probar: `redis-cli`

Conectarse al servidor Redis y verificar la instalación.

```bash
# Conectarse a Redis local
redis-cli
# Probar conexión
redis-cli PING
# Conectarse a Redis remoto
redis-cli -h hostname -p 6379 -a password
# Ejecutar comando único
redis-cli SET mykey "Hello Redis"
```

## Operaciones Básicas de Cadenas (Strings)

### Establecer y Obtener: `SET` / `GET`

Almacenar valores simples (texto, números, JSON, etc.).

```redis
# Establecer un par clave-valor
SET mykey "Hello World"
# Obtener valor por clave
GET mykey
# Establecer con expiración (en segundos)
SET session:123 "user_data" EX 3600
# Establecer solo si la clave no existe
SET mykey "new_value" NX
```

<BaseQuiz id="redis-set-get-1" correct="C">
  <template #question>
    ¿Qué hace `SET mykey "value" EX 3600`?
  </template>
  
  <BaseQuizOption value="A">Establece la clave con un valor de 3600 bytes</BaseQuizOption>
  <BaseQuizOption value="B">Establece la clave solo si ya existe</BaseQuizOption>
  <BaseQuizOption value="C" correct>Establece la clave con un valor que expira después de 3600 segundos</BaseQuizOption>
  <BaseQuizOption value="D">Establece la clave con 3600 valores diferentes</BaseQuizOption>
  
  <BaseQuizAnswer>
    La opción `EX` establece un tiempo de expiración en segundos. `SET mykey "value" EX 3600` almacena el valor y lo elimina automáticamente después de 3600 segundos (1 hora).
  </BaseQuizAnswer>
</BaseQuiz>

### Manipulación de Cadenas: `APPEND` / `STRLEN`

Modificar e inspeccionar valores de cadena.

```redis
# Añadir al final de la cadena existente
APPEND mykey " - Welcome!"
# Obtener longitud de la cadena
STRLEN mykey
# Obtener subcadena
GETRANGE mykey 0 4
# Establecer subcadena
SETRANGE mykey 6 "Redis"
```

### Operaciones Numéricas: `INCR` / `DECR`

Incrementar o decrementar valores enteros almacenados en Redis.

```redis
# Incrementar en 1
INCR counter
# Decrementar en 1
DECR counter
# Incrementar por cantidad específica
INCRBY counter 5
# Incrementar flotante
INCRBYFLOAT price 0.1
```

<BaseQuiz id="redis-incr-1" correct="A">
  <template #question>
    ¿Qué sucede si usa `INCR` en una clave que no existe?
  </template>
  
  <BaseQuizOption value="A" correct>Redis crea la clave con valor 1</BaseQuizOption>
  <BaseQuizOption value="B">Redis devuelve un error</BaseQuizOption>
  <BaseQuizOption value="C">Redis crea la clave con valor 0</BaseQuizOption>
  <BaseQuizOption value="D">No sucede nada</BaseQuizOption>
  
  <BaseQuizAnswer>
    Si una clave no existe, `INCR` la trata como si tuviera un valor de 0, la incrementa a 1 y crea la clave. Esto hace que `INCR` sea útil para inicializar contadores.
  </BaseQuizAnswer>
</BaseQuiz>

### Operaciones Múltiples: `MSET` / `MGET`

Trabajar con múltiples pares clave-valor de manera eficiente.

```redis
# Establecer múltiples claves a la vez
MSET key1 "value1" key2 "value2" key3 "value3"
# Obtener múltiples valores
MGET key1 key2 key3
# Establecer múltiples solo si ninguna existe
MSETNX key1 "val1" key2 "val2"
```

## Operaciones de Lista (List)

Las listas son secuencias ordenadas de cadenas, útiles como colas (queues) o pilas (stacks).

### Añadir Elementos: `LPUSH` / `RPUSH`

Añadir elementos al lado izquierdo (cabeza) o derecho (cola) de una lista.

```redis
# Añadir a la cabeza (izquierda)
LPUSH mylist "first"
# Añadir a la cola (derecha)
RPUSH mylist "last"
# Añadir múltiples elementos
LPUSH mylist "item1" "item2" "item3"
```

### Eliminar Elementos: `LPOP` / `RPOP`

Eliminar y devolver elementos de los extremos de la lista.

```redis
# Eliminar de la cabeza
LPOP mylist
# Eliminar de la cola
RPOP mylist
# Pop bloqueante (espera por un elemento)
BLPOP mylist 10
```

### Acceder a Elementos: `LRANGE` / `LINDEX`

Recuperar elementos o rangos de listas.

```redis
# Obtener la lista completa
LRANGE mylist 0 -1
# Obtener los primeros 3 elementos
LRANGE mylist 0 2
# Obtener elemento específico por índice
LINDEX mylist 0
# Obtener longitud de la lista
LLEN mylist
```

<BaseQuiz id="redis-list-1" correct="B">
  <template #question>
    ¿Qué devuelve `LRANGE mylist 0 -1`?
  </template>
  
  <BaseQuizOption value="A">Solo el primer elemento</BaseQuizOption>
  <BaseQuizOption value="B" correct>Todos los elementos de la lista</BaseQuizOption>
  <BaseQuizOption value="C">Solo el último elemento</BaseQuizOption>
  <BaseQuizOption value="D">Un error</BaseQuizOption>
  
  <BaseQuizAnswer>
    `LRANGE` con `0 -1` devuelve todos los elementos de la lista. El `0` es el índice de inicio y `-1` representa el último elemento, por lo que recupera todo desde el primero hasta el último elemento.
  </BaseQuizAnswer>
</BaseQuiz>

### Utilidades de Lista: `LSET` / `LTRIM`

Modificar el contenido y la estructura de la lista.

```redis
# Establecer elemento en un índice
LSET mylist 0 "new_value"
# Recortar lista a un rango
LTRIM mylist 0 99
# Encontrar posición de un elemento
LPOS mylist "search_value"
```

## Operaciones de Conjunto (Set)

Los conjuntos son colecciones de elementos de cadena únicos y no ordenados.

### Operaciones Básicas de Conjunto: `SADD` / `SMEMBERS`

Añadir elementos únicos a conjuntos y recuperar todos los miembros.

```redis
# Añadir elementos al conjunto
SADD myset "apple" "banana" "cherry"
# Obtener todos los miembros del conjunto
SMEMBERS myset
# Verificar si el elemento existe
SISMEMBER myset "apple"
```

<BaseQuiz id="redis-set-1" correct="C">
  <template #question>
    ¿Qué sucede si intenta añadir un elemento duplicado a un conjunto de Redis?
  </template>
  
  <BaseQuizOption value="A">Crea un error</BaseQuizOption>
  <BaseQuizOption value="B">Reemplaza el elemento existente</BaseQuizOption>
  <BaseQuizOption value="C" correct>El duplicado es ignorado y el conjunto permanece sin cambios</BaseQuizOption>
  <BaseQuizOption value="D">Crea una lista en su lugar</BaseQuizOption>
  
  <BaseQuizAnswer>
    Los conjuntos de Redis solo contienen elementos únicos. Si intenta añadir un elemento que ya existe, Redis lo ignora y devuelve 0 (indicando que no se añadió ningún elemento). El conjunto permanece sin cambios.
  </BaseQuizAnswer>
</BaseQuiz>
# Obtener tamaño del conjunto
SCARD myset
```

### Modificaciones de Conjunto: `SREM` / `SPOP`

Eliminar elementos de los conjuntos de diferentes maneras.

```redis
# Eliminar elementos específicos
SREM myset "banana"
# Eliminar y devolver un elemento aleatorio
SPOP myset
# Obtener elemento aleatorio sin eliminar
SRANDMEMBER myset
```

### Operaciones de Conjunto: `SINTER` / `SUNION`

Realizar operaciones de conjuntos matemáticas.

```redis
# Intersección de conjuntos
SINTER set1 set2
# Unión de conjuntos
SUNION set1 set2
# Diferencia de conjuntos
SDIFF set1 set2
# Almacenar resultado en un nuevo conjunto
SINTERSTORE result set1 set2
```

### Utilidades de Conjunto: `SMOVE` / `SSCAN`

Manipulación avanzada de conjuntos y escaneo.

```redis
# Mover elemento entre conjuntos
SMOVE source_set dest_set "element"
# Escanear conjunto incrementalmente
SSCAN myset 0 MATCH "a*" COUNT 10
```

## Operaciones de Hash

Los hashes almacenan pares campo-valor, como objetos JSON pequeños o diccionarios.

### Operaciones Básicas de Hash: `HSET` / `HGET`

Establecer y recuperar campos de hash individuales.

```redis
# Establecer campo de hash
HSET user:123 name "John Doe" age 30
# Obtener campo de hash
HGET user:123 name
# Establecer múltiples campos
HMSET user:123 email "john@example.com" city "NYC"
# Obtener múltiples campos
HMGET user:123 name age email
```

### Inspección de Hash: `HKEYS` / `HVALS`

Examinar la estructura y el contenido del hash.

```redis
# Obtener todos los nombres de campo
HKEYS user:123
# Obtener todos los valores
HVALS user:123
# Obtener todos los campos y valores
HGETALL user:123
# Obtener número de campos
HLEN user:123
```

### Utilidades de Hash: `HEXISTS` / `HDEL`

Verificar existencia y eliminar campos de hash.

```redis
# Verificar si el campo existe
HEXISTS user:123 email
# Eliminar campos
HDEL user:123 age city
# Incrementar campo de hash
HINCRBY user:123 age 1
# Incrementar por flotante
HINCRBYFLOAT user:123 balance 10.50
```

### Escaneo de Hash: `HSCAN`

Iterar a través de hashes grandes incrementalmente.

```redis
# Escanear campos del hash
HSCAN user:123 0
# Escanear con coincidencia de patrón
HSCAN user:123 0 MATCH "addr*" COUNT 10
```

## Operaciones de Conjunto Ordenado (Sorted Set)

Los conjuntos ordenados combinan la unicidad de los conjuntos con el orden basado en puntuaciones (scores).

### Operaciones Básicas: `ZADD` / `ZRANGE`

Añadir miembros con puntuación y recuperar rangos.

```redis
# Añadir miembros con puntuaciones
ZADD leaderboard 100 "player1" 200 "player2"
# Obtener miembros por rango (índice 0-based)
ZRANGE leaderboard 0 -1
# Obtener con puntuaciones
ZRANGE leaderboard 0 -1 WITHSCORES
# Obtener por rango de puntuación
ZRANGEBYSCORE leaderboard 100 200
```

### Información del Conjunto Ordenado: `ZCARD` / `ZSCORE`

Obtener información sobre los miembros del conjunto ordenado.

```redis
# Obtener tamaño del conjunto
ZCARD leaderboard
# Obtener puntuación del miembro
ZSCORE leaderboard "player1"
# Obtener rango del miembro
ZRANK leaderboard "player1"
# Contar miembros en rango de puntuación
ZCOUNT leaderboard 100 200
```

### Modificaciones: `ZREM` / `ZINCRBY`

Eliminar miembros y modificar puntuaciones.

```redis
# Eliminar miembros
ZREM leaderboard "player1"
# Incrementar puntuación del miembro
ZINCRBY leaderboard 10 "player2"
# Eliminar por rango
ZREMRANGEBYRANK leaderboard 0 2
# Eliminar por puntuación
ZREMRANGEBYSCORE leaderboard 0 100
```

### Avanzado: `ZUNIONSTORE` / `ZINTERSTORE`

Combinar múltiples conjuntos ordenados.

```redis
# Unión de conjuntos ordenados
ZUNIONSTORE result 2 set1 set2
# Intersección con pesos
ZINTERSTORE result 2 set1 set2 WEIGHTS 1 2
# Con función de agregación
ZUNIONSTORE result 2 set1 set2 AGGREGATE MAX
```

## Gestión de Claves (Key Management)

### Inspección de Claves: `KEYS` / `EXISTS`

Encontrar claves usando patrones y verificar existencia.

```redis
# Obtener todas las claves (usar con cuidado en producción)
KEYS *
# Claves con patrón
KEYS user:*
# Claves que terminan con patrón
KEYS *:profile
# Comodín de un solo carácter
KEYS order:?
# Verificar si la clave existe
EXISTS mykey
```

### Información de Clave: `TYPE` / `TTL`

Obtener metadatos de la clave e información de expiración.

```redis
# Obtener tipo de datos de la clave
TYPE mykey
# Obtener tiempo de vida (segundos)
TTL mykey
# Obtener TTL en milisegundos
PTTL mykey
# Eliminar expiración
PERSIST mykey
```

### Operaciones de Clave: `RENAME` / `DEL`

Renombrar, eliminar y mover claves.

```redis
# Renombrar clave
RENAME oldkey newkey
# Renombrar solo si la nueva clave no existe
RENAMENX oldkey newkey
# Eliminar claves
DEL key1 key2 key3
# Mover clave a base de datos diferente
MOVE mykey 1
```

### Expiración: `EXPIRE` / `EXPIREAT`

Establecer tiempos de expiración para las claves.

```redis
# Establecer expiración en segundos
EXPIRE mykey 3600
# Establecer expiración en marca de tiempo específica
EXPIREAT mykey 1609459200
# Establecer expiración en milisegundos
PEXPIRE mykey 60000
```

## Gestión de Bases de Datos

### Selección de Base de Datos: `SELECT` / `FLUSHDB`

Administrar múltiples bases de datos dentro de Redis.

```redis
# Seleccionar base de datos (0-15 por defecto)
SELECT 0
# Limpiar base de datos actual
FLUSHDB
# Limpiar todas las bases de datos
FLUSHALL
# Obtener tamaño de la base de datos actual
DBSIZE
```

### Información del Servidor: `INFO` / `PING`

Obtener estadísticas del servidor y probar conectividad.

```redis
# Probar conexión al servidor
PING
# Obtener información del servidor
INFO
# Obtener sección de información específica
INFO memory
INFO replication
# Obtener tiempo del servidor
TIME
```

### Persistencia: `SAVE` / `BGSAVE`

Controlar la persistencia y las copias de seguridad de datos de Redis.

```redis
# Guardado síncrono (bloquea el servidor)
SAVE
# Guardado en segundo plano (no bloqueante)
BGSAVE
# Obtener tiempo del último guardado
LASTSAVE
# Reescribir archivo AOF
BGREWRITEAOF
```

### Configuración: `CONFIG GET` / `CONFIG SET`

Ver y modificar la configuración de Redis.

```redis
# Obtener toda la configuración
CONFIG GET *
# Obtener configuración específica
CONFIG GET maxmemory
# Establecer configuración
CONFIG SET timeout 300
# Restablecer estadísticas
CONFIG RESETSTAT
```

## Monitoreo del Rendimiento

### Monitoreo en Tiempo Real: `MONITOR` / `SLOWLOG`

Rastrear comandos e identificar cuellos de botella de rendimiento.

```redis
# Monitorear todos los comandos en tiempo real
MONITOR
# Obtener registro de consultas lentas
SLOWLOG GET 10
# Obtener longitud del registro lento
SLOWLOG LEN
# Restablecer registro lento
SLOWLOG RESET
```

### Análisis de Memoria: `MEMORY USAGE` / `MEMORY STATS`

Analizar el consumo de memoria y la optimización.

```redis
# Obtener uso de memoria de la clave
MEMORY USAGE mykey
# Obtener estadísticas de memoria
MEMORY STATS
# Obtener informe de diagnóstico de memoria
MEMORY DOCTOR
# Purgar memoria
MEMORY PURGE
```

### Información del Cliente: `CLIENT LIST`

Monitorear clientes conectados y conexiones.

```redis
# Listar todos los clientes
CLIENT LIST
# Obtener información del cliente
CLIENT INFO
# Matar conexión de cliente
CLIENT KILL ip:port
# Establecer nombre del cliente
CLIENT SETNAME "my-app"
```

### Benchmarking: `redis-benchmark`

Probar el rendimiento de Redis con la herramienta de benchmark integrada.

```bash
# Benchmark básico
redis-benchmark
# Operaciones específicas
redis-benchmark -t SET,GET -n 100000
# Tamaño de carga útil personalizado
redis-benchmark -d 1024 -t SET -n 10000
```

## Características Avanzadas

### Transacciones: `MULTI` / `EXEC`

Ejecutar múltiples comandos atómicamente.

```redis
# Iniciar transacción
MULTI
SET key1 "value1"
INCR counter
# Ejecutar todos los comandos
EXEC
# Descartar transacción
DISCARD
# Vigilar claves en busca de cambios
WATCH mykey
```

### Pub/Sub: `PUBLISH` / `SUBSCRIBE`

Implementar el paso de mensajes entre clientes.

```redis
# Suscribirse a un canal
SUBSCRIBE news sports
# Publicar mensaje
PUBLISH news "Breaking: Redis 7.0 released!"
# Suscripción por patrón
PSUBSCRIBE news:*
# Desuscribirse
UNSUBSCRIBE news
```

### Scripting Lua: `EVAL` / `SCRIPT`

Ejecutar scripts Lua personalizados atómicamente.

```redis
# Ejecutar script Lua
EVAL "return redis.call('SET', 'key', 'value')" 0
# Cargar script y obtener SHA
SCRIPT LOAD "return redis.call('GET', KEYS[1])"
# Ejecutar por SHA
EVALSHA sha1 1 mykey
# Verificar existencia del script
SCRIPT EXISTS sha1
```

### Streams: `XADD` / `XREAD`

Trabajar con streams de Redis para datos tipo registro (log).

```redis
# Añadir entrada al stream
XADD mystream * field1 value1 field2 value2
# Leer del stream
XREAD STREAMS mystream 0
# Obtener longitud del stream
XLEN mystream
# Crear grupo de consumidores
XGROUP CREATE mystream mygroup 0
```

## Resumen de Tipos de Datos

### Cadenas (Strings): El tipo más versátil

Puede almacenar texto, números, JSON, datos binarios. Tamaño máximo: 512MB. Usar para: almacenamiento en caché, contadores, indicadores (flags).

```redis
SET user:123:name "John"
GET user:123:name
INCR page:views
```

### Listas (Lists): Colecciones ordenadas

Listas enlazadas de cadenas. Usar para: colas (queues), pilas (stacks), feeds de actividad, elementos recientes.

```redis
LPUSH queue:jobs "job1"
RPOP queue:jobs
LRANGE recent:posts 0 9
```

### Conjuntos (Sets): Colecciones únicas

Colecciones no ordenadas de cadenas únicas. Usar para: etiquetas (tags), visitantes únicos, relaciones.

```redis
SADD post:123:tags "redis" "database"
SISMEMBER post:123:tags "redis"
SINTER user:123:friends user:456:friends
```

## Consejos de Configuración de Redis

### Gestión de Memoria

Configurar límites de memoria y políticas de desalojo (eviction).

```redis
# Establecer límite de memoria
CONFIG SET maxmemory 2gb
# Establecer política de desalojo
CONFIG SET maxmemory-policy allkeys-lru
# Verificar uso de memoria
INFO memory
```

### Configuración de Persistencia

Configurar opciones de durabilidad de datos.

```redis
# Habilitar AOF
CONFIG SET appendonly yes
# Establecer intervalos de guardado
CONFIG SET save "900 1 300 10 60 10000"
# Configuración de reescritura AOF
CONFIG SET auto-aof-rewrite-percentage 100
```

### Configuración de Seguridad

Configuraciones básicas de seguridad para Redis.

```redis
# Establecer contraseña
CONFIG SET requirepass mypassword
# Autenticar
AUTH mypassword
# Deshabilitar comandos peligrosos
CONFIG SET rename-command FLUSHALL ""
# Establecer tiempo de espera
CONFIG SET timeout 300
# Keep alive de TCP
CONFIG SET tcp-keepalive 60
# Máximo de clientes
CONFIG SET maxclients 10000
```

### Ajuste de Rendimiento

Optimizar Redis para un mejor rendimiento.

```redis
# Habilitar pipelining para múltiples comandos
# Usar agrupación de conexiones (connection pooling)
# Configurar la política maxmemory apropiada
# Monitorear consultas lentas regularmente
# Usar estructuras de datos apropiadas para los casos de uso
```

## Enlaces Relevantes

- <router-link to="/database">Hoja de Trucos de Bases de Datos</router-link>
- <router-link to="/mysql">Hoja de Trucos de MySQL</router-link>
- <router-link to="/postgresql">Hoja de Trucos de PostgreSQL</router-link>
- <router-link to="/mongodb">Hoja de Trucos de MongoDB</router-link>
- <router-link to="/sqlite">Hoja de Trucos de SQLite</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>

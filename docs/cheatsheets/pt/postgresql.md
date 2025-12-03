---
title: 'Guia Rápido PostgreSQL | LabEx'
description: 'Aprenda gerenciamento de banco de dados PostgreSQL com este guia completo. Referência rápida para consultas SQL, recursos avançados, suporte a JSON, pesquisa de texto completo e administração de banco de dados empresarial.'
pdfUrl: '/cheatsheets/pdf/postgresql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas PostgreSQL
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/postgresql">Aprenda PostgreSQL com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda gerenciamento de banco de dados PostgreSQL através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de PostgreSQL cobrindo operações SQL essenciais, consultas avançadas, otimização de desempenho, administração de banco de dados e segurança. Domine o desenvolvimento e a administração de bancos de dados relacionais de nível empresarial.
</base-disclaimer-content>
</base-disclaimer>

## Conexão e Configuração do Banco de Dados

### Conectar ao PostgreSQL: `psql`

Conecte-se a um banco de dados PostgreSQL local ou remoto usando a ferramenta de linha de comando psql.

```bash
# Conectar ao banco de dados local
psql -U username -d database_name
# Conectar ao banco de dados remoto
psql -h hostname -p 5432 -U username -d database_name
# Conectar com solicitação de senha
psql -U postgres -W
# Conectar usando string de conexão
psql "host=localhost port=5432 dbname=mydb user=myuser"
```

### Criar Banco de Dados: `CREATE DATABASE`

Crie um novo banco de dados no PostgreSQL usando o comando CREATE DATABASE.

```sql
# Criar um novo banco de dados
CREATE DATABASE mydatabase;
# Criar banco de dados com proprietário
CREATE DATABASE mydatabase OWNER myuser;
# Criar banco de dados com codificação
CREATE DATABASE mydatabase
  WITH ENCODING 'UTF8'
  LC_COLLATE='en_US.UTF-8'
  LC_CTYPE='en_US.UTF-8';
```

### Listar Bancos de Dados: `\l`

Liste todos os bancos de dados no servidor PostgreSQL.

```bash
# Listar todos os bancos de dados
\l
# Listar bancos de dados com informações detalhadas
\l+
# Conectar a um banco de dados diferente
\c database_name
```

### Comandos Básicos do psql

Comandos essenciais do terminal psql para navegação e informação.

```bash
# Sair do psql
\q
# Obter ajuda para comandos SQL
\help CREATE TABLE
# Obter ajuda para comandos psql
\?
# Mostrar banco de dados e usuário atuais
\conninfo
# Executar comandos do sistema
\! ls
# Listar todas as tabelas
\dt
# Listar todas as tabelas com detalhes
\dt+
# Descrever tabela específica
\d table_name
# Listar todos os schemas
\dn
# Listar todos os usuários/funções (roles)
\du
```

### Versão e Configurações

Verificar a versão do PostgreSQL e as configurações de configuração.

```sql
# Verificar a versão do PostgreSQL
SELECT version();
# Mostrar todas as configurações
SHOW ALL;
# Mostrar configuração específica
SHOW max_connections;
# Definir parâmetro de configuração
SET work_mem = '256MB';
```

## Criação e Gerenciamento de Tabelas

### Criar Tabela: `CREATE TABLE`

Definir novas tabelas com colunas, tipos de dados e restrições.

```sql
# Criação básica de tabela
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

# Tabela com chave estrangeira
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending'
);
```

<BaseQuiz id="postgresql-create-table-1" correct="A">
  <template #question>
    O que `SERIAL PRIMARY KEY` faz no PostgreSQL?
  </template>
  
  <BaseQuizOption value="A" correct>Cria uma coluna de inteiro auto-incrementável que serve como chave primária</BaseQuizOption>
  <BaseQuizOption value="B">Cria uma coluna de texto</BaseQuizOption>
  <BaseQuizOption value="C">Cria uma restrição de chave estrangeira</BaseQuizOption>
  <BaseQuizOption value="D">Cria um índice exclusivo</BaseQuizOption>
  
  <BaseQuizAnswer>
    `SERIAL` é um tipo de dado específico do PostgreSQL que cria um inteiro auto-incrementável. Combinado com `PRIMARY KEY`, ele cria um identificador exclusivo para cada linha que se incrementa automaticamente.
  </BaseQuizAnswer>
</BaseQuiz>

### Modificar Tabelas: `ALTER TABLE`

Adicionar, modificar ou remover colunas e restrições de tabelas existentes.

```sql
# Adicionar nova coluna
ALTER TABLE users ADD COLUMN phone VARCHAR(15);
# Alterar tipo de coluna
ALTER TABLE users ALTER COLUMN phone TYPE VARCHAR(20);
# Remover coluna
ALTER TABLE users DROP COLUMN phone;
# Adicionar restrição
ALTER TABLE users ADD CONSTRAINT unique_email
    UNIQUE (email);
```

### Excluir e Truncar: `DROP/TRUNCATE`

Remover tabelas ou limpar todos os dados das tabelas.

```sql
# Excluir tabela completamente
DROP TABLE IF EXISTS old_table;
# Remover todos os dados, mas manter a estrutura
TRUNCATE TABLE users;
# Truncar com reinicialização da identidade
TRUNCATE TABLE users RESTART IDENTITY;
```

### Tipos de Dados e Restrições

Tipos de dados essenciais do PostgreSQL para diferentes tipos de dados.

```sql
# Tipos numéricos
INTEGER, BIGINT, SMALLINT
DECIMAL(10,2), NUMERIC(10,2)
REAL, DOUBLE PRECISION

# Tipos de caractere
CHAR(n), VARCHAR(n), TEXT

# Tipos Data/Hora
DATE, TIME, TIMESTAMP
TIMESTAMPTZ (com fuso horário)

# Booleano e outros
BOOLEAN
JSON, JSONB
UUID
ARRAY (ex: INTEGER[])

# Chave primária
id SERIAL PRIMARY KEY

# Chave estrangeira
user_id INTEGER REFERENCES users(id)

# Restrição exclusiva
email VARCHAR(100) UNIQUE

# Restrição de verificação
age INTEGER CHECK (age >= 0)

# Não nulo
name VARCHAR(50) NOT NULL
```

### Índices: `CREATE INDEX`

Melhorar o desempenho das consultas com índices de banco de dados.

```sql
# Índice básico
CREATE INDEX idx_username ON users(username);
# Índice exclusivo
CREATE UNIQUE INDEX idx_unique_email
    ON users(email);
# Índice composto
CREATE INDEX idx_user_date
    ON orders(user_id, created_at);
# Índice parcial
CREATE INDEX idx_active_users
    ON users(username) WHERE active = true;
# Excluir índice
DROP INDEX IF EXISTS idx_username;
```

<BaseQuiz id="postgresql-index-1" correct="A">
  <template #question>
    Qual é o principal objetivo de criar um índice no PostgreSQL?
  </template>
  
  <BaseQuizOption value="A" correct>Melhorar o desempenho da consulta acelerando a recuperação de dados</BaseQuizOption>
  <BaseQuizOption value="B">Reduzir o tamanho do banco de dados</BaseQuizOption>
  <BaseQuizOption value="C">Criptografar dados</BaseQuizOption>
  <BaseQuizOption value="D">Prevenir entradas duplicadas</BaseQuizOption>
  
  <BaseQuizAnswer>
    Índices criam uma estrutura de dados que permite ao banco de dados encontrar linhas rapidamente sem escanear a tabela inteira. Isso acelera significativamente as consultas SELECT, especialmente em tabelas grandes.
  </BaseQuizAnswer>
</BaseQuiz>

### Sequências: `CREATE SEQUENCE`

Gerar valores numéricos exclusivos automaticamente.

```sql
# Criar sequência
CREATE SEQUENCE user_id_seq;
# Usar sequência na tabela
CREATE TABLE users (
    id INTEGER DEFAULT nextval('user_id_seq'),
    username VARCHAR(50)
);
# Reiniciar sequência
ALTER SEQUENCE user_id_seq RESTART WITH 1000;
```

## Operações CRUD

### Inserir Dados: `INSERT`

Adicionar novos registros às tabelas do banco de dados.

```sql
# Inserir registro único
INSERT INTO users (username, email)
VALUES ('john_doe', 'john@example.com');
# Inserir múltiplos registros
INSERT INTO users (username, email) VALUES
    ('alice', 'alice@example.com'),
    ('bob', 'bob@example.com');
# Inserir com retorno
INSERT INTO users (username, email)
VALUES ('jane', 'jane@example.com')
RETURNING id, created_at;
# Inserir a partir de seleção
INSERT INTO archive_users
SELECT * FROM users WHERE active = false;
```

<BaseQuiz id="postgresql-insert-1" correct="C">
  <template #question>
    O que `RETURNING` faz em uma instrução INSERT do PostgreSQL?
  </template>
  
  <BaseQuizOption value="A">Ele reverte a inserção</BaseQuizOption>
  <BaseQuizOption value="B">Ele impede a inserção</BaseQuizOption>
  <BaseQuizOption value="C" correct>Ele retorna os dados da linha inserida</BaseQuizOption>
  <BaseQuizOption value="D">Ele atualiza linhas existentes</BaseQuizOption>
  
  <BaseQuizAnswer>
    A cláusula `RETURNING` no PostgreSQL permite que você recupere os dados da linha inserida (ou colunas específicas) imediatamente após a inserção, o que é útil para obter IDs gerados automaticamente ou carimbos de data/hora.
  </BaseQuizAnswer>
</BaseQuiz>

### Atualizar Dados: `UPDATE`

Modificar registros existentes nas tabelas do banco de dados.

```sql
# Atualizar registros específicos
UPDATE users
SET email = 'newemail@example.com'
WHERE username = 'john_doe';
# Atualizar múltiplas colunas
UPDATE users
SET email = 'new@example.com',
    updated_at = NOW()
WHERE id = 1;
# Atualizar com subconsulta
UPDATE orders
SET total = (SELECT SUM(price) FROM order_items
            WHERE order_id = orders.id);
```

### Selecionar Dados: `SELECT`

Consultar e recuperar dados das tabelas do banco de dados.

```sql
# Seleção básica
SELECT * FROM users;
# Selecionar colunas específicas
SELECT id, username, email FROM users;
# Selecionar com condições
SELECT * FROM users
WHERE active = true AND created_at > '2024-01-01';
# Selecionar com ordenação e limites
SELECT * FROM users
ORDER BY created_at DESC
LIMIT 10 OFFSET 20;
```

### Excluir Dados: `DELETE`

Remover registros das tabelas do banco de dados.

```sql
# Excluir registros específicos
DELETE FROM users
WHERE active = false;
# Excluir com subconsulta
DELETE FROM orders
WHERE user_id IN (
    SELECT id FROM users WHERE active = false
);
# Excluir todos os registros
DELETE FROM temp_table;
# Excluir com retorno
DELETE FROM users
WHERE id = 5
RETURNING *;
```

## Consultas Avançadas

### Joins: `INNER/LEFT/RIGHT JOIN`

Combinar dados de múltiplas tabelas usando vários tipos de join.

```sql
# Inner join
SELECT u.username, o.total
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# Left join
SELECT u.username, o.total
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# Múltiplos joins
SELECT u.username, o.total, p.name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

### Subconsultas e CTEs

Usar consultas aninhadas e expressões de tabela comuns para operações complexas.

```sql
# Subconsulta em WHERE
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders);
# Expressão de Tabela Comum (CTE)
WITH active_users AS (
    SELECT * FROM users WHERE active = true
)
SELECT au.username, COUNT(o.id) as order_count
FROM active_users au
LEFT JOIN orders o ON au.id = o.user_id
GROUP BY au.username;
```

### Agregação: `GROUP BY`

Agrupar dados e aplicar funções agregadas para análise.

```sql
# Agrupamento básico
SELECT status, COUNT(*) as count
FROM orders
GROUP BY status;
# Múltiplas agregações
SELECT user_id,
       COUNT(*) as order_count,
       SUM(total) as total_spent,
       AVG(total) as avg_order
FROM orders
GROUP BY user_id
HAVING COUNT(*) > 5;
```

### Funções de Janela (Window Functions)

Executar cálculos em linhas relacionadas sem agrupar.

```sql
# Numeração de linhas
SELECT username, email,
       ROW_NUMBER() OVER (ORDER BY created_at) as row_num
FROM users;
# Totais acumulados (Running totals)
SELECT date, amount,
       SUM(amount) OVER (ORDER BY date) as running_total
FROM sales;
# Classificação (Ranking)
SELECT username, score,
       RANK() OVER (ORDER BY score DESC) as rank
FROM user_scores;
```

## Importação e Exportação de Dados

### Importação CSV: `COPY`

Importar dados de arquivos CSV para tabelas PostgreSQL.

```sql
# Importar de arquivo CSV
COPY users(username, email, age)
FROM '/path/to/users.csv'
DELIMITER ',' CSV HEADER;
# Importar com opções específicas
COPY products
FROM '/path/to/products.csv'
WITH (FORMAT csv, HEADER true, DELIMITER ';');
# Importar de stdin
\copy users(username, email) FROM STDIN WITH CSV;
```

### Exportação CSV: `COPY TO`

Exportar dados do PostgreSQL para arquivos CSV.

```sql
# Exportar para arquivo CSV
COPY users TO '/path/to/users_export.csv'
WITH (FORMAT csv, HEADER true);
# Exportar resultados da consulta
COPY (SELECT username, email FROM users WHERE active = true)
TO '/path/to/active_users.csv' CSV HEADER;
# Exportar para stdout
\copy (SELECT * FROM orders) TO STDOUT WITH CSV HEADER;
```

### Backup e Restauração: `pg_dump`

Criar backups de banco de dados e restaurar a partir de arquivos de backup.

```bash
# Fazer dump de banco de dados inteiro
pg_dump -U username -h hostname database_name > backup.sql
# Fazer dump de tabela específica
pg_dump -U username -t table_name database_name > table_backup.sql
# Backup compactado
pg_dump -U username -Fc database_name > backup.dump
# Restaurar a partir do backup
psql -U username -d database_name < backup.sql
# Restaurar backup compactado
pg_restore -U username -d database_name backup.dump
```

### Operações com Dados JSON

Trabalhar com tipos de dados JSON e JSONB para dados semi-estruturados.

```sql
# Inserir dados JSON
INSERT INTO products (name, metadata)
VALUES ('Laptop', '{"brand": "Dell", "price": 999.99}');
# Consultar campos JSON
SELECT name, metadata->>'brand' as brand
FROM products
WHERE metadata->>'price'::numeric > 500;
# Operações com array JSON
SELECT name FROM products
WHERE metadata->'features' ? 'wireless';
```

## Gerenciamento de Usuários e Segurança

### Criar Usuários e Funções (Roles)

Gerenciar o acesso ao banco de dados com usuários e funções.

```sql
# Criar usuário
CREATE USER myuser WITH PASSWORD 'secretpassword';
# Criar função (role)
CREATE ROLE readonly_user;
# Criar usuário com privilégios específicos
CREATE USER admin_user WITH
    CREATEDB CREATEROLE PASSWORD 'adminpass';
# Conceder função a usuário
GRANT readonly_user TO myuser;
```

### Permissões: `GRANT/REVOKE`

Controlar o acesso a objetos de banco de dados através de permissões.

```sql
# Conceder permissões de tabela
GRANT SELECT, INSERT ON users TO myuser;
# Conceder todos os privilégios na tabela
GRANT ALL ON orders TO admin_user;
# Conceder permissões de banco de dados
GRANT CONNECT ON DATABASE mydb TO myuser;
# Revogar permissões
REVOKE INSERT ON users FROM myuser;
```

### Visualizar Informações do Usuário

Verificar usuários existentes e suas permissões.

```sql
# Listar todos os usuários
\du
# Visualizar permissões de tabela
SELECT table_name, privilege_type, grantee
FROM information_schema.table_privileges
WHERE table_schema = 'public';
# Ver usuário atual
SELECT current_user;
# Visualizar associações de função (role memberships)
SELECT r.rolname, r.rolsuper, r.rolcreaterole
FROM pg_roles r;
```

### Senha e Segurança

Gerenciar senhas de usuários e configurações de segurança.

```sql
# Alterar senha do usuário
ALTER USER myuser PASSWORD 'newpassword';
# Definir expiração de senha
ALTER USER myuser VALID UNTIL '2025-12-31';
# Criar usuário sem login
CREATE ROLE reporting_role NOLOGIN;
# Habilitar/desabilitar usuário
ALTER USER myuser WITH NOLOGIN;
ALTER USER myuser WITH LOGIN;
```

## Desempenho e Monitoramento

### Análise de Consulta: `EXPLAIN`

Analisar planos de execução de consultas e otimizar o desempenho.

```sql
# Mostrar plano de execução da consulta
EXPLAIN SELECT * FROM users WHERE active = true;
# Analisar com estatísticas de execução reais
EXPLAIN ANALYZE
SELECT u.username, COUNT(o.id)
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.username;
# Informações detalhadas de execução
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT * FROM large_table WHERE indexed_col = 'value';
```

### Manutenção do Banco de Dados: `VACUUM`

Manter o desempenho do banco de dados através de operações de limpeza regulares.

```sql
# Vacuum básico
VACUUM users;
# Vacuum completo com análise
VACUUM FULL ANALYZE users;
# Status do auto-vacuum
SELECT schemaname, tablename, last_vacuum, last_autovacuum
FROM pg_stat_user_tables;
# Reindexar tabela
REINDEX TABLE users;
```

### Monitoramento de Consultas

Rastrear a atividade do banco de dados e identificar problemas de desempenho.

```sql
# Atividade atual
SELECT pid, usename, query, state
FROM pg_stat_activity
WHERE state != 'idle';
# Consultas de longa duração
SELECT pid, now() - query_start as duration, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC;
# Encerrar consulta específica
SELECT pg_terminate_backend(pid) WHERE pid = 12345;
```

### Estatísticas do Banco de Dados

Obter informações sobre o uso e métricas de desempenho do banco de dados.

```sql
# Estatísticas da tabela
SELECT schemaname, tablename, n_tup_ins, n_tup_upd, n_tup_del
FROM pg_stat_user_tables;
# Estatísticas de uso de índice
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes;
# Tamanho do banco de dados
SELECT pg_size_pretty(pg_database_size('mydatabase'));
```

## Recursos Avançados

### Views: `CREATE VIEW`

Criar tabelas virtuais para simplificar consultas complexas e fornecer abstração de dados.

```sql
# Criar view simples
CREATE VIEW active_users AS
SELECT id, username, email
FROM users WHERE active = true;
# Criar view com joins
CREATE OR REPLACE VIEW order_summary AS
SELECT u.username, COUNT(o.id) as total_orders,
       SUM(o.total) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.username;
# Excluir view
DROP VIEW IF EXISTS order_summary;
```

### Triggers e Funções

Automatizar operações de banco de dados com procedimentos armazenados e triggers.

```sql
# Criar função
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
# Criar trigger
CREATE TRIGGER update_user_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();
```

### Transações

Garantir a consistência dos dados com controle de transação.

```sql
# Iniciar transação
BEGIN;
UPDATE accounts SET balance = balance - 100
WHERE id = 1;
UPDATE accounts SET balance = balance + 100
WHERE id = 2;
# Confirmar transação
COMMIT;
# Reverter se necessário
ROLLBACK;
# Savepoints
SAVEPOINT my_savepoint;
ROLLBACK TO my_savepoint;
```

### Configuração e Ajuste (Tuning)

Otimizar as configurações do servidor PostgreSQL para melhor desempenho.

```sql
# Visualizar configuração atual
SHOW shared_buffers;
SHOW max_connections;
# Definir parâmetros de configuração
SET work_mem = '256MB';
SET random_page_cost = 1.1;
# Recarregar configuração
SELECT pg_reload_conf();
# Mostrar localização do arquivo de configuração
SHOW config_file;
```

## Configuração e Dicas do psql

### Arquivos de Conexão: `.pgpass`

Armazenar credenciais de banco de dados com segurança para autenticação automática.

```bash
# Criar arquivo .pgpass (formato: hostname:port:database:username:password)
echo "localhost:5432:mydatabase:myuser:mypassword" >> ~/.pgpass
# Definir permissões adequadas
chmod 600 ~/.pgpass
# Usar arquivo de serviço de conexão
# ~/.pg_service.conf
[mydb]
host=localhost
port=5432
dbname=mydatabase
user=myuser
```

### Configuração do psql: `.psqlrc`

Personalizar as configurações de inicialização e comportamento do psql.

```bash
# Criar arquivo ~/.psqlrc com configurações personalizadas
\set QUIET on
\timing on
\set PROMPT1 '%n@%M:%> %`date` %R%# '
\set HISTSIZE 5000
\set COMP_KEYWORD_CASE upper
\x auto
\set QUIET off
# Aliases personalizados
\set show_slow_queries 'SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;'
```

### Variáveis de Ambiente

Definir variáveis de ambiente do PostgreSQL para facilitar as conexões.

```bash
# Definir no seu perfil de shell
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=mydatabase
export PGUSER=myuser
# Então simplesmente conectar com
psql
# Ou usar banco de dados específico no ambiente
PGDATABASE=testdb psql
```

### Informações do Banco de Dados

Obter informações sobre objetos e estrutura do banco de dados.

```bash
# Listar bancos de dados
\l, \l+
# Listar tabelas no banco de dados atual
\dt, \dt+
# Listar views
\dv, \dv+
# Listar índices
\di, \di+
# Listar funções
\df, \df+
# Listar sequências
\ds, \ds+
# Descrever estrutura da tabela
\d table_name
\d+ table_name
# Listar restrições da tabela
\d+ table_name
# Mostrar permissões da tabela
\dp table_name
\z table_name
# Listar chaves estrangeiras
SELECT * FROM information_schema.table_constraints
WHERE constraint_type = 'FOREIGN KEY';
```

### Saída e Formatação

Controlar como o psql exibe os resultados das consultas e a saída.

```bash
# Alternar saída expandida
\x
# Mudar formato de saída
\H  -- Saída HTML
\t  -- Apenas tuplas (sem cabeçalhos)
# Saída para arquivo
\o filename.txt
SELECT * FROM users;
\o  -- Parar saída para arquivo
# Executar SQL de arquivo
\i script.sql
# Editar consulta no editor externo
\e
```

### Tempo e Histórico

Rastrear o desempenho da consulta e gerenciar o histórico de comandos.

```bash
# Alternar exibição de tempo
\timing
# Mostrar histórico de comandos
\s
# Salvar histórico de comandos em arquivo
\s filename.txt
# Limpar tela
\! clear  -- Linux/Mac
\! cls   -- Windows
# Mostrar último erro
\errverbose
```

## Links Relevantes

- <router-link to="/database">Folha de Dicas de Banco de Dados</router-link>
- <router-link to="/mysql">Folha de Dicas MySQL</router-link>
- <router-link to="/sqlite">Folha de Dicas SQLite</router-link>
- <router-link to="/mongodb">Folha de Dicas MongoDB</router-link>
- <router-link to="/redis">Folha de Dicas Redis</router-link>
- <router-link to="/python">Folha de Dicas Python</router-link>
- <router-link to="/javascript">Folha de Dicas JavaScript</router-link>
- <router-link to="/devops">Folha de Dicas DevOps</router-link>

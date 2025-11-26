---
title: 'Guia Rápido de PostgreSQL'
description: 'Aprenda PostgreSQL com nosso guia completo, cobrindo comandos essenciais, conceitos e melhores práticas.'
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
psql -U nome_usuario -d nome_banco
# Conectar ao banco de dados remoto
psql -h nome_host -p 5432 -U nome_usuario -d nome_banco
# Conectar com solicitação de senha
psql -U postgres -W
# Conectar usando string de conexão
psql "host=localhost port=5432 dbname=meubanco user=meuusuario"
```

### Criar Banco de Dados: `CREATE DATABASE`

Crie um novo banco de dados no PostgreSQL usando o comando CREATE DATABASE.

```sql
# Criar um novo banco de dados
CREATE DATABASE meu_banco;
# Criar banco de dados com proprietário
CREATE DATABASE meu_banco OWNER meu_usuario;
# Criar banco de dados com codificação
CREATE DATABASE meu_banco
  WITH ENCODING 'UTF8'
  LC_COLLATE='pt_BR.UTF-8'
  LC_CTYPE='pt_BR.UTF-8';
```

### Listar Bancos de Dados: `\l`

Liste todos os bancos de dados no servidor PostgreSQL.

```bash
# Listar todos os bancos de dados
\l
# Listar bancos de dados com informações detalhadas
\l+
# Conectar a um banco de dados diferente
\c nome_banco
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
\d nome_tabela
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
CREATE TABLE usuarios (
    id SERIAL PRIMARY KEY,
    nome_usuario VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    criado_em TIMESTAMP DEFAULT NOW()
);

# Tabela com chave estrangeira
CREATE TABLE pedidos (
    id SERIAL PRIMARY KEY,
    id_usuario INTEGER REFERENCES usuarios(id),
    total DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pendente'
);
```

### Modificar Tabelas: `ALTER TABLE`

Adicionar, modificar ou remover colunas e restrições de tabelas existentes.

```sql
# Adicionar nova coluna
ALTER TABLE usuarios ADD COLUMN telefone VARCHAR(15);
# Alterar tipo de coluna
ALTER TABLE usuarios ALTER COLUMN telefone TYPE VARCHAR(20);
# Remover coluna
ALTER TABLE usuarios DROP COLUMN telefone;
# Adicionar restrição
ALTER TABLE usuarios ADD CONSTRAINT email_unico
    UNIQUE (email);
```

### Remover e Truncar: `DROP/TRUNCATE`

Remover tabelas ou limpar todos os dados das tabelas.

```sql
# Remover tabela completamente
DROP TABLE IF EXISTS tabela_antiga;
# Remover todos os dados, mas manter a estrutura
TRUNCATE TABLE usuarios;
# Truncar com reinicialização da identidade
TRUNCATE TABLE usuarios RESTART IDENTITY;
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
id_usuario INTEGER REFERENCES usuarios(id)

# Restrição única
email VARCHAR(100) UNIQUE

# Restrição de verificação (CHECK)
idade INTEGER CHECK (idade >= 0)

# Não nulo
nome VARCHAR(50) NOT NULL
```

### Índices: `CREATE INDEX`

Melhorar o desempenho das consultas com índices de banco de dados.

```sql
# Índice básico
CREATE INDEX idx_nome_usuario ON usuarios(nome_usuario);
# Índice único
CREATE UNIQUE INDEX idx_email_unico
    ON usuarios(email);
# Índice composto
CREATE INDEX idx_usuario_data
    ON pedidos(id_usuario, criado_em);
# Índice parcial
CREATE INDEX idx_usuarios_ativos
    ON usuarios(nome_usuario) WHERE ativo = true;
# Remover índice
DROP INDEX IF EXISTS idx_nome_usuario;
```

### Sequências: `CREATE SEQUENCE`

Gerar valores numéricos únicos automaticamente.

```sql
# Criar sequência
CREATE SEQUENCE id_usuario_seq;
# Usar sequência na tabela
CREATE TABLE usuarios (
    id INTEGER DEFAULT nextval('id_usuario_seq'),
    nome_usuario VARCHAR(50)
);
# Reiniciar sequência
ALTER SEQUENCE id_usuario_seq RESTART WITH 1000;
```

## Operações CRUD

### Inserir Dados: `INSERT`

Adicionar novos registros às tabelas do banco de dados.

```sql
# Inserir registro único
INSERT INTO usuarios (nome_usuario, email)
VALUES ('joao_silva', 'joao@exemplo.com');
# Inserir múltiplos registros
INSERT INTO usuarios (nome_usuario, email) VALUES
    ('ana', 'ana@exemplo.com'),
    ('pedro', 'pedro@exemplo.com');
# Inserir com retorno
INSERT INTO usuarios (nome_usuario, email)
VALUES ('maria', 'maria@exemplo.com')
RETURNING id, criado_em;
# Inserir a partir de seleção
INSERT INTO usuarios_arquivados
SELECT * FROM usuarios WHERE ativo = false;
```

### Atualizar Dados: `UPDATE`

Modificar registros existentes nas tabelas do banco de dados.

```sql
# Atualizar registros específicos
UPDATE usuarios
SET email = 'novoemail@exemplo.com'
WHERE nome_usuario = 'joao_silva';
# Atualizar múltiplas colunas
UPDATE usuarios
SET email = 'novo@exemplo.com',
    atualizado_em = NOW()
WHERE id = 1;
# Atualizar com subconsulta
UPDATE pedidos
SET total = (SELECT SUM(preco) FROM itens_pedido
            WHERE pedido_id = pedidos.id);
```

### Selecionar Dados: `SELECT`

Consultar e recuperar dados das tabelas do banco de dados.

```sql
# Seleção básica
SELECT * FROM usuarios;
# Selecionar colunas específicas
SELECT id, nome_usuario, email FROM usuarios;
# Selecionar com condições
SELECT * FROM usuarios
WHERE ativo = true AND criado_em > '2024-01-01';
# Selecionar com ordenação e limites
SELECT * FROM usuarios
ORDER BY criado_em DESC
LIMIT 10 OFFSET 20;
```

### Deletar Dados: `DELETE`

Remover registros das tabelas do banco de dados.

```sql
# Deletar registros específicos
DELETE FROM usuarios
WHERE ativo = false;
# Deletar com subconsulta
DELETE FROM pedidos
WHERE id_usuario IN (
    SELECT id FROM usuarios WHERE ativo = false
);
# Deletar todos os registros
DELETE FROM tabela_temp;
# Deletar com retorno
DELETE FROM usuarios
WHERE id = 5
RETURNING *;
```

## Consultas Avançadas

### Joins: `INNER/LEFT/RIGHT JOIN`

Combinar dados de múltiplas tabelas usando vários tipos de join.

```sql
# Inner join
SELECT u.nome_usuario, o.total
FROM usuarios u
INNER JOIN pedidos o ON u.id = o.id_usuario;
# Left join
SELECT u.nome_usuario, o.total
FROM usuarios u
LEFT JOIN pedidos o ON u.id = o.id_usuario;
# Múltiplos joins
SELECT u.nome_usuario, o.total, p.nome
FROM usuarios u
JOIN pedidos o ON u.id = o.id_usuario
JOIN produtos p ON o.id_produto = p.id;
```

### Subconsultas e CTEs

Usar consultas aninhadas e expressões de tabela comuns (CTEs) para operações complexas.

```sql
# Subconsulta em WHERE
SELECT * FROM usuarios
WHERE id IN (SELECT id_usuario FROM pedidos);
# Expressão de Tabela Comum (CTE)
WITH usuarios_ativos AS (
    SELECT * FROM usuarios WHERE ativo = true
)
SELECT ua.nome_usuario, COUNT(p.id) as contagem_pedidos
FROM usuarios_ativos ua
LEFT JOIN pedidos p ON ua.id = p.id_usuario
GROUP BY ua.nome_usuario;
```

### Agregação: `GROUP BY`

Agrupar dados e aplicar funções de agregação para análise.

```sql
# Agrupamento básico
SELECT status, COUNT(*) as contagem
FROM pedidos
GROUP BY status;
# Múltiplas agregações
SELECT id_usuario,
       COUNT(*) as contagem_pedidos,
       SUM(total) as total_gasto,
       AVG(total) as pedido_medio
FROM pedidos
GROUP BY id_usuario
HAVING COUNT(*) > 5;
```

### Funções de Janela (Window Functions)

Realizar cálculos em linhas relacionadas sem agrupar.

```sql
# Numeração de linhas
SELECT nome_usuario, email,
       ROW_NUMBER() OVER (ORDER BY criado_em) as num_linha
FROM usuarios;
# Totais correntes (Running totals)
SELECT data, valor,
       SUM(valor) OVER (ORDER BY data) as total_corrente
FROM vendas;
# Classificação (Ranking)
SELECT nome_usuario, pontuacao,
       RANK() OVER (ORDER BY pontuacao DESC) as classificacao
FROM pontuacoes_usuario;
```

## Importação e Exportação de Dados

### Importação CSV: `COPY`

Importar dados de arquivos CSV para tabelas PostgreSQL.

```sql
# Importar de arquivo CSV
COPY usuarios(nome_usuario, email, idade)
FROM '/caminho/para/usuarios.csv'
DELIMITER ',' CSV HEADER;
# Importar com opções específicas
COPY produtos
FROM '/caminho/para/produtos.csv'
WITH (FORMAT csv, HEADER true, DELIMITER ';');
# Importar de stdin
\copy usuarios(nome_usuario, email) FROM STDIN WITH CSV;
```

### Exportação CSV: `COPY TO`

Exportar dados do PostgreSQL para arquivos CSV.

```sql
# Exportar para arquivo CSV
COPY usuarios TO '/caminho/para/usuarios_export.csv'
WITH (FORMAT csv, HEADER true);
# Exportar resultados de consulta
COPY (SELECT nome_usuario, email FROM usuarios WHERE ativo = true)
TO '/caminho/para/usuarios_ativos.csv' CSV HEADER;
# Exportar para stdout
\copy (SELECT * FROM pedidos) TO STDOUT WITH CSV HEADER;
```

### Backup e Restauração: `pg_dump`

Criar backups de banco de dados e restaurar a partir de arquivos de backup.

```bash
# Dump de banco de dados inteiro
pg_dump -U nome_usuario -h nome_host nome_banco > backup.sql
# Dump de tabela específica
pg_dump -U nome_usuario -t nome_tabela nome_banco > backup_tabela.sql
# Backup compactado
pg_dump -U nome_usuario -Fc nome_banco > backup.dump
# Restaurar de backup
psql -U nome_usuario -d nome_banco < backup.sql
# Restaurar backup compactado
pg_restore -U nome_usuario -d nome_banco backup.dump
```

### Operações com Dados JSON

Trabalhar com tipos de dados JSON e JSONB para dados semiestruturados.

```sql
# Inserir dados JSON
INSERT INTO produtos (nome, metadados)
VALUES ('Notebook', '{"marca": "Dell", "preco": 999.99}');
# Consultar campos JSON
SELECT nome, metadados->>'marca' as marca
FROM produtos
WHERE metadados->>'preco'::numeric > 500;
# Operações com array JSON
SELECT nome FROM produtos
WHERE metadados->'recursos' ? 'sem_fio';
```

## Gerenciamento de Usuários e Segurança

### Criar Usuários e Funções (Roles)

Gerenciar acesso ao banco de dados com usuários e funções.

```sql
# Criar usuário
CREATE USER meu_usuario WITH PASSWORD 'senha_secreta';
# Criar função
CREATE ROLE usuario_somente_leitura;
# Criar usuário com privilégios específicos
CREATE USER usuario_admin WITH
    CREATEDB CREATEROLE PASSWORD 'senha_admin';
# Conceder função a usuário
GRANT usuario_somente_leitura TO meu_usuario;
```

### Permissões: `GRANT/REVOKE`

Controlar o acesso a objetos de banco de dados através de permissões.

```sql
# Conceder permissões de tabela
GRANT SELECT, INSERT ON usuarios TO meu_usuario;
# Conceder todos os privilégios na tabela
GRANT ALL ON pedidos TO usuario_admin;
# Conceder permissões de banco de dados
GRANT CONNECT ON DATABASE meu_banco TO meu_usuario;
# Revogar permissões
REVOKE INSERT ON usuarios FROM meu_usuario;
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
# Verificar usuário atual
SELECT current_user;
# Visualizar associações de função (role memberships)
SELECT r.rolname, r.rolsuper, r.rolcreaterole
FROM pg_roles r;
```

### Senha e Segurança

Gerenciar senhas de usuários e configurações de segurança.

```sql
# Alterar senha do usuário
ALTER USER meu_usuario PASSWORD 'nova_senha';
# Definir expiração de senha
ALTER USER meu_usuario VALID UNTIL '2025-12-31';
# Criar usuário sem login
CREATE ROLE role_relatorios NOLOGIN;
# Habilitar/desabilitar usuário
ALTER USER meu_usuario WITH NOLOGIN;
ALTER USER meu_usuario WITH LOGIN;
```

## Desempenho e Monitoramento

### Análise de Consulta: `EXPLAIN`

Analisar planos de execução de consultas e otimizar o desempenho.

```sql
# Mostrar plano de execução da consulta
EXPLAIN SELECT * FROM usuarios WHERE ativo = true;
# Analisar com estatísticas de execução reais
EXPLAIN ANALYZE
SELECT u.nome_usuario, COUNT(o.id)
FROM usuarios u
LEFT JOIN pedidos o ON u.id = o.id_usuario
GROUP BY u.nome_usuario;
# Informações detalhadas de execução
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT * FROM tabela_grande WHERE coluna_indexada = 'valor';
```

### Manutenção do Banco de Dados: `VACUUM`

Manter o desempenho do banco de dados através de operações de limpeza regulares.

```sql
# Vacuum básico
VACUUM usuarios;
# Vacuum completo com análise
VACUUM FULL ANALYZE usuarios;
# Status do auto-vacuum
SELECT schemaname, tablename, last_vacuum, last_autovacuum
FROM pg_stat_user_tables;
# Reindexar tabela
REINDEX TABLE usuarios;
```

### Monitoramento de Consultas

Rastrear a atividade do banco de dados e identificar problemas de desempenho.

```sql
# Atividade atual
SELECT pid, usename, query, state
FROM pg_stat_activity
WHERE state != 'idle';
# Consultas de longa duração
SELECT pid, now() - query_start as duracao, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duracao DESC;
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
SELECT pg_size_pretty(pg_database_size('meu_banco'));
```

## Recursos Avançados

### Views: `CREATE VIEW`

Criar tabelas virtuais para simplificar consultas complexas e fornecer abstração de dados.

```sql
# Criar view simples
CREATE VIEW usuarios_ativos AS
SELECT id, nome_usuario, email
FROM usuarios WHERE ativo = true;
# Criar view com joins
CREATE OR REPLACE VIEW resumo_pedidos AS
SELECT u.nome_usuario, COUNT(o.id) as total_pedidos,
       SUM(o.total) as total_gasto
FROM usuarios u
LEFT JOIN pedidos o ON u.id = o.id_usuario
GROUP BY u.id, u.nome_usuario;
# Remover view
DROP VIEW IF EXISTS resumo_pedidos;
```

### Triggers e Funções

Automatizar operações de banco de dados com procedimentos armazenados e triggers.

```sql
# Criar função
CREATE OR REPLACE FUNCTION atualizar_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.atualizado_em = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
# Criar trigger
CREATE TRIGGER atualizar_timestamp_usuario
    BEFORE UPDATE ON usuarios
    FOR EACH ROW
    EXECUTE FUNCTION atualizar_timestamp();
```

### Transações

Garantir a consistência dos dados com controle de transação.

```sql
# Iniciar transação
BEGIN;
UPDATE contas SET saldo = saldo - 100
WHERE id = 1;
UPDATE contas SET saldo = saldo + 100
WHERE id = 2;
# Confirmar transação
COMMIT;
# Reverter se necessário
ROLLBACK;
# Savepoints
SAVEPOINT meu_savepoint;
ROLLBACK TO meu_savepoint;
```

### Configuração e Ajuste Fino (Tuning)

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
# Criar arquivo .pgpass (formato: host:porta:banco:usuario:senha)
echo "localhost:5432:meu_banco:meu_usuario:minhasenha" >> ~/.pgpass
# Definir permissões adequadas
chmod 600 ~/.pgpass
# Usar arquivo de serviço de conexão
# ~/.pg_service.conf
[meubanco]
host=localhost
port=5432
dbname=meu_banco
user=meu_usuario
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
\set mostrar_consultas_lentas 'SELECT query, mean_time, calls FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;'
```

### Variáveis de Ambiente

Definir variáveis de ambiente PostgreSQL para facilitar as conexões.

```bash
# Definir no seu perfil de shell
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=meu_banco
export PGUSER=meu_usuario
# Então simplesmente conecte com
psql
# Ou use ambiente específico
PGDATABASE=teste_db psql
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
\d nome_tabela
\d+ nome_tabela
# Listar restrições da tabela
\d+ nome_tabela
# Mostrar permissões da tabela
\dp nome_tabela
\z nome_tabela
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
\o nome_arquivo.txt
SELECT * FROM usuarios;
\o  -- Parar saída para arquivo
# Executar SQL de arquivo
\i script.sql
# Editar consulta no editor externo
\e
```

### Tempo e Histórico

Rastrear o desempenho das consultas e gerenciar o histórico de comandos.

```bash
# Alternar exibição de tempo
\timing
# Mostrar histórico de comandos
\s
# Salvar histórico de comandos em arquivo
\s nome_arquivo.txt
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

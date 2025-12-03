---
title: 'Folha de Referência SQLite | LabEx'
description: 'Aprenda o banco de dados SQLite com esta folha de referência abrangente. Referência rápida para sintaxe SQL do SQLite, transações, triggers, views e gerenciamento leve de banco de dados para aplicações.'
pdfUrl: '/cheatsheets/pdf/sqlite-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas SQLite
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/sqlite">Aprenda SQLite com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda gerenciamento de banco de dados SQLite através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de SQLite cobrindo operações SQL essenciais, manipulação de dados, otimização de consultas, design de banco de dados e ajuste de desempenho. Domine o desenvolvimento de banco de dados leve e o gerenciamento eficiente de dados.
</base-disclaimer-content>
</base-disclaimer>

## Criação e Conexão de Banco de Dados

### Criar Banco de Dados: `sqlite3 database.db`

Cria um novo arquivo de banco de dados SQLite.

```bash
# Cria ou abre um banco de dados
sqlite3 mydata.db
# Cria banco de dados em memória (temporário)
sqlite3 :memory:
# Cria banco de dados com comando
.open mydata.db
# Mostra todos os bancos de dados anexados
.databases
# Mostra o esquema de todas as tabelas
.schema
# Mostra a lista de tabelas
.tables
# Sai do SQLite
.exit
# Comando de saída alternativo
.quit
```

### Informações do Banco de Dados: `.databases`

Lista todos os bancos de dados anexados e seus arquivos.

```sql
-- Anexa outro banco de dados
ATTACH DATABASE 'backup.db' AS backup;
-- Consulta do banco de dados anexado
SELECT * FROM backup.users;
-- Desanexa banco de dados
DETACH DATABASE backup;
```

### Sair do SQLite: `.exit` ou `.quit`

Fecha a interface de linha de comando do SQLite.

```bash
.exit
.quit
```

### Backup do Banco de Dados: `.backup`

Cria um backup do banco de dados atual.

```bash
# Backup para arquivo
.backup backup.db
# Restaura do backup
.restore backup.db
# Exporta para arquivo SQL
.output backup.sql
.dump
# Importa script SQL
.read backup.sql
```

## Criação de Tabela e Esquema

### Criar Tabela: `CREATE TABLE`

Cria uma nova tabela no banco de dados com colunas e restrições.

```sql
-- Criação básica de tabela
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    age INTEGER,
    created_date DATE DEFAULT CURRENT_TIMESTAMP
);

-- Tabela com chave estrangeira
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    amount REAL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

<BaseQuiz id="sqlite-create-table-1" correct="A">
  <template #question>
    O que `INTEGER PRIMARY KEY AUTOINCREMENT` faz no SQLite?
  </template>
  
  <BaseQuizOption value="A" correct>Cria uma chave primária inteira com auto-incremento</BaseQuizOption>
  <BaseQuizOption value="B">Cria uma chave primária de texto</BaseQuizOption>
  <BaseQuizOption value="C">Cria uma restrição de chave estrangeira</BaseQuizOption>
  <BaseQuizOption value="D">Cria um índice exclusivo</BaseQuizOption>
  
  <BaseQuizAnswer>
    `INTEGER PRIMARY KEY AUTOINCREMENT` cria uma coluna inteira que se incrementa automaticamente para cada nova linha e serve como chave primária. Isso garante que cada linha tenha um identificador exclusivo.
  </BaseQuizAnswer>
</BaseQuiz>

### Tipos de Dados: `INTEGER`, `TEXT`, `REAL`, `BLOB`

O SQLite usa tipagem dinâmica com classes de armazenamento para armazenamento de dados flexível.

```sql
-- Tipos de dados comuns
CREATE TABLE products (
    id INTEGER,           -- Números inteiros
    name TEXT,           -- Strings de texto
    price REAL,          -- Números de ponto flutuante
    image BLOB,          -- Dados binários
    active BOOLEAN,      -- Booleano (armazenado como INTEGER)
    created_at DATETIME  -- Data e hora
);
```

### Restrições: `PRIMARY KEY`, `NOT NULL`, `UNIQUE`

Define restrições para impor integridade de dados e relacionamentos de tabela.

```sql
CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL,
    salary REAL CHECK(salary > 0),
    manager_id INTEGER REFERENCES employees(id)
);
```

## Inserção e Modificação de Dados

### Inserir Dados: `INSERT INTO`

Adiciona novos registros a tabelas com linhas únicas ou múltiplas.

```sql
-- Insere registro único
INSERT INTO users (name, email, age)
VALUES ('John Doe', 'john@email.com', 30);

-- Insere múltiplos registros
INSERT INTO users (name, email, age) VALUES
    ('Jane Smith', 'jane@email.com', 25),
    ('Bob Wilson', 'bob@email.com', 35);

-- Insere com todas as colunas
INSERT INTO users VALUES
    (NULL, 'Alice Brown', 'alice@email.com', 28, datetime('now'));
```

### Atualizar Dados: `UPDATE SET`

Modifica registros existentes com base em condições.

```sql
-- Atualiza coluna única
UPDATE users SET age = 31 WHERE name = 'John Doe';

-- Atualiza múltiplas colunas
UPDATE users SET
    email = 'newemail@example.com',
    age = age + 1
WHERE id = 1;

-- Atualiza com subconsulta
UPDATE products SET price = price * 1.1
WHERE category = 'Electronics';
```

<BaseQuiz id="sqlite-update-1" correct="D">
  <template #question>
    O que acontece se você esquecer a cláusula WHERE em uma instrução UPDATE?
  </template>
  
  <BaseQuizOption value="A">A atualização falha</BaseQuizOption>
  <BaseQuizOption value="B">Apenas a primeira linha é atualizada</BaseQuizOption>
  <BaseQuizOption value="C">Nada acontece</BaseQuizOption>
  <BaseQuizOption value="D" correct>Todas as linhas da tabela são atualizadas</BaseQuizOption>
  
  <BaseQuizAnswer>
    Sem uma cláusula WHERE, a instrução UPDATE modificará todas as linhas da tabela. Sempre use WHERE para especificar quais linhas devem ser atualizadas para evitar alterar dados não intencionais acidentalmente.
  </BaseQuizAnswer>
</BaseQuiz>

### Excluir Dados: `DELETE FROM`

Remove registros de tabelas com base em condições especificadas.

```sql
-- Exclui registros específicos
DELETE FROM users WHERE age < 18;

-- Exclui todos os registros (mantém a estrutura da tabela)
DELETE FROM users;

-- Exclui com subconsulta
DELETE FROM orders
WHERE user_id IN (SELECT id FROM users WHERE active = 0);
```

### Upsert: `INSERT OR REPLACE`

Insere novos registros ou atualiza os existentes com base em conflitos.

```sql
-- Insere ou substitui em caso de conflito
INSERT OR REPLACE INTO users (id, name, email)
VALUES (1, 'Updated Name', 'updated@email.com');

-- Insere ou ignora duplicatas
INSERT OR IGNORE INTO users (name, email)
VALUES ('Duplicate', 'existing@email.com');
```

<BaseQuiz id="sqlite-upsert-1" correct="A">
  <template #question>
    Qual é a diferença entre `INSERT OR REPLACE` e `INSERT OR IGNORE`?
  </template>
  
  <BaseQuizOption value="A" correct>REPLACE atualiza linhas existentes, IGNORE ignora duplicatas</BaseQuizOption>
  <BaseQuizOption value="B">Não há diferença</BaseQuizOption>
  <BaseQuizOption value="C">REPLACE exclui a linha, IGNORE a atualiza</BaseQuizOption>
  <BaseQuizOption value="D">REPLACE funciona com tabelas, IGNORE funciona com visões</BaseQuizOption>
  
  <BaseQuizAnswer>
    `INSERT OR REPLACE` substituirá uma linha existente se houver um conflito (por exemplo, chave primária duplicada). `INSERT OR IGNORE` simplesmente ignorará a inserção se houver um conflito, deixando a linha existente inalterada.
  </BaseQuizAnswer>
</BaseQuiz>

## Consulta e Seleção de Dados

### Consultas Básicas: `SELECT`

Consulta dados de tabelas usando a instrução SELECT com várias opções.

```sql
-- Seleciona todas as colunas
SELECT * FROM users;

-- Seleciona colunas específicas
SELECT name, email FROM users;

-- Seleciona com alias
SELECT name AS full_name, age AS years_old FROM users;

-- Seleciona valores exclusivos
SELECT DISTINCT department FROM employees;
```

<BaseQuiz id="sqlite-select-1" correct="B">
  <template #question>
    O que `SELECT DISTINCT` faz?
  </template>
  
  <BaseQuizOption value="A">Seleciona todas as linhas</BaseQuizOption>
  <BaseQuizOption value="B" correct>Retorna apenas valores exclusivos, removendo duplicatas</BaseQuizOption>
  <BaseQuizOption value="C">Seleciona apenas a primeira linha</BaseQuizOption>
  <BaseQuizOption value="D">Ordena os resultados</BaseQuizOption>
  
  <BaseQuizAnswer>
    `SELECT DISTINCT` elimina linhas duplicadas do conjunto de resultados, retornando apenas valores exclusivos. Isso é útil quando você deseja ver todos os valores exclusivos em uma coluna.
  </BaseQuizAnswer>
</BaseQuiz>

### Filtragem: `WHERE`

Filtra linhas usando várias condições e operadores de comparação.

```sql
-- Condições simples
SELECT * FROM users WHERE age > 25;
SELECT * FROM users WHERE name = 'John Doe';

-- Múltiplas condições
SELECT * FROM users WHERE age > 18 AND age < 65;
SELECT * FROM users WHERE department = 'IT' OR salary > 50000;

-- Correspondência de padrão
SELECT * FROM users WHERE email LIKE '%@gmail.com';
SELECT * FROM users WHERE name GLOB 'J*';
```

### Ordenação e Limitação: `ORDER BY` / `LIMIT`

Ordena resultados e limita o número de linhas retornadas para melhor gerenciamento de dados.

```sql
-- Ordena ascendente (padrão)
SELECT * FROM users ORDER BY age;

-- Ordena descendente
SELECT * FROM users ORDER BY age DESC;

-- Múltiplas colunas de ordenação
SELECT * FROM users ORDER BY department, salary DESC;

-- Limita resultados
SELECT * FROM users LIMIT 10;

-- Limita com deslocamento (paginação)
SELECT * FROM users LIMIT 10 OFFSET 20;
```

### Funções de Agregação: `COUNT`, `SUM`, `AVG`

Executa cálculos em grupos de linhas para análise estatística.

```sql
-- Conta registros
SELECT COUNT(*) FROM users;
SELECT COUNT(DISTINCT department) FROM employees;

-- Soma e média
SELECT SUM(salary), AVG(salary) FROM employees;

-- Valores Mínimo e Máximo
SELECT MIN(age), MAX(age) FROM users;
```

## Consultas Avançadas

### Agrupamento: `GROUP BY` / `HAVING`

Agrupa linhas por critérios especificados e filtra grupos para relatórios de resumo.

```sql
-- Agrupa por coluna única
SELECT department, COUNT(*)
FROM employees
GROUP BY department;

-- Agrupa por múltiplas colunas
SELECT department, job_title, AVG(salary)
FROM employees
GROUP BY department, job_title;

-- Filtra grupos com HAVING
SELECT department, AVG(salary) as avg_salary
FROM employees
GROUP BY department
HAVING avg_salary > 60000;
```

### Subconsultas

Usa consultas aninhadas para recuperação complexa de dados e lógica condicional.

```sql
-- Subconsulta na cláusula WHERE
SELECT name FROM users
WHERE age > (SELECT AVG(age) FROM users);

-- Subconsulta na cláusula FROM
SELECT dept, avg_salary FROM (
    SELECT department as dept, AVG(salary) as avg_salary
    FROM employees
    GROUP BY department
) WHERE avg_salary > 50000;

-- Subconsulta EXISTS
SELECT * FROM users u
WHERE EXISTS (
    SELECT 1 FROM orders o WHERE o.user_id = u.id
);
```

### Junções: `INNER`, `LEFT`, `RIGHT`

Combina dados de múltiplas tabelas usando vários tipos de junção para consultas relacionais.

```sql
-- Inner join
SELECT u.name, o.amount
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- Left join (mostra todos os usuários)
SELECT u.name, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- Self join
SELECT e1.name as employee, e2.name as manager
FROM employees e1
LEFT JOIN employees e2 ON e1.manager_id = e2.id;
```

### Operações de Conjunto: `UNION` / `INTERSECT`

Combina resultados de múltiplas consultas usando operações de conjunto.

```sql
-- Union (combina resultados)
SELECT name FROM customers
UNION
SELECT name FROM suppliers;

-- Intersect (resultados comuns)
SELECT email FROM users
INTERSECT
SELECT email FROM newsletter_subscribers;

-- Except (diferença)
SELECT email FROM users
EXCEPT
SELECT email FROM unsubscribed;
```

## Índices e Desempenho

### Criar Índices: `CREATE INDEX`

Cria índices em colunas para acelerar consultas e melhorar o desempenho.

```sql
-- Índice de coluna única
CREATE INDEX idx_user_email ON users(email);

-- Índice de múltiplas colunas
CREATE INDEX idx_order_user_date ON orders(user_id, order_date);

-- Índice exclusivo
CREATE UNIQUE INDEX idx_product_sku ON products(sku);

-- Índice parcial (com condição)
CREATE INDEX idx_active_users ON users(name) WHERE active = 1;
```

### Análise de Consulta: `EXPLAIN QUERY PLAN`

Analisa planos de execução de consulta para identificar gargalos de desempenho.

```sql
-- Analisa o desempenho da consulta
EXPLAIN QUERY PLAN SELECT * FROM users WHERE email = 'test@example.com';

-- Verifica se o índice está sendo usado
EXPLAIN QUERY PLAN SELECT * FROM orders WHERE user_id = 123;
```

### Otimização do Banco de Dados: `VACUUM` / `ANALYZE`

Otimiza arquivos de banco de dados e atualiza estatísticas para melhor desempenho.

```sql
-- Reconstrói o banco de dados para recuperar espaço
VACUUM;

-- Atualiza estatísticas de índice
ANALYZE;

-- Verifica a integridade do banco de dados
PRAGMA integrity_check;
```

### Configurações de Desempenho: `PRAGMA`

Configura configurações do SQLite para desempenho e comportamento ótimos.

```sql
-- Define o modo de journal para melhor desempenho
PRAGMA journal_mode = WAL;

-- Define o modo síncrono
PRAGMA synchronous = NORMAL;

-- Habilita restrições de chave estrangeira
PRAGMA foreign_keys = ON;

-- Define o tamanho do cache (em páginas)
PRAGMA cache_size = 10000;
```

## Visões e Triggers

### Visões: `CREATE VIEW`

Cria tabelas virtuais que representam consultas armazenadas para acesso a dados reutilizável.

```sql
-- Cria uma visão simples
CREATE VIEW active_users AS
SELECT id, name, email
FROM users
WHERE active = 1;

-- Visão complexa com junções
CREATE VIEW order_summary AS
SELECT
    u.name,
    COUNT(o.id) as total_orders,
    SUM(o.amount) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- Consulta uma visão
SELECT * FROM active_users WHERE name LIKE 'J%';

-- Exclui uma visão
DROP VIEW IF EXISTS order_summary;
```

### Usando Visões

Consulta visões como tabelas regulares para acesso simplificado a dados.

```sql
SELECT * FROM active_users;
SELECT * FROM order_summary WHERE total_spent > 1000;
```

### Triggers: `CREATE TRIGGER`

Executa código automaticamente em resposta a eventos do banco de dados.

```sql
-- Trigger em INSERT
CREATE TRIGGER update_user_count
AFTER INSERT ON users
BEGIN
    UPDATE stats SET user_count = user_count + 1;
END;

-- Trigger em UPDATE
CREATE TRIGGER log_salary_changes
AFTER UPDATE OF salary ON employees
BEGIN
    INSERT INTO audit_log (table_name, action, old_value, new_value)
    VALUES ('employees', 'salary_update', OLD.salary, NEW.salary);
END;

-- Exclui trigger
DROP TRIGGER IF EXISTS update_user_count;
```

## Tipos de Dados e Funções

### Funções de Data e Hora

Lida com operações de data e hora com as funções internas do SQLite.

```sql
-- Data/hora atual
SELECT datetime('now');
SELECT date('now');
SELECT time('now');

-- Aritmética de data
SELECT date('now', '+1 day');
SELECT datetime('now', '-1 hour');
SELECT date('now', 'start of month');

-- Formata datas
SELECT strftime('%Y-%m-%d %H:%M', 'now');
SELECT strftime('%w', 'now'); -- dia da semana
```

### Funções de String

Manipula dados de texto com várias operações de string.

```sql
-- Manipulação de string
SELECT upper(name) FROM users;
SELECT lower(email) FROM users;
SELECT length(name) FROM users;
SELECT substr(name, 1, 3) FROM users;

-- Concatenação de string
SELECT name || ' - ' || email as display FROM users;
SELECT printf('%s (%d)', name, age) FROM users;

-- Substituição de string
SELECT replace(phone, '-', '') FROM users;
```

### Funções Numéricas

Executa operações matemáticas e cálculos.

```sql
-- Funções matemáticas
SELECT abs(-15);
SELECT round(price, 2) FROM products;
SELECT random(); -- número aleatório

-- Agregação com matemática
SELECT department, round(AVG(salary), 2) as avg_salary
FROM employees
GROUP BY department;
```

### Lógica Condicional: `CASE`

Implementa lógica condicional dentro de consultas SQL.

```sql
-- Declaração CASE simples
SELECT name,
    CASE
        WHEN age < 18 THEN 'Menor'
        WHEN age < 65 THEN 'Adulto'
        ELSE 'Idoso'
    END as age_category
FROM users;

-- CASE na cláusula WHERE
SELECT * FROM products
WHERE CASE WHEN category = 'Electronics' THEN price < 1000
          ELSE price < 100 END;
```

## Transações e Concorrência

### Controle de Transação

As transações do SQLite são totalmente compatíveis com ACID para operações de dados confiáveis.

```sql
-- Transação básica
BEGIN TRANSACTION;
INSERT INTO users (name, email) VALUES ('Test User', 'test@example.com');
UPDATE users SET age = 25 WHERE name = 'Test User';
COMMIT;

-- Transação com rollback
BEGIN;
DELETE FROM orders WHERE amount < 10;
-- Verifica resultados, faz rollback se necessário
ROLLBACK;

-- Savepoints para transações aninhadas
BEGIN;
SAVEPOINT sp1;
INSERT INTO products (name) VALUES ('Product A');
ROLLBACK TO sp1;
COMMIT;
```

### Bloqueio e Concorrência

Gerencia bloqueios de banco de dados e acesso concorrente para integridade de dados.

```sql
-- Verifica o status do bloqueio
PRAGMA locking_mode;

-- Define o modo WAL para melhor concorrência
PRAGMA journal_mode = WAL;

-- Timeout de ocupado para espera por bloqueios
PRAGMA busy_timeout = 5000;

-- Verifica as conexões de banco de dados atuais
.databases
```

## Ferramentas de Linha de Comando do SQLite

### Comandos de Banco de Dados: `.help`

Acessa a ajuda da linha de comando do SQLite e a documentação para comandos de ponto disponíveis.

```bash
# Mostra todos os comandos disponíveis
.help
# Mostra as configurações atuais
.show
# Define o formato de saída
.mode csv
.headers on
```

### Importação/Exportação: `.import` / `.export`

Transfere dados entre o SQLite e arquivos externos em vários formatos.

```bash
# Importa arquivo CSV
.mode csv
.import data.csv users

# Exporta para CSV
.headers on
.mode csv
.output users.csv
SELECT * FROM users;
```

### Gerenciamento de Esquema: `.schema` / `.tables`

Examina a estrutura do banco de dados e as definições de tabela para desenvolvimento e depuração.

```bash
# Mostra todas as tabelas
.tables
# Mostra o esquema para tabela específica
.schema users
# Mostra todos os esquemas
.schema
# Mostra informações da tabela
.mode column
.headers on
PRAGMA table_info(users);
```

### Formatação de Saída: `.mode`

Controla como os resultados da consulta são exibidos na interface de linha de comando.

```bash
# Diferentes modos de saída
.mode csv        # Valores separados por vírgula
.mode column     # Colunas alinhadas
.mode html       # Formato de tabela HTML
.mode json       # Formato JSON
.mode list       # Formato de lista
.mode table      # Formato de tabela (padrão)

# Define a largura da coluna
.width 10 15 20

# Salva a saída no arquivo
.output results.txt
SELECT * FROM users;
.output stdout

# Lê SQL do arquivo
.read script.sql

# Muda o arquivo de banco de dados
.open another_database.db
```

## Configuração e Ajustes

### Configurações do Banco de Dados: `PRAGMA`

Controla o comportamento do SQLite através de declarações pragma para otimização e configuração.

```sql
-- Informações do banco de dados
PRAGMA database_list;
PRAGMA table_info(users);
PRAGMA foreign_key_list(orders);

-- Configurações de desempenho
PRAGMA cache_size = 10000;
PRAGMA temp_store = memory;
PRAGMA mmap_size = 268435456;

-- Habilita restrições de chave estrangeira
PRAGMA foreign_keys = ON;

-- Define o modo de exclusão segura
PRAGMA secure_delete = ON;

-- Verifica restrições
PRAGMA foreign_key_check;
```

### Configurações de Segurança

Configura opções e restrições relacionadas à segurança do banco de dados.

```sql
-- Habilita restrições de chave estrangeira
PRAGMA foreign_keys = ON;

-- Modo de exclusão segura
PRAGMA secure_delete = ON;

-- Verifica integridade
PRAGMA integrity_check;
```

## Instalação e Configuração

### Download e Instalação

Baixa as ferramentas do SQLite e configura a interface de linha de comando para seu sistema operacional.

```bash
# Baixa de sqlite.org
# Para Windows: sqlite-tools-win32-x86-*.zip
# Para Linux/Mac: Use gerenciador de pacotes

# Ubuntu/Debian
sudo apt-get install sqlite3

# macOS com Homebrew
brew install sqlite

# Verifica a instalação
sqlite3 --version
```

### Criando Seu Primeiro Banco de Dados

Cria arquivos de banco de dados SQLite e começa a trabalhar com dados usando comandos simples.

```bash
# Cria novo banco de dados
sqlite3 myapp.db

# Cria tabela e adiciona dados
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE
);

INSERT INTO users (name, email)
VALUES ('John Doe', 'john@example.com');
```

### Integração com Linguagem de Programação

Usa SQLite com várias linguagens de programação através de bibliotecas internas ou de terceiros.

```python
# Python (módulo sqlite3 integrado)
import sqlite3
conn = sqlite3.connect('mydb.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users')
```

```javascript
// Node.js (requer pacote sqlite3)
const sqlite3 = require('sqlite3')
const db = new sqlite3.Database('mydb.db')
db.all('SELECT * FROM users', (err, rows) => {
  console.log(rows)
})
```

```php
// PHP (PDO SQLite integrado)
$pdo = new PDO('sqlite:mydb.db');
$stmt = $pdo->query('SELECT * FROM users');
```

## Links Relevantes

- <router-link to="/database">Folha de Dicas de Banco de Dados</router-link>
- <router-link to="/mysql">Folha de Dicas MySQL</router-link>
- <router-link to="/postgresql">Folha de Dicas PostgreSQL</router-link>
- <router-link to="/mongodb">Folha de Dicas MongoDB</router-link>
- <router-link to="/redis">Folha de Dicas Redis</router-link>
- <router-link to="/python">Folha de Dicas Python</router-link>
- <router-link to="/javascript">Folha de Dicas JavaScript</router-link>
- <router-link to="/devops">Folha de Dicas DevOps</router-link>

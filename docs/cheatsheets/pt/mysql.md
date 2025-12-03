---
title: 'Folha de Cola MySQL | LabEx'
description: 'Aprenda gerenciamento de banco de dados MySQL com esta folha de cola abrangente. Referência rápida para consultas SQL, junções, índices, transações, procedimentos armazenados e administração de banco de dados.'
pdfUrl: '/cheatsheets/pdf/mysql-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas MySQL
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/mysql">Aprenda MySQL com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda gerenciamento de banco de dados MySQL através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de MySQL cobrindo operações SQL essenciais, administração de banco de dados, otimização de desempenho e técnicas avançadas de consulta. Domine um dos sistemas de banco de dados relacionais mais populares do mundo.
</base-disclaimer-content>
</base-disclaimer>

## Conexão e Gerenciamento de Banco de Dados

### Conectar ao Servidor: `mysql -u username -p`

Conecta ao servidor MySQL usando a linha de comando.

```bash
# Conectar com nome de usuário e solicitação de senha
mysql -u root -p
# Conectar a um banco de dados específico
mysql -u username -p nome_do_banco_de_dados
# Conectar a um servidor remoto
mysql -h hostname -u username -p
# Conectar com especificação de porta
mysql -h hostname -P 3306 -u username -p nome_do_banco_de_dados
```

### Operações de Banco de Dados: `CREATE` / `DROP` / `USE`

Gerenciar bancos de dados no servidor.

```sql
# Criar um novo banco de dados
CREATE DATABASE company_db;
# Listar todos os bancos de dados
SHOW DATABASES;
# Selecionar um banco de dados para usar
USE company_db;
# Excluir um banco de dados (deletar permanentemente)
DROP DATABASE old_database;
```

<BaseQuiz id="mysql-database-1" correct="C">
  <template #question>
    O que `USE nome_do_banco_de_dados` faz?
  </template>
  
  <BaseQuizOption value="A">Cria um novo banco de dados</BaseQuizOption>
  <BaseQuizOption value="B">Exclui o banco de dados</BaseQuizOption>
  <BaseQuizOption value="C" correct>Seleciona o banco de dados para operações subsequentes</BaseQuizOption>
  <BaseQuizOption value="D">Mostra todas as tabelas no banco de dados</BaseQuizOption>
  
  <BaseQuizAnswer>
    A instrução `USE` seleciona um banco de dados, tornando-o o banco de dados ativo para todas as instruções SQL subsequentes. Isso é equivalente a selecionar um banco de dados ao conectar com `mysql -u user -p database_name`.
  </BaseQuizAnswer>
</BaseQuiz>

### Exportar Dados: `mysqldump`

Fazer backup dos dados do banco de dados para um arquivo SQL.

```bash
# Exportar banco de dados inteiro
mysqldump -u username -p database_name > backup.sql
# Exportar tabela específica
mysqldump -u username -p database_name table_name > table_backup.sql
# Exportar apenas a estrutura
mysqldump -u username -p --no-data database_name > structure.sql
# Backup completo do banco de dados com rotinas e triggers
mysqldump -u username -p --routines --triggers database_name > backup.sql
```

### Importar Dados: `mysql < file.sql`

Importar arquivo SQL para o banco de dados MySQL.

```bash
# Importar arquivo SQL para o banco de dados
mysql -u username -p database_name < backup.sql
# Importar sem especificar o banco de dados (se incluído no arquivo)
mysql -u username -p < full_backup.sql
```

### Gerenciamento de Usuários: `CREATE USER` / `GRANT`

Gerenciar usuários e permissões do banco de dados.

```sql
# Criar novo usuário
CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
# Conceder todos os privilégios
GRANT ALL PRIVILEGES ON database_name.* TO 'user'@'localhost';
# Conceder privilégios específicos
GRANT SELECT, INSERT, UPDATE ON table_name TO 'user'@'localhost';
# Aplicar alterações de privilégios
FLUSH PRIVILEGES;
```

### Mostrar Informações do Servidor: `SHOW STATUS` / `SHOW VARIABLES`

Exibir configuração e status do servidor.

```sql
# Mostrar status do servidor
SHOW STATUS;
# Mostrar variáveis de configuração
SHOW VARIABLES;
# Mostrar processos atuais
SHOW PROCESSLIST;
```

## Estrutura e Esquema da Tabela

### Criação de Tabela: `CREATE TABLE`

Criar novas tabelas com colunas e tipos de dados especificados.

```sql
# Criar tabela com vários tipos de dados
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    age INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# Criar tabela com chave estrangeira
CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Informações da Tabela: `DESCRIBE` / `SHOW`

Visualizar a estrutura da tabela e o conteúdo do banco de dados.

```sql
# Mostrar estrutura da tabela
DESCRIBE users;
# Sintaxe alternativa
SHOW COLUMNS FROM users;
# Listar todas as tabelas
SHOW TABLES;
# Mostrar instrução CREATE da tabela
SHOW CREATE TABLE users;
```

### Modificar Tabelas: `ALTER TABLE`

Alterar a estrutura da tabela existente, adicionar ou excluir colunas.

```sql
# Adicionar nova coluna
ALTER TABLE users ADD COLUMN phone VARCHAR(20);
# Excluir coluna
ALTER TABLE users DROP COLUMN age;
# Modificar tipo de coluna
ALTER TABLE users MODIFY COLUMN username VARCHAR(100);
# Renomear coluna
ALTER TABLE users CHANGE old_name new_name VARCHAR(50);
```

## Manipulação de Dados e Operações CRUD

### Inserir Dados: `INSERT INTO`

Adicionar novos registros às tabelas.

```sql
# Inserir registro único
INSERT INTO users (username, email, age)
VALUES ('john_doe', 'john@email.com', 25);
# Inserir múltiplos registros
INSERT INTO users (username, email, age) VALUES
('alice', 'alice@email.com', 30),
('bob', 'bob@email.com', 28);
# Inserir de outra tabela
INSERT INTO users_backup SELECT * FROM users;
```

<BaseQuiz id="mysql-insert-1" correct="A">
  <template #question>
    Qual é a sintaxe correta para inserir um único registro?
  </template>
  
  <BaseQuizOption value="A" correct>`INSERT INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="B">`INSERT table_name VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="C">`ADD INTO table_name (column1, column2) VALUES (value1, value2);`</BaseQuizOption>
  <BaseQuizOption value="D">`INSERT table_name (column1, column2) = (value1, value2);`</BaseQuizOption>
  
  <BaseQuizAnswer>
    A sintaxe correta é `INSERT INTO nome_da_tabela (colunas) VALUES (valores)`. A palavra-chave `INTO` é necessária, e você deve especificar tanto os nomes das colunas quanto os valores correspondentes.
  </BaseQuizAnswer>
</BaseQuiz>

### Atualizar Dados: `UPDATE`

Modificar registros existentes nas tabelas.

```sql
# Atualizar registro específico
UPDATE users SET age = 26 WHERE username = 'john_doe';
# Atualizar múltiplas colunas
UPDATE users SET age = 31, email = 'alice_new@email.com'
WHERE username = 'alice';
# Atualizar com cálculo
UPDATE products SET price = price * 1.1 WHERE category = 'electronics';
```

### Excluir Dados: `DELETE` / `TRUNCATE`

Remover registros das tabelas.

```sql
# Excluir registros específicos
DELETE FROM users WHERE age < 18;
# Excluir todos os registros (manter estrutura)
DELETE FROM users;
# Excluir todos os registros (mais rápido, redefine AUTO_INCREMENT)
TRUNCATE TABLE users;
# Excluir com JOIN
DELETE u FROM users u
JOIN inactive_accounts i ON u.id = i.user_id;
```

### Substituir Dados: `REPLACE` / `INSERT ... ON DUPLICATE KEY`

Lidar com situações de chave duplicada durante inserções.

```sql
# Substituir existente ou inserir novo
REPLACE INTO users (id, username, email)
VALUES (1, 'updated_user', 'new@email.com');
# Inserir ou atualizar em caso de chave duplicada
INSERT INTO users (username, email)
VALUES ('john', 'john@email.com')
ON DUPLICATE KEY UPDATE email = VALUES(email);
```

## Consulta e Seleção de Dados

### SELECT Básico: `SELECT * FROM`

Recuperar dados de tabelas com várias condições.

```sql
# Selecionar todas as colunas
SELECT * FROM users;
# Selecionar colunas específicas
SELECT username, email FROM users;
# Selecionar com condição WHERE
SELECT * FROM users WHERE age > 25;
# Selecionar com múltiplas condições
SELECT * FROM users WHERE age > 20 AND email LIKE '%gmail.com';
```

<BaseQuiz id="mysql-select-1" correct="D">
  <template #question>
    O que `SELECT * FROM users` retorna?
  </template>
  
  <BaseQuizOption value="A">Apenas a primeira linha da tabela users</BaseQuizOption>
  <BaseQuizOption value="B">Apenas a coluna username</BaseQuizOption>
  <BaseQuizOption value="C">A estrutura da tabela</BaseQuizOption>
  <BaseQuizOption value="D" correct>Todas as colunas e todas as linhas da tabela users</BaseQuizOption>
  
  <BaseQuizAnswer>
    O curinga `*` seleciona todas as colunas e, sem uma cláusula WHERE, retorna todas as linhas. Isso é útil para visualizar todos os dados, mas deve ser usado com cuidado em tabelas grandes.
  </BaseQuizAnswer>
</BaseQuiz>

### Ordenação e Limitação: `ORDER BY` / `LIMIT`

Controlar a ordem e o número de resultados retornados.

```sql
# Ordenar resultados
SELECT * FROM users ORDER BY age DESC;
# Ordenar por múltiplas colunas
SELECT * FROM users ORDER BY age DESC, username ASC;
# Limitar resultados
SELECT * FROM users LIMIT 10;
# Paginação (pular os primeiros 10, pegar os próximos 10)
SELECT * FROM users LIMIT 10 OFFSET 10;
```

### Filtragem: `WHERE` / `LIKE` / `IN`

Filtrar dados usando vários operadores de comparação.

```sql
# Correspondência de padrão
SELECT * FROM users WHERE username LIKE 'john%';
# Múltiplos valores
SELECT * FROM users WHERE age IN (25, 30, 35);
# Filtragem por intervalo
SELECT * FROM users WHERE age BETWEEN 20 AND 30;
# Verificações de NULL
SELECT * FROM users WHERE email IS NOT NULL;
```

### Agrupamento: `GROUP BY` / `HAVING`

Agrupar dados e aplicar funções de agregação.

```sql
# Agrupar por coluna
SELECT age, COUNT(*) FROM users GROUP BY age;
# Agrupar com condição nos grupos
SELECT age, COUNT(*) as count FROM users
GROUP BY age HAVING count > 1;
# Múltiplas colunas de agrupamento
SELECT age, gender, COUNT(*) FROM users
GROUP BY age, gender;
```

## Consultas Avançadas

### Operações JOIN: `INNER` / `LEFT` / `RIGHT`

Combinar dados de múltiplas tabelas.

```sql
# Inner join (apenas registros correspondentes)
SELECT u.username, o.order_date
FROM users u
INNER JOIN orders o ON u.id = o.user_id;
# Left join (todos os usuários, pedidos correspondentes)
SELECT u.username, o.order_date
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;
# Múltiplos joins
SELECT u.username, o.order_date, p.product_name
FROM users u
JOIN orders o ON u.id = o.user_id
JOIN products p ON o.product_id = p.id;
```

<BaseQuiz id="mysql-join-1" correct="B">
  <template #question>
    Qual é a diferença entre INNER JOIN e LEFT JOIN?
  </template>
  
  <BaseQuizOption value="A">Não há diferença</BaseQuizOption>
  <BaseQuizOption value="B" correct>INNER JOIN retorna apenas linhas correspondentes, LEFT JOIN retorna todas as linhas da tabela da esquerda</BaseQuizOption>
  <BaseQuizOption value="C">INNER JOIN é mais rápido</BaseQuizOption>
  <BaseQuizOption value="D">LEFT JOIN só funciona com duas tabelas</BaseQuizOption>
  
  <BaseQuizAnswer>
    INNER JOIN retorna apenas linhas onde há uma correspondência em ambas as tabelas. LEFT JOIN retorna todas as linhas da tabela da esquerda e as linhas correspondentes da tabela da direita, com valores NULL para linhas não correspondentes da tabela da direita.
  </BaseQuizAnswer>
</BaseQuiz>

### Subconsultas: `SELECT` dentro de `SELECT`

Usar consultas aninhadas para recuperação complexa de dados.

```sql
# Subconsulta na cláusula WHERE
SELECT * FROM users
WHERE id IN (SELECT user_id FROM orders WHERE total > 100);
# Subconsulta correlacionada
SELECT username FROM users u1
WHERE age > (SELECT AVG(age) FROM users u2);
# Subconsulta no SELECT
SELECT username,
(SELECT COUNT(*) FROM orders WHERE user_id = users.id) as order_count
FROM users;
```

### Funções de Agregação: `COUNT` / `SUM` / `AVG`

Calcular estatísticas e resumos a partir dos dados.

```sql
# Agregações básicas
SELECT COUNT(*) FROM users;
SELECT AVG(age), MIN(age), MAX(age) FROM users;
SELECT SUM(total) FROM orders;
# Agregação com agrupamento
SELECT department, AVG(salary)
FROM employees GROUP BY department;
# Múltiplas agregações
SELECT
    COUNT(*) as total_users,
    AVG(age) as avg_age,
    MAX(created_at) as latest_signup
FROM users;
```

### Funções de Janela: `OVER` / `PARTITION BY`

Executar cálculos em conjuntos de linhas da tabela.

```sql
# Funções de classificação
SELECT username, age,
RANK() OVER (ORDER BY age DESC) as age_rank
FROM users;
# Particionar por grupo
SELECT username, department, salary,
AVG(salary) OVER (PARTITION BY department) as dept_avg
FROM employees;
# Totais acumulados
SELECT order_date, total,
SUM(total) OVER (ORDER BY order_date) as running_total
FROM orders;
```

## Índices e Desempenho

### Criar Índices: `CREATE INDEX`

Melhorar o desempenho da consulta com índices de banco de dados.

```sql
# Criar índice regular
CREATE INDEX idx_username ON users(username);
# Criar índice composto
CREATE INDEX idx_user_age ON users(username, age);
# Criar índice único
CREATE UNIQUE INDEX idx_email ON users(email);
# Mostrar índices na tabela
SHOW INDEXES FROM users;
```

### Análise de Consulta: `EXPLAIN`

Analisar planos de execução de consulta e desempenho.

```sql
# Mostrar plano de execução da consulta
EXPLAIN SELECT * FROM users WHERE age > 25;
# Análise detalhada
EXPLAIN FORMAT=JSON SELECT u.*, o.total
FROM users u JOIN orders o ON u.id = o.user_id;
# Mostrar desempenho da consulta
SHOW PROFILES;
SET profiling = 1;
```

### Otimizar Consultas: Melhores Práticas

Técnicas para escrever consultas SQL eficientes.

```sql
# Usar colunas específicas em vez de *
SELECT username, email FROM users WHERE id = 1;
# Usar LIMIT para grandes conjuntos de dados
SELECT * FROM logs ORDER BY created_at DESC LIMIT 1000;
# Usar condições WHERE adequadas
SELECT * FROM orders WHERE user_id = 123 AND status = 'pending';
-- Usar índices de cobertura quando possível
```

### Manutenção de Tabela: `OPTIMIZE` / `ANALYZE`

Manter o desempenho e as estatísticas da tabela.

```sql
# Otimizar armazenamento da tabela
OPTIMIZE TABLE users;
# Atualizar estatísticas da tabela
ANALYZE TABLE users;
# Verificar integridade da tabela
CHECK TABLE users;
# Reparar tabela se necessário
REPAIR TABLE users;
```

## Importação/Exportação de Dados

### Carregar Dados: `LOAD DATA INFILE`

Importar dados de arquivos CSV e de texto.

```sql
# Carregar arquivo CSV
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
# Carregar com colunas específicas
LOAD DATA INFILE '/path/to/data.csv'
INTO TABLE users (username, email, age);
```

### Exportar Dados: `SELECT INTO OUTFILE`

Exportar resultados de consulta para arquivos.

```sql
# Exportar para arquivo CSV
SELECT username, email, age
FROM users
INTO OUTFILE '/path/to/export.csv'
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n';
```

### Backup e Restauração: `mysqldump` / `mysql`

Criar e restaurar backups de banco de dados.

```bash
# Backup de tabelas específicas
mysqldump -u username -p database_name table1 table2 > tables_backup.sql
# Restaurar a partir do backup
mysql -u username -p database_name < backup.sql
# Exportar do servidor remoto
mysqldump -h remote_host -u username -p database_name > remote_backup.sql
# Importar para banco de dados local
mysql -u local_user -p local_database < remote_backup.sql
# Cópia direta de dados entre servidores
mysqldump -h source_host -u user -p db_name | mysql -h dest_host -u user -p db_name
```

## Tipos de Dados e Funções

### Tipos de Dados Comuns: Números, Texto, Datas

Escolha os tipos de dados apropriados para suas colunas.

```sql
# Tipos numéricos
INT, BIGINT, DECIMAL(10,2), FLOAT, DOUBLE
# Tipos de string
VARCHAR(255), TEXT, CHAR(10), MEDIUMTEXT, LONGTEXT
# Tipos de data e hora
DATE, TIME, DATETIME, TIMESTAMP, YEAR
# Booleano e binário
BOOLEAN, BLOB, VARBINARY

# Criação de tabela de exemplo
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Funções de String: `CONCAT` / `SUBSTRING` / `LENGTH`

Manipular dados de texto com funções de string integradas.

```sql
# Concatenação de string
SELECT CONCAT(first_name, ' ', last_name) as full_name FROM users;
# Operações de string
SELECT SUBSTRING(email, 1, LOCATE('@', email)-1) as username FROM users;
SELECT LENGTH(username), UPPER(username) FROM users;
# Correspondência de padrão e substituição
SELECT REPLACE(phone, '-', '.') FROM users WHERE phone LIKE '___-___-____';
```

### Funções de Data: `NOW()` / `DATE_ADD` / `DATEDIFF`

Trabalhar com datas e horas de forma eficaz.

```sql
# Data e hora atuais
SELECT NOW(), CURDATE(), CURTIME();
# Aritmética de data
SELECT DATE_ADD(created_at, INTERVAL 30 DAY) as expiry_date FROM users;
SELECT DATEDIFF(NOW(), created_at) as days_since_signup FROM users;
# Formatação de data
SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') as formatted_date FROM orders;
```

### Funções Numéricas: `ROUND` / `ABS` / `RAND`

Executar operações matemáticas em dados numéricos.

```sql
# Funções matemáticas
SELECT ROUND(price, 2), ABS(profit_loss), SQRT(area) FROM products;
# Aleatório e estatístico
SELECT RAND(), FLOOR(price), CEIL(rating) FROM products;
# Matemática de agregação
SELECT AVG(price), STDDEV(price), VARIANCE(price) FROM products;
```

## Gerenciamento de Transações

### Controle de Transação: `BEGIN` / `COMMIT` / `ROLLBACK`

Gerenciar transações de banco de dados para consistência de dados.

```sql
# Iniciar transação
BEGIN;
# ou
START TRANSACTION;
# Executar operações
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;
# Confirmar alterações
COMMIT;
# Ou reverter em caso de erro
ROLLBACK;
```

### Nível de Isolamento da Transação: `SET TRANSACTION ISOLATION`

Controlar como as transações interagem umas com as outras.

```sql
# Definir nível de isolamento
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
# Mostrar nível de isolamento atual
SELECT @@transaction_isolation;
```

### Bloqueio: `LOCK TABLES` / `SELECT FOR UPDATE`

Controlar o acesso concorrente aos dados.

```sql
# Bloquear tabelas para acesso exclusivo
LOCK TABLES users WRITE, orders READ;
# Executar operações
# ...
UNLOCK TABLES;
# Bloqueio de nível de linha em transações
BEGIN;
SELECT * FROM accounts WHERE id = 1 FOR UPDATE;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
COMMIT;
```

### Savepoints: `SAVEPOINT` / `ROLLBACK TO`

Criar pontos de reversão dentro de transações.

```sql
BEGIN;
INSERT INTO users (username) VALUES ('user1');
SAVEPOINT sp1;
INSERT INTO users (username) VALUES ('user2');
SAVEPOINT sp2;
INSERT INTO users (username) VALUES ('user3');
# Reverter para savepoint
ROLLBACK TO sp1;
COMMIT;
```

## Técnicas SQL Avançadas

### Expressões de Tabela Comuns (CTEs): `WITH`

Criar conjuntos de resultados temporários para consultas complexas.

```sql
# CTE simples
WITH user_orders AS (
    SELECT user_id, COUNT(*) as order_count,
           SUM(total) as total_spent
    FROM orders
    GROUP BY user_id
)
SELECT u.username, uo.order_count, uo.total_spent
FROM users u
JOIN user_orders uo ON u.id = uo.user_id
WHERE uo.total_spent > 1000;
```

### Procedimentos Armazenados: `CREATE PROCEDURE`

Criar procedimentos de banco de dados reutilizáveis.

```sql
# Criar procedimento armazenado
DELIMITER //
CREATE PROCEDURE GetUserOrders(IN user_id INT)
BEGIN
    SELECT o.*, p.product_name
    FROM orders o
    JOIN products p ON o.product_id = p.id
    WHERE o.user_id = user_id;
END //
DELIMITER ;
# Chamar procedimento
CALL GetUserOrders(123);
```

### Triggers: `CREATE TRIGGER`

Executar código automaticamente em resposta a eventos de banco de dados.

```sql
# Criar trigger para log de auditoria
CREATE TRIGGER user_update_audit
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    INSERT INTO user_audit (user_id, old_email, new_email, changed_at)
    VALUES (NEW.id, OLD.email, NEW.email, NOW());
END;
# Mostrar triggers
SHOW TRIGGERS;
```

### Views: `CREATE VIEW`

Criar tabelas virtuais baseadas em resultados de consulta.

```sql
# Criar view
CREATE VIEW active_users AS
SELECT id, username, email, created_at
FROM users
WHERE status = 'active' AND last_login > DATE_SUB(NOW(), INTERVAL 30 DAY);
# Usar view como uma tabela
SELECT * FROM active_users WHERE username LIKE 'john%';
# Excluir view
DROP VIEW active_users;
```

## Instalação e Configuração do MySQL

### Instalação: Gerenciadores de Pacotes

Instalar MySQL usando gerenciadores de pacotes do sistema.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# CentOS/RHEL
sudo yum install mysql-server
# macOS com Homebrew
brew install mysql
# Iniciar serviço MySQL
sudo systemctl start mysql
```

### Docker: `docker run mysql`

Executar MySQL em contêineres Docker para desenvolvimento.

```bash
# Executar contêiner MySQL
docker run --name mysql-dev -e MYSQL_ROOT_PASSWORD=password -p 3306:3306 -d mysql:8.0
# Conectar ao MySQL conteinerizado
docker exec -it mysql-dev mysql -u root -p
# Criar banco de dados no contêiner
docker exec -it mysql-dev mysql -u root -p -e "CREATE DATABASE testdb;"
```

### Configuração Inicial e Segurança

Proteger sua instalação MySQL e verificar a configuração.

```bash
# Executar script de segurança
sudo mysql_secure_installation
# Conectar ao MySQL
mysql -u root -p
# Mostrar versão do MySQL
SELECT VERSION();
# Verificar status da conexão
STATUS;
# Definir senha do root
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
```

## Configuração e Ajustes

### Arquivos de Configuração: `my.cnf`

Modificar as configurações de configuração do servidor MySQL.

```ini
# Locais comuns de configuração
# Linux: /etc/mysql/my.cnf
# Windows: C:\ProgramData\MySQL\MySQL Server\my.ini
# macOS: /usr/local/etc/my.cnf

[mysqld]
max_connections = 200
innodb_buffer_pool_size = 1G
query_cache_size = 64M
slow_query_log = 1
long_query_time = 2
```

### Configuração em Tempo de Execução: `SET GLOBAL`

Alterar configurações enquanto o MySQL está em execução.

```sql
# Definir variáveis globais
SET GLOBAL max_connections = 500;
SET GLOBAL slow_query_log = ON;
# Mostrar configurações atuais
SHOW VARIABLES LIKE 'max_connections';
SHOW GLOBAL STATUS LIKE 'Slow_queries';
```

### Ajuste de Desempenho: Memória e Cache

Otimizar as configurações de desempenho do MySQL.

```sql
# Mostrar uso de memória
SHOW VARIABLES LIKE '%buffer_pool_size%';
SHOW VARIABLES LIKE '%query_cache%';
# Monitorar desempenho
SHOW STATUS LIKE 'Qcache%';
SHOW STATUS LIKE 'Created_tmp%';
# Configurações do InnoDB
SET GLOBAL innodb_buffer_pool_size = 2147483648; -- 2GB
```

### Configuração de Logs: Logs de Erro e Consulta

Configurar o registro do MySQL para monitoramento e depuração.

```sql
# Habilitar registro de consulta
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/query.log';
# Log de consulta lenta
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
# Mostrar configurações de log
SHOW VARIABLES LIKE '%log%';
```

## Links Relevantes

- <router-link to="/database">Folha de Dicas de Banco de Dados</router-link>
- <router-link to="/postgresql">Folha de Dicas PostgreSQL</router-link>
- <router-link to="/sqlite">Folha de Dicas SQLite</router-link>
- <router-link to="/mongodb">Folha de Dicas MongoDB</router-link>
- <router-link to="/redis">Folha de Dicas Redis</router-link>
- <router-link to="/python">Folha de Dicas Python</router-link>
- <router-link to="/javascript">Folha de Dicas JavaScript</router-link>
- <router-link to="/devops">Folha de Dicas DevOps</router-link>

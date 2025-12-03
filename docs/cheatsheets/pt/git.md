---
title: 'Folha de Cola Git | LabEx'
description: 'Aprenda controle de versão Git com esta folha de cola abrangente. Referência rápida para comandos Git, ramificação, mesclagem, rebase, fluxos de trabalho do GitHub e desenvolvimento colaborativo.'
pdfUrl: '/cheatsheets/pdf/git-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Git Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/git">Aprenda Git com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda controle de versão Git através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Git cobrindo comandos essenciais, estratégias de ramificação, fluxos de trabalho de colaboração e técnicas avançadas. Aprenda a gerenciar repositórios de código, resolver conflitos e trabalhar efetivamente com equipes usando Git e GitHub.
</base-disclaimer-content>
</base-disclaimer>

## Configuração e Inicialização de Repositório

### Inicializar Repositório: `git init`

Cria um novo repositório Git no diretório atual.

```bash
# Inicializar novo repositório
git init
# Inicializar em novo diretório
git init project-name
# Inicializar repositório bare (sem diretório de trabalho)
git init --bare
# Usar diretório de template personalizado
git init --template=path
```

### Clonar Repositório: `git clone`

Cria uma cópia local de um repositório remoto.

```bash
# Clonar via HTTPS
git clone https://github.com/user/repo.git
# Clonar via SSH
git clone git@github.com:user/repo.git
# Clonar com nome personalizado
git clone repo.git local-name
# Clonagem superficial (apenas o commit mais recente)
git clone --depth 1 repo.git
```

### Configuração Global: `git config`

Configura informações do usuário e preferências globalmente.

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# Visualizar todas as configurações
git config --list
```

### Configuração Local: `git config --local`

Define a configuração específica do repositório.

```bash
# Definir apenas para o repositório atual
git config user.name "Project Name"
# E-mail específico do projeto
git config user.email "project@example.com"
```

### Gerenciamento de Remotos: `git remote`

Gerencia conexões com repositórios remotos.

```bash
# Adicionar remoto
git remote add origin https://github.com/user/repo.git
# Listar todos os remotos com URLs
git remote -v
# Mostrar informações detalhadas do remoto
git remote show origin
# Renomear remoto
git remote rename origin upstream
# Remover remoto
git remote remove upstream
```

### Armazenamento de Credenciais: `git config credential`

Armazena credenciais de autenticação para evitar login repetido.

```bash
# Cache por 15 minutos
git config --global credential.helper cache
# Armazenar permanentemente
git config --global credential.helper store
# Cache por 1 hora
git config --global credential.helper 'cache --timeout=3600'
```

## Informações e Status do Repositório

### Verificar Status: `git status`

Exibe o estado atual do diretório de trabalho e da área de _staging_.

```bash
# Informações de status completas
git status
# Formato de status curto
git status -s
# Formato legível por máquina
git status --porcelain
# Mostrar também arquivos ignorados
git status --ignored
```

### Visualizar Diferenças: `git diff`

Mostra as alterações entre diferentes estados do seu repositório.

```bash
# Alterações no diretório de trabalho vs staging
git diff
# Alterações no staging vs último commit
git diff --staged
# Todas as alterações não confirmadas
git diff HEAD
# Alterações em um arquivo específico
git diff file.txt
```

### Visualizar Histórico: `git log`

Exibe o histórico de commits e a linha do tempo do repositório.

```bash
# Histórico de commits completo
git log
# Formato condensado de uma linha
git log --oneline
# Mostrar os últimos 5 commits
git log -5
# Gráfico visual de branches
git log --graph --all
```

## Staging e Confirmação de Alterações

### Preparar Arquivos: `git add`

Adiciona alterações à área de _staging_ para o próximo commit.

```bash
# Preparar arquivo específico
git add file.txt
# Preparar todas as alterações no diretório atual
git add .
# Preparar todas as alterações (incluindo exclusões)
git add -A
# Preparar todos os arquivos JavaScript
git add *.js
# Preparação interativa (modo patch)
git add -p
```

### Confirmar Alterações: `git commit`

Salva as alterações preparadas no repositório com uma mensagem descritiva.

```bash
# Commit com mensagem
git commit -m "Add user authentication"
# Preparar e confirmar arquivos modificados
git commit -a -m "Update docs"
# Modificar o último commit
git commit --amend
# Modificar sem alterar a mensagem
git commit --no-edit --amend
```

<BaseQuiz id="git-commit-1" correct="A">
  <template #question>
    O que `git commit -m "message"` faz?
  </template>
  
  <BaseQuizOption value="A" correct>Cria um novo commit com a mensagem especificada</BaseQuizOption>
  <BaseQuizOption value="B">Prepara todas as alterações no diretório de trabalho</BaseQuizOption>
  <BaseQuizOption value="C">Envia as alterações para o repositório remoto</BaseQuizOption>
  <BaseQuizOption value="D">Cria uma nova branch</BaseQuizOption>
  
  <BaseQuizAnswer>
    O comando `git commit -m` cria um novo commit com as alterações preparadas e as salva no histórico do repositório com a mensagem fornecida. Ele não envia para o remoto nem cria branches.
  </BaseQuizAnswer>
</BaseQuiz>

### Despreparar Arquivos: `git reset`

Remove arquivos da área de _staging_ ou desfaz commits.

```bash
# Despreparar arquivo específico
git reset file.txt
# Despreparar todos os arquivos
git reset
# Desfazer último commit, mantendo alterações preparadas
git reset --soft HEAD~1
# Desfazer último commit, descartando alterações
git reset --hard HEAD~1
```

### Descartar Alterações: `git checkout` / `git restore`

Reverte alterações no diretório de trabalho para o estado do último commit.

```bash
# Descartar alterações no arquivo (sintaxe antiga)
git checkout -- file.txt
# Descartar alterações no arquivo (nova sintaxe)
git restore file.txt
# Despreparar arquivo (nova sintaxe)
git restore --staged file.txt
# Descartar todas as alterações não confirmadas
git checkout .
```

## Operações de Branch

### Listar Branches: `git branch`

Visualiza e gerencia branches do repositório.

```bash
# Listar branches locais
git branch
# Listar todos os branches (locais e remotos)
git branch -a
# Listar apenas branches remotos
git branch -r
# Mostrar último commit em cada branch
git branch -v
```

### Criar e Mudar: `git checkout` / `git switch`

Cria novas branches e alterna entre elas.

```bash
# Criar e mudar para nova branch
git checkout -b feature-branch
# Criar e mudar (nova sintaxe)
git switch -c feature-branch
# Mudar para branch existente
git checkout main
# Mudar para branch existente (nova sintaxe)
git switch main
```

<BaseQuiz id="git-branch-1" correct="B">
  <template #question>
    O que `git checkout -b feature-branch` faz?
  </template>
  
  <BaseQuizOption value="A">Deleta a branch feature-branch</BaseQuizOption>
  <BaseQuizOption value="B" correct>Cria uma nova branch chamada feature-branch e muda para ela</BaseQuizOption>
  <BaseQuizOption value="C">Mescla feature-branch na branch atual</BaseQuizOption>
  <BaseQuizOption value="D">Mostra o histórico de commits da feature-branch</BaseQuizOption>
  
  <BaseQuizAnswer>
    A flag `-b` cria uma nova branch, e `checkout` muda para ela. Este comando combina ambas as operações: criar a branch e imediatamente mudar para ela.
  </BaseQuizAnswer>
</BaseQuiz>

### Mesclar Branches: `git merge`

Combina alterações de diferentes branches.

```bash
# Mesclar feature-branch na branch atual
git merge feature-branch
# Mesclagem forçada
git merge --no-ff feature-branch
# Agrupar commits antes de mesclar
git merge --squash feature-branch
```

### Deletar Branches: `git branch -d`

Remove branches que não são mais necessárias.

```bash
# Deletar branch mesclada
git branch -d feature-branch
# Deletar branch não mesclada forçadamente
git branch -D feature-branch
# Deletar branch remota
git push origin --delete feature-branch
```

## Operações de Repositório Remoto

### Buscar Atualizações: `git fetch`

Baixa alterações do repositório remoto sem mesclar.

```bash
# Buscar do remoto padrão
git fetch
# Buscar de um remoto específico
git fetch origin
# Buscar de todos os remotos
git fetch --all
# Buscar branch específica
git fetch origin main
```

### Puxar Alterações: `git pull`

Baixa e mescla alterações do repositório remoto.

```bash
# Puxar da branch de rastreamento
git pull
# Puxar de branch remota específica
git pull origin main
# Puxar com rebase em vez de merge
git pull --rebase
# Apenas fast-forward, sem commits de merge
git pull --ff-only
```

<BaseQuiz id="git-pull-1" correct="C">
  <template #question>
    Qual é a diferença entre `git fetch` e `git pull`?
  </template>
  
  <BaseQuizOption value="A">Não há diferença; eles fazem a mesma coisa</BaseQuizOption>
  <BaseQuizOption value="B">git fetch envia alterações, git pull baixa alterações</BaseQuizOption>
  <BaseQuizOption value="C" correct>git fetch baixa alterações sem mesclar, git pull baixa e mescla alterações</BaseQuizOption>
  <BaseQuizOption value="D">git fetch funciona com repositórios locais, git pull funciona com repositórios remotos</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git fetch` baixa alterações do repositório remoto, mas não as mescla na sua branch atual. `git pull` executa ambas as operações: ele busca as alterações e depois as mescla na sua branch atual.
  </BaseQuizAnswer>
</BaseQuiz>

### Enviar Alterações: `git push`

Carrega commits locais para o repositório remoto.

```bash
# Enviar para a branch de rastreamento
git push
# Enviar para branch remota específica
git push origin main
# Enviar e configurar rastreamento upstream
git push -u origin feature
# Envio forçado seguro
git push --force-with-lease
```

<BaseQuiz id="git-push-1" correct="D">
  <template #question>
    O que `git push -u origin feature` faz?
  </template>
  
  <BaseQuizOption value="A">Deleta a branch feature do remoto</BaseQuizOption>
  <BaseQuizOption value="B">Puxa alterações da branch feature</BaseQuizOption>
  <BaseQuizOption value="C">Mescla a branch feature em main</BaseQuizOption>
  <BaseQuizOption value="D" correct>Envia a branch feature para origin e configura o rastreamento</BaseQuizOption>
  
  <BaseQuizAnswer>
    A flag `-u` (ou `--set-upstream`) envia a branch para o repositório remoto e configura o rastreamento, para que comandos futuros de `git push` e `git pull` saibam qual branch remota usar.
  </BaseQuizAnswer>
</BaseQuiz>

### Rastrear Branches Remotas: `git branch --track`

Configura o rastreamento entre branches locais e remotas.

```bash
# Configurar rastreamento
git branch --set-upstream-to=origin/main main
# Rastrear branch remota
git checkout -b local-branch origin/remote-branch
```

## Stashing e Armazenamento Temporário

### Stash Alterações: `git stash`

Salva temporariamente alterações não confirmadas para uso posterior.

```bash
# Stash alterações atuais
git stash
# Stash com mensagem
git stash save "Work in progress on feature X"
# Incluir arquivos não rastreados
git stash -u
# Stash apenas alterações não preparadas
git stash --keep-index
```

### Listar Stashes: `git stash list`

Visualiza todos os stashes salvos.

```bash
# Mostrar todos os stashes
git stash list
# Mostrar alterações no stash mais recente
git stash show
# Mostrar alterações em um stash específico
git stash show stash@{1}
```

### Aplicar Stashes: `git stash apply`

Restaura alterações previamente salvas.

```bash
# Aplicar stash mais recente
git stash apply
# Aplicar stash específico
git stash apply stash@{1}
# Aplicar e remover o stash mais recente
git stash pop
# Deletar stash mais recente
git stash drop
# Criar branch a partir do stash
git stash branch new-branch stash@{1}
# Deletar todos os stashes
git stash clear
```

<BaseQuiz id="git-stash-1" correct="B">
  <template #question>
    Qual é a diferença entre `git stash apply` e `git stash pop`?
  </template>
  
  <BaseQuizOption value="A">git stash apply remove o stash, git stash pop o mantém</BaseQuizOption>
  <BaseQuizOption value="B" correct>git stash apply mantém o stash, git stash pop o remove após a aplicação</BaseQuizOption>
  <BaseQuizOption value="C">git stash apply funciona com repositórios remotos, git stash pop funciona localmente</BaseQuizOption>
  <BaseQuizOption value="D">Não há diferença; eles fazem a mesma coisa</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git stash apply` restaura as alterações salvas, mas mantém o stash na lista de stashes. `git stash pop` aplica o stash e depois o remove da lista de stashes, o que é útil quando você não precisa mais do stash.
  </BaseQuizAnswer>
</BaseQuiz>

## Análise de Histórico e Log

### Visualizar Histórico de Commits: `git log`

Explore o histórico do repositório com várias opções de formatação.

```bash
# Histórico visual de branches
git log --oneline --graph --all
# Commits de um autor específico
git log --author="John Doe"
# Commits recentes
git log --since="2 weeks ago"
# Buscar mensagens de commit
git log --grep="bug fix"
```

### Culpar e Anotar: `git blame`

Vê quem modificou cada linha de um arquivo pela última vez.

```bash
# Mostrar autoria linha por linha
git blame file.txt
# Blame em linhas específicas
git blame -L 10,20 file.txt
# Alternativa para blame
git annotate file.txt
```

### Pesquisar Repositório: `git grep`

Pesquisa padrões de texto em todo o histórico do repositório.

```bash
# Pesquisar texto em arquivos rastreados
git grep "function"
# Pesquisar com números de linha
git grep -n "TODO"
# Pesquisar em arquivos preparados
git grep --cached "bug"
```

### Mostrar Detalhes do Commit: `git show`

Exibe informações detalhadas sobre commits específicos.

```bash
# Mostrar detalhes do último commit
git show
# Mostrar commit anterior
git show HEAD~1
# Mostrar commit específico pelo hash
git show abc123
# Mostrar commit com estatísticas de arquivo
git show --stat
```

## Desfazendo Alterações e Editando Histórico

### Reverter Commits: `git revert`

Cria novos commits que desfazem alterações anteriores de forma segura.

```bash
# Reverter o último commit
git revert HEAD
# Reverter commit específico
git revert abc123
# Reverter intervalo de commits
git revert HEAD~3..HEAD
# Reverter sem commit automático
git revert --no-commit abc123
```

### Resetar Histórico: `git reset`

Move o ponteiro da branch e opcionalmente modifica o diretório de trabalho.

```bash
# Desfazer commit, manter alterações preparadas
git reset --soft HEAD~1
# Desfazer commit e staging
git reset --mixed HEAD~1
# Desfazer commit, staging e diretório de trabalho
git reset --hard HEAD~1
```

### Rebase Interativo: `git rebase -i`

Edita, reordena ou agrupa commits interativamente.

```bash
# Rebase interativo dos últimos 3 commits
git rebase -i HEAD~3
# Rebase da branch atual sobre main
git rebase -i main
# Continuar após resolver conflitos
git rebase --continue
# Cancelar operação de rebase
git rebase --abort
```

### Cherry-pick: `git cherry-pick`

Aplica commits específicos de outras branches.

```bash
# Aplicar commit específico na branch atual
git cherry-pick abc123
# Aplicar intervalo de commits
git cherry-pick abc123..def456
# Cherry-pick sem confirmar
git cherry-pick -n abc123
```

## Resolução de Conflitos

### Conflitos de Merge: Processo de Resolução

Passos para resolver conflitos durante operações de merge.

```bash
# Verificar arquivos em conflito
git status
# Marcar conflito como resolvido
git add resolved-file.txt
# Completar o merge
git commit
# Cancelar merge e retornar ao estado anterior
git merge --abort
```

### Ferramentas de Merge: `git mergetool`

Inicia ferramentas externas para ajudar a resolver conflitos visualmente.

```bash
# Iniciar ferramenta de merge padrão
git mergetool
# Definir ferramenta de merge padrão
git config --global merge.tool vimdiff
# Usar ferramenta específica para este merge
git mergetool --tool=meld
```

### Marcadores de Conflito: Entendendo o Formato

Interpreta os marcadores de conflito do Git nos arquivos.

```text
<<<<<<< HEAD
Conteúdo da branch atual
=======
Conteúdo da branch de entrada
>>>>>>> feature-branch
```

Após editar o arquivo para resolver:

```bash
git add conflicted-file.txt
git commit
```

### Ferramentas de Diff: `git difftool`

Usa ferramentas externas de diff para melhor visualização de conflitos.

```bash
# Iniciar ferramenta de diff para alterações
git difftool
# Definir ferramenta de diff padrão
git config --global diff.tool vimdiff
```

## Marcação e Lançamentos (Tagging)

### Criar Tags: `git tag`

Marca commits específicos com rótulos de versão.

```bash
# Criar tag leve (lightweight)
git tag v1.0
# Criar tag anotada
git tag -a v1.0 -m "Version 1.0 release"
# Marcar commit específico
git tag -a v1.0 abc123
# Criar tag assinada
git tag -s v1.0
```

### Listar e Mostrar Tags: `git tag -l`

Visualiza tags existentes e suas informações.

```bash
# Listar todas as tags
git tag
# Listar tags que correspondem ao padrão
git tag -l "v1.*"
# Mostrar detalhes da tag
git show v1.0
```

### Enviar Tags: `git push --tags`

Compartilha tags com repositórios remotos.

```bash
# Enviar tag específica
git push origin v1.0
# Enviar todas as tags
git push --tags
# Enviar todas as tags para um remoto específico
git push origin --tags
```

### Deletar Tags: `git tag -d`

Remove tags de repositórios locais e remotos.

```bash
# Deletar tag local
git tag -d v1.0
# Deletar tag remota
git push origin --delete tag v1.0
# Sintaxe alternativa para deletar
git push origin :refs/tags/v1.0
```

## Configuração e Aliases do Git

### Visualizar Configuração: `git config --list`

Exibe as configurações atuais do Git.

```bash
# Mostrar todas as configurações
git config --list
# Mostrar apenas configurações globais
git config --global --list
# Mostrar configurações específicas do repositório
git config --local --list
# Mostrar uma configuração específica
git config user.name
```

### Criar Aliases: `git config alias`

Cria atalhos para comandos frequentemente usados.

```bash
# git st = git status
git config --global alias.st status
# git co = git checkout
git config --global alias.co checkout
# git br = git branch
git config --global alias.br branch
# git ci = git commit
git config --global alias.ci commit
```

### Aliases Avançados: Comandos Complexos

Cria aliases para combinações complexas de comandos.

```bash
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.unstage "reset HEAD --"
git config --global alias.last "log -1 HEAD"
git config --global alias.visual "!gitk"
```

### Configuração do Editor: `git config core.editor`

Define o editor de texto preferido para mensagens de commit e conflitos.

```bash
# VS Code
git config --global core.editor "code --wait"
# Vim
git config --global core.editor "vim"
# Nano
git config --global core.editor "nano"
```

## Desempenho e Otimização

### Manutenção do Repositório: `git gc`

Otimiza o desempenho e o armazenamento do repositório.

```bash
# Coleta de lixo padrão
git gc
# Otimização mais completa
git gc --aggressive
# Executar apenas se necessário
git gc --auto
# Verificar integridade do repositório
git fsck
```

### Manipulação de Arquivos Grandes: `git lfs`

Gerencia eficientemente arquivos binários grandes com Git LFS.

```bash
# Instalar LFS no repositório
git lfs install
# Rastrear arquivos PDF com LFS
git lfs track "*.pdf"
# Listar arquivos rastreados por LFS
git lfs ls-files
# Migrar arquivos existentes
git lfs migrate import --include="*.zip"
```

### Clonagens Rasas (Shallow Clones): Reduzindo o Tamanho do Repositório

Clona repositórios com histórico limitado para operações mais rápidas.

```bash
# Apenas o commit mais recente
git clone --depth 1 https://github.com/user/repo.git
# Últimos 10 commits
git clone --depth 10 repo.git
# Converter clone raso em completo
git fetch --unshallow
```

### Sparse Checkout: Trabalhando com Subdiretórios

Faz checkout apenas de partes específicas de repositórios grandes.

```bash
git config core.sparseCheckout true
echo "src/*" > .git/info/sparse-checkout
# Aplicar sparse checkout
git read-tree -m -u HEAD
```

## Instalação e Configuração do Git

### Gerenciadores de Pacotes: `apt`, `yum`, `brew`

Instala o Git usando gerenciadores de pacotes do sistema.

```bash
# Ubuntu/Debian
sudo apt install git
# CentOS/RHEL
sudo yum install git
# macOS com Homebrew
brew install git
# Windows com winget
winget install Git.Git
```

### Download e Instalação: Instaladores Oficiais

Use instaladores oficiais do Git para sua plataforma.

```bash
# Baixar de https://git-scm.com/downloads
# Verificar instalação
git --version
# Mostrar caminho do executável do Git
which git
```

### Configuração Inicial: Identidade do Usuário

Configura sua identidade para commits.

```bash
git config --global user.name "Your Full Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# Definir comportamento de merge
git config --global pull.rebase false
```

## Fluxos de Trabalho e Melhores Práticas do Git

### Fluxo de Branch de Recurso (Feature Branch Workflow)

Fluxo de trabalho padrão para desenvolvimento de recursos com branches isoladas.

```bash
# Começar da branch main
git checkout main
# Obter últimas alterações
git pull origin main
# Criar branch de recurso
git checkout -b feature/user-auth
# ... fazer alterações e commits ...
# Enviar branch de recurso
git push -u origin feature/user-auth
# ... criar pull request ...
```

### Git Flow: Modelo Estruturado de Branching

Abordagem sistemática com branches dedicadas para diferentes propósitos.

```bash
# Inicializar Git Flow
git flow init
# Iniciar recurso
git flow feature start new-feature
# Finalizar recurso
git flow feature finish new-feature
# Iniciar branch de lançamento
git flow release start 1.0.0
```

### Convenções de Mensagens de Commit

Seguir o formato de commit convencional para um histórico de projeto claro.

```bash
# Formato: <tipo>(<escopo>): <assunto>
git commit -m "feat(auth): add user login functionality"
git commit -m "fix(api): resolve null pointer exception"
git commit -m "docs(readme): update installation instructions"
git commit -m "refactor(utils): simplify date formatting"
```

### Commits Atômicos: Melhores Práticas

Criar commits focados, de propósito único, para um histórico melhor.

```bash
# Preparar alterações interativamente
git add -p
# Alteração específica
git commit -m "Add validation to email field"
# Evitar: git commit -m "Fix stuff" # Muito vago
# Bom:  git commit -m "Fix email validation regex pattern"
```

## Solução de Problemas e Recuperação

### Reflog: Ferramenta de Recuperação

Usar o log de referências do Git para recuperar commits perdidos.

```bash
# Mostrar log de referências
git reflog
# Mostrar movimentos do HEAD
git reflog show HEAD
# Recuperar commit perdido
git checkout abc123
# Criar branch a partir de commit perdido
git branch recovery-branch abc123
```

### Repositório Corrompido: Reparo

Corrigir problemas de integridade e corrupção do repositório.

```bash
# Verificar integridade do repositório
git fsck --full
# Limpeza agressiva
git gc --aggressive --prune=now
# Reconstruir índice se corrompido
rm .git/index; git reset
```

### Problemas de Autenticação

Resolver problemas comuns de autenticação e permissão.

```bash
# Usar token
git remote set-url origin https://token@github.com/user/repo.git
# Adicionar chave SSH ao agente
ssh-add ~/.ssh/id_rsa
# Gerenciador de credenciais do Windows
git config --global credential.helper manager-core
```

### Problemas de Desempenho: Depuração

Identificar e resolver problemas de desempenho do repositório.

```bash
# Mostrar tamanho do repositório
git count-objects -vH
# Contar total de commits
git log --oneline | wc -l
# Contar branches
git for-each-ref --format='%(refname:short)' | wc -l
```

## Links Relevantes

- <router-link to="/linux">Cheatsheet de Linux</router-link>
- <router-link to="/shell">Cheatsheet de Shell</router-link>
- <router-link to="/devops">Cheatsheet de DevOps</router-link>
- <router-link to="/docker">Cheatsheet de Docker</router-link>
- <router-link to="/kubernetes">Cheatsheet de Kubernetes</router-link>
- <router-link to="/ansible">Cheatsheet de Ansible</router-link>
- <router-link to="/python">Cheatsheet de Python</router-link>
- <router-link to="/javascript">Cheatsheet de JavaScript</router-link>

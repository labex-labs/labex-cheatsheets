---
title: 'Folha de Cola Git'
description: 'Aprenda Git com nossa folha de cola abrangente cobrindo comandos essenciais, conceitos e melhores práticas.'
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

Define informações do usuário e preferências globalmente.

```bash
git config --global user.name "Seu Nome"
git config --global user.email "seu.email@example.com"
git config --global init.defaultBranch main
# Visualizar todas as configurações
git config --list
```

### Configuração Local: `git config --local`

Define configurações específicas do repositório.

```bash
# Definir apenas para o repositório atual
git config user.name "Nome do Projeto"
# E-mail específico do projeto
git config user.email "projeto@example.com"
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
# Alterações na área de staging vs último commit
git diff --staged
# Todas as alterações não commitadas
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

## Staging e Commit de Alterações

### Adicionar Arquivos (Stage): `git add`

Adiciona alterações à área de _staging_ para o próximo commit.

```bash
# Adicionar arquivo específico
git add file.txt
# Adicionar todas as alterações no diretório atual
git add .
# Adicionar todas as alterações (incluindo exclusões)
git add -A
# Adicionar todos os arquivos JavaScript
git add *.js
# Staging interativo (modo patch)
git add -p
```

### Commitar Alterações: `git commit`

Salva as alterações em _staging_ no repositório com uma mensagem descritiva.

```bash
# Commit com mensagem
git commit -m "Adiciona autenticação de usuário"
# Adicionar (stage) e commitar arquivos modificados
git commit -a -m "Atualiza documentação"
# Modificar o último commit
git commit --amend
# Modificar sem alterar a mensagem
git commit --no-edit --amend
```

### Desfazer Staging: `git reset`

Remove arquivos da área de _staging_ ou desfaz commits.

```bash
# Desfazer staging de arquivo específico
git reset file.txt
# Desfazer staging de todos os arquivos
git reset
# Desfazer último commit, mantendo alterações em staging
git reset --soft HEAD~1
# Desfazer último commit, descartando alterações
git reset --hard HEAD~1
```

### Descartar Alterações: `git checkout` / `git restore`

Reverte alterações no diretório de trabalho para o estado do último commit.

```bash
# Descartar alterações em arquivo (sintaxe antiga)
git checkout -- file.txt
# Descartar alterações em arquivo (nova sintaxe)
git restore file.txt
# Desfazer staging de arquivo (nova sintaxe)
git restore --staged file.txt
# Descartar todas as alterações não commitadas
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

Cria novos branches e alterna entre eles.

```bash
# Criar e mudar para novo branch
git checkout -b feature-branch
# Criar e mudar (nova sintaxe)
git switch -c feature-branch
# Mudar para branch existente
git checkout main
# Mudar para branch existente (nova sintaxe)
git switch main
```

### Mesclar Branches: `git merge`

Combina alterações de diferentes branches.

```bash
# Mesclar feature-branch no branch atual
git merge feature-branch
# Forçar commit de merge
git merge --no-ff feature-branch
# Agrupar commits antes de mesclar
git merge --squash feature-branch
```

### Excluir Branches: `git branch -d`

Remove branches que não são mais necessárias.

```bash
# Excluir branch mesclado
git branch -d feature-branch
# Excluir branch não mesclado à força
git branch -D feature-branch
# Excluir branch remoto
git push origin --delete feature-branch
```

## Operações de Repositório Remoto

### Buscar Atualizações: `git fetch`

Baixa alterações do repositório remoto sem mesclá-las.

```bash
# Buscar do remoto padrão
git fetch
# Buscar de um remoto específico
git fetch origin
# Buscar de todos os remotos
git fetch --all
# Buscar branch específico
git fetch origin main
```

### Puxar Alterações: `git pull`

Baixa e mescla alterações do repositório remoto.

```bash
# Puxar do branch de rastreamento
git pull
# Puxar de um branch remoto específico
git pull origin main
# Puxar com rebase em vez de merge
git pull --rebase
# Apenas fast-forward, sem commits de merge
git pull --ff-only
```

### Enviar Alterações: `git push`

Envia commits locais para o repositório remoto.

```bash
# Enviar para o branch de rastreamento
git push
# Enviar para um branch remoto específico
git push origin main
# Enviar e configurar rastreamento upstream
git push -u origin feature
# Enviar à força com segurança
git push --force-with-lease
```

### Rastrear Branches Remotos: `git branch --track`

Configura o rastreamento entre branches locais e remotos.

```bash
# Configurar rastreamento
git branch --set-upstream-to=origin/main main
# Rastrear branch remoto
git checkout -b local-branch origin/remote-branch
```

## Stashing e Armazenamento Temporário

### Stash de Alterações: `git stash`

Salva temporariamente alterações não commitadas para uso posterior.

```bash
# Stash de alterações atuais
git stash
# Stash com mensagem
git stash save "Trabalho em andamento no recurso X"
# Incluir arquivos não rastreados
git stash -u
# Stash apenas alterações não staged
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

Restaura alterações previamente armazenadas em stash.

```bash
# Aplicar o stash mais recente
git stash apply
# Aplicar stash específico
git stash apply stash@{1}
# Aplicar e remover o stash mais recente
git stash pop
# Excluir stash mais recente
git stash drop
# Criar branch a partir do stash
git stash branch new-branch stash@{1}
# Excluir todos os stashes
git stash clear
```

## Análise de Histórico e Log

### Visualizar Histórico de Commits: `git log`

Explora o histórico do repositório com várias opções de formatação.

```bash
# Histórico visual de branches
git log --oneline --graph --all
# Commits por um autor específico
git log --author="João Silva"
# Commits recentes
git log --since="2 weeks ago"
# Pesquisar mensagens de commit
git log --grep="correção de bug"
```

### Rastreamento e Anotação: `git blame`

Vê quem modificou cada linha de um arquivo por último.

```bash
# Mostrar autoria linha por linha
git blame file.txt
# Blame em linhas específicas
git blame -L 10,20 file.txt
# Alternativa ao blame
git annotate file.txt
```

### Pesquisar Repositório: `git grep`

Pesquisa padrões de texto em todo o histórico do repositório.

```bash
# Pesquisar por texto em arquivos rastreados
git grep "function"
# Pesquisar com números de linha
git grep -n "TODO"
# Pesquisar em arquivos em staging
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

Cria novos commits que desfazem alterações anteriores com segurança.

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

Move o ponteiro do branch e opcionalmente modifica o diretório de trabalho.

```bash
# Desfazer commit, mantendo alterações em staging
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
# Rebase do branch atual sobre main
git rebase -i main
# Continuar após resolver conflitos
git rebase --continue
# Cancelar operação de rebase
git rebase --abort
```

### Cherry-pick: `git cherry-pick`

Aplica commits específicos de outros branches.

```bash
# Aplicar commit específico no branch atual
git cherry-pick abc123
# Aplicar intervalo de commits
git cherry-pick abc123..def456
# Cherry-pick sem commitar
git cherry-pick -n abc123
```

## Resolução de Conflitos

### Conflitos de Merge: Processo de Resolução

Passos para resolver conflitos durante operações de merge.

```bash
# Verificar arquivos em conflito
git status
# Marcar arquivo como resolvido
git add resolved-file.txt
# Concluir o merge
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
Conteúdo do branch atual
=======
Conteúdo do branch de entrada
>>>>>>> feature-branch
```

Após editar o arquivo para resolver:

```bash
git add conflicted-file.txt
git commit
```

### Ferramentas de Diff: `git difftool`

Usa ferramentas de diff externas para melhor visualização de conflitos.

```bash
# Iniciar ferramenta de diff para alterações
git difftool
# Definir ferramenta de diff padrão
git config --global diff.tool vimdiff
```

## Marcação (Tagging) e Lançamentos

### Criar Tags: `git tag`

Marca commits específicos com rótulos de versão.

```bash
# Criar tag leve (lightweight)
git tag v1.0
# Criar tag anotada
git tag -a v1.0 -m "Lançamento da Versão 1.0"
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

### Excluir Tags: `git tag -d`

Remove tags dos repositórios local e remoto.

```bash
# Excluir tag local
git tag -d v1.0
# Excluir tag remota
git push origin --delete tag v1.0
# Sintaxe alternativa de exclusão
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

Define atalhos para comandos frequentemente usados.

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

Gerencia arquivos binários grandes de forma eficiente com Git LFS.

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
# Converter shallow para clone completo
git fetch --unshallow
```

### Sparse Checkout: Trabalhando com Subdiretórios

Verifica apenas partes específicas de repositórios grandes.

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

Configura o Git com sua identidade para commits.

```bash
git config --global user.name "Seu Nome Completo"
git config --global user.email "seu.email@example.com"
git config --global init.defaultBranch main
# Definir comportamento de merge
git config --global pull.rebase false
```

## Fluxos de Trabalho e Melhores Práticas do Git

### Fluxo de Trabalho de Branch de Recurso (Feature Branch)

Fluxo de trabalho padrão para desenvolvimento de recursos com branches isolados.

```bash
# Começar do branch principal
git checkout main
# Obter alterações mais recentes
git pull origin main
# Criar branch de recurso
git checkout -b feature/user-auth
# ... fazer alterações e commits ...
# Enviar branch de recurso
git push -u origin feature/user-auth
# ... criar pull request ...
```

### Git Flow: Modelo Estruturado de Branching

Abordagem sistemática com branches dedicados para diferentes propósitos.

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

Siga o formato de commit convencional para um histórico de projeto claro.

```bash
# Formato: <tipo>(<escopo>): <assunto>
git commit -m "feat(auth): adiciona funcionalidade de login de usuário"
git commit -m "fix(api): resolve exceção de ponteiro nulo"
git commit -m "docs(readme): atualiza instruções de instalação"
git commit -m "refactor(utils): simplifica formatação de data"
```

### Commits Atômicos: Melhores Práticas

Crie commits focados, de propósito único, para um histórico melhor.

```bash
# Adicionar alterações interativamente
git add -p
# Alteração específica
git commit -m "Adiciona validação ao campo de e-mail"
# Evitar: git commit -m "Corrige coisas" # Muito vago
# Bom:  git commit -m "Corrige padrão regex de validação de e-mail"
```

## Solução de Problemas e Recuperação

### Reflog: Ferramenta de Recuperação

Use o log de referências do Git para recuperar commits perdidos.

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

Corrige problemas de integridade e corrupção do repositório.

```bash
# Verificar integridade do repositório
git fsck --full
# Limpeza agressiva
git gc --aggressive --prune=now
# Reconstruir índice se corrompido
rm .git/index; git reset
```

### Problemas de Autenticação

Resolve problemas comuns de autenticação e permissão.

```bash
# Usar token
git remote set-url origin https://token@github.com/user/repo.git
# Adicionar chave SSH ao agente
ssh-add ~/.ssh/id_rsa
# Gerenciador de credenciais do Windows
git config --global credential.helper manager-core
```

### Problemas de Desempenho: Depuração

Identifica e resolve problemas de desempenho do repositório.

```bash
# Mostrar tamanho do repositório
git count-objects -vH
# Contar total de commits
git log --oneline | wc -l
# Contar branches
git for-each-ref --format='%(refname:short)' | wc -l
```

## Links Relevantes

- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/shell">Shell Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/kubernetes">Kubernetes Cheatsheet</router-link>
- <router-link to="/ansible">Ansible Cheatsheet</router-link>
- <router-link to="/python">Python Cheatsheet</router-link>
- <router-link to="/javascript">JavaScript Cheatsheet</router-link>

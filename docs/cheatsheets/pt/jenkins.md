---
title: 'Cheatsheet Jenkins | LabEx'
description: 'Aprenda CI/CD com Jenkins com este cheatsheet abrangente. Referência rápida para pipelines, jobs, plugins, automação, integração contínua e fluxos de trabalho DevOps do Jenkins.'
pdfUrl: '/cheatsheets/pdf/jenkins-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas Jenkins
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/jenkins">Aprenda Jenkins com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda automação CI/CD com Jenkins através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Jenkins cobrindo operações essenciais, criação de pipelines, gerenciamento de plugins, automação de builds e técnicas avançadas. Domine o Jenkins para construir pipelines eficientes de integração contínua e entrega contínua para o desenvolvimento de software moderno.
</base-disclaimer-content>
</base-disclaimer>

## Instalação e Configuração

### Instalação no Linux

Instale o Jenkins em sistemas Ubuntu/Debian.

```bash
# Atualizar gerenciador de pacotes e instalar Java
sudo apt update
sudo apt install fontconfig openjdk-21-jre
java -version
# Adicionar chave GPG do Jenkins
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
# Adicionar repositório Jenkins
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
/etc/apt/sources.list.d/jenkins.list > /dev/null
# Instalar Jenkins
sudo apt update && sudo apt install jenkins
# Iniciar serviço Jenkins
sudo systemctl start jenkins
sudo systemctl enable jenkins
```

### Windows e macOS

Instale o Jenkins usando instaladores ou gerenciadores de pacotes.

```bash
# Windows: Baixar instalador do Jenkins em jenkins.io
# Ou usar Chocolatey
choco install jenkins
# macOS: Usar Homebrew
brew install jenkins-lts
# Ou baixar diretamente de:
# https://www.jenkins.io/download/
# Iniciar serviço Jenkins
brew services start jenkins-lts
```

### Configuração Pós-Instalação

Configuração inicial e desbloqueio do Jenkins.

```bash
# Obter senha de administrador inicial
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# Ou para instalações Docker
docker exec jenkins_container cat /var/jenkins_home/secrets/initialAdminPassword
# Acessar interface web do Jenkins
# Navegar para http://localhost:8080
# Inserir a senha de administrador inicial
# Instalar plugins sugeridos ou selecionar plugins personalizados
```

### Configuração Inicial

Concluir o assistente de configuração e criar o usuário administrador.

```bash
# Após desbloquear o Jenkins:
# 1. Instalar plugins sugeridos (recomendado)
# 2. Criar primeiro usuário administrador
# 3. Configurar URL do Jenkins
# 4. Começar a usar o Jenkins
# Verificar se o Jenkins está em execução
sudo systemctl status jenkins
# Verificar logs do Jenkins se necessário
sudo journalctl -u jenkins.service
```

## Operações Básicas do Jenkins

### Acessar Jenkins: Interface Web e Configuração CLI

Acessar Jenkins pelo navegador e configurar ferramentas CLI.

```bash
# Acessar interface web do Jenkins
http://localhost:8080
# Baixar CLI do Jenkins
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
# Testar conexão CLI
java -jar jenkins-cli.jar -s http://localhost:8080 help
# Listar comandos disponíveis
java -jar jenkins-cli.jar -s http://localhost:8080 help
```

### Criação de Job: `create-job` / UI Web

Criar novos jobs de build usando CLI ou interface web.

```bash
# Criar job a partir da configuração XML
java -jar jenkins-cli.jar -auth user:token create-job meu-job < job-config.xml
# Criar job freestyle simples via UI web:
# 1. Clicar em "New Item"
# 2. Inserir nome do job
# 3. Selecionar "Freestyle project"
# 4. Configurar etapas de build
# 5. Salvar configuração
```

### Listar Jobs: `list-jobs`

Visualizar todos os jobs configurados no Jenkins.

```bash
# Listar todos os jobs
java -jar jenkins-cli.jar -auth user:token list-jobs
# Listar jobs com correspondência de padrão
java -jar jenkins-cli.jar -auth user:token list-jobs "*teste*"
# Obter configuração do job
java -jar jenkins-cli.jar -auth user:token get-job meu-job > job-config.xml
```

## Gerenciamento de Jobs

### Executar Jobs: `build`

Disparar e gerenciar builds de jobs.

```bash
# Executar um job
java -jar jenkins-cli.jar -auth user:token build meu-job
# Executar com parâmetros
java -jar jenkins-cli.jar -auth user:token build meu-job -p PARAM=valor
# Executar e aguardar conclusão
java -jar jenkins-cli.jar -auth user:token build meu-job -s -v
# Executar e seguir o output do console
java -jar jenkins-cli.jar -auth user:token build meu-job -f
```

<BaseQuiz id="jenkins-build-1" correct="B">
  <template #question>
    O que a flag `-s` em `jenkins-cli.jar build meu-job -s` faz?
  </template>
  
  <BaseQuizOption value="A">Pula o build</BaseQuizOption>
  <BaseQuizOption value="B" correct>Aguarda a conclusão do build (síncrono)</BaseQuizOption>
  <BaseQuizOption value="C">Mostra o status do build</BaseQuizOption>
  <BaseQuizOption value="D">Para o build</BaseQuizOption>
  
  <BaseQuizAnswer>
    A flag `-s` torna o comando de build síncrono, ou seja, espera o build terminar antes de retornar. Sem ela, o comando retorna imediatamente após disparar o build.
  </BaseQuizAnswer>
</BaseQuiz>

### Controle de Job: `enable-job` / `disable-job`

Habilitar ou desabilitar jobs.

```bash
# Habilitar um job
java -jar jenkins-cli.jar -auth user:token enable-job meu-job
# Desabilitar um job
java -jar jenkins-cli.jar -auth user:token disable-job meu-job
# Verificar status do job na UI web
# Navegar para o dashboard do job
# Procurar botão "Disable/Enable"
```

<BaseQuiz id="jenkins-job-control-1" correct="B">
  <template #question>
    O que acontece quando você desabilita um job do Jenkins?
  </template>
  
  <BaseQuizOption value="A">O job é excluído permanentemente</BaseQuizOption>
  <BaseQuizOption value="B" correct>A configuração do job é preservada, mas ele não será executado automaticamente</BaseQuizOption>
  <BaseQuizOption value="C">O job é movido para outra pasta</BaseQuizOption>
  <BaseQuizOption value="D">Todo o histórico de builds é excluído</BaseQuizOption>
  
  <BaseQuizAnswer>
    Desabilitar um job impede que ele seja executado automaticamente (builds agendados, gatilhos, etc.), mas preserva a configuração do job e o histórico de builds. Você pode reabilitá-lo mais tarde.
  </BaseQuizAnswer>
</BaseQuiz>

### Exclusão de Job: `delete-job`

Remover jobs do Jenkins.

```bash
# Excluir um job
java -jar jenkins-cli.jar -auth user:token delete-job meu-job
# Excluir jobs em lote (com cautela)
for job in job1 job2 job3; do
  java -jar jenkins-cli.jar -auth user:token delete-job $job
done
```

### Output do Console: `console`

Visualizar logs de build e output do console.

```bash
# Visualizar output do console do build mais recente
java -jar jenkins-cli.jar -auth user:token console meu-job
# Visualizar número de build específico
java -jar jenkins-cli.jar -auth user:token console meu-job 15
# Seguir output do console em tempo real
java -jar jenkins-cli.jar -auth user:token console meu-job -f
```

<BaseQuiz id="jenkins-console-1" correct="C">
  <template #question>
    O que a flag `-f` em `jenkins-cli.jar console meu-job -f` faz?
  </template>
  
  <BaseQuizOption value="A">Força a parada do build</BaseQuizOption>
  <BaseQuizOption value="B">Mostra apenas builds com falha</BaseQuizOption>
  <BaseQuizOption value="C" correct>Segue o output do console em tempo real</BaseQuizOption>
  <BaseQuizOption value="D">Formata o output como JSON</BaseQuizOption>
  
  <BaseQuizAnswer>
    A flag `-f` segue o output do console em tempo real, semelhante a `tail -f` no Linux. Isso é útil para monitorar builds enquanto eles estão em execução.
  </BaseQuizAnswer>
</BaseQuiz>

## Gerenciamento de Pipeline

### Criação de Pipeline

Criar e configurar pipelines Jenkins.

```groovy
// Jenkinsfile Básico (Pipeline Declarativo)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Construindo aplicação...'
                sh 'make build'
            }
        }

        stage('Test') {
            steps {
                echo 'Executando testes...'
                sh 'make test'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Implantando aplicação...'
                sh 'make deploy'
            }
        }
    }
}
```

### Sintaxe de Pipeline

Sintaxe comum de pipeline e diretivas.

```groovy
// Sintaxe de Pipeline Scripted
node {
    stage('Checkout') {
        checkout scm
    }

    stage('Build') {
        sh 'make build'
    }

    stage('Test') {
        sh 'make test'
        junit 'target/test-results/*.xml'
    }
}
// Execução Paralela
stages {
    stage('Testes Paralelos') {
        parallel {
            stage('Testes Unitários') {
                steps {
                    sh 'make unit-test'
                }
            }
            stage('Testes de Integração') {
                steps {
                    sh 'make integration-test'
                }
            }
        }
    }
}
```

### Configuração de Pipeline

Configuração avançada de pipeline e opções.

```groovy
// Pipeline com ações pós-build
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }

    post {
        always {
            echo 'Isso sempre é executado'
        }
        success {
            echo 'Build bem-sucedido'
        }
        failure {
            echo 'Build falhou'
            emailext subject: 'Build Falhou',
                     body: 'Build falhou',
                     to: 'equipe@empresa.com'
        }
    }
}
```

### Gatilhos de Pipeline

Configurar gatilhos automáticos de pipeline.

```groovy
// Pipeline com gatilhos
pipeline {
    agent any

    triggers {
        // Sondar SCM a cada 5 minutos
        pollSCM('H/5 * * * *')

        // Agendamento tipo Cron
        cron('H 2 * * *')  // Diariamente às 2h

        // Gatilho de job upstream
        upstream(upstreamProjects: 'job-anterior',
                threshold: hudson.model.Result.SUCCESS)
    }

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}
```

## Gerenciamento de Plugins

### Instalação de Plugin: CLI

Instalar plugins usando interface de linha de comando.

```bash
# Instalar plugin via CLI (requer reinicialização)
java -jar jenkins-cli.jar -auth user:token install-plugin git
# Instalar múltiplos plugins
java -jar jenkins-cli.jar -auth user:token install-plugin \
  git maven-plugin docker-plugin
# Instalar a partir de arquivo .hpi
java -jar jenkins-cli.jar -auth user:token install-plugin \
  /caminho/para/plugin.hpi
# Listar plugins instalados
java -jar jenkins-cli.jar -auth user:token list-plugins
# Instalação de plugin via plugins.txt (para Docker)
# Criar arquivo plugins.txt:
git:latest
maven-plugin:latest
docker-plugin:latest
pipeline-stage-view:latest
# Usar ferramenta jenkins-plugin-cli
jenkins-plugin-cli --plugins git maven-plugin docker-plugin
```

### Plugins Essenciais

Plugins comumente usados para diferentes propósitos.

```bash
# Plugins de Build e SCM
git                    # Integração Git
github                 # Integração GitHub
maven-plugin          # Suporte a build Maven
gradle                # Suporte a build Gradle
# Plugins de Pipeline
workflow-aggregator   # Suíte de plugins de Pipeline
pipeline-stage-view   # Visualização de estágios do Pipeline
blue-ocean           # UI moderna para pipelines
# Implantação e Integração
docker-plugin        # Integração Docker
kubernetes           # Implantação Kubernetes
ansible              # Automação Ansible
# Qualidade e Teste
junit                # Relatórios de teste JUnit
jacoco              # Cobertura de código
sonarqube           # Análise de qualidade de código
```

### UI Web de Gerenciamento de Plugins

Gerenciar plugins através da interface web do Jenkins.

```bash
# Acessar Gerenciador de Plugins:
# 1. Navegar para Gerenciar Jenkins
# 2. Clicar em "Gerenciar Plugins"
# 3. Usar abas Disponíveis/Instalados/Atualizações
# 4. Pesquisar por plugins
# 5. Selecionar e instalar
# 6. Reiniciar Jenkins se necessário
# Processo de atualização de plugin:
# 1. Verificar aba "Updates"
# 2. Selecionar plugins para atualizar
# 3. Clicar em "Download now and install after restart"
```

## Gerenciamento de Usuários e Segurança

### Gerenciamento de Usuários

Criar e gerenciar usuários do Jenkins.

```bash
# Habilitar segurança no Jenkins:
# 1. Gerenciar Jenkins → Configurar Segurança Global
# 2. Habilitar "Banco de dados de usuários próprio do Jenkins"
# 3. Permitir que usuários se inscrevam (configuração inicial)
# 4. Definir estratégia de autorização
# Criar usuário via CLI (requer permissões apropriadas)
# Usuários são tipicamente criados via UI web:
# 1. Gerenciar Jenkins → Gerenciar Usuários
# 2. Clicar em "Criar Usuário"
# 3. Preencher detalhes do usuário
# 4. Atribuir funções/permissões
```

### Autenticação e Autorização

Configurar reinos de segurança e estratégias de autorização.

```bash
# Opções de configuração de segurança:
# 1. Realm de Segurança (como os usuários se autenticam):
#    - Banco de dados de usuários próprio do Jenkins
#    - LDAP
#    - Active Directory
#    - Segurança baseada em Matriz
#    - Autorização baseada em Funções
# 2. Estratégia de Autorização:
#    - Qualquer um pode fazer qualquer coisa
#    - Modo legado
#    - Usuários logados podem fazer qualquer coisa
#    - Segurança baseada em Matriz
#    - Autorização de Matriz baseada em Projeto
```

### Tokens de API

Gerar e gerenciar tokens de API para acesso CLI.

```bash
# Gerar token de API:
# 1. Clicar no nome de usuário → Configurar
# 2. Seção Token de API
# 3. Clicar em "Adicionar novo Token"
# 4. Inserir nome do token
# 5. Gerar e copiar o token
# Usar token de API com CLI
java -jar jenkins-cli.jar -auth nome_usuario:token-api \
  -s http://localhost:8080 list-jobs
# Armazenar credenciais com segurança
echo "nome_usuario:token-api" > ~/.jenkins-cli-auth
chmod 600 ~/.jenkins-cli-auth
```

### Gerenciamento de Credenciais

Gerenciar credenciais armazenadas para jobs e pipelines.

```bash
# Gerenciar credenciais via CLI
java -jar jenkins-cli.jar -auth user:token \
  list-credentials system::system::jenkins
# Criar XML de credenciais e importar
java -jar jenkins-cli.jar -auth user:token \
  create-credentials-by-xml system::system::jenkins \
  < credencial.xml
```

```groovy
// Acessar credenciais em pipelines
withCredentials([usernamePassword(
  credentialsId: 'minhas-credenciais',
  usernameVariable: 'USUARIO',
  passwordVariable: 'SENHA'
)]) {
  sh 'docker login -u $USUARIO -p $SENHA'
}
```

## Monitoramento de Build e Solução de Problemas

### Status e Logs do Build

Monitorar o status do build e acessar logs detalhados.

```bash
# Verificar status do build
java -jar jenkins-cli.jar -auth user:token console meu-job
# Obter informações do build
java -jar jenkins-cli.jar -auth user:token get-job meu-job
# Monitorar fila de builds
# UI Web: Dashboard do Jenkins → Fila de Builds
# Mostra builds pendentes e seu status
# Acesso ao histórico de builds
# UI Web: Job → Histórico de Builds
# Mostra todos os builds anteriores com status
```

### Informações do Sistema

Obter informações do sistema Jenkins e diagnósticos.

```bash
# Informações do sistema
java -jar jenkins-cli.jar -auth user:token version
# Informações do nó
java -jar jenkins-cli.jar -auth user:token list-computers
# Console Groovy (apenas admin)
# Gerenciar Jenkins → Console de Script
# Executar scripts Groovy para informações do sistema:
println Jenkins.instance.version
println Jenkins.instance.getRootDir()
println System.getProperty("java.version")
```

### Análise de Logs

Acessar e analisar logs do sistema Jenkins.

```bash
# Localização dos logs do sistema
# Linux: /var/log/jenkins/jenkins.log
# Windows: C:\Program Files\Jenkins\jenkins.out.log
# Visualizar logs
tail -f /var/log/jenkins/jenkins.log
# Configuração de níveis de log
# Gerenciar Jenkins → Log do Sistema
# Adicionar novo gravador de log para componentes específicos
# Locais comuns de log:
sudo journalctl -u jenkins.service     # Logs Systemd
sudo cat /var/lib/jenkins/jenkins.log  # Arquivo de log do Jenkins
```

### Monitoramento de Desempenho

Monitorar o desempenho e uso de recursos do Jenkins.

```bash
# Monitoramento embutido
# Gerenciar Jenkins → Estatísticas de Carga
# Mostra a utilização do executor ao longo do tempo
# Monitoramento de JVM
# Gerenciar Jenkins → Gerenciar Nós → Master
# Mostra uso de memória, CPU e propriedades do sistema
# Tendências de Build
# Instalar plugin "Build History Metrics"
# Visualizar tendências de duração e taxas de sucesso de builds
# Monitoramento de uso de disco
# Instalar plugin "Disk Usage"
# Monitorar espaço de trabalho e armazenamento de artefatos de build
```

## Configuração e Configurações do Jenkins

### Configuração Global

Configurar configurações globais do Jenkins e ferramentas.

```bash
# Configuração Global de Ferramentas
# Gerenciar Jenkins → Configuração Global de Ferramentas
# Configurar:
# - Instalações de JDK
# - Instalações de Git
# - Instalações de Maven
# - Instalações de Docker
# Configuração do Sistema
# Gerenciar Jenkins → Configurar Sistema
# Definir:
# - URL do Jenkins
# - Mensagem do sistema
# - # de executores
# - Período de silêncio (Quiet period)
# - Limites de sondagem SCM
```

### Variáveis de Ambiente

Configurar variáveis de ambiente e propriedades do sistema do Jenkins.

```bash
# Variáveis de ambiente embutidas
BUILD_NUMBER          # Número do build
BUILD_ID              # ID do build
JOB_NAME             # Nome do job
WORKSPACE            # Caminho do espaço de trabalho do job
JENKINS_URL          # URL do Jenkins
NODE_NAME            # Nome do nó
# Variáveis de ambiente personalizadas
# Gerenciar Jenkins → Configurar Sistema
# Propriedades globais → Variáveis de ambiente
# Adicionar pares chave-valor para acesso global
```

### Jenkins Configuration as Code

Gerenciar a configuração do Jenkins usando o plugin JCasC.

```yaml
# Arquivo de configuração JCasC (jenkins.yaml)
jenkins:
  systemMessage: "Jenkins configurado como código"
  numExecutors: 4
  securityRealm:
    local:
      allowsSignup: false
      users:
       - id: "admin"
         password: "admin123"
# Aplicar configuração
# Definir variável de ambiente CASC_JENKINS_CONFIG
export CASC_JENKINS_CONFIG=/caminho/para/jenkins.yaml
```

## Melhores Práticas

### Melhores Práticas de Segurança

Mantenha sua instância Jenkins segura e pronta para produção.

```bash
# Recomendações de segurança:
# 1. Habilitar segurança e autenticação
# 2. Usar autorização baseada em matriz
# 3. Atualizações de segurança regulares
# 4. Limitar permissões de usuário
# 5. Usar tokens de API em vez de senhas
# Proteger a configuração do Jenkins:
# - Desabilitar CLI sobre remoting
# - Usar HTTPS com certificados válidos
# - Backup regular do JENKINS_HOME
# - Monitorar avisos de segurança
# - Usar plugins de credenciais para segredos
```

### Otimização de Desempenho

Otimizar o Jenkins para melhor desempenho e escalabilidade.

```bash
# Dicas de desempenho:
# 1. Usar builds distribuídos com agentes
# 2. Otimizar scripts de build e dependências
# 3. Limpar builds antigos automaticamente
# 4. Usar bibliotecas de pipeline para reutilização
# 5. Monitorar espaço em disco e uso de memória
# Otimização de build:
# - Usar builds incrementais sempre que possível
# - Execução paralela de estágios
# - Cache de artefatos
# - Limpeza de espaço de trabalho
# - Ajuste de alocação de recursos
```

## Links Relevantes

- <router-link to="/devops">Folha de Dicas DevOps</router-link>
- <router-link to="/docker">Folha de Dicas Docker</router-link>
- <router-link to="/kubernetes">Folha de Dicas Kubernetes</router-link>
- <router-link to="/ansible">Folha de Dicas Ansible</router-link>
- <router-link to="/git">Folha de Dicas Git</router-link>
- <router-link to="/linux">Folha de Dicas Linux</router-link>
- <router-link to="/shell">Folha de Dicas Shell</router-link>

---
title: 'Guia Rápido Docker | LabEx'
description: 'Aprenda conteinerização Docker com este guia rápido abrangente. Referência rápida para comandos Docker, imagens, contêineres, Dockerfile, Docker Compose e orquestração de contêineres.'
pdfUrl: '/cheatsheets/pdf/docker-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Docker Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/docker">Aprenda Docker com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda a conteinerização Docker através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Docker cobrindo gerenciamento essencial de contêineres, construção de imagens, Docker Compose, rede, volumes e implantação. Domine a orquestração de contêineres e técnicas modernas de implantação de aplicações.
</base-disclaimer-content>
</base-disclaimer>

## Instalação e Configuração

### Instalação no Linux

Instale o Docker em sistemas Ubuntu/Debian.

```bash
# Atualizar gerenciador de pacotes
sudo apt update
# Instalar pré-requisitos
sudo apt install apt-transport-https ca-certificates curl
software-properties-common
# Adicionar a chave GPG oficial do Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg
| sudo apt-key add -
# Adicionar repositório Docker
sudo add-apt-repository "deb [arch=amd64]
https://download.docker.com/linux/ubuntu bionic stable"
# Instalar Docker
sudo apt update && sudo apt install docker-ce
# Iniciar serviço Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### Windows e macOS

Instale o Docker Desktop para gerenciamento baseado em GUI.

```bash
# Windows: Baixar Docker Desktop em docker.com
# macOS: Usar Homebrew ou baixar de docker.com
brew install --cask docker
# Ou baixar diretamente de:
# https://www.docker.com/products/docker-desktop
```

### Configuração Pós-Instalação

Configure o Docker para uso não-root e verifique a instalação.

```bash
# Adicionar usuário ao grupo docker (Linux)
sudo usermod -aG docker $USER
# Sair e fazer login novamente para que as alterações de grupo tenham efeito
# Verificar instalação do Docker
docker --version
docker run hello-world
```

### Instalação do Docker Compose

Instale o Docker Compose para aplicações multi-contêineres.

```bash
# Linux: Instalar via curl
sudo curl -L
"https://github.com/docker/compose/releases/download
/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o
/usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
# Verificar instalação
docker-compose --version
# Nota: Docker Desktop inclui o Compose
```

## Comandos Básicos do Docker

### Informações do Sistema: `docker version` / `docker system info`

Verifique os detalhes da instalação e do ambiente Docker.

```bash
# Exibir informações de versão do Docker
docker version
# Mostrar informações do sistema Docker
information
docker system info
# Exibir ajuda para comandos Docker
docker help
docker <comando> --help
```

### Executando Contêineres: `docker run`

Crie e inicie um contêiner a partir de uma imagem.

```bash
# Executar um contêiner interativamente
docker run -it ubuntu:latest bash
# Executar contêiner em segundo plano
(detached)
docker run -d --name meu-container
nginx
# Executar com mapeamento de porta
docker run -p 8080:80 nginx
# Executar com remoção automática após a saída
docker run --rm hello-world
```

<BaseQuiz id="docker-run-1" correct="C">
  <template #question>
    O que `docker run -d` faz?
  </template>
  
  <BaseQuizOption value="A">Executa o contêiner em modo de depuração</BaseQuizOption>
  <BaseQuizOption value="B">Exclui o contêiner após ele parar</BaseQuizOption>
  <BaseQuizOption value="C" correct>Executa o contêiner em modo desanexado (background)</BaseQuizOption>
  <BaseQuizOption value="D">Executa o contêiner com configurações padrão</BaseQuizOption>
  
  <BaseQuizAnswer>
    O flag `-d` executa o contêiner em modo desanexado, o que significa que ele roda em segundo plano e retorna o controle imediatamente ao terminal. Isso é útil para serviços de longa execução.
  </BaseQuizAnswer>
</BaseQuiz>

### Listar Contêineres: `docker ps`

Visualize contêineres em execução e parados.

```bash
# Listar contêineres em execução
docker ps
# Listar todos os contêineres (incluindo
parados)
docker ps -a
# Listar apenas IDs de contêineres
docker ps -q
# Mostrar o contêiner criado mais recentemente
docker ps -l
```

## Gerenciamento de Contêineres

### Ciclo de Vida do Contêiner: `start` / `stop` / `restart`

Controle o estado de execução do contêiner.

```bash
# Parar um contêiner em execução
docker stop nome_do_container
# Iniciar um contêiner parado
docker start nome_do_container
# Reiniciar um contêiner
docker restart nome_do_container
# Pausar/despausar processos do contêiner
docker pause nome_do_container
docker unpause nome_do_container
```

### Executar Comandos: `docker exec`

Execute comandos dentro de contêineres em execução.

```bash
# Executar shell bash interativo
docker exec -it nome_do_container bash
# Executar um único comando
docker exec nome_do_container ls -la
# Executar como usuário diferente
docker exec -u root nome_do_container whoami
# Executar em um diretório específico
docker exec -w /app nome_do_container pwd
```

### Remoção de Contêineres: `docker rm`

Remova contêineres do sistema.

```bash
# Remover um contêiner parado
docker rm nome_do_container
# Remover forçadamente um contêiner em execução
docker rm -f nome_do_container
# Remover múltiplos contêineres
docker rm container1 container2
# Remover todos os contêineres parados
docker container prune
```

### Logs do Contêiner: `docker logs`

Visualize a saída do contêiner e depure problemas.

```bash
# Visualizar logs do contêiner
docker logs nome_do_container
# Seguir logs em tempo real
docker logs -f nome_do_container
# Mostrar apenas logs recentes
docker logs --tail 50 nome_do_container
# Mostrar logs com carimbos de data/hora
docker logs -t nome_do_container
```

## Gerenciamento de Imagens

### Construção de Imagens: `docker build`

Crie imagens Docker a partir de Dockerfiles.

```bash
# Construir imagem a partir do diretório atual
docker build .
# Construir e taguear uma imagem
docker build -t minhaapp:latest .
# Construir com argumentos de construção
docker build --build-arg VERSION=1.0 -t minhaapp .
# Construir sem usar cache
docker build --no-cache -t minhaapp .
```

<BaseQuiz id="docker-build-1" correct="A">
  <template #question>
    O que `docker build -t minhaapp:latest .` faz?
  </template>
  
  <BaseQuizOption value="A" correct>Constrói uma imagem Docker com a tag "minhaapp:latest" a partir do diretório atual</BaseQuizOption>
  <BaseQuizOption value="B">Executa um contêiner chamado "minhaapp"</BaseQuizOption>
  <BaseQuizOption value="C">Puxa a imagem "minhaapp:latest" do Docker Hub</BaseQuizOption>
  <BaseQuizOption value="D">Exclui a imagem "minhaapp:latest"</BaseQuizOption>
  
  <BaseQuizAnswer>
    O flag `-t` tagueia a imagem com o nome "minhaapp:latest", e o `.` especifica o contexto de construção (diretório atual). Este comando constrói uma nova imagem a partir de um Dockerfile no diretório atual.
  </BaseQuizAnswer>
</BaseQuiz>

### Inspeção de Imagens: `docker images` / `docker inspect`

Liste e examine imagens Docker.

```bash
# Listar todas as imagens locais
docker images
# Listar imagens com filtros específicos
docker images nginx
# Mostrar detalhes da imagem
docker inspect nome_da_imagem
# Ver histórico de construção da imagem
docker history nome_da_imagem
```

### Operações de Registro: `docker pull` / `docker push`

Baixar e enviar imagens para registros.

```bash
# Puxar imagem do Docker Hub
docker pull nginx:latest
# Puxar versão específica
docker pull ubuntu:20.04
# Enviar imagem para o registro
docker push meuusuario/minhaapp:latest
# Taguear imagem antes de enviar
docker tag minhaapp:latest meuusuario/minhaapp:v1.0
```

### Limpeza de Imagens: `docker rmi` / `docker image prune`

Remova imagens não utilizadas para liberar espaço em disco.

```bash
# Remover uma imagem específica
docker rmi nome_da_imagem
# Remover imagens não utilizadas
docker image prune
# Remover todas as imagens não utilizadas (não apenas pendentes)
docker image prune -a
# Remover imagem forçadamente
docker rmi -f nome_da_imagem
```

## Fundamentos do Dockerfile

### Instruções Essenciais

Comandos centrais do Dockerfile para construir imagens.

```dockerfile
# Imagem base
FROM ubuntu:20.04
# Definir informação do mantenedor
LABEL maintainer="user@example.com"
# Instalar pacotes
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# Copiar arquivos do host para o contêiner
COPY app.py /app/
# Definir diretório de trabalho
WORKDIR /app
# Expor porta
EXPOSE 8000
```

<BaseQuiz id="dockerfile-1" correct="B">
  <template #question>
    Qual é o propósito da instrução `FROM` em um Dockerfile?
  </template>
  
  <BaseQuizOption value="A">Copia arquivos do host para o contêiner</BaseQuizOption>
  <BaseQuizOption value="B" correct>Especifica a imagem base sobre a qual construir</BaseQuizOption>
  <BaseQuizOption value="C">Define variáveis de ambiente</BaseQuizOption>
  <BaseQuizOption value="D">Define o comando a ser executado quando o contêiner inicia</BaseQuizOption>
  
  <BaseQuizAnswer>
    A instrução `FROM` deve ser a primeira instrução não-comentada em um Dockerfile. Ela especifica a imagem base sobre a qual sua imagem será construída, fornecendo a fundação para seu contêiner.
  </BaseQuizAnswer>
</BaseQuiz>

### Configuração de Execução

Configure como o contêiner será executado.

```dockerfile
# Definir variáveis de ambiente
ENV PYTHON_ENV=production
ENV PORT=8000
# Criar usuário para segurança
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# Definir comando de inicialização
CMD ["python3", "app.py"]
# Ou usar ENTRYPOINT para comandos fixos
ENTRYPOINT ["python3"]
CMD ["app.py"]
# Definir verificação de saúde
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/ || exit 1
```

## Docker Compose

### Comandos Básicos do Compose: `docker-compose up` / `docker-compose down`

Iniciar e parar aplicações multi-contêineres.

```bash
# Iniciar serviços em primeiro plano
docker-compose up
# Iniciar serviços em segundo plano
docker-compose up -d
# Construir e iniciar serviços
docker-compose up --build
# Parar e remover serviços
docker-compose down
# Parar e remover com volumes
docker-compose down -v
```

<BaseQuiz id="docker-compose-1" correct="D">
  <template #question>
    O que `docker-compose up -d` faz?
  </template>
  
  <BaseQuizOption value="A">Para todos os contêineres em execução</BaseQuizOption>
  <BaseQuizOption value="B">Constrói imagens sem iniciar contêineres</BaseQuizOption>
  <BaseQuizOption value="C">Mostra logs de todos os serviços</BaseQuizOption>
  <BaseQuizOption value="D" correct>Inicia todos os serviços definidos em docker-compose.yml em modo desanexado</BaseQuizOption>
  
  <BaseQuizAnswer>
    O flag `-d` executa contêineres em modo desanexado (background). `docker-compose up` lê o arquivo docker-compose.yml e inicia todos os serviços definidos, facilitando o gerenciamento de aplicações multi-contêineres.
  </BaseQuizAnswer>
</BaseQuiz>

### Gerenciamento de Serviços

Controle serviços individuais dentro de aplicações Compose.

```bash
# Listar serviços em execução
docker-compose ps
# Visualizar logs de serviço
docker-compose logs nome_do_servico
# Seguir logs para todos os serviços
docker-compose logs -f
# Reiniciar um serviço específico
docker-compose restart nome_do_servico
```

### Exemplo de docker-compose.yml

Exemplo de configuração de aplicação multi-serviço.

```yaml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      -
DATABASE_URL=postgresql://user:pass@db:5432/myapp
    depends_on:
      - db
    volumes:
      - .:/app

  db:
    image: postgres:13
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - db_data:/var/lib/postgresql/data
volumes:
  db_data:
```

## Rede e Volumes

### Rede de Contêineres

Conecte contêineres e exponha serviços.

```bash
# Listar redes
docker network ls
# Criar uma rede personalizada
docker network create mynetwork
# Executar contêiner em rede específica
docker run --network mynetwork nginx
# Conectar contêiner em execução à rede
docker network connect mynetwork nome_do_container
# Inspecionar detalhes da rede
docker network inspect mynetwork
```

### Mapeamento de Portas

Exponha portas de contêineres para o sistema host.

```bash
# Mapear porta única
docker run -p 8080:80 nginx
```

<BaseQuiz id="docker-port-1" correct="A">
  <template #question>
    Em `docker run -p 8080:80 nginx`, o que os números das portas significam?
  </template>
  
  <BaseQuizOption value="A" correct>8080 é a porta do host, 80 é a porta do contêiner</BaseQuizOption>
  <BaseQuizOption value="B">80 é a porta do host, 8080 é a porta do contêiner</BaseQuizOption>
  <BaseQuizOption value="C">Ambas as portas são portas de contêiner</BaseQuizOption>
  <BaseQuizOption value="D">Ambas as portas são portas do host</BaseQuizOption>
  
  <BaseQuizAnswer>
    O formato é `-p porta_host:porta_container`. A porta 8080 na sua máquina host é mapeada para a porta 80 dentro do contêiner, permitindo que você acesse o servidor web nginx rodando no contêiner via localhost:8080.
  </BaseQuizAnswer>
</BaseQuiz>

```bash
# Mapear múltiplas portas
docker run -p 8080:80 -p 8443:443 nginx
# Mapear para interface host específica
docker run -p 127.0.0.1:8080:80 nginx
# Expor todas as portas definidas na imagem
docker run -P nginx
```

### Volumes de Dados: `docker volume`

Persistir e compartilhar dados entre contêineres.

```bash
# Criar um volume nomeado
docker volume create myvolume
# Listar todos os volumes
docker volume ls
# Inspecionar detalhes do volume
docker volume inspect myvolume
# Remover volume
docker volume rm myvolume
# Remover volumes não utilizados
docker volume prune
```

### Montagem de Volumes

Montar volumes nomeados e diretórios do host em contêineres.

```bash
# Montar volume nomeado
docker run -v myvolume:/data nginx
# Montar diretório do host (bind mount)
docker run -v /caminho/no/host:/caminho/no/container nginx
# Montar diretório atual
docker run -v $(pwd):/app nginx
# Montagem somente leitura
docker run -v /caminho/no/host:/caminho/no/container:ro nginx
```

## Inspeção e Depuração de Contêineres

### Detalhes do Contêiner: `docker inspect`

Obter informações detalhadas sobre contêineres e imagens.

```bash
# Inspecionar configuração do contêiner
docker inspect nome_do_container
# Obter informação específica usando formatação
docker inspect --format='{{.State.Status}}'
nome_do_container
# Obter endereço IP
docker inspect --format='{{.NetworkSettings.IPAddress}}'
nome_do_container
# Obter volumes montados
docker inspect --format='{{.Mounts}}' nome_do_container
```

### Monitoramento de Recursos

Monitorar o uso de recursos e o desempenho do contêiner.

```bash
# Mostrar processos em execução no contêiner
docker top nome_do_container
# Exibir estatísticas de uso de recursos ao vivo
docker stats
# Mostrar estatísticas para contêiner específico
docker stats nome_do_container
# Monitorar eventos em tempo real
docker events
```

### Operações de Arquivo: `docker cp`

Copiar arquivos entre contêineres e o sistema host.

```bash
# Copiar arquivo do contêiner para o host
docker cp nome_do_container:/caminho/do/arquivo ./
# Copiar arquivo do host para o contêiner
docker cp ./arquivo nome_do_container:/caminho/do/destino
# Copiar diretório
docker cp ./diretorio
nome_do_container:/caminho/do/destino/
# Copiar com modo de arquivo para preservar permissões
docker cp -a ./diretorio nome_do_container:/caminho/
```

### Solução de Problemas

Depurar problemas de contêiner e conectividade.

```bash
# Verificar código de saída do contêiner
docker inspect --format='{{.State.ExitCode}}'
nome_do_container
# Visualizar processos do contêiner
docker exec nome_do_container ps aux
# Testar conectividade de rede
docker exec nome_do_container ping google.com
# Verificar uso de disco
docker exec nome_do_container df -h
```

## Registro e Autenticação

### Operações do Docker Hub: `docker login` / `docker search`

Autenticar e interagir com o Docker Hub.

```bash
# Fazer login no Docker Hub
docker login
# Fazer login em registro específico
docker login registry.example.com
# Procurar por imagens no Docker Hub
docker search nginx
# Procurar com filtro
docker search --filter stars=100 nginx
```

### Marcação e Publicação de Imagens

Preparar e publicar imagens em registros.

```bash
# Taguear imagem para o registro
docker tag minhaapp:latest usuario/minhaapp:v1.0
docker tag minhaapp:latest
registry.example.com/minhaapp:latest
# Enviar para o Docker Hub
docker push usuario/minhaapp:v1.0
# Enviar para registro privado
docker push registry.example.com/minhaapp:latest
```

### Registro Privado

Trabalhar com registros Docker privados.

```bash
# Puxar de registro privado
docker pull registry.company.com/minhaapp:latest
# Executar registro local
docker run -d -p 5000:5000 --name registry registry:2
# Enviar para registro local
docker tag minhaapp localhost:5000/minhaapp
docker push localhost:5000/minhaapp
```

### Segurança de Imagens

Verificar integridade e segurança das imagens.

```bash
# Habilitar Docker Content Trust
export DOCKER_CONTENT_TRUST=1
# Assinar e enviar imagem
docker push usuario/minhaapp:signed
# Inspecionar assinaturas de imagem
docker trust inspect usuario/minhaapp:signed
# Escanear imagens em busca de vulnerabilidades
docker scan minhaapp:latest
```

## Limpeza e Manutenção do Sistema

### Limpeza do Sistema: `docker system prune`

Remover recursos Docker não utilizados para liberar espaço em disco.

```bash
# Remover contêineres, redes, imagens não utilizados
docker system prune
# Incluir volumes não utilizados na limpeza
docker system prune -a --volumes
# Remover tudo (use com cautela)
docker system prune -a -f
# Mostrar uso de espaço
docker system df
```

### Limpeza Direcionada

Remover tipos específicos de recursos não utilizados.

```bash
# Remover contêineres parados
docker container prune
# Remover imagens não utilizadas
docker image prune -a
# Remover volumes não utilizados
docker volume prune
# Remover redes não utilizadas
docker network prune
```

### Operações em Massa

Executar operações em múltiplos contêineres/imagens.

```bash
# Parar todos os contêineres em execução
docker stop $(docker ps -q)
# Remover todos os contêineres
docker rm $(docker ps -aq)
# Remover todas as imagens
docker rmi $(docker images -q)
# Remover apenas imagens pendentes (dangling)
docker rmi $(docker images -f "dangling=true" -q)
```

### Limites de Recursos

Controlar o consumo de recursos dos contêineres.

```bash
# Limitar uso de memória
docker run --memory=512m nginx
# Limitar uso de CPU
docker run --cpus="1.5" nginx
# Limitar CPU e memória
docker run --memory=1g --cpus="2.0" nginx
# Definir política de reinicialização
docker run --restart=always nginx
```

## Configuração e Configurações do Docker

### Configuração do Daemon

Configurar o daemon Docker para uso em produção.

```bash
# Editar configuração do daemon
sudo nano
/etc/docker/daemon.json
# Exemplo de configuração:
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
# Reiniciar serviço Docker
sudo systemctl restart docker
```

### Variáveis de Ambiente

Configurar o comportamento do cliente Docker com variáveis de ambiente.

```bash
# Definir host Docker
export
DOCKER_HOST=tcp://remote-
docker:2376
# Habilitar verificação TLS
export DOCKER_TLS_VERIFY=1
export
DOCKER_CERT_PATH=/caminho/para/cert
s
# Definir registro padrão
export
DOCKER_REGISTRY=registry.co
mpany.com
# Saída de depuração
export DOCKER_BUILDKIT=1
```

### Ajuste de Desempenho

Otimizar o Docker para melhor desempenho.

```bash
# Habilitar recursos experimentais
echo '{"experimental": true}' |
sudo tee
/etc/docker/daemon.json
# Opções de driver de armazenamento
{
  "storage-driver": "overlay2",
  "storage-opts": [

"overlay2.override_kernel_check
=true"
  ]
}
# Configurar logging
{
  "log-driver": "syslog",
  "log-opts": {"syslog-address":
"udp://logs.company.com:514"}
}
```

## Melhores Práticas

### Melhores Práticas de Segurança

Mantenha seus contêineres seguros e prontos para produção.

```dockerfile
# Executar como usuário não-root no Dockerfile
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# Usar tags de imagem específicas, não 'latest'
FROM node:16.20.0-alpine
# Usar sistemas de arquivos somente leitura quando possível
docker run --read-only nginx
```

### Otimização de Desempenho

Otimize contêineres para velocidade e eficiência de recursos.

```dockerfile
# Usar builds multi-stage para reduzir o tamanho da imagem
FROM node:16 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
FROM node:16-alpine
WORKDIR /app
COPY --from=builder /app/node_modules
./node_modules
COPY . .
CMD ["node", "server.js"]
```

## Links Relevantes

- <router-link to="/kubernetes">Kubernetes Cheatsheet</router-link>
- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/shell">Shell Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/ansible">Ansible Cheatsheet</router-link>
- <router-link to="/git">Git Cheatsheet</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Cheatsheet</router-link>
- <router-link to="/python">Python Cheatsheet</router-link>

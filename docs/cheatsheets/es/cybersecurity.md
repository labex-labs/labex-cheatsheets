---
title: 'Hoja de Trucos de Ciberseguridad | LabEx'
description: 'Aprenda ciberseguridad con esta hoja de trucos completa. Referencia rápida para conceptos de seguridad, detección de amenazas, evaluación de vulnerabilidades, pruebas de penetración y mejores prácticas de seguridad de la información.'
pdfUrl: '/cheatsheets/pdf/cybersecurity-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Ciberseguridad
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/cybersecurity">Aprenda Ciberseguridad con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda ciberseguridad a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de ciberseguridad que cubren identificación de amenazas, evaluación de seguridad, fortalecimiento de sistemas, respuesta a incidentes y técnicas de monitoreo. Aprenda a proteger sistemas y datos de amenazas cibernéticas utilizando herramientas estándar de la industria y las mejores prácticas.
</base-disclaimer-content>
</base-disclaimer>

## Fundamentos de Seguridad de Sistemas

### Gestión de Cuentas de Usuario

Controlar el acceso a sistemas y datos.

```bash
# Añadir un nuevo usuario
sudo adduser username
# Establecer política de contraseñas
sudo passwd -l username
# Otorgar privilegios sudo
sudo usermod -aG sudo username
# Ver información del usuario
id username
# Listar todos los usuarios
cat /etc/passwd
```

### Permisos y Seguridad de Archivos

Configurar acceso seguro a archivos y directorios.

```bash
# Cambiar permisos de archivo (lectura, escritura, ejecución)
chmod 644 file.txt
# Cambiar propietario
chown user:group file.txt
# Establecer permisos recursivamente
chmod -R 755 directory/
# Ver permisos de archivo
ls -la
```

<BaseQuiz id="cybersecurity-chmod-1" correct="C">
  <template #question>
    ¿Qué establece `chmod 644 file.txt` para los permisos de archivo?
  </template>
  
  <BaseQuizOption value="A">Lectura, escritura, ejecución para todos los usuarios</BaseQuizOption>
  <BaseQuizOption value="B">Lectura, escritura, ejecución para el propietario; lectura para los demás</BaseQuizOption>
  <BaseQuizOption value="C" correct>Lectura, escritura para el propietario; lectura para el grupo y los demás</BaseQuizOption>
  <BaseQuizOption value="D">Solo lectura para todos los usuarios</BaseQuizOption>
  
  <BaseQuizAnswer>
    `chmod 644` establece: propietario = 6 (rw-), grupo = 4 (r--), demás = 4 (r--). Este es un conjunto de permisos común para archivos que deben ser legibles por todos pero solo modificables por el propietario.
  </BaseQuizAnswer>
</BaseQuiz>

### Configuración de Seguridad de Red

Asegurar conexiones y servicios de red.

```bash
# Configurar firewall (UFW)
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw deny 23/tcp
# Comprobar puertos abiertos
netstat -tuln
sudo ss -tuln
```

<BaseQuiz id="cybersecurity-firewall-1" correct="B">
  <template #question>
    ¿Qué hace `sudo ufw allow 22/tcp`?
  </template>
  
  <BaseQuizOption value="A">Bloquea el puerto 22</BaseQuizOption>
  <BaseQuizOption value="B" correct>Permite tráfico TCP en el puerto 22 (SSH)</BaseQuizOption>
  <BaseQuizOption value="C">Habilita UDP en el puerto 22</BaseQuizOption>
  <BaseQuizOption value="D">Muestra el estado del firewall</BaseQuizOption>
  
  <BaseQuizAnswer>
    `ufw allow 22/tcp` crea una regla de firewall que permite conexiones TCP entrantes en el puerto 22, que es el puerto predeterminado de SSH. Esto es esencial para el acceso remoto al servidor.
  </BaseQuizAnswer>
</BaseQuiz>

### Actualizaciones y Parches del Sistema

Mantener los sistemas actualizados con los últimos parches de seguridad.

```bash
# Actualizar listas de paquetes (Ubuntu/Debian)
sudo apt update
# Actualizar todos los paquetes
sudo apt upgrade
# Actualizaciones de seguridad automáticas
sudo apt install unattended-upgrades
```

### Gestión de Servicios

Controlar y monitorear los servicios del sistema.

```bash
# Detener servicios innecesarios
sudo systemctl stop service_name
sudo systemctl disable service_name
# Comprobar estado del servicio
sudo systemctl status ssh
# Ver servicios en ejecución
systemctl list-units --type=service --state=running
```

### Monitoreo de Registros (Logs)

Monitorear los registros del sistema en busca de eventos de seguridad.

```bash
# Ver registros de autenticación
sudo tail -f /var/log/auth.log
# Revisar registros del sistema
sudo journalctl -f
# Buscar inicios de sesión fallidos
grep "Failed password" /var/log/auth.log
```

<BaseQuiz id="cybersecurity-logs-1" correct="A">
  <template #question>
    ¿Qué hace `tail -f /var/log/auth.log`?
  </template>
  
  <BaseQuizOption value="A" correct>Sigue el archivo de registro de autenticación en tiempo real</BaseQuizOption>
  <BaseQuizOption value="B">Muestra solo los intentos de inicio de sesión fallidos</BaseQuizOption>
  <BaseQuizOption value="C">Elimina entradas de registro antiguas</BaseQuizOption>
  <BaseQuizOption value="D">Archiva el archivo de registro</BaseQuizOption>
  
  <BaseQuizAnswer>
    La bandera `-f` hace que `tail` siga el archivo, mostrando nuevas entradas de registro a medida que se escriben. Esto es útil para el monitoreo en tiempo real de eventos de autenticación e incidentes de seguridad.
  </BaseQuizAnswer>
</BaseQuiz>

## Seguridad de Contraseñas y Autenticación

Implementar mecanismos de autenticación sólidos y políticas de contraseñas.

### Creación de Contraseñas Fuertes

Generar y gestionar contraseñas seguras siguiendo las mejores prácticas.

```bash
# Generar contraseña fuerte
openssl rand -base64 32
# Requisitos de fortaleza de contraseña:
# - Mínimo 12 caracteres
# - Mezcla de mayúsculas, minúsculas, números, símbolos
# - Sin palabras de diccionario ni información personal
# - Única para cada cuenta
```

### Autenticación Multifactor (MFA)

Añadir capas adicionales de autenticación más allá de las contraseñas.

```bash
# Instalar Google Authenticator
sudo apt install libpam-googleauthenticator
# Configurar MFA para SSH
google-authenticator
# Habilitar en la configuración de SSH
sudo nano /etc/pam.d/sshd
# Añadir: auth required pam_google_authenticator.so
```

### Gestión de Contraseñas

Utilizar gestores de contraseñas y prácticas de almacenamiento seguro.

```bash
# Instalar gestor de contraseñas (KeePassXC)
sudo apt install keepassxc
# Mejores prácticas:
# - Usar contraseñas únicas para cada servicio
# - Habilitar funciones de bloqueo automático
# - Rotación regular de contraseñas para cuentas críticas
# - Copia de seguridad segura de la base de datos de contraseñas
```

## Seguridad y Monitoreo de Red

### Escaneo de Puertos y Descubrimiento

Identificar puertos abiertos y servicios en ejecución.

```bash
# Escaneo básico de puertos con Nmap
nmap -sT target_ip
# Detección de versión de servicio
nmap -sV target_ip
# Escaneo exhaustivo
nmap -A target_ip
# Escanear puertos específicos
nmap -p 22,80,443 target_ip
# Escanear rango de IPs
nmap 192.168.1.1-254
```

### Análisis de Tráfico de Red

Monitorear y analizar las comunicaciones de red.

```bash
# Capturar paquetes con tcpdump
sudo tcpdump -i eth0
# Guardar en archivo
sudo tcpdump -w capture.pcap
# Filtrar tráfico específico
sudo tcpdump host 192.168.1.1
# Monitorear puerto específico
sudo tcpdump port 80
```

### Configuración de Firewall

Controlar el tráfico de red entrante y saliente.

```bash
# UFW (Uncomplicated Firewall)
sudo ufw status
sudo ufw allow ssh
sudo ufw deny 23
# Reglas de iptables
sudo iptables -L
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

### Gestión de Certificados SSL/TLS

Implementar comunicaciones seguras con cifrado.

```bash
# Generar certificado autofirmado
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
# Comprobar detalles del certificado
openssl x509 -in cert.pem -text -noout
# Probar conexión SSL
openssl s_client -connect example.com:443
```

## Evaluación de Vulnerabilidades

### Escaneo de Vulnerabilidades del Sistema

Identificar debilidades de seguridad en sistemas y aplicaciones.

```bash
# Instalar escáner Nessus
# Descargar desde tenable.com
sudo dpkg -i Nessus-X.X.X-ubuntu1404_amd64.deb
# Iniciar servicio Nessus
sudo systemctl start nessusd
# Acceder a la interfaz web en https://localhost:8834
# Usando OpenVAS (alternativa gratuita)
sudo apt install openvas
sudo gvm-setup
```

### Pruebas de Seguridad de Aplicaciones Web

Probar aplicaciones web en busca de vulnerabilidades comunes.

```bash
# Usando el escáner web Nikto
nikto -h http://target.com
# Enumeración de directorios
dirb http://target.com
# Pruebas de inyección SQL
sqlmap -u "http://target.com/page.php?id=1" --dbs
```

### Herramientas de Auditoría de Seguridad

Utilidades integrales de evaluación de seguridad.

```bash
# Auditoría de seguridad Lynis
sudo apt install lynis
sudo lynis audit system
# Comprobar rootkits
sudo apt install chkrootkit
sudo chkrootkit
# Monitoreo de integridad de archivos
sudo apt install aide
sudo aideinit
```

### Seguridad de la Configuración

Verificar configuraciones seguras de sistemas y aplicaciones.

```bash
# Comprobación de seguridad SSH
ssh-audit target_ip
# Prueba de configuración SSL
testssl.sh https://target.com
# Comprobar permisos de archivos sensibles
ls -la /etc/shadow /etc/passwd /etc/group
```

## Respuesta a Incidentes y Forense

### Análisis de Registros e Investigación

Analizar registros del sistema para identificar incidentes de seguridad.

```bash
# Buscar actividades sospechosas
grep -i "failed\|error\|denied" /var/log/auth.log
# Contar intentos de inicio de sesión fallidos
grep "Failed password" /var/log/auth.log | wc -l
# Encontrar direcciones IP únicas en los registros
awk '/Failed password/ {print $11}' /var/log/auth.log | sort | uniq -c
# Monitorear actividad de registro en vivo
tail -f /var/log/syslog
```

### Forense de Red

Investigar incidentes de seguridad basados en red.

```bash
# Analizar tráfico de red con Wireshark
# Instalar: sudo apt install wireshark
# Capturar tráfico en vivo
sudo wireshark
# Analizar archivos capturados
wireshark capture.pcap
# Análisis en línea de comandos con tshark
tshark -r capture.pcap -Y "http.request"
```

### Forense de Sistemas

Preservar y analizar evidencia digital.

```bash
# Crear imagen de disco
sudo dd if=/dev/sda of=/mnt/evidence/disk_image.dd bs=4096
# Calcular hashes de archivos para integridad
md5sum important_file.txt
sha256sum important_file.txt
# Buscar contenido específico en archivos
grep -r "password" /home/user/
# Listar archivos modificados recientemente
find /home -mtime -7 -type f
```

### Documentación de Incidentes

Documentar adecuadamente los incidentes de seguridad para su análisis.

```bash
# Lista de verificación de respuesta a incidentes:
# 1. Aislar sistemas afectados
# 2. Preservar evidencia
# 3. Documentar cronología de eventos
# 4. Identificar vectores de ataque
# 5. Evaluar daños y exposición de datos
# 6. Implementar medidas de contención
# 7. Planificar procedimientos de recuperación
```

## Inteligencia de Amenazas

Recopilar y analizar información sobre amenazas de seguridad actuales y emergentes.

### OSINT (Inteligencia de Fuentes Abiertas)

Recopilar información de amenazas disponible públicamente.

```bash
# Buscar información de dominio
whois example.com
# Búsqueda DNS
dig example.com
nslookup example.com
# Encontrar subdominios
sublist3r -d example.com
# Consultar bases de datos de reputación
# VirusTotal, URLVoid, AbuseIPDB
```

### Herramientas de Caza de Amenazas (Threat Hunting)

Buscar proactivamente amenazas en su entorno.

```bash
# Búsqueda de IOC (Indicadores de Compromiso)
grep -r "suspicious_hash" /var/log/
# Comprobar si hay IPs maliciosas
grep "192.168.1.100" /var/log/auth.log
# Comparación de hash de archivos
find /tmp -type f -exec sha256sum {} \;
```

### Fuentes y Inteligencia de Amenazas

Mantenerse actualizado con la última información de amenazas.

```bash
# Fuentes populares de inteligencia de amenazas:
# - MISP (Malware Information Sharing Platform)
# - Feeds STIX/TAXII
# - Fuentes comerciales (CrowdStrike, FireEye)
# - Fuentes gubernamentales (US-CERT, CISA)
# Ejemplo: Comprobar IP contra fuentes de amenazas
curl -s "https://api.threatintel.com/check?ip=1.2.3.4"
```

### Modelado de Amenazas

Identificar y evaluar amenazas de seguridad potenciales.

```bash
# Categorías del modelo de amenazas STRIDE:
# - Spoofing (Suplantación de identidad)
# - Tampering (Manipulación de datos)
# - Repudiation (Repudio de acciones)
# - Information Disclosure (Divulgación de información)
# - Denial of Service (Denegación de Servicio)
# - Elevation of Privilege (Elevación de Privilegios)
```

## Cifrado y Protección de Datos

Implementar un cifrado sólido para proteger los datos sensibles.

### Cifrado de Archivos y Discos

Cifrar archivos y dispositivos de almacenamiento para proteger los datos en reposo.

```bash
# Cifrar un archivo con GPG
gpg -c sensitive_file.txt
# Descifrar archivo
gpg sensitive_file.txt.gpg
# Cifrado de disco completo con LUKS
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup luksOpen /dev/sdb encrypted_drive
# Generar claves SSH
ssh-keygen -t rsa -b 4096
# Configurar autenticación con clave SSH
ssh-copy-id user@server
```

### Cifrado de Red

Asegurar las comunicaciones de red con cifrado.

```bash
# Configuración de VPN con OpenVPN
sudo apt install openvpn
sudo openvpn --config client.ovpn
```

### Gestión de Certificados

Administrar certificados digitales para comunicaciones seguras.

```bash
# Crear autoridad de certificación
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -key ca-key.pem -out ca.pem
# Generar certificado de servidor
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr
# Firmar certificado con CA
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -out server.pem
```

### Prevención de Pérdida de Datos

Prevenir la exfiltración y fuga no autorizada de datos.

```bash
# Monitorear acceso a archivos
sudo apt install auditd
# Configurar reglas de auditoría
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
# Buscar en registros de auditoría
sudo ausearch -k passwd_changes
```

## Automatización y Orquestación de Seguridad

Automatizar tareas de seguridad y procedimientos de respuesta.

### Automatización de Escaneo de Seguridad

Programar escaneos y evaluaciones de seguridad regulares.

```bash
# Script de escaneo Nmap automatizado
#!/bin/bash
DATE=$(date +%Y-%m-%d)
nmap -sS -O 192.168.1.0/24 > /var/log/nmap-scan-$DATE.log
# Programar con cron
# 0 2 * * * /path/to/security-scan.sh
```

```bash
# Escaneo de vulnerabilidades automatizado
#!/bin/bash
nikto -h $1 -o /var/log/nikto-$(date +%Y%m%d).txt
```

### Scripts de Monitoreo de Registros

Automatizar el análisis de registros y la alerta.

```bash
# Monitoreo de inicios de sesión fallidos
#!/bin/bash
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | tail -n 100 | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    echo "Se detectó un alto número de inicios de sesión fallidos: $FAILED_LOGINS" | mail -s "Alerta de Seguridad" admin@company.com
fi
```

### Automatización de Respuesta a Incidentes

Automatizar procedimientos iniciales de respuesta a incidentes.

```bash
# Script de respuesta a amenazas automatizada
#!/bin/bash
SUSPICIOUS_IP=$1
# Bloquear IP en el firewall
sudo ufw deny from $SUSPICIOUS_IP
# Registrar la acción
echo "$(date): IP sospechosa $SUSPICIOUS_IP bloqueada" >> /var/log/security-actions.log
# Enviar alerta
echo "IP sospechosa bloqueada: $SUSPICIOUS_IP" | mail -s "Bloqueo de IP" security@company.com
```

### Gestión de Configuración

Mantener configuraciones de sistema seguras.

```bash
# Ejemplo de playbook de Ansible
---
- name: Fortalecer configuración SSH
  hosts: all
  tasks:
    - name: Deshabilitar inicio de sesión de root
      lineinfile:
        path: /etc/ssh/sshd_config
        line: 'PermitRootLogin no'
    - name: Reiniciar servicio SSH
      service:
        name: sshd
        state: restarted
```

## Cumplimiento y Gestión de Riesgos

Implementar y mantener políticas y procedimientos de seguridad.

### Implementación de Políticas de Seguridad

Implementar y mantener políticas y procedimientos de seguridad.

```bash
# Aplicación de política de contraseñas (PAM)
sudo nano /etc/pam.d/common-password
# Añadir: password required pam_pwquality.so minlen=12
# Política de bloqueo de cuenta
sudo nano /etc/pam.d/common-auth
# Añadir: auth required pam_tally2.so deny=5 unlock_time=900
```

### Verificación de Auditoría y Cumplimiento

Verificar el cumplimiento de estándares y regulaciones de seguridad.

```bash
# Herramientas CIS (Center for Internet Security)
sudo apt install cis-cat-lite
# Ejecutar evaluación CIS
./CIS-CAT.sh -a -s
```

### Herramientas de Evaluación de Riesgos

Evaluar y cuantificar los riesgos de seguridad.

```bash
# Cálculo de matriz de riesgo:
# Riesgo = Probabilidad × Impacto
# Bajo (1-3), Medio (4-6), Alto (7-9)
# Priorización de vulnerabilidades
# Cálculo de puntuación CVSS
# Puntuación Base = Impacto × Explotabilidad
```

### Documentación e Informes

Mantener documentación e informes de seguridad adecuados.

```bash
# Plantilla de informe de incidente de seguridad:
# - Fecha y hora del incidente
# - Sistemas afectados
# - Vectores de ataque identificados
# - Datos comprometidos
# - Acciones tomadas
# - Lecciones aprendidas
# - Plan de remediación
```

## Instalación de Herramientas de Seguridad

Instalar y configurar herramientas esenciales de ciberseguridad.

### Gestores de Paquetes

Instalar herramientas utilizando gestores de paquetes del sistema.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap wireshark tcpdump
# CentOS/RHEL
sudo yum install nmap wireshark tcpdump
# Arch Linux
sudo pacman -S nmap wireshark-qt tcpdump
```

### Distribuciones de Seguridad

Distribuciones Linux especializadas para profesionales de la seguridad.

```bash
# Kali Linux - Pruebas de penetración
# Descargar desde: https://www.kali.org/
# Parrot Security OS
# Descargar desde: https://www.parrotsec.org/
# BlackArch Linux
# Descargar desde: https://blackarch.org/
```

### Verificación de Herramientas

Verificar la instalación y configuración básica de las herramientas.

```bash
# Comprobar versiones de herramientas
nmap --version
wireshark --version
# Prueba de funcionalidad básica
nmap 127.0.0.1
# Configurar rutas de herramientas
export PATH=$PATH:/opt/tools/bin
echo 'export PATH=$PATH:/opt/tools/bin' >> ~/.bashrc
```

## Mejores Prácticas de Configuración de Seguridad

Aplicar configuraciones de fortalecimiento de seguridad en sistemas y aplicaciones.

### Fortalecimiento del Sistema (System Hardening)

Asegurar las configuraciones del sistema operativo.

```bash
# Deshabilitar servicios innecesarios
sudo systemctl disable telnet
sudo systemctl disable ftp
# Establecer permisos de archivo seguros
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 644 /etc/passwd
# Configurar límites del sistema
echo "* hard core 0" >> /etc/security/limits.conf
```

### Configuraciones de Seguridad de Red

Implementar configuraciones de red seguras.

```bash
# Deshabilitar reenvío de IP (si no es un router)
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
# Habilitar cookies SYN
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
# Deshabilitar redirecciones ICMP
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
```

### Seguridad de Aplicaciones

Asegurar las configuraciones de aplicaciones y servicios.

```bash
# Encabezados de seguridad de Apache
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
# Configuración de seguridad de Nginx
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
```

### Seguridad de Copias de Seguridad y Recuperación

Implementar procedimientos seguros de copia de seguridad y recuperación ante desastres.

```bash
# Copias de seguridad cifradas con rsync
rsync -av --password-file=/etc/rsyncd.secrets /data/ backup@server::backups/
# Probar integridad de la copia de seguridad
tar -tzf backup.tar.gz > /dev/null && echo "Copia de seguridad OK"
# Verificación automatizada de copias de seguridad
#!/bin/bash
find /backups -name "*.tar.gz" -exec tar -tzf {} \; > /dev/null
```

## Técnicas Avanzadas de Seguridad

Implementar medidas y estrategias de defensa de seguridad avanzadas.

### Sistemas de Detección de Intrusiones

Desplegar y configurar IDS/IPS para la detección de amenazas.

```bash
# Instalar Suricata IDS
sudo apt install suricata
# Configurar reglas
sudo nano /etc/suricata/suricata.yaml
# Actualizar reglas
sudo suricata-update
# Iniciar Suricata
sudo systemctl start suricata
# Monitorear alertas
tail -f /var/log/suricata/fast.log
```

### Gestión de Información y Eventos de Seguridad (SIEM)

Centralizar y analizar registros de seguridad y eventos.

```bash
# Pila ELK (Elasticsearch, Logstash, Kibana)
# Instalar Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update && sudo apt install elasticsearch
```

## Concienciación y Formación en Seguridad

### Defensa contra Ingeniería Social

Reconocer y prevenir ataques de ingeniería social.

```bash
# Técnicas de identificación de phishing:
# - Revisar cuidadosamente el correo electrónico del remitente
# - Verificar enlaces antes de hacer clic (pasar el ratón por encima)
# - Buscar errores ortográficos/gramaticales
# - Ser sospechoso de solicitudes urgentes
# - Verificar solicitudes a través de un canal separado
# Encabezados de seguridad de correo electrónico a revisar:
# Registros SPF, DKIM, DMARC
```

### Desarrollo de Cultura de Seguridad

Construir una cultura organizacional consciente de la seguridad.

```bash
# Elementos del programa de concienciación de seguridad:
# - Sesiones de formación periódicas
# - Pruebas de simulación de phishing
# - Actualizaciones de políticas de seguridad
# - Procedimientos de notificación de incidentes
# - Reconocimiento de buenas prácticas de seguridad
# Métricas a seguir:
# - Tasas de finalización de la formación
# - Tasas de clics en simulaciones de phishing
# - Informes de incidentes de seguridad
```

## Enlaces Relevantes

- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/kali">Hoja de Trucos de Kali Linux</router-link>
- <router-link to="/nmap">Hoja de Trucos de Nmap</router-link>
- <router-link to="/wireshark">Hoja de Trucos de Wireshark</router-link>
- <router-link to="/hydra">Hoja de Trucos de Hydra</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/git">Hoja de Trucos de Git</router-link>

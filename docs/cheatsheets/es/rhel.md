---
title: 'Hoja de Trucos de Red Hat Enterprise Linux'
description: 'Aprenda Red Hat Enterprise Linux con nuestra hoja de trucos completa que cubre comandos esenciales, conceptos y mejores prácticas.'
pdfUrl: '/cheatsheets/pdf/red-hat-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Red Hat Enterprise Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/rhel">Aprenda Red Hat Enterprise Linux con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda Red Hat Enterprise Linux a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de RHEL que cubren administración esencial del sistema, gestión de paquetes, gestión de servicios, configuración de red, gestión de almacenamiento y seguridad. Domine las operaciones de Linux empresarial y las técnicas de administración de sistemas.
</base-disclaimer-content>
</base-disclaimer>

## Información del Sistema y Monitoreo

### Versión del Sistema: `cat /etc/redhat-release`

Muestra la versión y la información de lanzamiento de RHEL.

```bash
# Mostrar versión de RHEL
cat /etc/redhat-release
# Método alternativo
cat /etc/os-release
# Mostrar versión del kernel
uname -r
# Mostrar arquitectura del sistema
uname -m
```

### Rendimiento del Sistema: `top` / `htop`

Muestra los procesos en ejecución y el uso de recursos del sistema.

```bash
# Monitor de procesos en tiempo real
top
# Visor de procesos mejorado (si está instalado)
htop
# Mostrar árbol de procesos
pstree
# Mostrar todos los procesos
ps aux
```

### Información de Memoria: `free` / `cat /proc/meminfo`

Muestra el uso y la disponibilidad de la memoria.

```bash
# Mostrar uso de memoria en formato legible para humanos
free -h
# Mostrar información detallada de la memoria
cat /proc/meminfo
# Mostrar uso de swap
swapon --show
```

### Uso de Disco: `df` / `du`

Monitorea el uso del sistema de archivos y directorios.

```bash
# Mostrar uso del sistema de archivos
df -h
# Mostrar tamaños de directorios
du -sh /var/log/*
# Mostrar directorios más grandes
du -h --max-depth=1 / | sort -hr
```

### Tiempo de Actividad del Sistema: `uptime` / `who`

Verifica el tiempo de actividad del sistema y los usuarios conectados.

```bash
# Mostrar tiempo de actividad y carga del sistema
uptime
# Mostrar usuarios conectados
who
# Mostrar usuario actual
whoami
# Mostrar últimos inicios de sesión
last
```

### Información de Hardware: `lscpu` / `lsblk`

Muestra los componentes y la configuración del hardware.

```bash
# Mostrar información de la CPU
lscpu
# Mostrar dispositivos de bloque
lsblk
# Mostrar dispositivos PCI
lspci
# Mostrar dispositivos USB
lsusb
```

## Gestión de Paquetes

### Instalación de Paquetes: `dnf install` / `yum install`

Instala paquetes de software y dependencias.

```bash
# Instalar un paquete (RHEL 8+)
sudo dnf install package-name
# Instalar un paquete (RHEL 7)
sudo yum install package-name
# Instalar archivo RPM local
sudo rpm -i package.rpm
# Instalar desde un repositorio específico
sudo dnf install --enablerepo=repo-
name package
```

### Actualización de Paquetes: `dnf update` / `yum update`

Actualiza paquetes a las últimas versiones.

```bash
# Actualizar todos los paquetes
sudo dnf update
# Actualizar paquete específico
sudo dnf update package-name
# Verificar actualizaciones disponibles
dnf check-update
# Actualizar solo parches de seguridad
sudo dnf update --security
```

### Información de Paquetes: `dnf info` / `rpm -q`

Consulta información de paquetes y dependencias.

```bash
# Mostrar información del paquete
dnf info package-name
# Listar paquetes instalados
rpm -qa
# Buscar paquetes
dnf search keyword
# Mostrar dependencias del paquete
dnf deplist package-name
```

## Operaciones de Archivos y Directorios

### Navegación: `cd` / `pwd` / `ls`

Navega por el sistema de archivos y lista el contenido.

```bash
# Cambiar directorio
cd /path/to/directory
# Mostrar directorio actual
pwd
# Listar archivos y directorios
ls -la
# Listar con tamaños de archivo
ls -lh
# Mostrar archivos ocultos
ls -a
```

### Operaciones de Archivos: `cp` / `mv` / `rm`

Copia, mueve y elimina archivos y directorios.

```bash
# Copiar archivo
cp source.txt destination.txt
# Copiar directorio recursivamente
cp -r /source/dir/ /dest/dir/
# Mover/renombrar archivo
mv oldname.txt newname.txt
# Eliminar archivo
rm filename.txt
# Eliminar directorio recursivamente
rm -rf directory/
```

### Contenido de Archivos: `cat` / `less` / `head` / `tail`

Ver y examinar el contenido de los archivos.

```bash
# Mostrar contenido del archivo
cat filename.txt
# Ver archivo página por página
less filename.txt
# Mostrar las primeras 10 líneas
head filename.txt
# Mostrar las últimas 10 líneas
tail filename.txt
# Seguir archivo de registro en tiempo real
tail -f /var/log/messages
```

### Permisos de Archivos: `chmod` / `chown` / `chgrp`

Administra permisos y propiedad de archivos.

```bash
# Cambiar permisos de archivo
chmod 755 script.sh
# Cambiar propiedad del archivo
sudo chown user:group filename.txt
# Cambiar propiedad del grupo
sudo chgrp newgroup filename.txt
# Cambio de permisos recursivo
sudo chmod -R 644 /path/to/directory/
```

### Búsqueda de Archivos: `find` / `locate` / `grep`

Busca archivos y contenido dentro de archivos.

```bash
# Encontrar archivos por nombre
find /path -name "*.txt"
# Encontrar archivos por tamaño
find /path -size +100M
# Buscar texto en archivos
grep "pattern" filename.txt
# Búsqueda de texto recursiva
grep -r "pattern" /path/to/directory/
```

### Archivo y Compresión: `tar` / `gzip`

Crea y extrae archivos comprimidos.

```bash
# Crear archivo tar
tar -czf archive.tar.gz /path/to/directory/
# Extraer archivo tar
tar -xzf archive.tar.gz
# Crear archivo zip
zip -r archive.zip /path/to/directory/
# Extraer archivo zip
unzip archive.zip
```

## Gestión de Servicios

### Control de Servicios: `systemctl`

Administra servicios del sistema usando systemd.

```bash
# Iniciar un servicio
sudo systemctl start service-name
# Detener un servicio
sudo systemctl stop service-name
# Reiniciar un servicio
sudo systemctl restart service-name
# Verificar estado del servicio
systemctl status service-name
# Habilitar servicio al inicio
sudo systemctl enable service-name
# Deshabilitar servicio al inicio
sudo systemctl disable service-name
```

### Información de Servicios: `systemctl list-units`

Lista y consulta servicios del sistema.

```bash
# Listar todos los servicios activos
systemctl list-units --type=service
# Listar todos los servicios habilitados
systemctl list-unit-files --type=service --state=enabled
# Mostrar dependencias del servicio
systemctl list-dependencies service-name
```

### Registros del Sistema: `journalctl`

Visualiza y analiza los registros del sistema usando journald.

```bash
# Ver todos los registros
journalctl
# Ver registros para un servicio específico
journalctl -u service-name
# Seguir registros en tiempo real
journalctl -f
# Ver registros del último arranque
journalctl -b
# Ver registros por rango de tiempo
journalctl --since "2024-01-01" --until "2024-01-31"
```

### Gestión de Procesos: `ps` / `kill` / `killall`

Monitorea y controla procesos en ejecución.

```bash
# Mostrar procesos en ejecución
ps aux
# Matar proceso por PID
kill 1234
# Matar proceso por nombre
killall process-name
# Matar proceso forzosamente
kill -9 1234
# Mostrar jerarquía de procesos
pstree
```

## Gestión de Usuarios y Grupos

### Gestión de Usuarios: `useradd` / `usermod` / `userdel`

Crea, modifica y elimina cuentas de usuario.

```bash
# Añadir nuevo usuario
sudo useradd -m username
# Establecer contraseña de usuario
sudo passwd username
# Modificar cuenta de usuario
sudo usermod -aG groupname
username
# Eliminar cuenta de usuario
sudo userdel -r username
# Bloquear cuenta de usuario
sudo usermod -L username
```

### Gestión de Grupos: `groupadd` / `groupmod` / `groupdel`

Crea, modifica y elimina grupos.

```bash
# Añadir nuevo grupo
sudo groupadd groupname
# Añadir usuario a grupo
sudo usermod -aG groupname
username
# Eliminar usuario de grupo
sudo gpasswd -d username
groupname
# Eliminar grupo
sudo groupdel groupname
# Listar grupos de usuario
groups username
```

### Control de Acceso: `su` / `sudo`

Cambia de usuario y ejecuta comandos con privilegios elevados.

```bash
# Cambiar a usuario root
su -
# Cambiar a usuario específico
su - username
# Ejecutar comando como root
sudo command
# Editar archivo sudoers
sudo visudo
# Verificar permisos de sudo
sudo -l
```

## Configuración de Red

### Información de Red: `ip` / `nmcli`

Muestra detalles de la interfaz y configuración de red.

```bash
# Mostrar interfaces de red
ip addr show
# Mostrar tabla de enrutamiento
ip route show
# Mostrar conexiones del administrador de red
nmcli connection show
# Mostrar estado del dispositivo
nmcli device status
```

### Configuración de Red: `nmtui` / `nmcli`

Configura ajustes de red usando NetworkManager.

```bash
# Configuración de red basada en texto
sudo nmtui
# Añadir nueva conexión
sudo nmcli connection add type ethernet con-name
"eth0" ifname eth0
# Modificar conexión
sudo nmcli connection modify "eth0" ipv4.addresses
192.168.1.100/24
# Activar conexión
sudo nmcli connection up "eth0"
```

### Pruebas de Red: `ping` / `curl` / `wget`

Prueba la conectividad de red y descarga archivos.

```bash
# Probar conectividad
ping google.com
# Probar puerto específico
telnet hostname 80
# Descargar archivo
wget http://example.com/file.txt
# Probar peticiones HTTP
curl -I http://example.com
```

### Gestión de Firewall: `firewall-cmd`

Configura reglas de firewall usando firewalld.

```bash
# Mostrar estado del firewall
sudo firewall-cmd --state
# Listar zonas activas
sudo firewall-cmd --get-active-zones
# Añadir servicio al firewall
sudo firewall-cmd --permanent --add-service=http
# Recargar reglas del firewall
sudo firewall-cmd --reload
```

## Gestión de Almacenamiento

### Gestión de Discos: `fdisk` / `parted`

Crea y administra particiones de disco.

```bash
# Listar particiones de disco
sudo fdisk -l
# Editor de particiones interactivo
sudo fdisk /dev/sda
# Crear tabla de particiones
sudo parted /dev/sda mklabel gpt
# Crear nueva partición
sudo parted /dev/sda mkpart primary ext4 1MiB 100GiB
```

### Gestión de Sistemas de Archivos: `mkfs` / `mount`

Crea sistemas de archivos y monta dispositivos de almacenamiento.

```bash
# Crear sistema de archivos ext4
sudo mkfs.ext4 /dev/sda1
# Montar sistema de archivos
sudo mount /dev/sda1 /mnt/data
# Desmontar sistema de archivos
sudo umount /mnt/data
# Comprobar sistema de archivos
sudo fsck /dev/sda1
```

### Gestión de LVM: `pvcreate` / `vgcreate` / `lvcreate`

Administra el Almacenamiento de Volumen Lógico (LVM).

```bash
# Crear volumen físico
sudo pvcreate /dev/sdb
# Crear grupo de volúmenes
sudo vgcreate vg_data /dev/sdb
# Crear volumen lógico
sudo lvcreate -L 10G -n lv_data vg_data
# Extender volumen lógico
sudo lvextend -L +5G /dev/vg_data/lv_data
```

### Configuración de Montaje: `/etc/fstab`

Configura puntos de montaje permanentes.

```bash
# Editar archivo fstab
sudo vi /etc/fstab
# Probar entradas de fstab
sudo mount -a
# Mostrar sistemas de archivos montados
mount | column -t
```

## Seguridad y SELinux

### Gestión de SELinux: `getenforce` / `setenforce`

Controla la aplicación y las políticas de SELinux.

```bash
# Verificar estado de SELinux
getenforce
# Establecer SELinux en permisivo
sudo setenforce 0
# Establecer SELinux en forzando
sudo setenforce 1
# Verificar contexto SELinux
ls -Z filename
# Cambiar contexto SELinux
sudo chcon -t httpd_exec_t /path/to/file
```

### Herramientas SELinux: `sealert` / `ausearch`

Analiza denegaciones de SELinux y registros de auditoría.

```bash
# Revisar alertas de SELinux
sudo sealert -a /var/log/audit/audit.log
# Buscar en registros de auditoría
sudo ausearch -m avc -ts recent
# Generar política SELinux
sudo audit2allow -M mypolicy < /var/log/audit/audit.log
```

### Configuración SSH: `/etc/ssh/sshd_config`

Configura el demonio SSH para acceso remoto seguro.

```bash
# Editar configuración SSH
sudo vi /etc/ssh/sshd_config
# Reiniciar servicio SSH
sudo systemctl restart sshd
# Probar conexión SSH
ssh user@hostname
# Copiar clave SSH
ssh-copy-id user@hostname
```

### Actualizaciones del Sistema: `dnf update`

Mantén el sistema seguro con actualizaciones regulares.

```bash
# Actualizar todos los paquetes
sudo dnf update
# Actualizar solo parches de seguridad
sudo dnf update --security
# Verificar actualizaciones disponibles
dnf check-update --security
# Habilitar actualizaciones automáticas
sudo systemctl enable dnf-automatic.timer
```

## Monitoreo de Rendimiento

### Monitoreo del Sistema: `iostat` / `vmstat`

Monitorea el rendimiento del sistema y el uso de recursos.

```bash
# Mostrar estadísticas de I/O
iostat -x 1
# Mostrar estadísticas de memoria virtual
vmstat 1
# Mostrar estadísticas de red
ss -tuln
# Mostrar I/O de disco
iotop
```

### Uso de Recursos: `sar` / `top`

Analiza métricas históricas y en tiempo real del sistema.

```bash
# Informe de actividad del sistema
sar -u 1 3
# Informe de uso de memoria
sar -r
# Informe de actividad de red
sar -n DEV
# Monitoreo del promedio de carga
uptime
```

### Análisis de Procesos: `strace` / `lsof`

Depura procesos y acceso a archivos.

```bash
# Rastrear llamadas al sistema
strace -p 1234
# Listar archivos abiertos
lsof
# Mostrar archivos abiertos por proceso
lsof -p 1234
# Mostrar conexiones de red
lsof -i
```

### Ajuste de Rendimiento: `tuned`

Optimiza el rendimiento del sistema para cargas de trabajo específicas.

```bash
# Listar perfiles disponibles
tuned-adm list
# Mostrar perfil activo
tuned-adm active
# Establecer perfil de rendimiento
sudo tuned-adm profile throughput-performance
# Crear perfil personalizado
sudo tuned-adm profile_mode
```

## Instalación y Configuración de RHEL

### Registro del Sistema: `subscription-manager`

Registra el sistema con el Portal del Cliente de Red Hat.

```bash
# Registrar sistema
sudo subscription-manager
register --username
your_username
# Adjuntar suscripciones automáticamente
sudo subscription-manager
attach --auto
# Listar suscripciones disponibles
subscription-manager list --
available
# Mostrar estado del sistema
subscription-manager status
```

### Gestión de Repositorios: `dnf config-manager`

Administra repositorios de software.

```bash
# Listar repositorios habilitados
dnf repolist
# Habilitar repositorio
sudo dnf config-manager --
enable repository-name
# Deshabilitar repositorio
sudo dnf config-manager --
disable repository-name
# Añadir nuevo repositorio
sudo dnf config-manager --add-
repo https://example.com/repo
```

### Configuración del Sistema: `hostnamectl` / `timedatectl`

Configura ajustes básicos del sistema.

```bash
# Establecer nombre de host
sudo hostnamectl set-hostname
new-hostname
# Mostrar información del sistema
hostnamectl
# Establecer zona horaria
sudo timedatectl set-timezone
America/New_York
# Mostrar configuración de hora
timedatectl
```

## Solución de Problemas y Diagnóstico

### Registros del Sistema: `/var/log/`

Examina archivos de registro del sistema en busca de problemas.

```bash
# Ver mensajes del sistema
sudo tail -f /var/log/messages
# Ver registros de autenticación
sudo tail -f /var/log/secure
# Ver registros de arranque
sudo journalctl -b
# Ver mensajes del kernel
dmesg | tail
```

### Diagnóstico de Hardware: `dmidecode` / `lshw`

Examina la información y el estado de la salud del hardware.

```bash
# Mostrar información de hardware
sudo dmidecode -t system
# Listar componentes de hardware
sudo lshw -short
# Verificar información de memoria
sudo dmidecode -t memory
# Mostrar información de la CPU
lscpu
```

### Solución de Problemas de Red: `netstat` / `ss`

Herramientas y utilidades de diagnóstico de red.

```bash
# Mostrar conexiones de red
ss -tuln
# Mostrar tabla de enrutamiento
ip route show
# Probar resolución DNS
nslookup google.com
# Rastrear ruta de red
traceroute google.com
```

### Recuperación y Rescate: `systemctl rescue`

Procedimientos de recuperación y emergencia del sistema.

```bash
# Entrar en modo rescate
sudo systemctl rescue
# Entrar en modo de emergencia
sudo systemctl emergency
# Restablecer servicios fallidos
sudo systemctl reset-failed
# Reconfigurar cargador de arranque
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

## Automatización y Scripting

### Tareas Cron: `crontab`

Programa tareas automatizadas y de mantenimiento.

```bash
# Editar crontab del usuario
crontab -e
# Listar crontab del usuario
crontab -l
# Eliminar crontab del usuario
crontab -r
# Ejemplo: Ejecutar script diariamente a las 2 AM
0 2 * * * /path/to/script.sh
```

### Scripting de Shell: `bash`

Crea y ejecuta scripts de shell para automatización.

```bash
#!/bin/bash
# Script simple de respaldo
DATE=$(date +%Y%m%d)
tar -czf backup_$DATE.tar.gz /home/user/documents
echo "Respaldo completado: backup_$DATE.tar.gz"
```

### Variables de Entorno: `export` / `env`

Administra variables de entorno y configuraciones de shell.

```bash
# Establecer variable de entorno
export MY_VAR="value"
# Mostrar todas las variables de entorno
env
# Mostrar variable específica
echo $PATH
# Añadir a PATH
export PATH=$PATH:/new/directory
```

### Automatización del Sistema: `systemd timers`

Crea tareas programadas basadas en systemd.

```bash
# Crear archivo de unidad timer
sudo vi /etc/systemd/system/backup.timer
# Habilitar e iniciar temporizador
sudo systemctl enable backup.timer
sudo systemctl start backup.timer
# Listar temporizadores activos
systemctl list-timers
```

## Enlaces Relevantes

- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/git">Hoja de Trucos de Git</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>
- <router-link to="/kubernetes">Hoja de Trucos de Kubernetes</router-link>
- <router-link to="/ansible">Hoja de Trucos de Ansible</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/cybersecurity">Hoja de Trucos de Ciberseguridad</router-link>

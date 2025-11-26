---
title: 'Hoja de Trucos de Linux'
description: 'Aprenda Linux con nuestra hoja de trucos completa que cubre comandos esenciales, conceptos y mejores prácticas.'
pdfUrl: '/cheatsheets/pdf/linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Linux
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a href="https://linux-commands.labex.io/" target="_blank">Visitar Comandos de Linux</a>
</base-disclaimer-title>
<base-disclaimer-content>
Para materiales de referencia completos de comandos de Linux, ejemplos de sintaxis y documentación detallada, visite <a href="https://linux-commands.labex.io/" target="_blank">linux-commands.labex.io</a>. Este sitio independiente proporciona hojas de trucos extensas de Linux que cubren comandos esenciales, conceptos y mejores prácticas para administradores y desarrolladores de Linux.
</base-disclaimer-content>
</base-disclaimer>

## Información y Estado del Sistema

### Información del Sistema: `uname`

Muestra información del sistema incluyendo el kernel y la arquitectura.

```bash
# Mostrar nombre del kernel
uname
# Mostrar toda la información del sistema
uname -a
# Mostrar versión del kernel
uname -r
# Mostrar arquitectura
uname -m
# Mostrar sistema operativo
uname -o
```

### Información de Hardware: `lscpu`, `lsblk`

Ver especificaciones detalladas de hardware y dispositivos de bloque.

```bash
# Información de la CPU
lscpu
# Dispositivos de bloque (discos, particiones)
lsblk
# Información de memoria
free -h
# Uso de disco por sistema de archivos
df -h
```

### Tiempo de Actividad del Sistema: `uptime`

Muestra el tiempo de actividad del sistema y los promedios de carga.

```bash
# Tiempo de actividad y carga del sistema
uptime
# Información de tiempo de actividad más detallada
uptime -p
# Mostrar tiempo de actividad desde una fecha específica
uptime -s
```

### Usuarios Actuales: `who`, `w`

Muestra los usuarios actualmente conectados y sus actividades.

```bash
# Mostrar usuarios conectados
who
# Información detallada del usuario con actividades
w
# Mostrar nombre de usuario actual
whoami
# Mostrar historial de inicio de sesión
last
```

### Variables de Entorno: `env`

Muestra y gestiona variables de entorno.

```bash
# Mostrar todas las variables de entorno
env
# Mostrar variable específica
echo $HOME
# Establecer variable de entorno
export PATH=$PATH:/new/path
# Mostrar variable PATH
echo $PATH
```

### Fecha y Hora: `date`, `timedatectl`

Muestra y establece la fecha y hora del sistema.

```bash
# Fecha y hora actuales
date
# Establecer hora del sistema (como root)
date MMddhhmmyyyy
# Información de zona horaria
timedatectl
# Establecer zona horaria
timedatectl set-timezone America/New_York
```

## Operaciones de Archivos y Directorios

### Listar Archivos: `ls`

Muestra archivos y directorios con varias opciones de formato.

```bash
# Listar archivos en el directorio actual
ls
# Listado detallado con permisos
ls -l
# Mostrar archivos ocultos
ls -la
# Tamaños de archivo legibles por humanos
ls -lh
# Ordenar por tiempo de modificación
ls -lt
```

### Navegar Directorios: `cd`, `pwd`

Cambiar directorios y mostrar la ubicación actual.

```bash
# Ir al directorio de inicio
cd
# Ir a un directorio específico
cd /path/to/directory
# Subir un nivel
cd ..
# Mostrar directorio actual
pwd
# Ir al directorio anterior
cd -
```

### Crear y Eliminar: `mkdir`, `rmdir`, `rm`

Crear y eliminar archivos y directorios.

```bash
# Crear directorio
mkdir newdir
# Crear directorios anidados
mkdir -p path/to/nested/dir
# Eliminar directorio vacío
rmdir dirname
# Eliminar archivo
rm filename
# Eliminar directorio recursivamente
rm -rf dirname
```

### Ver Contenido de Archivos: `cat`, `less`, `head`, `tail`

Muestra el contenido de archivos usando varios métodos y paginación.

```bash
# Mostrar archivo completo
cat filename
# Ver archivo con paginación
less filename
# Mostrar las primeras 10 líneas
head filename
# Mostrar las últimas 10 líneas
tail filename
# Seguir cambios en el archivo en tiempo real
tail -f logfile
```

### Copiar y Mover: `cp`, `mv`

Copiar y mover archivos y directorios.

```bash
# Copiar archivo
cp source.txt destination.txt
# Copiar directorio recursivamente
cp -r sourcedir/ destdir/
# Mover/renombrar archivo
mv oldname.txt newname.txt
# Mover a un directorio diferente
mv file.txt /path/to/destination/
# Copiar preservando atributos
cp -p file.txt backup.txt
```

### Encontrar Archivos: `find`, `locate`

Buscar archivos y directorios por nombre, tipo o propiedades.

```bash
# Encontrar por nombre
find /path -name "filename"
# Encontrar archivos modificados en los últimos 7 días
find /path -mtime -7
# Encontrar por tipo de archivo
find /path -type f -name "*.txt"
# Localizar archivos rápidamente (requiere updatedb)
locate filename
# Encontrar y ejecutar comando
find /path -name "*.log" -exec rm {} \;
```

### Permisos de Archivo: `chmod`, `chown`

Modificar permisos y propiedad de archivos.

```bash
# Cambiar permisos (numérico)
chmod 755 filename
# Añadir permiso de ejecución
chmod +x script.sh
# Cambiar propiedad
chown user:group filename
# Cambiar propiedad recursivamente
chown -R user:group directory/
# Ver permisos de archivo
ls -l filename
```

## Gestión de Procesos

### Listado de Procesos: `ps`

Muestra los procesos en ejecución y sus detalles.

```bash
# Mostrar procesos del usuario
ps
# Mostrar todos los procesos con detalles
ps aux
# Mostrar árbol de procesos
ps -ef --forest
# Mostrar procesos por usuario
ps -u username
```

### Matar Procesos: `kill`, `killall`

Terminar procesos por PID o nombre.

```bash
# Monitor de procesos en tiempo real
top
# Matar proceso por PID
kill 1234
# Matar proceso forzadamente
kill -9 1234
# Matar por nombre de proceso
killall processname
# Listar todas las señales
kill -l
# Enviar señal específica
kill -HUP 1234
```

### Trabajos en Segundo Plano: `jobs`, `bg`, `fg`

Gestionar procesos en segundo plano y en primer plano.

```bash
# Listar trabajos activos
jobs
# Enviar trabajo al segundo plano
bg %1
# Traer trabajo al primer plano
fg %1
# Ejecutar comando en segundo plano
command &
# Desvincularse de la terminal
nohup command &
```

### Monitor del Sistema: `htop`, `systemctl`

Monitorear recursos del sistema y gestionar servicios.

```bash
# Visor de procesos mejorado (si está instalado)
htop
# Verificar estado del servicio
systemctl status servicename
# Iniciar servicio
systemctl start servicename
# Habilitar servicio al arranque
systemctl enable servicename
# Ver registros del sistema
journalctl -f
```

## Operaciones de Red

### Configuración de Red: `ip`, `ifconfig`

Mostrar y configurar interfaces de red.

```bash
# Mostrar interfaces de red
ip addr show
# Mostrar tabla de enrutamiento
ip route show
# Configurar interfaz (temporal)
ip addr add 192.168.1.10/24 dev eth0
# Levantar/bajar interfaz
ip link set eth0 up
# Configuración de interfaz heredada
ifconfig
```

### Pruebas de Red: `ping`, `traceroute`

Probar conectividad de red y trazar rutas de paquetes.

```bash
# Probar conectividad
ping google.com
# Ping con límite de conteo
ping -c 4 192.168.1.1
# Trazar ruta al destino
traceroute google.com
# MTR - herramienta de diagnóstico de red
mtr google.com
```

### Análisis de Puertos y Conexiones: `netstat`, `ss`

Mostrar conexiones de red y puertos en escucha.

```bash
# Mostrar todas las conexiones
netstat -tuln
# Mostrar puertos en escucha
netstat -tuln | grep LISTEN
# Reemplazo moderno de netstat
ss -tuln
# Mostrar procesos que usan puertos
netstat -tulnp
# Verificar puerto específico
netstat -tuln | grep :80
```

### Transferencia de Archivos: `scp`, `rsync`

Transferir archivos de forma segura entre sistemas.

```bash
# Copiar archivo a host remoto
scp file.txt user@host:/path/
# Copiar desde host remoto
scp user@host:/path/file.txt ./
# Sincronizar directorios
rsync -avz localdir/ user@host:/remotedir/
# Rsync con progreso
rsync -avz --progress src/ dest/
```

## Procesamiento y Búsqueda de Texto

### Búsqueda de Texto: `grep`

Buscar patrones en archivos y salida de comandos.

```bash
# Buscar patrón en archivo
grep "pattern" filename
# Búsqueda insensible a mayúsculas y minúsculas
grep -i "pattern" filename
# Búsqueda recursiva en directorios
grep -r "pattern" /path/
# Mostrar números de línea
grep -n "pattern" filename
# Contar líneas coincidentes
grep -c "pattern" filename
```

### Manipulación de Texto: `sed`, `awk`

Editar y procesar texto usando editores de flujo y analizadores de patrones.

```bash
# Reemplazar texto en archivo
sed 's/old/new/g' filename
# Eliminar líneas que contienen patrón
sed '/pattern/d' filename
# Imprimir campos específicos
awk '{print $1, $3}' filename
# Sumar valores en columna
awk '{sum += $1} END {print sum}' filename
```

### Ordenar y Contar: `sort`, `uniq`, `wc`

Ordenar datos, eliminar duplicados y contar líneas, palabras o caracteres.

```bash
# Ordenar contenido de archivo
sort filename
# Ordenar numéricamente
sort -n numbers.txt
# Eliminar líneas duplicadas
uniq filename
# Ordenar y eliminar duplicados
sort filename | uniq
# Contar líneas, palabras, caracteres
wc filename
# Contar solo líneas
wc -l filename
```

### Cortar y Pegar: `cut`, `paste`

Extraer columnas específicas y combinar archivos.

```bash
# Extraer primera columna
cut -d',' -f1 file.csv
# Extraer rango de caracteres
cut -c1-10 filename
# Combinar archivos lado a lado
paste file1.txt file2.txt
# Usar delimitador personalizado
cut -d':' -f1,3 /etc/passwd
```

## Archivo y Compresión

### Crear Archivos: `tar`

Crear y extraer archivos comprimidos.

```bash
# Crear archivo tar
tar -cf archive.tar files/
# Crear archivo comprimido
tar -czf archive.tar.gz files/
# Extraer archivo
tar -xf archive.tar
# Extraer archivo comprimido
tar -xzf archive.tar.gz
# Listar contenido del archivo
tar -tf archive.tar
```

### Compresión: `gzip`, `zip`

Comprimir y descomprimir archivos usando varios algoritmos.

```bash
# Comprimir archivo con gzip
gzip filename
# Descomprimir archivo gzip
gunzip filename.gz
# Crear archivo zip
zip archive.zip file1 file2
# Extraer archivo zip
unzip archive.zip
# Listar contenido de zip
unzip -l archive.zip
```

### Archivos Avanzados: Opciones de `tar`

Operaciones avanzadas de tar para copias de seguridad y restauración.

```bash
# Crear archivo con compresión
tar -czvf backup.tar.gz /home/user/
# Extraer a un directorio específico
tar -xzf archive.tar.gz -C /destination/
# Añadir archivos a archivo existente
tar -rf archive.tar newfile.txt
# Actualizar archivo con archivos más nuevos
tar -uf archive.tar files/
```

### Espacio en Disco: `du`

Analizar el uso del espacio en disco y los tamaños de directorios.

```bash
# Mostrar tamaños de directorio
du -h /path/
# Resumen del tamaño total
du -sh /path/
# Mostrar tamaños de todos los subdirectorios
du -h --max-depth=1 /path/
# Directorios más grandes primero
du -h | sort -hr | head -10
```

## Monitoreo y Rendimiento del Sistema

### Uso de Memoria: `free`, `vmstat`

Monitorear el uso de memoria y las estadísticas de memoria virtual.

```bash
# Resumen del uso de memoria
free -h
# Estadísticas detalladas de memoria
cat /proc/meminfo
# Estadísticas de memoria virtual
vmstat
# Uso de memoria cada 2 segundos
vmstat 2
# Mostrar uso de swap
swapon --show
```

### E/S de Disco: `iostat`, `iotop`

Monitorear el rendimiento de entrada/salida del disco e identificar cuellos de botella.

```bash
# Estadísticas de E/S (requiere sysstat)
iostat
# Estadísticas de E/S cada 2 segundos
iostat 2
# Monitorear E/S de disco por proceso
iotop
# Mostrar uso de E/S para dispositivo específico
iostat -x /dev/sda
```

### Carga del Sistema: `top`, `htop`

Monitorear la carga del sistema, el uso de CPU y los procesos en ejecución.

```bash
# Monitor de procesos en tiempo real
top
# Visor de procesos mejorado
htop
# Mostrar promedios de carga
uptime
# Mostrar información de la CPU
lscpu
# Monitorear proceso específico
top -p PID
```

### Archivos de Registro: `journalctl`, `dmesg`

Ver y analizar registros del sistema para solución de problemas.

```bash
# Ver registros del sistema
journalctl
# Seguir registros en tiempo real
journalctl -f
# Mostrar registros para servicio específico
journalctl -u servicename
# Mensajes del kernel
dmesg
# Mensajes del último arranque
dmesg | tail
```

## Gestión de Usuarios y Permisos

### Operaciones de Usuario: `useradd`, `usermod`, `userdel`

Crear, modificar y eliminar cuentas de usuario.

```bash
# Añadir nuevo usuario
useradd username
# Añadir usuario con directorio de inicio
useradd -m username
# Modificar cuenta de usuario
usermod -aG groupname username
# Eliminar cuenta de usuario
userdel username
# Eliminar usuario con directorio de inicio
userdel -r username
```

### Gestión de Grupos: `groupadd`, `groups`

Crear y gestionar grupos de usuarios.

```bash
# Crear nuevo grupo
groupadd groupname
# Mostrar grupos del usuario
groups username
# Mostrar todos los grupos
cat /etc/group
# Añadir usuario a grupo
usermod -aG groupname username
# Cambiar grupo primario del usuario
usermod -g groupname username
```

### Cambiar de Usuario: `su`, `sudo`

Cambiar de usuario y ejecutar comandos con privilegios elevados.

```bash
# Cambiar a usuario root
su -
# Cambiar a usuario específico
su - username
# Ejecutar comando como root
sudo command
# Ejecutar comando como usuario específico
sudo -u username command
# Editar archivo sudoers
visudo
```

### Gestión de Contraseñas: `passwd`, `chage`

Gestionar contraseñas de usuario y políticas de cuenta.

```bash
# Cambiar contraseña
passwd
# Cambiar contraseña de otro usuario (como root)
passwd username
# Mostrar información de caducidad de contraseña
chage -l username
# Establecer caducidad de contraseña
chage -M 90 username
# Forzar cambio de contraseña al próximo inicio de sesión
passwd -e username
```

## Gestión de Paquetes

### APT (Debian/Ubuntu): `apt`, `apt-get`

Gestionar paquetes en sistemas basados en Debian.

```bash
# Actualizar lista de paquetes
apt update
# Actualizar todos los paquetes
apt upgrade
# Instalar paquete
apt install packagename
# Eliminar paquete
apt remove packagename
# Buscar paquetes
apt search packagename
# Mostrar información del paquete
apt show packagename
```

### YUM/DNF (RHEL/Fedora): `yum`, `dnf`

Gestionar paquetes en sistemas basados en Red Hat.

```bash
# Instalar paquete
yum install packagename
# Actualizar todos los paquetes
yum update
# Eliminar paquete
yum remove packagename
# Buscar paquetes
yum search packagename
# Listar paquetes instalados
yum list installed
```

### Paquetes Snap: `snap`

Instalar y gestionar paquetes snap en varias distribuciones.

```bash
# Instalar paquete snap
snap install packagename
# Listar snaps instalados
snap list
# Actualizar paquetes snap
snap refresh
# Eliminar paquete snap
snap remove packagename
# Buscar paquetes snap
snap find packagename
```

### Paquetes Flatpak: `flatpak`

Gestionar aplicaciones Flatpak para software en contenedores (sandboxed).

```bash
# Instalar flatpak
flatpak install packagename
# Listar flatpaks instalados
flatpak list
# Actualizar paquetes flatpak
flatpak update
# Desinstalar flatpak
flatpak uninstall packagename
# Buscar paquetes flatpak
flatpak search packagename
```

## Shell y Scripting

### Historial de Comandos: `history`

Acceder y gestionar el historial de la línea de comandos.

```bash
# Mostrar historial de comandos
history
# Mostrar los últimos 10 comandos
history 10
# Ejecutar comando anterior
!!
# Ejecutar comando por número
!123
# Buscar historial interactivamente
Ctrl+R
```

### Alias y Funciones: `alias`

Crear atajos para comandos usados frecuentemente.

```bash
# Crear alias
alias ll='ls -la'
# Mostrar todos los alias
alias
# Eliminar alias
unalias ll
# Hacer alias permanente (añadir a .bashrc)
echo "alias ll='ls -la'" >> ~/.bashrc
```

### Redirección de Entrada/Salida

Redirigir la entrada y salida de comandos a archivos u otros comandos.

```bash
# Redirigir salida a archivo
command > output.txt
# Añadir salida a archivo
command >> output.txt
# Redirigir entrada desde archivo
command < input.txt
# Redirigir stdout y stderr
command &> output.txt
# Enviar salida a otro comando
command1 | command2
```

### Configuración del Entorno: `.bashrc`, `.profile`

Configurar el entorno del shell y los scripts de inicio.

```bash
# Editar configuración de bash
nano ~/.bashrc
# Recargar configuración
source ~/.bashrc
# Establecer variable de entorno
export VARIABLE=value
# Añadir a PATH
export PATH=$PATH:/new/path
# Mostrar variables de entorno
printenv
```

## Instalación y Configuración del Sistema

### Opciones de Distribución: Ubuntu, CentOS, Debian

Elegir e instalar distribuciones de Linux para diferentes casos de uso.

```bash
# Ubuntu Server
wget ubuntu-server.iso
# CentOS Stream
wget centos-stream.iso
# Debian Stable
wget debian.iso
# Verificar integridad de ISO
sha256sum linux.iso
```

### Arranque e Instalación: USB, Red

Crear medios de arranque e instalar el sistema.

```bash
# Crear USB de arranque (Linux)
dd if=linux.iso of=/dev/sdX bs=4M
# Crear USB de arranque (multiplataforma)
# Usar herramientas como Rufus, Etcher o UNetbootin
# Instalación en red
# Configurar arranque PXE para instalaciones en red
```

### Configuración Inicial: Usuarios, Red, SSH

Configurar la configuración básica del sistema después de la instalación.

```bash
# Establecer nombre de host
hostnamectl set-hostname newname
# Configurar IP estática
# Editar /etc/netplan/ (Ubuntu) o /etc/network/interfaces
# Habilitar servicio SSH
systemctl enable ssh
systemctl start ssh
# Configurar firewall
ufw enable
ufw allow ssh
```

## Seguridad y Mejores Prácticas

### Configuración del Firewall: `ufw`, `iptables`

Configurar reglas de firewall para proteger el sistema de amenazas de red.

```bash
# Habilitar firewall UFW
ufw enable
# Permitir puerto específico
ufw allow 22/tcp
# Permitir servicio por nombre
ufw allow ssh
# Denegar acceso
ufw deny 23
# Mostrar estado del firewall
ufw status verbose
# Reglas avanzadas con iptables
iptables -L
```

### Integridad de Archivos: `checksums`

Verificar la integridad de los archivos y detectar cambios no autorizados.

```bash
# Generar checksum MD5
md5sum filename
# Generar checksum SHA256
sha256sum filename
# Verificar checksum
sha256sum -c checksums.txt
# Crear archivo de checksum
sha256sum *.txt > checksums.txt
```

### Actualizaciones del Sistema: Parches de Seguridad

Mantener el sistema seguro con actualizaciones y parches de seguridad regulares.

```bash
# Actualizaciones de seguridad de Ubuntu
apt update && apt upgrade
# Actualizaciones de seguridad automáticas
unattended-upgrades
# Actualizaciones de CentOS/RHEL
yum update --security
# Listar actualizaciones disponibles
apt list --upgradable
```

### Monitoreo de Registros: Eventos de Seguridad

Monitorear los registros del sistema para eventos de seguridad y anomalías.

```bash
# Monitorear registros de autenticación
tail -f /var/log/auth.log
# Revisar intentos de inicio de sesión fallidos
grep "Failed password" /var/log/auth.log
# Monitorear registros del sistema
tail -f /var/log/syslog
# Ver historial de inicio de sesión
last
# Revisar actividades sospechosas
journalctl -p err
```

## Solución de Problemas y Recuperación

### Problemas de Arranque: Recuperación de GRUB

Recuperarse de problemas con el gestor de arranque y el kernel.

```bash
# Arrancar desde modo de rescate
# Acceder al menú GRUB durante el arranque
# Montar sistema de archivos raíz
mount /dev/sda1 /mnt
# Chroot al sistema
chroot /mnt
# Reinstalar GRUB
grub-install /dev/sda
# Actualizar configuración de GRUB
update-grub
```

### Reparación del Sistema de Archivos: `fsck`

Verificar y reparar la corrupción del sistema de archivos.

```bash
# Verificar sistema de archivos
fsck /dev/sda1
# Verificación forzada del sistema de archivos
fsck -f /dev/sda1
# Reparación automática
fsck -y /dev/sda1
# Verificar todos los sistemas de archivos montados
fsck -A
```

### Problemas de Servicio: `systemctl`

Diagnosticar y solucionar problemas relacionados con servicios.

```bash
# Verificar estado del servicio
systemctl status servicename
# Ver registros del servicio
journalctl -u servicename
# Reiniciar servicio fallido
systemctl restart servicename
# Habilitar servicio al arranque
systemctl enable servicename
# Listar servicios fallidos
systemctl --failed
```

### Problemas de Rendimiento: Análisis de Recursos

Identificar y resolver cuellos de botella en el rendimiento del sistema.

```bash
# Verificar espacio en disco
df -h
# Monitorear uso de E/S
iotop
# Verificar uso de memoria
free -h
# Identificar uso de CPU
top
# Listar archivos abiertos
lsof
```

## Enlaces Relevantes

- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/rhel">Hoja de Trucos de Red Hat Enterprise Linux</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>
- <router-link to="/kubernetes">Hoja de Trucos de Kubernetes</router-link>
- <router-link to="/git">Hoja de Trucos de Git</router-link>
- <router-link to="/ansible">Hoja de Trucos de Ansible</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/cybersecurity">Hoja de Trucos de Ciberseguridad</router-link>

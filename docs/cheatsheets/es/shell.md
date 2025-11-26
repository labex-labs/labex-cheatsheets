---
title: 'Hoja de Trucos de Shell'
description: 'Aprenda Shell con nuestra hoja de trucos completa que cubre comandos esenciales, conceptos y mejores prácticas.'
pdfUrl: '/cheatsheets/pdf/shell-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Shell
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/shell">Aprende Shell con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende scripting Shell y operaciones de línea de comandos a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Shell que cubren comandos Bash esenciales, operaciones de archivos, procesamiento de texto, gestión de procesos y automatización. Domina la eficiencia de la línea de comandos y las técnicas de scripting shell.
</base-disclaimer-content>
</base-disclaimer>

## Operaciones de Archivos y Directorios

### Listar Archivos: `ls`

Muestra archivos y directorios en la ubicación actual.

```bash
# Listar archivos en el directorio actual
ls
# Listar con información detallada
ls -l
# Mostrar archivos ocultos
ls -a
# Listar con tamaños de archivo legibles por humanos
ls -lh
# Ordenar por tiempo de modificación
ls -lt
```

### Crear Archivos: `touch`

Crea archivos vacíos o actualiza marcas de tiempo.

```bash
# Crear un nuevo archivo
touch newfile.txt
# Crear múltiples archivos
touch file1.txt file2.txt file3.txt
# Actualizar la marca de tiempo del archivo existente
touch existing_file.txt
```

### Crear Directorios: `mkdir`

Crea nuevos directorios.

```bash
# Crear un directorio
mkdir my_directory
# Crear directorios anidados
mkdir -p parent/child/grandchild
# Crear múltiples directorios
mkdir dir1 dir2 dir3
```

### Copiar Archivos: `cp`

Copia archivos y directorios.

```bash
# Copiar un archivo
cp source.txt destination.txt
# Copiar directorio recursivamente
cp -r source_dir dest_dir
# Copiar con solicitud de confirmación
cp -i file1.txt file2.txt
# Preservar atributos del archivo
cp -p original.txt copy.txt
```

### Mover/Renombrar: `mv`

Mueve o renombra archivos y directorios.

```bash
# Renombrar un archivo
mv oldname.txt newname.txt
# Mover archivo a directorio
mv file.txt /path/to/directory/
# Mover múltiples archivos
mv file1 file2 file3 target_directory/
```

### Eliminar Archivos: `rm`

Elimina archivos y directorios.

```bash
# Eliminar un archivo
rm file.txt
# Eliminar directorio y contenido
rm -r directory/
# Eliminar sin confirmación (forzar)
rm -f file.txt
# Eliminación interactiva (confirmar cada uno)
rm -i *.txt
```

## Navegación y Gestión de Rutas

### Directorio Actual: `pwd`

Imprime la ruta del directorio de trabajo actual.

```bash
# Mostrar directorio actual
pwd
# Ejemplo de salida:
/home/user/documents
```

### Cambiar Directorio: `cd`

Cambia a un directorio diferente.

```bash
# Ir al directorio de inicio
cd ~
# Ir al directorio padre
cd ..
# Ir al directorio anterior
cd -
# Ir a un directorio específico
cd /path/to/directory
```

### Árbol de Directorios: `tree`

Muestra la estructura del directorio en formato de árbol.

```bash
# Mostrar árbol de directorios
tree
# Limitar la profundidad a 2 niveles
tree -L 2
# Mostrar solo directorios
tree -d
```

## Procesamiento de Texto y Búsqueda

### Ver Archivos: `cat` / `less` / `head` / `tail`

Muestra el contenido del archivo de diferentes maneras.

```bash
# Mostrar archivo completo
cat file.txt
# Ver archivo página por página
less file.txt
# Mostrar las primeras 10 líneas
head file.txt
# Mostrar las últimas 10 líneas
tail file.txt
# Mostrar las últimas 20 líneas
tail -n 20 file.txt
# Seguir cambios en el archivo (útil para logs)
tail -f logfile.txt
```

### Buscar en Archivos: `grep`

Busca patrones en archivos de texto.

```bash
# Buscar patrón en archivo
grep "pattern" file.txt
# Búsqueda sin distinguir mayúsculas y minúsculas
grep -i "pattern" file.txt
# Búsqueda recursiva en directorios
grep -r "pattern" directory/
# Mostrar números de línea
grep -n "pattern" file.txt
# Contar líneas coincidentes
grep -c "pattern" file.txt
```

### Encontrar Archivos: `find`

Localiza archivos y directorios según criterios.

```bash
# Encontrar archivos por nombre
find . -name "*.txt"
# Encontrar archivos por tipo
find . -type f -name "config*"
# Encontrar directorios
find . -type d -name "backup"
# Encontrar archivos modificados en los últimos 7 días
find . -mtime -7
# Encontrar y ejecutar comando
find . -name "*.log" -delete
```

### Manipulación de Texto: `sed` / `awk` / `sort`

Procesa y manipula datos de texto.

```bash
# Reemplazar texto en archivo
sed 's/old/new/g' file.txt
# Extraer columnas específicas
awk '{print $1, $3}' file.txt
# Ordenar contenido del archivo
sort file.txt
# Eliminar líneas duplicadas
sort file.txt | uniq
# Contar frecuencia de palabras
cat file.txt | tr ' ' '\n' | sort | uniq -c
```

## Permisos y Propiedad de Archivos

### Ver Permisos: `ls -l`

Muestra permisos detallados y propiedad de archivos.

```bash
# Mostrar información detallada del archivo
ls -l
# Ejemplo de salida:
# -rw-r--r-- 1 user group 1024 Jan 1 12:00 file.txt
# d = directorio, r = lectura, w = escritura, x = ejecución
```

### Cambiar Permisos: `chmod`

Modifica los permisos de archivos y directorios.

```bash
# Dar permiso de ejecución al propietario
chmod +x script.sh
# Establecer permisos específicos (755)
chmod 755 file.txt
# Eliminar permiso de escritura para grupo/otros
chmod go-w file.txt
# Cambio de permisos recursivo
chmod -R 644 directory/
```

### Cambiar Propiedad: `chown` / `chgrp`

Cambia el propietario y el grupo del archivo.

```bash
# Cambiar propietario
chown newowner file.txt
# Cambiar propietario y grupo
chown newowner:newgroup file.txt
# Cambiar solo el grupo
chgrp newgroup file.txt
# Cambio de propiedad recursivo
chown -R user:group directory/
```

### Números de Permiso

Entendiendo la notación numérica de permisos.

```text
# Cálculo de permisos:
# 4 = lectura (r), 2 = escritura (w), 1 = ejecución (x)
# 755 = rwxr-xr-x (propietario: rwx, grupo: r-x, otros: r-x)
# 644 = rw-r--r-- (propietario: rw-, grupo: r--, otros: r--)
# 777 = rwxrwxrwx (todos los permisos completos)
# 600 = rw------- (propietario: rw-, grupo: ---, otros: ---)
```

## Gestión de Procesos

### Ver Procesos: `ps` / `top` / `htop`

Muestra información sobre los procesos en ejecución.

```bash
# Mostrar procesos para el usuario actual
ps
# Mostrar todos los procesos con detalles
ps aux
# Mostrar procesos en formato de árbol
ps -ef --forest
# Visor de procesos interactivo
top
# Visor de procesos mejorado (si está disponible)
htop
```

### Trabajos en Segundo Plano: `&` / `jobs` / `fg` / `bg`

Gestiona procesos en segundo plano y en primer plano.

```bash
# Ejecutar comando en segundo plano
command &
# Listar trabajos activos
jobs
# Traer trabajo al primer plano
fg %1
# Enviar trabajo al segundo plano
bg %1
# Suspender proceso actual
Ctrl+Z
```

### Terminar Procesos: `kill` / `killall`

Termina procesos por PID o nombre.

```bash
# Terminar proceso por PID
kill 1234
# Terminar proceso forzadamente
kill -9 1234
# Terminar todos los procesos con nombre
killall firefox
# Enviar señal específica
kill -TERM 1234
```

### Monitoreo del Sistema: `free` / `df` / `du`

Monitorea recursos del sistema y uso de disco.

```bash
# Mostrar uso de memoria
free -h
# Mostrar espacio en disco
df -h
# Mostrar tamaño del directorio
du -sh directory/
# Mostrar directorios más grandes
du -h --max-depth=1 | sort -hr
```

## Redirección de Entrada/Salida

### Redirección: `>` / `>>` / `<`

Redirige la salida y la entrada de comandos.

```bash
# Redirigir salida a archivo (sobrescribir)
command > output.txt
# Anexar salida a archivo
command >> output.txt
# Redirigir entrada desde archivo
command < input.txt
# Redirigir salida y errores
command > output.txt 2>&1
# Descartar salida
command > /dev/null
```

### Pipes: `|`

Encadena comandos juntos usando pipes.

```bash
# Uso básico de pipe
command1 | command2
# Múltiples pipes
cat file.txt | grep "pattern" | sort | uniq
# Contar líneas en la salida
ps aux | wc -l
# Paginación de salida larga
ls -la | less
```

### Tee: `tee`

Escribe la salida tanto al archivo como a stdout.

```bash
# Guardar salida y mostrarla
command | tee output.txt
# Anexar al archivo
command | tee -a output.txt
# Múltiples salidas
command | tee file1.txt file2.txt
```

### Here Documents: `<<`

Proporciona entrada multilínea a los comandos.

```bash
# Crear archivo con here document
cat << EOF > file.txt
Línea 1
Línea 2
Línea 3
EOF
# Enviar correo electrónico con here document
mail user@example.com << EOF
Subject: Prueba
Este es un mensaje de prueba.
EOF
```

## Variables y Entorno

### Variables: Asignación y Uso

Crea y usa variables de shell.

```bash
# Asignar variables (sin espacios alrededor de =)
name="John"
count=42
# Usar variables
echo $name
echo "Hola, $name"
echo "Cuenta: ${count}"
# Sustitución de comandos
current_dir=$(pwd)
date_today=$(date +%Y-%m-%d)
```

### Variables de Entorno: `export` / `env`

Gestiona variables de entorno.

```bash
# Exportar variable al entorno
export PATH="/new/path:$PATH"
export MY_VAR="value"
# Ver todas las variables de entorno
env
# Ver variable específica
echo $HOME
echo $PATH
# Desasignar variable
unset MY_VAR
```

### Variables Especiales

Variables de shell incorporadas con significados especiales.

```bash
# Argumentos del script
$0  # Nombre del script
$1, $2, $3...  # Primer, segundo, tercer argumento
$#  # Número de argumentos
$@  # Todos los argumentos como palabras separadas
$*  # Todos los argumentos como una sola palabra
$?  # Estado de salida del último comando
# Información del proceso
$$  # PID del shell actual
$!  # PID del último comando en segundo plano
```

### Expansión de Parámetros

Técnicas avanzadas de manipulación de variables.

```bash
# Valores predeterminados
${var:-default}  # Usar predeterminado si var está vacío
${var:=default}  # Establecer var al predeterminado si está vacío
# Manipulación de cadenas
${var#pattern}   # Eliminar la coincidencia más corta desde el
principio
${var##pattern}  # Eliminar la coincidencia más larga desde el
principio
${var%pattern}   # Eliminar la coincidencia más corta desde el final
${var%%pattern}  # Eliminar la coincidencia más larga desde el final
```

## Conceptos Básicos de Scripting

### Estructura del Script

Formato básico del script y ejecución.

```bash
#!/bin/bash
# Esto es un comentario
# Variables
greeting="¡Hola, Mundo!"
user=$(whoami)
# Salida
echo $greeting
echo "Usuario actual: $user"
# Hacer el script ejecutable:
chmod +x script.sh
# Ejecutar script:
./script.sh
```

### Sentencias Condicionales: `if`

Controla el flujo del script con condiciones.

```bash
#!/bin/bash
if [ -f "file.txt" ]; then
    echo "El archivo existe"
elif [ -d "directory" ]; then
    echo "El directorio existe"
else
    echo "Ninguno existe"
fi
# Comparación de cadenas
if [ "$USER" = "root" ]; then
    echo "Ejecutando como root"
fi
# Comparación numérica
if [ $count -gt 10 ]; then
    echo "La cuenta es mayor que 10"
fi
```

### Bucles: `for` / `while`

Repite comandos usando bucles.

```bash
#!/bin/bash
# Bucle for con rango
for i in {1..5}; do
    echo "Número: $i"
done
# Bucle for con archivos
for file in *.txt; do
    echo "Procesando: $file"
done
# Bucle while
count=1
while [ $count -le 5 ]; do
    echo "Cuenta: $count"
    count=$((count + 1))
done
```

### Funciones

Crea bloques de código reutilizables.

```bash
#!/bin/bash
# Definir función
greet() {
    local name=$1
    echo "Hola, $name!"
}
# Función con valor de retorno
add_numbers() {
    local sum=$(($1 + $2))
    echo $sum
}
# Llamar funciones
greet "Alicia"
result=$(add_numbers 5 3)
echo "Suma: $result"
```

## Comandos de Red y Sistema

### Comandos de Red

Prueba la conectividad y la configuración de red.

```bash
# Probar conectividad de red
ping google.com
ping -c 4 google.com  # Enviar solo 4 paquetes
# Búsqueda DNS
nslookup google.com
dig google.com
# Configuración de red
ip addr show  # Mostrar direcciones IP
ip route show # Mostrar tabla de enrutamiento
# Descargar archivos
wget https://example.com/file.txt
curl -O https://example.com/file.txt
```

### Información del Sistema: `uname` / `whoami` / `date`

Obtener información del sistema y del usuario.

```bash
# Información del sistema
uname -a      # Toda la información del sistema
uname -r      # Versión del kernel
hostname      # Nombre del equipo
whoami        # Nombre de usuario actual
id            # ID de usuario y grupos
# Fecha y hora
date          # Fecha/hora actual
date +%Y-%m-%d # Formato personalizado
uptime        # Tiempo de actividad del sistema
```

### Archivo y Compresión: `tar` / `zip`

Crea y extrae archivos comprimidos.

```bash
# Crear archivo tar
tar -czf archive.tar.gz directory/
# Extraer archivo tar
tar -xzf archive.tar.gz
# Crear archivo zip
zip -r archive.zip directory/
# Extraer archivo zip
unzip archive.zip
# Ver contenido del archivo
tar -tzf archive.tar.gz
unzip -l archive.zip
```

### Transferencia de Archivos: `scp` / `rsync`

Transfiere archivos entre sistemas.

```bash
# Copiar archivo a servidor remoto
scp file.txt user@server:/path/to/destination
# Copiar desde servidor remoto
scp user@server:/path/to/file.txt .
# Sincronizar directorios (local a remoto)
rsync -avz local_dir/ user@server:/remote_dir/
# Sincronizar con eliminación (espejo)
rsync -avz --delete local_dir/ user@server:/remote_dir/
```

## Historial de Comandos y Atajos

### Historial de Comandos: `history`

Ver y reutilizar comandos anteriores.

```bash
# Mostrar historial de comandos
history
# Mostrar los últimos 10 comandos
history 10
# Ejecutar comando anterior
!!
# Ejecutar comando por número
!123
# Ejecutar el último comando que comienza con 'ls'
!ls
# Buscar interactivamente en el historial
Ctrl+R
```

### Expansión del Historial

Reutilizar partes de comandos anteriores.

```bash
# Argumentos del último comando
!$    # Último argumento del comando anterior
!^    # Primer argumento del comando anterior
!*    # Todos los argumentos del comando anterior
# Ejemplo de uso:
ls /very/long/path/to/file.txt
cd !$  # Va a /very/long/path/to/file.txt
```

### Atajos de Teclado

Atajos esenciales para un uso eficiente de la línea de comandos.

```bash
# Navegación
Ctrl+A  # Mover al principio de la línea
Ctrl+E  # Mover al final de la línea
Ctrl+F  # Mover un carácter hacia adelante
Ctrl+B  # Mover un carácter hacia atrás
Alt+F   # Mover una palabra hacia adelante
Alt+B   # Mover una palabra hacia atrás
# Edición
Ctrl+U  # Borrar línea antes del cursor
Ctrl+K  # Borrar línea después del cursor
Ctrl+W  # Borrar palabra antes del cursor
Ctrl+Y  # Pegar texto borrado recientemente
# Control de procesos
Ctrl+C  # Interrumpir comando actual
Ctrl+Z  # Suspender comando actual
Ctrl+D  # Salir del shell o EOF
```

## Combinaciones y Consejos de Comandos

### Combinaciones de Comandos Útiles

One-liners potentes para tareas comunes.

```bash
# Encontrar y reemplazar texto en múltiples archivos
find . -name "*.txt" -exec sed -i 's/old/new/g' {} \;
# Encontrar los archivos más grandes en el directorio actual
du -ah . | sort -rh | head -10
# Monitorear archivo de registro en busca de un patrón específico
tail -f /var/log/syslog | grep "ERROR"
# Contar archivos en el directorio
ls -1 | wc -l
# Crear copia de seguridad con marca de tiempo
cp file.txt file.txt.backup.$(date +%Y%m%d-%H%M%S)
```

### Alias y Funciones

Crea atajos para comandos usados frecuentemente.

```bash
# Crear alias (añadir a ~/.bashrc)
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
# Ver todos los alias
alias
# Crear alias persistentes en ~/.bashrc:
echo "alias mycommand='long command here'" >>
~/.bashrc
source ~/.bashrc
```

### Control de Trabajos y Sesiones de Pantalla

Gestiona procesos de larga ejecución y sesiones.

```bash
# Iniciar comando en segundo plano
nohup long_running_command &
# Iniciar sesión de screen
screen -S mysession
# Desconectarse de screen: Ctrl+A seguido de D
# Reconectarse a screen
screen -r mysession
# Listar sesiones de screen
screen -ls
# Alternativa: tmux
tmux new -s mysession
# Desconectarse: Ctrl+B seguido de D
tmux attach -t mysession
```

### Mantenimiento del Sistema

Tareas comunes de administración del sistema.

```bash
# Verificar uso de disco
df -h
du -sh /*
# Verificar uso de memoria
free -h
cat /proc/meminfo
# Verificar servicios en ejecución
systemctl status service_name
systemctl list-units --type=service
# Actualizar listas de paquetes (Ubuntu/Debian)
sudo apt update && sudo apt upgrade
# Buscar paquetes instalados
dpkg -l | grep package_name
```

## Enlaces Relevantes

- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/rhel">Hoja de Trucos de Red Hat Enterprise Linux</router-link>
- <router-link to="/git">Hoja de Trucos de Git</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>
- <router-link to="/kubernetes">Hoja de Trucos de Kubernetes</router-link>
- <router-link to="/ansible">Hoja de Trucos de Ansible</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>

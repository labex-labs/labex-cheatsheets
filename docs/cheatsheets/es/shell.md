---
title: 'Hoja de Trucos de Shell | LabEx'
description: 'Aprenda scripting de shell con esta hoja de trucos completa. Referencia rápida para comandos bash, scripting de shell, automatización, herramientas de línea de comandos y administración de sistemas Linux/Unix.'
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
Aprende scripting de Shell y operaciones de línea de comandos a través de laboratorios prácticos y escenarios del mundo real. LabEx proporciona cursos completos de Shell que cubren comandos esenciales de Bash, operaciones de archivos, procesamiento de texto, gestión de procesos y automatización. Domina la eficiencia de la línea de comandos y las técnicas de scripting de shell.
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
touch nuevoarchivo.txt
# Crear múltiples archivos
touch archivo1.txt archivo2.txt archivo3.txt
# Actualizar la marca de tiempo del archivo existente
touch archivo_existente.txt
```

### Crear Directorios: `mkdir`

Crea nuevos directorios.

```bash
# Crear un directorio
mkdir mi_directorio
# Crear directorios anidados
mkdir -p padre/hijo/nieto
# Crear múltiples directorios
mkdir dir1 dir2 dir3
```

### Copiar Archivos: `cp`

Copia archivos y directorios.

```bash
# Copiar un archivo
cp fuente.txt destino.txt
# Copiar directorio recursivamente
cp -r dir_fuente dir_destino
# Copiar con solicitud de confirmación
cp -i archivo1.txt archivo2.txt
# Preservar atributos del archivo
cp -p original.txt copia.txt
```

### Mover/Renombrar: `mv`

Mueve o renombra archivos y directorios.

```bash
# Renombrar un archivo
mv nombre_antiguo.txt nombre_nuevo.txt
# Mover archivo a directorio
mv archivo.txt /ruta/al/directorio/
# Mover múltiples archivos
mv archivo1 archivo2 archivo3 directorio_destino/
```

### Eliminar Archivos: `rm`

Elimina archivos y directorios.

```bash
# Eliminar un archivo
rm archivo.txt
# Eliminar directorio y contenido
rm -r directorio/
# Eliminar forzadamente sin confirmación
rm -f archivo.txt
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
/home/usuario/documentos
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
cd /ruta/al/directorio
```

<BaseQuiz id="shell-cd-1" correct="A">
  <template #question>
    ¿Qué hace <code>cd ~</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Cambia al directorio de inicio</BaseQuizOption>
  <BaseQuizOption value="B">Cambia al directorio raíz</BaseQuizOption>
  <BaseQuizOption value="C">Cambia al directorio padre</BaseQuizOption>
  <BaseQuizOption value="D">Crea un nuevo directorio</BaseQuizOption>
  
  <BaseQuizAnswer>
    El símbolo <code>~</code> es un atajo para el directorio de inicio. <code>cd ~</code> navega a tu directorio de inicio, lo cual es equivalente a <code>cd $HOME</code> o <code>cd /home/nombre_usuario</code>.
  </BaseQuizAnswer>
</BaseQuiz>

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
cat archivo.txt
# Ver archivo página por página
less archivo.txt
# Mostrar las primeras 10 líneas
head archivo.txt
# Mostrar las últimas 10 líneas
tail archivo.txt
# Mostrar las últimas 20 líneas
tail -n 20 archivo.txt
# Seguir cambios en el archivo (útil para logs)
tail -f archivo_log.txt
```

### Buscar en Archivos: `grep`

Busca patrones en archivos de texto.

```bash
# Buscar patrón en archivo
grep "patron" archivo.txt
# Búsqueda sin distinguir mayúsculas y minúsculas
grep -i "patron" archivo.txt
# Búsqueda recursiva en directorios
grep -r "patron" directorio/
# Mostrar números de línea
grep -n "patron" archivo.txt
# Contar líneas coincidentes
grep -c "patron" archivo.txt
```

<BaseQuiz id="shell-grep-1" correct="B">
  <template #question>
    ¿Qué hace <code>grep -r "patron" directorio/</code>?
  </template>
  
  <BaseQuizOption value="A">Busca solo en el archivo actual</BaseQuizOption>
  <BaseQuizOption value="B" correct>Busca recursivamente a través de todos los archivos en el directorio</BaseQuizOption>
  <BaseQuizOption value="C">Reemplaza el patrón en los archivos</BaseQuizOption>
  <BaseQuizOption value="D">Elimina archivos que contienen el patrón</BaseQuizOption>
  
  <BaseQuizAnswer>
    El indicador <code>-r</code> hace que grep busque recursivamente a través de todos los archivos y subdirectorios. Esto es útil para encontrar patrones de texto en todo un árbol de directorios.
  </BaseQuizAnswer>
</BaseQuiz>

### Encontrar Archivos: `find`

Localiza archivos y directorios basándose en criterios.

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
sed 's/antiguo/nuevo/g' archivo.txt
# Extraer columnas específicas
awk '{print $1, $3}' archivo.txt
# Ordenar contenido del archivo
sort archivo.txt
# Eliminar líneas duplicadas
sort archivo.txt | uniq
# Contar frecuencia de palabras
cat archivo.txt | tr ' ' '\n' | sort | uniq -c
```

## Permisos y Propiedad de Archivos

### Ver Permisos: `ls -l`

Muestra permisos detallados y propiedad de archivos.

```bash
# Mostrar información detallada del archivo
ls -l
# Ejemplo de salida:
# -rw-r--r-- 1 usuario grupo 1024 Ene 1 12:00 archivo.txt
# d = directorio, r = lectura, w = escritura, x = ejecución
```

### Cambiar Permisos: `chmod`

Modifica los permisos de archivos y directorios.

```bash
# Dar permiso de ejecución al propietario
chmod +x script.sh
# Establecer permisos específicos (755)
chmod 755 archivo.txt
# Eliminar permiso de escritura para grupo/otros
chmod go-w archivo.txt
# Cambio de permisos recursivo
chmod -R 644 directorio/
```

<BaseQuiz id="shell-chmod-1" correct="C">
  <template #question>
    ¿Qué establece <code>chmod 755 archivo.txt</code>?
  </template>
  
  <BaseQuizOption value="A">Lectura, escritura, ejecución para todos los usuarios</BaseQuizOption>
  <BaseQuizOption value="B">Lectura y escritura para el propietario, lectura para los demás</BaseQuizOption>
  <BaseQuizOption value="C" correct>Lectura, escritura, ejecución para el propietario; lectura, ejecución para grupo y otros</BaseQuizOption>
  <BaseQuizOption value="D">Solo lectura para todos los usuarios</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 755</code> establece los permisos como: propietario = 7 (rwx), grupo = 5 (r-x), otros = 5 (r-x). Este es un conjunto de permisos común para archivos y directorios ejecutables.
  </BaseQuizAnswer>
</BaseQuiz>

### Cambiar Propiedad: `chown` / `chgrp`

Cambia el propietario y el grupo del archivo.

```bash
# Cambiar propietario
chown nuevo_propietario archivo.txt
# Cambiar propietario y grupo
chown nuevo_propietario:nuevo_grupo archivo.txt
# Cambiar solo el grupo
chgrp nuevo_grupo archivo.txt
# Cambio de propiedad recursivo
chown -R usuario:grupo directorio/
```

### Números de Permiso

Entendiendo la notación numérica de permisos.

```text
# Cálculo de permisos:
# 4 = lectura (r), 2 = escritura (w), 1 = ejecución (x)
# 755 = rwxr-xr-x (propietario: rwx, grupo: r-x, otros: r-x)
# 644 = rw-r--r-- (propietario: rw-, grupo: r--, otros: r--)
# 777 = rwxrwxrwx (todos los permisos completos para todos)
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
comando &
# Listar trabajos activos
jobs
# Traer trabajo al primer plano
fg %1
# Enviar trabajo al segundo plano
bg %1
# Suspender proceso actual
Ctrl+Z
```

### Matar Procesos: `kill` / `killall`

Termina procesos por PID o nombre.

```bash
# Matar proceso por PID
kill 1234
# Matar proceso forzadamente
kill -9 1234
# Matar todos los procesos con nombre
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
du -sh directorio/
# Mostrar directorios más grandes
du -h --max-depth=1 | sort -hr
```

## Redirección de Entrada/Salida

### Redirección: `>` / `>>` / `<`

Redirige la salida y entrada de comandos.

```bash
# Redirigir salida a archivo (sobrescribir)
comando > salida.txt
# Añadir salida al archivo
comando >> salida.txt
# Redirigir entrada desde archivo
comando < entrada.txt
# Redirigir salida y errores
comando > salida.txt 2>&1
# Descartar salida
comando > /dev/null
```

<BaseQuiz id="shell-redirect-1" correct="B">
  <template #question>
    ¿Cuál es la diferencia entre <code>></code> y <code>>></code> en la redirección de shell?
  </template>
  
  <BaseQuizOption value="A"><code>></code> añade, <code>>></code> sobrescribe</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>></code> sobrescribe el archivo, <code>>></code> añade al archivo</BaseQuizOption>
  <BaseQuizOption value="C"><code>></code> redirige stdout, <code>>></code> redirige stderr</BaseQuizOption>
  <BaseQuizOption value="D">No hay diferencia</BaseQuizOption>
  
  <BaseQuizAnswer>
    El operador <code>></code> sobrescribe el archivo de destino si existe, mientras que <code>>></code> añade la salida al final del archivo. Usa <code>>></code> cuando quieras preservar el contenido existente.
  </BaseQuizAnswer>
</BaseQuiz>

### Pipes: `|`

Encadena comandos juntos usando pipes.

```bash
# Uso básico de pipe
comando1 | comando2
# Múltiples pipes
cat archivo.txt | grep "patron" | sort | uniq
# Contar líneas en la salida
ps aux | wc -l
# Paginación a través de salida larga
ls -la | less
```

### Tee: `tee`

Escribe la salida tanto al archivo como a stdout.

```bash
# Guardar salida y mostrarla
comando | tee salida.txt
# Añadir al archivo
comando | tee -a salida.txt
# Múltiples salidas
comando | tee archivo1.txt archivo2.txt
```

### Here Documents: `<<`

Proporciona entrada multilínea a los comandos.

```bash
# Crear archivo con here document
cat << EOF > archivo.txt
Línea 1
Línea 2
Línea 3
EOF
# Enviar correo electrónico con here document
mail usuario@ejemplo.com << EOF
Asunto: Prueba
Este es un mensaje de prueba.
EOF
```

## Variables y Entorno

### Variables: Asignación y Uso

Crea y usa variables de shell.

```bash
# Asignar variables (sin espacios alrededor de =)
nombre="John"
contador=42
# Usar variables
echo $nombre
echo "Hola, $nombre"
echo "Contador: ${contador}"
# Sustitución de comandos
directorio_actual=$(pwd)
fecha_hoy=$(date +%Y-%m-%d)
```

### Variables de Entorno: `export` / `env`

Gestiona variables de entorno.

```bash
# Exportar variable al entorno
export PATH="/nuevo/ruta:$PATH"
export MI_VAR="valor"
# Ver todas las variables de entorno
env
# Ver variable específica
echo $HOME
echo $PATH
# Desasignar variable
unset MI_VAR
```

### Variables Especiales

Variables de shell integradas con significados especiales.

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
${var:-predeterminado}  # Usar predeterminado si var está vacío
${var:=predeterminado}  # Establecer var a predeterminado si está vacío
# Manipulación de cadenas
${var#patron}   # Eliminar la coincidencia más corta del
principio
${var##patron}  # Eliminar la coincidencia más larga del
principio
${var%patron}   # Eliminar la coincidencia más corta del final
${var%%patron}  # Eliminar la coincidencia más larga del final
```

## Conceptos Básicos de Scripting

### Estructura del Script

Formato básico del script y ejecución.

```bash
#!/bin/bash
# Esto es un comentario
# Variables
saludo="¡Hola, Mundo!"
usuario=$(whoami)
# Salida
echo $saludo
echo "Usuario actual: $usuario"
# Hacer el script ejecutable:
chmod +x script.sh
# Ejecutar script:
./script.sh
```

### Sentencias Condicionales: `if`

Controla el flujo del script con condiciones.

```bash
#!/bin/bash
if [ -f "archivo.txt" ]; then
    echo "El archivo existe"
elif [ -d "directorio" ]; then
    echo "El directorio existe"
else
    echo "Ninguno existe"
fi
# Comparación de cadenas
if [ "$USER" = "root" ]; then
    echo "Ejecutando como root"
fi
# Comparación numérica
if [ $contador -gt 10 ]; then
    echo "El contador es mayor que 10"
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
for archivo in *.txt; do
    echo "Procesando: $archivo"
done
# Bucle while
contador=1
while [ $contador -le 5 ]; do
    echo "Contador: $contador"
    contador=$((contador + 1))
done
```

### Funciones

Crea bloques de código reutilizables.

```bash
#!/bin/bash
# Definir función
saludar() {
    local nombre=$1
    echo "Hola, $nombre!"
}
# Función con valor de retorno
sumar_numeros() {
    local suma=$(($1 + $2))
    echo $suma
}
# Llamar funciones
saludar "Alicia"
resultado=$(sumar_numeros 5 3)
echo "Suma: $resultado"
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
wget https://ejemplo.com/archivo.txt
curl -O https://ejemplo.com/archivo.txt
```

### Información del Sistema: `uname` / `whoami` / `date`

Obtener información del sistema y del usuario.

```bash
# Información del sistema
uname -a      # Toda la información del sistema
uname -r      # Versión del kernel
hostname      # Nombre del equipo
whoami        # Nombre de usuario actual
id            # ID y grupos de usuario
# Fecha y hora
date          # Fecha/hora actual
date +%Y-%m-%d # Formato personalizado
uptime        # Tiempo de actividad del sistema
```

### Archivo y Compresión: `tar` / `zip`

Crea y extrae archivos comprimidos.

```bash
# Crear archivo tar
tar -czf archivo.tar.gz directorio/
# Extraer archivo tar
tar -xzf archivo.tar.gz
# Crear archivo zip
zip -r archivo.zip directorio/
# Extraer archivo zip
unzip archivo.zip
# Ver contenido del archivo
tar -tzf archivo.tar.gz
unzip -l archivo.zip
```

### Transferencia de Archivos: `scp` / `rsync`

Transfiere archivos entre sistemas.

```bash
# Copiar archivo a servidor remoto
scp archivo.txt usuario@servidor:/ruta/al/destino
# Copiar desde servidor remoto
scp usuario@servidor:/ruta/al/archivo.txt .
# Sincronizar directorios (local a remoto)
rsync -avz dir_local/ usuario@servidor:/dir_remoto/
# Sincronizar con eliminación (espejo)
rsync -avz --delete dir_local/ usuario@servidor:/dir_remoto/
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
# Buscar en el historial interactivamente
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
ls /ruta/muy/larga/a/archivo.txt
cd !$  # Va a /ruta/muy/larga/a/archivo.txt
```

### Atajos de Teclado

Atajos esenciales para el uso eficiente de la línea de comandos.

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

Comandos de una sola línea potentes para tareas comunes.

```bash
# Buscar y reemplazar texto en múltiples archivos
find . -name "*.txt" -exec sed -i 's/antiguo/nuevo/g' {} \;
# Encontrar los archivos más grandes en el directorio actual
du -ah . | sort -rh | head -10
# Monitorear archivo de registro en busca de un patrón específico
tail -f /var/log/syslog | grep "ERROR"
# Contar archivos en el directorio
ls -1 | wc -l
# Crear copia de seguridad con marca de tiempo
cp archivo.txt archivo.txt.backup.$(date +%Y%m%d-%H%M%S)
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
echo "alias micomando='comando largo aquí'" >>
~/.bashrc
source ~/.bashrc
```

### Control de Trabajos y Sesiones de Pantalla

Gestiona procesos de larga ejecución y sesiones.

```bash
# Iniciar comando en segundo plano
nohup comando_larga_ejecucion &
# Iniciar sesión de screen
screen -S mi_sesion
# Desconectarse de screen: Ctrl+A seguido de D
# Reconectarse a screen
screen -r mi_sesion
# Listar sesiones de screen
screen -ls
# Alternativa: tmux
tmux new -s mi_sesion
# Desconectarse: Ctrl+B seguido de D
tmux attach -t mi_sesion
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
systemctl status nombre_servicio
systemctl list-units --type=service
# Actualizar listas de paquetes (Ubuntu/Debian)
sudo apt update && sudo apt upgrade
# Buscar paquetes instalados
dpkg -l | grep nombre_paquete
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

---
title: 'Hoja de Trucos de Hydra | LabEx'
description: 'Aprenda el cracking de contraseñas con Hydra con esta hoja de trucos completa. Referencia rápida para ataques de fuerza bruta, auditoría de contraseñas, pruebas de seguridad, protocolos de autenticación y herramientas de pentesting.'
pdfUrl: '/cheatsheets/pdf/hydra-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Hydra
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/hydra">Aprende Hydra con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende sobre el cracking de contraseñas con Hydra y las pruebas de penetración a través de laboratorios prácticos y escenarios del mundo real. LabEx proporciona cursos completos de Hydra que cubren ataques a protocolos, explotación de formularios web, optimización del rendimiento y uso ético. Domina las técnicas de fuerza bruta para pruebas de seguridad autorizadas y evaluaciones de vulnerabilidades.
</base-disclaimer-content>
</base-disclaimer>

## Sintaxis Básica e Instalación

### Instalación: `sudo apt install hydra`

Hydra generalmente viene preinstalado en Kali Linux, pero se puede instalar en otras distribuciones.

```bash
# Instalar en sistemas Debian/Ubuntu
sudo apt install hydra
# Instalar en otros sistemas
sudo apt-get install hydra
# Verificar instalación
hydra -h
# Revisar protocolos soportados
hydra
```

### Sintaxis Básica: `hydra [opciones] objetivo servicio`

Sintaxis básica: `hydra -l <nombre_usuario> -P <archivo_contraseñas> <protocolo_objetivo>://<dirección_objetivo>`

```bash
# Un solo nombre de usuario, lista de contraseñas
hydra -l username -P passwords.txt target.com ssh
# Lista de nombres de usuario, lista de contraseñas
hydra -L users.txt -P passwords.txt target.com ssh
# Un solo nombre de usuario, una sola contraseña
hydra -l admin -p password123 192.168.1.100 ftp
```

<BaseQuiz id="hydra-syntax-1" correct="B">
  <template #question>
    ¿Cuál es la diferencia entre <code>-l</code> y <code>-L</code> en Hydra?
  </template>
  
  <BaseQuizOption value="A"><code>-l</code> es para contraseñas, <code>-L</code> es para nombres de usuario</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>-l</code> especifica un único nombre de usuario, <code>-L</code> especifica un archivo de lista de nombres de usuario</BaseQuizOption>
  <BaseQuizOption value="C">No hay diferencia</BaseQuizOption>
  <BaseQuizOption value="D"><code>-l</code> es minúscula, <code>-L</code> es mayúscula</BaseQuizOption>
  
  <BaseQuizAnswer>
    La opción <code>-l</code> se utiliza para un único nombre de usuario, mientras que <code>-L</code> se utiliza para un archivo que contiene una lista de nombres de usuario. De manera similar, <code>-p</code> es para una única contraseña y <code>-P</code> es para un archivo de lista de contraseñas.
  </BaseQuizAnswer>
</BaseQuiz>

### Opciones Principales: `-l`, `-L`, `-p`, `-P`

Especifica nombres de usuario y contraseñas para ataques de fuerza bruta.

```bash
# Opciones de nombre de usuario
-l username          # Nombre de usuario único
-L userlist.txt      # Archivo de lista de nombres de usuario
# Opciones de contraseña
-p password          # Contraseña única
-P passwordlist.txt  # Archivo de lista de contraseñas
# Ubicación común de listas de palabras
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/metasploit/unix_passwords.txt
```

### Opciones de Salida: `-o`, `-b`

Guarda los resultados en un archivo para su posterior análisis.

```bash
# Guardar resultados en un archivo
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# Formato de salida JSON
hydra -l admin -P passwords.txt target.com ssh -b json
# Salida detallada (verbose)
hydra -l admin -P passwords.txt target.com ssh -V
```

<BaseQuiz id="hydra-output-1" correct="A">
  <template #question>
    ¿Qué hace <code>hydra -V</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Habilita la salida detallada mostrando el progreso</BaseQuizOption>
  <BaseQuizOption value="B">Valida el archivo de lista de palabras</BaseQuizOption>
  <BaseQuizOption value="C">Muestra la versión de Hydra</BaseQuizOption>
  <BaseQuizOption value="D">Se ejecuta solo en modo detallado</BaseQuizOption>
  
  <BaseQuizAnswer>
    El indicador <code>-V</code> habilita el modo detallado, que muestra una salida detallada incluyendo cada intento de inicio de sesión, facilitando el monitoreo del progreso y la depuración de problemas durante los ataques de contraseñas.
  </BaseQuizAnswer>
</BaseQuiz>

## Ataques Específicos de Protocolo

### SSH: `hydra objetivo ssh`

Ataca servicios SSH con combinaciones de nombre de usuario y contraseña.

```bash
# Ataque SSH básico
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh
# Múltiples nombres de usuario
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
# Puerto SSH personalizado
hydra -l admin -P passwords.txt 192.168.1.100 -s 2222 ssh
# Con subprocesamiento (threading)
hydra -l root -P passwords.txt -t 6 ssh://192.168.1.100
```

<BaseQuiz id="hydra-ssh-1" correct="C">
  <template #question>
    ¿Qué hace el indicador <code>-s</code> en Hydra?
  </template>
  
  <BaseQuizOption value="A">Establece el tipo de servicio</BaseQuizOption>
  <BaseQuizOption value="B">Habilita el modo sigiloso</BaseQuizOption>
  <BaseQuizOption value="C" correct>Especifica un número de puerto personalizado</BaseQuizOption>
  <BaseQuizOption value="D">Establece el número de subprocesos</BaseQuizOption>
  
  <BaseQuizAnswer>
    El indicador <code>-s</code> especifica un número de puerto personalizado cuando el servicio se ejecuta en un puerto no estándar. Por ejemplo, <code>-s 2222</code> apunta a SSH en el puerto 2222 en lugar del puerto predeterminado 22.
  </BaseQuizAnswer>
</BaseQuiz>

### FTP: `hydra objetivo ftp`

Fuerza bruta de credenciales de inicio de sesión FTP.

```bash
# Ataque FTP básico
hydra -l admin -P passwords.txt ftp://192.168.1.100
# Verificación de FTP anónimo
hydra -l anonymous -p "" ftp://192.168.1.100
# Puerto FTP personalizado
hydra -l user -P passwords.txt -s 2121 192.168.1.100 ftp
```

### Ataques a Bases de Datos: `mysql`, `postgres`, `mssql`

Ataca servicios de bases de datos mediante fuerza bruta de credenciales.

```bash
# Ataque MySQL
hydra -l root -P passwords.txt 192.168.1.100 mysql
# Ataque PostgreSQL
hydra -l postgres -P passwords.txt 192.168.1.100 postgres
# Ataque MSSQL
hydra -l sa -P passwords.txt 192.168.1.100 mssql
# Ataque MongoDB
hydra -l admin -P passwords.txt 192.168.1.100 mongodb
```

### SMTP/Email: `hydra objetivo smtp`

Ataca la autenticación del servidor de correo electrónico.

```bash
# Fuerza bruta SMTP
hydra -l admin -P passwords.txt smtp://mail.target.com
# Con contraseñas nulas/vacías
hydra -P passwords.txt -e ns -V -s 25 smtp.target.com smtp
# Ataque IMAP
hydra -l user -P passwords.txt imap://mail.target.com
```

## Ataques a Aplicaciones Web

### Formularios POST HTTP: `http-post-form`

Ataca formularios de inicio de sesión web usando el método HTTP POST con marcadores de posición `^USER^` y `^PASS^`.

```bash
# Ataque básico de formulario POST
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
# Con mensaje de error personalizado
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid password"
# Con condición de éxito
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/admin:username=^USER^&password=^PASS^:S=Dashboard"
```

### Formularios GET HTTP: `http-get-form`

Similar a los formularios POST pero apunta a solicitudes GET.

```bash
# Ataque de formulario GET
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# Con encabezados personalizados
hydra -l admin -P passwords.txt 192.168.1.100 http-get-form "/auth:user=^USER^&pass=^PASS^:F=Error:H=Cookie: session=abc123"
```

### Autenticación Básica HTTP: `http-get`/`http-post`

Ataca servidores web usando autenticación básica HTTP.

```bash
# Autenticación Básica HTTP
hydra -l admin -P passwords.txt http-get://192.168.1.100
# Autenticación Básica HTTPS
hydra -l admin -P passwords.txt https-get://secure.target.com
# Con ruta personalizada
hydra -l admin -P passwords.txt http-get://192.168.1.100/admin
```

### Ataques Web Avanzados

Maneja aplicaciones web complejas con tokens CSRF y cookies.

```bash
# Con manejo de token CSRF
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^&csrf=^CSRF^:F=Error:H=Cookie: csrf=^CSRF^"
# Con cookies de sesión
hydra -l admin -P passwords.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: PHPSESSID=abc123"
```

## Opciones de Rendimiento y Subprocesamiento

### Subprocesamiento (Threading): `-t` (Tareas)

Controla el número de conexiones de ataque simultáneas durante el ataque.

```bash
# Subprocesamiento predeterminado (16 tareas)
hydra -l admin -P passwords.txt target.com ssh
# Número de subprocesos personalizado
hydra -l admin -P passwords.txt -t 4 target.com ssh
# Ataque de alto rendimiento (usar con precaución)
hydra -l admin -P passwords.txt -t 64 target.com ssh
# Subprocesamiento conservador (evitar detección)
hydra -l admin -P passwords.txt -t 1 target.com ssh
```

### Tiempo de Espera: `-w` (Retardo)

Añade retrasos entre intentos para evitar la limitación de velocidad y la detección.

```bash
# Espera de 30 segundos entre intentos
hydra -l admin -P passwords.txt -w 30 target.com ssh
# Combinado con subprocesamiento
hydra -l admin -P passwords.txt -t 2 -w 10 target.com ssh
# Retardo aleatorio (1-5 segundos)
hydra -l admin -P passwords.txt -W 5 target.com ssh
```

### Múltiples Objetivos: `-M` (Archivo de Objetivos)

Ataca múltiples hosts especificándolos en un archivo.

```bash
# Crear archivo de objetivos
echo "192.168.1.100" > targets.txt
echo "192.168.1.101" >> targets.txt
echo "192.168.1.102" >> targets.txt
# Atacar múltiples objetivos
hydra -L users.txt -P passwords.txt -M targets.txt ssh
# Con subprocesamiento personalizado por objetivo
hydra -L users.txt -P passwords.txt -M targets.txt -t 2 ssh
```

### Opciones de Reanudar y Detener

Reanuda ataques interrumpidos y controla el comportamiento de detención.

```bash
# Detener después del primer éxito
hydra -l admin -P passwords.txt -f target.com ssh
# Reanudar ataque anterior
hydra -R
# Crear archivo de restauración
hydra -l admin -P passwords.txt -I restore.txt target.com ssh
```

## Características Avanzadas y Opciones

### Generación de Contraseñas: `-e` (Pruebas Adicionales)

Prueba variaciones adicionales de contraseñas automáticamente.

```bash
# Probar contraseñas nulas
hydra -l admin -e n target.com ssh
# Probar el nombre de usuario como contraseña
hydra -l admin -e s target.com ssh
# Probar el nombre de usuario invertido
hydra -l admin -e r target.com ssh
# Combinar todas las opciones
hydra -l admin -e nsr -P passwords.txt target.com ssh
```

### Formato Separado por Dos Puntos: `-C`

Utiliza combinaciones de nombre_usuario:contraseña para reducir el tiempo de ataque.

```bash
# Crear archivo de credenciales
echo "admin:admin" > creds.txt
echo "root:password" >> creds.txt
echo "user:123456" >> creds.txt
# Usar formato de dos puntos
hydra -C creds.txt target.com ssh
# Más rápido que probar todas las combinaciones
```

### Soporte de Proxy: `HYDRA_PROXY`

Utiliza servidores proxy para ataques con variables de entorno.

```bash
# Proxy HTTP
export HYDRA_PROXY=connect://proxy.example.com:8080
hydra -l admin -P passwords.txt target.com ssh
# Proxy SOCKS4 con autenticación
export HYDRA_PROXY=socks4://user:pass@127.0.0.1:1080
# Proxy SOCKS5
export HYDRA_PROXY=socks5://proxy.example.com:1080
```

### Optimización de la Lista de Contraseñas: `pw-inspector`

Usa pw-inspector para filtrar listas de contraseñas basadas en políticas.

```bash
# Filtrar contraseñas (mínimo 6 caracteres, 2 clases de caracteres)
cat passwords.txt | pw-inspector -m 6 -c 2 -n > filtered.txt
# Usar lista filtrada con Hydra
hydra -l admin -P filtered.txt target.com ssh
# Eliminar duplicados primero
cat passwords.txt | sort | uniq > unique_passwords.txt
```

## Uso Ético y Mejores Prácticas

### Pautas Legales y Éticas

Es posible usar Hydra de manera legal e ilegal. Obtenga el permiso y la aprobación apropiados antes de realizar ataques de fuerza bruta.

```text
Realice ataques solo en sistemas para los cuales se haya obtenido permiso explícito
Asegúrese siempre de tener permiso explícito del propietario o administrador del sistema
Documente todas las actividades de prueba para el cumplimiento
Úselo solo durante pruebas de penetración autorizadas
Nunca lo use para intentos de acceso no autorizados
```

### Medidas Defensivas

Defiéndase contra ataques de fuerza bruta con contraseñas sólidas y políticas.

```text
Implementar políticas de bloqueo de cuentas para bloquear temporalmente las cuentas después de intentos fallidos
Usar autenticación multifactor (MFA)
Implementar sistemas CAPTCHA para prevenir herramientas de automatización
Monitorear y registrar los intentos de autenticación
Implementar limitación de velocidad y bloqueo de IP
```

### Mejores Prácticas de Pruebas

Comience con configuraciones conservadoras y documente todas las actividades para mayor transparencia.

```text
Comience con recuentos de subprocesos bajos para evitar la interrupción del servicio
Use listas de palabras apropiadas para el entorno objetivo
Pruebe durante las ventanas de mantenimiento aprobadas cuando sea posible
Monitoree el rendimiento del sistema objetivo durante las pruebas
Tenga listos los procedimientos de respuesta a incidentes
```

### Casos de Uso Comunes

Tanto los equipos rojos como los azules se benefician de las auditorías de contraseñas, las evaluaciones de seguridad y las pruebas de penetración.

```text
Cracking de contraseñas para identificar contraseñas débiles y evaluar la solidez de las contraseñas
Auditorías de seguridad de servicios de red
Pruebas de penetración y evaluaciones de vulnerabilidades
Pruebas de cumplimiento de políticas de contraseñas
Demostraciones de capacitación y educativas
```

## Alternativa de GUI y Herramientas Adicionales

### XHydra: Interfaz Gráfica de Usuario

XHydra es una GUI para Hydra que permite seleccionar la configuración desde controles a través de la GUI en lugar de interruptores de línea de comandos.

```bash
# Iniciar la GUI de XHydra
xhydra
# Instalar si no está disponible
sudo apt install hydra-gtk
# Características:
# - Interfaz de apuntar y hacer clic
# - Plantillas de ataque preconfiguradas
# - Monitoreo visual del progreso
# - Fácil selección de objetivos y listas de palabras
```

### Hydra Wizard: Configuración Interactiva

Asistente interactivo que guía a los usuarios a través de la configuración de Hydra con preguntas sencillas.

```bash
# Iniciar el asistente interactivo
hydra-wizard
# El asistente pregunta por:
# 1. Servicio a atacar
# 2. Objetivo a atacar
# 3. Nombre de usuario o archivo de nombres de usuario
# 4. Contraseña o archivo de contraseñas
# 5. Pruebas de contraseña adicionales
# 6. Número de puerto
# 7. Confirmación final
```

### Listas de Contraseñas Predeterminadas: `dpl4hydra`

Genera listas de contraseñas predeterminadas para marcas y sistemas específicos.

```bash
# Actualizar base de datos de contraseñas predeterminadas
dpl4hydra refresh
# Generar lista para una marca específica
dpl4hydra cisco
dpl4hydra netgear
dpl4hydra linksys
# Usar listas generadas
hydra -C dpl4hydra_cisco.lst 192.168.1.1 ssh
# Todas las marcas
dpl4hydra all
```

### Integración con Otras Herramientas

Combina Hydra con herramientas de reconocimiento y enumeración.

```bash
# Combinar con descubrimiento de servicios Nmap
nmap -sV 192.168.1.0/24 | grep -E "(ssh|ftp|http)"
# Usar con resultados de enumeración de nombres de usuario
enum4linux 192.168.1.100 | grep "user:" > users.txt
# Integrar con listas de palabras de Metasploit
ls /usr/share/wordlists/metasploit/
```

## Solución de Problemas y Rendimiento

### Problemas Comunes y Soluciones

Resuelve problemas típicos encontrados al usar Hydra.

```bash
# Errores de tiempo de espera de conexión
hydra -l admin -P passwords.txt -t 1 -w 30 target.com ssh
# Error de demasiadas conexiones
hydra -l admin -P passwords.txt -t 2 target.com ssh
# Optimización del uso de memoria
hydra -l admin -P small_list.txt target.com ssh
# Revisar protocolos soportados
hydra
# Buscar el protocolo en la lista de servicios soportados
```

### Optimización del Rendimiento

Optimiza las listas de contraseñas y ordénalas por probabilidad para obtener resultados más rápidos.

```bash
# Ordenar contraseñas por probabilidad
hydra -l admin -P passwords.txt -u target.com ssh
# Eliminar duplicados
sort passwords.txt | uniq > clean_passwords.txt
# Optimizar subprocesamiento basado en el objetivo
# Red local: -t 16
# Objetivo en Internet: -t 4
# Servicio lento: -t 1
```

### Formatos de Salida y Análisis

Diferentes formatos de salida para el análisis de resultados y la elaboración de informes.

```bash
# Salida de texto estándar
hydra -l admin -P passwords.txt target.com ssh -o results.txt
# Formato JSON para análisis
hydra -l admin -P passwords.txt target.com ssh -b json -o results.json
# Salida detallada para depuración
hydra -l admin -P passwords.txt target.com ssh -V
# Salida solo de éxito
hydra -l admin -P passwords.txt target.com ssh | grep "password:"
```

### Monitoreo de Recursos

Monitorea los recursos del sistema y de la red durante los ataques.

```bash
# Monitorear el uso de CPU
top -p $(pidof hydra)
# Monitorear conexiones de red
netstat -an | grep :22
# Monitorear el uso de memoria
ps aux | grep hydra
# Limitar el impacto en el sistema
nice -n 19 hydra -l admin -P passwords.txt target.com ssh
```

## Enlaces Relevantes

- <router-link to="/kali">Hoja de Trucos de Kali Linux</router-link>
- <router-link to="/cybersecurity">Hoja de Trucos de Ciberseguridad</router-link>
- <router-link to="/nmap">Hoja de Trucos de Nmap</router-link>
- <router-link to="/wireshark">Hoja de Trucos de Wireshark</router-link>
- <router-link to="/comptia">Hoja de Trucos de CompTIA</router-link>
- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>

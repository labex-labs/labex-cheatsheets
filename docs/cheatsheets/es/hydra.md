---
title: 'Hoja de Trucos de Hydra'
description: 'Aprenda Hydra con nuestra hoja de trucos completa que cubre comandos esenciales, conceptos y mejores prácticas.'
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
# Usuario único, lista de contraseñas
hydra -l usuario -P contraseñas.txt target.com ssh
# Lista de usuarios, lista de contraseñas
hydra -L usuarios.txt -P contraseñas.txt target.com ssh
# Usuario único, contraseña única
hydra -l admin -p password123 192.168.1.100 ftp
```

### Opciones Principales: `-l`, `-L`, `-p`, `-P`

Especifica nombres de usuario y contraseñas para ataques de fuerza bruta.

```bash
# Opciones de nombre de usuario
-l nombre_usuario          # Usuario único
-L archivo_lista_usuarios.txt      # Archivo de lista de nombres de usuario
# Opciones de contraseña
-p contraseña          # Contraseña única
-P archivo_lista_contraseñas.txt   # Archivo de lista de contraseñas
# Ubicación común de listas de palabras
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/metasploit/unix_passwords.txt
```

### Opciones de Salida: `-o`, `-b`

Guarda los resultados en un archivo para su posterior análisis.

```bash
# Guardar resultados en archivo
hydra -l admin -P contraseñas.txt target.com ssh -o resultados.txt
# Formato de salida JSON
hydra -l admin -P contraseñas.txt target.com ssh -b json
# Salida detallada (Verbose)
hydra -l admin -P contraseñas.txt target.com ssh -V
```

## Ataques Específicos de Protocolo

### SSH: `hydra objetivo ssh`

Ataca servicios SSH con combinaciones de nombre de usuario y contraseña.

```bash
# Ataque SSH básico
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.1.100 ssh
# Múltiples usuarios
hydra -L usuarios.txt -P contraseñas.txt ssh://192.168.1.100
# Puerto SSH personalizado
hydra -l admin -P contraseñas.txt 192.168.1.100 -s 2222 ssh
# Con subprocesamiento (threading)
hydra -l root -P contraseñas.txt -t 6 ssh://192.168.1.100
```

### FTP: `hydra objetivo ftp`

Fuerza bruta de credenciales de inicio de sesión FTP.

```bash
# Ataque FTP básico
hydra -l admin -P contraseñas.txt ftp://192.168.1.100
# Verificación de FTP anónimo
hydra -l anonymous -p "" ftp://192.168.1.100
# Puerto FTP personalizado
hydra -l user -P contraseñas.txt -s 2121 192.168.1.100 ftp
```

### Ataques a Bases de Datos: `mysql`, `postgres`, `mssql`

Ataca servicios de bases de datos con fuerza bruta de credenciales.

```bash
# Ataque MySQL
hydra -l root -P contraseñas.txt 192.168.1.100 mysql
# Ataque PostgreSQL
hydra -l postgres -P contraseñas.txt 192.168.1.100 postgres
# Ataque MSSQL
hydra -l sa -P contraseñas.txt 192.168.1.100 mssql
# Ataque MongoDB
hydra -l admin -P contraseñas.txt 192.168.1.100 mongodb
```

### SMTP/Email: `hydra objetivo smtp`

Ataca la autenticación del servidor de correo electrónico.

```bash
# Fuerza bruta SMTP
hydra -l admin -P contraseñas.txt smtp://mail.target.com
# Con contraseñas nulas/vacías
hydra -P contraseñas.txt -e ns -V -s 25 smtp.target.com smtp
# Ataque IMAP
hydra -l user -P contraseñas.txt imap://mail.target.com
```

## Ataques a Aplicaciones Web

### Formularios POST HTTP: `http-post-form`

Ataca formularios de inicio de sesión web usando el método HTTP POST con marcadores de posición `^USER^` y `^PASS^`.

```bash
# Ataque básico de formulario POST
hydra -l admin -P contraseñas.txt 192.168.1.100 http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect"
# Con mensaje de error personalizado
hydra -l admin -P contraseñas.txt 192.168.1.100 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid password"
# Con condición de éxito
hydra -l admin -P contraseñas.txt 192.168.1.100 http-post-form "/admin:username=^USER^&password=^PASS^:S=Dashboard"
```

### Formularios GET HTTP: `http-get-form`

Similar a los formularios POST pero apunta a solicitudes GET en su lugar.

```bash
# Ataque de formulario GET
hydra -l admin -P contraseñas.txt 192.168.1.100 http-get-form "/login:username=^USER^&password=^PASS^:F=Invalid"
# Con encabezados personalizados
hydra -l admin -P contraseñas.txt 192.168.1.100 http-get-form "/auth:user=^USER^&pass=^PASS^:F=Error:H=Cookie: session=abc123"
```

### Autenticación Básica HTTP: `http-get`/`http-post`

Ataca servidores web usando autenticación básica HTTP.

```bash
# Autenticación Básica HTTP
hydra -l admin -P contraseñas.txt http-get://192.168.1.100
# Autenticación Básica HTTPS
hydra -l admin -P contraseñas.txt https-get://secure.target.com
# Con ruta personalizada
hydra -l admin -P contraseñas.txt http-get://192.168.1.100/admin
```

### Ataques Web Avanzados

Maneja aplicaciones web complejas con tokens CSRF y cookies.

```bash
# Con manejo de token CSRF
hydra -l admin -P contraseñas.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^&csrf=^CSRF^:F=Error:H=Cookie: csrf=^CSRF^"
# Con cookies de sesión
hydra -l admin -P contraseñas.txt 192.168.1.100 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: PHPSESSID=abc123"
```

## Opciones de Rendimiento y Subprocesamiento

### Subprocesamiento (Threading): `-t` (Tareas)

Controla el número de conexiones de ataque simultáneas durante el ataque.

```bash
# Subprocesamiento por defecto (16 tareas)
hydra -l admin -P contraseñas.txt target.com ssh
# Conteo de hilos personalizado
hydra -l admin -P contraseñas.txt -t 4 target.com ssh
# Ataque de alto rendimiento (usar con precaución)
hydra -l admin -P contraseñas.txt -t 64 target.com ssh
# Subprocesamiento conservador (evitar detección)
hydra -l admin -P contraseñas.txt -t 1 target.com ssh
```

### Tiempo de Espera: `-w` (Retardo)

Añade retrasos entre intentos para evitar la limitación de velocidad y la detección.

```bash
# Espera de 30 segundos entre intentos
hydra -l admin -P contraseñas.txt -w 30 target.com ssh
# Combinado con subprocesamiento
hydra -l admin -P contraseñas.txt -t 2 -w 10 target.com ssh
# Retardo aleatorio (1-5 segundos)
hydra -l admin -P contraseñas.txt -W 5 target.com ssh
```

### Múltiples Objetivos: `-M` (Archivo de Objetivo)

Ataca múltiples hosts especificándolos en un archivo.

```bash
# Crear archivo de objetivos
echo "192.168.1.100" > objetivos.txt
echo "192.168.1.101" >> objetivos.txt
echo "192.168.1.102" >> objetivos.txt
# Atacar múltiples objetivos
hydra -L usuarios.txt -P contraseñas.txt -M objetivos.txt ssh
# Con subprocesamiento personalizado por objetivo
hydra -L usuarios.txt -P contraseñas.txt -M objetivos.txt -t 2 ssh
```

### Opciones de Reanudación y Detención

Reanuda ataques interrumpidos y controla el comportamiento de detención.

```bash
# Detener después del primer éxito
hydra -l admin -P contraseñas.txt -f target.com ssh
# Reanudar ataque previo
hydra -R
# Crear archivo de restauración
hydra -l admin -P contraseñas.txt -I restore.txt target.com ssh
```

## Características Avanzadas y Opciones

### Generación de Contraseñas: `-e` (Pruebas Adicionales)

Prueba variaciones de contraseñas adicionales automáticamente.

```bash
# Probar contraseñas nulas
hydra -l admin -e n target.com ssh
# Probar el nombre de usuario como contraseña
hydra -l admin -e s target.com ssh
# Probar el nombre de usuario invertido
hydra -l admin -e r target.com ssh
# Combinar todas las opciones
hydra -l admin -e nsr -P contraseñas.txt target.com ssh
```

### Formato Separado por Dos Puntos: `-C`

Usa combinaciones de usuario:contraseña para reducir el tiempo de ataque.

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

Usa servidores proxy para ataques con variables de entorno.

```bash
# Proxy HTTP
export HYDRA_PROXY=connect://proxy.example.com:8080
hydra -l admin -P contraseñas.txt target.com ssh
# Proxy SOCKS4 con autenticación
export HYDRA_PROXY=socks4://user:pass@127.0.0.1:1080
# Proxy SOCKS5
export HYDRA_PROXY=socks5://proxy.example.com:1080
```

### Optimización de Lista de Contraseñas: `pw-inspector`

Usa pw-inspector para filtrar listas de contraseñas basadas en políticas.

```bash
# Filtrar contraseñas (mínimo 6 caracteres, 2 clases de caracteres)
cat contraseñas.txt | pw-inspector -m 6 -c 2 -n > filtradas.txt
# Usar lista filtrada con Hydra
hydra -l admin -P filtradas.txt target.com ssh
# Eliminar duplicados primero
cat contraseñas.txt | sort | uniq > contraseñas_unicas.txt
```

## Uso Ético y Mejores Prácticas

### Pautas Legales y Éticas

Es posible usar Hydra tanto legal como ilegalmente. Obtén el permiso y la aprobación apropiados antes de realizar ataques de fuerza bruta.

```text
Realiza ataques solo en sistemas donde se haya obtenido permiso explícito
Asegúrate siempre de tener permiso explícito del propietario o administrador del sistema
Documenta todas las actividades de prueba para el cumplimiento
Úsalo solo durante pruebas de penetración autorizadas
Nunca lo uses para intentos de acceso no autorizados
```

### Medidas Defensivas

Defiéndete contra ataques de fuerza bruta con contraseñas sólidas y políticas.

```text
Implementa políticas de bloqueo de cuentas para bloquear temporalmente las cuentas después de intentos fallidos
Usa autenticación multifactor (MFA)
Implementa sistemas CAPTCHA para prevenir herramientas de automatización
Monitorea y registra los intentos de autenticación
Implementa limitación de velocidad y bloqueo de IP
```

### Mejores Prácticas de Pruebas

Comienza con configuraciones conservadoras y documenta todas las actividades para mayor transparencia.

```text
Comienza con bajos recuentos de hilos para evitar la interrupción del servicio
Usa listas de palabras apropiadas para el entorno objetivo
Prueba durante ventanas de mantenimiento aprobadas cuando sea posible
Monitorea el rendimiento del sistema objetivo durante las pruebas
Ten listos los procedimientos de respuesta a incidentes
```

### Casos de Uso Comunes

Tanto los equipos rojos como los azules se benefician para auditorías de contraseñas, evaluaciones de seguridad y pruebas de penetración.

```text
Cracking de contraseñas para identificar contraseñas débiles y evaluar la solidez de las contraseñas
Auditorías de seguridad de servicios de red
Pruebas de penetración y evaluaciones de vulnerabilidades
Pruebas de cumplimiento de políticas de contraseñas
Demostraciones de capacitación y educativas
```

## Alternativa de Interfaz Gráfica y Herramientas Adicionales

### XHydra: Interfaz Gráfica

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
# - Fácil selección de objetivo y lista de palabras
```

### Hydra Wizard: Configuración Interactiva

Asistente interactivo que guía a los usuarios a través de la configuración de Hydra con preguntas sencillas.

```bash
# Iniciar asistente interactivo
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
# Refrescar base de datos de contraseñas predeterminadas
dpl4hydra refresh
# Generar lista para marca específica
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
# Usar con resultados de enumeración de usuarios
enum4linux 192.168.1.100 | grep "user:" > usuarios.txt
# Integrar con listas de palabras de Metasploit
ls /usr/share/wordlists/metasploit/
```

## Solución de Problemas y Rendimiento

### Problemas Comunes y Soluciones

Resuelve problemas típicos encontrados durante el uso de Hydra.

```bash
# Errores de tiempo de espera de conexión
hydra -l admin -P contraseñas.txt -t 1 -w 30 target.com ssh
# Error de demasiadas conexiones
hydra -l admin -P contraseñas.txt -t 2 target.com ssh
# Optimización del uso de memoria
hydra -l admin -P lista_pequeña.txt target.com ssh
# Revisar protocolos soportados
hydra
# Buscar el protocolo en la lista de servicios soportados
```

### Optimización del Rendimiento

Optimiza las listas de contraseñas y ordénalas por probabilidad para obtener resultados más rápidos.

```bash
# Ordenar contraseñas por probabilidad
hydra -l admin -P contraseñas.txt -u target.com ssh
# Eliminar duplicados
sort contraseñas.txt | uniq > contraseñas_limpias.txt
# Optimizar subprocesamiento basado en el objetivo
# Red local: -t 16
# Objetivo en Internet: -t 4
# Servicio lento: -t 1
```

### Formatos de Salida y Análisis

Diferentes formatos de salida para el análisis de resultados y la elaboración de informes.

```bash
# Salida de texto estándar
hydra -l admin -P contraseñas.txt target.com ssh -o resultados.txt
# Formato JSON para análisis
hydra -l admin -P contraseñas.txt target.com ssh -b json -o resultados.json
# Salida detallada para depuración
hydra -l admin -P contraseñas.txt target.com ssh -V
# Salida solo de éxito
hydra -l admin -P contraseñas.txt target.com ssh | grep "password:"
```

### Monitoreo de Recursos

Monitorea los recursos del sistema y de la red durante los ataques.

```bash
# Monitorear uso de CPU
top -p $(pidof hydra)
# Monitorear conexiones de red
netstat -an | grep :22
# Monitorear uso de memoria
ps aux | grep hydra
# Limitar el impacto en el sistema
nice -n 19 hydra -l admin -P contraseñas.txt target.com ssh
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

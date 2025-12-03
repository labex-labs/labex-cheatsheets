---
title: 'Hoja de Trucos de Nmap | LabEx'
description: 'Aprenda escaneo de redes con Nmap usando esta hoja de trucos completa. Referencia rápida para escaneo de puertos, descubrimiento de redes, detección de vulnerabilidades, auditoría de seguridad y reconocimiento de red.'
pdfUrl: '/cheatsheets/pdf/nmap-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Nmap
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/nmap">Aprende Nmap con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende el escaneo de redes con Nmap a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Nmap que cubren descubrimiento de redes esencial, escaneo de puertos, detección de servicios, huella digital de SO y evaluación de vulnerabilidades. Domina las técnicas de reconocimiento de redes y auditoría de seguridad.
</base-disclaimer-content>
</base-disclaimer>

## Instalación y Configuración

### Instalación en Linux

Instala Nmap usando el gestor de paquetes de tu distribución.

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap
# RHEL/Fedora/CentOS
sudo dnf install nmap
# Verificar instalación
nmap --version
```

### Instalación en macOS

Instala usando el gestor de paquetes Homebrew.

```bash
# Instalar vía Homebrew
brew install nmap
# Descarga directa desde nmap.org
# Descargar .dmg desde https://nmap.org/download.html
```

### Instalación en Windows

Descarga e instala desde el sitio web oficial.

```bash
# Descargar instalador desde
https://nmap.org/download.html
# Ejecutar el instalador .exe con privilegios de administrador
# Incluye la GUI Zenmap y la versión de línea de comandos
```

### Verificación Básica

Prueba tu instalación y obtén ayuda.

```bash
# Mostrar información de la versión
nmap --version
# Mostrar menú de ayuda
nmap -h
# Ayuda extendida y opciones
man nmap
```

## Técnicas Básicas de Escaneo

### Escaneo Simple de Host: `nmap [objetivo]`

Escaneo básico de un host o dirección IP individual.

```bash
# Escanear IP individual
nmap 192.168.1.1
# Escanear nombre de host
nmap example.com
# Escanear múltiples IPs
nmap 192.168.1.1 192.168.1.5
192.168.1.10
```

<BaseQuiz id="nmap-scan-1" correct="A">
  <template #question>
    ¿Qué hace un escaneo básico de <code>nmap 192.168.1.1</code> por defecto?
  </template>
  
  <BaseQuizOption value="A" correct>Escanea los 1000 puertos TCP más comunes</BaseQuizOption>
  <BaseQuizOption value="B">Escanea los 65535 puertos</BaseQuizOption>
  <BaseQuizOption value="C">Solo realiza descubrimiento de host</BaseQuizOption>
  <BaseQuizOption value="D">Escanea solo el puerto 80</BaseQuizOption>
  
  <BaseQuizAnswer>
    Por defecto, Nmap escanea los 1000 puertos TCP más comunes. Para escanear todos los puertos, usa <code>-p-</code>, o especifica puertos concretos con <code>-p 80,443,22</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### Escaneo de Rango de Red

Nmap permite nombres de host, direcciones IP, subredes.

```bash
# Escanear rango de IP
nmap 192.168.1.1-254
# Escanear subred con notación CIDR
nmap 192.168.1.0/24
# Escanear múltiples redes
nmap 192.168.1.0/24 10.0.0.0/8
```

### Entrada desde Archivo

Escanear objetivos listados en un archivo.

```bash
# Leer objetivos desde archivo
nmap -iL targets.txt
# Excluir hosts específicos
nmap 192.168.1.0/24 --exclude
192.168.1.1
# Excluir desde archivo
nmap 192.168.1.0/24 --excludefile
exclude.txt
```

## Técnicas de Descubrimiento de Hosts

### Escaneo Ping: `nmap -sn`

El descubrimiento de hosts es una forma clave en que muchos analistas y pentesters usan Nmap. Su propósito es obtener una visión general de qué sistemas están en línea.

```bash
# Solo escaneo ping (sin escaneo de puertos)
nmap -sn 192.168.1.0/24
# Omitir descubrimiento de host (asumir que todos los hosts están activos)
nmap -Pn 192.168.1.1
# Ping de eco ICMP
nmap -PE 192.168.1.0/24
```

<BaseQuiz id="nmap-ping-1" correct="A">
  <template #question>
    ¿Qué hace <code>nmap -sn</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Realiza solo descubrimiento de host, sin escaneo de puertos</BaseQuizOption>
  <BaseQuizOption value="B">Escanea todos los puertos del objetivo</BaseQuizOption>
  <BaseQuizOption value="C">Realiza un escaneo sigiloso</BaseQuizOption>
  <BaseQuizOption value="D">Escanea solo puertos UDP</BaseQuizOption>
  
  <BaseQuizAnswer>
    El flag <code>-sn</code> le indica a Nmap que realice solo el descubrimiento de host (escaneo ping), sin escanear puertos. Esto es útil para identificar rápidamente qué hosts están en línea en una red.
  </BaseQuizAnswer>
</BaseQuiz>

### Técnicas de Ping TCP

Usa paquetes TCP para el descubrimiento de hosts.

```bash
# Ping TCP SYN al puerto 80
nmap -PS80 192.168.1.0/24
# Ping TCP ACK
nmap -PA80 192.168.1.0/24
# Ping TCP SYN a múltiples puertos
nmap -PS22,80,443 192.168.1.0/24
```

### Ping UDP: `nmap -PU`

Usa paquetes UDP para el descubrimiento de hosts.

```bash
# Ping UDP a puertos comunes
nmap -PU53,67,68,137 192.168.1.0/24
```

<BaseQuiz id="nmap-udp-1" correct="B">
  <template #question>
    ¿Por qué podrías usar ping UDP en lugar de ping ICMP?
  </template>
  
  <BaseQuizOption value="A">El ping UDP siempre es más rápido</BaseQuizOption>
  <BaseQuizOption value="B" correct>Algunas redes bloquean ICMP pero permiten paquetes UDP</BaseQuizOption>
  <BaseQuizOption value="C">El ping UDP escanea puertos automáticamente</BaseQuizOption>
  <BaseQuizOption value="D">El ping UDP solo funciona en redes locales</BaseQuizOption>
  
  <BaseQuizAnswer>
    El ping UDP puede ser útil cuando los firewalls bloquean ICMP. Muchas redes permiten paquetes UDP a puertos comunes (como el puerto 53 de DNS) incluso cuando ICMP está filtrado, haciendo que el ping UDP sea efectivo para el descubrimiento de hosts.
  </BaseQuizAnswer>
</BaseQuiz>
# Ping UDP a puertos por defecto
nmap -PU 192.168.1.0/24
```

### Ping ARP: `nmap -PR`

Usa solicitudes ARP para el descubrimiento de redes locales.

```bash
# Ping ARP (por defecto para redes locales)
nmap -PR 192.168.1.0/24
# Deshabilitar ping ARP
nmap --disable-arp-ping 192.168.1.0/24
```

## Tipos de Escaneo de Puertos

### Escaneo SYN TCP: `nmap -sS`

Este escaneo es más sigiloso, ya que Nmap envía un paquete RST, lo que evita múltiples solicitudes y acorta el tiempo de escaneo.

```bash
# Escaneo por defecto (requiere root)
nmap -sS 192.168.1.1
# Escaneo SYN a puertos específicos
nmap -sS -p 80,443 192.168.1.1
# Escaneo SYN rápido
nmap -sS -T4 192.168.1.1
```

### Escaneo Connect TCP: `nmap -sT`

Nmap envía un paquete TCP al puerto con el flag SYN establecido. Esto permite al usuario saber si los puertos están abiertos, cerrados o desconocidos.

```bash
# Escaneo connect TCP (no requiere root)
nmap -sT 192.168.1.1
# Escaneo connect con temporización
nmap -sT -T3 192.168.1.1
```

### Escaneo UDP: `nmap -sU`

Escanea puertos UDP en busca de servicios.

```bash
# Escaneo UDP (lento, requiere root)
nmap -sU 192.168.1.1
# Escaneo UDP de puertos comunes
nmap -sU -p 53,67,68,161 192.168.1.1
# Escaneo combinado TCP/UDP
nmap -sS -sU -p T:80,443,U:53,161 192.168.1.1
```

### Escaneos Sigilosos

Técnicas de escaneo avanzadas para evasión.

```bash
# Escaneo FIN
nmap -sF 192.168.1.1
# Escaneo NULL
nmap -sN 192.168.1.1
# Escaneo Xmas
nmap -sX 192.168.1.1
```

## Especificación de Puertos

### Rangos de Puertos: `nmap -p`

Dirigirse a puertos específicos, rangos o combinaciones de puertos TCP y UDP para escaneos más precisos.

```bash
# Puerto único
nmap -p 80 192.168.1.1
# Múltiples puertos
nmap -p 22,80,443 192.168.1.1
# Rango de puertos
nmap -p 1-1000 192.168.1.1
# Todos los puertos
nmap -p- 192.168.1.1
```

### Puertos Específicos de Protocolo

Especificar puertos TCP o UDP explícitamente.

```bash
# Solo puertos TCP
nmap -p T:80,443 192.168.1.1
# Solo puertos UDP
nmap -p U:53,161 192.168.1.1
# TCP y UDP mixtos
nmap -p T:80,U:53 192.168.1.1
```

### Conjuntos de Puertos Comunes

Escanear puertos usados frecuentemente rápidamente.

```bash
# Top 1000 puertos (por defecto)
nmap 192.168.1.1
# Top 100 puertos
nmap --top-ports 100 192.168.1.1
# Escaneo rápido (100 puertos más comunes)
nmap -F 192.168.1.1
# Mostrar solo puertos abiertos
nmap --open 192.168.1.1
# Mostrar todos los estados de puerto
nmap -v 192.168.1.1
```

## Detección de Servicio y Versión

### Detección de Servicio: `nmap -sV`

Detectar qué servicios se están ejecutando e intentar identificar su software, versiones y configuraciones.

```bash
# Detección de versión básica
nmap -sV 192.168.1.1
# Detección de versión agresiva
nmap -sV --version-intensity 9 192.168.1.1
# Detección de versión ligera
nmap -sV --version-intensity 0 192.168.1.1
# Scripts por defecto con detección de versión
nmap -sC -sV 192.168.1.1
```

### Scripts de Servicio

Usar scripts para una detección de servicio mejorada.

```bash
# Captura de banner
nmap --script banner 192.168.1.1
# Enumeración de servicio HTTP
nmap --script http-* 192.168.1.1
```

### Detección de Sistema Operativo: `nmap -O`

Usar huella digital TCP/IP para adivinar el sistema operativo de los hosts objetivo.

```bash
# Detección de SO
nmap -O 192.168.1.1
# Detección de SO agresiva
nmap -O --osscan-guess 192.168.1.1
# Limitar intentos de detección de SO
nmap -O --max-os-tries 1 192.168.1.1
```

### Detección Integral

Combinar múltiples técnicas de detección.

```bash
# Escaneo agresivo (SO, versión, scripts)
nmap -A 192.168.1.1
# Escaneo agresivo personalizado
nmap -sS -sV -O -sC 192.168.1.1
```

## Temporización y Rendimiento

### Plantillas de Temporización: `nmap -T`

Ajusta la velocidad del escaneo y el sigilo según tu entorno objetivo y el riesgo de detección.

```bash
# Paranoico (muy lento, sigiloso)
nmap -T0 192.168.1.1
# Astuto (lento, sigiloso)
nmap -T1 192.168.1.1
# Cortés (más lento, menos ancho de banda)
nmap -T2 192.168.1.1
# Normal (por defecto)
nmap -T3 192.168.1.1
# Agresivo (más rápido)
nmap -T4 192.168.1.1
# Insano (muy rápido, puede perder resultados)
nmap -T5 192.168.1.1
```

### Opciones de Temporización Personalizadas

Ajusta cómo Nmap maneja los tiempos de espera, reintentos y escaneo paralelo para optimizar el rendimiento.

```bash
# Establecer tasa mínima (paquetes por segundo)
nmap --min-rate 1000 192.168.1.1
# Establecer tasa máxima
nmap --max-rate 100 192.168.1.1
# Escaneo paralelo de hosts
nmap --min-hostgroup 10 192.168.1.0/24
# Tiempo de espera personalizado
nmap --host-timeout 5m 192.168.1.1
```

## Motor de Scripts de Nmap (NSE)

### Categorías de Scripts: `nmap --script`

Ejecutar scripts por categoría o nombre.

```bash
# Scripts por defecto
nmap --script default 192.168.1.1
# Scripts de vulnerabilidad
nmap --script vuln 192.168.1.1
# Scripts de descubrimiento
nmap --script discovery 192.168.1.1
# Scripts de autenticación
nmap --script auth 192.168.1.1
```

### Scripts Específicos

Dirigirse a vulnerabilidades o servicios específicos.

```bash
# Enumeración SMB
nmap --script smb-enum-* 192.168.1.1
# Métodos HTTP
nmap --script http-methods 192.168.1.1
# Información de certificado SSL
nmap --script ssl-cert 192.168.1.1
```

### Argumentos de Script

Pasar argumentos para personalizar el comportamiento del script.

```bash
# Fuerza bruta HTTP con lista de palabras personalizada
nmap --script http-brute --script-args
userdb=users.txt,passdb=pass.txt 192.168.1.1
# Fuerza bruta SMB
nmap --script smb-brute 192.168.1.1
# Fuerza bruta DNS
nmap --script dns-brute example.com
```

### Gestión de Scripts

Administrar y actualizar scripts NSE.

```bash
# Actualizar base de datos de scripts
nmap --script-updatedb
# Listar scripts disponibles
ls /usr/share/nmap/scripts/ | grep http
# Obtener ayuda del script
nmap --script-help vuln
```

## Formatos de Salida y Guardado de Resultados

### Formatos de Salida

Guardar resultados en diferentes formatos.

```bash
# Salida normal
nmap -oN scan_results.txt 192.168.1.1
# Salida XML
nmap -oX scan_results.xml 192.168.1.1
# Salida apta para grep
nmap -oG scan_results.gnmap 192.168.1.1
# Todos los formatos
nmap -oA scan_results 192.168.1.1
```

### Salida Detallada (Verbose)

Controlar la cantidad de información mostrada.

```bash
# Salida detallada
nmap -v 192.168.1.1
# Muy detallada
nmap -vv 192.168.1.1
# Modo depuración
nmap --packet-trace 192.168.1.1
```

### Reanudar y Anexar

Continuar o añadir a escaneos previos.

```bash
# Reanudar escaneo interrumpido
nmap --resume scan_results.gnmap
# Anexar a archivo existente
nmap --append-output -oN existing_scan.txt 192.168.1.1
```

### Procesamiento de Resultados en Vivo

Combinar la salida de Nmap con herramientas de línea de comandos para extraer información útil.

```bash
# Extraer hosts activos
nmap -sn 192.168.1.0/24 | grep "Nmap scan report"
# Encontrar servidores web
nmap -p 80,443 --open 192.168.1.0/24 | grep "open"
# Exportar a CSV
nmap -oX - 192.168.1.1 | xsltproc --html -
```

## Técnicas de Evasión de Firewall

### Fragmentación de Paquetes: `nmap -f`

Evadir medidas de seguridad usando fragmentación de paquetes, IPs falsificadas y métodos de escaneo sigilosos.

```bash
# Fragmentar paquetes
nmap -f 192.168.1.1
# Tamaño de MTU personalizado
nmap --mtu 16 192.168.1.1
# Unidad máxima de transmisión
nmap --mtu 24 192.168.1.1
```

### Escaneo con Señuelos (Decoy): `nmap -D`

Ocultar tu escaneo entre direcciones IP señuelo.

```bash
# Usar IPs señuelo
nmap -D 192.168.1.100,192.168.1.101 192.168.1.1
# Señuelos aleatorios
nmap -D RND:5 192.168.1.1
# Mezclar señuelos reales y aleatorios
nmap -D 192.168.1.100,RND:3 192.168.1.1
```

### Manipulación de IP/Puerto de Origen

Falsificar información de origen.

```bash
# Falsificar IP de origen
nmap -S 192.168.1.100 192.168.1.1
# Puerto de origen personalizado
nmap --source-port 53 192.168.1.1
# Longitud de datos aleatoria
nmap --data-length 25 192.168.1.1
```

### Escaneo Inactivo/Zombie: `nmap -sI`

Usar un host zombie para ocultar el origen del escaneo.

```bash
# Escaneo zombie (requiere host inactivo)
nmap -sI zombie_host 192.168.1.1
# Listar candidatos inactivos
nmap --script ipidseq 192.168.1.0/24
```

## Opciones Avanzadas de Escaneo

### Control de Resolución DNS

Controlar cómo Nmap maneja las búsquedas DNS.

```bash
# Deshabilitar resolución DNS
nmap -n 192.168.1.1
# Forzar resolución DNS
nmap -R 192.168.1.1
# Servidores DNS personalizados
nmap --dns-servers 8.8.8.8,1.1.1.1 192.168.1.1
```

### Escaneo IPv6: `nmap -6`

Usa estos flags de Nmap para funcionalidad adicional como soporte IPv6.

```bash
# Escaneo IPv6
nmap -6 2001:db8::1
# Escaneo de red IPv6
nmap -6 2001:db8::/32
```

### Interfaz y Enrutamiento

Controlar la interfaz de red y el enrutamiento.

```bash
# Especificar interfaz de red
nmap -e eth0 192.168.1.1
# Imprimir interfaz y rutas
nmap --iflist
# Trazado de ruta (Traceroute)
nmap --traceroute 192.168.1.1
```

### Opciones Misceláneas

Flags adicionales útiles.

```bash
# Imprimir versión y salir
nmap --version
# Enviar en nivel ethernet
nmap --send-eth 192.168.1.1
# Enviar en nivel IP
nmap --send-ip 192.168.1.1
```

## Ejemplos del Mundo Real

### Flujo de Trabajo de Descubrimiento de Red

Proceso completo de enumeración de red.

```bash
# Paso 1: Descubrir hosts activos
nmap -sn 192.168.1.0/24
# Paso 2: Escaneo rápido de puertos
nmap -sS -T4 --top-ports 1000 192.168.1.0/24
# Paso 3: Escaneo detallado de hosts interesantes
nmap -sS -sV -sC -O 192.168.1.50
# Paso 4: Escaneo exhaustivo
nmap -p- -A -T4 192.168.1.50
```

### Evaluación de Servidores Web

Enfocarse en servicios web y vulnerabilidades.

```bash
# Encontrar servidores web
nmap -sS -p 80,443,8080,8443 --open 192.168.1.0/24
# Enumerar servicios HTTP
nmap -sS -sV --script http-* 192.168.1.50
# Comprobar vulnerabilidades comunes
nmap --script vuln -p 80,443 192.168.1.50
```

### Enumeración SMB/NetBIOS

El siguiente ejemplo enumera Netbios en las redes objetivo.

```bash
# Detección de servicio SMB
nmap -sV -p 139,445 192.168.1.0/24
# Descubrimiento de nombre NetBIOS
nmap -sU --script nbstat -p 137 192.168.1.0/24
# Scripts de enumeración SMB
nmap --script smb-enum-* -p 445 192.168.1.50
# Comprobación de vulnerabilidad SMB
nmap --script smb-vuln-* -p 445 192.168.1.50
```

### Evaluación Sigilosa

Reconocimiento de bajo perfil.

```bash
# Escaneo ultra-sigiloso
nmap -sS -T0 -f --data-length 200 -D RND:10 192.168.1.1
# Escaneo SYN fragmentado
nmap -sS -f --mtu 8 -T1 192.168.1.1
```

## Optimización del Rendimiento

### Estrategias de Escaneo Rápido

Optimizar la velocidad del escaneo para redes grandes.

```bash
# Barrido rápido de red
nmap -sS -T4 --min-rate 1000 --max-retries 1
192.168.1.0/24
# Escaneo paralelo de hosts
nmap --min-hostgroup 50 --max-hostgroup 100
192.168.1.0/24
# Omitir operaciones lentas
nmap -sS -T4 --defeat-rst-ratelimit 192.168.1.0/24
```

### Gestión de Memoria y Recursos

Controlar el uso de recursos para la estabilidad.

```bash
# Limitar sondeos paralelos
nmap --max-parallelism 10 192.168.1.0/24
# Controlar retrasos de escaneo
nmap --scan-delay 100ms 192.168.1.1
# Tiempo de espera del host
nmap --host-timeout 10m 192.168.1.0/24
```

## Enlaces Relevantes

- <router-link to="/wireshark">Hoja de Trucos de Wireshark</router-link>
- <router-link to="/kali">Hoja de Trucos de Kali Linux</router-link>
- <router-link to="/cybersecurity">Hoja de Trucos de Ciberseguridad</router-link>
- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/network">Hoja de Trucos de Redes</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>

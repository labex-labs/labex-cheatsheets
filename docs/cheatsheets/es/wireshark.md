---
title: 'Hoja de Trucos de Wireshark | LabEx'
description: 'Aprenda análisis de red con Wireshark usando esta hoja de trucos completa. Referencia rápida para captura de paquetes, análisis de protocolos de red, inspección de tráfico, solución de problemas y monitoreo de seguridad de red.'
pdfUrl: '/cheatsheets/pdf/wireshark-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Wireshark
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/wireshark">Aprenda Wireshark con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda el análisis de paquetes de red con Wireshark a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Wireshark que cubren captura de paquetes esencial, filtros de visualización, análisis de protocolos, solución de problemas de red y monitoreo de seguridad. Domine las técnicas de análisis de tráfico de red e inspección de paquetes.
</base-disclaimer-content>
</base-disclaimer>

## Filtros de Captura y Captura de Tráfico

### Filtrado por Host

Capturar tráfico hacia/desde hosts específicos.

```bash
# Capturar tráfico desde/hacia IP específica
host 192.168.1.100
# Capturar tráfico desde fuente específica
src host 192.168.1.100
# Capturar tráfico hacia destino específico
dst host 192.168.1.100
# Capturar tráfico desde subred
net 192.168.1.0/24
```

<BaseQuiz id="wireshark-filter-1" correct="A">
  <template #question>
    ¿Qué filtra <code>host 192.168.1.100</code> en Wireshark?
  </template>
  
  <BaseQuizOption value="A" correct>Todo el tráfico hacia o desde 192.168.1.100</BaseQuizOption>
  <BaseQuizOption value="B">Solo el tráfico desde 192.168.1.100</BaseQuizOption>
  <BaseQuizOption value="C">Solo el tráfico hacia 192.168.1.100</BaseQuizOption>
  <BaseQuizOption value="D">Tráfico en el puerto 192.168.1.100</BaseQuizOption>
  
  <BaseQuizAnswer>
    El filtro <code>host</code> captura todo el tráfico donde la dirección IP especificada es la fuente o el destino. Use <code>src host</code> para solo fuente o <code>dst host</code> para solo destino.
  </BaseQuizAnswer>
</BaseQuiz>

### Filtrado por Puerto

Capturar tráfico en puertos específicos.

```bash
# Tráfico HTTP (puerto 80)
port 80
# Tráfico HTTPS (puerto 443)
port 443
# Tráfico SSH (puerto 22)
port 22
# Tráfico DNS (puerto 53)
port 53
# Rango de puertos
portrange 1000-2000
```

<BaseQuiz id="wireshark-port-1" correct="D">
  <template #question>
    ¿Qué filtra <code>port 80</code> en Wireshark?
  </template>
  
  <BaseQuizOption value="A">Solo solicitudes HTTP</BaseQuizOption>
  <BaseQuizOption value="B">Solo respuestas HTTP</BaseQuizOption>
  <BaseQuizOption value="C">Solo paquetes TCP</BaseQuizOption>
  <BaseQuizOption value="D" correct>Todo el tráfico en el puerto 80 (tanto fuente como destino)</BaseQuizOption>
  
  <BaseQuizAnswer>
    El filtro <code>port</code> captura todo el tráfico donde el puerto 80 es el puerto de origen o destino. Esto incluye tanto las solicitudes como las respuestas HTTP, así como cualquier otro tráfico que utilice el puerto 80.
  </BaseQuizAnswer>
</BaseQuiz>

### Filtrado por Protocolo

Capturar tráfico de protocolos específicos.

```bash
# Solo tráfico TCP
tcp
# Solo tráfico UDP
udp
# Solo tráfico ICMP
icmp
# Solo tráfico ARP
arp
```

### Filtros de Captura Avanzados

Combine múltiples condiciones para una captura precisa.

```bash
# Tráfico HTTP hacia/desde host específico
host 192.168.1.100 and port 80
# Tráfico TCP excepto SSH
tcp and not port 22
# Tráfico entre dos hosts
host 192.168.1.100 and host 192.168.1.200
# Tráfico HTTP o HTTPS
port 80 or port 443
```

<BaseQuiz id="wireshark-advanced-1" correct="B">
  <template #question>
    ¿Qué captura <code>tcp and not port 22</code>?
  </template>
  
  <BaseQuizOption value="A">Solo tráfico SSH</BaseQuizOption>
  <BaseQuizOption value="B" correct>Todo el tráfico TCP excepto SSH (puerto 22)</BaseQuizOption>
  <BaseQuizOption value="C">Tráfico UDP en el puerto 22</BaseQuizOption>
  <BaseQuizOption value="D">Todo el tráfico de red</BaseQuizOption>
  
  <BaseQuizAnswer>
    Este filtro captura todo el tráfico TCP pero excluye los paquetes en el puerto 22 (SSH). El operador <code>and not</code> excluye el puerto especificado mientras mantiene todo el demás tráfico TCP.
  </BaseQuizAnswer>
</BaseQuiz>

### Selección de Interfaz

Elegir interfaces de red para la captura.

```bash
# Listar interfaces disponibles
tshark -D
# Capturar en interfaz específica
# Interfaz Ethernet
eth0
# Interfaz WiFi
wlan0
# Interfaz de loopback
lo
```

### Opciones de Captura

Configurar parámetros de captura.

```bash
# Limitar el tamaño del archivo de captura (MB)
-a filesize:100
# Limitar la duración de la captura (segundos)
-a duration:300
# Búfer en anillo con 10 archivos
-b files:10
# Modo promiscuo (capturar todo el tráfico)
-p
```

## Filtros de Visualización y Análisis de Paquetes

### Filtros de Visualización Básicos

Filtros esenciales para protocolos comunes y tipos de tráfico.

```bash
# Mostrar solo tráfico HTTP
http
# Mostrar solo tráfico HTTPS/TLS
tls
# Mostrar solo tráfico DNS
dns
# Mostrar solo tráfico TCP
tcp
# Mostrar solo tráfico UDP
udp
# Mostrar solo tráfico ICMP
icmp
```

### Filtrado por Dirección IP

Filtrar paquetes por direcciones IP de origen y destino.

```bash
# Tráfico desde IP específica
ip.src == 192.168.1.100
# Tráfico hacia IP específica
ip.dst == 192.168.1.200
# Tráfico entre dos IPs
ip.addr == 192.168.1.100
# Tráfico desde subred
ip.src_net == 192.168.1.0/24
# Excluir IP específica
not ip.addr == 192.168.1.1
```

### Filtrado por Puerto y Protocolo

Filtrar por puertos y detalles de protocolo específicos.

```bash
# Tráfico en puerto específico
tcp.port == 80
# Filtro de puerto de origen
tcp.srcport == 443
# Filtro de puerto de destino
tcp.dstport == 22
# Rango de puertos
tcp.port >= 1000 and tcp.port <=
2000
# Múltiples puertos
tcp.port in {80 443 8080}
```

## Análisis Específico de Protocolos

### Análisis HTTP

Analizar solicitudes y respuestas HTTP.

```bash
# Solicitudes GET HTTP
http.request.method == "GET"
# Solicitudes POST HTTP
http.request.method == "POST"
# Códigos de estado HTTP específicos
http.response.code == 404
# Solicitudes HTTP a host específico
http.host == "example.com"
# Solicitudes HTTP que contienen cadena
http contains "login"
```

### Análisis DNS

Examinar consultas y respuestas DNS.

```bash
# Solo consultas DNS
dns.flags.response == 0
# Solo respuestas DNS
dns.flags.response == 1
# Consultas DNS para dominio específico
dns.qry.name == "example.com"
# Consultas DNS tipo A
dns.qry.type == 1
# Errores/fallos DNS
dns.flags.rcode != 0
```

### Análisis TCP

Analizar detalles de la conexión TCP.

```bash
# Paquetes TCP SYN (intentos de conexión)
tcp.flags.syn == 1
# Paquetes TCP RST (reinicios de conexión)
tcp.flags.reset == 1
# Retransmisiones TCP
tcp.analysis.retransmission
# Problemas de ventana TCP
tcp.analysis.window_update
# Establecimiento de conexión TCP
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### Análisis TLS/SSL

Examinar detalles de la conexión cifrada.

```bash
# Paquetes de handshake TLS
tls.handshake
# Información de certificado TLS
tls.handshake.certificate
# Alertas y errores TLS
tls.alert
# Versión TLS específica
tls.handshake.version == 0x0303
# Server Name Indication TLS
tls.handshake.extensions_server_name
```

### Solución de Problemas de Red

Identificar problemas comunes de red.

```bash
# Mensajes ICMP inalcanzable
icmp.type == 3
# Solicitudes/respuestas ARP
arp.opcode == 1 or arp.opcode == 2
# Tráfico de difusión (broadcast)
eth.dst == ff:ff:ff:ff:ff:ff
# Paquetes fragmentados
ip.flags.mf == 1
# Paquetes grandes (problemas potenciales de MTU)
frame.len > 1500
```

### Filtrado Basado en Tiempo

Filtrar paquetes por marca de tiempo y temporización.

```bash
# Paquetes dentro del rango de tiempo
frame.time >= "2024-01-01 10:00:00"
# Paquetes de la última hora
frame.time_relative >= -3600
# Análisis de tiempo de respuesta
tcp.time_delta > 1.0
# Tiempo entre llegadas
frame.time_delta > 0.1
```

## Estadísticas y Herramientas de Análisis

### Jerarquía de Protocolos

Ver la distribución de protocolos en la captura.

```bash
# Acceder a través de: Estadísticas > Jerarquía de Protocolos
# Muestra el porcentaje de cada protocolo
# Identifica los protocolos más comunes
# Útil para la visión general del tráfico
# Equivalente en línea de comandos
tshark -r capture.pcap -q -z io,phs
```

### Conversaciones

Analizar la comunicación entre endpoints.

```bash
# Acceder a través de: Estadísticas > Conversaciones
# Conversaciones Ethernet
# Conversaciones IPv4/IPv6
# Conversaciones TCP/UDP
# Muestra bytes transferidos, recuento de paquetes
# Equivalente en línea de comandos
tshark -r capture.pcap -q -z conv,tcp
```

### Gráficos de E/S (I/O Graphs)

Visualizar patrones de tráfico a lo largo del tiempo.

```bash
# Acceder a través de: Estadísticas > Gráficos de E/S
# Volumen de tráfico a lo largo del tiempo
# Paquetes por segundo
# Bytes por segundo
# Aplicar filtros para tráfico específico
# Útil para identificar picos de tráfico
```

### Información Experta

Identificar posibles problemas de red.

```bash
# Acceder a través de: Analizar > Información Experta
# Advertencias sobre problemas de red
# Errores en la transmisión de paquetes
# Problemas de rendimiento
# Preocupaciones de seguridad
# Filtrar por severidad de información experta
tcp.analysis.flags
```

### Gráficos de Flujo (Flow Graphs)

Visualizar la secuencia de paquetes entre endpoints.

```bash
# Acceder a través de: Estadísticas > Gráfico de Flujo
# Muestra la secuencia de paquetes
# Visualización basada en el tiempo
# Útil para la solución de problemas
# Identifica patrones de comunicación
```

### Análisis de Tiempo de Respuesta

Medir los tiempos de respuesta de las aplicaciones.

```bash
# Tiempos de respuesta HTTP
# Estadísticas > HTTP > Solicitudes
# Tiempos de respuesta DNS
# Estadísticas > DNS
# Tiempo de respuesta del servicio TCP
# Estadísticas > Gráficos de Secuencia de Tiempo TCP > Flujo TCP
```

## Operaciones y Exportación de Archivos

### Guardar y Cargar Capturas

Administrar archivos de captura en varios formatos.

```bash
# Guardar archivo de captura
# Archivo > Guardar como > capture.pcap
# Cargar archivo de captura
# Archivo > Abrir > existing.pcap
# Fusionar múltiples archivos de captura
# Archivo > Fusionar > seleccionar archivos
# Guardar solo paquetes filtrados
# Archivo > Exportar Paquetes Especificados
```

### Opciones de Exportación

Exportar datos específicos o subconjuntos de paquetes.

```bash
# Exportar paquetes seleccionados
# Archivo > Exportar Paquetes Especificados
# Exportar disecciones de paquetes
# Archivo > Exportar Disección de Paquetes
# Exportar objetos desde HTTP
# Archivo > Exportar Objetos > HTTP
# Exportar claves SSL/TLS
# Editar > Preferencias > Protocolos > TLS
```

### Captura en Línea de Comandos

Usar tshark para captura y análisis automatizados.

```bash
# Capturar a archivo
tshark -i eth0 -w capture.pcap
# Capturar con filtro
tshark -i eth0 -f "port 80" -w http.pcap
# Leer y mostrar paquetes
tshark -r capture.pcap
# Aplicar filtro de visualización al archivo
tshark -r capture.pcap -Y "tcp.port == 80"
```

### Procesamiento por Lotes

Procesar múltiples archivos de captura automáticamente.

```bash
# Fusionar múltiples archivos
mergecap -w merged.pcap file1.pcap file2.pcap
# Dividir archivos de captura grandes
editcap -c 1000 large.pcap split.pcap
# Extraer rango de tiempo
editcap -A "2024-01-01 10:00:00" \
        -B "2024-01-01 11:00:00" \
        input.pcap output.pcap
```

## Rendimiento y Optimización

### Gestión de Memoria

Manejar archivos de captura grandes de manera eficiente.

```bash
# Usar búfer en anillo para captura continua
-b filesize:100 -b files:10
# Limitar el tamaño de captura de paquetes
-s 96  # Capturar solo los primeros 96 bytes
# Usar filtros de captura para reducir datos
host 192.168.1.100 and port 80
# Deshabilitar la disección de protocolos para velocidad
-d tcp.port==80,http
```

### Optimización de Visualización

Mejorar el rendimiento de la GUI con grandes conjuntos de datos.

```bash
# Preferencias a ajustar:
# Editar > Preferencias > Apariencia
# Selección de esquema de color
# Tamaño y tipo de fuente
# Opciones de visualización de columnas
# Configuración del formato de tiempo
# Ver > Formato de Visualización de Tiempo
# Segundos desde el inicio de la captura
# Hora del día
# Hora UTC
```

### Flujo de Trabajo de Análisis Eficiente

Mejores prácticas para analizar tráfico de red.

```bash
# 1. Comenzar con filtros de captura
# Capturar solo el tráfico relevante
# 2. Usar filtros de visualización progresivamente
# Empezar amplio, luego estrechar
# 3. Usar estadísticas primero
# Obtener una visión general antes del análisis detallado
# 4. Enfocarse en flujos específicos
# Clic derecho en paquete > Seguir > Flujo TCP
```

### Automatización y Scripting

Automatizar tareas comunes de análisis.

```bash
# Crear botones de filtro de visualización personalizados
# Ver > Expresión de Filtro de Visualización
# Usar perfiles para diferentes escenarios
# Editar > Perfiles de Configuración
# Scripting con tshark
#!/bin/bash
tshark -r $1 -q -z endpoints,tcp | \
grep -v "Filter:" | head -20
```

## Instalación y Configuración

### Instalación en Windows

Descargar e instalar desde el sitio web oficial.

```bash
# Descargar desde wireshark.org
# Ejecutar instalador como Administrador
# Incluir WinPcap/Npcap
durante la instalación
# Instalación en línea de comandos
(chocolatey)
choco install wireshark
# Verificar instalación
wireshark --version
```

### Instalación en Linux

Instalar a través del gestor de paquetes o desde el código fuente.

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install wireshark
# Red Hat/CentOS/Fedora
sudo yum install wireshark
# o
sudo dnf install wireshark
# Añadir usuario al grupo wireshark
sudo usermod -a -G wireshark
$USER
```

### Instalación en macOS

Instalar usando Homebrew o el instalador oficial.

```bash
# Usando Homebrew
brew install --cask wireshark
# Descargar desde wireshark.org
# Instalar paquete .dmg
# Herramientas de línea de comandos
brew install wireshark
```

## Configuración y Preferencias

### Preferencias de Interfaz

Configurar interfaces de captura y opciones.

```bash
# Editar > Preferencias > Captura
# Interfaz de captura predeterminada
# Configuración del modo promiscuo
# Configuración del tamaño del búfer
# Desplazamiento automático en captura en vivo
# Configuración específica de la interfaz
# Captura > Opciones > Detalles de la Interfaz
```

### Configuración de Protocolos

Configurar diseccionadores de protocolos y decodificación.

```bash
# Editar > Preferencias > Protocolos
# Habilitar/deshabilitar diseccionadores de protocolos
# Asignación de puertos de configuración
# Claves de descifrado (TLS, WEP, etc.)
# Opciones de reensamblaje TCP
# Funcionalidad Decodificar Como
# Analizar > Decodificar Como
```

### Preferencias de Visualización

Personalizar la interfaz de usuario y las opciones de visualización.

```bash
# Editar > Preferencias > Apariencia
# Selección de esquema de color
# Tamaño y tipo de fuente
# Opciones de visualización de columnas
# Configuración del formato de tiempo
# Ver > Formato de Visualización de Tiempo
# Segundos desde el inicio de la captura
# Hora del día
# Hora UTC
```

### Configuración de Seguridad

Configurar opciones relacionadas con la seguridad y el descifrado.

```bash
# Configuración de descifrado TLS
# Editar > Preferencias > Protocolos > TLS
# Lista de claves RSA
# Claves precompartidas
# Ubicación del archivo de registro de claves
# Deshabilitar características potencialmente peligrosas
# Ejecución de scripts Lua
# Resolutores externos
```

## Técnicas de Filtrado Avanzado

### Operadores Lógicos

Combinar múltiples condiciones de filtro.

```bash
# Operador AND
tcp.port == 80 and ip.src == 192.168.1.100
# Operador OR
tcp.port == 80 or tcp.port == 443
# Operador NOT
not icmp
# Paréntesis para agrupación
(tcp.port == 80 or tcp.port == 443) and ip.src ==
192.168.1.0/24
```

### Coincidencia de Cadenas

Buscar contenido específico en los paquetes.

```bash
# Contiene cadena (sensible a mayúsculas y minúsculas)
tcp contains "password"
# Contiene cadena (insensible a mayúsculas y minúsculas)
tcp matches "(?i)login"
# Expresiones regulares
http.request.uri matches "\.php$"
# Secuencias de bytes
eth.src[0:3] == 00:11:22
```

### Comparaciones de Campos

Comparar campos de paquetes con valores y rangos.

```bash
# Igualdad
tcp.srcport == 80
# Mayor que/menor que
frame.len > 1000
# Verificaciones de rango
tcp.port >= 1024 and tcp.port <= 65535
# Pertenencia a conjunto
tcp.port in {80 443 8080 8443}
# Existencia de campo
tcp.options
```

### Análisis Avanzado de Paquetes

Identificar características y anomalías específicas de paquetes.

```bash
# Paquetes mal formados
_ws.malformed
# Paquetes duplicados
frame.number == tcp.analysis.duplicate_ack_num
# Paquetes fuera de orden
tcp.analysis.out_of_order
# Problemas de ventana TCP
tcp.analysis.window_full
```

## Casos de Uso Comunes

### Solución de Problemas de Red

Identificar y resolver problemas de conectividad de red.

```bash
# Encontrar tiempos de espera de conexión
tcp.analysis.retransmission and tcp.analysis.rto
# Identificar conexiones lentas
tcp.time_delta > 1.0
# Encontrar congestión de red
tcp.analysis.window_full
# Problemas de resolución DNS
dns.flags.rcode != 0
# Problemas de descubrimiento de MTU
icmp.type == 3 and icmp.code == 4
```

### Análisis de Seguridad

Detectar amenazas de seguridad potenciales y actividad sospechosa.

```bash
# Detección de escaneo de puertos
tcp.flags.syn == 1 and tcp.flags.ack == 0
# Gran número de conexiones desde una sola IP
# Usar Estadísticas > Conversaciones
# Consultas DNS sospechosas
dns.qry.name contains "dga" or dns.qry.name matches
"^[a-z]{8,}\.com$"
# POST HTTP a URLs sospechosas
http.request.method == "POST" and http.request.uri
contains "/upload"
# Patrones de tráfico inusuales
# Revisar Gráficos de E/S para picos
```

### Rendimiento de Aplicaciones

Monitorear y analizar los tiempos de respuesta de las aplicaciones.

```bash
# Análisis de aplicación web
http.time > 2.0
# Monitoreo de conexión a base de datos
tcp.port == 3306 and tcp.analysis.initial_rtt > 0.1
# Rendimiento de transferencia de archivos
tcp.stream eq X and tcp.analysis.bytes_in_flight
# Análisis de calidad de VoIP
rtp.jitter > 30 or rtp.marker == 1
```

### Investigación de Protocolos

Inmersión profunda en protocolos específicos y su comportamiento.

```bash
# Tráfico de correo electrónico
tcp.port == 25 or tcp.port == 587 or tcp.port == 993
# Transferencias de archivos FTP
ftp-data or ftp.request.command == "RETR"
# Compartición de archivos SMB/CIFS
smb2 or smb
# Análisis de asignación DHCP
bootp.option.dhcp == 1 or bootp.option.dhcp == 2
```

## Enlaces Relevantes

- <router-link to="/nmap">Hoja de Trucos de Nmap</router-link>
- <router-link to="/cybersecurity">Hoja de Trucos de Ciberseguridad</router-link>
- <router-link to="/kali">Hoja de Trucos de Kali Linux</router-link>
- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/network">Hoja de Trucos de Redes</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>

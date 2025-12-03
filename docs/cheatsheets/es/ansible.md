---
title: 'Guía Rápida de Ansible | LabEx'
description: 'Aprenda automatización con Ansible con esta guía completa. Referencia rápida para playbooks, módulos, inventario, gestión de configuración y automatización de infraestructura.'
pdfUrl: '/cheatsheets/pdf/ansible-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Ansible
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/ansible">Aprenda Ansible con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprenda automatización de infraestructura con Ansible a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Ansible que cubren la creación esencial de playbooks, gestión de inventario, uso de módulos y organización de roles. Domine la gestión de configuración y la automatización de infraestructura para flujos de trabajo DevOps.
</base-disclaimer-content>
</base-disclaimer>

## Instalación y Configuración

### Ubuntu/Debian: `apt install ansible`

Instalar Ansible en sistemas Linux basados en Debian.

```bash
# Añadir repositorio de Ansible
sudo apt-add-repository ppa:ansible/ansible
# Actualizar listas de paquetes
sudo apt-get update
# Instalar Ansible
sudo apt-get install ansible
# Verificar instalación
ansible --version
```

### CentOS/RHEL: `yum install ansible`

Instalar Ansible en sistemas basados en Red Hat.

```bash
# Instalar repositorio EPEL
sudo yum install epel-release -y
# Instalar Ansible
sudo yum install ansible -y
# Verificar instalación
ansible --version
```

### macOS: `brew install ansible`

Instalar Ansible en macOS usando Homebrew.

```bash
# Instalar usando Homebrew
brew install ansible
# Verificar instalación
ansible --version
```

### Configuración: `/etc/ansible/ansible.cfg`

Configurar ajustes y valores predeterminados de Ansible.

```bash
# Ver configuración actual
ansible-config list
# Ver configuración efectiva
ansible-config view
# Archivo de configuración personalizado
export ANSIBLE_CONFIG=/path/to/ansible.cfg
```

### Configuración SSH: Autenticación basada en Claves

Ansible utiliza SSH para comunicarse entre nodos.

```bash
# Generar clave SSH
ssh-keygen -t rsa -b 4096
# Copiar clave pública a hosts remotos
ssh-copy-id user@hostname
# Probar conexión SSH
ssh user@hostname
```

### Configuración del Entorno

Configurar variables de entorno y rutas del entorno Ansible.

```bash
# Establecer ubicación del archivo de inventario
export ANSIBLE_INVENTORY=/path/to/inventory
# Establecer verificación de claves de host
export ANSIBLE_HOST_KEY_CHECKING=False
# Establecer usuario remoto
export ANSIBLE_REMOTE_USER=ubuntu
```

## Gestión de Inventario

### Inventario Básico: `/etc/ansible/hosts`

Los grupos de hosts se pueden crear dando un nombre de grupo entre corchetes.

```ini
# Archivo de hosts básico (formato INI)
[webservers]
web1.example.com
web2.example.com
[databases]
db1.example.com
db2.example.com
[all:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/id_rsa
```

### Formato de Inventario YAML

Los archivos de inventario pueden estar en formato INI o YAML.

```yaml
# inventory.yml
all:
  children:
    webservers:
      hosts:
        web1.example.com:
        web2.example.com:
    databases:
      hosts:
        db1.example.com:
      vars:
        mysql_port: 3306
```

### Variables de Host y Grupos

Definir variables específicas del host y configuraciones de grupo.

```ini
# Inventario con variables
[webservers]
web1.example.com http_port=80
web2.example.com http_port=8080
[webservers:vars]
ansible_user=nginx
nginx_version=1.18

# Probar inventario
ansible-inventory --list
ansible-inventory --graph
```

## Comandos Ad-Hoc

### Estructura Básica del Comando

Estructura básica de un comando Ansible: `ansible <hosts> -m <module> -a "<arguments>"`

```bash
# Probar conectividad
ansible all -m ping
# Verificar grupo específico
ansible webservers -m ping
# Ejecutar comando en todos los hosts
ansible all -m command -a "uptime"
# Ejecutar con privilegios sudo
ansible all -m command -a "systemctl status nginx" --become
```

<BaseQuiz id="ansible-command-1" correct="C">
  <template #question>
    ¿Qué hace <code>ansible all -m ping</code>?
  </template>
  
  <BaseQuizOption value="A">Prueba la conectividad de red usando ping ICMP</BaseQuizOption>
  <BaseQuizOption value="B">Instala el paquete ping en todos los hosts</BaseQuizOption>
  <BaseQuizOption value="C" correct>Prueba la conectividad de Ansible a todos los hosts en el inventario</BaseQuizOption>
  <BaseQuizOption value="D">Verifica si los hosts están en línea</BaseQuizOption>
  
  <BaseQuizAnswer>
    El módulo <code>ping</code> en Ansible no utiliza ICMP. Es un módulo de prueba que verifica que Ansible puede conectarse a los hosts, ejecutar Python y devolver resultados. Se utiliza para verificar la conectividad y la configuración.
  </BaseQuizAnswer>
</BaseQuiz>

### Operaciones de Archivos

Crear directorios, archivos y enlaces simbólicos en los hosts.

```bash
# Crear directorio
ansible all -m file -a "path=/tmp/test state=directory mode=0755"
# Crear archivo
ansible all -m file -a "path=/tmp/test.txt state=touch"
# Eliminar archivo/directorio
ansible all -m file -a "path=/tmp/test state=absent"
# Crear enlace simbólico
ansible all -m file -a "src=/etc/nginx dest=/tmp/nginx state=link"
```

### Gestión de Paquetes

Instalar, actualizar y eliminar paquetes en diferentes sistemas.

```bash
# Instalar paquete (apt)
ansible webservers -m apt -a "name=nginx state=present" --become
# Instalar paquete (yum)
ansible webservers -m yum -a "name=httpd state=present" --become
# Actualizar todos los paquetes
ansible all -m apt -a "upgrade=dist" --become
# Eliminar paquete
ansible all -m apt -a "name=apache2 state=absent" --become
```

### Gestión de Servicios

Iniciar, detener y gestionar servicios del sistema.

```bash
# Iniciar servicio
ansible webservers -m service -a "name=nginx state=started" --become
# Detener servicio
ansible webservers -m service -a "name=apache2 state=stopped" --become
# Reiniciar servicio
ansible webservers -m service -a "name=ssh state=restarted" --become
# Habilitar servicio al arranque
ansible all -m service -a "name=nginx enabled=yes" --become
```

## Playbooks y Tareas

### Estructura Básica del Playbook

Archivos YAML que definen qué tareas deben ejecutarse y en qué hosts.

```yaml
---
- name: Configuración del servidor web
  hosts: webservers
  become: yes
  vars:
    nginx_port: 80

  tasks:
    - name: Instalar nginx
      apt:
        name: nginx
        state: present

    - name: Iniciar servicio nginx
      service:
        name: nginx
        state: started
        enabled: yes
```

### Ejecución de Playbooks

Ejecutar playbooks con varias opciones y configuraciones.

```bash
# Ejecutar playbook
ansible-playbook site.yml
# Ejecutar con inventario específico
ansible-playbook -i inventory.yml site.yml
# Ejecución simulada (modo check)
ansible-playbook site.yml --check
# Ejecutar en hosts específicos
ansible-playbook site.yml --limit webservers
# Ejecutar con variables extra
ansible-playbook site.yml --extra-vars "nginx_port=8080"
```

<BaseQuiz id="ansible-playbook-1" correct="B">
  <template #question>
    ¿Qué hace <code>ansible-playbook site.yml --check</code>?
  </template>
  
  <BaseQuizOption value="A">Ejecuta el playbook dos veces</BaseQuizOption>
  <BaseQuizOption value="B" correct>Ejecuta el playbook en modo de verificación (simulación) sin realizar cambios</BaseQuizOption>
  <BaseQuizOption value="C">Verifica la sintaxis del playbook</BaseQuizOption>
  <BaseQuizOption value="D">Ejecuta solo la primera tarea</BaseQuizOption>
  
  <BaseQuizAnswer>
    La bandera <code>--check</code> ejecuta Ansible en modo de verificación (simulación), lo que simula lo que sucedería sin realizar cambios reales. Esto es útil para probar playbooks antes de aplicarlos.
  </BaseQuizAnswer>
</BaseQuiz>

### Opciones de Tarea y Condicionales

Añadir condiciones, bucles y manejo de errores a las tareas.

```yaml
tasks:
  - name: Instalar paquetes
    apt:
      name: '{{ item }}'
      state: present
    loop:
      - nginx
      - mysql-server
      - php
    when: ansible_os_family == "Debian"

  - name: Crear usuario
    user:
      name: webuser
      state: present
    register: user_result

  - name: Mostrar resultado de creación de usuario
    debug:
      msg: 'Usuario creado: {{ user_result.changed }}'
```

### Handlers y Notificaciones

Definir _handlers_ que se ejecutan cuando son notificados por las tareas.

```yaml
tasks:
  - name: Actualizar configuración de nginx
    template:
      src: nginx.conf.j2
      dest: /etc/nginx/nginx.conf
    notify: reiniciar nginx

handlers:
  - name: reiniciar nginx
    service:
      name: nginx
      state: restarted
```

<BaseQuiz id="ansible-handlers-1" correct="C">
  <template #question>
    ¿Cuándo se ejecutan los *handlers* de Ansible?
  </template>
  
  <BaseQuizOption value="A">Inmediatamente después de ser definidos</BaseQuizOption>
  <BaseQuizOption value="B">Al inicio del playbook</BaseQuizOption>
  <BaseQuizOption value="C" correct>Al final del playbook, solo si son notificados por una tarea</BaseQuizOption>
  <BaseQuizOption value="D">Cada vez que se ejecuta una tarea</BaseQuizOption>
  
  <BaseQuizAnswer>
    Los *handlers* se ejecutan al final del playbook, y solo si son notificados por una tarea que ha cambiado algo. Esto asegura que los servicios solo se reinicien cuando los archivos de configuración se modifican realmente.
  </BaseQuizAnswer>
</BaseQuiz>

## Variables y Plantillas

### Definición de Variables

Definir variables en diferentes niveles y alcances.

```yaml
# En playbook
vars:
  app_name: myapp
  app_port: 8080

# En group_vars/all.yml
database_host: db.example.com
database_port: 5432

# En host_vars/web1.yml
server_role: frontend
max_connections: 100

# Variables de línea de comando
ansible-playbook site.yml -e "env=production"
```

### Plantillas Jinja2

Crear archivos de configuración dinámicos usando plantillas.

```jinja2
# Archivo de plantilla: nginx.conf.j2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};

    location / {
        proxy_pass http://{{ backend_host }}:{{ backend_port }};
    }
}
```

```yaml
# Usando el módulo template
- name: Desplegar configuración de nginx
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/sites-available/default
  notify: recargar nginx
```

### Facts y Información del Sistema

Recopilar y usar _facts_ del sistema en playbooks.

```bash
# Recopilar facts manualmente
ansible all -m setup
# Recopilar facts específicos
ansible all -m setup -a "filter=ansible_eth*"
```

```yaml
# Usar facts en playbooks
- name: Mostrar información del sistema
  debug:
    msg: '{{ ansible_hostname }} ejecuta {{ ansible_distribution }}'

- name: Instalar paquete basado en el SO
  apt:
    name: apache2
  when: ansible_os_family == "Debian"
```

### Vault y Gestión de Secretos

Cifrar datos sensibles usando Ansible Vault.

```bash
# Crear archivo cifrado
ansible-vault create secrets.yml
# Editar archivo cifrado
ansible-vault edit secrets.yml
# Cifrar archivo existente
ansible-vault encrypt passwords.yml
# Ejecutar playbook con vault
ansible-playbook site.yml --ask-vault-pass
# Usar archivo de contraseña vault
ansible-playbook site.yml --vault-password-file .vault_pass
```

## Roles y Organización

### Estructura de Roles

Organizar playbooks en roles reutilizables.

```bash
# Crear estructura de rol
ansible-galaxy init webserver
```

```
# Estructura de directorio del Rol
webserver/
├── tasks/
│   └── main.yml
├── handlers/
│   └── main.yml
├── templates/
├── files/
├── vars/
│   └── main.yml
├── defaults/
│   └── main.yml
└── meta/
    └── main.yml
```

### Uso de Roles en Playbooks

Aplicar roles a hosts en sus playbooks.

```yaml
---
- hosts: webservers
  roles:
    - common
    - webserver
    - { role: database, database_type: mysql }

# O con include_role
- hosts: webservers
  tasks:
    - include_role:
        name: webserver
      vars:
        nginx_port: 8080
```

### Ansible Galaxy

Descargar y gestionar roles de la comunidad desde Ansible Galaxy.

```bash
# Instalar rol desde Galaxy
ansible-galaxy install geerlingguy.nginx
# Instalar versión específica
ansible-galaxy install geerlingguy.nginx,2.8.0
# Instalar desde archivo requirements
ansible-galaxy install -r requirements.yml
# Listar roles instalados
ansible-galaxy list
# Eliminar rol
ansible-galaxy remove geerlingguy.nginx
```

### Colecciones

Trabajar con Colecciones de Ansible para funcionalidad extendida.

```bash
# Instalar colección
ansible-galaxy collection install community.general
```

```yaml
# Usar colección en playbook
collections:
  - community.general
tasks:
  - name: Instalar paquete
    community.general.snap:
      name: code
      state: present
```

## Depuración y Solución de Problemas

### Depuración de Tareas

Depurar y solucionar problemas en la ejecución de playbooks.

```yaml
# Añadir tareas de depuración
- name: Mostrar valor de variable
  debug:
    var: my_variable
- name: Mostrar mensaje personalizado
  debug:
    msg: 'Servidor {{ inventory_hostname }} tiene IP {{ ansible_default_ipv4.address }}'
```

```bash
# Ejecución detallada (verbose)
ansible-playbook site.yml -v
ansible-playbook site.yml -vvv  # Verbosity máxima
```

### Manejo de Errores

Manejar errores y fallos con elegancia.

```yaml
- name: Tarea que podría fallar
  command: /bin/false
  ignore_errors: yes

- name: Tarea con rescue
  block:
    - command: /bin/false
  rescue:
    - debug:
        msg: 'La tarea falló, ejecutando rescue'
  always:
    - debug:
        msg: 'Esto siempre se ejecuta'
```

### Pruebas y Validación

Probar playbooks y validar configuraciones.

```bash
# Verificar sintaxis
ansible-playbook site.yml --syntax-check
# Listar tareas
ansible-playbook site.yml --list-tasks
# Listar hosts
ansible-playbook site.yml --list-hosts
# Recorrer playbook paso a paso
ansible-playbook site.yml --step
# Probar con modo de verificación
ansible-playbook site.yml --check --diff
```

### Rendimiento y Optimización

Optimizar el rendimiento de la ejecución del playbook.

```yaml
# Ejecutar tareas en paralelo
- name: Instalar paquetes
  apt:
    name: '{{ packages }}'
  vars:
    packages:
      - nginx
      - mysql-server

# Usar async para tareas de larga duración
- name: Tarea de larga duración
  command: /usr/bin/long-task
  async: 300
  poll: 5
```

## Mejores Prácticas y Consejos

### Mejores Prácticas de Seguridad

Asegurar su infraestructura y operaciones de Ansible.

```bash
# Usar Ansible Vault para secretos
ansible-vault create group_vars/all/vault.yml
# Deshabilitar la verificación de claves de host con cautela
host_key_checking = False
# Usar become solo cuando sea necesario
become: yes
become_user: root
# Limitar el alcance del playbook
ansible-playbook site.yml --limit production
```

### Organización del Código

Estructurar sus proyectos Ansible de manera efectiva.

```
# Estructura de directorio recomendada
ansible-project/
├── inventories/
│   ├── production/
│   └── staging/
├── group_vars/
├── host_vars/
├── roles/
├── playbooks/
└── ansible.cfg
```

```yaml
# Usar nombres significativos y documentación
- name: Nombre de tarea descriptivo
  # Añadir comentarios para lógica compleja
```

### Control de Versiones y Pruebas

Gestionar el código de Ansible con un control de versiones adecuado.

```bash
# Usar Git para control de versiones
git init
git add .
git commit -m "Configuración inicial de Ansible"
# Probar en staging antes de producción
ansible-playbook -i staging site.yml
# Usar etiquetas (tags) para ejecución selectiva
ansible-playbook site.yml --tags "nginx,ssl"
```

## Configuración y Características Avanzadas

### Configuración de Ansible

Personalizar el comportamiento de Ansible con opciones de configuración.

```ini
# ansible.cfg
[defaults]
inventory = ./inventory
remote_user = ansible
host_key_checking = False
timeout = 30
forks = 5

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
pipelining = True
```

### Plugins de Callback

Mejorar la salida y el registro con plugins de _callback_.

```ini
# Habilitar plugins de callback en ansible.cfg
[defaults]
stdout_callback = yaml
callbacks_enabled = profile_tasks, timer

# Configuración de callback personalizado
[callback_profile_tasks]
task_output_limit = 20
```

### Filtros y Plugins de Búsqueda (Lookup)

Usar filtros Jinja2 y plugins de búsqueda para manipulación de datos.

```jinja2
# Filtros comunes en plantillas
{{ variable | default('default_value') }}
{{ list_var | length }}
{{ string_var | upper }}
{{ dict_var | to_nice_yaml }}
```

```yaml
# Plugins de búsqueda (lookup)
- name: Leer contenido de archivo
  debug:
    msg: "{{ lookup('file', '/etc/hostname') }}"

- name: Variable de entorno
  debug:
    msg: "{{ lookup('env', 'HOME') }}"
```

### Inventarios Dinámicos

Usar inventarios dinámicos para entornos de nube y contenedores.

```bash
# Inventario dinámico AWS EC2
ansible-playbook -i ec2.py site.yml
# Inventario dinámico Docker
ansible-playbook -i docker.yml site.yml
# Script de inventario personalizado
ansible-playbook -i ./dynamic_inventory.py site.yml
```

## Enlaces Relevantes

- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>
- <router-link to="/kubernetes">Hoja de Trucos de Kubernetes</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>

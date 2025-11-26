---
title: 'Ansible Spickzettel'
description: 'Lernen Sie Ansible mit unserem umfassenden Spickzettel, der wesentliche Befehle, Konzepte und Best Practices abdeckt.'
pdfUrl: '/cheatsheets/pdf/ansible-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Ansible Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/ansible">Lernen Sie Ansible mit praktischen Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie die Automatisierung von Ansible-Infrastrukturen durch praktische Labs und reale Szenarien. LabEx bietet umfassende Ansible-Kurse, die die Erstellung wesentlicher Playbooks, Bestandsverwaltung, Modulnutzung und Rollenorganisation abdecken. Meistern Sie Konfigurationsmanagement und Infrastrukturautomatisierung für DevOps-Workflows.
</base-disclaimer-content>
</base-disclaimer>

## Installation & Einrichtung

### Ubuntu/Debian: `apt install ansible`

Ansible auf Debian-basierten Linux-Systemen installieren.

```bash
# Ansible Repository hinzufügen
sudo apt-add-repository ppa:ansible/ansible
# Paketlisten aktualisieren
sudo apt-get update
# Ansible installieren
sudo apt-get install ansible
# Installation überprüfen
ansible --version
```

### CentOS/RHEL: `yum install ansible`

Ansible auf Red Hat-basierten Systemen installieren.

```bash
# EPEL Repository installieren
sudo yum install epel-release -y
# Ansible installieren
sudo yum install ansible -y
# Installation überprüfen
ansible --version
```

### macOS: `brew install ansible`

Ansible auf macOS mit Homebrew installieren.

```bash
# Installation mit Homebrew
brew install ansible
# Installation überprüfen
ansible --version
```

### Konfiguration: `/etc/ansible/ansible.cfg`

Ansible-Einstellungen und Standardwerte konfigurieren.

```bash
# Aktuelle Konfiguration anzeigen
ansible-config list
# Effektive Konfiguration anzeigen
ansible-config view
# Benutzerdefinierte Konfigurationsdatei
export ANSIBLE_CONFIG=/path/to/ansible.cfg
```

### SSH-Einrichtung: Schlüsselbasierte Authentifizierung

Ansible verwendet SSH zur Kommunikation zwischen den Knoten.

```bash
# SSH-Schlüssel generieren
ssh-keygen -t rsa -b 4096
# Öffentlichen Schlüssel auf Remote-Hosts kopieren
ssh-copy-id user@hostname
# SSH-Verbindung testen
ssh user@hostname
```

### Umgebung einrichten

Ansible-Umgebungsvariablen und Pfade einrichten.

```bash
# Speicherort der Inventardatei festlegen
export ANSIBLE_INVENTORY=/path/to/inventory
# Host-Schlüsselprüfung festlegen
export ANSIBLE_HOST_KEY_CHECKING=False
# Remote-Benutzer festlegen
export ANSIBLE_REMOTE_USER=ubuntu
```

## Bestandsverwaltung (Inventory Management)

### Basis-Inventar: `/etc/ansible/hosts`

Host-Gruppen können erstellt werden, indem ein Gruppenname in eckigen Klammern angegeben wird.

```ini
# Basis-Hosts-Datei (INI-Format)
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

### YAML-Inventarformat

Inventardateien können im INI- oder YAML-Format vorliegen.

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

### Host-Variablen & Gruppen

Hostspezifische Variablen und Gruppenkonfigurationen definieren.

```ini
# Inventar mit Variablen
[webservers]
web1.example.com http_port=80
web2.example.com http_port=8080
[webservers:vars]
ansible_user=nginx
nginx_version=1.18

# Inventar testen
ansible-inventory --list
ansible-inventory --graph
```

## Ad-Hoc-Befehle

### Grundlegende Befehlsstruktur

Grundstruktur eines Ansible-Befehls: `ansible <hosts> -m <module> -a "<arguments>"`

```bash
# Konnektivität testen
ansible all -m ping
# Spezifische Gruppe prüfen
ansible webservers -m ping
# Befehl auf allen Hosts ausführen
ansible all -m command -a "uptime"
# Mit sudo-Rechten ausführen
ansible all -m command -a "systemctl status nginx" --become
```

### Dateioperationen

Verzeichnisse, Dateien und symbolische Links auf Hosts erstellen.

```bash
# Verzeichnis erstellen
ansible all -m file -a "path=/tmp/test state=directory mode=0755"
# Datei erstellen
ansible all -m file -a "path=/tmp/test.txt state=touch"
# Datei/Verzeichnis löschen
ansible all -m file -a "path=/tmp/test state=absent"
# Symbolischen Link erstellen
ansible all -m file -a "src=/etc/nginx dest=/tmp/nginx state=link"
```

### Paketverwaltung

Pakete auf verschiedenen Systemen installieren, aktualisieren und entfernen.

```bash
# Paket installieren (apt)
ansible webservers -m apt -a "name=nginx state=present" --become
# Paket installieren (yum)
ansible webservers -m yum -a "name=httpd state=present" --become
# Alle Pakete aktualisieren
ansible all -m apt -a "upgrade=dist" --become
# Paket entfernen
ansible all -m apt -a "name=apache2 state=absent" --become
```

### Dienstverwaltung

Systemdienste starten, stoppen und verwalten.

```bash
# Dienst starten
ansible webservers -m service -a "name=nginx state=started" --become
# Dienst stoppen
ansible webservers -m service -a "name=apache2 state=stopped" --become
# Dienst neu starten
ansible webservers -m service -a "name=ssh state=restarted" --become
# Dienst beim Booten aktivieren
ansible all -m service -a "name=nginx enabled=yes" --become
```

## Playbooks & Aufgaben (Tasks)

### Grundlegende Playbook-Struktur

YAML-Dateien, die definieren, welche Aufgaben auf welchen Hosts ausgeführt werden sollen.

```yaml
---
- name: Webserver-Setup
  hosts: webservers
  become: yes
  vars:
    nginx_port: 80

  tasks:
    - name: nginx installieren
      apt:
        name: nginx
        state: present

    - name: nginx Dienst starten
      service:
        name: nginx
        state: started
        enabled: yes
```

### Playbooks ausführen

Playbooks mit verschiedenen Optionen und Konfigurationen ausführen.

```bash
# Playbook ausführen
ansible-playbook site.yml
# Mit spezifischem Inventar ausführen
ansible-playbook -i inventory.yml site.yml
# Trockenlauf (Check-Modus)
ansible-playbook site.yml --check
# Auf spezifischen Hosts ausführen
ansible-playbook site.yml --limit webservers
# Mit zusätzlichen Variablen ausführen
ansible-playbook site.yml --extra-vars "nginx_port=8080"
```

### Aufgabenoptionen & Bedingungen

Bedingungen, Schleifen und Fehlerbehandlung zu Aufgaben hinzufügen.

```yaml
tasks:
  - name: Pakete installieren
    apt:
      name: '{{ item }}'
      state: present
    loop:
      - nginx
      - mysql-server
      - php
    when: ansible_os_family == "Debian"

  - name: Benutzer erstellen
    user:
      name: webuser
      state: present
    register: user_result

  - name: Ergebnis der Benutzererstellung anzeigen
    debug:
      msg: 'Benutzer erstellt: {{ user_result.changed }}'
```

### Handler & Benachrichtigungen

Handler definieren, die benachrichtigt werden, wenn Aufgaben sie aufrufen.

```yaml
tasks:
  - name: nginx Konfiguration aktualisieren
    template:
      src: nginx.conf.j2
      dest: /etc/nginx/nginx.conf
    notify: nginx neu starten

handlers:
  - name: nginx neu starten
    service:
      name: nginx
      state: restarted
```

## Variablen & Vorlagen (Templates)

### Variablendefinition

Variablen auf verschiedenen Ebenen und in verschiedenen Gültigkeitsbereichen definieren.

```yaml
# Im Playbook
vars:
  app_name: myapp
  app_port: 8080

# In group_vars/all.yml
database_host: db.example.com
database_port: 5432

# In host_vars/web1.yml
server_role: frontend
max_connections: 100

# Variablen von der Kommandozeile
ansible-playbook site.yml -e "env=production"
```

### Jinja2-Vorlagen

Dynamische Konfigurationsdateien mithilfe von Vorlagen erstellen.

```jinja2
# Vorlagendatei: nginx.conf.j2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};

    location / {
        proxy_pass http://{{ backend_host }}:{{ backend_port }};
    }
}
```

```yaml
# Verwendung des template Moduls
- name: nginx Konfiguration bereitstellen
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/sites-available/default
  notify: nginx neu laden
```

### Fakten & Systeminformationen

Systemfakten sammeln und in Playbooks verwenden.

```bash
# Fakten manuell sammeln
ansible all -m setup
# Spezifische Fakten sammeln
ansible all -m setup -a "filter=ansible_eth*"
```

```yaml
# Fakten in Playbooks verwenden
- name: Systeminformationen anzeigen
  debug:
    msg: '{{ ansible_hostname }} läuft auf {{ ansible_distribution }}'

- name: Paket basierend auf OS installieren
  apt:
    name: apache2
  when: ansible_os_family == "Debian"
```

### Vault & Geheimnisverwaltung

Sensible Daten mithilfe von Ansible Vault verschlüsseln.

```bash
# Verschlüsselte Datei erstellen
ansible-vault create secrets.yml
# Verschlüsselte Datei bearbeiten
ansible-vault edit secrets.yml
# Bestehende Datei verschlüsseln
ansible-vault encrypt passwords.yml
# Playbook mit Vault ausführen
ansible-playbook site.yml --ask-vault-pass
# Vault-Passwortdatei verwenden
ansible-playbook site.yml --vault-password-file .vault_pass
```

## Rollen & Organisation

### Rollenstruktur

Playbooks in wiederverwendbare Rollen organisieren.

```bash
# Rollenstruktur erstellen
ansible-galaxy init webserver
```

```
# Rollenverzeichnisstruktur
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

### Rollen in Playbooks verwenden

Rollen auf Hosts in Ihren Playbooks anwenden.

```yaml
---
- hosts: webservers
  roles:
    - common
    - webserver
    - { role: database, database_type: mysql }

# Oder mit include_role
- hosts: webservers
  tasks:
    - include_role:
        name: webserver
      vars:
        nginx_port: 8080
```

### Ansible Galaxy

Community-Rollen von Ansible Galaxy herunterladen und verwalten.

```bash
# Rolle von Galaxy installieren
ansible-galaxy install geerlingguy.nginx
# Spezifische Version installieren
ansible-galaxy install geerlingguy.nginx,2.8.0
# Aus Requirements-Datei installieren
ansible-galaxy install -r requirements.yml
# Installierte Rollen auflisten
ansible-galaxy list
# Rolle entfernen
ansible-galaxy remove geerlingguy.nginx
```

### Collections

Mit Ansible Collections für erweiterte Funktionalität arbeiten.

```bash
# Collection installieren
ansible-galaxy collection install community.general
```

```yaml
# Collection im Playbook verwenden
collections:
  - community.general
tasks:
  - name: Paket installieren
    community.general.snap:
      name: code
      state: present
```

## Debugging & Fehlerbehebung

### Aufgaben debuggen

Playbook-Ausführung debuggen und Fehler beheben.

```yaml
# Debug-Aufgaben hinzufügen
- name: Variablenwert anzeigen
  debug:
    var: my_variable
- name: Benutzerdefinierte Nachricht anzeigen
  debug:
    msg: 'Server {{ inventory_hostname }} hat IP {{ ansible_default_ipv4.address }}'
```

```bash
# Ausführliche Ausführung
ansible-playbook site.yml -v
ansible-playbook site.yml -vvv  # Maximale Ausführlichkeit
```

### Fehlerbehandlung

Fehler elegant behandeln und abfangen.

```yaml
- name: Aufgabe, die fehlschlagen könnte
  command: /bin/false
  ignore_errors: yes

- name: Aufgabe mit Rettung (rescue)
  block:
    - command: /bin/false
  rescue:
    - debug:
        msg: 'Aufgabe fehlgeschlagen, führe Rettung aus'
  always:
    - debug:
        msg: 'Dies wird immer ausgeführt'
```

### Testen & Validieren

Playbooks testen und Konfigurationen validieren.

```bash
# Syntax prüfen
ansible-playbook site.yml --syntax-check
# Aufgaben auflisten
ansible-playbook site.yml --list-tasks
# Hosts auflisten
ansible-playbook site.yml --list-hosts
# Playbook schrittweise durchgehen
ansible-playbook site.yml --step
# Mit Check-Modus testen
ansible-playbook site.yml --check --diff
```

### Leistung & Optimierung

Playbook-Leistung und Ausführung optimieren.

```yaml
# Aufgaben parallel ausführen
- name: Pakete installieren
  apt:
    name: '{{ packages }}'
  vars:
    packages:
      - nginx
      - mysql-server

# Asynchrone Ausführung für langlaufende Aufgaben verwenden
- name: Langlaufende Aufgabe
  command: /usr/bin/long-task
  async: 300
  poll: 5
```

## Best Practices & Tipps

### Sicherheitspraktiken

Ansible-Infrastruktur und -Operationen absichern.

```bash
# Ansible Vault für Geheimnisse verwenden
ansible-vault create group_vars/all/vault.yml
# Host-Schlüsselprüfung vorsichtig deaktivieren
host_key_checking = False
# become nur bei Bedarf verwenden
become: yes
become_user: root
# Playbook-Umfang begrenzen
ansible-playbook site.yml --limit production
```

### Code-Organisation

Ansible-Projekte effektiv strukturieren.

```bash
# Empfohlene Verzeichnisstruktur
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
# Aussagekräftige Namen und Dokumentation verwenden
- name: Beschreibender Aufgabenname
  # Kommentare für komplexe Logik hinzufügen
```

### Versionskontrolle & Testen

Ansible-Code mit ordnungsgemäßer Versionskontrolle verwalten.

```bash
# Git für Versionskontrolle verwenden
git init
git add .
git commit -m "Erste Ansible-Einrichtung"
# In Staging testen, bevor in Produktion gegangen wird
ansible-playbook -i staging site.yml
# Tags für selektive Ausführung verwenden
ansible-playbook site.yml --tags "nginx,ssl"
```

## Konfiguration & Erweiterte Funktionen

### Ansible-Konfiguration

Ansible-Verhalten mit Konfigurationsoptionen anpassen.

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

### Callback-Plugins

Ausgabe und Protokollierung mit Callback-Plugins verbessern.

```ini
# Callback-Plugins in ansible.cfg aktivieren
[defaults]
stdout_callback = yaml
callbacks_enabled = profile_tasks, timer

# Benutzerdefinierte Callback-Konfiguration
[callback_profile_tasks]
task_output_limit = 20
```

### Filter & Lookups

Jinja2-Filter und Lookup-Plugins zur Datenmanipulation verwenden.

```jinja2
# Häufige Filter in Vorlagen
{{ variable | default('default_value') }}
{{ list_var | length }}
{{ string_var | upper }}
{{ dict_var | to_nice_yaml }}
```

```yaml
# Lookup-Plugins
- name: Dateiinhalt lesen
  debug:
    msg: "{{ lookup('file', '/etc/hostname') }}"

- name: Umgebungsvariable
  debug:
    msg: "{{ lookup('env', 'HOME') }}"
```

### Dynamische Inventare

Dynamische Inventare für Cloud- und Container-Umgebungen verwenden.

```bash
# AWS EC2 dynamisches Inventar
ansible-playbook -i ec2.py site.yml
# Docker dynamisches Inventar
ansible-playbook -i docker.yml site.yml
# Benutzerdefiniertes Inventarskript
ansible-playbook -i ./dynamic_inventory.py site.yml
```

## Relevante Links

- <router-link to="/linux">Linux Spickzettel</router-link>
- <router-link to="/shell">Shell Spickzettel</router-link>
- <router-link to="/devops">DevOps Spickzettel</router-link>
- <router-link to="/docker">Docker Spickzettel</router-link>
- <router-link to="/kubernetes">Kubernetes Spickzettel</router-link>
- <router-link to="/python">Python Spickzettel</router-link>

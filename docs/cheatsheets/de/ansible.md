---
title: 'Ansible Spickzettel | LabEx'
description: 'Lernen Sie Ansible-Automatisierung mit diesem umfassenden Spickzettel. Schnelle Referenz für Ansible Playbooks, Module, Bestandsverwaltung, Konfigurationsmanagement und Infrastrukturautomatisierung.'
pdfUrl: '/cheatsheets/pdf/ansible-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Ansible Spickzettel
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/de/learn/ansible">Lernen Sie Ansible mit Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Lernen Sie Ansible Infrastrukturautomatisierung durch praktische Labs und reale Szenarien. LabEx bietet umfassende Ansible-Kurse, die die Erstellung wesentlicher Playbooks, Bestandsverwaltung, Modulnutzung und Rollenorganisation abdecken. Meistern Sie Konfigurationsmanagement und Infrastrukturautomatisierung für DevOps-Workflows.
</base-disclaimer-content>
</base-disclaimer>

## Installation & Einrichtung

### Ubuntu/Debian: `apt install ansible`

Installieren Sie Ansible auf Debian-basierten Linux-Systemen.

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

Installieren Sie Ansible auf Red Hat-basierten Systemen.

```bash
# EPEL Repository installieren
sudo yum install epel-release -y
# Ansible installieren
sudo yum install ansible -y
# Installation überprüfen
ansible --version
```

### macOS: `brew install ansible`

Installieren Sie Ansible auf macOS mit Homebrew.

```bash
# Installation mit Homebrew
brew install ansible
# Installation überprüfen
ansible --version
```

### Konfiguration: `/etc/ansible/ansible.cfg`

Konfigurieren Sie Ansible-Einstellungen und Standardwerte.

```bash
# Aktuelle Konfiguration anzeigen
ansible-config list
# Effektive Konfiguration anzeigen
ansible-config view
# Benutzerdefinierte Konfigurationsdatei
export ANSIBLE_CONFIG=/path/to/ansible.cfg
```

### SSH-Einrichtung: Schlüsselbasierte Authentifizierung

Ansible verwendet SSH zur Kommunikation zwischen Knoten.

```bash
# SSH-Schlüssel generieren
ssh-keygen -t rsa -b 4096
# Öffentlichen Schlüssel auf Remote-Hosts kopieren
ssh-copy-id user@hostname
# SSH-Verbindung testen
ssh user@hostname
```

### Umgebungseinrichtung

Richten Sie Ansible-Umgebungsvariablen und Pfade ein.

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

Definieren Sie hostspezifische Variablen und Gruppenkonfigurationen.

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

<BaseQuiz id="ansible-command-1" correct="C">
  <template #question>
    Was bewirkt `ansible all -m ping`?
  </template>
  
  <BaseQuizOption value="A">Testet die Netzwerkverbindung mittels ICMP ping</BaseQuizOption>
  <BaseQuizOption value="B">Installiert das ping-Paket auf allen Hosts</BaseQuizOption>
  <BaseQuizOption value="C" correct>Testet die Ansible-Konnektivität zu allen Hosts im Inventar</BaseQuizOption>
  <BaseQuizOption value="D">Prüft, ob Hosts online sind</BaseQuizOption>
  
  <BaseQuizAnswer>
    Das `ping`-Modul in Ansible verwendet kein ICMP. Es ist ein Testmodul, das überprüft, ob Ansible eine Verbindung zu Hosts herstellen, Python ausführen und Ergebnisse zurückgeben kann. Es wird zur Überprüfung der Konnektivität und Konfiguration verwendet.
  </BaseQuizAnswer>
</BaseQuiz>

### Dateioperationen

Erstellen Sie Verzeichnisse, Dateien und symbolische Links auf Hosts.

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

Installieren, aktualisieren und entfernen Sie Pakete auf verschiedenen Systemen.

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

Starten, stoppen und verwalten Sie Systemdienste.

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

    - name: nginx-Dienst starten
      service:
        name: nginx
        state: started
        enabled: yes
```

### Playbooks ausführen

Führen Sie Playbooks mit verschiedenen Optionen und Konfigurationen aus.

```bash
# Playbook ausführen
ansible-playbook site.yml
# Mit spezifischem Inventar ausführen
ansible-playbook -i inventory.yml site.yml
# Trockenlauf (Prüfmodus)
ansible-playbook site.yml --check
# Auf spezifischen Hosts ausführen
ansible-playbook site.yml --limit webservers
# Mit zusätzlichen Variablen ausführen
ansible-playbook site.yml --extra-vars "nginx_port=8080"
```

<BaseQuiz id="ansible-playbook-1" correct="B">
  <template #question>
    Was bewirkt `ansible-playbook site.yml --check`?
  </template>
  
  <BaseQuizOption value="A">Führt das Playbook zweimal aus</BaseQuizOption>
  <BaseQuizOption value="B" correct>Führt das Playbook im Prüfmodus (Trockenlauf) aus, ohne Änderungen vorzunehmen</BaseQuizOption>
  <BaseQuizOption value="C">Prüft die Syntax des Playbooks</BaseQuizOption>
  <BaseQuizOption value="D">Führt nur die erste Aufgabe aus</BaseQuizOption>
  
  <BaseQuizAnswer>
    Die Option `--check` führt Ansible im Prüfmodus (Trockenlauf) aus, was simuliert, was passieren würde, ohne tatsächlich Änderungen vorzunehmen. Dies ist nützlich, um Playbooks vor der Anwendung zu testen.
  </BaseQuizAnswer>
</BaseQuiz>

### Aufgabenoptionen & Bedingungen

Fügen Sie Bedingungen, Schleifen und Fehlerbehandlung zu Aufgaben hinzu.

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

Definieren Sie Handler, die ausgeführt werden, wenn sie benachrichtigt werden.

```yaml
tasks:
  - name: nginx-Konfiguration aktualisieren
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

<BaseQuiz id="ansible-handlers-1" correct="C">
  <template #question>
    Wann werden Ansible-Handler ausgeführt?
  </template>
  
  <BaseQuizOption value="A">Unmittelbar nach ihrer Definition</BaseQuizOption>
  <BaseQuizOption value="B">Zu Beginn des Playbooks</BaseQuizOption>
  <BaseQuizOption value="C" correct>Am Ende des Playbooks, nur wenn sie von einer Aufgabe benachrichtigt werden</BaseQuizOption>
  <BaseQuizOption value="D">Jedes Mal, wenn eine Aufgabe ausgeführt wird</BaseQuizOption>
  
  <BaseQuizAnswer>
    Handler werden am Ende des Playbooks ausgeführt, und zwar nur, wenn sie von einer Aufgabe benachrichtigt werden, die etwas geändert hat. Dies stellt sicher, dass Dienste nur neu gestartet werden, wenn Konfigurationsdateien tatsächlich geändert wurden.
  </BaseQuizAnswer>
</BaseQuiz>

## Variablen & Vorlagen (Templates)

### Variablendefinition

Definieren Sie Variablen auf verschiedenen Ebenen und in verschiedenen Gültigkeitsbereichen.

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

# Kommandozeilenvariablen
ansible-playbook site.yml -e "env=production"
```

### Jinja2-Vorlagen

Erstellen Sie dynamische Konfigurationsdateien mithilfe von Vorlagen.

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
# Verwendung des template-Moduls
- name: nginx-Konfiguration bereitstellen
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/sites-available/default
  notify: nginx neu laden
```

### Fakten & Systeminformationen

Sammeln und verwenden Sie Systemfakten in Playbooks.

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

Verschlüsseln Sie sensible Daten mit Ansible Vault.

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

Organisieren Sie Playbooks in wiederverwendbare Rollen.

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

Wenden Sie Rollen auf Hosts in Ihren Playbooks an.

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

Laden Sie Community-Rollen von Ansible Galaxy herunter und verwalten Sie diese.

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

Arbeiten Sie mit Ansible Collections für erweiterte Funktionalität.

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

Debuggen und beheben Sie Probleme bei der Playbook-Ausführung.

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

Behandeln Sie Fehler und Fehler elegant.

```yaml
- name: Aufgabe, die fehlschlagen könnte
  command: /bin/false
  ignore_errors: yes

- name: Aufgabe mit Rettung (Rescue)
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

Testen Sie Playbooks und validieren Sie Konfigurationen.

```bash
# Syntax prüfen
ansible-playbook site.yml --syntax-check
# Aufgaben auflisten
ansible-playbook site.yml --list-tasks
# Hosts auflisten
ansible-playbook site.yml --list-hosts
# Schrittweise durchführen
ansible-playbook site.yml --step
# Mit Prüfmodus testen
ansible-playbook site.yml --check --diff
```

### Leistung & Optimierung

Optimieren Sie die Playbook-Leistung und -Ausführung.

```yaml
# Aufgaben parallel ausführen
- name: Pakete installieren
  apt:
    name: '{{ packages }}'
  vars:
    packages:
      - nginx
      - mysql-server

# Asynchrone Ausführung für lang laufende Aufgaben
- name: Lang laufende Aufgabe
  command: /usr/bin/long-task
  async: 300
  poll: 5
```

## Best Practices & Tipps

### Sicherheitspraktiken

Sichern Sie Ihre Ansible-Infrastruktur und -Vorgänge.

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

Strukturieren Sie Ihre Ansible-Projekte effektiv.

```
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
# Sinnvolle Namen und Dokumentation verwenden
- name: Beschreibender Aufgabenname
  # Kommentare für komplexe Logik hinzufügen
```

### Versionskontrolle & Testen

Verwalten Sie Ansible-Code mit ordnungsgemäßer Versionskontrolle.

```bash
# Git für Versionskontrolle verwenden
git init
git add .
git commit -m "Erste Ansible-Einrichtung"
# In Staging testen, bevor in Produktion
ansible-playbook -i staging site.yml
# Tags für selektive Ausführung verwenden
ansible-playbook site.yml --tags "nginx,ssl"
```

## Konfiguration & Erweiterte Funktionen

### Ansible-Konfiguration

Passen Sie das Ansible-Verhalten mit Konfigurationsoptionen an.

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

Erweitern Sie Ausgabe und Protokollierung mit Callback-Plugins.

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

Verwenden Sie Jinja2-Filter und Lookup-Plugins zur Datenmanipulation.

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

Verwenden Sie dynamische Inventare für Cloud- und Containerumgebungen.

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

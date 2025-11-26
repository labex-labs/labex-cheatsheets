---
title: 'Fiche Mémo Ansible'
description: 'Apprenez Ansible avec notre fiche mémo complète couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/ansible-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Ansible
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/ansible">Apprenez Ansible avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez l'automatisation de l'infrastructure Ansible grâce à des laboratoires pratiques et des scénarios du monde réel. LabEx propose des cours Ansible complets couvrant la création de playbooks essentiels, la gestion des inventaires, l'utilisation des modules et l'organisation des rôles. Maîtrisez la gestion de configuration et l'automatisation de l'infrastructure pour les flux de travail DevOps.
</base-disclaimer-content>
</base-disclaimer>

## Installation et Configuration

### Ubuntu/Debian: `apt install ansible`

Installer Ansible sur les systèmes Linux basés sur Debian.

```bash
# Ajouter le dépôt Ansible
sudo apt-add-repository ppa:ansible/ansible
# Mettre à jour les listes de paquets
sudo apt-get update
# Installer Ansible
sudo apt-get install ansible
# Vérifier l'installation
ansible --version
```

### CentOS/RHEL: `yum install ansible`

Installer Ansible sur les systèmes basés sur Red Hat.

```bash
# Installer le dépôt EPEL
sudo yum install epel-release -y
# Installer Ansible
sudo yum install ansible -y
# Vérifier l'installation
ansible --version
```

### macOS: `brew install ansible`

Installer Ansible sur macOS en utilisant Homebrew.

```bash
# Installer via Homebrew
brew install ansible
# Vérifier l'installation
ansible --version
```

### Configuration: `/etc/ansible/ansible.cfg`

Configurer les paramètres et les valeurs par défaut d'Ansible.

```bash
# Voir la configuration actuelle
ansible-config list
# Voir la configuration effective
ansible-config view
# Fichier de configuration personnalisé
export ANSIBLE_CONFIG=/chemin/vers/ansible.cfg
```

### Configuration SSH : Authentification par Clé

Ansible utilise SSH pour communiquer entre les nœuds.

```bash
# Générer une clé SSH
ssh-keygen -t rsa -b 4096
# Copier la clé publique sur les hôtes distants
ssh-copy-id user@hostname
# Tester la connexion SSH
ssh user@hostname
```

### Configuration de l'Environnement

Configurer les variables d'environnement et les chemins d'accès d'Ansible.

```bash
# Définir l'emplacement du fichier d'inventaire
export ANSIBLE_INVENTORY=/chemin/vers/inventory
# Désactiver la vérification des clés d'hôte
export ANSIBLE_HOST_KEY_CHECKING=False
# Définir l'utilisateur distant
export ANSIBLE_REMOTE_USER=ubuntu
```

## Gestion de l'Inventaire

### Inventaire de Base: `/etc/ansible/hosts`

Les groupes d'hôtes peuvent être créés en donnant un nom de groupe entre crochets.

```ini
# Fichier d'hôtes de base (format INI)
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

### Format d'Inventaire YAML

Les fichiers d'inventaire peuvent être au format INI ou YAML.

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

### Variables d'Hôte et de Groupe

Définir des variables spécifiques à l'hôte et des configurations de groupe.

```ini
# Inventaire avec variables
[webservers]
web1.example.com http_port=80
web2.example.com http_port=8080
[webservers:vars]
ansible_user=nginx
nginx_version=1.18

# Tester l'inventaire
ansible-inventory --list
ansible-inventory --graph
```

## Commandes Ad-Hoc

### Structure de Commande de Base

Structure de base d'une commande Ansible : `ansible <hôtes> -m <module> -a "<arguments>"`

```bash
# Tester la connectivité
ansible all -m ping
# Vérifier un groupe spécifique
ansible webservers -m ping
# Exécuter une commande sur tous les hôtes
ansible all -m command -a "uptime"
# Exécuter avec des privilèges sudo
ansible all -m command -a "systemctl status nginx" --become
```

### Opérations sur les Fichiers

Créer des répertoires, des fichiers et des liens symboliques sur les hôtes.

```bash
# Créer un répertoire
ansible all -m file -a "path=/tmp/test state=directory mode=0755"
# Créer un fichier
ansible all -m file -a "path=/tmp/test.txt state=touch"
# Supprimer un fichier/répertoire
ansible all -m file -a "path=/tmp/test state=absent"
# Créer un lien symbolique
ansible all -m file -a "src=/etc/nginx dest=/tmp/nginx state=link"
```

### Gestion des Paquets

Installer, mettre à jour et supprimer des paquets sur différents systèmes.

```bash
# Installer un paquet (apt)
ansible webservers -m apt -a "name=nginx state=present" --become
# Installer un paquet (yum)
ansible webservers -m yum -a "name=httpd state=present" --become
# Mettre à jour tous les paquets
ansible all -m apt -a "upgrade=dist" --become
# Supprimer un paquet
ansible all -m apt -a "name=apache2 state=absent" --become
```

### Gestion des Services

Démarrer, arrêter et gérer les services système.

```bash
# Démarrer le service
ansible webservers -m service -a "name=nginx state=started" --become
# Arrêter le service
ansible webservers -m service -a "name=apache2 state=stopped" --become
# Redémarrer le service
ansible webservers -m service -a "name=ssh state=restarted" --become
# Activer le service au démarrage
ansible all -m service -a "name=nginx enabled=yes" --become
```

## Playbooks et Tâches

### Structure de Playbook de Base

Fichiers YAML qui définissent quelles tâches doivent être exécutées et sur quels hôtes.

```yaml
---
- name: Configuration du serveur web
  hosts: webservers
  become: yes
  vars:
    nginx_port: 80

  tasks:
    - name: Installer nginx
      apt:
        name: nginx
        state: present

    - name: Démarrer le service nginx
      service:
        name: nginx
        state: started
        enabled: yes
```

### Exécution des Playbooks

Exécuter des playbooks avec diverses options et configurations.

```bash
# Exécuter le playbook
ansible-playbook site.yml
# Exécuter avec un inventaire spécifique
ansible-playbook -i inventory.yml site.yml
# Exécution à blanc (mode check)
ansible-playbook site.yml --check
# Exécuter sur des hôtes spécifiques
ansible-playbook site.yml --limit webservers
# Exécuter avec des variables supplémentaires
ansible-playbook site.yml --extra-vars "nginx_port=8080"
```

### Options de Tâche et Conditionnelles

Ajouter des conditions, des boucles et une gestion des erreurs aux tâches.

```yaml
tasks:
  - name: Installer les paquets
    apt:
      name: '{{ item }}'
      state: present
    loop:
      - nginx
      - mysql-server
      - php
    when: ansible_os_family == "Debian"

  - name: Créer un utilisateur
    user:
      name: webuser
      state: present
    register: user_result

  - name: Afficher le résultat de la création de l'utilisateur
    debug:
      msg: 'Utilisateur créé : {{ user_result.changed }}'
```

### Gestionnaires et Notifications

Définir des gestionnaires qui s'exécutent lorsqu'ils sont notifiés par des tâches.

```yaml
tasks:
  - name: Mettre à jour la configuration nginx
    template:
      src: nginx.conf.j2
      dest: /etc/nginx/nginx.conf
    notify: redémarrer nginx

handlers:
  - name: redémarrer nginx
    service:
      name: nginx
      state: restarted
```

## Variables et Modèles

### Définition des Variables

Définir des variables à différents niveaux et portées.

```yaml
# Dans le playbook
vars:
  app_name: myapp
  app_port: 8080

# Dans group_vars/all.yml
database_host: db.example.com
database_port: 5432

# Dans host_vars/web1.yml
server_role: frontend
max_connections: 100

# Variables de ligne de commande
ansible-playbook site.yml -e "env=production"
```

### Modèles Jinja2

Créer des fichiers de configuration dynamiques en utilisant des modèles.

```jinja2
# Fichier de modèle : nginx.conf.j2
server {
    listen {{ nginx_port }};
    server_name {{ server_name }};

    location / {
        proxy_pass http://{{ backend_host }}:{{ backend_port }};
    }
}
```

```yaml
# Utilisation du module template
- name: Déployer la configuration nginx
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/sites-available/default
  notify: recharger nginx
```

### Faits et Informations Système

Collecter et utiliser les faits système dans les playbooks.

```bash
# Collecter les faits manuellement
ansible all -m setup
# Collecter des faits spécifiques
ansible all -m setup -a "filter=ansible_eth*"
```

```yaml
# Utiliser les faits dans les playbooks
- name: Afficher les informations système
  debug:
    msg: '{{ ansible_hostname }} exécute {{ ansible_distribution }}'

- name: Installer un paquet basé sur l'OS
  apt:
    name: apache2
  when: ansible_os_family == "Debian"
```

### Vault et Gestion des Secrets

Chiffrer les données sensibles en utilisant Ansible Vault.

```bash
# Créer un fichier chiffré
ansible-vault create secrets.yml
# Modifier un fichier chiffré
ansible-vault edit secrets.yml
# Chiffrer un fichier existant
ansible-vault encrypt passwords.yml
# Exécuter le playbook avec vault
ansible-playbook site.yml --ask-vault-pass
# Utiliser un fichier de mot de passe vault
ansible-playbook site.yml --vault-password-file .vault_pass
```

## Rôles et Organisation

### Structure de Rôle

Organiser les playbooks en rôles réutilisables.

```bash
# Créer la structure de rôle
ansible-galaxy init webserver
```

```
# Structure de répertoire de rôle
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

### Utilisation des Rôles dans les Playbooks

Appliquer des rôles aux hôtes dans vos playbooks.

```yaml
---
- hosts: webservers
  roles:
    - common
    - webserver
    - { role: database, database_type: mysql }

# Ou avec include_role
- hosts: webservers
  tasks:
    - include_role:
        name: webserver
      vars:
        nginx_port: 8080
```

### Ansible Galaxy

Télécharger et gérer les rôles de la communauté depuis Ansible Galaxy.

```bash
# Installer un rôle depuis Galaxy
ansible-galaxy install geerlingguy.nginx
# Installer une version spécifique
ansible-galaxy install geerlingguy.nginx,2.8.0
# Installer depuis un fichier requirements
ansible-galaxy install -r requirements.yml
# Lister les rôles installés
ansible-galaxy list
# Supprimer un rôle
ansible-galaxy remove geerlingguy.nginx
```

### Collections

Travailler avec les collections Ansible pour des fonctionnalités étendues.

```bash
# Installer une collection
ansible-galaxy collection install community.general
```

```yaml
# Utiliser une collection dans le playbook
collections:
  - community.general
tasks:
  - name: Installer un paquet
    community.general.snap:
      name: code
      state: present
```

## Débogage et Dépannage

### Débogage des Tâches

Déboguer et dépanner l'exécution des playbooks.

```yaml
# Ajouter des tâches de débogage
- name: Afficher la valeur de la variable
  debug:
    var: my_variable
- name: Afficher un message personnalisé
  debug:
    msg: "L'hôte {{ inventory_hostname }} a l'IP {{ ansible_default_ipv4.address }}"
```

```bash
# Exécution verbeuse
ansible-playbook site.yml -v
ansible-playbook site.yml -vvv  # Verbosité maximale
```

### Gestion des Erreurs

Gérer les erreurs et les échecs avec élégance.

```yaml
- name: Tâche qui pourrait échouer
  command: /bin/false
  ignore_errors: yes

- name: Tâche avec rescue
  block:
    - command: /bin/false
  rescue:
    - debug:
        msg: 'La tâche a échoué, exécution de rescue'
  always:
    - debug:
        msg: 'Ceci s'exécute toujours'
```

### Tests et Validation

Tester les playbooks et valider les configurations.

```bash
# Vérifier la syntaxe
ansible-playbook site.yml --syntax-check
# Lister les tâches
ansible-playbook site.yml --list-tasks
# Lister les hôtes
ansible-playbook site.yml --list-hosts
# Parcourir le playbook
ansible-playbook site.yml --step
# Tester en mode check
ansible-playbook site.yml --check --diff
```

### Performance et Optimisation

Optimiser la performance et l'exécution des playbooks.

```yaml
# Exécuter des tâches en parallèle
- name: Installer des paquets
  apt:
    name: '{{ packages }}'
  vars:
    packages:
      - nginx
      - mysql-server

# Utiliser async pour les tâches de longue durée
- name: Tâche de longue durée
  command: /usr/bin/long-task
  async: 300
  poll: 5
```

## Bonnes Pratiques et Astuces

### Bonnes Pratiques de Sécurité

Sécuriser votre infrastructure et vos opérations Ansible.

```bash
# Utiliser Ansible Vault pour les secrets
ansible-vault create group_vars/all/vault.yml
# Désactiver la vérification des clés d'hôte avec prudence
host_key_checking = False
# Utiliser become uniquement lorsque nécessaire
become: yes
become_user: root
# Limiter la portée du playbook
ansible-playbook site.yml --limit production
```

### Organisation du Code

Structurer efficacement vos projets Ansible.

```bash
# Structure de répertoire recommandée
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
# Utiliser des noms significatifs et de la documentation
- name: Nom de tâche descriptif
  # Ajouter des commentaires pour une logique complexe
```

### Contrôle de Version et Tests

Gérer le code Ansible avec un contrôle de version approprié.

```bash
# Utiliser Git pour le contrôle de version
git init
git add .
git commit -m "Configuration Ansible initiale"
# Tester en staging avant la production
ansible-playbook -i staging site.yml
# Utiliser des tags pour une exécution sélective
ansible-playbook site.yml --tags "nginx,ssl"
```

## Configuration et Fonctionnalités Avancées

### Configuration Ansible

Personnaliser le comportement d'Ansible avec des options de configuration.

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

### Plugins de Rappel (Callback Plugins)

Améliorer la sortie et la journalisation avec des plugins de rappel.

```ini
# Activer les plugins de rappel dans ansible.cfg
[defaults]
stdout_callback = yaml
callbacks_enabled = profile_tasks, timer

# Configuration personnalisée du rappel
[callback_profile_tasks]
task_output_limit = 20
```

### Filtres et Plugins de Recherche (Lookup Plugins)

Utiliser les filtres Jinja2 et les plugins de recherche pour la manipulation de données.

```jinja2
# Filtres courants dans les modèles
{{ variable | default('default_value') }}
{{ list_var | length }}
{{ string_var | upper }}
{{ dict_var | to_nice_yaml }}
```

```yaml
# Plugins de recherche
- name: Lire le contenu d'un fichier
  debug:
    msg: "{{ lookup('file', '/etc/hostname') }}"

- name: Variable d'environnement
  debug:
    msg: "{{ lookup('env', 'HOME') }}"
```

### Inventaires Dynamiques

Utiliser des inventaires dynamiques pour les environnements cloud et conteneurisés.

```bash
# Inventaire dynamique AWS EC2
ansible-playbook -i ec2.py site.yml
# Inventaire dynamique Docker
ansible-playbook -i docker.yml site.yml
# Script d'inventaire personnalisé
ansible-playbook -i ./dynamic_inventory.py site.yml
```

## Liens Pertinents

- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/shell">Feuille de triche Shell</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>
- <router-link to="/docker">Feuille de triche Docker</router-link>
- <router-link to="/kubernetes">Feuille de triche Kubernetes</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>

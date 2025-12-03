---
title: 'Fiche Mémo Shell | LabEx'
description: "Apprenez le scripting shell avec cette fiche mémo complète. Référence rapide pour les commandes bash, le scripting shell, l'automatisation, les outils en ligne de commande et l'administration système Linux/Unix."
pdfUrl: '/cheatsheets/pdf/shell-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Feuille de triche Shell
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/shell">Apprenez le Shell avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez le scripting Shell et les opérations en ligne de commande grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours Shell complets couvrant les commandes Bash essentielles, les opérations sur fichiers, le traitement de texte, la gestion des processus et l'automatisation. Maîtrisez l'efficacité de la ligne de commande et les techniques de scripting shell.
</base-disclaimer-content>
</base-disclaimer>

## Opérations sur Fichiers et Répertoires

### Lister les Fichiers : `ls`

Afficher les fichiers et les répertoires dans l'emplacement actuel.

```bash
# Lister les fichiers dans le répertoire courant
ls
# Lister avec des informations détaillées
ls -l
# Afficher les fichiers cachés
ls -a
# Lister avec des tailles de fichiers lisibles par l'homme
ls -lh
# Trier par heure de modification
ls -lt
```

### Créer des Fichiers : `touch`

Créer des fichiers vides ou mettre à jour les horodatages.

```bash
# Créer un nouveau fichier
touch nouveau_fichier.txt
# Créer plusieurs fichiers
touch fichier1.txt fichier2.txt fichier3.txt
# Mettre à jour l'horodatage du fichier existant
touch fichier_existant.txt
```

### Créer des Répertoires : `mkdir`

Créer de nouveaux répertoires.

```bash
# Créer un répertoire
mkdir mon_repertoire
# Créer des répertoires imbriqués
mkdir -p parent/enfant/petit-enfant
# Créer plusieurs répertoires
mkdir dir1 dir2 dir3
```

### Copier des Fichiers : `cp`

Copier des fichiers et des répertoires.

```bash
# Copier un fichier
cp source.txt destination.txt
# Copier un répertoire récursivement
cp -r repertoire_source dest_repertoire
# Copier avec demande de confirmation
cp -i fichier1.txt fichier2.txt
# Préserver les attributs du fichier
cp -p original.txt copie.txt
```

### Déplacer/Renommer : `mv`

Déplacer ou renommer des fichiers et des répertoires.

```bash
# Renommer un fichier
mv ancien_nom.txt nouveau_nom.txt
# Déplacer un fichier vers un répertoire
mv fichier.txt /chemin/vers/repertoire/
# Déplacer plusieurs fichiers
mv fichier1 fichier2 fichier3 repertoire_cible/
```

### Supprimer des Fichiers : `rm`

Supprimer des fichiers et des répertoires.

```bash
# Supprimer un fichier
rm fichier.txt
# Supprimer un répertoire et son contenu
rm -r repertoire/
# Supprimer sans confirmation (force)
rm -f fichier.txt
# Suppression interactive (confirmer chaque élément)
rm -i *.txt
```

## Navigation et Gestion des Chemins

### Répertoire Courant : `pwd`

Afficher le chemin du répertoire de travail actuel.

```bash
# Afficher le répertoire courant
pwd
# Exemple de sortie :
/home/utilisateur/documents
```

### Changer de Répertoire : `cd`

Changer pour un répertoire différent.

```bash
# Aller au répertoire personnel
cd ~
# Aller au répertoire parent
cd ..
# Aller au répertoire précédent
cd -
# Aller à un répertoire spécifique
cd /chemin/vers/repertoire
```

<BaseQuiz id="shell-cd-1" correct="A">
  <template #question>
    Que fait <code>cd ~</code> ?
  </template>
  
  <BaseQuizOption value="A" correct>Change pour le répertoire personnel</BaseQuizOption>
  <BaseQuizOption value="B">Change pour le répertoire racine</BaseQuizOption>
  <BaseQuizOption value="C">Change pour le répertoire parent</BaseQuizOption>
  <BaseQuizOption value="D">Crée un nouveau répertoire</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le symbole <code>~</code> est un raccourci pour le répertoire personnel. <code>cd ~</code> navigue vers votre répertoire personnel, ce qui est équivalent à <code>cd $HOME</code> ou <code>cd /home/nom_utilisateur</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### Arborescence des Répertoires : `tree`

Afficher la structure des répertoires au format arborescent.

```bash
# Afficher l'arborescence du répertoire
tree
# Limiter la profondeur à 2 niveaux
tree -L 2
# Afficher uniquement les répertoires
tree -d
```

## Traitement de Texte et Recherche

### Visualiser des Fichiers : `cat` / `less` / `head` / `tail`

Afficher le contenu des fichiers de différentes manières.

```bash
# Afficher le fichier entier
cat fichier.txt
# Visualiser le fichier page par page
less fichier.txt
# Afficher les 10 premières lignes
head fichier.txt
# Afficher les 10 dernières lignes
tail fichier.txt
# Afficher les 20 dernières lignes
tail -n 20 fichier.txt
# Suivre les changements dans le fichier (utile pour les logs)
tail -f logfile.txt
```

### Rechercher dans les Fichiers : `grep`

Rechercher des motifs dans des fichiers texte.

```bash
# Rechercher un motif dans un fichier
grep "motif" fichier.txt
# Recherche insensible à la casse
grep -i "motif" fichier.txt
# Recherche récursive dans les répertoires
grep -r "motif" repertoire/
# Afficher les numéros de ligne
grep -n "motif" fichier.txt
# Compter les lignes correspondantes
grep -c "motif" fichier.txt
```

<BaseQuiz id="shell-grep-1" correct="B">
  <template #question>
    Que fait <code>grep -r "motif" repertoire/</code> ?
  </template>
  
  <BaseQuizOption value="A">Recherche uniquement dans le fichier courant</BaseQuizOption>
  <BaseQuizOption value="B" correct>Recherche récursivement dans tous les fichiers du répertoire</BaseQuizOption>
  <BaseQuizOption value="C">Remplace le motif dans les fichiers</BaseQuizOption>
  <BaseQuizOption value="D">Supprime les fichiers contenant le motif</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le drapeau <code>-r</code> fait que grep recherche récursivement dans tous les fichiers et sous-répertoires. Ceci est utile pour trouver des motifs de texte dans l'ensemble de l'arborescence d'un répertoire.
  </BaseQuizAnswer>
</BaseQuiz>

### Trouver des Fichiers : `find`

Localiser des fichiers et des répertoires en fonction de critères.

```bash
# Trouver des fichiers par nom
find . -name "*.txt"
# Trouver des fichiers par type
find . -type f -name "config*"
# Trouver des répertoires
find . -type d -name "backup"
# Trouver des fichiers modifiés dans les 7 derniers jours
find . -mtime -7
# Trouver et exécuter une commande
find . -name "*.log" -delete
```

### Manipulation de Texte : `sed` / `awk` / `sort`

Traiter et manipuler des données textuelles.

```bash
# Remplacer du texte dans un fichier
sed 's/ancien/nouveau/g' fichier.txt
# Extraire des colonnes spécifiques
awk '{print $1, $3}' fichier.txt
# Trier le contenu du fichier
sort fichier.txt
# Supprimer les lignes dupliquées
sort fichier.txt | uniq
# Compter la fréquence des mots
cat fichier.txt | tr ' ' '\n' | sort | uniq -c
```

## Permissions et Propriété des Fichiers

### Voir les Permissions : `ls -l`

Afficher les permissions détaillées et la propriété des fichiers.

```bash
# Afficher les informations détaillées du fichier
ls -l
# Exemple de sortie :
# -rw-r--r-- 1 utilisateur groupe 1024 Jan 1 12:00 fichier.txt
# d = répertoire, r = lecture, w = écriture, x = exécution
```

### Changer les Permissions : `chmod`

Modifier les permissions des fichiers et des répertoires.

```bash
# Donner la permission d'exécution au propriétaire
chmod +x script.sh
# Définir des permissions spécifiques (755)
chmod 755 fichier.txt
# Supprimer la permission d'écriture pour le groupe/autres
chmod go-w fichier.txt
# Changement de permission récursif
chmod -R 644 repertoire/
```

<BaseQuiz id="shell-chmod-1" correct="C">
  <template #question>
    Que définit <code>chmod 755 fichier.txt</code> ?
  </template>
  
  <BaseQuizOption value="A">Lecture, écriture, exécution pour tous les utilisateurs</BaseQuizOption>
  <BaseQuizOption value="B">Lecture et écriture pour le propriétaire, lecture pour les autres</BaseQuizOption>
  <BaseQuizOption value="C" correct>Lecture, écriture, exécution pour le propriétaire ; lecture, exécution pour le groupe et les autres</BaseQuizOption>
  <BaseQuizOption value="D">Lecture seule pour tous les utilisateurs</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 755</code> définit les permissions comme suit : propriétaire = 7 (rwx), groupe = 5 (r-x), autres = 5 (r-x). C'est un ensemble de permissions courant pour les fichiers exécutables et les répertoires.
  </BaseQuizAnswer>
</BaseQuiz>

### Changer la Propriété : `chown` / `chgrp`

Changer le propriétaire et le groupe d'un fichier.

```bash
# Changer le propriétaire
chown nouveau_proprietaire fichier.txt
# Changer le propriétaire et le groupe
chown nouveau_proprietaire:nouveau_groupe fichier.txt
# Changer uniquement le groupe
chgrp nouveau_groupe fichier.txt
# Changement de propriété récursif
chown -R utilisateur:groupe repertoire/
```

### Nombres de Permissions

Comprendre la notation numérique des permissions.

```text
# Calcul des permissions :
# 4 = lecture (r), 2 = écriture (w), 1 = exécution (x)
# 755 = rwxr-xr-x (propriétaire: rwx, groupe: r-x, autres: r-x)
# 644 = rw-r--r-- (propriétaire: rw-, groupe: r--, autres: r--)
# 777 = rwxrwxrwx (toutes les permissions pour tous)
# 600 = rw------- (propriétaire: rw-, groupe: ---, autres: ---)
```

## Gestion des Processus

### Voir les Processus : `ps` / `top` / `htop`

Afficher les informations sur les processus en cours d'exécution.

```bash
# Afficher les processus pour l'utilisateur courant
ps
# Afficher tous les processus avec détails
ps aux
# Afficher les processus en format arborescent
ps -ef --forest
# Visionneuse de processus interactive
top
# Visionneuse de processus améliorée (si disponible)
htop
```

### Tâches en Arrière-plan : `&` / `jobs` / `fg` / `bg`

Gérer les processus d'arrière-plan et de premier plan.

```bash
# Exécuter une commande en arrière-plan
commande &
# Lister les tâches actives
jobs
# Ramener une tâche au premier plan
fg %1
# Envoyer une tâche à l'arrière-plan
bg %1
# Suspendre le processus courant
Ctrl+Z
```

### Tuer les Processus : `kill` / `killall`

Terminer les processus par PID ou par nom.

```bash
# Tuer un processus par PID
kill 1234
# Tuer un processus de force
kill -9 1234
# Tuer tous les processus portant le nom
killall firefox
# Envoyer un signal spécifique
kill -TERM 1234
```

### Surveillance du Système : `free` / `df` / `du`

Surveiller les ressources système et l'utilisation du disque.

```bash
# Afficher l'utilisation de la mémoire
free -h
# Afficher l'espace disque
df -h
# Afficher la taille d'un répertoire
du -sh repertoire/
# Afficher les plus grands répertoires
du -h --max-depth=1 | sort -hr
```

## Redirection d'Entrée/Sortie

### Redirection : `>` / `>>` / `<`

Rediriger la sortie et l'entrée des commandes.

```bash
# Rediriger la sortie vers un fichier (écraser)
commande > sortie.txt
# Ajouter la sortie à un fichier
commande >> sortie.txt
# Rediriger l'entrée depuis un fichier
commande < entree.txt
# Rediriger la sortie et les erreurs
commande > sortie.txt 2>&1
# Jeter la sortie
commande > /dev/null
```

<BaseQuiz id="shell-redirect-1" correct="B">
  <template #question>
    Quelle est la différence entre <code>></code> et <code>>></code> dans la redirection shell ?
  </template>
  
  <BaseQuizOption value="A"><code>></code> ajoute, <code>>></code> écrase</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>></code> écrase le fichier, <code>>></code> ajoute au fichier</BaseQuizOption>
  <BaseQuizOption value="C"><code>></code> redirige stdout, <code>>></code> redirige stderr</BaseQuizOption>
  <BaseQuizOption value="D">Il n'y a pas de différence</BaseQuizOption>
  
  <BaseQuizAnswer>
    L'opérateur <code>></code> écrase le fichier cible s'il existe, tandis que <code>>></code> ajoute la sortie à la fin du fichier. Utilisez <code>>></code> lorsque vous souhaitez conserver le contenu existant.
  </BaseQuizAnswer>
</BaseQuiz>

### Pipes : `|`

Enchaîner des commandes ensemble à l'aide de pipes.

```bash
# Utilisation de base du pipe
commande1 | commande2
# Multiples pipes
cat fichier.txt | grep "motif" | sort | uniq
# Compter les lignes de la sortie
ps aux | wc -l
# Paginer à travers une longue sortie
ls -la | less
```

### Tee : `tee`

Écrire la sortie à la fois dans un fichier et dans la sortie standard.

```bash
# Sauvegarder la sortie et l'afficher
commande | tee sortie.txt
# Ajouter au fichier
commande | tee -a sortie.txt
# Sorties multiples
commande | tee fichier1.txt fichier2.txt
```

### Here Documents : `<<`

Fournir une entrée multiligne aux commandes.

```bash
# Créer un fichier avec here document
cat << EOF > fichier.txt
Ligne 1
Ligne 2
Ligne 3
EOF
# Envoyer un email avec here document
mail utilisateur@exemple.com << EOF
Sujet : Test
Ceci est un message de test.
EOF
```

## Variables et Environnement

### Variables : Affectation et Utilisation

Créer et utiliser des variables shell.

```bash
# Affecter des variables (pas d'espaces autour de =)
nom="John"
compte=42
# Utiliser des variables
echo $nom
echo "Bonjour, $nom"
echo "Compte : ${count}"
# Substitution de commande
repertoire_courant=$(pwd)
date_aujourdhui=$(date +%Y-%m-%d)
```

### Variables d'Environnement : `export` / `env`

Gérer les variables d'environnement.

```bash
# Exporter une variable vers l'environnement
export PATH="/nouveau/chemin:$PATH"
export MA_VAR="valeur"
# Afficher toutes les variables d'environnement
env
# Afficher une variable spécifique
echo $HOME
echo $PATH
# Supprimer une variable
unset MA_VAR
```

### Variables Spéciales

Variables shell intégrées ayant une signification particulière.

```bash
# Arguments du script
$0  # Nom du script
$1, $2, $3...  # Premier, deuxième, troisième argument
$#  # Nombre d'arguments
$@  # Tous les arguments comme mots séparés
$*  # Tous les arguments comme un seul mot
$?  # Statut de sortie de la dernière commande
# Information sur le processus
$$  # PID du shell courant
$!  # PID du dernier processus en arrière-plan
```

### Expansion de Paramètres

Techniques avancées de manipulation de variables.

```bash
# Valeurs par défaut
${var:-valeur_par_defaut}  # Utiliser la valeur par défaut si var est vide
${var:=valeur_par_defaut}  # Définir var à la valeur par défaut si vide
# Manipulation de chaînes
${var#motif}   # Supprimer la correspondance la plus courte depuis le début
${var##motif}  # Supprimer la correspondance la plus longue depuis le début
${var%motif}   # Supprimer la correspondance la plus courte depuis la fin
${var%%motif}  # Supprimer la correspondance la plus longue depuis la fin
```

## Bases du Scripting

### Structure du Script

Format de base du script et exécution.

```bash
#!/bin/bash
# Ceci est un commentaire
# Variables
salutation="Bonjour, Monde !"
utilisateur=$(whoami)
# Sortie
echo $salutation
echo "Utilisateur courant : $utilisateur"
# Rendre le script exécutable :
chmod +x script.sh
# Exécuter le script :
./script.sh
```

### Instructions Conditionnelles : `if`

Contrôler le flux d'exécution du script avec des conditions.

```bash
#!/bin/bash
if [ -f "fichier.txt" ]; then
    echo "Le fichier existe"
elif [ -d "repertoire" ]; then
    echo "Le répertoire existe"
else
    echo "Ni l'un ni l'autre n'existe"
fi
# Comparaison de chaînes
if [ "$USER" = "root" ]; then
    echo "Exécution en tant que root"
fi
# Comparaison numérique
if [ $compte -gt 10 ]; then
    echo "Le compte est supérieur à 10"
fi
```

### Boucles : `for` / `while`

Répéter des commandes à l'aide de boucles.

```bash
#!/bin/bash
# Boucle for avec une plage
for i in {1..5}; do
    echo "Nombre : $i"
done
# Boucle for avec des fichiers
for fichier in *.txt; do
    echo "Traitement de : $fichier"
done
# Boucle while
compte=1
while [ $compte -le 5 ]; do
    echo "Compte : $compte"
    count=$((count + 1))
done
```

### Fonctions

Créer des blocs de code réutilisables.

```bash
#!/bin/bash
# Définir une fonction
saluer() {
    local nom=$1
    echo "Bonjour, $nom !"
}
# Fonction avec valeur de retour
additionner_nombres() {
    local somme=$(($1 + $2))
    echo $somme
}
# Appeler des fonctions
saluer "Alice"
resultat=$(additionner_nombres 5 3)
echo "Somme : $resultat"
```

## Commandes Réseau et Système

### Commandes Réseau

Tester la connectivité et la configuration réseau.

```bash
# Tester la connectivité réseau
ping google.com
ping -c 4 google.com  # Envoyer seulement 4 paquets
# Recherche DNS
nslookup google.com
dig google.com
# Configuration réseau
ip addr show  # Afficher les adresses IP
ip route show # Afficher la table de routage
# Télécharger des fichiers
wget https://example.com/file.txt
curl -O https://example.com/file.txt
```

### Informations Système : `uname` / `whoami` / `date`

Obtenir des informations système et utilisateur.

```bash
# Informations système
uname -a      # Toutes les infos système
uname -r      # Version du noyau
hostname      # Nom de l'ordinateur
whoami        # Nom d'utilisateur courant
id            # ID utilisateur et groupes
# Date et heure
date          # Date/heure actuelle
date +%Y-%m-%d # Format personnalisé
uptime        # Temps de fonctionnement du système
```

### Archive et Compression : `tar` / `zip`

Créer et extraire des archives compressées.

```bash
# Créer une archive tar
tar -czf archive.tar.gz repertoire/
# Extraire une archive tar
tar -xzf archive.tar.gz
# Créer une archive zip
zip -r archive.zip repertoire/
# Extraire une archive zip
unzip archive.zip
# Voir le contenu de l'archive
tar -tzf archive.tar.gz
unzip -l archive.zip
```

### Transfert de Fichiers : `scp` / `rsync`

Transférer des fichiers entre systèmes.

```bash
# Copier un fichier vers un serveur distant
scp fichier.txt utilisateur@serveur:/chemin/vers/destination
# Copier depuis un serveur distant
scp utilisateur@serveur:/chemin/vers/fichier.txt .
# Synchroniser des répertoires (local vers distant)
rsync -avz repertoire_local/ utilisateur@serveur:/repertoire_distant/
# Synchroniser avec suppression (miroir)
rsync -avz --delete repertoire_local/ utilisateur@serveur:/repertoire_distant/
```

## Historique des Commandes et Raccourcis

### Historique des Commandes : `history`

Afficher et réutiliser les commandes précédentes.

```bash
# Afficher l'historique des commandes
history
# Afficher les 10 dernières commandes
history 10
# Exécuter la commande précédente
!!
# Exécuter une commande par son numéro
!123
# Exécuter la dernière commande commençant par 'ls'
!ls
# Rechercher dans l'historique interactivement
Ctrl+R
```

### Expansion de l'Historique

Réutiliser des parties des commandes précédentes.

```bash
# Arguments de la dernière commande
!$    # Dernier argument de la commande précédente
!^    # Premier argument de la commande précédente
!*    # Tous les arguments de la commande précédente
# Exemple d'utilisation :
ls /chemin/très/long/vers/fichier.txt
cd !$  # Va à /chemin/très/long/vers/fichier.txt
```

### Raccourcis Clavier

Raccourcis essentiels pour une utilisation efficace de la ligne de commande.

```bash
# Navigation
Ctrl+A  # Aller au début de la ligne
Ctrl+E  # Aller à la fin de la ligne
Ctrl+F  # Avancer d'un caractère
Ctrl+B  # Reculer d'un caractère
Alt+F   # Avancer d'un mot
Alt+B   # Reculer d'un mot
# Édition
Ctrl+U  # Effacer la ligne avant le curseur
Ctrl+K  # Effacer la ligne après le curseur
Ctrl+W  # Supprimer le mot avant le curseur
Ctrl+Y  # Coller le dernier texte supprimé
# Contrôle des processus
Ctrl+C  # Interrompre la commande courante
Ctrl+Z  # Suspendre la commande courante
Ctrl+D  # Quitter le shell ou EOF
```

## Combinaisons et Astuces de Commandes

### Combinaisons de Commandes Utiles

Commandes uniques puissantes pour les tâches courantes.

```bash
# Trouver et remplacer du texte dans plusieurs fichiers
find . -name "*.txt" -exec sed -i 's/ancien/nouveau/g' {} \;
# Trouver les plus grands fichiers dans le répertoire courant
du -ah . | sort -rh | head -10
# Surveiller un fichier journal pour un motif spécifique
tail -f /var/log/syslog | grep "ERREUR"
# Compter les fichiers dans un répertoire
ls -1 | wc -l
# Créer une sauvegarde avec horodatage
cp fichier.txt fichier.txt.sauvegarde.$(date +%Y%m%d-%H%M%S)
```

### Alias et Fonctions

Créer des raccourcis pour les commandes fréquemment utilisées.

```bash
# Créer des alias (ajouter à ~/.bashrc)
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
# Afficher tous les alias
alias
# Créer des alias persistants dans ~/.bashrc :
echo "alias ma_commande='longue commande ici'" >>
~/.bashrc
source ~/.bashrc
```

### Contrôle des Tâches et Sessions Screen

Gérer les processus de longue durée et les sessions.

```bash
# Démarrer une commande en arrière-plan
nohup longue_commande_en_cours &
# Démarrer une session screen
screen -S ma_session
# Détacher de screen : Ctrl+A puis D
# Rattaché à screen
screen -r ma_session
# Lister les sessions screen
screen -ls
# Alternative : tmux
tmux new -s ma_session
# Détacher : Ctrl+B puis D
tmux attach -t ma_session
```

### Maintenance du Système

Tâches courantes d'administration système.

```bash
# Vérifier l'utilisation du disque
df -h
du -sh /*
# Vérifier l'utilisation de la mémoire
free -h
cat /proc/meminfo
# Vérifier les services en cours d'exécution
systemctl status nom_service
systemctl list-units --type=service
# Mettre à jour les listes de paquets (Ubuntu/Debian)
sudo apt update && sudo apt upgrade
# Rechercher les paquets installés
dpkg -l | grep nom_paquet
```

## Liens Pertinents

- <router-link to="/linux">Feuille de triche Linux</router-link>
- <router-link to="/rhel">Feuille de triche Red Hat Enterprise Linux</router-link>
- <router-link to="/git">Feuille de triche Git</router-link>
- <router-link to="/docker">Feuille de triche Docker</router-link>
- <router-link to="/kubernetes">Feuille de triche Kubernetes</router-link>
- <router-link to="/ansible">Feuille de triche Ansible</router-link>
- <router-link to="/devops">Feuille de triche DevOps</router-link>
- <router-link to="/python">Feuille de triche Python</router-link>

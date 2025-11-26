---
title: 'Fiche Mémo Git'
description: 'Apprenez Git avec notre fiche mémo complète couvrant les commandes essentielles, les concepts et les meilleures pratiques.'
pdfUrl: '/cheatsheets/pdf/git-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Trombinoscope Git
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/fr/learn/git">Apprendre Git avec des Labs Pratiques</a>
</base-disclaimer-title>
<base-disclaimer-content>
Apprenez le contrôle de version Git grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours Git complets couvrant les commandes essentielles, les stratégies de branchement, les flux de travail de collaboration et les techniques avancées. Apprenez à gérer des dépôts de code, à résoudre des conflits et à travailler efficacement avec des équipes en utilisant Git et GitHub.
</base-disclaimer-content>
</base-disclaimer>

## Configuration et Initialisation du Dépôt

### Initialiser le Dépôt : `git init`

Créer un nouveau dépôt Git dans le répertoire courant.

```bash
# Initialiser un nouveau dépôt
git init
# Initialiser dans un nouveau répertoire
git init project-name
# Initialiser un dépôt "bare" (sans répertoire de travail)
git init --bare
# Utiliser un répertoire de modèles personnalisé
git init --template=path
```

### Cloner un Dépôt : `git clone`

Créer une copie locale d'un dépôt distant.

```bash
# Cloner via HTTPS
git clone https://github.com/user/repo.git
# Cloner via SSH
git clone git@github.com:user/repo.git
# Cloner avec un nom personnalisé
git clone repo.git local-name
# Clonage superficiel (dernier commit seulement)
git clone --depth 1 repo.git
```

### Configuration Globale : `git config`

Définir les informations utilisateur et les préférences globalement.

```bash
git config --global user.name "Votre Nom"
git config --global user.email "votre.email@example.com"
git config --global init.defaultBranch main
# Afficher tous les paramètres de configuration
git config --list
```

### Configuration Locale : `git config --local`

Définir la configuration spécifique au dépôt.

```bash
# Définir pour le dépôt courant uniquement
git config user.name "Nom du Projet"
# Email spécifique au projet
git config user.email "project@example.com"
```

### Gestion des Distants : `git remote`

Gérer les connexions aux dépôts distants.

```bash
# Ajouter un distant
git remote add origin https://github.com/user/repo.git
# Lister tous les remotes avec URLs
git remote -v
# Afficher les informations détaillées du distant
git remote show origin
# Renommer un distant
git remote rename origin upstream
# Supprimer un distant
git remote remove upstream
```

### Stockage des Identifiants : `git config credential`

Stocker les identifiants d'authentification pour éviter les connexions répétées.

```bash
# Mettre en cache pendant 15 minutes
git config --global credential.helper cache
# Stocker de manière permanente
git config --global credential.helper store
# Mettre en cache pendant 1 heure
git config --global credential.helper 'cache --timeout=3600'
```

## Informations et Statut du Dépôt

### Vérifier le Statut : `git status`

Afficher l'état actuel du répertoire de travail et de la zone de staging.

```bash
# Informations de statut complètes
git status
# Format de statut court
git status -s
# Format lisible par machine
git status --porcelain
# Afficher également les fichiers ignorés
git status --ignored
```

### Voir les Différences : `git diff`

Montrer les changements entre différents états de votre dépôt.

```bash
# Changements dans le répertoire de travail par rapport au staging
git diff
# Changements dans le staging par rapport au dernier commit
git diff --staged
# Tous les changements non validés
git diff HEAD
# Changements dans un fichier spécifique
git diff file.txt
```

### Voir l'Historique : `git log`

Afficher l'historique des commits et la chronologie du dépôt.

```bash
# Historique de commits complet
git log
# Format condensé sur une seule ligne
git log --oneline
# Afficher les 5 derniers commits
git log -5
# Graphique visuel des branches
git log --graph --all
```

## Staging et Validation des Changements

### Stager des Fichiers : `git add`

Ajouter des changements à la zone de staging pour le prochain commit.

```bash
# Stager un fichier spécifique
git add file.txt
# Stager tous les changements dans le répertoire courant
git add .
# Stager tous les changements (y compris les suppressions)
git add -A
# Stager tous les fichiers JavaScript
git add *.js
# Staging interactif (mode patch)
git add -p
```

### Valider les Changements : `git commit`

Enregistrer les changements stagés dans le dépôt avec un message descriptif.

```bash
# Commit avec message
git commit -m "Ajouter l'authentification utilisateur"
# Stager et commiter les fichiers modifiés
git commit -a -m "Mettre à jour la documentation"
# Modifier le dernier commit
git commit --amend
# Modifier sans changer le message
git commit --no-edit --amend
```

### Déstager des Fichiers : `git reset`

Retirer des fichiers de la zone de staging ou annuler des commits.

```bash
# Déstager un fichier spécifique
git reset file.txt
# Déstager tous les fichiers
git reset
# Annuler le dernier commit, garder les changements stagés
git reset --soft HEAD~1
# Annuler le dernier commit, jeter les changements
git reset --hard HEAD~1
```

### Jeter les Changements : `git checkout` / `git restore`

Rétablir les changements dans le répertoire de travail à l'état validé le plus récent.

```bash
# Jeter les changements dans un fichier (ancienne syntaxe)
git checkout -- file.txt
# Jeter les changements dans un fichier (nouvelle syntaxe)
git restore file.txt
# Déstager un fichier (nouvelle syntaxe)
git restore --staged file.txt
# Jeter tous les changements non validés
git checkout .
```

## Opérations sur les Branches

### Lister les Branches : `git branch`

Visualiser et gérer les branches du dépôt.

```bash
# Lister les branches locales
git branch
# Lister toutes les branches (locales et distantes)
git branch -a
# Lister uniquement les branches distantes
git branch -r
# Afficher le dernier commit sur chaque branche
git branch -v
```

### Créer et Changer : `git checkout` / `git switch`

Créer de nouvelles branches et basculer entre elles.

```bash
# Créer et basculer vers une nouvelle branche
git checkout -b feature-branch
# Créer et basculer (nouvelle syntaxe)
git switch -c feature-branch
# Basculer vers une branche existante
git checkout main
# Basculer vers une branche existante (nouvelle syntaxe)
git switch main
```

### Fusionner les Branches : `git merge`

Combiner les changements de différentes branches.

```bash
# Fusionner feature-branch dans la branche courante
git merge feature-branch
# Forcer la fusion (sans fast-forward)
git merge --no-ff feature-branch
# Squasher les commits avant la fusion
git merge --squash feature-branch
```

### Supprimer les Branches : `git branch -d`

Supprimer les branches qui ne sont plus nécessaires.

```bash
# Supprimer une branche fusionnée
git branch -d feature-branch
# Forcer la suppression d'une branche non fusionnée
git branch -D feature-branch
# Supprimer une branche distante
git push origin --delete feature-branch
```

## Opérations sur les Dépôts Distants

### Récupérer les Mises à Jour : `git fetch`

Télécharger les changements depuis le dépôt distant sans les fusionner.

```bash
# Récupérer depuis le distant par défaut
git fetch
# Récupérer depuis un distant spécifique
git fetch origin
# Récupérer depuis tous les remotes
git fetch --all
# Récupérer une branche spécifique
git fetch origin main
```

### Tirer les Changements : `git pull`

Télécharger et fusionner les changements depuis le dépôt distant.

```bash
# Tirer depuis la branche de suivi
git pull
# Tirer depuis une branche distante spécifique
git pull origin main
# Tirer avec rebase au lieu de merge
git pull --rebase
# Seulement fast-forward, pas de commit de fusion
git pull --ff-only
```

### Pousser les Changements : `git push`

Téléverser les commits locaux vers le dépôt distant.

```bash
# Pousser vers la branche de suivi
git push
# Pousser vers une branche distante spécifique
git push origin main
# Pousser et définir le suivi amont
git push -u origin feature
# Pousser de force en toute sécurité
git push --force-with-lease
```

### Suivre les Branches Distantes : `git branch --track`

Configurer le suivi entre les branches locales et distantes.

```bash
# Définir le suivi
git branch --set-upstream-to=origin/main main
# Suivre une branche distante
git checkout -b local-branch origin/remote-branch
```

## Stashing et Stockage Temporaire

### Stasher les Changements : `git stash`

Sauvegarder temporairement les changements non validés pour une utilisation ultérieure.

```bash
# Stasher les changements courants
git stash
# Stasher avec un message
git stash save "Travail en cours sur la fonctionnalité X"
# Inclure les fichiers non suivis
git stash -u
# Stasher uniquement les changements non stagés
git stash --keep-index
```

### Lister les Stashes : `git stash list`

Voir tous les stashes sauvegardés.

```bash
# Afficher tous les stashes
git stash list
# Afficher les changements dans le dernier stash
git stash show
# Afficher les changements dans un stash spécifique
git stash show stash@{1}
```

### Appliquer les Stashes : `git stash apply`

Restaurer les changements précédemment stashés.

```bash
# Appliquer le dernier stash
git stash apply
# Appliquer un stash spécifique
git stash apply stash@{1}
# Appliquer et supprimer le dernier stash
git stash pop
# Supprimer le dernier stash
git stash drop
# Créer une branche à partir d'un stash
git stash branch new-branch stash@{1}
# Supprimer tous les stashes
git stash clear
```

## Analyse de l'Historique et du Log

### Voir l'Historique des Commits : `git log`

Explorer l'historique du dépôt avec diverses options de formatage.

```bash
# Historique visuel des branches
git log --oneline --graph --all
# Commits par un auteur spécifique
git log --author="John Doe"
# Commits récents
git log --since="2 weeks ago"
# Rechercher dans les messages de commit
git log --grep="fix de bug"
```

### Annotation de Ligne : `git blame`

Voir qui a modifié pour la dernière fois chaque ligne d'un fichier.

```bash
# Afficher l'auteur ligne par ligne
git blame file.txt
# Annoter des lignes spécifiques
git blame -L 10,20 file.txt
# Alternative à blame
git annotate file.txt
```

### Rechercher dans le Dépôt : `git grep`

Rechercher des motifs de texte dans l'historique du dépôt.

```bash
# Rechercher du texte dans les fichiers suivis
git grep "function"
# Rechercher avec numéros de ligne
git grep -n "TODO"
# Rechercher dans les fichiers stagés
git grep --cached "bug"
```

### Détails du Commit : `git show`

Afficher les informations détaillées sur des commits spécifiques.

```bash
# Afficher les détails du dernier commit
git show
# Afficher le commit précédent
git show HEAD~1
# Afficher un commit spécifique par hash
git show abc123
# Afficher le commit avec les statistiques de fichier
git show --stat
```

## Annuler des Changements et Éditer l'Historique

### Revert des Commits : `git revert`

Créer de nouveaux commits qui annulent les changements précédents en toute sécurité.

```bash
# Revert du dernier commit
git revert HEAD
# Revert d'un commit spécifique
git revert abc123
# Revert d'une plage de commits
git revert HEAD~3..HEAD
# Revert sans commit automatique
git revert --no-commit abc123
```

### Réinitialiser l'Historique : `git reset`

Déplacer le pointeur de branche et modifier éventuellement le répertoire de travail.

```bash
# Annuler le commit, garder les changements stagés
git reset --soft HEAD~1
# Annuler le commit et le staging
git reset --mixed HEAD~1
# Annuler le commit, le staging et le répertoire de travail
git reset --hard HEAD~1
```

### Rebase Interactif : `git rebase -i`

Éditer, réordonner ou squasher des commits interactivement.

```bash
# Rebase interactif des 3 derniers commits
git rebase -i HEAD~3
# Rebase de la branche courante sur main
git rebase -i main
# Continuer après résolution des conflits
git rebase --continue
# Annuler l'opération de rebase
git rebase --abort
```

### Cherry-pick : `git cherry-pick`

Appliquer des commits spécifiques provenant d'autres branches.

```bash
# Appliquer un commit spécifique à la branche courante
git cherry-pick abc123
# Appliquer une plage de commits
git cherry-pick abc123..def456
# Cherry-pick sans valider
git cherry-pick -n abc123
```

## Résolution des Conflits

### Conflits de Fusion : Processus de Résolution

Étapes pour résoudre les conflits lors des opérations de fusion.

```bash
# Vérifier les fichiers en conflit
git status
# Marquer le conflit comme résolu
git add resolved-file.txt
# Terminer la fusion
git commit
# Annuler la fusion et revenir à l'état précédent
git merge --abort
```

### Outils de Fusion : `git mergetool`

Lancer des outils externes pour aider à résoudre visuellement les conflits.

```bash
# Lancer l'outil de fusion par défaut
git mergetool
# Définir l'outil de fusion par défaut
git config --global merge.tool vimdiff
# Utiliser un outil spécifique pour cette fusion
git mergetool --tool=meld
```

### Marqueurs de Conflit : Comprendre le Format

Interpréter le format des marqueurs de conflit de Git dans les fichiers.

```text
<<<<<<< HEAD
Contenu de la branche courante
=======
Contenu de la branche entrante
>>>>>>> feature-branch
```

Après avoir édité le fichier pour résoudre :

```bash
git add conflicted-file.txt
git commit
```

### Outils de Diff : `git difftool`

Utiliser des outils de diff externes pour une meilleure visualisation des conflits.

```bash
# Lancer l'outil de diff pour les changements
git difftool
# Définir l'outil de diff par défaut
git config --global diff.tool vimdiff
```

## Étiquetage et Versions

### Créer des Étiquettes : `git tag`

Marquer des commits spécifiques avec des étiquettes de version.

```bash
# Créer une étiquette légère (lightweight)
git tag v1.0
# Créer une étiquette annotée
git tag -a v1.0 -m "Version 1.0 release"
# Étiqueter un commit spécifique
git tag -a v1.0 abc123
# Créer une étiquette signée
git tag -s v1.0
```

### Lister et Afficher les Étiquettes : `git tag -l`

Visualiser les étiquettes existantes et leurs informations.

```bash
# Lister toutes les étiquettes
git tag
# Lister les étiquettes correspondant à un motif
git tag -l "v1.*"
# Afficher les détails de l'étiquette
git show v1.0
```

### Pousser les Étiquettes : `git push --tags`

Partager les étiquettes avec les dépôts distants.

```bash
# Pousser une étiquette spécifique
git push origin v1.0
# Pousser toutes les étiquettes
git push --tags
# Pousser toutes les étiquettes vers un distant spécifique
git push origin --tags
```

### Supprimer les Étiquettes : `git tag -d`

Supprimer les étiquettes des dépôts locaux et distants.

```bash
# Supprimer l'étiquette locale
git tag -d v1.0
# Supprimer l'étiquette distante
git push origin --delete tag v1.0
# Syntaxe de suppression alternative
git push origin :refs/tags/v1.0
```

## Configuration et Alias Git

### Voir la Configuration : `git config --list`

Afficher les paramètres de configuration Git actuels.

```bash
# Afficher tous les paramètres de configuration
git config --list
# Afficher uniquement les paramètres globaux
git config --global --list
# Afficher les paramètres spécifiques au dépôt
git config --local --list
# Afficher un paramètre spécifique
git config user.name
```

### Créer des Alias : `git config alias`

Configurer des raccourcis pour les commandes fréquemment utilisées.

```bash
# git st = git status
git config --global alias.st status
# git co = git checkout
git config --global alias.co checkout
# git br = git branch
git config --global alias.br branch
# git ci = git commit
git config --global alias.ci commit
```

### Alias Avancés : Commandes Complexes

Créer des alias pour des combinaisons de commandes complexes.

```bash
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.unstage "reset HEAD --"
git config --global alias.last "log -1 HEAD"
git config --global alias.visual "!gitk"
```

### Configuration de l'Éditeur : `git config core.editor`

Définir l'éditeur de texte préféré pour les messages de commit et les conflits.

```bash
# VS Code
git config --global core.editor "code --wait"
# Vim
git config --global core.editor "vim"
# Nano
git config --global core.editor "nano"
```

## Performance et Optimisation

### Maintenance du Dépôt : `git gc`

Optimiser les performances et le stockage du dépôt.

```bash
# Collecte des déchets standard
git gc
# Optimisation plus approfondie
git gc --aggressive
# Exécuter uniquement si nécessaire
git gc --auto
# Vérifier l'intégrité du dépôt
git fsck
```

### Gestion des Fichiers Volumineux : `git lfs`

Gérer efficacement les fichiers binaires volumineux avec Git LFS.

```bash
# Installer LFS dans le dépôt
git lfs install
# Suivre les fichiers PDF avec LFS
git lfs track "*.pdf"
# Lister les fichiers suivis par LFS
git lfs ls-files
# Migrer les fichiers existants
git lfs migrate import --include="*.zip"
```

### Clonages Superficiels : Réduire la Taille du Dépôt

Cloner des dépôts avec un historique limité pour des opérations plus rapides.

```bash
# Dernier commit seulement
git clone --depth 1 https://github.com/user/repo.git
# Les 10 derniers commits
git clone --depth 10 repo.git
# Convertir un clone superficiel en clone complet
git fetch --unshallow
```

### Checkout Épars : Travailler avec des Sous-répertoires

Ne récupérer que certaines parties des dépôts volumineux.

```bash
git config core.sparseCheckout true
echo "src/*" > .git/info/sparse-checkout
# Appliquer le checkout éparse
git read-tree -m -u HEAD
```

## Installation et Configuration de Git

### Gestionnaires de Paquets : `apt`, `yum`, `brew`

Installer Git en utilisant les gestionnaires de paquets du système.

```bash
# Ubuntu/Debian
sudo apt install git
# CentOS/RHEL
sudo yum install git
# macOS avec Homebrew
brew install git
# Windows avec winget
winget install Git.Git
```

### Téléchargement et Installation : Installateurs Officiels

Utiliser les installateurs officiels pour votre plateforme.

```bash
# Télécharger depuis https://git-scm.com/downloads
# Vérifier l'installation
git --version
# Afficher le chemin de l'exécutable Git
which git
```

### Configuration Initiale : Configuration Utilisateur

Configurer Git avec votre identité pour les commits.

```bash
git config --global user.name "Votre Nom Complet"
git config --global user.email "votre.email@example.com"
git config --global init.defaultBranch main
# Définir le comportement de fusion
git config --global pull.rebase false
```

## Flux de Travail et Bonnes Pratiques Git

### Flux de Travail des Branches de Fonctionnalités (Feature Branch Workflow)

Flux de travail standard pour le développement de fonctionnalités avec des branches isolées.

```bash
# Commencer depuis la branche main
git checkout main
# Obtenir les dernières modifications
git pull origin main
# Créer la branche de fonctionnalité
git checkout -b feature/user-auth
# ... effectuer des changements et des commits ...
# Pousser la branche de fonctionnalité
git push -u origin feature/user-auth
# ... créer une pull request ...
```

### Git Flow : Modèle de Branchement Structuré

Approche systématique avec des branches dédiées à différents objectifs.

```bash
# Initialiser Git Flow
git flow init
# Démarrer une fonctionnalité
git flow feature start new-feature
# Terminer la fonctionnalité
git flow feature finish new-feature
# Démarrer une branche de version
git flow release start 1.0.0
```

### Conventions de Message de Commit

Suivre le format de commit conventionnel pour un historique de projet clair.

```bash
# Format : <type>(<scope>): <sujet>
git commit -m "feat(auth): ajouter la fonctionnalité de connexion utilisateur"
git commit -m "fix(api): résoudre l'exception de pointeur nul"
git commit -m "docs(readme): mettre à jour les instructions d'installation"
git commit -m "refactor(utils): simplifier le formatage de la date"
```

### Commits Atomiques : Meilleures Pratiques

Créer des commits ciblés, à usage unique, pour un meilleur historique.

```bash
# Stager les changements interactivement
git add -p
# Changement spécifique
git commit -m "Ajouter la validation au champ email"
# À éviter : git commit -m "Corriger des trucs" # Trop vague
# Bon :  git commit -m "Corriger le motif regex de validation de l'email"
```

## Dépannage et Récupération

### Reflog : Outil de Récupération

Utiliser le journal de références de Git pour récupérer des commits perdus.

```bash
# Afficher le journal de références
git reflog
# Afficher les mouvements de HEAD
git reflog show HEAD
# Récupérer un commit perdu
git checkout abc123
# Créer une branche à partir d'un commit perdu
git branch recovery-branch abc123
```

### Dépôt Corrompu : Réparation

Corriger les problèmes d'intégrité du dépôt.

```bash
# Vérifier l'intégrité du dépôt
git fsck --full
# Nettoyage agressif
git gc --aggressive --prune=now
# Reconstruire l'index si corrompu
rm .git/index; git reset
```

### Problèmes d'Authentification

Résoudre les problèmes courants d'authentification et de permission.

```bash
# Utiliser un jeton
git remote set-url origin https://token@github.com/user/repo.git
# Ajouter la clé SSH à l'agent
ssh-add ~/.ssh/id_rsa
# Gestionnaire d'identifiants Windows
git config --global credential.helper manager-core
```

### Problèmes de Performance : Débogage

Identifier et résoudre les problèmes de performance du dépôt.

```bash
# Afficher la taille du dépôt
git count-objects -vH
# Compter le nombre total de commits
git log --oneline | wc -l
# Compter le nombre de branches
git for-each-ref --format='%(refname:short)' | wc -l
```

## Liens Pertinents

- <router-link to="/linux">Trombinoscope Linux</router-link>
- <router-link to="/shell">Trombinoscope Shell</router-link>
- <router-link to="/devops">Trombinoscope DevOps</router-link>
- <router-link to="/docker">Trombinoscope Docker</router-link>
- <router-link to="/kubernetes">Trombinoscope Kubernetes</router-link>
- <router-link to="/ansible">Trombinoscope Ansible</router-link>
- <router-link to="/python">Trombinoscope Python</router-link>
- <router-link to="/javascript">Trombinoscope JavaScript</router-link>

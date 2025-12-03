---
title: 'Fiche Mémo Git | LabEx'
description: 'Apprenez le contrôle de version Git avec cette fiche mémo complète. Référence rapide des commandes Git, du branching, du merging, du rebasing, des workflows GitHub et du développement collaboratif.'
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
Apprenez le contrôle de version Git grâce à des laboratoires pratiques et des scénarios réels. LabEx propose des cours Git complets couvrant les commandes essentielles, les stratégies de branchement, les flux de travail de collaboration et les techniques avancées. Apprenez à gérer les dépôts de code, à résoudre les conflits et à travailler efficacement avec des équipes en utilisant Git et GitHub.
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

Configurer les informations utilisateur et les préférences globalement.

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# Afficher tous les paramètres de configuration
git config --list
```

### Configuration Locale : `git config --local`

Configurer les paramètres spécifiques au dépôt.

```bash
# Définir pour le dépôt courant seulement
git config user.name "Project Name"
# Email spécifique au projet
git config user.email "project@example.com"
```

### Gestion des Distants : `git remote`

Gérer les connexions aux dépôts distants.

```bash
# Ajouter un distant
git remote add origin https://github.com/user/repo.git
# Lister tous les distants avec URLs
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

Afficher les changements entre différents états du dépôt.

```bash
# Changements dans le répertoire de travail vs staging
git diff
# Changements dans staging vs dernier commit
git diff --staged
# Tous les changements non validés
git diff HEAD
# Changements dans un fichier spécifique
git diff file.txt
```

### Voir l'Historique : `git log`

Afficher l'historique des commits et la chronologie du dépôt.

```bash
# Historique complet des commits
git log
# Format condensé sur une seule ligne
git log --oneline
# Afficher les 5 derniers commits
git log -5
# Graphique visuel des branches
git log --graph --all
```

## Mise en Staging et Validation (Commit)

### Mettre en Staging les Fichiers : `git add`

Ajouter des changements à la zone de staging pour le prochain commit.

```bash
# Mettre en staging un fichier spécifique
git add file.txt
# Mettre en staging tous les changements dans le répertoire courant
git add .
# Mettre en staging tous les changements (y compris les suppressions)
git add -A
# Mettre en staging tous les fichiers JavaScript
git add *.js
# Staging interactif (mode patch)
git add -p
```

### Valider les Changements : `git commit`

Sauvegarder les changements mis en staging dans le dépôt avec un message descriptif.

```bash
# Commit avec message
git commit -m "Add user authentication"
# Mettre en staging et valider les fichiers modifiés
git commit -a -m "Update docs"
# Modifier le dernier commit
git commit --amend
# Modifier sans changer le message
git commit --no-edit --amend
```

<BaseQuiz id="git-commit-1" correct="A">
  <template #question>
    Que fait `git commit -m "message"` ?
  </template>
  
  <BaseQuizOption value="A" correct>Crée un nouveau commit avec le message spécifié</BaseQuizOption>
  <BaseQuizOption value="B">Met en staging tous les changements dans le répertoire de travail</BaseQuizOption>
  <BaseQuizOption value="C">Pousse les changements vers le dépôt distant</BaseQuizOption>
  <BaseQuizOption value="D">Crée une nouvelle branche</BaseQuizOption>
  
  <BaseQuizAnswer>
    La commande `git commit -m` crée un nouveau commit avec les changements mis en staging et les sauvegarde dans l'historique du dépôt avec le message fourni. Elle ne pousse pas vers le distant et ne crée pas de branches.
  </BaseQuizAnswer>
</BaseQuiz>

### Retirer du Staging : `git reset`

Retirer des fichiers de la zone de staging ou annuler des commits.

```bash
# Retirer du staging un fichier spécifique
git reset file.txt
# Retirer du staging tous les fichiers
git reset
# Annuler le dernier commit, garder les changements en staging
git reset --soft HEAD~1
# Annuler le dernier commit, jeter les changements
git reset --hard HEAD~1
```

### Jeter les Changements : `git checkout` / `git restore`

Rétablir les changements du répertoire de travail à l'état validé le plus récent.

```bash
# Jeter les changements dans un fichier (ancienne syntaxe)
git checkout -- file.txt
# Jeter les changements dans un fichier (nouvelle syntaxe)
git restore file.txt
# Retirer du staging un fichier (nouvelle syntaxe)
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

<BaseQuiz id="git-branch-1" correct="B">
  <template #question>
    Que fait `git checkout -b feature-branch` ?
  </template>
  
  <BaseQuizOption value="A">Supprime la branche feature-branch</BaseQuizOption>
  <BaseQuizOption value="B" correct>Crée une nouvelle branche appelée feature-branch et bascule dessus</BaseQuizOption>
  <BaseQuizOption value="C">Fusionne feature-branch dans la branche courante</BaseQuizOption>
  <BaseQuizOption value="D">Affiche l'historique des commits de feature-branch</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le drapeau `-b` crée une nouvelle branche, et `checkout` bascule dessus. Cette commande combine les deux opérations : créer la branche et basculer immédiatement dessus.
  </BaseQuizAnswer>
</BaseQuiz>

### Fusionner les Branches : `git merge`

Combiner les changements provenant de différentes branches.

```bash
# Fusionner feature-branch dans la branche courante
git merge feature-branch
# Fusion forcée (sans fast-forward)
git merge --no-ff feature-branch
# Compacter les commits avant la fusion
git merge --squash feature-branch
```

### Supprimer les Branches : `git branch -d`

Supprimer les branches qui ne sont plus nécessaires.

```bash
# Supprimer une branche fusionnée
git branch -d feature-branch
# Supprimer de force une branche non fusionnée
git branch -D feature-branch
# Supprimer une branche distante
git push origin --delete feature-branch
```

## Opérations sur les Dépôts Distants

### Récupérer les Mises à Jour : `git fetch`

Télécharger les changements du dépôt distant sans les fusionner.

```bash
# Récupérer depuis le distant par défaut
git fetch
# Récupérer depuis un distant spécifique
git fetch origin
# Récupérer depuis tous les distants
git fetch --all
# Récupérer une branche spécifique
git fetch origin main
```

### Tirer les Changements : `git pull`

Télécharger et fusionner les changements du dépôt distant.

```bash
# Tirer depuis la branche de suivi
git pull
# Tirer depuis une branche distante spécifique
git pull origin main
# Tirer avec rebase au lieu de merge
git pull --rebase
# Fast-forward seulement, pas de commits de fusion
git pull --ff-only
```

<BaseQuiz id="git-pull-1" correct="C">
  <template #question>
    Quelle est la différence entre `git fetch` et `git pull` ?
  </template>
  
  <BaseQuizOption value="A">Il n'y a pas de différence ; ils font la même chose</BaseQuizOption>
  <BaseQuizOption value="B">git fetch pousse les changements, git pull télécharge les changements</BaseQuizOption>
  <BaseQuizOption value="C" correct>git fetch télécharge les changements sans fusionner, git pull télécharge et fusionne les changements</BaseQuizOption>
  <BaseQuizOption value="D">git fetch fonctionne avec les dépôts locaux, git pull fonctionne avec les dépôts distants</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git fetch` télécharge les changements depuis le dépôt distant mais ne les fusionne pas dans votre branche courante. `git pull` effectue les deux opérations : il récupère les changements puis les fusionne dans votre branche courante.
  </BaseQuizAnswer>
</BaseQuiz>

### Pousser les Changements : `git push`

Téléverser les commits locaux vers le dépôt distant.

```bash
# Pousser vers la branche de suivi
git push
# Pousser vers une branche distante spécifique
git push origin main
# Pousser et définir le suivi amont (upstream)
git push -u origin feature
# Pousser de force en toute sécurité
git push --force-with-lease
```

<BaseQuiz id="git-push-1" correct="D">
  <template #question>
    Que fait `git push -u origin feature` ?
  </template>
  
  <BaseQuizOption value="A">Supprime la branche feature du distant</BaseQuizOption>
  <BaseQuizOption value="B">Tire les changements depuis la branche feature</BaseQuizOption>
  <BaseQuizOption value="C">Fusionne la branche feature dans main</BaseQuizOption>
  <BaseQuizOption value="D" correct>Pousse la branche feature vers origin et configure le suivi</BaseQuizOption>
  
  <BaseQuizAnswer>
    Le drapeau `-u` (ou `--set-upstream`) pousse la branche vers le dépôt distant et configure le suivi, afin que les futures commandes `git push` et `git pull` sachent quelle branche distante utiliser.
  </BaseQuizAnswer>
</BaseQuiz>

### Suivre les Branches Distantes : `git branch --track`

Configurer le suivi entre les branches locales et distantes.

```bash
# Configurer le suivi
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
git stash save "Work in progress on feature X"
# Inclure les fichiers non suivis
git stash -u
# Stasher uniquement les changements non mis en staging
git stash --keep-index
```

### Lister les Stashes : `git stash list`

Visualiser tous les stashes sauvegardés.

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

<BaseQuiz id="git-stash-1" correct="B">
  <template #question>
    Quelle est la différence entre `git stash apply` et `git stash pop` ?
  </template>
  
  <BaseQuizOption value="A">git stash apply supprime le stash, git stash pop le conserve</BaseQuizOption>
  <BaseQuizOption value="B" correct>git stash apply conserve le stash, git stash pop le supprime après application</BaseQuizOption>
  <BaseQuizOption value="C">git stash apply fonctionne avec les dépôts distants, git stash pop fonctionne localement</BaseQuizOption>
  <BaseQuizOption value="D">Il n'y a pas de différence ; ils font la même chose</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git stash apply` restaure les changements stashés mais conserve le stash dans la liste. `git stash pop` applique le stash puis le supprime de la liste des stashes, ce qui est utile lorsque vous n'avez plus besoin du stash.
  </BaseQuizAnswer>
</BaseQuiz>

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
git log --grep="bug fix"
```

### Blâme et Annotation : `git blame`

Voir qui a modifié chaque ligne d'un fichier en dernier.

```bash
# Afficher l'auteur ligne par ligne
git blame file.txt
# Blâmer des lignes spécifiques
git blame -L 10,20 file.txt
# Alternative à blame
git annotate file.txt
```

### Rechercher dans le Dépôt : `git grep`

Rechercher des motifs de texte à travers l'historique du dépôt.

```bash
# Rechercher du texte dans les fichiers suivis
git grep "function"
# Rechercher avec les numéros de ligne
git grep -n "TODO"
# Rechercher dans les fichiers en staging
git grep --cached "bug"
```

### Détails du Commit : `git show`

Afficher des informations détaillées sur des commits spécifiques.

```bash
# Afficher les détails du dernier commit
git show
# Afficher le commit précédent
git show HEAD~1
# Afficher un commit spécifique par hash
git show abc123
# Afficher le commit avec les statistiques de fichiers
git show --stat
```

## Annuler les Changements et Éditer l'Historique

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
# Annuler le commit, garder les changements en staging
git reset --soft HEAD~1
# Annuler le commit et le staging
git reset --mixed HEAD~1
# Annuler le commit, le staging et le répertoire de travail
git reset --hard HEAD~1
```

### Rebase Interactif : `git rebase -i`

Éditer, réordonner ou compacter interactivement des commits.

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

Interpréter les marqueurs de conflit de Git dans les fichiers.

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

## Étiquetage et Versions (Tagging)

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

### Afficher la Configuration : `git config --list`

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
# Exécuter seulement si nécessaire
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
# 10 derniers commits
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

Utiliser les installateurs officiels Git pour votre plateforme.

```bash
# Télécharger depuis https://git-scm.com/downloads
# Vérifier l'installation
git --version
# Afficher le chemin de l'exécutable git
which git
```

### Configuration Initiale : Configuration Utilisateur

Configurer Git avec votre identité pour les commits.

```bash
git config --global user.name "Your Full Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# Définir le comportement de pull
git config --global pull.rebase false
```

## Flux de Travail Git et Bonnes Pratiques

### Flux de Travail des Branches de Fonctionnalités (Feature Branch Workflow)

Flux de travail standard pour le développement de fonctionnalités avec des branches isolées.

```bash
# Commencer depuis la branche main
git checkout main
# Obtenir les derniers changements
git pull origin main
# Créer la branche de fonctionnalité
git checkout -b feature/user-auth
# ... faire des changements et des commits ...
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
# Terminer une fonctionnalité
git flow feature finish new-feature
# Démarrer une branche de version
git flow release start 1.0.0
```

### Conventions de Messages de Commit

Suivre le format de commit conventionnel pour un historique de projet clair.

```bash
# Format : <type>(<scope>): <sujet>
git commit -m "feat(auth): add user login functionality"
git commit -m "fix(api): resolve null pointer exception"
git commit -m "docs(readme): update installation instructions"
git commit -m "refactor(utils): simplify date formatting"
```

### Commits Atomiques : Meilleures Pratiques

Créer des commits ciblés, à objectif unique, pour un meilleur historique.

```bash
# Stager interactivement
git add -p
# Changement spécifique
git commit -m "Add validation to email field"
# À éviter : git commit -m "Fix stuff" # Trop vague
# Bon :  git commit -m "Fix email validation regex pattern"
```

## Dépannage et Récupération

### Reflog : Outil de Récupération

Utiliser le journal de référence de Git pour récupérer des commits perdus.

```bash
# Afficher le journal de référence
git reflog
# Afficher les mouvements de HEAD
git reflog show HEAD
# Récupérer un commit perdu
git checkout abc123
# Créer une branche à partir d'un commit perdu
git branch recovery-branch abc123
```

### Dépôt Corrompu : Réparation

Corriger la corruption du dépôt et les problèmes d'intégrité.

```bash
# Vérifier l'intégrité du dépôt
git fsck --full
# Nettoyage agressif
git gc --aggressive --prune=now
# Reconstruire l'index si corrompu
rm .git/index; git reset
```

### Problèmes d'Authentification

Résoudre les problèmes courants d'authentification et de permissions.

```bash
# Utiliser un jeton (token)
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

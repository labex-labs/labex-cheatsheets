---
title: 'Hoja de Trucos de Git | LabEx'
description: 'Aprenda control de versiones Git con esta hoja de trucos completa. Referencia rápida de comandos Git, ramificación, fusión, rebase, flujos de trabajo de GitHub y desarrollo colaborativo.'
pdfUrl: '/cheatsheets/pdf/git-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Hoja de Trucos de Git
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/es/learn/git">Aprende Git con Laboratorios Prácticos</a>
</base-disclaimer-title>
<base-disclaimer-content>
Aprende el control de versiones Git a través de laboratorios prácticos y escenarios del mundo real. LabEx ofrece cursos completos de Git que cubren comandos esenciales, estrategias de ramificación, flujos de trabajo de colaboración y técnicas avanzadas. Aprende a gestionar repositorios de código, resolver conflictos y trabajar eficazmente con equipos utilizando Git y GitHub.
</base-disclaimer-content>
</base-disclaimer>

## Configuración e Inicialización del Repositorio

### Inicializar Repositorio: `git init`

Crea un nuevo repositorio Git en el directorio actual.

```bash
# Inicializar nuevo repositorio
git init
# Inicializar en nuevo directorio
git init project-name
# Inicializar repositorio "bare" (sin directorio de trabajo)
git init --bare
# Usar directorio de plantilla personalizado
git init --template=path
```

### Clonar Repositorio: `git clone`

Crea una copia local de un repositorio remoto.

```bash
# Clonar vía HTTPS
git clone https://github.com/user/repo.git
# Clonar vía SSH
git clone git@github.com:user/repo.git
# Clonar con nombre personalizado
git clone repo.git nombre-local
# Clonar superficial (solo el último commit)
git clone --depth 1 repo.git
```

### Configuración Global: `git config`

Establece la información del usuario y las preferencias globalmente.

```bash
git config --global user.name "Tu Nombre"
git config --global user.email "tu.email@example.com"
git config --global init.defaultBranch main
# Ver todas las configuraciones
git config --list
```

### Configuración Local: `git config --local`

Establece la configuración específica del repositorio.

```bash
# Establecer solo para el repo actual
git config user.name "Nombre del Proyecto"
# Email específico del proyecto
git config user.email "proyecto@example.com"
```

### Gestión de Remotos: `git remote`

Gestiona las conexiones a repositorios remotos.

```bash
# Añadir remoto
git remote add origin https://github.com/user/repo.git
# Listar todos los remotos con URLs
git remote -v
# Mostrar información detallada del remoto
git remote show origin
# Renombrar remoto
git remote rename origin upstream
# Eliminar remoto
git remote remove upstream
```

### Almacenamiento de Credenciales: `git config credential`

Almacena credenciales de autenticación para evitar iniciar sesión repetidamente.

```bash
# Caché por 15 minutos
git config --global credential.helper cache
# Almacenar permanentemente
git config --global credential.helper store
# Caché por 1 hora
git config --global credential.helper 'cache --timeout=3600'
```

## Información y Estado del Repositorio

### Verificar Estado: `git status`

Muestra el estado actual del directorio de trabajo y el área de preparación (staging).

```bash
# Información de estado completa
git status
# Formato de estado corto
git status -s
# Formato legible por máquina
git status --porcelain
# Mostrar también archivos ignorados
git status --ignored
```

### Ver Diferencias: `git diff`

Muestra los cambios entre diferentes estados de tu repositorio.

```bash
# Cambios en el directorio de trabajo vs staging
git diff
# Cambios en staging vs último commit
git diff --staged
# Todos los cambios no confirmados
git diff HEAD
# Cambios en un archivo específico
git diff file.txt
```

### Ver Historial: `git log`

Muestra el historial de commits y la línea de tiempo del repositorio.

```bash
# Historial de commits completo
git log
# Formato condensado de una sola línea
git log --oneline
# Mostrar los últimos 5 commits
git log -5
# Gráfico visual de ramas
git log --graph --all
```

## Preparación y Confirmación de Cambios

### Preparar Archivos: `git add`

Añade cambios al área de preparación para el próximo commit.

```bash
# Preparar archivo específico
git add file.txt
# Preparar todos los cambios en el directorio actual
git add .
# Preparar todos los cambios (incluyendo eliminaciones)
git add -A
# Preparar todos los archivos JavaScript
git add *.js
# Preparación interactiva (modo parche)
git add -p
```

### Confirmar Cambios: `git commit`

Guarda los cambios preparados en el repositorio con un mensaje descriptivo.

```bash
# Commit con mensaje
git commit -m "Añadir autenticación de usuario"
# Preparar y confirmar archivos modificados
git commit -a -m "Actualizar documentación"
# Modificar el último commit
git commit --amend
# Modificar sin cambiar el mensaje
git commit --no-edit --amend
```

<BaseQuiz id="git-commit-1" correct="A">
  <template #question>
    ¿Qué hace <code>git commit -m "message"</code>?
  </template>
  
  <BaseQuizOption value="A" correct>Crea un nuevo commit con el mensaje especificado</BaseQuizOption>
  <BaseQuizOption value="B">Prepara todos los cambios en el directorio de trabajo</BaseQuizOption>
  <BaseQuizOption value="C">Envía los cambios al repositorio remoto</BaseQuizOption>
  <BaseQuizOption value="D">Crea una nueva rama</BaseQuizOption>
  
  <BaseQuizAnswer>
    El comando <code>git commit -m</code> crea un nuevo commit con los cambios preparados y los guarda en el historial del repositorio con el mensaje proporcionado. No envía al remoto ni crea ramas.
  </BaseQuizAnswer>
</BaseQuiz>

### Despreparar Archivos: `git reset`

Elimina archivos del área de preparación o deshace commits.

```bash
# Despreparar archivo específico
git reset file.txt
# Despreparar todos los archivos
git reset
# Deshacer último commit, mantener cambios preparados
git reset --soft HEAD~1
# Deshacer último commit, descartar cambios
git reset --hard HEAD~1
```

### Descartar Cambios: `git checkout` / `git restore`

Revierte los cambios en el directorio de trabajo al último estado confirmado.

```bash
# Descartar cambios en archivo (sintaxis antigua)
git checkout -- file.txt
# Descartar cambios en archivo (nueva sintaxis)
git restore file.txt
# Despreparar archivo (nueva sintaxis)
git restore --staged file.txt
# Descartar todos los cambios no confirmados
git checkout .
```

## Operaciones de Ramas (Branches)

### Listar Ramas: `git branch`

Ver y gestionar las ramas del repositorio.

```bash
# Listar ramas locales
git branch
# Listar todas las ramas (locales y remotas)
git branch -a
# Listar solo ramas remotas
git branch -r
# Mostrar el último commit en cada rama
git branch -v
```

### Crear y Cambiar: `git checkout` / `git switch`

Crea nuevas ramas y cambia entre ellas.

```bash
# Crear y cambiar a nueva rama
git checkout -b feature-branch
# Crear y cambiar (nueva sintaxis)
git switch -c feature-branch
# Cambiar a rama existente
git checkout main
# Cambiar a rama existente (nueva sintaxis)
git switch main
```

<BaseQuiz id="git-branch-1" correct="B">
  <template #question>
    ¿Qué hace <code>git checkout -b feature-branch</code>?
  </template>
  
  <BaseQuizOption value="A">Elimina la rama feature-branch</BaseQuizOption>
  <BaseQuizOption value="B" correct>Crea una nueva rama llamada feature-branch y cambia a ella</BaseQuizOption>
  <BaseQuizOption value="C">Fusiona feature-branch en la rama actual</BaseQuizOption>
  <BaseQuizOption value="D">Muestra el historial de commits de feature-branch</BaseQuizOption>
  
  <BaseQuizAnswer>
    El flag <code>-b</code> crea una nueva rama, y <code>checkout</code> cambia a ella. Este comando combina ambas operaciones: crear la rama y cambiar inmediatamente a ella.
  </BaseQuizAnswer>
</BaseQuiz>

### Fusionar Ramas: `git merge`

Combina cambios de diferentes ramas.

```bash
# Fusionar feature-branch en la rama actual
git merge feature-branch
# Fusión forzada (sin fast-forward)
git merge --no-ff feature-branch
# Aplastar commits antes de fusionar
git merge --squash feature-branch
```

### Eliminar Ramas: `git branch -d`

Elimina ramas que ya no son necesarias.

```bash
# Eliminar rama fusionada
git branch -d feature-branch
# Eliminar rama no fusionada forzosamente
git branch -D feature-branch
# Eliminar rama remota
git push origin --delete feature-branch
```

## Operaciones de Repositorio Remoto

### Obtener Actualizaciones: `git fetch`

Descarga cambios del repositorio remoto sin fusionarlos.

```bash
# Obtener del remoto por defecto
git fetch
# Obtener de un remoto específico
git fetch origin
# Obtener de todos los remotos
git fetch --all
# Obtener rama específica
git fetch origin main
```

### Traer Cambios: `git pull`

Descarga y fusiona cambios del repositorio remoto.

```bash
# Traer desde la rama de seguimiento
git pull
# Traer desde rama remota específica
git pull origin main
# Traer usando rebase en lugar de merge
git pull --rebase
# Solo fast-forward, sin commits de fusión
git pull --ff-only
```

<BaseQuiz id="git-pull-1" correct="C">
  <template #question>
    ¿Cuál es la diferencia entre <code>git fetch</code> y <code>git pull</code>?
  </template>
  
  <BaseQuizOption value="A">No hay diferencia; hacen lo mismo</BaseQuizOption>
  <BaseQuizOption value="B">git fetch envía cambios, git pull descarga cambios</BaseQuizOption>
  <BaseQuizOption value="C" correct>git fetch descarga cambios sin fusionar, git pull descarga y fusiona cambios</BaseQuizOption>
  <BaseQuizOption value="D">git fetch funciona con repos locales, git pull funciona con repos remotos</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>git fetch</code> descarga cambios del repositorio remoto pero no los fusiona en tu rama actual. <code>git pull</code> realiza ambas operaciones: obtiene los cambios y luego los fusiona en tu rama actual.
  </BaseQuizAnswer>
</BaseQuiz>

### Enviar Cambios: `git push`

Sube los commits locales al repositorio remoto.

```bash
# Enviar a la rama de seguimiento
git push
# Enviar a rama remota específica
git push origin main
# Enviar y establecer seguimiento (upstream)
git push -u origin feature
# Empujar forzadamente de forma segura
git push --force-with-lease
```

<BaseQuiz id="git-push-1" correct="D">
  <template #question>
    ¿Qué hace <code>git push -u origin feature</code>?
  </template>
  
  <BaseQuizOption value="A">Elimina la rama feature del remoto</BaseQuizOption>
  <BaseQuizOption value="B">Trae cambios desde la rama feature</BaseQuizOption>
  <BaseQuizOption value="C">Fusiona la rama feature en main</BaseQuizOption>
  <BaseQuizOption value="D" correct>Envía la rama feature a origin y establece el seguimiento</BaseQuizOption>
  
  <BaseQuizAnswer>
    El flag <code>-u</code> (o <code>--set-upstream</code>) envía la rama al repositorio remoto y establece el seguimiento, por lo que los futuros comandos <code>git push</code> y <code>git pull</code> sabrán qué rama remota usar.
  </BaseQuizAnswer>
</BaseQuiz>

### Seguir Ramas Remotas: `git branch --track`

Establece el seguimiento entre ramas locales y remotas.

```bash
# Establecer seguimiento
git branch --set-upstream-to=origin/main main
# Seguir rama remota
git checkout -b local-branch origin/remote-branch
```

## Stashing y Almacenamiento Temporal

### Guardar Cambios Temporalmente: `git stash`

Guarda temporalmente los cambios no confirmados para usarlos más tarde.

```bash
# Guardar cambios actuales
git stash
# Guardar con mensaje
git stash save "Trabajo en progreso en la característica X"
# Incluir archivos no rastreados
git stash -u
# Guardar solo cambios no preparados
git stash --keep-index
```

### Listar Stashes: `git stash list`

Ver todos los stashes guardados.

```bash
# Mostrar todos los stashes
git stash list
# Mostrar cambios en el último stash
git stash show
# Mostrar cambios en un stash específico
git stash show stash@{1}
```

### Aplicar Stashes: `git stash apply`

Restaura los cambios guardados previamente.

```bash
# Aplicar el último stash
git stash apply
# Aplicar stash específico
git stash apply stash@{1}
# Aplicar y eliminar el último stash
git stash pop
# Eliminar el último stash
git stash drop
# Crear rama a partir de un stash
git stash branch new-branch stash@{1}
# Eliminar todos los stashes
git stash clear
```

<BaseQuiz id="git-stash-1" correct="B">
  <template #question>
    ¿Cuál es la diferencia entre <code>git stash apply</code> y <code>git stash pop</code>?
  </template>
  
  <BaseQuizOption value="A">git stash apply elimina el stash, git stash pop lo mantiene</BaseQuizOption>
  <BaseQuizOption value="B" correct>git stash apply mantiene el stash, git stash pop lo elimina después de aplicarlo</BaseQuizOption>
  <BaseQuizOption value="C">git stash apply funciona con repos remotos, git stash pop funciona localmente</BaseQuizOption>
  <BaseQuizOption value="D">No hay diferencia; hacen lo mismo</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>git stash apply</code> restaura los cambios guardados pero mantiene el stash en la lista. <code>git stash pop</code> aplica el stash y luego lo elimina de la lista, lo cual es útil cuando ya no necesitas el stash.
  </BaseQuizAnswer>
</BaseQuiz>

## Análisis de Historial y Logs

### Ver Historial de Commits: `git log`

Explora el historial del repositorio con varias opciones de formato.

```bash
# Historial visual de ramas
git log --oneline --graph --all
# Commits de un autor específico
git log --author="John Doe"
# Commits recientes
git log --since="2 weeks ago"
# Buscar en mensajes de commit
git log --grep="bug fix"
```

### Culpar y Anotar: `git blame`

Ver quién modificó por última vez cada línea de un archivo.

```bash
# Mostrar autoría línea por línea
git blame file.txt
# Culpar líneas específicas
git blame -L 10,20 file.txt
# Alternativa a blame
git annotate file.txt
```

### Buscar en el Repositorio: `git grep`

Busca patrones de texto a través del historial del repositorio.

```bash
# Buscar texto en archivos rastreados
git grep "function"
# Buscar con números de línea
git grep -n "TODO"
# Buscar en archivos preparados
git grep --cached "bug"
```

### Mostrar Detalles del Commit: `git show`

Muestra información detallada sobre commits específicos.

```bash
# Mostrar detalles del último commit
git show
# Mostrar commit anterior
git show HEAD~1
# Mostrar commit específico por hash
git show abc123
# Mostrar commit con estadísticas de archivos
git show --stat
```

## Deshacer Cambios y Edición de Historial

### Revertir Commits: `git revert`

Crea nuevos commits que deshacen cambios anteriores de forma segura.

```bash
# Revertir el último commit
git revert HEAD
# Revertir commit específico
git revert abc123
# Revertir rango de commits
git revert HEAD~3..HEAD
# Revertir sin commit automático
git revert --no-commit abc123
```

### Restablecer Historial: `git reset`

Mueve el puntero de la rama y modifica opcionalmente el directorio de trabajo.

```bash
# Deshacer commit, mantener cambios preparados
git reset --soft HEAD~1
# Deshacer commit y staging
git reset --mixed HEAD~1
# Deshacer commit, staging y directorio de trabajo
git reset --hard HEAD~1
```

### Rebase Interactivo: `git rebase -i`

Edita, reordena o aplasta commits interactivamente.

```bash
# Rebase interactivo de los últimos 3 commits
git rebase -i HEAD~3
# Rebase de la rama actual sobre main
git rebase -i main
# Continuar después de resolver conflictos
git rebase --continue
# Cancelar operación de rebase
git rebase --abort
```

### Cherry-pick: `git cherry-pick`

Aplica commits específicos de otras ramas.

```bash
# Aplicar commit específico a la rama actual
git cherry-pick abc123
# Aplicar rango de commits
git cherry-pick abc123..def456
# Cherry-pick sin confirmar
git cherry-pick -n abc123
```

## Resolución de Conflictos

### Conflictos de Fusión: Proceso de Resolución

Pasos para resolver conflictos durante operaciones de fusión.

```bash
# Verificar archivos en conflicto
git status
# Marcar archivo como resuelto
git add resolved-file.txt
# Completar la fusión
git commit
# Cancelar fusión y volver al estado anterior
git merge --abort
```

### Herramientas de Fusión: `git mergetool`

Lanza herramientas externas para ayudar a resolver conflictos visualmente.

```bash
# Lanzar herramienta de fusión por defecto
git mergetool
# Establecer herramienta de fusión por defecto
git config --global merge.tool vimdiff
# Usar herramienta específica para esta fusión
git mergetool --tool=meld
```

### Marcadores de Conflicto: Entender el Formato

Interpreta los marcadores de conflicto de Git en los archivos.

```text
<<<<<<< HEAD
Contenido de la rama actual
=======
Contenido de la rama entrante
>>>>>>> feature-branch
```

Después de editar el archivo para resolver:

```bash
git add conflicted-file.txt
git commit
```

### Herramientas de Diferencia: `git difftool`

Usa herramientas externas de diferencia para una mejor visualización de conflictos.

```bash
# Lanzar herramienta de diferencia para cambios
git difftool
# Establecer herramienta de diferencia por defecto
git config --global diff.tool vimdiff
```

## Etiquetado y Lanzamientos (Releases)

### Crear Etiquetas: `git tag`

Marca commits específicos con etiquetas de versión.

```bash
# Crear etiqueta ligera (lightweight)
git tag v1.0
# Crear etiqueta anotada
git tag -a v1.0 -m "Lanzamiento Versión 1.0"
# Etiquetar commit específico
git tag -a v1.0 abc123
# Crear etiqueta firmada
git tag -s v1.0
```

### Listar y Mostrar Etiquetas: `git tag -l`

Ver etiquetas existentes y su información.

```bash
# Listar todas las etiquetas
git tag
# Listar etiquetas que coinciden con un patrón
git tag -l "v1.*"
# Mostrar detalles de la etiqueta
git show v1.0
```

### Enviar Etiquetas: `git push --tags`

Comparte etiquetas con repositorios remotos.

```bash
# Enviar etiqueta específica
git push origin v1.0
# Enviar todas las etiquetas
git push --tags
# Enviar todas las etiquetas a un remoto específico
git push origin --tags
```

### Eliminar Etiquetas: `git tag -d`

Elimina etiquetas de repositorios locales y remotos.

```bash
# Eliminar etiqueta local
git tag -d v1.0
# Eliminar etiqueta remota
git push origin --delete tag v1.0
# Sintaxis alternativa de eliminación
git push origin :refs/tags/v1.0
```

## Configuración y Alias de Git

### Ver Configuración: `git config --list`

Muestra la configuración actual de Git.

```bash
# Mostrar todas las configuraciones
git config --list
# Mostrar solo configuraciones globales
git config --global --list
# Mostrar configuraciones específicas del repositorio
git config --local --list
# Mostrar configuración específica
git config user.name
```

### Crear Alias: `git config alias`

Establece atajos para comandos usados frecuentemente.

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

### Alias Avanzados: Comandos Complejos

Crea alias para combinaciones de comandos complejas.

```bash
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.unstage "reset HEAD --"
git config --global alias.last "log -1 HEAD"
git config --global alias.visual "!gitk"
```

### Configuración del Editor: `git config core.editor`

Establece el editor de texto preferido para mensajes de commit y conflictos.

```bash
# VS Code
git config --global core.editor "code --wait"
# Vim
git config --global core.editor "vim"
# Nano
git config --global core.editor "nano"
```

## Rendimiento y Optimización

### Mantenimiento del Repositorio: `git gc`

Optimiza el rendimiento y el almacenamiento del repositorio.

```bash
# Recolección de basura estándar
git gc
# Optimización más exhaustiva
git gc --aggressive
# Ejecutar solo si es necesario
git gc --auto
# Verificar integridad del repositorio
git fsck
```

### Manejo de Archivos Grandes: `git lfs`

Gestiona archivos binarios grandes eficientemente con Git LFS.

```bash
# Instalar LFS en el repositorio
git lfs install
# Rastrear archivos PDF con LFS
git lfs track "*.pdf"
# Listar archivos rastreados por LFS
git lfs ls-files
# Migrar archivos existentes
git lfs migrate import --include="*.zip"
```

### Clonaciones Superficiales: Reducción del Tamaño del Repositorio

Clona repositorios con historial limitado para operaciones más rápidas.

```bash
# Solo el último commit
git clone --depth 1 https://github.com/user/repo.git
# Últimos 10 commits
git clone --depth 10 repo.git
# Convertir superficial a completo
git fetch --unshallow
```

### Checkout Disperso (Sparse Checkout): Trabajar con Subdirectorios

Extrae solo partes específicas de repositorios grandes.

```bash
git config core.sparseCheckout true
echo "src/*" > .git/info/sparse-checkout
# Aplicar sparse checkout
git read-tree -m -u HEAD
```

## Instalación y Configuración de Git

### Gestores de Paquetes: `apt`, `yum`, `brew`

Instala Git usando gestores de paquetes del sistema.

```bash
# Ubuntu/Debian
sudo apt install git
# CentOS/RHEL
sudo yum install git
# macOS con Homebrew
brew install git
# Windows con winget
winget install Git.Git
```

### Descarga e Instalación: Instaladores Oficiales

Usa instaladores oficiales para tu plataforma.

```bash
# Descargar desde https://git-scm.com/downloads
# Verificar instalación
git --version
# Mostrar ruta del ejecutable de Git
which git
```

### Configuración Inicial: Configuración del Usuario

Configura Git con tu identidad para los commits.

```bash
git config --global user.name "Tu Nombre Completo"
git config --global user.email "tu.email@example.com"
git config --global init.defaultBranch main
# Establecer comportamiento de fusión
git config --global pull.rebase false
```

## Flujos de Trabajo y Mejores Prácticas de Git

### Flujo de Trabajo de Ramas de Características (Feature Branch Workflow)

Flujo de trabajo estándar para el desarrollo de características con ramas aisladas.

```bash
# Empezar desde la rama main
git checkout main
# Obtener los últimos cambios
git pull origin main
# Crear rama de característica
git checkout -b feature/user-auth
# ... hacer cambios y commits ...
# Enviar rama de característica
git push -u origin feature/user-auth
# ... crear pull request ...
```

### Git Flow: Modelo de Ramificación Estructurado

Enfoque sistemático con ramas dedicadas para diferentes propósitos.

```bash
# Inicializar Git Flow
git flow init
# Iniciar característica
git flow feature start nueva-caracteristica
# Finalizar característica
git flow feature finish nueva-caracteristica
# Iniciar rama de lanzamiento (release)
git flow release start 1.0.0
```

### Convenciones de Mensajes de Commit

Sigue el formato de commit convencional para un historial de proyecto claro.

```bash
# Formato: <tipo>(<ámbito>): <asunto>
git commit -m "feat(auth): añadir funcionalidad de inicio de sesión de usuario"
git commit -m "fix(api): resolver excepción de puntero nulo"
git commit -m "docs(readme): actualizar instrucciones de instalación"
git commit -m "refactor(utils): simplificar formato de fecha"
```

### Commits Atómicos: Mejores Prácticas

Crea commits enfocados y de propósito único para un mejor historial.

```bash
# Preparar cambios interactivamente
git add -p
# Cambio específico
git commit -m "Añadir validación al campo de correo electrónico"
# Evitar: git commit -m "Arreglar cosas" # Demasiado vago
# Bueno:  git commit -m "Arreglar patrón de expresión regular de validación de correo electrónico"
```

## Solución de Problemas y Recuperación

### Reflog: Herramienta de Recuperación

Usa el registro de referencias de Git para recuperar commits perdidos.

```bash
# Mostrar registro de referencias
git reflog
# Mostrar movimientos de HEAD
git reflog show HEAD
# Recuperar commit perdido
git checkout abc123
# Crear rama a partir de commit perdido
git branch recovery-branch abc123
```

### Repositorio Corrupto: Reparación

Soluciona problemas de corrupción e integridad del repositorio.

```bash
# Verificar integridad del repositorio
git fsck --full
# Limpieza agresiva
git gc --aggressive --prune=now
# Reconstruir índice si está corrupto
rm .git/index; git reset
```

### Problemas de Autenticación

Resuelve problemas comunes de autenticación y permisos.

```bash
# Usar token
git remote set-url origin https://token@github.com/user/repo.git
# Añadir clave SSH al agente
ssh-add ~/.ssh/id_rsa
# Administrador de credenciales de Windows
git config --global credential.helper manager-core
```

### Problemas de Rendimiento: Depuración

Identifica y resuelve problemas de rendimiento del repositorio.

```bash
# Mostrar tamaño del repositorio
git count-objects -vH
# Contar commits totales
git log --oneline | wc -l
# Contar ramas
git for-each-ref --format='%(refname:short)' | wc -l
```

## Enlaces Relevantes

- <router-link to="/linux">Hoja de Trucos de Linux</router-link>
- <router-link to="/shell">Hoja de Trucos de Shell</router-link>
- <router-link to="/devops">Hoja de Trucos de DevOps</router-link>
- <router-link to="/docker">Hoja de Trucos de Docker</router-link>
- <router-link to="/kubernetes">Hoja de Trucos de Kubernetes</router-link>
- <router-link to="/ansible">Hoja de Trucos de Ansible</router-link>
- <router-link to="/python">Hoja de Trucos de Python</router-link>
- <router-link to="/javascript">Hoja de Trucos de JavaScript</router-link>

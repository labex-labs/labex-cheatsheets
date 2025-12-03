---
title: 'Шпаргалка по Git | LabEx'
description: 'Изучите систему контроля версий Git с помощью этой исчерпывающей шпаргалки. Быстрый справочник по командам Git, ветвлению, слиянию, перебазированию, рабочим процессам GitHub и совместной разработке.'
pdfUrl: '/cheatsheets/pdf/git-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Git Справочник
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/git">Изучите Git с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите систему контроля версий Git с помощью практических лабораторных работ и сценариев из реального мира. LabEx предлагает комплексные курсы по Git, охватывающие основные команды, стратегии ветвления, рабочие процессы совместной работы и продвинутые методы. Научитесь управлять репозиториями кода, разрешать конфликты и эффективно работать с командами, используя Git и GitHub.
</base-disclaimer-content>
</base-disclaimer>

## Настройка и Конфигурация Репозитория

### Инициализация Репозитория: `git init`

Создает новый репозиторий Git в текущем каталоге.

```bash
# Инициализировать новый репозиторий
git init
# Инициализировать в новом каталоге
git init project-name
# Инициализировать "голый" репозиторий (без рабочей директории)
git init --bare
# Использовать пользовательский каталог шаблонов
git init --template=path
```

### Клонирование Репозитория: `git clone`

Создает локальную копию удаленного репозитория.

```bash
# Клонировать через HTTPS
git clone https://github.com/user/repo.git
# Клонировать через SSH
git clone git@github.com:user/repo.git
# Клонировать с пользовательским именем
git clone repo.git local-name
# Неполное клонирование (только последний коммит)
git clone --depth 1 repo.git
```

### Глобальная Конфигурация: `git config`

Настройка информации о пользователе и предпочтений глобально.

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# Просмотреть все настройки конфигурации
git config --list
```

### Локальная Конфигурация: `git config --local`

Установка конфигурации, специфичной для репозитория.

```bash
# Установить только для текущего репозитория
git config user.name "Project Name"
# Электронная почта для проекта
git config user.email "project@example.com"
```

### Управление Удаленными Репозиториями: `git remote`

Управление подключениями к удаленным репозиториям.

```bash
# Добавить удаленный репозиторий
git remote add origin https://github.com/user/repo.git
# Вывести список всех удаленных репозиториев с URL
git remote -v
# Показать подробную информацию об удаленном репозитории
git remote show origin
# Переименовать удаленный репозиторий
git remote rename origin upstream
# Удалить удаленный репозиторий
git remote remove upstream
```

### Хранение Учетных Данных: `git config credential`

Сохранение учетных данных аутентификации для избежания повторного входа.

```bash
# Кэшировать на 15 минут
git config --global credential.helper cache
# Сохранить на постоянной основе
git config --global credential.helper store
# Кэшировать на 1 час
git config --global credential.helper 'cache --timeout=3600'
```

## Информация о Репозитории и Статус

### Проверка Статуса: `git status`

Отображает текущее состояние рабочей директории и области проиндексированных изменений (staging area).

```bash
# Полная информация о статусе
git status
# Короткий формат статуса
git status -s
# Формат, пригодный для машинной обработки
git status --porcelain
# Также показывать игнорируемые файлы
git status --ignored
```

### Просмотр Различий: `git diff`

Показывает изменения между различными состояниями вашего репозитория.

```bash
# Изменения в рабочей директории по сравнению с областью проиндексированных изменений
git diff
# Изменения в области проиндексированных изменений по сравнению с последним коммитом
git diff --staged
# Все незафиксированные изменения
git diff HEAD
# Изменения в конкретном файле
git diff file.txt
```

### Просмотр Истории: `git log`

Отображает историю коммитов и временную шкалу репозитория.

```bash
# Полная история коммитов
git log
# Сжатый однострочный формат
git log --oneline
# Показать последние 5 коммитов
git log -5
# Визуальный граф ветвей
git log --graph --all
```

## Индексация и Фиксация Изменений

### Индексация Файлов: `git add`

Добавляет изменения в область проиндексированных изменений для следующего коммита.

```bash
# Индексировать конкретный файл
git add file.txt
# Индексировать все изменения в текущем каталоге
git add .
# Индексировать все изменения (включая удаления)
git add -A
# Индексировать все JavaScript файлы
git add *.js
# Интерактивная индексация (режим патча)
git add -p
```

### Фиксация Изменений: `git commit`

Сохраняет проиндексированные изменения в репозитории с описательным сообщением.

```bash
# Коммит с сообщением
git commit -m "Add user authentication"
# Индексировать и зафиксировать измененные файлы
git commit -a -m "Update docs"
# Изменить последний коммит
git commit --amend
# Изменить без изменения сообщения
git commit --no-edit --amend
```

<BaseQuiz id="git-commit-1" correct="A">
  <template #question>
    Что делает `git commit -m "message"`?
  </template>
  
  <BaseQuizOption value="A" correct>Создает новый коммит с указанным сообщением</BaseQuizOption>
  <BaseQuizOption value="B">Индексирует все изменения в рабочей директории</BaseQuizOption>
  <BaseQuizOption value="C">Отправляет изменения в удаленный репозиторий</BaseQuizOption>
  <BaseQuizOption value="D">Создает новую ветку</BaseQuizOption>
  
  <BaseQuizAnswer>
    Команда `git commit -m` создает новый коммит с проиндексированными изменениями и сохраняет их в истории репозитория с предоставленным сообщением. Она не отправляет изменения в удаленный репозиторий и не создает ветки.
  </BaseQuizAnswer>
</BaseQuiz>

### Отмена Индексации Файлов: `git reset`

Удаляет файлы из области проиндексированных изменений или отменяет коммиты.

```bash
# Отменить индексацию конкретного файла
git reset file.txt
# Отменить индексацию всех файлов
git reset
# Отменить последний коммит, сохранив изменения проиндексированными
git reset --soft HEAD~1
# Отменить последний коммит, отбросив изменения
git reset --hard HEAD~1
```

### Отбрасывание Изменений: `git checkout` / `git restore`

Возвращает изменения в рабочей директории к состоянию последнего коммита.

```bash
# Отбросить изменения в файле (старый синтаксис)
git checkout -- file.txt
# Отбросить изменения в файле (новый синтаксис)
git restore file.txt
# Отменить индексацию файла (новый синтаксис)
git restore --staged file.txt
# Отбросить все незафиксированные изменения
git checkout .
```

## Операции с Ветками

### Список Ветвей: `git branch`

Просмотр и управление ветвями репозитория.

```bash
# Вывести список локальных веток
git branch
# Вывести список всех веток (локальных и удаленных)
git branch -a
# Вывести список только удаленных веток
git branch -r
# Показать последний коммит в каждой ветке
git branch -v
```

### Создание и Переключение: `git checkout` / `git switch`

Создание новых веток и переключение между ними.

```bash
# Создать новую ветку и переключиться на нее
git checkout -b feature-branch
# Создать и переключиться (новый синтаксис)
git switch -c feature-branch
# Переключиться на существующую ветку
git checkout main
# Переключиться на существующую ветку (новый синтаксис)
git switch main
```

<BaseQuiz id="git-branch-1" correct="B">
  <template #question>
    Что делает `git checkout -b feature-branch`?
  </template>
  
  <BaseQuizOption value="A">Удаляет ветку feature-branch</BaseQuizOption>
  <BaseQuizOption value="B" correct>Создает новую ветку с именем feature-branch и переключается на нее</BaseQuizOption>
  <BaseQuizOption value="C">Объединяет feature-branch с текущей веткой</BaseQuizOption>
  <BaseQuizOption value="D">Показывает историю коммитов feature-branch</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `-b` создает новую ветку, а `checkout` переключается на нее. Эта команда объединяет обе операции: создание ветки и немедленное переключение на нее.
  </BaseQuizAnswer>
</BaseQuiz>

### Слияние Ветвей: `git merge`

Объединение изменений из разных веток.

```bash
# Объединить feature-branch с текущей веткой
git merge feature-branch
# Принудительное слияние с созданием коммита
git merge --no-ff feature-branch
# Сжать коммиты перед слиянием
git merge --squash feature-branch
```

### Удаление Ветвей: `git branch -d`

Удаление веток, которые больше не нужны.

```bash
# Удалить объединенную ветку
git branch -d feature-branch
# Принудительное удаление необъединенной ветки
git branch -D feature-branch
# Удалить удаленную ветку
git push origin --delete feature-branch
```

## Операции с Удаленным Репозиторием

### Получение Обновлений: `git fetch`

Загружает изменения из удаленного репозитория без слияния.

```bash
# Получить изменения из удаленного репозитория по умолчанию
git fetch
# Получить изменения из конкретного удаленного репозитория
git fetch origin
# Получить изменения из всех удаленных репозиториев
git fetch --all
# Получить конкретную ветку
git fetch origin main
```

### Загрузка Изменений: `git pull`

Загружает и объединяет изменения из удаленного репозитория.

```bash
# Загрузить из отслеживаемой ветки
git pull
# Загрузить из конкретной удаленной ветки
git pull origin main
# Загрузить с использованием rebase вместо merge
git pull --rebase
# Только fast-forward, без коммитов слияния
git pull --ff-only
```

<BaseQuiz id="git-pull-1" correct="C">
  <template #question>
    В чем разница между `git fetch` и `git pull`?
  </template>
  
  <BaseQuizOption value="A">Разницы нет; они делают одно и то же</BaseQuizOption>
  <BaseQuizOption value="B">git fetch отправляет изменения, git pull загружает изменения</BaseQuizOption>
  <BaseQuizOption value="C" correct>git fetch загружает изменения без слияния, git pull загружает и объединяет изменения</BaseQuizOption>
  <BaseQuizOption value="D">git fetch работает с локальными репозиториями, git pull работает с удаленными</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git fetch` загружает изменения из удаленного репозитория, но не объединяет их с вашей текущей веткой. `git pull` выполняет обе операции: он получает изменения, а затем объединяет их с вашей текущей веткой.
  </BaseQuizAnswer>
</BaseQuiz>

### Отправка Изменений: `git push`

Загружает локальные коммиты в удаленный репозиторий.

```bash
# Отправить в отслеживаемую ветку
git push
# Отправить в конкретную удаленную ветку
git push origin main
# Отправить и установить отслеживание (upstream)
git push -u origin feature
# Принудительная отправка с безопасной проверкой
git push --force-with-lease
```

<BaseQuiz id="git-push-1" correct="D">
  <template #question>
    Что делает `git push -u origin feature`?
  </template>
  
  <BaseQuizOption value="A">Удаляет ветку feature из удаленного репозитория</BaseQuizOption>
  <BaseQuizOption value="B">Загружает изменения из ветки feature</BaseQuizOption>
  <BaseQuizOption value="C">Объединяет ветку feature с main</BaseQuizOption>
  <BaseQuizOption value="D" correct>Отправляет ветку feature в origin и настраивает отслеживание</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `-u` (или `--set-upstream`) отправляет ветку в удаленный репозиторий и настраивает отслеживание, чтобы будущие команды `git push` и `git pull` знали, какую удаленную ветку использовать.
  </BaseQuizAnswer>
</BaseQuiz>

### Отслеживание Удаленных Ветвей: `git branch --track`

Настройка отслеживания между локальными и удаленными ветвями.

```bash
# Установить отслеживание
git branch --set-upstream-to=origin/main main
# Отслеживать удаленную ветку
git checkout -b local-branch origin/remote-branch
```

## Стейшинг и Временное Хранение

### Стейшинг Изменений: `git stash`

Временно сохраняет незафиксированные изменения для последующего использования.

```bash
# Стейшинг текущих изменений
git stash
# Стейшинг с сообщением
git stash save "Work in progress on feature X"
# Включая неотслеживаемые файлы
git stash -u
# Стейшинг только не проиндексированных изменений
git stash --keep-index
```

### Список Стейшей: `git stash list`

Просмотр всех сохраненных стейшей.

```bash
# Показать все стейши
git stash list
# Показать изменения в последнем стейше
git stash show
# Показать изменения в конкретном стейше
git stash show stash@{1}
```

### Применение Стейшей: `git stash apply`

Восстановление ранее сохраненных изменений.

```bash
# Применить последний стейш
git stash apply
# Применить конкретный стейш
git stash apply stash@{1}
# Применить и удалить последний стейш
git stash pop
# Удалить последний стейш
git stash drop
# Создать ветку из стейша
git stash branch new-branch stash@{1}
# Удалить все стейши
git stash clear
```

<BaseQuiz id="git-stash-1" correct="B">
  <template #question>
    В чем разница между `git stash apply` и `git stash pop`?
  </template>
  
  <BaseQuizOption value="A">git stash apply удаляет стейш, git stash pop оставляет его</BaseQuizOption>
  <BaseQuizOption value="B" correct>git stash apply оставляет стейш, git stash pop удаляет его после применения</BaseQuizOption>
  <BaseQuizOption value="C">git stash apply работает с удаленными репозиториями, git stash pop работает локально</BaseQuizOption>
  <BaseQuizOption value="D">Разницы нет; они делают одно и то же</BaseQuizOption>
  
  <BaseQuizAnswer>
    `git stash apply` восстанавливает стейшированные изменения, но оставляет стейш в списке. `git stash pop` применяет стейш, а затем удаляет его из списка стейшей, что полезно, когда стейш больше не нужен.
  </BaseQuizAnswer>
</BaseQuiz>

## Анализ Истории и Лога

### Просмотр Истории Коммитов: `git log`

Исследование истории репозитория с различными опциями форматирования.

```bash
# Визуальная история ветвей
git log --oneline --graph --all
# Коммиты от конкретного автора
git log --author="John Doe"
# Недавние коммиты
git log --since="2 weeks ago"
# Поиск по сообщениям коммитов
git log --grep="bug fix"
```

### Аннотация и Авторство: `git blame`

Показывает, кто и когда изменил каждую строку файла.

```bash
# Показать авторство построчно
git blame file.txt
# Аннотация конкретных строк
git blame -L 10,20 file.txt
# Альтернатива blame
git annotate file.txt
```

### Поиск по Репозиторию: `git grep`

Поиск текстовых шаблонов по истории репозитория.

```bash
# Поиск текста в отслеживаемых файлах
git grep "function"
# Поиск с номерами строк
git grep -n "TODO"
# Поиск в проиндексированных файлах
git grep --cached "bug"
```

### Детали Коммита: `git show`

Отображение подробной информации о конкретных коммитах.

```bash
# Показать детали последнего коммита
git show
# Показать предыдущий коммит
git show HEAD~1
# Показать конкретный коммит по хешу
git show abc123
# Показать коммит со статистикой по файлам
git show --stat
```

## Отмена Изменений и Редактирование Истории

### Отмена Коммитов: `git revert`

Создает новые коммиты, которые безопасно отменяют предыдущие изменения.

```bash
# Отменить последний коммит
git revert HEAD
# Отменить конкретный коммит
git revert abc123
# Отменить диапазон коммитов
git revert HEAD~3..HEAD
# Отменить без автоматического создания коммита
git revert --no-commit abc123
```

### Сброс Истории: `git reset`

Перемещает указатель ветки и, при необходимости, изменяет рабочую директорию.

```bash
# Отменить коммит, сохранив изменения проиндексированными
git reset --soft HEAD~1
# Отменить коммит и индексацию
git reset --mixed HEAD~1
# Отменить коммит, индексацию и рабочую директорию
git reset --hard HEAD~1
```

### Интерактивный Rebase: `git rebase -i`

Интерактивное редактирование, переупорядочивание или сжатие коммитов.

```bash
# Интерактивный rebase последних 3 коммитов
git rebase -i HEAD~3
# Rebase текущей ветки на main
git rebase -i main
# Продолжить после разрешения конфликтов
git rebase --continue
# Отменить операцию rebase
git rebase --abort
```

### Cherry-pick: `git cherry-pick`

Применение конкретных коммитов из других веток.

```bash
# Применить конкретный коммит к текущей ветке
git cherry-pick abc123
# Применить диапазон коммитов
git cherry-pick abc123..def456
# Cherry-pick без создания коммита
git cherry-pick -n abc123
```

## Разрешение Конфликтов

### Конфликты Слияния: Процесс Разрешения

Шаги для разрешения конфликтов во время операций слияния.

```bash
# Проверить конфликтные файлы
git status
# Отметить конфликт как разрешенный
git add resolved-file.txt
# Завершить слияние
git commit
# Отменить слияние и вернуться к предыдущему состоянию
git merge --abort
```

### Инструменты Слияния: `git mergetool`

Запуск внешних инструментов для визуального разрешения конфликтов.

```bash
# Запустить инструмент слияния по умолчанию
git mergetool
# Установить инструмент слияния по умолчанию
git config --global merge.tool vimdiff
# Использовать конкретный инструмент для этого слияния
git mergetool --tool=meld
```

### Маркеры Конфликтов: Понимание Формата

Интерпретация маркеров конфликтов Git в файлах.

```text
<<<<<<< HEAD
Содержимое текущей ветки
=======
Содержимое входящей ветки
>>>>>>> feature-branch
```

После редактирования файла для разрешения:

```bash
git add conflicted-file.txt
git commit
```

### Инструменты Diff: `git difftool`

Использование внешних инструментов diff для лучшей визуализации конфликтов.

```bash
# Запустить инструмент diff для изменений
git difftool
# Установить инструмент diff по умолчанию
git config --global diff.tool vimdiff
```

## Тегирование и Релизы

### Создание Тегов: `git tag`

Пометка конкретных коммитов метками версий.

```bash
# Создать легковесный тег
git tag v1.0
# Создать аннотированный тег
git tag -a v1.0 -m "Version 1.0 release"
# Тегировать конкретный коммит
git tag -a v1.0 abc123
# Создать подписанный тег
git tag -s v1.0
```

### Список и Просмотр Тегов: `git tag -l`

Просмотр существующих тегов и их информации.

```bash
# Вывести список всех тегов
git tag
# Вывести список тегов, соответствующих шаблону
git tag -l "v1.*"
# Показать детали тега
git show v1.0
```

### Отправка Тегов: `git push --tags`

Отправка тегов в удаленные репозитории.

```bash
# Отправить конкретный тег
git push origin v1.0
# Отправить все теги
git push --tags
# Отправить все теги в конкретный удаленный репозиторий
git push origin --tags
```

### Удаление Тегов: `git tag -d`

Удаление тегов из локальных и удаленных репозиториев.

```bash
# Удалить локальный тег
git tag -d v1.0
# Удалить удаленный тег
git push origin --delete tag v1.0
# Альтернативный синтаксис удаления
git push origin :refs/tags/v1.0
```

## Конфигурация и Псевдонимы Git

### Просмотр Конфигурации: `git config --list`

Отображение текущих настроек конфигурации Git.

```bash
# Показать все настройки конфигурации
git config --list
# Показать только глобальные настройки
git config --global --list
# Показать настройки, специфичные для репозитория
git config --local --list
# Показать конкретную настройку
git config user.name
```

### Создание Псевдонимов: `git config alias`

Настройка ярлыков для часто используемых команд.

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

### Сложные Псевдонимы: Комплексные Команды

Создание псевдонимов для сложных комбинаций команд.

```bash
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.unstage "reset HEAD --"
git config --global alias.last "log -1 HEAD"
git config --global alias.visual "!gitk"
```

### Конфигурация Редактора: `git config core.editor`

Установка предпочтительного текстового редактора для сообщений коммитов и конфликтов.

```bash
# VS Code
git config --global core.editor "code --wait"
# Vim
git config --global core.editor "vim"
# Nano
git config --global core.editor "nano"
```

## Производительность и Оптимизация

### Обслуживание Репозитория: `git gc`

Оптимизация производительности и хранения репозитория.

```bash
# Стандартная сборка мусора
git gc
# Более тщательная оптимизация
git gc --aggressive
# Запускать только при необходимости
git gc --auto
# Проверить целостность репозитория
git fsck
```

### Обработка Больших Файлов: `git lfs`

Эффективное управление большими бинарными файлами с помощью Git LFS.

```bash
# Установить LFS в репозитории
git lfs install
# Отслеживать PDF-файлы с помощью LFS
git lfs track "*.pdf"
# Показать файлы, отслеживаемые LFS
git lfs ls-files
# Миграция существующих файлов
git lfs migrate import --include="*.zip"
```

### Неполные Клоны: Уменьшение Размера Репозитория

Клонирование репозиториев с ограниченной историей для более быстрых операций.

```bash
# Только последний коммит
git clone --depth 1 https://github.com/user/repo.git
# Последние 10 коммитов
git clone --depth 10 repo.git
# Преобразовать неполный клон в полный
git fetch --unshallow
```

### Разреженное Извлечение: Работа с Подкаталогами

Извлечение только определенных частей больших репозиториев.

```bash
git config core.sparseCheckout true
echo "src/*" > .git/info/sparse-checkout
# Применить разреженное извлечение
git read-tree -m -u HEAD
```

## Установка и Настройка Git

### Менеджеры Пакетов: `apt`, `yum`, `brew`

Установка Git с использованием системных менеджеров пакетов.

```bash
# Ubuntu/Debian
sudo apt install git
# CentOS/RHEL
sudo yum install git
# macOS с Homebrew
brew install git
# Windows с winget
winget install Git.Git
```

### Загрузка и Установка: Официальные Установщики

Использование официальных установщиков Git для вашей платформы.

```bash
# Загрузить с https://git-scm.com/downloads
# Проверить установку
git --version
# Показать путь к исполняемому файлу git
which git
```

### Настройка При Первом Запуске: Конфигурация Пользователя

Настройка Git с вашей личностью для коммитов.

```bash
git config --global user.name "Your Full Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# Установить поведение слияния
git config --global pull.rebase false
```

## Рабочие Процессы и Лучшие Практики Git

### Рабочий Процесс Ветвей Функций (Feature Branch Workflow)

Стандартный рабочий процесс для разработки функций с изолированными ветвями.

```bash
# Начать с ветки main
git checkout main
# Получить последние изменения
git pull origin main
# Создать ветку функции
git checkout -b feature/user-auth
# ... внести изменения и коммиты ...
# Отправить ветку функции
git push -u origin feature/user-auth
# ... создать pull request ...
```

### Git Flow: Структурированная Модель Ветвления

Систематический подход с выделенными ветвями для разных целей.

```bash
# Инициализировать Git Flow
git flow init
# Начать работу над функцией
git flow feature start new-feature
# Завершить работу над функцией
git flow feature finish new-feature
# Начать ветку релиза
git flow release start 1.0.0
```

### Соглашения о Сообщениях Коммитов

Следование формату "Conventional Commits" для ясной истории проекта.

```bash
# Формат: <тип>(<область>): <тема>
git commit -m "feat(auth): add user login functionality"
git commit -m "fix(api): resolve null pointer exception"
git commit -m "docs(readme): update installation instructions"
git commit -m "refactor(utils): simplify date formatting"
```

### Атомарные Коммиты: Лучшие Практики

Создание сфокусированных, одноцелевых коммитов для лучшей истории.

```bash
# Интерактивно индексировать изменения
git add -p
# Конкретное изменение
git commit -m "Add validation to email field"
# Избегать: git commit -m "Fix stuff" # Слишком расплывчато
# Хорошо:  git commit -m "Fix email validation regex pattern"
```

## Устранение Неполадок и Восстановление

### Reflog: Инструмент Восстановления

Использование журнала ссылок Git для восстановления потерянных коммитов.

```bash
# Показать журнал ссылок
git reflog
# Показать перемещения HEAD
git reflog show HEAD
# Восстановить потерянный коммит
git checkout abc123
# Создать ветку из потерянного коммита
git branch recovery-branch abc123
```

### Поврежденный Репозиторий: Ремонт

Исправление проблем с целостностью репозитория.

```bash
# Проверить целостность репозитория
git fsck --full
# Агрессивная очистка
git gc --aggressive --prune=now
# Перестроить индекс при повреждении
rm .git/index; git reset
```

### Проблемы с Аутентификацией

Решение общих проблем с аутентификацией и разрешениями.

```bash
# Использовать токен
git remote set-url origin https://token@github.com/user/repo.git
# Добавить SSH ключ в агент
ssh-add ~/.ssh/id_rsa
# Менеджер учетных данных Windows
git config --global credential.helper manager-core
```

### Проблемы с Производительностью: Отладка

Определение и устранение проблем с производительностью репозитория.

```bash
# Показать размер репозитория
git count-objects -vH
# Посчитать общее количество коммитов
git log --oneline | wc -l
# Посчитать количество веток
git for-each-ref --format='%(refname:short)' | wc -l
```

## Соответствующие Ссылки

- <router-link to="/linux">Справочник Linux</router-link>
- <router-link to="/shell">Справочник Shell</router-link>
- <router-link to="/devops">Справочник DevOps</router-link>
- <router-link to="/docker">Справочник Docker</router-link>
- <router-link to="/kubernetes">Справочник Kubernetes</router-link>
- <router-link to="/ansible">Справочник Ansible</router-link>
- <router-link to="/python">Справочник Python</router-link>
- <router-link to="/javascript">Справочник JavaScript</router-link>

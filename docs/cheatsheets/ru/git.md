---
title: 'Шпаргалка по Git'
description: 'Изучите Git с нашей полной шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/git-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Git Шпаргалка
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/git">Изучите Git с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите систему контроля версий Git с помощью практических лабораторий и реальных сценариев. LabEx предлагает комплексные курсы по Git, охватывающие основные команды, стратегии ветвления, рабочие процессы совместной работы и продвинутые методы. Научитесь управлять репозиториями кода, разрешать конфликты и эффективно работать с командами, используя Git и GitHub.
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
# Неглубокое клонирование (только последний коммит)
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

Сохранение учетных данных для аутентификации, чтобы избежать повторного входа.

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

Отображает текущее состояние рабочей директории и области проиндексированных файлов (staging area).

```bash
# Полная информация о статусе
git status
# Короткий формат статуса
git status -s
# Формат, пригодный для машинной обработки
git status --porcelain
# Показать также проигнорированные файлы
git status --ignored
```

### Просмотр Различий: `git diff`

Показывает изменения между различными состояниями вашего репозитория.

```bash
# Изменения в рабочей директории по сравнению с областью проиндексированных файлов
git diff
# Изменения в области проиндексированных файлов по сравнению с последним коммитом
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
# Сжатый формат в одну строку
git log --oneline
# Показать последние 5 коммитов
git log -5
# Визуальный граф ветвей
git log --graph --all
```

## Индексация и Фиксация Изменений

### Индексация Файлов: `git add`

Добавляет изменения в область проиндексированных файлов для следующего коммита.

```bash
# Проиндексировать конкретный файл
git add file.txt
# Проиндексировать все изменения в текущем каталоге
git add .
# Проиндексировать все изменения (включая удаления)
git add -A
# Проиндексировать все JavaScript файлы
git add *.js
# Интерактивная индексация (режим патча)
git add -p
```

### Фиксация Изменений: `git commit`

Сохраняет проиндексированные изменения в репозитории с описательным сообщением.

```bash
# Коммит с сообщением
git commit -m "Add user authentication"
# Проиндексировать и зафиксировать измененные файлы
git commit -a -m "Update docs"
# Изменить последний коммит
git commit --amend
# Изменить без изменения сообщения
git commit --no-edit --amend
```

### Снятие Индексации Файлов: `git reset`

Удаляет файлы из области проиндексированных файлов или отменяет коммиты.

```bash
# Снять индексацию конкретного файла
git reset file.txt
# Снять индексацию всех файлов
git reset
# Отменить последний коммит, сохранить изменения проиндексированными
git reset --soft HEAD~1
# Отменить последний коммит, отбросить изменения
git reset --hard HEAD~1
```

### Отбрасывание Изменений: `git checkout` / `git restore`

Возвращает изменения в рабочей директории к состоянию последнего коммита.

```bash
# Отбросить изменения в файле (старый синтаксис)
git checkout -- file.txt
# Отбросить изменения в файле (новый синтаксис)
git restore file.txt
# Снять индексацию файла (новый синтаксис)
git restore --staged file.txt
# Отбросить все незафиксированные изменения
git checkout .
```

## Операции с Ветвями

### Список Ветвей: `git branch`

Просмотр и управление ветвями репозитория.

```bash
# Вывести список локальных ветвей
git branch
# Вывести список всех ветвей (локальных и удаленных)
git branch -a
# Вывести список только удаленных ветвей
git branch -r
# Показать последний коммит в каждой ветви
git branch -v
```

### Создание и Переключение: `git checkout` / `git switch`

Создание новых ветвей и переключение между ними.

```bash
# Создать и переключиться на новую ветвь
git checkout -b feature-branch
# Создать и переключиться (новый синтаксис)
git switch -c feature-branch
# Переключиться на существующую ветвь
git checkout main
# Переключиться на существующую ветвь (новый синтаксис)
git switch main
```

### Слияние Ветвей: `git merge`

Объединение изменений из разных ветвей.

```bash
# Слияние feature-branch в текущую ветвь
git merge feature-branch
# Принудительное слияние без fast-forward
git merge --no-ff feature-branch
# Сжать коммиты перед слиянием
git merge --squash feature-branch
```

### Удаление Ветвей: `git branch -d`

Удаление ветвей, которые больше не нужны.

```bash
# Удалить слитую ветвь
git branch -d feature-branch
# Принудительное удаление несшитой ветви
git branch -D feature-branch
# Удалить удаленную ветвь
git push origin --delete feature-branch
```

## Операции с Удаленным Репозиторием

### Получение Обновлений: `git fetch`

Загрузка изменений из удаленного репозитория без слияния.

```bash
# Получить из удаленного репозитория по умолчанию
git fetch
# Получить из конкретного удаленного репозитория
git fetch origin
# Получить из всех удаленных репозиториев
git fetch --all
# Получить конкретную ветвь
git fetch origin main
```

### Получение и Слияние: `git pull`

Загрузка и слияние изменений из удаленного репозитория.

```bash
# Получить из отслеживаемой ветви
git pull
# Получить из конкретной удаленной ветви
git pull origin main
# Получить с использованием rebase вместо merge
git pull --rebase
# Только fast-forward, без коммитов слияния
git pull --ff-only
```

### Отправка Изменений: `git push`

Загрузка локальных коммитов в удаленный репозиторий.

```bash
# Отправить в отслеживаемую ветвь
git push
# Отправить в конкретную удаленную ветвь
git push origin main
# Отправить и установить отслеживание (upstream)
git push -u origin feature
# Принудительная отправка с безопасной проверкой
git push --force-with-lease
```

### Отслеживание Удаленных Ветвей: `git branch --track`

Настройка отслеживания между локальными и удаленными ветвями.

```bash
# Установить отслеживание
git branch --set-upstream-to=origin/main main
# Отслеживать удаленную ветвь
git checkout -b local-branch origin/remote-branch
```

## Стейшинг и Временное Хранение

### Стейшинг Изменений: `git stash`

Временное сохранение незафиксированных изменений для последующего использования.

```bash
# Стейшинг текущих изменений
git stash
# Стейшинг с сообщением
git stash save "Work in progress on feature X"
# Включить неотслеживаемые файлы
git stash -u
# Стейшинг только снятых с индексации изменений
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
# Создать ветвь из стейша
git stash branch new-branch stash@{1}
# Удалить все стейши
git stash clear
```

## Анализ Истории и Лога

### Просмотр Истории Коммитов: `git log`

Изучение истории репозитория с различными опциями форматирования.

```bash
# Визуальная история ветвей
git log --oneline --graph --all
# Коммиты по конкретному автору
git log --author="John Doe"
# Недавние коммиты
git log --since="2 weeks ago"
# Поиск по сообщениям коммитов
git log --grep="bug fix"
```

### Аннотация и Авторство: `git blame`

Посмотреть, кто и когда изменил каждую строку файла.

```bash
# Показать авторство построчно
git blame file.txt
# Аннотация конкретных строк
git blame -L 10,20 file.txt
# Альтернатива blame
git annotate file.txt
```

### Поиск по Репозиторию: `git grep`

Поиск текстовых шаблонов в истории репозитория.

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
# Отменить без автоматического коммита
git revert --no-commit abc123
```

### Сброс Истории: `git reset`

Перемещает указатель ветви и, при необходимости, изменяет рабочую директорию.

```bash
# Отменить коммит, сохранить изменения проиндексированными
git reset --soft HEAD~1
# Отменить коммит и снятие индексации
git reset --mixed HEAD~1
# Отменить коммит, индексацию и рабочую директорию
git reset --hard HEAD~1
```

### Интерактивный Rebase: `git rebase -i`

Интерактивное редактирование, переупорядочивание или сжатие коммитов.

```bash
# Интерактивный rebase последних 3 коммитов
git rebase -i HEAD~3
# Rebase текущей ветви на main
git rebase -i main
# Продолжить после разрешения конфликтов
git rebase --continue
# Отменить операцию rebase
git rebase --abort
```

### Cherry-pick: `git cherry-pick`

Применение конкретных коммитов из других ветвей.

```bash
# Применить конкретный коммит к текущей ветви
git cherry-pick abc123
# Применить диапазон коммитов
git cherry-pick abc123..def456
# Cherry-pick без фиксации
git cherry-pick -n abc123
```

## Разрешение Конфликтов

### Конфликты Слияния: Процесс Разрешения

Шаги для разрешения конфликтов во время операций слияния.

```bash
# Проверить файлы с конфликтами
git status
# Отметить файл как разрешенный
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
Содержимое текущей ветви
=======
Содержимое входящей ветви
>>>>>>> feature-branch
```

После редактирования файла для разрешения конфликта:

```bash
git add conflicted-file.txt
git commit
```

### Инструменты Diff: `git difftool`

Использование внешних инструментов для лучшей визуализации конфликтов.

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

### Сложные Псевдонимы: Комбинации Команд

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

### Неглубокие Клоны: Уменьшение Размера Репозитория

Клонирование репозиториев с ограниченной историей для более быстрых операций.

```bash
# Только последний коммит
git clone --depth 1 https://github.com/user/repo.git
# Последние 10 коммитов
git clone --depth 10 repo.git
# Преобразовать неглубокий клон в полный
git fetch --unshallow
```

### Разреженная Выборка: Работа с Подкаталогами

Выборка только определенных частей больших репозиториев.

```bash
git config core.sparseCheckout true
echo "src/*" > .git/info/sparse-checkout
# Применить разреженную выборку
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

### Первоначальная Настройка: Конфигурация Пользователя

Настройка Git с вашей личностью для коммитов.

```bash
git config --global user.name "Your Full Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
# Установить поведение слияния
git config --global pull.rebase false
```

## Рабочие Процессы и Лучшие Практики Git

### Рабочий Процесс Feature Branch

Стандартный рабочий процесс для разработки функций с изолированными ветвями.

```bash
# Начать с ветви main
git checkout main
# Получить последние изменения
git pull origin main
# Создать ветвь функции
git checkout -b feature/user-auth
# ... внести изменения и коммиты ...
# Отправить ветвь функции
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
# Начать ветвь релиза
git flow release start 1.0.0
```

### Соглашения о Сообщениях Коммитов

Следовать формату конвенциональных коммитов для ясной истории проекта.

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
# Интерактивно проиндексировать изменения
git add -p
# Конкретное изменение
git commit -m "Add validation to email field"
# Избегать: git commit -m "Fix stuff" # Слишком расплывчато
# Хорошо:  git commit -m "Fix email validation regex pattern"
```

## Устранение Неполадок и Восстановление

### Reflog: Инструмент Восстановления

Использовать журнал ссылок Git для восстановления потерянных коммитов.

```bash
# Показать журнал ссылок
git reflog
# Показать перемещения HEAD
git reflog show HEAD
# Восстановить потерянный коммит
git checkout abc123
# Создать ветвь из потерянного коммита
git branch recovery-branch abc123
```

### Поврежденный Репозиторий: Ремонт

Исправление проблем с целостностью репозитория.

```bash
# Проверить целостность репозитория
git fsck --full
# Агрессивная очистка
git gc --aggressive --prune=now
# Перестроить индекс в случае повреждения
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
# Посчитать количество ветвей
git for-each-ref --format='%(refname:short)' | wc -l
```

## Соответствующие Ссылки

- <router-link to="/linux">Linux Шпаргалка</router-link>
- <router-link to="/shell">Shell Шпаргалка</router-link>
- <router-link to="/devops">DevOps Шпаргалка</router-link>
- <router-link to="/docker">Docker Шпаргалка</router-link>
- <router-link to="/kubernetes">Kubernetes Шпаргалка</router-link>
- <router-link to="/ansible">Ansible Шпаргалка</router-link>
- <router-link to="/python">Python Шпаргалка</router-link>
- <router-link to="/javascript">JavaScript Шпаргалка</router-link>

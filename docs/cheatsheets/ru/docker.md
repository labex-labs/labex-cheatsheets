---
title: 'Шпаргалка по Docker | LabEx'
description: 'Изучите контейнеризацию Docker с помощью этой исчерпывающей шпаргалки. Быстрый справочник по командам Docker, образам, контейнерам, Dockerfile, Docker Compose и оркестрации контейнеров.'
pdfUrl: '/cheatsheets/pdf/docker-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Docker Шпаргалка
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/docker">Изучите Docker с практическими лабораторными работами</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите контейнеризацию Docker с помощью практических лабораторных работ и сценариев реального мира. LabEx предлагает комплексные курсы по Docker, охватывающие управление контейнерами, сборку образов, Docker Compose, сетевое взаимодействие, тома и развертывание. Освойте оркестрацию контейнеров и современные методы развертывания приложений.
</base-disclaimer-content>
</base-disclaimer>

## Установка и Настройка

### Установка в Linux

Установка Docker в системах Ubuntu/Debian.

```bash
# Обновить менеджер пакетов
sudo apt update
# Установить предварительные требования
sudo apt install apt-transport-https ca-certificates curl
software-properties-common
# Добавить официальный GPG ключ Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg
| sudo apt-key add -
# Добавить репозиторий Docker
sudo add-apt-repository "deb [arch=amd64]
https://download.docker.com/linux/ubuntu bionic stable"
# Установить Docker
sudo apt update && sudo apt install docker-ce
# Запустить службу Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### Windows и macOS

Установите Docker Desktop для управления с помощью графического интерфейса.

```bash
# Windows: Скачать Docker Desktop с docker.com
# macOS: Использовать Homebrew или скачать с docker.com
brew install --cask docker
# Или скачать напрямую с:
# https://www.docker.com/products/docker-desktop
```

### Настройка после установки

Настройка Docker для использования без прав root и проверка установки.

```bash
# Добавить пользователя в группу docker (Linux)
sudo usermod -aG docker $USER
# Выйти и войти снова для применения изменений группы
# Проверить установку Docker
docker --version
docker run hello-world
```

### Установка Docker Compose

Установка Docker Compose для многоконтейнерных приложений.

```bash
# Linux: Установка через curl
sudo curl -L
"https://github.com/docker/compose/releases/download
/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o
/usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
# Проверить установку
docker-compose --version
# Примечание: Docker Desktop включает Compose
```

## Основные команды Docker

### Информация о системе: `docker version` / `docker system info`

Проверить детали установки и среды Docker.

```bash
# Показать информацию о версии Docker
docker version
# Показать системную информацию Docker
information
docker system info
# Показать справку по командам Docker
docker help
docker <command> --help
```

### Запуск контейнеров: `docker run`

Создать и запустить контейнер из образа.

```bash
# Запустить контейнер интерактивно
docker run -it ubuntu:latest bash
# Запустить контейнер в фоновом режиме
(detached)
docker run -d --name my-container
nginx
# Запустить с сопоставлением портов
docker run -p 8080:80 nginx
# Запустить с автоматическим удалением после завершения работы
docker run --rm hello-world
```

<BaseQuiz id="docker-run-1" correct="C">
  <template #question>
    Что делает `docker run -d`?
  </template>
  
  <BaseQuizOption value="A">Запускает контейнер в режиме отладки</BaseQuizOption>
  <BaseQuizOption value="B">Удаляет контейнер после его остановки</BaseQuizOption>
  <BaseQuizOption value="C" correct>Запускает контейнер в фоновом режиме (detached mode)</BaseQuizOption>
  <BaseQuizOption value="D">Запускает контейнер с настройками по умолчанию</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `-d` запускает контейнер в фоновом режиме, что означает, что он работает в фоновом режиме и немедленно возвращает управление терминалу. Это полезно для долго работающих служб.
  </BaseQuizAnswer>
</BaseQuiz>

### Список контейнеров: `docker ps`

Просмотр запущенных и остановленных контейнеров.

```bash
# Список запущенных контейнеров
docker ps
# Список всех контейнеров (включая
остановленные)
docker ps -a
# Список только идентификаторов контейнеров
docker ps -q
# Показать последний созданный контейнер
docker ps -l
```

## Управление контейнерами

### Жизненный цикл контейнера: `start` / `stop` / `restart`

Управление состоянием выполнения контейнера.

```bash
# Остановить запущенный контейнер
docker stop container_name
# Запустить остановленный контейнер
docker start container_name
# Перезапустить контейнер
docker restart container_name
# Приостановить/возобновить процессы контейнера
docker pause container_name
docker unpause container_name
```

### Выполнение команд: `docker exec`

Выполнение команд внутри запущенных контейнеров.

```bash
# Выполнить интерактивную оболочку bash
docker exec -it container_name bash
# Выполнить одну команду
docker exec container_name ls -la
# Выполнить от имени другого пользователя
docker exec -u root container_name whoami
# Выполнить в определенной директории
docker exec -w /app container_name pwd
```

### Удаление контейнеров: `docker rm`

Удаление контейнеров из системы.

```bash
# Удалить остановленный контейнер
docker rm container_name
# Принудительно удалить запущенный контейнер
docker rm -f container_name
# Удалить несколько контейнеров
docker rm container1 container2
# Удалить все остановленные контейнеры
docker container prune
```

### Логи контейнеров: `docker logs`

Просмотр вывода контейнера и отладка проблем.

```bash
# Просмотр логов контейнера
docker logs container_name
# Следить за логами в реальном времени
docker logs -f container_name
# Показать только недавние логи
docker logs --tail 50 container_name
# Показать логи с временными метками
docker logs -t container_name
```

## Управление образами

### Сборка образов: `docker build`

Создание образов Docker из Dockerfile.

```bash
# Собрать образ из текущей директории
docker build .
# Собрать и пометить образ
docker build -t myapp:latest .
# Собрать с аргументами сборки
docker build --build-arg VERSION=1.0 -t myapp .
# Собрать без использования кэша
docker build --no-cache -t myapp .
```

<BaseQuiz id="docker-build-1" correct="A">
  <template #question>
    Что делает `docker build -t myapp:latest .`?
  </template>
  
  <BaseQuizOption value="A" correct>Собирает образ Docker с тегом "myapp:latest" из текущей директории</BaseQuizOption>
  <BaseQuizOption value="B">Запускает контейнер с именем "myapp"</BaseQuizOption>
  <BaseQuizOption value="C">Загружает образ "myapp:latest" из Docker Hub</BaseQuizOption>
  <BaseQuizOption value="D">Удаляет образ "myapp:latest"</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `-t` помечает образ именем "myapp:latest", а `.` указывает на контекст сборки (текущая директория). Эта команда собирает новый образ из Dockerfile в текущей директории.
  </BaseQuizAnswer>
</BaseQuiz>

### Инспекция образов: `docker images` / `docker inspect`

Перечисление и изучение образов Docker.

```bash
# Список всех локальных образов
docker images
# Список образов с определенными фильтрами
docker images nginx
# Показать детали образа
docker inspect image_name
# Посмотреть историю сборки образа
docker history image_name
```

### Операции с реестром: `docker pull` / `docker push`

Загрузка и выгрузка образов в реестры.

```bash
# Загрузить образ из Docker Hub
docker pull nginx:latest
# Загрузить конкретную версию
docker pull ubuntu:20.04
# Выгрузить образ в реестр
docker push myusername/myapp:latest
# Пометить образ перед выгрузкой
docker tag myapp:latest myusername/myapp:v1.0
```

### Очистка образов: `docker rmi` / `docker image prune`

Удаление неиспользуемых образов для освобождения дискового пространства.

```bash
# Удалить конкретный образ
docker rmi image_name
# Удалить неиспользуемые образы
docker image prune
# Удалить все неиспользуемые образы (не только висячие)
docker image prune -a
# Принудительно удалить образ
docker rmi -f image_name
```

## Основы Dockerfile

### Основные инструкции

Основные команды Dockerfile для сборки образов.

```dockerfile
# Базовый образ
FROM ubuntu:20.04
# Установить информацию о сопровождающем
LABEL maintainer="user@example.com"
# Установить пакеты
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# Скопировать файлы с хоста в контейнер
COPY app.py /app/
# Установить рабочую директорию
WORKDIR /app
# Открыть порт
EXPOSE 8000
```

<BaseQuiz id="dockerfile-1" correct="B">
  <template #question>
    Каково назначение инструкции `FROM` в Dockerfile?
  </template>
  
  <BaseQuizOption value="A">Она копирует файлы с хоста в контейнер</BaseQuizOption>
  <BaseQuizOption value="B" correct>Она указывает базовый образ, на котором будет производиться сборка</BaseQuizOption>
  <BaseQuizOption value="C">Она устанавливает переменные окружения</BaseQuizOption>
  <BaseQuizOption value="D">Она определяет команду, которая будет выполняться при запуске контейнера</BaseQuizOption>
  
  <BaseQuizAnswer>
    Инструкция `FROM` должна быть первой инструкцией, не являющейся комментарием, в Dockerfile. Она указывает базовый образ, на котором будет построен ваш образ, предоставляя основу для вашего контейнера.
  </BaseQuizAnswer>
</BaseQuiz>

### Конфигурация времени выполнения

Настройка того, как запускается контейнер.

```dockerfile
# Установить переменные окружения
ENV PYTHON_ENV=production
ENV PORT=8000
# Создать пользователя для безопасности
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# Определить команду запуска
CMD ["python3", "app.py"]
# Или использовать ENTRYPOINT для фиксированных команд
ENTRYPOINT ["python3"]
CMD ["app.py"]
# Установить проверку работоспособности
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/ || exit 1
```

## Docker Compose

### Основные команды Compose: `docker-compose up` / `docker-compose down`

Запуск и остановка многоконтейнерных приложений.

```bash
# Запустить службы в режиме вывода в консоль
docker-compose up
# Запустить службы в фоновом режиме
docker-compose up -d
# Собрать и запустить службы
docker-compose up --build
# Остановить и удалить службы
docker-compose down
# Остановить и удалить с томами
docker-compose down -v
```

<BaseQuiz id="docker-compose-1" correct="D">
  <template #question>
    Что делает `docker-compose up -d`?
  </template>
  
  <BaseQuizOption value="A">Останавливает все запущенные контейнеры</BaseQuizOption>
  <BaseQuizOption value="B">Собирает образы без запуска контейнеров</BaseQuizOption>
  <BaseQuizOption value="C">Показывает логи всех служб</BaseQuizOption>
  <BaseQuizOption value="D" correct>Запускает все службы, определенные в docker-compose.yml, в фоновом режиме</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `-d` запускает контейнеры в фоновом режиме. `docker-compose up` считывает файл docker-compose.yml и запускает все определенные службы, что упрощает управление многоконтейнерными приложениями.
  </BaseQuizAnswer>
</BaseQuiz>

### Управление службами

Управление отдельными службами в приложениях Compose.

```bash
# Список запущенных служб
docker-compose ps
# Просмотр логов службы
docker-compose logs service_name
# Следить за логами всех служб
docker-compose logs -f
# Перезапустить службу
docker-compose restart service_name
```

### Пример docker-compose.yml

Пример конфигурации многосервисного приложения.

```yaml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      -
DATABASE_URL=postgresql://user:pass@db:5432/myapp
    depends_on:
      - db
    volumes:
      - .:/app

  db:
    image: postgres:13
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - db_data:/var/lib/postgresql/data
volumes:
  db_data:
```

## Сетевое взаимодействие и тома

### Сетевое взаимодействие контейнеров

Подключение контейнеров и открытие служб.

```bash
# Список сетей
docker network ls
# Создать пользовательскую сеть
docker network create mynetwork
# Запустить контейнер в определенной сети
docker run --network mynetwork nginx
# Подключить запущенный контейнер к сети
docker network connect mynetwork container_name
# Проверить детали сети
docker network inspect mynetwork
```

### Сопоставление портов

Открытие портов контейнера для хост-системы.

```bash
# Сопоставление одного порта
docker run -p 8080:80 nginx
```

<BaseQuiz id="docker-port-1" correct="A">
  <template #question>
    В команде `docker run -p 8080:80 nginx`, что означают номера портов?
  </template>
  
  <BaseQuizOption value="A" correct>8080 — это порт хоста, 80 — это порт контейнера</BaseQuizOption>
  <BaseQuizOption value="B">80 — это порт хоста, 8080 — это порт контейнера</BaseQuizOption>
  <BaseQuizOption value="C">Оба порта — порты контейнера</BaseQuizOption>
  <BaseQuizOption value="D">Оба порта — порты хоста</BaseQuizOption>
  
  <BaseQuizAnswer>
    Формат: `-p host_port:container_port`. Порт 8080 на вашей хост-машине сопоставлен порту 80 внутри контейнера, что позволяет вам получить доступ к веб-серверу nginx, работающему в контейнере, через localhost:8080.
  </BaseQuizAnswer>
</BaseQuiz>

```bash
# Сопоставление нескольких портов
docker run -p 8080:80 -p 8443:443 nginx
# Сопоставление с определенным интерфейсом хоста
docker run -p 127.0.0.1:8080:80 nginx
# Открыть все порты, определенные в образе
docker run -P nginx
```

### Тома данных: `docker volume`

Сохранение и совместное использование данных между контейнерами.

```bash
# Создать именованный том
docker volume create myvolume
# Список всех томов
docker volume ls
# Проверить детали тома
docker volume inspect myvolume
# Удалить том
docker volume rm myvolume
# Удалить неиспользуемые тома
docker volume prune
```

### Монтирование томов

Монтирование томов и директорий хоста в контейнерах.

```bash
# Смонтировать именованный том
docker run -v myvolume:/data nginx
# Смонтировать директорию хоста (bind mount)
docker run -v /host/path:/container/path nginx
# Смонтировать текущую директорию
docker run -v $(pwd):/app nginx
# Монтирование только для чтения
docker run -v /host/path:/container/path:ro nginx
```

## Инспекция и отладка контейнеров

### Детали контейнера: `docker inspect`

Получение подробной информации о контейнерах и образах.

```bash
# Проверить конфигурацию контейнера
docker inspect container_name
# Получить конкретную информацию с использованием формата
docker inspect --format='{{.State.Status}}'
container_name
# Получить IP-адрес
docker inspect --format='{{.NetworkSettings.IPAddress}}'
container_name
# Получить смонтированные тома
docker inspect --format='{{.Mounts}}' container_name
```

### Мониторинг ресурсов

Мониторинг использования ресурсов и производительности контейнеров.

```bash
# Показать запущенные процессы в контейнере
docker top container_name
# Отобразить статистику использования ресурсов в реальном времени
docker stats
# Показать статистику для конкретного контейнера
docker stats container_name
# Мониторинг событий в реальном времени
docker events
```

### Операции с файлами: `docker cp`

Копирование файлов между контейнерами и хост-системой.

```bash
# Скопировать файл из контейнера на хост
docker cp container_name:/path/to/file ./
# Скопировать файл с хоста в контейнер
docker cp ./file container_name:/path/to/destination
# Скопировать директорию
docker cp ./directory
container_name:/path/to/destination/
# Копировать с архивированием для сохранения разрешений
docker cp -a ./directory container_name:/path/
```

### Устранение неполадок

Отладка проблем контейнера и сетевых проблем.

```bash
# Проверить код выхода контейнера
docker inspect --format='{{.State.ExitCode}}'
container_name
# Просмотреть процессы контейнера
docker exec container_name ps aux
# Проверить сетевое подключение
docker exec container_name ping google.com
# Проверить использование диска
docker exec container_name df -h
```

## Реестр и аутентификация

### Операции с Docker Hub: `docker login` / `docker search`

Аутентификация и взаимодействие с Docker Hub.

```bash
# Войти в Docker Hub
docker login
# Войти в конкретный реестр
docker login registry.example.com
# Поиск образов в Docker Hub
docker search nginx
# Поиск с фильтром
docker search --filter stars=100 nginx
```

### Тегирование и публикация образов

Подготовка и публикация образов в реестрах.

```bash
# Пометить образ для реестра
docker tag myapp:latest username/myapp:v1.0
docker tag myapp:latest
registry.example.com/myapp:latest
# Выгрузить в Docker Hub
docker push username/myapp:v1.0
# Выгрузить в частный реестр
docker push registry.example.com/myapp:latest
```

### Частный реестр

Работа с частными реестрами Docker.

```bash
# Загрузить из частного реестра
docker pull registry.company.com/myapp:latest
# Запустить локальный реестр
docker run -d -p 5000:5000 --name registry registry:2
# Выгрузить в локальный реестр
docker tag myapp localhost:5000/myapp
docker push localhost:5000/myapp
```

### Безопасность образов

Проверка целостности и безопасности образов.

```bash
# Включить доверие к содержимому Docker
export DOCKER_CONTENT_TRUST=1
# Подписать и выгрузить образ
docker push username/myapp:signed
# Проверить подписи образов
docker trust inspect username/myapp:signed
# Сканировать образы на уязвимости
docker scan myapp:latest
```

## Очистка и обслуживание системы

### Очистка системы: `docker system prune`

Удаление неиспользуемых ресурсов Docker для освобождения дискового пространства.

```bash
# Удалить неиспользуемые контейнеры, сети, образы
docker system prune
# Включить неиспользуемые тома в очистку
docker system prune -a --volumes
# Удалить все (использовать с осторожностью)
docker system prune -a -f
# Показать использование дискового пространства
docker system df
```

### Целевая очистка

Удаление конкретных типов неиспользуемых ресурсов.

```bash
# Удалить остановленные контейнеры
docker container prune
# Удалить неиспользуемые образы
docker image prune -a
# Удалить неиспользуемые тома
docker volume prune
# Удалить неиспользуемые сети
docker network prune
```

### Массовые операции

Выполнение операций над несколькими контейнерами/образами.

```bash
# Остановить все запущенные контейнеры
docker stop $(docker ps -q)
# Удалить все контейнеры
docker rm $(docker ps -aq)
# Удалить все образы
docker rmi $(docker images -q)
# Удалить только висячие образы
docker rmi $(docker images -f "dangling=true" -q)
```

### Ограничение ресурсов

Контроль потребления ресурсов контейнерами.

```bash
# Ограничить использование памяти
docker run --memory=512m nginx
# Ограничить использование ЦП
docker run --cpus="1.5" nginx
# Ограничить и ЦП, и память
docker run --memory=1g --cpus="2.0" nginx
# Установить политику перезапуска
docker run --restart=always nginx
```

## Конфигурация и настройки Docker

### Конфигурация демона

Настройка демона Docker для производственного использования.

```bash
# Отредактировать конфигурацию демона
sudo nano
/etc/docker/daemon.json
# Пример конфигурации:
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
# Перезапустить службу Docker
sudo systemctl restart docker
```

### Переменные окружения

Настройка поведения клиента Docker с помощью переменных окружения.

```bash
# Установить хост Docker
export
DOCKER_HOST=tcp://remote-
docker:2376
# Включить проверку TLS
export DOCKER_TLS_VERIFY=1
export
DOCKER_CERT_PATH=/path/to/c
erts
# Установить реестр по умолчанию
export
DOCKER_REGISTRY=registry.co
mpany.com
# Вывод отладки
export DOCKER_BUILDKIT=1
```

### Настройка производительности

Оптимизация Docker для лучшей производительности.

```bash
# Включить экспериментальные функции
echo '{"experimental": true}' |
sudo tee
/etc/docker/daemon.json
# Опции драйвера хранения
{
  "storage-driver": "overlay2",
  "storage-opts": [

"overlay2.override_kernel_check
=true"
  ]
}
# Настройка логирования
{
  "log-driver": "syslog",
  "log-opts": {"syslog-address":
"udp://logs.company.com:514"}
}
```

## Лучшие практики

### Рекомендации по безопасности

Поддержание безопасности контейнеров и их готовности к производству.

```dockerfile
# Запуск от имени пользователя без прав root в Dockerfile
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# Использовать конкретные теги образов, а не 'latest'
FROM node:16.20.0-alpine
# Использовать файловые системы только для чтения, когда это возможно
docker run --read-only nginx
```

### Оптимизация производительности

Оптимизация контейнеров для скорости и эффективности использования ресурсов.

```dockerfile
# Использовать многоэтапную сборку для уменьшения размера образа
FROM node:16 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
FROM node:16-alpine
WORKDIR /app
COPY --from=builder /app/node_modules
./node_modules
COPY . .
CMD ["node", "server.js"]
```

## Связанные ссылки

- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>
- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/ansible">Шпаргалка по Ansible</router-link>
- <router-link to="/git">Шпаргалка по Git</router-link>
- <router-link to="/rhel">Шпаргалка по Red Hat Enterprise Linux</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>

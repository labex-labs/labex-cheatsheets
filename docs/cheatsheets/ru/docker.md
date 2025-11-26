---
title: 'Шпаргалка по Docker'
description: 'Изучите Docker с нашей исчерпывающей шпаргалкой, охватывающей основные команды, концепции и лучшие практики.'
pdfUrl: '/cheatsheets/pdf/docker-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Docker
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/docker">Изучите Docker с практическими лабораторными работами</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите контейнеризацию Docker с помощью практических лабораторных работ и сценариев реального мира. LabEx предлагает комплексные курсы по Docker, охватывающие основные аспекты управления контейнерами, сборки образов, Docker Compose, сетевых настроек, томов и развертывания. Освойте методы оркестрации контейнеров и современные методы развертывания приложений.
</base-disclaimer-content>
</base-disclaimer>

## Установка и Настройка

### Установка в Linux

Установка Docker в системах Ubuntu/Debian.

```bash
# Обновление менеджера пакетов
sudo apt update
# Установка предварительных требований
sudo apt install apt-transport-https ca-certificates curl
software-properties-common
# Добавление официального GPG-ключа Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg
| sudo apt-key add -
# Добавление репозитория Docker
sudo add-apt-repository "deb [arch=amd64]
https://download.docker.com/linux/ubuntu bionic stable"
# Установка Docker
sudo apt update && sudo apt install docker-ce
# Запуск службы Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### Windows и macOS

Установка Docker Desktop для управления через графический интерфейс.

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
# Добавление пользователя в группу docker (Linux)
sudo usermod -aG docker $USER
# Выйти и войти снова для применения изменений группы
# Проверка установки Docker
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
# Проверка установки
docker-compose --version
# Примечание: Docker Desktop включает Compose
```

## Основные Команды Docker

### Информация о системе: `docker version` / `docker system info`

Проверка деталей установки и среды Docker.

```bash
# Отображение информации о версии Docker
docker version
# Отображение системной информации Docker
system-wide
docker system info
# Отображение справки по командам Docker
docker help
docker <command> --help
```

### Запуск Контейнеров: `docker run`

Создание и запуск контейнера из образа.

```bash
# Запуск контейнера в интерактивном режиме
docker run -it ubuntu:latest bash
# Запуск контейнера в фоновом режиме
(detached)
docker run -d --name my-container
nginx
# Запуск с сопоставлением портов
docker run -p 8080:80 nginx
# Запуск с автоматическим удалением после выхода
docker run --rm hello-world
```

### Список Контейнеров: `docker ps`

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

## Управление Контейнерами

### Жизненный цикл контейнера: `start` / `stop` / `restart`

Управление состоянием выполнения контейнера.

```bash
# Остановка запущенного контейнера
docker stop container_name
# Запуск остановленного контейнера
docker start container_name
# Перезапуск контейнера
docker restart container_name
# Приостановка/возобновление процессов контейнера
docker pause container_name
docker unpause container_name
```

### Выполнение Команд: `docker exec`

Выполнение команд внутри запущенных контейнеров.

```bash
# Выполнение интерактивной оболочки bash
docker exec -it container_name bash
# Выполнение одной команды
docker exec container_name ls -la
# Выполнение от имени другого пользователя
docker exec -u root container_name whoami
# Выполнение в определенной директории
docker exec -w /app container_name pwd
```

### Удаление Контейнеров: `docker rm`

Удаление контейнеров из системы.

```bash
# Удаление остановленного контейнера
docker rm container_name
# Принудительное удаление запущенного контейнера
docker rm -f container_name
# Удаление нескольких контейнеров
docker rm container1 container2
# Удаление всех остановленных контейнеров
docker container prune
```

### Логи Контейнеров: `docker logs`

Просмотр вывода контейнера и отладка проблем.

```bash
# Просмотр логов контейнера
docker logs container_name
# Слежение за логами в реальном времени
docker logs -f container_name
# Показать только последние логи
docker logs --tail 50 container_name
# Показать логи с временными метками
docker logs -t container_name
```

## Управление Образами

### Сборка Образов: `docker build`

Создание образов Docker из Dockerfile.

```bash
# Сборка образа из текущей директории
docker build .
# Сборка и тегирование образа
docker build -t myapp:latest .
# Сборка с аргументами сборки
docker build --build-arg VERSION=1.0 -t myapp .
# Сборка без использования кэша
docker build --no-cache -t myapp .
```

### Инспекция Образов: `docker images` / `docker inspect`

Перечисление и изучение образов Docker.

```bash
# Список всех локальных образов
docker images
# Список образов с определенными фильтрами
docker images nginx
# Показать детали образа
docker inspect image_name
# Просмотр истории сборки образа
docker history image_name
```

### Операции с Реестром: `docker pull` / `docker push`

Загрузка и выгрузка образов в реестры.

```bash
# Загрузка образа из Docker Hub
docker pull nginx:latest
# Загрузка определенной версии
docker pull ubuntu:20.04
# Выгрузка образа в реестр
docker push myusername/myapp:latest
# Тегирование образа перед выгрузкой
docker tag myapp:latest myusername/myapp:v1.0
```

### Очистка Образов: `docker rmi` / `docker image prune`

Удаление неиспользуемых образов для освобождения дискового пространства.

```bash
# Удаление определенного образа
docker rmi image_name
# Удаление неиспользуемых образов
docker image prune
# Удаление всех неиспользуемых образов (не только "висячих")
docker image prune -a
# Принудительное удаление образа
docker rmi -f image_name
```

## Основы Dockerfile

### Основные Инструкции

Основные команды Dockerfile для сборки образов.

```dockerfile
# Базовый образ
FROM ubuntu:20.04
# Установка информации о мейнтейнере
LABEL maintainer="user@example.com"
# Установка пакетов
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
# Копирование файлов с хоста в контейнер
COPY app.py /app/
# Установка рабочей директории
WORKDIR /app
# Открытие порта
EXPOSE 8000
```

### Конфигурация Во Время Выполнения

Настройка того, как запускается контейнер.

```dockerfile
# Установка переменных окружения
ENV PYTHON_ENV=production
ENV PORT=8000
# Создание пользователя для безопасности
RUN useradd -m appuser
USER appuser
# Определение команды запуска
CMD ["python3", "app.py"]
# Или использование ENTRYPOINT для фиксированных команд
ENTRYPOINT ["python3"]
CMD ["app.py"]
# Установка проверки работоспособности
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/ || exit 1
```

## Docker Compose

### Основные Команды Compose: `docker-compose up` / `docker-compose down`

Запуск и остановка многоконтейнерных приложений.

```bash
# Запуск сервисов в режиме foreground
docker-compose up
# Запуск сервисов в фоновом режиме
docker-compose up -d
# Сборка и запуск сервисов
docker-compose up --build
# Остановка и удаление сервисов
docker-compose down
# Остановка и удаление с томами
docker-compose down -v
```

### Управление Сервисами

Управление отдельными сервисами в приложениях Compose.

```bash
# Список запущенных сервисов
docker-compose ps
# Просмотр логов сервиса
docker-compose logs service_name
# Слежение за логами всех сервисов
docker-compose logs -f
# Перезапуск определенного сервиса
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

## Сетевые Настройки и Тома (Volumes)

### Сеть Контейнеров

Подключение контейнеров и открытие сервисов.

```bash
# Список сетей
docker network ls
# Создание пользовательской сети
docker network create mynetwork
# Запуск контейнера в определенной сети
docker run --network mynetwork nginx
# Подключение запущенного контейнера к сети
docker network connect mynetwork container_name
# Инспекция деталей сети
docker network inspect mynetwork
```

### Сопоставление Портов

Открытие портов контейнера для хост-системы.

```bash
# Сопоставление одного порта
docker run -p 8080:80 nginx
# Сопоставление нескольких портов
docker run -p 8080:80 -p 8443:443 nginx
# Сопоставление с определенным интерфейсом хоста
docker run -p 127.0.0.1:8080:80 nginx
# Открытие всех портов, определенных в образе
docker run -P nginx
```

### Тома Данных: `docker volume`

Сохранение и совместное использование данных между контейнерами.

```bash
# Создание именованного тома
docker volume create myvolume
# Список всех томов
docker volume ls
# Инспекция деталей тома
docker volume inspect myvolume
# Удаление тома
docker volume rm myvolume
# Удаление неиспользуемых томов
docker volume prune
```

### Монтирование Томов

Монтирование томов и директорий хоста в контейнерах.

```bash
# Монтирование именованного тома
docker run -v myvolume:/data nginx
# Монтирование директории хоста (bind mount)
docker run -v /host/path:/container/path nginx
# Монтирование текущей директории
docker run -v $(pwd):/app nginx
# Монтирование только для чтения
docker run -v /host/path:/container/path:ro nginx
```

## Инспекция и Отладка Контейнеров

### Детали Контейнера: `docker inspect`

Получение подробной информации о контейнерах и образах.

```bash
# Инспекция конфигурации контейнера
docker inspect container_name
# Получение конкретной информации с использованием format
docker inspect --format='{{.State.Status}}'
container_name
# Получение IP-адреса
docker inspect --format='{{.NetworkSettings.IPAddress}}'
container_name
# Получение смонтированных томов
docker inspect --format='{{.Mounts}}' container_name
```

### Мониторинг Ресурсов

Мониторинг использования ресурсов контейнерами и производительности.

```bash
# Показать запущенные процессы в контейнере
docker top container_name
# Отображение статистики использования ресурсов в реальном времени
docker stats
# Показать статистику для конкретного контейнера
docker stats container_name
# Мониторинг событий в реальном времени
docker events
```

### Операции с Файлами: `docker cp`

Копирование файлов между контейнерами и хост-системой.

```bash
# Копирование файла из контейнера на хост
docker cp container_name:/path/to/file ./
# Копирование файла с хоста в контейнер
docker cp ./file container_name:/path/to/destination
# Копирование директории
docker cp ./directory
container_name:/path/to/destination/
# Копирование с архивированием для сохранения разрешений
docker cp -a ./directory container_name:/path/
```

### Устранение Неполадок

Отладка проблем с контейнерами и сетевым подключением.

```bash
# Проверка кода выхода контейнера
docker inspect --format='{{.State.ExitCode}}'
container_name
# Просмотр процессов контейнера
docker exec container_name ps aux
# Проверка сетевого подключения
docker exec container_name ping google.com
# Проверка использования диска
docker exec container_name df -h
```

## Реестр и Аутентификация

### Операции с Docker Hub: `docker login` / `docker search`

Аутентификация и взаимодействие с Docker Hub.

```bash
# Вход в Docker Hub
docker login
# Вход в определенный реестр
docker login registry.example.com
# Поиск образов в Docker Hub
docker search nginx
# Поиск с фильтром
docker search --filter stars=100 nginx
```

### Тегирование и Публикация Образов

Подготовка и публикация образов в реестрах.

```bash
# Тегирование образа для реестра
docker tag myapp:latest username/myapp:v1.0
docker tag myapp:latest
registry.example.com/myapp:latest
# Публикация в Docker Hub
docker push username/myapp:v1.0
# Публикация в частный реестр
docker push registry.example.com/myapp:latest
```

### Частный Реестр

Работа с частными реестрами Docker.

```bash
# Загрузка из частного реестра
docker pull registry.company.com/myapp:latest
# Запуск частного реестра локально
docker run -d -p 5000:5000 --name registry registry:2
# Публикация в локальный реестр
docker tag myapp localhost:5000/myapp
docker push localhost:5000/myapp
```

### Безопасность Образов

Проверка целостности и безопасности образов.

```bash
# Включение доверия содержимого Docker
export DOCKER_CONTENT_TRUST=1
# Подписание и выгрузка образа
docker push username/myapp:signed
# Проверка подписей образов
docker trust inspect username/myapp:signed
# Сканирование образов на уязвимости
docker scan myapp:latest
```

## Очистка и Обслуживание Системы

### Очистка Системы: `docker system prune`

Удаление неиспользуемых ресурсов Docker для освобождения дискового пространства.

```bash
# Удаление неиспользуемых контейнеров, сетей, образов
docker system prune
# Включение неиспользуемых томов в очистку
docker system prune -a --volumes
# Удаление всего (использовать с осторожностью)
docker system prune -a -f
# Отображение использования дискового пространства
docker system df
```

### Целевая Очистка

Удаление определенных типов неиспользуемых ресурсов.

```bash
# Удаление остановленных контейнеров
docker container prune
# Удаление неиспользуемых образов
docker image prune -a
# Удаление неиспользуемых томов
docker volume prune
# Удаление неиспользуемых сетей
docker network prune
```

### Массовые Операции

Выполнение операций над несколькими контейнерами/образами.

```bash
# Остановка всех запущенных контейнеров
docker stop $(docker ps -q)
# Удаление всех контейнеров
docker rm $(docker ps -aq)
# Удаление всех образов
docker rmi $(docker images -q)
# Удаление только "висячих" образов
docker rmi $(docker images -f "dangling=true" -q)
```

### Ограничение Ресурсов

Контроль потребления ресурсов контейнерами.

```bash
# Ограничение использования памяти
docker run --memory=512m nginx
# Ограничение использования CPU
docker run --cpus="1.5" nginx
# Ограничение CPU и памяти
docker run --memory=1g --cpus="2.0" nginx
# Установка политики перезапуска
docker run --restart=always nginx
```

## Конфигурация и Настройки Docker

### Конфигурация Демона

Настройка демона Docker для производственного использования.

```bash
# Редактирование конфигурации демона
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
# Перезапуск службы Docker
sudo systemctl restart docker
```

### Переменные Окружения

Настройка поведения клиента Docker с помощью переменных окружения.

```bash
# Установка хоста Docker
export
DOCKER_HOST=tcp://remote-
docker:2376
# Включение проверки TLS
export DOCKER_TLS_VERIFY=1
export
DOCKER_CERT_PATH=/path/to/c
erts
# Установка реестра по умолчанию
export
DOCKER_REGISTRY=registry.co
mpany.com
# Отладка вывода
export DOCKER_BUILDKIT=1
```

### Настройка Производительности

Оптимизация Docker для лучшей производительности.

```bash
# Включение экспериментальных функций
echo '{"experimental": true}' |
sudo tee
/etc/docker/daemon.json
# Настройка опций драйвера хранения
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

## Лучшие Практики

### Рекомендации по Безопасности

Обеспечение безопасности ваших контейнеров для продакшена.

```dockerfile
# Запуск от имени пользователя без прав root в Dockerfile
RUN groupadd -r appuser && useradd -r -g appuser
appuser
USER appuser
# Использование конкретных тегов образов, а не 'latest'
FROM node:16.20.0-alpine
# Использование файловых систем только для чтения, когда это возможно
docker run --read-only nginx
```

### Оптимизация Производительности

Оптимизация контейнеров для скорости и эффективности использования ресурсов.

```dockerfile
# Использование многоэтапной сборки для уменьшения размера образа
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

## Соответствующие Ссылки

- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>
- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>
- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/ansible">Шпаргалка по Ansible</router-link>
- <router-link to="/git">Шпаргалка по Git</router-link>
- <router-link to="/rhel">Шпаргалка по Red Hat Enterprise Linux</router-link>
- <router-link to="/python">Шпаргалка по Python</router-link>

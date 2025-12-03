---
title: 'Шпаргалка по Jenkins | LabEx'
description: 'Изучите CI/CD Jenkins с помощью этой исчерпывающей шпаргалки. Краткий справочник по конвейерам Jenkins, заданиям, плагинам, автоматизации, непрерывной интеграции и рабочим процессам DevOps.'
pdfUrl: '/cheatsheets/pdf/jenkins-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Шпаргалка по Jenkins
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/jenkins">Изучите Jenkins с практическими лабораторными работами</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите автоматизацию CI/CD с помощью Jenkins через практические лабораторные работы и сценарии из реального мира. LabEx предлагает комплексные курсы по Jenkins, охватывающие основные операции, создание конвейеров, управление плагинами, автоматизацию сборки и продвинутые методы. Освойте Jenkins для создания эффективных конвейеров непрерывной интеграции и развертывания для современной разработки программного обеспечения.
</base-disclaimer-content>
</base-disclaimer>

## Установка и Настройка

### Установка на Linux

Установка Jenkins в системах Ubuntu/Debian.

```bash
# Обновить менеджер пакетов и установить Java
sudo apt update
sudo apt install fontconfig openjdk-21-jre
java -version
# Добавить GPG ключ Jenkins
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
# Добавить репозиторий Jenkins
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc]" \
https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
/etc/apt/sources.list.d/jenkins.list > /dev/null
# Установить Jenkins
sudo apt update && sudo apt install jenkins
# Запустить службу Jenkins
sudo systemctl start jenkins
sudo systemctl enable jenkins
```

### Windows и macOS

Установка Jenkins с помощью установщиков или менеджеров пакетов.

```bash
# Windows: Загрузить установщик Jenkins с jenkins.io
# Или использовать Chocolatey
choco install jenkins
# macOS: Использовать Homebrew
brew install jenkins-lts
# Или скачать напрямую с:
# https://www.jenkins.io/download/
# Запустить службу Jenkins
brew services start jenkins-lts
```

### Настройка после установки

Первоначальная конфигурация и разблокировка Jenkins.

```bash
# Получить начальный пароль администратора
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# Или для установок Docker
docker exec jenkins_container cat /var/jenkins_home/secrets/initialAdminPassword
# Доступ к веб-интерфейсу Jenkins
# Открыть http://localhost:8080
# Ввести начальный пароль администратора
# Установить рекомендуемые плагины или выбрать пользовательские плагины
```

### Первоначальная настройка

Завершение мастера настройки и создание учетной записи администратора.

```bash
# После разблокировки Jenkins:
# 1. Установить рекомендуемые плагины (рекомендуется)
# 2. Создать первого пользователя-администратора
# 3. Настроить URL Jenkins
# 4. Начать использование Jenkins
# Проверить, что Jenkins запущен
sudo systemctl status jenkins
# Проверить логи Jenkins при необходимости
sudo journalctl -u jenkins.service
```

## Основные Операции Jenkins

### Доступ к Jenkins: Веб-интерфейс и Настройка CLI

Доступ к Jenkins через браузер и настройка инструментов CLI.

```bash
# Доступ к веб-интерфейсу Jenkins
http://localhost:8080
# Скачать Jenkins CLI
wget http://localhost:8080/jnlpJars/jenkins-cli.jar
# Проверить соединение CLI
java -jar jenkins-cli.jar -s http://localhost:8080 help
# Показать доступные команды
java -jar jenkins-cli.jar -s http://localhost:8080 help
```

### Создание Задания: `create-job` / Веб-интерфейс

Создание новых сборочных заданий с помощью CLI или веб-интерфейса.

```bash
# Создать задание из XML-конфигурации
java -jar jenkins-cli.jar -auth user:token create-job my-job < job-config.xml
# Создать простое задание Freestyle через веб-интерфейс:
# 1. Нажать "New Item" (Новый элемент)
# 2. Ввести имя задания
# 3. Выбрать "Freestyle project"
# 4. Настроить шаги сборки
# 5. Сохранить конфигурацию
```

### Список Заданий: `list-jobs`

Просмотр всех настроенных заданий в Jenkins.

```bash
# Показать все задания
java -jar jenkins-cli.jar -auth user:token list-jobs
# Показать задания, соответствующие шаблону
java -jar jenkins-cli.jar -auth user:token list-jobs "*test*"
# Получить конфигурацию задания
java -jar jenkins-cli.jar -auth user:token get-job my-job > job-config.xml
```

## Управление Заданиями

### Сборка Заданий: `build`

Запуск и управление сборками заданий.

```bash
# Собрать задание
java -jar jenkins-cli.jar -auth user:token build my-job
# Собрать с параметрами
java -jar jenkins-cli.jar -auth user:token build my-job -p PARAM=value
# Собрать и дождаться завершения
java -jar jenkins-cli.jar -auth user:token build my-job -s -v
# Собрать и следить за выводом консоли
java -jar jenkins-cli.jar -auth user:token build my-job -f
```

<BaseQuiz id="jenkins-build-1" correct="B">
  <template #question>
    Что делает флаг `-s` в команде `jenkins-cli.jar build my-job -s`?
  </template>
  
  <BaseQuizOption value="A">Пропускает сборку</BaseQuizOption>
  <BaseQuizOption value="B" correct>Ожидает завершения сборки (синхронно)</BaseQuizOption>
  <BaseQuizOption value="C">Показывает статус сборки</BaseQuizOption>
  <BaseQuizOption value="D">Останавливает сборку</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `-s` делает команду сборки синхронной, то есть она ждет завершения сборки перед возвратом. Без него команда возвращается немедленно после запуска сборки.
  </BaseQuizAnswer>
</BaseQuiz>

### Управление Заданиями: `enable-job` / `disable-job`

Включение или отключение заданий.

```bash
# Включить задание
java -jar jenkins-cli.jar -auth user:token enable-job my-job
# Отключить задание
java -jar jenkins-cli.jar -auth user:token disable-job my-job
# Проверить статус задания в веб-интерфейсе
# Перейти на панель управления заданием
# Искать кнопку "Disable/Enable" (Отключить/Включить)
```

<BaseQuiz id="jenkins-job-control-1" correct="B">
  <template #question>
    Что происходит, когда вы отключаете задание Jenkins?
  </template>
  
  <BaseQuizOption value="A">Задание удаляется навсегда</BaseQuizOption>
  <BaseQuizOption value="B" correct>Конфигурация задания сохраняется, но оно не будет запускаться автоматически</BaseQuizOption>
  <BaseQuizOption value="C">Задание перемещается в другую папку</BaseQuizOption>
  <BaseQuizOption value="D">Удаляется вся история сборок</BaseQuizOption>
  
  <BaseQuizAnswer>
    Отключение задания предотвращает его автоматический запуск (запланированные сборки, триггеры и т. д.), но сохраняет конфигурацию задания и историю сборок. Вы можете включить его позже.
  </BaseQuizAnswer>
</BaseQuiz>

### Удаление Задания: `delete-job`

Удаление заданий из Jenkins.

```bash
# Удалить задание
java -jar jenkins-cli.jar -auth user:token delete-job my-job
# Массовое удаление заданий (с осторожностью)
for job in job1 job2 job3; do
  java -jar jenkins-cli.jar -auth user:token delete-job $job
done
```

### Вывод Консоли: `console`

Просмотр логов сборки и вывода консоли.

```bash
# Посмотреть вывод консоли последней сборки
java -jar jenkins-cli.jar -auth user:token console my-job
# Посмотреть вывод консоли для конкретного номера сборки
java -jar jenkins-cli.jar -auth user:token console my-job 15
# Следить за выводом консоли в реальном времени
java -jar jenkins-cli.jar -auth user:token console my-job -f
```

<BaseQuiz id="jenkins-console-1" correct="C">
  <template #question>
    Что делает флаг `-f` в команде `jenkins-cli.jar console my-job -f`?
  </template>
  
  <BaseQuizOption value="A">Принудительно останавливает сборку</BaseQuizOption>
  <BaseQuizOption value="B">Показывает только неудачные сборки</BaseQuizOption>
  <BaseQuizOption value="C" correct>Следит за выводом консоли в реальном времени</BaseQuizOption>
  <BaseQuizOption value="D">Форматирует вывод как JSON</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `-f` отслеживает вывод консоли в реальном времени, аналогично `tail -f` в Linux. Это полезно для мониторинга сборок по мере их выполнения.
  </BaseQuizAnswer>
</BaseQuiz>

## Управление Конвейерами (Pipeline)

### Создание Конвейера

Создание и настройка конвейеров Jenkins.

```groovy
// Базовый Jenkinsfile (Декларативный конвейер)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Building application...'
                sh 'make build'
            }
        }

        stage('Test') {
            steps {
                echo 'Running tests...'
                sh 'make test'
            }
        }

        stage('Deploy') {
            steps {
                echo 'Deploying application...'
                sh 'make deploy'
            }
        }
    }
}
```

### Синтаксис Конвейера

Общий синтаксис и директивы конвейера.

```groovy
// Синтаксис Скриптового Конвейера (Scripted Pipeline)
node {
    stage('Checkout') {
        checkout scm
    }

    stage('Build') {
        sh 'make build'
    }

    stage('Test') {
        sh 'make test'
        junit 'target/test-results/*.xml'
    }
}
// Параллельное выполнение
stages {
    stage('Parallel Tests') {
        parallel {
            stage('Unit Tests') {
                steps {
                    sh 'make unit-test'
                }
            }
            stage('Integration Tests') {
                steps {
                    sh 'make integration-test'
                }
            }
        }
    }
}
```

### Настройка Конвейера

Расширенная настройка конвейеров и опции.

```groovy
// Конвейер с действиями после сборки (post-build actions)
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }

    post {
        always {
            echo 'This always runs'
        }
        success {
            echo 'Build succeeded'
        }
        failure {
            echo 'Build failed'
            emailext subject: 'Build Failed',
                     body: 'Build failed',
                     to: 'team@company.com'
        }
    }
}
```

### Триггеры Конвейера

Настройка автоматических триггеров конвейера.

```groovy
// Конвейер с триггерами
pipeline {
    agent any

    triggers {
        // Опрос SCM каждые 5 минут
        pollSCM('H/5 * * * *')

        // Планирование, похожее на Cron
        cron('H 2 * * *')  // Ежедневно в 2 часа ночи

        // Триггер от вышестоящего задания
        upstream(upstreamProjects: 'upstream-job',
                threshold: hudson.model.Result.SUCCESS)
    }

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}
```

## Управление Плагинами

### Установка Плагина: CLI

Установка плагинов с помощью интерфейса командной строки.

```bash
# Установить плагин через CLI (требуется перезапуск)
java -jar jenkins-cli.jar -auth user:token install-plugin git
# Установить несколько плагинов
java -jar jenkins-cli.jar -auth user:token install-plugin \
  git maven-plugin docker-plugin
# Установить из файла .hpi
java -jar jenkins-cli.jar -auth user:token install-plugin \
  /path/to/plugin.hpi
# Показать установленные плагины
java -jar jenkins-cli.jar -auth user:token list-plugins
# Установка плагинов через plugins.txt (для Docker)
# Создать файл plugins.txt:
git:latest
maven-plugin:latest
docker-plugin:latest
pipeline-stage-view:latest
# Использовать инструмент jenkins-plugin-cli
jenkins-plugin-cli --plugins git maven-plugin docker-plugin
```

### Основные Плагины

Часто используемые плагины Jenkins для различных целей.

```bash
# Плагины Сборки и SCM
git                    # Интеграция с Git
github                 # Интеграция с GitHub
maven-plugin          # Поддержка сборок Maven
gradle                # Поддержка сборок Gradle
# Плагины Конвейеров
workflow-aggregator   # Набор плагинов Pipeline
pipeline-stage-view   # Представление стадий конвейера
blue-ocean           # Современный UI для конвейеров
# Развертывание и Интеграция
docker-plugin        # Интеграция с Docker
kubernetes           # Развертывание в Kubernetes
ansible              # Автоматизация Ansible
# Качество и Тестирование
junit                # Отчеты о тестах JUnit
jacoco              # Покрытие кода
sonarqube           # Анализ качества кода
```

### Управление Плагинами через Веб-интерфейс

Управление плагинами через веб-интерфейс Jenkins.

```bash
# Доступ к Менеджеру Плагинов:
# 1. Перейти в Manage Jenkins (Управление Jenkins)
# 2. Нажать "Manage Plugins" (Управление плагинами)
# 3. Использовать вкладки Available/Installed/Updates (Доступные/Установленные/Обновления)
# 4. Поиск плагинов
# 5. Выбрать и установить
# 6. Перезапустить Jenkins, если требуется
# Процесс обновления плагина:
# 1. Проверить вкладку "Updates" (Обновления)
# 2. Выбрать плагины для обновления
# 3. Нажать "Download now and install after restart" (Скачать сейчас и установить после перезапуска)
```

## Управление Пользователями и Безопасность

### Управление Пользователями

Создание и управление пользователями Jenkins.

```bash
# Включить безопасность Jenkins:
# 1. Manage Jenkins → Configure Global Security
# 2. Включить "Jenkins' own user database" (Собственная база данных пользователей Jenkins)
# 3. Разрешить пользователям регистрироваться (первоначальная настройка)
# 4. Установить стратегию авторизации
# Создание пользователя через CLI (требует соответствующих разрешений)
# Пользователи обычно создаются через веб-интерфейс:
# 1. Manage Jenkins → Manage Users
# 2. Нажать "Create User" (Создать пользователя)
# 3. Заполнить данные пользователя
# 4. Назначить роли/разрешения
```

### Аутентификация и Авторизация

Настройка областей безопасности (security realms) и стратегий авторизации.

```bash
# Варианты настройки безопасности:
# 1. Security Realm (область безопасности - как пользователи проходят аутентификацию):
#    - Jenkins' own user database
#    - LDAP
#    - Active Directory
#    - Matrix-based security
#    - Role-based authorization
# 2. Authorization Strategy (стратегия авторизации):
#    - Anyone can do anything
#    - Legacy mode
#    - Logged-in users can do anything
#    - Matrix-based security
#    - Project-based Matrix Authorization
```

### API Токены

Генерация и управление API токенами для доступа CLI.

```bash
# Генерация API токена:
# 1. Нажать на имя пользователя → Configure
# 2. Раздел API Token
# 3. Нажать "Add new Token" (Добавить новый токен)
# 4. Ввести имя токена
# 5. Сгенерировать и скопировать токен
# Использование API токена с CLI
java -jar jenkins-cli.jar -auth username:api-token \
  -s http://localhost:8080 list-jobs
# Безопасное хранение учетных данных
echo "username:api-token" > ~/.jenkins-cli-auth
chmod 600 ~/.jenkins-cli-auth
```

### Управление Учетными Данными (Credentials)

Управление сохраненными учетными данными для заданий и конвейеров.

```bash
# Управление учетными данными через CLI
java -jar jenkins-cli.jar -auth user:token \
  list-credentials system::system::jenkins
# Создание учетных данных XML и импорт
java -jar jenkins-cli.jar -auth user:token \
  create-credentials-by-xml system::system::jenkins \
  < credential.xml
```

```groovy
// Доступ к учетным данным в конвейерах
withCredentials([usernamePassword(
  credentialsId: 'my-credentials',
  usernameVariable: 'USERNAME',
  passwordVariable: 'PASSWORD'
)]) {
  sh 'docker login -u $USERNAME -p $PASSWORD'
}
```

## Мониторинг Сборок и Устранение Неполадок

### Статус Сборки и Логи

Мониторинг статуса сборки и доступ к подробным логам.

```bash
# Проверить статус сборки
java -jar jenkins-cli.jar -auth user:token console my-job
# Получить информацию о сборке
java -jar jenkins-cli.jar -auth user:token get-job my-job
# Мониторинг очереди сборки
# Веб-интерфейс: Главная панель Jenkins → Build Queue
# Показывает ожидающие сборки и их статус
# Доступ к истории сборок
# Веб-интерфейс: Job → Build History
# Показывает все предыдущие сборки со статусом
```

### Информация о Системе

Получение системной информации Jenkins и диагностических данных.

```bash
# Системная информация
java -jar jenkins-cli.jar -auth user:token version
# Информация о узлах (агентах)
java -jar jenkins-cli.jar -auth user:token list-computers
# Консоль Groovy (только для администраторов)
# Manage Jenkins → Script Console
# Выполнение скриптов Groovy для получения системной информации:
println Jenkins.instance.version
println Jenkins.instance.getRootDir()
println System.getProperty("java.version")
```

### Анализ Логирования

Доступ и анализ системных логов Jenkins.

```bash
# Расположение системных логов
# Linux: /var/log/jenkins/jenkins.log
# Windows: C:\Program Files\Jenkins\jenkins.out.log
# Просмотр логов
tail -f /var/log/jenkins/jenkins.log
# Настройка уровней логирования
# Manage Jenkins → System Log
# Добавить новый регистратор логов для определенных компонентов
# Общие расположения логов:
sudo journalctl -u jenkins.service     # Логи Systemd
sudo cat /var/lib/jenkins/jenkins.log  # Файл лога Jenkins
```

### Мониторинг Производительности

Мониторинг производительности и использования ресурсов Jenkins.

```bash
# Встроенный мониторинг
# Manage Jenkins → Load Statistics
# Показывает утилизацию исполнителей с течением времени
# Мониторинг JVM
# Manage Jenkins → Manage Nodes → Master
# Показывает использование памяти, ЦП и системные свойства
# Тренды сборок
# Установить плагин "Build History Metrics"
# Просмотр трендов продолжительности сборок и показателей успеха
# Мониторинг использования диска
# Установить плагин "Disk Usage"
# Мониторинг места на диске для рабочих областей и артефактов сборок
```

## Конфигурация и Настройки Jenkins

### Глобальная Конфигурация

Настройка глобальных настроек Jenkins и инструментов.

```bash
# Глобальная Конфигурация Инструментов
# Manage Jenkins → Global Tool Configuration
# Настройка:
# - Установки JDK
# - Установки Git
# - Установки Maven
# - Установки Docker
# Системная Конфигурация
# Manage Jenkins → Configure System
# Установка:
# - URL Jenkins
# - Системное сообщение
# - # исполнителей (executors)
# - Quiet period (период ожидания)
# - Ограничения опроса SCM
```

### Переменные Окружения

Настройка переменных окружения и системных свойств Jenkins.

```bash
# Встроенные переменные окружения
BUILD_NUMBER          # Номер сборки
BUILD_ID              # ID сборки
JOB_NAME             # Имя задания
WORKSPACE            # Путь к рабочей области задания
JENKINS_URL          # URL Jenkins
NODE_NAME            # Имя узла
# Пользовательские переменные окружения
# Manage Jenkins → Configure System
# Global properties → Environment variables
# Добавление пар ключ-значение для глобального доступа
```

### Jenkins Configuration as Code (JCasC)

Управление конфигурацией Jenkins с помощью плагина JCasC.

```yaml
# Файл конфигурации JCasC (jenkins.yaml)
jenkins:
  systemMessage: "Jenkins configured as code"
  numExecutors: 4
  securityRealm:
    local:
      allowsSignup: false
      users:
       - id: "admin"
         password: "admin123"
# Применение конфигурации
# Установить переменную окружения CASC_JENKINS_CONFIG
export CASC_JENKINS_CONFIG=/path/to/jenkins.yaml
```

## Лучшие Практики

### Рекомендации по Безопасности

Поддержание безопасности экземпляра Jenkins для продакшена.

```bash
# Рекомендации по безопасности:
# 1. Включить безопасность и аутентификацию
# 2. Использовать авторизацию на основе матрицы
# 3. Регулярные обновления безопасности
# 4. Ограничение разрешений пользователей
# 5. Использование API токенов вместо паролей
# Защита конфигурации Jenkins:
# - Отключить CLI через remoting
# - Использовать HTTPS с действительными сертификатами
# - Регулярное резервное копирование JENKINS_HOME
# - Мониторинг уведомлений о безопасности
# - Использование плагинов учетных данных для секретов
```

### Оптимизация Производительности

Оптимизация Jenkins для лучшей производительности и масштабируемости.

```bash
# Советы по производительности:
# 1. Использовать распределенные сборки с агентами
# 2. Оптимизировать скрипты сборки и зависимости
# 3. Автоматическая очистка старых сборок
# 4. Использовать библиотеки конвейеров для повторного использования
# 5. Мониторинг дискового пространства и использования памяти
# Оптимизация сборки:
# - Использовать инкрементальные сборки, где это возможно
# - Параллельное выполнение стадий
# - Кэширование артефактов
# - Очистка рабочей области
# - Тонкая настройка выделения ресурсов
```

## Соответствующие Ссылки

- <router-link to="/devops">Шпаргалка по DevOps</router-link>
- <router-link to="/docker">Шпаргалка по Docker</router-link>
- <router-link to="/kubernetes">Шпаргалка по Kubernetes</router-link>
- <router-link to="/ansible">Шпаргалка по Ansible</router-link>
- <router-link to="/git">Шпаргалка по Git</router-link>
- <router-link to="/linux">Шпаргалка по Linux</router-link>
- <router-link to="/shell">Шпаргалка по Shell</router-link>

---
title: 'Шпаргалка по Kubernetes | LabEx'
description: 'Изучите оркестрацию Kubernetes с помощью этой исчерпывающей шпаргалки. Краткий справочник по командам kubectl, подам, развертываниям, сервисам, ingress и управлению облачными контейнерами.'
pdfUrl: '/cheatsheets/pdf/kubernetes-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Справочник по Kubernetes
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/ru/learn/kubernetes">Изучите Kubernetes с практическими лабораториями</a>
</base-disclaimer-title>
<base-disclaimer-content>
Изучите оркестрацию контейнеров Kubernetes с помощью практических лабораторий и сценариев реального мира. LabEx предлагает комплексные курсы по Kubernetes, охватывающие основные команды kubectl, управление подами (pod), развертываниями (deployment), службами (service), сетевое взаимодействие и администрирование кластера. Освойте оркестрацию контейнеров и развертывание облачных нативных приложений.
</base-disclaimer-content>
</base-disclaimer>

## Установка и Настройка

### Установка kubectl

Установите инструмент командной строки Kubernetes.

```bash
# macOS с Homebrew
brew install kubectl
# Linux (официальный бинарный файл)
curl -LO "https://dl.k8s.io/release/$(curl -L -s
https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kube
ctl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
# Windows с Chocolatey
choco install kubernetes-cli
```

### Проверка Установки

Проверьте версию kubectl и подключение к кластеру.

```bash
# Проверить версию kubectl
kubectl version --client
# Проверить версии клиента и сервера
kubectl version
# Получить информацию о кластере
kubectl cluster-info
```

### Настройка kubectl

Настройка доступа к кластеру и контекста.

```bash
# Просмотр текущей конфигурации
kubectl config view
# Список всех контекстов
kubectl config get-contexts
# Переключение на контекст
kubectl config use-context my-cluster
# Установка пространства имен по умолчанию
kubectl config set-context --current --namespace=my-
namespace
```

### Настройка Minikube

Быстрый локальный кластер Kubernetes для разработки.

```bash
# Запуск Minikube
minikube start
# Проверка статуса
minikube status
# Доступ к панели управления
minikube dashboard
# Остановка кластера
minikube stop
```

## Основные Команды и Информация о Кластере

### Информация о Кластере: `kubectl cluster-info`

Отображение основной информации о кластере и конечных точек служб.

```bash
# Получить информацию о кластере
kubectl cluster-info
# Получить конфигурацию кластера
kubectl config view
# Проверить доступные ресурсы API
kubectl api-resources
# Отобразить поддерживаемые версии API
kubectl api-versions
```

### Управление Узлами: `kubectl get nodes`

Просмотр и управление узлами кластера.

```bash
# Список всех узлов
kubectl get nodes
# Подробная информация об узлах
kubectl get nodes -o wide
# Описать конкретный узел
kubectl describe node
# Получить использование ресурсов узла
kubectl top nodes
```

### Операции с Пространствами Имен: `kubectl get namespaces`

Организация и изоляция ресурсов с использованием пространств имен.

```bash
# Список всех пространств имен
kubectl get namespaces
# Создать пространство имен
kubectl create namespace my-
namespace
# Удалить пространство имен
kubectl delete namespace my-
namespace
# Получить ресурсы в конкретном пространстве имен
kubectl get all -n my-namespace
```

<BaseQuiz id="kubernetes-namespace-1" correct="B">
  <template #question>
    Какова основная цель пространств имен Kubernetes?
  </template>
  
  <BaseQuizOption value="A">Для повышения производительности кластера</BaseQuizOption>
  <BaseQuizOption value="B" correct>Для организации и изоляции ресурсов внутри кластера</BaseQuizOption>
  <BaseQuizOption value="C">Для соединения кластеров вместе</BaseQuizOption>
  <BaseQuizOption value="D">Для хранения образов контейнеров</BaseQuizOption>
  
  <BaseQuizAnswer>
    Пространства имен предоставляют способ разделения ресурсов кластера между несколькими пользователями или командами. Они помогают организовать ресурсы и обеспечивают область видимости для имен, позволяя иметь ресурсы с одинаковыми именами в разных пространствах имен.
  </BaseQuizAnswer>
</BaseQuiz>

## Управление Подами (Pod Management)

### Создание и Запуск Подов: `kubectl run` / `kubectl create`

Запуск контейнеров и управление их жизненным циклом.

```bash
# Запустить простой под
kubectl run nginx --image=nginx
# Создать под из YAML-файла
kubectl create -f pod.yaml
# Запустить под с командой
kubectl run busybox --image=busybox -- echo "Hello
World"
# Создать задание (job)
kubectl create job hello --image=busybox:1.28 -- echo
"Hello World"
```

### Просмотр Информации о Подах: `kubectl get pods`

Список и инспекция запущенных подов.

```bash
# Список всех подов в пространстве имен по умолчанию
kubectl get pods
# Список подов с дополнительными деталями
kubectl get pods -o wide
# Список подов во всех пространствах имен
kubectl get pods --all-namespaces
# Наблюдение за изменениями статуса пода
kubectl get pods --watch
```

<BaseQuiz id="kubernetes-pods-1" correct="C">
  <template #question>
    Что делает команда `kubectl get pods --all-namespaces`?
  </template>
  
  <BaseQuizOption value="A">Выводит только запущенные поды</BaseQuizOption>
  <BaseQuizOption value="B">Выводит поды в пространстве имен по умолчанию</BaseQuizOption>
  <BaseQuizOption value="C" correct>Выводит поды во всех пространствах имен кластера</BaseQuizOption>
  <BaseQuizOption value="D">Удаляет все поды</BaseQuizOption>
  
  <BaseQuizAnswer>
    Флаг `--all-namespaces` (или `-A`) показывает поды из всех пространств имен, а не только из пространства по умолчанию. Это полезно для обзора всего кластера.
  </BaseQuizAnswer>
</BaseQuiz>

### Детали Пода: `kubectl describe pod`

Получение исчерпывающей информации о конкретных подах.

```bash
# Описать конкретный под
kubectl describe pod
# Описать под в конкретном пространстве имен
kubectl describe pod  -n
```

### Операции с Подами: `kubectl exec` / `kubectl delete`

Выполнение команд в подах и управление жизненным циклом пода.

```bash
# Получить логи пода
kubectl logs
# Следить за логами в реальном времени
kubectl logs -f
# Выполнить команду в поде
kubectl exec -it  -- /bin/bash
# Выполнить команду в конкретном контейнере
kubectl exec -it  -c  -- sh
# Удалить под
kubectl delete pod
# Принудительное удаление пода
kubectl delete pod  --grace-period=0 --force
```

## Развертывания (Deployments) и ReplicaSets

### Создание Развертываний: `kubectl create deployment`

Декларативное развертывание и управление приложениями.

```bash
# Создать развертывание
kubectl create deployment nginx --image=nginx
# Создать развертывание с репликами
kubectl create deployment webapp --image=nginx --
replicas=3
# Создать из YAML-файла
kubectl apply -f deployment.yaml
# Открыть развертывание как службу
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
```

<BaseQuiz id="kubernetes-deployment-1" correct="A">
  <template #question>
    Каково основное назначение развертывания Kubernetes (Deployment)?
  </template>
  
  <BaseQuizOption value="A" correct>Управление и поддержание желаемого количества реплик пода</BaseQuizOption>
  <BaseQuizOption value="B">Открытие подов для внешнего трафика</BaseQuizOption>
  <BaseQuizOption value="C">Хранение данных конфигурации</BaseQuizOption>
  <BaseQuizOption value="D">Управление узлами кластера</BaseQuizOption>
  
  <BaseQuizAnswer>
    Deployment управляет ReplicaSet, который обеспечивает запуск указанного числа реплик пода. Он предоставляет декларативные обновления, поэтапные обновления (rolling updates) и возможности отката.
  </BaseQuizAnswer>
</BaseQuiz>

### Управление Развертываниями: `kubectl get deployments`

Просмотр и контроль статуса и конфигурации развертывания.

```bash
# Список развертываний
kubectl get deployments
# Описать развертывание
kubectl describe deployment
# Редактировать развертывание
kubectl edit deployment
# Удалить развертывание
kubectl delete deployment
```

### Масштабирование: `kubectl scale`

Настройка количества запущенных реплик.

```bash
# Масштабировать развертывание
kubectl scale deployment nginx --replicas=5
# Масштабировать ReplicaSet
kubectl scale rs  --replicas=3
# Автомасштабирование развертывания
kubectl autoscale deployment nginx --min=2 --max=10 --
cpu-percent=80
```

<BaseQuiz id="kubernetes-scale-1" correct="B">
  <template #question>
    Что делает команда `kubectl scale deployment nginx --replicas=5`?
  </template>
  
  <BaseQuizOption value="A">Создает 5 новых развертываний</BaseQuizOption>
  <BaseQuizOption value="B" correct>Масштабирует развертывание nginx до 5 реплик пода</BaseQuizOption>
  <BaseQuizOption value="C">Удаляет 5 подов из развертывания</BaseQuizOption>
  <BaseQuizOption value="D">Обновляет образ развертывания</BaseQuizOption>
  
  <BaseQuizAnswer>
    Команда `scale` изменяет количество реплик для развертывания. Эта команда гарантирует, что развертывание nginx будет запускать ровно 5 реплик пода, создавая или удаляя поды по мере необходимости.
  </BaseQuizAnswer>
</BaseQuiz>

### Поэтапные Обновления: `kubectl rollout`

Управление обновлениями развертываний и их откатами.

```bash
# Проверить статус развертывания
kubectl rollout status deployment/nginx
# Просмотр истории развертывания
kubectl rollout history deployment/nginx
# Откат к предыдущей версии
kubectl rollout undo deployment/nginx
# Откат к определенной ревизии
kubectl rollout undo deployment/nginx --to-revision=2
```

## Службы (Services) и Сетевое Взаимодействие

### Открытие Служб: `kubectl expose`

Предоставление доступа к приложениям через сетевые службы.

```bash
# Открыть развертывание как службу ClusterIP
kubectl expose deployment nginx --port=80
# Открыть как службу NodePort
kubectl expose deployment nginx --port=80 --
type=NodePort
# Открыть как LoadBalancer
kubectl expose deployment nginx --port=80 --
type=LoadBalancer
# Создать службу из YAML
kubectl apply -f service.yaml
```

<BaseQuiz id="kubernetes-service-1" correct="A">
  <template #question>
    Какой тип службы по умолчанию используется при вызове `kubectl expose`?
  </template>
  
  <BaseQuizOption value="A" correct>ClusterIP</BaseQuizOption>
  <BaseQuizOption value="B">NodePort</BaseQuizOption>
  <BaseQuizOption value="C">LoadBalancer</BaseQuizOption>
  <BaseQuizOption value="D">ExternalName</BaseQuizOption>
  
  <BaseQuizAnswer>
    ClusterIP является типом службы по умолчанию. Он открывает службу на внутреннем IP-адресе кластера, делая ее доступной только внутри кластера. Типы NodePort и LoadBalancer предоставляют внешний доступ.
  </BaseQuizAnswer>
</BaseQuiz>

### Обнаружение Служб: `kubectl get services`

Список и инспекция служб в вашем кластере.

```bash
# Список всех служб
kubectl get services
# Список служб с дополнительными деталями
kubectl get svc -o wide
# Описать конкретную службу
kubectl describe service
# Получить конечные точки службы
kubectl get endpoints
```

### Перенаправление Портов: `kubectl port-forward`

Доступ к приложениям локально для тестирования и отладки.

```bash
# Перенаправить порт пода на локальную машину
kubectl port-forward pod/ 8080:80
# Перенаправить порт службы
kubectl port-forward svc/ 8080:80
# Перенаправить порт развертывания
kubectl port-forward deployment/ 8080:80
# Перенаправить несколько портов
kubectl port-forward pod/ 8080:80 8443:443
```

### Управление Ingress

Управление внешним доступом к службам через маршруты HTTP/HTTPS.

```bash
# Список ресурсов Ingress
kubectl get ingress
# Описать Ingress
kubectl describe ingress
# Создать Ingress из YAML
kubectl apply -f ingress.yaml
```

## ConfigMaps и Секреты (Secrets)

### ConfigMaps: `kubectl create configmap`

Хранение неконфиденциальных данных конфигурации в парах ключ-значение.

```bash
# Создать ConfigMap из литералов
kubectl create configmap app-config --from-
literal=database_url=localhost --from-literal=debug=true
# Создать из файла
kubectl create configmap app-config --from-
file=app.properties
# Создать из каталога
kubectl create configmap app-config --from-file=config/
```

### Использование ConfigMap

Использование ConfigMaps в подах в качестве переменных окружения или томов.

```bash
# Просмотр ConfigMap
kubectl get configmaps
kubectl describe configmap app-config
# Получить YAML ConfigMap
kubectl get configmap app-config -o yaml
# Редактировать ConfigMap
kubectl edit configmap app-config
# Удалить ConfigMap
kubectl delete configmap app-config
```

### Секреты (Secrets): `kubectl create secret`

Хранение и управление конфиденциальной информацией, такой как пароли и ключи API.

```bash
# Создать общий секрет
kubectl create secret generic db-secret --from-
literal=username=admin --from-
literal=password=secret123
# Создать секрет из файла
kubectl create secret generic ssl-certs --from-file=tls.crt --
from-file=tls.key
# Создать секрет реестра docker
kubectl create secret docker-registry my-registry --
docker-server=myregistry.com --docker-username=user -
-docker-password=pass
```

### Управление Секретами

Просмотр и управление секретами.

```bash
# Список секретов
kubectl get secrets
# Описать секрет (значения скрыты)
kubectl describe secret db-secret
# Декодировать значения секрета
kubectl get secret db-secret -o
jsonpath='{.data.password}' | base64 -d
# Удалить секрет
kubectl delete secret db-secret
```

## Хранилище и Тома (Storage & Volumes)

### Постоянные Тома (Persistent Volumes): `kubectl get pv`

Управление ресурсами хранения в масштабе всего кластера.

```bash
# Список постоянных томов
kubectl get pv
# Описать постоянный том
kubectl describe pv
# Создать PV из YAML
kubectl apply -f persistent-volume.yaml
# Удалить постоянный том
kubectl delete pv
```

### Запросы на Постоянный Том (Persistent Volume Claims): `kubectl get pvc`

Запрос ресурсов хранения для подов.

```bash
# Список PVC
kubectl get pvc
# Описать PVC
kubectl describe pvc
# Создать PVC из YAML
kubectl apply -f pvc.yaml
# Удалить PVC
kubectl delete pvc
```

### Классы Хранения (Storage Classes): `kubectl get storageclass`

Определение различных типов хранилищ с различными свойствами.

```bash
# Список классов хранения
kubectl get storageclass
# Описать класс хранения
kubectl describe storageclass
# Установить класс хранения по умолчанию
kubectl patch storageclass  -p '{"metadata":
{"annotations":{"storageclass.kubernetes.io/is-default-
class":"true"}}}'
```

### Операции с Томами

Работа с различными типами томов в ваших подах.

```bash
# Проверить монтирование томов в поде
kubectl describe pod  | grep -A5 "Mounts:"
# Список томов в поде
kubectl get pod  -o yaml | grep -A10 "volumes:"
```

## Устранение Неполадок и Отладка (Troubleshooting & Debugging)

### Логи и События: `kubectl logs` / `kubectl get events`

Анализ логов приложений и событий кластера для отладки.

```bash
# Просмотр логов пода
kubectl logs
# Следить за логами в реальном времени
kubectl logs -f
# Просмотр логов предыдущего контейнера
kubectl logs  --previous
# Просмотр логов конкретного контейнера
kubectl logs  -c
# Просмотр событий кластера
kubectl get events --sort-
by=.metadata.creationTimestamp
```

### Инспекция Ресурсов: `kubectl describe`

Получение подробной информации о любом ресурсе Kubernetes.

```bash
# Описать под
kubectl describe pod
# Описать развертывание
kubectl describe deployment
# Описать службу
kubectl describe service
# Описать узел
kubectl describe node
```

### Использование Ресурсов: `kubectl top`

Мониторинг потребления ресурсов узлами и подами.

```bash
# Использование ресурсов узлами
kubectl top nodes
# Использование ресурсов подами
kubectl top pods
# Использование ресурсов в пространстве имен
kubectl top pods -n
# Сортировка подов по использованию CPU
kubectl top pods --sort-by=cpu
```

### Интерактивная Отладка: `kubectl exec` / `kubectl debug`

Доступ к запущенным контейнерам для практического устранения неполадок.

```bash
# Выполнить интерактивную оболочку
kubectl exec -it  -- /bin/bash
# Отладка с помощью эфемерного контейнера (K8s 1.23+)
kubectl debug  -it --image=busybox
# Скопировать файлы из пода
kubectl cp :/path/to/file ./local-file
# Скопировать файлы в под
kubectl cp ./local-file :/path/to/destination
```

## Управление Ресурсами

### Применение Ресурсов: `kubectl apply`

Создание или обновление ресурсов с использованием декларативных конфигурационных файлов.

```bash
# Применить один файл
kubectl apply -f deployment.yaml
# Применить несколько файлов
kubectl apply -f deployment.yaml -f service.yaml
# Применить весь каталог
kubectl apply -f ./k8s-configs/
# Применить из URL
kubectl apply -f https://example.com/manifest.yaml
# Показать, что будет применено (сухой запуск)
kubectl apply -f deployment.yaml --dry-run=client -o yaml
```

### Операции с Ресурсами: `kubectl get` / `kubectl delete`

Список, инспекция и удаление ресурсов Kubernetes.

```bash
# Получить все ресурсы в пространстве имен
kubectl get all
# Получить ресурсы с пользовательскими столбцами
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase
# Получить ресурсы в формате JSON/YAML
kubectl get deployment nginx -o yaml
kubectl get pod  -o json
# Удалить ресурсы
kubectl delete -f deployment.yaml
kubectl delete pod,service -l app=nginx
```

### Редактирование Ресурсов: `kubectl edit` / `kubectl patch`

Прямое изменение существующих ресурсов.

```bash
# Редактировать ресурс интерактивно
kubectl edit deployment
# Патч ресурса с помощью стратегического слияния
kubectl patch deployment nginx -p '{"spec":
{"replicas":3}}'
# Патч с помощью слияния JSON
kubectl patch pod  --type='json' -p='[{"op": "replace",
"path": "/metadata/labels/env", "value": "prod"}]'
# Полностью заменить ресурс
kubectl replace -f updated-deployment.yaml
```

### Валидация Ресурсов: `kubectl diff` / `kubectl explain`

Сравнение конфигураций и понимание схем ресурсов.

```bash
# Показать различия перед применением
kubectl diff -f deployment.yaml
# Объяснить структуру ресурса
kubectl explain pod.spec.containers
# Объяснить с примерами
kubectl explain deployment --recursive
# Проверить ресурс без применения
kubectl apply -f deployment.yaml --dry-run=client --
validate=true
```

## Расширенные Операции

### Управление Узлами: `kubectl cordon` / `kubectl drain`

Управление доступностью узлов для обслуживания и обновлений.

```bash
# Отметить узел как недоступный для планирования
kubectl cordon
# Отметить узел как доступный для планирования
kubectl uncordon
# Осушить узел для обслуживания
kubectl drain  --ignore-daemonsets --delete-emptydir-
data
# Добавить "taint" к узлу
kubectl taint nodes  key=value:NoSchedule
# Удалить "taint" с узла
kubectl taint nodes  key:NoSchedule-
```

### Метки и Аннотации: `kubectl label` / `kubectl annotate`

Добавление метаданных к ресурсам для организации и выбора.

```bash
# Добавить метку к ресурсу
kubectl label pod  environment=production
# Удалить метку с ресурса
kubectl label pod  environment-
# Добавить аннотацию к ресурсу
kubectl annotate pod  description="Frontend web
server"
# Выбрать ресурсы по метке
kubectl get pods -l environment=production
kubectl get pods -l 'environment in (production,staging)'
```

### Прокси и Аутентификация: `kubectl proxy` / `kubectl auth`

Доступ к API кластера и управление аутентификацией.

```bash
# Запустить прокси для API Kubernetes
kubectl proxy --port=8080
# Проверить, может ли пользователь выполнить действие
kubectl auth can-i create pods
kubectl auth can-i '*' '*' --
as=system:serviceaccount:default:my-sa
# Выполнить действие от имени пользователя
kubectl get pods --as=system:serviceaccount:default:my-
sa
# Просмотр информации об аутентификации пользователя
kubectl config view --raw -o jsonpath='{.users[*].name}'
```

### Вспомогательные Команды

Дополнительные полезные команды для операций Kubernetes.

```bash
# Ожидание условия
kubectl wait --for=condition=Ready pod/ --timeout=300s
# Запуск временного пода для тестирования
kubectl run tmp-pod --rm -i --tty --image=busybox --
/bin/sh
# Генерация YAML ресурса без создания
kubectl create deployment nginx --image=nginx --dry-
run=client -o yaml
# Сортировка ресурсов по времени создания
kubectl get pods --sort-by=.metadata.creationTimestamp
```

## Производительность и Мониторинг

### Метрики Ресурсов: `kubectl top`

Просмотр потребления ресурсов в реальном времени по всему кластеру.

```bash
# Использование ресурсов узлами
kubectl top nodes --sort-by=cpu
kubectl top nodes --sort-by=memory
# Использование ресурсов подами
kubectl top pods --sort-by=cpu
kubectl top pods --sort-by=memory -A
# Использование ресурсов контейнерами
kubectl top pods --containers=true
# Историческое использование ресурсов (требуется metrics-server)
kubectl top pods --previous
```

### Проверки Состояния и Статус

Мониторинг состояния работоспособности приложений и кластера.

```bash
# Проверить статус развертывания
kubectl rollout status deployment/
# Проверить готовность пода
kubectl get pods --field-selector=status.phase=Running
# Мониторинг квот ресурсов
kubectl get resourcequota
kubectl describe resourcequota
# Проверить состояние компонентов кластера
kubectl get componentstatuses
```

### Оптимизация Производительности

Команды для помощи в оптимизации производительности кластера.

```bash
# Просмотр запросов и лимитов ресурсов
kubectl describe node  | grep -A5 "Allocated resources:"
# Проверить бюджеты прерывания пода
kubectl get pdb
# Просмотр горизонтальных автомасштабировщиков подов
kubectl get hpa
# Проверить сетевые политики
kubectl get networkpolicy
```

### Резервное Копирование и Восстановление

Основные команды для резервного копирования и аварийного восстановления кластера.

```bash
# Резервное копирование всех ресурсов в пространстве имен
kubectl get all -o yaml -n  > backup.yaml
# Экспорт конкретного ресурса
kubectl get deployment  -o yaml > deployment-
backup.yaml
# Список всех ресурсов для резервного копирования
kubectl api-resources --verbs=list --namespaced -o name
| xargs -n 1 kubectl get --show-kind --ignore-not-found -n
```

## Управление Конфигурацией и Контекстом

### Управление Контекстом

Переключение между различными кластерами и пользователями Kubernetes.

```bash
# Просмотр текущего контекста
kubectl config current-context
# Список всех контекстов
kubectl config get-contexts
# Переключение контекста
kubectl config use-context
# Создание нового контекста
kubectl config set-context dev-
context --cluster=dev-cluster --
user=dev-user --
namespace=development
```

### Управление Kubeconfig

Настройка kubectl для работы с несколькими кластерами.

```bash
# Просмотр объединенного kubeconfig
kubectl config view
# Установка информации о кластере
kubectl config set-cluster  --
server=https://cluster-api-url --
certificate-
authority=/path/to/ca.crt
# Установка учетных данных пользователя
kubectl config set-credentials  --
client-
certificate=/path/to/client.crt --
client-key=/path/to/client.key
# Слияние файлов kubeconfig
KUBECONFIG=~/.kube/config:~/.
kube/config2 kubectl config
view --merge --flatten >
~/.kube/merged-config
```

### Настройки по Умолчанию

Установка пространств имен по умолчанию и предпочтений для операций kubectl.

```bash
# Установить пространство имен по умолчанию для
текущего контекста
kubectl config set-context --
current --namespace=
# Установить другой формат вывода по умолчанию
kubectl config set-context --
current --output=yaml
# Просмотр деталей конфигурации
kubectl config view -o
jsonpath='{.users[*].name}'
kubectl config view --raw
```

## Лучшие Практики и Советы

### Эффективность Команд

Сокращения и псевдонимы для ускорения ежедневных операций.

```bash
# Общие псевдонимы kubectl
alias k=kubectl
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'
# Использование коротких имен для ресурсов
kubectl get po        # pods
kubectl get svc       # services
kubectl get deploy    # deployments
kubectl get ns        # namespaces
kubectl get no        # nodes
# Наблюдение за ресурсами на предмет изменений
kubectl get pods --watch
kubectl get events --watch
```

### Выбор Ресурсов

Эффективные способы выбора и фильтрации ресурсов.

```bash
# Выбор по меткам
kubectl get pods -l app=nginx
kubectl get pods -l 'environment in (prod,staging)'
kubectl get pods -l app=nginx,version!=v1.0
# Выбор по полю
kubectl get pods --field-selector=status.phase=Running
kubectl get pods --field-
selector=spec.nodeName=worker-node-1
# Комбинирование селекторов
kubectl get pods -l app=nginx --field-
selector=status.phase=Running
```

### Форматирование Вывода

Настройка вывода команд для лучшей читаемости и обработки.

```bash
# Различные форматы вывода
kubectl get pods -o wide
kubectl get pods -o yaml
kubectl get pods -o json
kubectl get pods -o name
# Пользовательские столбцы
kubectl get pods -o custom-
columns=NAME:.metadata.name,STATUS:.status.phase,N
ODE:.spec.nodeName
# Запросы JSONPath
kubectl get pods -o jsonpath='{.items[*].metadata.name}'
kubectl get pods -o
jsonpath='{.items[*].spec.containers[*].image}'
```

### Безопасность и Валидация

Команды для обеспечения безопасных операций и проверки конфигураций.

```bash
# Сухой запуск для предварительного просмотра изменений
kubectl apply -f deployment.yaml --dry-run=client -o yaml
# Валидация конфигурации
kubectl apply -f deployment.yaml --validate=true --dry-
run=client
# Показать различия перед применением
kubectl diff -f deployment.yaml
# Принудительное удаление с периодом ожидания
kubectl delete pod  --grace-period=0 --force
```

## Соответствующие Ссылки

- <router-link to="/docker">Справочник по Docker</router-link>
- <router-link to="/linux">Справочник по Linux</router-link>
- <router-link to="/shell">Справочник по Shell</router-link>
- <router-link to="/devops">Справочник по DevOps</router-link>
- <router-link to="/ansible">Справочник по Ansible</router-link>
- <router-link to="/git">Справочник по Git</router-link>
- <router-link to="/rhel">Справочник по Red Hat Enterprise Linux</router-link>
- <router-link to="/cybersecurity">Справочник по Кибербезопасности</router-link>

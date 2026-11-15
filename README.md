# Auth — сервис аутентификации на Go для сайтов, CRM и API

Auth — самостоятельный backend для входа пользователей, управления доступом и интеграции с другими сервисами. Он хранит учётные записи и браузерные сессии в PostgreSQL, использует Redis для лимитов и выдаёт JWT для приложений и внешних API. Подключите его к своему сайту или CRM по HTTP API.

- **Вход и аккаунты.** Email и пароль, подтверждение почты, восстановление пароля, опциональные Google, Telegram, email-код и MFA.
- **Сессии и JWT.** Выберите cookie для сайта, обмен сессии на JWT для backend или native-вход с access и refresh tokens.
- **Управление доступом.** Роли и разрешения, приглашения и блокировка пользователей. В режиме multi-project у каждого проекта своя БД.

[Руководство по API](docs/auth-guide.md) · [Swagger JSON](docs/api/generated/swagger.json) · [JWT для внешнего backend](docs/features/jwt-consumer.md) · [Развёртывание](deploy/README.md)

## Установка инструментов

| Инструмент | Как установить |
| --- | --- |
| Git | Установите [Git](https://git-scm.com/install), чтобы клонировать репозиторий. |
| Docker и Docker Compose | На macOS и Windows установите и запустите [Docker Desktop](https://docs.docker.com/compose/install/). На Linux установите Docker Engine и [плагин Compose](https://docs.docker.com/compose/install/linux/). Команды Windows ниже выполняйте из WSL 2 с включённой интеграцией Docker Desktop. |
| Task | Это утилита Go Task, которая выполняет команды из `Taskfile.yml`. На macOS с Homebrew выполните `brew install go-task`. Для Linux и WSL выберите способ из [инструкции Task](https://taskfile.dev/docs/installation). Проект использует Task v3, в CI закреплена версия 3.53.1. |
| curl | Нужен для примеров HTTP-запросов. Проверьте доступность через `curl --version` или установите через пакетный менеджер вашей системы. |
| Go | Для запуска через Docker достаточно инструментов выше. Для сборки и проверок на хосте установите [Go](https://go.dev/doc/install) версии из [`go.mod`](go.mod). |

Проверьте, что инструменты доступны и Docker запущен.

```sh
git --version
docker info --format '{{.ServerVersion}}'
docker compose version
task --version
curl --version
```

## Обычный запуск локально

Выполните команды в терминале. `.env.example` содержит согласованные параметры для локальных PostgreSQL, Redis и Mailpit. На новой копии репозитория этих настроек достаточно для запуска API.

```sh
git clone https://github.com/Inforberi/auth.git
cd auth
cp .env.example .env
task dev:up
task dev:ps
curl --fail-with-body http://localhost:8080/health/ready
```

На существующей установке используйте свой `.env`. `task dev:up` запускает PostgreSQL, Redis и Mailpit, применяет миграции и поднимает Auth с автопересборкой Go. Первый запуск может занять несколько минут. Когда сервис готов, `/health/ready` возвращает HTTP 200.

| Что нужно | Команда или адрес |
| --- | --- |
| API | `http://localhost:8080/api/v1` |
| Swagger UI | `http://localhost:8080/swagger/index.html`, Basic Auth из `SWAGGER_USERNAME` и `SWAGGER_PASSWORD` в `.env` |
| Тестовая почта | `http://localhost:8025` |
| Состояние контейнеров | `task dev:ps` |
| Логи API и сборки | `task dev:logs` |
| Миграции отдельно | `task migrate:up` |
| Остановить с сохранением БД | `task dev:down` |
| Остальные команды | `task --list` |

Для входа с браузерной cookie нужен HTTPS. Настройте локальный HTTPS reverse proxy или положите сертификат и ключ в доступный контейнеру каталог, например `tmp/dev-tls/`. Для прямого TLS задайте `HTTP_TLS_CERT_FILE=/workspace/tmp/dev-tls/tls.crt` и `HTTP_TLS_KEY_FILE=/workspace/tmp/dev-tls/tls.key` в `.env`. Укажите HTTPS origin клиента в `AUTH_ALLOWED_ORIGINS` и перезапустите сервис через `task dev:down` и `task dev:up`. Браузер или curl должны доверять сертификату. При прямом TLS на порту 8080 адрес API будет `https://localhost:8080/api/v1`.

После настройки HTTPS можно зарегистрировать тестового пользователя через `POST /api/v1/auth/register/email`, затем [войти с cookie](#вход-с-cookie). Если регистрация закрыта или требуется управление ролями, воспользуйтесь [API первичной настройки](docs/features/initial-setup.md) для создания первого администратора.

### Если сервис не запускается

- **`task: command not found`** — установите Task и убедитесь, что команда доступна в новом терминале.
- **Docker daemon недоступен** — запустите Docker Desktop или проверьте, что Docker Engine работает и ваш пользователь имеет доступ к нему.
- **`/health/ready` возвращает ошибку** — проверьте `task dev:ps` и `task dev:logs`. Если занят порт API, измените `PORT` в `.env` и используйте новое значение в URL.
- **Вход возвращает `403 invalid_origin`** — проверьте, что `Origin` совпадает с разрешённым значением по схеме, хосту и порту. Указывайте origin без пути.

## Что заполнить в ENV

Для production начните с [`.env.prod.example`](.env.prod.example) для Compose и миграций и [`.env.prod.app.example`](.env.prod.app.example) для процесса Auth. [Порядок запуска, права БД, TLS и хранение секретов](deploy/README.md).

| Когда нужно | Что настроить |
| --- | --- |
| Всегда | `DATABASE_URL` с ограниченной runtime-ролью, PostgreSQL с применёнными миграциями, `REDIS_HOST` и `REDIS_PORT`. Для production нужен отдельный сильный `REDIS_PASSWORD`. |
| Всегда в текущей версии | `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_DOMAIN`, `EMAIL_OUTBOX_KEY`, `EMAIL_VERIFICATION_URL`, `PASSWORD_RESET_URL`, `PASSWORD_RESET_TOKEN_TTL`. В production требуется `SMTP_REQUIRE_TLS=true`. SMTP логин и пароль задаются, если их требует сервер. |
| Браузер и cookie | `AUTH_ALLOWED_ORIGINS` с точными HTTPS origins. Включите `AUTH_CORS_ENABLED`, если frontend и Auth работают на разных origins и браузер обращается к Auth напрямую. |
| Парольный профиль под ENV | На новой установке `AUTH_SETTINGS_MODE=env`, `AUTH_PASSWORD_ENABLED=true`. Задайте `AUTH_REGISTRATION_ENABLED` для самостоятельной регистрации и `AUTH_PASSWORD_EMAIL_VERIFICATION` со значением `disabled`, `optional` или `required`. |
| Первый администратор | `INITIAL_SETUP_ENABLED=true` и отдельный `INITIAL_SETUP_SECRET` на время [первичной настройки](docs/features/initial-setup.md). Для setup также нужны `MFA_ENABLED=true` и рабочий SMTP. Можно выбрать `mfaMode=optional`, чтобы первый администратор не был обязан подключать второй фактор. |
| Google, Telegram, email-код, MFA | Включайте отдельно. Для базового парольного входа оставьте их выключенными. [Матрица возможностей и настроек](docs/auth-guide.md). |
| JWT | `JWT_ENABLED=true`, HTTPS issuer, signing key, JWKS и конфигурация audience. Для входа напрямую с access и refresh tokens нужен `JWT_NATIVE_ENABLED=true`. [Контракт JWT](docs/features/jwt-consumer.md). |
| Swagger UI | `SWAGGER_ENABLED=true` и отдельные `SWAGGER_USERNAME` и `SWAGGER_PASSWORD`. Для генерации SDK достаточно файла из репозитория. |
| Несколько проектов | Включайте `PLATFORM_ENABLED` для общей панели и независимых проектных БД. Для одного сервиса оставьте `false`. [Архитектура multi-project](docs/planning/multi-project.md). |

`AUTH_SETTINGS_MODE=api` — режим по умолчанию. Настройки меняются через API и сохраняются в БД. `env` читает поддерживаемые политики из окружения. Пользователи и роли в обоих режимах управляются через API. Источник настроек выбирается при установке. [Правила обновления существующей БД](docs/features/settings-source.md).

## Запуск на сервере

Подготовьте файлы конфигурации в новой копии репозитория:

```sh
cp .env.prod.example .env.prod
cp .env.prod.app.example .env.prod.app
```

В `.env.prod` задайте доступ владельца PostgreSQL для миграций и резервного копирования. В `.env.prod.app` укажите `DATABASE_URL` отдельной роли `auth_runtime` и настройки самого Auth. В обоих файлах должен совпадать пароль Redis. Подготовьте каталог `AUTH_SECRETS_DIR`, HTTPS и секреты по [инструкции развёртывания](deploy/README.md#конфигурация-production).

Команды ниже используют стандартные имена БД `auth` и роли `auth_runtime`. Если меняете имена, адаптируйте SQL-grants по инструкции развёртывания. Выполните из корня репозитория:

```sh
compose_prod() {
  docker compose --project-directory . --env-file .env.prod \
    -f deploy/compose/base.yml -f deploy/compose/production.yml "$@"
}

compose_prod up -d --wait postgres redis
compose_prod exec postgres sh -c 'exec psql -X -U "$POSTGRES_USER" "$POSTGRES_DB"'
```

В консоли `psql` создайте роль для новой БД и задайте ей пароль интерактивно. Используйте этот пароль в `DATABASE_URL`, кодируя специальные символы в URL.

```sql
CREATE ROLE auth_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password auth_runtime
\q
```

Примените миграции, выдайте права runtime и запустите Auth.

```sh
compose_prod run --rm migrate up
task db:runtime-grants
task prod:up
curl --fail-with-body https://auth.example.com/health/ready
```

Подставьте свой домен. Снаружи публикуйте HTTPS endpoint Auth, оставляя PostgreSQL и Redis во внутренней сети. Для первого администратора используйте [setup API](docs/features/initial-setup.md). После успешной настройки уберите одноразовый секрет и выключите `INITIAL_SETUP_ENABLED`.

Логи — `task prod:logs`. Остановка с сохранением данных — `task prod:down`. Обновления и восстановление описаны в [инструкции развёртывания](deploy/README.md).

## Подключение к приложению

| Клиент | Какой вариант использовать |
| --- | --- |
| Сайт с браузерной сессией | Вход по паролю, защищённая cookie, чтение профиля через `GET /api/v1/auth/me`. JWT можно оставить выключенным. |
| Сайт и отдельный backend, например CRM | Обмен браузерной сессии через `POST /api/v1/auth/token/exchange` на JWT для конкретного audience. CRM проверяет Bearer JWT и применяет свои правила доступа к данным. |
| Мобильное приложение | `POST /api/v1/auth/native/password/login`, затем access JWT и refresh token. При настроенной MFA обработайте ответ с challenge. |

### Вход с cookie

Используйте тестового пользователя на своём Auth. Подставьте HTTPS-адрес сервиса, разрешённый origin клиента, email и пароль. При частном CA передайте `--cacert /путь/к/ca.crt` в обе команды.

```sh
auth_url=https://auth.example.test
app_origin=https://app.example.test
jar=$(mktemp)
trap 'rm -f "$jar"' EXIT
curl --fail-with-body --cookie-jar "$jar" \
  -H "Origin: $app_origin" -H 'Content-Type: application/json' \
  --data '{"email":"user@example.test","password":"ExamplePass1"}' \
  "$auth_url/api/v1/auth/login/email"
curl --fail-with-body --cookie "$jar" \
  "$auth_url/api/v1/auth/me"
```

В браузере отправляйте запросы с `credentials: "include"`. Запросы, меняющие состояние, должны приходить с разрешённого `Origin`. При ответе `202` обработайте [продолжение входа](docs/auth-guide.md#82-вход-по-постоянному-паролю) до чтения профиля.

### Проверка JWT на другом backend

Создайте один consumer в Go при запуске backend. Пример ниже использует подписанные ключи Auth и локальную проверку. Для немедленного отзыва доступа выберите `strict` и задайте URL introspection и отдельные сервисные credentials.

```go
consumer, err := authjwt.NewConsumer(ctx, authjwt.ConsumerConfig{
    Expected: authjwt.Expectations{
        Issuer: "https://auth.example.com",
        Audience: "crm",
        Mode: authjwt.Local,
    },
    JWKSURL: "https://auth.example.com/.well-known/jwks.json",
})
if err != nil {
    return err
}
defer consumer.Close()
mux.Handle("GET /api/customers", consumer.Middleware(customersHandler))
```

Пакет — `github.com/Inforberi/financial-intelligence/pkg/authjwt`. В локальном режиме уже выданный JWT действует до истечения срока. В `strict` Auth проверяет актуальность доступа при каждом запросе. [Примеры и контракт consumer](docs/features/jwt-consumer.md).

## Swagger, SDK и интеграция с ИИ

1. Возьмите [`swagger.json`](docs/api/generated/swagger.json). Это Swagger 2.0 со стабильными `operationId`. Для примера используются `postAuthLoginEmail` и `getAuthMe`.
2. Сообщите агенту ваш base URL, выбранный способ входа, разрешённый origin и список включённых функций. Swagger включает опциональные профили, доступность зависит от настройки экземпляра.
3. Для браузерной cookie используйте cookie jar в серверном клиенте или встроенное хранилище cookie браузера. Проверьте, что сгенерированный клиент передаёт `Origin` там, где он нужен. Успешная генерация типов сама по себе не подтверждает прохождение сценария входа.
4. Дайте агенту [HTTP-контракт](docs/api/contract.md) для форматов ошибок, cookie и ограничений. Передавайте секреты через конфигурацию окружения, без включения их в примеры и запросы к ИИ.

## Проверки и эксплуатация

`task sandbox:up` поднимает отдельный HTTPS-стенд для автоматических проверок и синтетических данных. Команды стенда и тестовые адреса описаны [отдельно](docs/operations/local-sandbox.md). Остановка — `task sandbox:down`.

- `task check` — тесты и lint. `task swagger` обновляет API после изменения ручек, DTO или аннотаций. `task check:api` проверяет, что файлы Swagger воспроизводятся.
- [Резервные копии и восстановление](deploy/README.md) — операции развёртывания с явным подтверждением и отдельными правами.
- [Статус приёмки](docs/operations/acceptance-summary.md) и [план](docs/planning/ui-management.md) — результаты и ещё открытые проверки, включая новые административные операции.
- При изменении запуска, ENV или способа интеграции обновляйте этот README, ENV-примеры и соответствующий раздел руководства в той же правке.

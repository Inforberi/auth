# Auth — сервис аутентификации на Go для сайтов, CRM и API

Auth предоставляет вход по email и паролю, защищённые браузерные сессии, JWT для API, роли и разрешения. Его можно использовать как отдельный backend со своим интерфейсом. Можно начать с пароля и сессий, затем включить MFA, Google, Telegram или вход по email-коду.

[Руководство по API](docs/auth-guide.md) · [Swagger JSON](docs/api/generated/swagger.json) · [JWT для внешнего backend](docs/features/jwt-consumer.md) · [Развёртывание](deploy/README.md)

## Быстрый запуск с HTTPS

Нужны Docker с Compose v2 и Task. Из корня репозитория:

```sh
task sandbox:up
```

- Auth API — `https://localhost:18443/api/v1`.
- Swagger — `https://localhost:18443/swagger/index.html`.
- Mailpit — `http://localhost:18026`. Здесь видны письма тестовым пользователям.
- CA для curl — `tmp/sandbox/tls.crt`. Используйте `--cacert` для проверки TLS.

Создайте тестового администратора по [инструкции к стенду](docs/operations/local-sandbox.md) или зарегистрируйте тестового пользователя, если профиль разрешает регистрацию. Swagger имеет отдельные [учётные данные стенда](docs/operations/local-sandbox.md#запуск-и-адреса). Чтобы остановить стенд с сохранением данных, выполните `task sandbox:down`.

Для разработки Go с автопересборкой скопируйте `.env.example` в `.env` и запустите `task dev:up`. Dev API слушает `http://localhost:8080`. Для проверки браузерного входа с Secure-cookie используйте HTTPS-стенд.

## Что заполнить в ENV

Для production начните с [`.env.prod.example`](.env.prod.example) для Compose и миграций и [`.env.prod.app.example`](.env.prod.app.example) для процесса Auth. [Порядок запуска, права БД, TLS и хранение секретов](deploy/README.md).

| Когда нужно | Что настроить |
| --- | --- |
| Всегда | `DATABASE_URL` с ограниченной runtime-ролью, PostgreSQL с применёнными миграциями, `REDIS_HOST` и `REDIS_PORT`. Для production нужен отдельный сильный `REDIS_PASSWORD`. |
| Всегда в текущей версии | `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_DOMAIN`, `EMAIL_OUTBOX_KEY`, `EMAIL_VERIFICATION_URL`, `PASSWORD_RESET_URL`, `PASSWORD_RESET_TOKEN_TTL`. В production требуется `SMTP_REQUIRE_TLS=true`. SMTP логин и пароль задаются, если их требует сервер. |
| Браузер и cookie | `AUTH_ALLOWED_ORIGINS` с точными HTTPS origins. Включите `AUTH_CORS_ENABLED`, если frontend и Auth работают на разных origins и браузер обращается к Auth напрямую. |
| Парольный профиль под ENV | На новой установке `AUTH_SETTINGS_MODE=env`, `AUTH_PASSWORD_ENABLED=true`. Задайте `AUTH_REGISTRATION_ENABLED` для самостоятельной регистрации и `AUTH_PASSWORD_EMAIL_VERIFICATION` со значением `disabled`, `optional` или `required`. |
| Первый администратор | `INITIAL_SETUP_ENABLED=true` и отдельный `INITIAL_SETUP_SECRET` на время [первичной настройки](docs/features/initial-setup.md). Для подтверждения используется почта. |
| Google, Telegram, email-код, MFA | Включайте отдельно. Для базового парольного входа оставьте их выключенными. [Матрица возможностей и настроек](docs/auth-guide.md). |
| JWT | `JWT_ENABLED=true`, HTTPS issuer, signing key, JWKS и конфигурация audience. Для входа напрямую с access и refresh tokens нужен `JWT_NATIVE_ENABLED=true`. [Контракт JWT](docs/features/jwt-consumer.md). |
| Swagger UI | `SWAGGER_ENABLED=true` и отдельные `SWAGGER_USERNAME` и `SWAGGER_PASSWORD`. Для генерации SDK достаточно файла из репозитория. |
| Несколько проектов | Включайте `PLATFORM_ENABLED` для общей панели и независимых проектных БД. Для одного сервиса оставьте `false`. [Архитектура multi-project](docs/planning/multi-project.md). |

`AUTH_SETTINGS_MODE=api` — режим по умолчанию. Настройки меняются через API и сохраняются в БД. `env` читает поддерживаемые политики из окружения. Пользователи и роли в обоих режимах управляются через API. Источник настроек выбирается при установке. [Правила обновления существующей БД](docs/features/settings-source.md).

## Подключение к приложению

| Клиент | Какой вариант использовать |
| --- | --- |
| Сайт с браузерной сессией | Вход по паролю, защищённая cookie, чтение профиля через `GET /api/v1/auth/me`. JWT можно оставить выключенным. |
| Сайт и отдельный backend, например CRM | Обмен браузерной сессии через `POST /api/v1/auth/token/exchange` на JWT для конкретного audience. CRM проверяет Bearer JWT и применяет свои правила доступа к данным. |
| Мобильное приложение | `POST /api/v1/auth/native/password/login`, затем access JWT и refresh token. При настроенной MFA обработайте ответ с challenge. |

### Вход с cookie

Пример для синтетического пользователя на HTTPS-стенде. Подставьте его email и пароль.

```sh
auth_url=https://localhost:18443
jar=$(mktemp)
trap 'rm -f "$jar"' EXIT
curl --fail-with-body --cacert tmp/sandbox/tls.crt --cookie-jar "$jar" \
  -H "Origin: $auth_url" -H 'Content-Type: application/json' \
  --data '{"email":"user@example.test","password":"ExamplePass1"}' \
  "$auth_url/api/v1/auth/login/email"
curl --fail-with-body --cacert tmp/sandbox/tls.crt --cookie "$jar" \
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

- `task check` — тесты и lint. `task swagger` обновляет API после изменения ручек, DTO или аннотаций. `task check:api` проверяет, что файлы Swagger воспроизводятся.
- [Резервные копии и восстановление](deploy/README.md) — операции развёртывания с явным подтверждением и отдельными правами.
- [Статус приёмки](docs/operations/acceptance-summary.md) и [план](docs/planning/ui-management.md) — результаты и ещё открытые проверки, включая новые административные операции.
- При изменении запуска, ENV или способа интеграции обновляйте этот README, ENV-примеры и соответствующий раздел руководства в той же правке.

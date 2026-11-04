# Sandbox Auth

Изолированное локальное окружение обычного Auth. Использует текущий production Dockerfile и отдельные настоящие PostgreSQL, Redis и Mailpit. Собственного backend или специальных бизнес-ручек нет.

## Запуск и остановка

Из корня репозитория, от обычного пользователя с доступом к Docker:

```sh
task sandbox:up
task sandbox:down
```

Запуск читает только `.env.example` и явные тестовые overrides. Остановка сохраняет volumes и тестовые данные. Не подключать рабочие `.env`, БД, ключи или SMTP credentials. Файлы сертификатов и ответов API создаются в игнорируемом `tmp/sandbox`, не в этом каталоге.

- Auth API: `https://localhost:18443/api/v1`.
- Swagger: `https://localhost:18443/swagger/index.html`.
- Mailpit: `http://localhost:18026`; письма остаются внутри стенда.

Сертификат self-signed: CLI использует `--cacert tmp/sandbox/tls.crt`. Системное хранилище доверия автоматически не изменяется. Порты доступны только через loopback, PostgreSQL/Redis наружу не публикуются.

## Содержимое

- `compose.yml` дополняет общий `deploy/compose/base.yml`.
- `config/` содержит JWT Compose override, тестовый каталог разрешений и SQL подготовки restricted runtime/тестовой роли. Общие migrations/grants не копируются.
- `tests/{token,access,session,security,cleanup,load}` содержит существующие проверки по фичам.
- `internal/testsupport` содержит общие test-only helpers HTTPS/login/Mailpit/deployment, используемые этими suites. В production-сборку они не входят.

Проверки используют тот же API, что Swagger и будущий UI; подготовка JWT отдельно opt-in.

Внешние live-проверки выключены при обычном `go test ./...`. Тесты без opt-in проверяют только локальную логику клиента/измерений. Отсутствие ошибки со SKIP не означает проверку запущенного API.

## Проверки и данные

Полная инструкция подготовки синтетических пользователей, initial admin/TOTP, JWT, тестов и восстановления — [локальный HTTPS-стенд](../docs/operations/local-sandbox.md). Реальная внешняя почта и Telegram этим стендом не проверяются.

Команды: `sandbox:jwt`, `sandbox:jwt:rotation`, `sandbox:admin`, `sandbox:lifecycle`, `sandbox:security`, `sandbox:cleanup`. Для JWT/admin-сценариев сначала выполнить prerequisites из инструкции; файлы `tmp/sandbox/admin-setup.json` и JWT material не генерируются повторно вместо существующих пользователей.

Нагрузочные `sandbox:load` и `sandbox:load:rest` запускаются отдельно по задаче. Перенос тестов не требует повторных нагрузочных измерений.

Все live-команды выполняются последовательно: они могут менять policy, пересоздавать API или временно останавливать зависимости. Не запускать несколько runners на одном стенде. Fault operations проверяют Compose label `auth-sandbox`, cleanup затрагивает только свои fixtures. Не применять `down -v`, FLUSHDB или массовое удаление `tmp/sandbox` ради обычной проверки.

После прерванного runner cleanup может не выполниться: следовать инструкции восстановления соответствующего сценария. Самостоятельно удалять чужие контейнеры/volumes или рабочие данные запрещено.

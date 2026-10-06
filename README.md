# Auth template

Рабочая инфраструктурная основа Go Auth, **ещё не готовый production auth продукт**. Email verification/reset API, полноценная session security, Telegram, RBAC, MFA и payments реализуются по [плану](docs/auth-plan.md) и [шагам](docs/auth-implementation.md). Результат переноса инфраструктуры: [template-adoption](docs/template-adoption.md).

## Локальный запуск

Нужны Task v3 (проверено на 3.53.1), Docker Engine с Compose v2 и Go версии из `go.mod` для host checks. Создайте `.env` из `.env.example`, затем `task dev:up`. API: `http://localhost:8080`, Mailpit: `http://localhost:8025`. PostgreSQL/Redis доступны только на localhost. Swagger: `/swagger/index.html`, Basic Auth из локальной конфигурации. Примерные пароли разрешены только для изолированной разработки.

`task dev:down` сохраняет named volumes. Новый профиль **не использует** прежний `out/pgdata`: старые данные не перенесены и не удалены. `deploy/docker-compose.yml` — legacy, не поддерживаемый профиль; используйте `deploy/compose.base.yml` + `.dev.yml`/`.prod.yml` через Task. Не запускайте два профиля с одинаковыми именами/портами.

Dev запускает Air `v1.67.4` через `.air.toml`: пересборка `./cmd/auth` при изменении Go/HTML, tests и временные каталоги исключены. `task dev:up` собирает dev-образ; `task dev:logs` показывает build/restart. Go caches и бинарник в `tmp` используют отдельные volumes. Изменения `.env`, `go.mod/go.sum` или конфигурации Air требуют явного restart через `task dev:down` → `task dev:up`; Air не загружает новое окружение приложения автоматически. Production Air не использует.

## Проверки

```sh
task check
task swagger # только после изменения HTTP API
```

Checks используют `.env.example`/`.env.prod.example`, не читают рабочие secrets. Integration создаёт уникальный `auth-check-*` Compose project с временными volumes и удаляет только его при выходе. Не заменяйте его конфигурацию рабочей `.env`. Docker image `auth:stage1` нужно пересобрать после изменений Go. При аварии Docker daemon сначала проверьте оставшиеся test projects, не удаляйте пользовательские volumes.

Команды сгруппированы как `dev:*`, `migrate:*`, `go:*`, `check:*`, `prod:*`; старые имена сохранены как aliases. `task go:build` собирает `bin/auth`. `task go:fmt` применяет закреплённые formatters; `task swagger` обновляет контракт. JSON endpoints требуют `Content-Type: application/json`, максимум 1 MiB, один JSON value, без неизвестных полей. Ошибки декодирования возвращают существующий `400 invalid_json`. Cookies/CSRF/security contract уточняется на этапах 4–6.

По умолчанию выполняйте только `task check` (tests + lint). `task check:security` и `task check:integration` нужны после обновления зависимостей либо перед релизом; не повторяйте их после каждой правки. В CI tests/lint, security и image build; race/integration не выполняются на каждый push. Осталось три shell-файла: backup, host restore и один acceptance runner.

## Конфигурация

Полные примеры — `.env.example` и `.env.prod.example`; источник runtime validation — `internal/app/config/config.go`. `APP_ENV=dev|test|prod`, `LOG_LEVEL` задаёт logger. `PORT`, `DATABASE_URL`, pool limits, `REDIS_HOST/PORT/PASSWORD` обязательны для startup. `SESSION_TTL`, **отдельный** `ABSOLUTE_SESSION_TTL` и `SESSION_REFRESH_THRESHOLD` должны быть согласованы. Reset URL берётся только из `PASSWORD_RESET_URL`, TTL — `PASSWORD_RESET_TOKEN_TTL`; публичный reset API пока выключен.

Код Auth расположен в `internal/modules/auth` по фичам; инфраструктура — в `internal/infra`, HTTP router — в `internal/transport/http`, DI/config — в `internal/app`. Карта переноса и правила добавления кода — в [архитектуре](docs/architecture.md). Рукописные Go/HTML-файлы, включая tests, ограничены 150 строками; лимит и основные границы зависимостей проверяет обычный `task check`.

`SMTP_HOST/PORT/USERNAME/PASSWORD/FROM/DOMAIN` задают mailer. В dev SMTP идёт в Mailpit. Production SMTP delivery, TLS/timeouts/outbox ещё требуют отдельной проверки. `SWAGGER_ENABLED=false` по умолчанию; при включении нужны credentials. В prod dev mail route отсутствует, reset URL требует HTTPS, Redis password — минимум 16 символов. Validation не заменяет secret provisioning и review.

Compose дополнительно использует `APP_NAME`, `POSTGRES_IMAGE/DB/USER/PASSWORD`, `MIGRATION_DATABASE_URL`, `BACKUP_INTERVAL`, `BACKUP_RETENTION_COUNT`, `RESTORE_HEALTHCHECK_SQL`. Migration URL закрепляет `search_path=public`: metadata не должна переезжать при создании одноимённой user/schema. Real `.env` файлы исключены из Git и Docker context. Другой env file: `task dev:up DEV_ENV=config/dev.env` или `task prod:up PROD_ENV=config/prod.env`; Taskfile сам задаёт одинаковый путь для Compose interpolation и API env_file.

## Production profile: подготовка, не разрешение на release

Создайте `.env.prod` из `.env.prod.example`, замените **все** placeholders на отдельные случайные owner/runtime/Redis/SMTP credentials. Пример не предназначен для deployment. Секреты не source/eval и не передавайте через публичные logs; env-based provisioning допустим только на доверенном Docker host, secret manager подключается в конкретном проекте.

До первого `prod:up`:

1. Запустите PostgreSQL через `docker compose` с production profile; вручную создайте `auth_runtime LOGIN` без superuser/createdb/createrole и задайте пароль через `psql \password auth_runtime` в защищённом operator shell. Пароль должен совпадать с `DATABASE_URL`; URL-encode специальные символы.
2. Выполните migrations от `auth_owner` через prod Compose `run --rm migrate up`.
3. `task db:runtime-grants`; проверьте DML от runtime и запрет DDL. SQL `deploy/runtime-grants.sql` содержит template identifiers `auth`, `auth_owner`, `auth_runtime`: при адаптации другого проекта измените их согласованно с env.
4. После закрытия auth security release gates: `task prod:up`. Сейчас это команда инфраструктуры, не подтверждение готовности приложения.

API — nonroot, readonly, cap drop, localhost port; PostgreSQL/Redis без host ports. Нужен отдельный TLS ingress. `sslmode=disable` в примере допустим только внутри доверенной Docker network на одном host; для внешней БД настройте проверяемый TLS. `/health/live` проверяет процесс, `/health/ready` — PostgreSQL и Redis с deadline, без details/DSN. Reverse-proxy headers не доверяются; trusted-proxy policy вводится отдельно.

## Backup / restore

`task backup` создаёт custom-format dump + SHA256 в выделенном `/backups` named volume. Retention по count, shared flock, atomic publication, archive preflight. Backup содержит PII: нужны off-site encrypted copies, доступ, retention и restore drills. SHA256 не является криптографическим подтверждением источника. Global DB roles/passwords не входят в dump, provision их отдельно.

Restore **пересоздаёт выбранную БД**. После проверки target/project/archive: `task restore FILE=backup_....dump CONFIRM=auth-prod:auth`. Wrapper проверяет точное подтверждение, берёт host mutex, проверяет archive, останавливает api/migrate/backup, сохраняет pre-restore archive, восстанавливает, применяет migrations и runtime grants, выполняет health SQL. API/backup включаются обратно только после успеха и только если работали ранее. При ошибке не запускайте writers до ручной проверки. При прерывании проверьте running one-off containers и mutex перед повтором; принудительное удаление stale mutex без проверки запрещено.

Для проверки используйте только `task check:integration`, не restore рабочей базы. Перед production release дополните список writers email/billing workers, согласуйте Redis/session invalidation после point-in-time restore и schema/access/payment health SQL (этап 14). Эти гарантии пока не реализованы.

## Копирование и обновления

Оригинальный go-template больше не нужен: выбранные решения находятся в этом репозитории. До production fork закройте план, затем меняйте module/import path, branding, env/project/DB identifiers, SQL grants, trusted URLs и продуктовые permission/feature keys отдельными проверяемыми изменениями. Сейчас module сохраняет старое имя `financial-intelligence` — rename запланирован отдельно.

Dependencies обновляются небольшими тематическими изменениями с tests/race/lint/vulnerability/container/Swagger checks; crypto — дополнительно старые hashes и resource limits. Не переносите чужой go.sum и не используйте безусловный `@latest` в release workflow. CI проверяет код и disposable infrastructure, **не выполняет deploy**. Secret scanning, container CVE/SBOM, live provider sandbox и полноценный security audit остаются release gates этапа 14.

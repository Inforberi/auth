# Развёртывание Auth

Здесь находятся только файлы развёртывания. Локальный HTTPS-стенд, проверки инфраструктуры и fake-Docker тесты — в `sandbox/`. Тестовые данные и реальные секреты в этот каталог не помещаются.

```text
deploy/
├── compose/       # base.yml + development.yml или production.yml
├── docker/        # Dockerfile.dev и Dockerfile.prod
├── postgres/
│   ├── grants/    # права технических SQL-ролей по назначению
│   ├── storage-target.sql
│   └── restore-auth-state.sql
├── examples/      # manifest методов входа и env подготовки проекта
└── scripts/       # production backup и guarded restore
```

Команды Task задают корень репозитория через `--project-directory`: пути mounts, build и env считаются от него, независимо от расположения Compose-файлов. Не запускайте отдельный override как самостоятельную конфигурацию. Подробности — [правила Docker Compose](https://docs.docker.com/compose/how-tos/multiple-compose-files/merge/).

## Конфигурация production

Два файла с разными полномочиями:

| Файл | Кто получает | Содержимое |
| --- | --- | --- |
| `.env.prod` из `.env.prod.example` | Compose, migrations и backup | имя deployment, owner/служебные параметры PostgreSQL, Redis, backup, host port и каталог API-файлов |
| `.env.prod.app` из `.env.prod.app.example` | только API | runtime DATABASE_URL, Redis, Auth/MFA/session settings и необходимые API-секреты |

Замените все placeholders; реальные `.env*` и вложенные `*.env` исключены из Git и Docker build context; example-файлы остаются доступны. Не добавляйте `POSTGRES_PASSWORD`, migration URL и provisioning credentials в API env. Redis password в обоих файлах должен совпадать. `PORT` задаётся Compose и передаётся API явно. APP_NAME и именованные volumes сохраняйте при обновлениях.

`POSTGRES_USER` в bundled PostgreSQL — bootstrap/owner учётная запись. Она не является пользователем API, супер-администратором Auth или администратором проекта. Migration URL задаётся явно: fallback к API DATABASE_URL отсутствует. Для API создаётся отдельный `auth_runtime LOGIN` без superuser/createdb/createrole; его пароль используется только в API `DATABASE_URL`.

Файлы, которые нужны API, размещаются в `AUTH_SECRETS_DIR` (по умолчанию `./secrets`) и доступны внутри контейнера как `/run/secrets/...` только для чтения. Каталог должен существовать: Compose не создаёт его автоматически. В него помещаются только необходимые API TLS/JWT/CA/config файлы, а не owner env или backup. Файлы и каталоги должны быть доступны UID/GID `65532:65532`; приватным ключам достаточно чтения владельцем. Env-файлы оставьте доступны только оператору хоста. Пути `HTTP_TLS_*`, `JWT_*_FILE`, `ACCESS_CATALOG_FILE` и project manifest задаются как пути внутри контейнера.

Можно использовать другие имена:

```sh
task prod:up PROD_ENV=config/compose.env PROD_APP_ENV=config/api.env
```

## Первый запуск

1. Подготовьте оба env и каталог API-файлов. Настройте доверенный HTTPS ingress либо прямые `HTTP_TLS_CERT_FILE=/run/secrets/tls.crt` и `HTTP_TLS_KEY_FILE=/run/secrets/tls.key`. API публикуется только на loopback; внешний ingress устанавливается отдельно.
2. Через base + production Compose запустите только PostgreSQL/Redis. Создайте ограниченный runtime LOGIN в operator shell, задайте пароль через `psql \password auth_runtime`. URL-encode пароль в API DATABASE_URL.
3. Примените `migrate up` от владельца схемы. Затем выполните `task db:runtime-grants` и проверьте доступ runtime без DDL. Только после этого запускайте API.
4. После закрытия security release gates выполните `task prod:up`. Проверьте `/health/ready` через доверенный HTTPS endpoint; `/health/live` подтверждает только жизнь процесса.

Для шагов 2–3 используйте `docker compose --project-directory . --env-file .env.prod -f deploy/compose/base.yml -f deploy/compose/production.yml`, передав `APP_ENV_FILE=.env.prod.app`, если меняете его имя. Настоящие env не загружаются через shell source/eval.

API запускается как nonroot, с read-only filesystem, снятыми capabilities и без privilege escalation. PostgreSQL/Redis не публикуют host ports. `sslmode=disable` допустим только внутри доверенной сети одного Docker host; для внешней БД нужен проверяемый TLS. Доверие к proxy ограничивается `HTTP_TRUSTED_PROXY_CIDRS`, CORS — явными origins, а не wildcard.

## SQL-права и восстановление

`postgres/grants` разделяет технические полномочия: API общей админки, private catalog reader, подготовка проектов и recovery. Эти grants не выдаются всем ролям разом и не имеют отношения к ролям пользователей Auth. `storage-target.sql` подготавливает отдельный физический target для независимых проектных БД.

Runtime grants Auth имеют один канонический источник: [schema/runtime-grants.sql](../internal/admin/projects/schema/runtime-grants.sql). Он встраивается Go-загрузчиком рядом со schema identity/checksum и используется установкой проектной БД. `task db:runtime-grants`, restore и test runner читают тот же файл; копии или symlink в deploy нет. SQL-миграции остаются в `migrations/auth` и `migrations/admin`.

`task backup` создаёт dump и checksum. `task restore FILE=archive.dump CONFIRM=project:database` проверяет цель и архив, останавливает API, восстанавливает БД, применяет миграции/права и инвалидирует старые credentials. API автоматически не запускается. [Recovery protocol](../docs/operations/jwt-recovery.md) остаётся обязательным; наличие backup не доказывает возможность безопасного fleet restore. Backup содержит пользовательские данные и требует контролируемого off-site хранения.

## Проверки и границы

`task check:integration` использует `sandbox/compose.check.yml` и `sandbox/check-infrastructure.sh`, только synthetic credentials и собственный disposable Compose project. Production env и volumes не участвуют. `TestProductionComposeSeparatesCredentials` проверяет resolved Compose model без запуска контейнеров: runtime/owner separation, read-only API mounts и закрытые SQL/Redis ports. Restore failure tests находятся в `sandbox/tests/security`.

Эта структура готовит deployment к production, но не закрывает [MP7/MP8](../docs/planning/multi-project.md#mp7-функциональная-и-security-приёмка), реальные провайдеры/SMTP/ingress, fleet restore или измерение нагрузки. UI отдельно согласовывается.

Для multi-project и onboarding требуется TLS также на участке ingress→API: эти маршруты проверяют реальное TLS-соединение (`r.TLS`), а не `X-Forwarded-Proto`. Используйте прямой TLS либо re-encryption с проверкой сертификата backend. Plaintext listener standalone/introspection допустим только в доверенной изолированной сети за HTTPS ingress; не публикуйте его наружу. HSTS задаётся на HTTPS ingress после проверки списка доменов, без автоматического preload/includeSubDomains.

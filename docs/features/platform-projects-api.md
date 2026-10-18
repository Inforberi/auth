# Чтение каталога из платформы — MP2.5-read / MP2.6

18 октября 2026. Подключены только две GET-ручки операторского профиля. Создание проекта, retry/suspend/resume, физические БД и cross-project bridge **не опубликованы**. [Operator login](platform-login.md), [каталог](project-catalog.md), [lifecycle](project-lifecycle.md).

## Доступ

Только `PLATFORM_ENABLED=true`, ожидаемый SQL realm и exact HTTPS Host платформы. Standalone/project router не публикует эти пути даже при переданном catalog handler. Публичная регистрация/проектная роль/JWT не становятся платформенной authority.

Нужны действующая host-only browser session и текущая SQL permission `platform.projects.read`. Наличие `platform.projects.manage` или Auth super-admin само по себе чтения не разрешает. Principal берётся из проверенного session context, не из query/body/произвольного header. Bearer JWT не заменяет cookie. Как и раньше, платформенный login требует password+MFA; согласованный optional режим остаётся задачей [A6.3m](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7), этим блоком guard не ослаблен.

Чтение не требует обновлять fresh password/MFA, не продлевает session/административную активность, не меняет cookie и не вызывает project storage/provider/SMTP probes. `NoRefreshAuth` → существующий `AuthorizeRead` → bounded catalog lookup. Проверка права некешируемая на каждый запрос. Это разрешение ограниченного чтения: уже авторизованный read может завершиться при конкурентном отзыве в пределах deadline. Оно не даёт mutation/bridge authority; будущая запись должна удерживать SQL guards до commit.

Если Origin присутствует, он обязан совпадать с платформенным; у безопасного GET без Origin сохранена существующая поддержка CLI. CORS остаётся выключенным. Все ответы `Cache-Control: no-store`, без Set-Cookie. Startup дополнительно проверяет уже предусмотренный template grant `SELECT ON platform.projects`; новых DB mutation grants/ENV/миграций нет.

## Список проектов

`GET /api/v1/platform/projects`

| Query | Контракт |
| --- | --- |
| limit | 1–100, по умолчанию50 |
| phase | Необязательный pending/provisioning/failed/ready; это подготовка, не health |
| before | Opaque `nextCursor` предыдущей страницы с тем же phase filter |

Порядок — `(createdAt,id)` descending, курсор exclusive. Нет offset/total count/substring search. Повторяющиеся и неизвестные query parameters, нечисловой limit, неправильный cursor/filter дают400. Cursor ограничен256characters, versioned/canonical base64url с timestamp/UUID/filter; это boundary страницы, не secret или право доступа. Подделанный cursor не меняет permission/realm, только допустимую границу выборки. Cursor UUID и resource bounds проверяет persistence, формат/каноничность — service, JSON/URI shape — transport, без дублирующей предметной валидации в HTTP.

Ответ: `{ "projects": [...], "nextCursor": "..." }`. Пустая страница — `projects:[]`, конец — пустой nextCursor. Оператор видит также pending/failed/suspended проекты. На страницу — bounded indexed catalog query, limit+1; нет N+1, COUNT или подключения к каждой project DB. Весь use case ограничен3s, SQL операции имеют собственный2s bound с учётом caller context. Middleware session check/SQL authority/catalog read — отдельные bounded операции, не обещание одного SQL round trip или capacity.

## Карточка проекта

`GET /api/v1/platform/projects/{id}`

UUID — canonical nonzero project ID; query параметры не принимаются. Ответ содержит ровно:

`id`, `slug`, `name`, `origin`, `desiredState`, `phase`, `version`, `generation`, `createdAt`, `updatedAt`.

Список использует тот же явный DTO. Нет storageTarget/databaseName/credentialRef/schemaVersion/DSN/password/key/secrets; binding не сериализуется автоматически. Phase ready не доказывает доступность или законченный пользовательский onboarding. Этот read не запускает подготовку и не меняет lifecycle.

## Ошибки и документация

- 400: `invalid_query` / `invalid_project`.
- 401: `unauthorized` для отсутствующей/недействительной сессии.
- 403: `forbidden` для отсутствующей platform permission; `invalid_origin` для чужого Origin.
- 404: `project_not_found` для неизвестного проекта после авторизации. Чужой Host получает нейтральный404 на границе operator router.
- 503: `temporarily_unavailable`, без raw driver errors, addresses/DSN или выдачи данных при отказе authority/storage.

Общий HTTP mapper используется с локальными правилами каталога; неизвестные ошибки безопасно логируются без err payload. Общая Swagger schema дополнена этими paths/DTO. Route contract tests отдельно проверяют operator profile и отсутствие platform routes у standalone; DTO сверены с generated schema. Встроенный Swagger UI на platform origin этим этапом не включён.

## Реализация и проверки

`project/service/{catalog,list,read}.go` — consumer ports и сценарии. List query/cursor/page types перенесены из PostgreSQL adapter к использующему их сценарию, без compatibility aliases или второго pagination engine; прежний SQL/keyset/bounds сохранены. `transport/http/{catalog,list_projects,read_project}.go` — отдельный файл каждой ручки, общий Handler/DTO/error mapper. Assembly использует тот же pool и существующий operator repository; новых connections/workers/clients нет.

Unit/HTTP/router tests проверяют auth-before-data, повторную проверку permission, cursor shape/filter, default/empty page, query ambiguity, actor mapping, DTO/error redaction, Host/Origin/TLS/no-refresh/CORS и standalone route absence. Реальный `TestOperatorProfileSQLHTTPS` расширен: restricted LOGIN, startup SELECT guard,3 synthetic projects/tied timestamps, exclusive pagination, phase filter, pending/failed/suspended card, invalid limit/cursor/UUID, no private binding, unchanged session SQL row/no cookies, permission revoke403 при всё ещё действующей Auth super-admin session, восстановление grant и reset session401. Полный предыдущий setup/password/MFA/reset/recovery regression сохранён.

Результаты/cleanup — [history](../planning/history.md#результат-mp25-read-api--18-октября-2026). Без opt-in ENV SQL fixture SKIP; unit race не является live SQL race. Real browser/ingress, two-realm/fleet/capacity/load/GC остаются NOT RUN. UI не начинался и требует отдельного согласования. Далее — MP2.5-write с текущей platform authority/fresh proofs/locks, intent creation и lifecycle mutations; только после соответствующих revoke/concurrency/audit tests.

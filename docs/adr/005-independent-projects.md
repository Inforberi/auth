# ADR 005: независимые проекты и общая административная платформа

Статус: принято как целевое решение MP1, 18 октября 2026. Runtime пока однопроектный. [План MP1–MP8](../planning/multi-project.md), [базовая SQL authority](002-sessions-and-transactions.md). Заменяет single-deployment часть ADR001 для многопроектного профиля; SSO/OAuth server не вводится. Пользователь отдельно выбрал одну сессию оператора для управления пользователями/ролями/настройками всех проектов.

## 1. Области данных и идентификаторы

- Платформенная БД: каталог проектов, независимые operator accounts/session/MFA, platform permissions и audit/операции управления. Для операторов переиспользовать Auth механизмы в отдельной сборке/области, не второй password/MFA стек. Публичная регистрация и внешние primary methods панели в минимальном профиле выключены.
- Каждому проекту — отдельная БД с одинаковой схемой `auth`, своими accounts/roles/settings/session/refresh/outbox/audit. Не создавать схему с именем проекта в общей БД и не добавлять project_id во все существующие feature tables вместо отдельной БД.
- Неизменяемый project UUID — identity каталога/namespace; публичный slug — неизменяемая в первом профиле DNS-safe привязка; display name редактируется независимо. Переименование не меняет имя БД, origin, issuer или callback. Same email/UUID в разных БД не означает одного пользователя.
- Целевой origin: `https://<slug>.<auth-domain>`; панель имеет отдельно зарегистрированный origin. DNS/TLS и trusted storage targets настраивает оператор. В UI название не превращается в произвольный URL/SQL identifier. Автоматизация custom domains/cloud servers отложена.

## 2. Разрешение запроса и доступность

1. Process-wide HTTP admission/deadline, trusted proxy/IP и безопасная нормализация authority. Однозначный exact host/port binding из каталога; никаких project headers, извлечения DSN из JWT или wildcard fallback к первому проекту.
2. Одна ограниченная индексная проверка актуальной привязки/ready/desired state и runtime generation в платформенной БД. Публичный неизвестный/неподготовленный/приостановленный project origin получает одинаковый нейтральный404, dependency failure —503. Platform API показывает реальную стадию только оператору с правами. Операционные health endpoints не раскрывают каталог.
3. Lease проектного runtime, сформированного по ID/generation/ссылке на credential. Проверка identity хранилища при открытии не позволяет каталожной ошибке или rebinding направить проект в БД соседа. Generation входит в cache key; при смене binding старые owners дренируются, не переключаются в месте.
4. Существующие project routes и SQL authority. Host выбирает область, но не аутентифицирует клиента. Неизвестный либо чужой session/JWT/service credential отклоняется внутри ожидаемой области.

Положительный результат проверки статуса не кешировать в минимальном профиле. Cache runtime/pool не даёт разрешения обслуживать отключённый проект. Suspension закрывает новые admission после commit каталога; уже допущенные операции могут завершиться в пределах timeout, не обещается мгновенный rollback произвольных in-flight transactions. Новый callback/refresh/login проходит новое admission. Local JWT у внешнего consumer сохраняет явно согласованное окно до expiry; suspension не превращает offline verification в online отзыв. Strict authority должна проверять текущий проектный статус, а consumer URL/issuer остаются fixed trusted config.

Platform catalog/Redis — общие зависимости: при их отказе соответствующие защищённые сценарии fail-closed, без cached authorization/безлимитного SQL fallback. Общий `/health/ready` не обходит все project DB; проверяет необходимые platform dependencies. Отказ одной проектной БД даёт проектный503 и диагностическое состояние, не автоматически общую not-ready для всех. Pool opening не выполняется для каждого HTTP request.

## 3. Одна сессия оператора, без пользовательского SSO

Оператор входит на platform origin, проходит MFA/fresh proof и управляет любым разрешённым проектом через platform endpoints с явно указанным target ID. Пользовательский project origin не принимает платформенную cookie/Bearer и не создаёт project session для оператора. Project super-admin не получает platform rights. Cookie `__Host-session` может иметь прежнее имя на разных origins: Domain не задаётся, Path=/, HTTPS; Origin/CORS/CSRF policy остаётся exact и project-specific.

Platform management — отдельный доверенный сценарий, не HTTP proxy к произвольному URL/path и не вызов обычного project handler с подменённым UserID. Для users/access/settings определить отдельные platform permissions и конечное соответствие конкретным use cases. Platform actor не становится синтетическим пользователем проекта. Membership/delegation проверки обычного проектного администратора не заменяются `skipAuth=true`.

Минимальный контракт bridge для MP2/MP5:

1. Проверить текущую platform session/actor/permission/fresh password/MFA и конкретный target. Сохранить ограниченную idempotent запись намерения/operation ID в platform audit; повтор не означает автоматическое разрешение новой операции.
2. Перед проектной мутацией повторно получить блокирующий SQL guard платформенной authority. Guard удерживается до результата project commit/rollback с общим bounded deadline; изменения actor/session/factor/permissions должны конфликтовать с теми же guards. Точный lock protocol и race tests обязательны до публикации bridge. Порядок только platform authority → project Access/user/session locks, без обратного ожидания. Это два SQL соединения, учтённые в budget, не распределённая транзакция.
3. Выполнить конкретный project use case с отдельным типизированным PlatformActor; сохранить target version/last-admin/system-role/domain/consumption guards. Разрешение platform actor не выводится из его отсутствующих project roles. Schema аудита должна поддержать origin actor без FK на несуществующего project user.
4. Результат, audit с platform actor/target/operation ID и receipt/idempotency фиксируются атомарно с мутацией в project DB. Затем platform operation отмечается завершённой. Если project commit прошёл, а ответ/финальный platform update потерян, результат восстанавливается по receipt, а не повторной выдачей пароля/приглашения. Общий атомарный commit двух БД не обещается; состояние outcome_unknown не трактуется как rollback. Не добавлять broker или универсальный workflow engine.

Нельзя переносить этот путь на обычные пользовательские login endpoints. До доказанных SQL guards/audit/retry контрактов bridge закрыт, даже если каталог уже работает. Это осознанно необходимое отличие от простого создания БД; не маскировать разрыв authority между двумя хранилищами in-memory context или подписанным долгоживущим ticket.

## 4. Проверенные владельцы и минимальное изменение границ

| Область сейчас | Проверенный источник | Целевой owner / изменение |
| --- | --- | --- |
| Вход процесса, config, App.Run | `cmd/auth/main.go`, `internal/config/config.go` | Process owns config/logger/server/shared ceilings; не запускать отдельный listener для каждого проекта |
| SQL/Redis/logger lifecycle | `internal/app/auth/run.go`: resources.open/close | Один stdlog redirect и shared Redis clients; отдельные ограниченные SQL pools/runtime, отдельный pool каталога |
| Сборка всех фич | `internal/app/auth/app.go`: New | Разделить opening process resources и сборку project handlers/services; не вызывать полный New N раз |
| Hash concurrency | app.go: hasher.NewBounded | Один общий bounded hasher/process + project admission, иначе N runtimes умножают hash memory slots |
| HTTP admission/health | `internal/transport/http/router/router.go`: New | Общий admission до выбора проекта; project router не заменяет общий потолок и не создаёт N global probes |
| Access/Auth/provider/SMTP/retention settings | `internal/app/auth/{settings,provider_settings,smtp}.go` | Проектный pool и immutable snapshot/runtime capability; не мутировать shared config и не seed всех одним deployment secret |
| Session и native refresh | app.go: sessionpostgres.New, token.go | SQL project authority сохраняется; Redis session adapter существует, но не включён App как authority/cache |
| Redis limits/flows | account/mfa/password/settings/token `repository/redis`, app/auth/oidc.go | Везде namespace с immutable realm ID и purpose; email OTP использует password Redis adapter, отдельного OTP Redis repo нет |
| JWT/client manifests | `internal/app/auth/token.go`: assembleTokens | Project issuer/key/resource/consumer source; bounded shared no-retry Redis client при совместимой policy, не отдельный8-connection pool каждому runtime |
| Key/payload isolation | `internal/infra/secretbox/cipher.go`: NewScoped/Seal/Open | Отдельный project key, project+purpose+version context; текущая AAD — purpose, поэтому нужна явная миграция, не молчаливая замена scope |
| OIDC clients/письма/MFA | `internal/app/auth/{oidc,mfa,email_otp,smtp}.go` | Project credentials/cipher/URLs, context cancel и transport ownership; без fallback на соседа |
| Background и shutdown | run.go: serveAuth/startBackground/runWithDelivery | Server lifecycle отдельно, bounded fair project jobs с cancel/join; outbox живёт и без HTTP traffic |
| Схема | `migrations/000001_init.up.sql` | Существующие таблицы schema auth; каталог — отдельные миграции, project schema versions/grants отдельно |

Это targeted source audit, не нагрузочная/SQL/fleet проверка. Redis session legacy files не подключать ради симметрии; сначала определить их реальных consumers при затронутом рефакторинге. В токен-лимитах есть literal `project` key и статические hash tags: tenant ID требуется в полном ключе/hash-tag контракте, а не только в digest client ID. Автоматическую Redis Cluster поддержку этим ADR не объявлять.

Минимальные новые владельцы: platform/project management feature (`domain/service/repository/transport` по существующему стилю), process assembly в `internal/app`, project runtime registry с lease и bounded lifecycle. Точные имена файлов определяются реальной операцией в MP2/MP4; сейчас пустые пакеты не создаются. Existing Auth/access feature tree сохраняется.

## 5. Конфигурация, secrets и версии

Operational config: platform DB, root wrapping key, trusted target credentials references, HTTP/TLS/proxy/egress и общие ресурсы. Проектные данные: connection secret reference, catalog/issuer/keys/consumer definitions, provider/SMTP secrets, login policy/roles/MFA/session settings. ENV остаётся источником operational ceilings/первого bootstrap, не шаблоном credentials всех создаваемых проектов.

DB create/migrate выполняет отдельный executor с минимально необходимыми привилегиями. Normal platform API/project runtime не получают CREATE DATABASE/роль владельца. Идентичность существующего storage подтверждается marker/ownership/version в согласованной migration, не названием БД. Root key не хранится с ciphertext; проектные secrets хранятся envelope с realm/purpose/version, frontend их обратно не получает.

Разделить версии: catalog schema, project schema, persisted settings и runtime generation. При реализации каждого migration шаг объявляет поддерживаемый диапазон code/schema; dirty/unknown/incompatible schema отклоняется до обработки Auth. Точные номера будущих миграций/ENV не выдумывать в ADR: сейчас в checkout только000001; добавить миграцию/controlled upgrade при изменении применённой схемы, не переписывать её задним числом и не reset существующий sandbox.

## 6. Перенос текущей установки в первый проект

1. На разрешённом стенде сделать inventory текущей schema/ключей/URL/pending jobs и проверенный backup/restore dry-run. Существующая БД остаётся Auth первого проекта; operator realm создаётся отдельно, аккаунты не импортируются в platform realm автоматически.
2. Под maintenance остановить все writers/issuance и delivery leases, создать catalog entry с новым неизменяемым project ID, проверить storage ownership, schema compatibility/grants и зарегистрированный origin. Это operator процедура, не публичный «подключить любой DSN».
3. Сохранить users/password hashes/status/auth/access versions, custom/system roles, settings, TOTP seeds и recovery state. Не сбрасывать MFA ради новой панели. Первый platform owner проходит отдельный protected bootstrap/recovery.
4. Контролируемо перевыпустить connection/key bindings, перенести encrypted persistent secrets/outbox на project-scoped key/context: decrypt старым purpose → seal новым context → verify в безопасном migration tool, без plaintext в логах. Old key нужен только на время этого согласованного шага; бессрочный fallback на любой legacy scope запрещён. Durable security notifications не удалять как «временные данные».
5. Консервативный cutover — явно отозвать старые cookie/native/refresh authority и одноразовые pending flows; новые URL/issuer/namespace не должны интерпретировать старые tokens как глобальные. Existing local-only JWT не исчезают при SQL revoke: остановка issuance, key/consumer trust switch и/или expiry-drain с подтверждением consumers перед открытием traffic. Redis flow drain по прежнему runbook, без FLUSHDB.
6. Настроить origin/callback/email URLs и consumer trust для первого проекта; проверить ordinary login/MFA/admin/recovery/outbox/revoke и невозможность попасть в platform realm. Только затем ready/traffic. Старый URL допустим как зарегистрированный origin первого проекта при соблюдении отдельного platform origin; автоматический redirect POST/token callback не делать.
7. До открытия traffic возможен rollback deployment с writers fence. После новых writes нельзя просто вернуть старый backup/config: отдельная reconciliation/план fail-forward. Перенос не исполняется в MP1 и не разрешает операции с рабочей БД автоматически.

## 7. Проверки следующих подэтапов и ограничения

Перед любым публичным multi-project flow обязательны host/credential confusion tests, platform/project actor separation, одинаковые UUID/kid, settings/secrets mix-up, catalog failure/disable race, duplicate provisioning/ownership collision и compatible upgrade. Для admin bridge — revoke actor/session/factor/permission при конкурирующей project mutation, lock ordering/timeouts, project audit/receipt commit и lost-final-platform-update recovery. Нет этих проверок — bridge не публикуется.

Длительные resource/max-RPS проверки — MP8 после реализации. Обычные formatter/task check/targeted SQL/Redis/race — по фактическим изменениям. В MP1 изменена только документация: diff/ссылки/согласованность; Go/Docker/network/providers/credentials/БД не запускать для формальности. Ни гарантии multi-project, ни cross-DB locking пока не реализованы и не измерены.

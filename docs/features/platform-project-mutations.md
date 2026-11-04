# Управление состоянием проектов — MP2.5-write-lifecycle

19 октября 2026. Здесь описаны suspend/resume/retry в operator profile. Отдельно подключено [создание catalog intent](platform-project-creation.md); физические БД/executor/runtime dispatcher и cross-project bridge пока отсутствуют. [Чтение каталога](platform-projects-api.md), [матрица состояний](project-lifecycle.md), [оператор](platform-operators.md).

## Ручки и запрос

| POST | Решение в каталоге |
| --- | --- |
| `/api/v1/platform/projects/{id}/suspend` | enabled → suspended; подготовка и данные сохраняются |
| `/api/v1/platform/projects/{id}/resume` | suspended → enabled; phase не меняется, ready не подготавливается заново |
| `/api/v1/platform/projects/{id}/retry` | enabled/failed → enabled/pending; suspended сначала нужно возобновить |

Только точный HTTPS Host платформы, точный обязательный Origin и её host-only session cookie. Standalone этих ручек не публикует; JWT/project administrator не заменяют платформенную сессию. Query parameters запрещены. JSON имеет один общий контракт:

```json
{
  "operationId": "55555555-5555-4555-8555-555555555555",
  "expectedVersion": 3,
  "expectedGeneration": 3,
  "reason": "incident-123"
}
```

UUID — canonical/nonzero; версии положительные. Reason — безопасная причина/incident reference, UTF-8 1–500bytes без controls/внешних пробелов, не место для секретов. Actor и action не принимаются из body: actor задаёт проверенный session context, action — отдельная ручка. Transport проверяет JSON/query форму; domain проверяет команду один раз в существующем persistence transition, после authority.

Ответ200 содержит только `projectId`, `desiredState`, `phase`, `version`, `generation`, `replayed`. Это **committed receipt**, не текущая карточка проекта. Взять новые metadata можно отдельным GET при наличии `platform.projects.read`.

Первый успех увеличивает version/generation ровно на1 и сохраняет audit. Точный повтор с тем же project/operation/actor/action/reason/expected revisions возвращает прежний outcome и `replayed:true`, даже если состояние уже изменилось следующей командой. Другой payload под тем же operation UUID даёт409. Перед любым replay повторно проверяются текущие права и fresh proofs; потеря права не открывает старый receipt. Operation UUID уникален внутри проекта, а не всей платформы.

## Authority и транзакция

Требуется **`platform.projects.manage`**; `platform.projects.read` и одноимённое Auth permission сами запись не разрешают. Успешный login не является бессрочным разрешением управления. SQL проверяет expected initialized realm, active/nondeleted user, current auth_version/role revision bindings, browser/password profile, живую session, существующие password/TOTP credentials и proofs не из будущего.

Primary password proof должен быть моложе `SESSION_FRESH_AUTH_TTL` (существующая настройка1–15min, default5min), MFA proof — моложе5min, как в текущих административных guards. После истечения нужно существующее POST `/api/v1/auth/reauthenticate/password` и/или `/api/v1/auth/mfa/step-up`, без повторного setup. Настраиваемая required/optional MFA остаётся [A6.3m](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7); этот блок не публикует optional режим и не ослабляет текущую политику.

`NewManaged` получает существующий SQL pool/operator repository и fresh TTL из конфигурации. Сценарий использует одну Read Committed transaction с общим3s deadline:

1. Existing shared Access snapshot lock, исключающий штатные изменения ролей/назначений до commit.
2. Shared row locks initialized realm → active user → точная platform permission.
3. Current role-bound session/password/TOTP rows под shared locks; вычисляется ближайший deadline session/password/MFA.
4. Existing project `Transition`: project row lock → receipt lookup → version/domain rules → атомарные UPDATE+audit.
5. Повторная SQL clock-проверка deadline после ожидания project lock и перед commit. При expiry откатываются также audit/state. Только успешный commit позволяет вернуть receipt.

Shared authority locks позволяют одновременные команды разным проектам и конфликтуют с отзывом permission/session, изменением user auth_version/password/MFA. Кто первым взял нужную блокировку, тот линеаризует действие/отзыв; возврат revoke означает, что более поздняя команда/replay уже не получит authority. Доверенные DBA/manual SQL обязаны соблюдать документированный порядок при изменении ролей: advisory lock не блокирует произвольный обход протокола DBA.

Отмена/ошибка приводит к rollback с отдельным bounded cleanup context1s. Если ответ потерян после успешного commit, повторять **тот же** operation UUID/payload, не создавать новый. Нет автоматических SQL retries, новых соединений/workers/очередей или полного сканирования таблиц. Authority требует нескольких indexed round trips только в административном write path; это не оптимизация публичного login и не измерение capacity.

## Grants и ошибки

[Runtime template](../../deploy/postgres/grants/platform-runtime-grants.sql) содержит необходимые column UPDATE для lifecycle, SELECT/column INSERT для append-only `project_events`; timestamp события задаётся БД. UPDATE(permission_key) нужен PostgreSQL для row-locking SELECT, не является новым endpoint делегирования. Ограниченный project INSERT теперь добавлен только для [creation intent](platform-project-creation.md#схема-и-grants); нет project DELETE, binding/schema rewrite, event UPDATE/DELETE/TRUNCATE, CREATEDB/DDL или executor credential. CheckRuntime отвергает неполные/избыточные grants до assembly.

Для установленной платформы нужен отдельно контролируемый grants upgrade; новый код со старым набором fail-closed не запустится. Никакие реальные grants/ENV/secrets не менялись, новых ENV/dependencies/schema/migrations этим блоком нет.

Ошибки:400 invalid_json/invalid_query/invalid_project;401 unauthorized;403 forbidden/invalid_origin;404 project_not_found после authority;409 project_conflict/invalid_transition;428 fresh_auth_required;503 temporarily_unavailable. SQL error text/credentials не возвращаются и не передаются в log payload. Все ответы no-store, без session refresh, activity update или Set-Cookie.

**Важно:** запись suspended в каталог пока не останавливает произвольный уже работающий backend. Enforcement admission/generation leases появится с MP4; создание БД/finish readiness — только trusted executor MP3. Клиентских begin/fail/finish API нет. Retry сейчас сохраняет намерение pending, не запускает ещё отсутствующий executor. Не выдавать этот блок за готовую multi-project эксплуатацию.

## Проверки

Unit/HTTP/router/Swagger: actor/action/DTO mapping, JSON/query bounds, Origin/Host/TLS/session/no-refresh/standalone isolation и sanitized errors. SQL/Redis/local TLS: настоящий setup+password/MFA login, restricted runtime grants, все3 команды, original receipt после последующих изменений, stale version/payload/state conflicts, current permission revoke перед replay, stale proofs428, unchanged session/no cookie, atomic audit failure rollback. Проверены фактическое ожидание revoke/user/session/password/MFA/Access locks, независимость двух проектов и rollback при MFA expiry во время ожидания project lock.

В конкурентном fixture обнаружено изменение общего pgx Config после открытия административного пула; runtime теперь получает отдельный `Config.Copy()`. Ошибка исправлена в тестовой инфраструктуре, production grants ради теста не расширялись.

Команды/результаты/cleanup/NOT RUN — [history](../planning/history.md#результат-mp25-write-lifecycle--19-октября-2026). Общий race-прогон без opt-in ENV не является SQL-race acceptance. External browser/ingress/SMTP, two-realm/fleet, bridge/provisioning/load/GC/capacity этим блоком не проверены. UI не начинался.

## Связь с двумя runtime — MP5-lifecycle-fault

Принят отдельный [двухпроектный сценарий](../planning/multi-project.md#жизненный-цикл-и-восстановление-зависимостей--mp5-lifecycle-fault): Luna V1 Go tests/оба actual SQL race roots и V2 targeted lint PASS, штатный cleanup/manifest11 подтверждены. Реальные HTTP handlers/production middleware/SQL managed authority связывают suspend/resume/replay с runtime registry observer и доступом к двум физическим БД. Operator proof задаётся SQL fixture, full router/setup/login остаются отдельной принятой приёмкой. Старые исторические ограничения «runtime отсутствует» выше относятся к MP2.5, не к текущей реализации.

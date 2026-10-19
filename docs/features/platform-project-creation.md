# Создание проекта в каталоге — MP2.5-create

19 октября 2026. `POST /api/v1/platform/projects` сохраняет **намерение создать проект**: enabled/pending, version/generation1, без физической БД, ключей, пользователей и runtime. Это не готовый проект для входа. [Оператор](platform-operators.md), [чтение](platform-projects-api.md), [управление состоянием](platform-project-mutations.md).

Добавлен отдельный [внутренний port резервации подготовки](project-preparation.md), но API его автоматически не запускает. Исполняемый storage executor/DDL ещё не подключены; создание metadata не стало синхронным ожиданием подготовки.

## Конфигурация и запрос

Только operator profile, точный platform HTTPS Host/Origin, host-only browser session и current `platform.projects.manage`. Перед replay также необходимы текущие права/fresh password и MFA по существующему [write-контракту](platform-project-mutations.md#authority-и-транзакция). Standalone/JWT/project role не дают доступа.

Новые operational ENV, обязательные для включённого operator profile:

| ENV | Значение |
| --- | --- |
| `PLATFORM_PROJECT_AUTH_DOMAIN` | Канонический DNS-домен, например `auth.example.com`; без scheme/port/path/wildcard/IP |
| `PLATFORM_STORAGE_TARGET` | Один доверенный идентификатор хранилища, default `primary`; не host/DSN/credential |

DNS/TLS настраивает оператор отдельно. Target пока только сохраняется в каталоге: executor MP3 должен связать его с заранее разрешённым подключением. Его credential этому API не передаётся. В ENV-примерах platform остаётся выключенной, реальные ENV/secrets не менялись.

```json
{
  "operationId": "80000000-0000-4000-8000-000000000001",
  "slug": "shop",
  "name": "Магазин",
  "reason": "project-onboarding-123"
}
```

Origin вычисляется сервером как `https://<slug>.<PLATFORM_PROJECT_AUTH_DOMAIN>`, не может совпадать с platform origin. Custom domains/порты через API не принимаются. Slug неизменяемый DNS-safe1–63bytes с существующим reserved list. Name нормализуется один раз trim, UTF-8 1–200bytes без controls. Reason —1–500bytes без controls/внешних пробелов; не включать секреты. Operation UUID — canonical/nonzero, глобально уникален **в каталоге создания этой платформы**, в отличие от project-scoped UUID последующих lifecycle команд.

Actor/UUID проекта/target/БД/phase/version/origin/credentials не принимаются из body; query parameters запрещены. Project UUID генерирует PostgreSQL, а не имя проекта или клиент. Предметные правила применяются domain один раз после SQL authority, HTTP проверяет только форму JSON/query.

## Ответ и повторы

Первый успех —201, `{ "project": <ProjectResponse>, "replayed": false }`; committed повтор —200 с `replayed:true`. `Location` содержит относительный путь карточки `/api/v1/platform/projects/{id}`, не redirect на ещё не работающий origin. ProjectResponse имеет те же10 безопасных полей, что [read API](platform-projects-api.md#карточка-проекта); storage target/credentials не возвращаются. Все ответы no-store, без Set-Cookie/session refresh/activity update.

`platform.project_creations` — одна append-only запись **одновременно аудита и receipt**: operation UUID, project UUID, actor, normalized name/slug/reason, исходные origin/target/time. Отдельной очереди/job engine нет. Точный повтор сравнивает actor и нормализованный клиентский payload, возвращает исходный UUID и enabled/pending/v1 snapshot, не текущую карточку. Поэтому после suspend/provisioning/будущего rename повтор не сбрасывает состояние; изменение deployment domain/target тоже не переопределяет уже принятое намерение. Новый запрос использует текущую конфигурацию.

Тот же operation UUID с другим actor/slug/name/reason —409 project_conflict. Другой UUID с занятым slug/origin —409. После потери ответа повторять прежний UUID/payload; не создавать новый UUID для того же намерения. Удалять receipt и разрешать повторное применение пока нельзя: retention/horizon остаётся MP6, автоматическая Auth180d очистка его не затрагивает.

## Транзакция и ограничения

Используется тот же caller-owned pool и общий private `mutate` для создания/lifecycle: Read Committed,3s total, shared platform authority locks/fresh proofs до commit, отдельный rollback cleanup1s. После authority и domain normalization берётся transaction-level advisory lock от operation UUID, затем indexed receipt lookup в **новом statement snapshot**. Lock освобождается с commit/rollback; нет глобального creation mutex. Теоретическая hash collision только временно сериализует разные операции и не считается совпадением receipt.

При отсутствии receipt один data-modifying CTE вставляет project с SQL defaults и snapshot audit через RETURNING. Любая ошибка аудита/уникальности откатывает обе записи. Параллельные одинаковые operation UUID получают один project UUID/receipt; разные операции на один slug разрешает unique index, без лишних committed рядов. Перед commit общий guard ещё раз сверяет proof/session deadline после любых ожиданий. Нет автоматических SQL retries, фоновых goroutines/новых пулов/соединений к target и необязательных probes.

Ошибки:400 invalid_json/invalid_query/invalid_project;401 unauthorized;403 forbidden/invalid_origin;409 project_conflict;428 fresh_auth_required;503 temporarily_unavailable. Raw SQL/constraint/DSN/credential details не публикуются и не добавляются в error log payload. Для200/201 создаётся только metadata; создание БД не маскируется под синхронный успех.

## Схема и grants

По согласованному правилу добавлена таблица в **исходную** platform000001, без новой migration; down удаляет receipt до projects. Для ранее установленной platform DB требуется отдельно согласованный forward upgrade и новые grants/ENV; изменение исходного SQL не обновит старую БД. Не повторять initial migration/down/reset рабочей установки. Сама рабочая Auth БД не менялась.

[Runtime template](../../deploy/platform-runtime-grants.sql) добавляет только INSERT(id,slug,name,origin,storage_target) projects и SELECT/INSERT project_creations. State/version/time/binding задают SQL defaults, runtime не получает INSERT этих колонок. Receipt UPDATE/DELETE/TRUNCATE запрещены; CheckRuntime отвергает missing/excess grants до запуска. Нет CREATEDB/DDL/owner/executor credentials. Schema/audit table не связаны FK с Auth user, сохраняя независимый порядок platform migrations; project_id FK и уникальность защищены БД.

## Проверки и оставшееся

Domain/config/HTTP/Swagger/router/unit/race проверены. Реальный restricted PostgreSQL18.6 + Redis8.2.6/local TLS:201 creation, generated origin/UUID/defaults, safe DTO,200 original replay после suspend, payload/slug conflicts, current revoke403/stale proof428, audit failure без orphan project, concurrent one-operation и same-slug winners, bounded cancellation на operation lock, независимая другая операция, retry после cancellation и replay после изменения доверенной domain/target конфигурации. Existing read/lifecycle/Auth/recovery service regression сохранён. Подробности — [history](../planning/history.md#результат-mp25-create--19-октября-2026).

Нет реального DNS/TLS onboarding, physical provisioning/keys/admin setup, project runtime/admission/fleet/bridge. Capacity/load/GC и внешний browser/SMTP/ingress — NOT RUN. Следующий функциональный блок — MP3 trusted target/provisioning executor; MP2.7 межбазовое управление остаётся отдельным незавершённым контрактом. UI не начинался и требует отдельного согласования.

# Refresh storage — J4a-local

17 октября 2026: J4a-local реализует storage/profile foundation, J4b.1-local — transaction-owned refresh, J4b.2a — [первую password API issuance](native-issuance.md), J4b.2b.1 — [native MFA/enrollment](native-mfa.md), J4b.2b.2 — [email OTP binding](native-email-otp.md). **Это ещё не публичный native login/refresh API.** App/HTTP admission/error/transport contract остаётся открытым. `JWT_ENABLED` по-прежнему публикует только существующий [cookie session exchange](jwt-exchange.md), не native-профиль.

## Владельцы и границы

| Код | Назначение |
| --- | --- |
| `token/domain/refresh.go` | Canonical 32-byte opaque credential → SHA-256 verifier, family/result, предел поколений и интервал |
| `token/service/refresh_family.go` | Server-owned creation params/shape bounds, не HTTP DTO и не доказательство полномочий |
| `token/service/refresh.go` | Admission/budgets, генерация successor, current scope intersection и выдача raw только после repository commit |
| `token/repository/postgres/refresh.go` | Transaction owner, повторная проверка budget hint, committed replay denial, signing/issuance audit/commit |
| `token/repository/postgres/refresh_authorization.go` | Общие session guards, current grants и допустимый idle renew |
| `token/repository/postgres/refresh_family.go` | Создание family + первого verifier + audit в переданной transaction |
| `token/repository/postgres/refresh_lock.go` | Indexed lookup и порядок user/session/family/verifier locks |
| `token/repository/postgres/refresh_rotate.go` | Consume/successor/reuse writes в той же transaction |
| `account/repository/postgres/{retention,transient_cleanup}.go` | Existing bounded cleanup без нового worker |

SQL primitives принимают `pgx.Tx` только внутри repository слоя. Их нельзя вызывать из HTTP или передавать transaction в business service. `Repository.Refresh` владеет refresh transaction; `Repository.IssueNative` создаёт первую API session/family от server-owned password/email OTP proof без MFA requirement. Полный native primary/MFA transport ещё не подключён. Storage primitives сами не коммитят, не подписывают JWT и не возвращают raw secret.

## Профиль ledger

`auth.sessions.credential_profile` — immutable `browser` (default) либо `api`. API row требует primary_verified_at, но **наличие timestamp не заменяет реальную проверку primary/MFA coordinator**. Profile нельзя перевести UPDATE из browser в api или обратно. Существующие browser constructors неизменны; внутренний IssueNative создаёт API row только после текущих password/reference/policy/version guards, при MFA requirement отказывает. App/native HTTP ещё не подключены.

Cookie lookup/renew/rotate/password reauthentication/activity/management-caller и cookie JWT exchange требуют browser profile. Даже знание API ledger verifier не даёт cookie authentication или activity renew. Browser owner может перечислять/отзывать собственные sessions разных профилей через общий ledger; API verifier не становится browser management principal. Reset/logout-all/block/delete/auth_version/role-binding invalidation остаются общими, не второй user/session store.

Ledger verifier и refresh verifier — разные credentials: creation/rotation отвергают подстановку ledger hash как refresh hash. Будущий native login не должен отдавать raw ledger secret, а refresh secret генерирует существующий криптографический generator. Parser принимает только canonical base64url 43 chars/32 bytes: не JWT, padded value, Bearer header или caller-selected UUID.

## Хранение и порядок

Одна family на API session, immutable audience/maximum sorted scope/idle policy/absolute deadline. Idle policy при creation ограничивается исходным session lifetime и оставшимся absolute window (округление вниз); native creation owner дополнительно ограничит её deployment policy. Scope keys при первой выдаче должны быть проверены по catalog/current grants, одна shape validation этого не делает. При refresh уже проверяются текущие grants и deployment resource allowlist, family не расширяется.

`auth.refresh_tokens`: только verifier, session UUID, generation, immutable family deadline и used_at; raw secrets/ciphertext нет. Composite FK связывает deadline с family. Partial unique index допускает максимум один current verifier, UNIQUE(session,generation) — один successor поколения. `auth.refresh_audit` хранит UUID/event/generation/time без verifier/token/IP/email; events family_created/rotated/reuse_detected, indexed existing security retention.

Owner использует Read Committed, bounded overall context и Access shared snapshot **до** user/session locks. Primitive делает indexed verifier lookup → user SHARE → session UPDATE → family/verifier UPDATE. После ожидания session lock отдельный statement видит committed consume. Family status/deadline и current token generation загружаются из SQL, не из клиентского тела.

| Ситуация | Storage outcome |
| --- | --- |
| Неизвестный/malformed verifier | Invalid refresh, без отзыва чужих sessions и без audit write |
| Current verifier, active/current-version/role-bound live API session | Consume old → insert один successor → generation/last rotation → audit |
| Повтор уже spent verifier в открытом detection window | Revoke family + соответствующей API session + audit; result.Reused=true, **не error** |
| Закрытая/expired family | Invalid refresh, без возрождения |
| Current session blocked/revoked/version mismatch/invalid role binding | Invalid refresh, без successor |
| Меньше 30s после успешной rotation | ErrRefreshEarly, без consume/revoke; spent replay всё равно проверяется раньше |
| 4096 credentials/family (generation 0..4095) | ErrRefreshLimit, нужен новый login, без продления старой family |
| Ошибка SQL/audit/подписи будущего owner | Rollback, старый verifier не должен быть consumed |

Первая rotation поколения 0 может выполняться сразу: первоначальная выдача не считается rotation; затем между успешными rotations ≥30s. Cap проверяется до throttle. Нет retry grace/второго successor: два concurrent запроса дают один successor, затем replay второго отзывает family; потерянный ответ требует нового входа. Client single-flight обязателен.

**Reused — решение, которое owner обязан commit до HTTP 401.** Возврат обычной ошибки в transaction helper откатил бы security mutation. `Repository.Refresh` выполняет commit и только затем возвращает ErrInvalidRefresh. При ошибке commit/DB — dependency failure, не «reuse обработан». Это проверено через service и реальный PostgreSQL, включая deferred commit failure; публичный HTTP mapper ещё не подключён.

Примитив rotation **не обновляет session expiry, primary/MFA timestamps и не создаёт access JWT**. Эти действия принадлежат полному use case ниже; публичная ручка не должна вызывать primitive напрямую.

## Refresh use case — J4b.1-local

1. Service принимает только opaque credential и trusted IP; client не задаёт actor/session/audience/scope/mode. Общий deadline 3s и общий с exchange instance admission8, без очереди.
2. Redis IP/project lookup budgets срабатывают **до SQL**, включая неизвестные canonical secrets. Только затем один indexed lookup возвращает server-owned user/session/ledger hash как hint, не authentication. Existing issuance actor/session/IP/project budgets проверяются до transaction: family=API session, смена refresh hash не сбрасывает её лимит.
3. В Read Committed transaction: Access snapshot → user SHARE → session UPDATE → family/verifier UPDATE. Сверяются все hint bindings; state уже содержит текущую auth_version, повторный user lookup не нужен. Spent replay commit/revoke выполняется до текущих scope/MFA policy checks, не откатывается из-за исчезнувшего grant.
4. Для current credential выполняются общие с exchange session guards: active/version/role bindings/primary/MFA/factor, activation/temporary-password и актуальная password email-verification policy. Отключение primary method само по себе не logout существующей session.
5. Current grants выбираются одним bounded SQL по максимум64 family keys; service пересекает их с immutable family maximum и текущим deployment audience allowlist. Пустое пересечение/удалённый audience — отказ и rollback. Вновь назначенные permissions за пределами family не добавляются. Current mode берётся из server resource config, не клиента.
6. Обычная API session может продлить idle до min(now+family idle,absolute); UPDATE пропускается, если deadline не увеличивается. Административная session с idle_timeout_seconds>0 не продлевается refresh. Primary/MFA timestamps и absolute deadline не повышаются.
7. Общая с exchange claims/signing операция подписывает локально; access expiry ограничен текущим idle/absolute. Refresh audit, successor, renew и issuance audit коммитятся вместе. Последняя SQL проверка запрещает уже истёкшую issuance/session; подтверждённый SQL/audit/sign/commit abort возвращает nil result с rollback. При неопределённом сетевом результате commit raw всё равно не выдаётся: нужен новый вход, нельзя обещать rollback уже committed rotation. Повтор старого secret после такой rotation приводит к обычному reuse revoke, не retry grace. Raw successor добавляется в service result только после успешного repository commit.

Генератор подключается через service port из App, без импорта concrete infra в service. Новых зависимостей/pools/workers/ENV/schema changes в J4b.1 нет. Lookup counters используют отдельный namespace и те же bounded IP/project настройки: это предварительный abuse budget, не двойной расход issuance counter. Existing actor/session/IP/project issuance counters общие с exchange. Два Redis Lua calls и один indexed hint lookup происходят вне SQL transaction; Redis outage fail-closed, auto-retry не добавлен. Новые ключи не выделяются при исчерпанном budget, TTL60s не продлевается.

До публикации остаются App/config и HTTP login/MFA/enrollment/refresh/logout с cookie/Authorization conflict rejection/no-store/без Set-Cookie, safe mapper/Retry-After, отдельные negative API tests и management profile label. Внутренние [password issuance](native-issuance.md), [email OTP binding](native-email-otp.md) и [MFA completion](native-mfa.md) реализованы; ограничения cleanup/fleet/load ниже остаются обязательными, service-тесты не заменяют их.

## Очистка и rollout

Spent verifiers остаются до absolute family deadline даже при раннем logout. Existing worker сначала удаляет expired verifier rows — максимум batch через expiry index/SKIP LOCKED; отдельным bounded statement — expired families без children. Session retention не удаляет ledger, пока family существует. Нет каскада `batch × 4096` verifier deletes; metadata-only audit переживает удаление family. Закрытая история не возрождает authority и не требует per-request cleanup.

### Ограниченный обход — J4b.2c.2-local

Измерение прежнего actual SQL с batch100 на10000 held API sessions/families показало≈10000 посещений rows на каждую eligibility стадию: NOT EXISTS до LIMIT ограничивал удаление, но не просмотр. Исправлены именно shared queries `account/repository/postgres/{retention,transient_cleanup}.go`, без нового worker/pool/индексов/кеша.

`auth.retention_checkpoints` содержит две фиксированные строки sessions/refresh_families: `(cursor_at,cursor_id)`, начальная позиция `-infinity`/нулевой UUID. Checkpoint row берётся FOR UPDATE SKIP LOCKED; materialized keyset page по существующему временному индексу содержит максимум batch кандидатов **до** eligibility/row locks. Только для этой страницы проверяется отсутствие family/children и выполняются PK locks/deletes. Checkpoint продвигается до конца просмотренной страницы даже при held/locked candidates; пустая страница возвращает его в начало. Поэтому удерживаемая голова не заставляет каждый tick повторять весь backlog или навсегда забывать более поздние/пропущенные строки.

Deletes и checkpoint advancement коммитятся вместе. Session page входит в прежнюю transaction контактов/audits; family page — один atomic writable-CTE statement, без дополнительных BEGIN/COMMIT round trips. Другой worker пропускает занятый checkpoint, не дублирует эту страницу; состояние переживает смену экземпляра/restart. Missing checkpoint — ошибка, не молчаливый reseed. Cursor — только progress physical cleanup, не authority/session cache и не UI retention policy.

Нулевая партия удалений **не означает**, что очередь пуста. Held/locked/позднее ставшие eligible строки возвращаются на следующем круге; physical lag включает длительность полного sweep и drain history, не только interval. При росте backlog быстрее сканирования/удаления конечный SLA обещать нельзя. Срок логической недействительности токена от cursor не зависит. Старые verifiers не удаляются раньше absolute deadline; семья — только без children, ledger — только без family. Максимальная history4096 дренируется партиями, без cascade×4096. Порядок worker стадий сохранён: ledger может удалиться в следующем sweep после family.

Actual queries перехвачены тестовым pgx QueryTracer и проверены EXPLAIN ANALYZE/BUFFERS, не упрощёнными копиями. На100000 rows, batch100, в начале и после50000-й позиции: held session page —200 visits sessions/100 families, held family page —200 families/100 tokens,≈908–909 buffers; eligible pages — до400 visits одного relation/1708 buffers; verifier DELETE —200 visits/704 buffers. Visits суммируют повторные scan/lock/delete nodes, это не число разных кандидатов. Уменьшен рост работы с размером held backlog, не заявлено уменьшение каждого малого запроса: metadata/PK checks имеют собственную стоимость. Cache, btree height, dead tuples, FK triggers и I/O влияют на физическую цену; это не production capacity.

Real SQL/race также проверяют batch1 progress через held ledger, SKIP LOCKED с последующим wrap/revisit, занятые checkpoints, delete rollback, missing state и4096 history drain. Общий worker deadline5s сохранён. Внешние multi-instance throughput/fault/restore/load/GC и storage sizing по реальным данным остаются открыты.

### Бюджет хранения до подключения native API

Существующий JWT project budget по умолчанию3000/min разделяется exchange/native issuance/refresh; cleanup B100/I1min способен удалить **не более**100 expired verifier rows/min на один успешный worker. Это upper ceilings, не измеренный drain/RPS. При sustained native writes около3000/min backlog после закрытия history windows будет расти; нынешние defaults нельзя считать автоматически согласованными для native publication.

Для family с absolute lifetime L и минимальной rotation30s консервативный максимум credentials равен `min(4096, 2+floor(L/30s))`: initial и первая немедленная rotation учтены. При стабильных общих Redis counters/config и P project requests/min aggregate verifier writes за окно L ограничены примерно `P*(ceil(L/min)+1)`; нельзя одновременно умножать этот aggregate ceiling на4096 каждой family. Например L14d/P3000 даёт≈60.5млн writes/window, **не** гарантированный размер live таблицы: expired backlog без достаточного cleanup способен расти дальше. Redis reset, operator config changes и реальные нагрузки требуют отдельного учёта.

J4b.2c.3-config связывает lifetime/issuance ceilings с batch/interval явной startup-проверкой ниже. Batch и security TTL автоматически не меняются. Консервативно считается один worker; `N×B/I` — лишь идеальный верхний предел, не гарантированная мощность fleet под locks/deadline/ошибками. Cursor scan/drain budgets и storage оценка через реальные heap/index/bloat/backup размеры остаются операционной приёмкой; metadata audits/session retention считаются отдельно. HTTP не публиковать с молчаливым storage mismatch.

Изменена только исходная 000001 up/down, новой миграции нет. **Новый binary ожидает profile/refresh tables и две seeded retention checkpoint rows даже без native HTTP**: controlled schema/grants upgrade обязателен, включая SELECT/UPDATE на checkpoints. Runtime не создаёт потерянное состояние автоматически. Рабочая БД не менялась и не сбрасывалась. Режимы backup/restore/key distrust и load/GC остаются J7/pre-ui/A8.

### Настройки native — J4b.2c.3-config

`JWT_NATIVE_ENABLED=false` по умолчанию. При `true` обязательны `JWT_ENABLED=true` и `MFA_ENABLED=true`: требуется готовность MFA-компонента, а не принудительный второй фактор для каждого пользователя. Требования факторов определяет действующая SQL policy. Native HTTP ещё не опубликован; флаг подключает lifetime policy к единственному App token service, не создаёт дополнительные pools/workers и не меняет cookie exchange.

`JWT_REFRESH_IDLE_TTL=168h`, `JWT_REFRESH_ABSOLUTE_TTL=336h`: целые секунды, idle≥1m, absolute≥idle, не выше `SESSION_TTL`/`ABSOLUTE_SESSION_TTL`. Более строгие admin bounds сохраняются. Конфигурация проверяется при deployment startup до SQL и повторно перед JWT key/resource loading и открытием JWT Redis client; выключенный native не требует его TTL/MFA/cleanup совместимости. Невалидный тип ENV всё равно является ошибкой общего загрузчика. Сохраняемые UI-переключатели — будущий J6, не обход deployment ceilings.

Пусть P — общий `JWT_ISSUANCE_PROJECT_LIMIT_PER_MINUTE`, B — `RETENTION_BATCH_SIZE`, I — `RETENTION_INTERVAL`, D — существующий batch deadline 5s. Проверка требует:

```text
2 × P × (I + D) <= B × 1m
```

Интервалы считаются без округления, с проверенными bounds до арифметики. Учтён один worker и время его партии; половина расчётного бюджета оставлена в резерве. Shared project counter ограничивает суммарную выдачу/rotation, поэтому для верхней оценки записей не складываются отдельные лимиты native и exchange. Проверка не меняет B/I/P/TTL, не умножает запас на число replicas и не требует нового storage setting.

С B100/I1m допустим P≤46/min; P47/min уже отклоняется. При P3000/min арифметически проходит, например, B600/I1s — **пример проверки, не рекомендация без замеров и не применённая настройка**. Оператор выбирает budgets по результатам drain/storage/load приёмки. Все ENV-примеры остаются с native=false и прежними budgets; простое включение native при старых defaults намеренно останавливает запуск понятной ошибкой.

Это necessary configuration guard, не доказательство стабильного backlog: batch может завершиться ошибкой, deadline или ожиданием locks; page visits и eligibility не равны deletes. Требуются measured successful drain, задержка полного sweep, запас места на L/history/audits/indexes/bloat/backup, наблюдение за lag и согласованный fleet rollout. При Redis reset/смене лимитов старые записи также не исчезают. Сокращать reuse window ради нехватки диска запрещено. End-to-end capacity/GC/fault/restore этим блоком не измерены.

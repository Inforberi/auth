# Refresh storage — J4a-local

17 октября 2026: реализованы SQL-хранение, транзакционные операции ротации и изоляция API/cookie sessions. **Это ещё не работающий native login/refresh API.** App/HTTP/ENV/native credential output и полный refresh use case не подключены. `JWT_ENABLED` по-прежнему включает только существующий [cookie session exchange](jwt-exchange.md), не native-профиль.

## Владельцы и границы

| Код | Назначение |
| --- | --- |
| `token/domain/refresh.go` | Canonical 32-byte opaque credential → SHA-256 verifier, family/result, предел поколений и интервал |
| `token/service/refresh_family.go` | Server-owned creation params/shape bounds, не HTTP DTO и не доказательство полномочий |
| `token/repository/postgres/refresh_family.go` | Создание family + первого verifier + audit в переданной transaction |
| `token/repository/postgres/refresh_lock.go` | Indexed lookup и порядок user/session/family/verifier locks |
| `token/repository/postgres/refresh_rotate.go` | Consume/successor/reuse writes в той же transaction |
| `account/repository/postgres/{retention,transient_cleanup}.go` | Existing bounded cleanup без нового worker |

SQL primitives принимают `pgx.Tx` только внутри repository слоя. Их нельзя вызывать из HTTP или передавать transaction в business service. Следующий J4b owner должен собрать primary/MFA/current authorization/signing/rotation/renew/audit/commit в один явный workflow; эти primitives сами не коммитят, не подписывают JWT и не возвращают raw secret.

## Профиль ledger

`auth.sessions.credential_profile` — immutable `browser` (default) либо `api`. API row требует primary_verified_at, но **наличие timestamp не заменяет реальную проверку primary/MFA coordinator**. Profile нельзя перевести UPDATE из browser в api или обратно. Существующие session constructors создают только browser; production native row creation ещё не подключён.

Cookie lookup/renew/rotate/password reauthentication/activity/management-caller и cookie JWT exchange требуют browser profile. Даже знание API ledger verifier не даёт cookie authentication или activity renew. Browser owner может перечислять/отзывать собственные sessions разных профилей через общий ledger; API verifier не становится browser management principal. Reset/logout-all/block/delete/auth_version/role-binding invalidation остаются общими, не второй user/session store.

Ledger verifier и refresh verifier — разные credentials: creation/rotation отвергают подстановку ledger hash как refresh hash. Будущий native login не должен отдавать raw ledger secret, а refresh secret генерирует существующий криптографический generator. Parser принимает только canonical base64url 43 chars/32 bytes: не JWT, padded value, Bearer header или caller-selected UUID.

## Хранение и порядок

Одна family на API session, immutable audience/maximum sorted scope/idle policy/absolute deadline. Idle policy при creation ограничивается исходным session lifetime и оставшимся absolute window (округление вниз); следующий owner дополнительно ограничит её deployment policy. Scope keys должны быть проверены по catalog/current grants **до выдачи** J4b, одна shape validation этого не делает.

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

**Reused — решение, которое owner обязан commit до HTTP 401.** Возврат обычной ошибки в transaction helper откатил бы security mutation. При ошибке commit/DB нельзя возвращать «reuse обработан»: это dependency failure. Тестовый owner подтверждает commit semantics, но runtime owner/HTTP пока не реализован — не считать этот gate закрытым.

Примитив rotation **не обновляет session expiry, primary/MFA timestamps и не создаёт access JWT**. J4b должен повторно проверить current permissions ∩ immutable family scope ∩ audience allowlist, policy/verification/MFA/provisioning, сделать допустимый idle renew (не admin activity), clamp access expiry, local sign и audit до commit. Нельзя подключать нынешний primitive как публичную ручку без этих шагов, admission/Redis limits и transport binding.

## Очистка и rollout

Spent verifiers остаются до absolute family deadline даже при раннем logout. Existing worker сначала удаляет expired verifier rows — максимум batch через expiry index/SKIP LOCKED; отдельным bounded statement — expired families без children. Session retention не удаляет ledger, пока family существует. Нет каскада `batch × 4096` verifier deletes; metadata-only audit переживает удаление family. Закрытая история не возрождает authority и не требует per-request cleanup.

Deletion batch bound — не доказательство constant scan cost/drain rate. До sustained native traffic проверить plans, eligibility/held-ledger backlog при коротком session retention, storage/fleet/drain/locks и общий 5s worker budget. Static limits не throughput; shared-family history может задержать очистку ledger до закрытия/дренирования window.

Изменена только исходная 000001 up/down, новой миграции нет. **Новый binary ожидает profile column и refresh tables даже без native HTTP**: старую installation нельзя запускать с новой версией без controlled schema/grants upgrade. Рабочая БД не менялась и не сбрасывалась. Режимы backup/restore/key distrust и load/GC остаются J7/pre-ui/A8.

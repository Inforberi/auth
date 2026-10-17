# ADR 004: JWT-профили и границы доверия

Статус: проектное решение J1, 17 октября 2026. Пользователь согласовал стандартный Bearer JWT, отдельный native/API профиль и настраиваемую локальную проверку для дополнительных backend. J2/J3a/J3b-local реализованы: disabled-by-default session exchange/публичный JWKS с SQL authority и Redis budgets. J4a/J4b.1-local реализуют storage и transaction-owned refresh core. **Native login/refresh HTTP и online middleware пока нет.** Остальные пункты — обязательный контракт следующих этапов, не действующий API. [Порядок реализации](../planning/jwt-access.md), [базовая authority](002-sessions-and-transactions.md).

## 1. Профили

J2-local: [crypto/key foundation](../features/jwt-keys.md) реализован в internal signing и pkg/authjwt; J3b подключает optional [App/HTTP/ENV session exchange](../features/jwt-exchange.md). Crypto verification не является current authority consumer. Unknown claims отклоняются strict typed decoder, а не игнорируются; claims grammar и amr описаны в feature doc. Остальные гарантии ниже остаются контрактом следующих этапов.

| Профиль | Вход / credential | Продление | Authority |
| --- | --- | --- | --- |
| Browser/BFF | Существующая HttpOnly opaque cookie | Существующие session/activity правила | Текущий SQL ledger, без изменений |
| Session exchange | Полностью завершённый вход → JWT для одного resource audience | Новая выдача через живую cookie-session; отдельного refresh нет | Strict online по умолчанию |
| Native/API | Полностью завершённый вход → JWT + opaque rotating refresh, без browser session cookie | Refresh family, связанная с общей SQL session | Strict online по умолчанию |

JWT — результат входа, не новый primary method. Password/email OTP/Google/Telegram, verification, MFA, role-required enrollment и временная активация не обходятся выбором transport. Public login не принимает административный intent. Partial login возвращает только restricted challenge; полноценный credential появляется после всех проверок в финальной SQL-транзакции.

Для native сначала подключаются password/email OTP и существующий MFA coordinator. Challenge получает отдельную server-bound native purpose/transport/audience/scopes, не browser cookie binding в JSON. Public caller не выбирает `administrative=true`, чужой user/session или assurance. Google/Telegram сохраняют существующий HTTPS browser flow и session exchange; прямой native provider handoff не объявляется готовым вместе с password/native. Его отдельный J4c обязан определить system-browser + PKCE-bound одноразовый handoff/redemption до публикации, без access/refresh в URL и копирования OIDC verification. Новый OAuth server/SDK/plugin framework не нужен.

Каждая native family имеет собственную строку в общем ledger; cookie и native credentials не выдают доступ к одной сессии друг через друга. Операции logout-all/reset/block/delete и версия пользователя общие. Browser login response/cookie и существующие admin routes не меняются.

## 2. Strict и local

**Strict**: middleware проверяет JWT и делает один authenticated online decision в Auth. Auth проверяет полный токен и одним SQL snapshot связывает его с `sid/sub/auth_version`, profile/family, active/nondeleted user, `role_bound_sessions`, текущими permission assignments и policy. Positive authority не кешируется; SQL/Auth недоступен → 503, а не local fallback. Сам decision не продлевает idle/session/MFA и не пишет audit на каждый read.

Effective scope = подписанный issuance scope ∩ текущие permissions ∩ allowlist audience. Grant expansion не оживляет старые session role bindings; применяются AS6a/AS6b, не второй кеш grants. Объекты/строки/поля и критичные внешние эффекты защищает backend данных. Отзыв после online decision не отменяет уже начатый внешний эффект: перед критичной записью backend повторно авторизует действие в своём протоколе/транзакции.

**Local** — отдельно включаемая policy конкретного audience и осознанное исключение из немедленного отзыва ADR 002, а не новый default. С готовым trusted key snapshot обычный запрос не обращается в SQL/Redis/Auth. Consumer принимает только токен с подписанным `avm=local`; strict-токен нельзя молча валидировать как local. Тип решения выбирают deployment/администратор audience, не клиентский JSON и не ошибка сети.

Default access TTL = **2 минуты**, ceiling = **5 минут**. `exp-iat` не превышает ceiling. При `now >= exp` токен недействителен: **нет grace после exp**. Разрешённое отклонение будущего `iat/nbf` — до 30 секунд. При проверенной разнице часов issuer/consumer не более 30 секунд максимальная задержка применения logout/block/role revoke для ранее выданного local JWT — **5 минут 30 секунд** (обычно 2 минуты 30 секунд при default). Срок дополнительно ограничен session deadline при выдаче; локальный consumer не узнает о последующем сокращении этого deadline. Вне допущения о часах это не гарантия; clock monitoring — release prerequisite.

Local не разрешён для Auth admin/settings/users/roles/MFA/security routes и встроенных административных permissions. Внешние sensitive audiences обязаны быть strict. Внешний backend, игнорирующий verifier/согласованный scope, находится вне гарантии Auth. JWT не идентифицирует сам вызывающий сервис.

## 3. Credentials, claims и scopes

Выбран **ES256 / P-256 / SHA-256**, compact JWS из трёх segments, одна подпись. Алгоритм фиксирован в коде, не выбирается по входному `alg` или настройке клиента. Auth private key отделён от account encryption root; consumers получают только public JWKS. Библиотека — уже используемый `github.com/go-jose/go-jose/v4`, baseline **v4.1.6**, не новая параллельная JWT-библиотека и не собственная криптография.

Проверенные при J1 источники: [API go-jose](https://pkg.go.dev/github.com/go-jose/go-jose/v4), [case-sensitive JSON / duplicate rejection](https://pkg.go.dev/github.com/go-jose/go-jose/v4/json), [release 4.1.6](https://github.com/go-jose/go-jose/releases/tag/v4.1.6), [RSA JWK DoS advisory](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q). v4.1.4 в текущем go.mod обновляется до patch v4.1.6; это профилактика известной проблемы dependency, не доказательство эксплуатации нашего OIDC. Default RSA parsing ceiling 4096 bits не увеличиваем. Перед J2/J7 advisories проверяются снова; отсутствие известных проблем не равно аудиту приложения.

Header: только `alg=ES256`, bounded `kid`, `typ=at+jwt`. Отвергать `jku/x5u/jwk/x5c`, `crit`, `b64`, compression, JWE/nested/JSON JWS, duplicate/case-confused members и неподдерживаемые поля. `kid` — identifier 1–64 ASCII `[A-Za-z0-9_-]`, не URL/путь. JWS parser обязан применять algorithm allowlist; успех parse ещё не signature verification. В J2 нужны негативные tests/fuzz, не слепое доверие default parser.

| Claim | Контракт |
| --- | --- |
| `iss` | Точный deployment HTTPS issuer; не Host/forwarded headers/claim-driven discovery |
| `sub`, `sid` | Canonical user UUID и публичный session UUID, не cookie/hash |
| `aud` | Один bounded resource ID строкой, не набор взаимозаменяемых ресурсов |
| `iat`, `exp` | Целые Unix seconds, обязательны; expiry не позже текущих idle/absolute deadlines |
| `jti` | Случайный 256-bit identifier, base64url без padding; не отдельный SQL row каждого access JWT |
| `auth_version` | Положительная серверная версия, для online сравнения, не самостоятельный механизм отзыва |
| `scope` | Отсортированные permission keys через один ASCII space; без duplicates/wildcards/непроверенных role names |
| `avm` | `strict` или `local`, серверная policy audience при issuance |
| `auth_time`, `amr`, `mfa_time` | Исходные серверные proof timestamps/methods; MFA time только если фактор подтверждён |

`nbf`, если присутствует, проверяется с тем же future-skew bound. Unknown claims не повышают authority. Claims без PII/email/паролей/raw refresh/secrets/cookie verifier; JWT читаем, он не шифрование. `typ=at+jwt` не объявляет совместимость со всем RFC 9068: это собственный resource access contract поверх стандартного JWS/JWT.

Deployment audience allowlist ≤32 entries, ID ≤128 ASCII bytes. У audience — собственные разрешённые permission keys и validation mode; максимум 256 разрешённых keys, в одном token/request ≤64 и суммарно ≤2048 bytes. При превышении scope не обрезается молча: caller запрашивает меньший набор. Каждый scope существует в permission catalog и доступен пользователю; UUID/role/token claims из тела не заменяют SQL authority. Поля и row filters не пакуем в JWT.

## 4. Выдача, renew и refresh family

J4a-local реализует [storage/profile foundation](../features/refresh-storage.md), J4b.1-local — полный refresh core без native HTTP, J4b.2a-local — [первую API issuance от server-only password proof](../features/native-issuance.md). Assurance не повышается, при MFA requirement initial issuance пока отказывает. Первый refresh поколения0 может rotate сразу (issuance не rotation), затем между rotations≥30s. Repository owner коммитит reuse decision до ErrInvalidRefresh; commit failure — dependency error, не успешный revoke. Неопределённый сетевой commit не гарантирует rollback, raw не выдаётся и нужен новый вход. Native MFA/email OTP binding и безопасный transport остаются J4b.2b до публикации.

J3a/J3b-local реализуют [session exchange](../features/jwt-exchange.md) с SQL guards/commit audit/Redis budgets и optional HTTP/App/config/JWKS. Required password email verification проверяется по current SQL policy; отключение primary method само по себе не logout. Proof clarification: существующий ledger хранит общий факт MFA, поэтому exchange использует factor `amr=mfa`, не заявляя неизвестный TOTP/recovery mechanism. Более конкретные otp/recovery допустимы только при известном механизме.

Session exchange проверяет текущую cookie-session без sliding refresh; JWT issuance не считается пользовательской activity администратора. `exp = min(now+configured TTL, session idle deadline, absolute deadline)`, при истечении — отказ, а не token с продлённым сроком. Подпись только локальным ключом после admission; issuance/final guard/audit согласованы с user/session/Access locks и commit. Не отдавать signed result до successful commit и не держать транзакцию на сеть/provider/KMS.

Native login создаёт API-profile ledger session, не отдаёт opaque browser token. Family ограничена одним audience и issuance scope; изменение audience/расширение scope требует нового полного входа или разрешённого session exchange, не refresh. Native idle/absolute ceiling не выше существующих SessionTTL/AbsoluteSessionTTL; defaults **7/14 дней**, для администраторов действуют более строгие existing admin bounds. API refresh не считается admin activity; административные операции остаются cookie/private password+MFA. Bearer API не добавляется в старые admin handlers.

Refresh: 32 random bytes, opaque base64url, в БД только hash/verifier. Одна family на API session; отдельные устройства получают отдельные sessions. В той же SQL-транзакции: проверить актуальную session/policy/grants → consume current verifier → создать ровно один successor → session idle renew в допустимом профиле → audit/commit. MFA/password timestamps, role bindings и absolute deadline не обновляются. Нельзя расширять scope из-за новой роли; старый scope также пересекается с текущими grants.

Replay достоверно использованного verifier **коммитит отзыв API session/family**, даже когда HTTP возвращает 401. После этого не работают ни refresh, ни strict access; local access ограничен опубликованным TTL. Random/malformed/неизвестный secret не отзывает чужие sessions. Отказ dependency не маскируется под reuse.

Не вводим grace/retry второго successor: при двух concurrent refresh первый может получить token, но replay второго затем отзывает family; возможен повторный вход обоих. При потерянном ответе повтор уже использованного refresh также требует нового входа. Native client делает single-flight refresh; browser/BFF использует cookie profile, не refresh family в нескольких вкладках.

Spent verifiers сохраняются до absolute family deadline для reuse detection. Размер ограничен: минимум 30s между успешными rotations, максимум 4096 generations/family, затем новый полный вход без продления старой family. Too-early current refresh → 429 без rotation/revoke; известный spent verifier обрабатывается как reuse независимо от частоты. Это storage/resource ceiling, не оценка RPS. Cleanup existing bounded worker удаляет историю только после family deadline/закрытого detection window; logout/reset/block/delete не возрождают renew, даже если cleanup ещё не выполнен.

Обычная cookie rotation сохраняет ту же session identity/authority для уже выданных exchange JWT до expiry; security logout/reset/revoke отзывает authority. Ни новый JWT iat, ни fresh refresh не обновляют assurance. Утрата доказательства/новое MFA requirement ведёт к действующему restricted login/enrollment flow, не bearer bypass.

## 5. Служебная introspection

Только backend-to-backend HTTPS; отдельный deployment-managed credential на каждый consumer: client ID + 256-bit secret через HTTP Basic, stored SHA-256 verifier, constant-time comparison. Не browser/native secret, не user JWT как service identity. Отдельный clients manifest ≤32 clients, до двух credential verifiers/client для bounded rotation, fixed allowed audiences. Удаление credential требует согласованного reload/rollout всех Auth instances; до завершения rollout не обещать мгновенный fleet revoke. CORS/Origin/IP/proxy headers не доказывают service identity; неподтверждённый proxy identity header игнорируется.

Передаётся **полный access token** в bounded JSON POST; не UUID/sub/version и не `alreadyVerified`. Сначала service auth/admission, затем signature/claims и SQL decision. Consumer A не может introspect token audience B. Неактивный/невалидный access даёт только `{"active":false}`, без PII/lookup по user UUID. Неуспех service auth — 401, чужой audience — 403, dependency — 503. Не следуем произвольному issuer/JWKS URL. Response no-store, без positive proxy cache.

Активный response содержит `active`, `iss`, `sub`, `sid`, `jti`, `audience`, `expiresAt`, ограниченный effective `scope`. Adapter сверяет его с конкретным локально проверенным token/request; timeout/неоднозначный ответ/неверная корреляция — fail-closed. Один online decision на запрос, без отдельных вызовов за ролями/session/user и без скользящего UPDATE. Совместимость wire format RFC 7662 не заявляется.

## 6. Ключи, кеш и восстановление

Один active signing key, public verification set ≤4 P-256 keys, unique kid, согласованные kty/curve/alg/use/key_ops. Закрытые ключи не публикуются; public manifest с private material отклоняется. Signing/trust material — deployment files, не UI/БД/ENV text и не автогенерация при ошибке чтения. Disabled JWT не читает key files и не требует их наличия. Startup при enabled JWT без валидного material — отказ до traffic.

Consumer доверяет только фиксированному HTTPS JWKS endpoint из своей конфигурации. До первого защищённого запроса нужен свежий trust snapshot; persisted stale key set после restart не принимается. Max snapshot age **60s**, body ≤16 KiB, ≤4 keys, fetch deadline ≤2s, без redirects/private-network discovery; разрешённые internal endpoints задаются оператором, не token. Readiness и network policy проверяются на реальном deployment.

Один shared transport/cache на consumer instance, coalesced refresh/backoff, максимум один fetch attempt/10s. Unknown kid отклоняется, не форсирует refresh на каждый случайный token; следующий fetch только когда snapshot due. Не нужен растущий negative cache. После 60s без подтверждённого trusted snapshot — 503/fail-closed даже для знакомого kid, не вечный last-known key. Это означает периодический JWKS I/O, **не полную сетевую автономность**; на обычном запросе с готовыми keys нет authority/SQL вызова.

Planned rotation: заранее добавить новый public key → дождаться обновления consumers → переключить signing → после последней старой выдачи выдержать max TTL+30s → удалить старый key. Kid не переиспользуется. Ошибочный config не переключает алгоритм/ключ автоматически. Согласованный rollout, не общий secret для всех backend.

Compromise: остановить старые signers, удалить compromised kid из authoritative trust set всех узлов, запустить новую конфигурацию, затем подтвердить обновление consumers. Ceiling устаревшего cache — 60s после гарантированного прекращения old trust responses; если этот интервал неприемлем, закрыть traffic до подтверждённого refresh/restart. Обычный TTL overlap не лечит украденный key; нельзя доверять Auth node, продолжающему выдавать старый JWKS. Локальную нулевую задержку не обещаем.

Restore: traffic закрыт; восстановленные sessions/challenges/families принудительно отзываются, deployment получает новый signing key/kid и **старые keys удаляются из verification trust всех consumers**. До открытия traffic подтвердить новый trust snapshot либо restart consumer; если нет подтверждения — оставить traffic закрытым. Не используем epoch из откатившейся БД как защиту и не ждём TTL при возможной компрометации. Старые key manifests не восстанавливаются автоматически вместе с DB backup. Проверка этого runbook — J7/A8, не результат J1.

## 7. HTTP-контракт и защита ресурсов

Ниже зарезервирован контракт будущих J3–J6, **routes ещё нет в router/Swagger**:

| Метод/путь | Credential | Input / output |
| --- | --- | --- |
| GET `/.well-known/jwks.json` | Public read | Только bounded public keys; cache headers/ETag ≤60s |
| POST `/api/v1/auth/token/exchange` | Cookie + HTTPS Origin | `{audience,scope:[permission keys]}` → access result, без refresh |
| POST `/api/v1/auth/native/password/login` | Primary input | `{email,password,audience,scope}` → restricted challenge либо native result |
| POST `/api/v1/auth/native/email/request` | Primary input | `{email,audience,scope}` → нейтральный accepted, existing code/outbox/limits |
| POST `/api/v1/auth/native/email/confirm` | Bound primary challenge | Restricted challenge либо native result |
| POST `/api/v1/auth/native/mfa/complete` | Bound native challenge | После текущих MFA checks → native result |
| POST `/api/v1/auth/token/refresh` | Native opaque refresh в JSON | `{refreshToken}` → один successor + access result |
| POST `/api/v1/auth/token/logout` | Native opaque refresh в JSON | Revoke собственной family/session; нейтральный repeat, без чужого logout-all |
| POST `/api/v1/internal/auth/token/introspect` | Consumer HTTP Basic | `{token}` → inactive или связанный active decision |

Access result: `{accessToken,tokenType:"Bearer",expiresIn,expiresAt,audience,scope}`. Native result дополнительно `{refreshToken,refreshExpiresAt}`. Restricted result не имеет access/refresh и содержит только purpose-bound challenge + expiresAt + следующий шаг. Input/result разных сценариев не собираются в один Go results.go. Нельзя публичным флагом переключить существующий private admin login в native.

Resource backend принимает ровно один `Authorization: Bearer <accessToken>`; не query/path, не provider ID token и не refresh. Native/service routes отвергают browser session cookie/ambiguous credentials, без fallback. Cookie exchange/admin сохраняют existing CSRF/Origin. Служебный запрос без Origin не ослабляет соседние browser routes. CORS default-off; Authorization разрешается только на нужном bearer route group, точные origins/methods/headers, без wildcard+credentials. GET/HEAD/OPTIONS не выполняют mutations.

Token/body bounds до дорогой работы: access token ≤4096 bytes; decoded JOSE header ≤512 bytes; payload ≤3072 bytes; token/refresh/introspection JSON body ≤8 KiB; secret fields не логируются. DTO shape/domain/transaction-current guards разделены; parser из поддерживаемой библиотеки, не собственный JOSE/HTTP parser. Если готовый parser не может выполнить контракт, J2 блокируется/выбирает другой поддерживаемый parser, а не молча игнорирует требование.

Общий deadline exchange/refresh/introspection ≤3s; никакого auto-retry на SQL/HTTP error. Admission до crypto/SQL, без безлимитной очереди: начальный instance ceiling signing 8 / verify 32 / introspection 32 / refresh 8. Используются existing Redis limits и shared pools; суммы по fleet документируются. Default distributed requests/minute: issuance 10/session, 30/IP, 3000/project; refresh 10/family, 30/IP, 3000/project; introspection 60000/consumer и 60000/project. Это защитные стартовые budgets, не capacity или гарантия 1000 RPS. Настраиваются в bounded deployment config; нагрузка/invalid traffic/fairness измеряются в J7/A8, ограничения нельзя молча отключать при Redis outage.

Ошибки resource API: 401 missing/invalid credential с `WWW-Authenticate: Bearer`; 403 недостаточно scope; 429 admission/rate; 503 authority/key/DB outage. Exchange: existing 401/403 session/Origin + 400 invalid request + 403 scope denied + 409 profile disabled. Refresh invalid/reused → 401 после committed revoke outcome при reuse, dependency → 503, не reuse. Auth token responses no-store, без raw secrets в URL/redirect/Referer/logs/APM/errors. Invalid-token flood не создаёт synchronous SQL audit на каждый запрос; bounded redacted metrics/sampling, durable audit — issuance/rotation/revoke/config по гарантии транзакции.

## 8. Конфигурация, UI и пакеты

Планируемые имена, **ещё не действующие ENV**: `JWT_ENABLED=false` (deployment ceiling), `JWT_ISSUER`, `JWT_SIGNING_KEY_ID`, `JWT_PRIVATE_KEY_FILE`, `JWT_KEYSET_FILE`, `JWT_RESOURCE_CONFIG_FILE`, `JWT_INTROSPECTION_CLIENTS_FILE`, `JWT_ACCESS_TTL=2m`, `JWT_REFRESH_IDLE_TTL=168h`, `JWT_REFRESH_ABSOLUTE_TTL=336h`. Ни переменные-заглушки, ни фиктивные entries в env examples в J1 не добавляются. Config files bounded ≤64 KiB, unknown/duplicate properties отклоняются; private paths/verifiers не возвращаются в HTTP.

J6 добавляет SQL/UI policy для session-exchange/native enable и разрешённого audience local opt-in в пределах deployment allowlist/ceilings. Изменение с current auth.settings.manage/fresh password+MFA/version/audit и предупреждением окна отзыва; client не выбирает weaker mode. Root material/issuer/endpoints/budgets остаются deployment. Disable прекращает новые issuance/refresh; strict проверяет текущий enable/mode, local JWT действует до своей границы/удаления trust. JWT disable не отключает cookie/private admin и не отрезает последний административный вход.

Границы реализации: `internal/auth/token/{domain,service,repository,transport/http}` владеет exchange/native family/online authority; `internal/auth/token/signing` — private signing/key owner; `pkg/authjwt` — малый reusable verifier/principal/middleware без imports `internal/`, DB и private key. App собирает зависимости в `internal/app/auth`; existing account/session/MFA/access владельцы сохраняются. Не создавать пустые пакеты до появления работающего потребителя. Signing/JWT output не копирует login pipelines; native challenge transport связывается до proof creation/consume, не перепаковывает browser proof в конце.

## 9. Приёмка

J1 закрывает выбор контракта S1–S10, **не реализацию и не security/load acceptance**. J2 проверяет подпись/parser/key lifecycle, J3 — locked issuance/authority, J4 — native/family/reuse, J5 — consumer/service boundary, J6 — policies/browser, J7 — все негативные/fault/fuzz/race/fleet tests. Для каждого S-пункта нужны evidence и PASS/FAIL/NOT RUN; active routes не публикуются по одному документу или crypto benchmark. Реальные provider-native handoff, HTTPS/ingress, emergency trust/restore, abuse/load/GC остаются открыты до выполнения соответствующего подэтапа.

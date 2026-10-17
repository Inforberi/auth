# JWT из действующей сессии

J3a/J3b-local, 17 октября 2026: реализованы ядро выдачи, disabled-by-default App/ENV, cookie POST exchange и public-only JWKS. **Native login/refresh HTTP и online introspection ещё нет.** Внутренние [refresh](refresh-storage.md) и [первая password API issuance](native-issuance.md) реализованы без native MFA/email OTP/маршрутов. Strict online consumer требует J5; криптографическая проверка сама не проверяет актуальные права. External/fleet/load gates остаются открытыми до rollout.

## Включение и API

`JWT_ENABLED=false` по умолчанию: App не читает JWT key/resource files, не открывает дополнительный Redis pool; оба маршрута не зарегистрированы. При `true` обязательны `JWT_ISSUER` (точный HTTPS issuer), `JWT_SIGNING_KEY_ID`, `JWT_PRIVATE_KEY_FILE`, `JWT_KEYSET_FILE`, `JWT_RESOURCE_CONFIG_FILE`. Ошибка конфигурации/catalog/key matching/Redis readiness останавливает startup, fallback нет. `JWT_ACCESS_TTL=2m`, ceiling 5m; budgets — `JWT_ISSUANCE_{ACTOR,SESSION,IP,PROJECT}_LIMIT_PER_MINUTE` с defaults 30/10/30/3000. Это лимиты выдач, не число пользователей.

Пути указываются **в runtime/container**, не передаются браузером. Private PKCS#8 держать вне checkout/image, отдельным read-only secret с доступом runtime UID и mode 0400/0600. Compose автоматически ключи не монтирует: operator-controlled read-only mounts/secret paths настраиваются перед включением. `secrets/`, PEM и KEY исключены из Git/build context как дополнительная защита, не security sandbox. Signing key не encryption root и не секрет для UI.

Resource file — strict UTF-8 JSON ≤1 MiB, ≤32 audience entries. Дубликаты/unknown/case aliases/null/trailing documents отклоняются; policy/catalog bounds проверяет service constructor. Пример:

```json
{"resources":[{"audience":"orders","mode":"strict","permissions":["orders.read"]}]}
```

`orders.read` сначала должен существовать в Access catalog и быть выдан пользователю через роли. Mode можно опустить (strict), `local` — осознанное исключение из немедленного отзыва, не client parameter. Config immutable до controlled restart; одинаковые files/keys/limits на всех экземплярах — deployment prerequisite, не распределённый registry.

| Метод/путь | Доступ | Результат |
| --- | --- | --- |
| `POST /api/v1/auth/token/exchange` | Cookie `__Host-session`, exact allowed Origin, NoRefreshAuth | Access JWT для одного audience; no-store, без Set-Cookie/refresh credential |
| `GET /.well-known/jwks.json` | Публичный, без cookie/Origin | Только public JWKS, ETag, max-age=30/must-revalidate; exact If-None-Match → 304 |
| `HEAD /.well-known/jwks.json` | Публичный | Те же headers без body |

POST body: `{"audience":"orders","scope":["orders.read"]}`, application/json, максимум **8192 bytes**. Только два указанных поля; повторные/unknown/case aliases/null/trailing JSON не принимаются. User/session/proof/mode приходят не из body. `Authorization` на cookie exchange отклоняется как ambiguous_credentials, не Bearer fallback. Существующие Origin/CORS правила сохранены: CORS off по умолчанию, exact origins, Content-Type-only preflight; bearer Authorization глобально не добавлялся.

Ответ: `accessToken`, `tokenType:"Bearer"`, оставшиеся целые секунды `expiresIn`, `expiresAt` (UTC), `audience`, sorted space-delimited `scope`. Это credential для целевого backend, **не для существующих admin-cookie routes**. Token держать в BFF/памяти, не URL/localStorage/logs. Повторная выдача после expiry — через live cookie session, не token-per-request loop.

Ошибки: 400 invalid_json/invalid_token_request/ambiguous_credentials; 401 unauthorized; 403 invalid_origin/forbidden/email_not_verified/mfa_required; 429 rate_limited с conservative Retry-After=60; dependency/crypto admission failure — 503 temporarily_unavailable/Retry-After=1. Тексты SQL/Redis/crypto ошибок и raw credentials не публикуются. Request/response отражены в Swagger; разрешённые Origin/cookie всё равно нужны при прямом вызове из Swagger/API, он не обходит backend.

## Границы и порядок

`internal/auth/token/service/exchange.go` — один сценарий; `config.go` — immutable allowlist ресурсов; `repository/postgres/exchange.go` — SQL authority/commit; `repository/redis/limits.go` — распределённые бюджеты. Ключи/ES256 переиспользуют [J2](jwt-keys.md). Новых workers, caches и библиотек нет.

1. Cookie-handler получает user UUID, публичный session UUID и verifier из проверенного Auth context, IP — из существующей trusted-proxy обработки. Клиент передаёт только audience и scopes, не principal/session/MFA/mode. Router требует Origin и NoRefreshAuth до вызова handler.
2. Service проверяет principal, IP, запрошенные audience/scopes; копирует и сортирует scope без изменения входного slice. Ресурс по умолчанию strict; local только из server configuration, без client downgrade. Ключи должны существовать в Access catalog и allowlist ресурса. Local-конфигурация с core admin permissions отклоняется.
3. До Redis/SQL — nonblocking admission максимум 8 выдач на один Service. Общий deadline операции 3s; ожидание освобождения SQL locks входит в него. После отмены rollback имеет отдельный cleanup deadline до 3s. Владельцы Service/Signer должны быть общими для экземпляра, не создаваться на запрос; fleet budgets считаются суммарно.
4. Один Redis Lua-вызов проверяет actor, стабильный session ID, IP и project. Окно — счётчик 60 секунд от первого принятого запроса, не sliding window. По умолчанию соответственно **30/10/30/3000 в минуту**; constructor требует positive bounded budgets. Меньший лимит побеждает. При отказе все счётчики остаются прежними, новые ключи не создаются, TTL не продлевается. Принятый бюджет не возвращается при последующем SQL-отказе. Hash slot общий, identifiers/IP защищены переданным keyed digester; Redis на проект отдельный. Ошибка/недоступность — отказ, не unlimited fallback.
5. SQL Read Committed: shared Access advisory lock → active/nondeleted user FOR SHARE → role-bound session FOR SHARE → current auth-settings SHARE. Shared lock допускает параллельные выдачи, но исключает Access mutations с тем же exclusive lock. После ожидания user lock отдельный statement видит committed version/session/factor changes. Проверяются user/hash/sid/version, idle/absolute/revoked, immutable role revisions, все requested grants, завершённая activation/смена временного пароля и действующее MFA-требование/фактор. При required password email verification проверяется текущий подтверждённый credential email, даже если session создана раньше переключения. Это общий guard с primary login, не копия в HTTP. Нет проверки прав отдельным запросом на каждый scope.
6. Подпись ES256 выполняется локально под этими locks; callback не делает сеть, Redis или KMS. Claims используют SQL proof snapshot и время БД. `exp=min(now+TTL,idle deadline,absolute deadline)`, с округлением вниз до Unix seconds. Primary/MFA proof timestamps не повышаются. Issuance не refresh, reauthentication или admin activity.
7. Audit insert с финальной проверкой expiry → commit → возврат raw JWT. Ошибка подписи, отмена, audit или commit не возвращают токен. После неоднозначного результата commit audit может существовать без доставленного ответа; at-most-once доставка не обещается. Повторный вызов — новая выдача и новый бюджет, не retry loop.

Source `000001` содержит `auth.token_issuance_audit`: user/session UUID, random token ID, audience, scope, mode и expiry/time. Нет raw JWT, cookie/hash, email, IP или refresh credential. Session UUID без FK к sessions: аудит должен пережить очистку ledger. Retention использует существующие security audit дни (default 180) и indexed bounded batches.

## Proof и отзыв

Primary: password → `pwd`, emailotp → `emailotp`, внешний OIDC (включая Telegram) → `oidc`. Существующая session хранит факт MFA, но не различает TOTP/recovery-code при её создании. Поэтому exchange выдаёт честное общее `amr=mfa` с исходным `mfa_time`, а не выдумывает `otp`/`recovery`. Verifier поддерживает эти три factor labels, но один токен может содержать только один фактор. Это уточнение контракта перед публикацией J3, не изменение session schema.

Revoke/reset/block/role mutation, завершившийся до получения соответствующего lock, не оставляет устаревший issuance snapshot. Если issuance получила locks первой, она может commit до последующего revoke; это корректный порядок, не обещание «все уже выданные JWT исчезают». Затем strict consumer обязан проверить current authority в J5. Local JWT сохраняет [согласованное окно](../adr/004-jwt-access-profiles.md#2-strict-и-local) до exp, а не немедленный отзыв.

JWT deployment config загружается на startup и копируется constructor; это не сохраняемая/UI JWT policy (J6). Existing cookie routes не менялись. Отключение первичного способа входа не считается logout и не отзывает полностью завершённую session; обязательность email verification при производной выдаче всё равно проверяется актуально в SQL. Account/session/role revoke остаётся отдельным немедленным прекращением authority для strict режима.

## Ресурсы и ограничения приёмки

- App создаёт по одному Service/Signer/JWKS snapshot на экземпляр. Retry policy в go-redis client-global: выделен отдельный JWT client с MaxRetries=-1/context timeouts, максимум **8 active connections**, PoolTimeout/Dial/Read/Write=1s, MinIdle=0. Existing Auth client/retry policy не меняются. При планировании Redis connections прибавлять до 8 на каждый Auth instance; outer admission также 8, общий SQL pool не новый. Клиент закрывается existing resources lifecycle и при partial startup error.
- Routing фичи отделён в router/token.go, сборка — app/auth/token.go; lifecycle server/retention/delivery остаётся в existing run.go, а не в token adapter. Resource file I/O и strict schema decode разделены в одном settings/resources.go. Новых workers/caches/libraries нет.
- SQL policy/config readiness, disabled behavior, metadata-only JWKS, Origin/NoRefreshAuth/error/Swagger проверены локально. Согласование сохраняемой JWT policy/UI — J6 без подмены её ENV fallback. Native/refresh/introspection — J4/J5.
- До sustained traffic рассчитать скорость audit cleanup и storage: default retention batch 100/interval 1m не является гарантией очистки при постоянных 3000 issuances/min. Измерить drain rate/время bounded batch и подобрать существующие deployment budgets; не заявлять RPS/отсутствие backlog по одним лимитам.
- SQL/Redis integration/race покрывают локальные гарантии. Browser/ingress, реальные provider proofs, fleet settings/key rotation, failure/restore, mixed load/GC/soak остаются открытыми pre-ui/J7/A8 gates.

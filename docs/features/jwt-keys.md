# JWT: ключи и криптографическая проверка — J2-local

Реализована основа [ADR 004](../adr/004-jwt-access-profiles.md). J2 не менял cookie/session/API; J3a/J3b добавили [optional session exchange/App/ENV/public JWKS](jwt-exchange.md), выключенные по умолчанию. Native/refresh — J4, online authority/HTTP middleware/remote JWKS resolver — J5; crypto-only verifier сам по себе не проверяет текущий доступ.

## Код и ключи

| Пакет | Ответственность |
| --- | --- |
| `internal/auth/token/signing` | Private key owner, startup loader, подпись для transaction-owned issuance |
| `pkg/authjwt` | Typed claims, strict compact/JWKS parsing, public trust и crypto verification без internal/DB/private keys |

Existing go-jose/v4 v4.1.6 стал прямой dependency, новой библиотеки нет. Криптография и JSON/JWS parser библиотечные; поверх них — ограничения собственного typed-контракта. Formatter/architecture checks теперь включают pkg.

`signing.Load(KeyConfig)` подключён из app/auth/token.go только при JWT_ENABLED=true. Disabled не читает файлы. Enabled требует HTTPS issuer/kid, private PKCS#8 PEM и public JWKS; автогенерации/перезаписи/fallback нет. Runtime paths/ENV/secret mounts описаны в [session exchange](jwt-exchange.md).

Private key — один PKCS#8 PEM block PRIVATE KEY, ECDSA P-256, ≤16 KiB, без preamble/второго block/trailing data. Regular file с permissions без group/other (0600/0400). Deployment paths и родители доверенные, недоступные на запись посторонним; это не API загрузки ключа и не filesystem sandbox. Symlinks допустимы только в operator-managed дереве. Ошибки не раскрывают путь/ключ/токен.

Public JWKS ≤16 KiB, 1–4 unique kid; только EC/P-256/ES256/use=sig, optional key_ops ровно `["verify"]`. Private d, symmetric/RSA/другая curve, x5u/x5c/URLs, unknown/duplicate/null поля, неверные точки и duplicate kid отклоняются. Private key обязан соответствовать public kid. Временные private buffers очищаются, но гарантированного стирания всех копий из Go heap/GC не обещаем. Public responses возвращаются копией.

`Signer.Sign(ctx, claims, now)` задаёт configured issuer/iat/random 256-bit jti и возвращает SignedToken с Raw (`json:"-"`), ID и ExpiresAt. Метаданные доступны issuance-аудиту без повторного разбора/логирования токена. Это primitive, **не SQL authorization и не login API**: J3 обязан проверить session/grants/deadlines и не отдавать результат до commit. Signer ограничивает TTL ≤5m, а сроки конкретной session знает J3.

## Проверка

`NewVerifier(Expectations, PublicKeys, trustedAt)` фиксирует issuer/audience/mode. `VerifySignature(ctx, raw, now)` проверяет:

- Compact JWS, три canonical base64url segments без padding/newlines: ≤4096 bytes, header ≤512, payload ≤3072, signature ровно 64 bytes.
- Только ES256/typ=at+jwt/bounded kid; нет none/HMAC/embedded keys/crit/b64/compression/произвольного fetch URL.
- Подпись, затем exact issuer/audience/mode, canonical UUID/jti, positive auth_version, sorted bounded permission keys.
- Целые timestamps, TTL ≤5m, без grace после exp, future iat/nbf ≤30s; исходные proof times не обновляются.
- Один primary amr (pwd/emailotp/oidc), optional один factor (mfa/otp/recovery) с согласованным mfa_time. Exchange использует общее mfa: ledger не сохраняет точный TOTP/recovery mechanism; см. [J3a](jwt-exchange.md).

Unknown claims отклоняются, не игнорируются: это строгая форма собственного контракта, не обещание совместимости с любым issuer. Duplicate/case aliases/nulls/неверные JSON types также отвергаются. Claims — **криптографически проверенные данные, не текущий authorization principal**. Для strict ещё нужна online authority; для local — явная audience policy. Scope не доказывает доступ к конкретным строкам/полям.

## Ротация и ресурсы

`PublicKeys` не сохраняет caller-owned map/bytes. `ReplaceKeys` атомарно меняет snapshot без сброса admission; старое/равное observedAt отклоняется. Unknown kid не меняет trust и не вызывает I/O. In-flight проверка может закончиться с уже полученным snapshot; replacement — не cancellation barrier.

trustedAt — время успешно подтверждённого trusted fetch, **не mtime и не новое время на каждый запрос**. Snapshot age ≥60s или future → ErrKeysUnavailable. Remote resolver будет в J5: до него сетевого refresh здесь нет. Нельзя помечать старый кеш свежим fetch для обхода срока. Создавать один owner на instance, не на запрос.

Локально проверен overlap old+new keys и отказ старого token после удаления key. Реальные fleet rollout, emergency distrust/restore и сетевые отказы остаются J5/J7/A8; смена snapshot сама по себе не доказывает distributed revoke.

Admission: до 8 signatures/32 verifications на owner, без очереди; перегрузка ErrBusy. Context проверяется до/после операции; фиксированная crypto operation не прерывается посередине, но отменённый результат не возвращается успешным. Никаких SQL/Redis/network calls внутри primitives. Это лимиты, не measured RPS; budgets суммируются по owners/instances.

Ошибки: ErrInvalidToken/ErrConfiguration/ErrKeysUnavailable/ErrBusy/context cancellation; HTTP mapper ещё не подключён. Пакеты не логируют credentials и не пишут audit на hostile input.

## Приёмка

Unit/race tests: sign→verify, issuer/audience/mode/MFA/times, malformed JSON/compact/JWK, private/mismatched/retired keys, corrupted points, loader/permissions/disabled, immutable buffers, cancellation/admission/concurrent rotation. Короткие fuzz JWT/JWKS не являются исчерпывающим аудитом; evidence — [history](../planning/history.md).

Public issuance/introspection/HTTP middleware, remote resolver и browser/fleet/emergency/restore/load/GC acceptance ещё не реализованы/не выполнены. Старые Auth routes не начали принимать Bearer JWT.

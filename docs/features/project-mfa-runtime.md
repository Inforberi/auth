# MFA в проектном password runtime

MP4.1c, 25 октября2026. Решение зафиксировано до реализации; код и локальные проверки Luna V1/V2 PASS.

- Переиспользовать действующие MFA challenge/TOTP/recovery-code services и session issuance, без копирования криптографии, SQL или алгоритмов проверки. Никаких новых dependencies/schema/ENV.
- После password proof при MFA выдавать ограниченный challenge, не обычную сессию. Полноценная SQL-сессия — только после проверки второго фактора с current auth_version/policy/role guards. Recovery code одноразовый; challenge не становится общим bypass.
- Key/Redis/cipher scopes принадлежат проекту. Challenge или код другого проекта не принимается. До и после операции — current catalog key/profile; результат не раскрывается для stale/suspended/rebound проекта.
- Использовать existing UsePool logical lease и borrowed process resources. Не захватывать connection во время Argon2/проверок кодов и не сохранять pool/services после callback. Не создавать второй SQL pool или project workers.
- Изменение включённости MFA не отключает SQL-защиту enrolled/required-role пользователей. Если необходимые MFA dependencies не готовы — fail-closed. Для required MFA без enrollment сохраняется существующий restricted setup contract, не придумывается автоматическая обычная сессия.
- SMTP/notification outbox не подменять фиктивным successful mailer. Если конкретный сценарий требует недостающую доставку/worker, явно оставить его ограничение и не объявлять readiness. Первый законченный блок должен включать TOTP/recovery verification для enrolled пользователя.
- Новых публичных HTTP routes/readiness/capabilities/UI здесь нет. До публикации — оставшиеся selected dependencies и MP5 guards. Код нового блока не коммитить без отдельного запроса; tests передать отдельной Луне на frozen snapshot.

## Матрица проверки

- Сохранить прежний password-only профиль: disabled MFA не выдаёт обход enrolled/required-role проверки.
- При готовой MFA сборке пароль возвращает challenge без session/token; invalid second factor не создаёт сессию, attempts/TTL/rate limits действуют.
- Valid TOTP и recovery code завершают challenge через существующий SQL/session flow; reuse challenge/code запрещён действующим контрактом.
- Challenge/секрет другого project scope, blocked user, stale auth_version, policy/role change и suspended epoch не дают ordinary session/result.
- Проверить borrowed pool/hasher/Redis lifecycle, отсутствие seed/workers/новых pool, cleanup own synthetic user/factors/known scoped Redis keys. Existing test fixtures и valid encrypted factors должны переиспользовать реальные primitives.
- Исполняемые tests/lint/race/liveSQL+Redis — отдельный чат Luna; локальный субагент только разведка. Не объявлять SMTP/worker/full public-ready подтверждёнными при одной local MFA проверке.

## Внутренний контракт

`ProjectPasswordConfig.MFA` принимает существующую MFA config; default Enabled=false сохраняет прежний fail-closed профиль. Enabled=true собирает только Login pipeline на project-scoped cipher/limiter и existing TOTP authenticator. Loss-all-factors `RecoveryEnabled=true` отклоняется как неподготовленный отдельный сценарий; recovery codes для второго фактора работают независимо от этого флага, как в standalone Login.

`ProjectPassword.Login` использует existing sessionservice.NewLogin: обычному пользователю без MFA выдаётся сессия; enrolled/required-role — challenge с Token/Binding/EnrollmentRequired, без обычного token. `CompleteMFA(ctx,CompleteLoginInput)` выбирает TOTP или recovery code по существующему Recovery boolean и делегирует mfaservice.Login.Complete.

`StartMFAEnrollment` и `ConfirmMFAEnrollment` обслуживают только required enrollment challenge через existing StartRequiredEnrollment/ConfirmRequiredEnrollment. После успешного подтверждения возвращаются recovery codes, auth_version повышается, прежние sessions/challenges отзываются. Затем нужно заново пройти пароль и завершить новый challenge; прежний challenge не превращается автоматически в сессию. Эти изменения выполняются существующей SQL-транзакцией, не новым cleanup-механизмом.

Все операции ограничены timeout проекта и выполняются под UsePool lease, current catalog/profile до/после; на ошибке наружу не возвращается partial result/session/secret. Сервисы создаются локально внутри callback, pool не удерживается после него. SMTP, recovery delivery worker, management emails и неподготовленные primary providers не собираются; AllowPrimary принимает только password. Existing SQL MFA admission/attempts/TTL/one-use и session/auth_version/policy/role constraints сохраняются.

## Проверки блока

Unit: MFA config guards, запрет неподготовленного loss-all-factors recovery, disabled Complete/Enrollment fail-closed. Actual SQL+Redis drill расширяет existing prepared project fixture: required-no-enrollment challenge не создаёт сессию, enrollment/recovery codes/restart, wrong binding/challenge replay/recovery reuse, TOTP/recovery MFA sessions, fixed five factor attempts и suspended project. Cleanup перечисляет только known scoped MFA budget keys; SMTP/outbox/новых pools нет. Existing password-only восемь cases должны остаться успешными.

TOTP test API сверена через Context7 `/pquerna/otp` и installed v1.5.0 source; существующий totp.GenerateCode использует30s/SHA1/sixdigits, production crypto не переписывалась. Локальные проверки завершены; [результат](../planning/history.md#результат-mp41c-project-mfa--25-октября-2026). Cross-project full HTTP/fleet/browsers и другие MFA методы этим блоком не закрываются.

## Приёмка блока

Luna V1: task check и affected race PASS. V2 после typed-nil wiring fix: полный TestPrepareCommandSQL PASS без SKIP, включая disabled/enrolled/required MFA regression и enabled project MFA flow; targeted app/auth+cmd lint PASS (0 issues). Manifest7 совпал до/после и с рабочим source. PG18.6 TLS/SCRAM и Redis8.2 DB15 fixtures удалены, DB15 пуста; cleanup55006 не повторился. Это internal local acceptance, не public/full MP4/fleet. Проверенный блок подготовлен к запрошенному пользователем коммиту.

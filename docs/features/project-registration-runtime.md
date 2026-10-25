# Проектная регистрация по email и паролю

MP4.1g,25 октября2026. Решение перед реализацией.

- Переиспользовать существующие Register, сохраняемую Auth policy, registration transaction adapter и общий session/MFA coordinator. Не копировать SQL/правила или создавать второй registration flow.
- Выбранный current project key/data key, scoped Redis и process-wide bounded hasher; logical UsePool lease без удержания physical connection во время hash. После операции повторно сверять key, не выдавать token/result stale проекта.
- Политика disabled/optional/required применяется существующим SQL под lock: disabled не ставит verification письмо и не помечает email подтверждённым; optional допускает session по текущим правилам; required возвращает verificationRequired без session до подтверждения.
- Verification challenge/ciphertext/outbox/audit и account/contact/credential/profile создаются одной существующей транзакцией. Session создаётся после commit отдельно. Ошибка выдачи session/финального guard не доказывает rollback account; не запускать повторную регистрацию как компенсацию.
- Email URL — trusted HTTPS origin выбранного проекта, не request/Host/platform fallback. Для профиля с письмом использовать existing project scoped cipher и outbox delivery prerequisites; disabled registration не должна требовать SMTP.
- Disabled password/registration, concurrent duplicate, auth policy change/suspend, invalid input, rollback и resource bounds остаются fail-closed. Default role/permissions выдаёт существующий server-side registration contract, caller не назначает привилегии.
- Не открывать HTTP/readiness/UI, не добавлять deps/schema/worker/ENV seed. Внутреннюю assembly и lifecycle доставки использовать из MP4.1e/f.
- Достаточные проверки: formatter/diff; Luna task check/affected race и actual project SQL+Redis matrix disabled/optional/required/no-init/no fallback, transaction rollback/duplicates/session guards. Исходники проверяющий не меняет.

## Реализация

`ProjectPassword.Register(ctx,email,password,userAgent,ip)` — внутренний API. `ProjectPasswordConfig.RegistrationVerification` необязателен; содержит trusted HTTPS Origin и существующий account verification Config. Root key из него игнорируется: используется только key выбранного проекта. Constructor копирует настройки, проверяет URL/TTL/limits и не сохраняет caller pointer или root string в cfg. Проверка HTTPS origin переиспользуется email recovery assembly, не дублируется.

Без verification config регистрация в disabled policy всё равно использует existing scoped AllowRegistration (defaults5/IP и100/project за минуту). С явной конфигурацией — её limits. Они действуют до hash; общий bounded hasher остаётся process dependency. Если SQL policy стала optional/required, а config отсутствует, callback возвращает ErrUnavailable и откатывает account transaction; потеря письма не замалчивается.

Request-local account producer связывается через существующий assembleRegistration и QueueInTransaction на том же pgx.Tx. Он только готовит ciphertext, поэтому не требует SMTP mailer/сетевого вызова в транзакции. В optional/required запись outbox может ожидать настройки/восстановления SMTP: успешная постановка не означает готовность транспорта или доставку. Перед будущей публикацией registration route/readiness отдельно проверить selected mail prerequisites; синхронный SMTP probe на каждую регистрацию не добавляется. Disabled не делает SMTP reads или автоматическую верификацию email.

Общая passwordService assembly переиспользуется Login/Register и сохраняет session/MFA/policy guards. Register не превращён в отдельный MFA login flow: существующий CreateSessionAtVersion не несёт MFA proof; если SQL требует MFA, session выдача отказывает после account commit. Клиент должен использовать предусмотренный login/enrollment flow, а не повторять регистрацию как автоматический вход. Required email verification возвращает verificationRequired=true без raw token. Подтверждение email само сессию не создаёт; затем возможен обычный Login.

Current key проверяется до начала операции и после её результата. Suspend во время hash может совпасть с уже допущенной account/session transaction; финальный guard не выдаёт result/token, но не обещает распределённый rollback committed записей. Policy password/registration повторно блокируется SQL перед commit — здесь изменение запрета откатывает account transaction.

## Проверки

Добавлены unit factory/origin/key override/caller mutation cases и actual project SQL+Redis drill в TestPrepareCommandSQL: disabled/optional/required, no SMTP row, required confirm→Login, отсутствие verifier и outbox failure с rollback (без orphan users), password/registration switches, concurrent duplicate (один user/session), policy/suspend во время hashing и свободное единственное SQL connection. Cleanup восстанавливает policy/SMTP и удаляет только synthetic users/известные scoped Redis keys, сохраняя parent login-global key.

Formatter/diff выполнены main. Luna V2: task check exit0/lint0, cmd race exit0 и actual full TestPrepareCommandSQL exit0 без SKIP; все registration cases PASS. V1 app/auth race PASS сохраняется, V2 менял только fixtures. Manifest8 совпал до/после и с main, owned cleanup подтверждён/RedisDB15 пуста. Snapshot `/private/tmp/auth-project-registration-v2.4i7xfb6u`; подробности — history. Нет новых deps/schema/ENV seed/pools/workers/public routes/readiness. Load/fleet/UI приёмка не закрыта.

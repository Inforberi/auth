# Вход по одноразовому email-коду — A3.4a-local

Реализован backend отдельного passwordless метода. Выключен по умолчанию через EMAIL_OTP_ENABLED=false. Это не email verification и не MFA. Внешний SMTP/browser/fault/load прогон не выполнен; UI будет позже.

J4b.2b.2-local добавляет внутренний [email-код для JWT-входа](native-email-otp.md): общий mail/limits/consume pipeline с отдельным API profile/target и HMAC binding. App/native HTTP ещё не подключены; публичные ручки ниже остаются браузерными.

A5.2c добавляет отдельный [email proof для управления MFA](mfa.md#подтверждение-управления-mfa-по-почте-a52c-local), включаемый EMAIL_REAUTHENTICATION_ENABLED независимо от login. Он требует live session и уже verified owned contact external-only аккаунта, не добавляет адрес и не создаёт сессию. Generator/encrypted outbox/delivery/лимиты переиспользуются, но purpose/verifiers/cookies и SQL операции различаются; код одного сценария не подходит другому. Worker запускается при любом из этих enabled профилей. Тема и тело письма явно различают вход и подтверждение MFA; старые queued login payloads без subject сохраняют прежнюю тему.

## Поддержанный профиль

Вход разрешён только для существующего active, не удалённого пользователя с подтверждённым текущим login email и постоянными password credentials. Код не требует знания пароля, но не регистрирует неизвестного пользователя, не подтверждает неподтверждённый адрес, не выбирает прежний контакт после смены email и не активирует pending/temporary account.

Этот scope выбран как минимальный безопасный первый профиль. Самостоятельная passwordless регистрация, добавление email-метода external-only пользователю и per-user preferences пока не реализованы; перед расширением нужны отдельные ownership/registration/recovery rules. Одинаковый email от внешнего провайдера не привязывает аккаунт.

## API

| Метод | Тело | Успех |
| --- | --- | --- |
| POST /api/v1/auth/email-otp/request | `{"email":"user@example.test"}` | 202 `{"status":"accepted"}`, flow cookie |
| POST /api/v1/auth/email-otp/confirm | `{"code":"01234567"}` | 200 `{"status":"ok"}`, обычная session cookie |

Обе ручки требуют один точный Origin из AUTH_ALLOWED_ORIGINS, application/json и применяют no-store. Выключенный профиль не подключает routes. Swagger содержит optional контракт, независимо от enabled ENV.

Request возвращает одинаковый статус/тело и cookie одинакового формата для допустимого/неизвестного/неподтверждённого/заблокированного адреса. Это скрытие состояния в публичном контракте, не обещание одинаковой SQL latency. 202 не гарантирует доставку письма.

Cookie `__Host-email-otp`: случайные 32 байта, base64url, Secure/HttpOnly/SameSite=Lax/Path=/, без Domain, срок равен OTP TTL. Confirm должен выполняться в том браузере, где был request; cookie одного flow недостаточно без правильного кода. Нет code/token/owner ID в JSON request-ответе.

Код — ровно 8 ASCII цифр, включая ведущие нули. Генерация crypto/rand без modulo bias, uniform 0–99999999. Не логировать и не сохранять код в analytics/localStorage. После пяти корректно оформленных неверных попыток challenge непригоден; ошибки формата отсекаются до SQL.

Confirm получает owner только из серверного challenge, не принимает email/userID. Дубликат или отсутствие flow cookie не даёт authority. Неверный код/expired/replaced/replayed/unknown/inactive/version mismatch имеют общий `400 invalid_email_login`. Ошибка не устанавливает и не очищает обычную cookie другого уже вошедшего пользователя.

## Хранение и одноразовость

SQL challenge содержит keyed HMAC verifier короткого кода, digest browser binding, текущие user/email/version, TTL и счётчик. HMAC связывает code с конкретным browser secret; используется существующий EMAIL_OUTBOX_KEY и отдельный purpose `email-login:v1`. Обычный SHA-256 короткого кода не применяется.

На пользователя действует один challenge. Новая допустимая выдача заменяет старый вместе с outbox. Поэтому повторный request в другой вкладке/браузере отменяет прежний код. В одном браузере одна OTP flow cookie; не вести несколько независимых email-логинов одновременно.

Consume блокирует user до challenge, повторно проверяет текущие status/version/login contact/verification/expiry/attempts. Неверная попытка коммитит счётчик: публичная invalid_email_login возвращается **после** commit, иначе rollback вернул бы попытки.

Успех удаляет challenge, каскадно удаляет его outbox и пишет audit одной транзакцией. Нет лишнего consumed marker или сохранённого «успешного кода» для cleanup. При ошибке audit весь consume откатывается; из параллельных запросов проходит один.

Затем вызывается существующий SessionService.CreateSessionAtVersion. Это две последовательные транзакции, как отдельное доказательство и выдача сессии, а не atomic consume+session. При последующем сбое SQL/ответа код остаётся потреблённым: начать новый request с учётом cooldown. SQL session issuance повторно проверяет текущий статус/версию, поэтому block/reset/delete между этими шагами не выдаёт stale доступ.

Код не устанавливает password_verified_at, не даёт MFA/fresh password proof, не назначает роли и не меняет пароль. Успешный confirm заменяет текущую browser session cookie новой; прежняя SQL-сессия от этого автоматически не отзывается.

## Доставка и cleanup

Payload письма зашифрован AES-GCM с OTP purpose. Существующий SMTP sender/connection policy, pool и app lifecycle переиспользуются. Очередь email_login_outbox отдельная: не смешиваем verification/reset/login tokens.

Чтобы не копировать третий polling loop, одинаковый цикл account/reset delivery вынесен в `internal/auth/delivery` и используется тремя обработчиками очередей. Pace сохранён: tick 1s, до 10 jobs, остановка на пустом claim, cancellation и ограниченные deadlines. OTP worker запускается только при enabled профиле и использует общий SQL pool.

Claim — indexed due lookup, SKIP LOCKED, lease 30s; не выполняет global cleanup. SMTP ограничен 20s, SQL claim/ack — 5s. До пяти попыток с backoff 30/60/120/240s, acknowledgement только текущего lease. Техническая ошибка расшифровки/SMTP не считается успешной отправкой.

Exactly-once SMTP не обещается. После замены challenge уже взятое письмо может уйти, но старый код больше не действует. Версия/status/login-contact проверяются также при claim.

Существующий retention worker очищает expiry/outbox/exhausted jobs ограниченными партиями даже после выключения OTP. OTP audit подчиняется SECURITY_AUDIT_RETENTION_DAYS. При кратковременном security transition version/status немедленно закрывают authority, даже если stale ciphertext ещё ожидает физического cleanup.

## ENV и resource budgets

| ENV | Default | Значение |
| --- | --- | --- |
| EMAIL_OTP_ENABLED | false | Request/confirm и delivery worker |
| EMAIL_OTP_TTL | 5m | 1m–10m |
| EMAIL_OTP_RESEND_INTERVAL | 1m | Окно одной выдачи на email; минимум 1m и меньше TTL |
| EMAIL_OTP_REQUEST_PROJECT_ATTEMPTS_PER_MINUTE | 100 | Общие request attempts всех API проекта |
| EMAIL_OTP_CONFIRM_PROJECT_ATTEMPTS_PER_MINUTE | 1000 | Общие confirm attempts всех API проекта |

Request дополнительно: 10/IP/min, 3/email/15min, одна попытка выдачи/email/resend interval. Confirm: 10/IP/min и пять неправильных кодов на SQL challenge. Redis keys — scoped HMAC, без plaintext email/IP. Redis failure закрывает операции; нет SQL fallback без ограничений.

Общий request deadline 5s; confirm 10s, consume transaction 5s. Crypto/SMTP не удерживают SQL transaction. Нет дорогого Argon2 для восьмизначного кода, отдельного pool, SDK или безлимитной очереди.

429 — rate_limited с Retry-After: 60 (длинное 15-минутное окно может оставаться исчерпанным после этих 60 секунд). 503 — temporarily_unavailable. Generic acceptance не отменяет budgets. Превышение cooldown даёт 429 одинаково для всех адресов; не заменяет cookie/действующий challenge.

Пулы/budgets считаются по всем репликам и workers. Default request budget 100/мин согласован с текущим cleanup 100 кандидатов/мин, чтобы поток полностью брошенных кодов не опережал очистку. Успешные challenges/outbox удаляются сразу. При увеличении лимита выдачи согласовать batch/interval и SMTP capacity, измерить backlog и настроить alerts. Этот budget — защита выдачи писем, не максимальный API RPS.

## Проверки и ограничения release

Проверены input/disabled до зависимостей, HMAC/encrypted payload, отсутствие PII в limiter keys, error mapping, cookies/duplicate binding, Origin/disabled routes, env/Swagger contracts, SMTP/cipher failure acknowledgement и общий worker cancellation/batch.

Disposable PostgreSQL 18.6: up/down/up, обычная SQL session после consume без password fresh marker, replacement/replay, 16 параллельных правильных подтверждений — один успех; 16 неправильных — ровно пять сохранённых попыток, затем правильный код тоже не проходит. Проверены unverified/blocked/deleted/pending/version/expiry/смена current credentials, неизвестный email без создания пользователя, delivery lease/stale ack, audit rollback, bounded retention.

Реальная внешняя почта/HTTPS browser, новый профиль при реальном Redis fault, полная multi-instance mixed load и memory/GC приёмка ещё открыты. Старые password/verification/recovery/Telegram сценарии сохраняются. EMAIL_OTP_ENABLED и sample ENV добавлены, реальные secrets/.env и рабочая БД не изменяются.

Расширены только исходные 000001 up/down. Уже применённая схема требует отдельно согласованного upgrade; down/reset рабочей БД запрещён.

# Подтверждение email

Реализация 5.1, 9 октября 2026. Владелец — `internal/auth/account`; registration composition — `internal/app/auth/account.go`. Password repository остаётся владельцем текущей регистрационной транзакции, callback связывает account adapter на том же `pgx.Tx`. Бизнес-сервисы не получают транзакцию или concrete repository.

## Сценарий

Регистрация создаёт account/contact/credential/profile, verification challenge, зашифрованный outbox и audit одной транзакцией. Outbox/audit failure откатывает регистрацию. Сессия создаётся после commit; частичный сбой «account создан, SQL session не создан» остаётся задачей 6.6.

Login/register разрешены без подтверждения. Из существующих чувствительных routes `change-password` требует verified login email активного, не удалённого пользователя: 403 `email_not_verified`, при недоступности SQL — 503. С этапа 5.2 session middleware использует SQL ledger и проверяет status/version; полная приёмка и управление блокировками остаются 5.4/6.2. Будущие продуктовые/roles/billing routes обязаны явно применять соответствующие политики.

`POST /api/v1/auth/email/resend` с `{"email":"user@example.com"}` возвращает 202 `{"status":"accepted"}` для существующего/неизвестного/подтверждённого/заблокированного email и cooldown. Malformed email — 400, limit — 429, dependency failure — 503. Успешная постановка не обещает успешную доставку.

`POST /api/v1/auth/email/verify` с `{"token":"..."}` подтверждает адрес и удаляет challenge/outbox вместе с audit. Unknown/replaced/replayed/expired/blocked token — одинаковый 400 `invalid_verification`. Подтверждение не создаёт сессию и не меняет пароль. При конкурентном consume успешен только один запрос. На границе `now >= expires_at` токен недействителен.

В письме ссылка на frontend из `EMAIL_VERIFICATION_URL`, не backend GET endpoint. Frontend должен показать явное подтверждение, отправить POST, удалить token из адресной строки, выставить `Referrer-Policy: no-referrer`, не подключать analytics/сторонние ресурсы на странице с token. Email scanners/GET не должны автоматически подтверждать адрес. Frontend в этом шаблоне пока отсутствует.

## Токен и доставка

Token — 32 случайных байта, base64url без padding; SQL хранит SHA-256 verifier. Это высокоэнтропийная ссылка, не короткий угадываемый OTP. Purpose задан отдельной таблицей, owner — FK на email; неправильные попытки ограничены IP, resend — IP/email. Resend после cooldown удаляет прежний challenge/outbox, создавая новый; старая уже отправленная ссылка становится недействительной.

Outbox использует AES-256-GCM, отдельный `EMAIL_OUTBOX_KEY`, случайный nonce, authenticated purpose version. Raw token/link/recipient в SQL payload не открыты. Worker запускается вместе с API, завершает SMTP по cancellation/deadline до закрытия DB/Redis. SQL transaction не удерживается во время SMTP.

Claim использует SQL lease 30 секунд и `SKIP LOCKED`; SMTP bounded 20 сек. При failure — до 5 попыток с backoff 30/60/120/240 секунд, lease защищает от stale completion. Возможна повторная доставка после crash или неоднозначного SMTP результата: exactly-once не обещается. После успеха/исчерпания попыток ciphertext удаляется, после expiry удаляется challenge и его outbox. Cleanup выполняется работающим worker; при остановленном приложении expired данные остаются до запуска. Прежний leased worker после resend может отправить старое письмо, но его token уже недействителен.

Audit сейчас покрывает только `email_verification_issued` и `email_verified`, без email/token/payload. Общая audit model, доступ/retention и metrics/alerts ещё относятся к 6/14, не считаются реализованными этой таблицей.

## Настройки и ограничения

Обязательны `EMAIL_VERIFICATION_URL` и `EMAIL_OUTBOX_KEY` (base64 32 случайных байт). `EMAIL_VERIFICATION_TTL=30m` (1m–1h), `EMAIL_VERIFICATION_RESEND_INTERVAL=1m` (не меньше минуты и меньше TTL). Production требует HTTPS, отдельный ключ вместо локального примера и `SMTP_REQUIRE_TLS=true`; проверяется сертификат STARTTLS, TLS не ниже 1.2. Context-aware SMTP sender используется verification и reset workers; legacy dev Send остаётся отдельной задачей 6.5. EMAIL_OUTBOX_KEY шифрует обе очереди с разными authenticated purposes; ротация требует согласованной обработки обеих.

Ключ хранить в secrets manager, не в Git/логах. Смена ключа не поддерживает keyring: до ротации остановить issuance и дождаться очистки outbox, затем согласованно сменить ключ у всех экземпляров. После аварийной смены reissue через resend; старый ciphertext не расшифруется. Новый проект получает новый ключ. Изменение URL/key/durations проверяется при startup, placeholders production example не рабочие secrets.

Redis fixed-window limits: register 5/IP/min + 100/global/min, resend 10/IP/min + 3/email/15min, confirm 20/IP/min. Keys — purpose-scoped HMAC, не открытый email/IP. Redis failure не отключает защиту. IP — socket peer: `X-Forwarded-For` не доверяется; за proxy клиенты разделят лимит. Trusted proxy policy, динамические лимиты и нагрузочный подбор выполняются в 6.4/6.5. Worker опрашивает очередь раз в секунду и последовательно обрабатывает до 10 писем за tick, прекращая пустой batch; throughput/backpressure/alerts проверяются перед release. SQL issuance/consume/gate/claim имеют deadline 5 секунд; SMTP — 20 секунд.

Существующая `000001` не обновится автоматически: нужен согласованный перенос данных. Рабочую БД не сбрасывать. Локальная HTTPS frontend, реальная внешняя почта, browser flow, общий CSRF/fresh-auth и session revocation ещё не проверены/не реализованы. Шаблон не готов к production release.

## Проверки

Unit/HTTP tests: malformed token/input, failed-closed limiter/gate, скрытие dependency details, socket IP, AES round-trip/tampering/random nonce, config, delivery retry, SMTP TLS requirement/cancellation. API contract tests охватывают новые routes/DTO/status.

Opt-in SQL fixture `TestPostgresSchema` проверяет migrations up/down/up, registration+outbox rollback, cooldown, replacement/replay/expiry, concurrent consume, leased delivery/retry и ciphertext cleanup. Только disposable localhost `auth_schema_test`, как в [схеме](schema.md). `TestLimiterRedis` с `AUTH_EMAIL_TEST_REDIS_ADDR` — отдельная disposable loopback Redis: 30 concurrent attempts, ровно 5 accepted, TTL и unavailable behavior. SMTP delivery в SQL-тестах — test double; внешний staging/provider не проверен.

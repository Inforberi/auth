# Временный пароль — backend 5.7c

Выключенный по умолчанию дополнительный способ ручного создания пользователя. Приглашения остаются основным вариантом. Профиль независим от публичной регистрации и INVITATIONS_ENABLED; административных HTTP-ручек и UI пока нет.

## Создание и однократная выдача

`App.TemporaryPasswords.Provision` принимает actor UUID, отдельный UUID idempotency key и email. Сервис генерирует 256-битный случайный пароль, использует общий bounded Argon2 и атомарно создаёт pending user/profile/неподтверждённый контакт, provisioning identity, временный credentials и audit. Actor — attribution, не authorization; доверенный caller обязан проверять полномочия до вызова. Повтор той же команды возвращает UUID и Reused=true без пароля; другой email/профиль с тем же actor/key конфликтует.

Plaintext возвращается только из первого успешного внутреннего вызова; поле Password исключено из автоматической JSON-сериализации. Не логировать результат, не сохранять его в idempotency cache и не отправлять обычным email. Защищённая operator выдача после permissions/MFA/fresh-auth/CSRF будет частью admin transport/UI. Если ответ потерян, восстановить секрет из БД нельзя: нужна отдельная команда перевыпуска после cooldown. ExpiresAt при replay первоначального создания не восстанавливается, это не новое полномочие.

В БД — Argon2 hash и purpose-scoped SHA-256 fingerprint исключительно случайного 256-битного секрета. Fingerprint нужен для запрета выбрать тот же секрет постоянным паролем без дополнительного Argon2; не применять этот подход к пользовательским паролям. Проверка constant-time, fingerprint не зависит от ротации operational key. Ни plaintext, ни setup token не хранятся в audit. Indexed command lookup до hash исключает Argon2 и mutation на committed retry; первый конкурентный вызов всё равно проверяет identity внутри транзакции. Это дополнительное дешёвое чтение для экономии криптографического бюджета, не cache authority.

## Первый вход и установка пароля

- POST `/api/v1/auth/temporary-password/login`: email/временный пароль. Ответ `status=password_change_required`, token и expiresAt; без session cookie. Использует те же LOGIN_IP/EMAIL/GLOBAL_LIMIT и тот же Redis/scoped key, что обычный вход. После Compare транзакция повторно проверяет текущий hash/version/status/expiry. Каждый успешный вход заменяет прежний setup token: одновременно действителен только один.
- POST `/api/v1/auth/temporary-password/complete`: token, password, confirmPassword. Проверяет форму токена, policy/confirmation и Redis budgets; indexed preflight до hashing, актуальность снова проверяется внутри транзакции. Новый пароль должен отличаться от временного. Одноразовое consume, запись обычного credentials, отзыв временных credentials/полномочий/сессий, active/version/activation marker и audit атомарны.
- После установки требуется обычный login. Email остаётся неподтверждённым; существующий verified-email gate продолжает действовать. Ролей/permissions/grants не выдаём. MFA ещё отдельный этап 13.1, не заявляется реализованным.

Обе ручки opt-in, POST-only, no-store и RequireOrigin по AUTH_ALLOWED_ORIGINS. Нет GET mutations. Setup token canonical base64url 32 bytes, в SQL хранится digest; его срок не превышает ни SetupTTL, ни остаток TTL временного пароля. До установки пароль не является обычным credentials: account остаётся pending, SQL session issuance/validation/refresh требуют active. Стандартный login и forgot/reset не дают обхода; invitation reissue/activation запрещены при password_change_required. Future OIDC/Telegram/MFA должны сохранять этот account gate, не переводить pending в active самостоятельно.

## Перевыпуск и отзыв

`App.TemporaryPasswords.Reissue` принимает actor/user UUID и отдельный idempotency key. Только прежний pending temporary account с сохранённым неподтверждённым контактом. Меняет временный hash/TTL, увеличивает auth_version, удаляет прежнее setup authority и пишет audit одной транзакцией. Новый plaintext выдаётся лишь впервые; replay не раскрывает его и не обновляет TTL. Другой target с тем же actor/key конфликтует. Новая команда следует cooldown, включая первичную выдачу.

Block/delete удаляют временные credentials и каскадно setup token; статус/version также закрывают authority. Unblock не подменяет обязательную установку. Expiry закрывает доступ немедленно; физическая очистка идёт существующим bounded retention worker по индексам. Durable password_change_required/issued_at и command metadata переживают cleanup: после expiry можно перевыпустить для того же UUID, но нельзя воскресить старый секрет или заменить поздний retry новой выдачей. Автоматическая очистка idempotency metadata не добавлена.

## Env и бюджеты

| Env | Default | Назначение |
| --- | --- | --- |
| `TEMPORARY_PASSWORD_ENABLED` | false | Независимый профиль: internal provisioning/reissue и public login/complete |
| `TEMPORARY_PASSWORD_TTL` | 24h | Срок временного пароля; 1m–7d |
| `TEMPORARY_PASSWORD_SETUP_TTL` | 10m | Срок setup authority; 1m–30m, не больше password TTL |
| `TEMPORARY_PASSWORD_REISSUE_COOLDOWN` | 1m | Интервал выдач для одного пользователя; 1s–24h |
| `TEMPORARY_PASSWORD_ISSUE_ACTOR_ATTEMPTS_PER_MINUTE` | 30 | Создание/перевыпуск: попытки одного инициатора за минутное окно |
| `TEMPORARY_PASSWORD_ISSUE_PROJECT_ATTEMPTS_PER_MINUTE` | 100 | Создание/перевыпуск: общие попытки всех API проекта за минутное окно |
| `TEMPORARY_PASSWORD_SETUP_PROJECT_ATTEMPTS_PER_MINUTE` | 100 | Установка постоянного пароля: общие попытки за минутное окно; дополнительно 10/IP/min |

Это защитные квоты, не capacity/RPS. Redis failure/hash overload/SQL failure дают 503; quota — 429 и Retry-After 60; expired/replayed/blocked/unknown/wrong authority — общий 400 invalid_temporary_password. Policy/confirmation/same-password — отдельные 400. Context сценария 10s, SQL read/transaction 5s. Нет отдельного pool/worker/crypto queue, cache-only authority или SQL fallback. Cleanup добавляет две indexed bounded операции к текущему retention проходу, в том числе после выключения профиля; SQL authority и индексы сохраняются.

## Проверки и оставшиеся границы

Unit/HTTP/Swagger/env tests и race: validation order, disabled/Origin/GET/format/errors/no-cookie/no-store, secret omission on replay/serialization, quotas/failure/busy hashing, preflight до hash и same-password. Disposable PostgreSQL: up/down/up, 16 parallel provision/reissue — одна выдача plaintext, 16 first logins — один действующий setup, 16 complete — один успех; stale hash snapshot, version/expiry/cleanup, block/delete/unblock, ordinary login/session/status/reset/invitation bypass, reissue-complete race, atomic creation/completion audit rollback и отсутствие email verification.

Это локальная backend-приёмка, не безопасная внешняя operator delivery, browser UI, Redis fault E2E всего сценария или нагрузочный тест. Admin publication требует 10/13.1, UI/settings — в конце; load 6.8b перед release. Рабочая БД/secrets не меняются. Расширена только исходная 000001; перенос на уже применённую схему согласовать отдельно, не делать down/reset рабочей базы.

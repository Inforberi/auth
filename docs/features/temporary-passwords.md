# Временный пароль — backend 5.7c

Выключенный по умолчанию дополнительный способ ручного создания пользователя. Приглашения остаются основным вариантом. Профиль независим от публичной регистрации и INVITATIONS_ENABLED; protected admin выдача подключена в 13.2a.2-local, UI ещё нет.

## Создание и однократная выдача

`App.TemporaryPasswords.Provision` принимает principal (user UUID + hash текущей SQL-сессии), отдельный UUID idempotency key и email. Сервис генерирует 256-битный случайный пароль, использует общий bounded Argon2 и атомарно создаёт pending user/profile/неподтверждённый контакт, provisioning identity, временный credentials и audit. `accounts.users.manage`, active/current session, fresh password + MFA и существующий factor проверяются в guarded SQL preflight/replay, затем повторно внутри write transaction после hashing. Это проверка актуальности при записи, не дублирование domain validation. Повтор той же команды возвращает UUID и Reused=true без пароля; другой email/профиль с тем же actor/key конфликтует.

Plaintext возвращается только из первого успешного вызова; поле Password service-result исключено из автоматической JSON-сериализации, admin handler формирует отдельный one-time DTO. Не логировать результат, не сохранять его в idempotency cache и не отправлять обычным email. Если ответ потерян, восстановить секрет из БД нельзя: нужна отдельная команда перевыпуска после cooldown. ExpiresAt при replay первоначального создания не восстанавливается, это не новое полномочие.

В БД — Argon2 hash и purpose-scoped SHA-256 fingerprint исключительно случайного 256-битного секрета. Fingerprint нужен для запрета выбрать тот же секрет постоянным паролем без дополнительного Argon2; не применять этот подход к пользовательским паролям. Проверка constant-time, fingerprint не зависит от ротации operational key. Ни plaintext, ни setup token не хранятся в audit. Indexed command lookup до hash исключает Argon2 и mutation на committed retry; первый конкурентный вызов всё равно проверяет identity внутри транзакции. Это дополнительное дешёвое чтение для экономии криптографического бюджета, не cache authority.

## Первый вход и установка пароля

- POST `/api/v1/auth/temporary-password/login`: email/временный пароль. Ответ `status=password_change_required`, token и expiresAt; без session cookie. Использует те же LOGIN_IP/EMAIL/GLOBAL_LIMIT и тот же Redis/scoped key, что обычный вход. После Compare транзакция повторно проверяет текущий hash/version/status/expiry. Каждый успешный вход заменяет прежний setup token: одновременно действителен только один.
- POST `/api/v1/auth/temporary-password/complete`: token, password, confirmPassword. Проверяет форму токена, policy/confirmation и Redis budgets; indexed preflight до hashing, актуальность снова проверяется внутри транзакции. Новый пароль должен отличаться от временного. Одноразовое consume, запись обычного credentials, отзыв временных credentials/полномочий/сессий, active/version/activation marker и audit атомарны.
- После установки требуется обычный login. Email остаётся неподтверждённым; существующий verified-email gate продолжает действовать. Ролей/permissions/grants не выдаём. Дальнейший вход соблюдает действующую MFA policy, смена временного пароля её не обходит.

Обе ручки opt-in, POST-only, no-store и RequireOrigin по AUTH_ALLOWED_ORIGINS. Нет GET mutations. Setup token canonical base64url 32 bytes, в SQL хранится digest; его срок не превышает ни SetupTTL, ни остаток TTL временного пароля. До установки пароль не является обычным credentials: account остаётся pending, SQL session issuance/validation/refresh требуют active. Стандартный login и forgot/reset не дают обхода; invitation reissue/activation запрещены при password_change_required. Future OIDC/Telegram/MFA должны сохранять этот account gate, не переводить pending в active самостоятельно.

## Перевыпуск и отзыв

`App.TemporaryPasswords.Reissue` принимает principal, user UUID и отдельный idempotency key. Только прежний pending temporary account с сохранённым неподтверждённым контактом. Меняет временный hash/TTL, увеличивает auth_version, удаляет прежнее setup authority и пишет audit одной транзакцией. Новый plaintext выдаётся лишь впервые; replay не раскрывает его и не обновляет TTL. Другой target с тем же actor/key конфликтует. Новая команда следует cooldown, включая первичную выдачу.

## Admin API 13.2a.2-local

| Метод | Body | Результат |
| --- | --- | --- |
| POST `/api/v1/admin/users/temporary-password` | `{idempotencyKey,email}` | 201 при первом commit; 200 при replay |
| POST `/api/v1/admin/users/{id}/temporary-password` | `{idempotencyKey}` | 200 при первом перевыпуске и replay |

Требуются `TEMPORARY_PASSWORD_ENABLED` + `MFA_ENABLED`, `__Host-session`, exact allowed Origin и application/json. `INVITATIONS_ENABLED` не требуется. Actor/roles/verified/пользовательский password из JSON не принимаются; сервер выбирает случайный секрет сам. NoRefreshAuth, no-store, новые cookies/session не выдаются. Формат первого ответа:

```json
{"userId":"22222222-2222-4222-8222-222222222222","reused":false,"expiresAt":"2026-10-16T12:00:00Z","password":"one-time-secret"}
```

Пример секрета выше — только иллюстрация DTO, не допустимый тестовый credential. При replay `password` **отсутствует**, даже если адаптер ошибочно сохранил поле; у replay создания нет и `expiresAt`, у replay перевыпуска возвращается исходный сохранённый expiry. UI должен показать пароль один раз и передать владельцу по доверенному каналу, без сохранения в history/analytics. Lost response не разрешает перечитать секрет: reissue с новым UUID после cooldown. Повтор исходной команды после activation/block/delete не создаёт новый доступ; guarded replay возвращает лишь прежнюю metadata, если текущий администратор всё ещё авторизован.

Ошибки: 400 invalid_json/invalid_email; 401 unauthorized; 403 forbidden/fresh_auth_required/invalid_origin; 409 provisioning_conflict/email_unavailable/target_unavailable/issuance_cooldown; 429 rate_limited + Retry-After 60; 503 temporarily_unavailable. UUID/command conflicts используют существующий domain provisioning_conflict. Выдача не является reset активного аккаунта; для него обычные password recovery/change. Роли назначаются отдельной Access mutation.

SQL lock order Access → actor/target users по UUID → session → command/contact/credential. Replay/preflight — короткая guarded transaction до Argon2, write — повторная авторизация после него; Redis/hashing вне row locks. Password transactions явно Read Committed, независимо от default isolation DB-role: после ожидания Access lock видят committed revoke, а не старый snapshot. Один existing pool и общий bounded hasher; новых workers/pools/собственной crypto queue нет. Существующий idempotency key не становится постоянным разрешением после отзыва прав или истечения fresh proof.

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

Это локальная backend-приёмка, не внешняя operator delivery, browser UI, Redis fault E2E всего сценария или нагрузочный тест. Admin API опубликован с SQL guards в 13.2a.2-local, UI/settings — в конце; A8-admin-e2e и load 6.8b перед release остаются обязательными. В этом подэтапе схема/миграции не менялись, рабочая БД/secrets не затрагивались. Перенос на уже применённую схему согласовать отдельно, не делать down/reset рабочей базы.

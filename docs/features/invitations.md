# Создание аккаунтов и приглашения

## Реализованный профиль 5.7a

`account/service/ProvisionService.Provision` — сценарий, независимый от public registration, доступный через `App.Provisioning` и protected admin API 13.2a.2-local. Вместо доверенного ActorID принимает проверенный principal (user UUID + hash текущей SQL-сессии). `accounts.users.manage`, active/current session, свежие password + MFA и существующий factor проверяются в транзакции записи, в том числе при replay. UUID сам по себе полномочием не является.

Вход: principal из session context, отдельный UUID idempotency key, необязательный email, флаг Invite. Без Invite создаются UUID/профиль и optional неподтверждённый контакт. С Invite обязателен email; создаются также одноразовый invitation challenge и encrypted mail intent. Все записи, включая audit, коммитятся одной SQL-транзакцией. Аккаунт имеет status `pending`, пароль/сессия/роли/permissions/платные grants не выдаются.

Ключ команды scoped по actor. Повтор с теми же нормализованными параметрами возвращает прежний UUID с Reused=true, без повторного письма. Другие параметры с тем же ключом — конфликт. Чужой/занятый email — конфликт, без auto-merge, новых полномочий или изменения существующего пользователя. Повтор после активации/expiry/delete не создаёт аккаунт или invitation заново. Durable command identity и activation marker сохраняются вместе с UUID; это не полный PII erasure.

## Активация

Письмо содержит frontend URL с token в fragment. GET только открывает будущий UI. Пользователь задаёт пароль; UI отправляет POST `/api/v1/auth/invitations/activate` с `token`, `password`, `confirmPassword`. Требуются точный разрешённый Origin, application/json и no-store. При выключенном профиле маршрут отсутствует; Swagger описывает включённый профиль.

Service проверяет формат token и password policy один раз, затем Redis IP/global limits. Indexed SQL preflight отсеивает неизвестные/неактуальные tokens до Argon2. Hash использует общий bounded budget процесса, параметры не ослаблены. После hash транзакция повторно проверяет актуальность — это защита от block/delete/expiry/concurrent acceptance, не дублирование входной валидации.

Транзакция блокирует user до удаления challenge, проверяет pending/deleted/version/DB expiry, записывает credential для того же owner/contact, подтверждает email, переводит user в active, повышает auth_version, сохраняет activation marker и audit. Ошибка откатывает все изменения. Из конкурентных активаций проходит одна; остальные получают одинаковую invalid_invitation. Invitation не подходит для reset/verification и не создаёт session. После успеха пользователь входит обычным login.

Block/delete атомарно отменяют invitation/outbox. Простое unblock не активирует ранее неактивированный provisioned account: durable activation marker защищает и после expiry cleanup. Общие пароли и административный обход подтверждения не используются.

## Настройки и ресурсы

| Env | Default | Значение |
| --- | --- | --- |
| INVITATIONS_ENABLED | false | Provisioning, admin create/reissue и публичный POST активации; admin routes также требуют MFA_ENABLED |
| INVITATION_URL | не задан | Доверенный frontend URL; HTTPS обязателен в production |
| INVITATION_TTL | 24h | Срок одноразового приглашения; 1m–7d |
| ACTIVATION_GLOBAL_LIMIT | 100 | Попытки активации в минуту для всего проекта |

IP limit — 10/min, HTTP admission и hash concurrency — существующие общие budgets. Redis failure/hash overload/SQL failure — 503; quota — 429, Retry-After 60. SQL lookup/transaction имеют deadline 5s, общий activation context — 10s. Токены не логируются и не возвращаются из provisioning; SQL хранит digest, outbox — AES-GCM payload с текущим EMAIL_OUTBOX_KEY.

Invitation delivery — третья очередь существующего account worker, без нового poller/pool. Очереди обходятся справедливо, каждая не более одного раза за попытку claim. Сохраняются eligibility, UUID leases, SKIP LOCKED, до пяти paced attempts. Успешная отправка удаляет job, но не challenge. Expiry/exhausted cleanup выполняет существующий bounded retention worker по индексам при включённом invitation profile; invitation audit следует SECURITY_AUDIT_RETENTION_DAYS. Expiry не удаляет account/contact автоматически: операторский lifecycle и reservation остаются отдельными сценариями.

## Перевыпуск приглашения — 5.7b

`App.Provisioning.ReissueInvitation` принимает principal, существующий user UUID и отдельный UUID idempotency key. Создания нового пользователя, смены адреса, назначения прав и активации здесь нет. Guard проверяется перед чтением адреса и повторно в транзакции перевыпуска; это разные гарантии доступа к контакту и актуальности записи, не предварительный HTTP Authorize вместо SQL enforcement.

Новая команда допустима только для provisioned pending account без credentials, verification и activation marker, с исходным сохранённым контактом. SQL блокирует пользователя до контакта и повторно проверяет актуальность. В одной транзакции записываются command identity, замена challenge, encrypted outbox, время отправки и `reissued` audit. Старый token/job удаляется; новый token привязан к текущей auth_version и имеет новый TTL. Ошибка любого шага откатывает всё.

Успешный повтор того же actor/key/user возвращает `Reused=true` без повторной отправки. Другая цель с тем же ключом — конфликт. Повторы проходят Redis budgets; при его отказе операция закрыта. Команда не возвращает raw token. Сохранённый `last_invited_at` обеспечивает cooldown и после удаления истёкшего challenge; исходное создание с Invite тоже учитывается. Прошедшее cooldown приглашение можно перевыпустить после expiry или исчерпания доставки, сохранив UUID.

| Env | Default | Назначение |
| --- | --- | --- |
| `INVITATION_REISSUE_COOLDOWN` | 1m | Минимальный интервал между выдачами для одного пользователя; 1s–24h |
| `INVITATION_ISSUE_ACTOR_ATTEMPTS_PER_MINUTE` | 30 | Общие попытки создания аккаунта/выдачи/перевыпуска за минутное окно одного инициатора, включая replay |
| `INVITATION_ISSUE_PROJECT_ATTEMPTS_PER_MINUTE` | 100 | Общие попытки этих команд всех API проекта с общим Redis/scoped key |

Квоты не означают RPS сервиса. Прежние `INVITATION_REISSUE_ACTOR_ATTEMPTS_PER_MINUTE` / `INVITATION_REISSUE_PROJECT_ATTEMPTS_PER_MINUTE` переименованы в `INVITATION_ISSUE_*`: теперь бюджет общий с первичной выдачей. Старые ENV имена больше не читаются; если они были настроены, оператор должен перенести значения. Реальные ENV автоматически не меняются. Redis namespace сохранён, чтобы обновление не обнуляло действующий budget. Cooldown по-прежнему отдельный `INVITATION_REISSUE_COOLDOWN`.

Уже отправленное или находящееся в SMTP письмо отозвать нельзя: даже если старое письмо придёт после перевыпуска, его token недействителен. Delivery/GC остаются прежними, новых workers нет. Durable command metadata хранится как существующие provisioning records; автоматическая очистка ключей не добавлена, чтобы не превращать поздний retry в новое письмо. После retention-удаления исходного контакта replay не восстанавливает его.

## Admin API 13.2a.2-local

| Метод | Body | Результат |
| --- | --- | --- |
| POST `/api/v1/admin/users` | `{idempotencyKey,email?,invite?}` | Первый commit 201 `{userId,reused:false}`, replay 200 `{userId,reused:true}` без новой отправки |
| POST `/api/v1/admin/users/{id}/invitation` | `{idempotencyKey}` | 200 `{userId,reused}`; отдельная команда отправки для существующего pending provisioned account |

Обе ручки требуют включённые `INVITATIONS_ENABLED` и `MFA_ENABLED`, `__Host-session`, точный разрешённый Origin и application/json; без профиля 404, без сессии 401. NoRefreshAuth не продлевает session/freshness; ответы no-store, новых cookies нет. Actor/roles/verified/password из JSON не принимаются. Service один раз проверяет email; SQL constraints и current-state checks остаются отдельной транзакционной гарантией. SQL mutations берут общий Access lock до user/session locks, чтобы committed отзыв management permission был виден после ожидания.

Пример создания с приглашением:

```json
{"idempotencyKey":"11111111-1111-4111-8111-111111111111","email":"user@example.com","invite":true}
```

`invite` по умолчанию false: это только pending UUID/profile, не готовый доступ. Без контакта приглашение отправить нельзя. Для повторной отправки использовать отдельную reissue-команду, не менять параметры старого ключа. JSON не содержит raw invitation token; письмо отправляет существующий outbox worker после commit. HTTP success означает постановку intent, не подтверждение получения письма. Роли назначаются отдельно через [Access API](roles-permissions.md#http-api-a43-local).

Ошибки: 400 `invalid_json`/`invalid_email`; 403 `forbidden`/`fresh_auth_required`/`invalid_origin`; 409 `provisioning_conflict` (в том числе некорректный UUID команды/цели), `email_unavailable`, `target_unavailable`, `issuance_cooldown`; 429 `rate_limited` с Retry-After 60; 503 `temporarily_unavailable`. Текущие permissions/password/MFA обязательны и для committed replay после смены сессии: idempotency не заменяет authority. До подготовки письма применяются Redis actor/project budgets; таймаут SQL/общей операции — 5s. Административное чтение адреса и последующая запись используют короткие отдельные транзакции; SMTP/Redis не вызываются под SQL locks.

## Открытые границы профиля

Дополнительный профиль временного пароля реализован отдельно: сервис генерирует пароль с TTL, первый вход разрешает только установку постоянного пароля, account остаётся pending до смены. Credentials/полномочие отзываются атомарно; временный пароль не подтверждает email, не создаёт session и не назначает роли. Приглашение остаётся основным способом; [контракт и admin выдача](temporary-passwords.md). UI и внешняя приёмка остаются впереди; MFA/admin backend уже подключены локально.

Это backend password-профиль, не административный UI и не production acceptance. Перевыпуск 5.7b реализован отдельно; повтор исходной provisioning-команды не является resend. Активация bare account без контакта/другими методами — после реализации соответствующих proof flows 7/8. Не восстанавливать доступ ручными SQL UPDATE или повторным public registration.

Внешние SMTP/browser HTTPS, полный mixed/multi-instance нагрузочный профиль и restore reconciliation остаются release gates. Локально проверяются idempotency, unique email, purpose isolation, expiry/version/block/delete, replay, concurrent provisioning/activation, audit rollback, delivery retry/stale lease/GC и HTTP/Swagger contracts. Проверки и фактические результаты — [history](../planning/history.md).

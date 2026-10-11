# Создание аккаунтов и приглашения

## Реализованный профиль 5.7a

`account/service/ProvisionService.Provision` — внутренний сценарий, независимый от public registration. При включённом профиле доступен через `App.Provisioning`. Actor UUID задаёт attribution, но не заменяет authorization. Административной HTTP-ручки пока нет: её подключение требует permissions, MFA, fresh-auth и CSRF в 10/13.1.

Вход: actor UUID, отдельный UUID idempotency key, необязательный email, флаг Invite. Без Invite создаются UUID/профиль и optional неподтверждённый контакт. С Invite обязателен email; создаются также одноразовый invitation challenge и encrypted mail intent. Все записи, включая audit, коммитятся одной SQL-транзакцией. Аккаунт имеет status `pending`, пароль/сессия/роли/permissions/платные grants не выдаются.

Ключ команды scoped по actor. Повтор с теми же нормализованными параметрами возвращает прежний UUID с Reused=true, без повторного письма. Другие параметры с тем же ключом — конфликт. Чужой/занятый email — конфликт, без auto-merge, новых полномочий или изменения существующего пользователя. Повтор после активации/expiry/delete не создаёт аккаунт или invitation заново. Durable command identity и activation marker сохраняются вместе с UUID; это не полный PII erasure.

## Активация

Письмо содержит frontend URL с token в fragment. GET только открывает будущий UI. Пользователь задаёт пароль; UI отправляет POST `/api/v1/auth/invitations/activate` с `token`, `password`, `confirmPassword`. Требуются точный разрешённый Origin, application/json и no-store. При выключенном профиле маршрут отсутствует; Swagger описывает включённый профиль.

Service проверяет формат token и password policy один раз, затем Redis IP/global limits. Indexed SQL preflight отсеивает неизвестные/неактуальные tokens до Argon2. Hash использует общий bounded budget процесса, параметры не ослаблены. После hash транзакция повторно проверяет актуальность — это защита от block/delete/expiry/concurrent acceptance, не дублирование входной валидации.

Транзакция блокирует user до удаления challenge, проверяет pending/deleted/version/DB expiry, записывает credential для того же owner/contact, подтверждает email, переводит user в active, повышает auth_version, сохраняет activation marker и audit. Ошибка откатывает все изменения. Из конкурентных активаций проходит одна; остальные получают одинаковую invalid_invitation. Invitation не подходит для reset/verification и не создаёт session. После успеха пользователь входит обычным login.

Block/delete атомарно отменяют invitation/outbox. Простое unblock не активирует ранее неактивированный provisioned account: durable activation marker защищает и после expiry cleanup. Общие пароли и административный обход подтверждения не используются.

## Настройки и ресурсы

| Env | Default | Значение |
| --- | --- | --- |
| INVITATIONS_ENABLED | false | Внутренний provisioning и публичный POST активации |
| INVITATION_URL | не задан | Доверенный frontend URL; HTTPS обязателен в production |
| INVITATION_TTL | 24h | Срок одноразового приглашения; 1m–7d |
| ACTIVATION_GLOBAL_LIMIT | 100 | Попытки активации в минуту для всего проекта |

IP limit — 10/min, HTTP admission и hash concurrency — существующие общие budgets. Redis failure/hash overload/SQL failure — 503; quota — 429, Retry-After 60. SQL lookup/transaction имеют deadline 5s, общий activation context — 10s. Токены не логируются и не возвращаются из provisioning; SQL хранит digest, outbox — AES-GCM payload с текущим EMAIL_OUTBOX_KEY.

Invitation delivery — третья очередь существующего account worker, без нового poller/pool. Очереди обходятся справедливо, каждая не более одного раза за попытку claim. Сохраняются eligibility, UUID leases, SKIP LOCKED, до пяти paced attempts. Успешная отправка удаляет job, но не challenge. Expiry/exhausted cleanup выполняет существующий bounded retention worker по индексам при включённом invitation profile; invitation audit следует SECURITY_AUDIT_RETENTION_DAYS. Expiry не удаляет account/contact автоматически: операторский lifecycle и reservation остаются отдельными сценариями.

## Перевыпуск приглашения — 5.7b

`App.Provisioning.ReissueInvitation` принимает actor UUID, существующий user UUID и отдельный UUID idempotency key. Создания нового пользователя, смены адреса, назначения прав и активации здесь нет. Actor — attribution; будущий admin transport обязан отдельно проверить permissions/MFA/fresh-auth/CSRF.

Новая команда допустима только для provisioned pending account без credentials, verification и activation marker, с исходным сохранённым контактом. SQL блокирует пользователя до контакта и повторно проверяет актуальность. В одной транзакции записываются command identity, замена challenge, encrypted outbox, время отправки и `reissued` audit. Старый token/job удаляется; новый token привязан к текущей auth_version и имеет новый TTL. Ошибка любого шага откатывает всё.

Успешный повтор того же actor/key/user возвращает `Reused=true` без повторной отправки. Другая цель с тем же ключом — конфликт. Повторы проходят Redis budgets; при его отказе операция закрыта. Команда не возвращает raw token. Сохранённый `last_invited_at` обеспечивает cooldown и после удаления истёкшего challenge; исходное создание с Invite тоже учитывается. Прошедшее cooldown приглашение можно перевыпустить после expiry или исчерпания доставки, сохранив UUID.

| Env | Default | Назначение |
| --- | --- | --- |
| `INVITATION_REISSUE_COOLDOWN` | 1m | Минимальный интервал между выдачами для одного пользователя; 1s–24h |
| `INVITATION_REISSUE_ACTOR_ATTEMPTS_PER_MINUTE` | 30 | Попытки команды за минутное окно для одного инициатора |
| `INVITATION_REISSUE_PROJECT_ATTEMPTS_PER_MINUTE` | 100 | Попытки команды за минутное окно всех API проекта с общим Redis/scoped key |

Квоты не означают RPS сервиса. Уже отправленное или находящееся в SMTP письмо отозвать нельзя: даже если старое письмо придёт после перевыпуска, его token недействителен. Delivery/GC остаются прежними, новых workers и HTTP-ручек нет. Durable command metadata хранится как существующие provisioning records; автоматическая очистка ключей не добавлена, чтобы не превращать поздний retry в новое письмо. После retention-удаления исходного контакта replay не восстанавливает его.

## Открытые границы профиля

Согласован дополнительный будущий профиль 5.7c: сервис генерирует временный пароль с TTL, первый вход разрешает только установку постоянного пароля, backend не допускает обычный доступ до смены. После смены временный пароль/полномочие отзываются атомарно; verification/MFA остаются обязательными по выбранной политике. Временный пароль не подтверждает email. Приглашение остаётся основным способом; подробности безопасной выдачи и tests — [план](../planning/implementation.md#57c-опциональный-временный-пароль--согласовано-11-октября-не-реализовано). Сейчас профиль не реализован.

Это backend password-профиль, не административный UI и не production acceptance. Перевыпуск 5.7b реализован отдельно; повтор исходной provisioning-команды не является resend. Активация bare account без контакта/другими методами — после реализации соответствующих proof flows 7/8. Не восстанавливать доступ ручными SQL UPDATE или повторным public registration.

Внешние SMTP/browser HTTPS, полный mixed/multi-instance нагрузочный профиль и restore reconciliation остаются release gates. Локально проверяются idempotency, unique email, purpose isolation, expiry/version/block/delete, replay, concurrent provisioning/activation, audit rollback, delivery retry/stale lease/GC и HTTP/Swagger contracts. Проверки и фактические результаты — [history](../planning/history.md).

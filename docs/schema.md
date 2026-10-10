# Схема Auth — этапы 4.1 и 5.1–5.5d

Источник: `migrations/000001_init` (up/down). Один экземпляр Auth обслуживает один проект; внутренний UUID пользователя не зависит от метода входа.

Схема recovery включена в исходную 000001: recovery digest/encrypted payload/TTL и nullable issued version/expiry в email_changes, owner index для lifecycle cleanup, recovery kind в outbox и recovered event в audit. Все recovery поля для старых intents остаются NULL, они не получают recovery authority. Срок начинается при защитном report; worker сохраняет intent до максимума protection/recovery expiry. Успешное восстановление меняет password credential и verified contacts, отзывает доступ и инвалидирует прежние intents/jobs одной транзакцией. Повторный административный block отменяет даже уже выданный recovery. Подробный контракт — [email change](email-change.md).

## Владельцы данных

5.5 добавляет `auth.email_changes` (user/contact/session/version binding, отдельные confirm/report digests, state/expiry/protection window, encrypted completion payload), `auth.email_change_outbox` (mail intents/lease/retries) и `auth.email_change_audit` (user/change UUID/event без email/raw token). Один pending intent на пользователя; старый подтверждённый контакт сохраняется при переводе password credential на новый. Audit переживает expiry cleanup intent; restrict user/contact FK не разрешает незаметную потерю security history. Удаление/retention согласуется в 5.6; [подробности](email-change.md).

| Таблица | Назначение и ограничения |
| --- | --- |
| `auth.users` | UUID, status `active/blocked`, положительный `auth_version` (по умолчанию 1), timestamps. Soft deletion требует `blocked`. |
| `auth.user_emails` | Контакты отдельно от credentials: UUID, владелец, case-insensitive уникальный email, nullable `verified_at`. Новый контакт не подтверждён. |
| `auth.password_credentials` | Один пароль на пользователя; ссылка на email того же пользователя защищена составным FK. Непустой hash до 1024 байт; формат/криптография контролируются hasher. |
| `auth.user_profile` | Необязательные поля профиля, nullable телефон с проверкой формата, связь 1:1 с пользователем. |
| `auth.email_verifications` | SHA-256 verifier, один challenge на контакт, expiry; purpose фиксирован таблицей, owner — FK. |
| `auth.email_verification_outbox` | AES-GCM payload, expiry, due time, до 5 attempts, UUID lease; удаляется вместе с challenge. |
| `auth.email_verification_audit` | Issuance/confirmation с user UUID, без email/token/payload. Общая audit policy впереди. |
| `auth.sessions` | Независимый публичный UUID `id`, digest token, owner, auth_version, idle/absolute expiry, revoked_at, device metadata; SQL authority. Индекс `(user_id,created_at DESC,id DESC)` для собственных сессий. |
| `auth.password_resets` | Digest, один challenge на credential owner, auth_version, expiry; одноразовый consume. |
| `auth.password_reset_outbox` | Encrypted payload, expiry, attempts, lease; каскадно удаляется с challenge. |
| `auth.password_audit` | Reset issuance/reset/change/revoke events с user UUID, без token/password. |
| `auth.account_status_audit` | Actor/target UUID, предыдущий и новый active/blocked status, новая auth_version и timestamp. Пишется в одной транзакции с изменением статуса/отзывом; FK сохраняют существование actor/target, индекс owner/date/id. |

Первые четыре таблицы имеют `created_at/updated_at`; BEFORE UPDATE trigger поддерживает `updated_at`. Основные дочерние записи имеют каскадные FK при явном hard delete. Status audit использует restrictive FK actor/target: hard delete не должен незаметно стирать историю, его retention/anonymization policy определяется в 5.6. Soft deletion ничего физически не удаляет.

Email нормализуется приложением: trim + lower, максимум 255 байт, только адрес без display name, комментариев и обёртки `<…>`. SQL дополнительно проверяет базовую нормализацию, длину и наличие `@`; полный разбор адреса остаётся в приложении. Уникальность сохраняется после soft deletion: автоматическое освобождение адреса запрещено, политика повторного использования/удаления персональных данных определяется отдельно на этапе lifecycle.

PK/UNIQUE уже создают необходимые индексы. `(user_id, id)` поддерживает ownership FK и выборку контактов владельца; отдельные дублирующие индексы не добавлены. Индексы административных фильтров появятся вместе с реальными запросами.

Регистрация создаёт user → contact → password credential → profile в одной транзакции. Конкурентный конфликт `user_emails_email_key` преобразуется в существующий `ErrEmailAlreadyExists`; другие DB errors сохраняются. Поиск credential по email идёт через контакт, регистр не влияет на совпадение.

## Применение и границы

До первого production release схема развивается в исходной миграции 000001, без промежуточных миграций. Уже применённая старая версия **не обновится автоматически**: для существующей БД нужен отдельно согласованный перенос. Не выполнять down/reset рабочей БД ради этой схемы. В этом этапе рабочие данные не изменялись.

Verification, специализированные audit/outbox и verified-email gate смены пароля реализованы в 5.1. Регистрационная транзакция через composition callback включает challenge/outbox/audit; их failure откатывает регистрацию. Resend блокирует контакт/пользователя и заменяет challenge. Confirm проверяет expiry/status и меняет verified_at/consumes/audit одним commit. Подробности — [verification](email-verification.md). В 5.2 добавлены SQL session ledger и recovery: password reset/change повышают auth_version, отзывают все сессии и пишут audit одной транзакцией. Login issuance повторно проверяет status/version; stale refresh не воскрешает session. Подробности — [recovery](password-recovery.md). Общие account policies/audit, полная session security, роли и billing остаются впереди.

## Минимальная проверка

Обычный `task check` запускает unit tests и lint. Реальная schema-проверка opt-in: переменная `AUTH_SCHEMA_TEST_DATABASE_URL`, команда `go test ./internal/auth/methods/password/repository/postgres -run TestPostgresSchema -count=1 -v`.

Fixture допускает только localhost, пользователя/БД `auth_schema_test` и отсутствие исходной схемы `auth`. Использовать исключительно отдельный временный PostgreSQL: тест применяет SQL up/down/up и записывает тестовые данные. Без переменной он пропускается. Временный контейнер создаёт и удаляет оператор; новый sh-скрипт не добавлен.

7 октября 2026 на отдельном PostgreSQL 18.6 подтверждены up/down/up, repository round-trip, timestamps, UNIQUE/FK/CHECK, cascade delete, rollback регистрации, soft-deleted email reservation и конкурентная регистрация. Это проверка SQL/репозиториев, не полная HTTP/security acceptance.

9 октября проверка повторена для 5.1: registration+outbox rollback, cooldown/replacement, expiry/replay, concurrent consume, audit failure rollback, blocked account, lease/stale completion, retry limit и ciphertext cleanup. Redis concurrent limiter проверен отдельно. Рабочая БД не затронута.

9 октября проверка повторена для 5.2: reset cooldown/replacement/expiry/replay, ровно один concurrent consume, audit rollback, stale session issuance/refresh, атомарные reset/change с отзывом сессий и blocked account. Проверено на отдельном PostgreSQL 18.6; SQL delivery использует test double.

5.3 добавляет публичный UUID, не связанный с token/hash. Отзыв оставляет ledger-запись с `revoked_at`: действующий список её не возвращает, физическая очистка/retention остаются отдельной задачей. Logout-all увеличивает `auth_version`; проверка caller, отзыв и audit атомарны. Расширена исходная 000001 для свежих экземпляров. Уже применённую схему нельзя исправить повторным `migrate up`: нужен отдельно согласованный перенос, не reset рабочей БД.

5.4 добавляет account status use case: user row lock, expected `auth_version`, смена active/blocked + увеличение version + revoke всех сессий + удаление reset/verification challenges (outbox каскадно) + status audit одной транзакцией. При unchanged status и актуальной version запись не меняется; stale version — conflict, deleted account не разблокируется. Unblock тоже повышает version и не возрождает старые tokens/challenges. Для смены статуса использовать `account/service/StatusService`, а не отдельные UPDATE status/revoke/audit. Автоматический SQL trigger для этих бизнес-операций не добавлялся; прямой SQL не является поддерживаемым lifecycle workflow. Старый login snapshot после block/unblock не может выпустить новую сессию.

10 октября TestPostgresSchema прошёл на отдельном PostgreSQL 18.6: up/down/up и весь прежний набор, дополнительно block/unblock/no-op/conflict, actor/audit failure rollback, blocked/deleted credential/session checks, invalidation challenges/outbox, stale login snapshot, concurrent issuance/refresh/status writes и cancellation. Реальная рабочая БД не изменялась; новая audit table также требует отдельно согласованного переноса уже применённой схемы.

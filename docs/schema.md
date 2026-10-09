# Схема Auth — этапы 4.1 и 5.1

Источник: `migrations/000001_init.up.sql` и `.down.sql`. Один экземпляр Auth обслуживает один проект; внутренний UUID пользователя не зависит от метода входа.

## Владельцы данных

| Таблица | Назначение и ограничения |
| --- | --- |
| `auth.users` | UUID, status `active/blocked`, положительный `auth_version` (по умолчанию 1), timestamps. Soft deletion требует `blocked`. |
| `auth.user_emails` | Контакты отдельно от credentials: UUID, владелец, case-insensitive уникальный email, nullable `verified_at`. Новый контакт не подтверждён. |
| `auth.password_credentials` | Один пароль на пользователя; ссылка на email того же пользователя защищена составным FK. Непустой hash до 1024 байт; формат/криптография контролируются hasher. |
| `auth.user_profile` | Необязательные поля профиля, nullable телефон с проверкой формата, связь 1:1 с пользователем. |
| `auth.email_verifications` | SHA-256 verifier, один challenge на контакт, expiry; purpose фиксирован таблицей, owner — FK. |
| `auth.email_verification_outbox` | AES-GCM payload, expiry, due time, до 5 attempts, UUID lease; удаляется вместе с challenge. |
| `auth.email_verification_audit` | Issuance/confirmation с user UUID, без email/token/payload. Общая audit policy впереди. |

Все четыре таблицы имеют `created_at/updated_at`; BEFORE UPDATE trigger поддерживает `updated_at`. FK на пользователя каскадно удаляет дочерние записи при явном hard delete. Soft deletion ничего физически не удаляет.

Email нормализуется приложением: trim + lower, максимум 255 байт, только адрес без display name, комментариев и обёртки `<…>`. SQL дополнительно проверяет базовую нормализацию, длину и наличие `@`; полный разбор адреса остаётся в приложении. Уникальность сохраняется после soft deletion: автоматическое освобождение адреса запрещено, политика повторного использования/удаления персональных данных определяется отдельно на этапе lifecycle.

PK/UNIQUE уже создают необходимые индексы. `(user_id, id)` поддерживает ownership FK и выборку контактов владельца; отдельные дублирующие индексы не добавлены. Индексы административных фильтров появятся вместе с реальными запросами.

Регистрация создаёт user → contact → password credential → profile в одной транзакции. Конкурентный конфликт `user_emails_email_key` преобразуется в существующий `ErrEmailAlreadyExists`; другие DB errors сохраняются. Поиск credential по email идёт через контакт, регистр не влияет на совпадение.

## Применение и границы

До первого production release редактируется исходная миграция. Уже применённая версия `000001` **не обновится автоматически**: для существующей БД нужен отдельно согласованный перенос данных/новая миграция. Не выполнять down/reset рабочей БД ради этой схемы. В этом этапе рабочие данные не изменялись.

Verification, специализированные audit/outbox и verified-email gate смены пароля реализованы в 5.1. Регистрационная транзакция через composition callback включает challenge/outbox/audit; их failure откатывает регистрацию. Resend блокирует контакт/пользователя и заменяет challenge. Confirm проверяет expiry/status и меняет verified_at/consumes/audit одним commit. Подробности — [verification](email-verification.md). Login ещё не проверяет все account policies; смена пароля ещё не повышает версию и не обеспечивает SQL-отзыв сессий. Session ledger, общий audit/outbox, роли и billing остаются впереди.

## Минимальная проверка

Обычный `task check` запускает unit tests и lint. Реальная schema-проверка opt-in: переменная `AUTH_SCHEMA_TEST_DATABASE_URL`, команда `go test ./internal/auth/methods/password/repository/postgres -run TestPostgresSchema -count=1 -v`.

Fixture допускает только localhost, пользователя/БД `auth_schema_test` и отсутствие исходной схемы `auth`. Использовать исключительно отдельный временный PostgreSQL: тест применяет SQL up/down/up и записывает тестовые данные. Без переменной он пропускается. Временный контейнер создаёт и удаляет оператор; новый sh-скрипт не добавлен.

7 октября 2026 на отдельном PostgreSQL 18.6 подтверждены up/down/up, repository round-trip, timestamps, UNIQUE/FK/CHECK, cascade delete, rollback регистрации, soft-deleted email reservation и конкурентная регистрация. Это проверка SQL/репозиториев, не полная HTTP/security acceptance.

9 октября проверка повторена для 5.1: registration+outbox rollback, cooldown/replacement, expiry/replay, concurrent consume, audit failure rollback, blocked account, lease/stale completion, retry limit и ciphertext cleanup. Redis concurrent limiter проверен отдельно. Рабочая БД не затронута.

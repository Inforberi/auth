# Удаление аккаунта — 5.6a

Реализован внутренний `account/service/DeletionService.Delete`: target UUID, actor UUID и ожидаемая `auth_version`. Actor — атрибуция аудита, не доказательство разрешения. Сценарий не подключён к router или UI. Публичное удаление требует authorization, fresh-auth/MFA, CSRF и защиты последнего администратора на соответствующих этапах; не вызывать его напрямую из незащищённой ручки.

## Транзакция

PostgreSQL блокирует user перед дочерними данными, проверяет существование и ожидаемую version. Active и blocked аккаунты допускают удаление. Один commit устанавливает `blocked/deleted_at`, повышает version, отзывает все сессии и очищает их IP/User-Agent, удаляет password credential (reset challenges/outbox каскадно), verification challenges/outbox, email-change intents/outbox и профиль, снимает verification контактов, записывает deletion audit. Ошибка любой операции, включая audit, откатывает весь переход. Deadline сервиса — 5s.

Удаление не создаёт письмо, сессию или механизм восстановления. Уже взятое worker письмо физически может дойти, но его ссылка недействительна. Старые login snapshots, reset/verification/change/recovery tokens и admin unblock не восстанавливают удалённый account. Повторный запрос с текущей version возвращает её без нового audit/version bump; прежняя version получает conflict. Нет скрытого retry: если конкурентная операция первой повысила version, вызывающий должен явно перечитать состояние и повторно подтвердить удаление.

## Что хранится сейчас

| Данные | После удаления |
| --- | --- |
| Пароль, профиль, challenges, encrypted mail payloads и email-change intents | Физически удалены в транзакции |
| Сессии | Отозванный ledger без IP/User-Agent; дальнейший purge требует retention policy |
| Контакты email | Адреса и owner UUID сохранены, verification снята; адреса не освобождаются для регистрации |
| User UUID, version, deleted timestamp | Сохранён tombstone, автоматически не восстанавливается |
| Security audit | Сохранён, без добавления email/password/raw token в deletion event |

Это логическое удаление с частичной минимизацией, **не полное стирание персональных данных**. Email и связанный UUID остаются персональными данными; tombstone нельзя объявлять анонимизацией. Произвольный срок хранения по умолчанию не назначен, автоматический purge не реализован. Прямой `UPDATE deleted_at` не является поддерживаемым workflow; обычный SQL soft-delete сам по себе не выполняет cleanup. Hard-delete user с deletion audit ограничен FK и не заменяет согласованный purge.

5.6b остаётся открытым: определить сроки хранения контактов/ledger/audit/backups, допустимость повторной регистрации и отдельную схему reservations/anonymization, затем реализовать bounded purge и проверить отсутствие takeover. Освобождение email не должно восстанавливать старый UUID, roles, identities или подписки. Внешние методы входа при их появлении обязаны участвовать в lifecycle deletion; сегодня они не реализованы, пустые адаптеры не добавлены.

## Будущая оплата

Billing ещё не реализован, и deletion не делает запросов к воображаемому платёжному сервису. Нельзя каскадно удалять платёжную историю вместе с Auth account или трактовать `deleted_at` как успешную отмену внешнего recurring payment. До подключения оплаты этапы 11/12 должны определить согласованную cancellation policy, durable event/outbox и idempotency/retry, запрет выдачи новых entitlements удалённому UUID. Внешние сетевые операции не выполняются внутри Auth SQL transaction. Платёжные документы и их сроки хранения задаются отдельно для продукта; текущая реализация не объявляется готовой для активных подписок.

## Проверки

Unit tests проверяют валидацию, deadline и сохранение ошибок repository. `TestPostgresSchema/account deletion` проверяет cleanup/reservation/idempotency/version conflict, audit failure rollback, invalidation старых ссылок, no-unblock, concurrent deletion/recovery/unblock/issuance, active session issuance и verification confirm/resend. Verification теперь берёт user lock раньше contact; eligibility resend перечитывается после lock, а не из устаревшего snapshot. Fresh-install схема расширена в исходной 000001 без новой миграции; ранее применённой 000001 нужен отдельный согласованный перенос, не сброс рабочей базы.

# Удаление аккаунта и retention — 5.6

Реализован внутренний `account/service/DeletionService.Delete`: target UUID, actor UUID и ожидаемая `auth_version`. Actor — атрибуция аудита, не доказательство разрешения. Сценарий не подключён к router или UI. Публичное удаление требует authorization, fresh-auth/MFA, CSRF и защиты последнего администратора на соответствующих этапах; не вызывать его напрямую из незащищённой ручки.

## Транзакция

PostgreSQL блокирует user перед дочерними данными, проверяет существование и ожидаемую version. Active и blocked аккаунты допускают удаление. Один commit устанавливает `blocked/deleted_at`, повышает version, отзывает все сессии и очищает их IP/User-Agent, удаляет password credential (reset challenges/outbox каскадно), verification challenges/outbox, email-change intents/outbox и профиль, снимает verification контактов, записывает deletion audit. Ошибка любой операции, включая audit, откатывает весь переход. Deadline сервиса — 5s.

Удаление не создаёт письмо, сессию или механизм восстановления. Уже взятое worker письмо физически может дойти, но его ссылка недействительна. Старые login snapshots, reset/verification/change/recovery tokens и admin unblock не восстанавливают удалённый account. Повторный запрос с текущей version возвращает её без нового audit/version bump; прежняя version получает conflict. Нет скрытого retry: если конкурентная операция первой повысила version, вызывающий должен явно перечитать состояние и повторно подтвердить удаление.

## Что хранится сейчас

| Данные | После удаления |
| --- | --- |
| Пароль, профиль, challenges, encrypted mail payloads и email-change intents | Физически удалены в транзакции |
| Сессии | Отозванный ledger без IP/User-Agent; worker удаляет через 30 дней после завершения |
| Контакты email | Verification снята; адрес резервируется на 30 дней, затем worker удаляет contact. Если account был blocked перед удалением, автоматического освобождения нет |
| User UUID, version, deleted timestamp | Сохранён tombstone, автоматически не восстанавливается |
| Security audit | Worker удаляет события старше 180 дней, независимо от статуса владельца |

Это логическое удаление с частичной минимизацией, **не полное стирание персональных данных**. Email на время резервирования и связанный UUID остаются персональными данными; tombstone нельзя объявлять анонимизацией. Прямой `UPDATE deleted_at` не является поддерживаемым workflow; обычный SQL soft-delete сам по себе не выполняет cleanup. User не удаляется worker: UUID/version/deleted timestamp нужны для no-restore и будущих внешних ссылок, restrictive FK actor/target сохраняются.

## Согласованная политика и env

Удаление необратимое, восстановления аккаунта не добавляем. После завершения резервирования повторная регистрация требует нового UUID и нового proof владения email; старые роли, identities, подписки и приглашения не переносятся. Административная блокировка не превращается в разрешение обойти её удалением и регистрацией.

| Переменная | Default | Отсчёт cleanup |
| --- | --- | --- |
| `ACCOUNT_EMAIL_RESERVATION_DAYS` | 30 | От `deleted_at` |
| `SESSION_RETENTION_DAYS` | 30 | От `revoked_at`, а если сессия ранее истекла — от более раннего idle/absolute expiry; активные сессии не удаляются |
| `SECURITY_AUDIT_RETENTION_DAYS` | 180 | От времени события, не от удаления account |

Один день — 24 часа; значения — целые положительные дни в диапазоне Go duration, `0` не означает бесконечное хранение или отключение. Они загружаются через `Config.Retention` и проверяются до startup; изменения env требуют restart. Defaults есть в коде и обоих env examples, реальные env/secrets не менялись. Это выбранный профиль шаблона, не норматив для любого продукта. Сокращение срока после restart делает больше записей eligible для необратимой очистки.

### Worker и повторная регистрация

`RetentionService` запускается вместе с delivery workers, останавливается до закрытия pool/Redis. RETENTION_INTERVAL (default 1m) задаёт один проход, RETENTION_BATCH_SIZE (default 100, 1–1000) — максимум кандидатов каждой операции. Общий deadline 5s. Contacts/sessions/пять audit tables очищаются одной SQL-транзакцией; ошибка откатывает эту партию. Следом отдельные bounded statements очищают expired challenges/outbox/exhausted jobs и, в активном профиле, email-change intents; их частичный успех сохраняется, повтор идемпотентен. SKIP LOCKED распределяет партии между экземплярами, cutoff использует statement_timestamp и matching indexes. Это не мгновенное стирание в момент cutoff и не бесконечный draining backlog. Ограничения и проверки — [performance](../operations/performance.md); multi-instance приёмка 6.8 открыта.

Reservation storage — существующая `user_emails` с UNIQUE(email), без второй таблицы/HMAC key или дублирующего поиска. На 30 дней сохраняется только необходимый для резерва адрес с owner; после release contact удаляется физически. Когда удалён последний contact, `email_released_at` исключает tombstone из рабочего partial index; исторические tombstones не накапливаются в каждом scan. Это намеренно не немедленная pseudonymization. `users.email_reuse_blocked` фиксирует blocked status перед удалением, не зависит от истекающего audit. Такой адрес не освобождается автоматически, включая консервативный случай защитной блокировки: отдельная будущая ban-erasure/operator policy должна определить срок и доказательство снятия ограничения, а не незаметно обходить его retention worker.

Release не переносит контакт к новому owner. Обычная регистрационная транзакция создаёт новый UUID/contact/credential/profile; UNIQUE сериализует гонку с purge/другой регистрацией. Contact неподтверждён, новая verification выдаётся текущим registration callback. Старый proof не подтверждает новый contact; существующий `RequireVerified` gate сохраняется. Общую политику обязательности подтверждения для всех продуктовых ручек этот этап не меняет: login/register по-прежнему могут выдать неподтверждённую сессию. Роли/identities/subscriptions/invitations ещё не реализованы; их владельцы обязаны привязывать права к UUID, не восстанавливать их по совпадению email. Внешние методы при появлении участвуют в deletion, пустые адаптеры сейчас не создаём.

Session cutoff — `LEAST(revoked_at,expires_at,absolute_expires_at)`; PostgreSQL игнорирует NULL revoked_at. Поэтому более поздний revoke не продлевает уже истёкшую сессию. Active session с будущими expiry не удаляется. Audit cutoff применяется к event timestamp в verification/password/status/deletion/email-change audit; повторное deletion остаётся no-op по tombstone даже после удаления audit.

Backup policy остаётся отдельной: существующие `BACKUP_INTERVAL`/`BACKUP_RETENTION_COUNT` не заменены retention днями и в этом заходе не изменены. До открытия доступа после restore должны применяться удаления/истёкшие policies из надёжного журнала; восстановление backup не возрождает доступ. Реализация restore reconciliation остаётся operational/release gate. В финальных settings/UI эти три срока станут отдельными полями с той же backend-валидацией; audit изменений и права обязательны, история автоматически не загружается в UI. Необратимость удаления, новый UUID и отсутствие наследования прав — гарантии, не переключатели для обхода через UI.

## Будущая оплата

Billing ещё не реализован, и deletion не делает запросов к воображаемому платёжному сервису. Нельзя каскадно удалять платёжную историю вместе с Auth account или трактовать `deleted_at` как успешную отмену внешнего recurring payment. До подключения оплаты этапы 11/12 должны определить согласованную cancellation policy, durable event/outbox и idempotency/retry, запрет выдачи новых entitlements удалённому UUID. Внешние сетевые операции не выполняются внутри Auth SQL transaction. Платёжные документы и их сроки хранения задаются отдельно для продукта; текущая реализация не объявляется готовой для активных подписок.

## Проверки

Unit tests проверяют валидацию, deadline и сохранение ошибок repository. `TestPostgresSchema/account deletion` проверяет cleanup/reservation/idempotency/version conflict, audit failure rollback, invalidation старых ссылок, no-unblock, concurrent deletion/recovery/unblock/issuance, active session issuance и verification confirm/resend. Verification теперь берёт user lock раньше contact; eligibility resend перечитывается после lock, а не из устаревшего snapshot. Fresh-install схема расширена в исходной 000001 без новой миграции; ранее применённой 000001 нужен отдельный согласованный перенос, не сброс рабочей базы.

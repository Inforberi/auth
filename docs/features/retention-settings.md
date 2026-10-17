# Сохраняемые сроки очистки — A6.3c.3-local

Backend хранит сроки в PostgreSQL; UI ещё не реализован. Это настройки хранения данных, **не сроки действия сессий** и не универсальная runtime-конфигурация.

## Поля и defaults

| JSON | ENV первоначального seed | Default | Отсчёт |
| --- | --- | --- | --- |
| `emailReservationDays` | `ACCOUNT_EMAIL_RESERVATION_DAYS` | 30 | После удаления аккаунта; blocked-before-deletion сохраняет запрет reuse |
| `sessionDays` | `SESSION_RETENTION_DAYS` | 30 | После самого раннего revoke/idle expiry/absolute expiry |
| `securityAuditDays` | `SECURITY_AUDIT_RETENTION_DAYS` | 180 | От времени security-события |

Значения — целые дни по 24 часа, диапазон `1..106751`: прежняя техническая граница безопасного Go duration, не рекомендация хранить данные сотни лет. Ноль, отрицательные, дробные, null и отсутствующие периоды не отключают cleanup. HTTP проверяет JSON shape, service/domain — предметные границы, SQL CHECK — хранилище.

Новая установка сохраняет singleton `auth.retention_settings` с version=1 до открытия трафика. Параллельный startup получает одну строку и один победивший seed. Сохранённые значения не перезаписываются ENV при restart. Потеря строки после initialized setup — ошибка, не повод загрузить ENV заново. Эти поля не секреты, root keys не нужны.

`RETENTION_BATCH_SIZE` (1–1000, default 100) и `RETENTION_INTERVAL` (1s–1h, default 1m) остаются deployment ENV, меняются с restart. Pool/admission/rate limits, hashing, session deadlines, backup policy, callback URLs и root keys в этот API не переносятся.

## API

`GET /api/v1/admin/auth/settings/retention`

Требуются live `__Host-session`, разрешённый HTTPS Origin и текущее `auth.settings.manage`. SQL проверяет active/nondeleted пользователя, auth/role revisions, сроки и отзыв сессии, текущее permission. Fresh proof для чтения не нужен. Ответ не продлевает сессию и не выдаёт cookie; `Cache-Control: no-store`.

```json
{
  "version": 1,
  "policy": {
    "emailReservationDays": 30,
    "sessionDays": 30,
    "securityAuditDays": 180
  }
}
```

`POST /api/v1/admin/auth/settings/retention`

```json
{
  "expectedVersion": 1,
  "policy": {
    "emailReservationDays": 30,
    "sessionDays": 30,
    "securityAuditDays": 90
  },
  "confirmShortening": true
}
```

Полная policy, не patch. Actor только из cookie; actorId, технические budgets и неизвестные поля не принимаются. Нужны Origin, JSON, current permission и свежие password+MFA proofs с enrolled factor. При `MFA_ENABLED=false` POST не регистрируется, GET не становится публичным.

Транзакция: Access lock → актуальные actor/session/permissions/fresh proofs → singleton lock → expectedVersion → подтверждение сокращения → UPDATE/version+1 и audit. Ошибка аудита откатывает изменение. No-op проверяет authority/version, но не делает UPDATE/version bump/audit. Параллельные изменения одной версии дают одного победителя и conflict; автоматического retry нет.

Если хотя бы один срок уменьшается, нужен `confirmShortening=true`. Иначе `409 retention_confirmation_required`, изменений нет. Ранее допустимые данные могут стать кандидатами на необратимое удаление. После conflict перечитайте значения и заново подтвердите решение. В UI нужны прежний/новый срок и предупреждение, не скрытый автоматический флаг.

Увеличение срока не восстанавливает удалённые строки. Увеличение резервирования email не забирает адрес у нового владельца и не возрождает released reservation. Настройкой нельзя восстановить старый UUID, роли или proof.

Ответ `200` — формат GET с новой version. Ошибки:

| Статус | Код | Причина |
| --- | --- | --- |
| 400 | `invalid_json` | Форма, неизвестные поля, отсутствующая policy |
| 400 | `invalid_retention_settings` | Неверная version или дни |
| 401 | `unauthorized` | Нет действующей сессии |
| 403 | `invalid_origin`, `forbidden`, `fresh_auth_required` | Origin, permission или proofs |
| 409 | `retention_settings_conflict` | Настройки изменились |
| 409 | `retention_confirmation_required` | Нужно подтверждение сокращения |
| 503 | `temporarily_unavailable` | SQL/сохранённая конфигурация недоступны |

## Worker и нагрузка

Существующий worker читает одну SQL-строку перед каждой партией и использует локальный snapshot. Нет нового polling/cache/Redis round trip/timer/worker/pool. Обычные пользовательские запросы retention settings не читают. Ошибка чтения/проверки policy отменяет партию **до удаления**, без ENV fallback; повтор по прежнему расписанию.

Общий deadline партии остаётся 5s, включая settings; read ограничен 3s. Batch size, индексируемые cutoff, SKIP LOCKED, rollback и последующая bounded transient cleanup сохранены. До BatchSize строк **каждой** audit table за проход — не общий предел всех таблиц. Новая `retention_settings_audit` включена в тот же механизм, хранит actor/version/previous/next policy.

После commit новые партии всех экземпляров читают новую policy из общей БД. Уже начатая партия может завершиться с прежним snapshot в пределах 5s; API **не является барьером отмены текущей очистки**. Нет fleet-wide cache/отдельной доставки конфигурации. При N экземплярах бюджеты суммируются: около N settings reads за интервал и до N×BatchSize кандидатов каждой операции. Нет бесконечного draining backlog; capacity измеряется отдельно.

Действующие session deadlines не меняются. Завершённый ledger очищается позднее, а не продлевает действие сессии. Expiry MFA/OIDC/email/reset challenges, purpose/one-time proofs и доставка от retention дней не зависят. Tombstone, identities, last-admin и запрет переноса прав по email сохранены.

## Upgrade и приёмка

Дополнен source `000001_init.up/down.sql`, отдельной миграции нет. Рабочая БД автоматически не изменяется. Existing installation требует controlled schema/grants/seed rollout до трафика; нельзя сбрасывать setup marker/БД или запускать mixed old/new fleet с разными источниками retention. Maintenance upgrade CLI не добавлен.

Локальные тесты покрывают seed/concurrent update/no-op/audit rollback/current guards, границы, подтверждение сокращения, применение worker, сохранность активных deadlines и fail-closed потерянной строки. HTTPS multi-instance, нагрузка/память/GC, shutdown и restore reconciliation остаются pre-ui/A8 gates, не закрываются unit/SQL тестами.

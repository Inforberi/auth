# Статус и удаление пользователей проекта

## MP5.1m: проектный HTTP

| Метод и путь | Право | Тело |
| --- | --- | --- |
| POST `/api/v1/admin/users/{id}/status` | `accounts.users.status.manage` | `status` (active/blocked), `expectedAuthVersion` |
| DELETE `/api/v1/admin/users/{id}` | `accounts.users.delete` | `expectedAuthVersion` |

Переиспользуются существующие `UserLifecycleHandler`, DTO/error mapper, account service и SQL transactions. Прочитать, создать или знать UUID пользователя недостаточно для изменения. Actor берётся только из сессии проекта; platform principal не подставляется.

В UUID manifest `userLifecycle` default false и требует `browser=true`; в программной сборке — `ProjectProfileConfig.UserLifecycleEnabled`. Нужна готовая согласованная MFA management configuration. Публикация capability не назначает права. Маршруты используют `session_no_refresh`/exact browser Origin, свежие пароль и MFA проверяются существующим SQL authority внутри транзакции. Настраиваемая обязательность MFA — отдельный этап, текущие guards не ослаблены.

`projectUserLifecycle` держит один runtime lease выбранного проекта, общий timeout пять секунд, проверку актуальности binding до и после операции. После ошибки финального guard успешная версия не возвращается; возможен уже завершённый SQL commit. Нельзя считать ошибку доказательством rollback: нужно прочитать актуальную карточку и сверить состояние/версию перед повтором. Новых миграций, SQL-политик, зависимостей, ENV, кеша и workers нет.

## Существующее поведение

Смена статуса требует текущего `authVersion`, иначе 409. Блокировка увеличивает версию, отзывает сессии и outstanding activation/recovery proofs; разблокировка не оживляет старые сессии, не активирует pending аккаунт и не восстанавливает удалённый. Изменения и аудит атомарны. SQL Access lock и row locks сохраняются.

Удаление необратимо на уровне аккаунта: сохраняется tombstone, отзываются сессии, удаляются credentials/factors по существующему контракту и пишется аудит. Это не полное стирание всех персональных данных; email reservation/reuse policy прежняя. Повтор со старой версией конфликтует, повтор с текущей tombstone-версией — no-op после проверки полномочий. Подробности — [account deletion](account-deletion.md).

Защищён последний пригодный системный `super_admin`; custom роль с административными permissions сама по себе не равна этой системной роли. Нет нового общего запрета self-target: применяются existing authority/version/last-super-admin guards. UI должен отразить последствия и подтверждение удаления; UI сейчас не реализуется.

## Проверки

Source/default-off/isolation/prerequisite/route protection tests дополнены. В actual HTTPS/SQL account fixture добавлен отдельный lifecycle case: 401/403, foreign Origin, block/revoke, unblock без revival, stale-version409, pending activation409, tombstone/retry/audit, last-system-admin409 с проверкой error code. Свои users/role/sessions/audit очищаются; старые issuance/identity/MFA/directory сценарии сохраняются. Локальные проверки Luna PASS: task check/API/race и полный Linux ARM64 TestPrepareCommandSQL; новый lifecycle HTTP case и прежние directory/MFA/identity cases без skip. Полная two-project matrix/ресурсные проверки/UI отдельно.

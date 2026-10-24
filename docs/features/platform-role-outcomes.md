# Результат создания роли и его восстановление

MP2.7. Внутренние методы `ReadRoleOutcome` и `ReconcileRoleOutcome` дополняют [intent/admission/receipt protocol](platform-role-intents.md). HTTP пока закрыт.

## Кто получает результат

Читать можно только свою операцию по operation UUID при действующих platform session и `platform.projects.read`. Право `platform.project_access.manage` для такого чтения не требуется: его отзыв запрещает новые допуски, но не стирает историю уже принятой команды. Один UUID без авторизации не открывает результат. Чужой UUID и неизвестный UUID возвращают одинаковый not-found.

Используется существующий guarded catalog transaction с current authority locks и fresh password/MFA policy. Поэтому восстановление с отозванной/просроченной session, без текущего read permission, с неактивным аккаунтом или устаревшими proofs запрещено. Это намеренно более строгий путь, чем обычный catalog list; optional MFA policy остаётся отдельным этапом. Проверка чтения не выдаёт новый admission и не разрешает изменение проектных данных.

Другому оператору пока нельзя читать чужую операцию этим методом, даже зная UUID. Общеплатформенная support/recovery выдача результатов потребует отдельного согласованного сценария. Полностью лишённый прав исходный оператор не получает completion receipt в обход отзыва.

## Что означает ответ

`RoleCreationOutcome` содержит operation/project UUID и `Committed`:

- `true` — в каталоге есть durable completion evidence; Role содержит первоначальный snapshot результата создания;
- `false` — completion пока неизвестен, Role пуст. Это не подтверждение rollback и не указание повторно создать роль.

Snapshot описывает исходную операцию, а не текущие права или имя роли. Источником действующей конфигурации остаются обычные role APIs. Успешное чтение уже известного результата не требует доступной проектной БД или действующего write permission.

## Восстановление после потерянного ответа

1. Проверить текущий доступ и прочитать catalog outcome. Если он уже есть, вернуть его без обращения к проектной БД.
2. Для своей ранее допущенной операции прочитать immutable intent/binding. Если ни одного admission не было, reconciliation не запускается; метод возвращает not-found, обычное чтение intent по-прежнему показывает unknown.
3. Через [trusted registry](project-runtime-registry.md) получить соединение для исходных binding/version/generation. Открыть read-only project transaction, проверить её SQL runtime profile.
4. Прочитать только существующий project receipt; сверить realm/actor/project/binding/request и проверить, что его admission UUID принадлежит данной операции в каталоге.
5. Если receipt найден, дописать immutable catalog outcome существующим idempotent recorder. Project role/audit/receipt не изменять, новые admissions не создавать. Отсутствующий receipt оставить unknown.
6. Перед возвратом заново выполнить guarded чтение с текущей session/permission/proofs. Отзыв во время восстановления может запретить выдачу результата, даже если completion evidence успело сохраниться.

Первичное guarded чтение ограничено до3s. После него восстановление и финальная проверка доступа имеют общий отдельный бюджет до3s; существующий completion-only recorder может занять ещё до1s после отмены этого контекста. Эти бюджеты ограничивают чтение и фиксацию факта, не продлевают истёкший допуск на project mutation. Уже достоверно установленный факт может быть сохранён после отмены клиентского запроса; новой бизнес-операции из этого не возникает.

Если exact runtime недоступен, credentials потеряны или target изменился, не выбирать новую/чужую БД и не утверждать, что операция не произошла. Cold-open suspended/stale проекта может быть запрещён loader; результат остаётся неустановленным до разрешённого восстановления инфраструктуры. Для уже известного catalog outcome обращение к этому runtime не нужно.

## Границы проверки

Добавлена [конкурентная матрица](../operations/platform-role-faults.md#дополнение-команды-ролей-и-восстановление-результата): revoke между initial guard и финальным ответом, write revoke/suspend на warm runtime и параллельное reconciliation без новых admissions/перезаписи receipt. Новый набор проверен Luna: task check/command host race/actual TLS SQL suite PASS, fixture очищен, hashes совпали до/после. [Evidence](../planning/history.md#результат-mp27-role-concurrency--24-октября-2026). Предыдущий PASS ниже относится к прежнему набору.

Матрица ниже проверена отдельной Luna на actual PostgreSQL18.6 TLS: read/reconcile после session revoke запрещены; после read-permission revoke проверен отказ чтения. Финальный suite PASS9.01s, protected_role_outcome PASS0.03s. [Evidence и ограничения](../planning/history.md#результат-mp27-role-outcomes--24-октября-2026).

SQL-приёмка должна проверять read-own после отзыва write permission, read/reconcile refusal после session/read-permission revoke, одинаковый not-found для чужого и неизвестного UUID, missing outcome → receipt recovery без новых admissions, admitted-but-not-executed → unknown. Shared receipt reader сохраняет прежние execution/replay проверки.

Не заменяет реальные transport faults, concurrent revoke/factor/role matrix, production wiring/rate budgets и HTTP acceptance. Автоматического scanner/worker по всем операциям нет: один вызов работает только с одной операцией по индексированным UUID.

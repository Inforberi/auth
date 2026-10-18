# Состояния и переходы проектов — MP2.2

18 октября 2026. Внутренние domain rules и PostgreSQL persistence; **без service/HTTP/executor wiring и создания физических БД**. Полная матрица и решения — [ADR005 §2.1](../adr/005-independent-projects.md#21-lifecycle-проекта--mp22); исходная read-модель — [project catalog](project-catalog.md).

## Что реализовано

- `domain/transition.go`: шесть команд lifecycle, допустимые источники actor, validation/bounds, версия и generation, typed receipt. Здоровье SQL/Redis не является командой lifecycle. `DesiredState.Valid` и `Phase.Valid` запрещают неизвестные значения.
- `repository/postgres/transition.go`: `Transition(ctx, tx, command)` присоединяется к caller-owned transaction; не открывает свой pool/транзакцию. Это позволяет будущему platform service держать authority locks до того же commit, а не проверять права отдельным устаревающим запросом.
- `platform.project_events` в исходной catalog000001: атомарный audit/receipt, уникальность `(project_id,operation_id)`, metadata only. Нет credentials/DSN/raw SQL errors. PUBLIC grants отсутствуют; platform runtime пока не получает mutation/event grants.

Вызов требует явных `ProjectID`, `OperationID`, `ExpectedVersion`, `ExpectedGeneration`, `Action`, `ActorKind`, `ActorID` и `Reason`. IDs — canonical nonzero UUID; reason — непустой UTF-8 до500bytes, без controls/внешних пробелов. Reason — безопасная причина/incident reference, не место для пароля/секретов/driver error. Operator actor применяется к suspend/resume/retry; provisioner — к begin/fail/finish. Это проверка корректности attribution, **не авторизация оператора или executor**.

## Транзакционный контракт

Вызывающий service обязан открыть ограниченную Read Committed transaction, получить текущие platform session/permission/fresh-proof locks **до project row** и откатить транзакцию при любом error/cancellation. Persistence ограничивает свою работу3s с учётом caller context, но не может автоматически закрыть чужую транзакцию: caller отвечает за общий deadline и bounded rollback cleanup. Receipt становится подтверждённым результатом только после успешного commit.

Обычный переход — один indexed project row lock, один indexed receipt lookup и один data-modifying CTE `UPDATE … RETURNING → INSERT audit … RETURNING`. Audit failure не оставляет обновлённое состояние. Нет full scans, глобального project mutex, N+1, UPDATE при health/replay или автоматических retry loops. Разные проекты не сериализуются общей lifecycle-блокировкой.

Точный committed повтор возвращает прежний receipt (`Replayed=true`), а не текущее состояние проекта; повтор после последующих изменений также не выполняет действие снова. Различие любого существенного поля под тем же operation UUID или stale version/generation — `ErrConflict`. Невозможный переход/finish без binding — `ErrInvalidTransition`; unknown project — `ErrNotFound`; DB/scan/lock failures — sanitized `ErrUnavailable`, context cancellation сохраняется через errors.Is. Не публиковать драйверную ошибку.

Generation растёт на каждом принятом lifecycle change и предназначена для будущих runtime leases, но runtime registry ещё не подключён. Suspend не удаляет БД/пользователей/сессии; resume не переподготавливает готовую БД. Finish при suspended сохраняет suspension. Binding/schema поля на finish необходимы, но реальную storage ownership/readiness/compatible schema должен проверить будущий trusted executor MP3; произвольный клиент не получает finish API.

## Схема и границы

Новая audit table добавлена в исходную [catalog migration](../../migrations/platform/000001_catalog.up.sql); [down](../../migrations/platform/000001_catalog.down.sql) сначала удаляет её, затем projects. Рабочая Auth БД и реальные ENV/secrets не менялись. На старой установленной platform schema одного обновления исходного SQL недостаточно: нужен отдельно согласованный forward upgrade. Не запускать down/reset рабочей БД.

`project_events` не имеет FK на Auth пользователя: catalog migration остаётся независимо применимой до Auth/operator schema, а executor не является выдуманным project user. Future service получает actor из проверенной platform identity; прямые writers/DBA остаются доверенными. Audit rows/receipts пока не очищаются; retention/horizon и append-only management grants — отдельные задачи перед эксплуатацией. Существующий Auth audit cleanup эту таблицу не затрагивает.

## Проверки

Domain tests перебирают всю матрицу, неизвестные states/actions, source actor, input/reason bounds и counter overflow. `TestProjectTransitionsPostgres` проверяет workflow/retry/suspend/finish/resume, stale executor, missing binding, generation conflict, lost-response replay после новых изменений, payload/actor collision, отсутствие UPDATE при replay, rollback/audit failure, parallel version winner и duplicate operation, bounded lock/cancellation, независимость project locks, unknown project и отсутствие PUBLIC grants. В той же fixture выполнена регрессия catalog/indexes и platform owner/authority.

Команды/результаты/cleanup — [history](../planning/history.md#результат-mp22-project-lifecycle--18-октября-2026). Без AUTH_PLATFORM_TEST_DATABASE_URL SQL fixture SKIP; обычный `task check`/unit race не выдаются за SQL acceptance. HTTP/fleet/real provisioning/DB grants upgrade/load/GC не реализованы/не проверялись этим этапом. Далее — MP2.5/MP2.6 защищённый platform management API, не открытый вызов persistence из HTTP.

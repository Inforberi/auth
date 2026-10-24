# Отказы и конкурентный отзыв доступа при создании роли

MP2.7,24 октября2026. Статус: сценарии подготовлены, SQL/race/lint передаются в отдельный чат «Проверки Auth — Luna». До фактического отчёта это NOT RUN, не закрытый security gate.

## Матрица SQL authority

Для session revoke, удаления platform AccessManage, удаления TOTP и suspend проекта проверяются обе стороны [commit admission](../features/platform-role-intents.md):

| Порядок | Ожидание |
| --- | --- |
| Изменение начато → admission ждёт row lock → изменение committed | Admission отклонён, admission row отсутствует |
| Admission committed → изменение committed → новый admission | Новый admission отклонён |
| Admission committed → изменение committed → исходная команда на warm exact runtime | Принятая команда может завершиться до прежнего deadline; есть role receipt/outcome |

Порядок координируется настоящим PostgreSQL row lock и наблюдаемым `pg_stat_activity.wait_event_type='Lock'`, без предположений по sleep. Stats snapshot очищается перед наблюдением внутри blocker transaction. Все изменения — синтетический SQL fixture; это не browser/API сценарии выключения MFA и не имитация обычного user-session revoke.

У suspend нет обещания открыть новый cold runtime: credential loader всё ещё может запретить его. Проверяется разрешённое завершение уже принятой команды через существующий warm pool, без retarget/fallback/продления допуска. Permission case проверяет platform AccessManage grant; полная матрица изменения проектных roles/policy ещё отдельная задача.

## Реальное закрытие соединений

| Сценарий | Что контролируем |
| --- | --- |
| Backend terminate до начала записи | На выбранном leased connection получить PID и через root тестового стенда вызвать pg_terminate_backend с bounded wait. Выполнение на потерянном соединении отказывает до начала transaction; role/receipt отсутствуют |
| TCP close после durable commit, до клиентского ответа | Test-only net.Conn gate удерживает чтение ответа COMMIT после TLS. Независимое соединение видит committed receipt; контроллер закрывает реальный socket. Клиент должен вернуть unknown, не success/rollback |
| Восстановление после закрытия socket | Reconcile читает receipt через trusted registry, сохраняет outcome; роль остаётся одна и новый admission не выдаётся |

Gate не подменяет Commit ошибкой после успешного возврата: драйвер сам сталкивается с закрытым соединением до разбора ответа. Это управляемый локальный разрыв одного TCP/TLS соединения, не packet-loss/partition proxy, process crash, failover или fleet приёмка. Старый lost-ack adapter сохраняется как отдельная детерминированная regression.

Исходники: `cmd/project-prepare/role_{authority,transport,wire}_integration_test.go`; вход — nested `authority and transport faults` в existing TestPrepareCommandSQL. Требуется isolated PostgreSQL18.6 с TLS fixture, AUTH_STORAGE_TEST_TLS_CA и прочими existing command-test variables. При отсутствующем TLS fixture соответствующий parent SKIP не считать прохождением.

## Порядок проверки

Основной чат: formatter и compile-only `go test ./cmd/project-prepare -run '^$'`. Это не выполнение новой SQL матрицы.

Отдельный чат Luna: неизменяемый source snapshot, `task check`, целевой command `-race` и actual PostgreSQL TLS suite. Сохранять версию/логи/exit status и отсутствие SKIP для новых scenarios. При сбое вернуть диагностику; исправления — в основном чате, повторять только затронутые проверки. Disposable DB/roles/контейнеры имеют собственные имена, рабочие данные не меняются.

Результаты добавляются после отчёта в [history](../planning/history.md) и [acceptance](acceptance-summary.md). HTTP, production assembly/автоматический invalidation, fleet/fairness/rate budgets, concurrent read/reconcile authority changes и полная project-role matrix этим подготовленным блоком не закрыты.

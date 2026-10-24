# Отказы и конкурентный отзыв доступа при создании роли

MP2.7,24 октября2026. Статус: отдельный чат «Проверки Auth — Luna» выполнил task check/lint0, command race и actual PostgreSQL18.6 TLS suite PASS9.54s, все новые cases без SKIP. [Evidence](../planning/history.md#результат-mp27-authoritytransport--24-октября-2026). Это закрывает перечисленные локальные сценарии, не весь MP2.7/fleet security gate.

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

## Дополнение: команды ролей и восстановление результата

Сценарии добавлены24 октября и проверены Luna: **PASS** task check/command host race/actual TLS SQL suite, fixture очищен, manifest совпал до/после. [Evidence](../planning/history.md#результат-mp27-role-concurrency--24-октября-2026). Новые SQL cases входят в existing `TestPrepareCommandSQL`, без production hooks, schema/routes/dependencies.

| Сценарий | Требуемый результат |
| --- | --- |
| Четыре одновременных Execute с одним process-local admission | Один success/receipt, остальные conflict, admission не переиспользуется |
| Два разных operation UUID с одинаковым role key и разными permissions | Только один результат/receipt/outcome; права победителя не смешиваются с другим запросом |
| Локальный role writer держит общий Access lock и commits создание того же key | Platform Execute наблюдается ожидающим SQL lock, затем conflict без своего receipt |
| Тот же локальный writer откатывается | Platform Execute после lock wait создаёт роль и receipt |
| Session/read permission/TOTP/auth_version отозваны после initial guard, пока receipt SELECT заблокирован | Финальная выдача результата запрещена, даже если completion evidence уже записано |
| Write permission отозван или проект suspended в том же окне | Read-own ранее принятого результата разрешён на уже открытом exact runtime |
| Четыре параллельных reconciliation запроса | Один catalog outcome, прежний role snapshot; project receipt xmin и число admissions не меняются |

SQL порядок задаётся advisory lock Access и ACCESS EXCLUSIVE lock receipt-таблицы. Ожидание подтверждается `pg_stat_activity`, без sleep. Reconciliation проверяется отдельно от новых мутаций: suspend не обещает cold-open, новый admission и права на запись не выдаются. Все изменения session/proofs/state выполняет root только своего disposable fixture с восстановлением после подслучая.

Исходники: `cmd/project-prepare/role_concurrency_integration_test.go`, `role_outcome_concurrency_integration_test.go`; подключены к existing role admission/runtime drills. Cleanup расширен только на префикс синтетических `bridge_race_` ролей/receipts. Это не новые HTTP role update/assignment APIs и не полная матрица всех будущих project policy/settings сценариев.

## Порядок проверки

Все исполняемые проверки — отдельный чат Luna на неизменяемом снимке. Основной чат пишет сценарии и форматирует изменения, не запускает даже compile-only тесты. Передать `task check`, command package race и actual PostgreSQL18.6 TLS `TestPrepareCommandSQL` с новыми nested cases без SKIP. Production API/crypto/dependencies не менялись: повтор scanner/Swagger без причины не нужен.

Логи/exit status/версии/snapshot сохранять в evidence; обратно только ошибки, при успехе короткий PASS со snapshot ID. При сбое исправляет основной агент, Luna повторяет затронутые проверки. Disposable DB/roles/контейнеры имеют собственные имена, рабочие данные не меняются. [Правила](../ai/development-workflow.md).

Результаты добавляются после отчёта в [history](../planning/history.md) и [acceptance](acceptance-summary.md). HTTP и оставшиеся production assembly/credential rotation/fleet gates остаются отдельно; эта локальная матрица их не закрывает.

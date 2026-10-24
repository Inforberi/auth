# Сборка SQL runtime и изменения lifecycle

MP4,24 октября2026. Реализация проверена отдельным чатом Luna: Go tests/race/security и actual command/assembly SQL PASS, финальный targeted lint0/parser/runtime race PASS. Первоначальный полный task check завершился FAIL на lint до исправлений; полный повтор не выполнялся. [Evidence](../planning/history.md#результат-mp4-local-runtime-lifecycle--24-октября-2026). HTTP role bridge не открыт; существующие platform suspend/resume/retry routes передают подтверждённые изменения локальному реестру при включении runtime.

## Включение

По умолчанию `PLATFORM_PROJECT_RUNTIME_ENABLED=false`: нет нового reader pool, master codec или registry janitor. При включении требуется PLATFORM_ENABLED и валидный platform profile. Все значения ниже относятся к operational deployment, не к body/Host/origin клиентского запроса. Примеры — [.env.example](../../.env.example) и [.env.prod.example](../../.env.prod.example); реальные env не менялись.

| Настройка | Назначение |
| --- | --- |
| PLATFORM_RUNTIME_CATALOG_URL | Отдельный SELECT-only catalog LOGIN, не обычный DATABASE_URL и не provisioning/root credential |
| PLATFORM_PROJECT_MASTER_KEY / PLATFORM_PROJECT_MASTER_KEY_ID | Тот же защищённый master key/key ID, которым запечатаны credentials; не копия user password и не API input |
| PLATFORM_STORAGE_HOST / PLATFORM_STORAGE_PORT | Один configured storage endpoint, используемый выбранным PLATFORM_STORAGE_TARGET; database/runtime role выводятся из project UUID |
| PLATFORM_STORAGE_CA_FILE | Необязательный PEM CA для сети; без него системные roots. Network TLS проверяет host. Для Unix socket параметр должен быть пустым |
| PLATFORM_PROJECT_MAX_RUNTIMES / PLATFORM_PROJECT_MAX_CONNECTIONS / PLATFORM_PROJECT_SQL_BUDGET | По умолчанию8 ×4 ≤32 проектных connections на процесс |
| PLATFORM_PROJECT_MAX_ACQUIRING | До64 одновременно открывающих/ожидающих calls, сверх лимита отказ |
| PLATFORM_PROJECT_ACQUIRE_TIMEOUT / PLATFORM_PROJECT_OPEN_TIMEOUT / PLATFORM_PROJECT_IDLE_TIMEOUT | По умолчанию2s /2s /5m; не продлевают admission deadline |

Reader catalog pool имеет MaxConns2, MinConns/MinIdleConns0. Эти2 connections идут дополнительно к project budget; учесть также обычный platform pool, workers и число API replicas. Число зарегистрированных проектов не умножает MinConns. Fleet-wide admission/справедливость и общий deploy budget ещё отдельный этап.

Reader startup/readiness проверяют его SQL профиль и ожидаемый realm. Root/привилегированный/пишущий credential отклоняется; нет fallback к обычному API pool. [Минимальные grants](../../deploy/platform-runtime-reader-grants.sql) и отсутствие PUBLIC TEMP/CREATE должен подготовить deployment. Initialized realm не требуется для самого startup probe, но cold credential load требует enabled/ready проекта и initialized realm.

Общий trusted PostgreSQL parser вынесен в `internal/infra/postgres`: один явный endpoint, network verify-full или явный local Unix socket, без multi-host fallback и чужих PGOPTIONS/runtime params. Existing project-prepare использует тот же parser со своим прежним timeout profile, второй копии transport validation нет.

## После изменения состояния

`Catalog.ChangeState` сначала вызывает existing SQL mutation port. Только успешный commit result передаёт `TransitionReceipt` в observer; ошибка/unknown commit не превращаются в фиктивный success. Наблюдение локальное, без дополнительной SQL-транзакции и без зависимости от отменённого client context.

`Registry.Observe` привязан к realm/project UUID. Старые resident snapshots retiring по version/generation; точный snapshot не-ready/disabled состояния также retiring. Активная lease сохраняет свой pool до возврата callback. Opening старой версии после наблюдения не публикуется, idle pool закрывается, closing pool остаётся в бюджете.

Задержанный replay старого suspend не должен закрыть более новый generation после resume. Observer не хранит бесконечный watermark/tombstone на каждый зарегистрированный проект: работает только с bounded resident entries. Если старого entry уже нет, fresh cold load сверяет актуальные SQL state/version/generation. Observer не является authority; current admission/revoke и actual transaction profile по-прежнему обязательны.

При наблюдении suspend новые leases старого cached entry не выдаются. Уже выданные операции могут закончиться в ранее согласованном admission window; ещё не получивший lease admission не имеет гарантии завершения. Это не принудительный откат уже принятой команды и не изменение обычного session revoke.

## Завершение и ограничения

Сборка регистрирует свои resources в existing LIFO ownership: server drain → delivery/retention join → registry drain → private reader pool → shared dependencies. При ошибке последующей сборки закрываются уже созданные собственные resources; typed-nil observer при отключённом runtime не передаётся.

App.Close, как и прежний pgxpool.Close, синхронно ждёт своих активных операций; принудительного закрытия lease ради таймера нет. Registry.Close(ctx) по-прежнему позволяет отдельному caller ограничить ожидание; приложение при финальном cleanup использует uncancelled drain. Зависшие некорректные callbacks не объявлены автоматически безопасными: production lease consumers должны иметь bounded operation deadline, текущий role consumer ограничен admission.

Это local lifecycle wiring одного API instance. Direct provisioning SQL/другая replica не посылают этому observer уведомления. Fleet watcher/polling/Redis signal, ordinary project request resolver/полная Auth assembly и role bridge HTTP остаются открытыми. Пока готовые проекты физически не готовятся автоматически этим флагом, target migration/restore/readiness правила не обходятся.

Credential rotation ещё не реализована. Её producer должен менять catalog generation/version и инвалидировать соответствующие runtimes; не менять password незаметно под тем же snapshot key. Source reload/изменение deployment ENV применяется перезапуском, не изменением process-global current project.

## Проверки

Подготовлены unit tests: observe во время active lease/cold-open, realm fence, stale replay/new generation, observer только после confirmed receipt, config bounds/secret-safe errors, runtime disabled/invalid transport. SQL TestProjectRuntimeAssemblySQL — отдельная disposable БД auth_runtime_assembly_test, restricted reader startup/readiness, unsafe grants refusal/failed-start cleanup и shutdown без оставшихся reader sessions. Existing command TLS suite проверяет перенос trusted parser/reader profile без ослабления прежних гарантий.

Перечисленные unit/SQL сценарии проверены, новый assembly SQL выполнялся без SKIP. Отдельная [authority/transport матрица](../operations/platform-role-faults.md) также прошла в составе command regression. Host race не является live SQL-race; новая проверка не закрывает fleet/rotation/полную Auth assembly.

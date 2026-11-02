# Реестр подключений к проектам

MP2.7 / часть MP4,24 октября 2026. `internal/admin/projects/runtime` переиспользует ограниченное число SQL-пулов. `AdmittedRoleCreation.ExecuteWithRuntime` выполняет существующий role protocol через арендованное соединение. HTTP/server/полная Auth-сборка проектов пока не подключены.

## Доверенный источник подключения

`NewTarget` принимает только operational host/port/TLS config. Network требует проверки сертификата и точного ServerName, минимум TLS1.2; Unix socket разрешён только явным абсолютным путём без TLS. Подключение требует SCRAM, пароль берётся из typed credential, а имя БД/runtime роли выводится из UUID. DSN из HTTP, root/provisioning credential, default project и fallback-серверы не используются. Карта targets копируется при создании реестра; неизвестный target отклоняется до чтения секрета.

`RuntimeCredentialReader` использует отдельный catalog LOGIN NOINHERIT с SELECT на realm/projects/preparations/secrets, без Auth доступа, DDL/TEMP и catalog DML/членства в ролях. Образец выдачи прав — [platform-runtime-reader-grants.sql](../../deploy/platform-runtime-reader-grants.sql). Deployment должен отдельно создать LOGIN/его защищённый pool и убрать PUBLIC TEMP/CREATE; скрипт не создаёт роль и не отзывает права других пользователей автоматически. Master key передаётся готовому codec из защищённой сборки, не читается из API. Существующий provisioning reader не переиспользуется для ready-проекта.

Один SQL snapshot проверяет профиль reader и точные realm/project/reservation/target/OIDs/schema/version/generation, committed secrets flag и enabled/ready состояние перед расшифровкой. Reader возвращает только DB credential, не signing/setup/encryption material. Ключ пула включает полный binding, version и generation; он идентифицирует ресурсы, но не выдаёт authority. Повторное использование пула не проверяет каталог заново: текущая authority принадлежит admission, а не кешу подключения.

Runtime config перезаписывает endpoint/user/password/TLS/fallbacks, runtime parameters, authentication/protocol options и бюджеты. PostgreSQL environment не выбирает проект или его credentials. Ошибки открытия возвращаются без DSN, password и SQL/transport текста. При ошибке parsing внешнего окружения — отказ, не попытка другого endpoint.

Каждая новая physical connection проходит [SQL runtime profile](project-runtime-profile.md) через `AfterConnect`. Role writer дополнительно проверяет свою actual transaction: cold-open не заменяет текущие SQL гарантии. TLS подтверждает сервер, SQL profile — нужную БД/роль/схему; source checksum не является полным DDL scanner.

## Бюджеты и аренда

| Config | Назначение |
| --- | --- |
| MaxRuntimes | Максимум resident/opening/closing пулов в одном реестре |
| ConnectionsPerProject | Максимальный размер одного SQL-пула |
| ConnectionBudget | Проектный connection ceiling процесса; конфигурация требует MaxRuntimes × ConnectionsPerProject ≤ budget |
| MaxAcquiring | Максимум одновременно открывающих/ожидающих подключения вызовов; сверх него немедленный ErrBusy |
| AcquireTimeout | Общий deadline ожидания слота, cold-open и выдачи подключения |
| OpenTimeout | Дополнительный потолок cold-open/connect, не продлевающий deadline вызывающего кода |
| IdleTimeout | Закрытие неиспользуемых пулов; cleanup раз в min(IdleTimeout,1min) |

MinConns/MinIdleConns равны0. Пул открывается один раз на точный key; конкуренты ждут общий результат/освобождение слота с ограниченным deadline. Failed open освобождает слот; новые попытки могут повторить загрузку. Отдельного бесконечного retry/circuit-breaker нет.

`Use` удерживает ссылку на entry во время получения connection и до завершения callback, затем освобождает connection и lease даже при ошибке. Транзакции нужно закончить внутри callback; нельзя передавать DB/transaction в асинхронную работу после его возврата. Для role операции весь acquire/execute ограничен прежним admission deadline до3s; холодный старт может исчерпать его, но не продлевает authority.

На saturation вытесняется самый старый idle pool; активный не закрывается. `Invalidate(key)` снимает с повторной выдачи только точный снимок. Новая version/generation имеет другой key; старый запрос не переадресуется. Уже выданная lease завершает свою операцию согласно admission-контракту. Это не механизм отзыва пользовательской сессии.

Закрывающийся pool остаётся в budget до завершения `pgxpool.Close`. Закрытие выполняется отдельно, максимум одна такая работа на entry, их число ограничено MaxRuntimes. Один janitor на registry, не worker на зарегистрированный проект. `Close(ctx)` запрещает новые leases, будит ожидающих и ждёт освобождения ресурсов до deadline; при timeout активная операция не обрывается принудительно и остаётся обязанностью владельца. Повторный Close может дождаться её завершения. Не освобождать общие dependencies до drain/успешного Close.

## Проверки и оставшиеся границы

Unit/race: single-flight/reuse, exact snapshot keys, error release, idle eviction, invalidation активной lease, ожидание при занятом/закрывающемся слоте, bounded acquisition, cancellation, shutdown/retry и отсутствие endpoint/credential fallback. Config tests проверяют TLS, isolated password/runtime parameters и SQL ceilings.

Actual PostgreSQL18.6 suite: отдельный read-only catalog reader, отказ stale generation и лишних reader write privileges, запрет Auth/DML, TLS/SCRAM runtime connection, full SQL profile, role commit+catalog outcome через registry, отказ suspended cold-open и восстановление после enable. Стенд использует временные cert/credentials; это не production DNS/PKI/fleet acceptance. Базовый role/admission/provisioning suite также сохранён.

Отдельными блоками добавлены [read-own outcome recovery](platform-role-outcomes.md), проверенная [local authority/socket fault матрица](../operations/platform-role-faults.md) и [опциональная platform assembly/private reader/local lifecycle observer](project-runtime-lifecycle.md). Не закрыты fleet invalidation/master rotation, общий бюджет по instances/catalog/workers и fairness/rate admission; полного Auth runtime/worker scheduler нет. Pool registry сам по себе не выбирает policy, SMTP или feature services. Полная project-role/read-reconcile concurrency matrix и HTTP остаются gates. Memory/GC и capacity — MP8.

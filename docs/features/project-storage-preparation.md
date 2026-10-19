# Подготовка физической БД — MP3-storage

19 октября 2026. Работает одноразовая команда `cmd/project-prepare`: существующий [catalog Reserve](project-preparation.md) → отдельный PostgreSQL target → закрытая БД и NOLOGIN-владелец. Это **не готовый проект**. Opt-in установка схемы/NOLOGIN runtime grants добавлена [отдельным schema stage](project-schema-preparation.md); runtime LOGIN/credentials, независимые ключи, onboarding и публикация ready ещё впереди. Auth HTTP не вызывает DDL и не получает provisioning credentials. Фонового планировщика, брокера и новых HTTP routes нет.

## Настройка отдельного процесса

Используются четыре operational ENV из [отдельного примера](../../deploy/project-prepare.env.example), не из настроек пользователя/UI:

| ENV | Назначение |
| --- | --- |
| `PROVISIONER_REALM_ID` | UUID уже настроенной платформы |
| `PROVISIONER_STORAGE_TARGET` | Единственный разрешённый target, совпадающий с каталогом и marker |
| `PROVISIONER_CATALOG_URL` | Catalog LOGIN с [минимальными preparation grants](../../deploy/platform-preparation-grants.sql), без Auth/DDL |
| `PROVISIONER_STORAGE_URL` | Отдельный LOGIN целевого PostgreSQL, подключённый к выделенной maintenance-БД |

Для сети обязательны `sslmode=verify-full`, проверка hostname/certificate и один explicit endpoint без fallback. Для локального оператора/тестов допускается только явно указанный Unix socket с `sslmode=disable`; plaintext TCP не допускается. DSN/пароли не передаются в flags и не печатаются в результатах/driver errors. Runtime SQL options из URL/PGOPTIONS заменяются процессом, connect timeout5s, statement timeout45s, lock timeout2s, idle transaction5s. Секреты предоставляет защищённое окружение процесса; пример не содержит рабочих credentials.

Оператор инфраструктуры один раз создаёт **отдельную maintenance-БД**, не Auth/каталог, и отдельный LOGIN `auth_storage_executor`: CREATEDB CREATEROLE NOINHERIT, без SUPERUSER/REPLICATION/BYPASSRLS и чужих memberships. Затем owner/migrator устанавливает [storage-target.sql](../../deploy/storage-target.sql), передав `psql -v ON_ERROR_STOP=1 -v realm=<platform UUID> -v target=primary`. Скрипт не создаёт LOGIN/пароль, не вызывается Auth автоматически и не является новой миграцией Auth. Таблицы принадлежат другому административному владельцу; executor не может менять marker, nonce, owner OID или удалять журнал. API credential не получает grants на эти таблицы.

**Один target имеет ровно одну authoritative maintenance-БД**. Advisory locks PostgreSQL привязаны к БД: второй установленный журнал/копия maintenance-БД на том же кластере не является вторым независимым executor для того же target. Такая конфигурация запрещена. DSN нельзя принимать из HTTP; ручной перенос/failover требует остановки writers и согласованного восстановления marker/resources. Глобальную межкластерную блокировку этот этап не реализует.

## Запуск и результат

Из защищённого окружения процесса, для конкретного pending проекта и актуальных revisions:

```sh
go run ./cmd/project-prepare \
  -project a2000000-0000-4000-8000-000000000001 \
  -operation b2000000-0000-4000-8000-000000000001 \
  -version 1 -generation 1
```

UUID выше — пример, не существующий проект. `operation` — отдельная begin operation, не автоматически UUID создания проекта. После потери ответа повторяют **те же flags**, включая исходные expected version/generation: catalog проверяет receipt и актуальный epoch. После принятого operator retry нужен новый begin UUID/текущие revisions, но прежний reservation nonce сохраняется.

Результат — JSON `projectId`, `stage: database_sealed`, `databaseOid`. Имена ресурсов генерирует domain из project UUID. Публичный name/slug не попадает в SQL identifier; identifiers экранируются установленным `pgx.Identifier.Sanitize`. Вывод — operational результат, не HTTP DTO. Каталог остаётся `provisioning`; binding/credentialRef/schemaVersion и ready не записываются. При ошибке команда завершает процесс с ненулевым кодом; неоднозначный DDL не объявляется success/failed автоматически, состояние остаётся пригодным для явного повторения. Сохранённого error/progress API и автоматического продолжения пока нет.

## Владение и восстановление после сбоя

1. До catalog mutation проверяется storage LOGIN/profile и matching realm/target marker. Catalog Reserve выполняется отдельным ограниченным credential; долгой catalog транзакции на весь DDL нет.
2. Выделенная target connection берёт session advisory lock. Один DDL flow на target; конкурентный процесс немедленно получает `project storage preparation already running`, без очереди/бесконечного ожидания. Блокировка удерживается **той же backend session**, которая делает CREATE DATABASE. Нельзя использовать transaction-pooling PgBouncer или отдавать эту connection в общий pool.
3. В одной короткой target transaction создаются NOLOGIN/NOINHERIT-владелец и запись `project UUID + reservation UUID + owner OID + generation`. PostgreSQL транзакционно создаёт роль, поэтому сбой INSERT не оставляет роль без ownership record. Чужая роль/БД с нужным именем при отсутствии записи — conflict, не adoption. Более старый generation/другой nonce отвергается; новый generation обновляет только его поле.
4. `CREATE DATABASE ... OWNER ... TEMPLATE template0 ALLOW_CONNECTIONS false` выполняется вне транзакции. Владелец уникален и уже атомарно связан с резервацией; до этого у него нет LOGIN и memberships в других ролях. Только выделенный executor имеет membership для SET ROLE. Это связывает владельца с БД уже в момент CREATE, до отдельной записи database OID.
5. Существующая БД принимается только с matching actual owner OID, закрытыми подключениями и прежним database OID, если он был записан. Только для прерванного [schema stage](project-schema-preparation.md) допускается предварительный reseal с matching persisted intent/shared marker/OIDs/restricted ACL. Потом через bounded transaction/SET LOCAL ROLE снимаются PUBLIC database grants и сохраняется OID. Если ответ CREATE/запись OID потерялись, повтор под блокировкой распознаёт уже созданную закрытую БД. Роль с другим OID/LOGIN/чужими memberships, неразрешённая открытая БД, подмена owner/database OID или исчезнувшая уже recorded БД дают conflict.
6. Потерянный target journal при surviving ресурсах не пересоздаётся по имени. Ни БД, ни роль не удаляются автоматически. Утрата всего target/catalog history и самих ресурсов — отдельная recovery процедура, не доказуемая одной проверкой имени.

Роль с CREATEDB/CREATEROLE и superuser/администраторы кластера остаются доверенными инфраструктурными субъектами: журнал не защищает от их намеренного DDL/подделки/выдачи прав. Нельзя вручную создавать ресурсы под зарезервированным NOLOGIN owner и потом ожидать, что исполнитель отличит их от потерянного ответа CREATE. На этой стадии проектные runtime/migrator memberships ещё не выдаются; повтор после следующих стадий требует соответствующего stage-aware протокола.

Уже начатый внешний шаг может закончиться после concurrent suspend: остаётся только закрытая БД без пользователей/секретов. Он не публикует ready/трафик; следующие schema/binding/publication stages обязаны повторно проверять current catalog generation/desired state. Target generation — локальная монотонная защита, не замена catalog authority и не distributed lease.

## Ресурсы и границы проверки

На invocation — одна target session и catalog pool max1/min0, без pool на проект. Общий command deadline90s, storage stage60s, cleanup1s; target lock снимается закрытием connection, в том числе до вывода результата в потенциально заблокированный stdout. Автоматических retries/goroutines/сканирования всех проектов нет. Ограничение DDL на target=1 — консервативный первый профиль, не измеренная capacity и не fleet admission всех процессов. Redis/Auth hot paths не менялись.

SQL-приёмка проверяет реальные отдельные LOGIN и реальные CREATE ROLE/DATABASE на disposable PostgreSQL18.6. Storage tests: exact replay/unchanged ledger xmin, nonce/epoch/target/profile refusals, cross-session lock, bounded cancellation, lost-OID crash window, recorded DB loss, missing ledger, atomic role rollback, чужие role/database names. Command integration: настоящие Auth/platform migrations/grants, отдельные catalog/maintenance-БД, Reserve → physical DB, точный повтор, provisioning вместо ready, stale catalog receipt после suspend. Unit/race без opt-in ENV не заменяет SQL-приёмку.

Evidence этого physical подэтапа — [history](../planning/history.md#результат-mp3-storage--19-октября-2026). Схема и NOLOGIN runtime grants уже добавлены отдельным [opt-in schema stage](project-schema-preparation.md), с временной третьей SQL connection и новым source/identity протоколом. Далее — protected runtime credentials/независимые keys/admin/configuration/binding/readiness. TCP/TLS/storage failover, kill -9 во время active DDL, полный restore и fleet/load/GC — открытые gates; UI не начинать.

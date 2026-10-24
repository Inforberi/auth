# Схема и runtime-права проекта — MP3-schema

19 октября 2026. `project-prepare -schema` расширяет [physical storage stage](project-storage-preparation.md): устанавливает исходную схему Auth и права отдельной **NOLOGIN** runtime-роли, затем снова закрывает БД. Сам schema stage не создаёт пользователей/первого администратора, пароли/signing/integration keys или ready binding. Отдельный opt-in [encrypted secrets stage](project-secrets-preparation.md) уже сохраняет bootstrap-набор, не включает LOGIN/CONNECT. Каталог остаётся provisioning, обычный Auth API ещё не обслуживает этот проект.

## Запуск и источники

Те же четыре protected operational ENV и те же project/begin-operation/expected revisions; добавляется только flag:

```sh
go run ./cmd/project-prepare \
  -project a2000000-0000-4000-8000-000000000001 \
  -operation b2000000-0000-4000-8000-000000000001 \
  -version 1 -generation 1 -schema
```

UUID — пример. Повтор после потерянного ответа использует те же flags. Без `-schema` прежний `database_sealed` flow не меняется. Успех нового этапа возвращает `stage: schema_prepared`, `schemaVersion: 1`; это не readiness проекта.

Bootstrap использует **те же SQL sources**, не копии: [initial Auth SQL](../../migrations/000001_init.up.sql) встроен через `migrations/auth.go`, [runtime grants](../../deploy/runtime-grants.sql) — через `deploy/runtime.go`. Рендерятся только generated database/runtime identifiers с `pgx.Identifier.Sanitize`; SQL/DSN/имена из HTTP не принимаются. Auth SQL не изменён, новых migration-файлов нет. Это bootstrap версии1, не общий migration runner для уже работающих проектов.

Runtime SQL role — `authr_<32 hex project UUID>`, отдельно от владельца `autho_…`. До создания проверяется отсутствие совпадающей роли: существующая роль без matching project marker не принимается по имени. LOGIN, CONNECT и password не выдаются, пока нет защищённого хранения credentials и готовности следующего этапа. Пароль не генерируется «на потом» в открытом виде.

## Ограниченный доступ для установки

1. Существующий Reserve подтверждает catalog intent/epoch и даёт target reservation. `CheckCurrent` читает matching initialized platform realm, текущие enabled/provisioning, version/generation, operation/nonce/target и отсутствие готового binding. Проверка выполняется до schema stage и после его закрытия. Это point-in-time проверка offline стадии, не lease и не разрешение публиковать трафик.
2. Выделенная maintenance session держит прежний global target lock. Перед открытием проверяются actual database/owner OID и ACL: только владелец и возможный CONNECT executor, без PUBLIC/чужих grants. Чужой существующий database comment не перезаписывается.
3. Одна maintenance transaction сохраняет `schema_started=true`, независимый shared database marker `auth-project:<realm>:<project>:<reservation>`, CONNECT только executor и `ALLOW_CONNECTIONS true`. До commit БД остаётся закрытой; после commit разрешённый crash-open распознаётся по persisted intent/marker/OIDs/ACL. Роль runtime всё ещё отсутствует либо NOLOGIN без CONNECT.
4. Вторая connection получает конфигурацию того же trusted target, меняя только generated database. **До DDL** проверяет actual database/owner OID и shared marker: одного hostname/имени недостаточно, DNS мог направить новую connection в другой кластер. Это защита от несоответствия target, не обещание автоматического failover.
5. Project transaction берёт собственный advisory transaction lock: schema writers остаются сериализованы, даже если отдельная maintenance session потеряна. Создание runtime-роли выполняется trusted executor, сам Auth SQL и grants — `SET LOCAL ROLE` в NOLOGIN-владельца. `pgcrypto`/`citext` устанавливаются штатным механизмом trusted extensions с CREATE текущей БД, не superuser. В той же transaction устанавливаются grants и project marker. Ошибка откатывает **роль, схему, grants и marker вместе**.
6. Project connection закрывается, maintenance connection возвращает `ALLOW_CONNECTIONS false` и снимает CONNECT executor. Только после успешного seal и финального `CheckCurrent` возвращается успех. Runtime не может войти ни во время установки, ни после неё.

На ошибке есть ограниченный cleanup с отдельным3s context, project close1s. При потере сети/kill -9 cleanup не гарантирован: БД может временно остаться доступной только trusted executor. Следующий явный запуск reseal допускает исключительно с matching intent/shared marker/actual OIDs и safe ACL; открытая БД без intent или с чужим доступом — conflict. Существующие подключения ALLOW_CONNECTIONS=false не завершает; исполнитель закрывает собственную project session, не запускает принудительное завершение чужих backend.

Concurrent suspend может оставить уже установленную схему и NOLOGIN-роль, но не успешный stage receipt/ready/трафик. Следующая попытка требует актуального lifecycle-протокола, а не автоматического обновления expected revision. Смена состояния сразу после финального snapshot также не открывает доступ: БД sealed, роль NOLOGIN. Будущая публикация ready обязана иметь собственный атомарный authority/binding fence.

## Что хранится и проверяется при повторе

`project_meta.identity` в БД проекта хранит realm/project/reservation UUID, database/owner/runtime OID, schema version и SHA-256 source checksum. Schema, роль и marker коммитятся атомарно. Runtime не имеет USAGE/SELECT/записи в project_meta.

Уточнение24 октября: installer также создаёт [read-only auth.project_identity](project-runtime-profile.md) с несекретной identity/version/checksum проекцией. Прямые private privileges не выдаются. Общая fingerprint function включает initial Auth SQL, конкретные runtime grants и SQL view; old source checksum не обновляется автоматически. Onboarding и проектная role transaction используют единый SQL profile на реальном соединении.

Повтор проверяет marker и реальный runtime OID/имя, отсутствие LOGIN/elevated attributes/чужих memberships, owner schema и effective privileges. Несовпадение версии/source checksum — conflict, **не повторная initial migration поверх данных**. Утрата marker при surviving Auth schema/роли также не вызывает переустановку/adoption. Повтор не переписывает marker и не создаёт новые роли; временное открытие/закрытие БД остаётся необходимой offline проверкой.

Checksum — идентичность установленного source, не полный schema-drift scanner и не защита от злонамеренного владельца БД. Инфраструктурные admins/executor остаются доверенными. Обновления initial SQL/grants после появления постоянных проектов потребуют явного versioned upgrade, а не редактирования baseline и автоматического обхода checksum.

## Права и границы

- Runtime: USAGE auth, SELECT/INSERT/UPDATE/DELETE таблиц и USAGE/SELECT sequences по существующему template. Нет schema CREATE, owner membership, CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS/SUPERUSER, database CONNECT/CREATE/TEMP. `auth.restore_audit` не получает DML; offline MFA decision function не получает EXECUTE. Проверяются effective privileges, не только текст GRANT.
- PUBLIC: нет database доступа, schema CREATE public, доступа к auth/project_meta. Migration `search_path` задан явно `pg_catalog,public`, не берётся из клиентского SQL.
- DDL owner и runtime разделены. Для этого bootstrap отдельный постоянный migrator LOGIN **не выпущен**: защищённый executor работает с ограниченным effective NOLOGIN owner через SET LOCAL ROLE. Обычный Auth runtime эту credential не получает. MP3.4 целиком остаётся открытым до deployment/credentials readiness.
- В текущем [storage-target.sql](../../deploy/storage-target.sql) добавлены только `schema_started` default false и минимальный UPDATE grant, без права вставить flag. Старый target требует controlled forward schema/grants upgrade; автоматически replay/reset его журнала не выполняется.

На invocation максимум3 SQL connections: catalog max1/min0, maintenance1, временная migration1; pool на проект не создаётся. Command90s, schema stage60s, existing connect5s/statement45s/lock2s/idle transaction5s; без фоновой очереди/retry loops. Global target lock не является fleet admission для произвольного числа запущенных процессов; это не измеренная capacity. Auth/Redis горячие пути не менялись.

## Приёмка и следующий шаг

Реальный PostgreSQL18.6: прежний sealed storage flow; unmarked/unsafe crash-open отказ и корректный marked recovery; injected CREATE TABLE fault с полным rollback schema/runtime role; successful schema/replay; реальные SQLSTATE42501 для runtime DDL/audit/marker и разрешённый пользовательский DML в откатываемой test transaction; wrong project marker; suspend при реально заблокированной schema transaction с final conflict и sealed DB. Полный unit/lint, целевой unit race и security — [evidence](../planning/history.md#результат-mp3-schema--19-октября-2026).

Не проверены реальные network TLS/DNS switching/maintenance-session death во время active DDL/kill -9/full restore/production deployment/fleet/load/GC. SQL-рace не подменяется обычным race без opt-in ENV. Далее — защищённое хранение независимых runtime credentials/ключей, безопасная активация доступа, configuration/initial admin и binding/readiness. Ни UI, ни scheduler автоматически не запускаются.

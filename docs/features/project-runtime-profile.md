# Проверка проектного SQL runtime

MP2.7,24 октября 2026. Общий read-only профиль используется существующим onboarding probe и внутри транзакции административного создания роли. Это SQL-проверка, не запуск fleet registry, не выбор DSN из запроса и не готовая HTTP-ручка.

## Источник схемы и публичная проекция

Installer создаёт `auth.project_identity` — view с восемью несекретными полями: realm/project/reservation UUID, database/owner/runtime OID, schema version и source checksum. View принадлежит владельцу БД проекта. Runtime получает только SELECT, без grant option и без table/column прав PUBLIC. Приватные setup hash/flags/ключи не входят в проекцию; прямого USAGE или column/table доступа к `project_meta.identity` у runtime нет.

Чтение underlying marker использует стандартные права владельца view, не права runtime на приватную таблицу. Нового SECURITY DEFINER function нет. [PostgreSQL18 — CREATE VIEW](https://www.postgresql.org/docs/18/sql-createview.html). Профиль проверяет тип/owner и точный состав колонок view: лишнее поле, например setup hash, не принимается даже при совпавших остальных значениях.

`migrations.ProjectSchemaChecksum` — единый источник fingerprint для installer и runtime: SHA-256 от initial Auth SQL, конкретного runtime-grants template и SQL проекции. Fingerprint хранится в прежнем private marker; повторный install не обновляет его при несовпадении. Это идентичность установленного source, **не** динамический hash всей текущей DDL и не защита от злонамеренного DB owner/поддельного сервера. Trusted storage target/TLS/credential provenance остаются отдельной границей.

## Что проверяется

Один общий SQL predicate проверяет actual database/name/OID/comment, realm/project/reservation и runtime binding, версию/fingerprint marker, владельцев Auth/private schema и marker table, current/session user, LOGIN/NOINHERIT и отсутствие привилегированных атрибутов/членства, database/schema ACL и отсутствие DDL/TEMP/grant option. Для Auth tables/views/sequences проверяются контрактные права и owner; protected restore audit/MFA recovery function/project role receipts сохраняют свои исключения. PUBLIC column grants view и даже неиспользуемый runtime column grant приватного marker отклоняются. [PostgreSQL privileges](https://www.postgresql.org/docs/18/functions-info.html).

Onboarding добавляет к тому же predicate свои setup proof/safe-defaults условия, без копии ACL-политики. Создание роли вызывает профиль **на той же caller-owned transaction**, до Access lock, replay и любых role/audit writes. Успешная проверка одного соединения пула не становится разрешением для другого. Меньший прежний identity-only guard удалён, а не оставлен второй проверкой перед новой.

Профиль читает metadata/catalog, не пользователей и не крупные бизнес-таблицы; добавлен один SQL round trip на административный сценарий, а не отдельный запрос на каждую проверку. Обычный login/session/JWT hot path не менялся. Проверка не кеширует authority и не меняет согласованный admission/revoke контракт.

## Grants и обновления

Creation учитывает owner default privileges: сначала снимает возможные CRUD/grant права runtime с новой view, затем выдаёт только SELECT. Шаблон runtime grants объединяет широкую выдачу Auth CRUD и protected-object revokes в один атомарный DO statement; повторное применение после restore сохраняет view read-only и не оставляет промежуточное разрешение записи в неё. Неожиданный relation kind/owner — отказ, не молчаливое исправление чужого объекта. Dollar-quote delimiter не пересекается с подставляемыми экранированными identifiers.

Исходный project install расширен без новой migration/рабочего upgrade. Существующим постоянным проектам требуется согласованный controlled upgrade: новый fingerprint/view не появится от повторного исполнения старого init. При missing/mismatched marker/view/version/grants профиль отказывает; автоматического adoption/reinstall/fallback к соседней БД нет. Generic standalone Auth не требует project view; down SQL учитывает её наличие только если она создана.

## Проверки и границы

SQL fixture проверяет правильный профиль и отказ при wrong checksum/version/realm/project/reservation, unexpected projection, PUBLIC table/column grants, write/missing read на view, private-column grant, missing table/view/sequence права и DDL capability. После каждого fault restore проверяется валидный профиль в rollback-only role transaction. Intentional marker fault writes отделены от activation/replay xmin checkpoints, не отменяя прежнюю no-update гарантию. Проверены source fingerprint, identifier/dollar quoting и reapply grants.

HTTP по-прежнему закрыт. Следующие задачи: trusted target/credential loader и bounded registry/pools/leases, version/generation invalidation, protected outcome reconciliation и реальные transport/fleet faults. Только этот SQL predicate не доказывает доверие к серверу, доступность SMTP/providers, готовность пользователя/политики, capacity или отсутствие утечек памяти.

# Подготовка создания роли владельцем платформы

MP2.7, 21 октября 2026. Это внутренняя подготовка операции в каталоге, **не создание роли** и не открытая HTTP-ручка. Общий протокол — [ADR005 §3](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso).

## Контракт

`Project/repository/postgres.PrepareRoleCreation` принимает текущий platform principal и конкретный `domain.RoleCreation`: UUID операции/проекта, ожидаемые version/generation, key/name/description/permissions/MFARequired и причину. Обычные правила роли переиспользуются из Access domain; порядок permissions канонизируется без изменения входного slice. Пользователь не задаёт actor, realm, action или permission проверки.

Требуется `platform.project_access.manage`, а не только `platform.projects.manage`. Существующий `AuthorizeMutation` проверяет и удерживает текущие realm/user/permission/session/password/TOTP/role guards. Порядок: authority → project row → immutable intent. Вся транзакция ограничена тремя секундами, после ожиданий срок proofs проверяется перед commit. Пока A6.3m не выполнен, текущая platform policy требует password+TOTP.

Допускается только enabled/ready проект с точными version/generation, штатным именем БД и согласованными reservation/storage/schema метаданными подготовки и secrets. Shared project lock конфликтует с lifecycle writers; runtime не получает UPDATE на provisioner metadata и не читает ciphertext. Снимок содержит target, database, reservation и database/owner/runtime OID, schema version. Это **каталоговые метаданные**, не доказательство физической аттестации подключения.

`platform.project_role_intents` хранит неизменяемый снимок запроса, realm/actor/project/binding и время. Actor принадлежит платформе, а не выдуманному пользователю проекта. Platform runtime получает SELECT и INSERT только заданных столбцов; не UPDATE/DELETE/TRUNCATE и не INSERT времени. Runtime profile отвергает расширенные права. Исходная catalog migration дополнена без отдельной upgrade migration; существующие установки этим не обновляются автоматически.

UUID операции уникален в этом сценарии. Повтор сначала заново проверяет authority и актуальную цель: совпадение actor/realm/project/version/generation/binding/request возвращает исходное время без UPDATE. Отличающийся запрос или binding — conflict. Конкурентные одинаковые INSERT дают одну запись; ожидание ограничено общим deadline. Ошибка вставки не оставляет частичного результата.

После `INSERT ON CONFLICT DO NOTHING` существующая запись читается отдельным SQL statement: в Read Committed конфликтующий winner может быть невидим снимку самого INSERT, но видим следующему запросу. [PostgreSQL 18 — Read Committed](https://www.postgresql.org/docs/18/transaction-iso.html).

Возвращается только UUID/время/replayed. Ни сессия, ни секреты, ни подписанный capability не создаются. После потери ответа можно повторить тот же запрос; `unavailable` сам по себе не доказывает rollback.

## Проектная транзакция — 21 октября 2026

`CreatePlatformRoleInTransaction` реализует проектную часть, а не авторизованный bridge. Она принимает caller-owned transaction, отдельный `PlatformActor`, non-secret `credentials.Binding`, команду и реальный permission catalog/MFA capability выбранного проекта. Тип actor задаёт атрибуцию и не является доказательством прав.

До Access lock проверяется actual transaction connection: имя/UUID-derived database, database/owner/runtime OID, database comment с realm/project/reservation, runtime identity без привилегий/членства и владелец Auth schema. Поддерживается текущая schema version. Это защита от перепутанного подключения, **не** замена cold-open полной schema/grants/checksum аттестации, текущего catalog admission или locked platform authority. Затем существующий transaction-scoped Access lock сериализует редкие изменения ролей; горячие пользовательские чтения его не берут.

Новый запрос применяет общие role rules, проверяет permissions в project catalog и MFA capability. SQL-вставка роли/permissions общая с обычным Access create, но обычные project actor/delegation проверки не меняются. `super_admin`/system role создавать этим путём нельзя. Пользователей, memberships и сессий операция не создаёт.

Роль, permissions и `auth.platform_role_creations` фиксируются одной project transaction. Последняя таблица — конкретный audit/receipt: platform realm/actor, operation/project UUID, полный non-secret binding, canonical request и исходный role snapshot. FK ведёт к роли, но не к выдуманному project user. UUID операции уникален в проектной БД; точное совпадение возвращает исходный snapshot без UPDATE и без повторного применения capability policy к уже committed результату. Изменённый actor/binding/request даёт conflict. Реальную platform authority и target caller обязан заново проверить и перед replay. Snapshot — исторический результат операции, не актуальное состояние роли после её последующих изменений.

Project runtime имеет SELECT и column INSERT, но не изменение/удаление/подмену времени receipt; platform runtime в своей БД не имеет к этой таблице доступа. Existing schema/runtime probes учитывают это исключение из обычного Auth CRUD. Стандартная audit retention не очищает receipts; до отдельного контракта хранения очистку не добавлять. FK сохраняет аудируемую роль; будущий delete-role flow должен явно учитывать эти ссылки. Initial Auth source/grants дополнены без новой migration: существующим БД нужен controlled upgrade, а не повторный init/reset.

Функция ограничивает свою работу тремя секундами, но **сама не делает commit/rollback**. Caller обязан rollback при любой ошибке и не возвращать успех до собственного commit. Потерянный commit reply не доказывает rollback. Реальная SQL-приёмка проверяет запись, replay, параллельность, отказ аудита, явный caller rollback и immutable grants; production caller/HTTP ещё отсутствуют.

## Следующий gate — связь с платформенной authority

Намерение не разрешает исполнение само по себе и не означает постановку в автоматическую очередь. Теперь нужна orchestration вокруг готовой проектной транзакции: новая locked platform authority, current target/version/generation и полная cold-open connection attestation, удержание guards до результата, финальный platform status и восстановление по project receipt при неопределённом commit. Отдельно проверить потерю platform SQL-соединения, отзыв прав и suspend во время project write: предварительного чтения authority недостаточно. До этих доказательств нет dispatcher, публичной ручки, автоматического повтора project write или UI. Существующие project-user сценарии не меняются.

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

## Следующий gate — выполнение в проекте

Намерение не разрешает исполнение само по себе и не означает постановку в автоматическую очередь. Перед выполнением нужны новая актуальная platform authority, проверенное конкретное project connection, typed actor origin, сохранение Access invariants, атомарные project mutation/audit/receipt и обработка неопределённого commit. Отдельно проверить потерю platform SQL-соединения, отзыв прав и suspend во время project write: предварительного чтения authority недостаточно. До этих доказательств нет dispatcher, публичной ручки, автоматического повтора project write или UI. Существующие project-user сценарии не меняются.

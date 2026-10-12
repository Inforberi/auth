# Роли и разрешения

## Что реализовано

Backend access отделён от способов входа. Пользователь имеет один UUID и до 32 назначенных ролей; права — объединение permissions этих ролей. Название роли не участвует в проверке доступа. Пароль, Telegram, Google и email OTP используют одинаковые назначения. Регистрация сама по себе не выдаёт административные права.

Каталог объявляет поддерживаемые действия проекта через `settings.NewCatalog`. Permission имеет стабильный key, name, description и group. Пример ключей: `reports.read`, `reports.phone.read`, `reports.salary.read`. Произвольное название в UI не создаёт действующий доступ: backend данных должен проверять соответствующий key.

Два системных действия встроены в каталог:

| Permission | Действие |
| --- | --- |
| `access.roles.manage` | Создание и редактирование обычных ролей |
| `access.assignments.manage` | Назначение и отзыв обычных ролей |

Продукт не может подменить эти записи. Каталог ограничен 512 permissions, одна роль — 128 permissions; повторные ключи и wildcard отклоняются. Ключ — lowercase ASCII с сегментами через точку, максимум 96 байт. Название и описание поддерживают UTF-8 и имеют ограничения размера.

## Backend-контракт

Это внутренние use cases, не опубликованные HTTP-ручки. `service.New(repository, catalog)` получает существующий PostgreSQL pool через access repository; новых pools, Redis caches и workers нет.

| Метод | Назначение |
| --- | --- |
| `Catalog` | Каталог доступных permissions для будущего UI |
| `CreateRole` | Создать обычную роль с выбранными permissions |
| `UpdateRole` | Изменить обычную роль с expected role version |
| `ChangeAssignment` | Назначить/отозвать роль по user UUID, role UUID и ожидаемым role/access versions |
| `Authorize` | Проверить одну permission для текущего пользователя и verifier его SQL-сессии |
| `UserAccess` | Получить текущие role IDs, зарегистрированные permissions и assignment version |
| `ReadRole` | Прочитать роль с permissions; trusted-caller query |
| `ListRoles` | Метаданные ролей без permissions, до 100 за запрос, keyset pagination; trusted-caller query |

Principal содержит user UUID и hash session token, не клиентский список прав. Адаптер обязан получать его из проверенной аутентификации, не из произвольных полей запроса. ReadRole/ListRoles не являются административной авторизацией; до внешней публикации их защищает соответствующий permission check.

Для управления нужны active/nondeleted actor, действующая SQL-сессия с актуальным auth_version и password proof не старше пяти минут. Это ещё не MFA: перед публикацией admin mutations требуется A5. External-only actor без password proof пока не управляет ролями.

Оператор должен иметь management permission и все permissions создаваемой/изменяемой/назначаемой роли. При редактировании проверяются прежние и новые права; при отзыве — права отзываемой роли. Это консервативная delegation policy, без скрытого override. Самому себе назначать роль нельзя. Самоотзыв обычной роли допустим; системная роль защищена отдельно.

Назначать можно active или pending пользователю, но pending не получает доступ до активации. Blocked/deleted target отклоняется. Несколько ролей разрешены; одинаковое назначение не создаёт вторую запись.

## Транзакции и актуальность

Редкие access mutations сериализуются PostgreSQL transaction advisory lock; обычные проверки прав его не используют. Внутри транзакции блокируются пользователи в порядке UUID и session proof, повторно проверяются актуальные права, версии, изменяется состояние и пишется audit. Роль изменяется одним UPDATE и пакетной заменой permissions, без SQL-запроса на каждый permission. Сбой аудита откатывает всю операцию.

Повтор без изменений с актуальной версией не делает лишний UPDATE/audit. Устаревшая expected version даёт conflict, а не молча перезаписывает чужое изменение. После потери ответа следует прочитать текущее состояние; CreateRole не имеет command-id replay, повтор того же key даёт conflict.

Права не помещаются в session token и не кешируются. Authorize делает один индексируемый SQL-запрос с проверкой session/status/auth_version; UserAccess — один запрос. Следующая проверка после committed revoke/edit видит новые права. Уже разрешённая выполняющаяся операция автоматически не отменяется; чувствительные операции должны связывать проверку и запись своими транзакционными гарантиями.

`users.access_version` — версия назначений пользователя, не общий ETag effective permissions: изменение содержимого роли повышает `roles.version`, без массового UPDATE всех владельцев. По assignment version нельзя кешировать права. Все service операции ограничены тремя секундами; rollback cleanup — пятью.

## Системный администратор и незавершённые части

`super_admin` — зарезервированный key/system flag. Обычные create/update/assignment операции не создают, не изменяют, не назначают и не отзывают эту роль; автоматического wildcard bypass нет. Первый администратор, отдельное защищённое управление системными назначениями, MFA и полная last-effective-admin защита при block/delete/recovery остаются 10.3/A5. Нельзя считать последнего администратора полностью защищённым только из-за запрета обычного revoke. Production bootstrap не реализован; SQL seed используется исключительно в изолированных тестах.

Не реализованы HTTP/admin assembly, удаление роли, импорт каталога/шаблонов, MFA, UI и межсервисная передача прав. Импорт файла — 10.5a, trusted API — при конкретной интеграции по 10.5b. Для внешнего backend Auth управляет назначениями, а backend данных применяет ограничения действий/строк/полей, включая read/write/filter/sort/export. Импорт каталога не аутентифицирует этот backend.

## Хранение

`auth.roles`, `role_permissions`, `user_roles` хранят каталог ролей и назначения. Unique/FK/PK исключают повторные ключи и назначения. `auth.access_audit` содержит actor/target/role UUID, событие, версии и bounded role snapshot без session verifier/secrets. Очистка использует существующие SECURITY_AUDIT_RETENTION_DAYS и bounded retention worker, по умолчанию 180 дней.

Расширена только source `000001_init`; рабочая БД не изменяется автоматически. Уже применённой установке нужен отдельный согласованный upgrade, не reset БД.

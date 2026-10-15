# Роли и разрешения

## Что реализовано

Backend access отделён от способов входа. Пользователь имеет один UUID и до 32 назначенных ролей; права — объединение permissions этих ролей. Название роли не участвует в проверке доступа. Пароль, Telegram, Google и email OTP используют одинаковые назначения. Регистрация сама по себе не выдаёт административные права.

Каталог объявляет поддерживаемые действия проекта через `settings.NewCatalog`. Permission имеет стабильный key, name, description и group. Пример ключей: `reports.read`, `reports.phone.read`, `reports.salary.read`. Произвольное название в UI не создаёт действующий доступ: backend данных должен проверять соответствующий key.

Системные действия встроены в каталог:

| Permission | Действие |
| --- | --- |
| `access.roles.manage` | Создание и редактирование обычных ролей |
| `access.assignments.manage` | Назначение и отзыв обычных ролей |
| `accounts.email.bind` | Одобрение первичного контакта external-only пользователя |
| `accounts.users.manage` | Создание pending пользователей, выдача/перевыпуск приглашений и временных паролей |
| `accounts.users.read` | Список и карточка пользователей без права изменять их |
| `accounts.users.status.manage` | Административная блокировка и разблокировка |
| `accounts.users.delete` | Необратимое удаление аккаунта с сохранением tombstone |

Продукт не может подменить эти записи. Каталог ограничен 512 permissions, одна роль — 128 permissions; повторные ключи и wildcard отклоняются. Ключ — lowercase ASCII с сегментами через точку, максимум 96 байт. Название и описание поддерживают UTF-8 и имеют ограничения размера.

## Backend-контракт

`service.New(repository, catalog)` получает существующий PostgreSQL pool через access repository; новых pools, Redis caches и workers нет. В A4.3-local внутренние mutations подключены к protected HTTP без повторной реализации. Trusted ReadRole/ListRoles остаются внутренними; HTTP вызывает отдельно авторизованные management queries.

A5.2d публикует отдельный protected admin endpoint [первичной привязки почты](email-binding.md), не общий roles/users/status API. Встроенный `accounts.email.bind` разрешает только approval конкретного external-only target; текущие permission/password/MFA/session проверяются в SQL при выдаче и подтверждении. Выдача core permission существующим ролям не автоматическая. Владельцу этого административного permission отключение MFA запрещено, как и владельцам access management permissions.

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

Для изменений нужны active/nondeleted actor, действующая SQL-сессия с актуальным auth_version, password и MFA proofs не старше пяти минут и current enrolled factor. Это SQL enforcement A5.2b, не клиентский flag. External-only actor без password proof пока не управляет ролями; первичный setup описан ниже. Для административного чтения нужны текущие permissions/session, но повторное password/MFA подтверждение не требуется.

Оператор должен иметь management permission и все permissions создаваемой/изменяемой/назначаемой роли. При редактировании проверяются прежние и новые права; при отзыве — права отзываемой роли. Это консервативная delegation policy, без скрытого override. Самому себе назначать роль нельзя. Самоотзыв обычной роли допустим; системная роль защищена отдельно.

Назначать можно active или pending пользователю, но pending не получает доступ до активации. Blocked/deleted target отклоняется. Несколько ролей разрешены; одинаковое назначение не создаёт вторую запись.

## Транзакции и актуальность

Редкие access mutations сериализуются PostgreSQL transaction advisory lock; обычные проверки прав его не используют. Внутри транзакции блокируются пользователи в порядке UUID и session proof, повторно проверяются актуальные права, версии, изменяется состояние и пишется audit. Роль изменяется одним UPDATE и пакетной заменой permissions, без SQL-запроса на каждый permission. Сбой аудита откатывает всю операцию.

Повтор без изменений с актуальной версией не делает лишний UPDATE/audit. Устаревшая expected version даёт conflict, а не молча перезаписывает чужое изменение. После потери ответа следует прочитать текущее состояние; CreateRole не имеет command-id replay, повтор того же key даёт conflict.

Права не помещаются в session token и не кешируются. Authorize делает один индексируемый SQL-запрос с проверкой session/status/auth_version; UserAccess — один запрос. Следующая проверка после committed revoke/edit видит новые права. Уже разрешённая выполняющаяся операция автоматически не отменяется; чувствительные операции должны связывать проверку и запись своими транзакционными гарантиями.

`users.access_version` — версия назначений пользователя, не общий ETag effective permissions: изменение содержимого роли повышает `roles.version`, без массового UPDATE всех владельцев. По assignment version нельзя кешировать права. Все service операции ограничены тремя секундами; rollback cleanup — пятью.

## Системный администратор и незавершённые части

`super_admin` — зарезервированный key/system flag. Обычные create/update/assignment операции не создают, не изменяют, не назначают и не отзывают эту роль; автоматического wildcard bypass нет. [Первоначальный setup](initial-setup.md) создаёт первого владельца только после operator/email/TOTP proof, с тремя core permissions и durable marker. Прямой SQL seed используется исключительно в изолированных тестах; operational/browser/UI acceptance setup ещё открыты.

Внутренние account status/delete операции защищают последнее системное назначение: блокировка или удаление его владельца разрешены только при наличии другого active/nondeleted пользователя с `super_admin`. Pending, blocked и deleted не считаются резервным администратором. Обычная роль, даже с management permissions, не заменяет системного администратора. Неактивного последнего владельца также нельзя удалить или административно заблокировать повторно: такой запрос мог бы уничтожить его оставшееся восстановление. Отказ — `account/domain.ErrLastAdministrator`; устаревшая auth_version по-прежнему даёт account conflict раньше этой проверки. Уже завершённое удаление с текущей version остаётся no-op.

Проверка выполняется до отмены recovery/отзыва сессий/изменения аккаунта и аудита. Status/delete и защитный email report берут тот же transaction advisory lock, что access mutations, до блокировок user/session. Транзакции Account и Access явно используют Read Committed: отдельный запрос после ожидания lock видит предыдущий commit. Две административные операции не могут одновременно убрать двух последних владельцев. Это один дополнительный индексируемый EXISTS query на block/delete, не запрос в пути каждого входа или Authorize; ожидание входит в существующий deadline 5s.

Защитный report уже подтверждённой смены email — намеренное исключение: он блокирует даже последнего супер-админа, иначе украденный аккаунт нельзя было бы обезопасить. Назначение сохраняется, сессии отзываются, existing protected recovery возвращает доступ без повышения роли и создания сессии. После security block нельзя административным повторным block/delete уничтожить последнее восстановление. Обычный password reset сохраняет роль и не снимает административную блокировку.

Это гарантия сохранения active системного владельца и recoverable последнего назначения, не проверка доступности SMTP/провайдера или наличия всех будущих MFA факторов. Первичный setup выполнен в 10.3a-local, operator password/lost-factor recovery — локально в 10.3b/13.1d; их внешняя приёмка открыта. System assignment management и политики usable admin login/MFA остаются 10.3/A5/A6. [Status/delete HTTP](account-deletion.md#административный-api--106b-local) использует transaction-owned permissions/password/MFA guards; прежние внутренние ActorID-only операции не опубликованы. Прямое изменение SQL оператором не защищается этими use cases.

Реализованы operator JSON-каталог/preview и сборка `App.Access`: [использование](access-catalog.md). Шаблоны доступны для явного выбора, не создают и не меняют SQL-роли автоматически. MFA login/management и SQL guard реализованы в [A5.2b](mfa.md); удаление роли, runtime/browser импорт, UI и межсервисная передача прав ещё не реализованы. Trusted API — при конкретной интеграции по 10.5b. Для внешнего backend Auth управляет назначениями, а backend данных применяет ограничения действий/строк/полей, включая read/write/filter/sort/export. Импорт каталога не аутентифицирует этот backend.

## HTTP API A4.3-local

База `/api/v1`, HTTPS, существующая `__Host-session` cookie. Actor UUID и token hash берутся только из NoRefreshAuth context. Запросы не обновляют сессию или freshness; все ответы идут с `Cache-Control: no-store`. Mutations требуют разрешённый Origin и JSON; неизвестные поля, включая actor/system/approval, не принимаются. Новых ENV или secrets нет. При `MFA_ENABLED=false` mutation routes не регистрируются; чтения доступны по текущим правам.

| Метод и путь | Назначение и права |
| --- | --- |
| GET `/auth/access` | Собственные `accessVersion`, `roleIds`, `permissions`; без management permission, но с актуальной SQL-сессией |
| GET `/admin/permissions` | Объявленный каталог: key/name/description/group; roles.manage **или** assignments.manage |
| GET `/admin/roles?after=reader&limit=50` | Метаданные без permissions; те же права, limit 1..100, по умолчанию 50 |
| GET `/admin/roles/{id}` | Полная роль с permissions/version; те же права |
| POST `/admin/roles` | Create custom role; roles.manage, delegation, fresh password + MFA |
| POST `/admin/roles/{id}` | Полная замена definition с expectedVersion; тот же SQL guard, включая прежние права роли |
| GET `/admin/users/{id}/access` | Назначения и объединение известных permissions по UUID; assignments.manage |
| POST `/admin/users/{id}/roles/{roleId}` | Grant с expectedRoleVersion/expectedAccessVersion; assignments.manage, delegation, fresh password + MFA |
| DELETE `/admin/users/{id}/roles/{roleId}` | Revoke с тем же обязательным JSON body и SQL guard |

В таблице короткие имена означают полные `access.roles.manage` / `access.assignments.manage`. Каталог не позволяет создавать произвольные backend permissions через HTTP. System role видна в чтениях, но не изменяется/назначается/отзывается обычными mutations. Управление дополнительными системными администраторами — отдельная незавершённая задача.

List возвращает `{roles:[метаданные],nextAfter:"последний key"}`. Cursor исключающий, порядок по key; если страница короче limit, nextAfter пустой. Полная последняя страница может потребовать ещё один пустой запрос. Нет total-count, SQL на каждую роль или загрузки всех ролей. При конкурентном переименовании key список не является snapshot; после изменения обновить просмотр.

Пример create body:

```json
{"key":"report_reader","name":"Чтение отчётов","description":"Без редактирования","permissions":["reports.read"]}
```

Permission `reports.read` должен быть объявлен в operator catalog и доступен администратору. Ответ 201 содержит id/key/name/description/system/version/permissions. Повтор key — 409; API не назначает созданную роль автоматически. Для update передать все поля definition и `expectedVersion` из detail; отсутствующий permissions означает пустой набор, не частичное сохранение старых прав.

Для назначения сначала прочитать role detail и target `/access`, затем отправить:

```json
{"expectedRoleVersion":1,"expectedAccessVersion":1}
```

Ответ `{accessVersion:2}`. При 409 перечитать актуальное состояние и принять решение, а не автоматически подставлять новые версии поверх чужих изменений. DELETE также требует body. Потеря ответа не означает отсутствие commit; сначала чтение. Повтор текущего no-op не создаёт audit/update. Новая версия назначения не меняет auth_version и не требует нового входа: следующая SQL authorization видит grant/revoke.

Admin target read проверяет actor/session/permission и читает target одним SQL statement; неизвестный/deleted target и отсутствие прав дают одинаковый 403. Pending/blocked target может иметь назначения, но не получает действующий доступ: обычные authorization/session checks по-прежнему требуют active/nondeleted. User `/auth/access` не принимает target UUID или клиентский список прав. Это данные для UI, не bearer authority для внешнего backend; backend данных проверяет доступ самостоятельно. `accessVersion` не является ETag всего набора effective permissions.

Ошибки: 400 `invalid_json`/`invalid_query`/`invalid_role`/`invalid_permission`, 401 `unauthorized`, 403 `forbidden`/`fresh_auth_required`/`invalid_origin`, 404 `role_not_found`, 409 `access_conflict`/`target_unavailable`, 503 `temporarily_unavailable`. Domain validation выполняется в service один раз, mapper общий для Access; raw SQL/DSN/secret не попадают в ответы или логи. Reads role list/detail требуют до двух bounded SQL запросов после session middleware; self/target access — по одному. Mutations используют существующие bounded транзакции с атомарным audit, без дополнительного предварительного HTTP Authorize.

Users create/invite/temporary-password transport опубликован в 13.2a.2-local с `accounts.users.manage`, verified principal и transaction-owned password/MFA guard: [создание/приглашения](invitations.md#admin-api-132a2-local), [временные пароли](temporary-passwords.md#admin-api-132a2-local). Permission не даёт права назначать роли, блокировать/удалять или сбрасывать пароль active аккаунта. Владельцу этого management permission отключение MFA запрещено. Браузерная сквозная приёмка с синтетическими пользователями, реальными MFA/SMTP и UI обязательна в A8-admin-e2e; локальные тесты её не заменяют.

Новая чистая установка через initial setup получает семь core permissions. Уже сохранённые роли/назначения автоматически не меняются: при обновлении старого тестового развёртывания новые `accounts.users.manage` / `accounts.users.read` / `accounts.users.status.manage` / `accounts.users.delete` требуют отдельного контролируемого DBA upgrade существующей системной роли с audit/incident; не direct SQL из UI и не self-promotion через обычный API. Read, issuance, status и delete permissions независимы. [Список/карточка](user-directory.md) не требуют нового password/MFA proof, не продлевают session и не дают административных mutations. Нового bootstrap bypass, автоматического wildcard grant или reset БД для этого нет.

## Хранение

`auth.roles`, `role_permissions`, `user_roles` хранят каталог ролей и назначения. Unique/FK/PK исключают повторные ключи и назначения. `auth.access_audit` содержит actor/target/role UUID, событие, версии и bounded role snapshot без session verifier/secrets. Очистка использует существующие SECURITY_AUDIT_RETENTION_DAYS и bounded retention worker, по умолчанию 180 дней.

Расширена только source `000001_init`; рабочая БД не изменяется автоматически. Уже применённой установке нужен отдельный согласованный upgrade, не reset БД.

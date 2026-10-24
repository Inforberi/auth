# Пользователи проекта из общей панели

Часть MP2.7. Backend прошёл локальную приёмку Luna: tests/lint/race/API/security, проектный SQL и регрессия локального каталога PASS. Здесь только чтение; создание, блокировка, удаление и изменение назначений остаются отдельными явными сценариями. UI не добавляется.

## Маршруты и полномочия

| Метод | Путь | Platform permissions |
| --- | --- | --- |
| GET | `/api/v1/platform/projects/{id}/users` | `platform.project_users.manage` |
| GET | `/api/v1/platform/projects/{id}/users/{userId}` | Одновременно `platform.project_users.manage` и `platform.project_access.manage` |

Карточка содержит назначения и accessVersion, поэтому для неё нужен доступ и к пользователям, и к Access. Одного `platform.projects.read` или локальной роли проекта недостаточно. Новых permissions нет; отдельные platform read-only permissions можно согласовать позже, текущая политика консервативна.

Текущая platform session и fresh password/MFA проверяются до получения проектного подключения и повторно перед ответом. Project user не подделывается, проектная сессия не выдаётся. При отзыве любого необходимого разрешения или изменении binding во время чтения подготовленные данные отбрасываются.

Маршруты opt-in: только с project runtime и guarded catalog group. Сохраняются exact host/TLS/Origin, browser/session, capacity/Redis и `no-store`; сессия не продлевается. Все запросы требуют `expectedVersion` и `expectedGeneration` из карточки проекта. Проект enabled/ready и exact binding проверяются до/после readonly repeatable-read snapshot; общий deadline 3 секунды.

## Список

Используется тот же контракт, что у [локального каталога пользователей](user-directory.md):

- `limit`: 1..100, по умолчанию 50;
- `before`: непрозрачный nextCursor из предыдущей страницы;
- `status`: pending, active или blocked;
- `email`: точный нормализованный email, без substring-поиска.

Порядок — createdAt DESC, UUID DESC. SQL выбирает limit+1; нет offset, total count или отдельных сетевых запросов по каждому пользователю. Soft-deleted пользователи исключены. Ответ `account_http.UserPageResponse` содержит users и nextCursor; строка — UUID, status, createdAt, displayName, выбранный email и признак его подтверждения. Список не возвращает роли.

Cursor задаёт позицию, не права доступа и не фиксированный снимок всех страниц. При изменении фильтров следует начать новую пагинацию. Повторяющиеся/неизвестные параметры, GET body и некорректный query отвергаются; HTTP проверяет форму, account service один раз нормализует email/status/cursor/limit.

## Карточка

Ответ `account_http.UserDetailResponse` переиспользован без отдельной копии DTO/mapper. Возвращаются текущие account/auth/access versions, статус, retained contacts, названия external issuers, configured password/MFA flags и role metadata (UUID/key/name/system/version). Role permissions читаются через [карточку роли](platform-role-directory.md), а изменение — через [grant/revoke](platform-role-assignments.md) с актуальными версиями.

Нет password hash, external subject, token, MFA secret или recovery codes. Configuration flags не доказывают доступность метода входа или effective access. Сохранённый soft-deleted пользователь читается по UUID без восстановления. Contacts/providers/roles остаются ограничены действующими bounds; превышение — явный 409, не скрытое усечение. Неизвестный/чужой project user UUID — 404 внутри выбранной проектной БД, без поиска по соседним проектам.

## Разделение authority и persistence

Account repository владеет SQL-проекциями и scanner. Локальные `ListUsers/ReadUser` продолжают использовать исходный materialized `directoryActor` с SQL-проверкой локальной session/UsersRead. Новые явно доверенные transaction readers принимают pgx.Tx и не принимают actor: их единственный production caller — typed platform RuntimeUsers после своего authority/binding guard. Внутренняя transaction scope формирует разрешённую строку только для переиспользования проекции; она не является доказательством доступа и не передаётся из запроса. Нет публичного skipAuth-флага или fabricated local principal.

Нормализация и построение cursor/page выделены из прежнего account List и используются обоими service-сценариями. Разбор SQL ошибок не должен повторно превращать not-found/conflict в unavailable. При ошибке финального platform guard результаты не возвращаются. Данные читаются из одной проектной транзакции; списки и карточки не создают admissions/receipts, не меняют пользователей и не кешируют права.

## Приёмка

Добавлены service/HTTP/router cases и actual HTTPS SQL nested case `platform user directory` в существующем assignment drill. Проверяются pagination/filter/current role/access version, независимость UsersManage/AccessManage, отказ при отзыве UsersManage во время project read и retained deleted user без восстановления/попадания в список. Fixture создаёт только собственные данные/permissions и восстанавливает их при cleanup.

Дополнительно требуется реальный прежний `TestUserDirectorySchema`: локальный SQL actor guard, bounded relation overflow и однозапросный контракт не должны измениться из-за переиспользования проекций. Команды/снимок/PASS/FAIL/NOT RUN — [history](../planning/history.md). Source changes не означают production/fleet/UI sign-off.

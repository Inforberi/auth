# Роли и разрешения внутри проекта

## MP5.1n: HTTP-контракт

Подключаются существующие Access handlers/DTO/service и SQL repository, отдельно от platform operator bridge. Actor — текущая сессия выбранного проекта. Все маршруты используют exact browser Origin и NoRefresh; чтение без Origin разрешено существующим browser policy. Права и сессии не кешируются.

| Метод | Путь | Операция |
| --- | --- | --- |
| GET | `/api/v1/auth/access` | Собственные действующие роли/разрешения из SQL |
| GET | `/api/v1/admin/permissions` | Каталог известных разрешений |
| GET | `/api/v1/admin/roles` | Ограниченный список ролей с key cursor |
| GET | `/api/v1/admin/roles/{id}` | Определение роли |
| GET | `/api/v1/admin/users/{id}/access` | Назначения и разрешения пользователя |
| POST | `/api/v1/admin/roles` | Создать custom роль |
| POST | `/api/v1/admin/roles/{id}` | Изменить custom роль с expectedVersion |
| POST / DELETE | `/api/v1/admin/users/{id}/roles/{roleId}` | Назначить/снять custom роль |
| POST / DELETE | `/api/v1/admin/users/{id}/administrator` | Отдельный системный super_admin flow |

Поля, ограничения и ошибки прежние: [roles/permissions](roles-permissions.md), [каталог](access-catalog.md) и Swagger. API удаления роли не добавляется: его нет в существующем контракте.

## Публикация и каталог

UUID manifest содержит optional `access: {"permissions": [...]}`. Отсутствие объекта отключает все эти endpoints; `browser=true` обязателен. Пустой объект выбирает только built-in разрешения. В программной сборке — `ProjectProfileConfig.Access`, указатель на immutable `settings.Catalog`, созданный `settings.NewCatalog`. Пример — [deployment manifest](../../deploy/examples/project-auth.example.json).

Каталог проекта не наследуется из platform access config. Каждому проекту можно задать свои дополнительные key/name/description/group; built-in ключи сохраняются, wildcard/повторные ключи отклоняются. Это definition доступных permissions, а не выдача прав. Роли создаются/меняются через API, затем назначаются отдельно. Произвольное создание permission через новый endpoint этим блоком не реализуется; существующие import/definition workflows остаются в [контракте каталога](access-catalog.md).

JWT resource catalog остаётся отдельной существующей конфигурацией. При использовании JWT и ролей определения пересекающихся permission keys необходимо согласовать в deployment: включение Access не меняет JWT audiences/resources и не добавляет права в токен автоматически.

При сборке выполняется существующий bounded `CheckCatalog`: ссылки сохранённых SQL role_permissions должны быть объявлены. Несоответствие закрывает Access capability, не создаёт/переименовывает роли и не удаляет данные. В горячем пути эта проверка полного каталога не повторяется. Смена deployment требует обновления конфигурации/перезапуска существующего процесса; нового runtime reload/API нет.

Readiness `access_read` отделён от `access_write`: чтение может работать при отключённой MFA configuration, изменения публикуются только с готовой согласованной MFA management config. При отключённых primary methods существующие сессии сохраняют возможность управления согласно SQL authority. Новых ENV/deps/schema/workers/cache нет.

## Гарантии

ReadRole/ListRoles/catalog требуют актуальное `access.roles.manage` либо `access.assignments.manage`; чужие назначения — assignments.manage, собственный access — действующую сессию. Существующий read contract/последовательность SQL проверок не меняются; это не новая гарантия атомарного snapshot для всех read endpoints.

Изменения требуют свежие пароль и MFA внутри SQL транзакции. Создание/изменение роли требует roles.manage и всех передаваемых permissions; изменить system роль нельзя. Grant/revoke требуют assignments.manage, делегируемые permissions и ожидаемые role/access versions; self-grant и обход system flow запрещены. Изменение роли не назначает её автору автоматически.

Grant активному пользователю меняет access/auth versions и инвалидирует старые сессии. Расширение роли/включение role-required MFA меняет session_revision; no-op не увеличивает version. Revoke отражается в текущих SQL authorization reads. AccessVersion не разрешает кешировать права без политики актуальности.

System administrator flow требует actor уже в system super_admin и пригодного target с подтверждённым permanent password и TOTP; последний пригодный superadmin защищён при revoke. Это не bootstrap/SSO и не возможность custom менеджеру повысить себя.

Каждая операция берёт один runtime lease проекта, общий timeout5s и pre/post binding guards. При ошибке результат не возвращается; ошибка после commit не доказывает rollback. Повтор mutation выполняется по актуальным версиям после сверки состояния.

## Проверки

Добавлены manifest/default-off/UUID isolation/catalog validation и prerequisites/route tests; actual HTTPS/SQL case create/read/update/grant/revoke/my-access, conflict/delegation/unknown-permission/session invalidation, system-flow denial custom менеджеру. Existing standalone `TestAdministratorAssignmentsSchema` покрывает positive system-admin flow и его SQL prerequisites. Локальные проверки Luna V1/V2 PASS: Go tests/API/race/lint, полный Linux ARM64 TestPrepareCommandSQL с project_access_HTTP без skip и targeted TestAdministratorAssignmentsSchema. Выделение browserProfile проверено без изменения поведения; полной MP5 two-project matrix, security review/нагрузки/UI этот блок не закрывает.

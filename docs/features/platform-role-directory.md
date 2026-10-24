# Каталог ролей проекта из платформы

Часть MP2.7. Tests/SQL/race/API/security и финальный targeted lint прошли; исходные gofumpt замечания сохранены в history. Просмотр пользователей и их назначений — следующий отдельный сценарий. UI не добавляется.

## Доступ и маршруты

Используется platform session, без создания пользователя или сессии внутри проекта. Нужны текущие `platform.project_access.manage` и fresh password/MFA по действующей platform policy. Одного `platform.projects.read` недостаточно для просмотра Access-каталога. Новых permissions нет.

Маршруты публикуются вместе с существующим opt-in project runtime и сохраняют exact host/TLS/Origin, browser/session, capacity и Redis guards. Все ответы имеют `Cache-Control: no-store`, сессия не продлевается.

| Метод | Путь | Результат |
| --- | --- | --- |
| GET | `/api/v1/platform/projects/{id}/roles` | Страница метаданных ролей |
| GET | `/api/v1/platform/projects/{id}/roles/{roleId}` | Карточка роли с permissions |

Оба запроса требуют `expectedVersion` и `expectedGeneration` из текущей карточки проекта. Проект должен быть enabled/ready; несоответствие возвращает 409 без перехода на другую БД или default project. Неизвестный role UUID в выбранном проекте — 404. GET body, неизвестные/повторяющиеся параметры и некорректная форма запроса — 400.

## Пагинация и данные

Список принимает `limit` от 1 до 100 (по умолчанию 50) и исключительный `afterKey`. Роли упорядочены по key; `nextAfterKey` передаётся в следующий запрос, пустая строка означает конец страницы. Выбирается limit+1 строк, без offset, total count и запросов permissions для каждой роли.

Строка списка содержит `id`, `key`, `name`, `description`, `system`, `mfaRequired`, `version`. Permissions в списке отсутствуют; пустой список permissions не подставляется вместо неизвестных данных. Карточка дополнительно возвращает фактические permissions. Общий `PlatformRoleResponse` дополнен `system`, включая прежние ответы создания/операций.

Системные роли видны для понимания назначений. Это не разрешает менять `super_admin` обычными grant/revoke ручками. Пагинация не фиксирует весь каталог на время просмотра нескольких страниц: при параллельных изменениях нужно обновить список. Версия роли в карточке используется при последующей мутации, которая снова проверяет актуальность.

## Гарантии чтения

1. Ограниченный catalog guard проверяет текущую platform authority и точную привязку проекта/version/generation. Catalog locks освобождаются до ожидания проектного подключения.
2. Bounded registry выдаёт lease ровно для этой привязки. В проектной read-only repeatable-read транзакции проверяются runtime identity/schema/grants и читаются данные. SQL остаётся в Access repository; локальный actor не подделывается.
3. После чтения повторяются platform authority и точная привязка. Если за время чтения отозвали доступ, приостановили проект или сменили binding, подготовленные данные не выдаются.

На весь сценарий действует общий deadline 3 секунды, включая получение подключения и финальный guard. Здесь нет изменяющего данные admission, intent, receipt, аудита назначения или кеша permissions. Обычные границы отзывов при выдаче ответа сохраняются: проверки не обещают отменить уже отправленные клиенту данные.

## Проверки и ограничения

Добавлены service/HTTP/router cases: ограничения параметров, пагинация, ошибки и opt-in browser/session/capacity boundaries. Actual TLS SQL drill проверяет list/detail/version/unknown target, отсутствие новых admissions, current permission revoke и отзыв между первым guard и выдачей результата. Для последнего тест временно блокирует только собственную проектную таблицу, отзывает platform permission и ожидает ответ без project data.

Все исполняемые проверки выполняет Luna на отдельном снимке; актуальные evidence и статус — [history](../planning/history.md#результат-mp27-role-directory--25-октября-2026). Реальные UI, каталог пользователей, dynamic permission imports, полная project Auth assembly и fleet/load/GC этим блоком не закрываются. Предыдущая assignment SQL-приёмка закрыта: все её nested cases прошли без SKIP в том же общем прогоне.

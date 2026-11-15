# Управление состоянием проектов — MP2.5-write-lifecycle

19 октября 2026. Здесь описаны suspend/resume/retry в operator profile. Отдельно подключено [создание catalog intent](platform-project-creation.md); физические БД/executor/runtime dispatcher и cross-project bridge пока отсутствуют. [Чтение каталога](platform-projects-api.md), [матрица состояний](project-lifecycle.md), [оператор](platform-operators.md).

## Ручки и запрос

| POST | Решение в каталоге |
| --- | --- |
| `/api/v1/platform/projects/{id}/suspend` | enabled → suspended; подготовка и данные сохраняются |
| `/api/v1/platform/projects/{id}/resume` | suspended → enabled; phase не меняется, ready не подготавливается заново |
| `/api/v1/platform/projects/{id}/retry` | enabled/failed → enabled/pending; suspended сначала нужно возобновить |

Только точный HTTPS Host платформы, точный обязательный Origin и её host-only session cookie. Standalone этих ручек не публикует; JWT/project administrator не заменяют платформенную сессию. Query parameters запрещены. JSON имеет один общий контракт:

```json
{
  "operationId": "55555555-5555-4555-8555-555555555555",
  "expectedVersion": 3,
  "expectedGeneration": 3,
  "reason": "incident-123"
}
```

UUID — canonical/nonzero; версии положительные. Reason — безопасная причина/incident reference, UTF-8 1–500bytes без controls/внешних пробелов, не место для секретов. Actor и action не принимаются из body: actor задаёт проверенный session context, action — отдельная ручка. Transport проверяет JSON/query форму; domain проверяет команду один раз в существующем persistence transition, после authority.

Ответ200 содержит только `projectId`, `desiredState`, `phase`, `version`, `generation`, `replayed`. Это **committed receipt**, не текущая карточка проекта. Взять новые metadata можно отдельным GET при наличии `platform.projects.read`.

Первый успех увеличивает version/generation ровно на1 и сохраняет audit. Точный повтор с тем же project/operation/actor/action/reason/expected revisions возвращает прежний outcome и `replayed:true`, даже если состояние уже изменилось следующей командой. Другой payload под тем же operation UUID даёт409. Перед любым replay повторно проверяются текущие права и fresh proofs; потеря права не открывает старый receipt. Operation UUID уникален внутри проекта, а не всей платформы.

## Authority и транзакция

Требуется **`platform.projects.manage`**; `platform.projects.read` и одноимённое Auth permission сами запись не разрешают. Успешный login не является бессрочным разрешением управления. SQL проверяет expected initialized realm, active/nondeleted user, current auth_version/role revision bindings, browser/password profile, живую session, существующие password/TOTP credentials и proofs не из будущего.

Primary password proof должен быть моложе `SESSION_FRESH_AUTH_TTL` (существующая настройка1–15min, default5min), MFA proof — моложе5min, как в текущих административных guards. После истечения нужно существующее POST `/api/v1/auth/reauthenticate/password` и/или `/api/v1/auth/mfa/step-up`, без повторного setup. Настраиваемая required/optional MFA остаётся [A6.3m](../planning/implementation.md#настраиваемая-обязательность-mfa--a63m--a7); этот блок не публикует optional режим и не ослабляет текущую политику.

`NewManaged` получает существующий SQL pool/operator repository и fresh TTL из конфигурации. Сценарий использует одну Read Committed transaction с общим3s deadline:

1. Existing shared Access snapshot lock, исключающий штатные изменения ролей/назначений до commit.
2. Shared row locks initialized realm → active user → точная platform permission.
3. Current role-bound session/password/TOTP rows под shared locks; вычисляется ближайший deadline session/password/MFA.
4. Existing project `Transition`: project row lock → receipt lookup → version/domain rules → атомарные UPDATE+audit.
5. Повторная SQL clock-проверка deadline после ожидания project lock и перед commit. При expiry откатываются также audit/state. Только успешный commit позволяет вернуть receipt.

Shared authority locks позволяют одновременные команды разным проектам и конфликтуют с отзывом permission/session, изменением user auth_version/password/MFA. Кто первым взял нужную блокировку, тот линеаризует действие/отзыв; возврат revoke означает, что более поздняя команда/replay уже не получит authority. Доверенные DBA/manual SQL обязаны соблюдать документированный порядок при изменении ролей: advisory lock не блокирует произвольный обход протокола DBA.

Отмена/ошибка приводит к rollback с отдельным bounded cleanup context1s. Если ответ потерян после успешного commit, повторять **тот же** operation UUID/payload, не создавать новый. Нет автоматических SQL retries, новых соединений/workers/очередей или полного сканирования таблиц. Authority требует нескольких indexed round trips только в административном write path; это не оптимизация публичного login и не измерение capacity.

## Grants и ошибки

[Runtime template](../../deploy/postgres/grants/platform-runtime-grants.sql) содержит необходимые column UPDATE для lifecycle, SELECT/column INSERT для append-only `project_events`; timestamp события задаётся БД. UPDATE(permission_key) нужен PostgreSQL для row-locking SELECT, не является новым endpoint делегирования. Ограниченный project INSERT теперь добавлен только для [creation intent](platform-project-creation.md#схема-и-grants); нет project DELETE, binding/schema rewrite, event UPDATE/DELETE/TRUNCATE, CREATEDB/DDL или executor credential. CheckRuntime отвергает неполные/избыточные grants до assembly.

Для установленной платформы нужен отдельно контролируемый grants upgrade; новый код со старым набором fail-closed не запустится. Никакие реальные grants/ENV/secrets не менялись, новых ENV/dependencies/schema/migrations этим блоком нет.

Ошибки:400 invalid_json/invalid_query/invalid_project;401 unauthorized;403 forbidden/invalid_origin;404 project_not_found после authority;409 project_conflict/invalid_transition;428 fresh_auth_required;503 temporarily_unavailable. SQL error text/credentials не возвращаются и не передаются в log payload. Все ответы no-store, без session refresh, activity update или Set-Cookie.

**Важно:** запись suspended в каталог пока не останавливает произвольный уже работающий backend. Enforcement admission/generation leases появится с MP4; создание БД/finish readiness — только trusted executor MP3. Клиентских begin/fail/finish API нет. Retry сейчас сохраняет намерение pending, не запускает ещё отсутствующий executor. Не выдавать этот блок за готовую multi-project эксплуатацию.

## Проверки

Unit/HTTP/router/Swagger: actor/action/DTO mapping, JSON/query bounds, Origin/Host/TLS/session/no-refresh/standalone isolation и sanitized errors. SQL/Redis/local TLS: настоящий setup+password/MFA login, restricted runtime grants, все3 команды, original receipt после последующих изменений, stale version/payload/state conflicts, current permission revoke перед replay, stale proofs428, unchanged session/no cookie, atomic audit failure rollback. Проверены фактическое ожидание revoke/user/session/password/MFA/Access locks, независимость двух проектов и rollback при MFA expiry во время ожидания project lock.

В конкурентном fixture обнаружено изменение общего pgx Config после открытия административного пула; runtime теперь получает отдельный `Config.Copy()`. Ошибка исправлена в тестовой инфраструктуре, production grants ради теста не расширялись.

Команды/результаты/cleanup/NOT RUN — [history](../planning/history.md#результат-mp25-write-lifecycle--19-октября-2026). Общий race-прогон без opt-in ENV не является SQL-race acceptance. External browser/ingress/SMTP, two-realm/fleet, bridge/provisioning/load/GC/capacity этим блоком не проверены. UI не начинался.

## Связь с двумя runtime — MP5-lifecycle-fault

Принят отдельный [двухпроектный сценарий](../planning/multi-project.md#жизненный-цикл-и-восстановление-зависимостей--mp5-lifecycle-fault): Luna V1 Go tests/оба actual SQL race roots и V2 targeted lint PASS, штатный cleanup/manifest11 подтверждены. Реальные HTTP handlers/production middleware/SQL managed authority связывают suspend/resume/replay с runtime registry observer и доступом к двум физическим БД. Operator proof задаётся SQL fixture, full router/setup/login остаются отдельной принятой приёмкой. Старые исторические ограничения «runtime отсутствует» выше относятся к MP2.5, не к текущей реализации.

## Отображаемое имя проекта

`POST /api/v1/platform/projects/{id}/name` принимает `operationId`, `expectedVersion`, `name` и `reason`. Возвращает имя, версию проекта и признак повтора. Команда требует `platform.projects.manage` и действующих подтверждений пароля и MFA. Повтор с тем же идентификатором и payload возвращает сохранённый результат после проверки полномочий.

Новое имя увеличивает версию карточки. Поколение, slug, origin и привязка к БД сохраняются. Пока идёт подготовка проекта, команда возвращает конфликт. Имя и запись аудита сохраняются одной транзакцией. Перед развёртыванием применить platform-миграцию `000003_project_names` и обновить runtime grants.

## Жизненный цикл пользователя проекта

`POST /api/v1/platform/projects/{id}/users/{userId}/lifecycle` принимает текущие `expectedVersion` и `expectedGeneration` проекта в query, а в JSON — `operationId`, `expectedAuthVersion` и действие `active`, `blocked` или `delete`. Операция требует `platform.project_users.manage` и действующих подтверждений пароля и MFA. Для записи используются проверенная привязка проекта и его runtime-роль. Ответ содержит итоговый `authVersion`. При неопределённом результате следует повторить запрос с тем же идентификатором и параметрами.

Аудит в БД проекта хранит идентификаторы оператора, платформы, проекта и пользователя. Смена статуса и мягкое удаление используют существующие правила последнего администратора и отзыва доступа. Новые проектные БД получают таблицу аудита при подготовке. Для существующего проекта администратор БД применяет Auth-миграцию `000010_platform_user_lifecycle` и выдаёт права из [шаблона проектного runtime](/Users/inforberi/Desktop/Projects/auth/internal/admin/projects/schema/runtime-grants.sql). До применения миграции операция возвращает ошибку доступности.

`POST /api/v1/platform/projects/{id}/users` использует те же параметры версии проекта и принимает `operationId`. Создаёт аккаунт в состоянии `pending` и возвращает его `userId`. Повтор той же операции тем же оператором возвращает первоначальный идентификатор. Создание аккаунта и атрибуция оператора записываются одной транзакцией.

Передайте `invitationEmail`, чтобы вместе с созданием аккаунта поставить в очередь письмо со ссылкой активации выбранного проекта. Запрос использует текущую конфигурацию проекта и лимиты выдачи. Ссылка позволяет задать пароль и подтвердить адрес, открытие ссылки само по себе аккаунт не активирует. Токен и содержимое письма в API не возвращаются. Повтор команды с тем же адресом не создаёт вторую запись в очереди. Изменение адреса под тем же `operationId` возвращает конфликт. Для повторного запроса по-прежнему нужны действующие права и доступность приглашений проекта.

Передайте `temporaryPasswordEmail`, чтобы создать пользователя с временным паролем. Поля `temporaryPasswordEmail` и `invitationEmail` взаимоисключающие. Проект должен поддерживать вход по паролю и выдачу временных паролей. Общая панель возвращает `temporaryPassword` и `expiresAt` один раз. При повторе команды возвращается `userId`, срок действия не продлевается. Временный пароль даёт только право задать постоянный пароль через существующий сценарий проекта. Он не подтверждает email и не создаёт сессию.

В Auth-миграции 000010 выдача из общей панели связывается с записью об операторе платформы. В проектной БД для этого не создаётся локальный администратор. Откат миграции останавливается, пока существуют записи выдачи с этой связью.

Тот же endpoint `POST /api/v1/platform/projects/{id}/users/{userId}/lifecycle` поддерживает два дополнительных действия.

- `temporary_password` повторно выдаёт пароль для pending-аккаунта, которому уже выдавали временный пароль. Действуют настройки проекта и пауза между выдачами. Новый пароль и срок возвращаются один раз. Старый пароль и начатая по нему смена прекращают действовать в той же транзакции. Повтор с прежним `operationId` возвращает `authVersion` без секрета.
- `initial_email` принимает `email` для pending-аккаунта, созданного в общей панели без credentials и без email. Адрес сохраняется неподтверждённым. Команда не отправляет письмо, не активирует аккаунт и не заменяет существующий адрес. Для действующих аккаунтов предусмотрен отдельный сценарий привязки с подтверждением владельцем.

## Операторы общей панели

Владелец платформы управляет операторами через `GET /api/v1/platform/operators` и `POST /api/v1/platform/operators`. Список возвращает до 50 записей и курсор `nextCursor`. Для следующей страницы передайте его как `after`.

Для записи нужны действующая операторская сессия и свежие подтверждения согласно политике платформы. Передавайте `operationId` и действие:

- `invite` принимает `email` и список `permissions`. Auth создаёт pending-аккаунт в БД платформы и ставит письмо в существующую очередь. Получатель задаёт пароль через `POST /api/v1/auth/invitations/activate`, затем входит через обычный вход оператора. Включите `INVITATIONS_ENABLED` и задайте `INVITATION_URL` на HTTPS-origin самой панели.
- `permissions` принимает `userId` и новый список `permissions`. Для действующего оператора замена списка отзывает существующие сессии. Для приглашённого сохраняется возможность активировать аккаунт по уже выданной ссылке.
- `revoke` принимает `userId`, удаляет полномочия, блокирует аккаунт, отзывает сессии и аннулирует приглашение.

Первый владелец защищён от изменений через эти команды. Право `platform.operators.manage` не делегируется. Запись с актором и результатом операции сохраняется в БД платформы. Повтор с тем же идентификатором и параметрами возвращает исходный `userId` без второй отправки письма. Перед обновлением примените platform-миграцию `000004_operator_management` и её runtime grants.

## Настройки MFA, очистки и роли проекта

Пути ниже находятся под `/api/v1/platform/projects/{id}`. Во всех запросах передаются `expectedVersion` и `expectedGeneration` проекта в query. Запись проверяет актуальные полномочия оператора и версию изменяемого объекта.

| API | Что меняет |
| --- | --- |
| `GET/POST /auth/settings/mfa` | Режим MFA проекта. Для записи передайте `expectedVersion` политики и `mode`. Усиление режима требует готового проектного MFA. |
| `GET/POST /auth/settings/retention` | Сроки хранения. Для записи передайте `expectedVersion`, `policy` и `confirmShortening`, если срок уменьшается. |
| `PUT /roles/{roleId}` | Название, ключ, описание, разрешения и MFA обычной роли. Передайте `expectedRoleVersion`. |
| `POST /users/{userId}/administrator` | Назначение или отзыв системного администратора. Требует `platform.operators.manage`, `grant` и текущие версии пользователя и роли. Для назначения проверяются готовность MFA проекта и credentials пользователя. При отзыве сохраняется хотя бы один пригодный к входу администратор. |

Настройки требуют управляемого API-режима для записи. Аудит новых операций записывается в БД проекта вместе с изменением в рамках Auth-миграции 000010.

Для интеграций в том же пространстве проекта доступны `GET/POST /auth/settings/smtp`, `GET/POST /auth/settings/providers/{provider}` (`google` или `telegram`) и `GET/POST /auth/settings/telegram-bot`. Передавайте версию проекта и поколение в query, а при записи также `expectedVersion` соответствующей настройки в теле запроса. Ответ содержит признаки настройки credentials. Пароли, токены, client secrets и ключ webhook в ответ не включаются.

SMTP проверяется по разрешённым целям и TLS-политике проекта. При смене SMTP-сервера или имени пользователя пароль нужно указать заново. Для OIDC действуют проверки привязанных аккаунтов и включённых методов входа. Обновление бота проверяет токен через Telegram и сохраняет результат с повторной проверкой прав и версии. После ротации ключа вызовите `POST /auth/settings/telegram-bot/webhook` с `expectedVersion` и `expectedGeneration` проекта в query и актуальным `expectedVersion` бота в теле. С актуальным подтверждением входа оператор с `platform.project_settings.manage` регистрирует webhook по сохранённому origin проекта. После ответа Telegram API повторно проверяет полномочия и версию, записывает аудит и возвращает новую версию. При конфликте после внешнего вызова перечитайте настройки и повторите активацию при необходимости.

`GET/POST /auth/settings/sessions` управляет сроками новых браузерных сессий выбранного проекта. В query передаются версия и поколение проекта, в теле записи — версия политики и полный объект `policy`. Продолжительность и пороги задаются в секундах. До первой записи действует конфигурация запуска. Запись отклоняется в режиме ENV. Новая политика применяется при выдаче сессии. Действующие сессии сохраняют первоначальные сроки и параметры продления. JWT этим API не настраивается.

Новый проект получает Auth-миграцию 000004 при подготовке БД. Если в существующей проектной БД таблица `auth.browser_session_policy` отсутствует, примените 000004 перед 000010 и обновите проектный профиль после миграций. До обновления проект использует сроки запуска.

`GET/POST /auth/settings/link-lifetimes` настраивает сроки ссылок подтверждения email и сброса пароля. При записи передайте `expectedVersion` политики и `policy` с `verificationSeconds` и `resetSeconds`. Срок подтверждения применяется при регистрации и повторной отправке письма. Ранее выданные ссылки сохраняют записанные даты истечения. В ENV-режиме действует конфигурация запуска. Для существующих проектов нужна Auth-миграция 000005, новые проекты получают её при подготовке БД.

`GET/POST /auth/settings/credential-lifetimes` настраивает сроки новых MFA challenges, кодов привязки email, приглашений, временных паролей и смены email. Здесь же задаются интервалы повторной выдачи и срок свежести подтверждения для повторной аутентификации, работы с внешними аккаунтами и смены email. Значения передаются в секундах в полном объекте `policy` с `expectedVersion` политики. Уже выданные credentials сохраняют записанные даты истечения. В ENV-режиме действует конфигурация запуска. Для существующих проектов нужна Auth-миграция 000006.

`GET/POST /auth/settings/login-budgets` задаёт квоты в попытках за минуту для входа по паролю, регистрации и сброса пароля. Настройка ограничена значениями запуска и применяется к Redis-счётчикам проекта. Локальные экземпляры обновляют сохранённую политику после истечения секундного кеша. Для существующих проектных БД нужна миграция 000007.

`GET/POST /auth/settings/frontend` настраивает проверку Origin, CORS и адреса страниц для ссылок в письмах. Дополнительные HTTPS-origin разрешаются для конкретного проекта через `frontendOrigins` в манифесте развёртывания. Через API можно выбрать подмножество этих адресов и собственного origin проекта. Ссылки в письмах используют собственный HTTPS-origin проекта. Для существующих проектных БД нужна миграция 000008. В режиме ENV обе политики доступны для чтения.

`GET/POST /auth/settings/operation-budgets` управляет минутными квотами Google и Telegram OIDC, MFA, подтверждения привязки email, приглашений и активации, временных паролей, выдачи JWT и introspection. Запись принимает `expectedVersion` политики и полный объект `policy`. Верхние пределы задаёт конфигурация запуска. Действующие счётчики Redis сохраняются при смене квот, экземпляры перечитывают настройки через секундный кеш. В ENV-режиме действует конфигурация запуска. Для существующих проектных БД нужна Auth-миграция 000009.

## Подготовка проекта

`POST /api/v1/platform/projects/{id}/preparation` принимает `operationId`, `expectedVersion`, `expectedGeneration` и возвращает `202` с адресом операции. Повтор того же запроса возвращает сохранённую операцию. Для того же поколения разрешена одна заявка.

На доверенном узле хранилища запустите `project-prepare -watch` с конфигурацией существующего provisioner для нужного storage target. Исполнитель забирает заявки, создаёт БД и роль, проверяет реальное подключение проектной роли, затем одной транзакцией публикует привязку, фазу `ready` и статус заявки. Managed-профиль оставляет публичные способы входа закрытыми по умолчанию. Ручной запуск заявки использует `project-prepare -requested -operation <UUID>`. API общей панели не получает доступа к DDL.

`GET /api/v1/platform/projects/{id}/preparation/{operationId}` возвращает этап заявки и фазу проекта. `requested` ожидает исполнителя, `running` означает выполнение, `managed_configuration_prepared` означает подготовленную конфигурацию до публикации, `ready` означает завершение. При `failed` исполнитель может повторить работу с тем же ID. Автоматические попытки ограничены пятью, с паузой до следующей попытки.

## Удаление проекта

`GET /api/v1/platform/projects/{id}/deletion-preview` принимает текущие версию и поколение готового включённого проекта. Первый владелец платформы с актуальным подтверждением получает имя, UUID и признак наличия любых пользовательских записей, включая мягко удалённые.

`POST /api/v1/platform/projects/{id}/deletion` принимает `operationId`, `expectedVersion`, `expectedGeneration`, точный UUID в `confirmProjectId` и `confirmDataLoss: true`. При наличии пользователей требуется также `acknowledgeUsers: true`. Подтвердить удаление и прочитать его статус может только первый владелец платформы с актуальным подтверждением входа. API приостанавливает проект в одной транзакции с записью подтверждения и возвращает `202` с адресом статуса.

Исполнитель сверяет физические идентификаторы БД и её ролей с журналом подготовки. Он закрывает новые подключения и ждёт освобождения существующих, затем заново проверяет наличие пользователей. После сохранения этапа `verified` выполняет `DROP DATABASE`. При потере ответа об удалении проверяет физическое состояние и завершает сохранённую операцию. Панель читает этап по `GET /api/v1/platform/projects/{id}/deletion/{operationId}`.

- `confirmed` — запись ожидает исполнителя.
- `draining` — исполнитель закрывает новые подключения и ждёт освобождения существующих.
- `verified` — проверка пройдена, исполнитель может закончить удаление.
- `deleted` — БД удалена. Карточка и запись операции остаются для аудита, возобновление запрещено.
- `users_present` или `expired` — удаление остановилось из-за отсутствия подтверждения потери пользователей или истечения 15 минут до проверки. Исполнитель восстанавливает возможность подключения к БД, проект остаётся приостановленным до явного возобновления.

Для развёртывания нужны миграция каталога `000005_project_operations`, обновлённые grants общей панели и provisioner, и запущенный executor для целевого хранилища. При долгих внешних подключениях их должен закрыть владелец этих подключений. Executor не завершает чужие сеансы принудительно. Глобальные SQL-роли, зашифрованная привязка и резервные копии остаются после удаления БД.

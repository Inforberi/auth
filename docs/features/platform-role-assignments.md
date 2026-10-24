# Назначение ролей из платформы

MP2.7,24 октября2026. Код готов, все исполняемые проверки переданы Luna на отдельном снимке: до отчёта статус **pending**. UI не подключался.

## Методы

| Метод | Путь | Действие |
| --- | --- | --- |
| POST | `/api/v1/platform/projects/{id}/users/{userId}/roles/{roleId}/grant` | Назначить обычную роль |
| POST | `/api/v1/platform/projects/{id}/users/{userId}/roles/{roleId}/revoke` | Снять обычную роль |
| GET | `/api/v1/platform/projects/{id}/role-operations/{operationId}` | Исходный результат своей операции |
| POST | `/api/v1/platform/projects/{id}/role-operations/{operationId}/reconcile` | Восстановить исходный результат по receipt |

Доступны в operator-профиле с включённым project runtime. Переиспользуются exact HTTPS Host/Origin, browser cookie/NoRefreshAuth, SQL platform authority/password/MFA guards и global/actor/project admission. Для записи нужно текущее `platform.project_access.manage`, для чтения результата — `platform.projects.read`. Обычные JWT/Bearer не подменяют browser session.

Project/user/role/action берутся только из URL и выбранного server handler. JSON не принимает actor, target ID, action, credentials или admission. Роли и пользователи читаются в exact attested project connection; ID из соседней БД не вызывает её открытие. Это не SSO и не вход оператора от лица project user.

## Запрос

```json
{
  "operationId": "f7000000-0000-4000-8000-000000000001",
  "expectedVersion": 3,
  "expectedGeneration": 3,
  "expectedRoleVersion": 1,
  "expectedAccessVersion": 1,
  "reason": "Назначение роли редактора"
}
```

`expectedVersion/generation` относятся к проекту; `expectedRoleVersion` — к роли; `expectedAccessVersion` — к назначениям пользователя. Все версии положительные и должны соответствовать актуальному состоянию для новой операции. Клиент использует метаданные своего проектного API/provisioning; platform directory/list/read bridge для будущего UI ещё отдельно, версии не следует подбирать наугад.

Максимум JSON8KiB; неизвестные поля, неправильный Content-Type, несколько JSON-объектов и query parameters запрещены. UUID/versions/reason проверяются domain в SQL authority flow, HTTP не повторяет предметную валидацию.

Один operation UUID означает одну команду в общей role-family namespace: его нельзя переиспользовать для другого target, grant вместо revoke, другого payload или создания роли. Новое явное действие получает новый UUID, повтор после потери ответа — прежний UUID и точный payload.

## Транзакция и ограничения

1. Сохранить immutable intent и выдать краткий SQL admission с актуальными authority/project metadata. Каталоговые locks освобождаются до работы с project DB.
2. Заимствовать exact runtime, проверить SQL profile и взять прежний Access lock.
3. Сначала проверить существующий receipt. Replay возвращает исходный snapshot без повторного назначения, UPDATE пользователя или повторной валидации уже изменившихся target versions.
4. Для новой команды прочитать текущую роль и проверить её версию. Системные роли запрещены в обоих направлениях. На grant permissions должны присутствовать в deployment catalog; MFA-required role требует готовую project capability. Пока она не подключена, новый grant такой роли получает409 `mfa_not_ready`. Снятие обычной MFA-required роли не требует её включения.
5. Заблокировать project user, проверить access_version и доступность. Grant разрешён только active/pending, revoke — также blocked при отсутствии deleted_at. Удалённый/неизвестный target недоступен.
6. Переиспользовать Access persistence: максимум32 роли, изменение связи и версии только при реальном изменении. В той же транзакции записать immutable project receipt/audit. Ошибка receipt откатывает связь и user counters.
7. После project commit сохранить catalog completion evidence. Как и раньше, admission — окончательное разрешение на уже принятую команду до его короткого deadline; последующий revoke запрещает новые admissions, не отменяет завершившийся commit.

Системный `super_admin` не назначается и не снимается этими маршрутами, включая самого оператора. Для него нужен отдельный administrator flow с last-administrator policy. Существующий локальный `ChangeAdministrator` и его `RequireAdministratorRemains` не обходятся и не ослабляются. Owner-managed проекты не требуют выдуманного локального super_admin для применения обычных ролей.

## Сессии и ответы

При фактическом grant active user получает `access_version+1` и `auth_version+1`: сессии до выдачи прав не получают новые привилегии. Для pending user auth_version сохраняется, чтобы не ломать activation credentials. На revoke увеличивается только access_version; текущие SQL-проверки разрешений сразу видят снятие. Поведение offline JWT/его TTL и introspection не меняется.

Повторная выдача уже назначенной роли или снятие отсутствующей связи с актуальными версиями возвращает `changed=false`; auth.users не обновляется, но операция получает свой receipt. Replay возвращает `replayed=true` и первоначальные `changed/accessVersion/role` даже после других последующих действий. **Это история операции, не текущие effective permissions.**

200 возвращает `operationId`, `projectId`, `userId`, `action` (`grant`/`revoke`), `status="committed"`, `role`, `accessVersion`, `changed`, `replayed`, `catalogRecorded`. Location указывает прежний role-operation URL. `catalogRecorded=false` не отменяет подтверждённое назначение.

При неизвестном COMMIT —202 `status="unknown"`, без role/changed. Не считать это rollback и не менять UUID ради повтора. GET/reconcile используют текущую read authority, проверяют project/actor/operation до runtime borrow; отозванный reader не получает результат. Recovery читает receipt нужного типа, не создаёт admission и не применяет назначение повторно. Общий outcome теперь содержит `action`, а для assignment — `userId`, `accessVersion`, `changed`. Старые create intents без Action читаются как `create`.

При replay восстановление catalog evidence использует **admission исходного project receipt**, а не свежего допуска повторного запроса. FK каталога подтверждает принадлежность admission операции. Это правило применяется и к существующему созданию роли; его результат в HTTP не раскрывает receipt/admission ID.

Ошибки:400 invalid_json/invalid_query/invalid_project/invalid_role;401 отсутствие сессии;403 forbidden/system role/чужой Origin;404 role_not_found или role_operation_not_found;409 role_conflict/project_conflict/target_unavailable/mfa_not_ready;428 fresh_auth_required;429 rate_limited;503 temporarily_unavailable. При role/access version conflict обновить метаданные; автоматических бесконечных повторов нет. Ответы no-store.

## Хранение и проверка

Каталоговые role intents/admissions/outcomes переиспользуются без новых таблиц. Тип определяется immutable typed request (`Action` только у assignment), result snapshot разделён по этому типу. Общие Go-модели названы RoleIntent/RoleOutcome; создание и назначение остаются отдельными typed service/HTTP методами, универсальный execute API не добавлен.

В initial Auth schema добавлена одна `auth.platform_role_assignments`: одновременно project receipt и платформенный аудит с actor/realm/project/binding/request, target/role, исходным role snapshot/access_version/changed/admission. Platform actor не имеет FK к project users. Runtime может SELECT и INSERT только нужных колонок; UPDATE/DELETE/TRUNCATE/INSERT времени запрещены и проверяются profile guards. Platform runtime в своей catalog DB не имеет прав к этой project receipt таблице.

Рабочие БД/ENV не менялись. Новых upgrade migration файлов нет по текущему правилу проекта; изменены initial schema/grants/checksum. Существующим БД нужен отдельный controlled upgrade, старый SQL профиль автоматически не принимается. Retention административного ledger ещё отдельная задача; обычный audit worker не удаляет эти receipts.

Добавлены domain/HTTP/service/router cases и actual TLS SQL drill: grant/revoke/replay/no-op, pre-grant session invalidation, pending credentials, cap32, system/last-admin, unavailable/MFA targets, receipt rollback, concurrent same-op/optimistic conflict/role edit, recovery без мутации и точный original admission, старый local Access audit/administrator regression. Тестовые session/Redis adapters HTTP drill синтетические; реальный SQL authority и transaction/registry работают. Общие transport faults и operator login/Redis suites остаются отдельными проверками.

Все исполняемые проверки — Luna; актуальные результаты и повторные прогоны — [history](../planning/history.md#результат-mp27-role-assignments--24-октября-2026). Приёмка ещё открыта. UI, directory/read bridge, системное назначение администратора из платформы, project MFA capability, полная Auth assembly/workers и fleet/load/GC приёмка этим блоком не закрываются.

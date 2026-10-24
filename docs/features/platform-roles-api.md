# Роли проекта через API платформы

MP2.7,24 октября2026. Реализация подключена к opt-in project runtime; V1 tests/race/actual SQL HTTPS/API/scanner PASS;3 lint замечания исправлены, targeted V2 lint/race у Luna **PASS**. Это не завершение всего multi-project и не запуск UI.

## Когда доступны маршруты

Нужны `PLATFORM_ENABLED=true`, `PLATFORM_PROJECT_RUNTIME_ENABLED=true`, успешно проверенные private catalog reader/trusted storage/master key и bounded registry. Обычный standalone-профиль и operator deployment с выключенным runtime эти маршруты не публикуют. Недопустимая сборка с role handler без runtime/catalog/admission отклоняется при создании router.

Проект должен быть подготовлен и `enabled/ready` для нового создания: этот API не создаёт БД/администратора и не переводит проект в ready. Полная feature assembly и owner-managed readiness остаются следующими этапами.

Требуется platform browser session. Запросы не принимают Bearer как замену cookie. Direct HTTPS Host совпадает с `PLATFORM_ORIGIN`; для POST обязателен точный Origin, для GET отсутствие Origin допустимо, чужой — запрещён. Действуют browser protection, NoRefreshAuth, общие HTTP deadline/concurrency и Redis/local administrative admission. Эти запросы не продлевают сессию и не обновляют cookie.

Каталог разрешений берётся из доверенного `ACCESS_CATALOG_FILE` (пустой путь — built-in permissions), одинакового для данного deployment. Нельзя передать свой каталог, DSN, realm, actor, admission или project ID в JSON. Независимые каталоги permissions из будущих project settings здесь ещё не реализованы. Доступ к управлению не определяется разрешениями создаваемой роли.

## Методы

| Метод | Путь | Требуемое право |
| --- | --- | --- |
| POST | `/api/v1/platform/projects/{id}/roles` | `platform.project_access.manage` |
| GET | `/api/v1/platform/projects/{id}/role-operations/{operationId}` | `platform.projects.read` |
| POST | `/api/v1/platform/projects/{id}/role-operations/{operationId}/reconcile` | `platform.projects.read` |

Все три сценария дополнительно требуют актуальные password/MFA proofs по существующей platform policy. Это не новая обязательная MFA policy для всех пользователей проектов. Чтение и recovery доступны только исходному actor, не всем операторам, знающим UUID.

## Создание роли

Пример тела POST:

```json
{
  "operationId": "f4000000-0000-4000-8000-000000000001",
  "expectedVersion": 3,
  "expectedGeneration": 3,
  "key": "editor",
  "name": "Редактор",
  "description": "Работа с пользователями",
  "permissions": ["accounts.users.read"],
  "mfaRequired": false,
  "reason": "Добавление роли редактора"
}
```

UUID проекта приходит только из URL. Version/generation — из текущей карточки проекта. `operationId` создаёт клиент для одной команды и сохраняет для повторов. Один UUID с изменённым payload, другим проектом/actor/binding вызывает conflict. Сначала снова проверяются текущие права/цель: старый UUID не восстанавливает отозванное право записи.

Максимум JSON32KiB; неизвестные поля, неверный Content-Type, несколько JSON-объектов и query parameters запрещены. Role domain проверяет key/name/description/permissions, максимум128 permissions и запрет `super_admin`; HTTP не дублирует эти правила. Неизвестное permission из каталога отвергается. Причина и лимиты команды проверяются существующим SQL guard/domain.

Порядок: сохранить immutable intent → новый краткоживущий SQL admission → exact runtime lease → project SQL profile/Access lock → role и receipt в одной транзакции → completion evidence в каталоге. Actor не превращается в project user. Роль никому автоматически не назначается; управление назначениями будет отдельным сценарием.

**MFA-required роли:** готовность MFA конкретного проекта пока не привязана к полной Auth assembly. Operator `MFA_ENABLED` её не доказывает. Поэтому новая роль с `mfaRequired=true` получает409 `mfa_not_ready`, без project role/receipt. Intent/admission могли уже сохраниться: они не означают создание роли. Нельзя включать capability простым клиентским флагом или подстановкой operator config. Уже существующий receipt остаётся достоверным результатом исходной операции.

Успешный ответ:

```json
{
  "operationId": "f4000000-0000-4000-8000-000000000001",
  "projectId": "a2000000-0000-4000-8000-000000000001",
  "status": "committed",
  "role": {
    "id": "b4000000-0000-4000-8000-000000000001",
    "key": "editor",
    "name": "Редактор",
    "description": "Работа с пользователями",
    "permissions": ["accounts.users.read"],
    "mfaRequired": false,
    "version": 1
  },
  "replayed": false,
  "catalogRecorded": true
}
```

201 — новый project commit,200 — receipt replay. Заголовок `Location` указывает относительный URL операции. `catalogRecorded=false` при известном project commit не отменяет роль: можно восстановить completion через reconcile.

При потере подтверждения COMMIT возвращается202 с `status="unknown"`, без `role`, и тем же Location. Это не доказательство rollback и не повод генерировать другую операцию. Если сам HTTP-ответ потерян, клиент уже знает project/operation UUID. Тот же UUID/payload допускает безопасный replay при текущих write authority/version; нет автоматической фоновой переотправки и безлимитных retry.

## Чтение и восстановление

GET принимает пустое тело, не обращается к project DB и возвращает `operationId`, `projectId`, `committed` и исходный role snapshot только при `committed=true`. Snapshot не описывает последующие изменения роли. `committed=false` означает отсутствие catalog evidence, не отсутствие роли.

POST reconcile тоже требует пустое тело. При известном результате возвращает его из каталога. Иначе читает только исходный project receipt на exact binding/version/generation и дописывает outcome. Не создаёт новую роль/admission. Перед ответом повторно проверяет authority; отзыв session/read permission/proofs может запретить выдачу, хотя completion evidence успело сохраниться.

Project/actor/operation scope проверяется SQL-предикатом **до заимствования project connection**, а не сравнением уже прочитанного результата с URL. Другой project, неизвестный UUID и чужая операция дают одинаковый404. Внутренние ReadRoleOutcome/ReconcileRoleOutcome теперь требуют явный project UUID; SQL-тесты обновлены и проверяют неверный project даже при nil registry.

После write-permission revoke известный результат доступен при текущем read permission. После suspend GET известного результата доступен; recovery может сработать на warm exact runtime, но cold suspended/stale target может быть недоступен. Никогда не выбирается новая/соседняя БД и не продлевается старый admission.

## Ошибки и нагрузка

| HTTP | Code / значение |
| --- | --- |
| 400 | `invalid_json`, `invalid_query`, `invalid_body`, `invalid_project`, `invalid_role`, `invalid_permission` |
| 401 | Нет действующей browser session |
| 403 | `forbidden`, чужой Origin или отозванные SQL-полномочия |
| 404 | `role_operation_not_found`; либо маршрут не включён в профиле |
| 409 | `project_conflict`, `role_conflict`, `mfa_not_ready` |
| 428 | `fresh_auth_required` |
| 429 | `rate_limited`, Retry-After60 |
| 503 | `temporarily_unavailable`: недоступность catalog/runtime, saturation, истёкший admission |

Ответы `no-store`; ошибки не раскрывают credentials/SQL/ciphertext. Для операций используется тот же project lane `{id}` и actor/global limits, что для каталога. Лимиты и отказ Redis не включают SQL fallback. Новых workers, очередей, миграций и зависимостей нет. Ledger retention остаётся отдельной задачей: обычная audit cleanup эти receipts не удаляет.

## Проверки и оставшиеся границы

Добавлены unit для DTO/32KiB/ошибок/202/Location/scope, service ordering, runtime-off assembly, guarded router и Swagger. В existing command TLS fixture добавлен настоящий HTTPS/SQL flow: create/replay/conflict, wrong project404, missing catalog outcome → reconcile без нового admission, MFA capability отказ и revoke write/read/session. Session adapter этого drill предоставляет синтетический SQL proof; Redis admission заменён identity middleware. Реальные login/session HTTPS и Redis limiter suites проверены отдельно, этот drill их не подменяет.

Luna выполнила V1: tests/race/actual TLS SQL HTTPS/operator regression/API/scanner PASS; task check FAIL только3 lint замечания. Они исправлены без нового поведения, V2 targeted lint/race PASS, manifest совпал до/после; старые успешные suites не повторяются без причины. UI, назначения ролей, user provisioning, project Auth assembly/worker scheduler, credential rotation, fleet/load/GC приёмка остаются отдельно.

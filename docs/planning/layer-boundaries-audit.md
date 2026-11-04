# Аудит слоёв — 4 ноября 2026

Статус: корректирующий блок принят Luna по V2, 4 ноября 2026. Это продолжение MP6R и [плана app](app-boundaries-audit.md), без новых функций и изменения API. Проверки предыдущего переноса фабрики принимаются отдельно; они не закрывают перечисленные архитектурные задачи.

## Область и достоверность

Проверены направления зависимостей и признаки смешения в 990 рукописных production Go-файлах `internal`, `pkg`, `cmd` (без `_test.go` и каталогов `tests`). Поиск SQL вне repository, HTTP вне transport и обратных imports дополнен чтением конкретных операций Auth, Access, Admin, project adapters и app. Просмотрены определения SQL security-функций/триггеров; их корректность этим просмотром не доказана. Подробный предыдущий аудит app входит в область настоящего плана.

Это обзор всех основных областей и точечная семантическая проверка кандидатов, а не построчная проверка каждого метода, security-аудит или PASS тестов. Импорт domain/service из внешнего адаптера сам по себе не нарушение: адаптер вправе реализовывать порт потребителя. Отсутствие подозрительного импорта не доказывает отсутствие бизнес-правила в SQL. Исполняемые проверки не запускались.

## Постоянные границы

| Слой | Что принадлежит ему | Что сюда не помещаем |
| --- | --- | --- |
| domain | Модели, чистые правила, допустимость переходов | SQL/Redis, HTTP, env, сборку и внешние вызовы |
| service | Сценарий, порядок действий и применение правил через узкие порты | SQL-текст, pgx.Tx, HTTP DTO/status и создание инфраструктурных клиентов |
| repository | Запросы/сканирование, storage errors, locks, CAS, constraints, atomic mutation/revoke/audit/outbox/receipt | Самостоятельный выбор продуктовой политики и сетевую доставку |
| transport | Форма запроса, DTO, протокол, вызов сценария, mapper ответа/ошибки | SQL, выбор бизнес-политики и сборку сервисного графа |
| app | Создание и соединение компонентов, startup readiness, ресурсы, lifecycle | Обработку каждого запроса и реализацию предметных сценариев |
| project adapter | Выбор текущего project binding, bounded lease, адаптацию вызова фичи к проектной БД | Собственные правила входа, HTTP-ответы и SQL-текст |
| integrations/infra | Внешний протокол, технические клиенты и инфраструктурные механизмы | Решения о ролях, правах и жизненном цикле пользователя |

Repository может вызывать чистое domain-правило над состоянием, прочитанным под lock, либо переданное service правило. Это не делает транзакцию неправильной. Service владеет намерением сценария; SQL-адаптер обеспечивает его атомарность. Не передавать pgx.Tx в service, не выполнять проверку только до транзакции и не создавать общий UnitOfWork framework ради формального разделения.

## Подтверждённые задачи

| Код и символ | Находка | Целевой владелец и границы исправления |
| --- | --- | --- |
| `internal/app/admin/project_http.go`: `projectHostRouter` | Исполняемая HTTP-маршрутизация по host находится в сборке | `internal/transport/http/router`; app подключает готовый router. Сохранить origin/host semantics и закрытость неизвестных проектов |
| `internal/app/admin/mfa_settings.go`: `operatorMFASettings.Read/Update` | Runtime-адаптер административных настроек находится в app | `internal/admin/administrators/service` для сценарного адаптера; преобразование HTTP ошибок остаётся у transport. Авторизация и запись остаются одной транзакцией |
| `internal/app/projects/profile` | 29 рабочих и 22 тестовых файла: deployment parsing, построение графа, readiness и правила доступности перемешаны | Deployment source выделить отдельно от фабрики; фабрика остаётся app. Правила допустимых комбинаций принадлежат Auth domain/service/readiness. Само соединение компонентов и проверка constructor errors остаются app |
| `internal/auth/project/profile/settings_readiness.go`: `profileDependencyVersions` | SQL чтения SMTP/provider revisions находится в runtime profile | Узкая операция `auth/settings/repository/postgres`, используемая через project adapter. Сохранить один SELECT на чтение, before/after comparison и исходные ошибки |
| `internal/auth/project/mfa/telegram_webhook.go`: `WebhookHTTP` | Заголовки, request body, HTTP ошибки, lease, приём кода и отправка смешаны в одном методе | HTTP contract — `internal/transport/http/projects`; получение project credentials и bounded lease — project adapter; приём/доставка — существующие MFA service/integration. Не переносить decoding до проверки секретного webhook и не добавлять повторную доставку |
| `internal/auth/project/methods/method_bindings.go`: `ChangePasswordHandler` | Project adapter создаёт HTTP handler | Создавать handler в `internal/transport/http/projects`; остальные BrowserPolicy/credential methods оставить у своих владельцев |
| `internal/transport/http/projects/http.go`: `NewProjectHTTP` | HTTP facade принимает конкретный `RuntimeCredentialReader` | Использовать существующий узкий resolver-контракт router либо потребительский интерфейс с реально нужными методами. Конкретный repository создаёт app. Factory Build/Assess сохраняется |
| `internal/admin/projects/preparation/transport/cli/run.go`: `Run` | CLI фичи импортирует app и вызывает сборку напрямую | Связать command с preparation runner в `cmd/project-prepare`; CLI получает узкий callback/порт. Env/аргументы/JSON принадлежат CLI, ресурсы — app, Prepare — service |
| `internal/auth/settings/repository/postgres/provider_update.go`: `providerReplacement` | Чистое решение о сохранении/смене credentials и допустимости enabled provider живёт в repository | Правило — settings/providers domain/service. Применять к текущему locked состоянию; не возвращать plaintext secrets в HTTP и не менять secret-preserve semantics |
| `internal/access/repository/postgres/manage_roles.go`: `UpdateRole` | Вычисление изменения прав/MFA и влияния на session revision смешано с SQL | Чистое сравнение роли/изменений — Access domain; service применяет правило через узкий контракт. Locks, проверка полномочий, запись revision и audit остаются атомарными |

При распределении profile не переносить все условия автоматически: `nil dependency`, startup Ping, чтение сохранённых credentials, constructor errors и выбор включаемого компонента допустимы в сборке. `needsProfileVerification`, `selectProfileNative` и условия email/Telegram MFA разобрать отдельно: выделять предметное правило, не дублируя уже существующие policy checks. Одна самостоятельная группа сценариев — понятный пакет; не новый пакет на каждый bind.

## Транзакционные кандидаты: уточнить правило, сохранить persistence owner

Эти места просмотрены, но вызов другого SQL helper/domain функции не означает, что всю транзакцию нужно переносить в service:

- `admin/projects/repository/postgres/transition.go`: `Transition` уже вызывает `Project.Next` из domain. Дополнительное условие `FinishPreparation && !bindingPresent` включить в явный domain-контракт перехода. Service задаёт действие; repository применяет правило над locked snapshot, сохраняет replay/CAS/event в той же транзакции.
- `admin/projects/roles/repository/postgres/mutation/creation.go`: `CreatePlatformRoleInTransaction` уже использует `Role.RequireCapabilities`. Уточнить владение подготовкой role definition и Normalize у service/domain. Проверку admission, точное replay matching и role+receipt commit сохранить; replay не должен начать зависеть от новой конфигурации каталога.
- `admin/projects/policy/repository/postgres/mutation/update.go`: `ApplyAuthPolicyInTransaction` объединяет runtime attestation, Access lock, replay, policy lock, write и receipt. Это обоснованный atomic persistence operation. Проверить лишь выбор `RequireStoredProviders` и владельца правила change; существующий `PolicyRuntime.CheckChange` уже domain. Не разбивать операцию на независимые repository calls.
- `admin/administrators/repository/postgres/mfa_settings.go`: `UpdateMFAPolicy` проверяет актуального оператора и записывает policy в общей транзакции. После выноса сценарного адаптера из app сохранить эту persistence operation; исключить только самостоятельно выбранные правила/значения, если они подтвердятся при реализации.
- `auth/settings/repository/postgres/mfa_update.go`: `ApplyMFAPolicyChange` содержит readiness/transition проверки и SQL revision. Вынести оставшиеся чистые условия в domain вместе с существующим `Strengthens`; повторная проверка на locked snapshot остаётся. Не удалять fail-closed защиту internal transaction entrypoints.

Нельзя механически заменить эти методы CRUD-вызовами из service. Для каждого изменения сначала записать: исходный порядок ошибок/replay, владелец правила, transaction boundary и SQL/Redis round trips, затем выбрать минимальный порт.

## Уже корректно и не требует повторного переноса

- MFA selection: `mfa/repository/postgres/selection.go` читает `MethodSelection`; `mfa/domain/selection.go` выбирает метод; `mfa/login/service/selector.go` запускает выбранный factor. Старый кандидат `SelectMFAMethod` из раннего плана уже устранён.
- TOTP Disable: `mfa/repository/postgres/management.go` передаёт `DisableState` в supplied check внутри transaction. Правило отделено; locks/proof/invalidation/audit сохраняются. Повторно дробить не нужно.
- Основные domain/service/feature HTTP imports Auth и Access не показали прямых зависимостей domain от SQL/HTTP и service от concrete repositories в выполненном обзоре.
- `integrations/google|telegram.New` принимает service config и переводит его в OIDC client config; OIDC возвращает domain identity. Это реализация потребительского контракта, а не доказательство смешения. Не создавать дублирующие Config/Identity типы только ради чистого списка imports.
- Project wrappers, которые берут lease и создают нужный service/repository для выбранного pool, являются адаптерами. Их не переносить целиком в app: заимствование ресурсов при операции отличается от построения общего графа.
- Startup initialize/check в `app/auth/settings`, readiness в `app/access`, открытие pools в `app/projects/runtime`, lifecycle workers и cleanup допустимы. Сами циклы доставки/очистки принадлежат фичам.
- SQL функции `auth.mfa_required`, factor usability, session/refresh binding triggers и recovery grants требуют актуального состояния и защищают от гонок/прямых записей. Не удалять их из миграций ради лозунга «все правила в service»; изменения только по отдельной доказанной гарантии.

## Порядок выполнения

1. [x] Зафиксировать контракты владения ресурсами, state/readiness и правил profile; связать с незавершённым app-планом. Составить карту перемещаемых символов и тестов до редактирования.
2. [x] Разделить протокол и адаптеры: host routing, administrator settings, Telegram webhook, password handler, HTTP resolver и CLI runner. Сохранить последовательность авторизации, лимитов, parsing и публичные ошибки.
3. [x] Убрать SQL из profile и чистые решения из repositories в существующие domain/service. По одному transaction owner; отдельно закрыть перечисленных транзакционных кандидатов решением «исправлено» или «обоснованно оставлено» с причиной.
4. [x] Упорядочить project composition: отдельный deployment source, логические группы сборки, короткий явный orchestrator. Не копировать правила, не расширять private API ради переноса тестов. Удалять только действительно неиспользуемое.
5. [x] Перенести проверки к владельцам: HTTP/Swagger — transport, правила — domain/service, SQL authority — repository, wiring/resources — app. Public tests в локальных tests; private рядом с небольшим владельцем. Обновить architecture, feature docs, карту и текущий шаг.
6. [x] Luna принимает неизменяемый снимок и проверяет только затронутую область; исправления возвращаются основному агенту. Архитектурный gate закрывается после source review и необходимых PASS, не по факту перемещения файлов.

Для реализации: formatter затронутого Go; tests/lint по достаточному режиму проекта у Luna; race для изменённых общих ресурсов/callbacks; SQL/Redis/API только по затронутым гарантиям (replay, locks, немедленный отзыв, MFA без обхода, project isolation, revisions, webhook secret/rate limits). Не повторять не затронутые load/security/image suites. До UI остаются отдельные MP7/MP8 gates.

Критерий завершения: каждый перечисленный пункт имеет итог и владельца; нет SQL в runtime profile и HTTP в project feature adapter; service не получает pgx/Redis clients; правило применяется один раз к правильному состоянию; transaction/replay/error order и число round trips сохранены либо изменение обосновано. Никаких новых зависимостей или универсальных framework в рамках этой уборки.

## Реализация корректирующего блока

Полная реализация разрешена пользователем 4 ноября. Исполняемые проверки принимает Luna отдельным снимком; отметки ниже описывают source delta и не заменяют PASS.

Контракты: общие pools/Redis/hasher/worker clients создаёт app и закрывает зарегистрированный lifecycle; project adapters получают заимствованный bounded registry lease. HTTP использует Factory и RuntimeResolver, не конкретный repository. Readiness читает версии до/после сборки; Publish сохраняет current-проверку. Ни service, ни HTTP не получают pgx.Tx.

- Host routing — `transport/http/router.ProjectHosts`; app передаёт проектный handler только при ненулевом профиле, чтобы не преобразовать typed nil в ненулевой interface. Изолированный host-routing test перемещён к router; lifecycle test остаётся app.
- Administrator MFA adapter — `admin/administrators/service.MFASettings` с узким repository interface; app создаёт handler и задаёт error mapping. Транзакционный `UpdateMFAPolicy` оставлен у PostgreSQL owner: авторизация оператора и policy write должны коммититься вместе.
- Password change handler создаётся transport; project adapter реализует необходимый `AllowUser`, сохраняя существующий limiter без выдачи его private поля наружу.
- Telegram webhook: HTTP заголовки/ответы/DecodeStart — transport; project adapter держит lease во время получения credentials, callback decoding, receipt и одной отправки. Сохранены проверки до чтения body и прежний порядок лимитов.
- CLI получает injected Runner; cmd связывает connection parsing и app preparation. SQL/HTTP suite использует свой fixture runner, CLI больше не импортирует app.
- `Project.AllowsOnboarding` владеет допустимым состоянием проекта; app проверяет полноту зависимостей и привязку ключей.
- SQL revisions перенесён в settings repository через `auth/project/settings.DependencyVersions`; один SELECT на чтение и before/after остаются прежними.
- Access `RoleChange.Apply`, provider `ProviderUpdate.Replacement`, MFA `ValidateChange/CheckChange` и project `NextWithBinding` отделяют чистые решения от SQL. Применяются над locked состоянием в прежнем порядке; mutations/audit/receipts не разделены.
- Role creation оставлен с `RequireCapabilities` после replay: правило уже domain, перестановка могла бы лишить старую receipt повторяемости после смены каталога.
- Project policy mutation оставлен atomic persistence operation: `PolicyRuntime.CheckChange` уже domain, `RequireStoredProviders=true` — обязательная fail-closed граница проектной записи, а не новая продуктовая настройка.

Коммит этого блока не запрошен. После нового receipt дополнить результат приёмки, не переносить старый PASS на новый delta.

- Project composition: deployment source выделен в `app/projects/deployment` (5 рабочих, 5 тестовых файлов); `app/projects/profile` сокращён с 29/22 до 17/11. Policy/delivery settings, user adapters и MFA factors сгруппированы по смыслу. `ProjectProfileConfig.NeedsVerification/SelectNative/EmailMFARecoveryConfigured/AssessmentPolicy` находятся у runtime readiness. Проверки готовых компонентов и binding остаются app.
- RoutePlan/readiness public assertions находятся в `auth/project/profile/tests`, Swagger parity — `transport/http/projects/tests`. Test-only методы private builder удалены; private state ради тестов не экспортирован. Добавлены узкие проверки webhook admission и factory nil dependencies.

Пункты1–5 отмечены как реализованный source delta; пункт6 и общая приёмка остаются открыты до receipt. Заявления о сохранении поведения выше — цели/результаты source review, подтверждение исполнением ожидается.

## Приёмка V2

Luna: PASS для `/private/tmp/auth-layer-boundaries-v2-7da4k02g`, base `12c038f`; receipt `/private/tmp/auth-layer-boundaries-v2-summary.json`. Targeted compile/security tests, lint (0 issues), три группы race и 11 SQL/HTTP roots — фактические RUN/PASS без SKIP в отдельно запущенной SQL-фазе. Telegram root использовал retained Redis DB15. Credential-free unit skips не считались SQL приёмкой.

Основной агент сверил manifest: 121 present hash, 44 deletions, drift0, дополнительных изменений0; проверил 17 exit evidence (все0) и RUN/PASS маркеры всех11 SQL roots. Ошибка unused import из V1 устранена до V2. Fixture postflight clean, без изменения retained ролей и broad reset/drop/flush. Full task check, pentest/scan/load не запускались по согласованному affected-only scope. MP7/MP8 и реальная deployment TLS topology остаются отдельными gates; эта приёмка не является заявлением об отсутствии всех уязвимостей.

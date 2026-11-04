# Аудит границ app — 4 ноября 2026

Статус: согласованный план реализован и принят по V5 4 ноября 2026. Main сверил исходники рабочего дерева с проверенным snapshot: расхождений нет. [Результаты и границы приёмки](../operations/acceptance-summary.md#границы-app-и-корректировка-слоёв--приёмка-v5-4-ноября-2026). Ниже сохранены исходные находки и решения; промежуточные FAIL устранены и не выдаются за PASS.

## Ответ на основной вопрос

`app` в этом проекте должен создавать и связывать зависимости, выбирать режим запуска, регистрировать workers и их завершение. Подкаталоги `app/auth`, `app/admin`, `app/projects`, `app/access` допустимы: большая сборка не обязана помещаться в один файл. Название projects обозначает сборку Auth для независимых проектов, а не ещё один каталог бизнес-сущностей.

Но фактический `app/projects` шире этого назначения: включает исполняемые project-scoped adapters, HTTP route maps, readiness-проверки, подготовку БД и цикл фоновой доставки. Это смешение границ читаемости, не автоматически уязвимость или неисправность сценария. Простое переименование папки ничего не исправит.

В другой архитектуре application layer может намеренно содержать use cases. Это допустимо, но здесь уже согласовано другое правило: сценарии в service, adapters у владельцев, app — composition/lifecycle. Нужно последовательно соблюдать именно его.

## Итоговое решение по app после проверки production-примеров

Рекомендация: сохранить `app/{auth,admin,access,projects}`. Это четыре группы сборки с разными обязанностями, а не четыре самостоятельных сервиса или четыре бизнес-слоя. Их наличие само по себе не нарушает production-практики. Исправление должно затронуть содержимое и направление зависимостей, а не названия ради нового дерева.

| Пакет | Контракт сборки | Что ему не принадлежит |
| --- | --- | --- |
| `app` | Создать общие ресурсы процесса, выбрать режим, вызвать builders, запустить server/workers, завершить в установленном порядке | Правила регистрации/доступа, SQL, очередь доставки |
| `app/auth` | Собрать обычный Auth для переданных зависимостей; переиспользуемые constructors account/methods/MFA/token/settings | Новая реализация входа или MFA, запросы пользователей |
| `app/admin` | Собрать Auth администратора, управление проектами, administrative handlers и подключить project factory | Отдельная копия password/MFA, правила выдачи ролей и подготовки БД |
| `app/access` | Подключить каталог permissions, repository, service и startup-проверку совместимости | Решения «разрешить действие», выдача/отзыв ролей |
| `app/projects` | Собрать bounded runtime resources и фабрику Auth-профиля по доверенному project snapshot | Диспетчеризация каждого запроса, исполняемые project adapters, delivery loop, сценарий Prepare |

Пакеты не обязаны быть одинаковыми по размеру: небольшой переиспользуемый Access builder может оставаться отдельным пакетом. Количество папок не является метрикой качества. Большой builder делится по реальным группам зависимостей, а не на файл для каждого New.

### Направление зависимостей и lifetime

- Root App вызывает builders. Внутри composition разрешено переиспользование builders (`admin` использует существующие Auth constructors), но domain/service/repository/HTTP adapters не импортируют app.
- Root App выбирает существующий режим запуска. В multi-project режиме admin assembly подключает фабрику проектных профилей. `app/projects` не второй сервер и не отдельный микросервис.
- Factory получает доверенные project identity/version и узкие зависимости. HTTP dispatcher получает factory через функцию/интерфейс; обратного импорта app из transport нет.
- Общие SQL/Redis clients, logger и hash budget принадлежат процессу; project pools — bounded registry; profile-owned resources — профилю. Нельзя закрывать borrowed ресурс при закрытии одного проекта.
- Фабрика может работать после старта при создании/обновлении профиля. Она не должна создавать полный App на каждый запрос. Актуальность permissions/session/auth_version не заменяется кэшем профиля.
- Startup I/O допустим: загрузить каталог, проверить SQL grants/schema и связность конфигурации. App вызывает готовую проверку владельца, а не реализует её SQL или бизнес-правила.
- Привилегированная подготовка БД запускается своим CLI, не включается в ordinary HTTP runtime. App создаёт adapters и connections; preparation service выполняет сценарий.
- Shutdown сохраняет текущие гарантии: прекратить приём, завершить активные запросы и workers, освободить profile/registry leases, затем закрыть заимствуемые нижележащие ресурсы. Точный порядок зависимых ресурсов фиксируется по существующему коду перед переносом.

### Что показали реальные проекты

Просмотрены текущие публичные исходники 4 ноября 2026:

- [Grafana `pkg/server/server.go`](https://github.com/grafana/grafana/blob/main/pkg/server/server.go): Server принимает готовые сервисы и background service registry, управляет Init/Run/Shutdown. Инициализация вызывает сервисы provisioning и ролей. Это пример lifecycle boundary, а не требование назвать нашу папку server или скопировать их DI.
- [ZITADEL `cmd/start/start.go`](https://github.com/zitadel/zitadel/blob/main/cmd/start/start.go): стартовая сборка соединяет database, queries, commands, authorization, API и фоновые компоненты. Реализации находятся в других пакетах. Большой startup-файл отражает их историю и масштаб; копировать его размер/глобальные зависимости здесь не требуется.
- [Официальные рекомендации Go](https://go.dev/doc/modules/layout#server-project) прямо допускают разнообразие серверных layouts и рекомендуют cmd/internal, не устанавливая обязательные auth/admin/projects внутри app.

Вывод для нашего проекта: один понятный вход сборки процесса, явные constructors, ограниченное владение ресурсами, feature-local бизнес-код и отделённый transport. Это обоснование выбранных границ, а не заявление о совпадении с архитектурой всех крупных компаний. Новые DI frameworks не нужны.

## Проверенные находки

Пути относительно корня; символы указаны вместо нестабильных номеров строк.

| Источник | Что реально делает | Оценка и действие |
| --- | --- | --- |
| `internal/app/app.go:New`, `resources.go:openResources` | Создаёт общие SQL/Redis/logger/hasher, выбирает Auth/admin, регистрирует cleanup | Оставить. Это composition root; проверка конфигурации и доступности ресурсов при старте уместна |
| `internal/app/admin/{assembly,roles,users,project_delivery}.go` | Создаёт сервисы, repository adapters, handlers и worker, связывает router | В просмотренных constructors самостоятельных пользовательских сценариев не подтверждено. Оставить; запуск worker не означает размещение его реализации в app |
| `internal/app/access/app.go:New` | Загружает catalog, создаёт repository/service, проверяет совместимость существующих разрешений | Допустимая startup-проверка. Не переносить только из-за вызова repository: SQL находится у repository, app вызывает его контракт |
| `internal/app/projects/runtime/runtime.go:Open` | Открывает приватный reader pool, создаёт codec/registry, запускает sync, задаёт порядок закрытия | Оставить startup graph и ownership. Сам registry/reader уже находятся у `admin/projects/runtime`. Не перемещать весь файл как бизнес-логику |
| `internal/app/projects/preparation/execute.go:Run` | Открывает connections, затем Reserve → Prepare → optional InstallSchema → prepareSecrets; формирует stage/result | Смешение сборки ресурсов с исполняемым сценарием. Открытие/cleanup оставить composition; последовательность подготовки — `admin/projects/preparation/service` через конкретные узкие порты |
| `internal/app/projects/access/access_queries.go:ProjectAccess.*` | При каждом вызове через `use` выбирает проектный сервис и вызывает операции доступа | Runtime adapter, не constructor. Перенести связную группу в `internal/access/project`, не копировать Access business rules |
| `internal/app/projects/{account,methods,mfa,native,settings}` | Project-scoped связки к существующим сценариям Auth; часть файлов — constructors, часть исполняется при запросах | Разделять по поведению, не переносить вслепую целые папки. Runtime adapters — в `internal/auth/project` с понятными подгруппами; assembly остаётся в app |
| `internal/app/projects/delivery/delivery.go:Run,deliverProject` | Пагинация проектов, ограниченный параллелизм, rotation очередей, SMTP readiness и выполнение доставки | Реальная фоновая работа. Перенести scheduler и связный state в `internal/auth/project/delivery`; в app только создать и зарегистрировать Run/stop. Это межфичевая доставка, не только account email verification |
| `internal/app/projects/browser/http.go:NewProjectHTTP` | Связывает dispatcher, фабрику profiles и router; хранит runtime dependencies для Assess | Constructor частично уместен в app. HTTP facade и request-time Assess отделить в HTTP adapter. Существующий RuntimeDispatcher повторно не писать |
| `internal/app/projects/profile/profile.go:buildProjectProfile,CheckCurrent`; `profile/http_access.go:accessHandlers` | Сборка сервисов смешана с чтением trusted configuration, проверкой актуальности, состоянием доступности и route maps | Сохранить фабрику графа в app; HTTP binding — в transport, runtime guards/readiness — у project Auth adapter. Не превращать весь profile в service с pgx и HTTP |
| `internal/app/projects/onboarding/onboarding.go:NewProjectOnboarding` | Сборка setup/SMTP и проверки актуального допуска к onboarding | Разделить construction и действующую защиту: builder в app, guards у существующих preparation/setup owners, HTTP adapter в transport. Повторную проверку допуска не удалять как «дубль» |

Последний рефакторинг разделил ordinary Auth/admin assembly и часть SQL-владельцев. Он не устранил перечисленные project runtime обязанности; формулировка «app полностью очищен» была бы неверной.

## Предлагаемое размещение

Это целевое дерево ответственности, не задание создавать пустые каталоги или все перечисленные файлы заранее.

```text
internal/
├── app/
│   ├── app.go, resources.go, run.go, server.go
│   ├── auth/                         # constructors обычного Auth
│   ├── admin/                        # constructors общей админки
│   ├── access/                       # загрузка/подключение Access
│   ├── projects/
│   │   ├── assembly.go               # сборка project Auth dependencies
│   │   ├── runtime.go                # создание registry/reader и cleanup
│   │   ├── profile/                  # фабрика графа сервисов для snapshot
│   │   └── tests/                    # интеграция сборки, без копий fixtures
│   └── tests/
├── auth/
│   ├── account/, methods/, session/, mfa/, token/, settings/
│   └── project/                      # использование Auth в выбранном проекте
│       ├── account/, methods/, mfa/, token/, settings/
│       ├── delivery/                 # project scheduler и доставка
│       └── readiness/                # исполняемые capability/current guards
├── access/
│   ├── domain/, service/, repository/, transport/
│   └── project/                      # project-scoped Access adapter
├── admin/projects/
│   ├── domain/, service/, repository/, roles/, policy/, runtime/
│   └── preparation/
│       ├── service/                  # этапы подготовки, не создание connections
│       ├── repository/postgres/      # каталог/reservations
│       ├── database/postgres/        # physical DDL и SQL-роли
│       └── transport/cli/            # аргументы/вывод команды
└── transport/http/
    ├── router/, middleware/, httpx/
    └── projects/                     # facade/HTTP binding project runtime
```

`auth/project` не новая реализация входа: adapters делегируют существующим Auth-сервисам и обеспечивают их работу с выбранной БД. Предметные правила остаются у исходной фичи. Название `native` уточняется до `token`, поскольку это JWT/native token flows, а не отдельный вид проекта.

Существующий `admin/projects/transport/http.RuntimeDispatcher` используется повторно. Новый HTTP facade принимает фабрику routes как функцию/узкий контракт, а не импортирует `app`. Если целая связная HTTP-группа удобнее остаётся у существующего transport owner, дополнительную папку не создавать. Итоговый путь этой группы уточнить по import graph до переноса, один владелец, без forwarding aliases.

Runtime factory может вызываться при создании/обновлении cached profile после старта. Это само по себе не нарушение: важно, чтобы она только собирала граф и явно владела его ресурсами. Нельзя заменять её созданием нового полного App, pools, hash budgets или clients на каждый запрос.

## План — четыре последовательных блока

1. **Закрепить границы и карту переноса.** Для каждого project source определить: constructor / runtime adapter / HTTP / orchestration / repository. Проследить фактические dispatcher cache/eviction/invalidation и lifetime ресурсов. Составить import graph будущих владельцев и список регрессионных roots. Не двигать код до разрешения циклов на уровне карты. Предыдущий проверяемый снимок остаётся отдельной работой.
2. **Выделить исполняемые adapters и workers.** Связными группами перенести project Access и Auth adapters к указанным владельцам. Scheduler/state доставки — вместе, startup/shutdown wiring оставить в app. Сохранить bounded parallelism, lease, current-scope checks, SMTP-before-claim и rotation очередей. Не добавлять универсальную фабрику операций и новые forwarding layers.
3. **Разделить подготовку, profile и HTTP.** Подготовку физических ресурсов оформить сценарием service с переданными adapters; dedicated DDL connection/session lock сохраняются. В profile оставить graph factory; HTTP route maps/facade отделить от assembly, а runtime readiness/current guards — от builders. Сохранить порядок authority checks, profile invalidation и drain. Существующие router/dispatcher/guards переиспользовать.
4. **Документация и приёмка всего изменения.** Обновить architecture/map/команды, реальные тестовые пути и fixture roots. Public tests — локальные tests, private assertions — у узкого владельца; не экспортировать внутреннее состояние ради переноса. Не удалять существующие сценарии. Передать Луне один immutable snapshot: обычные tests/lint при общем переносе пакетов, targeted SQL/Redis/race для затронутых гарантий. После ошибок — только affected repeat. Нагрузочные прогоны остаются отдельным финальным этапом.

## Условия завершения

- app создаёт граф и управляет его lifecycle; нет самостоятельных login/provisioning/delivery/preparation алгоритмов внутри app;
- динамическая фабрика строит профиль по доверенному snapshot, не является глобальным service locator;
- исполняемые пакеты не импортируют app/config. Нужные typed configuration values передаются constructors; HTTP/CLI не импортируют repository напрямую;
- service не зависит от pgx, конкретного repository или app. Locks, constraints, replay, актуальные права и audit остаются у SQL-владельца внутри исходных транзакций;
- неизменны API, ENV, schema, crypto purpose, проектная изоляция, SQL/Redis round trips и общий бюджет ресурсов, если отдельное изменение не согласовано;
- нет общего mutable current project; не создаётся полный App на каждый запрос;
- нет новых зависимостей, DI framework, SSO/billing scope или совместимых alias-пакетов;
- обязательные проверки фактически выполнены, ограничения отражены отдельно. Новое дерево не является доказательством production readiness или достигнутого RPS.

## Источники и пределы аудита

- [Go: Organizing a Go module, Server project](https://go.dev/doc/modules/layout#server-project) — cmd/internal и разнообразие layouts, без обязательного каталога app.
- [Mark Seemann: Composition Root](https://blog.ploeh.dk/2011/07/28/CompositionRoot/) — сборка графа около точки входа, отделение library code от composition.
- [Martin Fowler: Separating Configuration from Use](https://www.martinfowler.com/articles/injection.html#SeparatingConfigurationFromUse) — разделение настройки и использования сервисов.

Из этих принципов выведены рекомендации для текущего проекта. Это не утверждение, что у всех крупных компаний одинаковое дерево. Новый DI framework не требуется. Архитектурный аудит выполнен по исходникам и ограниченному независимому поиску; полный lifecycle cache и безопасность всех сценариев ещё не доказаны. Исполняемые проверки и изменения production-кода в этом задании не выполнялись.

Первоначальный промежуточный перенос сохранял HTTP bindings в runtime owner; этот остаток затем устранён через Endpoints и отдельный transport, см. завершение ниже.

## Ход реализации

Согласован пользователем. Вынесены runtime adapters, scheduler, SMTP/binding и preparation service. Общий registration bridge больше не принадлежит app. Межпроектный HTTP facade — transport/http/projects; runtime profile — auth/project/profile, deployment compilation остаётся app/projects/profile. HTTP bindings впоследствии выделены через runtime-контракт; весь план ожидает исполняемую приёмку. Пропущенный operatorReadyCheck восстановлен по исходнику после FAIL Luna предыдущего снимка. Исполняемая приёмка нового source delta ещё не завершена.

## Завершение исходного разделения HTTP/profile

HTTP bindings, feature handler construction, request guards и session HTTP binding находятся в `internal/transport/http/projects`. Runtime profile остаётся в `auth/project/profile`: закрытые поля, SQL authority/current checks, session adapters и profile factory. `Endpoints` — реальный внутренний production-контракт для HTTP с готовыми сценариями и callbacks доступности/актуальности; он не раскрывает pool, reader, cipher, limiter, root config или карту состояния. SessionRuntime сохраняет прежний UsePool/current-before-and-after протокол. HTTP не импортирует repository/pgx и не выполняет SQL. Origin/key guards и последняя policy/current проверка сохранены в прежнем порядке, фабрика и dispatcher переиспользуются.

Исправлены выявленные Luna compile errors: runtime profile symbols в consumers с двумя profile owners, устаревшие `.scope` после перехода к realmscope.Scope, private fixture dependency provider-settings test. Прежний operatorReadyCheck восстановлен. Source-реализация четырёх блоков завершена, но приёмочный пункт остаётся открытым до PASS нового snapshot; предыдущие FAIL не закрыты чтением кода.

## Закрытие плана

- [x] Зафиксированы владельцы, направления imports и lifetime: app — composition/lifecycle; runtime/SQL/HTTP у соответствующих owners.
- [x] Runtime Auth/Access adapters, scheduler, SMTP/current binding вынесены из app.
- [x] Preparation service выделен через ports; HTTP bindings отделены от закрытого runtime profile через Endpoints/SessionRuntime.
- [x] Документация и source пути обновлены; affected tests/lint/race/SQL/Redis приняты по V5, без повторов несвязанных наборов.

План закрыт. Следующий этап — MP7 по основному плану; MP8 нагрузка/память/GC затем. Подключение UI требует отдельного согласования. Код закоммичен по запросу пользователя: `f0cefe8 refactor(app): разделил сборку и проектные сценарии`.

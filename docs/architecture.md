# Архитектура универсального Auth

Целевая структура согласована 1 ноября 2026 для планируемого MP6R. Сейчас меняется только документация; перенос исходников не начат. Карта конкретных переносов и интерфейсов уточняется в R1 [плана рефакторинга](planning/readability-refactor.md). Фактические пути — в [карте проекта](ai/index.md), текущее состояние — в [текущем шаге](ai/current-task.md).

## Структура кода и правила пакетов

Фича владеет своими domain/service/repository/transport. Глубокое дерево допустимо, когда каждая папка обозначает самостоятельную понятную обязанность. Таблица БД или отдельная функция сами по себе не образуют фичу. Пустые пакеты и одинаковые слои ради симметрии не создаём.

```text
cmd/
├── auth/                         # HTTP backend
├── access-catalog/               # проверка и preview permissions
├── admin-recovery/               # аварийное восстановление
└── project-prepare/               # privileged подготовка проектных БД
internal/
├── app/
│   ├── app.go                    # общие ресурсы и сборка приложения
│   ├── run.go                    # запуск, остановка и cleanup
│   ├── auth/                     # сборка Auth-сервисов
│   ├── admin/                    # сборка общей панели управления
│   └── projects/                 # подключение Auth выбранного проекта
├── config/                       # конфигурация запуска
├── server/http/                  # HTTP server, timeouts, graceful shutdown
├── auth/
│   ├── account/                  # пользователь и его жизненный цикл
│   │   ├── domain/               # общие user/email/identity инварианты
│   │   ├── service/              # профиль, каталог, статус, удаление, identities
│   │   ├── email/{service,transport/http}/
│   │   ├── provisioning/{service,transport/http}/
│   │   ├── setup/{service,transport/http}/
│   │   ├── repository/{postgres,redis}/
│   │   └── transport/http/       # профиль, directory и общие actor/response helpers
│   ├── methods/
│   │   ├── password/
│   │   │   ├── domain/
│   │   │   ├── service/          # login/register/change/reauth, shared ports/crypto
│   │   │   ├── recovery/{service,transport/http}/
│   │   │   ├── provisioning/{service,transport/http}/
│   │   │   ├── repository/{postgres,redis}/
│   │   │   └── transport/http/
│   │   ├── emailotp/
│   │   ├── google/
│   │   └── telegram/
│   ├── session/
│   ├── token/
│   │   ├── service/              # issuance, refresh, native и общая authority
│   │   ├── native/transport/http/
│   │   ├── introspection/transport/http/
│   │   ├── transport/http/       # exchange/JWKS, parser и общие error rules
│   │   ├── signing/
│   │   ├── settings/
│   │   └── repository/{postgres,redis}/
│   ├── mfa/
│   │   ├── domain/               # модели и чистые правила выбора/отключения
│   │   ├── service/              # общие proof, crypto и admission контракты
│   │   ├── login/{service,transport/http}/
│   │   ├── management/{service,transport/http}/
│   │   ├── recovery/{service,transport/http}/
│   │   ├── telegram/{service,transport/http}/
│   │   ├── delivery/service/
│   │   ├── repository/{postgres,redis}/
│   │   └── transport/http/       # общие responses, errors и извлечение proof
│   ├── settings/
│   │   ├── domain/               # Policy/MFA, настройки и их инварианты
│   │   ├── service/              # Auth/MFA policy и общие ports
│   │   ├── smtp/{service,transport/http}/
│   │   ├── providers/{service,transport/http}/
│   │   ├── retention/{service,transport/http}/
│   │   ├── telegram/{service,transport/http}/
│   │   ├── repository/{postgres,redis}/
│   │   └── transport/http/       # Auth/MFA policy, trusted principal и mapper
│   └── delivery/                 # существующая доставка уведомлений
├── admin/
│   ├── administrators/           # владельцы и администраторы всей системы
│   └── projects/                 # каталог и управление проектами
│       ├── domain/
│       ├── service/
│       ├── repository/postgres/
│       ├── transport/http/
│       ├── runtime/              # bounded pools/leases проектов
│       ├── credentials/          # защита технических credentials
│       └── storage/postgres/     # подготовка БД и технических ролей
├── access/                       # роли, permissions и назначения
├── audit/
├── integrations/                 # протокольные клиенты
├── infra/                        # подключения, mailer, logger
└── transport/http/               # router, общие middleware и httpx
pkg/authjwt/                      # публичный verifier для внешних сервисов
migrations/
├── auth/                         # базовая схема Auth и её embed loader
├── admin/                        # дополнение только общей управляющей БД
└── tests/                        # проверки применения/отката схем
deploy/                           # развёртывание приложения
sandbox/
├── README.md
├── compose.yml
├── config/
├── internal/testsupport/          # общие helpers только проверочного стенда
└── tests/
    ├── token/
    ├── security/
    ├── cleanup/
    ├── session/
    ├── mfa/
    ├── projects/
    ├── access/
    └── load/
docs/
tmp/sandbox/                      # временные артефакты, ignored
Taskfile.yml
```

Это целевые границы, а не текущее дерево и не обязательный набор новых папок. Существующие feature adapters, hasher, signing и templates сохраняются у своих владельцев. Общий OIDC-код выделяется по реальным потребителям; существующие Google/Telegram adapters не удаляются и не переписываются ради общего framework. Оплата, entitlements и SSO отложены и не входят в этот рефакторинг.

### Сборка и запуск

`internal/app` владеет общими ресурсами и жизненным циклом. `app/auth` собирает сервисы авторизации; `app/admin` подключает общую панель; `app/projects` связывает обычные Auth-сервисы с доверенным контекстом выбранного проекта, настройками и ограниченными подключениями. Это один backend. Полный App не создаётся на каждый запрос, глобального current project нет.

`internal/admin` содержит поведение общей системы управления. `admin/administrators` — администраторы всей системы, а не роли пользователей одного проекта. `admin/projects` — каталог, состояния и административные операции проектов. Проектные пользователи принадлежат account, роли — access; административный bridge не копирует их бизнес-логику и не заменяет проектную сессию сессией владельца системы.

Пакеты app не импортируют корневой App обратно. Узкие зависимости передаются явно; не экспортировать весь внутренний граф ради нового дерева. Разделение app на пакеты не создаёт дополнительные pools, clients или workers. Сохраняются порядок startup/cleanup/shutdown и lifetime leases.

`internal/config` загружает конфигурацию запуска. `internal/server/http` получает готовый handler и отвечает за Listen/Serve, timeouts и Shutdown с deadline. Приложение завершает обслуживание запросов и фоновые процессы до закрытия их ресурсов. Config и server не содержат бизнес-правил или сборки repositories.

В cmd остаются arguments/env, stdio/signals, подтверждения и коды завершения. Связный application workflow извлекается только по необходимости. Project-prepare сохраняет отдельные credentials/privileges; обычный HTTP backend не получает DDL-доступ.

### Владельцы ответственности

| Слой | Ответственность |
| --- | --- |
| domain | Предметные состояния, правила и допустимые переходы |
| service | Сценарий, применение правил и координация зависимостей |
| repository | Чтение/сохранение, storage errors, атомарность и конкурентная целостность |
| transport/http | Форма запроса, JSON DTO, вызов сервиса и HTTP-ответ |
| app | Сборка, ресурсы и lifecycle |
| integrations | Протокол внешней системы, без ролей и пользовательских сценариев |
| infra | Технические подключения и общая инфраструктура |

Account владеет UUID, профилем, email и привязками внешних аккаунтов. Методы входа проверяют свои доказательства, session общая для всех методов, MFA выполняется до выдачи требуемой сессии. JWT сохраняет разделение authority/signing/public verification по [ADR004](adr/004-jwt-access-profiles.md). Совпадение email не объединяет внешние личности автоматически.

### Когда разделять большой пакет

Много файлов — повод проверить границы пакета, а не только размер каждого файла. Если внутри есть несколько самостоятельных групп сценариев с различными зависимостями, правилами и тестами, выделяем логические подфичи. Недостаточно просто раскидать файлы внутри того же широкого пакета или переименовать префиксы.

Сначала определить владельцев данных, публичные контракты, imports и транзакции. Для развитой подфичи допустимы собственные domain/service/repository/transport; небольшая подфича получает только нужные части. Тесты переходят вместе с владельцем. Общее остаётся у понятного владельца, без common/utils и циклов. Единую security-транзакцию не разрываем ради пакетов.

Числового лимита файлов нет. Не выделяем пакет на каждую ручку или маленький helper. Признак удачного разделения: разработчик находит весь сценарий, его зависимости и проверки в понятной области, а публичный API пакетов не разрастается ради доступа к внутренностям.

### Слои развитой фичи

```text
internal/auth/methods/password/
├── domain/
│   ├── credential.go
│   ├── password.go
│   ├── errors.go
│   └── tests/password_test.go
├── service/
│   ├── service.go
│   ├── ports.go
│   ├── login.go                  # сценарий, input/result
│   ├── register.go
│   ├── change_password.go
│   ├── forgot_password.go
│   ├── reset_password.go
│   └── tests/                    # публичные сценарии и свои mocks
├── repository/
│   ├── postgres/
│   │   ├── repository.go
│   │   ├── credentials.go
│   │   ├── password_change.go
│   │   └── tests/                # repository tests и testdata
│   └── redis/                    # только существующие нужные операции
├── transport/http/
│   ├── handler.go
│   ├── errors.go
│   ├── login.go                  # ручка, JSON DTO, Swagger
│   ├── register.go
│   └── tests/
├── hasher/
└── templates/
```

Самостоятельная HTTP-ручка — файл сценария с DTO/Swagger. Input/result находятся рядом со сценарием service, предметные модели — в domain. Constructor и действительно общие error mappings остаются у фичи. Не складывать различные контракты в results.go и не создавать глобальный каталог business errors.

### Зависимости, транзакции и файлы

Transport → service → domain. Repository реализует узкие интерфейсы потребителя; service не импортирует конкретные repositories/transport, domain не знает SQL/Redis/HTTP. Межфичевые связи — через явные контракты; app соединяет реализации.

Чистое решение бизнес-политики принадлежит domain/service. Repository загружает актуальные данные и обеспечивает сохранение, locks, constraints, CAS/version guards. Проверка до транзакции не заменяет проверку актуального состояния при изменении. Для межфичевого сценария сохраняется один владелец commit/rollback; service работает через узкий persistence port без зависимости от pgx.Tx. Redis и SMTP не становятся частью SQL-транзакции; audit/outbox — по [ADR002](adr/002-sessions-and-transactions.md). Универсальный CRUD/UoW framework не вводим.

HTTP проверяет форму запроса; service один раз применяет предметные правила. Не дублировать одинаковую валидацию между слоями. Resource bounds, транзакционная актуальность и fail-closed guards оцениваются отдельно и не удаляются как дубли.

Около 150 строк — смысловой ориентир рукописного Go. Связную операцию не разрывать и не уплотнять ради размера. Большой файл разделяем по обязанностям, широкий пакет — по подфичам. Tests/generated не ограничены этим ориентиром. Комментарии объясняют причины и гарантии; очевидные doc.go, part1/part2 и пустые слои не нужны.

### Тесты и sandbox

Миграции R3: auth-набор нужен каждой проектной БД и входу администраторов в общей БД; admin-набор устанавливается дополнительно только в общую управляющую БД. Go-загрузчик migrations/auth/schema.go встраивает единственный исходный SQL для privileged подготовки проектов. В migrations нет бизнес-сценариев; их tests находятся у фич, прямые schema up/down tests — migrations/tests. Файловые пути/loader обновляются вместе с callers и Compose/migrate commands; имена SQL-схем, версии, checksum и permissions сохраняются. Это фактическое размещение после принятого R3. Подробности — [R3](planning/readability-refactor.md#миграции-и-подготовка-бд).

Публичные tests фичи находятся в её локальном tests. Подпапка — отдельный Go-пакет даже при одинаковом package name. Обоснованные private tests остаются рядом с кодом; не экспортировать детали и не добавлять wrappers ради переноса. Repository tests могут использовать собственную настоящую тестовую БД без запуска всего Auth. Fixtures — в testdata своего suite; helpers общие только по реальному повторному использованию. Отдельный go.mod не создаётся.

Sandbox запускает тот же Auth с отдельными настоящими PostgreSQL/Redis и Mailpit. Тесты вызывают обычные API, отдельной реализации backend или бизнес-ручек стенда нет. Здесь ручные и сквозные проверки работающего сервиса; локальные unit tests не переносятся сюда только ради единой папки. Load/длительные проверки запускаются отдельно, окружение не обязано работать постоянно.

Сохраняются local-only ports, собственные сети/volumes, synthetic credentials и guarded cleanup. Реальные env/secrets и рабочие данные стенд не использует. Source schema/grants и Dockerfile не копируются ради нового дерева; final image содержит приложение без тестовых артефактов. Временные ключи/сертификаты/отчёты — tmp/sandbox вне Git.

При переносе обновить Taskfile/CI/Luna commands, relative fixture paths, opt-in conditions и coverage packages. go test ./... обходит обычные tests-подпакеты; команда одного пакета сама их не включает. Отсутствие ошибок при потерянном suite не считается успешной проверкой. Перенос файлов сам по себе не ускоряет runtime и не доказывает экономию токенов.

Общий код project identity/checksum принадлежит `internal/admin/projects/schema`, которым пользуются storage и repository. В storage его не помещаем: существующий onboarding storage уже зависит от repository, обратный импорт создаёт цикл. Это технический контракт установленной схемы, без бизнес-правил.

### Реализация разделения R3

Проектные roles/directory/policy имеют собственные service, repository adapters и HTTP. В projects/repository/postgres остаётся единый владелец catalog authority/admission/receipt транзакций; адаптеры не создают независимые commits. Общие bounded ReadDirectory/ReadDirectoryWithRuntime операции сохраняют прежние authority locks и target-current checks. Это узкий контракт существующей SQL-операции, без экспорта pool/полей repository и без универсального UoW.

Preparer workflow находится в app/projects/preparation; флаги/env/stdio/JSON — preparation/transport/cli, cmd/project-prepare только управляет сигналами/exit. Два private CLI tests остаются рядом с parser, self-managed SQL/HTTP suites перенесены целиком в app/projects/tests, сохранив общие fixtures. В service нет JSON DTO; результат сериализует CLI. App/admin собирает административные handlers, финальная root/Auth assembly и lifecycle — R7. Существующий admin-recovery уже разделяет CLI подтверждения и вызовы password/MFA services; новый framework команд не добавляется.

### Документация при рефакторинге

До переноса в R1 записать «старый путь → новый владелец → контракт → транзакции/ресурсы → проверки». Для крупного пакета описать выделяемые подфичи. В каждом рабочем блоке обновлять соответствующий раздел этой архитектуры, карту реальных путей, feature/API контракты и operational commands. Не оставлять это на конец всей переделки.

Для cmd документировать назначение, обязательные условия, privileges и подтверждения. Для sandbox — запуск/остановку, настройки, тестовые данные, группы проверок и безопасную очистку. Значимые гарантии, ограничения и объяснения границ хранить в существующих docs, не создавать README/doc.go у каждого файла. Статусы выполнения — в implementation/current-task, evidence — в history/acceptance, а не в архитектурном дереве.

## Исторические сведения до MP6R

Ниже сохранены ранее записанные детали реализации и исторические карты. Их формулировки «ещё не реализовано» относятся к датам соответствующих этапов, не к текущему статусу. Структуру задают разделы выше; актуальное поведение — код и feature-контракты, статус — current-task/implementation. Старые пути не означают, что запланированный перенос уже выполнен.

## Согласованное решение — 7 октября 2026

Фичевая архитектура была принята 7 октября и переносилась в этапе 4.5. Уточнение 1 ноября сохраняет направления зависимостей и заменяет прежнее целевое дерево правилами выше.

## Профиль и границы

MP4 resident sync: `project/runtime/sync.go` один worker на registry, только resident keys → batch metadata reader `repository/postgres/runtime_state.go`; shared binding SQL с cold loader. Failure/expired/incomplete evidence retiring исходный entry, active lease сохраняется; worker join перед закрытием private reader. [Контракт/verification status](features/project-runtime-sync.md). Не broker/full catalog scan/кеш permissions и не замена session authority.

MP4 local lifecycle: опциональная сборка в `app/auth/project_runtime.go` владеет private catalog reader/codec и bounded registry; `project/service.ChangeState` передаёт confirmed SQL receipt через узкий observer, `runtime.Observe` retiring только старые snapshots нужного realm/project. Existing resources закрывают registry перед catalog pools. [Config/ограничения/статус проверки](features/project-runtime-lifecycle.md). Не fleet signal, не credential rotation и не полная Auth feature assembly.

MP2.7 SQL registry: `internal/platform/project/runtime` владеет ограниченными project pools/leases и их cleanup; credential reader в project repository использует отдельный SELECT-only catalog pool, configured target задаёт transport. `ExecuteWithRuntime` соединяет registry с существующим role admission, без process-global current project или полного Auth.New на каждый проект. [Контракт и оставшиеся gates](features/project-runtime-registry.md). Production server/feature assembly/fleet budgets ещё не подключены.

Проектный runtime проверяется [общим SQL profile](features/project-runtime-profile.md): установленный source checksum и несекретная read-only identity projection, actual connection/owners/ACL. Role mutation выполняет проверку на собственной transaction connection; onboarding добавляет свои условия к тому же predicate. Обычный Auth hot path не получает этот probe. Registry/transport trust и bounded pools — отдельные задачи, SQL marker не аутентифицирует произвольный сервер.

Межбазовое административное создание роли использует [intent → committed admission → project receipt → catalog outcome](features/platform-role-intents.md#окончательный-допуск-и-выполнение--24-октября-2026). Authority locks защищают точку commit admission; последующий отзыв запрещает новые допуски, но не отменяет уже допущенную bounded команду. Никакой общей атомарной транзакции двух БД, пользовательского SSO или переноса platform cookie в project origin. Project runtime/pool проходит отдельную cold-open аттестацию; обычная session authority и немедленный отзыв не заменяются этим административным протоколом.

MP3 onboarding: [контракт](features/project-onboarding-preparation.md), opt-in -onboarding использует scoped SetupProof и общие settings/setup transaction-owned SQL operations, не новый Auth stack. Safe defaults/setup pin/private identity marker атомарны; общий schema/onboarding executor-only connection lifecycle сохраняет attestation/reseal. Ни users/roles, ни LOGIN/CONNECT/project ready не создаются этим stage. Raw setup secret не экспортируется; operator bridge/runtime/setup admission ещё впереди.

MP3 credentials: [контракт](features/project-secrets-preparation.md), `project/credentials` использует existing AES-GCM с realm/project/reservation/target/OIDs/schema/format/key-ID binding. Catalog EnsureSecrets/ReadDatabaseCredential — immutable row/flag и bounded current authority locks, typed reader возвращает snapshot после commit. `storage/postgres/password{,_verifier}`/opt-in CLI -password устанавливает SCRAM через согласованную xdg-go/scram v1.2.0; password+target receipt атомарны, replay без перезаписи. Root key только protected executor ENV, ordinary API не имеет ciphertext SELECT/SCRAM dependency. БД sealed/runtime NOLOGIN; LOGIN/CONNECT/runtime registry/configuration/admin/binding/ready впереди. UI не включён.

MP3-schema: [opt-in schema stage](features/project-schema-preparation.md) в существующем project-prepare. Встроенные initial Auth SQL/runtime grants остаются одним источником; отдельная NOLOGIN runtime role, schema и version/checksum/realm/project/OID marker коммитятся в project transaction. Persisted schema intent + exclusive CONNECT executor/shared marker, проверка новой connection до DDL, target session lock и project transaction lock; success только после reseal/current catalog check. Secrets/LOGIN/initial admin/binding/ready ещё не выпущены; обычный Auth API по-прежнему без DDL.

MP3-storage: [отдельный one-shot executor](features/project-storage-preparation.md), `cmd/project-prepare` → existing catalog Reserve + `platform/project/storage/postgres`. Две отдельные credentials, authoritative maintenance-БД с ownership journal и session lock, atomic role+owner OID record, закрытая physical DB и проверка реальных owner/database OID. Auth API не импортирует executor и не получает DDL privileges. Schema/runtime/keys/onboarding/ready и background scheduling ещё не реализованы; network connections требуют verified TLS.

MP3 reservation foundation: [внутренняя подготовка](features/project-preparation.md) — отдельный catalog SQL credential/profile, existing begin transition + one durable reservation, generation/target/replay guards в одной bounded transaction. Technical names по project UUID, nonce неизменяемый. HTTP/worker не запускают этот port; ручная CLI добавлена в MP3-storage, ready не публикуется.

MP2.5-create: [создание pending intent](features/platform-project-creation.md) — domain policy/command → managed project repository/common authority transaction → project INSERT + immutable creation snapshot/audit в одном CTE. Same operation получает один UUID, slug/origin защищены unique indexes; origin и single storage target задаёт trusted deployment config, не HTTP. Initial platform000001/grants расширены, existing install требует controlled upgrade. Executor/physical DB/runtime/bridge/UI не добавлены.

MP2.5-write-lifecycle: [retry/suspend/resume](features/platform-project-mutations.md) используют service ChangeState → managed project repository → caller-owned transaction/operator.AuthorizeMutation → прежний Transition. Shared authority locks до commit, fresh-proof deadline после ожидания, atomic audit/replay; ограниченные column grants. Нет нового pool/worker/schema/ENV, intent/provisioning/bridge/fleet ещё впереди.

MP2.5-read: [platform catalog API](features/platform-projects-api.md) — `project/service` владеет List/Read и pagination contracts, `project/transport/http` содержит две отдельные ручки. Operator assembly использует существующие SQL pool/AuthorizeRead, router — exact Host/TLS/Origin и NoRefreshAuth. Standalone эти пути не публикует. Запись/bridge этим read snapshot не авторизуются.

MP2.2: [lifecycle проектов](features/project-lifecycle.md) — domain matrix и `project/repository/postgres.Transition` в caller-owned Read Committed transaction, чтобы будущий platform service удерживал authority locks до того же commit. Audit/receipt находятся в platform catalog; нет своего worker/server/HTTP или универсального workflow. Health отделён от lifecycle; реальные storage checks и runtime generation leases принадлежат MP3/MP4.

MP2.3-operator-profile: [вход платформы](features/platform-login.md) выбирается через PLATFORM_ENABLED (default false). `app/auth/operator.go` собирает прежние Auth сервисы, `router/operator.go` публикует только setup/admin password+MFA/recovery/self-session allowlist на exact HTTPS authority. Matching SQL marker/restricted grants обязательны до assembly writes; fixed platform scope, без JWT/public registration/проектных admin API. Local SQL/Redis/TLS и unit/race PASS; lost-all-factors operational recovery и несколько проектов/dispatcher остаются открытыми.

MP2.3-realm-scope: [Redis/crypto isolation](features/realm-isolation.md) использует trusted kind+UUID+purpose. Все активные Redis constructors и cipher creation assembly получают scope; standalone явно legacy, нулевой scope запрещён. Новых HTTP routes/SQL schema/ENV нет. Independent key provisioning, storage identity, exact origin, grants и recovery новых realm остаются будущими gates; это не опубликованная multi-project платформа.

MP2.3-runtime-split: `internal/app/auth/app.go` — standalone resources/hasher/server composition; `realm.go` — существующая feature assembly с borrowed dependencies и собственными clients; `run.go` — background lifecycle/cleanup. HTTP routes/SQL authority не менялись; отключённый email OTP не добавляет typed-nil worker. Это проверенный single-runtime prerequisite: router contracts/task check/race PASS, но новые operator HTTP/realm namespaces/process admission/fleet scheduler ещё не реализованы.

MP2.3/MP2.4-foundation: [оператор платформы](features/platform-operators.md) находится в `internal/platform/operator/{domain,repository/postgres}`. Новая platform migration отделяет realm/grants/audit от проектных ролей; первый владелец создаётся атомарно через существующий Auth SetupService. SQL snapshot чтения прав не заменяет guard мутации/bridge. `task check` и реальный SQL setup/authority PASS; runtime/HTTP/login/recovery/origin/Redis/key isolation остаются открытыми.

MP2.1: [read foundation каталога](features/project-catalog.md) находится в `internal/platform/project/{domain,repository/postgres}`, migration — `migrations/platform`; unit/task check и реальный SQL integration на PostgreSQL18.6 PASS. Каталог не подключён к HTTP/App, management API/provisioning не реализованы; текущая рабочая Auth схема/пулы/ENV не менялись, migration применялась только в удалённой после теста disposable БД. Отдельные service/transport пакеты появятся с защищёнными сценариями, не как пустые заглушки.

MP1, 18 октября: [ADR005](adr/005-independent-projects.md) фиксирует целевой multi-project контракт и карту существующих владельцев. Один process/shared budgets, отдельный origin/runtime/SQL pool в общей ограниченной системе и отдельная БД schema auth каждого проекта. Platform operator управляет users/roles/settings всех разрешённых проектов из одной своей сессии через отдельный administrative bridge, не через пользовательский project login. Atomic project audit/receipt и guard платформенной authority — prerequisites будущего bridge, пока не реализованы. Существующее дерево Auth/access сохраняется, полный App.New не создаётся отдельно на каждый проект. Схема каталога/новые endpoints будут реализованы в MP2–MP5, SSO отложен.

J4a storage добавляет immutable browser/api profile в общем session ledger и feature-owned refresh tables/transaction primitives в token/repository/postgres. J4b.1 добавляет refresh owner; J4b.2a — первую password API issuance; J4b.2b.1 — native MFA coordinator/enrollment; J4b.2b.2 — email OTP binding к тому же workflow. Common primary/session guards, mail/consume, TOTP/recovery/start/enrollment и signing/audit переиспользованы. Native factor consume и API issuance имеют один repository transaction owner; email primary consume остаётся отдельным одноразовым workflow. Browser session не создаётся и не перепаковывается. NativePolicy server-only задаётся проверяемой deployment config. [Native App/HTTP](features/native-http.md) подключены disabled-by-default с общими owners, без новых pools/workers; online strict consumer — J5. Cookie/native профили изолированы, общий revoke сохранён. [Refresh](features/refresh-storage.md), [первая issuance](features/native-issuance.md), [native MFA](features/native-mfa.md), [native email OTP](features/native-email-otp.md).

Текущая реализация: один независимый backend на проект, собственные PostgreSQL, Redis, SMTP и secrets. Согласовано 18 октября, пока не реализовано: следующий функциональный этап до UI — один сервис/панель с каталогом независимых проектов и отдельной PostgreSQL-БД каждого проекта; SQL/Redis/settings/session/JWT границы проверяются по подэтапам [MP1–MP8](planning/multi-project.md), итоговая нагрузка и ресурсы — в MP8. Браузер работает через cookie/BFF и HTTPS; native/API access требует отдельного контракта, не переиспользования browser cookie. Общий SSO, организации, multi-app и Telegram commerce — отдельные расширения. Не строим свой OAuth server или универсальный plugin framework.

Physical cleanup принадлежит существующему account retention worker. J4b.2c.2 сохраняет две SQL keyset checkpoint rows для sessions/families: progress/deletes атомарны, no per-process authority state, bounded candidate page до eligibility/locks. Это не новая очередь или Auth settings; reuse window и текущая session authority не зависят от cursor. [Алгоритм/storage gates](features/refresh-storage.md#ограниченный-обход--j4b2c2-local).

### Текущая карта кода — 10 октября 2026

| Ответственность | Путь |
| --- | --- |
| Точка входа, signal context | `cmd/auth/main.go` |
| Сборка, Run, cleanup ресурсов | `internal/app/auth/app.go`, `run.go` |
| Configuration load / validation | `internal/config/config.go`, `validation.go` |
| HTTP serve / bounded shutdown | `internal/server/http/server.go`, `shutdown.go` |
| UUID, status, profile, email/contact | `internal/auth/account/domain` |
| Verification scenarios/config/encrypted delivery | `internal/auth/account/service` |
| Verification/audit/outbox SQL, Redis limits | `internal/auth/account/repository` |
| Verify/resend JSON API, verified-email gate | `internal/auth/account/transport/http` |
| Account assembly | `internal/app/auth/account.go` |
| Registration transaction composition | `internal/app/auth/app.go` |
| Resource lifecycle / delivery workers | `internal/app/auth/run.go` |
| AES-GCM payload / HMAC keys, bounded SMTP | `internal/infra/secretbox`, `internal/infra/mailer` |
| Password rules / credential | `internal/auth/methods/password/domain` |
| Password scenarios / ports / config / results | `internal/auth/methods/password/service` |
| Repository constructor / transaction helper | `internal/auth/methods/password/repository/postgres/repository.go` |
| Credential SQL / atomic registration, reset/change, outbox/audit | `internal/auth/methods/password/repository/postgres` |
| Recovery Redis limits | `internal/auth/methods/password/repository/redis` |
| Password JSON API | `internal/auth/methods/password/transport/http` |
| Argon2 / complete reset HTML | `internal/auth/methods/password/hasher`, `templates` |
| Session entity / errors | `internal/auth/session/domain` |
| Session scenarios / ports / config / results | `internal/auth/session/service` |
| Session SQL ledger / HTTP cookies/context/middleware | `internal/auth/session/repository/postgres`, `transport/http` |
| Выдача/валидация сессии | `session/service/create.go`, `validate.go`; PostgreSQL `sessions.go` |
| Список/отзыв собственных сессий | `session/service/management.go`, PostgreSQL `management.go`; HTTP `me.go`, `list.go`, `logout.go`, `logout_all.go`, `revoke.go` |
| Проверка доверенного Origin | `internal/transport/http/middleware/origin.go`; конфигурация загружается в `internal/config` |
| Block/unblock account / optimistic conflict / atomic revoke и audit | `internal/auth/account/domain/status.go`, `service/status.go`, `repository/postgres/status.go`; HTTP adapter пока отсутствует |
| Security event / recording contract | `internal/audit/domain`, `service` |
| Router, health, common HTTP helpers | `internal/transport/http` |
| Общий mapper / запись ошибки / безопасное логирование | `internal/transport/http/httpx/errors.go` |

Tests находятся рядом с кодом; register/login/change-password/validate сгруппированы по операции без потери прежних сценариев. HTML письма снова цельный, исходные байты сохранены. Рукописный Go-код ориентирован на 150 строк без числового gate; tests не ограничены. Clock/token helpers остаются в узких существующих infra-пакетах: не переносить их лишь ради внешней симметрии дерева.

### Контракт межфичевой регистрации и security-транзакций

В structural refactor сохранён текущий `passwordRepo.CreateUser`: account/contact/profile/credential создаются одной SQL-транзакцией. Метод и интерфейс явно помечены как legacy cross-feature write; SQL и поведение не менялись. Разделение на независимые commit запрещено.

При lifecycle реализации account отвечает за пользователя/контакт/профиль, password — credential, session — SQL ledger. Service сценария получает transaction-aware port с узкими операциями этих владельцев; composition root связывает PostgreSQL adapters на одном pool и одном tx. Общий tx не передаётся как pgx.Tx в бизнес-сервис и не хранится неявно в context. Конкретный контракт вводится под операцию, без универсального CRUD или framework. Повышение auth_version, отзыв и security audit/outbox входят в ту же SQL-транзакцию; сетевые отправки — после commit через outbox. Повторная/конкурентная обработка проверяется в этапах 5/6. В 5.2 SQL ledger и atomic reset/change с auth_version/revoke/audit реализованы; Redis session adapter больше не подключён в app и не является fallback. Общие audit/lifecycle policies и полная security-приёмка остаются впереди.

### Legacy session adapter

`internal/auth/session/repository/redis` сохранён как прежняя, неподключённая реализация: imports из app/действующих фич отсутствуют. Он не проверяет актуальную SQL auth_version, а refresh использует безусловную запись; это не действующий authority, не безопасный fallback и не реализация optional cache-профиля 6.9. Redis клиента/limits не удаляли. Повторное использование адаптера требует отдельного проектирования по ADR 002.

Результат создания сессии и параметры находятся в `service/create.go`, результат проверки `ValidationResult` — в `service/validate.go`. Password `LoginInput`/`LoginResult` находятся в `service/login.go`, `RegisterResult` — в `service/register.go`: это контракты сценариев, не domain-модели. Общие `results.go` удалены. HTTP session middleware — в `transport/http/auth.go`, session domain errors — в `domain/errors.go`. Password repo constructor и transaction helper — в `repository/postgres/repository.go`; общий revoke helper используется change/reset в той же транзакции. Выдача reset challenge — в `forgot_password.go`, его потребление — в `reset_password.go`. MIME building — `infra/mailer/message.go`; отправка сохраняет прежнее поведение.

После 5.2h account HTTP resend/confirm и password HTTP forgot/reset имеют отдельные файлы со своими DTO и Swagger; общие Handler/constructor/response — в handler.go. Change-password DTO/валидация находятся в change_password.go. Feature-local errors.go/recovery_errors.go содержат ordered правила и fallback; общий httpx/errors.go не импортирует domain фич. MapError сопоставляет sentinel через errors.Is и typed errors через локальный predicate с errors.As; WriteFailure пишет ответ, RespondError логирует безопасные публичные поля один раз через request logger. Request ID генерируется сервером; raw errors, входные данные и secrets не логируются. Health сохраняет отдельный контракт.

Account verification service и HTTP-сценарии называются `verification_resend.go`/`verification_confirm.go`; подготовка письма и challenge через `PrepareVerification` — в `service/verification_mail.go`, настройки — в `verification_config.go`, ограничение регистрации — в `registration_limit.go`. `delivery.go` содержит цикл worker, `email_message.go` — расшифровку payload и отправку письма. Общие части HTTP смены email находятся в `email_change_handler.go`, SQL-транзакционные helpers — в `email_change_transaction.go`. Password recovery settings — в `service/recovery_config.go`. Config validation остаётся одним файлом с именованными проверками. Это правила для дальнейшей разработки, закреплённые также в [AGENTS.md](../AGENTS.md).

### Историческая карта переноса 4.0 (до согласования 4.5)

| Прежнее место | Текущее место |
| --- | --- |
| `internal/featers/password_auth` | `internal/modules/auth/password` |
| `internal/featers/session` | `internal/modules/auth/session` |
| Feature `domain` / `repo` | Feature `model` / `repository` |
| `core/domain/user.go` | `auth/account/model/user.go` |
| `core/domain/email.go` | `auth/email/model/email.go` |
| `core/domain/password.go` | `auth/password/model/password.go` |
| `core/domain/session.go` | `auth/session/model/id.go` |
| `core/config` | `internal/app/config`; feature config types — в своих `model` |
| `core/infra/hasher`, `mailer/templates` | `auth/password/hasher`, `auth/password/templates` |
| Остальной `core/infra` | `internal/infra` |
| `core/audit` | `auth/audit` (контракт, ещё не durable sink) |
| Cookie/context/auth middleware из `core/transport` | `auth/session/transport/http` |
| Остальной `core/transport/http` | `internal/transport/http` |

Пути `auth/...` в таблице сокращены относительно `internal/modules`. Aggregated config размещён в `app/config`, потому что он связывает infrastructure settings и feature-owned config; сами сервисы не зависят от него. Config tags/defaults и runtime validation сохранены. `CreatedSession` перенесён из session service в session model: парольный сервис использует интерфейс и модель результата, не импортирует реализацию session service.

HTML reset-письма разделён на header/content, которые соединяются перед parsing: шаблон и контекст escaping сохранены без изменения исходных байтов.

После 4.5 use cases добавляются в service выбранной фичи, domain types — в её domain, SQL — в локальный repository, HTTP DTO/handlers — в transport/http. Маршрут подключается общим router, зависимости — в app/auth, Swagger обновляется при изменении API. Стабильные Swagger schema names сохраняются при переносе через @name. До переноса фактические пути остаются из исторической карты выше.

| Модуль | Ответственность | Не отвечает за |
| --- | --- | --- |
| Account / auth methods | Пользователь, привязки, проверенные методы, credentials, challenges | Роли и оплаченные функции |
| Sessions | Сроки, authentication context, устройства и отзыв | Выдачу прав по данным клиента |
| Access | Каталог permissions/roles, назначения, ownership | Тариф и факт оплаты |
| Entitlements | Каталог features/plans, grants, периоды и квоты | Административные permissions |
| Billing | Заказы, checkout, subscriptions, inbox/reconciliation | Вход и самостоятельную выдачу ролей |
| Infrastructure | DB/Redis/SMTP/HTTP, конфигурация, audit/outbox | Продуктовую политику |

Взаимодействие — через явные сервисные контракты и транзакционные domain operations. Billing переводит подтверждённые события в grants через entitlement service; другие модули не интерпретируют raw provider payload. Операция продукта проверяет permission + ownership и, если требуется каталогом, entitlement/квоту.

Уточнено 10 октября: ручное создание/приглашение принадлежит account (5.7), назначение ролей/optional персональных permissions — access (10.6), manual/paid grants и effective access — entitlement (11.5). Будущий UI использует защищённые APIs этих фич, не переносит правила в frontend. Создание пользователя само не назначает роли; paid entitlement не меняет `account.status` и не выдаёт admin.

Billing может быть включён внутри приложения либо вынесен в отдельный payments service. Во втором профиле Auth сохраняет минимальный billing event adapter (12.8), собственный durable inbox и локальные атомарные entitlement/audit операции; provider secrets, checkout и финансовый ledger остаются снаружи. Интеграция — через authenticated versioned events/retries/reconciliation, не shared DB и не distributed SQL transaction. Event endpoint выключен без выбранного профиля. Текущее дерево сохраняется, заранее пустые пакеты/interfaces не добавляются; детали в [ADR 003](adr/003-access-and-optional-billing.md).

## Источники истины

PostgreSQL хранит пользователей/status/auth version, identities, session ledger, одноразовые challenges, назначения прав, каталоги/grants, billing state, audit и inbox/outbox. Изменение credentials/status, инвалидация и запись security audit выполняются одной SQL-транзакцией. Redis — ограничители нагрузки и ускорение, но не единственное доказательство действительности сессии/прав/оплаты. Детали отказов — [ADR 002](adr/002-sessions-and-transactions.md).

Согласовано 9 октября: от Redis не отказываемся. В базовом профиле session/status/version enforcement остаётся SQL с немедленным отзывом для проверок после commit. Redis кеширует только данные с явно допустимой устарелостью и обслуживает распределённые limits. Взаимодействие хранилищ находится в session feature, app только собирает зависимости. Cached session validation — optional extension после измерений 6.8 и нового ADR 6.9; задержка 5 секунд не согласована и не является default.

Производительность подтверждается измеримым load profile, несколькими API instances, bounded pools/hash concurrency/deadlines, контролируемым refresh и защитой от stampede. Failover/restore не возвращает revoked access; отказы кеша не превращаются в безлимитный SQL fallback. Шаблон не требует JWT, микросервисов или plugin framework; методы входа, роли и оплата остаются независимыми. Общий multi-project SSO — отдельное расширение, не следствие повторного использования кода.

UUID пользователя неизменен; email, username и provider display name не являются идентификатором владельца. Identity определяется проверенным issuer/subject с областью выбранного адаптера. В базовом профиле scope одного приложения задаётся сервером; client app/user/owner ID не расширяет доступ. Цена и владелец покупки фиксируются сервером.

5.4: `account/service/StatusService.Change` — внутренний сценарий active/blocked с actor/target UUID и expected auth_version. PostgreSQL владеет lock/conflict/deleted проверкой и атомарной записью status/version/revoke/challenge cleanup/audit. Status audit failure отменяет весь transition. `ActorID` — attribution, не проверка permissions; сервис не подключён к router и не публикуется до authorization/MFA/fresh-auth/CSRF/last-admin guards этапов 10/13.1. Account deletion/retention и восстановление удалённых пользователей сюда не входят. Вход/сессии используют прежние active/not-deleted/version SQL gates; права доступа не дублируются в HTTP/domain.

5.6a: `account/service/DeletionService.Delete` — внутренний lifecycle без router/UI. Одна SQL transaction помечает account blocked/deleted, повышает version, отзывает и очищает metadata сессий, удаляет password/profile/challenges/change intents/outbox, снимает verification, записывает deletion audit. Verification lock order — user перед contact. 5.6b-worker: `RetentionService` и feature SQL выполняют bounded purge контактов/завершённых sessions/пяти audit tables по env, раз в минуту/SKIP LOCKED/deadline 5s. Контакт после release не переезжает к новому owner; новый UUID и verification не наследуют прежнее состояние. Users/tombstones сохранены, `email_released_at` исключает завершённые reservations из рабочего индекса; `email_reuse_blocked` защищает blocked-before-deletion адреса. Restore reconciliation, ban-erasure и billing lifecycle остаются открытыми; [контракт](features/account-deletion.md).

## Независимые настройки

5.7a: account ProvisionService создаёт pending UUID/contact и purpose-bound invitation/outbox/audit; durable actor-scoped command identity отделена от ephemeral token. Password ActivationService применяет policy/hash/Redis budgets и узкий порт account repository для атомарной owner/version/expiry activation. App собирает их, публичен только optional POST activation; internal App.Provisioning не заменяет authorization. Account worker обслуживает invitation queue вместе с verification/email-change, retention очищает expired jobs/challenges и audit. Роли/session/grants не выдаются; подробности/5.7b — [invitations](features/invitations.md).

Это будущий контракт этапов 9–12, ещё не существующие env-переменные или endpoints:

- `access`: permission/role catalog отдельно от назначений пользователям. Продукт расширяет каталог без hardcoded business enum. Системные permissions защищены от произвольного переопределения.
- `auth`: независимый выбор методов входа, registration enabled, email verification enabled/required для password, TTL/cooldown и frontend URL. Optional verification не подменяет verified_at; OTP/reset/change-email/linking всё равно доказывают контроль почты. Настройки/API/UI реализуются в самом конце, 14.4s–14.4u, после backend и permissions + MFA; сейчас используются нынешние operational env и политики.
- `entitlements`: features/plans/limits, версии и manual/trial grants отдельно от access. Free/Pro — пример, а не обязательные названия.
- `billing`: подключение выбранного provider, checkout/recurring capabilities и режим новых продаж отдельно от entitlement catalog. Secrets — только operational configuration.

Auth-only deployment не требует payment secrets, provider connections или billing workers. Entitlements могут работать без оплаты через manual/trial grants. Billing-enabled профиль подключает checkout и обслуживает обязательства. Выключение новых продаж существующего billing deployment не выключает cancellation/webhooks/reconciliation и не удаляет историю/grants. Полное снятие интеграции допускается лишь после завершения обязательств. Нельзя выключением модуля молча разрешить платную функцию: неизвестный feature или недоступный evaluator даёт отказ; отсутствие платных ограничений задаётся явно проектом.

Доступ к настройкам ролей, назначениям, тарифам и оплате защищают разные permissions. Admin не получает Pro, Pro не получает admin. Защищённые admin API публикуются после MFA 13.1: fresh auth, audit, проверка scope и optimistic version/conflict при изменении. Первоначальная настройка супер-админа — одноразовая operator-controlled операция с durable initialized marker: backend 10.3a-local реализован внутри account/service/repository/transport, [контракт](features/initial-setup.md). Email/TOTP доказываются до атомарного создания user/password/factor/system grant; root encryption key не является operator proof. UI-мастер — позже в 14.4u-setup. Потеря admin не открывает setup заново: обычный password recovery по почте или [отдельная operator CLI](features/admin-recovery.md) 10.3b-local без reset БД, смены status/roles или MFA bypass. CLI собирает только password service/repository и ограниченный SQL pool, не HTTP app/Redis/SMTP/root secrets. Lost-factor recovery и внешняя operator acceptance ещё открыты. Каталог custom roles и ручные назначения — UI поверх access API, не privileged поля аккаунта; общие management routes/settings/UI остаются в плане.

UI также позволит вводить/заменять SMTP/provider secrets через отдельный protected API. Чтение даст только configured/masked state, storage защищается шифрованием/secret storage, audit исключает payload. Минимальные operational root key и первый admin остаются вне этой UI-зависимости. Настройки и UI — последние функциональные задачи 14.4s–14.4u перед release 14.5, не уже реализованная возможность; текущие email env остаются startup configuration.

## Реализация и открытые условия

5.7c-local: optional TemporaryPasswordService и его repository/HTTP находятся внутри methods/password по сценариям temporary_provision/reissue/login/complete. Account ProvisionInTransaction обеспечивает ту же atomic user/profile/contact/idempotency creation без второй реализации; password repository добавляет временный credentials и audit в эту транзакцию. App.TemporaryPasswords — внутренний trusted-caller API, не административное разрешение. Публичны только opt-in login/complete с Origin/no-store: pending gate, ограниченное setup authority вместо session, atomic permanent password без email verification/roles. Shared Redis/Argon2/pool и существующий indexed retention, без новых workers. Admin/operator UI и MFA остаются отдельными gates; [контракт](features/temporary-passwords.md).

Приняты [ADR 001](adr/001-deployment-and-reuse.md), [ADR 002](adr/002-sessions-and-transactions.md), [ADR 003](adr/003-access-and-optional-billing.md). [Модель угроз](threat-model.md) задаёт негативные acceptance tests.

Этап 4 и 5.1–5.4 выполнены локально; 5.5a–d реализованы как opt-in [email change/report/protected password recovery](features/email-change.md), локальная backend-приёмка 5.5e-local завершена. 5.6a deletion и 5.6b-worker реализованы и проверены локально; далее provisioning 5.7. 5.6b-operations и внешняя приёмка 5.5e-staging с настоящим email/browser остаются открытыми. Ограничения — [API-контракт](api/contract.md), [verification](features/email-verification.md), [recovery](features/password-recovery.md). После 5.2r/5.2h дерево сохранено: app/auth остаётся app.go/account.go/run.go, независимые HTTP-сценарии и feature-local error rules отделены, общий mapper не импортирует business domain. EmailChangeService и RetentionService собираются в существующем app.go; workers останавливаются общим app lifecycle до закрытия ресурсов. Request/confirm/report и PostgreSQL операции находятся в своих смысловых файлах. Далее остальное 5/6, MFA 13.1 до административных действий; 7–10, 11 и optional 12, release 14. Полная session security и нагрузочная приёмка 6.8 остаются впереди; 6.9 optional.

5.5d: policy/hash сценарий защищённого восстановления находится в password `service/protected_recovery.go`, его DTO/HTTP mapper — в password `transport/http/protected_recovery.go`. Узкий порт связывается с account `repository/postgres/protected_recovery.go`, который владеет атомарным восстановлением user/contact/credential/version/challenges/audit. Password service не импортирует repository; app только собирает dependencies. ProtectedRecoveryService использует существующий RecoveryService для общего Redis/hash budget, не вводит второй worker или lifecycle. Mail intent подготавливает account email-change service; при report SQL выдаёт version-bound authority и помещает отдельный encrypted payload старому contact в тот же outbox. Future MFA/non-password recovery требует собственного доказательства и не наследует mailbox-only unblock.

До 12.1 пользователь выбирает merchant profile: страна/юридический статус продавца, валюты, товары, разовая/recurring оплата, refund/cancel требования. Затем выбирается и проверяется один hosted-checkout provider; конкретный поставщик сейчас не объявлен поддержанным. Native/SSO/organizations/Telegram commerce требуют отдельного подтверждения scope перед своими подэтапами.

Уточнение executor assembly: app/projects/preparation создаёт и закрывает concrete SQL/storage adapters для отдельного privileged процесса. Это инфраструктурная сборка, поэтому она не находится в service. Preparation CLI читает flags/env и вызывает этот application workflow; domain/service фич не импортируют concrete adapters. Правила архитектурного теста не ослаблялись.

### MFA после R4

Login владеет browser/native challenge, завершением и required enrollment; management — TOTP enrollment/replacement, step-up, отключением, recovery codes, email-фактором и предпочтением. Recovery владеет независимо одобряемым восстановлением и операторским решением. Telegram управляет каналом и фактором; доставка security notices находится в delivery/service. TelegramLogin остаётся в login/service. Существующая EmailLogin-реализация использует общий OTP challenge/outbox в methods/emailotp/service; перенос в login с обратным import создал бы цикл, копии механизма не добавляем.

Общий mfa/service содержит только используемые несколькими сценариями proof/ports/configuration, криптографическую проверку, подготовку enrollment/recovery codes и admission. Он не импортирует конкретные MFA-подфичи. Общий mfa/transport/http не импортирует их handlers; app/router подключают management, login и recovery отдельно. Никакого umbrella handler или forwarding facade нет.

Repository возвращает MethodSelection одним прежним SQL-запросом, domain выбирает метод без fallback при недоступном предпочтении. Service передаёт CanDisableTOTP в узкий transaction-scoped порт; repository вызывает его после прежних access/user/session locks и fresh proof на актуальном состоянии, перед delete/preference/invalidate/audit/commit. SQL constraints и current guards сохраняются.

Публичные unit/HTTP tests расположены в локальных tests. Private securityNotice payload tests остаются рядом с delivery implementation. Связный cross-feature SQL suite и общие fixtures перенесены из password/repository/postgres в internal/app/auth/tests одной closure: проверки не становятся частью парольного repository и не копируют fixtures. Private registrationError test остаётся у password repository. Проектные сквозные suites остаются internal/app/projects/tests. Это единый тестовый suite сборки, а не новый production-пакет.

HTTP-пакеты подфич имеют явные Go names mfaloginhttp, mfamanagementhttp, mfarecoveryhttp и mfatelegramhttp; общий остаётся mfahttp. Существующие Swagger schema IDs закреплены @name: перенос не меняет клиентский контракт и не требует новой копии DTO ради генератора.

### Account и пароль после R5

Account/email владеет подтверждением, привязкой и сменой email, защитным report и существующей доставкой account outbox. Общая модель Email/User/Identity остаётся account/domain; правила не копируются в способы входа. Account/provisioning управляет ручной выдачей пользователя и приглашениями; account/setup — первым администратором и одноразовым setup. Каталог/статус/удаление/identity resolution и management остаются в корневом account/service по существующим сценариям.

Account/provisioning и EmailChange получают собственные узкие repository ports, limiter и cipher напрямую. Verification не используется как контейнер технических зависимостей. App/account возвращает именованные собранные ресурсы verification/repository/limits/cipher: сборка соединяет их, service не импортирует app. Общие ports, admission, token helpers и зашифрованный EmailMessage лежат account/service и используются реальными потребителями. Bootstrap Config с прежними ENV остаётся там же; новых глобальных настроек не вводим.

Password/service сохраняет обычные login/register/change/reauth и общие contracts. ParseCredentials используется обычным и временным входом без копирования правил. Password/recovery объединяет reset/outbox, защищённое и операторское восстановление. Password/provisioning — временные credentials, их обязательную замену и активацию приглашения. Activation не создаёт RecoveryService ради hashing/limits: получает эти зависимости явно, сохраняя порядок bounds/policy/admission/preflight/hash/transaction recheck. OIDC callback сохраняет общую атомарную flow-consumption/provider verification; email OTP сохраняет единый challenge/outbox, включая EmailLogin. Дополнительные слои для Google/Telegram не добавлены.

SQL-владельцы account/repository/postgres и password/repository/postgres сохранены: current proofs, user/access locks, email/credential/version updates, invalidation/audit/outbox и idempotency commits не разрываем ради симметрии подпапок. Leaf repositories не создаются пустыми wrappers поверх этих transactions. Код SQL и schema не переписывается из-за имён Go-пакетов.

Публичные service/HTTP сценарии, которые переносились, тестируются в локальных tests. Private cursor/error-table/payload assertions остаются рядом; инжектированный cipher в setup-тесте берётся из собственной fixture, не из private поля production service. Connected SQL suites остаются app/auth/tests и app/projects/tests после R4; повторного переноса/копий нет. Режим приёмки — только affected packages и связанные guarantees, с переиспользованием собственного стенда Luna.

Go names HTTP-пакетов: accounthttp/accountemailhttp/accountprovisioninghttp/accountsetuphttp и passwordhttp/passwordrecoveryhttp/passwordprovisioninghttp. Прежние публичные Swagger schema IDs явно закреплены @name; внешние ссылки обновляются вместе с переносом, DTO не копируются ради генератора.

### Сессии, токены и настройки после R6

Настройки SMTP, внешних провайдеров, сроков очистки и Telegram Bot имеют собственные service/HTTP в settings/smtp, providers, retention, telegram. Policy/MFA и общие ProviderCipher/SettingsLimiter остаются settings/service, предметные snapshot/инварианты — settings/domain. Раздельные сервисы получают нужные порты напрямую. Общий settings/repository/postgres сохраняет locked authorization, версии, согласованные guards и audit; новые repository wrappers не вводятся.

Token HTTP разделён на browser exchange/JWKS (transport/http), cookie-free native endpoints (native/transport/http) и service introspection (introspection/transport/http). Общий DecodeRequest сохраняет прежние ограничения JSON/размера/required/null/unknown полей; общие error rules не копируются. Публичные Swagger schema IDs явно закреплены. Сервис issuance/native/refresh остаётся связным: coordinator, factory и native completion используют один admission budget, signer и transaction authority. Introspection factory и существующий public verifier boundary сохранены; private поля/каналы не открываем для переноса по имени файла.

SessionService, Management, Activity и Rotation остаются в session/service с собственными сценариями и узкими портами; целостные SQL operations и немедленный отзыв сохранены. Access остаётся в существующих domain/service/repository/HTTP: общий Principal/permissions/версии и locked writes не разрываются. Audit Event/Recorder и маленький bounded delivery worker не требуют новых слоёв. Mailer уже разделён на connection/send/message и сохраняет прежнюю SMTP-реализацию.

Публичные tests session service/HTTP, Access service/domain/settings, settings domain/service/HTTP, token domain/Redis, SMTP Redis, mailer и delivery находятся в локальных tests. Тесты приватного admission/signing/codec в token, private Access HTTP DTO assertions и SMTP gate/probe остаются рядом с владельцами. Тесты сессий проверяют оба существующих публичных validation entrypoints; safety mapper settings проверяется через публичный Read. Production internals ради tests не экспортируются. Малые test actors/лимитеры у владельцев не становятся production framework.

### R7: сборка приложения и проектные границы

`cmd/auth` вызывает `internal/app.New`. Root App владеет process SQL/Redis/logger/shared hasher, HTTP запуском, startup cleanup и завершением. `app/auth.Assemble` получает заимствованные Dependencies и возвращает Runtime с Handler/Run/Close. Runtime владеет своими workers; teardown выполняется в прежнем порядке через небольшую LIFO Resources-группу. Общая конфигурация и `server/http` самостоятельны.

```text
internal/app/
├── app.go, run.go, server.go, resources.go
├── auth/                   # общая Auth сборка и lifecycle
│   ├── registration/      # сборка регистрации с email-outbox
│   └── setup/             # сборка первого администратора
├── admin/                  # сборка административных сценариев
└── projects/
    ├── runtime/            # registry, reader, scoped SMTP и Binding
    ├── profile/            # конфигурация, readiness и таблица маршрутов
    ├── browser/            # HTTP dispatcher, cache и lifetime профиля
    ├── methods/            # password/registration/temporary, OTP, OIDC
    ├── account/            # email, приглашения, directory и lifecycle
    ├── mfa/                # сборка login, management и факторов
    ├── native/             # сборка JWT/native/refresh
    ├── access/             # проектные адаптеры ролей и permissions
    ├── settings/           # проектные адаптеры настроек
    ├── delivery/           # bounded workers доставки
    ├── onboarding/         # закрытый setup проекта
    ├── preparation/        # сборка privileged preparation CLI
    └── tests/              # связанные проектные SQL/HTTP suites
```

Это сборка существующих фич: domain/service/repository/transport остаются у фич, SQL и транзакции не переносятся в app. Scoped adapters используют Binding вместо ссылки на весь профиль. Profile зависит от feature adapters; browser публикует собранные маршруты. Обратных imports в source нет. Shared setup/registration сборка используется обычным и проектным режимами, без копий security-сценариев.

Crypto state, limiters и техническая конфигурация остаются private. Внешняя сборка использует операции готовности, создания сервисов и привязки факторов. SMTP.Use сохраняет один lease и прежние guards до/после операции; Mailer связан с тем же pool. `secretbox.ForScope` выполняет прежние Scope.Purpose и NewScoped. Общие hash/SMTP/Bot gates переиспользуются.

Root tests проверяют реальный App.Run/startup cleanup. Общие синтетические config/manifest helpers используются только тестами из `internal/app/tests/fixtures`; production-код их не импортирует. Private lifecycle/конфигурационные assertions остаются рядом с владельцем; публичные сценарии могут быть в локальных tests. Связанные SQL suites не копируются. Весь R7 принят Luna по итоговому V5: tests/lint, affected race, SQL/Redis и API. Evidence и ограничения — в [сводке приёмки](operations/acceptance-summary.md#r7-сборка-приложения--приёмка-4-ноября-2026).

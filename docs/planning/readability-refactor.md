# MP6R: план рефакторинга читаемости

Статус: целевые принципы и дерево согласованы 1 ноября 2026; пользователь отдельно подтвердил разделение широких пакетов по логике. Сейчас только документация и планирование, реализация не разрешена. Это детализация [MP6R](multi-project.md#mp6r-проверка-безопасности-и-рефакторинг-перед-итоговой-приёмкой), а не новый функциональный этап. [Целевая архитектура](../architecture.md) определяет направления; конкретные переносы, интерфейсы и выделяемые подфичи уточняются в R1 до изменения кода.

## Итог обсуждения

- Сохраняем фичевую архитектуру domain/service/repository/transport и собственные repositories фич. Убираем смешение обязанностей внутри пакетов и файлов.
- Тесты публичного контракта переносим в локальную подпапку tests у владельца. Закрытые детали не экспортируем ради красивого дерева; необходимые private tests остаются рядом с кодом.
- Сохраняем имя sandbox. Окружение и связанные с ним проверки собираются в корневом sandbox, с группировкой проверок по фичам. Отдельное общее дерево tests/integration/acceptance/performance не используем.
- В cmd остаются понятные эксплуатационные команды; в app — сборка и владение ресурсами. Целевые имена: app/auth, app/admin, app/projects; функции общей панели — admin/administrators и admin/projects. Старые platform/projectauth и standalone/operator/project не используем для нового дерева.
- Если в пакете много разнородных файлов, разделяем по самостоятельным логическим подфичам и контрактам. Один большой пакет из множества маленьких файлов не решает проблему читаемости. Числового лимита файлов нет, перенос обязан сохранять транзакции и понятное владение ресурсами.
- Чистые бизнес-решения принадлежат domain/service; repository обеспечивает сохранение, актуальность и атомарность. Перенос правил не разрывает транзакции.
- Документация обновляется вместе с каждым переносом: архитектура и реальные пути, контракты фич, команды cmd/sandbox и проверки. Следующий результат планирования — точная карта переносов и интерфейсов. Исполнение R1–R8 начинается после отдельного разрешения; сейчас меняются только документы.

## Цель и неизменяемые условия

Разработчик должен находить сценарий по имени фичи и читать его без обхода десятков несвязанных файлов. Сохраняем согласованную [архитектуру](../architecture.md): фича → domain / service / repository / transport; PostgreSQL repositories принадлежат своим фичам. Config, server, integrations и assembly имеют отдельные обязанности.

Не вводим core/common/utils, универсальный DI-контейнер, слой на каждую функцию и новые зависимости. Не добавляем функционал, workers, pools или Redis/SQL обращения ради новой структуры. Около150 строк — смысловой ориентир, а не предел. Связная транзакция может быть длиннее; её нельзя дробить так, чтобы терялся владелец commit/rollback.

Сохраняем API, CLI flags/exit codes, формат токенов, SQL authority/constraints, немедленный отзыв, proof freshness, MFA/recovery, crypto scopes, project isolation и resource ownership. Исправление обнаруженного дефекта безопасности оформляется отдельно от механического переноса и проверяется по затронутой гарантии.

## Что фактически обнаружено

Структурная инвентаризация handwritten Go-файлов и целевое чтение владельцев сборки/HTTP/сервисов выполнены на базе58714c1. Числа — прямые файлы одного каталога, без вложенных каталогов; строки сами по себе не доказывают сложность. Generated Swagger не используется для оценки читаемости.

| Каталог | Рабочие Go-файлы | Тестовые Go-файлы | Наблюдение |
| --- | ---: | ---: | --- |
| `internal/app/auth` | 111 | 52 | Разные режимы приложения, project runtime adapters, HTTP bindings и delivery собраны одним пакетом |
| `cmd/project-prepare` | 3 | 122 | Большая часть объёма — системные SQL/HTTP/изоляционные тесты, не CLI |
| `internal/auth/methods/password/repository/postgres` | 17 | 131 | Место хранения интеграционных тестов account/access/MFA/settings и других фич |
| `internal/platform/project/repository/postgres` | 50 | 2 | Catalog/preparation/runtime и несколько административных протоколов соседствуют в одном пакете |
| `internal/auth/mfa/service` | 26 | 14 | Login, enrollment, management, recovery, delivery и разные факторы требуют проверки самостоятельности |
| `internal/auth/mfa/transport/http` | 33 | 2 | Много самостоятельных ручек; число файлов само по себе не повод сливать их |

Крупнейшие рабочие файлы: router.go240 строк, project_profile.go204, realm.go196. Значит основной источник неудобства — широта пакетов, распределение тестов и неочевидные связи, а не многотысячные рабочие файлы.

Конкретные смешения:

- `app/auth/project_http_browser.go`: в одном файле wrappers verification, password reauthentication/recovery, MFA и temporary password. Переместить рядом с уже существующей сборкой соответствующего сценария, не создавать helper-пакет на каждый wrapper.
- `app/auth/project_profile.go`: feature config, dependencies, собранный profile и current-policy проверки. Различить данные сборки и проверку актуальности; не экспортировать весь внутренний граф.
- `app/auth/realm.go`: большая сборка standalone; отделить её от платформенного и project-профилей через явные границы сборки, а не ещё десяток префиксов в той же папке.
- `app/auth/project_telegram_settings.go`: преимущественно runtime adapter — lease + сборка сервиса + вызов. Это не доказательство бизнес-логики в app. Сохранять проверенную границу trusted origin/readiness и владение lease, сокращать только подтверждённое дублирование.
- `platform/project/repository/postgres`: role/assignment/policy admission, execution и receipt — разные административные сценарии поверх общих authority/transaction guarantees. Не переносить отдельно каждый SQL-файл без зависимостей и владельца транзакции.

Это структурный анализ, не завершённый security review всех функций и не новые измерения производительности.

## 1. Расположение тестов

Go допускает отдельную подпапку `tests`, но это другой import path и пакет. Одинаковое `package service` в двух папках не объединяет их. Суффикс `service_test` в прежней папке создаёт black-box test package, но не убирает файл из дерева. `testdata` предназначен для данных; Go не обходит его как обычный пакет тестов.

Предлагаемая политика:

- Тесты сценариев работающего стенда — в `sandbox/tests/<фича>`. Межфичевые проверки получают место по владельцу сценария: например, изоляция двух проектов — projects. Сам по себе SQL или Redis не является причиной переноса в sandbox.
- Локальные black-box tests фичи можно держать в `tests/` внутри этой фичи/слоя, если они используют его публичный контракт и не требуют чужих fixtures.
- Пользователь предпочитает локальные подпапки tests: для тестов публичных сценариев это основной кандидат, включая unit-тесты через моки интерфейсов. Unit-тесты, которым обоснованно нужны закрытые детали, остаются рядом с владельцем. Не экспортировать внутренности, не применять unsafe/linkname и не писать production wrappers только для их переноса.
- Общий test support появляется только при реальном повторном использовании. Фичевые fixtures остаются с соответствующим suite; не строим универсальный testing framework.
- Переносить test functions, assertions, fixtures, cleanup и opt-in условия одним связным блоком. Учесть relative SQL paths, embedded fixtures, package working directory, coverage packages и CI/Luna команды.

Пример целевых мест, не обязательный набор создаваемых папок:

```text
auth/methods/password/service/
├── login.go
├── credentials_test.go     # если проверяет обоснованно закрытые детали
└── tests/
    └── login_test.go        # публичный сценарий через интерфейсные моки

auth/methods/password/repository/postgres/
├── repository.go
├── credentials.go
└── tests/                  # автономные black-box repository tests, если нужны

sandbox/tests/
├── session/                # сценарии входа и отзыва через API
├── mfa/                    # второй фактор и восстановление на стенде
└── projects/               # создание, управление и изоляция проектов
```

Обычный `go test ./...` обходит tests-подпакеты, а `go test ./path/service` проверяет только указанный пакет и их не подхватывает: targeted команды обновить на соответствующие package patterns. Coverage вынесенных tests нужно настроить на production packages через coverpkg, иначе отчёт будет неполным. Не создавать для tests второй go.mod. В `tests` допустимы только *_test.go файлы и собственные test fixtures; это не отдельный сервер.

Конкретные кандидаты после read-only проверки:

| Текущие tests | Место / условие |
| --- | --- |
| password/service/authenticate_test.go, public_policy_test.go | service/tests: публичные Authenticate/Login/Register/WithPublicPolicy; перенести собственные test mocks, production API не менять |
| mfa/service/telegram_factor_test.go, telegram_preparation_test.go | service/tests: публичные конструкторы/методы через interface stubs; fixtures перемещаются вместе |
| password/service/credentials_test.go | публичные сценарии можно вынести; direct parseCredentials test оставить рядом с private parser |
| mfa/service/native_login_test.go | читает login.cipher; перед переносом оценить black-box проверку через injected test cipher и наблюдаемые repo stub arguments, поле не экспортировать |

Подпапки tests внутри текущего модуля могут импортировать его internal-пакеты в пределах разрешённого родителя. Отдельный модуль/репозиторий тестов не вводится. Утверждение «все unit-тесты обязаны лежать рядом» не принимаем: это обычная Go-конвенция, но пользовательская структура с локальными tests технически корректна для black-box сценариев.

Тесты не включаются в обычную сборку приложения; перенос не ускоряет сам сервис. Его польза — навигация, ясное владение suite и независимая подготовка стендов.

## 2. Назначение cmd

В проекте4 executable-команды, а не отдельный сервер на каждый файл:

| Команда | Зачем нужна | Решение |
| --- | --- | --- |
| `auth` | HTTP backend, config и signal lifecycle | Оставить тонкой точкой входа |
| `access-catalog` | Проверка/preview каталога permissions | Оставить отдельным эксплуатационным инструментом |
| `admin-recovery` | Аварийный password reset / MFA approval/cancel | Сохранить отдельные credentials, подтверждения и безопасность |
| `project-prepare` | Privileged подготовка отдельных project DB | Сохранить отдельный executor, обычному API DDL-доступ не давать |

Не объединять команды ради меньшего числа папок. Несколько файлов с package main внутри команды — один binary.

Из `project-prepare/main.go` вынести связный application workflow (`run`, `prepareSecrets`) в именованный app-пакет подготовки проекта. В cmd оставить разбор arguments/env, stdio/signals и отображение результата. `parseCommand`, `validateStages`, `connectionConfig` могут оставаться CLI-деталями. Вынесение не должно запускать DDL из обычного API.

Для admin-recovery разделить CLI подтверждение/вывод и существующие password/MFA services; перенос оправдан только если main действительно содержит сценарий сверх CLI boundary. Не создавать новый framework команд и не менять порядок подтверждений. `auth` и `access-catalog` уже близки к тонким entrypoints.

В cmd оставить tests CLI parsing/flags/exit/output и минимальную проверку executable. Для внешних integration suites не импортировать package main: использовать существующие app/service contracts, а при проверке самой команды — её настоящий CLI boundary.

## 2а. Sandbox: окружение и проверки сервиса

Проверен текущий deployment: `deploy/compose.sandbox.yml` запускает тот же cmd/auth через Dockerfile.prod с synthetic configuration, отдельными PostgreSQL/Redis/Mailpit и HTTPS на loopback. Это не вторая реализация backend и не runtime-пакет приложения. Команды запуска/остановки и opt-in acceptance/load находятся в Taskfile. `deploy/sandbox` содержит28 файлов tests/fixtures, то есть конфигурация окружения и проверочные сценарии сейчас смешаны по назначению каталога.

Стенд не требуется для обычной работы Auth, но нужен как воспроизводимое окружение сквозных HTTPS/JWT/session/roles/email/recovery/rotation и ресурсных проверок. Сохранить назначение и изоляцию; каждую полезную гарантию проверять на основном backend, не копировать его логику в test implementation. Не запускать тяжёлые сценарии при каждом изменении.

Предлагаемое размещение с сохранением имени sandbox:

```text
sandbox/
├── README.md            # назначение, запуск, проверки и ограничения
├── compose.yml          # тестовое окружение обычного Auth
├── config/              # необходимые настройки стенда
└── tests/
    ├── session/         # вход, сессии и отзыв
    ├── mfa/             # второй фактор и восстановление
    ├── projects/        # проекты и изоляция
    ├── access/          # роли и разрешения
    └── load/            # отдельный запуск нагрузочных сценариев
tmp/sandbox/             # временные сертификаты, ключи и результаты, ignored
```

Это пример размещения существующих сценариев, не список пустых пакетов для создания. Название конкретной группы определяется её содержимым. Fixtures находятся в testdata своего suite. Общие помощники выделяются только при реальном повторном использовании. Тесты отдельного repository со своей тестовой БД могут оставаться в repository/postgres/tests; им не нужен весь запущенный Auth.

Sandbox запускает обычные API Auth с настоящими отдельными PostgreSQL/Redis и Mailpit, который принимает тестовые письма локально. Собственных бизнес-ручек или второго backend здесь нет. Приложение пишет в тестовую БД через свои обычные repositories. Это окружение для ручной и автоматической проверки; его постоянная работа не обязательна. Наличие Mailpit не подтверждает работу внешнего SMTP.

Не отдельный репозиторий/модуль/сервис. Использовать существующий production Dockerfile и source binary; при использовании Compose override сохранить один источник общей конфигурации. Чистить только owned fixtures. Сохранить opt-in, local-only bindings, synthetic credentials и safety guards при переносе. SQL/JWT fixtures разделять по потребителям; не терять cross-suite helpers и не создавать глобальный testkit без необходимости. Source000001 и production grants не дублировать. Устаревшие/повторяющиеся fixtures удалять только после подтверждения эквивалентного актуального покрытия, не ради числа файлов.

Во время реализации обновить Taskfile paths, mounts, build contexts, test selections, ignored paths и operations docs; сохранить понятные sandbox:up/down и отдельный запуск тяжёлых проверок. Проверить, что final image содержит приложение без тестовых артефактов. Не добавлять shell scripts или зависимости ради переноса. Сам перенос не экономит токены: экономию дают целевое чтение, достаточные проверки и устранение подтверждённых дублей. Sandbox container status и новые прогоны на этапе анализа не проверялись; это не новая acceptance/performance аттестация.

## 3. Границы application assembly

Главный приоритет — `internal/app/auth`, а не повсеместное дробление domain/service.

Согласованное целевое размещение:

```text
internal/app/
├── app.go                 # общие ресурсы и сборка приложения
├── run.go                 # жизненный цикл
├── auth/                  # сборка Auth-сервисов
├── admin/                 # сборка общей панели управления
└── projects/              # подключение Auth выбранного проекта
internal/admin/
├── administrators/        # владельцы и администраторы всей системы
└── projects/              # каталог и управление проектами
```

App/admin соединяет реализации, internal/admin содержит поведение. Проектный администратор остаётся пользователем своего проекта с ролями Access. Он не становится администратором всей системы. Существующие административные bridge и SQL-authority протоколы сохраняются, новая реализация не создаётся.

App/projects получает доверенный контекст, настройки и ограниченные подключения выбранного проекта, связывает обычные Auth-сервисы. Не создавать полный App на каждый запрос или глобальный current project. Разобрать внутри построение профиля, HTTP bindings и scoped adapters; простое перемещение всех project_* в новую папку недостаточно. Подпакеты выделять по самостоятельным контрактам, без общего склада helpers.

Config и HTTP server/shutdown остаются самостоятельными. Workflow project-prepare извлекается только при подтверждённой необходимости; его окончательное место определяется в R1 по владельцу операции, а не ради ещё одного сборочного пакета. Сохраняются четыре команды cmd и разделение credentials/privileges.

До переноса проверить import graph. Пакеты сборки не должны требовать импорта корневого App обратно; передавать узкие зависимости владельцам. Не заводить app/common и не экспортировать весь граф для устранения циклов. Если невозможно выделить пакет без массового экспорта полей, сначала упростить контракт. Config и HTTP server/shutdown остаются в своих текущих отдельных пакетах.

В app оставляем сборку, lease/lifecycle, выбор доверенного project context и связывание сервисов. Повторяющийся scoped adapter не заменять универсальным callback-контейнером без доказанной пользы.

## 3а. Бизнес-правила и repository

Domain определяет допустимые состояния/переходы и чистые правила; service координирует use case и применяет эти правила. Repository читает/сохраняет данные, отображает SQL errors и реализует атомарные persistence operations. Он не выбирает продуктовую политику самостоятельно.

Подтверждённые кандидаты:

- `mfa/repository/postgres/selection.go: SelectMFAMethod`: помимо SQL lookup содержит приоритет TOTP/email/Telegram, влияние preference/admin/primary и отказ fallback. Возвращать согласованное состояние selection, решение принимать в domain/service; повторные SQL current guards перед issuance сохраняются. Не заменять один lookup на N+1 queries.
- `mfa/repository/postgres/management.go: Disable`: ветвления required/available/admin определяют допустимость удаления TOTP. Чистое правило отделить от загрузки/locks и DELETE; service должен вызывать его на актуальном состоянии внутри одной транзакционной границы, а не до её открытия.

Безопасный порядок: service открывает сценарную transaction scope через узкий persistence port → repository блокирует/читает текущие строки → domain правило проверяет полученное состояние → repository применяет mutation/revoke/audit → общий commit. Точная форма порта определяется по существующему transaction owner; не вводить универсальный UnitOfWork framework на весь проект.

SQL constraints, unique keys, CAS/auth_version, permission/current-state checks и locks остаются защитой целостности и конкурентного исполнения. Не удалять их под лозунгом «в repository только CRUD». Условный UPDATE/DELETE или SQL proof guard может быть необходим для гарантии, которую проверка до запроса не обеспечивает. При ревью отмечать отдельно определение бизнес-правила и способ атомарно обеспечить его в storage.

Для каждого переноса фиксировать прежнюю гарантию, новый владелец правила, transaction boundary и число SQL/Redis round trips. Сначала исправить подтверждённые примеры, затем распространять подход только на аналогичные найденные случаи.

## 4. Границы развитых фич

Разбирать по реальным сценариям, не применять одинаковую матрицу ко всем папкам:

Большой пакет из десятков маленьких файлов не считается решением. При нескольких самостоятельных группах сценариев с разными зависимостями, правилами и тестами нужно выделить логические подфичи. В R1 назвать их владельцев, публичные контракты и общие транзакции; при переносе сохранить эти границы. Развитая подфича получает необходимые domain/service/repository/transport, небольшая — только нужные пакеты. Не устанавливать лимит количества файлов и не создавать подпакет на каждую ручку. Если выделение требует циклов, массового экспорта private fields или разделения единой security-транзакции, сначала переработать контракт, а не механически двигать файлы.

- MFA: отдельно оценить login coordination, enrollment/management, recovery и security delivery; factor-specific Telegram/email реализацию держать обозримой. Перенос в подпакеты допустим при самостоятельных контракте/владельце; общую транзакцию issuance/consume не разрывать.
- Project: отделить административные сценарии ролей/назначений/policy от catalog/provisioning/runtime, если import/transaction анализ подтвердит границы. Каждая выделенная развитая подфича сохраняет свои service/repository/transport, вместо общего каталога PostgreSQL всех фич.
- Account: сохранить согласованное владение user/profile/email/linked identities; не вводить ранее отвергнутые contact/identity/authentication модули ради количества файлов. Проверить provision/invitation/email lifecycle и общие helpers по самостоятельности сценариев.
- Не объединять все HTTP-ручки в один handler.go. Самостоятельная ручка остаётся файлом сценария с DTO/Swagger. Constructor/errors/shared response — рядом, только действительно общие.
- Не переносить input/result в domain ради слова «struct»: они описывают application scenario, а domain — предметные состояния/правила.
- Маленькие файлы с одной необходимой обязанностью не мусор. Объединять только фрагменты одной операции, которые сейчас заставляют прыгать между файлами без пользы.

## 5. Документация как часть каждого этапа

| Документ | Что фиксировать |
| --- | --- |
| architecture.md | Целевые границы, обязанности, зависимости, тесты, sandbox и правила разделения пакетов |
| ai/index.md | Фактические пути после переноса; целевые имена не выдавать за уже существующие |
| features и api/contract.md | Владельцы сценариев и реальные ссылки, гарантии, ошибки и ограничения; публичный API без скрытых изменений |
| operations/local-sandbox.md и будущий sandbox/README.md | Назначение, prerequisites, запуск/остановка, Mailpit, тестовые данные, группы проверок, безопасная очистка |
| Operations-документы команд | Что делают четыре cmd, privileges/credentials, подтверждения, примеры и последствия выполнения |
| Taskfile/CI и процесс Luna | Новые package patterns, fixtures, opt-in и coverage, достаточный набор проверок |
| current-task/implementation | Текущий этап, завершённые переносы и следующий шаг |
| history/acceptance | Evidence проверок и незакрытые gates |

Документировать рядом с изменением, а не после всего рефакторинга. Не создавать параллельные каталоги статусов и README/doc.go на каждый файл. До переноса в R1 достаточно карты владельцев и контрактов в этом плане; команды будущего расположения не представлять как уже работающие. После переноса обновлять реальные инструкции и ссылки в том же рабочем блоке.

## R1: карта переносов и контрактов — 2 ноября 2026

База анализа: 58714c1; поверх неё только незакоммиченные Markdown-правки. Это карта для реализации, а не выполненный перенос или доказательство компиляции целевого дерева. Использованы Serena symbols/bodies, целевое чтение SQL/lifecycle и ограниченное read-only исследование помощника. Новых endpoints, CRUD администраторов, workers или зависимостей не требуется.

### Сборка, команды и инфраструктура

| Существующий источник | Целевой владелец / правило | Контракт и сохраняемая гарантия |
| --- | --- | --- |
| app/auth/app.go: New, standalone; run.go: App, resources | internal/app/app.go и run.go | Root создаёт SQL/Redis/hash ресурсы, выбирает сборку, владеет cleanup; одна регистрация каждого close |
| app/auth/realm.go, realm_security.go, password.go, account.go, mfa.go, token*.go, native_token.go, email_otp.go, google.go, telegram.go, oidc.go, settings.go, smtp.go, provider_settings.go | app/auth, по владельцам сборки фич | Существующая сборка Auth и её feature adapters; domain/service не импортируют app |
| app/auth/operator.go, operator_mfa_settings.go | app/admin | Существующий вход общей панели, policy и административные маршруты; не новый administrators CRUD |
| app/auth/project_runtime.go | app/projects/runtime | Создание/владение registry и private reader; это сборка, реестр остаётся в admin/projects/runtime |
| app/auth/project_profile*.go, project_auth_source.go, project_auth_manifest.go, project_settings_readiness.go | app/projects/profile | BuildProjectProfile, конфигурация, snapshots и CheckCurrent; конфигурация сборки отделена от authority текущего состояния |
| app/auth/project_http*.go | app/projects/browser; token/native bindings — app/projects/native | Только HTTP bindings с существующими feature handlers; mixed project_http_browser.go разбирается по сценариям, не переносится монолитом |
| app/auth/project_token*.go, project_auth_tokens.go | app/projects/native | JWT/native configuration, issuance/introspection и связывание готовых сервисов; signing не переносится в app |
| app/auth/project_delivery.go, project_smtp.go, project_email_runtime.go | app/projects/delivery | Доставка, использование lease и текущего SMTP; общий bounded worker/client ownership сохраняется |
| project_password*/registration/email_otp/oidc*, account/email/invitation/provisioning*, access/roles/users*, mfa/telegram*, settings* adapters | app/projects/{methods,account,access,mfa,settings} по обслуживаемой фиче | Связанные операции в своём пакете; profile не становится складом wrappers. Token/native, delivery и общий runtime определены отдельными строками выше |
| cmd/auth/main.go | cmd/auth → internal/app.New/Run | Сигналы/запуск остаются CLI, server/http получает готовый handler |
| cmd/access-catalog | тот же cmd + существующие access/settings | Проверка/preview; не новый механизм назначения ролей |
| cmd/project-prepare | CLI остаётся; связный workflow принадлежит admin/projects/preparation | Privileged SQL выполняется только отдельной командой. parseCommand/validateStages/connectionConfig — CLI, не library API |
| cmd/admin-recovery | CLI + существующие password/MFA/recovery authority | Сохраняются подтверждения, отдельные credentials и CheckRecovery; не включать privileged port в обычный HTTP runtime |

Разделение project assembly требует исправления private coupling: ProjectProfile сейчас хранит private password/email/MFA/token dependencies. Browser/native/delivery используют узкие scenario-facing interfaces; profile не импортирует adapters обратно. Profile хранит нужные контракты операций вместо concrete native/browser adapters; общая сборка app/projects соединяет реализации. Не переносить текущие ProjectProfileConfig/Dependencies буквально, если это создаёт обратные imports. Общие неизменяемые config/proof/domain types принадлежат владельцам, не новому app/common. Существующий shared Bot client/hash budget/SMTP gate передаётся в сборку, не создаётся в каждом подпакете.

Допустимые направления: root app → app/auth, app/admin, app/projects; app/projects/{browser,native,delivery} → узкие контракты profile/фич; profile → сервисы фич и admin/projects/runtime. Ни один дочерний сборочный пакет не импортирует root app. Конкретные имена новых exported methods задаются при переносе; они не объявляются существующим API. Если контракт потребует массового экспорта графа или циклов, изменить границу до механического переноса, не делать временный framework.

### Общая панель и проекты

| Источник | Целевое место | Callers / граница |
| --- | --- | --- |
| platform/operator/domain | admin/administrators/domain | Principal, Permission, RealmID, OwnerPermissions; используют project HTTP/service, config/platform.go, router/operator.go |
| platform/operator/repository/postgres | admin/administrators/repository/postgres | AuthorizeRead/AuthorizeMutation, CheckRuntime/CheckRecovery, MFA policy/setup; caller admin-recovery/realm.go сохраняется |
| platform/project/domain | admin/projects/domain | Общие Project, receipts, authority targets; не копировать в подфичи |
| project/service catalog.go, create/list/read/state сценарии + их repository/HTTP | admin/projects/{service,repository/postgres,transport/http} | Catalog, Repository, ReadAuthority, RuntimeObserver; узкий каталог и состояния остаются корневой фичей |
| project service/repository/HTTP users и roles directory | admin/projects/directory/{service,repository/postgres,transport/http} | Чтение проектных пользователей/ролей через DirectoryTarget, без собственного account/access storage |
| project service/repository/HTTP role creation/assignment/admission/outcomes | admin/projects/roles/{service,repository/postgres,transport/http} | Протокол intent/admission/project receipt/catalog outcome; целые authority/tx operations переходят вместе |
| project service/repository/HTTP auth policy | admin/projects/policy/{service,repository/postgres,transport/http} | Управление policy выбранного проекта, guards/readiness; не дубль auth/settings |
| project preparation/onboarding/schema/secrets coordination | admin/projects/preparation с необходимыми service/repository частями | Catalog reservation/target/identity/readiness и CLI orchestration, без HTTP DDL |
| project/runtime, credentials, storage/postgres | admin/projects/runtime, credentials, storage/postgres | Registry.Use/Invalidate/Close; шифрование с прежними scopes; подготовка физической БД отдельными credentials |

Authority Principal/Permission/RealmID остаются в administrators/domain. Не добавлять service/transport только ради симметрии: текущий operator — authority/setup, а не готовый CRUD администраторов. Подфичи зависят от общих project domain contracts; каталог не импортирует роли/directory/policy. Общий transaction helper остаётся у подтверждённого владельца конкретной операции, не в глобальном postgres всех фич.

### Auth: подфичи и бизнес-правила

| Область | Разделение и интерфейсы | Что не разрываем |
| --- | --- | --- |
| mfa/service selector.go; repository/postgres/selection.go | domain задаёт чистое решение; service применяет snapshot из repository и вызывает FactorStarter | Один lookup актуального user/auth_version/factors/preferences; перед issuance сохраняются current SQL guards, fail-closed при недоступном предпочтении |
| mfa/service/management.go; repository/postgres/management.go Disable | domain правило допустимости; service координирует узкий transaction-scoped port | LockAccessChanges → requireProof/fresh MFA → locked current state → правило → delete/preference/invalidate/audit → commit |
| MFA login/primary/native coordination | mfa/login/{service,transport/http} по нужным частям; чистые общие модели остаются mfa/domain | Единственное создание/погашение challenge и общая session/token authority |
| MFA enrollment/step-up/management | mfa/management/{service,transport/http}, существующие factor implementations у владельцев | Proof freshness, last-factor/admin и отзыв; общий repository tx не дробится на независимые commits |
| MFA recovery/operator decisions | mfa/recovery/{service,repository/postgres,transport/http} | Отдельные recovery intent/approval/consume и ограничения, не fallback из login |
| MFA Telegram channel и notification delivery | mfa/telegram для управления каналом; mfa/delivery для security notifications, только нужные пакеты | Binding/settings version, delivered-before-consume, bounded Bot client; не второй Telegram login |
| account user/profile/directory/status/deletion | корневые account domain/service/repository/HTTP; directory tests у владельца | UUID/status/deleted/auth_version и пользовательская authority |
| account invitation/provision/reissue/setup | account/provisioning и account/setup по самостоятельным сценариям | Atomic account/credential/idempotency, initial-admin uniqueness и setup authority; не новая duplicate registration |
| account verification/binding/change/report | account/email/{service,repository/postgres,transport/http} | Email lifecycle и outbox; protected password recovery связывается с существующим password service узким портом |
| account identity resolution/management | остаётся у account, смысловые файлы | issuer+subject, explicit linking и last-method; отдельные contact/identity/authentication модули не вводятся |
| password/emailotp/google/telegram/session/token/settings/access/audit | существующие feature owners; новые подфичи только при подтверждённом смешении | Перемещать локальные tests с владельцем, уже связные операции не переписывать |

Это конечные логические области, но не приказ создать все слои и новые repository constructors. Операции общих locks/issuance, которые неразрывно используют private tx helpers, сначала сохраняют единый storage owner. Извлечение отдельной transaction operation допускается только вместе со всеми её guards и callers.

### Матрица тестов и fixtures

| Текущая группа | Окончательный владелец | Правило переноса |
| --- | --- | --- |
| deploy/sandbox acceptance/JWT/rotation/lifecycle/security/admin | sandbox/tests/{session,token,access,projects,security} по сценарию | Внешний работающий HTTPS Auth; fixtures и shared client переносятся вместе, не обязательно одна папка на каждый сценарий |
| deploy/sandbox load_*, cleanup observation и scheduler diagnostics | sandbox/tests/load либо sandbox/tests/cleanup для обычной retention acceptance | Длительные/ресурсные сценарии отдельно opt-in; быстрые проверки percentile/scheduler не запускают load автоматически |
| cmd/project-prepare TestTwoProject* и общие project_* fixture/helpers | internal/app/projects/tests | Self-managed два проекта, SQL/Redis/HTTP, единый fixture lifecycle. Это tests сборки, не требование постоянно работающего sandbox |
| cmd/project-prepare TestPrepareCommandSQL и его private CLI helpers | cmd/project-prepare, пока проверяется сама команда | Не импортировать package main. Если сценарий переезжает в preparation workflow, проверить его публичный контракт и оставить CLI assertions в cmd |
| cmd project flags/connection/validation tests | прежний cmd рядом с private CLI code | Не экспортировать parseCommand только ради папки tests |
| password repository TestPostgresSchema и все его check* callbacks/fixture | internal/app/auth/tests/schema | Сохранить cross-feature root/subtest names и его жизненный цикл целиком; не разносить callbacks между пакетами и не терять общий migration setup |
| Самостоятельные password repository schema roots MFA/settings/access/account/token | tests соответствующего конечного владельца; cross-feature целостный root — app/auth/tests/schema | При необходимости shared fixture выделяется только для фактических потребителей; сначала owner map, затем проверяемый перенос dependency closure |
| password repository errors_test.go TestRegistrationError | остаётся рядом с private error mapper | Обоснованный private test, не менять production export |
| Локальные service/domain/HTTP/repository tests | конечный пакет владельца/tests | Публичные сценарии через порты, own mocks и testdata; private tests остаются рядом без unsafe/wrappers |
| app/auth profile/runtime/HTTP tests | app/projects/{profile,browser,native,delivery}/tests по владельцу; межкомпонентный root — app/projects/tests | Не перемещать каждый helper самостоятельно; сохранить current profile/version/lease fault checks |

Список test roots снимается из исходников перед переносом группы и сравнивается после; fixture closure включает непубличные check* и helpers без собственного Test*. Не считать все131 password repository files парольной логикой и все122 cmd files проверками CLI. TestPostgresSchema уже смешивает MFA/access/JWT/email/session/account; его сохранение как явного assembly suite предотвращает переписывание всего тестового набора ради каталогов.

Для service tests подтверждённые исключения: password credentials_test.go обращается к parseCredentials — private часть остаётся рядом; MFA native_login_test.go читает login.cipher — использовать наблюдаемый результат injected cipher либо оставить узкий private тест, поле не экспортировать. Authenticate/public policy и Telegram factor/preparation tests могут идти в tests с собственными mocks.

### Порядок, риски и достаточные проверки

1. R2 перемещает только существующий внешний sandbox с его fixtures/Taskfile. Actual multi-project suites не переносить в этот стенд ради одинаковых имён.
2. R3 сначала переносит authority domain и project domain contracts с callers/config/router, затем связанные repositories/services/handlers/CLI по подфичам. Не менять persisted realm IDs, SQL schema/table names, permission strings, ENV, routes или crypto scopes при замене Go import paths.
3. R4 выполняет механическую организацию MFA отдельно от изменения selection/Disable портов. SQL proof/version/lock/audit guards сохраняются; policy не выносится до открытия транзакции.
4. R5 account/методы входа; R6 session/token/access/settings; каждая фича обновляет callers и необходимую сборку сразу. Root schema suite остаётся одним потребителем окончательных контрактов.
5. R7 завершает root app и project adapter boundaries; до R7 не нужны временные alias-пакеты. Зависимость, которую невозможно перенести атомарно без цикла, включает её callers в тот же минимальный шаг по R1.

Подтверждённые риски: private ProjectProfile graph; reverse-order idempotent resources.close; worker cancel/join до закрытия зависимостей; CLI relative paths и opt-in ENV; migration umbrella helpers; catalog/project две БД не становятся одной транзакцией; MFA guards не равны лишней валидации. Это риски переноса, не доказанные новые уязвимости.

Luna: R2 — task check плюс actual затронутые sandbox roots; R3 — task check/race authority/runtime/preparation и affected TestTwoProject*/TestPrepareCommandSQL; R4 — task check/race MFA и actual MFA schema/login/recovery/two-project roots; R5/R6 — task check и затронутые feature schema/API/race roots; R7 — task check/lifecycle/profile/runtime и representative multi-project HTTP; R8 сводит evidence, не повторяет всё без причины. Coverage на production packages, ни один root/subtest не теряется. Проверяемые фактические имена команд сохраняются в передаче Luna по существующему Taskfile/исходникам, новые CLI flags не изобретаются.

R1 выполнен как статическая карта: исполняемые проверки не запускались и целевой import graph ещё не существует в коде. Конкретный перенос закрывается только после проверки его результата Luna. Не трактовать эту запись как security PASS или готовность всей архитектуры.

## Небольшие рабочие блоки

Согласованная рабочая разбивка — 8 блоков по владельцам и фичам. Это единственный порядок выполнения рефакторинга. Каждый блок включает относящиеся к нему tests, fixtures, callers, сборку и документацию. Самостоятельного массового переноса всех tests перед изменением их владельцев не делаем.

### R1. Окончательная карта переносов и контрактов

- [x] Записать «старый путь → окончательный владелец → imports/callers → контракт → транзакции/ресурсы → проверки» для app/cmd/admin и широких фич.
- [x] Определить логические подфичи, shared dependencies и закрытые символы. Проверить направление imports и способ сохранения единой security-транзакции до переноса.
- [x] Назначить окончательное место каждому suite вместе с fixtures: локальные tests владельца либо sandbox/tests для сценария работающего сервиса.
- [x] Отделить механическое перемещение от изменения бизнес-правил. Зафиксировать конкретные известные риски и security prerequisites; найденные уязвимости не оставлять до финального R8.
- [x] Установить порядок по зависимостям: блок не должен нуждаться в неопределённом контракте из будущего блока. Для большого связного переноса выбрать безопасные шаги внутри блока.

Результат: одна конечная карта и достаточные проверки, без реализации и повторного исследования всего проекта. После разрешения реализации карта используется как маршрут, а не повод заново проектировать архитектуру в каждом блоке.

### R2. Sandbox и проверки работающего сервиса

2 ноября: перенос реализован, gate приёмки Luna открыт. Общие HTTPS/login/Mailpit/deployment helpers находятся в sandbox/internal/testsupport, используемый cleanup/load engine — sandbox/internal/loadtest. Test-функции находятся в feature suites; fixtures переходят вместе с владельцем. Новые API backend, зависимости и test wrappers не добавлялись. Gofmt выполнен; полный formatter в основном окружении недоступен из-за DNS proxy.golang.org, проверка результата — Luna.

- [ ] Собрать существующие Compose/config и связанные проверки в корневом sandbox; сохранить обычный backend, production Dockerfile и один источник schema/grants.
- [ ] Разместить существующие сквозные suites по фичам, fixtures — с их потребителями, временные артефакты — tmp/sandbox. Не переносить сюда автономные package tests.
- [ ] Обновить mounts/build contexts/Taskfile/ignored paths и инструкции up/down, Mailpit, opt-in проверок и cleanup. Сохранить synthetic credentials, loopback ports и собственные ресурсы.
- [ ] Сверить список сценариев до/после, условия запуска и достаточные проверки стенда. Не запускать load/длительные прогоны ради перемещения файлов.

Результат: отдельный понятный стенд и проверенные команды без изменения Auth-поведения. Реализацию фич и их локальные tests этот блок не реорганизует.

### R3. Общая панель, проекты и эксплуатационные команды

- [x] Упорядочить migrations по разделу «Миграции и подготовка БД» ниже: auth/admin SQL, понятный embed loader, тесты по владельцам и все пути загрузки. Это часть R3, не новый функциональный этап.
- [x] Перенести существующие operator-сценарии в admin/administrators, project-сценарии — в admin/projects; сборку общей панели связать через app/admin.
- [x] Разделить подтверждённые самостоятельные группы каталога/состояний, подготовки БД/credentials и административных операций. Не воспроизводить один широкий project-пакет под новым именем.
- [x] Сохранить runtime registry/pools/leases, SQL authority, admission/receipts и межбазовую изоляцию. Минимально обновить затронутую сборку/callers без переписывания протоколов.
- [x] Оставить четыре понятные cmd. Извлечь только необходимый workflow project-prepare/admin-recovery по карте R1; сохранить CLI flags/exit/output/подтверждения и отдельные credentials/privileges.
- [x] Перенести принадлежащие этим сценариям tests/fixtures, включая ошибочно расположенные в cmd и password repository. Обновить actual package patterns, coverage и operations docs.

Результат: понятное управление системой/проектами, отдельная privileged подготовка БД и проверки у окончательных владельцев. Это единый блок фич с последовательными проверяемыми шагами, а не один массовый непроверенный diff.

#### Миграции и подготовка БД

Одна общая управляющая БД содержит каталог проектов, администраторов системы, их полномочия и общую конфигурацию управления. Для каждого проекта создаётся отдельная БД с пользователями, identities, credentials, sessions, roles/permissions, MFA, audit и проектными настройками. Это разные БД; их SQL-схемы могут иметь одинаковое имя auth, не смешивая данные.

Целевое размещение исходников:

```text
migrations/
├── auth/
│   ├── 000001_init.up.sql
│   ├── 000001_init.down.sql
│   └── schema.go                 # только embed SQL, версия и получение содержимого
├── admin/
│   ├── 000001_catalog.up.sql
│   ├── 000001_catalog.down.sql
│   ├── 000002_operators.up.sql
│   └── 000002_operators.down.sql
└── tests/                        # непосредственные проверки up/down и схемы
```

- Основная Auth-схема устанавливается в каждой проектной БД; общая управляющая БД также использует её для входа администраторов. Admin-набор добавляет только управляющие таблицы в общей БД. Независимые последовательности миграций не объединять; номера/порядок сохраняются.
- migrations/auth.go становится migrations/auth/schema.go с прежним смыслом go:embed. Это не бизнес-логика и не отдельная копия SQL: executor project-prepare использует тот же файл схемы, встроенный в сборку. Пустые loaders для admin не добавлять, если нет реального потребителя.
- migrations/platform SQL переходит в migrations/admin. SQL-схема platform, имена таблиц, persisted identifiers и permission strings при этом не меняются. Не добавлять миграцию переименования объектов БД ради Go-каталогов.
- Логику установленной project identity/checksum из migrations/project_identity.go отнести к техническому владельцу проверки проектной схемы admin/projects/storage/postgres, с учётом всех callers. Сохранить байты формулы checksum, SQL view и crypto scopes. Если перенос создаёт цикл, сначала уточнить узкий контракт, не копировать вычисление.
- Тесты catalog/operator authority/role operations/MFA/setup из migrations/platform распределить по настоящим владельцам admin/projects, admin/administrators и связанным фичам вместе с fixtures. Только проверки применения/отката схемы остаются migrations/tests; текущие cross-feature roots не дробить произвольно.
- Обновить go:embed/imports, migrate CLI paths и Compose mounts, schema loader/checksum callers, SQL fixtures и относительные пути, Taskfile/CI/Luna selections, operations и карту проекта. Обычный migrate после переноса должен читать auth-набор, подготовка общей БД — отдельный admin-набор. Не применять оба набора к каждой проектной БД.
- Сравнить исходный SQL/версии/checksum до и после: перемещение файлов само по себе не должно менять устанавливаемую схему. Luna проверяет task check, прямые up/down и существующие authority/setup/preparation/project identity suites на своём disposable стенде. Рабочие БД не переименовывать и не сбрасывать.

2 ноября: реализация R3 охватила весь согласованный scope и принята Luna на V7: task check, race, API и семь SQL roots PASS. Namespaces platform/operator/project перенесены в admin/administrators/projects. Roles/directory/policy имеют свои service/repository adapters/HTTP, preparation — собственный workflow и CLI transport, runtime reader — отдельный repository, SQL attestation — schema/postgres. Корневой repository сохраняет shared authority/admission/receipt transaction closure; новая абстракция UoW не добавлена. App/admin собирает handlers; окончательная root/Auth assembly остаётся R7. Cmd/project-prepare — signal/exit entrypoint, его общий SQL/HTTP fixture suite перенесён в app/projects/tests. Public role/directory/domain tests — локальные tests; private policy response/cursor tests остаются рядом без экспорта деталей. SQL auth/admin и loader перенесены без изменения содержимого. Новых функций Auth, endpoints, зависимостей и workers нет.

Причина прежних V1 ошибок — HBA hostssl trust и схема подключения проверочного runtime, подтверждено на base6429cde. На исправленном disposable SCRAM TCP+Unix socket/Redis стенде весь TestPrepareCommandSQL PASS без изменения assertions. Последующие compile/lint diagnostics исправлены без ослабления architecture tests и assertions. Workflow подготовки с concrete adapters находится в app/projects/preparation; общий identity/checksum — admin/projects/schema, чтобы не создавать цикл imports. Итоговая приёмка V7 и оставшиеся gates записаны в acceptance-summary.

### R4. MFA целиком

- [x] Разделить подтверждённые группы login, enrollment/management, recovery и delivery по логике и зависимости, с собственными нужными слоями.
- [x] Перенести чистое решение выбора метода из repository в domain/service, сохранив SQL snapshot, preference/admin/primary policy, отказ fallback и число запросов.
- [x] Отделить правило допустимости отключения фактора от persistence; применять его на актуальном locked state в общей transaction scope. Не ослаблять last-factor/admin/revoke/audit.
- [x] Обновить MFA adapters/HTTP bindings вместе с фичей. Перенести её tests один раз к конечным владельцам, сохранив действующие recovery и project isolation suites.

Результат: правила MFA и работа с данными имеют понятных владельцев, исходные гарантии входа и восстановления сохранены.

3 ноября: R4 реализован и принят Luna на `/private/tmp/auth-r4-mfa-v9-20mfgxxw`, base788940b. Сервисы/HTTP разделены по login/management/recovery/telegram/delivery; общий SQL transaction owner сохранён. Shared contracts/crypto/admission остаются mfa/service без imports подфич. Чистые MethodSelection.Select и CanDisableTOTP находятся в domain; selection использует один прежний SQL lookup, Disable callback вызывается внутри прежних locks/current state. Routes и service contracts подключены явно без umbrella handler. Публичные MFA tests — local tests; private notice payload tests рядом; весь связный cross-feature SQL suite с fixtures из password repository перенесён в app/auth/tests один раз (private registrationError test остаётся). Проектные suites в app/projects/tests сохранены. Конкретный EmailLogin остаётся частью существующего OTP challenge/outbox в methods/emailotp/service: копии или import cycle не добавлены. SQL/schema/API/ENV/dependencies/workers не менялись. Приёмка завершена: V7 full Go tests, V8 lint0/race, V9 targeted tests/lint0/API и все согласованные SQL roots PASS; main сверил source/manifest. Полные evidence и ограничения — в acceptance-summary. Пользователь разрешил main исправлять diagnostics и после явного PASS Luna делать коммит без нового подтверждения.

### R5. Account и методы входа

- [x] Упорядочить согласованные группы user/profile, provisioning/invitations, email lifecycle и linked accounts. Общие account-инварианты не копировать в методы входа.
- [x] Разделить самостоятельные сценарии password, email OTP и внешних входов только там, где подтверждено смешение; сохранить общую session/MFA authority.
- [x] Проверить input/result рядом со сценарием, HTTP DTO/Swagger рядом с ручкой, отсутствие дублирующей предметной валидации и разрозненных error switches.
- [x] Обновить затронутые adapters/HTTP bindings вместе с владельцем. Перенести собственные tests/fixtures, сохранив необходимые private tests рядом и прежние ошибки/приоритет проверок.

Результат: пользовательские сценарии и методы входа читаются в своих областях, между слоями нет подтверждённого лишнего дублирования.

3 ноября: R5 реализован и принят Luna на `/private/tmp/auth-r5-account-password-v4-_34822o1`, base cfa0421. Account email/provisioning/setup и password recovery/provisioning получили собственные service/HTTP; общие domain-инварианты и SQL transaction owners сохранены. User/profile/identity остаются root account, обычный login/register/change/reauth — root password. Provisioning/EmailChange получают limiter/cipher напрямую; Activation — hash/limiter/digest. OIDC/email OTP остаются связными. Публичные tests у владельцев, private cursor/codec/error-table assertions рядом, fixture использует инжектированные cipher/limiter без доступа к private полям. API/schema/routes/ENV/dependencies не менялись.

Приёмка: 35 affected packages под race, pinned lint без замечаний, API reproduction и все 8 exact SQL roots PASS без SKIP/NOT RUN. Main сверил source/manifest и actual SQL RUN/PASS. Ранние ошибки переноса исправлены; fixture-проблемы устранены в стенде. Собственный стенд Luna сохранён для следующего блока, тестовые данные очищены. Evidence и незакрытые внешние/load gates — в acceptance-summary. Следующий блок — R6.

### R6. Сессии, JWT, роли и настройки

- [ ] Применить ту же организацию к session/token/access/settings/audit/delivery и связанным интеграциям — только в подтверждённых проблемных местах.
- [ ] Сохранить feature-local repositories, signing/public verifier boundary, auth/access versions, немедленный отзыв и действующие SQL/Redis guarantees.
- [ ] Разделить широкие группы по самостоятельным контрактам; не переписывать уже связные пакеты и не добавлять Redis repositories/слои/tests ради симметрии дерева.
- [ ] Перенести оставшиеся tests сразу к конечным владельцам; учесть переехавшие ранее cross-feature suites, targeted commands и coverage.
- [ ] Обновить необходимые callers, настройки сборки и профильные документы в этом же блоке.

Результат: оставшиеся общие механизмы и tests приведены к единым правилам, только обоснованные изменения, без новой реализации уже проверенного функционала.

### R7. Завершение сборки приложения и lifecycle

- [ ] После стабилизации контрактов фич завершить root app/app.go/run.go и app/auth/admin/projects. Сначала сверить сделанное в R3–R6; повторно не переносить уже упорядоченные adapters.
- [ ] Упорядочить оставшиеся mixed browser wrappers/profile configuration и scoped adapters. В app оставить только сборку, trusted context, ресурсы и связывание сервисов.
- [ ] Сохранить startup failure cleanup, общий порядок shutdown, bounded pools/hash/Bot budgets и lifetime leases; config и server/http самостоятельны.
- [ ] Удалить только подтверждённые unused/duplicate fragments. Проверить направление imports, отсутствие массового экспорта private fields и необходимость всех новых пакетов.
- [ ] Синхронизировать архитектуру, фактическую карту путей, команды и документацию startup/shutdown.

Результат: понятная итоговая сборка приложения поверх готовых фич. R7 не переопределяет их контракты и не начинает повторный рефакторинг ранее завершённых блоков.

### R8. Сквозное ревью и закрытие рефакторинга

- [ ] Завершить security review sessions/JWT/refresh/revoke, MFA/recovery, roles/admin bridge, project isolation, provisioning/rotation, HTTP/CORS/CSRF/cookies, secrets/errors/logs. Проверки безопасности также идут в R3–R7 по изменениям.
- [ ] Зафиксировать конкретные дефекты и ограничения; дефекты исправлять отдельно от механического переноса с затронутыми regression checks.
- [ ] Сверить SQL/Redis round trips, индексы/locks, bounded inputs/concurrency и pool/client ownership; не выдавать структурный рефакторинг за измеренную capacity.
- [ ] Сверить исходные/новые suites и coverage, согласованность путей/команд/контрактов и документации. Исчезнувший suite не PASS.
- [ ] Свести evidence уже принятых проверок без формального повторения всего набора; закрыть оставшиеся затронутые checks через Luna, отметить NOT RUN.
- [ ] Подготовить краткий итог и передачу в MP7, затем MP8 нагрузка/память/GC. UI требует отдельного предупреждения и согласования.

Результат: рефакторинг принят с явными проверками и оставшимися gates. Новые функции и недоступные внешние проверки не объявляются выполненными.

### Правила выполнения без лишних переносов

1. В R1 фиксируем конечных владельцев и интерфейсы. Порядок R3–R6 уточняется только по обнаруженным зависимостям до правок, без создания временного compatibility framework.
2. Фича, её tests/fixtures и затронутые callers/assembly/docs меняются вместе. Общая сборка получает необходимые изменения сразу, а её оставшаяся структурная уборка выполняется в R7. Так приложение остаётся собираемым, а контракты не переизобретаются.
3. Уже завершённые части не переносим повторно ради номера блока. По R1 сохранить один список владельцев suites; не создавать параллельный процесс массовой сортировки tests.
4. Крупный блок делаем связными проверяемыми шагами по подфичам. Это8 областей работ, а не обещание8 запросов или одного огромного diff на блок. Новые постоянные этапы ради каждого файла не добавляем.
5. Механическое перемещение и изменение бизнес-правил оформляем раздельными изменениями внутри блока, чтобы можно было проверить сохранение поведения. Общая транзакционная гарантия остаётся цельной.
6. Обычный check не наследует opt-in SQL/provider ENV. Общие fixtures и SQL suites не запускаются конкурентно против одной изменяемой схемы.

### Завершение каждого блока

- Документация, фактические пути и команды обновляются вместе с изменением. Current-task хранит конкретный следующий шаг и существенные ограничения.
- Основной агент готовит снимок; существующий отдельный чат Luna выполняет task check и затронутые race/SQL/Redis/API по риску. Основной агент не подменяет это локальными прогонами. Для чистой документации — diff/ссылки/согласованность, без Go/Docker.
- При ошибке повторяются необходимые затронутые проверки. Зависимый шаг не закрывается без явного PASS; полные логи остаются вне основного контекста.
- Итог пользователю краткий: результат, PASS/NOT RUN, ограничения и следующий шаг. Коммит — по запросу, завершённой логической частью.

Сейчас выполняется только планирование. Разбивка не разрешает перенос кода или запуск новой функциональной разработки.

## Критерий результата

Разработчик находит фичу, её сценарий, repository и transport по дереву и именам. В cmd находятся команды, в app — сборка, в feature — её поведение и локальные tests, в sandbox — окружение и связанные с ним проверки по фичам. Одна операция сохраняет одного владельца ресурсов/транзакции. Меньшее число файлов не является целью само по себе; более сложный public API или ослабление тестов ради чистого дерева неприемлемы.

## Основания

- [Go: organizing a module](https://go.dev/doc/modules/layout) — cmd/internal и несколько файлов в одном пакете.
- [Go: testing](https://pkg.go.dev/testing) — same-package/black-box tests, доступ к закрытым символам и исключение test files из обычной сборки.
- [Согласованная архитектура](../architecture.md), [правила проекта](../../AGENTS.md), [MP6R](multi-project.md#mp6r-проверка-безопасности-и-рефакторинг-перед-итоговой-приёмкой).

На этапе планирования tests/lint/SQL/Docker не запускались; безопасность и производительность заново не аттестованы. Изменения ограничены Markdown-планом и навигацией к нему.

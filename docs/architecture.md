# Архитектура универсального Auth

Решения этапа 0 приняты 6 октября 2026. Это целевая архитектура, а не описание уже реализованных возможностей. Текущее состояние и порядок изменений — в [плане](planning/roadmap.md) и [пошаговой реализации](planning/implementation.md).

## Профиль и границы

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

## Согласованное решение — 7 октября 2026

Целевая архитектура утверждена 7 октября; перенос существующего кода 4.5 выполнен 8 октября 2026. Реализованы app/auth, config, server/http, account/domain, methods/password, session и audit contract. Остальные модули в дереве — будущие, не пустые пакеты в checkout. API/SQL/dependencies сохранены; выполненные 4.0/4.1 остаются в истории, их правила структуры заменены этим решением. Legacy module rename остаётся задачей 14.4.

## Структура кода и правила пакетов

Глубина дерева допустима, когда каждый каталог обозначает понятную ответственность. Auth разделён по фичам и методам входа; роли, тарифные возможности, оплата и audit — отдельные модули. У каждой развитой фичи свои domain/service/repository/transport. Не создавать общие хранилища всех фич или плоскую смесь правил, SQL и HTTP.

```text
cmd/
├── auth/
│   └── main.go
├── admin-recovery/
│   └── main.go
└── access-catalog/
    └── main.go

internal/
├── app/
│   ├── auth/
│   │   ├── app.go
│   │   ├── account.go
│   │   └── run.go
│   └── access/
│       └── app.go
├── config/
│   ├── config.go
│   └── validation.go
├── server/
│   └── http/
│       ├── config.go
│       ├── server.go
│       └── shutdown.go
├── auth/
│   ├── delivery/                # общий paced цикл почтовых очередей Auth
│   ├── account/
│   │   ├── domain/
│   │   ├── service/
│   │   ├── repository/
│   │   │   ├── postgres/
│   │   │   └── redis/
│   │   └── transport/http/
│   ├── methods/
│   │   ├── password/
│   │   │   ├── domain/
│   │   │   ├── service/
│   │   │   ├── repository/
│   │   │   │   ├── postgres/
│   │   │   │   └── redis/
│   │   │   ├── transport/http/
│   │   │   ├── hasher/
│   │   │   └── templates/
│   │   ├── emailotp/
│   │   │   ├── domain/
│   │   │   ├── service/
│   │   │   ├── repository/postgres/
│   │   │   ├── transport/http/
│   │   │   └── templates/
│   │   ├── oidc/
│   │   │   ├── domain/
│   │   │   ├── service/
│   │   │   ├── repository/redis/
│   │   │   └── transport/http/
│   │   ├── google/
│   │   │   ├── domain/
│   │   │   ├── service/
│   │   │   └── transport/http/
│   │   └── telegram/
│   │       ├── domain/
│   │       ├── service/
│   │       └── transport/http/
│   ├── session/
│   │   ├── domain/
│   │   ├── service/
│   │   ├── repository/
│   │   │   ├── postgres/
│   │   │   └── redis/
│   │   └── transport/http/
│   ├── settings/                # Auth policy, SMTP settings и commit guards
│   │   ├── domain/
│   │   ├── service/
│   │   ├── repository/
│   │   │   ├── postgres/
│   │   │   └── redis/
│   │   └── transport/http/      # protected settings API и локальное преобразование ошибок
│   └── mfa/
│       ├── domain/
│       ├── service/
│       ├── totp/
│       ├── repository/
│       │   ├── postgres/
│       │   └── redis/
│       └── transport/http/
├── access/
│   ├── domain/
│   ├── service/
│   ├── settings/
│   ├── repository/postgres/
│   └── transport/http/
├── entitlement/
│   ├── domain/
│   ├── service/
│   ├── settings/
│   ├── repository/postgres/
│   └── transport/http/
├── billing/
│   ├── domain/
│   ├── service/
│   ├── settings/
│   ├── repository/postgres/
│   └── transport/http/
├── audit/
│   ├── domain/
│   ├── service/
│   └── repository/postgres/
├── integrations/
│   ├── oidc/
│   ├── telegram/
│   └── payment/
│       └── provider/
├── infra/
│   ├── postgres/
│   ├── redis/
│   ├── mailer/
│   └── logger/
└── transport/
    └── http/
        ├── router.go
        ├── health.go
        ├── middleware/
        └── httpx/

migrations/
deploy/
docs/
├── api/
│   ├── contract.md
│   └── generated/
├── features/
├── planning/
│   ├── roadmap.md
│   ├── implementation.md
│   └── history.md
├── ai/
│   ├── index.md
│   └── current-task.md
├── adr/
├── architecture.md
├── schema.md
└── threat-model.md
.air.toml
.env.example
.env.prod.example
Taskfile.yml
go.mod
go.sum
README.md
```

`repository/postgres` и `transport/http` в дереве — сокращение вложенных каталогов. Будущие методы, repositories и остальные модули появляются только вместе с реализацией. Provider — placeholder названия конкретного платёжного адаптера, не обязательный пустой пакет. Не создавать workers/seeds/scripts ради симметрии. Air — только dev, production не использует.

### Сборка и запуск

JWT по [ADR 004](adr/004-jwt-access-profiles.md): `internal/auth/token/signing` владеет private key/loader/signing; `pkg/authjwt` — strict public-key crypto verifier без internal/DB/private key imports. Token service/domain, собственные PostgreSQL/Redis repositories и transport/http реализуют transaction-owned session exchange/JWKS; settings хранит deployment config/strict resource loader, app/auth/token.go — сборку, router/token.go — регистрацию. Выключен по умолчанию; отдельный bounded Redis owner только для issuance, lifecycle в existing run.go. Это не primary method и не перенос session/access/MFA ownership; старый cookie API сохраняется. [Ключи](features/jwt-keys.md), [выдача и ограничения](features/jwt-exchange.md).

`cmd/auth/main.go` — точка входа и передача signal context приложению. `internal/app/auth/app.go` — App, constructor и явная сборка зависимостей; `run.go` — lifecycle и порядок освобождения ресурсов. Для другого самостоятельного процесса при необходимости создаётся свой пакет `app/<process>`. Не вводить `bootstrap` или `app/wiring`; конфигурация находится отдельно в `internal/config`.

`internal/server/http` получает готовый handler и отвечает за Listen/Serve, timeouts и Shutdown с deadline; не знает о бизнес-фичах и DB repositories. Приложение контролирует завершение сервера, затем закрывает PostgreSQL/Redis и остальные ресурсы. Обработать ошибки запуска, частично созданные ресурсы, deadline shutdown и завершение активных запросов без зависания. Сборка обязательна, но не становится бизнес-логикой или auto-discovery framework.

### Владельцы ответственности

- `account`: внутренний UUID, профиль, email/verification/change, status/deletion; привязки внешних аккаунтов также здесь (`linked_identity`, linking/unlinking). Отдельные `contact`, `identity` и `authentication` модули сейчас не вводим.
- `methods/password`: парольные credentials, email + пароль, смена/reset. Не владелец всех способов входа или профиля.
- `methods/emailotp`: доказательство владения адресом через одноразовый код.
- `methods/oidc`: OIDC identity verification; OAuth-only providers требуют отдельной проверки личности через официальный API. Не объединять аккаунты автоматически по совпадению email.
- `methods/telegram`: подтверждение личности Telegram, не Telegram commerce.
- `session`: общие сессии независимо от метода; `mfa`: второй фактор/recovery.
- `access`: роли/permissions/назначения; `entitlement`: функции/grants/квоты; `billing`: оплаты/подписки; `audit`: значимые действия. Оплата не обязательна для Auth или manual/trial grants.

Метод проверяет своё доказательство, account разрешает пользователя и его состояние, MFA выполняет второй фактор при необходимости, session выдаётся только после нужных проверок. Общую координацию выделять позже лишь при реальном дублировании сценариев.

A3.1 реализует account identity resolution в существующих domain/service/repository/postgres. IdentityKey — точные issuer/subject, не email; user и identity создаются атомарно. A3.2 подключает проверку provider proof и создание сессии для Telegram; A3.3 добавляет явный linking/unlinking с fresh password proof. MFA остаётся отдельной задачей. [Текущий контракт](features/external-identities.md).

A3.2 подключает optional Telegram OIDC: методы/service/repository/transport находятся в `auth/methods/telegram`, протокольный клиент — `integrations/telegram`, сборка — `app/auth/telegram.go`. Общего provider framework и пустого oidc-пакета нет: выделение общего кода допускается при втором adapter. Session переиспользуется. A3.3: method хранит purpose/owner/session-bound flow и проверяет proof; account IdentityManagement владеет SQL linking/unlinking/last-method policy и audit. Общий session proof переиспользован с email change; не появляется второй password Compare или provider-specific SQL в integrations. External-only step-up/MFA ещё впереди. [Текущий flow](features/telegram-login.md).

`settings` принадлежит access/entitlement/billing, не глобальному модулю: продуктовые каталоги/политики отдельно от secret provisioning и runtime подключения. `integrations` — протокольные клиенты, не linking, роли или payment state machine. `infra/postgres`/`infra/redis` — подключения; feature repository — операции хранения. Название Redis обозначает технологию, не ограничивает назначение адаптера кешем или временными данными. Источник истины определяется гарантиями конкретного сценария и ADR.

### Слои развитой фичи

```text
internal/auth/methods/password/
  domain/
    credential.go
    password.go
    errors.go
  service/
    service.go
    ports.go
    register.go
    register_test.go
    login.go
    login_test.go
    change_password.go
    change_password_test.go
    reset_password.go
    reset_password_test.go
  repository/
    postgres/
      repository.go
      credentials.go
      errors.go
      credentials_test.go
    redis/
      repository.go
      limits.go
      limits_test.go
  transport/http/
    handler.go
    register.go
    register_test.go
    login.go
    login_test.go
    change_password.go
    reset_password.go
    errors.go
  hasher/
  templates/
```

Это ориентир, не обязательный набор файлов. Domain содержит сущности/инварианты/предметные ошибки, не service results, HTTP DTO, SQL rows или operational configuration. Input/result принадлежат service и располагаются рядом со сценарием; JSON DTO — transport; локальные storage representations — repository. Не создавать копии одинаковых типов без причины.

### Зависимости, транзакции и файлы

Transport → service → domain. Repository реализует малые consumer-owned interfaces service и использует нужные domain types. Service не импортирует конкретный repository/transport/provider; domain не зависит от SQL/Redis/HTTP/SDK; infra не импортирует бизнес-фичи. App собирает реализации. Межфичевые связи — через явные контракты, не чужие concrete repositories; циклы запрещены.

Repository локален фиче; таблица не равна фиче. Определить владельца каждой операции, особенно существующего `PasswordRepo.CreateUser`, который создаёт account/contact/profile/credential. Регистрация и security-критические межфичевые изменения требуют одной согласованной SQL-транзакции: service не получает `pgx.Tx`, repositories не коммитят части независимо. Не считать Redis/SMTP частью SQL-транзакции; audit/outbox и частичные сбои обрабатываются по ADR 002. Ownership/transaction contract сначала проектируется, затем реализуется в lifecycle/security этапах, без универсального CRUD/UoW framework заранее.

150 физических строк — целевой ориентир для рукописного Go-кода, а не жёсткий лимит. Если код можно осмысленно разделить на файлы до 150 строк с самостоятельной ответственностью — разделяем. Если разделение разрывает связную операцию или создаёт искусственные файлы/пакеты — оставляем больше; фиксированного верхнего порога нет. Не уплотнять код, не сокращать полезные комментарии и не вводить part1/part2 ради числа строк. Тесты и generated-файлы не ограничиваем по длине: tests группируются по операции с именованными сценариями, большой suite делится только по смыслу. HTML и SQL сохраняем смыслово цельными. Generated файлы не редактировать вручную. В 4.5 автоматический отказ по числу строк убран; TestPackageBoundaries в internal/app/auth/layout_test.go сохраняет проверки направления imports; ориентир применять при разработке и review, без нового скрипта или числового release gate.

Не вводить `core/common/utils`, глобальный склад domain types, пустые слои или interfaces на каждую функцию. Не экспортировать детали ради tests. Пакеты с одинаковыми именами импортировать с понятными aliases. Комментарии объясняют неочевидные ограничения, безопасность и причины решений, а не пересказывают названия пакетов или шаги кода. Отдельные doc.go с очевидным описанием не создаём; навигация и границы ответственности описаны здесь.



Предметные правила не проверяются повторно в HTTP и service: HTTP декодирует запрос, service один раз создаёт/проверяет domain value, локальный mapper формирует HTTP-ошибку. Проверки актуальности внутри транзакции — отдельная гарантия, не такое дублирование. В resend email валидируется в service до Redis, как раньше на HTTP-пути; ErrEmailRequired/ErrEmailInvalid дают прежний 400 invalid_email.

Register/login используют service/credentials.go для однократного разбора email и обязательности password с сохранением приоритета публичных ошибок. Новую password policy применяет только регистрация, не login. Resource bound токена confirm/reset находится в service до limiter, canonical format — после него; HTTP не повторяет эти проверки. Forgot missing/whitespace email и login whitespace email корректно сопоставляются с documented 400, вместо ошибочного dependency/internal fallback.

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

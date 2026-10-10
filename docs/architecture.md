# Архитектура универсального Auth

Решения этапа 0 приняты 6 октября 2026. Это целевая архитектура, а не описание уже реализованных возможностей. Текущее состояние и порядок изменений — в [плане](auth-plan.md) и [пошаговой реализации](auth-implementation.md).

## Профиль и границы

Один независимый backend на проект, собственные PostgreSQL, Redis, SMTP и secrets. Браузер работает через cookie/BFF и HTTPS; native/API access требует отдельного контракта, не переиспользования browser cookie. Общий SSO, организации, multi-app и Telegram commerce — отдельные расширения. Не строим свой OAuth server или универсальный plugin framework.

## Согласованное решение — 7 октября 2026

Целевая архитектура утверждена 7 октября; перенос существующего кода 4.5 выполнен 8 октября 2026. Реализованы app/auth, config, server/http, account/domain, methods/password, session и audit contract. Остальные модули в дереве — будущие, не пустые пакеты в checkout. API/SQL/dependencies сохранены; выполненные 4.0/4.1 остаются в истории, их правила структуры заменены этим решением. Legacy module rename остаётся задачей 14.4.

## Структура кода и правила пакетов

Глубина дерева допустима, когда каждый каталог обозначает понятную ответственность. Auth разделён по фичам и методам входа; роли, тарифные возможности, оплата и audit — отдельные модули. У каждой развитой фичи свои domain/service/repository/transport. Не создавать общие хранилища всех фич или плоскую смесь правил, SQL и HTTP.

```text
cmd/
└── auth/
    └── main.go

internal/
├── app/
│   └── auth/
│       ├── app.go
│       ├── account.go
│       └── run.go
├── config/
│   ├── config.go
│   └── validation.go
├── server/
│   └── http/
│       ├── config.go
│       ├── server.go
│       └── shutdown.go
├── auth/
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
│   └── mfa/
│       ├── domain/
│       ├── service/
│       ├── repository/postgres/
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

## Независимые настройки

Это будущий контракт этапов 9–12, ещё не существующие env-переменные или endpoints:

- `access`: permission/role catalog отдельно от назначений пользователям. Продукт расширяет каталог без hardcoded business enum. Системные permissions защищены от произвольного переопределения.
- `auth`: независимый выбор методов входа, registration enabled, email verification enabled/required для password, TTL/cooldown и frontend URL. Optional verification не подменяет verified_at; OTP/reset/change-email/linking всё равно доказывают контроль почты. Настройки/API/UI реализуются в самом конце, 14.4s–14.4u, после backend и permissions + MFA; сейчас используются нынешние operational env и политики.
- `entitlements`: features/plans/limits, версии и manual/trial grants отдельно от access. Free/Pro — пример, а не обязательные названия.
- `billing`: подключение выбранного provider, checkout/recurring capabilities и режим новых продаж отдельно от entitlement catalog. Secrets — только operational configuration.

Auth-only deployment не требует payment secrets, provider connections или billing workers. Entitlements могут работать без оплаты через manual/trial grants. Billing-enabled профиль подключает checkout и обслуживает обязательства. Выключение новых продаж существующего billing deployment не выключает cancellation/webhooks/reconciliation и не удаляет историю/grants. Полное снятие интеграции допускается лишь после завершения обязательств. Нельзя выключением модуля молча разрешить платную функцию: неизвестный feature или недоступный evaluator даёт отказ; отсутствие платных ограничений задаётся явно проектом.

Доступ к настройкам ролей, назначениям, тарифам и оплате защищают разные permissions. Admin не получает Pro, Pro не получает admin. Защищённые admin API публикуются после MFA 13.1: fresh auth, audit, проверка scope и optimistic version/conflict при изменении. Bootstrap первого admin — одноразовая operator operation; последний административный доступ сохраняется.

UI также позволит вводить/заменять SMTP/provider secrets через отдельный protected API. Чтение даст только configured/masked state, storage защищается шифрованием/secret storage, audit исключает payload. Минимальные operational root key и первый admin остаются вне этой UI-зависимости. Настройки и UI — последние функциональные задачи 14.4s–14.4u перед release 14.5, не уже реализованная возможность; текущие email env остаются startup configuration.

## Реализация и открытые условия

Приняты [ADR 001](adr/001-deployment-and-reuse.md), [ADR 002](adr/002-sessions-and-transactions.md), [ADR 003](adr/003-access-and-optional-billing.md). [Модель угроз](threat-model.md) задаёт негативные acceptance tests.

Этап 4 и 5.1–5.4 выполнены локально; 5.5a–c реализованы как opt-in [email change/report](email-change.md), далее безопасное восстановление 5.5d и оставшаяся приёмка 5.5e. Внешний email/browser staging впереди. Ограничения — [API-контракт](api-contract.md), [verification](email-verification.md), [recovery](password-recovery.md). После 5.2r/5.2h дерево сохранено: app/auth остаётся app.go/account.go/run.go, независимые HTTP-сценарии и feature-local error rules отделены, общий mapper не импортирует business domain. EmailChangeService собирается в существующем app.go; account worker переиспользуется, отдельного lifecycle нет. Request/confirm/report и PostgreSQL операции находятся в своих смысловых файлах. Далее остальное 5/6, MFA 13.1 до административных действий; 7–10, 11 и optional 12, release 14. Полная session security и нагрузочная приёмка 6.8 остаются впереди; 6.9 optional.

До 12.1 пользователь выбирает merchant profile: страна/юридический статус продавца, валюты, товары, разовая/recurring оплата, refund/cancel требования. Затем выбирается и проверяется один hosted-checkout provider; конкретный поставщик сейчас не объявлен поддержанным. Native/SSO/organizations/Telegram commerce требуют отдельного подтверждения scope перед своими подэтапами.

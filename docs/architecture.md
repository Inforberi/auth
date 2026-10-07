# Архитектура универсального Auth

Решения этапа 0 приняты 6 октября 2026. Это целевая архитектура, а не описание уже реализованных возможностей. Текущее состояние и порядок изменений — в [плане](auth-plan.md) и [пошаговой реализации](auth-implementation.md).

## Профиль и границы

Один независимый backend на проект, собственные PostgreSQL, Redis, SMTP и secrets. Браузер работает через cookie/BFF и HTTPS; native/API access требует отдельного контракта, не переиспользования browser cookie. Общий SSO, организации, multi-app и Telegram commerce — отдельные расширения. Не строим свой OAuth server или универсальный plugin framework.

## Согласованное решение — 7 октября 2026

Целевая архитектура ниже утверждена пользователем. Это план переноса 4.5, не уже выполненный refactor: сейчас код находится в `internal/modules/auth`, сборка — в `internal/app/auth.go`, config — в `internal/app/config`, server — в `internal/infra/httpserver`. Выполненные 4.0/4.1 сохраняются в истории; их правила структуры и лимит 150 строк заменены этим решением. Schema/API/security поведение не меняется самим переносом. Legacy module rename остаётся отдельной задачей 14.4.

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
│   │   ├── repository/postgres/
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
      reset_tokens.go
      reset_tokens_test.go
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

150 физических строк — целевой ориентир для рукописного Go-кода, а не жёсткий лимит. Если код можно осмысленно разделить на файлы до 150 строк с самостоятельной ответственностью — разделяем. Если разделение разрывает связную операцию или создаёт искусственные файлы/пакеты — оставляем больше; фиксированного верхнего порога нет. Не уплотнять код, не сокращать полезные комментарии и не вводить part1/part2 ради числа строк. Тесты и generated-файлы не ограничиваем по длине: tests группируются по операции с именованными сценариями, большой suite делится только по смыслу. HTML и SQL сохраняем смыслово цельными. Generated файлы не редактировать вручную. Существующий enforcing test пока действует: в 4.5 убрать автоматический отказ по числу строк, сохранить/адаптировать полезные import-boundary checks; ориентир применять при разработке и review, без нового скрипта или числового release gate.

Не вводить `core/common/utils`, глобальный склад domain types, пустые слои или interfaces на каждую функцию. Не экспортировать детали ради tests. Пакеты с одинаковыми именами импортировать с понятными aliases. У развитых пакетов короткая документация ответственности, а не обязательные пустые `doc.go`.



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

## Источники истины

PostgreSQL хранит пользователей/status/auth version, identities, session ledger, одноразовые challenges, назначения прав, каталоги/grants, billing state, audit и inbox/outbox. Изменение credentials/status, инвалидация и запись security audit выполняются одной SQL-транзакцией. Redis — ограничители нагрузки и ускорение, но не единственное доказательство действительности сессии/прав/оплаты. Детали отказов — [ADR 002](adr/002-sessions-and-transactions.md).

UUID пользователя неизменен; email, username и provider display name не являются идентификатором владельца. Identity определяется проверенным issuer/subject с областью выбранного адаптера. В базовом профиле scope одного приложения задаётся сервером; client app/user/owner ID не расширяет доступ. Цена и владелец покупки фиксируются сервером.

## Независимые настройки

Это будущий контракт этапов 9–12, ещё не существующие env-переменные или endpoints:

- `access`: permission/role catalog отдельно от назначений пользователям. Продукт расширяет каталог без hardcoded business enum. Системные permissions защищены от произвольного переопределения.
- `entitlements`: features/plans/limits, версии и manual/trial grants отдельно от access. Free/Pro — пример, а не обязательные названия.
- `billing`: подключение выбранного provider, checkout/recurring capabilities и режим новых продаж отдельно от entitlement catalog. Secrets — только operational configuration.

Auth-only deployment не требует payment secrets, provider connections или billing workers. Entitlements могут работать без оплаты через manual/trial grants. Billing-enabled профиль подключает checkout и обслуживает обязательства. Выключение новых продаж существующего billing deployment не выключает cancellation/webhooks/reconciliation и не удаляет историю/grants. Полное снятие интеграции допускается лишь после завершения обязательств. Нельзя выключением модуля молча разрешить платную функцию: неизвестный feature или недоступный evaluator даёт отказ; отсутствие платных ограничений задаётся явно проектом.

Доступ к настройкам ролей, назначениям, тарифам и оплате защищают разные permissions. Admin не получает Pro, Pro не получает admin. Защищённые admin API публикуются после MFA 13.1: fresh auth, audit, проверка scope и optimistic version/conflict при изменении. Bootstrap первого admin — одноразовая operator operation; последний административный доступ сохраняется.

## Реализация и открытые условия

Приняты [ADR 001](adr/001-deployment-and-reuse.md), [ADR 002](adr/002-sessions-and-transactions.md), [ADR 003](adr/003-access-and-optional-billing.md). [Модель угроз](threat-model.md) задаёт негативные acceptance tests.

Структура 4.0 и схема/domain 4.1 выполнены. 7 октября согласована новая целевая структура: сначала перенос 4.5, затем API/schema contract 4.4. Далее 5/6; MFA 13.1 сразу после 6 до административных действий; 7–10, 11 и опционально 12, release 14. Session ledger/enforcement и межфичевые security-транзакции завершаются в 5/6: перенос каталогов сам по себе не закрывает дефекты.

До 12.1 пользователь выбирает merchant profile: страна/юридический статус продавца, валюты, товары, разовая/recurring оплата, refund/cancel требования. Затем выбирается и проверяется один hosted-checkout provider; конкретный поставщик сейчас не объявлен поддержанным. Native/SSO/organizations/Telegram commerce требуют отдельного подтверждения scope перед своими подэтапами.

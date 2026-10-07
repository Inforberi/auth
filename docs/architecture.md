# Архитектура универсального Auth

Решения этапа 0 приняты 6 октября 2026. Это целевая архитектура, а не описание уже реализованных возможностей. Текущее состояние и порядок изменений — в [плане](auth-plan.md) и [пошаговой реализации](auth-implementation.md).

## Профиль и границы

Один независимый backend на проект, собственные PostgreSQL, Redis, SMTP и secrets. Браузер работает через cookie/BFF и HTTPS; native/API access требует отдельного контракта, не переиспользования browser cookie. Общий SSO, организации, multi-app и Telegram commerce — отдельные расширения. Не строим свой OAuth server или универсальный plugin framework.

Сохраняем composition root `internal/app/auth.go`, HTTP-контракт, service/repo interfaces и внутренний UUID. Структурный подэтап 4.0 выполнен: `internal/core` и `internal/featers` заменены фичами `internal/modules/auth`, infrastructure и transport. Legacy module переименовывается отдельно в 14.4. Новые модули добавляются по этапам, не заранее пустыми каркасами.

## Структура кода и правила пакетов

Структура уточнена по предоставленным скриншотам: предметный модуль `internal/modules/auth`, внутри — фичи. Инфраструктура, интеграции и общий транспорт отдельно. Адаптируем организацию папок, не банковские модули или инструменты примера.

```text
cmd/auth/                    # точка входа
deploy/                      # Docker/Compose и operational scripts
docs/                        # план, архитектура, ADR, API
migrations/                  # SQL
internal/
  app/                       # DI, сборка приложения и lifecycle
    config/                  # агрегат runtime config и общая валидация
  infra/                     # DB/Redis connections, SMTP, logger, server
  integrations/              # технические внешние adapters
    telegram/
    oidc/
    payment/                 # выбранный платёжный provider
  modules/
    auth/
      account/               # UUID, статус, профиль, lifecycle
      password/              # регистрация, вход, смена и восстановление
      session/               # сессии, отзыв, authentication context
      identity/              # разрешение identity и linking
      email/                 # verification, OTP, auth-письма
      access/                # роли, permissions, назначения и настройки
      entitlement/           # тарифы, grants, квоты и настройки
      billing/               # orders/subscriptions и настройки оплаты
      mfa/                   # факторы и recovery
  transport/http/            # router, общие HTTP middleware/helpers
Taskfile.yml                 # команды разработки и проверки
```

Будущие фичи/adapters появляются только вместе с реализацией. `pkg/` нужен только для действительно независимой библиотеки с внешним потребителем; `internal/pkg/` не вводим. `scripts/` и `seeds/` не создаём без необходимости; существующие scripts остаются в `deploy/scripts`. Дополнительные workers со скриншотов автоматически не включаем. Air добавлен позднее по явному запросу: только dev profile, конфигурация `.air.toml`, production не меняется.

Пример развитой фичи, не обязательный пустой каркас:

```text
internal/modules/auth/password/
  doc.go
  model/                     # типы и ошибки без IO
  service/                   # use cases и интерфейсы зависимостей
    service.go
    register.go
    login.go
    change_password.go
    register_test.go
    login_test.go
  repository/
    postgres/                # SQL queries и mapping
    redis/                   # только при реальной необходимости
  transport/http/            # DTO, handlers, mapping ошибок
    handler.go
    register.go
    login.go
```

Типы принадлежат `model` конкретной фичи, use cases — `service`, queries — `repository/postgres`, пул/соединение — `infra`. Общая маршрутизация подключает feature handlers через `app`, не дублирует DTO/политики. Session cookies принадлежат session-фиче; письма — email/password; permissions — access. Не создавать общий склад моделей.

`integrations` содержит protocol/SDK adapters, не linking, role policy или payment state machine. Telegram/OIDC adapters реализуют контракты identity-сервиса, payment adapter — billing-контракт. Настройки ролей, тарифов и оплаты остаются у владельцев access/entitlement/billing; не объединяем их в глобальный settings-модуль.

Направление зависимостей: feature HTTP/storage adapters → service/model; service → model и малые consumer-owned interfaces. Service не импортирует свой repository/transport или конкретный provider adapter; model не зависит от SQL/Redis/HTTP/SDK. Внешний adapter может импортировать контракт фичи, обратной зависимости нет; `infra` не импортирует фичи. `app` связывает реализации. Межфичевые вызовы — через явные контракты, не чужой repository. Account ID/status принадлежит `account/model`, не дублируется. Циклы запрещены.

Небольшая фича может начинаться одним пакетом: слои выделяются при реальных границах, не ради одного метода. Не вводим `core/common/utils/helpers` или глобальный `domain`. Transaction/audit contract имеет конкретного владельца и назначение. Публичный API минимален, детали не экспортируются ради тестов.

Каждый рукописный Go/HTML файл исходного кода, включая tests, — не более 150 физических строк с комментариями и пустыми строками. Generated Swagger/mocks не дробить вручную: явно пометить generated и исключить из лимита. Документация и миграции не дробятся механически ради этого ограничения. Большие tests разбивать по сценарию; реализацию — по use case/ответственности (`register.go`, `login.go`, `refresh.go`), не на `part1/part2`. Не уплотнять строки для обхода лимита, не разрывать связную операцию между искусственными пакетами.

У каждой существующей фичи — короткий `doc.go`: назначение, основные операции и зависимости. Названия отражают предметную область; комментарии объясняют инварианты/причины, а не повторяют код. Лимит проверяется в `internal/app/layout_test.go` обычным `task check`, без отдельного shell-скрипта.

### Карта выполненного переноса 4.0

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

Новый use case добавлять в `auth/<feature>/service/<operation>.go`, его типы — в `model`, SQL adapter — в `repository/postgres`. Feature DTO/handler — в `transport/http`; маршрут подключить в общем router и wiring `app`, затем обновить Swagger. Test размещать рядом с операцией, большие наборы — отдельными именованными сценариями. У существующих DTO стабильные Swagger schema names сохранены `@name`; перемещение Go-пакета не переименовывает API-схемы. Не создавать placeholders для будущих Telegram/OIDC/billing: они появятся в своих этапах.

| Модуль | Ответственность | Не отвечает за |
| --- | --- | --- |
| Identity/authentication | Проверенные методы, credentials, challenges, linking | Роли и оплаченные функции |
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

Структура 4.0 и схема/domain 4.1 выполнены; текущие таблицы и ограничения — [schema](schema.md). Следующий шаг — 4.4: API/schema contract. Затем 5/6; MFA 13.1 сразу после 6 до административных действий; 7–10, 11 и опционально 12, release 14. Session ledger и реальный enforcement/concurrency tests завершаются в 6: один SQL-файл сам по себе не закрывает дефекты.

До 12.1 пользователь выбирает merchant profile: страна/юридический статус продавца, валюты, товары, разовая/recurring оплата, refund/cancel требования. Затем выбирается и проверяется один hosted-checkout provider; конкретный поставщик сейчас не объявлен поддержанным. Native/SSO/organizations/Telegram commerce требуют отдельного подтверждения scope перед своими подэтапами.

# ADR 003: отдельные роли, доступ по тарифу и оплата

Статус: принято, 6 октября 2026; уточнено 10 октября: ручное добавление пользователей и optional external payments. Реализация: 5.7, 9.4, 10–12, 13.1–13.2, 14. Новые сценарии пока не реализованы.

## Решение

Три независимых области настроек: access catalog/assignments, entitlement catalog/grants, billing integration/sales policy. Раздельные permissions управления ими; проект задаёт собственные role/permission/feature/plan keys. Role assignments не вычисляются из суммы покупок. Administrative permissions не обходят paid entitlement check.

Каталоги версионируются; изменения проходят валидацию ссылок, scope, безопасных defaults и конфликтов версии. Backend отдельно проверяет ownership, permission и required entitlement/atomic quota. Неизвестные permissions/features запрещены. Проверенный email не означает право admin; отключённый billing не означает бесплатный Pro.

Минимальный billing owner — личный account с immutable user UUID и server app scope. Organization/shared package — расширение. Entitlement grants содержат owner/scope/source/period и связь с исходной операцией. Price snapshot покупки неизменен: integer amount, currency/unit, catalog version. Free/Pro — демонстрация; manual/trial grants работают без provider, имеют expiry/audit и не создают роли.

## Профили и переключения

1. Auth-only: access работает, платных ограничений в продуктовых операциях нет по явной конфигурации. Billing routes/workers/provider secrets не нужны.
2. Entitlements без payments: manual/trial catalog и quota enforcement; недоступный evaluator не превращается в unlimited access.
3. Billing-enabled: один выбранный hosted checkout adapter. Secrets выдаются оператором; публичная discovery возвращает только доступные возможности, не secrets/internal configuration.

Новый проект без billing не требует provider credentials/connections, payment routes/workers или обязательной инициализации billing tables. SQL profile и migration selection закрепить в 4/12, не менять существующую БД переключением флага. Проверить запуск без оплаты отдельно в 12.0/14.4.

Отключение новых продаж существующего deployment — отдельный режим, не полное выключение integration: продолжать webhook/inbox, refund/cancel и reconciliation текущих обязательств. Сохранить историю и valid grants; не удалять таблицы, не выдавать дополнительный доступ. Полное отключение — operator runbook после отмены recurring/завершения обязательств и сверки с provider. При смене provider исторические записи сохраняют исходный adapter ID.

## Payments и административные изменения

До 12.1 выбирается merchant profile и один provider; цены/покупатель/валюта определяются backend. Redirect не подтверждает оплату. Проверенное событие сохраняется в durable inbox до ACK; state transition + grant + audit/outbox транзакционны и идемпотентны по event и бизнес-операции. Повторные/неупорядоченные события не дают double fulfillment. Timeout после provider success разрешается idempotency/reconciliation, а не повторной покупкой вслепую.

Admin settings — только после MFA 13.1, с fresh auth/audit, отдельными permissions, last-admin guard и запретом self-promotion. До этого nonsecret policy задаётся operator config. Нужные provider-specific capabilities/проверки уточняются по официальным docs в 12, а не объявляются реализованными этим ADR.

## Ручные пользователи и независимые состояния

Account provisioning принадлежит account; роли/permissions — access; manual/trial/paid доступ — entitlement. Создание через администратора независимо от публичной регистрации, не означает verified email, рабочий credential, сессию или дополнительные права. Приглашение/активация доказывает контроль включённого метода; не использовать общий пароль, автоматический merge по email или доверие к email, введённому администратором. Административные API используют те же services, что и будущий UI; до permissions/MFA/CSRF/fresh-auth не публикуются.

Роли — основной механизм назначения permissions. Прямые персональные grants — optional проектный сценарий с source/scope/expiry и audit; не произвольное поле пользователя. Отдельные permissions для user provisioning, назначения доступа, изменения каталога и manual entitlements. Delegation policy ограничивает выдаваемые caller права, включая прямые grants; last-admin проверяет эффективный административный доступ, не только наличие имени роли.

| Состояние | Владелец | Следствие успешной оплаты |
| --- | --- | --- |
| `account.status` / authentication version | Account | Не меняется, blocked не разблокируется |
| Roles / permissions | Access | Административные полномочия не выдаются |
| Plan / features / действующие grants | Entitlement | Выдача доступа по проверенной операции и периоду |
| Payment / subscription state | Billing или внешний payments service | Финансовый переход и доставка grant-события |

«Pro/оплачен» в UI — проекция действующего entitlement, не общий `user.status=paid`. Несколько источников доступа сохраняют независимость: refund одной покупки не снимает ручной grant. Источник истины для финансового состояния один, а для доступных в Auth возможностей — entitlement service.

## Внешний платёжный сервис — включаемый профиль

Микросервис не обязателен. В local payments профиле включённый billing module владеет provider/checkout/orders. В external payments профиле это владелец во внешнем сервисе; в Auth остаются account/access/entitlement APIs и минимальный adapter входящих событий. Не создавать одновременно два финансовых ledger и не требовать provider secrets/полную billing schema от external профиля. Auth-only не публикует event endpoint и не запускает соответствующий worker.

Внутренний endpoint (предварительно POST `/api/v1/internal/billing/events`, этап 12.8) принимает только разрешённую service identity с ограниченными правами. Не browser cookie и не публичное «set paid». Provider проверяется платежным владельцем; Auth проверяет доверенный источник, scope, user UUID, операцию, plan/period и допустимый переход. Event/business operation IDs, replay policy, версии событий и schema compatibility фиксируются до реализации. Успешная оплата не может менять account status/roles, назначать неизвестные features или произвольный plan вне политики интеграции.

Sender outbox/retry и Auth durable inbox обеспечивают повторяемую доставку. После приёма локальная SQL-транзакция фиксирует grant/revoke, audit и результат обработки/receipt до ACK. Повтор после lost ACK не продлевает доступ; разные события одной операции не создают double fulfillment. Межсервисной SQL-транзакции нет: задержки/пропуски/неупорядоченность разрешаются retries и reconciliation, а не объявляются exactly-once. Refund/expiry относятся к исходным grants; ручные и trial grants не теряются.

Возможность интеграции фиксируется сейчас только архитектурой/планом. Код, migrations, interfaces и новый сервис вводятся с соответствующим реализуемым подэтапом; UI — в конце 14.4u-admin.

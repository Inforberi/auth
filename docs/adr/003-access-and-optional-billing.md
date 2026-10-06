# ADR 003: отдельные роли, доступ по тарифу и оплата

Статус: принято, 6 октября 2026. Реализация: 9.4, 10–12, 13.1–13.2, 14.

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

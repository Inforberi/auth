# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Telegram MFA](../features/telegram-mfa.md#настройки-bot-api--a63m6d2b) · [Implementation](../planning/implementation.md).

## A6.3m.6d.2b — Luna V3 PASS

Private Bot API settings: masked read; permission/fresh-proof/version preflight; getMe без SQL locks; повторная авторизация и CAS; project-scoped encrypted token/webhook secret, server-generated rotation; общий mfa_settings.version инвалидирует pending preparation; atomic masked audit/rollback и bounded retention. Canonical token validator переиспользован adapter; SettingsLimiter заменил имя SMTPLimiter без смены контракта. Нет новых dependencies/routes/ENV/workers; реальные DB/secrets не менялись.

Принят снимок `/private/tmp/auth-telegram-bot-settings-v3.3s7p7yz4`, base16bce831632c2f26e30bf35bbf5d5182c8923e32. Luna: manifest25/25, V2→V3 rename-only equivalence, final targeted lint0; V2 full Go tests stage/affected race/четыре actual SQL roots с nested7/18/382/1 PASS без SKIP. Full task check после rename не повторялся: единственный V2 G101 устранён. Fixture/TLS/isolated caches очищены. Evidence turn01a1975a-597e-71d2-b11a-6fc84f1e6607, cursor944a6e9d-49fe-49f7-8ff5-48acb6c615a1:74; FAIL/исправления — в history. Main сверил25/25 с рабочим деревом до обновления только Markdown статусов; tests/lint не запускал, pinned formatter выполнен как подготовка. Пользователь разрешил коммит после PASS.

## Далее — .6d.3

Telegram factor lifecycle/policy: безопасные подключение/смена/удаление, last-factor/strong-admin/revocation/recovery/audit. Перед публикацией нужна защита смены bot ID при enrolled factors. Затем .6d.4 protected settings routes/platform-owner bridge, crypto/limiter/client lifetime wiring, method-aware login/delivery/readiness/webhook и двухпроектная fault/recovery приёмка. Сейчас private backend без HTTP/app wiring, setWebhook не вызывается; реальные credentials не подключать.

Source000001 up/down изменён без новой миграции. Новая schema нужна binary даже при disabled Telegram из-за retention; controlled upgrade MP6 отдельно. Real Telegram/ingress/fleet/capacity/GC и UI — открытые gates. UI не начинать без предупреждения и отдельного согласования.

Проверки — только отдельный чат «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d, host local). Jason (01a196ae-b5d3-7313-acb1-b14dad3aa9b6) — bounded code researcher, не исполнитель проверок.

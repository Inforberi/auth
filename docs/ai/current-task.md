# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Telegram MFA](../features/telegram-mfa.md) · [Implementation](../planning/implementation.md).

## Завершён A6.3m.6d.1 — Luna V3 PASS

Внутренний Bot API adapter internal/integrations/telegram/bot: bounded shared client, getMe identity check, private SendCode, безопасные credentials/errors, authenticated private /start decoder. OIDC секреты не используются. Привязка в БД, factor lifecycle/login, public webhook и bot settings ещё не подключены: parser не обеспечивает SQL single-use или готовую MFA.

Luna V3: manifest10/10, task check/lint0 и package race/count1 PASS/exit0; cache и test server/transport ресурсы очищены. Снимок `/private/tmp/auth-telegram-mfa-bot-v3.14fggzk7`, base affc554; evidence turn `01a196e2-210f-7de3-a3df-647ccf720811`, cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:67`. V1/V2 lint findings исправлены: cohesive response/private-message validation, checked Close в HTTP caller, style; два точечных объяснённых owner-lifetime lint exceptions без изменения правил проекта. [История/evidence](../planning/history.md).

Main сверил10/10 перед обновлением только Markdown, проверки не повторял. Schema/ENV/dependencies/routes/settings/workers не добавлены; real Telegram/secrets/БД не использовались. Пользователь разрешил коммит после PASS.

## Далее — .6d.2

Source browser/password/factor proof + project SQL intent, authenticated bot candidate, confirmation code в исходной browser session, owner/version/config/expiry/replay guards. Start URL сам не включает фактор и не назначает владельца. Guarded bot settings/secret storage и bot identity revision до реальных credentials. Сетевой вызов не выполнять под SQL locks. Public flow закрыт до lifecycle/login/readiness/двухпроектной приёмки .6d.3–.4. UI не начинать без предупреждения и отдельного согласования.

Локальный исследователь Luna gpt-6-luna (Jason, 01a196ae-b5d3-7313-acb1-b14dad3aa9b6) дал read-only карту Telegram/MFA helpers; для связанных уточнений переиспользовать. Проверки — только отдельный чат «Проверки Auth — Luna», 01a16eab-c777-78a0-a815-47b45ff0860d, host local. Локальная email .4b уже принята, коммит affc554; её проверки не повторять.

# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Private lifecycle](../features/telegram-mfa.md#private-lifecycle--a63m6d3a) · [Implementation](../planning/implementation.md).

## A6.3m.6d.3a — Luna V2 PASS

Private TelegramFactors Status/Enable/Disable и TelegramMFA policy. Enrolled mfa_telegram отделён от preparation/OIDC; current confirmed source/session/auth_version/bot/settings.version, unique channel owner; enable/replace/disable атомарно revoke/auth_version/challenges/audit. Bot ID и allowed нельзя менять с привязками. First-TOTP/admin guards, account deletion и assisted Telegram-only recovery/operator/TOTP/codes/notice/no-auto-login. mfa_login_required учитывает Telegram, но mfa_proof_usable НЕ принимает telegram, capability запрещает такой runtime до .d4.

Принят снимок `/private/tmp/auth-telegram-factor-lifecycle-v2.dkxo5y_m`, base131aff7df9f85583783bcb8b5273b485d2381ba6. Luna V2: manifest39/39 (3 expected deletions); task check exit0/lint0; affected service race exit0; actual TelegramLifecycle/EmailLifecycle/PolicyFactorRaces SQL23/23 без SKIP. V1 остальные5 roots409/409 сохранены по diff equivalence; recovery/schema не менялись. Итого432 SQL tests/subtests без SKIP; полный набор8 roots повторно не запускался. Source lock/proof/last-factor/deadline/revoke/audit/API equivalence и docs проверены; собственные fixture/TLS/cache/worktrees очищены. Evidence turn01a19778-758a-79f2-978e-e33cc4fd6099/cursor76; logs `/private/tmp/auth-telegram-factor-lifecycle-v2-*`. FAIL/исправления в history. Main сверил39/39 с рабочим деревом до обновления только Markdown статусов, tests/lint не запускал; formatter выполнен как подготовка. Пользователь разрешил коммит после PASS.

## Далее — .6d.3b

Обычные lifecycle notifications/preferred method и remaining last-factor/proof acceptance перед публикацией. Затем .6d.4 method-aware Telegram proof/login/browser/native/delivery/HTTP settings/platform-owner bridge/runtime readiness/webhook/two-project tests. Сейчас backend private, без app wiring/HTTP/ENV, реальные credentials не подключать. Existing recovery notice не заменяет уведомления обычного lifecycle. .d3 целиком не закрыт.

Source000001 up/down изменён без новой миграции; real DB/ENV/secrets не менялись, dependencies/workers/новые очереди не добавлены. Новая schema нужна binary даже с disabled методом, controlled MP6 upgrade отдельно. External Telegram/ingress/fleet/capacity/GC/UI gates открыты; UI не начинать без предупреждения/отдельного согласования.

Проверки — только отдельный чат «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d, host local). Jason01a196ae-b5d3-7313-acb1-b14dad3aa9b6 — bounded code researcher.

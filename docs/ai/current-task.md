# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Уведомления и предпочтение](../features/telegram-mfa.md#уведомления-и-предпочтение--a63m6d3b) · [Implementation](../planning/implementation.md).

## A6.3m.6d.3b — private backend, Luna V2 PASS

Telegram enable/replace/disable атомарно enqueue encrypted security notice на verified recipient snapshot вместе с factor/revoke/audit; нет verified email — audit без job. Existing recovery queue/worker обобщены в mfa_security_outbox/SecurityDelivery, тот же cipher/lease/retry/backoff. Restore/wiring обновлены; failed TTL bounded по SecurityAuditDays, soft deletion чистит jobs. Новых workers/deps/HTTP/ENV нет.

mfa_preferences: monotonic version, nullable totp|email; private fresh-proof/limits/usable/admin/CAS/audit, reset на explicit disable/recovery повышает version. Preference change не меняет auth_version/сессии. Telegram choice запрещён до .d4; existing explicit login endpoints НЕ переключаются по сохранённому preference.

Принят снимок `/private/tmp/auth-mfa-notices-preferences-v2.j7s01ar2`, base739f653. Luna: manifest48/48,4 expected deletions, final targeted lint0 и selector-only V1→V2 equivalence (input.Proof.Validate→input.Validate, promoted value-receiver method). Унаследованы V1 full Go test stage/affected service race/все9 actual SQL roots —432 PASS,0 SKIP. Full task check после одной строки не повторялся, единственный V1 QF1008 устранён. Проверены source/security/rollback/lease/retention/preferences/restore/deletion,524 Markdown links и unchanged dependencies. Fixture/TLS/temporary copy/cache cleanup подтверждены. Evidence turn01a1979a-1a43-7d70-be0b-3c0c0c80610d/cursor78; `/private/tmp/auth-mfa-notices-preferences-v2-evidence.log`, прочие логи V1/V2 рядом. Main сверил48/48+HEAD перед обновлением только Markdown статусов; tests/lint не запускал, pinned formatter выполнен как подготовка. Пользователь разрешил коммит после PASS.

## Далее — .6d.4

Complete Telegram proof/login/browser/native/delivery/HTTP/platform-owner bridge/readiness/webhook/two-project tests. Подключить preference selector без automatic downgrade, добавить Telegram только с готовым runtime, закрыть last-factor/strong-admin matrix с настоящим Telegram proof до публикации. Private .d3b принят, весь .d3 до final proof acceptance не закрыт. UI отдельно: не начинать без предупреждения/согласования.

Source000001 up/down без новой миграции, реальные DB/ENV/secrets не менялись; controlled MP6 upgrade учитывает queue rename/legacy encrypted payloads. External SMTP/Telegram/ingress/fleet/capacity/GC gates открыты. Проверки — только отдельный чат «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d (host local). Jason01a196ae-b5d3-7313-acb1-b14dad3aa9b6 — bounded code researcher.

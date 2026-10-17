# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-a63c2-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — A6.3c.2-local

- [Google/Telegram settings](../features/provider-settings.md): fixed provider rows, per-provider encrypted secret, ENV только seed, protected presence-only GET/versioned POST с current permission/fresh password+MFA/audit. Client ID нельзя менять при existing identities; disabled method и explicit secret обязательны для его замены. Callback/issuer/endpoints/budgets/root keys — deployment, не UI.
- Current SQL credential snapshot на start/callback, immutable OAuth/verifier view на shared HTTP/JWKS owner/provider, без polling/cache/new pools/workers/dependencies. ProviderVersion связан с Redis flow → verified identity/primary → SQL creation/link/session/MFA/enrollment/recovery до commit; stale/zero managed proof требует restart, existing sessions сохранены. [Правила и ограничения](../features/provider-settings.md#rotation-и-незавершённые-входы).
- Adapter operational readiness и configured SQL credential readiness разделены; enable/startup не разрешены без credentials. Неготовый enabled seed не сохраняется. Lost row/cipher failure не разрешают ENV fallback. Source 000001 дополнен; existing install требует controlled encrypted bootstrap/schema/grants/legacy pending invalidation до traffic, maintenance upgrade CLI не реализован. Mixed old/new fleet недопустим.
- Formatter/Swagger/final task check PASS/lint 0 issues; full PostgreSQL 18.6/race PASS 34.835s, Redis/OIDC/crypto/service race PASS. Docker disk-full диагностирован: свой test PG пересоздан на bounded tmpfs, чужие Docker данные не чистились. Все созданные временные containers/data удалены; рабочая DB/ENV/secrets не трогались. Коммит — только по запросу.

## Следующий блок — A6.3c.3

Сохраняемые retention/runtime settings: сначала минимальный набор существующих worker параметров и владельцы/bounds/суммарные бюджеты, version/current permission/fresh password+MFA/audit, безопасное применение на экземплярах без новых timers/cache. Не переносить весь deployment env/root secrets в UI и не менять deadlines ранее выданных sessions. Сохранять SMTP/provider credential contracts, current SQL authority и fixed admin protection. Родители A6.3c/A6.3 открыты.

Затем A6.4 [JWT](../planning/jwt-access.md) → pre-ui-backend → UI A7 → A8. Cookie/session default, strict online authority без ослабления ADR 002.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.

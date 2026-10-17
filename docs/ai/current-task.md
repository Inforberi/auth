# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-a63c1-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — A6.3c.1-local

- [SMTP settings](../features/smtp-settings.md): versioned SQL store, scoped AES-GCM secret, first-install ENV seed/no overwrite/no reseed после initialized setup. Protected read/update/test, password только на запись, current permission/fresh password+MFA/audit guards. Root key и destination allowlist остаются ENV.
- Все Auth mail send/retry используют current SQL source, один indexed read+decrypt на попытку, без cache/polling/new workers/pools/session requests. In-flight send может использовать прежний snapshot до 20s. Fleet key/allowlist и external rotation overlap обязательны; единый SQL source не доказывает готовность внешней инфраструктуры.
- Probe saved version после SQL commit: TLS/AUTH/NOOP без email, deadline 10s/dial 5s, Redis 3/operator/min + 10/project/min, 2 concurrent/instance. No secrets/refresh/health persistence.
- `task go:fmt`, Swagger, `task check` PASS/lint 0 issues; full PostgreSQL 18.6/race PASS 31.793s, actual Redis 8.2.2/race + service/mailer PASS. Временные containers/data удалены; рабочая DB/ENV/secrets не трогались. Source 000001 изменён; для existing installation нужен controlled encrypted bootstrap/schema/grants/rollout до трафика, без reset/mixed old fleet. Maintenance upgrade CLI не реализован. Коммит — только по запросу.

## Следующий блок — A6.3c.2

Google/Telegram credentials/settings: сейчас по-прежнему ENV. До кода определить минимальный protected masked read/versioned update и binding credentials revision к pending OIDC start/callback/link/MFA. Сохранить purpose/browser/PKCE/nonce/issuer ownership и current SQL policy, не менять shared mutable config и не публиковать storage без runtime consumer. Lifecycle/cleanup HTTP clients, bounded fleet propagation/fail-closed; реальные provider credentials — отдельная внешняя приёмка. Не обобщать рабочий SMTP в plugin framework.

Затем A6.3c.3 retention/runtime settings; root/deployment keys остаются ENV. Родитель A6.3 открыт. Далее A6.4 [JWT](../planning/jwt-access.md) → pre-ui-backend → UI A7 → A8. Cookie/session default, strict online authority без ослабления ADR 002.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый изолированный HTTPS-стенд/synthetic data: browser/ingress/multi-tab/polling-vs-activity/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c, shutdown/backup/restore обязательны; capacity не установлена. Controlled upgrade/invalidation старых sessions/challenges из предыдущих блоков также обязателен. Не включать cache/GC tuning без измерений.

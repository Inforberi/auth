# Модель угроз Auth

Этап 0, 6 октября 2026. Модель задаёт требования и проверки будущих этапов; не является pentest или подтверждением текущей безопасности. Решения — [архитектура](architecture.md), [ADR](adr/002-sessions-and-transactions.md); реальные статусы — [план](planning/roadmap.md).

## Активы и границы доверия

Защищаем credentials, sessions/challenges/MFA secrets, пользовательские данные, роли, grants, платежи, audit и backups. Недоверенные стороны: browser/client, внешние callback/webhook payload, email/display name, redirect parameters, forwarded headers вне разрешённого proxy. Отдельные доверенные границы: TLS edge → HTTP, backend → SQL/Redis/SMTP, backend → provider, operator → secrets/deployment/backup. DB/operator compromise не устраняется одним auth middleware: нужны минимальные privileges, secret rotation, restricted audit и recovery runbook.

## Угрозы и acceptance tests

| Угроза | Защита | Негативная проверка / этап |
| --- | --- | --- |
| Credential stuffing/enumeration | Bounded hashing/конкуренция, rate limits, generic recovery, verification policy | Known/unknown email, distributed attempts, malformed hashes, limiter failure; 5.1–5.2, 6.4–6.7, 8.4 |
| Reset/OTP replay и account takeover | Purpose/owner/expiry, verifier, SQL single consume + invalidation | Parallel consume, resend, boundary deadline, DB/SMTP failure; 5.1–5.2, 8.4 |
| Session theft/fixation/refresh после logout | Secure cookies, rotation, durable ledger/status/version | Logout-refresh race, blocked user, Redis stale cache, absolute expiry/cookie; 5.3–5.4, 6.1–6.3 |
| CSRF/login CSRF/linking takeover | Origin/CSRF policy, state/nonce/PKCE по adapter, binding user/session/intent | Cross-origin POST, reused callback, session switch, unlink last method; 6.5, 8.1–8.3, 9.2 |
| Поддельная identity/auto-merge | Verified issuer/subject/audience, no merge по email | Wrong issuer/audience, unverified email, duplicate identity race, expired Telegram payload; 7–9 |
| IDOR/privilege escalation/cross-app | Deny-by-default access/ownership, server scope, protected settings | Foreign IDs/list leakage, role DTO injection, self-promotion, last admin, concurrent settings edits; 10, 9.4 |
| Paid→admin/admin→paid bypass | Раздельные access/entitlements/settings | Pro admin request, admin без grant, unknown feature, disabled billing, expired/manual grant; 10–12 |
| Quota race/expired access | Atomic usage, explicit period, SQL truth/cache invalidation | Parallel limit crossing, expiry boundary, downgrade, stale cache; 11.2–11.3 |
| Webhook forgery/double fulfillment | Provider verification, durable inbox, unique domain transitions | Bad signature/raw body, duplicate/out-of-order/lost events, timeout after success, mismatched owner/amount; 12.2–12.7 |
| Скрытые recurring обязательства | Sales pause отдельно от integration shutdown, reconciliation | Disable new sales while subscription active; webhook/cancel still works, restart/drain failures; 12.0, 12.4–12.5 |
| MFA/recovery bypass | Verified enrollment, bounded attempts, one-time recovery, fresh auth | Reused TOTP/recovery, lost-factor bypass, old auth context, admin без MFA; 13.1 |
| DoS/SSRF/redirect/secret leak | Body/time/resource bounds, allowlisted destinations, redacted logs | Oversize/trailing body, timeout/redirect to private host, tokens в logs/metrics, forwarding spoof; 1.4–1.5, 6, 8/12 adapter tests |
| Restore возвращает отозванный доступ | Invalidate sessions/challenges, provider reconciliation before traffic | Old cookie/reset after restore, missing payment events, restore failure at each step; 14.2 |

Названия мер — требования, не новые непроверенные library APIs. Протокольные детали сверяются по установленной версии и official docs при реализации адаптера. Monetary/provider правила не выводятся из клиентского redirect.

## Release gate

Все baseline P0 session/credential defects закрываются в 5/6 до внешнего трафика. До административных API необходима 13.1. Auth-only, entitlements-only и billing-enabled проверяются как разные поддерживаемые профили; выключенная интеграция не объявляется протестированной. Содержательные concurrency/negative tests добавляются вместе с затронутым модулем, без полного infrastructure drill после каждого изменения документации.

SMTP delivery и external provider sandbox требуют отдельных staging checks. Linux/architecture coverage, нагрузка, retention/RPO/RTO и secret provisioning фиксируются в 14; локальный dev smoke не заменяет эти проверки. Operational recovery имеет документированный owner и порядок действий при compromise/DB failure/backup restore.

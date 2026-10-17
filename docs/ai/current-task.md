# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j3b-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J3b-local

- [Session exchange](../features/jwt-exchange.md) подключён через App/settings/router/HTTP и Swagger. JWT_ENABLED=false: без JWT files/дополнительного pool/маршрутов. Enabled: bounded strict resource file/catalog/ES256 key matching, один общий owner на instance. Cookie POST exchange — exact Origin/NoRefreshAuth, JSON≤8KiB/no duplicates/aliases/unknown/null, Authorization conflict rejection, no-store/no Set-Cookie. Public GET/HEAD /.well-known/jwks.json — только public data/ETag/cache30s, не online authorization.
- J3a SQL guards сохранены; добавлен общий с primary login current password-email verification guard: old session не обходит required verification, выключенный primary method сам по себе не logout. Issuance не refresh/activity/fresh proof; amr=mfa сохраняет реальную детализацию ledger. Deployment/resource policy immutable до restart, saved/UI JWT policy — J6. Native/refresh/introspection ещё нет; crypto-only VerifySignature не current authority.
- Context7 подтвердил client-global retries: отдельный JWT Redis client/max8 active connections/no retries/context deadlines/1s socket-pool bounds; суммировать +8 connections/instance. Existing Auth Redis не менялся. Server/retention/delivery lifecycle — existing run.go, feature routing — router/token.go. Новых workers/caches/libraries/schema changes нет. Audit cleanup/storage sizing остаётся gate: default batch100/min не гарантирует drain при3000 issuances/min.
- Formatter/final task check PASS/lint0; Swagger generation/reproducibility PASS; full SQL -race PASS16.836s, real Redis/assembly/unit/race и final App/router/settings/service race PASS. Security scan: 0 affected symbols/imported packages, 1 module-level finding/no observed calls. Только synthetic keys/disposable PostgreSQL/Redis; временные контейнеры удалены. Рабочие ENV/secrets/DB не менялись, коммит — только по запросу.

## Следующий блок — J4

Cookie-free password/email OTP+MFA login и opaque rotating refresh на общем session ledger по [JWT-плану](../planning/jwt-access.md)/ADR004. До реализации определить native credential-output boundary, purpose/audience/scope binding restricted MFA challenges и atomic family consume/reuse/revoke. Не копировать primary pipelines, не выдавать JWT до завершения MFA/activation и не добавлять bearer fallback на cookie/admin routes. Сначала bounded storage/family guarantees и tests, затем publication; прямой native Google/Telegram handoff — отдельный J4c. Strict consumer — J5, не signature-only authorization.

Затем J4 native password/email OTP+MFA/refresh (direct native provider handoff — J4c) → J5 → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.

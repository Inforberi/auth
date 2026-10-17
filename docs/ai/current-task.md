# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j4b1-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J4b.1-local

- [Refresh use case](../features/refresh-storage.md#refresh-use-case--j4b1-local): общий с exchange admission8/deadline3s, Redis IP/project до indexed lookup; server-owned hint → actor/family/IP/project budgets до transaction. В repository повторно связываются user/session/ledger hash и актуальная locked authority. Никакой сети внутри SQL transaction, нового pool/worker/dependency/schema/ENV нет.
- Current session/version/role/MFA/verification/provisioning guards и signing общие с exchange; повторный user lookup убран. Scope=current grants∩immutable family maximum∩resource allowlist. Ordinary idle renew ограничен absolute deadline, admin refresh не activity; primary/MFA proof times не меняются. Spent replay commit до отказа; sign/audit/commit failures возвращают nil с rollback. Raw successor только после commit. App передаёт existing generator через service port; native primary/output/HTTP пока нет, JWT_ENABLED публикует только J3 exchange/JWKS.
- Formatter/task check/lint0 PASS; final full SQL -race PASS19.429s. Real Redis/race PASS1.279s, final service/App/router -race PASS1.211s/2.313s/4.410s. Concurrency/replay, deferred commit failures, pending block/scope revoke, current verification/MFA/provisioning, admin no-activity и budgets/TTL проверены. Disposable PostgreSQL/Redis удалены; рабочие DB/ENV/secrets не менялись, source000001 upgrade requirements J4a сохраняются. Коммит только по запросу.

## Следующий блок — J4b.2

По [JWT-плану](../planning/jwt-access.md)/ADR004: native password/email OTP+MFA purpose/audience/scope-bound flow, первая API session/family и credential output без browser cookie и копирования primary pipelines. Затем refresh/logout HTTP с conflict rejection/no-store/safe errors/Retry-After, management profile label и negative/API/concurrency tests. До native publication — deployment idle/absolute ceilings, retention candidate-scan/held-ledger eligibility/backlog/drain/storage checks. Не добавлять bearer fallback на cookie/admin routes; direct native providers — J4c, strict consumer — J5. Refresh core не публиковать отдельно как готовый native профиль.

Затем J4 native password/email OTP+MFA/refresh (direct native provider handoff — J4c) → J5 → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.

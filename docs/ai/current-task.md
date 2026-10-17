# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j4b2a-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J4b.2a-local

- [Первая API issuance](../features/native-issuance.md): общий Password Authenticate/rehash/limits возвращает server-only proof без browser session. Token service/repository атомарно создаёт API ledger/family/access JWT с current reference/version/policy/grants/provisioning guards. Отдельные ledger/refresh secrets, common resource/authority/audit/signing; повторный policy lookup убран. Новых schema/migrations/ENV/dependencies/pools/workers нет.
- Optional constructor NativePolicy копируется и ограничена existing session ceilings; нынешний App её не задаёт. Native actor/IP/project budgets до SQL без empty-session key, общий admission8/deadline3s. MFA/factor/role requirement пока fail-closed без tokens: native challenge/enrollment/email OTP transport binding не готов. Administrative/OIDC/email OTP proof в IssueNative не принимается. JWT_ENABLED публикует только existing exchange/JWKS; native HTTP отсутствует. Неопределённый network commit не гарантирует rollback: raw не отдаётся без подтверждения, нужен новый вход, auto-retry нет.
- Formatter/task check/lint0 PASS; full SQL -race PASS21.063s, final targeted native SQL -race PASS2.637s. Real Redis -race PASS1.292s; final token/password/MFA/session/App -race PASS1.726s/1.404s/1.188s/1.551s/1.963s. Real password→rehash→API issuance→refresh, current denials/commit rollback/pending block/grant races проверены. Disposable PostgreSQL/Redis удалены; рабочие DB/ENV/secrets не менялись, source000001 upgrade requirements J4a сохраняются. Коммит только по запросу.

## Следующий блок — J4b.2b

По [JWT-плану](../planning/jwt-access.md)/ADR004: native purpose/transport/audience/scope-bound MFA/enrollment и email OTP flow; browser challenge нельзя redeem в native и наоборот. Factor consume + первая API ledger/family/sign/audit/commit в одном workflow, без создания browser session и перепаковки её в JWT. Не принимать клиентский PrimaryProof/user/assurance/admin intent. Затем App/native config/HTTP login/refresh/logout с conflict rejection/no-store/safe errors/Retry-After, management profile label и negative/API/concurrency tests. До публикации — deployment ceilings, retention candidate-scan/held-ledger eligibility/backlog/drain/storage checks. Не добавлять bearer fallback на cookie/admin routes; direct native providers — J4c, strict consumer — J5.

Затем J4 native password/email OTP+MFA/refresh (direct native provider handoff — J4c) → J5 → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.

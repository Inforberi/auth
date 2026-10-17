# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j4b2b2-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J4b.2b.2-local

- [Native email OTP](../features/native-email-otp.md): общий email mail/request/consume pipeline, отдельные API HMAC/profile/immutable SQL target. Consume возвращает server-owned current email proof/target, затем NativeLogin выдаёт API credentials либо MFA/enrollment challenge без browser session. Consume и issuance — два workflow: после успешного consume сбой выдачи требует нового кода. Claims emailotp, без false MFA/private password proof. Общие policy/version/contact/grants/eligibility и одноразовость сохранены.
- [Native MFA](../features/native-mfa.md) теперь поддерживает password/emailotp primary, не OIDC/admin. Factor consume и API ledger/family/sign/audit/challenge delete атомарны; обязательная настройка требует нового primary login. Email target сохраняется во всей цепочке. Общие admission8/credential IP-project/email/token/MFA budgets, без нового Redis namespace/worker/pool/dependency/ENV/HTTP. Slot consume освобождается до Begin; один email challenge/user между profiles/purposes сохраняется.
- Только source000001: новые email challenge columns/trigger и расширенный MFA API CHECK нужны binary даже без native enable; рабочая DB не мигрировалась. NativePolicy не подключена в App. При неопределённом network commit raw не отдаётся без подтверждения, нужен новый вход, auto-retry нет. Legacy browser MFA admission/cardinality остаётся обязательным gate.
- Formatter/final task check/lint0 PASS. Full SQL -race PASS20.510s, targeted native email SQL -race PASS2.923s. Email/token/MFA/session/App/router -race PASS; real mail payload/code→issuance→ES256 verify→refresh, concurrent winner/attempts, profile/target/current authority/rollback и enrollment проверены. Native HTTP/SMTP/real Redis fault/fleet/load/GC/restore этим блоком не проверены. Временная synthetic PostgreSQL удалена; рабочие DB/ENV/secrets не менялись. Коммит только по запросу.

## Следующий блок — J4b.2c

По [JWT-плану](../planning/jwt-access.md)/ADR004: сначала legacy browser MFA invalid-token admission/cardinality и deployment ceilings/retention candidate-scan/held-ledger eligibility/backlog/drain/storage prerequisites. Затем App/native config/HTTP password login/email request-confirm/MFA/enrollment/refresh/logout с conflict rejection/no-store/safe errors/Retry-After, management profile label и negative/API/concurrency tests. Не принимать клиентский PrimaryProof/user/assurance/admin intent; не добавлять bearer fallback на cookie/admin routes. Direct native providers — J4c, strict consumer — J5.

Затем J4 native password/email OTP+MFA/refresh (direct native provider handoff — J4c) → J5 → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.

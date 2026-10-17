# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j4b2b1-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J4b.2b.1-local

- [Native MFA](../features/native-mfa.md): общий coordinator возвращает API credentials либо связанный с profile/audience/scope challenge. TOTP/recovery consume, API ledger/family/sign/audit и удаление challenge — одна транзакция без промежуточной browser session. Неверный код сохраняет attempts; известный signing/SQL abort откатывает factor и issuance. Browser/native completion/enrollment/recovery изолированы.
- Обязательное native enrollment использует существующие primitives, повышает auth_version/отзывает контекст и требует нового primary login. Один активный challenge/user сохранён: новый вход заменяет предыдущий. Credential IP/project admission выполняется до native MFA subject allocation/SQL; общий с refresh Redis namespace сохранён. Для legacy browser MFA записан отдельный обязательный admission/cardinality gate до HTTP/UI.
- Изменена только source000001: новые challenge columns/trigger нужны новому binary даже без native enable; рабочая DB не мигрировалась. Нет новых dependencies/pools/workers/ENV/публичных ручек; App NativePolicy не включает. Primary proof пока password-only; email OTP следующий. При неопределённом network commit raw не отдаётся без подтверждения, нужен новый вход, auto-retry нет.
- Formatter/task check/lint0 PASS. Full SQL -race PASS23.754s; после финального admission изменения targeted native MFA SQL -race PASS3.076s. Real Redis/token/MFA/session/App/router -race PASS; concurrency, profile confusion, binding/target guards, current authority, rollback и enrollment проверены. Временные synthetic PostgreSQL/Redis удалены; рабочие DB/ENV/secrets не менялись. Статус коммита проверять через Git.

## Следующий блок — J4b.2b.2

По [JWT-плану](../planning/jwt-access.md)/ADR004: email OTP purpose/transport/audience/scope binding с общей native issuance/MFA цепочкой; browser code нельзя redeem в native и наоборот. Не принимать клиентский PrimaryProof/user/assurance/admin intent. Затем App/native config/HTTP login/MFA/enrollment/refresh/logout с conflict rejection/no-store/safe errors/Retry-After, management profile label и negative/API/concurrency tests. До публикации — legacy browser MFA invalid-token admission/cardinality, deployment ceilings, retention candidate-scan/held-ledger eligibility/backlog/drain/storage checks. Не добавлять bearer fallback на cookie/admin routes; direct native providers — J4c, strict consumer — J5.

Затем J4 native password/email OTP+MFA/refresh (direct native provider handoff — J4c) → J5 → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.

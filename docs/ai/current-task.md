# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j4b2c1-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J4b.2c.1-local

- [Atomic MFA admission](../features/mfa.md#атомарный-admission--j4b2c1-local): batch subject/IP/project до owner SQL, отдельный user/factor-user batch после него и management user/project. Denied budget batch не выделяет random keys/не расходует часть counters/не продлевает TTL. Existing prefix/keys/TTL/лимиты сохранены. Accounting стадийный: accepted lookup расходуется даже при unknown owner/последующем отказе; network retry/lost reply не exactly-once. Standalone browser MFA работает при JWT disabled.
- Limiter.AllowAll использует один bounded Lua, максимум3 distinct keys; malformed counters/error fail-closed. SQL attempts/factor guards/пяти-попытный cap не менялись; single step-up/recovery-start counters сохранены. Нет новых pools/dependencies/workers/ENV/schema/HTTP; parent J4b.2c и native API publication ещё не закрыты. Native password/email OTP/MFA/refresh cores предыдущих блоков сохранены, App NativePolicy не задаёт; source000001 schema/grants rollout по прежним контрактам обязателен.
- Formatter/final task check/lint0 PASS; real Redis final -race PASS1.524s, full SQL -race PASS20.659s, MFA/token/session/App/router -race PASS. Two-client concurrency/legacy counters/TTL/malformed/fail-closed проверены; 256 random token/binding при project exhaustion не создали keys и не вызвали owner port. Disposable Redis/PostgreSQL удалены, рабочие DB/ENV/secrets не менялись. Внешние fleet/fault/HTTP/load/GC/restore не проверены; capacity не установлена. Коммит только по запросу.

## Следующий блок — J4b.2c.2

По [JWT-плану](../planning/jwt-access.md)/ADR004: actual retention EXPLAIN/BUFFERS на mixed browser/API, expired/revoked held ledger/families и spent history. NOT EXISTS сейчас до LIMIT в session/family selection — deletion batch не доказывает bounded eligibility scan/отсутствие starvation. Проверить drain/locks/общий worker deadline и исправить bounds/progress по evidence, сохраняя reuse window/без массового cascade. Согласовать native lifetime/rotation/issuance ceilings, cleanup batch/interval и storage budget. Затем App/native config/HTTP password/email request-confirm/MFA/enrollment/refresh/logout, conflict rejection/no-store/safe errors/Retry-After, management profile label и negative/API/concurrency tests. Не принимать клиентский PrimaryProof/user/assurance/admin intent; не добавлять bearer fallback на cookie/admin routes. Direct native providers — J4c, strict consumer — J5.

Затем J4 native password/email OTP+MFA/refresh (direct native provider handoff — J4c) → J5 → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.

# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j4b2c2-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J4b.2c.2-local

- [Bounded retention pages](../features/refresh-storage.md#ограниченный-обход--j4b2c2-local): baseline actual SQL≈10000 visits при batch100 исправлен indexed keyset page до eligibility/locks. Source000001 добавляет две retention_checkpoints rows sessions/families; advance/wrap и deletes atomic, busy checkpoint/row пропускаются, held/locked/late eligible возвращаются на следующем круге. Missing state — error без reseed. Runtime worker/pools/индексы/ENV/API не добавлены, source upgrade/seeds/grants обязательны даже без native enable; рабочая DB не менялась.
- Verifiers удаляются только после absolute window, family без children, ledger без family; history4096 дренируется batch без cascade. Zero removals не означает завершённый backlog, physical lag включает sweep/drain. Session page в прежней transaction, family page — один atomic statement без лишнего BEGIN/COMMIT. Подтверждены current authority/retention/reuse гарантии, не уменьшены TTL. Previous native primary/MFA/refresh и atomic MFA admission сохранены; App NativePolicy по-прежнему не подключает.
- Formatter/final task check/lint0 PASS. Full SQL -race PASS23.213s, exact actual plans -race PASS8.677s:100000 rows, cursor0/50000 и positive deletes,≈200–400 visits на relation/704–1708 buffers при page100. Rollback/busy checkpoint/locked row/wrap/missing state/4096 drain проверены. Disposable PostgreSQL удалена, рабочие DB/ENV/secrets не менялись. Внешние fleet/fault/HTTP/SMTP/load/GC/restore не проверены; capacity не установлена. Коммит только по запросу.

## Следующий блок — J4b.2c.3

По [JWT-плану](../planning/jwt-access.md)/ADR004: working native deployment config/startup guard до App/HTTP. [Storage расчёт](../features/refresh-storage.md#бюджет-хранения-до-подключения-native-api) показал default JWT3000/min vs максимум100 expired verifier deletes/min default worker: sustained native writes нельзя публиковать как согласованную capacity. Связать lifetime/issuance ceilings с cleanup batch/interval и явным запасом/validation; считать консервативно один worker, не повышать batch/не сокращать TTL автоматически и не вводить ENV-заглушки без подключённого потребителя. Затем App/HTTP password/email request-confirm/MFA/enrollment/refresh/logout, no-store/conflict rejection/safe errors/Retry-After/profile label/negative/concurrency API tests. Parent J4b.2c открыт. Не принимать клиентский PrimaryProof/user/assurance/admin intent; не добавлять bearer fallback на cookie/admin routes. Direct native providers — J4c, strict consumer — J5.

Затем J4 native password/email OTP+MFA/refresh (direct native provider handoff — J4c) → J5 → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.

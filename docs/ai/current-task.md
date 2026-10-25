# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1h project account/email

[Контракт](../features/project-account-runtime.md). ProjectEmail подключает invitation/reissue/activation, binding request/confirm, change confirm/report/protected recovery; ProjectPassword — temporary issue/reissue/begin/complete. Reuse existing services/repo/proofs/scopes/hash; no operator impersonation/new SQL/deps/schema/ENV/routes/readiness. ProjectEmailConfig вынесен в собственный config файл: verification/recovery отдельно выбираются flags, binding-only без fake reset URL. FreshAuthTTL shared validator прежних1m–15m. Temporary secret — one-time JSON-hidden response, не mail.

Runner ротирует account queue раз в полный catalog sweep, один selected flag+verification fallback, reset отдельно. Нет per-project map/worker и вложенных leases; existing claims/backoff/cancellation сохраняются. Added unit disabled/config/fairness и actual SQL+Redis invitation/temporary/binding/change/recovery tests с отдельным owned no-STARTTLS SMTP; проверяется безопасный retry каждой очереди, не внешняя доставка. Formatter/diff выполнены main. Luna V3: actual full TestPrepareCommandSQL exit0 без SKIP, включая account scenarios и downstream policy assertions; targeted cmd lint exit0/0issues. V1 task check/lint0 и affected race PASS сохранены: V2/V3 меняли только SQL-fixture seed/cleanup. Manifest17 совпал до/после и с main; RedisDB15 пуста, owned fixtures удалены. Snapshot `/private/tmp/auth-project-account-v3.ey656x8o`, manifest `/private/tmp/auth-project-account-v3-manifest.sha256`, metadata `/private/tmp/auth-project-account-v3-snapshot.json`. Локальный verification завершён; public/externalSMTP/fleet gates не закрыты.

## Следующий шаг

После фиксации проверенного блока продолжить remaining OTP/MFA mail, provider/token assembly и readiness/MP5 guards; retention/fleet fairness/MP6R/MP7/MP8 отдельно. UI не начинать, [email templates](../planning/email-templates.md) запланированы A7 после backend.

## Процесс и ограничения

- Local read-only researcher Helmholtz (gpt-6-luna medium), ID01a17292-5405-7341-bae9-f5884a755889. Сохранять для reuse; нашёл ctor/guard/fixture контракты, сделал короткий source review, tests/edits не выполняет. Bohr закрыт по просьбе пользователя.
- Executable checks — отдельная «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd, default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- UsePool не сохраняет pool/services/async за callback; scalar/result после final current guard. Hash/network не держат physical SQL connection, committed in-flight side effects не обещают distributed rollback. Shared resources закрываются owner после drain.
- Component flags не подменяют SQL policy/permissions и не разрешают передать platform operator proof вместо project session. Target scope/host routing/issuer/cookie matrix — MP5, UI отдельно согласовать.
- PostgreSQL+Redis; новые deps только с разрешения. Реальные ENV/БД/secrets/staging сохранять. Commit только по запросу. Предыдущий registration ea14216 проверен/закоммичен; его PASS не подтверждает этот diff.

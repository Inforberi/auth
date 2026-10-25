# Текущий шаг

Обновлено 25 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1i project email OTP

[Контракт](../features/project-email-otp-runtime.md). Добавлены внутренние ProjectEmailOTP Request/Confirm и email reauthentication, общий private projectMFA coordinator для password/OTP и OTP delivery через существующий bounded runner. Primary/reauth flags независимы, текущая SQL policy не заменяется caller hook, scoped cipher/Redis и current-key guards сохранены. При MFA сначала challenge, обычная сессия после фактора. Recovery при потере всех факторов закрыт. Нет новых SQL/deps/ENV/HTTP/readiness/UI.

Main: formatter и diff check; Helmholtz targeted review, tests/edits не выполнял. Luna V2: task check exit0/lint0, полный TestPrepareCommandSQL exit0 без SKIP, включая OTP/reauth/MFA/delivery и прежние password/MFA regressions. Affected race app/auth+cmd V1 PASS; после него только эквивалентные selectors и исправленный synthetic seed. Manifest13 совпал до/после и с main. RedisDB15 пуста, disposable PostgreSQL/Redis удалены. Snapshot `/private/tmp/auth-project-email-otp-v2.jyhbf526`, manifest `/private/tmp/auth-project-email-otp-v2.jyhbf526-manifest.sha256`, metadata `/private/tmp/auth-project-email-otp-v2.jyhbf526-snapshot.json`. Блок проверен; пользователь запросил коммит. Git/staging и факт коммита проверять через Git.

## Следующий шаг

После фиксации проверенного блока продолжить provider/token assembly и readiness/MP5 guards; remaining MFA recovery/retention/fleet fairness/MP6R/MP7/MP8 отдельно. UI не начинать до отдельного согласования; [email templates](../planning/email-templates.md) — A7 после backend.

## Процесс и ограничения

- Local read-only researcher Helmholtz (gpt-6-luna medium), ID01a17292-5405-7341-bae9-f5884a755889, сохранять для reuse. Bohr закрыт по просьбе пользователя.
- Executable checks — отдельная «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd; default6377/auth stale. Main не дублирует и не ждёт полный прогон. [Процесс](development-workflow.md).
- UsePool не сохраняет pool/services/async за callback. Final guard не обещает rollback committed in-flight действий. Shared resources закрываются owner после drain.
- Component flags не подменяют SQL policy/permissions и не разрешают platform operator proof вместо project session. Target scope/host routing/issuer/cookie matrix — MP5.
- PostgreSQL+Redis; новые deps только с разрешения. Реальные ENV/БД/secrets/staging сохранять. Commit только по запросу. Предыдущий account `7ca3296` проверен/закоммичен; его PASS не подтверждает этот diff.

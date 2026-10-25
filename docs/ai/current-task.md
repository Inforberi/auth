# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1g project registration

[Контракт](../features/project-registration-runtime.md). Добавлен ProjectPassword.Register и optional RegistrationVerification config (trusted HTTPS origin/существующий account Config). Existing assembleRegistration/QueueInTransaction создают account и encrypted verification outbox атомарно, session после commit отдельно. Shared passwordService сохраняет Login/MFA/session policy. Scoped registration IP/global limiter действует всегда; nil verifier допустим только при disabled verification (SQL callback откатывает optional/required). Ключ берётся только из loader, caller config копируется; SMTP в registration transaction не вызывается. No deps/schema/ENV/pool/worker/HTTP/readiness changes.

Добавлены unit config/key/origin/mutation и actual SQL+Redis modes/rollback/duplicates/policy+suspend during hash tests. Физическое SQL connection во время hash свободно; final current guard не выдаёт stale token, не обещая rollback committed in-flight account. Formatter/diff выполнены main. Luna V2: task check exit0/lint0, cmd race exit0 и actual full TestPrepareCommandSQL exit0 без SKIP, все registration cases PASS. V1 app/auth race PASS сохранён: V2 изменил только fixtures. Manifest8 совпал до/после и с main; owned containers/TLS/binaries/schema/roles удалены, RedisDB15 пуста. Snapshot `/private/tmp/auth-project-registration-v2.4i7xfb6u`, manifest `/private/tmp/auth-project-registration-v2-manifest.sha256`, metadata `/private/tmp/auth-project-registration-v2-snapshot.json`. Локальный verification завершён; public-ready/external SMTP/fleet не подтверждены.

## Следующий шаг

После фиксации проверенного блока продолжить remaining email queues/provider/token assembly и readiness/MP5 guards. Не начинать UI. Остальные outbox/retention/fleet fairness, MP6R security/refactor и MP7/MP8 остаются отдельными; [шаблоны писем](../planning/email-templates.md) в A7 после защищённого backend.

## Процесс и ограничения

- Read-only research: Helmholtz (gpt-6-luna medium), ID01a17292-5405-7341-bae9-f5884a755889, переиспользовать. Он нашёл registration/session/tx/fixture контракты и выполнил короткий review новой wiring, tests/source edits не делал. Bohr закрыт по просьбе пользователя.
- Все executable checks — отдельная «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd; default6377/auth stale. Main не дублирует tests и не ждёт весь прогон. [Процесс](development-workflow.md).
- UsePool не сохраняет pool/services/async за callback, без nested acquisition. Shared dependencies закрывает owner после drain. Required registration не создаёт MFA challenge; SQL MFA guard может отказать session уже после account commit. SMTP delivery/readiness не доказаны enqueue.
- PostgreSQL+обязательный Redis; новые deps только с разрешения. Реальные ENV/БД/secrets/staging сохранять. Commit только по запросу. Предыдущий lifecycle блок30f694c закоммичен и проверен; его PASS не подтверждает текущий diff.

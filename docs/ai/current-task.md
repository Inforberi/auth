# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1f project delivery lifecycle

[Контракт/ENV](../features/project-delivery-lifecycle.md). Default-off cfg.Platform.Delivery, explicit project SMTP allowlist, parallelism/page/interval/fleet settings; startup проверяет включённые platform/runtime, половину MaxAcquiring оставляет другим consumers, parallelism<=MaxRuntimes и APIInstances×parallelism<=FleetConcurrency. Используются existing registry/private reader/shared Redis, без новых pools/clients/schema/deps. Примеры ENV обновлены, реальные ENV не менялись.

Operator assembly добавляет только concrete non-nil worker. Existing realm.run/runWithDelivery/App.Close обеспечивают start после сборки и cancel/join до resources close. Добавлены config tests и actual TestProjectRuntimeAssemblySQL lifecycle drill: фоновый page query без HTTP, serve return/error/cancel, worker join/resources order и restart. Empty-catalog fixture не вызывает Redis; реальные email/outbox/Redis случаи проверены MP4.1e, core SQL/claim/payload не менялись. Formatter/diff выполнены main. Luna V2: full task check exit0/lint0 и config race exit0. V1 app/auth race и actual TestProjectRuntimeAssemblySQL PASS без SKIP, включая return/error/cancel/resources cleanup; после V1 менялась только группировка config validation. Manifest9 совпал до/после и с main. Snapshot `/private/tmp/auth-project-delivery-lifecycle-v2.6ow2pp9y`, manifest `/private/tmp/auth-project-delivery-lifecycle-v2-manifest.sha256`, metadata `/private/tmp/auth-project-delivery-lifecycle-v2-snapshot.json`. Локальный verification завершён; внешний delivery/fleet/readiness не подтверждены.

## Следующий шаг

После фиксации проверенного блока продолжить remaining registration/email queues/provider/token assembly и отдельные readiness/MP5 guards. Не закрывать full MP4.4/4.5: остальные outbox/retention/fleet fairness ещё отдельно. UI не начинать; дальше MP6R security/refactor, MP7/MP8 и отдельное согласование UI. [Шаблоны писем](../planning/email-templates.md) запланированы в A7 после защищённого backend.

## Процесс и ограничения

- Local research: Helmholtz (gpt-6-luna medium), ID01a17292-5405-7341-bae9-f5884a755889. Только targeted read-only карта, без tests/source edits. Переиспользовать, не закрывать после отчёта. Bohr закрыт по просьбе пользователя.
- Все executable checks — отдельная «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd; default6377/auth stale. Main не дублирует tests и не ждёт весь прогон. [Процесс](development-workflow.md).
- UsePool не сохраняет pool/services/async за callback, не делает nested acquisitions. Worker logical lease bounded, physical SQL connection не удерживается во время SMTP/hash. Shared dependencies закрываются после worker/registry drain.
- Current key не обещает отмену committed SMTP side effect; FleetConcurrency — статическая declared topology с surge, не distributed semaphore или измеренный RPS. Нельзя увеличивать число экземпляров мимо бюджета.
- PostgreSQL+обязательный Redis. Новые deps только после разрешения, реальные ENV/БД/secrets/staging сохранять. Коммит только по запросу. Предыдущий email блок e875ac8 и план шаблонов c0a3f75 закоммичены; их PASS не подтверждает этот lifecycle diff.

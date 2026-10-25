# Текущий шаг

Обновлено 25 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1l project introspection

[Контракт](../features/project-introspection-runtime.md). Optional ProjectTokenConfig.Introspection: project client ID/hash/audience manifests и scalar budgets. Issuer/resources/prepared public keys берутся из того же token runtime. ProjectTokens.Authenticate/Inspect совместимы с existing HTTP interface, но routes/readiness не публикуются. IntrospectionFactory хранит parsed clients/verifier/admission32 без repo; Bind request-local под existing UsePool/current guards. Shared JWT no-retry Redis owner/scopes сохраняются, новых pools/schema/deps/ENV нет. Strict SQL authority без positive cache/sliding UPDATE, inactive без metadata; credential authentication отдельно не означает project readiness.

Main formatter/diff и read-only review; tests не запускал. Luna V2: task check/lint0, affected race, security и Linux ARM64 full TestPrepareCommandSQL/TestPostgresSchema PASS, включая introspection/consumer/token/native regressions. Security: вызываемых кодом уязвимостей нет; одна в dependency недостижима по scanner. Manifest11 совпал до/после и с main. Свои containers/network/credentials/test binaries удалены. Snapshot `/private/tmp/auth-project-introspection-v2.b_9o47b6`, manifest `/private/tmp/auth-project-introspection-v2.b_9o47b6-manifest.sha256`, metadata `/private/tmp/auth-project-introspection-v2.b_9o47b6-snapshot.json`; logs `/private/tmp/auth-project-introspection-v2-*.log`. Блок проверен; пользователь запросил коммит. Git/staging и факт коммита проверять через Git.

## Следующий шаг

После фиксации проверенного блока продолжить readiness/MP5 issuer/host/cookie/callback guards; managed key/consumer credential source+rotation, remaining MFA recovery/retention/fleet fairness/MP6R/MP7/MP8 отдельно. UI не начинать до отдельного согласования; [email templates](../planning/email-templates.md) — A7 после backend.

## Процесс и ограничения

- Local read-only researcher Helmholtz (gpt-6-luna medium), ID01a17292-5405-7341-bae9-f5884a755889, сохранять для reuse. Bohr закрыт по просьбе пользователя.
- Executable checks — отдельная «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- Actual command SQL: Linux ARM64 binary внутри собственного postgres18.6 container, source readonly /src; admin sockettrust, TCP127 SCRAM (wrong-password deny) и TLS server+SAN127, Redis8.2 shared network DB15. AUTH_STORAGE_TEST_SCRAM_HOST=127.0.0.1 обязателен; macHost/randomport/trustTCP не подходят. Предыдущая успешная recipe/evidence в Luna и [history](../planning/history.md), V3token retry.
- UsePool не сохраняет pool/services/async за callback. Final guard не обещает rollback committed in-flight действий. Shared resources закрываются owner после drain.
- Credentials/clients только trusted config, не global fallback. Crypto-only verification не проверяет текущий revoke; strict online/local expiry сохраняют разные гарантии. Секреты consumer не передавать browser/UI.
- PostgreSQL+Redis; новые deps только с разрешения. Реальные ENV/БД/secrets/staging сохранять. Commit только по запросу. Предыдущий token2a31fa7 проверен/закоммичен; его PASS не подтверждает этот diff.

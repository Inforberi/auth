# Текущий шаг

Обновлено 25 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP5.0 HTTP authority boundary

[Контракт](../features/project-http-boundary.md). Restricted reader ResolveRuntime выбирает exact canonical origin через unique origin и прежние runtime profile/snapshot predicates, только Key без credentials. HTTP NewRuntimeBoundary: directTLS/Host/platform exclusion/absolute+opaque authority/Origin-if-present, immutable per-request selection, no forwarded/header/token fallback. Unknown/disabled/incomplete404, dependency503, no-store. Lookup3s отменяется до next без отмены исходного handler context. Outer process admission/deadline нужен прежний, новых pools/cache/workers нет.

Это первый подэтап к полной readiness/публикации: boundary не создаёт route/capability/readiness и не подключён к production server. Browser/service/callback/CORS/CSRF профили всё ещё нужны отдельно. Catalog ready не считается feature-ready, нельзя монтировать обычный router без явного проекта/profile. UI не начинать.

Main formatter/diff и read-only source review; tests не запускал. Luna: task check/lint0, affected race, security и Linux ARM64 actual full TestPrepareCommandSQL PASS; TLS/SCRAM wrong-password deny/RedisDB15 fixture подтверждён. Security: вызываемых кодом уязвимостей нет, одна в dependency недостижима по scanner. Manifest5 совпал до/после и с main; свои containers/network/certificates/test binary удалены. Snapshot `/private/tmp/auth-project-http-boundary-v1.qjuqgphs`, manifest `/private/tmp/auth-project-http-boundary-v1.qjuqgphs-manifest.sha256`, metadata `/private/tmp/auth-project-http-boundary-v1.qjuqgphs-snapshot.json`; logs `/private/tmp/auth-project-http-boundary-v1-*.log`. Блок проверен; пользователь запросил коммит. Git/staging и факт коммита проверять через Git.

## Следующий шаг

После фиксации проверенного блока продолжить coherent selected-feature readiness и явные resident HTTP route profiles/lifecycle; далее полная MP5 issuer/cookies/callback/redirect matrix. Managed key/consumer source+rotation, MFA recovery/retention/fleet fairness/MP6R/MP7/MP8 отдельно. UI только после отдельного согласования; [email templates](../planning/email-templates.md) — A7 после backend.

## Процесс и ограничения

- Local read-only researcher Helmholtz (gpt-6-luna medium), ID01a17292-5405-7341-bae9-f5884a755889, сохранять для reuse. Bohr закрыт по просьбе пользователя.
- Executable checks — отдельная «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- Actual command SQL: Linux ARM64 binary внутри собственного postgres18.6 container, source readonly /src; admin sockettrust, TCP127 SCRAM (wrong-password deny), TLS server+SAN127, Redis8.2 shared network DB15. SCRAM_HOST=127.0.0.1/TLS_CA/ROOT/src/Redis127 env обязательны; macHost/randomport/trustTCP не подходят. [History](../planning/history.md), known tokenV3/introspectionV2 recipe в Luna.
- UsePool не сохраняет pool/services/async за callback. Final guard не обещает rollback committed in-flight действий. Shared resources закрывает owner после drain. Host выбирает область, не аутентифицирует пользователя.
- PostgreSQL+Redis; новые deps только с разрешения. Реальные ENV/БД/secrets/staging сохранять. Commit только по запросу. Предыдущий introspectionc9a2512 проверен/закоммичен; его PASS не подтверждает этот diff.
